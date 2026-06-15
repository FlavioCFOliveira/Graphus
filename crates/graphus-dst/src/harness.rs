//! The simulation harness: drives the storage/WAL/txn engine under a seeded workload, injects a
//! seeded fault, recovers, and verifies the four invariants (`specification/04-technical-design.md`
//! §11).
//!
//! A scenario is a pure function of its seed. The harness:
//!
//! 1. builds a [`RecordStore`] on the in-memory DST device + log ([`graphus_io::MemBlockDevice`],
//!    [`graphus_wal::MemLogSink`]), exactly as `graphus-storage`'s crash-recovery tests do;
//! 2. plans a workload ([`crate::workload`]) and applies it transaction by transaction, mirroring
//!    every acknowledged effect into the reference [`Model`] and counting outcomes in the
//!    [`AckLedger`]; effects of a rolled-back or in-flight transaction are *never* merged, so the
//!    model holds only acknowledged commits;
//! 3. injects the scenario's [`FaultKind`] at a seeded point (a crash drops the un-synced tail of
//!    the device and the WAL; the steal variant first writes dirty pages home; a torn-WAL-tail
//!    truncates the durable prefix inside the last, un-acknowledged record);
//! 4. runs three-phase ARIES recovery ([`graphus_storage::recovery::recover_device`]) and reopens
//!    the store;
//! 5. checks durability, atomicity, and integrity against the model ([`crate::checker::verify`]).
//!
//! ## How a fault is reproduced
//!
//! Every stochastic decision — the workload, the fault kind, the crash point, whether a loser's
//! tail was hardened — is drawn from the one [`crate::rng::DetRng`] seeded by the scenario seed, so
//! re-running a seed replays the exact run and the exact pass/fail. A failure prints its seed; that
//! one number is the whole reproducer.

use std::collections::HashMap;

use graphus_core::TxnId;
use graphus_io::{BlockDevice, MemBlockDevice, PAGE_SIZE, Page};
use graphus_storage::recovery::recover_device;
use graphus_storage::{Namespace, RecordStore};
use graphus_wal::{LogSink, MemLogSink, WalManager};

use crate::checker::{self, CheckFailure};
use crate::fault::FaultKind;
use crate::model::{AckLedger, Model, PropTriple};
use crate::rng::DetRng;
use crate::workload::{self, Op, PlannedTxn, TxnOutcome, WorkloadConfig};

/// The store type the harness drives: the record store over the in-memory DST device + log.
type Store = RecordStore<MemBlockDevice, MemLogSink>;

/// The reltype token the harness uses for every relationship (one type keeps the model simple while
/// still exercising parallel edges and self-loops).
const REL_TYPE: &str = "E";
/// A property-key token used for generated node properties.
const PROP_KEY: &str = "p";
/// The inline property type tag used for generated integer properties (`04 §2.3` INTEGER).
const PROP_TYPE_TAG: u8 = 2;
/// The buffer-pool capacity for scenario stores (small, to exercise eviction + the WAL rule).
const POOL_CAPACITY: usize = 32;

/// The outcome of a single scenario run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScenarioReport {
    /// The scenario seed (the reproducer).
    pub seed: u64,
    /// The fault that was injected.
    pub fault: FaultKind,
    /// Total operations applied across all transactions before the fault.
    pub ops_applied: u64,
    /// The acknowledged-commit ledger after the run.
    pub ledger: AckLedger,
    /// `Ok(())` if all invariants held, else the first failure.
    pub result: std::result::Result<(), CheckFailure>,
    /// Whether the run actually exercised non-vacuous conditions: at least one acknowledged commit
    /// AND (work left in flight OR recovery rolled work back). Tests use this to prove the scenario
    /// is not trivially empty.
    pub non_vacuous: bool,
    /// The recovery report's loser count (transactions rolled back by recovery).
    pub recovery_losers: usize,
    /// Whether recovery observed a truncated/torn tail.
    pub tail_truncated: bool,
}

impl ScenarioReport {
    /// Whether the scenario passed all invariants.
    #[must_use]
    pub fn passed(&self) -> bool {
        self.result.is_ok()
    }
}

/// Picks the fault kind for a scenario deterministically from `rng`. Crashes dominate (the central
/// DST fault), with the torn-WAL-tail fault mixed in.
fn pick_fault(rng: &mut DetRng) -> FaultKind {
    match rng.below(5) {
        0 => FaultKind::Crash { steal: false },
        1 => FaultKind::TornWalTail,
        2 => FaultKind::TornDataPage,
        // Weighted toward the steal crash, the richest path (undo of stolen, uncommitted pages).
        _ => FaultKind::Crash { steal: true },
    }
}

/// Runs the default crash scenario for `seed` (the multi-seed durability test's workhorse): a crash
/// fault chosen between no-force and steal by the seed.
#[must_use]
pub fn run_crash_scenario(seed: u64) -> ScenarioReport {
    let mut rng = DetRng::new(seed);
    let steal = rng.below(2) == 1;
    run_with_fault(seed, FaultKind::Crash { steal }, &mut rng)
}

/// Runs a scenario for `seed` choosing the fault kind from the seed (the CLI's default).
#[must_use]
pub fn run_scenario(seed: u64) -> ScenarioReport {
    let mut rng = DetRng::new(seed);
    let fault = pick_fault(&mut rng);
    run_with_fault(seed, fault, &mut rng)
}

/// Runs a scenario for `seed` with an explicit `fault`. `rng` is the seeded stream already advanced
/// past any fault-selection draw, so the workload that follows is a deterministic function of the
/// seed and the chosen fault.
#[must_use]
pub fn run_with_fault(seed: u64, fault: FaultKind, rng: &mut DetRng) -> ScenarioReport {
    Driver::new(seed, fault).run(rng)
}

/// Resolves a generated slot reference against the live ids, clamping a stale slot into range.
fn resolve(slot: usize, live: &[u64]) -> Option<u64> {
    if live.is_empty() {
        None
    } else {
        Some(live[slot % live.len()])
    }
}

/// The mutable state of one scenario run.
struct Driver {
    seed: u64,
    fault: FaultKind,
    store: Store,
    model: Model,
    ledger: AckLedger,
    /// Live (committed) node physical ids, for slot resolution.
    live_nodes: Vec<u64>,
    /// Live (committed) relationship physical ids, for slot resolution.
    live_rels: Vec<u64>,
    /// Committed relationship endpoints, mirrored so deletion can detach a node's edges.
    rel_endpoints: HashMap<u64, (u64, u64)>,
    rel_type: u32,
    prop_key: u32,
    next_txn: u64,
    ops_applied: u64,
}

impl Driver {
    fn new(seed: u64, fault: FaultKind) -> Self {
        let device = MemBlockDevice::new(0);
        let wal = WalManager::create(MemLogSink::new()).expect("create wal");
        let mut store = RecordStore::create(device, wal, POOL_CAPACITY, 1).expect("create store");
        // Intern the tokens once, in their own committed transaction, so they are durable before any
        // workload runs (token creation is itself a WAL-logged, transactional operation, `04 §2.6`).
        let setup = TxnId(1);
        store.begin(setup);
        let rel_type = store
            .intern_token(Namespace::RelType, REL_TYPE)
            .expect("intern reltype");
        let prop_key = store
            .intern_token(Namespace::PropKey, PROP_KEY)
            .expect("intern propkey");
        store.commit(setup).expect("commit setup");

        Self {
            seed,
            fault,
            store,
            model: Model::new(),
            ledger: AckLedger::new(),
            live_nodes: Vec::new(),
            live_rels: Vec::new(),
            rel_endpoints: HashMap::new(),
            rel_type,
            prop_key,
            next_txn: 2,
            ops_applied: 0,
        }
    }

    fn fresh_txn(&mut self) -> TxnId {
        let t = TxnId(self.next_txn);
        self.next_txn += 1;
        t
    }

    /// Runs the whole scenario: workload + fault + recovery + verification.
    fn run(&mut self, rng: &mut DetRng) -> ScenarioReport {
        let cfg = WorkloadConfig::default();
        let plan = workload::generate(rng, cfg);

        let mut committed_seen = false;
        let mut in_flight_seen = false;

        // Apply every planned transaction, fully resolving each to Commit or Rollback. A
        // plan-level "leave in flight" is downgraded to Rollback here on purpose: the **only**
        // in-flight work allowed is the work the crash actually interrupts (the final phase below).
        //
        // Why: this record store is single-version, so an in-flight transaction's uncommitted
        // writes are visible to *later* transactions running in the same store. If an earlier
        // transaction were left dangling while later ones committed over its records, a committed
        // transaction could legitimately delete an uncommitted record — an interleaving that crash
        // undo cannot reconcile and that no real session would produce (a real client either
        // commits, rolls back, or *is* the one the crash hits). Concentrating in-flight work at the
        // crash boundary models exactly the realistic "power loss with transactions still open".
        for txn in &plan {
            match self.apply_txn(txn) {
                AppliedOutcome::Committed => {
                    committed_seen = true;
                    self.ledger.record_commit();
                }
                AppliedOutcome::RolledBack => self.ledger.record_rollback(),
            }
        }

        // The final in-flight phase: open one or more transactions, do real work, and **never
        // resolve them** — this is precisely the work the crash interrupts. Their effects must not
        // survive recovery (atomicity), while everything committed above must (durability).
        let in_flight_txns = rng.range_inclusive(1, 3);
        for _ in 0..in_flight_txns {
            if self.run_in_flight_txn(rng) {
                in_flight_seen = true;
                self.ledger.record_in_flight_at_crash();
            }
        }

        // For a torn-WAL-tail fault, guarantee there is a hardened-but-uncommitted record at the end
        // of the durable log to tear, so the tear lands *after* the last acknowledged commit.
        if matches!(self.fault, FaultKind::TornWalTail) {
            self.append_hardened_loser_tail();
            in_flight_seen = true;
        }

        let recovery = self.crash_and_recover(rng);
        // Deletes are MVCC tombstones (`rmp` task #45): a committed-deleted node/relationship keeps
        // its slot (and incidence-chain links) until GC reclaims it. Run a GC pass post-recovery
        // (watermark = the latest commit; recovery leaves no live reader) so the physical store
        // reflects the committed logical model the checker compares against. In-flight (loser)
        // tombstones were already undone by recovery, so only committed deletions are reclaimed.
        self.gc_after_recovery();
        let result = checker::verify(&mut self.store, &self.model);

        let non_vacuous = committed_seen && (in_flight_seen || recovery.losers > 0);

        ScenarioReport {
            seed: self.seed,
            fault: self.fault,
            ops_applied: self.ops_applied,
            ledger: self.ledger.clone(),
            result,
            non_vacuous,
            recovery_losers: recovery.losers,
            tail_truncated: recovery.tail_truncated,
        }
    }

    /// Runs an MVCC GC pass over the recovered store, reclaiming every tombstone whose deletion
    /// committed at or before the latest commit timestamp (`04 §5.5`, `rmp` task #45). After
    /// recovery there is no live reader, so the latest commit is a safe watermark and every
    /// committed deletion becomes physically reclaimable — leaving the store's live records and
    /// incidence chains exactly equal to the committed logical model.
    fn gc_after_recovery(&mut self) {
        let tid = self.fresh_txn();
        let watermark = self.store.snapshot_ts();
        self.store.begin(tid);
        self.store.gc(tid, watermark).expect("gc");
        self.store.commit(tid).expect("gc commit");
        // Write the GC's pages home so the checker's page-checksum pass reads a clean durable image
        // (a committed-but-unflushed page carries a stale checksum field until write-back).
        self.store.flush().expect("flush after gc");
    }

    /// Applies one planned transaction to completion, mirroring acknowledged effects into the model
    /// only on commit. A plan-level [`TxnOutcome::LeaveInFlight`] is resolved as a rollback here (see
    /// [`Self::run`] for why in-flight work is confined to the crash boundary).
    fn apply_txn(&mut self, txn: &PlannedTxn) -> AppliedOutcome {
        let tid = self.fresh_txn();
        self.store.begin(tid);

        let mut pending = Pending::default();
        for op in &txn.ops {
            self.ops_applied += 1;
            self.apply_op(tid, *op, &mut pending);
        }

        match txn.outcome {
            TxnOutcome::Commit => {
                self.store.commit(tid).expect("commit");
                pending.merge_into(self);
                AppliedOutcome::Committed
            }
            // Rollback and (downgraded) LeaveInFlight both abort: undo the work, discard pending.
            TxnOutcome::Rollback | TxnOutcome::LeaveInFlight => {
                self.store.rollback(tid).expect("rollback");
                AppliedOutcome::RolledBack
            }
        }
    }

    /// Opens a transaction, does real generated work, and **leaves it unresolved** — the in-flight
    /// work the crash interrupts. Sometimes hardens its tail so the crash log carries it (forcing
    /// recovery's undo to run); sometimes leaves it un-synced so the crash simply drops it. Either
    /// way its effects must not survive recovery. Returns whether any work was actually issued.
    fn run_in_flight_txn(&mut self, rng: &mut DetRng) -> bool {
        if self.live_nodes.is_empty() {
            // Ensure there is at least one node so the in-flight txn can build edges.
            let tid = self.fresh_txn();
            self.store.begin(tid);
            let (id, _eid) = self.store.create_node(tid).expect("seed node");
            self.store.commit(tid).expect("commit seed node");
            self.model.add_node(id);
            self.live_nodes.push(id);
            self.ledger.record_commit();
        }

        let tid = self.fresh_txn();
        self.store.begin(tid);
        let mut pending = Pending::default();
        let n_ops = rng.range_inclusive(1, 6);
        for _ in 0..n_ops {
            // A small, self-contained op mix; pending is discarded (this txn never commits).
            let op = match rng.below(3) {
                0 => Op::CreateNode,
                1 => {
                    let s = rng.index(self.live_nodes.len().max(1));
                    let e = if rng.chance(20) {
                        s
                    } else {
                        rng.index(self.live_nodes.len().max(1))
                    };
                    Op::CreateRel {
                        start_slot: s,
                        end_slot: e,
                    }
                }
                _ => Op::AddNodeProp {
                    node_slot: rng.index(self.live_nodes.len().max(1)),
                    value: rng.next_u64(),
                },
            };
            self.ops_applied += 1;
            self.apply_op(tid, op, &mut pending);
        }
        // Harden the in-flight tail on a coin flip (un-acknowledged either way; never committed).
        if rng.below(2) == 1 {
            self.store.with_wal(WalManager::flush);
        }
        // Deliberately do NOT commit or roll back: this transaction is in flight at the crash.
        true
    }

    /// Applies a single op under `tid`, recording the intended effect into `pending` as an ordered
    /// effect (so a free-then-reuse of the same physical id within one transaction nets out exactly
    /// as the store does, `04 §2.7`).
    ///
    /// Generated ops are always legal (the generator only references live slots and the harness
    /// guards deletions), so the store calls succeed; an unexpected store error is a real bug and
    /// is surfaced via `expect` with the op for diagnosis.
    fn apply_op(&mut self, tid: TxnId, op: Op, pending: &mut Pending) {
        match op {
            Op::CreateNode => {
                let (id, _eid) = self.store.create_node(tid).expect("create_node");
                pending.push(Effect::AddNode(id));
            }
            Op::CreateRel {
                start_slot,
                end_slot,
            } => {
                let live = self.live_nodes_in_txn(pending);
                let (Some(a), Some(b)) = (resolve(start_slot, &live), resolve(end_slot, &live))
                else {
                    return; // no nodes yet; skip
                };
                let (id, _eid) = self
                    .store
                    .create_rel(tid, self.rel_type, a, b)
                    .expect("create_rel");
                pending.push(Effect::AddRel(id, a, b));
            }
            Op::AddNodeProp { node_slot, value } => {
                let live = self.live_nodes_in_txn(pending);
                let Some(node) = resolve(node_slot, &live) else {
                    return;
                };
                let _pid = self
                    .store
                    .add_node_property(tid, node, self.prop_key, PROP_TYPE_TAG, value)
                    .expect("add_node_property");
                pending.push(Effect::AddProp(
                    node,
                    PropTriple {
                        key: self.prop_key,
                        type_tag: PROP_TYPE_TAG,
                        value_inline: value,
                    },
                ));
            }
            Op::DeleteRel { rel_slot } => {
                let live = self.live_rels_in_txn(pending);
                let Some(rid) = resolve(rel_slot, &live) else {
                    return;
                };
                // Only delete a relationship the store still holds as a *live version*. A deleted
                // relationship is now an MVCC tombstone (`rmp` task #45): it keeps its in-use slot
                // until GC, so we check `expired_ts == 0` (not just `in_use`) to avoid re-deleting a
                // tombstone, which the store rejects.
                let mvcc = self.store.rel(rid).expect("rel").mvcc;
                if mvcc.in_use() && mvcc.expired_ts == 0 {
                    self.store.delete_rel(tid, rid).expect("delete_rel");
                    pending.push(Effect::DelRel(rid));
                }
            }
            Op::DeleteNode { node_slot } => {
                let live = self.live_nodes_in_txn(pending);
                let Some(node) = resolve(node_slot, &live) else {
                    return;
                };
                // Detach the node's live relationships first. `incident_rels` returns every
                // relationship still threaded into the chain, including MVCC tombstones not yet GC'd
                // (`rmp` task #45), so skip any already-expired one to avoid re-deleting a tombstone.
                let incident = self.store.incident_rels(node).expect("incident_rels");
                for rid in incident {
                    let mvcc = self.store.rel(rid).expect("rel").mvcc;
                    if mvcc.in_use() && mvcc.expired_ts == 0 {
                        self.store
                            .delete_rel(tid, rid)
                            .expect("delete_rel (detach)");
                        pending.push(Effect::DelRel(rid));
                    }
                }
                let mvcc = self.store.node(node).expect("node").mvcc;
                if mvcc.in_use() && mvcc.expired_ts == 0 {
                    self.store.delete_node(tid, node).expect("delete_node");
                    pending.push(Effect::DelNode(node));
                }
            }
        }
    }

    /// The node ids live *inside the open transaction*: committed live nodes plus this
    /// transaction's ordered effects applied to a scratch set. Ordered application makes a
    /// free-then-reuse of an id resolve to the live entity, matching the store.
    fn live_nodes_in_txn(&self, pending: &Pending) -> Vec<u64> {
        let mut set: std::collections::BTreeSet<u64> = self.live_nodes.iter().copied().collect();
        for e in &pending.effects {
            match *e {
                Effect::AddNode(id) => {
                    set.insert(id);
                }
                Effect::DelNode(id) => {
                    set.remove(&id);
                }
                _ => {}
            }
        }
        set.into_iter().collect()
    }

    /// The relationship ids live inside the open transaction (see [`Self::live_nodes_in_txn`]).
    fn live_rels_in_txn(&self, pending: &Pending) -> Vec<u64> {
        let mut set: std::collections::BTreeSet<u64> = self.live_rels.iter().copied().collect();
        for e in &pending.effects {
            match *e {
                Effect::AddRel(id, _, _) => {
                    set.insert(id);
                }
                Effect::DelRel(id) => {
                    set.remove(&id);
                }
                _ => {}
            }
        }
        set.into_iter().collect()
    }

    /// Begins an uncommitted transaction, performs one logged write, and hardens its tail, so the
    /// durable WAL ends with a record that belongs to no acknowledged commit. Used only by the
    /// torn-WAL-tail fault so the tear lands strictly after the last committed record.
    fn append_hardened_loser_tail(&mut self) {
        let tid = self.fresh_txn();
        self.store.begin(tid);
        // A node creation is a self-contained logged write; we never commit this txn.
        let _ = self.store.create_node(tid).expect("loser create_node");
        self.store.with_wal(WalManager::flush); // harden the loser's tail (un-acknowledged)
        self.ledger.record_in_flight_at_crash();
    }

    /// Crashes the engine per the scenario fault and recovers, returning the recovery summary.
    fn crash_and_recover(&mut self, rng: &mut DetRng) -> RecoverySummary {
        match self.fault {
            FaultKind::Crash { steal: false } => self.recover_no_force(None),
            FaultKind::Crash { steal: true } => self.recover_steal(),
            FaultKind::TornWalTail => {
                let keep = self.torn_truncation_point(rng);
                self.recover_no_force(Some(keep))
            }
            FaultKind::TornDataPage => self.recover_torn_data_page(rng),
        }
    }

    /// Torn-data-page recovery: flush dirty pages home **under doublewrite protection**, snapshot
    /// that on-disk image while **tearing one home data page** (a power loss mid-write), then recover
    /// with the doublewrite buffer so the torn page is repaired from its intact doublewrite copy
    /// *before* ARIES redo reads its `page_lsn` (`05 §3`, `04 §4.5`).
    ///
    /// This is the full-engine analogue of [`recover_steal`](Self::recover_steal): same flush + disk
    /// snapshot + recover spine, but the home image carries a torn page and recovery is the
    /// DWB-aware [`graphus_storage::recovery::recover_device_with_dwb`]. The post-recovery checker's
    /// page-checksum invariant (`crate::checker`) fails loudly if the tear is *not* repaired, so a
    /// pass is real evidence the DWB closed the hole.
    fn recover_torn_data_page(&mut self, rng: &mut DetRng) -> RecoverySummary {
        use graphus_storage::Dwb;
        use graphus_storage::recovery::recover_device_with_dwb;

        // 1. Flush dirty pages home under doublewrite protection: the DWB holds a durable copy of
        //    every flushed image before the home write.
        let mut dwb = Dwb::new(MemBlockDevice::new(0)).expect("dwb device");
        self.store
            .flush_protected(&mut dwb)
            .expect("flush_protected");

        // 2. Snapshot the on-disk home image into a fresh device, tearing one data page.
        let pages = self.store.mapped_pages();
        let max = pages.iter().map(|p| p.0).max().unwrap_or(0);
        let mut device = MemBlockDevice::new(max + 1);

        let staged: Vec<(u64, Box<Page>)> = pages
            .iter()
            .map(|p| {
                (
                    p.0,
                    self.store.read_device_page(*p).expect("read device page"),
                )
            })
            .collect();

        // Choose a (page, prefix) tear that **provably lands**: a torn write keeps the first `prefix`
        // bytes of the new image and leaves the rest as the device's old bytes (all-zero on this
        // fresh device). For the tear to corrupt the page its body `prefix..PAGE_SIZE` must differ
        // from zero (a sparse page whose tail is already zero would tear into an identical, still-valid
        // image — a vacuous fault). We therefore simulate the tear on the staged image and pick the
        // first candidate whose torn form fails its checksum, deterministically from the seed. The
        // metadata head (page 0) is excluded so the tear lands on a record page.
        let prefix = 512 + rng.index(2048);
        let mut torn_page = None;
        // A seed-rotated scan order so different seeds tear different pages while staying deterministic.
        let start = rng.index(staged.len().max(1));
        for k in 0..staged.len() {
            let (idx, bytes) = &staged[(start + k) % staged.len()];
            if *idx == 0 {
                continue; // never the metadata head
            }
            // Simulate the torn image: new prefix over a zero page.
            let mut sim = [0u8; PAGE_SIZE];
            sim[..prefix].copy_from_slice(&bytes[..prefix]);
            if !graphus_bufpool::page::verify_checksum(&sim) {
                torn_page = Some(*idx);
                break;
            }
        }
        // `torn_page` is `None` only for a degenerate near-empty store where every non-head page is
        // sparse enough that a prefix tear stays byte-identical (no record content past `prefix`).
        // That run still exercises the DWB-protected flush + DWB-aware recovery spine end to end; it
        // simply has no torn page to repair, which is itself a valid (committed-or-nothing) outcome.
        for (idx, bytes) in &staged {
            if Some(*idx) == torn_page {
                device.arm_torn_write(graphus_core::PageId(*idx), prefix);
            }
            device
                .write_page(graphus_core::PageId(*idx), bytes)
                .expect("stage page");
        }
        device.sync_all().expect("persist disk image");

        // When a tear was injected, it must actually have landed (the home page now fails its
        // checksum), or the repair side would be vacuous. This is the load-bearing precondition: a
        // pass after a *real* tear is what proves the DWB repaired it.
        if let Some(tp) = torn_page {
            let mut buf = [0u8; PAGE_SIZE];
            device
                .read_page(graphus_core::PageId(tp), &mut buf)
                .expect("read torn");
            assert!(
                !graphus_bufpool::page::verify_checksum(&buf),
                "seed {}: torn home page {tp} unexpectedly passes its checksum \
                 (the simulated tear and the real tear disagree)",
                self.seed
            );
        }

        // 3. Snapshot the DWB device into a fresh device and recover with doublewrite repair.
        let dwb_pages = dwb.device().page_count();
        let mut dwb_dev = MemBlockDevice::new(dwb_pages);
        for i in 0..dwb_pages {
            let mut buf = [0u8; PAGE_SIZE];
            dwb.device()
                .read_page(graphus_core::PageId(i), &mut buf)
                .expect("read dwb page");
            dwb_dev
                .write_page(graphus_core::PageId(i), &buf)
                .expect("stage dwb page");
        }
        dwb_dev.sync_all().expect("persist dwb image");
        let mut dwb_restore = Dwb::new(dwb_dev).expect("dwb restore");

        let log = self.store.with_wal(|w| w.sink().durable_bytes().to_vec());
        let mut sink = MemLogSink::new();
        sink.append(&log);
        sink.sync().expect("sync log prefix");

        let mut wal = WalManager::open(sink.clone()).expect("open wal");
        let report = recover_device_with_dwb(&mut wal, &mut device, &mut dwb_restore)
            .expect("recover with dwb");
        let wal = WalManager::open(sink).expect("reopen wal");
        self.store = RecordStore::open(device, wal, 64).expect("open store");
        RecoverySummary {
            losers: report.losers,
            tail_truncated: report.tail_truncated,
        }
    }

    /// The byte length to truncate the durable WAL to for a torn-tail fault.
    ///
    /// [`append_hardened_loser_tail`](Self::append_hardened_loser_tail) guarantees the durable log
    /// ends with un-acknowledged records, so tearing the final `1..=N` bytes corrupts (only) that
    /// trailing un-acknowledged record: its CRC/length no longer decodes, and recovery stops at the
    /// last intact record — which is at or after the last committed record, so no acknowledged
    /// commit is lost.
    fn torn_truncation_point(&self, rng: &mut DetRng) -> usize {
        let durable_len = self.store.with_wal(|w| w.durable_len()) as usize;
        if durable_len <= 1 {
            return durable_len;
        }
        let tear = rng.range_inclusive(1, 8).min(durable_len as u64 - 1) as usize;
        durable_len - tear
    }

    /// No-force recovery: rebuild onto a fresh empty device from the durable WAL prefix, optionally
    /// truncated to `keep` bytes (torn tail). Mirrors `crash_recovery.rs::recover_no_force`.
    fn recover_no_force(&mut self, keep: Option<usize>) -> RecoverySummary {
        let mut log = self.store.with_wal(|w| w.sink().durable_bytes().to_vec());
        if let Some(n) = keep {
            log.truncate(n.min(log.len()));
        }
        let mut sink = MemLogSink::new();
        sink.append(&log);
        sink.sync().expect("sync log prefix");

        let mut device = MemBlockDevice::new(0);
        let mut wal = WalManager::open(sink.clone()).expect("open wal");
        let report = recover_device(&mut wal, &mut device).expect("recover");

        let wal = WalManager::open(sink).expect("reopen wal");
        self.store = RecordStore::open(device, wal, 64).expect("open store");
        RecoverySummary {
            losers: report.losers,
            tail_truncated: report.tail_truncated,
        }
    }

    /// Steal recovery: flush dirty pages home, snapshot that on-disk image, then recover so undo
    /// rolls back any stolen uncommitted pages. Mirrors `crash_recovery.rs::recover_steal`.
    fn recover_steal(&mut self) -> RecoverySummary {
        self.store.flush().expect("flush (steal)");
        let pages = self.store.mapped_pages();
        let max = pages.iter().map(|p| p.0).max().unwrap_or(0);
        let mut device = MemBlockDevice::new(max + 1);
        {
            let mut staged: Vec<(u64, Box<Page>)> = Vec::with_capacity(pages.len());
            for p in &pages {
                staged.push((
                    p.0,
                    self.store.read_device_page(*p).expect("read device page"),
                ));
            }
            for (idx, bytes) in staged {
                device
                    .write_page(graphus_core::PageId(idx), &bytes)
                    .expect("stage page");
            }
            device.sync_all().expect("persist disk image");
        }

        let log = self.store.with_wal(|w| w.sink().durable_bytes().to_vec());
        let mut sink = MemLogSink::new();
        sink.append(&log);
        sink.sync().expect("sync log prefix");

        let mut wal = WalManager::open(sink.clone()).expect("open wal");
        let report = recover_device(&mut wal, &mut device).expect("recover");
        let wal = WalManager::open(sink).expect("reopen wal");
        self.store = RecordStore::open(device, wal, 64).expect("open store");
        RecoverySummary {
            losers: report.losers,
            tail_truncated: report.tail_truncated,
        }
    }
}

/// Outcome of applying one planned transaction to completion.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AppliedOutcome {
    Committed,
    RolledBack,
}

/// A compact recovery summary the harness needs (subset of [`graphus_wal::RecoveryReport`]).
struct RecoverySummary {
    losers: usize,
    tail_truncated: bool,
}

/// One ordered effect of an open transaction. Recording effects *in apply order* (rather than
/// bucketing all creations then all deletions) is what makes a free-then-reuse of the same physical
/// id within one transaction net out exactly as the store does: the store's free list may hand the
/// just-freed id straight back to a later create in the same transaction (`04 §2.7`), so the final
/// create wins and the id stays live.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Effect {
    /// A node was created with this physical id.
    AddNode(u64),
    /// A relationship `(id, start, end)` was created.
    AddRel(u64, u64, u64),
    /// A property was prepended to a node's chain.
    AddProp(u64, PropTriple),
    /// A relationship id was deleted (freed).
    DelRel(u64),
    /// A node id was deleted (freed).
    DelNode(u64),
}

/// The ordered effect log staged within an open transaction, merged into the reference state only
/// on commit (discarded on rollback or when a crash leaves the transaction in flight).
#[derive(Debug, Default)]
struct Pending {
    effects: Vec<Effect>,
}

impl Pending {
    /// Appends an effect in apply order.
    fn push(&mut self, e: Effect) {
        self.effects.push(e);
    }

    /// Replays this transaction's effects into the driver's model and live-id bookkeeping, in
    /// order, so create/delete/recreate of a reused id resolves to the store's final state.
    fn merge_into(self, d: &mut Driver) {
        for e in self.effects {
            match e {
                Effect::AddNode(id) => {
                    d.model.add_node(id);
                    if !d.live_nodes.contains(&id) {
                        d.live_nodes.push(id);
                    }
                }
                Effect::AddRel(id, a, b) => {
                    d.model.add_rel(id, a, b);
                    if !d.live_rels.contains(&id) {
                        d.live_rels.push(id);
                    }
                    d.rel_endpoints.insert(id, (a, b));
                }
                Effect::AddProp(node, prop) => d.model.add_node_prop(node, prop),
                Effect::DelRel(id) => {
                    d.model.remove_rel(id);
                    d.live_rels.retain(|&r| r != id);
                    d.rel_endpoints.remove(&id);
                }
                Effect::DelNode(id) => {
                    d.model.remove_node(id);
                    d.live_nodes.retain(|&n| n != id);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_crash_scenario_passes_and_is_non_vacuous_for_some_seed() {
        let mut any_non_vacuous = false;
        for seed in 1..=20u64 {
            let r = run_crash_scenario(seed);
            assert!(r.passed(), "seed {seed} failed: {:?}", r.result);
            any_non_vacuous |= r.non_vacuous;
        }
        assert!(any_non_vacuous, "no seed produced a non-vacuous crash run");
    }

    #[test]
    fn same_seed_same_report() {
        for seed in [1u64, 7, 42, 100] {
            let a = run_scenario(seed);
            let b = run_scenario(seed);
            assert_eq!(a, b, "seed {seed} is not deterministic");
        }
    }
}
