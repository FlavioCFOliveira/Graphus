//! Focused crash-recovery soak for **interleaved self-loop incidence-chain churn** (`rmp` #468,
//! originally DST seed 11731).
//!
//! The generic [`crate::harness`] applies each planned transaction to completion, deliberately never
//! interleaving statements across transactions (a single-version record store makes general
//! interleaving unsound — see the comment in `harness::Driver::run`). That sequential discipline
//! cannot reach the one realistic interleaving that the seed-11731 defect needs: **two open sessions
//! both prepending self-loops onto the same committed node's incidence chain, statement-interleaved,
//! one rolled back live, the other in flight when the power is lost.**
//!
//! This soak drives exactly that family through the real engine, deterministically from a seed:
//!
//! 1. commit some nodes and a handful of self-loops on a shared node (the **survivors** — committed
//!    data threaded *below* the loser churn that a crash must never lose);
//! 2. open two loser transactions and **interleave** their self-loop creations on the shared node;
//! 3. **roll one loser back live** (mid-history) and leave the other **in flight**;
//! 4. **crash** (no-force or steal) and run ARIES recovery + reopen;
//! 5. assert the recovered graph still satisfies every DST integrity invariant via
//!    [`crate::checker::verify`] — the committed self-loops survive and the incidence chain is a
//!    well-formed forward thread (no "malformed (cycle?)").
//!
//! Before the fix in `RecordStore::open` (`rmp` #468), the crash-undo of the in-flight loser left
//! the shared node's `first_rel` pointing at a corpse whose run was **uncovered** by the recovered
//! `high_water` (the corpses share the committed node's densely-packed rel page), so the
//! incidence-walk cycle guard `2 * high_water + 2` tripped before reaching the committed self-loops
//! below the run — losing committed data. The soak's [`SelfLoopChurnReport::head_pointed_at_corpse`]
//! flag records when a run actually reaches that vulnerable post-recovery state, so the sweep can
//! assert it is exercised non-vacuously.

use graphus_core::{PageId, TxnId};
use graphus_io::{BlockDevice, MemBlockDevice};
use graphus_storage::recovery::recover_device;
use graphus_storage::{Namespace, RecordStore};
use graphus_wal::{LogSink, MemLogSink, WalManager};

use crate::checker::{self, CheckFailure};
use crate::model::Model;
use crate::rng::DetRng;

/// The store type the soak drives: the record store over the in-memory DST device + log.
type Store = RecordStore<MemBlockDevice, MemLogSink>;

/// The single reltype token used for every relationship (one type keeps the reference model simple
/// while still exercising self-loops and parallel edges).
const REL_TYPE: &str = "E";
/// A small buffer-pool capacity, to exercise eviction and the WAL rule during the run.
const POOL_CAPACITY: usize = 16;

/// The outcome of one self-loop-churn crash-recovery run.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SelfLoopChurnReport {
    /// The scenario seed (the reproducer).
    pub seed: u64,
    /// `Ok(())` if every DST integrity invariant held after recovery, else the first failure.
    pub result: std::result::Result<(), CheckFailure>,
    /// How many committed relationships (survivors) the run created and must preserve.
    pub committed_rels: usize,
    /// The recovery report's loser count (transactions rolled back by recovery — at least the
    /// in-flight loser).
    pub recovery_losers: usize,
    /// Whether the recovered shared node's `first_rel` legitimately pointed at a not-in-use dead-link
    /// corpse (`rmp` #220) — the exact post-recovery state the `rmp` #468 defect mishandled. A sweep
    /// asserts this is reached for at least one seed, so the coverage is non-vacuous.
    pub head_pointed_at_corpse: bool,
    /// Whether the crash stole (flushed) dirty pages home before recovery.
    pub steal: bool,
}

impl SelfLoopChurnReport {
    /// Whether the run preserved every invariant.
    #[must_use]
    pub fn passed(&self) -> bool {
        self.result.is_ok()
    }
}

/// Allocates a fresh monotonically-increasing [`TxnId`] from `next`.
fn next_txn(next: &mut u64) -> TxnId {
    let id = TxnId(*next);
    *next += 1;
    id
}

/// Picks a relationship's endpoints, biased toward a self-loop on `shared` (the chain whose head the
/// losers churn). A cross edge still touches `shared`, so it churns the same head.
fn pick_endpoints(
    rng: &mut DetRng,
    nodes: &[u64],
    shared: u64,
    self_loop_percent: u64,
) -> (u64, u64) {
    if nodes.len() == 1 || rng.chance(self_loop_percent) {
        (shared, shared)
    } else {
        let other = nodes[rng.index(nodes.len())];
        if rng.chance(50) {
            (shared, other)
        } else {
            (other, shared)
        }
    }
}

/// Runs one deterministic self-loop-churn crash-recovery scenario for `seed`.
#[must_use]
pub fn run_selfloop_churn_crash(seed: u64) -> SelfLoopChurnReport {
    let mut rng = DetRng::new(seed);
    let steal = rng.chance(40);

    let device = MemBlockDevice::new(0);
    let wal = WalManager::create(MemLogSink::new()).expect("create wal");
    let mut store = RecordStore::create(device, wal, POOL_CAPACITY, 1).expect("create store");

    let mut next = 1u64;
    let setup = next_txn(&mut next);
    store.begin(setup);
    let rel_type = store
        .intern_token(Namespace::RelType, REL_TYPE)
        .expect("intern reltype");
    store.commit(setup).expect("commit setup");

    let mut model = Model::new();

    // --- Committed survivors: nodes + self-loops on a shared node that MUST persist. ---
    let node_count = rng.range_inclusive(1, 3) as usize;
    let tnodes = next_txn(&mut next);
    store.begin(tnodes);
    let mut nodes = Vec::with_capacity(node_count);
    for _ in 0..node_count {
        let (id, _) = store.create_node(tnodes).expect("create_node");
        nodes.push(id);
    }
    store.commit(tnodes).expect("commit nodes");
    for &n in &nodes {
        model.add_node(n);
    }
    let shared = nodes[0];

    // At least one committed self-loop on the shared node, so there is committed data threaded
    // *below* the loser corpse run that a crash could lose.
    let survivors = rng.range_inclusive(1, 5);
    let tsurv = next_txn(&mut next);
    store.begin(tsurv);
    let mut committed_rels = Vec::new();
    for _ in 0..survivors {
        let (a, b) = pick_endpoints(&mut rng, &nodes, shared, 80);
        let (id, _) = store
            .create_rel(tsurv, rel_type, a, b)
            .expect("create_rel survivor");
        committed_rels.push((id, a, b));
    }
    store.commit(tsurv).expect("commit survivors");
    for &(id, a, b) in &committed_rels {
        model.add_rel(id, a, b);
    }

    // --- Two interleaved loser transactions churning self-loops on the shared node. One is rolled
    //     back LIVE; the other is left in flight at the crash (the seed-11731 family). ---
    let la = next_txn(&mut next);
    let lb = next_txn(&mut next);
    store.begin(la);
    store.begin(lb);

    let mut rem_a = rng.range_inclusive(1, 4);
    let mut rem_b = rng.range_inclusive(1, 4);
    while rem_a + rem_b > 0 {
        let use_a = if rem_a == 0 {
            false
        } else if rem_b == 0 {
            true
        } else {
            rng.chance(50)
        };
        let tid = if use_a { la } else { lb };
        let (a, b) = pick_endpoints(&mut rng, &nodes, shared, 80);
        let _ = store
            .create_rel(tid, rel_type, a, b)
            .expect("create_rel loser");
        if use_a {
            rem_a -= 1;
        } else {
            rem_b -= 1;
        }
    }

    // Roll one loser back LIVE (seeded which), leaving the other in flight at the crash.
    if rng.chance(50) {
        store.rollback(la).expect("live rollback la");
    } else {
        store.rollback(lb).expect("live rollback lb");
    }

    // Sometimes a freshly-begun, empty transaction at the crash boundary (mirrors seed-11731's txn7).
    if rng.chance(50) {
        let t = next_txn(&mut next);
        store.begin(t);
    }

    // Harden the loser tail so the crash WAL carries the in-flight loser's prepends: recovery redoes
    // them as corpses then undoes the loser — the state where `first_rel` can end on a corpse.
    store.with_wal(WalManager::flush);

    let (mut store, recovery_losers) = if steal {
        crash_steal(store)
    } else {
        crash_no_force(store)
    };

    // The vulnerable post-recovery state: the shared node's `first_rel` legitimately pointing at a
    // not-in-use dead-link corpse (`rmp` #220), so the incidence walk MUST thread through the corpse
    // run to reach the committed self-loops below it.
    let head = store.node(shared).expect("node").first_rel;
    let head_pointed_at_corpse = head != 0 && !store.rel(head).expect("rel").mvcc.in_use();

    let result = checker::verify(&mut store, &model);

    SelfLoopChurnReport {
        seed,
        result,
        committed_rels: committed_rels.len(),
        recovery_losers,
        head_pointed_at_corpse,
        steal,
    }
}

/// No-force crash: rebuild onto a fresh empty device from the durable WAL prefix, then reopen.
fn crash_no_force(store: Store) -> (Store, usize) {
    let log = store.with_wal(|w| w.sink().durable_bytes().to_vec());
    let mut sink = MemLogSink::new();
    sink.append(&log);
    sink.sync().expect("sync log prefix");
    let mut device = MemBlockDevice::new(0);
    let mut wal = WalManager::open(sink.clone()).expect("open wal");
    let report = recover_device(&mut wal, &mut device).expect("recover");
    let wal = WalManager::open(sink).expect("reopen wal");
    let store = RecordStore::open(device, wal, POOL_CAPACITY).expect("open store");
    (store, report.losers)
}

/// Steal crash: flush dirty pages home, snapshot that on-disk image, then recover so undo rolls back
/// any stolen uncommitted (loser) pages.
fn crash_steal(mut store: Store) -> (Store, usize) {
    store.flush().expect("flush (steal)");
    let pages = store.mapped_pages();
    let max = pages.iter().map(|p| p.0).max().unwrap_or(0);
    let mut device = MemBlockDevice::new(max + 1);
    for p in &pages {
        let bytes = store.read_device_page(*p).expect("read device page");
        device.write_page(PageId(p.0), &bytes).expect("stage page");
    }
    device.sync_all().expect("persist disk image");

    let log = store.with_wal(|w| w.sink().durable_bytes().to_vec());
    let mut sink = MemLogSink::new();
    sink.append(&log);
    sink.sync().expect("sync log prefix");
    let mut wal = WalManager::open(sink.clone()).expect("open wal");
    let report = recover_device(&mut wal, &mut device).expect("recover");
    let wal = WalManager::open(sink).expect("reopen wal");
    let store = RecordStore::open(device, wal, POOL_CAPACITY).expect("open store");
    (store, report.losers)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_seed_is_deterministic_and_passes() {
        let a = run_selfloop_churn_crash(11731);
        let b = run_selfloop_churn_crash(11731);
        assert_eq!(a, b, "self-loop-churn scenario is not deterministic");
        assert!(a.passed(), "seed 11731 must pass: {:?}", a.result);
    }

    #[test]
    fn small_sweep_is_non_vacuous() {
        // A small in-crate sweep that proves the soak actually reaches the vulnerable post-recovery
        // state (a corpse head with committed self-loops below it) for at least one seed. The large
        // 10k-seed regression sweep lives in `tests/selfloop_churn_recovery.rs`.
        let mut hit_corpse_head = false;
        let mut hit_losers = false;
        for seed in 1..=500u64 {
            let r = run_selfloop_churn_crash(seed);
            assert!(r.passed(), "seed {seed} failed: {:?}", r.result);
            assert!(r.committed_rels >= 1, "seed {seed}: must commit survivors");
            hit_corpse_head |= r.head_pointed_at_corpse;
            hit_losers |= r.recovery_losers > 0;
        }
        assert!(
            hit_corpse_head,
            "no seed reached a corpse head — the soak is not exercising the rmp #468 condition"
        );
        assert!(
            hit_losers,
            "no seed produced a recovery loser — coverage is vacuous"
        );
    }
}
