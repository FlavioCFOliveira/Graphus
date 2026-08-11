//! Deterministic crash-recovery sweep for the **undo area** (`rmp` #966, `05-storage-format.md` §12).
//!
//! ## What this proves
//!
//! `05 §12.5` makes one durability claim about the undo area and one only: it is **ordinary storage**.
//! Both its stores are ordinary logical pages with the `05 §6` header, their own CRC32C, torn-write
//! protection and page LSN; every mutation is an ordinary WAL-logged intra-page patch, redone by the
//! same three-phase ARIES machinery as a record-store page. *"There is no separate undo-area recovery
//! path and no rebuild on open."*
//!
//! That claim has a precise, falsifiable consequence, and this sweep is that consequence: after a
//! crash, **every surviving version chain must be intact** — a winner's chain reachable and
//! well-formed, a loser's chain gone (its head publication compare-and-set-undone, its deltas
//! reverted to corpses), no dangling link, no cycle, and every surviving delta still able to resolve
//! its commit status through a live slot. The full storage consistency checker
//! ([`graphus_storage::verify_on_open`]) decides all of that, so it is run on every recovered store
//! — and the chains it validates are then read back and compared against what the run committed.
//!
//! ## Shape
//!
//! Modelled on `selfloop_churn` / `property_churn_recovery`: commit a set of survivors whose chains
//! must be reachable after the crash, then interleave two loser transactions that build chains of
//! their own on both new and *shared* entities, roll one back live, leave the other in flight, and
//! crash (no-force or steal, chosen by the seed). Recovery then runs, the store reopens, and the
//! assertions run.
//!
//! ## Non-vacuity
//!
//! A crash-recovery sweep is the classic place for a vacuous pass: if nothing ever built a chain, or
//! recovery always left every chain empty, every assertion below would hold trivially. Two counters
//! guard against that and are asserted over the sweep, not merely reported:
//! [`survivor_chain_deltas`](UndoRecoveryReport::survivor_chain_deltas) must be non-zero on **every**
//! run (a recovered winner really does have a chain to validate), and
//! [`losers_left_a_chain`](UndoRecoveryReport::losers_left_a_chain) must be zero on every run (a
//! recovered loser really does have none). A build that stopped writing `undo_ptr` fails the first;
//! a build whose recovery left a loser's chain published fails the second.

use graphus_core::{PageId, TxnId};
use graphus_dst::rng::DetRng;
use graphus_io::{BlockDevice, MemBlockDevice};
use graphus_storage::recovery::recover_device;
use graphus_storage::{Namespace, RecordStore, StoreKind, UndoAction, verify_on_open};
use graphus_wal::{LogSink, MemLogSink, WalManager};

type Store = RecordStore<MemBlockDevice, MemLogSink>;

/// A small buffer-pool capacity, so the run exercises eviction and the WAL-before-data rule while the
/// chains are being written.
const POOL_CAPACITY: usize = 16;

/// The outcome of one undo-area crash-recovery run.
#[derive(Debug, Clone, PartialEq, Eq)]
struct UndoRecoveryReport {
    seed: u64,
    /// Total deltas reachable, after recovery, on the chains of the entities the run **committed**.
    /// The non-vacuity floor: a run in which this is `0` proved nothing.
    survivor_chain_deltas: usize,
    /// How many entities created by a **loser** transaction still carry a published chain head after
    /// recovery. Must always be `0`: a loser's chain-head publication is compare-and-set-undone.
    losers_left_a_chain: usize,
    /// Whether the run crashed by the steal path (dirty pages written home first) rather than
    /// no-force. Reported so the sweep can assert both paths are exercised.
    steal: bool,
    /// Recovery's loser count, for the same reason.
    recovery_losers: usize,
    /// Delta slots the post-recovery GC pass returned to the free list. After a crash these are the
    /// deltas of transactions that never committed: ARIES undo turned each into a corpse, and no chain
    /// ever reached it, so only the reference sweep can collect them. A crash that stranded deltas and
    /// a GC that reclaimed none would be an unbounded-per-crash space leak.
    stranded_deltas_reclaimed: usize,
}

fn next_txn(next: &mut u64) -> TxnId {
    let t = TxnId(*next);
    *next += 1;
    t
}

/// One deterministic run: build committed chains, churn losers on top of them, crash, recover, and
/// validate every surviving chain.
fn run_undo_chain_crash(seed: u64) -> UndoRecoveryReport {
    let mut rng = DetRng::new(seed);
    let steal = rng.chance(40);

    let device = MemBlockDevice::new(0);
    let wal = WalManager::create(MemLogSink::new()).expect("create wal");
    let store = RecordStore::create(device, wal, POOL_CAPACITY, 1).expect("create store");

    let mut next = 1u64;
    let setup = next_txn(&mut next);
    store.begin(setup);
    let rel_type = store
        .intern_token(Namespace::RelType, "LINK")
        .expect("intern reltype");
    store.commit(setup).expect("commit setup");

    // --- Committed survivors. Their chains MUST be reachable and well-formed after the crash. ---
    let node_count = rng.range_inclusive(2, 4) as usize;
    let t_nodes = next_txn(&mut next);
    store.begin(t_nodes);
    let mut survivors: Vec<(StoreKind, u64)> = Vec::new();
    let mut nodes = Vec::with_capacity(node_count);
    for _ in 0..node_count {
        let (id, _) = store.create_node(t_nodes).expect("create_node");
        nodes.push(id);
        survivors.push((StoreKind::Node, id));
    }
    store.commit(t_nodes).expect("commit nodes");

    // A second committed transaction that both creates edges and DELETES one node, so at least one
    // survivor carries a TWO-delta chain (`RecreateObject` over `DeleteObject`) across the crash.
    let t_edges = next_txn(&mut next);
    store.begin(t_edges);
    let edge_count = rng.range_inclusive(1, 3);
    for _ in 0..edge_count {
        let a = nodes[rng.index(nodes.len())];
        let b = nodes[rng.index(nodes.len())];
        let (id, _) = store
            .create_rel(t_edges, rel_type, a, b)
            .expect("create_rel");
        survivors.push((StoreKind::Rel, id));
    }
    let deleted_node = if rng.chance(60) {
        // Delete a node with no incident edge, so the delete cannot fail on a referential guard.
        let extra = store.create_node(t_edges).expect("extra node").0;
        store.delete_node(t_edges, extra).expect("delete");
        survivors.push((StoreKind::Node, extra));
        Some(extra)
    } else {
        None
    };
    store.commit(t_edges).expect("commit edges");

    // --- Two interleaved losers: one rolled back LIVE, one left in flight at the crash. ---
    let la = next_txn(&mut next);
    let lb = next_txn(&mut next);
    store.begin(la);
    store.begin(lb);
    let mut loser_entities: Vec<(StoreKind, u64)> = Vec::new();
    let mut rem_a = rng.range_inclusive(1, 3);
    let mut rem_b = rng.range_inclusive(1, 3);
    while rem_a + rem_b > 0 {
        let use_a = if rem_a == 0 {
            false
        } else if rem_b == 0 {
            true
        } else {
            rng.chance(50)
        };
        let tid = if use_a { la } else { lb };
        // A loser both creates a fresh entity (its own chain) and prepends onto a SHARED committed
        // node's chain by hanging an edge off it — the interleaving that makes the chain-head
        // compare-and-set undo load-bearing.
        let (n, _) = store.create_node(tid).expect("loser node");
        loser_entities.push((StoreKind::Node, n));
        let anchor = nodes[rng.index(nodes.len())];
        let (r, _) = store
            .create_rel(tid, rel_type, anchor, n)
            .expect("loser rel");
        loser_entities.push((StoreKind::Rel, r));
        if use_a {
            rem_a -= 1;
        } else {
            rem_b -= 1;
        }
    }
    if rng.chance(50) {
        store.rollback(la).expect("live rollback la");
    } else {
        store.rollback(lb).expect("live rollback lb");
    }
    // Harden the loser tail so the crash WAL carries the in-flight loser's delta writes: recovery
    // redoes them and then undoes the loser, which is the state the chain assertions care about.
    store.with_wal(WalManager::flush);

    let (store, recovery_losers) = if steal {
        crash_steal(store)
    } else {
        crash_no_force(store)
    };

    // ---- The recovered store must pass the FULL storage consistency check, chains included. ----
    //
    // A GC pass runs first, exactly as `graphus_dst::harness` does after recovery: an aborted /
    // crashed edge creation legitimately leaves a **dead-link relationship corpse** whose incidence
    // links are transiently asymmetric (`rmp` #220), and it is the corpse splice that repairs them.
    // That is a pre-existing property of the incidence chain, not of the undo area — but the storage
    // checker validates the whole store, so the pass has to reach its steady state before it is asked
    // to certify one. The chain assertions that follow are made on the POST-GC store, which is the
    // stricter place to make them: GC is also what reclaims chains, so a chain still standing here has
    // survived both recovery and a reclamation pass.
    //
    // Before that pass runs, assert the sharper thing this sweep is actually about: **immediately
    // after recovery, with no repair of any kind, the undo area itself is already clean**. Any
    // violation left at this point belongs to the incidence chain (the corpse class above); not one
    // of them may be an `UndoChain` / `UndoSlot` fault, because `05 §12.5` promises the undo area
    // needs no recovery path of its own — ARIES redo alone must leave it correct.
    let pre_gc = graphus_storage::check::check_store(&store, &[]).expect("check runs");
    let undo_faults: Vec<_> = pre_gc
        .violations
        .iter()
        .filter(|v| {
            matches!(
                v,
                graphus_storage::Violation::UndoChain { .. }
                    | graphus_storage::Violation::UndoSlot { .. }
            )
        })
        .collect();
    assert!(
        undo_faults.is_empty(),
        "seed {seed}: ARIES redo alone must leave the undo area consistent, found {undo_faults:?}"
    );

    let gc = next_txn(&mut next);
    store.begin(gc);
    // Watermark `0`: no committed chain is old enough to reclaim, so every delta this pass frees is
    // one the reference sweep found unreachable — which isolates exactly the crash-stranded class.
    let gc_report = store.gc(gc, graphus_core::Timestamp(0)).expect("gc pass");
    store.commit(gc).expect("commit gc");
    store.flush().expect("flush");
    verify_on_open(&store, &[]).expect("the recovered store must be consistent");

    // ---- Every committed survivor's chain is intact and reachable. ----
    let mut survivor_chain_deltas = 0usize;
    for &(kind, id) in &survivors {
        let chain = store
            .version_chain(kind, id)
            .expect("a survivor's chain must be walkable");
        assert!(
            !chain.is_empty(),
            "seed {seed}: committed {kind:?} {id} lost its version chain across the crash"
        );
        survivor_chain_deltas += chain.len();
        // Every delta on it resolves through a live commit slot — the `05 §12.4` invariant that makes
        // its committed-ness knowable at all.
        for (delta_id, delta) in &chain {
            let slot = store
                .commit_slot(delta.commit_info)
                .expect("slot read")
                .unwrap_or_else(|| {
                    panic!(
                        "seed {seed}: delta {delta_id} of {kind:?} {id} names commit slot {} which \
                         no longer exists",
                        delta.commit_info
                    )
                });
            // A **live** delta must resolve through a live slot. A **corpse** delta legitimately
            // resolves through a corpse slot: that pairing is precisely how the area records "this
            // transaction did not commit" (`05 §12.4`).
            //
            // Stated as the invariant rather than as "the slot is live" because that is what
            // `05 §12.4` actually promises, and because the stricter form was only ever true by
            // accident of which states happened to be reachable. A draft of `rmp` #969 made the
            // corpse-below-a-survivor state reachable by letting incidence deltas interleave across
            // transactions on one node's chain; `D-incidence-anchor` removed that by anchoring them
            // on the relationship instead. The assertion is kept in its true form so a future change
            // that makes the state reachable again is not reported as corruption.
            assert!(
                slot.in_use() || !delta.in_use(),
                "seed {seed}: a LIVE delta of a committed survivor must resolve through a live \
                 slot (a corpse delta may resolve through a corpse slot)"
            );
        }
        // The oldest delta of any surviving entity is its creation's inverse.
        assert_eq!(
            chain.last().expect("non-empty").1.action,
            UndoAction::DeleteObject,
            "seed {seed}: the oldest delta of {kind:?} {id} records its creation"
        );
    }
    if let Some(deleted) = deleted_node {
        let chain = store
            .version_chain(StoreKind::Node, deleted)
            .expect("chain");
        assert_eq!(
            chain.len(),
            2,
            "seed {seed}: a created-then-deleted node keeps BOTH versions across the crash"
        );
        assert_eq!(chain[0].1.action, UndoAction::RecreateObject);
        assert_eq!(chain[1].1.action, UndoAction::DeleteObject);
    }

    // ---- No loser left a published chain head behind. ----
    let mut losers_left_a_chain = 0usize;
    for &(kind, id) in &loser_entities {
        // A loser's record may not even be addressable after recovery (its page can be unmapped), and
        // that is a perfectly good outcome: no record, no chain.
        let head = match kind {
            StoreKind::Node => store.node(id).ok().map(|n| n.mvcc.undo_ptr),
            _ => store.rel(id).ok().map(|r| r.mvcc.undo_ptr),
        };
        if head.unwrap_or(0) != 0 {
            losers_left_a_chain += 1;
        }
    }

    UndoRecoveryReport {
        seed,
        survivor_chain_deltas,
        losers_left_a_chain,
        steal,
        recovery_losers,
        stranded_deltas_reclaimed: gc_report.undo_deltas_reclaimed,
    }
}

/// No-force crash: rebuild onto a fresh empty device from the durable WAL prefix, then reopen.
fn crash_no_force(store: Store) -> (Store, usize) {
    let log = store.with_wal(|w| w.sink().durable_bytes().to_vec());
    let mut sink = MemLogSink::new();
    sink.append(&log);
    sink.sync().expect("sync log prefix");
    let mut device = MemBlockDevice::new(0);
    let mut wal = WalManager::open(sink).expect("open wal");
    let report = recover_device(&mut wal, &mut device).expect("recover");
    let store = RecordStore::open(device, reopen_over(&wal), POOL_CAPACITY).expect("open store");
    (store, report.losers)
}

/// Steal crash: flush dirty pages home, snapshot that on-disk image, then recover so undo rolls back
/// any stolen uncommitted (loser) pages — including the loser's delta writes.
fn crash_steal(store: Store) -> (Store, usize) {
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
    let mut wal = WalManager::open(sink).expect("open wal");
    let report = recover_device(&mut wal, &mut device).expect("recover");
    let store = RecordStore::open(device, reopen_over(&wal), POOL_CAPACITY).expect("open store");
    (store, report.losers)
}

/// The log a recovered store must reopen over: **the one recovery just wrote to**, CLRs included.
///
/// `MemLogSink` derives `Clone` as a deep copy of its byte vectors, so recovering over `sink.clone()`
/// and reopening over the original — which both crash shapes above used to do — silently discards
/// every compensation record the undo phase appended, and every `ABORT` end marker after them. What
/// that models does not exist: a real reopen attaches to the same log file recovery appended to.
///
/// The damage was not confined to the log. Undo stamps each page it compensates with the LSN of the
/// CLR it just wrote (`graphus_wal::recovery`), so the recovered pages carried LSNs naming records
/// that the reopened log did not contain — a `page_lsn` one byte past the end of the log, on which
/// `assert_wal_covers` is decided. The blind (non-monotone) `set_page_lsn` hid it by overwriting the
/// value on the next write to each page; the moment `rmp` #1029 makes the stamp a `max`, the value is
/// retained and the flush cannot converge. Measured (`rmp` #1031): `page_lsn 14496` against a durable
/// frontier of `14495`.
///
/// It also broke recovery IDEMPOTENCE, which is what the CLRs are for: a second crash after this
/// reopen would re-undo actions the discarded CLRs said were already compensated.
fn reopen_over(wal: &WalManager<MemLogSink>) -> WalManager<MemLogSink> {
    WalManager::open(wal.sink().clone()).expect("reopen over the log recovery wrote to")
}

/// The sweep. Every run must recover a consistent store with intact survivor chains and no loser
/// chain; over the whole sweep both crash shapes must be exercised.
#[test]
fn undo_chains_survive_crash_recovery_across_a_seed_sweep() {
    const SEEDS: u64 = 400;
    let mut steal_runs = 0usize;
    let mut no_force_runs = 0usize;
    let mut runs_with_recovery_losers = 0usize;
    let mut runs_that_reclaimed_stranded_deltas = 0usize;

    for seed in 1..=SEEDS {
        let report = run_undo_chain_crash(seed);
        assert!(
            report.survivor_chain_deltas > 0,
            "NON-VACUITY: seed {seed} recovered no survivor delta at all, so its chain assertions \
             proved nothing"
        );
        assert_eq!(
            report.losers_left_a_chain, 0,
            "seed {seed}: a rolled-back / crashed transaction left a published chain head"
        );
        if report.steal {
            steal_runs += 1;
        } else {
            no_force_runs += 1;
        }
        if report.recovery_losers > 0 {
            runs_with_recovery_losers += 1;
        }
        if report.stranded_deltas_reclaimed > 0 {
            runs_that_reclaimed_stranded_deltas += 1;
        }
    }

    // Sweep-level non-vacuity: both crash shapes ran, and the in-flight loser really was undone by
    // RECOVERY (not merely by the live rollback) in a meaningful share of runs.
    assert!(
        steal_runs > 0 && no_force_runs > 0,
        "both crash shapes must run"
    );
    assert!(
        runs_with_recovery_losers * 4 >= SEEDS as usize,
        "recovery must actually have had losers to undo in a substantial share of runs \
         ({runs_with_recovery_losers}/{SEEDS})"
    );
    // Every run leaves stranded deltas behind — the live-rollback loser's (its free-list pushes were
    // never checkpointed before the crash) and the in-flight loser's — so every run must reclaim some.
    // Without this the sweep could silently do nothing and the assertions above would not notice.
    assert_eq!(
        runs_that_reclaimed_stranded_deltas, SEEDS as usize,
        "the post-recovery reference sweep must collect the deltas a crash stranded, on every run \
         ({runs_that_reclaimed_stranded_deltas}/{SEEDS})"
    );
}

/// The sweep is a pure function of the seed, so a failure is reproducible.
#[test]
fn the_sweep_is_deterministic() {
    for seed in [1u64, 7, 42, 199] {
        assert_eq!(run_undo_chain_crash(seed), run_undo_chain_crash(seed));
    }
}
