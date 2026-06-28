//! Regression: crash recovery of self-loop incidence-chain churn must never lose a committed
//! relationship (`rmp` #468, originally surfaced by DST seed 11731).
//!
//! A self-loop (`start_node == end_node`) is threaded into a single node's doubly-linked incidence
//! chain **twice** (once per side). Under `rmp` #220 the chain-head compare-and-set undo can
//! legitimately leave a committed node's `first_rel` pointing at a not-in-use **dead-link corpse**
//! left by an aborted/crash-loser relationship creation; the forward incidence walk threads through
//! the corpse run to reach the live relationships below it, and GC repairs the head lazily.
//!
//! The bug: when a loser's self-loop record is allocated on the **same** densely-packed rel page as
//! an earlier committed self-loop (`records_per_page(102) == 80`, so the first 79 rel ids share one
//! page), that page is in the committed catalog. On reopen, `reconstruct_orphan_store_pages` (which
//! floors `high_water` for *orphan* pages only) skips it, so the corpse slots materialised above the
//! durable `high_water` are left **uncovered**. The incidence-walk cycle guard is `2 * high_water +
//! 2`; an uncovered corpse run makes the committed head unreachable within the guard, so
//! `incident_rels` errors "malformed (cycle?)" and the committed self-loops below the run become
//! **unreadable — committed-data loss after a crash**. (It also left the allocator free to re-hand-out
//! a still-referenced corpse slot.) The fix floors `high_water` past the corpse run on already-mapped
//! pages in `RecordStore::open`.
//!
//! The failing case reproduces the exact composition that triggers the defect — a **live rollback** of
//! one interleaved multi-self-loop loser **and** a **crash-undo** of a second interleaved
//! multi-self-loop loser — which together leave `first_rel` pointing at a corpse with an uncovered
//! corpse run. The three variants are guard tests that isolate the contributing factors and must keep
//! passing: each on its own does **not** trigger the defect, proving it is specifically the
//! live-rollback + crash-undo composition over a shared rel page.

use graphus_core::TxnId;
use graphus_io::MemBlockDevice;
use graphus_storage::recovery::recover_device;
use graphus_storage::{Namespace, RecordStore};
use graphus_wal::{LogSink, MemLogSink, WalManager};

type Store = RecordStore<MemBlockDevice, MemLogSink>;

fn fresh() -> Store {
    let device = MemBlockDevice::new(0);
    let wal = WalManager::create(MemLogSink::new()).expect("create wal");
    RecordStore::create(device, wal, 256, 1).expect("create store")
}

/// Crashes the store: takes the durable WAL prefix, replays it onto a fresh device via
/// `recover_device` (ARIES redo + loser undo), and reopens the recovered store.
fn recover_no_force(store: &Store) -> Store {
    let log = store.with_wal(|w| w.sink().durable_bytes().to_vec());
    let mut sink = MemLogSink::new();
    sink.append(&log);
    sink.sync().expect("sync log prefix");
    let mut device = MemBlockDevice::new(0);
    let mut wal = WalManager::open(sink.clone()).expect("open wal");
    recover_device(&mut wal, &mut device).expect("recover");
    let wal = WalManager::open(sink).expect("reopen wal");
    RecordStore::open(device, wal, 256).expect("open store")
}

/// The full seed-11731 composition: a live-rolled-back multi-self-loop loser (txn5) interleaved with
/// an in-flight-at-crash multi-self-loop loser (txn6), on top of two committed self-loops (txn3). The
/// crash-undo of txn6 leaves `node1.first_rel` pointing at a txn5 corpse; recovery must still cover
/// the corpse run so the two committed self-loops stay readable.
#[test]
fn crash_recovery_keeps_committed_self_loops_through_interleaved_loser_corpses() {
    let mut s = fresh();
    let rt = s.intern_token(Namespace::RelType, "KNOWS").unwrap();

    // txn1: create node 1 (committed). txn2 begins, stays empty.
    s.begin(TxnId(1));
    let (n1, _) = s.create_node(TxnId(1)).unwrap();
    s.begin(TxnId(2));
    s.commit(TxnId(1)).unwrap();
    assert_eq!(n1, 1);

    // txn3: two self-loops id1,id2 (committed). txn2 rolled back (empty). txn4 begins, empty.
    s.begin(TxnId(3));
    let (r1, _) = s.create_rel(TxnId(3), rt, n1, n1).unwrap(); // id1
    s.rollback(TxnId(2)).unwrap();
    s.begin(TxnId(4));
    let (r2, _) = s.create_rel(TxnId(3), rt, n1, n1).unwrap(); // id2
    s.commit(TxnId(3)).unwrap();
    s.commit(TxnId(4)).unwrap(); // empty

    // txn5 (LOSER, rolled back live) and txn6 (LOSER, in-flight at crash) interleave self-loops.
    s.begin(TxnId(5));
    let _ = s.create_rel(TxnId(5), rt, n1, n1).unwrap(); // id3
    s.begin(TxnId(6));
    let _ = s.create_rel(TxnId(6), rt, n1, n1).unwrap(); // id4
    let _ = s.create_rel(TxnId(5), rt, n1, n1).unwrap(); // id5
    let _ = s.create_rel(TxnId(6), rt, n1, n1).unwrap(); // id6
    let _ = s.create_rel(TxnId(6), rt, n1, n1).unwrap(); // id7
    s.rollback(TxnId(5)).unwrap(); // live rollback of id3,id5
    s.begin(TxnId(7));
    // CRASH: txn6 (id4,id6,id7) never committed; txn7 just began.
    // Harden the loser tail so the crash WAL carries it.
    s.with_wal(graphus_wal::WalManager::flush);

    let s = recover_no_force(&s);

    // The committed edges are the two txn3 self-loops r1,r2. They must survive and the chain must be
    // well-formed (no cycle/malformed), threading through the loser corpses to NULL.
    let mut incident = s.incident_rels(n1).unwrap();
    incident.sort_unstable();
    assert_eq!(
        incident,
        vec![r1, r2],
        "after crash recovery node 1 keeps both committed self-loops"
    );
}

/// Variant A: NO live rollback. A txn6 multi-self-loop loser is in-flight at crash, on top of two
/// committed self-loops. Isolates whether multi-self-loop crash-undo alone breaks the chain (it does
/// not — losers undone in LIFO order restore `first_rel` to the committed head).
#[test]
fn variant_a_inflight_multi_self_loop_no_live_rollback() {
    let mut s = fresh();
    let rt = s.intern_token(Namespace::RelType, "KNOWS").unwrap();
    s.begin(TxnId(1));
    let (n1, _) = s.create_node(TxnId(1)).unwrap();
    let (r1, _) = s.create_rel(TxnId(1), rt, n1, n1).unwrap();
    let (r2, _) = s.create_rel(TxnId(1), rt, n1, n1).unwrap();
    s.commit(TxnId(1)).unwrap();

    // txn2: three self-loops, never committed.
    s.begin(TxnId(2));
    let _ = s.create_rel(TxnId(2), rt, n1, n1).unwrap();
    let _ = s.create_rel(TxnId(2), rt, n1, n1).unwrap();
    let _ = s.create_rel(TxnId(2), rt, n1, n1).unwrap();
    s.with_wal(graphus_wal::WalManager::flush);

    let s = recover_no_force(&s);
    let mut incident = s.incident_rels(n1).unwrap();
    incident.sort_unstable();
    assert_eq!(
        incident,
        vec![r1, r2],
        "variant A: committed self-loops survive"
    );
}

/// Variant B: LIVE rollback of a multi-self-loop loser, NO crash. Isolates whether the live rollback
/// of interleaved multi-self-loop prepends breaks the chain on its own (it does not — the committed
/// txn6 keeps a live head, no recovery involved).
#[test]
fn variant_b_live_rollback_multi_self_loop_no_crash() {
    let mut s = fresh();
    let rt = s.intern_token(Namespace::RelType, "KNOWS").unwrap();
    s.begin(TxnId(1));
    let (n1, _) = s.create_node(TxnId(1)).unwrap();
    let (r1, _) = s.create_rel(TxnId(1), rt, n1, n1).unwrap();
    let (r2, _) = s.create_rel(TxnId(1), rt, n1, n1).unwrap();
    s.commit(TxnId(1)).unwrap();

    // txn5 (loser, live rollback) and txn6 (committed) interleave self-loops.
    s.begin(TxnId(5));
    let _ = s.create_rel(TxnId(5), rt, n1, n1).unwrap();
    s.begin(TxnId(6));
    let (r4, _) = s.create_rel(TxnId(6), rt, n1, n1).unwrap();
    let _ = s.create_rel(TxnId(5), rt, n1, n1).unwrap();
    let (r6, _) = s.create_rel(TxnId(6), rt, n1, n1).unwrap();
    let (r7, _) = s.create_rel(TxnId(6), rt, n1, n1).unwrap();
    s.rollback(TxnId(5)).unwrap();
    s.commit(TxnId(6)).unwrap();

    let mut incident = s.incident_rels(n1).unwrap();
    incident.sort_unstable();
    assert_eq!(
        incident,
        vec![r1, r2, r4, r6, r7],
        "variant B: live rollback of multi-self-loop loser keeps committed self-loops"
    );
}

/// Variant C: the seed-11731 shape but txn6 COMMITS (instead of crashing in-flight). Isolates whether
/// the live rollback of txn5 leaves a tangle that breaks even a committed read with no crash (it does
/// not — the committed txn6 head is live and the walk threads through the txn5 corpses).
#[test]
fn variant_c_live_rollback_then_commit_other_loser() {
    let mut s = fresh();
    let rt = s.intern_token(Namespace::RelType, "KNOWS").unwrap();
    s.begin(TxnId(1));
    let (n1, _) = s.create_node(TxnId(1)).unwrap();
    let (r1, _) = s.create_rel(TxnId(1), rt, n1, n1).unwrap();
    let (r2, _) = s.create_rel(TxnId(1), rt, n1, n1).unwrap();
    s.commit(TxnId(1)).unwrap();

    s.begin(TxnId(5));
    let _ = s.create_rel(TxnId(5), rt, n1, n1).unwrap(); // id3
    s.begin(TxnId(6));
    let (r4, _) = s.create_rel(TxnId(6), rt, n1, n1).unwrap(); // id4
    let _ = s.create_rel(TxnId(5), rt, n1, n1).unwrap(); // id5
    let (r6, _) = s.create_rel(TxnId(6), rt, n1, n1).unwrap(); // id6
    let (r7, _) = s.create_rel(TxnId(6), rt, n1, n1).unwrap(); // id7
    s.rollback(TxnId(5)).unwrap();
    s.commit(TxnId(6)).unwrap();

    let mut incident = s.incident_rels(n1).unwrap();
    incident.sort_unstable();
    assert_eq!(
        incident,
        vec![r1, r2, r4, r6, r7],
        "variant C: live rollback leaves a clean tangle for the committed txn6"
    );
}
