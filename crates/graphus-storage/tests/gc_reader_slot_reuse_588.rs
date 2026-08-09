//! Regression: `rmp` #588 (sprint-52 Finding B1) — maintenance GC must not REUSE a freed physical
//! slot while an off-thread reader that predates the free may still be walking a chain through it.
//!
//! An off-thread reader-pool worker walks an incidence chain lock-free, hop-by-hop, caching
//! `predecessor.next = X` across an unlatched hop. If, between caching it and reading X, the engine
//! thread runs a maintenance GC that frees X's slot AND a later create reuses it, the reader reads a
//! FOREIGN record at X and diverts — a committed live edge below X becomes invisible (or a foreign one
//! is reported / the chain reads malformed). That is an ACID Isolation violation.
//!
//! The fix shadow-holds a GC-freed slot from reuse (`RecordStore::set_reuse_barrier` /
//! `release_held`) until every transaction that predates the free has retired. A held slot keeps its
//! record body intact, so the reader threads correctly THROUGH the preserved corpse to the live
//! record below it. This test drives the exact interleaving deterministically and asserts the live
//! edge stays reachable while the reader is "in flight", and that reuse resumes once it retires.

use graphus_io::MemBlockDevice;
use graphus_storage::{NULL_ID, Namespace, RecordStore};
use graphus_wal::{MemLogSink, WalManager};

fn fresh(cap: usize) -> RecordStore<MemBlockDevice, MemLogSink> {
    let device = MemBlockDevice::new(0);
    let wal = WalManager::create(MemLogSink::new()).expect("create wal");
    RecordStore::create(device, wal, cap, 1).expect("create store")
}

/// One GC pass under a reuse barrier `barrier` (models the engine bracketing a maintenance GC while a
/// transaction with a smaller ticket is open): freed slots are shadow-held until `release_held`.
fn gc_pass_with_barrier(
    s: &mut RecordStore<MemBlockDevice, MemLogSink>,
    txn: graphus_core::TxnId,
    barrier: Option<u64>,
) {
    let watermark = s.snapshot_ts();
    s.set_reuse_barrier(barrier);
    s.begin(txn);
    s.gc(txn, watermark).unwrap();
    s.commit(txn).unwrap();
    s.set_reuse_barrier(None);
}

#[test]
fn gc_freed_slot_is_not_reused_while_an_inflight_reader_may_walk_through_it() {
    let mut s = fresh(256);
    let t = {
        let txn = graphus_core::TxnId(1);
        s.begin(txn);
        let tk = s.intern_token(Namespace::RelType, "LINK").unwrap();
        s.commit(txn).unwrap();
        tk
    };

    // Hub H with three START-side edges H->L1, H->L2, H->L3.
    let txn = graphus_core::TxnId(2);
    s.begin(txn);
    let (h, _) = s.create_node(txn).unwrap();
    let (l1, _) = s.create_node(txn).unwrap();
    let (l2, _) = s.create_node(txn).unwrap();
    let (l3, _) = s.create_node(txn).unwrap();
    s.create_rel(txn, t, h, l1).unwrap();
    s.create_rel(txn, t, h, l2).unwrap();
    s.create_rel(txn, t, h, l3).unwrap();
    s.commit(txn).unwrap();

    let clean = s.incident_rels(h).unwrap();
    assert_eq!(clean.len(), 3);
    let mid = clean[1]; // the corpse-to-be, threaded between clean[0] and clean[2]
    let live_below = clean[2]; // the live edge an in-flight reader must still reach through the corpse

    // Delete the middle edge and commit — a tombstone, still threaded in the chain.
    let txn = graphus_core::TxnId(3);
    s.begin(txn);
    s.delete_rel(txn, mid).unwrap();
    s.commit(txn).unwrap();

    // Model an OFF-THREAD READER in flight with ticket 100 (it pins the GC watermark; MVCC visibility
    // is applied above this layer). The engine's `gc_reuse_barrier` computes `next_ticket + 1`, and
    // `open_tx` issues the reader's ticket == `next_ticket` (post-increment) — so for a reader with the
    // NEWEST ticket 100, the barrier the wiring produces is 101 (strictly greater). This models that
    // wiring faithfully: a reader ticket and the barrier the engine derives from it (`ticket + 1`). A
    // lost `+ 1` (barrier == 100) would let `release_held(100)` free the slot under the newest reader.
    const READER_TICKET: u64 = 100;
    const BARRIER: u64 = READER_TICKET + 1;

    // Capture the reader's shared read view and start the walk: read the predecessor, cache next = mid.
    let view = s.read_view();
    let mut out: Vec<u64> = Vec::new();
    let mut cur = view.node(h).unwrap().first_rel;
    let mut injected = false;
    let mut steps = 0u64;
    while cur != NULL_ID {
        steps += 1;
        assert!(
            steps <= 64,
            "walk did not terminate (malformed chain / cycle)"
        );
        if cur == mid && !injected {
            injected = true;
            // The engine runs a maintenance GC that frees `mid`'s slot — under the reuse barrier, so the
            // slot is SHADOW-HELD (the reader with ticket 100 < 101 is still in flight) ...
            gc_pass_with_barrier(&mut s, graphus_core::TxnId(4), Some(BARRIER));
            assert_eq!(
                s.held_slots_len_of(graphus_storage::StoreKind::Rel),
                1,
                "the freed slot must be shadow-held from reuse"
            );
            // ... and a later, UNRELATED create must therefore NOT reuse `mid`'s slot (it grows a fresh
            // id instead), leaving `mid`'s preserved corpse body intact for the in-flight reader.
            let txn = graphus_core::TxnId(5);
            s.begin(txn);
            let (p, _) = s.create_node(txn).unwrap();
            let (q, _) = s.create_node(txn).unwrap();
            let reused = s.create_rel(txn, t, p, q).unwrap().0;
            s.commit(txn).unwrap();
            assert_ne!(
                reused, mid,
                "a held slot must NOT be reused while a predating reader is in flight"
            );
        }
        let r = view.rel(cur).unwrap();
        if r.mvcc.in_use() && (r.start_node == h || r.end_node == h) {
            out.push(cur);
        }
        cur = if r.start_node == h {
            r.start_next_rel
        } else {
            // end-side (or a foreign reused slot: mirror incident_rels' branch).
            r.end_next_rel
        };
    }

    // The fix holds: the in-flight reader still threads through the preserved corpse to the live edge.
    assert!(
        out.contains(&live_below),
        "#588: an in-flight reader must still reach the committed live edge {live_below} below a \
         GC-freed corpse (out={out:?})"
    );

    // BOUNDARY (the #588 off-by-one guard): while the newest reader (ticket == READER_TICKET) is still
    // the oldest open, `release_held(READER_TICKET)` must NOT free the slot — barrier (101) > oldest-open
    // (100). A lost `+ 1` in the wiring would make barrier == 100 and free it here, under the reader.
    s.release_held(READER_TICKET);
    assert_eq!(
        s.held_slots_len_of(graphus_storage::StoreKind::Rel),
        1,
        "#588 boundary: the newest in-flight reader (oldest open) must keep its held slot protected"
    );

    // Once the reader retires (oldest open ticket reaches the barrier), the slot is released and reuse
    // resumes — the hold is not a permanent leak.
    s.release_held(BARRIER); // oldest_open_ticket = 101 >= barrier 101 => release
    assert_eq!(
        s.held_slots_len(),
        0,
        "every held slot — record and undo-area alike — must be released once no predating reader \
         remains"
    );
    let txn = graphus_core::TxnId(6);
    s.begin(txn);
    let (p2, _) = s.create_node(txn).unwrap();
    let (q2, _) = s.create_node(txn).unwrap();
    let reused_now = s.create_rel(txn, t, p2, q2).unwrap().0;
    s.commit(txn).unwrap();
    assert_eq!(
        reused_now, mid,
        "after release, the freed slot is reusable again (no space leak)"
    );
    let _ = (l1, l2, l3, READER_TICKET);
}

/// Regression: `rmp` #811 — the SIBLING hole `#588`'s reuse barrier does not close.
///
/// `#588` (above) proved a GC-freed slot is not REUSED under an in-flight reader. But `held_slots`
/// only defers re-allocation; it never guarded the phase-3 ZEROING of a **dead-link corpse** (a rel
/// slot left by an ABORTED create, reclaimed via `gc_splice_corpses`, NOT the tombstone path through
/// the already-body-preserving `reclaim_rel`). The old phase 3 wrote `RelRecord::new(id, 0, 0, 0, 0)`,
/// so an off-thread reader that entered hub's incidence walk holding `cur == corpse` BEFORE phase 2
/// bridged it out, and read the corpse AFTER phase 3, saw a zeroed forward pointer, terminated its
/// walk, and SILENTLY DROPPED every live rel threaded below the corpse — a wrong (short) traversal, an
/// ACID Isolation defect a two-thread reproduction confirmed. The fix makes phase 3 preserve the body
/// exactly as `reclaim_rel` does.
///
/// FAILS on the pre-fix zeroing phase 3: the reader's `out` loses the live rel below the corpse.
#[test]
fn a_gc_freed_dead_link_corpse_still_threads_an_inflight_reader_to_the_live_rel_below_811() {
    let s = fresh(256);
    let t = {
        let txn = graphus_core::TxnId(1);
        s.begin(txn);
        let tk = s.intern_token(Namespace::RelType, "LINK").unwrap();
        s.commit(txn).unwrap();
        tk
    };

    // Committed hub H + three leaves.
    let txn = graphus_core::TxnId(2);
    s.begin(txn);
    let (h, _) = s.create_node(txn).unwrap();
    let (l1, _) = s.create_node(txn).unwrap();
    let (l2, _) = s.create_node(txn).unwrap();
    let (l3, _) = s.create_node(txn).unwrap();
    s.commit(txn).unwrap();

    // Three interleaved prepends onto H. The MIDDLE (r2) is rolled back LIVE while r1/r3 commit, so it
    // becomes a dead-link corpse (aborted create -> gc_splice_corpses, not a tombstone). create_rel
    // prepends, so the physical chain is H -> r3 -> r2(corpse) -> r1.
    let (t1, t2, t3) = (
        graphus_core::TxnId(3),
        graphus_core::TxnId(4),
        graphus_core::TxnId(5),
    );
    s.begin(t1);
    s.begin(t2);
    s.begin(t3);
    let r1 = s.create_rel(t1, t, h, l1).unwrap().0;
    let r2 = s.create_rel(t2, t, h, l2).unwrap().0;
    let r3 = s.create_rel(t3, t, h, l3).unwrap().0;
    s.commit(t1).unwrap();
    s.rollback(t2).unwrap(); // the middle writer aborts: r2 is a dead-link corpse
    s.commit(t3).unwrap();

    assert!(
        !s.rel(r2).unwrap().mvcc.in_use(),
        "r2 must be a not-in-use corpse before GC"
    );

    // An OFF-THREAD READER (the shared Arc<pool> view) walks H's incidence chain hop-by-hop. When it
    // reaches the corpse r2 — poised on it, exactly as it would be if it had cached `r3.next = r2`
    // across an unlatched hop — the engine runs a maintenance GC (phase 2 bridges r3 -> r1, phase 3
    // frees r2). The reader then reads r2 through the SAME shared view.
    let view = s.read_view();
    let mut out: Vec<u64> = Vec::new();
    let mut cur = view.node(h).unwrap().first_rel;
    let mut injected = false;
    let mut steps = 0u64;
    while cur != NULL_ID {
        steps += 1;
        assert!(
            steps <= 64,
            "walk did not terminate (malformed chain / cycle)"
        );
        if cur == r2 && !injected {
            injected = true;
            let watermark = s.snapshot_ts();
            s.begin(graphus_core::TxnId(6));
            s.gc(graphus_core::TxnId(6), watermark).unwrap();
            s.commit(graphus_core::TxnId(6)).unwrap();
            assert!(
                !s.rel(r2).unwrap().mvcc.in_use(),
                "the corpse must be freed by the GC (in-use bit clear)"
            );
        }
        let r = view.rel(cur).unwrap();
        if r.mvcc.in_use() && (r.start_node == h || r.end_node == h) {
            out.push(cur);
        }
        cur = if r.start_node == h {
            r.start_next_rel
        } else {
            r.end_next_rel
        };
    }

    // The in-flight reader must still reach the live edge r1 threaded BELOW the corpse. The pre-fix
    // zeroing severed r2's forward pointer, so the walk terminated at r2 and lost r1.
    assert!(
        out.contains(&r1),
        "#811: an in-flight reader poised on a dead-link corpse before GC must still thread through \
         the freed corpse to the live rel {r1} below it; a zeroed corpse body severs the walk \
         (out={out:?})"
    );
    // r3 (the still-live head) is of course also reached.
    assert!(
        out.contains(&r3),
        "the live head r3 is reached (out={out:?})"
    );
}
