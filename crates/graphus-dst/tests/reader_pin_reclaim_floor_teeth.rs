//! Deterministic regression guard for the **reader GC-pin reclaim-floor** invariant (`rmp` #337
//! Slice 2 / #551; the **W2** defense-in-depth guard from the 2026-07 commit-pipeline durability
//! audit).
//!
//! [`TxnCoordinator::gc`] must reclaim MVCC versions at the **reader-safe watermark**
//! [`gc_watermark`](graphus_cypher::TxnCoordinator::gc_watermark) =
//! [`oldest_active_snapshot`](graphus_cypher::TxnCoordinator::oldest_active_snapshot) — the begin
//! timestamp of the oldest still-open reader — and never `snapshot_ts()`. An off-thread reader-pool
//! read registers its snapshot in the active set on the engine thread *before* dispatch, so while it
//! is live the floor is pinned at its snapshot and no version it can still observe is reclaimable.
//! When that reader retires — including via a **rollback** (the seam a per-statement-timeout / Bolt
//! `RESET` reaper would use to abort an in-flight reader) — it leaves the active set atomically, the
//! floor advances, and a subsequent GC reclaims exactly what it had pinned.
//!
//! ## Why this is the seam that locks the invariant
//!
//! The audit's W2 watch-item is that the pin/advance behavior is an **emergent** property of several
//! independent mechanisms (the age reaper excludes auto-commit; `finish_reader` removes the reader
//! from `active` only post-drain; a rollback removes it atomically) rather than one enforced check.
//! A *future* change that rolls back an in-flight reader and then runs maintenance GC could advance
//! `oldest_active_snapshot()` past a still-live reader and enable a premature reclaim. The DST/VOPR
//! harness is inline (single-threaded), so a genuinely off-thread reader is not expressible; but the
//! in-flight reader's *observable state* — its snapshot in the active set — is exactly what pins the
//! floor, and that is coordinator-level. So this drives the **real** [`TxnCoordinator`] derivation
//! (`gc()` → `gc_watermark()` → `oldest_active_snapshot()`) across the reader's begin→rollback
//! lifecycle, asserting both directions with teeth:
//!
//!  1. **The pin holds.** With the reader open, `gc_watermark()` is the reader's snapshot (not
//!     `snapshot_ts()`), and `coordinator.gc()` reclaims nothing the reader can still observe — the
//!     version's slot is retained.
//!  2. **Rollback releases the pin (mirror).** After `coordinator.rollback(reader)` the reader leaves
//!     the active set, `oldest_active_snapshot()` advances, and a second `coordinator.gc()` reclaims
//!     the now-unpinned version, freeing its slot.
//!
//! A regression that made GC ignore the live reader (part 1) OR fail to advance after the rollback
//! (part 2) fires the corresponding assertion.

use graphus_core::{Timestamp, Value};
use graphus_cypher::TxnCoordinator;
use graphus_io::MemBlockDevice;
use graphus_storage::{Namespace, RecordStore};
use graphus_txn::IsolationLevel;
use graphus_wal::{MemLogSink, WalManager};

type Coord = TxnCoordinator<MemBlockDevice, MemLogSink>;

const V1: i64 = 100;
const V2: i64 = 200;

/// A fresh coordinator over the DST in-memory device + log, exactly as the harness builds a store.
fn new_coord() -> Coord {
    let device = MemBlockDevice::new(0);
    let wal = WalManager::create(MemLogSink::new()).expect("create wal");
    // A small pool, like the other GC-watermark guard; the scenario touches a handful of pages.
    let store = RecordStore::create(device, wal, 32, 1).expect("create store");
    TxnCoordinator::new(store)
}

#[test]
fn reader_pins_reclaim_floor_until_it_rolls_back() {
    let mut coord = new_coord();

    // --- t1: create node A with A.p = V1, commit at ts 1 (the committed base the reader observes). ---
    let t1 = coord.begin(IsolationLevel::Serializable);
    let (key, node_a, p1) = coord.with_store_mut(|s| {
        let key = s
            .intern_token(Namespace::PropKey, "p")
            .expect("intern prop key");
        let (a, _) = s.create_node(t1).expect("create node a");
        // Inline integer value → V1 lives entirely in one prop slot (`p1`), so its reclamation is a
        // single observable slot free.
        let p1 = s
            .set_node_property_value(t1, a, key, &Value::Integer(V1))
            .expect("set a.p = V1");
        (key, a, p1)
    });
    let ts1 = coord.commit(t1).expect("commit t1");
    assert_eq!(ts1, Timestamp(1), "the only commit so far is at ts 1");

    // --- An in-flight READER opens on the ts-1 snapshot: the exact active-set state an off-thread
    //     reader-pool read leaves (registered on the engine thread before dispatch). Snapshot
    //     isolation — the auto-commit-reader model (`rmp` #543). ---
    let reader = coord.begin(IsolationLevel::Snapshot);
    assert_eq!(
        coord.oldest_active_snapshot(),
        Some(Timestamp(1)),
        "the open reader pins the GC low-water at its snapshot (ts 1)"
    );

    // --- t2: overwrite A.p = V2 and commit at ts 2 — V1 becomes a tombstone (its xmax committed at 2,
    //     i.e. AFTER the reader's snapshot, so the reader must still see V1). ---
    let t2 = coord.begin(IsolationLevel::Serializable);
    coord.with_store_mut(|s| {
        s.set_node_property_value(t2, node_a, key, &Value::Integer(V2))
            .expect("set a.p = V2");
    });
    let ts2 = coord.commit(t2).expect("commit t2");
    assert_eq!(ts2, Timestamp(2), "the overwrite committed at ts 2");

    // === Part 1 — THE PIN HOLDS. ===
    // The reader is still open, so the safe watermark is its snapshot (1), NOT snapshot_ts (2).
    assert_eq!(
        coord.gc_watermark(),
        Timestamp(1),
        "while the reader is open, gc_watermark() is its snapshot (1), never snapshot_ts (2)"
    );
    // V1's xmax committed at 2, and `2 <= 1` is false, so the reader-safe GC reclaims nothing.
    let live = coord.gc().expect("gc while the reader is live");
    assert_eq!(
        live.reclaimed, 0,
        "a live reader pins the floor at 1; the V1 version (xmax 2) MUST NOT be reclaimed"
    );
    assert!(
        coord.with_store_mut(|s| s.property(p1).expect("read V1's slot").mvcc.in_use()),
        "V1's physical slot must still be in use while the reader can observe it (no lost version)"
    );

    // === Part 2 — ROLLBACK RELEASES THE PIN (mirror). ===
    // Aborting the in-flight reader removes it from the active set atomically, so the floor advances.
    coord
        .rollback(reader)
        .expect("rollback the in-flight reader");
    assert_eq!(
        coord.oldest_active_snapshot(),
        None,
        "after the reader rolls back, no open reader pins the floor"
    );
    // A subsequent GC now runs at the advanced watermark and reclaims exactly what the reader pinned.
    let after = coord.gc().expect("gc after the reader departs");
    assert!(
        after.reclaimed >= 1,
        "once the reader is gone the floor advances past the V1 tombstone, which is now reclaimed \
         (got reclaimed={})",
        after.reclaimed
    );
    assert!(
        !coord.with_store_mut(|s| s.property(p1).expect("read V1's slot").mvcc.in_use()),
        "after the reader departs and GC runs, V1's physical slot must be reclaimed (freed for reuse)"
    );
}
