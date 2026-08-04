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
//!     `snapshot_ts()`), `coordinator.gc()` reclaims nothing the reader can still observe, and the
//!     reader's snapshot still resolves the superseded value.
//!  2. **Rollback releases the pin (mirror).** After `coordinator.rollback(reader)` the reader leaves
//!     the active set, `oldest_active_snapshot()` advances, and a second `coordinator.gc()` reclaims
//!     the now-unpinned version — after which that same snapshot can no longer reconstruct it, and
//!     resolves the value committed *after* it instead.
//!
//! A regression that made GC ignore the live reader (part 1) OR fail to advance after the rollback
//! (part 2) fires the corresponding assertion.
//!
//! ## What `rmp` #967 moved, and what it did not
//!
//! **What the pin protects moved; that it must protect it did not.** Before #967 an overwrite
//! tombstoned the old `props.store` record (stamping its `xmax`) and prepended a new one, so the
//! pinned version was a physically distinct prop record and the teeth were "its slot is retained /
//! freed". After #967 (`D-property-removal` / `D-property-visibility`) the new value is written **in
//! place** into the same cell — which an overwrite never frees and never tombstones, so its
//! `in_use()` bit can no longer distinguish a pinned version from a reclaimed one — and the
//! superseded value descends onto the entity's **undo chain** as a `SetProperty` delta. So the
//! reclamation is asserted on the TOTAL work
//! ([`reclaimed`](graphus_storage::GcPassReport::reclaimed) +
//! [`undo_deltas_reclaimed`](graphus_storage::GcPassReport::undo_deltas_reclaimed), which `rmp` #966
//! keeps separate so `reclaimed` retains its "live record versions" meaning), and the retained-slot
//! and freed-slot checks are replaced by the strictly stronger observable consequence: whether the
//! reader's own snapshot can still resolve the superseded value through the production read path.

use graphus_core::{Timestamp, TxnId, Value};
use graphus_cypher::TxnCoordinator;
use graphus_io::MemBlockDevice;
use graphus_storage::{Namespace, RecordStore};
use graphus_txn::{IsolationLevel, Snapshot};
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

/// Resolves the value a reader at `snapshot` observes for node `node`'s property `key`, exactly as
/// the production read path does (`graphus_cypher::record_graph::read_node_prop_one`). `None` means
/// the reader observes no value for that key at its snapshot.
///
/// This goes through [`RecordStore::decision_scan_node_properties`] — the store's decision-polarity
/// walk over the cell **and** the entity's undo chain — because `rmp` #967's `D-property-visibility`
/// makes that chain the sole oracle for a property's visible version; the cell's own `created_ts` is
/// informative only. A helper that reconstructed the value some other way would stop testing what the
/// production reader does, which is the whole point of asserting on it here.
fn resolves(coord: &Coord, node: u64, key: u32, snapshot: Snapshot) -> Option<i64> {
    coord.with_store_mut(|s| {
        let decided = s
            .decision_scan_node_properties(node, snapshot)
            .expect("reconstruct the node's properties at the reader's snapshot");
        let prop = decided.visible_version(key)?;
        let value = s
            .decode_property_value(prop.type_tag, prop.value_inline)
            .expect("decode the visible value");
        match value {
            Value::Integer(i) => Some(i),
            other => panic!("expected an integer property, got {other:?}"),
        }
    })
}

#[test]
fn reader_pins_reclaim_floor_until_it_rolls_back() {
    let mut coord = new_coord();

    // --- t1: create node A with A.p = V1, commit at ts 1 (the committed base the reader observes). ---
    let t1 = coord.begin(IsolationLevel::Serializable);
    let (key, node_a) = coord.with_store_mut(|s| {
        let key = s
            .intern_token(Namespace::PropKey, "p")
            .expect("intern prop key");
        let (a, _) = s.create_node(t1).expect("create node a");
        // Inline integer value → the value lives entirely in one prop cell, so once it is superseded
        // the version the reader pins is exactly one `SetProperty` delta on a's undo chain.
        s.set_node_property_value(t1, a, key, &Value::Integer(V1))
            .expect("set a.p = V1");
        (key, a)
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
    // The reader's own begin snapshot, the one every resolution below is evaluated at.
    let reader_snapshot = Snapshot {
        owner: reader,
        ts: ts1,
    };
    assert_eq!(
        resolves(&coord, node_a, key, reader_snapshot),
        Some(V1),
        "the reader observes V1 at its snapshot before the overwrite"
    );

    // --- t2: overwrite A.p = V2 and commit at ts 2. The cell now holds V2 in place and V1 descends
    //     onto A's undo chain as a delta written by t2, which committed AFTER the reader's snapshot —
    //     so the reader must still be able to reconstruct V1. ---
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
    // The delta carrying V1 was written by t2, which committed at 2, and `2 <= 1` is false, so the
    // reader-safe GC reclaims nothing. Asserted on the TOTAL work (see the module note): since #967 an
    // overwrite creates no prop record and tombstones none, `reclaimed` alone is 0 here whatever GC
    // does — trivially true, and its part-2 mirror impossible. The sum can fail in both directions.
    let live = coord.gc().expect("gc while the reader is live");
    assert_eq!(
        live.reclaimed + live.undo_deltas_reclaimed,
        0,
        "a live reader pins the floor at 1; the version it still observes MUST NOT be reclaimed \
         (records = {}, undo deltas = {})",
        live.reclaimed,
        live.undo_deltas_reclaimed
    );
    // The observable consequence, and the semantic the retained-slot check stood for: the pinned
    // reader can still reconstruct V1 through the production read path. This replaces the pre-#967
    // `property(p1).mvcc.in_use()` assertion, which an in-place overwrite made unable to fail.
    assert_eq!(
        resolves(&coord, node_a, key, reader_snapshot),
        Some(V1),
        "while it pins the floor, the reader must still resolve V1 (ACID: no lost version)"
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
        after.reclaimed + after.undo_deltas_reclaimed >= 1,
        "once the reader is gone the floor advances past the superseded V1 version, which is now \
         reclaimed (records = {}, undo deltas = {})",
        after.reclaimed,
        after.undo_deltas_reclaimed
    );
    // The mirror of part 1's observable consequence, and what makes the pin non-vacuous: the very same
    // snapshot that resolved V1 while it was pinned can no longer reconstruct it, because the delta
    // holding it is gone. This replaces the pre-#967 `!property(p1).mvcc.in_use()` assertion, which an
    // in-place overwrite made unable to fail — the cell holds V2 and stays in use regardless.
    let unpinned = resolves(&coord, node_a, key, reader_snapshot);
    assert_ne!(
        unpinned,
        Some(V1),
        "after the reader departs and GC runs, its snapshot can no longer reconstruct V1 — exactly \
         the loss the pin was preventing"
    );
    // The shape of that loss, pinned for the same reason as in `gc_watermark_teeth.rs`: post-#967 the
    // superseded value lives only on the undo chain, so reclaiming the chain leaves the in-place cell
    // standing and the departed reader's snapshot now resolves V2 — a value committed at 2, after that
    // snapshot. Reclaiming it while the reader was live would therefore have been a wrong-row read,
    // not merely a missing value: strictly worse, and exactly what part 1 proves the pin prevents.
    assert_eq!(
        unpinned,
        Some(V2),
        "with the pinned version reclaimed, the ts-1 snapshot resolves V2 — committed after it"
    );
    // ...and the reclamation was targeted, not a wholesale wipe: the live value survives it. (A GC
    // regression that emptied the cell outright would fail here while the assertions above passed.)
    let current = Snapshot {
        owner: TxnId(9_999),
        ts: coord.with_store_mut(|s| s.snapshot_ts()),
    };
    assert_eq!(
        resolves(&coord, node_a, key, current),
        Some(V2),
        "GC reclaimed only what the departed reader had pinned: the live value V2 survives"
    );
}
