//! DST regression guard for the GC **min-active-snapshot watermark** accounting (`rmp` #337 Slice 2;
//! the #220 premature-reclamation class).
//!
//! [`graphus_cypher::TxnCoordinator::gc`] derives its [`RecordStore::gc`] watermark from
//! [`oldest_active_snapshot`](graphus_cypher::TxnCoordinator::oldest_active_snapshot) — the begin
//! timestamp of the **oldest still-open reader** — so it can never physically reclaim a version that
//! a live reader's snapshot must still observe. `RecordStore::gc(watermark)` reclaims what no live
//! snapshot can reach any more; if the watermark were `snapshot_ts()` (the latest commit) instead, an
//! older reader's needed version would be destroyed — a lost-version read, an ACID violation.
//!
//! **Where that superseded version lives moved with `rmp` #967, and this file moved with it.** Before
//! #967 an overwrite tombstoned the old `props.store` record (stamping its `xmax`) and prepended a new
//! one, so the reader's version was a physically distinct prop record that GC freed and the free list
//! re-handed out; the teeth were "the slot is freed and reused". After #967 (`D-property-removal` /
//! `D-property-visibility`) the new value is written **in place** into the same cell — which is never
//! freed and never tombstoned by an overwrite — and the superseded value descends onto the entity's
//! **undo chain** as a `SetProperty` delta. The reclaimable garbage is therefore an `undo.store`
//! delta, reported in [`GcPassReport::undo_deltas_reclaimed`](graphus_storage::GcPassReport), and the
//! observable teeth are what the production read path can still resolve at the old reader's snapshot.
//!
//! This is a deterministic, reproducible scenario driven directly through the real engine
//! (`RecordStore` over the DST in-memory device + log, exactly as the DST harness builds it — every
//! step is fixed, so it is the single-threaded interleaving the DST simulator models). It proves the
//! accounting has **teeth** two ways:
//!
//!  1. **The fix holds:** with `watermark = oldest_active_snapshot()` nothing is reclaimed and the old
//!     reader still resolves every version it needs after a concurrent writer commits and GC runs.
//!  2. **The bug is real:** the *same* scenario with `watermark = snapshot_ts()` reclaims that
//!     version, and the old reader can no longer reconstruct it — it reads the value committed
//!     *after* its own snapshot instead, a wrong-row read. This is what the accounting prevents — if
//!     a future change weakened [`gc_watermark`](graphus_cypher::TxnCoordinator::gc_watermark) back
//!     to `snapshot_ts()`, part 1 would start failing.

use graphus_core::{TxnId, Value};
use graphus_io::MemBlockDevice;
use graphus_storage::{Namespace, RecordStore};
use graphus_txn::Snapshot;
use graphus_wal::{MemLogSink, WalManager};

type Store = RecordStore<MemBlockDevice, MemLogSink>;

/// The store + the interned property key + node `a`, after `t1` created `a` with `a.p = V1` and
/// committed it at timestamp 1.
struct Fixture {
    store: Store,
    key: u32,
    node_a: u64,
}

const V1: i64 = 100;
const V2: i64 = 200;

fn build() -> Fixture {
    let device = MemBlockDevice::new(0);
    let wal = WalManager::create(MemLogSink::new()).expect("create wal");
    // A small pool, like the harness; the scenario touches a handful of pages.
    let store: Store = RecordStore::create(device, wal, 32, 1).expect("create store");

    let t1 = TxnId(1);
    store.begin(t1);
    let key = store
        .intern_token(Namespace::PropKey, "p")
        .expect("intern key");
    let (a, _) = store.create_node(t1).expect("create node a");
    // Inline integer value (no overflow heap) → the value lives entirely in one prop cell, so the
    // version the old reader needs is exactly one `SetProperty` delta on `a`'s undo chain.
    store
        .set_node_property_value(t1, a, key, &Value::Integer(V1))
        .expect("set a.p = V1");
    store.commit(t1).expect("commit t1"); // commit timestamp 1
    assert_eq!(
        store.snapshot_ts().0,
        1,
        "the only commit so far is at ts 1"
    );

    Fixture {
        store,
        key,
        node_a: a,
    }
}

/// Resolves the value reader `R` (at `reader_snapshot`) sees for node `a`'s property `key`, exactly
/// as the production read path does (`graphus_cypher::record_graph::read_node_prop_one`). `None`
/// means the reader observes no value for the key at its snapshot.
///
/// The mechanism moved with `rmp` #967 and this helper moved with it, because a helper that resolved
/// a version some *other* way would stop testing what the production reader does. Before #967 every
/// version of a key was a `props.store` cell with its own MVCC stamps, so the resolution was "walk
/// the prepend-ordered chain, keep the first record `is_visible_via` accepts". After #967 the newest
/// version is written in place and the old value descends onto the node's undo chain, which
/// `D-property-visibility` makes the sole oracle — so the resolution is the store's decision-polarity
/// walk, the same one `read_node_prop_one` now calls.
fn reader_resolves(store: &Store, node_a: u64, key: u32, reader_snapshot: Snapshot) -> Option<i64> {
    let decided = store
        .decision_scan_node_properties(node_a, reader_snapshot)
        .expect("reconstruct a's properties at the reader's snapshot");
    let prop = decided.visible_version(key)?;
    let value = store
        .decode_property_value(prop.type_tag, prop.value_inline)
        .expect("decode the visible value");
    match value {
        Value::Integer(i) => Some(i),
        other => panic!("expected an integer property, got {other:?}"),
    }
}

/// The snapshot of a read-only reader `R` that began at timestamp 1 — after `t1` committed `a.p = V1`
/// but before any overwrite. Its owner id is irrelevant to V1's visibility (V1 was committed by `t1`,
/// not by `R`), so any id distinct from every writer in the scenario serves. This is the begin
/// snapshot `TxnCoordinator::oldest_active_snapshot()` would report while `R` is the only open txn.
fn reader_snapshot_at_ts1() -> Snapshot {
    Snapshot::new(TxnId(999), graphus_core::Timestamp(1))
}

/// Part 1 — **the fix holds.** A reader on the old (ts 1) snapshot still resolves V1 after a
/// concurrent writer overwrites the property (committing at ts 2) and a GC pass runs at the
/// reader-safe watermark `oldest_active_snapshot()` = the reader's snapshot (1). The delta carrying
/// V1 was written by the overwrite, which committed at 2, so it is NOT reclaimable at watermark 1
/// (`2 <= 1` is false) and the old reader reads V1.
#[test]
fn old_reader_keeps_its_version_under_safe_watermark() {
    let f = build();
    let reader = reader_snapshot_at_ts1();

    // Before any overwrite the old reader sees V1.
    assert_eq!(
        reader_resolves(&f.store, f.node_a, f.key, reader),
        Some(V1),
        "the old reader sees V1 at ts 1 before the overwrite"
    );

    // A concurrent writer overwrites a.p = V2 and commits at ts 2. The cell now holds V2 in place and
    // V1 is a `SetProperty` delta on a's undo chain, produced by a writer that committed at 2.
    let t2 = TxnId(2);
    f.store.begin(t2);
    f.store
        .set_node_property_value(t2, f.node_a, f.key, &Value::Integer(V2))
        .expect("set a.p = V2");
    f.store.commit(t2).expect("commit t2");
    assert_eq!(
        f.store.snapshot_ts().0,
        2,
        "the overwrite committed at ts 2"
    );

    // GC at the SAFE watermark: the oldest open reader's snapshot is ts 1, so the watermark is 1.
    // (This is exactly what `TxnCoordinator::gc_watermark()` computes when that reader is open.)
    let safe_watermark = reader.ts; // = oldest_active_snapshot() = Timestamp(1)
    let gc_txn = TxnId(3);
    f.store.begin(gc_txn);
    let report = f
        .store
        .gc(gc_txn, safe_watermark)
        .expect("gc at the safe watermark");
    f.store.commit(gc_txn).expect("commit the gc txn");
    // Asserted on the TOTAL reclamation work, because that is where the old reader's version now is.
    // `rmp` #966 reports undo deltas in their own field so that `reclaimed` keeps its pre-#966
    // "live record versions" meaning; since #967 an overwrite creates no prop record and tombstones
    // none, `reclaimed` alone would be 0 here whatever GC did — trivially true, and its mirror in the
    // part-2 test below impossible. The sum can fail in both directions, so both are asserted.
    assert_eq!(
        report.reclaimed + report.undo_deltas_reclaimed,
        0,
        "the safe watermark (1) protects V1, which now lives as a delta on a's undo chain written by \
         a writer that committed at 2: records = {}, undo deltas = {}",
        report.reclaimed,
        report.undo_deltas_reclaimed
    );

    // The old reader still resolves V1 — no data loss. This replaces the pre-#967 check that V1's own
    // physical prop slot was still `in_use()`: after #967 an overwrite neither frees nor tombstones
    // that cell (it holds V2 in place and stays in use however GC behaves), so that check could no
    // longer fail. Resolving the value through the production read path can, and is what the
    // reader-safe watermark actually owes the reader.
    assert_eq!(
        reader_resolves(&f.store, f.node_a, f.key, reader),
        Some(V1),
        "after the safe GC the old reader still reads its V1 version (ACID: no lost version)"
    );

    // Sanity: a fresh reader (snapshot ts 2) correctly sees the new value V2.
    let fresh = Snapshot::new(TxnId(998), f.store.snapshot_ts());
    assert_eq!(
        reader_resolves(&f.store, f.node_a, f.key, fresh),
        Some(V2),
        "a fresh reader at ts 2 sees the overwrite V2"
    );
}

/// Part 2 — **the bug is real (teeth).** The *same* scenario, but GC runs at `snapshot_ts()` (the
/// latest commit, ts 2) — the watermark the accounting must NOT use while a reader on ts 1 is open.
/// The delta carrying V1 was written by a writer that committed at 2 and `2 <= 2` holds, so V1 IS
/// reclaimed and the old reader can no longer reconstruct it, while a reader at the current snapshot
/// still reads the live value V2 — the destruction is specific to the reader the watermark ignored.
/// This is precisely what `oldest_active_snapshot()` prevents.
#[test]
fn old_reader_loses_its_version_under_buggy_snapshot_ts_watermark() {
    let f = build();
    let reader = reader_snapshot_at_ts1();

    assert_eq!(
        reader_resolves(&f.store, f.node_a, f.key, reader),
        Some(V1),
        "the old reader sees V1 at ts 1 before the overwrite"
    );

    // Same overwrite: a.p = V2, committed at ts 2 (V1 pushed onto a's undo chain by that writer).
    let t2 = TxnId(2);
    f.store.begin(t2);
    f.store
        .set_node_property_value(t2, f.node_a, f.key, &Value::Integer(V2))
        .expect("set a.p = V2");
    f.store.commit(t2).expect("commit t2");

    // GC at the BUGGY watermark: `snapshot_ts()` = 2, ignoring the open reader on ts 1.
    let buggy_watermark = f.store.snapshot_ts(); // = Timestamp(2); the bug the accounting prevents
    assert_eq!(buggy_watermark.0, 2);
    let gc_txn = TxnId(3);
    f.store.begin(gc_txn);
    let report = f
        .store
        .gc(gc_txn, buggy_watermark)
        .expect("gc at the buggy watermark");
    f.store.commit(gc_txn).expect("commit the gc txn");
    // The mirror of part 1, on the same total and for the same reason (see the note there): at
    // watermark 2 nothing on a's undo chain is reachable any more, so the delta carrying V1 — the only
    // remaining copy of the old reader's value, since the cell itself was overwritten in place — is
    // reclaimed. On `reclaimed` alone this assertion could never hold after `rmp` #967.
    assert!(
        report.reclaimed + report.undo_deltas_reclaimed >= 1,
        "the buggy watermark (2) reclaims the superseded V1 version (its delta was written by a \
         writer that committed at 2, and 2 <= 2): records = {}, undo deltas = {}",
        report.reclaimed,
        report.undo_deltas_reclaimed
    );

    // The old reader has now LOST its version. THIS is the ACID violation `oldest_active_snapshot()`
    // prevents, and it is the load-bearing assertion of this test: it replaces the pre-#967 "V1's slot
    // is no longer in use" and "the freed slot was handed to the next allocation (LIFO free list)"
    // checks, which asserted a physical mechanism an in-place overwrite no longer has.
    let lost = reader_resolves(&f.store, f.node_a, f.key, reader);
    assert_ne!(
        lost,
        Some(V1),
        "after the buggy GC the old reader can no longer reconstruct V1 — lost version (the bug)"
    );
    // The SHAPE of that loss, which #967 changed and which is worth pinning because it is worse than a
    // missing value: pre-#967 V1 was a separate record, so destroying it left the ts-1 reader with
    // nothing to read. Post-#967 the value it superseded lived only on the undo chain, so destroying
    // that delta leaves the in-place cell standing — and `D-property-visibility` makes the chain the
    // sole oracle, so with no delta to restore V1 the ts-1 reader observes V2, a value committed at 2,
    // strictly after its own snapshot. A wrong-row read rather than an empty one.
    assert_eq!(
        lost,
        Some(V2),
        "the ts-1 reader now observes V2, committed at 2 — a value from after its own snapshot"
    );

    // The live value itself survived the pass: the buggy watermark destroyed the version an open
    // reader still needed, not the property. (A GC regression that emptied the cell outright would
    // fail here while the assertions above still passed.)
    let fresh = Snapshot::new(TxnId(998), f.store.snapshot_ts());
    assert_eq!(
        reader_resolves(&f.store, f.node_a, f.key, fresh),
        Some(V2),
        "the current snapshot still reads the live value V2 after the buggy GC"
    );
}
