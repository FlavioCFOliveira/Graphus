//! DST regression guard for the GC **min-active-snapshot watermark** accounting (`rmp` #337 Slice 2;
//! the #220 premature-reclamation class).
//!
//! [`graphus_cypher::TxnCoordinator::gc`] derives its [`RecordStore::gc`] watermark from
//! [`oldest_active_snapshot`](graphus_cypher::TxnCoordinator::oldest_active_snapshot) — the begin
//! timestamp of the **oldest still-open reader** — so it can never physically reclaim a version that
//! a live reader's snapshot must still observe. `RecordStore::gc(watermark)` frees a slot whose
//! `xmax` committed `<= watermark` and returns it to the free list for reuse; if the watermark were
//! `snapshot_ts()` (the latest commit) instead, an older reader's needed version would be freed and
//! its slot reused — a lost-version / wrong-row read, an ACID violation.
//!
//! This is a deterministic, reproducible scenario driven directly through the real engine
//! (`RecordStore` over the DST in-memory device + log, exactly as the DST harness builds it — every
//! step is fixed, so it is the single-threaded interleaving the DST simulator models). It proves the
//! accounting has **teeth** two ways:
//!
//!  1. **The fix holds:** with `watermark = oldest_active_snapshot()` the old reader still resolves
//!     every version it needs after a concurrent writer commits and GC runs, and the version's slot
//!     is retained.
//!  2. **The bug is real:** the *same* scenario with `watermark = snapshot_ts()` reclaims that
//!     version, frees + reuses its slot, and the old reader can no longer read it (lost data / a
//!     freed-then-reused slot). This is what the accounting prevents — if a future change weakened
//!     [`gc_watermark`](graphus_cypher::TxnCoordinator::gc_watermark) back to `snapshot_ts()`, part 1
//!     would start failing.

use graphus_core::{TxnId, Value};
use graphus_io::MemBlockDevice;
use graphus_storage::{Namespace, RecordStore};
use graphus_txn::{CommitRegistry, Snapshot, is_visible};
use graphus_wal::{MemLogSink, WalManager};

type Store = RecordStore<MemBlockDevice, MemLogSink>;

/// The store + the interned property key + node `a`, after `t1` created `a` with `a.p = V1` and
/// committed it at timestamp 1. `p1` is the physical id of the V1 property record.
struct Fixture {
    store: Store,
    key: u32,
    node_a: u64,
    p1: u64,
}

const V1: i64 = 100;
const V2: i64 = 200;
const V3: i64 = 300;

fn build() -> Fixture {
    let device = MemBlockDevice::new(0);
    let wal = WalManager::create(MemLogSink::new()).expect("create wal");
    // A small pool, like the harness; the scenario touches a handful of pages.
    let mut store: Store = RecordStore::create(device, wal, 32, 1).expect("create store");

    let t1 = TxnId(1);
    store.begin(t1);
    let key = store
        .intern_token(Namespace::PropKey, "p")
        .expect("intern key");
    let (a, _) = store.create_node(t1).expect("create node a");
    // Inline integer value (no overflow heap) → the V1 record lives entirely in one prop slot.
    let p1 = store
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
        p1,
    }
}

/// Resolves the value reader `R` (at `reader_snapshot`) sees for node `a`'s property `key`, exactly
/// as the production read path does (`graphus_cypher::record_graph::read_node_prop_one`): walk the
/// prepend-ordered property chain, keep the first record of `key` that `is_visible` to `R`, decode
/// its value. `None` means the reader observes no value for the key at its snapshot.
fn reader_resolves(store: &Store, node_a: u64, key: u32, reader_snapshot: Snapshot) -> Option<i64> {
    let registry: CommitRegistry = store.commit_registry().clone();
    let chain = store
        .node_properties(node_a)
        .expect("walk a's property chain");
    for (_pid, prop) in chain {
        if prop.key != key {
            continue;
        }
        if !is_visible(
            reader_snapshot,
            prop.mvcc.created_ts,
            prop.mvcc.expired_ts,
            &registry,
        ) {
            continue;
        }
        let value = store
            .decode_property_value(prop.type_tag, prop.value_inline)
            .expect("decode the visible value");
        return match value {
            Value::Integer(i) => Some(i),
            other => panic!("expected an integer property, got {other:?}"),
        };
    }
    None
}

/// The snapshot of a read-only reader `R` that began at timestamp 1 — after `t1` committed `a.p = V1`
/// but before any overwrite. Its owner id is irrelevant to V1's visibility (V1 was committed by `t1`,
/// not by `R`), so any id distinct from every writer in the scenario serves. This is the begin
/// snapshot `TxnCoordinator::oldest_active_snapshot()` would report while `R` is the only open txn.
fn reader_snapshot_at_ts1() -> Snapshot {
    Snapshot {
        owner: TxnId(999),
        ts: graphus_core::Timestamp(1),
    }
}

/// Part 1 — **the fix holds.** A reader on the old (ts 1) snapshot still resolves V1 after a
/// concurrent writer overwrites the property (committing at ts 2) and a GC pass runs at the
/// reader-safe watermark `oldest_active_snapshot()` = the reader's snapshot (1). V1 is NOT
/// reclaimable (its `xmax` committed at 2, and `2 <= 1` is false), so the old reader reads it.
#[test]
fn old_reader_keeps_its_version_under_safe_watermark() {
    let mut f = build();
    let reader = reader_snapshot_at_ts1();

    // Before any overwrite the old reader sees V1.
    assert_eq!(
        reader_resolves(&f.store, f.node_a, f.key, reader),
        Some(V1),
        "the old reader sees V1 at ts 1 before the overwrite"
    );

    // A concurrent writer overwrites a.p = V2 and commits at ts 2 (V1 is now a tombstone, xmax=2).
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
    assert_eq!(
        report.reclaimed, 0,
        "the safe watermark (1) protects the V1 tombstone (xmax committed at 2): nothing reclaimed"
    );

    // The V1 record is retained in its slot, and the old reader still resolves V1 — no data loss.
    assert!(
        f.store
            .property(f.p1)
            .expect("read V1's slot")
            .mvcc
            .in_use(),
        "V1's physical slot must still be in use after a safe GC"
    );
    assert_eq!(
        reader_resolves(&f.store, f.node_a, f.key, reader),
        Some(V1),
        "after the safe GC the old reader still reads its V1 version (ACID: no lost version)"
    );

    // Sanity: a fresh reader (snapshot ts 2) correctly sees the new value V2.
    let fresh = Snapshot {
        owner: TxnId(998),
        ts: f.store.snapshot_ts(),
    };
    assert_eq!(
        reader_resolves(&f.store, f.node_a, f.key, fresh),
        Some(V2),
        "a fresh reader at ts 2 sees the overwrite V2"
    );
}

/// Part 2 — **the bug is real (teeth).** The *same* scenario, but GC runs at `snapshot_ts()` (the
/// latest commit, ts 2) — the watermark the accounting must NOT use while a reader on ts 1 is open.
/// V1's `xmax` committed at 2 and `2 <= 2` holds, so V1 IS reclaimed: its slot is freed, then reused
/// by a later write with foreign content (V3). The old reader can no longer read V1 — a lost-version
/// read off a freed-and-reused slot. This is precisely what `oldest_active_snapshot()` prevents.
#[test]
fn old_reader_loses_its_version_under_buggy_snapshot_ts_watermark() {
    let mut f = build();
    let reader = reader_snapshot_at_ts1();

    assert_eq!(
        reader_resolves(&f.store, f.node_a, f.key, reader),
        Some(V1),
        "the old reader sees V1 at ts 1 before the overwrite"
    );

    // Same overwrite: a.p = V2, committed at ts 2 (V1 tombstoned with xmax=2).
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
    assert!(
        report.reclaimed >= 1,
        "the buggy watermark (2) reclaims the V1 tombstone (xmax committed at 2 <= 2): \
         reclaimed = {}",
        report.reclaimed
    );

    // The V1 slot was physically freed (no longer in use) — the freed-slot half of the violation.
    assert!(
        !f.store
            .property(f.p1)
            .expect("read V1's old slot")
            .mvcc
            .in_use(),
        "the buggy GC freed V1's physical slot"
    );

    // The old reader has now LOST its version: walking a.p at ts 1 finds only V2 (invisible to it,
    // committed at 2 > 1), so it resolves nothing — a committed value that was live for this reader
    // is gone. THIS is the ACID violation `oldest_active_snapshot()` prevents.
    assert_eq!(
        reader_resolves(&f.store, f.node_a, f.key, reader),
        None,
        "after the buggy GC the old reader can no longer read V1 — lost version (the bug)"
    );

    // Drive the freed slot's REUSE to make "reads a freed/reused slot" literal: a new node's property
    // takes V1's just-freed physical slot (the free list is LIFO), now holding foreign content V3.
    let t4 = TxnId(4);
    f.store.begin(t4);
    let (c, _) = f.store.create_node(t4).expect("create node c");
    let reused = f
        .store
        .set_node_property_value(t4, c, f.key, &Value::Integer(V3))
        .expect("set c.p = V3");
    f.store.commit(t4).expect("commit t4");
    assert_eq!(
        reused, f.p1,
        "the freed V1 slot was reused by the next property allocation (LIFO free list)"
    );
    // The slot the old reader needed for V1 now physically holds a different record (V3).
    let reused_value = f
        .store
        .decode_property_value(
            f.store.property(f.p1).expect("read reused slot").type_tag,
            f.store
                .property(f.p1)
                .expect("read reused slot")
                .value_inline,
        )
        .expect("decode reused slot");
    assert_eq!(
        reused_value,
        Value::Integer(V3),
        "V1's old physical slot now holds foreign content (V3) — a freed-then-reused slot"
    );
}
