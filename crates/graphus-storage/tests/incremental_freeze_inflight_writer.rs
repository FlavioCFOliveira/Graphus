//! Regression: the `rmp` #522 incremental freeze frontier must not strand a committed writer's stamp
//! when a maintenance GC ran while that writer was still in-flight.
//!
//! Reproduces the exact production-reachable sequence:
//!   1. `t1` creates `n.v = 1` and commits.
//!   2. `t2` overwrites `n.v = 2` but does NOT commit yet (an explicit `BEGIN … RUN … ` whose writes
//!      are already in the store with in-flight stamps).
//!   3. A maintenance GC runs under its OWN txn while `t2` is in-flight (GC runs between engine
//!      commands; an open explicit txn is present).
//!   4. `t2` commits.
//!   5. A second maintenance GC runs — its prune forgets `t2` from the commit registry.
//!
//! A fresh reader at the latest snapshot MUST still see `n.v = 2` (a committed value). This asserts
//! that through the real MVCC visibility path (`graphus_txn::is_visible_via`) — NOT merely the physical
//! chain length, which stays 1 even when the value is unresolvable.

use graphus_core::{TxnId, Value};
use graphus_io::MemBlockDevice;
use graphus_storage::{Namespace, RecordStore};
use graphus_txn::Snapshot;
use graphus_wal::{MemLogSink, WalManager};

type Store = RecordStore<MemBlockDevice, MemLogSink>;

fn fresh() -> Store {
    let device = MemBlockDevice::new(0);
    let wal = WalManager::create(MemLogSink::new()).expect("create wal");
    RecordStore::create(device, wal, 32, 1).expect("create store")
}

/// The value a reader at `reader` sees for `node`'s property `key`, resolved exactly as the
/// production read path does.
///
/// **Semantic equivalent of** the retired hand-rolled fold (walk the `first_prop` chain, keep the
/// first record `graphus_txn::is_visible_via` accepts). That fold encoded the retired oracle — the
/// cell's own `created_ts`/`expired_ts` — which after `rmp` #967's `D-property-visibility` decides
/// nothing. It is replaced by the store's own decision-polarity read, which is *stronger* here: the
/// helper can no longer drift from the production rule, because it now IS the production rule.
fn visible_value(store: &Store, node: u64, key: u32, reader: Snapshot) -> Option<i64> {
    let decided = store
        .decision_scan_node_properties(node, reader)
        .expect("decision-polarity property read");
    let seen = decided.visible_version(key)?;
    match store
        .decode_property_value(seen.type_tag, seen.value_inline)
        .expect("decode visible value")
    {
        Value::Integer(i) => Some(i),
        other => panic!("expected an integer property, got {other:?}"),
    }
}

#[test]
fn committed_value_survives_a_gc_that_ran_while_its_writer_was_in_flight() {
    let s = fresh();
    let key = s.intern_token(Namespace::PropKey, "v").unwrap();

    // 1) t1: n.v = 1, commit.
    let t1 = TxnId(1);
    s.begin(t1);
    let (n, _) = s.create_node(t1).unwrap();
    s.set_node_property_value(t1, n, key, &Value::Integer(1))
        .unwrap();
    s.commit(t1).unwrap();

    // 2) t2: overwrite n.v = 2, still IN-FLIGHT (its records are in the store with in-flight stamps).
    let t2 = TxnId(2);
    s.begin(t2);
    s.set_node_property_value(t2, n, key, &Value::Integer(2))
        .unwrap();

    // 3) A maintenance GC runs under its own txn WHILE t2 is in-flight. Its freeze sweep must keep the
    //    freeze frontier covering t2's not-yet-committable records so a later pass can freeze them.
    let gc_a = TxnId(3);
    s.begin(gc_a);
    s.gc(gc_a, s.snapshot_ts()).unwrap();
    s.commit(gc_a).unwrap();

    // 4) t2 commits: n.v = 2 is now a committed value.
    s.commit(t2).unwrap();

    // 5) A second maintenance GC runs; its prune forgets t2 from the commit registry.
    let gc_b = TxnId(4);
    s.begin(gc_b);
    s.gc(gc_b, s.snapshot_ts()).unwrap();
    s.commit(gc_b).unwrap();

    // A fresh reader at the latest snapshot MUST see the committed n.v = 2. If the incremental freeze
    // stranded t2's stamp (never froze it) and the prune forgot t2, the value 2 resolves as INVISIBLE
    // (its in-flight stamp names a now-unknown → treated-as-aborted writer) — silent lost committed
    // data, even though the physical chain still holds the record.
    let reader = Snapshot::new(TxnId(9999), s.snapshot_ts());
    assert_eq!(
        visible_value(&s, n, key, reader),
        Some(2),
        "the committed value n.v=2 must remain visible after a GC that ran while its writer (t2) was \
         in-flight, then forgot t2 — a stranded, never-frozen committed stamp is silent data loss"
    );
}
