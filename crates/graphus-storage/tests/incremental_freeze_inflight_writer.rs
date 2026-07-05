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
//! that through the real MVCC visibility path (`graphus_txn::is_visible`) — NOT merely the physical
//! chain length, which stays 1 even when the value is unresolvable.

use graphus_core::{TxnId, Value};
use graphus_io::MemBlockDevice;
use graphus_storage::{Namespace, RecordStore};
use graphus_txn::{CommitRegistry, Snapshot, is_visible};
use graphus_wal::{MemLogSink, WalManager};

type Store = RecordStore<MemBlockDevice, MemLogSink>;

fn fresh() -> Store {
    let device = MemBlockDevice::new(0);
    let wal = WalManager::create(MemLogSink::new()).expect("create wal");
    RecordStore::create(device, wal, 32, 1).expect("create store")
}

/// The value a reader at `reader` sees for `node`'s property `key`, resolved exactly as the production
/// read path does: walk the chain, keep the first record of `key` that `is_visible` to `reader`.
fn visible_value(store: &Store, node: u64, key: u32, reader: Snapshot) -> Option<i64> {
    let registry: CommitRegistry = store.commit_registry().clone();
    for (_pid, prop) in store.node_properties(node).expect("walk property chain") {
        if prop.key != key {
            continue;
        }
        if !is_visible(
            reader,
            prop.mvcc.created_ts,
            prop.mvcc.expired_ts,
            &registry,
        ) {
            continue;
        }
        return match store
            .decode_property_value(prop.type_tag, prop.value_inline)
            .expect("decode visible value")
        {
            Value::Integer(i) => Some(i),
            other => panic!("expected an integer property, got {other:?}"),
        };
    }
    None
}

#[test]
fn committed_value_survives_a_gc_that_ran_while_its_writer_was_in_flight() {
    let mut s = fresh();
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
    let reader = Snapshot {
        owner: TxnId(9999),
        ts: s.snapshot_ts(),
    };
    assert_eq!(
        visible_value(&s, n, key, reader),
        Some(2),
        "the committed value n.v=2 must remain visible after a GC that ran while its writer (t2) was \
         in-flight, then forgot t2 — a stranded, never-frozen committed stamp is silent data loss"
    );
}
