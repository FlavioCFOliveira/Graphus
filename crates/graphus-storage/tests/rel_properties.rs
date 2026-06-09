//! Integration tests for the **relationship-property** value-level API over a real [`RecordStore`]
//! (`04-technical-design.md` §2.3; `05-storage-format.md` §9; `rmp` task #44).
//!
//! Relationship properties mirror the node-property path exactly: a relationship's property chain is
//! rooted at [`RelRecord.first_prop`](graphus_storage::record::RelRecord) — the relationship analogue
//! of `NodeRecord.first_prop` — threaded through the **same** `props.store` records and overflowing
//! `String`/`List` values to the **same** `strings.store` heap (`rmp` task #43). These tests are the
//! relationship counterpart of `tests/overflow_heap.rs`:
//!
//! * **set / get / remove round-trips** for an inline scalar, a multi-block `String`, and a `List`;
//! * **independence** across distinct relationships (one rel's properties never bleed into another);
//! * **`delete_rel` frees the property chain + every overflow chain** (asserted via
//!   [`RecordStore::heap_block_usage`] and a record-leak check — no block, no property leak);
//! * **newest-wins on overwrite** (an overwrite replaces the record and frees the old overflow chain);
//! * **`clear_rel_properties`** frees every overflow chain;
//! * **durability + crash recovery**: a committed relationship property recovers byte-for-byte; an
//!   uncommitted one is rolled back with no leaked blocks.
//!
//! Index seeks + MVCC over these chains remain `rmp` task #39 and are not exercised here.

use graphus_core::{TxnId, Value};
use graphus_io::MemBlockDevice;
use graphus_storage::{BLOCK_PAYLOAD, Namespace, RecordStore};
use graphus_wal::{MemLogSink, WalManager};

type Store = RecordStore<MemBlockDevice, MemLogSink>;

/// A fresh store over an in-memory device + log.
fn fresh() -> Store {
    let device = MemBlockDevice::new(0);
    let wal = WalManager::create(MemLogSink::new()).expect("create wal");
    RecordStore::create(device, wal, 64, 1).expect("create store")
}

/// Creates two nodes and a relationship `a -[:KNOWS]-> b`, returning `(store-positioned-in-txn, rel)`.
/// The caller must drive `txn` (begin already done) and commit.
fn rel_between(s: &mut Store, txn: TxnId) -> u64 {
    let (a, _) = s.create_node(txn).unwrap();
    let (b, _) = s.create_node(txn).unwrap();
    let t = s.intern_token(Namespace::RelType, "KNOWS").unwrap();
    s.create_rel(txn, t, a, b).unwrap().0
}

/// The value bound to `key` in `rel`'s live property set, or `None`.
fn rel_val(s: &mut Store, rel: u64, key: u32) -> Option<Value> {
    s.rel_property_values(rel)
        .unwrap()
        .into_iter()
        .find(|(_, k, _)| *k == key)
        .map(|(_, _, v)| v)
}

/// The number of live (in-use, not freed) property records, derived from a full consistency pass
/// (`ConsistencyReport::live_props`). Used to assert no property-record leak across a delete (mirrors
/// `heap_block_usage` for the overflow heap). The pass is read-only.
fn prop_record_usage(s: &mut Store) -> u64 {
    graphus_storage::check::check_store(s, &[])
        .expect("consistency pass")
        .live_props
}

// =================================================================================================
// set / get / remove round-trips: inline scalar, String overflow, List
// =================================================================================================

#[test]
fn inline_scalar_rel_property_round_trips_and_uses_no_heap() {
    let mut s = fresh();
    let txn = TxnId(1);
    s.begin(txn);
    let r = rel_between(&mut s, txn);
    let k_i = s.intern_token(Namespace::PropKey, "since").unwrap();
    let k_b = s.intern_token(Namespace::PropKey, "active").unwrap();
    let k_f = s.intern_token(Namespace::PropKey, "weight").unwrap();

    s.set_rel_property_value(txn, r, k_i, &Value::Integer(1999))
        .unwrap();
    s.set_rel_property_value(txn, r, k_b, &Value::Boolean(true))
        .unwrap();
    s.set_rel_property_value(txn, r, k_f, &Value::Float(1.5))
        .unwrap();

    // Inline scalars allocate no heap blocks.
    assert_eq!(s.heap_block_usage().unwrap(), 0);
    assert_eq!(rel_val(&mut s, r, k_i), Some(Value::Integer(1999)));
    assert_eq!(rel_val(&mut s, r, k_b), Some(Value::Boolean(true)));
    assert_eq!(rel_val(&mut s, r, k_f), Some(Value::Float(1.5)));
    s.commit(txn).unwrap();
}

#[test]
fn string_and_list_rel_values_round_trip_through_the_heap() {
    let mut s = fresh();
    let txn = TxnId(1);
    s.begin(txn);
    let r = rel_between(&mut s, txn);
    let k_s = s.intern_token(Namespace::PropKey, "note").unwrap();
    let k_l = s.intern_token(Namespace::PropKey, "tags").unwrap();

    let long = "z".repeat(BLOCK_PAYLOAD * 3 + 7); // multi-block string
    let list = Value::List(vec![
        Value::String("a".to_owned()),
        Value::String("b".to_owned()),
    ]);
    s.set_rel_property_value(txn, r, k_s, &Value::String(long.clone()))
        .unwrap();
    s.set_rel_property_value(txn, r, k_l, &list).unwrap();

    assert_eq!(rel_val(&mut s, r, k_s), Some(Value::String(long)));
    assert_eq!(rel_val(&mut s, r, k_l), Some(list));
    s.commit(txn).unwrap();
}

#[test]
fn removing_an_overflow_rel_value_frees_its_chain() {
    let mut s = fresh();
    let txn = TxnId(1);
    s.begin(txn);
    let r = rel_between(&mut s, txn);
    let k = s.intern_token(Namespace::PropKey, "note").unwrap();
    s.set_rel_property_value(txn, r, k, &Value::String("y".repeat(BLOCK_PAYLOAD * 3)))
        .unwrap();
    assert_eq!(s.heap_block_usage().unwrap(), 3);

    assert!(s.remove_rel_property_value(txn, r, k).unwrap());
    assert_eq!(s.heap_block_usage().unwrap(), 0, "removal frees the chain");
    // Removing again is a no-op (returns false), not an error.
    assert!(!s.remove_rel_property_value(txn, r, k).unwrap());
    assert!(s.rel_property_values(r).unwrap().is_empty());
    s.commit(txn).unwrap();
}

// =================================================================================================
// Independence across relationships + newest-wins on overwrite
// =================================================================================================

#[test]
fn rel_properties_are_independent_across_relationships() {
    let mut s = fresh();
    let txn = TxnId(1);
    s.begin(txn);
    let (a, _) = s.create_node(txn).unwrap();
    let (b, _) = s.create_node(txn).unwrap();
    let (c, _) = s.create_node(txn).unwrap();
    let t = s.intern_token(Namespace::RelType, "KNOWS").unwrap();
    let r1 = s.create_rel(txn, t, a, b).unwrap().0;
    let r2 = s.create_rel(txn, t, b, c).unwrap().0;
    let k = s.intern_token(Namespace::PropKey, "since").unwrap();

    s.set_rel_property_value(txn, r1, k, &Value::Integer(2001))
        .unwrap();
    s.set_rel_property_value(txn, r2, k, &Value::String("hello".to_owned()))
        .unwrap();

    // Each relationship sees only its own value.
    assert_eq!(rel_val(&mut s, r1, k), Some(Value::Integer(2001)));
    assert_eq!(
        rel_val(&mut s, r2, k),
        Some(Value::String("hello".to_owned()))
    );

    // Removing r1's property leaves r2's intact.
    assert!(s.remove_rel_property_value(txn, r1, k).unwrap());
    assert_eq!(rel_val(&mut s, r1, k), None);
    assert_eq!(
        rel_val(&mut s, r2, k),
        Some(Value::String("hello".to_owned()))
    );
    s.commit(txn).unwrap();
}

#[test]
fn overwriting_an_overflow_rel_value_is_newest_wins_and_frees_old_chain() {
    let mut s = fresh();
    let txn = TxnId(1);
    s.begin(txn);
    let r = rel_between(&mut s, txn);
    let k = s.intern_token(Namespace::PropKey, "note").unwrap();

    let first = Value::String("a".repeat(BLOCK_PAYLOAD * 4)); // 4 blocks
    s.set_rel_property_value(txn, r, k, &first).unwrap();
    assert_eq!(s.heap_block_usage().unwrap(), 4);

    // Overwrite with a 2-block value; the old 4-block chain must be freed (and partly reused).
    let second = Value::String("b".repeat(BLOCK_PAYLOAD + 1)); // 2 blocks
    s.set_rel_property_value(txn, r, k, &second).unwrap();
    assert_eq!(
        s.heap_block_usage().unwrap(),
        2,
        "overwrite frees the old chain; only the new 2-block chain is live"
    );

    // The read returns the new value, and only one property record for the key remains (no shadow).
    let vals = s.rel_property_values(r).unwrap();
    let for_key: Vec<_> = vals.iter().filter(|(_, key, _)| *key == k).collect();
    assert_eq!(
        for_key.len(),
        1,
        "overwrite removes the old record (no shadow)"
    );
    assert_eq!(for_key[0].2, second);
    s.commit(txn).unwrap();
}

// =================================================================================================
// delete_rel frees the property chain + overflow chains (no leak)
// =================================================================================================

#[test]
fn delete_rel_frees_its_property_chain_and_overflow_chains() {
    let mut s = fresh();
    let txn = TxnId(1);
    s.begin(txn);
    let r = rel_between(&mut s, txn);
    let k_inline = s.intern_token(Namespace::PropKey, "since").unwrap();
    let k_str = s.intern_token(Namespace::PropKey, "note").unwrap();
    let k_list = s.intern_token(Namespace::PropKey, "tags").unwrap();

    s.set_rel_property_value(txn, r, k_inline, &Value::Integer(7))
        .unwrap();
    s.set_rel_property_value(
        txn,
        r,
        k_str,
        &Value::String("w".repeat(BLOCK_PAYLOAD * 2 + 3)),
    )
    .unwrap();
    s.set_rel_property_value(
        txn,
        r,
        k_list,
        &Value::List(vec![
            Value::Integer(1),
            Value::Integer(2),
            Value::Integer(3),
        ]),
    )
    .unwrap();

    let blocks_before = s.heap_block_usage().unwrap();
    let props_before = prop_record_usage(&mut s);
    assert!(
        blocks_before >= 3,
        "the String + List allocated heap blocks"
    );
    assert_eq!(props_before, 3, "three live property records before delete");

    // Deleting the relationship must free its three property records AND every overflow chain.
    s.delete_rel(txn, r).unwrap();
    assert_eq!(
        s.heap_block_usage().unwrap(),
        0,
        "delete_rel frees every overflow chain (no block leak)"
    );
    assert_eq!(
        prop_record_usage(&mut s),
        0,
        "delete_rel frees every property record (no record leak)"
    );
    // The relationship is gone.
    assert!(!s.rel(r).unwrap().mvcc.in_use());
    s.commit(txn).unwrap();
}

#[test]
fn clear_rel_properties_frees_every_overflow_chain() {
    let mut s = fresh();
    let txn = TxnId(1);
    s.begin(txn);
    let r = rel_between(&mut s, txn);
    let k1 = s.intern_token(Namespace::PropKey, "a").unwrap();
    let k2 = s.intern_token(Namespace::PropKey, "b").unwrap();
    let k3 = s.intern_token(Namespace::PropKey, "c").unwrap();
    s.set_rel_property_value(txn, r, k1, &Value::String("aaaa".repeat(20)))
        .unwrap();
    s.set_rel_property_value(txn, r, k2, &Value::Integer(7))
        .unwrap(); // inline
    s.set_rel_property_value(
        txn,
        r,
        k3,
        &Value::List(vec![Value::Integer(1), Value::Integer(2)]),
    )
    .unwrap();
    assert!(s.heap_block_usage().unwrap() >= 2);

    let removed = s.clear_rel_properties(txn, r).unwrap();
    assert_eq!(removed, 3, "all three property records are removed");
    assert_eq!(
        s.heap_block_usage().unwrap(),
        0,
        "every overflow chain is freed"
    );
    assert!(s.rel_property_values(r).unwrap().is_empty());
    // The relationship itself survives a property clear (only the chain is freed).
    assert!(s.rel(r).unwrap().mvcc.in_use());
    s.commit(txn).unwrap();
}

#[test]
fn deleting_a_rel_does_not_disturb_a_sibling_rels_properties() {
    let mut s = fresh();
    let txn = TxnId(1);
    s.begin(txn);
    let (a, _) = s.create_node(txn).unwrap();
    let (b, _) = s.create_node(txn).unwrap();
    let (c, _) = s.create_node(txn).unwrap();
    let t = s.intern_token(Namespace::RelType, "KNOWS").unwrap();
    let r1 = s.create_rel(txn, t, a, b).unwrap().0;
    let r2 = s.create_rel(txn, t, b, c).unwrap().0;
    let k = s.intern_token(Namespace::PropKey, "note").unwrap();
    s.set_rel_property_value(txn, r1, k, &Value::String("r1".repeat(BLOCK_PAYLOAD)))
        .unwrap();
    s.set_rel_property_value(txn, r2, k, &Value::String("r2-value".to_owned()))
        .unwrap();

    s.delete_rel(txn, r1).unwrap();
    // r2's property is untouched by r1's deletion.
    assert_eq!(
        rel_val(&mut s, r2, k),
        Some(Value::String("r2-value".to_owned()))
    );
    s.commit(txn).unwrap();
}

// =================================================================================================
// Durability + crash recovery (committed survives; uncommitted rolls back, no leak)
// =================================================================================================

/// Recovers a no-force crash: replay the durable WAL prefix onto a fresh device, then open.
fn recover_no_force(store: &Store) -> Store {
    use graphus_wal::LogSink;
    let log = store.with_wal(|w| w.sink().durable_bytes().to_vec());
    let mut sink = MemLogSink::new();
    sink.append(&log);
    sink.sync().expect("sync log prefix");
    let mut device = MemBlockDevice::new(0);
    let mut wal = WalManager::open(sink.clone()).expect("open wal");
    graphus_storage::recovery::recover_device(&mut wal, &mut device).expect("recover");
    let wal = WalManager::open(sink).expect("reopen wal");
    RecordStore::open(device, wal, 64).expect("open store")
}

#[test]
fn committed_rel_property_survives_a_no_force_crash() {
    let mut s = fresh();
    let txn = TxnId(1);
    s.begin(txn);
    let r = rel_between(&mut s, txn);
    let k = s.intern_token(Namespace::PropKey, "note").unwrap();
    let list = Value::List(vec![
        Value::String("alpha".to_owned()),
        Value::String("beta, a longer element to push past one block boundary cleanly".to_owned()),
    ]);
    s.set_rel_property_value(txn, r, k, &list).unwrap();
    s.commit(txn).unwrap();

    let mut rec = recover_no_force(&s);
    assert_eq!(
        rel_val(&mut rec, r, k),
        Some(list),
        "committed relationship overflow List recovers byte-for-byte"
    );
}

#[test]
fn uncommitted_rel_property_is_rolled_back_after_a_crash() {
    let mut s = fresh();
    // A committed baseline: a relationship with one committed property.
    let t1 = TxnId(1);
    s.begin(t1);
    let r = rel_between(&mut s, t1);
    let k = s.intern_token(Namespace::PropKey, "since").unwrap();
    s.set_rel_property_value(t1, r, k, &Value::Integer(2000))
        .unwrap();
    s.commit(t1).unwrap();

    // An uncommitted loser: set a multi-block String value, then crash before commit.
    let t2 = TxnId(2);
    s.begin(t2);
    s.set_rel_property_value(
        t2,
        r,
        k,
        &Value::String("never committed".repeat(BLOCK_PAYLOAD)),
    )
    .unwrap();
    s.with_wal(graphus_wal::WalManager::flush);

    let mut rec = recover_no_force(&s);
    // The loser's overflow chain was undone (no leaked blocks) and the committed inline value stands.
    assert_eq!(
        rec.heap_block_usage().unwrap(),
        0,
        "the loser's overflow blocks were rolled back, not leaked"
    );
    assert_eq!(
        rel_val(&mut rec, r, k),
        Some(Value::Integer(2000)),
        "the committed inline value survives; the uncommitted overwrite is undone"
    );
}

// =================================================================================================
// Errors: a missing relationship and a non-persistable value
// =================================================================================================

#[test]
fn rel_property_ops_on_a_deleted_rel_are_a_storage_error() {
    let mut s = fresh();
    let txn = TxnId(1);
    s.begin(txn);
    let r = rel_between(&mut s, txn);
    s.delete_rel(txn, r).unwrap();
    let k = s.intern_token(Namespace::PropKey, "since").unwrap();
    assert!(
        s.set_rel_property_value(txn, r, k, &Value::Integer(1))
            .is_err()
    );
    s.commit(txn).unwrap();
}

#[test]
fn non_persistable_rel_value_errors_before_any_mutation() {
    let mut s = fresh();
    let txn = TxnId(1);
    s.begin(txn);
    let r = rel_between(&mut s, txn);
    let k = s.intern_token(Namespace::PropKey, "m").unwrap();
    // A Map is outside the stored-property subtype (`05 §7.2`); encoding fails before any write, so
    // no partial state and no heap blocks are left behind.
    let map = Value::Map(vec![("a".to_owned(), Value::Integer(1))]);
    assert!(s.set_rel_property_value(txn, r, k, &map).is_err());
    assert_eq!(
        s.heap_block_usage().unwrap(),
        0,
        "no orphan blocks on a failed encode"
    );
    assert!(s.rel_property_values(r).unwrap().is_empty());
    s.commit(txn).unwrap();
}
