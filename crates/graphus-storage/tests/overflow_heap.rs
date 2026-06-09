//! Integration tests for the `strings.store` **block-chained overflow heap** and the value-level
//! node-property API (`04-technical-design.md` §2.1, §2.3; `rmp` task #43).
//!
//! Two layers are exercised over a real [`RecordStore`] on an in-memory DST device + log:
//!
//! * the **heap chain ops** ([`RecordStore::alloc_chain`] / [`read_chain`] / [`free_chain`]):
//!   alloc→read round-trips for payloads spanning 1, 2 and many blocks; empty and large payloads;
//!   and free→realloc reuse of freed block ids (no leak);
//! * the **value-level property codec** ([`RecordStore::set_node_property_value`] /
//!   [`node_property_values`]): `String` and `List` values round-trip through the heap, inline
//!   scalars stay inline, and an overwrite/removal frees the old chain (asserted via
//!   [`RecordStore::heap_block_usage`]).
//!
//! [`read_chain`]: graphus_storage::RecordStore::read_chain
//! [`free_chain`]: graphus_storage::RecordStore::free_chain
//! [`node_property_values`]: graphus_storage::RecordStore::node_property_values

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

// =================================================================================================
// Heap chain: alloc -> read round-trips across block counts
// =================================================================================================

#[test]
fn chain_round_trips_single_block() {
    let mut s = fresh();
    let txn = TxnId(1);
    s.begin(txn);
    let payload = b"short"; // < BLOCK_PAYLOAD -> exactly one block
    let head = s.alloc_chain(txn, payload).unwrap();
    assert_eq!(s.read_chain(head).unwrap(), payload);
    s.commit(txn).unwrap();
}

#[test]
fn chain_round_trips_two_blocks() {
    let mut s = fresh();
    let txn = TxnId(1);
    s.begin(txn);
    // BLOCK_PAYLOAD + 1 bytes -> exactly two blocks (boundary).
    let payload: Vec<u8> = (0..=BLOCK_PAYLOAD as u8).collect();
    let head = s.alloc_chain(txn, &payload).unwrap();
    assert_eq!(s.read_chain(head).unwrap(), payload);
    s.commit(txn).unwrap();
}

#[test]
fn chain_round_trips_many_blocks() {
    let mut s = fresh();
    let txn = TxnId(1);
    s.begin(txn);
    // Many blocks, and a payload whose length is not a multiple of BLOCK_PAYLOAD (a partial tail).
    let payload: Vec<u8> = (0..(BLOCK_PAYLOAD * 7 + 13))
        .map(|i| (i % 251) as u8)
        .collect();
    let head = s.alloc_chain(txn, &payload).unwrap();
    assert_eq!(s.read_chain(head).unwrap(), payload);
    s.commit(txn).unwrap();
}

#[test]
fn chain_round_trips_an_empty_payload() {
    let mut s = fresh();
    let txn = TxnId(1);
    s.begin(txn);
    let head = s.alloc_chain(txn, &[]).unwrap();
    // An empty payload still allocates exactly one (empty) block, so the head is a valid pointer.
    assert_ne!(head, 0, "an empty chain still has a non-null head block");
    assert_eq!(s.read_chain(head).unwrap(), Vec::<u8>::new());
    assert_eq!(s.heap_block_usage().unwrap(), 1);
    s.commit(txn).unwrap();
}

#[test]
fn chain_round_trips_a_large_payload() {
    let mut s = fresh();
    let txn = TxnId(1);
    s.begin(txn);
    // 100 KiB spans many heap pages as well as many blocks.
    let payload: Vec<u8> = (0..100_000).map(|i| (i * 7 % 256) as u8).collect();
    let head = s.alloc_chain(txn, &payload).unwrap();
    assert_eq!(s.read_chain(head).unwrap(), payload);
    s.commit(txn).unwrap();
}

#[test]
fn distinct_chains_are_independent() {
    let mut s = fresh();
    let txn = TxnId(1);
    s.begin(txn);
    let a = s.alloc_chain(txn, b"alpha payload one").unwrap();
    let b = s.alloc_chain(txn, b"beta payload two, distinct").unwrap();
    assert_ne!(a, b);
    assert_eq!(s.read_chain(a).unwrap(), b"alpha payload one");
    assert_eq!(s.read_chain(b).unwrap(), b"beta payload two, distinct");
    s.commit(txn).unwrap();
}

// =================================================================================================
// Heap chain: free -> realloc reuses blocks (no leak)
// =================================================================================================

#[test]
fn free_then_realloc_reuses_blocks() {
    let mut s = fresh();
    let txn = TxnId(1);
    s.begin(txn);
    let payload: Vec<u8> = (0..(BLOCK_PAYLOAD * 4)).map(|i| i as u8).collect();
    let head1 = s.alloc_chain(txn, &payload).unwrap();
    let usage_after_alloc = s.heap_block_usage().unwrap();
    assert_eq!(usage_after_alloc, 4, "four-block payload uses four blocks");

    // Free the chain: live usage drops to zero.
    s.free_chain(txn, head1).unwrap();
    assert_eq!(
        s.heap_block_usage().unwrap(),
        0,
        "freed chain has no live blocks"
    );

    // A new chain of the same size reuses the freed ids — the store does not grow its high-water.
    let head2 = s.alloc_chain(txn, &payload).unwrap();
    assert_eq!(
        s.heap_block_usage().unwrap(),
        4,
        "realloc reuses freed blocks (no leak), so live usage is again four"
    );
    assert_eq!(s.read_chain(head2).unwrap(), payload);
    s.commit(txn).unwrap();
}

#[test]
fn reading_a_freed_chain_head_is_an_error_not_garbage() {
    let mut s = fresh();
    let txn = TxnId(1);
    s.begin(txn);
    let head = s.alloc_chain(txn, b"to be freed").unwrap();
    s.free_chain(txn, head).unwrap();
    // The head block id now refers to a freed block; reading must error, never return stale bytes.
    assert!(s.read_chain(head).is_err());
    s.commit(txn).unwrap();
}

// =================================================================================================
// Heap chains are durable + crash-recoverable (committed survives; uncommitted rolls back)
// =================================================================================================

/// Recovers a no-force crash: replay the durable WAL onto a fresh device, then open.
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
fn committed_chain_survives_a_no_force_crash() {
    let mut s = fresh();
    let txn = TxnId(1);
    s.begin(txn);
    let payload: Vec<u8> = (0..(BLOCK_PAYLOAD * 3 + 7))
        .map(|i| (i % 200) as u8)
        .collect();
    let head = s.alloc_chain(txn, &payload).unwrap();
    s.commit(txn).unwrap();

    let mut rec = recover_no_force(&s);
    assert_eq!(
        rec.read_chain(head).unwrap(),
        payload,
        "committed chain recovers byte-for-byte"
    );
}

#[test]
fn uncommitted_chain_is_rolled_back_after_a_crash() {
    let mut s = fresh();
    // A committed baseline chain.
    let t1 = TxnId(1);
    s.begin(t1);
    let kept = s.alloc_chain(t1, b"committed value").unwrap();
    s.commit(t1).unwrap();

    // An uncommitted chain (a loser); harden its tail so undo runs on recovery.
    let t2 = TxnId(2);
    s.begin(t2);
    let _lost = s
        .alloc_chain(t2, b"this is never committed and must be undone")
        .unwrap();
    s.with_wal(graphus_wal::WalManager::flush);

    let mut rec = recover_no_force(&s);
    // The committed chain survives; the loser's blocks are not live (rolled back, not leaked).
    assert_eq!(rec.read_chain(kept).unwrap(), b"committed value");
    assert_eq!(
        rec.heap_block_usage().unwrap(),
        1,
        "only the committed single-block chain is live; the loser's chain was undone"
    );
}

// =================================================================================================
// Value-level node-property API: String/List overflow + inline scalars unchanged
// =================================================================================================

#[test]
fn inline_scalars_stay_inline_and_use_no_heap_blocks() {
    let mut s = fresh();
    let txn = TxnId(1);
    s.begin(txn);
    let (n, _) = s.create_node(txn).unwrap();
    let k_i = s.intern_token(Namespace::PropKey, "i").unwrap();
    let k_f = s.intern_token(Namespace::PropKey, "f").unwrap();
    let k_b = s.intern_token(Namespace::PropKey, "b").unwrap();
    s.set_node_property_value(txn, n, k_i, &Value::Integer(42))
        .unwrap();
    s.set_node_property_value(txn, n, k_f, &Value::Float(1.5))
        .unwrap();
    s.set_node_property_value(txn, n, k_b, &Value::Boolean(true))
        .unwrap();

    // No heap blocks were allocated for inline scalars.
    assert_eq!(s.heap_block_usage().unwrap(), 0);
    let vals = s.node_property_values(n).unwrap();
    let by_key = |key: u32| {
        vals.iter()
            .find(|(_, k, _)| *k == key)
            .map(|(_, _, v)| v.clone())
    };
    assert_eq!(by_key(k_i), Some(Value::Integer(42)));
    assert_eq!(by_key(k_f), Some(Value::Float(1.5)));
    assert_eq!(by_key(k_b), Some(Value::Boolean(true)));
    s.commit(txn).unwrap();
}

#[test]
fn string_and_list_values_round_trip_through_the_property_api() {
    let mut s = fresh();
    let txn = TxnId(1);
    s.begin(txn);
    let (n, _) = s.create_node(txn).unwrap();
    let k_s = s.intern_token(Namespace::PropKey, "s").unwrap();
    let k_l = s.intern_token(Namespace::PropKey, "l").unwrap();

    let long = "x".repeat(BLOCK_PAYLOAD * 3 + 5); // multi-block string
    let list = Value::List(vec![
        Value::Integer(1),
        Value::Integer(2),
        Value::Integer(3),
    ]);
    s.set_node_property_value(txn, n, k_s, &Value::String(long.clone()))
        .unwrap();
    s.set_node_property_value(txn, n, k_l, &list).unwrap();

    let vals = s.node_property_values(n).unwrap();
    let by_key = |key: u32| {
        vals.iter()
            .find(|(_, k, _)| *k == key)
            .map(|(_, _, v)| v.clone())
    };
    assert_eq!(by_key(k_s), Some(Value::String(long)));
    assert_eq!(by_key(k_l), Some(list));
    s.commit(txn).unwrap();
}

#[test]
fn overwriting_an_overflow_value_frees_the_old_chain() {
    let mut s = fresh();
    let txn = TxnId(1);
    s.begin(txn);
    let (n, _) = s.create_node(txn).unwrap();
    let k = s.intern_token(Namespace::PropKey, "s").unwrap();

    let first = Value::String("a".repeat(BLOCK_PAYLOAD * 4)); // 4 blocks
    s.set_node_property_value(txn, n, k, &first).unwrap();
    assert_eq!(s.heap_block_usage().unwrap(), 4);

    // Overwrite with a 2-block value; the old 4-block chain must be freed (and partly reused).
    let second = Value::String("b".repeat(BLOCK_PAYLOAD + 1)); // 2 blocks
    s.set_node_property_value(txn, n, k, &second).unwrap();
    assert_eq!(
        s.heap_block_usage().unwrap(),
        2,
        "overwrite frees the old chain; only the new 2-block chain is live"
    );

    // The read returns the new value, and only one property record for the key remains.
    let vals = s.node_property_values(n).unwrap();
    let for_key: Vec<_> = vals.iter().filter(|(_, key, _)| *key == k).collect();
    assert_eq!(
        for_key.len(),
        1,
        "overwrite removes the old record (no shadow)"
    );
    assert_eq!(for_key[0].2, second);
    s.commit(txn).unwrap();
}

#[test]
fn removing_an_overflow_value_frees_its_chain() {
    let mut s = fresh();
    let txn = TxnId(1);
    s.begin(txn);
    let (n, _) = s.create_node(txn).unwrap();
    let k = s.intern_token(Namespace::PropKey, "s").unwrap();
    s.set_node_property_value(txn, n, k, &Value::String("y".repeat(BLOCK_PAYLOAD * 3)))
        .unwrap();
    assert_eq!(s.heap_block_usage().unwrap(), 3);

    assert!(s.remove_node_property_value(txn, n, k).unwrap());
    assert_eq!(s.heap_block_usage().unwrap(), 0, "removal frees the chain");
    // Removing again is a no-op (returns false), not an error.
    assert!(!s.remove_node_property_value(txn, n, k).unwrap());
    assert!(s.node_property_values(n).unwrap().is_empty());
    s.commit(txn).unwrap();
}

#[test]
fn clearing_all_properties_frees_every_overflow_chain() {
    let mut s = fresh();
    let txn = TxnId(1);
    s.begin(txn);
    let (n, _) = s.create_node(txn).unwrap();
    let k1 = s.intern_token(Namespace::PropKey, "a").unwrap();
    let k2 = s.intern_token(Namespace::PropKey, "b").unwrap();
    let k3 = s.intern_token(Namespace::PropKey, "c").unwrap();
    s.set_node_property_value(txn, n, k1, &Value::String("aaaa".repeat(20)))
        .unwrap();
    s.set_node_property_value(txn, n, k2, &Value::Integer(7))
        .unwrap(); // inline
    s.set_node_property_value(
        txn,
        n,
        k3,
        &Value::List(vec![Value::Integer(1), Value::Integer(2)]),
    )
    .unwrap();
    assert!(s.heap_block_usage().unwrap() >= 2);

    let removed = s.clear_node_properties(txn, n).unwrap();
    assert_eq!(removed, 3, "all three property records are removed");
    assert_eq!(
        s.heap_block_usage().unwrap(),
        0,
        "every overflow chain is freed"
    );
    assert!(s.node_property_values(n).unwrap().is_empty());
    s.commit(txn).unwrap();
}

#[test]
fn committed_overflow_property_survives_a_crash_and_recovers() {
    let mut s = fresh();
    let txn = TxnId(1);
    s.begin(txn);
    let (n, _) = s.create_node(txn).unwrap();
    let k = s.intern_token(Namespace::PropKey, "tags").unwrap();
    let list = Value::List(vec![
        Value::String("alpha".to_owned()),
        Value::String("beta".to_owned()),
        Value::String("gamma, a longer element to push past one block boundary cleanly".to_owned()),
    ]);
    s.set_node_property_value(txn, n, k, &list).unwrap();
    s.commit(txn).unwrap();

    let mut rec = recover_no_force(&s);
    let vals = rec.node_property_values(n).unwrap();
    let v = vals
        .iter()
        .find(|(_, key, _)| *key == k)
        .map(|(_, _, v)| v.clone());
    assert_eq!(
        v,
        Some(list),
        "committed overflow List recovers byte-for-byte"
    );
}
