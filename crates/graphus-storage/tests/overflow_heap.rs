//! Integration tests for the `strings.store` **block-chained overflow heap** and the value-level
//! node-property API (`04-technical-design.md` §2.1, §2.3; `rmp` task #43).
//!
//! Two layers are exercised over a real [`RecordStore`] on an in-memory DST device + log:
//!
//! * the **heap chain ops** ([`RecordStore::alloc_chain`] / [`read_chain`] / [`free_chain`]):
//!   alloc→read round-trips for payloads spanning 1, 2 and many blocks; empty and large payloads;
//!   and free→realloc reuse of freed block ids (no leak);
//! * the **value-level property codec** ([`RecordStore::set_node_property_value`] /
//!   [`node_property_values`]): `String`, `List` and temporal values round-trip through the heap,
//!   inline scalars stay inline, and an overwrite/removal frees the old chain (asserted via
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

/// Runs one garbage-collection pass under a fresh `txn` (`04 §5.5`; `rmp` task #50). Per-value
/// property MVCC made an overwrite / removal / clear a logical tombstone: the writing transaction
/// stamps the old version's `xmax` and physical reclamation (freeing the property record, its
/// `strings.store` overflow chain, and the record's id, then splicing it out of the chain) is
/// deferred to GC.
///
/// The watermark is [`RecordStore::snapshot_ts`] — the latest commit timestamp. That is the correct
/// (and safe) watermark for these single-threaded tests: the writing transaction has already
/// committed (its `xmax` is therefore committed at or below `snapshot_ts`) and there is no older
/// live reader that could still observe the tombstoned version, so GC reclaims it.
fn gc_pass(s: &mut Store, txn: TxnId) {
    let watermark = s.snapshot_ts();
    s.begin(txn);
    s.gc(txn, watermark).unwrap();
    s.commit(txn).unwrap();
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
fn temporal_values_round_trip_through_the_property_api() {
    use graphus_core::value::temporal::{
        Date, Duration, LocalDateTime, LocalTime, ZonedDateTime, ZonedTime,
    };

    let mut s = fresh();
    let txn = TxnId(1);
    s.begin(txn);
    let (n, _) = s.create_node(txn).unwrap();

    // One property per temporal class (negative components and an empty zone id included), plus a
    // homogeneous list of temporals -- the full overflow temporal surface through the record store.
    let values = [
        (
            "d",
            Value::Date(Date {
                days_since_epoch: -719_528, // 0001-01-01, a pre-epoch date
            }),
        ),
        (
            "lt",
            Value::LocalTime(LocalTime {
                nanos_of_day: 86_399_999_999_999,
            }),
        ),
        (
            "zt",
            Value::ZonedTime(ZonedTime {
                time: LocalTime {
                    nanos_of_day: 43_200_000_000_000,
                },
                offset_seconds: -3600,
            }),
        ),
        (
            "ldt",
            Value::LocalDateTime(LocalDateTime {
                epoch_seconds: -1,
                nanos: 999_999_999,
            }),
        ),
        (
            "zdt",
            Value::ZonedDateTime(ZonedDateTime {
                local: LocalDateTime {
                    epoch_seconds: 1_700_000_000,
                    nanos: 123_456_789,
                },
                offset_seconds: 3600,
                zone_id: "Europe/Lisbon".to_owned(),
            }),
        ),
        (
            "zdt_offset_only",
            Value::ZonedDateTime(ZonedDateTime {
                local: LocalDateTime::default(),
                offset_seconds: -64_800,
                zone_id: String::new(), // offset-only (empty zone id)
            }),
        ),
        (
            "dur",
            Value::Duration(Duration {
                months: -1,
                days: 40,
                seconds: -86_400,
                nanos: 999_999_999,
            }),
        ),
        (
            "dates",
            Value::List(vec![
                Value::Date(Date {
                    days_since_epoch: -1,
                }),
                Value::Date(Date {
                    days_since_epoch: 20_000,
                }),
            ]),
        ),
    ];

    let mut keys = Vec::with_capacity(values.len());
    for (name, value) in &values {
        let k = s.intern_token(Namespace::PropKey, name).unwrap();
        s.set_node_property_value(txn, n, k, value).unwrap();
        keys.push(k);
    }
    // Every temporal value goes through the overflow heap (none fits the 64-bit inline payload).
    assert!(s.heap_block_usage().unwrap() >= values.len() as u64);

    let vals = s.node_property_values(n).unwrap();
    for (k, (name, value)) in keys.iter().zip(&values) {
        let got = vals
            .iter()
            .find(|(_, key, _)| key == k)
            .map(|(_, _, v)| v.clone());
        assert_eq!(got.as_ref(), Some(value), "property {name} must round-trip");
    }
    s.commit(txn).unwrap();
}

#[test]
fn committed_temporal_property_survives_a_crash_and_recovers() {
    use graphus_core::value::temporal::{LocalDateTime, ZonedDateTime};

    let mut s = fresh();
    let txn = TxnId(1);
    s.begin(txn);
    let (n, _) = s.create_node(txn).unwrap();
    let k = s.intern_token(Namespace::PropKey, "when").unwrap();
    let zdt = Value::ZonedDateTime(ZonedDateTime {
        local: LocalDateTime {
            epoch_seconds: 1_700_000_000,
            nanos: 42,
        },
        offset_seconds: 3600,
        zone_id: "Europe/Lisbon".to_owned(),
    });
    s.set_node_property_value(txn, n, k, &zdt).unwrap();
    s.commit(txn).unwrap();

    let mut rec = recover_no_force(&s);
    let vals = rec.node_property_values(n).unwrap();
    let v = vals
        .iter()
        .find(|(_, key, _)| *key == k)
        .map(|(_, _, v)| v.clone());
    assert_eq!(
        v,
        Some(zdt),
        "committed temporal property recovers byte-for-byte"
    );
}

#[test]
fn spatial_point_values_round_trip_through_the_property_api() {
    use graphus_core::value::spatial::{Crs, Point};

    let mut s = fresh();
    let txn = TxnId(1);
    s.begin(txn);
    let (n, _) = s.create_node(txn).unwrap();

    // One property per CRS (2D and 3D), with negative and extreme coordinates included.
    let values = [
        (
            "cart2",
            Value::Point(Point::new_2d(Crs::Cartesian, 1.5, -2.5)),
        ),
        (
            "cart3",
            Value::Point(Point::new_3d(Crs::Cartesian3D, -1.0, 2.0, 3.0)),
        ),
        (
            "wgs2",
            Value::Point(Point::new_2d(Crs::Wgs84, -8.61, 41.15)),
        ),
        (
            "wgs3",
            Value::Point(Point::new_3d(Crs::Wgs84_3D, 12.5, -7.25, 100.0)),
        ),
    ];

    let mut keys = Vec::with_capacity(values.len());
    for (name, value) in &values {
        let k = s.intern_token(Namespace::PropKey, name).unwrap();
        s.set_node_property_value(txn, n, k, value).unwrap();
        keys.push(k);
    }
    // A point does not fit the 64-bit inline payload, so each goes through the overflow heap.
    assert!(s.heap_block_usage().unwrap() >= values.len() as u64);

    let vals = s.node_property_values(n).unwrap();
    for (k, (name, value)) in keys.iter().zip(&values) {
        let got = vals
            .iter()
            .find(|(_, key, _)| key == k)
            .map(|(_, _, v)| v.clone());
        assert_eq!(
            got.as_ref(),
            Some(value),
            "point property {name} must round-trip"
        );
    }
    s.commit(txn).unwrap();
}

#[test]
fn committed_point_property_survives_a_crash_and_recovers() {
    use graphus_core::value::spatial::{Crs, Point};

    let mut s = fresh();
    let txn = TxnId(1);
    s.begin(txn);
    let (n, _) = s.create_node(txn).unwrap();
    let k = s.intern_token(Namespace::PropKey, "loc").unwrap();
    let point = Value::Point(Point::new_2d(Crs::Wgs84, -8.61, 41.15));
    s.set_node_property_value(txn, n, k, &point).unwrap();
    s.commit(txn).unwrap();

    let mut rec = recover_no_force(&s);
    let vals = rec.node_property_values(n).unwrap();
    let v = vals
        .iter()
        .find(|(_, key, _)| *key == k)
        .map(|(_, _, v)| v.clone());
    assert_eq!(
        v,
        Some(point),
        "committed point property recovers byte-for-byte after a crash"
    );
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

    // Overwrite with a 2-block value. Per-value MVCC (`rmp` task #50) tombstones the old 4-block
    // version and prepends the new 2-block one, so both chains are live until GC: the old chain's
    // blocks survive for older snapshots (here: none) and are reclaimed by the GC pass below.
    let second = Value::String("b".repeat(BLOCK_PAYLOAD + 1)); // 2 blocks
    s.set_node_property_value(txn, n, k, &second).unwrap();
    s.commit(txn).unwrap();

    // After commit + GC the tombstoned 4-block version is physically reclaimed (record + overflow
    // blocks + splice), so only the new 2-block chain remains live -- the original no-leak intent.
    gc_pass(&mut s, TxnId(2));
    assert_eq!(
        s.heap_block_usage().unwrap(),
        2,
        "overwrite frees the old chain at GC; only the new 2-block chain is live"
    );

    // The read returns the new value, and only one property record for the key remains.
    let vals = s.node_property_values(n).unwrap();
    let for_key: Vec<_> = vals.iter().filter(|(_, key, _)| *key == k).collect();
    assert_eq!(
        for_key.len(),
        1,
        "the tombstoned old record is spliced out at GC (no shadow)"
    );
    assert_eq!(for_key[0].2, second);
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

    // Per-value MVCC (`rmp` task #50): the removal tombstones the live version (stamps `xmax`); it
    // is no longer a live version, so removing again in the same txn is a no-op (returns false).
    assert!(s.remove_node_property_value(txn, n, k).unwrap());
    assert!(!s.remove_node_property_value(txn, n, k).unwrap());
    s.commit(txn).unwrap();

    // After commit + GC the tombstoned record and its 3-block overflow chain are reclaimed -- the
    // original "removal frees the chain" no-leak intent, now satisfied at GC.
    gc_pass(&mut s, TxnId(2));
    assert_eq!(
        s.heap_block_usage().unwrap(),
        0,
        "removal frees the chain at GC"
    );
    assert!(s.node_property_values(n).unwrap().is_empty());
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

    // Per-value MVCC (`rmp` task #50): clearing tombstones all three live property records.
    let removed = s.clear_node_properties(txn, n).unwrap();
    assert_eq!(removed, 3, "all three live property records are tombstoned");
    s.commit(txn).unwrap();

    // After commit + GC every tombstoned record and its overflow chain is reclaimed -- the original
    // "every overflow chain is freed" no-leak intent, now satisfied at GC.
    gc_pass(&mut s, TxnId(2));
    assert_eq!(
        s.heap_block_usage().unwrap(),
        0,
        "every overflow chain is freed at GC"
    );
    assert!(s.node_property_values(n).unwrap().is_empty());
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
