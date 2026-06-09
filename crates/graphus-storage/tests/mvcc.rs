//! Storage-layer MVCC regression tests (`04-technical-design.md` §5.2/§5.3/§5.5; `rmp` task #45).
//!
//! These pin the record store's MVCC mechanism directly (the visibility *rule* itself lives in
//! `graphus-txn` and is exercised end-to-end through Cypher in `graphus-cypher`):
//!
//! * a created record is stamped `xmin = in_flight(TxnId)` and **settled** to the commit timestamp
//!   at commit, so a committed version is self-describing;
//! * a delete is an MVCC **tombstone** (`xmax`) that keeps the slot until [`RecordStore::gc`]
//!   physically reclaims it;
//! * the commit-timestamp high-water mark is durable, so timestamps stay strictly monotonic across
//!   a crash + recovery (a reader's snapshot can never alias or regress past a committed version).

use graphus_core::{Timestamp, TxnId, VersionStamp};
use graphus_io::MemBlockDevice;
use graphus_storage::RecordStore;
use graphus_storage::recovery::recover_device;
use graphus_wal::{LogSink, MemLogSink, WalManager};

type Store = RecordStore<MemBlockDevice, MemLogSink>;

fn fresh() -> Store {
    let device = MemBlockDevice::new(0);
    let wal = WalManager::create(MemLogSink::new()).expect("create wal");
    RecordStore::create(device, wal, 64, 1).expect("create store")
}

/// Recovers a no-force crash: replay the durable WAL prefix onto a fresh device and reopen.
fn recover_no_force(store: &Store) -> Store {
    let log = store.with_wal(|w| w.sink().durable_bytes().to_vec());
    let mut sink = MemLogSink::new();
    sink.append(&log);
    sink.sync().expect("sync log prefix");
    let mut device = MemBlockDevice::new(0);
    let mut wal = WalManager::open(sink.clone()).expect("open wal");
    recover_device(&mut wal, &mut device).expect("recover");
    let wal = WalManager::open(sink).expect("reopen wal");
    RecordStore::open(device, wal, 64).expect("open store")
}

#[test]
fn created_ts_is_inflight_before_commit_then_settled_at_commit() {
    let mut s = fresh();
    let txn = TxnId(1);
    s.begin(txn);
    let (id, _eid) = s.create_node(txn).unwrap();

    // Before commit: xmin is the writer's in-flight TxnId, xmax is the live sentinel, and no commit
    // timestamp has been issued yet.
    let mvcc = s.node(id).unwrap().mvcc;
    assert_eq!(
        VersionStamp::from_raw(mvcc.created_ts),
        VersionStamp::InFlight(txn)
    );
    assert_eq!(mvcc.expired_ts, 0);
    assert_eq!(s.snapshot_ts(), Timestamp(0));

    s.commit(txn).unwrap();

    // After commit: xmin is settled to the commit timestamp (1), so the version is self-describing,
    // and the snapshot high-water advanced to it.
    let mvcc = s.node(id).unwrap().mvcc;
    assert_eq!(
        VersionStamp::from_raw(mvcc.created_ts),
        VersionStamp::Committed(Timestamp(1))
    );
    assert_eq!(s.snapshot_ts(), Timestamp(1));
}

#[test]
fn delete_is_a_tombstone_reclaimed_only_by_gc() {
    let mut s = fresh();
    s.begin(TxnId(1));
    let (id, _eid) = s.create_node(TxnId(1)).unwrap();
    s.commit(TxnId(1)).unwrap(); // committed at ts 1

    s.begin(TxnId(2));
    s.delete_node(TxnId(2), id).unwrap();
    s.commit(TxnId(2)).unwrap(); // tombstone xmax committed at ts 2

    // The tombstone keeps the slot in use (an older snapshot could still need it) and stamps xmax;
    // a scan still enumerates the slot (visibility filtering is the reader's concern, layered above).
    let mvcc = s.node(id).unwrap().mvcc;
    assert!(mvcc.in_use(), "a tombstone keeps its slot in use until GC");
    assert_eq!(
        VersionStamp::from_raw(mvcc.expired_ts),
        VersionStamp::Committed(Timestamp(2))
    );
    assert_eq!(s.scan_node_ids().unwrap(), vec![id]);

    // GC at a watermark past the deletion reclaims the slot.
    let watermark = s.snapshot_ts();
    s.begin(TxnId(3));
    let reclaimed = s.gc(TxnId(3), watermark).unwrap();
    s.commit(TxnId(3)).unwrap();
    assert_eq!(reclaimed, 1, "GC reclaimed the one tombstoned node");
    assert!(
        !s.node(id).unwrap().mvcc.in_use(),
        "the reclaimed slot is no longer in use"
    );
    assert!(
        s.scan_node_ids().unwrap().is_empty(),
        "the reclaimed node no longer appears in a scan"
    );
}

#[test]
fn commit_timestamp_high_water_survives_recovery_and_stays_monotonic() {
    let mut s = fresh();
    s.begin(TxnId(1));
    let (first, _eid) = s.create_node(TxnId(1)).unwrap();
    s.commit(TxnId(1)).unwrap(); // ts 1
    assert_eq!(s.snapshot_ts(), Timestamp(1));

    // Crash + recover: the durable commit-timestamp high-water is restored from the metadata page.
    let mut s = recover_no_force(&s);
    assert_eq!(
        s.snapshot_ts(),
        Timestamp(1),
        "the commit-timestamp high-water survives recovery"
    );
    // The committed node's header survives recovery already settled (self-describing, no registry).
    assert_eq!(
        VersionStamp::from_raw(s.node(first).unwrap().mvcc.created_ts),
        VersionStamp::Committed(Timestamp(1))
    );

    // A new transaction after recovery gets a strictly greater timestamp — no alias, no regression.
    s.begin(TxnId(2));
    let (second, _eid) = s.create_node(TxnId(2)).unwrap();
    s.commit(TxnId(2)).unwrap();
    assert_eq!(s.snapshot_ts(), Timestamp(2));
    assert_eq!(
        VersionStamp::from_raw(s.node(second).unwrap().mvcc.created_ts),
        VersionStamp::Committed(Timestamp(2))
    );
}
