//! Integration test (DST / mem-backed): a real [`graphus_storage::RecordStore`] runs over the
//! **encrypted** block device, proving the encryption seam is transparent to the storage layer and
//! that **crash-consistency holds under encryption** (rmp #85 acceptance criteria).
//!
//! The flow mirrors `graphus-storage`'s own `crash_recovery.rs` no-force scenario: create nodes +
//! edges, commit (the durable WAL prefix captures the committed work), then model a crash where the
//! data device was never flushed home — recovery must reconstruct every committed change from the
//! WAL alone, replayed onto a **fresh encrypted device** opened with the **same key**. We then assert
//! the graph is intact and the pages decrypt, and that a **wrong key cannot open** the recovered
//! store.

use graphus_core::TxnId;
use graphus_crypto::{EncryptedBlockDevice, KEY_LEN, Keyring, MemRawSlots, SALT_LEN};
use graphus_io::BlockDevice;
use graphus_storage::recovery::recover_device;
use graphus_storage::{Namespace, RecordStore};
use graphus_wal::{LogSink, MemLogSink, WalManager};

type EncMem = EncryptedBlockDevice<MemRawSlots>;
type Store = RecordStore<EncMem, MemLogSink>;

const SALT: [u8; SALT_LEN] = [0x9E; SALT_LEN];

fn keyring(byte: u8) -> Keyring {
    Keyring::from_key_file_bytes(&[byte; KEY_LEN], &SALT).expect("keyring")
}

/// A fresh encrypted device over an empty in-memory backing, with its header written.
fn fresh_device(kr: &Keyring) -> EncMem {
    EncryptedBlockDevice::create(MemRawSlots::new(0), kr, SALT).expect("create encrypted device")
}

/// Builds a fresh store over a fresh encrypted device + in-memory log.
fn fresh_store(kr: &Keyring, cap: usize) -> Store {
    let device = fresh_device(kr);
    let wal = WalManager::create(MemLogSink::new()).expect("create wal");
    RecordStore::create(device, wal, cap, 1).expect("create store")
}

/// The durable WAL bytes of a store (its group-committed log prefix).
fn durable_log(store: &Store) -> Vec<u8> {
    store.with_wal(|w| w.sink().durable_bytes().to_vec())
}

/// Recovers a no-force crash onto a **fresh encrypted device** opened with `kr`: replays the durable
/// WAL prefix, then opens the store.
fn recover_no_force(store: &Store, kr: &Keyring) -> Store {
    let log = durable_log(store);
    let mut sink = MemLogSink::new();
    sink.append(&log);
    sink.sync().expect("sync log prefix");

    let mut device = fresh_device(kr);
    let mut wal = WalManager::open(sink.clone()).expect("open wal");
    recover_device(&mut wal, &mut device).expect("recover onto encrypted device");

    let wal = WalManager::open(sink).expect("reopen wal");
    RecordStore::open(device, wal, 64).expect("open store over encrypted device")
}

#[test]
fn committed_graph_survives_a_crash_over_the_encrypted_device() {
    let kr = keyring(0x01);
    let mut s = fresh_store(&kr, 64);

    let txn = TxnId(1);
    s.begin(txn);
    let (a, eid_a) = s.create_node(txn).unwrap();
    let (b, _) = s.create_node(txn).unwrap();
    let t = s.intern_token(Namespace::RelType, "KNOWS").unwrap();
    let (r, eid_r) = s.create_rel(txn, t, a, b).unwrap();
    s.commit(txn).unwrap();

    // Crash + recover onto a fresh encrypted device with the SAME key. The WAL redo writes every
    // committed page through the encryption seam; the reopened store reads them back decrypted.
    let rec = recover_no_force(&s, &kr);

    assert!(rec.node(a).unwrap().mvcc.in_use());
    assert_eq!(rec.node(a).unwrap().element_id, eid_a);
    assert_eq!(rec.rel(r).unwrap().element_id, eid_r);
    assert_eq!(rec.incident_rels(a).unwrap(), vec![r]);
    assert_eq!(rec.incident_rels(b).unwrap(), vec![r]);
    assert_eq!(rec.token_id(Namespace::RelType, "KNOWS"), Some(t));
}

#[test]
fn uncommitted_work_is_rolled_back_over_the_encrypted_device() {
    let kr = keyring(0x02);
    let mut s = fresh_store(&kr, 64);

    // T1 commits a node.
    let t1 = TxnId(1);
    s.begin(t1);
    let (a, _) = s.create_node(t1).unwrap();
    s.commit(t1).unwrap();

    // T2 creates a node + edge but never commits (a loser); harden its tail so undo runs.
    let t2 = TxnId(2);
    s.begin(t2);
    let (b, _) = s.create_node(t2).unwrap();
    let t = s.intern_token(Namespace::RelType, "E").unwrap();
    let _ = s.create_rel(t2, t, a, b).unwrap();
    s.with_wal(graphus_wal::WalManager::flush);

    let rec = recover_no_force(&s, &kr);

    assert!(rec.node(a).unwrap().mvcc.in_use());
    assert_eq!(
        rec.incident_rels(a).unwrap(),
        Vec::<u64>::new(),
        "the uncommitted edge must be rolled back, exactly as on the plaintext device"
    );
}

#[test]
fn a_wrong_key_cannot_open_the_recovered_store() {
    let kr = keyring(0x03);
    let mut s = fresh_store(&kr, 64);
    let txn = TxnId(1);
    s.begin(txn);
    let _ = s.create_node(txn).unwrap();
    s.commit(txn).unwrap();

    // Capture the durable WAL and recover onto a fresh encrypted device with the RIGHT key, then
    // harden it so the device's header (with the KCV for `kr`) is on the backing.
    let log = durable_log(&s);
    let mut sink = MemLogSink::new();
    sink.append(&log);
    sink.sync().expect("sync log prefix");
    let mut device = fresh_device(&kr);
    {
        let mut wal = WalManager::open(sink.clone()).expect("open wal");
        recover_device(&mut wal, &mut device).expect("recover");
    }
    device.sync_all().expect("harden");

    // Take the backing out and attempt to reopen with a DIFFERENT key: must fail closed at open
    // (KCV mismatch), before any page read.
    let backing = device.into_backing();
    let wrong = keyring(0xFF);
    let err = EncryptedBlockDevice::open(backing, &wrong).expect_err("wrong key must fail to open");
    assert!(matches!(
        err,
        graphus_core::error::GraphusError::Security(_)
    ));
}
