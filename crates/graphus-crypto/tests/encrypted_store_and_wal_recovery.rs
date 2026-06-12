//! Integration test (DST / mem-backed): a real [`graphus_storage::RecordStore`] runs over **both**
//! an encrypted block device **and** an encrypted WAL sink, proving the two encryption seams compose
//! and that **crash-consistency holds end-to-end under full encryption** (rmp #88 acceptance
//! criteria — the strongest test: create a graph, crash, recover, assert the graph is intact).
//!
//! The flow mirrors `encrypted_store_recovery.rs` (the device-only test), but the WAL is now an
//! [`EncryptedLogSink`] too: the committed work is captured in the encrypted WAL's durable frames,
//! a crash drops everything not group-committed, and recovery replays the decrypted WAL onto a fresh
//! encrypted device opened with the **same key**.

use graphus_core::TxnId;
use graphus_crypto::{
    EncryptedBlockDevice, EncryptedLogSink, KEY_LEN, Keyring, MemRawSlots, SALT_LEN,
};
use graphus_storage::recovery::recover_device;
use graphus_storage::{Namespace, RecordStore};
use graphus_wal::{LogSink, MemLogSink, WalManager};

type EncDevice = EncryptedBlockDevice<MemRawSlots>;
type EncWal = EncryptedLogSink<MemLogSink>;
type Store = RecordStore<EncDevice, EncWal>;

const SALT: [u8; SALT_LEN] = [0xC3; SALT_LEN];

fn keyring(byte: u8) -> Keyring {
    Keyring::from_key_file_bytes(&[byte; KEY_LEN], &SALT).expect("keyring")
}

fn fresh_device(kr: &Keyring) -> EncDevice {
    EncryptedBlockDevice::create(MemRawSlots::new(0), kr, SALT).expect("create encrypted device")
}

fn fresh_wal(kr: &Keyring) -> EncWal {
    EncryptedLogSink::create(MemLogSink::new(), kr).expect("create encrypted WAL sink")
}

fn fresh_store(kr: &Keyring, cap: usize) -> Store {
    let device = fresh_device(kr);
    let wal = WalManager::create(fresh_wal(kr)).expect("create wal");
    RecordStore::create(device, wal, cap, 1).expect("create store")
}

/// The durable *physical* backing bytes of the store's encrypted WAL (its group-committed frames).
fn durable_wal_backing(store: &Store) -> Vec<u8> {
    store.with_wal(|w| w.sink().backing().durable_bytes().to_vec())
}

/// Recovers a no-force crash onto a **fresh encrypted device** + over a **reopened encrypted WAL**,
/// both keyed with `kr`: rebuild the WAL's durable physical prefix, reopen the encrypted sink
/// (decrypting + authenticating its frames), replay onto the fresh device, then open the store.
fn recover_no_force(store: &Store, kr: &Keyring) -> Store {
    let physical = durable_wal_backing(store);

    // Rebuild the encrypted WAL's backing from its durable physical bytes, then reopen the encrypted
    // sink over it (this is the crash-recovery view of the WAL).
    let mut backing = MemLogSink::new();
    backing.append(&physical);
    backing.sync().expect("sync physical prefix");
    let reopened = EncryptedLogSink::open(backing.clone(), kr).expect("reopen encrypted wal");

    let mut device = fresh_device(kr);
    let mut wal = WalManager::open(reopened).expect("open wal");
    recover_device(&mut wal, &mut device).expect("recover onto encrypted device");

    // Reopen the WAL fresh for serving (recovery consumed the recovery view).
    let reopened2 = EncryptedLogSink::open(backing, kr).expect("reopen encrypted wal again");
    let wal = WalManager::open(reopened2).expect("reopen wal");
    RecordStore::open(device, wal, 64).expect("open store over encrypted device + wal")
}

#[test]
fn committed_graph_survives_a_crash_over_encrypted_device_and_wal() {
    let kr = keyring(0x11);
    let mut s = fresh_store(&kr, 64);

    let txn = TxnId(1);
    s.begin(txn);
    let (a, eid_a) = s.create_node(txn).unwrap();
    let (b, _) = s.create_node(txn).unwrap();
    let t = s.intern_token(Namespace::RelType, "KNOWS").unwrap();
    let (r, eid_r) = s.create_rel(txn, t, a, b).unwrap();
    s.commit(txn).unwrap();

    // Crash + recover onto a fresh encrypted device + reopened encrypted WAL with the SAME key.
    let mut rec = recover_no_force(&s, &kr);

    assert!(rec.node(a).unwrap().mvcc.in_use());
    assert_eq!(rec.node(a).unwrap().element_id, eid_a);
    assert_eq!(rec.rel(r).unwrap().element_id, eid_r);
    assert_eq!(rec.incident_rels(a).unwrap(), vec![r]);
    assert_eq!(rec.incident_rels(b).unwrap(), vec![r]);
    assert_eq!(rec.token_id(Namespace::RelType, "KNOWS"), Some(t));
}

#[test]
fn uncommitted_work_is_rolled_back_over_encrypted_device_and_wal() {
    let kr = keyring(0x12);
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

    let mut rec = recover_no_force(&s, &kr);

    assert!(rec.node(a).unwrap().mvcc.in_use());
    assert_eq!(
        rec.incident_rels(a).unwrap(),
        Vec::<u64>::new(),
        "the uncommitted edge must be rolled back, exactly as on the plaintext path"
    );
}

#[test]
fn a_wrong_key_cannot_open_the_recovered_wal() {
    let kr = keyring(0x13);
    let mut s = fresh_store(&kr, 64);
    let txn = TxnId(1);
    s.begin(txn);
    let _ = s.create_node(txn).unwrap();
    s.commit(txn).unwrap();

    // Capture the durable encrypted-WAL backing, then attempt to reopen the encrypted sink with a
    // DIFFERENT key: must fail closed at open (WAL KCV mismatch), before any frame is decrypted.
    let physical = durable_wal_backing(&s);
    let mut backing = MemLogSink::new();
    backing.append(&physical);
    backing.sync().expect("sync physical prefix");

    let wrong = keyring(0xFF);
    let err = EncryptedLogSink::open(backing, &wrong).expect_err("wrong key must fail to open");
    assert!(matches!(
        err,
        graphus_core::error::GraphusError::Security(_)
    ));
}
