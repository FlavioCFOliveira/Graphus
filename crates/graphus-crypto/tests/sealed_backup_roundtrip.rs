//! Integration test (rmp #89, Part A): the **sealed backup** path end to end.
//!
//! `graphus-storage`'s [`backup_store`](graphus_storage::backup::backup_store) produces a *plaintext*
//! snapshot artifact even from an **encrypted** store (it reads page images above the device seam).
//! This test proves the rmp #89 contract for that artifact:
//!
//! 1. build a real [`RecordStore`] over an **encrypted** device + WAL, write a small graph;
//! 2. `backup_store` it (a consistent plaintext snapshot, with the label name in the clear);
//! 3. [`seal_backup`] it with the master key — and assert the **sealed** bytes leak no page content;
//! 4. [`open_backup`] with the master key, [`verify_backup`] the recovered artifact, and
//!    [`restore`] it — asserting the restored graph is byte-for-byte the original;
//! 5. a wrong master key fails [`open_backup`] closed.
//!
//! `graphus-storage` stays crypto-free; this test lives in `graphus-crypto` (which dev-depends on
//! storage) precisely because it is the seam that may depend on both.

use graphus_core::TxnId;
use graphus_crypto::{
    EncryptedBlockDevice, EncryptedLogSink, KEY_LEN, Keyring, MemRawSlots, SALT_LEN, open_backup,
    seal_backup,
};
use graphus_storage::backup::{backup_store, restore, verify_backup};
use graphus_storage::{Namespace, RecordStore};
use graphus_wal::{MemLogSink, WalManager};

type EncDevice = EncryptedBlockDevice<MemRawSlots>;
type EncWal = EncryptedLogSink<MemLogSink>;
type Store = RecordStore<EncDevice, EncWal>;

const SALT: [u8; SALT_LEN] = [0x7E; SALT_LEN];
const MASTER: [u8; KEY_LEN] = [0x44; KEY_LEN];

fn keyring(master: &[u8; KEY_LEN]) -> Keyring {
    Keyring::from_master_key(*master, &SALT)
}

fn fresh_encrypted_store() -> Store {
    let kr = keyring(&MASTER);
    let device = EncryptedBlockDevice::create(MemRawSlots::new(0), &kr, SALT).expect("device");
    let wal =
        WalManager::create(EncryptedLogSink::create(MemLogSink::new(), &kr).expect("wal sink"))
            .expect("wal");
    RecordStore::create(device, wal, 64, 1).expect("store")
}

/// Writes a tiny labelled graph and returns the node/rel handles + the rel-type token to assert on
/// after a restore.
fn write_graph(store: &mut Store) -> (u64, u64, u64, u32) {
    let txn = TxnId(1);
    store.begin(txn);
    let label = store
        .intern_token(Namespace::Label, "SecretLabel")
        .expect("intern label");
    let (a, _) = store.create_node(txn).expect("node a");
    store.add_label(txn, a, label).expect("label a");
    let (b, _) = store.create_node(txn).expect("node b");
    let rt = store
        .intern_token(Namespace::RelType, "KNOWS")
        .expect("intern rel type");
    let (r, _) = store.create_rel(txn, rt, a, b).expect("rel");
    store.commit(txn).expect("commit");
    (a, b, r, rt)
}

#[test]
fn sealed_backup_round_trips_an_encrypted_store_without_leaking_pages() {
    let mut store = fresh_encrypted_store();
    let (a, b, r, rt) = write_graph(&mut store);

    // 1) The plaintext snapshot artifact (plaintext even though the store is encrypted).
    let artifact = backup_store(&mut store).expect("backup_store");
    // Sanity: the artifact itself carries the label in the clear (it is above the device seam),
    // which is exactly why it must be sealed before it leaves the machine.
    assert!(
        artifact
            .windows(b"SecretLabel".len())
            .any(|w| w == b"SecretLabel"),
        "the plaintext artifact is expected to carry the label in the clear (it is unencrypted)"
    );

    // 2) Seal it with the master key.
    let sealed = seal_backup(&artifact, &MASTER).expect("seal_backup");

    // 3) The SEALED bytes must leak no page content — neither the label nor the raw artifact.
    assert!(
        !sealed
            .windows(b"SecretLabel".len())
            .any(|w| w == b"SecretLabel"),
        "the sealed backup must not contain the label name in the clear"
    );
    assert!(
        !sealed
            .windows(artifact.len().min(64))
            .any(|w| w == &artifact[..artifact.len().min(64)]),
        "the sealed backup must not contain a verbatim prefix of the plaintext artifact"
    );

    // 4) Open with the master key, verify, and restore — the graph must come back intact.
    let opened = open_backup(&sealed, &MASTER).expect("open_backup");
    assert_eq!(
        opened, artifact,
        "open_backup must recover the exact artifact"
    );
    verify_backup(&opened).expect("verify_backup on the recovered artifact");

    let fresh_wal = WalManager::create(MemLogSink::new()).expect("fresh plaintext wal for restore");
    let mut restored = restore(&opened, fresh_wal, 64).expect("restore");

    // The restored graph equals the original.
    assert!(restored.node(a).expect("node a").mvcc.in_use());
    assert!(restored.node(b).expect("node b").mvcc.in_use());
    assert_eq!(restored.incident_rels(a).expect("incident a"), vec![r]);
    assert_eq!(restored.incident_rels(b).expect("incident b"), vec![r]);
    assert_eq!(restored.token_id(Namespace::RelType, "KNOWS"), Some(rt));
    assert!(
        restored.token_id(Namespace::Label, "SecretLabel").is_some(),
        "the label token must survive the restore"
    );
}

#[test]
fn a_wrong_master_key_cannot_open_a_sealed_backup() {
    let mut store = fresh_encrypted_store();
    let _ = write_graph(&mut store);
    let artifact = backup_store(&mut store).expect("backup_store");
    let sealed = seal_backup(&artifact, &MASTER).expect("seal_backup");

    let wrong = [0x99u8; KEY_LEN];
    let err = open_backup(&sealed, &wrong).expect_err("a wrong key must fail to open");
    assert!(matches!(
        err,
        graphus_core::error::GraphusError::Security(_)
    ));
}
