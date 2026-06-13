//! Atomic, verified file restore over the **encrypted** device seam (storage audit F2/F7/F11).
//!
//! `graphus_storage::restore_file_atomic` is device-generic: it creates the restore device over a
//! fresh temp file, writes the artifact's (plaintext-above-the-seam) page images through it, proves
//! the image consistent, then atomically renames the temp over the target. This test drives that
//! path with an [`EncryptedFileDevice`] factory — proving the encrypted store restores atomically
//! and that re-backing-up the restored encrypted store reproduces the original artifact byte-for-byte
//! (encryption is transparent above the `BlockDevice` seam, so the page images round-trip exactly).

use std::sync::atomic::{AtomicU64, Ordering};

use graphus_crypto::{EncryptedFileDevice, KEY_LEN, Keyring, SALT_LEN, random_salt};
use graphus_storage::{Namespace, RecordStore, backup_store, restore_file_atomic, verify_on_open};
use graphus_wal::{MemLogSink, WalManager};

fn unique_path(tag: &str) -> std::path::PathBuf {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    std::env::temp_dir().join(format!(
        "graphus-enc-atomic-{tag}-{}-{n}.blk",
        std::process::id()
    ))
}

/// Builds a small committed graph in a fresh plaintext in-memory store and returns its backup
/// artifact (plaintext page images — the universal restore input).
fn build_artifact() -> Vec<u8> {
    use graphus_core::TxnId;
    use graphus_io::MemBlockDevice;
    let device = MemBlockDevice::new(0);
    let wal = WalManager::create(MemLogSink::new()).expect("wal");
    let mut store = RecordStore::create(device, wal, 64, 1).expect("create store");
    let txn = TxnId(1);
    store.begin(txn);
    let rt = store.intern_token(Namespace::RelType, "KNOWS").unwrap();
    let key = store.intern_token(Namespace::PropKey, "age").unwrap();
    let (a, _) = store.create_node(txn).unwrap();
    let (b, _) = store.create_node(txn).unwrap();
    store.add_node_property(txn, a, key, 2, 42).unwrap();
    store.create_rel(txn, rt, a, b).unwrap();
    store.commit(txn).unwrap();
    backup_store(&mut store).expect("backup")
}

#[test]
fn restore_file_atomic_round_trips_over_an_encrypted_device() {
    let artifact = build_artifact();
    let path = unique_path("ok");

    let salt: [u8; SALT_LEN] = random_salt();
    let keyring = Keyring::from_key_file_bytes(&[0x37u8; KEY_LEN], &salt).expect("keyring");

    // Atomic restore THROUGH an encrypted device: the factory creates a fresh encrypted file over
    // the temp path (header: magic, salt, KCV); the plaintext page images are encrypted on write.
    restore_file_atomic(
        &artifact,
        &path,
        |p| EncryptedFileDevice::create_file(p, &keyring, salt),
        64,
    )
    .expect("atomic encrypted restore");
    assert!(path.exists(), "encrypted restore must create the target");
    assert!(
        !path
            .with_file_name(format!(
                "{}.graphus-replace-tmp",
                path.file_name().unwrap().to_str().unwrap()
            ))
            .exists(),
        "a successful restore leaves no temp residue"
    );

    // Reopen the encrypted store with the right key and re-prove consistency.
    let device = EncryptedFileDevice::open_file(&path, &keyring).expect("reopen encrypted");
    let mut store = RecordStore::open(device, WalManager::create(MemLogSink::new()).unwrap(), 64)
        .expect("open restored encrypted store");
    verify_on_open(&mut store, &[]).expect("restored encrypted store is consistent");

    // Re-backing-up the restored encrypted store reproduces the original artifact byte-for-byte:
    // encryption is transparent above the device seam, so the captured page images are identical.
    let re_artifact = backup_store(&mut store).expect("re-backup");
    assert_eq!(
        artifact, re_artifact,
        "restored encrypted store must reproduce the original plaintext image exactly"
    );

    // The wrong key fails closed when reopening (defence in depth on the restored file).
    let wrong = Keyring::from_key_file_bytes(&[0x99u8; KEY_LEN], &salt).expect("wrong keyring");
    assert!(
        EncryptedFileDevice::open_file(&path, &wrong).is_err(),
        "a wrong key must fail closed on the restored encrypted store"
    );

    std::fs::remove_file(&path).ok();
}
