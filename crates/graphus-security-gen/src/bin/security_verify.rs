//! `security_verify` — a **hermetic, deterministic, in-process** verifier of Graphus's
//! encryption-at-rest security properties for the `examples/security-multitenant` demonstration.
//!
//! It drives the REAL storage + crypto stack (`graphus-storage` `RecordStore` over a
//! `graphus-crypto` `EncryptedFileDevice` + `EncryptedFileLogSink`, the `graphus-server`
//! offline `rotate_master_key`, and the `graphus-crypto` sealed-backup envelope) entirely in process
//! — no server, no network — and proves three things, each asserted:
//!
//! 1. **Ciphertext on disk.** A known sensitive plaintext (`TENANT_A_SECRET_TOKEN`, interned as a
//!    label token so it lands on a device page) seeded into an **encrypted** store is **ABSENT** from
//!    the raw `graphus.store` bytes — *and* is **PRESENT** in a **cleartext** store built the same
//!    way (no `[encryption]`), proving the test is meaningful (the absence is encryption, not a
//!    mis-seed).
//! 2. **Offline key rotation.** `rotate_master_key` re-keys the encrypted database from `MASTER_A`
//!    to `MASTER_B`; the data is intact + readable under the new key, the decrypted pages are
//!    byte-for-byte identical across the rotation, and the **OLD key fails closed** (a `Security`
//!    error via the KCV) — Graphus's never-half-rotated guarantee.
//! 3. **Encrypted backup roundtrip.** `backup_store` produces a plaintext artifact (which carries
//!    the secret in the clear); `seal_backup` encrypts it and the sealed bytes are asserted to **not
//!    contain** the secret; `open_backup` + `restore` reconstruct the store **losslessly** (the
//!    graph is identical); a wrong key fails closed. Backup/restore time + artifact size are
//!    measured.
//!
//! On full success it prints `GRAPHUS_SECURITY_VERIFY_OK` and a single machine-readable
//! `GRAPHUS_STATS {…}` line (parsed by `run.sh` for the evidence report). Deterministic: fixed keys,
//! fixed graph, no clock-dependent behaviour in the assertions.
//!
//! Usage:
//!   cargo run -p graphus-security-gen --features dst-repro --bin security_verify -- --out-dir <dir>

use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::time::Instant;

use graphus_core::TxnId;
use graphus_core::error::{GraphusError, Result};
use graphus_crypto::{
    EncryptedFileDevice, EncryptedFileLogSink, KEY_LEN, Keyring, open_backup, random_salt,
    seal_backup,
};
use graphus_io::{BlockDevice, FileBlockDevice, PAGE_SIZE, Page};
use graphus_server::dbcatalog::{STORE_FILE_NAME, WAL_FILE_NAME};
use graphus_server::key_rotation::rotate_master_key;
use graphus_storage::backup::{backup_store, restore, verify_backup};
use graphus_storage::recovery::recover_device;
use graphus_storage::{Namespace, RecordStore};
use graphus_wal::{FileLogSink, MemLogSink, WalManager};

/// The known sensitive plaintext probe seeded into tenant_a's store (matches the generator's canary
/// `sensitive_token`). It is interned as a **label token** so its UTF-8 bytes land on a device page,
/// exactly like the `graphus-crypto` `sealed_backup_roundtrip` test does with `"SecretLabel"`.
const SENSITIVE: &str = "TENANT_A_SECRET_TOKEN";

/// Two fixed master keys (deterministic — never random, so the run is reproducible).
const MASTER_A: [u8; KEY_LEN] = [0xA1; KEY_LEN];
const MASTER_B: [u8; KEY_LEN] = [0xB2; KEY_LEN];

/// File-backed encrypted store type (the production encryption-at-rest seam).
type EncFileStore = RecordStore<EncryptedFileDevice, EncryptedFileLogSink>;
/// In-memory store type (for the sealed-backup roundtrip; the artifact is device-agnostic).
type MemStore = RecordStore<graphus_io::MemBlockDevice, MemLogSink>;

fn main() -> ExitCode {
    let mut out_dir: Option<PathBuf> = None;
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--out-dir" => out_dir = args.next().map(PathBuf::from),
            "-h" | "--help" => {
                eprintln!("usage: security_verify [--out-dir <dir>]");
                return ExitCode::SUCCESS;
            }
            other => {
                eprintln!("security_verify: unexpected argument '{other}'");
                return ExitCode::FAILURE;
            }
        }
    }

    // A private scratch directory for the file-backed stores; auto-removed on exit.
    let work = out_dir.unwrap_or_else(|| {
        std::env::temp_dir().join(format!("graphus-secverify-{}", std::process::id()))
    });
    let _guard = ScratchDir::new(&work);

    match run(&work) {
        Ok(stats) => {
            println!("GRAPHUS_SECURITY_VERIFY_OK");
            println!("GRAPHUS_STATS {stats}");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("security_verify: FAILED: {e}");
            ExitCode::FAILURE
        }
    }
}

/// Runs all three proofs, returning the machine-readable stats JSON line on success.
fn run(work: &Path) -> Result<String> {
    // ---- Proof 1: ciphertext on disk (encrypted absent / cleartext present). -------------------
    let enc_dir = work.join("enc");
    let clear_dir = work.join("clear");
    std::fs::create_dir_all(&enc_dir).map_err(io_err)?;
    std::fs::create_dir_all(&clear_dir).map_err(io_err)?;

    let enc_store_path = enc_dir.join(STORE_FILE_NAME);
    let enc_wal_path = enc_dir.join(WAL_FILE_NAME);
    let clear_store_path = clear_dir.join(STORE_FILE_NAME);
    let clear_wal_path = clear_dir.join(WAL_FILE_NAME);

    // The encrypted store: seed the sensitive token + a small graph, then drop (flush to disk).
    let (a, b, r, rt) = create_encrypted_store(&enc_store_path, &enc_wal_path, &MASTER_A)?;
    // A cleartext store built identically (no encryption), to prove the probe IS on disk in the clear.
    create_cleartext_store(&clear_store_path, &clear_wal_path)?;

    let enc_bytes = std::fs::read(&enc_store_path).map_err(io_err)?;
    let clear_bytes = std::fs::read(&clear_store_path).map_err(io_err)?;
    let enc_store_size = enc_bytes.len() as u64;

    let present_in_clear = contains(&clear_bytes, SENSITIVE.as_bytes());
    let absent_in_enc = !contains(&enc_bytes, SENSITIVE.as_bytes());
    if !present_in_clear {
        return Err(sec(
            "ciphertext proof is not meaningful: the sensitive token is NOT present in the cleartext store",
        ));
    }
    if !absent_in_enc {
        return Err(sec(
            "PLAINTEXT LEAK: the sensitive token IS present in the raw encrypted store bytes",
        ));
    }

    // ---- Proof 2: offline key rotation (data intact across; old key fails closed). -------------
    let before = decrypted_pages(&enc_store_path, &MASTER_A)?;
    let rot_t0 = Instant::now();
    rotate_master_key(
        &enc_dir,
        &enc_store_path,
        &enc_wal_path,
        &MASTER_A,
        &MASTER_B,
    )?;
    let rotation_ms = rot_t0.elapsed().as_secs_f64() * 1000.0;

    // The NEW key opens it and the graph is intact.
    assert_graph_intact(&enc_store_path, &enc_wal_path, &MASTER_B, a, b, r, rt)?;
    // Decrypted page images are byte-for-byte identical across the rotation.
    let after = decrypted_pages(&enc_store_path, &MASTER_B)?;
    if before != after {
        return Err(sec(
            "rotation changed the decrypted page images (data not preserved)",
        ));
    }
    // The OLD key now fails closed (KCV — a Security error, never a silent misread).
    match open_store(&enc_store_path, &enc_wal_path, &MASTER_A) {
        Ok(_) => {
            return Err(sec(
                "PRIVILEGE/SECURITY BUG: the OLD key still opens the store after rotation",
            ));
        }
        Err(GraphusError::Security(_)) => {}
        Err(other) => {
            return Err(sec(&format!(
                "old key must fail via the KCV (Security), got: {other}"
            )));
        }
    }
    // The sensitive token is still absent from the raw (re-keyed) store bytes.
    let enc_bytes_after = std::fs::read(&enc_store_path).map_err(io_err)?;
    if contains(&enc_bytes_after, SENSITIVE.as_bytes()) {
        return Err(sec(
            "PLAINTEXT LEAK: the sensitive token appeared in the re-keyed store bytes",
        ));
    }

    // ---- Proof 3: encrypted backup roundtrip (no plaintext sealed; lossless restore). ----------
    let mut src = create_mem_store_with_graph()?;
    let src_snapshot = node_rel_summary(&mut src);

    let backup_t0 = Instant::now();
    let artifact = backup_store(&mut src)?;
    let backup_ms = backup_t0.elapsed().as_secs_f64() * 1000.0;
    let artifact_size = artifact.len() as u64;

    // The plaintext artifact carries the secret in the clear (that is WHY it must be sealed).
    if !contains(&artifact, SENSITIVE.as_bytes()) {
        return Err(sec(
            "the plaintext backup artifact unexpectedly lacks the sensitive token",
        ));
    }
    let sealed = seal_backup(&artifact, &MASTER_A)?;
    let sealed_size = sealed.len() as u64;
    // The SEALED bytes must leak neither the secret nor a verbatim prefix of the artifact.
    if contains(&sealed, SENSITIVE.as_bytes()) {
        return Err(sec(
            "PLAINTEXT LEAK: the sealed backup contains the sensitive token in the clear",
        ));
    }
    let prefix = &artifact[..artifact.len().min(64)];
    if contains(&sealed, prefix) {
        return Err(sec(
            "PLAINTEXT LEAK: the sealed backup contains a verbatim prefix of the plaintext artifact",
        ));
    }

    // Open + verify + restore into a FRESH store; assert the graph is identical (lossless).
    let opened = open_backup(&sealed, &MASTER_A)?;
    if opened != artifact {
        return Err(sec("open_backup did not recover the exact artifact"));
    }
    verify_backup(&opened)?;
    let restore_t0 = Instant::now();
    let mut restored: MemStore = restore(&opened, WalManager::create(MemLogSink::new())?, 64)?;
    let restore_ms = restore_t0.elapsed().as_secs_f64() * 1000.0;
    let restored_snapshot = node_rel_summary(&mut restored);
    if src_snapshot != restored_snapshot {
        return Err(sec(
            "restored graph differs from the original (backup is NOT lossless)",
        ));
    }
    // A wrong key must fail closed.
    match open_backup(&sealed, &MASTER_B) {
        Ok(_) => {
            return Err(sec(
                "SECURITY BUG: a wrong master key opened the sealed backup",
            ));
        }
        Err(GraphusError::Security(_)) => {}
        Err(other) => {
            return Err(sec(&format!(
                "wrong key on sealed backup must fail Security, got: {other}"
            )));
        }
    }

    Ok(format!(
        "{{\"ciphertext_proof\":true,\"enc_store_bytes\":{enc_store_size},\
         \"rotation_ms\":{:.3},\"old_key_rejected\":true,\
         \"backup_artifact_bytes\":{artifact_size},\"sealed_backup_bytes\":{sealed_size},\
         \"backup_ms\":{:.3},\"restore_ms\":{:.3},\"lossless_restore\":true,\"wrong_key_rejected\":true}}",
        rotation_ms, backup_ms, restore_ms
    ))
}

// ====================================================================================================
// Store construction (file-backed encrypted + cleartext; in-memory for the backup roundtrip).
// ====================================================================================================

/// Creates a fresh **encrypted** store under `master` at `store_path`/`wal_path`, interns the
/// sensitive token as a label, writes a small graph, hardens it, and returns
/// `(node_a, node_b, rel, sensitive_label_token)` for later assertions.
fn create_encrypted_store(
    store_path: &Path,
    wal_path: &Path,
    master: &[u8; KEY_LEN],
) -> Result<(u64, u64, u64, u32)> {
    let salt = random_salt();
    let kr = Keyring::from_master_key(*master, &salt);
    let device = EncryptedFileDevice::create_file(store_path, &kr, salt)?;
    let wal_backing = FileLogSink::open(wal_path).map_err(wal_err)?;
    let wal =
        WalManager::create(EncryptedFileLogSink::create(wal_backing, &kr)?).map_err(wal_err)?;
    let mut store: EncFileStore = RecordStore::create(device, wal, 64, 1)?;
    let handles = write_secret_graph(&mut store)?;
    store.flush()?;
    drop(store);
    Ok(handles)
}

/// Creates a fresh **cleartext** (unencrypted) store at `store_path`/`wal_path` with the SAME secret
/// graph, proving the ciphertext-on-disk test is meaningful (the probe IS on disk here).
fn create_cleartext_store(store_path: &Path, wal_path: &Path) -> Result<()> {
    let device = FileBlockDevice::open(store_path)?;
    let wal_backing = FileLogSink::open(wal_path).map_err(wal_err)?;
    let wal = WalManager::create(wal_backing).map_err(wal_err)?;
    let mut store: RecordStore<FileBlockDevice, FileLogSink> =
        RecordStore::create(device, wal, 64, 1)?;
    write_secret_graph(&mut store)?;
    store.flush()?;
    drop(store);
    Ok(())
}

/// Creates an in-memory store with the SAME secret graph (for the sealed-backup roundtrip).
fn create_mem_store_with_graph() -> Result<MemStore> {
    let device = graphus_io::MemBlockDevice::new(0);
    let wal = WalManager::create(MemLogSink::new())?;
    let mut store: MemStore = RecordStore::create(device, wal, 64, 1)?;
    write_secret_graph(&mut store)?;
    Ok(store)
}

/// Writes the shared "secret graph": two nodes, one `LINKS` rel, and the sensitive token interned as
/// a label on node `a` (so its plaintext bytes land on a device page). Returns
/// `(node_a, node_b, rel, sensitive_label_token)`.
fn write_secret_graph<D: BlockDevice, S: graphus_wal::LogSink>(
    store: &mut RecordStore<D, S>,
) -> Result<(u64, u64, u64, u32)> {
    let txn = TxnId(1);
    store.begin(txn);
    let secret_label = store.intern_token(Namespace::Label, SENSITIVE)?;
    let (a, _) = store.create_node(txn)?;
    store.add_label(txn, a, secret_label)?;
    let (b, _) = store.create_node(txn)?;
    let rt = store.intern_token(Namespace::RelType, "LINKS")?;
    let (r, _) = store.create_rel(txn, rt, a, b)?;
    store.commit(txn)?;
    Ok((a, b, r, rt))
}

// ====================================================================================================
// Encrypted-store open / inspect helpers (mirroring crates/graphus-server/src/key_rotation.rs tests).
// ====================================================================================================

/// Opens the encrypted store under `master` (recover the WAL onto the device, then open the store),
/// or returns an error (a wrong key fails closed via the KCV).
fn open_store(store_path: &Path, wal_path: &Path, master: &[u8; KEY_LEN]) -> Result<EncFileStore> {
    let header = EncryptedFileDevice::read_file_header(store_path)?;
    let kr = Keyring::from_master_key(*master, &header.salt);

    let mut device = EncryptedFileDevice::open_file(store_path, &kr)?;
    let wal_backing = FileLogSink::open(wal_path).map_err(wal_err)?;
    let recovery_sink = EncryptedFileLogSink::open(wal_backing, &kr)?;
    let mut wal = WalManager::open(recovery_sink).map_err(wal_err)?;
    recover_device(&mut wal, &mut device)?;

    let wal_backing2 = FileLogSink::open(wal_path).map_err(wal_err)?;
    let serving_sink = EncryptedFileLogSink::open(wal_backing2, &kr)?;
    let wal = WalManager::open(serving_sink).map_err(wal_err)?;
    RecordStore::open(device, wal, 64)
}

/// Asserts the encrypted store opens under `master` and the secret graph is intact.
fn assert_graph_intact(
    store_path: &Path,
    wal_path: &Path,
    master: &[u8; KEY_LEN],
    a: u64,
    b: u64,
    r: u64,
    rt: u32,
) -> Result<()> {
    let mut store = open_store(store_path, wal_path, master)?;
    if !store.node(a)?.mvcc.in_use() || !store.node(b)?.mvcc.in_use() {
        return Err(sec("a node is not live after rotation"));
    }
    if store.incident_rels(a)? != vec![r] || store.incident_rels(b)? != vec![r] {
        return Err(sec("incidence changed after rotation"));
    }
    if store.token_id(Namespace::RelType, "LINKS") != Some(rt) {
        return Err(sec("rel-type token changed after rotation"));
    }
    if store.token_id(Namespace::Label, SENSITIVE).is_none() {
        return Err(sec("the sensitive label token did not survive rotation"));
    }
    Ok(())
}

/// Snapshots every decrypted page of the encrypted store under `master` (for byte-for-byte
/// data-preservation assertions across a rotation).
fn decrypted_pages(store_path: &Path, master: &[u8; KEY_LEN]) -> Result<Vec<Page>> {
    let header = EncryptedFileDevice::read_file_header(store_path)?;
    let kr = Keyring::from_master_key(*master, &header.salt);
    let device = EncryptedFileDevice::open_file(store_path, &kr)?;
    let count = device.page_count();
    let mut out = Vec::with_capacity(count as usize);
    for p in 0..count {
        let mut buf: Page = [0u8; PAGE_SIZE];
        device.read_page(graphus_core::PageId(p), &mut buf)?;
        out.push(buf);
    }
    Ok(out)
}

/// An order-independent fingerprint of a store's live nodes + rels (start/end/type), for the
/// lossless-restore equality check.
fn node_rel_summary<D: BlockDevice>(store: &mut RecordStore<D, MemLogSink>) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut id = 1u64;
    while let Ok(rec) = store.node(id) {
        if rec.mvcc.in_use() {
            out.push(format!("N:{}", rec.element_id.0));
        }
        id += 1;
    }
    let mut id = 1u64;
    while let Ok(rec) = store.rel(id) {
        if rec.mvcc.in_use() {
            out.push(format!(
                "R:{}:{}:{}:{}",
                rec.element_id.0, rec.type_id, rec.start_node, rec.end_node
            ));
        }
        id += 1;
    }
    out.sort();
    out
}

// ====================================================================================================
// Small helpers.
// ====================================================================================================

/// Substring search over raw bytes.
fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    needle.len() <= haystack.len() && haystack.windows(needle.len()).any(|w| w == needle)
}

fn sec(msg: &str) -> GraphusError {
    GraphusError::Security(msg.to_owned())
}

fn io_err(e: std::io::Error) -> GraphusError {
    GraphusError::Storage(format!("io: {e}"))
}

fn wal_err(e: impl std::fmt::Display) -> GraphusError {
    GraphusError::Storage(format!("wal: {e}"))
}

/// A scratch directory removed when dropped (so the verifier leaves no residue).
struct ScratchDir {
    path: PathBuf,
}

impl ScratchDir {
    fn new(path: &Path) -> Self {
        let _ = std::fs::create_dir_all(path);
        Self {
            path: path.to_path_buf(),
        }
    }
}

impl Drop for ScratchDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}
