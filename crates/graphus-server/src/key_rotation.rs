//! Crash-safe **offline master-key rotation** for an encrypted database directory (rmp #89).
//!
//! Rotates the AES-256-GCM master key protecting one database's store device + WAL from
//! `old_master` to `new_master`, with **no data loss and full crash-safety**: an interruption at any
//! point leaves the directory openable under *exactly one* key — the old key (if the rotation never
//! committed) or the new key (once it did) — but **never** a torn or half-rotated mix. This serves
//! `CLAUDE.md`'s inviolable *100% ACID / never-corrupt* mandate for the encryption-at-rest layer.
//!
//! ## Preconditions and scope
//!
//! - The database is **OFFLINE** (the server is stopped, or this database's engine is not running).
//!   Rotation rewrites the device and WAL files wholesale; it must not race a live engine.
//! - This is **encrypted → encrypted** rotation only. Enabling encryption on a plaintext store, or
//!   disabling it (encrypted → plaintext), is explicitly **out of scope** (future work): it would
//!   require changing the on-disk *format* (magic), not just re-keying existing slots.
//!
//! ## How the operator supplies the new key
//!
//! The configured engine reads its master key from `encryption.key_path` (see
//! [`crate::store_device::MasterKey`]). After a successful rotation the directory's device + WAL are
//! encrypted under `new_master`, so the operator **replaces the key file at the configured
//! `key_path` with the new key** as part of the rotation procedure, then restarts the server. If the
//! key file is *not* swapped, the next open fails closed — the store's KCV (in the device header and
//! the WAL sink header) does not match the old key, so [`crate::store_device`]'s open path returns a
//! [`GraphusError::Security`] rather than silently misreading. (Order does not strictly matter: an
//! old key file after a committed rotation, or a new key file before one, both fail closed at open —
//! the KCV is the guard.)
//!
//! ## The algorithm (`rotate_master_key`)
//!
//! 1. **Recover first.** Open the old device (old keyring, salt from the device header) and the old
//!    WAL, run [`recover_device`] so the device reflects every committed change. After this the
//!    device is the authoritative image and the WAL only needs its *existing logical bytes*
//!    preserved (re-encrypted), so store↔WAL LSN consistency is trivially maintained.
//! 2. **New keyring.** Generate a fresh random salt; derive the new keyring from `new_master` + it.
//! 3. **Re-encrypt the device** into a temp `device_file.rot-new`: a fresh [`EncryptedFileDevice`]
//!    under the new keyring/salt, extended to the old page count, then `old.read_page(p)` (decrypt
//!    old) → `new.write_page(p)` (encrypt new) for every page. Page *contents* are preserved
//!    byte-for-byte; only the encryption key changes. `sync_all`.
//! 4. **Re-encrypt the WAL** into a temp `wal_file.rot-new`: read the old WAL's *logical* durable
//!    bytes through an [`EncryptedFileLogSink`] (decrypting old frames), create a fresh encrypted
//!    sink under the new keyring, append the **same** logical bytes + `sync`. Logical bytes are
//!    preserved exactly, so the LSNs (== logical byte offsets) are identical to before, and the
//!    recovered device's `page_lsn`s still reference valid WAL offsets. An empty / header-only WAL
//!    becomes a fresh header under the new key.
//! 5. **Atomic two-file swap via a marker journal** (the hard part). Both files must swap as a unit.
//!    After both temps are fully written + fsynced, the database directory is `fsync`ed once so the
//!    temps' *directory entries* (not just their contents) are durable **before** the marker exists —
//!    otherwise a metadata-reordering filesystem could persist the marker while a temp's name was
//!    still volatile, and the replay would find a temp missing and leave a torn mix. Then, in order:
//!    (a) write a marker file `.rotation-commit` (naming the targets + their temps), fsync it, fsync
//!    the directory — **this is the linearization point**: its presence means "the new files are
//!    complete and authoritative; finish the swap";
//!    (b) swap `device_file.rot-new` → `device_file`, then `wal_file.rot-new` → `wal_file`; fsync
//!    the directory (the swaps' directory entries are durable);
//!    (c) remove the marker; fsync the directory.
//!
//! The store device is a single **file**, swapped by an atomic POSIX `rename(2)`. The WAL is a
//! segmented **directory** (`rmp` #116), which `rename(2)` cannot atomically replace when the target
//! is a non-empty directory — so its swap is `remove_dir_all(target)` then `rename(temp, target)`
//! ([`replace_path`]). That two-step swap is **not atomic**, but under the marker it is crash-safe by
//! **idempotent replay**: the temp directory is consumed (removed-then-renamed) only while it still
//! exists, so a crash between the remove and the rename — or partway through the remove — re-runs as
//! `remove (finishes/no-op) + rename` and converges; a fully-completed swap has no temp and is a
//! no-op. The per-window table below therefore holds for the directory swap too; "rename" reads as
//! "the [`replace_path`] swap" for the WAL.
//!
//! ## Per-window crash-safety analysis
//!
//! Let "the marker" be `.rotation-commit`. The directory is opened by [`recover_pending_rotation`]
//! at startup (wired in before any store is opened):
//!
//! | Crash window | On-disk state | Recovery action | Resulting key |
//! |---|---|---|---|
//! | (a) after temps written, **before** the marker | originals intact + stray `.rot-new` temps | no marker ⇒ delete the stray temps; originals are authoritative | **old** |
//! | (b) after the marker, before any rename | marker + both temps + both originals | marker present ⇒ rename each temp that still exists over its target | **new** |
//! | (c) after one rename, before the second | marker + one temp + one rotated + one original | marker present ⇒ rename the remaining temp over its target (the already-renamed one has no temp ⇒ skipped) | **new** |
//! | (d) after both renames, before marker removal | marker + both rotated, no temps | marker present ⇒ no temp to rename (idempotent no-op); remove the marker | **new** |
//!
//! The crux: the **new files become authoritative the instant the marker exists**, and the replay is
//! **idempotent** — a temp is renamed over its target only if the temp still exists, so a half-done
//! swap is completed and a fully-done swap is a no-op. Before the marker, the originals are
//! authoritative and any stray temp is discarded (an aborted rotation that never committed leaves no
//! trace). A POSIX `rename(2)` over an existing path is atomic (the device file), so that target is
//! never seen torn; the WAL directory swap is the non-atomic `remove_dir_all + rename` made safe by
//! idempotent replay, as described above.
//!
//! No `unsafe`; no key/plaintext is ever logged.

use std::path::{Path, PathBuf};

use graphus_core::PageId;
use graphus_core::error::{GraphusError, Result};
use graphus_crypto::{
    EncryptedFileDevice, EncryptedFileLogSink, KEY_LEN, Keyring, SALT_LEN, random_salt,
};
use graphus_io::{BlockDevice, PAGE_SIZE, Page};
use graphus_storage::recovery::recover_device;
use graphus_wal::{FileLogSink, HEADER_LEN, LogSink, WalManager};

/// The filename suffix of a rotation's in-progress temp file (a fully re-encrypted device or WAL,
/// not yet swapped over its target).
const ROT_NEW_SUFFIX: &str = "rot-new";

/// The marker (commit journal) filename, written under the database directory. Its presence means
/// "the `.rot-new` temps are complete and authoritative; finish swapping them over their targets".
pub const ROTATION_MARKER_NAME: &str = ".rotation-commit";

/// Appends the rotation temp suffix to a path: `…/graphus.store` → `…/graphus.store.rot-new`.
fn temp_path(target: &Path) -> PathBuf {
    let mut name = target
        .file_name()
        .map(std::ffi::OsString::from)
        .unwrap_or_default();
    name.push(".");
    name.push(ROT_NEW_SUFFIX);
    match target.parent() {
        Some(parent) => parent.join(name),
        None => PathBuf::from(name),
    }
}

/// Opens `dir` and `fsync`s it, hardening its directory entries (the renames and unlinks of the
/// swap). The standard POSIX way to make directory-level changes durable.
fn fsync_dir(dir: &Path) -> Result<()> {
    let f = std::fs::File::open(dir).map_err(|e| {
        GraphusError::Storage(format!("opening directory to fsync {}: {e}", dir.display()))
    })?;
    f.sync_all()
        .map_err(|e| GraphusError::Storage(format!("syncing directory {}: {e}", dir.display())))
}

/// Rotates the encrypted database in `db_dir` (whose store device is `device_file` and WAL is
/// `wal_file`) from `old_master` to `new_master`, crash-safely (see the module docs for the
/// algorithm and the per-window crash analysis).
///
/// The database **must be offline** (no live engine). On success the device + WAL are encrypted
/// under `new_master`; the operator then replaces the configured key file with the new key (module
/// docs). On failure before the commit marker is written, the originals are untouched (still
/// `old_master`); any partial temp is left for [`recover_pending_rotation`] to discard at the next
/// open.
///
/// # Errors
/// - [`GraphusError::Security`] if `old_master` does not open the existing store (KCV mismatch).
/// - [`GraphusError::Storage`] on any I/O failure during recovery, re-encryption, or the swap.
pub fn rotate_master_key(
    db_dir: &Path,
    device_file: &Path,
    wal_file: &Path,
    old_master: &[u8; KEY_LEN],
    new_master: &[u8; KEY_LEN],
) -> Result<()> {
    // A stale temp/marker from a previously aborted attempt must be reconciled before we begin, or a
    // leftover `.rot-new` could be mistaken for this run's output. This is exactly the startup
    // recovery, so run it first (idempotent).
    recover_pending_rotation(db_dir, device_file, wal_file)?;

    // ---- 1) Recover the old device from the old WAL so it reflects all committed changes. --------
    // The old keyring is derived from the master + the device header's salt (one salt source per
    // store). A wrong `old_master` fails closed here via the KCV inside `open_file`.
    let old_header = EncryptedFileDevice::read_file_header(device_file)?;
    let old_keyring = Keyring::from_master_key(*old_master, &old_header.salt);

    let mut old_device = EncryptedFileDevice::open_file(device_file, &old_keyring)?;
    {
        // Replay the durable WAL onto the device (ARIES redo+undo), then drop the recovery view.
        let old_wal_backing = FileLogSink::open(wal_file)
            .map_err(|e| GraphusError::Storage(format!("opening old WAL backing: {e}")))?;
        let old_wal_sink = EncryptedFileLogSink::open(old_wal_backing, &old_keyring)?;
        let mut old_wal = WalManager::open(old_wal_sink)
            .map_err(|e| GraphusError::Storage(format!("opening old WAL manager: {e}")))?;
        recover_device(&mut old_wal, &mut old_device)?;
    }

    // ---- 2) New keyring (fresh salt + new master). ----------------------------------------------
    let new_salt: [u8; SALT_LEN] = random_salt();
    let new_keyring = Keyring::from_master_key(*new_master, &new_salt);

    let device_temp = temp_path(device_file);
    let wal_temp = temp_path(wal_file);

    // ---- 3) Re-encrypt the device into `device_file.rot-new`. -----------------------------------
    reencrypt_device(&old_device, &new_keyring, new_salt, &device_temp)?;

    // ---- 4) Re-encrypt the WAL into `wal_file.rot-new`. -----------------------------------------
    // Read the old WAL's LOGICAL durable bytes (decrypting old frames) and re-seal them under the
    // new key. Logical bytes (hence LSNs) are preserved exactly, so the recovered device's
    // `page_lsn`s still reference valid WAL offsets.
    let logical_wal_bytes = read_old_wal_logical_bytes(wal_file, &old_keyring)?;
    reencrypt_wal(&logical_wal_bytes, &new_keyring, &wal_temp)?;

    // ---- 4b) Harden the temps' DIRECTORY ENTRIES before the marker becomes the commit point. -----
    // `reencrypt_*` fsync the temp files' *contents* (`sync_all`/`sync`), but an `fsync` of a file
    // does not harden its *name* in the parent directory. POSIX gives no ordering guarantee between
    // the marker's directory entry and the older temp entries, so on a metadata-reordering filesystem
    // a crash could persist the marker (commit point) while a temp's entry was still volatile — then
    // [`recover_pending_rotation`] would see "committed" but find a temp missing, skip that rename,
    // and leave a torn mix (e.g. old device + new WAL → unopenable). An explicit directory `fsync`
    // here makes both temp entries durable *before* the marker can claim them authoritative, closing
    // that window (same barrier discipline as the database-catalog provisioning fix).
    fsync_dir(db_dir)?;

    // ---- 5) Atomic two-file swap via the marker journal. ----------------------------------------
    commit_swap(db_dir, device_file, wal_file, &device_temp, &wal_temp)
}

/// Re-encrypts every logical page of `old_device` into a fresh encrypted device at `dest`, under
/// `new_keyring`/`new_salt`. Page contents are copied byte-for-byte (decrypt old → encrypt new);
/// only the key changes. The destination is created fresh (an existing temp is removed first), grown
/// to the old page count, written, and `sync_all`'d before returning.
fn reencrypt_device(
    old_device: &EncryptedFileDevice,
    new_keyring: &Keyring,
    new_salt: [u8; SALT_LEN],
    dest: &Path,
) -> Result<()> {
    // Start from a clean temp: a leftover from an earlier aborted attempt must not be appended to.
    remove_if_exists(dest)?;
    let mut new_device = EncryptedFileDevice::create_file(dest, new_keyring, new_salt)?;

    let page_count = old_device.page_count();
    if page_count > 0 {
        new_device.extend(page_count)?;
    }
    let mut buf: Page = [0u8; PAGE_SIZE];
    for p in 0..page_count {
        let page = PageId(p);
        old_device.read_page(page, &mut buf)?; // decrypt under the old key
        new_device.write_page(page, &buf)?; // encrypt under the new key
    }
    new_device.sync_all()?;
    Ok(())
}

/// Reads the old WAL's **logical** durable bytes (the plaintext the WAL manager sees), decrypting the
/// old encrypted frames under `old_keyring`. Returns the logical stream `[0, durable_len)`.
fn read_old_wal_logical_bytes(wal_file: &Path, old_keyring: &Keyring) -> Result<Vec<u8>> {
    let backing = FileLogSink::open(wal_file).map_err(|e| {
        GraphusError::Storage(format!("opening old WAL backing for re-encrypt: {e}"))
    })?;
    let sink = EncryptedFileLogSink::open(backing, old_keyring)?;
    let mut logical = Vec::new();
    sink.read_durable(0, &mut logical)?;
    Ok(logical)
}

/// Writes `logical_bytes` as a fresh encrypted WAL at `dest` under `new_keyring`. The WAL header
/// (`[0, HEADER_LEN)`) is sealed as its **own** first frame and the remaining records as a second
/// frame, exactly mirroring a freshly created WAL (`WalManager::create` syncs the header alone before
/// any record). This keeps the rotated WAL's reclamation granularity intact (`rmp` #116): the tiny
/// header frame stays protected while the records frame and everything appended after it can later be
/// reclaimed — without the split, a single giant header-bearing frame would be pinned forever. An
/// empty/header-only old WAL yields just the header frame (or a bare header). Created clean and
/// `sync`'d before returning.
fn reencrypt_wal(logical_bytes: &[u8], new_keyring: &Keyring, dest: &Path) -> Result<()> {
    // The WAL is a segmented directory (`rmp` #116); clear any leftover temp directory wholesale.
    remove_path_if_exists(dest)?;
    let backing = FileLogSink::open(dest)
        .map_err(|e| GraphusError::Storage(format!("creating new WAL backing: {e}")))?;
    let mut sink = EncryptedFileLogSink::create(backing, new_keyring)?;
    let header_len = HEADER_LEN as usize;
    if logical_bytes.is_empty() {
        // No logical bytes: still harden the fresh sink header (create already synced it, but a
        // uniform sync keeps the contract explicit and costs nothing for an empty WAL).
        sink.sync()?;
    } else if logical_bytes.len() <= header_len {
        // Header-only WAL: one frame carrying exactly the header bytes.
        sink.append(logical_bytes);
        sink.sync()?;
    } else {
        // Header frame, then a records frame — matching a fresh WAL's frame structure so the header
        // frame (logical `[0, HEADER_LEN)`) is protected and the records frame remains reclaimable.
        sink.append(&logical_bytes[..header_len]);
        sink.sync()?;
        sink.append(&logical_bytes[header_len..]);
        sink.sync()?;
    }
    Ok(())
}

/// Performs the crash-safe two-file swap: write + fsync the commit marker (the linearization point),
/// then rename both temps over their targets, then remove the marker — fsyncing the directory at
/// each durability barrier (see the module docs' per-window analysis).
fn commit_swap(
    db_dir: &Path,
    device_file: &Path,
    wal_file: &Path,
    device_temp: &Path,
    wal_temp: &Path,
) -> Result<()> {
    // (a) Write + harden the commit marker. Its presence flips the directory's authoritative image
    //     from the originals to the `.rot-new` temps.
    let marker = db_dir.join(ROTATION_MARKER_NAME);
    write_marker(&marker, device_file, wal_file)?;
    fsync_dir(db_dir)?;

    // (b) Swap each temp over its target (the device file by an atomic rename; the segmented WAL
    //     directory by a marker-guarded remove+rename), then harden the directory entries.
    replace_path(device_temp, device_file)?;
    replace_path(wal_temp, wal_file)?;
    fsync_dir(db_dir)?;

    // (c) Remove the marker; harden its unlink. The rotation is now fully complete.
    remove_if_exists(&marker)?;
    fsync_dir(db_dir)?;
    Ok(())
}

/// The recorded contents of the commit marker: the two `(target, temp)` swap pairs, one per line, as
/// `target<TAB>temp`. Self-describing for an operator inspecting an interrupted rotation, and it lets
/// the replay name the exact files without re-deriving them. (The replay also derives temps from
/// targets, so a corrupt/partial marker still completes correctly — see [`recover_pending_rotation`].)
fn write_marker(marker: &Path, device_file: &Path, wal_file: &Path) -> Result<()> {
    use std::io::Write as _;
    let body = format!(
        "{}\t{}\n{}\t{}\n",
        device_file.display(),
        temp_path(device_file).display(),
        wal_file.display(),
        temp_path(wal_file).display(),
    );
    let mut f = std::fs::File::create(marker)
        .map_err(|e| GraphusError::Storage(format!("creating rotation marker: {e}")))?;
    f.write_all(body.as_bytes())
        .map_err(|e| GraphusError::Storage(format!("writing rotation marker: {e}")))?;
    f.sync_all()
        .map_err(|e| GraphusError::Storage(format!("syncing rotation marker: {e}")))?;
    Ok(())
}

/// Renames `from` over `to` (atomic). Errors if `from` is absent — callers must only rename a temp
/// they have confirmed exists.
fn rename(from: &Path, to: &Path) -> Result<()> {
    std::fs::rename(from, to).map_err(|e| {
        GraphusError::Storage(format!(
            "renaming {} -> {}: {e}",
            from.display(),
            to.display()
        ))
    })
}

/// Replaces `target` with `temp` (a confirmed-existing temp), handling both kinds of target:
///
/// - **File** (the store device): a POSIX `rename(2)` atomically replaces the existing target file.
/// - **Directory** (the segmented WAL, `rmp` #116): `rename(2)` cannot atomically replace a non-empty
///   directory, so the (possibly partial) target directory is removed first, then the temp directory
///   is renamed into place. Under the rotation commit marker this two-step swap stays crash-safe and
///   **idempotent**: a crash after the remove but before the rename re-runs as `remove (no-op) +
///   rename`, and a crash mid-remove re-runs as `remove (finishes) + rename` — see the module docs'
///   per-window analysis (the marker is the linearization point; a temp is consumed only if present).
fn replace_path(temp: &Path, target: &Path) -> Result<()> {
    if temp.is_dir() {
        remove_path_if_exists(target)?;
    }
    rename(temp, target)
}

/// Removes a file if it exists; an already-absent file is fine (idempotent).
fn remove_if_exists(path: &Path) -> Result<()> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(GraphusError::Storage(format!(
            "removing {}: {e}",
            path.display()
        ))),
    }
}

/// Removes `path` whether it is a file or a directory tree; an already-absent path is fine
/// (idempotent). Used for the segmented WAL, whose temp/target are directories (`rmp` #116).
fn remove_path_if_exists(path: &Path) -> Result<()> {
    let meta = match std::fs::symlink_metadata(path) {
        Ok(m) => m,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => {
            return Err(GraphusError::Storage(format!(
                "stat {} for removal: {e}",
                path.display()
            )));
        }
    };
    let result = if meta.is_dir() {
        std::fs::remove_dir_all(path)
    } else {
        std::fs::remove_file(path)
    };
    match result {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(GraphusError::Storage(format!(
            "removing {}: {e}",
            path.display()
        ))),
    }
}

/// Completes or discards a pending rotation for `db_dir`, idempotently. **Call at startup, before any
/// store in the directory is opened** (wired into the catalog's per-database open path).
///
/// - If the commit marker `.rotation-commit` **exists**, the new files are authoritative: for each
///   target (`device_file`, `wal_file`) whose `.rot-new` temp still exists, rename the temp over the
///   target (completing a crash mid-swap — windows (b)/(c)/(d) in the module docs); a target with no
///   temp was already swapped, so it is skipped. Then remove the marker. Each step fsyncs the
///   directory. This is fully idempotent: re-running it after a crash mid-recovery converges.
/// - If the marker is **absent**, any `.rot-new` temp is the debris of an aborted rotation that never
///   committed (window (a)); the originals are authoritative, so the stray temps are discarded.
///
/// # Errors
/// [`GraphusError::Storage`] on any filesystem failure while completing/cleaning up the swap.
pub fn recover_pending_rotation(db_dir: &Path, device_file: &Path, wal_file: &Path) -> Result<()> {
    let marker = db_dir.join(ROTATION_MARKER_NAME);
    let device_temp = temp_path(device_file);
    let wal_temp = temp_path(wal_file);

    if marker.exists() {
        // Committed: the new files are authoritative. Finish each swap that has not landed yet.
        // A temp that still exists has not been renamed over its target; rename it (idempotent — a
        // target already swapped simply has no temp). The directory fsync after the renames hardens
        // the new directory entries before the marker is removed, so a crash here replays cleanly.
        let mut swapped_any = false;
        for (target, temp) in [(device_file, &device_temp), (wal_file, &wal_temp)] {
            if temp.exists() {
                replace_path(temp, target)?;
                swapped_any = true;
            }
        }
        if swapped_any {
            fsync_dir(db_dir)?;
        }
        // The swap is complete (or was already complete). Remove the marker and harden the unlink.
        remove_if_exists(&marker)?;
        fsync_dir(db_dir)?;
        tracing::warn!(
            dir = %db_dir.display(),
            "completed a pending encryption-key rotation on open (the new key is now authoritative)"
        );
    } else {
        // Not committed: discard any debris from an aborted rotation; the originals stand.
        let mut removed_any = false;
        for temp in [&device_temp, &wal_temp] {
            if temp.exists() {
                remove_path_if_exists(temp)?;
                removed_any = true;
            }
        }
        if removed_any {
            fsync_dir(db_dir)?;
            tracing::warn!(
                dir = %db_dir.display(),
                "discarded an incomplete encryption-key rotation's temp files (it never committed; \
                 the original key remains authoritative)"
            );
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use graphus_storage::{Namespace, RecordStore};
    use graphus_wal::WalManager;

    use crate::dbcatalog::{STORE_FILE_NAME, WAL_FILE_NAME};

    /// A unique temp database directory for one test (auto-removed on drop).
    struct TempDir {
        path: PathBuf,
    }

    impl TempDir {
        fn new(tag: &str) -> Self {
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock after epoch")
                .as_nanos();
            let path = std::env::temp_dir().join(format!(
                "graphus-keyrot-{tag}-{nanos}-{}",
                std::process::id()
            ));
            std::fs::create_dir_all(&path).expect("create temp dir");
            Self { path }
        }

        fn device(&self) -> PathBuf {
            self.path.join(STORE_FILE_NAME)
        }

        fn wal(&self) -> PathBuf {
            self.path.join(WAL_FILE_NAME)
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }

    const MASTER_A: [u8; KEY_LEN] = [0xA1; KEY_LEN];
    const MASTER_B: [u8; KEY_LEN] = [0xB2; KEY_LEN];

    /// The store type over file-backed encrypted device + WAL.
    type FileStore = RecordStore<EncryptedFileDevice, EncryptedFileLogSink>;

    /// Creates a fresh encrypted store in `dir` under `master`, writes a small labelled graph, and
    /// hardens it. Returns `(node_a, node_b, rel, label_token, reltype_token)` for later assertions.
    fn create_store_with_graph(dir: &TempDir, master: &[u8; KEY_LEN]) -> (u64, u64, u64, u32, u32) {
        let salt = random_salt();
        let kr = Keyring::from_master_key(*master, &salt);
        let device =
            EncryptedFileDevice::create_file(dir.device(), &kr, salt).expect("create device");
        let wal_backing = FileLogSink::open(dir.wal()).expect("wal backing");
        let wal = WalManager::create(
            EncryptedFileLogSink::create(wal_backing, &kr).expect("create wal sink"),
        )
        .expect("create wal");
        let mut store: FileStore = RecordStore::create(device, wal, 64, 1).expect("create store");

        let txn = graphus_core::TxnId(1);
        store.begin(txn);
        let label = store
            .intern_token(Namespace::Label, "Rotated")
            .expect("label");
        let (a, _) = store.create_node(txn).expect("node a");
        store.add_label(txn, a, label).expect("add label");
        let (b, _) = store.create_node(txn).expect("node b");
        let rt = store
            .intern_token(Namespace::RelType, "LINKS")
            .expect("rel type");
        let (r, _) = store.create_rel(txn, rt, a, b).expect("rel");
        store.commit(txn).expect("commit");
        store.flush().expect("flush");
        // Drop the store (and its file handles) so the rotation can reopen the files cleanly.
        drop(store);
        (a, b, r, label, rt)
    }

    /// Opens the store in `dir` under `master` (the catalog's open path, condensed): recover the WAL
    /// onto the device, then open the store. Returns the opened store, or an error (e.g. a wrong key
    /// fails closed via the KCV).
    fn open_store(dir: &TempDir, master: &[u8; KEY_LEN]) -> Result<FileStore> {
        let header = EncryptedFileDevice::read_file_header(dir.device())?;
        let kr = Keyring::from_master_key(*master, &header.salt);

        let mut device = EncryptedFileDevice::open_file(dir.device(), &kr)?;
        let wal_backing = FileLogSink::open(dir.wal())
            .map_err(|e| GraphusError::Storage(format!("open wal: {e}")))?;
        let recovery_sink = EncryptedFileLogSink::open(wal_backing, &kr)?;
        let mut wal = WalManager::open(recovery_sink)
            .map_err(|e| GraphusError::Storage(format!("open wal mgr: {e}")))?;
        recover_device(&mut wal, &mut device)?;

        let wal_backing2 = FileLogSink::open(dir.wal())
            .map_err(|e| GraphusError::Storage(format!("reopen wal: {e}")))?;
        let serving_sink = EncryptedFileLogSink::open(wal_backing2, &kr)?;
        let wal = WalManager::open(serving_sink)
            .map_err(|e| GraphusError::Storage(format!("reopen wal mgr: {e}")))?;
        RecordStore::open(device, wal, 64)
    }

    /// Asserts the store in `dir` opens under `master` and the graph is intact.
    fn assert_graph_intact(dir: &TempDir, master: &[u8; KEY_LEN], a: u64, b: u64, r: u64, rt: u32) {
        let store = open_store(dir, master).expect("open under the expected key");
        assert!(store.node(a).expect("node a").mvcc.in_use());
        assert!(store.node(b).expect("node b").mvcc.in_use());
        assert_eq!(store.incident_rels(a).expect("incident a"), vec![r]);
        assert_eq!(store.incident_rels(b).expect("incident b"), vec![r]);
        assert_eq!(store.token_id(Namespace::RelType, "LINKS"), Some(rt));
        assert!(
            store.token_id(Namespace::Label, "Rotated").is_some(),
            "the label token survives rotation"
        );
    }

    /// Snapshots every decrypted page of the store in `dir` under `master` (for byte-for-byte
    /// data-preservation assertions across a rotation).
    fn decrypted_pages(dir: &TempDir, master: &[u8; KEY_LEN]) -> Vec<Page> {
        let header = EncryptedFileDevice::read_file_header(dir.device()).expect("header");
        let kr = Keyring::from_master_key(*master, &header.salt);
        let device = EncryptedFileDevice::open_file(dir.device(), &kr).expect("open device");
        let count = device.page_count();
        let mut out = Vec::with_capacity(count as usize);
        for p in 0..count {
            let mut buf: Page = [0u8; PAGE_SIZE];
            device.read_page(PageId(p), &mut buf).expect("read page");
            out.push(buf);
        }
        out
    }

    // ---- round-trip ---------------------------------------------------------------------------------

    #[test]
    fn rotation_reopens_under_the_new_key_and_rejects_the_old() {
        let dir = TempDir::new("roundtrip");
        let (a, b, r, _label, rt) = create_store_with_graph(&dir, &MASTER_A);

        // Capture the decrypted pages BEFORE rotation (under the old key) for byte-for-byte equality.
        let before = decrypted_pages(&dir, &MASTER_A);

        rotate_master_key(&dir.path, &dir.device(), &dir.wal(), &MASTER_A, &MASTER_B)
            .expect("rotate A -> B");

        // The new key opens it and the graph is intact.
        assert_graph_intact(&dir, &MASTER_B, a, b, r, rt);

        // The OLD key no longer opens it (KCV fail-closed). `RecordStore` is not `Debug`, so match
        // on the result rather than `expect_err`.
        match open_store(&dir, &MASTER_A) {
            Ok(_) => panic!("old key must fail closed after rotation"),
            Err(GraphusError::Security(_)) => {}
            Err(other) => panic!("old key must fail via the KCV (Security), got {other:?}"),
        }

        // Data preservation: the decrypted pages are byte-for-byte identical under the new key.
        let after = decrypted_pages(&dir, &MASTER_B);
        assert_eq!(
            before, after,
            "every decrypted page must be byte-for-byte identical after rotation"
        );
    }

    #[test]
    fn no_temps_or_marker_remain_after_a_clean_rotation() {
        let dir = TempDir::new("clean");
        let _ = create_store_with_graph(&dir, &MASTER_A);
        rotate_master_key(&dir.path, &dir.device(), &dir.wal(), &MASTER_A, &MASTER_B)
            .expect("rotate");
        assert!(!temp_path(&dir.device()).exists(), "device temp removed");
        assert!(!temp_path(&dir.wal()).exists(), "wal temp removed");
        assert!(
            !dir.path.join(ROTATION_MARKER_NAME).exists(),
            "marker removed"
        );
    }

    #[test]
    fn rotating_with_the_wrong_old_key_fails_closed() {
        let dir = TempDir::new("wrongold");
        let _ = create_store_with_graph(&dir, &MASTER_A);
        let wrong_old = [0xCCu8; KEY_LEN];
        let err = rotate_master_key(&dir.path, &dir.device(), &dir.wal(), &wrong_old, &MASTER_B)
            .expect_err("wrong old key must fail");
        assert!(matches!(err, GraphusError::Security(_)));
    }

    // ---- crash-during-rotation (the critical tests) ------------------------------------------------
    //
    // We simulate a crash at each window by performing the rotation steps up to that point manually
    // (the same sequence `rotate_master_key` runs), NOT calling the later steps, then invoking
    // `recover_pending_rotation` and asserting the store opens under EXACTLY one key.

    /// Runs steps 1-4 of a rotation (recover + re-encrypt device + re-encrypt WAL into temps) and
    /// returns the new salt's keyring inputs. Mirrors `rotate_master_key` up to the swap.
    fn prepare_temps(dir: &TempDir, old_master: &[u8; KEY_LEN], new_master: &[u8; KEY_LEN]) {
        let old_header = EncryptedFileDevice::read_file_header(dir.device()).expect("old header");
        let old_kr = Keyring::from_master_key(*old_master, &old_header.salt);
        let mut old_device =
            EncryptedFileDevice::open_file(dir.device(), &old_kr).expect("open old device");
        {
            let backing = FileLogSink::open(dir.wal()).expect("old wal backing");
            let sink = EncryptedFileLogSink::open(backing, &old_kr).expect("old wal sink");
            let mut wal = WalManager::open(sink).expect("old wal mgr");
            recover_device(&mut wal, &mut old_device).expect("recover");
        }
        let new_salt = random_salt();
        let new_kr = Keyring::from_master_key(*new_master, &new_salt);
        reencrypt_device(&old_device, &new_kr, new_salt, &temp_path(&dir.device()))
            .expect("reencrypt device");
        let logical =
            read_old_wal_logical_bytes(&dir.wal(), &old_kr).expect("read old wal logical");
        reencrypt_wal(&logical, &new_kr, &temp_path(&dir.wal())).expect("reencrypt wal");
    }

    /// (a) Crash after the temps are written but BEFORE the marker: recovery discards the temps; the
    /// store still opens under the OLD key, never the new.
    #[test]
    fn crash_before_marker_keeps_the_old_key() {
        let dir = TempDir::new("crash-a");
        let (a, b, r, _l, rt) = create_store_with_graph(&dir, &MASTER_A);
        prepare_temps(&dir, &MASTER_A, &MASTER_B);
        // No marker written. The temps exist.
        assert!(temp_path(&dir.device()).exists());
        assert!(temp_path(&dir.wal()).exists());

        recover_pending_rotation(&dir.path, &dir.device(), &dir.wal()).expect("recover");

        // Temps gone; OLD key opens; NEW key does not.
        assert!(!temp_path(&dir.device()).exists());
        assert!(!temp_path(&dir.wal()).exists());
        assert_graph_intact(&dir, &MASTER_A, a, b, r, rt);
        assert!(
            open_store(&dir, &MASTER_B).is_err(),
            "new key must not open"
        );
    }

    /// (b) Crash after the marker but BEFORE any rename: recovery completes both swaps; the store
    /// opens under the NEW key, never the old.
    #[test]
    fn crash_after_marker_before_rename_completes_to_new_key() {
        let dir = TempDir::new("crash-b");
        let (a, b, r, _l, rt) = create_store_with_graph(&dir, &MASTER_A);
        prepare_temps(&dir, &MASTER_A, &MASTER_B);
        // Write the marker but perform NO renames (the crash window).
        write_marker(
            &dir.path.join(ROTATION_MARKER_NAME),
            &dir.device(),
            &dir.wal(),
        )
        .expect("write marker");

        recover_pending_rotation(&dir.path, &dir.device(), &dir.wal()).expect("recover");

        assert!(!dir.path.join(ROTATION_MARKER_NAME).exists(), "marker gone");
        assert_graph_intact(&dir, &MASTER_B, a, b, r, rt);
        assert!(
            open_store(&dir, &MASTER_A).is_err(),
            "old key must not open"
        );
    }

    /// (c) Crash after ONE rename but before the second: recovery completes the remaining swap; the
    /// store opens under the NEW key.
    #[test]
    fn crash_after_one_rename_completes_to_new_key() {
        let dir = TempDir::new("crash-c");
        let (a, b, r, _l, rt) = create_store_with_graph(&dir, &MASTER_A);
        prepare_temps(&dir, &MASTER_A, &MASTER_B);
        write_marker(
            &dir.path.join(ROTATION_MARKER_NAME),
            &dir.device(),
            &dir.wal(),
        )
        .expect("write marker");
        // Swap ONLY the device temp over its target (the WAL temp still pending).
        replace_path(&temp_path(&dir.device()), &dir.device()).expect("swap device temp");
        assert!(!temp_path(&dir.device()).exists());
        assert!(temp_path(&dir.wal()).exists());

        recover_pending_rotation(&dir.path, &dir.device(), &dir.wal()).expect("recover");

        assert!(!temp_path(&dir.wal()).exists(), "wal temp swapped");
        assert!(!dir.path.join(ROTATION_MARKER_NAME).exists());
        assert_graph_intact(&dir, &MASTER_B, a, b, r, rt);
        assert!(
            open_store(&dir, &MASTER_A).is_err(),
            "old key must not open"
        );
    }

    /// (d) Crash after BOTH renames but before the marker is removed: recovery has nothing to rename
    /// (idempotent no-op), removes the marker; the store opens under the NEW key.
    #[test]
    fn crash_after_both_renames_before_marker_removal_is_new_key() {
        let dir = TempDir::new("crash-d");
        let (a, b, r, _l, rt) = create_store_with_graph(&dir, &MASTER_A);
        prepare_temps(&dir, &MASTER_A, &MASTER_B);
        write_marker(
            &dir.path.join(ROTATION_MARKER_NAME),
            &dir.device(),
            &dir.wal(),
        )
        .expect("write marker");
        replace_path(&temp_path(&dir.device()), &dir.device()).expect("swap device temp");
        replace_path(&temp_path(&dir.wal()), &dir.wal()).expect("swap wal temp");
        // Marker still present (the crash window before its removal).
        assert!(dir.path.join(ROTATION_MARKER_NAME).exists());

        recover_pending_rotation(&dir.path, &dir.device(), &dir.wal()).expect("recover");

        assert!(!dir.path.join(ROTATION_MARKER_NAME).exists(), "marker gone");
        assert_graph_intact(&dir, &MASTER_B, a, b, r, rt);
        assert!(
            open_store(&dir, &MASTER_A).is_err(),
            "old key must not open"
        );
    }

    /// (c') The directory-swap crash window unique to the segmented WAL (`rmp` #116): after the
    /// marker and after the WAL **target directory was removed** but before the temp directory was
    /// renamed into its place. Recovery must complete the swap (remove is a no-op, then rename) and
    /// open under the NEW key — proving the two-step remove+rename stays crash-safe and idempotent.
    #[test]
    fn crash_after_wal_target_removed_before_rename_completes_to_new_key() {
        let dir = TempDir::new("crash-dir-swap");
        let (a, b, r, _l, rt) = create_store_with_graph(&dir, &MASTER_A);
        prepare_temps(&dir, &MASTER_A, &MASTER_B);
        write_marker(
            &dir.path.join(ROTATION_MARKER_NAME),
            &dir.device(),
            &dir.wal(),
        )
        .expect("write marker");
        // Device fully swapped; WAL target directory removed, but the temp dir not yet renamed.
        replace_path(&temp_path(&dir.device()), &dir.device()).expect("swap device temp");
        remove_path_if_exists(&dir.wal()).expect("remove wal target dir");
        assert!(!dir.wal().exists(), "wal target removed");
        assert!(temp_path(&dir.wal()).exists(), "wal temp still pending");

        recover_pending_rotation(&dir.path, &dir.device(), &dir.wal()).expect("recover");

        assert!(
            !temp_path(&dir.wal()).exists(),
            "wal temp swapped into place"
        );
        assert!(!dir.path.join(ROTATION_MARKER_NAME).exists(), "marker gone");
        assert_graph_intact(&dir, &MASTER_B, a, b, r, rt);
        assert!(
            open_store(&dir, &MASTER_A).is_err(),
            "old key must not open"
        );
    }

    /// A rotation round-trip over a WAL that has been **reclaimed** (a zero gap in its logical stream):
    /// the re-encrypted WAL must preserve the logical bytes (offsets/LSNs), so the graph stays intact
    /// under the new key. Guards the #116 interaction between reclamation and key rotation.
    #[test]
    fn rotation_round_trips_a_reclaimed_wal() {
        let dir = TempDir::new("rotate-reclaimed");
        let (a, b, r, _l, rt) = create_store_with_graph(&dir, &MASTER_A);
        // Reclaim the old WAL's prefix below a safe floor, then rotate. Open the WAL, reclaim, drop.
        {
            let header = EncryptedFileDevice::read_file_header(dir.device()).expect("header");
            let kr = Keyring::from_master_key(MASTER_A, &header.salt);
            let backing = FileLogSink::open(dir.wal()).expect("wal backing");
            let sink = EncryptedFileLogSink::open(backing, &kr).expect("wal sink");
            let mut wal = WalManager::open(sink).expect("wal mgr");
            // No active transactions after the committed graph, so the floor is the durable length;
            // reclaim everything reclaimable below it (keeps the header + active frame).
            let durable = wal.durable_len();
            wal.reclaim(graphus_core::Lsn(durable)).expect("reclaim");
        }
        rotate_master_key(&dir.path, &dir.device(), &dir.wal(), &MASTER_A, &MASTER_B)
            .expect("rotate a reclaimed wal");
        assert_graph_intact(&dir, &MASTER_B, a, b, r, rt);
    }

    /// Recovery is idempotent: running it twice (a crash mid-recovery) still converges to the new key.
    #[test]
    fn recovery_is_idempotent() {
        let dir = TempDir::new("idempotent");
        let (a, b, r, _l, rt) = create_store_with_graph(&dir, &MASTER_A);
        prepare_temps(&dir, &MASTER_A, &MASTER_B);
        write_marker(
            &dir.path.join(ROTATION_MARKER_NAME),
            &dir.device(),
            &dir.wal(),
        )
        .expect("write marker");

        recover_pending_rotation(&dir.path, &dir.device(), &dir.wal()).expect("recover 1");
        // A second call must be a clean no-op (marker already gone, temps already swapped).
        recover_pending_rotation(&dir.path, &dir.device(), &dir.wal()).expect("recover 2");
        assert_graph_intact(&dir, &MASTER_B, a, b, r, rt);
    }

    /// `recover_pending_rotation` on a directory with no pending rotation is a clean no-op.
    #[test]
    fn recover_with_no_pending_rotation_is_a_noop() {
        let dir = TempDir::new("nopending");
        let (a, b, r, _l, rt) = create_store_with_graph(&dir, &MASTER_A);
        recover_pending_rotation(&dir.path, &dir.device(), &dir.wal()).expect("recover noop");
        assert_graph_intact(&dir, &MASTER_A, a, b, r, rt);
    }
}
