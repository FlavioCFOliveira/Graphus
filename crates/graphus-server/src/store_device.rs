//! The record-store **block device** the engine is built on, abstracted over plaintext vs.
//! encrypted (rmp #85).
//!
//! The engine, coordinator, buffer pool, recovery and consistency checker are all generic over a
//! [`graphus_io::BlockDevice`]. To let the **same** generic engine run over either a plaintext file
//! device or an encrypted one, without two parallel monomorphisations threaded through every
//! signature, we pick **one** device type — [`StoreDevice`] — that is an enum dispatching to either
//! backend. The plaintext arm forwards straight to [`graphus_io::FileBlockDevice`], so the
//! plaintext path is byte-identical to before (one `match` per page op, negligible next to the I/O).
//!
//! The encryption **key** is carried as a [`MasterKey`] (a `Zeroizing` 32-byte secret behind an
//! `Arc`, so it is cheap to share across the per-database engine spawns and is wiped on drop). Each
//! database's store has its **own** KDF salt persisted in its header, so the per-store subkey is
//! derived from `(master key, that store's salt)` at create/open time — never reused across stores.

use std::path::Path;
use std::sync::Arc;

use graphus_core::PageId;
use graphus_core::error::{GraphusError, Result};
use graphus_crypto::{EncryptedFileDevice, EncryptedFileLogSink, Keyring};
use graphus_io::{BlockDevice, FileBlockDevice, Page};
use graphus_wal::{FileLogSink, LogSink};
use zeroize::Zeroizing;

/// The 256-bit master key for encryption at rest, loaded once at startup and shared (read-only)
/// across every database's engine spawn. Zeroized on drop.
///
/// Cloning is cheap (an `Arc` bump); the inner bytes are never copied out except to derive a
/// per-store [`Keyring`].
#[derive(Clone)]
pub struct MasterKey {
    bytes: Arc<Zeroizing<[u8; graphus_crypto::KEY_LEN]>>,
}

impl std::fmt::Debug for MasterKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never render key material.
        f.debug_struct("MasterKey").finish_non_exhaustive()
    }
}

impl MasterKey {
    /// Loads the master key from a key file (raw 32 bytes or 64 hex characters).
    ///
    /// # Errors
    /// [`GraphusError::Security`] if the file cannot be read or the material is malformed (wrong
    /// length / bad hex). The error never echoes key bytes.
    pub fn load_from_file(path: &Path) -> Result<Self> {
        let raw = std::fs::read(path).map_err(|e| {
            GraphusError::Security(format!(
                "reading encryption key file {}: {e}",
                path.display()
            ))
        })?;
        // Validate + parse via a throwaway keyring derivation with a fixed salt: this confirms the
        // material is a valid 32-byte/64-hex key and surfaces a clear error now (fail fast at
        // startup), but we keep the *raw* master bytes (each store derives its own salted subkey).
        let bytes = parse_master_key(&raw)?;
        Ok(Self {
            bytes: Arc::new(bytes),
        })
    }

    /// Derives a [`Keyring`] for one store from this master key and that store's KDF `salt`.
    #[must_use]
    pub fn keyring_for(&self, salt: &[u8; graphus_crypto::SALT_LEN]) -> Keyring {
        // Deref the `Arc`, then the `Zeroizing`, yielding the `[u8; KEY_LEN]` the keyring copies in.
        let master: [u8; graphus_crypto::KEY_LEN] = **self.bytes;
        Keyring::from_master_key(master, salt)
    }

    /// Seals an operator backup artifact under this master key (AES-256-GCM, rmp #89), so a backup
    /// file of an **encrypted** database never contains plaintext page images at rest. The salt is
    /// generated per call and embedded in the envelope, so the artifact is openable with the master
    /// key alone via [`open_artifact`](Self::open_artifact).
    ///
    /// # Errors
    /// [`GraphusError::Security`] if the AEAD seal fails.
    pub fn seal_artifact(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        graphus_crypto::seal_backup(plaintext, &self.bytes)
    }

    /// Opens a sealed operator backup artifact, returning its plaintext (the inverse of
    /// [`seal_artifact`](Self::seal_artifact)). Fail-closed: a wrong key or any tamper is rejected.
    ///
    /// # Errors
    /// [`GraphusError::Security`] if the envelope is malformed or fails authentication.
    pub fn open_artifact(&self, sealed: &[u8]) -> Result<Vec<u8>> {
        graphus_crypto::open_backup(sealed, &self.bytes)
    }
}

/// Parses key-file bytes into a 32-byte master key (raw 32 bytes, or 64 hex chars), trimming
/// surrounding ASCII whitespace. Mirrors `graphus_crypto::Keyring`'s own parser so the server can
/// hold the raw master key (which the crypto crate consumes into a keyring) and re-derive per store.
fn parse_master_key(bytes: &[u8]) -> Result<Zeroizing<[u8; graphus_crypto::KEY_LEN]>> {
    const KEY_LEN: usize = graphus_crypto::KEY_LEN;
    let trimmed = trim_ascii_ws(bytes);
    if trimmed.len() == KEY_LEN {
        let mut key = Zeroizing::new([0u8; KEY_LEN]);
        key.copy_from_slice(trimmed);
        return Ok(key);
    }
    if trimmed.len() == KEY_LEN * 2 && trimmed.iter().all(u8::is_ascii_hexdigit) {
        let mut key = Zeroizing::new([0u8; KEY_LEN]);
        for (i, byte) in key.iter_mut().enumerate() {
            let hi = hex_val(trimmed[i * 2]);
            let lo = hex_val(trimmed[i * 2 + 1]);
            *byte = (hi << 4) | lo;
        }
        return Ok(key);
    }
    Err(GraphusError::Security(format!(
        "invalid encryption key material: expected {KEY_LEN} raw bytes or {} hex characters \
         (key bytes are not logged)",
        KEY_LEN * 2
    )))
}

fn trim_ascii_ws(mut b: &[u8]) -> &[u8] {
    while let [first, rest @ ..] = b {
        if first.is_ascii_whitespace() {
            b = rest;
        } else {
            break;
        }
    }
    while let [rest @ .., last] = b {
        if last.is_ascii_whitespace() {
            b = rest;
        } else {
            break;
        }
    }
    b
}

fn hex_val(c: u8) -> u8 {
    match c {
        b'0'..=b'9' => c - b'0',
        b'a'..=b'f' => c - b'a' + 10,
        b'A'..=b'F' => c - b'A' + 10,
        _ => 0,
    }
}

/// The record-store device: either a plaintext file device (today's path, byte-identical) or an
/// AES-256-GCM encrypted file device (rmp #85). One enum so the engine stays single-monomorphised.
///
/// The encrypted variant is **boxed**: it carries the expanded AES-GCM cipher state (~1 KiB),
/// whereas the plaintext variant is a bare file handle. Boxing keeps the enum small (a pointer) so
/// the plaintext path pays no size penalty, while the encrypted path adds only one pointer
/// indirection per page op — negligible beside the AES round and the I/O it guards.
#[derive(Debug)]
pub enum StoreDevice {
    /// The plaintext path — unchanged from before encryption existed.
    Plain(FileBlockDevice),
    /// The encrypted path — each page is an AES-256-GCM slot (`graphus-crypto`). Boxed to keep the
    /// enum small (see the type docs).
    Encrypted(Box<EncryptedFileDevice>),
}

impl BlockDevice for StoreDevice {
    fn read_page(&self, page: PageId, buf: &mut Page) -> Result<()> {
        match self {
            Self::Plain(d) => d.read_page(page, buf),
            Self::Encrypted(d) => d.read_page(page, buf),
        }
    }

    fn write_page(&mut self, page: PageId, buf: &Page) -> Result<()> {
        match self {
            Self::Plain(d) => d.write_page(page, buf),
            Self::Encrypted(d) => d.write_page(page, buf),
        }
    }

    fn sync_data(&mut self) -> Result<()> {
        match self {
            Self::Plain(d) => d.sync_data(),
            Self::Encrypted(d) => d.sync_data(),
        }
    }

    fn sync_all(&mut self) -> Result<()> {
        match self {
            Self::Plain(d) => d.sync_all(),
            Self::Encrypted(d) => d.sync_all(),
        }
    }

    fn page_count(&self) -> u64 {
        match self {
            Self::Plain(d) => d.page_count(),
            Self::Encrypted(d) => d.page_count(),
        }
    }

    fn extend(&mut self, additional: u64) -> Result<()> {
        match self {
            Self::Plain(d) => d.extend(additional),
            Self::Encrypted(d) => d.extend(additional),
        }
    }
}

/// The write-ahead-log sink: either a plaintext file sink (today's path, byte-identical) or an
/// AES-256-GCM encrypted file sink (rmp #88). One enum so the engine stays single-monomorphised
/// over its [`graphus_wal::LogSink`] parameter, exactly as [`StoreDevice`] does for the device.
///
/// The encrypted variant presents **plaintext logical byte offsets upward**, so the WAL byte-offset
/// == LSN invariant is preserved and the plaintext path is byte-identical when no key is configured.
/// The encrypted variant is boxed (it carries the expanded AES-GCM cipher state + the frame index),
/// keeping the enum small so the plaintext path pays no size penalty.
#[derive(Debug)]
pub enum WalSink {
    /// The plaintext path — unchanged from before WAL encryption existed.
    Plain(FileLogSink),
    /// The encrypted path — every synced batch is one AES-256-GCM frame (`graphus-crypto`). Boxed
    /// to keep the enum small (see the type docs).
    Encrypted(Box<EncryptedFileLogSink>),
}

impl LogSink for WalSink {
    fn append(&mut self, bytes: &[u8]) {
        match self {
            Self::Plain(s) => s.append(bytes),
            Self::Encrypted(s) => s.append(bytes),
        }
    }

    fn sync(&mut self) -> Result<()> {
        match self {
            Self::Plain(s) => s.sync(),
            Self::Encrypted(s) => s.sync(),
        }
    }

    fn begin_harden(&mut self) -> Result<graphus_wal::FsyncJob> {
        // Forward through to the concrete sink so the pipelined commit harden (`rmp` #532) actually
        // offloads the `fdatasync` in production — WITHOUT this, `WalSink` (the real type
        // `graphus-server` opens every database with) would inherit the trait's DEFAULT `begin_harden`
        // (a full inline `sync` + no-op job), so the fdatasync would stay on the engine thread and the
        // whole offload would be inert (the reverted prototype's Defect A). The plaintext
        // `FileLogSink` does the real deferred-fdatasync offload; the encrypted sink deliberately keeps
        // the inline default (each synced batch is one AES-GCM frame, so it does not pipeline), which
        // forwarding here preserves.
        match self {
            Self::Plain(s) => s.begin_harden(),
            Self::Encrypted(s) => s.begin_harden(),
        }
    }

    fn complete_harden(&mut self, target_len: u64) {
        // Forward the COMPLETE half so the durable watermark advances on the concrete sink after the
        // offloaded `fdatasync` runs (`rmp` #532); pairs with `begin_harden` above.
        match self {
            Self::Plain(s) => s.complete_harden(target_len),
            Self::Encrypted(s) => s.complete_harden(target_len),
        }
    }

    fn durable_len(&self) -> u64 {
        match self {
            Self::Plain(s) => s.durable_len(),
            Self::Encrypted(s) => s.durable_len(),
        }
    }

    fn buffered_len(&self) -> u64 {
        match self {
            Self::Plain(s) => s.buffered_len(),
            Self::Encrypted(s) => s.buffered_len(),
        }
    }

    fn read_durable(&self, from: u64, into: &mut Vec<u8>) -> Result<()> {
        match self {
            Self::Plain(s) => s.read_durable(from, into),
            Self::Encrypted(s) => s.read_durable(from, into),
        }
    }

    fn read_bounded(&self, from: u64, to: u64, into: &mut Vec<u8>) -> Result<()> {
        // Forward for the same reason `read_durable`/`reclaimed_floor` are forwarded (`rmp` #525):
        // without this, `WalSink` would inherit the trait's default (`read_durable` + truncate), which
        // does not avoid the unbounded allocation this method exists to prevent.
        match self {
            Self::Plain(s) => s.read_bounded(from, to, into),
            Self::Encrypted(s) => s.read_bounded(from, to, into),
        }
    }

    fn reclaim(&mut self, from: u64, up_to: u64) -> Result<()> {
        // Forward to the concrete sink so production WAL disk is actually bounded (`rmp` #116):
        // without this, `WalSink` would inherit the trait's NO-OP `reclaim` and the segmented
        // `FileLogSink` / encrypted sink would never free anything in production.
        match self {
            Self::Plain(s) => s.reclaim(from, up_to),
            Self::Encrypted(s) => s.reclaim(from, up_to),
        }
    }

    fn reclaimed_floor(&self) -> u64 {
        // Forward to the concrete sink for the same reason `reclaim` is forwarded above (`rmp` #525):
        // without this, `WalSink` — the actual type `graphus-server` opens every database with —
        // would silently inherit the trait's default `0` and every reopen would read from true LSN
        // `0`, exactly reproducing the crash this method exists to prevent.
        match self {
            Self::Plain(s) => s.reclaimed_floor(),
            Self::Encrypted(s) => s.reclaimed_floor(),
        }
    }

    fn set_segment_target(&mut self, target_bytes: u64) {
        // Forward to the concrete sink so the store-proportional segment sizing of `rmp` #706 actually
        // reaches production: without this, `WalSink` — the type `graphus-server` opens every database
        // with — would inherit the trait's NO-OP, the segmented `FileLogSink` would keep its fixed
        // 64 MiB seal threshold, and a small database's WAL would climb hundreds of times its store.
        match self {
            Self::Plain(s) => s.set_segment_target(target_bytes),
            Self::Encrypted(s) => s.set_segment_target(target_bytes),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A unique temp WAL directory, removed on drop.
    struct TempWalDir {
        path: std::path::PathBuf,
    }
    impl TempWalDir {
        fn new(tag: &str) -> Self {
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock after epoch")
                .as_nanos();
            let path = std::env::temp_dir().join(format!(
                "graphus-walsink-{tag}-{nanos}-{}",
                std::process::id()
            ));
            Self { path }
        }
    }
    impl Drop for TempWalDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }

    /// `rmp` #532 **Defect-A gate (offload is wired THROUGH `WalSink`, not just `FileLogSink`)**: a
    /// `WalSink::Plain` `begin_harden` must return a genuinely **deferred** fsync job — the records are
    /// written to the file but `durable_len` is NOT advanced until the offloaded job runs and
    /// `complete_harden` is called.
    ///
    /// The reverted prototype's Defect A was that `WalSink` did NOT forward `begin_harden`, so it
    /// inherited the trait's DEFAULT (a full inline `sync` + no-op job): the fdatasync stayed on the
    /// engine thread and the offload was inert in production while unit tests (driving `FileLogSink`
    /// directly) still passed. This asserts the forwarding: on the defective version `begin_harden`
    /// would advance `durable_len` immediately and `assert_eq!(sink.durable_len(), d0)` FAILS.
    #[cfg_attr(
        miri,
        ignore = "real filesystem I/O is outside miri's isolation/UB scope"
    )]
    #[test]
    fn walsink_plain_begin_harden_defers_the_fdatasync() {
        let dir = TempWalDir::new("defecta");
        let mut sink = WalSink::Plain(FileLogSink::open(&dir.path).unwrap());
        // The first sync writes + hardens the header into the anchor (advances durable_len).
        sink.append(b"GWAL0001");
        sink.sync().unwrap();
        let d0 = sink.durable_len();
        assert_eq!(d0, 8, "the header is durable after the anchor sync");

        // Append a batch's records and PREPARE-harden them via `WalSink::begin_harden`.
        sink.append(b"a-batch-of-commit-records");
        let job = sink.begin_harden().unwrap();
        assert_eq!(
            sink.durable_len(),
            d0,
            "Defect A: WalSink::Plain begin_harden must NOT advance durable_len — the fdatasync is \
             deferred to the returned job (if WalSink fell back to the inline default, durable_len \
             would already have jumped here)"
        );
        assert!(
            sink.buffered_len() > sink.durable_len(),
            "the records are written to the file but not yet durable"
        );

        // Run the offloaded fdatasync, then complete the harden — only NOW is the batch durable.
        let target = job.target_len();
        job.run().unwrap();
        sink.complete_harden(target);
        assert!(
            sink.durable_len() > d0,
            "complete_harden (after the offloaded fdatasync) advances the durable watermark"
        );
        assert_eq!(sink.durable_len(), sink.buffered_len());

        // And the bytes survive a reopen (they were genuinely fdatasync'd by the offloaded job).
        drop(sink);
        let reopened = WalSink::Plain(FileLogSink::open(&dir.path).unwrap());
        assert_eq!(reopened.durable_len(), d0 + 25);
    }

    /// The encrypted arm keeps the inline default (no pipelining — each synced batch is one AES-GCM
    /// frame): `begin_harden` hardens inline, so `durable_len` advances immediately. This documents
    /// and pins that deliberate asymmetry (`rmp` #532/#533).
    #[cfg_attr(
        miri,
        ignore = "real filesystem I/O is outside miri's isolation/UB scope"
    )]
    #[test]
    fn walsink_encrypted_begin_harden_is_inline() {
        use graphus_crypto::{EncryptedFileLogSink, Keyring};
        let dir = TempWalDir::new("defecta-enc");
        let keyring = Keyring::from_master_key(
            [7u8; graphus_crypto::KEY_LEN],
            &[3u8; graphus_crypto::SALT_LEN],
        );
        let backing = FileLogSink::open(dir.path.join("wal")).unwrap();
        let inner = EncryptedFileLogSink::create(backing, &keyring).unwrap();
        let mut sink = WalSink::Encrypted(Box::new(inner));
        // The first sync flushes the sink header + frame 0 and hardens it.
        sink.append(b"first-frame");
        sink.sync().unwrap();
        let d0 = sink.durable_len();
        assert!(d0 > 0, "the first frame is durable after sync");

        sink.append(b"an-encrypted-batch");
        let job = sink.begin_harden().unwrap();
        // Inline default (the encrypted sink does NOT override begin_harden): the fdatasync already
        // happened, so durable_len advanced in begin_harden.
        assert!(
            sink.durable_len() > d0,
            "the encrypted sink hardens inline (no pipelining), so begin_harden advances durable_len"
        );
        let target = job.target_len();
        job.run().unwrap(); // a no-op job
        sink.complete_harden(target); // monotonic no-op
        assert!(sink.durable_len() >= target);
    }
}
