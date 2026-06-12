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
}
