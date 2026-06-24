//! `graphus-crypto` — authenticated **encryption at rest** for the Graphus record store.
//!
//! This is the foundation half of encryption-at-rest (rmp #85; parent #69, ratified decision
//! `D-security-scope`). It encrypts the record store **at the [`graphus_io::BlockDevice`] seam**, so
//! every 8192-byte logical page is stored as one authenticated-encryption slot. Everything above the
//! seam — the buffer pool, checkpoint, recovery and consistency checker — is untouched: it reads and
//! writes pages through the same trait, transparently decrypted/encrypted.
//!
//! ## What it provides
//!
//! - [`Keyring`] — loads a 256-bit master key from operator-supplied key material, derives
//!   purpose-separated subkeys via HKDF-SHA256, and exposes the store AES-256-GCM AEAD plus a
//!   **Key-Check-Value** so a wrong or missing key fails closed immediately.
//! - [`EncryptedBlockDevice`] / [`EncryptedFileDevice`] — a drop-in [`graphus_io::BlockDevice`] that
//!   stores each page as `nonce(12) || tag(16) || ciphertext(8192)` in a single atomic slot, with a
//!   non-secret header (magic, version, salt, KCV, logical page count) in physical slot 0.
//! - [`EncryptedLogSink`] / [`EncryptedFileLogSink`] — a drop-in [`graphus_wal::LogSink`] (rmp #88)
//!   that encrypts every synced batch of WAL bytes into one authenticated frame while presenting
//!   **plaintext logical byte offsets upward**, so the WAL byte-offset == LSN invariant and the WAL
//!   manager / recovery above the seam are byte-identical. A wrong/missing key fails closed at open
//!   via a WAL Key-Check-Value, and a torn tail frame is dropped (the un-synced-tail-lost crash
//!   semantics the plaintext sink already has).
//!
//! ## Cipher choice: AES-256-GCM
//!
//! AES-256-GCM is an **AEAD** (authenticated encryption with associated data): one primitive gives
//! confidentiality, integrity, and tamper-detection. It is **AES-NI hardware-accelerated** on every
//! Graphus target — x86-64, arm64/aarch64 (incl. Apple Silicon and Raspberry Pi 5) — so the
//! per-page cost is small. It uses the same RustCrypto stack `graphus-auth` already depends on
//! (`argon2`, `jsonwebtoken` with `rust_crypto`), keeping the dependency surface coherent. The nonce
//! is 96-bit, the tag 128-bit; the AAD binds each page to its on-disk offset (a page cannot be
//! silently relocated). The [`Keyring`] type documents the full threat model, and the slot module
//! the crash-consistency argument.
//!
//! ## Scope boundary
//!
//! This crate encrypts the **record-store device** (rmp #85), the **write-ahead log** (rmp #88, via
//! [`EncryptedLogSink`]), and **backup artifacts** (rmp #89, via [`seal_backup`]/[`open_backup`] —
//! a portable, self-describing AEAD envelope independent of any store's salt). Crash-safe **master-
//! key rotation** of an encrypted store directory lives in `graphus-server` (rmp #89), one layer up
//! where the device/WAL files and their swap protocol are owned. This crate's own code contains
//! **no `unsafe`** (the RustCrypto crates use `unsafe` internally for SIMD, which is their concern,
//! not ours).
#![forbid(unsafe_code)]

mod backup_envelope;
mod device;
mod header;
mod keyring;
mod nonce_budget;
mod nonce_source;
mod raw;
mod slot;
mod wal_sink;

pub use backup_envelope::{
    BACKUP_ENVELOPE_MAGIC, BACKUP_ENVELOPE_VERSION, BACKUP_SUBKEY_INFO, open_backup, seal_backup,
};
pub use device::{EncryptedBlockDevice, EncryptedFileDevice};
pub use header::{CIPHER_AES_256_GCM, HEADER_MAGIC, HEADER_SLOTS, HEADER_VERSION, Header};
pub use keyring::{
    COUNTER_SUBKEY_INFO, KEY_LEN, Kcv, Keyring, SALT_LEN, STORE_KCV_SUBKEY_INFO, STORE_SUBKEY_INFO,
    WAL_KCV_SUBKEY_INFO, WAL_SUBKEY_INFO, random_salt,
};
pub use nonce_budget::MAX_WRITES_PER_SUBKEY;
pub use raw::{FileRawSlots, MemRawSlots, RawSlots};
pub use slot::{NONCE_LEN, SLOT_SIZE, TAG_LEN};
pub use wal_sink::{
    EncryptedFileLogSink, EncryptedLogSink, WAL_CIPHER_AES_256_GCM, WAL_SINK_MAGIC,
    WAL_SINK_VERSION,
};
