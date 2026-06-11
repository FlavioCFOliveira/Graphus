//! The [`Keyring`]: master-key loading, HKDF subkey derivation, the store AEAD primitive, and the
//! Key-Check-Value (KCV) used to fail closed on a wrong/missing key.
//!
//! ## Threat model (what encryption at rest does and does not protect)
//!
//! This protects **data at rest on disk**: an attacker who obtains the store file (a stolen disk, a
//! leaked backup, a discarded drive) learns nothing about its contents and cannot forge or tamper
//! with a page undetected — every page is authenticated (AES-256-GCM AEAD), so any modification,
//! truncation, or relocation of a page is caught on read.
//!
//! One documented exception, outside this (stolen-disk *confidentiality*) threat model: a never-written
//! page is stored as an all-zero slot and read back as a zero page *without* AEAD verification (this is
//! required for the never-written-page-reads-zeros contract; see [`crate::device`]'s `read_page`). An
//! *active* attacker with write access to the live disk could therefore overwrite a real page's slot
//! with zeros and have it read as a zero page, with the tag bypassed — AEAD does not detect this
//! particular substitution. This active-tamper-on-the-live-disk case is out of scope here, and it is
//! further mitigated because the storage layer validates each page's own CRC32C/header on read, which
//! rejects a zeroed-out real page. Writing `enc(zero-page)` for every extended page (so no slot is ever
//! a bare zero) is a possible future hardening.
//!
//! It does **not** protect against an attacker who can read the **running process's memory** or who
//! holds the **key**: the plaintext pages live in the buffer pool in cleartext while the server
//! runs (they must, to be queried), and the key is in memory while the server is up. Key material is
//! held in [`zeroize::Zeroizing`] and wiped on drop (defence in depth — keys do not linger in freed
//! memory), but a live-memory adversary is out of scope. This is the standard guarantee of
//! transparent storage encryption (cf. SQLCipher, InnoDB tablespace encryption).
//!
//! ## Key hierarchy
//!
//! A single 256-bit **master key** is loaded at startup from an operator-supplied key file. We never
//! persist the master key ourselves. From it, HKDF-SHA256 derives **purpose-separated subkeys**,
//! each with a distinct `info` label, so the store key and (future) WAL key are independent: a
//! compromise of one derivation context cannot be replayed against another. The KDF **salt** is a
//! random 16 bytes persisted in the device header; the salt is not secret (HKDF salts never are —
//! their job is domain separation across stores, so two stores with the same master key derive
//! different subkeys).

use aes_gcm::aead::Aead;
use aes_gcm::aead::OsRng;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use graphus_core::error::{GraphusError, Result};
use hkdf::Hkdf;
use sha2::Sha256;
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

/// Length of the master key and every derived subkey, in bytes (256-bit).
pub const KEY_LEN: usize = 32;

/// Length of the HKDF salt persisted in the device header, in bytes.
pub const SALT_LEN: usize = 16;

/// The HKDF `info` label for the record-store subkey (versioned, so a future scheme change is a new
/// label rather than a silent reinterpretation of the same bytes). The WAL subkey label
/// (`"graphus/wal/aes-256-gcm/v1"`) is reserved for sub-task #86 and intentionally not derived here.
pub const STORE_SUBKEY_INFO: &[u8] = b"graphus/store/aes-256-gcm/v1";

/// The fixed plaintext encrypted under the store subkey to form the Key-Check-Value. Any fixed,
/// non-secret constant works; this string documents its own purpose if ever seen in a hex dump.
const KCV_PLAINTEXT: &[u8] = b"graphus-store-kcv-v1";

/// The fixed nonce used for the KCV. A fixed nonce is safe here because the KCV plaintext is itself
/// fixed and public: there is exactly one (plaintext, nonce) pair per key, so the GCM
/// nonce-uniqueness requirement is trivially met (it is never reused for a *different* message under
/// the same key). The KCV reveals nothing — it is a deterministic function of the key over public
/// inputs, exactly its purpose.
const KCV_NONCE: [u8; 12] = [0u8; 12];

/// The Key-Check-Value: the AES-256-GCM encryption (ciphertext `||` tag) of a fixed known constant
/// under the store subkey with a fixed nonce, persisted in the device header. On open it is
/// recomputed and compared **constant-time**; a wrong or missing key fails closed immediately,
/// before any page is read.
pub type Kcv = Vec<u8>;

/// Holds the master key and derives the per-purpose AEAD primitives. The master key is zeroized on
/// drop.
///
/// A `Keyring` is cheap to share behind an [`std::sync::Arc`]; it is `Send + Sync` (it owns only
/// immutable key bytes). Per-page ciphers are derived on demand from the cached subkey, which is
/// itself the only secret retained after construction.
pub struct Keyring {
    /// The derived record-store subkey (the master key is consumed into the HKDF and not retained
    /// beyond construction). Zeroized on drop.
    store_subkey: Zeroizing<[u8; KEY_LEN]>,
}

impl std::fmt::Debug for Keyring {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never render key material.
        f.debug_struct("Keyring").finish_non_exhaustive()
    }
}

impl Keyring {
    /// Builds a keyring from raw 32-byte master key material and the device's KDF salt, deriving the
    /// store subkey via HKDF-SHA256.
    ///
    /// The `master` bytes are consumed (moved into a `Zeroizing` wrapper and dropped after
    /// derivation) so the caller's copy is the only one left to manage.
    #[must_use]
    pub fn from_master_key(master: [u8; KEY_LEN], salt: &[u8; SALT_LEN]) -> Self {
        let master = Zeroizing::new(master);
        let hkdf = Hkdf::<Sha256>::new(Some(salt.as_slice()), master.as_slice());
        let mut store_subkey = Zeroizing::new([0u8; KEY_LEN]);
        // HKDF-Expand cannot fail for a 32-byte output (well under the 255*HashLen ceiling).
        hkdf.expand(STORE_SUBKEY_INFO, store_subkey.as_mut_slice())
            .expect("INVARIANT: 32-byte HKDF output is always within the HKDF length bound");
        Self { store_subkey }
    }

    /// Parses operator-supplied key-file bytes into a 32-byte master key, then derives the keyring.
    ///
    /// The key material is accepted in **one of two forms**, auto-detected by length after trimming
    /// surrounding ASCII whitespace:
    /// - **64 hex characters** (`[0-9a-fA-F]`) → decoded to 32 raw bytes;
    /// - **exactly 32 raw bytes** → used verbatim.
    ///
    /// # Errors
    /// [`GraphusError::Security`] with a clear message if the material is neither 32 raw bytes nor 64
    /// hex characters, or if hex decoding fails. The error never echoes the key bytes.
    pub fn from_key_file_bytes(bytes: &[u8], salt: &[u8; SALT_LEN]) -> Result<Self> {
        let master = parse_master_key(bytes)?;
        Ok(Self::from_master_key(*master, salt))
    }

    /// The AES-256-GCM AEAD primitive for record-store pages.
    #[must_use]
    pub fn store_cipher(&self) -> Aes256Gcm {
        // `new` cannot fail: the subkey is exactly the 32-byte AES-256 key length.
        Aes256Gcm::new_from_slice(self.store_subkey.as_slice())
            .expect("INVARIANT: store subkey is exactly KEY_LEN (32) bytes — a valid AES-256 key")
    }

    /// Computes the Key-Check-Value for the store subkey: the GCM sealing of a fixed known constant
    /// under a fixed nonce. Deterministic for a given key.
    ///
    /// # Errors
    /// [`GraphusError::Security`] if the AEAD seal fails (not expected for this fixed input).
    pub fn compute_store_kcv(&self) -> Result<Kcv> {
        let cipher = self.store_cipher();
        let nonce = Nonce::from(KCV_NONCE);
        cipher
            .encrypt(&nonce, KCV_PLAINTEXT)
            .map_err(|_| GraphusError::Security("computing key-check-value failed".to_owned()))
    }

    /// Verifies a stored KCV against this keyring **constant-time**, failing closed on mismatch.
    ///
    /// # Errors
    /// [`GraphusError::Security`] if the stored KCV does not match the one this key produces — i.e.
    /// the configured key is wrong for this store (or the header is corrupt). The comparison is
    /// constant-time (no timing oracle on key validity).
    pub fn verify_store_kcv(&self, stored: &[u8]) -> Result<()> {
        let expected = self.compute_store_kcv()?;
        // Length first (a length mismatch is not secret); then a constant-time byte compare.
        let ok = expected.len() == stored.len() && bool::from(expected.as_slice().ct_eq(stored));
        if ok {
            Ok(())
        } else {
            Err(GraphusError::Security(
                "wrong or missing encryption key: the store key-check-value does not match (the \
                 store cannot be opened with this key)"
                    .to_owned(),
            ))
        }
    }
}

/// Parses key-file bytes into a 32-byte master key (32 raw bytes, or 64 hex chars). The result is
/// `Zeroizing` so an intermediate copy of the key never lingers.
fn parse_master_key(bytes: &[u8]) -> Result<Zeroizing<[u8; KEY_LEN]>> {
    // Trim only surrounding ASCII whitespace/newlines (a key file commonly ends in a newline). We do
    // NOT trim interior bytes — a raw 32-byte key may legitimately contain whitespace byte values,
    // so trimming is applied to the *outer* edges only and the trimmed length decides the format.
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
        "invalid encryption key material: expected {KEY_LEN} raw bytes or {} hex characters, found \
         {} bytes (the key file content is wrong; key bytes are not logged)",
        KEY_LEN * 2,
        trimmed.len()
    )))
}

/// Trims surrounding ASCII whitespace from a byte slice (`str::trim`'s byte analogue, ASCII only).
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

/// Maps a validated ASCII hex digit to its 0–15 value. Callers must ensure `c.is_ascii_hexdigit()`.
fn hex_val(c: u8) -> u8 {
    match c {
        b'0'..=b'9' => c - b'0',
        b'a'..=b'f' => c - b'a' + 10,
        b'A'..=b'F' => c - b'A' + 10,
        // Unreachable: callers gate on `is_ascii_hexdigit`. Return 0 rather than panic to keep the
        // function total (the gate upstream is the real invariant).
        _ => 0,
    }
}

/// Generates a fresh random 16-byte KDF salt from the OS CSPRNG.
#[must_use]
pub fn random_salt() -> [u8; SALT_LEN] {
    use aes_gcm::aead::rand_core::RngCore;
    let mut salt = [0u8; SALT_LEN];
    OsRng.fill_bytes(&mut salt);
    salt
}

#[cfg(test)]
mod tests {
    use super::*;

    fn salt() -> [u8; SALT_LEN] {
        [0x5A; SALT_LEN]
    }

    #[test]
    fn raw_32_byte_key_is_accepted() {
        let bytes = [0x11u8; KEY_LEN];
        let kr = Keyring::from_key_file_bytes(&bytes, &salt()).expect("raw key");
        // The KCV round-trips: compute then verify.
        let kcv = kr.compute_store_kcv().expect("kcv");
        kr.verify_store_kcv(&kcv).expect("verify own kcv");
    }

    #[test]
    fn hex_64_char_key_is_accepted_and_matches_raw() {
        let raw = [0xABu8; KEY_LEN];
        let hex: String = raw.iter().map(|b| format!("{b:02x}")).collect();
        let kr_hex = Keyring::from_key_file_bytes(hex.as_bytes(), &salt()).expect("hex key");
        let kr_raw = Keyring::from_key_file_bytes(&raw, &salt()).expect("raw key");
        // The hex form decodes to the same master key, so both KCVs match.
        let kcv = kr_raw.compute_store_kcv().expect("kcv");
        kr_hex
            .verify_store_kcv(&kcv)
            .expect("hex key matches raw key");
    }

    #[test]
    fn surrounding_whitespace_is_trimmed_for_hex() {
        let raw = [0x01u8; KEY_LEN];
        let hex: String = raw.iter().map(|b| format!("{b:02x}")).collect();
        let with_ws = format!("\n  {hex}\n");
        let kr = Keyring::from_key_file_bytes(with_ws.as_bytes(), &salt()).expect("trimmed hex");
        let kcv = kr.compute_store_kcv().expect("kcv");
        kr.verify_store_kcv(&kcv).expect("verify");
    }

    #[test]
    fn bad_length_key_fails_closed() {
        let err = Keyring::from_key_file_bytes(b"too-short", &salt()).expect_err("must reject");
        assert!(matches!(err, GraphusError::Security(_)));
        // The error must not echo the (here trivial) key bytes.
        assert!(!err.to_string().contains("too-short"));
    }

    #[test]
    fn different_key_fails_kcv_verification() {
        let kr_a = Keyring::from_key_file_bytes(&[0x01u8; KEY_LEN], &salt()).expect("a");
        let kr_b = Keyring::from_key_file_bytes(&[0x02u8; KEY_LEN], &salt()).expect("b");
        let kcv_a = kr_a.compute_store_kcv().expect("kcv a");
        let err = kr_b
            .verify_store_kcv(&kcv_a)
            .expect_err("wrong key must fail");
        assert!(matches!(err, GraphusError::Security(_)));
    }

    #[test]
    fn different_salt_derives_a_different_subkey() {
        // Same master key, different salt → different store subkey → different KCV (HKDF salt's job:
        // domain separation across stores).
        let master = [0x33u8; KEY_LEN];
        let kr1 = Keyring::from_key_file_bytes(&master, &[0xA0; SALT_LEN]).expect("kr1");
        let kr2 = Keyring::from_key_file_bytes(&master, &[0xB0; SALT_LEN]).expect("kr2");
        let kcv1 = kr1.compute_store_kcv().expect("kcv1");
        assert!(
            kr2.verify_store_kcv(&kcv1).is_err(),
            "a different salt must not validate the other store's KCV"
        );
    }

    #[test]
    fn random_salt_is_not_all_zero() {
        // Vanishingly unlikely to be all zero; guards a broken RNG wiring.
        let s = random_salt();
        assert!(s.iter().any(|&b| b != 0));
    }
}
