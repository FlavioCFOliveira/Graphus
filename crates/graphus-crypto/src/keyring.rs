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
//! particular substitution. This active-tamper-on-the-live-disk case is out of scope here.
//!
//! This residual gap is **bounded and defeated in practice for the real consumer** (rmp #87): the
//! storage layer verifies each page's own CRC32C header on every read, and an all-zero page fails that
//! check (the CRC32C of an all-zero page body is non-zero while the stored checksum field is zero), so
//! a zeroed-out *real* page is rejected before use. The seemingly-obvious fix — writing `enc(zero-page)`
//! for every extended page so no slot is ever a bare zero — was evaluated and **rejected**: it does not
//! close the gap (a crash after `extend`'s durable `set_len` but before the content writes are synced
//! re-creates all-zero slots that the derived page count includes) and would re-open a crash-recovery
//! window while roughly doubling page-allocation write I/O. The bare-zero read path is therefore
//! retained deliberately; see [`crate::device`]'s `read_page` and module docs for the full analysis.
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
//! each with a distinct `info` label, so the store key and the WAL key are independent: a
//! compromise of one derivation context cannot be replayed against another. The KDF **salt** is a
//! random 16 bytes persisted in the device header; the salt is not secret (HKDF salts never are —
//! their job is domain separation across stores, so two stores with the same master key derive
//! different subkeys).
//!
//! Four subkeys are derived from the same master + salt, each under a distinct `info`:
//! - the **store** page-encryption subkey ([`STORE_SUBKEY_INFO`]);
//! - the **WAL** frame-encryption subkey ([`WAL_SUBKEY_INFO`]);
//! - a dedicated **store KCV** subkey ([`STORE_KCV_SUBKEY_INFO`], rmp #87);
//! - a dedicated **WAL KCV** subkey ([`WAL_KCV_SUBKEY_INFO`], rmp #87).
//!
//! The two KCV subkeys are deliberately **separate** from the encryption subkeys. The KCV is
//! computed under a *fixed* nonce ([`KCV_NONCE`]) while page/frame writes use *random* nonces under
//! the encryption subkeys. Deriving the KCV under its own subkey means the fixed-nonce KCV shares
//! **no nonce space** with any encryption: the KCV subkey is used for exactly one (plaintext, nonce)
//! pair, ever, so the GCM nonce-uniqueness requirement is met not merely with overwhelming
//! probability but by construction (rmp #87). This eliminates the (negligible, 2^-96) chance that a
//! page/frame write under the *same* subkey could ever draw the all-zero nonce and collide with the
//! KCV's (subkey, nonce) pair.

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
/// label rather than a silent reinterpretation of the same bytes).
pub const STORE_SUBKEY_INFO: &[u8] = b"graphus/store/aes-256-gcm/v1";

/// The HKDF `info` label for the write-ahead-log subkey (rmp #88). Distinct from
/// [`STORE_SUBKEY_INFO`], so the WAL and store subkeys are independent even under the same master
/// key + salt: a compromise of one derivation context cannot be replayed against the other. The
/// version suffix means a future scheme change is a new label, never a silent reinterpretation.
pub const WAL_SUBKEY_INFO: &[u8] = b"graphus/wal/aes-256-gcm/v1";

/// The HKDF `info` label for the **store KCV** subkey (rmp #87). The Key-Check-Value is computed
/// under this dedicated subkey, cryptographically independent of [`STORE_SUBKEY_INFO`] (the
/// page-encryption subkey). Because the KCV subkey shares **no nonce space** with the page subkey,
/// the KCV's fixed nonce ([`KCV_NONCE`]) is provably safe: that subkey is used for exactly one
/// (plaintext, nonce) pair, ever — there is no page write under it that could draw the same nonce.
pub const STORE_KCV_SUBKEY_INFO: &[u8] = b"graphus/store-kcv/aes-256-gcm/v1";

/// The HKDF `info` label for the **WAL KCV** subkey (rmp #87), the WAL analogue of
/// [`STORE_KCV_SUBKEY_INFO`]: the WAL KCV is computed under this dedicated subkey, independent of
/// [`WAL_SUBKEY_INFO`] (the frame-encryption subkey), so the WAL KCV's fixed nonce shares no nonce
/// space with any frame encryption.
pub const WAL_KCV_SUBKEY_INFO: &[u8] = b"graphus/wal-kcv/aes-256-gcm/v1";

/// The fixed plaintext sealed under the **store KCV subkey** to form the Key-Check-Value. Any fixed,
/// non-secret constant works; this string documents its own purpose if ever seen in a hex dump.
const KCV_PLAINTEXT: &[u8] = b"graphus-store-kcv-v1";

/// The fixed plaintext sealed under the **WAL KCV subkey** to form the WAL Key-Check-Value. Distinct
/// from [`KCV_PLAINTEXT`] so the two KCVs are visibly different artefacts in a hex dump (though the
/// subkey separation already makes them cryptographically independent).
const WAL_KCV_PLAINTEXT: &[u8] = b"graphus-wal-kcv-v1";

/// The fixed nonce used for the KCV. A fixed nonce is safe here because the KCV is computed under a
/// **dedicated KCV subkey** ([`STORE_KCV_SUBKEY_INFO`] / [`WAL_KCV_SUBKEY_INFO`], rmp #87) that
/// shares no nonce space with page/frame encryption: that subkey is used for exactly one (plaintext,
/// nonce) pair, ever, so the GCM nonce-uniqueness requirement holds **by construction** (it is never
/// reused for a *different* message under the same key, and no random-nonce write can collide with
/// it). The KCV reveals nothing — it is a deterministic function of the key over public inputs,
/// exactly its purpose.
const KCV_NONCE: [u8; 12] = [0u8; 12];

/// The Key-Check-Value: the AES-256-GCM encryption (ciphertext `||` tag) of a fixed known constant
/// under the dedicated **KCV subkey** with a fixed nonce, persisted in the device/sink header. On
/// open it is recomputed and compared **constant-time**; a wrong or missing key fails closed
/// immediately, before any page/frame is read.
pub type Kcv = Vec<u8>;

/// Holds the master key and derives the per-purpose AEAD primitives. The master key is zeroized on
/// drop.
///
/// A `Keyring` is cheap to share behind an [`std::sync::Arc`]; it is `Send + Sync` (it owns only
/// immutable key bytes). Per-page ciphers are derived on demand from the cached subkey, which is
/// itself the only secret retained after construction.
pub struct Keyring {
    /// The derived record-store page-encryption subkey (the master key is consumed into the HKDF and
    /// not retained beyond construction). Zeroized on drop.
    store_subkey: Zeroizing<[u8; KEY_LEN]>,
    /// The derived write-ahead-log frame-encryption subkey (rmp #88), independent of
    /// [`Self::store_subkey`] via a distinct HKDF `info` label. Zeroized on drop.
    wal_subkey: Zeroizing<[u8; KEY_LEN]>,
    /// The derived **store KCV** subkey (rmp #87), cryptographically independent of
    /// [`Self::store_subkey`] via a distinct HKDF `info` label. The KCV is sealed under this subkey
    /// with a fixed nonce, so the KCV's fixed nonce shares no nonce space with page encryption.
    /// Zeroized on drop.
    store_kcv_subkey: Zeroizing<[u8; KEY_LEN]>,
    /// The derived **WAL KCV** subkey (rmp #87), the WAL analogue of [`Self::store_kcv_subkey`],
    /// independent of [`Self::wal_subkey`]. Zeroized on drop.
    wal_kcv_subkey: Zeroizing<[u8; KEY_LEN]>,
}

impl std::fmt::Debug for Keyring {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never render key material.
        f.debug_struct("Keyring").finish_non_exhaustive()
    }
}

impl Keyring {
    /// Builds a keyring from raw 32-byte master key material and the device's KDF salt, deriving the
    /// four purpose-separated subkeys (store, WAL, store-KCV, WAL-KCV) via HKDF-SHA256.
    ///
    /// The `master` bytes are consumed (moved into a `Zeroizing` wrapper and dropped after
    /// derivation) so the caller's copy is the only one left to manage.
    #[must_use]
    pub fn from_master_key(master: [u8; KEY_LEN], salt: &[u8; SALT_LEN]) -> Self {
        let master = Zeroizing::new(master);
        let hkdf = Hkdf::<Sha256>::new(Some(salt.as_slice()), master.as_slice());
        // A small helper to derive one 32-byte subkey under a distinct `info` label. HKDF-Expand
        // cannot fail for a 32-byte output (well under the 255*HashLen ceiling).
        let derive = |info: &[u8]| {
            let mut subkey = Zeroizing::new([0u8; KEY_LEN]);
            hkdf.expand(info, subkey.as_mut_slice())
                .expect("INVARIANT: 32-byte HKDF output is always within the HKDF length bound");
            subkey
        };
        // All four subkeys share the master key + salt (one salt source per store, rmp #88) but each
        // has a distinct `info` label, so they are pairwise cryptographically independent. The two
        // KCV subkeys (rmp #87) are independent of the encryption subkeys, so the KCV's fixed nonce
        // shares no nonce space with random-nonce page/frame writes.
        let store_subkey = derive(STORE_SUBKEY_INFO);
        let wal_subkey = derive(WAL_SUBKEY_INFO);
        let store_kcv_subkey = derive(STORE_KCV_SUBKEY_INFO);
        let wal_kcv_subkey = derive(WAL_KCV_SUBKEY_INFO);
        Self {
            store_subkey,
            wal_subkey,
            store_kcv_subkey,
            wal_kcv_subkey,
        }
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

    /// The AES-256-GCM AEAD primitive for the **store KCV** (rmp #87): a dedicated subkey, distinct
    /// from [`Self::store_cipher`], so the fixed-nonce KCV shares no nonce space with page
    /// encryption.
    #[must_use]
    fn store_kcv_cipher(&self) -> Aes256Gcm {
        Aes256Gcm::new_from_slice(self.store_kcv_subkey.as_slice()).expect(
            "INVARIANT: store KCV subkey is exactly KEY_LEN (32) bytes — a valid AES-256 key",
        )
    }

    /// Computes the Key-Check-Value under the dedicated **store KCV subkey** (rmp #87): the GCM
    /// sealing of a fixed known constant under a fixed nonce. Deterministic for a given key. Because
    /// the KCV subkey is cryptographically independent of the page-encryption subkey and shares no
    /// nonce space with it, the fixed nonce is provably safe (one (plaintext, nonce) pair, ever).
    ///
    /// # Errors
    /// [`GraphusError::Security`] if the AEAD seal fails (not expected for this fixed input).
    pub fn compute_store_kcv(&self) -> Result<Kcv> {
        let cipher = self.store_kcv_cipher();
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

    /// The AES-256-GCM AEAD primitive for write-ahead-log frames (rmp #88).
    #[must_use]
    pub fn wal_cipher(&self) -> Aes256Gcm {
        // `new` cannot fail: the subkey is exactly the 32-byte AES-256 key length.
        Aes256Gcm::new_from_slice(self.wal_subkey.as_slice())
            .expect("INVARIANT: WAL subkey is exactly KEY_LEN (32) bytes — a valid AES-256 key")
    }

    /// The AES-256-GCM AEAD primitive for the **WAL KCV** (rmp #87): a dedicated subkey, distinct
    /// from [`Self::wal_cipher`], so the fixed-nonce WAL KCV shares no nonce space with frame
    /// encryption.
    #[must_use]
    fn wal_kcv_cipher(&self) -> Aes256Gcm {
        Aes256Gcm::new_from_slice(self.wal_kcv_subkey.as_slice())
            .expect("INVARIANT: WAL KCV subkey is exactly KEY_LEN (32) bytes — a valid AES-256 key")
    }

    /// Computes the Key-Check-Value under the dedicated **WAL KCV subkey** (rmp #87): the GCM sealing
    /// of a fixed known constant under a fixed nonce. Deterministic for a given key. Used by the
    /// encrypted WAL sink header so a wrong or missing key fails closed at open, before any frame is
    /// decrypted. As with the store KCV, the dedicated subkey makes the fixed nonce provably safe.
    ///
    /// # Errors
    /// [`GraphusError::Security`] if the AEAD seal fails (not expected for this fixed input).
    pub fn compute_wal_kcv(&self) -> Result<Kcv> {
        let cipher = self.wal_kcv_cipher();
        let nonce = Nonce::from(KCV_NONCE);
        cipher
            .encrypt(&nonce, WAL_KCV_PLAINTEXT)
            .map_err(|_| GraphusError::Security("computing WAL key-check-value failed".to_owned()))
    }

    /// Verifies a stored WAL KCV against this keyring **constant-time**, failing closed on mismatch
    /// (the WAL analogue of [`Self::verify_store_kcv`]).
    ///
    /// # Errors
    /// [`GraphusError::Security`] if the stored KCV does not match the one this key produces — i.e.
    /// the configured key is wrong for this WAL (or the sink header is corrupt). The comparison is
    /// constant-time (no timing oracle on key validity).
    pub fn verify_wal_kcv(&self, stored: &[u8]) -> Result<()> {
        let expected = self.compute_wal_kcv()?;
        let ok = expected.len() == stored.len() && bool::from(expected.as_slice().ct_eq(stored));
        if ok {
            Ok(())
        } else {
            Err(GraphusError::Security(
                "wrong or missing encryption key: the WAL key-check-value does not match (the \
                 encrypted WAL cannot be opened with this key)"
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

    #[test]
    fn wal_kcv_round_trips() {
        let kr = Keyring::from_key_file_bytes(&[0x44u8; KEY_LEN], &salt()).expect("keyring");
        let kcv = kr.compute_wal_kcv().expect("wal kcv");
        kr.verify_wal_kcv(&kcv).expect("verify own wal kcv");
    }

    #[test]
    fn wrong_key_fails_wal_kcv_verification() {
        let kr_a = Keyring::from_key_file_bytes(&[0x01u8; KEY_LEN], &salt()).expect("a");
        let kr_b = Keyring::from_key_file_bytes(&[0x02u8; KEY_LEN], &salt()).expect("b");
        let kcv_a = kr_a.compute_wal_kcv().expect("wal kcv a");
        let err = kr_b
            .verify_wal_kcv(&kcv_a)
            .expect_err("wrong key must fail");
        assert!(matches!(err, GraphusError::Security(_)));
    }

    #[test]
    fn wal_and_store_subkeys_are_independent() {
        // Same key + salt, but the WAL and store subkeys derive under distinct `info` labels, so
        // their KCVs must differ and neither verifies the other's KCV. This is the purpose
        // separation that keeps a compromise of one context from being replayed against the other.
        let kr = Keyring::from_key_file_bytes(&[0x55u8; KEY_LEN], &salt()).expect("keyring");
        let store_kcv = kr.compute_store_kcv().expect("store kcv");
        let wal_kcv = kr.compute_wal_kcv().expect("wal kcv");
        assert_ne!(
            store_kcv, wal_kcv,
            "the two subkeys must produce distinct KCVs"
        );
        assert!(
            kr.verify_wal_kcv(&store_kcv).is_err(),
            "the store KCV must not validate as a WAL KCV"
        );
        assert!(
            kr.verify_store_kcv(&wal_kcv).is_err(),
            "the WAL KCV must not validate as a store KCV"
        );
    }

    #[test]
    fn different_salt_derives_a_different_wal_subkey() {
        let master = [0x77u8; KEY_LEN];
        let kr1 = Keyring::from_key_file_bytes(&master, &[0xA0; SALT_LEN]).expect("kr1");
        let kr2 = Keyring::from_key_file_bytes(&master, &[0xB0; SALT_LEN]).expect("kr2");
        let kcv1 = kr1.compute_wal_kcv().expect("wal kcv1");
        assert!(
            kr2.verify_wal_kcv(&kcv1).is_err(),
            "a different salt must not validate the other WAL's KCV"
        );
    }

    #[test]
    fn store_kcv_uses_a_subkey_independent_of_the_page_subkey() {
        // rmp #87: the KCV must NOT be the seal of the constant under the *page* subkey. If the KCV
        // subkey were the page subkey (the pre-#87 shape), `store_cipher().encrypt(KCV_NONCE, ...)`
        // would equal the KCV; the dedicated KCV subkey makes them differ. This proves the KCV
        // subkey shares no nonce space with page encryption (the fixed nonce is now provably safe).
        let kr = Keyring::from_key_file_bytes(&[0x66u8; KEY_LEN], &salt()).expect("keyring");
        let kcv = kr.compute_store_kcv().expect("store kcv");
        let under_page_subkey = kr
            .store_cipher()
            .encrypt(&Nonce::from(KCV_NONCE), KCV_PLAINTEXT)
            .expect("seal under page subkey");
        assert_ne!(
            kcv, under_page_subkey,
            "the store KCV must be computed under a dedicated subkey, not the page subkey"
        );
    }

    #[test]
    fn wal_kcv_uses_a_subkey_independent_of_the_frame_subkey() {
        // rmp #87, the WAL analogue: the WAL KCV must not be the seal of the constant under the
        // *frame* subkey.
        let kr = Keyring::from_key_file_bytes(&[0x67u8; KEY_LEN], &salt()).expect("keyring");
        let kcv = kr.compute_wal_kcv().expect("wal kcv");
        let under_frame_subkey = kr
            .wal_cipher()
            .encrypt(&Nonce::from(KCV_NONCE), WAL_KCV_PLAINTEXT)
            .expect("seal under frame subkey");
        assert_ne!(
            kcv, under_frame_subkey,
            "the WAL KCV must be computed under a dedicated subkey, not the frame subkey"
        );
    }

    #[test]
    fn all_four_kcv_and_encryption_artefacts_are_distinct() {
        // The four derivation contexts (store/WAL page-encryption + store/WAL KCV) are pairwise
        // independent: every artefact that touches the fixed KCV nonce differs from every other.
        let kr = Keyring::from_key_file_bytes(&[0x68u8; KEY_LEN], &salt()).expect("keyring");
        let store_kcv = kr.compute_store_kcv().expect("store kcv");
        let wal_kcv = kr.compute_wal_kcv().expect("wal kcv");
        // Seals of each KCV constant under each *encryption* subkey at the fixed nonce — none may
        // equal the real KCV (that is the whole point of the dedicated KCV subkeys).
        let store_under_page = kr
            .store_cipher()
            .encrypt(&Nonce::from(KCV_NONCE), KCV_PLAINTEXT)
            .expect("seal");
        let wal_under_frame = kr
            .wal_cipher()
            .encrypt(&Nonce::from(KCV_NONCE), WAL_KCV_PLAINTEXT)
            .expect("seal");
        assert_ne!(store_kcv, wal_kcv);
        assert_ne!(store_kcv, store_under_page);
        assert_ne!(wal_kcv, wal_under_frame);
        assert_ne!(store_under_page, wal_under_frame);
    }
}
