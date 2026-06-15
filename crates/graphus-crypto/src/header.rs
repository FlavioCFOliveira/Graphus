//! The encrypted-device **header** (superblock), stored in physical slot 0.
//!
//! The header makes an encrypted store a **distinct on-disk format**: it is magic-tagged, so opening
//! a plaintext store as encrypted (or an encrypted store without the key) fails closed with a clear
//! error rather than misinterpreting bytes. It holds only **non-secret** metadata — a magic string,
//! the format version, the cipher id, the KDF salt (salts are public), and the Key-Check-Value (a
//! deterministic, non-secret function of the key). It contains **no key material and no plaintext
//! user data**.
//!
//! The header is written **exactly once, at create**, and is never rewritten afterwards. The logical
//! page count is **not** stored here: it is derived from the backing slot count
//! (`backing.slot_count() - HEADER_SLOTS`), which is the single source of truth. Keeping a page-count
//! copy in the header would let the two diverge on a crash during `extend` (the file's `set_len` can
//! become durable while a buffered header rewrite is lost), turning a recoverable store into one that
//! refuses to open. Deriving it from the backing removes that divergence entirely, and it means slot
//! 0 (magic/salt/KCV — critical to opening the whole store) is never rewritten on the hot path.
//!
//! The header occupies exactly one physical slot ([`crate::slot::SLOT_SIZE`] bytes), written and
//! read with a single positioned operation like any other slot. Logical page `p` therefore maps to
//! physical slot `p + HEADER_SLOTS`.

use graphus_core::error::{GraphusError, Result};

use crate::keyring::SALT_LEN;
use crate::slot::{SLOT_SIZE, Slot};

/// Number of physical slots reserved at the start of the device before the logical pages. Logical
/// page `p` lives at physical slot `p + HEADER_SLOTS`.
///
/// Two reserved slots (v3, rmp #175):
/// - physical slot 0 — the **header** (magic/version/cipher/salt/KCV), written **once at create**,
///   never rewritten (critical to opening the whole store; see the module docs);
/// - physical slot 1 — the **nonce-budget counter** ([`crate::nonce_budget`]), a durable high-water
///   mark of random-nonce encryptions under the store subkey, rewritten on each `sync` so the
///   2^32-write GCM birthday cap is enforced across reopens. Unlike the header it is *not* critical
///   to opening the store: a torn/garbage counter slot is read conservatively as the maximum
///   budget, failing closed rather than risking nonce reuse.
pub const HEADER_SLOTS: u64 = 2;

/// Physical slot index of the header superblock (written once at create).
pub const HEADER_SLOT_INDEX: u64 = 0;

/// Physical slot index of the durable nonce-budget counter (rewritten on each sync, rmp #175).
pub const COUNTER_SLOT_INDEX: u64 = 1;

/// Magic bytes identifying a Graphus **encrypted** store file (ASCII "GRAPHUSE" — Graphus
/// Encrypted). Distinct from the plaintext store magic so the two formats can never be confused.
pub const HEADER_MAGIC: [u8; 8] = *b"GRAPHUSE";

/// The encrypted on-disk format version. Bumped on any incompatible header/slot layout change, or
/// any change to how the persisted KCV bytes are computed.
///
/// - **v1**: KCV sealed under the *store* page-encryption subkey.
/// - **v2** (rmp #87): KCV sealed under a dedicated, independent *store-KCV* subkey (the fixed KCV
///   nonce now shares no nonce space with page encryption). This changes the persisted KCV bytes, so
///   a v1 file's KCV would not validate under v2 anyway; the version check fails it closed first with
///   a clear "unsupported version" error. This is a pre-1.0 greenfield database with **no persisted
///   production encrypted stores**, so no migration path is needed.
/// - **v3** (rmp #175): a dedicated **nonce-budget counter** slot (physical slot 1) is reserved
///   before the logical pages, so [`HEADER_SLOTS`] grew from 1 to 2 and logical page `p` now lives
///   at slot `p + 2`. The counter durably bounds random-nonce encryptions under the store subkey to
///   the GCM birthday-safe ceiling ([`crate::nonce_budget::MAX_WRITES_PER_SUBKEY`]). A v2 file fails
///   closed at open on the version check. No migration is needed (pre-1.0, no persisted production
///   encrypted stores).
pub const HEADER_VERSION: u32 = 3;

/// Cipher identifier for AES-256-GCM with a 96-bit nonce and 128-bit tag.
pub const CIPHER_AES_256_GCM: u32 = 1;

/// Length of the persisted KCV (AES-256-GCM sealing of a fixed 20-byte plaintext = 20-byte
/// ciphertext + 16-byte tag).
const KCV_LEN: usize = 20 + 16;

// Byte offsets within the header slot (all little-endian for multi-byte integers). The logical page
// count is deliberately NOT stored here — it is derived from the backing slot count (see module
// docs), so there is no page-count field to keep in step with the backing on `extend`.
const OFF_MAGIC: usize = 0; // 8 bytes
const OFF_VERSION: usize = 8; // 4 bytes
const OFF_CIPHER: usize = 12; // 4 bytes
const OFF_SALT: usize = 16; // SALT_LEN bytes
const OFF_KCV_LEN: usize = 16 + SALT_LEN; // 4 bytes
const OFF_KCV: usize = 20 + SALT_LEN; // KCV_LEN bytes

/// The parsed, validated header of an encrypted device.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Header {
    /// The KDF salt (public).
    pub salt: [u8; SALT_LEN],
    /// The persisted Key-Check-Value.
    pub kcv: Vec<u8>,
}

impl Header {
    /// Serialises the header into one physical slot. Unused trailing bytes are zero.
    #[must_use]
    pub fn encode(&self) -> Slot {
        let mut slot = [0u8; SLOT_SIZE];
        slot[OFF_MAGIC..OFF_MAGIC + 8].copy_from_slice(&HEADER_MAGIC);
        slot[OFF_VERSION..OFF_VERSION + 4].copy_from_slice(&HEADER_VERSION.to_le_bytes());
        slot[OFF_CIPHER..OFF_CIPHER + 4].copy_from_slice(&CIPHER_AES_256_GCM.to_le_bytes());
        slot[OFF_SALT..OFF_SALT + SALT_LEN].copy_from_slice(&self.salt);
        let kcv_len = self.kcv.len() as u32;
        slot[OFF_KCV_LEN..OFF_KCV_LEN + 4].copy_from_slice(&kcv_len.to_le_bytes());
        slot[OFF_KCV..OFF_KCV + self.kcv.len()].copy_from_slice(&self.kcv);
        slot
    }

    /// Parses and validates a header slot, failing closed on a wrong magic, unsupported version, or
    /// unsupported cipher.
    ///
    /// # Errors
    /// [`GraphusError::Security`] if the magic does not match (this is not an encrypted Graphus store
    /// — e.g. a plaintext store opened as encrypted), or [`GraphusError::Storage`] if the version,
    /// cipher, or KCV length is unsupported/corrupt.
    pub fn decode(slot: &Slot) -> Result<Self> {
        let magic = &slot[OFF_MAGIC..OFF_MAGIC + 8];
        if magic != HEADER_MAGIC {
            return Err(GraphusError::Security(
                "not an encrypted Graphus store (header magic mismatch): refusing to open. A \
                 plaintext store cannot be opened as encrypted, nor vice versa"
                    .to_owned(),
            ));
        }
        let version = u32::from_le_bytes(read4(slot, OFF_VERSION));
        if version != HEADER_VERSION {
            return Err(GraphusError::Storage(format!(
                "unsupported encrypted-store format version {version} (this build supports \
                 {HEADER_VERSION})"
            )));
        }
        let cipher = u32::from_le_bytes(read4(slot, OFF_CIPHER));
        if cipher != CIPHER_AES_256_GCM {
            return Err(GraphusError::Storage(format!(
                "unsupported cipher id {cipher} in encrypted-store header (this build supports \
                 AES-256-GCM = {CIPHER_AES_256_GCM})"
            )));
        }
        let mut salt = [0u8; SALT_LEN];
        salt.copy_from_slice(&slot[OFF_SALT..OFF_SALT + SALT_LEN]);
        let kcv_len = u32::from_le_bytes(read4(slot, OFF_KCV_LEN)) as usize;
        if kcv_len != KCV_LEN || OFF_KCV + kcv_len > SLOT_SIZE {
            return Err(GraphusError::Storage(format!(
                "corrupt encrypted-store header: KCV length {kcv_len} is invalid (expected \
                 {KCV_LEN})"
            )));
        }
        let kcv = slot[OFF_KCV..OFF_KCV + kcv_len].to_vec();
        Ok(Self { salt, kcv })
    }
}

fn read4(slot: &Slot, off: usize) -> [u8; 4] {
    let mut b = [0u8; 4];
    b.copy_from_slice(&slot[off..off + 4]);
    b
}

// --- nonce-budget counter slot (physical slot 1, rmp #175) ----------------------------------------
//
// The counter slot durably records the random-nonce write high-water mark for the store subkey (see
// `crate::nonce_budget`). It is authenticated under the dedicated counter subkey
// (`Keyring::counter_cipher`) with a fresh random nonce per rewrite, so a torn or maliciously
// tampered counter slot fails AEAD and is read conservatively as the maximum budget (fail closed) —
// an attacker cannot lower the count to defeat the GCM birthday cap.
//
// Layout: magic(8) || nonce(12) || tag(16) || ciphertext(8 = counter u64 LE). The AAD is the slot
// magic so the slot cannot be repurposed from another offset.

use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, Nonce};

use crate::nonce_budget::MAX_WRITES_PER_SUBKEY;
use crate::slot::{NONCE_LEN, TAG_LEN};

/// Magic bytes identifying the nonce-budget counter slot (`"GRPHCNTR"`).
const COUNTER_MAGIC: [u8; 8] = *b"GRPHCNTR";
const CNT_OFF_MAGIC: usize = 0;
const CNT_OFF_NONCE: usize = 8;
const CNT_OFF_CIPHERTEXT: usize = CNT_OFF_NONCE + NONCE_LEN; // ciphertext || tag follow

/// Encodes the durable nonce-budget counter into physical slot 1, authenticated under the counter
/// subkey with a fresh random nonce. Trailing bytes are zero.
///
/// # Errors
/// [`GraphusError::Security`] if the AEAD seal fails (not expected for this fixed-size input).
pub fn encode_counter_slot(counter: u64, counter_cipher: &Aes256Gcm) -> Result<Slot> {
    let nonce_bytes = random_counter_nonce();
    let nonce = Nonce::from(nonce_bytes);
    let sealed = counter_cipher
        .encrypt(
            &nonce,
            aes_gcm::aead::Payload {
                msg: &counter.to_le_bytes(),
                aad: &COUNTER_MAGIC,
            },
        )
        .map_err(|_| GraphusError::Security("sealing the nonce-budget counter failed".to_owned()))?;
    let mut slot = [0u8; SLOT_SIZE];
    slot[CNT_OFF_MAGIC..CNT_OFF_MAGIC + 8].copy_from_slice(&COUNTER_MAGIC);
    slot[CNT_OFF_NONCE..CNT_OFF_NONCE + NONCE_LEN].copy_from_slice(&nonce_bytes);
    // sealed = ciphertext(8) || tag(16); both fit comfortably in one slot.
    debug_assert_eq!(sealed.len(), 8 + TAG_LEN);
    slot[CNT_OFF_CIPHERTEXT..CNT_OFF_CIPHERTEXT + sealed.len()].copy_from_slice(&sealed);
    Ok(slot)
}

/// Decodes and authenticates the durable nonce-budget counter from physical slot 1.
///
/// Fails **conservatively**: a fresh all-zero slot (a store created before its first counter sync, or
/// an interrupted extend) decodes to `0` (no writes yet); any *other* slot that does not authenticate
/// — a torn write, a tampered/zeroed-out-but-non-empty slot, or corruption — is treated as
/// [`MAX_WRITES_PER_SUBKEY`] (the budget is considered exhausted), so the device fails closed on the
/// next write rather than risking nonce reuse. This is the safe direction: an attacker cannot lower
/// the count, only (harmlessly) force an early rotation.
#[must_use]
pub fn decode_counter_slot(slot: &Slot, counter_cipher: &Aes256Gcm) -> u64 {
    // A genuinely pristine (never-counter-written) slot is all-zero → 0 writes consumed.
    if slot.iter().all(|&b| b == 0) {
        return 0;
    }
    if slot[CNT_OFF_MAGIC..CNT_OFF_MAGIC + 8] != COUNTER_MAGIC {
        return MAX_WRITES_PER_SUBKEY; // not a counter slot / corrupt → fail closed
    }
    let nonce_bytes: [u8; NONCE_LEN] = match slot[CNT_OFF_NONCE..CNT_OFF_NONCE + NONCE_LEN].try_into()
    {
        Ok(n) => n,
        Err(_) => return MAX_WRITES_PER_SUBKEY,
    };
    let nonce = Nonce::from(nonce_bytes);
    let ct_and_tag = &slot[CNT_OFF_CIPHERTEXT..CNT_OFF_CIPHERTEXT + 8 + TAG_LEN];
    match counter_cipher.decrypt(
        &nonce,
        aes_gcm::aead::Payload {
            msg: ct_and_tag,
            aad: &COUNTER_MAGIC,
        },
    ) {
        Ok(pt) if pt.len() == 8 => {
            let mut b = [0u8; 8];
            b.copy_from_slice(&pt);
            u64::from_le_bytes(b)
        }
        // AEAD failure or unexpected length → corrupt/tampered counter → fail closed (max budget).
        _ => MAX_WRITES_PER_SUBKEY,
    }
}

/// Draws a fresh random 96-bit nonce for a counter-slot rewrite from the OS CSPRNG.
fn random_counter_nonce() -> [u8; NONCE_LEN] {
    use aes_gcm::aead::OsRng;
    use aes_gcm::aead::rand_core::RngCore;
    let mut n = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut n);
    n
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Header {
        Header {
            salt: [0x42; SALT_LEN],
            kcv: vec![0xCC; KCV_LEN],
        }
    }

    #[test]
    fn encode_decode_roundtrips() {
        let h = sample();
        let slot = h.encode();
        let back = Header::decode(&slot).expect("decode");
        assert_eq!(h, back);
    }

    #[test]
    fn header_fits_in_one_slot() {
        // The header layout must fit within a single physical slot with room to spare (a
        // compile-time guarantee).
        const { assert!(OFF_KCV + KCV_LEN <= SLOT_SIZE) };
    }

    #[test]
    fn wrong_magic_fails_closed_as_security_error() {
        let mut slot = sample().encode();
        slot[0] = b'X'; // corrupt the magic
        let err = Header::decode(&slot).expect_err("must reject");
        assert!(matches!(err, GraphusError::Security(_)));
    }

    #[test]
    fn zeroed_slot_is_rejected() {
        // A fresh zero slot (e.g. a plaintext store's first page read through this layer) has no
        // magic and must fail closed.
        let slot = [0u8; SLOT_SIZE];
        assert!(matches!(
            Header::decode(&slot),
            Err(GraphusError::Security(_))
        ));
    }

    #[test]
    fn unsupported_version_is_a_storage_error() {
        let mut slot = sample().encode();
        slot[OFF_VERSION..OFF_VERSION + 4].copy_from_slice(&999u32.to_le_bytes());
        assert!(matches!(
            Header::decode(&slot),
            Err(GraphusError::Storage(_))
        ));
    }
}
