//! A self-describing, **portable** AEAD envelope for a backup artifact (rmp #89).
//!
//! [`backup_store`](../../graphus_storage/backup/fn.backup_store.html) produces a plaintext snapshot
//! artifact — *plaintext even from an encrypted store*, because it reads page images **above** the
//! device seam (the pages are already decrypted there). To keep a backup confidential at rest, the
//! artifact must therefore be encrypted **separately**, by this envelope.
//!
//! ## Why a fresh salt per envelope (portability)
//!
//! Unlike the store device and the WAL — whose subkeys derive from the master key + *the store's*
//! salt (one salt source per store) — a sealed backup is **self-contained**: it carries its own
//! fresh random salt in its header, so it can be opened with the **master key alone**, independent of
//! any store's salt or even of the store still existing. This is the right shape for a backup that
//! may be restored onto a brand-new machine, or long after the source store is gone.
//!
//! ## Envelope format (all multi-byte integers little-endian)
//!
//! ```text
//!   magic("GRAPHUSB") || version(4) || salt(16) || nonce(12) || ciphertext || tag(16)
//!   └──────────── header (AAD) ────────────┘    └──── AES-256-GCM output ────┘
//! ```
//!
//! - **magic** `"GRAPHUSB"` (Graphus Backup) — distinct from the store (`"GRAPHUSE"`) and WAL
//!   (`"GRAPHUSW"`) magics, so the three encrypted formats can never be confused.
//! - **version** — bumped on any incompatible envelope-layout change (a new label, not a silent
//!   reinterpretation).
//! - **salt** — a fresh random 16-byte HKDF salt, generated per `seal_backup`.
//! - **nonce** — a fresh random 96-bit AES-GCM nonce.
//! - **ciphertext || tag** — the AES-256-GCM sealing of the artifact under the **backup subkey**
//!   (HKDF-SHA256 of the master key + this salt, `info = graphus/backup/aes-256-gcm/v1`).
//!
//! The **AAD is the header bytes** (`magic || version || salt`), so the envelope cannot be spliced:
//! a header from one envelope grafted onto another envelope's ciphertext fails authentication
//! (the salt, hence the subkey, would not match, and the AAD binds the header to the ciphertext).
//!
//! ## Fail-closed guarantees
//!
//! - A wrong master key derives a different subkey → AEAD authentication fails → [`open_backup`]
//!   returns [`GraphusError::Security`]. (There is no KCV here: a backup is opened end-to-end in one
//!   shot, so the AEAD tag *is* the key check — a wrong key cannot decrypt.)
//! - Any flipped byte anywhere (salt, nonce, ciphertext, or tag) breaks authentication → fail
//!   closed. A flipped salt re-derives the wrong subkey; a flipped header byte breaks the AAD; a
//!   flipped ciphertext/tag byte breaks the GCM tag.
//! - A truncated or garbage envelope is rejected by length/magic/version validation **before** any
//!   crypto, with no out-of-bounds read and no unbounded allocation.
//!
//! This module contains **no `unsafe`** and never logs key material or plaintext.

use aes_gcm::aead::Aead;
use aes_gcm::aead::OsRng;
use aes_gcm::aead::rand_core::RngCore;
use aes_gcm::{Aes256Gcm, KeyInit, Nonce};
use graphus_core::error::{GraphusError, Result};
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::keyring::{KEY_LEN, SALT_LEN};
use crate::slot::{NONCE_LEN, TAG_LEN};

/// Magic bytes identifying a sealed Graphus **backup** envelope (`"GRAPHUSB"` — Graphus Backup).
/// Distinct from the store (`"GRAPHUSE"`) and WAL (`"GRAPHUSW"`) magics.
pub const BACKUP_ENVELOPE_MAGIC: [u8; 8] = *b"GRAPHUSB";

/// The sealed-backup envelope format version. Bumped on any incompatible layout change.
pub const BACKUP_ENVELOPE_VERSION: u32 = 1;

/// The HKDF `info` label for the backup subkey (versioned, so a future scheme change is a new label,
/// never a silent reinterpretation of the same bytes). Distinct from the store/WAL `info` labels so
/// the backup subkey is cryptographically independent of them under the same master key.
pub const BACKUP_SUBKEY_INFO: &[u8] = b"graphus/backup/aes-256-gcm/v1";

// Header layout (all multi-byte integers little-endian): magic(8) || version(4) || salt(16).
const OFF_MAGIC: usize = 0;
const OFF_VERSION: usize = 8;
const OFF_SALT: usize = 12;

/// Byte length of the envelope header: magic(8) + version(4) + salt(16). The header is the AEAD AAD.
const HEADER_LEN: usize = 8 + 4 + SALT_LEN;

/// Byte offset where the nonce begins (immediately after the header).
const OFF_NONCE: usize = HEADER_LEN;

/// Byte offset where the AES-GCM output (ciphertext || tag) begins.
const OFF_CIPHERTEXT: usize = OFF_NONCE + NONCE_LEN;

/// The minimum length of a well-formed envelope: header + nonce + an empty GCM output (just the
/// 16-byte tag). A shorter buffer cannot be a valid envelope.
const MIN_ENVELOPE_LEN: usize = OFF_CIPHERTEXT + TAG_LEN;

/// Derives the backup subkey from the master key + `salt` via HKDF-SHA256 under
/// [`BACKUP_SUBKEY_INFO`], returning the AES-256-GCM cipher built from it.
///
/// The subkey lives only inside this function (in a `Zeroizing` buffer wiped on return); only the
/// expanded cipher state escapes.
fn backup_cipher(master: &[u8; KEY_LEN], salt: &[u8; SALT_LEN]) -> Aes256Gcm {
    let hkdf = Hkdf::<Sha256>::new(Some(salt.as_slice()), master.as_slice());
    let mut subkey = Zeroizing::new([0u8; KEY_LEN]);
    // HKDF-Expand cannot fail for a 32-byte output (well under the 255*HashLen ceiling).
    hkdf.expand(BACKUP_SUBKEY_INFO, subkey.as_mut_slice())
        .expect("INVARIANT: 32-byte HKDF output is always within the HKDF length bound");
    // `new` cannot fail: the subkey is exactly the 32-byte AES-256 key length.
    Aes256Gcm::new_from_slice(subkey.as_slice())
        .expect("INVARIANT: backup subkey is exactly KEY_LEN (32) bytes — a valid AES-256 key")
}

/// Builds the envelope header (`magic || version || salt`) used as the AEAD associated data.
fn header_bytes(salt: &[u8; SALT_LEN]) -> [u8; HEADER_LEN] {
    let mut hdr = [0u8; HEADER_LEN];
    hdr[OFF_MAGIC..OFF_MAGIC + 8].copy_from_slice(&BACKUP_ENVELOPE_MAGIC);
    hdr[OFF_VERSION..OFF_VERSION + 4].copy_from_slice(&BACKUP_ENVELOPE_VERSION.to_le_bytes());
    hdr[OFF_SALT..OFF_SALT + SALT_LEN].copy_from_slice(salt);
    hdr
}

/// **Seals** a backup artifact into a portable, self-describing AEAD envelope (rmp #89).
///
/// Generates a fresh random 16-byte salt and 96-bit nonce, derives the backup subkey from
/// `master` + that salt (HKDF-SHA256, [`BACKUP_SUBKEY_INFO`]), and AES-256-GCM seals `plaintext`
/// with the envelope header (`magic || version || salt`) as the associated data. The returned
/// envelope is `magic || version || salt || nonce || ciphertext || tag` (see the module docs for the
/// exact layout and the anti-splicing argument).
///
/// The result is openable with the master key alone — it carries its own salt — so it is independent
/// of any store's salt. The plaintext never appears in the output; the raw bytes are high-entropy
/// ciphertext + a non-secret header.
///
/// # Errors
/// [`GraphusError::Security`] if the AEAD seal fails (not expected for a valid 32-byte key).
pub fn seal_backup(plaintext: &[u8], master: &[u8; KEY_LEN]) -> Result<Vec<u8>> {
    let mut salt = [0u8; SALT_LEN];
    OsRng.fill_bytes(&mut salt);
    let mut nonce_bytes = [0u8; NONCE_LEN];
    OsRng.fill_bytes(&mut nonce_bytes);

    let cipher = backup_cipher(master, &salt);
    let header = header_bytes(&salt);
    let nonce = Nonce::from(nonce_bytes);
    let sealed = cipher
        .encrypt(
            &nonce,
            aes_gcm::aead::Payload {
                msg: plaintext,
                aad: &header,
            },
        )
        .map_err(|_| {
            GraphusError::Security("sealing the backup envelope failed (AEAD encrypt)".to_owned())
        })?;

    // header || nonce || (ciphertext || tag)
    let mut out = Vec::with_capacity(HEADER_LEN + NONCE_LEN + sealed.len());
    out.extend_from_slice(&header);
    out.extend_from_slice(&nonce_bytes);
    out.extend_from_slice(&sealed);
    Ok(out)
}

/// **Opens** a sealed backup envelope, returning the recovered plaintext artifact (rmp #89).
///
/// Validates the envelope structure (length, magic, version) **before** any crypto, re-derives the
/// backup subkey from `master` + the envelope's stored salt, and AES-256-GCM authenticates +
/// decrypts the ciphertext with the header as the associated data. A wrong master key, or any
/// flipped byte (in the salt, nonce, ciphertext, or tag), fails authentication and returns
/// [`GraphusError::Security`] — the envelope is fail-closed end to end.
///
/// # Errors
/// - [`GraphusError::Security`] if the envelope is not a sealed Graphus backup (bad magic), is too
///   short, declares an unsupported version, or fails AEAD authentication (wrong key or any tamper).
///   A malformed envelope is rejected without any out-of-bounds read or unbounded allocation.
pub fn open_backup(sealed: &[u8], master: &[u8; KEY_LEN]) -> Result<Vec<u8>> {
    if sealed.len() < MIN_ENVELOPE_LEN {
        return Err(GraphusError::Security(format!(
            "sealed backup envelope is too short: {} bytes (need at least {MIN_ENVELOPE_LEN})",
            sealed.len()
        )));
    }
    if sealed[OFF_MAGIC..OFF_MAGIC + 8] != BACKUP_ENVELOPE_MAGIC {
        return Err(GraphusError::Security(
            "not a sealed Graphus backup envelope (magic mismatch): refusing to open".to_owned(),
        ));
    }
    let version = u32::from_le_bytes(
        sealed[OFF_VERSION..OFF_VERSION + 4]
            .try_into()
            .expect("4-byte slice (length checked above)"),
    );
    if version != BACKUP_ENVELOPE_VERSION {
        return Err(GraphusError::Security(format!(
            "unsupported sealed-backup envelope version {version} (this build supports \
             {BACKUP_ENVELOPE_VERSION})"
        )));
    }

    let mut salt = [0u8; SALT_LEN];
    salt.copy_from_slice(&sealed[OFF_SALT..OFF_SALT + SALT_LEN]);
    // The header bytes are the AAD; reconstruct them from the stored salt (binds the ciphertext to
    // the exact header, so a spliced/altered header fails authentication).
    let header = header_bytes(&salt);

    let nonce_bytes: [u8; NONCE_LEN] = sealed[OFF_NONCE..OFF_NONCE + NONCE_LEN]
        .try_into()
        .expect("NONCE_LEN slice (length checked above)");
    let nonce = Nonce::from(nonce_bytes);
    let ct_and_tag = &sealed[OFF_CIPHERTEXT..];

    let cipher = backup_cipher(master, &salt);
    cipher
        .decrypt(
            &nonce,
            aes_gcm::aead::Payload {
                msg: ct_and_tag,
                aad: &header,
            },
        )
        .map_err(|_| {
            GraphusError::Security(
                "opening the backup envelope failed: wrong key or a tampered/corrupt envelope (AEAD \
                 authentication failed)"
                    .to_owned(),
            )
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    const MASTER_A: [u8; KEY_LEN] = [0x11; KEY_LEN];
    const MASTER_B: [u8; KEY_LEN] = [0x22; KEY_LEN];

    #[test]
    fn round_trip_recovers_the_plaintext() {
        let plaintext = b"the quick brown fox jumps over the lazy dog".repeat(10);
        let sealed = seal_backup(&plaintext, &MASTER_A).expect("seal");
        let opened = open_backup(&sealed, &MASTER_A).expect("open");
        assert_eq!(opened, plaintext);
    }

    #[test]
    fn round_trip_of_empty_plaintext() {
        // An empty artifact is still a valid (minimal) envelope.
        let sealed = seal_backup(&[], &MASTER_A).expect("seal empty");
        assert_eq!(sealed.len(), MIN_ENVELOPE_LEN);
        let opened = open_backup(&sealed, &MASTER_A).expect("open empty");
        assert!(opened.is_empty());
    }

    #[test]
    fn the_envelope_begins_with_the_magic_and_version() {
        let sealed = seal_backup(b"x", &MASTER_A).expect("seal");
        assert_eq!(&sealed[0..8], &BACKUP_ENVELOPE_MAGIC);
        assert_eq!(
            u32::from_le_bytes(sealed[8..12].try_into().unwrap()),
            BACKUP_ENVELOPE_VERSION
        );
    }

    #[test]
    fn sealed_bytes_contain_no_plaintext_marker() {
        let marker = b"SUPER-SECRET-BACKUP-MARKER";
        let mut plaintext = Vec::new();
        plaintext.extend_from_slice(marker);
        plaintext.extend_from_slice(&[0u8; 4096]); // a chunk of structured data
        let sealed = seal_backup(&plaintext, &MASTER_A).expect("seal");
        assert!(
            !sealed.windows(marker.len()).any(|w| w == marker),
            "the plaintext marker leaked into the sealed envelope"
        );
    }

    #[test]
    fn two_seals_of_the_same_plaintext_differ() {
        // Fresh salt + nonce per seal ⇒ two envelopes of the same plaintext are distinct.
        let p = b"same plaintext";
        let a = seal_backup(p, &MASTER_A).expect("seal a");
        let b = seal_backup(p, &MASTER_A).expect("seal b");
        assert_ne!(
            a, b,
            "salt/nonce randomness must make repeated seals differ"
        );
        // Both still open to the same plaintext.
        assert_eq!(open_backup(&a, &MASTER_A).unwrap(), p);
        assert_eq!(open_backup(&b, &MASTER_A).unwrap(), p);
    }

    #[test]
    fn wrong_key_fails_closed() {
        let sealed = seal_backup(b"confidential", &MASTER_A).expect("seal");
        let err = open_backup(&sealed, &MASTER_B).expect_err("wrong key must fail");
        assert!(matches!(err, GraphusError::Security(_)));
    }

    #[test]
    fn a_flipped_byte_anywhere_fails_closed() {
        let plaintext = b"authenticate every region".repeat(20);
        let sealed = seal_backup(&plaintext, &MASTER_A).expect("seal");

        // One representative offset in each region: salt, nonce, ciphertext, tag.
        let regions = [
            ("salt", OFF_SALT),
            ("nonce", OFF_NONCE),
            ("ciphertext", OFF_CIPHERTEXT),
            ("tag", sealed.len() - 1),
        ];
        for (name, pos) in regions {
            let mut tampered = sealed.clone();
            tampered[pos] ^= 0xFF;
            let err = open_backup(&tampered, &MASTER_A)
                .unwrap_err_or_else_panic(&format!("flipped {name} byte must fail"));
            assert!(
                matches!(err, GraphusError::Security(_)),
                "flipped {name} byte should be a Security error"
            );
        }
    }

    #[test]
    fn a_flipped_byte_in_every_position_fails_closed() {
        // Exhaustive: flipping ANY single byte of the envelope must break authentication.
        let sealed = seal_backup(b"per-byte integrity", &MASTER_A).expect("seal");
        for i in 0..sealed.len() {
            // The version field's high bytes are zero; flipping them yields an unsupported version
            // (still a Security error) rather than an AEAD failure — both are fail-closed, which is
            // all we assert.
            let mut tampered = sealed.clone();
            tampered[i] ^= 0xFF;
            assert!(
                open_backup(&tampered, &MASTER_A).is_err(),
                "flipping byte {i} must fail closed"
            );
        }
    }

    #[test]
    fn truncated_envelope_fails_closed_without_panic() {
        let sealed = seal_backup(b"truncate me", &MASTER_A).expect("seal");
        // Every truncation length from 0 up to (but not including) the full envelope must be rejected
        // cleanly (no panic, no OOB).
        for len in 0..sealed.len() {
            let truncated = &sealed[..len];
            assert!(
                open_backup(truncated, &MASTER_A).is_err(),
                "a {len}-byte truncated envelope must fail closed"
            );
        }
    }

    #[test]
    fn garbage_and_wrong_magic_fail_closed() {
        // Random-ish garbage of various lengths, plus a long buffer with the wrong magic.
        for len in [0usize, 1, 8, MIN_ENVELOPE_LEN, MIN_ENVELOPE_LEN + 100] {
            let garbage = vec![0xABu8; len];
            assert!(open_backup(&garbage, &MASTER_A).is_err());
        }
        // Correct length, wrong magic.
        let mut wrong_magic = vec![0u8; MIN_ENVELOPE_LEN + 16];
        wrong_magic[0..8].copy_from_slice(b"NOTGRAPH");
        let err = open_backup(&wrong_magic, &MASTER_A).expect_err("wrong magic");
        assert!(matches!(err, GraphusError::Security(_)));
    }

    #[test]
    fn unsupported_version_fails_closed() {
        let mut sealed = seal_backup(b"v", &MASTER_A).expect("seal");
        sealed[OFF_VERSION..OFF_VERSION + 4]
            .copy_from_slice(&(BACKUP_ENVELOPE_VERSION + 1).to_le_bytes());
        let err = open_backup(&sealed, &MASTER_A).expect_err("bad version");
        assert!(matches!(err, GraphusError::Security(_)));
    }

    #[test]
    fn splicing_two_envelopes_fails_closed() {
        // Seal two different plaintexts; graft envelope A's header onto envelope B's nonce+ciphertext.
        // The AAD (A's header, carrying A's salt) no longer matches B's subkey/ciphertext ⇒ fail.
        let a = seal_backup(b"alpha-plaintext", &MASTER_A).expect("seal a");
        let b = seal_backup(b"beta-plaintext-longer", &MASTER_A).expect("seal b");
        let mut spliced = Vec::new();
        spliced.extend_from_slice(&a[..HEADER_LEN]); // A's header (magic||version||A-salt)
        spliced.extend_from_slice(&b[HEADER_LEN..]); // B's nonce || ciphertext || tag
        let err = open_backup(&spliced, &MASTER_A).expect_err("spliced envelope must fail");
        assert!(matches!(err, GraphusError::Security(_)));
    }

    /// Tiny helper so the per-region tamper test reads cleanly (a labelled `expect_err`).
    trait UnwrapErrOrPanic<T> {
        fn unwrap_err_or_else_panic(self, msg: &str) -> GraphusError;
    }
    impl UnwrapErrOrPanic<Vec<u8>> for Result<Vec<u8>> {
        fn unwrap_err_or_else_panic(self, msg: &str) -> GraphusError {
            match self {
                Ok(_) => panic!("{msg}"),
                Err(e) => e,
            }
        }
    }
}
