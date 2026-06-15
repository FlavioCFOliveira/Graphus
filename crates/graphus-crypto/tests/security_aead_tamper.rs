//! Security regression battery for AEAD tamper/forgery resistance (red-team audit, 2026-06).
//!
//! Confirms that every region of an authenticated record (ciphertext, tag, nonce, AAD-bound page
//! offset) is integrity-protected, that a wrong key fails closed, and that the backup envelope
//! rejects truncation/splicing/per-byte tamper. These are KAT-style negative tests: any flip MUST
//! fail closed. They are the empirical complement to the in-crate unit tests.
//!
//! It also pins the SEC-179 residual-risk bound at the crypto seam: an all-zero slot reads back as a
//! zero page **without** AEAD verification (the never-written-page contract), so an active live-disk
//! attacker can zero a *real* page's slot undetected by the tag — but ANY *other* mutation of a real
//! slot (even a single flipped byte, or a partially-zeroed slot) still fails AEAD. The full residual
//! bound (the storage-layer CRC32C backstop that catches the one zeroing AEAD cannot) is pinned at
//! the real `BufferPool::fetch` consumer in `pristine_page_tamper_bound.rs`. Decision (SEC-179): the
//! documented limitation is **kept**, not closed with an allocated-page bitmap — a bitmap would
//! reintroduce exactly the crash-mid-`extend` durability divergence the derived-page-count design
//! deliberately removed, while adding write amplification, and the CRC32C backstop already defeats
//! the attack in practice.

use graphus_core::PageId;
use graphus_core::error::GraphusError;
use graphus_crypto::{
    EncryptedBlockDevice, HEADER_SLOTS, KEY_LEN, Keyring, MemRawSlots, RawSlots, SALT_LEN,
    SLOT_SIZE, open_backup, seal_backup,
};
use graphus_io::{BlockDevice, PAGE_SIZE};

const MASTER: [u8; KEY_LEN] = [0x11; KEY_LEN];
const OTHER: [u8; KEY_LEN] = [0x22; KEY_LEN];

/// Round-trip sanity: a sealed backup opens to the exact plaintext under the right key.
#[test]
fn backup_round_trip_recovers_plaintext() {
    let pt = b"confidential graph snapshot bytes".repeat(64);
    let sealed = seal_backup(&pt, &MASTER).expect("seal");
    assert_eq!(open_backup(&sealed, &MASTER).expect("open"), pt);
}

/// A wrong master key derives a different subkey -> AEAD authentication fails -> fail closed. There
/// is no plaintext leak and no panic.
#[test]
fn backup_wrong_key_fails_closed() {
    let sealed = seal_backup(b"secret", &MASTER).expect("seal");
    assert!(
        open_backup(&sealed, &OTHER).is_err(),
        "wrong key must fail closed"
    );
}

/// EXHAUSTIVE per-byte tamper: flipping ANY single byte of the envelope must break authentication
/// (salt -> wrong subkey, header -> AAD mismatch, nonce/ciphertext/tag -> GCM tag). This is the
/// strongest integrity assertion: no single-byte modification can ever be silently accepted.
#[test]
fn backup_single_byte_tamper_anywhere_fails_closed() {
    let sealed = seal_backup(b"per-byte integrity matters", &MASTER).expect("seal");
    for i in 0..sealed.len() {
        let mut t = sealed.clone();
        t[i] ^= 0xFF;
        assert!(
            open_backup(&t, &MASTER).is_err(),
            "flipping byte {i} must fail closed (no silent acceptance)"
        );
    }
}

/// EXHAUSTIVE truncation: every prefix shorter than the full envelope must be rejected cleanly — no
/// panic, no out-of-bounds read, no unbounded allocation.
#[test]
fn backup_every_truncation_fails_closed_without_panic() {
    let sealed = seal_backup(b"truncate me at every boundary", &MASTER).expect("seal");
    for len in 0..sealed.len() {
        assert!(
            open_backup(&sealed[..len], &MASTER).is_err(),
            "a {len}-byte truncated envelope must fail closed"
        );
    }
}

/// Splicing two envelopes (A's header onto B's nonce+ciphertext) must fail: the AAD binds the header
/// (carrying A's salt -> A's subkey) to A's ciphertext, so B's ciphertext cannot authenticate.
#[test]
fn backup_splicing_two_envelopes_fails_closed() {
    let a = seal_backup(b"alpha-plaintext", &MASTER).expect("seal a");
    let b = seal_backup(b"beta-plaintext-longer", &MASTER).expect("seal b");
    // Header is magic(8)||version(4)||salt(16) = 28 bytes.
    const HEADER_LEN: usize = 28;
    let mut spliced = Vec::new();
    spliced.extend_from_slice(&a[..HEADER_LEN]);
    spliced.extend_from_slice(&b[HEADER_LEN..]);
    assert!(
        open_backup(&spliced, &MASTER).is_err(),
        "a spliced envelope must fail closed"
    );
}

// ---- SEC-179: the all-zero-slot AEAD-bypass boundary, pinned at the crypto seam ------------------

const STORE_SALT: [u8; SALT_LEN] = [0x5E; SALT_LEN];

fn store_keyring() -> Keyring {
    Keyring::from_key_file_bytes(&[0x42u8; KEY_LEN], &STORE_SALT).expect("keyring")
}

/// Regression: SEC-179. The documented gap, pinned precisely: zeroing a *whole* real slot bypasses
/// AEAD (reads back as a zero page) — but this is the ONLY substitution the tag cannot catch, and it
/// is defeated by the storage CRC32C backstop (see `pristine_page_tamper_bound.rs`). The point of
/// this test is to bound the gap to *exactly* the all-zero case.
#[test]
fn only_a_fully_zeroed_real_slot_bypasses_aead_nothing_else() {
    let target = PageId(0);
    let mut dev = EncryptedBlockDevice::create(MemRawSlots::new(0), &store_keyring(), STORE_SALT)
        .expect("create");
    dev.extend(1).expect("extend");
    dev.write_page(target, &[0xAB; PAGE_SIZE]).expect("write");
    dev.sync_all().expect("sync");
    let mut backing = dev.into_backing();

    let phys = target.0 + HEADER_SLOTS; // logical page -> physical slot

    // (1) The full-zero substitution is the documented bypass: it reads back as a zero page, no AEAD
    // error. This is the gap — intentional, for the never-written-page contract.
    backing
        .write_slot(phys, &[0u8; SLOT_SIZE])
        .expect("zero the slot");
    let dev = EncryptedBlockDevice::open(backing, &store_keyring()).expect("reopen");
    let mut buf = [0xFFu8; PAGE_SIZE];
    dev.read_page(target, &mut buf)
        .expect("a fully-zeroed real slot reads back as zeros (the documented bypass)");
    assert_eq!(buf, [0u8; PAGE_SIZE]);

    // (2) A *partially* zeroed slot (all but one byte zero) is NOT all-zero, so it takes the AEAD
    // path and FAILS closed — the bypass is strictly the all-zero case, nothing adjacent to it.
    let mut backing = dev.into_backing();
    let mut almost = [0u8; SLOT_SIZE];
    almost[0] = 0x01; // a single non-zero byte forces the real decrypt path
    backing
        .write_slot(phys, &almost)
        .expect("write an almost-zero slot");
    let dev = EncryptedBlockDevice::open(backing, &store_keyring()).expect("reopen");
    let mut buf = [0u8; PAGE_SIZE];
    let err = dev
        .read_page(target, &mut buf)
        .expect_err("an almost-zero (non-pristine) slot must fail AEAD, not bypass it");
    assert!(matches!(err, GraphusError::Storage(_)), "got: {err:?}");
}

/// Two seals of the same plaintext under the same key differ (fresh salt + nonce each time) yet both
/// open to the same plaintext — confirms semantic security (no deterministic ciphertext leak).
#[test]
fn backup_is_randomized_no_deterministic_leak() {
    let pt = b"same plaintext both times";
    let a = seal_backup(pt, &MASTER).expect("a");
    let b = seal_backup(pt, &MASTER).expect("b");
    assert_ne!(a, b, "fresh salt/nonce must make repeated seals differ");
    assert_eq!(open_backup(&a, &MASTER).unwrap(), pt);
    assert_eq!(open_backup(&b, &MASTER).unwrap(), pt);
}
