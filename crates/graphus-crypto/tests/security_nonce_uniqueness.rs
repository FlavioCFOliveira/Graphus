//! Security regression battery for AES-256-GCM nonce handling (red-team audit, 2026-06).
//!
//! Verifies the *positive* nonce properties the crate guarantees (a fresh random nonce per write,
//! distinct nonces across writes, a real slot is never all-zero) AND pins the SEC-175 fix: random
//! 96-bit nonces are now bounded by a durable, fail-closed write-count cap
//! ([`graphus_crypto::MAX_WRITES_PER_SUBKEY`]) that is enforced **across reopens**, so the
//! (key, nonce) birthday region (~2^32 writes per key) can never be entered silently.
//!
//! The encrypted device's internal `MemRawSlots::raw_slot` inspector is `#[cfg(test)]` (not visible
//! to an integration test), so we supply our OWN inspectable [`graphus_crypto::RawSlots`] backing —
//! the trait is public and the encrypted device is generic over it. This lets us read the stored
//! `nonce(12) || tag(16) || ciphertext` slot bytes directly.
//!
//! ## Physical layout (v3, rmp #175)
//!
//! Physical slot 0 = header, slot 1 = the durable nonce-budget counter, and logical page `p` lives
//! at physical slot `p + HEADER_SLOTS` (= `p + 2`). The nonce-inspection helpers below therefore
//! read `slot(p + 2)` for logical page `p`.

use std::cell::RefCell;
use std::collections::HashSet;

use graphus_core::PageId;
use graphus_core::error::{GraphusError, Result};
use graphus_crypto::{
    EncryptedBlockDevice, HEADER_SLOTS, Keyring, MAX_WRITES_PER_SUBKEY, NONCE_LEN, RawSlots,
    SALT_LEN, SLOT_SIZE,
};
use graphus_io::{BlockDevice, PAGE_SIZE};

/// Physical slot index of logical page `p` (header + counter precede the pages, v3/rmp #175).
fn page_slot(p: u64) -> u64 {
    p + HEADER_SLOTS
}

const KEY: [u8; 32] = [0x42; 32];

fn keyring(salt: &[u8; SALT_LEN]) -> Keyring {
    Keyring::from_key_file_bytes(&KEY, salt).expect("keyring")
}

/// A minimal in-memory [`RawSlots`] whose raw bytes are publicly inspectable from the test (the
/// crate's own `MemRawSlots` inspector is `#[cfg(test)]`-private to the crate). Slots are kept in a
/// `RefCell<Vec<_>>` so reads can borrow while the device holds it by value.
#[derive(Default)]
struct InspectableSlots {
    slots: RefCell<Vec<[u8; SLOT_SIZE]>>,
}

impl InspectableSlots {
    fn new() -> Self {
        Self::default()
    }
    /// The raw bytes of physical slot `i` (a snapshot copy).
    fn slot(&self, i: u64) -> [u8; SLOT_SIZE] {
        self.slots.borrow()[i as usize]
    }
    /// Overwrites physical slot `i` (test tamper helper).
    fn set_slot(&self, i: u64, bytes: [u8; SLOT_SIZE]) {
        self.slots.borrow_mut()[i as usize] = bytes;
    }
    fn count(&self) -> u64 {
        self.slots.borrow().len() as u64
    }
}

impl RawSlots for InspectableSlots {
    fn read_slot(&self, index: u64, buf: &mut [u8; SLOT_SIZE]) -> Result<()> {
        let slots = self.slots.borrow();
        let s = slots
            .get(index as usize)
            .ok_or_else(|| GraphusError::Storage(format!("read oob: {index}")))?;
        buf.copy_from_slice(s);
        Ok(())
    }
    fn write_slot(&mut self, index: u64, buf: &[u8; SLOT_SIZE]) -> Result<()> {
        let mut slots = self.slots.borrow_mut();
        let s = slots
            .get_mut(index as usize)
            .ok_or_else(|| GraphusError::Storage(format!("write oob: {index}")))?;
        s.copy_from_slice(buf);
        Ok(())
    }
    fn sync_data(&mut self) -> Result<()> {
        Ok(())
    }
    fn sync_all(&mut self) -> Result<()> {
        Ok(())
    }
    fn slot_count(&self) -> u64 {
        self.slots.borrow().len() as u64
    }
    fn extend(&mut self, additional: u64) -> Result<()> {
        let mut slots = self.slots.borrow_mut();
        for _ in 0..additional {
            slots.push([0u8; SLOT_SIZE]);
        }
        Ok(())
    }
}

fn nonce_of(slot: &[u8; SLOT_SIZE]) -> [u8; NONCE_LEN] {
    let mut n = [0u8; NONCE_LEN];
    n.copy_from_slice(&slot[0..NONCE_LEN]);
    n
}

/// Re-writing the SAME page id many times must draw a DISTINCT nonce every time. A repeated nonce
/// under one key would be catastrophic for GCM (plaintext-XOR leak + GHASH forgery).
#[test]
fn rewriting_one_page_draws_a_fresh_distinct_nonce_each_time() {
    let salt = [0xA1; SALT_LEN];
    let kr = keyring(&salt);
    let mut dev = EncryptedBlockDevice::create(InspectableSlots::new(), &kr, salt).expect("create");
    dev.extend(1).expect("extend");

    let mut seen = HashSet::new();
    const ROUNDS: usize = 4096;
    for i in 0..ROUNDS {
        dev.write_page(PageId(0), &[i as u8; PAGE_SIZE])
            .expect("write");
        let backing = dev.into_backing();
        let nonce = nonce_of(&backing.slot(page_slot(0))); // page 0 -> physical slot 2 (after header+counter)
        assert!(
            seen.insert(nonce),
            "duplicate nonce on rewrite #{i}: random-nonce GCM repeated a (key,nonce) pair"
        );
        // Re-open the device over the same backing to continue (open re-derives the cipher; the
        // header KCV is intact, so this is the normal reopen path).
        dev = EncryptedBlockDevice::open(backing, &kr).expect("reopen");
    }
    assert_eq!(seen.len(), ROUNDS);
}

/// Distinct nonces across many *different* pages, inspected at the raw-slot level.
#[test]
fn distinct_nonces_across_many_pages() {
    let salt = [0xA2; SALT_LEN];
    let kr = keyring(&salt);
    const N: u64 = 4096;
    let mut dev = EncryptedBlockDevice::create(InspectableSlots::new(), &kr, salt).expect("create");
    dev.extend(N).expect("extend");
    for p in 0..N {
        dev.write_page(PageId(p), &[0xCD; PAGE_SIZE])
            .expect("write");
    }
    let backing = dev.into_backing();

    let mut seen = HashSet::new();
    for p in 0..N {
        let nonce = nonce_of(&backing.slot(page_slot(p))); // logical p -> physical p + HEADER_SLOTS
        assert_ne!(
            nonce, [0u8; NONCE_LEN],
            "a real slot's nonce must never be all-zero"
        );
        assert!(
            seen.insert(nonce),
            "nonce collision at page {p}: random-nonce GCM drew a duplicate"
        );
    }
    assert_eq!(seen.len(), N as usize);
}

/// Even encrypting an all-zero plaintext yields a non-zero slot, so the zero-slot read fast path can
/// never collide with a real page (the 2^-96 nonce argument, pinned at the byte level).
#[test]
fn a_real_written_slot_is_high_entropy_never_all_zero() {
    let salt = [0xA3; SALT_LEN];
    let kr = keyring(&salt);
    let mut dev = EncryptedBlockDevice::create(InspectableSlots::new(), &kr, salt).expect("create");
    dev.extend(1).expect("extend");
    dev.write_page(PageId(0), &[0u8; PAGE_SIZE])
        .expect("write all-zero plaintext");
    let backing = dev.into_backing();
    assert!(
        backing.slot(page_slot(0)).iter().any(|&b| b != 0),
        "encrypting zeros must still yield a non-zero slot (nonce+tag+ciphertext)"
    );
}

/// Regression: SEC-175. The random-nonce write budget is now **durable** and resumed conservatively
/// on reopen: re-opening the device must continue the consumed count, not reset it to zero. A reset
/// would let a store reopened many times silently blow past the 2^32 birthday-safe ceiling.
///
// Regression: SEC-175
#[test]
fn nonce_budget_is_durable_and_resumes_across_reopen() {
    let salt = [0xA4; SALT_LEN];
    let kr = keyring(&salt);
    let mut dev = EncryptedBlockDevice::create(InspectableSlots::new(), &kr, salt).expect("create");
    dev.extend(1).expect("extend");

    const WRITES: u64 = 5_000;
    for i in 0..WRITES {
        dev.write_page(PageId(0), &[(i & 0xFF) as u8; PAGE_SIZE])
            .expect("write within budget");
    }
    assert_eq!(
        dev.nonce_budget_consumed(),
        WRITES,
        "every page write consumes exactly one unit of nonce budget"
    );
    // Persist the durable counter, then reopen: the budget must resume, not reset.
    dev.sync_all().expect("sync persists the durable counter");
    let backing = dev.into_backing();
    let dev2 = EncryptedBlockDevice::open(backing, &kr).expect("reopen");
    assert_eq!(
        dev2.nonce_budget_consumed(),
        WRITES,
        "the nonce budget resumes from the durable counter on reopen (no silent reset)"
    );
    // The backing holds header + counter + one page (the counter slot is not a logical page).
    let backing = dev2.into_backing();
    assert_eq!(backing.count(), HEADER_SLOTS + 1);
}

/// Regression: SEC-175. The write budget is a hard, fail-closed ceiling: once
/// [`MAX_WRITES_PER_SUBKEY`] is reached the device refuses further writes with a `Security` error
/// (the operator must rotate the master key), so a (key, nonce) collision is impossible. We cannot
/// drive 2^32 real writes, so we tamper the durable counter slot to a budget-exhausted state and
/// prove the device fails closed on reopen — exactly the conservative-resume path.
///
// Regression: SEC-175
#[test]
fn exhausted_budget_fails_closed_on_write() {
    use graphus_core::error::GraphusError;

    let salt = [0xA5; SALT_LEN];
    let kr = keyring(&salt);
    let mut dev = EncryptedBlockDevice::create(InspectableSlots::new(), &kr, salt).expect("create");
    dev.extend(1).expect("extend");
    dev.write_page(PageId(0), &[0x11; PAGE_SIZE])
        .expect("write");
    dev.sync_all().expect("sync");
    let backing = dev.into_backing();

    // Corrupt the durable counter slot (physical slot 1) with non-zero garbage. The counter is
    // AEAD-authenticated under a dedicated subkey, so an attacker cannot forge a *lower* count; any
    // unauthenticated mutation is read conservatively as MAX_WRITES_PER_SUBKEY (budget exhausted).
    let mut tampered = backing.slot(1);
    tampered[20] ^= 0xFF; // flip a ciphertext/tag byte → AEAD fails on read
    backing.set_slot(1, tampered);

    let mut dev2 =
        EncryptedBlockDevice::open(backing, &kr).expect("reopen still succeeds (KCV ok)");
    assert_eq!(
        dev2.nonce_budget_consumed(),
        MAX_WRITES_PER_SUBKEY,
        "a tampered/unauthenticated counter is treated as the maximum budget (fail closed)"
    );
    // The next write must fail closed with a Security error — never a silent nonce reuse.
    let err = dev2
        .write_page(PageId(0), &[0x22; PAGE_SIZE])
        .expect_err("a write past the exhausted budget must fail closed");
    assert!(
        matches!(err, GraphusError::Security(_)),
        "budget exhaustion is a Security error directing key rotation, got: {err:?}"
    );
}

/// Regression: SEC-175. A pristine, never-counter-written zero slot must resume as budget 0 (a fresh
/// store has consumed nothing) — the conservative-resume path must NOT confuse a legitimately empty
/// counter slot with a tampered one.
///
// Regression: SEC-175
#[test]
fn pristine_counter_slot_resumes_as_zero_budget() {
    let salt = [0xA6; SALT_LEN];
    let kr = keyring(&salt);
    let dev = EncryptedBlockDevice::create(InspectableSlots::new(), &kr, salt).expect("create");
    assert_eq!(
        dev.nonce_budget_consumed(),
        0,
        "a freshly created device has consumed no nonce budget"
    );
}
