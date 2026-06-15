//! The **random-nonce write budget** that bounds how many AES-256-GCM encryptions are performed
//! under a single subkey before the (key, nonce) birthday-collision probability stops being
//! negligible (SEC-175, CWE-323).
//!
//! ## Why a budget at all
//!
//! Both the store device ([`crate::device`]) and the WAL sink ([`crate::wal_sink`]) draw a **fresh
//! random 96-bit nonce** per write. That is correct CSPRNG practice, but for *random* 96-bit nonces
//! the probability that two writes under the **same subkey** ever draw the same nonce follows the
//! birthday bound: it reaches ~2^-32 at ~2^32 writes per key. NIST SP 800-38D §8.3 therefore caps a
//! single key at 2^32 invocations for the random-nonce construction. A single (key, nonce) reuse in
//! GCM is catastrophic — it leaks the XOR of the two plaintexts **and** the GHASH authentication
//! subkey (universal-hash forgery) — so the cap must be enforced, not merely documented.
//!
//! Under Graphus's "extreme load" mandate a long-lived, high-throughput store can plausibly exceed
//! 2^32 page/frame writes under one subkey, so the previous design (a comment pointing at key
//! rotation, with no actual enforcement) was a latent confidentiality + integrity break. This module
//! makes the bound a **hard, fail-closed ceiling** that is reached **before** the birthday-unsafe
//! region, at which point the device/sink refuses further writes with a clear
//! [`GraphusError::Security`] instructing the operator to rotate the master key (`graphus-server`'s
//! `rotate_master_key`, rmp #86/#89), which re-derives every subkey from a fresh salt and resets the
//! budget by construction.
//!
//! ## The hard ceiling
//!
//! [`MAX_WRITES_PER_SUBKEY`] is set to **2^32**, two orders of magnitude **below** the 2^34 point
//! and well inside the regime NIST treats as safe: at 2^32 writes the collision probability is on
//! the order of 2^-32, the conventional safety margin for a 96-bit random nonce. (The encryption
//! happens under the *encryption* subkey; the dedicated KCV subkey — see [`crate::keyring`] — is used
//! for exactly one message and is therefore excluded from this budget entirely.) The ceiling is a
//! `const` so it can be tuned with measurement; it is deliberately a round power of two so a durable
//! counter never needs more than 33 bits, and overflow arithmetic is trivially correct.
//!
//! ## Durable, conservative resume (write-ahead reservation)
//!
//! A purely in-memory counter would reset to zero on every reopen, so a store reopened millions of
//! times could silently blow far past the real budget. The counter is therefore **durable** and
//! resumed **conservatively** on open: each consumer persists a monotonic high-water mark that is
//! always **≥ the number of writes that ever became durable**, by writing the reservation *before*
//! the writes it covers are hardened (a write-ahead reservation). On open the in-memory counter is
//! seeded from that durable high-water mark, so the budget can only ever be **over**-counted (the
//! safe direction: the cap may fire slightly early, never late). See the store device's counter slot
//! and the WAL frame's per-frame counter for the two concrete persistence strategies.

use graphus_core::error::{GraphusError, Result};

/// The hard ceiling on the number of random-nonce AES-256-GCM encryptions performed under one
/// encryption subkey before writes fail closed and the operator must rotate the master key.
///
/// Set to 2^32. For a random 96-bit nonce the (key, nonce) birthday-collision probability is ~2^-32
/// at this many writes (NIST SP 800-38D §8.3 caps the random-nonce construction at 2^32 invocations
/// per key); reaching it fails closed *before* the unsafe region rather than after. Rotating the
/// master key (which re-derives every subkey from a fresh salt) resets the budget.
pub const MAX_WRITES_PER_SUBKEY: u64 = 1 << 32;

/// A monotonic, fail-closed counter of random-nonce encryptions performed under one subkey.
///
/// The counter is seeded on open from a durable high-water mark (see the module docs) and advanced
/// once per write. [`reserve`](Self::reserve) is called **before** a write is allowed: it refuses
/// once the [`MAX_WRITES_PER_SUBKEY`] ceiling would be crossed, so the unsafe birthday region is
/// never entered. The current value is exposed so each consumer can persist it as its durable
/// reservation.
#[derive(Debug, Clone)]
pub struct NonceBudget {
    /// Writes already consumed under this subkey (durable high-water mark + this-process writes).
    consumed: u64,
}

impl NonceBudget {
    /// Creates a budget that has already consumed `consumed` writes (the durable high-water mark read
    /// at open). A fresh device/sink passes `0`.
    #[must_use]
    pub fn resume_from(consumed: u64) -> Self {
        Self { consumed }
    }

    /// The number of writes consumed so far (the value a consumer persists as its durable
    /// reservation). Monotonic.
    #[must_use]
    pub fn consumed(&self) -> u64 {
        self.consumed
    }

    /// Reserves budget for **one** more write, returning the new consumed count to persist, or fails
    /// closed if the [`MAX_WRITES_PER_SUBKEY`] ceiling has been reached.
    ///
    /// Call this *before* performing the encryption + write. On success the caller is cleared to
    /// encrypt exactly one page/frame; the returned count is the value to record as the durable
    /// reservation (so a crash mid-write can only ever over-count on the next open).
    ///
    /// # Errors
    /// [`GraphusError::Security`] once the random-nonce budget for this subkey is exhausted, with a
    /// message directing the operator to rotate the master key. The write must not proceed.
    pub fn reserve(&mut self) -> Result<u64> {
        if self.consumed >= MAX_WRITES_PER_SUBKEY {
            return Err(GraphusError::Security(format!(
                "random-nonce AES-256-GCM write budget exhausted for this encryption subkey \
                 ({MAX_WRITES_PER_SUBKEY} writes): refusing further writes to avoid a (key, nonce) \
                 birthday collision (NIST SP 800-38D). Rotate the master key to re-derive a fresh \
                 subkey and reset the budget."
            )));
        }
        self.consumed += 1;
        Ok(self.consumed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reserve_advances_monotonically() {
        let mut b = NonceBudget::resume_from(0);
        assert_eq!(b.consumed(), 0);
        assert_eq!(b.reserve().expect("1"), 1);
        assert_eq!(b.reserve().expect("2"), 2);
        assert_eq!(b.consumed(), 2);
    }

    #[test]
    fn reserve_fails_closed_at_the_ceiling() {
        // Seed one below the ceiling: exactly one more write is allowed, then it fails closed.
        let mut b = NonceBudget::resume_from(MAX_WRITES_PER_SUBKEY - 1);
        assert_eq!(
            b.reserve().expect("the last write under the ceiling is allowed"),
            MAX_WRITES_PER_SUBKEY
        );
        let err = b.reserve().expect_err("the ceiling write must fail closed");
        assert!(matches!(err, GraphusError::Security(_)));
        // It stays failed closed (idempotent refusal), never wrapping or resetting.
        assert!(b.reserve().is_err());
        assert_eq!(b.consumed(), MAX_WRITES_PER_SUBKEY);
    }

    #[test]
    fn resume_from_a_durable_high_water_mark_carries_the_budget() {
        // A reopened device resumes the consumed count, so the budget is never silently reset.
        let b = NonceBudget::resume_from(1_000_000);
        assert_eq!(b.consumed(), 1_000_000);
    }
}
