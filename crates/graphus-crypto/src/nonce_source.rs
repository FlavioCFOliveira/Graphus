//! A buffered cryptographically-secure nonce source for AEAD encryption (rmp #378).
//!
//! # Why this exists
//!
//! Every encrypted page write (`device::EncryptedBlockDevice::write_page`) and every sealed WAL
//! frame (`wal_sink::EncryptedLogSink::seal_frame`, one per group-commit/`sync`) needs a fresh,
//! unpredictable 96-bit GCM nonce. The previous implementation drew each nonce straight from
//! `aes_gcm::aead::OsRng` — the **un-buffered** OS RNG — which issues one `getrandom(2)` **syscall
//! per nonce**. A write-heavy or bulk-load workload therefore paid *millions* of `getrandom`
//! syscalls (and, under concurrency, hammered a kernel-side contention point) purely to mint
//! nonces, with the syscall overhead landing squarely on the durability hot path.
//!
//! [`NonceSource`] replaces that with a per-device / per-sink [`ChaCha20Rng`] that is **seeded once**
//! from `OsRng` (a single `getrandom` for the full 32-byte ChaCha20 seed) and thereafter produces
//! every nonce from userspace.
//!
//! # Security: identical guarantees to the OS nonces
//!
//! * **Unpredictability / collision bound.** `ChaCha20Rng` is a *cryptographically secure* PRNG
//!   (ChaCha20, the stream cipher behind `getrandom`'s own backends on several platforms). Its
//!   output is computationally indistinguishable from uniform random, so a 96-bit nonce drawn from
//!   it has the **same birthday-collision probability** as a 96-bit nonce drawn from `OsRng`. The
//!   GCM birthday ceiling — and therefore the durable nonce budget (`crate::nonce_budget`, the max
//!   frames/pages per subkey before a rekey is required) — is **unchanged**: this is a swap of
//!   *one* CSPRNG for *another*, not a weakening of the randomness model.
//!
//! * **Not a counter.** This is deliberately *not* a deterministic counter nonce. A counter nonce
//!   changes the nonce-derivation security model (and would need separate crypto sign-off); the
//!   nonce here is still 96 bits of CSPRNG output, exactly as before.
//!
//! * **AEAD bytes unchanged.** The nonce is still 96 bits placed in the same slot/frame region; the
//!   ciphertext, AAD, and tag are byte-for-byte identical to the `OsRng` path. Only the *source* of
//!   the nonce bytes changed, never the format.
//!
//! # Seeding & reseeding
//!
//! Seeded **once** from `OsRng::from_rng` at device/sink construction. We do **not** add periodic
//! reseeding: forward secrecy of the *nonce stream* is not part of Graphus's at-rest threat model —
//! nonces are written to disk in the clear (they must be, to decrypt), so a nonce is never a secret.
//! What matters is non-repetition and unpredictability, both of which a single ChaCha20 seed
//! provides over a stream length far beyond the GCM birthday budget that bounds a subkey's lifetime.
//! Keeping it to one seed also keeps the syscall count at exactly one per device/sink lifetime.
//!
//! # Thread-safety
//!
//! [`NonceSource`] holds plain `ChaCha20Rng` state and exposes [`next_nonce`](NonceSource::next_nonce)
//! through `&mut self`. The two callers — `EncryptedBlockDevice` (`write_page`/`&mut self`) and
//! `EncryptedLogSink` (`seal_frame`, reached only from `sync`/`&mut self`) — already serialize **all**
//! mutation through `&mut self` on the `BlockDevice` / `LogSink` traits. Rust's exclusive-borrow rule
//! therefore guarantees that no two threads can ever call `next_nonce` on the same source at the same
//! time, so **no nonce can be drawn twice via a data race** — the exclusive `&mut` *is* the
//! synchronization. No `Mutex` is needed (and adding one would only re-establish a guarantee the
//! borrow checker already gives us, at a lock cost on the hot path). `ChaCha20Rng` is itself
//! `Send + Sync`, so embedding it does not weaken the `Send`/`Sync` story of the device or sink.

use rand_chacha::ChaCha20Rng;
use rand_chacha::rand_core::{RngCore, SeedableRng};

use crate::slot::NONCE_LEN;

/// A buffered CSPRNG that mints fresh 96-bit AEAD nonces from userspace, seeded once from `OsRng`.
///
/// See the [module documentation](self) for the security rationale (identical birthday bound to
/// `OsRng`, why it is not a counter, and the thread-safety argument).
pub(crate) struct NonceSource {
    rng: ChaCha20Rng,
}

impl NonceSource {
    /// Creates a nonce source seeded **once** from the OS CSPRNG.
    ///
    /// This performs exactly one `getrandom(2)` syscall (to draw the 32-byte ChaCha20 seed); every
    /// subsequent nonce is generated in userspace.
    ///
    /// # Panics
    /// If the OS RNG fails to provide seed entropy. This mirrors the previous behaviour: the old
    /// `OsRng.fill_bytes(..)` nonce draw would itself panic on OS RNG failure, and a host that cannot
    /// supply randomness cannot safely run an encrypting database, so failing loud at construction is
    /// strictly safer than continuing.
    pub(crate) fn from_os() -> Self {
        // SECURITY: `OsRng` is the platform CSPRNG (the same source the previous per-nonce path used).
        // Seeding ChaCha20Rng from it gives a CSPRNG stream cryptographically indistinguishable from
        // uniform random, preserving the 96-bit nonce birthday bound exactly.
        let rng = ChaCha20Rng::from_rng(aes_gcm::aead::OsRng)
            .expect("INVARIANT: OS CSPRNG must provide ChaCha20 seed entropy on a host running an encrypting store");
        Self { rng }
    }

    /// Draws a fresh, unpredictable 96-bit nonce from the buffered CSPRNG (no syscall).
    pub(crate) fn next_nonce(&mut self) -> [u8; NONCE_LEN] {
        let mut n = [0u8; NONCE_LEN];
        self.rng.fill_bytes(&mut n);
        n
    }
}

impl std::fmt::Debug for NonceSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never expose RNG internal state.
        f.debug_struct("NonceSource").finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn two_sources_seed_independently_and_do_not_collide() {
        // Distinct OsRng seeds → distinct streams; the chance of a 96-bit collision across a few
        // thousand draws is negligible. This guards against an accidental fixed/shared seed.
        let mut a = NonceSource::from_os();
        let mut b = NonceSource::from_os();
        let mut seen: HashSet<[u8; NONCE_LEN]> = HashSet::new();
        for _ in 0..10_000 {
            assert!(
                seen.insert(a.next_nonce()),
                "nonce repeated within source A"
            );
            assert!(seen.insert(b.next_nonce()), "nonce repeated across sources");
        }
    }

    #[test]
    fn nonces_are_unique_across_many_draws() {
        let mut src = NonceSource::from_os();
        let mut seen: HashSet<[u8; NONCE_LEN]> = HashSet::new();
        for _ in 0..100_000 {
            assert!(seen.insert(src.next_nonce()), "the CSPRNG repeated a nonce");
        }
    }
}
