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
//! # Fork safety (rmp #393) — the one mandatory reseed
//!
//! There is exactly **one** situation that *forces* a reseed: a `fork(2)`. A buffered userspace
//! CSPRNG is **not** fork-safe by default. `fork` clones the parent's entire address space, including
//! the `ChaCha20Rng` state, so immediately after a fork the parent and child hold the **identical**
//! RNG state and would emit the **identical** nonce stream. If both then write under the **same**
//! encryption subkey (the common case — they share the open device/sink and its derived subkey),
//! every `(key, nonce)` pair repeats across the two processes. For AES-256-GCM that is the
//! catastrophic failure mode: it leaks the XOR of the two plaintexts **and** the GHASH
//! authentication subkey (universal-hash forgery). The pre-#378 per-call `OsRng` path did **not**
//! have this hazard, because `getrandom(2)` reads fresh kernel entropy on every call in *both*
//! processes; introducing a userspace buffer re-introduced it. (This is the same class of bug the
//! OpenSSL/`fork` RNG-reseed mitigations and `pthread_atfork` handlers address.)
//!
//! [`NonceSource`] closes this by **stamping the PID** at seed time and re-checking it before every
//! nonce draw. If the current PID differs from the stamp, the process has forked (or otherwise
//! changed identity), so the source **reseeds from `OsRng`** and re-stamps before producing the
//! nonce. Cost on the steady-state hot path is one `getpid`-equivalent (`std::process::id`, a single
//! cheap syscall — vDSO-fast on Linux) and an integer compare; the expensive reseed runs only on the
//! first draw after an actual fork. This is option (a) of rmp #393: a pid-stamped buffer that
//! reseeds on mismatch — chosen over a `pthread_atfork` handler (no extra FFI/global handler state,
//! and it works even for a fork that never calls back into our handler, e.g. a raw `clone`) and over
//! reverting to per-draw `OsRng` (which would discard the #378 syscall win on the durability hot
//! path). The PID source is injectable (see [`NonceSource::with_pid_source`]) so the reseed-on-fork
//! behaviour is testable deterministically without an actual `fork`.
//!
//! **Interaction with the nonce budget / persistence (`crate::nonce_budget`).** The reseed is
//! invisible to the budget. The budget bounds the number of GCM encryptions under one subkey so the
//! birthday-collision probability of *random* nonces stays negligible; it is agnostic to *which*
//! CSPRNG stream produced those random bytes. A reseed swaps the stream for a fresh independent one
//! (so the child's nonces are independent of the parent's, restoring non-collision) **without**
//! drawing, consuming, or rewinding any budget: `next_nonce` does not touch
//! [`NonceBudget`](crate::nonce_budget::NonceBudget), the
//! persisted WAL `write_count` / store counter slot is never read or written here, and the reseed
//! neither double-counts nor re-uses a `write_count`. The budget is reserved by the caller *around*
//! the nonce draw exactly as before. A forked child that keeps writing under the same subkey simply
//! continues consuming the *same* durable budget — which is the safe direction, since the budget is a
//! per-subkey cap, not a per-process one.
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

/// A buffered CSPRNG that mints fresh 96-bit AEAD nonces from userspace, seeded once from `OsRng`
/// and **reseeded on `fork`** (PID change) to stay fork-safe (rmp #393).
///
/// See the [module documentation](self) for the security rationale (identical birthday bound to
/// `OsRng`, why it is not a counter, the fork-safety argument, and the thread-safety argument).
pub(crate) struct NonceSource {
    rng: ChaCha20Rng,
    /// The PID under which `rng` was last (re)seeded. A mismatch on the current PID means the process
    /// forked and the inherited `rng` state is shared with another process, so it must be reseeded
    /// before the next draw (rmp #393).
    seeded_pid: u32,
    /// The source of the current process PID. `std::process::id` in production; injectable in tests
    /// so reseed-on-fork is exercised deterministically without an actual `fork`.
    pid_of: fn() -> u32,
}

impl NonceSource {
    /// Creates a nonce source seeded **once** from the OS CSPRNG, stamped with the current PID.
    ///
    /// This performs exactly one `getrandom(2)` syscall (to draw the 32-byte ChaCha20 seed); every
    /// subsequent nonce is generated in userspace, except on the first draw after a `fork` (see the
    /// [module docs](self)), which reseeds once.
    ///
    /// # Panics
    /// If the OS RNG fails to provide seed entropy. This mirrors the previous behaviour: the old
    /// `OsRng.fill_bytes(..)` nonce draw would itself panic on OS RNG failure, and a host that cannot
    /// supply randomness cannot safely run an encrypting database, so failing loud at construction is
    /// strictly safer than continuing.
    pub(crate) fn from_os() -> Self {
        Self::with_pid_source(std::process::id)
    }

    /// Like [`from_os`](Self::from_os) but with an injectable PID source, so the reseed-on-fork
    /// behaviour can be driven deterministically in tests (a fake PID provider) without a real
    /// `fork`. Production always uses [`from_os`] (`std::process::id`).
    pub(crate) fn with_pid_source(pid_of: fn() -> u32) -> Self {
        Self {
            rng: Self::fresh_rng(),
            seeded_pid: pid_of(),
            pid_of,
        }
    }

    /// Test-only: a nonce source seeded from a **fixed** 32-byte seed, so two sources draw the
    /// **identical** nonce stream. Used to prove a higher layer's nonce is independent of some other
    /// input (e.g. the WAL `write_count`): hold the nonce stream fixed across two seals and show the
    /// nonce bytes match while the other input varies. The PID source is `std::process::id`, so the
    /// stamp matches (no spurious reseed) within a single test process.
    #[cfg(test)]
    pub(crate) fn from_fixed_seed(seed: [u8; 32]) -> Self {
        Self {
            rng: ChaCha20Rng::from_seed(seed),
            seeded_pid: std::process::id(),
            pid_of: std::process::id,
        }
    }

    /// Seeds a fresh `ChaCha20Rng` from the OS CSPRNG.
    fn fresh_rng() -> ChaCha20Rng {
        // SECURITY: `OsRng` is the platform CSPRNG (the same source the previous per-nonce path used).
        // Seeding ChaCha20Rng from it gives a CSPRNG stream cryptographically indistinguishable from
        // uniform random, preserving the 96-bit nonce birthday bound exactly.
        ChaCha20Rng::from_rng(aes_gcm::aead::OsRng)
            .expect("INVARIANT: OS CSPRNG must provide ChaCha20 seed entropy on a host running an encrypting store")
    }

    /// Draws a fresh, unpredictable 96-bit nonce from the buffered CSPRNG (no syscall on the steady
    /// path).
    ///
    /// Before drawing, it re-checks the process PID: if it differs from the PID stamped at the last
    /// seed, the process has forked and the inherited `rng` state is shared with another process, so
    /// it **reseeds from `OsRng`** and re-stamps first (rmp #393). This is the one mandatory reseed;
    /// it guarantees a forked child never replays the parent's nonce stream under the same subkey.
    /// The reseed does **not** touch the nonce budget or any persisted `write_count` (see module
    /// docs): it only swaps the random-byte stream for a fresh independent one.
    pub(crate) fn next_nonce(&mut self) -> [u8; NONCE_LEN] {
        let pid = (self.pid_of)();
        if pid != self.seeded_pid {
            // Fork detected: parent and child share the inherited stream. Reseed to an independent
            // stream so no (key, nonce) pair can ever repeat across the two processes.
            self.rng = Self::fresh_rng();
            self.seeded_pid = pid;
        }
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

    // ----------------------------------------------------------------------------------------------
    // Fork-safety (rmp #393)
    // ----------------------------------------------------------------------------------------------

    use std::cell::Cell;

    // A *thread-local* fake PID the injected pid source reads. Thread-local (not a process-global
    // static) so the parallel test runner cannot let one test's PID flip perturb another's: each
    // `#[test]` runs on its own thread and sees its own cell. Lets a test deterministically "fork"
    // by flipping the PID, exercising reseed-on-mismatch without an actual `fork(2)`.
    thread_local! {
        static FAKE_PID: Cell<u32> = const { Cell::new(1000) };
    }

    fn set_fake_pid(p: u32) {
        FAKE_PID.with(|c| c.set(p));
    }

    fn fake_pid() -> u32 {
        FAKE_PID.with(Cell::get)
    }

    /// rmp #393 regression: a PID change (a fork) MUST reseed the buffer so the post-fork nonce
    /// stream is independent of the pre-fork one. This is the deterministic stand-in for a real
    /// `fork`: we clone the source's state into a second source (modelling the child inheriting the
    /// parent's address space) and then flip the PID seen by the *child*. Without reseed-on-mismatch
    /// the two streams are byte-identical (catastrophic (key, nonce) reuse); with it they diverge.
    #[test]
    fn pid_change_reseeds_so_streams_never_collide() {
        set_fake_pid(1000);

        // Parent, seeded under PID 1000.
        let mut parent = NonceSource::with_pid_source(fake_pid);

        // Model `fork`: the child inherits an IDENTICAL copy of the parent's RNG state and PID stamp.
        let mut child = NonceSource {
            rng: parent.rng.clone(),
            seeded_pid: parent.seeded_pid,
            pid_of: fake_pid,
        };

        // Sanity: with the SAME stamp and SAME state, the two would emit identical streams — this is
        // exactly the fork hazard. Prove it on a throwaway clone first (no reseed because PID matches).
        {
            let mut a = NonceSource {
                rng: parent.rng.clone(),
                seeded_pid: parent.seeded_pid,
                pid_of: fake_pid,
            };
            let mut b = NonceSource {
                rng: parent.rng.clone(),
                seeded_pid: parent.seeded_pid,
                pid_of: fake_pid,
            };
            assert_eq!(
                a.next_nonce(),
                b.next_nonce(),
                "inherited-but-not-reseeded clones must replay the same nonce (the hazard #393 fixes)"
            );
        }

        // Now the child observes a NEW PID (the fork happened). Its first draw must reseed.
        set_fake_pid(2000);

        let mut parent_nonces: HashSet<[u8; NONCE_LEN]> = HashSet::new();
        let mut all: HashSet<[u8; NONCE_LEN]> = HashSet::new();
        for _ in 0..5_000 {
            // Parent stays under PID 2000 too in this model, but it keeps its own (already-stamped)
            // state. The point is the CHILD reseeded to an independent stream.
            let p = parent.next_nonce();
            let c = child.next_nonce();
            assert!(parent_nonces.insert(p), "parent repeated a nonce");
            assert!(all.insert(p), "collision within parent stream");
            assert!(
                all.insert(c),
                "child emitted a nonce already produced by the parent — fork reseed FAILED (#393)"
            );
        }
    }

    /// rmp #393: the child's stamped PID is updated by the reseed, so it reseeds exactly ONCE per
    /// fork (not on every subsequent draw). Guards against a perf regression on the hot path.
    #[test]
    fn reseed_happens_once_per_pid_change_not_every_draw() {
        set_fake_pid(4242);
        let mut src = NonceSource::with_pid_source(fake_pid);
        // First draw under the seeding PID: no reseed, stamp unchanged.
        let _ = src.next_nonce();
        assert_eq!(src.seeded_pid, 4242);

        // Flip PID once: next draw reseeds and re-stamps to the new PID.
        set_fake_pid(4243);
        let _ = src.next_nonce();
        assert_eq!(src.seeded_pid, 4243, "reseed must re-stamp the PID");

        // Subsequent draws under the SAME (new) PID must NOT reseed (stamp stays put).
        for _ in 0..100 {
            let _ = src.next_nonce();
            assert_eq!(src.seeded_pid, 4243, "no spurious reseed on stable PID");
        }
    }

    // A REAL `fork(2)` regression also exists, but it lives in `tests/fork_nonce_safety.rs` (a
    // separate test crate) rather than here, because this crate is `#![forbid(unsafe_code)]` and the
    // raw `fork`/pipe FFI needs `unsafe`. The integration test drives fork-safety through the public
    // `EncryptedLogSink` API (open a sink, fork, both processes seal frames, assert the on-disk
    // nonce fields never collide), so the production crate keeps its `forbid(unsafe_code)` invariant.
}
