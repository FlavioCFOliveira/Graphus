//! The synchronization-primitive abstraction used by [`crate::concurrent`].
//!
//! `loom` model-checks concurrent code by *replacing* the standard synchronization primitives
//! with instrumented versions that explore every legal interleaving permitted by the C++/Rust
//! memory model. For that to work the code under test must use `loom`'s `Mutex`, `RwLock`,
//! `Arc` and atomics — but only when compiled for model checking. In every other build it must
//! use the real `std` primitives.
//!
//! This module is the single seam that switches between the two. The concurrent buffer pool
//! imports its primitives from here and never names `std::sync` or `loom::sync` directly, so a
//! single `--cfg loom` flips the whole pool over to model checking.
//!
//! # Running the loom model checker
//!
//! The loom tests live in `tests/loom_bufpool.rs` and are gated on `#[cfg(loom)]`, so they are
//! **not** compiled by a normal `cargo test`. To run them:
//!
//! ```text
//! RUSTFLAGS="--cfg loom" cargo test -p graphus-bufpool --test loom_bufpool --release
//! ```
//!
//! `--release` is recommended because loom explores an exponential interleaving space; the
//! model is kept deliberately tiny (2 threads, 1–2 frames, 2–3 pages) so it still terminates
//! quickly.

#[cfg(loom)]
pub(crate) use loom::sync::atomic::{AtomicUsize, Ordering};
#[cfg(loom)]
pub(crate) use loom::sync::{Arc, Mutex, MutexGuard, RwLock, RwLockReadGuard, RwLockWriteGuard};

#[cfg(not(loom))]
pub(crate) use std::sync::atomic::{AtomicUsize, Ordering};
#[cfg(not(loom))]
pub(crate) use std::sync::{Arc, Mutex, MutexGuard, RwLock, RwLockReadGuard, RwLockWriteGuard};

/// An **escalating backoff** used by the buffer pool's `fetch` retry loop to drain a thundering herd
/// of evictors that momentarily latch-contend the few free frames (`rmp` #359).
///
/// # Why this exists (the measured livelock)
///
/// Under a concurrent-reader eviction storm over a pool smaller than the working set, many threads
/// miss at once and each reserves a victim, holding that frame's write latch across its device load.
/// A peer's `select_victim` sweep then finds every *unpinned* frame momentarily write-latched and
/// comes up empty — **never** because the pool is genuinely full (instrumentation: the
/// all-frames-pinned case is observed **zero** times), always transient `try_write` contention. A
/// **tight** retry (re-sweep immediately, or `yield_now` in lockstep) is positive feedback: every
/// retrying thread re-enters the sweep and re-contends the same latches in step, so the contention
/// that caused the miss only worsens — the naive spin-retry made the `morsel_expand` flake *worse*,
/// not better. Spreading the retries out in **time** (a few `spin_loop` hints, escalating to
/// `yield_now`, then longer yields) lets the in-flight loaders finish and release their latches, so a
/// victim becomes takeable and the herd drains instead of cascading.
///
/// This is the classic exponential-backoff contention strategy (e.g. `crossbeam`'s `Backoff`,
/// `parking_lot`'s adaptive spin), implemented locally so the crate takes no new dependency.
///
/// # loom
///
/// Under `--cfg loom` the escalation collapses to a single bounded `yield_now()` per step (no real
/// spinning): loom drives the scheduler itself, real spins would only bloat the (already exponential)
/// interleaving search, and a bounded yield is the model-equivalent of "let a peer make progress".
pub(crate) struct Backoff {
    /// The escalation step (only meaningful off-loom; under loom the backoff is a single bounded
    /// model yield with no escalation, so the field would be dead — hence it exists only off-loom).
    #[cfg(not(loom))]
    step: u32,
}

impl Backoff {
    /// A fresh backoff at the lowest (cheapest) escalation step.
    #[inline]
    pub(crate) fn new() -> Self {
        Self {
            #[cfg(not(loom))]
            step: 0,
        }
    }

    /// Backs off once, escalating the patience: a short `spin_loop` burst for the first few steps
    /// (cheap, no syscall, lets a peer holding a latch on the same core finish), then `yield_now`
    /// (deschedule so a peer on another core can run), capped so a single backoff never blocks for
    /// long. Each call advances the step until a ceiling.
    #[cfg(not(loom))]
    #[inline]
    pub(crate) fn spin(&mut self) {
        // Spin steps 0..=5 (1, 2, 4, …, 32 pauses), then yield for higher steps. The yield steps
        // escalate by issuing several yields, spreading heavily-contended threads further apart in
        // time so the loader herd drains. Capped at step 10 so the patience is bounded.
        const SPIN_CEIL: u32 = 6;
        const STEP_CEIL: u32 = 10;
        if self.step < SPIN_CEIL {
            for _ in 0..(1u32 << self.step) {
                std::hint::spin_loop();
            }
        } else {
            // A few yields per call at the higher steps: deschedule repeatedly so a peer loader is
            // very likely to be scheduled and finish its load before we re-sweep.
            for _ in 0..(self.step - SPIN_CEIL + 1) {
                std::thread::yield_now();
            }
        }
        if self.step < STEP_CEIL {
            self.step += 1;
        }
    }

    /// See the non-loom variant: under loom a backoff is one bounded model-checker yield (loom drives
    /// the scheduler, so real escalation would only bloat the interleaving search).
    #[cfg(loom)]
    #[inline]
    pub(crate) fn spin(&mut self) {
        loom::thread::yield_now();
    }
}
