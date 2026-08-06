//! The atomic-primitive seam used by [`crate::pagemap`], so the lock-free page map can be
//! **model-checked by `loom`** (`rmp` #721).
//!
//! # Why this exists
//!
//! [`crate::pagemap::PageMap`] is a hand-rolled lock-free structure whose correctness rests on a
//! single, deliberately minimal happens-before edge: the writer `Release`-stores `len` after writing an
//! entry, and a reader `Acquire`-loads `len` before reading one. The entries themselves are `Relaxed`,
//! *because* that edge dominates them.
//!
//! A real-thread test cannot verify that. Development and CI here run on **x86-64, which is TSO**:
//! loads are acquire and stores are release *in hardware*, so downgrading the `len` edge to `Relaxed`
//! would still pass every real-thread test on this machine — and then reorder, and corrupt reads, on
//! **aarch64**, which CLAUDE.md names as a first-class target (Apple Silicon, Raspberry Pi 5). Only a
//! model checker explores the interleavings the *memory model* permits rather than the ones this CPU
//! happens to produce.
//!
//! `loom` model-checks concurrent code by *replacing* the standard atomics with instrumented versions
//! that explore every legal interleaving. This module is the single seam that switches between the two,
//! mirroring [`graphus_bufpool`]'s `sync.rs` (which does the same for the buffer pool's latches).
//!
//! # What is and is not modelled
//!
//! Only the **atomics** are swapped. `Arc` and `OnceLock` stay `std`:
//!
//! - `loom` (0.7) provides **no `OnceLock`** — verified, not assumed. That is sound to leave unmodelled
//!   here, because the `OnceLock`'s ordering is **not load-bearing**: a reader reaches a chunk only
//!   *after* the `Acquire` load of `len` that admits the index, and the chunk's installation is
//!   sequenced-before the writer's `Release` store of that `len`. So the `len` edge already makes the
//!   installed chunk visible; `OnceLock`'s own acquire/release is belt-and-braces on top of it.
//! - `Arc`'s refcount atomics are not under test (they are `std`'s, and correct by construction).
//!
//! Under `loom`'s cooperative scheduler every thread runs on one OS thread, so these `std` primitives
//! cannot race inside a model — they are simply opaque to it, which is exactly the intent.
//!
//! # Running the model checker
//!
//! ```text
//! RUSTFLAGS="--cfg loom" cargo test -p graphus-storage --test loom_pagemap --release
//! ```
//!
//! `--release` is recommended because loom explores an exponential interleaving space; the models are
//! kept deliberately tiny (2 threads, a handful of entries) so they still terminate quickly.

#[cfg(loom)]
pub(crate) use loom::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

#[cfg(not(loom))]
pub(crate) use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

/// One turn of a bounded spin — the publication wait in `PageMapWriter::push` (`rmp` #1012).
///
/// The seam matters here as much as the atomics do, and for a reason specific to a *waiting* loop.
/// Under `loom` a spin that never yields is not merely slow: every thread runs on one OS thread under
/// a cooperative scheduler, so a producer spinning for a predecessor that the scheduler has not run
/// **cannot make progress**, and the model deadlocks instead of exploring. `loom::thread::yield_now`
/// is the explicit "another thread may run now" point that lets the checker interleave the wait.
///
/// In production the same call site wants the opposite: no scheduler involvement at all, just the
/// CPU's spin hint (`pause` / `yield`), which keeps the wait cheap for the handful of instructions a
/// predecessor needs to publish.
#[cfg(loom)]
pub(crate) fn spin_once() {
    loom::thread::yield_now();
}

/// See the `loom` twin above.
#[cfg(not(loom))]
pub(crate) fn spin_once() {
    std::hint::spin_loop();
}
