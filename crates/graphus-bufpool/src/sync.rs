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
pub(crate) use loom::sync::{Arc, Mutex, MutexGuard, RwLock, RwLockWriteGuard};

#[cfg(not(loom))]
pub(crate) use std::sync::atomic::{AtomicUsize, Ordering};
#[cfg(not(loom))]
pub(crate) use std::sync::{Arc, Mutex, MutexGuard, RwLock, RwLockWriteGuard};

/// A scheduling yield point. Under `loom` this is a model-checker yield (lets the loader thread
/// make progress in a reservation spin); otherwise it is a plain thread yield.
#[cfg(loom)]
pub(crate) fn yield_now() {
    loom::thread::yield_now();
}

/// See the `loom` variant.
#[cfg(not(loom))]
pub(crate) fn yield_now() {
    std::thread::yield_now();
}
