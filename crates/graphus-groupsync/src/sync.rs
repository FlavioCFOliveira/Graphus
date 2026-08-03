//! The synchronization-primitive seam used by [`crate::dwb`]'s group-staging barrier (`rmp` #994).
//!
//! `loom` model-checks concurrent code by *replacing* the standard synchronization primitives with
//! instrumented versions that explore every legal interleaving permitted by the memory model. For
//! that to work the code under test must use `loom`'s `Mutex`, `Condvar` and atomics — but only when
//! compiled for model checking. In every other build it must use the real `std` primitives.
//!
//! This module is the single seam that switches between the two, mirroring `graphus-bufpool`'s
//! (`graphus_bufpool::sync`, added for the buffer pool's latch protocol). The staging barrier imports
//! its primitives from here and never names `std::sync` or `loom::sync` directly, so a single
//! `--cfg loom` flips the whole protocol over to model checking.
//!
//! # Running the model
//!
//! ```text
//! RUSTFLAGS="--cfg loom" cargo test -p graphus-storage --test loom_staging_barrier --release
//! ```
//!
//! `--release` is recommended because loom explores an exponential interleaving space; the model is
//! kept deliberately tiny (2–3 threads, 1 barrier) so it still terminates quickly.

#[cfg(loom)]
pub(crate) use loom::sync::atomic::{AtomicU64, Ordering};
#[cfg(loom)]
pub(crate) use loom::sync::{Condvar, Mutex, MutexGuard};

#[cfg(not(loom))]
pub(crate) use std::sync::atomic::{AtomicU64, Ordering};
#[cfg(not(loom))]
pub(crate) use std::sync::{Condvar, Mutex, MutexGuard};
