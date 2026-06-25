//! `graphus-bufpool` — the self-managed buffer pool and page format for Graphus.
//!
//! Provides the page header + CRC32C checksum helpers ([`page`]) and two buffer pools over a
//! [`graphus_io::BlockDevice`], both with CLOCK eviction, pinning, checksummed dirty-page
//! write-back, and the write-ahead-log ordering rule:
//!
//! - [`BufferPool`] — the original **single-threaded** pool (`&mut self` methods). This is what
//!   `graphus-storage` and `graphus-index` build on today; its API is frozen.
//! - [`ConcurrentBufferPool`] — a **concurrent, latched** pool (`&self` methods, shareable via
//!   [`ConcurrentBufferPool::shared`]) with a sharded frame table and per-frame reader/writer
//!   latches, validated with `loom` (see the `concurrent` module and `tests/loom_bufpool.rs`).
//!
//! The two coexist; migrating the existing dependents onto the concurrent pool is a documented
//! follow-up. See `specification/04-technical-design.md` §3.
//!
//! # Safety
//!
//! This crate is `#![forbid(unsafe_code)]`. With zero `unsafe`, the concurrent pool has no
//! undefined behaviour and no data races *by construction* — Rust's type system guarantees it —
//! so the substantive validation of the *latching logic* is the `loom` model checker. The
//! internal `sync` module is the seam that swaps `std` primitives for `loom`'s under `--cfg loom`;
//! run the loom tests with:
//!
//! ```text
//! RUSTFLAGS="--cfg loom" cargo test -p graphus-bufpool --test loom_bufpool --release
//! ```
#![forbid(unsafe_code)]

mod concurrent;
pub mod page;
mod pool;
mod sync;

pub use concurrent::{ConcurrentBufferPool, PageStager, PinnedFrame};
pub use pool::{BufferPool, FrameId, NoWal, WalRule};
