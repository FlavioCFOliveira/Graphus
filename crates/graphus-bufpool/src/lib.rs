//! `graphus-bufpool` — the self-managed buffer pool and page format for Graphus.
//!
//! Provides the page header + CRC32C checksum helpers ([`page`]) and a single-threaded
//! buffer pool ([`BufferPool`]) over a [`graphus_io::BlockDevice`], with CLOCK eviction,
//! pinning, checksummed dirty-page write-back, and the write-ahead-log ordering rule. A
//! concurrent, latched version is tracked as a separate Phase 1 task.

pub mod page;
mod pool;

pub use pool::{BufferPool, FrameId, NoWal, WalRule};
