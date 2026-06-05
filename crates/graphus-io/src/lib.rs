//! `graphus-io` — the I/O substrate for the Graphus storage core.
//!
//! This crate currently provides the **synchronous, page-granular block-device**
//! abstraction ([`BlockDevice`]) that the buffer pool and write-ahead log build on, with a
//! production file-backed implementation ([`FileBlockDevice`]) and an in-memory
//! implementation ([`MemBlockDevice`]) that models the durability boundary with crash,
//! torn-write and I/O-error injection for Deterministic Simulation Testing.
//!
//! Async network I/O and the optional `io_uring` fast path are tracked as a separate task
//! (see the `rmp` roadmap `graphus`); see `specification/04-technical-design.md` §2.

mod block;
mod file;
mod mem;

pub use block::{BlockDevice, PAGE_SIZE, Page};
pub use file::FileBlockDevice;
pub use mem::MemBlockDevice;
