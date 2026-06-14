//! `graphus-wal` — the ARIES write-ahead log, group commit, fuzzy checkpoints and crash
//! recovery that give Graphus its durability and never-corrupt guarantees (NFR-1).
//!
//! The design is `specification/04-technical-design.md` §4: **steal + no-force** buffer
//! management, **group commit + `fdatasync`** ([`WalManager::commit`]), physiological redo with
//! logical undo ([`record`]), **CLR**-based undo, **fuzzy checkpoints** ([`WalManager::checkpoint`]),
//! three-phase **ARIES recovery** ([`recover`]), and **PANIC on fsync failure** (`§4.9`).
//!
//! Layering:
//! - [`sink`] is the append-only byte log ([`FileLogSink`] in production, [`MemLogSink`] for
//!   Deterministic Simulation Testing).
//! - [`record`] is the on-log record format; an LSN is a record's byte offset (`§4.1`).
//! - [`WalManager`] turns logical operations into records and owns the durability policy.
//! - [`recover`] replays the durable log against an [`ApplyTarget`] so only committed work
//!   survives a crash at any LSN.
//!
//! The WAL is parameterised over its sink and its [`ApplyTarget`] precisely so the whole
//! durability path can be driven deterministically and crash-tested exhaustively (decision
//! `D-dst-investment`); see `tests/aries_recovery.rs`.
// `forbid(unsafe_code)` everywhere except macOS, which needs one scoped `unsafe` block
// (`fcntl(fd, F_FULLFSYNC)` in `fullsync.rs`) to issue a true stable-storage barrier for the WAL
// segments — a bare `fdatasync` on APFS/HFS+ does not flush the drive's volatile write cache. macOS
// relaxes the lint to `deny` (any other stray `unsafe` still fails the build).
#![cfg_attr(not(target_os = "macos"), forbid(unsafe_code))]
#![cfg_attr(target_os = "macos", deny(unsafe_code))]

pub mod checkpoint;
mod fullsync;
pub mod manager;
pub mod record;
pub mod recovery;
pub mod sink;

pub use checkpoint::CheckpointSnapshot;
pub use manager::{HEADER_LEN, WAL_MAGIC, WAL_VERSION, WalManager};
pub use record::{DecodeError, LogRecord, LogRecordRef, RecordType};
pub use recovery::{ApplyTarget, RecoveryReport, recover, recover_from};
pub use sink::{FileLogSink, LogSink, MemLogSink};
