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
#![forbid(unsafe_code)]

pub mod checkpoint;
pub mod manager;
pub mod record;
pub mod recovery;
pub mod sink;

pub use checkpoint::CheckpointSnapshot;
pub use manager::{HEADER_LEN, WalManager};
pub use record::{DecodeError, LogRecord, RecordType};
pub use recovery::{ApplyTarget, RecoveryReport, recover};
pub use sink::{FileLogSink, LogSink, MemLogSink};
