//! `graphus-txn` — the MVCC + Serializable Snapshot Isolation transaction manager: Graphus's ACID
//! core (`specification/04-technical-design.md` §5; `D-concurrency-control`, `D-isolation-level`).
//!
//! 100% serializability is an **inviolable** project requirement, so correctness dominates this
//! crate. It implements:
//!
//! - **MVCC visibility** to the letter of `04 §5.3` ([`visibility`]): a transaction reads from a
//!   consistent snapshot; reads take **no locks** and never block writers (`§5.7`, NFR-4).
//! - **Serializable Snapshot Isolation** ([`ssi`]): non-blocking SIREAD markers, rw-antidependency
//!   tracking, and pivot abort with PostgreSQL-style safe retry (`§5.4`). **Snapshot Isolation** is
//!   a documented weaker opt-in ([`IsolationLevel`]).
//! - **Write-write conflict handling** ([`lock`]): first-updater-wins with a wait-for-graph
//!   **deadlock detector** that aborts the youngest on a cycle (`§5.7`).
//! - **Version GC** ([`gc`]): reclaims versions dead below the oracle's low-water mark (`§5.5`).
//! - A deterministic **serialization-graph checker** ([`serializability`]) — the Elle/Jepsen-style
//!   anomaly oracle the manager is validated against.
//!
//! ## The version-stamp convention (`04 §5.2`, `05 §7`)
//!
//! The frozen MVCC record header (`graphus_storage::record::MvccHeader`) stores `created_ts`
//! (`xmin`) and `expired_ts` (`xmax`) as raw `u64`s. A single field encodes **either** a committed
//! [`Timestamp`](graphus_core::Timestamp) **or** the [`TxnId`](graphus_core::TxnId) of an in-flight
//! writer, discriminated by the high bit; `0` is the frozen *none/live* sentinel. [`oracle::VersionStamp`]
//! owns this convention.
//!
//! ## Architecture: the [`VersionedStore`] seam
//!
//! `04 §5.1`/`05 §5` chose **in-place latest + undo-delta chain** as the version representation, but
//! that representation is the open spike `04 §12 item 2`, and real `graphus-storage` does not yet
//! implement version-chain mechanics. To keep this milestone self-contained and fully testable now,
//! the manager is written against the small [`VersionedStore`] trait ([`store`]) — a multiversion
//! key→value record interface — with an in-memory reference implementation ([`MemVersionedStore`])
//! for tests. **Wiring real `graphus-storage` records to implement [`VersionedStore`] is a documented
//! follow-up task**, intentionally out of scope here; the trait is the seam any store drops into.
//!
//! Durability on commit is likewise a seam: the [`Durability`] hook is bound in production to
//! `graphus_wal::WalManager::commit` (group commit + `fdatasync`, `04 §1.3` step 6 / `§4.2`) so a
//! commit returns only once its `COMMIT` record is durable, while tests use the no-op
//! [`NoDurability`].
//!
//! ## Quick start
//!
//! ```
//! use graphus_txn::{IsolationLevel, MemVersionedStore, TxnManager};
//!
//! let mut mgr = TxnManager::new(MemVersionedStore::new());
//!
//! // A writer commits a value.
//! let w = mgr.begin(IsolationLevel::Serializable).unwrap();
//! mgr.write(w, /* key */ 1, b"hello".to_vec()).unwrap();
//! mgr.commit(w).unwrap();
//!
//! // A later transaction reads it from its snapshot.
//! let r = mgr.begin_serializable().unwrap();
//! assert_eq!(mgr.read(r, 1).unwrap(), Some(b"hello".to_vec()));
//! mgr.commit(r).unwrap();
//! ```
#![forbid(unsafe_code)]

pub mod gc;
pub mod lock;
pub mod manager;
pub mod oracle;
pub mod serializability;
pub mod snapshot;
pub mod ssi;
pub mod store;
pub mod visibility;

pub use gc::{GcReport, collect};
pub use lock::{LockOutcome, LockTable};
#[cfg(any(test, feature = "test-support"))]
pub use manager::NoDurability;
pub use manager::{
    DEFAULT_IDLE_TIMEOUT, DEFAULT_MAX_ACTIVE_TXNS, Durability, TxnConfig, TxnManager,
};
pub use oracle::{TimestampOracle, VersionStamp};
pub use serializability::{HistoryChecker, Op, TxnHistory};
pub use snapshot::{CommitRegistry, IsolationLevel, Snapshot, TxnOutcome};
pub use ssi::SsiTracker;
#[cfg(any(test, feature = "test-support"))]
pub use store::MemVersionedStore;
pub use store::{Key, Version, VersionedStore};
pub use visibility::is_visible;
