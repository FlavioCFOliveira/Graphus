//! `graphus-txn` — the MVCC + Serializable Snapshot Isolation transaction manager: Graphus's ACID
//! core (`specification/04-technical-design.md` §5; `D-concurrency-control`, `D-isolation-level`).
//!
//! 100% serializability is an **inviolable** project requirement, so correctness dominates this
//! crate. It implements:
//!
//! - **MVCC visibility** to the letter of `04 §5.3` ([`visibility`]): a transaction reads from a
//!   consistent snapshot; reads take **no locks** and never block writers (`§5.7`, NFR-4). Every
//!   header stamp is resolved through **one fallible door**, [`CommitOracle`] (`rmp` #1069); the
//!   former infallible `is_visible` free function was **removed**, not deprecated, so no caller can
//!   decide visibility around it. [`CommitOracle`] serves the record header
//!   (`created_ts`/`expired_ts`) and **never** `graphus_storage::undo::CommitSlot::commit_ts`, which
//!   shares the bit layout but is a different population of words — since `rmp` #1069 phase 3 the
//!   two have distinct types ([`graphus_core::HeaderStamp`] and [`VersionStamp`]) precisely because
//!   the compiler cannot otherwise tell them apart.
//!
//!   The implementor of that door is now `graphus_storage::RecordStore` (and its off-thread twin
//!   `StoreReadView`), which resolves a header stamp against the **durable** commit slot the word
//!   names. This crate's [`CommitRegistry`] is no longer a `CommitOracle`: it still records commit
//!   outcomes by `TxnId`, and [`RegistryOracle`] is the explicitly-named way to resolve the
//!   populations that still carry one — see its docs for the two legitimate uses.
//! - **Statement-level isolation** (`§5.1.4`, `rmp` #972): a [`Snapshot`] names not only the
//!   transaction and its begin timestamp but the **statement** within it ([`graphus_core::CommandId`])
//!   and which side of that statement the read is taken on ([`View`]). `View::New` is
//!   read-your-own-writes in full; `View::Old` is the state the statement started from, which is what
//!   stops a statement from observing the rows it is itself producing (the Halloween problem). The
//!   rule is one comparison, [`command_hides_own_write`], and the chain walk in `graphus-storage`
//!   applies it.
//! - **Serializable Snapshot Isolation** ([`ssi`]): non-blocking SIREAD markers, rw-antidependency
//!   tracking, and pivot abort with PostgreSQL-style safe retry (`§5.4`). **Snapshot Isolation** is
//!   a documented weaker opt-in ([`IsolationLevel`]).
//! - **Write-write conflict handling**: first-updater-wins, detected on the entity's own MVCC
//!   header and aborting the second writer immediately with a retriable serialization failure
//!   (`§5.7`). There is **no lock table, no waiting and no deadlock detector** — since `rmp` #971 a
//!   writer never waits, so no wait-for cycle can form.
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
pub mod manager;
pub mod oracle;
pub mod serializability;
pub mod snapshot;
pub mod ssi;
pub mod store;
pub mod visibility;

pub use gc::{GcReport, collect};
#[cfg(any(test, feature = "test-support"))]
pub use manager::NoDurability;
pub use manager::{
    DEFAULT_IDLE_TIMEOUT, DEFAULT_MAX_ACTIVE_TXNS, Durability, TxnConfig, TxnManager,
};
pub use oracle::{TimestampOracle, VersionStamp};
pub use serializability::{HistoryChecker, Op, TxnHistory};
pub use snapshot::{
    CommitRegistry, IsolationLevel, Snapshot, TxnOutcome, View, command_hides_own_write,
};
pub use ssi::{PredicateRead, SsiReadBuffer, SsiTracker};
#[cfg(any(test, feature = "test-support"))]
pub use store::MemVersionedStore;
pub use store::{Key, Version, VersionedStore};
pub use visibility::{CommitOracle, RegistryOracle, StampOutcome, is_visible_via};
