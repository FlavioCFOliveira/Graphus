//! The transaction coordinator: drives **concurrent** Cypher transactions over one shared record
//! store with Serializable Snapshot Isolation (`04-technical-design.md` §5.4/§5.7; `rmp` task #46).
//!
//! [`crate::record_graph::RecordStoreGraph`] already runs one transaction at a time over the
//! MVCC-native store (`rmp` task #45). [`TxnCoordinator`] is the layer above that lets several
//! transactions be open at once and makes their concurrent execution **serializable**:
//!
//! - it owns the one shared [`RecordStore`] (so several transactions read/write the same graph) and
//!   uses the store itself as the timestamp source (the store became the commit-timestamp oracle in
//!   `rmp` task #45: [`RecordStore::snapshot_ts`] is the begin snapshot, and a `commit` advances it);
//! - it owns the shared [`SsiTracker`] and [`LockTable`] from `graphus-txn` — the **complete,
//!   tested** SSI machine — so each transaction's statements contribute non-blocking SIREAD markers
//!   and rw-antidependency edges, and writes take a first-updater-wins lock;
//! - at [`commit`](TxnCoordinator::commit) it runs SSI validation (SERIALIZABLE only) and aborts a
//!   **pivot** on a dangerous structure with a retriable serialization error (PostgreSQL safe-retry:
//!   at least one transaction in any unsafe set commits, no livelock). [`IsolationLevel::Snapshot`]
//!   is the documented weaker opt-in that skips validation and therefore permits write-skew.
//!
//! ## Driving a transaction
//!
//! ```ignore
//! let mut coord = TxnCoordinator::new(store);
//! let t1 = coord.begin_serializable();
//! {
//!     // One statement: borrow a per-statement graph seam, run the executor over it, drop it.
//!     let mut g = coord.statement(t1)?;
//!     let mut cursor = execute(&plan, &bound, &mut g)?;
//!     let _rows = cursor.collect_all()?;
//!     // (check `g.has_error()` before relying on the rows)
//! }
//! coord.commit(t1)?; // may return a retriable serialization failure under SSI
//! ```
//!
//! A transaction spans many statements: [`begin`](TxnCoordinator::begin) once, any number of
//! [`statement`](TxnCoordinator::statement) executions (the store is borrowed only for each
//! statement's duration, never for the whole transaction), then [`commit`](TxnCoordinator::commit)
//! or [`rollback`](TxnCoordinator::rollback). Markers and locks accumulate across statements in the
//! coordinator's shared trackers.

use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;

use graphus_core::error::{GraphusError, Result};
use graphus_core::{Timestamp, TxnId};
use graphus_io::BlockDevice;
use graphus_storage::RecordStore;
use graphus_txn::{IsolationLevel, LockTable, Snapshot, SsiTracker};
use graphus_wal::LogSink;

use crate::record_graph::RecordStoreGraph;

/// Live state of an open transaction the coordinator drives.
#[derive(Debug, Clone, Copy)]
struct ActiveTxn {
    snapshot: Snapshot,
    isolation: IsolationLevel,
}

/// Drives concurrent, serializable Cypher transactions over one shared [`RecordStore`] (`04 §5`).
pub struct TxnCoordinator<D: BlockDevice, S: LogSink> {
    /// The one shared store, behind `Rc<RefCell<…>>` so each statement seam borrows it for the
    /// statement's duration while the transaction stays open across statements.
    store: Rc<RefCell<RecordStore<D, S>>>,
    /// The shared SSI dangerous-structure tracker (`04 §5.4`).
    ssi: Rc<RefCell<SsiTracker>>,
    /// The shared first-updater-wins write-lock table (`04 §5.7`).
    locks: Rc<RefCell<LockTable>>,
    /// Open transactions (begun, not yet committed/rolled back).
    active: HashMap<TxnId, ActiveTxn>,
    /// Monotonic transaction-id source (distinct from the commit timestamp, which the store issues).
    next_txn_id: u64,
}

impl<D: BlockDevice, S: LogSink> TxnCoordinator<D, S> {
    /// A coordinator over `store` with no open transactions.
    #[must_use]
    pub fn new(store: RecordStore<D, S>) -> Self {
        Self {
            store: Rc::new(RefCell::new(store)),
            ssi: Rc::new(RefCell::new(SsiTracker::new())),
            locks: Rc::new(RefCell::new(LockTable::new())),
            active: HashMap::new(),
            next_txn_id: 0,
        }
    }

    /// Begins a transaction at `isolation`, returning its [`TxnId`].
    ///
    /// Its read snapshot is the store's latest commit ([`RecordStore::snapshot_ts`], `04 §5.2`), so
    /// it sees exactly what has committed so far; it is registered with the SSI tracker so its
    /// conflicts are tracked from this begin timestamp.
    pub fn begin(&mut self, isolation: IsolationLevel) -> TxnId {
        self.next_txn_id += 1;
        let txn = TxnId(self.next_txn_id);
        let begin_ts = self.store.borrow().snapshot_ts();
        self.store.borrow_mut().begin(txn);
        self.ssi.borrow_mut().register(txn, begin_ts);
        self.active.insert(
            txn,
            ActiveTxn {
                snapshot: Snapshot {
                    owner: txn,
                    ts: begin_ts,
                },
                isolation,
            },
        );
        txn
    }

    /// Begins a SERIALIZABLE transaction (the default level).
    pub fn begin_serializable(&mut self) -> TxnId {
        self.begin(IsolationLevel::Serializable)
    }

    /// Borrows a per-statement [`RecordStoreGraph`] seam for the open transaction `txn`: the executor
    /// runs over it, its reads/writes contribute SIREAD markers / rw-edges / write locks to the
    /// shared trackers, and it is dropped when the statement ends (the transaction stays open).
    ///
    /// # Errors
    /// Returns [`GraphusError::Transaction`] if `txn` is not an open transaction.
    pub fn statement(&self, txn: TxnId) -> Result<RecordStoreGraph<D, S>> {
        let snapshot = self
            .active
            .get(&txn)
            .map(|a| a.snapshot)
            .ok_or_else(|| GraphusError::Transaction(format!("statement in inactive txn {}", txn.0)))?;
        Ok(RecordStoreGraph::attach(
            Rc::clone(&self.store),
            txn,
            snapshot,
            Rc::clone(&self.ssi),
            Rc::clone(&self.locks),
        ))
    }

    /// Commits `txn`: runs SSI validation (SERIALIZABLE only, aborting a pivot on a dangerous
    /// structure), then commits it on the store (assign commit timestamp, settle MVCC headers, WAL
    /// group-commit) and publishes the SSI outcome. Returns the commit timestamp.
    ///
    /// # Errors
    /// - [`GraphusError::Transaction`] if `txn` is not open.
    /// - [`GraphusError::Transaction`] (retriable serialization failure) if `txn` is chosen as the
    ///   SSI abort victim — it is rolled back and the caller should retry.
    /// - A storage error if the store commit fails.
    pub fn commit(&mut self, txn: TxnId) -> Result<Timestamp> {
        let isolation = self
            .active
            .get(&txn)
            .map(|a| a.isolation)
            .ok_or_else(|| GraphusError::Transaction(format!("commit of inactive txn {}", txn.0)))?;

        // 1) SSI validation (SERIALIZABLE only): abort a pivot on a dangerous structure (`04 §5.4`).
        if isolation.runs_ssi() {
            let victim = self.ssi.borrow().detect_pivot_abort(txn);
            if let Some(victim) = victim {
                if victim == txn {
                    self.abort(txn)?;
                    return Err(GraphusError::Transaction(format!(
                        "serialization failure: transaction {} aborted to preserve serializability \
                         (SSI dangerous structure); retry",
                        txn.0
                    )));
                }
                // The pivot is another open transaction: abort it so this safe member commits. Its
                // own later commit/statement will fail as inactive (the poisoned-victim model).
                self.abort(victim)?;
            }
        }

        // 2) Commit on the store: it assigns the commit timestamp, settles MVCC headers and group-
        //    commits the WAL (`rmp` task #45). The store is the timestamp oracle, so the commit
        //    timestamp is its post-commit snapshot high-water.
        self.store.borrow_mut().commit(txn)?;
        let commit_ts = self.store.borrow().snapshot_ts();

        // 3) Publish the outcome: record the commit in the SSI tracker (kept for later conflict
        //    resolution until GC), release write locks, and close the transaction.
        self.ssi.borrow_mut().record_commit(txn, commit_ts);
        self.locks.borrow_mut().release_all(txn);
        self.active.remove(&txn);
        Ok(commit_ts)
    }

    /// Rolls `txn` back: undoes its writes on the store, forgets its SSI markers, and releases its
    /// locks.
    ///
    /// # Errors
    /// Returns [`GraphusError::Transaction`] if `txn` is not open, or a storage error if the undo
    /// fails.
    pub fn rollback(&mut self, txn: TxnId) -> Result<()> {
        if !self.active.contains_key(&txn) {
            return Err(GraphusError::Transaction(format!(
                "rollback of inactive txn {}",
                txn.0
            )));
        }
        self.abort(txn)
    }

    /// The number of currently open transactions (observability / tests).
    #[must_use]
    pub fn active_count(&self) -> usize {
        self.active.len()
    }

    /// Reclaims the underlying store once no transaction is open and no statement seam is live
    /// (tests / shutdown).
    ///
    /// # Panics
    /// Panics if a statement seam still shares the store (a live [`RecordStoreGraph`] from
    /// [`statement`](Self::statement) has not been dropped).
    #[must_use]
    pub fn into_store(self) -> RecordStore<D, S> {
        match Rc::try_unwrap(self.store) {
            Ok(cell) => cell.into_inner(),
            Err(_) => panic!("into_store requires that no statement seam still shares the store"),
        }
    }

    /// Aborts `txn`: store undo, SSI forget, lock release, and removal from the open set.
    fn abort(&mut self, txn: TxnId) -> Result<()> {
        self.store.borrow_mut().rollback(txn)?;
        self.ssi.borrow_mut().forget(txn);
        self.locks.borrow_mut().release_all(txn);
        self.active.remove(&txn);
        Ok(())
    }
}
