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
use graphus_storage::{Namespace, RecordStore};
use graphus_txn::{IsolationLevel, LockTable, Snapshot, SsiTracker};
use graphus_wal::LogSink;

use crate::catalog::IndexCatalog;
use crate::index_set::IndexSet;
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
    /// The shared derived secondary [`IndexSet`] (`rmp` task #48): the always-present label index
    /// plus any declared node-property indexes. Rebuilt from the store on [`new`](Self::new) and on
    /// [`create_node_property_index`](Self::create_node_property_index), and maintained per write by
    /// each statement seam ([`RecordStoreGraph::reindex_node`]). It holds **candidate** ids only
    /// (never visibility-filtered), so it is in-memory and never committed or recovered — a fresh
    /// coordinator over a recovered store rebuilds a store-consistent index by construction.
    index: Rc<RefCell<IndexSet>>,
    /// Open transactions (begun, not yet committed/rolled back).
    active: HashMap<TxnId, ActiveTxn>,
    /// Monotonic transaction-id source (distinct from the commit timestamp, which the store issues).
    next_txn_id: u64,
}

impl<D: BlockDevice, S: LogSink> TxnCoordinator<D, S> {
    /// A coordinator over `store` with no open transactions.
    ///
    /// The derived [`IndexSet`] is built empty and then **rebuilt** from `store` so it is consistent
    /// with the persisted graph by construction (`rmp` task #48). Over a freshly-recovered store this
    /// is precisely the crash-recovery requirement: a new coordinator's index reflects exactly the
    /// recovered, committed graph — nothing to commit or replay for the index itself.
    #[must_use]
    pub fn new(store: RecordStore<D, S>) -> Self {
        let store = Rc::new(RefCell::new(store));
        let index = Rc::new(RefCell::new(IndexSet::new()));
        Self::rebuild_index(&store, &index);
        Self {
            store,
            ssi: Rc::new(RefCell::new(SsiTracker::new())),
            locks: Rc::new(RefCell::new(LockTable::new())),
            index,
            active: HashMap::new(),
            next_txn_id: 0,
        }
    }

    /// Clears `index` and repopulates it from every in-use node in `store` (`rmp` task #48): each
    /// node's label tokens go into the label index, and for each **registered** node-property index
    /// the node matches, its current property value is inserted.
    ///
    /// This is the store-side analogue of [`RecordStoreGraph::reindex_node`], but it reads directly
    /// off the store (no MVCC snapshot) because the index is a **candidate** set: an entry for a
    /// version that is invisible to some future reader is harmless — every seek re-checks visibility,
    /// the current label, and the current value. Inserting every in-use node's current state
    /// therefore guarantees **no false negatives**.
    ///
    /// Errors reading any single node/label/property are skipped (best-effort): a missing candidate
    /// only degrades that node to the full-scan fallback for that reader, never to a wrong row. The
    /// store and the index are borrowed in separate, non-overlapping scopes.
    fn rebuild_index(store: &Rc<RefCell<RecordStore<D, S>>>, index: &Rc<RefCell<IndexSet>>) {
        index.borrow_mut().clear();

        // The set of registered node-property indexes, captured before walking the store so the
        // index is not borrowed across a store borrow.
        let registered: Vec<(u32, u32)> = index.borrow().registered_node_properties();

        let node_ids = match store.borrow_mut().scan_node_ids() {
            Ok(ids) => ids,
            // A store-read fault on the whole scan leaves the index empty; every reader then falls
            // back to a full scan (correct, just unaccelerated).
            Err(_) => return,
        };

        for id in node_ids {
            // Read this node's current label tokens (store borrow, released before the index borrow).
            let label_tokens = match store.borrow_mut().node_labels(id) {
                Ok(tokens) => tokens,
                Err(_) => continue, // overflow-form bitmap or read fault: skip this node's entries.
            };

            // Resolve the node's current property values, keyed by prop-key, so the index borrow
            // below never overlaps a store borrow. `node_property_values` decodes the whole chain
            // newest-first (`rmp` task #50); the first occurrence per key is the newest value. No MVCC
            // snapshot is needed — the index is a candidate set and every seek re-checks visibility.
            let mut values: Vec<(u32, graphus_core::Value)> = Vec::new();
            {
                let chain = match store.borrow_mut().node_property_values(id) {
                    Ok(chain) => chain,
                    Err(_) => continue, // a non-storable / read fault: skip this node's properties.
                };
                for (_pid, key, value) in chain {
                    // Newest-wins: keep only the first occurrence of each key.
                    if values.iter().any(|(k, _)| *k == key) {
                        continue;
                    }
                    // Only keep keys that a registered index over one of this node's labels uses.
                    let used = registered.iter().any(|&(reg_label, prop_key)| {
                        prop_key == key && label_tokens.contains(&reg_label)
                    });
                    if used {
                        values.push((key, value));
                    }
                }
            }

            let mut index = index.borrow_mut();
            for &lt in &label_tokens {
                index.insert_label(lt, id);
            }
            for (prop_key, value) in &values {
                for &lt in &label_tokens {
                    if index.has_node_property(lt, *prop_key) {
                        index.insert_node_property(lt, *prop_key, value, id);
                    }
                }
            }
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

    /// Declares a node-property index on `(label, property)` and populates it from the current graph
    /// (`rmp` task #48).
    ///
    /// The label and property-key tokens are interned **durably** in their own committed transaction
    /// (a token becomes persistent on commit, `04 §2.6`), the `(label_token, prop_key)` index is
    /// registered in the shared [`IndexSet`], and the index is then rebuilt so every existing node is
    /// indexed. Subsequent writes maintain it incrementally via the statement seam. The index data
    /// itself is in-memory and candidate-only (never committed), so only the *token interning* needs
    /// durability.
    ///
    /// # Errors
    /// Returns a storage error if interning either token, or its committing transaction, fails.
    pub fn create_node_property_index(&mut self, label: &str, property: &str) -> Result<()> {
        // Intern the label + prop-key tokens durably in a dedicated transaction so the catalog can
        // map them back to names, and so the schema change survives a crash even if no node yet uses
        // them.
        self.next_txn_id += 1;
        let txn = TxnId(self.next_txn_id);
        self.store.borrow_mut().begin(txn);
        let (label_token, prop_key) = {
            let mut store = self.store.borrow_mut();
            let label_token = match store.intern_token(Namespace::Label, label) {
                Ok(t) => t,
                Err(e) => {
                    drop(store);
                    let _ = self.store.borrow_mut().rollback(txn);
                    return Err(e);
                }
            };
            let prop_key = match store.intern_token(Namespace::PropKey, property) {
                Ok(t) => t,
                Err(e) => {
                    drop(store);
                    let _ = self.store.borrow_mut().rollback(txn);
                    return Err(e);
                }
            };
            (label_token, prop_key)
        };
        self.store.borrow_mut().commit(txn)?;

        // Register the index and (re)build it so existing rows are indexed.
        self.index
            .borrow_mut()
            .register_node_property(label_token, prop_key);
        Self::rebuild_index(&self.store, &self.index);
        Ok(())
    }

    /// The physical planner's [`IndexCatalog`] reflecting the indexes this coordinator currently
    /// holds (`rmp` task #48, `04 §6.6`): a token-lookup entry for every label that has at least one
    /// indexed node, and a single-property entry for every registered node-property index. Tokens
    /// with no resolvable name (a defensively-skipped impossibility for a live token) are omitted.
    pub fn catalog(&self) -> IndexCatalog {
        let mut builder = IndexCatalog::builder();
        let store = self.store.borrow();

        for token in self.index.borrow_mut().indexed_label_tokens() {
            if let Some(name) = store.token_name(Namespace::Label, token) {
                builder = builder.with_token_lookup(name);
            }
        }
        for (label_token, prop_key) in self.index.borrow().registered_node_properties() {
            let (Some(label), Some(property)) = (
                store.token_name(Namespace::Label, label_token),
                store.token_name(Namespace::PropKey, prop_key),
            ) else {
                continue;
            };
            builder = builder.with_label_property(label, property);
        }
        builder.build()
    }

    /// Borrows a per-statement [`RecordStoreGraph`] seam for the open transaction `txn`: the executor
    /// runs over it, its reads/writes contribute SIREAD markers / rw-edges / write locks to the
    /// shared trackers, and it is dropped when the statement ends (the transaction stays open).
    ///
    /// # Errors
    /// Returns [`GraphusError::Transaction`] if `txn` is not an open transaction.
    pub fn statement(&self, txn: TxnId) -> Result<RecordStoreGraph<D, S>> {
        let snapshot = self.active.get(&txn).map(|a| a.snapshot).ok_or_else(|| {
            GraphusError::Transaction(format!("statement in inactive txn {}", txn.0))
        })?;
        Ok(RecordStoreGraph::attach(
            Rc::clone(&self.store),
            txn,
            snapshot,
            Rc::clone(&self.ssi),
            Rc::clone(&self.locks),
            Rc::clone(&self.index),
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
        let isolation = self.active.get(&txn).map(|a| a.isolation).ok_or_else(|| {
            GraphusError::Transaction(format!("commit of inactive txn {}", txn.0))
        })?;

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
