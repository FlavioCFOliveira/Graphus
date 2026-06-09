//! A [`GraphAccess`] backed by the **real** persistent record store
//! (`04-technical-design.md` §2, §7.4; `rmp` task #38).
//!
//! [`RecordStoreGraph`] is the seam where the two halves of the database meet: the Cypher
//! compile/execute pipeline ([`crate::executor`]) runs **unchanged** over a real, WAL-logged,
//! crash-recoverable [`graphus_storage::RecordStore`] instead of the in-memory reference
//! [`MemGraph`](crate::graph_access::MemGraph). The executor depends only on the [`GraphAccess`]
//! trait, so swapping the backend needs no operator change (`04 §7.4`).
//!
//! # The achievable subset (#38 + #42 + #43 + #44) and what is deferred (#39)
//!
//! This is the **achievable subset** of the storage integration: nodes/relationships/properties
//! (#38), **node labels** (#42, the bit-packed small-label-set case of `05 §9`), the
//! **`strings.store` String/List property overflow heap + node-property removal** (#43), and
//! **relationship properties** (#44, over [`RelRecord.first_prop`], the relationship analogue of
//! the node-property path, sharing the same `props.store` chain + `strings.store` overflow heap),
//! and **MVCC snapshot visibility** (#45 — every read is filtered through `graphus_txn::is_visible`
//! against each record's frozen `xmin`/`xmax`, so a query reads a consistent point-in-time graph;
//! see [`begin_at_snapshot`](RecordStoreGraph::begin_at_snapshot)). The remaining wiring
//! (index-accelerated label/property scans #48, the label token-list overflow block, SSI
//! conflict detection #46, and per-value property MVCC) is the follow-up under EPIC **#16/#39**.
//! Every deferral is signalled by a **clear error**, never a silently wrong answer:
//!
//! | Capability | status | How a deferral is signalled |
//! |------------|--------|-----------------------------|
//! | Nodes / relationships CRUD + traverse | supported (over real records, real WAL) | — |
//! | Inline scalar node properties (`Integer`/`Float`/`Boolean`) | supported (#38) inline | — |
//! | **`String` / `List` node property values** | **supported** (#43) via the `strings.store` overflow heap (`04 §2.1`/§2.3) | a `Map`/`Bytes`/temporal value, or a heterogeneous/nested `List`, captures a runtime error (outside the stored-property subtype, `05 §7.2`) |
//! | **Node property removal / overwrite** (`SET n.p = null`, `REMOVE n.p`, `SET n = map`) | **supported** (#43) — removes the record and frees any overflow chain (no leak) | — |
//! | Node **labels** (`CREATE (:L)`, `SET`/`REMOVE` label, `n:L` predicates, `labels(n)`, label scan) | **supported** (#42) via the inline label bitmap, `05 §9` | a label needing token id `≥ 63` (a 64th+ distinct label) captures the documented overflow error (the token-list block is #39) |
//! | **Relationship properties** — read (`r.k`, `properties(r)`), create (`CREATE ()-[:T {..}]->()`), `SET`/`REMOVE`, inline **and** `String`/`List` overflow | **supported** (#44) over [`RelRecord.first_prop`] (`04 §2.3`/§2.1, `05 §9`); `delete_rel` frees the chain (no leak) | a `Map`/`Bytes`/temporal value, or a heterogeneous/nested `List`, captures the same runtime error as a node property |
//! | **Index-accelerated** label / property scans | **deferred (#48)** | a label scan is correct but does a full scan + `node_has_label` filter (no label index); the [`GraphAccess`] default `index_seek_*` returns `None`, so the executor falls back to scan+filter |
//! | **MVCC snapshot visibility** (consistent reads, own-writes, tombstone visibility, crash-safe) | **supported** (#45) — reads filtered by `graphus_txn::is_visible` on each record's `xmin`/`xmax`; delete is an MVCC tombstone reclaimed by GC | — |
//! | **Serializable concurrency / SSI** (write-skew abort, write-write first-updater-wins) | **supported** (#46) via [`TxnCoordinator`](crate::coordinator::TxnCoordinator) — this seam records SIREAD markers and rw-edges into the shared `SsiTracker`, and the coordinator aborts a pivot at commit with a retriable serialization error | — |
//! | **Per-value property MVCC** (snapshot-consistent property reads, no dirty read) | **supported** (#50) — a property overwrite/removal MVCC-tombstones the old `PropRecord` and prepends the new one; [`read_node_props`](Self::read_node_props) filters the chain by `is_visible` (newest-visible-wins), and GC reclaims tombstoned versions | — |
//! | Index-range (predicate) SSI markers | **deferred (#48)** | read markers are node/relationship-level, so a full label/all-nodes scan reads every node (a safe SSI over-abort until index-range markers arrive with index wiring, #48) |
//!
//! [`RelRecord.first_prop`]: graphus_storage::record::RelRecord
//!
//! # Identity
//!
//! A [`NodeId`] / [`RelId`] **is** the store's physical record id (`u64`). The executor treats them
//! as opaque handles (`04 §7.4`), so using the physical id directly is sound and avoids a side
//! table. Physical ids are reused after deletion (`04 §2.7`); within one transaction that is
//! invisible to the executor (a deleted id is not handed back out mid-query).
//!
//! # Transaction scope
//!
//! The seam is transaction-scoped (`04 §7.4`): [`RecordStoreGraph::begin`] opens one store
//! transaction, the executor reads and writes through it, and the caller ends it with
//! [`commit`](RecordStoreGraph::commit) or [`rollback`](RecordStoreGraph::rollback). A committed
//! query's effects are durable and survive a crash; an uncommitted (or rolled-back) query's writes
//! are undone by the store's ARIES WAL (`04 §4.4`), so a query that hits a deferred-feature error
//! can be rolled back cleanly with no partial state.
//!
//! # Interior mutability and error capture (two impedance mismatches)
//!
//! The [`GraphAccess`] trait's read methods take `&self` and return plain values (no `Result`),
//! while [`RecordStore`]'s reads take `&mut self` (they fetch pages through the buffer pool) and
//! return `Result`. [`RecordStoreGraph`] bridges both:
//!
//! * a [`RefCell`] gives the `&self` trait methods the `&mut` access the store needs (the type is
//!   single-threaded — `!Sync`); several such seams over one `Rc`-shared store, driven by the
//!   [`TxnCoordinator`](crate::coordinator::TxnCoordinator), run concurrent transactions through SSI
//!   validation (#46);
//! * a captured-error cell records the **first** storage / deferred-feature error a read or write
//!   hits. The trait method then degrades safely (a read returns `None`/empty, a write is a no-op),
//!   and the caller **must** inspect [`take_error`](RecordStoreGraph::take_error) after running the
//!   cursor. A captured error means the result is **not** trustworthy and the transaction should be
//!   rolled back. This keeps a deferral a hard, surfaced error — never a wrong row.

use std::cell::RefCell;
use std::rc::Rc;

use graphus_core::error::GraphusError;
use graphus_core::{Timestamp, TxnId, Value};
use graphus_io::BlockDevice;
use graphus_storage::{MvccHeader, Namespace, RecordStore};
use graphus_txn::{CommitRegistry, LockOutcome, LockTable, Snapshot, SsiTracker, is_visible};
use graphus_wal::LogSink;

/// Tag bit distinguishing a relationship key from a node key in the shared [`SsiTracker`]
/// (`rmp` task #46). Physical record ids fit far below this bit, so a node id and a relationship id
/// with the same numeric value map to distinct SSI keys.
const REL_SSI_KEY_TAG: u64 = 1 << 63;

/// The SSI conflict key for node physical id `id` (its own id; node space is the low keys).
fn node_ssi_key(id: u64) -> u64 {
    id
}

/// The SSI conflict key for relationship physical id `id` (tagged into the high half of the space).
fn rel_ssi_key(id: u64) -> u64 {
    id | REL_SSI_KEY_TAG
}

use crate::graph_access::{ExpandDirection, GraphAccess, Incident, NodeId, RelData, RelId};

/// A [`GraphAccess`] implementation over a real [`RecordStore`], scoped to one transaction
/// (`rmp` task #38; see the module docs for the supported-vs-deferred matrix).
///
/// Generic over the block device `D` and WAL log sink `S` exactly like the underlying
/// [`RecordStore`], so it runs over the production file device + file log and over the in-memory
/// DST device + log used by the executor/crash-recovery tests.
#[must_use]
pub struct RecordStoreGraph<D: BlockDevice, S: LogSink> {
    /// The store, behind a `RefCell` so the `&self` [`GraphAccess`] reads can drive the store's
    /// `&mut self` methods, and behind an `Rc` so a [`TxnCoordinator`](crate::coordinator::TxnCoordinator)
    /// can share one store across the concurrent transactions it drives (`rmp` task #46). In the
    /// standalone single-transaction path the `Rc` is the sole owner, so [`commit`](Self::commit) /
    /// [`rollback`](Self::rollback) / [`into_store`](Self::into_store) unwrap it back to an owned store.
    store: Rc<RefCell<RecordStore<D, S>>>,
    /// The single transaction this query runs in.
    txn: TxnId,
    /// This query's MVCC read snapshot (`04 §5.3`, `rmp` task #45): every read is filtered through
    /// [`is_visible`] against each record's frozen `xmin`/`xmax`, so the query sees a consistent
    /// point-in-time graph — only versions committed at or before its begin timestamp, plus its own
    /// in-flight writes, and not versions another transaction committed later or deleted.
    snapshot: Snapshot,
    /// Resolves any still-in-flight writer to its commit outcome (`04 §5.3`). Eager commit-time
    /// settling makes committed records self-describing, so this stays empty even under the
    /// concurrent execution the coordinator drives (a committed writer's headers are settled, never
    /// observed as in-flight by a concurrent reader).
    registry: CommitRegistry,
    /// When this graph is driven by a [`TxnCoordinator`](crate::coordinator::TxnCoordinator), the
    /// shared SSI conflict tracker every concurrent transaction records its SIREAD markers and writes
    /// into, so the coordinator can detect a dangerous structure and abort a pivot at commit
    /// (`04 §5.4`, `rmp` task #46). `None` in the standalone single-transaction path (no concurrency,
    /// nothing to track).
    ssi: Option<Rc<RefCell<SsiTracker>>>,
    /// The shared write-lock table, present iff coordinated. A write acquires the entity's lock
    /// first-updater-wins; a conflicting concurrent writer captures a retriable serialization error
    /// (`04 §5.7`, `rmp` task #46). Reads never touch it (they never block, NFR-4).
    locks: Option<Rc<RefCell<LockTable>>>,
    /// The first storage / deferred-feature error encountered by a read or write, if any. While set,
    /// results are untrustworthy and the transaction should be rolled back (see module docs).
    error: RefCell<Option<GraphusError>>,
}

impl<D: BlockDevice, S: LogSink> RecordStoreGraph<D, S> {
    /// Wraps `store` and **begins** transaction `txn`, returning a graph seam the executor can run
    /// one query against.
    ///
    /// The caller owns the transaction lifecycle: after running the query it calls
    /// [`commit`](Self::commit) (to make the writes durable) or [`rollback`](Self::rollback) (to
    /// undo them), and should first check [`take_error`](Self::take_error).
    pub fn begin(mut store: RecordStore<D, S>, txn: TxnId) -> Self {
        // The snapshot timestamp is the store's latest commit (`04 §5.2`): this query sees exactly
        // what has committed so far, plus its own writes. Reads on a database that has changed since
        // this begin therefore stay on this consistent snapshot.
        store.begin(txn);
        let snapshot = Snapshot {
            owner: txn,
            ts: store.snapshot_ts(),
        };
        Self {
            store: Rc::new(RefCell::new(store)),
            txn,
            snapshot,
            registry: CommitRegistry::new(),
            ssi: None,
            locks: None,
            error: RefCell::new(None),
        }
    }

    /// Attaches a per-statement seam to an **already-open** transaction `txn` driven by a
    /// [`TxnCoordinator`](crate::coordinator::TxnCoordinator) (`rmp` task #46): the coordinator owns
    /// the shared `store`, has already called `store.begin(txn)`, holds `txn`'s `snapshot`, and
    /// passes the shared `ssi` tracker so this statement's reads/writes contribute SIREAD markers and
    /// rw-edges. Unlike [`begin`](Self::begin) it does **not** begin a transaction and must not be
    /// committed/rolled back through this handle — the coordinator owns that lifecycle.
    pub fn attach(
        store: Rc<RefCell<RecordStore<D, S>>>,
        txn: TxnId,
        snapshot: Snapshot,
        ssi: Rc<RefCell<SsiTracker>>,
        locks: Rc<RefCell<LockTable>>,
    ) -> Self {
        Self {
            store,
            txn,
            snapshot,
            registry: CommitRegistry::new(),
            ssi: Some(ssi),
            locks: Some(locks),
            error: RefCell::new(None),
        }
    }

    /// Records a non-blocking SIREAD marker for `key` under this transaction, if it is coordinated
    /// (`04 §5.4`); a no-op in the standalone path. Reads never block (NFR-4).
    fn note_read(&self, key: u64) {
        if let Some(ssi) = &self.ssi {
            ssi.borrow_mut().record_read(self.txn, key);
        }
    }

    /// Records that this transaction wrote `key`: closes rw-antidependency edges with concurrent
    /// readers in the shared tracker (`04 §5.4`) and acquires the write lock first-updater-wins
    /// (`04 §5.7`). On a write-write conflict with another in-flight transaction, captures a
    /// retriable serialization error so the caller rolls this transaction back. A no-op in the
    /// standalone path (no concurrency).
    fn note_write(&self, key: u64) {
        if let Some(ssi) = &self.ssi {
            ssi.borrow_mut().record_write(self.txn, key);
        }
        if let Some(locks) = &self.locks
            && let LockOutcome::Wait { holder } = locks.borrow_mut().acquire(self.txn, key)
        {
            self.capture(GraphusError::Transaction(format!(
                "write-write conflict: entity held by transaction {}; retry (serialization failure)",
                holder.0
            )));
        }
    }

    /// Like [`begin`](Self::begin) but with an explicit snapshot timestamp `ts` instead of the
    /// store's latest commit. This is how a reader that *began earlier* (before some later commit)
    /// is modelled over the single-threaded store: choosing `ts` below a record's commit timestamp
    /// makes that record invisible, exactly as a concurrent older reader would experience it
    /// (`04 §5.3`). Primarily an MVCC-visibility testing seam.
    pub fn begin_at_snapshot(mut store: RecordStore<D, S>, txn: TxnId, ts: Timestamp) -> Self {
        store.begin(txn);
        Self {
            store: Rc::new(RefCell::new(store)),
            txn,
            snapshot: Snapshot { owner: txn, ts },
            registry: CommitRegistry::new(),
            ssi: None,
            locks: None,
            error: RefCell::new(None),
        }
    }

    /// Whether the version carrying `mvcc` is visible to this query's snapshot (`04 §5.3`): its
    /// creator committed at or before the snapshot (or is this transaction's own write) and its
    /// expirer does not hide it. The one place the executor's reads consult MVCC.
    fn visible(&self, mvcc: MvccHeader) -> bool {
        is_visible(
            self.snapshot,
            mvcc.created_ts,
            mvcc.expired_ts,
            &self.registry,
        )
    }

    /// The transaction id this query runs in.
    #[must_use]
    pub fn txn(&self) -> TxnId {
        self.txn
    }

    /// Takes the first captured storage / deferred-feature error, leaving the cell empty.
    ///
    /// Returns `Some(err)` if any read or write hit an error during execution — in which case the
    /// query's results are **not** trustworthy and the caller should [`rollback`](Self::rollback)
    /// rather than [`commit`](Self::commit). `None` means every seam operation succeeded.
    #[must_use]
    pub fn take_error(&self) -> Option<GraphusError> {
        self.error.borrow_mut().take()
    }

    /// Whether a storage / deferred-feature error has been captured (non-consuming peek).
    #[must_use]
    pub fn has_error(&self) -> bool {
        self.error.borrow().is_some()
    }

    /// Commits the query's transaction, making its writes durable, and returns the wrapped store.
    ///
    /// # Errors
    /// Returns a storage error if the commit (catalog persist + WAL group-commit) fails.
    pub fn commit(self) -> Result<RecordStore<D, S>, GraphusError> {
        let txn = self.txn;
        let mut store = Self::unwrap_store(self.store);
        store.commit(txn)?;
        Ok(store)
    }

    /// Unwraps the sole-owner `Rc` back to an owned store. Panics if the store is still shared — only
    /// a standalone graph (the single-transaction path) owns its store outright; a coordinated
    /// statement handle must never end the transaction (the coordinator owns that lifecycle).
    fn unwrap_store(store: Rc<RefCell<RecordStore<D, S>>>) -> RecordStore<D, S> {
        match Rc::try_unwrap(store) {
            Ok(cell) => cell.into_inner(),
            Err(_) => panic!(
                "RecordStoreGraph::{{commit,rollback,into_store}} requires sole ownership of the \
                 store; a coordinated statement handle must not end the transaction"
            ),
        }
    }

    /// Rolls the query's transaction back (undoing every write via the WAL) and returns the wrapped
    /// store. Use this when [`take_error`](Self::take_error) reported an error, or to discard a
    /// read-only or speculative query.
    ///
    /// # Errors
    /// Returns a storage error if the undo apply or catalog reload fails.
    pub fn rollback(self) -> Result<RecordStore<D, S>, GraphusError> {
        let txn = self.txn;
        let mut store = Self::unwrap_store(self.store);
        store.rollback(txn)?;
        Ok(store)
    }

    /// Reclaims the wrapped store **without** ending the transaction (no commit, no rollback).
    ///
    /// The transaction's effects remain uncommitted: not durable, and a crash before a later commit
    /// rolls them back via the WAL (`04 §4.4`). This is the seam the orchestration layer uses to
    /// retrieve the store for inspection or shutdown, and the crash-recovery tests use it to crash
    /// with an in-flight (loser) transaction.
    pub fn into_store(self) -> RecordStore<D, S> {
        Self::unwrap_store(self.store)
    }

    /// Records `err` as the first captured error (a later error does not overwrite the first, which
    /// is usually the root cause).
    fn capture(&self, err: GraphusError) {
        let mut slot = self.error.borrow_mut();
        if slot.is_none() {
            *slot = Some(err);
        }
    }

    /// Resolves the property key id for `key`, interning it if new (a new key becomes durable when
    /// the transaction commits, `04 §2.6`). Captures and returns `None` on a storage error.
    fn prop_key_id(&self, key: &str) -> Option<u32> {
        match self
            .store
            .borrow_mut()
            .intern_token(Namespace::PropKey, key)
        {
            Ok(id) => Some(id),
            Err(e) => {
                self.capture(e);
                None
            }
        }
    }

    /// Resolves the [`Namespace::Label`] token id for `name`, **interning it if new** (a new label
    /// token becomes durable when the transaction commits, exactly like a relationship type,
    /// `04 §2.6`). Used by label writes (`CREATE (:L)`, `SET n:L`). Captures and returns `None` on a
    /// storage error.
    fn label_id_intern(&self, name: &str) -> Option<u32> {
        match self.store.borrow_mut().intern_token(Namespace::Label, name) {
            Ok(id) => Some(id),
            Err(e) => {
                self.capture(e);
                None
            }
        }
    }

    /// The existing [`Namespace::Label`] token id for `name`, **without** interning it.
    ///
    /// Returns `None` when `name` was never interned — by which point no live node can carry it (a
    /// label only exists once some node was labelled with it), so a label *read* (scan / predicate)
    /// on an unknown label is correctly empty/false. This is the read-side counterpart to
    /// [`label_id_intern`](Self::label_id_intern), which must not create a token just by *asking*
    /// whether a node has a label.
    fn label_id_existing(&self, name: &str) -> Option<u32> {
        self.store.borrow().token_id(Namespace::Label, name)
    }

    /// Interns and sets each of `labels` on `node`'s inline label bitmap (`05 §9`, `rmp` task #42),
    /// idempotently. Shared by `create_node` (with labels) and `add_labels`.
    ///
    /// On the first error — a storage fault, or the documented overflow deferral (a label whose
    /// token id is `≥ 63`, i.e. the 64th+ distinct label, whose token-list block is #39) — the error
    /// is captured and the rest are skipped; the captured error makes the whole query untrustworthy
    /// (the caller rolls back). This is never a silently-dropped label.
    fn apply_add_labels(&self, node: NodeId, labels: &[String]) {
        for name in labels {
            let Some(token_id) = self.label_id_intern(name) else {
                return; // storage error already captured (token-namespace exhaustion)
            };
            if let Err(e) = self
                .store
                .borrow_mut()
                .add_label(self.txn, node.0, token_id)
            {
                self.capture(e);
                return;
            }
        }
    }

    /// Reads `node`'s properties as newest-**visible**-wins `(key_name, value)` pairs (`rmp` task
    /// #50), decoding both inline scalars (#38) and `String`/`List` overflow values (`rmp` task #43).
    ///
    /// A property overwrite is an MVCC operation now (`rmp` task #50): the old `PropRecord` is
    /// tombstoned and the new one prepended, so the chain (from [`RecordStore::node_properties`])
    /// holds **multiple versions per key**, live and not-yet-GC'd tombstones. Each is filtered through
    /// [`is_visible`] on its `xmin`/`xmax`, so this query sees exactly the version committed at or
    /// before its snapshot (or its own write) — never a concurrent transaction's uncommitted value.
    /// The chain is prepend-ordered (newest first), so the **first visible** record per key id wins.
    fn read_node_props(&self, node: NodeId) -> Vec<(String, Value)> {
        let mut store = self.store.borrow_mut();
        let chain = match store.node_properties(node.0) {
            Ok(chain) => chain,
            Err(e) => {
                drop(store);
                self.capture(e);
                return Vec::new();
            }
        };
        let mut out: Vec<(u32, Value)> = Vec::new();
        for (_pid, prop) in chain {
            // MVCC visibility filter + newest-visible-wins: skip versions invisible to this snapshot,
            // and a key id already resolved to a newer visible version.
            if !self.visible(prop.mvcc) || out.iter().any(|(k, _)| *k == prop.key) {
                continue;
            }
            match store.decode_property_value(prop.type_tag, prop.value_inline) {
                Ok(value) => out.push((prop.key, value)),
                Err(e) => {
                    drop(store);
                    self.capture(e);
                    return Vec::new();
                }
            }
        }
        // Map key ids back to names and sort by name for the deterministic order the seam promises.
        let mut named: Vec<(String, Value)> = out
            .into_iter()
            .filter_map(|(kid, v)| {
                store
                    .token_name(Namespace::PropKey, kid)
                    .map(|name| (name.to_owned(), v))
            })
            .collect();
        named.sort_by(|a, b| a.0.cmp(&b.0));
        named
    }

    /// Reads `rel`'s live properties as newest-wins `(key_name, value)` pairs, decoding both inline
    /// scalars (#38) and `String`/`List` values stored in the `strings.store` overflow heap
    /// (`rmp` task #43) via [`RecordStore::rel_property_values`] (`rmp` task #44). The relationship
    /// analogue of [`read_node_props`](Self::read_node_props) — identical newest-wins + key-sort
    /// discipline, over [`RelRecord.first_prop`](graphus_storage::record::RelRecord) instead of the
    /// node's `first_prop`.
    fn read_rel_props(&self, rel: RelId) -> Vec<(String, Value)> {
        let mut store = self.store.borrow_mut();
        let chain = match store.rel_properties(rel.0) {
            Ok(chain) => chain,
            Err(e) => {
                drop(store);
                self.capture(e);
                return Vec::new();
            }
        };
        let mut out: Vec<(u32, Value)> = Vec::new();
        for (_pid, prop) in chain {
            // MVCC visibility filter + newest-visible-wins (`rmp` task #50), as for node properties.
            if !self.visible(prop.mvcc) || out.iter().any(|(k, _)| *k == prop.key) {
                continue;
            }
            match store.decode_property_value(prop.type_tag, prop.value_inline) {
                Ok(value) => out.push((prop.key, value)),
                Err(e) => {
                    drop(store);
                    self.capture(e);
                    return Vec::new();
                }
            }
        }
        // Map key ids back to names and sort by name for the deterministic order the seam promises.
        let mut named: Vec<(String, Value)> = out
            .into_iter()
            .filter_map(|(kid, v)| {
                store
                    .token_name(Namespace::PropKey, kid)
                    .map(|name| (name.to_owned(), v))
            })
            .collect();
        named.sort_by(|a, b| a.0.cmp(&b.0));
        named
    }
}

impl<D: BlockDevice, S: LogSink> GraphAccess for RecordStoreGraph<D, S> {
    // ---- reads --------------------------------------------------------------------------------

    fn scan_nodes(&self) -> Vec<NodeId> {
        // `scan_node_ids` returns every slot-occupied node (live versions *and* tombstones not yet
        // GC'd); keep only those visible to this snapshot (`04 §5.3`, `rmp` task #45).
        let mut store = self.store.borrow_mut();
        let ids = match store.scan_node_ids() {
            Ok(ids) => ids,
            Err(e) => {
                drop(store);
                self.capture(e);
                return Vec::new();
            }
        };
        let mut out = Vec::new();
        for id in ids {
            match store.node(id) {
                Ok(rec) => {
                    // A full scan examines every node, so SIREAD-mark each one: a concurrent writer
                    // of any scanned node closes an rw-edge (`04 §5.4`, `rmp` task #46).
                    self.note_read(node_ssi_key(id));
                    if self.visible(rec.mvcc) {
                        out.push(NodeId(id));
                    }
                }
                Err(e) => {
                    drop(store);
                    self.capture(e);
                    return Vec::new();
                }
            }
        }
        out
    }

    fn scan_nodes_by_label(&self, label: &str) -> Vec<NodeId> {
        // Resolve the label name -> token id without interning: if the label was never created, no
        // live node can carry it, so the scan is correctly empty (`05 §9`, `rmp` task #42).
        let Some(token_id) = self.label_id_existing(label) else {
            return Vec::new();
        };
        // Index-accelerated label scans are #39; here we scan every live node and filter by the
        // inline label bitmap (`node_has_label`). This is correct, just O(live nodes).
        let mut store = self.store.borrow_mut();
        let ids = match store.scan_node_ids() {
            Ok(ids) => ids,
            Err(e) => {
                drop(store);
                self.capture(e);
                return Vec::new();
            }
        };
        let mut out = Vec::new();
        for id in ids {
            // Skip nodes not visible to this snapshot (tombstoned or not-yet-committed) before
            // testing the label, so a label scan honours MVCC visibility (`04 §5.3`, `rmp` task #45).
            let visible = match store.node(id) {
                Ok(rec) => self.visible(rec.mvcc),
                Err(e) => {
                    drop(store);
                    self.capture(e);
                    return Vec::new();
                }
            };
            // SIREAD-mark every scanned node, visible or not (the label predicate examined it).
            self.note_read(node_ssi_key(id));
            if !visible {
                continue;
            }
            match store.node_has_label(id, token_id) {
                Ok(true) => out.push(NodeId(id)),
                Ok(false) => {}
                Err(e) => {
                    // An overflow-form bitmap (a #39-written node) surfaces as a captured error
                    // rather than a wrong (missing/extra) row.
                    drop(store);
                    self.capture(e);
                    return Vec::new();
                }
            }
        }
        out
    }

    fn expand(&self, node: NodeId, direction: ExpandDirection, types: &[String]) -> Vec<Incident> {
        let mut store = self.store.borrow_mut();
        let rels = match store.incident_rels(node.0) {
            Ok(rels) => rels,
            Err(e) => {
                drop(store);
                self.capture(e);
                return Vec::new();
            }
        };
        let mut out = Vec::new();
        for rid in rels {
            let rec = match store.rel(rid) {
                Ok(rec) => rec,
                Err(e) => {
                    drop(store);
                    self.capture(e);
                    return Vec::new();
                }
            };
            // SIREAD-mark each incident relationship the traversal examined (`04 §5.4`).
            self.note_read(rel_ssi_key(rid));
            // Skip relationships not visible to this snapshot — a concurrently-deleted (tombstoned)
            // edge an older reader could still traverse, or an edge a later transaction committed
            // (`04 §5.3`, `rmp` task #45). The incidence chain still threads them until GC.
            if !self.visible(rec.mvcc) {
                continue;
            }
            // Filter by relationship type name (empty = any type).
            if !types.is_empty() {
                let type_ok = store
                    .token_name(Namespace::RelType, rec.type_id)
                    .is_some_and(|name| types.iter().any(|t| t == name));
                if !type_ok {
                    continue;
                }
            }
            // Report the matching side(s) relative to the anchor, exactly like `MemGraph`: a
            // self-loop participates as both start and end and is reported once per matching
            // direction (the executor deduplicates by rel id, `04 §2.4`). `incident_rels` already
            // deduplicates a self-loop's two chain links to one id, so a self-loop is reported once
            // per matching direction here.
            let touches_as_start = rec.start_node == node.0;
            let touches_as_end = rec.end_node == node.0;
            let want_out = matches!(direction, ExpandDirection::Outgoing | ExpandDirection::Both);
            let want_in = matches!(direction, ExpandDirection::Incoming | ExpandDirection::Both);
            if touches_as_start && want_out {
                out.push(Incident {
                    rel: RelId(rid),
                    neighbour: NodeId(rec.end_node),
                });
            }
            if touches_as_end && want_in {
                out.push(Incident {
                    rel: RelId(rid),
                    neighbour: NodeId(rec.start_node),
                });
            }
        }
        out
    }

    fn node_exists(&self, node: NodeId) -> bool {
        // "Exists" means "visible to this query's snapshot" (`04 §5.3`): a node created after this
        // snapshot, deleted before it, or never allocated, does not exist *for us*.
        let mvcc = match self.store.borrow_mut().node(node.0) {
            Ok(rec) => rec.mvcc,
            // A missing page means the id was never allocated — i.e. the node does not exist. That
            // is a normal answer, not a captured storage fault.
            Err(_) => return false,
        };
        // SIREAD marker: this transaction examined the node (independent of whether it is visible),
        // so a concurrent writer of it closes an rw-edge (`04 §5.4`, `rmp` task #46).
        self.note_read(node_ssi_key(node.0));
        self.visible(mvcc)
    }

    fn rel_exists(&self, rel: RelId) -> bool {
        let mvcc = match self.store.borrow_mut().rel(rel.0) {
            Ok(rec) => rec.mvcc,
            Err(_) => return false,
        };
        self.note_read(rel_ssi_key(rel.0));
        self.visible(mvcc)
    }

    fn node_labels(&self, node: NodeId) -> Option<Vec<String>> {
        if !self.node_exists(node) {
            return None;
        }
        // Read the node's label token ids from its inline bitmap (`05 §9`, `rmp` task #42), then map
        // each id back to its name. An overflow-form bitmap (a #39-written node) is captured as an
        // error and reported as `Some(vec![])` so the result is not silently wrong; the caller must
        // inspect `take_error`.
        let mut store = self.store.borrow_mut();
        let ids = match store.node_labels(node.0) {
            Ok(ids) => ids,
            Err(e) => {
                drop(store);
                self.capture(e);
                return Some(Vec::new());
            }
        };
        let mut names: Vec<String> = ids
            .into_iter()
            .filter_map(|id| {
                store
                    .token_name(Namespace::Label, id)
                    .map(ToOwned::to_owned)
            })
            .collect();
        // Deterministic, name-sorted order (mirrors `MemGraph`, which keeps labels sorted).
        names.sort();
        Some(names)
    }

    fn rel_data(&self, rel: RelId) -> Option<RelData> {
        let mut store = self.store.borrow_mut();
        let rec = match store.rel(rel.0) {
            Ok(rec) => rec,
            Err(_) => return None,
        };
        self.note_read(rel_ssi_key(rel.0));
        if !self.visible(rec.mvcc) {
            return None;
        }
        let rel_type = store
            .token_name(Namespace::RelType, rec.type_id)
            .unwrap_or("")
            .to_owned();
        Some(RelData {
            rel_type,
            start: NodeId(rec.start_node),
            end: NodeId(rec.end_node),
        })
    }

    fn node_property(&self, node: NodeId, key: &str) -> Option<Value> {
        if !self.node_exists(node) {
            return None;
        }
        self.read_node_props(node)
            .into_iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v)
    }

    fn rel_property(&self, rel: RelId, key: &str) -> Option<Value> {
        if !self.rel_exists(rel) {
            return None;
        }
        // Relationship properties are stored over `RelRecord.first_prop`, the relationship analogue of
        // the node-property path (`rmp` task #44). Read the live newest-wins set and pick `key`.
        self.read_rel_props(rel)
            .into_iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v)
    }

    fn node_properties(&self, node: NodeId) -> Option<Vec<(String, Value)>> {
        if !self.node_exists(node) {
            return None;
        }
        Some(self.read_node_props(node))
    }

    fn rel_properties(&self, rel: RelId) -> Option<Vec<(String, Value)>> {
        // Relationship properties are stored over `RelRecord.first_prop` (`rmp` task #44); report the
        // live key-sorted set for a live relationship, or `None` for a missing one (mirrors
        // `node_properties`).
        if !self.rel_exists(rel) {
            return None;
        }
        Some(self.read_rel_props(rel))
    }

    // ---- writes -------------------------------------------------------------------------------

    fn create_node(&mut self, labels: &[String], properties: &[(String, Value)]) -> NodeId {
        let id = match self.store.borrow_mut().create_node(self.txn) {
            Ok((id, _eid)) => id,
            Err(e) => {
                self.capture(e);
                // Return a sentinel id; the captured error makes the whole query untrustworthy.
                return NodeId(0);
            }
        };
        let node = NodeId(id);
        self.note_write(node_ssi_key(id));
        // Apply labels via the inline label bitmap (`05 §9`, `rmp` task #42). An overflowing label
        // (token id `≥ 63`) captures the documented deferred error rather than dropping it silently.
        self.apply_add_labels(node, labels);
        for (k, v) in properties {
            self.set_node_property(node, k, v.clone());
        }
        node
    }

    fn create_rel(
        &mut self,
        rel_type: &str,
        start: NodeId,
        end: NodeId,
        properties: &[(String, Value)],
    ) -> RelId {
        let type_id = match self
            .store
            .borrow_mut()
            .intern_token(Namespace::RelType, rel_type)
        {
            Ok(id) => id,
            Err(e) => {
                self.capture(e);
                return RelId(0);
            }
        };
        let id = match self
            .store
            .borrow_mut()
            .create_rel(self.txn, type_id, start.0, end.0)
        {
            Ok((id, _eid)) => id,
            Err(e) => {
                self.capture(e);
                return RelId(0);
            }
        };
        let rel = RelId(id);
        self.note_write(rel_ssi_key(id));
        // Relationship properties are stored over `RelRecord.first_prop` (`rmp` task #44), exactly
        // like node properties on `create_node`. A null entry is not stored (Cypher does not persist
        // nulls); a non-persistable class captures a runtime error rather than dropping it silently.
        for (k, v) in properties {
            if !v.is_null() {
                self.set_rel_property(rel, k, v.clone());
            }
        }
        rel
    }

    fn set_node_property(&mut self, node: NodeId, key: &str, value: Value) {
        let Some(key_id) = self.prop_key_id(key) else {
            return; // error already captured
        };
        self.note_write(node_ssi_key(node.0));
        if value.is_null() {
            // `SET n.p = null` is a removal in Cypher: drop the key (and free any overflow chain it
            // owned) so a later read sees the property absent.
            if let Err(e) = self
                .store
                .borrow_mut()
                .remove_node_property_value(self.txn, node.0, key_id)
            {
                self.capture(e);
            }
            return;
        }
        // Inline scalars stay inline (#38); String/List values overflow to the strings.store heap
        // (`rmp` task #43). `set_node_property_value` replaces any current value of the key, freeing
        // its old overflow chain (no leak). A class the store cannot persist (Map/Bytes/temporal,
        // heterogeneous List) is captured as a runtime error, never a silently-dropped property.
        if let Err(e) = self
            .store
            .borrow_mut()
            .set_node_property_value(self.txn, node.0, key_id, &value)
        {
            self.capture(e);
        }
    }

    fn set_rel_property(&mut self, rel: RelId, key: &str, value: Value) {
        if !self.rel_exists(rel) {
            return; // no-op on a missing relationship (mirrors `set_node_property` / `MemGraph`)
        }
        let Some(key_id) = self.prop_key_id(key) else {
            return; // error already captured
        };
        self.note_write(rel_ssi_key(rel.0));
        if value.is_null() {
            // `SET r.p = null` is a removal in Cypher: drop the key (and free any overflow chain it
            // owned) so a later read sees the property absent.
            if let Err(e) = self
                .store
                .borrow_mut()
                .remove_rel_property_value(self.txn, rel.0, key_id)
            {
                self.capture(e);
            }
            return;
        }
        // Inline scalars stay inline (#38); String/List values overflow to the strings.store heap
        // (`rmp` task #43). `set_rel_property_value` replaces any current value of the key, freeing
        // its old overflow chain (no leak). A class the store cannot persist (Map/Bytes/temporal,
        // heterogeneous List) is captured as a runtime error, never a silently-dropped property
        // (`rmp` task #44).
        if let Err(e) = self
            .store
            .borrow_mut()
            .set_rel_property_value(self.txn, rel.0, key_id, &value)
        {
            self.capture(e);
        }
    }

    fn add_labels(&mut self, node: NodeId, labels: &[String]) {
        if labels.is_empty() || !self.node_exists(node) {
            return;
        }
        self.note_write(node_ssi_key(node.0));
        self.apply_add_labels(node, labels);
    }

    fn remove_labels(&mut self, node: NodeId, labels: &[String]) {
        if labels.is_empty() || !self.node_exists(node) {
            return;
        }
        self.note_write(node_ssi_key(node.0));
        // Remove each label that has ever been interned; a label name that was never created cannot
        // be set on any node, so removing it is a no-op (no token is created just to remove it).
        for name in labels {
            let Some(token_id) = self.label_id_existing(name) else {
                continue;
            };
            if let Err(e) = self
                .store
                .borrow_mut()
                .remove_label(self.txn, node.0, token_id)
            {
                self.capture(e);
                return;
            }
        }
    }

    fn remove_node_property(&mut self, node: NodeId, key: &str) {
        if !self.node_exists(node) {
            return;
        }
        self.note_write(node_ssi_key(node.0));
        // `REMOVE n.p` over a never-interned key is a no-op (no node can carry an unknown key), so do
        // not intern just to remove. Otherwise drop the key and free any overflow chain it owned
        // (`rmp` task #43); removing an absent key is itself a no-op in the store.
        let Some(key_id) = self.store.borrow().token_id(Namespace::PropKey, key) else {
            return;
        };
        if let Err(e) = self
            .store
            .borrow_mut()
            .remove_node_property_value(self.txn, node.0, key_id)
        {
            self.capture(e);
        }
    }

    fn remove_rel_property(&mut self, rel: RelId, key: &str) {
        if !self.rel_exists(rel) {
            return;
        }
        // `REMOVE r.p` over a never-interned key is a no-op (no relationship can carry an unknown
        // key), so do not intern just to remove. Otherwise drop the key and free any overflow chain
        // it owned (`rmp` task #44); removing an absent key is itself a no-op in the store. Mirrors
        // `remove_node_property`.
        let Some(key_id) = self.store.borrow().token_id(Namespace::PropKey, key) else {
            return;
        };
        if let Err(e) = self
            .store
            .borrow_mut()
            .remove_rel_property_value(self.txn, rel.0, key_id)
        {
            self.capture(e);
        }
    }

    fn replace_node_properties(&mut self, node: NodeId, properties: &[(String, Value)]) {
        if !self.node_exists(node) {
            return;
        }
        // `SET n = map` replaces the whole property set: clear the existing properties (freeing any
        // overflow chains, `rmp` task #43), then set each non-null entry of the map (mirrors
        // `MemGraph::replace_node_properties`).
        if let Err(e) = self
            .store
            .borrow_mut()
            .clear_node_properties(self.txn, node.0)
        {
            self.capture(e);
            return;
        }
        for (k, v) in properties {
            if !v.is_null() {
                self.set_node_property(node, k, v.clone());
            }
        }
    }

    fn merge_node_properties(&mut self, node: NodeId, properties: &[(String, Value)]) {
        // `SET n += map` keeps unmentioned keys and overlays the map; for a non-null value this is
        // an append (newest-wins read), which the store supports. A null value would be a removal
        // (deferred); `set_node_property` signals that.
        if !self.node_exists(node) {
            return;
        }
        for (k, v) in properties {
            self.set_node_property(node, k, v.clone());
        }
    }

    fn incident_rels(&self, node: NodeId) -> Vec<RelId> {
        match self.store.borrow_mut().incident_rels(node.0) {
            Ok(rels) => rels.into_iter().map(RelId).collect(),
            Err(e) => {
                self.capture(e);
                Vec::new()
            }
        }
    }

    fn delete_rel(&mut self, rel: RelId) {
        // Idempotent: a relationship not visible to this query (already gone, deleted by us earlier,
        // or never created) is a no-op, not an error — matching the `MemGraph` contract. Visibility
        // (not raw `in_use`) is the right guard now that delete is an MVCC tombstone (the slot stays
        // in use): a second delete in the same transaction sees its own tombstone and does nothing.
        let mvcc = match self.store.borrow_mut().rel(rel.0) {
            Ok(r) => r.mvcc,
            Err(_) => return,
        };
        if !self.visible(mvcc) {
            return;
        }
        self.note_write(rel_ssi_key(rel.0));
        if let Err(e) = self.store.borrow_mut().delete_rel(self.txn, rel.0) {
            self.capture(e);
        }
    }

    fn delete_node(&mut self, node: NodeId) {
        let mvcc = match self.store.borrow_mut().node(node.0) {
            Ok(n) => n.mvcc,
            Err(_) => return,
        };
        if !self.visible(mvcc) {
            return;
        }
        self.note_write(node_ssi_key(node.0));
        if let Err(e) = self.store.borrow_mut().delete_node(self.txn, node.0) {
            self.capture(e);
        }
    }
}
