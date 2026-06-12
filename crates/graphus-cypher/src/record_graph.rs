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
//! see [`begin_at_snapshot`](RecordStoreGraph::begin_at_snapshot)), **SSI serializable concurrency**
//! (#46), **per-value property MVCC** (#50), and **index-accelerated label/property scans** (#48).
//! The remaining wiring (the label token-list overflow block, and index-range *predicate* SSI
//! markers) is the follow-up under EPIC **#16/#39**. Every deferral is signalled by a **clear
//! error**, never a silently wrong answer:
//!
//! | Capability | status | How a deferral is signalled |
//! |------------|--------|-----------------------------|
//! | Nodes / relationships CRUD + traverse | supported (over real records, real WAL) | — |
//! | Inline scalar node properties (`Integer`/`Float`/`Boolean`) | supported (#38) inline | — |
//! | **`String` / `List` node property values** | **supported** (#43) via the `strings.store` overflow heap (`04 §2.1`/§2.3) | a `Map`/`Bytes`/temporal value, or a heterogeneous/nested `List`, captures a runtime error (outside the stored-property subtype, `05 §7.2`) |
//! | **Node property removal / overwrite** (`SET n.p = null`, `REMOVE n.p`, `SET n = map`) | **supported** (#43) — removes the record and frees any overflow chain (no leak) | — |
//! | Node **labels** (`CREATE (:L)`, `SET`/`REMOVE` label, `n:L` predicates, `labels(n)`, label scan) | **supported** (#42) via the inline label bitmap, `05 §9` | a label needing token id `≥ 63` (a 64th+ distinct label) captures the documented overflow error (the token-list block is #39) |
//! | **Relationship properties** — read (`r.k`, `properties(r)`), create (`CREATE ()-[:T {..}]->()`), `SET`/`REMOVE`, inline **and** `String`/`List` overflow | **supported** (#44) over [`RelRecord.first_prop`] (`04 §2.3`/§2.1, `05 §9`); `delete_rel` frees the chain (no leak) | a `Map`/`Bytes`/temporal value, or a heterogeneous/nested `List`, captures the same runtime error as a node property |
//! | **Index-accelerated** label / property scans | **supported** (#48) — when driven by a [`TxnCoordinator`](crate::coordinator::TxnCoordinator) the seam holds a derived [`IndexSet`](crate::index_set::IndexSet): a label scan seeks the label index then re-checks, and `index_seek_eq`/`index_seek_range` seek the property index then re-check exactly the scan+filter residual, returning the same visible rows. Standalone (no coordinator) falls back to scan+filter | — |
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
use graphus_index::histogram::PropertyHistogram;
use graphus_index::keycodec::encode_single;
use graphus_index::kinds::DEFAULT_HISTOGRAM_BUCKETS;
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
use crate::index_set::IndexSet;

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
    /// The coordinator's derived secondary [`IndexSet`] (`rmp` task #48), present **only** on the
    /// coordinated path ([`attach`](Self::attach)). When `Some`, label scans and node-property
    /// predicates are answered from the index as **candidate** ids re-checked against the store
    /// (visibility + current label + current value), which makes an index seek return *exactly* the
    /// scan-and-filter result; writes (re)insert the node's current entries via
    /// [`reindex_node`](Self::reindex_node). `None` on the standalone [`begin`](Self::begin) /
    /// [`begin_at_snapshot`](Self::begin_at_snapshot) path, where every access falls back to a full
    /// scan (the index lives in the coordinator, rebuilt from the store). The index is in-memory and
    /// candidate-only, so it is never committed or recovered — see [`IndexSet`].
    index: Option<Rc<RefCell<IndexSet>>>,
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
        // Snapshot the store's Active/Recent Transaction Table at begin (`rmp` task #49): reads
        // resolve an on-disk in-flight stamp to its commit timestamp through this. A later commit is
        // correctly excluded whether or not this snapshot captured it (visibility filters by `ts`),
        // and own in-flight writes are visible via the owner rule, not the table.
        let registry = store.commit_registry().clone();
        Self {
            store: Rc::new(RefCell::new(store)),
            txn,
            snapshot,
            registry,
            ssi: None,
            locks: None,
            error: RefCell::new(None),
            // Standalone path: no coordinator, so no derived index; every access falls back to a
            // full scan (`rmp` task #48). This keeps the standalone `record_store_graph.rs` path
            // behaviour byte-for-byte unchanged.
            index: None,
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
        index: Rc<RefCell<IndexSet>>,
    ) -> Self {
        // Snapshot the shared store's Active/Recent Transaction Table for this statement's reads
        // (`rmp` task #49). Cloning at attach is consistent with snapshot isolation: a transaction
        // that commits later is excluded by the `ts` filter regardless, and this statement's own
        // in-flight writes resolve via the owner rule.
        let registry = store.borrow().commit_registry().clone();
        Self {
            store,
            txn,
            snapshot,
            registry,
            ssi: Some(ssi),
            locks: Some(locks),
            error: RefCell::new(None),
            // Coordinated path: the shared derived index is present, so label scans and node-property
            // predicates seek candidates from it and re-check them here (`rmp` task #48).
            index: Some(index),
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
        let registry = store.commit_registry().clone();
        Self {
            store: Rc::new(RefCell::new(store)),
            txn,
            snapshot: Snapshot { owner: txn, ts },
            registry,
            ssi: None,
            locks: None,
            error: RefCell::new(None),
            // Standalone snapshot path: no derived index (the index lives in the coordinator).
            index: None,
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

    /// SIREAD-marks **every live node** as this transaction's predicate-read footprint (`04 §5.4`,
    /// `rmp` task #46), the conservative phantom-safe approximation a label/all-nodes predicate read
    /// requires while the `SsiTracker` is per-node (no predicate/range marker yet). Only meaningful
    /// on the coordinated path; a no-op for the SSI tracker on the standalone path. Read errors are
    /// captured exactly as the full scan would have, so the marker footprint matches the pre-index
    /// behaviour byte-for-byte.
    fn mark_all_live_nodes(&self) {
        // No SSI tracker -> nothing to mark (the standalone path never reaches here, but guard anyway
        // so this stays an O(0) call when there is nothing to track).
        if self.ssi.is_none() {
            return;
        }
        let mut store = self.store.borrow_mut();
        let ids = match store.scan_node_ids() {
            Ok(ids) => ids,
            Err(e) => {
                drop(store);
                self.capture(e);
                return;
            }
        };
        drop(store);
        for id in ids {
            self.note_read(node_ssi_key(id));
        }
    }

    /// Filters `ids` (a full-scan id list or an index candidate list) to the nodes that **currently**
    /// carry `token_id` and are **visible** to this snapshot, SIREAD-marking each examined id
    /// (`04 §5.3`/§5.4, `rmp` tasks #42/#45/#46). This is the one per-candidate filter shared by the
    /// index-accelerated and full-scan label-scan paths, so an index seek returns *exactly* the
    /// full-scan result over a candidate subset (`rmp` task #48).
    ///
    /// On a storage fault (or an overflow-form bitmap, a #39-written node) the error is captured and
    /// an empty result returned, exactly as the full scan did — never a wrong (missing/extra) row.
    fn filter_label_candidates(&self, token_id: u32, ids: Vec<u64>) -> Vec<NodeId> {
        let mut store = self.store.borrow_mut();
        let mut out = Vec::new();
        for id in ids {
            // Skip nodes not visible to this snapshot (tombstoned or not-yet-committed) before
            // testing the label, so the scan honours MVCC visibility (`04 §5.3`, `rmp` task #45).
            let visible = match store.node(id) {
                Ok(rec) => self.visible(rec.mvcc),
                // A candidate id whose page is unallocated (a stale index entry for a reclaimed slot)
                // is not a live node; on the full-scan path `scan_node_ids` never yields such an id,
                // so this only fires for stale candidates and is correctly dropped, not an error.
                Err(_) => continue,
            };
            // SIREAD-mark every examined node, visible or not (the label predicate examined it).
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

    /// Re-derives `node`'s entries in the coordinator's [`IndexSet`] from the node's **current**
    /// state at this transaction's snapshot (`rmp` task #48); a no-op on the standalone path (no
    /// index). Called at the end of every node write (`create_node`, `set_node_property`,
    /// `add_labels`) once the store write succeeded and no error was captured.
    ///
    /// Inserts the node's *current* label tokens and, for each registered `(label_token, prop_key)`
    /// index the node matches, its current property value. This guarantees **no false negatives**:
    /// after the write, every label/value the node currently carries is a candidate, so a later seek
    /// re-checks the store and keeps exactly the matching rows. Stale entries left by a prior value
    /// or label are harmless — the seek's re-check drops them — so no index removal is ever needed.
    ///
    /// The store and the index are borrowed in **separate, non-overlapping** scopes: the node's
    /// labels and property values are read out first (releasing the store borrow), then the prop-key
    /// tokens are resolved, then the entries are inserted into the index.
    fn reindex_node(&self, node: NodeId) {
        let Some(index) = &self.index else {
            return; // standalone path: no derived index to maintain.
        };

        // --- read the node's current labels (store borrow, released before touching the index) ---
        let label_tokens: Vec<u32> = {
            let mut store = self.store.borrow_mut();
            match store.node_labels(node.0) {
                Ok(ids) => ids,
                // An overflow-form bitmap (#39) surfaces elsewhere as a captured error; here it just
                // means we cannot enumerate the labels, so we skip indexing (the seek then re-checks
                // the store and, on a full scan, still finds the node — never a wrong row).
                Err(_) => return,
            }
        };

        // The node's current property values (this borrows the store internally and releases it).
        let props = self.read_node_props(node);

        // --- resolve each property's prop-key token (read-only store borrow) ---
        // Pre-resolve all `(name, value, prop_key)` triples so the index borrow below does not
        // overlap a store borrow.
        let resolved_props: Vec<(u32, Value)> = {
            let store = self.store.borrow();
            props
                .into_iter()
                .filter_map(|(name, value)| {
                    store
                        .token_id(Namespace::PropKey, &name)
                        .map(|prop_key| (prop_key, value))
                })
                .collect()
        };

        // The node's current string property values, by prop-key token, for full-text maintenance
        // (`rmp` task #72): a full-text index covers string text, so only string values participate.
        let string_props: Vec<(u32, String)> = resolved_props
            .iter()
            .filter_map(|(prop_key, value)| match value {
                Value::String(s) => Some((*prop_key, s.clone())),
                _ => None,
            })
            .collect();

        // --- (re)insert the node's current entries into the index (index borrow only) ---
        let mut index = index.borrow_mut();
        for &lt in &label_tokens {
            index.insert_label(lt, node.0);
        }
        for (prop_key, value) in &resolved_props {
            for &lt in &label_tokens {
                if index.has_node_property(lt, *prop_key) {
                    index.insert_node_property(lt, *prop_key, value, node.0);
                }
            }
        }
        // Full-text indexes are maintained by a wholesale per-node re-index (`rmp` task #72): each
        // covering index replaces the node's terms with the freshly-analyzed current text, and a node
        // that lost the covered label is removed. Unlike the property indexes (which tolerate stale
        // candidates because the seek re-checks the value), the full-text inverted index removes the
        // node's old terms here so a query never returns a node whose text no longer matches.
        index.reindex_fulltext_node(node.0, &label_tokens, &string_props);
    }

    /// **Recomputes** (the `ANALYZE` path) the equi-depth value histogram for the node-label property
    /// `(label, property)` by scanning the live, snapshot-visible nodes carrying `label`, then
    /// **persists** it in the store's durable statistics catalogue (`rmp` task #81).
    ///
    /// # The ANALYZE model (full scan → build → persist → commit)
    ///
    /// This is a deliberate **recompute-only** maintenance path, matching standard practice: an
    /// equi-depth histogram cannot be maintained incrementally without resampling, so it is rebuilt
    /// from a full scan on demand (`ANALYZE` / `UPDATE STATISTICS`), while the *counts*
    /// (per-label / per-relationship-type / grand-total, `rmp` tasks #79/#82) are the cheaply,
    /// incrementally-maintained statistics. The lifecycle is:
    ///
    /// 1. **Scan.** Enumerate the nodes carrying `label` **visible to this transaction's snapshot**,
    ///    reusing the same machinery `MATCH (n:Label)` uses ([`scan_nodes_by_label`](GraphAccess::scan_nodes_by_label)),
    ///    so the recompute observes exactly the rows a query would — no phantom rows, no rows hidden
    ///    by MVCC.
    /// 2. **Build.** For each visible node read the current visible value of `property`; skip a node
    ///    whose value is absent or not index-encodable (`Null` / `List` / `Map`), since such a value
    ///    never participates in the indexed distribution. Order-preservingly encode each present value
    ///    ([`encode_single`]), sort the encodings ascending (the [`from_sorted_encoded`](PropertyHistogram::from_sorted_encoded)
    ///    contract), and build the histogram with [`DEFAULT_HISTOGRAM_BUCKETS`].
    /// 3. **Persist.** Resolve (interning if new, so a brand-new `label`/`property` gets a durable
    ///    token) the label and property-key tokens, then store the encoded histogram via
    ///    [`RecordStore::set_property_histogram`]. An **empty** result (no node has an index-encodable
    ///    value) instead [`removes`](RecordStore::remove_property_histogram) any stale histogram, so a
    ///    column that lost all its indexable values reverts cleanly to the estimator's constant
    ///    fallback rather than reporting a stale distribution.
    /// 4. **Commit.** The mutation is in-memory until the caller commits **this** graph's transaction
    ///    ([`commit`](Self::commit)); on commit it is checkpointed durably, on rollback it is
    ///    discarded — exactly the crash-consistency contract of `set_property_histogram`.
    ///
    /// The histogram's selectivity is then surfaced through this graph's
    /// [`Statistics`](crate::statistics::Statistics) impl (and so to the planner via
    /// [`plan_physical_with_stats`](crate::physical::plan_physical_with_stats)) on any *later*
    /// transaction whose snapshot sees the commit.
    ///
    /// # Errors
    ///
    /// Returns the first storage error the scan or token interning hit. A captured read error (the
    /// scan degraded to empty under [`take_error`](Self::take_error)) is surfaced as the same error,
    /// so a faulty scan never silently persists a partial histogram.
    pub fn recompute_property_histogram(
        &self,
        label: &str,
        property: &str,
    ) -> Result<(), GraphusError> {
        // --- scan: the live, snapshot-visible nodes carrying `label` (the MATCH (n:Label) path) ---
        let nodes = self.scan_nodes_by_label(label);
        if let Some(err) = self.take_error() {
            // The label scan degraded to a (possibly partial) list on a storage fault; do not persist
            // a histogram built from an untrustworthy scan.
            return Err(err);
        }

        // --- build: encode each present, index-encodable value of `property` ---
        let mut encoded: Vec<Vec<u8>> = Vec::new();
        for node in nodes {
            // Read the current visible value of `property` for this node (newest-visible-wins).
            let Some(value) = self.node_property(node, property) else {
                continue; // property absent on this node — it does not participate
            };
            // A non-index-encodable value (Null / List / Map) is skipped, matching how the index and
            // MemGraph's reference histogram treat it.
            if let Ok(bytes) = encode_single(&value) {
                encoded.push(bytes);
            }
        }
        if let Some(err) = self.take_error() {
            // A per-node property read hit a storage / decode fault: abort rather than persist a
            // partial histogram.
            return Err(err);
        }

        // --- persist: resolve (interning if new) the tokens, then store / clear the histogram ---
        if encoded.is_empty() {
            // No index-encodable value: clear any stale histogram so the estimator falls back cleanly.
            // Resolve the tokens *without* interning — if either was never created, there is nothing
            // stored to remove, so this is a no-op (and we avoid minting a token just to clear).
            let (Some(label_token), Some(prop_token)) = (
                self.label_id_existing(label),
                self.store.borrow().token_id(Namespace::PropKey, property),
            ) else {
                return Ok(());
            };
            self.store
                .borrow_mut()
                .remove_property_histogram(label_token, prop_token);
            return Ok(());
        }

        // `from_sorted_encoded` requires ascending byte order; the encoder is order-preserving, so a
        // plain lexicographic sort of the encodings is exactly Cypher value order.
        encoded.sort_unstable();
        let hist = PropertyHistogram::from_sorted_encoded(&encoded, DEFAULT_HISTOGRAM_BUCKETS);

        // Intern so a brand-new label / property gets a durable token (it becomes durable at commit,
        // like the count statistics).
        let label_token = self.label_id_intern(label).ok_or_else(|| {
            self.take_error()
                .unwrap_or_else(|| GraphusError::Storage("label token interning failed".to_owned()))
        })?;
        let prop_token = self.prop_key_id(property).ok_or_else(|| {
            self.take_error().unwrap_or_else(|| {
                GraphusError::Storage("property-key token interning failed".to_owned())
            })
        })?;
        self.store
            .borrow_mut()
            .set_property_histogram(label_token, prop_token, hist.encode());
        Ok(())
    }

    /// Recomputes the histograms for every `(label, property)` in `targets`, in order, short-circuiting
    /// on the first error (`rmp` task #81). A convenience over [`recompute_property_histogram`](Self::recompute_property_histogram)
    /// for an `ANALYZE` over several columns; all persist into the same transaction, so one
    /// [`commit`](Self::commit) makes them all durable together.
    ///
    /// # Errors
    ///
    /// Returns the first error any single recompute hits (see [`recompute_property_histogram`](Self::recompute_property_histogram)).
    pub fn recompute_property_histograms(
        &self,
        targets: &[(&str, &str)],
    ) -> Result<(), GraphusError> {
        for &(label, property) in targets {
            self.recompute_property_histogram(label, property)?;
        }
        Ok(())
    }

    /// Decodes the durable histogram stored for `(label, property)`, or `None` when the label /
    /// property token was never interned or no histogram is recorded for the pair.
    ///
    /// The lookup itself is the shared [`crate::store_statistics::decode_histogram`] (`rmp` task
    /// #82) — the same reader [`crate::coordinator::CoordinatorStatistics`] uses, so the two seams
    /// cannot drift. This seam's policy for a **decode error** (a corrupt or truncated stored
    /// histogram): it is captured into this graph's error cell — so the caller's `take_error`
    /// surfaces it — and reported as `None` (the estimator then falls back to its constant), never a
    /// panic. This mirrors how every other read in this seam degrades safely on a storage fault.
    fn decode_histogram(&self, label: &str, property: &str) -> Option<PropertyHistogram> {
        // The store borrow is a temporary scoped to this statement: it is released before `capture`
        // touches the (separate) error cell.
        let decoded =
            crate::store_statistics::decode_histogram(&self.store.borrow(), label, property);
        match decoded {
            Ok(hist) => hist,
            Err(e) => {
                self.capture(e);
                None
            }
        }
    }
}

/// Exact-count + histogram-backed statistics over the **real** store's durable catalogue
/// (`rmp` task #81), surfaced to the cardinality estimator ([`crate::cardinality`]).
///
/// # What is reported
///
/// The counts are the store's **global committed catalogue counts** (`rmp` tasks #79/#82): the
/// grand total of live nodes / relationships and the per-label / per-relationship-type breakdowns,
/// maintained incrementally and persisted with the catalog. They are **not** filtered by this
/// graph's MVCC snapshot — and deliberately so: cost estimation wants the catalogue's aggregate
/// shape of the data, not one transaction's snapshot view (statistics are inherently approximate
/// inputs to a cost model, and the catalogue counts are the conventional, cheaply-maintained source
/// a planner consumes). This matches how the per-label counts themselves are maintained.
///
/// The property-selectivity methods decode the durable equi-depth histogram for the
/// `(label, property)` pair (built by [`recompute_property_histogram`](RecordStoreGraph::recompute_property_histogram)).
/// Decoding returns an **owned** [`PropertyHistogram`], so no borrow of the store escapes the method
/// — the `&self` / `RefCell` borrow is released before the histogram is queried.
///
/// # `None` semantics (fall back), exactly as the seam documents
///
/// A property method returns `None` — requesting the estimator's documented constant fallback — when
/// **no** histogram is stored for the pair (the column was never `ANALYZE`d, or the label/property
/// token was never interned), or when the query value / a present range bound is not index-encodable
/// (`Null` / `List` / `Map`). A *stored* histogram over an absent value legitimately answers
/// `Some(0.0)` (an exact "nothing matches"), distinct from the `None` "unknown" sentinel.
impl<D: BlockDevice, S: LogSink> crate::statistics::Statistics for RecordStoreGraph<D, S> {
    fn total_nodes(&self) -> u64 {
        self.store.borrow().total_node_count()
    }

    fn nodes_with_label(&self, label: &str) -> Option<u64> {
        // The backend tracks exact per-label counts (`rmp` task #79). A label that was never interned
        // can have no live node, so it is an exact `Some(0)` — never the `None` "unknown" sentinel.
        // The reader is shared with `CoordinatorStatistics` (`rmp` task #82).
        Some(crate::store_statistics::nodes_with_label(
            &self.store.borrow(),
            label,
        ))
    }

    fn total_relationships(&self) -> u64 {
        self.store.borrow().total_relationship_count()
    }

    fn relationships_with_type(&self, rel_type: &str) -> Option<u64> {
        // Exact per-relationship-type counts (`rmp` task #79); a never-interned type is an exact 0.
        Some(crate::store_statistics::relationships_with_type(
            &self.store.borrow(),
            rel_type,
        ))
    }

    fn estimate_nodes_label_property_eq(
        &self,
        label: &str,
        property: &str,
        value: &Value,
    ) -> Option<f64> {
        // No histogram stored -> None (fall back). A decode error is captured and also reported as
        // None (the caller must inspect `take_error`). An unindexable query value (Null/List/Map)
        // cannot be placed in the histogram -> None (`crate::store_statistics` docs).
        let hist = self.decode_histogram(label, property)?;
        crate::store_statistics::histogram_estimate_eq(&hist, value)
    }

    fn estimate_nodes_label_property_range(
        &self,
        label: &str,
        property: &str,
        lo: Option<&Value>,
        lo_inclusive: bool,
        hi: Option<&Value>,
        hi_inclusive: bool,
    ) -> Option<f64> {
        // A *present* bound that is not index-encodable makes the range unsound, so the shared
        // estimator returns `None` (fall back) rather than silently dropping the bound; an *absent*
        // bound is simply open on that side (`crate::store_statistics::histogram_estimate_range`).
        let hist = self.decode_histogram(label, property)?;
        crate::store_statistics::histogram_estimate_range(&hist, lo, lo_inclusive, hi, hi_inclusive)
    }

    fn distinct_label_property_values(&self, label: &str, property: &str) -> Option<u64> {
        Some(self.decode_histogram(label, property)?.distinct())
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

        // Index-accelerated path (`rmp` task #48): on the coordinated path the derived label
        // [`IndexSet`] yields **candidate** node ids carrying this token. Candidates may be a
        // superset (stale entries from rolled-back / overwritten / deleted nodes), so the **same**
        // per-candidate filter the full scan applies (visibility + `node_has_label`) is re-run; the
        // result is therefore *exactly* the full-scan result over a candidate subset.
        if let Some(index) = &self.index {
            // SSI predicate footprint (`04 §5.4`, `rmp` task #46): a `MATCH (n:Label)` is a
            // **predicate read**, not a point read of the matching rows — a concurrent transaction
            // that writes *any* node (changing which nodes match the label, the phantom case) must
            // close an rw-edge with this scan. The per-node `SsiTracker` has no predicate/range
            // marker yet (that is the deferred index-range-marker follow-up, still #16/#39), so we
            // keep the conservative, **correct** approximation the pre-index full scan used: SIREAD
            // every live node. The index only accelerates computing the *result*, never narrows the
            // read footprint — narrowing it would drop the phantom protection that makes write-skew
            // over a label predicate serializable.
            self.mark_all_live_nodes();
            let candidates = index.borrow_mut().seek_label(token_id);
            return self.filter_label_candidates(token_id, candidates);
        }

        // Standalone fallback: scan every live node and filter by the inline label bitmap. Correct,
        // just O(live nodes).
        let ids = {
            let mut store = self.store.borrow_mut();
            match store.scan_node_ids() {
                Ok(ids) => ids,
                Err(e) => {
                    drop(store);
                    self.capture(e);
                    return Vec::new();
                }
            }
        };
        self.filter_label_candidates(token_id, ids)
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

    fn index_seek_eq(&self, label: &str, property: &str, seek: &Value) -> Option<Vec<NodeId>> {
        // Only the coordinated path has a derived index; otherwise the executor falls back to
        // `scan_filter_eq` (`rmp` task #48).
        let index = self.index.as_ref()?;
        // Resolve the label + prop-key tokens via the store; if either was never interned, no node
        // can match, but we still only serve the seek when a *matching index is registered* (else
        // fall back so the executor's scan covers a property the index does not).
        let label_token = self.label_id_existing(label)?;
        let prop_key = self.store.borrow().token_id(Namespace::PropKey, property)?;
        if !index.borrow().has_node_property(label_token, prop_key) {
            return None; // no usable index: scan fallback
        }

        // SSI predicate footprint: an indexed equality predicate replaces the `scan_filter_eq`
        // fallback, which read every node via `scan_nodes_by_label`. Preserve that exact read
        // footprint so an index seek and the scan fallback are indistinguishable to SSI (`04 §5.4`,
        // `rmp` task #46) — see `mark_all_live_nodes`.
        self.mark_all_live_nodes();

        // Candidate ids for `(label_token, prop_key) == seek`. The index is candidate-only, so we
        // re-check the FULL `scan_filter_eq` predicate per candidate: visible + carries the label
        // (`filter_label_candidates`) + the *current* value equals `seek` by Cypher equality.
        let candidates = index
            .borrow_mut()
            .seek_node_property_eq(label_token, prop_key, seek)
            .unwrap_or_default();
        let labelled = self.filter_label_candidates(label_token, candidates);

        let mut out: Vec<NodeId> = labelled
            .into_iter()
            .filter(|id| {
                self.node_property(*id, property)
                    .is_some_and(|v| crate::equality::equals(&v, seek).is_true())
            })
            .collect();
        // De-duplicate: a stale + a live index entry can name the same id twice.
        out.sort_unstable();
        out.dedup();
        Some(out)
    }

    fn index_seek_range(
        &self,
        label: &str,
        property: &str,
        lower: Option<(&Value, bool)>,
        upper: Option<(&Value, bool)>,
    ) -> Option<Vec<NodeId>> {
        use std::cmp::Ordering;

        let index = self.index.as_ref()?;
        let label_token = self.label_id_existing(label)?;
        let prop_key = self.store.borrow().token_id(Namespace::PropKey, property)?;
        if !index.borrow().has_node_property(label_token, prop_key) {
            return None; // no usable index: scan fallback
        }

        // SSI predicate footprint: an indexed range predicate replaces the `scan_filter_range`
        // fallback (which read every node via `scan_nodes_by_label`). Preserve that read footprint so
        // the index path and the scan fallback are indistinguishable to SSI (`04 §5.4`).
        self.mark_all_live_nodes();

        // Candidate ids for the requested range (a superset; see `IndexSet::seek_node_property_range`).
        // NOTE (v1-index limitation): the index keys by exact encoded value, so the value-match path
        // assumes per-property type consistency (the common case). Mixed int/float values for one
        // property would need the scan fallback; the planner is only given a property index where
        // that holds. The re-check below guarantees no WRONG rows regardless of candidate skew.
        let candidates = index
            .borrow_mut()
            .seek_node_property_range(label_token, prop_key, lower, upper)
            .unwrap_or_default();
        let labelled = self.filter_label_candidates(label_token, candidates);

        // Re-check the FULL `scan_filter_range` predicate per candidate: visible + has label (done
        // above) + the current value is non-null and satisfies BOTH provided bounds via `cmp_values`.
        let satisfies = |v: &Value| -> bool {
            if v.is_null() {
                return false;
            }
            // Lower bound: `(value, inclusive)` -> keep `ord != Less` if inclusive else `ord == Greater`.
            if let Some((bound_value, inclusive)) = lower {
                if bound_value.is_null() {
                    return false;
                }
                let ord = crate::ordering::cmp_values(v, bound_value);
                let ok = if inclusive {
                    ord != Ordering::Less
                } else {
                    ord == Ordering::Greater
                };
                if !ok {
                    return false;
                }
            }
            // Upper bound: keep `ord != Greater` if inclusive else `ord == Less`.
            if let Some((bound_value, inclusive)) = upper {
                if bound_value.is_null() {
                    return false;
                }
                let ord = crate::ordering::cmp_values(v, bound_value);
                let ok = if inclusive {
                    ord != Ordering::Greater
                } else {
                    ord == Ordering::Less
                };
                if !ok {
                    return false;
                }
            }
            true
        };

        let mut out: Vec<NodeId> = labelled
            .into_iter()
            .filter(|id| {
                self.node_property(*id, property)
                    .is_some_and(|v| satisfies(&v))
            })
            .collect();
        out.sort_unstable();
        out.dedup();
        Some(out)
    }

    fn fulltext_query(&self, name: &str, search: &str) -> Option<Vec<NodeId>> {
        // Only the coordinated path carries the derived `IndexSet` that holds the full-text index
        // (`rmp` task #72). Without one there is no full-text index at all, so `None` (the procedure
        // turns that into a "no such full-text index" error).
        let index = self.index.as_ref()?;
        // The full-text index must be declared (by name). If it is not, return `None` so the
        // procedure raises a clear error rather than silently empty results.
        let (label_token, _props, _analyzer) = index.borrow().fulltext_target(name)?;

        // SSI predicate footprint: a full-text query reads the candidate documents; preserve the same
        // read footprint as the scan fallback would by marking every live node of the covered label
        // (so the query and any future scan are indistinguishable to SSI, `04 §5.4`).
        self.mark_all_live_nodes();

        // Candidate ids from the inverted index (analyzed with the index's analyzer). Candidate-only,
        // so re-check visibility + current label via `filter_label_candidates` (which also records the
        // SIREAD markers). The inverted index is maintained on every write (`reindex_node`), so a
        // surviving candidate's terms are the node's current committed/own-transaction text.
        let candidates = index
            .borrow()
            .query_fulltext(name, search, graphus_index::fulltext::MatchSemantics::Or)
            .unwrap_or_default();
        let mut out = self.filter_label_candidates(label_token, candidates);
        out.sort_unstable();
        out.dedup();
        Some(out)
    }

    fn fulltext_score(&self, name: &str, node: NodeId, search: &str) -> Option<u64> {
        let index = self.index.as_ref()?;
        index.borrow().fulltext_score(name, node.0, search)
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
        // Index the node's now-current labels and property values, once all writes succeeded
        // (`rmp` task #48). On any captured error the node is untrustworthy and the caller rolls
        // back, so skip indexing rather than record entries for a doomed write. (`set_node_property`
        // already reindexed per property, but a final pass after the labels are set is the single
        // point that guarantees label entries are present too.)
        if !self.has_error() {
            self.reindex_node(node);
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
            return;
        }
        // The store write succeeded: index the node's now-current value (`rmp` task #48). A removal
        // (`SET n.p = null`, handled above) needs no reindex — dropping a key never adds a candidate,
        // and the seek re-checks the store so a stale candidate is filtered out.
        self.reindex_node(node);
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
        // Index the node's now-current labels (and, for any newly-matched label-property index, its
        // values) once the store write succeeded and no error was captured (`rmp` task #48).
        if !self.has_error() {
            self.reindex_node(node);
        }
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

    // ---- statistics ---------------------------------------------------------------------------

    /// Surfaces the store's durable statistics catalogue to the cardinality estimator
    /// (`rmp` task #81). The real backend tracks live counts (`rmp` tasks #79/#82) and per-indexed-
    /// property equi-depth histograms (built on demand by [`recompute_property_histogram`](Self::recompute_property_histogram)),
    /// so the planner gets real selectivities here exactly as it does over [`MemGraph`](crate::graph_access::MemGraph).
    fn statistics(&self) -> Option<&dyn crate::statistics::Statistics> {
        Some(self)
    }
}
