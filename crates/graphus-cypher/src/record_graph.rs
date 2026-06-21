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
use graphus_core::{Timestamp, TxnId, Value, VersionStamp};
use graphus_index::histogram::PropertyHistogram;
use graphus_index::keycodec::{encode_equality_canonical, encode_single};
use graphus_index::kinds::DEFAULT_HISTOGRAM_BUCKETS;
use graphus_io::BlockDevice;
use graphus_storage::{ConstraintKind, MvccHeader, Namespace, RecordStore};
use graphus_txn::{
    CommitRegistry, LockOutcome, LockTable, PredicateRead, Snapshot, SsiTracker, is_visible,
};
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

/// Renders a [`Value`] compactly for a constraint-violation message (`rmp` task #99): a string is
/// single-quoted, everything else uses its `Debug` form. Only for the human message.
fn render_value(value: &Value) -> String {
    match value {
        Value::String(s) => format!("'{s}'"),
        other => format!("{other:?}"),
    }
}

/// Renders a composite-tuple value list as `(v1, v2, …)` for a node-key violation message (`rmp` task
/// #100), reusing [`render_value`] per element.
fn render_tuple(values: &[Value]) -> String {
    let inner = values
        .iter()
        .map(render_value)
        .collect::<Vec<_>>()
        .join(", ");
    format!("({inner})")
}

/// Whether two composite tuples are equal by **Cypher value equality**, element-wise (`rmp` task
/// #100), used to confirm a candidate node holds the same node-key tuple. Unequal lengths are never
/// equal; a null element would make a tuple incomplete and never reaches here.
fn tuples_match(a: &[Value], b: &[Value]) -> bool {
    a.len() == b.len()
        && a.iter()
            .zip(b)
            .all(|(x, y)| crate::equality::equals(x, y).is_true())
}

use crate::constraint::ConstraintViolation;
use crate::graph_access::{
    DeletedEntity, ExpandDirection, GraphAccess, Incident, NodeId, RelData, RelId,
};
use crate::index_set::{ConstraintRule, IndexSet};

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
    /// While `true`, the per-property constraint check in
    /// [`set_node_property`](Self::set_node_property) is **suppressed** (`rmp` task #99). Set by
    /// [`create_node`](Self::create_node) and [`replace_node_properties`](Self::replace_node_properties)
    /// for the duration of applying a node's full property map, so constraints are checked **once**,
    /// after every property is written — never against a half-built node where a not-yet-set required
    /// property would spuriously trip an existence check, or a soon-to-be-overwritten value would trip
    /// a uniqueness check. The enclosing method runs the single deferred check itself.
    defer_constraint_check: std::cell::Cell<bool>,
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
            defer_constraint_check: std::cell::Cell::new(false),
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
            defer_constraint_check: std::cell::Cell::new(false),
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

    /// Records a **predicate** SIREAD marker for this transaction, if coordinated (`04 §5.4`, `rmp`
    /// #171); a no-op in the standalone path. This is what closes the **phantom** hole the per-record
    /// [`note_read`](Self::note_read) cannot: a predicate read sees the *set* of matching nodes
    /// (possibly empty), so a concurrent insert that makes a node match must abort one of the two.
    fn note_predicate_read(&self, predicate: PredicateRead) {
        if let Some(ssi) = &self.ssi {
            ssi.borrow_mut().record_predicate_read(self.txn, predicate);
        }
    }

    /// Announces the **predicate footprint** of node `node` to the SSI tracker (`rmp` #171): the set
    /// of [`PredicateRead`] markers the node currently satisfies, so a concurrent transaction that
    /// read any of those predicates (and saw this node's absence) gets an rw-edge into this writer.
    /// Driven from [`reindex_node`](Self::reindex_node) with the node's already-resolved current
    /// `label_tokens` + `(prop_key, value)` pairs, so it reuses that single write-time read of the
    /// node's state. A no-op in the standalone path (no SSI tracker).
    ///
    /// The footprint enumerates exactly the markers a reader can register (see [`PredicateRead`]):
    /// the `AllNodes` marker, one `Label` marker per label, and one `Equality` marker per
    /// `(label, property, value)` the node holds (the value order-preservingly encoded, matching how
    /// an equality predicate read encodes its sought value). A non-encodable value (`Null`/`List`/
    /// `Map`) contributes no `Equality` marker — it can never be an equality predicate's sought value
    /// either, so nothing is missed; the coarser `Label`/`AllNodes` markers still cover any
    /// label/all-nodes reader.
    fn note_predicate_write(&self, label_tokens: &[u32], resolved_props: &[(u32, Value)]) {
        let Some(ssi) = &self.ssi else {
            return; // standalone path: nothing to track.
        };
        let mut footprint = Vec::with_capacity(1 + label_tokens.len() * (1 + resolved_props.len()));
        footprint.push(PredicateRead::AllNodes);
        for &label in label_tokens {
            footprint.push(PredicateRead::Label(label));
            for (prop_key, value) in resolved_props {
                // Use the **Cypher-equality-canonical** encoding (`rmp` #171 blocker C1), NOT the
                // order-preserving index key: `encode_single` tags `Integer(1)` and `Float(1.0)`
                // apart (they differ in the numtag tie-break byte), so a reader of `{p: 1}` and this
                // writer's `{p: 1.0}` would register different markers and the phantom rw-edge would
                // never close. `encode_equality_canonical` maps Cypher-equal numbers to one key, so
                // the cross-type numeric phantom is caught. NaN yields no marker (never equal to
                // anything), exactly as a non-encodable value is skipped.
                if let Ok(encoded) = encode_equality_canonical(value) {
                    footprint.push(PredicateRead::Equality {
                        label,
                        property: *prop_key,
                        value: encoded,
                    });
                }
            }
        }
        ssi.borrow_mut()
            .record_predicate_write(self.txn, &footprint);
    }

    /// Announces a node's **pre-image** predicate footprint before a mutation that makes the node
    /// **stop** satisfying one or more predicates (`rmp` #171 blocker B1): a `DELETE` / `DETACH DELETE`,
    /// a `REMOVE n:Label`, or a property clear (`SET n.p = null` / `REMOVE n.p`).
    ///
    /// # Why a delete is a predicate write
    ///
    /// A reader that evaluated `MATCH (n:Label {p: v})` and **saw** a matching node has read that the
    /// node *is* present. A concurrent transaction that then **deletes** (or un-matches) that node has
    /// invalidated the reader's result — a classic *read-then-delete write-skew* — yet the physical-key
    /// rw-edge alone is insufficient when the reader reached the node via a **predicate** scan whose
    /// result set the delete changed. Announcing the node's *current* (pre-mutation) labels/properties
    /// as a predicate write closes the rw-edge into this writer for exactly those predicate readers,
    /// symmetric to how an **insert** ([`note_predicate_write`](Self::note_predicate_write) from
    /// [`reindex_node`](Self::reindex_node)) closes the edge for an absence-reader.
    ///
    /// Must be called **before** the store mutation, while the pre-image is still readable. A no-op in
    /// the standalone path (no SSI tracker) and a best-effort read: if the labels cannot be enumerated
    /// (an overflow-form bitmap) only the coarse `AllNodes`/`Label` markers from any readable state are
    /// announced — never a wrong row, and the per-record `note_write` already covers the physical key.
    fn note_predicate_write_preimage(&self, node: NodeId) {
        if self.ssi.is_none() {
            return; // standalone path: nothing to track.
        }
        // Read the node's *current* labels (store borrow released before announcing).
        let label_tokens: Vec<u32> = {
            let mut store = self.store.borrow_mut();
            match store.node_labels(node.0) {
                Ok(ids) => ids,
                // Cannot enumerate labels (overflow-form / missing): still announce `AllNodes` so an
                // all-nodes predicate reader closes the edge. `note_predicate_write` with empty labels
                // pushes exactly the `AllNodes` marker.
                Err(_) => {
                    self.note_predicate_write(&[], &[]);
                    return;
                }
            }
        };
        // The node's current property values (borrows the store internally and releases it).
        let props = self.read_node_props(node);
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
        self.note_predicate_write(&label_tokens, &resolved_props);
    }

    /// Registers the **relationship-pattern** predicate read footprint for a traversal filtered by
    /// `types` (`rmp` #171 blocker A1): a `MATCH ()-[r:T]-()` reads which relationships of type `T`
    /// exist, so a concurrent `create_rel`/`delete_rel` of that type is a relationship phantom that
    /// must close an rw-edge — even when the traversal returns nothing.
    ///
    /// * An empty `types` (an untyped `MATCH ()-[r]-()`) registers the conservative [`PredicateRead::AnyRel`]
    ///   marker: *any* relationship create/delete matches.
    /// * Each requested type name resolves to its [`Namespace::RelType`] token; a
    ///   [`PredicateRead::RelType`] marker is registered per token. A type name that was **never
    ///   interned** (no edge of that type can exist yet) registers the conservative `AnyRel` marker
    ///   instead — a concurrent writer could `CREATE` the first edge of that type, interning a token we
    ///   cannot know here, exactly as [`scan_nodes_by_label`](Self::scan_nodes_by_label) falls back to
    ///   `AllNodes` for a never-seen label. Reads never intern (no durable side effect on a read path).
    ///
    /// A no-op in the standalone path (no SSI tracker).
    fn note_rel_predicate_read(&self, types: &[String]) {
        if self.ssi.is_none() {
            return; // standalone path: nothing to track.
        }
        if types.is_empty() {
            self.note_predicate_read(PredicateRead::AnyRel);
            return;
        }
        for name in types {
            match self.store.borrow().token_id(Namespace::RelType, name) {
                Some(token) => self.note_predicate_read(PredicateRead::RelType(token)),
                // Never-interned type: a concurrent writer could create the first edge of it (a
                // phantom) under a token we cannot know, so register the conservative `AnyRel`.
                None => self.note_predicate_read(PredicateRead::AnyRel),
            }
        }
    }

    /// Announces a relationship's **predicate footprint** to the SSI tracker (`rmp` #171 blocker A1):
    /// the [`PredicateRead::AnyRel`] marker plus the [`PredicateRead::RelType`] marker for its type
    /// token, so a concurrent transaction that read a relationship-pattern predicate (`MATCH ()-[r:T]-()`,
    /// or untyped) this edge satisfies — and saw its absence (on a `create_rel`) or presence (on a
    /// `delete_rel`) — closes an rw-edge into this writer. The relationship analogue of
    /// [`note_predicate_write`](Self::note_predicate_write). A no-op in the standalone path.
    fn note_rel_predicate_write(&self, type_id: u32) {
        if self.ssi.is_none() {
            return; // standalone path: nothing to track.
        }
        self.note_predicate_write_footprint(&[
            PredicateRead::AnyRel,
            PredicateRead::RelType(type_id),
        ]);
    }

    /// Thin wrapper announcing an explicit `footprint` of [`PredicateRead`] markers to the shared
    /// tracker (used for the relationship footprint, whose markers are not derived from node state).
    fn note_predicate_write_footprint(&self, footprint: &[PredicateRead]) {
        if let Some(ssi) = &self.ssi {
            ssi.borrow_mut().record_predicate_write(self.txn, footprint);
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
            defer_constraint_check: std::cell::Cell::new(false),
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

    /// Whether the version carrying `mvcc` was **deleted by this very transaction** — its creator is
    /// visible to the snapshot (it existed before our `DELETE`) and its expirer is *our own*
    /// in-flight stamp (`04 §5.3`). This is the discriminator openCypher needs for a same-query
    /// `DELETE`: such an entity keeps its identity (`id`/`type`) but a property/label read on it
    /// raises `DeletedEntityAccess` (`clauses/return/Return2.feature`).
    ///
    /// `is_visible(snapshot, created_ts, 0, registry)` tests creator-visibility alone (passing `0` as
    /// the expirer = "live", so the result is true iff the creator committed at/before our snapshot or
    /// is our own write). The deliberate side-effect-free read (no `note_read`/SSI marker) keeps the
    /// own-write self-delete check from perturbing serializability: a transaction inspecting its *own*
    /// tombstone has no rw-dependency to record.
    fn deleted_by_self(&self, mvcc: MvccHeader) -> bool {
        let creator_visible = is_visible(self.snapshot, mvcc.created_ts, 0, &self.registry);
        creator_visible
            && VersionStamp::from_raw(mvcc.expired_ts) == VersionStamp::InFlight(self.txn)
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

        // SSI predicate footprint (`rmp` #171): announce the markers this node now satisfies, so a
        // concurrent transaction that read one of those predicates (and saw this node's absence) gets
        // an rw-antidependency edge into this writer — closing the phantom hole the per-record write
        // marker (`note_write`, already recorded at the store mutation) cannot. Done with the same
        // current `(label_tokens, resolved_props)` this index maintenance already read, so no extra
        // store read is needed.
        self.note_predicate_write(&label_tokens, &resolved_props);

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

        // Spatial (point) indexes are maintained per-write the same way the inverted index is
        // (`rmp` task #98): for every registered spatial index `(label_token, prop_key)`, if the node
        // currently carries the covered label AND has a point value for the covered property, that
        // point is (re)inserted into the grid; in every other case (the node lost the label, the
        // property is absent, or it is no longer a point) the node is removed from the grid so a seek
        // never sees a phantom. Like the full-text index this is a wholesale per-node re-index, because
        // the grid is keyed by node id and a removed/changed point must not linger.
        for (label_token, prop_key) in index.registered_spatial() {
            let covered = label_tokens.contains(&label_token);
            let point = covered.then(|| {
                resolved_props
                    .iter()
                    .find(|(k, v)| *k == prop_key && matches!(v, Value::Point(_)))
                    .map(|(_, v)| v)
            });
            match point {
                Some(Some(value)) => {
                    index.insert_spatial_point(label_token, prop_key, value, node.0);
                }
                _ => index.remove_spatial_point(label_token, prop_key, node.0),
            }
        }

        // Composite indexes — a node-key constraint's backing index (`rmp` task #100) — are maintained
        // the same candidate-only way as the property indexes: for every registered composite index
        // `(label_token, property tuple)`, if the node currently carries the covered label AND holds the
        // whole tuple (every covered property present and non-null), the current tuple is **inserted**.
        // Stale entries from a prior value are tolerated because the node-key duplicate check re-reads
        // each candidate's *current* tuple and excludes the node itself — so an over-broad candidate set
        // is always correct (a subset never is). A node missing a covered property is simply not indexed
        // for that key (it is not a uniqueness candidate, matching the node-key existence rule).
        for (label_token, property_tokens) in index.registered_composite() {
            if !label_tokens.contains(&label_token) {
                continue;
            }
            let mut tuple = Vec::with_capacity(property_tokens.len());
            let mut complete = true;
            for prop_key in &property_tokens {
                match resolved_props
                    .iter()
                    .find(|(k, _)| k == prop_key)
                    .map(|(_, v)| v)
                    .filter(|v| !v.is_null())
                {
                    Some(v) => tuple.push(v.clone()),
                    None => {
                        complete = false;
                        break;
                    }
                }
            }
            if complete {
                index.insert_composite(label_token, &property_tokens, &tuple, node.0);
            }
        }
    }

    /// Enforces every declared constraint (`rmp` task #99) that applies to `node`'s **current**
    /// labels, capturing a [`ConstraintViolation`] runtime error on the first breach so the statement
    /// aborts and the transaction rolls back **before commit** (the captured-error channel — see the
    /// module docs and `graphus_server::engine::exec::stream_rows`, which surfaces `take_error` as a
    /// terminal row error). A no-op on the standalone path (no coordinator ⇒ no constraint registry)
    /// and when no error-free constraint applies.
    ///
    /// Called after a node write has been applied to the store but **before** the matching
    /// `reindex_node`, at every site that can introduce a violation: `create_node` (new node),
    /// `set_node_property` (a value change), and `add_labels` (a node that gains a constrained label).
    /// Existing data is checked at `CREATE CONSTRAINT` time by the coordinator, so this only guards
    /// **incremental** writes.
    ///
    /// # Uniqueness — index-backed, candidate-set re-checked
    ///
    /// A uniqueness constraint registers a backing node-property index (see
    /// [`TxnCoordinator::create_constraint`](crate::coordinator::TxnCoordinator::create_constraint)),
    /// so the duplicate search reuses [`index_seek_eq`](Self::index_seek_eq)'s machinery: candidate
    /// ids of the label holding the same value are re-checked against the store (visibility + current
    /// label + current value), then `node` itself is excluded. Any **other** visible node of the label
    /// holding the value is a violation. If no index is registered (a defensive fallback) a label scan
    /// is used — correctness first.
    ///
    /// # Existence — a pure per-node predicate
    ///
    /// An existence (`NOT NULL`) constraint is satisfied iff `node` currently carries the covered
    /// property with a non-null value, read straight from `node`'s own state.
    fn enforce_constraints_for_node(&self, node: NodeId) {
        // No coordinator ⇒ no constraint registry (standalone path); nothing to enforce.
        let Some(index) = &self.index else {
            return;
        };

        // The node's current label tokens (store borrow, released before consulting the registry).
        let label_tokens: Vec<u32> = {
            let mut store = self.store.borrow_mut();
            match store.node_labels(node.0) {
                Ok(ids) => ids,
                Err(_) => return, // cannot enumerate labels: skip (a captured store error already aborts)
            }
        };
        if label_tokens.is_empty() {
            return;
        }

        // Gather the applicable rules (index borrow released before the per-rule store re-checks). A
        // rule may apply via several of the node's labels; de-duplicate by name so a constraint is
        // checked once.
        let mut rules: Vec<ConstraintRule> = Vec::new();
        {
            let idx = index.borrow();
            for &lt in &label_tokens {
                for rule in idx.constraints_for_label(lt) {
                    if !rules.contains(&rule) {
                        rules.push(rule);
                    }
                }
            }
        }
        if rules.is_empty() {
            return;
        }

        for rule in rules {
            // Resolve the covered label name + every covered property name for a precise message (and
            // the seek API, which is name-keyed). A token with no resolvable name cannot apply to a live
            // node, so the whole rule is skipped defensively.
            let (label_name, property_names) = {
                let store = self.store.borrow();
                let Some(label) = store
                    .token_name(Namespace::Label, rule.label_token)
                    .map(ToOwned::to_owned)
                else {
                    continue;
                };
                let mut names = Vec::with_capacity(rule.property_tokens.len());
                let mut ok = true;
                for &prop_key in &rule.property_tokens {
                    match store.token_name(Namespace::PropKey, prop_key) {
                        Some(p) => names.push(p.to_owned()),
                        None => {
                            ok = false;
                            break;
                        }
                    }
                }
                if !ok {
                    continue;
                }
                (label, names)
            };

            // The constraint name (for the message): the first registered constraint matching this
            // rule. (`registered_constraints` is small; this is off the hot write path only when a
            // constraint applies.)
            let constraint_name = index
                .borrow()
                .registered_constraints()
                .into_iter()
                .find(|(_, r)| *r == rule)
                .map(|(name, _)| name)
                .unwrap_or_default();

            match rule.kind {
                ConstraintKind::Existence => {
                    let property_name = &property_names[0];
                    let own_value = self.node_property(node, property_name);
                    if own_value.as_ref().is_none_or(Value::is_null) {
                        self.capture(
                            ConstraintViolation::Existence {
                                name: constraint_name,
                                label: label_name,
                                property: property_name.clone(),
                            }
                            .into_error(),
                        );
                        return;
                    }
                }
                ConstraintKind::Unique => {
                    let property_name = &property_names[0];
                    // A null/absent value never participates in uniqueness (Cypher equality: null is
                    // never equal), matching the index's treatment — so it can never collide.
                    let Some(value) = self
                        .node_property(node, property_name)
                        .filter(|v| !v.is_null())
                    else {
                        continue;
                    };
                    if self
                        .unique_conflict(&label_name, property_name, &value, node)
                        .is_some()
                    {
                        self.capture(
                            ConstraintViolation::Uniqueness {
                                name: constraint_name,
                                label: label_name,
                                property: property_name.clone(),
                                value: render_value(&value),
                            }
                            .into_error(),
                        );
                        return;
                    }
                }
                ConstraintKind::NodeKey => {
                    if let Some(violation) = self.node_key_conflict(
                        &constraint_name,
                        &label_name,
                        &property_names,
                        &rule,
                        node,
                    ) {
                        self.capture(violation.into_error());
                        return;
                    }
                }
                ConstraintKind::PropertyType => {
                    let property_name = &property_names[0];
                    // Only a present, non-null value is type-checked: a missing/null value is allowed
                    // (a property-type constraint does not imply existence).
                    let Some(value) = self
                        .node_property(node, property_name)
                        .filter(|v| !v.is_null())
                    else {
                        continue;
                    };
                    // A `PropertyType` rule always carries its descriptor (set at registration); a
                    // missing one is a defensive skip rather than a panic on the write path.
                    let Some(descriptor) = rule.type_descriptor.as_ref() else {
                        continue;
                    };
                    if !crate::constraint::value_matches_descriptor(&value, descriptor) {
                        self.capture(
                            ConstraintViolation::PropertyType {
                                name: constraint_name,
                                label: label_name,
                                property: property_name.clone(),
                                expected: crate::constraint::type_descriptor_name(descriptor),
                                actual: crate::constraint::value_type_name(&value),
                            }
                            .into_error(),
                        );
                        return;
                    }
                }
            }
        }
    }

    /// Checks a node-key constraint for `node` (`rmp` task #100): the covered composite tuple of
    /// `property_names` must be (a) **complete** — every covered property present and non-null — and
    /// (b) **unique** among the other nodes carrying the label. Returns the [`ConstraintViolation`] to
    /// capture on the first breach, or [`None`] when `node` conforms.
    ///
    /// The uniqueness search reuses the backing **composite** index when one is registered (a node-key
    /// constraint registers one in [`TxnCoordinator::create_constraint_general`]): candidate ids holding
    /// the same tuple are re-checked against the store (visibility + current label + current tuple) and
    /// `node` itself is excluded. With no index a label scan + per-node tuple re-check is the (correct,
    /// slower) fallback. Either way every candidate is an exact match, so the first one that is not
    /// `node` is a genuine duplicate.
    fn node_key_conflict(
        &self,
        constraint_name: &str,
        label_name: &str,
        property_names: &[String],
        rule: &ConstraintRule,
        node: NodeId,
    ) -> Option<ConstraintViolation> {
        // Build `node`'s own current tuple; a single absent/null covered property is an existence breach.
        let mut tuple = Vec::with_capacity(property_names.len());
        for property_name in property_names {
            match self
                .node_property(node, property_name)
                .filter(|v| !v.is_null())
            {
                Some(v) => tuple.push(v),
                None => {
                    return Some(ConstraintViolation::NodeKeyMissing {
                        name: constraint_name.to_owned(),
                        label: label_name.to_owned(),
                        properties: property_names.to_vec(),
                    });
                }
            }
        }

        // Uniqueness over the complete tuple, excluding `node`.
        if self
            .node_key_tuple_conflict(label_name, rule, &tuple, node)
            .is_some()
        {
            return Some(ConstraintViolation::NodeKeyDuplicate {
                name: constraint_name.to_owned(),
                label: label_name.to_owned(),
                properties: property_names.to_vec(),
                values: render_tuple(&tuple),
            });
        }
        None
    }

    /// Finds **another** visible node carrying `label_name` whose current covered tuple equals `tuple`,
    /// excluding `self_node` (`rmp` task #100). Index-backed via the composite index when registered,
    /// else a label scan + per-node tuple re-check — both re-check the store, so the first non-self
    /// match is a genuine node-key duplicate. Returns the conflicting id, or [`None`].
    fn node_key_tuple_conflict(
        &self,
        label_name: &str,
        rule: &ConstraintRule,
        tuple: &[Value],
        self_node: NodeId,
    ) -> Option<u64> {
        let candidates: Vec<NodeId> = self
            .composite_seek_eq(rule, tuple)
            .unwrap_or_else(|| self.scan_nodes_by_label(label_name));
        candidates
            .into_iter()
            .filter(|id| *id != self_node)
            .find(|id| {
                self.node_tuple(*id, &rule.property_tokens)
                    .is_some_and(|other| tuples_match(&other, tuple))
            })
            .map(|n| n.0)
    }

    /// Candidate node ids whose composite tuple for `rule`'s `(label, property tuple)` equals `tuple`,
    /// re-checked for visibility + current label (`rmp` task #100). [`None`] when no composite index is
    /// registered (the caller falls back to a label scan). The composite index is candidate-only, so the
    /// caller re-checks the exact tuple per candidate.
    fn composite_seek_eq(&self, rule: &ConstraintRule, tuple: &[Value]) -> Option<Vec<NodeId>> {
        let index = self.index.as_ref()?;
        if !index
            .borrow()
            .has_composite(rule.label_token, &rule.property_tokens)
        {
            return None; // no usable composite index: scan fallback
        }
        // SSI predicate footprint: a composite-tuple equality replaces the label-scan fallback, so
        // preserve that exact read footprint (`04 §5.4`).
        self.mark_all_live_nodes();
        let candidates = index
            .borrow_mut()
            .seek_composite_eq(rule.label_token, &rule.property_tokens, tuple)
            .unwrap_or_default();
        Some(self.filter_label_candidates(rule.label_token, candidates))
    }

    /// The current composite tuple node `id` holds for the property-key tokens `property_tokens`, or
    /// [`None`] if any covered property is absent or null on the node (`rmp` task #100). Reads the
    /// node's current properties once; a non-existent node yields [`None`].
    fn node_tuple(&self, id: NodeId, property_tokens: &[u32]) -> Option<Vec<Value>> {
        let props = self.node_properties(id)?;
        let mut tuple = Vec::with_capacity(property_tokens.len());
        for &prop_key in property_tokens {
            // Resolve the property name once per token via the store (token → name), then read it.
            let name = self
                .store
                .borrow()
                .token_name(Namespace::PropKey, prop_key)
                .map(ToOwned::to_owned)?;
            let value = props
                .iter()
                .find(|(k, _)| *k == name)
                .map(|(_, v)| v.clone())
                .filter(|v| !v.is_null())?;
            tuple.push(value);
        }
        Some(tuple)
    }

    /// Finds **another** visible node carrying `label_token` whose current value for `property` equals
    /// `value` by Cypher equality, excluding `self_node` (`rmp` task #99). Returns the conflicting id,
    /// or [`None`] when `self_node` is the unique holder. Index-backed when a node-property index on
    /// `(label, property)` exists (a uniqueness constraint registers one), else a label scan — both
    /// re-check the store, so the result is exact.
    fn unique_conflict(
        &self,
        label: &str,
        property: &str,
        value: &Value,
        self_node: NodeId,
    ) -> Option<u64> {
        // Prefer the index path (`index_seek_eq` returns store-re-checked matching ids); fall back to
        // a full label scan + value re-check when no index is registered. Either way the candidates
        // are exact matches, so the first one that is not `self_node` is a genuine duplicate.
        let matches: Vec<NodeId> =
            self.index_seek_eq(label, property, value)
                .unwrap_or_else(|| {
                    self.scan_nodes_by_label(label)
                        .into_iter()
                        .filter(|id| {
                            self.node_property(*id, property)
                                .is_some_and(|v| crate::equality::equals(&v, value).is_true())
                        })
                        .collect()
                });
        matches.into_iter().find(|id| *id != self_node).map(|n| n.0)
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
        // SSI predicate footprint (`rmp` #171): an all-nodes scan `MATCH (n)` depends on *which nodes
        // exist*, so a concurrent insert of ANY node invalidates it. Register the `AllNodes` predicate
        // marker so that phantom closes an rw-edge even when this scan returns nothing (an empty graph)
        // — the per-node SIREADs below only cover nodes that already exist.
        self.note_predicate_read(PredicateRead::AllNodes);
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
            // The label was never interned, so no node can carry it *now*. But a *concurrent* writer
            // could `CREATE` the first node of this label (a phantom) — and it would intern a token we
            // cannot know here. We therefore register the conservative `AllNodes` marker so any such
            // insert closes an rw-edge, rather than interning the label on a read path (which would be
            // a durable side effect that changes read semantics). This is the rare "label never seen"
            // case, so the coarseness costs nothing in practice. `note_predicate_read` no-ops standalone.
            self.note_predicate_read(PredicateRead::AllNodes);
            return Vec::new();
        };

        // SSI predicate footprint (`rmp` #171): `MATCH (n:Label)` is a predicate over which nodes
        // carry the label, so a concurrent insert/relabel of a node into this label is a phantom that
        // must close an rw-edge — even when this scan returns nothing. The per-node SIREADs
        // (`mark_all_live_nodes` / `filter_label_candidates`) only cover *existing* nodes; the `Label`
        // predicate marker covers the not-yet-existing matching node. This same coarse `Label` marker
        // is also the conservative footprint for the scan-fallback equality / range filters that sit
        // on top of this scan (`scan_filter_eq` / `scan_filter_range`).
        self.note_predicate_read(PredicateRead::Label(token_id));

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
        // Relationship-pattern predicate read (`rmp` #171 blocker A1): a `MATCH ()-[r:T]-()` traversal
        // reads which relationships of the requested type(s) exist incident to the anchor. Register the
        // rel-type (or, untyped, `AnyRel`) predicate marker so a concurrent `create_rel`/`delete_rel`
        // of a matching type closes an rw-edge — the relationship phantom (read "no `:T` edges", then a
        // concurrent `CREATE` of a `:T` edge). This covers the *absent* edge the per-rel SIREADs below
        // (which only mark edges that already exist) cannot.
        self.note_rel_predicate_read(types);
        let mut store = self.store.borrow_mut();
        let rels = match store.incident_rels(node.0) {
            Ok(rels) => rels,
            Err(e) => {
                drop(store);
                self.capture(e);
                return Vec::new();
            }
        };
        // Resolve the requested rel-type names to interned type ids ONCE per expand, so the
        // per-edge filter is an integer compare instead of a `token_name` string lookup + compare
        // repeated across the whole incidence chain (`rmp` #319). A requested name with no interned
        // token matches no existing edge (the absent-edge phantom is already covered by
        // `note_rel_predicate_read` above), so it simply contributes no id. `None` means "any type".
        let wanted_type_ids: Option<Vec<u32>> = if types.is_empty() {
            None
        } else {
            Some(
                types
                    .iter()
                    .filter_map(|t| store.token_id(Namespace::RelType, t))
                    .collect(),
            )
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
            // Filter by relationship type (empty/`None` = any type).
            if let Some(ref ids) = wanted_type_ids {
                if !ids.contains(&rec.type_id) {
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

    fn rel_data_including_deleted(&self, rel: RelId) -> Option<RelData> {
        // Read the raw record. Unlike `rel_data` this does **not** apply the snapshot's expirer-hide,
        // so a relationship this transaction deleted earlier in the same query still yields its type
        // (openCypher keeps `type(r)`/`id(r)` accessible after `DELETE r`,
        // `clauses/return/Return2.feature` [14]). We still require the *creator* to be visible (a
        // relationship never created for us, or created by a concurrent uncommitted writer, is not
        // ours to read). No `note_read`/SSI marker: reading our own tombstone has no rw-dependency.
        let mut store = self.store.borrow_mut();
        let rec = match store.rel(rel.0) {
            Ok(rec) => rec,
            Err(_) => return None,
        };
        // Visible normally, or a tombstone we wrote ourselves: both keep the type readable.
        if !self.visible(rec.mvcc) && !self.deleted_by_self(rec.mvcc) {
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

    fn entity_deleted_by_txn(&self, entity: DeletedEntity) -> bool {
        // The raw MVCC header of the physical record (a missing page = the id was never allocated, so
        // it cannot be our self-delete). No `note_read`/SSI marker: a self-delete check on our own
        // write records no rw-dependency, so it must not perturb serializability (the surrounding read
        // methods all mark, but this is a side-effect-free identity check).
        let mvcc = match entity {
            DeletedEntity::Node(id) => match self.store.borrow_mut().node(id.0) {
                Ok(rec) => rec.mvcc,
                Err(_) => return false,
            },
            DeletedEntity::Rel(id) => match self.store.borrow_mut().rel(id.0) {
                Ok(rec) => rec.mvcc,
                Err(_) => return false,
            },
        };
        self.deleted_by_self(mvcc)
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

        // SSI predicate footprint for an indexed equality predicate (`rmp` #316). We do NOT
        // SIREAD-mark every live node here. The earlier `scan_filter_eq` fallback read every node,
        // so it conservatively marked all of them; that blanket marker manufactured an rw-edge with
        // *any* concurrent node writer — even one touching a node that does not match `(label,
        // property, value)` and that we never examined — which under contention produced a storm of
        // false aborts (measured: fraud-oltp abort_rate ≈ 0.97). It is also unnecessary for
        // serializability, which is fully covered by two precise markers:
        //   1. the per-candidate SIREAD in `filter_label_candidates` (below) marks every node the
        //      seek actually examined, so a concurrent modify/delete of a *matching* node closes an
        //      rw-edge; and
        //   2. the precise `Equality` predicate marker (below) pairs with the writer's pre- and
        //      post-image predicate writes (`note_predicate_write_preimage` + `reindex_node` in
        //      `set_node_property`, and `create_node`'s insert footprint), so a concurrent INSERT or
        //      an UPDATE of some other node *into* this exact `(label, property, value)` closes an
        //      rw-edge even when the seek currently matches nothing.
        // Together these cover every phantom the blanket marker did, without conflicting on nodes
        // that neither match nor were examined. (The range path keeps its conservative marker — a
        // value-change-into-range phantom is not as precisely covered; see `index_seek_range`.)
        // The phantom-safe predicate marker (`rmp` #171): the *precise* equality predicate, so a
        // concurrent insert of a node with this exact `(label, property, value)` closes an rw-edge
        // even when the seek currently matches nothing. The value is encoded with the
        // **Cypher-equality-canonical** encoder — the same encoding the writer's
        // `note_predicate_write` uses — so Cypher-equal values (incl. cross-type `1` vs `1.0`, blocker
        // C1) register the SAME marker. NOTE this is the SSI marker ONLY; the index lookup below passes
        // the raw `seek` `Value`, so seek/scan result semantics are entirely unchanged. A non-encodable
        // seek value (`Null`/`List`/`Map`/`NaN`) registers no `Equality` marker (it can never equal a
        // stored value either); the `mark_all_live_nodes` footprint still covers existing rows.
        if let Ok(encoded) = encode_equality_canonical(seek) {
            self.note_predicate_read(PredicateRead::Equality {
                label: label_token,
                property: prop_key,
                value: encoded,
            });
        }

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
        // Plus the phantom-safe predicate marker (`rmp` #171): a range / property scan registers the
        // conservative `Label` marker (any insert of this label matches), the documented coarse
        // over-approximation for a non-equality predicate — sound, at most a few extra aborts among
        // concurrent range-reader / label-writer pairs. This is the same coarse marker the
        // scan-fallback range filter (`scan_filter_range` over `scan_nodes_by_label`) registers.
        self.note_predicate_read(PredicateRead::Label(label_token));

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

    fn index_seek_spatial(
        &self,
        label: &str,
        property: &str,
        center_x: f64,
        center_y: f64,
        radius: f64,
    ) -> Option<Vec<NodeId>> {
        // Only the coordinated path has the derived `IndexSet` holding the grid spatial index;
        // otherwise the executor falls back to a label scan (`rmp` task #73).
        let index = self.index.as_ref()?;
        let label_token = self.label_id_existing(label)?;
        let prop_key = self.store.borrow().token_id(Namespace::PropKey, property)?;
        if !index.borrow().has_spatial(label_token, prop_key) {
            return None; // no usable spatial index: scan fallback
        }

        // SSI predicate footprint: an indexed proximity predicate replaces the label-scan + filter
        // fallback (which read every node via `scan_nodes_by_label`). Preserve that exact read
        // footprint so the index path and the scan fallback are indistinguishable to SSI (`04 §5.4`).
        self.mark_all_live_nodes();

        // Candidate ids whose point lies within the radius of the centre's 2D projection — a geometric
        // superset (the grid buckets by `(x, y)`). The caller's residual `distance(...) <op> r` filter
        // re-checks the exact predicate, CRS, current value, visibility, and current label per
        // candidate, so this need only narrow to nodes that currently carry the label.
        let candidates = index
            .borrow()
            .seek_spatial_within(label_token, prop_key, center_x, center_y, radius)
            .unwrap_or_default();
        let labelled = self.filter_label_candidates(label_token, candidates);

        let mut out = labelled;
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
        // Defer the per-property constraint check while building the node: a not-yet-set required
        // property or a soon-to-be-overwritten value must not trip a constraint mid-construction
        // (`rmp` task #99). A single check after every property is written is correct and complete.
        self.defer_constraint_check.set(true);
        for (k, v) in properties {
            self.set_node_property(node, k, v.clone());
        }
        self.defer_constraint_check.set(false);
        // Enforce constraints (`rmp` task #99) BEFORE indexing: a uniqueness / existence violation on
        // the freshly-created node is captured as a runtime error, which aborts the statement and
        // rolls the transaction back before commit (the captured-error channel). Only run when the
        // write so far is clean — a doomed write is already being rolled back.
        if !self.has_error() {
            self.enforce_constraints_for_node(node);
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
        // Relationship phantom (`rmp` #171 blocker A1): announce this new edge's rel-type predicate
        // footprint so a concurrent transaction that read `MATCH ()-[r:T]-()` (and saw no such edge)
        // closes an rw-edge into this create. The per-rel `note_write` above marks only the physical
        // id, which a predicate reader of the (previously absent) edge never SIREAD-marked.
        self.note_rel_predicate_write(type_id);
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
        // Read-then-update/clear write-skew (`rmp` #171 blocker B1): a `SET n.p = …` changes which
        // nodes satisfy `MATCH (n:Label {p: old})` (the old value's equality predicate, and on a
        // `SET n.p = null` removal the predicate the node previously matched). Announce the node's
        // PRE-image footprint before the store mutation so a concurrent reader of the *old* equality
        // predicate (who saw this node) closes an rw-edge. The follow-on `reindex_node` on the non-null
        // path additionally announces the NEW footprint (the new value's predicate), so both the
        // vacated and the newly-occupied predicates are covered.
        self.note_predicate_write_preimage(node);
        if value.is_null() {
            // `SET n.p = null` is a removal in Cypher: drop the key (and free any overflow chain it
            // owned) so a later read sees the property absent.
            if let Err(e) = self
                .store
                .borrow_mut()
                .remove_node_property_value(self.txn, node.0, key_id)
            {
                self.capture(e);
                return;
            }
            // A removal can only *relax* a uniqueness rule, but it **violates an existence (NOT NULL)
            // rule** if the node carries the constrained label (`rmp` task #99). Enforce after the
            // removal so the now-absent property is detected; the captured error aborts the statement
            // before commit. No reindex is needed on a removal (dropping a key never adds a candidate).
            // Suppressed while a multi-property write is mid-flight (the caller checks once at the end).
            if !self.defer_constraint_check.get() {
                self.enforce_constraints_for_node(node);
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
        // Enforce constraints on the now-current value (`rmp` task #99) before indexing: a `SET` that
        // makes the node's covered property duplicate another node's of the same label (uniqueness) is
        // captured as a runtime error, so the statement aborts and rolls back before commit. (The
        // `SET n.p = null` removal path above enforces existence separately.) Suppressed while a
        // multi-property write (CREATE / SET n = map) is mid-flight — the caller checks once at the end.
        if !self.defer_constraint_check.get() {
            self.enforce_constraints_for_node(node);
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
        // Adding a label can bring the node under a constraint declared on that label (`rmp` task
        // #99): a node that now carries a uniqueness-/existence-constrained label is checked against
        // its current value, so `SET n:Label` that would create a duplicate or expose a missing
        // required property is rejected before commit. Run only on a clean write.
        if !self.has_error() {
            self.enforce_constraints_for_node(node);
        }
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
        // Read-then-unlabel write-skew (`rmp` #171 blocker B1): `REMOVE n:Label` changes which nodes
        // satisfy a `MATCH (n:Label …)` predicate, so announce the node's PRE-image footprint (its
        // current labels + properties) before stripping the label. A concurrent reader of any of those
        // predicates that saw this node closes an rw-edge into this writer.
        self.note_predicate_write_preimage(node);
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
        // Read-then-clear write-skew (`rmp` #171 blocker B1): removing a property changes which nodes
        // satisfy `MATCH (n:Label {p: v})`, so announce the node's PRE-image (which still holds the
        // property `p: v`) before the removal. A concurrent reader of that equality predicate that saw
        // this node closes an rw-edge into this writer.
        self.note_predicate_write_preimage(node);
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
        // Read-then-replace write-skew (`rmp` #171 blocker B1): `SET n = map` clears every existing
        // property before re-setting, so announce the node's PRE-image footprint (its current
        // labels + properties) BEFORE the clear — once the chain is cleared the per-key
        // `set_node_property` pre-image reads below would no longer see the vacated values. A
        // concurrent reader of any predicate the node previously satisfied closes an rw-edge here.
        self.note_predicate_write_preimage(node);
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
        // Defer the per-property constraint check across the whole map replace, then check once on the
        // final state (`rmp` task #99) — a transient state where a required property is momentarily
        // absent (just cleared, not yet re-set) must not spuriously trip an existence check.
        self.defer_constraint_check.set(true);
        for (k, v) in properties {
            if !v.is_null() {
                self.set_node_property(node, k, v.clone());
            }
        }
        self.defer_constraint_check.set(false);
        if !self.has_error() {
            self.enforce_constraints_for_node(node);
        }
    }

    fn merge_node_properties(&mut self, node: NodeId, properties: &[(String, Value)]) {
        // `SET n += map` keeps unmentioned keys and overlays the map; for a non-null value this is
        // an append (newest-wins read), which the store supports. A null value would be a removal
        // (deferred); `set_node_property` signals that.
        if !self.node_exists(node) {
            return;
        }
        // Defer the per-property check across the overlay, then check once (`rmp` task #99): across
        // several keys an interim value could momentarily match another node, so a single final check
        // on the settled state is the correct granularity.
        self.defer_constraint_check.set(true);
        for (k, v) in properties {
            self.set_node_property(node, k, v.clone());
        }
        self.defer_constraint_check.set(false);
        if !self.has_error() {
            self.enforce_constraints_for_node(node);
        }
    }

    fn replace_rel_properties(&mut self, rel: RelId, properties: &[(String, Value)]) {
        // `SET r = map` replaces the whole property set: clear the existing relationship properties
        // (freeing any overflow chains), then set each non-null entry of the map. Mirrors
        // `replace_node_properties`; relationships carry no constraints, so no deferred check.
        if !self.rel_exists(rel) {
            return;
        }
        if let Err(e) = self
            .store
            .borrow_mut()
            .clear_rel_properties(self.txn, rel.0)
        {
            self.capture(e);
            return;
        }
        for (k, v) in properties {
            if !v.is_null() {
                self.set_rel_property(rel, k, v.clone());
            }
        }
    }

    fn merge_rel_properties(&mut self, rel: RelId, properties: &[(String, Value)]) {
        // `SET r += map` keeps unmentioned keys and overlays the map; a null value removes that key.
        // `set_rel_property` already implements both (null = removal).
        if !self.rel_exists(rel) {
            return;
        }
        for (k, v) in properties {
            self.set_rel_property(rel, k, v.clone());
        }
    }

    fn incident_rels(&self, node: NodeId) -> Vec<RelId> {
        // The store walks the physical incidence chain, which still threads MVCC-tombstoned
        // relationships (their slot stays in use until vacuum). Filter to those visible to this
        // transaction so a deleted relationship is not reported as incident — otherwise a node's
        // DETACH check, the result-egress snapshot, and any degree-style read would observe a
        // relationship this transaction has already removed (or that another transaction deleted).
        let ids = match self.store.borrow_mut().incident_rels(node.0) {
            Ok(rels) => rels,
            Err(e) => {
                self.capture(e);
                return Vec::new();
            }
        };
        ids.into_iter()
            .filter(|&rid| {
                let mvcc = match self.store.borrow_mut().rel(rid) {
                    Ok(rec) => rec.mvcc,
                    Err(e) => {
                        self.capture(e);
                        return false;
                    }
                };
                self.note_read(rel_ssi_key(rid));
                self.visible(mvcc)
            })
            .map(RelId)
            .collect()
    }

    fn delete_rel(&mut self, rel: RelId) {
        // Idempotent: a relationship not visible to this query (already gone, deleted by us earlier,
        // or never created) is a no-op, not an error — matching the `MemGraph` contract. Visibility
        // (not raw `in_use`) is the right guard now that delete is an MVCC tombstone (the slot stays
        // in use): a second delete in the same transaction sees its own tombstone and does nothing.
        let (mvcc, type_id) = match self.store.borrow_mut().rel(rel.0) {
            Ok(r) => (r.mvcc, r.type_id),
            Err(_) => return,
        };
        if !self.visible(mvcc) {
            return;
        }
        self.note_write(rel_ssi_key(rel.0));
        // Read-then-delete relationship write-skew (`rmp` #171 blocker A1): a concurrent reader of
        // `MATCH ()-[r:T]-()` that SAW this edge must close an rw-edge into this delete. Announce the
        // edge's rel-type predicate footprint (its pre-image type), symmetric to `create_rel`.
        self.note_rel_predicate_write(type_id);
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
        // Read-then-delete write-skew (`rmp` #171 blocker B1): announce the node's PRE-image predicate
        // footprint before removing it, so a concurrent transaction that read a predicate this node
        // satisfied (and saw it present) closes an rw-edge into this delete. Must run before the store
        // mutation while the pre-image is still readable.
        self.note_predicate_write_preimage(node);
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
