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
use graphus_index::keycodec::{encode_equality_canonical, encode_single};
use graphus_index::kinds::DEFAULT_HISTOGRAM_BUCKETS;
use graphus_io::BlockDevice;
use graphus_storage::{ConstraintKind, MvccHeader, Namespace, RecordStore};
use graphus_txn::{
    CommitRegistry, LockOutcome, LockTable, PredicateRead, Snapshot, SsiReadBuffer, SsiTracker,
    is_visible,
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

/// Holds this statement's [`SsiReadBuffer`] and merges it into the shared [`SsiTracker`] at the
/// **single-writer merge point** (`rmp` #341).
///
/// Every read seam (`note_read` / `note_predicate_read`) **appends** a SIREAD marker to this buffer
/// rather than recording it into the shared tracker directly — the universal path, single-threaded
/// and (later) off-thread alike. The accumulated markers are merged back in exactly once, through
/// [`SsiTracker::merge_read_buffer`] (which sorts+dedups them so the conflict graph is a
/// deterministic function of the read *set*, byte-identical to recording each marker inline).
///
/// ## When the merge happens (the M1 barrier)
///
/// - **Universal single-threaded path (#341):** the guard's [`Drop`] runs when the per-statement
///   [`RecordStoreGraph`] seam is dropped (statement-end). Because the engine dispatches commands
///   serially, no other transaction's `record_write` / `detect_pivot_abort` can run between a
///   marker's append and this drop, so the merge is timing-equivalent to inline recording. The seam
///   is always dropped before the coordinator runs the next command (COMMIT, or the next statement),
///   so a partner's commit-time detection always observes this reader's markers — rule M1.
/// - **Off-thread reader pool (#336, Slice 3):** the coordinator will instead call
///   [`flush_read_buffer`](RecordStoreGraph::flush_read_buffer) (or take the buffer via
///   [`take_read_buffer`](Self::take)) when the reader thread retires, merging on the coordinator
///   thread with the happens-before the retirement channel establishes. After a take/flush the
///   buffer is empty, so the `Drop` merge is a no-op — the two delivery routes never double-apply.
///
/// The guard owns a **clone of the `Rc<RefCell<SsiTracker>>`** (single-threaded; the tracker is only
/// ever touched on the coordinator thread) so the merge does not depend on the rest of the seam, and
/// so a *partial move* of the seam's `store` (in `commit`/`rollback`/`into_store`) still drops the
/// guard normally and performs the merge. On the standalone path (`ssi: None`) there is nothing to
/// merge and every method is a cheap no-op (the buffer stays empty — `note_*` skip the append).
struct ReadBufferGuard {
    /// The shared tracker to merge into, or `None` on the standalone (un-coordinated) path.
    ssi: Option<Rc<RefCell<SsiTracker>>>,
    /// This statement's accumulated SIREAD markers. `None` once taken for off-thread delivery
    /// (`rmp` #336); `Some(empty)` after an explicit flush. `RefCell` because the read seams append
    /// through `&self`.
    buffer: RefCell<Option<SsiReadBuffer>>,
}

impl ReadBufferGuard {
    /// A guard for transaction `txn`, merging into `ssi` (or a no-op guard when `ssi` is `None`).
    fn new(txn: TxnId, ssi: Option<Rc<RefCell<SsiTracker>>>) -> Self {
        Self {
            ssi,
            buffer: RefCell::new(Some(SsiReadBuffer::new(txn))),
        }
    }

    /// Appends a physical-key SIREAD marker. A no-op on the standalone path (no tracker to merge to),
    /// matching the pre-#341 behaviour where `note_read` did nothing without a coordinator.
    fn record_read(&self, key: u64) {
        if self.ssi.is_some()
            && let Some(buf) = self.buffer.borrow_mut().as_mut()
        {
            buf.record_read(key);
        }
    }

    /// Appends a predicate SIREAD marker. A no-op on the standalone path.
    fn record_predicate_read(&self, predicate: PredicateRead) {
        if self.ssi.is_some()
            && let Some(buf) = self.buffer.borrow_mut().as_mut()
        {
            buf.record_predicate_read(predicate);
        }
    }

    /// Merges the accumulated markers into the shared tracker **now**, leaving the buffer empty so a
    /// later `Drop` (or flush) does not re-apply them. Idempotent. The well-factored merge point
    /// Slice 3's reader-pool retirement will call from the coordinator thread.
    fn flush(&self) {
        let Some(ssi) = &self.ssi else {
            return; // standalone path: nothing to merge.
        };
        // Take the markers out (replacing with an empty buffer for the same txn) so the merge runs
        // exactly once even if `flush` is called again or the `Drop` runs afterwards.
        let drained = {
            let mut slot = self.buffer.borrow_mut();
            match slot.as_mut() {
                Some(buf) if !buf.is_empty() => {
                    let reader = buf.reader();
                    Some(std::mem::replace(buf, SsiReadBuffer::new(reader)))
                }
                _ => None,
            }
        };
        if let Some(buf) = drained {
            ssi.borrow_mut().merge_read_buffer(buf);
        }
    }

    /// Removes the buffer for **off-thread delivery** (`rmp` #336, Slice 3): the reader thread hands
    /// the owned buffer back to the coordinator, which merges it with the retirement channel's
    /// happens-before. After this the `Drop` merge is a no-op. `None` if already taken/flushed empty.
    /// Surfaced on the seam through
    /// [`RecordStoreGraph::take_read_buffer`](RecordStoreGraph::take_read_buffer).
    fn take(&self) -> Option<SsiReadBuffer> {
        self.buffer.borrow_mut().take()
    }
}

impl Drop for ReadBufferGuard {
    fn drop(&mut self) {
        // The universal single-threaded merge point: drain at statement-end (seam drop). A no-op on
        // the standalone path, after an explicit `flush`, or after the buffer was `take`n for
        // off-thread delivery.
        self.flush();
    }
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
use crate::read_source::{self, LiveSource, ReadSink, VisCtx};
use crate::snapshot::{GraphSnapshot, SnapshotSpec};

/// The result of the single authoritative columnar candidate pass
/// ([`columnar_label_pass`](RecordStoreGraph::columnar_label_pass)): every visible label-carrying
/// node id and the subset whose property is present. Shared by the serial columnar scan and the
/// parallel-read snapshot projection so they register byte-identical SSI markers (`rmp` task #352).
#[derive(Debug, Default)]
struct ColumnarPass {
    /// Every visible node carrying the label, in candidate order (the exact `count(*)` support).
    members: Vec<NodeId>,
    /// The `(node, value)` rows whose property is present (a subset of `members`).
    rows: Vec<(NodeId, Value)>,
}

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
    /// This statement's deferred SIREAD-marker buffer + its merge-on-drop guard (`rmp` #341). Reads
    /// (`note_read`/`note_predicate_read`) **append** their markers here instead of recording them
    /// into the shared `ssi` tracker inline; the markers are merged back — sorted+deduped, so
    /// byte-identically to inline recording — when this seam is dropped (statement-end, the M1
    /// barrier) or when the coordinator explicitly drains it (the off-thread path, `rmp` #336). On
    /// the standalone path it holds no tracker and every append is a no-op, so reads stay marker-free
    /// exactly as before. See [`ReadBufferGuard`].
    read_buffer: ReadBufferGuard,
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
    /// The coordinator's derived **columnar value cache** (`rmp` tasks #329 / #330), present **only**
    /// on the coordinated path ([`attach`](Self::attach)). When `Some` and a declared column covers
    /// `(label, property)`, [`columnar_label_property_scan`](GraphAccess::columnar_label_property_scan)
    /// answers an analytical property scan from the contiguous column, **re-validating** each cached
    /// value against the node's current MVCC header (xmin/tombstone witnesses) and falling back to the
    /// authoritative single-property read on any mismatch. Like the [`IndexSet`] it is derived,
    /// in-memory and candidate-class, so it is never committed or recovered; unlike the index it caches
    /// the *value* (not just a candidate id), so its read-time re-check is what guarantees the
    /// accelerator can never return a wrong row. `None` on the standalone path (every analytical scan
    /// then uses the row path).
    columns: Option<Rc<RefCell<crate::column_cache::ColumnCache>>>,
    /// The shared derived **zone-map data-skipping sidecar** (`rmp` task #331), present only on the
    /// coordinated path. Maintained (widening) on write by [`reindex_node`](Self::reindex_node); the
    /// skip decision it drives is conservative, so it never changes which rows a scan returns.
    zones: Option<Rc<RefCell<crate::zone_map::ZoneMap>>>,
    /// The coordinator's **opt-in** type-bucketed CSR adjacency accelerator (`rmp` task #324, "Win 2"),
    /// present only on the coordinated path **and** only when the
    /// [`csr_adjacency_enabled`](crate::read_source::csr_adjacency_enabled) knob is on. When `Some` and
    /// **fresh**, a typed [`expand`](GraphAccess::expand) seeks matching-type candidate rel-ids from it
    /// (so it touches no non-matching incidence-chain link) and re-checks each, instead of the Win-1
    /// chain walk; the result and SSI markers are identical (the candidates are a re-checked superset).
    /// It is **marked stale** on the first relationship mutation ([`create_rel`](GraphAccess::create_rel)
    /// / [`delete_rel`](GraphAccess::delete_rel)) and then declines (`candidates` returns `None`), so the
    /// chain walk — always store-faithful — takes over until the next rebuild-on-open. `None` on the
    /// standalone path or when the knob is off (zero extra RAM).
    csr: Option<Rc<RefCell<crate::csr_adjacency::CsrAdjacency>>>,
}

impl<D: BlockDevice + Send + Sync + 'static, S: LogSink + Send + Sync + 'static>
    RecordStoreGraph<D, S>
{
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
            // Standalone path: no coordinator ⇒ no tracker to merge into; the guard's appends are
            // no-ops, so reads register no SIREAD markers exactly as before (`rmp` #341).
            read_buffer: ReadBufferGuard::new(txn, None),
            locks: None,
            error: RefCell::new(None),
            // Standalone path: no coordinator, so no derived index; every access falls back to a
            // full scan (`rmp` task #48). This keeps the standalone `record_store_graph.rs` path
            // behaviour byte-for-byte unchanged.
            index: None,
            defer_constraint_check: std::cell::Cell::new(false),
            // Standalone path: no derived columnar cache, so an analytical scan uses the row path
            // (`rmp` #329). The cache lives in the coordinator.
            columns: None,
            // Standalone path: no zone-map sidecar (it lives in the coordinator); scans skip nothing.
            zones: None,
            // Standalone path: no CSR accelerator (it lives in the coordinator); typed expand always
            // walks the live chain (`rmp` #324).
            csr: None,
        }
    }

    /// Attaches a per-statement seam to an **already-open** transaction `txn` driven by a
    /// [`TxnCoordinator`](crate::coordinator::TxnCoordinator) (`rmp` task #46): the coordinator owns
    /// the shared `store`, has already called `store.begin(txn)`, holds `txn`'s `snapshot`, and
    /// passes the shared `ssi` tracker so this statement's reads/writes contribute SIREAD markers and
    /// rw-edges. Unlike [`begin`](Self::begin) it does **not** begin a transaction and must not be
    /// committed/rolled back through this handle — the coordinator owns that lifecycle.
    // Eight shared handles wired from the coordinator (store, txn, snapshot, ssi, locks, index,
    // columns, zones) — an internal constructor where threading a struct would only obscure the seam.
    #[allow(clippy::too_many_arguments)]
    pub fn attach(
        store: Rc<RefCell<RecordStore<D, S>>>,
        txn: TxnId,
        snapshot: Snapshot,
        ssi: Rc<RefCell<SsiTracker>>,
        locks: Rc<RefCell<LockTable>>,
        index: Rc<RefCell<IndexSet>>,
        columns: Rc<RefCell<crate::column_cache::ColumnCache>>,
        zones: Rc<RefCell<crate::zone_map::ZoneMap>>,
        csr: Option<Rc<RefCell<crate::csr_adjacency::CsrAdjacency>>>,
    ) -> Self {
        // Snapshot the shared store's Active/Recent Transaction Table for this statement's reads
        // (`rmp` task #49). Cloning at attach is consistent with snapshot isolation: a transaction
        // that commits later is excluded by the `ts` filter regardless, and this statement's own
        // in-flight writes resolve via the owner rule.
        let registry = store.borrow().commit_registry().clone();
        // The deferred-read buffer merges into the same shared tracker; clone the `Rc` for the guard
        // before `ssi` is moved into the field (`rmp` #341).
        let read_buffer = ReadBufferGuard::new(txn, Some(Rc::clone(&ssi)));
        Self {
            store,
            txn,
            snapshot,
            registry,
            ssi: Some(ssi),
            read_buffer,
            locks: Some(locks),
            error: RefCell::new(None),
            // Coordinated path: the shared derived index is present, so label scans and node-property
            // predicates seek candidates from it and re-check them here (`rmp` task #48).
            index: Some(index),
            defer_constraint_check: std::cell::Cell::new(false),
            // Coordinated path: the shared derived columnar cache is present, so an analytical
            // property scan can read from the contiguous column with a per-node re-check (`rmp` #329).
            columns: Some(columns),
            // Coordinated path: the shared zone-map sidecar is present and maintained on write (`rmp` #331).
            zones: Some(zones),
            // Coordinated path: the opt-in CSR accelerator is present only when the knob enabled it at
            // coordinator construction (`rmp` #324, Win 2); `None` otherwise (zero extra RAM).
            csr,
        }
    }

    /// Records a non-blocking SIREAD marker for `key` under this transaction, if it is coordinated
    /// (`04 §5.4`); a no-op in the standalone path. Reads never block (NFR-4).
    ///
    /// The marker is **buffered** in this statement's [`ReadBufferGuard`] (the universal path,
    /// `rmp` #341) rather than recorded into the shared [`SsiTracker`] inline; it is merged
    /// (sorted/deduped, byte-identically to inline recording) at statement-end (the M1 barrier),
    /// which lets the read run off-thread (`rmp` #336) without taking a lock on the shared tracker.
    fn note_read(&self, key: u64) {
        self.read_buffer.record_read(key);
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
        self.read_buffer.record_predicate_read(predicate);
    }

    /// Merges this statement's buffered SIREAD markers into the shared [`SsiTracker`] **now** (`rmp`
    /// #341), the well-factored single-writer merge point. Idempotent and a no-op on the standalone
    /// path; after it runs the seam's drop will not re-merge.
    ///
    /// The universal single-threaded path relies on the seam's drop to merge at statement-end, so
    /// callers do **not** normally invoke this. It exists so the off-thread reader pool (`rmp` #336,
    /// Slice 3) can drain a retired reader's buffer **on the coordinator thread** — the merge must
    /// run where the tracker lives, never on the reader thread — keeping the merge point a single,
    /// reused function for both delivery routes.
    pub fn flush_read_buffer(&self) {
        self.read_buffer.flush();
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
        // Read the node's *current* labels (store borrow released before announcing). Read-only:
        // `node_labels` is `&self` (`rmp` #337 Slice 2), so a shared borrow suffices.
        let label_tokens: Vec<u32> = {
            let store = self.store.borrow();
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
            // Standalone snapshot path: no coordinator ⇒ no tracker; the guard's appends are no-ops
            // (reads register no SIREAD markers, exactly as before — `rmp` #341).
            read_buffer: ReadBufferGuard::new(txn, None),
            locks: None,
            error: RefCell::new(None),
            // Standalone snapshot path: no derived index (the index lives in the coordinator).
            index: None,
            defer_constraint_check: std::cell::Cell::new(false),
            // Standalone snapshot path: no derived columnar cache (it lives in the coordinator).
            columns: None,
            // Standalone snapshot path: no zone-map sidecar (it lives in the coordinator).
            zones: None,
            // Standalone snapshot path: no CSR accelerator (it lives in the coordinator).
            csr: None,
        }
    }

    /// Latches the opt-in CSR accelerator stale (`rmp` task #324, "Win 2"), if present. A no-op when the
    /// knob is off / standalone (`csr` is `None`). Called from `create_rel` / `delete_rel`: any
    /// relationship mutation invalidates the built incidence snapshot, so subsequent typed expands fall
    /// back to the always-faithful chain walk until the next rebuild-on-open.
    fn mark_csr_dirty(&self) {
        if let Some(csr) = &self.csr {
            csr.borrow_mut().mark_dirty();
        }
    }

    /// Seeks the matching-type CSR candidate rel-ids for a typed expand of `node` over `types`, or
    /// `None` when the chain walk must be used (`rmp` task #324, "Win 2").
    ///
    /// Returns `None` (⇒ Win-1 chain walk) when **any** of:
    ///   * the CSR is absent (knob off / standalone path) — zero-RAM default;
    ///   * the expand is **untyped** (`types` empty) — no type bucket to seek;
    ///   * the CSR is **stale** (a relationship mutation since the last build) — handled inside
    ///     [`CsrAdjacency::candidates`](crate::csr_adjacency::CsrAdjacency::candidates);
    ///   * any requested type name is **un-interned** — a never-interned type matches no existing edge,
    ///     so the chain-walk path's existing un-interned short-circuit (which also covers the absent-edge
    ///     phantom) must run; we therefore decline to the chain walk rather than seeking a partial set.
    ///
    /// When it returns `Some(ids)`, the ids are matching-type candidates (re-checked by the lifted
    /// body). Token resolution mirrors `read_source::expand`'s own `wanted_type_ids` resolution exactly,
    /// so the CSR seek covers the identical requested-type set; the difference is purely that the body
    /// reads the CSR's candidates rather than walking the chain.
    fn csr_candidates_for(&self, node: NodeId, types: &[String]) -> Option<Vec<u64>> {
        let csr = self.csr.as_ref()?;
        if types.is_empty() {
            return None;
        }
        // Resolve every requested type name to its interned id. If ANY name is un-interned we decline
        // to the chain walk (see the doc): a read never mints a token.
        let mut wanted: Vec<u32> = Vec::with_capacity(types.len());
        {
            let store = self.store.borrow();
            for t in types {
                wanted.push(store.token_id(Namespace::RelType, t)?);
            }
        }
        // `candidates` returns `None` if the CSR is stale (the freshness gate); else the matching-type
        // candidate ids for this node.
        csr.borrow().candidates(node.0, &wanted)
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

    /// This statement's visibility context (snapshot + registry + txn) for the shared lifted read body
    /// (`rmp` task #336, Slice 3b-i). The read methods pass this and a [`LiveSource`] over the live
    /// store to [`crate::read_source`], so they run the **same** code the off-thread
    /// [`ReadOnlyGraph`](crate::read_only_graph::ReadOnlyGraph) runs — preserving exact behaviour.
    #[inline]
    fn vis_ctx(&self) -> VisCtx<'_> {
        VisCtx {
            snapshot: self.snapshot,
            registry: &self.registry,
            txn: self.txn,
        }
    }

    /// Removes this statement's accumulated SIREAD-marker buffer for **off-thread delivery** (`rmp` task
    /// #336): the reader hands the owned buffer back to the coordinator, which merges it on the engine
    /// thread (the merge must run where the shared tracker lives). After this the seam's drop merge is a
    /// no-op. `None` if there is no buffer to take (already taken, or flushed empty). This is the
    /// symmetric counterpart to [`ReadOnlyGraph::take_buffer`](crate::read_only_graph::ReadOnlyGraph::take_buffer);
    /// in the single-threaded path the drop-merge is used instead, so this is currently exercised only by
    /// the Slice 3b-i equivalence test.
    pub fn take_read_buffer(&self) -> Option<SsiReadBuffer> {
        self.read_buffer.take()
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

    /// Reads a **single** property `key` of `node` (newest-visible-wins) WITHOUT materializing,
    /// name-mapping or sorting the node's whole property set (`rmp` #326 — late materialization).
    ///
    /// The previous path (`read_node_props(node).find(k == key)`) decoded **every** property value
    /// of the node (including overflow-heap walks for strings/lists), allocated a `Vec<(String,
    /// Value)>`, mapped every key id back to a name and sorted it — all to keep one value. On an
    /// analytical scan that touches one property over millions of rows (the measured `top_liked`
    /// hot path) that amplification dominates. This probe instead resolves the key name to its
    /// interned id once, then returns the **first visible** record of that id from the prepend-
    /// ordered (newest-first) chain — decoding exactly one value. A key name that was never interned
    /// cannot occur on any record, so it short-circuits to `None`. Result is identical to the old
    /// `find` (the first visible record of a key id is its newest visible version).
    fn read_node_prop_one(&self, node: NodeId, key: &str) -> Option<Value> {
        // Read-only store access: `rmp` #337 Slice 2 made every read method (`token_id`,
        // `node_properties`, `decode_property_value`) take `&self`, so a shared borrow suffices.
        let store = self.store.borrow();
        let key_id = store.token_id(Namespace::PropKey, key)?;
        let chain = match store.node_properties(node.0) {
            Ok(chain) => chain,
            Err(e) => {
                drop(store);
                self.capture(e);
                return None;
            }
        };
        for (_pid, prop) in chain {
            if prop.key != key_id || !self.visible(prop.mvcc) {
                continue;
            }
            return match store.decode_property_value(prop.type_tag, prop.value_inline) {
                Ok(value) => Some(value),
                Err(e) => {
                    drop(store);
                    self.capture(e);
                    None
                }
            };
        }
        None
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
        // Read-only store access (`rmp` #337 Slice 2): `&self` read methods, shared borrow.
        let store = self.store.borrow();
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
        // Read-only store access (`rmp` #337 Slice 2): `scan_node_ids` is `&self`, shared borrow.
        let store = self.store.borrow();
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
        // Read-only store access (`rmp` #337 Slice 2): `node` / `node_has_label` are `&self`.
        let store = self.store.borrow();
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
        // Read-only: `node_labels` is `&self` (`rmp` #337 Slice 2), so a shared borrow suffices.
        let label_tokens: Vec<u32> = {
            let store = self.store.borrow();
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

        // Bitmap (low-cardinality) indexes are maintained membership-EXACT the same wholesale way
        // (`rmp` task #328): unlike the read-only columnar cache, a bitmap is a candidate SOURCE, so a
        // node it wrongly OMITS would make a query miss a row (a subset — never correct). For each
        // registered bitmap `(label_token, prop_key)`, first remove this node from every value-bitmap
        // of the column (drop any prior value's bit), then if the node currently carries the covered
        // label AND holds an indexable value of the key, set its bit under that value. A node that
        // lost the label or the property ends up in no bitmap, so a seek never returns a phantom.
        //
        // Record the node as bitmap-dirty for this txn FIRST (`rmp` #453, F-IDX-3), before mutating the
        // bitmap, so that even a panic struck mid-reindex (between the remove and the reinsert) leaves
        // the node marked for the abort path to re-derive from the reverted store. A no-op unless a
        // bitmap index is declared.
        index.note_bitmap_dirty(self.txn, node.0);
        for (label_token, prop_key) in index.registered_bitmap() {
            index.remove_bitmap_node(label_token, prop_key, node.0);
            if label_tokens.contains(&label_token) {
                if let Some((_, value)) = resolved_props.iter().find(|(k, _)| *k == prop_key) {
                    index.insert_bitmap_value(label_token, prop_key, value, node.0);
                }
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
        drop(index);

        // Zone-map data-skipping sidecar (`rmp` task #331): widen the node's zone for each declared
        // `(label, property)` it carries. Widening-only — a removal/overwrite leaves the interval
        // over-wide, which only reduces skipping (never wrongly skips), so no removal hook is needed
        // (the scan's per-row re-check drops a since-changed value). A no-op when nothing is declared.
        if let Some(zones) = &self.zones {
            let mut zones = zones.borrow_mut();
            for (label_token, prop_key) in zones.declared() {
                if label_tokens.contains(&label_token) {
                    if let Some((_, value)) = resolved_props.iter().find(|(k, _)| *k == prop_key) {
                        zones.record(label_token, prop_key, node.0, value);
                    }
                }
            }
        }
    }

    /// Maintains **only** the bitmap (low-cardinality) indexes (`rmp` task #328) for `node` from its
    /// current labels + property values, used by the removal paths (`REMOVE n.p`, `REMOVE n:Label`)
    /// that deliberately skip the full [`reindex_node`](Self::reindex_node) (the other index kinds
    /// tolerate the resulting stale candidate, dropped by the seek's re-check — see `set_node_property`).
    ///
    /// The bitmap, by contrast, is exposed as a **direct** candidate source (it is intersected for
    /// multi-predicate AND), so it is kept membership-exact even across removals: the node is dropped
    /// from every value-bitmap of each registered column and re-inserted only under its current value
    /// (or left out if it lost the label / property). This is O(distinct) per column — cheap, because
    /// the column is low-cardinality by construction. A no-op on the standalone path or when no bitmap
    /// index is declared.
    fn reindex_node_bitmaps(&self, node: NodeId) {
        let Some(index) = &self.index else {
            return;
        };
        if index.borrow().registered_bitmap().is_empty() {
            return; // nothing declared — avoid the label/property reads entirely.
        }
        // Read the node's current labels + property values (store borrows released before the index
        // borrow), mirroring `reindex_node`. Read-only: `node_labels` is `&self` (`rmp` #337 Slice 2).
        let label_tokens: Vec<u32> = match self.store.borrow().node_labels(node.0) {
            Ok(ids) => ids,
            Err(_) => return,
        };
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
        let mut index = index.borrow_mut();
        // Record the node as bitmap-dirty for this txn before mutating (`rmp` #453, F-IDX-3 — same
        // rationale as `reindex_node`: an abort/panic must be able to re-derive it from the store).
        index.note_bitmap_dirty(self.txn, node.0);
        for (label_token, prop_key) in index.registered_bitmap() {
            index.remove_bitmap_node(label_token, prop_key, node.0);
            if label_tokens.contains(&label_token) {
                if let Some((_, value)) = resolved_props.iter().find(|(k, _)| *k == prop_key) {
                    index.insert_bitmap_value(label_token, prop_key, value, node.0);
                }
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
        // Read-only: `node_labels` is `&self` (`rmp` #337 Slice 2), so a shared borrow suffices.
        let label_tokens: Vec<u32> = {
            let store = self.store.borrow();
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
        //
        // The `mark_all_live_nodes` physical-key SIREADs alone are INSUFFICIENT for the node-key
        // *absence* phantom (`rmp` #401): two concurrent CREATEs of a brand-new tuple with no
        // existing holder each see an empty candidate set — neither node is in the other's live-set,
        // so no physical-key rw-edge forms, and both commit a duplicate node-key. The label-scan
        // fallback (`scan_nodes_by_label`) closes this hole by registering `PredicateRead::Label`,
        // which pairs with every node insert's `note_predicate_write` `Label(L)` write footprint
        // (`reindex_node`); the composite-index seek bypasses that fallback, so it must register the
        // same coarse `Label` predicate read here. A coarse `Label` (rather than a precise composite
        // `Equality` variant) is sound — it only adds an rw-edge between concurrent same-label
        // writers, exactly as the scan fallback already did. (The single-property `IS UNIQUE` path
        // `index_seek_eq` is unaffected: it registers a precise `Equality` predicate read, `rmp`
        // #316, which already pairs with the writer's single-prop `Equality` write footprint.)
        self.note_predicate_read(PredicateRead::Label(rule.label_token));
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

    /// The **complementary columnar** answer to an analytical property scan over `(label, property)`
    /// (`rmp` tasks #329 / #330): the `(node, value)` pairs the row path would produce
    /// (`scan_nodes_by_label` filtered to the nodes whose `property` is present), read from the
    /// contiguous columnar cache where it is fresh and from the authoritative row read otherwise.
    /// `None` when no declared column covers the pair (the caller uses the row path).
    ///
    /// # Why this is exactly the row-path result (the soundness contract)
    ///
    /// The scan is **driven off the authoritative current label-candidate set** — the very same
    /// candidates [`scan_nodes_by_label`](GraphAccess::scan_nodes_by_label) uses — so it is **complete**:
    /// a node that gained the label/property *after* the cache was built (hence absent from the cached
    /// column) is still a candidate and gets the row read. The columnar cache only **accelerates the
    /// value read** for a candidate, never decides membership. For each candidate:
    ///
    /// 1. The node's current MVCC header is read (one O(1) record read) and the node is dropped if it
    ///    is invisible to this snapshot — identical to [`filter_label_candidates`](Self::filter_label_candidates).
    /// 2. The same per-candidate SIREAD ([`note_read`](Self::note_read)) is recorded, visible or not —
    ///    so the SSI read footprint is **byte-for-byte** the row scan's (serializability unchanged).
    /// 3. The node must currently carry `label` (`node_has_label`), exactly as the row label scan
    ///    requires.
    /// 4. The value is taken from the cache **iff** the two staleness witnesses still hold (the node's
    ///    `first_prop` chain head is unchanged ⇒ no prepend since rebuild ⇒ the cached `PropRecord` is
    ///    still the newest version of its key, **and** that `PropRecord` re-read by id is still visible
    ///    and the right key ⇒ not tombstoned). Otherwise the value is read by the authoritative
    ///    [`read_node_prop_one`](Self::read_node_prop_one) — which is what the row scan would have done
    ///    for *every* node. A node whose current value is absent contributes no row, exactly as the row
    ///    path filters a null/missing property.
    ///
    /// So the cache can be arbitrarily stale and the result is still **identical** to the row scan; it
    /// is a pure accelerator. The predicate markers ([`note_predicate_read`](Self::note_predicate_read)
    /// `Label` + [`mark_all_live_nodes`](Self::mark_all_live_nodes)) are registered exactly as
    /// `scan_nodes_by_label` registers them, so a concurrent phantom closes the same rw-edge.
    fn columnar_scan_checked(
        &self,
        label: &str,
        property: &str,
    ) -> Option<crate::graph_access::ColumnarScan> {
        // The full candidate pass (members + present rows) registers the identical SSI predicate +
        // per-node markers; `ColumnarScan` is just the projection the seam exposes (`rmp` #329/#330).
        let scan = self.columnar_label_pass(label, property)?;
        Some(crate::graph_access::ColumnarScan {
            rows: scan.rows,
            label_matches: scan.members.len(),
        })
    }

    /// The single authoritative candidate pass shared by the columnar scan
    /// ([`columnar_scan_checked`](Self::columnar_scan_checked)) and the parallel-read snapshot
    /// projection ([`project_snapshot`](GraphAccess::project_snapshot), `rmp` task #352): it returns
    /// **both** the full set of visible `label`-carrying node ids (`members`, the exact `count(*)`
    /// support) **and** the `(node, value)` rows whose `property` is present (`rows`), computed in one
    /// pass over the authoritative live candidate set.
    ///
    /// Factoring this out is what lets the parallel aggregation reuse the **identical** SSI/predicate
    /// read-marker registration the serial columnar scan performs (`PredicateRead::Label` +
    /// [`mark_all_live_nodes`](Self::mark_all_live_nodes) + the per-candidate
    /// [`note_read`](Self::note_read), all below) — the markers are recorded here, on the engine
    /// thread, **before** the owned snapshot is handed to rayon, so serializability is byte-for-byte
    /// what the row scan would produce regardless of which read path the executor chose. `None` when no
    /// declared column covers the pair, exactly as the columnar scan declines (the caller then uses the
    /// row path); see the long soundness note on [`columnar_scan_checked`](Self::columnar_scan_checked)
    /// for why the per-value re-validation makes the result identical to a row scan-and-filter.
    fn columnar_label_pass(&self, label: &str, property: &str) -> Option<ColumnarPass> {
        // Only the coordinated path has a columnar cache; the standalone path declines (row scan).
        let columns = self.columns.as_ref()?;
        // Resolve the label + property tokens WITHOUT interning (a read must not mint a token). A
        // never-interned label/property can have no live matching node, but a *concurrent* writer
        // could create the first one — so registering the conservative predicate markers below (as
        // `scan_nodes_by_label` does) is what keeps that phantom serializable; here we simply decline
        // acceleration (return `None`) so the caller's row scan handles the empty/edge case verbatim.
        let label_token = self.label_id_existing(label)?;
        let prop_key = self.store.borrow().token_id(Namespace::PropKey, property)?;
        // Only an explicitly declared column is accelerated; everything else uses the row path.
        if !columns.borrow().is_declared(label_token, prop_key) {
            return None;
        }

        // --- SSI predicate footprint: identical to `scan_nodes_by_label` (`rmp` #171 / #46) ---
        // `MATCH (n:Label)` is a predicate read over which nodes carry the label, so a concurrent
        // insert/relabel is a phantom that must close an rw-edge even if the scan returns nothing; and
        // the per-node SIREADs below only cover existing nodes, so the coarse all-live-nodes marker is
        // kept. The columnar path narrows neither the membership nor the read footprint.
        self.note_predicate_read(PredicateRead::Label(label_token));
        self.mark_all_live_nodes();

        // --- the authoritative current candidate set (same source `scan_nodes_by_label` uses) ---
        let candidates: Vec<u64> = if let Some(index) = &self.index {
            index.borrow_mut().seek_label(label_token)
        } else {
            // No index (should not happen on the coordinated path, but stay correct): full id scan.
            // Read-only: `scan_node_ids` is `&self` (`rmp` #337 Slice 2), shared borrow.
            match self.store.borrow().scan_node_ids() {
                Ok(ids) => ids,
                Err(e) => {
                    self.capture(e);
                    return Some(ColumnarPass::default());
                }
            }
        };

        // --- the cached column, accessed by a memoized O(1) node_id -> row-index map ---
        // (`rmp` task #375 (c)) The decode (`Rc<DecodedColumn>`) and the `id -> index` map are both
        // **memoized on the column** and shared here by `Rc`, so a repeated scan of an un-mutated
        // column re-uses them instead of decoding the whole column and rebuilding an O(n) `HashMap`
        // on every query (which is what this hot path used to do). The contiguous `values` are
        // borrowed from the shared decode; a fresh hit **clones** the one served `Value` (a short,
        // low-cardinality `String` for the analytical hot columns) — strictly less work than the row
        // path, which also walks the `strings.store` overflow heap (`rmp` #329/#330). Late
        // materialization: a candidate that is invisible / mislabelled / stale never touches `values`,
        // so no value it would discard is ever cloned.
        let snapshot = columns.borrow().snapshot(label_token, prop_key);
        // `(decode, id->index, witnesses)` of the cached column, or empty views when uncached.
        let (cached_decoded, cached_index, cached_witnesses): (
            std::rc::Rc<crate::column_cache::DecodedColumn>,
            std::rc::Rc<std::collections::HashMap<u64, usize>>,
            Vec<crate::column_cache::ColumnWitness>,
        ) = match snapshot {
            Some(snap) => (snap.decoded, snap.index_map, snap.witnesses),
            None => (
                std::rc::Rc::new(crate::column_cache::DecodedColumn {
                    values: Vec::new(),
                    string_codes: None,
                }),
                std::rc::Rc::new(std::collections::HashMap::new()),
                Vec::new(),
            ),
        };

        let mut out: Vec<(NodeId, Value)> = Vec::new();
        // Every visible label-carrying node id, in candidate order — the exact `count(*)` support
        // (every matched node, present-property or not) and the snapshot's `scan_nodes_by_label` set,
        // accumulated from the same single candidate pass (`rmp` task #352). Its `.len()` is the
        // `label_matches` the columnar scan reports.
        let mut members: Vec<NodeId> = Vec::new();
        // Decode accounting (`rmp` #329/#330): values served from the column (zero decode) vs read
        // from the property chain (fallback). Published to the cache at the end of the scan.
        let mut value_hits: u64 = 0;
        let mut fallback_reads: u64 = 0;
        for id in candidates {
            // Read the node record once (visibility + label re-check + the freshness witness). A
            // candidate whose page is unallocated (a stale index entry for a reclaimed slot) is not a
            // live node and is dropped — exactly as `filter_label_candidates` drops it.
            let node_rec = match self.store.borrow().node(id) {
                Ok(rec) => rec,
                Err(_) => continue,
            };
            // SIREAD-mark every examined candidate, visible or not (the predicate examined it) — the
            // identical per-candidate marker `filter_label_candidates` records.
            self.note_read(node_ssi_key(id));
            if !self.visible(node_rec.mvcc) {
                continue;
            }
            // The node must currently carry the label (the row label scan's membership test).
            match self.store.borrow().node_has_label(id, label_token) {
                Ok(true) => {}
                Ok(false) => continue,
                Err(e) => {
                    // An overflow-form bitmap (#39) surfaces as a captured error, never a wrong row.
                    self.capture(e);
                    return Some(ColumnarPass::default());
                }
            }
            // A visible label-carrying node: it counts toward `count(*)` regardless of the property.
            members.push(NodeId(id));

            // Try the cache; fall back to the authoritative single-property read on any mismatch.
            // Look the candidate's row up in the memoized id->index map (O(1), no per-query rebuild),
            // and only when the witness re-check passes do we **materialize** (clone) its value from
            // the shared decode — late materialization (`rmp` task #375).
            let node = NodeId(id);
            let cache_row = cached_index.get(&id).copied().filter(|&i| {
                self.columnar_entry_is_fresh(&node_rec, cached_witnesses[i], prop_key)
            });
            let value = match cache_row {
                Some(i) => {
                    // Fresh: the cached value IS the node's snapshot-visible newest value of the key.
                    // Served from the contiguous column with ZERO property-chain decode (the win);
                    // one clone of the (short) value materialized only for this kept row.
                    value_hits += 1;
                    Some(cached_decoded.values[i].clone())
                }
                // Cache miss, or stale (a prepend/overwrite/tombstone since rebuild, or a concurrent
                // writer): read the authoritative current value — exactly the row path (one decode).
                None => {
                    fallback_reads += 1;
                    self.read_node_prop_one(node, property)
                }
            };
            if let Some(value) = value {
                out.push((node, value));
            }
        }
        // Publish the decode-accounting tallies (`rmp` #329/#330 measurement / observability): how many
        // values were served from the column (zero decode) vs read from the property chain (fallback).
        if let Some(columns) = &self.columns {
            let cache = columns.borrow();
            cache.record_value_hits(value_hits);
            cache.record_fallback_reads(fallback_reads);
        }
        Some(ColumnarPass { members, rows: out })
    }

    /// Whether a cached column entry for property-key `prop_key` is still **fresh** for the node whose
    /// current record is `node_rec` (`rmp` #329). Fresh means the cached value is provably the node's
    /// snapshot-visible *newest* value of the key, so it can be used in place of a property-chain read.
    ///
    /// Two O(1) witness checks (see [`ColumnWitness`](crate::column_cache::ColumnWitness) for the full
    /// argument):
    ///
    /// 1. `node_rec.first_prop == witness.node_first_prop` — the property-chain head is unchanged, so
    ///    **no prepend** happened since rebuild ⇒ the cached `PropRecord` is still the newest version
    ///    of its key (no overwrite or addition slipped past, newest-visible-wins preserved).
    /// 2. The cached `PropRecord` (re-read by `witness.prop_pid`) still has key `prop_key` **and is
    ///    visible** to this snapshot — catching the one mutation `first_prop` does not: an in-place
    ///    tombstone (`REMOVE n.p` / `SET n.p = null`), which stamps `xmax` without moving the head.
    ///
    /// On any storage fault reading the `PropRecord`, returns `false` (decline the cache → the caller
    /// falls back to the authoritative read, which surfaces the fault through the captured-error
    /// channel). Records **no** SSI marker (the per-node SIREAD is recorded by the caller for the node
    /// key; re-reading the property record is an internal freshness probe, not an additional read of a
    /// distinct conflict key — the property value belongs to the same node the caller already marked).
    fn columnar_entry_is_fresh(
        &self,
        node_rec: &graphus_storage::record::NodeRecord,
        witness: crate::column_cache::ColumnWitness,
        prop_key: u32,
    ) -> bool {
        // Witness 1: the chain head must be byte-identical (no prepend of any kind since rebuild).
        if node_rec.first_prop != witness.node_first_prop {
            return false;
        }
        // Witness 2: the cached `PropRecord` must still be the same key AND visible (not tombstoned).
        let prop = match self.store.borrow().property(witness.prop_pid) {
            Ok(p) => p,
            Err(_) => return false, // a read fault: decline the cache, fall back to the row read.
        };
        prop.key == prop_key && self.visible(prop.mvcc)
    }
}

/// The live seam routes the shared lifted read body's markers / errors to its **existing** channels
/// (`rmp` task #336, Slice 3b-i): a per-record / predicate SIREAD marker goes to this statement's
/// [`ReadBufferGuard`] (the `rmp` #341 buffer, merged into the shared `SsiTracker` at statement-end),
/// and a captured error to the `error` cell. So calling the lifted body with `self` as the sink
/// reproduces `RecordStoreGraph`'s prior behaviour exactly — the markers/errors land where they always
/// did.
impl<D: BlockDevice + Send + Sync + 'static, S: LogSink + Send + Sync + 'static> ReadSink
    for RecordStoreGraph<D, S>
{
    fn note_read(&self, key: u64) {
        self.note_read(key);
    }

    fn note_predicate_read(&self, predicate: PredicateRead) {
        self.note_predicate_read(predicate);
    }

    fn capture(&self, err: GraphusError) {
        self.capture(err);
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
impl<D: BlockDevice + Send + Sync + 'static, S: LogSink + Send + Sync + 'static>
    crate::statistics::Statistics for RecordStoreGraph<D, S>
{
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

impl<D: BlockDevice + Send + Sync + 'static, S: LogSink + Send + Sync + 'static> GraphAccess
    for RecordStoreGraph<D, S>
{
    // ---- reads --------------------------------------------------------------------------------

    fn scan_nodes(&self) -> Vec<NodeId> {
        // The shared lifted body (`rmp` task #336): register the `AllNodes` predicate marker, then
        // SIREAD-mark and visibility-filter every slot-occupied node — byte-identical to the prior
        // inline body, now also run by the off-thread reader. Read-only: `LiveSource` over the live
        // store's `&self` read methods (`rmp` #337 Slice 2), so a shared borrow suffices.
        read_source::scan_nodes(&LiveSource(&*self.store.borrow()), &self.vis_ctx(), self)
    }

    fn scan_nodes_by_label(&self, label: &str) -> Vec<NodeId> {
        // The index-accelerated arm stays here (it owns the derived `IndexSet`); only the scan-fallback
        // arm is the lifted body. On the coordinated path: register the same `Label` + `mark_all_live_
        // nodes` predicate footprint, seek candidates from the label index, then re-check them with the
        // **shared lifted** `filter_label_candidates` — so the index seek returns *exactly* the
        // full-scan result over a candidate subset (`rmp` task #48), with the per-candidate SIREAD
        // markers identical to the fallback path. Read-only: `LiveSource` over the live store.
        if let Some(index) = &self.index {
            // Resolve the label token without interning; a never-interned label has no live node, but a
            // concurrent writer could create the first one — so register the conservative `AllNodes`
            // marker rather than interning on a read path (`rmp` #171). `note_predicate_read` no-ops
            // standalone.
            let Some(token_id) = self.label_id_existing(label) else {
                self.note_predicate_read(PredicateRead::AllNodes);
                return Vec::new();
            };
            // `MATCH (n:Label)` is a predicate over which nodes carry the label, so a concurrent
            // insert/relabel is a phantom that must close an rw-edge even when this scan returns nothing.
            self.note_predicate_read(PredicateRead::Label(token_id));
            // The index only accelerates computing the *result*, never narrows the read footprint:
            // keep the conservative SIREAD-every-live-node marker (the deferred index-range marker is
            // #16/#39) so write-skew over a label predicate stays serializable.
            let src = LiveSource(&*self.store.borrow());
            read_source::mark_all_live_nodes(&src, self);
            let candidates = index.borrow_mut().seek_label(token_id);
            return read_source::filter_label_candidates(
                &src,
                &self.vis_ctx(),
                self,
                token_id,
                candidates,
            );
        }

        // Standalone fallback (no coordinator ⇒ no index): resolve the token + register the
        // `Label`/`AllNodes` predicate marker exactly as before (NOT `mark_all_live_nodes` — the
        // pre-#336 standalone path did not, and standalone markers no-op anyway), then scan every live
        // node and filter by the inline bitmap via the **shared lifted** `filter_label_candidates`.
        // This keeps the standalone path byte-for-byte unchanged. (The off-thread `ReadOnlyGraph`, which
        // is always coordinated and index-free, instead uses the full lifted `scan_nodes_by_label`,
        // whose `mark_all_live_nodes` reproduces the coordinated index arm's marker footprint.)
        let Some(token_id) = self.label_id_existing(label) else {
            self.note_predicate_read(PredicateRead::AllNodes);
            return Vec::new();
        };
        self.note_predicate_read(PredicateRead::Label(token_id));
        let src = LiveSource(&*self.store.borrow());
        let ids = match src.0.scan_node_ids() {
            Ok(ids) => ids,
            Err(e) => {
                self.capture(e);
                return Vec::new();
            }
        };
        read_source::filter_label_candidates(&src, &self.vis_ctx(), self, token_id, ids)
    }

    fn columnar_label_property_scan(
        &self,
        label: &str,
        property: &str,
    ) -> Option<crate::graph_access::ColumnarScan> {
        // Delegates to the inherent helper, which drives off the authoritative label-candidate set,
        // re-validates each cached value against the node's current MVCC header, and falls back to the
        // row read on any mismatch — so the result is exactly the row-path result (`rmp` #329).
        self.columnar_scan_checked(label, property)
    }

    fn project_snapshot(&self, spec: &SnapshotSpec) -> Option<GraphSnapshot> {
        // The parallel-read enabler (`rmp` task #352, phase 1 of #336): project the single
        // `(label, property)` column declared in `spec` into a frozen, owned `Send + Sync`
        // [`GraphSnapshot`] the executor can fold across all cores, built **here on the engine thread
        // under this statement's already-pinned read snapshot** before the owned copy is handed to
        // rayon.
        //
        // # Why this goes through `columnar_label_pass`
        //
        // It deliberately reuses the **identical** internal candidate pass the serial
        // [`columnar_label_property_scan`](GraphAccess::columnar_label_property_scan) uses
        // ([`columnar_label_pass`](Self::columnar_label_pass)), so:
        //
        // * **SSI / predicate read-markers are byte-for-byte identical** — the `PredicateRead::Label`
        //   marker, the `mark_all_live_nodes` footprint, and the per-candidate `note_read` are all
        //   registered by that shared pass on the engine thread, *before* the snapshot is frozen. A
        //   statement that takes the parallel path therefore closes exactly the same rw-edges (the same
        //   phantoms) as one that took the serial columnar or row path; serializability is unchanged.
        // * **MVCC visibility + value re-validation are identical** — every value is the node's
        //   snapshot-visible current value (cache hit re-checked against the MVCC header, else the
        //   authoritative row read), so the snapshot's rows are exactly the row-path
        //   `(node, value)` set, and `members` is exactly the `scan_nodes_by_label` set.
        //
        // It declines (returns `None`) on exactly the set the serial columnar scan declines on: the
        // standalone / [`begin_at_snapshot`](Self::begin_at_snapshot) historical-read path (no columnar
        // cache, `self.columns` is `None`) and any column not declared. The caller then falls through
        // to the serial aggregation tiers, which run verbatim.
        //
        // RBAC composition is handled one layer up by
        // [`AuthorizedGraph`](crate::authorized_graph::AuthorizedGraph), which declines this for a
        // restricted principal (mirroring its `columnar_label_property_scan`), so a restricted reader
        // can never observe filtered-out data through the snapshot.

        // Phase 1 covers exactly one node column (`MATCH (n:Label) RETURN <agg>(n.p)`); a spec naming
        // anything else (zero columns, multiple columns, or any relationship column) is not the shape
        // the parallel aggregation requests — decline so the caller stays on the serial path.
        let [(label, property)] = spec.columns() else {
            return None;
        };
        if !spec.rel_columns().is_empty() {
            return None;
        }

        // The single authoritative candidate pass (registers the identical SSI markers); `None` ⇒ no
        // declared column / historical read ⇒ decline (caller uses the serial path).
        let pass = self.columnar_label_pass(label, property)?;
        Some(GraphSnapshot::from_label_column(
            label,
            property,
            pass.members,
            pass.rows,
        ))
    }

    fn note_parallel_aggregate(&self) {
        // Observability (`rmp` task #352): the executor calls this once it has committed to folding a
        // projected snapshot in parallel (every gate passed, including the all-integer column check),
        // so the counter measures *completed* parallel aggregations — distinct from a projection that
        // is declined afterwards (e.g. a float `sum`) and from the serial columnar `scan_hits`.
        if let Some(columns) = &self.columns {
            columns.borrow().record_parallel_scan_hit();
        }
    }

    fn morsel_label_scan(&self, label: &str) -> Option<crate::morsel::MorselLabelScan> {
        // The morsel-driven parallel-read enabler (`rmp` task #339, Slice 3a): capture, on the engine
        // thread, the bundle the executor's morsel tier needs to read a bare label scan across
        // concurrent morsels — the authoritative candidate-id vector + an erased, `Send`, cheap-cloneable
        // read surface (an owned `StoreReadView` + `TokenSnapshot`) + this statement's visibility inputs.
        //
        // # Why it is the coordinated path only
        //
        // The morsels record their per-candidate SIREAD markers into their own buffers and the executor
        // folds them back into THIS statement's shared `SsiTracker` via `merge_morsel_buffer`. That
        // tracker exists only on the coordinated path (`attach`); the standalone / `begin_at_snapshot`
        // historical-read path has no shared tracker (markers are no-ops there), and — crucially — the
        // coordinated path is also where the candidate set comes from the derived label index. So decline
        // (`None`) unless coordinated; the caller then runs the serial tier, which is always correct. The
        // restricted-RBAC decline is handled one layer up by `AuthorizedGraph` (mirroring
        // `project_snapshot`), so a restricted reader never bypasses per-node RBAC through a morsel.
        let index = self.index.as_ref()?;

        // Resolve the label token WITHOUT interning (a read must not mint a token). A never-interned
        // label has no live matching node, but a concurrent writer could create the first one — so
        // register the conservative `AllNodes` marker (the absent-node phantom) and decline acceleration
        // (`None`), exactly as the serial `scan_nodes_by_label` index arm does on a missing token. The
        // caller's serial path then handles the empty case verbatim.
        let Some(label_token) = self.label_id_existing(label) else {
            self.note_predicate_read(PredicateRead::AllNodes);
            return None;
        };

        // --- the coarse SSI predicate footprint, registered ONCE on the engine thread ---
        // Byte-identical to the serial `scan_nodes_by_label` index arm / `columnar_label_pass`: the
        // `Label` predicate marker (a concurrent insert/relabel is a phantom) + the all-live-nodes
        // footprint (the conservative phantom approximation the per-candidate SIREADs cannot supply for a
        // not-yet-existing matching node). The morsels supply the per-candidate `note_read` markers into
        // their own buffers; this coarse footprint is the part that must be on the engine thread.
        self.note_predicate_read(PredicateRead::Label(label_token));
        self.mark_all_live_nodes();
        // A storage fault while marking all live nodes captured an error; the result is now untrustworthy,
        // so decline the morsel path (the caller's serial path will surface the same captured error).
        if self.has_error() {
            return None;
        }

        // --- the authoritative current candidate set (the SAME source `scan_nodes_by_label` uses) ---
        let candidates: Vec<u64> = index.borrow_mut().seek_label(label_token);

        // --- the engine-thread-captured, owned, `Send` read surface (cheap to clone per morsel) ---
        let store = self.store.borrow();
        let source: Box<dyn crate::morsel::MorselSource> = Box::new(
            crate::morsel::MorselView::new(store.read_view(), store.token_snapshot()),
        );
        drop(store);

        Some(crate::morsel::MorselLabelScan {
            candidates,
            label_token,
            source,
            snapshot: self.snapshot,
            registry: self.registry.clone(),
            txn: self.txn,
        })
    }

    fn merge_morsel_buffer(&self, buffer: SsiReadBuffer) {
        // Convergence (`rmp` task #339): fold a morsel's accumulated SIREAD markers into this statement's
        // shared `SsiTracker`, on the engine thread (the merge must run where the tracker lives). The
        // tracker's `merge_read_buffer` sorts + dedups + replays through the existing `record_read`, so
        // the conflict graph is the UNION of the morsels' markers — byte-identical to the serial scan's
        // marker set. A no-op on the standalone path (no shared tracker). Mirrors the `rmp` #341 /
        // `coordinator::merge_read_buffer` single-writer merge point.
        if let Some(ssi) = &self.ssi {
            ssi.borrow_mut().merge_read_buffer(buffer);
        }
    }

    fn expand(&self, node: NodeId, direction: ExpandDirection, types: &[String]) -> Vec<Incident> {
        // The shared lifted body (`rmp` task #336): register the relationship-pattern predicate marker
        // (rel-type or, untyped, `AnyRel` — the absent-edge phantom, `rmp` #171 blocker A1), walk the
        // incidence chain resolving the requested types to ids once (`rmp` #319), and SIREAD-mark +
        // visibility-filter each edge, reporting the matching side(s). Byte-identical to the prior inline
        // body. Read-only: `LiveSource` over the live store's `&self` read methods.
        //
        // `rmp` #324, "Win 2": if the opt-in CSR accelerator is present **and fresh**, and this is a
        // typed expand, resolve the requested type names to ids and seek the matching candidate rel-ids
        // from the CSR — so the lifted body reads only those candidates (touching no non-matching chain
        // link) instead of walking the incidence chain. A stale/absent CSR or an untyped expand yields
        // `None` and the body takes the Win-1 chain walk. The candidate ids are re-checked (type +
        // visibility) by the body, so the result and SSI markers are byte-identical either way.
        let csr_candidates = self.csr_candidates_for(node, types);
        read_source::expand_with_csr(
            &LiveSource(&*self.store.borrow()),
            &self.vis_ctx(),
            self,
            node,
            direction,
            types,
            csr_candidates,
        )
    }

    fn node_exists(&self, node: NodeId) -> bool {
        // The shared lifted body (`rmp` task #336): "exists" = visible to this query's snapshot;
        // SIREAD-marks the examined node. Byte-identical to the prior inline body.
        read_source::node_exists(
            &LiveSource(&*self.store.borrow()),
            &self.vis_ctx(),
            self,
            node,
        )
    }

    fn rel_exists(&self, rel: RelId) -> bool {
        read_source::rel_exists(
            &LiveSource(&*self.store.borrow()),
            &self.vis_ctx(),
            self,
            rel,
        )
    }

    fn node_labels(&self, node: NodeId) -> Option<Vec<String>> {
        // The shared lifted body (`rmp` task #336): existence check, then the node's label names
        // mapped + name-sorted; an overflow-form bitmap is captured and reported as `Some(vec![])`
        // (not silently wrong). Byte-identical to the prior inline body.
        read_source::node_labels(
            &LiveSource(&*self.store.borrow()),
            &self.vis_ctx(),
            self,
            node,
        )
    }

    fn rel_data(&self, rel: RelId) -> Option<RelData> {
        read_source::rel_data(
            &LiveSource(&*self.store.borrow()),
            &self.vis_ctx(),
            self,
            rel,
        )
    }

    fn rel_data_including_deleted(&self, rel: RelId) -> Option<RelData> {
        // No SIREAD *read* marker (reading our own tombstone has no rw-dependency), but the sink is
        // passed so a storage *fault* on the lookup is captured, not swallowed into `None` (`rmp` #359
        // defence-in-depth). Keeps `type(r)`/`id(r)` accessible after a same-query `DELETE r`.
        read_source::rel_data_including_deleted(
            &LiveSource(&*self.store.borrow()),
            &self.vis_ctx(),
            self,
            rel,
        )
    }

    fn entity_deleted_by_txn(&self, entity: DeletedEntity) -> bool {
        // No SIREAD *read* marker (a self-delete check on our own write records no rw-dependency), but
        // the sink is passed so a storage *fault* on the probe is captured rather than swallowed into
        // `false` (`rmp` #359 defence-in-depth).
        read_source::entity_deleted_by_txn(
            &LiveSource(&*self.store.borrow()),
            &self.vis_ctx(),
            self,
            entity,
        )
    }

    fn node_property(&self, node: NodeId, key: &str) -> Option<Value> {
        read_source::node_property(
            &LiveSource(&*self.store.borrow()),
            &self.vis_ctx(),
            self,
            node,
            key,
        )
    }

    fn rel_property(&self, rel: RelId, key: &str) -> Option<Value> {
        read_source::rel_property(
            &LiveSource(&*self.store.borrow()),
            &self.vis_ctx(),
            self,
            rel,
            key,
        )
    }

    fn node_properties(&self, node: NodeId) -> Option<Vec<(String, Value)>> {
        read_source::node_properties(
            &LiveSource(&*self.store.borrow()),
            &self.vis_ctx(),
            self,
            node,
        )
    }

    fn rel_properties(&self, rel: RelId) -> Option<Vec<(String, Value)>> {
        read_source::rel_properties(
            &LiveSource(&*self.store.borrow()),
            &self.vis_ctx(),
            self,
            rel,
        )
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

    fn scan_filter_eq(&self, label: &str, property: &str, value: &Value) -> Vec<NodeId> {
        // The precise full-scan equality path (`rmp` task #325): the scan-path twin of `index_seek_eq`'s
        // SSI footprint. The lifted body (shared with `ReadOnlyGraph`) registers the precise
        // `Equality` predicate marker and SIREAD-marks ONLY the matching nodes — never the blanket
        // `mark_all_live_nodes` a bare label scan registers — so two writers matching DISJOINT keys no
        // longer conflict reciprocally (the abort-storm fix). Read-only: `LiveSource` over the live
        // store's `&self` reads (`rmp` #337 Slice 2), so a shared borrow suffices.
        read_source::scan_filter_eq(
            &LiveSource(&*self.store.borrow()),
            &self.vis_ctx(),
            self,
            label,
            property,
            value,
        )
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
        // `rmp` #324, Win 2: a new edge changes incidence, so invalidate the CSR snapshot — it now
        // declines and `expand` walks the live chain until the next rebuild-on-open. No-op when off.
        self.mark_csr_dirty();
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
            // Keep the bitmap candidate source membership-exact after a `SET n.p = null` removal
            // (`rmp` #328): the node must leave the column's value-bitmaps.
            self.reindex_node_bitmaps(node);
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
        // Keep the bitmap candidate source membership-exact after a label loss (`rmp` #328): a node
        // that no longer carries the covered label must drop out of the column's bitmaps.
        self.reindex_node_bitmaps(node);
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
        // Keep the bitmap candidate source membership-exact after a property removal (`rmp` #328): the
        // node must leave the column's value-bitmaps (the other index kinds tolerate the stale entry).
        self.reindex_node_bitmaps(node);
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
        // The shared lifted body (`rmp` task #336): the relationship ids incident to `node`, filtered
        // to those visible to this transaction (a deleted edge is not reported) and SIREAD-marked.
        // Byte-identical to the prior inline body.
        read_source::incident_rels(
            &LiveSource(&*self.store.borrow()),
            &self.vis_ctx(),
            self,
            node,
        )
    }

    fn delete_rel(&mut self, rel: RelId) {
        // Idempotent: a relationship not visible to this query (already gone, deleted by us earlier,
        // or never created) is a no-op, not an error — matching the `MemGraph` contract. Visibility
        // (not raw `in_use`) is the right guard now that delete is an MVCC tombstone (the slot stays
        // in use): a second delete in the same transaction sees its own tombstone and does nothing.
        let (mvcc, type_id) = match self.store.borrow().rel(rel.0) {
            Ok(r) => (r.mvcc, r.type_id),
            Err(_) => return,
        };
        if !self.visible(mvcc) {
            return;
        }
        // `rmp` #324, Win 2: deleting an edge changes incidence, so invalidate the CSR snapshot. No-op
        // when off; idempotent. Marked before the store mutation so a later read in this same
        // transaction never consults a CSR that still lists the about-to-be-removed edge.
        self.mark_csr_dirty();
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
        let mvcc = match self.store.borrow().node(node.0) {
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
            return;
        }
        // De-index the bitmap (`rmp` #453, F-IDX-4): a committed `DELETE n` must clear n's bit from
        // every covered value-bitmap, or the bitmap would keep a phantom membership the seek's re-check
        // could only mask (today by id-recycle self-heal — a superset that violates membership-exactness
        // once the seek is wired into the planner). Record the node as bitmap-dirty FIRST so an abort
        // re-derives (re-adds) it from the reverted store, then remove it from every bitmap. A store
        // read here would be wrong: the node is only tombstoned, so its labels/values are still present
        // and would re-add it — hence the unconditional remove, not a `reindex_node_bitmaps`.
        if let Some(index) = &self.index {
            let mut index = index.borrow_mut();
            index.note_bitmap_dirty(self.txn, node.0);
            index.remove_node_from_all_bitmaps(node.0);
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
