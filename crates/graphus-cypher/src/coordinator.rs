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
use std::collections::{HashMap, VecDeque};
use std::rc::Rc;

use graphus_core::Value;
use graphus_core::error::{GraphusError, Result};
use graphus_core::{Lsn, Timestamp, TxnId};
use graphus_index::fulltext::Analyzer;
use graphus_index::histogram::PropertyHistogram;
use graphus_index::{Similarity, VectorIndexError};
use graphus_io::BlockDevice;
use graphus_storage::{
    CompositeIndexEntry, ConstraintEntry, ConstraintKind, ConstraintTypeDescriptor, FulltextEntity,
    FulltextIndexEntry, GcPassReport, IndexState, Namespace, RecordStore, RelCompositeIndexEntry,
    SpatialEntity, SpatialIndexEntry, StoreReadView, TextIndexEntry, TokenSnapshot, VectorEntity,
    VectorIndexEntry, VectorSimilarity,
};
use graphus_txn::{CommitRegistry, IsolationLevel, LockTable, Snapshot, SsiReadBuffer, SsiTracker};
use graphus_wal::LogSink;

use crate::catalog::IndexCatalog;
use crate::constraint::{ConstraintViolation, ViolationEntity};
use crate::index_set::IndexSet;
use crate::record_graph::RecordStoreGraph;
use crate::schema_error::{
    constraint_name_in_use, equivalent_composite_index_exists, equivalent_constraint_exists,
    equivalent_index_exists, equivalent_rel_composite_index_exists, equivalent_rel_index_exists,
    index_drop_not_found, index_name_in_use,
};
use crate::statistics::Statistics;

/// One row of [`TxnCoordinator::list_fulltext_indexes`] (`rmp` tasks #72, #663): the index name, its
/// [`FulltextEntity`], its covered labels/types (one or more), its covered properties, its analyzer and
/// its build state — the tuple a `SHOW FULLTEXT INDEXES` surface renders.
pub type FulltextIndexListing = (
    String,
    FulltextEntity,
    Vec<String>,
    Vec<String>,
    Analyzer,
    IndexState,
);

/// One row of [`TxnCoordinator::list_vector_index_listings`] (`rmp` task #671): every field a
/// `SHOW INDEXES` VECTOR row needs — the index name, its [`VectorEntity`], its covered label / type,
/// its covered embedding property, the embedding `dimensions`, the [`VectorSimilarity`] metric, the
/// HNSW `m` / `ef_construction` build parameters and its build state.
///
/// Unlike the thinner [`TxnCoordinator::list_vector_indexes`] tuple (`(name, label, property, state)`,
/// `rmp` #669), this carries the full `indexConfig` so the unified index listing can render the
/// `options` map and a round-trippable `createStatement`. A struct (rather than a wide tuple) keeps the
/// nine fields self-documenting at every use site.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VectorIndexListing {
    /// The server-unique index name.
    pub name: String,
    /// Whether the index covers a node label or a relationship type.
    pub entity: VectorEntity,
    /// The covered node label ([`Node`](VectorEntity::Node)) or relationship type
    /// ([`Relationship`](VectorEntity::Relationship)).
    pub label_or_type: String,
    /// The covered embedding property (exactly one).
    pub property: String,
    /// The embedding dimension (`> 0`).
    pub dimensions: u32,
    /// The similarity metric the HNSW graph navigates by.
    pub similarity: VectorSimilarity,
    /// The HNSW `m` build parameter (target out-degree per layer).
    pub m: u32,
    /// The HNSW `ef_construction` build parameter (construction candidate-list size).
    pub ef_construction: u32,
    /// The build state of the index.
    pub state: IndexState,
}
use crate::store_statistics;

/// Renders a [`Value`] compactly for a constraint-violation message (`rmp` task #99): a string is
/// single-quoted, everything else uses its `Debug` form. Kept small and side-effect-free — this is
/// only for the human message, never for comparison or persistence.
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
/// #100). Used to detect a node-key duplicate; the tuples always have equal length (the same covered
/// property count). A null element would make the tuple incomplete and never reach here.
fn tuples_equal(a: &[Value], b: &[Value]) -> bool {
    a.len() == b.len()
        && a.iter()
            .zip(b)
            .all(|(x, y)| crate::equality::equals(x, y).is_true())
}

/// A declared constraint resolved to human-readable names, for the `SHOW CONSTRAINTS` surface
/// (`rmp` tasks #99, #100). Carries the covered label, the **whole** covered property tuple (one for a
/// non-composite kind, several for a node key), the [`ConstraintKind`] and (for a property-type
/// constraint) the declared [`ConstraintTypeDescriptor`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConstraintInfo {
    /// The server-unique constraint name.
    pub name: String,
    /// The covered node label.
    pub label: String,
    /// The covered properties, in declared order (one for `Unique`/`Existence`/`PropertyType`,
    /// one-or-more for a `NodeKey`).
    pub properties: Vec<String>,
    /// The constraint kind.
    pub kind: ConstraintKind,
    /// The declared value type of a [`ConstraintKind::PropertyType`] constraint, or [`None`] otherwise.
    pub type_descriptor: Option<ConstraintTypeDescriptor>,
}

/// Live state of an open transaction the coordinator drives.
#[derive(Debug, Clone, Copy)]
struct ActiveTxn {
    snapshot: Snapshot,
    isolation: IsolationLevel,
    /// The **monotonic**-clock reading (nanoseconds, `rmp` #395) captured at begin, or `None` when the
    /// transaction was opened through the clock-agnostic [`TxnCoordinator::begin`] (the TCK / unit
    /// tests — never age-reaped). The server's open path uses [`TxnCoordinator::begin_at`] to stamp it,
    /// so the maximum-transaction-age sweep ([`TxnCoordinator::aged_transactions`], `rmp` #477) can
    /// reap a transaction whose lifetime exceeds the configured cap — freeing the GC watermark
    /// ([`TxnCoordinator::oldest_active_snapshot`]) it would otherwise pin indefinitely.
    begin_nanos: Option<u64>,
}

/// One in-progress **non-blocking** node-property index build (`rmp` task #91).
///
/// A build indexes the nodes captured in `snapshot` (the store's live node-id list at build
/// start), a bounded chunk at a time, advancing `cursor` until it reaches the end; the index is
/// then promoted to [`IndexState::Online`]. Nodes created *after* the snapshot, value changes,
/// and deletes are all handled outside this snapshot by [`RecordStoreGraph::reindex_node`] /
/// the candidate-set re-check (see [`TxnCoordinator::advance_index_builds`] for the full
/// consistency argument), so the snapshot only needs to cover the rows that already existed.
/// How many consecutive failures-to-progress a non-blocking index build tolerates before it is
/// **poisoned** (`rmp` task #733) — see [`PendingIndexBuild::stall`]. Generous enough that a transient
/// storage fault self-heals, small enough that a permanent one terminates promptly instead of spinning
/// the engine at 100% CPU.
const BUILD_STALL_BUDGET: u8 = 32;

/// The ceiling on the degraded-index rebuild backoff (`rmp` task #733), in attempts skipped between
/// probes. A repair rebuild is O(store) and runs **synchronously on the engine thread**, stalling every
/// query behind it, so a permanently-faulting store must not trigger one every couple of seconds. At the
/// engine's 2 ms idle tick this ceiling is ≈ 8.7 minutes between attempts; on a busy engine (where the
/// counter advances once per command) it is longer still. Counted in attempts, not wall-clock: the
/// coordinator must remain deterministic for DST and so never reads the clock.
const MAX_DEGRADED_RETRY_BACKOFF: u32 = 262_144;

/// The drains to skip before the next poisoned-build resurrection attempt, given how many consecutive
/// resurrections have already failed to complete (`rmp` task #733, B2). `2^(attempts-1)`, capped at
/// [`MAX_DEGRADED_RETRY_BACKOFF`]: the first re-poison waits 1 drain, then 2, 4, 8, …, so a build that
/// keeps hitting an unreadable page is retried ever-less-often — its resurrection *rate* decays
/// geometrically to zero, instead of spinning the engine every tick. `attempts == 0` never reaches here
/// (the first resurrection is immediate), but is handled defensively as no skip.
#[must_use]
fn poison_backoff(attempts: u32) -> u32 {
    if attempts == 0 {
        return 0;
    }
    let shift = (attempts - 1).min(31);
    (1u32 << shift).min(MAX_DEGRADED_RETRY_BACKOFF)
}

struct PendingIndexBuild {
    /// The label token the index is declared on.
    label_token: u32,
    /// The property-key token the index is declared on.
    prop_key: u32,
    /// The node-id list captured at build start (`store.scan_node_ids()`). Indexing walks this in
    /// order; a since-deleted id simply inserts a stale candidate (harmless — the re-check drops it).
    snapshot: Vec<u64>,
    /// The next index into `snapshot` to process; the build is complete once `cursor >= snapshot.len()`.
    cursor: usize,
    /// The [`IndexSet::wipe_generation`] this build is indexing into (`rmp` task #733). If a
    /// `fail_closed` wipes the index set mid-build, the epoch changes and the build **re-takes its
    /// snapshot from the store and restarts from cursor 0** instead of resuming over an emptied tree.
    /// Resuming would index only the tail of the snapshot and then promote the index `Online` with a hole
    /// in it; restarting over the *original* snapshot would still lose every row written after the
    /// snapshot was taken, because the wipe destroyed those maintenance writes too.
    generation: u64,
    /// How many more times this build may fail to make final progress before it is **poisoned**
    /// (`rmp` task #733) — dropped un-promoted, leaving its index `Populating` and therefore never
    /// served. Decremented on a chunk that could not read a node, and on a promotion blocked by a
    /// degraded index set; refilled by any chunk that does make progress.
    ///
    /// It exists because Graphus assumes storage faults are **persistent** (checksum / torn page). A
    /// build that retries an unreadable chunk forever never advances its cursor, and
    /// `LocalEngine::drain_index_builds` spins `while has_pending_index_builds()` — an infinite loop at
    /// 100% CPU, re-scanning the store on every iteration. A bounded budget keeps a *transient* fault
    /// self-healing while guaranteeing termination against a permanent one.
    stall: u8,
}

/// One in-progress **non-blocking** full-text index build (`rmp` task #72), the analogue of
/// [`PendingIndexBuild`] for the inverted index. Indexes the `snapshot` nodes a bounded chunk at a
/// time, then promotes the named full-text index to [`IndexState::Online`]. The same candidate-set
/// argument applies: writes after the snapshot are maintained by
/// [`RecordStoreGraph::reindex_node`] and deletes are dropped by the query-time re-check, so the
/// snapshot only needs to cover the rows that already existed at build start.
struct PendingFulltextBuild {
    /// The server-unique name of the full-text index being built.
    name: String,
    /// The node-id list captured at build start.
    snapshot: Vec<u64>,
    /// The next index into `snapshot` to process; complete once `cursor >= snapshot.len()`.
    cursor: usize,
    /// The [`IndexSet::wipe_generation`] this build is indexing into (`rmp` task #733). If a
    /// `fail_closed` wipes the index set mid-build, the epoch changes and the build **re-takes its
    /// snapshot from the store and restarts from cursor 0** instead of resuming over an emptied tree.
    /// Resuming would index only the tail of the snapshot and then promote the index `Online` with a hole
    /// in it; restarting over the *original* snapshot would still lose every row written after the
    /// snapshot was taken, because the wipe destroyed those maintenance writes too.
    generation: u64,
    /// How many more times this build may fail to make final progress before it is **poisoned**
    /// (`rmp` task #733) — dropped un-promoted, leaving its index `Populating` and therefore never
    /// served. Decremented on a chunk that could not read a node, and on a promotion blocked by a
    /// degraded index set; refilled by any chunk that does make progress.
    ///
    /// It exists because Graphus assumes storage faults are **persistent** (checksum / torn page). A
    /// build that retries an unreadable chunk forever never advances its cursor, and
    /// `LocalEngine::drain_index_builds` spins `while has_pending_index_builds()` — an infinite loop at
    /// 100% CPU, re-scanning the store on every iteration. A bounded budget keeps a *transient* fault
    /// self-healing while guaranteeing termination against a permanent one.
    stall: u8,
}

/// One in-progress **non-blocking** spatial (point) index build (`rmp` task #98), the analogue of
/// [`PendingFulltextBuild`] for the grid spatial index. Indexes the `snapshot` nodes a bounded chunk
/// at a time, then promotes the spatial index on `(label_token, prop_key)` to [`IndexState::Online`].
/// The same candidate-set argument applies: writes after the snapshot are maintained by
/// [`RecordStoreGraph::reindex_node`] and deletes / stale points are dropped by the query-time
/// re-check, so the snapshot only needs to cover the rows that already existed at build start.
struct PendingSpatialBuild {
    /// The server-unique name of the spatial index being built.
    name: String,
    /// The label token the index covers (so the per-node indexer knows which point property to grid).
    label_token: u32,
    /// The property-key token the index covers (a single point property).
    prop_key: u32,
    /// The node-id list captured at build start.
    snapshot: Vec<u64>,
    /// The next index into `snapshot` to process; complete once `cursor >= snapshot.len()`.
    cursor: usize,
    /// The [`IndexSet::wipe_generation`] this build is indexing into (`rmp` task #733). If a
    /// `fail_closed` wipes the index set mid-build, the epoch changes and the build **re-takes its
    /// snapshot from the store and restarts from cursor 0** instead of resuming over an emptied tree.
    /// Resuming would index only the tail of the snapshot and then promote the index `Online` with a hole
    /// in it; restarting over the *original* snapshot would still lose every row written after the
    /// snapshot was taken, because the wipe destroyed those maintenance writes too.
    generation: u64,
    /// How many more times this build may fail to make final progress before it is **poisoned**
    /// (`rmp` task #733) — dropped un-promoted, leaving its index `Populating` and therefore never
    /// served. Decremented on a chunk that could not read a node, and on a promotion blocked by a
    /// degraded index set; refilled by any chunk that does make progress.
    ///
    /// It exists because Graphus assumes storage faults are **persistent** (checksum / torn page). A
    /// build that retries an unreadable chunk forever never advances its cursor, and
    /// `LocalEngine::drain_index_builds` spins `while has_pending_index_builds()` — an infinite loop at
    /// 100% CPU, re-scanning the store on every iteration. A bounded budget keeps a *transient* fault
    /// self-healing while guaranteeing termination against a permanent one.
    stall: u8,
}

/// The owned, `Send` pieces an off-thread reader needs to run a read-only statement against a
/// [`ReadOnlyGraph`](crate::read_only_graph::ReadOnlyGraph), captured on the engine thread by
/// [`TxnCoordinator::read_task_inputs`] (`rmp` task #336, Slice 3b-ii).
///
/// Every field is `Send` (compile-asserted just below), so the whole bundle moves cleanly
/// to a reader thread. It holds **no** `Rc`/`RefCell` and no live borrow of the store: the
/// [`StoreReadView`] is an `Arc`-shared page cache over an owned metadata snapshot, the
/// [`CommitRegistry`] is a clone, and the [`SsiReadBuffer`] is freshly minted for the reader.
pub struct ReadTaskInputs<D: BlockDevice, S: LogSink> {
    /// The owned decode surface over the committed store (`Arc<pool>` + `MetaSnapshot`).
    pub view: StoreReadView<D, S>,
    /// The owned `id ↔ name` token dictionary.
    pub tokens: TokenSnapshot,
    /// This reader's MVCC read snapshot (begin timestamp + owner txn).
    pub snapshot: Snapshot,
    /// A clone of the store's commit registry (resolves an in-flight writer to its outcome).
    pub registry: CommitRegistry,
    /// A fresh, empty SIREAD-marker buffer tagged with the reader's txn.
    pub buffer: SsiReadBuffer,
    /// A `Send + Sync` snapshot of the declared full-text index catalogue (`rmp` task #546), so an
    /// off-thread `CALL db.index.fulltext.queryNodes(name, …)` resolves the index by name and
    /// recomputes its matches from this reader's MVCC snapshot — without the coordinator's `!Send`
    /// [`IndexSet`](crate::index_set::IndexSet). Usually empty (no full-text index declared).
    pub fulltext: crate::read_source::FulltextReadSnapshot,
}

// `rmp` #336 Slice 3b-ii: `ReadTaskInputs` is captured on the engine thread and MOVED into the
// `ReadTask` sent to a reader thread, so it MUST be `Send`. A compile-time assertion (no runtime
// body) that fails to build the instant a non-`Send` field is introduced — making the off-thread
// dispatch's safety explicit here rather than only as a distant error at the `SyncSender<ReadTask>`
// send site. Every field is `Send`: `StoreReadView`/`TokenSnapshot` are `Send + Sync` (Slice 3a),
// `Snapshot` is `Copy`, and `CommitRegistry`/`SsiReadBuffer` are plain owned data. Asserted both for
// the concrete DST instantiation and generically over the `D, S: Send + Sync` bound the view requires.
const _: () = {
    fn assert_send<T: Send>() {}
    fn assert_read_task_inputs() {
        assert_send::<ReadTaskInputs<graphus_io::MemBlockDevice, graphus_wal::MemLogSink>>();
        fn assert_generic<D: BlockDevice + Send + Sync, S: LogSink + Send + Sync>() {
            fn inner<T: Send>() {}
            inner::<ReadTaskInputs<D, S>>();
        }
        assert_generic::<graphus_io::MemBlockDevice, graphus_wal::MemLogSink>();
    }
    let _ = assert_read_task_inputs;
};

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
    /// The shared derived **columnar value cache** (`rmp` tasks #329 / #330): a contiguous,
    /// graphus-columnar-encoded snapshot of each declared `(label, property)` column, used to
    /// accelerate an analytical property scan / aggregation. Like [`Self::index`] it is derived,
    /// in-memory and **never committed or recovered** — rebuilt from the store on [`new`](Self::new)
    /// and re-captured on [`rebuild_columns`](Self::rebuild_columns) (a declaration / schema change).
    /// Unlike the index it caches the *value* (not just a candidate id); correctness is guaranteed at
    /// READ time by [`RecordStoreGraph::columnar_label_property_scan`], which re-validates every cached
    /// value against the node's current MVCC header and falls back to the authoritative row read on
    /// any mismatch — so the cache can be arbitrarily stale and never returns a wrong row. Maintenance
    /// is therefore **rebuild-only** (no commit-path hook), exactly the safe design `rmp` #329 mandates.
    columns: Rc<RefCell<crate::column_cache::ColumnCache>>,
    /// The derived per-`(label, property)` **zone-map data-skipping sidecar** (`rmp` task #331),
    /// opt-in via [`declare_zone_map`](Self::declare_zone_map), rebuilt from the store and maintained
    /// (widening) on write. In-memory, never persisted/recovered — a re-opened coordinator re-declares.
    zones: Rc<RefCell<crate::zone_map::ZoneMap>>,
    /// The **opt-in** type-bucketed CSR adjacency accelerator (`rmp` task #324, "Win 2"). `None` unless
    /// the [`csr_adjacency_enabled`](crate::read_source::csr_adjacency_enabled) knob is on at
    /// [`new`](Self::new) — so when off there is **zero** extra RAM and a typed `expand` behaves exactly
    /// as Win-1-only. When `Some`, it is built from the store on open (like [`Self::index`]) and handed
    /// to each statement seam; it is **marked stale** on the first relationship mutation and consulted
    /// only while fresh, falling back to the chain walk otherwise. Derived, in-memory, never recovered.
    csr: Option<Rc<RefCell<crate::csr_adjacency::CsrAdjacency>>>,
    /// Open transactions (begun, not yet committed/rolled back).
    active: HashMap<TxnId, ActiveTxn>,
    /// Monotonic transaction-id source (distinct from the commit timestamp, which the store issues).
    next_txn_id: u64,
    /// Queue of in-progress **non-blocking** index builds (`rmp` task #91), advanced in bounded
    /// chunks by [`advance_index_builds`](Self::advance_index_builds) between engine commands. The
    /// front build is the one currently being populated; each completes (durably promoted to
    /// [`IndexState::Online`]) before the next starts, so the queue is processed in declaration order.
    pending_builds: VecDeque<PendingIndexBuild>,
    /// Queue of in-progress **non-blocking** full-text index builds (`rmp` task #72), the analogue of
    /// [`pending_builds`](Self#structfield.pending_builds) for the inverted index, advanced by
    /// [`advance_index_builds`](Self::advance_index_builds) alongside the node-property builds.
    pending_fulltext_builds: VecDeque<PendingFulltextBuild>,
    /// Queue of in-progress **non-blocking** spatial (point) index builds (`rmp` task #98), the
    /// analogue of [`pending_fulltext_builds`](Self#structfield.pending_fulltext_builds) for the grid
    /// spatial index, advanced by [`advance_index_builds`](Self::advance_index_builds) alongside the
    /// other build kinds.
    pending_spatial_builds: VecDeque<PendingSpatialBuild>,
    /// Ticks still to skip before the next degraded-index rebuild attempt (`rmp` task #733), and the
    /// current backoff width. A `fail_closed` is usually transient, so the engine retries the rebuild
    /// from its tick ([`retry_degraded_index_rebuild`](TxnCoordinator::retry_degraded_index_rebuild))
    /// rather than staying scan-only until restart — but a rebuild is O(store), so a *persistent* fault
    /// must not re-scan every tick. The backoff doubles (1, 2, 4, … 1024) on each failed attempt and
    /// resets on success.
    degraded_retry_skip: u32,
    /// The current retry backoff width, in ticks — see
    /// [`degraded_retry_skip`](Self#structfield.degraded_retry_skip).
    degraded_retry_backoff: u32,
    /// Builds **poisoned** by a storage fault they could not get past (`rmp` task #733, M1): dropped from
    /// the pending queue un-promoted, so the engine terminates instead of spinning, but NOT thrown away.
    ///
    /// Poisoning used to be a one-way door: the index was left `Populating` (in memory *and* durably) with
    /// nothing in the process able to bring it back — `retry_degraded_index_rebuild` only runs while the
    /// set is degraded (which poisoning does not set), and the recovery promotion only runs in `new()`. So
    /// 32 unlucky chunks meant a dead index until someone restarted the server, with no log and no metric
    /// to say so. They are parked here instead and re-enqueued by
    /// [`retry_poisoned_index_builds`](Self::retry_poisoned_index_builds) once the store reads cleanly
    /// again.
    poisoned_builds: Vec<PendingIndexBuild>,
    /// Poisoned full-text builds — see [`poisoned_builds`](Self#structfield.poisoned_builds).
    poisoned_fulltext_builds: Vec<PendingFulltextBuild>,
    /// Poisoned spatial builds — see [`poisoned_builds`](Self#structfield.poisoned_builds).
    poisoned_spatial_builds: Vec<PendingSpatialBuild>,
    /// How many builds have been poisoned over this coordinator's life (`rmp` task #733, M1) — monotonic.
    /// The server samples it to log at `ERROR` and drive a metric: an index that quietly stopped being
    /// built is exactly the kind of degradation that otherwise passes for "healthy but slow".
    poison_events: u64,
    /// Drains still to skip before the next poisoned-build resurrection probe (`rmp` task #733) — the
    /// throttle that stops a permanently-broken store from making the engine re-scan every command. Its
    /// width comes from [`poison_backoff`] applied to
    /// [`poison_resurrect_attempts`](Self#structfield.poison_resurrect_attempts).
    poison_retry_skip: u32,
    /// How many times in a row a parked build has been **resurrected without completing** (`rmp` task
    /// #733, B2 — the fix for a defect the M1 resurrection introduced).
    ///
    /// A resurrection re-snapshots with `scan_node_ids` and re-enqueues every parked build. But that
    /// probe only reads the node *slot* pages — not the property / label pages a build actually indexes.
    /// A build poisoned by an unreadable **property** page therefore passes the probe, is resurrected,
    /// re-drains, hits the same page, and re-poisons — every tick, forever, at ~100% CPU (the very spin
    /// the stall budget was meant to end, re-introduced through the resurrection door). This counts the
    /// consecutive failed resurrections so the backoff can grow geometrically (`2^attempts`, capped),
    /// collapsing the retry *rate* toward zero; it resets to `0` the moment the graveyard clears (a
    /// resurrected build actually completed), so a genuinely-healed store returns to fast retries.
    poison_resurrect_attempts: u32,
}

/// The deterministic, stable **auto-name** for a node-property index on `(label, property)`
/// (`rmp` task #624).
///
/// Used both when a `CREATE INDEX` omits a name and when backfilling a legacy anonymous index on open.
/// Form: `index_<label>_<property>`, with each part sanitized to the identifier charset `[A-Za-z0-9_]`
/// (any other character → `_`). This is a **pure** function of its arguments, so the same
/// `(label, property)` always yields the same base name across restarts and rebuilds — which is what
/// makes a legacy index's backfilled name stable.
///
/// The base can collide — two distinct `(label, property)` pairs can sanitize to the same string, or
/// the base can equal an explicitly-declared name. [`TxnCoordinator`] resolves such a collision by
/// appending the deterministic token suffix `_<label_token>_<property_token>` (see
/// `unique_auto_index_name`); because the resolved name is then persisted durably, the resolution is
/// computed at most once and is stable thereafter.
#[must_use]
pub fn auto_index_name(label: &str, property: &str) -> String {
    format!(
        "index_{}_{}",
        sanitize_identifier(label),
        sanitize_identifier(property)
    )
}

/// The token namespace a constraint's covering name lives in (`rmp` #638): a node label for the
/// node kinds, a relationship type for the relationship kinds. Used by the `IF NOT EXISTS`
/// equivalence check to resolve the covering token in the right namespace.
fn constraint_covering_namespace(kind: ConstraintKind) -> Namespace {
    if kind.is_relationship() {
        Namespace::RelType
    } else {
        Namespace::Label
    }
}

/// Maps every character outside the identifier charset `[A-Za-z0-9_]` to `_`, so an auto-generated
/// index name is always a clean bare identifier (`rmp` task #624).
fn sanitize_identifier(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect()
}

/// Which schema catalog a name is being declared into, for the global name-uniqueness check
/// (`rmp` task #624). Names are unique across **all** catalogs; a `CREATE` rejects a name already used
/// by a *different* catalog while preserving each catalog's own re-declare (replace) semantics.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NameCatalog {
    /// The node-property index name catalog.
    NodeProperty,
    /// The relationship-property index name catalog (`rmp` task #646).
    RelProperty,
    /// The full-text index catalog.
    Fulltext,
    /// The spatial (point) index catalog.
    Spatial,
    /// The constraint catalog.
    Constraint,
    /// The composite (multi-property) node index catalog (`rmp` task #657).
    Composite,
    /// The composite (multi-property) relationship index catalog (`rmp` task #666).
    RelComposite,
    /// The text (trigram) node index catalog (`rmp` task #662).
    Text,
    /// The vector (HNSW) index catalog (`rmp` task #669).
    Vector,
}

/// A deterministic auto-name for the composite (multi-property) node index on `(label, properties)`
/// (`rmp` task #657) — the composite analogue of [`auto_index_name`]. Reuses the `index_` prefix and
/// appends each covered property in declared order (`index_<label>_<a>_<b>`), so the name is stable and
/// the covered tuple order is reflected in the name.
#[must_use]
pub fn auto_composite_index_name(label: &str, properties: &[String]) -> String {
    let mut name = format!("index_{}", sanitize_identifier(label));
    for property in properties {
        name.push('_');
        name.push_str(&sanitize_identifier(property));
    }
    name
}

/// A deterministic auto-name for the relationship-property index on `(rel_type, property)`
/// (`rmp` task #646) — the relationship analogue of [`auto_index_name`]. A distinct `rel_index_`
/// prefix keeps a rel index's auto-name from ever colliding with a node index's auto-name over the
/// same identifiers (they live in the one global name namespace).
#[must_use]
pub fn auto_rel_index_name(rel_type: &str, property: &str) -> String {
    format!(
        "rel_index_{}_{}",
        sanitize_identifier(rel_type),
        sanitize_identifier(property)
    )
}

/// A deterministic auto-name for the composite (multi-property) relationship index on
/// `(rel_type, properties)` (`rmp` task #666) — the relationship analogue of
/// [`auto_composite_index_name`]. The distinct `rel_index_` prefix keeps it from ever colliding with a
/// node composite's auto-name over the same identifiers; each covered property is appended in declared
/// order (`rel_index_<type>_<a>_<b>`), so the name is stable and reflects the covered tuple order.
#[must_use]
pub fn auto_rel_composite_index_name(rel_type: &str, properties: &[String]) -> String {
    let mut name = format!("rel_index_{}", sanitize_identifier(rel_type));
    for property in properties {
        name.push('_');
        name.push_str(&sanitize_identifier(property));
    }
    name
}

/// A deterministic auto-name for the **node** vector (HNSW) index on `(label, property)`
/// (`rmp` task #669). A distinct `vector_index_` prefix keeps it from ever colliding with any other
/// index kind's auto-name over the same identifiers (they share the one global name namespace).
#[must_use]
pub fn auto_vector_index_name(label: &str, property: &str) -> String {
    format!(
        "vector_index_{}_{}",
        sanitize_identifier(label),
        sanitize_identifier(property)
    )
}

/// A deterministic auto-name for the **relationship** vector (HNSW) index on `(rel_type, property)`
/// (`rmp` task #669) — the relationship analogue of [`auto_vector_index_name`]. The distinct
/// `vector_rel_index_` prefix keeps it from ever colliding with a node vector index's auto-name over
/// the same identifiers.
#[must_use]
pub fn auto_vector_rel_index_name(rel_type: &str, property: &str) -> String {
    format!(
        "vector_rel_index_{}_{}",
        sanitize_identifier(rel_type),
        sanitize_identifier(property)
    )
}

/// Maps a durable [`VectorSimilarity`] discriminant to the in-memory `graphus_index::Similarity`
/// (`rmp` task #669). Storage does not depend on `graphus-index`, so the metric is stored as its own
/// byte enum and translated here when the query layer (re)builds the HNSW graph.
#[must_use]
fn similarity_from_storage(similarity: VectorSimilarity) -> Similarity {
    match similarity {
        VectorSimilarity::Cosine => Similarity::Cosine,
        VectorSimilarity::Euclidean => Similarity::Euclidean,
    }
}

impl<D: BlockDevice, S: LogSink> TxnCoordinator<D, S> {
    /// A coordinator over `store` with no open transactions.
    ///
    /// The derived [`IndexSet`] is built empty and then **rebuilt** from `store` so it is consistent
    /// with the persisted graph by construction (`rmp` task #48). Over a freshly-recovered store this
    /// is precisely the crash-recovery requirement: a new coordinator's index reflects exactly the
    /// recovered, committed graph — nothing to commit or replay for the index itself.
    ///
    /// # Resuming an interrupted non-blocking build (the `rmp` task #91 crash path)
    ///
    /// A non-blocking index build ([`begin_online_node_property_index`](Self::begin_online_node_property_index))
    /// records its catalog entry durably as [`IndexState::Populating`] and only flips it to
    /// [`IndexState::Online`] once every snapshot node is indexed. If a crash interrupts a build, its
    /// catalog entry recovers `Populating`. But `rebuild_index` above has just **synchronously and
    /// fully** repopulated *every registered index* — `Populating` ones included — from the recovered
    /// store, so an interrupted build is now actually complete. We therefore **promote every
    /// durable-`Populating` index to `Online`** here, in one committed transaction, and mirror the
    /// promotion in the in-memory set. Startup is allowed to block: the server is not yet serving when
    /// the coordinator is constructed (see `graphus_server::engine::spawn_engine`). After this, no
    /// build is left pending — they either completed online before the crash or are completed by the
    /// rebuild here.
    #[must_use]
    pub fn new(store: RecordStore<D, S>) -> Self {
        // Seed the transaction-id counter **past** every id already in the durable WAL. Transaction
        // ids are written into the WAL but are not otherwise persisted, so a reopened coordinator that
        // restarted its counter from `0` would reuse ids from before the crash. A reused id is fatal to
        // ARIES recovery: a later crash's analysis collapses both incarnations into one
        // Active-Transaction-Table entry, and if the post-recovery incarnation committed, the pre-crash
        // *uncommitted* incarnation stops being classified as a loser — its redone effects are never
        // undone and an uncommitted record survives (an atomicity violation). Resuming past the
        // recovered high-water keeps ids globally unique across recovery. (`0` for a fresh store.)
        let recovered_txn_hw = store.recovered_txn_hw();
        let store = Rc::new(RefCell::new(store));
        let index = Rc::new(RefCell::new(IndexSet::new()));
        Self::rebuild_index(&store, &index);
        // Promote any index left `Populating` by an interrupted `rmp` task #91 build: the rebuild
        // above already fully populated it from the recovered store, so it is complete. Minted from the
        // recovered id high-water so even the promotion transaction never reuses a pre-crash id.
        let next_txn_id =
            Self::promote_recovered_populating_indexes(&store, &index, recovered_txn_hw);
        // Backfill a deterministic, durable auto-name for every declared node-property index that has
        // none — a **legacy anonymous** index persisted before named indexes existed (`rmp` task #624).
        // After this, every declared index is named end-to-end (droppable by name, listed with a name in
        // `SHOW INDEXES`), and the name is stable across restarts because it is now durable.
        let next_txn_id = Self::backfill_recovered_index_names(&store, next_txn_id);
        // The opt-in CSR adjacency (`rmp` #324, Win 2): built from the store on open ONLY when the knob
        // is enabled, so the default (off) path allocates nothing. Like the index it is derived and
        // never recovered — a fresh coordinator over a recovered store rebuilds a store-consistent CSR.
        let csr = if crate::read_source::csr_adjacency_enabled() {
            let mut adjacency = crate::csr_adjacency::CsrAdjacency::empty();
            adjacency.build_from_store(&store.borrow());
            Some(Rc::new(RefCell::new(adjacency)))
        } else {
            None
        };
        Self {
            store,
            ssi: Rc::new(RefCell::new(SsiTracker::new())),
            locks: Rc::new(RefCell::new(LockTable::new())),
            index,
            // The columnar cache starts with no declared columns; a column is declared (and then
            // captured) via `declare_columnar_cache`. Derived/in-memory, never recovered (`rmp` #329),
            // so a fresh coordinator over a recovered store simply re-declares + re-captures as asked.
            columns: Rc::new(RefCell::new(crate::column_cache::ColumnCache::new())),
            // The zone-map data-skipping sidecar (`rmp` #331) likewise starts empty; columns are
            // declared via `declare_zone_map` and rebuilt from the store, derived/never-recovered.
            zones: Rc::new(RefCell::new(crate::zone_map::ZoneMap::new())),
            csr,
            active: HashMap::new(),
            next_txn_id,
            pending_builds: VecDeque::new(),
            pending_fulltext_builds: VecDeque::new(),
            pending_spatial_builds: VecDeque::new(),
            degraded_retry_skip: 0,
            degraded_retry_backoff: 1,
            poisoned_builds: Vec::new(),
            poisoned_fulltext_builds: Vec::new(),
            poisoned_spatial_builds: Vec::new(),
            poison_events: 0,
            poison_retry_skip: 0,
            poison_resurrect_attempts: 0,
        }
    }

    /// Promotes every durable-[`IndexState::Populating`] node-property index to
    /// [`IndexState::Online`] (catalog + in-memory set), in one committed transaction minted from
    /// `next_txn_id`. Returns the advanced `next_txn_id` (so [`new`](Self::new) keeps its monotonic
    /// id source consistent). A no-op (no commit) when no index is `Populating`.
    ///
    /// This is the crash-recovery completion of an interrupted non-blocking build (`rmp` task #91):
    /// by the time this runs the rebuild has already fully populated the in-memory index, so the
    /// durable state simply needs to catch up. The candidate-set contract makes this sound regardless:
    /// even if some node were missed, a seek re-checks the store, so promoting can only ever expose a
    /// fully-populated index. Errors interning/committing are swallowed best-effort: a failed promotion
    /// leaves the index `Populating` (withheld from the planner, scan-and-filter fallback stays
    /// correct), to be retried on the next open.
    fn promote_recovered_populating_indexes(
        store: &Rc<RefCell<RecordStore<D, S>>>,
        index: &Rc<RefCell<IndexSet>>,
        next_txn_id: u64,
    ) -> u64 {
        // The whole premise of this promotion is the sentence above: *"the rebuild has already fully
        // populated it from the recovered store, so it is complete"*. When the open-time rebuild **failed
        // closed** that premise is false — the trees are empty or holed and every index was demoted — so
        // promoting anything now would publish `Online`, durably and in memory, an index with no rows in
        // it (`rmp` task #733).
        //
        // That is the whole `rmp` #733 defect, resurrected on the recovery path, and it is worse here:
        // the flip is DURABLE, so it also survives the restart that would otherwise have repaired it. The
        // planner would route a real `NodeIndexSeek` at the empty tree (committed rows invisible), and
        // `unique_conflict` — which trusts that tree as an EXACT candidate source — would let an
        // `IS UNIQUE` constraint accept a duplicate. It further defeated the `SHOW INDEXES` effective-
        // state machinery, which trusts the in-memory state this would have just falsified.
        //
        // Abort: leave every index `Populating` (withheld from the planner, and now honestly reported),
        // let the degraded rebuild retry repair the trees, and promote on a later open.
        if index.borrow().is_degraded() {
            return next_txn_id;
        }
        let populating: Vec<(u32, u32)> = store
            .borrow()
            .node_property_indexes()
            .into_iter()
            .filter(|(_, _, state)| *state == IndexState::Populating)
            .map(|(label_token, prop_key, _)| (label_token, prop_key))
            .collect();
        // Full-text indexes left `Populating` by an interrupted `rmp` task #72 build are promoted the
        // same way — the rebuild above has already fully repopulated their inverted index from the
        // recovered store, so the durable state just needs to catch up.
        let populating_fulltext: Vec<(String, FulltextIndexEntry)> = store
            .borrow()
            .fulltext_indexes()
            .into_iter()
            .filter(|(_, entry)| entry.state == IndexState::Populating)
            .collect();
        // Spatial indexes left `Populating` by an interrupted `rmp` task #98 build are promoted the
        // same way — the rebuild above has already fully repopulated their grid from the recovered
        // store, so the durable state just needs to catch up.
        let populating_spatial: Vec<(String, SpatialIndexEntry)> = store
            .borrow()
            .spatial_indexes()
            .into_iter()
            .filter(|(_, entry)| entry.state == IndexState::Populating)
            .collect();
        if populating.is_empty() && populating_fulltext.is_empty() && populating_spatial.is_empty()
        {
            return next_txn_id;
        }

        let txn = TxnId(next_txn_id + 1);
        store.borrow_mut().begin(txn);
        {
            let mut store = store.borrow_mut();
            for &(label_token, prop_key) in &populating {
                store.set_node_property_index(label_token, prop_key, IndexState::Online);
            }
            for (name, entry) in &populating_fulltext {
                store.set_fulltext_index(
                    name.clone(),
                    FulltextIndexEntry {
                        state: IndexState::Online,
                        ..entry.clone()
                    },
                );
            }
            for (name, entry) in &populating_spatial {
                store.set_spatial_index(
                    name.clone(),
                    SpatialIndexEntry {
                        state: IndexState::Online,
                        ..entry.clone()
                    },
                );
            }
        }
        if store.borrow_mut().commit(txn).is_err() {
            // Could not make the promotion durable; leave the indexes `Populating` (still correct via
            // the scan fallback) and reconcile on the next open.
            return next_txn_id + 1;
        }
        let mut idx = index.borrow_mut();
        for (label_token, prop_key) in populating {
            idx.set_node_property_state(label_token, prop_key, IndexState::Online);
        }
        for (name, _) in populating_fulltext {
            idx.set_fulltext_state(&name, IndexState::Online);
        }
        for (_, entry) in populating_spatial {
            // Route by entity (`rmp` task #664): a relationship point index promotes in the rel-keyed
            // map. (Relationship point indexes are created synchronous-`Online`, so in practice they are
            // never left `Populating` — this stays correct if one ever were.)
            if entry.entity.is_relationship() {
                idx.set_spatial_rel_state(
                    entry.label_token,
                    entry.property_token,
                    IndexState::Online,
                );
            } else {
                idx.set_spatial_state(entry.label_token, entry.property_token, IndexState::Online);
            }
        }
        next_txn_id + 1
    }

    /// Backfills a deterministic, durable **auto-name** for every declared node-property index that has
    /// none — a **legacy anonymous** index persisted before named indexes existed (`rmp` task #624). One
    /// committed transaction minted from `next_txn_id`; returns the advanced `next_txn_id`. A no-op (no
    /// commit) when every declared index is already named — so after the first migration this is free.
    ///
    /// The name assigned to each index is [`unique_auto_index_name`](Self::unique_auto_index_name),
    /// which resolves a base-name collision by a deterministic token suffix. Because each assignment is
    /// applied to the store *before* the next index's name is computed, two legacy indexes whose bases
    /// collide are disambiguated deterministically (the ascending `(label_token, prop_key)` iteration
    /// order is stable). Once persisted here, every name is read back verbatim on the next open, so the
    /// migration is stable regardless.
    ///
    /// Errors interning/committing are swallowed best-effort: a failed backfill leaves the affected
    /// indexes nameless (reconciled on the next open), and [`list_node_property_indexes`]
    /// (Self::list_node_property_indexes) falls back to the freshly-computed auto-name meanwhile, so
    /// reads stay correct. Startup is allowed to block (the engine is not yet serving).
    fn backfill_recovered_index_names(
        store: &Rc<RefCell<RecordStore<D, S>>>,
        next_txn_id: u64,
    ) -> u64 {
        // Which declared node-property indexes carry no durable name? (Legacy anonymous indexes.)
        let nameless: Vec<(u32, u32)> = {
            let store = store.borrow();
            store
                .node_property_indexes()
                .into_iter()
                .filter(|(lt, pk, _)| store.node_property_index_name_for(*lt, *pk).is_none())
                .map(|(lt, pk, _)| (lt, pk))
                .collect()
        };
        if nameless.is_empty() {
            return next_txn_id;
        }

        let txn = TxnId(next_txn_id + 1);
        store.borrow_mut().begin(txn);
        {
            let mut store = store.borrow_mut();
            for (label_token, prop_key) in nameless {
                // Resolve the tokens to names; skip (leave nameless, retried next open) if a token has no
                // resolvable name — a defensive impossibility for a live token.
                let (Some(label), Some(property)) = (
                    store
                        .token_name(Namespace::Label, label_token)
                        .map(str::to_owned),
                    store
                        .token_name(Namespace::PropKey, prop_key)
                        .map(str::to_owned),
                ) else {
                    continue;
                };
                // Compute against the *current* store state (including names assigned earlier in this
                // same pass) so colliding bases are disambiguated deterministically.
                let name =
                    Self::unique_auto_index_name(&store, &label, &property, label_token, prop_key);
                store.set_node_property_index_name(name, label_token, prop_key);
            }
        }
        // The txn advanced an id whether or not the commit lands (mirrors the promote path). A failed
        // backfill commit is a best-effort no-op that self-heals: the auto-names stay in memory for
        // this session and are recomputed (identically, being a pure function of durable tokens) on
        // the next open, so a startup I/O error here never corrupts the catalog (`rmp` #624 audit,
        // LOW). Reads remain correct meanwhile; only DROP-by-auto-name would miss until the reopen.
        // Surface the durability event to stderr for observability rather than swallowing it silently
        // (startup only — the engine is not yet serving; the core crate carries no logging facade, so
        // this matches the top-level `graphus-server` fault convention).
        if let Err(e) = store.borrow_mut().commit(txn) {
            eprintln!(
                "graphus-cypher: WARN best-effort node-property index name backfill commit failed \
                 (auto-names stay in memory, recomputed on next open): {e}"
            );
        }
        next_txn_id + 1
    }

    /// Reloads the durable node-property index catalog into `index` (`rmp` task #90), then clears and
    /// repopulates `index` from every in-use node in `store` (`rmp` task #48): each node's label
    /// tokens go into the label index, and for each **registered** node-property index the node
    /// matches, its current property value is inserted.
    ///
    /// # Durable registration reload (the crash-recovery fix, `rmp` task #90)
    ///
    /// The set of declared node-property indexes is recovered from the store's durable index catalog
    /// **before** the rebuild scan, so a fresh coordinator over a recovered store re-registers exactly
    /// the indexes that were committed — no manual re-registration after recovery. A catalog entry
    /// recorded `Online` is registered `Online`; a `Populating` one is registered, populated by the
    /// scan below, and — since population is synchronous in this task — left registered (its promotion
    /// to `Online` is the coordinator's caller path; `rmp` task #91 owns the non-blocking flip). Any
    /// indexes already registered in `index` (e.g. one just declared via
    /// [`create_node_property_index`](Self::create_node_property_index)) are preserved: the reload only
    /// *adds* the durable set, and [`IndexSet::register_node_property_with_state`] is idempotent.
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
    ///
    /// A fault on a **whole scan** (nodes or relationships) is different in kind: the rebuild cannot be
    /// completed, and since [`IndexSet::clear`] has already dropped every entry, the indexes would be
    /// left registered, `Online` and **empty** — silently answering every seek with zero rows. Such a
    /// fault therefore **fails closed** via [`IndexSet::fail_closed`], which makes every index unusable
    /// (not merely empty) so all consumers degrade to the always-correct store scan (`rmp` task #733).
    /// This matters at run time, not just on open: `rebuild_index` is also driven by index / constraint
    /// DDL.
    fn rebuild_index(store: &Rc<RefCell<RecordStore<D, S>>>, index: &Rc<RefCell<IndexSet>>) {
        // Recover the durable index catalog (`rmp` task #90) into the in-memory set first: this is
        // what makes registration survive a crash. Done before `clear` (which keeps the registered set
        // but wipes entries) so the rebuild scan below indexes the recovered indexes too.
        let durable: Vec<(u32, u32, IndexState)> = store.borrow().node_property_indexes();
        {
            let mut idx = index.borrow_mut();
            for (label_token, prop_key, state) in durable {
                idx.register_node_property_with_state(label_token, prop_key, state);
            }
        }

        // Recover the durable relationship-property index catalog (`rmp` task #646) the same way: a
        // fresh coordinator over a recovered store re-registers exactly the rel-property indexes that
        // were committed, so their backing trees are repopulated by the rel scan below.
        let durable_rel: Vec<(u32, u32, IndexState)> = store.borrow().rel_property_indexes();
        {
            let mut idx = index.borrow_mut();
            for (type_token, prop_key, state) in durable_rel {
                idx.register_rel_property_with_state(type_token, prop_key, state);
            }
        }

        // Recover the durable full-text index catalog (`rmp` task #72) the same way: register each
        // declared index in the in-memory set (analyzer + covered label/properties), so the rebuild
        // scan below populates its inverted index. An entry whose analyzer byte is unknown
        // (forward-incompatible) is skipped defensively — its inverted index stays empty and the
        // procedure surface returns no matches rather than mis-analyzing.
        let durable_fulltext: Vec<(String, FulltextIndexEntry)> = store.borrow().fulltext_indexes();
        {
            let mut idx = index.borrow_mut();
            for (name, entry) in durable_fulltext {
                let Some(analyzer) = Analyzer::from_byte(entry.analyzer) else {
                    continue;
                };
                // Route by entity (`rmp` task #663): a node index registers into the node full-text map
                // (covered by labels), a relationship index into the separate relationship full-text map
                // (covered by rel types). The rebuild scan below repopulates whichever inverted index
                // was registered here.
                if entry.entity.is_relationship() {
                    idx.register_fulltext_rel(
                        &name,
                        entry.tokens,
                        entry.property_tokens,
                        analyzer,
                        entry.state,
                    );
                } else {
                    idx.register_fulltext(
                        &name,
                        entry.tokens,
                        entry.property_tokens,
                        analyzer,
                        entry.state,
                    );
                }
            }
        }

        // Recover the durable spatial index catalog (`rmp` task #98) the same way: register each
        // declared index's grid in the in-memory set (covered label/property + state), so the rebuild
        // scan below repopulates the grid. A spatial index has no analyzer to validate; it is keyed by
        // `(label_token, prop_key)` in the `IndexSet` (the catalog's `name` is the durable identifier).
        let durable_spatial: Vec<(String, SpatialIndexEntry)> = store.borrow().spatial_indexes();
        {
            let mut idx = index.borrow_mut();
            for (_name, entry) in durable_spatial {
                // Route by entity (`rmp` task #664): a node point index registers into the node-keyed
                // spatial map (covered by labels), a relationship point index into the separate
                // relationship-keyed spatial map (covered by rel types). The rebuild scan below
                // repopulates whichever grid was registered here.
                if entry.entity.is_relationship() {
                    idx.register_spatial_rel(
                        entry.label_token,
                        entry.property_token,
                        graphus_index::DEFAULT_CELL_SIZE,
                        entry.state,
                    );
                } else {
                    idx.register_spatial(
                        entry.label_token,
                        entry.property_token,
                        graphus_index::DEFAULT_CELL_SIZE,
                        entry.state,
                    );
                }
            }
        }

        // Recover the durable constraint catalog (`rmp` tasks #99, #100) the same way: register each
        // declared constraint's rule (carrying its type descriptor) in the in-memory set, and register
        // the right backing index so the write-path duplicate check stays index-accelerated after a
        // crash:
        //   - UNIQUENESS  → a node-property index on its single `(label, property)` at `Online`;
        //   - NODE KEY    → a COMPOSITE index over its whole `(label, property tuple)`.
        // Existence and property-type need no backing index (pure per-node predicates). The rebuild
        // scan below repopulates whichever backing indexes were registered here.
        let durable_constraints: Vec<(String, ConstraintEntry)> = store.borrow().constraints();
        {
            let mut idx = index.borrow_mut();
            for (name, entry) in durable_constraints {
                idx.register_constraint(
                    &name,
                    entry.label_token,
                    entry.property_tokens.clone(),
                    entry.kind,
                    entry.type_descriptor.clone(),
                );
                match entry.kind {
                    ConstraintKind::Unique => {
                        if let [prop_key] = entry.property_tokens.as_slice() {
                            idx.register_node_property_with_state(
                                entry.label_token,
                                *prop_key,
                                IndexState::Online,
                            );
                        }
                    }
                    ConstraintKind::NodeKey => {
                        idx.register_composite(entry.label_token, entry.property_tokens.clone());
                    }
                    ConstraintKind::RelUnique => {
                        // A relationship uniqueness constraint (`rmp` #638) is backed by a
                        // relationship-property index on its single `(type, property)` (`rmp` task #646),
                        // so the write-time duplicate check is index-accelerated after a crash (the rel
                        // scan below repopulates it). The covering token is a relationship-**type** token.
                        if let [prop_key] = entry.property_tokens.as_slice() {
                            idx.register_rel_property_with_state(
                                entry.label_token,
                                *prop_key,
                                IndexState::Online,
                            );
                        }
                    }
                    // No backing index: pure per-entity predicates, plus RelKey / RelPropertyType which
                    // stay scan-based (a relationship COMPOSITE index is deferred; RelPropertyType is a
                    // pure per-relationship predicate).
                    ConstraintKind::Existence
                    | ConstraintKind::PropertyType
                    | ConstraintKind::RelExistence
                    | ConstraintKind::RelKey
                    | ConstraintKind::RelPropertyType => {}
                }
            }
        }

        // Register every durable **standalone composite index** (`rmp` task #657) in the in-memory set,
        // so the write path maintains it and the rebuild scan below repopulates its backing tree. This
        // is distinct from a node-key constraint's backing composite (registered above): a standalone
        // composite enforces no uniqueness. It is recorded `Online` in the durable catalog (a synchronous
        // build), so recovery repopulates a fully-online index, never a half-built one. The in-memory
        // composite map is keyed by `(label_token, property tuple)`, so a standalone composite and a
        // node key over the *same* tuple share one backing tree — always correct (both are pure
        // candidate sources re-checked against the store).
        let durable_composites: Vec<(String, CompositeIndexEntry)> =
            store.borrow().composite_indexes();
        {
            let mut idx = index.borrow_mut();
            for (_name, entry) in durable_composites {
                idx.register_composite(entry.label_token, entry.property_tokens);
            }
        }

        // Register every durable **standalone composite relationship index** (`rmp` task #666) in the
        // in-memory set, so the write path maintains it and the rebuild scan below repopulates its
        // backing tree — the relationship analogue of the node composite registration above. It is
        // recorded `Online` in the durable catalog (a synchronous build), so recovery repopulates a
        // fully-online index. Keyed by `(type_token, property tuple)` in the separate `rel_composite`
        // map (a numeric collision between a label token and a rel-type token never mixes the two).
        let durable_rel_composites: Vec<(String, RelCompositeIndexEntry)> =
            store.borrow().rel_composite_indexes();
        {
            let mut idx = index.borrow_mut();
            for (_name, entry) in durable_rel_composites {
                idx.register_rel_composite(entry.type_token, entry.property_tokens);
            }
        }

        // Register every durable **text (trigram) index** (`rmp` task #662) in the in-memory set, so the
        // write path maintains it and the rebuild scan below repopulates its trigram index. It is
        // recorded `Online` in the durable catalog (a synchronous build), so recovery repopulates a
        // fully-online index, never a half-built one. Keyed by `(label_token, prop_key)`, like spatial.
        let durable_text: Vec<(String, TextIndexEntry)> = store.borrow().text_indexes();
        {
            let mut idx = index.borrow_mut();
            for (_name, entry) in durable_text {
                idx.register_text(entry.label_token, entry.property_token, IndexState::Online);
            }
        }

        // Register every durable **vector (HNSW) index** (`rmp` task #669) in the in-memory set BEFORE
        // the rebuild scan below, so the write path maintains it and the scan repopulates its ANN graph.
        // It is recorded `Online` in the durable catalog (a synchronous build), so recovery repopulates a
        // fully-online index. Route by entity: a node index into the node-keyed `vector` map (covered by
        // labels), a relationship index into the separate rel-keyed `vector_rel` map (covered by rel
        // types). The declared dimension / similarity / m / ef_construction come straight from the durable
        // entry, so the rebuilt graph has exactly the shape the create recorded.
        let durable_vector: Vec<(String, VectorIndexEntry)> = store.borrow().vector_indexes();
        {
            let mut idx = index.borrow_mut();
            for (_name, entry) in durable_vector {
                let similarity = similarity_from_storage(entry.similarity);
                if entry.entity.is_relationship() {
                    idx.register_vector_rel(
                        entry.token,
                        entry.property_token,
                        entry.dimensions as usize,
                        similarity,
                        entry.m as usize,
                        entry.ef_construction as usize,
                        entry.state,
                    );
                } else {
                    idx.register_vector(
                        entry.token,
                        entry.property_token,
                        entry.dimensions as usize,
                        similarity,
                        entry.m as usize,
                        entry.ef_construction as usize,
                        entry.state,
                    );
                }
            }
        }

        index.borrow_mut().clear();
        // Re-register every bitmap column this session declared (`rmp` task #733, M2). A bitmap is opt-in
        // and has NO durable catalog entry, so unlike every other kind it cannot be recovered from the
        // store — a fail-closed retires the live index and only this brings it back. The scan below then
        // repopulates it (it is in `registered_bitmap()` again).
        index.borrow_mut().reregister_declared_bitmaps();

        // The set of registered node-property indexes (any state), captured before walking the store so
        // the index is not borrowed across a store borrow. A `Populating` index is maintained too (so
        // its entries are ready the instant it is promoted), so the rebuild reads the full set here;
        // the planner only ever sees the `Online` subset via `catalog()`.
        let registered: Vec<(u32, u32)> = index.borrow().registered_node_properties();

        let node_ids = match store.borrow_mut().scan_node_ids() {
            Ok(ids) => ids,
            // A store-read fault on the whole scan means the rebuild CANNOT be completed. `clear()`
            // above already dropped every index's entries, so at this point every index is registered,
            // still `Online` — and EMPTY. That is the most dangerous state the engine can be in
            // (`rmp` task #733): the planner keeps routing seeks to those indexes, the write path keeps
            // consulting them for uniqueness / node-key duplicate detection, and the full-text /
            // vector procedures keep reading their postings — all returning ZERO rows, silently. (This
            // is not a recovery-only path: `rebuild_index` also runs at run time from five DDL
            // call sites, so a transient I/O fault during a `CREATE INDEX` could wipe the process's
            // in-memory indexes and serve wrong answers until restart.)
            //
            // So fail **closed**: make every index unusable rather than empty. `fail_closed` demotes
            // the state-carrying kinds out of `Online` (withdrawing them from the planner's catalog and
            // from every read seam, which since `rmp` #733 declines unless `Online`), unregisters the
            // state-less candidate sources (composite / bitmap), and poisons the full-text/spatial
            // freshness marker. Every consumer then degrades to the always-correct store scan — the
            // outcome the old comment here CLAIMED but did not deliver. The durable catalog is
            // untouched, so the schema survives and the next successful rebuild (any index/constraint
            // DDL, or reopening the store) restores the fast paths.
            Err(_) => {
                index.borrow_mut().fail_closed();
                return;
            }
        };

        let has_fulltext = !index.borrow().registered_fulltext().is_empty();
        // The registered spatial index keys `(label_token, prop_key)`, captured before the scan so the
        // index is not borrowed across a store borrow (`rmp` task #98).
        let registered_spatial: Vec<(u32, u32)> = index.borrow().registered_spatial();
        // The registered text (trigram) index keys `(label_token, prop_key)` (`rmp` task #662), captured
        // before the scan so the index is not borrowed across a store borrow.
        let registered_text: Vec<(u32, u32)> = index.borrow().registered_text();
        // The registered node vector index keys `(label_token, prop_key)` (`rmp` task #669), captured
        // before the scan so the index is not borrowed across a store borrow.
        let registered_vector: Vec<(u32, u32)> = index.borrow().registered_vector();
        // The registered composite index keys `(label_token, property tuple)` — a node-key constraint's
        // backing index (`rmp` task #100). Captured before the scan so the index is not borrowed across
        // a store borrow.
        let registered_composite: Vec<(u32, Vec<u32>)> = index.borrow().registered_composite();
        // The registered bitmap (low-cardinality) index keys (`rmp` task #328), captured before the
        // scan like the others. The bitmap is membership-exact, so the rebuild re-captures it whole.
        let registered_bitmap: Vec<(u32, u32)> = index.borrow().registered_bitmap();
        for id in node_ids {
            Self::index_one_node(store, index, id, &registered);
            // Repopulate the full-text inverted indexes from the same scan (`rmp` task #72), so a
            // recovered store rebuilds them store-consistently — only when at least one is declared.
            if has_fulltext {
                Self::index_one_node_fulltext(store, index, id);
            }
            // Repopulate the spatial grids from the same scan (`rmp` task #98), only when at least one
            // is declared.
            if !registered_spatial.is_empty() {
                Self::index_one_node_spatial(store, index, id, &registered_spatial);
            }
            // Repopulate the text (trigram) indexes from the same scan (`rmp` task #662), only when at
            // least one is declared.
            if !registered_text.is_empty() {
                Self::index_one_node_text(store, index, id, &registered_text);
            }
            // Repopulate the vector (HNSW) indexes from the same scan (`rmp` task #669), only when at
            // least one is declared.
            if !registered_vector.is_empty() {
                Self::index_one_node_vector(store, index, id, &registered_vector);
            }
            // Repopulate the composite indexes from the same scan (`rmp` task #100), only when at least
            // one node-key constraint is declared.
            if !registered_composite.is_empty() {
                Self::index_one_node_composite(store, index, id, &registered_composite);
            }
            // Repopulate the bitmap indexes from the same scan (`rmp` task #328), only when at least
            // one low-cardinality column is declared.
            if !registered_bitmap.is_empty() {
                Self::index_one_node_bitmap(store, index, id, &registered_bitmap);
            }
        }

        // Repopulate the relationship-property indexes (`rmp` task #646) and the relationship full-text
        // indexes (`rmp` task #663) from a relationship scan — but only when at least one of either is
        // declared, so a store with no relationship index pays nothing for the extra walk. Captured
        // before the scan so the index is not borrowed across a store borrow.
        let registered_rel: Vec<(u32, u32)> = index.borrow().registered_rel_properties();
        let has_rel_fulltext = index.borrow().has_any_fulltext_rel();
        // The registered relationship spatial index keys `(type_token, prop_key)` (`rmp` task #664),
        // captured before the scan so the index is not borrowed across a store borrow.
        let registered_rel_spatial: Vec<(u32, u32)> = index.borrow().registered_spatial_rel();
        // The registered composite relationship index keys `(type_token, property tuple)` (`rmp` task
        // #666), captured before the scan like the others.
        let registered_rel_composite: Vec<(u32, Vec<u32>)> =
            index.borrow().registered_rel_composite();
        // The registered relationship vector index keys `(type_token, prop_key)` (`rmp` task #669),
        // captured before the scan like the others.
        let registered_rel_vector: Vec<(u32, u32)> = index.borrow().registered_vector_rel();
        // A store-read fault enumerating the relationships **fails closed**, exactly like the node scan
        // above (`rmp` task #733): the relationship indexes would otherwise be left registered,
        // `Online` and EMPTY, silently answering every relationship seek / relationship full-text query
        // with zero rows. `fail_closed` is deliberately **total** (it demotes the node indexes too, not
        // just the relationship ones): a whole-scan storage fault means the store itself is faulting, so
        // preserving the node fast paths would only buy speed in a database that is already broken —
        // and a second, partial fail-closed mode is more surface to get wrong. Per-relationship read
        // faults inside `index_one_rel*` still skip that relationship best-effort (a missing candidate
        // in a *populated* index degrades that reader to a re-check, never to a wrong row).
        let needs_rel_scan = !registered_rel.is_empty()
            || has_rel_fulltext
            || !registered_rel_spatial.is_empty()
            || !registered_rel_composite.is_empty()
            || !registered_rel_vector.is_empty();
        if needs_rel_scan {
            let rel_ids = match store.borrow().scan_rel_ids() {
                Ok(ids) => ids,
                Err(_) => {
                    index.borrow_mut().fail_closed();
                    return;
                }
            };
            for id in rel_ids {
                if !registered_rel.is_empty() {
                    Self::index_one_rel(store, index, id, &registered_rel);
                }
                // Repopulate the relationship full-text inverted indexes (`rmp` task #663), only when at
                // least one is declared.
                if has_rel_fulltext {
                    Self::index_one_rel_fulltext(store, index, id);
                }
                // Repopulate the relationship spatial grids (`rmp` task #664), only when at least one is
                // declared.
                if !registered_rel_spatial.is_empty() {
                    Self::index_one_rel_spatial(store, index, id, &registered_rel_spatial);
                }
                // Repopulate the composite relationship indexes (`rmp` task #666), only when at least one
                // is declared.
                if !registered_rel_composite.is_empty() {
                    Self::index_one_rel_composite(store, index, id, &registered_rel_composite);
                }
                // Repopulate the relationship vector (HNSW) indexes (`rmp` task #669), only when at least
                // one is declared.
                if !registered_rel_vector.is_empty() {
                    Self::index_one_rel_vector(store, index, id, &registered_rel_vector);
                }
            }
        }

        // Did the rebuild have to SKIP an entity it could not read (`rmp` task #733)? The per-entity
        // helpers are best-effort, but "best effort" is not good enough while an index is being built:
        // an entity they skipped is absent from the label index (invisible to every `MATCH (n:Label)`)
        // and from every property index (invisible to every seek), and no re-check can resurrect it —
        // a committed row silently lost to queries for the life of the process. An index we know to be
        // an incomplete image of the store must not be published, so fail closed exactly as a failed
        // whole-scan does. (Empirically caught by the fault-injection sweep in
        // `tests/index_fail_closed.rs`: a single transient read fault inside the loop above used to
        // drop one node from the label index, and a plain `MATCH (a:Article)` then returned 299 of 300
        // rows — silently.)
        if index.borrow().rebuild_gap() {
            index.borrow_mut().fail_closed();
            return;
        }

        // Reset the cross-snapshot full-text/spatial freshness marker (`rmp` task #467). The rebuild
        // above re-inserted every full-text/spatial posting via the instrumented mutation methods,
        // which raised the transient dirty flag (and, on the recovery/DDL paths, may have to clear a
        // prior poison); the rebuilt index now reflects exactly the committed store state at the
        // current high-water. Stamp the marker to that high-water so a reader at-or-after it trusts the
        // index (index == committed state) and an older reader conservatively declines to the scan
        // path — and discard the build's dirty flag so it does not leak into the next user statement.
        let high_water = store.borrow().snapshot_ts();
        index.borrow_mut().reset_ft_spatial_marker(high_water);
        // The rebuild completed with no whole-scan fault and no per-entity gap: the index set is once
        // again a faithful image of the store, so a previous `fail_closed` is repaired (`rmp` task #733).
        // This is what lets a process self-heal from a *transient* storage fault instead of serving
        // scan-only (and reporting itself degraded) until it is restarted.
        index.borrow_mut().heal();
    }

    /// Whether `name` is already used by **any** schema catalog — a node-property index name, a
    /// full-text index, a spatial index, or a constraint (`rmp` task #624). The global name-uniqueness
    /// predicate a named `CREATE INDEX` consults before recording its name.
    fn name_in_use(store: &RecordStore<D, S>, name: &str) -> bool {
        store.node_property_index_name(name).is_some()
            || store.rel_property_index_name(name).is_some()
            || store.fulltext_index(name).is_some()
            || store.spatial_index(name).is_some()
            || store.constraint(name).is_some()
            || store.composite_index(name).is_some()
            || store.rel_composite_index(name).is_some()
            || store.text_index(name).is_some()
            || store.vector_index(name).is_some()
    }

    /// Whether `name` is used by a schema catalog **other than** `own` (`rmp` task #624). Lets a
    /// `CREATE` in the `own` catalog reject a cross-catalog name collision while preserving that
    /// catalog's own re-declare (replace) semantics for a name it already owns.
    fn name_used_by_other_catalog(store: &RecordStore<D, S>, name: &str, own: NameCatalog) -> bool {
        (own != NameCatalog::NodeProperty && store.node_property_index_name(name).is_some())
            || (own != NameCatalog::RelProperty && store.rel_property_index_name(name).is_some())
            || (own != NameCatalog::Fulltext && store.fulltext_index(name).is_some())
            || (own != NameCatalog::Spatial && store.spatial_index(name).is_some())
            || (own != NameCatalog::Constraint && store.constraint(name).is_some())
            || (own != NameCatalog::Composite && store.composite_index(name).is_some())
            || (own != NameCatalog::RelComposite && store.rel_composite_index(name).is_some())
            || (own != NameCatalog::Text && store.text_index(name).is_some())
            || (own != NameCatalog::Vector && store.vector_index(name).is_some())
    }

    /// Whether `name` is used by any schema rule **other than** the node-property index on
    /// `(label_token, prop_token)` (`rmp` task #624). Distinguishing "used by this same index" from
    /// "used by something else" is what keeps [`auto-naming`](auto_index_name) idempotent: recomputing
    /// the auto-name of an index that already carries that name is **not** a collision.
    fn name_used_by_other_target(
        store: &RecordStore<D, S>,
        name: &str,
        label_token: u32,
        prop_token: u32,
    ) -> bool {
        store.fulltext_index(name).is_some()
            || store.spatial_index(name).is_some()
            || store.constraint(name).is_some()
            || store.text_index(name).is_some()
            || store.vector_index(name).is_some()
            || matches!(
                store.node_property_index_name(name),
                Some(target) if target != (label_token, prop_token)
            )
    }

    /// A globally-unique, deterministic auto-name for the node-property index on `(label, property)`
    /// (`rmp` task #624). Returns the [`auto_index_name`] base when it is free (or already owned by this
    /// same index), else the deterministic token-suffixed form `<base>_<label_token>_<prop_token>` — the
    /// tokens uniquely identify the index, so the suffixed form is unique among auto-names.
    fn unique_auto_index_name(
        store: &RecordStore<D, S>,
        label: &str,
        property: &str,
        label_token: u32,
        prop_token: u32,
    ) -> String {
        let base = auto_index_name(label, property);
        if !Self::name_used_by_other_target(store, &base, label_token, prop_token) {
            return base;
        }
        // The token-suffixed form uniquely identifies the index *among auto-names*, but it can still
        // collide with an explicit, user-chosen name in any catalog. Verify the candidate is free and,
        // on a residual collision, iterate a deterministic counter until it is — so the returned name
        // is guaranteed unused by any *other* schema rule. Without this final check, a collision would
        // let two names map to the same target (a state `decode_index_name_catalog` rejects → the
        // store would fail to reopen) or let a nameless CREATE steal an existing index's name
        // (`rmp` #624 durability audit, HIGH + MEDIUM).
        let suffixed = format!("{base}_{label_token}_{prop_token}");
        if !Self::name_used_by_other_target(store, &suffixed, label_token, prop_token) {
            return suffixed;
        }
        let mut n: u64 = 2;
        loop {
            let candidate = format!("{suffixed}_{n}");
            if !Self::name_used_by_other_target(store, &candidate, label_token, prop_token) {
                return candidate;
            }
            n += 1;
        }
    }

    /// Whether `name` is used by any schema rule **other than** the relationship-property index on
    /// `(type_token, prop_token)` (`rmp` task #646) — the relationship analogue of
    /// [`name_used_by_other_target`](Self::name_used_by_other_target). Keeps a rel index's auto-name
    /// idempotent (recomputing an index's own name is not a collision).
    fn rel_name_used_by_other_target(
        store: &RecordStore<D, S>,
        name: &str,
        type_token: u32,
        prop_token: u32,
    ) -> bool {
        store.node_property_index_name(name).is_some()
            || store.fulltext_index(name).is_some()
            || store.spatial_index(name).is_some()
            || store.constraint(name).is_some()
            || store.text_index(name).is_some()
            || store.vector_index(name).is_some()
            || matches!(
                store.rel_property_index_name(name),
                Some(target) if target != (type_token, prop_token)
            )
    }

    /// A globally-unique, deterministic auto-name for the relationship-property index on
    /// `(rel_type, property)` (`rmp` task #646) — the relationship analogue of
    /// [`unique_auto_index_name`](Self::unique_auto_index_name). Returns the [`auto_rel_index_name`]
    /// base when free (or already owned by this same index), else the deterministic token-suffixed form,
    /// then a numeric counter — always verifying the candidate is free of *other* schema rules.
    fn unique_auto_rel_index_name(
        store: &RecordStore<D, S>,
        rel_type: &str,
        property: &str,
        type_token: u32,
        prop_token: u32,
    ) -> String {
        let base = auto_rel_index_name(rel_type, property);
        if !Self::rel_name_used_by_other_target(store, &base, type_token, prop_token) {
            return base;
        }
        let suffixed = format!("{base}_{type_token}_{prop_token}");
        if !Self::rel_name_used_by_other_target(store, &suffixed, type_token, prop_token) {
            return suffixed;
        }
        let mut n: u64 = 2;
        loop {
            let candidate = format!("{suffixed}_{n}");
            if !Self::rel_name_used_by_other_target(store, &candidate, type_token, prop_token) {
                return candidate;
            }
            n += 1;
        }
    }

    /// Inserts node `id`'s current composite tuples into every registered composite index whose covered
    /// label it carries and whose covered property tuple it holds **in full** (`rmp` task #100). The
    /// composite analogue of [`index_one_node`](Self::index_one_node): a node missing any covered
    /// property (or carrying a null for one) is **not** indexed for that key — matching the node-key
    /// rule that an incomplete tuple never participates in uniqueness. Store and index are borrowed in
    /// separate, non-overlapping scopes (the file's borrow discipline). Read faults skip best-effort.
    /// Decrements the front build's stall budget, returning whether it is now **exhausted** — i.e.
    /// whether the caller must poison (drop) the build (`rmp` task #733). A no-op returning `false` when
    /// the queue is empty.
    /// **Poisons** the front build: takes it off the pending queue (so the engine stops re-driving it and
    /// `has_pending_index_builds()` can go false — the termination guarantee) and parks it in the
    /// graveyard, counted (`rmp` task #733, M1). It is NOT discarded: once the store reads cleanly again,
    /// [`retry_poisoned_index_builds`](Self::retry_poisoned_index_builds) re-enqueues it from a fresh
    /// snapshot, so a transient fault costs a delay rather than a permanently dead index.
    fn poison_front<B>(queue: &mut VecDeque<B>, graveyard: &mut Vec<B>, events: &mut u64) {
        if let Some(build) = queue.pop_front() {
            graveyard.push(build);
            *events = events.saturating_add(1);
        }
    }

    fn stall_or_poison<B>(queue: &mut VecDeque<B>, stall: impl Fn(&mut B) -> &mut u8) -> bool {
        let Some(front) = queue.front_mut() else {
            return false;
        };
        let budget = stall(front);
        // An already-exhausted budget stays exhausted (`rmp` task #733, L2). Testing `== 0` *after* a
        // saturating decrement would also poison a build that somehow started at `0` on its very first
        // stall — unreachable today (every build is enqueued at `BUILD_STALL_BUDGET`), but a trap for
        // whoever adds the next build kind. Spend a unit, then report exhaustion.
        if *budget == 0 {
            return true;
        }
        *budget -= 1;
        *budget == 0
    }

    /// Re-establishes a wiped build's snapshot from the **current** store (`rmp` task #733).
    ///
    /// Restarting a build at `cursor = 0` over its ORIGINAL snapshot is **not** enough, and believing it
    /// was is what left `rmp` #733 half-fixed. The original snapshot covered only the rows that existed
    /// when the build started; every row written *since* then was carried by
    /// [`RecordStoreGraph::reindex_node`](crate::record_graph) straight into the index's tree — and
    /// [`IndexSet::clear`] (which every rebuild runs, immediately before the scan that may fault)
    /// **destroys those maintenance writes along with everything else**. So at the moment of the wipe the
    /// tree is empty of post-snapshot rows too, and replaying only the old snapshot loses them *forever*,
    /// under an index that then promotes itself `Online`. A fresh scan is the only thing that covers both.
    ///
    /// Returns [`None`] when the store scan faults — the caller must then **poison** the build (drop it
    /// un-promoted, leaving the index `Populating` and therefore unused), never resume it.
    fn resnapshot_build(store: &Rc<RefCell<RecordStore<D, S>>>) -> Option<Vec<u64>> {
        // INVARIANT (`rmp` task #733, L1): every incremental build — node-property (`rmp` #91), full-text
        // (#72) and spatial (#98) — walks a snapshot of **node** ids, so one re-snapshot serves all three.
        // The relationship-covering indexes (rel-property, rel-composite, rel-full-text, rel-point,
        // rel-vector) are all built **synchronously** at create time and never enqueue an incremental
        // build, which is why no `scan_rel_ids` variant exists here. The day a relationship build becomes
        // incremental it MUST re-snapshot with `scan_rel_ids`: re-basing it on node ids would silently
        // index the wrong entities.
        store.borrow_mut().scan_node_ids().ok()
    }

    /// The **effective** state of an index, as the engine will actually treat it (`rmp` task #733) —
    /// the value every `SHOW INDEXES` surface must report.
    ///
    /// The durable catalog records what the schema *declares*; the in-memory [`IndexSet`] records what
    /// the engine can actually *use*. They diverge exactly when something went wrong: a build whose fill
    /// faulted stays `Populating` in memory while the catalog already says `ONLINE`, and a
    /// [`IndexSet::fail_closed`] demotes (or unregisters) every index while touching no durable byte.
    ///
    /// Reporting the durable state in those windows is not a cosmetic inaccuracy — it is a *false
    /// report of readiness*. An operator (or an automated `wait_for_indexes` poll, as the example
    /// harnesses use) that waits for `state != populating` would sail straight through a degraded
    /// engine, then attribute scan latencies to an index that is not being used. So an index that is not
    /// usable in memory reports `POPULATING`, whatever the catalog says: not usable, not online.
    ///
    /// `in_memory` is the kind's registered state, or [`None`] when the kind carries no state and its
    /// *registration* is its gate (composite, bitmap) — an unregistered one is reported `POPULATING`.
    fn effective_state(durable: IndexState, in_memory: Option<IndexState>) -> IndexState {
        match in_memory {
            // Usable in memory: the durable catalog is the truth (it may legitimately still say
            // `Populating` while an incremental build runs).
            Some(IndexState::Online) => durable,
            // Not registered, or registered but not `Online`: the engine will NOT use it.
            _ => IndexState::Populating,
        }
    }

    /// Records that a per-entity indexing helper **could not read an entity** and had to skip it
    /// (`rmp` task #733) — the shared reporting seam for every `index_one_*` helper.
    ///
    /// Skipping is safe only for an index that is *already published*: there, a missing candidate simply
    /// degrades that entity to a re-check. It is **not** safe while an index is being *built*: a seek can
    /// only drop candidates the index returns, never resurrect one it never returned, so an entity the
    /// build skipped is invisible to every label scan and every seek for the life of the process — a
    /// committed row silently lost to queries. The build that drove the helper reads this flag back and
    /// refuses to publish an index it knows is incomplete (a full rebuild goes
    /// [`IndexSet::fail_closed`]; an incremental build declines to promote itself `Online`).
    fn note_rebuild_gap(index: &Rc<RefCell<IndexSet>>) {
        index.borrow_mut().note_rebuild_gap();
    }

    fn index_one_node_composite(
        store: &Rc<RefCell<RecordStore<D, S>>>,
        index: &Rc<RefCell<IndexSet>>,
        id: u64,
        registered: &[(u32, Vec<u32>)],
    ) {
        // The node's current label tokens + its property values, read in one store-borrow scope.
        // Read-only: `node_labels` / `node_property_values` are `&self` (`rmp` #337 Slice 2).
        let (label_tokens, props): (Vec<u32>, Vec<(u32, Value)>) = {
            let store = store.borrow();
            let labels = match store.node_labels(id) {
                Ok(l) => l,
                Err(_) => {
                    // `rmp` task #733: record the gap instead of hiding it — an entity missing from
                    // the index is a candidate a seek can never resurrect, so the build that drove
                    // this helper must refuse to publish the index (fail closed / stay Populating).
                    Self::note_rebuild_gap(index);
                    return;
                }
            };
            let props = match store.node_property_values(id) {
                Ok(chain) => chain
                    .into_iter()
                    .map(|(_pid, key, value)| (key, value))
                    .collect(),
                Err(_) => {
                    // `rmp` task #733: record the gap instead of hiding it — an entity missing from
                    // the index is a candidate a seek can never resurrect, so the build that drove
                    // this helper must refuse to publish the index (fail closed / stay Populating).
                    Self::note_rebuild_gap(index);
                    return;
                }
            };
            (labels, props)
        };

        let mut idx = index.borrow_mut();
        for (label_token, property_tokens) in registered {
            if !label_tokens.contains(label_token) {
                continue; // node does not carry this composite index's label
            }
            // Build the tuple newest-wins; bail on the first absent/null covered property (the tuple is
            // incomplete, so the node is not a uniqueness candidate and is left unindexed for this key).
            let mut tuple = Vec::with_capacity(property_tokens.len());
            let mut complete = true;
            for prop_key in property_tokens {
                match props
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
                idx.insert_composite(*label_token, property_tokens, &tuple, id);
            }
        }
    }

    /// Inserts node `id`'s current label tokens and indexed property values into `index`, for the
    /// set of `registered` `(label_token, prop_key)` indexes. The store and the index are borrowed in
    /// **separate, non-overlapping** scopes (the load-bearing borrow discipline of this file).
    ///
    /// Extracted so the full-store rebuild ([`rebuild_index`](Self::rebuild_index)) and the
    /// incremental non-blocking build ([`advance_index_builds`](Self::advance_index_builds)) index a
    /// node through **exactly one** code path — the per-node logic cannot drift between them. A
    /// store-read fault on this node (an overflow-form bitmap, a non-storable value, a reclaimed slot)
    /// skips that node's entries best-effort: a missing candidate degrades that node to the full-scan
    /// fallback for a reader, never to a wrong row (the candidate-set contract).
    fn index_one_node(
        store: &Rc<RefCell<RecordStore<D, S>>>,
        index: &Rc<RefCell<IndexSet>>,
        id: u64,
        registered: &[(u32, u32)],
    ) {
        // Read this node's current label tokens (store borrow, released before the index borrow).
        let label_tokens = match store.borrow_mut().node_labels(id) {
            Ok(tokens) => tokens,
            Err(_) => {
                // overflow-form bitmap or read fault: skip this node's entries.
                // `rmp` task #733: record the gap instead of hiding it — an entity missing from
                // the index is a candidate a seek can never resurrect, so the build that drove
                // this helper must refuse to publish the index (fail closed / stay Populating).
                Self::note_rebuild_gap(index);
                return;
            }
        };

        // Resolve the node's current property values, keyed by prop-key, so the index borrow
        // below never overlaps a store borrow. `node_property_values` decodes the whole chain
        // newest-first (`rmp` task #50); the first occurrence per key is the newest value. No MVCC
        // snapshot is needed — the index is a candidate set and every seek re-checks visibility.
        let mut values: Vec<(u32, graphus_core::Value)> = Vec::new();
        {
            let chain = match store.borrow_mut().node_property_values(id) {
                Ok(chain) => chain,
                Err(_) => {
                    // a non-storable / read fault: skip this node's properties.
                    // `rmp` task #733: record the gap instead of hiding it — an entity missing from
                    // the index is a candidate a seek can never resurrect, so the build that drove
                    // this helper must refuse to publish the index (fail closed / stay Populating).
                    Self::note_rebuild_gap(index);
                    return;
                }
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

    /// Inserts relationship `id`'s current property values into every registered relationship-property
    /// index whose covered type it carries (`rmp` task #646) — the relationship analogue of
    /// [`index_one_node`](Self::index_one_node). Candidate-only, exactly like the node path: only the
    /// current value is inserted (a seek re-checks visibility, current type and current value), so no
    /// stale-entry removal is needed. Store and index are borrowed in separate, non-overlapping scopes
    /// (the file's borrow discipline); a read fault skips this relationship best-effort.
    fn index_one_rel(
        store: &Rc<RefCell<RecordStore<D, S>>>,
        index: &Rc<RefCell<IndexSet>>,
        id: u64,
        registered: &[(u32, u32)],
    ) {
        // The relationship's current type token (store borrow, released before the index borrow).
        let type_token = match store.borrow().rel(id) {
            Ok(r) => r.type_id,
            Err(_) => {
                // read fault: skip this relationship's entries.
                // `rmp` task #733: record the gap instead of hiding it — an entity missing from
                // the index is a candidate a seek can never resurrect, so the build that drove
                // this helper must refuse to publish the index (fail closed / stay Populating).
                Self::note_rebuild_gap(index);
                return;
            }
        };
        // Nothing registered for this type ⇒ nothing to index (avoid the property-chain decode).
        if !registered
            .iter()
            .any(|&(reg_type, _)| reg_type == type_token)
        {
            return;
        }

        // Resolve the relationship's current property values (newest-wins per key), keeping only the
        // keys a registered index over this relationship's type uses.
        let mut values: Vec<(u32, graphus_core::Value)> = Vec::new();
        {
            let chain = match store.borrow().rel_property_values(id) {
                Ok(chain) => chain,
                Err(_) => {
                    // a non-storable / read fault: skip this relationship's properties.
                    // `rmp` task #733: record the gap instead of hiding it — an entity missing from
                    // the index is a candidate a seek can never resurrect, so the build that drove
                    // this helper must refuse to publish the index (fail closed / stay Populating).
                    Self::note_rebuild_gap(index);
                    return;
                }
            };
            for (_pid, key, value) in chain {
                if values.iter().any(|(k, _)| *k == key) {
                    continue; // newest-wins: keep only the first (head-most) occurrence per key.
                }
                let used = registered
                    .iter()
                    .any(|&(reg_type, prop_key)| reg_type == type_token && prop_key == key);
                if used {
                    values.push((key, value));
                }
            }
        }

        let mut index = index.borrow_mut();
        for (prop_key, value) in &values {
            index.insert_rel_property(type_token, *prop_key, value, id);
        }
    }

    /// Inserts relationship `id`'s current composite tuple into every registered composite relationship
    /// index whose covered type it carries (`rmp` task #666) — the relationship analogue of
    /// [`index_one_node_composite`](Self::index_one_node_composite). Candidate-only: only the current
    /// tuple is inserted (a seek re-checks visibility, current type and current tuple), so no stale-entry
    /// removal is needed. Store and index are borrowed in separate, non-overlapping scopes; a read fault
    /// skips this relationship best-effort. A relationship missing a covered property (an incomplete
    /// tuple) is left unindexed for that key.
    fn index_one_rel_composite(
        store: &Rc<RefCell<RecordStore<D, S>>>,
        index: &Rc<RefCell<IndexSet>>,
        id: u64,
        registered: &[(u32, Vec<u32>)],
    ) {
        // The relationship's current type token (store borrow released before the index borrow).
        let type_token = match store.borrow().rel(id) {
            Ok(r) => r.type_id,
            Err(_) => {
                // read fault: skip this relationship's entries.
                // `rmp` task #733: record the gap instead of hiding it — an entity missing from
                // the index is a candidate a seek can never resurrect, so the build that drove
                // this helper must refuse to publish the index (fail closed / stay Populating).
                Self::note_rebuild_gap(index);
                return;
            }
        };
        // Nothing registered for this type ⇒ nothing to index (avoid the property-chain decode).
        if !registered
            .iter()
            .any(|(reg_type, _)| *reg_type == type_token)
        {
            return;
        }
        // Resolve the relationship's current property values (newest-wins per key).
        let props: Vec<(u32, Value)> = {
            let chain = match store.borrow().rel_property_values(id) {
                Ok(chain) => chain,
                Err(_) => {
                    // a non-storable / read fault: skip this relationship's properties.
                    // `rmp` task #733: record the gap instead of hiding it — an entity missing from
                    // the index is a candidate a seek can never resurrect, so the build that drove
                    // this helper must refuse to publish the index (fail closed / stay Populating).
                    Self::note_rebuild_gap(index);
                    return;
                }
            };
            let mut out: Vec<(u32, Value)> = Vec::new();
            for (_pid, key, value) in chain {
                if out.iter().any(|(k, _)| *k == key) {
                    continue; // newest-wins: keep only the first (head-most) occurrence per key.
                }
                out.push((key, value));
            }
            out
        };

        let mut idx = index.borrow_mut();
        for (reg_type, property_tokens) in registered {
            if *reg_type != type_token {
                continue; // relationship does not carry this composite index's type
            }
            // Build the tuple newest-wins; bail on the first absent/null covered property (the tuple is
            // incomplete, so the relationship is left unindexed for this key).
            let mut tuple = Vec::with_capacity(property_tokens.len());
            let mut complete = true;
            for prop_key in property_tokens {
                match props
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
                idx.insert_rel_composite(type_token, property_tokens, &tuple, id);
            }
        }
    }

    /// Re-indexes node `id` in **every** registered full-text index from its current label tokens and
    /// **string** property values (`rmp` task #72). The full-text analogue of
    /// [`index_one_node`](Self::index_one_node): the same single per-node code path the full rebuild
    /// ([`rebuild_index`](Self::rebuild_index)) and the non-blocking full-text build
    /// ([`advance_index_builds`](Self::advance_index_builds)) both drive, so their per-node logic can
    /// never diverge.
    ///
    /// Unlike `index_one_node` it reads **all** of the node's string property values (not just those a
    /// registered property index uses), because which properties a full-text index covers is a
    /// per-index decision the [`IndexSet`] applies; the value class is filtered to strings here (a
    /// full-text index covers text). The store and the index are borrowed in **separate,
    /// non-overlapping** scopes, the load-bearing discipline of this file. A read fault on the node
    /// skips it best-effort (the candidate-set contract: a missing candidate degrades to the
    /// scan-and-filter fallback for that reader, never a wrong row).
    fn index_one_node_fulltext(
        store: &Rc<RefCell<RecordStore<D, S>>>,
        index: &Rc<RefCell<IndexSet>>,
        id: u64,
    ) {
        let label_tokens = match store.borrow_mut().node_labels(id) {
            Ok(tokens) => tokens,
            Err(_) => {
                // `rmp` task #733: record the gap instead of hiding it — an entity missing from
                // the index is a candidate a seek can never resurrect, so the build that drove
                // this helper must refuse to publish the index (fail closed / stay Populating).
                Self::note_rebuild_gap(index);
                return;
            }
        };
        // The node's current string property values, keyed by prop-key (newest-wins per key).
        let mut string_props: Vec<(u32, String)> = Vec::new();
        {
            let chain = match store.borrow_mut().node_property_values(id) {
                Ok(chain) => chain,
                Err(_) => {
                    // `rmp` task #733: record the gap instead of hiding it — an entity missing from
                    // the index is a candidate a seek can never resurrect, so the build that drove
                    // this helper must refuse to publish the index (fail closed / stay Populating).
                    Self::note_rebuild_gap(index);
                    return;
                }
            };
            for (_pid, key, value) in chain {
                if string_props.iter().any(|(k, _)| *k == key) {
                    continue; // newest-wins: keep only the first occurrence of each key.
                }
                if let graphus_core::Value::String(s) = value {
                    string_props.push((key, s));
                }
            }
        }
        index
            .borrow_mut()
            .reindex_fulltext_node(id, &label_tokens, &string_props);
    }

    /// Re-indexes relationship `id` in **every** registered relationship full-text index from its
    /// current type token and **string** property values (`rmp` task #663) — the relationship analogue
    /// of [`index_one_node_fulltext`](Self::index_one_node_fulltext). Read faults skip the relationship
    /// best-effort (the candidate-set contract). The store and the index are borrowed in **separate,
    /// non-overlapping** scopes, the load-bearing discipline of this file.
    fn index_one_rel_fulltext(
        store: &Rc<RefCell<RecordStore<D, S>>>,
        index: &Rc<RefCell<IndexSet>>,
        id: u64,
    ) {
        let type_token = match store.borrow().rel(id) {
            Ok(r) => r.type_id,
            Err(_) => {
                // `rmp` task #733: record the gap instead of hiding it — an entity missing from
                // the index is a candidate a seek can never resurrect, so the build that drove
                // this helper must refuse to publish the index (fail closed / stay Populating).
                Self::note_rebuild_gap(index);
                return;
            }
        };
        // The relationship's current string property values, keyed by prop-key (newest-wins per key).
        let mut string_props: Vec<(u32, String)> = Vec::new();
        {
            let chain = match store.borrow().rel_property_values(id) {
                Ok(chain) => chain,
                Err(_) => {
                    // `rmp` task #733: record the gap instead of hiding it — an entity missing from
                    // the index is a candidate a seek can never resurrect, so the build that drove
                    // this helper must refuse to publish the index (fail closed / stay Populating).
                    Self::note_rebuild_gap(index);
                    return;
                }
            };
            for (_pid, key, value) in chain {
                if string_props.iter().any(|(k, _)| *k == key) {
                    continue; // newest-wins: keep only the first occurrence of each key.
                }
                if let graphus_core::Value::String(s) = value {
                    string_props.push((key, s));
                }
            }
        }
        index
            .borrow_mut()
            .reindex_fulltext_rel(id, type_token, &string_props);
    }

    /// Inserts relationship `id`'s current point value into each `registered` `(type_token, prop_key)`
    /// relationship spatial index it matches (`rmp` task #664). The relationship analogue of
    /// [`index_one_node_spatial`](Self::index_one_node_spatial): the same single per-relationship code
    /// path the full rebuild ([`rebuild_index`](Self::rebuild_index)) and the synchronous create build
    /// both drive, so a recovered store rebuilds the relationship grids store-consistently. Only the
    /// **point**-valued properties a registered index covers are read; a relationship of a different
    /// type, or whose covered property is absent / non-point, contributes nothing (the grid is a
    /// candidate set). The store and index are borrowed in **separate, non-overlapping** scopes.
    fn index_one_rel_spatial(
        store: &Rc<RefCell<RecordStore<D, S>>>,
        index: &Rc<RefCell<IndexSet>>,
        id: u64,
        registered: &[(u32, u32)],
    ) {
        let type_token = match store.borrow().rel(id) {
            Ok(r) => r.type_id,
            Err(_) => {
                // `rmp` task #733: record the gap instead of hiding it — an entity missing from
                // the index is a candidate a seek can never resurrect, so the build that drove
                // this helper must refuse to publish the index (fail closed / stay Populating).
                Self::note_rebuild_gap(index);
                return;
            }
        };
        // The relationship's current property values, keyed by prop-key (newest-wins per key), keeping
        // only the point values a registered relationship spatial index covers for this relationship's
        // type.
        let mut values: Vec<(u32, Value)> = Vec::new();
        {
            let chain = match store.borrow().rel_property_values(id) {
                Ok(chain) => chain,
                Err(_) => {
                    // `rmp` task #733: record the gap instead of hiding it — an entity missing from
                    // the index is a candidate a seek can never resurrect, so the build that drove
                    // this helper must refuse to publish the index (fail closed / stay Populating).
                    Self::note_rebuild_gap(index);
                    return;
                }
            };
            for (_pid, key, value) in chain {
                if values.iter().any(|(k, _)| *k == key) {
                    continue; // newest-wins: keep only the first occurrence of each key.
                }
                let used = registered
                    .iter()
                    .any(|&(reg_type, prop_key)| prop_key == key && reg_type == type_token);
                if used && matches!(value, Value::Point(_)) {
                    values.push((key, value));
                }
            }
        }

        let mut index = index.borrow_mut();
        for (prop_key, value) in &values {
            if index.has_spatial_rel(type_token, *prop_key) {
                index.insert_spatial_rel_point(type_token, *prop_key, value, id);
            }
        }
    }

    /// Inserts node `id`'s current point value into each `registered` `(label_token, prop_key)`
    /// spatial index it matches (`rmp` task #98). The spatial analogue of
    /// [`index_one_node`](Self::index_one_node) / [`index_one_node_fulltext`](Self::index_one_node_fulltext):
    /// the same single per-node code path the full rebuild ([`rebuild_index`](Self::rebuild_index)) and
    /// the non-blocking spatial build ([`advance_spatial_build`](Self::advance_spatial_build)) both
    /// drive, so their per-node logic can never diverge.
    ///
    /// Only the **point**-valued properties a registered index covers are read; a node that does not
    /// carry the covered label, or whose covered property is absent / non-point, contributes nothing
    /// (the grid is a candidate set, so a missing candidate degrades to the scan fallback for that
    /// reader — never a wrong row). The store and the index are borrowed in **separate,
    /// non-overlapping** scopes (the load-bearing borrow discipline of this file).
    fn index_one_node_spatial(
        store: &Rc<RefCell<RecordStore<D, S>>>,
        index: &Rc<RefCell<IndexSet>>,
        id: u64,
        registered: &[(u32, u32)],
    ) {
        let label_tokens = match store.borrow_mut().node_labels(id) {
            Ok(tokens) => tokens,
            Err(_) => {
                // `rmp` task #733: record the gap instead of hiding it — an entity missing from
                // the index is a candidate a seek can never resurrect, so the build that drove
                // this helper must refuse to publish the index (fail closed / stay Populating).
                Self::note_rebuild_gap(index);
                return;
            }
        };
        // The node's current property values, keyed by prop-key (newest-wins per key), keeping only
        // the point values a registered spatial index covers for one of this node's labels.
        let mut values: Vec<(u32, Value)> = Vec::new();
        {
            let chain = match store.borrow_mut().node_property_values(id) {
                Ok(chain) => chain,
                Err(_) => {
                    // `rmp` task #733: record the gap instead of hiding it — an entity missing from
                    // the index is a candidate a seek can never resurrect, so the build that drove
                    // this helper must refuse to publish the index (fail closed / stay Populating).
                    Self::note_rebuild_gap(index);
                    return;
                }
            };
            for (_pid, key, value) in chain {
                if values.iter().any(|(k, _)| *k == key) {
                    continue; // newest-wins: keep only the first occurrence of each key.
                }
                let used = registered.iter().any(|&(reg_label, prop_key)| {
                    prop_key == key && label_tokens.contains(&reg_label)
                });
                if used && matches!(value, Value::Point(_)) {
                    values.push((key, value));
                }
            }
        }

        let mut index = index.borrow_mut();
        for (prop_key, value) in &values {
            for &lt in &label_tokens {
                if index.has_spatial(lt, *prop_key) {
                    index.insert_spatial_point(lt, *prop_key, value, id);
                }
            }
        }
    }

    /// (Re)indexes node `id`'s current string value into each `registered` `(label_token, prop_key)`
    /// text (trigram) index it matches (`rmp` task #662). The text analogue of
    /// [`index_one_node_spatial`](Self::index_one_node_spatial): the same single per-node code path the
    /// full rebuild ([`rebuild_index`](Self::rebuild_index)) and the synchronous create build both drive,
    /// so a recovered store rebuilds the trigram indexes store-consistently. Only the **string**-valued
    /// properties a registered index covers are read; a node not carrying the covered label, or whose
    /// covered property is absent / non-string, contributes nothing (the trigram index is a candidate
    /// set, so a missing candidate degrades to the scan fallback for that reader — never a wrong row).
    /// The store and index are borrowed in **separate, non-overlapping** scopes (this file's borrow
    /// discipline).
    fn index_one_node_text(
        store: &Rc<RefCell<RecordStore<D, S>>>,
        index: &Rc<RefCell<IndexSet>>,
        id: u64,
        registered: &[(u32, u32)],
    ) {
        let label_tokens = match store.borrow_mut().node_labels(id) {
            Ok(tokens) => tokens,
            Err(_) => {
                // `rmp` task #733: record the gap instead of hiding it — an entity missing from
                // the index is a candidate a seek can never resurrect, so the build that drove
                // this helper must refuse to publish the index (fail closed / stay Populating).
                Self::note_rebuild_gap(index);
                return;
            }
        };
        // The node's current property values, keyed by prop-key (newest-wins per key), keeping only the
        // string values a registered text index covers for one of this node's labels.
        let mut values: Vec<(u32, Value)> = Vec::new();
        {
            let chain = match store.borrow_mut().node_property_values(id) {
                Ok(chain) => chain,
                Err(_) => {
                    // `rmp` task #733: record the gap instead of hiding it — an entity missing from
                    // the index is a candidate a seek can never resurrect, so the build that drove
                    // this helper must refuse to publish the index (fail closed / stay Populating).
                    Self::note_rebuild_gap(index);
                    return;
                }
            };
            for (_pid, key, value) in chain {
                if values.iter().any(|(k, _)| *k == key) {
                    continue; // newest-wins: keep only the first occurrence of each key.
                }
                let used = registered.iter().any(|&(reg_label, prop_key)| {
                    prop_key == key && label_tokens.contains(&reg_label)
                });
                if used && matches!(value, Value::String(_)) {
                    values.push((key, value));
                }
            }
        }

        let mut index = index.borrow_mut();
        for (prop_key, value) in &values {
            for &lt in &label_tokens {
                if index.has_text(lt, *prop_key) {
                    index.insert_text_value(lt, *prop_key, value, id);
                }
            }
        }
    }

    /// (Re)indexes node `id`'s current embedding into each `registered` `(label_token, prop_key)` vector
    /// (HNSW) index it matches (`rmp` task #669). The vector analogue of
    /// [`index_one_node_text`](Self::index_one_node_text): the same single per-node code path the full
    /// rebuild ([`rebuild_index`](Self::rebuild_index)) drives, so a recovered store rebuilds the ANN
    /// graphs store-consistently. Only the covered property is read; its value is handed verbatim to
    /// [`insert_vector_value`](crate::index_set::IndexSet::insert_vector_value), which indexes it iff it
    /// is a valid embedding (a numeric list of the declared dimension) and otherwise leaves the node out
    /// — so a node not carrying the covered label, or whose covered property is absent / malformed,
    /// contributes nothing. Store and index are borrowed in **separate, non-overlapping** scopes.
    fn index_one_node_vector(
        store: &Rc<RefCell<RecordStore<D, S>>>,
        index: &Rc<RefCell<IndexSet>>,
        id: u64,
        registered: &[(u32, u32)],
    ) {
        let label_tokens = match store.borrow_mut().node_labels(id) {
            Ok(tokens) => tokens,
            Err(_) => {
                // `rmp` task #733: record the gap instead of hiding it — an entity missing from
                // the index is a candidate a seek can never resurrect, so the build that drove
                // this helper must refuse to publish the index (fail closed / stay Populating).
                Self::note_rebuild_gap(index);
                return;
            }
        };
        // The node's current property values, keyed by prop-key (newest-wins per key), keeping only the
        // values a registered vector index covers for one of this node's labels. The value type is NOT
        // pre-filtered here (unlike text/spatial): `insert_vector_value` validates the embedding shape.
        let mut values: Vec<(u32, Value)> = Vec::new();
        {
            let chain = match store.borrow_mut().node_property_values(id) {
                Ok(chain) => chain,
                Err(_) => {
                    // `rmp` task #733: record the gap instead of hiding it — an entity missing from
                    // the index is a candidate a seek can never resurrect, so the build that drove
                    // this helper must refuse to publish the index (fail closed / stay Populating).
                    Self::note_rebuild_gap(index);
                    return;
                }
            };
            for (_pid, key, value) in chain {
                if values.iter().any(|(k, _)| *k == key) {
                    continue; // newest-wins: keep only the first occurrence of each key.
                }
                let used = registered.iter().any(|&(reg_label, prop_key)| {
                    prop_key == key && label_tokens.contains(&reg_label)
                });
                if used {
                    values.push((key, value));
                }
            }
        }

        let mut index = index.borrow_mut();
        for (prop_key, value) in &values {
            for &lt in &label_tokens {
                if index.has_vector(lt, *prop_key) {
                    index.insert_vector_value(lt, *prop_key, value, id);
                }
            }
        }
    }

    /// (Re)indexes relationship `id`'s current embedding into each `registered` `(type_token, prop_key)`
    /// vector (HNSW) index it matches (`rmp` task #669) — the relationship analogue of
    /// [`index_one_node_vector`](Self::index_one_node_vector) (its structure mirrors
    /// [`index_one_rel_spatial`](Self::index_one_rel_spatial)).
    fn index_one_rel_vector(
        store: &Rc<RefCell<RecordStore<D, S>>>,
        index: &Rc<RefCell<IndexSet>>,
        id: u64,
        registered: &[(u32, u32)],
    ) {
        let type_token = match store.borrow().rel(id) {
            Ok(r) => r.type_id,
            Err(_) => {
                // `rmp` task #733: record the gap instead of hiding it — an entity missing from
                // the index is a candidate a seek can never resurrect, so the build that drove
                // this helper must refuse to publish the index (fail closed / stay Populating).
                Self::note_rebuild_gap(index);
                return;
            }
        };
        let mut values: Vec<(u32, Value)> = Vec::new();
        {
            let chain = match store.borrow().rel_property_values(id) {
                Ok(chain) => chain,
                Err(_) => {
                    // `rmp` task #733: record the gap instead of hiding it — an entity missing from
                    // the index is a candidate a seek can never resurrect, so the build that drove
                    // this helper must refuse to publish the index (fail closed / stay Populating).
                    Self::note_rebuild_gap(index);
                    return;
                }
            };
            for (_pid, key, value) in chain {
                if values.iter().any(|(k, _)| *k == key) {
                    continue; // newest-wins: keep only the first occurrence of each key.
                }
                let used = registered
                    .iter()
                    .any(|&(reg_type, prop_key)| prop_key == key && reg_type == type_token);
                if used {
                    values.push((key, value));
                }
            }
        }

        let mut index = index.borrow_mut();
        for (prop_key, value) in &values {
            if index.has_vector_rel(type_token, *prop_key) {
                index.insert_vector_rel_value(type_token, *prop_key, value, id);
            }
        }
    }

    /// (Re)captures node `id`'s current value into each `registered` `(label_token, prop_key)` bitmap
    /// index it matches (`rmp` task #328). The bitmap analogue of [`index_one_node`](Self::index_one_node):
    /// the same single per-node path the full rebuild drives, so a recovered store rebuilds the
    /// low-cardinality bitmaps store-consistently. Membership is exact (the bitmap is a candidate
    /// SOURCE): each registered column the node carries gets the node's bit set under its current
    /// value; a node missing the label / property contributes nothing. Store and index are borrowed in
    /// **separate, non-overlapping** scopes (the borrow discipline of this file).
    fn index_one_node_bitmap(
        store: &Rc<RefCell<RecordStore<D, S>>>,
        index: &Rc<RefCell<IndexSet>>,
        id: u64,
        registered: &[(u32, u32)],
    ) {
        // Skip a slot that is not in use (`rmp` #453, F-IDX-3): the rebuild/declare callers only pass
        // ids from the in-use scan, but the abort re-derive (`rederive_node_bitmap`) may pass a node
        // whose CREATE was just rolled back — a header-only create-undo (#220) clears the slot's in-use
        // bit but PRESERVES its body, so `node_labels`/`node_property_values` below would still decode
        // residual labels/values and wrongly RE-INSERT a phantom. Guarding on `in_use` keeps a
        // reverted-create node out of every bitmap (correct: it no longer exists), and is a defensive
        // no-op for the rebuild/declare callers (their nodes are always in use).
        match store.borrow().node(id) {
            Ok(node) if node.mvcc.in_use() => {}
            _ => return, // not in use, or a read fault: contribute nothing (the bitmap stays cleared).
        }
        let label_tokens = match store.borrow_mut().node_labels(id) {
            Ok(tokens) => tokens,
            Err(_) => {
                // `rmp` task #733: record the gap instead of hiding it — an entity missing from
                // the index is a candidate a seek can never resurrect, so the build that drove
                // this helper must refuse to publish the index (fail closed / stay Populating).
                Self::note_rebuild_gap(index);
                return;
            }
        };
        // The node's current property values, keyed by prop-key (newest-wins per key), keeping only
        // the keys a registered bitmap index covers for one of this node's labels.
        let mut values: Vec<(u32, Value)> = Vec::new();
        {
            let chain = match store.borrow_mut().node_property_values(id) {
                Ok(chain) => chain,
                Err(_) => {
                    // `rmp` task #733: record the gap instead of hiding it — an entity missing from
                    // the index is a candidate a seek can never resurrect, so the build that drove
                    // this helper must refuse to publish the index (fail closed / stay Populating).
                    Self::note_rebuild_gap(index);
                    return;
                }
            };
            for (_pid, key, value) in chain {
                if values.iter().any(|(k, _)| *k == key) {
                    continue; // newest-wins: keep only the first occurrence of each key.
                }
                let used = registered.iter().any(|&(reg_label, prop_key)| {
                    prop_key == key && label_tokens.contains(&reg_label)
                });
                if used {
                    values.push((key, value));
                }
            }
        }

        let mut index = index.borrow_mut();
        for (prop_key, value) in &values {
            for &lt in &label_tokens {
                if index.has_bitmap(lt, *prop_key) {
                    index.insert_bitmap_value(lt, *prop_key, value, id);
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
        self.begin_inner(isolation, None)
    }

    /// Begins a transaction at `isolation`, stamping it with the **monotonic**-clock reading
    /// `begin_nanos` (nanoseconds, `rmp` #395) so the maximum-transaction-age sweep
    /// ([`aged_transactions`](Self::aged_transactions), `rmp` #477) can reap it once its lifetime
    /// exceeds the configured cap.
    ///
    /// The server's open path uses this; pass a reading from the **same** monotonic clock later handed
    /// to [`aged_transactions`](Self::aged_transactions), so an NTP step on the wall clock can neither
    /// expire a fresh transaction nor perpetually reprieve a stale one. Otherwise identical to
    /// [`begin`](Self::begin) (which leaves the transaction age-untracked, hence never reaped — the TCK
    /// / unit-test path).
    pub fn begin_at(&mut self, isolation: IsolationLevel, begin_nanos: u64) -> TxnId {
        self.begin_inner(isolation, Some(begin_nanos))
    }

    /// Shared body of [`begin`](Self::begin) / [`begin_at`](Self::begin_at): mints the id, snapshots
    /// the store's latest commit, registers SSI tracking, and inserts the active entry with its
    /// (optional) monotonic begin reading.
    fn begin_inner(&mut self, isolation: IsolationLevel, begin_nanos: Option<u64>) -> TxnId {
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
                begin_nanos,
            },
        );
        txn
    }

    /// Begins a SERIALIZABLE transaction (the default level).
    pub fn begin_serializable(&mut self) -> TxnId {
        self.begin(IsolationLevel::Serializable)
    }

    /// Declares a node-property index on `(label, property)`, **durably records it** in the store's
    /// index catalog, and populates it from the current graph (`rmp` tasks #48 / #90).
    ///
    /// The label and property-key tokens are interned **durably** and the `(label_token, prop_key)`
    /// index is recorded in the durable index catalog (`rmp` task #90) — both in one committed
    /// transaction, so the *registration* survives a crash. Before `rmp` task #90 only the tokens were
    /// durable and the registered-index set lived only in the in-memory [`IndexSet`], so after a crash
    /// and reopen the index was silently lost; persisting the catalog entry fixes that. The index is
    /// then registered in the shared [`IndexSet`] and rebuilt so every existing node is indexed, and
    /// subsequent writes maintain it incrementally via the statement seam.
    ///
    /// Population is **synchronous** in this task (the non-blocking incremental build is `rmp`
    /// task #91), so the durable end-state of a successful create is [`IndexState::Online`]: the
    /// catalog entry is written `Online` in the same committed transaction as the tokens, and the
    /// in-memory index is registered `Online`. The index *data* itself is in-memory and candidate-only
    /// (never committed); only the token interning and the catalog entry need durability.
    ///
    /// # Errors
    /// Returns a storage error if interning either token, recording the catalog entry, or the
    /// committing transaction fails.
    pub fn create_node_property_index(&mut self, label: &str, property: &str) -> Result<()> {
        // Intern the label + prop-key tokens and record the durable catalog entry in one dedicated
        // transaction so the schema change (tokens + registration) survives a crash atomically, even
        // if no node yet uses them.
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
            // Record the index in the durable catalog at `Online` (population is synchronous here, so a
            // successful create ends `Online`). This becomes durable at the commit below, alongside the
            // tokens; a crash mid-create recovers to the last committed catalog (no entry), and the
            // failed create leaves no orphan registration.
            store.set_node_property_index(label_token, prop_key, IndexState::Online);
            // Record a deterministic auto-name (`rmp` task #624) so this index is named end-to-end (it
            // shows up in `SHOW INDEXES` with a name and is droppable by name). Idempotent: recomputing
            // the auto-name of an index that already carries it is not a collision, so re-declaring the
            // same `(label, property)` keeps the same name.
            let name = Self::unique_auto_index_name(&store, label, property, label_token, prop_key);
            store.set_node_property_index_name(name, label_token, prop_key);
            (label_token, prop_key)
        };
        self.store.borrow_mut().commit(txn)?;

        // Register the index `Online` in the in-memory set and (re)build it so existing rows are
        // indexed. The durable catalog and the in-memory set now agree.
        self.index.borrow_mut().register_node_property_with_state(
            label_token,
            prop_key,
            IndexState::Online,
        );
        Self::rebuild_index(&self.store, &self.index);
        Ok(())
    }

    /// Declares a **relationship-property index** named `name` (or an auto-generated name) over
    /// `(rel_type, property)`, durably records it, and **synchronously builds** it from the existing
    /// relationships (`rmp` task #646) — the relationship analogue of
    /// [`create_node_property_index`](Self::create_node_property_index), plus the named / `IF NOT EXISTS`
    /// surface. Because the build is synchronous, a successful create ends [`IndexState::Online`].
    ///
    /// Returns whether an index was **actually created** (`true`) or the call was an idempotent
    /// `IF NOT EXISTS` no-op (`false`) — the executor turns `false` into a `0` `indexes-added` counter
    /// (Neo4j-conformant idempotent-DDL summary).
    ///
    /// # Errors
    /// - `Neo.ClientError.Schema.EquivalentSchemaRuleAlreadyExists` (no `IF NOT EXISTS`) when an
    ///   equivalent index on `(rel_type, property)` already exists;
    /// - `Neo.ClientError.Schema.IndexWithNameAlreadyExists` (no `IF NOT EXISTS`) when `name` is already
    ///   taken by another schema rule;
    /// - a storage error if interning a token, recording the catalog entry, or committing fails. On any
    ///   error the index is left undeclared.
    pub fn create_rel_property_index_named(
        &mut self,
        name: Option<&str>,
        rel_type: &str,
        property: &str,
        if_not_exists: bool,
    ) -> Result<bool> {
        // 1. Equivalent-index check (read-only, by token *lookup* — an absent token means no index).
        let equivalent_exists = {
            let store = self.store.borrow();
            matches!(
                (
                    store.token_id(Namespace::RelType, rel_type),
                    store.token_id(Namespace::PropKey, property),
                ),
                (Some(tt), Some(pk)) if store.rel_property_index_state(tt, pk).is_some()
            )
        };
        if equivalent_exists {
            return if if_not_exists {
                Ok(false)
            } else {
                Err(equivalent_rel_index_exists(rel_type, property))
            };
        }

        // 2. Explicit-name global uniqueness (read-only). An omitted name is auto-generated in step 3
        //    (it needs the interned tokens for its deterministic collision suffix).
        if let Some(n) = name
            && Self::name_in_use(&self.store.borrow(), n)
        {
            return if if_not_exists {
                Ok(false)
            } else {
                Err(index_name_in_use(n))
            };
        }

        // 3. Intern the tokens and record the durable catalog entry (`Online`) + its name, in one
        //    committed transaction — so the schema change (tokens + registration) survives a crash
        //    atomically even if no relationship yet uses them.
        self.next_txn_id += 1;
        let txn = TxnId(self.next_txn_id);
        self.store.borrow_mut().begin(txn);
        let (type_token, prop_key) = {
            let mut store = self.store.borrow_mut();
            let type_token = match store.intern_token(Namespace::RelType, rel_type) {
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
            let effective_name = match name {
                Some(n) => n.to_owned(),
                None => Self::unique_auto_rel_index_name(
                    &store, rel_type, property, type_token, prop_key,
                ),
            };
            store.set_rel_property_index(type_token, prop_key, IndexState::Online);
            store.set_rel_property_index_name(effective_name, type_token, prop_key);
            (type_token, prop_key)
        };
        self.store.borrow_mut().commit(txn)?;

        // Register the index `Online` in the in-memory set and (re)build it so existing relationships
        // are indexed. The durable catalog and the in-memory set now agree.
        self.index.borrow_mut().register_rel_property_with_state(
            type_token,
            prop_key,
            IndexState::Online,
        );
        Self::rebuild_index(&self.store, &self.index);
        Ok(true)
    }

    /// Drops the relationship-property index covering `(rel_type, property)` (`rmp` task #646), the
    /// by-**target** `DROP INDEX FOR ()-[r:T]-() ON (r.p)` surface. Idempotent: a no-op success on a
    /// missing target. Removes the durable catalog + name entries in one committed transaction and
    /// unregisters the index from the in-memory [`IndexSet`].
    ///
    /// Returns whether an index was **actually removed** (`true`) or the call was a no-op (`false`).
    ///
    /// # Errors
    /// Returns a storage error if the committing transaction fails.
    pub fn drop_rel_property_index(&mut self, rel_type: &str, property: &str) -> Result<bool> {
        let tokens = {
            let store = self.store.borrow();
            match (
                store.token_id(Namespace::RelType, rel_type),
                store.token_id(Namespace::PropKey, property),
            ) {
                (Some(type_token), Some(prop_key))
                    if store
                        .rel_property_index_state(type_token, prop_key)
                        .is_some() =>
                {
                    Some((type_token, prop_key))
                }
                _ => None,
            }
        };
        let Some((type_token, prop_key)) = tokens else {
            return Ok(false); // no such index → clean no-op, nothing removed.
        };

        self.next_txn_id += 1;
        let txn = TxnId(self.next_txn_id);
        self.store.borrow_mut().begin(txn);
        {
            let mut store = self.store.borrow_mut();
            store.remove_rel_property_index(type_token, prop_key);
            store.remove_rel_property_index_name_for(type_token, prop_key);
        }
        self.store.borrow_mut().commit(txn)?;

        self.index
            .borrow_mut()
            .unregister_rel_property(type_token, prop_key);
        Ok(true)
    }

    /// Drops the relationship-property index named `name` (`rmp` task #646), the `DROP INDEX <name>`
    /// surface: resolves the name to its covered `(rel_type, property)`, removes the durable catalog +
    /// name entries in one committed transaction, and unregisters it from the in-memory [`IndexSet`].
    ///
    /// `if_exists` controls the missing-name case: `true` makes a never-declared name a clean no-op
    /// success; `false` returns `Neo.ClientError.Schema.IndexDropFailed`.
    ///
    /// Returns whether an index was **actually removed** (`true`) or the call was a no-op (`false`).
    ///
    /// # Errors
    /// - `Neo.ClientError.Schema.IndexDropFailed` (no `IF EXISTS`) when no index of that name exists;
    /// - a storage error if the committing transaction fails.
    pub fn drop_rel_property_index_by_name(&mut self, name: &str, if_exists: bool) -> Result<bool> {
        let target = self.store.borrow().rel_property_index_name(name);
        let Some((type_token, prop_key)) = target else {
            return if if_exists {
                Ok(false)
            } else {
                Err(index_drop_not_found(name))
            };
        };

        self.next_txn_id += 1;
        let txn = TxnId(self.next_txn_id);
        self.store.borrow_mut().begin(txn);
        {
            let mut store = self.store.borrow_mut();
            store.remove_rel_property_index(type_token, prop_key);
            store.remove_rel_property_index_name(name);
        }
        self.store.borrow_mut().commit(txn)?;

        self.index
            .borrow_mut()
            .unregister_rel_property(type_token, prop_key);
        Ok(true)
    }

    /// Drops the index named `name` — resolving it against **every** index catalog so the unified
    /// Neo4j `DROP INDEX <name>` form (which does not spell the index kind) drops an index of any kind:
    /// node-property, relationship-property (`rmp` task #646), composite (`rmp` task #657), full-text
    /// and spatial/point (`rmp` task #661). Index names are globally unique across all catalogs, so at
    /// most one matches.
    ///
    /// `if_exists` controls the missing-name case: `true` makes a never-declared name a clean no-op
    /// success; `false` returns `Neo.ClientError.Schema.IndexDropFailed`.
    ///
    /// Returns whether an index was **actually removed** (`true`) or the call was a no-op (`false`).
    ///
    /// # Errors
    /// - `Neo.ClientError.Schema.IndexDropFailed` (no `IF EXISTS`) when no index of that name exists;
    /// - a storage error if the committing transaction fails.
    pub fn drop_property_index_by_name(&mut self, name: &str, if_exists: bool) -> Result<bool> {
        // A node-property index of that name? (Its resolver already handles the missing case, but we
        // gate here so a rel index of the same-shaped name is not shadowed by the node resolver's
        // "not found" — names are globally unique, so only one catalog can hold it.)
        if self.store.borrow().node_property_index_name(name).is_some() {
            return self.drop_node_property_index_by_name(name, if_exists);
        }
        // A relationship-property index of that name?
        if self.store.borrow().rel_property_index_name(name).is_some() {
            return self.drop_rel_property_index_by_name(name, if_exists);
        }
        // A standalone composite (multi-property) index of that name (`rmp` task #657)?
        let composite = self.store.borrow().composite_index(name);
        if let Some(entry) = composite {
            self.remove_composite_index_committed(name, entry.label_token, &entry.property_tokens)?;
            return Ok(true);
        }
        // A standalone composite relationship index of that name (`rmp` task #666)?
        let rel_composite = self.store.borrow().rel_composite_index(name);
        if let Some(entry) = rel_composite {
            self.remove_rel_composite_index_committed(
                name,
                entry.type_token,
                &entry.property_tokens,
            )?;
            return Ok(true);
        }
        // A full-text index of that name (`rmp` task #661)? The name is known-present here, so the
        // delegate removes it and returns `Ok(true)`.
        if self.store.borrow().fulltext_index(name).is_some() {
            return self.drop_fulltext_index(name, if_exists);
        }
        // A spatial (point) index of that name (`rmp` task #661)?
        if self.store.borrow().spatial_index(name).is_some() {
            return self.drop_point_index(name, if_exists);
        }
        // A text (trigram) index of that name (`rmp` task #662)?
        if self.store.borrow().text_index(name).is_some() {
            return self.drop_text_index(name, if_exists);
        }
        // A vector (HNSW) index of that name (`rmp` task #671)?
        if self.store.borrow().vector_index(name).is_some() {
            return self.drop_vector_index(name, if_exists);
        }
        // No catalog holds the name: honour `IF EXISTS`.
        if if_exists {
            Ok(false)
        } else {
            Err(index_drop_not_found(name))
        }
    }

    /// Drops the **standalone composite** index over `(label, properties)` — the by-target
    /// `DROP INDEX FOR (n:L) ON (n.a, n.b)` shape (`rmp` task #657). Resolves the covered composite by
    /// its label + ordered property tuple; a missing target is a clean no-op success. Returns whether an
    /// index was actually removed.
    ///
    /// # Errors
    /// Returns a storage error if the committing transaction fails.
    pub fn drop_node_composite_index(
        &mut self,
        label: &str,
        properties: &[String],
    ) -> Result<bool> {
        let resolved = {
            let store = self.store.borrow();
            match Self::resolve_property_tokens(&store, label, properties) {
                Some((label_token, property_tokens)) => store
                    .composite_index_name_for(label_token, &property_tokens)
                    .map(|name| (name.to_owned(), label_token, property_tokens)),
                None => None,
            }
        };
        let Some((name, label_token, property_tokens)) = resolved else {
            return Ok(false); // no such composite index → clean no-op.
        };
        self.remove_composite_index_committed(&name, label_token, &property_tokens)?;
        Ok(true)
    }

    /// Removes the durable composite index catalog entry named `name` in one committed transaction and
    /// unregisters its in-memory backing tree — **unless** a node-key constraint over the *same*
    /// `(label, tuple)` still needs it (`rmp` task #657). A standalone composite index and a node-key
    /// constraint over the same tuple share one in-memory tree (keyed by target, not name), so dropping
    /// the index must not tear the tree out from under a still-live constraint.
    ///
    /// # Errors
    /// Returns a storage error if the committing transaction fails.
    fn remove_composite_index_committed(
        &mut self,
        name: &str,
        label_token: u32,
        property_tokens: &[u32],
    ) -> Result<()> {
        self.next_txn_id += 1;
        let txn = TxnId(self.next_txn_id);
        self.store.borrow_mut().begin(txn);
        self.store.borrow_mut().remove_composite_index(name);
        self.store.borrow_mut().commit(txn)?;

        // Keep the backing tree iff a node-key constraint over the same tuple still shares it.
        let still_backs_node_key = self
            .index
            .borrow()
            .constraints_for_label(label_token)
            .iter()
            .any(|rule| {
                rule.kind == ConstraintKind::NodeKey && rule.property_tokens == property_tokens
            });
        if !still_backs_node_key {
            self.index
                .borrow_mut()
                .unregister_composite(label_token, property_tokens);
        }
        Ok(())
    }

    /// Lists every declared standalone composite index as `(name, label, properties, state)`
    /// (`rmp` task #657), for a `SHOW INDEXES` surface. Reads the durable catalog and resolves the
    /// tokens back to names; an entry whose tokens have no resolvable name (a defensively-skipped
    /// impossibility for a live token) is omitted. Ordered by the catalog's ascending name.
    #[must_use]
    pub fn list_composite_indexes(&self) -> Vec<(String, String, Vec<String>, IndexState)> {
        let store = self.store.borrow();
        store
            .composite_indexes()
            .into_iter()
            .filter_map(|(name, entry)| {
                let label = store.token_name(Namespace::Label, entry.label_token)?;
                let mut properties = Vec::with_capacity(entry.property_tokens.len());
                for pk in &entry.property_tokens {
                    properties.push(store.token_name(Namespace::PropKey, *pk)?.to_owned());
                }
                // The EFFECTIVE state (`rmp` task #733): a composite carries no in-memory state, so its
                // *registration* is its gate — a fail-closed unregisters it, and it is then unusable.
                let state = Self::effective_state(
                    entry.state,
                    self.index
                        .borrow()
                        .has_composite(entry.label_token, &entry.property_tokens)
                        .then_some(IndexState::Online),
                );
                Some((name, label.to_owned(), properties, state))
            })
            .collect()
    }

    /// Drops the **standalone composite relationship** index over `(rel_type, properties)` — the
    /// by-target `DROP INDEX FOR ()-[r:T]-() ON (r.a, r.b)` shape (`rmp` task #666). Resolves the covered
    /// composite by its relationship type + ordered property tuple; a missing target is a clean no-op
    /// success. Returns whether an index was actually removed.
    ///
    /// # Errors
    /// Returns a storage error if the committing transaction fails.
    pub fn drop_rel_composite_index(
        &mut self,
        rel_type: &str,
        properties: &[String],
    ) -> Result<bool> {
        let resolved = {
            let store = self.store.borrow();
            match Self::resolve_rel_property_tokens(&store, rel_type, properties) {
                Some((type_token, property_tokens)) => store
                    .rel_composite_index_name_for(type_token, &property_tokens)
                    .map(|name| (name.to_owned(), type_token, property_tokens)),
                None => None,
            }
        };
        let Some((name, type_token, property_tokens)) = resolved else {
            return Ok(false); // no such composite relationship index → clean no-op.
        };
        self.remove_rel_composite_index_committed(&name, type_token, &property_tokens)?;
        Ok(true)
    }

    /// Removes the durable composite relationship index catalog entry named `name` in one committed
    /// transaction and unregisters its in-memory backing tree (`rmp` task #666). Unlike the node
    /// composite (which may share its tree with a node-key constraint), a composite relationship index
    /// backs no constraint (a relationship-key constraint stays scan-based), so its tree is always
    /// unregistered.
    ///
    /// # Errors
    /// Returns a storage error if the committing transaction fails.
    fn remove_rel_composite_index_committed(
        &mut self,
        name: &str,
        type_token: u32,
        property_tokens: &[u32],
    ) -> Result<()> {
        self.next_txn_id += 1;
        let txn = TxnId(self.next_txn_id);
        self.store.borrow_mut().begin(txn);
        self.store.borrow_mut().remove_rel_composite_index(name);
        self.store.borrow_mut().commit(txn)?;
        self.index
            .borrow_mut()
            .unregister_rel_composite(type_token, property_tokens);
        Ok(())
    }

    /// Lists every declared standalone composite relationship index as `(name, rel_type, properties,
    /// state)` (`rmp` task #666), for a `SHOW INDEXES` surface — the relationship analogue of
    /// [`list_composite_indexes`](Self::list_composite_indexes). An entry whose tokens have no resolvable
    /// name is omitted. Ordered by the catalog's ascending name.
    #[must_use]
    pub fn list_rel_composite_indexes(&self) -> Vec<(String, String, Vec<String>, IndexState)> {
        let store = self.store.borrow();
        store
            .rel_composite_indexes()
            .into_iter()
            .filter_map(|(name, entry)| {
                let rel_type = store.token_name(Namespace::RelType, entry.type_token)?;
                let mut properties = Vec::with_capacity(entry.property_tokens.len());
                for pk in &entry.property_tokens {
                    properties.push(store.token_name(Namespace::PropKey, *pk)?.to_owned());
                }
                // The EFFECTIVE state (`rmp` task #733) — registration is the gate, as for the node
                // composite above.
                let state = Self::effective_state(
                    entry.state,
                    self.index
                        .borrow()
                        .has_rel_composite(entry.type_token, &entry.property_tokens)
                        .then_some(IndexState::Online),
                );
                Some((name, rel_type.to_owned(), properties, state))
            })
            .collect()
    }

    /// Lists every declared relationship-property index as `(name, rel_type, property, state)`
    /// (`rmp` task #646), for a `SHOW INDEXES` surface. Reads the durable catalog and resolves tokens
    /// back to names; the index **name** is the durable name if recorded, else the deterministic
    /// [`auto_rel_index_name`] fallback. An index whose tokens have no resolvable name is omitted.
    #[must_use]
    pub fn list_rel_property_indexes(&self) -> Vec<(String, String, String, IndexState)> {
        let store = self.store.borrow();
        store
            .rel_property_indexes()
            .into_iter()
            .filter_map(|(type_token, prop_key, state)| {
                // The EFFECTIVE state (`rmp` task #733) — see `effective_state`.
                let state = Self::effective_state(
                    state,
                    self.index.borrow().rel_property_state(type_token, prop_key),
                );
                let rel_type = store.token_name(Namespace::RelType, type_token)?;
                let property = store.token_name(Namespace::PropKey, prop_key)?;
                let name = store
                    .rel_property_index_name_for(type_token, prop_key)
                    .unwrap_or_else(|| auto_rel_index_name(rel_type, property));
                Some((name, rel_type.to_owned(), property.to_owned(), state))
            })
            .collect()
    }

    /// Declares that the **complementary columnar value cache** (`rmp` tasks #329 / #330) should
    /// cover `(label, property)`, and **captures the column now** from the current graph.
    ///
    /// This is opt-in per `(label, property)`, exactly like declaring a node-property index — a caller
    /// (a server admin surface, the analytical examples/benches) declares the columns its analytical
    /// workload scans. Unlike a node-property index, **nothing here is durable**: the cache is a
    /// derived, in-memory, rebuilt-on-open accelerator (it has no on-disk / ACID / recovery surface),
    /// so a re-opened coordinator that wants the acceleration simply re-declares. The label and
    /// property-key tokens are interned (so a brand-new label/property resolves to a stable token) in
    /// one tiny committed transaction — that token interning is the *only* durable effect, identical
    /// to how any token is minted, and it carries no columnar data.
    ///
    /// After this returns, an analytical scan `MATCH (n:Label) RETURN agg(n.property)` over a
    /// statement seam reads the column from the cache (re-validated per node) instead of decoding each
    /// node's property chain. The result is **identical** to the row path — see
    /// [`RecordStoreGraph::columnar_label_property_scan`](crate::record_graph::RecordStoreGraph).
    ///
    /// # Errors
    /// Returns a storage error if interning either token (or its committing transaction) fails.
    pub fn declare_columnar_cache(&mut self, label: &str, property: &str) -> Result<()> {
        // Intern the tokens in one committed transaction (the only durable effect — no columnar data
        // is persisted). Mirrors the token-minting prologue of `create_node_property_index`.
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

        // Declare the column and capture it now from the current graph.
        self.columns.borrow_mut().declare(label_token, prop_key);
        Self::rebuild_columns(&self.store, &self.columns);
        Ok(())
    }

    /// Declares a **low-cardinality Roaring-bitmap index** on `(label, property)` (`rmp` task #328),
    /// the complementary index for boolean / enum-like / status columns: ~100× smaller postings than
    /// the B+-tree and microsecond multi-predicate AND via bitmap intersection (see
    /// [`bitmap_conjunction`](Self::bitmap_conjunction)). Like the columnar cache this is an **opt-in,
    /// derived, in-memory** structure — nothing here is durable except the token interning (the only
    /// durable effect, identical to any token mint); a re-opened coordinator re-declares. The column is
    /// captured now and kept **membership-exact** by the per-write re-index, so its seek result is a
    /// correct candidate set (the caller still re-checks MVCC visibility, exactly as for every index).
    ///
    /// Intended for **low-cardinality** columns; on a high-cardinality column a bitmap holds one id per
    /// value and the B+-tree (which also serves ranges) is the right structure — the declaration is the
    /// operator's assertion that the column is low-cardinality.
    ///
    /// # Cardinality guard (`rmp` task #453, F-IDX-5)
    ///
    /// The build is bounded by an **exact runtime distinct-value cap**
    /// ([`graphus_index::bitmap::MAX_DISTINCT_VALUES`]): as the store is scanned, the moment the column's
    /// live distinct-value count exceeds the cap the half-built bitmap is **torn down** (the column is
    /// unregistered) and the declaration is **refused** with a clear error, instead of letting one
    /// `RoaringTreemap`-per-value structure grow unbounded on a near-unique column (the OOM footgun the
    /// header doc warns about). The check is against the true built cardinality, so it needs no
    /// pre-existing cost histogram and cannot be fooled by an estimate.
    ///
    /// # Errors
    /// - A storage error if interning either token (or its committing transaction) fails.
    /// - [`GraphusError::Runtime`] if the column's distinct-value count exceeds
    ///   [`graphus_index::bitmap::MAX_DISTINCT_VALUES`] — the column is too high-cardinality for a
    ///   bitmap index (use the B+-tree node-property index instead).
    pub fn declare_bitmap_index(&mut self, label: &str, property: &str) -> Result<()> {
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

        // Register the column and capture it now from the current graph (membership-exact).
        self.index
            .borrow_mut()
            .register_bitmap(label_token, prop_key);
        let registered = [(label_token, prop_key)];
        self.index.borrow_mut().clear_rebuild_gap();
        let node_ids = match self.store.borrow_mut().scan_node_ids() {
            Ok(ids) => ids,
            // A scan fault used to `return Ok(())` here — reporting SUCCESS while leaving an EMPTY bitmap
            // registered (`rmp` task #733). A bitmap is a **membership-exact candidate source**, not a
            // hint: an empty one answers every seek with zero rows. Unregister it (it carries no
            // `IndexState` to demote, so registration IS its gate) and surface the fault.
            Err(e) => {
                self.index
                    .borrow_mut()
                    .unregister_bitmap(label_token, prop_key);
                return Err(e);
            }
        };
        // Build the bitmap, enforcing the distinct-value cap as we go (`rmp` #453, F-IDX-5). Checking
        // after each node short-circuits a near-unique column before its bitmap blows up, bounding the
        // transient memory too. On breach: unregister the (now-torn-down) column and refuse.
        for id in node_ids {
            Self::index_one_node_bitmap(&self.store, &self.index, id, &registered);
            if self
                .index
                .borrow()
                .bitmap_distinct(label_token, prop_key)
                .is_some_and(|d| d > graphus_index::bitmap::MAX_DISTINCT_VALUES)
            {
                self.index
                    .borrow_mut()
                    .unregister_bitmap(label_token, prop_key);
                return Err(GraphusError::Runtime(format!(
                    "cannot create a bitmap index on `{label}.{property}`: the column has more than {} \
                     distinct values (too high-cardinality for a bitmap index — use a node-property \
                     index instead)",
                    graphus_index::bitmap::MAX_DISTINCT_VALUES
                )));
            }
        }
        // A node the capture could not read is missing from the bitmap for good (`rmp` task #733), and a
        // bitmap is membership-exact — a seek against it would silently drop that node's rows. Unregister
        // and surface the fault rather than report success over a holed candidate source. (This also
        // clears the flag, which the old code left dirty for the next build to trip over.)
        if self.index.borrow().rebuild_gap() {
            let mut idx = self.index.borrow_mut();
            idx.clear_rebuild_gap();
            idx.unregister_bitmap(label_token, prop_key);
            drop(idx);
            return Err(GraphusError::Storage(format!(
                "cannot create a bitmap index on `{label}.{property}`: the store scan skipped at \
                 least one node"
            )));
        }
        Ok(())
    }

    /// Candidate node ids for `label` whose `property` equals `value`, via the declared bitmap index
    /// (`rmp` #328); `None` if no bitmap index is declared for the column. Test/diagnostic surface for
    /// the single-predicate bitmap seek (the caller re-checks visibility + the exact predicate).
    #[must_use]
    pub fn bitmap_seek_eq(&self, label: &str, property: &str, value: &Value) -> Option<Vec<u64>> {
        let store = self.store.borrow();
        let label_token = store.token_id(Namespace::Label, label)?;
        let prop_key = store.token_id(Namespace::PropKey, property)?;
        drop(store);
        self.index
            .borrow()
            .seek_bitmap_eq(label_token, prop_key, value)
    }

    /// Candidate node ids for `label` satisfying the conjunction of `(property, value)` equalities, via
    /// **bitmap intersection** (`rmp` #328 multi-predicate AND fast path); `None` unless every column
    /// has a declared bitmap index. The caller re-checks MVCC visibility + the exact predicates.
    #[must_use]
    pub fn bitmap_conjunction(
        &self,
        label: &str,
        predicates: &[(&str, &Value)],
    ) -> Option<Vec<u64>> {
        let store = self.store.borrow();
        let label_token = store.token_id(Namespace::Label, label)?;
        // Resolve each predicate's prop-key token; a never-interned property has no index ⇒ decline.
        let mut resolved: Vec<(u32, &Value)> = Vec::with_capacity(predicates.len());
        for &(property, value) in predicates {
            let prop_key = store.token_id(Namespace::PropKey, property)?;
            resolved.push((prop_key, value));
        }
        drop(store);
        self.index
            .borrow()
            .seek_bitmap_conjunction(label_token, &resolved)
    }

    /// The serialized byte footprint of the declared `(label, property)` bitmap index, or `None` if no
    /// bitmap index is declared. Used by the measurement harness to compare against the B+-tree
    /// postings size. (Diagnostics only.)
    #[must_use]
    pub fn bitmap_serialized_bytes(&self, label: &str, property: &str) -> Option<u64> {
        let store = self.store.borrow();
        let label_token = store.token_id(Namespace::Label, label)?;
        let prop_key = store.token_id(Namespace::PropKey, property)?;
        drop(store);
        self.index
            .borrow()
            .bitmap_serialized_bytes(label_token, prop_key)
    }

    // --------------------------------------------------------------------------------------------
    // Zone-map data-skipping sidecar (`rmp` task #331)
    // --------------------------------------------------------------------------------------------

    /// Declares a **zone-map data-skipping** sidecar on `(label, property)` (`rmp` task #331): a
    /// coarse per-zone `{min, max}` summary over the node-id space that lets a non-indexed predicate
    /// scan skip whole id zones whose range cannot match. Opt-in / derived / in-memory (only the token
    /// interning is durable), rebuilt from the current store now and maintained (widening) on every
    /// write. Best on a column clustered by node id (append-only timestamps / sequences); it degrades
    /// gracefully to a full scan on an unclustered column, and never changes a query's result.
    ///
    /// # Errors
    /// Returns a storage error if interning either token (or its committing transaction) fails.
    pub fn declare_zone_map(&mut self, label: &str, property: &str) -> Result<()> {
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

        self.zones.borrow_mut().declare(label_token, prop_key);
        self.rebuild_zone_column(label_token, prop_key);
        Ok(())
    }

    /// Rebuilds one declared zone-map column exactly from the current store: scans the in-use nodes
    /// that carry the label and captures `(id, value)` for the property, then installs the exact
    /// per-zone summary. Reads committed state without a snapshot (like the index rebuild); the scan's
    /// per-row re-check makes any later staleness harmless.
    fn rebuild_zone_column(&self, label_token: u32, prop_key: u32) {
        // Read-only store access (`rmp` #337 Slice 2): the rebuild scan only reads.
        let node_ids = match self.store.borrow().scan_node_ids() {
            Ok(ids) => ids,
            Err(_) => return,
        };
        let mut rows: Vec<(u64, Value)> = Vec::new();
        for id in node_ids {
            let (labels, chain) = {
                let store = self.store.borrow();
                let labels = match store.node_labels(id) {
                    Ok(l) => l,
                    Err(_) => continue,
                };
                let chain = match store.node_property_values(id) {
                    Ok(c) => c,
                    Err(_) => continue,
                };
                (labels, chain)
            };
            if !labels.contains(&label_token) {
                continue;
            }
            if let Some((_pid, _k, value)) = chain.iter().find(|(_, k, _)| *k == prop_key) {
                rows.push((id, value.clone()));
            }
        }
        self.zones
            .borrow_mut()
            .rebuild_column(label_token, prop_key, rows);
    }

    /// Candidate-and-confirmed node ids for `label` whose `property` **equals** `value`, driven by the
    /// zone-map data-skipping sidecar (`rmp` #331): only the id zones the summary cannot exclude are
    /// examined, and each examined node is authoritatively re-checked (in-use, current label, current
    /// value) — so the result is **exactly** the committed matching set regardless of zone staleness.
    /// `None` if no zone map is declared for the column (the caller scans normally). After the call,
    /// [`zone_map_zones_skipped`](Self::zone_map_zones_skipped) reports how many zones were pruned.
    #[must_use]
    pub fn zone_scan_eq(&self, label: &str, property: &str, value: &Value) -> Option<Vec<u64>> {
        let (label_token, prop_key) = {
            let store = self.store.borrow();
            (
                store.token_id(Namespace::Label, label)?,
                store.token_id(Namespace::PropKey, property)?,
            )
        };
        let ranges = self
            .zones
            .borrow()
            .candidate_ranges_eq(label_token, prop_key, value)?;
        let high_water = self.store.borrow().node_high_water();
        let mut out = Vec::new();
        for (lo, hi) in ranges {
            for id in lo.max(1)..hi.min(high_water) {
                let (labels, chain) = {
                    // Read-only store access (`rmp` #337 Slice 2): zone-scan re-check only reads.
                    let store = self.store.borrow();
                    let node = match store.node(id) {
                        Ok(n) => n,
                        Err(_) => continue,
                    };
                    if !node.mvcc.in_use() {
                        continue;
                    }
                    let labels = match store.node_labels(id) {
                        Ok(l) => l,
                        Err(_) => continue,
                    };
                    let chain = match store.node_property_values(id) {
                        Ok(c) => c,
                        Err(_) => continue,
                    };
                    (labels, chain)
                };
                if !labels.contains(&label_token) {
                    continue;
                }
                if chain
                    .iter()
                    .find(|(_, k, _)| *k == prop_key)
                    .is_some_and(|(_, _, v)| v == value)
                {
                    out.push(id);
                }
            }
        }
        Some(out)
    }

    /// Zones the most recent [`zone_scan_eq`](Self::zone_scan_eq) pruned (`rmp` #331 measurement).
    #[must_use]
    pub fn zone_map_zones_skipped(&self) -> u64 {
        self.zones.borrow().zones_skipped()
    }

    /// Zones the most recent [`zone_scan_eq`](Self::zone_scan_eq) kept / scanned.
    #[must_use]
    pub fn zone_map_zones_scanned(&self) -> u64 {
        self.zones.borrow().zones_scanned()
    }

    /// Re-captures **every declared** columnar column from the current store (`rmp` #329): the
    /// derived analogue of [`rebuild_index`](Self::rebuild_index) for the columnar cache. Each
    /// declared `(label_token, prop_key)` column is rebuilt by scanning the in-use nodes, capturing,
    /// for every node that currently carries the label and holds an index-stable value of the key, the
    /// tuple `(node_id, value, prop_pid, node_first_prop)` — the value plus the two staleness witnesses
    /// the read-time re-check needs.
    ///
    /// Reads directly off the store with **no MVCC snapshot** (like `rebuild_index`): the cache is a
    /// candidate-class accelerator whose every entry is re-validated at read time, so capturing each
    /// node's *current newest in-use* value is sufficient — a value that some future reader cannot see
    /// is harmless (the read-time visibility re-check drops it, falling back to the row read). Store
    /// read faults on a single node skip that node best-effort (it degrades to the row path for that
    /// node, never a wrong row). The store and the cache are borrowed in separate scopes.
    fn rebuild_columns(
        store: &Rc<RefCell<RecordStore<D, S>>>,
        columns: &Rc<RefCell<crate::column_cache::ColumnCache>>,
    ) {
        // The declared columns, captured before the scan so the cache is not borrowed across a store
        // borrow. Drop all captured data first (keeping declarations) so a rebuild starts clean.
        let declared: Vec<(u32, u32)> = columns.borrow().declared().to_vec();
        columns.borrow_mut().clear();
        if declared.is_empty() {
            return;
        }

        let node_ids = match store.borrow_mut().scan_node_ids() {
            Ok(ids) => ids,
            // A whole-scan fault leaves every column empty; every reader then uses the row path.
            Err(_) => return,
        };

        // Accumulate each declared column's rows in node-id order (the scan order).
        let mut per_column: Vec<Vec<(u64, Value, u64, u64)>> =
            declared.iter().map(|_| Vec::new()).collect();

        for id in node_ids {
            // Read the node's labels, first_prop chain head, and newest-in-use property values once.
            let (label_tokens, first_prop, props): (Vec<u32>, u64, Vec<(u64, u32, Value)>) = {
                // Read-only store access (`rmp` #337 Slice 2): the column rebuild scan only reads.
                let store = store.borrow();
                let node = match store.node(id) {
                    Ok(n) => n,
                    Err(_) => continue,
                };
                // Tombstoned / not-in-use slots are skipped (the index rebuild skips them too via the
                // in-use scan; this guards a since-reclaimed slot defensively).
                if !node.mvcc.in_use() {
                    continue;
                }
                let labels = match store.node_labels(id) {
                    Ok(l) => l,
                    Err(_) => continue,
                };
                let chain = match store.node_property_values(id) {
                    Ok(chain) => chain,
                    Err(_) => continue,
                };
                (labels, node.first_prop, chain)
            };

            // For each declared column the node matches, capture its newest in-use value of the key.
            for (ci, &(label_token, prop_key)) in declared.iter().enumerate() {
                if !label_tokens.contains(&label_token) {
                    continue;
                }
                // `node_property_values` decodes the chain newest-first, so the FIRST occurrence of the
                // key is the newest in-use version — its pid is the staleness witness.
                if let Some((pid, _key, value)) = props.iter().find(|(_, key, _)| *key == prop_key)
                {
                    // A null value is never stored as a property (Cypher), so any present record holds a
                    // non-null value; capture it with the witnesses (pid + the node's chain head).
                    per_column[ci].push((id, value.clone(), *pid, first_prop));
                }
            }
        }

        // Install the captured columns (cache borrow only).
        let mut cache = columns.borrow_mut();
        for ((label_token, prop_key), rows) in declared.into_iter().zip(per_column) {
            cache.set_column(label_token, prop_key, rows);
        }
    }

    /// The number of cached rows for the columnar column `(label, property)`, or `None` when the pair
    /// is not a declared/captured column (`rmp` #329). A diagnostics / test accessor proving the
    /// column was actually captured (so a measurement is not vacuously over an empty cache).
    #[must_use]
    pub fn columnar_column_len(&self, label: &str, property: &str) -> Option<usize> {
        let store = self.store.borrow();
        let label_token = store.token_id(Namespace::Label, label)?;
        let prop_key = store.token_id(Namespace::PropKey, property)?;
        drop(store);
        self.columns.borrow().column_len(label_token, prop_key)
    }

    /// The number of times the columnar analytical read path served a cached column since this
    /// coordinator was built (`rmp` #330): a cheap monitor / test signal that the accelerator was
    /// actually engaged (a test asserts it incremented, so an equivalence check is not vacuously
    /// comparing the row path against itself).
    #[must_use]
    pub fn columnar_scan_hits(&self) -> u64 {
        self.columns.borrow().scan_hits()
    }

    /// The number of columnar scans that **re-used a column's memoized decode** instead of decoding it
    /// afresh (`rmp` task #375): a second scan of an un-mutated column hits this, proving the
    /// dictionary/integer decode (and the per-query lookup map) is paid once, not per query. A test
    /// asserts it increments on a repeat scan and stays put across a re-capture (new generation).
    #[must_use]
    pub fn columnar_decode_cache_hits(&self) -> u64 {
        self.columns.borrow().decode_cache_hits()
    }

    /// The cumulative count of values the columnar path served straight from the contiguous column
    /// (zero property-record decode) since this coordinator was built (`rmp` #329/#330) — the
    /// accelerator's payoff signal, exposed for measurement.
    #[must_use]
    pub fn columnar_value_hits(&self) -> u64 {
        self.columns.borrow().value_hits()
    }

    /// The cumulative count of values the columnar path read from the authoritative property chain (a
    /// stale / missing cache entry) since this coordinator was built (`rmp` #329/#330). On a fresh
    /// cache this stays `0`; the row path pays one such decode for every matched node, so the pair
    /// `(columnar_value_hits, columnar_fallback_reads)` is the measured decode reduction.
    #[must_use]
    pub fn columnar_fallback_reads(&self) -> u64 {
        self.columns.borrow().fallback_reads()
    }

    /// The number of times the **parallel** label-property aggregation tier (`rmp` task #352) projected
    /// a snapshot off this coordinator's columnar cache and folded it across cores. Distinct from
    /// [`columnar_scan_hits`](Self::columnar_scan_hits) (which the serial columnar scan also bumps): a
    /// test asserts this incremented to prove the parallel path was actually taken, so a
    /// parallel-vs-serial equivalence check is not vacuously comparing serial against itself.
    #[must_use]
    pub fn parallel_scan_hits(&self) -> u64 {
        self.columns.borrow().parallel_scan_hits()
    }

    /// Declares a node-property index on `(label, property)` and starts a **non-blocking** background
    /// build of it (`rmp` task #91): the catalog entry is recorded durably as [`IndexState::Populating`]
    /// and a pending build is enqueued, but **no node is scanned here** — the call returns promptly so
    /// the single-threaded engine stays responsive to other commands. The build is advanced in bounded
    /// chunks by [`advance_index_builds`](Self::advance_index_builds) and promoted to
    /// [`IndexState::Online`] only when every snapshot node has been indexed.
    ///
    /// In contrast, [`create_node_property_index`](Self::create_node_property_index) populates the
    /// index **synchronously** before returning (`Online` on success) — keep it for the
    /// startup/recovery path and any caller that can tolerate a blocking full-store scan; use *this*
    /// for a live `CREATE INDEX` over a populated store, where blocking the engine thread for the scan
    /// would stall every concurrent query.
    ///
    /// # Build snapshot and the no-missed-results guarantee
    ///
    /// At build start the current live node-id list is snapshotted ([`RecordStore::scan_node_ids`]).
    /// The build later indexes each snapshot node's *current* state. Concurrent writes between chunks
    /// are covered without any extra bookkeeping because the index is a **candidate set** and writes
    /// already maintain it (`RecordStoreGraph::reindex_node` inserts into *every* registered index in
    /// *any* state):
    ///
    /// - A node **deleted** before the scan reaches it → indexed as a stale candidate → harmless (the
    ///   seek's re-check drops the now-invisible version).
    /// - A node **created** after build start → not in the snapshot, but `reindex_node` inserts its
    ///   current label/value on the creating write → covered.
    /// - A value **changed** mid-build → `reindex_node` inserts the new value as a candidate; the
    ///   snapshot scan may also insert the old value; both are candidates and the re-check keeps only
    ///   the current one → covered.
    ///
    /// So at completion every node that should match is a candidate (zero missed results), and only
    /// harmless stale candidates may exist — exactly the contract the executor's re-check already
    /// assumes.
    ///
    /// While `Populating`, the planner withholds the index (it is absent from
    /// [`catalog`](Self::catalog)), so reads fall back to a label-scan + filter and observe correct
    /// results throughout the build.
    ///
    /// # Errors
    /// Returns a storage error if interning either token, recording the catalog entry, the committing
    /// transaction, or the initial snapshot scan fails. On any error the index is left undeclared.
    ///
    /// # Naming
    /// This positional form is the internal / test / bench entry point: it assigns a deterministic
    /// **auto-name** (`rmp` task #624) and is **idempotent** on the covered `(label, property)` — a
    /// re-declare is a clean no-op success. The named server surface (a Cypher `CREATE INDEX`) goes
    /// through [`begin_online_node_property_index_named`](Self::begin_online_node_property_index_named),
    /// which enforces global name uniqueness and Neo4j `IF NOT EXISTS` semantics.
    pub fn begin_online_node_property_index(&mut self, label: &str, property: &str) -> Result<()> {
        // `if_not_exists = true` preserves the historical idempotent-on-redeclare behaviour of this
        // positional API (a second declare of the same index is a no-op, never an error). The
        // created-vs-no-op flag is irrelevant to the positional callers, so it is discarded here.
        self.begin_online_node_property_index_named(None, label, property, true)
            .map(|_created| ())
    }

    /// Declares a **named** node-property index on `(label, property)` and starts a **non-blocking**
    /// background build of it, enforcing Neo4j-conformant schema semantics (`rmp` tasks #91, #624):
    ///
    /// - `name` is the requested server-unique name, or [`None`] to auto-generate a deterministic one
    ///   ([`auto_index_name`]);
    /// - the covered `(label, property)` must not already be indexed by an **equivalent** index, and
    ///   the resolved name must not already be used by **any** schema catalog (node-property, full-text,
    ///   spatial, constraint) — names are globally unique;
    /// - `if_not_exists` turns both "already exists" cases (equivalent index / name in use) into a
    ///   **no-op success** instead of an error, matching `CREATE INDEX … IF NOT EXISTS`.
    ///
    /// Returns whether the index was **actually created** (`true`) or the call was an idempotent no-op
    /// (`false`, an `IF NOT EXISTS` that changed nothing) — the executor turns `false` into a `0`
    /// `indexes-added` counter (`rmp` task #626 follow-up: Neo4j-conformant idempotent-DDL summary).
    ///
    /// The build snapshot / no-missed-results contract is identical to the positional
    /// [`begin_online_node_property_index`](Self::begin_online_node_property_index) (see its docs); this
    /// method only adds the naming + idempotency layer around it.
    ///
    /// # Errors
    /// - `Neo.ClientError.Schema.EquivalentSchemaRuleAlreadyExists` (no `IF NOT EXISTS`) when an
    ///   equivalent index on `(label, property)` already exists;
    /// - `Neo.ClientError.Schema.IndexWithNameAlreadyExists` (no `IF NOT EXISTS`) when `name` is already
    ///   taken by another schema rule;
    /// - a storage error if interning a token, recording the catalog entry, committing, or the initial
    ///   snapshot scan fails. On any error the index is left undeclared.
    pub fn begin_online_node_property_index_named(
        &mut self,
        name: Option<&str>,
        label: &str,
        property: &str,
        if_not_exists: bool,
    ) -> Result<bool> {
        // 1. Equivalent-index check (read-only, by token *lookup* — an absent token means no index).
        let equivalent_exists = {
            let store = self.store.borrow();
            matches!(
                (
                    store.token_id(Namespace::Label, label),
                    store.token_id(Namespace::PropKey, property),
                ),
                (Some(lt), Some(pk)) if store.node_property_index_state(lt, pk).is_some()
            )
        };
        if equivalent_exists {
            return if if_not_exists {
                Ok(false) // idempotent no-op: nothing was added.
            } else {
                Err(equivalent_index_exists(label, property))
            };
        }

        // 2. Explicit-name global uniqueness (read-only). An omitted name is auto-generated in step 3
        //    (it needs the interned tokens for its deterministic collision suffix).
        if let Some(n) = name
            && Self::name_in_use(&self.store.borrow(), n)
        {
            return if if_not_exists {
                Ok(false) // idempotent no-op: nothing was added.
            } else {
                Err(index_name_in_use(n))
            };
        }

        // 3. Intern the tokens and record the durable catalog entry (`Populating`) + its name, in one
        //    committed transaction — so the schema change survives a crash atomically, and an interrupted
        //    build recovers `Populating` and is completed by the open-time rebuild.
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
            let effective_name = match name {
                Some(n) => n.to_owned(),
                None => {
                    Self::unique_auto_index_name(&store, label, property, label_token, prop_key)
                }
            };
            store.set_node_property_index(label_token, prop_key, IndexState::Populating);
            store.set_node_property_index_name(effective_name, label_token, prop_key);
            (label_token, prop_key)
        };
        self.store.borrow_mut().commit(txn)?;

        // Register the index `Populating` in the in-memory set so concurrent writes maintain it from
        // now on (the planner still withholds it until it is promoted `Online`).
        self.index.borrow_mut().register_node_property_with_state(
            label_token,
            prop_key,
            IndexState::Populating,
        );

        // Snapshot the current live node-id list and enqueue the pending build. The scan is the only
        // store walk here; the per-node indexing is deferred to `advance_index_builds`.
        let snapshot = self.store.borrow_mut().scan_node_ids()?;
        self.pending_builds.push_back(PendingIndexBuild {
            label_token,
            prop_key,
            snapshot,
            cursor: 0,
            generation: self.index.borrow().wipe_generation(),
            stall: BUILD_STALL_BUDGET,
        });
        Ok(true) // the index was created.
    }

    /// Declares a node index over `(label, properties)` — a **single-property** RANGE index when
    /// `properties` has arity 1, or a **composite** (multi-property) RANGE index when arity ≥ 2
    /// (`rmp` task #657) — enforcing Neo4j-conformant schema semantics.
    ///
    /// This is the single server entry point behind `CREATE INDEX FOR (n:L) ON (n.a[, n.b, …])`:
    ///
    /// - **arity 1** delegates verbatim to
    ///   [`begin_online_node_property_index_named`](Self::begin_online_node_property_index_named), so the
    ///   single-property (non-blocking, `Populating` → `Online`) path is untouched — nothing regresses;
    /// - **arity ≥ 2** declares a **standalone** composite index — distinct from a node-key constraint's
    ///   backing composite (`rmp` task #100), it enforces **no uniqueness**. The label + property-key
    ///   tokens are interned **durably** and the named catalog entry is recorded as
    ///   [`IndexState::Online`] in one committed transaction (so the *registration* survives a crash),
    ///   then the index is registered in the in-memory [`IndexSet`] and **synchronously built** from the
    ///   current nodes. The synchronous build is crash-safe: the backing tree is ephemeral and rebuilt
    ///   from the durable catalog + store on open, so a crash mid-build recovers the `Online`
    ///   registration and repopulates it — recovery never observes a half-built index.
    ///
    /// The composite key **order is significant** (`(a, b)` differs from `(b, a)`). Returns whether the
    /// index was **actually created** (`true`) or the call was an idempotent no-op (`false`, an
    /// `IF NOT EXISTS` that changed nothing).
    ///
    /// # Errors
    /// - `Neo.ClientError.Schema.EquivalentSchemaRuleAlreadyExists` (no `IF NOT EXISTS`) when an
    ///   equivalent composite index on `(label, ordered tuple)` already exists;
    /// - `Neo.ClientError.Schema.IndexWithNameAlreadyExists` (no `IF NOT EXISTS`) when `name` is already
    ///   taken by another schema rule;
    /// - a storage error if interning a token, recording the catalog entry, committing, or the build
    ///   scan fails. On any error the index is left undeclared.
    ///
    /// # Panics
    /// Panics if `properties` is empty (the parser guarantees at least one property; a composite has two
    /// or more).
    pub fn begin_online_node_composite_index_named(
        &mut self,
        name: Option<&str>,
        label: &str,
        properties: &[String],
        if_not_exists: bool,
    ) -> Result<bool> {
        assert!(
            !properties.is_empty(),
            "a node index covers at least one property"
        );
        // Arity 1: keep the single-property path (non-blocking build, no regression).
        if let [property] = properties {
            return self.begin_online_node_property_index_named(
                name,
                label,
                property,
                if_not_exists,
            );
        }

        // ---- Arity ≥ 2: a standalone composite index (`rmp` task #657) --------------------------------

        // 1. Equivalent-index check (read-only, by token *lookup* — an absent token means no index can
        //    cover this tuple, so no equivalent exists).
        let equivalent_exists = {
            let store = self.store.borrow();
            match Self::resolve_property_tokens(&store, label, properties) {
                Some((label_token, property_tokens)) => store
                    .composite_index_name_for(label_token, &property_tokens)
                    .is_some(),
                None => false,
            }
        };
        if equivalent_exists {
            return if if_not_exists {
                Ok(false) // idempotent no-op: nothing was added.
            } else {
                Err(equivalent_composite_index_exists(label, properties))
            };
        }

        // 2. Explicit-name global uniqueness (read-only). An omitted name is auto-generated in step 3.
        if let Some(n) = name
            && Self::name_in_use(&self.store.borrow(), n)
        {
            return if if_not_exists {
                Ok(false)
            } else {
                Err(index_name_in_use(n))
            };
        }

        // 3. Intern the tokens and record the durable catalog entry (`Online`) in one committed
        //    transaction — so the schema change survives a crash atomically.
        self.next_txn_id += 1;
        let txn = TxnId(self.next_txn_id);
        self.store.borrow_mut().begin(txn);
        let (label_token, property_tokens, effective_name) = {
            let mut store = self.store.borrow_mut();
            let label_token = match store.intern_token(Namespace::Label, label) {
                Ok(t) => t,
                Err(e) => {
                    drop(store);
                    let _ = self.store.borrow_mut().rollback(txn);
                    return Err(e);
                }
            };
            let mut property_tokens = Vec::with_capacity(properties.len());
            for property in properties {
                match store.intern_token(Namespace::PropKey, property) {
                    Ok(t) => property_tokens.push(t),
                    Err(e) => {
                        drop(store);
                        let _ = self.store.borrow_mut().rollback(txn);
                        return Err(e);
                    }
                }
            }
            let effective_name = match name {
                Some(n) => n.to_owned(),
                None => Self::unique_auto_composite_index_name(
                    &store,
                    label,
                    properties,
                    label_token,
                    &property_tokens,
                ),
            };
            store.set_composite_index(
                effective_name.clone(),
                CompositeIndexEntry {
                    label_token,
                    property_tokens: property_tokens.clone(),
                    state: IndexState::Online,
                },
            );
            (label_token, property_tokens, effective_name)
        };
        let _ = effective_name; // recorded durably above; the in-memory tree is keyed by target, not name.
        self.store.borrow_mut().commit(txn)?;

        // Register the composite in the in-memory set so concurrent writes maintain it from now on, then
        // synchronously index the existing nodes into its backing tree. The tree is ephemeral (rebuilt on
        // open from the durable catalog + store), so this synchronous fill is a pure in-memory build with
        // no durability surface — a crash before it finishes recovers the `Online` registration and the
        // open-time rebuild repopulates the tree store-consistently.
        self.index
            .borrow_mut()
            .register_composite(label_token, property_tokens.clone());
        let node_ids = match self.store.borrow_mut().scan_node_ids() {
            Ok(ids) => ids,
            Err(e) => {
                // The build could not start (`rmp` task #733). A composite index carries no
                // [`IndexState`] in the in-memory set — its consumers gate on *registration*
                // (`has_composite`) — so the only way to make it unusable is to **unregister** it.
                // Leaving it registered-and-empty would be far worse than slow: the node-key duplicate
                // check (`composite_seek_eq`) trusts it as an exact candidate source, so an empty tree
                // would report "no duplicate" for every tuple and let a NODE KEY constraint be violated.
                // Unregistered, both the planner's seek and the duplicate check fall back to the exact
                // label scan; the durable catalog is untouched, so any later successful `rebuild_index`
                // (or a reopen) re-registers and repopulates it.
                self.index
                    .borrow_mut()
                    .unregister_composite(label_token, &property_tokens);
                return Err(e);
            }
        };
        let registered = vec![(label_token, property_tokens.clone())];
        self.index.borrow_mut().clear_rebuild_gap();
        for id in node_ids {
            Self::index_one_node_composite(&self.store, &self.index, id, &registered);
        }
        // A node the fill could not read is missing from the composite tree for good (`rmp` task #733) —
        // and a node-key constraint trusts that tree as an EXACT candidate source, so a hole in it would
        // let a duplicate tuple through. Unregister (the tree has no state to demote), so the duplicate
        // check and the planner both fall back to the exact label scan, and surface the fault.
        if self.index.borrow().rebuild_gap() {
            let mut idx = self.index.borrow_mut();
            idx.clear_rebuild_gap();
            idx.unregister_composite(label_token, &property_tokens);
            drop(idx);
            return Err(GraphusError::Storage(
                "the composite index could not be built: the store scan skipped at least one node"
                    .to_owned(),
            ));
        }
        Ok(true) // the index was created.
    }

    /// Resolves `(label, properties)` to `(label_token, property_tokens)` by **token lookup** (never
    /// interning) (`rmp` task #657). Returns [`None`] if the label or **any** property key has no
    /// interned token — meaning no index can cover this tuple, so no equivalent index exists.
    fn resolve_property_tokens(
        store: &RecordStore<D, S>,
        label: &str,
        properties: &[String],
    ) -> Option<(u32, Vec<u32>)> {
        let label_token = store.token_id(Namespace::Label, label)?;
        let mut property_tokens = Vec::with_capacity(properties.len());
        for property in properties {
            property_tokens.push(store.token_id(Namespace::PropKey, property)?);
        }
        Some((label_token, property_tokens))
    }

    /// A globally-unique, deterministic auto-name for the composite index on `(label, properties)`
    /// (`rmp` task #657) — the composite analogue of
    /// [`unique_auto_index_name`](Self::unique_auto_index_name). The equivalence check in the caller has
    /// already guaranteed no composite index covers this exact target, so the base name can only collide
    /// with an *unrelated* schema rule; a deterministic token-suffixed form, then a numeric counter,
    /// resolves any residual collision so the returned name is free across **every** catalog.
    fn unique_auto_composite_index_name(
        store: &RecordStore<D, S>,
        label: &str,
        properties: &[String],
        label_token: u32,
        property_tokens: &[u32],
    ) -> String {
        let base = auto_composite_index_name(label, properties);
        if !Self::name_in_use(store, &base) {
            return base;
        }
        let mut suffixed = format!("{base}_{label_token}");
        for t in property_tokens {
            suffixed.push('_');
            suffixed.push_str(&t.to_string());
        }
        if !Self::name_in_use(store, &suffixed) {
            return suffixed;
        }
        let mut n: u64 = 2;
        loop {
            let candidate = format!("{suffixed}_{n}");
            if !Self::name_in_use(store, &candidate) {
                return candidate;
            }
            n += 1;
        }
    }

    /// Declares a relationship index over `(rel_type, properties)` — a **single-property** RANGE index
    /// when `properties` has arity 1, or a **composite** (multi-property) RANGE index when arity ≥ 2
    /// (`rmp` task #666) — the relationship analogue of
    /// [`begin_online_node_composite_index_named`](Self::begin_online_node_composite_index_named).
    ///
    /// This is the single server entry point behind `CREATE INDEX FOR ()-[r:T]-() ON (r.a[, r.b, …])`:
    ///
    /// - **arity 1** delegates verbatim to
    ///   [`create_rel_property_index_named`](Self::create_rel_property_index_named), so the
    ///   single-property relationship path is untouched — nothing regresses;
    /// - **arity ≥ 2** declares a **standalone** composite relationship index (no uniqueness). The
    ///   relationship-type + property-key tokens are interned **durably** and the named catalog entry is
    ///   recorded [`IndexState::Online`] in one committed transaction (so the *registration* survives a
    ///   crash), then the index is registered in the in-memory [`IndexSet`] and **synchronously built**
    ///   from the current relationships. The synchronous build is crash-safe: the backing tree is
    ///   ephemeral and rebuilt from the durable catalog + store on open, so recovery never observes a
    ///   half-built index.
    ///
    /// The composite key **order is significant** (`(a, b)` differs from `(b, a)`). Returns whether the
    /// index was **actually created** (`true`) or the call was an idempotent no-op (`false`).
    ///
    /// # Errors
    /// - `Neo.ClientError.Schema.EquivalentSchemaRuleAlreadyExists` (no `IF NOT EXISTS`) when an
    ///   equivalent composite relationship index on `(rel_type, ordered tuple)` already exists;
    /// - `Neo.ClientError.Schema.IndexWithNameAlreadyExists` (no `IF NOT EXISTS`) when `name` is already
    ///   taken by another schema rule;
    /// - a storage error if interning a token, recording the catalog entry, committing, or the build
    ///   scan fails. On any error the index is left undeclared.
    ///
    /// # Panics
    /// Panics if `properties` is empty (the parser guarantees at least one property).
    pub fn begin_online_rel_composite_index_named(
        &mut self,
        name: Option<&str>,
        rel_type: &str,
        properties: &[String],
        if_not_exists: bool,
    ) -> Result<bool> {
        assert!(
            !properties.is_empty(),
            "a relationship index covers at least one property"
        );
        // Arity 1: keep the single-property relationship path (no regression).
        if let [property] = properties {
            return self.create_rel_property_index_named(name, rel_type, property, if_not_exists);
        }

        // ---- Arity ≥ 2: a standalone composite relationship index (`rmp` task #666) ------------------

        // 1. Equivalent-index check (read-only, by token *lookup* — an absent token means no index can
        //    cover this tuple, so no equivalent exists).
        let equivalent_exists = {
            let store = self.store.borrow();
            match Self::resolve_rel_property_tokens(&store, rel_type, properties) {
                Some((type_token, property_tokens)) => store
                    .rel_composite_index_name_for(type_token, &property_tokens)
                    .is_some(),
                None => false,
            }
        };
        if equivalent_exists {
            return if if_not_exists {
                Ok(false) // idempotent no-op: nothing was added.
            } else {
                Err(equivalent_rel_composite_index_exists(rel_type, properties))
            };
        }

        // 2. Explicit-name global uniqueness (read-only). An omitted name is auto-generated in step 3.
        if let Some(n) = name
            && Self::name_in_use(&self.store.borrow(), n)
        {
            return if if_not_exists {
                Ok(false)
            } else {
                Err(index_name_in_use(n))
            };
        }

        // 3. Intern the tokens and record the durable catalog entry (`Online`) in one committed
        //    transaction — so the schema change survives a crash atomically.
        self.next_txn_id += 1;
        let txn = TxnId(self.next_txn_id);
        self.store.borrow_mut().begin(txn);
        let (type_token, property_tokens, effective_name) = {
            let mut store = self.store.borrow_mut();
            let type_token = match store.intern_token(Namespace::RelType, rel_type) {
                Ok(t) => t,
                Err(e) => {
                    drop(store);
                    let _ = self.store.borrow_mut().rollback(txn);
                    return Err(e);
                }
            };
            let mut property_tokens = Vec::with_capacity(properties.len());
            for property in properties {
                match store.intern_token(Namespace::PropKey, property) {
                    Ok(t) => property_tokens.push(t),
                    Err(e) => {
                        drop(store);
                        let _ = self.store.borrow_mut().rollback(txn);
                        return Err(e);
                    }
                }
            }
            let effective_name = match name {
                Some(n) => n.to_owned(),
                None => Self::unique_auto_rel_composite_index_name(
                    &store,
                    rel_type,
                    properties,
                    type_token,
                    &property_tokens,
                ),
            };
            store.set_rel_composite_index(
                effective_name.clone(),
                RelCompositeIndexEntry {
                    type_token,
                    property_tokens: property_tokens.clone(),
                    state: IndexState::Online,
                },
            );
            (type_token, property_tokens, effective_name)
        };
        let _ = effective_name; // recorded durably above; the in-memory tree is keyed by target, not name.
        self.store.borrow_mut().commit(txn)?;

        // Register the composite in the in-memory set so concurrent writes maintain it, then synchronously
        // index the existing relationships into its backing tree. The tree is ephemeral (rebuilt on open),
        // so this synchronous fill has no durability surface — a crash recovers the `Online` registration
        // and the open-time rebuild repopulates the tree store-consistently.
        self.index
            .borrow_mut()
            .register_rel_composite(type_token, property_tokens.clone());
        let rel_ids = match self.store.borrow().scan_rel_ids() {
            Ok(ids) => ids,
            Err(e) => {
                // The build could not start: unregister so the empty tree can never answer a seek
                // (`rmp` task #733) — the relationship twin of the node composite fail-closed above.
                self.index
                    .borrow_mut()
                    .unregister_rel_composite(type_token, &property_tokens);
                return Err(e);
            }
        };
        let registered = vec![(type_token, property_tokens.clone())];
        self.index.borrow_mut().clear_rebuild_gap();
        for id in rel_ids {
            Self::index_one_rel_composite(&self.store, &self.index, id, &registered);
        }
        // The relationship twin of the node composite guard (`rmp` task #733): unregister the holed tree
        // so every consumer falls back to the exact typed scan, and surface the fault.
        if self.index.borrow().rebuild_gap() {
            let mut idx = self.index.borrow_mut();
            idx.clear_rebuild_gap();
            idx.unregister_rel_composite(type_token, &property_tokens);
            drop(idx);
            return Err(GraphusError::Storage(
                "the composite relationship index could not be built: the store scan skipped at \
                 least one relationship"
                    .to_owned(),
            ));
        }
        Ok(true) // the index was created.
    }

    /// Resolves `(rel_type, properties)` to `(type_token, property_tokens)` by **token lookup** (never
    /// interning) (`rmp` task #666) — the relationship analogue of
    /// [`resolve_property_tokens`](Self::resolve_property_tokens). Returns [`None`] if the relationship
    /// type or **any** property key has no interned token — meaning no index can cover this tuple.
    fn resolve_rel_property_tokens(
        store: &RecordStore<D, S>,
        rel_type: &str,
        properties: &[String],
    ) -> Option<(u32, Vec<u32>)> {
        let type_token = store.token_id(Namespace::RelType, rel_type)?;
        let mut property_tokens = Vec::with_capacity(properties.len());
        for property in properties {
            property_tokens.push(store.token_id(Namespace::PropKey, property)?);
        }
        Some((type_token, property_tokens))
    }

    /// A globally-unique, deterministic auto-name for the composite relationship index on
    /// `(rel_type, properties)` (`rmp` task #666) — the relationship analogue of
    /// [`unique_auto_composite_index_name`](Self::unique_auto_composite_index_name).
    fn unique_auto_rel_composite_index_name(
        store: &RecordStore<D, S>,
        rel_type: &str,
        properties: &[String],
        type_token: u32,
        property_tokens: &[u32],
    ) -> String {
        let base = auto_rel_composite_index_name(rel_type, properties);
        if !Self::name_in_use(store, &base) {
            return base;
        }
        let mut suffixed = format!("{base}_{type_token}");
        for t in property_tokens {
            suffixed.push('_');
            suffixed.push_str(&t.to_string());
        }
        if !Self::name_in_use(store, &suffixed) {
            return suffixed;
        }
        let mut n: u64 = 2;
        loop {
            let candidate = format!("{suffixed}_{n}");
            if !Self::name_in_use(store, &candidate) {
                return candidate;
            }
            n += 1;
        }
    }

    /// Declares a **full-text index** named `name` over `(label, properties)` analyzed with
    /// `analyzer`, **durably records it**, and starts a **non-blocking** background build of it
    /// (`rmp` task #72) — the full-text analogue of
    /// [`begin_online_node_property_index`](Self::begin_online_node_property_index).
    ///
    /// The label and property-key tokens are interned **durably** and the named catalog entry is
    /// recorded as [`IndexState::Populating`] — both in one committed transaction, so the
    /// *registration* survives a crash (an interrupted build recovers `Populating` and is completed by
    /// the open-time rebuild). The index is registered in the in-memory [`IndexSet`] so concurrent
    /// writes maintain it from now on, and a pending build is enqueued; **no node is scanned here**, so
    /// the engine stays responsive. The build is advanced in bounded chunks by
    /// [`advance_index_builds`](Self::advance_index_builds) and promoted to [`IndexState::Online`] only
    /// when every snapshot node has been indexed.
    ///
    /// Re-declaring an existing name **replaces** it (a fresh build over the new label/properties).
    ///
    /// # Errors
    /// Returns a storage error if `properties` is empty, interning any token, recording the catalog
    /// entry, the committing transaction, or the initial snapshot scan fails. On any error the index
    /// is left undeclared.
    pub fn create_fulltext_index(
        &mut self,
        name: &str,
        labels: &[String],
        properties: &[String],
        analyzer: Analyzer,
        if_not_exists: bool,
    ) -> Result<bool> {
        if properties.is_empty() {
            return Err(GraphusError::Storage(
                "a full-text index must cover at least one property".to_owned(),
            ));
        }
        if labels.is_empty() {
            return Err(GraphusError::Storage(
                "a node full-text index must cover at least one label".to_owned(),
            ));
        }
        // `IF NOT EXISTS` (`rmp` #661): an equivalent index — the same `name` in the full-text catalog,
        // or the same covered `(entity, ordered label/type tuple, ordered property tuple)` under any
        // name — makes this an idempotent no-op (nothing added), mirroring the node-property path.
        if if_not_exists
            && self.fulltext_equivalent_exists(name, FulltextEntity::Node, labels, properties)
        {
            return Ok(false);
        }
        // Names are globally unique across every schema catalog (`rmp` task #624): reject a name already
        // used by a *different* catalog. Re-declaring within the full-text catalog keeps its historical
        // replace semantics (a name it already owns is not "used by another catalog").
        if Self::name_used_by_other_catalog(&self.store.borrow(), name, NameCatalog::Fulltext) {
            return Err(index_name_in_use(name));
        }

        // Intern the label + property-key tokens and record the durable catalog entry `Populating`, in
        // one committed transaction (so the schema change survives a crash atomically).
        self.next_txn_id += 1;
        let txn = TxnId(self.next_txn_id);
        self.store.borrow_mut().begin(txn);
        let entry = {
            let mut store = self.store.borrow_mut();
            let mut label_tokens = Vec::with_capacity(labels.len());
            for label in labels {
                match store.intern_token(Namespace::Label, label) {
                    Ok(t) => {
                        // De-duplicate a repeated label (`FOR (n:A|A)`) so the token set stays minimal.
                        if !label_tokens.contains(&t) {
                            label_tokens.push(t);
                        }
                    }
                    Err(e) => {
                        drop(store);
                        let _ = self.store.borrow_mut().rollback(txn);
                        return Err(e);
                    }
                }
            }
            let mut property_tokens = Vec::with_capacity(properties.len());
            for property in properties {
                match store.intern_token(Namespace::PropKey, property) {
                    Ok(t) => property_tokens.push(t),
                    Err(e) => {
                        drop(store);
                        let _ = self.store.borrow_mut().rollback(txn);
                        return Err(e);
                    }
                }
            }
            let entry = FulltextIndexEntry {
                entity: FulltextEntity::Node,
                tokens: label_tokens,
                property_tokens,
                analyzer: analyzer.as_byte(),
                state: IndexState::Populating,
            };
            store.set_fulltext_index(name.to_owned(), entry.clone());
            entry
        };
        self.store.borrow_mut().commit(txn)?;

        // Register the index `Populating` in the in-memory set so concurrent writes maintain it.
        self.index.borrow_mut().register_fulltext(
            name,
            entry.tokens,
            entry.property_tokens,
            analyzer,
            IndexState::Populating,
        );

        // Cancel any prior pending build of the same name (a re-declare), then enqueue this one.
        self.pending_fulltext_builds.retain(|b| b.name != name);
        let snapshot = self.store.borrow_mut().scan_node_ids()?;
        self.pending_fulltext_builds
            .push_back(PendingFulltextBuild {
                name: name.to_owned(),
                snapshot,
                cursor: 0,
                generation: self.index.borrow().wipe_generation(),
                stall: BUILD_STALL_BUDGET,
            });
        Ok(true)
    }

    /// Declares a **relationship** full-text index named `name` over `types` (one or more relationship
    /// types) + `properties`, analyzed by `analyzer`, and **synchronously builds** it (`rmp` task #663)
    /// — the relationship analogue of [`create_fulltext_index`](Self::create_fulltext_index).
    ///
    /// Unlike the node full-text index (which builds non-blockingly), the relationship index is built
    /// **synchronously and recorded `Online`** in one committed transaction, then a full
    /// [`rebuild_index`](Self::rebuild_index) repopulates its rel-keyed inverted index from the store —
    /// exactly the pattern the relationship-property index (`rmp` #646) uses. `rebuild_index` also
    /// resets the shared full-text/spatial freshness marker to the store's high-water, so a reader whose
    /// snapshot predates the build declines to the correct scan path.
    ///
    /// # Errors
    /// Returns a storage error if `types` or `properties` is empty, interning any token, recording the
    /// catalog entry, or the committing transaction fails. On any error the index is left undeclared.
    pub fn create_fulltext_rel_index(
        &mut self,
        name: &str,
        types: &[String],
        properties: &[String],
        analyzer: Analyzer,
        if_not_exists: bool,
    ) -> Result<bool> {
        if properties.is_empty() {
            return Err(GraphusError::Storage(
                "a full-text index must cover at least one property".to_owned(),
            ));
        }
        if types.is_empty() {
            return Err(GraphusError::Storage(
                "a relationship full-text index must cover at least one type".to_owned(),
            ));
        }
        if if_not_exists
            && self.fulltext_equivalent_exists(
                name,
                FulltextEntity::Relationship,
                types,
                properties,
            )
        {
            return Ok(false);
        }
        if Self::name_used_by_other_catalog(&self.store.borrow(), name, NameCatalog::Fulltext) {
            return Err(index_name_in_use(name));
        }

        self.next_txn_id += 1;
        let txn = TxnId(self.next_txn_id);
        self.store.borrow_mut().begin(txn);
        let entry = {
            let mut store = self.store.borrow_mut();
            let mut type_tokens = Vec::with_capacity(types.len());
            for ty in types {
                match store.intern_token(Namespace::RelType, ty) {
                    Ok(t) => {
                        if !type_tokens.contains(&t) {
                            type_tokens.push(t);
                        }
                    }
                    Err(e) => {
                        drop(store);
                        let _ = self.store.borrow_mut().rollback(txn);
                        return Err(e);
                    }
                }
            }
            let mut property_tokens = Vec::with_capacity(properties.len());
            for property in properties {
                match store.intern_token(Namespace::PropKey, property) {
                    Ok(t) => property_tokens.push(t),
                    Err(e) => {
                        drop(store);
                        let _ = self.store.borrow_mut().rollback(txn);
                        return Err(e);
                    }
                }
            }
            // Synchronous build → recorded `Online` (the relationship-property/composite precedent).
            let entry = FulltextIndexEntry {
                entity: FulltextEntity::Relationship,
                tokens: type_tokens,
                property_tokens,
                analyzer: analyzer.as_byte(),
                state: IndexState::Online,
            };
            store.set_fulltext_index(name.to_owned(), entry.clone());
            entry
        };
        self.store.borrow_mut().commit(txn)?;

        // Register the index `Online` in the in-memory set and (re)build it so existing relationships
        // are indexed — `rebuild_index` scans the relationships, populates the rel-keyed inverted index,
        // and resets the shared full-text/spatial marker to the store's high-water.
        self.index.borrow_mut().register_fulltext_rel(
            name,
            entry.tokens,
            entry.property_tokens,
            analyzer,
            IndexState::Online,
        );
        Self::rebuild_index(&self.store, &self.index);
        Ok(true)
    }

    /// Whether a full-text index equivalent to the requested `(name, entity, tokens, properties)`
    /// already exists (`rmp` #661, #663) — the same `name` in the full-text catalog, or the same covered
    /// `(entity, ordered label/type tuple, ordered property tuple)` under any name. Backs
    /// `CREATE FULLTEXT INDEX … IF NOT EXISTS` idempotency. Read-only, by token *lookup* (an unindexable
    /// token tuple means no index can cover it, so no equivalent exists).
    fn fulltext_equivalent_exists(
        &self,
        name: &str,
        entity: FulltextEntity,
        tokens: &[String],
        properties: &[String],
    ) -> bool {
        let store = self.store.borrow();
        if store.fulltext_index(name).is_some() {
            return true;
        }
        // Resolve the covering tokens in the right namespace (labels for a node index, rel types for a
        // relationship index) and the property tokens. A never-interned token means no index can cover
        // it, so no equivalent exists.
        let namespace = if entity.is_relationship() {
            Namespace::RelType
        } else {
            Namespace::Label
        };
        let mut token_ids = Vec::with_capacity(tokens.len());
        for tok in tokens {
            let Some(t) = store.token_id(namespace, tok) else {
                return false;
            };
            if !token_ids.contains(&t) {
                token_ids.push(t);
            }
        }
        let mut property_tokens = Vec::with_capacity(properties.len());
        for property in properties {
            let Some(t) = store.token_id(Namespace::PropKey, property) else {
                return false;
            };
            property_tokens.push(t);
        }
        store.fulltext_indexes().iter().any(|(_n, e)| {
            e.entity == entity && e.tokens == token_ids && e.property_tokens == property_tokens
        })
    }

    /// Drops the full-text index named `name` (`rmp` task #72): removes its durable catalog entry in a
    /// committed transaction, unregisters it from the in-memory [`IndexSet`], and cancels any
    /// in-progress build. Idempotent on a never-declared name (a clean no-op success).
    ///
    /// Returns whether an index was **actually removed** (`true`) or the call was a no-op (`false`, no
    /// such index) — the executor turns `false` into a `0` `indexes-removed` counter (`rmp` task #626
    /// follow-up: Neo4j-conformant idempotent-DDL summary).
    ///
    /// # Errors
    /// Returns a storage error if the committing transaction fails.
    pub fn drop_fulltext_index(&mut self, name: &str, if_exists: bool) -> Result<bool> {
        // Not declared: without `IF EXISTS` this is a `Neo.ClientError.Schema.IndexDropFailed` error
        // (Neo4j) and side-effect-free (nothing durable to remove). With `IF EXISTS` it is a clean no-op
        // success — defensively cancel any stray in-flight build + in-memory registration first
        // (`rmp` tasks #72, #661).
        if self.store.borrow().fulltext_index(name).is_none() {
            if !if_exists {
                return Err(index_drop_not_found(name));
            }
            self.pending_fulltext_builds.retain(|b| b.name != name);
            // The name is unique across catalogs, so at most one of these unregisters anything
            // (`rmp` task #663): one is a no-op.
            self.index.borrow_mut().unregister_fulltext(name);
            self.index.borrow_mut().unregister_fulltext_rel(name);
            return Ok(false); // nothing removed.
        }
        self.next_txn_id += 1;
        let txn = TxnId(self.next_txn_id);
        self.store.borrow_mut().begin(txn);
        self.store.borrow_mut().remove_fulltext_index(name);
        self.store.borrow_mut().commit(txn)?;

        self.pending_fulltext_builds.retain(|b| b.name != name);
        // Unregister from whichever in-memory map holds it (node or relationship, `rmp` #663).
        self.index.borrow_mut().unregister_fulltext(name);
        self.index.borrow_mut().unregister_fulltext_rel(name);
        Ok(true) // an index was removed.
    }

    /// Lists every declared full-text index as `(name, entity, labels-or-types, properties, analyzer,
    /// state)` (`rmp` tasks #72, #663) for a `SHOW FULLTEXT INDEXES` surface. Reads the durable catalog
    /// and resolves the tokens back to names in the entity's namespace (labels for a node index, rel
    /// types for a relationship index); an entry whose tokens have no resolvable name (a
    /// defensively-skipped impossibility for a live token) or an unknown analyzer byte is omitted.
    /// Ordered by name.
    #[must_use]
    pub fn list_fulltext_indexes(&self) -> Vec<FulltextIndexListing> {
        let store = self.store.borrow();
        store
            .fulltext_indexes()
            .into_iter()
            .filter_map(|(name, entry)| {
                let token_namespace = if entry.entity.is_relationship() {
                    Namespace::RelType
                } else {
                    Namespace::Label
                };
                let mut labels_or_types = Vec::with_capacity(entry.tokens.len());
                for tok in &entry.tokens {
                    labels_or_types.push(store.token_name(token_namespace, *tok)?.to_owned());
                }
                let mut properties = Vec::with_capacity(entry.property_tokens.len());
                for pk in &entry.property_tokens {
                    properties.push(store.token_name(Namespace::PropKey, *pk)?.to_owned());
                }
                let analyzer = Analyzer::from_byte(entry.analyzer)?;
                // The EFFECTIVE state (`rmp` task #733): route by entity to the in-memory catalogue the
                // query seam actually consults, so a still-building (or fail-closed) index never reports
                // itself ONLINE — which is exactly what a `wait_for_indexes` poll keys on.
                let in_memory = if entry.entity.is_relationship() {
                    self.index.borrow().fulltext_rel_state(&name)
                } else {
                    self.index.borrow().fulltext_state(&name)
                };
                let state = Self::effective_state(entry.state, in_memory);
                Some((
                    name,
                    entry.entity,
                    labels_or_types,
                    properties,
                    analyzer,
                    state,
                ))
            })
            .collect()
    }

    /// Declares a **spatial (point) index** named `name` over `(label, property)`, **durably records
    /// it**, and starts a **non-blocking** background build of it (`rmp` task #98) — the spatial
    /// analogue of [`create_fulltext_index`](Self::create_fulltext_index).
    ///
    /// The label and property-key tokens are interned **durably** and the named catalog entry is
    /// recorded as [`IndexState::Populating`] — both in one committed transaction, so the
    /// *registration* survives a crash (an interrupted build recovers `Populating` and is completed by
    /// the open-time rebuild). The grid is registered in the in-memory [`IndexSet`] so concurrent
    /// writes maintain it from now on, and a pending build is enqueued; **no node is scanned here**, so
    /// the engine stays responsive. The build is advanced in bounded chunks by
    /// [`advance_index_builds`](Self::advance_index_builds) and promoted to [`IndexState::Online`] only
    /// when every snapshot node has been indexed — and only an `Online` spatial index drives a
    /// `SpatialIndexSeek` (see [`catalog`](Self::catalog) / [`IndexSet::online_spatial`]).
    ///
    /// Re-declaring an existing name **replaces** it (a fresh build over the new label/property).
    ///
    /// # Errors
    /// Returns a storage error if interning either token, recording the catalog entry, the committing
    /// transaction, or the initial snapshot scan fails. On any error the index is left undeclared.
    pub fn create_point_index(
        &mut self,
        name: &str,
        label: &str,
        property: &str,
        if_not_exists: bool,
    ) -> Result<bool> {
        // `IF NOT EXISTS` (`rmp` #661): an equivalent index — the same `name` in the spatial catalog, or
        // the same covered `(label, property)` under any name — makes this an idempotent no-op (nothing
        // added), mirroring the node-property path.
        if if_not_exists && self.point_equivalent_exists(name, label, property) {
            return Ok(false);
        }
        // Names are globally unique across every schema catalog (`rmp` task #624): reject a name already
        // used by a *different* catalog (a re-declare within the spatial catalog keeps replace semantics).
        if Self::name_used_by_other_catalog(&self.store.borrow(), name, NameCatalog::Spatial) {
            return Err(index_name_in_use(name));
        }
        // Intern the label + property-key tokens and record the durable catalog entry `Populating`, in
        // one committed transaction (so the schema change survives a crash atomically).
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
            store.set_spatial_index(
                name.to_owned(),
                SpatialIndexEntry {
                    entity: SpatialEntity::Node,
                    label_token,
                    property_token: prop_key,
                    state: IndexState::Populating,
                },
            );
            (label_token, prop_key)
        };
        self.store.borrow_mut().commit(txn)?;

        // Register the grid `Populating` in the in-memory set so concurrent writes maintain it.
        self.index.borrow_mut().register_spatial(
            label_token,
            prop_key,
            graphus_index::DEFAULT_CELL_SIZE,
            IndexState::Populating,
        );

        // Cancel any prior pending build of the same name (a re-declare), then enqueue this one.
        self.pending_spatial_builds.retain(|b| b.name != name);
        let snapshot = self.store.borrow_mut().scan_node_ids()?;
        self.pending_spatial_builds.push_back(PendingSpatialBuild {
            name: name.to_owned(),
            label_token,
            prop_key,
            snapshot,
            cursor: 0,
            generation: self.index.borrow().wipe_generation(),
            stall: BUILD_STALL_BUDGET,
        });
        Ok(true)
    }

    /// Declares a **relationship** spatial (point) index named `name` over `(rel_type, property)`
    /// (`rmp` task #664) — the relationship analogue of [`create_point_index`](Self::create_point_index).
    ///
    /// Unlike the node point index (which builds non-blockingly), the relationship index is built
    /// **synchronously and recorded `Online`** in one committed transaction, then a full
    /// [`rebuild_index`](Self::rebuild_index) repopulates its rel-keyed grid from the store — exactly the
    /// pattern the relationship full-text (`rmp` #663) and relationship-property (`rmp` #646) indexes
    /// use. `rebuild_index` also resets the shared full-text/spatial freshness marker to the store's
    /// high-water, so a reader whose snapshot predates the build declines to the correct scan path.
    ///
    /// Returns whether the index was **actually created** (`true`) or the call was an idempotent no-op
    /// (`false`, an `IF NOT EXISTS` that changed nothing).
    ///
    /// # Errors
    /// Returns a storage error if interning any token, recording the catalog entry, or the committing
    /// transaction fails; `Neo.ClientError.Schema.IndexWithNameAlreadyExists` when `name` is already
    /// taken by another schema catalog. On any error the index is left undeclared.
    pub fn create_point_rel_index(
        &mut self,
        name: &str,
        rel_type: &str,
        property: &str,
        if_not_exists: bool,
    ) -> Result<bool> {
        // `IF NOT EXISTS` (`rmp` #661): an equivalent relationship point index — the same name, or the
        // same covered `(type, property)` under any name — makes this an idempotent no-op.
        if if_not_exists && self.point_rel_equivalent_exists(name, rel_type, property) {
            return Ok(false);
        }
        // Names are globally unique across every schema catalog (`rmp` task #624).
        if Self::name_used_by_other_catalog(&self.store.borrow(), name, NameCatalog::Spatial) {
            return Err(index_name_in_use(name));
        }
        // Intern the rel-type + property-key tokens and record the durable catalog entry `Online`
        // (synchronous build), in one committed transaction (so the schema change survives a crash).
        self.next_txn_id += 1;
        let txn = TxnId(self.next_txn_id);
        self.store.borrow_mut().begin(txn);
        {
            let mut store = self.store.borrow_mut();
            let type_token = match store.intern_token(Namespace::RelType, rel_type) {
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
            store.set_spatial_index(
                name.to_owned(),
                SpatialIndexEntry {
                    entity: SpatialEntity::Relationship,
                    label_token: type_token,
                    property_token: prop_key,
                    state: IndexState::Online,
                },
            );
        }
        self.store.borrow_mut().commit(txn)?;

        // Register the grid `Online` in the in-memory set and (re)build it so existing relationships are
        // indexed — `rebuild_index` scans the relationships, populates the rel-keyed grid, and resets the
        // shared full-text/spatial marker to the store's high-water.
        let type_token = self
            .store
            .borrow()
            .token_id(Namespace::RelType, rel_type)
            .expect("INVARIANT: the rel-type token was just interned in the committed transaction");
        let prop_key = self
            .store
            .borrow()
            .token_id(Namespace::PropKey, property)
            .expect(
                "INVARIANT: the property-key token was just interned in the committed transaction",
            );
        self.index.borrow_mut().register_spatial_rel(
            type_token,
            prop_key,
            graphus_index::DEFAULT_CELL_SIZE,
            IndexState::Online,
        );
        Self::rebuild_index(&self.store, &self.index);
        Ok(true)
    }

    /// Whether a spatial (point) index equivalent to the requested `(name, label, property)` already
    /// exists (`rmp` #661) — the same `name` in the spatial catalog, or the same covered
    /// `(label, property)` under any name. Backs `CREATE POINT INDEX … IF NOT EXISTS` idempotency.
    /// Read-only, by token *lookup*.
    fn point_equivalent_exists(&self, name: &str, label: &str, property: &str) -> bool {
        let store = self.store.borrow();
        if store.spatial_index(name).is_some() {
            return true;
        }
        let props = [property.to_owned()];
        let Some((label_token, property_tokens)) =
            Self::resolve_property_tokens(&store, label, &props)
        else {
            return false;
        };
        let prop_token = property_tokens[0];
        store.spatial_indexes().iter().any(|(_n, e)| {
            // A node index equivalence: a relationship point index (same numeric token in a different
            // namespace) is never equivalent (`rmp` task #664).
            !e.entity.is_relationship()
                && e.label_token == label_token
                && e.property_token == prop_token
        })
    }

    /// Whether a **relationship** spatial (point) index equivalent to the requested `(name, type,
    /// property)` already exists (`rmp` task #664) — the same `name` in the spatial catalog, or the same
    /// covered `(type, property)` under any name. Backs `CREATE POINT INDEX … FOR ()-[r:T]-() … IF NOT
    /// EXISTS` idempotency. Read-only, by token *lookup*.
    fn point_rel_equivalent_exists(&self, name: &str, rel_type: &str, property: &str) -> bool {
        let store = self.store.borrow();
        if store.spatial_index(name).is_some() {
            return true;
        }
        let Some(type_token) = store.token_id(Namespace::RelType, rel_type) else {
            return false;
        };
        let Some(prop_token) = store.token_id(Namespace::PropKey, property) else {
            return false;
        };
        store.spatial_indexes().iter().any(|(_n, e)| {
            e.entity.is_relationship()
                && e.label_token == type_token
                && e.property_token == prop_token
        })
    }

    /// Drops the spatial (point) index named `name` (`rmp` task #98): removes its durable catalog
    /// entry in a committed transaction, unregisters its grid from the in-memory [`IndexSet`], and
    /// cancels any in-progress build. Idempotent on a never-declared name (a clean no-op success).
    ///
    /// # Errors
    /// Returns a storage error if the committing transaction fails.
    pub fn drop_point_index(&mut self, name: &str, if_exists: bool) -> Result<bool> {
        // Resolve the covered `(label_token, prop_key)` from the durable entry so we can unregister the
        // right grid from the in-memory set (which is keyed by tokens, not by name).
        let entry = self.store.borrow().spatial_index(name);
        let Some(entry) = entry else {
            // Not declared: without `IF EXISTS` this is a `Neo.ClientError.Schema.IndexDropFailed`
            // error (Neo4j) and side-effect-free. With `IF EXISTS` it is a clean no-op success —
            // defensively cancel any stray in-flight build first (`rmp` tasks #98, #661).
            if !if_exists {
                return Err(index_drop_not_found(name));
            }
            self.pending_spatial_builds.retain(|b| b.name != name);
            return Ok(false); // nothing removed.
        };

        self.next_txn_id += 1;
        let txn = TxnId(self.next_txn_id);
        self.store.borrow_mut().begin(txn);
        self.store.borrow_mut().remove_spatial_index(name);
        self.store.borrow_mut().commit(txn)?;

        self.pending_spatial_builds.retain(|b| b.name != name);
        // Route the unregister by entity (`rmp` task #664): a relationship point index lives in the
        // rel-keyed grid map, a node one in the node-keyed map (both keyed by `(token, prop_key)`).
        if entry.entity.is_relationship() {
            self.index
                .borrow_mut()
                .unregister_spatial_rel(entry.label_token, entry.property_token);
        } else {
            self.index
                .borrow_mut()
                .unregister_spatial(entry.label_token, entry.property_token);
        }
        Ok(true) // an index was removed.
    }

    /// Lists every declared **node** spatial (point) index as `(name, label, property, state)`
    /// (`rmp` tasks #98, #664) for a `SHOW POINT INDEXES` surface. Reads the durable catalog and resolves
    /// the tokens back to names; a **relationship** point index (`rmp` #664) and an entry whose tokens
    /// have no resolvable name (a defensively-skipped impossibility for a live token) are omitted.
    /// Ordered by name.
    #[must_use]
    pub fn list_point_indexes(&self) -> Vec<(String, String, String, IndexState)> {
        let store = self.store.borrow();
        store
            .spatial_indexes()
            .into_iter()
            .filter(|(_n, entry)| !entry.entity.is_relationship())
            .filter_map(|(name, entry)| {
                // The EFFECTIVE state (`rmp` task #733) — see `effective_state`.
                let state = Self::effective_state(
                    entry.state,
                    self.index
                        .borrow()
                        .spatial_state(entry.label_token, entry.property_token),
                );
                let label = store.token_name(Namespace::Label, entry.label_token)?;
                let property = store.token_name(Namespace::PropKey, entry.property_token)?;
                Some((name, label.to_owned(), property.to_owned(), state))
            })
            .collect()
    }

    /// Lists every declared **relationship** spatial (point) index as `(name, type, property, state)`
    /// (`rmp` task #664) for the `SHOW INDEXES` surface. Reads the durable catalog and resolves the rel
    /// type + property tokens back to names; a node point index and an entry whose tokens have no
    /// resolvable name are omitted. Ordered by name — the relationship analogue of
    /// [`list_point_indexes`](Self::list_point_indexes).
    #[must_use]
    pub fn list_point_rel_indexes(&self) -> Vec<(String, String, String, IndexState)> {
        let store = self.store.borrow();
        store
            .spatial_indexes()
            .into_iter()
            .filter(|(_n, entry)| entry.entity.is_relationship())
            .filter_map(|(name, entry)| {
                // The EFFECTIVE state (`rmp` task #733) — see `effective_state`.
                let state = Self::effective_state(
                    entry.state,
                    self.index
                        .borrow()
                        .spatial_rel_state(entry.label_token, entry.property_token),
                );
                let rel_type = store.token_name(Namespace::RelType, entry.label_token)?;
                let property = store.token_name(Namespace::PropKey, entry.property_token)?;
                Some((name, rel_type.to_owned(), property.to_owned(), state))
            })
            .collect()
    }

    /// Declares a text (trigram) node index named `name` over `(label, property)` (`rmp` task #662),
    /// enforcing Neo4j-conformant schema semantics. A `TEXT` index accelerates `CONTAINS` / `ENDS WITH`
    /// / `STARTS WITH` — the substring/suffix predicates a forward-ordered range index cannot serve.
    ///
    /// The label + property-key tokens are interned **durably** and the named catalog entry is recorded
    /// as [`IndexState::Online`] in one committed transaction (so the *registration* survives a crash),
    /// then the index is registered in the in-memory [`IndexSet`] and **synchronously built** from the
    /// current nodes. The synchronous build is crash-safe: the backing trigram index is ephemeral and
    /// rebuilt from the durable catalog + store on open, so a crash mid-build recovers the `Online`
    /// registration and repopulates it — recovery never observes a half-built index. This mirrors the
    /// composite index (`rmp` task #657) rather than the non-blocking spatial/full-text builds.
    ///
    /// Returns whether the index was **actually created** (`true`) or the call was an idempotent no-op
    /// (`false`, an `IF NOT EXISTS` that changed nothing).
    ///
    /// # Errors
    /// - `Neo.ClientError.Schema.EquivalentSchemaRuleAlreadyExists` (no `IF NOT EXISTS`) when an
    ///   equivalent text index on `(label, property)` already exists;
    /// - `Neo.ClientError.Schema.IndexWithNameAlreadyExists` (no `IF NOT EXISTS`) when `name` is already
    ///   taken by another schema catalog;
    /// - a storage error if interning a token, recording the catalog entry, committing, or the build
    ///   scan fails. On any error the index is left undeclared.
    pub fn create_text_index(
        &mut self,
        name: &str,
        label: &str,
        property: &str,
        if_not_exists: bool,
    ) -> Result<bool> {
        // 1. Equivalent-index check (a text index on the same `(label, property)` under any name, or the
        //    same `name`): `IF NOT EXISTS` makes it an idempotent no-op, else it is an error. A text
        //    index is DISTINCT from a range index over the same `(label, property)` — both may coexist in
        //    Neo4j — so this consults only the text catalog.
        if self.text_equivalent_exists(name, label, property) {
            return if if_not_exists {
                Ok(false)
            } else {
                Err(equivalent_index_exists(label, property))
            };
        }
        // 2. Names are globally unique across every schema catalog (`rmp` task #624): reject a name
        //    already used by a *different* catalog (a re-declare within the text catalog is caught by the
        //    equivalence check above, so it never reaches here).
        if Self::name_used_by_other_catalog(&self.store.borrow(), name, NameCatalog::Text) {
            return if if_not_exists {
                Ok(false)
            } else {
                Err(index_name_in_use(name))
            };
        }
        // 3. Intern the label + property-key tokens and record the durable catalog entry `Online` in one
        //    committed transaction — so the schema change survives a crash atomically.
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
            store.set_text_index(
                name.to_owned(),
                TextIndexEntry {
                    label_token,
                    property_token: prop_key,
                    state: IndexState::Online,
                },
            );
            (label_token, prop_key)
        };
        self.store.borrow_mut().commit(txn)?;

        // 4. Register the trigram index **`Populating`** so the write path maintains it from now on
        //    while the build runs, then synchronously index the existing nodes, and only THEN promote it
        //    to `Online`. The order is what makes it safe (`rmp` task #733): the index becomes visible
        //    to readers (the planner's catalog and the `index_seek_text` seam both gate on `Online`)
        //    only once it is COMPLETE. Registering `Online` up front — as this did before — meant that a
        //    fault in the scan below returned an error to the client but left behind an `Online`, EMPTY
        //    trigram index, after which every `CONTAINS` / `STARTS WITH` / `ENDS WITH` on the covered
        //    property silently returned no rows until the process restarted.
        //
        //    The index is ephemeral (rebuilt on open from the durable catalog + store), so this
        //    synchronous fill is a pure in-memory build with no durability surface — a crash before it
        //    finishes recovers the durable `Online` registration and the open-time rebuild repopulates
        //    it store-consistently.
        self.index
            .borrow_mut()
            .register_text(label_token, prop_key, IndexState::Populating);
        let node_ids = match self.store.borrow_mut().scan_node_ids() {
            Ok(ids) => ids,
            Err(e) => {
                // The build could not start. Leave the in-memory index `Populating` (declined by every
                // reader, which falls back to the exact label scan + residual) and surface the error.
                // The durable entry stays `Online`, so re-opening the store — or any later successful
                // `rebuild_index` — repopulates and promotes it. Never `Online` and empty.
                return Err(e);
            }
        };
        let registered = vec![(label_token, prop_key)];
        self.index.borrow_mut().clear_rebuild_gap();
        for id in node_ids {
            Self::index_one_node_text(&self.store, &self.index, id, &registered);
        }
        // A node the fill could not read is missing from the trigram index for good (`rmp` task #733):
        // the residual `CONTAINS` filter can drop a candidate but never add one back. Leave the index
        // `Populating` (declined by every reader, which falls back to the exact label scan) and surface
        // the fault, rather than publish an index with a hole in it.
        if self.index.borrow().rebuild_gap() {
            self.index.borrow_mut().clear_rebuild_gap();
            return Err(GraphusError::Storage(format!(
                "the text index {name:?} could not be built: the store scan skipped at least one node"
            )));
        }
        // The trigram index now holds every existing node's terms: promote it so readers may use it.
        self.index
            .borrow_mut()
            .set_text_state(label_token, prop_key, IndexState::Online);

        // 5. Stamp the cross-snapshot freshness marker (`rmp` task #467): the trigram index now reflects
        //    committed state at the store's current high-water, and the build raised the transient dirty
        //    flag on every insert. Bump the marker to the high-water so a reader whose snapshot predates
        //    the build declines to the always-correct scan path, and clear the build's dirty flag so it
        //    does not leak into the next user statement (as `bump_ft_spatial_marker_after_build` does).
        let high_water = self.store.borrow().snapshot_ts();
        self.index
            .borrow_mut()
            .bump_ft_spatial_marker_after_build(high_water);
        Ok(true) // the index was created.
    }

    /// Whether a text (trigram) index equivalent to the requested `(name, label, property)` already
    /// exists (`rmp` task #662) — the same `name` in the text catalog, or the same covered
    /// `(label, property)` under any name. Backs `CREATE TEXT INDEX … IF NOT EXISTS` idempotency.
    /// Read-only, by token *lookup*. Consults ONLY the text catalog: a range/point index over the same
    /// `(label, property)` is a different kind and does not make a text index "equivalent".
    fn text_equivalent_exists(&self, name: &str, label: &str, property: &str) -> bool {
        let store = self.store.borrow();
        if store.text_index(name).is_some() {
            return true;
        }
        let props = [property.to_owned()];
        let Some((label_token, property_tokens)) =
            Self::resolve_property_tokens(&store, label, &props)
        else {
            return false;
        };
        let prop_token = property_tokens[0];
        store
            .text_indexes()
            .iter()
            .any(|(_n, e)| e.label_token == label_token && e.property_token == prop_token)
    }

    /// Drops the text (trigram) index named `name` (`rmp` task #662): removes its durable catalog entry
    /// in a committed transaction and unregisters its trigram index from the in-memory [`IndexSet`].
    /// Idempotent on a never-declared name (a clean no-op success under `if_exists`).
    ///
    /// # Errors
    /// - `Neo.ClientError.Schema.IndexDropFailed` when the index is not declared and `if_exists` is
    ///   `false`;
    /// - a storage error if the committing transaction fails.
    pub fn drop_text_index(&mut self, name: &str, if_exists: bool) -> Result<bool> {
        // Resolve the covered `(label_token, prop_key)` from the durable entry so we can unregister the
        // right trigram index from the in-memory set (which is keyed by tokens, not by name).
        let entry = self.store.borrow().text_index(name);
        let Some(entry) = entry else {
            // Not declared: without `IF EXISTS` this is a `Neo.ClientError.Schema.IndexDropFailed` error
            // (Neo4j) and side-effect-free. With `IF EXISTS` it is a clean no-op success.
            if !if_exists {
                return Err(index_drop_not_found(name));
            }
            return Ok(false); // nothing removed.
        };

        self.next_txn_id += 1;
        let txn = TxnId(self.next_txn_id);
        self.store.borrow_mut().begin(txn);
        self.store.borrow_mut().remove_text_index(name);
        self.store.borrow_mut().commit(txn)?;

        self.index
            .borrow_mut()
            .unregister_text(entry.label_token, entry.property_token);
        Ok(true) // an index was removed.
    }

    /// Lists every declared text (trigram) index as `(name, label, property, state)` (`rmp` task #662),
    /// for a `SHOW INDEXES` surface. Reads the durable catalog and resolves the tokens back to names; an
    /// entry whose tokens have no resolvable name (a defensively-skipped impossibility for a live token)
    /// is omitted. Ordered by name.
    #[must_use]
    pub fn list_text_indexes(&self) -> Vec<(String, String, String, IndexState)> {
        let store = self.store.borrow();
        store
            .text_indexes()
            .into_iter()
            .filter_map(|(name, entry)| {
                // The EFFECTIVE state (`rmp` task #733) — see `effective_state`.
                let state = Self::effective_state(
                    entry.state,
                    self.index
                        .borrow()
                        .text_state(entry.label_token, entry.property_token),
                );
                let label = store.token_name(Namespace::Label, entry.label_token)?;
                let property = store.token_name(Namespace::PropKey, entry.property_token)?;
                Some((name, label.to_owned(), property.to_owned(), state))
            })
            .collect()
    }

    // ---- Vector (HNSW) index surface (`rmp` task #669) --------------------------------------------

    /// Declares a **vector (HNSW) index** — over a node label (`entity == VectorEntity::Node`) or a
    /// relationship type (`entity == VectorEntity::Relationship`) — named `name` (or an auto-name when
    /// `None`) over `(covering, property)`, **durably records it**, and **synchronously builds** it from
    /// the current data (`rmp` task #669). The single coordinator entry point behind
    /// `CREATE VECTOR INDEX … FOR (n:L) ON (n.p)` / `FOR ()-[r:T]-() ON (r.p)` (the DDL surface is
    /// `rmp` #671, part C/D).
    ///
    /// The covering + property-key tokens are interned **durably** and the named catalog entry — carrying
    /// the entity, the embedding `dimensions`, the `similarity` metric and the HNSW `m` /
    /// `ef_construction` parameters — is recorded [`IndexState::Online`] in one committed transaction (so
    /// the *registration* survives a crash), then the HNSW graph is registered in the in-memory
    /// [`IndexSet`] and synchronously filled from the current nodes / relationships. The synchronous fill
    /// is crash-safe: the graph is ephemeral and rebuilt from the durable catalog + store on open, so a
    /// crash mid-build recovers the `Online` registration and repopulates it store-consistently — exactly
    /// like the text (`rmp` #662) and composite (`rmp` #657) indexes.
    ///
    /// Returns whether the index was **actually created** (`true`) or the call was an idempotent no-op
    /// (`false`, an `IF NOT EXISTS` that changed nothing).
    ///
    /// # Errors
    /// - a storage error when `dimensions == 0` (a zero-dimension embedding is meaningless);
    /// - `Neo.ClientError.Schema.EquivalentSchemaRuleAlreadyExists` (no `IF NOT EXISTS`) when an
    ///   equivalent vector index on `(entity, covering, property)` already exists;
    /// - `Neo.ClientError.Schema.IndexWithNameAlreadyExists` (no `IF NOT EXISTS`) when `name` is already
    ///   taken by another schema rule;
    /// - a storage error if interning a token, recording the catalog entry, committing, or the build scan
    ///   fails. On any error the index is left undeclared.
    #[allow(clippy::too_many_arguments)]
    pub fn begin_online_vector_index_named(
        &mut self,
        name: Option<&str>,
        entity: VectorEntity,
        covering: &str,
        property: &str,
        dimensions: usize,
        similarity: VectorSimilarity,
        m: usize,
        ef_construction: usize,
        if_not_exists: bool,
    ) -> Result<bool> {
        if dimensions == 0 {
            return Err(GraphusError::Runtime(
                "a vector index dimension must be greater than zero".to_owned(),
            ));
        }
        let namespace = if entity.is_relationship() {
            Namespace::RelType
        } else {
            Namespace::Label
        };

        // 1. Equivalent-index check (read-only, by token *lookup*): the same covered
        //    `(entity, covering, property)` under any name makes this an idempotent no-op (or an error
        //    without `IF NOT EXISTS`). An absent token means no index can cover this target.
        let equivalent_exists = {
            let store = self.store.borrow();
            match (
                store.token_id(namespace, covering),
                store.token_id(Namespace::PropKey, property),
            ) {
                (Some(token), Some(prop_token)) => store
                    .vector_index_name_for(entity, token, prop_token)
                    .is_some(),
                _ => false,
            }
        };
        if equivalent_exists {
            return if if_not_exists {
                Ok(false)
            } else if entity.is_relationship() {
                Err(equivalent_rel_index_exists(covering, property))
            } else {
                Err(equivalent_index_exists(covering, property))
            };
        }

        // 2. Explicit-name global uniqueness (read-only). An omitted name is auto-generated in step 3.
        if let Some(n) = name
            && Self::name_in_use(&self.store.borrow(), n)
        {
            return if if_not_exists {
                Ok(false)
            } else {
                Err(index_name_in_use(n))
            };
        }

        // 3. Intern the tokens and record the durable catalog entry (`Online`) in one committed
        //    transaction — so the schema change survives a crash atomically.
        self.next_txn_id += 1;
        let txn = TxnId(self.next_txn_id);
        self.store.borrow_mut().begin(txn);
        let (token, prop_key) = {
            let mut store = self.store.borrow_mut();
            let token = match store.intern_token(namespace, covering) {
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
            let effective_name = match name {
                Some(n) => n.to_owned(),
                None => Self::unique_auto_vector_index_name(&store, entity, covering, property),
            };
            store.set_vector_index(
                effective_name,
                VectorIndexEntry {
                    entity,
                    token,
                    property_token: prop_key,
                    dimensions: dimensions as u32,
                    similarity,
                    m: m as u32,
                    ef_construction: ef_construction as u32,
                    state: IndexState::Online,
                },
            );
            (token, prop_key)
        };
        self.store.borrow_mut().commit(txn)?;

        // 4. Register the HNSW graph **`Populating`** in the in-memory set so concurrent writes maintain
        //    it while the build runs, synchronously index the existing nodes / relationships into it, and
        //    only THEN promote it to `Online` (`rmp` task #733). The order is the safety property: a
        //    vector index is the one kind with **no scan fallback** (an approximate structure cannot be
        //    re-derived exactly by brute force), so an `Online`-but-empty HNSW would answer every k-NN
        //    with an empty neighbour set — indistinguishable, to the caller, from "there are no near
        //    neighbours". Registering `Online` up front (as this did before) left exactly that state
        //    behind whenever the scan below faulted. While `Populating`, the query seam returns a clear
        //    "still populating" error instead. The graph is ephemeral (rebuilt on open), so this
        //    synchronous fill has no durability surface.
        let sim = similarity_from_storage(similarity);
        if entity.is_relationship() {
            self.index.borrow_mut().register_vector_rel(
                token,
                prop_key,
                dimensions,
                sim,
                m,
                ef_construction,
                IndexState::Populating,
            );
            // The build could not start: `?` leaves the index `Populating` (its query seam then raises a
            // clear "still populating" error) and surfaces the fault. A reopen — or any later successful
            // `rebuild_index` — repopulates it from the durable catalog and promotes it.
            let rel_ids = self.store.borrow().scan_rel_ids()?;
            let registered = vec![(token, prop_key)];
            self.index.borrow_mut().clear_rebuild_gap();
            for id in rel_ids {
                Self::index_one_rel_vector(&self.store, &self.index, id, &registered);
            }
            // A relationship the fill could not read is missing from the HNSW for good, and a vector index
            // has no scan fallback that could compensate (`rmp` task #733). Leave it `Populating` — its
            // query seam then raises a clear "still populating" error — and surface the fault.
            if self.index.borrow().rebuild_gap() {
                self.index.borrow_mut().clear_rebuild_gap();
                return Err(GraphusError::Storage(
                    "the vector index could not be built: the store scan skipped at least one \
                     relationship"
                        .to_owned(),
                ));
            }
            self.index
                .borrow_mut()
                .set_vector_rel_state(token, prop_key, IndexState::Online);
        } else {
            self.index.borrow_mut().register_vector(
                token,
                prop_key,
                dimensions,
                sim,
                m,
                ef_construction,
                IndexState::Populating,
            );
            // As above: a fault leaves the index `Populating`, never `Online` and empty.
            let node_ids = self.store.borrow_mut().scan_node_ids()?;
            let registered = vec![(token, prop_key)];
            self.index.borrow_mut().clear_rebuild_gap();
            for id in node_ids {
                Self::index_one_node_vector(&self.store, &self.index, id, &registered);
            }
            // The node twin of the guard above (`rmp` task #733).
            if self.index.borrow().rebuild_gap() {
                self.index.borrow_mut().clear_rebuild_gap();
                return Err(GraphusError::Storage(
                    "the vector index could not be built: the store scan skipped at least one node"
                        .to_owned(),
                ));
            }
            self.index
                .borrow_mut()
                .set_vector_state(token, prop_key, IndexState::Online);
        }

        // 5. Stamp the cross-snapshot freshness marker (`rmp` task #467): the HNSW graph now reflects
        //    committed state at the store's high-water, and the build raised the transient dirty flag on
        //    every insert. Bump the marker so a reader whose snapshot predates the build declines to the
        //    always-correct scan path, and clear the build's dirty flag so it does not leak into the next
        //    statement — exactly like the text index create.
        let high_water = self.store.borrow().snapshot_ts();
        self.index
            .borrow_mut()
            .bump_ft_spatial_marker_after_build(high_water);
        Ok(true)
    }

    /// A globally-unique, deterministic auto-name for the vector index on `(entity, covering, property)`
    /// (`rmp` task #669) — the vector analogue of
    /// [`unique_auto_index_name`](Self::unique_auto_index_name). The equivalence check in the caller has
    /// already guaranteed no vector index covers this exact target, so the base name can only collide
    /// with an *unrelated* schema rule; a numeric counter resolves any residual collision so the returned
    /// name is free across **every** catalog.
    fn unique_auto_vector_index_name(
        store: &RecordStore<D, S>,
        entity: VectorEntity,
        covering: &str,
        property: &str,
    ) -> String {
        let base = if entity.is_relationship() {
            auto_vector_rel_index_name(covering, property)
        } else {
            auto_vector_index_name(covering, property)
        };
        if !Self::name_in_use(store, &base) {
            return base;
        }
        let mut n: u64 = 2;
        loop {
            let candidate = format!("{base}_{n}");
            if !Self::name_in_use(store, &candidate) {
                return candidate;
            }
            n += 1;
        }
    }

    /// Drops the vector (HNSW) index named `name` (`rmp` task #669): removes its durable catalog entry in
    /// a committed transaction and unregisters its HNSW graph from the in-memory [`IndexSet`] (routing by
    /// entity to the node- or relationship-keyed map). Idempotent on a never-declared name under
    /// `if_exists`.
    ///
    /// # Errors
    /// - `Neo.ClientError.Schema.IndexDropFailed` when the index is not declared and `if_exists` is
    ///   `false`;
    /// - a storage error if the committing transaction fails.
    pub fn drop_vector_index(&mut self, name: &str, if_exists: bool) -> Result<bool> {
        // Resolve the covered `(entity, token, prop_key)` from the durable entry so we can unregister the
        // right graph from the in-memory set (which is keyed by tokens, not by name).
        let entry = self.store.borrow().vector_index(name);
        let Some(entry) = entry else {
            if !if_exists {
                return Err(index_drop_not_found(name));
            }
            return Ok(false); // nothing removed.
        };

        self.next_txn_id += 1;
        let txn = TxnId(self.next_txn_id);
        self.store.borrow_mut().begin(txn);
        self.store.borrow_mut().remove_vector_index(name);
        self.store.borrow_mut().commit(txn)?;

        if entry.entity.is_relationship() {
            self.index
                .borrow_mut()
                .unregister_vector_rel(entry.token, entry.property_token);
        } else {
            self.index
                .borrow_mut()
                .unregister_vector(entry.token, entry.property_token);
        }
        Ok(true) // an index was removed.
    }

    /// Lists every declared **node** vector index as `(name, label, property, state)` (`rmp` task #669)
    /// for a `SHOW VECTOR INDEXES` surface. Reads the durable catalog and resolves the tokens back to
    /// names; a **relationship** vector index and an entry whose tokens have no resolvable name are
    /// omitted. Ordered by name.
    #[must_use]
    pub fn list_vector_indexes(&self) -> Vec<(String, String, String, IndexState)> {
        let store = self.store.borrow();
        store
            .vector_indexes()
            .into_iter()
            .filter(|(_n, entry)| !entry.entity.is_relationship())
            .filter_map(|(name, entry)| {
                // The EFFECTIVE state (`rmp` task #733) — see `effective_state`.
                let state = Self::effective_state(
                    entry.state,
                    self.index
                        .borrow()
                        .vector_state(entry.token, entry.property_token),
                );
                let label = store.token_name(Namespace::Label, entry.token)?;
                let property = store.token_name(Namespace::PropKey, entry.property_token)?;
                Some((name, label.to_owned(), property.to_owned(), state))
            })
            .collect()
    }

    /// Lists every declared **relationship** vector index as `(name, type, property, state)`
    /// (`rmp` task #669) — the relationship analogue of
    /// [`list_vector_indexes`](Self::list_vector_indexes). Ordered by name.
    #[must_use]
    pub fn list_vector_rel_indexes(&self) -> Vec<(String, String, String, IndexState)> {
        let store = self.store.borrow();
        store
            .vector_indexes()
            .into_iter()
            .filter(|(_n, entry)| entry.entity.is_relationship())
            .filter_map(|(name, entry)| {
                // The EFFECTIVE state (`rmp` task #733) — see `effective_state`.
                let state = Self::effective_state(
                    entry.state,
                    self.index
                        .borrow()
                        .vector_rel_state(entry.token, entry.property_token),
                );
                let rel_type = store.token_name(Namespace::RelType, entry.token)?;
                let property = store.token_name(Namespace::PropKey, entry.property_token)?;
                Some((name, rel_type.to_owned(), property.to_owned(), state))
            })
            .collect()
    }

    /// Lists every declared vector index — node **and** relationship — as a [`VectorIndexListing`]
    /// carrying its full `indexConfig` (`rmp` task #671), for the unified `SHOW INDEXES` VECTOR rows.
    /// Reads the durable catalog and resolves each covered token (by [`entity`](VectorIndexListing::entity)
    /// namespace) plus the property token back to names; an entry whose tokens have no resolvable name is
    /// omitted. Ordered by name (the catalog's [`BTreeMap`](std::collections::BTreeMap) order).
    #[must_use]
    pub fn list_vector_index_listings(&self) -> Vec<VectorIndexListing> {
        let store = self.store.borrow();
        store
            .vector_indexes()
            .into_iter()
            .filter_map(|(name, entry)| {
                let namespace = if entry.entity.is_relationship() {
                    Namespace::RelType
                } else {
                    Namespace::Label
                };
                let label_or_type = store.token_name(namespace, entry.token)?;
                let property = store.token_name(Namespace::PropKey, entry.property_token)?;
                // The EFFECTIVE state (`rmp` task #733), routed by entity — a vector index that is not
                // usable ERRORS on query, so reporting it ONLINE would be doubly misleading.
                let in_memory = if entry.entity.is_relationship() {
                    self.index
                        .borrow()
                        .vector_rel_state(entry.token, entry.property_token)
                } else {
                    self.index
                        .borrow()
                        .vector_state(entry.token, entry.property_token)
                };
                let state = Self::effective_state(entry.state, in_memory);
                Some(VectorIndexListing {
                    name,
                    entity: entry.entity,
                    label_or_type: label_or_type.to_owned(),
                    property: property.to_owned(),
                    dimensions: entry.dimensions,
                    similarity: entry.similarity,
                    m: entry.m,
                    ef_construction: entry.ef_construction,
                    state,
                })
            })
            .collect()
    }

    /// The `k` nearest **node** ids to `query` in the vector index over `(label, property)`, as
    /// `(id, score)` by descending score (`rmp` task #669) — the seek primitive the query planner
    /// (`rmp` #671) will build on. [`None`] when the label / property tokens are unknown or no vector
    /// index covers them; `Some(Err)` on a query-dimension mismatch; otherwise `Some(Ok(hits))`.
    ///
    /// The returned ids are **candidates**: the query planner layers MVCC visibility + current-label +
    /// current-value re-checks (and the cross-snapshot freshness gate) on top. `ef_search` defaults are
    /// the caller's; [`graphus_index::DEFAULT_EF_SEARCH`] is a sensible starting point.
    #[must_use]
    pub fn vector_query_nodes(
        &self,
        label: &str,
        property: &str,
        query: &[f32],
        k: usize,
        ef_search: usize,
    ) -> Option<std::result::Result<Vec<(u64, f32)>, VectorIndexError>> {
        let (label_token, prop_key) = {
            let store = self.store.borrow();
            (
                store.token_id(Namespace::Label, label)?,
                store.token_id(Namespace::PropKey, property)?,
            )
        };
        self.index
            .borrow()
            .seek_vector_knn(label_token, prop_key, query, k, ef_search)
    }

    /// The `k` nearest **relationship** ids to `query` in the vector index over `(rel_type, property)`
    /// (`rmp` task #669) — the relationship analogue of
    /// [`vector_query_nodes`](Self::vector_query_nodes).
    #[must_use]
    pub fn vector_query_rels(
        &self,
        rel_type: &str,
        property: &str,
        query: &[f32],
        k: usize,
        ef_search: usize,
    ) -> Option<std::result::Result<Vec<(u64, f32)>, VectorIndexError>> {
        let (type_token, prop_key) = {
            let store = self.store.borrow();
            (
                store.token_id(Namespace::RelType, rel_type)?,
                store.token_id(Namespace::PropKey, property)?,
            )
        };
        self.index
            .borrow()
            .seek_vector_rel_knn(type_token, prop_key, query, k, ef_search)
    }

    /// Idempotency-aware `CREATE CONSTRAINT` entry point (`rmp` #638): wraps
    /// [`create_constraint_general`](Self::create_constraint_general) with `IF NOT EXISTS` and
    /// `OR REPLACE` handling, returning whether the schema was **actually mutated** (which drives the
    /// DDL summary's `constraints-added` counter — a no-op reports `0`).
    ///
    /// * `or_replace` — drop any same-named constraint first, then create; a replace always mutates
    ///   (`Ok(true)`). A **Graphus superset** of the Neo4j constraint surface (which offers only
    ///   `IF NOT EXISTS`).
    /// * `if_not_exists` — if a constraint with the same `name`, or an **equivalent** one (same
    ///   covering token + property tuple + kind + declared type, possibly under another name), already
    ///   exists, this is an idempotent no-op success (`Ok(false)`); otherwise it creates (`Ok(true)`).
    /// * neither — create, surfacing a name-in-use error on a colliding name.
    ///
    /// `covering` is the label name (node kinds) or the relationship-type name (relationship kinds);
    /// the namespace is derived from `kind`.
    ///
    /// # Errors
    /// Propagates any [`create_constraint_general`](Self::create_constraint_general) or
    /// [`drop_constraint`](Self::drop_constraint) error (a constraint violation or storage fault); on
    /// any error the schema is left unchanged (the drop-then-create is not atomic across the two, but
    /// each step is individually transactional, and a failed create after a successful `OR REPLACE`
    /// drop leaves the name free — matching the operator's intent to replace).
    #[allow(clippy::too_many_arguments)]
    pub fn create_constraint_ddl(
        &mut self,
        name: &str,
        covering: &str,
        properties: &[&str],
        kind: ConstraintKind,
        type_descriptor: Option<ConstraintTypeDescriptor>,
        if_not_exists: bool,
        or_replace: bool,
    ) -> Result<bool> {
        if or_replace {
            // Drop any existing constraint of this name, then (re)create. A replace always mutates.
            let _ = self.drop_constraint(name)?;
            self.create_constraint_general(name, covering, properties, kind, type_descriptor)?;
            return Ok(true);
        }
        // Detect any conflict once (read-only): a same-name constraint, or an equivalent-schema one.
        let name_taken = self.store.borrow().constraint(name).is_some();
        let schema_taken =
            self.constraint_schema_exists(covering, properties, kind, type_descriptor.as_ref());
        if if_not_exists {
            // `IF NOT EXISTS`: an equivalent existing constraint (by name or schema) is a no-op.
            if name_taken || schema_taken {
                return Ok(false); // idempotent no-op: nothing added.
            }
        } else {
            // Plain `CREATE CONSTRAINT`: a same-name or same-schema constraint is a conflict (matching
            // Neo4j, which requires `IF NOT EXISTS`/`OR REPLACE` to reconcile). This is what makes
            // `IF NOT EXISTS` semantically meaningful.
            if name_taken {
                return Err(constraint_name_in_use(name));
            }
            if schema_taken {
                return Err(equivalent_constraint_exists(covering, properties));
            }
        }
        self.create_constraint_general(name, covering, properties, kind, type_descriptor)?;
        Ok(true)
    }

    /// Whether a constraint with the **same schema** — covering token + property tuple + kind + type
    /// descriptor (possibly under a different name) — already exists (`rmp` #638). Read-only; an absent
    /// covering/property token means the covered label/type or property has never been seen, so no such
    /// schema exists yet.
    fn constraint_schema_exists(
        &self,
        covering: &str,
        properties: &[&str],
        kind: ConstraintKind,
        type_descriptor: Option<&ConstraintTypeDescriptor>,
    ) -> bool {
        let store = self.store.borrow();
        let namespace = constraint_covering_namespace(kind);
        let Some(covering_token) = store.token_id(namespace, covering) else {
            return false;
        };
        let mut prop_tokens = Vec::with_capacity(properties.len());
        for p in properties {
            match store.token_id(Namespace::PropKey, p) {
                Some(t) => prop_tokens.push(t),
                None => return false,
            }
        }
        store.constraints().into_iter().any(|(_n, entry)| {
            entry.label_token == covering_token
                && entry.property_tokens == prop_tokens
                && entry.kind == kind
                && entry.type_descriptor.as_ref() == type_descriptor
        })
    }

    /// Declares a **constraint** named `name` over `(label, property)` of `kind`, **validating it
    /// against existing data first** and only then **durably recording it** (`rmp` task #99) — the
    /// constraint analogue of [`create_point_index`](Self::create_point_index), but synchronous and
    /// validated (a constraint has no `Populating` phase — it is in force the instant it is created).
    ///
    /// Order of operations (so a rejected creation has **zero** side effects):
    ///
    /// 1. **Intern** the label + property-key tokens (in a dedicated transaction).
    /// 2. **Validate** every currently-live node carrying the label against the rule
    ///    ([`validate_existing_against_constraint`](Self::validate_existing_against_constraint)):
    ///    a uniqueness constraint rejects if two nodes share a value; an existence constraint rejects
    ///    if a node lacks the property. On any violation the transaction is **rolled back** (no token,
    ///    no catalog entry, no registration) and a [`ConstraintViolation`] runtime error is returned.
    /// 3. **Persist** the catalog entry, **register** the in-memory rule, and — for a uniqueness
    ///    constraint — **register + populate** the backing node-property index, all in the committed
    ///    transaction. After commit the durable catalog and the in-memory set agree, and the write
    ///    path enforces the rule.
    ///
    /// Re-declaring an existing name **replaces** it (re-validated against current data).
    ///
    /// # Errors
    /// Returns a [`ConstraintViolation`]-wrapped [`GraphusError::Runtime`] if existing data violates
    /// the constraint, or a storage error if interning a token, recording the catalog entry, or the
    /// committing transaction fails. On any error the constraint is left undeclared.
    pub fn create_constraint(
        &mut self,
        name: &str,
        label: &str,
        property: &str,
        kind: ConstraintKind,
    ) -> Result<()> {
        // The single-property convenience entry point (uniqueness / existence / property-type): forward
        // to the general composite-aware path with one property and no declared type.
        self.create_constraint_general(name, label, &[property], kind, None)
    }

    /// Declares a constraint over a (possibly composite) property tuple, validating existing data and
    /// durably recording it (`rmp` tasks #99, #100). The general form behind
    /// [`create_constraint`](Self::create_constraint) (single-property) and the NODE KEY / PROPERTY
    /// TYPE engine paths:
    ///
    /// - `properties` is the covered tuple in declared order — one property for `Unique` / `Existence`
    ///   / `PropertyType`, one-or-more for a composite `NodeKey`.
    /// - `type_descriptor` is the declared value type of a `PropertyType` constraint (`None` for every
    ///   other kind).
    ///
    /// The order of operations is identical to the single-property path (intern → validate existing →
    /// persist + register), so a rejected creation has **zero** side effects. For a `Unique` constraint
    /// a backing node-property index is registered + populated; for a `NodeKey` a backing **composite**
    /// index over the whole tuple is registered + populated (the composite analogue), so the write-time
    /// duplicate check is index-accelerated.
    ///
    /// # Errors
    /// Returns a [`ConstraintViolation`]-wrapped runtime error if existing data violates the
    /// constraint, or a storage error if interning a token, recording the entry, or committing fails.
    /// On any error the constraint is left undeclared.
    pub fn create_constraint_general(
        &mut self,
        name: &str,
        label: &str,
        properties: &[&str],
        kind: ConstraintKind,
        type_descriptor: Option<ConstraintTypeDescriptor>,
    ) -> Result<()> {
        debug_assert!(
            !properties.is_empty(),
            "a constraint covers at least one property"
        );
        // Names are globally unique across every schema catalog (`rmp` task #624): reject a name already
        // used by a *different* catalog (a re-declare within the constraint catalog keeps its semantics).
        if Self::name_used_by_other_catalog(&self.store.borrow(), name, NameCatalog::Constraint) {
            return Err(index_name_in_use(name));
        }
        self.next_txn_id += 1;
        let txn = TxnId(self.next_txn_id);
        self.store.borrow_mut().begin(txn);

        // Intern the covering token — a node **label** for the node kinds, a relationship **type** for
        // the `Rel*` kinds (`rmp` #638) — plus every property-key token (rolled back with the
        // transaction on any failure).
        let covering_ns = if kind.is_relationship() {
            Namespace::RelType
        } else {
            Namespace::Label
        };
        let intern = (|| -> Result<(u32, Vec<u32>)> {
            let mut store = self.store.borrow_mut();
            let label_token = store.intern_token(covering_ns, label)?;
            let mut prop_keys = Vec::with_capacity(properties.len());
            for property in properties {
                prop_keys.push(store.intern_token(Namespace::PropKey, property)?);
            }
            Ok((label_token, prop_keys))
        })();
        let (label_token, prop_keys) = match intern {
            Ok(v) => v,
            Err(e) => {
                let _ = self.store.borrow_mut().rollback(txn);
                return Err(e);
            }
        };

        // Validate existing data BEFORE recording anything. A violation rolls back the whole
        // transaction (so the interned tokens never become durable for a rejected create) and reports
        // the offending entity precisely. Relationship constraints scan relationships of the type; node
        // constraints scan nodes carrying the label.
        let validation = if kind.is_relationship() {
            self.validate_existing_rels_against_constraint(
                name,
                label,
                properties,
                label_token,
                &prop_keys,
                kind,
                type_descriptor.as_ref(),
            )
        } else {
            self.validate_existing_against_constraint(
                name,
                label,
                properties,
                label_token,
                &prop_keys,
                kind,
                type_descriptor.as_ref(),
            )
        };
        if let Err(e) = validation {
            let _ = self.store.borrow_mut().rollback(txn);
            return Err(e);
        }

        // Conforming: record the durable catalog entry and commit (tokens + entry atomically).
        self.store.borrow_mut().set_constraint(
            name.to_owned(),
            ConstraintEntry {
                label_token,
                property_tokens: prop_keys.clone(),
                kind,
                type_descriptor: type_descriptor.clone(),
            },
        );
        self.store.borrow_mut().commit(txn)?;

        // Register the rule in the in-memory set so the write path enforces it from now on. A uniqueness
        // constraint registers + populates a backing node-property index; a node-key constraint
        // registers + populates a backing COMPOSITE index over the whole tuple — both make the write-time
        // duplicate check index-backed (a full rebuild repopulates them from the store). Existence and
        // property-type need no backing index (they are pure per-node predicates).
        let needs_rebuild = {
            let mut idx = self.index.borrow_mut();
            idx.register_constraint(name, label_token, prop_keys.clone(), kind, type_descriptor);
            match kind {
                ConstraintKind::Unique => {
                    match prop_keys.as_slice() {
                        [prop_key] => idx.register_node_property_with_state(
                            label_token,
                            *prop_key,
                            IndexState::Online,
                        ),
                        // Composite uniqueness (`rmp` #651) is backed by a composite index over the
                        // whole tuple — exactly like a node key — so the write-time duplicate check is
                        // index-accelerated and its SSI predicate footprint matches the key path.
                        _ => idx.register_composite(label_token, prop_keys.clone()),
                    }
                    true
                }
                ConstraintKind::NodeKey => {
                    idx.register_composite(label_token, prop_keys.clone());
                    true
                }
                ConstraintKind::RelUnique => {
                    // A relationship uniqueness constraint (`rmp` #638) registers + populates a backing
                    // relationship-property index on its single `(type, property)` (`rmp` task #646), so
                    // the write-time duplicate check is index-accelerated (a full rebuild repopulates it).
                    if let [prop_key] = prop_keys.as_slice() {
                        idx.register_rel_property_with_state(
                            label_token,
                            *prop_key,
                            IndexState::Online,
                        );
                    }
                    true
                }
                // Existence + property-type are pure per-entity predicates; RelKey / RelPropertyType
                // stay scan-based (a relationship COMPOSITE index is deferred; RelPropertyType is a pure
                // per-relationship predicate). None of these need an index rebuild.
                ConstraintKind::Existence
                | ConstraintKind::PropertyType
                | ConstraintKind::RelExistence
                | ConstraintKind::RelKey
                | ConstraintKind::RelPropertyType => false,
            }
        };
        if needs_rebuild {
            Self::rebuild_index(&self.store, &self.index);
        }
        Ok(())
    }

    /// Scans every currently-live node carrying `label_token` and rejects if any violates the
    /// constraint of `kind` on `prop_key` (`rmp` task #99). Used by
    /// [`create_constraint`](Self::create_constraint) to refuse a constraint that existing data does
    /// not satisfy. No-op success when no node carries the label.
    ///
    /// # Errors
    /// Returns a [`ConstraintViolation`]-wrapped runtime error naming the first offending node /
    /// duplicate value (uniqueness) or the first node missing the property (existence). A store-read
    /// fault on a node is treated as "skip that node" (best-effort), consistent with the rebuild path.
    #[allow(clippy::too_many_arguments)]
    fn validate_existing_against_constraint(
        &self,
        name: &str,
        label: &str,
        properties: &[&str],
        label_token: u32,
        prop_keys: &[u32],
        kind: ConstraintKind,
        type_descriptor: Option<&ConstraintTypeDescriptor>,
    ) -> Result<()> {
        let node_ids = self.store.borrow_mut().scan_node_ids()?;
        // For single-property uniqueness: remember the values seen to detect a duplicate.
        let mut seen: Vec<(Value, u64)> = Vec::new();
        // For composite node-key uniqueness: remember the full tuples seen.
        let mut seen_tuples: Vec<Vec<Value>> = Vec::new();
        for id in node_ids {
            // A node whose labels cannot be read **fails the DDL** (`rmp` task #733). This used to
            // `continue`, i.e. validate the constraint against the nodes it happened to be able to read
            // — so a `CREATE CONSTRAINT … IS UNIQUE` could be ACCEPTED over data that violates it, with
            // the duplicate hiding in the unreadable node. From that moment the constraint is a lie: the
            // catalog says the property is unique, queries and planners may rely on it, and the
            // offending row is already committed. Refusing is always safe for a DDL — the operator
            // retries once the store is readable — and it is the only answer that cannot corrupt the
            // schema's meaning. (This is the same class of defect `rmp` #733 exists to eliminate: never
            // publish a schema object you could not fully verify.)
            let label_tokens = self.store.borrow_mut().node_labels(id)?;
            if !label_tokens.contains(&label_token) {
                continue; // node does not carry the covered label
            }
            match kind {
                ConstraintKind::Existence => {
                    // A missing or null value violates the existence (NOT NULL) constraint.
                    let value = self.node_value_for_key(id, prop_keys[0])?;
                    if value.as_ref().is_none_or(graphus_core::Value::is_null) {
                        return Err(ConstraintViolation::Existence {
                            name: name.to_owned(),
                            entity: ViolationEntity::Node,
                            label: label.to_owned(),
                            property: properties[0].to_owned(),
                        }
                        .into_error());
                    }
                }
                ConstraintKind::Unique if prop_keys.len() == 1 => {
                    // A null/absent value never participates in uniqueness (Cypher equality treats
                    // null as never-equal), matching the index's treatment.
                    let Some(value) = self
                        .node_value_for_key(id, prop_keys[0])?
                        .filter(|v| !v.is_null())
                    else {
                        continue;
                    };
                    if seen
                        .iter()
                        .any(|(v, _)| crate::equality::equals(v, &value).is_true())
                    {
                        return Err(ConstraintViolation::Uniqueness {
                            name: name.to_owned(),
                            entity: ViolationEntity::Node,
                            label: label.to_owned(),
                            property: properties[0].to_owned(),
                            value: render_value(&value),
                        }
                        .into_error());
                    }
                    seen.push((value, id));
                }
                ConstraintKind::Unique => {
                    // Composite uniqueness (`rmp` #651): no existence requirement — a null in any
                    // covered property relaxes uniqueness, so an incomplete tuple is skipped; the
                    // complete tuple must be unique across the scanned nodes.
                    let mut tuple = Vec::with_capacity(prop_keys.len());
                    let mut complete = true;
                    for &prop_key in prop_keys {
                        match self
                            .node_value_for_key(id, prop_key)?
                            .filter(|v| !v.is_null())
                        {
                            Some(v) => tuple.push(v),
                            None => {
                                complete = false;
                                break;
                            }
                        }
                    }
                    if !complete {
                        continue;
                    }
                    if seen_tuples.iter().any(|seen| tuples_equal(seen, &tuple)) {
                        return Err(ConstraintViolation::UniquenessComposite {
                            name: name.to_owned(),
                            entity: ViolationEntity::Node,
                            label: label.to_owned(),
                            properties: properties.iter().map(|p| (*p).to_owned()).collect(),
                            values: render_tuple(&tuple),
                        }
                        .into_error());
                    }
                    seen_tuples.push(tuple);
                }
                ConstraintKind::NodeKey => {
                    // Existence half: every covered property must be present and non-null.
                    let mut tuple = Vec::with_capacity(prop_keys.len());
                    let mut complete = true;
                    for &prop_key in prop_keys {
                        match self
                            .node_value_for_key(id, prop_key)?
                            .filter(|v| !v.is_null())
                        {
                            Some(v) => tuple.push(v),
                            None => {
                                complete = false;
                                break;
                            }
                        }
                    }
                    if !complete {
                        return Err(ConstraintViolation::NodeKeyMissing {
                            name: name.to_owned(),
                            entity: ViolationEntity::Node,
                            label: label.to_owned(),
                            properties: properties.iter().map(|p| (*p).to_owned()).collect(),
                        }
                        .into_error());
                    }
                    // Uniqueness half: the complete tuple must not have been seen before.
                    if seen_tuples.iter().any(|seen| tuples_equal(seen, &tuple)) {
                        return Err(ConstraintViolation::NodeKeyDuplicate {
                            name: name.to_owned(),
                            entity: ViolationEntity::Node,
                            label: label.to_owned(),
                            properties: properties.iter().map(|p| (*p).to_owned()).collect(),
                            values: render_tuple(&tuple),
                        }
                        .into_error());
                    }
                    seen_tuples.push(tuple);
                }
                ConstraintKind::PropertyType => {
                    // Only a present, non-null value is type-checked (a missing/null value is allowed —
                    // property-type does not imply existence).
                    let Some(value) = self
                        .node_value_for_key(id, prop_keys[0])?
                        .filter(|v| !v.is_null())
                    else {
                        continue;
                    };
                    let descriptor = type_descriptor
                        .expect("INVARIANT: a PropertyType constraint always carries a descriptor");
                    if !crate::constraint::value_matches_descriptor(&value, descriptor) {
                        return Err(ConstraintViolation::PropertyType {
                            name: name.to_owned(),
                            entity: ViolationEntity::Node,
                            label: label.to_owned(),
                            property: properties[0].to_owned(),
                            expected: crate::constraint::type_descriptor_name(descriptor),
                            actual: crate::constraint::value_type_name(&value),
                        }
                        .into_error());
                    }
                }
                // The relationship kinds are validated by `validate_existing_rels_against_constraint`;
                // the caller never routes them here, so treat them as "no node violation".
                ConstraintKind::RelUnique
                | ConstraintKind::RelExistence
                | ConstraintKind::RelKey
                | ConstraintKind::RelPropertyType => continue,
            }
        }
        Ok(())
    }

    /// The newest value node `id` holds for property-key token `prop_key`, or [`None`] if the node has
    /// no such property. Reads the property chain newest-first and keeps the first occurrence — the same
    /// newest-wins discipline the index rebuild uses (`rmp` task #99).
    ///
    /// # Errors
    /// Propagates a store read fault. It is deliberately **fallible** (`rmp` task #733): it used to fold
    /// a read fault into `None`, indistinguishable from "the node has no such property" — which let the
    /// constraint-validation walk that calls it treat an unreadable node as *not* violating, and so
    /// accept a `IS UNIQUE` constraint whose duplicate was hiding in that node.
    fn node_value_for_key(&self, id: u64, prop_key: u32) -> Result<Option<Value>> {
        let chain = self.store.borrow_mut().node_property_values(id)?;
        Ok(chain
            .into_iter()
            .find(|(_pid, key, _value)| *key == prop_key)
            .map(|(_pid, _key, value)| value))
    }

    /// The newest value relationship `id` holds for property-key token `prop_key` (`rmp` #638), or
    /// [`None`] if the relationship has no such property — the relationship analogue of
    /// [`node_value_for_key`](Self::node_value_for_key).
    ///
    /// # Errors
    /// Propagates a store read fault, for the reason documented on
    /// [`node_value_for_key`](Self::node_value_for_key) (`rmp` task #733).
    fn rel_value_for_key(&self, id: u64, prop_key: u32) -> Result<Option<Value>> {
        let chain = self.store.borrow().rel_property_values(id)?;
        Ok(chain
            .into_iter()
            .find(|(_pid, key, _value)| *key == prop_key)
            .map(|(_pid, _key, value)| value))
    }

    /// Scans every currently-slot-occupied relationship of the type token `type_token` and rejects if
    /// any violates the relationship constraint of `kind` on `prop_keys` (`rmp` #638) — the
    /// relationship analogue of
    /// [`validate_existing_against_constraint`](Self::validate_existing_against_constraint). Used by
    /// [`create_constraint_general`](Self::create_constraint_general) to refuse a relationship
    /// constraint that existing data does not satisfy. No-op success when no relationship carries the
    /// type. A relationship whose record cannot be read is skipped best-effort (matching the node path).
    ///
    /// # Errors
    /// Returns a [`ConstraintViolation`]-wrapped runtime error (with `entity: Relationship`) naming the
    /// first offending relationship / duplicate value.
    #[allow(clippy::too_many_arguments)]
    fn validate_existing_rels_against_constraint(
        &self,
        name: &str,
        rel_type: &str,
        properties: &[&str],
        type_token: u32,
        prop_keys: &[u32],
        kind: ConstraintKind,
        type_descriptor: Option<&ConstraintTypeDescriptor>,
    ) -> Result<()> {
        let rel_ids = self.store.borrow().scan_rel_ids()?;
        // Single-property uniqueness: values seen so far, to detect a duplicate.
        let mut seen: Vec<(Value, u64)> = Vec::new();
        // Composite key uniqueness: full tuples seen so far.
        let mut seen_tuples: Vec<Vec<Value>> = Vec::new();
        for id in rel_ids {
            // A relationship whose record cannot be read **fails the DDL** (`rmp` task #733) — the
            // relationship twin of the node guard above. Skipping it would let a `CREATE CONSTRAINT …
            // IS UNIQUE` be accepted over data that violates it, with the duplicate hiding in the
            // unreadable slot.
            let this_type = self.store.borrow().rel(id)?.type_id;
            if this_type != type_token {
                continue; // relationship does not carry the covered type
            }
            match kind {
                ConstraintKind::RelExistence => {
                    let value = self.rel_value_for_key(id, prop_keys[0])?;
                    if value.as_ref().is_none_or(graphus_core::Value::is_null) {
                        return Err(ConstraintViolation::Existence {
                            name: name.to_owned(),
                            entity: ViolationEntity::Relationship,
                            label: rel_type.to_owned(),
                            property: properties[0].to_owned(),
                        }
                        .into_error());
                    }
                }
                ConstraintKind::RelUnique if prop_keys.len() == 1 => {
                    let Some(value) = self
                        .rel_value_for_key(id, prop_keys[0])?
                        .filter(|v| !v.is_null())
                    else {
                        continue;
                    };
                    if seen
                        .iter()
                        .any(|(v, _)| crate::equality::equals(v, &value).is_true())
                    {
                        return Err(ConstraintViolation::Uniqueness {
                            name: name.to_owned(),
                            entity: ViolationEntity::Relationship,
                            label: rel_type.to_owned(),
                            property: properties[0].to_owned(),
                            value: render_value(&value),
                        }
                        .into_error());
                    }
                    seen.push((value, id));
                }
                ConstraintKind::RelUnique => {
                    // Composite relationship uniqueness (`rmp` #651): no existence requirement — a null
                    // in any covered property relaxes uniqueness (skip an incomplete tuple); the
                    // complete tuple must be unique across the scanned relationships.
                    let mut tuple = Vec::with_capacity(prop_keys.len());
                    let mut complete = true;
                    for &prop_key in prop_keys {
                        match self
                            .rel_value_for_key(id, prop_key)?
                            .filter(|v| !v.is_null())
                        {
                            Some(v) => tuple.push(v),
                            None => {
                                complete = false;
                                break;
                            }
                        }
                    }
                    if !complete {
                        continue;
                    }
                    if seen_tuples.iter().any(|seen| tuples_equal(seen, &tuple)) {
                        return Err(ConstraintViolation::UniquenessComposite {
                            name: name.to_owned(),
                            entity: ViolationEntity::Relationship,
                            label: rel_type.to_owned(),
                            properties: properties.iter().map(|p| (*p).to_owned()).collect(),
                            values: render_tuple(&tuple),
                        }
                        .into_error());
                    }
                    seen_tuples.push(tuple);
                }
                ConstraintKind::RelKey => {
                    // Existence half: every covered property must be present and non-null.
                    let mut tuple = Vec::with_capacity(prop_keys.len());
                    let mut complete = true;
                    for &prop_key in prop_keys {
                        match self
                            .rel_value_for_key(id, prop_key)?
                            .filter(|v| !v.is_null())
                        {
                            Some(v) => tuple.push(v),
                            None => {
                                complete = false;
                                break;
                            }
                        }
                    }
                    if !complete {
                        return Err(ConstraintViolation::NodeKeyMissing {
                            name: name.to_owned(),
                            entity: ViolationEntity::Relationship,
                            label: rel_type.to_owned(),
                            properties: properties.iter().map(|p| (*p).to_owned()).collect(),
                        }
                        .into_error());
                    }
                    // Uniqueness half: the complete tuple must not have been seen before.
                    if seen_tuples.iter().any(|seen| tuples_equal(seen, &tuple)) {
                        return Err(ConstraintViolation::NodeKeyDuplicate {
                            name: name.to_owned(),
                            entity: ViolationEntity::Relationship,
                            label: rel_type.to_owned(),
                            properties: properties.iter().map(|p| (*p).to_owned()).collect(),
                            values: render_tuple(&tuple),
                        }
                        .into_error());
                    }
                    seen_tuples.push(tuple);
                }
                ConstraintKind::RelPropertyType => {
                    let Some(value) = self
                        .rel_value_for_key(id, prop_keys[0])?
                        .filter(|v| !v.is_null())
                    else {
                        continue;
                    };
                    let descriptor = type_descriptor
                        .expect("INVARIANT: a PropertyType constraint always carries a descriptor");
                    if !crate::constraint::value_matches_descriptor(&value, descriptor) {
                        return Err(ConstraintViolation::PropertyType {
                            name: name.to_owned(),
                            entity: ViolationEntity::Relationship,
                            label: rel_type.to_owned(),
                            property: properties[0].to_owned(),
                            expected: crate::constraint::type_descriptor_name(descriptor),
                            actual: crate::constraint::value_type_name(&value),
                        }
                        .into_error());
                    }
                }
                // The node kinds are validated by `validate_existing_against_constraint`; the caller
                // never routes them here.
                ConstraintKind::Unique
                | ConstraintKind::Existence
                | ConstraintKind::NodeKey
                | ConstraintKind::PropertyType => continue,
            }
        }
        Ok(())
    }

    /// Drops the constraint named `name` (`rmp` tasks #99, #100): removes its durable catalog entry in
    /// a committed transaction and unregisters its in-memory rule, so the write path stops enforcing it.
    /// Idempotent on a never-declared name (a clean no-op success).
    ///
    /// The backing node-property index of a uniqueness constraint is **left registered** (a query may
    /// still benefit from it, and a plain `CREATE INDEX` may have independently declared it); only the
    /// constraint *rule* is removed. A node-key constraint's backing **composite** index, by contrast,
    /// exists only to serve the constraint (no `CREATE INDEX` surface declares one), so it is
    /// **unregistered** here to release its in-memory tree.
    ///
    /// # Errors
    /// Returns a storage error if the committing transaction fails.
    pub fn drop_constraint(&mut self, name: &str) -> Result<bool> {
        // Resolve the entry first so a node key's backing composite index can be unregistered by its
        // covered `(label, property tuple)` after the durable removal.
        let entry = self.store.borrow().constraint(name);
        let Some(entry) = entry else {
            // A no-op when the constraint is not declared (avoids an empty committed transaction).
            self.index.borrow_mut().unregister_constraint(name);
            return Ok(false); // nothing removed.
        };
        self.next_txn_id += 1;
        let txn = TxnId(self.next_txn_id);
        self.store.borrow_mut().begin(txn);
        self.store.borrow_mut().remove_constraint(name);
        self.store.borrow_mut().commit(txn)?;
        // A node key's backing composite tree may be **shared** with a standalone composite index over
        // the same `(label, tuple)` (`rmp` task #657): keep it if such an index still needs it, so
        // dropping the constraint does not silently disable the standalone index's acceleration.
        let shared_with_composite_index = entry.kind == ConstraintKind::NodeKey
            && self
                .store
                .borrow()
                .composite_index_name_for(entry.label_token, &entry.property_tokens)
                .is_some();
        let mut idx = self.index.borrow_mut();
        idx.unregister_constraint(name);
        if entry.kind == ConstraintKind::NodeKey && !shared_with_composite_index {
            idx.unregister_composite(entry.label_token, &entry.property_tokens);
        }
        Ok(true) // a constraint was removed.
    }

    /// Lists every declared constraint as a [`ConstraintInfo`] (`rmp` tasks #99, #100) for a
    /// `SHOW CONSTRAINTS` surface. Reads the durable catalog and resolves the tokens back to names; an
    /// entry whose tokens have no resolvable name (a defensively-skipped impossibility for a live token)
    /// is omitted. A node-key constraint reports its **whole** property tuple in declared order; a
    /// property-type constraint reports its declared type. Ordered by name.
    #[must_use]
    pub fn list_constraints(&self) -> Vec<ConstraintInfo> {
        let store = self.store.borrow();
        store
            .constraints()
            .into_iter()
            .filter_map(|(name, entry)| {
                // Resolve the covering token in its namespace — a relationship type for the `Rel*`
                // kinds (`rmp` #638), a node label otherwise.
                let covering_ns = constraint_covering_namespace(entry.kind);
                let label = store.token_name(covering_ns, entry.label_token)?;
                // Resolve every covered property token's name (one for non-composite kinds, the whole
                // tuple for a node key). A token with no resolvable name skips the whole entry.
                let mut properties = Vec::with_capacity(entry.property_tokens.len());
                for &prop_token in &entry.property_tokens {
                    properties.push(store.token_name(Namespace::PropKey, prop_token)?.to_owned());
                }
                Some(ConstraintInfo {
                    name,
                    label: label.to_owned(),
                    properties,
                    kind: entry.kind,
                    type_descriptor: entry.type_descriptor,
                })
            })
            .collect()
    }

    /// Whether any non-blocking index build is still in progress (`rmp` task #91/#72/#98). The engine
    /// loop uses this to decide between a plain blocking receive (no builds) and a timed receive that
    /// also drives the build between commands.
    ///
    /// Deliberately does **not** include the degraded state (`rmp` task #733): callers such as
    /// `LocalEngine::drain_index_builds` spin `while has_pending_index_builds() { advance… }`, so
    /// reporting a permanently-faulting store as "pending" would hang them forever. Degradation is
    /// surfaced by [`indexes_degraded`](Self::indexes_degraded) and repaired by
    /// [`retry_degraded_index_rebuild`](Self::retry_degraded_index_rebuild), which is bounded and
    /// back-off-limited.
    #[must_use]
    pub fn has_pending_index_builds(&self) -> bool {
        !self.pending_builds.is_empty()
            || !self.pending_fulltext_builds.is_empty()
            || !self.pending_spatial_builds.is_empty()
    }

    /// Whether the **label (token LOOKUP) index** may still be used (`rmp` task #733).
    ///
    /// It is the base of every fallback in the engine — a declined seek degrades to a label scan — and a
    /// `fail_closed` leaves it empty, at which point the label-scan seam bypasses it and enumerates the
    /// store instead. `SHOW INDEXES` must therefore report the synthetic `LOOKUP` row as `POPULATING`
    /// rather than the hard-coded `ONLINE`: the index that stopped being usable is precisely the one the
    /// engine leans on hardest, and claiming it is online is the most misleading thing the surface could
    /// say.
    #[must_use]
    pub fn label_lookup_usable(&self) -> bool {
        self.index.borrow().labels_usable()
    }

    /// Whether the derived indexes are currently **degraded** — a storage fault made them
    /// untrustworthy and [`IndexSet::fail_closed`] dropped the engine to scans (`rmp` task #733).
    ///
    /// Answers are still **correct** while degraded (every read path is on the exact scan), but they are
    /// unaccelerated, and the condition must be visible: the server logs it, meters it, and reports the
    /// affected indexes as `POPULATING` rather than `ONLINE`.
    #[must_use]
    pub fn indexes_degraded(&self) -> bool {
        self.index.borrow().is_degraded()
    }

    /// How many times the derived indexes have been wiped by [`IndexSet::fail_closed`] over this
    /// coordinator's life (`rmp` task #733) — monotonic. The server samples it to log each new
    /// occurrence at `ERROR` and drive a metric; a silent degradation is indistinguishable from a
    /// healthy-but-slow engine, which is how this class of fault stays unnoticed.
    #[must_use]
    pub fn index_fail_closed_events(&self) -> u64 {
        self.index.borrow().fail_closed_events()
    }

    /// How many builds have been **poisoned** over this coordinator's life (`rmp` task #733, M1) —
    /// monotonic. A poisoned build is one a storage fault stopped for good: its index is left
    /// `Populating` (never served, so answers stay correct via the scan) until the store reads cleanly
    /// again. The server samples this to log the event at `ERROR` and drive a metric.
    #[must_use]
    pub fn index_build_poison_events(&self) -> u64 {
        self.poison_events
    }

    /// How many poisoned builds are currently parked awaiting resurrection (`rmp` task #733, M1).
    #[must_use]
    pub fn poisoned_index_builds(&self) -> usize {
        self.poisoned_builds.len()
            + self.poisoned_fulltext_builds.len()
            + self.poisoned_spatial_builds.len()
    }

    /// Re-enqueues every **poisoned** build once the store reads cleanly again (`rmp` task #733, M1),
    /// returning whether any build was resurrected.
    ///
    /// Poisoning is what guarantees termination against a permanently-faulting store, but on its own it
    /// is a **one-way door**: the index stays `Populating` — never served, so answers remain correct, but
    /// never accelerated either — with nothing in the process able to bring it back before a restart. A
    /// *transient* fault would therefore cost an index permanently. So a poisoned build is parked, not
    /// discarded, and this probes the store (one `scan_node_ids`) and, when it succeeds, re-enqueues each
    /// parked build with a **fresh snapshot**, a full stall budget and the current wipe epoch — exactly
    /// the state a healthy build starts from.
    ///
    /// Throttled by the same backoff discipline as the degraded rebuild retry, so a broken store cannot
    /// make the engine probe on every command. It must NOT be called from inside
    /// [`advance_index_builds`](Self::advance_index_builds): a build that fails again would be re-enqueued
    /// within the same drain loop, and `while has_pending_index_builds() { advance… }` would never
    /// terminate. The engine calls it *around* the drain, never inside it.
    ///
    /// # Bounding the poison↔resurrect cycle (`rmp` task #733, B2)
    ///
    /// The probe ([`resnapshot_build`](Self::resnapshot_build)) reads only the node *slot* pages, not the
    /// property / label pages a build indexes. A build poisoned by an unreadable **property** page thus
    /// passes the probe, is resurrected, re-drains, hits the same page, and re-poisons. The M1 code reset
    /// the throttle to `0` on every successful probe, so this repeated **every tick** (≈ 500 O(store)
    /// re-scans/second on a live server — a CPU + I/O + log-flood DoS, and the exact spin the round-3
    /// stall budget had eliminated, re-introduced through the resurrection door).
    ///
    /// The fix keeps the throttle **armed** across resurrections and *escalates* it whenever the parked
    /// builds were re-poisoned since the last resurrection (detected via
    /// [`poison_watermark`](Self#structfield.poison_watermark)). The backoff only resets when the
    /// graveyard truly clears — i.e. a resurrected build actually **completed** — so a genuinely-healed
    /// store returns to a fast retry while a permanently-broken one has its retry rate collapse
    /// geometrically to one attempt per [`MAX_DEGRADED_RETRY_BACKOFF`] drains.
    pub fn retry_poisoned_index_builds(&mut self) -> bool {
        if self.poisoned_index_builds() == 0 {
            // The graveyard is clear: either nothing was ever poisoned, or a resurrection's builds all
            // COMPLETED. Reset the throttle so a store that has genuinely healed retries promptly.
            self.poison_resurrect_attempts = 0;
            self.poison_retry_skip = 0;
            return false;
        }
        if self.poison_retry_skip > 0 {
            self.poison_retry_skip -= 1;
            return false;
        }
        // Probe: can the store even be scanned? If not, stay parked and back off (this is a *different*
        // failure — the slot pages themselves are unreadable — and it escalates like a re-poison).
        let Some(snapshot) = Self::resnapshot_build(&self.store) else {
            self.poison_resurrect_attempts = self.poison_resurrect_attempts.saturating_add(1);
            self.poison_retry_skip = poison_backoff(self.poison_resurrect_attempts);
            return false;
        };
        let generation = self.index.borrow().wipe_generation();
        for mut build in self.poisoned_builds.drain(..) {
            build.snapshot.clone_from(&snapshot);
            build.cursor = 0;
            build.stall = BUILD_STALL_BUDGET;
            build.generation = generation;
            self.pending_builds.push_back(build);
        }
        for mut build in self.poisoned_fulltext_builds.drain(..) {
            build.snapshot.clone_from(&snapshot);
            build.cursor = 0;
            build.stall = BUILD_STALL_BUDGET;
            build.generation = generation;
            self.pending_fulltext_builds.push_back(build);
        }
        for mut build in self.poisoned_spatial_builds.drain(..) {
            build.snapshot.clone_from(&snapshot);
            build.cursor = 0;
            build.stall = BUILD_STALL_BUDGET;
            build.generation = generation;
            self.pending_spatial_builds.push_back(build);
        }
        // Count this resurrection and ARM the throttle for the NEXT one (`rmp` task #733, B2). The FIRST
        // resurrection after a poisoning is immediate (`attempts` was 0, so this is attempt 1); if these
        // builds re-poison — which happens later in the same drain — the graveyard refills and the next
        // call skips `poison_backoff(attempts)` drains before probing again, doubling each time. If they
        // instead complete, the graveyard clears and the `== 0` branch above resets `attempts` to 0. So a
        // transient fault heals within one or two cycles while a permanent one has its retry rate decay
        // geometrically to one attempt per [`MAX_DEGRADED_RETRY_BACKOFF`] drains.
        self.poison_resurrect_attempts = self.poison_resurrect_attempts.saturating_add(1);
        self.poison_retry_skip = poison_backoff(self.poison_resurrect_attempts);
        true
    }

    /// Attempts to **repair** a degraded index set by rebuilding it from the store (`rmp` task #733),
    /// returning whether the engine is healthy afterwards.
    ///
    /// A `fail_closed` is usually the result of a *transient* storage fault, and without this the
    /// process would serve scan-only until it was restarted. So the engine calls this from its tick: a
    /// successful rebuild restores every fast path (and re-promotes the indexes in `SHOW INDEXES`),
    /// while a rebuild that faults again simply fails closed once more — always correct, never wrong.
    ///
    /// A full rebuild is **O(store)** and runs synchronously on the engine thread, stalling every query
    /// behind it — so against a *persistently* broken store it must be rare, not merely throttled. Retries
    /// are therefore backed off exponentially up to [`MAX_DEGRADED_RETRY_BACKOFF`] attempts-worth of
    /// skips (≈ 8.7 minutes at the engine's 2 ms tick, and far longer under load, where the counter only
    /// advances once per command). The backoff resets the moment a rebuild succeeds. Deliberately counted
    /// in *attempts* rather than wall-clock: the coordinator must stay deterministic for DST, so it may
    /// not read the clock. A no-op returning `true` when the index set is healthy, so callers can invoke
    /// it unconditionally.
    pub fn retry_degraded_index_rebuild(&mut self) -> bool {
        if !self.index.borrow().is_degraded() {
            return true;
        }
        if self.degraded_retry_skip > 0 {
            self.degraded_retry_skip -= 1;
            return false;
        }
        Self::rebuild_index(&self.store, &self.index);
        if self.index.borrow().is_degraded() {
            // Still faulting: back off so a permanently-broken store cannot make the engine thread burn
            // a whole store scan every tick (correctness is unaffected either way — reads are on scans).
            self.degraded_retry_backoff = self
                .degraded_retry_backoff
                .saturating_mul(2)
                .min(MAX_DEGRADED_RETRY_BACKOFF);
            self.degraded_retry_skip = self.degraded_retry_backoff;
            false
        } else {
            // Repaired. The backoff is **halved**, not reset (`rmp` task #733, M3): an *intermittent*
            // device — fail, repair, fail, repair — would otherwise re-arm a 1-attempt backoff on every
            // success, so the very next fault triggers another O(store) synchronous rebuild on the engine
            // thread and the engine spends its life re-scanning the store. Decaying the backoff lets a
            // genuinely-healed store return to a fast retry within a few cycles, while a flapping one
            // stays throttled.
            self.degraded_retry_backoff = (self.degraded_retry_backoff / 2).max(1);
            self.degraded_retry_skip = 0;
            true
        }
    }

    /// Advances the front non-blocking index build by up to `budget` nodes (`rmp` task #91), returning
    /// whether **any** build remains pending afterwards.
    ///
    /// For the front build it indexes the next `budget` snapshot nodes (each via the shared
    /// `index_one_node` helper, so the per-node logic matches the full
    /// rebuild). When the front build's cursor reaches the end of its snapshot it is **complete**: the
    /// catalog entry is durably flipped to [`IndexState::Online`] in a committed transaction, the
    /// in-memory state is promoted, and the build is dequeued — after which the planner begins routing
    /// seeks to it. Per-call work is bounded by `budget` so a build never monopolises the engine
    /// thread (the responsiveness guarantee).
    ///
    /// A `budget` of `0` performs no indexing but still returns the pending state (callers should pass
    /// a positive chunk size). If the durable promotion commit fails, the build is left in place
    /// `Populating` (still correct via the scan fallback) to be retried on the next call/open.
    pub fn advance_index_builds(&mut self, budget: usize) -> bool {
        // Repair a fail-closed index set FIRST (`rmp` task #733). This runs on the **command** path (the
        // engine drives an index build after every command), not just on the idle tick — under sustained
        // load an idle tick may never come, and a build cannot promote while the set is degraded, so
        // without this the engine would stay scan-only for as long as it was busy. The attempt itself is
        // exponentially backed off inside `retry_degraded_index_rebuild`, so a permanently-faulting store
        // costs at most one bounded probe per backoff window.
        if self.index.borrow().is_degraded() {
            let _healed = self.retry_degraded_index_rebuild();
        }
        // Drive a node-property build first if one is pending; then a full-text build; then a spatial
        // build. Processing one queue per call keeps the per-call work bounded by `budget` for any kind.
        if !self.pending_builds.is_empty() {
            self.advance_node_property_build(budget);
        } else if !self.pending_fulltext_builds.is_empty() {
            self.advance_fulltext_build(budget);
        } else {
            self.advance_spatial_build(budget);
        }
        self.has_pending_index_builds()
    }

    /// Advances the front **node-property** build by up to `budget` nodes (`rmp` task #91), promoting
    /// + dequeuing it when complete.
    fn advance_node_property_build(&mut self, budget: usize) {
        // (1) EPOCH CHECK (`rmp` task #733). Was the index set wiped by a `fail_closed` since this build
        // last ran? The build queues live on the coordinator, out of `IndexSet`'s reach, so a wipe empties
        // the half-built tree without telling the build. Resuming from the old cursor would index only the
        // TAIL of the snapshot and then promote the index `Online` over the hole. And restarting at
        // cursor 0 over the ORIGINAL snapshot is *still* not enough — the wipe also destroyed the
        // maintenance writes for rows created after the snapshot — so the snapshot itself is re-taken.
        // See `resnapshot_build`.
        let generation = self.index.borrow().wipe_generation();
        if self
            .pending_builds
            .front()
            .is_some_and(|b| b.generation != generation)
        {
            let Some(fresh) = Self::resnapshot_build(&self.store) else {
                // The store cannot be scanned: POISON the build (drop it un-promoted). The index stays
                // `Populating`, so it is never served — correct, just unaccelerated — and the degraded
                // rebuild retry will repopulate its tree. Never resume a build we cannot re-base.
                Self::poison_front(
                    &mut self.pending_builds,
                    &mut self.poisoned_builds,
                    &mut self.poison_events,
                );
                return;
            };
            if let Some(build) = self.pending_builds.front_mut() {
                build.snapshot = fresh;
                build.cursor = 0;
                build.generation = generation;
                build.stall = BUILD_STALL_BUDGET;
            }
        }

        let Some(build) = self.pending_builds.front_mut() else {
            return;
        };

        // Index up to `budget` nodes from the snapshot, starting at the cursor.
        let registered = [(build.label_token, build.prop_key)];
        let start = build.cursor;
        let end = build.snapshot.len().min(build.cursor + budget);
        let chunk: Vec<u64> = build.snapshot[start..end].to_vec();
        let total = build.snapshot.len();
        // A clean slate: only THIS chunk's read faults may fail THIS build (`rmp` task #733).
        self.index.borrow_mut().clear_rebuild_gap();
        for id in chunk {
            Self::index_one_node(&self.store, &self.index, id, &registered);
        }

        // (2) GAP CHECK. Could a node in this chunk not be read? Then the tree has a hole a seek could
        // never resurrect, so the cursor does NOT advance and the index is NOT promoted — the chunk is
        // retried. A *transient* fault heals within a few attempts; a **persistent** one (the model this
        // project assumes: checksum / torn page) would otherwise retry forever, and
        // `LocalEngine::drain_index_builds` spins `while has_pending_index_builds()`, so that is an
        // infinite loop at 100% CPU re-scanning the store. Hence the bounded stall budget: when it is
        // exhausted the build is POISONED (dropped, un-promoted, index left `Populating` and therefore
        // never served). Terminates, never holes, never spins.
        if self.index.borrow().rebuild_gap() {
            self.index.borrow_mut().clear_rebuild_gap();
            if Self::stall_or_poison(&mut self.pending_builds, |b| &mut b.stall) {
                Self::poison_front(
                    &mut self.pending_builds,
                    &mut self.poisoned_builds,
                    &mut self.poison_events,
                );
            }
            return;
        }

        let Some(build) = self.pending_builds.front_mut() else {
            return;
        };
        build.cursor = end;
        // Refill the stall budget ONLY on real progress. An **empty** chunk (`start == end == total`, the
        // state of a completed build that keeps being re-driven because the degraded gate below will not
        // let it promote) is not progress: refilling on it resets the budget faster than the gate spends
        // it, so the build never poisons, `has_pending_index_builds()` never goes false, and
        // `LocalEngine::drain_index_builds` spins forever (`rmp` task #733).
        if end > start {
            build.stall = BUILD_STALL_BUDGET;
        }
        if build.cursor < total {
            return; // more of this build remains.
        }

        // (3) BELT AND BRACES. Never publish into a WIPED index set: while the engine is degraded, the
        // derived structures are known-untrustworthy and a repair rebuild is pending, so an `Online`
        // promotion now could only be a claim we cannot back. Stall (bounded) and let the repair run
        // first; on exhaustion the build is poisoned rather than promoted.
        if self.index.borrow().is_degraded() {
            if Self::stall_or_poison(&mut self.pending_builds, |b| &mut b.stall) {
                Self::poison_front(
                    &mut self.pending_builds,
                    &mut self.poisoned_builds,
                    &mut self.poison_events,
                );
            }
            return;
        }

        let Some(build) = self.pending_builds.front_mut() else {
            return;
        };
        // The front build's snapshot is fully indexed: promote it durably to `Online`, then dequeue.
        let (label_token, prop_key) = (build.label_token, build.prop_key);
        self.next_txn_id += 1;
        let txn = TxnId(self.next_txn_id);
        self.store.borrow_mut().begin(txn);
        self.store
            .borrow_mut()
            .set_node_property_index(label_token, prop_key, IndexState::Online);
        if self.store.borrow_mut().commit(txn).is_err() {
            // The durable flip failed; leave the build pending `Populating` and retry next call.
            return;
        }
        self.index
            .borrow_mut()
            .set_node_property_state(label_token, prop_key, IndexState::Online);
        self.pending_builds.pop_front();
    }

    /// Advances the front **full-text** build by up to `budget` nodes (`rmp` task #72), promoting +
    /// dequeuing it when complete. The full-text analogue of
    /// [`advance_node_property_build`](Self::advance_node_property_build): each chunk re-indexes a
    /// bounded number of snapshot nodes' text into the inverted index via the shared
    /// [`index_one_node_fulltext`](Self::index_one_node_fulltext) helper, then on completion the named
    /// catalog entry is durably flipped to [`IndexState::Online`].
    fn advance_fulltext_build(&mut self, budget: usize) {
        // (1) EPOCH CHECK + RE-SNAPSHOT, exactly as `advance_node_property_build` documents (`rmp` #733).
        // The full-text index escapes the worst of a stale resume by accident (the `rmp` #467 marker
        // poison keeps readers off a wiped inverted index), but it must not be left half-filled-and-
        // `Online` either — and the marker is cleared by the very rebuild that repairs the set.
        let generation = self.index.borrow().wipe_generation();
        if self
            .pending_fulltext_builds
            .front()
            .is_some_and(|b| b.generation != generation)
        {
            let Some(fresh) = Self::resnapshot_build(&self.store) else {
                Self::poison_front(
                    &mut self.pending_fulltext_builds,
                    &mut self.poisoned_fulltext_builds,
                    &mut self.poison_events,
                ); // poison: never resume a build we cannot re-base.
                return;
            };
            if let Some(build) = self.pending_fulltext_builds.front_mut() {
                build.snapshot = fresh;
                build.cursor = 0;
                build.generation = generation;
                build.stall = BUILD_STALL_BUDGET;
            }
        }
        let Some(build) = self.pending_fulltext_builds.front_mut() else {
            return;
        };
        let total = build.snapshot.len();
        let start = build.cursor;
        let end = total.min(build.cursor + budget);
        let chunk: Vec<u64> = build.snapshot[start..end].to_vec();
        let name = build.name.clone();
        build.cursor = end;
        let done = end >= total;

        // A clean slate: only THIS chunk's read faults may fail THIS build (`rmp` task #733).
        self.index.borrow_mut().clear_rebuild_gap();
        for id in chunk {
            Self::index_one_node_fulltext(&self.store, &self.index, id);
        }
        // (2) GAP CHECK. A node this chunk could not read is missing from the inverted index for good, and
        // no per-candidate re-check can resurrect it. Rewind and retry — bounded by the stall budget, so a
        // persistent fault poisons the build instead of spinning the engine forever (`rmp` task #733).
        if self.index.borrow().rebuild_gap() {
            self.index.borrow_mut().clear_rebuild_gap();
            if Self::stall_or_poison(&mut self.pending_fulltext_builds, |b| &mut b.stall) {
                Self::poison_front(
                    &mut self.pending_fulltext_builds,
                    &mut self.poisoned_fulltext_builds,
                    &mut self.poison_events,
                );
            } else if let Some(build) = self.pending_fulltext_builds.front_mut() {
                build.cursor = start;
            }
            return;
        }
        if end > start
            && let Some(build) = self.pending_fulltext_builds.front_mut()
        {
            build.stall = BUILD_STALL_BUDGET; // real progress: refill the budget.
        }
        // The chunk re-indexed committed text into the inverted index; raise the cross-snapshot
        // freshness marker to the store high-water so a reader whose snapshot predates this build
        // (and predates a covered node's current committed value, possibly written before the index
        // existed) declines to the always-correct scan path (`rmp` task #467). Only raises; never
        // clears a poison (an incremental build is not exhaustive — see
        // `bump_ft_spatial_marker_after_build`). Also discards the build's transient dirty flag so it
        // is not mis-attributed to the next user transaction.
        let high_water = self.store.borrow().snapshot_ts();
        self.index
            .borrow_mut()
            .bump_ft_spatial_marker_after_build(high_water);

        if !done {
            return; // more of this build remains.
        }

        // (3) BELT AND BRACES: never publish into a WIPED index set (`rmp` task #733) — stall (bounded)
        // until the repair rebuild has run, then poison rather than promote.
        //
        // The cursor is deliberately NOT rewound here. Rewinding would make the *next* call re-run a
        // non-empty chunk, which the gap check would read as progress and use to refill the stall budget
        // — so the budget would be replenished faster than this gate spends it and the build would never
        // poison, spinning `LocalEngine::drain_index_builds` forever. Leaving the cursor at the end costs
        // nothing: the chunk's entries are already in the tree, and if the set is wiped again the epoch
        // check re-snapshots and rebuilds from scratch anyway.
        if self.index.borrow().is_degraded() {
            if Self::stall_or_poison(&mut self.pending_fulltext_builds, |b| &mut b.stall) {
                Self::poison_front(
                    &mut self.pending_fulltext_builds,
                    &mut self.poisoned_fulltext_builds,
                    &mut self.poison_events,
                );
            }
            return;
        }

        // The snapshot is fully indexed: durably flip the catalog entry to `Online`, then dequeue.
        // Read the current entry in its own scope so the store borrow is released before the write.
        let entry = self.store.borrow().fulltext_index(&name);
        self.next_txn_id += 1;
        let txn = TxnId(self.next_txn_id);
        self.store.borrow_mut().begin(txn);
        let promoted = if let Some(entry) = entry {
            self.store.borrow_mut().set_fulltext_index(
                name.clone(),
                FulltextIndexEntry {
                    state: IndexState::Online,
                    ..entry
                },
            );
            true
        } else {
            // The index was dropped mid-build; nothing to promote (the build will be dequeued).
            false
        };
        if promoted {
            if self.store.borrow_mut().commit(txn).is_err() {
                // The durable flip failed; leave the build pending `Populating` and retry next call.
                return;
            }
        } else {
            let _ = self.store.borrow_mut().rollback(txn);
        }
        self.index
            .borrow_mut()
            .set_fulltext_state(&name, IndexState::Online);
        self.pending_fulltext_builds.pop_front();
    }

    /// Advances the front **spatial** build by up to `budget` nodes (`rmp` task #98), promoting +
    /// dequeuing it when complete. The spatial analogue of
    /// [`advance_fulltext_build`](Self::advance_fulltext_build): each chunk indexes a bounded number of
    /// snapshot nodes' point values into the grid via the shared
    /// [`index_one_node_spatial`](Self::index_one_node_spatial) helper, then on completion the named
    /// catalog entry is durably flipped to [`IndexState::Online`] (after which the planner begins
    /// routing proximity seeks to it).
    fn advance_spatial_build(&mut self, budget: usize) {
        // (1) EPOCH CHECK + RE-SNAPSHOT — the spatial twin of `advance_node_property_build` (`rmp` #733).
        let generation = self.index.borrow().wipe_generation();
        if self
            .pending_spatial_builds
            .front()
            .is_some_and(|b| b.generation != generation)
        {
            let Some(fresh) = Self::resnapshot_build(&self.store) else {
                Self::poison_front(
                    &mut self.pending_spatial_builds,
                    &mut self.poisoned_spatial_builds,
                    &mut self.poison_events,
                ); // poison: cannot re-base this build.
                return;
            };
            if let Some(build) = self.pending_spatial_builds.front_mut() {
                build.snapshot = fresh;
                build.cursor = 0;
                build.generation = generation;
                build.stall = BUILD_STALL_BUDGET;
            }
        }
        let Some(build) = self.pending_spatial_builds.front_mut() else {
            return;
        };
        let total = build.snapshot.len();
        let start = build.cursor;
        let end = total.min(build.cursor + budget);
        let chunk: Vec<u64> = build.snapshot[start..end].to_vec();
        let name = build.name.clone();
        let registered = [(build.label_token, build.prop_key)];
        build.cursor = end;
        let done = end >= total;

        // A clean slate: only THIS chunk's read faults may fail THIS build (`rmp` task #733).
        self.index.borrow_mut().clear_rebuild_gap();
        for id in chunk {
            Self::index_one_node_spatial(&self.store, &self.index, id, &registered);
        }
        // (2) GAP CHECK. A node this chunk could not read would be missing from the grid for good — the
        // residual `distance(...)` filter can drop a candidate but never add one back. Rewind and retry,
        // bounded by the stall budget so a persistent fault poisons the build (`rmp` task #733).
        if self.index.borrow().rebuild_gap() {
            self.index.borrow_mut().clear_rebuild_gap();
            if Self::stall_or_poison(&mut self.pending_spatial_builds, |b| &mut b.stall) {
                Self::poison_front(
                    &mut self.pending_spatial_builds,
                    &mut self.poisoned_spatial_builds,
                    &mut self.poison_events,
                );
            } else if let Some(build) = self.pending_spatial_builds.front_mut() {
                build.cursor = start;
            }
            return;
        }
        if end > start
            && let Some(build) = self.pending_spatial_builds.front_mut()
        {
            build.stall = BUILD_STALL_BUDGET; // real progress: refill the budget.
        }
        // Raise the cross-snapshot freshness marker to the store high-water (read BEFORE the promotion
        // commit below so it reflects the indexed nodes' committed state, not the promotion txn's ts),
        // for the same reason as the full-text build: a reader whose snapshot predates this build must
        // decline to the scan path (`rmp` task #467). Only raises; never clears a poison. Also clears
        // the build's transient dirty flag.
        let high_water = self.store.borrow().snapshot_ts();
        self.index
            .borrow_mut()
            .bump_ft_spatial_marker_after_build(high_water);

        if !done {
            return; // more of this build remains.
        }

        // (3) BELT AND BRACES: never publish into a WIPED index set (`rmp` task #733). The cursor is not
        // rewound — see `advance_fulltext_build` for why rewinding here defeats the stall budget.
        if self.index.borrow().is_degraded() {
            if Self::stall_or_poison(&mut self.pending_spatial_builds, |b| &mut b.stall) {
                Self::poison_front(
                    &mut self.pending_spatial_builds,
                    &mut self.poisoned_spatial_builds,
                    &mut self.poison_events,
                );
            }
            return;
        }

        // The snapshot is fully indexed: durably flip the catalog entry to `Online`, then dequeue.
        // Read the current entry in its own scope so the store borrow is released before the write.
        let entry = self.store.borrow().spatial_index(&name);
        self.next_txn_id += 1;
        let txn = TxnId(self.next_txn_id);
        self.store.borrow_mut().begin(txn);
        let promoted = if let Some(entry) = entry {
            self.store.borrow_mut().set_spatial_index(
                name.clone(),
                SpatialIndexEntry {
                    state: IndexState::Online,
                    ..entry
                },
            );
            true
        } else {
            // The index was dropped mid-build; nothing to promote (the build will be dequeued).
            false
        };
        if promoted {
            if self.store.borrow_mut().commit(txn).is_err() {
                // The durable flip failed; leave the build pending `Populating` and retry next call.
                return;
            }
        } else {
            let _ = self.store.borrow_mut().rollback(txn);
        }
        self.index.borrow_mut().set_spatial_state(
            registered[0].0,
            registered[0].1,
            IndexState::Online,
        );
        self.pending_spatial_builds.pop_front();
    }

    /// Drops the node-property index on `(label, property)` (`rmp` task #91): removes its durable
    /// catalog entry in a committed transaction and unregisters it from the in-memory [`IndexSet`],
    /// cancelling any in-progress non-blocking build of the same index.
    ///
    /// Idempotent on a never-declared index: the durable removal is a no-op and the in-memory
    /// unregister is a no-op, so dropping an absent index succeeds. The tokens are looked up (not
    /// interned): an unknown label/property means no such index can exist, so the call is a clean
    /// no-op success.
    ///
    /// Returns whether an index was **actually removed** (`true`) or the call was a no-op (`false`, no
    /// such index) — the executor turns `false` into a `0` `indexes-removed` counter (`rmp` task #626
    /// follow-up: Neo4j-conformant idempotent-DDL summary).
    ///
    /// # Errors
    /// Returns a storage error if the committing transaction fails.
    pub fn drop_node_property_index(&mut self, label: &str, property: &str) -> Result<bool> {
        // Resolve the tokens by lookup only; a missing token means the index cannot exist.
        let tokens = {
            let store = self.store.borrow();
            match (
                store.token_id(Namespace::Label, label),
                store.token_id(Namespace::PropKey, property),
            ) {
                // Only an actually-declared index is a real drop; tokens can exist with no index.
                (Some(label_token), Some(prop_key))
                    if store
                        .node_property_index_state(label_token, prop_key)
                        .is_some() =>
                {
                    Some((label_token, prop_key))
                }
                _ => None,
            }
        };
        let Some((label_token, prop_key)) = tokens else {
            return Ok(false); // no such index → clean no-op, nothing removed.
        };

        // Remove the durable catalog entry AND its name entry in one committed transaction (mirrors the
        // create path, which records both). Clearing the name alongside the index keeps the two in sync
        // and frees the name for reuse.
        self.next_txn_id += 1;
        let txn = TxnId(self.next_txn_id);
        self.store.borrow_mut().begin(txn);
        {
            let mut store = self.store.borrow_mut();
            store.remove_node_property_index(label_token, prop_key);
            store.remove_node_property_index_name_for(label_token, prop_key);
        }
        self.store.borrow_mut().commit(txn)?;

        // Cancel any in-progress build for this index and unregister it from the in-memory set.
        self.pending_builds
            .retain(|b| !(b.label_token == label_token && b.prop_key == prop_key));
        self.index
            .borrow_mut()
            .unregister_node_property(label_token, prop_key);
        Ok(true) // an index was removed.
    }

    /// Drops the node-property index named `name` (`rmp` task #624), the `DROP INDEX <name>` surface:
    /// resolves the name to its covered `(label, property)`, removes the durable catalog + name entries
    /// in one committed transaction, cancels any in-progress build and unregisters it from the in-memory
    /// [`IndexSet`].
    ///
    /// `if_exists` controls the missing-name case: `true` (a `DROP INDEX <name> IF EXISTS`) makes a
    /// never-declared name a clean no-op success; `false` returns
    /// `Neo.ClientError.Schema.IndexDropFailed`.
    ///
    /// Returns whether an index was **actually removed** (`true`) or the call was a no-op (`false`, an
    /// `IF EXISTS` drop of a missing name) — the executor turns `false` into a `0` `indexes-removed`
    /// counter (`rmp` task #626 follow-up: Neo4j-conformant idempotent-DDL summary).
    ///
    /// # Errors
    /// - `Neo.ClientError.Schema.IndexDropFailed` (no `IF EXISTS`) when no index of that name exists;
    /// - a storage error if the committing transaction fails.
    pub fn drop_node_property_index_by_name(
        &mut self,
        name: &str,
        if_exists: bool,
    ) -> Result<bool> {
        let target = self.store.borrow().node_property_index_name(name);
        let Some((label_token, prop_key)) = target else {
            return if if_exists {
                Ok(false) // idempotent no-op: nothing removed.
            } else {
                Err(index_drop_not_found(name))
            };
        };

        // Remove the durable index catalog entry + its name in one committed transaction.
        self.next_txn_id += 1;
        let txn = TxnId(self.next_txn_id);
        self.store.borrow_mut().begin(txn);
        {
            let mut store = self.store.borrow_mut();
            store.remove_node_property_index(label_token, prop_key);
            store.remove_node_property_index_name(name);
        }
        self.store.borrow_mut().commit(txn)?;

        // Cancel any in-progress build for this index and unregister it from the in-memory set.
        self.pending_builds
            .retain(|b| !(b.label_token == label_token && b.prop_key == prop_key));
        self.index
            .borrow_mut()
            .unregister_node_property(label_token, prop_key);
        Ok(true) // an index was removed.
    }

    /// Lists every declared node-property index as `(name, label, property, state)` (`rmp` tasks #91,
    /// #624), for a `SHOW INDEXES` surface. Reads the durable catalog and resolves the tokens back to
    /// names; the index **name** is the durable name if recorded, else the deterministic
    /// [`auto_index_name`] (a defensive fallback for a not-yet-backfilled legacy index). An index whose
    /// tokens have no resolvable name (a defensively-skipped impossibility for a live token) is omitted.
    /// Ordered by the catalog's ascending `(label_token, prop_key)` key.
    #[must_use]
    pub fn list_node_property_indexes(&self) -> Vec<(String, String, String, IndexState)> {
        let store = self.store.borrow();
        store
            .node_property_indexes()
            .into_iter()
            .filter_map(|(label_token, prop_key, state)| {
                // The EFFECTIVE state (`rmp` task #733): a failed build / fail-closed leaves the durable
                // catalog saying ONLINE while the engine cannot use the index.
                let state = Self::effective_state(
                    state,
                    self.index
                        .borrow()
                        .node_property_state(label_token, prop_key),
                );
                let label = store.token_name(Namespace::Label, label_token)?;
                let property = store.token_name(Namespace::PropKey, prop_key)?;
                let name = store
                    .node_property_index_name_for(label_token, prop_key)
                    .unwrap_or_else(|| auto_index_name(label, property));
                Some((name, label.to_owned(), property.to_owned(), state))
            })
            .collect()
    }

    /// The physical planner's [`IndexCatalog`] reflecting the indexes this coordinator currently
    /// holds (`rmp` task #48, `04 §6.6`): a token-lookup entry for every label that has at least one
    /// indexed node, and a single-property entry for every **`Online`** node-property index. Tokens
    /// with no resolvable name (a defensively-skipped impossibility for a live token) are omitted.
    ///
    /// # State gating (`rmp` task #90)
    ///
    /// Only an [`IndexState::Online`] node-property index is surfaced to the planner: a `Populating`
    /// one is **withheld** so the planner never routes a seek to a half-built index — it falls back to
    /// a label-scan + filter for that `(label, property)` until the index is promoted. The filtering
    /// happens here ([`IndexSet::online_node_properties`]), so the `IndexCatalog` only ever contains
    /// usable indexes and the physical planner needs no state awareness — the lowest-friction path.
    /// The token-lookup (label) entries are unaffected: they come from the always-present label index,
    /// not from any declared node-property index.
    pub fn catalog(&self) -> IndexCatalog {
        let mut builder = IndexCatalog::builder();
        let store = self.store.borrow();

        // The label (token-lookup) index, but only while it may be trusted: a rebuild whose store scan
        // faulted leaves it empty, and the seam then enumerates the store instead (`rmp` task #733), so
        // advertising an index the engine will not use would only mislead the planner's costing.
        if self.index.borrow().labels_usable() {
            for token in self.index.borrow_mut().indexed_label_tokens() {
                if let Some(name) = store.token_name(Namespace::Label, token) {
                    builder = builder.with_token_lookup(name);
                }
            }
        }
        for (label_token, prop_key) in self.index.borrow().online_node_properties() {
            let (Some(label), Some(property)) = (
                store.token_name(Namespace::Label, label_token),
                store.token_name(Namespace::PropKey, prop_key),
            ) else {
                continue;
            };
            builder = builder.with_label_property(label, property);
        }
        // Spatial indexes (`rmp` task #73): surface every **`Online`** spatial index so the physical
        // planner can route a proximity predicate to a `SpatialIndexSeek`. Like node-property indexes,
        // only `Online` ones are exposed (`online_spatial` filters by state), so a half-built spatial
        // index never drives a seek — the planner keeps the scan + filter until it is promoted.
        for (label_token, prop_key) in self.index.borrow().online_spatial() {
            let (Some(label), Some(property)) = (
                store.token_name(Namespace::Label, label_token),
                store.token_name(Namespace::PropKey, prop_key),
            ) else {
                continue;
            };
            builder = builder.with_label_spatial(label, property);
        }
        // Text (trigram) indexes (`rmp` task #662): surface every **`Online`** text index so the
        // physical planner can route a `CONTAINS` / `ENDS WITH` / `STARTS WITH` predicate to a
        // `NodeTextIndexSeek`. Like the other kinds only `Online` ones are exposed (`online_text` filters
        // by state), so a half-built text index never drives a seek — the planner keeps the scan + filter
        // until it is promoted; the backing trigram index exists in the in-memory set (registered on open
        // / create), so the seek the planner emits always finds it.
        for (label_token, prop_key) in self.index.borrow().online_text() {
            let (Some(label), Some(property)) = (
                store.token_name(Namespace::Label, label_token),
                store.token_name(Namespace::PropKey, prop_key),
            ) else {
                continue;
            };
            builder = builder.with_label_text(label, property);
        }
        // Standalone composite (multi-property) node indexes (`rmp` task #657): surface every
        // **`Online`** one so the physical planner can consume a leading run of equality conjuncts into
        // one composite `NodeIndexSeek`. Read from the **durable** catalog (the source of a standalone
        // composite's registration), filtered to `Online` — a `Populating` one is withheld exactly like a
        // half-built single-property index. The backing tree exists in the in-memory set (registered on
        // open / create), so the seek the planner emits always finds it.
        for (_name, entry) in store.composite_indexes() {
            if entry.state != IndexState::Online {
                continue;
            }
            let Some(label) = store.token_name(Namespace::Label, entry.label_token) else {
                continue;
            };
            let mut properties = Vec::with_capacity(entry.property_tokens.len());
            let mut resolvable = true;
            for pk in &entry.property_tokens {
                match store.token_name(Namespace::PropKey, *pk) {
                    Some(p) => properties.push(p.to_owned()),
                    None => {
                        resolvable = false;
                        break;
                    }
                }
            }
            if resolvable {
                builder = builder.with_label_composite(label, properties);
            }
        }
        // Relationship-property indexes (`rmp` task #659): surface every **`Online`** rel-property index
        // so the physical planner can route a `MATCH ()-[r:T {p: v}]-()` / `WHERE r.p = v` equality to a
        // `RelIndexSeek` instead of scanning every `:T` relationship and filtering. Only `Online` ones are
        // exposed (`online_rel_properties` filters by state), so a half-built index never drives a seek —
        // the planner keeps the scan + filter until it is promoted; the backing tree exists in the
        // in-memory set (registered on open / create), so the seek the planner emits always finds it.
        for (type_token, prop_key) in self.index.borrow().online_rel_properties() {
            let (Some(rel_type), Some(property)) = (
                store.token_name(Namespace::RelType, type_token),
                store.token_name(Namespace::PropKey, prop_key),
            ) else {
                continue;
            };
            builder = builder.with_rel_property(rel_type, property);
        }
        // Relationship spatial (point) indexes (`rmp` task #664): surface every **`Online`** relationship
        // spatial index so the physical planner can route a `MATCH ()-[r:T]-() WHERE distance(r.p, $c) <=
        // $d` proximity to a `RelSpatialIndexSeek` instead of scanning every `:T` relationship. Only
        // `Online` ones are exposed (`online_spatial_rel` filters by state); relationship spatial indexes
        // are created synchronous-`Online`, so this is always the full set. The backing grid exists in the
        // in-memory set (registered on open / create), so the seek the planner emits always finds it.
        for (type_token, prop_key) in self.index.borrow().online_spatial_rel() {
            let (Some(rel_type), Some(property)) = (
                store.token_name(Namespace::RelType, type_token),
                store.token_name(Namespace::PropKey, prop_key),
            ) else {
                continue;
            };
            builder = builder.with_rel_spatial(rel_type, property);
        }
        // Standalone composite (multi-property) relationship indexes (`rmp` task #666): surface every
        // **`Online`** one so the physical planner can consume a leading run of equality conjuncts on a
        // relationship variable into one `RelCompositeIndexSeek` (or serve its leading key as a
        // single-key `RelIndexSeek`). Read from the **durable** catalog filtered to `Online`, exactly
        // like the node composite surface above; the backing tree exists in the in-memory `rel_composite`
        // map (registered on open / create), so the seek the planner emits always finds it.
        for (_name, entry) in store.rel_composite_indexes() {
            if entry.state != IndexState::Online {
                continue;
            }
            let Some(rel_type) = store.token_name(Namespace::RelType, entry.type_token) else {
                continue;
            };
            let mut properties = Vec::with_capacity(entry.property_tokens.len());
            let mut resolvable = true;
            for pk in &entry.property_tokens {
                match store.token_name(Namespace::PropKey, *pk) {
                    Some(p) => properties.push(p.to_owned()),
                    None => {
                        resolvable = false;
                        break;
                    }
                }
            }
            if resolvable {
                builder = builder.with_rel_composite(rel_type, properties);
            }
        }
        // Vector (HNSW) indexes (`rmp` task #669): surface every **`Online`** node / relationship vector
        // index so the query planner (`rmp` #671) can route a k-NN query to a vector index seek. Only
        // `Online` ones are exposed (`online_vector` / `online_vector_rel` filter by state); vector
        // indexes are created synchronous-`Online`, so this is always the full set. The backing HNSW
        // graph exists in the in-memory set (registered on open / create), so the seek the planner emits
        // always finds it. Without this surfacing the planner (#671) would never see the index — the
        // #659 trap.
        for (label_token, prop_key) in self.index.borrow().online_vector() {
            let (Some(label), Some(property)) = (
                store.token_name(Namespace::Label, label_token),
                store.token_name(Namespace::PropKey, prop_key),
            ) else {
                continue;
            };
            builder = builder.with_label_vector(label, property);
        }
        for (type_token, prop_key) in self.index.borrow().online_vector_rel() {
            let (Some(rel_type), Some(property)) = (
                store.token_name(Namespace::RelType, type_token),
                store.token_name(Namespace::PropKey, prop_key),
            ) else {
                continue;
            };
            builder = builder.with_rel_vector(rel_type, property);
        }
        builder.build()
    }

    /// A compile-time [`Statistics`] source over this coordinator's shared store (`rmp` task #82),
    /// for [`plan_physical_with_stats`](crate::physical::plan_physical_with_stats).
    ///
    /// This is how the production compile paths (the server's per-`Run` compile, the TCK runner,
    /// the LDBC bench driver) activate the cost-based optimiser: they hold no statement seam while
    /// compiling, so the per-statement [`RecordStoreGraph::statistics`](crate::graph_access::GraphAccess::statistics)
    /// seam is unavailable — this one answers from the same durable catalogue without needing an
    /// open transaction. See [`CoordinatorStatistics`] for the snapshot and borrow contracts.
    #[must_use]
    pub fn statistics(&self) -> CoordinatorStatistics<D, S> {
        CoordinatorStatistics {
            store: Rc::clone(&self.store),
        }
    }

    /// Borrows a per-statement [`RecordStoreGraph`] seam for the open transaction `txn`: the executor
    /// runs over it, its reads/writes contribute SIREAD markers / rw-edges / write locks to the
    /// shared trackers, and it is dropped when the statement ends (the transaction stays open).
    ///
    /// # Errors
    /// Returns [`GraphusError::Transaction`] if `txn` is not an open transaction.
    ///
    /// `D`/`S` carry `Send + Sync + 'static` because the returned seam can hand the executor an
    /// off-thread morsel read view (`rmp` task #339); every real store instantiation already meets these
    /// bounds (the `rmp` #336 off-thread reader path requires the same).
    pub fn statement(&self, txn: TxnId) -> Result<RecordStoreGraph<D, S>>
    where
        D: Send + Sync + 'static,
        S: Send + Sync + 'static,
    {
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
            Rc::clone(&self.columns),
            Rc::clone(&self.zones),
            self.csr.as_ref().map(Rc::clone),
        ))
    }

    /// Captures, **on the engine thread**, the owned `Send` pieces an off-thread reader needs to run a
    /// read-only statement for the open transaction `txn` against a
    /// [`ReadOnlyGraph`](crate::read_only_graph::ReadOnlyGraph) — without holding any `Rc`/`RefCell`
    /// across the thread boundary (`rmp` task #336, Slice 3b-ii).
    ///
    /// The returned [`ReadTaskInputs`] bundles: a [`StoreReadView`] (`Arc`-shared page cache + an owned
    /// [`MetaSnapshot`](graphus_storage::MetaSnapshot) of the committed location metadata), a
    /// [`TokenSnapshot`] (the `id ↔ name` dictionary), this reader's MVCC read [`Snapshot`], a **clone**
    /// of the store's [`CommitRegistry`] (so the reader resolves an in-flight writer to its outcome
    /// independently of the live store), and a **fresh, empty** [`SsiReadBuffer`] tagged with `txn` for
    /// the reader to accumulate its SIREAD markers into.
    ///
    /// Because `txn` was registered with the SSI tracker and inserted into the active set at
    /// [`begin`](Self::begin) — which happens **before** this capture and the subsequent dispatch — a
    /// concurrent writer's `record_write` always sees `txn` in `ssi.txns` and forms any rw-edge against
    /// it; and `txn` keeps pinning [`oldest_active_snapshot`](Self::oldest_active_snapshot) (so GC
    /// cannot reclaim a version the reader still needs) until it is removed at retirement
    /// (commit/rollback on the engine thread). The capture itself only **reads** the store (append-only
    /// `device_pages` + monotonic `high_water`), so it is MVCC-superset-safe.
    ///
    /// # Errors
    /// Returns [`GraphusError::Transaction`] if `txn` is not an open transaction.
    /// Demotes a standalone auto-commit read-only transaction to **Snapshot Isolation** (`rmp` task
    /// #545): it stops participating in SSI serializability tracking — [`merge_read_buffer`] drops its
    /// SIREAD markers unmerged and [`commit`](Self::commit) skips `detect_pivot_abort` (via
    /// [`IsolationLevel::runs_ssi`] returning `false`) — so a read carries no serializability overhead
    /// and can never cause a writer to abort. This is the MySQL / MariaDB / SQL-Server model: a
    /// standalone read is an SI snapshot read, not a serializable transaction.
    ///
    /// The transaction KEEPS its active-set snapshot reservation, so it still pins the GC watermark
    /// ([`oldest_active_snapshot`](Self::oldest_active_snapshot)) for the versions it reads (the InnoDB
    /// read-view analogue) — reads remain lock-free and observe a consistent MVCC snapshot with no
    /// premature reclamation (the #220 invariant).
    ///
    /// A no-op if `txn` is not open. The engine applies it ONLY to auto-commit read-only statements
    /// (both the off-thread reader path and the inline fallback), so the isolation is identical however
    /// the read is dispatched; explicit user transactions (`BEGIN … COMMIT`) and every write keep full
    /// Serializable SSI.
    pub fn demote_read_to_snapshot(&mut self, txn: TxnId) {
        if let Some(active) = self.active.get_mut(&txn) {
            active.isolation = IsolationLevel::Snapshot;
            self.ssi.borrow_mut().mark_snapshot(txn);
        }
    }

    pub fn read_task_inputs(&self, txn: TxnId) -> Result<ReadTaskInputs<D, S>> {
        let snapshot = self.active.get(&txn).map(|a| a.snapshot).ok_or_else(|| {
            GraphusError::Transaction(format!("read dispatch for inactive txn {}", txn.0))
        })?;
        let store = self.store.borrow();
        Ok(ReadTaskInputs {
            view: store.read_view(),
            tokens: store.token_snapshot(),
            snapshot,
            registry: store.commit_registry().clone(),
            buffer: SsiReadBuffer::new(txn),
            // `rmp` #546: capture the full-text catalogue so an off-thread `db.index.fulltext.
            // queryNodes` resolves the index by name and recomputes matches from this snapshot. Small
            // (one entry per declared index) and usually empty, so a per-read `Arc`-free clone is
            // negligible.
            fulltext: self.index.borrow().fulltext_snapshot(),
        })
    }

    /// Merges an off-thread reader's accumulated [`SsiReadBuffer`] into the shared
    /// [`SsiTracker`](graphus_txn::SsiTracker) on the engine thread, replaying its SIREAD markers
    /// (sorted + deduped) so the conflict graph is byte-identical to recording them inline (`rmp` tasks
    /// #341 + #336, Slice 3b-ii).
    ///
    /// **This is the M1 serializability barrier.** The engine MUST call this for a retiring reader
    /// **before** it runs [`commit`](Self::commit) for that reader (or for any concurrent writer whose
    /// pivot detection could depend on the reader's edges) — i.e. the merge is the first step of closing
    /// the reader. Because the merge and every [`commit`](Self::commit)'s `detect_pivot_abort` both run
    /// on the engine thread from the single serial event stream, M1 reduces to in-order event
    /// processing (see the Slice 3b no-lost-edge proof). Calling it for a still-open `txn` simply folds
    /// the markers in; it does not commit or remove the transaction.
    pub fn merge_read_buffer(&mut self, buffer: SsiReadBuffer) {
        self.ssi.borrow_mut().merge_read_buffer(buffer);
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

        // Authoritative cross-snapshot freshness stamp (`rmp` task #467): if `txn` structurally
        // mutated a full-text/spatial posting (recorded by the statement seam during its writes), retire
        // it as a committed mutator and raise the marker to `commit_ts`. From `commit_ts` onward the
        // change is committed-visible in BOTH the index and the scan, so a reader at-or-after it may
        // trust the fast index path; an older reader correctly declines. Because the in-flight set is
        // keyed by txn, the effective marker stays `u64::MAX` until EVERY concurrent full-text/spatial
        // mutator retires — a sibling writer's still-uncommitted mutation is never prematurely exposed.
        // A no-op for a non-mutating transaction.
        self.index
            .borrow_mut()
            .commit_ft_spatial_marker(txn, commit_ts);

        // 3) Publish the outcome: record the commit in the SSI tracker (kept for later conflict
        //    resolution until GC), release write locks, and close the transaction.
        self.ssi.borrow_mut().record_commit(txn, commit_ts);
        self.locks.borrow_mut().release_all(txn);
        // Drop this txn's bitmap abort-repair tracking (`rmp` #453, F-IDX-3): on commit the eagerly
        // maintained bitmap already reflects the now-committed writes, so there is nothing to re-derive
        // — only the bookkeeping is freed (a no-op unless a bitmap index was touched).
        self.index.borrow_mut().forget_dirty_bitmap_nodes(txn);
        self.active.remove(&txn);
        Ok(commit_ts)
    }

    /// Commit-**PREPARE** (cross-transaction group commit, phase 1, `04 §4.2` / `rmp` #528): runs SSI
    /// validation and the FULL in-memory commit publish of `txn` (assign commit timestamp, publish the
    /// SSI outcome + full-text/spatial marker, release locks, retire the transaction) EXCEPT the WAL
    /// group-commit `fdatasync`. Every observable effect is identical to [`commit`](Self::commit); only
    /// the durability sync is deferred, so the engine can PREPARE many committers and then issue ONE
    /// [`harden_wal`](Self::harden_wal) covering the whole batch.
    ///
    /// Returns `(commit_ts, commit_lsn)` where `commit_lsn` is `Some` iff a durable `COMMIT` record was
    /// appended (a real write commit the batch `fdatasync` must cover) or `None` for the read-only fast
    /// path (`rmp` #529 — nothing appended, nothing to harden). The caller MUST
    /// [`harden_wal`](Self::harden_wal) (advancing the durable watermark past `commit_lsn`) **before**
    /// acknowledging `txn` to its client — the ack-after-fsync durability rule.
    ///
    /// # Errors
    /// - [`GraphusError::Transaction`] if `txn` is not open.
    /// - [`GraphusError::Transaction`] (retriable serialization failure) if `txn` is the SSI abort
    ///   victim — it is rolled back and its client should retry. **An aborted pivot never joins a
    ///   batch** (it appended no `COMMIT` record), so the caller answers it the error immediately.
    /// - A storage error if the store PREPARE fails.
    pub fn commit_prepare(&mut self, txn: TxnId) -> Result<(Timestamp, Option<Lsn>)> {
        let isolation = self.active.get(&txn).map(|a| a.isolation).ok_or_else(|| {
            GraphusError::Transaction(format!("commit of inactive txn {}", txn.0))
        })?;

        // 1) SSI validation (SERIALIZABLE only): abort a pivot on a dangerous structure (`04 §5.4`) —
        //    identical to `commit`. An aborted pivot never reaches the WAL PREPARE below.
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
                self.abort(victim)?;
            }
        }

        // 2) Store PREPARE: assign the commit timestamp, publish the outcome and append the `COMMIT`
        //    record WITHOUT hardening (`rmp` #528). The store is the timestamp oracle.
        let commit_lsn = self.store.borrow_mut().commit_prepare(txn)?;
        let commit_ts = self.store.borrow().snapshot_ts();

        // 3) Publish the outcome — byte-identical to `commit` (the WAL harden is the only deferred step).
        self.index
            .borrow_mut()
            .commit_ft_spatial_marker(txn, commit_ts);
        // LOAD-BEARING for the pipelined group commit (`rmp` #583, F1b): `record_commit` publishes the
        // committer's timestamp into the SSI tracker HERE, at PREPARE time — *before* the WAL harden, and
        // before `pipelined_group_commit` may drain an off-thread reader's retirement between two hardened
        // batches. That retirement folds the reader's SIREAD markers and runs `detect_pivot_abort`; because
        // a prepared-but-unhardened writer is already recorded committed (and removed from `active` below),
        // the reader's rw-edge to it fires the eager committed-pivot break and correctly dooms the read-only
        // reader on a dangerous structure. If this `record_commit` were ever deferred to harden/complete
        // time (leaving prepared writers "active" in SSI), that mid-pipeline merge could MISS the structure
        // — so this ordering must not move.
        self.ssi.borrow_mut().record_commit(txn, commit_ts);
        self.locks.borrow_mut().release_all(txn);
        self.index.borrow_mut().forget_dirty_bitmap_nodes(txn);
        self.active.remove(&txn);
        Ok((commit_ts, commit_lsn))
    }

    /// Group-commit **HARDEN** (phase 2, `04 §4.2` / `rmp` #528): `fdatasync`s the WAL, making every
    /// record appended by the [`commit_prepare`](Self::commit_prepare)s since the last harden durable in
    /// ONE sync — the whole batch of concurrent committers. Call after the last PREPARE and **before**
    /// acknowledging any committer (the ack-after-fsync rule). A no-op syscall when nothing is pending
    /// (a batch of only read-only commits).
    ///
    /// # Panics
    /// Panics (controlled abort) if the durability `fdatasync` fails (`04 §4.9`, fsyncgate) — the WHOLE
    /// batch fails together (none of its members are acked), which is correct.
    pub fn harden_wal(&mut self) {
        self.store.borrow_mut().harden_wal();
    }

    /// Group-commit **HARDEN — PREPARE half** of a *pipelined* commit (`rmp` #532): writes every
    /// [`commit_prepare`](Self::commit_prepare)d record to the WAL backing store (advancing its write
    /// frontier) and returns the deferred [`FsyncJob`](graphus_wal::FsyncJob), WITHOUT `fdatasync`ing.
    /// The engine offloads the job to a dedicated fsync thread and overlaps the sync with preparing
    /// the next batch, then calls [`complete_harden_wal`](Self::complete_harden_wal) with the job's
    /// `target_len` once the job has run — the two-phase split of [`harden_wal`](Self::harden_wal).
    ///
    /// The commit is committed-**durable** only after the job runs *and* `complete_harden_wal`
    /// returns, so the caller MUST NOT acknowledge any committer before then (ack-after-fsync). A
    /// crash in the overlap loses the un-synced batch WHOLE (torn-tail recovery truncates), which is
    /// correct precisely because no committer was acked.
    ///
    /// # Panics
    /// Panics (fsyncgate, `04 §4.9`) if writing the records to the backing store fails.
    pub fn begin_harden_wal(&mut self) -> graphus_wal::FsyncJob {
        self.store.borrow_mut().begin_harden_wal()
    }

    /// Group-commit **HARDEN — COMPLETE half** of a pipelined commit (`rmp` #532): advances the WAL
    /// durable watermark to `target_len` (the `FsyncJob::target_len` of the job returned by
    /// [`begin_harden_wal`](Self::begin_harden_wal)) after that job's `fdatasync` has run. Monotonic
    /// (composes with an eviction's inline hardening during the overlap). Call **before** acking any
    /// committer whose record the job covered.
    pub fn complete_harden_wal(&mut self, target_len: u64) {
        self.store.borrow_mut().complete_harden_wal(target_len);
    }

    /// Runs the redo-bounding auto-checkpoint if enough WAL has accumulated (`rmp` storage audit F3),
    /// a no-op otherwise. The engine's group-commit path calls this **once per drained batch**, after
    /// its committers are acknowledged (their commits are already durable via
    /// [`harden_wal`](Self::harden_wal); a checkpoint only bounds later recovery redo).
    ///
    /// # Errors
    /// Returns a storage error if flushing the dirty pages or syncing the device fails.
    pub fn checkpoint_if_due(&mut self) -> Result<()> {
        self.store.borrow_mut().checkpoint_if_due()
    }

    /// The **oldest** read snapshot timestamp among the coordinator's open transactions — the
    /// low-water mark of what any live reader can still observe — or `None` when no transaction is
    /// open (`rmp` #337 Slice 2, the #220 premature-reclamation class).
    ///
    /// Every open transaction (read-only readers **included**: a `MATCH` that never writes still holds
    /// a snapshot at its begin timestamp and can read any version live at that timestamp) contributes
    /// its `snapshot.ts`; the minimum is the oldest version any of them could still need. This is the
    /// **only** safe upper bound for a [`RecordStore::gc`] watermark while readers are open: `gc`
    /// physically frees a slot whose `xmax` committed `<= watermark` and returns it to the free list
    /// for reuse, so a watermark above this low-water would let `gc` reclaim — and a later writer
    /// reuse — a slot that an older still-open reader's snapshot must still see, which is exactly the
    /// freed/reused-slot read (a lost-version / wrong-row ACID violation) the #220 class describes.
    ///
    /// A read-only transaction does not advance the commit timestamp, so under a steady stream of
    /// short readers this tracks the store's high-water; a single long-running reader pins it back to
    /// that reader's begin timestamp, deliberately holding reclamation of everything it might read.
    #[must_use]
    pub fn oldest_active_snapshot(&self) -> Option<Timestamp> {
        self.active.values().map(|a| a.snapshot.ts).min()
    }

    /// The [`TxnId`]s of open transactions whose lifetime (`now_nanos − begin`) is **at least**
    /// `max_age_nanos`, where `now_nanos` and each transaction's begin reading both come from the
    /// engine's **monotonic** clock (`rmp` #395). The result is sorted by id (deterministic). This is
    /// the detection half of the **maximum-transaction-age** guard (`rmp` #477).
    ///
    /// Only transactions opened through [`begin_at`](Self::begin_at) (the server's open path) are
    /// age-tracked; one opened through the clock-agnostic [`begin`](Self::begin) (the TCK / unit tests)
    /// is never reported. `max_age_nanos == 0` **disables** the cap and returns empty.
    ///
    /// ## Why this exists
    ///
    /// A long-running reader — a single sustained `BEGIN`, or one a client keeps *active* by
    /// periodically touching it so the inactivity sweep never fires — pins
    /// [`oldest_active_snapshot`](Self::oldest_active_snapshot), the GC low-water mark, indefinitely. No
    /// dead version committed after its snapshot can then be reclaimed, so the store and RAM grow
    /// without bound with other transactions' write rate (the classic "idle-in-transaction blocks
    /// vacuum" denial of service). The age cap bounds a transaction's *total lifetime*, complementing
    /// the inactivity timeout (which a periodically-touched holder evades).
    ///
    /// The cap is **wall-clock-driven**, hence non-deterministic, so the detection is kept here (pure,
    /// clock-agnostic — the caller supplies `now_nanos`) while only the production engine drives it; the
    /// deterministic `LocalEngine` / DST path never calls it, preserving replay determinism.
    ///
    /// ## Contract for the caller (the engine)
    ///
    /// Aborting a reported transaction is the caller's job and **must** be a clean
    /// [`rollback`](Self::rollback): that removes it from the active set so
    /// [`oldest_active_snapshot`](Self::oldest_active_snapshot) advances and a subsequent
    /// [`gc`](Self::gc) reclaims what it had pinned, while its SSI / lock / store state is discarded
    /// atomically (no partial commit). Its next use then surfaces a clean retriable
    /// [`GraphusError::Transaction`]. The engine additionally excludes auto-commit statements (transient
    /// single-statement units, bounded by the per-statement timeout) and the one statement currently
    /// executing inline, so a reap never races a live read.
    #[must_use]
    pub fn aged_transactions(&self, now_nanos: u64, max_age_nanos: u64) -> Vec<TxnId> {
        if max_age_nanos == 0 {
            return Vec::new();
        }
        let mut aged: Vec<TxnId> = self
            .active
            .iter()
            .filter_map(|(id, a)| {
                let begin = a.begin_nanos?;
                (now_nanos.saturating_sub(begin) >= max_age_nanos).then_some(*id)
            })
            .collect();
        aged.sort_unstable();
        aged
    }

    /// The safe GC watermark **right now**: the oldest open reader's snapshot
    /// ([`oldest_active_snapshot`](Self::oldest_active_snapshot)), or — when no transaction is open —
    /// the store's current snapshot high-water ([`RecordStore::snapshot_ts`]), at which everything
    /// committed is reclaimable because no live reader can observe a reclaimed version (`rmp` #337
    /// Slice 2). This is the watermark every GC invocation path that could run with a live reader MUST
    /// use; [`gc`](Self::gc) computes it for the caller so a future GC trigger (`rmp` #305) cannot
    /// reintroduce the premature-reclamation bug by passing `snapshot_ts()` directly.
    #[must_use]
    pub fn gc_watermark(&self) -> Timestamp {
        self.oldest_active_snapshot()
            .unwrap_or_else(|| self.store.borrow().snapshot_ts())
    }

    /// Runs one MVCC garbage-collection pass over the store at the **reader-safe watermark**
    /// ([`gc_watermark`](Self::gc_watermark)), in its own internal transaction, and returns what it
    /// reclaimed/froze (`rmp` #337 Slice 2, staging for the #305 GC trigger).
    ///
    /// This is the *correct-by-construction* GC entry point: it derives the watermark from the open
    /// reader set rather than trusting the caller, so it physically reclaims **only** versions no
    /// still-open reader can observe (the #220 premature-reclamation guard). There is no production
    /// trigger calling it yet (`rmp` #305 owns scheduling); it stages the accounting so that when a
    /// trigger lands it calls this — never `store.gc(snapshot_ts())` — and the regression scenario in
    /// `graphus-dst` proves the watermark has teeth.
    ///
    /// The GC pass is itself a transaction the coordinator opens and commits here (its frozen headers
    /// become durable on commit, exactly as [`RecordStore::gc`] documents); it does not run SSI
    /// validation (a system maintenance txn touches only reclaimable tombstones, no user predicate).
    /// It must not run while a statement seam holds the store borrow — the same discipline
    /// [`with_store_mut`](Self::with_store_mut) requires.
    ///
    /// # Errors
    /// Propagates a storage error from the GC pass or its commit.
    pub fn gc(&mut self) -> Result<GcPassReport> {
        self.gc_scoped(false)
    }

    /// A **freeze-only** GC pass (`rmp` #590): drives [`RecordStore::gc_freeze_only`] instead of
    /// [`RecordStore::gc`], so it advances the WAL reclaim floor (the incremental freeze sweep) without
    /// paying the `O(store)` reclamation sweeps. Used only by the mid-bulk-load maintenance cadence — see
    /// [`checkpoint_reader_safe_freeze_only`](Self::checkpoint_reader_safe_freeze_only).
    fn gc_scoped(&mut self, freeze_only: bool) -> Result<GcPassReport> {
        let watermark = self.gc_watermark();
        self.next_txn_id += 1;
        let gc_txn = TxnId(self.next_txn_id);
        let mut store = self.store.borrow_mut();
        store.begin(gc_txn);
        let gc_result = if freeze_only {
            store.gc_freeze_only(gc_txn, watermark)
        } else {
            store.gc(gc_txn, watermark)
        };
        let report = match gc_result {
            Ok(report) => report,
            Err(e) => {
                // Best-effort undo of the partial pass so the store stays consistent for the caller.
                let _ = store.rollback(gc_txn);
                return Err(e);
            }
        };
        store.commit(gc_txn)?;
        Ok(report)
    }

    /// Drives a full **maintenance checkpoint** (`rmp` #305): a reader-safe GC pass followed by a
    /// sharp store checkpoint, so storage actually reclaims RAM (the in-memory WAL tail), disk (the
    /// sealed WAL segments below the floor), and version slots — the three resource leaks that had no
    /// production trigger (`rmp` #305 / #313 / #315).
    ///
    /// The order is load-bearing:
    ///
    /// 1. **[`gc`](Self::gc)** reclaims dead versions *and* runs the freeze sweep that settles each
    ///    committed in-flight MVCC stamp to its durable `Committed(ts)` form. Freezing is what lets
    ///    [`RecordStore`] drop a writer from its `unfrozen_commit_lsn` map — i.e. it **lowers the WAL
    ///    reclaim floor**. Without this pass first, the floor stays pinned at the oldest unfrozen
    ///    commit record and a checkpoint can free almost nothing.
    /// 2. **[`RecordStore::checkpoint`]** then flushes every dirty page home (enforcing WAL-before-data
    ///    per page), writes the clean checkpoint marker, and physically reclaims the WAL prefix below
    ///    the now-lowered floor.
    /// 3. **[`SsiTracker::prune_committed`]** finally reclaims the in-memory SSI conflict records of
    ///    committed transactions no live transaction can still conflict with (`rmp` #552). The server
    ///    engine drives every transaction through this coordinator, whose `SsiTracker` was otherwise
    ///    never pruned (its only prior caller was `TxnManager::prune`, which the server never uses), so
    ///    every committed write **and** every committed auto-commit read (`rmp` #545) accumulated a
    ///    permanent `txns`/reverse-index entry — an unbounded RAM leak and an O(N)-per-commit
    ///    `detect_pivot_abort` scan. Pruning here bounds the tracker to live-plus-recently-committed on
    ///    the same maintenance cadence as every other reclaimed resource.
    ///
    /// Durability is preserved throughout: the GC pass commits its frozen headers before the
    /// checkpoint reads the floor, the checkpoint flush makes everything prior durable on its data
    /// page before the WAL prefix is freed, and the reclaim floor still clamps to the oldest active
    /// transaction's first record (loser undo) and the oldest unfrozen commit record — so ARIES
    /// recovery over the reclaimed log is unaffected. Must run between commands on the engine thread,
    /// never while a statement seam holds the store borrow (same discipline as
    /// [`with_store_mut`](Self::with_store_mut)).
    ///
    /// # Errors
    /// Propagates a storage error from the GC pass, its commit, or the checkpoint flush/reclaim.
    /// **`rmp` #588 (sprint-52 B1).** Brackets a maintenance GC pass with the reuse barrier so the
    /// slots it frees are shadow-held from physical reuse while an off-thread reader that predates the
    /// pass may still be walking a chain through them. The engine passes `Some(next_ticket)` around a
    /// [`checkpoint`](Self::checkpoint) and `None` after; forwards to
    /// [`RecordStore::set_reuse_barrier`]. See [`release_reusable_slots`](Self::release_reusable_slots).
    pub fn set_reuse_barrier(&self, barrier: Option<u64>) {
        self.store.borrow_mut().set_reuse_barrier(barrier);
    }

    /// **`rmp` #588.** Lifts the reuse hold on every GC-freed slot whose barrier the oldest open
    /// transaction's ticket has now reached (`barrier <= oldest_open_ticket`); `u64::MAX` (no open
    /// transaction) releases everything. The engine calls this after each maintenance pass and as
    /// readers retire, so a freed slot becomes reusable exactly when no predating reader remains — no
    /// space leak, no premature reuse. Forwards to [`RecordStore::release_held`].
    pub fn release_reusable_slots(&self, oldest_open_ticket: u64) {
        self.store.borrow_mut().release_held(oldest_open_ticket);
    }

    /// **`rmp` #588** (observability): physical slots currently shadow-held from reuse (see
    /// [`RecordStore::held_slots_len`]).
    #[must_use]
    pub fn held_slots_len(&self) -> usize {
        self.store.borrow().held_slots_len()
    }

    /// **`rmp` #588 (sprint-52 B1).** A [`checkpoint`](Self::checkpoint) whose GC reclaim is **reader-
    /// safe**: it brackets the pass with the reuse barrier so a freed physical slot is shadow-held from
    /// reuse until every transaction that predates the free has retired, then lifts the hold for every
    /// slot the oldest open transaction's ticket has passed. `reuse_barrier` is `Some(next_ticket + 1)`
    /// **only when an off-thread reader is in flight** — `next_ticket` equals the newest open
    /// transaction's own ticket (`open_tx` issues it post-increment), so `+ 1` makes the barrier
    /// strictly exceed every open ticket, and [`release_held`](graphus_storage::RecordStore::release_held)
    /// (which releases a slot once `oldest_open_ticket >= barrier`) then keeps a slot held while the
    /// newest reader is still the oldest open. `None` when no off-thread reader is in flight (the
    /// inline/DST path and the no-reader fast path): freed slots are immediately reusable and
    /// `held_slots` stays empty, preserving DST determinism. `oldest_open_ticket` is the oldest open
    /// transaction's ticket (`u64::MAX` when none is open). Every production GC reclaim trigger that can
    /// run concurrently with an off-thread reader (`rmp` #336) MUST use this, never bare
    /// [`checkpoint`](Self::checkpoint).
    pub fn checkpoint_reader_safe(
        &mut self,
        reuse_barrier: Option<u64>,
        oldest_open_ticket: u64,
    ) -> Result<GcPassReport> {
        self.checkpoint_reader_safe_scoped(reuse_barrier, oldest_open_ticket, false)
    }

    /// **`rmp` #590.** The freeze-only counterpart of
    /// [`checkpoint_reader_safe`](Self::checkpoint_reader_safe): it drives a freeze-only GC pass
    /// ([`gc_scoped`](Self::gc_scoped)`(true)`) — advancing the WAL reclaim floor via the incremental
    /// freeze sweep — and then the same sharp store checkpoint, but **skips** the `O(store)` reclamation
    /// sweeps. This is what lets the engine tighten the mid-bulk-load maintenance cadence (bounding the
    /// retained WAL so a crash/`STOP` **before** `?end=true` cannot leave a multi-GB un-reclaimed WAL for
    /// the next `START DATABASE` to materialise into its recovery heap) **without** reintroducing the
    /// `O(N²)` mid-load maintenance cost the property sweep would otherwise incur every pass (the Mode A
    /// checkpoint sentinel tombstones a property version per batch). The (few) dead property versions the
    /// load leaves behind are reclaimed by the ordinary full cadence after the next `START DATABASE`, or by
    /// the FULL end-of-load checkpoint (`rmp` #579) at a clean `End`. Same reader-safe barrier discipline
    /// as [`checkpoint_reader_safe`](Self::checkpoint_reader_safe) (a no-op in practice, since a freeze-only
    /// pass frees no slots).
    pub fn checkpoint_reader_safe_freeze_only(
        &mut self,
        reuse_barrier: Option<u64>,
        oldest_open_ticket: u64,
    ) -> Result<GcPassReport> {
        self.checkpoint_reader_safe_scoped(reuse_barrier, oldest_open_ticket, true)
    }

    fn checkpoint_reader_safe_scoped(
        &mut self,
        reuse_barrier: Option<u64>,
        oldest_open_ticket: u64,
        freeze_only: bool,
    ) -> Result<GcPassReport> {
        self.set_reuse_barrier(reuse_barrier);
        let outcome = self.checkpoint_scoped(freeze_only);
        // Clear the barrier BEFORE releasing so a subsequent non-GC free is not held, then lift the hold
        // on every slot whose predating readers have all retired. Both run on every path (Ok or Err).
        self.set_reuse_barrier(None);
        self.release_reusable_slots(oldest_open_ticket);
        outcome
    }

    pub fn checkpoint(&mut self) -> Result<GcPassReport> {
        self.checkpoint_scoped(false)
    }

    /// Shared body of [`checkpoint`](Self::checkpoint) (`freeze_only == false`) and the freeze-only
    /// maintenance path (`rmp` #590): a GC pass (full or freeze-only per `freeze_only`), then the sharp
    /// store checkpoint that reclaims the WAL prefix below the now-lowered floor, then the SSI-tracker
    /// prune.
    fn checkpoint_scoped(&mut self, freeze_only: bool) -> Result<GcPassReport> {
        let report = self.gc_scoped(freeze_only)?;
        self.store.borrow_mut().checkpoint()?;

        // Reclaim the SSI tracker's retained committed records (`rmp` #552). The watermark is the
        // oldest active read snapshot — the oldest *begin* timestamp among open transactions, or `None`
        // when none are open — which is precisely `SsiTracker::prune_committed`'s `low_water` contract
        // (identical to the one `TxnManager::run_gc` passes). A committed transaction whose commit is
        // `<= low_water` committed before every open transaction began, so it is concurrent with no live
        // transaction: `are_concurrent` gates every rw-edge on concurrency, so no live transaction holds
        // (or can newly form) an edge to or from it, and forgetting it can never hide a dangerous
        // structure `detect_pivot_abort` would catch (the documented no-false-negative retention rule,
        // the same PostgreSQL applies to its committed-SSI summary). `gc()` above opens its maintenance
        // transaction on the *store* only (never `self.active`/`self.ssi`), so it does not perturb this
        // watermark. Serializability for live transactions is untouched: only committed records strictly
        // below the live low-water are forgotten.
        let low_water = self.oldest_active_snapshot();
        self.ssi.borrow_mut().prune_committed(low_water);

        Ok(report)
    }

    /// The current durable WAL length in bytes (the group-commit watermark). The engine's background
    /// maintenance cadence (`rmp` #305) reads this to decide when enough WAL has accumulated since the
    /// last maintenance [`checkpoint`](Self::checkpoint) to drive another one — bounding the resource
    /// drift (RAM/disk/version slots) between operator-triggered checkpoints.
    #[must_use]
    pub fn wal_durable_len(&self) -> u64 {
        self.store.borrow().with_wal(|w| w.durable_len())
    }

    /// The live store size in bytes (mapped durable device pages × [`graphus_io::PAGE_SIZE`]).
    ///
    /// The engine's adaptive maintenance cadence (`rmp` #556) reads this alongside
    /// [`wal_durable_len`](Self::wal_durable_len) to size the WAL reclaim interval proportionally to the
    /// store, so a small OLTP store is not left with a WAL tens of times its size. Backed by the cheap,
    /// non-allocating [`RecordStore::store_page_count`], so it is safe to call on every mutating command.
    #[must_use]
    pub fn store_byte_len(&self) -> u64 {
        self.store
            .borrow()
            .store_page_count()
            .saturating_mul(graphus_io::PAGE_SIZE as u64)
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

    /// Test-only witness that the SSI engine still tracks `txn` (a live conflict record / dangling
    /// rw-edge). Used by the `rmp` #415 regression to assert that an abort whose durable store undo
    /// failed/panicked nonetheless freed the transaction's SSI footprint.
    #[cfg(test)]
    #[must_use]
    pub(crate) fn ssi_tracks(&self, txn: TxnId) -> bool {
        self.ssi.borrow().tracks(txn)
    }

    /// The SSI tracker's retained-conflict-record count — the size of its `txns` table, the single
    /// unbounded-growth vector the tracker exposes (`rmp` #552 / #591 D-#1). It is the direct witness that
    /// [`checkpoint`](Self::checkpoint)'s `prune_committed` shrank the tracker after a burst of committed
    /// transactions and auto-commit reads, and the value the engine publishes as the
    /// `graphus_ssi_tracked_transactions` observability gauge so an operator can alert on a long-lived
    /// active reader pinning the GC watermark (retention is REQUIRED for serializability — this surfaces
    /// the growth, it does not change it). An O(1) map length read.
    #[must_use]
    pub fn ssi_tracked_len(&self) -> usize {
        self.ssi.borrow().tracked_len()
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

    /// Installs the shared **drain-progress beacon** into the underlying store (`rmp` #563). The engine
    /// calls this once at startup with the same [`AtomicU64`](std::sync::atomic::AtomicU64) it exposes on
    /// its handle, so the store's long GC/flush loops heartbeat it and the server's `stop_engine` can
    /// distinguish a slow-but-progressing drain from a wedged one.
    pub fn set_drain_progress(&self, beacon: std::sync::Arc<std::sync::atomic::AtomicU64>) {
        self.store.borrow_mut().set_drain_progress(beacon);
    }

    /// Runs `f` with **mutable** access to the underlying store, without consuming the coordinator.
    ///
    /// This is the lending counterpart to [`into_store`](Self::into_store): it gives storage-level
    /// maintenance that needs `&mut RecordStore` (a backup capture, an explicit checkpoint) a way to
    /// run *between* commands on the single engine thread and leave the coordinator usable afterwards.
    /// The store is borrowed for exactly the duration of `f`; do not call back into the coordinator
    /// from within `f` (it would re-borrow the same `RefCell`).
    ///
    /// # Panics
    /// Panics if the store is already borrowed (a live statement seam from
    /// [`statement`](Self::statement) is held, or `f` re-enters the coordinator) — the same misuse
    /// [`into_store`](Self::into_store) rejects.
    pub fn with_store_mut<R>(&self, f: impl FnOnce(&mut RecordStore<D, S>) -> R) -> R {
        let mut store = self.store.borrow_mut();
        f(&mut store)
    }

    /// Mints one fresh, coordinator-issued [`TxnId`] from [`Self::next_txn_id`](Self#structfield.next_txn_id)
    /// and hands `f` mutable store access under it — **without** registering the id in
    /// [`active`](Self#structfield.active), the SSI tracker, or the lock table (`rmp` #519, network
    /// bulk-import Mode A).
    ///
    /// This is the raw, transaction-agnostic sibling of [`with_store_mut`](Self::with_store_mut) (used
    /// by backup/checkpoint, which need no transaction at all): it exists for a caller that must issue
    /// its own low-level `RecordStore::begin`/`create_node`/.../`commit` sequence — exactly what
    /// `graphus_bulk`'s free ingestion functions (`ingest_node_row`/`ingest_rel_row`) do — while
    /// guaranteeing the id can never collide with one this coordinator already issued or will issue
    /// later, on this same store, via its ordinary `begin`/`begin_serializable`/etc. methods. Unlike
    /// those methods this performs **no** SSI/lock/`record_graph` bookkeeping: the caller is fully
    /// responsible for `store.begin(txn)`/`store.commit(txn)`/`store.rollback(txn)` and for ensuring no
    /// concurrent access requires conflict detection over this write (true by construction for Mode A:
    /// the target database is `Loading`, exclusive to this session, `08 §5.2`).
    ///
    /// Because the id still comes from the coordinator's own WAL-seeded counter
    /// ([`new`](Self::new) reseeds it past [`RecordStore::recovered_txn_hw`] on every open), a
    /// transaction begun+committed through this seam recovers identically to an ordinary
    /// coordinator-driven one — `graphus_wal`/`graphus_storage::recovery` redo/undo keys off each WAL
    /// record's own `TxnId` tag, never coordinator in-memory state.
    ///
    /// The store is borrowed for exactly the duration of `f`; do not call back into the coordinator
    /// from within `f` (the same `RefCell` re-entrancy hazard [`with_store_mut`](Self::with_store_mut)
    /// documents).
    ///
    /// # Panics
    /// Panics if the store is already borrowed (a live statement seam, or `f` re-enters the
    /// coordinator).
    pub fn raw_txn<R>(&mut self, f: impl FnOnce(TxnId, &mut RecordStore<D, S>) -> R) -> R {
        self.next_txn_id += 1;
        let txn = TxnId(self.next_txn_id);
        let mut store = self.store.borrow_mut();
        f(txn, &mut store)
    }

    /// Aborts `txn`: store undo, SSI forget, lock release, and removal from the open set.
    ///
    /// # Why the in-memory cleanup is unconditional (`rmp` #415)
    ///
    /// The durable store undo (`RecordStore::rollback`) is **fallible** and may even **panic** — the
    /// documented `rmp` #359 buffer-pool/`RefCell`-replay class, which `rmp` #409's `catch_recovery`
    /// now catches *and keeps the engine alive*. If we ran the undo first and bailed on its `Err`/unwind
    /// (the historical ordering), the three pure in-memory cleanups would be skipped and the
    /// transaction would **leak**: it would stay in [`active`](Self#structfield.active) forever, pinning
    /// `oldest_active_snapshot`, freezing the GC watermark (unbounded version accumulation → slow OOM),
    /// keeping its SSI rw-edges (false-aborting innocent transactions) and holding its locks.
    ///
    /// So the in-memory SSI / lock / active-set state is freed **unconditionally**, whether or not the
    /// durable undo succeeds, returns `Err`, or panics. This is sound: a half-undone *durable* state is
    /// the store's concern and is reconciled by ARIES recovery on the next open; the in-memory
    /// bookkeeping carries no durability obligation and must never leak. A [`Cleanup`] drop guard runs
    /// the cleanup on every exit path (normal return, `?` early-return, or unwind). The cleanup borrows
    /// only `ssi` / `locks` (distinct `RefCell`s from `store`) and `active` (no `RefCell`), so it never
    /// conflicts with the store borrow even when that borrow is being torn down by an unwind. Each step
    /// is idempotent (`forget` / `release_all` / `HashMap::remove` are no-ops for an absent txn), so a
    /// double abort cannot double-free.
    ///
    /// # Bitmap index repair (`rmp` #453, F-IDX-3)
    ///
    /// The eagerly-maintained in-memory bitmap index (`rmp` #328) reflects this transaction's
    /// uncommitted writes (a `SET n.active = false` moved `n`'s bit), so the store undo above leaves it
    /// out of sync — and because the bitmap is a *membership-exact candidate source*, a missing entry
    /// cannot be resurrected by the query-time re-check. So this txn's bitmap-dirtied node set is
    /// **drained up front** (freeing the bookkeeping unconditionally, exactly like the leak-safety of
    /// the SSI/lock state) and, *only if the durable undo succeeded*, each dirtied node is re-derived
    /// from the now-reverted store. If the undo failed/panicked the store is not cleanly reverted, so
    /// re-derivation is skipped: the bitmap may be momentarily stale, but it is in-memory, has no
    /// planner consumer yet, and is fully resynced by the next open-time rebuild — never a durability or
    /// committed-data concern.
    fn abort(&mut self, txn: TxnId) -> Result<()> {
        /// Drop guard that frees the pure in-memory transaction state. Runs on normal return **and** on
        /// unwind, so a panicking store undo can never leak the SSI markers, locks, or `active` entry.
        struct Cleanup<'a> {
            ssi: &'a RefCell<SsiTracker>,
            locks: &'a RefCell<LockTable>,
            index: &'a RefCell<IndexSet>,
            active: &'a mut HashMap<TxnId, ActiveTxn>,
            txn: TxnId,
        }
        impl Drop for Cleanup<'_> {
            fn drop(&mut self) {
                // All four are idempotent no-ops for an already-removed/non-mutator txn, so this is safe
                // even if the txn was somehow torn down concurrently / twice.
                self.ssi.borrow_mut().forget(self.txn);
                self.locks.borrow_mut().release_all(self.txn);
                // Cross-snapshot freshness marker (`rmp` task #467): retire `txn` as a ROLLED-BACK
                // full-text/spatial mutator. The store undo above (or below) does NOT roll back the
                // in-memory inverted index / grid, so a rolled-back replace/delete may leave a still-
                // committed node dropped from a posting it should occupy — a false negative the query-
                // time re-check cannot resurrect. `rollback_ft_spatial_marker` therefore pins the
                // effective marker at `u64::MAX` (every reader uses the always-correct scan path) until
                // a full store-consistent rebuild repairs the index. A no-op if `txn` was not a mutator,
                // so the common (non-full-text/spatial) rollback leaves the fast path untouched.
                self.index.borrow_mut().rollback_ft_spatial_marker(self.txn);
                self.active.remove(&self.txn);
            }
        }

        // Drain this txn's bitmap-dirtied node set BEFORE the undo (`rmp` #453, F-IDX-3): this frees the
        // per-txn bookkeeping unconditionally — like the SSI/lock leak-safety — so even a panicking undo
        // cannot leak it. The set is complete (statement maintenance has finished by abort time) and the
        // undo never grows it, so draining now loses nothing. Re-derivation runs AFTER a successful undo.
        let dirty_bitmap_nodes = self.index.borrow_mut().take_dirty_bitmap_nodes(txn);

        let cleanup = Cleanup {
            ssi: &self.ssi, // `&Rc<RefCell<_>>` coerces to `&RefCell<_>` via deref.
            locks: &self.locks,
            index: &self.index,
            active: &mut self.active,
            txn,
        };
        // The durable undo runs while the guard is armed. Its borrow of `self.store` is a *different*
        // `RefCell` from the guard's `ssi`/`locks`, so an `Err` (early `?` return) or a panic both leave
        // the guard free to run its cleanup on scope exit / unwind without a borrow conflict.
        let undo = self.store.borrow_mut().rollback(txn);
        drop(cleanup); // Free the in-memory state now; on `Err`/panic above this same drop runs anyway.

        // Re-derive each bitmap-dirtied node from the now-reverted store, but ONLY if the undo
        // succeeded (a failed/panicked undo leaves the store half-reverted, so a re-derive could read
        // inconsistent state — skip it; the bitmap resyncs on the next rebuild). A node's pre-image
        // value is back in the store, so this restores the bitmap to its committed membership. No-op
        // unless a bitmap index is declared (`dirty_bitmap_nodes` is then empty).
        if undo.is_ok() {
            for node in dirty_bitmap_nodes {
                self.rederive_node_bitmap(node);
            }
        }
        undo
    }

    /// Re-derives node `id`'s bitmap membership from the **current** store state across every registered
    /// bitmap column (`rmp` #453, F-IDX-3): removes the node from every value-bitmap, then re-inserts it
    /// under its current store value for each covered column it still carries (via
    /// [`index_one_node_bitmap`](Self::index_one_node_bitmap), which only inserts). Used by abort to
    /// undo a rolled-back change's effect on the in-memory bitmap. Store and index are borrowed in
    /// separate, non-overlapping scopes (the file's borrow discipline). A no-op if no bitmap is declared.
    fn rederive_node_bitmap(&self, id: u64) {
        let registered = self.index.borrow().registered_bitmap();
        if registered.is_empty() {
            return;
        }
        // Clear the node from every value-bitmap first (drop the rolled-back value's bit), then
        // re-insert under the reverted store value for each column it still matches.
        self.index.borrow_mut().remove_node_from_all_bitmaps(id);
        // This is an ABORT path, not a build: it borrows `index_one_node_bitmap`, which reports an
        // unreadable node by raising the shared `rebuild_gap` flag (`rmp` task #733). Leaving that flag
        // set here would be a landmine — the next build to read it would poison itself over a fault that
        // had nothing to do with it. So the gap is consumed HERE, where it means something specific: the
        // node could not be re-derived, so the bitmap (a **membership-exact** candidate source, whose
        // holes a seek can never resurrect) no longer faithfully describes this column. Unregister the
        // affected columns — their consumers gate on registration — so every seek falls back to the exact
        // scan, and the next successful rebuild re-captures them.
        self.index.borrow_mut().clear_rebuild_gap();
        Self::index_one_node_bitmap(&self.store, &self.index, id, &registered);
        if self.index.borrow().rebuild_gap() {
            let mut index = self.index.borrow_mut();
            index.clear_rebuild_gap();
            for (label_token, prop_key) in registered {
                // RETIRE, keeping the declaration: the column stops answering seeks now, and the next
                // successful rebuild re-registers and repopulates it (`rmp` task #733, M2).
                index.disable_bitmap(label_token, prop_key);
            }
        }
    }
}

/// The coordinator-level [`Statistics`] seam (`rmp` task #82): exact catalogue counts and
/// per-indexed-property histograms over the coordinator's shared store, consumed by
/// [`plan_physical_with_stats`](crate::physical::plan_physical_with_stats) at compile time.
///
/// # What is reported (snapshot semantics)
///
/// Each call reads the store's **current committed catalogue**: the durable grand-total and
/// per-label / per-relationship-type counts (`rmp` task #79) and the durable equi-depth property
/// histograms (`rmp` task #81). The planner treats the values as a consistent-enough snapshot for
/// one compilation; the counts are advisory cost inputs, so a materially-stale histogram (or a count
/// racing a concurrent commit) only **mis-costs** a plan — it never affects correctness, because
/// every cost-based rewrite is bag-preserving (`rmp` task #65). This deliberately mirrors the
/// catalogue-count semantics of [`RecordStoreGraph`]'s own [`Statistics`] impl: cost estimation
/// wants the aggregate shape of the data, not one transaction's MVCC view.
///
/// # Borrow discipline (why this is safe on the single engine thread)
///
/// The seam holds an `Rc` clone of the coordinator's shared store and borrows it **briefly, per
/// method call** — never across calls, and any decoded histogram is owned before the borrow is
/// released. The other holders of this `Rc` ([`TxnCoordinator`] itself and every
/// [`RecordStoreGraph`] statement seam) likewise borrow only for the duration of one call, so a
/// `CoordinatorStatistics` may be held across an entire compilation — including while a transaction
/// is open and while a statement seam exists — without ever overlapping a live borrow: the planner
/// is pure and never re-enters the store while one of these calls is borrowing it.
///
/// # Error policy
///
/// This seam has **no error-capture channel** (compilation must not fail over an advisory
/// statistic), so a corrupt stored histogram degrades to the `None` "fall back" sentinel — the
/// estimator then uses its documented constants — instead of being surfaced. The per-statement
/// [`RecordStoreGraph`] seam, which *does* have a channel, captures the same error; both read
/// through the shared (crate-private) `store_statistics` helpers so the lookup semantics cannot
/// drift.
pub struct CoordinatorStatistics<D: BlockDevice, S: LogSink> {
    /// A clone of the coordinator's shared store handle (see the borrow-discipline doc above).
    store: Rc<RefCell<RecordStore<D, S>>>,
}

impl<D: BlockDevice, S: LogSink> CoordinatorStatistics<D, S> {
    /// Decodes the durable histogram for `(label, property)` via the shared reader, applying this
    /// seam's error policy: a corrupt histogram is reported as `None` (the estimator's constant
    /// fallback) because compile-time statistics are advisory and have no error channel — never a
    /// panic, never a failed compilation.
    fn decode_histogram(&self, label: &str, property: &str) -> Option<PropertyHistogram> {
        store_statistics::decode_histogram(&self.store.borrow(), label, property)
            .ok()
            .flatten()
    }
}

impl<D: BlockDevice, S: LogSink> Statistics for CoordinatorStatistics<D, S> {
    fn total_nodes(&self) -> u64 {
        self.store.borrow().total_node_count()
    }

    fn nodes_with_label(&self, label: &str) -> Option<u64> {
        // Exact per-label catalogue counts (`rmp` task #79): a never-interned label is an exact
        // `Some(0)`, never the `None` "unknown" sentinel.
        Some(store_statistics::nodes_with_label(
            &self.store.borrow(),
            label,
        ))
    }

    fn total_relationships(&self) -> u64 {
        self.store.borrow().total_relationship_count()
    }

    fn relationships_with_type(&self, rel_type: &str) -> Option<u64> {
        // Exact per-relationship-type catalogue counts; a never-interned type is an exact 0.
        Some(store_statistics::relationships_with_type(
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
        // No histogram (or a corrupt one, per this seam's error policy) -> None (fall back); an
        // unindexable query value (Null/List/Map) likewise -> None (`store_statistics` docs).
        let hist = self.decode_histogram(label, property)?;
        store_statistics::histogram_estimate_eq(&hist, value)
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
        // A *present* but unindexable bound -> None (fall back) rather than silently dropping the
        // bound; an absent bound is open on that side (`store_statistics::histogram_estimate_range`).
        let hist = self.decode_histogram(label, property)?;
        store_statistics::histogram_estimate_range(&hist, lo, lo_inclusive, hi, hi_inclusive)
    }

    fn distinct_label_property_values(&self, label: &str, property: &str) -> Option<u64> {
        Some(self.decode_histogram(label, property)?.distinct())
    }
}

#[cfg(test)]
mod abort_failure_tests {
    //! `rmp` #415 regression: an abort whose **durable store undo fails or panics** must still free
    //! the transaction's pure in-memory state (SSI markers, write locks, the `active` entry), so it
    //! can never leak — pinning `oldest_active_snapshot`, freezing the GC watermark into unbounded
    //! version accumulation (slow OOM behind the `rmp` #409 503), or false-aborting innocent
    //! transactions with stale rw-edges.

    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

    use graphus_core::{GraphusError, Result, TxnId};
    use graphus_wal::{LogSink, MemLogSink, WalManager};

    use crate::binding::{Parameters, bind_parameters};
    use crate::catalog::IndexCatalog;
    use crate::coordinator::TxnCoordinator;
    use crate::executor::execute;
    use crate::lexer::tokenize;
    use crate::lower::lower;
    use crate::parser::parse_tokens;
    use crate::physical::{PhysicalPlan, plan_physical};
    use crate::semantics::analyze;
    use graphus_io::MemBlockDevice;
    use graphus_storage::RecordStore;

    /// A [`LogSink`] wrapping [`MemLogSink`] whose `sync()` returns `Err` once a shared flag is armed.
    /// Because [`WalManager::harden`] treats an fsync failure as unrecoverable and **panics**
    /// (fsyncgate, `§4.9`), arming this flag turns the next `RecordStore::rollback` into the documented
    /// panic-during-undo class (`rmp` #359 / #409) — exactly the path under test. The flag is shared via
    /// `Arc<AtomicBool>` (the sink must be `Send + Sync` for the off-thread read bounds) so the test
    /// keeps a handle to arm it *after* the transaction has written, while the sink itself lives inside
    /// the coordinator's store.
    struct FaultSink {
        inner: MemLogSink,
        fail_sync: Arc<AtomicBool>,
    }

    impl LogSink for FaultSink {
        fn append(&mut self, bytes: &[u8]) {
            self.inner.append(bytes);
        }
        fn sync(&mut self) -> Result<()> {
            if self.fail_sync.load(Ordering::SeqCst) {
                return Err(GraphusError::Storage(
                    "injected rollback fdatasync failure (rmp #415)".to_owned(),
                ));
            }
            self.inner.sync()
        }
        fn begin_harden(&mut self) -> Result<graphus_wal::FsyncJob> {
            // Forward to the inner sink (mirroring `read_bounded`/`reclaimed_floor`), so `FaultSink`
            // stays a faithful `LogSink` wrapper under the pipelined-harden path (`rmp` #532). The
            // rollback fsync-failure fault this double injects fires on the inline `sync`/harden path
            // these tests drive (`RecordStore::rollback` → `WalManager::rollback` → `harden` → `sync`),
            // which is unchanged; `MemLogSink`'s default `begin_harden` hardens inline.
            self.inner.begin_harden()
        }
        fn complete_harden(&mut self, target_len: u64) {
            self.inner.complete_harden(target_len);
        }
        fn durable_len(&self) -> u64 {
            self.inner.durable_len()
        }
        fn buffered_len(&self) -> u64 {
            self.inner.buffered_len()
        }
        fn read_durable(&self, from: u64, into: &mut Vec<u8>) -> Result<()> {
            self.inner.read_durable(from, into)
        }
        fn read_bounded(&self, from: u64, to: u64, into: &mut Vec<u8>) -> Result<()> {
            self.inner.read_bounded(from, to, into)
        }
        fn reclaim(&mut self, from: u64, up_to: u64) -> Result<()> {
            self.inner.reclaim(from, up_to)
        }
        fn reclaimed_floor(&self) -> u64 {
            self.inner.reclaimed_floor()
        }
    }

    type Coord = TxnCoordinator<MemBlockDevice, FaultSink>;

    fn fresh_coord(fail_sync: Arc<AtomicBool>) -> Coord {
        let device = MemBlockDevice::new(0);
        let sink = FaultSink {
            inner: MemLogSink::new(),
            fail_sync,
        };
        let wal = WalManager::create(sink).expect("create wal");
        let store: RecordStore<MemBlockDevice, FaultSink> =
            RecordStore::create(device, wal, 64, 1).expect("create store");
        TxnCoordinator::new(store)
    }

    fn compile(src: &str) -> PhysicalPlan {
        let toks = tokenize(src).expect("lex");
        let ast = parse_tokens(&toks, src).expect("parse");
        let validated = analyze(&ast).expect("analyze");
        plan_physical(&lower(&validated), &IndexCatalog::empty())
    }

    /// Runs one statement under `txn`, asserting it captured no error.
    fn run_stmt(coord: &Coord, txn: TxnId, src: &str) {
        let plan = compile(src);
        let bound = bind_parameters(&plan, &Parameters::new()).expect("bind");
        let mut graph = coord.statement(txn).expect("statement");
        {
            let mut cursor = execute(&plan, &bound, &mut graph).expect("open cursor");
            cursor.collect_all().expect("collect");
        }
        assert!(graph.take_error().is_none(), "captured error in: {src}");
    }

    /// THE GATE. A transaction that has written (so the store undo has real work and reaches the
    /// panicking `harden`) and built an SSI / lock footprint is aborted with the store undo armed to
    /// **panic**. We assert that the panic propagates (proving the durable undo really failed) yet the
    /// pure in-memory state is freed regardless: the txn is gone from `active`, its SSI footprint is
    /// forgotten, and the GC watermark / oldest-active-snapshot can advance afterward.
    ///
    /// This must FAIL before the `rmp` #415 fix (old ordering ran the fallible undo first and skipped
    /// the three cleanups on its `Err`/unwind) and PASS after (the cleanup runs in a drop guard that
    /// fires on unwind).
    #[test]
    fn abort_failure_does_not_leak_active_txn_or_watermark() {
        let fail_sync = Arc::new(AtomicBool::new(false));
        let mut coord = fresh_coord(Arc::clone(&fail_sync));

        let baseline_active = coord.active_count();
        let baseline_watermark = coord.gc_watermark();

        // Open a SERIALIZABLE txn and give it a real footprint: a committed-then-read register so the
        // txn holds an SSI read marker + a write (the node create) the store must undo.
        let txn = coord.begin_serializable();
        run_stmt(&coord, txn, "CREATE (:Reg {k: 1, v: 0})");
        // A read so the SSI engine records a read marker for this txn (dangling rw-edge candidate).
        run_stmt(&coord, txn, "MATCH (n:Reg {k: 1}) RETURN n.v AS v");

        assert!(
            coord.ssi_tracks(txn),
            "precondition: the open txn must be SSI-tracked before abort"
        );
        assert_eq!(
            coord.active_count(),
            baseline_active + 1,
            "precondition: the open txn must be in the active set"
        );

        // Arm the store undo to PANIC (the `harden` fsyncgate panic), then abort. The panic is the
        // documented `rmp` #359/#409 class that `catch_recovery` catches while keeping the engine alive.
        fail_sync.store(true, Ordering::SeqCst);
        let unwound = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            // `rollback` is the public entry to `abort`; it returns `Err` only for an inactive txn, so
            // for our active txn it runs `abort`, whose store undo we have armed to panic.
            let _ = coord.rollback(txn);
        }));
        assert!(
            unwound.is_err(),
            "the armed durable undo must actually panic (proving the failure path is exercised)"
        );
        // Disarm so the post-abort assertions / drop do not re-trip the fault.
        fail_sync.store(false, Ordering::SeqCst);

        // THE ASSERTIONS: the in-memory state was freed despite the panicking undo.
        assert_eq!(
            coord.active_count(),
            baseline_active,
            "active set must return to baseline — the aborted txn must not leak (rmp #415)"
        );
        assert!(
            !coord.ssi_tracks(txn),
            "SSI footprint must be forgotten — no dangling rw-edge for the aborted txn (rmp #415)"
        );
        assert_eq!(
            coord.oldest_active_snapshot(),
            None,
            "no open reader must remain pinning the snapshot watermark"
        );
        // The GC watermark can advance again (it is no longer pinned by the leaked txn). It is at least
        // the baseline; the committed CREATE before the panic advanced the store's high-water, so it is
        // free to move forward now that no transaction is open.
        assert!(
            coord.gc_watermark() >= baseline_watermark,
            "GC watermark must be free to advance once the aborted txn is gone (rmp #415)"
        );

        // And the coordinator is still usable: a fresh txn begins, writes, commits, aborts cleanly —
        // proving neither a leaked lock nor a stale rw-edge false-aborts an innocent successor.
        let txn2 = coord.begin_serializable();
        run_stmt(&coord, txn2, "CREATE (:Reg {k: 2, v: 0})");
        coord
            .commit(txn2)
            .expect("innocent successor txn must commit");
        assert_eq!(
            coord.active_count(),
            baseline_active,
            "coordinator must be left in a clean state after the failed abort + successful successor"
        );
    }
}

#[cfg(test)]
mod max_transaction_age_tests {
    //! `rmp` #477 regression: the maximum-transaction-age guard. A long-running reader that pins the GC
    //! low-water mark ([`TxnCoordinator::oldest_active_snapshot`]) indefinitely — the classic
    //! "idle-in-transaction blocks vacuum" denial of service — is detected by
    //! [`TxnCoordinator::aged_transactions`] once its lifetime exceeds the cap and reaped by a clean
    //! [`TxnCoordinator::rollback`], so the watermark advances and dead-version retention stops growing.
    //!
    //! The clock is supplied explicitly (no wall clock), so the scenario is fully deterministic.

    use graphus_core::{GraphusError, TxnId};
    use graphus_io::MemBlockDevice;
    use graphus_storage::RecordStore;
    use graphus_txn::IsolationLevel;
    use graphus_wal::{MemLogSink, WalManager};

    use crate::binding::{Parameters, bind_parameters};
    use crate::catalog::IndexCatalog;
    use crate::coordinator::TxnCoordinator;
    use crate::executor::execute;
    use crate::lexer::tokenize;
    use crate::lower::lower;
    use crate::parser::parse_tokens;
    use crate::physical::{PhysicalPlan, plan_physical};
    use crate::semantics::analyze;

    type Coord = TxnCoordinator<MemBlockDevice, MemLogSink>;

    fn fresh_coord() -> Coord {
        let device = MemBlockDevice::new(0);
        let wal = WalManager::create(MemLogSink::new()).expect("create wal");
        let store: RecordStore<MemBlockDevice, MemLogSink> =
            RecordStore::create(device, wal, 256, 1).expect("create store");
        TxnCoordinator::new(store)
    }

    fn compile(src: &str) -> PhysicalPlan {
        let toks = tokenize(src).expect("lex");
        let ast = parse_tokens(&toks, src).expect("parse");
        let validated = analyze(&ast).expect("analyze");
        plan_physical(&lower(&validated), &IndexCatalog::empty())
    }

    /// Runs one statement under `txn`, asserting it captured no error.
    fn run_stmt(coord: &Coord, txn: TxnId, src: &str) {
        let plan = compile(src);
        let bound = bind_parameters(&plan, &Parameters::new()).expect("bind");
        let mut graph = coord.statement(txn).expect("statement");
        {
            let mut cursor = execute(&plan, &bound, &mut graph).expect("open cursor");
            cursor.collect_all().expect("collect");
        }
        assert!(graph.take_error().is_none(), "captured error in: {src}");
    }

    /// Nanoseconds in one millisecond — the cap is expressed in ms in the server config.
    const MS: u64 = 1_000_000;

    /// THE GATE. A long reader opened via `begin_at` pins the watermark while a churn of committed
    /// writers accumulates dead versions GC cannot reclaim. Once the reader's lifetime crosses the cap,
    /// `aged_transactions` reports it (and a younger reader is left alone); reaping it via `rollback`
    /// advances the watermark and a GC pass — which reclaimed **nothing** while pinned — now reclaims
    /// the accumulated garbage. The reaped reader's next use is a clean retriable error.
    #[test]
    fn aged_reader_is_reaped_freeing_the_gc_watermark() {
        let mut coord = fresh_coord();
        // The configured cap (mirrors the server's `max_transaction_age_ms`), in monotonic nanoseconds.
        let max_age_nanos = 60 * 60 * 1000 * MS; // 1 hour

        // Seed exactly one committed node at t = 0, so there is no pre-existing garbage.
        let seed = coord.begin_at(IsolationLevel::Serializable, 0);
        run_stmt(&coord, seed, "CREATE (:Reg {k: 1, v: 0})");
        coord.commit(seed).expect("seed commit");

        // A long-lived reader opens its snapshot near t = 0 and reads the register, taking SSI markers.
        let reader = coord.begin_at(IsolationLevel::Serializable, MS);
        run_stmt(&coord, reader, "MATCH (n:Reg {k: 1}) RETURN n.v AS v");
        let pinned = coord
            .oldest_active_snapshot()
            .expect("the open reader pins the GC low-water mark");

        // Churn the SAME node many times AFTER the reader's snapshot: every overwrite supersedes the
        // prior version, but each dead version committed after the reader began (xmax > the watermark),
        // so GC cannot reclaim any of it while the reader stays open.
        const CHURN: u64 = 25;
        for i in 1..=CHURN {
            let w = coord.begin_at(IsolationLevel::Serializable, MS + i);
            run_stmt(&coord, w, &format!("MATCH (n:Reg {{k: 1}}) SET n.v = {i}"));
            coord.commit(w).expect("churn writer commits cleanly");
        }
        // The reader still pins the watermark, so a GC pass reclaims (essentially) nothing.
        assert_eq!(
            coord.oldest_active_snapshot(),
            Some(pinned),
            "the long reader must still pin the watermark while it is open"
        );
        let reclaimed_pinned = coord.gc().expect("gc pass while pinned").reclaimed;
        assert_eq!(
            reclaimed_pinned, 0,
            "while the reader pins the watermark, no dead version is reclaimable"
        );

        // Now: time has advanced one nanosecond past the cap for the reader (begin = MS), but a younger
        // reader opened just now must NOT be disturbed.
        let now = MS + max_age_nanos + 1;
        let young = coord.begin_at(IsolationLevel::Serializable, now - 1); // age 1ns << cap
        let aged = coord.aged_transactions(now, max_age_nanos);
        assert_eq!(
            aged,
            vec![reader],
            "only the over-age reader is reported — the just-opened reader is left alone"
        );

        // Reap the over-age reader with a clean rollback (the engine's contract).
        coord
            .rollback(reader)
            .expect("clean rollback of the over-age reader");

        // The watermark advanced: the young reader is now the oldest snapshot (the reaped reader is gone
        // from the active set). A GC pass — which reclaimed 0 while pinned — now reclaims the garbage the
        // reader had been holding back, proving retention stops growing.
        assert_ne!(
            coord.oldest_active_snapshot(),
            Some(pinned),
            "reaping the over-age reader must release its hold on the watermark"
        );
        let reclaimed_after = coord.gc().expect("gc pass after reap").reclaimed;
        assert!(
            reclaimed_after > reclaimed_pinned && reclaimed_after > 0,
            "the advanced watermark must unblock reclamation of the pinned garbage: \
             reclaimed {reclaimed_pinned} (pinned) -> {reclaimed_after} (after reap)"
        );

        // The reaped reader's next use surfaces a clean retriable error — it is no longer active.
        // (`statement`'s `Ok` value is not `Debug`, so match rather than `expect_err`.)
        match coord.statement(reader) {
            Ok(_) => panic!("the reaped reader must be inactive — its next statement must error"),
            Err(GraphusError::Transaction(_)) => {}
            Err(other) => panic!(
                "a reaped over-age transaction must surface a retriable Transaction error, got: {other:?}"
            ),
        }
        assert!(
            coord.commit(reader).is_err(),
            "commit of the reaped reader errors"
        );
        assert!(
            coord.rollback(reader).is_err(),
            "rollback of the reaped reader errors (already inactive)"
        );

        // The coordinator is left clean and usable: the young reader still commits.
        coord
            .commit(young)
            .expect("the untouched young reader commits cleanly");
    }

    /// `aged_transactions` is a pure, deterministic detector: a disabled cap (`0`) reports nothing, an
    /// age-untracked transaction (opened via `begin`) is never reported, and the boundary is inclusive.
    #[test]
    fn aged_transactions_detection_rules() {
        let mut coord = fresh_coord();

        // Untracked (opened via the clock-agnostic `begin`): never reported, even far past any cap.
        let untracked = coord.begin(IsolationLevel::Serializable);
        // Tracked, opened at t = 1000ns.
        let tracked = coord.begin_at(IsolationLevel::Serializable, 1_000);

        // Disabled cap (0) reports nothing regardless of age.
        assert!(
            coord.aged_transactions(u64::MAX, 0).is_empty(),
            "cap 0 disables"
        );

        // Just under the cap: nothing.
        assert!(
            coord.aged_transactions(1_000 + 500, 1_000).is_empty(),
            "age 500ns < 1000ns cap — not yet aged"
        );
        // Exactly at the cap: inclusive — the tracked txn is reported, the untracked one never.
        assert_eq!(
            coord.aged_transactions(1_000 + 1_000, 1_000),
            vec![tracked],
            "age == cap is inclusive; the untracked transaction is never reported"
        );
        // `now` before begin (a monotonic clock cannot do this, but saturate rather than wrap): age 0.
        assert!(
            coord.aged_transactions(0, 1_000).is_empty(),
            "saturating age computation never reports a negative age"
        );

        let _ = untracked;
        coord.rollback(tracked).expect("rollback");
    }
}

#[cfg(test)]
mod ssi_prune_tests {
    //! `rmp` #552 regression: the maintenance checkpoint MUST prune the coordinator's `SsiTracker`.
    //!
    //! The server engine drives every transaction through this coordinator, whose `SsiTracker` was
    //! never pruned in production (its only prior caller, `TxnManager::prune`, is unused by the server).
    //! `record_commit` retains a committed transaction's record for later conflict resolution, so every
    //! committed write — and, since `rmp` #545, every committed auto-commit read demoted to Snapshot
    //! Isolation — accumulated a permanent `txns` entry: an unbounded RAM leak and an O(N)-per-commit
    //! `detect_pivot_abort` scan. `TxnCoordinator::checkpoint` now drains it at the reader-safe
    //! `oldest_active_snapshot` watermark. These tests prove the tracker GROWS without a prune and
    //! SHRINKS with one, and that pruning at the live watermark preserves serializability (it retains
    //! every record a live transaction could still conflict with).

    use graphus_core::TxnId;
    use graphus_io::MemBlockDevice;
    use graphus_storage::RecordStore;
    use graphus_wal::{MemLogSink, WalManager};

    use crate::binding::{Parameters, bind_parameters};
    use crate::catalog::IndexCatalog;
    use crate::coordinator::TxnCoordinator;
    use crate::executor::execute;
    use crate::lexer::tokenize;
    use crate::lower::lower;
    use crate::parser::parse_tokens;
    use crate::physical::{PhysicalPlan, plan_physical};
    use crate::semantics::analyze;

    type Coord = TxnCoordinator<MemBlockDevice, MemLogSink>;

    fn fresh_coord() -> Coord {
        let device = MemBlockDevice::new(0);
        let wal = WalManager::create(MemLogSink::new()).expect("create wal");
        let store: RecordStore<MemBlockDevice, MemLogSink> =
            RecordStore::create(device, wal, 256, 1).expect("create store");
        TxnCoordinator::new(store)
    }

    fn compile(src: &str) -> PhysicalPlan {
        let toks = tokenize(src).expect("lex");
        let ast = parse_tokens(&toks, src).expect("parse");
        let validated = analyze(&ast).expect("analyze");
        plan_physical(&lower(&validated), &IndexCatalog::empty())
    }

    /// Runs one statement under `txn`, asserting it captured no error.
    fn run_stmt(coord: &Coord, txn: TxnId, src: &str) {
        let plan = compile(src);
        let bound = bind_parameters(&plan, &Parameters::new()).expect("bind");
        let mut graph = coord.statement(txn).expect("statement");
        {
            let mut cursor = execute(&plan, &bound, &mut graph).expect("open cursor");
            cursor.collect_all().expect("collect");
        }
        assert!(graph.take_error().is_none(), "captured error in: {src}");
    }

    /// THE LEAK GATE. A burst of committed writers AND committed auto-commit reads (SI-demoted, the
    /// `rmp` #545 path) each retains an SSI conflict record; with no transaction open, the maintenance
    /// checkpoint must prune every one of them. Proves the tracker GROWS to `WRITERS + READS` without a
    /// prune and SHRINKS to zero with one.
    ///
    /// Fails before the `rmp` #552 fix (`checkpoint` never pruned the tracker → `after == grown`) and
    /// passes after (`after == 0`).
    #[test]
    fn checkpoint_prunes_accumulated_committed_ssi_records() {
        let mut coord = fresh_coord();
        assert_eq!(
            coord.ssi_tracked_len(),
            0,
            "a fresh coordinator's SSI tracker retains nothing"
        );

        // A burst of committed writers — each `commit` retains its record (`record_commit`).
        const WRITERS: usize = 8;
        for i in 0..WRITERS {
            let w = coord.begin_serializable();
            run_stmt(&coord, w, &format!("CREATE (:N {{id: {i}}})"));
            coord.commit(w).expect("writer commits");
        }

        // A burst of committed auto-commit READS demoted to Snapshot Isolation (`rmp` #545). A clean
        // read is finalized through `commit` → `record_commit`, which retains its record too — the leak
        // this fix closes for the read-heavy workload.
        const READS: usize = 8;
        for _ in 0..READS {
            let r = coord.begin_serializable();
            coord.demote_read_to_snapshot(r);
            run_stmt(&coord, r, "MATCH (n:N) RETURN n.id AS id");
            coord.commit(r).expect("auto-commit read commits");
        }

        let grown = coord.ssi_tracked_len();
        assert_eq!(
            grown,
            WRITERS + READS,
            "every committed write AND every committed auto-commit read retains an SSI record"
        );
        assert_eq!(coord.active_count(), 0, "no transaction is open");

        // The maintenance checkpoint (`rmp` #305 / #552) prunes the tracker at `oldest_active_snapshot`
        // = None (no open transaction), so every settled committed record is forgotten.
        coord.checkpoint().expect("maintenance checkpoint");

        let after = coord.ssi_tracked_len();
        assert!(
            after < grown,
            "the checkpoint must SHRINK the SSI tracker (before {grown} -> after {after})"
        );
        assert_eq!(
            after, 0,
            "with no open transaction every committed record is settled and pruned"
        );

        // The coordinator remains fully usable after the prune.
        let w = coord.begin_serializable();
        run_stmt(&coord, w, "CREATE (:N {id: 999})");
        coord.commit(w).expect("post-prune writer commits cleanly");
    }

    /// THE WATERMARK GATE (ACID-serializability safety). Pruning must forget ONLY committed records
    /// strictly at/below the live low-water mark. With a long reader open, a checkpoint prunes the
    /// records older than the reader's snapshot but RETAINS both the reader (still in flight) and a
    /// writer that committed concurrently with it — a record that could still contribute an
    /// rw-antidependency and so must not be dropped.
    #[test]
    fn checkpoint_retains_records_a_live_reader_still_needs() {
        let mut coord = fresh_coord();

        // Two writers that commit BEFORE the long reader opens its snapshot.
        let pre1 = coord.begin_serializable();
        run_stmt(&coord, pre1, "CREATE (:N {id: 1})");
        coord.commit(pre1).expect("pre1 commits");
        let pre2 = coord.begin_serializable();
        run_stmt(&coord, pre2, "CREATE (:N {id: 2})");
        coord.commit(pre2).expect("pre2 commits");

        // A long-lived reader opens its snapshot and pins the GC / prune low-water mark at its begin.
        let reader = coord.begin_serializable();
        run_stmt(&coord, reader, "MATCH (n:N) RETURN n.id AS id");
        let pinned = coord
            .oldest_active_snapshot()
            .expect("the open reader pins the watermark");

        // A writer that begins AFTER the reader and commits: concurrent with the reader, its commit
        // timestamp is strictly above `pinned`, so it must survive the prune.
        let after_w = coord.begin_serializable();
        run_stmt(&coord, after_w, "CREATE (:N {id: 3})");
        coord.commit(after_w).expect("after_w commits");

        // Pre-prune: every record is present.
        assert!(coord.ssi_tracks(pre1) && coord.ssi_tracks(pre2));
        assert!(coord.ssi_tracks(reader) && coord.ssi_tracks(after_w));
        assert_eq!(
            coord.oldest_active_snapshot(),
            Some(pinned),
            "the reader still pins the low-water mark"
        );

        // Checkpoint prunes at `oldest_active_snapshot` = the reader's snapshot.
        coord
            .checkpoint()
            .expect("maintenance checkpoint with a live reader open");

        // The pre-reader writers (committed <= the watermark) are forgotten; the still-open reader and
        // the concurrent writer (committed > the watermark) are RETAINED — the serializability contract.
        assert!(
            !coord.ssi_tracks(pre1),
            "a writer committed before the live watermark is pruned"
        );
        assert!(
            !coord.ssi_tracks(pre2),
            "a writer committed at the live watermark is pruned (commit_ts <= low_water)"
        );
        assert!(
            coord.ssi_tracks(reader),
            "the still-open reader must be retained (it has no commit timestamp)"
        );
        assert!(
            coord.ssi_tracks(after_w),
            "a writer concurrent with the open reader must be retained — it could still form an rw-edge"
        );

        // The reader still commits cleanly after the prune (no serializability regression).
        coord
            .commit(reader)
            .expect("the pinned reader commits cleanly after the prune");
    }
}

#[cfg(test)]
mod index_wipe_tests {
    //! White-box regressions for the `rmp` #733 wipe/poison machinery.
    //!
    //! These live **inside** the crate on purpose. The end-to-end tests in
    //! `tests/index_fail_closed.rs` drive a faulty block device, which is the honest way to prove the
    //! engine's *behaviour* — but it cannot isolate any single guard, because the guards deliberately
    //! overlap (a wipe is covered by the epoch re-snapshot, by the degraded-promotion gate, AND by the
    //! command-path repair). An end-to-end test therefore stays green when one of them is deleted, which
    //! makes it worthless as a regression guard for that one.
    //!
    //! So each guard is pinned here against the exact adversarial state it exists for, using the
    //! coordinator's own internals. Every test below FAILS when its guard is reverted (proven, not
    //! assumed).

    use graphus_io::MemBlockDevice;
    use graphus_storage::{IndexState, Namespace, RecordStore};
    use graphus_wal::{MemLogSink, WalManager};

    use crate::binding::{Parameters, bind_parameters};
    use crate::coordinator::TxnCoordinator;
    use crate::executor::execute;
    use crate::lexer::tokenize;
    use crate::lower::lower;
    use crate::parser::parse_tokens;
    use crate::physical::{PhysicalPlan, plan_physical};
    use crate::semantics::analyze;

    type Coord = TxnCoordinator<MemBlockDevice, MemLogSink>;

    fn fresh_coord() -> Coord {
        let device = MemBlockDevice::new(0);
        let wal = WalManager::create(MemLogSink::new()).expect("create wal");
        let store: RecordStore<MemBlockDevice, MemLogSink> =
            RecordStore::create(device, wal, 256, 1).expect("create store");
        TxnCoordinator::new(store)
    }

    fn compile(coord: &Coord, src: &str) -> PhysicalPlan {
        let toks = tokenize(src).expect("lex");
        let ast = parse_tokens(&toks, src).expect("parse");
        let validated = analyze(&ast).expect("analyze");
        plan_physical(&lower(&validated), &coord.catalog())
    }

    fn run(coord: &mut Coord, src: &str) -> Vec<crate::runtime::Row> {
        let plan = compile(coord, src);
        let txn = coord.begin_serializable();
        let bound = bind_parameters(&plan, &Parameters::new()).expect("bind");
        let rows = {
            let mut graph = coord.statement(txn).expect("statement");
            let rows = {
                let mut cursor = execute(&plan, &bound, &mut graph).expect("open cursor");
                cursor.collect_all().expect("collect")
            };
            assert!(!graph.has_error(), "statement captured an error");
            rows
        };
        coord.commit(txn).expect("commit");
        rows
    }

    fn seed(coord: &mut Coord, n: usize) {
        run(
            coord,
            &format!("UNWIND range(1, {n}) AS i CREATE (:Article {{slug: 'a' + toString(i)}})"),
        );
    }

    fn slug_rows(coord: &mut Coord, slug: &str) -> usize {
        run(
            coord,
            &format!("MATCH (a:Article {{slug: '{slug}'}}) RETURN id(a) AS id"),
        )
        .len()
    }

    /// **(C1, isolated.)** A wipe mid-build must make the build re-take its snapshot — not merely restart
    /// over the old one.
    ///
    /// The adversarial state is reproduced exactly: a build is half-done, a row is written **after** its
    /// snapshot (carried into the tree by `reindex_node`), then the index set is wiped. The wipe is
    /// applied directly, and the degraded flag is then cleared **without repopulating** — which is
    /// precisely the window the command-path repair leaves open when its backoff skips a probe, and the
    /// only state in which the epoch guard is the last line of defence.
    ///
    /// Resuming (or restarting over the ORIGINAL snapshot) loses the post-snapshot row for good and then
    /// promotes the index `Online` over the hole: a committed row invisible to every seek, and a
    /// uniqueness check that no longer sees the existing holder.
    #[test]
    fn a_wipe_mid_build_re_takes_the_snapshot_so_post_snapshot_rows_survive() {
        let mut coord = fresh_coord();
        seed(&mut coord, 200);
        coord
            .begin_online_node_property_index("Article", "slug")
            .expect("declare the online index");
        coord.advance_index_builds(64); // half-built: the tree holds the head of the snapshot.
        assert!(coord.has_pending_index_builds());

        // A row written AFTER the build's snapshot. `reindex_node` puts it straight into the tree.
        run(&mut coord, "CREATE (:Article {slug: 'late-1'})");

        // THE WIPE, reproduced exactly as `rebuild_index` performs it: `clear()` empties every tree
        // FIRST — taking the post-snapshot row's maintenance write with it — and only then does the
        // faulting scan trigger `fail_closed()`. Calling `fail_closed()` alone would leave the trees
        // populated and the test would prove nothing (it would pass with the guard deleted).
        coord.index.borrow_mut().clear();
        coord.index.borrow_mut().fail_closed();
        // ...and the set is marked healthy WITHOUT being repopulated. This is the state a skipped repair
        // probe leaves behind, and the one in which the build's own guard is the last line of defence.
        coord.index.borrow_mut().heal();

        let mut iters = 0;
        while coord.has_pending_index_builds() {
            coord.advance_index_builds(64);
            iters += 1;
            assert!(iters < 10_000, "the build must terminate");
        }

        // The index went `Online`, so the planner routes a real seek at it...
        assert_eq!(
            coord.index.borrow().node_property_state(
                coord
                    .store
                    .borrow()
                    .token_id(Namespace::Label, "Article")
                    .expect("label"),
                coord
                    .store
                    .borrow()
                    .token_id(Namespace::PropKey, "slug")
                    .expect("prop"),
            ),
            Some(IndexState::Online),
            "the build must complete and promote"
        );
        let probe = "MATCH (a:Article {slug: 'late-1'}) RETURN id(a) AS id";
        assert!(
            format!("{:?}", compile(&coord, probe)).contains("NodeIndexSeek"),
            "the probe must be served by an index seek — otherwise it proves nothing"
        );
        // ...and it must find the post-snapshot row. Without the re-snapshot: 0 rows.
        assert_eq!(
            slug_rows(&mut coord, "late-1"),
            1,
            "a row written after the build's snapshot must survive the wipe: the build has to \
             RE-TAKE its snapshot, not merely restart over the stale one"
        );
        assert_eq!(
            slug_rows(&mut coord, "a1"),
            1,
            "and the head of the snapshot too"
        );
    }

    /// **(B4 iii.)** A build must never promote its index while the set is degraded — and, because a
    /// degraded set may never heal, it must eventually give up rather than be re-driven forever.
    #[test]
    fn a_degraded_set_blocks_promotion_and_the_build_terminates() {
        let mut coord = fresh_coord();
        seed(&mut coord, 100);
        coord
            .begin_online_node_property_index("Article", "slug")
            .expect("declare the online index");

        // Wipe the set and leave it degraded (no repair): the build may complete its chunks, but it must
        // not publish into a wrecked index set.
        coord.index.borrow_mut().fail_closed();

        let label = coord
            .store
            .borrow()
            .token_id(Namespace::Label, "Article")
            .expect("label");
        let prop = coord
            .store
            .borrow()
            .token_id(Namespace::PropKey, "slug")
            .expect("prop");

        // The engine's own drain loop. It MUST terminate: an empty chunk is not progress, so the stall
        // budget is spent rather than refilled, and the build is poisoned.
        let mut iters = 0;
        while coord.has_pending_index_builds() {
            // Drive the build directly, so the command-path repair (which would clear `degraded` and let
            // the promotion through) cannot mask the gate under test.
            coord.advance_node_property_build(64);
            iters += 1;
            assert!(
                iters < 1_000,
                "the drain loop must TERMINATE against a degraded set — it spun {iters} times"
            );
        }
        assert_eq!(
            coord.index.borrow().node_property_state(label, prop),
            Some(IndexState::Populating),
            "a build must NEVER promote its index into a wiped index set"
        );
        assert_eq!(
            coord.index_build_poison_events(),
            1,
            "the build must be poisoned (parked + counted), not silently dropped"
        );
        assert_eq!(
            coord.poisoned_index_builds(),
            1,
            "and parked for resurrection"
        );
    }

    /// **(M1.)** A poisoned build is not a one-way door: once the store reads cleanly again it is
    /// resurrected from a fresh snapshot and completes.
    #[test]
    fn a_poisoned_build_is_resurrected_once_the_store_is_readable() {
        let mut coord = fresh_coord();
        seed(&mut coord, 100);
        coord
            .begin_online_node_property_index("Article", "slug")
            .expect("declare the online index");
        coord.index.borrow_mut().fail_closed();
        // Bounded: a reverted liveness guard must FAIL this test, never hang the suite.
        let mut iters = 0;
        while coord.has_pending_index_builds() {
            coord.advance_node_property_build(64);
            iters += 1;
            assert!(
                iters < 1_000,
                "the build must terminate — it spun {iters} times"
            );
        }
        assert_eq!(coord.poisoned_index_builds(), 1, "the build was poisoned");

        // The store is fine (the wipe was injected, not caused by a real fault): a repair heals the set,
        // and the parked build is then resurrected and completes.
        assert!(coord.retry_degraded_index_rebuild(), "the set repairs");
        assert!(
            coord.retry_poisoned_index_builds(),
            "the build is resurrected"
        );
        assert!(coord.has_pending_index_builds(), "and back in the queue");
        let mut iters = 0;
        while coord.has_pending_index_builds() {
            coord.advance_index_builds(64);
            iters += 1;
            assert!(iters < 10_000, "the resurrected build must terminate");
        }
        let label = coord
            .store
            .borrow()
            .token_id(Namespace::Label, "Article")
            .expect("label");
        let prop = coord
            .store
            .borrow()
            .token_id(Namespace::PropKey, "slug")
            .expect("prop");
        assert_eq!(
            coord.index.borrow().node_property_state(label, prop),
            Some(IndexState::Online),
            "a resurrected build must finish and promote its index"
        );
        assert_eq!(coord.poisoned_index_builds(), 0);
        assert_eq!(slug_rows(&mut coord, "a1"), 1);
    }

    /// **(M2.)** A bitmap column has no durable catalog, so a fail-closed that *dropped* its declaration
    /// lost it for the life of the process. It must be RETIRED (so an empty membership-exact index never
    /// answers a seek) and brought back by the next rebuild.
    #[test]
    fn a_bitmap_declaration_survives_a_wipe() {
        let mut coord = fresh_coord();
        seed(&mut coord, 50);
        coord
            .declare_bitmap_index("Article", "slug")
            .expect("declare the bitmap column");
        let label = coord
            .store
            .borrow()
            .token_id(Namespace::Label, "Article")
            .expect("label");
        let prop = coord
            .store
            .borrow()
            .token_id(Namespace::PropKey, "slug")
            .expect("prop");
        assert!(coord.index.borrow().has_bitmap(label, prop));

        coord.index.borrow_mut().fail_closed();
        // Retired: it must NOT answer seeks while it is empty...
        assert!(
            !coord.index.borrow().has_bitmap(label, prop),
            "an emptied membership-exact bitmap must not stay registered"
        );
        // ...but the DECLARATION survives, so the repair rebuild restores the column.
        assert!(coord.retry_degraded_index_rebuild(), "the set repairs");
        assert!(
            coord.index.borrow().has_bitmap(label, prop),
            "a declared bitmap column must come back after the rebuild — it has no durable catalog, \
             so nothing else can restore it and it would be gone until the process restarted"
        );
    }

    /// **(B4 i / BLOCKER 1.)** The recovery promotion must ABORT on a degraded set.
    ///
    /// `TxnCoordinator::new` runs the open-time rebuild (which may fail closed) and then promotes every
    /// durably-`Populating` index to `Online` — on the premise that the rebuild has just populated it.
    /// When the rebuild failed closed that premise is false, and the promotion publishes an EMPTY index
    /// `Online`, **durably**: the planner routes a real seek at a tree with no rows in it, and
    /// `unique_conflict` — which trusts that tree as an exact candidate source — lets a `IS UNIQUE`
    /// constraint accept a duplicate. It also falsifies the in-memory state that `SHOW INDEXES` reports.
    #[test]
    fn the_recovery_promotion_aborts_on_a_degraded_index_set() {
        let mut coord = fresh_coord();
        seed(&mut coord, 50);
        // A durably-`Populating` index — exactly what an interrupted `CREATE INDEX` leaves behind.
        coord
            .begin_online_node_property_index("Article", "slug")
            .expect("declare the online index");
        let label = coord
            .store
            .borrow()
            .token_id(Namespace::Label, "Article")
            .expect("label");
        let prop = coord
            .store
            .borrow()
            .token_id(Namespace::PropKey, "slug")
            .expect("prop");
        assert!(
            coord
                .store
                .borrow()
                .node_property_indexes()
                .iter()
                .any(|&(l, p, state)| l == label && p == prop && state == IndexState::Populating),
            "the durable catalog must hold a Populating index"
        );

        // The open-time rebuild failed closed: the trees are empty and every index is demoted.
        coord.index.borrow_mut().fail_closed();

        // The recovery promotion now runs — and must refuse.
        let next = TxnCoordinator::promote_recovered_populating_indexes(
            &coord.store,
            &coord.index,
            coord.next_txn_id,
        );
        coord.next_txn_id = next;

        assert_eq!(
            coord.index.borrow().node_property_state(label, prop),
            Some(IndexState::Populating),
            "the recovery promotion must NOT publish an index the failed rebuild left empty"
        );
        assert!(
            coord
                .store
                .borrow()
                .node_property_indexes()
                .iter()
                .any(|&(l, p, state)| l == label && p == prop && state == IndexState::Populating),
            "and it must not flip the DURABLE state either — that would survive the restart that \
             would otherwise have repaired it"
        );
        // The index is withheld from the planner, so the query is served by the (correct) scan.
        assert!(
            !format!(
                "{:?}",
                compile(&coord, "MATCH (a:Article {slug: 'a1'}) RETURN id(a) AS id")
            )
            .contains("NodeIndexSeek"),
            "a degraded engine must not plan a seek against an empty tree"
        );
        assert_eq!(slug_rows(&mut coord, "a1"), 1, "and the row is still found");
    }

    /// **(B4 ii / BLOCKER 2.)** While degraded, `SHOW INDEXES` must never report `ONLINE` — not even for
    /// an index the recovery promotion would previously have flipped.
    #[test]
    fn show_indexes_never_reports_online_while_degraded() {
        let mut coord = fresh_coord();
        seed(&mut coord, 50);
        coord
            .begin_online_node_property_index("Article", "slug")
            .expect("declare the online index");
        coord.index.borrow_mut().fail_closed();
        let next = TxnCoordinator::promote_recovered_populating_indexes(
            &coord.store,
            &coord.index,
            coord.next_txn_id,
        );
        coord.next_txn_id = next;

        assert!(
            coord
                .list_node_property_indexes()
                .iter()
                .all(|(_, _, _, state)| *state == IndexState::Populating),
            "a degraded engine must not report any index ONLINE: {:?}",
            coord.list_node_property_indexes()
        );
        assert!(
            !coord.label_lookup_usable(),
            "and the LOOKUP row must report the label index as unusable too"
        );
    }

    /// **(V2 — the `poison_backoff` shift clamp.)** `poison_backoff` computes `2^(attempts-1)` to widen
    /// the poisoned-build resurrection backoff. `attempts` is an unbounded `u32` (it grows once per
    /// failed resurrection over the life of a coordinator), and `1u32 << shift` is **undefined for
    /// `shift >= 32`** — in a debug build it panics `attempt to shift left with overflow`, aborting the
    /// engine thread on a merely-degraded (still-correct) store. The `(attempts - 1).min(31)` clamp is
    /// what makes it total; this pins that clamp.
    ///
    /// Reverting the clamp (`(attempts - 1)` without `.min(31)`) makes the extreme-`attempts` calls below
    /// panic, so this test FAILS — the non-vacuity proof for the clamp.
    #[test]
    fn poison_backoff_is_total_monotone_and_saturating() {
        use super::{MAX_DEGRADED_RETRY_BACKOFF, poison_backoff};

        // (a) It never panics for ANY attempts value — including every shift boundary and the extremes
        // that would overflow `1u32 << shift` without the clamp (33 ⇒ shift 32, u32::MAX ⇒ shift huge).
        for attempts in [0u32, 1, 2, 17, 18, 19, 31, 32, 33, 63, 64, 1_000, u32::MAX] {
            let b = poison_backoff(attempts);
            assert!(
                b <= MAX_DEGRADED_RETRY_BACKOFF,
                "poison_backoff({attempts}) = {b} exceeds the cap {MAX_DEGRADED_RETRY_BACKOFF}"
            );
        }

        // (b) The documented early values, then monotone non-decreasing across a full sweep, saturating
        // at the cap (never above it).
        assert_eq!(poison_backoff(0), 0, "attempts 0 is a defensive no-skip");
        assert_eq!(poison_backoff(1), 1, "the first re-poison waits 1 drain");
        assert_eq!(poison_backoff(2), 2);
        assert_eq!(poison_backoff(3), 4);
        let mut prev = 0u32;
        for attempts in 0..=64u32 {
            let b = poison_backoff(attempts);
            assert!(
                b >= prev,
                "poison_backoff must be monotone: {attempts} gave {b} < previous {prev}"
            );
            assert!(b <= MAX_DEGRADED_RETRY_BACKOFF);
            prev = b;
        }

        // (c) Once the geometric growth reaches the cap it STAYS there for every larger `attempts` — no
        // wrap, no UB, no dip. The cap is 2^18, so it is first reached at attempts = 19 (shift 18).
        assert_eq!(
            poison_backoff(19),
            MAX_DEGRADED_RETRY_BACKOFF,
            "cap first reached at 19"
        );
        for attempts in [19u32, 20, 32, 33, 64, 100, 1_000, u32::MAX] {
            assert_eq!(
                poison_backoff(attempts),
                MAX_DEGRADED_RETRY_BACKOFF,
                "poison_backoff({attempts}) must saturate at the cap, not overflow or wrap"
            );
        }
    }
}
