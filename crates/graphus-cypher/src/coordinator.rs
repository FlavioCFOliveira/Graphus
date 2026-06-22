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
use graphus_core::{Timestamp, TxnId};
use graphus_index::fulltext::Analyzer;
use graphus_index::histogram::PropertyHistogram;
use graphus_io::BlockDevice;
use graphus_storage::{
    ConstraintEntry, ConstraintKind, ConstraintTypeDescriptor, FulltextIndexEntry, IndexState,
    Namespace, RecordStore, SpatialIndexEntry,
};
use graphus_txn::{IsolationLevel, LockTable, Snapshot, SsiTracker};
use graphus_wal::LogSink;

use crate::catalog::IndexCatalog;
use crate::constraint::ConstraintViolation;
use crate::index_set::IndexSet;
use crate::record_graph::RecordStoreGraph;
use crate::statistics::Statistics;
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
}

/// One in-progress **non-blocking** node-property index build (`rmp` task #91).
///
/// A build indexes the nodes captured in `snapshot` (the store's live node-id list at build
/// start), a bounded chunk at a time, advancing `cursor` until it reaches the end; the index is
/// then promoted to [`IndexState::Online`]. Nodes created *after* the snapshot, value changes,
/// and deletes are all handled outside this snapshot by [`RecordStoreGraph::reindex_node`] /
/// the candidate-set re-check (see [`TxnCoordinator::advance_index_builds`] for the full
/// consistency argument), so the snapshot only needs to cover the rows that already existed.
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
            active: HashMap::new(),
            next_txn_id,
            pending_builds: VecDeque::new(),
            pending_fulltext_builds: VecDeque::new(),
            pending_spatial_builds: VecDeque::new(),
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
            idx.set_spatial_state(entry.label_token, entry.property_token, IndexState::Online);
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
                idx.register_fulltext(
                    &name,
                    entry.label_token,
                    entry.property_tokens,
                    analyzer,
                    entry.state,
                );
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
                idx.register_spatial(
                    entry.label_token,
                    entry.property_token,
                    graphus_index::DEFAULT_CELL_SIZE,
                    entry.state,
                );
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
                    ConstraintKind::Existence | ConstraintKind::PropertyType => {}
                }
            }
        }

        index.borrow_mut().clear();

        // The set of registered node-property indexes (any state), captured before walking the store so
        // the index is not borrowed across a store borrow. A `Populating` index is maintained too (so
        // its entries are ready the instant it is promoted), so the rebuild reads the full set here;
        // the planner only ever sees the `Online` subset via `catalog()`.
        let registered: Vec<(u32, u32)> = index.borrow().registered_node_properties();

        let node_ids = match store.borrow_mut().scan_node_ids() {
            Ok(ids) => ids,
            // A store-read fault on the whole scan leaves the index empty; every reader then falls
            // back to a full scan (correct, just unaccelerated).
            Err(_) => return,
        };

        let has_fulltext = !index.borrow().registered_fulltext().is_empty();
        // The registered spatial index keys `(label_token, prop_key)`, captured before the scan so the
        // index is not borrowed across a store borrow (`rmp` task #98).
        let registered_spatial: Vec<(u32, u32)> = index.borrow().registered_spatial();
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
    }

    /// Inserts node `id`'s current composite tuples into every registered composite index whose covered
    /// label it carries and whose covered property tuple it holds **in full** (`rmp` task #100). The
    /// composite analogue of [`index_one_node`](Self::index_one_node): a node missing any covered
    /// property (or carrying a null for one) is **not** indexed for that key — matching the node-key
    /// rule that an incomplete tuple never participates in uniqueness. Store and index are borrowed in
    /// separate, non-overlapping scopes (the file's borrow discipline). Read faults skip best-effort.
    fn index_one_node_composite(
        store: &Rc<RefCell<RecordStore<D, S>>>,
        index: &Rc<RefCell<IndexSet>>,
        id: u64,
        registered: &[(u32, Vec<u32>)],
    ) {
        // The node's current label tokens + its property values, read in one store-borrow scope.
        let (label_tokens, props): (Vec<u32>, Vec<(u32, Value)>) = {
            let mut store = store.borrow_mut();
            let labels = match store.node_labels(id) {
                Ok(l) => l,
                Err(_) => return,
            };
            let props = match store.node_property_values(id) {
                Ok(chain) => chain
                    .into_iter()
                    .map(|(_pid, key, value)| (key, value))
                    .collect(),
                Err(_) => return,
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
            Err(_) => return, // overflow-form bitmap or read fault: skip this node's entries.
        };

        // Resolve the node's current property values, keyed by prop-key, so the index borrow
        // below never overlaps a store borrow. `node_property_values` decodes the whole chain
        // newest-first (`rmp` task #50); the first occurrence per key is the newest value. No MVCC
        // snapshot is needed — the index is a candidate set and every seek re-checks visibility.
        let mut values: Vec<(u32, graphus_core::Value)> = Vec::new();
        {
            let chain = match store.borrow_mut().node_property_values(id) {
                Ok(chain) => chain,
                Err(_) => return, // a non-storable / read fault: skip this node's properties.
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
            Err(_) => return,
        };
        // The node's current string property values, keyed by prop-key (newest-wins per key).
        let mut string_props: Vec<(u32, String)> = Vec::new();
        {
            let chain = match store.borrow_mut().node_property_values(id) {
                Ok(chain) => chain,
                Err(_) => return,
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
            Err(_) => return,
        };
        // The node's current property values, keyed by prop-key (newest-wins per key), keeping only
        // the point values a registered spatial index covers for one of this node's labels.
        let mut values: Vec<(u32, Value)> = Vec::new();
        {
            let chain = match store.borrow_mut().node_property_values(id) {
                Ok(chain) => chain,
                Err(_) => return,
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
        let label_tokens = match store.borrow_mut().node_labels(id) {
            Ok(tokens) => tokens,
            Err(_) => return,
        };
        // The node's current property values, keyed by prop-key (newest-wins per key), keeping only
        // the keys a registered bitmap index covers for one of this node's labels.
        let mut values: Vec<(u32, Value)> = Vec::new();
        {
            let chain = match store.borrow_mut().node_property_values(id) {
                Ok(chain) => chain,
                Err(_) => return,
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
    /// # Errors
    /// Returns a storage error if interning either token (or its committing transaction) fails.
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
        let node_ids = match self.store.borrow_mut().scan_node_ids() {
            Ok(ids) => ids,
            Err(_) => return Ok(()), // empty graph / scan fault: an empty bitmap, rebuilt later.
        };
        for id in node_ids {
            Self::index_one_node_bitmap(&self.store, &self.index, id, &registered);
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
        let node_ids = match self.store.borrow_mut().scan_node_ids() {
            Ok(ids) => ids,
            Err(_) => return,
        };
        let mut rows: Vec<(u64, Value)> = Vec::new();
        for id in node_ids {
            let (labels, chain) = {
                let mut store = self.store.borrow_mut();
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
                    let mut store = self.store.borrow_mut();
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
                let mut store = store.borrow_mut();
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
    pub fn begin_online_node_property_index(&mut self, label: &str, property: &str) -> Result<()> {
        // Intern the tokens and record the durable catalog entry as `Populating`, in one committed
        // transaction — exactly like `create_node_property_index` but for the in-progress state, so an
        // interrupted build recovers `Populating` and is completed by the open-time rebuild.
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
            store.set_node_property_index(label_token, prop_key, IndexState::Populating);
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
        });
        Ok(())
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
        label: &str,
        properties: &[String],
        analyzer: Analyzer,
    ) -> Result<()> {
        if properties.is_empty() {
            return Err(GraphusError::Storage(
                "a full-text index must cover at least one property".to_owned(),
            ));
        }

        // Intern the label + property-key tokens and record the durable catalog entry `Populating`, in
        // one committed transaction (so the schema change survives a crash atomically).
        self.next_txn_id += 1;
        let txn = TxnId(self.next_txn_id);
        self.store.borrow_mut().begin(txn);
        let entry = {
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
            let entry = FulltextIndexEntry {
                label_token,
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
            entry.label_token,
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
            });
        Ok(())
    }

    /// Drops the full-text index named `name` (`rmp` task #72): removes its durable catalog entry in a
    /// committed transaction, unregisters it from the in-memory [`IndexSet`], and cancels any
    /// in-progress build. Idempotent on a never-declared name (a clean no-op success).
    ///
    /// # Errors
    /// Returns a storage error if the committing transaction fails.
    pub fn drop_fulltext_index(&mut self, name: &str) -> Result<()> {
        // A no-op when the index is not declared (avoids an empty committed transaction).
        if self.store.borrow().fulltext_index(name).is_none() {
            // Still cancel any in-flight build + in-memory registration defensively, then succeed.
            self.pending_fulltext_builds.retain(|b| b.name != name);
            self.index.borrow_mut().unregister_fulltext(name);
            return Ok(());
        }
        self.next_txn_id += 1;
        let txn = TxnId(self.next_txn_id);
        self.store.borrow_mut().begin(txn);
        self.store.borrow_mut().remove_fulltext_index(name);
        self.store.borrow_mut().commit(txn)?;

        self.pending_fulltext_builds.retain(|b| b.name != name);
        self.index.borrow_mut().unregister_fulltext(name);
        Ok(())
    }

    /// Lists every declared full-text index as `(name, label, properties, analyzer, state)`
    /// (`rmp` task #72) for a `SHOW FULLTEXT INDEXES` surface. Reads the durable catalog and resolves
    /// the tokens back to names; an entry whose tokens have no resolvable name (a defensively-skipped
    /// impossibility for a live token) or an unknown analyzer byte is omitted. Ordered by name.
    #[must_use]
    pub fn list_fulltext_indexes(
        &self,
    ) -> Vec<(String, String, Vec<String>, Analyzer, IndexState)> {
        let store = self.store.borrow();
        store
            .fulltext_indexes()
            .into_iter()
            .filter_map(|(name, entry)| {
                let label = store.token_name(Namespace::Label, entry.label_token)?;
                let mut properties = Vec::with_capacity(entry.property_tokens.len());
                for pk in &entry.property_tokens {
                    properties.push(store.token_name(Namespace::PropKey, *pk)?.to_owned());
                }
                let analyzer = Analyzer::from_byte(entry.analyzer)?;
                Some((name, label.to_owned(), properties, analyzer, entry.state))
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
    pub fn create_point_index(&mut self, name: &str, label: &str, property: &str) -> Result<()> {
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
        });
        Ok(())
    }

    /// Drops the spatial (point) index named `name` (`rmp` task #98): removes its durable catalog
    /// entry in a committed transaction, unregisters its grid from the in-memory [`IndexSet`], and
    /// cancels any in-progress build. Idempotent on a never-declared name (a clean no-op success).
    ///
    /// # Errors
    /// Returns a storage error if the committing transaction fails.
    pub fn drop_point_index(&mut self, name: &str) -> Result<()> {
        // Resolve the covered `(label_token, prop_key)` from the durable entry so we can unregister the
        // right grid from the in-memory set (which is keyed by tokens, not by name).
        let entry = self.store.borrow().spatial_index(name);
        let Some(entry) = entry else {
            // Not declared: still cancel any in-flight build defensively, then succeed.
            self.pending_spatial_builds.retain(|b| b.name != name);
            return Ok(());
        };

        self.next_txn_id += 1;
        let txn = TxnId(self.next_txn_id);
        self.store.borrow_mut().begin(txn);
        self.store.borrow_mut().remove_spatial_index(name);
        self.store.borrow_mut().commit(txn)?;

        self.pending_spatial_builds.retain(|b| b.name != name);
        self.index
            .borrow_mut()
            .unregister_spatial(entry.label_token, entry.property_token);
        Ok(())
    }

    /// Lists every declared spatial (point) index as `(name, label, property, state)` (`rmp` task
    /// #98) for a `SHOW POINT INDEXES` surface. Reads the durable catalog and resolves the tokens back
    /// to names; an entry whose tokens have no resolvable name (a defensively-skipped impossibility for
    /// a live token) is omitted. Ordered by name.
    #[must_use]
    pub fn list_point_indexes(&self) -> Vec<(String, String, String, IndexState)> {
        let store = self.store.borrow();
        store
            .spatial_indexes()
            .into_iter()
            .filter_map(|(name, entry)| {
                let label = store.token_name(Namespace::Label, entry.label_token)?;
                let property = store.token_name(Namespace::PropKey, entry.property_token)?;
                Some((name, label.to_owned(), property.to_owned(), entry.state))
            })
            .collect()
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
        self.next_txn_id += 1;
        let txn = TxnId(self.next_txn_id);
        self.store.borrow_mut().begin(txn);

        // Intern the label + every property-key token (rolled back with the transaction on any failure).
        let intern = (|| -> Result<(u32, Vec<u32>)> {
            let mut store = self.store.borrow_mut();
            let label_token = store.intern_token(Namespace::Label, label)?;
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
        // the offending node precisely.
        if let Err(e) = self.validate_existing_against_constraint(
            name,
            label,
            properties,
            label_token,
            &prop_keys,
            kind,
            type_descriptor.as_ref(),
        ) {
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
                    if let [prop_key] = prop_keys.as_slice() {
                        idx.register_node_property_with_state(
                            label_token,
                            *prop_key,
                            IndexState::Online,
                        );
                    }
                    true
                }
                ConstraintKind::NodeKey => {
                    idx.register_composite(label_token, prop_keys.clone());
                    true
                }
                ConstraintKind::Existence | ConstraintKind::PropertyType => false,
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
            // Read this node's label tokens; skip a read-faulting node best-effort.
            let label_tokens = match self.store.borrow_mut().node_labels(id) {
                Ok(t) => t,
                Err(_) => continue,
            };
            if !label_tokens.contains(&label_token) {
                continue; // node does not carry the covered label
            }
            match kind {
                ConstraintKind::Existence => {
                    // A missing or null value violates the existence (NOT NULL) constraint.
                    let value = self.node_value_for_key(id, prop_keys[0]);
                    if value.as_ref().is_none_or(graphus_core::Value::is_null) {
                        return Err(ConstraintViolation::Existence {
                            name: name.to_owned(),
                            label: label.to_owned(),
                            property: properties[0].to_owned(),
                        }
                        .into_error());
                    }
                }
                ConstraintKind::Unique => {
                    // A null/absent value never participates in uniqueness (Cypher equality treats
                    // null as never-equal), matching the index's treatment.
                    let Some(value) = self
                        .node_value_for_key(id, prop_keys[0])
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
                            label: label.to_owned(),
                            property: properties[0].to_owned(),
                            value: render_value(&value),
                        }
                        .into_error());
                    }
                    seen.push((value, id));
                }
                ConstraintKind::NodeKey => {
                    // Existence half: every covered property must be present and non-null.
                    let mut tuple = Vec::with_capacity(prop_keys.len());
                    let mut complete = true;
                    for &prop_key in prop_keys {
                        match self
                            .node_value_for_key(id, prop_key)
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
                            label: label.to_owned(),
                            properties: properties.iter().map(|p| (*p).to_owned()).collect(),
                        }
                        .into_error());
                    }
                    // Uniqueness half: the complete tuple must not have been seen before.
                    if seen_tuples.iter().any(|seen| tuples_equal(seen, &tuple)) {
                        return Err(ConstraintViolation::NodeKeyDuplicate {
                            name: name.to_owned(),
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
                        .node_value_for_key(id, prop_keys[0])
                        .filter(|v| !v.is_null())
                    else {
                        continue;
                    };
                    let descriptor = type_descriptor
                        .expect("INVARIANT: a PropertyType constraint always carries a descriptor");
                    if !crate::constraint::value_matches_descriptor(&value, descriptor) {
                        return Err(ConstraintViolation::PropertyType {
                            name: name.to_owned(),
                            label: label.to_owned(),
                            property: properties[0].to_owned(),
                            expected: crate::constraint::type_descriptor_name(descriptor),
                            actual: crate::constraint::value_type_name(&value),
                        }
                        .into_error());
                    }
                }
            }
        }
        Ok(())
    }

    /// The newest value node `id` holds for property-key token `prop_key`, or [`None`] if the node
    /// has no such property (or a read fault occurs). Reads the property chain newest-first and keeps
    /// the first occurrence — the same newest-wins discipline the index rebuild uses (`rmp` task #99).
    fn node_value_for_key(&self, id: u64, prop_key: u32) -> Option<Value> {
        let chain = self.store.borrow_mut().node_property_values(id).ok()?;
        chain
            .into_iter()
            .find(|(_pid, key, _value)| *key == prop_key)
            .map(|(_pid, _key, value)| value)
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
    pub fn drop_constraint(&mut self, name: &str) -> Result<()> {
        // Resolve the entry first so a node key's backing composite index can be unregistered by its
        // covered `(label, property tuple)` after the durable removal.
        let entry = self.store.borrow().constraint(name);
        let Some(entry) = entry else {
            // A no-op when the constraint is not declared (avoids an empty committed transaction).
            self.index.borrow_mut().unregister_constraint(name);
            return Ok(());
        };
        self.next_txn_id += 1;
        let txn = TxnId(self.next_txn_id);
        self.store.borrow_mut().begin(txn);
        self.store.borrow_mut().remove_constraint(name);
        self.store.borrow_mut().commit(txn)?;
        let mut idx = self.index.borrow_mut();
        idx.unregister_constraint(name);
        if entry.kind == ConstraintKind::NodeKey {
            idx.unregister_composite(entry.label_token, &entry.property_tokens);
        }
        Ok(())
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
                let label = store.token_name(Namespace::Label, entry.label_token)?;
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
    #[must_use]
    pub fn has_pending_index_builds(&self) -> bool {
        !self.pending_builds.is_empty()
            || !self.pending_fulltext_builds.is_empty()
            || !self.pending_spatial_builds.is_empty()
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
        let Some(build) = self.pending_builds.front_mut() else {
            return;
        };

        // Index up to `budget` nodes from the snapshot, starting at the cursor.
        let registered = [(build.label_token, build.prop_key)];
        let end = build.snapshot.len().min(build.cursor + budget);
        for &id in &build.snapshot[build.cursor..end] {
            Self::index_one_node(&self.store, &self.index, id, &registered);
        }
        build.cursor = end;

        if build.cursor < build.snapshot.len() {
            return; // more of this build remains.
        }

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
        let Some(build) = self.pending_fulltext_builds.front_mut() else {
            return;
        };
        let total = build.snapshot.len();
        let end = total.min(build.cursor + budget);
        let chunk: Vec<u64> = build.snapshot[build.cursor..end].to_vec();
        let name = build.name.clone();
        build.cursor = end;
        let done = end >= total;

        for id in chunk {
            Self::index_one_node_fulltext(&self.store, &self.index, id);
        }

        if !done {
            return; // more of this build remains.
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
        let Some(build) = self.pending_spatial_builds.front_mut() else {
            return;
        };
        let total = build.snapshot.len();
        let end = total.min(build.cursor + budget);
        let chunk: Vec<u64> = build.snapshot[build.cursor..end].to_vec();
        let name = build.name.clone();
        let registered = [(build.label_token, build.prop_key)];
        build.cursor = end;
        let done = end >= total;

        for id in chunk {
            Self::index_one_node_spatial(&self.store, &self.index, id, &registered);
        }

        if !done {
            return; // more of this build remains.
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
    /// # Errors
    /// Returns a storage error if the committing transaction fails.
    pub fn drop_node_property_index(&mut self, label: &str, property: &str) -> Result<()> {
        // Resolve the tokens by lookup only; a missing token means the index cannot exist.
        let tokens = {
            let store = self.store.borrow();
            match (
                store.token_id(Namespace::Label, label),
                store.token_id(Namespace::PropKey, property),
            ) {
                (Some(label_token), Some(prop_key)) => Some((label_token, prop_key)),
                _ => None,
            }
        };
        let Some((label_token, prop_key)) = tokens else {
            return Ok(()); // no such tokens → no such index → clean no-op.
        };

        // Remove the durable catalog entry in its own committed transaction (mirrors the create path).
        self.next_txn_id += 1;
        let txn = TxnId(self.next_txn_id);
        self.store.borrow_mut().begin(txn);
        self.store
            .borrow_mut()
            .remove_node_property_index(label_token, prop_key);
        self.store.borrow_mut().commit(txn)?;

        // Cancel any in-progress build for this index and unregister it from the in-memory set.
        self.pending_builds
            .retain(|b| !(b.label_token == label_token && b.prop_key == prop_key));
        self.index
            .borrow_mut()
            .unregister_node_property(label_token, prop_key);
        Ok(())
    }

    /// Lists every declared node-property index as `(label, property, state)` (`rmp` task #91), for a
    /// `SHOW INDEXES` surface. Reads the durable catalog and resolves the tokens back to names; an
    /// index whose tokens have no resolvable name (a defensively-skipped impossibility for a live
    /// token) is omitted. Ordered by the catalog's ascending `(label_token, prop_key)` key.
    #[must_use]
    pub fn list_node_property_indexes(&self) -> Vec<(String, String, IndexState)> {
        let store = self.store.borrow();
        store
            .node_property_indexes()
            .into_iter()
            .filter_map(|(label_token, prop_key, state)| {
                let label = store.token_name(Namespace::Label, label_token)?;
                let property = store.token_name(Namespace::PropKey, prop_key)?;
                Some((label.to_owned(), property.to_owned(), state))
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

        for token in self.index.borrow_mut().indexed_label_tokens() {
            if let Some(name) = store.token_name(Namespace::Label, token) {
                builder = builder.with_token_lookup(name);
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
            Rc::clone(&self.columns),
            Rc::clone(&self.zones),
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

    /// Aborts `txn`: store undo, SSI forget, lock release, and removal from the open set.
    fn abort(&mut self, txn: TxnId) -> Result<()> {
        self.store.borrow_mut().rollback(txn)?;
        self.ssi.borrow_mut().forget(txn);
        self.locks.borrow_mut().release_all(txn);
        self.active.remove(&txn);
        Ok(())
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
