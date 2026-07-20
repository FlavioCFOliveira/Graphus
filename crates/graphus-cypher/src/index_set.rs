//! `IndexSet` — an in-memory, token-keyed set of derived secondary indexes (`rmp` task #48).
//!
//! This is the **data-structure layer** for index wiring. An [`IndexSet`] holds:
//!
//! - one always-present **label** [`TokenIndex`] (`(label_token, node_id)`), auto-maintained, that
//!   answers `MATCH (n:Label)` candidate scans; and
//! - a map `(label_token, prop_key) -> ` [`PropertyIndex`] of **declared** node-property indexes
//!   that answer equality and range predicates.
//!
//! # Derived / ephemeral by design (`graphus-index` crate-root seam)
//!
//! Every backing tree lives over an **in-memory** device ([`MemBlockDevice`]) and a non-retaining log
//! sink ([`DiscardingLogSink`]): the index set is rebuilt from the record store on open and is never
//! recovered after a crash, so there is no durability requirement here — the sink discards every WAL
//! record body it is handed, eliminating the retained-WAL `Vec` (`rmp` #321/#313). Consequently the
//! internal
//! WAL transaction id is irrelevant — every op uses a fixed [`TxnId`]`(1)`; the buffer pool applies
//! each mutation to its in-memory page immediately, so reads observe writes without a commit.
//!
//! # Candidates, not answers
//!
//! Like the underlying [`graphus_index`] kinds, every `seek_*` here returns **candidate** record
//! ids and never filters by MVCC visibility, by current label membership, or by the *current* value
//! of the property (an entry may be stale): that re-check is the caller's job (the
//! coordinator/`RecordStoreGraph`). Because the caller re-checks the predicate, returning a
//! **superset** of the truly-matching ids is always correct; returning a subset never is. The range
//! seek deliberately exploits this when a bound cannot be expressed exactly against the backing
//! index (see [`IndexSet::seek_node_property_range`]).

use std::collections::{BTreeSet, HashMap, HashSet, VecDeque};

use graphus_bufpool::BufferPool;
use graphus_core::{Timestamp, TxnId, Value};
use graphus_index::bitmap::{self, BitmapIndex};
use graphus_index::fulltext::{Analyzer, InvertedIndex, MatchSemantics};
use graphus_index::recovery::SharedWal;
use graphus_index::spatial::SpatialIndex;
use graphus_index::text::TrigramIndex;
use graphus_index::vector::VectorIndex;
use graphus_index::{
    BTree, CompositeIndex, PropertyIndex, RelPropertyIndex, Similarity, TokenIndex,
    VectorIndexError,
};
use graphus_io::MemBlockDevice;
use graphus_storage::{ConstraintKind, ConstraintTypeDescriptor, IndexState};
use graphus_wal::{DiscardingLogSink, WalManager};

/// One node-property RANGE seek to pre-run for an off-thread reader (`rmp` task #768):
/// `(label_token, prop_key, lower, upper)`, each bound owned as `(value, inclusive)` or `None` (open).
/// Consumed by [`IndexSet::capture_node_property_range`].
pub type RangeCaptureRequest = (u32, u32, Option<(Value, bool)>, Option<(Value, bool)>);
/// One node COMPOSITE equality seek to pre-run for an off-thread reader (`rmp` task #768):
/// `(label_token, property_tokens, values)` — the full ordered key and the per-key seek values.
/// Consumed by [`IndexSet::capture_node_property_composite`].
pub type CompositeCaptureRequest = (u32, Vec<u32>, Vec<Value>);
/// One node TEXT (trigram) seek to pre-run for an off-thread reader (`rmp` task #768):
/// `(label_token, prop_key, op, needle)`. Consumed by [`IndexSet::capture_node_property_text`].
pub type TextCaptureRequest = (u32, u32, crate::physical::TextSeekOp, String);
/// One SPATIAL (point) proximity seek to pre-run for an off-thread reader (`rmp` task #770), shared by
/// nodes and relationships: `(token, prop_key, center_x, center_y, radius)`. The centre/radius are the
/// plan-time-folded `f64` constants. Consumed by [`IndexSet::capture_node_spatial`] /
/// [`IndexSet::capture_rel_spatial`].
pub type SpatialCaptureRequest = (u32, u32, f64, f64, f64);

/// The in-memory block device the derived indexes are built on.
type Dev = MemBlockDevice;
/// The log sink the derived indexes' ephemeral WAL is built on (`rmp` task #321).
///
/// A derived index's WAL is **never synced, never read back, never recovered** — the index is rebuilt
/// from the record store on open — so its records are pure overhead. A [`DiscardingLogSink`] keeps the
/// WAL-before-page contract (LSNs advance, appends are immediately "durable") while *discarding* every
/// record body, eliminating both the unbounded retained-WAL `Vec` (`~72 %` of a large bulk-load's peak
/// RSS, `rmp` #313/#305) and the per-insert full-page double copy that dominated index build time
/// (measured `2.14s → 0.93s`, 2.3x, on a 53k-node build).
type Sink = DiscardingLogSink;

/// The fixed transaction id used for every backing-tree op. The WAL is ephemeral and never
/// recovered, so the id carries no meaning; the buffer pool applies each mutation in-memory
/// immediately, so reads see writes without a commit.
const EPHEMERAL_TXN: TxnId = TxnId(1);

/// Buffer-pool capacity (in frames) for each backing tree. Generous enough that a derived index of
/// a modestly sized store stays resident; the pool spills to the in-memory device otherwise.
const POOL_FRAMES: usize = 64;

/// Builds a fresh, empty in-memory [`BTree`] with its own throwaway WAL.
///
/// Each call wires a brand-new [`MemBlockDevice`] + [`DiscardingLogSink`] pair, so trees are fully
/// independent — exactly what [`IndexSet::clear`] needs to drop all entries by recreation.
fn fresh_tree() -> BTree<Dev, Sink> {
    // A non-retaining sink + manager: `WalManager::create` over `DiscardingLogSink` cannot fail in
    // practice. The sink retains only the WAL header (which `create` reads back) and discards every
    // record body — sound because this WAL is never recovered (`rmp` task #321).
    let wal = WalManager::create(DiscardingLogSink::new())
        .expect("INVARIANT: in-memory WAL creation over DiscardingLogSink is infallible");
    let shared = SharedWal::new(wal);
    let pool = BufferPool::with_wal(MemBlockDevice::new(0), shared.clone(), POOL_FRAMES);
    // An in-memory B+-tree: `BTree::create` over a fresh in-memory pool cannot fail in practice.
    BTree::create(pool, shared).expect("INVARIANT: in-memory BTree creation is infallible")
}

/// An in-memory, token-keyed set of derived secondary indexes over the [`graphus_index`] kinds.
///
/// See the [module docs](self) for the durability / candidate-vs-answer contract. The struct is
/// `!Sync` (it holds `&mut`-driven trees); the coordinator owns it single-threaded.
pub struct IndexSet {
    /// The always-present label scan index, keyed `(label_token, node_id)`.
    labels: TokenIndex<Dev, Sink>,
    /// Declared node-property indexes, keyed by `(label_token, prop_key)`. Each value is the backing
    /// [`PropertyIndex`] (keyed internally on `(prop_key, property_value, node_id)`, sufficient because
    /// the map already partitions by `label_token`) **plus its build [`IndexState`]** (`rmp` task #90).
    ///
    /// The state gates *exposure to the planner*, not maintenance: a `Populating` index is kept up to
    /// date by [`insert_node_property`](Self::insert_node_property) (harmless), but is omitted from
    /// [`online_node_properties`](Self::online_node_properties) so the planner never routes a seek to a
    /// half-built index — it falls back to a label-scan + filter until the index is promoted `Online`.
    node_props: HashMap<(u32, u32), NodePropertyIndex>,
    /// Declared **relationship-property** indexes (`rmp` task #646), keyed by `(rel_type_token,
    /// prop_key)`. The relationship analogue of [`node_props`](Self#structfield.node_props): each value
    /// is the backing [`RelPropertyIndex`] (keyed internally on `(prop_key, property_value, rel_id)`)
    /// plus its build [`IndexState`], mirrored from the durable catalog. Like every derived index the
    /// backing tree is **ephemeral** (rebuilt from the store on open); only the *registration* is
    /// durable. A `Populating` index is maintained (harmlessly) but withheld from
    /// [`online_rel_properties`](Self::online_rel_properties) so the planner never routes a seek to a
    /// half-built index.
    rel_props: HashMap<(u32, u32), RelationshipPropertyIndex>,
    /// Declared **node** full-text indexes (`rmp` tasks #72, #663), keyed by their server-unique
    /// **name**. Each value carries the covered labels, the covered property keys, the analyzer, the
    /// build state and the in-memory [`InvertedIndex`]. Like the property indexes the inverted index is
    /// **ephemeral** (rebuilt from the store on open); only the *registration* is durable (the storage
    /// catalog).
    fulltext: HashMap<String, FulltextEntry>,
    /// Declared **relationship** full-text indexes (`rmp` task #663), keyed by their server-unique
    /// **name** — the relationship analogue of [`fulltext`](Self#structfield.fulltext). Each value
    /// carries the covered relationship types, the covered property keys, the analyzer, the build state
    /// and an in-memory [`InvertedIndex`] whose postings are **relationship** ids. Kept in a separate
    /// map from the node full-text indexes (a numeric collision between a label token and a rel-type
    /// token never mixes the two), exactly as `rel_props` is separate from `node_props`. Ephemeral,
    /// rebuilt from the store on open; only the *registration* is durable.
    fulltext_rel: HashMap<String, FulltextRelEntry>,
    /// Declared **spatial** indexes (`rmp` task #73), keyed by `(label_token, prop_key)`. Each value
    /// carries the build state and the in-memory [`SpatialIndex`] grid over the covered point
    /// property. Ephemeral and rebuilt on open, exactly like the property and full-text indexes.
    spatial: HashMap<(u32, u32), SpatialEntry>,
    /// Declared **relationship** spatial indexes (`rmp` task #664), keyed by `(type_token, prop_key)` —
    /// the relationship analogue of [`spatial`](Self#structfield.spatial). Each value carries the build
    /// state and the in-memory [`SpatialIndex`] grid whose postings are **relationship** ids (the grid is
    /// already `u64`-generic, exactly as the rel-keyed [`InvertedIndex`] is). Kept in a separate map from
    /// the node spatial indexes (a numeric collision between a label token and a rel-type token never
    /// mixes the two), exactly as `fulltext_rel` is separate from `fulltext`. Ephemeral, rebuilt on open;
    /// only the *registration* is durable.
    spatial_rel: HashMap<(u32, u32), SpatialEntry>,
    /// Declared **text (trigram)** indexes (`rmp` task #662), keyed by `(label_token, prop_key)`. Each
    /// value carries the build state and the in-memory [`TrigramIndex`] over the covered string
    /// property, accelerating `CONTAINS` / `ENDS WITH` / `STARTS WITH`. Ephemeral and rebuilt on open,
    /// exactly like the spatial index; only the *registration* is durable (the storage catalog).
    text: HashMap<(u32, u32), TextEntry>,
    /// Declared **vector (HNSW)** node indexes (`rmp` task #669), keyed by `(label_token, prop_key)`.
    /// Each value carries the build state and the in-memory [`VectorIndex`] (an approximate-nearest-
    /// neighbour graph) over the covered embedding property. Ephemeral and rebuilt on open, exactly like
    /// the spatial / text index; only the *registration* is durable (the storage catalog). Because the
    /// HNSW graph keeps only the latest state (no version history), it rides the SAME cross-snapshot
    /// freshness marker as the full-text / spatial / text indexes.
    vector: HashMap<(u32, u32), VectorEntry>,
    /// Declared **vector (HNSW)** relationship indexes (`rmp` task #669), keyed by `(type_token,
    /// prop_key)` — the relationship analogue of [`vector`](Self#structfield.vector). Kept in a
    /// **separate** map (a numeric collision between a label token and a relationship-type token never
    /// mixes the two), exactly as `spatial_rel` / `fulltext_rel` are separate from their node maps.
    vector_rel: HashMap<(u32, u32), VectorEntry>,
    /// Declared **constraints** (`rmp` tasks #99, #100), keyed by their server-unique **name**. Each
    /// value is a [`ConstraintRule`] carrying the covered label token, the covered property tokens, the
    /// [`ConstraintKind`] and (for a property-type constraint) the declared type descriptor. Unlike the
    /// index maps this holds no backing tree of its own: a uniqueness constraint reuses the
    /// node-property index on its `(label, property)`, and a node-key constraint reuses the **composite**
    /// index on its `(label, property tuple)` (see [`composite`](Self#structfield.composite)), so
    /// write-time enforcement is just a registry of *which* rules apply, re-checked against the store +
    /// index by the `RecordStoreGraph` write path. Ephemeral and rebuilt from the durable catalog on
    /// open, exactly like the indexes.
    constraints: HashMap<String, ConstraintRule>,
    /// Declared **composite** indexes (`rmp` task #100), keyed by `(label_token, property_tokens)` (the
    /// covered tuple in declared order). A node-key constraint registers one here so the write-path
    /// composite-uniqueness check is index-accelerated (a scan fallback covers the no-index case). Like
    /// every other backing structure the tree is **ephemeral** (rebuilt from the store on open); only
    /// the constraint *declaration* is durable. The map key carries the whole property tuple because a
    /// label may host several node keys over different property tuples.
    composite: HashMap<(u32, Vec<u32>), CompositeIndex<Dev, Sink>>,
    /// Declared **composite (multi-property) relationship** indexes (`rmp` task #666), keyed by
    /// `(type_token, property_tokens)` — the relationship analogue of
    /// [`composite`](Self#structfield.composite). Kept in a **separate** map from the node composites (a
    /// numeric collision between a label token and a relationship-type token never mixes the two),
    /// exactly as `spatial_rel` / `fulltext_rel` are separate from their node maps. Each value is an
    /// ephemeral [`CompositeIndex`] over the covered relationship-property tuple (rebuilt from the store
    /// on open); only the *registration* is durable. A standalone composite relationship index is a pure
    /// query accelerator (no uniqueness), maintained candidate-only by the relationship write path.
    rel_composite: HashMap<(u32, Vec<u32>), CompositeIndex<Dev, Sink>>,
    /// **Reachability gate** for [`PredicateRead::RelEquality`] markers (`rmp` #683): the
    /// `type_token -> {prop_key}` pairs for which some reader in this process's lifetime *could* have
    /// registered such a marker.
    ///
    /// # Why this exists
    ///
    /// Every relationship write path must announce the `RelEquality` markers its edge satisfies, or the
    /// precise marker silently stops matching and SSI misses an anomaly. But announcing requires reading
    /// the relationship's property chain, which is **not** free — measured at ~3x on `SET r.p` for a
    /// store with no relationship index at all, where the announcement is provably inert because
    /// **nobody can hold the marker**. A reader can only register `RelEquality{T, p, _}` via one of
    /// exactly three paths, and each requires schema over `(T, p)`:
    ///   1. `rel_index_seek_eq` — requires an `Online` relationship-property index on `(T, p)`;
    ///   2. `rel_unique_conflict` — requires a `RelUnique` rule covering `(T, p)`;
    ///   3. `rel_composite_seek_eq` — requires a `RelKey`/`RelUnique` rule covering `(T, tuple ∋ p)`.
    ///
    /// So `(T, p)` absent from this map ⇒ no marker can exist ⇒ skipping the announcement is sound.
    ///
    /// # MONOTONE — entries are NEVER removed (this is the load-bearing property)
    ///
    /// A gate that merely asked "is there an index **now**?" would make the write footprint
    /// **schema-derived** and open a DDL/DML race: a reader seeks (holding the marker), a concurrent
    /// `DROP INDEX`/`DROP CONSTRAINT` commits, and the writer then sees no schema, skips the
    /// announcement, and the reader's marker is never matched — a **FALSE NEGATIVE**, the exact hazard
    /// that made the marker design per-component rather than tuple-shaped in the first place.
    ///
    /// Keeping the entry forever makes the gate a sound **superset**: a drop can only ever leave us
    /// announcing markers nobody holds (correct and slightly slow — the safe direction), never skipping
    /// markers somebody does hold. The map is part of the derived, rebuilt-on-open `IndexSet`, so it
    /// resets only when no transaction — and therefore no marker — can survive.
    rel_equality_declared: HashMap<u32, HashSet<u32>>,
    /// Declared **low-cardinality Roaring-bitmap** indexes (`rmp` task #328), keyed by `(label_token,
    /// prop_key)`. Each value is an in-memory [`BitmapIndex`] (value → compressed node-id bitmap) over
    /// the covered low-cardinality column. Like every other backing structure it is **ephemeral**
    /// (rebuilt from the store on open); unlike the catalog-backed kinds it uses the **opt-in** model
    /// (declared in-session, no durable catalog entry), exactly like the columnar value cache — so a
    /// re-opened coordinator re-declares the columns it wants bitmap-accelerated. Because it is a
    /// **candidate source** (not a read-only accelerator), it is kept membership-exact under writes by
    /// the wholesale per-node re-index in [`RecordStoreGraph::reindex_node`](crate::record_graph).
    bitmap: HashMap<(u32, u32), BitmapIndex>,
    /// The **declared** bitmap columns (`rmp` task #733, M2), independent of whether a live
    /// [`BitmapIndex`] is currently registered for them in [`bitmap`](Self#structfield.bitmap).
    ///
    /// A bitmap column is opt-in and **has no durable catalog entry**: it is declared in-session. So when
    /// [`fail_closed`](Self::fail_closed) unregisters the live bitmaps — which it must, since a bitmap is
    /// a *membership-exact* candidate source and an empty one answers every seek with zero rows — there
    /// is nothing on disk for a rebuild to re-register from, and the declaration would be lost **for the
    /// life of the process**: every bitmap column silently gone after the first storage fault, with no
    /// way back short of a restart. Keeping the declarations here (they are two tokens, not data) lets
    /// the next rebuild re-register and repopulate exactly the columns the session asked for.
    ///
    /// Only an explicit drop ([`unregister_bitmap`](Self::unregister_bitmap)) removes a declaration; the
    /// fail-closed paths use [`disable_bitmap`](Self::disable_bitmap), which retires the live index but
    /// keeps the declaration so a rebuild can restore it.
    bitmap_declared: BTreeSet<(u32, u32)>,
    /// **Per-transaction set of node ids whose bitmap entry this transaction touched** (`rmp` task
    /// #453, F-IDX-3). The bitmap is maintained *eagerly* during statement execution (remove-then-
    /// reinsert on a property/label change), but a transaction **abort** rolls back only the durable
    /// store — not this in-memory index. Because the bitmap is a *membership-exact candidate source*, a
    /// node left under the rolled-back value (and missing under the committed one) cannot be resurrected
    /// by the query-time re-check (which can only *drop* a stale candidate, never *add* a missing one):
    /// a committed row would be silently lost once the seek is wired into the planner. So every write
    /// path that maintains a node's bitmap records `(txn, node_id)` here; on abort the coordinator
    /// re-derives exactly these nodes from the reverted store, and on commit it drops the txn's set.
    /// Empty for any transaction that touched no bitmap-indexed column (the overwhelmingly common case,
    /// since a bitmap index is opt-in), so this costs nothing unless a bitmap index is declared and a
    /// covered node is written.
    dirty_bitmap_nodes: HashMap<TxnId, BTreeSet<u64>>,
    /// The cross-snapshot freshness marker for the **full-text + spatial** indexes (`rmp` task #467).
    ///
    /// # The problem this closes
    ///
    /// Unlike every other index kind here, the full-text [`InvertedIndex`] and the [`SpatialIndex`]
    /// hold **only the latest state** (a commit-time wholesale [`reindex_fulltext_node`](Self::reindex_fulltext_node)
    /// / [`insert_spatial_point`](Self::insert_spatial_point), no version history). When a committed
    /// writer A *replaces* a node's indexed term / point, a reader B whose MVCC snapshot **predates**
    /// A's commit gets candidates keyed by A's **new** state. The per-candidate visibility re-check
    /// filters false *positives* but **cannot resurrect a candidate that is now missing** from the
    /// posting list — so B's indexed query for the *old* value returns a strict **subset** of what B's
    /// own snapshot sees via the scan path: a silent false **negative** (an ACID-correctness defect;
    /// SSI deliberately does **not** abort B — this is not a serialization retry).
    ///
    /// # The marker (the airtight gate)
    ///
    /// `ft_spatial_trustworthy_from` is the timestamp **from and after which** a reader may TRUST the
    /// full-text/spatial index. A reader with `snapshot.ts >= effective_ft_spatial_marker()` uses the
    /// fast index path; a reader with `snapshot.ts < effective_ft_spatial_marker()` **declines to the
    /// scan path** (always correct — the scan re-reads the node's snapshot-visible value via MVCC).
    /// The *effective* marker (what readers compare against, [`effective_ft_spatial_marker`](Self::effective_ft_spatial_marker))
    /// is `u64::MAX` whenever an uncommitted full-text/spatial mutation is outstanding
    /// (`ft_spatial_inflight` non-empty) or the index was left potentially-stale by a rolled-back
    /// mutator (`ft_spatial_poisoned`); otherwise it is this committed value. See those fields and the
    /// marker methods for the full correctness argument.
    ft_spatial_trustworthy_from: Timestamp,
    /// The set of **currently-open transactions** that have at least one *uncommitted* structural
    /// full-text/spatial mutation in the index (`rmp` task #467). While this set is non-empty the
    /// [`effective_ft_spatial_marker`](Self::effective_ft_spatial_marker) is `u64::MAX`, so **every**
    /// reader (whose snapshot ts is always `< u64::MAX`) declines to the scan path — correct, because
    /// the index may reflect uncommitted state. A transaction is recorded here by
    /// [`note_ft_spatial_mutator`](Self::note_ft_spatial_mutator) (the statement seam, on a write that
    /// actually changed a registered posting) and removed by
    /// [`commit_ft_spatial_marker`](Self::commit_ft_spatial_marker) /
    /// [`rollback_ft_spatial_marker`](Self::rollback_ft_spatial_marker). Keyed by [`TxnId`] so the
    /// gate stays `u64::MAX` until **all** concurrent full-text/spatial mutators have retired — the
    /// property a single committed transaction's commit-ts cannot provide on its own.
    ft_spatial_inflight: BTreeSet<TxnId>,
    /// The subset of [`ft_spatial_inflight`](Self#structfield.ft_spatial_inflight) transactions that
    /// have **removed or replaced** at least one covered full-text/spatial posting — i.e. dropped an
    /// entry a still-committed node might need (`rmp` task #756). This is the discriminator that makes
    /// the rollback poison **conditional**: only a rolled-back *remove/replace* can drop a still-
    /// committed node from a posting it should occupy (a false negative the query-time re-check cannot
    /// resurrect), whereas a rolled-back pure *insert* leaves only a re-check-filterable false positive.
    ///
    /// A transaction is recorded here by [`note_ft_spatial_mutator`](Self::note_ft_spatial_mutator)
    /// (the statement seam) whenever a mutation actually *dropped or changed a pre-existing posting* —
    /// signalled by the transient
    /// [`ft_spatial_removed_dirty`](Self#structfield.ft_spatial_removed_dirty) flag, which the structural
    /// mutation methods raise **only** when the underlying `remove` / `remove_document` reported a real
    /// removal, or when a last-wins `index_*` reported the value actually **changed** (a different value,
    /// NOT an unchanged re-index — e.g. the wholesale re-index a write of an unrelated property triggers,
    /// which leaves the covered posting identical and must not poison on rollback). It is removed
    /// by [`commit_ft_spatial_marker`](Self::commit_ft_spatial_marker) (a committed remove/replace is
    /// correctly reflected — no poison) and by
    /// [`rollback_ft_spatial_marker`](Self::rollback_ft_spatial_marker) (which poisons iff the retiring
    /// txn is present here). By construction this is a subset of `ft_spatial_inflight` (every removal is
    /// also a posting change, so a remover is always also an in-flight mutator).
    ft_spatial_removers: BTreeSet<TxnId>,
    /// Whether a full-text/spatial mutator **rolled back after removing or replacing a covered posting**,
    /// possibly leaving the in-memory index with stale postings the query-time re-check cannot repair
    /// (`rmp` tasks #467, #756). A rolled-back *replace* or *delete* can drop a still-committed node from
    /// a posting it should occupy (a false negative the re-check cannot resurrect — unlike a rolled-back
    /// *insert*, which leaves only a re-check-filterable false positive, so it does **not** set this).
    /// Because the in-memory index is **not** transactional (an abort rolls back only the durable store,
    /// not these structures — see the `rmp` #410 note on [`seek_bitmap_eq`](Self::seek_bitmap_eq)), the
    /// only provably-correct response is to force every reader onto the always-correct scan path until the
    /// index is rebuilt to committed state. So this pins
    /// [`effective_ft_spatial_marker`](Self::effective_ft_spatial_marker) at `u64::MAX` until a full
    /// [`reset_ft_spatial_marker`](Self::reset_ft_spatial_marker) (driven by the coordinator's
    /// store-consistent rebuild) clears it. Conservative (it disables the fast path after a full-text/
    /// spatial-mutating rollback that dropped a posting) but never returns a wrong answer. It is set only
    /// via [`rollback_ft_spatial_marker`](Self::rollback_ft_spatial_marker) (a rolled-back remover) or
    /// [`poison_ft_spatial_marker`](Self::poison_ft_spatial_marker) (a faulted rebuild, `rmp` #733).
    ft_spatial_poisoned: bool,
    /// How many times [`ft_spatial_poisoned`](Self#structfield.ft_spatial_poisoned) has gone
    /// clean→poisoned over this set's life (`rmp` task #803) — monotonic. See
    /// [`ft_spatial_poison_events`](Self::ft_spatial_poison_events).
    ft_spatial_poison_events: u64,
    /// Whether the **label** [`TokenIndex`] ([`labels`](Self#structfield.labels)) may be trusted as the
    /// authoritative candidate source for a label scan (`rmp` task #733).
    ///
    /// The label index underpins **every** fallback in the engine: `scan_nodes_by_label` is what an
    /// index seek degrades *to*, and what `MATCH (n:Label)` compiles to. Unlike the property indexes it
    /// carries no per-index [`IndexState`] — it is not declared, it simply exists — so nothing else could
    /// express "this is not usable". That made it the deepest instance of the empty-but-trusted hazard:
    /// [`clear`](Self::clear) empties it at the start of a rebuild, so a rebuild whose store scan then
    /// faulted left it **empty and trusted**, and every label scan in the process returned ZERO ROWS —
    /// including the very scan fallbacks that are supposed to rescue the other index kinds.
    ///
    /// `false` makes the label-scan seam bypass the index and enumerate the store directly
    /// (`scan_node_ids` + the per-node inline label bitmap re-check — exactly what the standalone,
    /// index-free path does), which is always correct, just unaccelerated. Set by
    /// [`fail_closed`](Self::fail_closed); restored by [`clear`](Self::clear), which every rebuild calls
    /// immediately before refilling the index.
    labels_usable: bool,
    /// Whether the build currently filling this index **skipped an entity it could not read**
    /// (`rmp` task #733).
    ///
    /// The per-entity indexing helpers (`TxnCoordinator::index_one_node` and friends) are *best-effort*:
    /// a read fault on one node or relationship skips it and carries on. That stance is sound for a
    /// **populated** index — a missing candidate merely degrades that entity to a re-check — but it is
    /// **not** sound for the entity's presence in the index at all: a seek can only *drop* candidates
    /// the index returns, never resurrect one it never returned. A node skipped by the rebuild is
    /// therefore missing from the label index (invisible to every `MATCH (n:Label)`) and from every
    /// property index (invisible to every seek) for the life of the process — a committed row silently
    /// lost to queries.
    ///
    /// So the helpers now *record* the gap here instead of hiding it, and the build that drove them
    /// refuses to publish an index it knows is incomplete: a full rebuild goes
    /// [`fail_closed`](Self::fail_closed), and an incremental build declines to promote itself `Online`.
    /// Cleared by [`clear`](Self::clear) (a fresh rebuild starts clean) and by
    /// [`clear_rebuild_gap`](Self::clear_rebuild_gap).
    rebuild_gap: bool,
    /// How many times a VECTOR index has **entered** the blocked (exact-brute-force-scan) state over
    /// this set's life (`rmp` task #780) — monotonic, counted on the empty→non-empty blocker-list edge
    /// so one build blocked by five writers is one event, not five.
    ///
    /// This exists for the same reason [`fail_closed_events`](Self#structfield.fail_closed_events)
    /// does, and the #733 comment there states it best: a silent degradation is indistinguishable from
    /// a healthy-but-slow engine. A blocked vector index keeps reporting `ONLINE` while every k-NN it
    /// serves costs `O(covered entities x dim)` instead of an ANN descent, so the transition has to be
    /// observable. The server samples this to log the entry at `WARN` and drive a counter.
    vector_conflict_events: u64,
    /// Whether the build currently filling a **single-value-per-entity** index (full-text — and, by
    /// #779/#780, spatial/vector) observed that an **in-flight** transaction holds the NEWEST version of
    /// a covered property on some entity it visited (`rmp` task #778). Unlike [`rebuild_gap`], which
    /// reports a read *fault*, this reports a live *conflict*: a newest-wins build would bake that
    /// uncommitted value and index the committed one nowhere (the #766 loss), and — because the
    /// full-text consumer re-checks visibility + label but NOT the term — the reader cannot repair it.
    ///
    /// The signal is the same seam→coordinator channel as [`rebuild_gap`]: the per-entity build helper
    /// records it here, and the build driver reacts by NOT promoting the index to `Online` — it stays
    /// `Populating`, so every reader declines to the snapshot-correct scan fallback until the writer
    /// commits or aborts (option (b), poison-on-build). Distinct from `rebuild_gap` because a *fault*
    /// must fail the whole rebuild closed, whereas a *conflict* is transient and clears when the writer
    /// resolves. Cleared by [`clear`](Self::clear) and [`clear_ft_build_conflict`](Self::clear_ft_build_conflict).
    ///
    /// This holds the **blocking writers** rather than a bare flag, and non-emptiness IS the flag
    /// ([`ft_build_conflict`](Self::ft_build_conflict)) so the two can never disagree. The ids are what
    /// makes the resurrection *cheap*: the driver re-drives the build when — and only when — every writer
    /// recorded here has resolved, instead of re-scanning the store on every command for as long as any
    /// transaction happens to be open.
    ft_build_conflict_writers: Vec<TxnId>,
    /// The writers whose resolution must re-drive a **whole-set rebuild**, because that rebuild demoted
    /// the full-text indexes via [`demote_fulltext_for_conflict`](Self::demote_fulltext_for_conflict)
    /// (`rmp` task #778). Set and cleared only by
    /// [`rebuild_index`](crate::coordinator::TxnCoordinator), and read only by its resurrection.
    ///
    /// Deliberately a SECOND slot rather than a re-read of
    /// [`ft_build_conflict_writers`](Self#structfield.ft_build_conflict_writers), which is a *transient
    /// per-pass channel* from the per-entity helpers to whichever driver is currently running — and the
    /// chunked node build clears it on every chunk. Sharing one slot between the two drivers let a node
    /// build's chunk wipe the rebuild's record, after which nothing would ever re-drive the rebuild and
    /// the demoted indexes stayed `Populating` for the life of the process: answers still correct, but
    /// permanently unaccelerated, with no way back.
    ft_demoted_blockers: Vec<TxnId>,
    /// `(label, property)` pairs whose selectivity histogram a `db.resampleIndex` /
    /// `db.resampleOutdatedIndexes` has **asked** to have recomputed (`rmp` task #572), oldest first.
    ///
    /// The same seam→coordinator signalling channel as [`rebuild_gap`](Self#structfield.rebuild_gap):
    /// the per-statement seam records here, and the coordinator's
    /// `advance_index_builds` drain reads it — because only the coordinator can mint the transaction
    /// the recompute must run in. The procedure cannot do the work itself: it holds the **caller's**
    /// transaction, and a catalog mutation staged there is exactly what must not happen (see
    /// `TxnCoordinator::seed_index_histogram`).
    ///
    /// Deliberately **not** cleared by [`clear`](Self::clear) / [`fail_closed`](Self::fail_closed),
    /// unlike `rebuild_gap`: a request is a user's instruction, not state derived from the trees, and a
    /// rebuild has no business silently dropping it. The recompute reads the **store**, so it is
    /// unaffected by a wiped index set.
    pending_resamples: VecDeque<(String, String)>,
    /// How many times this index set has been **wiped** by [`fail_closed`](Self::fail_closed)
    /// (`rmp` task #733) — an epoch counter that invalidates work computed against a previous epoch.
    ///
    /// The incremental index builds live in the **coordinator** (`pending_builds` and friends), not
    /// here, so `fail_closed` cannot reach them: it can empty a half-built tree, but it cannot tell the
    /// build that its progress is gone. Without this counter an in-flight build resumed **from its old
    /// cursor** over a now-empty tree, indexed only the TAIL of its snapshot, and promoted itself
    /// `Online` holding a fraction of the rows — an `Online` index missing committed rows, which is
    /// exactly the state `rmp` #733 exists to make impossible. (Worse than a wrong query: the
    /// uniqueness / node-key duplicate checks trust that tree as an EXACT candidate source, so a hole in
    /// it lets a `IS UNIQUE` constraint accept a duplicate.) The full-text and spatial builds escaped
    /// only by accident, via the `rmp` #467 marker poison; the node-property B-tree has no such marker.
    ///
    /// Each pending build records the epoch it is indexing into; when it observes a different epoch it
    /// restarts from cursor `0` over the same snapshot. Restarting is sound: the snapshot only ever
    /// needed to cover the rows that existed at build start, and writes since then are maintained by
    /// [`RecordStoreGraph::reindex_node`](crate::record_graph), which gates on *registration* (which
    /// `fail_closed` preserves for the state-carrying kinds), not on state. Re-indexing a node that is
    /// already in the tree is idempotent.
    wipe_generation: u64,
    /// How many times [`fail_closed`](Self::fail_closed) has fired over this index set's life
    /// (`rmp` task #733) — the observability counter. A fail-closed is a **serious** event (a storage
    /// fault made the derived indexes untrustworthy and the engine dropped to scans), so the server
    /// polls this to log it at `ERROR` and expose it as a metric: silent degradation would otherwise
    /// look identical to a healthy-but-slow engine.
    fail_closed_events: u64,
    /// Whether the index set is currently **degraded** — wiped by [`fail_closed`](Self::fail_closed)
    /// and not yet repaired by a successful rebuild (`rmp` task #733). Read by the engine so it can
    /// retry the rebuild (self-healing rather than staying degraded until restart), and by the schema
    /// surfaces so `SHOW INDEXES` reports the **effective** state instead of the durable catalog's
    /// stale `ONLINE`. Cleared by [`heal`](Self::heal), which a rebuild calls once it completes with no
    /// gap.
    degraded: bool,
    /// The store snapshot timestamp from which the **stale-retaining candidate trees** are a faithful
    /// image of committed state — i.e. the high-water stamped by the last [`clear`](Self::clear)-and-
    /// refill rebuild (`rmp` tasks #755 / #765). A reader with
    /// `snapshot.ts >= rebuilt_trees_trustworthy_from` may be served a seek; an **older** reader must
    /// decline to the exact scan.
    ///
    /// # Which trees this covers, and why exactly these (`rmp` #765)
    ///
    /// The four trees that are **stale-retaining** (insert-only per entry, so an overwritten value's OLD
    /// entry survives) over **MVCC-versioned** values (`rmp` #50: newest-**visible**-wins, so an older
    /// reader's visible value can BE that old one): `node_props`, `rel_props`, `composite`,
    /// `rel_composite`. For these, and only these, a wholesale wipe + newest-wins refill destroys an
    /// entry an older reader is genuinely entitled to, and the per-candidate re-check can only REMOVE
    /// candidates, never resurrect a missing one. One watermark serves all four because
    /// [`clear`](Self::clear) wipes them together and the rebuild stamps one high-water.
    ///
    /// The other trees `clear` empties need no gate, each for a positive reason. The common thread: they
    /// are **destructive per entry** (a rewrite/remove drops the old entry as the write happens), so the
    /// live tree already holds only current state and the newest-wins refill REPRODUCES it — the rebuild
    /// destroys nothing a reader could still be owed.
    /// * **full-text / spatial / text** — destructive per entry, and additionally gated by the
    ///   poisonable [`ft_spatial_trustworthy_from`](Self#structfield.ft_spatial_trustworthy_from) marker
    ///   (`rmp` #467/#756), which a plain watermark could not replace: a rolled-back remove/replace can
    ///   strip a still-committed entity from a posting, so they need poisoning, not just an ordering.
    /// * **`vector`** — destructive per entry (`VectorIndex` is id-keyed: an insert for an existing id
    ///   REPLACES it, and `remove` drops it), so the refill reproduces the live graph exactly. NOTE it is
    ///   gated only by `IndexState::Online` (`rmp` #733), NOT by the #467 marker — do not assume it is.
    /// * **`labels`** — stale-RETAINING, and `clear` does **not** empty it at all (`rmp` task #771), so
    ///   there is nothing for a watermark to gate: the refill only ever ADDS. It needs that exemption
    ///   rather than a watermark because labels are mutated IN PLACE, so the refill's only source is
    ///   the CURRENT bitmap and it cannot reproduce a committed label an uncommitted writer has
    ///   removed — see [`clear`](Self::clear) for the full argument. Since `rmp` #767 that retention
    ///   is also the ONLY defence left: the per-candidate re-check is now snapshot-isolated, so it no
    ///   longer independently rejects a stale entry an older reader may genuinely need.
    ///
    ///   This entry used to claim the opposite — that emptying `labels` was safe because "any entry the
    ///   refill drops is one the re-check would have rejected anyway", so "the rebuild changes no
    ///   answer". That was FALSE, and it was the #771 defect: it holds only at the refill INSTANT, and
    ///   the record's bitmap changes BACK when the writer rolls back, at which point the re-check would
    ///   have accepted the entry the refill had already destroyed.
    /// * **`bitmap`** — membership-EXACT (maintained by remove-then-reinsert, `rmp` #453), so the refill
    ///   reproduces exactly what the live bitmap already held. It also has no *planner* consumer (only
    ///   `TxnCoordinator::bitmap_seek_eq` / `bitmap_conjunction`, a documented test/diagnostic surface),
    ///   so no query path reaches it.
    ///
    /// `0` (the default) means "never rebuilt": the trees are then purely append-only and every reader
    /// may be served.
    ///
    /// # Read by BOTH seams
    ///
    /// Every reader of these trees consults this watermark, at whichever seam it reads from:
    /// [`capture_node_property_eq`](Self::capture_node_property_eq) declines to build a capture for the
    /// off-thread `ReadOnlyGraph`, and `RecordStoreGraph`'s inline seeks decline against the live trees.
    /// Both fall back to the exact scan. A seam that reads one of these trees without consulting this
    /// field re-opens `rmp` #765 (committed-row loss) on that seam.
    rebuilt_trees_trustworthy_from: Timestamp,
    /// Transient "a registered full-text/spatial posting changed during the current statement" flag,
    /// set by the structural mutation methods and consumed by
    /// [`note_ft_spatial_mutator`](Self::note_ft_spatial_mutator) (the statement seam, which knows the
    /// [`TxnId`]) / cleared by [`clear_ft_spatial_dirty`](Self::clear_ft_spatial_dirty) (the rebuild /
    /// online-build path, whose insertions reflect *committed* state and must not be attributed to any
    /// open transaction) (`rmp` task #467). It exists because the mutation methods' signatures carry no
    /// `TxnId`, so they cannot record set membership themselves; they flag dirtiness here and the seam
    /// converts it to a [`ft_spatial_inflight`](Self#structfield.ft_spatial_inflight) entry.
    ft_spatial_dirty: bool,
    /// Transient companion to [`ft_spatial_dirty`](Self#structfield.ft_spatial_dirty) that additionally
    /// records that the current statement's full-text/spatial mutation **dropped or changed a
    /// pre-existing posting** (a remove, or a last-wins re-index to a DIFFERENT value), not merely added
    /// a new one or re-indexed an UNCHANGED value (`rmp` task #756). Set by the structural mutation
    /// methods **only** when the underlying structure reported a real removal (its `remove` /
    /// `remove_document` returned `true`) or an actual value change (a last-wins `index_*` returned
    /// `true`), and consumed by [`note_ft_spatial_mutator`](Self::note_ft_spatial_mutator) into
    /// [`ft_spatial_removers`](Self#structfield.ft_spatial_removers) / cleared by
    /// [`clear_ft_spatial_dirty`](Self::clear_ft_spatial_dirty) — mirroring `ft_spatial_dirty` exactly.
    ///
    /// **Invariant:** every site that sets this also sets `ft_spatial_dirty` (a removal is always a
    /// posting change), so `removed ⇒ dirty`. This is what lets the poison stay off for a rolled-back
    /// pure insert (a brand-new node's `CREATE`, which drops nothing) while still failing closed for a
    /// rolled-back remove/replace of a still-committed node.
    ft_spatial_removed_dirty: bool,
}

/// A declared constraint's in-memory rule (`rmp` tasks #99, #100): the covered label token, the
/// covered property tokens (one for `Unique`/`Existence`/`PropertyType`, one-or-more for a composite
/// `NodeKey`), the [`ConstraintKind`] and (for a property-type constraint) the declared type
/// descriptor. Mirrors the durable [`graphus_storage::ConstraintEntry`]; this is the value the
/// write-path enforcement consults.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConstraintRule {
    /// The label-namespace token the constraint covers.
    pub label_token: u32,
    /// The property-key tokens the constraint covers, in declared order (exactly one except for a
    /// composite node-key, which carries the whole tuple).
    pub property_tokens: Vec<u32>,
    /// Whether the constraint is a uniqueness, existence, node-key or property-type rule.
    pub kind: ConstraintKind,
    /// The declared value type of a [`ConstraintKind::PropertyType`] constraint (`rmp` task #100), or
    /// [`None`] for every other kind. Consulted by the write path to type-check the covered value.
    pub type_descriptor: Option<ConstraintTypeDescriptor>,
}

/// A declared node-property index plus its durable build [`IndexState`] (`rmp` task #90).
struct NodePropertyIndex {
    /// The backing in-memory property B+-tree.
    index: PropertyIndex<Dev, Sink>,
    /// The build state, mirrored from the durable catalog. Only an [`IndexState::Online`] index is
    /// surfaced to the planner; a [`IndexState::Populating`] one falls back to a scan + filter.
    state: IndexState,
}

/// A declared relationship-property index plus its durable build [`IndexState`] (`rmp` task #646) —
/// the relationship analogue of [`NodePropertyIndex`].
struct RelationshipPropertyIndex {
    /// The backing in-memory relationship-property B+-tree (keyed `(prop_key, value, rel_id)`).
    index: RelPropertyIndex<Dev, Sink>,
    /// The build state, mirrored from the durable catalog. Only an [`IndexState::Online`] index is
    /// surfaced to the planner / index-backed enforcement; a [`IndexState::Populating`] one is
    /// maintained but not yet exposed.
    state: IndexState,
}

/// A declared **node** full-text index plus its build [`IndexState`] and the in-memory inverted index
/// (`rmp` tasks #72, #663). The `label_tokens` + `prop_keys` + `analyzer` mirror the durable catalog
/// entry; the `index` is ephemeral (rebuilt from the store on open). A node carrying **any** of the
/// covered labels is indexed (Neo4j multi-label semantics — `rmp` #663 widened this from a single
/// label token).
struct FulltextEntry {
    /// The label-namespace tokens the index covers (one or more). A node with **any** of these labels
    /// is indexed (`rmp` task #663 multi-label semantics).
    label_tokens: Vec<u32>,
    /// The property-key tokens the index covers, in declared order (one or more).
    prop_keys: Vec<u32>,
    /// The analyzer applied at both index time and query time (same instance, by construction).
    analyzer: Analyzer,
    /// The build state, mirrored from the durable catalog. A [`IndexState::Populating`] index is
    /// maintained but not yet "complete"; a query still works against it (candidate-set contract).
    state: IndexState,
    /// The backing in-memory inverted index (term → sorted postings + forward map).
    index: InvertedIndex,
}

/// A declared **relationship** full-text index plus its build [`IndexState`] and the in-memory
/// inverted index (`rmp` task #663) — the relationship analogue of [`FulltextEntry`]. The
/// `type_tokens` + `prop_keys` + `analyzer` mirror the durable catalog entry; the `index` (whose
/// postings are **relationship** ids) is ephemeral (rebuilt from the store on open). A relationship of
/// **any** of the covered types is indexed (Neo4j multi-type semantics).
struct FulltextRelEntry {
    /// The relationship-type-namespace tokens the index covers (one or more). A relationship of **any**
    /// of these types is indexed.
    type_tokens: Vec<u32>,
    /// The property-key tokens the index covers, in declared order (one or more).
    prop_keys: Vec<u32>,
    /// The analyzer applied at both index time and query time (same instance, by construction).
    analyzer: Analyzer,
    /// The build state, mirrored from the durable catalog.
    state: IndexState,
    /// The backing in-memory inverted index — postings are **relationship** ids (`rmp` task #663).
    index: InvertedIndex,
}

/// A declared spatial index plus its build [`IndexState`] and the in-memory grid (`rmp` task #73).
/// The `(label_token, prop_key)` key (the map key) mirrors the durable catalog entry; the grid is
/// ephemeral (rebuilt from the store on open).
struct SpatialEntry {
    /// The build state, mirrored from the durable catalog. A `Populating` index is maintained but not
    /// yet surfaced to the planner; a query still works against it (candidate-set contract).
    state: IndexState,
    /// The backing in-memory uniform grid over the covered point property.
    index: SpatialIndex,
}

/// A declared text (trigram) index plus its build [`IndexState`] and the in-memory trigram index
/// (`rmp` task #662). The `(label_token, prop_key)` key (the map key) mirrors the durable catalog
/// entry; the trigram index is ephemeral (rebuilt from the store on open).
struct TextEntry {
    /// The build state, mirrored from the durable catalog. A `Populating` index is maintained but not
    /// yet surfaced to the planner; a query still works against it (candidate-set contract).
    state: IndexState,
    /// The backing in-memory trigram inverted index over the covered string property.
    index: TrigramIndex,
}

/// A declared vector (HNSW) index plus its build [`IndexState`] and the in-memory ANN graph
/// (`rmp` task #669). The `(token, prop_key)` key (the map key) mirrors the durable catalog entry; the
/// HNSW graph is ephemeral (rebuilt from the store on open).
struct VectorEntry {
    /// The build state, mirrored from the durable catalog. A `Populating` index is maintained but not
    /// yet surfaced to the planner; a query still works against it (candidate-set contract).
    state: IndexState,
    /// The backing in-memory HNSW approximate-nearest-neighbour graph over the covered embedding.
    index: VectorIndex,
    /// The still-unresolved transactions whose **uncommitted** embedding this graph's build had to
    /// skip (`rmp` task #780). Non-empty means the graph is **not trustworthy** for reads: the build
    /// collapsed the property chain newest-wins, and for these entities the newest version belonged to
    /// an active writer, so baking it would have indexed an uncommitted embedding and left the
    /// committed one indexed nowhere (the `rmp` #766 loss). While non-empty, every k-NN declines to the
    /// **exact brute-force scan** over snapshot-visible embeddings — vector is the one kind with no
    /// approximate fallback, and the exact scan is strictly MORE correct than the index path it
    /// replaces (it shares `graphus_index::similarity_score` with both the HNSW and the Cypher
    /// `vector.similarity.*` functions, so the scores are identical in scale).
    ///
    /// Cleared only by a successful conflict-free re-fill
    /// (`TxnCoordinator::retry_conflicted_vector_builds`), never by the writers merely resolving: the
    /// skipped entity is *missing* from the graph, and a k-NN can drop a candidate but never resurrect
    /// one, so resolution alone does not repair it.
    conflict_blockers: Vec<TxnId>,
}

/// Extracts a dense `f32` embedding of exactly `dim` elements from `value` (`rmp` task #669).
///
/// The value must be a [`Value::List`] of **finite** numbers ([`Value::Integer`] / [`Value::Float`])
/// of length `dim`. A value that is absent (handled by the caller), not a list, holds a non-numeric or
/// **non-finite** (`NaN` / ±∞) element, or has the wrong length yields [`None`] — the entity is then
/// simply **not indexed** (exactly like a node missing a covered property), never an error on the write
/// path. Rejecting non-finite values matches Neo4j (a vector with `NaN`/`Inf` is not a valid embedding)
/// and keeps the HNSW distance order well-defined (a `NaN` distance would otherwise rank first under the
/// `total_cmp` result ordering; `rmp` #669 storage-audit follow-up).
pub(crate) fn extract_embedding(value: &Value, dim: usize) -> Option<Vec<f32>> {
    let Value::List(items) = value else {
        return None;
    };
    if items.len() != dim {
        return None;
    }
    let mut out = Vec::with_capacity(dim);
    for item in items {
        let x = match item {
            Value::Integer(i) => *i as f32,
            Value::Float(f) => *f as f32,
            _ => return None, // a non-numeric element makes the whole list an invalid embedding.
        };
        if !x.is_finite() {
            return None; // NaN / ±∞ is not a valid embedding (Neo4j parity) — leave the entity unindexed.
        }
        out.push(x);
    }
    Some(out)
}

/// A deterministic HNSW seed for the vector index on `(token, prop_key)` (`rmp` task #669).
///
/// The durable catalog does not persist a seed (it is an internal build detail), so the seed is derived
/// from the index's identity. This makes an index's graph **reproducible across a reopen** (the rebuild
/// re-inserts the same nodes in id order with the same seed), and gives two distinct indexes distinct
/// graphs. The ANN query is approximate, so the exact graph shape never affects correctness — only the
/// determinism the project's tests and simulator rely on.
#[must_use]
fn vector_seed(token: u32, prop_key: u32) -> u64 {
    (u64::from(token) << 32) | u64::from(prop_key)
}

/// Whether `v` can be encoded into an order-preserving index key — the same
/// [`keycodec::encode_single`](graphus_index::keycodec::encode_single) fallibility the backing
/// [`PropertyIndex`] applies at insert and seek time.
///
/// The one **comparable-but-unindexable** value class is [`Value::List`]: Cypher *compares* two lists
/// (`compare_values` is defined on them), yet a list is not a legal index key, so a list-valued
/// property is silently skipped at insert and a list *bound* cannot be encoded for a seek. (`Null` and
/// `Map` are also unindexable but are *incomparable*, so both the index seek and the scan re-check
/// return empty for them — harmless either way; this still declines on them for good measure.)
///
/// A seek whose bound is not index-encodable MUST return [`None`] so the caller takes the **exact scan
/// fallback**: otherwise the seam collapses the un-encodable bound to an empty candidate set
/// (`Some(vec![])`), the executor uses it verbatim (the fallback fires only on `None`), and the index
/// silently drops rows the equivalent scan + `WHERE` keeps — an index changing a query's result, the
/// exact defect class `rmp` #680 exists to eliminate (found while certifying it).
fn is_index_encodable(v: &Value) -> bool {
    graphus_index::keycodec::encode_single(v).is_ok()
}

impl IndexSet {
    /// An empty index set: a single label [`TokenIndex`] (always present, auto-maintained) and no
    /// property indexes yet.
    #[must_use]
    pub fn new() -> Self {
        Self {
            labels: TokenIndex::new(fresh_tree()),
            node_props: HashMap::new(),
            rel_props: HashMap::new(),
            fulltext: HashMap::new(),
            fulltext_rel: HashMap::new(),
            spatial: HashMap::new(),
            spatial_rel: HashMap::new(),
            text: HashMap::new(),
            vector: HashMap::new(),
            vector_rel: HashMap::new(),
            constraints: HashMap::new(),
            composite: HashMap::new(),
            rel_composite: HashMap::new(),
            rel_equality_declared: HashMap::new(),
            bitmap: HashMap::new(),
            bitmap_declared: BTreeSet::new(),
            dirty_bitmap_nodes: HashMap::new(),
            // A fresh label index is consistent with a fresh (empty) store, so it is usable; only a
            // failed rebuild makes it untrustworthy (`rmp` task #733).
            labels_usable: true,
            rebuild_gap: false,
            vector_conflict_events: 0,
            ft_build_conflict_writers: Vec::new(),
            ft_demoted_blockers: Vec::new(),
            pending_resamples: VecDeque::new(),
            wipe_generation: 0,
            fail_closed_events: 0,
            degraded: false,
            // Never rebuilt: the trees are purely append-only, so every reader may be served.
            rebuilt_trees_trustworthy_from: Timestamp::default(),
            // A fresh, empty index reflects committed state at the genesis timestamp: there is nothing
            // indexed and no mutator in flight, so every reader may trust it (`ts >= 0` always holds).
            ft_spatial_trustworthy_from: Timestamp(0),
            ft_spatial_inflight: BTreeSet::new(),
            ft_spatial_removers: BTreeSet::new(),
            ft_spatial_poisoned: false,
            ft_spatial_poison_events: 0,
            ft_spatial_dirty: false,
            ft_spatial_removed_dirty: false,
        }
    }

    /// Declares a node-property index on `(label_token, prop_key)` at [`IndexState::Online`].
    /// Idempotent: a no-op if one is already registered (its state is left unchanged), otherwise
    /// creates the backing [`PropertyIndex`].
    ///
    /// This is the convenience entry point for callers that build an index synchronously and have no
    /// `Populating` phase. The state-aware [`register_node_property_with_state`](Self::register_node_property_with_state)
    /// is the path the durable catalog (`rmp` task #90) drives.
    pub fn register_node_property(&mut self, label_token: u32, prop_key: u32) {
        self.register_node_property_with_state(label_token, prop_key, IndexState::Online);
    }

    /// Declares a node-property index on `(label_token, prop_key)` at `state` (`rmp` task #90).
    /// Idempotent on the key: if one is already registered its backing tree is kept, but its state is
    /// updated to `state` (so a recovered `Online` declaration promotes a freshly-created entry).
    pub fn register_node_property_with_state(
        &mut self,
        label_token: u32,
        prop_key: u32,
        state: IndexState,
    ) {
        self.node_props
            .entry((label_token, prop_key))
            .and_modify(|np| np.state = state)
            .or_insert_with(|| NodePropertyIndex {
                index: PropertyIndex::new(fresh_tree()),
                state,
            });
    }

    /// Sets the build [`IndexState`] of an already-registered `(label_token, prop_key)` index
    /// (`rmp` task #90), e.g. promoting `Populating` → `Online` after a synchronous build. A no-op if
    /// no such index is registered.
    pub fn set_node_property_state(&mut self, label_token: u32, prop_key: u32, state: IndexState) {
        if let Some(np) = self.node_props.get_mut(&(label_token, prop_key)) {
            np.state = state;
        }
    }

    /// Unregisters the node-property index on `(label_token, prop_key)`, dropping its backing tree and
    /// all its entries (`rmp` task #91, `DROP INDEX`). A no-op if no such index is registered. After
    /// this the pair is no longer maintained, no longer answers a seek, and is absent from
    /// [`registered_node_properties`](Self::registered_node_properties) /
    /// [`online_node_properties`](Self::online_node_properties).
    pub fn unregister_node_property(&mut self, label_token: u32, prop_key: u32) {
        self.node_props.remove(&(label_token, prop_key));
    }

    /// Whether a node-property index is registered for `(label_token, prop_key)` (in **any** state).
    #[must_use]
    pub fn has_node_property(&self, label_token: u32, prop_key: u32) -> bool {
        self.node_props.contains_key(&(label_token, prop_key))
    }

    /// The build [`IndexState`] of the `(label_token, prop_key)` index, or [`None`] if unregistered
    /// (`rmp` task #90).
    #[must_use]
    pub fn node_property_state(&self, label_token: u32, prop_key: u32) -> Option<IndexState> {
        self.node_props
            .get(&(label_token, prop_key))
            .map(|np| np.state)
    }

    // ---- RelEquality marker reachability gate (`rmp` #683) -------------------------------------

    /// Records that a reader could, from now on, register a [`PredicateRead::RelEquality`] marker over
    /// `(type_token, prop_key)` (`rmp` #683). Monotone: never undone. See
    /// [`rel_equality_declared`](Self::rel_equality_declared).
    fn note_rel_equality_declared(&mut self, type_token: u32, prop_key: u32) {
        self.rel_equality_declared
            .entry(type_token)
            .or_default()
            .insert(prop_key);
    }

    /// Whether **any** relationship `(type, property)` in this store could have a `RelEquality` marker
    /// held against it (`rmp` #683). The O(1) outermost gate: a store with no relationship-property
    /// index and no relationship uniqueness/key constraint pays **nothing** on its relationship writes —
    /// not even the record read needed to learn the relationship's type.
    #[must_use]
    pub fn rel_equality_any_declared(&self) -> bool {
        !self.rel_equality_declared.is_empty()
    }

    /// Whether a reader could hold a `RelEquality` marker over `(type_token, prop_key)` (`rmp` #683).
    /// `false` ⇒ the writer's announcement for that property is provably inert and may be skipped.
    #[must_use]
    pub fn rel_equality_marker_possible(&self, type_token: u32, prop_key: u32) -> bool {
        self.rel_equality_declared
            .get(&type_token)
            .is_some_and(|props| props.contains(&prop_key))
    }

    /// Whether a reader could hold a `RelEquality` marker over **any** property of `type_token`
    /// (`rmp` #683). Gates the wholesale pre-image announcements (`delete_rel`,
    /// `replace_rel_properties`), which would otherwise decode the whole property chain.
    #[must_use]
    pub fn rel_equality_possible_for_type(&self, type_token: u32) -> bool {
        self.rel_equality_declared.contains_key(&type_token)
    }

    // ---- Constraints (`rmp` task #99) ---------------------------------------------------------

    /// Registers (or replaces) the constraint named `name` over `(label_token, property_tokens)` of
    /// `kind`, carrying the property-type `type_descriptor` for a [`ConstraintKind::PropertyType`]
    /// (`None` for every other kind) (`rmp` tasks #99, #100). Idempotent on the name: re-registering
    /// overwrites the rule. Holds no backing tree itself — a uniqueness constraint reuses the
    /// node-property index, a node-key constraint reuses the composite index; this map only records
    /// *which* rules the write path must enforce.
    pub fn register_constraint(
        &mut self,
        name: &str,
        label_token: u32,
        property_tokens: Vec<u32>,
        kind: ConstraintKind,
        type_descriptor: Option<ConstraintTypeDescriptor>,
    ) {
        // Feed the `RelEquality` reachability gate (`rmp` #683): a relationship uniqueness / KEY rule
        // makes the write-path enforcement reader (`rel_unique_conflict` / `rel_composite_seek_eq`)
        // register a marker over every covered `(type, property)`, so writers must announce for those
        // pairs from now on. Only these two kinds have such a reader — `RelExistence` /
        // `RelPropertyType` are pure per-relationship predicates that read no equality predicate — and
        // the node kinds do not touch this gate at all.
        if matches!(kind, ConstraintKind::RelUnique | ConstraintKind::RelKey) {
            for &prop_key in &property_tokens {
                self.note_rel_equality_declared(label_token, prop_key);
            }
        }
        self.constraints.insert(
            name.to_owned(),
            ConstraintRule {
                label_token,
                property_tokens,
                kind,
                type_descriptor,
            },
        );
    }

    // ---- Composite indexes (`rmp` task #100, node-key backing) --------------------------------

    /// Declares a composite index over `(label_token, property_tokens)` if absent (`rmp` task #100).
    /// Idempotent on the key: a no-op if one is already registered (its entries are kept). The backing
    /// [`CompositeIndex`] keys on the property tuple; the node-key write-path uniqueness check seeks it.
    ///
    /// # Panics
    /// Panics if `property_tokens` is empty (a node key covers at least one property — the surface and
    /// the durable catalog both enforce this before reaching here).
    pub fn register_composite(&mut self, label_token: u32, property_tokens: Vec<u32>) {
        assert!(
            !property_tokens.is_empty(),
            "composite index needs at least one property"
        );
        let arity = property_tokens.len();
        self.composite
            .entry((label_token, property_tokens))
            .or_insert_with(|| CompositeIndex::new(fresh_tree(), arity));
    }

    /// Unregisters the composite index over `(label_token, property_tokens)`, dropping its backing tree
    /// (`rmp` task #100, `DROP CONSTRAINT` of a node key). A no-op if absent.
    pub fn unregister_composite(&mut self, label_token: u32, property_tokens: &[u32]) {
        self.composite
            .remove(&(label_token, property_tokens.to_vec()));
    }

    /// Whether a composite index is registered for `(label_token, property_tokens)` (`rmp` task #100).
    #[must_use]
    pub fn has_composite(&self, label_token: u32, property_tokens: &[u32]) -> bool {
        self.composite
            .contains_key(&(label_token, property_tokens.to_vec()))
    }

    /// The registered composite-index keys `(label_token, property_tokens)`, ascending and
    /// de-duplicated (`rmp` task #100). Used by the coordinator's index rebuild to know which composite
    /// tuples to (re)index for each node.
    #[must_use]
    pub fn registered_composite(&self) -> Vec<(u32, Vec<u32>)> {
        let mut keys: Vec<(u32, Vec<u32>)> = self.composite.keys().cloned().collect();
        keys.sort_unstable();
        keys
    }

    /// Records that node `node_id` has the composite tuple `values` for the `(label_token,
    /// property_tokens)` composite index, if such an index is registered (else a no-op) (`rmp` task
    /// #100). The whole tuple must be present and non-null — a node missing any covered property is not
    /// indexed (and is therefore not a uniqueness candidate, matching the node-key existence rule).
    pub fn insert_composite(
        &mut self,
        label_token: u32,
        property_tokens: &[u32],
        values: &[Value],
        node_id: u64,
    ) {
        if let Some(idx) = self
            .composite
            .get_mut(&(label_token, property_tokens.to_vec()))
        {
            // The synthetic per-index token is `label_token` (the map key already partitions by the
            // full tuple, so any fixed token is sufficient). An in-memory composite op cannot fail in
            // practice; a failure leaves the entry absent (the caller re-checks via a scan fallback,
            // degrading to correctness, never to a wrong answer).
            let _ = idx.insert(EPHEMERAL_TXN, label_token, values, node_id);
        }
    }

    /// Candidate node ids whose composite tuple for `(label_token, property_tokens)` equals `values`,
    /// ascending (`rmp` task #100). [`None`] if no such composite index is registered; otherwise a
    /// candidate set the caller re-checks (visibility, current label, current tuple). `Some(vec![])` —
    /// "registered but no candidate" — is distinct from `None`.
    pub fn seek_composite_eq(
        &mut self,
        label_token: u32,
        property_tokens: &[u32],
        values: &[Value],
    ) -> Option<Vec<u64>> {
        let idx = self
            .composite
            .get_mut(&(label_token, property_tokens.to_vec()))?;
        // If ANY key value is not index-encodable (a `List`), decline the whole composite seek so the
        // caller takes the exact scan fallback (`rmp` #680; see [`is_index_encodable`]).
        if !values.iter().all(is_index_encodable) {
            return None;
        }
        Some(idx.seek_eq(label_token, values).unwrap_or_default())
    }

    // ---- Composite (multi-property) relationship indexes (`rmp` task #666) ------------------------
    // Structural twins of the node composite methods above, keyed by `(type_token, property_tokens)`
    // and kept in the separate `rel_composite` map. Same candidate-vs-answer contract (a seek returns a
    // superset the caller re-checks against the store).

    /// Declares a composite relationship index over `(type_token, property_tokens)` if absent
    /// (`rmp` task #666). Idempotent on the key: a no-op if one is already registered (its entries are
    /// kept). The backing [`CompositeIndex`] keys on the property tuple; the relationship composite seek
    /// probes it.
    ///
    /// # Panics
    /// Panics if `property_tokens` is empty (a composite relationship index covers at least one property
    /// — the surface and the durable catalog both enforce this before reaching here).
    pub fn register_rel_composite(&mut self, type_token: u32, property_tokens: Vec<u32>) {
        assert!(
            !property_tokens.is_empty(),
            "composite relationship index needs at least one property"
        );
        // Feed the `RelEquality` reachability gate (`rmp` #683): `rel_composite_seek_eq` registers one
        // per-component marker for every covered property, so writers must announce for each.
        for &prop_key in &property_tokens {
            self.note_rel_equality_declared(type_token, prop_key);
        }
        let arity = property_tokens.len();
        self.rel_composite
            .entry((type_token, property_tokens))
            .or_insert_with(|| CompositeIndex::new(fresh_tree(), arity));
    }

    /// Unregisters the composite relationship index over `(type_token, property_tokens)`, dropping its
    /// backing tree (`rmp` task #666, `DROP INDEX`). A no-op if absent.
    pub fn unregister_rel_composite(&mut self, type_token: u32, property_tokens: &[u32]) {
        self.rel_composite
            .remove(&(type_token, property_tokens.to_vec()));
    }

    /// Whether a composite relationship index is registered for `(type_token, property_tokens)`
    /// (`rmp` task #666).
    #[must_use]
    pub fn has_rel_composite(&self, type_token: u32, property_tokens: &[u32]) -> bool {
        self.rel_composite
            .contains_key(&(type_token, property_tokens.to_vec()))
    }

    /// Whether **any** composite relationship index is registered (`rmp` task #666) — an O(1) gate the
    /// per-write maintenance path checks before decoding a relationship's property chain, so a store
    /// with no composite relationship index pays nothing for the maintenance hook.
    #[must_use]
    pub fn has_any_rel_composite(&self) -> bool {
        !self.rel_composite.is_empty()
    }

    /// The registered composite relationship-index keys `(type_token, property_tokens)`, ascending and
    /// de-duplicated (`rmp` task #666). Used by the coordinator's index rebuild to know which composite
    /// tuples to (re)index for each relationship.
    #[must_use]
    pub fn registered_rel_composite(&self) -> Vec<(u32, Vec<u32>)> {
        let mut keys: Vec<(u32, Vec<u32>)> = self.rel_composite.keys().cloned().collect();
        keys.sort_unstable();
        keys
    }

    /// Records that relationship `rel_id` has the composite tuple `values` for the `(type_token,
    /// property_tokens)` composite relationship index, if such an index is registered (else a no-op)
    /// (`rmp` task #666). The whole tuple must be present and non-null — a relationship missing any
    /// covered property is not indexed for that key (matching the node composite rule).
    pub fn insert_rel_composite(
        &mut self,
        type_token: u32,
        property_tokens: &[u32],
        values: &[Value],
        rel_id: u64,
    ) {
        if let Some(idx) = self
            .rel_composite
            .get_mut(&(type_token, property_tokens.to_vec()))
        {
            // The synthetic per-index token is `type_token` (the map key already partitions by the full
            // tuple, so any fixed token is sufficient). An in-memory composite op cannot fail in
            // practice; a failure leaves the entry absent (the caller re-checks via a scan fallback,
            // degrading to correctness, never to a wrong answer).
            let _ = idx.insert(EPHEMERAL_TXN, type_token, values, rel_id);
        }
    }

    /// Candidate relationship ids whose composite tuple for `(type_token, property_tokens)` equals
    /// `values`, ascending (`rmp` task #666). [`None`] if no such composite relationship index is
    /// registered; otherwise a candidate set the caller re-checks (visibility, current type, current
    /// tuple). `Some(vec![])` — "registered but no candidate" — is distinct from `None`.
    pub fn seek_rel_composite_eq(
        &mut self,
        type_token: u32,
        property_tokens: &[u32],
        values: &[Value],
    ) -> Option<Vec<u64>> {
        let idx = self
            .rel_composite
            .get_mut(&(type_token, property_tokens.to_vec()))?;
        // If ANY key value is not index-encodable (a `List`), decline to the exact scan fallback
        // (`rmp` #680; see [`is_index_encodable`]).
        if !values.iter().all(is_index_encodable) {
            return None;
        }
        Some(idx.seek_eq(type_token, values).unwrap_or_default())
    }

    /// Unregisters the constraint named `name`, if registered (`rmp` task #99, `DROP CONSTRAINT`). A
    /// no-op if absent. After this the rule is no longer enforced by the write path. The backing
    /// node-property index of a uniqueness constraint is **not** dropped here — the coordinator owns
    /// that decision (a property index may still be wanted for query routing).
    pub fn unregister_constraint(&mut self, name: &str) {
        self.constraints.remove(name);
    }

    /// Whether a constraint named `name` is registered (`rmp` task #99).
    #[must_use]
    pub fn has_constraint(&self, name: &str) -> bool {
        self.constraints.contains_key(name)
    }

    /// The **node** constraint rules that apply to `label_token` (`rmp` task #99): every registered
    /// node constraint whose covered label is `label_token`. Used by the write path to enforce only the
    /// relevant rules for a node carrying that label. The `!is_relationship()` guard is load-bearing
    /// (`rmp` #638): a relationship constraint's covering token is a relationship-**type** token whose
    /// numeric value can coincide with a node label token, so filtering by token value alone would
    /// wrongly apply a relationship rule to a node. Returned by value (cloned) so the caller does not
    /// hold the `IndexSet` borrow across the per-rule store re-checks.
    #[must_use]
    pub fn constraints_for_label(&self, label_token: u32) -> Vec<ConstraintRule> {
        self.constraints
            .values()
            .filter(|rule| rule.label_token == label_token && !rule.kind.is_relationship())
            .cloned()
            .collect()
    }

    /// The **relationship** constraint rules that apply to `type_token` (`rmp` #638): every registered
    /// relationship constraint whose covered relationship type is `type_token` — the relationship
    /// analogue of [`constraints_for_label`](Self::constraints_for_label). The `is_relationship()`
    /// guard keeps a node rule (whose label token could share the numeric value) from being applied to
    /// a relationship.
    #[must_use]
    pub fn constraints_for_rel_type(&self, type_token: u32) -> Vec<ConstraintRule> {
        self.constraints
            .values()
            .filter(|rule| rule.label_token == type_token && rule.kind.is_relationship())
            .cloned()
            .collect()
    }

    /// Every registered constraint as `(name, rule)`, ascending by name (deterministic) (`rmp` task
    /// #99). Used by `SHOW CONSTRAINTS`.
    #[must_use]
    pub fn registered_constraints(&self) -> Vec<(String, ConstraintRule)> {
        let mut out: Vec<(String, ConstraintRule)> = self
            .constraints
            .iter()
            .map(|(name, rule)| (name.clone(), rule.clone()))
            .collect();
        out.sort_by(|a, b| a.0.cmp(&b.0));
        out
    }

    /// Drops all entries from every index, keeping the registered `(label_token, prop_key)` set **and
    /// each one's state**, for a full rebuild from the store. Implemented by recreating each backing
    /// tree (the simplest correct reset for an ephemeral in-memory index).
    ///
    /// The constraint registry (`rmp` task #99) is left untouched: it holds *declarations*, not data,
    /// and a uniqueness constraint's data lives in the node-property index that `clear` resets above.
    ///
    /// # The `labels` tree is deliberately NOT reset (`rmp` task #771)
    ///
    /// Every other tree here is rebuilt from a source that can reproduce it. The label tree is not:
    /// **labels are mutated IN PLACE, with no version chain** (they live in the node record's inline
    /// bitmap), so the refill's only source is
    /// [`node_labels`](graphus_storage::RecordStore::node_labels) — the *current* bitmap, including
    /// every UNCOMMITTED change. The committed label set exists nowhere the refill can read it; it
    /// survives only in the WAL undo image. So a clear-then-refill run while a writer holds an
    /// uncommitted `REMOVE n:Label` writes a **subset**: the entry is destroyed, not re-inserted, and
    /// when that writer ROLLS BACK the record bit comes back but nothing brings the index entry back.
    /// `MATCH (n:Label)` then returned ZERO rows for a label the node demonstrably still carries —
    /// permanently, for the life of the process (`tests/index_rebuild_label.rs`).
    ///
    /// Retaining the tree is what makes the refill purely ADDITIVE, and additive is the only image this
    /// tree may hold, by the false-negative asymmetry the whole index set rests on: the re-check
    /// (via `read_source::filter_label_candidates`) can REMOVE a candidate but can never RESURRECT
    /// one. A retained stale entry is a false POSITIVE the re-check drops; a destroyed entry is a
    /// committed row silently lost.
    ///
    /// # Since `rmp` #767 this retention is the ONLY thing keeping the tree safe from #765
    ///
    /// That re-check used to test the CURRENT label bitmap, which made a dropped entry harmless *by
    /// itself*: the re-check would have rejected it anyway. #767 made label membership
    /// snapshot-isolated, so the re-check now tests the bitmap AS OF THE READER'S SNAPSHOT and an
    /// older reader can legitimately need a candidate the current bitmap no longer shows. The
    /// second, independent line of defence is therefore GONE, and additive retention is load-bearing
    /// on its own. Pruning this tree — the "cost of retaining" noted below is exactly the temptation —
    /// or re-enabling the wipe now costs a REAL lost row. Pinned by
    /// `tests/label_tree_765_reaudit_767.rs`.
    ///
    /// This corrects a claim this file used to make — that dropping label entries "changes no answer"
    /// because "any entry the refill drops is one the re-check would have rejected anyway". That holds
    /// only at the refill INSTANT. The record's bitmap can change BACK afterwards (a rollback restores
    /// it), and the re-check would then have ACCEPTED the very entry the refill dropped.
    ///
    /// The cost of retaining: nothing prunes a label entry whose node was since deleted or relabelled.
    /// That is not a new leak — this tree has **never** removed an entry (there is no `remove_label` on
    /// `IndexSet`; it is stale-retaining by design, see
    /// [`rebuilt_trees_trustworthy_from`](Self#structfield.rebuilt_trees_trustworthy_from)), and
    /// `clear` was only ever an incidental reclaim, one that was never sound. Entries are still
    /// reclaimed wholesale when the process
    /// re-opens the store (a fresh `IndexSet`). A correctness-preserving prune would have to know that
    /// no in-flight transaction could roll a label back, which nothing here can establish.
    pub fn clear(&mut self) {
        // The caller (a rebuild) is about to refill the label index from the store, so it becomes
        // trustworthy again — unless that rebuild fails, in which case `fail_closed` marks it unusable
        // (`rmp` task #733). Restoring it here is what lets a successful rebuild heal a prior failure.
        self.labels_usable = true;
        // A fresh rebuild starts with no known gap; the per-entity helpers raise it if they must skip an
        // entity they cannot read.
        self.rebuild_gap = false;
        // Likewise the transient full-text/spatial attribution flags (`rmp` task #803): the caller is
        // about to re-derive every posting from the committed store, so any bit left over from an
        // earlier path describes work that is being discarded. Mirrors `rebuild_gap` exactly.
        self.ft_spatial_dirty = false;
        self.ft_spatial_removed_dirty = false;
        // Likewise a fresh rebuild starts with no known active-writer conflict (`rmp` task #778); the
        // full-text helpers raise it if the newest version of a covered property is held by an in-flight
        // transaction.
        self.ft_build_conflict_writers.clear();
        // Likewise the demotion record: `rebuild_index` calls `clear` at its start and re-establishes
        // this from its own fresh pass, so carrying a previous pass's blockers forward would strand the
        // repair behind transactions that are no longer relevant.
        self.ft_demoted_blockers.clear();
        for np in self.node_props.values_mut() {
            np.index = PropertyIndex::new(fresh_tree());
        }
        // Relationship-property indexes (`rmp` task #646): recreate each backing tree to drop its
        // entries while keeping the registered `(rel_type_token, prop_key)` set + state, exactly like
        // the node-property indexes above.
        for rp in self.rel_props.values_mut() {
            rp.index = RelPropertyIndex::new(fresh_tree());
        }
        // Full-text indexes: drop the inverted-index entries but keep the registration + state
        // (`rmp` task #72), mirroring the node-property handling.
        for ft in self.fulltext.values_mut() {
            ft.index.clear();
        }
        // Relationship full-text indexes (`rmp` task #663): drop the rel-keyed inverted-index entries
        // but keep the registration + state, exactly like the node full-text indexes above.
        for ft in self.fulltext_rel.values_mut() {
            ft.index.clear();
        }
        // Spatial indexes: clear the grid entries, keep the registration + state (`rmp` task #73).
        for sp in self.spatial.values_mut() {
            sp.index.clear();
        }
        // Relationship spatial indexes (`rmp` task #664): clear the rel-keyed grid entries but keep the
        // registration + state, exactly like the node spatial indexes above.
        for sp in self.spatial_rel.values_mut() {
            sp.index.clear();
        }
        // Text (trigram) indexes: clear the trigram entries, keep the registration + state
        // (`rmp` task #662), exactly like the spatial index.
        for tx in self.text.values_mut() {
            tx.index.clear();
        }
        // Vector (HNSW) indexes: clear the ANN graph entries but keep the registration + state + build
        // parameters (`rmp` task #669), exactly like the spatial / text index. `VectorIndex::clear`
        // preserves the configured dimension / similarity / m / ef_construction.
        //
        // The per-index build blockers go WITH the entries (`rmp` task #780), for exactly the reason
        // `ft_demoted_blockers` above states: the caller is about to re-derive this graph from a fresh
        // store scan, and that scan re-records whatever conflicts are *currently* real. A blocker
        // carried across it names a transaction that pass never saw, so it strands the index on the
        // exact brute-force scan — and costs a redundant O(store) wipe + re-fill on the next drain to
        // undo. Missing this was a #780 audit finding: `register_vector`'s `and_modify` preserves the
        // blockers too, so `clear` is the only place that can drop them.
        for v in self.vector.values_mut() {
            v.index.clear();
            v.conflict_blockers.clear();
        }
        for v in self.vector_rel.values_mut() {
            v.index.clear();
            v.conflict_blockers.clear();
        }
        // Composite indexes (`rmp` task #100): recreate each backing tree to drop its entries while
        // keeping the registered `(label_token, property_tokens)` set, exactly like the property indexes.
        for (key, idx) in &mut self.composite {
            *idx = CompositeIndex::new(fresh_tree(), key.1.len());
        }
        // Composite relationship indexes (`rmp` task #666): recreate each backing tree to drop its
        // entries while keeping the registered `(type_token, property_tokens)` set, exactly like the
        // node composite indexes above.
        for (key, idx) in &mut self.rel_composite {
            *idx = CompositeIndex::new(fresh_tree(), key.1.len());
        }
        // Bitmap indexes (`rmp` task #328): drop the value→id bitmaps but keep the registered
        // `(label_token, prop_key)` set so the open-time rebuild re-captures exactly those columns.
        for bm in self.bitmap.values_mut() {
            *bm = BitmapIndex::new();
        }
        // A full rebuild re-derives every bitmap from the committed store, so any pending per-txn
        // abort-repair tracking (`rmp` #453) is moot — drop it so a stale txn id can never leak.
        self.dirty_bitmap_nodes.clear();
    }

    /// **Fail-closed**: makes every derived index unusable for reads after a rebuild could not be
    /// completed (`rmp` task #733).
    ///
    /// # The hazard this closes
    ///
    /// [`clear`](Self::clear) drops every index's *entries* but deliberately keeps its *registration
    /// and state*, because the caller ([`TxnCoordinator::rebuild_index`](crate::coordinator)) is about
    /// to refill it from a store scan. If that scan **fails** (a storage fault), the caller is left
    /// holding indexes that are registered, `Online` — and **empty**. An empty `Online` index is the
    /// worst possible state: the planner keeps routing seeks to it, the write-path uniqueness /
    /// node-key checks keep consulting it, and the full-text procedure keeps reading its postings — all
    /// of which then return **zero rows, silently**. Silent false negatives are an ACID-correctness
    /// defect (a committed row that a query cannot see), not a performance regression.
    ///
    /// # What it does
    ///
    /// Every index kind is made *unusable* rather than *empty*, so every consumer degrades to the
    /// always-correct store scan (the same fallback the `rmp` #467 stale-reader gate uses):
    ///
    /// - The **state-carrying** kinds (node/relationship property, node/relationship full-text,
    ///   node/relationship spatial, text, node/relationship vector) are demoted to
    ///   [`IndexState::Populating`]. That withholds them from the planner's catalog (`online_*`) and —
    ///   since `rmp` #733 — from every `RecordStoreGraph` read seam, which now declines to the scan
    ///   unless the index is `Online`.
    /// - The **state-less** candidate sources (node/relationship composite, bitmap) are
    ///   **unregistered**, because they have no state to demote and their consumers gate on
    ///   registration alone (`has_composite` / `has_bitmap`). Leaving an empty composite registered
    ///   would silently break node-key duplicate detection, which trusts it as an exact candidate
    ///   source.
    /// - The cross-snapshot full-text/spatial marker is **poisoned**, so even a reader that somehow
    ///   reaches a latest-state index declines to the scan.
    ///
    /// The *durable* catalog is untouched: the schema still exists (`SHOW INDEXES` reads the store, so
    /// it keeps reporting the declared indexes and their durable state), and the next successful
    /// rebuild — triggered by any index/constraint DDL, or by re-opening the store — re-registers every
    /// index from the durable catalog and repopulates it, restoring the fast paths. Demoting the
    /// durable state instead would require writing to a store that has just faulted, so it is
    /// deliberately not attempted.
    pub fn fail_closed(&mut self) {
        // A new epoch: every derived structure below is about to become untrustworthy, so any work
        // computed against the previous epoch — above all an **in-flight incremental build**, which
        // lives in the coordinator and cannot be reached from here — must revalidate itself and start
        // over rather than resume over the wreckage (`rmp` task #733).
        self.wipe_generation = self.wipe_generation.wrapping_add(1);
        self.fail_closed_events = self.fail_closed_events.saturating_add(1);
        self.degraded = true;
        // The label index first: it is the base of EVERY fallback (a declined seek degrades to a label
        // scan), so an empty-but-trusted label index would make even the rescue path return zero rows.
        self.labels_usable = false;
        for np in self.node_props.values_mut() {
            np.state = IndexState::Populating;
        }
        for rp in self.rel_props.values_mut() {
            rp.state = IndexState::Populating;
        }
        for ft in self.fulltext.values_mut() {
            ft.state = IndexState::Populating;
        }
        for ft in self.fulltext_rel.values_mut() {
            ft.state = IndexState::Populating;
        }
        for sp in self.spatial.values_mut() {
            sp.state = IndexState::Populating;
        }
        for sp in self.spatial_rel.values_mut() {
            sp.state = IndexState::Populating;
        }
        for tx in self.text.values_mut() {
            tx.state = IndexState::Populating;
        }
        for v in self.vector.values_mut() {
            v.state = IndexState::Populating;
        }
        for v in self.vector_rel.values_mut() {
            v.state = IndexState::Populating;
        }
        // State-less candidate sources: unregister (their consumers gate on registration, not state).
        self.composite.clear();
        self.rel_composite.clear();
        // The bitmaps are RETIRED, not dropped: their live indexes go (an empty membership-exact index
        // would answer every seek with zero rows) but their **declarations** survive in
        // `bitmap_declared`, because a bitmap column has no durable catalog entry for a rebuild to
        // recover it from — dropping them here lost every declared column for the life of the process
        // (`rmp` task #733, M2). The next successful rebuild re-registers and repopulates them.
        self.bitmap.clear();
        self.dirty_bitmap_nodes.clear();
        // And force every latest-state reader onto the scan path too (`rmp` #467's poison).
        self.poison_ft_spatial_marker();
        // Discard the TRANSIENT attribution flags too (`rmp` task #803). A fail-closed is the
        // "everything derived is untrustworthy" path: it wipes every structure and poisons the marker,
        // so a half-raised dirty bit describing work that has just been thrown away has no meaning left.
        // Leaving it standing let a faulted rebuild's residue be charged to the next unrelated write
        // statement, which then poisoned the marker a SECOND time on abort — by a transaction that
        // touched nothing indexed. (`rebuild_index` reaches `fail_closed` on both of its bail paths
        // AFTER its refill loops have raised the flag.)
        self.clear_ft_spatial_dirty();
        // The gap (if any) has been acted upon: everything it could have made incomplete is now unusable.
        self.rebuild_gap = false;
    }

    /// Whether the **label** index may be trusted as the authoritative candidate source for a label scan
    /// (`rmp` task #733). `false` after a failed rebuild left it empty: the label-scan seam must then
    /// enumerate the store directly instead (see
    /// [`labels_usable`](Self#structfield.labels_usable)).
    #[must_use]
    pub fn labels_usable(&self) -> bool {
        self.labels_usable
    }

    /// Records that the build currently filling this index **had to skip an entity it could not read**
    /// (`rmp` task #733) — see [`rebuild_gap`](Self#structfield.rebuild_gap). Called by the per-entity
    /// indexing helpers in place of silently swallowing the read fault.
    pub fn note_rebuild_gap(&mut self) {
        self.rebuild_gap = true;
    }

    /// Whether the build currently filling this index skipped an entity — i.e. whether the index is known
    /// to be an **incomplete** image of the store, and so must not be published (`rmp` task #733).
    #[must_use]
    pub fn rebuild_gap(&self) -> bool {
        self.rebuild_gap
    }

    /// Clears the gap flag, so a build can start from a known-clean slate (`rmp` task #733). Used by the
    /// synchronous / incremental builds that do not go through [`clear`](Self::clear).
    /// Records a request to recompute the `(label, property)` selectivity histogram (`rmp` task #572),
    /// for the coordinator's drain to execute. Idempotent: a pair already queued is not queued twice, so
    /// N calls before one drain cost one recompute — a histogram is a point-in-time image, so the second
    /// of two back-to-back recomputes would only redo the first.
    pub fn request_resample(&mut self, label: &str, property: &str) {
        if self
            .pending_resamples
            .iter()
            .any(|(l, p)| l == label && p == property)
        {
            return;
        }
        self.pending_resamples
            .push_back((label.to_owned(), property.to_owned()));
    }

    /// Whether any resample request is still waiting for the coordinator's drain (`rmp` task #572).
    #[must_use]
    pub fn has_pending_resamples(&self) -> bool {
        !self.pending_resamples.is_empty()
    }

    /// Takes the oldest pending resample request, or [`None`] when the queue is empty (`rmp` task
    /// #572). The caller **owns** the request once taken: it is not re-queued on failure, which is what
    /// makes the drain loop terminate (`while has_pending_index_builds() { advance… }`).
    pub fn pop_pending_resample(&mut self) -> Option<(String, String)> {
        self.pending_resamples.pop_front()
    }

    pub fn clear_rebuild_gap(&mut self) {
        self.rebuild_gap = false;
    }

    /// Records that a single-value-per-entity index build saw the **in-flight** transaction `writer`
    /// holding the NEWEST version of a covered property (`rmp` task #778) — see
    /// [`ft_build_conflict_writers`](Self#structfield.ft_build_conflict_writers). Called by the full-text
    /// build helpers in place of baking that uncommitted value newest-wins.
    ///
    /// De-duplicated: one writer typically blocks many entities of the same build, and the driver only
    /// ever asks whether they have all resolved.
    pub fn note_ft_build_conflict(&mut self, writer: TxnId) {
        if !self.ft_build_conflict_writers.contains(&writer) {
            self.ft_build_conflict_writers.push(writer);
        }
    }

    /// Whether the build currently filling a single-value-per-entity index observed an active-writer
    /// conflict — i.e. whether promoting it `Online` now would bake an uncommitted value over a committed
    /// one (`rmp` task #778).
    #[must_use]
    pub fn ft_build_conflict(&self) -> bool {
        !self.ft_build_conflict_writers.is_empty()
    }

    /// The in-flight writers that blocked the current build (`rmp` task #778) — the set whose resolution
    /// the driver waits on before re-driving. Empty when the build saw no conflict.
    #[must_use]
    pub fn ft_build_conflict_writers(&self) -> &[TxnId] {
        &self.ft_build_conflict_writers
    }

    /// Clears the active-writer conflict record so a build can start from a known-clean slate (`rmp` task
    /// #778). Used by the incremental / synchronous builds that do not go through [`clear`](Self::clear).
    pub fn clear_ft_build_conflict(&mut self) {
        self.ft_build_conflict_writers.clear();
    }

    /// Demotes every registered full-text index — node AND relationship — to
    /// [`IndexState::Populating`] **in memory only**, because the build that was filling them skipped an
    /// entity whose newest covered version an in-flight writer holds (`rmp` task #778).
    ///
    /// # Why in-memory only, and why *every* full-text index
    ///
    /// In-memory only follows the [`fail_closed`](Self::fail_closed) precedent: the durable catalog keeps
    /// whatever state it had, so the single route back to `Online` is
    /// [`rebuild_index`](crate::coordinator::TxnCoordinator)'s re-registration from that catalog — which
    /// re-runs the refill first, so an index can only come back `Online` by being rebuilt cleanly. Writing
    /// `Populating` durably instead would make a *transient* write conflict survive a restart, and would
    /// route through the recovery promotion path, which does not re-check anything.
    ///
    /// Every index, because the conflict signal is per-build, not per-index: a build visits entities, and
    /// one skipped entity may be covered by any subset of the declared full-text indexes. Demoting the
    /// superset is the conservative choice — it costs a scan fallback on indexes that were not actually
    /// holed (correct, just unaccelerated), where demoting too few would leave a holed index `Online` and
    /// silently losing rows.
    /// The writers whose resolution must re-drive the whole-set rebuild that demoted the full-text
    /// indexes (`rmp` task #778). Empty when no rebuild is awaiting repair — see
    /// [`ft_demoted_blockers`](Self#structfield.ft_demoted_blockers).
    #[must_use]
    pub fn ft_demoted_blockers(&self) -> &[TxnId] {
        &self.ft_demoted_blockers
    }

    pub fn demote_fulltext_for_conflict(&mut self) {
        // Record the blockers in the SAME step as the demotion: an index demoted without a recorded
        // blocker has no resurrection trigger and would stay `Populating` forever.
        self.ft_demoted_blockers
            .clone_from(&self.ft_build_conflict_writers);
        for ft in self.fulltext.values_mut() {
            ft.state = IndexState::Populating;
        }
        for ft in self.fulltext_rel.values_mut() {
            ft.state = IndexState::Populating;
        }
    }

    /// The union of covered property-key tokens of every registered **node** full-text index whose
    /// covered label set intersects `label_tokens` (`rmp` task #778) — the keys whose newest version the
    /// build must check for an in-flight writer before it may bake this node newest-wins. Empty when the
    /// node carries no covered label of any full-text index.
    #[must_use]
    pub fn fulltext_covered_keys_for_labels(&self, label_tokens: &[u32]) -> Vec<u32> {
        let mut keys: Vec<u32> = Vec::new();
        for ft in self.fulltext.values() {
            if ft.label_tokens.iter().any(|lt| label_tokens.contains(lt)) {
                for &pk in &ft.prop_keys {
                    if !keys.contains(&pk) {
                        keys.push(pk);
                    }
                }
            }
        }
        keys
    }

    /// The union of covered property-key tokens of every registered **relationship** full-text index
    /// covering `type_token` (`rmp` task #778) — the relationship analogue of
    /// [`fulltext_covered_keys_for_labels`](Self::fulltext_covered_keys_for_labels).
    #[must_use]
    pub fn fulltext_rel_covered_keys_for_type(&self, type_token: u32) -> Vec<u32> {
        let mut keys: Vec<u32> = Vec::new();
        for ft in self.fulltext_rel.values() {
            if ft.type_tokens.contains(&type_token) {
                for &pk in &ft.prop_keys {
                    if !keys.contains(&pk) {
                        keys.push(pk);
                    }
                }
            }
        }
        keys
    }

    /// The current **wipe epoch** (`rmp` task #733): incremented by every
    /// [`fail_closed`](Self::fail_closed). An incremental build records the epoch it is indexing into
    /// and restarts from scratch when it observes a different one — see
    /// [`wipe_generation`](Self#structfield.wipe_generation) for why resuming would publish an `Online`
    /// index missing rows.
    #[must_use]
    pub fn wipe_generation(&self) -> u64 {
        self.wipe_generation
    }

    /// Whether the index set is currently **degraded**: wiped by [`fail_closed`](Self::fail_closed) and
    /// not yet repaired by a successful rebuild (`rmp` task #733). While degraded, every read path is on
    /// the (correct, unaccelerated) scan, `SHOW INDEXES` must report the effective state rather than the
    /// durable catalog's `ONLINE`, and the engine should keep retrying the rebuild.
    #[must_use]
    pub fn is_degraded(&self) -> bool {
        self.degraded
    }

    /// How many times [`fail_closed`](Self::fail_closed) has fired (`rmp` task #733) — monotonic. The
    /// server samples it to log the transition at `ERROR` and drive a metric; a jump means a storage
    /// fault just cost the engine its derived indexes.
    #[must_use]
    pub fn fail_closed_events(&self) -> u64 {
        self.fail_closed_events
    }

    /// Marks the index set **repaired** (`rmp` task #733): called by a rebuild that completed with no
    /// whole-scan fault and no per-entity gap, i.e. one whose result is a faithful image of the store.
    /// Clears the degraded flag (the fast paths are trustworthy again); the epoch counter is *not*
    /// touched, since a build that was invalidated must still restart.
    pub fn heal(&mut self) {
        self.degraded = false;
    }

    /// Records that node `node_id` carries label `label_token` (a candidate for label scans).
    ///
    /// # This tree is INSERT-ONLY, and that is load-bearing for correctness (`rmp` #771 / #767)
    ///
    /// There is deliberately **no** `remove_label` counterpart, and [`clear`](Self::clear) does not
    /// reset this tree. Do not add one without reading both arguments below — the absence of a removal
    /// path is not an oversight or a missing optimisation, it is what makes two separate defects
    /// impossible.
    ///
    /// * **`rmp` #771** — the refill's only source is the node's CURRENT bitmap, which includes an
    ///   uncommitted writer's change. Destroying entries makes the rebuild write a SUBSET, and when
    ///   that writer rolls back the record's bit returns while nothing restores the index entry.
    /// * **`rmp` #767** — the per-candidate re-check is now snapshot-isolated, so an older reader can
    ///   legitimately need a candidate the current bitmap no longer shows. Before #767 a dropped
    ///   entry was harmless *by itself* because the re-check tested the current bitmap and would have
    ///   rejected it anyway; that second, independent line of defence is GONE.
    ///
    /// So the tree must stay a monotone SUPERSET: a retained stale entry is a false positive the
    /// re-check drops, while a destroyed entry is a committed row silently lost. The tempting reason
    /// to add a removal — nothing prunes an entry whose node was deleted or relabelled — is
    /// acknowledged in [`clear`](Self::clear); entries are reclaimed wholesale when the store reopens.
    ///
    /// `tests/label_tree_765_reaudit_767.rs` fires on entry destruction (verified by mutation), and
    /// `tests/index_rebuild_label.rs` covers the #771 direction.
    pub fn insert_label(&mut self, label_token: u32, node_id: u64) {
        // in-memory index: a BTree op cannot fail in practice; an insert failure leaves the entry
        // simply absent (the caller re-checks, so a missing candidate degrades to a full scan, never
        // to a wrong answer).
        let _ = self.labels.insert(EPHEMERAL_TXN, label_token, node_id);
    }

    /// Records that node `node_id` has `value` for the `(label_token, prop_key)` index, if such an
    /// index is registered (else a no-op).
    pub fn insert_node_property(
        &mut self,
        label_token: u32,
        prop_key: u32,
        value: &Value,
        node_id: u64,
    ) {
        if let Some(np) = self.node_props.get_mut(&(label_token, prop_key)) {
            // in-memory index: a BTree op cannot fail in practice. A `Null` value is unindexable
            // (`PropertyIndex::insert` errors) and is correctly skipped — `Null` properties are
            // absent for index purposes, matching Cypher's treatment in equality/range predicates.
            // Maintained regardless of state: keeping a `Populating` index up to date is harmless (it
            // is simply not yet exposed to the planner, see `online_node_properties`).
            let _ = np.index.insert(EPHEMERAL_TXN, prop_key, value, node_id);
        }
    }

    /// Candidate node ids carrying `label_token`, ascending. The caller re-checks visibility and
    /// current label membership.
    pub fn seek_label(&mut self, label_token: u32) -> Vec<u64> {
        // in-memory index: a BTree op cannot fail in practice; a seek error degrades to no
        // candidates (which the caller turns into a full scan), never to a wrong answer.
        self.labels.scan_token(label_token).unwrap_or_default()
    }

    /// Candidate node ids for `(label_token, prop_key) == value`, ascending. `None` if no such index
    /// is registered. The caller re-checks visibility, current label, and the current value.
    pub fn seek_node_property_eq(
        &mut self,
        label_token: u32,
        prop_key: u32,
        value: &Value,
    ) -> Option<Vec<u64>> {
        let np = self.node_props.get_mut(&(label_token, prop_key))?;
        // A non-index-encodable bound (a `List`) must DECLINE so the caller takes the exact scan
        // fallback — never collapse to `Some(vec![])`, which would silently drop matching rows
        // (`rmp` #680; see [`is_index_encodable`]).
        if !is_index_encodable(value) {
            return None;
        }
        // in-memory index: a BTree op cannot fail in practice; a seek error degrades to an empty
        // candidate list. Note this is `Some(vec![])`, not `None`: the index *is* registered, it
        // simply has no matching candidate.
        Some(np.index.seek_eq(prop_key, value).unwrap_or_default())
    }

    /// Candidate node ids for `(label_token, prop_key)` within a range, ascending. `None` if no such
    /// index is registered; otherwise a **superset** of the in-range candidates (see below).
    ///
    /// Bounds are `(value, inclusive)`; a `None` bound is unbounded on that side. The caller
    /// re-checks the predicate, so a superset is correct and a subset is not.
    ///
    /// # Bound mapping (superset semantics)
    ///
    /// The backing [`PropertyIndex::seek_range`]`(token, lo, hi)` answers a **half-open** range
    /// `[lo, hi)` over one token: the lower value is **inclusive**, `hi = Some(v)` is **exclusive**,
    /// and `hi = None` is unbounded above. It has no unbounded-below and no exclusive-lower form.
    /// We translate the requested `(lower, upper)` to the *tightest range it can express that is
    /// still a superset* of the request:
    ///
    /// - **Lower** `Some((v, true))` (inclusive) maps exactly to `lo = v`.
    /// - **Lower** `Some((v, false))` (exclusive) cannot be expressed (the backing lower is always
    ///   inclusive), so we widen to `lo = v` (inclusive). This adds at most the `== v` candidates,
    ///   which the caller's predicate re-check then drops.
    /// - **Lower** `None` (unbounded below) cannot be expressed (a concrete `lo` is required), so we
    ///   widen to the smallest indexable value for the token. Because the index stores no `Null`
    ///   keys and orders every other value above the integer/temporal floor, scanning from the most
    ///   negative integer would still miss values that sort *below* integers (e.g. strings, by
    ///   openCypher orderability). To remain a correct **superset**, an unbounded-below request
    ///   therefore returns **all** candidates for the token (the whole index column), which is
    ///   always a superset of any `< upper` request. The caller re-checks the predicate.
    /// - **Upper** `Some((v, false))` (exclusive) maps exactly to `hi = Some(v)`.
    /// - **Upper** `Some((v, true))` (inclusive) cannot be expressed (the backing upper is always
    ///   exclusive), so we widen to `hi = None` (unbounded above). This over-includes everything
    ///   `> v`, which the caller's predicate re-check then drops. (A tighter `next-value` upper is
    ///   not generally constructible for arbitrary `Value`s, so the safe superset is used.)
    /// - **Upper** `None` (unbounded above) maps exactly to `hi = None`.
    ///
    /// Net effect: the returned set always contains every node whose current value satisfies the
    /// requested bounds (assuming its index entry is up to date), and may contain extra candidates
    /// that the caller filters out.
    pub fn seek_node_property_range(
        &mut self,
        label_token: u32,
        prop_key: u32,
        lower: Option<(&Value, bool)>,
        upper: Option<(&Value, bool)>,
    ) -> Option<Vec<u64>> {
        let np = self.node_props.get_mut(&(label_token, prop_key))?;

        // Decline (→ exact scan fallback) if ANY present bound is not index-encodable (a `List`): the
        // order-preserving key cannot represent it, so an unbounded lower would return the (list-empty)
        // whole column and a present list bound would encode-error to empty — either way the index
        // would silently drop rows the scan keeps (`rmp` #680; see [`is_index_encodable`]).
        if let Some((v, _)) = lower {
            if !is_index_encodable(v) {
                return None;
            }
        }
        if let Some((v, _)) = upper {
            if !is_index_encodable(v) {
                return None;
            }
        }

        // Map the upper bound: exclusive maps exactly; inclusive widens to unbounded-above (a
        // superset); `None` is unbounded-above.
        let hi: Option<&Value> = match upper {
            Some((v, false)) => Some(v), // exclusive: exact
            Some((_, true)) => None,     // inclusive: widen to unbounded above (superset)
            None => None,                // unbounded above
        };

        let candidates = match lower {
            // Inclusive lower maps exactly; exclusive lower widens to inclusive (superset).
            Some((v, _)) => np.index.seek_range(prop_key, v, hi),
            // Unbounded below cannot be expressed against the inclusive-lower backing range without
            // risking a subset (values may sort below the integer floor). Return all candidates for
            // the token — always a superset of any `< upper` request.
            None => Self::all_candidates(np.index.tree_mut(), prop_key),
        };

        // in-memory index: a BTree op cannot fail in practice; a seek error degrades to an empty
        // candidate list (still `Some`, since the index is registered).
        Some(candidates.unwrap_or_default())
    }

    /// The label tokens that currently have at least one entry, ascending and de-duplicated. Used to
    /// build the planner's auto token-lookup catalog.
    #[must_use]
    pub fn indexed_label_tokens(&mut self) -> Vec<u32> {
        // `TokenIndex` has no token-enumeration API, so recover the tokens from the label index by
        // scanning the full keyspace via the underlying tree (`scan_all`, ascending). The tree is
        // the only place that holds the per-token keys.
        // Each label key is `(token: u32 BE, element_id: u64 BE)`; the leading 4 bytes are the label
        // token. Anything shorter is not a label key and is skipped defensively. Streaming over the key
        // slices avoids an owned `(key, value)` pair per row.
        let mut tokens: Vec<u32> = Vec::new();
        let _ = self.labels.tree_mut().scan_all_for_each(|k, _| {
            if let Some(b) = k.get(0..4) {
                tokens.push(u32::from_be_bytes([b[0], b[1], b[2], b[3]]));
            }
        });
        tokens.sort_unstable();
        tokens.dedup();
        tokens
    }

    /// The registered node-property index keys `(label_token, prop_key)` in **any** state, ascending
    /// and de-duplicated.
    ///
    /// Used by the coordinator's index rebuild to decide which property values to index for each node;
    /// a `Populating` index *is* maintained (so its entries are ready the instant it is promoted), so
    /// the rebuild must see it here. The planner instead consumes
    /// [`online_node_properties`](Self::online_node_properties), which omits non-`Online` indexes.
    #[must_use]
    pub fn registered_node_properties(&self) -> Vec<(u32, u32)> {
        let mut keys: Vec<(u32, u32)> = self.node_props.keys().copied().collect();
        keys.sort_unstable();
        keys
    }

    /// The **`Online`** node-property index keys `(label_token, prop_key)`, ascending and de-duplicated
    /// (`rmp` task #90). Used to build the planner's label-property catalog: only an `Online` index may
    /// serve a seek, so a `Populating` index is omitted here and the planner falls back to a label-scan
    /// + filter for that `(label, property)` until it is promoted.
    #[must_use]
    pub fn online_node_properties(&self) -> Vec<(u32, u32)> {
        let mut keys: Vec<(u32, u32)> = self
            .node_props
            .iter()
            .filter(|(_, np)| np.state == IndexState::Online)
            .map(|(&key, _)| key)
            .collect();
        keys.sort_unstable();
        keys
    }

    // ============================================================================================
    // Relationship-property indexes (`rmp` task #646)
    // ============================================================================================
    // Structural twins of the node-property index methods above, keyed by `(rel_type_token, prop_key)`
    // and backed by a `RelPropertyIndex`. Same candidate-vs-answer contract (a seek returns a superset
    // the caller re-checks against the store) and the same state gating (only an `Online` index is
    // surfaced to the planner / index-backed enforcement).

    /// Declares a relationship-property index on `(type_token, prop_key)` at [`IndexState::Online`]
    /// (`rmp` task #646). Idempotent: a no-op if one is already registered (its state is left
    /// unchanged), otherwise creates the backing [`RelPropertyIndex`].
    pub fn register_rel_property(&mut self, type_token: u32, prop_key: u32) {
        self.register_rel_property_with_state(type_token, prop_key, IndexState::Online);
    }

    /// Declares a relationship-property index on `(type_token, prop_key)` at `state` (`rmp` task #646).
    /// Idempotent on the key: if one is already registered its backing tree is kept but its state is
    /// updated to `state` (so a recovered `Online` declaration promotes a freshly-created entry).
    pub fn register_rel_property_with_state(
        &mut self,
        type_token: u32,
        prop_key: u32,
        state: IndexState,
    ) {
        // Feed the `RelEquality` reachability gate (`rmp` #683): once this index exists, `index_seek_eq`
        // can serve a seek over `(type_token, prop_key)` and register a marker, so every writer of that
        // property must announce from now on. Recorded for ANY state, not just `Online`: a `Populating`
        // index becomes `Online` without passing through here again.
        self.note_rel_equality_declared(type_token, prop_key);
        self.rel_props
            .entry((type_token, prop_key))
            .and_modify(|rp| rp.state = state)
            .or_insert_with(|| RelationshipPropertyIndex {
                index: RelPropertyIndex::new(fresh_tree()),
                state,
            });
    }

    /// Sets the build [`IndexState`] of an already-registered `(type_token, prop_key)` rel index
    /// (`rmp` task #646). A no-op if no such index is registered.
    pub fn set_rel_property_state(&mut self, type_token: u32, prop_key: u32, state: IndexState) {
        if let Some(rp) = self.rel_props.get_mut(&(type_token, prop_key)) {
            rp.state = state;
        }
    }

    /// Unregisters the relationship-property index on `(type_token, prop_key)`, dropping its backing
    /// tree (`rmp` task #646, `DROP INDEX`). A no-op if no such index is registered.
    pub fn unregister_rel_property(&mut self, type_token: u32, prop_key: u32) {
        self.rel_props.remove(&(type_token, prop_key));
    }

    /// Whether a relationship-property index is registered for `(type_token, prop_key)` (in **any**
    /// state) (`rmp` task #646).
    #[must_use]
    pub fn has_rel_property(&self, type_token: u32, prop_key: u32) -> bool {
        self.rel_props.contains_key(&(type_token, prop_key))
    }

    /// Whether **any** relationship-property index is registered (`rmp` task #646) — an O(1) gate the
    /// per-write maintenance path checks before decoding a relationship's property chain, so a store
    /// with no rel index pays nothing for the maintenance hook.
    #[must_use]
    pub fn has_any_rel_property(&self) -> bool {
        !self.rel_props.is_empty()
    }

    /// The build [`IndexState`] of the `(type_token, prop_key)` rel index, or [`None`] if unregistered
    /// (`rmp` task #646).
    #[must_use]
    pub fn rel_property_state(&self, type_token: u32, prop_key: u32) -> Option<IndexState> {
        self.rel_props
            .get(&(type_token, prop_key))
            .map(|rp| rp.state)
    }

    /// Records that relationship `rel_id` has `value` for the `(type_token, prop_key)` index, if such
    /// an index is registered (else a no-op) (`rmp` task #646). Maintained regardless of state (a
    /// `Populating` index is kept up to date, harmlessly). A `Null` value is unindexable and correctly
    /// skipped — a `Null` property is absent for index purposes, matching the node-property handling.
    pub fn insert_rel_property(
        &mut self,
        type_token: u32,
        prop_key: u32,
        value: &Value,
        rel_id: u64,
    ) {
        if let Some(rp) = self.rel_props.get_mut(&(type_token, prop_key)) {
            // The `let _ =` is tolerated because this is a purely in-memory BTree insert with no I/O:
            // it cannot fail in practice.
            //
            // It is NOT tolerated because a failure would be harmless — it would not be. A dropped
            // entry means a MISSING CANDIDATE, and a candidate seek returns candidates, not a scan:
            // the caller's re-check can only ever *remove* ids, never resurrect one the seek never
            // yielded. So a lost entry is a lost row, a lost SIREAD marker, and (via
            // `rel_unique_conflict`) a uniqueness check that reports "no duplicate" — the `rmp`
            // #738 class. There is no "degrades to a full scan" fallback on this path; do not
            // reintroduce that claim.
            let _ = rp.index.insert(EPHEMERAL_TXN, prop_key, value, rel_id);
        }
    }

    /// Candidate relationship ids for `(type_token, prop_key) == value`, ascending (`rmp` task #646).
    /// [`None`] if no such index is registered; otherwise a candidate set the caller re-checks
    /// (visibility, current type, current value). `Some(vec![])` — "registered but no candidate" — is
    /// distinct from `None`.
    pub fn seek_rel_property_eq(
        &mut self,
        type_token: u32,
        prop_key: u32,
        value: &Value,
    ) -> Option<Vec<u64>> {
        let rp = self.rel_props.get_mut(&(type_token, prop_key))?;
        // A non-index-encodable bound (a `List`) declines to the exact scan fallback (`rmp` #680).
        if !is_index_encodable(value) {
            return None;
        }
        Some(rp.index.seek_eq(prop_key, value).unwrap_or_default())
    }

    /// The **candidate** relationship ids of `(type_token, prop_key)` whose current value satisfies the
    /// range `[lower, upper]` (`rmp` task #680). The relationship analogue of
    /// [`seek_node_property_range`](Self::seek_node_property_range): identical bound mapping (an inclusive
    /// lower maps exactly, an exclusive lower widens to inclusive; an exclusive upper maps exactly, an
    /// inclusive upper widens to unbounded-above; either side `None` is open), so the result is always a
    /// **superset** the caller re-checks against the store. Returns [`None`] when no relationship-property
    /// index is registered for `(type_token, prop_key)`.
    pub fn seek_rel_property_range(
        &mut self,
        type_token: u32,
        prop_key: u32,
        lower: Option<(&Value, bool)>,
        upper: Option<(&Value, bool)>,
    ) -> Option<Vec<u64>> {
        let rp = self.rel_props.get_mut(&(type_token, prop_key))?;

        // Decline (→ exact scan fallback) if ANY present bound is not index-encodable (a `List`) —
        // mirrors `seek_node_property_range` (`rmp` #680; see [`is_index_encodable`]).
        if let Some((v, _)) = lower {
            if !is_index_encodable(v) {
                return None;
            }
        }
        if let Some((v, _)) = upper {
            if !is_index_encodable(v) {
                return None;
            }
        }

        // Map the upper bound: exclusive maps exactly; inclusive widens to unbounded-above (a
        // superset); `None` is unbounded-above. Mirrors `seek_node_property_range`.
        let hi: Option<&Value> = match upper {
            Some((v, false)) => Some(v), // exclusive: exact
            Some((_, true)) => None,     // inclusive: widen to unbounded above (superset)
            None => None,                // unbounded above
        };

        let candidates = match lower {
            // Inclusive lower maps exactly; exclusive lower widens to inclusive (superset).
            Some((v, _)) => rp.index.seek_range(prop_key, v, hi),
            // Unbounded below cannot be expressed against the inclusive-lower backing range without
            // risking a subset, so return every candidate for the token (always a superset of any
            // `< upper` request) — the same treatment the node range seek gives.
            None => Self::all_candidates(rp.index.tree_mut(), prop_key),
        };

        // in-memory index: a BTree op cannot fail in practice; a seek error degrades to an empty
        // candidate list (still `Some`, since the index is registered).
        Some(candidates.unwrap_or_default())
    }

    /// The registered relationship-property index keys `(type_token, prop_key)` in **any** state,
    /// ascending and de-duplicated (`rmp` task #646). Used by the coordinator's index rebuild to decide
    /// which relationship property values to index.
    #[must_use]
    pub fn registered_rel_properties(&self) -> Vec<(u32, u32)> {
        let mut keys: Vec<(u32, u32)> = self.rel_props.keys().copied().collect();
        keys.sort_unstable();
        keys
    }

    /// The **`Online`** relationship-property index keys `(type_token, prop_key)`, ascending and
    /// de-duplicated (`rmp` task #646). Used to build the planner's relationship-property catalog and to
    /// gate index-backed uniqueness enforcement: only an `Online` index may serve a seek.
    #[must_use]
    pub fn online_rel_properties(&self) -> Vec<(u32, u32)> {
        let mut keys: Vec<(u32, u32)> = self
            .rel_props
            .iter()
            .filter(|(_, rp)| rp.state == IndexState::Online)
            .map(|(&key, _)| key)
            .collect();
        keys.sort_unstable();
        keys
    }

    // ============================================================================================
    // Full-text indexes (`rmp` task #72)
    // ============================================================================================

    /// Declares (or replaces) a full-text index named `name` over `(label_token, prop_keys)` with
    /// `analyzer`, at `state` (`rmp` task #72). Idempotent on the name: re-declaring **replaces** the
    /// entry (covered label/properties/analyzer and state) and **resets** its inverted index, so a
    /// recovered declaration starts from a clean, about-to-be-rebuilt index.
    ///
    /// # Panics
    /// Panics if `prop_keys` is empty (a full-text index covers at least one property — the surface
    /// and the durable catalog both enforce this before reaching here).
    pub fn register_fulltext(
        &mut self,
        name: &str,
        label_tokens: Vec<u32>,
        prop_keys: Vec<u32>,
        analyzer: Analyzer,
        state: IndexState,
    ) {
        assert!(
            !prop_keys.is_empty(),
            "full-text index needs at least one property"
        );
        assert!(
            !label_tokens.is_empty(),
            "full-text index needs at least one label"
        );
        self.fulltext.insert(
            name.to_owned(),
            FulltextEntry {
                label_tokens,
                prop_keys,
                analyzer,
                state,
                index: InvertedIndex::new(),
            },
        );
    }

    /// Sets the build [`IndexState`] of the full-text index named `name` (`rmp` task #72), e.g.
    /// promoting `Populating` → `Online`. A no-op if no such index is registered.
    pub fn set_fulltext_state(&mut self, name: &str, state: IndexState) {
        if let Some(ft) = self.fulltext.get_mut(name) {
            ft.state = state;
        }
    }

    /// Unregisters the full-text index named `name`, dropping its inverted index (`rmp` task #72,
    /// `DROP INDEX`). A no-op if no such index is registered.
    pub fn unregister_fulltext(&mut self, name: &str) {
        self.fulltext.remove(name);
    }

    /// Whether a full-text index named `name` is registered (in any state).
    #[must_use]
    pub fn has_fulltext(&self, name: &str) -> bool {
        self.fulltext.contains_key(name)
    }

    /// The build [`IndexState`] of the full-text index named `name`, or [`None`] if unregistered.
    #[must_use]
    pub fn fulltext_state(&self, name: &str) -> Option<IndexState> {
        self.fulltext.get(name).map(|ft| ft.state)
    }

    /// The covered `(label_tokens, prop_keys, analyzer)` of the full-text index named `name`, or
    /// [`None`] if unregistered (`rmp` tasks #72, #663). The coordinator's rebuild/maintenance uses this
    /// to know which property values to analyze for a node; a multi-label index reports every covered
    /// label token.
    #[must_use]
    pub fn fulltext_target(&self, name: &str) -> Option<(Vec<u32>, Vec<u32>, Analyzer)> {
        self.fulltext
            .get(name)
            .map(|ft| (ft.label_tokens.clone(), ft.prop_keys.clone(), ft.analyzer))
    }

    /// An owned, `Send + Sync` snapshot of every declared full-text index's covered target, keyed by
    /// index name (`rmp` task #546) — captured on the engine thread into an off-thread read's
    /// [`ReadTaskInputs`](crate::coordinator::ReadTaskInputs) so `db.index.fulltext.queryNodes`
    /// resolves the index by name on a reader thread without touching this `!Send` [`IndexSet`].
    ///
    /// Includes **every** registered index (in any build state), matching the no-state-gate resolution
    /// [`fulltext_target`](Self::fulltext_target) gives the inline fast path — so the off-thread
    /// "does this index exist?" determination is identical to inline. It carries only the catalogue
    /// (name → covered `(label, props, analyzer)`), **not** the inverted-index postings: the reader
    /// recomputes matches from its MVCC snapshot (`read_source::fulltext_scan_fallback`).
    #[must_use]
    pub fn fulltext_snapshot(&self) -> crate::read_source::FulltextReadSnapshot {
        crate::read_source::FulltextReadSnapshot::from_targets(self.fulltext.iter().map(
            |(name, ft)| {
                (
                    name.clone(),
                    (ft.label_tokens.clone(), ft.prop_keys.clone(), ft.analyzer),
                )
            },
        ))
        // Include the relationship full-text indexes (`rmp` task #663) so an off-thread
        // `db.index.fulltext.queryRelationships` resolves them from the captured catalogue too.
        .with_rel_targets(self.fulltext_rel.iter().map(|(name, ft)| {
            (
                name.clone(),
                (ft.type_tokens.clone(), ft.prop_keys.clone(), ft.analyzer),
            )
        }))
    }

    /// Runs the node-property **equality seeks** in `requests` on this (engine-thread) index and
    /// memoises their candidate ids for an off-thread reader (`rmp` task #755, Slice S2).
    ///
    /// Each request is `(label_token, prop_key, seek_value)`, resolved by the caller from a compiled
    /// plan's `NodeIndexSeek` operators whose seek value is **statically knowable** (a literal or a
    /// bound parameter — never a correlated per-row key, which is `rmp` #764). The result is the
    /// `Send + Sync` [`IndexCandidateCapture`](crate::read_source::IndexCandidateCapture) the reader
    /// consults; see its docs for the MVCC-superset argument this relies on.
    ///
    /// # The gates (each omission below would be silent row loss)
    ///
    /// A request is captured **only** when the memo is provably a **superset** for `reader_ts`:
    ///
    /// 1. **Not degraded** — after [`fail_closed`](Self::fail_closed) the backing trees are wiped, so
    ///    every seek against them is a SUBSET of the truth (`rmp` #733). Capture nothing at all.
    /// 2. **`Online`** — a `Populating` (half-built) index is a genuine subset (`rmp` #733). This is
    ///    the same gate `RecordStoreGraph::index_seek_eq` applies, restated here because this seam must
    ///    be correct **by itself**, not by the planner's grace.
    /// 3. **Not older than the last rebuild** — see below. This is the one that is NOT obvious.
    /// 4. **Append-only class only** — this method touches `node_props` and nothing else. The
    ///    destructive classes (full-text / spatial / text / vector / bitmap) re-index wholesale via
    ///    their `remove_*` paths, so a memo taken now can be a subset for a reader whose snapshot
    ///    predates the rewrite (`rmp` #467).
    ///
    /// A request that fails a gate — or whose value the index cannot key (a `List`) — is simply not
    /// captured, so the reader misses it and takes its exact scan fallback: correct, merely unaccelerated.
    ///
    /// # GATE 3, and why "append-only" was not enough (`rmp` #755 / #765)
    ///
    /// The memo's soundness rests on `node_props` being append-only, so that a *stale* entry — the one a
    /// reader whose snapshot predates a value change still depends on — survives to be captured. That is
    /// true of the **per-entry** surface: [`insert_node_property`](Self::insert_node_property) is the only
    /// per-entry mutation and there is no `remove_node_property`.
    ///
    /// It is **not true of the tree**. [`clear`](Self::clear) — driven by `TxnCoordinator::rebuild_index`
    /// from any index/constraint DDL, and from the degraded-rebuild retry — destroys **every**
    /// node-property tree and refills it **newest-wins**, keeping each index `Online` and healing
    /// `degraded`. Stale entries are annihilated: gates 1 and 2 both pass over a tree that is a genuine
    /// SUBSET for any snapshot older than that rebuild. Measured: a reader begins, a writer moves a node
    /// off the sought value, an *unrelated* `CREATE INDEX` rebuilds — and the reader's seek loses a
    /// committed row it can still see (1 row → 0 rows). `node_props` is therefore in the same wholesale-
    /// destructive hazard class as full-text/spatial (`rmp` #467), just reached by a different verb.
    ///
    /// So gate 3 is the exact analogue of the #467 marker: serve only a reader at-or-after the rebuild's
    /// high-water; an older one declines to the scan, which is snapshot-correct.
    ///
    /// # One invariant, two seams — this gate is load-bearing (`rmp` #765, closed)
    ///
    /// This gate began life as *containment*: it kept the then-open #765 off the captured off-thread
    /// path while the inline path still lost the row. #765 is now **closed**, by applying the same gate
    /// to the inline seek (`RecordStoreGraph::index_seek_eq` / `index_seek_range` decline when
    /// `snapshot.ts < rebuilt_trees_trustworthy_from`). That does **not** make this gate redundant, and it
    /// must not be removed: the two seams read **different sources**. The inline gate guards
    /// `RecordStoreGraph` reading the **live tree**; this gate guards the off-thread `ReadOnlyGraph`,
    /// which never touches the live tree and can only read the **capture** handed to it at dispatch. A
    /// capture built for a pre-rebuild reader would be a subset no downstream gate could repair — the
    /// off-thread reader's `index_seek_eq` would HIT with `Some(subset)` and silently drop the row.
    ///
    /// So both are enforcement points of a single invariant: **a reader older than the last rebuild is
    /// never served from `node_props`** — it declines to the exact scan, which is snapshot-correct.
    /// Removing either one re-opens #765 on that seam.
    #[must_use]
    pub fn capture_node_property_eq(
        &mut self,
        reader_ts: Timestamp,
        requests: &[(u32, u32, Value)],
    ) -> crate::read_source::IndexCandidateCapture {
        let mut capture = crate::read_source::IndexCandidateCapture::default();
        // GATE 1: a degraded set's trees are wiped — every seek is a subset. Capture nothing.
        if self.degraded {
            return capture;
        }
        // GATE 3: a rebuild wiped the stale entries this reader may still depend on. Capture nothing;
        // the reader declines to the snapshot-correct scan. (`rmp` #755 containment of `rmp` #765.)
        if reader_ts < self.rebuilt_trees_trustworthy_from {
            return capture;
        }
        for (label_token, prop_key, value) in requests {
            // GATE 2: only an `Online` index may answer.
            if self.node_property_state(*label_token, *prop_key) != Some(IndexState::Online) {
                continue;
            }
            // GATE 3 is structural: `seek_node_property_eq` reads `node_props` — the append-only class
            // — and nothing else. It declines (`None`) an unindexable value, which we simply skip.
            if let Some(ids) = self.seek_node_property_eq(*label_token, *prop_key, value) {
                capture.insert(*label_token, *prop_key, value, ids);
            }
        }
        capture
    }

    /// Runs the node-property **RANGE seeks** in `requests` on this (engine-thread) index and memoises
    /// their candidate ids for an off-thread reader (`rmp` task #768) — the range twin of
    /// [`capture_node_property_eq`](Self::capture_node_property_eq).
    ///
    /// Each request is `(label_token, prop_key, lower, upper)` where each bound is an owned
    /// `(value, inclusive)` or `None` (an open side), resolved by the caller from a plan's
    /// `NodeIndexRangeSeek` / `NodeIndexScan` / `NodeIndexStartsWithSeek` operators whose bound values are
    /// statically knowable (a literal or bound parameter — never a correlated per-row key, `rmp` #764).
    ///
    /// # Gates — identical in kind to [`capture_node_property_eq`](Self::capture_node_property_eq)
    ///
    /// RANGE is the same append-only node-property tree class as equality, so it rides the same
    /// wholesale-rebuild watermark (`rmp` #765): capture nothing when [`degraded`](Self#structfield.degraded),
    /// nothing when the reader predates the last rebuild (`reader_ts < rebuilt_trees_trustworthy_from`),
    /// and per request only when the index is `Online`. A gate failure — or a `List` bound the index
    /// cannot key — simply is not captured, so the reader misses and takes its exact scan fallback.
    #[must_use]
    pub fn capture_node_property_range(
        &mut self,
        reader_ts: Timestamp,
        requests: &[RangeCaptureRequest],
    ) -> crate::read_source::IndexCandidateCapture {
        let mut capture = crate::read_source::IndexCandidateCapture::default();
        // GATE 1 (degraded) + GATE 3 (rebuild watermark): identical to the equality capture — a wiped or
        // pre-rebuild tree is a subset for this reader, so capture nothing (it declines to the scan).
        if self.degraded || reader_ts < self.rebuilt_trees_trustworthy_from {
            return capture;
        }
        for (label_token, prop_key, lower, upper) in requests {
            // GATE 2: only an `Online` index may answer.
            if self.node_property_state(*label_token, *prop_key) != Some(IndexState::Online) {
                continue;
            }
            let lo = lower.as_ref().map(|(v, inc)| (v, *inc));
            let up = upper.as_ref().map(|(v, inc)| (v, *inc));
            // Structural: `seek_node_property_range` reads `node_props` (the append-only class) and
            // declines (`None`) an unindexable `List` bound, which we skip.
            if let Some(ids) = self.seek_node_property_range(*label_token, *prop_key, lo, up) {
                capture.insert_range(*label_token, *prop_key, lo, up, ids);
            }
        }
        capture
    }

    /// Runs the node **COMPOSITE (multi-property) equality seeks** in `requests` on this (engine-thread)
    /// index and memoises their candidate ids for an off-thread reader (`rmp` task #768) — the composite
    /// twin of [`capture_node_property_eq`](Self::capture_node_property_eq).
    ///
    /// Each request is `(label_token, property_tokens, values)`, the composite index's full ordered key
    /// and the per-key seek values (both statically knowable). Composite indexes are the same append-only
    /// node-property tree class as equality (`clear`-and-refill rebuild, no per-entry removal), so they
    /// ride the same rebuild watermark (`rmp` #765). Per request the index must be registered
    /// ([`has_composite`](Self::has_composite)); a `List` element the index cannot key is skipped.
    #[must_use]
    pub fn capture_node_property_composite(
        &mut self,
        reader_ts: Timestamp,
        requests: &[CompositeCaptureRequest],
    ) -> crate::read_source::IndexCandidateCapture {
        let mut capture = crate::read_source::IndexCandidateCapture::default();
        if self.degraded || reader_ts < self.rebuilt_trees_trustworthy_from {
            return capture;
        }
        for (label_token, property_tokens, values) in requests {
            if !self.has_composite(*label_token, property_tokens) {
                continue;
            }
            if let Some(ids) = self.seek_composite_eq(*label_token, property_tokens, values) {
                capture.insert_composite(*label_token, property_tokens, values, ids);
            }
        }
        capture
    }

    /// Runs the node **TEXT (trigram) seeks** in `requests` on this (engine-thread) index and memoises
    /// their candidate ids for an off-thread reader (`rmp` task #768).
    ///
    /// Each request is `(label_token, prop_key, op, needle)` from a plan's `NodeTextIndexSeek` operator
    /// whose needle is a statically-knowable string.
    ///
    /// # Gates — the TEXT/trigram class, NOT the node-property tree class
    ///
    /// The trigram index is **not** an append-only node-property tree: like full-text and spatial it keeps
    /// only the latest state (a write re-keys a node's trigrams wholesale), so it rides the
    /// [`effective_ft_spatial_marker`](Self::effective_ft_spatial_marker) freshness gate (`rmp` #467),
    /// **not** `rebuilt_trees_trustworthy_from`. Capture nothing when the reader's snapshot predates that
    /// marker (an in-flight or rolled-back ft/spatial mutation forces it to `u64::MAX`, so every reader
    /// declines); per request only when the trigram index is `Online`. This mirrors the inline
    /// `RecordStoreGraph::index_seek_text` gates exactly — using the node-property watermark here instead
    /// would be a soundness bug (a reader newer than the last node-property rebuild but older than the last
    /// trigram re-key would be served a subset).
    #[must_use]
    pub fn capture_node_property_text(
        &mut self,
        reader_ts: Timestamp,
        requests: &[TextCaptureRequest],
    ) -> crate::read_source::IndexCandidateCapture {
        use crate::physical::TextSeekOp;
        let mut capture = crate::read_source::IndexCandidateCapture::default();
        // The TEXT class freshness gate (`rmp` #467): an older reader may face a wholesale-re-keyed index,
        // so it declines to the snapshot-correct scan. Folds in the in-flight / poisoned sentinels.
        if reader_ts < self.effective_ft_spatial_marker() {
            return capture;
        }
        for (label_token, prop_key, op, needle) in requests {
            // Only an `Online` trigram index may answer (`rmp` #733); a half-built or rebuild-failed one
            // is a subset.
            if self.text_state(*label_token, *prop_key) != Some(IndexState::Online) {
                continue;
            }
            let ids = match op {
                TextSeekOp::Contains => self.seek_text_contains(*label_token, *prop_key, needle),
                TextSeekOp::EndsWith => self.seek_text_ends_with(*label_token, *prop_key, needle),
                TextSeekOp::StartsWith => {
                    self.seek_text_starts_with(*label_token, *prop_key, needle)
                }
            };
            // `None` = the needle is too short to form a trigram: the index cannot narrow, so skip it and
            // let the reader decline to the scan (exactly as the inline seek does).
            if let Some(ids) = ids {
                capture.insert_text(*label_token, *prop_key, *op, needle, ids);
            }
        }
        capture
    }

    /// Runs the RELATIONSHIP-property **equality seeks** in `requests` on this (engine-thread) index and
    /// memoises their candidate rel ids for an off-thread reader (`rmp` task #769) — the relationship
    /// twin of [`capture_node_property_eq`](Self::capture_node_property_eq).
    ///
    /// Each request is `(type_token, prop_key, value)`. Relationship-property trees are the same
    /// append-only, `clear`-and-refill-rebuilt class as node-property trees, so they ride the identical
    /// gates: capture nothing when [`degraded`](Self#structfield.degraded) or when the reader predates
    /// the last rebuild (`reader_ts < rebuilt_trees_trustworthy_from`, `rmp` #765), and per request only
    /// when the index is `Online`. A `List` value the index cannot key is skipped (the reader then
    /// declines to the exact typed scan, `rmp` #680).
    #[must_use]
    pub fn capture_rel_property_eq(
        &mut self,
        reader_ts: Timestamp,
        requests: &[(u32, u32, Value)],
    ) -> crate::read_source::IndexCandidateCapture {
        let mut capture = crate::read_source::IndexCandidateCapture::default();
        if self.degraded || reader_ts < self.rebuilt_trees_trustworthy_from {
            return capture;
        }
        for (type_token, prop_key, value) in requests {
            if self.rel_property_state(*type_token, *prop_key) != Some(IndexState::Online) {
                continue;
            }
            if let Some(ids) = self.seek_rel_property_eq(*type_token, *prop_key, value) {
                capture.insert_rel_eq(*type_token, *prop_key, value, ids);
            }
        }
        capture
    }

    /// Runs the RELATIONSHIP-property **RANGE seeks** in `requests` (`rmp` task #769/#680) — the twin of
    /// [`capture_node_property_range`](Self::capture_node_property_range). Same append-only rebuild-watermark
    /// gates as the rel-eq capture; per request the index must be `Online`.
    #[must_use]
    pub fn capture_rel_property_range(
        &mut self,
        reader_ts: Timestamp,
        requests: &[RangeCaptureRequest],
    ) -> crate::read_source::IndexCandidateCapture {
        let mut capture = crate::read_source::IndexCandidateCapture::default();
        if self.degraded || reader_ts < self.rebuilt_trees_trustworthy_from {
            return capture;
        }
        for (type_token, prop_key, lower, upper) in requests {
            if self.rel_property_state(*type_token, *prop_key) != Some(IndexState::Online) {
                continue;
            }
            let lo = lower.as_ref().map(|(v, inc)| (v, *inc));
            let up = upper.as_ref().map(|(v, inc)| (v, *inc));
            if let Some(ids) = self.seek_rel_property_range(*type_token, *prop_key, lo, up) {
                capture.insert_rel_range(*type_token, *prop_key, lo, up, ids);
            }
        }
        capture
    }

    /// Runs the RELATIONSHIP **COMPOSITE equality seeks** in `requests` (`rmp` task #769/#666) — the twin
    /// of [`capture_node_property_composite`](Self::capture_node_property_composite). Composite relationship
    /// indexes are the same append-only rebuild class; per request the index must be registered
    /// ([`has_rel_composite`](Self::has_rel_composite)).
    #[must_use]
    pub fn capture_rel_composite(
        &mut self,
        reader_ts: Timestamp,
        requests: &[CompositeCaptureRequest],
    ) -> crate::read_source::IndexCandidateCapture {
        let mut capture = crate::read_source::IndexCandidateCapture::default();
        if self.degraded || reader_ts < self.rebuilt_trees_trustworthy_from {
            return capture;
        }
        for (type_token, property_tokens, values) in requests {
            if !self.has_rel_composite(*type_token, property_tokens) {
                continue;
            }
            if let Some(ids) = self.seek_rel_composite_eq(*type_token, property_tokens, values) {
                capture.insert_rel_composite(*type_token, property_tokens, values, ids);
            }
        }
        capture
    }

    /// Runs the node SPATIAL (point) proximity seeks in `requests` on this (engine-thread) grid index and
    /// memoises their candidate node ids for an off-thread reader (`rmp` task #770).
    ///
    /// Each request is `(label_token, prop_key, center_x, center_y, radius)` from a plan's
    /// [`SpatialIndexSeek`](crate::physical::PhysicalOp::SpatialIndexSeek), whose centre + radius are
    /// plan-time-folded constants.
    ///
    /// # Gates — the ft/spatial (grid) class, exactly as [`capture_node_property_text`](Self::capture_node_property_text)
    ///
    /// The grid, like the trigram and full-text indexes, keeps only the LATEST state (a write re-keys a
    /// node's cell wholesale), so it rides the [`effective_ft_spatial_marker`](Self::effective_ft_spatial_marker)
    /// freshness gate (`rmp` #467) — **not** the node-property `rebuilt_trees_trustworthy_from` watermark:
    /// using the latter would serve a reader newer than the last node-property rebuild but older than the
    /// last grid re-key a subset (silent row loss). Capture nothing when the reader predates the marker
    /// (an in-flight / rolled-back ft/spatial mutation forces it to `u64::MAX`, so every reader declines);
    /// per request only when the grid is `Online` (`rmp` #733). The memo captures the RAW grid superset
    /// (before label filtering) — the reader's re-check runs [`filter_label_candidates`](crate::read_source)
    /// on it, exactly as the inline seam does, so the per-candidate SIREAD footprint is identical.
    #[must_use]
    pub fn capture_node_spatial(
        &mut self,
        reader_ts: Timestamp,
        requests: &[SpatialCaptureRequest],
    ) -> crate::read_source::IndexCandidateCapture {
        let mut capture = crate::read_source::IndexCandidateCapture::default();
        if reader_ts < self.effective_ft_spatial_marker() {
            return capture;
        }
        for (label_token, prop_key, cx, cy, r) in requests {
            if self.spatial_state(*label_token, *prop_key) != Some(IndexState::Online) {
                continue;
            }
            if let Some(ids) = self.seek_spatial_within(*label_token, *prop_key, *cx, *cy, *r) {
                capture.insert_spatial(*label_token, *prop_key, *cx, *cy, *r, ids);
            }
        }
        capture
    }

    /// Runs the RELATIONSHIP SPATIAL (point) proximity seeks in `requests` (`rmp` task #770/#664) — the
    /// relationship twin of [`capture_node_spatial`](Self::capture_node_spatial). Same ft/spatial freshness
    /// gate; per request only when the relationship grid is `Online`.
    #[must_use]
    pub fn capture_rel_spatial(
        &mut self,
        reader_ts: Timestamp,
        requests: &[SpatialCaptureRequest],
    ) -> crate::read_source::IndexCandidateCapture {
        let mut capture = crate::read_source::IndexCandidateCapture::default();
        if reader_ts < self.effective_ft_spatial_marker() {
            return capture;
        }
        for (type_token, prop_key, cx, cy, r) in requests {
            if self.spatial_rel_state(*type_token, *prop_key) != Some(IndexState::Online) {
                continue;
            }
            if let Some(ids) = self.seek_spatial_rel_within(*type_token, *prop_key, *cx, *cy, *r) {
                capture.insert_rel_spatial(*type_token, *prop_key, *cx, *cy, *r, ids);
            }
        }
        capture
    }

    /// The registered full-text index names (in any state), ascending. Used by the coordinator's
    /// rebuild to know which indexes to repopulate and by `SHOW FULLTEXT INDEXES`.
    #[must_use]
    pub fn registered_fulltext(&self) -> Vec<String> {
        let mut names: Vec<String> = self.fulltext.keys().cloned().collect();
        names.sort_unstable();
        names
    }

    /// All node full-text indexes that cover `label_token`, as `(name, prop_keys, analyzer)`, ascending
    /// by name (`rmp` tasks #72, #663). The coordinator's per-write maintenance uses this: for each
    /// index a written node's label matches, it re-analyzes the node's covered property values. A
    /// multi-label index matches if `label_token` is **any** of its covered labels.
    #[must_use]
    pub fn fulltext_indexes_for_label(
        &self,
        label_token: u32,
    ) -> Vec<(String, Vec<u32>, Analyzer)> {
        let mut out: Vec<(String, Vec<u32>, Analyzer)> = self
            .fulltext
            .iter()
            .filter(|(_, ft)| ft.label_tokens.contains(&label_token))
            .map(|(name, ft)| (name.clone(), ft.prop_keys.clone(), ft.analyzer))
            .collect();
        out.sort_by(|a, b| a.0.cmp(&b.0));
        out
    }

    /// Indexes (or **re-indexes**) `node_id` in the full-text index named `name` with `terms` (the
    /// node's already-analyzed covered text). Replaces the node's previous terms wholesale; an empty
    /// `terms` removes the node from the index. A no-op if no such index is registered.
    pub fn index_fulltext_document(&mut self, name: &str, node_id: u64, terms: &[String]) {
        if let Some(ft) = self.fulltext.get_mut(name) {
            let changed = ft.index.index_document(node_id, terms);
            // A registered posting changed: flag the cross-snapshot freshness marker dirty so the
            // statement seam records this writer as a full-text/spatial mutator (`rmp` task #467).
            self.ft_spatial_dirty = true;
            // If this (re-)index actually CHANGED the document (different terms, or an update-to-empty
            // removal), a rolled-back writer can leave a still-committed node dropped from a posting — a
            // false negative the re-check cannot resurrect. Flag the removal so the rollback path fails
            // closed; a pure insert or an unchanged re-index does not (`rmp` task #756).
            if changed {
                self.ft_spatial_removed_dirty = true;
            }
        }
    }

    /// Removes `node_id` from the full-text index named `name` (a delete, or a node that lost the
    /// covered label). A no-op if no such index is registered.
    pub fn remove_fulltext_document(&mut self, name: &str, node_id: u64) {
        if let Some(ft) = self.fulltext.get_mut(name) {
            // Flag the freshness marker dirty only when a posting actually changed (`remove_document`
            // returns whether the node was present), so a no-op removal does not needlessly force
            // concurrent readers off the fast path (`rmp` task #467). A real removal is also a
            // remove/replace for the rollback poison discriminator (`rmp` task #756): a rolled-back
            // delete can drop a still-committed node from a posting it should occupy.
            if ft.index.remove_document(node_id) {
                self.ft_spatial_dirty = true;
                self.ft_spatial_removed_dirty = true;
            }
        }
    }

    /// Re-derives `node_id`'s entries in **every** registered full-text index from the node's current
    /// label tokens and string property values (`rmp` task #72). The single maintenance entry point
    /// the coordinator drives per write, mirroring [`insert_node_property`](Self::insert_node_property)
    /// for the property indexes.
    ///
    /// For each full-text index: if `label_tokens` contains the index's covered label, the node's
    /// covered property values (the `(prop_key, text)` pairs in `string_props` whose key the index
    /// covers, **in the index's declared property order**) are concatenated, analyzed with the
    /// index's analyzer, and the document is (re-)indexed — replacing the node's previous terms
    /// wholesale (so an update is reflected). If the node does **not** carry the covered label (e.g.
    /// the label was just removed), the node is **removed** from that index. A non-string covered
    /// property is skipped (a full-text index covers text); a node with no covered text is removed.
    pub fn reindex_fulltext_node(
        &mut self,
        node_id: u64,
        label_tokens: &[u32],
        string_props: &[(u32, String)],
    ) {
        // Collect the work first (immutable borrows) so the mutable per-index calls do not alias.
        let names: Vec<String> = self.fulltext.keys().cloned().collect();
        // Whether any covering full-text index's posting actually changed for this node — drives the
        // cross-snapshot freshness marker (`rmp` task #467). A write to a node that NO registered
        // full-text index covers (and whose terms were already absent) leaves every posting unchanged,
        // so such a writer is not a full-text mutator and must not force concurrent readers off the
        // fast path.
        let mut changed = false;
        // Whether any covering full-text index actually DROPPED a pre-existing posting for this node —
        // a remove (lost the covered label) or a wholesale replace (`index_document` reported it swapped
        // out an existing document). This drives the rollback poison discriminator (`rmp` task #756):
        // only a rolled-back remove/replace can drop a still-committed node from a posting it should
        // occupy (a false negative), whereas a rolled-back pure insert (a brand-new node, no prior
        // posting) leaves only a re-check-filterable false positive.
        let mut removed = false;
        for name in names {
            let Some(ft) = self.fulltext.get(&name) else {
                continue;
            };
            // Multi-label semantics (`rmp` task #663): the node is covered iff it carries **any** of
            // the index's covered labels.
            if !ft.label_tokens.iter().any(|lt| label_tokens.contains(lt)) {
                // The node does not (or no longer) carries any covered label: drop it from this index.
                // `remove_document` reports whether it was present (a real posting change / removal).
                if self
                    .fulltext
                    .get_mut(&name)
                    .expect("index present")
                    .index
                    .remove_document(node_id)
                {
                    changed = true;
                    removed = true;
                }
                continue;
            }
            // Gather the covered text in the index's declared property order, then analyze it.
            //
            // EXACTLY ONE value per covered key contributes — the caller's newest. This must NOT become
            // a union over several values of the same key (`rmp` task #766 tried it, `rmp` task #773
            // tracks the residue): unlike the property trees, the full-text consumer canNOT re-check the
            // predicate. `RecordStoreGraph::fulltext_query` re-checks a candidate's VISIBILITY and
            // CURRENT LABEL (`filter_any_label_candidates`) and nothing else, so every term in a node's
            // document is taken as the node's current text. Indexing a stale or uncommitted version's
            // terms therefore does not add a re-checkable false positive — it returns a WRONG ROW
            // (measured: `queryNodes('quantum')` matching a node whose title is now 'classical
            // mechanics'). The candidate-superset argument is only sound where the consumer re-checks.
            let analyzer = ft.analyzer;
            let prop_keys = ft.prop_keys.clone();
            let mut terms: Vec<String> = Vec::new();
            for pk in &prop_keys {
                if let Some((_, text)) = string_props.iter().find(|(k, _)| k == pk) {
                    terms.extend(analyzer.analyze(text));
                }
            }
            // The node carries the covered label, so `index_document` re-indexes it (a wholesale term
            // replace that can both ADD and DROP postings — exactly the stale-reader false-negative
            // this marker guards). Treat any covered re-index as a posting change (the over-mark of the
            // in-flight marker — identical terms re-indexed — only makes concurrent readers
            // conservatively decline; it never returns a wrong answer). But the rollback poison
            // discriminator (`rmp` task #756) must be PRECISE: it flags a removal ONLY when
            // `index_document` reports the document actually CHANGED (returned `true`), so a brand-new
            // node's first index (a pure insert) AND an unchanged re-index (e.g. driven by an unrelated
            // property write) — both safe on rollback — do not poison.
            changed = true;
            if self
                .fulltext
                .get_mut(&name)
                .expect("index present")
                .index
                .index_document(node_id, &terms)
            {
                removed = true;
            }
        }
        if changed {
            self.ft_spatial_dirty = true;
        }
        if removed {
            self.ft_spatial_removed_dirty = true;
        }
    }

    /// Analyzes `search` with the analyzer of the full-text index named `name` and returns the
    /// **candidate** node ids matching it under `semantics`, ascending (`rmp` task #72). [`None`] if
    /// no such index is registered. The caller re-checks visibility, the current label, and the
    /// current text against the transaction snapshot (the candidate-set contract).
    #[must_use]
    pub fn query_fulltext(
        &self,
        name: &str,
        search: &str,
        semantics: MatchSemantics,
    ) -> Option<Vec<u64>> {
        let ft = self.fulltext.get(name)?;
        let terms = ft.analyzer.analyze(search);
        Some(ft.index.query(&terms, semantics))
    }

    /// The per-distinct-term overlap **score** of `node_id` against `search` for the full-text index
    /// named `name`, using the index's analyzer (`rmp` task #72). [`None`] if unregistered. A
    /// best-effort relevance score (see [`InvertedIndex::score`]).
    #[must_use]
    pub fn fulltext_score(&self, name: &str, node_id: u64, search: &str) -> Option<u64> {
        let ft = self.fulltext.get(name)?;
        let terms = ft.analyzer.analyze(search);
        Some(ft.index.score(node_id, &terms))
    }

    // ============================================================================================
    // Relationship full-text indexes (`rmp` task #663)
    // ============================================================================================
    // Structural twins of the node full-text accessors above, keyed by index name in a **separate**
    // map (`fulltext_rel`) whose inverted-index postings are relationship ids and whose covering tokens
    // are relationship-type tokens, so a numeric collision between a label token and a rel-type token
    // never mixes the two catalogs.

    /// Declares (or replaces) the **relationship** full-text index named `name` over `type_tokens`
    /// (one or more relationship types) + `prop_keys`, analyzed by `analyzer`, at `state`
    /// (`rmp` task #663). Idempotent on the name: re-declaring resets its inverted index.
    ///
    /// # Panics
    /// Panics if `prop_keys` or `type_tokens` is empty (a relationship full-text index covers at least
    /// one property and one type — the surface and the durable catalog both enforce this).
    pub fn register_fulltext_rel(
        &mut self,
        name: &str,
        type_tokens: Vec<u32>,
        prop_keys: Vec<u32>,
        analyzer: Analyzer,
        state: IndexState,
    ) {
        assert!(
            !prop_keys.is_empty(),
            "relationship full-text index needs at least one property"
        );
        assert!(
            !type_tokens.is_empty(),
            "relationship full-text index needs at least one type"
        );
        self.fulltext_rel.insert(
            name.to_owned(),
            FulltextRelEntry {
                type_tokens,
                prop_keys,
                analyzer,
                state,
                index: InvertedIndex::new(),
            },
        );
    }

    /// Sets the build [`IndexState`] of the relationship full-text index named `name`. No-op if
    /// unregistered.
    pub fn set_fulltext_rel_state(&mut self, name: &str, state: IndexState) {
        if let Some(ft) = self.fulltext_rel.get_mut(name) {
            ft.state = state;
        }
    }

    /// Unregisters the relationship full-text index named `name`, dropping its inverted index. No-op if
    /// unregistered.
    pub fn unregister_fulltext_rel(&mut self, name: &str) {
        self.fulltext_rel.remove(name);
    }

    /// Whether a relationship full-text index named `name` is registered (in any state).
    #[must_use]
    pub fn has_fulltext_rel(&self, name: &str) -> bool {
        self.fulltext_rel.contains_key(name)
    }

    /// Whether **any** relationship full-text index is registered — the O(1) gate the write path uses to
    /// skip relationship full-text maintenance when none is declared (`rmp` task #663).
    #[must_use]
    pub fn has_any_fulltext_rel(&self) -> bool {
        !self.fulltext_rel.is_empty()
    }

    /// The build [`IndexState`] of the relationship full-text index named `name`, or [`None`].
    #[must_use]
    pub fn fulltext_rel_state(&self, name: &str) -> Option<IndexState> {
        self.fulltext_rel.get(name).map(|ft| ft.state)
    }

    /// The covered `(type_tokens, prop_keys, analyzer)` of the relationship full-text index named
    /// `name`, or [`None`] if unregistered (`rmp` task #663).
    #[must_use]
    pub fn fulltext_rel_target(&self, name: &str) -> Option<(Vec<u32>, Vec<u32>, Analyzer)> {
        self.fulltext_rel
            .get(name)
            .map(|ft| (ft.type_tokens.clone(), ft.prop_keys.clone(), ft.analyzer))
    }

    /// The registered relationship full-text index names (in any state), ascending (`rmp` task #663).
    #[must_use]
    pub fn registered_fulltext_rel(&self) -> Vec<String> {
        let mut names: Vec<String> = self.fulltext_rel.keys().cloned().collect();
        names.sort_unstable();
        names
    }

    /// All relationship full-text indexes that cover `type_token`, as `(name, prop_keys, analyzer)`,
    /// ascending by name (`rmp` task #663) — the per-write-maintenance driver. A multi-type index
    /// matches if `type_token` is **any** of its covered types.
    #[must_use]
    pub fn fulltext_rel_indexes_for_type(
        &self,
        type_token: u32,
    ) -> Vec<(String, Vec<u32>, Analyzer)> {
        let mut out: Vec<(String, Vec<u32>, Analyzer)> = self
            .fulltext_rel
            .iter()
            .filter(|(_, ft)| ft.type_tokens.contains(&type_token))
            .map(|(name, ft)| (name.clone(), ft.prop_keys.clone(), ft.analyzer))
            .collect();
        out.sort_by(|a, b| a.0.cmp(&b.0));
        out
    }

    /// Re-derives relationship `rel_id`'s entries in **every** registered relationship full-text index
    /// from the relationship's current type token and string property values (`rmp` task #663) — the
    /// relationship analogue of [`reindex_fulltext_node`](Self::reindex_fulltext_node).
    ///
    /// For each index: if `type_token` is one of the index's covered types, the relationship's covered
    /// string property values (the `(prop_key, text)` pairs in `string_props` the index covers, in the
    /// index's declared property order) are concatenated, analyzed, and the document is (re-)indexed —
    /// a wholesale term replace, so an update is reflected. If the relationship's type is not covered
    /// (a value/type change that dropped coverage), the relationship is **removed** from that index.
    pub fn reindex_fulltext_rel(
        &mut self,
        rel_id: u64,
        type_token: u32,
        string_props: &[(u32, String)],
    ) {
        let names: Vec<String> = self.fulltext_rel.keys().cloned().collect();
        let mut changed = false;
        // Whether any covering relationship full-text index actually DROPPED a pre-existing posting for
        // this relationship — a remove (type no longer covered) or a wholesale replace. Drives the
        // rollback poison discriminator (`rmp` task #756), exactly as in `reindex_fulltext_node`.
        let mut removed = false;
        for name in names {
            let Some(ft) = self.fulltext_rel.get(&name) else {
                continue;
            };
            if !ft.type_tokens.contains(&type_token) {
                if self
                    .fulltext_rel
                    .get_mut(&name)
                    .expect("index present")
                    .index
                    .remove_document(rel_id)
                {
                    changed = true;
                    removed = true;
                }
                continue;
            }
            // Exactly one value per covered key — the no-union rule of `reindex_fulltext_node`, for the
            // same reason: the relationship full-text consumer re-checks visibility and current type,
            // never the terms (`rmp` tasks #766 / #773).
            let analyzer = ft.analyzer;
            let prop_keys = ft.prop_keys.clone();
            let mut terms: Vec<String> = Vec::new();
            for pk in &prop_keys {
                if let Some((_, text)) = string_props.iter().find(|(k, _)| k == pk) {
                    terms.extend(analyzer.analyze(text));
                }
            }
            // Any covered re-index is a posting change (the same over-mark-is-safe rule as
            // `reindex_fulltext_node`): it only makes concurrent readers conservatively decline. The
            // rollback poison discriminator (`rmp` task #756) is precise: it flags a removal ONLY when
            // `index_document` reports the document actually CHANGED.
            changed = true;
            if self
                .fulltext_rel
                .get_mut(&name)
                .expect("index present")
                .index
                .index_document(rel_id, &terms)
            {
                removed = true;
            }
        }
        if changed {
            // Reuse the shared full-text/spatial freshness marker (`rmp` task #467) so a stale reader of
            // this relationship full-text index declines to the snapshot-correct scan fallback, exactly
            // as it does for a node full-text mutation.
            self.ft_spatial_dirty = true;
        }
        if removed {
            self.ft_spatial_removed_dirty = true;
        }
    }

    /// The **candidate** relationship ids matching `search` under the analyzer of the relationship
    /// full-text index named `name`, ascending (`rmp` task #663). [`None`] if unregistered. The caller
    /// re-checks visibility + current type + current text against the transaction snapshot.
    #[must_use]
    pub fn query_fulltext_rel(
        &self,
        name: &str,
        search: &str,
        semantics: MatchSemantics,
    ) -> Option<Vec<u64>> {
        let ft = self.fulltext_rel.get(name)?;
        let terms = ft.analyzer.analyze(search);
        Some(ft.index.query(&terms, semantics))
    }

    /// The per-distinct-term overlap **score** of relationship `rel_id` against `search` for the
    /// relationship full-text index named `name` (`rmp` task #663). [`None`] if unregistered.
    #[must_use]
    pub fn fulltext_rel_score(&self, name: &str, rel_id: u64, search: &str) -> Option<u64> {
        let ft = self.fulltext_rel.get(name)?;
        let terms = ft.analyzer.analyze(search);
        Some(ft.index.score(rel_id, &terms))
    }

    // ============================================================================================
    // Spatial indexes (`rmp` task #73)
    // ============================================================================================

    /// Declares a spatial index on `(label_token, prop_key)` at `state` with `cell_size` (`rmp` task
    /// #73). Idempotent on the key: if one is already registered its grid is kept but its state is
    /// updated (so a recovered `Online` declaration promotes a freshly-created entry); otherwise a
    /// fresh grid is created.
    pub fn register_spatial(
        &mut self,
        label_token: u32,
        prop_key: u32,
        cell_size: f64,
        state: IndexState,
    ) {
        self.spatial
            .entry((label_token, prop_key))
            .and_modify(|sp| sp.state = state)
            .or_insert_with(|| SpatialEntry {
                state,
                index: SpatialIndex::new(cell_size),
            });
    }

    /// Sets the build [`IndexState`] of the `(label_token, prop_key)` spatial index, e.g. promoting
    /// `Populating` → `Online`. A no-op if no such index is registered.
    pub fn set_spatial_state(&mut self, label_token: u32, prop_key: u32, state: IndexState) {
        if let Some(sp) = self.spatial.get_mut(&(label_token, prop_key)) {
            sp.state = state;
        }
    }

    /// Unregisters the spatial index on `(label_token, prop_key)`, dropping its grid (`rmp` task #73,
    /// `DROP INDEX`). A no-op if no such index is registered.
    pub fn unregister_spatial(&mut self, label_token: u32, prop_key: u32) {
        self.spatial.remove(&(label_token, prop_key));
    }

    /// Whether a spatial index is registered for `(label_token, prop_key)` (in any state).
    #[must_use]
    pub fn has_spatial(&self, label_token: u32, prop_key: u32) -> bool {
        self.spatial.contains_key(&(label_token, prop_key))
    }

    /// The build [`IndexState`] of the `(label_token, prop_key)` spatial index, or [`None`] if
    /// unregistered.
    #[must_use]
    pub fn spatial_state(&self, label_token: u32, prop_key: u32) -> Option<IndexState> {
        self.spatial
            .get(&(label_token, prop_key))
            .map(|sp| sp.state)
    }

    /// The registered spatial index keys `(label_token, prop_key)` in any state, ascending. Used by
    /// the coordinator's rebuild to know which point properties to (re-)index.
    #[must_use]
    pub fn registered_spatial(&self) -> Vec<(u32, u32)> {
        let mut keys: Vec<(u32, u32)> = self.spatial.keys().copied().collect();
        keys.sort_unstable();
        keys
    }

    /// The **`Online`** spatial index keys `(label_token, prop_key)`, ascending. Used to build the
    /// planner's catalog: only an `Online` spatial index may serve a proximity/range seek.
    #[must_use]
    pub fn online_spatial(&self) -> Vec<(u32, u32)> {
        let mut keys: Vec<(u32, u32)> = self
            .spatial
            .iter()
            .filter(|(_, sp)| sp.state == IndexState::Online)
            .map(|(&key, _)| key)
            .collect();
        keys.sort_unstable();
        keys
    }

    /// Records that node `node_id` has point `value` for the `(label_token, prop_key)` spatial index,
    /// if such an index is registered (else a no-op). A non-point `value` is skipped (a spatial index
    /// covers points only) — exactly mirroring the property index's `Null`-is-absent handling.
    /// Maintained regardless of state (a `Populating` index is kept up to date, harmlessly).
    pub fn insert_spatial_point(
        &mut self,
        label_token: u32,
        prop_key: u32,
        value: &Value,
        node_id: u64,
    ) {
        if let Some(sp) = self.spatial.get_mut(&(label_token, prop_key)) {
            if let Value::Point(p) = value {
                // `index_point` is last-wins; it returns whether the point actually CHANGED (the node
                // moved), not merely whether an entry existed.
                let changed = sp.index.index_point(node_id, *p);
                // A point was (re)inserted: a real grid change. Flag the freshness marker dirty so the
                // statement seam records this writer as a full-text/spatial mutator (`rmp` task #467).
                self.ft_spatial_dirty = true;
                // A real move DROPPED the old cell entry, so a rolled-back writer can leave a still-
                // committed node missing from the grid — a false negative. Flag the removal so the
                // rollback path fails closed; a pure insert or an unchanged re-index does not
                // (`rmp` task #756).
                if changed {
                    self.ft_spatial_removed_dirty = true;
                }
            } else {
                // The property is no longer a point (e.g. an update changed its type) — drop the
                // stale grid entry so a re-check never sees a phantom. Only a real removal flags dirty,
                // and a real removal is a remove/replace for the rollback poison (`rmp` task #756).
                if sp.index.remove(node_id) {
                    self.ft_spatial_dirty = true;
                    self.ft_spatial_removed_dirty = true;
                }
            }
        }
    }

    /// **Unions** node `node_id`'s point `value` into the `(label_token, prop_key)` spatial grid without
    /// dropping any cell it already occupies (`rmp` task #779) — the build-path analogue of
    /// [`insert_spatial_point`](Self::insert_spatial_point), which is last-wins. A no-op when no such
    /// index is registered or `value` is not a point (a spatial index covers points only; unlike the
    /// last-wins path there is nothing to remove, because a build only ever adds).
    ///
    /// An index build reads a property's whole version chain and calls this once per point version, so
    /// the grid becomes the candidate **SUPERSET** across all versions — the only image safe for a
    /// structure whose seek re-check can drop a candidate but never resurrect one (`rmp` task #766). The
    /// residual `distance(...) <op> r` filter above the seek drops every version's cell that does not
    /// match the reader's snapshot-visible point.
    ///
    /// Raises only the transient `ft_spatial_dirty` flag (a grid entry changed), never
    /// `ft_spatial_removed_dirty`: a union is a pure insert, so it can never leave a still-committed
    /// node dropped from a cell (`rmp` task #756). The build path clears the flag via
    /// [`bump_ft_spatial_marker_after_build`](Self::bump_ft_spatial_marker_after_build) either way, so
    /// this is never attributed to an open transaction.
    pub fn merge_spatial_point(
        &mut self,
        label_token: u32,
        prop_key: u32,
        value: &Value,
        node_id: u64,
    ) {
        if let Some(sp) = self.spatial.get_mut(&(label_token, prop_key)) {
            if let Value::Point(p) = value {
                sp.index.merge_point(node_id, *p);
                self.ft_spatial_dirty = true;
            }
        }
    }

    /// Removes `node_id` from the `(label_token, prop_key)` spatial index (a delete, a type change, or
    /// a node that lost the covered label). A no-op if no such index is registered.
    pub fn remove_spatial_point(&mut self, label_token: u32, prop_key: u32, node_id: u64) {
        if let Some(sp) = self.spatial.get_mut(&(label_token, prop_key)) {
            // Flag the freshness marker dirty only when a grid entry actually existed and was removed
            // (`remove` returns whether the node was present), so the per-write wholesale re-index's
            // unconditional `remove_spatial_point` over UNcovered nodes does not needlessly force
            // concurrent readers off the fast path (`rmp` task #467). A real removal is a remove/replace
            // for the rollback poison discriminator (`rmp` task #756).
            if sp.index.remove(node_id) {
                self.ft_spatial_dirty = true;
                self.ft_spatial_removed_dirty = true;
            }
        }
    }

    /// Candidate node ids whose `(label_token, prop_key)` point lies within `radius` of `(center_x,
    /// center_y)`, ascending. `None` if no such index is registered; otherwise a **geometric
    /// superset** (`rmp` task #73). The caller re-checks visibility, current label, current value,
    /// CRS, and the exact `distance(loc, center) <= radius` predicate.
    #[must_use]
    pub fn seek_spatial_within(
        &self,
        label_token: u32,
        prop_key: u32,
        center_x: f64,
        center_y: f64,
        radius: f64,
    ) -> Option<Vec<u64>> {
        let sp = self.spatial.get(&(label_token, prop_key))?;
        Some(sp.index.query_within(center_x, center_y, radius))
    }

    /// Candidate node ids whose `(label_token, prop_key)` point lies within the bounding box
    /// `[min_x, max_x] × [min_y, max_y]`, ascending. `None` if no such index is registered; otherwise
    /// a **geometric superset** (`rmp` task #73). The caller re-checks the exact predicate.
    ///
    /// # The exact re-check is MANDATORY, not an optimisation (`rmp` task #779)
    ///
    /// This method has **no production caller today** — the planner lowers only the proximity shape
    /// (`distance(...) <op> r`) to a `SpatialIndexSeek`, never a bounding box — so the warning below is
    /// for whoever wires it up.
    ///
    /// The returned ids are a superset along TWO independent axes, and a consumer that skips the
    /// re-check returns WRONG ROWS on either:
    ///
    /// 1. **Geometric** — the grid buckets whole cells, so a cell clipped by the box contributes points
    ///    outside it (the original `rmp` #73 contract); and
    /// 2. **Temporal** — a node may be indexed at SEVERAL points at once, because an index build unions
    ///    every version of its point property (`rmp` #779). A node whose visible point is far away is
    ///    deliberately still a candidate here, since that union is what stops a committed point being
    ///    indexed nowhere while an uncommitted writer holds the newest version (`rmp` #766).
    ///
    /// Axis 2 is the newer and the easier to overlook: before #779 a node had exactly one indexed point,
    /// so a bbox consumer that skipped the re-check would merely have returned cell-edge false positives
    /// — visibly wrong, but only at the margins. It now returns nodes that are nowhere near the box.
    /// The proximity path stays correct because the planner ALWAYS re-attaches the exact
    /// `distance(...)` predicate as a residual `Filter` above the seek (`Planner::lower_filter` →
    /// `attach_residual`, called with every conjunct), and that residual re-reads each candidate's
    /// snapshot-visible point. A bbox lowering MUST do the same with its coordinate predicate.
    #[must_use]
    pub fn seek_spatial_bbox(
        &self,
        label_token: u32,
        prop_key: u32,
        min_x: f64,
        max_x: f64,
        min_y: f64,
        max_y: f64,
    ) -> Option<Vec<u64>> {
        let sp = self.spatial.get(&(label_token, prop_key))?;
        Some(sp.index.query_bbox(min_x, max_x, min_y, max_y))
    }

    // ============================================================================================
    // Relationship spatial indexes (`rmp` task #664)
    // ============================================================================================

    /// Declares a **relationship** spatial index on `(type_token, prop_key)` at `state` with `cell_size`
    /// (`rmp` task #664) — the relationship analogue of [`register_spatial`](Self::register_spatial).
    /// Idempotent on the key: if one is already registered its grid is kept but its state is updated
    /// (so a recovered `Online` declaration promotes a freshly-created entry); otherwise a fresh grid is
    /// created.
    pub fn register_spatial_rel(
        &mut self,
        type_token: u32,
        prop_key: u32,
        cell_size: f64,
        state: IndexState,
    ) {
        self.spatial_rel
            .entry((type_token, prop_key))
            .and_modify(|sp| sp.state = state)
            .or_insert_with(|| SpatialEntry {
                state,
                index: SpatialIndex::new(cell_size),
            });
    }

    /// Sets the build [`IndexState`] of the `(type_token, prop_key)` relationship spatial index
    /// (`rmp` task #664). A no-op if no such index is registered.
    pub fn set_spatial_rel_state(&mut self, type_token: u32, prop_key: u32, state: IndexState) {
        if let Some(sp) = self.spatial_rel.get_mut(&(type_token, prop_key)) {
            sp.state = state;
        }
    }

    /// Unregisters the relationship spatial index on `(type_token, prop_key)`, dropping its grid
    /// (`rmp` task #664, `DROP INDEX`). A no-op if no such index is registered.
    pub fn unregister_spatial_rel(&mut self, type_token: u32, prop_key: u32) {
        self.spatial_rel.remove(&(type_token, prop_key));
    }

    /// Whether a relationship spatial index is registered for `(type_token, prop_key)` (in any state).
    #[must_use]
    pub fn has_spatial_rel(&self, type_token: u32, prop_key: u32) -> bool {
        self.spatial_rel.contains_key(&(type_token, prop_key))
    }

    /// Whether **any** relationship spatial index is registered (`rmp` task #664). The O(1) gate the
    /// write path uses to skip relationship spatial maintenance when none is declared.
    #[must_use]
    pub fn has_any_spatial_rel(&self) -> bool {
        !self.spatial_rel.is_empty()
    }

    /// The build [`IndexState`] of the `(type_token, prop_key)` relationship spatial index, or [`None`]
    /// if unregistered.
    #[must_use]
    pub fn spatial_rel_state(&self, type_token: u32, prop_key: u32) -> Option<IndexState> {
        self.spatial_rel
            .get(&(type_token, prop_key))
            .map(|sp| sp.state)
    }

    /// The registered relationship spatial index keys `(type_token, prop_key)` in any state, ascending.
    /// Used by the coordinator's rebuild to know which relationship point properties to (re-)index.
    #[must_use]
    pub fn registered_spatial_rel(&self) -> Vec<(u32, u32)> {
        let mut keys: Vec<(u32, u32)> = self.spatial_rel.keys().copied().collect();
        keys.sort_unstable();
        keys
    }

    /// The **`Online`** relationship spatial index keys `(type_token, prop_key)`, ascending. Used to
    /// build the planner's catalog: only an `Online` relationship spatial index may serve a proximity
    /// seek.
    #[must_use]
    pub fn online_spatial_rel(&self) -> Vec<(u32, u32)> {
        let mut keys: Vec<(u32, u32)> = self
            .spatial_rel
            .iter()
            .filter(|(_, sp)| sp.state == IndexState::Online)
            .map(|(&key, _)| key)
            .collect();
        keys.sort_unstable();
        keys
    }

    /// Records that relationship `rel_id` has point `value` for the `(type_token, prop_key)` relationship
    /// spatial index, if such an index is registered (else a no-op) — the relationship analogue of
    /// [`insert_spatial_point`](Self::insert_spatial_point). A non-point `value` drops the stale grid
    /// entry. Maintained regardless of state.
    pub fn insert_spatial_rel_point(
        &mut self,
        type_token: u32,
        prop_key: u32,
        value: &Value,
        rel_id: u64,
    ) {
        if let Some(sp) = self.spatial_rel.get_mut(&(type_token, prop_key)) {
            if let Value::Point(p) = value {
                // Last-wins; `index_point` returns whether the point actually CHANGED — only a real move
                // can drop a still-committed rel from the grid on rollback (`rmp` task #756).
                let changed = sp.index.index_point(rel_id, *p);
                self.ft_spatial_dirty = true;
                if changed {
                    self.ft_spatial_removed_dirty = true;
                }
            } else if sp.index.remove(rel_id) {
                self.ft_spatial_dirty = true;
                self.ft_spatial_removed_dirty = true;
            }
        }
    }

    /// **Unions** relationship `rel_id`'s point `value` into the `(type_token, prop_key)` relationship
    /// spatial grid without dropping any cell it already occupies (`rmp` task #779) — the relationship
    /// analogue of [`merge_spatial_point`](Self::merge_spatial_point), and the build-path counterpart of
    /// the last-wins [`insert_spatial_rel_point`](Self::insert_spatial_rel_point). See
    /// [`merge_spatial_point`](Self::merge_spatial_point) for why a build MUST union every version.
    pub fn merge_spatial_rel_point(
        &mut self,
        type_token: u32,
        prop_key: u32,
        value: &Value,
        rel_id: u64,
    ) {
        if let Some(sp) = self.spatial_rel.get_mut(&(type_token, prop_key)) {
            if let Value::Point(p) = value {
                sp.index.merge_point(rel_id, *p);
                self.ft_spatial_dirty = true;
            }
        }
    }

    /// Removes `rel_id` from the `(type_token, prop_key)` relationship spatial index (a delete, a type
    /// change, or a relationship that lost the covered point property) — the relationship analogue of
    /// [`remove_spatial_point`](Self::remove_spatial_point). A no-op if no such index is registered.
    pub fn remove_spatial_rel_point(&mut self, type_token: u32, prop_key: u32, rel_id: u64) {
        if let Some(sp) = self.spatial_rel.get_mut(&(type_token, prop_key)) {
            // A real removal is a remove/replace for the rollback poison discriminator (`rmp` #756).
            if sp.index.remove(rel_id) {
                self.ft_spatial_dirty = true;
                self.ft_spatial_removed_dirty = true;
            }
        }
    }

    /// Candidate relationship ids whose `(type_token, prop_key)` point lies within `radius` of
    /// `(center_x, center_y)`, ascending (`rmp` task #664). `None` if no such index is registered;
    /// otherwise a **geometric superset** — the caller re-checks visibility, current type, current value,
    /// CRS, and the exact `distance(loc, center) <= radius` predicate. The relationship analogue of
    /// [`seek_spatial_within`](Self::seek_spatial_within).
    #[must_use]
    pub fn seek_spatial_rel_within(
        &self,
        type_token: u32,
        prop_key: u32,
        center_x: f64,
        center_y: f64,
        radius: f64,
    ) -> Option<Vec<u64>> {
        let sp = self.spatial_rel.get(&(type_token, prop_key))?;
        Some(sp.index.query_within(center_x, center_y, radius))
    }

    // ============================================================================================
    // Text (trigram) indexes (`rmp` task #662)
    // ============================================================================================

    /// Declares a text (trigram) index on `(label_token, prop_key)` at `state` (`rmp` task #662).
    /// Idempotent on the key: if one is already registered its trigram index is kept but its state is
    /// updated (so a recovered `Online` declaration promotes a freshly-created entry); otherwise a
    /// fresh trigram index is created.
    pub fn register_text(&mut self, label_token: u32, prop_key: u32, state: IndexState) {
        self.text
            .entry((label_token, prop_key))
            .and_modify(|tx| tx.state = state)
            .or_insert_with(|| TextEntry {
                state,
                index: TrigramIndex::new(),
            });
    }

    /// Sets the build [`IndexState`] of the `(label_token, prop_key)` text index, e.g. promoting
    /// `Populating` → `Online`. A no-op if no such index is registered.
    pub fn set_text_state(&mut self, label_token: u32, prop_key: u32, state: IndexState) {
        if let Some(tx) = self.text.get_mut(&(label_token, prop_key)) {
            tx.state = state;
        }
    }

    /// Unregisters the text index on `(label_token, prop_key)`, dropping its trigram index (`rmp` task
    /// #662, `DROP INDEX`). A no-op if no such index is registered.
    pub fn unregister_text(&mut self, label_token: u32, prop_key: u32) {
        self.text.remove(&(label_token, prop_key));
    }

    /// Whether a text index is registered for `(label_token, prop_key)` (in any state).
    #[must_use]
    pub fn has_text(&self, label_token: u32, prop_key: u32) -> bool {
        self.text.contains_key(&(label_token, prop_key))
    }

    /// The build [`IndexState`] of the `(label_token, prop_key)` text index, or [`None`] if
    /// unregistered.
    #[must_use]
    pub fn text_state(&self, label_token: u32, prop_key: u32) -> Option<IndexState> {
        self.text.get(&(label_token, prop_key)).map(|tx| tx.state)
    }

    /// The registered text index keys `(label_token, prop_key)` in any state, ascending. Used by the
    /// coordinator's rebuild to know which string properties to (re-)index.
    #[must_use]
    pub fn registered_text(&self) -> Vec<(u32, u32)> {
        let mut keys: Vec<(u32, u32)> = self.text.keys().copied().collect();
        keys.sort_unstable();
        keys
    }

    /// The **`Online`** text index keys `(label_token, prop_key)`, ascending. Used to build the
    /// planner's catalog: only an `Online` text index may serve a `CONTAINS`/`ENDS WITH`/`STARTS WITH`
    /// seek.
    #[must_use]
    pub fn online_text(&self) -> Vec<(u32, u32)> {
        let mut keys: Vec<(u32, u32)> = self
            .text
            .iter()
            .filter(|(_, tx)| tx.state == IndexState::Online)
            .map(|(&key, _)| key)
            .collect();
        keys.sort_unstable();
        keys
    }

    /// Records that node `node_id` has string `value` for the `(label_token, prop_key)` text index, if
    /// such an index is registered (else a no-op). A non-string `value` removes the node from the index
    /// (a text index covers strings only) — mirroring the spatial index's non-point handling. Maintained
    /// regardless of state (a `Populating` index is kept up to date, harmlessly).
    pub fn insert_text_value(
        &mut self,
        label_token: u32,
        prop_key: u32,
        value: &Value,
        node_id: u64,
    ) {
        if let Some(tx) = self.text.get_mut(&(label_token, prop_key)) {
            if let Value::String(s) = value {
                // `index_value` is last-wins; it returns whether the indexed content actually CHANGED
                // (different trigrams), not merely whether a value existed.
                let changed = tx.index.index_value(node_id, s);
                // A value was (re)indexed: a real trigram change. Flag the freshness marker dirty so the
                // statement seam records this writer as a full-text/spatial mutator (`rmp` task #467) —
                // the text index rides the same cross-snapshot marker (it too keeps only latest state).
                self.ft_spatial_dirty = true;
                // A real change DROPPED the old trigrams, so a rolled-back writer can leave a still-
                // committed node missing from the index — a false negative. Flag the removal so the
                // rollback path fails closed; a pure insert or an unchanged re-index does not
                // (`rmp` task #756).
                if changed {
                    self.ft_spatial_removed_dirty = true;
                }
            } else if tx.index.remove(node_id) {
                // The property is no longer a string (e.g. an update changed its type) — drop the stale
                // entry so a re-check never sees a phantom. Only a real removal flags dirty, and a real
                // removal is a remove/replace for the rollback poison discriminator (`rmp` task #756).
                self.ft_spatial_dirty = true;
                self.ft_spatial_removed_dirty = true;
            }
        }
    }

    /// **Unions** node `node_id`'s string `value` into the `(label_token, prop_key)` text index without
    /// dropping any trigram it already contributes (`rmp` task #773) — the build-path analogue of
    /// [`insert_text_value`](Self::insert_text_value), which is last-wins. A no-op when no such index is
    /// registered or `value` is not a string (a text index covers strings only; unlike the last-wins
    /// path there is nothing to remove, because a build only ever adds).
    ///
    /// An index build reads a property's whole version chain and calls this once per string version, so
    /// the trigram tree becomes the candidate **SUPERSET** across all versions — the only image safe for
    /// a tree whose seek re-check can drop a candidate but never resurrect one (`rmp` task #766). The
    /// residual `CONTAINS`/`STARTS WITH`/`ENDS WITH` filter above the seek drops every version's trigrams
    /// that do not match the reader's snapshot-visible value.
    ///
    /// Raises only the transient `ft_spatial_dirty` flag (a posting changed), never
    /// `ft_spatial_removed_dirty`: a union is a pure insert, so it can never leave a still-committed node
    /// dropped from a posting (`rmp` task #756). The build path clears the flag via
    /// [`bump_ft_spatial_marker_after_build`](Self::bump_ft_spatial_marker_after_build) either way, so
    /// this is never attributed to an open transaction.
    pub fn merge_text_value(
        &mut self,
        label_token: u32,
        prop_key: u32,
        value: &Value,
        node_id: u64,
    ) {
        if let Some(tx) = self.text.get_mut(&(label_token, prop_key)) {
            if let Value::String(s) = value {
                tx.index.merge_value(node_id, s);
                self.ft_spatial_dirty = true;
            }
        }
    }

    /// Removes `node_id` from the `(label_token, prop_key)` text index (a delete, a type change, or a
    /// node that lost the covered label). A no-op if no such index is registered.
    pub fn remove_text(&mut self, label_token: u32, prop_key: u32, node_id: u64) {
        if let Some(tx) = self.text.get_mut(&(label_token, prop_key)) {
            // Flag the freshness marker dirty only when a trigram entry actually existed and was removed
            // (`remove` returns whether the node was present), so the per-write wholesale re-index's
            // unconditional `remove_text` over UNcovered nodes does not needlessly force concurrent
            // readers off the fast path (`rmp` task #467). A real removal is a remove/replace for the
            // rollback poison discriminator (`rmp` task #756).
            if tx.index.remove(node_id) {
                self.ft_spatial_dirty = true;
                self.ft_spatial_removed_dirty = true;
            }
        }
    }

    /// Candidate node ids whose `(label_token, prop_key)` string may **contain** `needle`, ascending.
    /// [`None`] when no such index is registered **or** `needle` is too short to narrow (the caller then
    /// scans the label); otherwise a candidate **superset** (`rmp` task #662) the caller re-checks with
    /// the exact `CONTAINS` predicate.
    #[must_use]
    pub fn seek_text_contains(
        &self,
        label_token: u32,
        prop_key: u32,
        needle: &str,
    ) -> Option<Vec<u64>> {
        self.text
            .get(&(label_token, prop_key))?
            .index
            .query_contains(needle)
    }

    /// Candidate node ids whose `(label_token, prop_key)` string may **start with** `prefix`, ascending.
    /// [`None`] when no such index is registered **or** `prefix` is too short to narrow; otherwise a
    /// candidate **superset** (`rmp` task #662) the caller re-checks with the exact `STARTS WITH`
    /// predicate.
    #[must_use]
    pub fn seek_text_starts_with(
        &self,
        label_token: u32,
        prop_key: u32,
        prefix: &str,
    ) -> Option<Vec<u64>> {
        self.text
            .get(&(label_token, prop_key))?
            .index
            .query_starts_with(prefix)
    }

    /// Candidate node ids whose `(label_token, prop_key)` string may **end with** `suffix`, ascending.
    /// [`None`] when no such index is registered **or** `suffix` is too short to narrow; otherwise a
    /// candidate **superset** (`rmp` task #662) the caller re-checks with the exact `ENDS WITH`
    /// predicate.
    #[must_use]
    pub fn seek_text_ends_with(
        &self,
        label_token: u32,
        prop_key: u32,
        suffix: &str,
    ) -> Option<Vec<u64>> {
        self.text
            .get(&(label_token, prop_key))?
            .index
            .query_ends_with(suffix)
    }

    // ============================================================================================
    // Vector (HNSW) indexes (`rmp` task #669)
    // ============================================================================================

    /// Declares a **node** vector (HNSW) index on `(label_token, prop_key)` at `state` (`rmp` task
    /// #669). Idempotent on the key: if one is already registered its HNSW graph is kept but its state
    /// is updated (so a recovered `Online` declaration promotes a freshly-created entry); otherwise a
    /// fresh HNSW graph is created with the declared `dim` / `similarity` / `m` / `ef_construction`. The
    /// seed is derived deterministically from the key so the graph is reproducible across a reopen.
    #[allow(clippy::too_many_arguments)]
    pub fn register_vector(
        &mut self,
        label_token: u32,
        prop_key: u32,
        dim: usize,
        similarity: Similarity,
        m: usize,
        ef_construction: usize,
        state: IndexState,
    ) {
        let seed = vector_seed(label_token, prop_key);
        self.vector
            .entry((label_token, prop_key))
            .and_modify(|v| v.state = state)
            .or_insert_with(|| VectorEntry {
                state,
                index: VectorIndex::new(dim, similarity, m, ef_construction, seed)
                    .expect("INVARIANT: vector dimension validated > 0 at create + decode"),
                conflict_blockers: Vec::new(),
            });
    }

    /// Sets the build [`IndexState`] of the `(label_token, prop_key)` node vector index, e.g. promoting
    /// `Populating` → `Online`. A no-op if no such index is registered.
    pub fn set_vector_state(&mut self, label_token: u32, prop_key: u32, state: IndexState) {
        if let Some(v) = self.vector.get_mut(&(label_token, prop_key)) {
            v.state = state;
        }
    }

    /// Unregisters the node vector index on `(label_token, prop_key)`, dropping its HNSW graph
    /// (`rmp` task #669, `DROP INDEX`). A no-op if no such index is registered.
    pub fn unregister_vector(&mut self, label_token: u32, prop_key: u32) {
        self.vector.remove(&(label_token, prop_key));
    }

    /// Whether a node vector index is registered for `(label_token, prop_key)` (in any state).
    #[must_use]
    pub fn has_vector(&self, label_token: u32, prop_key: u32) -> bool {
        self.vector.contains_key(&(label_token, prop_key))
    }

    /// The build [`IndexState`] of the `(label_token, prop_key)` node vector index, or [`None`] if
    /// unregistered.
    #[must_use]
    pub fn vector_state(&self, label_token: u32, prop_key: u32) -> Option<IndexState> {
        self.vector.get(&(label_token, prop_key)).map(|v| v.state)
    }

    // ---- Build-conflict tracking (`rmp` task #780) ------------------------------------------------
    //
    // These eight methods are the whole mechanism. They are deliberately NOT the `rmp` #778 full-text
    // machinery (`ft_build_conflict_writers` / `ft_demoted_blockers` / `conflicted_fulltext_builds`):
    // that machinery parks a CHUNKED build driven by `advance_fulltext_build` and resumes it from a
    // fresh snapshot, whereas a vector build is a SYNCHRONOUS single pass inside the `CREATE` call
    // (`TxnCoordinator::begin_online_vector_index_named`). There is no chunk to park and no pending
    // build to re-enqueue, so bending #778's shape onto it would have carried its whole two-slot
    // drain/park protocol for a build that never yields. The state here is per-index instead of shared,
    // which also keeps one conflicted index from making an unrelated one decline.

    /// Records that the build of the `(label_token, prop_key)` node vector index had to skip an entity
    /// because the still-active transaction `writer` held the newest version of its covered embedding
    /// (`rmp` task #780). Idempotent per writer. A no-op if no such index is registered.
    pub fn note_vector_build_conflict(&mut self, label_token: u32, prop_key: u32, writer: TxnId) {
        if let Some(v) = self.vector.get_mut(&(label_token, prop_key))
            && !v.conflict_blockers.contains(&writer)
        {
            // The empty→non-empty EDGE is the observable event (`rmp` task #780): this index just left
            // the ANN fast path for the exact scan. Counted here rather than per writer so one build
            // blocked by five transactions reports one degradation, not five.
            let entering = v.conflict_blockers.is_empty();
            v.conflict_blockers.push(writer);
            if entering {
                self.vector_conflict_events += 1;
            }
        }
    }

    /// The unresolved writers blocking the `(label_token, prop_key)` node vector index (`rmp` #780).
    /// A non-empty slice means a reader MUST decline this index and take the exact scan instead.
    #[must_use]
    pub fn vector_blockers(&self, label_token: u32, prop_key: u32) -> &[TxnId] {
        self.vector
            .get(&(label_token, prop_key))
            .map_or(&[], |v| v.conflict_blockers.as_slice())
    }

    /// Clears the node vector index's recorded blockers and **wipes its HNSW graph** so a caller can
    /// re-fill it from scratch (`rmp` task #780). Both happen together on purpose: clearing the
    /// blockers without wiping would re-publish a graph that is still missing every skipped entity.
    pub fn reset_vector_for_refill(&mut self, label_token: u32, prop_key: u32) {
        if let Some(v) = self.vector.get_mut(&(label_token, prop_key)) {
            v.conflict_blockers.clear();
            v.index.clear();
        }
    }

    /// Every node vector index key that currently has unresolved build blockers, ascending
    /// (`rmp` task #780) — the work list for the coordinator's re-fill driver.
    #[must_use]
    pub fn conflicted_vector(&self) -> Vec<(u32, u32)> {
        let mut keys: Vec<(u32, u32)> = self
            .vector
            .iter()
            .filter(|(_, v)| !v.conflict_blockers.is_empty())
            .map(|(&key, _)| key)
            .collect();
        keys.sort_unstable();
        keys
    }

    /// Relationship twin of [`note_vector_build_conflict`](Self::note_vector_build_conflict).
    pub fn note_vector_rel_build_conflict(
        &mut self,
        type_token: u32,
        prop_key: u32,
        writer: TxnId,
    ) {
        if let Some(v) = self.vector_rel.get_mut(&(type_token, prop_key))
            && !v.conflict_blockers.contains(&writer)
        {
            // The empty→non-empty edge; see the node twin.
            let entering = v.conflict_blockers.is_empty();
            v.conflict_blockers.push(writer);
            if entering {
                self.vector_conflict_events += 1;
            }
        }
    }

    /// Relationship twin of [`vector_blockers`](Self::vector_blockers).
    #[must_use]
    pub fn vector_rel_blockers(&self, type_token: u32, prop_key: u32) -> &[TxnId] {
        self.vector_rel
            .get(&(type_token, prop_key))
            .map_or(&[], |v| v.conflict_blockers.as_slice())
    }

    /// Relationship twin of [`reset_vector_for_refill`](Self::reset_vector_for_refill).
    pub fn reset_vector_rel_for_refill(&mut self, type_token: u32, prop_key: u32) {
        if let Some(v) = self.vector_rel.get_mut(&(type_token, prop_key)) {
            v.conflict_blockers.clear();
            v.index.clear();
        }
    }

    /// How many VECTOR indexes are **currently** blocked — node and relationship together
    /// (`rmp` task #780). Non-zero means that many k-NN surfaces are serving the exact brute-force
    /// scan while still reporting `ONLINE`. The server publishes this and uses the non-zero→zero edge
    /// to log the recovery.
    #[must_use]
    pub fn blocked_vector_indexes(&self) -> usize {
        self.vector
            .values()
            .filter(|v| !v.conflict_blockers.is_empty())
            .count()
            + self
                .vector_rel
                .values()
                .filter(|v| !v.conflict_blockers.is_empty())
                .count()
    }

    /// How many times a VECTOR index has entered the blocked state over this set's life
    /// (`rmp` task #780) — monotonic; see
    /// [`vector_conflict_events`](Self#structfield.vector_conflict_events).
    #[must_use]
    pub fn vector_conflict_events(&self) -> u64 {
        self.vector_conflict_events
    }

    /// Relationship twin of [`conflicted_vector`](Self::conflicted_vector).
    #[must_use]
    pub fn conflicted_vector_rel(&self) -> Vec<(u32, u32)> {
        let mut keys: Vec<(u32, u32)> = self
            .vector_rel
            .iter()
            .filter(|(_, v)| !v.conflict_blockers.is_empty())
            .map(|(&key, _)| key)
            .collect();
        keys.sort_unstable();
        keys
    }

    /// The registered node vector index keys `(label_token, prop_key)` in any state, ascending. Used by
    /// the coordinator's rebuild to know which embedding properties to (re-)index.
    #[must_use]
    pub fn registered_vector(&self) -> Vec<(u32, u32)> {
        let mut keys: Vec<(u32, u32)> = self.vector.keys().copied().collect();
        keys.sort_unstable();
        keys
    }

    /// The **`Online`** node vector index keys `(label_token, prop_key)`, ascending. Used to build the
    /// planner's catalog: only an `Online` vector index may drive a k-NN seek.
    #[must_use]
    pub fn online_vector(&self) -> Vec<(u32, u32)> {
        let mut keys: Vec<(u32, u32)> = self
            .vector
            .iter()
            .filter(|(_, v)| v.state == IndexState::Online)
            .map(|(&key, _)| key)
            .collect();
        keys.sort_unstable();
        keys
    }

    /// Records that node `node_id` has embedding `value` for the `(label_token, prop_key)` node vector
    /// index, if such an index is registered (else a no-op). A `value` that is not a numeric list of the
    /// declared dimension is treated as **absent**: the node is removed from the graph (so a re-check
    /// never sees a phantom), exactly mirroring the spatial index's non-point handling. Maintained
    /// regardless of state (a `Populating` index is kept up to date, harmlessly).
    pub fn insert_vector_value(
        &mut self,
        label_token: u32,
        prop_key: u32,
        value: &Value,
        node_id: u64,
    ) {
        if let Some(v) = self.vector.get_mut(&(label_token, prop_key)) {
            match extract_embedding(value, v.index.dim()) {
                Some(embedding) => {
                    // `insert` is last-wins, so this also serves the update case, and returns whether the
                    // embedding actually CHANGED (present before AND the vector differs). Only a real
                    // change can drop a still-committed node from the graph on rollback (a false
                    // negative); a pure insert or an unchanged re-index (e.g. a wholesale re-index driven
                    // by an UNRELATED property write) leaves at worst a re-check-filterable false
                    // positive, so it must NOT poison (`rmp` task #756). A dimension mismatch is
                    // impossible here (`extract_embedding` already checked length), so the result is Ok.
                    if let Ok(changed) = v.index.insert(node_id, &embedding) {
                        self.ft_spatial_dirty = true;
                        if changed {
                            self.ft_spatial_removed_dirty = true;
                        }
                    }
                }
                None => {
                    // Absent / malformed embedding: drop any stale graph entry so a seek never sees a
                    // phantom. Only a real removal flags the freshness marker dirty, and a real removal is
                    // a remove/replace for the rollback poison discriminator (`rmp` task #756).
                    if v.index.remove(node_id) {
                        self.ft_spatial_dirty = true;
                        self.ft_spatial_removed_dirty = true;
                    }
                }
            }
        }
    }

    /// Removes `node_id` from the `(label_token, prop_key)` node vector index (a delete, a type change,
    /// or a node that lost the covered label). A no-op if no such index is registered.
    pub fn remove_vector(&mut self, label_token: u32, prop_key: u32, node_id: u64) {
        if let Some(v) = self.vector.get_mut(&(label_token, prop_key)) {
            // A real removal is a remove/replace for the rollback poison discriminator (`rmp` #756).
            if v.index.remove(node_id) {
                self.ft_spatial_dirty = true;
                self.ft_spatial_removed_dirty = true;
            }
        }
    }

    /// The `k` nearest node ids to `query` in the `(label_token, prop_key)` node vector index, as
    /// `(id, score)` pairs by descending score (`rmp` task #669). [`None`] when no such index is
    /// registered; `Some(Err)` on a query-dimension mismatch; otherwise `Some(Ok(hits))`. The caller
    /// re-checks visibility / current label / current value against the store (the ANN graph is a
    /// candidate set).
    #[must_use]
    pub fn seek_vector_knn(
        &self,
        label_token: u32,
        prop_key: u32,
        query: &[f32],
        k: usize,
        ef_search: usize,
    ) -> Option<Result<Vec<(u64, f32)>, VectorIndexError>> {
        let v = self.vector.get(&(label_token, prop_key))?;
        Some(v.index.query_knn(query, k, ef_search))
    }

    /// Declares a **relationship** vector index on `(type_token, prop_key)` (`rmp` task #669) — the
    /// relationship analogue of [`register_vector`](Self::register_vector).
    #[allow(clippy::too_many_arguments)]
    pub fn register_vector_rel(
        &mut self,
        type_token: u32,
        prop_key: u32,
        dim: usize,
        similarity: Similarity,
        m: usize,
        ef_construction: usize,
        state: IndexState,
    ) {
        let seed = vector_seed(type_token, prop_key);
        self.vector_rel
            .entry((type_token, prop_key))
            .and_modify(|v| v.state = state)
            .or_insert_with(|| VectorEntry {
                state,
                index: VectorIndex::new(dim, similarity, m, ef_construction, seed)
                    .expect("INVARIANT: vector dimension validated > 0 at create + decode"),
                conflict_blockers: Vec::new(),
            });
    }

    /// Sets the build [`IndexState`] of the `(type_token, prop_key)` relationship vector index. A no-op
    /// if none is registered.
    pub fn set_vector_rel_state(&mut self, type_token: u32, prop_key: u32, state: IndexState) {
        if let Some(v) = self.vector_rel.get_mut(&(type_token, prop_key)) {
            v.state = state;
        }
    }

    /// Unregisters the relationship vector index on `(type_token, prop_key)`. A no-op if none is
    /// registered.
    pub fn unregister_vector_rel(&mut self, type_token: u32, prop_key: u32) {
        self.vector_rel.remove(&(type_token, prop_key));
    }

    /// Whether a relationship vector index is registered for `(type_token, prop_key)` (in any state).
    #[must_use]
    pub fn has_vector_rel(&self, type_token: u32, prop_key: u32) -> bool {
        self.vector_rel.contains_key(&(type_token, prop_key))
    }

    /// Whether **any** relationship vector index is declared (the O(1) gate `reindex_rel` consults
    /// before decoding a relationship's property chain).
    #[must_use]
    pub fn has_any_vector_rel(&self) -> bool {
        !self.vector_rel.is_empty()
    }

    /// The build [`IndexState`] of the `(type_token, prop_key)` relationship vector index, or [`None`].
    #[must_use]
    pub fn vector_rel_state(&self, type_token: u32, prop_key: u32) -> Option<IndexState> {
        self.vector_rel
            .get(&(type_token, prop_key))
            .map(|v| v.state)
    }

    /// The registered relationship vector index keys `(type_token, prop_key)` in any state, ascending.
    #[must_use]
    pub fn registered_vector_rel(&self) -> Vec<(u32, u32)> {
        let mut keys: Vec<(u32, u32)> = self.vector_rel.keys().copied().collect();
        keys.sort_unstable();
        keys
    }

    /// The **`Online`** relationship vector index keys `(type_token, prop_key)`, ascending. Used to
    /// build the planner's catalog.
    #[must_use]
    pub fn online_vector_rel(&self) -> Vec<(u32, u32)> {
        let mut keys: Vec<(u32, u32)> = self
            .vector_rel
            .iter()
            .filter(|(_, v)| v.state == IndexState::Online)
            .map(|(&key, _)| key)
            .collect();
        keys.sort_unstable();
        keys
    }

    /// Records that relationship `rel_id` has embedding `value` for the `(type_token, prop_key)`
    /// relationship vector index, if registered (else a no-op) — the relationship analogue of
    /// [`insert_vector_value`](Self::insert_vector_value).
    pub fn insert_vector_rel_value(
        &mut self,
        type_token: u32,
        prop_key: u32,
        value: &Value,
        rel_id: u64,
    ) {
        if let Some(v) = self.vector_rel.get_mut(&(type_token, prop_key)) {
            match extract_embedding(value, v.index.dim()) {
                Some(embedding) => {
                    // Last-wins; `insert` returns whether the embedding actually CHANGED — only a real
                    // change can drop a still-committed rel from the graph on rollback, whereas a pure
                    // insert or an unchanged re-index does not (`rmp` task #756).
                    if let Ok(changed) = v.index.insert(rel_id, &embedding) {
                        self.ft_spatial_dirty = true;
                        if changed {
                            self.ft_spatial_removed_dirty = true;
                        }
                    }
                }
                None => {
                    if v.index.remove(rel_id) {
                        self.ft_spatial_dirty = true;
                        self.ft_spatial_removed_dirty = true;
                    }
                }
            }
        }
    }

    /// Removes `rel_id` from the `(type_token, prop_key)` relationship vector index. A no-op if none is
    /// registered.
    pub fn remove_vector_rel(&mut self, type_token: u32, prop_key: u32, rel_id: u64) {
        if let Some(v) = self.vector_rel.get_mut(&(type_token, prop_key)) {
            // A real removal is a remove/replace for the rollback poison discriminator (`rmp` #756).
            if v.index.remove(rel_id) {
                self.ft_spatial_dirty = true;
                self.ft_spatial_removed_dirty = true;
            }
        }
    }

    /// The `k` nearest relationship ids to `query` in the `(type_token, prop_key)` relationship vector
    /// index (`rmp` task #669) — the relationship analogue of
    /// [`seek_vector_knn`](Self::seek_vector_knn).
    #[must_use]
    pub fn seek_vector_rel_knn(
        &self,
        type_token: u32,
        prop_key: u32,
        query: &[f32],
        k: usize,
        ef_search: usize,
    ) -> Option<Result<Vec<(u64, f32)>, VectorIndexError>> {
        let v = self.vector_rel.get(&(type_token, prop_key))?;
        Some(v.index.query_knn(query, k, ef_search))
    }

    // ============================================================================================
    // Cross-snapshot full-text + spatial freshness marker (`rmp` task #467)
    // ============================================================================================
    //
    // The full-text [`InvertedIndex`] and the [`SpatialIndex`] keep only the LATEST state, so a reader
    // whose MVCC snapshot predates a committed replace/delete can get a strict SUBSET of its
    // snapshot-visible matches (a false negative the per-candidate re-check cannot repair, because it
    // filters false positives but cannot resurrect a missing candidate). The marker below is the
    // airtight gate: a reader TRUSTS the index iff `snapshot.ts >= effective_ft_spatial_marker()`,
    // otherwise it declines to the always-correct scan path. See
    // [`ft_spatial_trustworthy_from`](Self#structfield.ft_spatial_trustworthy_from) for the full
    // rationale. The two stamping points (in-flight sentinel at mutation, authoritative commit ts at
    // commit) make it sound against both the open-writer window and all future readers.

    /// The **effective** full-text/spatial freshness marker a reader compares its `snapshot.ts`
    /// against (`rmp` task #467): a reader with `snapshot.ts >= self` uses the fast index path; one
    /// with `snapshot.ts < self` declines to the scan path.
    ///
    /// It is `u64::MAX` (so **every** reader declines — every snapshot ts is `< u64::MAX`) whenever:
    /// - any open transaction has an *uncommitted* full-text/spatial mutation in the index
    ///   ([`ft_spatial_inflight`](Self#structfield.ft_spatial_inflight) non-empty) — the index may
    ///   reflect uncommitted state, so no snapshot may trust it; or
    /// - a full-text/spatial mutator *rolled back* leaving possibly-stale postings
    ///   ([`ft_spatial_poisoned`](Self#structfield.ft_spatial_poisoned)) — the in-memory index is not
    ///   transactional, so the only correct response is the scan path until a rebuild.
    ///
    /// Otherwise it is the committed
    /// [`ft_spatial_trustworthy_from`](Self#structfield.ft_spatial_trustworthy_from): from that ts
    /// onward every full-text/spatial mutation is committed-visible in BOTH the index and the scan, so
    /// the fast path is correct; an older reader correctly declines.
    #[must_use]
    pub fn effective_ft_spatial_marker(&self) -> Timestamp {
        if self.ft_spatial_poisoned || !self.ft_spatial_inflight.is_empty() {
            Timestamp(u64::MAX)
        } else {
            self.ft_spatial_trustworthy_from
        }
    }

    /// Flags that a registered full-text/spatial posting changed during the current statement
    /// (`rmp` task #467). Called by the structural mutation methods themselves (so EVERY caller — the
    /// statement-seam [`reindex_node`](crate::record_graph) AND the coordinator's incremental online
    /// build — is covered). Because the mutation methods carry no [`TxnId`], they only set this
    /// transient flag; the statement seam later converts it to a
    /// [`ft_spatial_inflight`](Self#structfield.ft_spatial_inflight) entry via
    /// [`note_ft_spatial_mutator`](Self::note_ft_spatial_mutator), and the rebuild path discards it via
    /// [`clear_ft_spatial_dirty`](Self::clear_ft_spatial_dirty).
    ///
    /// This manual seam carries **no** information about whether the mutation it stands for *dropped* a
    /// pre-existing posting, so it is classified **conservatively as a removal** (`rmp` task #756): it
    /// also raises [`ft_spatial_removed_dirty`](Self#structfield.ft_spatial_removed_dirty), which fails
    /// closed (a rollback of a txn that used this seam poisons the marker). Over-poisoning is
    /// conservative-safe — it only disables the fast path until the next rebuild — whereas
    /// under-poisoning could miss a real removal and return a false negative. The precise per-site
    /// mutation methods (which know their actual did-remove boolean) are preferred over this seam.
    pub fn mark_ft_spatial_mutated_inflight(&mut self) {
        self.ft_spatial_dirty = true;
        self.ft_spatial_removed_dirty = true;
    }

    /// Converts a pending dirty flag into an in-flight-mutator record for `txn`, returning whether
    /// `txn` was recorded (i.e. whether a full-text/spatial posting changed since the flag was last
    /// cleared) (`rmp` task #467).
    ///
    /// Called by the statement seam ([`reindex_node`](crate::record_graph)) at the end of each write:
    /// if a covered posting changed, `txn` is inserted into
    /// [`ft_spatial_inflight`](Self#structfield.ft_spatial_inflight) (idempotent across the
    /// transaction's many statements) so [`effective_ft_spatial_marker`](Self::effective_ft_spatial_marker)
    /// becomes `u64::MAX` until `txn` retires. The flag is cleared either way, so a subsequent
    /// non-mutating statement of any transaction does not inherit it.
    pub fn note_ft_spatial_mutator(&mut self, txn: TxnId) -> bool {
        // Consume the transient removal flag alongside the dirty flag (`rmp` task #756). By construction
        // `removed ⇒ dirty` (every removal is also a posting change), so a removal is only ever recorded
        // when `txn` is also recorded as an in-flight mutator — keeping `ft_spatial_removers` a subset of
        // `ft_spatial_inflight`. Clearing it here (whether or not a posting changed) prevents a later
        // non-mutating statement of any transaction from inheriting a stale removal signal.
        let removed = self.ft_spatial_removed_dirty;
        self.ft_spatial_removed_dirty = false;
        if self.ft_spatial_dirty {
            self.ft_spatial_inflight.insert(txn);
            self.ft_spatial_dirty = false;
            if removed {
                // This txn dropped/replaced a pre-existing posting: if it later rolls back, the in-memory
                // index may be left with a still-committed node missing from a posting it should occupy
                // (a false negative the re-check cannot resurrect), so the rollback must fail closed.
                self.ft_spatial_removers.insert(txn);
            }
            true
        } else {
            false
        }
    }

    /// Discards any pending dirty flag **without** recording an in-flight mutator (`rmp` task #467).
    ///
    /// The rebuild / online-build path drives the same mutation methods, but its insertions reflect
    /// the *committed* store state and must not be attributed to any open transaction (the build runs
    /// between commands, and a `Populating` index is withheld from the planner). The coordinator calls
    /// this after such a build so the flag the mutation methods raised does not leak into the next
    /// user statement.
    ///
    /// Discards the companion [`ft_spatial_removed_dirty`](Self#structfield.ft_spatial_removed_dirty)
    /// flag too (`rmp` task #756): a rebuild re-indexing committed state may replace postings (raising
    /// the removal flag), but that reflects committed state and must not be attributed to — or poison on
    /// rollback of — any open transaction.
    pub fn clear_ft_spatial_dirty(&mut self) {
        self.ft_spatial_dirty = false;
        self.ft_spatial_removed_dirty = false;
    }

    /// Whether `txn` currently has an uncommitted full-text/spatial mutation recorded (`rmp` task
    /// #467). Used by the coordinator to decide whether a committing/rolling-back transaction was a
    /// full-text/spatial mutator without itself tracking that bit.
    #[must_use]
    pub fn is_ft_spatial_mutator(&self, txn: TxnId) -> bool {
        self.ft_spatial_inflight.contains(&txn)
    }

    /// Retires `txn` as a **committed** full-text/spatial mutator, raising the committed marker to
    /// `commit_ts` (`rmp` task #467). A no-op if `txn` was not a mutator.
    ///
    /// From `commit_ts` onward the writer's change is committed-visible in both the index and the
    /// scan, so a reader at `commit_ts` or later may trust the index; an older reader still declines.
    /// The marker only ever *rises* (`max` with the prior committed value). Because the in-flight set
    /// is keyed by [`TxnId`], [`effective_ft_spatial_marker`](Self::effective_ft_spatial_marker) stays
    /// `u64::MAX` until **every** concurrent mutator has retired — so a sibling writer's still-
    /// uncommitted mutation is never prematurely exposed by this one's commit.
    pub fn commit_ft_spatial_marker(&mut self, txn: TxnId, commit_ts: Timestamp) {
        // A COMMITTED remove/replace is correctly reflected in both the index and the store, so it must
        // never poison — just retire the txn from the removers set (`rmp` task #756). This is cleanup
        // only; the poison decision lives in `rollback_ft_spatial_marker`.
        self.ft_spatial_removers.remove(&txn);
        if self.ft_spatial_inflight.remove(&txn) && commit_ts.0 > self.ft_spatial_trustworthy_from.0
        {
            self.ft_spatial_trustworthy_from = commit_ts;
        }
    }

    /// Retires `txn` as a **rolled-back** full-text/spatial mutator (`rmp` task #467). A no-op if
    /// `txn` was not a mutator.
    ///
    /// A rollback undoes the durable store but **not** the in-memory index (it is not transactional —
    /// see the `rmp` #410 note on [`seek_bitmap_eq`](Self::seek_bitmap_eq)). It **poisons** the marker
    /// ([`effective_ft_spatial_marker`](Self::effective_ft_spatial_marker) pinned at `u64::MAX`, forcing
    /// every reader onto the always-correct scan path until a full
    /// [`reset_ft_spatial_marker`](Self::reset_ft_spatial_marker) rebuilds the index to committed state)
    /// **only when the retiring txn actually removed or replaced a covered posting** — recorded in
    /// [`ft_spatial_removers`](Self#structfield.ft_spatial_removers) (`rmp` task #756).
    ///
    /// The discrimination is the crux of `rmp` #756: a rolled-back *replace* or *delete* can leave a
    /// still-committed node dropped from a posting it should occupy — a false negative the query-time
    /// re-check cannot resurrect — so it MUST fail closed (poison). A rolled-back pure *insert* (e.g. an
    /// aborted `CREATE` of a brand-new node, or an aborted insert that added a posting to a node that had
    /// none) leaves only a re-check-filterable false **positive**, so poisoning it would needlessly
    /// disable the fast path DB-wide for every reader of that index kind until a reopen — the regression
    /// `rmp` #756 fixes. The txn is retired from the in-flight set either way (its window is over).
    /// Conservative but never returns a wrong answer: it only ever poisons on a genuine remove/replace.
    pub fn rollback_ft_spatial_marker(&mut self, txn: TxnId) {
        // Retire the txn from the in-flight set regardless — its uncommitted window is over.
        self.ft_spatial_inflight.remove(&txn);
        // Poison iff this txn dropped/replaced a pre-existing posting. `ft_spatial_removers ⊆
        // ft_spatial_inflight` by construction, so a remover was always also in-flight; keying the poison
        // solely on the removers set is the fail-closed choice (a removal always poisons; a pure insert
        // never does).
        if self.ft_spatial_removers.remove(&txn) {
            self.poison_ft_spatial_marker();
        }
    }

    /// Poisons the full-text/spatial freshness marker unconditionally — no transaction involved
    /// (`rmp` task #733): [`effective_ft_spatial_marker`](Self::effective_ft_spatial_marker) is pinned
    /// at `u64::MAX`, so **every** reader declines to the always-correct scan path until a full
    /// [`reset_ft_spatial_marker`](Self::reset_ft_spatial_marker) rebuilds the latest-state indexes.
    ///
    /// Where [`rollback_ft_spatial_marker`](Self::rollback_ft_spatial_marker) poisons because a *writer*
    /// left possibly-stale postings behind, this poisons because the *index itself* is known to be
    /// untrustworthy: a rebuild whose store scan faulted leaves the inverted indexes / grids empty (see
    /// [`fail_closed`](Self::fail_closed)). Both reach the same conclusion — the in-memory index is not
    /// transactional and cannot be repaired in place, so the only provably-correct response is to stop
    /// reading it.
    pub fn poison_ft_spatial_marker(&mut self) {
        // Count the clean→poisoned EDGE (`rmp` task #803): one observable degradation per entry, not
        // one per poisoning write.
        if !self.ft_spatial_poisoned {
            self.ft_spatial_poison_events += 1;
        }
        self.ft_spatial_poisoned = true;
    }

    /// Whether the cross-snapshot full-text/spatial marker is currently **poisoned** (`rmp` task #803).
    ///
    /// While poisoned, [`effective_ft_spatial_marker`](Self::effective_ft_spatial_marker) is
    /// `u64::MAX`, so EVERY reader declines EVERY node and relationship TEXT / FULLTEXT / SPATIAL seek
    /// to the exact scan — including the off-thread reader pool. Answers stay correct; the "index" now
    /// costs strictly more than having none (measured in the product-recommendations example: 801
    /// dbHits for the seek against 800 for the equivalent full scan), while `SHOW INDEXES` still
    /// reports `ONLINE`.
    ///
    /// Read by the coordinator to (a) drive the repair — only a full `rebuild_index` can clear a
    /// poison, since the poison means the in-memory index may be MISSING a committed posting that no
    /// re-check can resurrect — and (b) publish the state, because a permanent silent DB-wide
    /// degradation is precisely the fault class `rmp` #733 exists to make impossible.
    #[must_use]
    pub fn ft_spatial_poisoned(&self) -> bool {
        self.ft_spatial_poisoned
    }

    /// How many times the marker has been poisoned over this set's life (`rmp` task #803) — monotonic,
    /// counted on the clean→poisoned edge so a repeatedly-poisoning workload reports each transition
    /// once. The server samples it to log the entry at `WARN` and drive a counter.
    #[must_use]
    pub fn ft_spatial_poison_events(&self) -> u64 {
        self.ft_spatial_poison_events
    }

    /// Raises the committed full-text/spatial marker to at least `ts` after an **incremental online
    /// build** chunk, and discards the build's dirty flag (`rmp` task #467).
    ///
    /// An online build (`rmp` tasks #72/#98) re-indexes its build-snapshot nodes' *committed* values
    /// into the inverted index / grid via the instrumented mutation methods. Those committed values
    /// may have been written by transactions that committed **before** the index existed (so they
    /// never bumped this marker on commit). A reader whose snapshot predates such a value would, once
    /// the index is `Online`, get the node keyed by its newer indexed value and miss it for the older
    /// one — the same false negative the marker guards. Stamping the marker up to the store's current
    /// high-water at build progress forces every reader whose snapshot predates the build to decline to
    /// the scan path (correct), while the build's postings reflect committed state at or before that
    /// high-water (so an at-or-after reader trusts them correctly).
    ///
    /// Unlike [`reset_ft_spatial_marker`](Self::reset_ft_spatial_marker) this only ever **raises** the
    /// marker and does **not** clear [`ft_spatial_poisoned`](Self#structfield.ft_spatial_poisoned): an
    /// incremental build covers only its snapshot nodes, so it cannot repair every stale posting a
    /// rolled-back mutator may have left (e.g. on a node created after the build snapshot). Only a full
    /// rebuild ([`reset_ft_spatial_marker`](Self::reset_ft_spatial_marker)) is exhaustive enough to
    /// clear the poison.
    pub fn bump_ft_spatial_marker_after_build(&mut self, ts: Timestamp) {
        if ts.0 > self.ft_spatial_trustworthy_from.0 {
            self.ft_spatial_trustworthy_from = ts;
        }
        self.ft_spatial_dirty = false;
        // The build's committed re-index may have replaced postings (raising the removal flag); discard
        // it so it is never attributed to an open transaction (`rmp` task #756), mirroring the dirty flag.
        self.ft_spatial_removed_dirty = false;
    }

    /// Resets the full-text/spatial freshness marker to `ts` and clears the poison / dirty flags
    /// (`rmp` task #467), called by the coordinator after a full store-consistent index rebuild.
    ///
    /// The rebuilt index reflects exactly the committed state at the store's current high-water `ts`,
    /// so a reader at `ts` or later may trust it (correct — index == committed state at `ts`) and an
    /// older reader declines (conservative, correct). The in-flight set is **not** touched: a rebuild
    /// runs between commands with no open transaction, so it is empty; clearing it would be wrong if a
    /// mutator were somehow open.
    /// Stamps the snapshot timestamp from which the stale-retaining candidate trees (`node_props`,
    /// `rel_props`, `composite`, `rel_composite`) are a faithful image of committed state, after a
    /// [`clear`](Self::clear)-and-refill rebuild (`rmp` tasks #755 / #765). The append-only-class twin of
    /// [`reset_ft_spatial_marker`](Self::reset_ft_spatial_marker) (`rmp` #467), called from the same
    /// place in `TxnCoordinator::rebuild_index` with the same high-water.
    pub fn note_trees_rebuilt(&mut self, ts: Timestamp) {
        self.rebuilt_trees_trustworthy_from = ts;
    }

    /// The snapshot timestamp from which a seek against the stale-retaining candidate trees may be
    /// trusted; a reader older than this must decline to the exact scan (`rmp` tasks #755 / #765). See
    /// [`rebuilt_trees_trustworthy_from`](Self#structfield.rebuilt_trees_trustworthy_from).
    #[must_use]
    pub fn rebuilt_trees_trustworthy_from(&self) -> Timestamp {
        self.rebuilt_trees_trustworthy_from
    }

    pub fn reset_ft_spatial_marker(&mut self, ts: Timestamp) {
        self.ft_spatial_trustworthy_from = ts;
        self.ft_spatial_poisoned = false;
        self.ft_spatial_dirty = false;
        // Clear only the TRANSIENT removal flag (`rmp` task #756), mirroring `ft_spatial_dirty`. The
        // `ft_spatial_removers` set is deliberately NOT touched, exactly as `ft_spatial_inflight` is not:
        // a rebuild runs between commands with no open transaction, so both are empty; clearing them
        // would drop a still-open mutator's poison-on-rollback signal if one were somehow in flight.
        self.ft_spatial_removed_dirty = false;
    }

    // ============================================================================================
    // Bitmap indexes (`rmp` task #328) — low-cardinality columns, opt-in / derived
    // ============================================================================================

    /// Declares a low-cardinality bitmap index on `(label_token, prop_key)` (`rmp` task #328).
    /// Idempotent: re-declaring keeps the existing bitmap. The column is then captured by the
    /// coordinator rebuild and kept membership-exact by the per-write re-index.
    pub fn register_bitmap(&mut self, label_token: u32, prop_key: u32) {
        self.bitmap.entry((label_token, prop_key)).or_default();
        // Remember the *declaration* too, so a fail-closed (which retires the live bitmap) cannot lose
        // the column for the life of the process — a bitmap has no durable catalog to recover it from
        // (`rmp` task #733, M2).
        self.bitmap_declared.insert((label_token, prop_key));
    }

    /// **Drops** the bitmap index on `(label_token, prop_key)`: its bitmaps *and* its declaration, so no
    /// rebuild will bring it back. A no-op if none is registered. This is the explicit-drop path — a
    /// fail-closed must use [`disable_bitmap`](Self::disable_bitmap) instead.
    pub fn unregister_bitmap(&mut self, label_token: u32, prop_key: u32) {
        self.bitmap.remove(&(label_token, prop_key));
        self.bitmap_declared.remove(&(label_token, prop_key));
    }

    /// **Retires** the live bitmap on `(label_token, prop_key)` while KEEPING its declaration
    /// (`rmp` task #733, M2): the column stops answering seeks immediately (its consumers gate on
    /// registration, and a membership-exact index with a hole in it is worse than none), but the next
    /// successful rebuild re-registers and repopulates it from the store. The fail-closed path for a
    /// bitmap.
    pub fn disable_bitmap(&mut self, label_token: u32, prop_key: u32) {
        self.bitmap.remove(&(label_token, prop_key));
    }

    /// The bitmap columns this session **declared**, whether or not a live bitmap is registered for them
    /// right now (`rmp` task #733, M2). A rebuild re-registers exactly these, so a column retired by a
    /// fail-closed comes back once the store is readable again.
    #[must_use]
    pub fn declared_bitmaps(&self) -> Vec<(u32, u32)> {
        self.bitmap_declared.iter().copied().collect()
    }

    /// Re-registers every **declared** bitmap column that has no live index (`rmp` task #733, M2), so the
    /// rebuild's store scan repopulates it. Called by the rebuild right after [`clear`](Self::clear).
    pub fn reregister_declared_bitmaps(&mut self) {
        for key in self.bitmap_declared.clone() {
            self.bitmap.entry(key).or_default();
        }
    }

    /// Whether a bitmap index is registered for `(label_token, prop_key)`.
    #[must_use]
    pub fn has_bitmap(&self, label_token: u32, prop_key: u32) -> bool {
        self.bitmap.contains_key(&(label_token, prop_key))
    }

    /// The registered bitmap index keys `(label_token, prop_key)`, ascending. Used by the
    /// coordinator's rebuild to know which low-cardinality columns to (re-)capture.
    #[must_use]
    pub fn registered_bitmap(&self) -> Vec<(u32, u32)> {
        let mut keys: Vec<(u32, u32)> = self.bitmap.keys().copied().collect();
        keys.sort_unstable();
        keys
    }

    /// Records that node `node_id` currently has `value` for the `(label_token, prop_key)` bitmap
    /// index, if one is registered (else a no-op). A `Null`/unindexable value is skipped. Maintained
    /// membership-exact by the caller's wholesale per-node re-index (which first removes the node from
    /// every value-bitmap of the column — see [`Self::remove_bitmap_node`] — then re-inserts here).
    pub fn insert_bitmap_value(
        &mut self,
        label_token: u32,
        prop_key: u32,
        value: &Value,
        node_id: u64,
    ) {
        if let Some(bm) = self.bitmap.get_mut(&(label_token, prop_key)) {
            bm.insert(value, node_id);
        }
    }

    /// Removes `node_id` from **every** value-bitmap of the `(label_token, prop_key)` index (a delete,
    /// a value change, or a node that lost the covered label). A no-op if none is registered. Cheap
    /// because the column is low-cardinality.
    pub fn remove_bitmap_node(&mut self, label_token: u32, prop_key: u32, node_id: u64) {
        if let Some(bm) = self.bitmap.get_mut(&(label_token, prop_key)) {
            bm.remove_node_everywhere(node_id);
        }
    }

    /// Removes `node_id` from **every** value-bitmap of **every** registered bitmap column, with no
    /// re-insert (`rmp` task #453, F-IDX-4). This is the delete path's de-index: a committed `DELETE n`
    /// removes the node, so its bit must be cleared from all covered columns. Unlike the per-write
    /// re-index ([`RecordStoreGraph::reindex_node`](crate::record_graph)) there is no re-insert — the
    /// node is gone — and unlike re-deriving from the store this needs no read, because a deleted node's
    /// record is only tombstoned (its labels/values are still physically present until GC reclaim), so a
    /// store read would wrongly re-add it. A no-op if no bitmap index is declared.
    pub fn remove_node_from_all_bitmaps(&mut self, node_id: u64) {
        for bm in self.bitmap.values_mut() {
            bm.remove_node_everywhere(node_id);
        }
    }

    /// Records that transaction `txn` touched node `node_id`'s bitmap entry (`rmp` task #453, F-IDX-3),
    /// so an abort can re-derive exactly that node from the reverted store. A no-op unless at least one
    /// bitmap index is registered (a transaction that cannot have touched a bitmap records nothing, so
    /// the map stays empty in the common case). Idempotent per `(txn, node_id)`.
    pub fn note_bitmap_dirty(&mut self, txn: TxnId, node_id: u64) {
        if self.bitmap.is_empty() {
            return; // no bitmap index ⇒ nothing to repair on abort ⇒ record nothing.
        }
        self.dirty_bitmap_nodes
            .entry(txn)
            .or_default()
            .insert(node_id);
    }

    /// Removes and returns the set of node ids whose bitmap `txn` touched (`rmp` task #453), draining
    /// the entry so a later commit/abort of the same id cannot double-process it. Empty (and allocates
    /// nothing) when `txn` touched no bitmap-indexed node. Used by the coordinator's **abort** to know
    /// which nodes to re-derive from the reverted store.
    #[must_use]
    pub fn take_dirty_bitmap_nodes(&mut self, txn: TxnId) -> BTreeSet<u64> {
        self.dirty_bitmap_nodes.remove(&txn).unwrap_or_default()
    }

    /// Drops `txn`'s dirty-bitmap-node set without acting on it (`rmp` task #453) — the **commit** path,
    /// where the eagerly-maintained bitmap already reflects the now-committed writes, so no repair is
    /// needed. A no-op if `txn` touched no bitmap-indexed node.
    pub fn forget_dirty_bitmap_nodes(&mut self, txn: TxnId) {
        self.dirty_bitmap_nodes.remove(&txn);
    }

    /// Candidate node ids whose `(label_token, prop_key)` value equals `value`, ascending. `None` if
    /// no bitmap index is registered for the column; otherwise the membership-exact set (the caller
    /// still re-checks MVCC visibility + the exact predicate, per the candidate contract).
    ///
    /// # Abort/delete repair (`rmp` #453, F-IDX-3/F-IDX-4 — resolved)
    ///
    /// The bitmap is a *membership-exact* candidate source maintained by remove-then-reinsert on a
    /// property/label change ([`remove_bitmap_node`](Self::remove_bitmap_node) +
    /// [`insert_bitmap_value`](Self::insert_bitmap_value)), so an omitted node would make a seek miss a
    /// committed row (a subset — never correct), and unlike the planner's insert-only candidate index
    /// the query-time re-check cannot resurrect a *missing* candidate. Two write paths used to break
    /// this and are now repaired:
    /// - **Abort.** A transaction abort rolls back the durable store but not this in-memory index, so a
    ///   rolled-back (or panic-interrupted mid-reindex) change used to leave the bitmap out of sync.
    ///   Every write that maintains a node's bitmap now records `(txn, node)` via
    ///   [`note_bitmap_dirty`](Self::note_bitmap_dirty) **before** mutating it, and `coordinator::abort`
    ///   re-derives exactly those nodes from the reverted store — so even a panic struck *between* the
    ///   remove and the reinsert is repaired (the node was recorded before the remove).
    /// - **Delete.** A committed `DELETE n` now clears the node from every covered bitmap via
    ///   [`remove_node_from_all_bitmaps`](Self::remove_node_from_all_bitmaps).
    ///
    /// With both in place this seek is membership-exact across aborts and deletes and is safe to wire
    /// into the planner. (The seek itself is still test/diagnostic-only — there is no `plan_physical`
    /// consumer yet — but it no longer *blocks* one.)
    #[must_use]
    pub fn seek_bitmap_eq(
        &self,
        label_token: u32,
        prop_key: u32,
        value: &Value,
    ) -> Option<Vec<u64>> {
        let bm = self.bitmap.get(&(label_token, prop_key))?;
        Some(bm.seek_eq(value))
    }

    /// Candidate node ids satisfying the conjunction `label_token` ∧ (every `(prop_key, value)`
    /// equality in `predicates`), ascending — the **multi-predicate bitmap-AND fast path** (`rmp`
    /// #328). Returns `None` unless **every** predicate's column has a registered bitmap index (so the
    /// caller can fall back to its ordinary seek+filter); otherwise intersects the per-value Roaring
    /// bitmaps entirely inside Roaring and returns the common ids. An empty `predicates` yields `None`
    /// (no conjunction to accelerate).
    ///
    /// Membership-exactness across aborts and deletes is maintained the same way as
    /// [`seek_bitmap_eq`](Self::seek_bitmap_eq) (`rmp` #453, F-IDX-3/F-IDX-4): the abort repair and the
    /// delete de-index keep every value-bitmap in sync with the committed store, so the intersection
    /// here is over membership-exact inputs.
    #[must_use]
    pub fn seek_bitmap_conjunction(
        &self,
        label_token: u32,
        predicates: &[(u32, &Value)],
    ) -> Option<Vec<u64>> {
        if predicates.is_empty() {
            return None;
        }
        // Every conjoined column must be bitmap-indexed, else decline (the caller uses its B-tree /
        // scan path). Collect each predicate's value-bitmap (a `None` entry = value absent ⇒ empty).
        let mut bitmaps = Vec::with_capacity(predicates.len());
        for &(prop_key, value) in predicates {
            let bm = self.bitmap.get(&(label_token, prop_key))?;
            bitmaps.push(bm.bitmap_for(value));
        }
        Some(bitmap::intersect(&bitmaps))
    }

    /// The serialized byte footprint of all bitmaps in the `(label_token, prop_key)` index, or `None`
    /// if none is registered (`rmp` #328 measurement surface — the compressed posting size).
    #[must_use]
    pub fn bitmap_serialized_bytes(&self, label_token: u32, prop_key: u32) -> Option<u64> {
        self.bitmap
            .get(&(label_token, prop_key))
            .map(BitmapIndex::serialized_bytes)
    }

    /// The number of **distinct values** currently held by the `(label_token, prop_key)` bitmap index,
    /// or `None` if none is registered (`rmp` #453, F-IDX-5). Used by the declaration's cardinality
    /// guard to refuse a column whose true built cardinality exceeds
    /// [`graphus_index::bitmap::MAX_DISTINCT_VALUES`].
    #[must_use]
    pub fn bitmap_distinct(&self, label_token: u32, prop_key: u32) -> Option<usize> {
        self.bitmap
            .get(&(label_token, prop_key))
            .map(BitmapIndex::distinct)
    }

    /// All candidate ids for `token` in the backing `tree`, regardless of value. Used as the correct
    /// unbounded-below superset for both the node ([`Self::seek_node_property_range`]) and relationship
    /// ([`Self::seek_rel_property_range`]) range seeks — a node-property and a relationship-property
    /// index share the same layout: the **key** is `token: u32 BE ++ encoded_value ++ rid: u64 BE` and
    /// the **value payload** is `rid: u64 LE`, so one tree scan serves both. Implemented by scanning the
    /// whole keyspace, keeping the entries whose key carries this token in its leading `u32`, and
    /// decoding the rid from the value payload (little-endian).
    fn all_candidates(
        tree: &mut BTree<Dev, Sink>,
        token: u32,
    ) -> graphus_core::error::Result<Vec<u64>> {
        let prefix = token.to_be_bytes();
        // Stream the whole keyspace, decoding the rid out of each matching value slice — no owned
        // `(key, value)` pair per row. The unbounded-below superset semantics are unchanged.
        let mut out: Vec<u64> = Vec::new();
        tree.scan_all_for_each(|k, v| {
            if k.get(0..4) == Some(&prefix[..]) {
                if let Ok(bytes) = v.try_into() {
                    out.push(u64::from_le_bytes(bytes));
                }
            }
        })?;
        Ok(out)
    }
}

impl Default for IndexSet {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use graphus_core::Value;

    fn s(v: &str) -> Value {
        Value::String(v.to_owned())
    }

    #[test]
    fn label_insert_then_seek_returns_inserted_ids_ascending() {
        let mut set = IndexSet::new();
        set.insert_label(7, 100);
        set.insert_label(7, 50);
        set.insert_label(9, 200); // different label token

        assert_eq!(set.seek_label(7), vec![50, 100]);
        assert_eq!(set.seek_label(9), vec![200]);
        assert_eq!(set.seek_label(1), Vec::<u64>::new()); // no entries
    }

    #[test]
    fn register_is_idempotent_and_queryable() {
        let mut set = IndexSet::new();
        assert!(!set.has_node_property(1, 2));
        set.register_node_property(1, 2);
        assert!(set.has_node_property(1, 2));
        // Idempotent: registering again does not panic or wipe state.
        set.insert_node_property(1, 2, &Value::Integer(10), 42);
        set.register_node_property(1, 2);
        assert_eq!(
            set.seek_node_property_eq(1, 2, &Value::Integer(10)),
            Some(vec![42])
        );
    }

    #[test]
    fn node_property_eq_returns_matches_and_none_when_unregistered() {
        let mut set = IndexSet::new();
        set.register_node_property(1, 2);
        set.insert_node_property(1, 2, &Value::Integer(10), 1000);
        set.insert_node_property(1, 2, &Value::Integer(10), 1001); // same value, two ids
        set.insert_node_property(1, 2, &Value::Integer(20), 1002);

        let mut got = set
            .seek_node_property_eq(1, 2, &Value::Integer(10))
            .expect("index is registered");
        got.sort_unstable();
        assert_eq!(got, vec![1000, 1001]);

        // Registered but no such value -> Some(empty), not None.
        assert_eq!(
            set.seek_node_property_eq(1, 2, &Value::Integer(999)),
            Some(Vec::<u64>::new())
        );

        // Unregistered (label_token, prop_key) -> None.
        assert_eq!(set.seek_node_property_eq(1, 3, &Value::Integer(10)), None);
        assert_eq!(set.seek_node_property_eq(9, 2, &Value::Integer(10)), None);
    }

    #[test]
    fn insert_node_property_on_unregistered_is_noop() {
        let mut set = IndexSet::new();
        // No register call: insert is a silent no-op and the pair stays unregistered.
        set.insert_node_property(1, 2, &Value::Integer(10), 42);
        assert!(!set.has_node_property(1, 2));
        assert_eq!(set.seek_node_property_eq(1, 2, &Value::Integer(10)), None);
    }

    #[test]
    fn null_value_is_skipped_silently() {
        let mut set = IndexSet::new();
        set.register_node_property(1, 2);
        // Null is unindexable; the insert is a no-op and does not panic.
        set.insert_node_property(1, 2, &Value::Null, 7);
        // A seek whose bound is unindexable DECLINES (`None`) so the caller takes the exact scan
        // fallback, rather than returning `Some(vec![])` (`rmp` #680; see [`is_index_encodable`]). For a
        // `Null` bound this is still correct AND yields the same result: `= null` is `NULL` for every
        // stored value, so the scan fallback matches nothing either. (The change is load-bearing for a
        // `List` bound, which — unlike `Null` — is *comparable*, so an empty candidate set would
        // wrongly drop a genuinely matching list-valued row.)
        assert_eq!(set.seek_node_property_eq(1, 2, &Value::Null), None);
    }

    /// (`rmp` #598, Finding C-F3): the bitmap is a **membership-exact candidate SOURCE**, so its
    /// per-write maintenance (`RecordStoreGraph::reindex_node`) records the node as bitmap-dirty
    /// **before** the destructive `remove` half of its remove-then-reinsert re-index. This test pins
    /// the crux that makes the maintenance panic window safe **before** the seek is ever wired into
    /// the planner: even if a panic strikes in the gap between the remove and the reinsert — leaving
    /// the node dropped from the bitmap (a subset hazard, reproduced here) — the node was already
    /// captured in the txn's dirty set, so the coordinator's abort path knows to re-derive it from the
    /// reverted store. Were the ordering ever inverted (mutate first, mark second), a panic in that gap
    /// would leave a node silently missing from a candidate source and a query would miss a committed
    /// row. The companion end-to-end proof that the abort re-derive actually *restores* membership
    /// lives in `tests/bitmap_index.rs` (`aborted_set_does_not_desync_bitmap`,
    /// `aborted_delete_restores_bitmap_membership`).
    #[test]
    fn bitmap_maintenance_panic_window_is_captured_before_the_destructive_remove() {
        let txn = TxnId(7);
        let mut set = IndexSet::new();
        set.register_bitmap(1, 2);
        set.insert_bitmap_value(1, 2, &Value::Boolean(true), 100);
        assert_eq!(
            set.seek_bitmap_eq(1, 2, &Value::Boolean(true)),
            Some(vec![100]),
            "the committed value is a bitmap candidate before any re-index"
        );

        // Reproduce the exact state a panic *between* the remove and the reinsert leaves: the
        // maintenance path marks the node dirty FIRST, then removes it — and here the reinsert never
        // runs (the panic struck in that gap).
        set.note_bitmap_dirty(txn, 100);
        set.remove_node_from_all_bitmaps(100);

        assert_eq!(
            set.seek_bitmap_eq(1, 2, &Value::Boolean(true)),
            Some(Vec::<u64>::new()),
            "the subset hazard is real: mid-reindex the node is momentarily absent from the bitmap"
        );
        // The load-bearing guarantee: the node was captured for the abort re-derive despite the
        // reinsert never running. This is only true because the dirty-mark precedes the remove.
        assert_eq!(
            set.take_dirty_bitmap_nodes(txn),
            BTreeSet::from([100]),
            "the node must be captured for abort re-derive even though the reinsert never ran"
        );
    }

    #[test]
    fn range_returns_superset_of_in_range_ids() {
        let mut set = IndexSet::new();
        set.register_node_property(1, 2);
        set.insert_node_property(1, 2, &Value::Integer(-5), 100);
        set.insert_node_property(1, 2, &Value::Integer(0), 101);
        set.insert_node_property(1, 2, &Value::Integer(10), 102);
        set.insert_node_property(1, 2, &Value::Integer(10), 103); // two ids share value 10
        set.insert_node_property(1, 2, &Value::Integer(20), 104);

        // Helper: a result must be a superset of `expected` (every expected id present), and may
        // contain extras (caller re-checks). It must NEVER be a subset.
        let assert_superset = |got: Vec<u64>, expected: &[u64]| {
            for id in expected {
                assert!(got.contains(id), "missing in-range id {id}; got {got:?}");
            }
        };

        // [0, 20): inclusive lower, exclusive upper -> exact mapping, ids 101, 102, 103.
        let r = set
            .seek_node_property_range(
                1,
                2,
                Some((&Value::Integer(0), true)),
                Some((&Value::Integer(20), false)),
            )
            .expect("registered");
        assert_superset(r.clone(), &[101, 102, 103]);
        assert!(
            !r.contains(&100),
            "{:?} must exclude the < 0 id (exact lower)",
            r
        );

        // [0, 10] inclusive upper -> widens to unbounded-above superset; must include 101,102,103
        // and may include 104.
        let r = set
            .seek_node_property_range(
                1,
                2,
                Some((&Value::Integer(0), true)),
                Some((&Value::Integer(10), true)),
            )
            .expect("registered");
        assert_superset(r, &[101, 102, 103]);

        // (0, 20) exclusive lower -> widens to inclusive lower; superset still contains 101.
        let r = set
            .seek_node_property_range(
                1,
                2,
                Some((&Value::Integer(0), false)),
                Some((&Value::Integer(20), false)),
            )
            .expect("registered");
        assert_superset(r, &[102, 103]); // strictly-in-range ids guaranteed present

        // Unbounded below, exclusive upper 20 -> all candidates < 20 superset (returns whole column,
        // a valid superset); must include 100, 101, 102, 103.
        let r = set
            .seek_node_property_range(1, 2, None, Some((&Value::Integer(20), false)))
            .expect("registered");
        assert_superset(r, &[100, 101, 102, 103]);

        // Unbounded both ways -> the whole column.
        let mut r = set
            .seek_node_property_range(1, 2, None, None)
            .expect("registered");
        r.sort_unstable();
        assert_superset(r, &[100, 101, 102, 103, 104]);

        // Unregistered pair -> None.
        assert_eq!(
            set.seek_node_property_range(1, 3, Some((&Value::Integer(0), true)), None),
            None
        );
    }

    #[test]
    fn range_over_strings_unbounded_below_is_superset() {
        // Strings sort below numbers in openCypher orderability; the unbounded-below path must still
        // return them (it returns the whole column), proving the superset guarantee for a value
        // class that an integer-floor lower bound would have missed.
        let mut set = IndexSet::new();
        set.register_node_property(1, 2);
        set.insert_node_property(1, 2, &s("alice"), 1);
        set.insert_node_property(1, 2, &s("bob"), 2);

        let r = set
            .seek_node_property_range(1, 2, None, Some((&s("zzz"), false)))
            .expect("registered");
        assert!(
            r.contains(&1) && r.contains(&2),
            "superset must include both strings; got {r:?}"
        );
    }

    #[test]
    fn clear_empties_the_property_indexes_but_retains_the_label_tree() {
        let mut set = IndexSet::new();
        set.register_node_property(1, 2);
        set.insert_label(7, 100);
        set.insert_node_property(1, 2, &Value::Integer(10), 42);
        assert_eq!(set.seek_label(7), vec![100]);
        assert_eq!(
            set.seek_node_property_eq(1, 2, &Value::Integer(10)),
            Some(vec![42])
        );

        set.clear();
        // The property index's ENTRIES are gone, but its registration is preserved: it is refilled from
        // a source (the MVCC version chain) that can reproduce every version a reader may be owed.
        assert_eq!(
            set.seek_node_property_eq(1, 2, &Value::Integer(10)),
            Some(Vec::<u64>::new())
        );
        assert!(set.has_node_property(1, 2));

        // The LABEL tree is RETAINED across `clear` (`rmp` task #771). Emptying it wrote a subset: labels
        // are mutated in place with no version chain, so the refill reads the CURRENT bitmap and cannot
        // reproduce a committed label an uncommitted writer has removed — and when that writer rolls back,
        // the record bit returns but the destroyed entry does not. Retaining the tree makes the refill
        // purely additive, which the query-time re-check (`node_has_label`) then narrows to the exact set.
        assert_eq!(
            set.seek_label(7),
            vec![100],
            "clear must NOT drop label entries (#771): a destroyed label entry is unrecoverable",
        );

        // Re-insert after clear works, and a retained label entry does not block a new one.
        set.insert_label(7, 200);
        set.insert_node_property(1, 2, &Value::Integer(10), 99);
        assert_eq!(set.seek_label(7), vec![100, 200]);
        assert_eq!(
            set.seek_node_property_eq(1, 2, &Value::Integer(10)),
            Some(vec![99])
        );
    }

    #[test]
    fn indexed_label_tokens_lists_nonempty_tokens_sorted_deduped() {
        let mut set = IndexSet::new();
        assert_eq!(set.indexed_label_tokens(), Vec::<u32>::new());
        set.insert_label(9, 1);
        set.insert_label(7, 2);
        set.insert_label(7, 3); // duplicate token, distinct node
        let tokens = set.indexed_label_tokens();
        assert_eq!(tokens, vec![7, 9]);
    }

    #[test]
    fn registered_node_properties_lists_keys_sorted() {
        let mut set = IndexSet::new();
        assert_eq!(set.registered_node_properties(), Vec::<(u32, u32)>::new());
        set.register_node_property(2, 5);
        set.register_node_property(1, 9);
        set.register_node_property(1, 3);
        assert_eq!(
            set.registered_node_properties(),
            vec![(1, 3), (1, 9), (2, 5)]
        );
    }

    #[test]
    fn register_defaults_to_online() {
        let mut set = IndexSet::new();
        set.register_node_property(1, 2);
        assert_eq!(set.node_property_state(1, 2), Some(IndexState::Online));
        assert_eq!(set.node_property_state(9, 9), None);
    }

    #[test]
    fn online_node_properties_omits_populating_indexes() {
        let mut set = IndexSet::new();
        set.register_node_property_with_state(1, 2, IndexState::Online);
        set.register_node_property_with_state(3, 4, IndexState::Populating);
        // Both are *registered*; only the Online one is exposed to the planner.
        assert_eq!(
            set.registered_node_properties(),
            vec![(1, 2), (3, 4)],
            "registered set must include both states"
        );
        assert_eq!(
            set.online_node_properties(),
            vec![(1, 2)],
            "only the Online index is planner-visible"
        );

        // A Populating index still maintains entries and answers a *direct* seek (the candidate-set
        // model is intact) — it is merely withheld from the planner's catalog.
        set.insert_node_property(3, 4, &Value::Integer(7), 100);
        assert_eq!(
            set.seek_node_property_eq(3, 4, &Value::Integer(7)),
            Some(vec![100])
        );

        // Promote it: now it is planner-visible too.
        set.set_node_property_state(3, 4, IndexState::Online);
        assert_eq!(set.node_property_state(3, 4), Some(IndexState::Online));
        assert_eq!(set.online_node_properties(), vec![(1, 2), (3, 4)]);
    }

    #[test]
    fn register_with_state_is_idempotent_and_updates_state() {
        let mut set = IndexSet::new();
        set.register_node_property_with_state(1, 2, IndexState::Populating);
        set.insert_node_property(1, 2, &Value::Integer(5), 9);
        assert_eq!(set.node_property_state(1, 2), Some(IndexState::Populating));
        // Re-registering Online keeps the entries (idempotent on the backing tree) but promotes state.
        set.register_node_property_with_state(1, 2, IndexState::Online);
        assert_eq!(set.node_property_state(1, 2), Some(IndexState::Online));
        assert_eq!(
            set.seek_node_property_eq(1, 2, &Value::Integer(5)),
            Some(vec![9]),
            "re-registering must not drop the existing entries"
        );
    }

    #[test]
    fn unregister_drops_index_and_entries() {
        let mut set = IndexSet::new();
        set.register_node_property_with_state(1, 2, IndexState::Populating);
        set.insert_node_property(1, 2, &Value::Integer(5), 9);
        assert!(set.has_node_property(1, 2));

        // Unregister: the pair is gone from every registry and answers no seek.
        set.unregister_node_property(1, 2);
        assert!(!set.has_node_property(1, 2));
        assert_eq!(set.node_property_state(1, 2), None);
        assert_eq!(set.registered_node_properties(), Vec::<(u32, u32)>::new());
        assert_eq!(set.online_node_properties(), Vec::<(u32, u32)>::new());
        // A seek on the now-unregistered pair is `None` (unregistered), not `Some(empty)`.
        assert_eq!(set.seek_node_property_eq(1, 2, &Value::Integer(5)), None);

        // Idempotent: unregistering an absent pair is a harmless no-op.
        set.unregister_node_property(1, 2);
        set.unregister_node_property(9, 9);
        assert!(!set.has_node_property(1, 2));
    }

    #[test]
    fn clear_preserves_registered_set_and_state() {
        let mut set = IndexSet::new();
        set.register_node_property_with_state(1, 2, IndexState::Populating);
        set.insert_node_property(1, 2, &Value::Integer(5), 9);
        set.clear();
        // The registered set and its state survive a clear (only the entries are wiped).
        assert_eq!(set.node_property_state(1, 2), Some(IndexState::Populating));
        assert_eq!(
            set.seek_node_property_eq(1, 2, &Value::Integer(5)),
            Some(Vec::<u64>::new())
        );
    }

    // ---- constraints (`rmp` task #99) ------------------------------------------------------

    #[test]
    fn constraint_register_lookup_by_label_and_unregister() {
        let mut set = IndexSet::new();
        assert!(!set.has_constraint("uniq"));
        // Two constraints on label token 1, one on label token 2.
        set.register_constraint("uniq", 1, vec![10], ConstraintKind::Unique, None);
        set.register_constraint("exists", 1, vec![11], ConstraintKind::Existence, None);
        set.register_constraint("other", 2, vec![12], ConstraintKind::Unique, None);
        assert!(set.has_constraint("uniq"));

        // `constraints_for_label` returns only the rules covering that label.
        let mut for_1 = set.constraints_for_label(1);
        for_1.sort_by_key(|r| r.property_tokens[0]);
        assert_eq!(for_1.len(), 2);
        assert_eq!(for_1[0].kind, ConstraintKind::Unique);
        assert_eq!(for_1[0].property_tokens, vec![10]);
        assert_eq!(for_1[1].kind, ConstraintKind::Existence);
        assert_eq!(set.constraints_for_label(2).len(), 1);
        assert!(set.constraints_for_label(99).is_empty());

        // `registered_constraints` lists all, ascending by name.
        let names: Vec<String> = set
            .registered_constraints()
            .into_iter()
            .map(|(n, _)| n)
            .collect();
        assert_eq!(names, vec!["exists", "other", "uniq"]);

        // A clear keeps the constraint registrations (they are declarations, not data).
        set.clear();
        assert!(set.has_constraint("uniq"));
        assert_eq!(set.constraints_for_label(1).len(), 2);

        // Unregister removes only that constraint.
        set.unregister_constraint("uniq");
        assert!(!set.has_constraint("uniq"));
        assert_eq!(set.constraints_for_label(1).len(), 1);
    }

    #[test]
    fn constraint_register_carries_type_descriptor() {
        let mut set = IndexSet::new();
        set.register_constraint(
            "typed",
            1,
            vec![10],
            ConstraintKind::PropertyType,
            Some(ConstraintTypeDescriptor::Integer),
        );
        let rule = set.constraints_for_label(1).pop().expect("one rule");
        assert_eq!(rule.kind, ConstraintKind::PropertyType);
        assert_eq!(
            rule.type_descriptor,
            Some(ConstraintTypeDescriptor::Integer)
        );
    }

    // ---- composite indexes (`rmp` task #100, node-key backing) ----------------------------

    #[test]
    fn composite_register_insert_seek_and_clear() {
        let mut set = IndexSet::new();
        assert!(!set.has_composite(1, &[10, 11]));
        set.register_composite(1, vec![10, 11]);
        assert!(set.has_composite(1, &[10, 11]));
        assert_eq!(set.registered_composite(), vec![(1u32, vec![10, 11])]);

        // Two nodes share the same composite tuple; a third differs in the second field.
        let tuple_a = [Value::Integer(7), Value::String("x".to_owned())];
        let tuple_b = [Value::Integer(7), Value::String("y".to_owned())];
        set.insert_composite(1, &[10, 11], &tuple_a, 100);
        set.insert_composite(1, &[10, 11], &tuple_a, 101);
        set.insert_composite(1, &[10, 11], &tuple_b, 102);

        let mut hits = set.seek_composite_eq(1, &[10, 11], &tuple_a).unwrap();
        hits.sort_unstable();
        assert_eq!(hits, vec![100, 101]);
        assert_eq!(
            set.seek_composite_eq(1, &[10, 11], &tuple_b).unwrap(),
            vec![102]
        );

        // An unregistered tuple seeks to `None` (scan fallback), not an empty candidate set.
        assert_eq!(set.seek_composite_eq(1, &[10], &tuple_a), None);
        assert_eq!(set.seek_composite_eq(9, &[10, 11], &tuple_a), None);

        // A clear keeps the registration but drops entries.
        set.clear();
        assert!(set.has_composite(1, &[10, 11]));
        assert_eq!(
            set.seek_composite_eq(1, &[10, 11], &tuple_a),
            Some(Vec::<u64>::new())
        );

        // Unregister drops it entirely.
        set.unregister_composite(1, &[10, 11]);
        assert!(!set.has_composite(1, &[10, 11]));
        assert_eq!(set.seek_composite_eq(1, &[10, 11], &tuple_a), None);
    }

    // ---- full-text (`rmp` task #72) --------------------------------------------------------

    #[test]
    fn fulltext_register_index_query_and_state() {
        let mut set = IndexSet::new();
        assert!(!set.has_fulltext("ft"));
        set.register_fulltext(
            "ft",
            vec![1],
            vec![5, 6],
            Analyzer::Standard,
            IndexState::Online,
        );
        assert!(set.has_fulltext("ft"));
        assert_eq!(set.fulltext_state("ft"), Some(IndexState::Online));
        assert_eq!(
            set.fulltext_target("ft"),
            Some((vec![1], vec![5, 6], Analyzer::Standard))
        );
        assert_eq!(set.registered_fulltext(), vec!["ft".to_owned()]);

        // Index documents through the SAME analyzer used at query time.
        let terms_a = Analyzer::Standard.analyze("The Quick Brown Fox");
        let terms_b = Analyzer::Standard.analyze("A slow brown bear");
        set.index_fulltext_document("ft", 100, &terms_a);
        set.index_fulltext_document("ft", 200, &terms_b);

        // OR query "brown" -> both; "fox" -> only 100.
        assert_eq!(
            set.query_fulltext("ft", "brown", MatchSemantics::Or),
            Some(vec![100, 200])
        );
        assert_eq!(
            set.query_fulltext("ft", "FOX", MatchSemantics::Or),
            Some(vec![100])
        );
        // A stop-word-only search matches nothing.
        assert_eq!(
            set.query_fulltext("ft", "the a", MatchSemantics::Or),
            Some(Vec::<u64>::new())
        );
        // Unregistered index -> None.
        assert_eq!(set.query_fulltext("nope", "x", MatchSemantics::Or), None);
    }

    #[test]
    fn fulltext_update_delete_and_unregister() {
        let mut set = IndexSet::new();
        set.register_fulltext(
            "ft",
            vec![1],
            vec![5],
            Analyzer::Standard,
            IndexState::Populating,
        );
        set.index_fulltext_document("ft", 100, &Analyzer::Standard.analyze("graph database"));
        assert_eq!(
            set.query_fulltext("ft", "database", MatchSemantics::Or),
            Some(vec![100])
        );

        // Update: re-index with new text replaces the old terms wholesale.
        set.index_fulltext_document("ft", 100, &Analyzer::Standard.analyze("graph theory"));
        assert_eq!(
            set.query_fulltext("ft", "database", MatchSemantics::Or),
            Some(Vec::<u64>::new())
        );
        assert_eq!(
            set.query_fulltext("ft", "theory", MatchSemantics::Or),
            Some(vec![100])
        );

        // Delete the document.
        set.remove_fulltext_document("ft", 100);
        assert_eq!(
            set.query_fulltext("ft", "graph", MatchSemantics::Or),
            Some(Vec::<u64>::new())
        );

        // Promote then unregister.
        set.set_fulltext_state("ft", IndexState::Online);
        assert_eq!(set.fulltext_state("ft"), Some(IndexState::Online));
        set.unregister_fulltext("ft");
        assert!(!set.has_fulltext("ft"));
        assert_eq!(set.query_fulltext("ft", "graph", MatchSemantics::Or), None);
    }

    #[test]
    fn fulltext_indexes_for_label_filters_by_label_token() {
        let mut set = IndexSet::new();
        set.register_fulltext(
            "a",
            vec![1],
            vec![5],
            Analyzer::Standard,
            IndexState::Online,
        );
        set.register_fulltext("b", vec![1], vec![6], Analyzer::Keyword, IndexState::Online);
        set.register_fulltext(
            "c",
            vec![2],
            vec![7],
            Analyzer::Standard,
            IndexState::Online,
        );
        // A multi-label index over labels {2, 3} is matched for label 2 (any covered label, `rmp` #663).
        set.register_fulltext(
            "d",
            vec![2, 3],
            vec![8],
            Analyzer::Standard,
            IndexState::Online,
        );
        let for_1 = set.fulltext_indexes_for_label(1);
        assert_eq!(for_1.len(), 2);
        assert_eq!(for_1[0].0, "a");
        assert_eq!(for_1[1].0, "b");
        assert_eq!(set.fulltext_indexes_for_label(2).len(), 2); // "c" + multi-label "d"
        assert_eq!(set.fulltext_indexes_for_label(3).len(), 1); // multi-label "d"
        assert_eq!(set.fulltext_indexes_for_label(9).len(), 0);
    }

    #[test]
    fn fulltext_rel_register_index_query_and_state() {
        // `rmp` task #663: the relationship full-text index mirrors the node one over a separate map.
        let mut set = IndexSet::new();
        assert!(!set.has_fulltext_rel("rt"));
        assert!(!set.has_any_fulltext_rel());
        set.register_fulltext_rel(
            "rt",
            vec![1, 2],
            vec![5],
            Analyzer::Standard,
            IndexState::Online,
        );
        assert!(set.has_fulltext_rel("rt"));
        assert!(set.has_any_fulltext_rel());
        assert_eq!(set.fulltext_rel_state("rt"), Some(IndexState::Online));
        assert_eq!(
            set.fulltext_rel_target("rt"),
            Some((vec![1, 2], vec![5], Analyzer::Standard))
        );
        assert_eq!(set.registered_fulltext_rel(), vec!["rt".to_owned()]);
        // A multi-type index over types {1, 2} is matched for either type.
        assert_eq!(set.fulltext_rel_indexes_for_type(1).len(), 1);
        assert_eq!(set.fulltext_rel_indexes_for_type(2).len(), 1);
        assert_eq!(set.fulltext_rel_indexes_for_type(9).len(), 0);

        // Maintain + query by rel id.
        set.reindex_fulltext_rel(100, 1, &[(5, "graph database".to_owned())]);
        set.reindex_fulltext_rel(200, 2, &[(5, "graph theory".to_owned())]);
        assert_eq!(
            set.query_fulltext_rel("rt", "graph", MatchSemantics::Or),
            Some(vec![100, 200])
        );
        assert_eq!(
            set.query_fulltext_rel("rt", "database", MatchSemantics::Or),
            Some(vec![100])
        );
        assert_eq!(set.fulltext_rel_score("rt", 100, "graph database"), Some(2));

        // A type change that drops coverage removes the rel from the index.
        set.reindex_fulltext_rel(100, 9, &[(5, "graph database".to_owned())]);
        assert_eq!(
            set.query_fulltext_rel("rt", "graph", MatchSemantics::Or),
            Some(vec![200])
        );

        set.unregister_fulltext_rel("rt");
        assert!(!set.has_fulltext_rel("rt"));
        assert!(!set.has_any_fulltext_rel());
        assert_eq!(set.query_fulltext_rel("rt", "x", MatchSemantics::Or), None);
    }

    #[test]
    fn fulltext_clear_preserves_registration_drops_entries() {
        let mut set = IndexSet::new();
        set.register_fulltext(
            "ft",
            vec![1],
            vec![5],
            Analyzer::Standard,
            IndexState::Online,
        );
        set.index_fulltext_document("ft", 100, &Analyzer::Standard.analyze("graph"));
        set.clear();
        // Registration + state survive; entries are gone.
        assert!(set.has_fulltext("ft"));
        assert_eq!(set.fulltext_state("ft"), Some(IndexState::Online));
        assert_eq!(
            set.query_fulltext("ft", "graph", MatchSemantics::Or),
            Some(Vec::<u64>::new())
        );
    }

    #[test]
    fn fulltext_score_uses_index_analyzer() {
        let mut set = IndexSet::new();
        set.register_fulltext(
            "ft",
            vec![1],
            vec![5],
            Analyzer::Standard,
            IndexState::Online,
        );
        set.index_fulltext_document(
            "ft",
            100,
            &Analyzer::Standard.analyze("graph database fast"),
        );
        // "graph database slow" overlaps on 2 distinct terms.
        assert_eq!(
            set.fulltext_score("ft", 100, "graph database slow"),
            Some(2)
        );
        assert_eq!(set.fulltext_score("nope", 100, "x"), None);
    }

    // ---- Spatial index (`rmp` task #73) -------------------------------------------------------

    fn pt(x: f64, y: f64) -> Value {
        use graphus_core::value::spatial::{Crs, Point};
        Value::Point(Point::new_2d(Crs::Cartesian, x, y))
    }

    #[test]
    fn spatial_register_insert_seek_and_maintenance() {
        let mut set = IndexSet::new();
        set.register_spatial(1, 5, 1.0, IndexState::Online);
        assert!(set.has_spatial(1, 5));
        assert_eq!(set.spatial_state(1, 5), Some(IndexState::Online));

        set.insert_spatial_point(1, 5, &pt(0.5, 0.5), 100);
        set.insert_spatial_point(1, 5, &pt(0.7, 0.2), 101); // same cell
        set.insert_spatial_point(1, 5, &pt(50.0, 50.0), 102); // far away
        // A non-point value is skipped (not indexed).
        set.insert_spatial_point(1, 5, &Value::Integer(7), 103);

        // Proximity around the origin returns the two near points as candidates, not the far one.
        let mut got = set.seek_spatial_within(1, 5, 0.0, 0.0, 1.5).unwrap();
        got.sort_unstable();
        assert_eq!(got, vec![100, 101]);
        // The non-point node was never indexed.
        assert!(!got.contains(&103));

        // Update: move 101 far away → it leaves the origin cell.
        set.insert_spatial_point(1, 5, &pt(60.0, 60.0), 101);
        assert_eq!(
            set.seek_spatial_within(1, 5, 0.0, 0.0, 1.5).unwrap(),
            vec![100]
        );

        // Delete 100.
        set.remove_spatial_point(1, 5, 100);
        assert!(
            set.seek_spatial_within(1, 5, 0.0, 0.0, 1.5)
                .unwrap()
                .is_empty()
        );

        // A bbox seek works too.
        let mut bbox = set.seek_spatial_bbox(1, 5, 49.0, 61.0, 49.0, 61.0).unwrap();
        bbox.sort_unstable();
        assert_eq!(bbox, vec![101, 102]);

        // No such index → None (distinct from an empty candidate list).
        assert_eq!(set.seek_spatial_within(9, 9, 0.0, 0.0, 1.0), None);
    }

    #[test]
    fn spatial_state_gates_planner_exposure() {
        let mut set = IndexSet::new();
        set.register_spatial(1, 5, 1.0, IndexState::Populating);
        // Maintained while populating...
        set.insert_spatial_point(1, 5, &pt(0.0, 0.0), 100);
        assert_eq!(
            set.seek_spatial_within(1, 5, 0.0, 0.0, 1.0).unwrap(),
            vec![100]
        );
        // ...but not surfaced to the planner until Online.
        assert_eq!(set.registered_spatial(), vec![(1, 5)]);
        assert!(set.online_spatial().is_empty());
        set.set_spatial_state(1, 5, IndexState::Online);
        assert_eq!(set.online_spatial(), vec![(1, 5)]);
        // Drop removes it entirely.
        set.unregister_spatial(1, 5);
        assert!(!set.has_spatial(1, 5));
        assert!(set.registered_spatial().is_empty());
    }

    #[test]
    fn text_register_insert_seek_and_maintenance() {
        let mut set = IndexSet::new();
        set.register_text(1, 5, IndexState::Online);
        assert!(set.has_text(1, 5));
        assert_eq!(set.text_state(1, 5), Some(IndexState::Online));

        set.insert_text_value(1, 5, &s("database"), 100);
        set.insert_text_value(1, 5, &s("warehouse"), 101);
        // A non-string value is skipped (not indexed).
        set.insert_text_value(1, 5, &Value::Integer(7), 102);

        // CONTAINS / ENDS WITH / STARTS WITH candidate seeks.
        assert_eq!(set.seek_text_contains(1, 5, "atab"), Some(vec![100]));
        assert_eq!(set.seek_text_ends_with(1, 5, "house"), Some(vec![101]));
        assert_eq!(set.seek_text_starts_with(1, 5, "data"), Some(vec![100]));
        // The non-string node was never indexed.
        assert!(!set.seek_text_contains(1, 5, "abas").unwrap().contains(&102));

        // Update: 100's value changes → its old trigrams are gone (wholesale replace).
        set.insert_text_value(1, 5, &s("archive"), 100);
        assert_eq!(set.seek_text_contains(1, 5, "atab"), Some(Vec::new()));
        assert_eq!(set.seek_text_contains(1, 5, "rchi"), Some(vec![100]));

        // Delete 101.
        set.remove_text(1, 5, 101);
        assert_eq!(set.seek_text_ends_with(1, 5, "house"), Some(Vec::new()));

        // A short needle → None (cannot narrow, the caller scans); no such index → None.
        assert_eq!(set.seek_text_contains(1, 5, "ab"), None);
        assert_eq!(set.seek_text_contains(9, 9, "abc"), None);
    }

    #[test]
    fn text_state_gates_planner_exposure() {
        let mut set = IndexSet::new();
        set.register_text(1, 5, IndexState::Populating);
        // Maintained while populating...
        set.insert_text_value(1, 5, &s("database"), 100);
        assert_eq!(set.seek_text_contains(1, 5, "atab"), Some(vec![100]));
        // ...but not surfaced to the planner until Online.
        assert_eq!(set.registered_text(), vec![(1, 5)]);
        assert!(set.online_text().is_empty());
        set.set_text_state(1, 5, IndexState::Online);
        assert_eq!(set.online_text(), vec![(1, 5)]);
        // Clear drops the entries but keeps the registration + state (like the other kinds).
        set.clear();
        assert!(set.has_text(1, 5));
        assert_eq!(set.seek_text_contains(1, 5, "atab"), Some(Vec::new()));
        // Drop removes it entirely.
        set.unregister_text(1, 5);
        assert!(!set.has_text(1, 5));
        assert!(set.registered_text().is_empty());
    }

    /// `fail_closed` must make **every** index unusable — not merely empty (`rmp` task #733). An empty
    /// index that still answers is the worst possible state: it returns zero rows, silently.
    #[test]
    fn fail_closed_makes_every_index_unusable() {
        let mut set = IndexSet::new();
        set.register_node_property_with_state(1, 5, IndexState::Online);
        set.register_rel_property_with_state(2, 5, IndexState::Online);
        set.register_fulltext(
            "ft",
            vec![1],
            vec![5],
            Analyzer::Standard,
            IndexState::Online,
        );
        set.register_fulltext_rel(
            "ftr",
            vec![2],
            vec![5],
            Analyzer::Standard,
            IndexState::Online,
        );
        set.register_spatial(1, 6, 1.0, IndexState::Online);
        set.register_spatial_rel(2, 6, 1.0, IndexState::Online);
        set.register_text(1, 5, IndexState::Online);
        set.register_vector(1, 7, 3, Similarity::Cosine, 16, 100, IndexState::Online);
        set.register_vector_rel(2, 7, 3, Similarity::Cosine, 16, 100, IndexState::Online);
        set.register_composite(1, vec![5, 6]);
        set.register_rel_composite(2, vec![5, 6]);
        set.register_bitmap(1, 8);
        set.insert_label(1, 100);
        assert!(set.labels_usable());

        set.fail_closed();

        // The state-carrying kinds are demoted out of `Online`, so the planner's `online_*` surfaces —
        // and, since `rmp` #733, the read seams themselves — decline them.
        assert!(set.online_node_properties().is_empty());
        assert!(set.online_rel_properties().is_empty());
        assert_eq!(set.fulltext_state("ft"), Some(IndexState::Populating));
        assert_eq!(set.fulltext_rel_state("ftr"), Some(IndexState::Populating));
        assert!(set.online_spatial().is_empty());
        assert!(set.online_spatial_rel().is_empty());
        assert!(set.online_text().is_empty());
        assert!(set.online_vector().is_empty());
        assert!(set.online_vector_rel().is_empty());
        // The state-less candidate sources are unregistered: their consumers gate on registration, and a
        // node-key duplicate check trusts the composite tree as EXACT (an empty one would admit a
        // duplicate).
        assert!(!set.has_composite(1, &[5, 6]));
        assert!(!set.has_rel_composite(2, &[5, 6]));
        assert!(!set.has_bitmap(1, 8));
        // The label index — the base of every scan fallback — is no longer trusted, so a label scan
        // enumerates the store instead of reading an empty index.
        assert!(!set.labels_usable());
        // And every latest-state reader is forced onto the scan path.
        assert_eq!(set.effective_ft_spatial_marker(), Timestamp(u64::MAX));

        // The wipe is an EPOCH change, and the degradation is observable (`rmp` task #733): an in-flight
        // incremental build lives on the coordinator, out of reach from here, so the only way to stop it
        // resuming over the wreckage — and publishing an `Online` index holding just the tail of its
        // snapshot — is for it to notice that the epoch moved.
        assert_eq!(set.wipe_generation(), 1, "fail_closed opens a new epoch");
        assert!(set.is_degraded(), "the degradation must be observable");
        assert_eq!(set.fail_closed_events(), 1, "and counted, for the metric");

        // A later successful rebuild heals it: `clear` restores the label index's trust, and the
        // registrations are re-established from the durable catalog by the caller.
        set.clear();
        assert!(set.labels_usable());
        assert!(!set.rebuild_gap());
        set.heal();
        assert!(!set.is_degraded(), "a completed rebuild repairs the engine");
        // The epoch does NOT rewind: a build invalidated by the wipe must still restart, even though the
        // index set is healthy again.
        assert_eq!(set.wipe_generation(), 1);
        // A second wipe opens a second epoch (so a build cannot mistake it for the first).
        set.fail_closed();
        assert_eq!(set.wipe_generation(), 2);
        assert_eq!(set.fail_closed_events(), 2);
    }

    /// A per-entity read fault during a build must be **recorded**, not swallowed: the build reads the
    /// flag back and refuses to publish an index it knows has a hole in it (`rmp` task #733).
    #[test]
    fn a_rebuild_gap_is_recorded_and_cleared() {
        let mut set = IndexSet::new();
        assert!(!set.rebuild_gap());
        set.note_rebuild_gap();
        assert!(set.rebuild_gap());
        set.clear_rebuild_gap();
        assert!(!set.rebuild_gap());
        // `fail_closed` consumes the gap (it has acted on it).
        set.note_rebuild_gap();
        set.fail_closed();
        assert!(!set.rebuild_gap());
    }

    // ---- Vector (HNSW) index (`rmp` task #669) ------------------------------------------------

    /// A 3-D embedding [`Value::List`] from integer coordinates (round-trip through `extract_embedding`).
    fn emb(x: i64, y: i64, z: i64) -> Value {
        Value::List(vec![
            Value::Integer(x),
            Value::Integer(y),
            Value::Integer(z),
        ])
    }

    #[test]
    fn vector_register_insert_seek_and_maintenance() {
        let mut set = IndexSet::new();
        set.register_vector(1, 5, 3, Similarity::Euclidean, 16, 200, IndexState::Online);
        assert!(set.has_vector(1, 5));
        assert_eq!(set.vector_state(1, 5), Some(IndexState::Online));

        set.insert_vector_value(1, 5, &emb(0, 0, 0), 100);
        set.insert_vector_value(1, 5, &emb(10, 0, 0), 101);
        set.insert_vector_value(1, 5, &emb(0, 10, 0), 102);
        // A malformed value (wrong length / non-list / non-numeric / non-finite) is NOT indexed.
        set.insert_vector_value(1, 5, &Value::List(vec![Value::Integer(1)]), 200); // wrong length
        set.insert_vector_value(1, 5, &Value::Integer(7), 201); // not a list
        // NaN / ±∞ are invalid embeddings (Neo4j parity, `rmp` #669 audit follow-up): a `NaN` distance
        // would otherwise rank first under the `total_cmp` result order. They stay out of the graph.
        set.insert_vector_value(
            1,
            5,
            &Value::List(vec![
                Value::Float(f64::NAN),
                Value::Float(0.0),
                Value::Float(0.0),
            ]),
            202,
        ); // NaN element
        set.insert_vector_value(
            1,
            5,
            &Value::List(vec![
                Value::Float(f64::INFINITY),
                Value::Float(0.0),
                Value::Float(0.0),
            ]),
            203,
        ); // +inf element

        // The nearest neighbour of ~origin is node 100.
        let hits = set
            .seek_vector_knn(1, 5, &[0.0, 1.0, 0.0], 3, 64)
            .expect("registered")
            .expect("dim matches");
        assert_eq!(hits[0].0, 100, "node 100 (at origin) is nearest to [0,1,0]");
        // The malformed rows never entered the graph.
        let all: Vec<u64> = set
            .seek_vector_knn(1, 5, &[0.0, 0.0, 0.0], 10, 64)
            .unwrap()
            .unwrap()
            .into_iter()
            .map(|(id, _)| id)
            .collect();
        assert_eq!(all.len(), 3, "only the three valid embeddings are indexed");
        assert!(!all.contains(&200) && !all.contains(&201));
        assert!(
            !all.contains(&202) && !all.contains(&203),
            "NaN / +inf embeddings are rejected, never indexed"
        );

        // Update: 100 moves far away → it is no longer nearest to the origin.
        set.insert_vector_value(1, 5, &emb(100, 100, 100), 100);
        let hits = set
            .seek_vector_knn(1, 5, &[0.0, 0.0, 0.0], 1, 64)
            .unwrap()
            .unwrap();
        assert_ne!(
            hits[0].0, 100,
            "the moved node is no longer nearest the origin"
        );

        // A value that becomes malformed removes the node (a re-check never sees a phantom).
        set.insert_vector_value(1, 5, &Value::Integer(0), 101);
        let ids: Vec<u64> = set
            .seek_vector_knn(1, 5, &[10.0, 0.0, 0.0], 10, 64)
            .unwrap()
            .unwrap()
            .into_iter()
            .map(|(id, _)| id)
            .collect();
        assert!(
            !ids.contains(&101),
            "node 101 was removed when its value went bad"
        );

        // Explicit delete.
        set.remove_vector(1, 5, 102);
        let ids: Vec<u64> = set
            .seek_vector_knn(1, 5, &[0.0, 10.0, 0.0], 10, 64)
            .unwrap()
            .unwrap()
            .into_iter()
            .map(|(id, _)| id)
            .collect();
        assert!(!ids.contains(&102));

        // A query-dimension mismatch is a `Some(Err)`; an unregistered key is `None`.
        assert!(
            set.seek_vector_knn(1, 5, &[1.0, 0.0], 1, 64)
                .unwrap()
                .is_err()
        );
        assert!(set.seek_vector_knn(9, 9, &[0.0, 0.0, 0.0], 1, 64).is_none());
    }

    #[test]
    fn vector_state_gates_planner_exposure_and_clear_preserves_registration() {
        let mut set = IndexSet::new();
        set.register_vector(1, 5, 3, Similarity::Cosine, 16, 200, IndexState::Populating);
        // Maintained while populating…
        set.insert_vector_value(1, 5, &emb(1, 0, 0), 100);
        assert_eq!(
            set.seek_vector_knn(1, 5, &[1.0, 0.0, 0.0], 1, 64)
                .unwrap()
                .unwrap()[0]
                .0,
            100
        );
        // …but not surfaced to the planner until Online.
        assert_eq!(set.registered_vector(), vec![(1, 5)]);
        assert!(set.online_vector().is_empty());
        set.set_vector_state(1, 5, IndexState::Online);
        assert_eq!(set.online_vector(), vec![(1, 5)]);

        // Clear drops the graph entries but keeps the registration + state + parameters (like the other
        // kinds): the graph is empty but the seek still works (returns nothing), and dim is preserved.
        set.clear();
        assert!(set.has_vector(1, 5));
        assert_eq!(set.vector_state(1, 5), Some(IndexState::Online));
        assert_eq!(
            set.seek_vector_knn(1, 5, &[1.0, 0.0, 0.0], 1, 64)
                .unwrap()
                .unwrap(),
            Vec::new()
        );
        // The preserved dimension still rejects a mismatched query.
        assert!(
            set.seek_vector_knn(1, 5, &[1.0, 0.0], 1, 64)
                .unwrap()
                .is_err()
        );

        // Drop removes it entirely.
        set.unregister_vector(1, 5);
        assert!(!set.has_vector(1, 5));
        assert!(set.registered_vector().is_empty());
    }

    #[test]
    fn vector_rel_is_separate_from_node_over_the_same_tokens() {
        // A node vector index and a relationship vector index over the SAME numeric tokens are distinct.
        let mut set = IndexSet::new();
        set.register_vector(1, 5, 2, Similarity::Euclidean, 16, 200, IndexState::Online);
        set.register_vector_rel(1, 5, 2, Similarity::Euclidean, 16, 200, IndexState::Online);
        assert!(set.has_vector(1, 5) && set.has_vector_rel(1, 5));
        assert!(set.has_any_vector_rel());

        set.insert_vector_value(
            1,
            5,
            &Value::List(vec![Value::Float(1.0), Value::Float(0.0)]),
            10,
        );
        set.insert_vector_rel_value(
            1,
            5,
            &Value::List(vec![Value::Float(0.0), Value::Float(1.0)]),
            20,
        );
        // Each side sees only its own element id.
        assert_eq!(
            set.seek_vector_knn(1, 5, &[1.0, 0.0], 5, 64)
                .unwrap()
                .unwrap()[0]
                .0,
            10
        );
        assert_eq!(
            set.seek_vector_rel_knn(1, 5, &[0.0, 1.0], 5, 64)
                .unwrap()
                .unwrap()[0]
                .0,
            20
        );

        // Dropping the node side leaves the relationship side intact.
        set.unregister_vector(1, 5);
        assert!(!set.has_vector(1, 5));
        assert!(set.has_vector_rel(1, 5));
        set.unregister_vector_rel(1, 5);
        assert!(!set.has_any_vector_rel());
    }

    #[test]
    fn spatial_index_candidates_are_a_superset_of_a_full_scan() {
        // The inviolable property: the index candidate set must be a SUPERSET of the brute-force
        // exact answer, so a re-check yields the SAME result as a full scan (`rmp` task #73 AC).
        use graphus_core::value::spatial::{Crs, Point};
        let mut set = IndexSet::new();
        set.register_spatial(1, 5, 3.0, IndexState::Online);
        let mut all: Vec<(u64, f64, f64)> = Vec::new();
        let mut id = 0u64;
        for gx in -8..=8 {
            for gy in -8..=8 {
                let (x, y) = (gx as f64 * 1.3, gy as f64 * 1.1);
                set.insert_spatial_point(1, 5, &pt(x, y), id);
                all.push((id, x, y));
                id += 1;
            }
        }
        for (cx, cy, r) in [(0.0, 0.0, 2.0), (5.0, -3.0, 4.0), (-7.0, 7.0, 1.0)] {
            let candidates: std::collections::BTreeSet<u64> = set
                .seek_spatial_within(1, 5, cx, cy, r)
                .unwrap()
                .into_iter()
                .collect();
            // The exact answer a full scan + `distance(...) <= r` re-check would compute.
            let exact: std::collections::BTreeSet<u64> = all
                .iter()
                .filter(|(_, x, y)| {
                    let p = Point::new_2d(Crs::Cartesian, *x, *y);
                    let c = Point::new_2d(Crs::Cartesian, cx, cy);
                    let dx = p.x() - c.x();
                    let dy = p.y() - c.y();
                    (dx * dx + dy * dy).sqrt() <= r
                })
                .map(|(i, _, _)| *i)
                .collect();
            assert!(
                exact.is_subset(&candidates),
                "index missed a true match: exact={exact:?} candidates={candidates:?}"
            );
            // And re-checking the candidates reproduces the exact answer (index never changes a result).
            let rechecked: std::collections::BTreeSet<u64> = candidates
                .iter()
                .filter(|id| {
                    let (_, x, y) = all[**id as usize];
                    let dx = x - cx;
                    let dy = y - cy;
                    (dx * dx + dy * dy).sqrt() <= r
                })
                .copied()
                .collect();
            assert_eq!(rechecked, exact, "re-checked index == full scan");
        }
    }

    // =============================================================================================
    // `rmp` #756 — the rollback poison must be CONDITIONAL on an actual remove/replace
    // =============================================================================================
    // The in-memory full-text/spatial index is NOT transactional, so a rollback undoes only the durable
    // store, not these structures. The false negative a rolled-back mutator can cause exists ONLY when
    // the txn REMOVED or REPLACED a pre-existing posting (dropping a still-committed node from a posting
    // it should occupy — a false negative the query-time re-check cannot resurrect). A rolled-back pure
    // INSERT leaves only a re-check-filterable false POSITIVE, so poisoning it needlessly forces every
    // reader of that index kind onto the scan path DB-wide until a reopen (the `rmp` #756 regression).
    // These tests pin BOTH directions.

    /// A text index with node 100 committed under "apple" at commit ts 5. After this the marker is the
    /// committed `Timestamp(5)` (no in-flight mutator, not poisoned).
    fn text_set_with_committed_apple() -> IndexSet {
        let mut set = IndexSet::new();
        set.register_text(1, 5, IndexState::Online);
        let t0 = TxnId(1);
        set.insert_text_value(1, 5, &s("apple"), 100); // node 100: a brand-new posting (pure insert).
        assert!(set.note_ft_spatial_mutator(t0));
        set.commit_ft_spatial_marker(t0, Timestamp(5));
        assert_eq!(
            set.effective_ft_spatial_marker(),
            Timestamp(5),
            "baseline must be committed, in-flight-free, and not poisoned"
        );
        set
    }

    /// `rmp` #768: the TEXT capture rides the **trigram/ft-spatial** freshness marker
    /// (`effective_ft_spatial_marker`), NOT the node-property rebuild watermark the range/composite
    /// captures use — the trigram index keeps only the latest state, so a reader older than the last
    /// re-key could be handed a subset. This pins that the capture declines below the marker and serves
    /// at/above it. Using the wrong watermark here would be silent row loss (a stale text reader served a
    /// subset), which is exactly the "no path safe by analogy" trap.
    #[test]
    fn rmp768_text_capture_declines_for_a_reader_older_than_the_trigram_marker() {
        use crate::physical::TextSeekOp;
        // Node 100 = "apple" committed at ts 5, so the effective marker is Timestamp(5).
        let mut set = text_set_with_committed_apple();
        let req = [(1u32, 5u32, TextSeekOp::Contains, "ppl".to_owned())];

        // A reader AT/AFTER the marker is served the trigram candidate ("apple" holds the "ppl" trigram).
        let served = set.capture_node_property_text(Timestamp(5), &req);
        assert_eq!(
            served
                .get_text(1, 5, TextSeekOp::Contains, "ppl")
                .as_deref(),
            Some(&[100u64][..]),
            "a reader at/after the trigram marker must be SERVED the candidate — else the decline below \
             is vacuous"
        );

        // A reader OLDER than the marker must DECLINE (→ exact scan), never be handed a subset.
        let declined = set.capture_node_property_text(Timestamp(4), &req);
        assert!(
            declined
                .get_text(1, 5, TextSeekOp::Contains, "ppl")
                .is_none(),
            "a reader older than the trigram freshness marker MUST decline; serving it would risk a subset"
        );
        assert!(
            declined.is_empty(),
            "the whole text capture must be empty for a pre-marker reader"
        );
    }

    /// `rmp` #769: the RELATIONSHIP-property capture rides the SAME node-property rebuild watermark
    /// (`rebuilt_trees_trustworthy_from`) as the node capture — rel-property trees are the same
    /// append-only, `clear`-and-refill-rebuilt class (`rmp` #765). Exercised here, not presumed from the
    /// node test: a reader older than the last rebuild must have its rel capture DECLINE (→ exact typed
    /// scan), never be served a subset (which on the rel trees would be a `rmp` #683 uniqueness hazard).
    /// The rel-range and rel-composite captures share the identical guard (same first two lines).
    #[test]
    fn rmp769_rel_capture_declines_for_a_reader_older_than_the_rebuild() {
        let mut set = IndexSet::new();
        set.register_rel_property_with_state(1, 5, IndexState::Online);
        set.insert_rel_property(1, 5, &Value::Integer(7), 100);
        // A rebuild wiped + newest-wins-refilled every tree; stamp its high-water at ts 10.
        set.note_trees_rebuilt(Timestamp(10));

        // A reader AT/AFTER the watermark is served the candidate rel id.
        let served = set.capture_rel_property_eq(Timestamp(10), &[(1, 5, Value::Integer(7))]);
        assert_eq!(
            served.get_rel_eq(1, 5, &Value::Integer(7)).as_deref(),
            Some(&[100u64][..]),
            "a reader at/after the rebuild watermark must be SERVED — else the decline below is vacuous"
        );

        // A reader OLDER than the watermark must DECLINE (the stale entries it depends on were annihilated).
        let declined = set.capture_rel_property_eq(Timestamp(9), &[(1, 5, Value::Integer(7))]);
        assert!(
            declined.get_rel_eq(1, 5, &Value::Integer(7)).is_none(),
            "a reader older than the rebuild watermark MUST decline; serving it would risk a subset — and \
             on the rel trees a missing candidate admits a committed duplicate (`rmp` #683)"
        );
        assert!(
            declined.is_empty(),
            "the whole rel capture must be empty for a pre-rebuild reader"
        );
    }

    #[test]
    fn rmp756_rolled_back_pure_insert_to_text_index_does_not_poison() {
        let mut set = text_set_with_committed_apple();
        let t1 = TxnId(2);
        // T1 inserts a BRAND-NEW node 200 (no prior posting) — a pure insert.
        set.insert_text_value(1, 5, &s("banana"), 200);
        assert!(set.note_ft_spatial_mutator(t1), "T1 mutated the index");
        assert!(set.is_ft_spatial_mutator(t1));
        assert_eq!(
            set.effective_ft_spatial_marker(),
            Timestamp(u64::MAX),
            "while T1 is in flight every reader declines (may reflect uncommitted state)"
        );
        set.rollback_ft_spatial_marker(t1);
        assert!(
            !set.is_ft_spatial_mutator(t1),
            "T1 is retired from the in-flight set on rollback"
        );
        assert_eq!(
            set.effective_ft_spatial_marker(),
            Timestamp(5),
            "a rolled-back PURE INSERT must NOT poison — the fast path is preserved (`rmp` #756)"
        );
    }

    #[test]
    fn rmp756_rolled_back_replace_of_text_index_still_fails_closed() {
        let mut set = text_set_with_committed_apple();
        let t1 = TxnId(2);
        // T1 REPLACES node 100's committed "apple" with "banana" — last-wins drops the "apple" posting.
        set.insert_text_value(1, 5, &s("banana"), 100);
        assert!(set.note_ft_spatial_mutator(t1));
        set.rollback_ft_spatial_marker(t1);
        assert!(
            !set.is_ft_spatial_mutator(t1),
            "T1 is retired from the in-flight set (so the pinned MAX below is the POISON, not residual \
             in-flight state)"
        );
        assert_eq!(
            set.effective_ft_spatial_marker(),
            Timestamp(u64::MAX),
            "a rolled-back REPLACE dropped the still-committed 'apple' posting: it MUST poison so no \
             reader can get a false negative (`rmp` #756)"
        );
    }

    #[test]
    fn rmp756_rolled_back_remove_of_text_index_still_fails_closed() {
        let mut set = text_set_with_committed_apple();
        let t1 = TxnId(2);
        // T1 DELETEs node 100 from the index — a real removal of a committed posting.
        set.remove_text(1, 5, 100);
        assert!(set.note_ft_spatial_mutator(t1));
        set.rollback_ft_spatial_marker(t1);
        assert!(!set.is_ft_spatial_mutator(t1));
        assert_eq!(
            set.effective_ft_spatial_marker(),
            Timestamp(u64::MAX),
            "a rolled-back REMOVE of a committed posting MUST poison (`rmp` #756)"
        );
    }

    #[test]
    fn rmp756_rolled_back_noop_remove_does_not_poison() {
        // The per-write wholesale re-index calls `remove_*` UNCONDITIONALLY over nodes no index covers.
        // Such a no-op removal (nothing was present) must not mark the txn a remover — this is exactly
        // the reco CREATE-of-a-new-node case that used to poison the whole database (`rmp` #756).
        let mut set = IndexSet::new();
        set.register_text(1, 5, IndexState::Online);
        let t1 = TxnId(2);
        set.remove_text(1, 5, 999); // node 999 was never indexed — a no-op.
        assert!(
            !set.note_ft_spatial_mutator(t1),
            "a no-op removal changed no posting, so T1 is not even recorded as a mutator"
        );
        assert!(!set.is_ft_spatial_mutator(t1));
        set.rollback_ft_spatial_marker(t1);
        assert_eq!(
            set.effective_ft_spatial_marker(),
            Timestamp(0),
            "a rolled-back no-op removal must NOT poison"
        );
    }

    #[test]
    fn rmp756_committed_replace_does_not_poison_and_clears_removers() {
        let mut set = text_set_with_committed_apple();
        let t1 = TxnId(2);
        set.insert_text_value(1, 5, &s("banana"), 100); // replace: drops the committed "apple" posting.
        assert!(set.note_ft_spatial_mutator(t1));
        // T1 COMMITS at ts 9: the replace is correctly reflected in BOTH the index and the store, so it
        // must advance the marker and must NOT poison.
        set.commit_ft_spatial_marker(t1, Timestamp(9));
        assert!(!set.is_ft_spatial_mutator(t1));
        assert_eq!(
            set.effective_ft_spatial_marker(),
            Timestamp(9),
            "a COMMITTED replace advances the marker and does not poison"
        );
        // And the removers set really was cleared on commit: a LATER unrelated rolled-back txn that only
        // inserts must not resurrect T1's removal and wrongly poison.
        let t2 = TxnId(3);
        set.insert_text_value(1, 5, &s("cherry"), 300); // new node — pure insert.
        assert!(set.note_ft_spatial_mutator(t2));
        set.rollback_ft_spatial_marker(t2);
        assert_eq!(
            set.effective_ft_spatial_marker(),
            Timestamp(9),
            "committing T1 cleared it from the removers set, so T2's pure-insert rollback stays clean"
        );
    }

    #[test]
    fn rmp756_spatial_pure_insert_rollback_no_poison_but_replace_poisons() {
        let mut set = IndexSet::new();
        set.register_spatial(1, 6, 1.0, IndexState::Online);
        let t0 = TxnId(1);
        set.insert_spatial_point(1, 6, &pt(0.5, 0.5), 100); // baseline committed point.
        assert!(set.note_ft_spatial_mutator(t0));
        set.commit_ft_spatial_marker(t0, Timestamp(5));

        // (a) pure insert of a NEW node 200, rolled back -> no poison.
        let t1 = TxnId(2);
        set.insert_spatial_point(1, 6, &pt(9.0, 9.0), 200);
        assert!(set.note_ft_spatial_mutator(t1));
        set.rollback_ft_spatial_marker(t1);
        assert!(!set.is_ft_spatial_mutator(t1));
        assert_eq!(
            set.effective_ft_spatial_marker(),
            Timestamp(5),
            "a rolled-back pure spatial insert must not poison"
        );

        // (b) REPLACE node 100's committed point (last-wins re-buckets it), rolled back -> poison.
        let t2 = TxnId(3);
        set.insert_spatial_point(1, 6, &pt(3.5, 3.5), 100);
        assert!(set.note_ft_spatial_mutator(t2));
        set.rollback_ft_spatial_marker(t2);
        assert!(!set.is_ft_spatial_mutator(t2));
        assert_eq!(
            set.effective_ft_spatial_marker(),
            Timestamp(u64::MAX),
            "a rolled-back spatial replace dropped the committed grid entry: it must poison"
        );
    }

    #[test]
    fn rmp756_vector_pure_insert_rollback_no_poison_but_replace_poisons() {
        let mut set = IndexSet::new();
        set.register_vector(1, 7, 3, Similarity::Cosine, 16, 100, IndexState::Online);
        let t0 = TxnId(1);
        set.insert_vector_value(1, 7, &emb(1, 0, 0), 100); // baseline committed embedding.
        assert!(set.note_ft_spatial_mutator(t0));
        set.commit_ft_spatial_marker(t0, Timestamp(5));

        // (a) pure insert of a NEW node 200, rolled back -> no poison.
        let t1 = TxnId(2);
        set.insert_vector_value(1, 7, &emb(0, 1, 0), 200);
        assert!(set.note_ft_spatial_mutator(t1));
        set.rollback_ft_spatial_marker(t1);
        assert_eq!(
            set.effective_ft_spatial_marker(),
            Timestamp(5),
            "a rolled-back pure vector insert must not poison"
        );

        // (b) REPLACE node 100's committed embedding (last-wins), rolled back -> poison.
        let t2 = TxnId(3);
        set.insert_vector_value(1, 7, &emb(0, 0, 1), 100);
        assert!(set.note_ft_spatial_mutator(t2));
        set.rollback_ft_spatial_marker(t2);
        assert_eq!(
            set.effective_ft_spatial_marker(),
            Timestamp(u64::MAX),
            "a rolled-back vector replace dropped the committed graph entry: it must poison"
        );
    }

    #[test]
    fn rmp756_fulltext_reindex_pure_insert_no_poison_but_replace_and_lost_label_poison() {
        let mut set = IndexSet::new();
        set.register_fulltext(
            "ft",
            vec![1],
            vec![5],
            Analyzer::Standard,
            IndexState::Online,
        );
        let t0 = TxnId(1);
        set.reindex_fulltext_node(100, &[1], &[(5, "cat".to_owned())]); // baseline committed document.
        assert!(set.note_ft_spatial_mutator(t0));
        set.commit_ft_spatial_marker(t0, Timestamp(5));

        // (a) a covered NEW node 200 reindexed -> a pure insert (no prior document) -> rollback: no poison.
        let t1 = TxnId(2);
        set.reindex_fulltext_node(200, &[1], &[(5, "dog".to_owned())]);
        assert!(set.note_ft_spatial_mutator(t1));
        set.rollback_ft_spatial_marker(t1);
        assert_eq!(
            set.effective_ft_spatial_marker(),
            Timestamp(5),
            "a rolled-back full-text pure insert (new document) must not poison"
        );

        // (b) node 100's terms REPLACED cat -> bird (a wholesale term swap) -> rollback: poison.
        let t2 = TxnId(3);
        set.reindex_fulltext_node(100, &[1], &[(5, "bird".to_owned())]);
        assert!(set.note_ft_spatial_mutator(t2));
        set.rollback_ft_spatial_marker(t2);
        assert_eq!(
            set.effective_ft_spatial_marker(),
            Timestamp(u64::MAX),
            "a rolled-back full-text replace dropped the committed 'cat' posting: it must poison"
        );

        // (c) a reindex that DROPS node 100's covered label (now labelled 9, not 1) removes its document
        // from the covering index -> a real removal -> rollback: poison. (Fresh set to isolate.)
        let mut set2 = IndexSet::new();
        set2.register_fulltext(
            "ft",
            vec![1],
            vec![5],
            Analyzer::Standard,
            IndexState::Online,
        );
        let u0 = TxnId(1);
        set2.reindex_fulltext_node(100, &[1], &[(5, "cat".to_owned())]);
        assert!(set2.note_ft_spatial_mutator(u0));
        set2.commit_ft_spatial_marker(u0, Timestamp(5));
        let u1 = TxnId(2);
        set2.reindex_fulltext_node(100, &[9], &[(5, "cat".to_owned())]); // lost the covered label.
        assert!(set2.note_ft_spatial_mutator(u1));
        set2.rollback_ft_spatial_marker(u1);
        assert_eq!(
            set2.effective_ft_spatial_marker(),
            Timestamp(u64::MAX),
            "a rolled-back reindex that dropped a committed posting (lost label) must poison"
        );
    }

    #[test]
    fn rmp756_manual_inflight_seam_is_conservatively_a_remover() {
        // `mark_ft_spatial_mutated_inflight` carries no did-remove information, so it is classified
        // conservatively as a removal: a rollback of a txn that used it fails closed (`rmp` #756).
        // Over-poisoning is safe; under-poisoning could miss a real removal and return a false negative.
        let mut set = IndexSet::new();
        set.register_text(1, 5, IndexState::Online);
        let t1 = TxnId(2);
        set.mark_ft_spatial_mutated_inflight();
        assert!(set.note_ft_spatial_mutator(t1));
        set.rollback_ft_spatial_marker(t1);
        assert_eq!(
            set.effective_ft_spatial_marker(),
            Timestamp(u64::MAX),
            "the conservative manual seam fails closed on rollback"
        );
    }

    #[test]
    fn rmp756_same_txn_create_then_update_conservatively_poisons() {
        // A txn that creates node 300 AND then replaces its indexed value within the SAME txn hits a real
        // (same-txn) posting replace on the second write, so it is recorded as a remover and its rollback
        // poisons. This is a CONSERVATIVE over-approximation: the dropped posting belonged to the same
        // uncommitted txn, so no COMMITTED node is ever lost — both poisoning and not poisoning are safe.
        // We pin the current (safe) behavior; the marker is deliberately coarse (a single DB-wide bit) and
        // does not track per-posting txn provenance. A plain `CREATE` (one wholesale re-index with the
        // full property set) is a single pure insert and does NOT hit this path — see
        // `rmp756_rolled_back_pure_insert_to_text_index_does_not_poison`.
        let mut set = IndexSet::new();
        set.register_text(1, 5, IndexState::Online);
        let t1 = TxnId(2);
        set.insert_text_value(1, 5, &s("apple"), 300); // create: pure insert.
        set.insert_text_value(1, 5, &s("apricot"), 300); // same-txn update: replaces the same-txn posting.
        assert!(set.note_ft_spatial_mutator(t1));
        set.rollback_ft_spatial_marker(t1);
        assert_eq!(
            set.effective_ft_spatial_marker(),
            Timestamp(u64::MAX),
            "conservative but safe: a same-txn replace rollback poisons"
        );
    }
}
