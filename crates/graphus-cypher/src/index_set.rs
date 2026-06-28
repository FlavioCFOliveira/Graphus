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

use std::collections::{BTreeSet, HashMap};

use graphus_bufpool::BufferPool;
use graphus_core::{Timestamp, TxnId, Value};
use graphus_index::bitmap::{self, BitmapIndex};
use graphus_index::fulltext::{Analyzer, InvertedIndex, MatchSemantics};
use graphus_index::recovery::SharedWal;
use graphus_index::spatial::SpatialIndex;
use graphus_index::{BTree, CompositeIndex, PropertyIndex, TokenIndex};
use graphus_io::MemBlockDevice;
use graphus_storage::{ConstraintKind, ConstraintTypeDescriptor, IndexState};
use graphus_wal::{DiscardingLogSink, WalManager};

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
    /// Declared **full-text** indexes (`rmp` task #72), keyed by their server-unique **name**. Each
    /// value carries the covered label, the covered property keys, the analyzer, the build state and
    /// the in-memory [`InvertedIndex`]. Like the property indexes the inverted index is **ephemeral**
    /// (rebuilt from the store on open); only the *registration* is durable (the storage catalog).
    fulltext: HashMap<String, FulltextEntry>,
    /// Declared **spatial** indexes (`rmp` task #73), keyed by `(label_token, prop_key)`. Each value
    /// carries the build state and the in-memory [`SpatialIndex`] grid over the covered point
    /// property. Ephemeral and rebuilt on open, exactly like the property and full-text indexes.
    spatial: HashMap<(u32, u32), SpatialEntry>,
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
    /// Declared **low-cardinality Roaring-bitmap** indexes (`rmp` task #328), keyed by `(label_token,
    /// prop_key)`. Each value is an in-memory [`BitmapIndex`] (value → compressed node-id bitmap) over
    /// the covered low-cardinality column. Like every other backing structure it is **ephemeral**
    /// (rebuilt from the store on open); unlike the catalog-backed kinds it uses the **opt-in** model
    /// (declared in-session, no durable catalog entry), exactly like the columnar value cache — so a
    /// re-opened coordinator re-declares the columns it wants bitmap-accelerated. Because it is a
    /// **candidate source** (not a read-only accelerator), it is kept membership-exact under writes by
    /// the wholesale per-node re-index in [`RecordStoreGraph::reindex_node`](crate::record_graph).
    bitmap: HashMap<(u32, u32), BitmapIndex>,
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
    /// Whether a full-text/spatial mutator **rolled back**, possibly leaving the in-memory index with
    /// stale postings the query-time re-check cannot repair (`rmp` task #467). A rolled-back *replace*
    /// or *delete* can drop a still-committed node from a posting it should occupy (a false negative
    /// the re-check cannot resurrect — unlike a rolled-back *insert*, which leaves only a re-check-
    /// filterable false positive). Because the in-memory index is **not** transactional (an abort
    /// rolls back only the durable store, not these structures — see the `rmp` #410 note on
    /// [`seek_bitmap_eq`](Self::seek_bitmap_eq)), the only provably-correct response is to force every
    /// reader onto the always-correct scan path until the index is rebuilt to committed state. So this
    /// pins [`effective_ft_spatial_marker`](Self::effective_ft_spatial_marker) at `u64::MAX` until a
    /// full [`reset_ft_spatial_marker`](Self::reset_ft_spatial_marker) (driven by the coordinator's
    /// store-consistent rebuild) clears it. Conservative (it disables the fast path after a full-text/
    /// spatial-mutating rollback) but never returns a wrong answer.
    ft_spatial_poisoned: bool,
    /// Transient "a registered full-text/spatial posting changed during the current statement" flag,
    /// set by the structural mutation methods and consumed by
    /// [`note_ft_spatial_mutator`](Self::note_ft_spatial_mutator) (the statement seam, which knows the
    /// [`TxnId`]) / cleared by [`clear_ft_spatial_dirty`](Self::clear_ft_spatial_dirty) (the rebuild /
    /// online-build path, whose insertions reflect *committed* state and must not be attributed to any
    /// open transaction) (`rmp` task #467). It exists because the mutation methods' signatures carry no
    /// `TxnId`, so they cannot record set membership themselves; they flag dirtiness here and the seam
    /// converts it to a [`ft_spatial_inflight`](Self#structfield.ft_spatial_inflight) entry.
    ft_spatial_dirty: bool,
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

/// A declared full-text index plus its build [`IndexState`] and the in-memory inverted index
/// (`rmp` task #72). The `label_token` + `prop_keys` + `analyzer` mirror the durable catalog entry;
/// the `index` is ephemeral (rebuilt from the store on open).
struct FulltextEntry {
    /// The label-namespace token the index covers.
    label_token: u32,
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

impl IndexSet {
    /// An empty index set: a single label [`TokenIndex`] (always present, auto-maintained) and no
    /// property indexes yet.
    #[must_use]
    pub fn new() -> Self {
        Self {
            labels: TokenIndex::new(fresh_tree()),
            node_props: HashMap::new(),
            fulltext: HashMap::new(),
            spatial: HashMap::new(),
            constraints: HashMap::new(),
            composite: HashMap::new(),
            bitmap: HashMap::new(),
            dirty_bitmap_nodes: HashMap::new(),
            // A fresh, empty index reflects committed state at the genesis timestamp: there is nothing
            // indexed and no mutator in flight, so every reader may trust it (`ts >= 0` always holds).
            ft_spatial_trustworthy_from: Timestamp(0),
            ft_spatial_inflight: BTreeSet::new(),
            ft_spatial_poisoned: false,
            ft_spatial_dirty: false,
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
        Some(idx.seek_eq(label_token, values).unwrap_or_default())
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

    /// The constraint rules that apply to `label_token` (`rmp` task #99): every registered constraint
    /// whose covered label is `label_token`. Used by the write path to enforce only the relevant rules
    /// for a node carrying that label. Returned by value (cloned) so the caller does not hold the
    /// `IndexSet` borrow across the per-rule store re-checks.
    #[must_use]
    pub fn constraints_for_label(&self, label_token: u32) -> Vec<ConstraintRule> {
        self.constraints
            .values()
            .filter(|rule| rule.label_token == label_token)
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
    pub fn clear(&mut self) {
        self.labels = TokenIndex::new(fresh_tree());
        for np in self.node_props.values_mut() {
            np.index = PropertyIndex::new(fresh_tree());
        }
        // Full-text indexes: drop the inverted-index entries but keep the registration + state
        // (`rmp` task #72), mirroring the node-property handling.
        for ft in self.fulltext.values_mut() {
            ft.index.clear();
        }
        // Spatial indexes: clear the grid entries, keep the registration + state (`rmp` task #73).
        for sp in self.spatial.values_mut() {
            sp.index.clear();
        }
        // Composite indexes (`rmp` task #100): recreate each backing tree to drop its entries while
        // keeping the registered `(label_token, property_tokens)` set, exactly like the property indexes.
        for (key, idx) in &mut self.composite {
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

    /// Records that node `node_id` carries label `label_token` (a candidate for label scans).
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
            None => Self::all_candidates(&mut np.index, prop_key),
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
        label_token: u32,
        prop_keys: Vec<u32>,
        analyzer: Analyzer,
        state: IndexState,
    ) {
        assert!(
            !prop_keys.is_empty(),
            "full-text index needs at least one property"
        );
        self.fulltext.insert(
            name.to_owned(),
            FulltextEntry {
                label_token,
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

    /// The covered `(label_token, prop_keys, analyzer)` of the full-text index named `name`, or
    /// [`None`] if unregistered. The coordinator's rebuild/maintenance uses this to know which
    /// property values to analyze for a node.
    #[must_use]
    pub fn fulltext_target(&self, name: &str) -> Option<(u32, Vec<u32>, Analyzer)> {
        self.fulltext
            .get(name)
            .map(|ft| (ft.label_token, ft.prop_keys.clone(), ft.analyzer))
    }

    /// The registered full-text index names (in any state), ascending. Used by the coordinator's
    /// rebuild to know which indexes to repopulate and by `SHOW FULLTEXT INDEXES`.
    #[must_use]
    pub fn registered_fulltext(&self) -> Vec<String> {
        let mut names: Vec<String> = self.fulltext.keys().cloned().collect();
        names.sort_unstable();
        names
    }

    /// All full-text indexes that cover `label_token`, as `(name, prop_keys, analyzer)`, ascending by
    /// name (`rmp` task #72). The coordinator's per-write maintenance uses this: for each index a
    /// written node's label matches, it re-analyzes the node's covered property values.
    #[must_use]
    pub fn fulltext_indexes_for_label(
        &self,
        label_token: u32,
    ) -> Vec<(String, Vec<u32>, Analyzer)> {
        let mut out: Vec<(String, Vec<u32>, Analyzer)> = self
            .fulltext
            .iter()
            .filter(|(_, ft)| ft.label_token == label_token)
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
            ft.index.index_document(node_id, terms);
            // A registered posting changed: flag the cross-snapshot freshness marker dirty so the
            // statement seam records this writer as a full-text/spatial mutator (`rmp` task #467).
            self.ft_spatial_dirty = true;
        }
    }

    /// Removes `node_id` from the full-text index named `name` (a delete, or a node that lost the
    /// covered label). A no-op if no such index is registered.
    pub fn remove_fulltext_document(&mut self, name: &str, node_id: u64) {
        if let Some(ft) = self.fulltext.get_mut(name) {
            // Flag the freshness marker dirty only when a posting actually changed (`remove_document`
            // returns whether the node was present), so a no-op removal does not needlessly force
            // concurrent readers off the fast path (`rmp` task #467).
            if ft.index.remove_document(node_id) {
                self.ft_spatial_dirty = true;
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
        for name in names {
            let Some(ft) = self.fulltext.get(&name) else {
                continue;
            };
            if !label_tokens.contains(&ft.label_token) {
                // The node does not (or no longer) carries the covered label: drop it from this index.
                // `remove_document` reports whether it was present (a real posting change).
                if self
                    .fulltext
                    .get_mut(&name)
                    .expect("index present")
                    .index
                    .remove_document(node_id)
                {
                    changed = true;
                }
                continue;
            }
            // Gather the covered text in the index's declared property order, then analyze it.
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
            // this marker guards). Treat any covered re-index as a posting change. This is the simplest
            // sound rule (the over-mark — identical terms re-indexed — only makes concurrent readers
            // conservatively decline; it never returns a wrong answer) and needs no `graphus-index`
            // presence-probe API.
            changed = true;
            self.fulltext
                .get_mut(&name)
                .expect("index present")
                .index
                .index_document(node_id, &terms);
        }
        if changed {
            self.ft_spatial_dirty = true;
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
                sp.index.index_point(node_id, *p);
                // A point was (re)inserted: a real grid change. Flag the freshness marker dirty so the
                // statement seam records this writer as a full-text/spatial mutator (`rmp` task #467).
                self.ft_spatial_dirty = true;
            } else {
                // The property is no longer a point (e.g. an update changed its type) — drop the
                // stale grid entry so a re-check never sees a phantom. Only a real removal flags dirty.
                if sp.index.remove(node_id) {
                    self.ft_spatial_dirty = true;
                }
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
            // concurrent readers off the fast path (`rmp` task #467).
            if sp.index.remove(node_id) {
                self.ft_spatial_dirty = true;
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
    pub fn mark_ft_spatial_mutated_inflight(&mut self) {
        self.ft_spatial_dirty = true;
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
        if self.ft_spatial_dirty {
            self.ft_spatial_inflight.insert(txn);
            self.ft_spatial_dirty = false;
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
    pub fn clear_ft_spatial_dirty(&mut self) {
        self.ft_spatial_dirty = false;
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
        if self.ft_spatial_inflight.remove(&txn) && commit_ts.0 > self.ft_spatial_trustworthy_from.0
        {
            self.ft_spatial_trustworthy_from = commit_ts;
        }
    }

    /// Retires `txn` as a **rolled-back** full-text/spatial mutator (`rmp` task #467). A no-op if
    /// `txn` was not a mutator.
    ///
    /// A rollback undoes the durable store but **not** the in-memory index (it is not transactional —
    /// see the `rmp` #410 note on [`seek_bitmap_eq`](Self::seek_bitmap_eq)). A rolled-back *replace*
    /// or *delete* can leave a still-committed node dropped from a posting it should occupy — a false
    /// negative the query-time re-check cannot resurrect. So this **poisons** the marker
    /// ([`effective_ft_spatial_marker`](Self::effective_ft_spatial_marker) pinned at `u64::MAX`),
    /// forcing every reader onto the always-correct scan path until a full
    /// [`reset_ft_spatial_marker`](Self::reset_ft_spatial_marker) rebuilds the index to committed
    /// state. Conservative — it disables the fast path after a full-text/spatial-mutating rollback —
    /// but never returns a wrong answer.
    pub fn rollback_ft_spatial_marker(&mut self, txn: TxnId) {
        if self.ft_spatial_inflight.remove(&txn) {
            self.ft_spatial_poisoned = true;
        }
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
    }

    /// Resets the full-text/spatial freshness marker to `ts` and clears the poison / dirty flags
    /// (`rmp` task #467), called by the coordinator after a full store-consistent index rebuild.
    ///
    /// The rebuilt index reflects exactly the committed state at the store's current high-water `ts`,
    /// so a reader at `ts` or later may trust it (correct — index == committed state at `ts`) and an
    /// older reader declines (conservative, correct). The in-flight set is **not** touched: a rebuild
    /// runs between commands with no open transaction, so it is empty; clearing it would be wrong if a
    /// mutator were somehow open.
    pub fn reset_ft_spatial_marker(&mut self, ts: Timestamp) {
        self.ft_spatial_trustworthy_from = ts;
        self.ft_spatial_poisoned = false;
        self.ft_spatial_dirty = false;
    }

    // ============================================================================================
    // Bitmap indexes (`rmp` task #328) — low-cardinality columns, opt-in / derived
    // ============================================================================================

    /// Declares a low-cardinality bitmap index on `(label_token, prop_key)` (`rmp` task #328).
    /// Idempotent: re-declaring keeps the existing bitmap. The column is then captured by the
    /// coordinator rebuild and kept membership-exact by the per-write re-index.
    pub fn register_bitmap(&mut self, label_token: u32, prop_key: u32) {
        self.bitmap.entry((label_token, prop_key)).or_default();
    }

    /// Unregisters the bitmap index on `(label_token, prop_key)`, dropping its bitmaps. A no-op if
    /// none is registered.
    pub fn unregister_bitmap(&mut self, label_token: u32, prop_key: u32) {
        self.bitmap.remove(&(label_token, prop_key));
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

    /// All candidate ids for `token` in `idx`, regardless of value. Used as the correct
    /// unbounded-below superset (see [`Self::seek_node_property_range`]). Implemented by scanning the
    /// whole keyspace and keeping the entries whose key carries this token in its leading `u32`.
    fn all_candidates(
        idx: &mut PropertyIndex<Dev, Sink>,
        token: u32,
    ) -> graphus_core::error::Result<Vec<u64>> {
        let prefix = token.to_be_bytes();
        // Stream the whole keyspace, decoding the rid out of each matching value slice — no owned
        // `(key, value)` pair per row. The unbounded-below superset semantics are unchanged.
        let mut out: Vec<u64> = Vec::new();
        idx.tree_mut().scan_all_for_each(|k, v| {
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
        assert_eq!(
            set.seek_node_property_eq(1, 2, &Value::Null),
            Some(Vec::<u64>::new())
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
    fn clear_empties_then_reinsert_works() {
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
        // Entries gone, but the registered set is preserved.
        assert_eq!(set.seek_label(7), Vec::<u64>::new());
        assert_eq!(
            set.seek_node_property_eq(1, 2, &Value::Integer(10)),
            Some(Vec::<u64>::new())
        );
        assert!(set.has_node_property(1, 2));

        // Re-insert after clear works.
        set.insert_label(7, 200);
        set.insert_node_property(1, 2, &Value::Integer(10), 99);
        assert_eq!(set.seek_label(7), vec![200]);
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
        set.register_fulltext("ft", 1, vec![5, 6], Analyzer::Standard, IndexState::Online);
        assert!(set.has_fulltext("ft"));
        assert_eq!(set.fulltext_state("ft"), Some(IndexState::Online));
        assert_eq!(
            set.fulltext_target("ft"),
            Some((1, vec![5, 6], Analyzer::Standard))
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
        set.register_fulltext("ft", 1, vec![5], Analyzer::Standard, IndexState::Populating);
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
        set.register_fulltext("a", 1, vec![5], Analyzer::Standard, IndexState::Online);
        set.register_fulltext("b", 1, vec![6], Analyzer::Keyword, IndexState::Online);
        set.register_fulltext("c", 2, vec![7], Analyzer::Standard, IndexState::Online);
        let for_1 = set.fulltext_indexes_for_label(1);
        assert_eq!(for_1.len(), 2);
        assert_eq!(for_1[0].0, "a");
        assert_eq!(for_1[1].0, "b");
        assert_eq!(set.fulltext_indexes_for_label(2).len(), 1);
        assert_eq!(set.fulltext_indexes_for_label(9).len(), 0);
    }

    #[test]
    fn fulltext_clear_preserves_registration_drops_entries() {
        let mut set = IndexSet::new();
        set.register_fulltext("ft", 1, vec![5], Analyzer::Standard, IndexState::Online);
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
        set.register_fulltext("ft", 1, vec![5], Analyzer::Standard, IndexState::Online);
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
}
