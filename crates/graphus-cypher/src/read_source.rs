//! The shared read **source** seam and the single authoritative read body it backs (`rmp` task #336,
//! Slice 3b-i — the off-thread-read enabler).
//!
//! # The problem this solves
//!
//! [`RecordStoreGraph`](crate::record_graph::RecordStoreGraph) is the live, `!Send`, transaction-scoped
//! [`GraphAccess`](crate::graph_access::GraphAccess) over an `Rc<RefCell<RecordStore>>`. Slice 3 moves
//! OLTP **reads** onto reader threads, where the store cannot be `&`-aliased; Slice 3a gave us the owned,
//! `Send + Sync` [`StoreReadView`] (the decode surface over
//! `(Arc<pool>, MetaSnapshot)`) plus the [`TokenSnapshot`] (the
//! `id ↔ name` resolution surface). What remains is the **visibility heart** — MVCC `is_visible`
//! filtering, id/token mapping, the per-candidate SIREAD markers, the newest-visible-wins property fold,
//! the deterministic key/label sort, the self-delete/tombstone handling. Duplicating that for the reader
//! would risk silent drift from the live path (and so a serializability or visibility bug).
//!
//! # The factoring (Fork 1 of the Slice 3b plan)
//!
//! A grep of every store call on `RecordStoreGraph`'s read path resolves into exactly two categories:
//!
//! 1. the **decode** surface (`node` / `rel` / `scan_node_ids` / `scan_rel_ids` / `node_labels` /
//!    `node_has_label` / `node_properties` / `rel_properties` / `incident_rels` /
//!    `decode_property_value` / `read_prop`), which [`StoreReadView`]
//!    already implements method-for-method; and
//! 2. **token** resolution (`token_id` / `token_name`), which the view lacks (it is satisfied by a
//!    [`TokenSnapshot`]).
//!
//! So the live store and the off-thread view differ on the read path in **exactly one** capability
//! (token name ↔ id). [`StoreReadSource`] captures the union of both categories. The visibility/id/token/
//! marker bodies are then lifted into the free functions below, generic over `S: StoreReadSource` and
//! `K: ReadSink`, parameterised by a [`VisCtx`] (the snapshot + commit registry + txn id that decide
//! visibility) and a `&K` sink (where SIREAD markers and the first captured error go). The sink is a
//! **static** generic (not `&dyn`), so it monomorphises per concrete graph and the hot per-edge
//! `note_read` inlines with no vtable dispatch — keeping the lifted read path at parity with the prior
//! inline `self.note_read(…)`. Two sources implement the
//! [`StoreReadSource`] trait — [`LiveSource`] (a thin wrapper over `&RecordStore`, whose read methods are `&self` since
//! `rmp` #337 Slice 2 → 1-line forwards) and [`ReadViewSource`] (over a [`StoreReadView`] +
//! [`TokenSnapshot`]) — and two sinks consume the markers/errors: `RecordStoreGraph`'s existing
//! [`ReadBufferGuard`](crate::record_graph) path, and
//! [`ReadOnlyGraph`](crate::read_only_graph::ReadOnlyGraph)'s owned buffer.
//!
//! `RecordStoreGraph`'s `GraphAccess` read methods become thin wrappers that call the lifted body with
//! `LiveSource(&*self.store.borrow())` + its own [`VisCtx`] + its own sink, so its observable behaviour
//! stays **byte-identical** (the openCypher TCK and the Slice 3b-i equivalence test are the guards).

use graphus_core::error::GraphusError;
use graphus_core::{TxnId, Value, VersionStamp};
use graphus_io::BlockDevice;
use graphus_storage::record::{NodeRecord, PropRecord, RelRecord};
use graphus_storage::{MvccHeader, Namespace, RecordStore, StoreReadView, TokenSnapshot};
use graphus_txn::{CommitRegistry, PredicateRead, Snapshot, is_visible};
use graphus_wal::LogSink;

use crate::graph_access::{DeletedEntity, ExpandDirection, Incident, NodeId, RelData, RelId};

/// The conflict key for relationship physical id `id` (tagged into the high half of the SSI key
/// space). Mirrors `record_graph::rel_ssi_key` — node ids occupy the low keys, relationship ids the
/// high half, so a node id and a relationship id of the same numeric value map to distinct SSI keys.
const REL_SSI_KEY_TAG: u64 = 1 << 63;

/// The SSI conflict key for node physical id `id`.
#[inline]
fn node_ssi_key(id: u64) -> u64 {
    id
}

/// The SSI conflict key for relationship physical id `id`.
#[inline]
fn rel_ssi_key(id: u64) -> u64 {
    id | REL_SSI_KEY_TAG
}

// =================================================================================================
// StoreReadSource — the shared read surface
// =================================================================================================

/// The store-side read surface the lifted read body
/// ([`scan_nodes`] … [`rel_properties`]) drives (`rmp` task #336, Slice
/// 3b-i). It is exactly the decode surface
/// [`RecordStoreGraph`](crate::record_graph::RecordStoreGraph)'s read path calls on the store, **plus**
/// the one capability the off-thread [`StoreReadView`] lacks — token
/// `id ↔ name` resolution.
///
/// Implemented by [`LiveSource`] (over `&RecordStore`, on the engine thread) and [`ReadViewSource`]
/// (over a [`StoreReadView`] + [`TokenSnapshot`], on a reader thread). Both return identical values for
/// the same store state — that is the Slice-3a decode-equivalence guarantee, extended here to tokens by
/// the append-only `TokenSnapshot` — so the single lifted body runs identically over either.
///
/// Every method is read-only (`&self`): the live read methods are `&self` since `rmp` #337 Slice 2, and
/// the view/snapshot are immutable. The methods return the **raw** decoded records and id lists; MVCC
/// visibility, token name-mapping, the newest-visible-wins fold and the SIREAD markers are applied
/// **above** this surface by the lifted body, exactly as `RecordStoreGraph` applied them above the
/// store.
pub trait StoreReadSource {
    /// Decodes the node record at physical id `id`. (The `RecordStore::node` / `StoreReadView::node`
    /// twin.) An unallocated id is a storage `Err`, which the caller treats as "does not exist".
    fn node(&self, id: u64) -> Result<NodeRecord, GraphusError>;

    /// Decodes the relationship record at physical id `id`.
    fn rel(&self, id: u64) -> Result<RelRecord, GraphusError>;

    /// The slot-occupied node ids in `1..high_water`, ascending.
    fn scan_node_ids(&self) -> Result<Vec<u64>, GraphusError>;

    /// The `Label`-namespace token ids of node `id`'s labels, ascending.
    fn node_labels(&self, id: u64) -> Result<Vec<u32>, GraphusError>;

    /// Whether node `id` carries the label with `label_token_id`.
    fn node_has_label(&self, id: u64, label_token_id: u32) -> Result<bool, GraphusError>;

    /// Every live `(physical_id, record)` in `node_id`'s property chain, head to tail (newest first).
    fn node_properties(&self, node_id: u64) -> Result<Vec<(u64, PropRecord)>, GraphusError>;

    /// Every live `(physical_id, record)` in `rel_id`'s property chain, head to tail (newest first).
    fn rel_properties(&self, rel_id: u64) -> Result<Vec<(u64, PropRecord)>, GraphusError>;

    /// The physical ids of the relationships incident to `node_id` (self-loops deduped, dead-link
    /// corpses threaded through transparently).
    fn incident_rels(&self, node_id: u64) -> Result<Vec<u64>, GraphusError>;

    /// Decodes a property value from its `(type_tag, value_inline)` pair (inline scalar, or an overflow
    /// value reassembled from the strings heap).
    fn decode_property_value(&self, type_tag: u8, value_inline: u64)
    -> Result<Value, GraphusError>;

    /// The id for token `name` in `ns`, if present (without interning — a read must not mint a token).
    fn token_id(&self, ns: Namespace, name: &str) -> Option<u32>;

    /// The name for token `id` in `ns`, if present (returned **owned** so it does not borrow `self`,
    /// matching the off-thread [`TokenSnapshot`] which yields a `&str` into its `Arc`).
    fn token_name(&self, ns: Namespace, id: u32) -> Option<String>;
}

/// [`StoreReadSource`] over the **live** store, on the engine thread (`rmp` task #336, Slice 3b-i).
///
/// A thin borrow wrapper: every method is a 1-line forward to the corresponding `RecordStore` `&self`
/// read method (all `&self` since `rmp` #337 Slice 2). This is what
/// [`RecordStoreGraph`](crate::record_graph::RecordStoreGraph)'s read wrappers pass to the lifted body,
/// so the live path runs the same code as the off-thread path.
pub struct LiveSource<'a, D: BlockDevice, S: LogSink>(pub &'a RecordStore<D, S>);

impl<D: BlockDevice, S: LogSink> StoreReadSource for LiveSource<'_, D, S> {
    fn node(&self, id: u64) -> Result<NodeRecord, GraphusError> {
        self.0.node(id)
    }
    fn rel(&self, id: u64) -> Result<RelRecord, GraphusError> {
        self.0.rel(id)
    }
    fn scan_node_ids(&self) -> Result<Vec<u64>, GraphusError> {
        self.0.scan_node_ids()
    }
    fn node_labels(&self, id: u64) -> Result<Vec<u32>, GraphusError> {
        self.0.node_labels(id)
    }
    fn node_has_label(&self, id: u64, label_token_id: u32) -> Result<bool, GraphusError> {
        self.0.node_has_label(id, label_token_id)
    }
    fn node_properties(&self, node_id: u64) -> Result<Vec<(u64, PropRecord)>, GraphusError> {
        self.0.node_properties(node_id)
    }
    fn rel_properties(&self, rel_id: u64) -> Result<Vec<(u64, PropRecord)>, GraphusError> {
        self.0.rel_properties(rel_id)
    }
    fn incident_rels(&self, node_id: u64) -> Result<Vec<u64>, GraphusError> {
        self.0.incident_rels(node_id)
    }
    fn decode_property_value(
        &self,
        type_tag: u8,
        value_inline: u64,
    ) -> Result<Value, GraphusError> {
        self.0.decode_property_value(type_tag, value_inline)
    }
    fn token_id(&self, ns: Namespace, name: &str) -> Option<u32> {
        self.0.token_id(ns, name)
    }
    fn token_name(&self, ns: Namespace, id: u32) -> Option<String> {
        self.0.token_name(ns, id).map(ToOwned::to_owned)
    }
}

/// [`StoreReadSource`] over an owned, `Send + Sync` [`StoreReadView`] + [`TokenSnapshot`], for a reader
/// thread (`rmp` task #336, Slice 3b-i). The decode methods forward to the view; token resolution
/// forwards to the snapshot. Both were captured on the engine thread under the reader's pinned snapshot.
pub struct ReadViewSource<'a, D: BlockDevice, S: LogSink> {
    /// The owned decode surface (`Arc<pool>` + `MetaSnapshot`).
    pub view: &'a StoreReadView<D, S>,
    /// The owned token dictionary (`id ↔ name`).
    pub tokens: &'a TokenSnapshot,
}

impl<D: BlockDevice, S: LogSink> StoreReadSource for ReadViewSource<'_, D, S> {
    fn node(&self, id: u64) -> Result<NodeRecord, GraphusError> {
        self.view.node(id)
    }
    fn rel(&self, id: u64) -> Result<RelRecord, GraphusError> {
        self.view.rel(id)
    }
    fn scan_node_ids(&self) -> Result<Vec<u64>, GraphusError> {
        self.view.scan_node_ids()
    }
    fn node_labels(&self, id: u64) -> Result<Vec<u32>, GraphusError> {
        self.view.node_labels(id)
    }
    fn node_has_label(&self, id: u64, label_token_id: u32) -> Result<bool, GraphusError> {
        self.view.node_has_label(id, label_token_id)
    }
    fn node_properties(&self, node_id: u64) -> Result<Vec<(u64, PropRecord)>, GraphusError> {
        self.view.node_properties(node_id)
    }
    fn rel_properties(&self, rel_id: u64) -> Result<Vec<(u64, PropRecord)>, GraphusError> {
        self.view.rel_properties(rel_id)
    }
    fn incident_rels(&self, node_id: u64) -> Result<Vec<u64>, GraphusError> {
        self.view.incident_rels(node_id)
    }
    fn decode_property_value(
        &self,
        type_tag: u8,
        value_inline: u64,
    ) -> Result<Value, GraphusError> {
        self.view.decode_property_value(type_tag, value_inline)
    }
    fn token_id(&self, ns: Namespace, name: &str) -> Option<u32> {
        self.tokens.token_id(ns, name)
    }
    fn token_name(&self, ns: Namespace, id: u32) -> Option<String> {
        self.tokens.token_name(ns, id).map(ToOwned::to_owned)
    }
}

// =================================================================================================
// ReadSink — where markers + the first captured error go
// =================================================================================================

/// The side-effect channel of the lifted read body (`rmp` task #336, Slice 3b-i): where a per-record
/// SIREAD marker, a predicate SIREAD marker, and the first storage / deferred-feature error go.
///
/// Both [`RecordStoreGraph`](crate::record_graph::RecordStoreGraph) and
/// [`ReadOnlyGraph`](crate::read_only_graph::ReadOnlyGraph) implement this:
///
/// * `RecordStoreGraph` appends markers to its per-statement
///   [`ReadBufferGuard`](crate::record_graph) (the `rmp` #341 buffer, merged into the shared
///   `SsiTracker` at statement-end) and captures into its `error` cell — i.e. its **existing**
///   behaviour, now reached through this sink.
/// * `ReadOnlyGraph` appends to its own owned [`SsiReadBuffer`](graphus_txn::SsiReadBuffer) (handed
///   back to the coordinator at retirement by Slice 3b-ii) and captures into its own `error` cell.
///
/// Both append-only marker methods are no-ops on the **standalone** (un-coordinated) `RecordStoreGraph`
/// path, exactly as before — there is no tracker to merge into, so a read registers no markers.
pub trait ReadSink {
    /// Records a per-record SIREAD marker for SSI conflict `key` (a node/relationship physical key,
    /// already tagged). A no-op on the standalone path.
    fn note_read(&self, key: u64);

    /// Records a predicate SIREAD marker (`MATCH (n:Label)` / all-nodes / relationship-pattern). A
    /// no-op on the standalone path.
    fn note_predicate_read(&self, predicate: PredicateRead);

    /// Records `err` as the first captured storage / deferred-feature error (a later error never
    /// overwrites the first, which is usually the root cause). While set, the read result is
    /// untrustworthy and the caller must roll back.
    fn capture(&self, err: GraphusError);
}

// =================================================================================================
// VisCtx — the MVCC visibility inputs
// =================================================================================================

/// The visibility inputs the lifted read body filters every record through (`rmp` task #336, Slice
/// 3b-i): this query's read [`Snapshot`], the [`CommitRegistry`] that resolves an in-flight writer to
/// its outcome, and the owning [`TxnId`] (for the same-transaction self-delete discriminator).
///
/// Bundling them lets the lifted functions take one `&VisCtx` instead of three borrows, and keeps the
/// visibility logic ([`visible`](VisCtx::visible) / [`deleted_by_self`](VisCtx::deleted_by_self))
/// identical between the live and off-thread paths — it is the single copy of the visibility heart.
#[derive(Clone, Copy)]
pub struct VisCtx<'a> {
    /// This query's MVCC read snapshot (`04 §5.3`): a version is visible iff its creator committed at
    /// or before `snapshot.ts` (or is this transaction's own write) and its expirer does not hide it.
    pub snapshot: Snapshot,
    /// Resolves a still-in-flight writer's `TxnId` to its commit outcome.
    pub registry: &'a CommitRegistry,
    /// The transaction this query runs in (the self-delete discriminator owner).
    pub txn: TxnId,
}

impl VisCtx<'_> {
    /// Whether the version carrying `mvcc` is visible to this query's snapshot (`04 §5.3`). The one
    /// place the read body consults MVCC.
    #[inline]
    pub fn visible(&self, mvcc: MvccHeader) -> bool {
        is_visible(
            self.snapshot,
            mvcc.created_ts,
            mvcc.expired_ts,
            self.registry,
        )
    }

    /// Whether the version carrying `mvcc` was **deleted by this very transaction** — its creator is
    /// visible (it existed before our `DELETE`) and its expirer is *our own* in-flight stamp
    /// (`04 §5.3`). The discriminator openCypher needs for a same-query `DELETE` (the entity keeps its
    /// identity but a property/label read on it raises `DeletedEntityAccess`).
    ///
    /// Side-effect-free (no SIREAD marker): a transaction inspecting its *own* tombstone has no
    /// rw-dependency to record, so this must not perturb serializability.
    #[inline]
    pub fn deleted_by_self(&self, mvcc: MvccHeader) -> bool {
        let creator_visible = is_visible(self.snapshot, mvcc.created_ts, 0, self.registry);
        creator_visible
            && VersionStamp::from_raw(mvcc.expired_ts) == VersionStamp::InFlight(self.txn)
    }
}

// =================================================================================================
// The single lifted read body — identical for the live store and the off-thread view
// =================================================================================================
//
// Each function reproduces the corresponding `RecordStoreGraph` read method / helper exactly, but over
// `(src: &impl StoreReadSource, ctx: &VisCtx, sink: &K)` instead of `self`. The store
// borrow/decode is `src.*`, visibility is `ctx.visible` / `ctx.deleted_by_self`, the SIREAD markers and
// captured errors go to `sink.*`. `RecordStoreGraph` calls these with `LiveSource`; `ReadOnlyGraph`
// calls them with `ReadViewSource`.

/// The body of `RecordStoreGraph::scan_nodes` (`GraphAccess::scan_nodes`). Registers the `AllNodes`
/// predicate marker, then SIREAD-marks and visibility-filters every slot-occupied node.
pub fn scan_nodes<S: StoreReadSource, K: ReadSink>(src: &S, ctx: &VisCtx, sink: &K) -> Vec<NodeId> {
    // SSI predicate footprint (`rmp` #171): an all-nodes scan depends on *which nodes exist*, so a
    // concurrent insert of ANY node invalidates it. The per-node SIREADs below only cover existing
    // nodes; the `AllNodes` marker covers the not-yet-existing one.
    sink.note_predicate_read(PredicateRead::AllNodes);
    let ids = match src.scan_node_ids() {
        Ok(ids) => ids,
        Err(e) => {
            sink.capture(e);
            return Vec::new();
        }
    };
    let mut out = Vec::new();
    for id in ids {
        match src.node(id) {
            Ok(rec) => {
                // A full scan examines every node, so SIREAD-mark each (`04 §5.4`).
                sink.note_read(node_ssi_key(id));
                if ctx.visible(rec.mvcc) {
                    out.push(NodeId(id));
                }
            }
            Err(e) => {
                sink.capture(e);
                return Vec::new();
            }
        }
    }
    out
}

/// SIREAD-marks **every live node** as this transaction's predicate-read footprint (the body of
/// `RecordStoreGraph::mark_all_live_nodes`), the conservative phantom-safe approximation a
/// label/all-nodes predicate read requires. Read errors are captured exactly as the full scan would.
pub fn mark_all_live_nodes<S: StoreReadSource, K: ReadSink>(src: &S, sink: &K) {
    let ids = match src.scan_node_ids() {
        Ok(ids) => ids,
        Err(e) => {
            sink.capture(e);
            return;
        }
    };
    for id in ids {
        sink.note_read(node_ssi_key(id));
    }
}

/// Filters `ids` (a full-scan id list or an index candidate list) to the nodes that **currently** carry
/// `token_id` and are **visible**, SIREAD-marking each examined id (the body of
/// `RecordStoreGraph::filter_label_candidates`). On a storage fault / overflow-form bitmap the error is
/// captured and an empty result returned — never a wrong (missing/extra) row.
pub fn filter_label_candidates<S: StoreReadSource, K: ReadSink>(
    src: &S,
    ctx: &VisCtx,
    sink: &K,
    token_id: u32,
    ids: Vec<u64>,
) -> Vec<NodeId> {
    let mut out = Vec::new();
    for id in ids {
        // Skip nodes not visible before testing the label, honouring MVCC visibility.
        let visible = match src.node(id) {
            Ok(rec) => ctx.visible(rec.mvcc),
            // A candidate id whose page is unallocated (a stale index entry) is not a live node; the
            // full-scan path never yields such an id, so this only fires for stale candidates and is
            // correctly dropped, not an error.
            Err(_) => continue,
        };
        // SIREAD-mark every examined node, visible or not (the label predicate examined it).
        sink.note_read(node_ssi_key(id));
        if !visible {
            continue;
        }
        match src.node_has_label(id, token_id) {
            Ok(true) => out.push(NodeId(id)),
            Ok(false) => {}
            Err(e) => {
                // An overflow-form bitmap surfaces as a captured error, never a wrong row.
                sink.capture(e);
                return Vec::new();
            }
        }
    }
    out
}

/// The **scan-fallback** body of `RecordStoreGraph::scan_nodes_by_label` (the non-index arm): resolve
/// the label token (no intern), register the `Label`/`AllNodes` predicate marker, then scan every live
/// node and filter by the inline label bitmap. The index-accelerated arm stays in the `RecordStoreGraph`
/// wrapper (it owns the derived `IndexSet`); `ReadOnlyGraph` has no index, so it always takes this path.
pub fn scan_nodes_by_label<S: StoreReadSource, K: ReadSink>(
    src: &S,
    ctx: &VisCtx,
    sink: &K,
    label: &str,
) -> Vec<NodeId> {
    let Some(token_id) = src.token_id(Namespace::Label, label) else {
        // The label was never interned, so no node can carry it *now*. A concurrent writer could
        // `CREATE` the first node of it (a phantom) under a token we cannot know here, so register the
        // conservative `AllNodes` marker rather than interning on a read path.
        sink.note_predicate_read(PredicateRead::AllNodes);
        return Vec::new();
    };
    // `MATCH (n:Label)` is a predicate over which nodes carry the label, so a concurrent insert/relabel
    // is a phantom that must close an rw-edge even when this scan returns nothing.
    sink.note_predicate_read(PredicateRead::Label(token_id));
    // Mark every live node (the conservative phantom footprint the per-node SIREADs cannot supply for a
    // not-yet-existing matching node) — identical to the index arm's `mark_all_live_nodes`.
    mark_all_live_nodes(src, sink);
    let ids = match src.scan_node_ids() {
        Ok(ids) => ids,
        Err(e) => {
            sink.capture(e);
            return Vec::new();
        }
    };
    filter_label_candidates(src, ctx, sink, token_id, ids)
}

/// The body of `RecordStoreGraph::expand` (`GraphAccess::expand`): register the relationship-pattern
/// predicate marker, then walk `node`'s incidence chain, SIREAD-marking and visibility-filtering each
/// edge and reporting the matching side(s) relative to the anchor.
pub fn expand<S: StoreReadSource, K: ReadSink>(
    src: &S,
    ctx: &VisCtx,
    sink: &K,
    node: NodeId,
    direction: ExpandDirection,
    types: &[String],
) -> Vec<Incident> {
    // Relationship-pattern predicate read (`rmp` #171 blocker A1): register the rel-type (or, untyped,
    // `AnyRel`) marker so a concurrent create/delete of a matching type closes an rw-edge — the absent
    // edge the per-rel SIREADs below cannot cover.
    note_rel_predicate_read(src, sink, types);
    let rels = match src.incident_rels(node.0) {
        Ok(rels) => rels,
        Err(e) => {
            sink.capture(e);
            return Vec::new();
        }
    };
    // Resolve the requested rel-type names to interned ids ONCE per expand (`rmp` #319), so the
    // per-edge filter is an integer compare. A requested name with no interned token matches no
    // existing edge (the absent-edge phantom is covered by `note_rel_predicate_read`), so it
    // contributes no id. `None` means "any type".
    let wanted_type_ids: Option<Vec<u32>> = if types.is_empty() {
        None
    } else {
        Some(
            types
                .iter()
                .filter_map(|t| src.token_id(Namespace::RelType, t))
                .collect(),
        )
    };
    let mut out = Vec::new();
    for rid in rels {
        let rec = match src.rel(rid) {
            Ok(rec) => rec,
            Err(e) => {
                sink.capture(e);
                return Vec::new();
            }
        };
        // SIREAD-mark each incident relationship the traversal examined (`04 §5.4`).
        sink.note_read(rel_ssi_key(rid));
        // Skip relationships not visible to this snapshot (a concurrently-deleted tombstone an older
        // reader could still traverse, or a later-committed edge). The incidence chain threads them
        // until GC.
        if !ctx.visible(rec.mvcc) {
            continue;
        }
        if let Some(ref ids) = wanted_type_ids {
            if !ids.contains(&rec.type_id) {
                continue;
            }
        }
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

/// Registers the **relationship-pattern** predicate read footprint for a traversal filtered by `types`
/// (the body of `RecordStoreGraph::note_rel_predicate_read`, `rmp` #171 blocker A1). An empty `types`
/// registers the conservative [`PredicateRead::AnyRel`]; each requested type resolves to its
/// [`Namespace::RelType`] token (a never-interned type falls back to `AnyRel`, since a concurrent writer
/// could create the first edge of it under a token we cannot know).
fn note_rel_predicate_read<S: StoreReadSource, K: ReadSink>(src: &S, sink: &K, types: &[String]) {
    if types.is_empty() {
        sink.note_predicate_read(PredicateRead::AnyRel);
        return;
    }
    for name in types {
        match src.token_id(Namespace::RelType, name) {
            Some(token) => sink.note_predicate_read(PredicateRead::RelType(token)),
            None => sink.note_predicate_read(PredicateRead::AnyRel),
        }
    }
}

/// The body of `RecordStoreGraph::node_exists` (`GraphAccess::node_exists`): "exists" = visible to this
/// query's snapshot. SIREAD-marks the node (it was examined) before returning visibility. An
/// unallocated id is a normal `false`, not a captured fault.
pub fn node_exists<S: StoreReadSource, K: ReadSink>(
    src: &S,
    ctx: &VisCtx,
    sink: &K,
    node: NodeId,
) -> bool {
    let mvcc = match src.node(node.0) {
        Ok(rec) => rec.mvcc,
        Err(_) => return false,
    };
    sink.note_read(node_ssi_key(node.0));
    ctx.visible(mvcc)
}

/// The body of `RecordStoreGraph::rel_exists` (`GraphAccess::rel_exists`).
pub fn rel_exists<S: StoreReadSource, K: ReadSink>(
    src: &S,
    ctx: &VisCtx,
    sink: &K,
    rel: RelId,
) -> bool {
    let mvcc = match src.rel(rel.0) {
        Ok(rec) => rec.mvcc,
        Err(_) => return false,
    };
    sink.note_read(rel_ssi_key(rel.0));
    ctx.visible(mvcc)
}

/// The body of `RecordStoreGraph::node_labels` (`GraphAccess::node_labels`): the node's label names,
/// deterministically sorted, or `None` if the node does not exist. An overflow-form bitmap is captured
/// and reported as `Some(vec![])` (not silently wrong; the caller inspects the captured error).
pub fn node_labels<S: StoreReadSource, K: ReadSink>(
    src: &S,
    ctx: &VisCtx,
    sink: &K,
    node: NodeId,
) -> Option<Vec<String>> {
    if !node_exists(src, ctx, sink, node) {
        return None;
    }
    let ids = match src.node_labels(node.0) {
        Ok(ids) => ids,
        Err(e) => {
            sink.capture(e);
            return Some(Vec::new());
        }
    };
    let mut names: Vec<String> = ids
        .into_iter()
        .filter_map(|id| src.token_name(Namespace::Label, id))
        .collect();
    // Deterministic, name-sorted order (mirrors `MemGraph`, which keeps labels sorted).
    names.sort();
    Some(names)
}

/// The body of `RecordStoreGraph::rel_data` (`GraphAccess::rel_data`): the relationship's structural
/// fields, or `None` for a missing / invisible relationship. SIREAD-marks the examined edge.
pub fn rel_data<S: StoreReadSource, K: ReadSink>(
    src: &S,
    ctx: &VisCtx,
    sink: &K,
    rel: RelId,
) -> Option<RelData> {
    let rec = match src.rel(rel.0) {
        Ok(rec) => rec,
        Err(_) => return None,
    };
    sink.note_read(rel_ssi_key(rel.0));
    if !ctx.visible(rec.mvcc) {
        return None;
    }
    let rel_type = src
        .token_name(Namespace::RelType, rec.type_id)
        .unwrap_or_default();
    Some(RelData {
        rel_type,
        start: NodeId(rec.start_node),
        end: NodeId(rec.end_node),
    })
}

/// The body of `RecordStoreGraph::rel_data_including_deleted` (`GraphAccess::rel_data_including_deleted`):
/// like [`rel_data`] but does **not** apply the expirer-hide, so a relationship this transaction deleted
/// earlier in the same query still yields its type (openCypher keeps `type(r)`/`id(r)` accessible after
/// `DELETE r`). The creator must still be visible. No SIREAD marker (reading our own tombstone has no
/// rw-dependency).
pub fn rel_data_including_deleted<S: StoreReadSource>(
    src: &S,
    ctx: &VisCtx,
    rel: RelId,
) -> Option<RelData> {
    let rec = match src.rel(rel.0) {
        Ok(rec) => rec,
        Err(_) => return None,
    };
    // Visible normally, or a tombstone we wrote ourselves: both keep the type readable.
    if !ctx.visible(rec.mvcc) && !ctx.deleted_by_self(rec.mvcc) {
        return None;
    }
    let rel_type = src
        .token_name(Namespace::RelType, rec.type_id)
        .unwrap_or_default();
    Some(RelData {
        rel_type,
        start: NodeId(rec.start_node),
        end: NodeId(rec.end_node),
    })
}

/// The body of `RecordStoreGraph::entity_deleted_by_txn` (`GraphAccess::entity_deleted_by_txn`):
/// whether `entity` was deleted by *this* transaction (a tombstone we wrote). No SIREAD marker — a
/// self-delete check on our own write records no rw-dependency.
pub fn entity_deleted_by_txn<S: StoreReadSource>(
    src: &S,
    ctx: &VisCtx,
    entity: DeletedEntity,
) -> bool {
    let mvcc = match entity {
        DeletedEntity::Node(id) => match src.node(id.0) {
            Ok(rec) => rec.mvcc,
            Err(_) => return false,
        },
        DeletedEntity::Rel(id) => match src.rel(id.0) {
            Ok(rec) => rec.mvcc,
            Err(_) => return false,
        },
    };
    ctx.deleted_by_self(mvcc)
}

/// The body of `RecordStoreGraph::node_property` (`GraphAccess::node_property`): the single value of
/// `node`'s property `key` (newest-visible-wins), or `None` if the node/property is absent.
pub fn node_property<S: StoreReadSource, K: ReadSink>(
    src: &S,
    ctx: &VisCtx,
    sink: &K,
    node: NodeId,
    key: &str,
) -> Option<Value> {
    if !node_exists(src, ctx, sink, node) {
        return None;
    }
    read_node_prop_one(src, ctx, sink, node, key)
}

/// The body of `RecordStoreGraph::rel_property` (`GraphAccess::rel_property`).
pub fn rel_property<S: StoreReadSource, K: ReadSink>(
    src: &S,
    ctx: &VisCtx,
    sink: &K,
    rel: RelId,
    key: &str,
) -> Option<Value> {
    if !rel_exists(src, ctx, sink, rel) {
        return None;
    }
    read_rel_prop_one(src, ctx, sink, rel, key)
}

/// The body of `RecordStoreGraph::node_properties` (`GraphAccess::node_properties`): all of `node`'s
/// properties as key-sorted newest-visible-wins `(name, value)` pairs, or `None` if absent.
pub fn node_properties<S: StoreReadSource, K: ReadSink>(
    src: &S,
    ctx: &VisCtx,
    sink: &K,
    node: NodeId,
) -> Option<Vec<(String, Value)>> {
    if !node_exists(src, ctx, sink, node) {
        return None;
    }
    Some(read_node_props(src, ctx, sink, node))
}

/// The body of `RecordStoreGraph::rel_properties` (`GraphAccess::rel_properties`).
pub fn rel_properties<S: StoreReadSource, K: ReadSink>(
    src: &S,
    ctx: &VisCtx,
    sink: &K,
    rel: RelId,
) -> Option<Vec<(String, Value)>> {
    if !rel_exists(src, ctx, sink, rel) {
        return None;
    }
    Some(read_rel_props(src, ctx, sink, rel))
}

/// The body of `RecordStoreGraph::incident_rels` (`GraphAccess::incident_rels`): the relationship ids
/// incident to `node`, filtered to those visible to this transaction (a deleted edge is not reported),
/// SIREAD-marking each. Used by `DETACH DELETE` and degree-style reads.
pub fn incident_rels<S: StoreReadSource, K: ReadSink>(
    src: &S,
    ctx: &VisCtx,
    sink: &K,
    node: NodeId,
) -> Vec<RelId> {
    let ids = match src.incident_rels(node.0) {
        Ok(rels) => rels,
        Err(e) => {
            sink.capture(e);
            return Vec::new();
        }
    };
    ids.into_iter()
        .filter(|&rid| {
            let mvcc = match src.rel(rid) {
                Ok(rec) => rec.mvcc,
                Err(e) => {
                    sink.capture(e);
                    return false;
                }
            };
            sink.note_read(rel_ssi_key(rid));
            ctx.visible(mvcc)
        })
        .map(RelId)
        .collect()
}

// --------------------------------- read-only property helpers ---------------------------------

/// The body of `RecordStoreGraph::read_node_prop_one` (`rmp` #326 late materialization): the **first
/// visible** record of `key`'s interned id from the prepend-ordered (newest-first) chain, decoding
/// exactly one value. A never-interned key short-circuits to `None`.
fn read_node_prop_one<S: StoreReadSource, K: ReadSink>(
    src: &S,
    ctx: &VisCtx,
    sink: &K,
    node: NodeId,
    key: &str,
) -> Option<Value> {
    let key_id = src.token_id(Namespace::PropKey, key)?;
    let chain = match src.node_properties(node.0) {
        Ok(chain) => chain,
        Err(e) => {
            sink.capture(e);
            return None;
        }
    };
    for (_pid, prop) in chain {
        if prop.key != key_id || !ctx.visible(prop.mvcc) {
            continue;
        }
        return match src.decode_property_value(prop.type_tag, prop.value_inline) {
            Ok(value) => Some(value),
            Err(e) => {
                sink.capture(e);
                None
            }
        };
    }
    None
}

/// The relationship analogue of [`read_node_prop_one`] (the body of
/// `RecordStoreGraph::read_rel_prop_one`).
fn read_rel_prop_one<S: StoreReadSource, K: ReadSink>(
    src: &S,
    ctx: &VisCtx,
    sink: &K,
    rel: RelId,
    key: &str,
) -> Option<Value> {
    let key_id = src.token_id(Namespace::PropKey, key)?;
    let chain = match src.rel_properties(rel.0) {
        Ok(chain) => chain,
        Err(e) => {
            sink.capture(e);
            return None;
        }
    };
    for (_pid, prop) in chain {
        if prop.key != key_id || !ctx.visible(prop.mvcc) {
            continue;
        }
        return match src.decode_property_value(prop.type_tag, prop.value_inline) {
            Ok(value) => Some(value),
            Err(e) => {
                sink.capture(e);
                None
            }
        };
    }
    None
}

/// The body of `RecordStoreGraph::read_node_props` (`rmp` task #50): `node`'s properties as
/// newest-**visible**-wins `(name, value)` pairs, name-mapped and sorted by name. The chain is
/// prepend-ordered (newest first), so the **first visible** record per key id wins.
fn read_node_props<S: StoreReadSource, K: ReadSink>(
    src: &S,
    ctx: &VisCtx,
    sink: &K,
    node: NodeId,
) -> Vec<(String, Value)> {
    let chain = match src.node_properties(node.0) {
        Ok(chain) => chain,
        Err(e) => {
            sink.capture(e);
            return Vec::new();
        }
    };
    let out = match collect_visible_props(src, ctx, sink, chain) {
        Some(out) => out,
        None => return Vec::new(),
    };
    name_and_sort_props(src, out)
}

/// The relationship analogue of [`read_node_props`] (the body of `RecordStoreGraph::read_rel_props`).
fn read_rel_props<S: StoreReadSource, K: ReadSink>(
    src: &S,
    ctx: &VisCtx,
    sink: &K,
    rel: RelId,
) -> Vec<(String, Value)> {
    let chain = match src.rel_properties(rel.0) {
        Ok(chain) => chain,
        Err(e) => {
            sink.capture(e);
            return Vec::new();
        }
    };
    let out = match collect_visible_props(src, ctx, sink, chain) {
        Some(out) => out,
        None => return Vec::new(),
    };
    name_and_sort_props(src, out)
}

/// The shared newest-visible-wins fold over a property chain (factored out of `read_node_props` /
/// `read_rel_props`, which were byte-identical apart from the chain source): skip versions invisible to
/// this snapshot and a key id already resolved to a newer visible version; decode each kept value.
/// Returns `None` if a decode hit a captured fault (the caller then yields an empty result, exactly as
/// the originals did).
fn collect_visible_props<S: StoreReadSource, K: ReadSink>(
    src: &S,
    ctx: &VisCtx,
    sink: &K,
    chain: Vec<(u64, PropRecord)>,
) -> Option<Vec<(u32, Value)>> {
    let mut out: Vec<(u32, Value)> = Vec::new();
    for (_pid, prop) in chain {
        if !ctx.visible(prop.mvcc) || out.iter().any(|(k, _)| *k == prop.key) {
            continue;
        }
        match src.decode_property_value(prop.type_tag, prop.value_inline) {
            Ok(value) => out.push((prop.key, value)),
            Err(e) => {
                sink.capture(e);
                return None;
            }
        }
    }
    Some(out)
}

/// Maps property key ids back to names and sorts by name for the deterministic order the seam promises
/// (the tail of `read_node_props` / `read_rel_props`).
fn name_and_sort_props<S: StoreReadSource>(
    src: &S,
    out: Vec<(u32, Value)>,
) -> Vec<(String, Value)> {
    let mut named: Vec<(String, Value)> = out
        .into_iter()
        .filter_map(|(kid, v)| {
            src.token_name(Namespace::PropKey, kid)
                .map(|name| (name, v))
        })
        .collect();
    named.sort_by(|a, b| a.0.cmp(&b.0));
    named
}
