//! The shared read **source** seam and the single authoritative read body it backs (`rmp` task #336,
//! Slice 3b-i — the off-thread-read enabler).
//!
//! # The problem this solves
//!
//! [`RecordStoreGraph`](crate::record_graph::RecordStoreGraph) is the live, `!Sync`, transaction-scoped
//! [`GraphAccess`](crate::graph_access::GraphAccess) over a shared, mutex-guarded `RecordStore`. Slice 3 moves
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
//!    `node_has_label` / `superset_scan_node_properties` / `superset_scan_rel_properties` /
//!    `incident_rels` / `decode_property_value` / `read_prop`), which [`StoreReadView`] already
//!    implements method-for-method; and
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

use std::cell::Cell;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use std::collections::{BTreeSet, HashMap};

use graphus_core::error::GraphusError;
use graphus_core::{TxnId, Value, VersionStamp};
use graphus_index::fulltext::Analyzer;
use graphus_index::keycodec::{encode_equality_canonical, encode_single};
use graphus_io::BlockDevice;
use graphus_storage::record::{NodeRecord, RelRecord};
use graphus_storage::{
    DecidedProperties, MvccHeader, Namespace, RecordStore, StoreKind, StoreReadView,
    SupersetProperties, TokenSnapshot, labels,
};
use graphus_txn::{CommitRegistry, PredicateRead, Snapshot, is_visible};
use graphus_wal::LogSink;

use crate::graph_access::{
    CompositeSeekHits, DeletedEntity, ExpandDirection, Incident, IndexSeekHits, KeyValues, NodeId,
    RelData, RelId, ScanFilter,
};

/// The conflict key for relationship physical id `id` (tagged into the high half of the SSI key
/// space). Mirrors `record_graph::rel_ssi_key` — node ids occupy the low keys, relationship ids the
/// high half, so a node id and a relationship id of the same numeric value map to distinct SSI keys.
const REL_SSI_KEY_TAG: u64 = 1 << 63;

/// The SSI conflict key for node physical id `id`.
#[inline]
#[must_use]
pub fn node_ssi_key(id: u64) -> u64 {
    id
}

/// The SSI conflict key for relationship physical id `id`.
///
/// Public so a test comparing two access paths' SIREAD buffers can name the key of a specific
/// relationship without re-deriving the tag encoding (`rmp` task #867 — the relationship-scan footprint
/// containment guard). One definition, no copy to drift.
#[inline]
#[must_use]
pub fn rel_ssi_key(id: u64) -> u64 {
    id | REL_SSI_KEY_TAG
}

// =================================================================================================
// The opt-in CSR-adjacency knob (`rmp` task #324, "Win 2")
// =================================================================================================

/// The process-global "build + consult the type-bucketed CSR adjacency" knob (`rmp` task #324,
/// Win 2). Default **off**: when off, the coordinator builds **no**
/// [`CsrAdjacency`](crate::csr_adjacency::CsrAdjacency) (zero extra RAM) and a typed `expand` walks the
/// incidence chain exactly as Win-1-only does. The server sets it from
/// [`AdmissionConfig::csr_adjacency`](../../graphus_server/struct.AdmissionConfig.html) at startup
/// (default `false`), mirroring the `set_morsel_threads` global-static plumbing the morsel tier
/// (`rmp` #339) uses — a runtime knob that reaches the Cypher read path without threading a parameter
/// through every seam constructor.
///
/// A process-global is sound here because, like the morsel knob, it is read once at coordinator
/// construction (to decide whether to *build* the CSR) and is otherwise consulted only on the
/// already-built structure. The DST simulator drives `LocalEngine`/`MemGraph` inline and never sets
/// this, so determinism is unaffected (the knob stays off ⇒ no CSR).
static CSR_ADJACENCY_ENABLED: AtomicBool = AtomicBool::new(false);

/// Enables or disables the opt-in CSR-adjacency accelerator process-wide (`rmp` task #324, Win 2).
/// Called once on engine startup with `AdmissionConfig::csr_adjacency` (and by tests/benches that opt
/// in). Off by default.
pub fn set_csr_adjacency(enabled: bool) {
    CSR_ADJACENCY_ENABLED.store(enabled, Ordering::Relaxed);
}

/// Whether the opt-in CSR-adjacency accelerator is enabled (`rmp` task #324, Win 2). Read by the
/// coordinator to decide whether to build/maintain a CSR. Default `false`.
#[must_use]
pub fn csr_adjacency_enabled() -> bool {
    CSR_ADJACENCY_ENABLED.load(Ordering::Relaxed)
}

// =================================================================================================
// StoreReadSource — the shared read surface
// =================================================================================================

/// The store-side read surface the lifted read body ([`scan_nodes`] …
/// [`StoreReadSource::superset_scan_rel_properties`]) drives (`rmp` task #336, Slice 3b-i). It is
/// exactly the decode surface [`RecordStoreGraph`](crate::record_graph::RecordStoreGraph)'s read
/// path calls on the store, **plus** the one capability the off-thread [`StoreReadView`] lacks —
/// token `id ↔ name` resolution.
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

    /// The slot-occupied relationship ids in `1..high_water`, ascending (`rmp` task #663) — the rel
    /// analogue of [`scan_node_ids`](Self::scan_node_ids), used by the off-thread relationship full-text
    /// scan fallback.
    fn scan_rel_ids(&self) -> Result<Vec<u64>, GraphusError>;

    /// The `Label`-namespace token ids of node `id`'s labels, ascending.
    fn node_labels(&self, id: u64) -> Result<Vec<u32>, GraphusError>;

    /// Whether node `id` carries the label with `label_token_id`.
    ///
    /// **Reads the CURRENT word.** For a visibility-correct membership test use
    /// [`label_bitmap_at`](Self::label_bitmap_at) (`rmp` #767).
    fn node_has_label(&self, id: u64, label_token_id: u32) -> Result<bool, GraphusError>;

    /// The label bitmap node `id` presents to `snapshot`, given the `live` word already decoded from
    /// its record (`rmp` task #767).
    ///
    /// The label word is mutated IN PLACE, so reading it directly returns whatever it holds at that
    /// instant — including an uncommitted writer's change (a dirty read) or one committed after the
    /// reader's snapshot began (a non-repeatable read). This resolves it through the node's own undo
    /// chain (`rmp` #968), the same early-stopping walk the property chain already gets, rather than
    /// through the in-process history `rmp` #767 used.
    ///
    /// Takes `live` and the record's `undo_ptr` as `head` rather than re-reading the record: every
    /// hot-path caller has just decoded both for the MVCC visibility check one line earlier, and a
    /// node no open transaction has relabelled (`head == 0`) is answered with no read at all.
    ///
    /// # Errors
    /// Returns a storage error if the chain cannot be walked. It is never answered with `live`, which
    /// would turn a read fault into a silent dirty read.
    fn label_bitmap_at(
        &self,
        id: u64,
        live: u64,
        head: u64,
        snapshot: Snapshot,
    ) -> Result<u64, GraphusError>;

    /// Whether the node / relationship `(kind, id)` carrying `mvcc` **exists** as of `snapshot`, at
    /// statement granularity (`04 §5.1.4`, `rmp` #972).
    ///
    /// `graphus_txn::is_visible` answers the same question across *transactions*, from the two header
    /// words alone. It cannot answer it **within** one transaction: the header records which
    /// transaction created or expired the entity and never which statement of it, so a row the current
    /// statement is creating is indistinguishable from one an earlier statement created. That
    /// distinction lives on the undo chain, which this walks — and only when it can matter, so a read
    /// under [`View::New`](graphus_txn::View::New) pays one comparison and no I/O.
    ///
    /// It is on the seam, rather than folded per implementation, for exactly the reason
    /// [`decision_scan_node_properties`](Self::decision_scan_node_properties) is: the off-thread reader
    /// pool and the inline path must resolve existence through the **same** mechanism. A reader pool
    /// that answers from a different mechanism than the inline path is the `rmp` #755/#768/#769/#770
    /// defect family.
    ///
    /// # Errors
    /// Returns a storage error if the entity's undo chain cannot be walked. It is never answered with
    /// the header's own verdict, which is the answer the chain was consulted to correct.
    fn entity_visible_at(
        &self,
        kind: StoreKind,
        id: u64,
        mvcc: MvccHeader,
        snapshot: Snapshot,
        registry: &CommitRegistry,
    ) -> Result<bool, GraphusError>;

    /// The **superset**-polarity read of `node_id`'s property chain, head to tail (newest first).
    ///
    /// This doc used to promise every *live* record. It does not: it returns every
    /// **slot-occupied** record, MVCC tombstones and uncommitted versions included, which is the
    /// same false claim `rmp` task #902 had to correct on
    /// `RecordStore::superset_scan_node_properties` itself. The visibility fold is applied ABOVE
    /// this surface — see [`graphus_storage::scan_polarity`] for which reads owe which answer.
    fn superset_scan_node_properties(
        &self,
        node_id: u64,
    ) -> Result<SupersetProperties, GraphusError>;

    /// The **superset**-polarity read of `rel_id`'s property chain, head to tail (newest first) —
    /// the relationship twin of
    /// [`superset_scan_node_properties`](Self::superset_scan_node_properties), with the same
    /// polarity.
    fn superset_scan_rel_properties(&self, rel_id: u64)
    -> Result<SupersetProperties, GraphusError>;

    /// The **decision**-polarity read of `node_id`'s properties: the value of each key exactly as
    /// `snapshot` sees it, reconstructed by the early-stopping undo-chain walk (`rmp` #967,
    /// `04 §5.6`).
    ///
    /// This is the read every query property materialisation owes. After `rmp` #967 an overwrite is
    /// written **in place** and the old value descends onto the entity's undo chain, so a version can
    /// no longer be selected by folding the chain against each cell's own MVCC stamp — the cell's
    /// `created_ts` is informative and the chain is the sole visibility oracle
    /// (`D-property-visibility`).
    ///
    /// It is on the seam, rather than folded per implementation, so the **off-thread reader pool and
    /// the inline path resolve visibility through the same mechanism**: both implementations forward
    /// to the one body in [`graphus_storage::read_view`], and a reader pool that answers from a
    /// different mechanism than the inline path is the `rmp` #755/#768/#769/#770 defect family.
    fn decision_scan_node_properties(
        &self,
        node_id: u64,
        snapshot: Snapshot,
    ) -> Result<DecidedProperties, GraphusError>;

    /// The **decision**-polarity read of `rel_id`'s properties — the relationship twin of
    /// [`decision_scan_node_properties`](Self::decision_scan_node_properties), with the same
    /// obligation and the same shared body.
    fn decision_scan_rel_properties(
        &self,
        rel_id: u64,
        snapshot: Snapshot,
    ) -> Result<DecidedProperties, GraphusError>;

    /// The physical ids of the relationships incident to `node_id` (self-loops deduped, dead-link
    /// corpses threaded through transparently).
    fn incident_rels(&self, node_id: u64) -> Result<Vec<u64>, GraphusError>;

    /// The `(physical_id, record)` of the relationships incident to `node_id`, read once each and
    /// filtered to `wanted_types` (empty = all), self-loops deduped, corpses threaded through (`rmp`
    /// #324). The single-pass twin of `incident_rels` + per-id `rel()`: returning the decoded record
    /// lets the typed-expand body skip the second read and the SSI mark of non-matching edges.
    fn incident_rels_typed(
        &self,
        node_id: u64,
        wanted_types: &[u32],
    ) -> Result<Vec<(u64, RelRecord)>, GraphusError>;

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
    fn scan_rel_ids(&self) -> Result<Vec<u64>, GraphusError> {
        self.0.scan_rel_ids()
    }
    fn node_labels(&self, id: u64) -> Result<Vec<u32>, GraphusError> {
        self.0.node_labels(id)
    }
    fn node_has_label(&self, id: u64, label_token_id: u32) -> Result<bool, GraphusError> {
        self.0.node_has_label(id, label_token_id)
    }
    fn label_bitmap_at(
        &self,
        id: u64,
        live: u64,
        head: u64,
        snapshot: Snapshot,
    ) -> Result<u64, GraphusError> {
        self.0.label_bitmap_at(id, live, head, snapshot)
    }
    fn entity_visible_at(
        &self,
        kind: StoreKind,
        id: u64,
        mvcc: MvccHeader,
        snapshot: Snapshot,
        registry: &CommitRegistry,
    ) -> Result<bool, GraphusError> {
        self.0.entity_visible_at(kind, id, mvcc, snapshot, registry)
    }
    fn superset_scan_node_properties(
        &self,
        node_id: u64,
    ) -> Result<SupersetProperties, GraphusError> {
        self.0.superset_scan_node_properties(node_id)
    }
    fn superset_scan_rel_properties(
        &self,
        rel_id: u64,
    ) -> Result<SupersetProperties, GraphusError> {
        self.0.superset_scan_rel_properties(rel_id)
    }
    fn decision_scan_node_properties(
        &self,
        node_id: u64,
        snapshot: Snapshot,
    ) -> Result<DecidedProperties, GraphusError> {
        self.0.decision_scan_node_properties(node_id, snapshot)
    }
    fn decision_scan_rel_properties(
        &self,
        rel_id: u64,
        snapshot: Snapshot,
    ) -> Result<DecidedProperties, GraphusError> {
        self.0.decision_scan_rel_properties(rel_id, snapshot)
    }
    fn incident_rels(&self, node_id: u64) -> Result<Vec<u64>, GraphusError> {
        self.0.incident_rels(node_id)
    }
    fn incident_rels_typed(
        &self,
        node_id: u64,
        wanted_types: &[u32],
    ) -> Result<Vec<(u64, RelRecord)>, GraphusError> {
        self.0.incident_rels_typed(node_id, wanted_types)
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
        self.0.token_name(ns, id).map(|n| n.to_string())
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
    fn scan_rel_ids(&self) -> Result<Vec<u64>, GraphusError> {
        self.view.scan_rel_ids()
    }
    fn node_labels(&self, id: u64) -> Result<Vec<u32>, GraphusError> {
        self.view.node_labels(id)
    }
    fn node_has_label(&self, id: u64, label_token_id: u32) -> Result<bool, GraphusError> {
        self.view.node_has_label(id, label_token_id)
    }
    fn label_bitmap_at(
        &self,
        id: u64,
        live: u64,
        head: u64,
        snapshot: Snapshot,
    ) -> Result<u64, GraphusError> {
        self.view.label_bitmap_at(id, live, head, snapshot)
    }
    fn entity_visible_at(
        &self,
        kind: StoreKind,
        id: u64,
        mvcc: MvccHeader,
        snapshot: Snapshot,
        registry: &CommitRegistry,
    ) -> Result<bool, GraphusError> {
        self.view
            .entity_visible_at(kind, id, mvcc, snapshot, registry)
    }
    fn superset_scan_node_properties(
        &self,
        node_id: u64,
    ) -> Result<SupersetProperties, GraphusError> {
        self.view.superset_scan_node_properties(node_id)
    }
    fn superset_scan_rel_properties(
        &self,
        rel_id: u64,
    ) -> Result<SupersetProperties, GraphusError> {
        self.view.superset_scan_rel_properties(rel_id)
    }
    fn decision_scan_node_properties(
        &self,
        node_id: u64,
        snapshot: Snapshot,
    ) -> Result<DecidedProperties, GraphusError> {
        self.view.decision_scan_node_properties(node_id, snapshot)
    }
    fn decision_scan_rel_properties(
        &self,
        rel_id: u64,
        snapshot: Snapshot,
    ) -> Result<DecidedProperties, GraphusError> {
        self.view.decision_scan_rel_properties(rel_id, snapshot)
    }
    fn incident_rels(&self, node_id: u64) -> Result<Vec<u64>, GraphusError> {
        self.view.incident_rels(node_id)
    }
    fn incident_rels_typed(
        &self,
        node_id: u64,
        wanted_types: &[u32],
    ) -> Result<Vec<(u64, RelRecord)>, GraphusError> {
        self.view.incident_rels_typed(node_id, wanted_types)
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
// IndexCandidateCapture — the engine thread's index seek RESULTS, moved to a reader
// =================================================================================================

/// An owned, `Send + Sync` memo of node-property **equality seek results**, computed on the engine
/// thread at read dispatch so an off-thread reader can serve `index_seek_eq` without touching the live
/// index (`rmp` task #755, Slice S2).
///
/// # Why a memo of results and not a snapshot of the index
///
/// The obvious move — share the [`IndexSet`](crate::index_set::IndexSet) with the reader — does not
/// work, and not because of the shared-cell wrapper: **every read method of the backing `BTree` takes
/// `&mut self`** (`lookup`, `range`, `scan_all`, and hence `PropertyIndex::seek_eq`), because the
/// single-threaded `BufferPool` mutates frames and pin counts on fetch. A `Send + Sync` index shared
/// behind `&self` would therefore still be unusable, and making the pool concurrent is the `rmp` #721
/// hazard class. So instead of moving the *index*, we move the *answers*: the engine thread runs the
/// seeks it can prove the reader will ask for and hands over the resulting id lists. The engine
/// contributes only raw candidate ids — a pure accelerator with **zero semantics**; the reader still
/// does all of it (visibility, label re-check, value residual, SIREAD markers) through the one lifted
/// [`index_seek_eq_recheck`] body that the live path uses.
///
/// # Why the memo is a superset (the MVCC soundness argument)
///
/// The reader's snapshot `T` is taken at `begin`, which precedes the capture instant `W`. Let node `n`
/// be visible at `T` with value `v`. Its writer `A` has `commit_ts(A) <= T <= W`, and `reindex_node`
/// inserts `(v, n)` **during** `A`'s statement — before `A` commits, hence before `W`. So `(v, n)` is
/// present at `W`: the capture cannot miss a row the reader must return. Entries from uncommitted
/// transactions are merely *extra*, and the per-candidate re-check can only ever REMOVE.
///
/// **The index is no longer append-only per entry, and this argument was re-derived under that**
/// (`rmp` #992). It used to say the node-property index has no per-entry removal at all; two now
/// exist — a rolled-back transaction removes the entries it *created* (`IndexSet::undo_entries`) and
/// the version GC removes the entries dead versions leave behind (`IndexSet::collect_dead_keys`).
/// Neither can take `(v, n)` away from the reader above:
///
/// * the rollback removes only keys the aborting transaction created, i.e. keys absent before it ran,
///   so no key a committed `A` warrants is in its log;
/// * the collection removes a key only when a superset-polarity read of `n` — its live cells plus
///   everything its undo chain can still reconstruct — shows nothing occupying that key. `v` is
///   visible at `T`, so it is either the value in place or behind a delta committed after `T`; and
///   `T >= watermark` for as long as this reader is open, so the GC cannot have freed that delta.
///   Either way `v` is in the witness and the entry is retained.
///
/// So the property the argument actually needs is not "append-only" but **"nothing removes an entry a
/// live snapshot warrants"**, which is what both removal paths are built to guarantee.
///
/// The capture is also **atomic** with respect to index mutation: it and every index write run on the
/// same serial engine thread, so it can never observe a half-applied `reindex_node`.
///
/// # What must NEVER be captured (each is silent row loss)
///
/// * a **non-`Online`** index — `Populating` is a genuine SUBSET of the truth (`rmp` #733);
/// * a **degraded / fail-closed** index — its trees have been wiped, so it is a subset (`rmp` #733);
/// * the **destructive** index classes (full-text / spatial / text / vector / bitmap) — they
///   re-index wholesale via `remove_*` + re-insert, so a reader whose snapshot predates the rewrite
///   sees a subset (`rmp` #467). Only the node-property class is captured here; its two removal paths
///   (`rmp` #992) are snapshot-safe, as the argument above derives, which is what keeps it on this
///   side of the line while the wholesale kinds stay off it.
///
/// [`Self::get`] returning `None` means "not captured" and MUST be treated by the caller as
/// **decline → exact scan fallback**, never as "no rows" (`rmp` #680/#738).
///
/// # Beyond equality (`rmp` task #768)
///
/// `rmp` #755 captured only node-property **equality** seeks; every other node-property seek — RANGE,
/// COMPOSITE, TEXT — fell to the reader's `GraphAccess` default (`None`) and full-scanned the label
/// while the plan still named the index. This memo now carries all three, each keyed by the exact
/// `GraphAccess` call the reader makes so the reader looks it up by the same arguments the capture
/// resolved. The MVCC-superset argument and the "miss ⇒ decline, never `Some(empty)`" contract are
/// unchanged and apply per kind; the per-kind capture gates (which rebuild watermark, which index
/// state) live in [`IndexSet`](crate::index_set::IndexSet) — RANGE/COMPOSITE ride the node-property
/// `rebuilt_trees_trustworthy_from` watermark (`rmp` #765), TEXT rides the trigram index's
/// `effective_ft_spatial_marker` (`rmp` #467), exactly as their inline seeks do.
/// The memo key for a captured COMPOSITE seek (`rmp` #768): `(label_token, property_tokens,
/// encode_values(values))`. Factored to a named type so the map declaration stays legible.
type CompositeCaptureKey = (u32, Vec<u32>, Vec<u8>);
/// The memo key for a captured SPATIAL (point) seek (`rmp` #770): `(token, prop_key, cx_bits, cy_bits,
/// r_bits)`, where the three coordinates are `f64::to_bits()` of the plan-time-folded centre/radius.
/// Bit-exact keying is correct here — the reader forms the identical `f64` constants from the same
/// [`SpatialIndexSeek`](crate::physical::PhysicalOp::SpatialIndexSeek) operator the capture read, so the
/// bits always agree; a key that failed to agree would simply miss and decline to the exact scan.
type SpatialCaptureKey = (u32, u32, u64, u64, u64);

#[derive(Debug, Clone, Default)]
pub struct IndexCandidateCapture {
    /// `(label_token, prop_key, encode_single(seek))` → the candidate ids that seek returned.
    ///
    /// The key uses [`encode_single`] — the **index lookup** encoding, i.e. the identity of the value
    /// that was sought — deliberately NOT `encode_equality_canonical` (which is the SSI *marker*
    /// encoding, and which merges Cypher-equal `1`/`1.0`). They are different jobs: a lookup that
    /// merged `1` with `1.0` would hand back the wrong memo. Because the reader re-evaluates the very
    /// same literal/parameter the capture used, the two encodings always agree; and a key that does not
    /// agree simply misses, which degrades to the exact scan.
    entries: HashMap<(u32, u32, Vec<u8>), Arc<[u64]>>,
    /// `(label_token, prop_key, encode_range_bounds(lower, upper))` → the range candidate ids
    /// (`rmp` #768). The bound encoding is byte-canonical and unambiguous (a tag byte per side, and a
    /// length-prefixed [`encode_single`] of each present bound value), so the reader — which forms the
    /// same `(lower, upper)` from the same literal/parameter the capture used — keys identically.
    range: HashMap<(u32, u32, Vec<u8>), Arc<[u64]>>,
    /// `(label_token, property_tokens, encode_values(values))` → the composite candidate ids
    /// (`rmp` #768). The property tokens are the composite index's full ordered key; the value encoding
    /// is a length-prefixed [`encode_single`] of each element, matching the reader's own resolution.
    composite: HashMap<CompositeCaptureKey, Arc<[u64]>>,
    /// `(label_token, prop_key, op, needle)` → the trigram text candidate ids (`rmp` #768). The needle
    /// is the raw string (the trigram index keys on characters, not the order-preserving codec), so it
    /// is stored verbatim; the reader looks it up with the same `(op, needle)` it evaluated.
    text: HashMap<(u32, u32, crate::physical::TextSeekOp, String), Arc<[u64]>>,
    /// `(type_token, prop_key, encode_single(seek))` → the RELATIONSHIP equality candidate ids
    /// (`rmp` #769). The relationship twin of [`entries`](Self#structfield.entries), keyed on the rel-type
    /// token. Values are rel ids.
    rel_eq: HashMap<(u32, u32, Vec<u8>), Arc<[u64]>>,
    /// `(type_token, prop_key, encode_range_bounds(lower, upper))` → the RELATIONSHIP range candidate ids
    /// (`rmp` #769) — the twin of [`range`](Self#structfield.range) over the #680 `RelIndexRangeSeek`.
    rel_range: HashMap<(u32, u32, Vec<u8>), Arc<[u64]>>,
    /// `(type_token, property_tokens, encode_values(values))` → the RELATIONSHIP composite candidate ids
    /// (`rmp` #769) — the twin of [`composite`](Self#structfield.composite).
    rel_composite: HashMap<CompositeCaptureKey, Arc<[u64]>>,
    /// `(label_token, prop_key, cx_bits, cy_bits, r_bits)` → the SPATIAL (point) candidate node ids
    /// (`rmp` #770). The grid seek is a geometric superset; the reader narrows it to visible + currently
    /// labelled nodes and the executor's residual `distance(...) <op> r` filter restores exactness.
    spatial: HashMap<SpatialCaptureKey, Arc<[u64]>>,
    /// `(type_token, prop_key, cx_bits, cy_bits, r_bits)` → the SPATIAL (point) candidate rel ids
    /// (`rmp` #770/#664) — the relationship twin of [`spatial`](Self#structfield.spatial). Values are rel ids.
    rel_spatial: HashMap<SpatialCaptureKey, Arc<[u64]>>,
}

// `rmp` #755/#768, Slice S2: the capture rides a `ReadTask` to a reader thread, so it must be
// `Send + Sync`. A compile-time assertion (no runtime body), mirroring `TokenSnapshot`'s — it fails to
// build the instant a non-`Sync` field is introduced. Every field is a `HashMap` of `Send + Sync`
// keys/values (`TextSeekOp` is a plain `Copy` enum), so this holds by auto-derivation, no `unsafe impl`.
const _: () = {
    fn assert_send_sync<T: Send + Sync>() {}
    fn assert_index_candidate_capture() {
        assert_send_sync::<IndexCandidateCapture>();
    }
    let _ = assert_index_candidate_capture;
};

/// A `Send + Sync` memo of the **count-store answers** an off-thread reader's plan will ask for
/// (`rmp` task #866), captured on the engine thread at dispatch by
/// [`TxnCoordinator::count_store_for`](crate::coordinator::TxnCoordinator::count_store_for).
///
/// # Why a memo and not a live read
///
/// The reader thread holds no live store — only an owned [`StoreReadView`] and a snapshot — so it
/// cannot read the durable counters at all, and it could not evaluate their equivalence predicate
/// even if it could: "no transaction holds a pending count delta" and "nothing has committed since
/// this snapshot" are facts about the engine thread's *current* state, and by the time a reader ran
/// them the engine would already have moved on. Capturing the verdict **and** the value together, on
/// the engine thread, in the same borrow that takes the snapshot, is what makes the answer race-free:
/// the pair is frozen at an instant at which the predicate provably held.
///
/// # Contract
///
/// A **miss declines** — the reader falls back to the `Aggregation`-over-scan subtree, which is the
/// reference path. So an empty capture (the default) is always safe, and the capture is deliberately
/// left empty whenever the predicate fails, when the plan needs no count, or when a token is unknown.
/// There is no "captured but wrong" state to guard against: the only way a value enters is with the
/// predicate already proven.
#[derive(Debug, Default, Clone)]
pub struct CountStoreCapture {
    /// `Some(label)` → nodes carrying it; `None` → the grand total (a bare `MATCH (n)`).
    nodes: HashMap<Option<String>, u64>,
    /// The **deduplicated** relationship-type list the operator asked for (empty = any type) → the
    /// count. Keyed by the list itself, in the operator's own order, because that is what the reader
    /// re-presents verbatim; a differently-ordered spelling simply misses and declines.
    rels: HashMap<Vec<String>, u64>,
}

// `rmp` #866: the capture rides a `ReadTask` to a reader thread, so it must be `Send + Sync` — the same
// compile-time assertion `IndexCandidateCapture` carries, for the same reason.
const _: () = {
    fn assert_send_sync<T: Send + Sync>() {}
    fn assert_count_store_capture() {
        assert_send_sync::<CountStoreCapture>();
    }
    let _ = assert_count_store_capture;
};

impl CountStoreCapture {
    /// Memoises `count` as the answer for a node count over `label` (`None` = every node).
    pub fn insert_nodes(&mut self, label: Option<String>, count: u64) {
        self.nodes.insert(label, count);
    }

    /// Memoises `count` as the answer for a relationship count over `types` (empty = any type).
    pub fn insert_rels(&mut self, types: Vec<String>, count: u64) {
        self.rels.insert(types, count);
    }

    /// The memoised node count, or [`None`] if it was not captured — which the caller MUST turn into a
    /// declined seam (the scan fallback), never a zero. A `Some(0)` here is a real, captured "no such
    /// node"; the `None` is "no answer", and conflating them would report an empty graph.
    #[must_use]
    pub fn nodes(&self, label: Option<&str>) -> Option<u64> {
        // `HashMap<Option<String>, _>` cannot be probed with `Option<&str>` through `Borrow`, so the key
        // is materialised. It happens once per statement, not once per row.
        self.nodes.get(&label.map(ToOwned::to_owned)).copied()
    }

    /// The memoised relationship count, or [`None`] if it was not captured — see
    /// [`nodes`](Self::nodes) for why that is not a zero.
    #[must_use]
    pub fn rels(&self, types: &[String]) -> Option<u64> {
        self.rels.get(types).copied()
    }
}

/// The canonical, unambiguous byte key for a `(lower, upper)` range request (`rmp` #768). Each side is
/// a tag byte — `0` = open, `1` = inclusive, `2` = exclusive — followed, when present, by the
/// length-prefixed [`encode_single`] of the bound value. Returns `None` when a present bound value is
/// not index-encodable (a `List`): the capture then does not key it and the reader misses → declines to
/// the exact scan, exactly as the inline seek declines a `List` bound (`rmp` #680).
fn encode_range_bounds_key(
    lower: Option<(&Value, bool)>,
    upper: Option<(&Value, bool)>,
) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    for side in [lower, upper] {
        match side {
            None => out.push(0u8),
            Some((v, inclusive)) => {
                let enc = encode_single(v).ok()?;
                out.push(if inclusive { 1u8 } else { 2u8 });
                out.extend_from_slice(&(enc.len() as u32).to_le_bytes());
                out.extend_from_slice(&enc);
            }
        }
    }
    Some(out)
}

/// The canonical, unambiguous byte key for a composite tuple's `values` (`rmp` #768): the
/// length-prefixed [`encode_single`] of each element, concatenated in key order. Returns `None` when
/// **any** element is not index-encodable (a `List`), matching the inline composite seek's whole-tuple
/// decline (`rmp` #680).
fn encode_values_key(values: &[Value]) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    for v in values {
        let enc = encode_single(v).ok()?;
        out.extend_from_slice(&(enc.len() as u32).to_le_bytes());
        out.extend_from_slice(&enc);
    }
    Some(out)
}

impl IndexCandidateCapture {
    /// Memoises `ids` as the candidate list for `(label_token, prop_key) == seek`.
    ///
    /// The caller is responsible for the gates above: only an `Online`, non-degraded, append-only
    /// node-property index may be captured, and `ids` must be the seek's own (superset) output. A
    /// non-index-encodable `seek` (`Null`/`List`/`Map`) cannot be keyed and is silently not captured —
    /// the reader then misses and takes the exact scan, exactly as the live path declines it.
    pub fn insert(&mut self, label_token: u32, prop_key: u32, seek: &Value, ids: Vec<u64>) {
        if let Ok(key) = encode_single(seek) {
            self.entries
                .insert((label_token, prop_key, key), ids.into());
        }
    }

    /// The memoised candidate ids for `(label_token, prop_key) == seek`, or `None` if this seek was not
    /// captured — which the caller MUST turn into a declined seek (exact scan fallback), never an empty
    /// result. Cheap: one hash lookup + one `Arc` refcount bump.
    #[must_use]
    pub fn get(&self, label_token: u32, prop_key: u32, seek: &Value) -> Option<Arc<[u64]>> {
        let key = encode_single(seek).ok()?;
        self.entries.get(&(label_token, prop_key, key)).cloned()
    }

    /// Memoises `ids` as the RANGE candidate list for `(label_token, prop_key)` under `(lower, upper)`
    /// (`rmp` #768). A `List` bound value cannot be keyed and is silently not captured — the reader then
    /// misses and takes the exact scan, exactly as the inline seek declines it (`rmp` #680).
    pub fn insert_range(
        &mut self,
        label_token: u32,
        prop_key: u32,
        lower: Option<(&Value, bool)>,
        upper: Option<(&Value, bool)>,
        ids: Vec<u64>,
    ) {
        if let Some(key) = encode_range_bounds_key(lower, upper) {
            self.range.insert((label_token, prop_key, key), ids.into());
        }
    }

    /// The memoised RANGE candidate ids for `(label_token, prop_key)` under `(lower, upper)`, or `None`
    /// if this range was not captured — which the caller MUST turn into a declined seek (exact scan
    /// fallback), never an empty result (`rmp` #680/#738).
    #[must_use]
    pub fn get_range(
        &self,
        label_token: u32,
        prop_key: u32,
        lower: Option<(&Value, bool)>,
        upper: Option<(&Value, bool)>,
    ) -> Option<Arc<[u64]>> {
        let key = encode_range_bounds_key(lower, upper)?;
        self.range.get(&(label_token, prop_key, key)).cloned()
    }

    /// Memoises `ids` as the COMPOSITE candidate list for `(label_token, property_tokens)` under
    /// `values` (`rmp` #768). A `List` element cannot be keyed and is silently not captured.
    pub fn insert_composite(
        &mut self,
        label_token: u32,
        property_tokens: &[u32],
        values: &[Value],
        ids: Vec<u64>,
    ) {
        if let Some(key) = encode_values_key(values) {
            self.composite
                .insert((label_token, property_tokens.to_vec(), key), ids.into());
        }
    }

    /// The memoised COMPOSITE candidate ids for `(label_token, property_tokens)` under `values`, or
    /// `None` if this tuple was not captured — the caller MUST decline (exact scan fallback), never an
    /// empty result (`rmp` #680/#738).
    #[must_use]
    pub fn get_composite(
        &self,
        label_token: u32,
        property_tokens: &[u32],
        values: &[Value],
    ) -> Option<Arc<[u64]>> {
        let key = encode_values_key(values)?;
        self.composite
            .get(&(label_token, property_tokens.to_vec(), key))
            .cloned()
    }

    /// Memoises `ids` as the TEXT candidate list for `(label_token, prop_key)` under `(op, needle)`
    /// (`rmp` #768).
    pub fn insert_text(
        &mut self,
        label_token: u32,
        prop_key: u32,
        op: crate::physical::TextSeekOp,
        needle: &str,
        ids: Vec<u64>,
    ) {
        self.text
            .insert((label_token, prop_key, op, needle.to_owned()), ids.into());
    }

    /// The memoised TEXT candidate ids for `(label_token, prop_key)` under `(op, needle)`, or `None` if
    /// not captured — the caller MUST decline (exact scan fallback), never an empty result
    /// (`rmp` #680/#738).
    #[must_use]
    pub fn get_text(
        &self,
        label_token: u32,
        prop_key: u32,
        op: crate::physical::TextSeekOp,
        needle: &str,
    ) -> Option<Arc<[u64]>> {
        self.text
            .get(&(label_token, prop_key, op, needle.to_owned()))
            .cloned()
    }

    /// Memoises `ids` as the RELATIONSHIP equality candidate list for `(type_token, prop_key) == seek`
    /// (`rmp` #769). A `List` value cannot be keyed and is silently not captured (the reader then misses
    /// and takes the exact typed-scan fallback, `rmp` #680).
    pub fn insert_rel_eq(&mut self, type_token: u32, prop_key: u32, seek: &Value, ids: Vec<u64>) {
        if let Ok(key) = encode_single(seek) {
            self.rel_eq.insert((type_token, prop_key, key), ids.into());
        }
    }

    /// The memoised RELATIONSHIP equality candidate ids, or `None` if not captured — the caller MUST
    /// decline (exact typed scan), never an empty result (`rmp` #680/#738).
    #[must_use]
    pub fn get_rel_eq(&self, type_token: u32, prop_key: u32, seek: &Value) -> Option<Arc<[u64]>> {
        let key = encode_single(seek).ok()?;
        self.rel_eq.get(&(type_token, prop_key, key)).cloned()
    }

    /// Memoises `ids` as the RELATIONSHIP range candidate list for `(type_token, prop_key)` under
    /// `(lower, upper)` (`rmp` #769). A `List` bound is silently not captured.
    pub fn insert_rel_range(
        &mut self,
        type_token: u32,
        prop_key: u32,
        lower: Option<(&Value, bool)>,
        upper: Option<(&Value, bool)>,
        ids: Vec<u64>,
    ) {
        if let Some(key) = encode_range_bounds_key(lower, upper) {
            self.rel_range
                .insert((type_token, prop_key, key), ids.into());
        }
    }

    /// The memoised RELATIONSHIP range candidate ids, or `None` if not captured — the caller MUST decline
    /// (exact typed scan), never an empty result (`rmp` #680/#738).
    #[must_use]
    pub fn get_rel_range(
        &self,
        type_token: u32,
        prop_key: u32,
        lower: Option<(&Value, bool)>,
        upper: Option<(&Value, bool)>,
    ) -> Option<Arc<[u64]>> {
        let key = encode_range_bounds_key(lower, upper)?;
        self.rel_range.get(&(type_token, prop_key, key)).cloned()
    }

    /// Memoises `ids` as the RELATIONSHIP composite candidate list for `(type_token, property_tokens)`
    /// under `values` (`rmp` #769). A `List` element is silently not captured.
    pub fn insert_rel_composite(
        &mut self,
        type_token: u32,
        property_tokens: &[u32],
        values: &[Value],
        ids: Vec<u64>,
    ) {
        if let Some(key) = encode_values_key(values) {
            self.rel_composite
                .insert((type_token, property_tokens.to_vec(), key), ids.into());
        }
    }

    /// The memoised RELATIONSHIP composite candidate ids, or `None` if not captured — the caller MUST
    /// decline (exact typed scan), never an empty result (`rmp` #680/#738).
    #[must_use]
    pub fn get_rel_composite(
        &self,
        type_token: u32,
        property_tokens: &[u32],
        values: &[Value],
    ) -> Option<Arc<[u64]>> {
        let key = encode_values_key(values)?;
        self.rel_composite
            .get(&(type_token, property_tokens.to_vec(), key))
            .cloned()
    }

    /// Memoises `ids` as the SPATIAL (point) candidate node list for `(label_token, prop_key)` under the
    /// centre `(center_x, center_y)` + `radius` (`rmp` #770). The centre/radius are keyed bit-exactly via
    /// [`f64::to_bits`] — the reader forms the identical constants from the same operator, so they agree.
    pub fn insert_spatial(
        &mut self,
        label_token: u32,
        prop_key: u32,
        center_x: f64,
        center_y: f64,
        radius: f64,
        ids: Vec<u64>,
    ) {
        self.spatial.insert(
            (
                label_token,
                prop_key,
                center_x.to_bits(),
                center_y.to_bits(),
                radius.to_bits(),
            ),
            ids.into(),
        );
    }

    /// The memoised SPATIAL candidate node ids for `(label_token, prop_key)` + `(center_x, center_y,
    /// radius)`, or `None` if not captured — the caller MUST decline (exact label scan + residual
    /// `distance` filter), never an empty result (`rmp` #680/#738).
    #[must_use]
    pub fn get_spatial(
        &self,
        label_token: u32,
        prop_key: u32,
        center_x: f64,
        center_y: f64,
        radius: f64,
    ) -> Option<Arc<[u64]>> {
        self.spatial
            .get(&(
                label_token,
                prop_key,
                center_x.to_bits(),
                center_y.to_bits(),
                radius.to_bits(),
            ))
            .cloned()
    }

    /// Memoises `ids` as the SPATIAL (point) candidate RELATIONSHIP list for `(type_token, prop_key)`
    /// under the centre + radius (`rmp` #770/#664) — the relationship twin of [`insert_spatial`](Self::insert_spatial).
    pub fn insert_rel_spatial(
        &mut self,
        type_token: u32,
        prop_key: u32,
        center_x: f64,
        center_y: f64,
        radius: f64,
        ids: Vec<u64>,
    ) {
        self.rel_spatial.insert(
            (
                type_token,
                prop_key,
                center_x.to_bits(),
                center_y.to_bits(),
                radius.to_bits(),
            ),
            ids.into(),
        );
    }

    /// The memoised SPATIAL candidate RELATIONSHIP ids, or `None` if not captured — the caller MUST
    /// decline (exact typed scan + residual `distance` filter), never an empty result (`rmp` #680/#738).
    #[must_use]
    pub fn get_rel_spatial(
        &self,
        type_token: u32,
        prop_key: u32,
        center_x: f64,
        center_y: f64,
        radius: f64,
    ) -> Option<Arc<[u64]>> {
        self.rel_spatial
            .get(&(
                type_token,
                prop_key,
                center_x.to_bits(),
                center_y.to_bits(),
                radius.to_bits(),
            ))
            .cloned()
    }

    /// Folds `other`'s memoised seeks into `self` (`rmp` tasks #768/#769/#770), used by the dispatch site
    /// to merge the per-kind captures (node + relationship equality, range, composite, text, spatial) into
    /// one memo for the reader. The maps are disjoint by kind, so this is a straight per-map extend.
    pub fn absorb(&mut self, other: IndexCandidateCapture) {
        self.entries.extend(other.entries);
        self.range.extend(other.range);
        self.composite.extend(other.composite);
        self.text.extend(other.text);
        self.rel_eq.extend(other.rel_eq);
        self.rel_range.extend(other.rel_range);
        self.rel_composite.extend(other.rel_composite);
        self.spatial.extend(other.spatial);
        self.rel_spatial.extend(other.rel_spatial);
    }

    /// Whether nothing was captured (the common case: a read with no indexed seek).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
            && self.range.is_empty()
            && self.composite.is_empty()
            && self.text.is_empty()
            && self.rel_eq.is_empty()
            && self.rel_range.is_empty()
            && self.rel_composite.is_empty()
            && self.spatial.is_empty()
            && self.rel_spatial.is_empty()
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

    /// Adds one access path's **candidate-examination** counts to this sink's [`ReadTally`]
    /// (`rmp` task #991): `examined` candidate records were decoded and tested, of which
    /// `rejected_by_visibility` were dropped by the MVCC visibility re-check and
    /// `rejected_by_predicate` by the access path's own predicate re-check (label, value, range,
    /// relationship type). The three are disjoint, so
    /// `examined - rejected_by_visibility - rejected_by_predicate` is what survived.
    ///
    /// Default: a **no-op**. A sink that does not measure candidate examination reports nothing
    /// rather than a fabricated number — the same rule the omitted `pageCache*`/`time` counters
    /// follow (decision `D-query-prefixes`). Note the consequence for a seam that keeps the default
    /// (in-tree, only [`MemGraph`](crate::graph_access::MemGraph), which is reachable from
    /// `graphus-cypher`/`graphus-tck` tests and never in production): its plans carry **no** candidate
    /// counter at all, and there the absence means "not measured" rather than "measured zero".
    fn note_candidates(
        &self,
        _examined: u64,
        _rejected_by_visibility: u64,
        _rejected_by_predicate: u64,
    ) {
    }
}

// =================================================================================================
// ReadTally / ReadCounts — the measured cost of the candidate + re-verification model (`rmp` #991)
// =================================================================================================

/// One access path's measured **candidate-examination** counts, drained off a [`ReadTally`]
/// (`rmp` task #991).
///
/// # Why this exists
///
/// Every index access path in Graphus is a *candidate list plus a re-verification*: the index answers
/// with a **superset** of the matching ids (it is a derived, MVCC-unaware structure), and the read body
/// re-reads each candidate to test visibility and re-apply the predicate. `dbHits` charges what an
/// operator **matched**, so a seek that examines a million candidates to return ten rows is
/// indistinguishable from one that examines ten — and the blanket `mark_all_live_nodes` predicate
/// footprint that every non-equality seek registers costs a pass over every live node without appearing
/// anywhere at all. These counters make both visible.
///
/// # What each field is (all **measured**, none derived)
///
/// The three candidate counters are **disjoint**: a candidate is counted once in
/// [`candidates_examined`](Self::candidates_examined) and then at most once as a rejection, so
/// `candidates_examined - rejected_by_visibility - rejected_by_predicate` is the number of candidates
/// that **survived the re-verification**.
///
/// That is a statement about *candidates*, and deliberately **not** about the operator's rows. Two
/// mechanisms make the two differ, both measured and pinned by
/// `tests/candidate_instrumentation.rs::surviving_candidates_are_not_rows_991`:
///
/// * **De-duplication.** A stale and a live index entry can name the same id, which is then examined
///   twice, survives twice, and yields **one** row — every `index_seek_*_recheck` body de-duplicates
///   before returning, precisely because that happens.
/// * **One candidate, several rows.** A self-loop under [`ExpandDirection::Both`] is one surviving
///   relationship candidate that [`expand_with_csr`] reports on both of its sides.
///
/// The two marker counters are counted at the point of emission — one per call the read body makes to
/// [`ReadSink::note_read`] / [`ReadSink::note_predicate_read`] — never inferred from the candidate
/// counts, which is why a blanket marker pass (zero candidates, one marker per live node) shows up
/// here as exactly what it is.
///
/// # Where a storage **fault** is counted (`rmp` #991, documented rather than separated)
///
/// A candidate whose record cannot be read at all is neither invisible nor predicate-rejected, but it
/// is aggregated into [`rejected_by_visibility`](Self::rejected_by_visibility) — and, for a property
/// read that faults inside a value residual, into
/// [`rejected_by_predicate`](Self::rejected_by_predicate). No fourth counter is spent on it because
/// the case is unobservable in a delivered plan: every such site **fails closed**, capturing the error
/// so the statement is rolled back and its plan never reaches a client. The aggregation is recorded
/// here rather than left implicit so that a future reader does not mistake a fault for a visibility
/// decision when debugging a captured-error path.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ReadCounts {
    /// Candidate records decoded from the store and tested by an access path's re-verification.
    pub candidates_examined: u64,
    /// Of those, how many were dropped because the version is not visible to this snapshot.
    pub rejected_by_visibility: u64,
    /// Of those, how many were dropped by the access path's own predicate re-check — the label
    /// bitmap, the current property value against the seek value or range bounds, or the
    /// relationship type.
    pub rejected_by_predicate: u64,
    /// Per-record SIREAD markers emitted ([`ReadSink::note_read`] calls).
    pub read_markers: u64,
    /// Predicate SIREAD markers emitted ([`ReadSink::note_predicate_read`] calls).
    pub predicate_markers: u64,
}

impl ReadCounts {
    /// The all-zero counts — what a seam that measures nothing reports.
    pub const ZERO: Self = Self {
        candidates_examined: 0,
        rejected_by_visibility: 0,
        rejected_by_predicate: 0,
        read_markers: 0,
        predicate_markers: 0,
    };

    /// Whether nothing at all was measured (the common case for an operator that never touches the
    /// storage seam).
    #[must_use]
    pub fn is_zero(&self) -> bool {
        *self == Self::ZERO
    }
}

/// The live accumulator behind [`ReadCounts`], owned by a seam that measures its own candidate
/// examination (`rmp` task #991).
///
/// # Why `Cell` and not an atomic
///
/// The seams that own one ([`RecordStoreGraph`](crate::record_graph::RecordStoreGraph) and
/// [`ReadOnlyGraph`](crate::read_only_graph::ReadOnlyGraph)) are already `!Sync` — both drive the store
/// through `RefCell` — and each is used by exactly one thread at a time (the engine thread, or the one
/// reader-pool thread the read was dispatched to). A `Cell` therefore needs no synchronisation at all,
/// which matters because these counters are incremented on the **always-on** path: an unprofiled
/// statement still tallies, it simply never drains.
///
/// The two halves accumulate differently, and only one is batched:
///
/// * **Candidates are batched.** A read body counts into plain `u64` locals and calls
///   [`ReadSink::note_candidates`] **once** per access, so the per-candidate cost is a register
///   increment and the per-access cost is three `Cell` read-modify-writes.
/// * **Markers are per-event.** [`note_read_marker`](Self::note_read_marker) /
///   [`note_predicate_marker`](Self::note_predicate_marker) do **one** `Cell` read-modify-write **per
///   marker emitted**, because markers are emitted from many scattered sites rather than from a single
///   loop. On the measured baseline that is 120 read-modify-writes for 40 candidates on an unselective
///   range seek — three per candidate, not three per access.
///
/// Neither shape is atomic and neither allocates, which is why the measured effect stays inside the
/// benchmark noise (`benches/read_seam.rs`, and `graphus-bench/RESULTS.md` §11.2 for the limits of
/// that evidence) — but the marker path is genuinely per-event and is described as such.
#[derive(Debug, Default)]
pub struct ReadTally {
    examined: Cell<u64>,
    rejected_by_visibility: Cell<u64>,
    rejected_by_predicate: Cell<u64>,
    read_markers: Cell<u64>,
    predicate_markers: Cell<u64>,
}

impl ReadTally {
    /// A fresh, zeroed tally.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds one access path's candidate counts (see [`ReadSink::note_candidates`]).
    #[inline]
    pub fn note_candidates(
        &self,
        examined: u64,
        rejected_by_visibility: u64,
        rejected_by_predicate: u64,
    ) {
        self.examined.set(self.examined.get() + examined);
        self.rejected_by_visibility
            .set(self.rejected_by_visibility.get() + rejected_by_visibility);
        self.rejected_by_predicate
            .set(self.rejected_by_predicate.get() + rejected_by_predicate);
    }

    /// Counts one emitted per-record SIREAD marker.
    #[inline]
    pub fn note_read_marker(&self) {
        self.read_markers.set(self.read_markers.get() + 1);
    }

    /// Counts one emitted predicate SIREAD marker.
    #[inline]
    pub fn note_predicate_marker(&self) {
        self.predicate_markers.set(self.predicate_markers.get() + 1);
    }

    /// Takes everything measured since the previous drain and **resets** to zero.
    ///
    /// Draining is what makes the counts attributable: the profiler drains immediately after each
    /// storage-seam call, so the counts land on the operator that made it and never leak into the next.
    #[must_use]
    pub fn take(&self) -> ReadCounts {
        ReadCounts {
            candidates_examined: self.examined.replace(0),
            rejected_by_visibility: self.rejected_by_visibility.replace(0),
            rejected_by_predicate: self.rejected_by_predicate.replace(0),
            read_markers: self.read_markers.replace(0),
            predicate_markers: self.predicate_markers.replace(0),
        }
    }
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
    /// Whether the node / relationship `(kind, id)` carrying `mvcc` **exists** as of this query's
    /// snapshot (`04 §5.3`), at statement granularity (`04 §5.1.4`, `rmp` #972). The one place the read
    /// body consults MVCC for existence.
    ///
    /// It takes `src` for the same reason [`labels_at`](Self::labels_at) does: the header words settle
    /// the cross-transaction half of the question, and the entity's undo chain settles the
    /// within-transaction half, which only the store can walk. Under
    /// [`View::New`](graphus_txn::View::New) the walk is not entered at all, so the default read path
    /// costs one comparison more than the header-only test it replaced.
    ///
    /// # Errors
    /// Returns a storage error if the entity's undo chain cannot be walked. **Every caller must fail
    /// closed on it** (`rmp` #733) — capture through the sink and yield no row — never fall back to the
    /// header's verdict, which is precisely the answer that needed correcting.
    #[inline]
    pub fn visible<S: StoreReadSource>(
        &self,
        src: &S,
        kind: StoreKind,
        id: u64,
        mvcc: MvccHeader,
    ) -> Result<bool, GraphusError> {
        src.entity_visible_at(kind, id, mvcc, self.snapshot, self.registry)
    }

    /// The header-only, cross-transaction visibility test (`04 §5.3`), for the callers whose subject is
    /// **not** an entity that owns an undo chain — a property cell's own stamps, say.
    ///
    /// Kept distinct from [`visible`](Self::visible) rather than merged: a caller that reaches for this
    /// on a node or a relationship silently loses statement granularity, and a differently-named method
    /// makes that a visible choice instead of an invisible default.
    #[inline]
    pub fn visible_header(&self, mvcc: MvccHeader) -> bool {
        is_visible(
            self.snapshot,
            mvcc.created_ts,
            mvcc.expired_ts,
            self.registry,
        )
    }

    /// The label bitmap `id` presents to this query's snapshot (`rmp` task #767), given the `live`
    /// word already decoded from `id`'s record.
    ///
    /// The label counterpart of [`visible`](Self::visible): where `visible` filters a *record*
    /// version, this resolves the *label word*, which is mutated in place and so has its versions on
    /// the node's undo chain rather than in the record (`rmp` #968).
    ///
    /// # Errors
    /// Returns a storage error if the node's undo chain cannot be walked (`rmp` #968).
    #[inline]
    pub fn labels_at<S: StoreReadSource>(
        &self,
        src: &S,
        id: u64,
        live: u64,
        head: u64,
    ) -> Result<u64, GraphusError> {
        src.label_bitmap_at(id, live, head, self.snapshot)
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
    // Candidate instrumentation (`rmp` #991), accumulated in locals and flushed once — see `ReadTally`.
    let (mut examined, mut hidden) = (0u64, 0u64);
    for id in ids {
        match src.node(id) {
            Ok(rec) => {
                examined += 1;
                // A full scan examines every node, so SIREAD-mark each (`04 §5.4`).
                sink.note_read(node_ssi_key(id));
                // Statement-granular existence (`rmp` #972): under `View::Old` a node this very
                // statement created is not yet there. A chain read fault FAILS CLOSED (`rmp` #733) —
                // never the header's own verdict, which is the answer the chain corrects.
                match ctx.visible(src, StoreKind::Node, id, rec.mvcc) {
                    Ok(true) => out.push(NodeId(id)),
                    Ok(false) => hidden += 1,
                    Err(e) => {
                        sink.note_candidates(examined, hidden, 0);
                        sink.capture(e);
                        return Vec::new();
                    }
                }
            }
            Err(e) => {
                sink.note_candidates(examined, hidden, 0);
                sink.capture(e);
                return Vec::new();
            }
        }
    }
    sink.note_candidates(examined, hidden, 0);
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
///
/// Fails closed on a node read fault (`rmp` task #733): this is the same per-candidate re-check the
/// write-path uniqueness / node-key duplicate checks reach through the off-thread read graph, and a
/// swallowed fault on the existing holder's record would let a duplicate commit. See the inline
/// [`RecordStoreGraph::filter_label_candidates`](crate::record_graph) copy for the full argument — this
/// twin must stay byte-for-byte equivalent so the inline and off-thread paths never disagree.
pub fn filter_label_candidates<S: StoreReadSource, K: ReadSink>(
    src: &S,
    ctx: &VisCtx,
    sink: &K,
    token_id: u32,
    ids: Vec<u64>,
) -> Vec<NodeId> {
    let mut out = Vec::new();
    // Candidate instrumentation (`rmp` #991): this is THE candidate re-verification of every node
    // access path — the label re-check every index seek funnels its candidate list through — so its
    // counts are what makes "examined a million to return ten" visible. Counted in locals, flushed once.
    let (mut examined, mut hidden, mut filtered) = (0u64, 0u64, 0u64);
    for id in ids {
        // Skip nodes not visible before testing the label, honouring MVCC visibility.
        let rec = match src.node(id) {
            Ok(rec) => rec,
            // A read fault on the record itself: FAIL CLOSED (`rmp` task #733). `node` only errors on a
            // genuine fault (a reclaimed slot decodes to `Ok` with `in_use=false`), so capturing is
            // never a false alarm — and dropping the candidate could let a uniqueness / node-key check
            // miss an unreadable existing holder and commit a duplicate.
            Err(e) => {
                sink.note_candidates(examined, hidden, filtered);
                sink.capture(e);
                return Vec::new();
            }
        };
        examined += 1;
        // Statement-granular existence (`rmp` #972), fail-closed on a chain read fault (`rmp` #733).
        let visible = match ctx.visible(src, StoreKind::Node, id, rec.mvcc) {
            Ok(v) => v,
            Err(e) => {
                sink.note_candidates(examined, hidden, filtered);
                sink.capture(e);
                return Vec::new();
            }
        };
        // SIREAD-mark every examined node, visible or not (the label predicate examined it).
        sink.note_read(node_ssi_key(id));
        if !visible {
            hidden += 1;
            continue;
        }
        // Resolve the label word AS OF THIS SNAPSHOT (`rmp` #767) rather than reading whatever it
        // holds now. `rec` is already in hand, so this also drops the second `read_node` the old
        // `node_has_label(id, ..)` call performed per candidate.
        let bitmap = match ctx.labels_at(src, id, rec.labels, rec.mvcc.undo_ptr) {
            Ok(b) => b,
            Err(e) => {
                // A chain read fault is captured and the scan yields nothing, never a
                // wrong (missing/extra) row (`rmp` #733 fail-closed-on-read-fault).
                sink.note_candidates(examined, hidden, filtered);
                sink.capture(e);
                return Vec::new();
            }
        };
        match labels::has_label(bitmap, token_id) {
            Ok(true) => out.push(NodeId(id)),
            Ok(false) => filtered += 1,
            Err(e) => {
                // An overflow-form bitmap surfaces as a captured error, never a wrong row.
                sink.note_candidates(examined, hidden, filtered);
                sink.capture(GraphusError::from(e));
                return Vec::new();
            }
        }
    }
    sink.note_candidates(examined, hidden, filtered);
    out
}

/// Filters `ids` to the nodes that **currently** carry **any** of `token_ids` and are **visible**,
/// SIREAD-marking each examined id exactly once (`rmp` task #663) — the multi-label generalisation of
/// [`filter_label_candidates`] for a multi-label full-text index. An empty `token_ids` keeps nothing.
/// On a storage fault / overflow-form bitmap the error is captured and an empty result returned — never
/// a wrong (missing/extra) row (`rmp` task #733), the off-thread twin of the inline
/// `filter_any_label_candidates`.
pub fn filter_any_label_candidates<S: StoreReadSource, K: ReadSink>(
    src: &S,
    ctx: &VisCtx,
    sink: &K,
    token_ids: &[u32],
    ids: Vec<u64>,
) -> Vec<NodeId> {
    let mut out = Vec::new();
    // Candidate instrumentation (`rmp` #991) — see `filter_label_candidates`; counted in locals and
    // flushed once, including on every fail-closed exit (the candidates WERE examined).
    let (mut examined, mut hidden, mut filtered) = (0u64, 0u64, 0u64);
    for id in ids {
        let rec = match src.node(id) {
            Ok(rec) => rec,
            // FAIL CLOSED on a genuine read fault (`rmp` task #733), matching the `node_has_label` arm.
            Err(e) => {
                sink.note_candidates(examined, hidden, filtered);
                sink.capture(e);
                return Vec::new();
            }
        };
        examined += 1;
        // Statement-granular existence (`rmp` #972), fail-closed on a chain read fault (`rmp` #733).
        let visible = match ctx.visible(src, StoreKind::Node, id, rec.mvcc) {
            Ok(v) => v,
            Err(e) => {
                sink.note_candidates(examined, hidden, filtered);
                sink.capture(e);
                return Vec::new();
            }
        };
        // SIREAD-mark every examined node exactly once, visible or not.
        sink.note_read(node_ssi_key(id));
        if !visible {
            hidden += 1;
            continue;
        }
        // One snapshot-correct resolution (`rmp` #767) for the whole token loop below.
        let bitmap = match ctx.labels_at(src, id, rec.labels, rec.mvcc.undo_ptr) {
            Ok(b) => b,
            Err(e) => {
                // A chain read fault is captured and the scan yields nothing, never a
                // wrong (missing/extra) row (`rmp` #733 fail-closed-on-read-fault).
                sink.note_candidates(examined, hidden, filtered);
                sink.capture(e);
                return Vec::new();
            }
        };
        let mut carries = false;
        for &token_id in token_ids {
            match labels::has_label(bitmap, token_id) {
                Ok(true) => {
                    carries = true;
                    break;
                }
                Ok(false) => {}
                Err(e) => {
                    sink.note_candidates(examined, hidden, filtered);
                    sink.capture(GraphusError::from(e));
                    return Vec::new();
                }
            }
        }
        if carries {
            out.push(NodeId(id));
        } else {
            filtered += 1;
        }
    }
    sink.note_candidates(examined, hidden, filtered);
    out
}

/// A **fused** morsel scan (`rmp` task #339, Slice 3a): for each candidate `id`, read the node **once**,
/// SIREAD-mark it, and — if it is visible and currently carries `token_id` — read its `property` value
/// (newest-visible-wins), returning the surviving `(visible-label-carrying node count, present-property
/// values)`. This is the per-morsel work the parallel label-aggregate tier runs; it is
/// **byte-identical** to [`filter_label_candidates`] followed by a per-survivor [`node_property`] over
/// the same `ids`, but reads each candidate's node record fewer times (no separate `node_exists`
/// existence probe), which matters under buffer-pool contention when many morsels read concurrently.
///
/// The returned `label_matches` counts every **visible label-carrying** node (property present or not) —
/// the morsel's `count(*)` contribution — while `values` holds only the present-property values. The
/// per-candidate SIREAD marker is recorded exactly **once** per examined id (identical to
/// [`filter_label_candidates`]); the property read records no *additional* per-node marker (it re-reads
/// the same node's chain, which is the freshness probe `columnar_label_pass` documents — not a distinct
/// conflict key). On a storage fault the error is captured and the partial result is returned untrusted
/// (the caller abandons the parallel path).
///
/// **Cross-module marker-equivalence dependency (do not break):** equivalence to the serial path holds
/// at the *deduped set* level, not the multiset. The serial path marks each survivor **twice** (once in
/// [`filter_label_candidates`], once again in the [`node_property`] freshness re-read), whereas this
/// fused scan marks it **once**; the two SIREAD sets agree only because `graphus-txn`'s
/// `SsiReadBuffer::into_sorted_markers` and `SsiTracker::merge_read_buffer` **sort + dedup** before
/// replay. The `merge_read_buffer_*` regression tests in `graphus-txn` guard that dedup invariant; were
/// it ever removed, the serial-vs-morsel marker multisets would diverge even though the *sets* still
/// match.
pub fn scan_label_property_morsel<S: StoreReadSource, K: ReadSink>(
    src: &S,
    ctx: &VisCtx,
    sink: &K,
    token_id: u32,
    property: &str,
    ids: &[u64],
) -> (usize, Vec<Value>) {
    let mut label_matches = 0usize;
    let mut values: Vec<Value> = Vec::new();
    // Candidate instrumentation (`rmp` #991), identical in meaning to `filter_label_candidates`'s.
    let (mut examined, mut hidden, mut filtered) = (0u64, 0u64, 0u64);
    for &id in ids {
        // Read the node record ONCE (visibility + label re-check). A read fault FAILS CLOSED
        // (`rmp` task #733), exactly as the sibling `node_has_label` arm below and
        // `filter_label_candidates` do — `node` only errors on a genuine fault, so a swallowed error
        // would silently drop a node from the off-thread aggregation (a wrong `count(*)` / `sum(...)`).
        let rec = match src.node(id) {
            Ok(rec) => rec,
            Err(e) => {
                sink.note_candidates(examined, hidden, filtered);
                sink.capture(e);
                return (label_matches, values);
            }
        };
        examined += 1;
        // SIREAD-mark every examined candidate, visible or not (the predicate examined it) — the
        // identical per-candidate marker `filter_label_candidates` records.
        sink.note_read(node_ssi_key(id));
        // Statement-granular existence (`rmp` #972), fail-closed on a chain read fault (`rmp` #733).
        match ctx.visible(src, StoreKind::Node, id, rec.mvcc) {
            Ok(true) => {}
            Ok(false) => {
                hidden += 1;
                continue;
            }
            Err(e) => {
                sink.note_candidates(examined, hidden, filtered);
                sink.capture(e);
                return (label_matches, values);
            }
        }
        // Snapshot-correct label membership (`rmp` #767), resolved from the record read above.
        let bitmap = match ctx.labels_at(src, id, rec.labels, rec.mvcc.undo_ptr) {
            Ok(b) => b,
            Err(e) => {
                // A chain read fault is captured and the scan yields nothing, never a
                // wrong (missing/extra) row (`rmp` #733 fail-closed-on-read-fault).
                sink.note_candidates(examined, hidden, filtered);
                sink.capture(e);
                return (label_matches, values);
            }
        };
        match labels::has_label(bitmap, token_id) {
            Ok(true) => {}
            Ok(false) => {
                filtered += 1;
                continue;
            }
            Err(e) => {
                // An overflow-form bitmap surfaces as a captured error, never a wrong row.
                sink.note_candidates(examined, hidden, filtered);
                sink.capture(GraphusError::from(e));
                return (label_matches, values);
            }
        }
        // A visible label-carrying node: it counts toward `count(*)` regardless of the property.
        label_matches += 1;
        // Read the single property value (newest-visible-wins). `read_node_prop_one` re-walks this same
        // node's chain (no existence re-probe), recording no additional conflict marker.
        if let Some(value) = read_node_prop_one(src, ctx, sink, NodeId(id), property) {
            values.push(value);
        }
    }
    sink.note_candidates(examined, hidden, filtered);
    (label_matches, values)
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

/// The **precise** equality-filtered label-scan body for `MATCH (n:Label {prop: value})` served by a
/// full store scan (no derived property index, `rmp` task #325). It is the scan-path twin of
/// `RecordStoreGraph::index_seek_eq`'s SSI footprint: it reads **every** live node to evaluate the
/// predicate but builds a read **dependency** (SIREAD marker) on **only the matching nodes**, instead
/// of the blanket `mark_all_live_nodes` the bare label scan registers.
///
/// # Why this is the fix for the abort storm (`rmp` #325)
///
/// The old equality fallback ran `scan_nodes_by_label` (which `mark_all_live_nodes`-marks every live
/// node) and then a residual `Filter`. That blanket marker manufactured an rw-edge with **any**
/// concurrent node writer — even one touching a node that does not match `(label, property, value)` and
/// that the query never selected — so two transactions equality-matching **disjoint** keys conflicted
/// reciprocally and one was falsely aborted (measured: fraud-oltp `abort_rate ≈ 0.97`). This body marks
/// only the rows the query actually depends on, exactly as the indexed path already does (`rmp` #316).
///
/// # Phantom safety (identical to the indexed path, `rmp` #171/#316)
///
/// Serializability is preserved by two precise markers, mirroring `index_seek_eq`:
///   1. the per-**match** SIREAD below — a concurrent modify/delete of a *matching* node closes an
///      rw-edge (the writer's per-record `note_write` / pre-image footprint pairs with it); and
///   2. the precise [`PredicateRead::Equality`] marker — it pairs with the writer's post-image
///      `note_predicate_write` (driven from `reindex_node`/`create_node`, using the **same**
///      `encode_equality_canonical` encoder), so a concurrent INSERT or an UPDATE of some other node
///      *into* this exact `(label, property, value)` closes an rw-edge **even when this scan currently
///      matches nothing**. A non-matching node read here is therefore *not* under-covered: it cannot
///      silently start matching without a writer registering the paired `Equality` marker.
///
/// # When the precise marker cannot be formed → coarse fallback
///
/// The precise `Equality` marker requires the label and property-key tokens to already exist and the
/// seek value to be equality-encodable (`Null`/`List`/`Map`/`NaN` are not). If any is absent we cannot
/// form a marker that a writer's footprint could match, so we **fall back to the conservative
/// `scan_nodes_by_label` footprint** (`Label`/`AllNodes` + `mark_all_live_nodes`) and filter — exactly
/// what the path did before, and exactly what `index_seek_eq` does when it returns `None`. This keeps
/// the "label/property does not exist yet" phantom (a concurrent `CREATE` that interns the token and
/// inserts the first matching node) covered by the coarse marker.
pub fn scan_filter_eq<S: StoreReadSource, K: ReadSink>(
    src: &S,
    ctx: &VisCtx,
    sink: &K,
    label: &str,
    property: &str,
    seek: &Value,
) -> ScanFilter {
    // Resolve the label + prop-key tokens (no intern — a read never mints a token) and encode the seek
    // value canonically. If any is unavailable, the precise `Equality` marker cannot be formed, so fall
    // back to the conservative label-scan footprint + an equality filter (phantom-safe, see the doc).
    let (Some(label_token), Some(prop_key), Ok(encoded)) = (
        src.token_id(Namespace::Label, label),
        src.token_id(Namespace::PropKey, property),
        encode_equality_canonical(seek),
    ) else {
        let candidates = scan_nodes_by_label(src, ctx, sink, label);
        let examined = candidates.len();
        let matched: Vec<NodeId> = candidates
            .into_iter()
            .filter(|id| {
                node_property(src, ctx, sink, *id, property)
                    .is_some_and(|v| crate::equality::equals(&v, seek).is_true())
            })
            .collect();
        // The value residual's own rejections (`rmp` #991). The candidates themselves were already
        // counted (examined + visibility + label) by the `scan_nodes_by_label` above, so only the
        // *additional* predicate rejections are added here — never the candidates a second time.
        sink.note_candidates(0, 0, (examined - matched.len()) as u64);
        return ScanFilter { matched, examined };
    };

    // The phantom-safe predicate marker: the *precise* equality predicate, so a concurrent insert /
    // update of a node *into* this exact `(label, property, value)` closes an rw-edge even when the scan
    // currently matches nothing. Uses the same canonical encoder the writer's `note_predicate_write`
    // uses, so Cypher-equal values (incl. `1` vs `1.0`) register the SAME marker (`rmp` #171 blocker C1).
    sink.note_predicate_read(PredicateRead::Equality {
        label: label_token,
        property: prop_key,
        value: encoded,
    });

    // Read every live node to evaluate the predicate, but SIREAD-mark **only** the matching rows (those
    // that are visible, carry the label, and whose current value equals `seek` by Cypher equality). A
    // non-matching node is examined but **not** marked, so it creates no read dependency — exactly the
    // precision `filter_label_candidates` gives the indexed path over its candidate subset, here applied
    // to a full scan over the matching subset.
    let ids = match src.scan_node_ids() {
        Ok(ids) => ids,
        Err(e) => {
            sink.capture(e);
            return ScanFilter::default();
        }
    };
    // Every live node record is READ to evaluate the predicate (only the matches are SIREAD-marked and
    // returned). That read count is this operator's true storage cost, so it is reported to the caller for
    // a `PROFILE`'s `dbHits` (`rmp` #752) — a measured number, free to obtain (it is the scan's own length).
    let examined = ids.len();
    let mut out = Vec::new();
    // Candidate instrumentation (`rmp` #991). `examined` above is the same quantity, already reported to
    // the caller as this operator's `dbHits`; it is tallied here too so the fused scan+filter is
    // comparable, operator for operator, with the index seek that replaces it.
    let (mut seen, mut hidden, mut filtered) = (0u64, 0u64, 0u64);
    for id in ids {
        // Visibility first (MVCC): a tombstoned / not-yet-committed node never matches.
        let rec = match src.node(id) {
            Ok(rec) => rec,
            // `scan_node_ids` only yields slot-occupied ids; a transient decode fault is a real error.
            Err(e) => {
                sink.note_candidates(seen, hidden, filtered);
                sink.capture(e);
                return ScanFilter::default();
            }
        };
        seen += 1;
        // Statement-granular existence (`rmp` #972), fail-closed on a chain read fault (`rmp` #733).
        match ctx.visible(src, StoreKind::Node, id, rec.mvcc) {
            Ok(true) => {}
            Ok(false) => {
                hidden += 1;
                continue;
            }
            Err(e) => {
                sink.note_candidates(seen, hidden, filtered);
                sink.capture(e);
                return ScanFilter::default();
            }
        }
        // Carries the label AS OF THIS SNAPSHOT (`rmp` #767)?
        let bitmap = match ctx.labels_at(src, id, rec.labels, rec.mvcc.undo_ptr) {
            Ok(b) => b,
            Err(e) => {
                // A chain read fault is captured and the scan yields nothing, never a
                // wrong (missing/extra) row (`rmp` #733 fail-closed-on-read-fault).
                sink.note_candidates(examined as u64, hidden, filtered);
                sink.capture(e);
                return ScanFilter::default();
            }
        };
        match labels::has_label(bitmap, label_token) {
            Ok(true) => {}
            Ok(false) => {
                filtered += 1;
                continue;
            }
            Err(e) => {
                // An overflow-form bitmap (#39) surfaces as a captured error, never a wrong row.
                sink.note_candidates(seen, hidden, filtered);
                sink.capture(GraphusError::from(e));
                return ScanFilter::default();
            }
        }
        // Current value equals `seek`? Use the non-marking property read (`read_node_prop_one`) so that
        // probing a non-matching node does NOT register a SIREAD on it — the whole point of #325.
        let matches = read_node_prop_one(src, ctx, sink, NodeId(id), property)
            .is_some_and(|v| crate::equality::equals(&v, seek).is_true());
        if matches {
            // The node is part of the result set: build the read dependency on it now (a concurrent
            // modify/delete of *this* matching node must abort one of the two).
            sink.note_read(node_ssi_key(id));
            out.push(NodeId(id));
        } else {
            filtered += 1;
        }
    }
    sink.note_candidates(seen, hidden, filtered);
    ScanFilter {
        matched: out,
        examined,
    }
}

/// The **re-check half** of an indexed node-property equality seek (`rmp` task #755, Slice S1): given a
/// candidate id list produced by *some* index source, register the seek's SSI footprint and reduce the
/// candidates to exactly the rows `scan_filter_eq` would return for the same `(label, property, seek)`.
///
/// # Why this is lifted (the anti-drift move)
///
/// A node index is **candidate-only**: it yields a SUPERSET of the matching ids (stale entries, entries
/// written by transactions this snapshot cannot see, cross-type encodings). Everything that turns that
/// superset into the answer — MVCC visibility, the label re-check, the current-value equality residual,
/// the SIREAD markers, the dedup — is *semantics*, and it must be identical no matter where the
/// candidates came from. Lifting it here (the Fork-1 factorisation of `rmp` #336 applied to seeks) makes
/// "identical" a property of the **code**, not of code review: `RecordStoreGraph::index_seek_eq` calls
/// this with candidates from its live `IndexSet`, and any future off-thread candidate source calls the
/// same body with the same guarantees.
///
/// # The contract on `candidates`
///
/// `candidates` MUST be a **superset** of the ids whose *current, snapshot-visible* value equals `seek`
/// under `(label_token, prop_key)`. A superset is safe (this body filters extras out); a **subset is
/// silent row loss** and this body cannot detect it. A caller that cannot guarantee the superset property
/// MUST decline (return `None` to the executor, taking the exact `scan_filter_eq` fallback) rather than
/// pass a partial list — never `Some(vec![])`, which reads as "no match" (`rmp` #680/#738).
///
/// # SSI footprint (byte-identical to the inline path it replaces, `rmp` #316/#325)
///
/// Two precise markers, and deliberately **no** `mark_all_live_nodes` blanket:
///   1. the per-candidate SIREAD in [`filter_label_candidates`] — a concurrent modify/delete of a node
///      this seek *examined* closes an rw-edge; and
///   2. the precise [`PredicateRead::Equality`] marker — it pairs with the writer's
///      `note_predicate_write` (same `encode_equality_canonical` encoder), so a concurrent INSERT or an
///      UPDATE of some *other* node **into** this exact `(label, property, value)` closes an rw-edge even
///      when the seek currently matches nothing.
///
/// `rmp` #316 removed the blanket marker (it manufactured an rw-edge with any concurrent node writer:
/// measured fraud-oltp `abort_rate ≈ 0.97`); **do NOT reintroduce it here**. A non-encodable `seek`
/// registers no `Equality` marker, and that is sound with no backstop: `List` declines upstream and takes
/// the exact scan fallback; `Null`/`Map` are not equality-seekable; and `NaN` equals nothing (not even
/// itself), so no writer can make a node match — there is no phantom to catch.
/// # Carrying the re-checked value (`rmp` task #879)
///
/// The value-residual below **reads the current visible value from the store** and then throws it
/// away. Under [`KeyValues::Carry`] it is kept instead and returned parallel to the ids, so a later
/// `n.property` is served from the row rather than repeating that read. What is carried is precisely
/// what the store returned through [`node_property`] — the same call, at the same point, under the
/// same snapshot, having registered the same SIREAD marker — so it is byte-identical to what a
/// second read would return, for every Cypher type. Nothing is decoded from an index key: the key
/// codec is not injective (`rmp` #894) and `graphus-index` has no decoder at all.
#[allow(clippy::too_many_arguments)] // a lifted read body; the source/ctx/sink seams are positional
pub fn index_seek_eq_recheck<S: StoreReadSource, K: ReadSink>(
    src: &S,
    ctx: &VisCtx,
    sink: &K,
    label_token: u32,
    prop_key: u32,
    property: &str,
    seek: &Value,
    candidates: Vec<u64>,
    carry: KeyValues,
) -> IndexSeekHits {
    // (2) The precise equality predicate marker. NOTE this is the SSI marker ONLY: the candidate lookup
    // upstream keys off the raw `Value`, so seek/scan *result* semantics are entirely unchanged.
    if let Ok(encoded) = encode_equality_canonical(seek) {
        sink.note_predicate_read(PredicateRead::Equality {
            label: label_token,
            property: prop_key,
            value: encoded,
        });
    }

    // (1) Re-check the FULL `scan_filter_eq` predicate per candidate: visible + carries the label
    // (`filter_label_candidates`, which SIREAD-marks each examined id and fails closed on a read fault),
    // then the *current* value equals `seek` by Cypher equality.
    let labelled = filter_label_candidates(src, ctx, sink, label_token, candidates);

    let mut out: Vec<(NodeId, Option<Value>)> = Vec::with_capacity(labelled.len());
    // The value residual's own rejections (`rmp` #991): a candidate that survived the label re-check but
    // whose current value is absent, or differs from `seek`. The candidates were already counted by
    // `filter_label_candidates` — only the extra rejections are added, never the candidates twice.
    let mut filtered = 0u64;
    for id in labelled {
        let Some(value) = node_property(src, ctx, sink, id, property) else {
            filtered += 1;
            continue;
        };
        if crate::equality::equals(&value, seek).is_true() {
            // `carry.keep` DROPS the value under `Discard`, right here — the discarding path never
            // holds a second copy of the result set (`rmp` #879).
            out.push((id, carry.keep(value)));
        } else {
            filtered += 1;
        }
    }
    sink.note_candidates(0, 0, filtered);
    // De-duplicate: a stale + a live index entry can name the same id twice. Keyed on the id alone,
    // so the carried value stays aligned with the id it was read from. The sort stays UNSTABLE, as
    // before: two entries sharing an id also share their value — both came from `node_property(id,
    // property)` in this loop, at one snapshot, with nothing writing in between — so which of them
    // survives the dedup is unobservable.
    out.sort_unstable_by_key(|(id, _)| *id);
    out.dedup_by_key(|(id, _)| *id);
    IndexSeekHits::from_pairs(out)
}

/// The **re-check half** of an indexed node-property RANGE seek (`rmp` task #768): given a candidate id
/// list from *some* index source, register the seek's SSI footprint and reduce the candidates to exactly
/// the rows `scan_filter_range` would return for the same `(label, property, lower, upper)`.
///
/// Lifted for the same anti-drift reason as [`index_seek_eq_recheck`]: `RecordStoreGraph::index_seek_range`
/// (candidates from its live `IndexSet`) and the off-thread `ReadOnlyGraph` (candidates from the
/// [`IndexCandidateCapture`] memo) both call this one body, so their rows and their SSI footprint are
/// identical **by construction**, not by review.
///
/// # SSI footprint (byte-identical to the inline range seek and to `scan_filter_range`, `rmp` #171/§5.4)
///
/// A range predicate has no precise per-value `Equality` marker, so — exactly as the inline seek and the
/// scan fallback it stands in for both do — it registers the conservative pair: the coarse
/// [`PredicateRead::Label`] marker (any concurrent INSERT of this label is a possible phantom) plus the
/// blanket [`mark_all_live_nodes`] read (a range scan reads every node to evaluate the predicate). The
/// per-candidate SIREAD in [`filter_label_candidates`] is subsumed by that blanket. This is the same
/// footprint whether the index serves the seek or the scan replaces it, so serving it off-thread changes
/// nothing (`rmp` #755's "do not change the footprint" rule).
///
/// # The contract on `candidates`
///
/// `candidates` MUST be a **superset** of the ids whose *current, snapshot-visible* value satisfies
/// `(lower, upper)` under `(label_token, prop_key)`. A superset is safe (this body filters extras out via
/// [`crate::eval::satisfies_range`], the single comparison source of truth); a **subset is silent row
/// loss** this body cannot detect. A caller that cannot guarantee the superset MUST decline (`None` →
/// exact scan fallback), never `Some(vec![])` (`rmp` #680/#738).
#[allow(clippy::too_many_arguments)] // a lifted read body; the source/ctx/sink seams are positional
pub fn index_seek_range_recheck<S: StoreReadSource, K: ReadSink>(
    src: &S,
    ctx: &VisCtx,
    sink: &K,
    label_token: u32,
    property: &str,
    lower: Option<(&Value, bool)>,
    upper: Option<(&Value, bool)>,
    candidates: Vec<u64>,
    carry: KeyValues,
) -> IndexSeekHits {
    // Preserve the exact `scan_filter_range` read footprint (`scan_nodes_by_label` → `Label` +
    // `mark_all_live_nodes`) so the index path and the scan fallback are indistinguishable to SSI.
    sink.note_predicate_read(PredicateRead::Label(label_token));
    mark_all_live_nodes(src, sink);

    // Re-check the FULL predicate per candidate: visible + carries the label (`filter_label_candidates`,
    // which SIREAD-marks each examined id — subsumed by the blanket above — and fails closed on a read
    // fault), then the *current* value satisfies BOTH bounds under Cypher comparison semantics.
    let labelled = filter_label_candidates(src, ctx, sink, label_token, candidates);
    let mut out: Vec<(NodeId, Option<Value>)> = Vec::with_capacity(labelled.len());
    // The range residual's own rejections (`rmp` #991) — see `index_seek_eq_recheck`.
    let mut filtered = 0u64;
    for id in labelled {
        let Some(value) = node_property(src, ctx, sink, id, property) else {
            filtered += 1;
            continue;
        };
        if crate::eval::satisfies_range(&value, lower, upper) {
            // The value the range residual just tested — carried under `rmp` #879, dropped otherwise.
            out.push((id, carry.keep(value)));
        } else {
            filtered += 1;
        }
    }
    sink.note_candidates(0, 0, filtered);
    // De-duplicate: a stale + a live index entry can name the same id twice.
    out.sort_unstable_by_key(|(id, _)| *id);
    out.dedup_by_key(|(id, _)| *id);
    IndexSeekHits::from_pairs(out)
}

/// The **re-check half** of an indexed node COMPOSITE (multi-property) equality seek (`rmp` task #768):
/// given a candidate id list from *some* index source, register the seek's SSI footprint and reduce the
/// candidates to exactly the rows `scan_filter_composite_eq` would return for the same
/// `(label, properties, values)`.
///
/// Lifted for the same anti-drift reason as [`index_seek_eq_recheck`]: the inline
/// `RecordStoreGraph::index_seek_composite_eq` and the off-thread reader both call this one body.
///
/// # SSI footprint (byte-identical to the inline composite seek and to `scan_filter_composite_eq`)
///
/// The composite index has no precise multi-property `Equality` marker, so — exactly as the inline seek
/// and the scan fallback both do — it registers the coarse [`PredicateRead::Label`] marker (pairing with
/// every node insert's `Label(L)` write footprint, closing the composite-absence phantom the physical
/// per-key SIREADs alone would miss) plus the blanket [`mark_all_live_nodes`]. Conservative but never
/// wrong; unchanged whether the index serves the seek or the scan replaces it (`rmp` #401/#755).
///
/// # The contract on `candidates`
///
/// `candidates` MUST be a **superset** of the ids whose *current, snapshot-visible* tuple over
/// `properties` equals `values` element-wise by Cypher equality. A superset is safe (this body filters
/// extras out); a subset is silent row loss. A caller that cannot guarantee the superset MUST decline
/// (`None` → exact scan fallback), never `Some(vec![])` (`rmp` #680/#738).
#[allow(clippy::too_many_arguments)] // a lifted read body; the source/ctx/sink seams are positional
pub fn index_seek_composite_recheck<S: StoreReadSource, K: ReadSink>(
    src: &S,
    ctx: &VisCtx,
    sink: &K,
    label_token: u32,
    properties: &[String],
    values: &[Value],
    candidates: Vec<u64>,
    carry: KeyValues,
) -> CompositeSeekHits {
    // Preserve the exact `scan_filter_composite_eq` read footprint (the coarse `Label` marker + the
    // blanket `mark_all_live_nodes`) so the index path and the scan fallback are indistinguishable.
    sink.note_predicate_read(PredicateRead::Label(label_token));
    mark_all_live_nodes(src, sink);

    // Re-check the FULL predicate per candidate: visible + carries the label
    // (`filter_label_candidates`), then the *current* per-property tuple equals `values` element-wise by
    // Cypher equality — the same test `scan_filter_composite_eq` applies, so both paths return the
    // identical set.
    let labelled = filter_label_candidates(src, ctx, sink, label_token, candidates);
    let mut out: Vec<(NodeId, Option<Vec<Value>>)> = Vec::with_capacity(labelled.len());
    // The tuple residual's own rejections (`rmp` #991) — see `index_seek_eq_recheck`. One per rejected
    // CANDIDATE, not per rejected key: the short-circuit means a candidate fails on exactly one key.
    let mut filtered = 0u64;
    for id in labelled {
        // The element-wise tuple residual, still SHORT-CIRCUITING on the first key that fails: a
        // candidate rejected on key 1 must not read keys 2..k, or the read footprint would grow.
        // A candidate that SURVIVES has, by definition, read every key — which is exactly why the
        // whole tuple is available to carry (`rmp` #879) at no extra cost.
        let mut tuple: Vec<Value> = Vec::with_capacity(properties.len());
        let mut all_match = true;
        for (property, value) in properties.iter().zip(values.iter()) {
            match node_property(src, ctx, sink, id, property) {
                Some(v) if crate::equality::equals(&v, value).is_true() => tuple.push(v),
                _ => {
                    all_match = false;
                    break;
                }
            }
        }
        if all_match {
            out.push((id, carry.keep(tuple)));
        } else {
            filtered += 1;
        }
    }
    sink.note_candidates(0, 0, filtered);
    // De-duplicate: a stale + a live index entry can name the same id twice.
    out.sort_unstable_by_key(|(id, _)| *id);
    out.dedup_by_key(|(id, _)| *id);
    CompositeSeekHits::from_pairs(out)
}

/// The **re-check half** of an indexed node TEXT (trigram) seek (`rmp` task #768): given a candidate id
/// list from *some* index source, register the seek's SSI footprint and reduce the candidates to the
/// visible, currently-labelled nodes — the exact set the inline `RecordStoreGraph::index_seek_text`
/// returns for the same `label_token`.
///
/// Lifted for the same anti-drift reason as [`index_seek_eq_recheck`]: the inline
/// `RecordStoreGraph::index_seek_text` and the off-thread reader both call this one body, so their rows
/// and their SSI footprint are identical **by construction**.
///
/// # No predicate residual here — the executor keeps it (verified, `rmp` #662/#768)
///
/// Unlike RANGE/COMPOSITE, the text operator does **not** consume its predicate: the planner leaves the
/// exact `CONTAINS`/`ENDS WITH`/`STARTS WITH` as a residual [`Filter`](crate::physical::PhysicalOp::Filter)
/// **above** [`NodeTextIndexSeek`](crate::physical::PhysicalOp::NodeTextIndexSeek) (executor.rs, the
/// `NodeTextIndexSeek` arm). So this body — like the inline seek — only narrows the trigram candidate
/// superset to visible, labelled nodes; that residual filter restores exactness. It therefore applies **no**
/// string predicate itself, and the result is identical whether the trigram index serves the seek or a
/// label scan replaces it.
///
/// # SSI footprint (byte-identical to the inline text seek, `rmp` #467/#768)
///
/// The blanket [`mark_all_live_nodes`] read (the trigram seek stands in for a label scan that reads every
/// node) plus the per-candidate [`filter_label_candidates`] SIREAD it subsumes. This matches the **inline
/// text seek** exactly (the acceptance bar); note the inline text seek — and its spatial sibling — register
/// **no** coarse `Label` phantom marker, so this reproduces the inline seek's footprint, not the scan's
/// (which does register `Label`). That established seek/scan asymmetry is pre-existing (`rmp` #662/#73),
/// out of scope for this task, and reproduced here rather than altered.
pub fn index_seek_text_recheck<S: StoreReadSource, K: ReadSink>(
    src: &S,
    ctx: &VisCtx,
    sink: &K,
    label_token: u32,
    candidates: Vec<u64>,
) -> Vec<NodeId> {
    // Preserve the inline text seek's read footprint: the blanket `mark_all_live_nodes` (a text seek
    // stands in for a label scan) + the per-candidate SIREAD in `filter_label_candidates` it subsumes.
    mark_all_live_nodes(src, sink);
    let mut out = filter_label_candidates(src, ctx, sink, label_token, candidates);
    out.sort_unstable();
    out.dedup();
    out
}

/// The **re-check half** of an indexed node SPATIAL (point) proximity seek (`rmp` task #770): narrow the
/// grid candidate superset to exactly the nodes the inline `index_seek_spatial` would return.
///
/// The spatial and text node seeks are the **same** narrowing (`rmp` #662/#73): the grid returns a
/// geometric superset just as the trigram index returns a candidate superset; both register the blanket
/// [`mark_all_live_nodes`] (the seek stands in for a label scan) + the per-candidate
/// [`filter_label_candidates`] SIREAD, and neither applies a predicate residual — the executor keeps the
/// exact `distance(...) <op> r` filter above [`SpatialIndexSeek`](crate::physical::PhysicalOp::SpatialIndexSeek)
/// (executor.rs, the `SpatialIndexSeek` arm), exactly as it keeps the `CONTAINS`/`ENDS WITH`/`STARTS WITH`
/// residual above the text seek. So this delegates to the one shared body ([`index_seek_text_recheck`]) —
/// no fork, no drift — and the inline seam calls it too, so rows + SSI footprint are identical by
/// construction. `candidates` MUST be a superset; a subset is silent row loss (a caller that cannot
/// guarantee it MUST decline `None`, never `Some(vec![])`, `rmp` #680/#738).
pub fn index_seek_spatial_recheck<S: StoreReadSource, K: ReadSink>(
    src: &S,
    ctx: &VisCtx,
    sink: &K,
    label_token: u32,
    candidates: Vec<u64>,
) -> Vec<NodeId> {
    index_seek_text_recheck(src, ctx, sink, label_token, candidates)
}

// =================================================================================================
// Relationship index seeks (`rmp` task #769) — the off-thread twin of the node seeks above
// =================================================================================================

/// Registers the **precise relationship-equality** SIREAD predicate marker for a rel-eq seek
/// (`rmp` #683/#769): [`PredicateRead::RelEquality`] when `value` is canonically encodable, else the
/// coarse [`PredicateRead::RelType`] fallback (never "no marker"). The reader twin of
/// `RecordStoreGraph::note_rel_equality_read`, sharing the same [`encode_equality_canonical`] encoder so
/// a reader's marker pairs byte-for-byte with the writer's post-image announcement.
pub fn note_rel_equality_read<K: ReadSink>(
    sink: &K,
    type_token: u32,
    prop_key: u32,
    value: &Value,
) {
    match encode_equality_canonical(value) {
        Ok(encoded) => sink.note_predicate_read(PredicateRead::RelEquality {
            rel_type: type_token,
            property: prop_key,
            value: encoded,
        }),
        Err(_) => sink.note_predicate_read(PredicateRead::RelType(type_token)),
    }
}

/// SIREAD-marks **every live relationship** as this transaction's predicate-read footprint (the body of
/// `RecordStoreGraph::mark_all_live_rels`), the conservative phantom-safe approximation a
/// relationship-type / range / composite predicate read requires. Read errors are captured exactly as
/// the inline path would.
pub fn mark_all_live_rels<S: StoreReadSource, K: ReadSink>(src: &S, sink: &K) {
    let ids = match src.scan_rel_ids() {
        Ok(ids) => ids,
        Err(e) => {
            sink.capture(e);
            return;
        }
    };
    for id in ids {
        sink.note_read(rel_ssi_key(id));
    }
}

/// The **re-check half** of an indexed relationship-property EQUALITY seek (`rmp` #769/#683): given a
/// candidate rel-id list from *some* index source, reduce it to exactly the relationships the inline
/// `rel_index_seek_eq` would return for the same `(type, property, value)`.
///
/// # Why the marker is NOT here (the relationship/node asymmetry, `rmp` #683)
///
/// Unlike the node [`index_seek_eq_recheck`], this body registers **no** predicate marker. The precise
/// [`PredicateRead::RelEquality`] marker is registered by the *caller* (both the inline seam and the
/// reader call [`note_rel_equality_read`] just before this body) and NOT moved in here, because the
/// relationship scan fallback registers no `RelEquality` marker of its own — so the inline seam must
/// register it *before* its rebuild/`List` decline (to keep the decline's footprint), which this body,
/// reached only on a serve, cannot do. What is shared here is the ACID-critical part: the per-candidate
/// re-check that determines the rows **and** the per-candidate SIREAD (via [`rel_data`] / [`rel_property`],
/// which mark every relationship the seek examined). That is what backs the `rmp` #683 uniqueness path,
/// so it must be identical at both seams — and it is, because it is this one body.
///
/// # The contract on `candidates`
///
/// `candidates` MUST be a **superset** of the visible relationships of `type_name` whose current
/// `property` equals `value`. A superset is safe (this body filters extras out); a **subset is silent
/// row loss** — and, on the uniqueness path, an admitted committed duplicate (`rmp` #683). A caller that
/// cannot guarantee the superset MUST decline (`None` → exact typed scan), never `Some(vec![])`
/// (`rmp` #680/#738).
#[allow(clippy::too_many_arguments)] // a lifted read body; the source/ctx/sink seams are positional
pub fn rel_index_seek_eq_recheck<S: StoreReadSource, K: ReadSink>(
    src: &S,
    ctx: &VisCtx,
    sink: &K,
    type_name: &str,
    property: &str,
    value: &Value,
    candidates: Vec<u64>,
) -> Vec<RelId> {
    // Candidate instrumentation (`rmp` #991): `rel_candidate` discriminates a hidden version from a
    // type/value mismatch, which the `Option` of `rel_data` cannot.
    let (mut examined, mut hidden, mut filtered) = (0u64, 0u64, 0u64);
    let mut out: Vec<u64> = candidates
        .into_iter()
        .filter(|&id| {
            let r = RelId(id);
            examined += 1;
            match rel_candidate(src, ctx, sink, r) {
                RelCandidate::Visible(data) if data.rel_type == type_name => {
                    let keep = rel_property(src, ctx, sink, r, property)
                        .is_some_and(|v| crate::equality::equals(&v, value).is_true());
                    if !keep {
                        filtered += 1;
                    }
                    keep
                }
                RelCandidate::Visible(_) => {
                    filtered += 1;
                    false
                }
                RelCandidate::Hidden | RelCandidate::Faulted => {
                    hidden += 1;
                    false
                }
            }
        })
        .collect();
    sink.note_candidates(examined, hidden, filtered);
    // De-duplicate: a stale + a live index entry can name the same id twice.
    out.sort_unstable();
    out.dedup();
    out.into_iter().map(RelId).collect()
}

/// The **re-check half** of an indexed relationship-property RANGE seek (`rmp` #769/#680): the range
/// twin of [`rel_index_seek_eq_recheck`]. Re-checks visible + current type + the current value satisfies
/// both bounds under [`crate::eval::satisfies_range`] (the single comparison source of truth). As with
/// the eq twin, the SSI markers (the coarse [`PredicateRead::RelType`] + the blanket [`mark_all_live_rels`])
/// are registered by the caller, not here (`rmp` #683 asymmetry); this body owns the rows + the
/// per-candidate SIREAD.
#[allow(clippy::too_many_arguments)] // a lifted read body; the source/ctx/sink seams are positional
pub fn rel_index_seek_range_recheck<S: StoreReadSource, K: ReadSink>(
    src: &S,
    ctx: &VisCtx,
    sink: &K,
    type_name: &str,
    property: &str,
    lower: Option<(&Value, bool)>,
    upper: Option<(&Value, bool)>,
    candidates: Vec<u64>,
) -> Vec<RelId> {
    // Candidate instrumentation (`rmp` #991) — see `rel_index_seek_eq_recheck`.
    let (mut examined, mut hidden, mut filtered) = (0u64, 0u64, 0u64);
    let mut out: Vec<u64> = candidates
        .into_iter()
        .filter(|&id| {
            let r = RelId(id);
            examined += 1;
            match rel_candidate(src, ctx, sink, r) {
                RelCandidate::Visible(data) if data.rel_type == type_name => {
                    let keep = rel_property(src, ctx, sink, r, property)
                        .is_some_and(|v| crate::eval::satisfies_range(&v, lower, upper));
                    if !keep {
                        filtered += 1;
                    }
                    keep
                }
                RelCandidate::Visible(_) => {
                    filtered += 1;
                    false
                }
                RelCandidate::Hidden | RelCandidate::Faulted => {
                    hidden += 1;
                    false
                }
            }
        })
        .collect();
    sink.note_candidates(examined, hidden, filtered);
    out.sort_unstable();
    out.dedup();
    out.into_iter().map(RelId).collect()
}

/// The **re-check half** of an indexed relationship COMPOSITE (multi-property) equality seek
/// (`rmp` #769/#666): re-checks visible + current type + the current per-property tuple equals `values`
/// element-wise by Cypher equality. SSI markers registered by the caller (`rmp` #683 asymmetry).
#[allow(clippy::too_many_arguments)] // a lifted read body; the source/ctx/sink seams are positional
pub fn rel_index_seek_composite_recheck<S: StoreReadSource, K: ReadSink>(
    src: &S,
    ctx: &VisCtx,
    sink: &K,
    type_name: &str,
    properties: &[String],
    values: &[Value],
    candidates: Vec<u64>,
) -> Vec<RelId> {
    // Candidate instrumentation (`rmp` #991) — see `rel_index_seek_eq_recheck`.
    let (mut examined, mut hidden, mut filtered) = (0u64, 0u64, 0u64);
    let mut out: Vec<u64> = candidates
        .into_iter()
        .filter(|&id| {
            let r = RelId(id);
            examined += 1;
            match rel_candidate(src, ctx, sink, r) {
                RelCandidate::Visible(data) if data.rel_type == type_name => {
                    let keep = properties
                        .iter()
                        .zip(values.iter())
                        .all(|(property, value)| {
                            rel_property(src, ctx, sink, r, property)
                                .is_some_and(|v| crate::equality::equals(&v, value).is_true())
                        });
                    if !keep {
                        filtered += 1;
                    }
                    keep
                }
                RelCandidate::Visible(_) => {
                    filtered += 1;
                    false
                }
                RelCandidate::Hidden | RelCandidate::Faulted => {
                    hidden += 1;
                    false
                }
            }
        })
        .collect();
    sink.note_candidates(examined, hidden, filtered);
    out.sort_unstable();
    out.dedup();
    out.into_iter().map(RelId).collect()
}

/// The **re-check half** of an indexed relationship SPATIAL (point) proximity seek (`rmp` task #770/#664):
/// narrow the grid candidate superset to exactly the relationships the inline `index_seek_spatial_rel`
/// would return for the same `(type, centre, radius)`.
///
/// # The marker IS here (unlike the rel eq/range/composite bodies, `rmp` #769/#683)
///
/// The rel eq/range/composite bodies leave their marker to the caller because the rel scan fallback
/// registers no matching precise marker, and the inline seam must register it *before* its `List`/rebuild
/// decline. A spatial seek has **no such asymmetry**: its centre/radius are constants (never a `List`), so
/// there is no pre-decline marker to preserve — the inline seam simply calls `self.mark_all_live_rels()`
/// right before this narrowing, on a serve. So the blanket [`mark_all_live_rels`] lives *inside* this body
/// (exactly as [`mark_all_live_nodes`] lives inside the node [`index_seek_text_recheck`] this delegates
/// the node spatial seek to), and there is **no** `distance` residual here — the executor keeps the exact
/// `distance(...) <op> r` filter above [`RelSpatialIndexSeek`](crate::physical::PhysicalOp::RelSpatialIndexSeek).
/// Both the inline seam and the reader call this one body, so rows + SSI footprint match by construction.
///
/// `candidates` MUST be a superset of the visible relationships of `type_name` within the radius; a subset
/// is silent row loss (a caller that cannot guarantee it MUST decline `None`, never `Some(vec![])`,
/// `rmp` #680/#738).
pub fn rel_index_seek_spatial_recheck<S: StoreReadSource, K: ReadSink>(
    src: &S,
    ctx: &VisCtx,
    sink: &K,
    type_name: &str,
    candidates: Vec<u64>,
) -> Vec<RelId> {
    // The inline rel spatial seam marks every live relationship (the seek stands in for a typed scan) —
    // reproduce it here so the served footprint is identical.
    mark_all_live_rels(src, sink);
    // Candidate instrumentation (`rmp` #991) — see `rel_index_seek_eq_recheck`.
    let (mut examined, mut hidden, mut filtered) = (0u64, 0u64, 0u64);
    let mut out: Vec<u64> = candidates
        .into_iter()
        .filter(|&id| {
            // `rel_candidate` SIREAD-marks + visibility-filters each candidate, mirroring the inline
            // seam's per-candidate `self.rel_data(...)` type re-check; the residual `distance` filter
            // above restores exactness.
            examined += 1;
            match rel_candidate(src, ctx, sink, RelId(id)) {
                RelCandidate::Visible(data) if data.rel_type == type_name => true,
                RelCandidate::Visible(_) => {
                    filtered += 1;
                    false
                }
                RelCandidate::Hidden | RelCandidate::Faulted => {
                    hidden += 1;
                    false
                }
            }
        })
        .collect();
    sink.note_candidates(examined, hidden, filtered);
    out.sort_unstable();
    out.dedup();
    out.into_iter().map(RelId).collect()
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
    expand_with_csr(src, ctx, sink, node, direction, types, None)
}

/// The body of [`expand`], parameterised by an optional **CSR candidate list** (`rmp` task #324,
/// "Win 2"). When `csr_candidates` is `None`, this is exactly the Win-1 path: walk the incidence chain
/// once with [`incident_rels_typed`](StoreReadSource::incident_rels_typed). When it is `Some(ids)` (the
/// caller consulted a *fresh* CSR), the ids are matching-type **candidates** read directly — the engine
/// never touches a non-matching chain link — but each is still re-read with `rel()` and re-checked for
/// type membership and MVCC visibility, so the result is byte-identical to the chain-walk path.
///
/// # Why the candidate path is result- and marker-equivalent (`rmp` #324 constraint 3)
///
/// The CSR is built from the same committed-edge enumeration the chain walk traverses and is consulted
/// **only while fresh** (no relationship mutation since build), so its `(node, wanted_types)` id set is
/// exactly `incident_rels_typed`'s id set. We:
///   * register the **same** rel-type predicate marker (the phantom cover — unchanged);
///   * read each candidate with `rel()` and re-apply the **same** `type_id ∈ wanted_types` filter the
///     storage chain walk applies inline (so a CSR id whose record's type somehow no longer matches is
///     dropped, never reported — a stale id can only be a *superset*, never a wrong row);
///   * SIREAD-mark each **matching** candidate and visibility-filter it, exactly as the chain path
///     marks each edge the storage walk returned.
///
/// A self-loop appears once in the CSR (built deduped), matching the chain walk's single emission.
pub fn expand_with_csr<S: StoreReadSource, K: ReadSink>(
    src: &S,
    ctx: &VisCtx,
    sink: &K,
    node: NodeId,
    direction: ExpandDirection,
    types: &[String],
    csr_candidates: Option<Vec<u64>>,
) -> Vec<Incident> {
    // Relationship-pattern predicate read (`rmp` #171 blocker A1): register the rel-type (or, untyped,
    // `AnyRel`) marker so a concurrent create/delete of a matching type closes an rw-edge — the absent
    // edge the per-rel SIREADs below cannot cover. THIS is what covers the phantom for a matching-type
    // INSERT; it is the reason skipping the per-rel SIREAD of a NON-matching edge (below) is sound.
    note_rel_predicate_read(src, sink, types);
    // Resolve the requested rel-type names to interned ids ONCE per expand (`rmp` #319), so the
    // per-edge filter is an integer compare pushed into the storage chain walk. A requested name with
    // no interned token matches no existing edge (the absent-edge phantom is covered by
    // `note_rel_predicate_read` above), so it contributes no id — and if EVERY requested name is
    // un-interned the resolved set is empty, which the storage layer would treat as "any type"; guard
    // that by short-circuiting to an empty result when types were requested but none resolved.
    let wanted_type_ids: Vec<u32> = types
        .iter()
        .filter_map(|t| src.token_id(Namespace::RelType, t))
        .collect();
    if !types.is_empty() && wanted_type_ids.is_empty() {
        // A typed pattern whose every type name is un-interned matches no existing edge. The phantom
        // for a concurrent first-insert of such a type is already covered by the `AnyRel` predicate
        // marker `note_rel_predicate_read` registered for an un-interned name.
        return Vec::new();
    }
    // The matching incident `(rel_id, record)` list to examine. Two equivalent sources (`rmp` #324):
    //   * "Win 2" (the fast path): a fresh CSR handed us the matching-type candidate ids directly, so
    //     we read each with `rel()` and re-apply the type filter — touching NO non-matching chain link.
    //     `csr_candidates` is `Some` only for a typed expand over a fresh CSR (the caller's gate), so a
    //     stale id can only be a superset (filtered out below), never a missing match (under-coverage,
    //     which the freshness gate forbids).
    //   * "Win 1" (the fallback): walk the incidence chain once with `incident_rels_typed`, reading
    //     each link once and filtering type inline. Used when the CSR is off/stale or the expand is
    //     untyped. An empty `wanted_type_ids` (untyped) returns every incident edge here.
    // Candidate instrumentation (`rmp` #991): on the CSR arm a candidate rejected by the type re-check is
    // a predicate rejection recorded before the chain is even touched; on the chain arm the storage walk
    // has already applied the type filter, so every returned link is a candidate this body examines.
    let mut filtered = 0u64;
    let rels: Vec<(u64, RelRecord)> = match csr_candidates {
        Some(candidate_ids) => {
            // The CSR stores each incident rel-id of a `(node, type)` bucket exactly once (a self-loop
            // is bucketed once at build, matching the chain walk's single emission), and an edge has a
            // single type so it cannot appear under two requested-type buckets of the same node — hence
            // `candidate_ids` is already duplicate-free and no `out.last()`-style dedupe is needed.
            let mut matched: Vec<(u64, RelRecord)> = Vec::with_capacity(candidate_ids.len());
            for rid in candidate_ids {
                let rec = match src.rel(rid) {
                    Ok(rec) => rec,
                    Err(e) => {
                        sink.note_candidates(filtered + matched.len() as u64, 0, filtered);
                        sink.capture(e);
                        return Vec::new();
                    }
                };
                // Re-apply the exact filter the storage chain walk applies inline: a candidate must be
                // an `in_use` slot of a requested type. (`wanted_type_ids` is non-empty here — the
                // caller only supplies CSR candidates for a typed expand.) A stale CSR id can only fail
                // this re-check (a superset id), never silently inject a wrong row.
                if !rec.mvcc.in_use() || !wanted_type_ids.contains(&rec.type_id) {
                    filtered += 1;
                    continue;
                }
                matched.push((rid, rec));
            }
            matched
        }
        None => match src.incident_rels_typed(node.0, &wanted_type_ids) {
            Ok(rels) => rels,
            Err(e) => {
                sink.capture(e);
                return Vec::new();
            }
        },
    };
    let mut out = Vec::new();
    let (mut examined, mut hidden) = (filtered, 0u64);
    for (rid, rec) in rels {
        examined += 1;
        // SIREAD-mark each MATCHING incident relationship the traversal examined (`04 §5.4`). Edges of
        // a non-requested type were never examined (the storage walk filtered them), so they need no
        // per-rel SIREAD: the rel-type predicate marker above already covers any concurrent
        // create/delete of a matching-type edge — the only rw-conflict a typed expand can have.
        sink.note_read(rel_ssi_key(rid));
        // Skip relationships not visible to this snapshot (a concurrently-deleted tombstone an older
        // reader could still traverse, or a later-committed edge). The incidence chain threads them
        // until GC.
        // Statement-granular existence (`rmp` #972), fail-closed on a chain read fault (`rmp` #733):
        // an edge this very statement created is not traversable under `View::Old`.
        match ctx.visible(src, StoreKind::Rel, rid, rec.mvcc) {
            Ok(true) => {}
            Ok(false) => {
                hidden += 1;
                continue;
            }
            Err(e) => {
                sink.note_candidates(examined, hidden, filtered);
                sink.capture(e);
                return Vec::new();
            }
        }
        let touches_as_start = rec.start_node == node.0;
        let touches_as_end = rec.end_node == node.0;
        let want_out = matches!(direction, ExpandDirection::Outgoing | ExpandDirection::Both);
        let want_in = matches!(direction, ExpandDirection::Incoming | ExpandDirection::Both);
        let before = out.len();
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
        if out.len() == before {
            // A visible incident edge the traversal DIRECTION rejected (it only touches the anchor on
            // the side this pattern does not want) — a predicate rejection like any other (`rmp` #991).
            filtered += 1;
        }
    }
    // NOTE the surviving-candidate identity holds on the CANDIDATES, not on the rows: a self-loop under
    // `ExpandDirection::Both` is one surviving candidate that emits **two** incidents.
    sink.note_candidates(examined, hidden, filtered);
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
/// query's snapshot. SIREAD-marks the node (it was examined) before returning visibility.
///
/// # Error handling (`rmp` #359 defence-in-depth)
///
/// A storage `Err` here is **captured**, not silently swallowed into `false`. The node store never
/// unmaps pages (its high-water is monotonic), and no caller in normal Cypher operation passes an id
/// past high-water — every id reaching this body is scan-, traversal-, endpoint-, path- or
/// index-candidate-sourced, hence an *allocated* slot that reads `Ok`. So a real `Err` here is only
/// ever a genuine I/O / buffer-pool fault (or actual record corruption), in which case returning a
/// bare `false` would silently mis-report a present node as absent — a wrong-result ACID
/// read-integrity violation, and the exact way a transient pool error became `Value::Null`. Capturing
/// it routes the fault through the read sink so the executor abandons the result (and, on the parallel
/// morsel path, re-runs serial) rather than trusting a value derived from a swallowed error.
pub fn node_exists<S: StoreReadSource, K: ReadSink>(
    src: &S,
    ctx: &VisCtx,
    sink: &K,
    node: NodeId,
) -> bool {
    let mvcc = match src.node(node.0) {
        Ok(rec) => rec.mvcc,
        Err(e) => {
            sink.capture(e);
            return false;
        }
    };
    sink.note_read(node_ssi_key(node.0));
    // Statement-granular existence (`rmp` #972). A chain read fault is captured and reported as
    // "absent" — the same fail-closed discipline as the record `Err` arm above, and for the same
    // reason: the caller inspects the captured error and abandons the result rather than trusting it.
    match ctx.visible(src, StoreKind::Node, node.0, mvcc) {
        Ok(v) => v,
        Err(e) => {
            sink.capture(e);
            false
        }
    }
}

/// The body of `RecordStoreGraph::rel_exists` (`GraphAccess::rel_exists`). A storage `Err` is
/// **captured**, not swallowed into `false` — identical `rmp` #359 defence-in-depth reasoning as
/// [`node_exists`] (the rel store never unmaps pages; every id reaching here is traversal-sourced and
/// allocated, so a real `Err` is a genuine fault that must not silently read as "no such relationship").
pub fn rel_exists<S: StoreReadSource, K: ReadSink>(
    src: &S,
    ctx: &VisCtx,
    sink: &K,
    rel: RelId,
) -> bool {
    let mvcc = match src.rel(rel.0) {
        Ok(rec) => rec.mvcc,
        Err(e) => {
            sink.capture(e);
            return false;
        }
    };
    sink.note_read(rel_ssi_key(rel.0));
    // Statement-granular existence (`rmp` #972); fail-closed like [`node_exists`].
    match ctx.visible(src, StoreKind::Rel, rel.0, mvcc) {
        Ok(v) => v,
        Err(e) => {
            sink.capture(e);
            false
        }
    }
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
    // Resolve the label word AS OF THIS SNAPSHOT (`rmp` #767), not whatever it holds now.
    let (live, head) = match src.node(node.0) {
        Ok(rec) => (rec.labels, rec.mvcc.undo_ptr),
        Err(e) => {
            sink.capture(e);
            return Some(Vec::new());
        }
    };
    let resolved = match ctx.labels_at(src, node.0, live, head) {
        Ok(b) => b,
        Err(e) => {
            sink.capture(e);
            return Some(Vec::new());
        }
    };
    let ids = match labels::token_ids(resolved) {
        Ok(ids) => ids,
        Err(e) => {
            sink.capture(GraphusError::from(e));
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

/// The body of `RecordStoreGraph::scan_rels_by_type` (`GraphAccess::scan_rels_by_type`, `rmp` task
/// #867): every **visible** relationship whose type is among `types` (empty = any), each id once, in
/// ascending physical-id order — read straight out of the relationship store instead of walking every
/// node's incidence chain.
///
/// # Why this exists
///
/// `MATCH ()-[r:T]->()` lowers to [`AllRelationshipsScan`](crate::physical::PhysicalOp::AllRelationshipsScan),
/// whose only enumeration used to be `scan_nodes` + `expand` **per node**: every node record decoded,
/// every incidence chain chased, to produce a set the relationship store already holds contiguously.
/// This reads the relationship slots once, sequentially.
///
/// # The SSI read footprint is a **superset** of the node-walk's — never a subset
///
/// This is the ACID bar the access path has to clear, and it is a *containment*, not an equality.
/// Deliberately so: a **narrower** footprint would drop rw-edges the previous plan created and could
/// admit an anomaly SSI used to catch, whereas a **wider** one only ever adds rw-edges — it can cost a
/// false abort but can never miss a conflict, so serializability is preserved in the safe direction.
///
/// What is reproduced exactly:
///
/// * [`PredicateRead::AllNodes`] + a SIREAD on **every** slot-occupied node — what
///   [`scan_nodes`] registers, id for id (that scan marks before its own visibility filter, and so does
///   this). The node ids are marked without decoding their records (the answer does not depend on any
///   node's *content*, only on the set the walk would have visited), which is the whole per-node saving.
/// * the relationship-type predicate marker(s) — what [`expand`] registers via the shared
///   `note_rel_predicate_read` helper, covering the concurrently-inserted (absent) edge the per-edge
///   SIREADs cannot.
/// * a SIREAD on every relationship whose type **matches**, registered *before* the visibility filter —
///   mirroring [`expand`], which also marks a matching edge before hiding it. A **non-matching** edge is
///   deliberately *not* marked, again mirroring `expand` (whose storage-side type filter never surfaces
///   it) and the CSR candidate path, whose soundness rests on the type predicate marker above.
///
/// Where the extra markers come from: the node-walk only ever reaches an edge through an endpoint that
/// is **visible** (`scan_nodes` yields visible nodes, and `expand` marks every matching edge incident to
/// one). A matching edge **both** of whose endpoints are invisible — an in-flight writer's freshly
/// created pair, say — is therefore never marked by the walk, while this scan marks it. Neither route
/// *returns* it (both apply the same visibility filter to the answer), so the divergence is confined to
/// the conflict graph, in the over-marking direction.
///
/// # Errors
///
/// A storage fault is captured into `sink` **and** reported as `None`. The `None` is not a "try the
/// other route and carry on" signal: `capture` has already poisoned the statement's error cell, and
/// every caller of this seam checks it — `engine::exec` (`exec.rs:663`, `exec.rs:1296`) and
/// `engine::read_pool` (`read_pool.rs:252`) all fail the statement once `take_error()` is `Some`. So the
/// caller does compute the node-walk fallback, and those rows are then **discarded** along with the
/// statement. That is the intended fail-closed-on-read-fault behaviour (`rmp` #733): a read that
/// faulted must never be answered from a partial set. The `None` exists so that, in the moment before
/// the error surfaces, nothing downstream can mistake a short list for the truth — declining is always
/// safe, `Some(short_vec)` never is (`rmp` #738).
///
/// # The referential invariant this depends on (`rmp` task #891)
///
/// This filters on the **relationship's** MVCC header alone. The node-walk it replaces additionally
/// required the **start node** to be visible, because [`scan_nodes`] returns visible nodes only. The two
/// agree because of a storage invariant: *a live relationship's endpoints are live records* — the
/// referential integrity of relationship endpoints, asserted as rule 3a by the consistency checker
/// (`graphus-storage/src/check.rs:748`, and again at `877-881` where a dangling endpoint is excluded
/// from the incidence-count comparison).
///
/// That invariant is **not enforced by the write path**:
/// [`RecordStore::delete_node`](graphus_storage::RecordStore::delete_node) documents that the caller is
/// expected to have MVCC-deleted the node's relationships first (`DETACH DELETE`) and does not check it.
/// What masks the gap today is the isolation level, not the storage layer: at `Serializable` — which is
/// what every production **write** runs at (`demote_read_to_snapshot` applies only to auto-commit
/// *reads*) — SSI aborts the write-skew that would delete a node while a concurrent transaction attaches
/// an edge to it. Under an explicit `IsolationLevel::Snapshot` transaction both commit, and the two
/// spellings of the same pattern then disagree: with a tombstoned start node and a live edge,
/// `MATCH ()-[r:T]->() RETURN count(r)` is 1 (this scan) while `MATCH (a)-[r:T]->(b) RETURN count(r)` is
/// 0 (the node-walk). `rmp` task #891 closes it by enforcing the invariant in `delete_node`.
///
/// A per-relationship endpoint-visibility check here would restore agreement, and is deliberately **not
/// done**: it costs a node record read per relationship, which is precisely the cost this access path
/// exists to remove (`rmp` task #867).
pub fn scan_rels_typed<S: StoreReadSource, K: ReadSink>(
    src: &S,
    ctx: &VisCtx,
    sink: &K,
    types: &[String],
) -> Option<Vec<crate::graph_access::ScannedRel>> {
    // ---- footprint half 1: what `scan_nodes` would have registered ---------------------------
    sink.note_predicate_read(PredicateRead::AllNodes);
    let node_ids = match src.scan_node_ids() {
        Ok(ids) => ids,
        Err(e) => {
            sink.capture(e);
            return None;
        }
    };
    for id in node_ids {
        sink.note_read(node_ssi_key(id));
    }

    // ---- footprint half 2: what `expand` would have registered -------------------------------
    note_rel_predicate_read(src, sink, types);
    // Resolve the requested type names to interned ids once, exactly as `expand_with_csr` does, so the
    // per-edge test is an integer compare. A requested name with no interned token matches no existing
    // edge; if EVERY requested name is un-interned the answer is empty (the phantom for a concurrent
    // first-insert of such a type is already covered by the `AnyRel` marker registered above).
    let wanted_type_ids: Vec<u32> = types
        .iter()
        .filter_map(|t| src.token_id(Namespace::RelType, t))
        .collect();
    if !types.is_empty() && wanted_type_ids.is_empty() {
        return Some(Vec::new());
    }

    let rel_ids = match src.scan_rel_ids() {
        Ok(ids) => ids,
        Err(e) => {
            sink.capture(e);
            return None;
        }
    };
    let mut out = Vec::new();
    // Candidate instrumentation (`rmp` #991). A reclaimed (`!in_use`) slot and a non-matching type are
    // both predicate rejections here: the record WAS decoded to decide either.
    let (mut examined, mut hidden, mut filtered) = (0u64, 0u64, 0u64);
    for id in rel_ids {
        let rec = match src.rel(id) {
            Ok(rec) => rec,
            Err(e) => {
                sink.note_candidates(examined, hidden, filtered);
                sink.capture(e);
                return None;
            }
        };
        examined += 1;
        // Re-check slot occupancy on the RE-READ record, exactly as `expand_with_csr` re-checks its CSR
        // candidates. `scan_rel_ids` reported the slot occupied, but that was a separate read: this makes
        // the safety **local** instead of derived from three remote invariants. Without it, correctness
        // would rest on (1) a reclaimed slot decoding with `created_ts == 0`, (2) `VersionStamp::None`
        // making `creator_visible` false, and (3) the `rmp` #588 held-slots barrier keeping the slot out
        // of reuse for the duration — all true today, none of them stated here.
        if !rec.mvcc.in_use() {
            filtered += 1;
            continue;
        }
        // An untyped scan wants every occupied slot, a typed one only the matching type. The type test
        // precedes the SIREAD so the marked set matches `expand`'s exactly (see the footprint section).
        if !wanted_type_ids.is_empty() && !wanted_type_ids.contains(&rec.type_id) {
            filtered += 1;
            continue;
        }
        sink.note_read(rel_ssi_key(id));
        // Statement-granular existence (`rmp` #972), fail-closed on a chain read fault (`rmp` #733):
        // this body must return the EXACT visible set — a subset is silent row loss, and answering an
        // unresolvable existence from the header would be exactly such a wrong row.
        match ctx.visible(src, StoreKind::Rel, id, rec.mvcc) {
            // The endpoints come straight out of the record just decoded, so the caller never needs a
            // second `rel_data` read (which would also allocate the type name it does not want).
            Ok(true) => out.push(crate::graph_access::ScannedRel {
                rel: RelId(id),
                start: NodeId(rec.start_node),
                end: NodeId(rec.end_node),
            }),
            Ok(false) => hidden += 1,
            Err(e) => {
                sink.note_candidates(examined, hidden, filtered);
                sink.capture(e);
                return None;
            }
        }
    }
    sink.note_candidates(examined, hidden, filtered);
    Some(out)
}

/// The body of `RecordStoreGraph::rel_data` (`GraphAccess::rel_data`): the relationship's structural
/// fields, or `None` for a missing / invisible relationship. SIREAD-marks the examined edge.
pub fn rel_data<S: StoreReadSource, K: ReadSink>(
    src: &S,
    ctx: &VisCtx,
    sink: &K,
    rel: RelId,
) -> Option<RelData> {
    match rel_candidate(src, ctx, sink, rel) {
        RelCandidate::Visible(data) => Some(data),
        RelCandidate::Hidden | RelCandidate::Faulted => None,
    }
}

/// Why one relationship candidate's re-read did or did not yield data — the discrimination the
/// [`Option`] of [`rel_data`] collapses (`rmp` task #991).
///
/// The relationship index seek bodies need it to tell a candidate **rejected by MVCC visibility** from
/// one rejected by the type/value predicate, which `Option` cannot express. Keeping it as one body that
/// `rel_data` delegates to (rather than a second copy of the read) is what stops the two from drifting.
pub(crate) enum RelCandidate {
    /// The relationship exists and is visible to this snapshot.
    Visible(RelData),
    /// The record decoded, but the version is not visible to this snapshot.
    Hidden,
    /// The record could not be read at all; the fault has been captured, so the statement's result is
    /// already untrustworthy and will be rolled back.
    ///
    /// Every call site aggregates this with [`Hidden`](Self::Hidden) into
    /// [`ReadCounts::rejected_by_visibility`] rather than spending a fourth counter on it: a fault is
    /// strictly neither a visibility nor a predicate decision, but the site **fails closed**, so the
    /// plan carrying the count never reaches a client. The aggregation is stated here and on
    /// [`ReadCounts`] so it is never mistaken for a visibility decision when reading a captured-error
    /// path.
    Faulted,
}

/// The single body behind [`rel_data`]: read the relationship record, SIREAD-mark it, and report
/// **why** it did or did not yield data (see [`RelCandidate`]).
pub(crate) fn rel_candidate<S: StoreReadSource, K: ReadSink>(
    src: &S,
    ctx: &VisCtx,
    sink: &K,
    rel: RelId,
) -> RelCandidate {
    let rec = match src.rel(rel.0) {
        Ok(rec) => rec,
        // A storage `Err` is captured (not swallowed into `None`): every `RelId` reaching here is
        // expand/incidence-sourced and allocated, so a real `Err` is a genuine fault that must not
        // silently read as a missing relationship (`rmp` #359 defence-in-depth).
        Err(e) => {
            sink.capture(e);
            return RelCandidate::Faulted;
        }
    };
    sink.note_read(rel_ssi_key(rel.0));
    // Statement-granular existence (`rmp` #972). A chain read fault is captured and reported as
    // `Faulted`, never as `Hidden` — the caller distinguishes the two, and reporting a fault as a
    // legitimate miss is the swallowed-error shape `rmp` #359 exists to prevent.
    match ctx.visible(src, StoreKind::Rel, rel.0, rec.mvcc) {
        Ok(true) => {}
        Ok(false) => return RelCandidate::Hidden,
        Err(e) => {
            sink.capture(e);
            return RelCandidate::Faulted;
        }
    }
    let rel_type = src
        .token_name(Namespace::RelType, rec.type_id)
        .unwrap_or_default();
    RelCandidate::Visible(RelData {
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
pub fn rel_data_including_deleted<S: StoreReadSource, K: ReadSink>(
    src: &S,
    ctx: &VisCtx,
    sink: &K,
    rel: RelId,
) -> Option<RelData> {
    let rec = match src.rel(rel.0) {
        Ok(rec) => rec,
        // A storage `Err` is captured (not swallowed into `None`): `rel` is a bound, expand-sourced id
        // (allocated slot), so a real `Err` is a genuine fault, not a legitimate not-found
        // (`rmp` #359 defence-in-depth). No SIREAD *read* marker is added (reading our own tombstone
        // records no rw-dependency), but a *fault* must still surface.
        Err(e) => {
            sink.capture(e);
            return None;
        }
    };
    // Visible normally, or a tombstone we wrote ourselves: both keep the type readable. Statement
    // granularity applies to the first half only (`rmp` #972) — the self-tombstone discriminator is a
    // question about our own transaction's stamps, not about which statement wrote them. A chain read
    // fault is captured and yields `None`, never a type read off an unresolved existence.
    let visible = match ctx.visible(src, StoreKind::Rel, rel.0, rec.mvcc) {
        Ok(v) => v,
        Err(e) => {
            sink.capture(e);
            return None;
        }
    };
    if !visible && !ctx.deleted_by_self(rec.mvcc) {
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
pub fn entity_deleted_by_txn<S: StoreReadSource, K: ReadSink>(
    src: &S,
    ctx: &VisCtx,
    sink: &K,
    entity: DeletedEntity,
) -> bool {
    // A storage `Err` on either probe is captured (not swallowed into `false`): the id is the same
    // bound, scan/expand/endpoint-sourced id that already passed `node_exists`/`rel_exists` in this
    // access path (an allocated slot), so a real `Err` is a genuine fault that must surface rather than
    // silently read as "not self-deleted" (`rmp` #359 defence-in-depth). No SIREAD *read* marker (a
    // self-delete check on our own write records no rw-dependency).
    let mvcc = match entity {
        DeletedEntity::Node(id) => match src.node(id.0) {
            Ok(rec) => rec.mvcc,
            Err(e) => {
                sink.capture(e);
                return false;
            }
        },
        DeletedEntity::Rel(id) => match src.rel(id.0) {
            Ok(rec) => rec.mvcc,
            Err(e) => {
                sink.capture(e);
                return false;
            }
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

// =================================================================================================
// Full-text off-thread support (`rmp` task #546)
// =================================================================================================

/// The covered target of one declared (node) full-text index: the covered label tokens, the covered
/// property-key tokens (in declared order), and the analyzer (`rmp` tasks #546, #663). Mirrors the
/// tuple `IndexSet::fulltext_target` returns, but owned + `Send + Sync` so it can be captured into the
/// off-thread [`ReadTaskInputs`](crate::coordinator::ReadTaskInputs). A multi-label index carries every
/// covered label token; a node with **any** of them is a candidate.
#[derive(Debug, Clone)]
pub struct FulltextTarget {
    /// The `Label`-namespace tokens the index covers (one or more, `rmp` #663). A node carrying **any**
    /// of these labels is a candidate.
    pub label_tokens: Vec<u32>,
    /// The covered `PropKey`-namespace tokens, in the index's declared property order.
    pub prop_keys: Vec<u32>,
    /// The analyzer applied at index and query time.
    pub analyzer: Analyzer,
}

/// The covered target of one declared **relationship** full-text index (`rmp` task #663): the covered
/// relationship-type tokens, the covered property-key tokens (in declared order), and the analyzer —
/// the relationship analogue of [`FulltextTarget`], owned + `Send + Sync` for the off-thread read.
#[derive(Debug, Clone)]
pub struct FulltextRelTarget {
    /// The `RelType`-namespace tokens the index covers (one or more). A relationship of **any** covered
    /// type is a candidate.
    pub type_tokens: Vec<u32>,
    /// The covered `PropKey`-namespace tokens, in the index's declared property order.
    pub prop_keys: Vec<u32>,
    /// The analyzer applied at index and query time.
    pub analyzer: Analyzer,
}

/// An owned, `Send + Sync` snapshot of the coordinator's declared full-text indexes (`rmp` tasks #546,
/// #663), keyed by index name — captured on the engine thread and moved into an off-thread read so a
/// `CALL db.index.fulltext.queryNodes(name, …)` / `…queryRelationships(name, …)` resolves the index by
/// name without touching the coordinator's [`IndexSet`](crate::index_set::IndexSet).
///
/// It carries the index **catalogue** (name → covered `(labels/types, props, analyzer)`), **not** the
/// inverted-index postings: the off-thread full-text query recomputes its matches directly from the
/// reader's MVCC snapshot (a snapshot-correct full scan — [`fulltext_scan_fallback`] /
/// [`fulltext_rel_scan_fallback`]), so it never depends on the ephemeral postings and is immune to the
/// cross-snapshot staleness `rmp` #467 guards against. The catalogue is small (one entry per declared
/// index) and usually empty, so capturing it per read is negligible.
#[derive(Debug, Clone, Default)]
pub struct FulltextReadSnapshot {
    targets: HashMap<String, FulltextTarget>,
    rel_targets: HashMap<String, FulltextRelTarget>,
}

impl FulltextReadSnapshot {
    /// Builds a snapshot from `(name, (label_tokens, prop_keys, analyzer))` **node** tuples — exactly
    /// what `IndexSet::fulltext_target` yields per registered node index name (`rmp` tasks #546, #663).
    /// Chain [`with_rel_targets`](Self::with_rel_targets) to add the relationship indexes.
    #[must_use]
    pub fn from_targets(
        entries: impl IntoIterator<Item = (String, (Vec<u32>, Vec<u32>, Analyzer))>,
    ) -> Self {
        Self {
            targets: entries
                .into_iter()
                .map(|(name, (label_tokens, prop_keys, analyzer))| {
                    (
                        name,
                        FulltextTarget {
                            label_tokens,
                            prop_keys,
                            analyzer,
                        },
                    )
                })
                .collect(),
            rel_targets: HashMap::new(),
        }
    }

    /// Adds the **relationship** full-text targets from `(name, (type_tokens, prop_keys, analyzer))`
    /// tuples — exactly what `IndexSet::fulltext_rel_target` yields per registered relationship index
    /// name (`rmp` task #663).
    #[must_use]
    pub fn with_rel_targets(
        mut self,
        entries: impl IntoIterator<Item = (String, (Vec<u32>, Vec<u32>, Analyzer))>,
    ) -> Self {
        self.rel_targets = entries
            .into_iter()
            .map(|(name, (type_tokens, prop_keys, analyzer))| {
                (
                    name,
                    FulltextRelTarget {
                        type_tokens,
                        prop_keys,
                        analyzer,
                    },
                )
            })
            .collect();
        self
    }

    /// The covered target of the **node** full-text index named `name`, or `None` if no such node index
    /// is declared (the caller turns `None` into the "no such full-text index" procedure error —
    /// identical to the inline `IndexSet::fulltext_target(name).is_none()` outcome).
    #[must_use]
    pub fn target(&self, name: &str) -> Option<&FulltextTarget> {
        self.targets.get(name)
    }

    /// The covered target of the **relationship** full-text index named `name`, or `None` if no such
    /// relationship index is declared (`rmp` task #663).
    #[must_use]
    pub fn rel_target(&self, name: &str) -> Option<&FulltextRelTarget> {
        self.rel_targets.get(name)
    }

    /// Whether no full-text index of either flavour is declared (the common case — capture is then
    /// free).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.targets.is_empty() && self.rel_targets.is_empty()
    }
}

/// The **snapshot-correct full-text scan fallback**, lifted over a [`StoreReadSource`] (`rmp` task
/// #546) so an off-thread [`ReadOnlyGraph`](crate::read_only_graph::ReadOnlyGraph) computes the same
/// full-text match set as the live inline path — **without** the coordinator's inverted index.
///
/// It reproduces `RecordStoreGraph::fulltext_scan_fallback` exactly (the `rmp` #467 stale-reader
/// repair path the inline seam already runs when a reader's snapshot predates a full-text mutation),
/// over this reader's captured view:
///
/// 1. **SSI footprint** — [`mark_all_live_nodes`] + the per-candidate [`filter_label_candidates`]
///    markers, byte-identical to the inline fast path (whose `mark_all_live_nodes` already dominates
///    its candidate-only markers, so both routes' *deduped* marker sets are `{all live node keys}`).
/// 2. **Match rule** — for each snapshot-visible node carrying the covered label, the covered STRING
///    properties are read at this snapshot ([`node_property`], MVCC-correct) and analyzed in the
///    index's declared property order with the index's analyzer; the node matches under `Or` iff its
///    analyzed term set shares at least one term with the analyzed `search` term set (an empty search
///    or an empty document matches nothing).
///
/// The result equals what the inline fast index path returns on a current snapshot (the inverted
/// index is built by analyzing the same covered properties with the same analyzer), so the off-thread
/// and inline full-text queries are byte-identical (results **and** SIREAD markers).
pub fn fulltext_scan_fallback<S: StoreReadSource, K: ReadSink>(
    src: &S,
    ctx: &VisCtx,
    sink: &K,
    target: &FulltextTarget,
    search: &str,
) -> Vec<NodeId> {
    // SSI: mark every live node, exactly as the inline fast path does (`04 §5.4`).
    mark_all_live_nodes(src, sink);

    // Enumerate every live node id, then narrow to snapshot-visible nodes carrying the covered label
    // via the SAME shared re-check the inline path uses — registering the per-candidate SIREAD markers
    // identically.
    let all_ids = match src.scan_node_ids() {
        Ok(ids) => ids,
        Err(e) => {
            sink.capture(e);
            return Vec::new();
        }
    };
    // Multi-label (`rmp` #663): a node carrying **any** covered label is a candidate.
    let labelled = filter_any_label_candidates(src, ctx, sink, &target.label_tokens, all_ids);

    // Resolve the covered prop-key tokens to names once. A token without a name was never interned and
    // cannot occur on any node, so it is skipped (contributes no terms).
    let prop_names: Vec<String> = target
        .prop_keys
        .iter()
        .filter_map(|pk| src.token_name(Namespace::PropKey, *pk))
        .collect();

    // The analyzed search terms (the query side). An empty set matches nothing.
    let search_terms: BTreeSet<String> = target.analyzer.analyze(search).into_iter().collect();
    if search_terms.is_empty() {
        return Vec::new();
    }

    let mut out: Vec<NodeId> = Vec::new();
    // The term residual's own rejections (`rmp` #991): the candidates were already counted by
    // `filter_any_label_candidates`, so only the extra rejections are added here.
    let mut filtered = 0u64;
    for node in labelled {
        let mut matched = false;
        'props: for name in &prop_names {
            // Read at THIS snapshot via MVCC `node_property`, so the value is this reader's visible
            // value (and the read is SIREAD-marked, subsumed by `mark_all_live_nodes` above).
            let Some(Value::String(text)) = node_property(src, ctx, sink, node, name) else {
                continue;
            };
            for term in target.analyzer.analyze(&text) {
                if search_terms.contains(&term) {
                    matched = true;
                    break 'props;
                }
            }
        }
        if matched {
            out.push(node);
        } else {
            filtered += 1;
        }
    }
    sink.note_candidates(0, 0, filtered);
    out.sort_unstable();
    out.dedup();
    out
}

/// The **full-text scoring rule**, in one place (`rmp` task #733): the best-effort relevance of a
/// document — the covered STRING property values `doc_texts`, in the index's declared property order —
/// against `search`, both analyzed with the index's `analyzer`.
///
/// It mirrors `InvertedIndex::score` exactly: the count of **distinct** analyzed `search` terms that
/// appear among the document's terms. Extracted so that **every** score path — the off-thread
/// [`fulltext_score_recompute`] / [`fulltext_rel_score_recompute`] and the inline
/// `RecordStoreGraph::fulltext_score` / `fulltext_score_rel` degraded paths — shares one
/// implementation, instead of each re-deriving the rule (and drifting from it). The caller supplies the
/// document's texts however it reads them (MVCC `node_property` off-thread, MVCC `node_property` inline),
/// which is the only part that differs.
#[must_use]
pub fn fulltext_score_of_document(
    analyzer: Analyzer,
    doc_texts: impl IntoIterator<Item = String>,
    search: &str,
) -> u64 {
    // The document's term set: analyze each covered STRING value with the index's analyzer.
    let mut doc_terms: BTreeSet<String> = BTreeSet::new();
    for text in doc_texts {
        doc_terms.extend(analyzer.analyze(&text));
    }
    // Count each DISTINCT query term at most once, and only if the document has it (the
    // `InvertedIndex::score` contract).
    let mut seen: BTreeSet<String> = BTreeSet::new();
    let mut score = 0u64;
    for term in analyzer.analyze(search) {
        if seen.insert(term.clone()) && doc_terms.contains(&term) {
            score += 1;
        }
    }
    score
}

/// The off-thread twin of `IndexSet::fulltext_score` (`rmp` task #546): the best-effort relevance of
/// `node` for `search` under `target`, recomputed from the node's snapshot-visible covered properties
/// instead of the inverted index's forward map.
///
/// Applies the shared [`fulltext_score_of_document`] rule to the node's document terms (the union of
/// its covered STRING properties, read at this snapshot in declared order). On a current snapshot this
/// equals the inline index score exactly (both analyze the same covered properties with the same
/// analyzer). The node's read is SIREAD-marked (the marker is subsumed by the preceding
/// [`fulltext_scan_fallback`]'s `mark_all_live_nodes`, so the merged conflict graph is unchanged).
#[must_use]
pub fn fulltext_score_recompute<S: StoreReadSource, K: ReadSink>(
    src: &S,
    ctx: &VisCtx,
    sink: &K,
    target: &FulltextTarget,
    node: NodeId,
    search: &str,
) -> u64 {
    let doc_texts = target.prop_keys.iter().filter_map(|pk| {
        let name = src.token_name(Namespace::PropKey, *pk)?;
        match node_property(src, ctx, sink, node, &name) {
            Some(Value::String(text)) => Some(text),
            _ => None,
        }
    });
    fulltext_score_of_document(target.analyzer, doc_texts, search)
}

/// The **snapshot-correct relationship full-text scan fallback**, lifted over a [`StoreReadSource`]
/// (`rmp` task #663) so an off-thread [`ReadOnlyGraph`](crate::read_only_graph::ReadOnlyGraph) computes
/// the same relationship full-text match set as the inline store-backed path — the relationship
/// analogue of [`fulltext_scan_fallback`]. It marks every live relationship (the blanket SSI footprint
/// the inline `rel_index_seek_eq` / relationship full-text path uses), then keeps each snapshot-visible
/// relationship of a covered type whose covered STRING text shares at least one analyzed term with the
/// analyzed `search` (the `Or` rule of [`InvertedIndex::query`](graphus_index::fulltext::InvertedIndex)).
pub fn fulltext_rel_scan_fallback<S: StoreReadSource, K: ReadSink>(
    src: &S,
    ctx: &VisCtx,
    sink: &K,
    target: &FulltextRelTarget,
    search: &str,
) -> Vec<RelId> {
    // SSI: mark every live relationship (blanket footprint), then examine each candidate via `rel_data`
    // (which SIREAD-marks it), exactly as the inline path does.
    let all_ids = match src.scan_rel_ids() {
        Ok(ids) => ids,
        Err(e) => {
            sink.capture(e);
            return Vec::new();
        }
    };
    for id in &all_ids {
        sink.note_read(rel_ssi_key(*id));
    }

    // Resolve the covered type + property names once (a never-interned token cannot occur on any rel).
    let type_names: BTreeSet<String> = target
        .type_tokens
        .iter()
        .filter_map(|tt| src.token_name(Namespace::RelType, *tt))
        .collect();
    let prop_names: Vec<String> = target
        .prop_keys
        .iter()
        .filter_map(|pk| src.token_name(Namespace::PropKey, *pk))
        .collect();

    let search_terms: BTreeSet<String> = target.analyzer.analyze(search).into_iter().collect();
    if search_terms.is_empty() {
        return Vec::new();
    }

    let mut out: Vec<RelId> = Vec::new();
    // Candidate instrumentation (`rmp` #991) — `rel_candidate` separates a hidden version from a
    // type/term mismatch, which the `Option` of `rel_data` cannot.
    let (mut examined, mut hidden, mut filtered) = (0u64, 0u64, 0u64);
    for id in all_ids {
        let rel = RelId(id);
        examined += 1;
        // Visible + of a covered type? A hidden version yields no data at all.
        let RelCandidate::Visible(data) = rel_candidate(src, ctx, sink, rel) else {
            hidden += 1;
            continue;
        };
        if !type_names.contains(&data.rel_type) {
            filtered += 1;
            continue;
        }
        let mut matched = false;
        'props: for name in &prop_names {
            let Some(Value::String(text)) = rel_property(src, ctx, sink, rel, name) else {
                continue;
            };
            for term in target.analyzer.analyze(&text) {
                if search_terms.contains(&term) {
                    matched = true;
                    break 'props;
                }
            }
        }
        if matched {
            out.push(rel);
        } else {
            filtered += 1;
        }
    }
    sink.note_candidates(examined, hidden, filtered);
    out.sort_unstable();
    out.dedup();
    out
}

/// The off-thread twin of `IndexSet::fulltext_rel_score` (`rmp` task #663): the best-effort relevance
/// of relationship `rel` for `search` under `target`, recomputed from the relationship's
/// snapshot-visible covered properties — the relationship analogue of [`fulltext_score_recompute`],
/// applying the same shared [`fulltext_score_of_document`] rule.
#[must_use]
pub fn fulltext_rel_score_recompute<S: StoreReadSource, K: ReadSink>(
    src: &S,
    ctx: &VisCtx,
    sink: &K,
    target: &FulltextRelTarget,
    rel: RelId,
    search: &str,
) -> u64 {
    let doc_texts = target.prop_keys.iter().filter_map(|pk| {
        let name = src.token_name(Namespace::PropKey, *pk)?;
        match rel_property(src, ctx, sink, rel, &name) {
            Some(Value::String(text)) => Some(text),
            _ => None,
        }
    });
    fulltext_score_of_document(target.analyzer, doc_texts, search)
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
    // Candidate instrumentation (`rmp` #991): every incidence-chain link is a candidate this body reads
    // and visibility-filters.
    let (mut examined, mut hidden) = (0u64, 0u64);
    let out: Vec<RelId> = ids
        .into_iter()
        .filter(|&rid| {
            let mvcc = match src.rel(rid) {
                Ok(rec) => rec.mvcc,
                Err(e) => {
                    sink.capture(e);
                    return false;
                }
            };
            examined += 1;
            sink.note_read(rel_ssi_key(rid));
            // Statement-granular existence (`rmp` #972). A chain read fault is captured and the edge
            // dropped, matching the record-read arm above: the caller inspects the captured error and
            // abandons the result rather than acting on a partially-read incidence list.
            let visible = match ctx.visible(src, StoreKind::Rel, rid, mvcc) {
                Ok(v) => v,
                Err(e) => {
                    sink.capture(e);
                    return false;
                }
            };
            if !visible {
                hidden += 1;
            }
            visible
        })
        .map(RelId)
        .collect();
    sink.note_candidates(examined, hidden, 0);
    out
}

// --------------------------------- read-only property helpers ---------------------------------

/// The body of `RecordStoreGraph::read_node_prop_one` (`rmp` #326 late materialization): the value
/// `key`'s interned id holds **as of this query's snapshot**, decoding exactly one value. A
/// never-interned key short-circuits to `None`.
///
/// POLARITY — DECISION (`rmp` #967). It used to walk the prepend-ordered chain and keep the first
/// record `is_visible` accepted, which worked only while every version of a key was a cell with its
/// own MVCC stamps. After #967 the newest version is written **in place** and the old value lives on
/// the entity's undo chain, so the version is selected by the chain walk
/// ([`StoreReadSource::decision_scan_node_properties`]) — the same body the off-thread reader pool
/// runs, which is what keeps the two paths from answering from different mechanisms
/// (`rmp` #755/#768/#769/#770).
///
/// The walk also **stops early**: it descends only as far as the first delta this snapshot already
/// reflects, so the common "no history to undo" case costs one chain read and no delta reads at all.
fn read_node_prop_one<S: StoreReadSource, K: ReadSink>(
    src: &S,
    ctx: &VisCtx,
    sink: &K,
    node: NodeId,
    key: &str,
) -> Option<Value> {
    let key_id = src.token_id(Namespace::PropKey, key)?;
    let decided = match src.decision_scan_node_properties(node.0, ctx.snapshot) {
        Ok(decided) => decided,
        Err(e) => {
            sink.capture(e);
            return None;
        }
    };
    let prop = decided.visible_version(key_id)?;
    match src.decode_property_value(prop.type_tag, prop.value_inline) {
        Ok(value) => Some(value),
        Err(e) => {
            sink.capture(e);
            None
        }
    }
}

/// The relationship analogue of [`read_node_prop_one`] (the body of
/// `RecordStoreGraph::read_rel_prop_one`), with the same decision polarity.
fn read_rel_prop_one<S: StoreReadSource, K: ReadSink>(
    src: &S,
    ctx: &VisCtx,
    sink: &K,
    rel: RelId,
    key: &str,
) -> Option<Value> {
    let key_id = src.token_id(Namespace::PropKey, key)?;
    let decided = match src.decision_scan_rel_properties(rel.0, ctx.snapshot) {
        Ok(decided) => decided,
        Err(e) => {
            sink.capture(e);
            return None;
        }
    };
    let prop = decided.visible_version(key_id)?;
    match src.decode_property_value(prop.type_tag, prop.value_inline) {
        Ok(value) => Some(value),
        Err(e) => {
            sink.capture(e);
            None
        }
    }
}

/// The body of `RecordStoreGraph::read_node_props` (`rmp` task #50): `node`'s properties as
/// `(name, value)` pairs **as of this query's snapshot**, name-mapped and sorted by name.
///
/// POLARITY — DECISION (`rmp` #967), for the reason given on [`read_node_prop_one`].
fn read_node_props<S: StoreReadSource, K: ReadSink>(
    src: &S,
    ctx: &VisCtx,
    sink: &K,
    node: NodeId,
) -> Vec<(String, Value)> {
    let decided = match src.decision_scan_node_properties(node.0, ctx.snapshot) {
        Ok(decided) => decided,
        Err(e) => {
            sink.capture(e);
            return Vec::new();
        }
    };
    let out = match decode_decided_props(src, sink, &decided) {
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
    let decided = match src.decision_scan_rel_properties(rel.0, ctx.snapshot) {
        Ok(decided) => decided,
        Err(e) => {
            sink.capture(e);
            return Vec::new();
        }
    };
    let out = match decode_decided_props(src, sink, &decided) {
        Some(out) => out,
        None => return Vec::new(),
    };
    name_and_sort_props(src, out)
}

/// Decodes every key an already-narrowed [`DecidedProperties`] holds (factored out of
/// `read_node_props` / `read_rel_props`, which are byte-identical apart from the read).
///
/// The snapshot fold that used to live here — "skip versions invisible to this snapshot and a key id
/// already resolved to a newer visible version" — moved into the storage-side chain walk in `rmp`
/// #967, where it is the shared `DecisionFold` both the eager `SupersetProperties::decide` and the
/// early-stopping `read_view` walk apply. So this is now decode-only, and the narrowing can no longer
/// be skipped by construction: [`DecidedProperties`] has no constructor that does not take a
/// [`Snapshot`].
///
/// Returns `None` if a decode hit a captured fault (the caller then yields an empty result, exactly as
/// the originals did).
fn decode_decided_props<S: StoreReadSource, K: ReadSink>(
    src: &S,
    sink: &K,
    decided: &DecidedProperties,
) -> Option<Vec<(u32, Value)>> {
    let mut out: Vec<(u32, Value)> = Vec::with_capacity(decided.len());
    for prop in decided.visible_versions() {
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
