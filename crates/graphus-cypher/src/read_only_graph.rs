//! An owned, `Send`, off-thread read-only [`GraphAccess`] over a
//! [`StoreReadView`] (`rmp` task #336, Slice 3b-i — the off-thread-read
//! enabler).
//!
//! # What this is
//!
//! [`ReadOnlyGraph`] runs the **same** Cypher read logic — MVCC visibility, id/token mapping, the SIREAD
//! markers that make reads serializable — as the live
//! [`RecordStoreGraph`](crate::record_graph::RecordStoreGraph), but sourcing store data from an owned,
//! `Send + Sync` [`StoreReadView`] + [`TokenSnapshot`] instead of an
//! `Rc<RefCell<RecordStore>>`. It does **not** duplicate the visibility heart: every read delegates to
//! the single lifted body in [`crate::read_source`] (the same body `RecordStoreGraph`'s read methods now
//! call), parameterised here over a [`ReadViewSource`] and this graph's own marker/error sink. That is
//! what guarantees the off-thread reader produces byte-identical results — including which SIREAD
//! markers / rw-edges form — to the live path (the Slice 3b-i equivalence test is the guard).
//!
//! # `Send`, not `Sync`
//!
//! Construction captures the view, token snapshot, read snapshot, a cloned commit registry, and a fresh
//! owned [`SsiReadBuffer`] — all on the engine thread under the reader's pinned snapshot — and the whole
//! graph is then **moved** to one reader thread, which mutates it (the buffer, the captured-error cell)
//! through `&self` via [`RefCell`]. `RefCell<T: Send>` is `Send` but `!Sync`, which is exactly right: the
//! graph is owned by one reader and never shared between threads. The compile-time assertion at the end
//! of this file fails the instant a non-`Send` field is introduced (mirroring
//! [`StoreReadView`]'s own `Send + Sync` assertion).
//!
//! # Reads vs writes (Fork 2 of the Slice 3b plan)
//!
//! [`ReadOnlyGraph`] implements the **full** [`GraphAccess`] trait (it is not split into read/write
//! supertraits — `run_cursor`, the operators, [`AuthorizedGraph`](crate::authorized_graph::AuthorizedGraph)
//! and [`MemGraph`](crate::graph_access::MemGraph) are all bound on `&mut dyn GraphAccess`, so splitting
//! would have a huge blast radius for zero gain). The **write** methods are statically unreachable on the
//! reader path — the engine rejects a write in a `Read`-mode transaction before it ever reaches an
//! operator — so each write **captures a degrade error** (`Internal("write reached the read-only reader
//! path")`) and returns a benign default. A captured error makes the result untrustworthy and aborts the
//! statement, so even if reached it can never corrupt anything. The optional index / columnar /
//! statistics seams decline (`None`): a first-cut reader uses scan-fallback for everything.
//!
//! Slice 3b-i is **single-threaded and behaviour-preserving**: this graph is constructed and exercised
//! **only** by the equivalence test. Slice 3b-ii turns on the reader pool, dispatch and retirement that
//! actually run it off-thread.

use std::cell::RefCell;

use graphus_core::error::GraphusError;
use graphus_core::{TxnId, Value};
use graphus_io::BlockDevice;
use graphus_storage::{StoreReadView, TokenSnapshot};
use graphus_txn::{CommitRegistry, PredicateRead, Snapshot, SsiReadBuffer};
use graphus_wal::LogSink;

use crate::graph_access::{
    DeletedEntity, ExpandDirection, GraphAccess, Incident, NodeId, RelData, RelId,
};
use crate::read_source::{self, ReadSink, ReadViewSource, VisCtx};

/// An owned, `Send` (`!Sync`) read-only [`GraphAccess`] over a captured store read view, scoped to one
/// transaction's read snapshot (`rmp` task #336, Slice 3b-i). See the module docs.
///
/// Generic over the block device `D` and WAL log sink `S` exactly like the
/// [`StoreReadView`] it reads through, so it runs over the production
/// file device + file log and over the in-memory DST device + log.
#[must_use]
pub struct ReadOnlyGraph<D: BlockDevice, S: LogSink> {
    /// The owned, `Send + Sync` decode surface (`Arc<pool>` + `MetaSnapshot`), captured on the engine
    /// thread (`rmp` task #336, Slice 3a).
    view: StoreReadView<D, S>,
    /// The owned, `Send + Sync` token dictionary (`id ↔ name`), captured alongside the view.
    tokens: TokenSnapshot,
    /// This reader's MVCC read snapshot (`04 §5.3`): every read is filtered through `is_visible` against
    /// each record's frozen `xmin`/`xmax`, so the reader sees a consistent point-in-time graph.
    snapshot: Snapshot,
    /// The cloned commit registry that resolves an in-flight writer to its commit outcome, captured at
    /// dispatch (a writer committing later is excluded by the `ts` filter regardless).
    registry: CommitRegistry,
    /// The transaction this read runs in.
    txn: TxnId,
    /// The reader's **owned** SIREAD-marker buffer (`rmp` #341 + #336): every read appends its markers
    /// here (never to a shared `SsiTracker` — a reader thread holds no shared lock). The coordinator
    /// takes it back at retirement ([`take_buffer`](Self::take_buffer)) and merges it on the engine
    /// thread (Slice 3b-ii). `RefCell` because the read seams append through `&self`; `Option` so it can
    /// be moved out at retirement.
    buffer: RefCell<Option<SsiReadBuffer>>,
    /// The first storage / deferred-feature error a read hit, if any. While set, the result is
    /// untrustworthy and the statement should be rolled back. `RefCell` because reads capture through
    /// `&self` (mirrors `RecordStoreGraph::error`).
    error: RefCell<Option<GraphusError>>,
}

impl<D: BlockDevice, S: LogSink> ReadOnlyGraph<D, S> {
    /// Builds an off-thread read-only graph from the engine-thread-captured pieces (`rmp` task #336,
    /// Slice 3b-i): the store read `view`, the `tokens` snapshot, this reader's read `snapshot`, a clone
    /// of the commit `registry`, the `txn` id, and a **fresh, empty** [`SsiReadBuffer`] for `txn` to
    /// accumulate SIREAD markers into.
    ///
    /// All arguments are captured on the engine thread under the reader's pinned snapshot; the resulting
    /// graph is then `Send` and may be moved to a reader thread (Slice 3b-ii). The `buffer` must be
    /// empty and tagged with `txn` (the markers this reader records are replayed under `txn`).
    pub fn new(
        view: StoreReadView<D, S>,
        tokens: TokenSnapshot,
        snapshot: Snapshot,
        registry: CommitRegistry,
        txn: TxnId,
        buffer: SsiReadBuffer,
    ) -> Self {
        debug_assert_eq!(
            buffer.reader(),
            txn,
            "ReadOnlyGraph buffer must be tagged with the reader txn"
        );
        debug_assert!(
            buffer.is_empty(),
            "ReadOnlyGraph must start with an empty SIREAD buffer"
        );
        Self {
            view,
            tokens,
            snapshot,
            registry,
            txn,
            buffer: RefCell::new(Some(buffer)),
            error: RefCell::new(None),
        }
    }

    /// The transaction id this read runs in.
    #[must_use]
    pub fn txn(&self) -> TxnId {
        self.txn
    }

    /// Takes the first captured storage / deferred-feature error, leaving the cell empty.
    ///
    /// Returns `Some(err)` if any read hit an error — in which case the result is **not** trustworthy and
    /// the caller should roll the transaction back. Mirrors
    /// [`RecordStoreGraph::take_error`](crate::record_graph::RecordStoreGraph::take_error).
    #[must_use]
    pub fn take_error(&self) -> Option<GraphusError> {
        self.error.borrow_mut().take()
    }

    /// Whether a storage / deferred-feature error has been captured (non-consuming peek).
    #[must_use]
    pub fn has_error(&self) -> bool {
        self.error.borrow().is_some()
    }

    /// Moves the reader's accumulated SIREAD-marker buffer out, for the coordinator to merge into the
    /// shared [`SsiTracker`](graphus_txn::SsiTracker) on the engine thread at retirement (`rmp` task
    /// #336, Slice 3b-ii). After this the graph holds no buffer, so further reads would record no
    /// markers (the reader is being retired). Returns a fresh empty buffer for `txn` if already taken,
    /// so the caller always gets a mergeable buffer exactly once. The returned [`SsiReadBuffer`] is
    /// itself `#[must_use]` — it must be merged or it loses the reader's markers.
    pub fn take_buffer(&self) -> SsiReadBuffer {
        self.buffer
            .borrow_mut()
            .take()
            .unwrap_or_else(|| SsiReadBuffer::new(self.txn))
    }

    /// This reader's visibility context (snapshot + registry + txn) for the lifted read body.
    #[inline]
    fn ctx(&self) -> VisCtx<'_> {
        VisCtx {
            snapshot: self.snapshot,
            registry: &self.registry,
            txn: self.txn,
        }
    }

    /// This reader's [`StoreReadSource`](crate::read_source::StoreReadSource) over the owned view +
    /// token snapshot.
    #[inline]
    fn source(&self) -> ReadViewSource<'_, D, S> {
        ReadViewSource {
            view: &self.view,
            tokens: &self.tokens,
        }
    }

    /// Filters the candidate id list `ids` to the nodes that **currently** carry `label_token` and are
    /// **visible** to this reader's snapshot, recording the per-candidate SIREAD markers into this
    /// reader's own buffer (`rmp` task #339, Slice 3b — the morsel scan→filter→project primitive).
    ///
    /// This is the lifted [`read_source::filter_label_candidates`] over this reader's own
    /// [`ReadViewSource`] + buffer/error sink, i.e. the **same** candidate filter the serial
    /// `scan_nodes_by_label` index arm applies over the same ids — so a morsel's survivor set + markers
    /// over a contiguous candidate slice match the serial path exactly. The coarse
    /// `PredicateRead::Label` + all-live-nodes footprint is registered once on the **engine** thread (by
    /// `morsel_label_scan`), never here, so taking this path does not double-register it.
    pub fn filter_label_candidates(&self, label_token: u32, ids: Vec<u64>) -> Vec<NodeId> {
        read_source::filter_label_candidates(&self.source(), &self.ctx(), self, label_token, ids)
    }

    /// Captures `err` as the first read error (a later error never overwrites the first). Shared by the
    /// [`ReadSink`] impl and the write-degrade paths.
    fn capture_err(&self, err: GraphusError) {
        let mut slot = self.error.borrow_mut();
        if slot.is_none() {
            *slot = Some(err);
        }
    }

    /// Records the write-degrade error and returns: a write reached the read-only reader path, which is
    /// statically unreachable (the engine rejects writes in a `Read`-mode transaction before any
    /// operator runs). The captured error makes the statement untrustworthy, so even if reached it can
    /// never corrupt anything — it is a transaction-layer invariant breach, surfaced as
    /// [`GraphusError::Transaction`] so the caller rolls back.
    #[cold]
    fn degrade_write(&self) {
        self.capture_err(GraphusError::Transaction(
            "write reached the read-only reader path".to_owned(),
        ));
    }
}

/// The reader appends its SIREAD markers to its **own** buffer and captures errors into its **own** cell
/// (`rmp` task #336, Slice 3b-i) — no shared `SsiTracker`, no shared lock (a reader thread holds
/// neither). The coordinator merges the buffer on the engine thread at retirement.
impl<D: BlockDevice, S: LogSink> ReadSink for ReadOnlyGraph<D, S> {
    fn note_read(&self, key: u64) {
        if let Some(buf) = self.buffer.borrow_mut().as_mut() {
            buf.record_read(key);
        }
    }

    fn note_predicate_read(&self, predicate: PredicateRead) {
        if let Some(buf) = self.buffer.borrow_mut().as_mut() {
            buf.record_predicate_read(predicate);
        }
    }

    fn capture(&self, err: GraphusError) {
        self.capture_err(err);
    }
}

impl<D: BlockDevice, S: LogSink> GraphAccess for ReadOnlyGraph<D, S> {
    // ---- reads: the single lifted body over this reader's ReadViewSource ----------------------

    fn scan_nodes(&self) -> Vec<NodeId> {
        read_source::scan_nodes(&self.source(), &self.ctx(), self)
    }

    fn scan_nodes_by_label(&self, label: &str) -> Vec<NodeId> {
        // The reader holds no derived index, so it always takes the scan-fallback arm (which the lifted
        // body implements) — registering the identical `Label`/`AllNodes` + per-candidate SIREAD markers
        // the live index arm registers, so serializability is unchanged.
        read_source::scan_nodes_by_label(&self.source(), &self.ctx(), self, label)
    }

    fn scan_filter_eq(&self, label: &str, property: &str, value: &Value) -> Vec<NodeId> {
        // The precise equality-filtered scan (`rmp` task #325): the same lifted body the live store runs,
        // so an off-thread morsel reader registers the identical precise `Equality` + per-match SIREAD
        // footprint (never the blanket `mark_all_live_nodes`) — serializability unchanged, abort storm
        // gone. The reader holds no derived index, so the lifted body is the only path.
        read_source::scan_filter_eq(&self.source(), &self.ctx(), self, label, property, value)
    }

    fn expand(&self, node: NodeId, direction: ExpandDirection, types: &[String]) -> Vec<Incident> {
        read_source::expand(&self.source(), &self.ctx(), self, node, direction, types)
    }

    fn node_exists(&self, node: NodeId) -> bool {
        read_source::node_exists(&self.source(), &self.ctx(), self, node)
    }

    fn rel_exists(&self, rel: RelId) -> bool {
        read_source::rel_exists(&self.source(), &self.ctx(), self, rel)
    }

    fn node_labels(&self, node: NodeId) -> Option<Vec<String>> {
        read_source::node_labels(&self.source(), &self.ctx(), self, node)
    }

    fn rel_data(&self, rel: RelId) -> Option<RelData> {
        read_source::rel_data(&self.source(), &self.ctx(), self, rel)
    }

    fn rel_data_including_deleted(&self, rel: RelId) -> Option<RelData> {
        // No SIREAD *read* marker (reading our own tombstone has no rw-dependency), but the sink is
        // passed so a storage *fault* is captured, not swallowed into `None` (`rmp` #359 defence-in-depth).
        read_source::rel_data_including_deleted(&self.source(), &self.ctx(), self, rel)
    }

    fn entity_deleted_by_txn(&self, entity: DeletedEntity) -> bool {
        // Sink passed so a storage *fault* on the probe is captured, not swallowed into `false`
        // (`rmp` #359 defence-in-depth); no SIREAD read marker (self-delete check records no rw-dep).
        read_source::entity_deleted_by_txn(&self.source(), &self.ctx(), self, entity)
    }

    fn node_property(&self, node: NodeId, key: &str) -> Option<Value> {
        read_source::node_property(&self.source(), &self.ctx(), self, node, key)
    }

    fn rel_property(&self, rel: RelId, key: &str) -> Option<Value> {
        read_source::rel_property(&self.source(), &self.ctx(), self, rel, key)
    }

    fn node_properties(&self, node: NodeId) -> Option<Vec<(String, Value)>> {
        read_source::node_properties(&self.source(), &self.ctx(), self, node)
    }

    fn rel_properties(&self, rel: RelId) -> Option<Vec<(String, Value)>> {
        read_source::rel_properties(&self.source(), &self.ctx(), self, rel)
    }

    fn incident_rels(&self, node: NodeId) -> Vec<RelId> {
        read_source::incident_rels(&self.source(), &self.ctx(), self, node)
    }

    // The optional index / full-text / spatial / columnar seams all DECLINE on the reader (first-cut
    // scan-fallback): the derived accelerators live in the coordinator, not in this owned read view. The
    // executor then uses the ordinary Volcano scan, which the reads above answer correctly. Each falls
    // back to the `GraphAccess` default (`None`), so they are deliberately not overridden here.
    //
    // `statistics()` likewise defaults to `None`: the reader does not carry the durable statistics
    // catalogue (cost-based planning happens on the engine thread before dispatch).

    // ---- writes: statically unreachable on the reader path → capture-degrade ------------------

    fn create_node(&mut self, _labels: &[String], _properties: &[(String, Value)]) -> NodeId {
        self.degrade_write();
        NodeId(0)
    }

    fn create_rel(
        &mut self,
        _rel_type: &str,
        _start: NodeId,
        _end: NodeId,
        _properties: &[(String, Value)],
    ) -> RelId {
        self.degrade_write();
        RelId(0)
    }

    fn set_node_property(&mut self, _node: NodeId, _key: &str, _value: Value) {
        self.degrade_write();
    }

    fn set_rel_property(&mut self, _rel: RelId, _key: &str, _value: Value) {
        self.degrade_write();
    }

    fn add_labels(&mut self, _node: NodeId, _labels: &[String]) {
        self.degrade_write();
    }

    fn remove_labels(&mut self, _node: NodeId, _labels: &[String]) {
        self.degrade_write();
    }

    fn remove_node_property(&mut self, _node: NodeId, _key: &str) {
        self.degrade_write();
    }

    fn remove_rel_property(&mut self, _rel: RelId, _key: &str) {
        self.degrade_write();
    }

    fn replace_node_properties(&mut self, _node: NodeId, _properties: &[(String, Value)]) {
        self.degrade_write();
    }

    fn merge_node_properties(&mut self, _node: NodeId, _properties: &[(String, Value)]) {
        self.degrade_write();
    }

    fn replace_rel_properties(&mut self, _rel: RelId, _properties: &[(String, Value)]) {
        self.degrade_write();
    }

    fn merge_rel_properties(&mut self, _rel: RelId, _properties: &[(String, Value)]) {
        self.degrade_write();
    }

    fn delete_rel(&mut self, _rel: RelId) {
        self.degrade_write();
    }

    fn delete_node(&mut self, _node: NodeId) {
        self.degrade_write();
    }
}

// `rmp` #336, Slice 3b-i: `ReadOnlyGraph<D, S>` must be `Send` (moved to one reader thread) and `!Sync`
// (owned by that one reader, never shared). A compile-time assertion (no runtime body): it fails to
// build the instant a non-`Send` field is introduced. The owned fields are all `Send + Sync`
// (`StoreReadView` / `TokenSnapshot` from Slice 3a, `Snapshot` `Copy`, `CommitRegistry`/`TxnId` plain
// data) except the two `RefCell<…>` interior-mutability cells, which are `Send` (their contents are) and
// `!Sync` — exactly the bound we want. Asserted both for the concrete DST instantiation and generically
// over the `D, S: Send + Sync` bound the view's own `Send + Sync` requires.
const _: () = {
    fn assert_send<T: Send>() {}
    fn assert_read_only_graph() {
        assert_send::<ReadOnlyGraph<graphus_io::MemBlockDevice, graphus_wal::MemLogSink>>();
        fn assert_generic<D: BlockDevice + Send + Sync, S: LogSink + Send + Sync>() {
            fn inner<T: Send>() {}
            inner::<ReadOnlyGraph<D, S>>();
        }
        assert_generic::<graphus_io::MemBlockDevice, graphus_wal::MemLogSink>();
    }
    let _ = assert_read_only_graph;
};
