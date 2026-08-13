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
//! a live shared handle to the `RecordStore`. It does **not** duplicate the visibility heart: every read delegates to
//! the single lifted body in [`crate::read_source`] (the same body `RecordStoreGraph`'s read methods now
//! call), parameterised here over a [`ReadViewSource`] and this graph's own marker/error sink. That is
//! what guarantees the off-thread reader produces byte-identical results — including which SIREAD
//! markers / rw-edges form — to the live path (the Slice 3b-i equivalence test is the guard).
//!
//! # `Send`, not `Sync`
//!
//! Construction captures the view, token snapshot, read snapshot, and a fresh
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
use graphus_storage::{Namespace, StoreReadView, TokenSnapshot};
use graphus_txn::{PredicateRead, Snapshot, SsiReadBuffer, View};
use graphus_wal::LogSink;

use crate::graph_access::{
    CompositeSeekHits, DeletedEntity, ExpandDirection, GraphAccess, Incident, IndexSeekHits,
    KeyValues, NodeId, RelData, RelId, ScanFilter, ScannedRel,
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
    /// This reader's MVCC read snapshot (`04 §5.3`): every read is filtered through `is_visible_via` against
    /// each record's frozen `xmin`/`xmax`, so the reader sees a consistent point-in-time graph.
    snapshot: Snapshot,
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
    /// The declared full-text index catalogue captured on the engine thread (`rmp` task #546), so an
    /// off-thread `CALL db.index.fulltext.queryNodes(name, …)` resolves the index by name and
    /// recomputes matches from this reader's snapshot. Empty (the [`new`](Self::new) default) unless a
    /// full-text-capable read supplies it via [`with_fulltext`](Self::with_fulltext) — the morsel
    /// readers (`rmp` #339) never call procedures, so they keep the free empty catalogue.
    fulltext: read_source::FulltextReadSnapshot,
    /// The engine-thread-captured memo of node-property equality seek results (`rmp` task #755, Slice
    /// S2), letting this reader serve `index_seek_eq` as a real seek instead of declining to a full
    /// scan. Empty (the [`new`](Self::new) default) unless supplied via
    /// [`with_index_candidates`](Self::with_index_candidates); an empty capture simply declines, which
    /// is the pre-#755 behaviour (correct, just unaccelerated).
    index_candidates: read_source::IndexCandidateCapture,
    /// The engine-thread-captured memo of **count-store answers** (`rmp` task #866), letting this
    /// reader answer an ungrouped `count()` over a bare scan from a counter instead of reading every
    /// record. Empty (the [`new`](Self::new) default) unless supplied via
    /// [`with_count_store`](Self::with_count_store); an empty capture simply declines to the
    /// `Aggregation`-over-scan subtree, which is the reference path.
    ///
    /// The memo carries values only — the equivalence predicate that authorised them was proven on the
    /// engine thread at capture time, because this thread can neither evaluate it nor keep it true.
    count_store: read_source::CountStoreCapture,
    /// The measured cost of this reader's **candidate + re-verification** work (`rmp` task #991) —
    /// candidates examined, candidates rejected by MVCC visibility, candidates rejected by the access
    /// path's own predicate re-check, and SIREAD markers emitted.
    ///
    /// The off-thread twin of `RecordStoreGraph::tally`, and for the same reason a `Cell` accumulator
    /// rather than an atomic: this reader is `!Sync` (it appends markers through `RefCell`) and is
    /// owned by exactly one reader-pool thread for its whole life. Drained by the profiling decorator
    /// through [`take_read_tally`](GraphAccess::take_read_tally) after each seam call.
    tally: read_source::ReadTally,
}

impl<D: BlockDevice, S: LogSink> ReadOnlyGraph<D, S> {
    /// Builds an off-thread read-only graph from the engine-thread-captured pieces (`rmp` task #336,
    /// Slice 3b-i): the store read `view`, the `tokens` snapshot, this reader's read `snapshot`, the
    /// `txn` id, and a **fresh, empty** [`SsiReadBuffer`] for `txn` to accumulate SIREAD markers into.
    ///
    /// It takes **no commit registry** since `rmp` #1069 phase 3. It used to carry a clone of the
    /// in-memory table, because that was the only thing that could translate an unsettled record stamp
    /// into a commit outcome, and the clone had to be captured on the engine thread. A stamp now names
    /// a slot in `commit.store`, which this reader's own `view` reads — so the answer is durable, is
    /// resolved by the same mechanism the inline path uses, and needs nothing captured at dispatch.
    ///
    /// All arguments are captured on the engine thread under the reader's pinned snapshot; the resulting
    /// graph is then `Send` and may be moved to a reader thread (Slice 3b-ii). The `buffer` must be
    /// empty and tagged with `txn` (the markers this reader records are replayed under `txn`).
    pub fn new(
        view: StoreReadView<D, S>,
        tokens: TokenSnapshot,
        snapshot: Snapshot,
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
            txn,
            buffer: RefCell::new(Some(buffer)),
            error: RefCell::new(None),
            fulltext: read_source::FulltextReadSnapshot::default(),
            index_candidates: read_source::IndexCandidateCapture::default(),
            count_store: read_source::CountStoreCapture::default(),
            tally: read_source::ReadTally::new(),
        }
    }

    /// Attaches the captured full-text index catalogue (`rmp` task #546), enabling this reader to serve
    /// `CALL db.index.fulltext.queryNodes(name, …)` off-thread. A builder so [`new`](Self::new) keeps
    /// its (churn-free) signature and the morsel readers, which never call procedures, keep the free
    /// empty catalogue. Consumes and returns `self` for chaining at the dispatch site.
    pub fn with_fulltext(mut self, fulltext: read_source::FulltextReadSnapshot) -> Self {
        self.fulltext = fulltext;
        self
    }

    /// Attaches the captured node-property equality seek results (`rmp` task #755, Slice S2), enabling
    /// this reader to serve [`index_seek_eq`](crate::graph_access::GraphAccess::index_seek_eq) as a real
    /// seek. A builder for the same reasons as [`with_fulltext`](Self::with_fulltext): [`new`](Self::new)
    /// keeps its signature, and the morsel readers (`rmp` #339), which never seek an index, keep the free
    /// empty capture. Consumes and returns `self` for chaining at the dispatch site.
    pub fn with_index_candidates(mut self, candidates: read_source::IndexCandidateCapture) -> Self {
        self.index_candidates = candidates;
        self
    }

    /// Attaches the captured count-store answers (`rmp` task #866), enabling this reader to serve
    /// [`count_store_nodes`](crate::graph_access::GraphAccess::count_store_nodes) /
    /// [`count_store_rels`](crate::graph_access::GraphAccess::count_store_rels). A builder for the same
    /// reasons as [`with_index_candidates`](Self::with_index_candidates). Consumes and returns `self`
    /// for chaining at the dispatch site.
    pub fn with_count_store(mut self, counts: read_source::CountStoreCapture) -> Self {
        self.count_store = counts;
        self
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

    /// This reader's visibility context (snapshot + txn) for the lifted read body.
    ///
    /// It carries no commit oracle: since `rmp` #1069 phase 3 a header stamp is resolved by the
    /// SOURCE — the view's own `commit.store` — which the lifted body already holds.
    #[inline]
    fn ctx(&self) -> VisCtx {
        VisCtx {
            snapshot: self.snapshot,
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
        // Counted at the point of emission (`rmp` #991), exactly as the live seam counts it.
        self.tally.note_read_marker();
        if let Some(buf) = self.buffer.borrow_mut().as_mut() {
            buf.record_read(key);
        }
    }

    fn note_predicate_read(&self, predicate: PredicateRead) {
        self.tally.note_predicate_marker();
        if let Some(buf) = self.buffer.borrow_mut().as_mut() {
            buf.record_predicate_read(predicate);
        }
    }

    fn capture(&self, err: GraphusError) {
        self.capture_err(err);
    }

    fn note_candidates(
        &self,
        examined: u64,
        rejected_by_visibility: u64,
        rejected_by_predicate: u64,
    ) {
        self.tally
            .note_candidates(examined, rejected_by_visibility, rejected_by_predicate);
    }
}

// `Send + Sync + 'static` on `D, S` (mirroring `RecordStoreGraph`'s `GraphAccess` impl): the
// `rmp` #575-g.1 `frontier_morsel_source` boxes a `MorselView<D, S>` into a `Box<dyn MorselSource>`
// (`Send + Sync`), which needs the store types to be `Send + Sync`. The off-thread reader path already
// requires this (the whole `ReadOnlyGraph` is moved to a worker thread), so it is no real restriction.
impl<D: BlockDevice + Send + Sync + 'static, S: LogSink + Send + Sync + 'static> GraphAccess
    for ReadOnlyGraph<D, S>
{
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

    fn count_store_nodes(&self, label: Option<&str>) -> Option<u64> {
        // A pure memo lookup (`rmp` task #866). Everything that makes answering *sound* — the
        // equivalence predicate, the counter read, the atomicity between them — happened on the engine
        // thread at dispatch; this thread only reports what was frozen there.
        //
        // A MISS declines, and must: returning `Some(0)` for an uncaptured count would report an empty
        // graph, which is the scalar face of the `rmp` #680/#738 "never `Some(empty)`" rule. The capture
        // is deliberately empty whenever the predicate failed, so "not equivalent" and "not asked for"
        // arrive here as the same, safe answer.
        self.count_store.nodes(label)
    }

    fn count_store_rels(&self, types: &[String]) -> Option<u64> {
        // See `count_store_nodes` above (`rmp` task #866).
        self.count_store.rels(types)
    }

    fn scan_filter_eq(&self, label: &str, property: &str, value: &Value) -> ScanFilter {
        // The precise equality-filtered scan (`rmp` task #325): the same lifted body the live store runs,
        // so an off-thread morsel reader registers the identical precise `Equality` + per-match SIREAD
        // footprint (never the blanket `mark_all_live_nodes`) — serializability unchanged, abort storm
        // gone. This stays the exact fallback whenever the seek below declines.
        read_source::scan_filter_eq(&self.source(), &self.ctx(), self, label, property, value)
    }

    fn index_seek_eq(
        &self,
        label: &str,
        property: &str,
        seek: &Value,
        carry: KeyValues,
    ) -> Option<IndexSeekHits> {
        // `rmp` task #755, Slice S2 — the fix for "the planner picks the index, the plan REPORTS
        // `NodeIndexSeek`, and the runtime reads the whole store". This reader holds no `IndexSet` (its
        // `BTree`s are `&mut self` throughout, so even a `Send + Sync` one would be unusable behind
        // `&self`), so the *candidates* come from the memo the engine thread captured at dispatch.
        //
        // Resolve the tokens through this reader's own captured dictionary — the same dictionary the
        // capture's tokens were resolved from, so they agree by construction.
        let label_token = self.tokens.token_id(Namespace::Label, label)?;
        let prop_key = self.tokens.token_id(Namespace::PropKey, property)?;

        // A MISS — not captured, wrong value, a gate refused it (non-`Online` / degraded / unindexable)
        // — MUST decline so the executor takes the exact `scan_filter_eq` fallback. Returning
        // `Some(vec![])` here would read as "no rows" and silently drop them (`rmp` #680/#738). Declining
        // is always safe: it is precisely the pre-#755 behaviour.
        let candidates = self.index_candidates.get(label_token, prop_key, seek)?;

        // Everything past the candidate list is the SAME lifted body the live inline seam runs
        // (`rmp` #755, Slice S1): the precise `Equality` predicate marker, the per-candidate SIREAD +
        // fail-closed visibility/label re-check, the current-value residual, the dedup. The engine
        // contributed raw ids and no semantics whatsoever, so this seek's rows and SSI footprint are
        // identical to the inline seek's — not by review, but because it is the same code.
        Some(read_source::index_seek_eq_recheck(
            &self.source(),
            &self.ctx(),
            self,
            label_token,
            prop_key,
            property,
            seek,
            candidates.to_vec(),
            carry,
        ))
    }

    fn index_seek_range(
        &self,
        label: &str,
        property: &str,
        lower: Option<(&Value, bool)>,
        upper: Option<(&Value, bool)>,
        carry: KeyValues,
    ) -> Option<IndexSeekHits> {
        // `rmp` task #768 — the range twin of `index_seek_eq` above. The reader holds no `IndexSet`, so
        // the range candidates come from the memo the engine thread captured at dispatch, keyed by the
        // same `(lower, upper)` the executor formed. A MISS (not captured, a `List` bound, a gate
        // refused it) MUST decline so the executor takes the exact `scan_filter_range` fallback — never
        // `Some(vec![])`, which would silently drop rows (`rmp` #680/#738).
        let label_token = self.tokens.token_id(Namespace::Label, label)?;
        let prop_key = self.tokens.token_id(Namespace::PropKey, property)?;
        let candidates = self
            .index_candidates
            .get_range(label_token, prop_key, lower, upper)?;

        // The SAME lifted body the inline seam runs (`rmp` #768): the `Label` predicate marker + the
        // blanket `mark_all_live_nodes` + the per-candidate visibility/label re-check + the
        // `satisfies_range` residual + the dedup — so rows and SSI footprint match the inline seek by
        // construction.
        Some(read_source::index_seek_range_recheck(
            &self.source(),
            &self.ctx(),
            self,
            label_token,
            property,
            lower,
            upper,
            candidates.to_vec(),
            carry,
        ))
    }

    fn index_seek_composite_eq(
        &self,
        label: &str,
        properties: &[String],
        values: &[Value],
        carry: KeyValues,
    ) -> Option<CompositeSeekHits> {
        // `rmp` task #768 — the composite twin. Resolve the label + every property key to a token (a
        // missing token cannot match any composite index, so decline), then consult the memo keyed by
        // the full ordered property-token tuple. A MISS MUST decline to the exact
        // `scan_filter_composite_eq` fallback (`rmp` #680/#738).
        let label_token = self.tokens.token_id(Namespace::Label, label)?;
        let property_tokens: Option<Vec<u32>> = properties
            .iter()
            .map(|p| self.tokens.token_id(Namespace::PropKey, p))
            .collect();
        let property_tokens = property_tokens?;
        let candidates =
            self.index_candidates
                .get_composite(label_token, &property_tokens, values)?;

        // The SAME lifted body the inline seam runs: the `Label` marker + `mark_all_live_nodes` + the
        // per-candidate label re-check + the element-wise tuple equality residual + the dedup.
        Some(read_source::index_seek_composite_recheck(
            &self.source(),
            &self.ctx(),
            self,
            label_token,
            properties,
            values,
            candidates.to_vec(),
            carry,
        ))
    }

    fn index_seek_text(
        &self,
        label: &str,
        property: &str,
        op: crate::physical::TextSeekOp,
        needle: &str,
    ) -> Option<Vec<NodeId>> {
        // `rmp` task #768 — the trigram-text twin. The candidates come from the memo keyed by
        // `(label, property, op, needle)`; a MISS (not captured, needle too short, a gate refused it)
        // MUST decline so the executor takes the exact label-scan fallback and the residual
        // `CONTAINS`/`ENDS WITH`/`STARTS WITH` filter above restores exactness (`rmp` #680/#738).
        let label_token = self.tokens.token_id(Namespace::Label, label)?;
        let prop_key = self.tokens.token_id(Namespace::PropKey, property)?;
        let candidates = self
            .index_candidates
            .get_text(label_token, prop_key, op, needle)?;

        // The SAME lifted body the inline seam runs: the blanket `mark_all_live_nodes` + the
        // per-candidate visibility/label re-check + the dedup (no predicate residual — the executor keeps
        // the exact string filter above this operator). Rows and SSI footprint match the inline text seek
        // by construction.
        Some(read_source::index_seek_text_recheck(
            &self.source(),
            &self.ctx(),
            self,
            label_token,
            candidates.to_vec(),
        ))
    }

    fn index_seek_rel_eq(
        &self,
        rel_type: &str,
        property: &str,
        value: &Value,
    ) -> Option<Vec<RelId>> {
        // `rmp` task #769 — the relationship twin of `index_seek_eq`. The candidates come from the memo
        // keyed by `(type, property, value)`; a MISS MUST decline so the executor takes the exact typed
        // relationship scan — never `Some(vec![])`, which on the rel-property trees is not only silent
        // row loss but a UNIQUE bypass (`rmp` #680/#738/#683).
        let type_token = self.tokens.token_id(Namespace::RelType, rel_type)?;
        let prop_key = self.tokens.token_id(Namespace::PropKey, property)?;
        let candidates = self
            .index_candidates
            .get_rel_eq(type_token, prop_key, value)?;

        // On a HIT, register the SAME footprint the inline seek does — the precise `RelEquality` predicate
        // marker (registered by the seam, NOT inside the lifted body: the rel scan fallback registers no
        // such marker, so it must stay in each seam, `rmp` #683) — then run the SAME lifted per-candidate
        // re-check both seams share (rows + per-candidate SIREAD identical by construction).
        read_source::note_rel_equality_read(self, type_token, prop_key, value);
        Some(read_source::rel_index_seek_eq_recheck(
            &self.source(),
            &self.ctx(),
            self,
            rel_type,
            property,
            value,
            candidates.to_vec(),
        ))
    }

    fn index_seek_rel_range(
        &self,
        rel_type: &str,
        property: &str,
        lower: Option<(&Value, bool)>,
        upper: Option<(&Value, bool)>,
    ) -> Option<Vec<RelId>> {
        // `rmp` task #769/#680 — gives the `RelIndexRangeSeek` a production read path. A MISS declines to
        // the exact typed-scan + range filter (`rmp` #680/#738).
        let type_token = self.tokens.token_id(Namespace::RelType, rel_type)?;
        let prop_key = self.tokens.token_id(Namespace::PropKey, property)?;
        let candidates = self
            .index_candidates
            .get_rel_range(type_token, prop_key, lower, upper)?;

        // On a HIT, register the SAME footprint the inline range seek does — the coarse `RelType` marker +
        // the blanket `mark_all_live_rels` (a range predicate has no precise equality marker) — then run
        // the SAME lifted per-candidate re-check.
        self.note_predicate_read(PredicateRead::RelType(type_token));
        read_source::mark_all_live_rels(&self.source(), self);
        Some(read_source::rel_index_seek_range_recheck(
            &self.source(),
            &self.ctx(),
            self,
            rel_type,
            property,
            lower,
            upper,
            candidates.to_vec(),
        ))
    }

    fn index_seek_rel_composite_eq(
        &self,
        rel_type: &str,
        properties: &[String],
        values: &[Value],
    ) -> Option<Vec<RelId>> {
        // `rmp` task #769/#666 — the relationship composite twin. A MISS declines to the exact typed scan
        // + per-key equality (`rmp` #680/#738).
        let type_token = self.tokens.token_id(Namespace::RelType, rel_type)?;
        let property_tokens: Option<Vec<u32>> = properties
            .iter()
            .map(|p| self.tokens.token_id(Namespace::PropKey, p))
            .collect();
        let property_tokens = property_tokens?;
        let candidates =
            self.index_candidates
                .get_rel_composite(type_token, &property_tokens, values)?;

        // On a HIT, register the SAME footprint the inline composite seek does (`RelType` + blanket
        // `mark_all_live_rels`), then run the SAME lifted per-candidate tuple re-check.
        self.note_predicate_read(PredicateRead::RelType(type_token));
        read_source::mark_all_live_rels(&self.source(), self);
        Some(read_source::rel_index_seek_composite_recheck(
            &self.source(),
            &self.ctx(),
            self,
            rel_type,
            properties,
            values,
            candidates.to_vec(),
        ))
    }

    fn index_seek_spatial(
        &self,
        label: &str,
        property: &str,
        center_x: f64,
        center_y: f64,
        radius: f64,
    ) -> Option<Vec<NodeId>> {
        // `rmp` task #770 — the SPATIAL (point) twin of the seeks above. Unlike VECTOR (whose ANN probe is
        // a run-time vector the reader cannot pre-capture, so `db.index.vector.*` stays inline by dispatch
        // rule), the centre + radius are plan-time-folded `f64` constants, so the grid candidate superset
        // was memoised at dispatch, keyed on the same constants the executor passes. A MISS (not captured,
        // a since-dropped/`Populating` grid, a stale reader past the ft/spatial marker) MUST decline so the
        // executor takes the exact `scan_nodes_by_label` + residual `distance(...) <op> r` filter — never
        // `Some(vec![])`, which would silently drop rows (`rmp` #680/#738).
        let label_token = self.tokens.token_id(Namespace::Label, label)?;
        let prop_key = self.tokens.token_id(Namespace::PropKey, property)?;
        let candidates =
            self.index_candidates
                .get_spatial(label_token, prop_key, center_x, center_y, radius)?;

        // The SAME lifted body the inline seam runs (`rmp` #770): the blanket `mark_all_live_nodes` + the
        // per-candidate visibility/label re-check + the dedup, with NO predicate residual (the executor
        // keeps the exact `distance` filter above). Spatial shares the text-family narrowing, so this rides
        // `index_seek_text_recheck` — rows + SSI footprint identical to the inline spatial seek by
        // construction.
        Some(read_source::index_seek_spatial_recheck(
            &self.source(),
            &self.ctx(),
            self,
            label_token,
            candidates.to_vec(),
        ))
    }

    fn index_seek_spatial_rel(
        &self,
        rel_type: &str,
        property: &str,
        center_x: f64,
        center_y: f64,
        radius: f64,
    ) -> Option<Vec<RelId>> {
        // `rmp` task #770/#664 — the relationship spatial twin. A MISS declines to the exact typed
        // relationship scan + residual `distance` filter (`rmp` #680/#738).
        let type_token = self.tokens.token_id(Namespace::RelType, rel_type)?;
        let prop_key = self.tokens.token_id(Namespace::PropKey, property)?;
        let candidates = self
            .index_candidates
            .get_rel_spatial(type_token, prop_key, center_x, center_y, radius)?;

        // The SAME lifted body the inline seam runs: the blanket `mark_all_live_rels` (INSIDE the body,
        // since a spatial seek has no `List`/rebuild pre-decline marker to preserve — unlike the rel
        // eq/range/composite seams, `rmp` #683) + the per-candidate visibility/type re-check + the dedup,
        // with NO `distance` residual (the executor keeps it above). Rows + SSI footprint identical to the
        // inline rel spatial seek by construction.
        Some(read_source::rel_index_seek_spatial_recheck(
            &self.source(),
            &self.ctx(),
            self,
            rel_type,
            candidates.to_vec(),
        ))
    }

    fn expand(&self, node: NodeId, direction: ExpandDirection, types: &[String]) -> Vec<Incident> {
        read_source::expand(&self.source(), &self.ctx(), self, node, direction, types)
    }

    fn scan_rels_by_type(&self, types: &[String]) -> Option<Vec<ScannedRel>> {
        // Served off-thread from this reader's own MVCC read view (`rmp` task #867), not from any
        // coordinator-side structure: it is a plain relationship-store scan, so there is nothing to
        // pre-capture at dispatch and nothing that could go stale. The SAME lifted body the inline seam
        // runs, so the rows AND the SIREAD markers this reader accumulates are byte-identical to the
        // INLINE seam's — the off-thread parity `rmp` #768 makes mandatory for every access path.
        //
        // (Byte-identical to the inline *scan*, which is a different claim from the scan-vs-node-walk
        // relation: against the node-walk this access path's footprint is a superset, never a subset —
        // see `read_source::scan_rels_typed`.)
        read_source::scan_rels_typed(&self.source(), &self.ctx(), self, types)
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

    // The property-index and spatial seeks above are SERVED off-thread from the dispatch-time memo
    // (`rmp` #755/#768/#769 property seeks + #770 spatial) — a MISS declines to the exact scan, never
    // `Some(empty)`. The remaining accelerators DECLINE on the reader (their derived structures live in
    // the coordinator, not in this owned read view): `columnar_label_property_scan` / `morsel_label_scan`
    // fall to the `GraphAccess` default (`None`), so the executor uses the ordinary Volcano scan / row
    // read — always correct, and its "candidate set" is the whole column, so pre-capturing it at dispatch
    // would move the bulk read back onto the engine thread, defeating off-thread dispatch (`rmp` #770
    // verdict; #352 measured a full-column projection ~1.8x SLOWER than serial). VECTOR seeks are never
    // reached here: `db.index.vector.*` is registered NOT reader-safe, so an ANN read stays inline by
    // dispatch rule (its query vector is a run-time value, not a plan constant, `rmp` #770). `statistics()`
    // likewise defaults to `None` (cost-based planning happens on the engine thread before dispatch, which
    // also keeps the morsel/parallel tiers — gated on `statistics()` — from being attempted off-thread).

    // Full-text is the exception (`rmp` task #546): unlike a declined *index seek* (which the executor
    // turns into a correct scan), a declined `fulltext_query` surfaces as a hard "no such index"
    // procedure error — so a `CALL db.index.fulltext.queryNodes` could not run off-thread at all. We
    // serve it from the captured catalogue (`with_fulltext`) via the snapshot-correct full-text scan
    // fallback: it recomputes the match set + score directly from this reader's MVCC snapshot (never
    // the coordinator's inverted-index postings), so the result + SIREAD markers are byte-identical to
    // the inline fast path (whose `mark_all_live_nodes` dominates its candidate-only markers) AND immune
    // to the cross-snapshot staleness `rmp` #467 guards against. An index the catalogue does not know
    // yields `None`, exactly as the inline `IndexSet::fulltext_target(name).is_none()` path does.

    fn fulltext_query(&self, name: &str, search: &str) -> Option<Vec<NodeId>> {
        let target = self.fulltext.target(name)?;
        Some(read_source::fulltext_scan_fallback(
            &self.source(),
            &self.ctx(),
            self,
            target,
            search,
        ))
    }

    fn fulltext_score(&self, name: &str, node: NodeId, search: &str) -> Option<u64> {
        let target = self.fulltext.target(name)?;
        Some(read_source::fulltext_score_recompute(
            &self.source(),
            &self.ctx(),
            self,
            target,
            node,
            search,
        ))
    }

    // Relationship full-text (`rmp` task #663): served off-thread from the captured catalogue via the
    // snapshot-correct relationship scan fallback, byte-identical to the inline store-backed path (never
    // the coordinator's inverted-index postings). A name the catalogue does not know yields
    // `None`, exactly as the inline `IndexSet::fulltext_rel_target(name).is_none()` path does.
    fn fulltext_query_rel(&self, name: &str, search: &str) -> Option<Vec<RelId>> {
        let target = self.fulltext.rel_target(name)?;
        Some(read_source::fulltext_rel_scan_fallback(
            &self.source(),
            &self.ctx(),
            self,
            target,
            search,
        ))
    }

    fn fulltext_score_rel(&self, name: &str, rel: RelId, search: &str) -> Option<u64> {
        let target = self.fulltext.rel_target(name)?;
        Some(read_source::fulltext_rel_score_recompute(
            &self.source(),
            &self.ctx(),
            self,
            target,
            rel,
            search,
        ))
    }

    /// The covered property names of the node full-text index `name` (`rmp` task #826), resolved from
    /// the captured catalogue + token snapshot — the off-thread twin of `RecordStoreGraph`'s impl, so
    /// the `AuthorizedGraph` decorator's property-read gate composes identically whether a restricted
    /// principal's full-text query runs inline or on the reader pool. `None` for an unknown index,
    /// exactly as `fulltext_query` signals it.
    fn fulltext_covered_properties(&self, name: &str) -> Option<Vec<String>> {
        let target = self.fulltext.target(name)?;
        Some(
            target
                .prop_keys
                .iter()
                .filter_map(|&pk| {
                    self.tokens
                        .token_name(Namespace::PropKey, pk)
                        .map(str::to_owned)
                })
                .collect(),
        )
    }

    /// The relationship analogue of
    /// [`fulltext_covered_properties`](Self::fulltext_covered_properties) (`rmp` task #826).
    fn fulltext_rel_covered_properties(&self, name: &str) -> Option<Vec<String>> {
        let target = self.fulltext.rel_target(name)?;
        Some(
            target
                .prop_keys
                .iter()
                .filter_map(|&pk| {
                    self.tokens
                        .token_name(Namespace::PropKey, pk)
                        .map(str::to_owned)
                })
                .collect(),
        )
    }

    // ---- morsel intra-query parallelism (off-thread, `rmp` task #575-g.1) ---------------------------

    fn frontier_morsel_source(&self) -> Option<crate::morsel::MorselFrontierSource> {
        // `rmp` task #575-g.1: let the off-thread reader engage the `rmp` #575 **frontier** morsel tier
        // (the heavy `r3_fof3` recommendation shape). Before this, `ReadOnlyGraph` used the trait default
        // (`None`), so — even with the `rmp` #575-g.1 adaptive morsel width in force on the reader worker —
        // the tier declined here and a lone heavy read still ran on ONE reader thread; the `rmp` #575 win
        // never reached the live server.
        //
        // An off-thread reader IS a **coordinated** read: it accumulates SIREAD markers into its own
        // buffer, which the engine merges into the shared `SsiTracker` at retirement (M1) — so, unlike a
        // standalone/historical read (no shared tracker), it may hand off the frontier source. It captures
        // exactly the pieces `RecordStoreGraph::frontier_morsel_source` does: the owned, `Send`,
        // cheap-cloneable read surface (a `StoreReadView` + `TokenSnapshot` clone — `Arc` bumps, no page
        // copy) plus this reader's snapshot + commit-registry clone + txn. No index is needed (the frontier
        // anchors come from the earlier sub-plan the executor drains serially, through THIS graph, so its
        // anchor-set markers land in this reader's buffer) and no coarse predicate is registered here
        // (mirroring the inline seam). A captured error makes the result untrustworthy, so decline and let
        // the serial fallback re-run + surface it.
        if self.has_error() {
            return None;
        }
        let source: Box<dyn crate::morsel::MorselSource> = Box::new(
            crate::morsel::MorselView::new(self.view.clone(), self.tokens.clone()),
        );
        Some(crate::morsel::MorselFrontierSource {
            source,
            snapshot: self.snapshot,
            txn: self.txn,
        })
    }

    fn take_read_tally(&self) -> read_source::ReadCounts {
        // `rmp` #991: what this reader's candidate re-verification measured since the last drain. The
        // off-thread twin of `RecordStoreGraph::take_read_tally`; a profiled statement drains through
        // whichever of the two actually ran, so the counters do not depend on the dispatch route.
        self.tally.take()
    }

    fn merge_morsel_buffer(&self, buffer: graphus_txn::SsiReadBuffer) {
        // Convergence (`rmp` task #575-g.1): fold a morsel's accumulated SIREAD markers into THIS reader's
        // own buffer. A reader thread holds no shared `SsiTracker` (that lives only on the engine thread),
        // so — unlike `RecordStoreGraph::merge_morsel_buffer`, which folds straight into the tracker — the
        // reader absorbs every morsel's markers into its buffer and the whole buffer is merged into the
        // tracker once, at retirement (M1). `SsiTracker::merge_read_buffer` sorts + dedups + replays, so
        // the resulting conflict graph is the UNION of the morsels' markers — byte-identical rw-edges to
        // both the serial scan and the inline morsel path. The morsel buffers are tagged with this
        // reader's txn (the frontier source captured `self.txn`), so `absorb`'s reader-match holds.
        //
        // If the buffer was already taken (retirement in progress, buffer moved out via `take_buffer`),
        // there is nothing to fold into — but that only happens AFTER the statement finished streaming, so
        // a mid-statement morsel convergence always finds the buffer present.
        if let Some(buf) = self.buffer.borrow_mut().as_mut() {
            buf.absorb(buffer);
        }
    }

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

    // ---- statement-level isolation (`04 §5.1.4`, `rmp` #972) -------------------------------------

    fn read_view(&self) -> View {
        self.snapshot.view
    }

    fn set_read_view(&mut self, view: View) -> View {
        // Implemented for real, even though this reader can observe no difference today: the polarity
        // must reach the lifted read bodies identically on both paths, because a reader pool that
        // resolves visibility by a different mechanism than the inline path is the `rmp`
        // #755/#768/#769/#770 defect family. Threading it through the snapshot is all it takes — every
        // off-thread read already carries `self.snapshot` down to `read_source`.
        std::mem::replace(&mut self.snapshot.view, view)
    }

    fn begin_command(&mut self) {
        // Deliberately a NO-OP, and it is the only correct behaviour here.
        //
        // The statement counter belongs to the *writing* transaction and is advanced by mutating the
        // `RecordStore`'s active-transaction entry. This seam is a frozen, owned read view captured on
        // the engine thread: it holds no store handle to advance, it never writes a delta that could
        // carry a new command id, and it serves exactly one auto-commit read statement — so there is no
        // second statement for the counter to separate. Advancing anything here would either be a lie
        // (a local counter no delta is stamped with) or a data race (reaching back into the engine's
        // store from a reader thread).
    }
}

// `rmp` #336, Slice 3b-i: `ReadOnlyGraph<D, S>` must be `Send` (moved to one reader thread) and `!Sync`
// (owned by that one reader, never shared). A compile-time assertion (no runtime body): it fails to
// build the instant a non-`Send` field is introduced. The owned fields are all `Send + Sync`
// (`StoreReadView` / `TokenSnapshot` from Slice 3a, `Snapshot` `Copy`, `TxnId` plain
// data) except the interior-mutability cells — the two `RefCell<…>` and the `rmp` #991 `ReadTally`'s
// `Cell<u64>`s — which are `Send` (their contents are) and `!Sync`: exactly the bound we want. Asserted both for the concrete DST instantiation and generically
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
