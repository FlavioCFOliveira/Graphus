//! **`PROFILE` runtime instrumentation** — the measured per-operator `rows` and `dbHits` a profiled
//! statement reports (`rmp` task #752).
//!
//! This module is the *measurement* half of the `EXPLAIN` / `PROFILE` feature; the *rendering* half is
//! [`crate::plan_description`]. It exists so that a client can confirm — empirically, over the wire —
//! **which access path actually ran**: a query that silently regresses from an index seek to a full scan
//! shows it both in the operator type and in an exploded `dbHits` count.
//!
//! # What `dbHits` means here (read this before trusting a number)
//!
//! Neo4j documents a *DbHit* as "an abstract unit of storage-engine work", and its exact accounting is
//! an internal implementation detail of that engine. Graphus therefore does **not** claim to reproduce
//! Neo4j's numbers. It reports its own, precisely-defined, **measured** quantity:
//!
//! > **A `dbHit` is one record obtained from the storage seam** ([`GraphAccess`]) **by that operator.**
//!
//! Concretely, every [`GraphAccess`] call an operator makes is counted as `max(1, records_returned)`:
//!
//! * a scalar read (`node_property`, `node_labels`, `rel_data`, `node_exists`, …) costs **1**, whether or
//!   not it found anything (the store was consulted either way);
//! * a set-returning read (`scan_nodes`, `scan_nodes_by_label`, `expand`, `incident_rels`, every
//!   `index_seek_*`, `fulltext_query`, `vector_query_*`, the columnar scan …) costs **one per record it
//!   returned**, and 1 when it returned none — so a 1 000 000-node label scan reports ~1 000 000 hits
//!   while the index seek that replaces it reports the handful of candidates it actually fetched;
//! * every write (`create_node`, `set_node_property`, `delete_rel`, …) costs **1**.
//!
//! Calls that read no store record are deliberately **not** counted: `entity_deleted_by_txn` (a lookup in
//! the current transaction's own in-memory tombstone set, made before every property access — counting it
//! would double every property read with work the store never did), `index_exists_by_name` (a catalogue
//! metadata lookup), and the pure-metadata seams (`statistics`, `write_counters`).
//!
//! Nothing here is estimated, extrapolated or synthesised: each number is an exact count of calls the
//! statement really made through the one seam every store access passes through. It is *not* a page-cache
//! or disk-IO count — Graphus does not report `pageCacheHits` / `pageCacheMisses` / `time` at all rather
//! than invent them (all three are optional on the wire; the official drivers default them to `0`).
//!
//! # What `dbHits` cannot show, and the counters that do (`rmp` task #991)
//!
//! `dbHits` charges an operator for what it **matched**. That is deliberate and unchanged — but it makes
//! the cost of Graphus's *candidate + re-verification* access model invisible. Every index access path
//! answers from a derived, MVCC-unaware structure, so the index yields a **superset** of the matching ids
//! and the read body re-reads each candidate to test visibility and re-apply the predicate. Two
//! scalability brakes therefore had no signal at all:
//!
//! 1. a seek that examines a million candidates to return ten rows looked exactly as cheap as one that
//!    examines ten; and
//! 2. the blanket `mark_all_live_nodes` predicate footprint, which every **non-equality** node seek
//!    registers unconditionally, costs one SIREAD marker per live node whatever the seek returns — and
//!    appeared nowhere.
//!
//! [`ReadCounts`] closes both. The seam ([`GraphAccess::take_read_tally`]) measures, this recorder
//! attributes, and [`crate::plan_description`] renders — as `CandidatesExamined`,
//! `CandidatesRejectedByVisibility`, `CandidatesRejectedByFilter`, `ReadMarkers` and `PredicateMarkers`
//! inside each operator's `args`. The three candidate counters are **disjoint**, so
//! `examined - rejected(visibility) - rejected(filter)` is what survived; the two marker counters are
//! counted at the point of emission, never inferred from the candidates. Each is emitted only when
//! non-zero, so absence means a *measured* zero — never an unmeasured quantity, which stays omitted
//! (decision `D-query-prefixes`).
//!
//! PostgreSQL's `EXPLAIN ANALYZE` makes the same distinction with *"Rows Removed by Filter"*
//! (`src/backend/commands/explain.c`; counters in `src/include/executor/instrument.h`) and is the direct
//! precedent; the names here are Graphus's own because the measured quantity is Graphus's own.
//!
//! # Cost on the normal path: none
//!
//! Instrumentation is **entirely absent** unless the statement carries the `PROFILE` prefix. An
//! unprofiled statement builds no [`ProfileRecorder`], wraps no operator, and calls the store through the
//! bare seam exactly as before — there is no branch, no atomic and no allocation on the hot path, because
//! the profiling operators and the counting decorator are simply never constructed.
//!
//! The one half that *is* always on is the seam's own accumulation into its
//! [`ReadTally`](crate::read_source::ReadTally), and it has two shapes, only one of them batched:
//! **candidates** are counted into plain locals and flushed with three `Cell` read-modify-writes per
//! access, while **markers** cost one `Cell` read-modify-write **each**, because they are emitted from
//! many scattered sites rather than from one loop (on the measured baseline, 120 of them for 40
//! candidates on an unselective range seek). An unprofiled statement simply never drains the result.
//!
//! `benches/read_seam.rs` measures that half over the real record store —
//! `cargo bench -p graphus-cypher --bench read_seam`. On the four access paths this instrumentation
//! touches, Criterion detected **no change at the mean** on any of them (all `p > 0.05`); two of the
//! four *medians* are distinguishable from zero in **opposite** directions (+3.1 % and −2.8 %), which is
//! code-layout drift between binaries rather than a cost of the counters. With 30 samples the run does
//! not exclude a regression below roughly 12 % on the shortest path (`seek_eq_selective`, ~7.5 µs).
//! `graphus-bench/RESULTS.md` §11.2 carries the full numbers and the limits of that evidence; it is what
//! to re-check whenever this module or `read_source` is touched.
//!
//! # Attribution model (why the numbers land on the right operator)
//!
//! Every physical operator is numbered once, in pre-order, when the [`ProfileRecorder`] is built. At run time
//! the executor wraps each operator in a thin profiling shim that, on entry, makes its id the recorder's
//! **current** operator and restores the previous one on exit. Since a child's own shim re-enters with the
//! child's id, work performed *by* an operator (a `Filter` evaluating its predicate, a scan materialising
//! its rows) is attributed to that operator, while work performed by its children is attributed to them —
//! the same containment rule Neo4j's plan description uses.
//!
//! Two consequences are deliberate and documented rather than hidden:
//!
//! * **Result materialisation** (resolving the labels/properties of the entities in a returned row at the
//!   result boundary) happens *outside* any operator; it is attributed to the **root** operator, which is
//!   the operator that produced the row. This mirrors the role Neo4j's `ProduceResults` plays.
//! * **Morsel-driven intra-query parallelism is disabled for a profiled statement** (see
//!   [`crate::executor`]): its worker threads read the store through a seam this decorator does not sit on,
//!   so a parallel profiled run would silently *under*-count. Running the profiled statement serially keeps
//!   every storage access attributable. A `PROFILE`d query may therefore be slower than the same query run
//!   normally — a diagnostic-only cost, exactly as Neo4j warns for `PROFILE`.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::PoisonError;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use graphus_core::Value;

use crate::counters::QueryCounters;
use crate::graph_access::{
    ColumnarScan, CompositeSeekHits, DeletedEntity, ExpandDirection, GraphAccess, Incident,
    IndexSeekHits, KeyValues, NodeId, RelData, RelId, ScanFilter, ScannedRel, SeekHits,
    VectorQueryResult,
};
use crate::physical::{PhysicalOp, PhysicalPlan, TextSeekOp};
use crate::read_source::ReadCounts;

/// The id of one operator in a profiled plan: its index in the plan's **pre-order** numbering.
///
/// The root is `0`, and a subtree's ids are contiguous — the property the executor relies on when it
/// re-numbers a per-row-rebuilt sub-plan template (see [`ProfileRecorder::rebind_template`]).
pub type OpId = usize;

/// The measured runtime counters of a profiled statement, one slot per plan operator (`rmp` #752).
///
/// Created by the executor when — and only when — the compiled plan carries the
/// [`Profile`](crate::ast::QueryPrefix::Profile) prefix, and shared (`Arc`) with the caller so the
/// counters survive the cursor: the server reads them *after* the statement finishes, to build the result
/// summary, even though the cursor that produced them is long gone.
///
/// Counters are plain relaxed atomics. The profiled statement runs serially (morsel parallelism is
/// disabled for it), so no ordering between them is needed or implied; atomics are used only so the
/// recorder is `Send + Sync` and can ride the same paths as the plan it belongs to.
#[derive(Debug)]
pub struct ProfileRecorder {
    /// The plan being profiled — held so the description can be rendered from it after execution, and so
    /// the operator addresses this recorder maps stay alive for the recorder's whole life.
    plan: Arc<PhysicalPlan>,
    /// Rows emitted, per operator id.
    rows: Vec<AtomicU64>,
    /// Storage-seam records obtained, per operator id (see the [module docs](self)).
    db_hits: Vec<AtomicU64>,
    /// The seam's measured candidate-examination counts, per operator id (`rmp` task #991) — what the
    /// "candidate + re-verification" access model actually cost, which `db_hits` cannot show because it
    /// charges what an operator *matched*. Drained off the seam after every call it makes (see
    /// [`ProfilingGraph::tally`]).
    counts: Vec<Mutex<ReadCounts>>,
    /// The operator currently executing — the one storage accesses are attributed to. Starts at the root
    /// (`0`), so an access made outside any operator (result materialisation) lands on the root.
    current: AtomicUsize,
    /// Address → id for every operator of `plan`, assigned once at construction (pre-order).
    plan_ids: HashMap<usize, OpId>,
    /// Address → id for the operators of the sub-plan **template** currently being rebuilt (a nested-loop
    /// join's right branch, a `FOREACH` body). The executor clones such a template out of the plan, so its
    /// nodes have their own addresses; [`rebind_template`](Self::rebind_template) re-numbers them from the
    /// template root's id before each rebuild. Cleared on every rebind, so it never grows without bound.
    template_ids: Mutex<HashMap<usize, OpId>>,
}

impl ProfileRecorder {
    /// Creates a recorder for `plan`, numbering its operators in pre-order and zeroing every counter.
    #[must_use]
    pub fn new(plan: Arc<PhysicalPlan>) -> Self {
        let len = plan.root.subtree_len();
        let mut plan_ids = HashMap::with_capacity(len);
        number_subtree(&plan.root, 0, &mut plan_ids);
        Self {
            rows: (0..len).map(|_| AtomicU64::new(0)).collect(),
            db_hits: (0..len).map(|_| AtomicU64::new(0)).collect(),
            counts: (0..len).map(|_| Mutex::new(ReadCounts::ZERO)).collect(),
            current: AtomicUsize::new(0),
            plan_ids,
            template_ids: Mutex::new(HashMap::new()),
            plan,
        }
    }

    /// The plan these counters were recorded against.
    #[must_use]
    pub fn plan(&self) -> &Arc<PhysicalPlan> {
        &self.plan
    }

    /// The id of `op`, which must be an operator of the profiled plan or of the sub-plan template
    /// currently bound by [`rebind_template`](Self::rebind_template).
    ///
    /// Returns `None` only if it is neither — which the executor cannot produce (it looks up exactly the
    /// operators it was handed). A `None` disables profiling for that operator rather than misattributing
    /// its work to another one: an absent counter is honest, a wrong counter is not.
    #[must_use]
    pub fn id_of(&self, op: &PhysicalOp) -> Option<OpId> {
        let key = std::ptr::from_ref(op) as usize;
        if let Some(id) = self
            .template_ids
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(&key)
        {
            return Some(*id);
        }
        self.plan_ids.get(&key).copied()
    }

    /// Re-numbers a per-row-rebuilt sub-plan `template` whose root is the plan operator with id `root_id`.
    ///
    /// The executor clones the right branch of a [`NestedLoopJoin`](PhysicalOp::NestedLoopJoin) and the body
    /// of a [`Foreach`](PhysicalOp::Foreach) out of the plan and rebuilds them once per driving row, so those
    /// nodes are *not* the plan's own nodes and are not in [`plan_ids`](Self::plan_ids). Because a pre-order
    /// numbering gives every subtree a **contiguous** id range, and the template is a structural clone of the
    /// plan subtree, numbering the template in pre-order from `root_id` reproduces exactly the ids the plan's
    /// own nodes carry — so a rebuilt operator accumulates into the same counter every time.
    ///
    /// The previous template numbering is dropped first: only one template is ever being built at a time (an
    /// inner template's rebuild happens strictly after the outer template's build has finished), so the map
    /// stays bounded by the largest template regardless of how many rows drive the rebuild.
    pub fn rebind_template(&self, template: &PhysicalOp, root_id: OpId) {
        let mut ids = self
            .template_ids
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        ids.clear();
        number_subtree(template, root_id, &mut ids);
    }

    /// Makes `id` the operator that storage accesses are attributed to, returning the previous one (which
    /// the caller must restore when the operator returns).
    #[must_use]
    pub fn enter(&self, id: OpId) -> OpId {
        self.current.swap(id, Ordering::Relaxed)
    }

    /// Restores the operator [`enter`](Self::enter) displaced.
    pub fn leave(&self, previous: OpId) {
        self.current.store(previous, Ordering::Relaxed);
    }

    /// Records one row emitted by operator `id`.
    pub fn record_row(&self, id: OpId) {
        if let Some(c) = self.rows.get(id) {
            c.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Records `n` storage-seam records obtained by the **current** operator.
    fn record_db_hits(&self, n: u64) {
        let id = self.current.load(Ordering::Relaxed);
        if let Some(c) = self.db_hits.get(id) {
            c.fetch_add(n, Ordering::Relaxed);
        }
    }

    /// The rows emitted by operator `id` (`0` for an operator that never ran).
    #[must_use]
    pub fn rows(&self, id: OpId) -> u64 {
        self.rows.get(id).map_or(0, |c| c.load(Ordering::Relaxed))
    }

    /// The storage-seam records obtained by operator `id` (`0` for an operator that never ran).
    #[must_use]
    pub fn db_hits(&self, id: OpId) -> u64 {
        self.db_hits
            .get(id)
            .map_or(0, |c| c.load(Ordering::Relaxed))
    }

    /// Adds `counts` — one storage-seam call's measured candidate examination, just drained off the
    /// seam — to the **current** operator's tally (`rmp` task #991).
    ///
    /// An all-zero drain is discarded without touching the slot, so the overwhelming majority of seam
    /// calls (scalar reads, writes, metadata) cost nothing here.
    fn record_counts(&self, counts: ReadCounts) {
        if counts.is_zero() {
            return;
        }
        let id = self.current.load(Ordering::Relaxed);
        let Some(slot) = self.counts.get(id) else {
            return;
        };
        let mut slot = slot.lock().unwrap_or_else(PoisonError::into_inner);
        slot.candidates_examined += counts.candidates_examined;
        slot.rejected_by_visibility += counts.rejected_by_visibility;
        slot.rejected_by_predicate += counts.rejected_by_predicate;
        slot.read_markers += counts.read_markers;
        slot.predicate_markers += counts.predicate_markers;
    }

    /// The measured candidate-examination counts of operator `id`
    /// ([`ReadCounts::ZERO`] for an operator that never touched the storage seam).
    #[must_use]
    pub fn read_counts(&self, id: OpId) -> ReadCounts {
        self.counts.get(id).map_or(ReadCounts::ZERO, |c| {
            *c.lock().unwrap_or_else(PoisonError::into_inner)
        })
    }
}

/// Numbers `op`'s subtree in pre-order starting at `base`, mapping each operator's address to its id.
///
/// Pre-order guarantees that a subtree's ids are **contiguous** starting at the subtree root's own id —
/// the invariant [`ProfileRecorder::rebind_template`] depends on.
fn number_subtree(op: &PhysicalOp, base: OpId, out: &mut HashMap<usize, OpId>) {
    out.insert(std::ptr::from_ref(op) as usize, base);
    let mut next = base + 1;
    for child in op.children() {
        number_subtree(child, next, out);
        next += child.subtree_len();
    }
}

/// A **counting decorator** over the graph seam: forwards every [`GraphAccess`] call to the real seam and
/// tallies the records it returned against the operator currently executing (`rmp` #752).
///
/// It is installed **only** for a `PROFILE`d statement, for the duration of one cursor operation, and wraps
/// whatever seam the statement would otherwise have used (the live store seam, the off-thread reader's
/// read-only view, or the RBAC [`AuthorizedGraph`](crate::authorized_graph::AuthorizedGraph) decorator) — so
/// profiling never changes *which* seam runs, only that its calls are counted.
///
/// # Every method is forwarded explicitly, and that is load-bearing
///
/// [`GraphAccess`] gives several methods a *default* implementation written in terms of other trait methods
/// (`scan_filter_eq`, `rel_data_including_deleted`, …), and the real seams **override** them with
/// behaviour that is not merely an optimisation: `RecordStoreGraph::scan_filter_eq`, for instance, registers
/// a far tighter SSI read footprint than the default composition would. If this decorator inherited any
/// default, a profiled statement would silently take a *different* execution path — different isolation
/// behaviour under `PROFILE` than without it. Every method is therefore forwarded to the inner seam
/// explicitly, and `profiling_graph_forwards_specialised_seam_methods` in this module's tests pins that.
pub struct ProfilingGraph<'g> {
    inner: &'g mut dyn GraphAccess,
    rec: Arc<ProfileRecorder>,
}

impl<'g> ProfilingGraph<'g> {
    /// Wraps `inner`, tallying its accesses into `rec`.
    ///
    /// The seam's [`ReadTally`](crate::read_source::ReadTally) is drained and **discarded** here, so a
    /// wrapper never inherits candidate counts produced while no wrapper was installed (`rmp` #991).
    /// Work done outside every operator is not attributable to one, and an absent counter is honest
    /// where a misattributed one is not — the same rule [`ProfileRecorder::id_of`] follows.
    pub fn new(inner: &'g mut dyn GraphAccess, rec: Arc<ProfileRecorder>) -> Self {
        let _ = inner.take_read_tally();
        Self { inner, rec }
    }

    /// Drains the seam's candidate-examination counts onto the **current** operator (`rmp` task #991).
    ///
    /// Called after **every** forwarded seam call — reads, writes and the uncounted metadata calls
    /// alike — because a tally left undrained would be attributed to whichever operator drains next.
    fn tally(&self) {
        self.rec.record_counts(self.inner.take_read_tally());
    }

    /// Counts one storage access that obtained `records` records (a lookup that found nothing still touched
    /// the store, so it costs 1), and drains that call's candidate counts.
    fn hit(&self, records: usize) {
        self.rec.record_db_hits(records.max(1) as u64);
        self.tally();
    }

    /// Counts a scalar access (exactly one record consulted).
    fn hit1(&self) {
        self.rec.record_db_hits(1);
        self.tally();
    }

    /// Counts an optional set-returning access: a decline (`None` — no such index) is not a storage access
    /// at all and costs nothing; a served seek costs one per candidate it returned.
    ///
    /// A decline still **drains**: a seam that declines after registering its SSI markers (the
    /// relationship seeks do exactly that, `rmp` #683) really did emit them, and dropping the tally
    /// would both hide that cost and misattribute it to the next operator to drain.
    fn hit_opt<T>(&self, r: &Option<Vec<T>>) {
        match r {
            Some(v) => self.hit(v.len()),
            None => self.tally(),
        }
    }

    /// The [`SeekHits`] twin of [`hit_opt`](Self::hit_opt) (`rmp` task #879). Charges exactly what the
    /// id-returning shape charged before the seam started carrying key values — one per matched id,
    /// never one per carried value — so the *seek's* own `dbHits` are unchanged by the feature and the
    /// saving shows up where it is real: in the consumer that no longer reads the store.
    fn hit_hits<V>(&self, r: &Option<SeekHits<V>>) {
        match r {
            Some(hits) => self.hit(hits.len()),
            None => self.tally(),
        }
    }
}

impl GraphAccess for ProfilingGraph<'_> {
    // ---- reads ------------------------------------------------------------------------------------
    fn scan_nodes(&self) -> Vec<NodeId> {
        let r = self.inner.scan_nodes();
        self.hit(r.len());
        r
    }

    fn scan_nodes_by_label(&self, label: &str) -> Vec<NodeId> {
        let r = self.inner.scan_nodes_by_label(label);
        self.hit(r.len());
        r
    }

    fn expand(&self, node: NodeId, direction: ExpandDirection, types: &[String]) -> Vec<Incident> {
        let r = self.inner.expand(node, direction, types);
        self.hit(r.len());
        r
    }

    fn scan_rels_by_type(&self, types: &[String]) -> Option<Vec<ScannedRel>> {
        // Forwarded explicitly (`rmp` task #867): the trait default is `None`, so an unforwarded method
        // would silently make every `PROFILE`d relationship scan take the node-walk fallback the real
        // run does not — a plan whose measured `dbHits` describe a different access path than the one
        // that ran. `hit_opt` charges nothing for a decline and one per relationship enumerated.
        let r = self.inner.scan_rels_by_type(types);
        self.hit_opt(&r);
        r
    }

    fn count_store_nodes(&self, label: Option<&str>) -> Option<u64> {
        // Forwarded explicitly (`rmp` task #866), for the same reason as `scan_rels_by_type` above: the
        // trait default is `None`, so an unforwarded method would make every `PROFILE`d count take the
        // scan fallback that an un-profiled run does not — the plan would then report `dbHits` for a
        // path that only PROFILE takes, which is precisely the `rmp` #755 defect class.
        //
        // One `dbHit` per answer: the count is a single catalogue read, however many entities it
        // counts. That is the whole point of the operator, and it is what makes `dbHits` the honest
        // witness of which path ran — a served count charges 1, a decline charges 0 here and the
        // fallback subtree charges its own scan underneath.
        let r = self.inner.count_store_nodes(label);
        if r.is_some() {
            self.hit1();
        } else {
            // A decline reads no record, but it may still have emitted markers — drain so they are not
            // attributed to the next operator (`rmp` #991).
            self.tally();
        }
        r
    }

    fn count_store_rels(&self, types: &[String]) -> Option<u64> {
        // See `count_store_nodes` above (`rmp` task #866).
        let r = self.inner.count_store_rels(types);
        if r.is_some() {
            self.hit1();
        } else {
            self.tally();
        }
        r
    }

    fn node_exists(&self, node: NodeId) -> bool {
        self.rec.record_db_hits(1);
        let r = self.inner.node_exists(node);
        self.tally();
        r
    }

    fn rel_exists(&self, rel: RelId) -> bool {
        self.rec.record_db_hits(1);
        let r = self.inner.rel_exists(rel);
        self.tally();
        r
    }

    fn node_labels(&self, node: NodeId) -> Option<Vec<String>> {
        self.rec.record_db_hits(1);
        let r = self.inner.node_labels(node);
        self.tally();
        r
    }

    fn rel_data(&self, rel: RelId) -> Option<RelData> {
        self.rec.record_db_hits(1);
        let r = self.inner.rel_data(rel);
        self.tally();
        r
    }

    fn rel_data_including_deleted(&self, rel: RelId) -> Option<RelData> {
        self.rec.record_db_hits(1);
        let r = self.inner.rel_data_including_deleted(rel);
        self.tally();
        r
    }

    fn entity_deleted_by_txn(&self, entity: DeletedEntity) -> bool {
        // NOT a storage read: this consults the current transaction's own in-memory tombstone set (to
        // decide whether a property read on a self-deleted entity must raise). Counting it would inflate
        // every property access by 2x with work the store never did — a wrong number, so it is not counted.
        let r = self.inner.entity_deleted_by_txn(entity);
        self.tally();
        r
    }

    fn node_property(&self, node: NodeId, key: &str) -> Option<Value> {
        self.rec.record_db_hits(1);
        let r = self.inner.node_property(node, key);
        self.tally();
        r
    }

    fn rel_property(&self, rel: RelId, key: &str) -> Option<Value> {
        self.rec.record_db_hits(1);
        let r = self.inner.rel_property(rel, key);
        self.tally();
        r
    }

    fn node_properties(&self, node: NodeId) -> Option<Vec<(String, Value)>> {
        let r = self.inner.node_properties(node);
        self.hit(r.as_ref().map_or(0, Vec::len));
        r
    }

    fn rel_properties(&self, rel: RelId) -> Option<Vec<(String, Value)>> {
        let r = self.inner.rel_properties(rel);
        self.hit(r.as_ref().map_or(0, Vec::len));
        r
    }

    fn index_seek_eq(
        &self,
        label: &str,
        property: &str,
        value: &Value,
        carry: KeyValues,
    ) -> Option<IndexSeekHits> {
        let r = self.inner.index_seek_eq(label, property, value, carry);
        self.hit_hits(&r);
        r
    }

    fn scan_filter_eq(&self, label: &str, property: &str, value: &Value) -> ScanFilter {
        let r = self.inner.scan_filter_eq(label, property, value);
        // The fused scan+filter READS every record it examined and returns only the matches, so the
        // examined count — which the seam reports precisely because a profile would otherwise understate a
        // full-scan fallback by orders of magnitude — is this operator's true `dbHits` (`rmp` #752).
        self.hit(r.examined.max(r.matched.len()));
        r
    }

    fn index_seek_range(
        &self,
        label: &str,
        property: &str,
        lower: Option<(&Value, bool)>,
        upper: Option<(&Value, bool)>,
        carry: KeyValues,
    ) -> Option<IndexSeekHits> {
        let r = self
            .inner
            .index_seek_range(label, property, lower, upper, carry);
        self.hit_hits(&r);
        r
    }

    fn index_seek_composite_eq(
        &self,
        label: &str,
        properties: &[String],
        values: &[Value],
        carry: KeyValues,
    ) -> Option<CompositeSeekHits> {
        let r = self
            .inner
            .index_seek_composite_eq(label, properties, values, carry);
        self.hit_hits(&r);
        r
    }

    fn index_seek_rel_eq(
        &self,
        rel_type: &str,
        property: &str,
        value: &Value,
    ) -> Option<Vec<RelId>> {
        let r = self.inner.index_seek_rel_eq(rel_type, property, value);
        self.hit_opt(&r);
        r
    }

    fn index_seek_rel_range(
        &self,
        rel_type: &str,
        property: &str,
        lower: Option<(&Value, bool)>,
        upper: Option<(&Value, bool)>,
    ) -> Option<Vec<RelId>> {
        let r = self
            .inner
            .index_seek_rel_range(rel_type, property, lower, upper);
        self.hit_opt(&r);
        r
    }

    fn index_seek_rel_composite_eq(
        &self,
        rel_type: &str,
        properties: &[String],
        values: &[Value],
    ) -> Option<Vec<RelId>> {
        let r = self
            .inner
            .index_seek_rel_composite_eq(rel_type, properties, values);
        self.hit_opt(&r);
        r
    }

    fn index_seek_spatial(
        &self,
        label: &str,
        property: &str,
        center_x: f64,
        center_y: f64,
        radius: f64,
    ) -> Option<Vec<NodeId>> {
        let r = self
            .inner
            .index_seek_spatial(label, property, center_x, center_y, radius);
        self.hit_opt(&r);
        r
    }

    fn index_seek_spatial_rel(
        &self,
        rel_type: &str,
        property: &str,
        center_x: f64,
        center_y: f64,
        radius: f64,
    ) -> Option<Vec<RelId>> {
        let r = self
            .inner
            .index_seek_spatial_rel(rel_type, property, center_x, center_y, radius);
        self.hit_opt(&r);
        r
    }

    fn index_seek_text(
        &self,
        label: &str,
        property: &str,
        op: TextSeekOp,
        needle: &str,
    ) -> Option<Vec<NodeId>> {
        let r = self.inner.index_seek_text(label, property, op, needle);
        self.hit_opt(&r);
        r
    }

    fn fulltext_query(&self, name: &str, search: &str) -> Option<Vec<NodeId>> {
        let r = self.inner.fulltext_query(name, search);
        self.hit_opt(&r);
        r
    }

    fn fulltext_score(&self, name: &str, node: NodeId, search: &str) -> Option<u64> {
        self.rec.record_db_hits(1);
        let r = self.inner.fulltext_score(name, node, search);
        self.tally();
        r
    }

    fn fulltext_query_rel(&self, name: &str, search: &str) -> Option<Vec<RelId>> {
        let r = self.inner.fulltext_query_rel(name, search);
        self.hit_opt(&r);
        r
    }

    fn fulltext_score_rel(&self, name: &str, rel: RelId, search: &str) -> Option<u64> {
        self.rec.record_db_hits(1);
        let r = self.inner.fulltext_score_rel(name, rel, search);
        self.tally();
        r
    }

    fn vector_query_nodes(&self, name: &str, query: &[f32], k: usize) -> VectorQueryResult {
        let r = self.inner.vector_query_nodes(name, query, k);
        self.hit(match &r {
            VectorQueryResult::Hits { hits, .. } => hits.len(),
            _ => 0,
        });
        r
    }

    fn vector_query_rels(&self, name: &str, query: &[f32], k: usize) -> VectorQueryResult {
        let r = self.inner.vector_query_rels(name, query, k);
        self.hit(match &r {
            VectorQueryResult::Hits { hits, .. } => hits.len(),
            _ => 0,
        });
        r
    }

    fn index_exists_by_name(&self, name: &str) -> Option<bool> {
        // A catalogue metadata lookup, not a record read — not counted (see `entity_deleted_by_txn`).
        let r = self.inner.index_exists_by_name(name);
        self.tally();
        r
    }

    fn fulltext_scan_fallback(
        &self,
        label_tokens: &[u32],
        prop_keys: &[u32],
        analyzer: graphus_index::fulltext::Analyzer,
        search: &str,
    ) -> Vec<NodeId> {
        let r = self
            .inner
            .fulltext_scan_fallback(label_tokens, prop_keys, analyzer, search);
        self.hit(r.len());
        r
    }

    fn columnar_label_property_scan(&self, label: &str, property: &str) -> Option<ColumnarScan> {
        let r = self.inner.columnar_label_property_scan(label, property);
        if let Some(scan) = &r {
            // `label_matches` counts every visible label-carrying node the columnar pass touched — the
            // records read — which is `>= rows.len()` (a node with no value contributes no row).
            self.hit(scan.label_matches.max(scan.rows.len()));
        } else {
            self.tally();
        }
        r
    }

    fn project_snapshot(
        &self,
        spec: &crate::snapshot::SnapshotSpec,
    ) -> Option<crate::snapshot::GraphSnapshot> {
        let r = self.inner.project_snapshot(spec);
        if let Some(snap) = &r {
            self.hit(snap.node_count());
        } else {
            self.tally();
        }
        r
    }

    fn note_parallel_aggregate(&self) {
        self.inner.note_parallel_aggregate();
        self.tally();
    }

    fn morsel_label_scan(&self, label: &str) -> Option<crate::morsel::MorselLabelScan> {
        // Unreachable while profiling (the morsel tier is disabled for a profiled statement), but
        // forwarded rather than declined so the decorator never changes which seam a caller reaches.
        let r = self.inner.morsel_label_scan(label);
        self.tally();
        r
    }

    fn frontier_morsel_source(&self) -> Option<crate::morsel::MorselFrontierSource> {
        let r = self.inner.frontier_morsel_source();
        self.tally();
        r
    }

    fn merge_morsel_buffer(&self, buffer: graphus_txn::SsiReadBuffer) {
        self.inner.merge_morsel_buffer(buffer);
        self.tally();
    }

    // ---- writes -----------------------------------------------------------------------------------
    fn create_node(&mut self, labels: &[String], properties: &[(String, Value)]) -> NodeId {
        self.rec.record_db_hits(1);
        let r = self.inner.create_node(labels, properties);
        self.tally();
        r
    }

    fn create_rel(
        &mut self,
        rel_type: &str,
        start: NodeId,
        end: NodeId,
        properties: &[(String, Value)],
    ) -> RelId {
        self.rec.record_db_hits(1);
        let r = self.inner.create_rel(rel_type, start, end, properties);
        self.tally();
        r
    }

    fn set_node_property(&mut self, node: NodeId, key: &str, value: Value) {
        self.rec.record_db_hits(1);
        self.inner.set_node_property(node, key, value);
        self.tally();
    }

    fn set_rel_property(&mut self, rel: RelId, key: &str, value: Value) {
        self.rec.record_db_hits(1);
        self.inner.set_rel_property(rel, key, value);
        self.tally();
    }

    fn add_labels(&mut self, node: NodeId, labels: &[String]) {
        self.rec.record_db_hits(1);
        self.inner.add_labels(node, labels);
        self.tally();
    }

    fn remove_labels(&mut self, node: NodeId, labels: &[String]) {
        self.rec.record_db_hits(1);
        self.inner.remove_labels(node, labels);
        self.tally();
    }

    fn remove_node_property(&mut self, node: NodeId, key: &str) {
        self.rec.record_db_hits(1);
        self.inner.remove_node_property(node, key);
        self.tally();
    }

    fn remove_rel_property(&mut self, rel: RelId, key: &str) {
        self.rec.record_db_hits(1);
        self.inner.remove_rel_property(rel, key);
        self.tally();
    }

    fn replace_node_properties(&mut self, node: NodeId, properties: &[(String, Value)]) {
        self.rec.record_db_hits(1);
        self.inner.replace_node_properties(node, properties);
        self.tally();
    }

    fn merge_node_properties(&mut self, node: NodeId, properties: &[(String, Value)]) {
        self.rec.record_db_hits(1);
        self.inner.merge_node_properties(node, properties);
        self.tally();
    }

    fn replace_rel_properties(&mut self, rel: RelId, properties: &[(String, Value)]) {
        self.rec.record_db_hits(1);
        self.inner.replace_rel_properties(rel, properties);
        self.tally();
    }

    fn merge_rel_properties(&mut self, rel: RelId, properties: &[(String, Value)]) {
        self.rec.record_db_hits(1);
        self.inner.merge_rel_properties(rel, properties);
        self.tally();
    }

    fn incident_rels(&self, node: NodeId) -> Vec<RelId> {
        let r = self.inner.incident_rels(node);
        self.hit(r.len());
        r
    }

    fn delete_rel(&mut self, rel: RelId) {
        self.rec.record_db_hits(1);
        self.inner.delete_rel(rel);
        self.tally();
    }

    fn delete_node(&mut self, node: NodeId) {
        self.rec.record_db_hits(1);
        self.inner.delete_node(node);
        self.tally();
    }

    // ---- metadata (not storage reads: never counted) ----------------------------------------------
    fn statistics(&self) -> Option<&dyn crate::statistics::Statistics> {
        self.inner.statistics()
    }

    fn write_counters(&self) -> QueryCounters {
        self.inner.write_counters()
    }

    fn take_read_tally(&self) -> ReadCounts {
        // Forwarded like every other seam method, so a caller above this decorator sees exactly what the
        // wrapped seam measured. Nothing above it drains during a profiled statement — `tally()` is the
        // only drain — so forwarding cannot steal counts from the attribution path (`rmp` #991).
        self.inner.take_read_tally()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::catalog::IndexCatalog;
    use crate::graph_access::MemGraph;
    use crate::lexer::tokenize;
    use crate::lower::lower;
    use crate::parser::parse_tokens;
    use crate::physical::plan_physical;
    use crate::semantics::analyze;

    fn plan(src: &str) -> Arc<PhysicalPlan> {
        let toks = tokenize(src).expect("lex");
        let ast = parse_tokens(&toks, src).expect("parse");
        let validated = analyze(&ast).expect("analyze");
        Arc::new(plan_physical(&lower(&validated), &IndexCatalog::empty()))
    }

    #[test]
    fn preorder_ids_are_contiguous_per_subtree() {
        // Projection(0) → Filter(1) → NodeByLabelScan(2): a chain numbers 0,1,2 top-down.
        let p = plan("MATCH (n:Person) WHERE n.age > 3 RETURN n");
        let rec = ProfileRecorder::new(Arc::clone(&p));
        assert_eq!(rec.id_of(&p.root), Some(0));
        let mut op = &p.root;
        let mut expected = 0;
        loop {
            assert_eq!(rec.id_of(op), Some(expected));
            let kids = op.children();
            let Some(next) = kids.first() else { break };
            expected += 1;
            op = next;
        }
        assert!(expected >= 2, "expected a chain of at least 3 operators");
    }

    #[test]
    fn rebind_template_reproduces_the_plan_ids() {
        let p = plan("MATCH (n:Person) WHERE n.age > 3 RETURN n");
        let rec = ProfileRecorder::new(Arc::clone(&p));
        // A structural clone of a subtree (what the executor keeps as a rebuild template) is numbered
        // from the subtree root's id, so its operators land on the plan's own counters.
        let sub = p.root.children()[0];
        let sub_id = rec.id_of(sub).expect("subtree numbered");
        let template = sub.clone();
        rec.rebind_template(&template, sub_id);
        assert_eq!(rec.id_of(&template), Some(sub_id));
        assert_eq!(rec.id_of(template.children()[0]), Some(sub_id + 1));
        // …and the plan's own nodes are still resolvable.
        assert_eq!(rec.id_of(&p.root), Some(0));
    }

    #[test]
    fn db_hits_count_records_not_calls() {
        let mut g = MemGraph::new();
        for i in 0..7 {
            g.add_node(["Person"], [("age", Value::Integer(i))]);
        }
        let p = plan("MATCH (n:Person) RETURN n");
        let rec = Arc::new(ProfileRecorder::new(p));
        {
            let pg = ProfilingGraph::new(&mut g, Arc::clone(&rec));
            // A label scan returning 7 nodes is 7 hits; a scalar property read is 1.
            let ids = pg.scan_nodes_by_label("Person");
            assert_eq!(ids.len(), 7);
            let _ = pg.node_property(ids[0], "age");
        }
        assert_eq!(rec.db_hits(0), 8);
        // A lookup that finds nothing still consulted the store: 1 hit, never 0.
        {
            let pg = ProfilingGraph::new(&mut g, Arc::clone(&rec));
            let none = pg.scan_nodes_by_label("Nobody");
            assert!(none.is_empty());
        }
        assert_eq!(rec.db_hits(0), 9);
    }

    #[test]
    fn db_hits_land_on_the_current_operator() {
        let mut g = MemGraph::new();
        g.add_node(["Person"], [("age", Value::Integer(1))]);
        let p = plan("MATCH (n:Person) RETURN n");
        let rec = Arc::new(ProfileRecorder::new(p));
        {
            let pg = ProfilingGraph::new(&mut g, Arc::clone(&rec));
            // Operator 1 is the plan's leaf scan (0 = the root projection).
            let prev = rec.enter(1);
            let _ = pg.scan_nodes();
            rec.leave(prev);
            let _ = pg.node_property(NodeId(0), "age");
        }
        assert_eq!(rec.db_hits(1), 1, "the scan is attributed to operator 1");
        assert_eq!(
            rec.db_hits(0),
            1,
            "the access outside any operator lands on the root"
        );
    }

    #[test]
    fn profiling_graph_forwards_specialised_seam_methods() {
        // `scan_filter_eq` has a *default* trait implementation, and the real store seam overrides it with
        // one that registers a much tighter SSI footprint. The decorator must forward it (not inherit the
        // default), or a profiled statement would take a different execution path than an unprofiled one.
        // `MemGraph` does not override it, so behaviour equality is what we can pin here; the forwarding
        // itself is pinned by construction (every trait method is written out in this module).
        let mut g = MemGraph::new();
        let a = g.add_node(["Person"], [("name", Value::String("Ada".into()))]);
        g.add_node(["Person"], [("name", Value::String("Bob".into()))]);
        let direct = g.scan_filter_eq("Person", "name", &Value::String("Ada".into()));
        let p = plan("MATCH (n:Person) RETURN n");
        let rec = Arc::new(ProfileRecorder::new(p));
        let pg = ProfilingGraph::new(&mut g, Arc::clone(&rec));
        let through = pg.scan_filter_eq("Person", "name", &Value::String("Ada".into()));
        assert_eq!(direct, through);
        assert_eq!(through.matched, vec![a]);
        // The seam reports what it EXAMINED (both :Person nodes), not just what it matched — the number a
        // PROFILE reports as this operator's `dbHits`, so a full-scan fallback cannot look cheap.
        assert_eq!(through.examined, 2);
        assert_eq!(rec.db_hits(0), 2);
    }

    #[test]
    fn rows_are_recorded_per_operator() {
        let p = plan("MATCH (n:Person) RETURN n");
        let rec = ProfileRecorder::new(p);
        rec.record_row(1);
        rec.record_row(1);
        rec.record_row(0);
        assert_eq!(rec.rows(0), 1);
        assert_eq!(rec.rows(1), 2);
        assert_eq!(rec.rows(2), 0);
    }
}
