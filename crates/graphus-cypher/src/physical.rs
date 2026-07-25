//! The Cypher **physical plan** and the heuristic, index-aware **physical planner**
//! (`04-technical-design.md` §7.1, §6.6).
//!
//! [`plan_physical`] lowers a [logical plan](crate::logical::LogicalOp) into a [`PhysicalPlan`]: the
//! tree of [`PhysicalOp`]s the executor (the next sub-task) consumes, plus the set of catalog
//! [`IndexId`](crate::catalog::IndexId)s the plan depends on (for cache invalidation, `04 §6.6`).
//! The physical plan makes the *strategy* choices the logical plan deliberately left open
//! (`04 §7.1`):
//!
//! > *"physical planner → physical plan (index seeks, expand-into vs expand-all, hash vs
//! > nested-loop join, sort, limit pushdown)"*.
//!
//! # Rule-based vs cost-based planning
//!
//! The planner has **two modes**, selected by whether graph [`Statistics`] are supplied:
//!
//! * [`plan_physical`] (and [`plan_physical_with_stats`] with `stats = None`) is **rule-based with
//!   index awareness** (`04 §6.6`): it makes the four obviously-sound strategy choices below and
//!   nothing else. This is the byte-for-byte stable plan the TCK runner and the server execute, and it
//!   is the deterministic *fallback* the cost-based mode starts from.
//! * [`plan_physical_with_stats`] with `stats = Some(..)` is **cost-based** (`00-overview` §6, task
//!   #65): it first builds the rule-based tree, then applies the bag-preserving rewrites in
//!   [the cost-based optimiser](self#cost-based-optimisation) — **join reordering**, **hash-join
//!   build-side selection**, and **cost-based access-path (seek-vs-scan) selection** — keeping only the
//!   cheaper alternative under the [cost model](crate::cost). Only the plan *shape* changes; the result
//!   bag is invariant (see each rewrite's soundness argument).
//!
//! Each rule below is chosen so it is *obviously* correct — it never changes the rows a plan produces,
//! only how they are produced.
//!
//! 1. **Index selection.** A [`NodeByLabelScan`](crate::logical::LogicalOp::NodeByLabelScan)
//!    immediately under a [`Filter`](crate::logical::LogicalOp::Filter) whose predicate is an
//!    **equality** on an *indexed* labelled property (`n.p = v`) becomes a
//!    [`NodeIndexSeek`](PhysicalOp::NodeIndexSeek); a **range** predicate (`n.p > v`, `<`, `>=`,
//!    `<=`) on an indexed property becomes a [`NodeIndexRangeSeek`](PhysicalOp::NodeIndexRangeSeek).
//!    A bare label scan with a matching **token-lookup** index becomes a
//!    [`TokenLookupScan`](PhysicalOp::TokenLookupScan). With no usable index the access falls back
//!    to [`NodeByLabelScan`](PhysicalOp::NodeByLabelScan) / [`AllNodesScan`](PhysicalOp::AllNodesScan)
//!    plus the residual [`Filter`](PhysicalOp::Filter). **Soundness:** a seek returns exactly the
//!    records matching the predicate the [`Filter`] tested, so consuming the predicate into the seek
//!    is equivalence-preserving; any predicate the seek does *not* fully cover is retained as a
//!    residual filter.
//! 2. **Expand-into vs expand-all** (`04 §7.1`). An [`Expand`](crate::logical::LogicalOp::Expand) is
//!    realised as [`ExpandInto`](PhysicalOp::ExpandInto) when **both** endpoints are already bound by
//!    the input (a connection/cycle check — enumerate the edges *between* two known nodes), else
//!    [`ExpandAll`](PhysicalOp::ExpandAll) (enumerate neighbours of the bound `from`). **Soundness:**
//!    both enumerate the same relationship set; expand-into is merely the specialisation that filters
//!    on a `to` already in scope.
//! 3. **Hash vs nested-loop join** (`04 §7.1`). The relational join points —
//!    [`Apply`](crate::logical::LogicalOp::Apply) and the distinct
//!    [`Union`](crate::logical::LogicalOp::Union) — pick a join *strategy* by a documented rule:
//!    an **equi-join** (the two sides share one or more join-key columns by name) compiles to a
//!    [`HashJoin`](PhysicalOp::HashJoin); otherwise a [`NestedLoopJoin`](PhysicalOp::NestedLoopJoin).
//!    See [`choose_join`]. **Soundness:** both compute the same correlated/combined result; the
//!    strategy is a performance choice only. (A correlated `Apply` whose right branch genuinely reads
//!    the left row through an [`Argument`](crate::logical::LogicalOp::Argument) is always a
//!    nested-loop — a hash join cannot express the per-row correlation.)
//! 4. **Sort/Limit pushdown** (`04 §7.1`). A [`Limit`](crate::logical::LogicalOp::Limit) directly
//!    over a [`Sort`](crate::logical::LogicalOp::Sort) fuses into a single
//!    [`TopN`](PhysicalOp::TopN) (compute only the top *k* rows instead of sorting all then
//!    truncating). A `Limit` directly over a **row-count-preserving** projection (a non-`DISTINCT`,
//!    non-aggregating [`Projection`](crate::logical::LogicalOp::Projection)) is pushed **below** the
//!    projection. **Soundness:** `TopN(k, sort) ≡ Limit(k, Sort(sort))` by definition; and pushing a
//!    `Limit` below a projection that maps rows one-to-one (no `DISTINCT`, no aggregation) yields the
//!    same first-*k* rows in the same order, because such a projection neither drops nor adds rows.
//!    The pushdown is explicitly **NOT** applied below a `DISTINCT` projection or an
//!    [`Aggregation`](crate::logical::LogicalOp::Aggregation) — those change the row count, so
//!    limiting first would change the result (a negative test guards this).
//!
//! # Covered vs deferred (named)
//!
//! **Covered:** all [`LogicalOp`](crate::logical::LogicalOp) variants are lowered to a physical
//! form (the relational, graph, write, and procedure operators carry through; the four decisions
//! above specialise where they apply). Index selection covers single-property **equality** and
//! **range** node predicates, the **`STARTS WITH` string-prefix** node predicate (a bounded range
//! seek over `[prefix, successor)`, `rmp` task #658), the **token-lookup** label scan, and
//! single-property **relationship** predicates routed through the catalog.
//!
//! **Cost-based (task #65, #366), only when statistics are supplied:** selectivity-driven
//! **access-path choice** (index seek vs label/token scan, [the seek-vs-scan rule](self#cost-based-optimisation)),
//! **inner-join reordering** and **hash-join build-side selection** over independent, write-free join
//! regions (System-R-style bottom-up dynamic programming), and **expand-direction reversal** — a
//! binary single hop whose *far* endpoint is index-servable is re-anchored on that endpoint (`seek +
//! reverse-expand` costed against `scan + forward-expand`, `rmp` task #366). The logical plan still
//! fixes the *rule-based* anchor; the optimiser may flip it when the cost model says the reversal
//! wins, enumerating the same directed edge set from the other end (see rule 3 below).
//!
//! **Deferred, by name:** (1) **multi-predicate composite-index seeds** beyond a single leading-key
//! predicate, and general predicate pushdown (`04 §6.6`); (2) **`AllRelationshipsScan` index
//! routing** — a relationship-type-only scan keeps its logical form (the relationship-property seek
//! requires a property predicate, lowered when a [`Filter`] supplies one over an expand, which is
//! itself later territory); (3) **composite multi-key seeks** — only a composite's *leading* key
//! drives a seek here, matching the catalog's
//! [`label_property`](crate::catalog::IndexCatalog::label_property) contract; (4) **`IN`-list index
//! acceleration**, and **`ENDS WITH` / `CONTAINS`** string acceleration (a suffix/substring is not a
//! contiguous key range — it needs a dedicated text index) — treated as residual filters in v1.
//! (`STARTS WITH` *is* accelerated, `rmp` task #658; see [`PhysicalOp::NodeIndexStartsWithSeek`].)
//!
//! # Cost-based optimisation
//!
//! [`plan_physical_with_stats`] with `stats = Some(..)` runs the rule-based planner, then a single
//! bottom-up optimisation pass over the resulting tree, applying three families of bag-preserving
//! rewrites, each gated on the [cost model](crate::cost):
//!
//! 1. **Access-path selection (seek vs scan).** At a seek (or a scan+filter) that the rule-based
//!    planner produced from a `Filter`-over-label-scan, the optimiser costs *both* realisations — the
//!    index seek (`seek + residual filter`) and the scan (`label/token scan + full filter`) — and keeps
//!    the cheaper. A selective predicate keeps the seek (today's behaviour); a non-selective one the
//!    histogram says matches most rows reverts to the scan. **Soundness:** both realisations produce
//!    exactly the rows the predicate selects — a seek returns precisely those rows; the residual filter
//!    is preserved either way — so the result bag is identical.
//! 2. **Join reordering + build-side selection.** A maximal connected region of *reorderable* binary
//!    joins ([`HashJoin`](PhysicalOp::HashJoin) or **cartesian** [`NestedLoopJoin`](PhysicalOp::NestedLoopJoin)
//!    over **independent** — non-correlated, write-free — sides) is flattened into its leaf operands
//!    and join graph, then re-assembled by **bottom-up dynamic programming** that minimises total cost,
//!    left-deep, with each hash join building its lower-cardinality side. **Soundness:** inner equi-join
//!    and cartesian product are commutative and associative, so any join order over the same operands
//!    yields the same result multiset; build-side choice only swaps a hash join's build/probe inputs,
//!    which the executor's symmetric `merge_rows` leaves bag-invariant. Correlated applies (an
//!    [`Argument`](PhysicalOp::Argument) on the spine) and any write-bearing subtree are **never**
//!    reordered.
//! 3. **Expand-direction reversal (`rmp` task #366).** A fresh, fixed-length, single
//!    [`ExpandAll`](PhysicalOp::ExpandAll) over a *pure label scan* of the anchor, whose **far**
//!    endpoint carries an index-servable predicate (a `Filter` stack above the expand pins
//!    `to.prop <op> v` plus `to`'s label), is re-anchored on `to`: seek `to`, then walk the
//!    **reversed** incidence to bind `from`, with `from`'s label and the unconsumed conjuncts
//!    re-applied as a residual filter. The optimiser costs `seek + reverse-expand` against the
//!    rule-based `scan + forward-expand` and keeps the cheaper. **Soundness:** the pattern's
//!    relationship direction is preserved exactly — a directed edge `a→b` is the *same* `RelId`
//!    whether enumerated as `b`'s `Outgoing` incidence from anchor `a` or `a`'s `Incoming` incidence
//!    from anchor `b` (the same relationship-set equality that makes `ExpandInto` sound, rule 2
//!    above) — so the reversal binds the identical `{from, relationship, to}` columns to the
//!    identical entities and the result bag (and any downstream order) is byte-identical.
//!
//! The optimiser recurses into every operand and child, so all three rewrites apply throughout the
//! tree.
//! Cost ties break on a stable structural key, so plan choice is deterministic for fixed statistics.

use crate::ast::{
    BinaryOp, Expr, ExprKind, Label, LabelExpr, PredicateOp, QueryPrefix, RelType, SortDirection,
};
use crate::cardinality::estimate_rows;
use crate::catalog::{IndexCatalog, IndexDescriptor, IndexId};
use crate::cost::estimate_cost;
use crate::logical::{
    CreatePart, LogicalOp, ProjectionColumn, QppStep, RemoveOp, SetOp, SortKey, Var, YieldColumn,
};
use crate::statistics::Statistics;
use graphus_core::Value;
use graphus_core::value::spatial::Crs;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

/// A compiled **physical plan**: the operator tree plus the catalog indexes it depends on.
///
/// The dependency set is the mechanism `04 §6.6` describes — *"plans record which indexes they
/// depend on so the plan cache is invalidated on schema/index change"*. The plan cache
/// ([`crate::plan_cache`]) keys on `schema_version` (bumped on any DDL/index change), and the
/// recorded [`IndexId`]s additionally enable finer-grained invalidation later.
///
/// A `PhysicalPlan` is **parameter-independent** (`04 §7.5`): it embeds no bound parameter values,
/// so a single compiled plan is reused across every parameter set (parameters bind at execution via
/// [`crate::binding::bind_parameters`]).
#[derive(Debug, Clone, PartialEq)]
#[must_use]
pub struct PhysicalPlan {
    /// The root physical operator (the last thing computed; data flows leaves → root).
    pub root: PhysicalOp,
    /// The catalog index ids this plan's access paths depend on, ascending and de-duplicated.
    index_dependencies: BTreeSet<IndexId>,
    /// The estimated number of rows the plan's root emits, from the cardinality estimator
    /// ([`crate::cardinality::estimate_rows`]) over the optional graph [`Statistics`].
    estimated_rows: f64,
    /// Whether the **cost-based** optimiser ran (graph [`Statistics`] were supplied to
    /// [`plan_physical_with_stats`]) rather than only the rule-based lowering. Reported verbatim as the
    /// plan description's root `planner` argument (`rmp` #752) — never guessed.
    cost_based: bool,
    /// The statement's `EXPLAIN` / `PROFILE` prefix, if any (`rmp` #752).
    ///
    /// The prefix is a property of the *statement*, not of the operator tree: it changes only whether the
    /// plan is executed and whether runtime counters are recorded, never the plan's shape or its result.
    /// It rides on the compiled plan so that the single artefact the plan cache stores — and the executor
    /// receives — carries everything needed to run the statement, with no second parse.
    prefix: Option<QueryPrefix>,
}

/// The read/write classification of a compiled [`PhysicalPlan`] (`rmp` task #511).
///
/// This is the Bolt `RUN` summary's **query type** (`metadata.type`): the official driver ecosystem
/// reports `"r"` / `"w"` / `"rw"` / `"s"` for read / write / read-write / schema statements. Graphus
/// computes the data-statement classes here; the schema (`"s"`) class is **not** represented because
/// DDL is intercepted before the Cypher pipeline (a later task), so a `PhysicalPlan` is only ever
/// `Read`, `Write`, or `ReadWrite`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use]
pub enum QueryType {
    /// A read-only statement: no write operator anywhere in the plan (Bolt `"r"`).
    ///
    /// E.g. `MATCH (n) RETURN n`.
    Read,
    /// A pure write: the plan contains a write operator **and** its root is a write (so it yields no
    /// result rows — no `RETURN`, Bolt `"w"`).
    ///
    /// E.g. `CREATE (n)`, `MATCH (n) SET n.x = 1`, `MATCH (a)-[r]->(b) DETACH DELETE a`.
    Write,
    /// A read-write statement: the plan contains a write operator but its root is **not** a write —
    /// a projection sits above the write, so the statement returns rows (Bolt `"rw"`).
    ///
    /// E.g. `CREATE (n) RETURN n`, `MATCH (n) SET n.x = 1 RETURN n`.
    ReadWrite,
}

impl PhysicalPlan {
    /// The catalog [`IndexId`]s this plan depends on, ascending (`04 §6.6`).
    ///
    /// A change to any of these indexes (or a `schema_version` bump) must invalidate the cached
    /// plan ([`crate::plan_cache`]).
    pub fn index_dependencies(&self) -> impl Iterator<Item = IndexId> + '_ {
        self.index_dependencies.iter().copied()
    }

    /// The read/write [`QueryType`] of this plan — the Bolt `RUN` summary's `metadata.type`
    /// (`rmp` task #511).
    ///
    /// Classification is structural and exact, reusing the same write-operator predicates the planner
    /// and executor already rely on (so it can never drift from how the plan actually behaves):
    ///
    /// - **No** write operator anywhere ⇒ [`QueryType::Read`].
    /// - A write operator **at the root** ⇒ [`QueryType::Write`]: a write root has no `RETURN` above
    ///   it (a `RETURN` would put a projection at the root), so the statement yields zero rows.
    /// - A write operator present but **not** at the root ⇒ [`QueryType::ReadWrite`]: a projection (or
    ///   other row-emitting operator) sits above the write, so the statement returns rows.
    ///
    /// The schema (`"s"`) class is not produced here: DDL is intercepted ahead of the Cypher pipeline,
    /// so a compiled plan is only ever read, write, or read-write.
    pub fn query_type(&self) -> QueryType {
        if !contains_write(&self.root) {
            QueryType::Read
        } else if root_is_write(&self.root) {
            QueryType::Write
        } else {
            QueryType::ReadWrite
        }
    }

    /// Whether this plan invokes a stored/user/GDS/`db.*` procedure (`CALL …`) anywhere in the tree
    /// (`rmp` task #548).
    ///
    /// The server uses this to keep a procedure-calling read **inline** on the engine thread rather
    /// than dispatching it to the off-thread reader pool (`rmp` task #543): a procedure can reach a
    /// derived-accelerator seam (full-text / spatial) that has no scan fallback and declines on the
    /// reader's owned read view, surfacing as a spurious "no such index" error. The predicate is an
    /// **exhaustive** structural walk — like the sibling [`contains_write`] it matches every
    /// [`PhysicalOp`] variant with no `_` wildcard, so a newly-added operator with children fails to
    /// compile until it is explicitly classified here, rather than silently letting a nested
    /// `ProcedureCall` escape detection and be mis-dispatched off-thread.
    #[must_use]
    pub fn calls_procedure(&self) -> bool {
        contains_procedure_call(&self.root)
    }

    /// Whether **every** procedure this plan invokes is **reader-safe** (`rmp` task #546) — i.e. the
    /// plan calls no procedure at all, or every `CALL` targets a procedure the `registry` classifies
    /// reader-safe ([`ProcedureRegistry::is_reader_safe`](crate::procedure_registry::ProcedureRegistry::is_reader_safe)).
    ///
    /// The server uses this — instead of the blanket [`calls_procedure`](Self::calls_procedure) — as
    /// the off-thread reader-pool eligibility gate: a read-only auto-commit statement whose procedures
    /// are all reader-safe (GDS algorithms, `db.*` introspection, `db.index.fulltext.queryNodes`) runs
    /// correctly on a reader thread over the captured read view, so it scales across cores instead of
    /// being pinned to the single engine thread. A plan that calls even one non-reader-safe procedure
    /// (a UDP that may write, or one whose side effects are not thread-safe) stays inline.
    ///
    /// Like [`calls_procedure`](Self::calls_procedure) this is an **exhaustive** structural walk (no
    /// `_` wildcard), so a newly-added child-bearing operator fails to compile until it is classified,
    /// rather than silently letting a nested `ProcedureCall` escape the reader-safety check.
    #[must_use]
    pub fn calls_only_reader_safe_procedures(
        &self,
        registry: &dyn crate::procedure_registry::ProcedureRegistry,
    ) -> bool {
        all_procedure_calls_reader_safe(&self.root, registry)
    }

    /// Every `(label, property, seek_value)` this plan will ask
    /// [`index_seek_eq`](crate::graph_access::GraphAccess::index_seek_eq) for and whose seek value is
    /// **statically knowable** at dispatch — i.e. resolvable *now*, on the engine thread, to exactly the
    /// value the executor will later compute (`rmp` task #755, Slice S2).
    ///
    /// The engine uses this to pre-run those seeks against the live index and hand the results to an
    /// off-thread reader as an [`IndexCandidateCapture`](crate::read_source::IndexCandidateCapture).
    ///
    /// # What "statically knowable" means, and why the test is the expression itself
    ///
    /// A seek value qualifies iff it is an [`ExprKind::Literal`] or an [`ExprKind::Parameter`] (the
    /// latter is the overwhelmingly common shape: auto-parameterisation turns `{email: 'u7@x.io'}` into
    /// a `$param`). No plan-position analysis is needed, because those two forms **cannot** reference a
    /// row: they are row-independent *by construction*. That single test excludes, in one stroke:
    ///
    /// * **correlated** seeks (`rmp` #708/#764 — `UNWIND rows AS t MATCH (b:L {p: t.k})`), whose value
    ///   is a `Property`/`Variable` expression keyed off the left row; and
    /// * every **non-deterministic or graph-dependent** expression (`date()`, `rand()`, a function of
    ///   another node), which could evaluate differently at dispatch than in the executor.
    ///
    /// Anything else yields no entry, the reader's lookup misses, and it declines to its exact scan
    /// fallback — so a value this method fails to anticipate costs performance, never rows.
    ///
    /// A missing parameter resolves to no entry here; the executor evaluates it to `Null`, which is
    /// unindexable and declines anyway — the two agree.
    #[must_use]
    pub fn static_node_index_eq_seeks(
        &self,
        params: &crate::binding::BoundParameters,
    ) -> Vec<(String, String, graphus_core::Value)> {
        let mut out = Vec::new();
        collect_static_node_index_eq_seeks(&self.root, params, &mut out);
        out
    }

    /// Every node-property **RANGE seek** this plan will ask
    /// [`index_seek_range`](crate::graph_access::GraphAccess::index_seek_range) for, resolved to the exact
    /// `(label, property, lower, upper)` the executor will pass — whenever the bound is statically knowable
    /// (`rmp` task #768). Covers all three range-index operators: [`NodeIndexRangeSeek`](PhysicalOp::NodeIndexRangeSeek)
    /// (a `<`/`<=`/`>`/`>=` bound), [`NodeIndexScan`](PhysicalOp::NodeIndexScan) (`IS NOT NULL` → the open
    /// `(None, None)` range), and [`NodeIndexStartsWithSeek`](PhysicalOp::NodeIndexStartsWithSeek)
    /// (`STARTS WITH` → `[prefix, successor(prefix))`). The bound derivation mirrors the executor's byte
    /// for byte, so the reader keys the memo identically; a value it fails to anticipate costs the
    /// acceleration, never rows (the reader misses and takes the exact scan).
    #[must_use]
    pub fn static_node_index_range_seeks(
        &self,
        params: &crate::binding::BoundParameters,
    ) -> Vec<StaticRangeSeek> {
        let mut out = Vec::new();
        collect_static_node_range_seeks(&self.root, params, &mut out);
        out
    }

    /// Every node **COMPOSITE (multi-property) equality seek** this plan will ask
    /// [`index_seek_composite_eq`](crate::graph_access::GraphAccess::index_seek_composite_eq) for, resolved
    /// to `(label, properties, values)` — but only when **every** per-key seek value is statically knowable
    /// (`rmp` task #768). A single correlated key disqualifies the whole tuple (the reader would then miss
    /// and take the exact scan).
    #[must_use]
    pub fn static_node_composite_seeks(
        &self,
        params: &crate::binding::BoundParameters,
    ) -> Vec<StaticCompositeSeek> {
        let mut out = Vec::new();
        collect_static_node_composite_seeks(&self.root, params, &mut out);
        out
    }

    /// Every node **TEXT (trigram) seek** this plan will ask
    /// [`index_seek_text`](crate::graph_access::GraphAccess::index_seek_text) for, resolved to
    /// `(label, property, op, needle)` — but only when the needle is a statically-knowable **string**
    /// (`rmp` task #768). A non-string needle matches nothing and falls to a scan in the executor, so it is
    /// not captured.
    #[must_use]
    pub fn static_node_text_seeks(
        &self,
        params: &crate::binding::BoundParameters,
    ) -> Vec<StaticTextSeek> {
        let mut out = Vec::new();
        collect_static_node_text_seeks(&self.root, params, &mut out);
        out
    }

    /// Every RELATIONSHIP-property **equality seek** this plan will ask
    /// [`index_seek_rel_eq`](crate::graph_access::GraphAccess::index_seek_rel_eq) for, resolved to
    /// `(rel_type, property, value)` when the value is statically knowable (`rmp` task #769). The
    /// relationship twin of [`static_node_index_eq_seeks`](Self::static_node_index_eq_seeks).
    #[must_use]
    pub fn static_rel_index_eq_seeks(
        &self,
        params: &crate::binding::BoundParameters,
    ) -> Vec<(String, String, graphus_core::Value)> {
        let mut out = Vec::new();
        collect_static_rel_eq_seeks(&self.root, params, &mut out);
        out
    }

    /// Every RELATIONSHIP-property **RANGE seek** this plan will ask
    /// [`index_seek_rel_range`](crate::graph_access::GraphAccess::index_seek_rel_range) for, resolved to
    /// `(rel_type, property, lower, upper)` (`rmp` task #769/#680). Relationships have a single range
    /// operator ([`RelIndexRangeSeek`](PhysicalOp::RelIndexRangeSeek)) — there is no rel existence-scan or
    /// rel starts-with operator — so this covers the whole rel-range surface.
    #[must_use]
    pub fn static_rel_index_range_seeks(
        &self,
        params: &crate::binding::BoundParameters,
    ) -> Vec<StaticRangeSeek> {
        let mut out = Vec::new();
        collect_static_rel_range_seeks(&self.root, params, &mut out);
        out
    }

    /// Every RELATIONSHIP **COMPOSITE equality seek** this plan will ask
    /// [`index_seek_rel_composite_eq`](crate::graph_access::GraphAccess::index_seek_rel_composite_eq) for,
    /// resolved to `(rel_type, properties, values)` when every per-key value is statically knowable
    /// (`rmp` task #769/#666).
    #[must_use]
    pub fn static_rel_composite_seeks(
        &self,
        params: &crate::binding::BoundParameters,
    ) -> Vec<StaticCompositeSeek> {
        let mut out = Vec::new();
        collect_static_rel_composite_seeks(&self.root, params, &mut out);
        out
    }

    /// Every node **SPATIAL (point) proximity seek** this plan will ask
    /// [`index_seek_spatial`](crate::graph_access::GraphAccess::index_seek_spatial) for, resolved to
    /// `(label, property, center_x, center_y, radius)` (`rmp` task #770).
    ///
    /// # Why this needs no `params` (the VECTOR contrast)
    ///
    /// Unlike an ANN probe (whose query vector is a run-time value the off-thread reader cannot
    /// pre-capture — `rmp` #770 keeps `db.index.vector.*` inline), a [`SpatialIndexSeek`](PhysicalOp::SpatialIndexSeek)'s
    /// centre and radius are **plan-time-folded `f64` constants** (a proximity predicate whose operands are
    /// not compile-time constants never reaches this operator — the planner falls back to scan + filter,
    /// see [`binding::params_in_physical`](crate::binding)). So the candidate superset is fully
    /// determined at dispatch and can be memoised for the reader exactly like the #768/#769 seeks — no
    /// parameter resolution is involved.
    #[must_use]
    pub fn static_node_spatial_seeks(&self) -> Vec<StaticSpatialSeek> {
        let mut out = Vec::new();
        collect_static_node_spatial_seeks(&self.root, &mut out);
        out
    }

    /// Every RELATIONSHIP **SPATIAL (point) proximity seek** this plan will ask
    /// [`index_seek_spatial_rel`](crate::graph_access::GraphAccess::index_seek_spatial_rel) for, resolved
    /// to `(rel_type, property, center_x, center_y, radius)` (`rmp` task #770/#664) — the relationship
    /// twin of [`static_node_spatial_seeks`](Self::static_node_spatial_seeks). Same constant-centre
    /// argument: [`RelSpatialIndexSeek`](PhysicalOp::RelSpatialIndexSeek) carries plan-time-folded `f64`s.
    #[must_use]
    pub fn static_rel_spatial_seeks(&self) -> Vec<StaticSpatialSeek> {
        let mut out = Vec::new();
        collect_static_rel_spatial_seeks(&self.root, &mut out);
        out
    }

    /// Whether this plan depends on `id`.
    #[must_use]
    pub fn depends_on(&self, id: IndexId) -> bool {
        self.index_dependencies.contains(&id)
    }

    /// The estimated number of rows this plan's root operator emits (`00-overview` §6).
    ///
    /// This is the cardinality estimator's verdict ([`crate::cardinality::estimate_rows`]) computed
    /// against the [`Statistics`] supplied to [`plan_physical_with_stats`] — exact where the backend
    /// tracks counts, and the documented `DEFAULT_*` fallbacks otherwise (so [`plan_physical`], which
    /// passes no statistics, still yields a finite, positive estimate). It is the **root** cardinality:
    /// the estimated size of the whole plan's result, which the cost-based rewrites preserve (they
    /// change *how* the result is produced, never the multiset of rows). Always finite and `>= 0.0`
    /// (the estimator guarantees it).
    #[must_use]
    pub fn estimated_rows(&self) -> f64 {
        self.estimated_rows
    }

    /// Whether the **cost-based** optimiser ran for this plan (graph statistics were available), as
    /// opposed to the purely rule-based lowering. Surfaced as the plan description's root `planner`
    /// argument (`"COST"` / `"RULE"`, `rmp` #752).
    #[must_use]
    pub fn cost_based(&self) -> bool {
        self.cost_based
    }

    /// The statement's `EXPLAIN` / `PROFILE` prefix, if any (`rmp` #752).
    ///
    /// `None` for an ordinary statement — the overwhelmingly common case, and the only one the TCK, the
    /// DST simulator and library callers ever produce, so their behaviour is untouched.
    #[must_use]
    pub fn prefix(&self) -> Option<QueryPrefix> {
        self.prefix
    }

    /// Attaches the statement's `EXPLAIN` / `PROFILE` prefix to a freshly-planned statement
    /// (`rmp` #752).
    ///
    /// The compile pipeline calls this once, right after [`plan_physical_with_stats`], with the prefix the
    /// parser found on the [`Query`](crate::ast::Query). It is a property of the statement text, so it is
    /// set *outside* the planner (which only ever sees the prefix-free logical plan) and travels with the
    /// compiled plan into the plan cache and the executor.
    pub fn with_prefix(mut self, prefix: Option<QueryPrefix>) -> Self {
        self.prefix = prefix;
        self
    }
}

impl PhysicalOp {
    /// This operator's **sub-plans**, in the canonical order a plan description lists them
    /// (`rmp` #752).
    ///
    /// This is the single, exhaustive definition of "the children of a physical operator". Both the plan
    /// description ([`crate::plan_description`]) and the profiling operator-id numbering
    /// ([`crate::profile`]) walk the plan through it, so the tree the client sees and the tree the
    /// runtime counters are attributed to are numbered by *one* traversal and can never drift apart.
    ///
    /// Every sub-plan is included, whether or not the executor builds it eagerly: a
    /// [`NestedLoopJoin`](Self::NestedLoopJoin)'s right branch and a [`Foreach`](Self::Foreach)'s body are
    /// rebuilt per row from a template, and a plan description that omitted them would hide real work.
    #[must_use]
    pub fn children(&self) -> Vec<&PhysicalOp> {
        match self {
            // Leaves: no sub-plan.
            Self::AllNodesScan { .. }
            | Self::NodeByLabelScan { .. }
            | Self::TokenLookupScan { .. }
            | Self::NodeIndexSeek { .. }
            | Self::NodeCompositeIndexSeek { .. }
            | Self::NodeLabelScanEq { .. }
            | Self::NodeIndexRangeSeek { .. }
            | Self::NodeIndexScan { .. }
            | Self::NodeIndexStartsWithSeek { .. }
            | Self::SpatialIndexSeek { .. }
            | Self::NodeTextIndexSeek { .. }
            | Self::AllRelationshipsScan { .. }
            | Self::RelIndexSeek { .. }
            | Self::RelIndexRangeSeek { .. }
            | Self::RelCompositeIndexSeek { .. }
            | Self::RelSpatialIndexSeek { .. }
            | Self::Argument { .. }
            | Self::Empty => Vec::new(),

            // One sub-plan.
            Self::ExpandAll { input, .. }
            | Self::ExpandInto { input, .. }
            | Self::NamedPath { input, .. }
            | Self::ShortestPath { input, .. }
            | Self::QuantifiedPath { input, .. }
            | Self::Filter { input, .. }
            | Self::Projection { input, .. }
            | Self::Aggregation { input, .. }
            | Self::Sort { input, .. }
            | Self::TopN { input, .. }
            | Self::Skip { input, .. }
            | Self::Limit { input, .. }
            | Self::Eager { input }
            | Self::Unwind { input, .. }
            | Self::LoadCsv { input, .. }
            | Self::Optional { input, .. }
            | Self::Create { input, .. }
            | Self::Merge { input, .. }
            | Self::SetClause { input, .. }
            | Self::Delete { input, .. }
            | Self::Remove { input, .. } => vec![input],

            // Two sub-plans.
            Self::NestedLoopJoin { left, right }
            | Self::HashJoin { left, right, .. }
            | Self::Union { left, right, .. } => vec![left, right],
            // FOREACH's per-element update body is a sub-plan, rebuilt per element by the executor.
            Self::Foreach { input, body, .. } => vec![input, body],

            // An optional sub-plan (a leading `CALL` has no upstream relation).
            Self::ProcedureCall { input, .. } => {
                input.iter().map(std::convert::AsRef::as_ref).collect()
            }
        }
    }

    /// The operator's **type name** — the `operatorType` of a plan description (`rmp` #752).
    ///
    /// These are Graphus's own physical-operator names (the ones this crate's planner produces and this
    /// crate's [`Display`](fmt::Display) renders), which is exactly what an operator inspecting a plan
    /// needs in order to assert *which access path ran* — e.g. `RelIndexRangeSeek` versus
    /// `AllRelationshipsScan`.
    #[must_use]
    pub fn operator_type(&self) -> &'static str {
        match self {
            Self::AllNodesScan { .. } => "AllNodesScan",
            Self::NodeByLabelScan { .. } => "NodeByLabelScan",
            Self::TokenLookupScan { .. } => "TokenLookupScan",
            Self::NodeIndexSeek { .. } => "NodeIndexSeek",
            Self::NodeCompositeIndexSeek { .. } => "NodeCompositeIndexSeek",
            Self::NodeLabelScanEq { .. } => "NodeLabelScanEq",
            Self::NodeIndexRangeSeek { .. } => "NodeIndexRangeSeek",
            Self::NodeIndexScan { .. } => "NodeIndexScan",
            Self::NodeIndexStartsWithSeek { .. } => "NodeIndexStartsWithSeek",
            Self::SpatialIndexSeek { .. } => "SpatialIndexSeek",
            Self::NodeTextIndexSeek { .. } => "NodeTextIndexSeek",
            Self::AllRelationshipsScan { .. } => "AllRelationshipsScan",
            Self::RelIndexSeek { .. } => "RelIndexSeek",
            Self::RelIndexRangeSeek { .. } => "RelIndexRangeSeek",
            Self::RelCompositeIndexSeek { .. } => "RelCompositeIndexSeek",
            Self::RelSpatialIndexSeek { .. } => "RelSpatialIndexSeek",
            Self::Argument { .. } => "Argument",
            Self::Empty => "Empty",
            Self::ExpandAll { .. } => "ExpandAll",
            Self::ExpandInto { .. } => "ExpandInto",
            Self::NamedPath { .. } => "NamedPath",
            Self::ShortestPath { .. } => "ShortestPath",
            Self::QuantifiedPath { .. } => "QuantifiedPath",
            Self::Filter { .. } => "Filter",
            Self::Projection { .. } => "Projection",
            Self::Aggregation { .. } => "Aggregation",
            Self::Sort { .. } => "Sort",
            Self::TopN { .. } => "TopN",
            Self::Skip { .. } => "Skip",
            Self::Limit { .. } => "Limit",
            Self::Eager { .. } => "Eager",
            Self::Unwind { .. } => "Unwind",
            Self::LoadCsv { .. } => "LoadCsv",
            Self::NestedLoopJoin { .. } => "NestedLoopJoin",
            Self::HashJoin { .. } => "HashJoin",
            Self::Union { .. } => "Union",
            Self::Optional { .. } => "Optional",
            Self::Create { .. } => "Create",
            Self::Merge { .. } => "Merge",
            Self::SetClause { .. } => "SetClause",
            Self::Delete { .. } => "Delete",
            Self::Remove { .. } => "Remove",
            Self::Foreach { .. } => "Foreach",
            Self::ProcedureCall { .. } => "ProcedureCall",
        }
    }

    /// The variables this (sub)plan binds, in introduction order — the `identifiers` of a plan
    /// description (`rmp` #752).
    ///
    /// Reuses the planner's own bound-variable analysis, so the identifiers reported to a client are
    /// exactly the ones the operator makes available to its parent (a `Projection` / `Aggregation`
    /// resets the visible set to its output columns, as the projection-boundary rule requires).
    #[must_use]
    pub fn identifiers(&self) -> Vec<String> {
        bound_var_names(self)
    }

    /// The number of operators in this subtree, `self` included (`rmp` #752): the size of the
    /// contiguous id range a pre-order numbering assigns to it.
    #[must_use]
    pub fn subtree_len(&self) -> usize {
        1 + self
            .children()
            .into_iter()
            .map(PhysicalOp::subtree_len)
            .sum::<usize>()
    }
}

impl fmt::Display for PhysicalPlan {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.root.fmt(f)
    }
}

/// The bound a [`NodeIndexRangeSeek`](PhysicalOp::NodeIndexRangeSeek) uses for one side of a range.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[must_use]
pub enum RangeBound {
    /// `>` (strictly greater than the bound value).
    GreaterThan,
    /// `>=` (greater than or equal).
    GreaterOrEqual,
    /// `<` (strictly less than).
    LessThan,
    /// `<=` (less than or equal).
    LessOrEqual,
}

impl RangeBound {
    /// The bound implied by a comparison operator with the property on the **left**
    /// (`n.p <op> value`). Returns `None` for non-range operators.
    fn from_property_lhs(op: BinaryOp) -> Option<Self> {
        match op {
            BinaryOp::Gt => Some(Self::GreaterThan),
            BinaryOp::Gte => Some(Self::GreaterOrEqual),
            BinaryOp::Lt => Some(Self::LessThan),
            BinaryOp::Lte => Some(Self::LessOrEqual),
            _ => None,
        }
    }

    /// The symmetric bound when the property is on the **right** (`value <op> n.p`), i.e. the
    /// operator is mirrored.
    fn mirrored(self) -> Self {
        match self {
            Self::GreaterThan => Self::LessThan,
            Self::GreaterOrEqual => Self::LessOrEqual,
            Self::LessThan => Self::GreaterThan,
            Self::LessOrEqual => Self::GreaterOrEqual,
        }
    }

    /// The operator spelling for plan rendering.
    const fn symbol(self) -> &'static str {
        match self {
            Self::GreaterThan => ">",
            Self::GreaterOrEqual => ">=",
            Self::LessThan => "<",
            Self::LessOrEqual => "<=",
        }
    }

    /// The [`BinaryOp`] this bound represents with the property on the **left** (`n.p <op> value`).
    /// The inverse of [`from_property_lhs`](Self::from_property_lhs); used by the cost-based optimiser
    /// to reconstruct a range seek's consumed predicate when costing the scan alternative.
    const fn to_binary_op(self) -> BinaryOp {
        match self {
            Self::GreaterThan => BinaryOp::Gt,
            Self::GreaterOrEqual => BinaryOp::Gte,
            Self::LessThan => BinaryOp::Lt,
            Self::LessOrEqual => BinaryOp::Lte,
        }
    }
}

/// Which string predicate a [`NodeTextIndexSeek`](PhysicalOp::NodeTextIndexSeek) serves (`rmp` task
/// #662). The trigram text index accelerates all three, using unanchored / head-anchored /
/// tail-anchored trigrams respectively; the executor picks the matching
/// [`TrigramIndex`](graphus_index::TrigramIndex) query.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[must_use]
pub enum TextSeekOp {
    /// `n.p CONTAINS <needle>` — substring match (unanchored trigrams).
    Contains,
    /// `n.p ENDS WITH <needle>` — suffix match (tail-anchored trigrams).
    EndsWith,
    /// `n.p STARTS WITH <needle>` — prefix match (head-anchored trigrams).
    StartsWith,
}

impl TextSeekOp {
    /// The operator spelling for plan rendering.
    const fn symbol(self) -> &'static str {
        match self {
            Self::Contains => "CONTAINS",
            Self::EndsWith => "ENDS WITH",
            Self::StartsWith => "STARTS WITH",
        }
    }
}

/// A node in a [physical plan](PhysicalPlan) tree: one executor-ready operator (`04 §7.1`).
///
/// The relational, graph, write, and procedure operators mirror their [logical
/// counterparts](crate::logical::LogicalOp) one-for-one (the executor needs them all); the
/// **physical specialisations** — index seeks, expand-into/all, hash/nested-loop join, top-n — are
/// the extra variants the physical planner introduces.
#[derive(Debug, Clone, PartialEq)]
#[must_use]
pub enum PhysicalOp {
    // ---- leaf reads (physical access paths) ---------------------------------------------------
    /// Full all-nodes store scan (fallback for an unlabelled node, `04 §7.1`).
    AllNodesScan {
        /// The node variable bound by each row.
        variable: Var,
    },
    /// Label scan via a full store scan filtered by label (fallback when no token-lookup index
    /// exists for the label).
    NodeByLabelScan {
        /// The node variable bound by each row.
        variable: Var,
        /// The label scanned for.
        label: Label,
    },
    /// **Token-lookup index scan** for `MATCH (n:Label)` — a per-token range scan over the
    /// label/token-lookup index instead of a full store scan (`04 §6.2`).
    TokenLookupScan {
        /// The node variable bound by each row.
        variable: Var,
        /// The label served by the token-lookup index.
        label: Label,
        /// The catalog index backing the scan.
        index: IndexId,
    },
    /// **Index equality seek**: records of `label` whose `property` equals the seek expression
    /// (`04 §7.1` *"index seeks"*). The `value` expression is the unevaluated AST (literal or
    /// parameter), evaluated by the executor at run time.
    NodeIndexSeek {
        /// The node variable bound by each row.
        variable: Var,
        /// The label the index covers.
        label: Label,
        /// The indexed property key.
        property: String,
        /// The equality seek value (unevaluated AST; commonly a parameter after auto-parameterisation).
        value: Expr,
        /// Emit candidates in ascending Cypher `property` order (ties broken by node id) so a matching
        /// single-key `ORDER BY property` above can elide its [`Sort`](Self::Sort) (`rmp` task #665,
        /// part B); `false` leaves the emission order unspecified (node-id order in practice). Set only
        /// by [`elide_sort_over_ordered_index`].
        ordered: bool,
        /// The catalog index backing the seek.
        index: IndexId,
    },
    /// **Composite (multi-property) index equality seek** (`rmp` task #657): records of `label` whose
    /// current values of `properties` (in the composite key's declared order) equal `values`
    /// element-wise — served by the composite B+-tree in a **single** seek, consuming a run of leading
    /// equality conjuncts (`MATCH (n:L {a: …, b: …})` / `WHERE n.a = … AND n.b = …`) that would
    /// otherwise be a leading-key seek + residual filter.
    ///
    /// `properties` and `values` are parallel and cover the composite index's **full** ordered key
    /// tuple (the planner only emits this when every key has an equality conjunct). The seek returns a
    /// **candidate** set; the executor re-checks each candidate's visibility, current label and current
    /// per-property values, so an over-broad candidate never reaches the result — and it falls back to a
    /// label scan + residual equality filters when the seam has no usable composite index.
    NodeCompositeIndexSeek {
        /// The node variable bound by each row.
        variable: Var,
        /// The label the composite index covers.
        label: Label,
        /// The indexed property keys, in the composite key's declared order (two or more).
        properties: Vec<String>,
        /// The per-key equality seek values (parallel to `properties`; unevaluated AST).
        values: Vec<Expr>,
        /// The catalog index backing the seek.
        index: IndexId,
    },
    /// **Precise equality-filtered label scan** (`rmp` task #325): records of `label` whose `property`
    /// equals the seek expression, served by a **full store scan** (the path chosen when no derived
    /// property index covers `(label, property)`).
    ///
    /// Result-equivalent to a [`NodeByLabelScan`](Self::NodeByLabelScan) wrapped in an equality
    /// [`Filter`](Self::Filter) — but it routes through the [`scan_filter_eq`](crate::graph_access::GraphAccess::scan_filter_eq)
    /// seam, which builds an SSI read dependency on **only the matching nodes** (plus the precise
    /// `Equality` predicate marker), instead of the blanket "mark every live node" footprint a bare label
    /// scan registers. That blanket footprint manufactured reciprocal rw-edges between transactions
    /// matching **disjoint** keys, producing a storm of false serialization aborts; this operator gives
    /// the scan path the same tight footprint the indexed [`NodeIndexSeek`](Self::NodeIndexSeek) already
    /// has. The `value` expression is the unevaluated AST, evaluated by the executor at run time.
    NodeLabelScanEq {
        /// The node variable bound by each row.
        variable: Var,
        /// The label scanned for.
        label: Label,
        /// The equality-filtered property key.
        property: String,
        /// The equality seek value (unevaluated AST; commonly a parameter after auto-parameterisation).
        value: Expr,
    },
    /// **Index range seek**: records of `label` whose `property` satisfies a range predicate
    /// (`04 §7.1`).
    NodeIndexRangeSeek {
        /// The node variable bound by each row.
        variable: Var,
        /// The label the index covers.
        label: Label,
        /// The indexed property key.
        property: String,
        /// The range bound operator (`>`, `>=`, `<`, `<=`).
        bound: RangeBound,
        /// The bound value expression (unevaluated AST).
        value: Expr,
        /// Emit candidates in ascending Cypher `property` order (ties broken by node id) so a matching
        /// single-key `ORDER BY property` above can elide its [`Sort`](Self::Sort) (`rmp` task #665,
        /// part B); `false` leaves the emission order unspecified (node-id order in practice). Set only
        /// by [`elide_sort_over_ordered_index`].
        ordered: bool,
        /// The catalog index backing the seek.
        index: IndexId,
    },
    /// **Full property-index scan** (`rmp` task #665, part A): every visible node of `label` that has a
    /// **non-null** value for `property`, streamed from the order-preserving range index instead of a
    /// full store scan. Serves `MATCH (n:L) WHERE n.p IS NOT NULL` (an *existence* predicate): every
    /// entry in a property index has a present, non-null value, so scanning the whole index yields
    /// exactly the nodes that carry the property — cheaper than a store scan when the property is
    /// sparse (the Neo4j `NodeIndexScan` access path).
    ///
    /// The scan returns a **candidate** set the seam re-checks (visible + carries the label + the
    /// current value is non-null), so a stale index entry (the value was since deleted or changed) is
    /// dropped; and the exact `IS NOT NULL` predicate is **also retained as a residual
    /// [`Filter`](Self::Filter) above this operator** (see [`Planner::lower_filter`]), so the
    /// scan-fallback path — a full label scan taken when no derived index is available at run time (the
    /// off-thread reader, or a seam with no index) — is trimmed to the identical result. `IS NULL` is
    /// **not** served here (an index cannot witness *absence*) and stays a scan + filter.
    ///
    /// When `ordered` is set the executor emits the candidates in ascending Cypher `property` order
    /// (ties broken by node id), so an `ORDER BY n.property` above needs no separate
    /// [`Sort`](Self::Sort) (see [`elide_sort_over_ordered_index`]).
    NodeIndexScan {
        /// The node variable bound by each row.
        variable: Var,
        /// The label the index covers.
        label: Label,
        /// The indexed property key (present and non-null for every emitted node).
        property: String,
        /// Emit candidates in ascending Cypher `property` order (ties broken by node id) to satisfy a
        /// provided-order `ORDER BY property`; `false` leaves the emission order unspecified.
        ordered: bool,
        /// The catalog index backing the scan.
        index: IndexId,
    },
    /// **String-prefix index seek** (`rmp` task #658): records of `label` whose string `property`
    /// begins with `prefix` (`n.p STARTS WITH <prefix>`), served by a **bounded range seek** over the
    /// order-preserving property index — `[prefix, successor(prefix))` — instead of a full label scan.
    ///
    /// The `prefix` is an unevaluated [`Expr`](crate::ast::Expr) (a string literal or, after literal
    /// auto-parameterisation, a `$param`), so the seek bounds are computed by the executor **at run
    /// time** from the evaluated prefix (the exclusive upper is the shortest string strictly greater
    /// than every string with that prefix; see `string_prefix_successor` in the executor). The seek
    /// returns a **superset** of the matches (the range can admit non-prefix strings in the
    /// last-scalar carry window, and — for a mixed-type property — values the bound re-check does not
    /// exclude), so the exact `STARTS WITH` predicate is **always retained as a residual
    /// [`Filter`](PhysicalOp::Filter) above this operator** (see [`Planner::lower_filter`]); the index
    /// only narrows the candidate set, never the result. Only `STARTS WITH` is accelerated —
    /// `ENDS WITH` / `CONTAINS` need a text index and stay scan + filter.
    NodeIndexStartsWithSeek {
        /// The node variable bound by each row.
        variable: Var,
        /// The label the index covers.
        label: Label,
        /// The indexed property key.
        property: String,
        /// The search prefix expression (unevaluated AST; a string literal or an auto-/user-parameter).
        prefix: Expr,
        /// The catalog index backing the seek.
        index: IndexId,
    },
    /// **Spatial proximity seek** (`rmp` task #73): records of `label` whose point `property` lies
    /// within `radius` of the constant centre `(center_x, center_y)`, served by the grid spatial
    /// index instead of a full label scan.
    ///
    /// The seek is the **2D projection** the grid buckets by — `(x, y)` — so it returns a *geometric
    /// **superset*** of the matching records (every node whose point could be within the radius, plus
    /// grid-cell false positives). The exact `distance(prop, centre) <op> radius` predicate is
    /// therefore **always retained as a residual [`Filter`](PhysicalOp::Filter) above this operator**
    /// (see [`Planner::lower_filter`]); the index only narrows the candidate set, never the result.
    /// Because the centre and radius are *constant* (evaluated at plan time), they are stored as
    /// plain `f64`s rather than as unevaluated [`Expr`](crate::ast::Expr)s — a proximity predicate
    /// whose operands are not compile-time constants never reaches this operator (the planner falls
    /// back to scan + filter).
    SpatialIndexSeek {
        /// The node variable bound by each row.
        variable: Var,
        /// The label the spatial index covers.
        label: Label,
        /// The indexed point property key.
        property: String,
        /// The constant centre's `x` coordinate (the grid's first projected axis).
        center_x: f64,
        /// The constant centre's `y` coordinate (the grid's second projected axis).
        center_y: f64,
        /// The constant proximity radius (in the property CRS's distance units).
        radius: f64,
        /// The catalog index backing the seek.
        index: IndexId,
    },
    /// **Text (trigram) index seek** (`rmp` task #662): records of `label` whose string `property`
    /// satisfies a `CONTAINS` / `ENDS WITH` / `STARTS WITH` predicate, served by the trigram text index
    /// instead of a full label scan. A forward-ordered range index cannot serve `CONTAINS`/`ENDS WITH`
    /// (substring/suffix are not a contiguous key range); the text index is the distinct native string
    /// index for exactly these.
    ///
    /// The trigram index returns a **candidate superset** (the trigram intersection is a *necessary*,
    /// not sufficient, condition — see [`graphus_index::TrigramIndex`]), so the exact predicate
    /// (`op`) is **always retained as a residual [`Filter`](PhysicalOp::Filter) above this operator**
    /// (see [`Planner::lower_filter`]); the index only narrows the candidate set, never the result. The
    /// `needle` is an unevaluated [`Expr`](crate::ast::Expr) (a string literal or, after literal
    /// auto-parameterisation, a `$param`) so it is evaluated by the executor **at run time**; a needle
    /// too short to form a trigram, a non-string needle, or an unavailable index at run time each fall
    /// back to a label scan (the residual filter then does the exact trimming — both paths yield the
    /// identical node set).
    NodeTextIndexSeek {
        /// The node variable bound by each row.
        variable: Var,
        /// The label the text index covers.
        label: Label,
        /// The indexed string property key.
        property: String,
        /// Which string predicate the seek serves (`CONTAINS` / `ENDS WITH` / `STARTS WITH`).
        op: TextSeekOp,
        /// The searched string expression (unevaluated AST; a string literal or an auto-/user-parameter).
        needle: Expr,
        /// The catalog index backing the seek.
        index: IndexId,
    },
    /// Full relationship scan binding the relationship and its endpoints (carried through from the
    /// logical [`AllRelationshipsScan`](crate::logical::LogicalOp::AllRelationshipsScan)).
    AllRelationshipsScan {
        /// The relationship variable.
        relationship: Var,
        /// The source-endpoint variable.
        from: Var,
        /// The target-endpoint variable.
        to: Var,
        /// The arrow direction.
        direction: crate::ast::RelDirection,
        /// The relationship-type alternatives; empty means "any type".
        types: Vec<RelType>,
    },
    /// **Relationship-property index equality seek** (`rmp` task #659): the visible relationships of
    /// `rel_type` whose current `property` equals the seek expression, served by the
    /// relationship-property index (a candidate seek + re-check) instead of scanning **every**
    /// `:rel_type` relationship and filtering.
    ///
    /// The relationship analogue of [`NodeIndexSeek`](Self::NodeIndexSeek). The planner emits it only
    /// for a **standalone**, single-type, fixed-length relationship pattern whose endpoints are
    /// otherwise unconstrained — `MATCH ()-[r:T {p: $x}]-()` / `MATCH (a)-[r:T]->(b) WHERE r.p = $x` —
    /// so both endpoints can be materialised directly from each matched relationship's own record. It
    /// therefore replaces the whole `Filter`-over-[`ExpandAll`](Self::ExpandAll)-over-[`AllNodesScan`](Self::AllNodesScan)
    /// subtree that scan path lowered to. `direction` reproduces the pattern arrow's endpoint binding
    /// **and** the undirected pattern's two-orientation semantics exactly, so the seek is
    /// bag-equivalent to that scan path. The seek returns a **candidate** set the seam has already
    /// re-checked (visibility, current type, current value); the executor falls back to a typed
    /// relationship scan + residual equality when the seam exposes no usable rel-property index (e.g.
    /// the off-thread reader — consistent with how the other seeks degrade off-thread).
    RelIndexSeek {
        /// The relationship variable bound by each row.
        relationship: Var,
        /// The source-endpoint node variable (bound per `direction`).
        from: Var,
        /// The target-endpoint node variable (bound per `direction`).
        to: Var,
        /// The single relationship type the index covers.
        rel_type: RelType,
        /// The indexed property key.
        property: String,
        /// The equality seek value (unevaluated AST; commonly a `$param` after auto-parameterisation).
        value: Expr,
        /// The arrow direction of the originating pattern (drives endpoint binding + undirected doubling).
        direction: crate::ast::RelDirection,
        /// The catalog index backing the seek.
        index: IndexId,
    },
    /// **Relationship-property index range seek** (`rmp` task #680): the visible relationships of
    /// `rel_type` whose current `property` satisfies a range predicate (`<`, `<=`, `>`, `>=`), served by
    /// the relationship RANGE (property) index — a candidate seek + re-check — instead of scanning
    /// **every** `:rel_type` relationship and filtering.
    ///
    /// The relationship analogue of [`NodeIndexRangeSeek`](Self::NodeIndexRangeSeek), and the range
    /// analogue of [`RelIndexSeek`](Self::RelIndexSeek): the planner emits it from the identical
    /// **standalone**, single-type, fixed-length relationship-pattern shape whose endpoints are otherwise
    /// unconstrained (`MATCH ()-[r:T]-() WHERE r.p >= $x`), so both endpoints are materialised directly
    /// from each matched relationship's own record and it replaces the whole
    /// `Filter`-over-[`ExpandAll`](Self::ExpandAll)-over-[`AllNodesScan`](Self::AllNodesScan) subtree.
    /// `direction` reproduces the pattern arrow's endpoint binding **and** the undirected pattern's
    /// two-orientation semantics exactly, so the seek is bag-equivalent to that scan path.
    ///
    /// Only a **single** bound is carried (`bound` + `value`), exactly like the node range seek: a
    /// two-sided range (`r.p >= lo AND r.p <= hi`) consumes the first bound here and re-attaches the
    /// second as a residual [`Filter`](Self::Filter). The seek returns a **candidate** set the seam has
    /// already re-checked (visibility, current type, and the current value against the bound under the
    /// *Cypher comparison semantics* — [`crate::eval::satisfies_range`], the same predicate a `Filter`
    /// applies), so the operator **consumes** the range conjunct. The executor falls back to a typed
    /// relationship scan + the identical range filter when the seam exposes no usable rel-property index
    /// (the off-thread reader, a restricted RBAC principal, a `Populating` index, or one dropped since
    /// planning) — both paths yield the identical relationship set.
    RelIndexRangeSeek {
        /// The relationship variable bound by each row.
        relationship: Var,
        /// The source-endpoint node variable (bound per `direction`).
        from: Var,
        /// The target-endpoint node variable (bound per `direction`).
        to: Var,
        /// The single relationship type the index covers.
        rel_type: RelType,
        /// The indexed property key.
        property: String,
        /// The range bound operator (`>`, `>=`, `<`, `<=`).
        bound: RangeBound,
        /// The bound value expression (unevaluated AST; commonly a `$param` after auto-parameterisation).
        value: Expr,
        /// The arrow direction of the originating pattern (drives endpoint binding + undirected doubling).
        direction: crate::ast::RelDirection,
        /// The catalog index backing the seek.
        index: IndexId,
    },
    /// **Composite (multi-property) relationship index equality seek** (`rmp` task #666): the visible
    /// relationships of `rel_type` whose current values of `properties` (in the composite key's declared
    /// order) equal `values` element-wise, served by the composite relationship B+-tree in a **single**
    /// seek — consuming a run of leading equality conjuncts (`MATCH ()-[r:T {a: …, b: …}]-()` /
    /// `MATCH ()-[r:T]-() WHERE r.a = … AND r.b = …`) that would otherwise be a single-key seek +
    /// residual filter.
    ///
    /// The relationship analogue of [`NodeCompositeIndexSeek`](Self::NodeCompositeIndexSeek), lowered
    /// from the same standalone single-type fixed-length pattern shape as
    /// [`RelIndexSeek`](Self::RelIndexSeek) so both endpoints are materialised directly from each matched
    /// relationship's own record. `properties` and `values` are parallel and cover the composite index's
    /// **full** ordered key tuple (the planner only emits this when every key has an equality conjunct).
    /// `direction` reproduces the pattern arrow's endpoint binding **and** the undirected pattern's
    /// two-orientation semantics exactly. The seek returns a **candidate** set the seam has already
    /// re-checked (visibility, current type, current per-property tuple); the executor falls back to a
    /// typed relationship scan + residual full-tuple equality when the seam exposes no usable composite
    /// relationship index (e.g. the off-thread reader).
    RelCompositeIndexSeek {
        /// The relationship variable bound by each row.
        relationship: Var,
        /// The source-endpoint node variable (bound per `direction`).
        from: Var,
        /// The target-endpoint node variable (bound per `direction`).
        to: Var,
        /// The single relationship type the composite index covers.
        rel_type: RelType,
        /// The indexed property keys, in the composite key's declared order (two or more).
        properties: Vec<String>,
        /// The per-key equality seek values (parallel to `properties`; unevaluated AST).
        values: Vec<Expr>,
        /// The arrow direction of the originating pattern (drives endpoint binding + undirected doubling).
        direction: crate::ast::RelDirection,
        /// The catalog index backing the seek.
        index: IndexId,
    },
    /// **Relationship spatial (point) index proximity seek** (`rmp` task #664): the visible
    /// relationships of `rel_type` whose current point `property` lies within `radius` of a constant
    /// centre, served by the relationship spatial (grid) index instead of scanning **every** `:rel_type`
    /// relationship and filtering.
    ///
    /// The relationship analogue of [`SpatialIndexSeek`](Self::SpatialIndexSeek), lowered from the same
    /// standalone single-type fixed-length pattern shape as [`RelIndexSeek`](Self::RelIndexSeek)
    /// (`MATCH ()-[r:T]-() WHERE point.distance(r.p, <const>) <= <const>`). Like the node spatial seek
    /// the grid returns only a geometric **superset** (it buckets the 2D projection), so the exact
    /// `distance(...) <op> radius` predicate is **always retained as a residual
    /// [`Filter`](Self::Filter) above this operator** — the index only narrows the candidate set, never
    /// the result. `direction` reproduces the pattern arrow's endpoint binding **and** the undirected
    /// pattern's two-orientation semantics exactly, so the seek is bag-equivalent to the scan path. The
    /// seek returns a **candidate** set the seam has already re-checked (visibility, current type); the
    /// executor falls back to a typed relationship scan + residual proximity filter when the seam exposes
    /// no usable relationship spatial index (the off-thread reader, or a since-dropped index).
    RelSpatialIndexSeek {
        /// The relationship variable bound by each row.
        relationship: Var,
        /// The source-endpoint node variable (bound per `direction`).
        from: Var,
        /// The target-endpoint node variable (bound per `direction`).
        to: Var,
        /// The single relationship type the index covers.
        rel_type: RelType,
        /// The indexed point property key.
        property: String,
        /// The constant centre's `x` coordinate (the grid's first projected axis).
        center_x: f64,
        /// The constant centre's `y` coordinate (the grid's second projected axis).
        center_y: f64,
        /// The constant proximity radius (in the property CRS's distance units).
        radius: f64,
        /// The arrow direction of the originating pattern (drives endpoint binding + undirected doubling).
        direction: crate::ast::RelDirection,
        /// The catalog index backing the seek.
        index: IndexId,
    },
    /// The single-row correlation argument of a join (carried through from
    /// [`Argument`](crate::logical::LogicalOp::Argument)).
    Argument {
        /// The variables provided by the enclosing join's left side.
        arguments: Vec<Var>,
    },
    /// A single empty row (carried through from [`Empty`](crate::logical::LogicalOp::Empty)).
    Empty,

    // ---- graph traversal (physical expand strategy) -------------------------------------------
    /// **Expand-all**: enumerate the neighbours of the bound `from`, binding `relationship` and the
    /// new `to` (`04 §7.1`).
    ExpandAll {
        /// The upstream relation (binds `from`).
        input: Box<PhysicalOp>,
        /// The bound anchor node to expand from.
        from: Var,
        /// The relationship variable bound by the traversal.
        relationship: Var,
        /// The far-endpoint variable bound by the traversal.
        to: Var,
        /// The traversal direction.
        direction: crate::ast::RelDirection,
        /// The relationship-type alternatives; empty means "any type".
        types: Vec<RelType>,
        /// The variable-length range, if any.
        range: Option<crate::ast::VarLengthRange>,
        /// Relationship variables bound by earlier links of the same MATCH pattern, whose bound
        /// relationships this traversal must not re-use (relationship isomorphism).
        prior_rels: Vec<Var>,
        /// A var-length hop's inline relationship-property map, applied per relationship during
        /// expansion (`None` for a fixed-length hop).
        rel_props: Option<crate::ast::Expr>,
    },
    /// **Expand-into**: both endpoints are already bound; enumerate only the relationships
    /// **between** them (a connection / cycle check, `04 §7.1`).
    ExpandInto {
        /// The upstream relation (binds **both** `from` and `to`).
        input: Box<PhysicalOp>,
        /// The bound source endpoint.
        from: Var,
        /// The relationship variable bound by the traversal.
        relationship: Var,
        /// The bound target endpoint.
        to: Var,
        /// The traversal direction.
        direction: crate::ast::RelDirection,
        /// The relationship-type alternatives; empty means "any type".
        types: Vec<RelType>,
        /// The variable-length range, if any.
        range: Option<crate::ast::VarLengthRange>,
        /// Relationship variables bound by earlier links of the same MATCH pattern, whose bound
        /// relationships this traversal must not re-use (relationship isomorphism).
        prior_rels: Vec<Var>,
        /// A var-length hop's inline relationship-property map, applied per relationship during
        /// expansion (`None` for a fixed-length hop).
        rel_props: Option<crate::ast::Expr>,
    },
    /// Bind a **named path** variable from the pattern part's bound traversal variables (carried
    /// through from [`NamedPath`](crate::logical::LogicalOp::NamedPath); `04 §7.2`).
    NamedPath {
        /// The upstream relation (binds `start` and every step).
        input: Box<PhysicalOp>,
        /// The path variable being bound.
        variable: Var,
        /// The pattern part's start-node variable.
        start: Var,
        /// The relationship variable of each chain link, in pattern order (a single relationship
        /// for a fixed hop; the relationship list of a variable-length hop).
        steps: Vec<Var>,
    },

    /// **Shortest-path search**: find the minimal-relationship-count path(s) between the bound
    /// `from` and `to` endpoints over a variable-length relationship (carried through from
    /// [`ShortestPath`](crate::logical::LogicalOp::ShortestPath)). Breadth-first, no repeated nodes
    /// within a path; `all` selects every minimal-length path vs. one.
    ShortestPath {
        /// The upstream relation, binding both endpoints.
        input: Box<PhysicalOp>,
        /// The (bound) source endpoint.
        from: Var,
        /// The (bound) target endpoint.
        to: Var,
        /// The relationship variable bound to the path's relationship list.
        relationship: Var,
        /// The named path variable (`p = shortestPath(...)`), if any.
        path: Option<Var>,
        /// The traversal direction.
        direction: crate::ast::RelDirection,
        /// The relationship-type alternatives; empty means "any type".
        types: Vec<RelType>,
        /// The variable-length length bounds.
        range: crate::ast::VarLengthRange,
        /// `true` for `allShortestPaths`; `false` for `shortestPath`.
        all: bool,
    },

    /// **Quantified path pattern** (QPP, GPM / Neo4j 5.9+): a trail walk repeating the interior
    /// single hop `(group_start)-[relationship]-(group_end)` between `min` and `max` times from the
    /// bound `from`, binding the interior variables as group lists (carried through from
    /// [`QuantifiedPath`](crate::logical::LogicalOp::QuantifiedPath)). `into` is `true` when `to` is
    /// already bound by the input (only walks ending there are kept).
    QuantifiedPath {
        /// The upstream relation, binding `from`.
        input: Box<PhysicalOp>,
        /// The (bound) anchor node the walk starts from.
        from: Var,
        /// The trailing boundary node (bound to the final node, or matched against when `into`).
        to: Var,
        /// The interior start group variable (list of each iteration's start node).
        group_start: Var,
        /// The interior end group variable (list of each iteration's end node).
        group_end: Var,
        /// The first interior relationship's group variable (its slice of the trail).
        relationship: Var,
        /// The first interior relationship's traversal direction.
        direction: crate::ast::RelDirection,
        /// The first interior relationship's type alternatives; empty means "any type".
        types: Vec<RelType>,
        /// Interior hops beyond the first relationship (empty for the single-hop fast path); each
        /// advances the walk one relationship per iteration and binds its own group variables.
        extra_hops: Vec<QppStep>,
        /// The minimum iteration count (inclusive).
        min: u64,
        /// The maximum iteration count (inclusive); `None` = unbounded.
        max: Option<u64>,
        /// Relationship variables bound by earlier links of the same pattern (trail extends over
        /// them).
        prior_rels: Vec<Var>,
        /// The per-iteration interior predicate (scalar interior bindings across all hops).
        interior_predicate: Option<Expr>,
        /// `true` when `to` is already bound by the input (keep only walks ending at that node).
        into: bool,
    },

    // ---- relational ---------------------------------------------------------------------------
    /// Keep rows whose `predicate` is `TRUE` (residual filter; three-valued logic, `04 §7.6`).
    Filter {
        /// The upstream relation.
        input: Box<PhysicalOp>,
        /// The residual predicate (unevaluated AST).
        predicate: Expr,
    },
    /// Project each row to a new tuple of named columns; `distinct` de-duplicates.
    Projection {
        /// The upstream relation.
        input: Box<PhysicalOp>,
        /// The projected columns, in result order.
        items: Vec<ProjectionColumn>,
        /// `true` for `DISTINCT`.
        distinct: bool,
    },
    /// Group by `group_keys` and compute `aggregates` per group.
    Aggregation {
        /// The upstream relation.
        input: Box<PhysicalOp>,
        /// The grouping-key columns; empty = single group.
        group_keys: Vec<ProjectionColumn>,
        /// The aggregate columns.
        aggregates: Vec<ProjectionColumn>,
    },
    /// Sort the input by `keys` (full sort; used when no adjacent `LIMIT` fuses it into a
    /// [`TopN`](Self::TopN)).
    Sort {
        /// The upstream relation.
        input: Box<PhysicalOp>,
        /// The sort keys, primary first.
        keys: Vec<SortKey>,
    },
    /// **Top-N**: the fused `Sort` + `Limit` — emit only the first `limit` rows in sort order
    /// (`04 §7.1` sort/limit). `limit` is the unevaluated AST limit expression.
    TopN {
        /// The upstream relation.
        input: Box<PhysicalOp>,
        /// The sort keys, primary first.
        keys: Vec<SortKey>,
        /// The number-of-rows-to-keep expression.
        limit: Expr,
    },
    /// Discard the first `count` rows (`SKIP`).
    Skip {
        /// The upstream relation.
        input: Box<PhysicalOp>,
        /// The number-of-rows-to-skip expression.
        count: Expr,
    },
    /// Keep at most `count` rows (`LIMIT`).
    Limit {
        /// The upstream relation.
        input: Box<PhysicalOp>,
        /// The maximum-row-count expression.
        count: Expr,
    },
    /// **Eager barrier**: drain `input` completely, then emit the buffered rows.
    ///
    /// Inserted by the planner between a [`Limit`](Self::Limit) and an input subtree containing a
    /// write operator, so the write side effects run to completion no matter how many rows the
    /// limit lets through. openCypher write clauses are *eager*: `LIMIT` bounds the **returned**
    /// rows, never the side effects — `CREATE (n) RETURN n LIMIT 0` must still create the node.
    Eager {
        /// The upstream relation, drained in full before any row is emitted.
        input: Box<PhysicalOp>,
    },
    /// Expand `list` into one row per element bound to `variable` (`UNWIND`).
    Unwind {
        /// The upstream relation.
        input: Box<PhysicalOp>,
        /// The list expression.
        list: Expr,
        /// The element variable.
        variable: Var,
    },
    /// Stream a CSV source, binding one row per record to `variable` (`LOAD CSV`).
    LoadCsv {
        /// The upstream relation.
        input: Box<PhysicalOp>,
        /// Whether the first record names the columns (`WITH HEADERS`).
        with_headers: bool,
        /// The URL expression (a string at runtime).
        url: Expr,
        /// The record variable.
        variable: Var,
        /// The optional single-character field separator (defaults to `,`).
        field_terminator: Option<char>,
    },

    // ---- joins (physical join strategy) -------------------------------------------------------
    /// **Nested-loop join** / correlated apply: for each left row, evaluate the right branch with
    /// the left bindings available (`04 §7.1`). The only realisation for a *correlated* `Apply`
    /// (the right branch reads the left row through an [`Argument`](Self::Argument)).
    NestedLoopJoin {
        /// The left (driving) relation.
        left: Box<PhysicalOp>,
        /// The right (per-left-row) relation.
        right: Box<PhysicalOp>,
    },
    /// **Hash join**: build a hash table on the join keys of one side, probe with the other
    /// (`04 §7.1`). Chosen for an **equi-join** (shared join-key columns); see [`choose_join`].
    HashJoin {
        /// The build (left) relation.
        left: Box<PhysicalOp>,
        /// The probe (right) relation.
        right: Box<PhysicalOp>,
        /// The column names joined on (present on both sides), ascending.
        join_keys: Vec<String>,
    },
    /// Combine two branches, optionally de-duplicating (`UNION` / `UNION ALL`).
    Union {
        /// The left branch.
        left: Box<PhysicalOp>,
        /// The right branch.
        right: Box<PhysicalOp>,
        /// `true` for `UNION ALL` (keep duplicates).
        all: bool,
    },
    /// Left-outer guarantee for `OPTIONAL MATCH`: at least one row per drive, null-filling
    /// `null_variables` on the no-match path.
    Optional {
        /// The optional subplan.
        input: Box<PhysicalOp>,
        /// The variables null-filled when `input` is empty.
        null_variables: Vec<Var>,
    },

    // ---- write --------------------------------------------------------------------------------
    /// Create the `pattern` once per input row (`CREATE`).
    Create {
        /// The driving relation.
        input: Box<PhysicalOp>,
        /// The entities to create.
        pattern: Vec<CreatePart>,
    },
    /// Match-or-create `pattern`, running the create/match side-effects (`MERGE`).
    Merge {
        /// The driving relation.
        input: Box<PhysicalOp>,
        /// The single pattern to match-or-create.
        pattern: Vec<CreatePart>,
        /// `ON CREATE SET` actions.
        on_create: Vec<SetOp>,
        /// `ON MATCH SET` actions.
        on_match: Vec<SetOp>,
    },
    /// Apply property/label mutations to bound entities (`SET`).
    SetClause {
        /// The upstream relation.
        input: Box<PhysicalOp>,
        /// The mutations, in source order.
        ops: Vec<SetOp>,
    },
    /// Delete the entities identified by `exprs` (`[DETACH] DELETE`).
    Delete {
        /// The upstream relation.
        input: Box<PhysicalOp>,
        /// `true` for `DETACH DELETE`.
        detach: bool,
        /// The entity-reference expressions.
        exprs: Vec<Expr>,
    },
    /// Remove labels/properties from bound entities (`REMOVE`).
    Remove {
        /// The upstream relation.
        input: Box<PhysicalOp>,
        /// The removals, in source order.
        ops: Vec<RemoveOp>,
    },
    /// Run the inner update sub-plan once per `(input row, list element)` for its side effects,
    /// passing each input row through unchanged (`FOREACH`). The `body` is correlated (rooted at an
    /// [`Argument`](PhysicalOp::Argument) leaf); the executor rebuilds it per `(row, element)`.
    Foreach {
        /// The upstream relation driving the iteration.
        input: Box<PhysicalOp>,
        /// The loop variable bound to each list element (local to the body).
        variable: Var,
        /// The list expression, evaluated once per input row.
        list: Expr,
        /// The correlated inner update sub-plan (Argument-rooted).
        body: Box<PhysicalOp>,
    },

    // ---- procedure ----------------------------------------------------------------------------
    /// Invoke a procedure, binding the `yields` columns (`CALL … YIELD`).
    ProcedureCall {
        /// The upstream relation when correlated; `None` for a leading call.
        input: Option<Box<PhysicalOp>>,
        /// The dotted procedure name.
        name: Vec<String>,
        /// The argument expressions; `None` for the implicit form.
        args: Option<Vec<Expr>>,
        /// The `YIELD` columns; `None` when there is no `YIELD`.
        yields: Option<Vec<YieldColumn>>,
    },
}

/// Lowers a [logical plan](LogicalOp) into a [`PhysicalPlan`], consulting `catalog` for index-aware
/// access-path selection (`04 §7.1`, §6.6).
///
/// This is the physical planner's entry point. It is **total and infallible** — like the logical
/// planner ([`crate::lower`]), it transforms an already-validated plan and makes only sound,
/// rule-based strategy choices, never re-checking compile-time invariants. The returned plan records
/// every catalog [`IndexId`] it depends on (`04 §6.6`).
///
/// This is the no-statistics form: it is exactly [`plan_physical_with_stats`] with `stats = None`, so
/// the plan's [`estimated_rows`](PhysicalPlan::estimated_rows) uses the cardinality estimator's
/// documented constant fallbacks. Pass a [`Statistics`] source to [`plan_physical_with_stats`] for an
/// estimate informed by real counts; the operator tree and query results are identical either way.
///
/// # Examples
///
/// ```
/// use graphus_cypher::{catalog::IndexCatalog, lexer::tokenize, lower::lower, parser::parse_tokens,
///     physical::plan_physical, semantics::analyze};
///
/// let catalog = IndexCatalog::builder().with_label_property("Person", "name").build();
/// let toks = tokenize("MATCH (n:Person {name: 'Ada'}) RETURN n").unwrap();
/// let ast = parse_tokens(&toks, "MATCH (n:Person {name: 'Ada'}) RETURN n").unwrap();
/// let validated = analyze(&ast).unwrap();
/// let logical = lower(&validated);
/// let physical = plan_physical(&logical, &catalog);
/// // The equality on the indexed `name` property became an index seek.
/// assert!(physical.to_string().contains("NodeIndexSeek"));
/// // … and the plan records its dependency on the index.
/// assert_eq!(physical.index_dependencies().count(), 1);
/// // The plan carries a finite, positive row estimate (here from the no-stats fallbacks).
/// assert!(physical.estimated_rows().is_finite() && physical.estimated_rows() >= 0.0);
/// ```
pub fn plan_physical(logical: &LogicalOp, catalog: &IndexCatalog) -> PhysicalPlan {
    plan_physical_with_stats(logical, catalog, None)
}

/// Lowers a [logical plan](LogicalOp) into a [`PhysicalPlan`], **cost-based when graph `stats` are
/// supplied** and rule-based otherwise (`00-overview` §6, task #65).
///
/// The `stats` source ([`crate::statistics::Statistics`], typically obtained from
/// [`GraphAccess::statistics`](crate::graph_access::GraphAccess::statistics)) drives both the
/// [cardinality estimate](PhysicalPlan::estimated_rows) ([`estimate_rows`]) and the [cost
/// model](crate::cost) the optimiser minimises.
///
/// * With **`stats = None`** this is exactly [`plan_physical`]: the rule-based operator tree (no
///   cost-based rewrites), the recorded index dependencies, and the result set are identical, and the
///   estimate uses the estimator's documented constant fallbacks. The order-preserving
///   [`Sort`-elision pass](elide_provided_order_sorts) still runs (it is rule-based, not cost-based:
///   it only drops a `Sort` already provided by an index access), so an `ORDER BY` served by the
///   index carries no `Sort` on either path.
/// * With **`stats = Some(..)`** the planner first builds that same rule-based tree (the sound,
///   correct starting point) and then applies the [cost-based optimiser](self#cost-based-optimisation):
///   it may reorder independent inner joins, flip a hash join's build side, and choose index-seek vs
///   scan by estimated cost. **Only the plan shape changes** — every rewrite is bag-preserving (see
///   the module docs for each soundness argument), so the executor returns the identical result
///   multiset. The recorded [`index_dependencies`](PhysicalPlan::index_dependencies) are recomputed
///   from the *final* tree (a plan that drops a seek for a scan no longer records that index).
///
/// The root [`estimated_rows`](PhysicalPlan::estimated_rows) is the cardinality estimate over the
/// logical plan, which the rewrites preserve.
/// Pushes each `WHERE` conjunct as deep into the plan as it can legally go, so it lands on the scan
/// that binds the variable it constrains (`rmp` task #857).
///
/// # The gap this closes, measured
///
/// A predicate written in the same clause as its pattern already reaches the scan — the existing
/// access-path selection ([`seek_alternative_for_filter`]) folds a `Filter` over a scan into a seek
/// there. One written after a `WITH` did not: `MATCH (v:USER)-[:LIKES]->(a) WITH v, a WHERE v.uidn = 42`
/// planned a `NodeByLabelScan(v)` and filtered above both the projection and the expand, while the
/// identical `MATCH (v:USER {uidn: 42})-…` planned a `NodeIndexSeek`. Two operators sat between the
/// filter and the scan and nothing moved the conjunct past them.
///
/// Running before the access-path pass is what makes it pay off: the conjunct arrives directly over the
/// scan, which is exactly the shape that pass turns into a seek. It also helps on its own — a filter
/// evaluated below an expand discards rows before they fan out.
///
/// # What a conjunct may travel through, and what stops it
///
/// Descent is **allow-listed**, never inferred: an operator this function does not name explicitly
/// stops the conjunct, which is what keeps an unfamiliar or newly-added operator safe by default.
///
/// * [`Filter`](PhysicalOp::Filter) — always. Two filters in sequence evaluate the same predicates on
///   the same rows; they are deliberately **not** merged into one `AND`, so neither predicate's
///   evaluation order changes.
/// * [`Projection`](PhysicalOp::Projection) — only when every variable the conjunct reads is projected
///   through by **identity** (`v AS v`), and it touches nothing the projection introduced or renamed.
///   That is what makes the predicate mean the same thing on either side: the column it reads is
///   literally the same binding. `DISTINCT` is included — filtering before or after de-duplication
///   yields the same set, because a predicate reading only identity-projected columns cannot
///   distinguish two rows the de-duplication would merge.
/// * [`ExpandAll`](PhysicalOp::ExpandAll) / [`ExpandInto`](PhysicalOp::ExpandInto) — only when the
///   conjunct reads neither the relationship variable nor the target the hop introduces. Those are
///   unbound below the expand, so a predicate touching them cannot be evaluated there.
/// * [`Sort`](PhysicalOp::Sort) — always. Sorting permutes rows; it neither adds nor removes any, so
///   filtering below produces the same bag in the same order.
///
/// Everything else stops it, and the load-bearing cases are worth naming:
/// [`Aggregation`](PhysicalOp::Aggregation) (filtering before a grouping would change every count),
/// [`Limit`](PhysicalOp::Limit) / [`Skip`](PhysicalOp::Skip) / [`TopN`](PhysicalOp::TopN) (filtering
/// past a bound selects a different bounded set), [`Optional`](PhysicalOp::Optional) (a predicate pushed
/// inside would remove the row the outer join must preserve with nulls), `Union`, `Eager`, `Unwind`,
/// every join, and every writing operator.
///
/// A conjunction is split, so `WHERE v.uidn = 1 AND size(keys(a)) > 2` pushes the part that qualifies
/// and leaves the rest where it was. When nothing qualifies the tree is rebuilt unchanged, which keeps
/// the rule-based/TCK plan identical wherever this does not apply.
fn push_filters_through_projections(op: PhysicalOp) -> PhysicalOp {
    // Bottom-up, so a `WITH … WITH … WHERE` chain is rewritten from the leaves and a conjunct can
    // travel through several projections in one pass.
    let op = map_children(op, &push_filters_through_projections);
    let PhysicalOp::Filter { input, predicate } = op else {
        return op;
    };
    // Each conjunct is re-inserted at the deepest point it may legally reach — which, for one that
    // cannot move at all, is exactly where it already was. So the `Filter` is not "removed": it is
    // rebuilt, once per conjunct, wherever each one belongs.
    let conjuncts: Vec<Expr> = split_conjuncts(&predicate).into_iter().cloned().collect();
    let mut below = *input;
    for conjunct in conjuncts {
        below = push_conjunct_into(below, &conjunct);
    }
    below
}

/// Wraps `conjunct` in a [`Filter`](PhysicalOp::Filter) at the deepest point inside `op` the allow-list
/// permits — immediately around `op` itself when it may not travel at all.
///
/// Traversability is decided by **reference** before the operator is consumed, then the descent reuses
/// [`map_children`], so the recursion cannot disagree with the decision and no operator's fields need
/// re-listing here. Every traversable operator has a single input, which is what makes that safe.
fn push_conjunct_into(op: PhysicalOp, conjunct: &Expr) -> PhysicalOp {
    // A `Filter` whose own input refuses the conjunct absorbs it instead of gaining a nested `Filter`
    // below. Two reasons, and the first is not cosmetic: nesting one `Filter` per conjunct adds a plan
    // level per conjunct, and a 12-part pattern with 11 join conjuncts overflowed the stack in the
    // recursive passes that walk the tree afterwards (`tests/planner_join_bound.rs`). Merging keeps the
    // depth constant. And it is exactly semantics-preserving here: the conjuncts are re-joined in their
    // original order, so `c1 AND c2` is the predicate the query already had.
    if let PhysicalOp::Filter { input, predicate } = op {
        if can_traverse(&input, conjunct) {
            return PhysicalOp::Filter {
                input: Box::new(push_conjunct_into(*input, conjunct)),
                predicate,
            };
        }
        let span = predicate.span;
        return PhysicalOp::Filter {
            input,
            predicate: Expr::new(
                ExprKind::Binary {
                    op: BinaryOp::And,
                    lhs: Box::new(predicate),
                    rhs: Box::new(conjunct.clone()),
                },
                span,
            ),
        };
    }
    if !can_traverse(&op, conjunct) {
        return PhysicalOp::Filter {
            input: Box::new(op),
            predicate: conjunct.clone(),
        };
    }
    map_children(op, &|child| push_conjunct_into(child, conjunct))
}

/// Whether `conjunct` may legally be evaluated below `op` — the allow-list of the pass.
///
/// Decided by reference, before the operator is consumed, so [`push_conjunct_into`]'s descent cannot
/// disagree with the decision. Every traversable operator has a single input, which is what makes
/// descending through [`map_children`] safe.
fn can_traverse(op: &PhysicalOp, conjunct: &Expr) -> bool {
    match op {
        // A filter can always host another below it; a sort permutes rows without adding or removing
        // any. Neither is merged into the other, so no predicate's evaluation order changes.
        PhysicalOp::Filter { .. } | PhysicalOp::Sort { .. } => true,
        PhysicalOp::Projection { input, items, .. } => {
            projection_passes_through(input, items, conjunct)
        }
        // A hop's relationship variable and its target are unbound below it, so a conjunct touching
        // either cannot be evaluated there.
        PhysicalOp::ExpandAll {
            relationship, to, ..
        } => {
            !expr_references_var(conjunct, &relationship.name)
                && !expr_references_var(conjunct, &to.name)
        }
        // Expand-into binds no new node — both endpoints are already bound — but still introduces the
        // relationship variable.
        PhysicalOp::ExpandInto { relationship, .. } => {
            !expr_references_var(conjunct, &relationship.name)
        }
        // Everything else stops it. Explicitly a catch-all, so a newly-added operator is a barrier
        // until someone proves it traversable.
        _ => false,
    }
}

/// Whether `conjunct` means the same thing below a projection as above it.
///
/// True only when it reads at least one column the projection passes through by **identity** (`v AS v`)
/// — so moving it can actually help — and touches nothing the projection introduced or renamed. Identity
/// is what makes the two sides equivalent: the column read below is literally the same binding.
///
/// The introduced/renamed set is tested with the exhaustive [`expr_references_var`] walk rather than by
/// enumerating the conjunct's own variables, so a newly-added `ExprKind` cannot silently escape the
/// check.
///
/// `DISTINCT` is deliberately not consulted: filtering before or after de-duplication yields the same
/// set, because a predicate reading only identity-projected columns cannot distinguish two rows the
/// de-duplication would merge.
fn projection_passes_through(
    input: &PhysicalOp,
    items: &[ProjectionColumn],
    conjunct: &Expr,
) -> bool {
    let identity: BTreeSet<&str> = items
        .iter()
        .filter_map(|c| match &c.expr.kind {
            ExprKind::Variable(name) if *name == c.alias => Some(name.as_str()),
            _ => None,
        })
        .collect();
    let below_binds: BTreeSet<String> = bound_var_names(input).into_iter().collect();
    let reads_identity = identity.iter().any(|v| expr_references_var(conjunct, v));
    let blocked = items
        .iter()
        .map(|c| c.alias.as_str())
        .filter(|a| !identity.contains(*a) || !below_binds.contains(*a))
        .any(|v| expr_references_var(conjunct, v));
    reads_identity && !blocked
}

pub fn plan_physical_with_stats(
    logical: &LogicalOp,
    catalog: &IndexCatalog,
    stats: Option<&dyn Statistics>,
) -> PhysicalPlan {
    let estimated_rows = estimate_rows(logical, stats);
    let mut deps = BTreeSet::new();
    // Predicate pushdown across pass-through projections (`rmp` task #857) runs on the rule-based tree,
    // BEFORE the access-path pass below: it delivers a conjunct to the scan that binds the variable it
    // constrains, which is exactly the `Filter`-over-scan shape that pass turns into a seek. It is
    // bag-preserving, so it applies with or without statistics.
    let rule_based =
        push_filters_through_projections(Planner { catalog }.lower(logical, &mut deps));

    // With statistics, refine the rule-based tree by the cost model; without, keep its shape (no
    // cost-based rewrites). The optimiser is bag-preserving, so only the shape changes — and the index
    // dependencies are recomputed from the final tree it produces. Either way the provided-order
    // Sort-elision pass (`rmp` #665) runs last on the final tree; it is order-preserving (not
    // cost-based), so it applies on both paths without changing the result multiset.
    let (root, index_dependencies) = match stats {
        Some(s) => {
            let optimized = optimize(rule_based, catalog, s);
            // Provided-order Sort elision (`rmp` task #665, part B) runs as the FINAL pass, after the
            // cost-based optimiser has settled every access path — so it only elides a Sort when the
            // subtree kept an ordered-capable index access (a cost-reverted scan keeps its Sort).
            let optimized = elide_provided_order_sorts(optimized);
            let deps = collect_index_dependencies(&optimized);
            (optimized, deps)
        }
        // No stats: the rule-based tree is final (no access-path rewrites), so the elision pass is
        // sound to run directly on it. It preserves index ops (only marks one ordered), so the
        // dependencies gathered during lowering stay correct.
        None => (elide_provided_order_sorts(rule_based), deps),
    };

    PhysicalPlan {
        root,
        index_dependencies,
        estimated_rows,
        cost_based: stats.is_some(),
        // The prefix is a property of the statement text, not of the plan: the compile pipeline attaches
        // it with [`PhysicalPlan::with_prefix`] (`rmp` #752). A plan built straight from a logical tree
        // (the TCK, the DST simulator, library callers) carries none.
        prefix: None,
    }
}

/// The physical-planning driver, borrowing the catalog for the duration of one compilation.
struct Planner<'c> {
    catalog: &'c IndexCatalog,
}

impl Planner<'_> {
    /// Lowers one logical operator to its physical form, recording index dependencies into `deps`.
    fn lower(&self, op: &LogicalOp, deps: &mut BTreeSet<IndexId>) -> PhysicalOp {
        match op {
            // ---- leaf reads: index-aware selection -------------------------------------------
            LogicalOp::AllNodesScan { variable } => PhysicalOp::AllNodesScan {
                variable: variable.clone(),
            },
            LogicalOp::NodeByLabelScan { variable, label } => {
                self.lower_label_scan(variable, label, deps)
            }
            LogicalOp::AllRelationshipsScan {
                relationship,
                from,
                to,
                direction,
                types,
            } => PhysicalOp::AllRelationshipsScan {
                relationship: relationship.clone(),
                from: from.clone(),
                to: to.clone(),
                direction: *direction,
                types: types.clone(),
            },
            LogicalOp::Argument { arguments } => PhysicalOp::Argument {
                arguments: arguments.clone(),
            },
            LogicalOp::Empty => PhysicalOp::Empty,

            // ---- Filter: the index-selection trigger -----------------------------------------
            LogicalOp::Filter { input, predicate } => self.lower_filter(input, predicate, deps),

            // ---- Expand: into vs all ---------------------------------------------------------
            LogicalOp::Expand {
                input,
                from,
                relationship,
                to,
                direction,
                types,
                range,
                prior_rels,
                rel_props,
            } => {
                let phys_input = self.lower(input, deps);
                // Expand-into iff BOTH endpoints are already bound by the input.
                let bound = bound_vars(&phys_input);
                let both_bound = bound.iter().any(|v| v.name == from.name)
                    && bound.iter().any(|v| v.name == to.name);
                let input = Box::new(phys_input);
                if both_bound {
                    PhysicalOp::ExpandInto {
                        input,
                        from: from.clone(),
                        relationship: relationship.clone(),
                        to: to.clone(),
                        direction: *direction,
                        types: types.clone(),
                        range: *range,
                        prior_rels: prior_rels.clone(),
                        rel_props: rel_props.clone(),
                    }
                } else {
                    PhysicalOp::ExpandAll {
                        input,
                        from: from.clone(),
                        relationship: relationship.clone(),
                        to: to.clone(),
                        direction: *direction,
                        types: types.clone(),
                        range: *range,
                        prior_rels: prior_rels.clone(),
                        rel_props: rel_props.clone(),
                    }
                }
            }

            // ---- named path ------------------------------------------------------------------
            LogicalOp::NamedPath {
                input,
                variable,
                start,
                steps,
            } => PhysicalOp::NamedPath {
                input: Box::new(self.lower(input, deps)),
                variable: variable.clone(),
                start: start.clone(),
                steps: steps.clone(),
            },

            // ---- shortest path ---------------------------------------------------------------
            LogicalOp::ShortestPath {
                input,
                from,
                to,
                relationship,
                path,
                direction,
                types,
                range,
                all,
            } => PhysicalOp::ShortestPath {
                input: Box::new(self.lower(input, deps)),
                from: from.clone(),
                to: to.clone(),
                relationship: relationship.clone(),
                path: path.clone(),
                direction: *direction,
                types: types.clone(),
                range: *range,
                all: *all,
            },

            // ---- quantified path pattern -----------------------------------------------------
            LogicalOp::QuantifiedPath {
                input,
                from,
                to,
                group_start,
                group_end,
                relationship,
                direction,
                types,
                extra_hops,
                min,
                max,
                prior_rels,
                interior_predicate,
            } => {
                let phys_input = self.lower(input, deps);
                // Into iff the trailing boundary node is already bound by the input (a reused node).
                let into = bound_vars(&phys_input).iter().any(|v| v.name == to.name);
                PhysicalOp::QuantifiedPath {
                    input: Box::new(phys_input),
                    from: from.clone(),
                    to: to.clone(),
                    group_start: group_start.clone(),
                    group_end: group_end.clone(),
                    relationship: relationship.clone(),
                    direction: *direction,
                    types: types.clone(),
                    extra_hops: extra_hops.clone(),
                    min: *min,
                    max: *max,
                    prior_rels: prior_rels.clone(),
                    interior_predicate: interior_predicate.clone(),
                    into,
                }
            }

            // ---- relational ------------------------------------------------------------------
            LogicalOp::Projection {
                input,
                items,
                distinct,
            } => PhysicalOp::Projection {
                input: Box::new(self.lower(input, deps)),
                items: items.clone(),
                distinct: *distinct,
            },
            LogicalOp::Aggregation {
                input,
                group_keys,
                aggregates,
            } => PhysicalOp::Aggregation {
                input: Box::new(self.lower(input, deps)),
                group_keys: group_keys.clone(),
                aggregates: aggregates.clone(),
            },
            LogicalOp::Sort { input, keys } => PhysicalOp::Sort {
                input: Box::new(self.lower(input, deps)),
                keys: keys.clone(),
            },
            LogicalOp::Skip { input, count } => PhysicalOp::Skip {
                input: Box::new(self.lower(input, deps)),
                count: count.clone(),
            },
            LogicalOp::Limit { input, count } => self.lower_limit(input, count, deps),
            LogicalOp::Unwind {
                input,
                list,
                variable,
            } => PhysicalOp::Unwind {
                input: Box::new(self.lower(input, deps)),
                list: list.clone(),
                variable: variable.clone(),
            },
            LogicalOp::LoadCsv {
                input,
                with_headers,
                url,
                variable,
                field_terminator,
            } => PhysicalOp::LoadCsv {
                input: Box::new(self.lower(input, deps)),
                with_headers: *with_headers,
                url: url.clone(),
                variable: variable.clone(),
                field_terminator: *field_terminator,
            },

            // ---- joins: hash vs nested-loop --------------------------------------------------
            LogicalOp::Apply { left, right } => {
                let phys_left = self.lower(left, deps);
                let phys_right = self.lower(right, deps);
                // Eagerness barrier (openCypher "Eager" rule) across a write→read clause boundary. A
                // fresh `MATCH` after a write becomes `Apply(left = <… writes …>, right = scan)`, and
                // the join drives the right scan **once per left row**. If the left's writes are
                // pipelined (one create per left row pulled), the right scan for an early row sees only
                // the writes produced so far, so a later `MATCH () CREATE ()` re-scans the graph
                // mid-mutation and the create count drifts (observed +9/+12, expected +10;
                // `clauses/create/Create3.feature` [3]). When the left contains a write **and** the
                // right reads the graph, drain the left into an `Eager` buffer first, so every
                // left-side write settles before the right scan runs for any row. A left with no write,
                // or a right that performs no graph read, needs no barrier (the common, hot path).
                let phys_left = if contains_write(&phys_left) && contains_read(&phys_right) {
                    PhysicalOp::Eager {
                        input: Box::new(phys_left),
                    }
                } else {
                    phys_left
                };
                choose_join(phys_left, phys_right, right)
            }
            LogicalOp::Optional {
                input,
                null_variables,
            } => PhysicalOp::Optional {
                input: Box::new(self.lower(input, deps)),
                null_variables: null_variables.clone(),
            },
            LogicalOp::Union { left, right, all } => PhysicalOp::Union {
                left: Box::new(self.lower(left, deps)),
                right: Box::new(self.lower(right, deps)),
                all: *all,
            },

            // ---- write -----------------------------------------------------------------------
            LogicalOp::Create { input, pattern } => PhysicalOp::Create {
                // Eagerness barrier (openCypher "Eager" rule). A `CREATE` adds nodes its own upstream
                // `MATCH` could match: in `MATCH () CREATE () WITH * MATCH () CREATE ()` the second
                // `MATCH ()` feeds the second `CREATE ()`, a read→write cycle. If the read is pipelined
                // into the create, an early row's fresh node is re-scanned and the create count
                // snowballs (`clauses/create/Create3.feature` [3]). Draining the read into an `Eager`
                // buffer first makes the `MATCH` observe exactly the pre-`CREATE` graph (this barrier
                // pairs with the one on a write-bearing `Apply` *left*, which settles an *earlier*
                // clause's writes before this `MATCH` scans — both are needed for the two-stage case
                // above). A create whose input performs no graph read (a bare `CREATE ()` from `Empty`,
                // `CREATE (a) CREATE (b)`) needs no barrier — the common, hot path.
                input: Box::new(eager_for_read_write(self.lower(input, deps))),
                pattern: pattern.clone(),
            },
            LogicalOp::Merge {
                input,
                pattern,
                on_create,
                on_match,
            } => PhysicalOp::Merge {
                // Eagerness barrier (openCypher "Eager" rule), the same one a read-then-write `DELETE`
                // gets. `MATCH (a:A) DELETE a MERGE (a2:A)` deletes one node per driving row; if the
                // pipelined MERGE for the first row runs before the second row's DELETE, its match scan
                // still sees the not-yet-deleted node and matches it instead of creating fresh — the
                // wrong result (`clauses/merge/Merge1` [14], `Merge5` [20]). Draining the read into an
                // `Eager` buffer before any MERGE decouples the upstream deletes from the MERGE scan, so
                // every delete is settled before the first match attempt.
                input: Box::new(eager_for_read_write(self.lower(input, deps))),
                pattern: pattern.clone(),
                on_create: on_create.clone(),
                on_match: on_match.clone(),
            },
            LogicalOp::SetClause { input, ops } => PhysicalOp::SetClause {
                input: Box::new(self.lower(input, deps)),
                ops: ops.clone(),
            },
            LogicalOp::Delete {
                input,
                detach,
                exprs,
            } => PhysicalOp::Delete {
                // Eagerness barrier (openCypher "Eager" rule). A `DELETE` removes graph elements its
                // own upstream read may still be scanning: in `MATCH (a)-[r]-(b) DELETE r, a, b
                // RETURN count(*)` the undirected expansion yields two rows for the one relationship,
                // but if the first row's pipelined `DELETE` runs before the second is produced, the
                // expansion no longer finds the (now-deleted) relationship and the row count collapses
                // (`clauses/delete/Delete4.feature` [1][2]). Draining the read into an `Eager` buffer
                // before any deletion decouples the read from the write, so the full pre-delete row set
                // is observed.
                input: Box::new(eager_for_read_write(self.lower(input, deps))),
                detach: *detach,
                exprs: exprs.clone(),
            },
            LogicalOp::Remove { input, ops } => PhysicalOp::Remove {
                input: Box::new(self.lower(input, deps)),
                ops: ops.clone(),
            },
            LogicalOp::Foreach {
                input,
                variable,
                list,
                body,
            } => PhysicalOp::Foreach {
                // Eagerness barrier (openCypher "Eager" rule): FOREACH is a write, so a read feeding
                // it is fully drained before any iteration runs (same rationale as CREATE/DELETE).
                input: Box::new(eager_for_read_write(self.lower(input, deps))),
                variable: variable.clone(),
                list: list.clone(),
                // The body is the correlated update sub-plan (Argument-rooted); lower it directly.
                body: Box::new(self.lower(body, deps)),
            },

            // ---- procedure -------------------------------------------------------------------
            LogicalOp::ProcedureCall {
                input,
                name,
                args,
                yields,
            } => PhysicalOp::ProcedureCall {
                input: input.as_ref().map(|i| Box::new(self.lower(i, deps))),
                name: name.clone(),
                args: args.clone(),
                yields: yields.clone(),
            },
        }
    }

    /// Lowers a bare label scan: a token-lookup index scan when the catalog has one, else a label
    /// store scan (`04 §6.2`/§6.6).
    fn lower_label_scan(
        &self,
        variable: &Var,
        label: &Label,
        deps: &mut BTreeSet<IndexId>,
    ) -> PhysicalOp {
        if let Some(idx) = self.catalog.token_lookup(label) {
            deps.insert(idx.id);
            PhysicalOp::TokenLookupScan {
                variable: variable.clone(),
                label: label.clone(),
                index: idx.id,
            }
        } else {
            PhysicalOp::NodeByLabelScan {
                variable: variable.clone(),
                label: label.clone(),
            }
        }
    }

    /// Lowers a `Filter` over its input, attempting index selection when the filter sits directly
    /// over a label scan and its predicate is an index-usable single-property predicate.
    ///
    /// The predicate is decomposed at top-level `AND`s into conjuncts; the planner tries to consume
    /// **one** conjunct into an index seek (the strongest available) and re-attaches the rest as a
    /// residual [`Filter`](PhysicalOp::Filter). When the input is not a directly-indexable label
    /// scan, or no conjunct matches an index, the whole predicate stays a residual filter over the
    /// physically-lowered input.
    fn lower_filter(
        &self,
        input: &LogicalOp,
        predicate: &Expr,
        deps: &mut BTreeSet<IndexId>,
    ) -> PhysicalOp {
        // A multi-key inline map (`MATCH (n:L {a: …, b: …})`) lowers each key to its **own** nested
        // `Filter` (see `lower::filter_inline_props`), so a composite index seek (`rmp` task #657) —
        // which needs to see every key together — would never fire. Fold a chain of `Filter`s over a
        // label scan into a single conjunction and re-enter, so the index-selection logic below sees all
        // conjuncts at once. Harmless for every existing single-key path (the folded conjunction splits
        // back into the same conjuncts a `WHERE a AND b` already produced).
        if matches!(input, LogicalOp::Filter { .. })
            && let Some((scan, folded)) = fold_label_scan_filter_chain(input, predicate)
        {
            return self.lower_filter(&scan, &folded, deps);
        }

        // Relationship-property index seek (`rmp` task #659): a filter whose equality on a
        // relationship variable sits over a standalone single-type, fixed-length `Expand` from a bare
        // all-nodes scan can seek the rel-property index instead of scanning every `:T` relationship
        // and filtering. Its input is an `Expand` (never a label scan), so it is disjoint from the
        // node-oriented paths below; try it first.
        if let Some(seek) = self.try_rel_index_seek(input, predicate, deps) {
            return seek;
        }

        // Relationship spatial (point) index seek (`rmp` task #664): a filter whose proximity predicate
        // `distance(r.p, <const>) <= <const>` on a relationship variable sits over the same standalone
        // single-type, fixed-length `Expand` from a bare all-nodes scan can seek the relationship spatial
        // grid instead of scanning every `:T` relationship and filtering. Like `try_rel_index_seek` its
        // input is an `Expand` (never a label scan), so it is disjoint from the node-oriented paths below.
        if let Some(seek) = self.try_rel_spatial_index_seek(input, predicate, deps) {
            return seek;
        }

        // Correlated (row-valued) index seek (`rmp` tasks #708 single-property, #729 composite). A
        // `Filter` sitting over an [`Apply`](LogicalOp::Apply) whose RIGHT branch is a bare label scan,
        // carrying equality/range conjuncts on the right's node keyed by values that reference only the
        // LEFT (correlated) branch — the shape `UNWIND rows AS t MATCH (b:L {p: t.k})` (single key) or
        // `MATCH (b:L {a: t.x, b: t.y})` (composite key) lowers to — seeks the index **per left row**
        // instead of scanning every `:L` node and filtering. Without this the correlation lives in the
        // `Filter` **above** a cartesian nested-loop join, so each of the N left rows drives a full
        // O(store) label scan (the O(N)-per-row cost measured on `social-network-uds` #697; the root of
        // the #312 family's O(E·N) bulk-over-Cypher).
        //
        // The predicate may be a **stacked chain** of `Filter`s (an inline `{a: …, b: …}` map lowers to
        // one `Filter` per key) bottoming out at the `Apply`, so fold the whole chain into one
        // conjunction first — otherwise each level would see only its own key and a full composite tuple
        // could never be recognised together (mirrors `fold_label_scan_filter_chain` on the
        // non-correlated path). Runs before the bare-label-scan path below (whose `input` is a scan, not
        // an `Apply`), so the two are disjoint.
        if let Some((left, right, folded)) = fold_apply_filter_chain(input, predicate)
            && let Some(seek) = self.try_correlated_index_seek(left, right, &folded, deps)
        {
            return seek;
        }

        // Correlated seek pushed THROUGH a traversal (`rmp` task #730, the expand follow-up to #708).
        // A correlated equality on a per-row anchor that then EXPANDS — `UNWIND rows AS t MATCH
        // (b:L)-[:R]->(c) WHERE b.uid = t.uid` — lowers to `Filter(b.uid = t.uid, Expand(Apply(Unwind,
        // NodeByLabelScan b)))`: the anchor's `Apply` is buried BENEATH the `Expand`, so the
        // `fold_apply_filter_chain` path above (whose input must fold straight to an `Apply`) does not
        // reach it and the anchor stays an O(N)-per-row label scan. Push the anchor equality down onto
        // that scan so the anchor seeks the index per driving row while the expand runs from each seeked
        // anchor. The inline-anchor-map form (`(b:L {uid: t.uid})-[:R]->(c)`) already seeks — the logical
        // planner places its `Filter` directly over the `Apply`, below the `Expand` — so this only rescues
        // the `WHERE`-after-pattern shape. Runs after the bare-`Apply` path (disjoint: that input folds to
        // an `Apply`, this one is an `Expand`) and before the label-scan fallback.
        if let Some(seek) = self.try_correlated_seek_through_expand(input, predicate, deps) {
            return seek;
        }

        // Index selection only fires directly over a label scan (the logical anchor of a labelled
        // node). Anything else: lower the input normally and keep the predicate as a residual filter.
        let LogicalOp::NodeByLabelScan { variable, label } = input else {
            return PhysicalOp::Filter {
                input: Box::new(self.lower(input, deps)),
                predicate: predicate.clone(),
            };
        };

        let conjuncts = split_conjuncts(predicate);

        // Composite (multi-property) seek (`rmp` task #657): collect the top-level equality conjuncts on
        // this variable, and if a composite index's FULL ordered key tuple is entirely covered by them,
        // consume exactly those conjuncts into ONE composite `NodeCompositeIndexSeek` (instead of a
        // leading-key seek + residual filters). Runs before the single-conjunct index loop so a
        // full-key composite match takes priority over consuming just the leading key.
        let eq_conjuncts: Vec<(usize, String, &Expr)> = conjuncts
            .iter()
            .enumerate()
            .filter_map(|(i, conj)| {
                let pp = analyze_property_predicate(conj, &variable.name)?;
                match pp.kind {
                    // Defer cloning the value to the consumed keys only: keep the conjunct by reference.
                    PropertyPredicateKind::Equality { value: _ } => Some((i, pp.property, *conj)),
                    _ => None,
                }
            })
            .collect();
        if eq_conjuncts.len() >= 2 {
            let available: Vec<&str> = eq_conjuncts.iter().map(|(_, p, _)| p.as_str()).collect();
            if let Some(idx) = self.catalog.label_composite_full_eq(label, &available) {
                deps.insert(idx.id);
                // Build the per-key value list in the composite's declared key order, recording which
                // conjuncts are consumed (the first matching conjunct per key, so a repeated key leaves
                // its later conjuncts as residual filters — correct: the residual restores exactness).
                let mut values: Vec<Expr> = Vec::with_capacity(idx.properties.len());
                let mut consumed: Vec<usize> = Vec::with_capacity(idx.properties.len());
                for key in &idx.properties {
                    let (ci, _, conj) = eq_conjuncts
                        .iter()
                        .find(|(ci, p, _)| p == key && !consumed.contains(ci))
                        .or_else(|| eq_conjuncts.iter().find(|(_, p, _)| p == key))
                        .expect("label_composite_full_eq guarantees every key is available");
                    let value = analyze_property_predicate(conj, &variable.name)
                        .and_then(|pp| match pp.kind {
                            PropertyPredicateKind::Equality { value } => Some(value),
                            _ => None,
                        })
                        .expect("eq_conjuncts holds only equality predicates");
                    values.push(value);
                    consumed.push(*ci);
                }
                let seek = PhysicalOp::NodeCompositeIndexSeek {
                    variable: variable.clone(),
                    label: label.clone(),
                    properties: idx.properties.clone(),
                    values,
                    index: idx.id,
                };
                let residual: Vec<&Expr> = conjuncts
                    .iter()
                    .enumerate()
                    .filter(|(j, _)| !consumed.contains(j))
                    .map(|(_, e)| *e)
                    .collect();
                return attach_residual(seek, &residual);
            }
        }

        // Find the first conjunct that names an index-usable predicate on this variable+label.
        for (i, conj) in conjuncts.iter().enumerate() {
            if let Some(pp) = analyze_property_predicate(conj, &variable.name) {
                if let Some(idx) = self.match_index(label, &pp) {
                    deps.insert(idx.id);
                    let seek = build_seek(variable, label, &pp, idx.id);
                    // Re-attach the remaining conjuncts (all but the consumed one) as a residual
                    // filter, preserving their order.
                    let residual: Vec<&Expr> = conjuncts
                        .iter()
                        .enumerate()
                        .filter(|(j, _)| *j != i)
                        .map(|(_, e)| *e)
                        .collect();
                    return attach_residual(seek, &residual);
                }
            }
            // A proximity conjunct `distance(var.prop, <const point>) <op> <const r>` can drive the
            // spatial index when one is declared on `(label, prop)`. Unlike a property seek, the grid
            // returns only a geometric **superset** (it buckets the 2D projection), so the exact
            // `distance(...) <op> r` predicate MUST be re-checked — we re-attach **all** conjuncts
            // (including this one) as the residual filter. See [`PhysicalOp::SpatialIndexSeek`].
            if let Some(sp) = analyze_spatial_predicate(conj, &variable.name) {
                // A geographic (WGS-84) centre measures `distance` in great-circle METRES, but the grid
                // buckets the 2D projection in coordinate DEGREES: a degree-sized bbox cannot bound a
                // metric radius near the antimeridian (longitude wraps ±180) or the poles (longitude
                // converges), so the grid would silently DROP true matches — a wrong result on a
                // proximity query (`rmp` #465). Decline the seek for a geographic centre and keep the
                // exact predicate on the scan path; the seek stays sound for a Cartesian CRS, where a
                // degree IS the distance unit. (A per-latitude-scaled degree bbox with an antimeridian
                // split could re-enable the index for geographic CRSs as a future optimisation.)
                if !sp.crs.is_geographic() {
                    if let Some(idx) = self.catalog.label_spatial(label, &sp.property) {
                        deps.insert(idx.id);
                        let seek = PhysicalOp::SpatialIndexSeek {
                            variable: variable.clone(),
                            label: label.clone(),
                            property: sp.property,
                            center_x: sp.center_x,
                            center_y: sp.center_y,
                            radius: sp.radius,
                            index: idx.id,
                        };
                        // Re-attach EVERY conjunct (the proximity predicate included) as the residual
                        // filter: the index is a superset, the filter restores exactness.
                        return attach_residual(seek, &conjuncts);
                    }
                }
            }
            // A `var.prop CONTAINS/ENDS WITH/STARTS WITH <needle>` conjunct can drive the **text
            // (trigram) index** when one covers `(label, prop)` (`rmp` task #662) — the only index that
            // serves `CONTAINS`/`ENDS WITH` (substring/suffix are not a contiguous key range). The
            // trigram intersection is a candidate **superset** (a *necessary*, not sufficient,
            // condition), so the exact predicate MUST be re-checked: we re-attach **all** conjuncts
            // (this one included) as the residual filter. Runs BEFORE the range-index `STARTS WITH`
            // prefix seek below, so a declared text index is preferred for `STARTS WITH` too (and it is
            // the *only* path for `CONTAINS`/`ENDS WITH`). See [`PhysicalOp::NodeTextIndexSeek`].
            if let Some((property, text_op, needle)) = analyze_text_predicate(conj, &variable.name)
            {
                if let Some(idx) = self.catalog.label_text(label, &property) {
                    deps.insert(idx.id);
                    let seek = PhysicalOp::NodeTextIndexSeek {
                        variable: variable.clone(),
                        label: label.clone(),
                        property,
                        op: text_op,
                        needle: needle.clone(),
                        index: idx.id,
                    };
                    return attach_residual(seek, &conjuncts);
                }
            }
            // A `var.prop STARTS WITH <prefix>` conjunct can drive a **bounded range seek** over the
            // order-preserving property index when one covers `(label, prop)` — `[prefix,
            // successor(prefix))` (`rmp` task #658). Like the spatial seek, the range is a candidate
            // **superset** (it admits non-prefix strings in the last-scalar carry window, and — for a
            // mixed-type property — values the bound re-check does not exclude), so the exact
            // `STARTS WITH` predicate MUST be re-checked: we re-attach **all** conjuncts (this one
            // included) as the residual filter. Reached only when NO text index covers `(label, prop)`
            // (the text-index check above returns first when one does); `ENDS WITH` / `CONTAINS` without
            // a text index stay scan + filter (a range index cannot serve them).
            if let Some((property, prefix)) = analyze_starts_with_predicate(conj, &variable.name) {
                if let Some(idx) = self.catalog.label_property(label, &property) {
                    deps.insert(idx.id);
                    let seek = PhysicalOp::NodeIndexStartsWithSeek {
                        variable: variable.clone(),
                        label: label.clone(),
                        property,
                        prefix: prefix.clone(),
                        index: idx.id,
                    };
                    return attach_residual(seek, &conjuncts);
                }
            }
        }

        // No index applied. Before falling back to a bare label scan + residual filter, try to fuse a
        // single **equality** conjunct into a precise `NodeLabelScanEq` (`rmp` task #325): it routes
        // through the `scan_filter_eq` seam, which marks only the matching nodes for SSI instead of the
        // blanket "every live node" footprint a bare label scan + filter registers (the abort-storm fix).
        // The remaining conjuncts re-attach as a residual filter. Range/spatial/other conjuncts keep the
        // plain scan + filter — only an equality predicate has a precise predicate marker to register.
        for (i, conj) in conjuncts.iter().enumerate() {
            if let Some(pp) = analyze_property_predicate(conj, &variable.name) {
                if let PropertyPredicateKind::Equality { value } = &pp.kind {
                    let seek = PhysicalOp::NodeLabelScanEq {
                        variable: variable.clone(),
                        label: label.clone(),
                        property: pp.property.clone(),
                        value: value.clone(),
                    };
                    let residual: Vec<&Expr> = conjuncts
                        .iter()
                        .enumerate()
                        .filter(|(j, _)| *j != i)
                        .map(|(_, e)| *e)
                        .collect();
                    return attach_residual(seek, &residual);
                }
            }
        }

        // Existence via a full property-index scan (`rmp` task #665): a `var.prop IS NOT NULL` conjunct
        // over an indexed `(label, prop)` is served by a `NodeIndexScan` — every index entry has a
        // present, non-null value, so scanning the whole index yields exactly the nodes carrying the
        // property, cheaper than a full store scan when the property is sparse (the Neo4j access path).
        // Runs **after** the `NodeLabelScanEq` loop, so a same-filter equality (`n.q = 5 AND
        // n.p IS NOT NULL`) still takes the precise equality scan (preserving its tight SSI footprint,
        // `rmp` #325) and the existence scan only fires when *no* equality conjunct is present. The scan
        // returns a candidate superset the seam re-checks, so the exact predicate is re-attached with
        // **all** conjuncts as the residual filter (which also trims the scan-fallback's full label scan
        // to the non-null nodes). `IS NULL` is deliberately not matched — an index cannot witness absence.
        for conj in &conjuncts {
            if let Some(property) = analyze_is_not_null(conj, &variable.name) {
                if let Some(idx) = self.catalog.label_property(label, &property) {
                    deps.insert(idx.id);
                    let scan = PhysicalOp::NodeIndexScan {
                        variable: variable.clone(),
                        label: label.clone(),
                        property,
                        ordered: false,
                        index: idx.id,
                    };
                    return attach_residual(scan, &conjuncts);
                }
            }
        }

        // No index and no equality predicate: label scan (possibly token-lookup) + the full predicate as
        // a filter.
        let scan = self.lower_label_scan(variable, label, deps);
        PhysicalOp::Filter {
            input: Box::new(scan),
            predicate: predicate.clone(),
        }
    }

    /// Attempts to lower a `Filter` over an [`Apply`](LogicalOp::Apply) whose RIGHT branch is a bare
    /// [`NodeByLabelScan`](LogicalOp::NodeByLabelScan) into a **per-left-row index seek** on that
    /// node, when a conjunct is an index-usable equality/range on the right node keyed by a value that
    /// references only the LEFT (correlated) branch (`rmp` task #708). Returns [`None`] (the caller
    /// keeps its normal paths) unless that exact shape and an `(label, property)` index both hold.
    ///
    /// This is the fix for the O(N)-per-row cost of `UNWIND rows AS t MATCH (b:L {p: t.k})` (and the
    /// two-anchor `MATCH (a:L {p: r.x}), (b:L {p: r.y}) CREATE …` of the #312 family): the logical
    /// planner leaves the correlation in a `Filter` **above** a cartesian nested-loop join, so each of
    /// the N left rows drives a full label scan of every `:L` node. Because the right branch binds
    /// **only** `variable` (a bare label scan), `analyze_property_predicate` already guarantees the seek
    /// value does not reference it, so the value's free variables are a subset of the left branch's
    /// bindings — available as the nested-loop **correlation row** (`arg`) when the right branch is
    /// rebuilt per left row. The executor's seek operators therefore evaluate the value against that
    /// correlation row (not the empty row), yielding an index seek per left row instead of a scan.
    ///
    /// **Soundness.** The seek returns the identical node set the label-scan-and-filter did: the seam
    /// re-checks each candidate's visibility, current label and current property value, and the seek is
    /// keyed by the same value the `Filter` compared against. A [`NestedLoopJoin`](PhysicalOp::NestedLoopJoin)
    /// is emitted unconditionally (never a hash join): the right branch now reads the left row's
    /// bindings, so only the per-left-row realisation is correct. Remaining conjuncts re-attach as a
    /// residual [`Filter`](PhysicalOp::Filter) **above** the join, where the merged left+right row makes
    /// every variable they reference visible.
    fn try_correlated_index_seek(
        &self,
        left: &LogicalOp,
        right: &LogicalOp,
        predicate: &Expr,
        deps: &mut BTreeSet<IndexId>,
    ) -> Option<PhysicalOp> {
        // The right branch must be a **bare** label scan: it then binds exactly `variable`, so any
        // conjunct value that does not reference `variable` references only the left (correlated)
        // branch — the invariant the per-left-row seek relies on. A richer right branch (an expand
        // chain, a nested apply) could bind other variables the value might close over, so it declines
        // here and keeps its normal lowering.
        let LogicalOp::NodeByLabelScan { variable, label } = right else {
            return None;
        };

        let conjuncts = split_conjuncts(predicate);

        // Wrap a built per-left-row `seek` (whose value(s) reference only the LEFT branch) into the
        // correlated nested-loop join, re-attaching every conjunct the seek did NOT consume as a
        // residual filter above the join (preserving conjunct order). Shared by the composite pass and
        // the single-property pass below — `this`/`deps` are threaded as parameters so the closure
        // borrows neither `self` nor `deps`, leaving `self.lower`/`deps.insert` free to run inside it.
        let finish =
            |this: &Self, seek: PhysicalOp, consumed: &[usize], deps: &mut BTreeSet<IndexId>| {
                // Lower the left branch and preserve the `Apply` lowering's eager barrier: if the left
                // performs a write and the right reads the graph, the left must settle into an `Eager`
                // buffer before the per-left-row seek runs, so a later `MATCH` never observes the left's
                // own in-flight writes (the openCypher eagerness rule; see the `LogicalOp::Apply` arm).
                let phys_left = this.lower(left, deps);
                let phys_left = if contains_write(&phys_left) && contains_read(&seek) {
                    PhysicalOp::Eager {
                        input: Box::new(phys_left),
                    }
                } else {
                    phys_left
                };
                let join = PhysicalOp::NestedLoopJoin {
                    left: Box::new(phys_left),
                    right: Box::new(seek),
                };
                let residual: Vec<&Expr> = conjuncts
                    .iter()
                    .enumerate()
                    .filter(|(j, _)| !consumed.contains(j))
                    .map(|(_, e)| *e)
                    .collect();
                attach_residual(join, &residual)
            };

        // Composite (multi-property) correlated seek (`rmp` task #729, the composite follow-up to the
        // single-property #708). Collect the equality conjuncts on the right node whose value references
        // only the LEFT branch — `analyze_property_predicate` already rejects a value referencing
        // `variable`, and the bare-scan right branch binds nothing but `variable`, so a value it accepts
        // closes over the left (correlated) row alone. If a composite index's FULL ordered key tuple is
        // entirely covered by them, lower to ONE per-left-row `NodeCompositeIndexSeek` (whose executor
        // arm evaluates every key value against the correlation row). Runs BEFORE the single-conjunct
        // loop so a full-key composite match takes priority over consuming just the leading key — mirror
        // of the non-correlated composite pass in `lower_filter`. A PARTIAL match (`label_composite_full_eq`
        // returns `None`) falls through to the single-property loop, which serves the leading key as a
        // leading-prefix `NodeIndexSeek` exactly as #708 does today.
        let eq_conjuncts: Vec<(usize, String, &Expr)> = conjuncts
            .iter()
            .enumerate()
            .filter_map(|(i, conj)| {
                let pp = analyze_property_predicate(conj, &variable.name)?;
                match pp.kind {
                    // Defer cloning the value to the consumed keys only: keep the conjunct by reference.
                    PropertyPredicateKind::Equality { value: _ } => Some((i, pp.property, *conj)),
                    _ => None,
                }
            })
            .collect();
        if eq_conjuncts.len() >= 2 {
            let available: Vec<&str> = eq_conjuncts.iter().map(|(_, p, _)| p.as_str()).collect();
            if let Some(idx) = self.catalog.label_composite_full_eq(label, &available) {
                deps.insert(idx.id);
                // Build the per-key value list in the composite's declared key order, recording which
                // conjuncts are consumed (the first matching conjunct per key, so a repeated key leaves
                // its later conjuncts as residual filters — the residual restores exactness).
                let mut values: Vec<Expr> = Vec::with_capacity(idx.properties.len());
                let mut consumed: Vec<usize> = Vec::with_capacity(idx.properties.len());
                for key in &idx.properties {
                    let (ci, _, conj) = eq_conjuncts
                        .iter()
                        .find(|(ci, p, _)| p == key && !consumed.contains(ci))
                        .or_else(|| eq_conjuncts.iter().find(|(_, p, _)| p == key))
                        .expect("label_composite_full_eq guarantees every key is available");
                    let value = analyze_property_predicate(conj, &variable.name)
                        .and_then(|pp| match pp.kind {
                            PropertyPredicateKind::Equality { value } => Some(value),
                            _ => None,
                        })
                        .expect("eq_conjuncts holds only equality predicates");
                    values.push(value);
                    consumed.push(*ci);
                }
                let seek = PhysicalOp::NodeCompositeIndexSeek {
                    variable: variable.clone(),
                    label: label.clone(),
                    properties: idx.properties.clone(),
                    values,
                    index: idx.id,
                };
                return Some(finish(self, seek, &consumed, deps));
            }
        }

        // Find the first conjunct that is an index-usable equality/range on the right node whose value
        // is independent of that node (hence of the whole right branch). This mirrors the bare-label-scan
        // index-selection loop, but the anchor is the correlated right branch of the join.
        for (i, conj) in conjuncts.iter().enumerate() {
            let Some(pp) = analyze_property_predicate(conj, &variable.name) else {
                continue;
            };
            let Some(idx) = self.match_index(label, &pp) else {
                continue;
            };
            deps.insert(idx.id);
            let seek = build_seek(variable, label, &pp, idx.id);
            return Some(finish(self, seek, &[i], deps));
        }
        None
    }

    /// Attempts the correlated push-down **through a traversal** (`rmp` task #730): a `Filter` over an
    /// [`Expand`](LogicalOp::Expand) chain that bottoms out at an [`Apply`](LogicalOp::Apply) whose right
    /// branch is a bare [`NodeByLabelScan`](LogicalOp::NodeByLabelScan) anchor. Pushes the anchor's
    /// correlated equality conjuncts down onto that scan (so the anchor seeks the index per driving row,
    /// with the expand running from each seeked anchor), leaving every other conjunct as a residual
    /// [`Filter`](PhysicalOp::Filter) above the traversal. Returns [`None`] (the caller keeps its normal
    /// residual-filter lowering) when the shape does not qualify or no pushed conjunct is index-usable.
    ///
    /// **Soundness of the push-down.** A predicate on the expand's *source* (`b` in
    /// `(b)-[:R]->(c)`) selects exactly the same `(b, r, c)` rows whether applied before or after the
    /// traversal — `b` is bound below the expand and the expand does not change it — so moving it below
    /// the `Expand` is result-preserving (standard filter-pushdown onto a traversal's anchor).
    ///
    /// **The critical correctness bar.** A conjunct is pushed **only** when its value's free variables
    /// are disjoint from *every* variable the intervening subtree binds — the anchor itself **and** every
    /// relationship/target the `Expand` chain introduces (`r`, `c`, …). Pushing a value that references a
    /// variable bound *inside* the traversal (e.g. `b.uid = c.uid`, where `c` is the expand's target)
    /// would evaluate it against an unbound variable at the anchor and change the result — so such a
    /// conjunct stays a residual filter above the expand, keeping the anchor a scan. `analyze_property_predicate`
    /// already rejects a value referencing the anchor; this adds the expand-bound-variable check.
    ///
    /// **Mechanism.** The qualifying conjuncts are pushed as a `Filter` directly over the `Apply` (below
    /// the `Expand` chain), reproducing the exact shape [`try_correlated_index_seek`] already lowers — so
    /// the seek, the composite fusion (`rmp` #729), and the reorderer/scan-revert guards all come for
    /// free by re-lowering the rewritten tree. It fires only when at least one pushed conjunct is served
    /// by an index ([`match_index`](Self::match_index)), so a no-index anchor is never moved for nothing.
    fn try_correlated_seek_through_expand(
        &self,
        input: &LogicalOp,
        predicate: &Expr,
        deps: &mut BTreeSet<IndexId>,
    ) -> Option<PhysicalOp> {
        // The filter's input must be an `Expand` (a traversal) — the shape the bare-`Apply` path above
        // cannot reach. Walk the `Expand` chain down to the anchor's `Apply`, collecting every variable
        // the chain binds (each hop's relationship + target); a non-`Expand`, non-`Apply` node on the
        // way (another `Filter`, a nested apply, a scan) declines.
        let LogicalOp::Expand { .. } = input else {
            return None;
        };
        let mut expand_bound: Vec<&str> = Vec::new();
        let mut cur = input;
        let (anchor, label) = loop {
            match cur {
                LogicalOp::Expand {
                    input: inner,
                    relationship,
                    to,
                    ..
                } => {
                    // Every variable a hop introduces is off-limits to a pushed value (it is unbound at
                    // the anchor, below the expand).
                    expand_bound.push(relationship.name.as_str());
                    expand_bound.push(to.name.as_str());
                    cur = inner;
                }
                LogicalOp::Apply { right, .. } => {
                    let LogicalOp::NodeByLabelScan { variable, label } = right.as_ref() else {
                        return None; // a richer / non-bare right branch is not a materialisable anchor
                    };
                    break (variable, label);
                }
                _ => return None,
            }
        };

        // A conjunct is PUSHABLE when it constrains `anchor.<prop>` (equality or range) against a value
        // whose free variables are disjoint from every expand-bound variable. `analyze_property_predicate`
        // already guarantees the value does not reference the anchor; the added check rejects a value
        // referencing anything the traversal binds (the critical correctness bar).
        let conjuncts = split_conjuncts(predicate);
        let is_pushable = |conj: &Expr| -> bool {
            let Some(pp) = analyze_property_predicate(conj, &anchor.name) else {
                return false;
            };
            let value = match &pp.kind {
                PropertyPredicateKind::Equality { value } => value,
                PropertyPredicateKind::Range { value, .. } => value,
            };
            !expand_bound
                .iter()
                .any(|bound| expr_references_var(value, bound))
        };
        let (push_down, keep_above): (Vec<&Expr>, Vec<&Expr>) =
            conjuncts.iter().partition(|conj| is_pushable(conj));

        // Fire only when the push produces a real seek: at least one pushed conjunct must be served by an
        // index (a single-property index, or a composite's leading key). Otherwise the anchor would be
        // moved below the expand for no acceleration — decline and keep the scan + residual filter.
        let any_indexable = push_down.iter().any(|conj| {
            analyze_property_predicate(conj, &anchor.name)
                .is_some_and(|pp| self.match_index(label, &pp).is_some())
        });
        if !any_indexable {
            return None;
        }

        // Rewrite: push the qualifying conjuncts as a `Filter` directly over the `Apply` (below the
        // expand chain), and re-lower. The re-lowering hits `try_correlated_index_seek` on that pushed
        // filter (single-property #708 or composite #729), while any non-pushable conjunct stays a
        // residual `Filter` above the rebuilt traversal. Re-entry is safe: the residual carries no
        // pushable anchor conjunct (they were all consumed into `push_down`), so this method declines the
        // second time and the residual becomes an ordinary filter.
        let pushed_predicate = conjunction_of(&push_down)?;
        let pushed_tree = push_filter_below_expands(input, pushed_predicate)?;
        let rewritten = match conjunction_of(&keep_above) {
            Some(residual) => LogicalOp::Filter {
                input: Box::new(pushed_tree),
                predicate: residual,
            },
            None => pushed_tree,
        };
        Some(self.lower(&rewritten, deps))
    }

    /// Attempts to lower a `Filter` carrying an **equality or a range predicate on a relationship
    /// variable**, sitting over a standalone single-type fixed-length [`Expand`](LogicalOp::Expand) from a
    /// bare [`AllNodesScan`](LogicalOp::AllNodesScan), into a [`RelIndexSeek`](PhysicalOp::RelIndexSeek)
    /// (`rmp` task #659), a [`RelIndexRangeSeek`](PhysicalOp::RelIndexRangeSeek) (`rmp` task #680), or —
    /// when a **composite** relationship index's full ordered tuple is covered by two or more equality
    /// conjuncts — a single [`RelCompositeIndexSeek`](PhysicalOp::RelCompositeIndexSeek) (`rmp` task
    /// #666). Returns [`None`] (the caller keeps its normal paths) when the shape does not qualify or no
    /// `Online` relationship index covers the `(type, property)` the predicate names.
    ///
    /// Only the **seek-materialisable** shape qualifies: exactly one relationship type (a single-type
    /// index), fixed length (`range` is `None`), no earlier pattern relationships to exclude
    /// (`prior_rels` empty), no per-hop var-length property map, and an anchor that is a **bare**
    /// [`AllNodesScan`](LogicalOp::AllNodesScan) of the expand's `from` — so both endpoints are
    /// unconstrained and can be materialised directly from each matched relationship's own record.
    /// `-[r:T*]-` (var-length), `-[r:T1|T2]-` (no single-type index), a label-constrained anchor (a
    /// label scan, not an all-nodes scan), and an `OPTIONAL MATCH` (whose anchor is an `Apply`-over-
    /// `Argument`, never a bare scan) therefore all decline here and stay scans.
    ///
    /// The consumption order is **composite-equality → single equality → single range** (each pass
    /// consumes exactly one predicate; every other conjunct — a second range bound, a residual
    /// `HasLabels` on an endpoint, another property predicate — is re-attached as a residual
    /// [`Filter`](PhysicalOp::Filter)). Equality is tried before range because it is strictly more
    /// selective and no cost-based rewrite reverts a relationship seek to a scan; it also keeps every
    /// pre-#680 plan byte-identical. The executor's re-check keeps the result exact either way.
    fn try_rel_index_seek(
        &self,
        input: &LogicalOp,
        predicate: &Expr,
        deps: &mut BTreeSet<IndexId>,
    ) -> Option<PhysicalOp> {
        // Collect every conjunct of the (possibly nested) filter chain down to the bottom `Expand`, so
        // a multi-key inline map (`{a: …, b: …}`, which lowers to stacked `Filter`s) still exposes the
        // relationship-equality conjunct.
        let (expand, conjuncts) = fold_expand_filter_chain(input, predicate)?;
        let LogicalOp::Expand {
            input: exp_input,
            from,
            relationship,
            to,
            direction,
            types,
            range,
            prior_rels,
            rel_props,
        } = expand
        else {
            return None;
        };
        // Seek-materialisable shape only (see the doc): fixed length, standalone, single type, bare
        // anchor scan.
        if range.is_some() || !prior_rels.is_empty() || rel_props.is_some() {
            return None;
        }
        let [rel_type] = types.as_slice() else {
            return None; // zero or multiple types: no single-type rel-property index applies
        };
        let LogicalOp::AllNodesScan { variable: anchor } = exp_input.as_ref() else {
            return None; // a constrained anchor (label scan / correlated Apply) is not materialisable
        };
        if anchor.name != from.name {
            return None;
        }

        // A relationship seek binds ALL THREE of `relationship`, `from` and `to` (the endpoints are
        // materialised from each matched relationship's own record), and the executor evaluates its seek
        // value against the **empty row** — there is no correlation feed for a bare-`AllNodesScan` anchor.
        // So a value that references ANY variable is unknowable when the seek runs.
        //
        // `analyze_property_predicate` only rejects a value referencing the *relationship* variable, which
        // left `MATCH (a)-[r:T]->(b) WHERE r.p = a.q` lowering to a seek whose value evaluated to `null` —
        // returning ZERO rows where the scan path returns the true matches (a silent wrong answer, i.e.
        // declaring an index made a correct query return nothing). Guard every consumed predicate with
        // this test instead: no variable at all ⇒ the empty-row evaluation is exactly right; otherwise
        // decline, and the conjunct stays a residual `Filter` over the scan (`rmp` task #680, fixing a
        // pre-existing `rmp` #659 / #666 defect).
        let seekable_value = |value: &Expr| !expr_contains_variable(value);

        // Composite (multi-property) relationship seek (`rmp` task #666): collect the equality conjuncts
        // on the relationship variable, and if a composite relationship index's FULL ordered key tuple
        // is entirely covered by them, consume exactly those conjuncts into ONE `RelCompositeIndexSeek`
        // (instead of a single leading-key seek + residual filters). Runs before the single-conjunct
        // loop below so a full-key composite match takes priority over consuming just the leading key.
        let eq_conjuncts: Vec<(usize, String, &Expr)> = conjuncts
            .iter()
            .enumerate()
            .filter_map(|(i, conj)| {
                let pp = analyze_property_predicate(conj, &relationship.name)?;
                match pp.kind {
                    // Defer cloning the value to the consumed keys only: keep the conjunct by reference.
                    // A value referencing a variable is NOT a usable composite key (see `seekable_value`):
                    // dropping it here means the composite's full tuple is no longer covered, so the
                    // composite seek declines and the conjunct stays a residual filter.
                    PropertyPredicateKind::Equality { value } if seekable_value(&value) => {
                        Some((i, pp.property, *conj))
                    }
                    _ => None,
                }
            })
            .collect();
        if eq_conjuncts.len() >= 2 {
            let available: Vec<&str> = eq_conjuncts.iter().map(|(_, p, _)| p.as_str()).collect();
            if let Some(idx) = self.catalog.rel_composite_full_eq(rel_type, &available) {
                deps.insert(idx.id);
                // Build the per-key value list in the composite's declared key order, recording which
                // conjuncts are consumed (the first matching conjunct per key, so a repeated key leaves
                // its later conjuncts as residual filters — the residual restores exactness).
                let mut values: Vec<Expr> = Vec::with_capacity(idx.properties.len());
                let mut consumed: Vec<usize> = Vec::with_capacity(idx.properties.len());
                for key in &idx.properties {
                    let (ci, _, conj) = eq_conjuncts
                        .iter()
                        .find(|(ci, p, _)| p == key && !consumed.contains(ci))
                        .or_else(|| eq_conjuncts.iter().find(|(_, p, _)| p == key))
                        .expect("rel_composite_full_eq guarantees every key is available");
                    let value = analyze_property_predicate(conj, &relationship.name)
                        .and_then(|pp| match pp.kind {
                            PropertyPredicateKind::Equality { value } => Some(value),
                            _ => None,
                        })
                        .expect("eq_conjuncts holds only equality predicates");
                    values.push(value);
                    consumed.push(*ci);
                }
                let seek = PhysicalOp::RelCompositeIndexSeek {
                    relationship: relationship.clone(),
                    from: from.clone(),
                    to: to.clone(),
                    rel_type: rel_type.clone(),
                    properties: idx.properties.clone(),
                    values,
                    direction: *direction,
                    index: idx.id,
                };
                let residual: Vec<&Expr> = conjuncts
                    .iter()
                    .enumerate()
                    .filter(|(j, _)| !consumed.contains(j))
                    .map(|(_, e)| *e)
                    .collect();
                return Some(attach_residual(seek, &residual));
            }
        }

        // Consume the first equality conjunct on the relationship variable whose `(type, property)` an
        // `Online` rel-property index covers; re-attach the rest as a residual filter.
        for (i, conj) in conjuncts.iter().enumerate() {
            let Some(pp) = analyze_property_predicate(conj, &relationship.name) else {
                continue;
            };
            let PropertyPredicateKind::Equality { value } = pp.kind else {
                continue; // a range conjunct is served by the SECOND pass below (`rmp` #680)
            };
            if !seekable_value(&value) {
                continue; // the value references a variable the seek itself binds: stay a scan + filter
            }
            let Some(idx) = self.catalog.rel_property(rel_type, &pp.property) else {
                continue;
            };
            deps.insert(idx.id);
            let seek = PhysicalOp::RelIndexSeek {
                relationship: relationship.clone(),
                from: from.clone(),
                to: to.clone(),
                rel_type: rel_type.clone(),
                property: pp.property,
                value,
                direction: *direction,
                index: idx.id,
            };
            let residual: Vec<&Expr> = conjuncts
                .iter()
                .enumerate()
                .filter(|(j, _)| *j != i)
                .map(|(_, e)| *e)
                .collect();
            return Some(attach_residual(seek, &residual));
        }

        // No indexable equality: consume the first **range** conjunct (`<`, `<=`, `>`, `>=`) on the
        // relationship variable whose `(type, property)` an `Online` relationship RANGE index covers, into
        // a `RelIndexRangeSeek` (`rmp` task #680) — the relationship analogue of the node
        // `NodeIndexRangeSeek`, which a `>=` on a relationship property used to be denied (it stayed a
        // full `ExpandAll` + `Filter` scan; the empirical finding of `rmp` #673's fraud-oltp example).
        //
        // A **second, separate pass** rather than one combined loop (which is how the node path does it):
        // an equality is strictly more selective than a range, and — unlike the node path — no cost-based
        // rewrite can later flip a relationship seek back to a scan, so consuming a *leading* range
        // conjunct in preference to a later equality would be a permanent pessimisation. Ordering the
        // passes this way also keeps every pre-#680 plan byte-identical: nothing that used to lower to a
        // `RelIndexSeek` changes shape.
        //
        // Only ONE bound is consumed (like the node range seek). A two-sided range
        // (`r.p >= lo AND r.p <= hi`) lowers to a seek on the first bound + a residual `Filter` for the
        // second — the seek is a candidate superset of neither bound alone but of *both* re-checked sets,
        // and the residual restores exactness. `catalog.rel_property` returns only a `RelProperty` (RANGE)
        // or a leading-key `RelComposite` index — never a TEXT / POINT / FULLTEXT / VECTOR kind, none of
        // which can answer an ordered range — and the coordinator's catalog surfaces only `Online` ones.
        for (i, conj) in conjuncts.iter().enumerate() {
            let Some(pp) = analyze_property_predicate(conj, &relationship.name) else {
                continue;
            };
            let PropertyPredicateKind::Range { bound, value } = pp.kind else {
                continue; // equality was already tried above
            };
            if !seekable_value(&value) {
                continue; // the bound references a variable the seek itself binds: stay a scan + filter
            }
            let Some(idx) = self.catalog.rel_property(rel_type, &pp.property) else {
                continue;
            };
            deps.insert(idx.id);
            let seek = PhysicalOp::RelIndexRangeSeek {
                relationship: relationship.clone(),
                from: from.clone(),
                to: to.clone(),
                rel_type: rel_type.clone(),
                property: pp.property,
                bound,
                value,
                direction: *direction,
                index: idx.id,
            };
            let residual: Vec<&Expr> = conjuncts
                .iter()
                .enumerate()
                .filter(|(j, _)| *j != i)
                .map(|(_, e)| *e)
                .collect();
            return Some(attach_residual(seek, &residual));
        }
        None
    }

    /// Attempts to lower a `Filter` carrying a **proximity predicate on a relationship variable**
    /// (`distance(r.p, <const>) <op> <const>`) sitting over a standalone single-type fixed-length
    /// [`Expand`](LogicalOp::Expand) from a bare [`AllNodesScan`](LogicalOp::AllNodesScan), into a
    /// [`RelSpatialIndexSeek`](PhysicalOp::RelSpatialIndexSeek) (`rmp` task #664) — the relationship
    /// analogue of the node [`SpatialIndexSeek`](PhysicalOp::SpatialIndexSeek) lowering, sharing the
    /// seek-materialisable shape check with [`try_rel_index_seek`](Self::try_rel_index_seek).
    ///
    /// Returns [`None`] (the caller keeps its normal paths) when the shape does not qualify, the centre
    /// is **geographic** (a WGS-84 centre measures `distance` in metres while the grid buckets degrees —
    /// the same soundness decline as the node seek, `rmp` #465), or no `Online` relationship spatial
    /// index covers the `(type, property)` the predicate names. Like the node spatial seek the grid is a
    /// superset, so **every** conjunct (the proximity predicate included) is re-attached as a residual
    /// [`Filter`](PhysicalOp::Filter) — the executor's re-check keeps the result exact.
    fn try_rel_spatial_index_seek(
        &self,
        input: &LogicalOp,
        predicate: &Expr,
        deps: &mut BTreeSet<IndexId>,
    ) -> Option<PhysicalOp> {
        let (expand, conjuncts) = fold_expand_filter_chain(input, predicate)?;
        let LogicalOp::Expand {
            input: exp_input,
            from,
            relationship,
            to,
            direction,
            types,
            range,
            prior_rels,
            rel_props,
        } = expand
        else {
            return None;
        };
        // Seek-materialisable shape only (shared with `try_rel_index_seek`): fixed length, standalone,
        // single type, bare anchor scan.
        if range.is_some() || !prior_rels.is_empty() || rel_props.is_some() {
            return None;
        }
        let [rel_type] = types.as_slice() else {
            return None; // zero or multiple types: no single-type rel spatial index applies
        };
        let LogicalOp::AllNodesScan { variable: anchor } = exp_input.as_ref() else {
            return None; // a constrained anchor (label scan / correlated Apply) is not materialisable
        };
        if anchor.name != from.name {
            return None;
        }
        // Consume the first proximity conjunct on the relationship variable whose `(type, property)` a
        // relationship spatial index covers; re-attach **all** conjuncts (this one included) as a
        // residual filter (the grid is a geometric superset — the filter restores exactness).
        for conj in conjuncts.iter() {
            let Some(sp) = analyze_spatial_predicate(conj, &relationship.name) else {
                continue;
            };
            // A geographic (WGS-84) centre measures `distance` in great-circle metres while the grid
            // buckets the 2D projection in coordinate degrees, so the seek is unsound near the
            // antimeridian/poles — decline and keep the exact predicate on the scan path (`rmp` #465),
            // exactly like the node spatial seek. Sound for a Cartesian CRS (degrees == distance unit).
            if sp.crs.is_geographic() {
                continue;
            }
            let Some(idx) = self.catalog.rel_spatial(rel_type, &sp.property) else {
                continue;
            };
            deps.insert(idx.id);
            let seek = PhysicalOp::RelSpatialIndexSeek {
                relationship: relationship.clone(),
                from: from.clone(),
                to: to.clone(),
                rel_type: rel_type.clone(),
                property: sp.property,
                center_x: sp.center_x,
                center_y: sp.center_y,
                radius: sp.radius,
                direction: *direction,
                index: idx.id,
            };
            return Some(attach_residual(seek, &conjuncts));
        }
        None
    }

    /// The catalog index that serves `pp` on `label`, if any (equality/range → property/composite).
    fn match_index<'a>(
        &'a self,
        label: &Label,
        pp: &PropertyPredicate,
    ) -> Option<&'a IndexDescriptor> {
        // Both equality and range predicates on a single property are served by a property index
        // (or a composite whose leading key matches), per the catalog's `label_property` contract.
        self.catalog.label_property(label, &pp.property)
    }

    /// Lowers a `Limit`: fuse a `Limit(Sort)` into [`TopN`](PhysicalOp::TopN), or push a `Limit`
    /// below a row-count-preserving projection; otherwise a plain [`Limit`](PhysicalOp::Limit).
    ///
    /// **Eager-write barrier.** openCypher write clauses are eager: `LIMIT` bounds the returned
    /// rows, never the side effects (`CREATE (n) RETURN n LIMIT 0` still creates the node). A
    /// `Limit` operator stops pulling from its input once satisfied, which would suppress upstream
    /// writes — so when the limited subtree contains a write operator it is wrapped in an
    /// [`Eager`](PhysicalOp::Eager) barrier that drains it in full first. `TopN` needs no barrier:
    /// sorting already consumes its whole input.
    fn lower_limit(
        &self,
        input: &LogicalOp,
        count: &Expr,
        deps: &mut BTreeSet<IndexId>,
    ) -> PhysicalOp {
        match input {
            // Limit directly over a Sort -> Top-N (compute only the top k rows). Sound by
            // definition: TopN(k, sort) == Limit(k, Sort(sort)).
            LogicalOp::Sort {
                input: sort_input,
                keys,
            } => PhysicalOp::TopN {
                input: Box::new(self.lower(sort_input, deps)),
                keys: keys.clone(),
                limit: count.clone(),
            },
            // Limit over a row-count-preserving projection (no DISTINCT, no aggregation) -> push the
            // limit BELOW the projection. Sound: a 1:1 projection neither drops nor adds rows, so the
            // first k rows are the same before and after projecting.
            LogicalOp::Projection {
                input: proj_input,
                items,
                distinct: false,
            } => {
                let pushed = PhysicalOp::Limit {
                    input: Box::new(eager_over_writes(self.lower(proj_input, deps))),
                    count: count.clone(),
                };
                PhysicalOp::Projection {
                    input: Box::new(pushed),
                    items: items.clone(),
                    distinct: false,
                }
            }
            // Any other input (incl. DISTINCT projection / Aggregation): plain Limit, NOT pushed —
            // pushing below a row-count-changing operator would change the result.
            other => PhysicalOp::Limit {
                input: Box::new(eager_over_writes(self.lower(other, deps))),
                count: count.clone(),
            },
        }
    }
}

/// Wraps `input` in an [`Eager`](PhysicalOp::Eager) barrier when its subtree contains a write
/// operator, so a `Limit` above cannot suppress the writes (see [`Planner::lower_limit`]).
fn eager_over_writes(input: PhysicalOp) -> PhysicalOp {
    if contains_write(&input) {
        PhysicalOp::Eager {
            input: Box::new(input),
        }
    } else {
        input
    }
}

/// Wraps a `DELETE`'s input in an [`Eager`](PhysicalOp::Eager) barrier when that input reads the
/// graph, so the entire pre-delete row set is materialized before any element is removed (the
/// openCypher delete-after-read eagerness rule; see the `LogicalOp::Delete` lowering). An input
/// that performs no graph read (e.g. `CREATE (n) DELETE n`, where the row is freshly created and
/// cannot be re-scanned) needs no barrier.
fn eager_for_read_write(input: PhysicalOp) -> PhysicalOp {
    if contains_read(&input) {
        PhysicalOp::Eager {
            input: Box::new(input),
        }
    } else {
        input
    }
}

/// Whether the physical (sub)plan reads the graph through a scan, index seek or expansion anywhere —
/// the reads a same-query write could interfere with.
fn contains_read(op: &PhysicalOp) -> bool {
    match op {
        PhysicalOp::AllNodesScan { .. }
        | PhysicalOp::NodeByLabelScan { .. }
        | PhysicalOp::TokenLookupScan { .. }
        | PhysicalOp::NodeIndexSeek { .. }
        | PhysicalOp::NodeCompositeIndexSeek { .. }
        | PhysicalOp::NodeLabelScanEq { .. }
        | PhysicalOp::NodeIndexRangeSeek { .. }
        | PhysicalOp::NodeIndexScan { .. }
        | PhysicalOp::NodeIndexStartsWithSeek { .. }
        | PhysicalOp::SpatialIndexSeek { .. }
        | PhysicalOp::NodeTextIndexSeek { .. }
        | PhysicalOp::AllRelationshipsScan { .. }
        | PhysicalOp::RelIndexSeek { .. }
        | PhysicalOp::RelIndexRangeSeek { .. }
        | PhysicalOp::RelCompositeIndexSeek { .. }
        | PhysicalOp::RelSpatialIndexSeek { .. }
        | PhysicalOp::ExpandAll { .. }
        | PhysicalOp::ExpandInto { .. }
        | PhysicalOp::QuantifiedPath { .. }
        | PhysicalOp::ShortestPath { .. } => true,
        PhysicalOp::Filter { input, .. }
        | PhysicalOp::Projection { input, .. }
        | PhysicalOp::Aggregation { input, .. }
        | PhysicalOp::Sort { input, .. }
        | PhysicalOp::TopN { input, .. }
        | PhysicalOp::Skip { input, .. }
        | PhysicalOp::Limit { input, .. }
        | PhysicalOp::Eager { input }
        | PhysicalOp::Unwind { input, .. }
        | PhysicalOp::LoadCsv { input, .. }
        | PhysicalOp::NamedPath { input, .. }
        | PhysicalOp::Create { input, .. }
        | PhysicalOp::Merge { input, .. }
        | PhysicalOp::SetClause { input, .. }
        | PhysicalOp::Delete { input, .. }
        | PhysicalOp::Remove { input, .. }
        | PhysicalOp::Foreach { input, .. }
        | PhysicalOp::Optional { input, .. } => contains_read(input),
        PhysicalOp::NestedLoopJoin { left, right }
        | PhysicalOp::HashJoin { left, right, .. }
        | PhysicalOp::Union { left, right, .. } => contains_read(left) || contains_read(right),
        PhysicalOp::ProcedureCall { input, .. } => input.as_deref().is_some_and(contains_read),
        PhysicalOp::Argument { .. } | PhysicalOp::Empty => false,
    }
}

/// Whether the physical (sub)plan contains a write operator
/// (`Create`/`Merge`/`SetClause`/`Delete`/`Remove`) anywhere.
fn contains_write(op: &PhysicalOp) -> bool {
    match op {
        PhysicalOp::Create { .. }
        | PhysicalOp::Merge { .. }
        | PhysicalOp::SetClause { .. }
        | PhysicalOp::Delete { .. }
        | PhysicalOp::Remove { .. }
        | PhysicalOp::Foreach { .. } => true,
        PhysicalOp::Filter { input, .. }
        | PhysicalOp::Projection { input, .. }
        | PhysicalOp::Aggregation { input, .. }
        | PhysicalOp::Sort { input, .. }
        | PhysicalOp::TopN { input, .. }
        | PhysicalOp::Skip { input, .. }
        | PhysicalOp::Limit { input, .. }
        | PhysicalOp::Eager { input }
        | PhysicalOp::Unwind { input, .. }
        | PhysicalOp::LoadCsv { input, .. }
        | PhysicalOp::ExpandAll { input, .. }
        | PhysicalOp::ExpandInto { input, .. }
        | PhysicalOp::ShortestPath { input, .. }
        | PhysicalOp::QuantifiedPath { input, .. }
        | PhysicalOp::NamedPath { input, .. }
        | PhysicalOp::Optional { input, .. } => contains_write(input),
        PhysicalOp::NestedLoopJoin { left, right }
        | PhysicalOp::HashJoin { left, right, .. }
        | PhysicalOp::Union { left, right, .. } => contains_write(left) || contains_write(right),
        PhysicalOp::ProcedureCall { input, .. } => input.as_deref().is_some_and(contains_write),
        PhysicalOp::AllNodesScan { .. }
        | PhysicalOp::NodeByLabelScan { .. }
        | PhysicalOp::TokenLookupScan { .. }
        | PhysicalOp::NodeIndexSeek { .. }
        | PhysicalOp::NodeCompositeIndexSeek { .. }
        | PhysicalOp::NodeLabelScanEq { .. }
        | PhysicalOp::NodeIndexRangeSeek { .. }
        | PhysicalOp::NodeIndexScan { .. }
        | PhysicalOp::NodeIndexStartsWithSeek { .. }
        | PhysicalOp::SpatialIndexSeek { .. }
        | PhysicalOp::NodeTextIndexSeek { .. }
        | PhysicalOp::AllRelationshipsScan { .. }
        | PhysicalOp::RelIndexSeek { .. }
        | PhysicalOp::RelIndexRangeSeek { .. }
        | PhysicalOp::RelCompositeIndexSeek { .. }
        | PhysicalOp::RelSpatialIndexSeek { .. }
        | PhysicalOp::Argument { .. }
        | PhysicalOp::Empty => false,
    }
}

/// Whether the physical (sub)plan invokes a procedure (`CALL …` ⇒ a [`PhysicalOp::ProcedureCall`])
/// anywhere — the structural predicate behind [`PhysicalPlan::calls_procedure`] (`rmp` task #548).
///
/// **Exhaustive by construction**: every [`PhysicalOp`] variant is matched with no `_` wildcard, so a
/// new operator variant is a compile error until it is classified here. This is the whole point of the
/// rewrite — the previous server-side `op_calls_procedure` used a `_ => false` catch-all that only
/// recursed a *subset* of child-bearing operators (it missed `ExpandAll`/`ExpandInto`/`NamedPath`/
/// `ShortestPath`/`Eager`/`LoadCsv`), so a `ProcedureCall` nested under one of them escaped detection
/// and a full-text/spatial read (e.g. `CALL db.index.fulltext.queryNodes(…) YIELD node MATCH (node)-->…`)
/// was mis-dispatched off-thread and failed with a spurious "no such index" error.
fn contains_procedure_call(op: &PhysicalOp) -> bool {
    match op {
        PhysicalOp::ProcedureCall { .. } => true,
        // Single-input operators: recurse into the one child.
        PhysicalOp::Filter { input, .. }
        | PhysicalOp::Projection { input, .. }
        | PhysicalOp::Aggregation { input, .. }
        | PhysicalOp::Sort { input, .. }
        | PhysicalOp::TopN { input, .. }
        | PhysicalOp::Skip { input, .. }
        | PhysicalOp::Limit { input, .. }
        | PhysicalOp::Eager { input }
        | PhysicalOp::Unwind { input, .. }
        | PhysicalOp::LoadCsv { input, .. }
        | PhysicalOp::ExpandAll { input, .. }
        | PhysicalOp::ExpandInto { input, .. }
        | PhysicalOp::ShortestPath { input, .. }
        | PhysicalOp::QuantifiedPath { input, .. }
        | PhysicalOp::NamedPath { input, .. }
        | PhysicalOp::Create { input, .. }
        | PhysicalOp::Merge { input, .. }
        | PhysicalOp::SetClause { input, .. }
        | PhysicalOp::Delete { input, .. }
        | PhysicalOp::Remove { input, .. }
        | PhysicalOp::Optional { input, .. } => contains_procedure_call(input),
        // `Foreach` has two children — the driving `input` and the `body` clause; check both.
        PhysicalOp::Foreach { input, body, .. } => {
            contains_procedure_call(input) || contains_procedure_call(body)
        }
        // Binary operators: recurse into both branches.
        PhysicalOp::NestedLoopJoin { left, right }
        | PhysicalOp::HashJoin { left, right, .. }
        | PhysicalOp::Union { left, right, .. } => {
            contains_procedure_call(left) || contains_procedure_call(right)
        }
        // Leaves (scans / index seeks / `Argument` / `Empty`) never call a procedure.
        PhysicalOp::AllNodesScan { .. }
        | PhysicalOp::NodeByLabelScan { .. }
        | PhysicalOp::TokenLookupScan { .. }
        | PhysicalOp::NodeIndexSeek { .. }
        | PhysicalOp::NodeCompositeIndexSeek { .. }
        | PhysicalOp::NodeLabelScanEq { .. }
        | PhysicalOp::NodeIndexRangeSeek { .. }
        | PhysicalOp::NodeIndexScan { .. }
        | PhysicalOp::NodeIndexStartsWithSeek { .. }
        | PhysicalOp::SpatialIndexSeek { .. }
        | PhysicalOp::NodeTextIndexSeek { .. }
        | PhysicalOp::AllRelationshipsScan { .. }
        | PhysicalOp::RelIndexSeek { .. }
        | PhysicalOp::RelIndexRangeSeek { .. }
        | PhysicalOp::RelCompositeIndexSeek { .. }
        | PhysicalOp::RelSpatialIndexSeek { .. }
        | PhysicalOp::Argument { .. }
        | PhysicalOp::Empty => false,
    }
}

/// Whether **every** [`PhysicalOp::ProcedureCall`] in the (sub)plan targets a procedure the `registry`
/// classifies **reader-safe** (`rmp` task #546) — the structural predicate behind
/// [`PhysicalPlan::calls_only_reader_safe_procedures`]. Returns `true` for a subtree with no procedure
/// call (vacuously all-safe).
///
/// **Exhaustive by construction** (mirrors [`contains_procedure_call`]): every [`PhysicalOp`] variant
/// is matched with no `_` wildcard, so a new child-bearing operator is a compile error until it is
/// classified here — a `ProcedureCall` nested under a newly-added operator can never silently escape
/// the reader-safety check and be mis-dispatched off-thread (the `rmp` #548 lesson).
fn all_procedure_calls_reader_safe(
    op: &PhysicalOp,
    registry: &dyn crate::procedure_registry::ProcedureRegistry,
) -> bool {
    match op {
        // The call itself must be reader-safe, AND any correlated input subtree must also be all-safe.
        PhysicalOp::ProcedureCall { input, name, .. } => {
            registry.is_reader_safe(&name.join("."))
                && input
                    .as_deref()
                    .is_none_or(|i| all_procedure_calls_reader_safe(i, registry))
        }
        // Single-input operators: recurse into the one child.
        PhysicalOp::Filter { input, .. }
        | PhysicalOp::Projection { input, .. }
        | PhysicalOp::Aggregation { input, .. }
        | PhysicalOp::Sort { input, .. }
        | PhysicalOp::TopN { input, .. }
        | PhysicalOp::Skip { input, .. }
        | PhysicalOp::Limit { input, .. }
        | PhysicalOp::Eager { input }
        | PhysicalOp::Unwind { input, .. }
        | PhysicalOp::LoadCsv { input, .. }
        | PhysicalOp::ExpandAll { input, .. }
        | PhysicalOp::ExpandInto { input, .. }
        | PhysicalOp::ShortestPath { input, .. }
        | PhysicalOp::QuantifiedPath { input, .. }
        | PhysicalOp::NamedPath { input, .. }
        | PhysicalOp::Create { input, .. }
        | PhysicalOp::Merge { input, .. }
        | PhysicalOp::SetClause { input, .. }
        | PhysicalOp::Delete { input, .. }
        | PhysicalOp::Remove { input, .. }
        | PhysicalOp::Optional { input, .. } => all_procedure_calls_reader_safe(input, registry),
        // `Foreach` has two children — the driving `input` and the `body` clause; check both.
        PhysicalOp::Foreach { input, body, .. } => {
            all_procedure_calls_reader_safe(input, registry)
                && all_procedure_calls_reader_safe(body, registry)
        }
        // Binary operators: recurse into both branches.
        PhysicalOp::NestedLoopJoin { left, right }
        | PhysicalOp::HashJoin { left, right, .. }
        | PhysicalOp::Union { left, right, .. } => {
            all_procedure_calls_reader_safe(left, registry)
                && all_procedure_calls_reader_safe(right, registry)
        }
        // Leaves (scans / index seeks / `Argument` / `Empty`) never call a procedure — vacuously safe.
        PhysicalOp::AllNodesScan { .. }
        | PhysicalOp::NodeByLabelScan { .. }
        | PhysicalOp::TokenLookupScan { .. }
        | PhysicalOp::NodeIndexSeek { .. }
        | PhysicalOp::NodeCompositeIndexSeek { .. }
        | PhysicalOp::NodeLabelScanEq { .. }
        | PhysicalOp::NodeIndexRangeSeek { .. }
        | PhysicalOp::NodeIndexScan { .. }
        | PhysicalOp::NodeIndexStartsWithSeek { .. }
        | PhysicalOp::SpatialIndexSeek { .. }
        | PhysicalOp::NodeTextIndexSeek { .. }
        | PhysicalOp::AllRelationshipsScan { .. }
        | PhysicalOp::RelIndexSeek { .. }
        | PhysicalOp::RelIndexRangeSeek { .. }
        | PhysicalOp::RelCompositeIndexSeek { .. }
        | PhysicalOp::RelSpatialIndexSeek { .. }
        | PhysicalOp::Argument { .. }
        | PhysicalOp::Empty => true,
    }
}

/// Whether `op` is a **top-level** write operator (`Create`/`Merge`/`SetClause`/`Delete`/`Remove`/
/// `Foreach`).
///
/// A query whose physical-plan **root** is such an operator has no `RETURN` and therefore yields zero
/// result rows (openCypher: a write's effect is a summary-only side effect). When a `RETURN` follows
/// the write, the plan root is the projection above it, not the write, so this is `false`.
///
/// The single source of truth for the write-root test: the executor uses it to set the cursor's
/// `emits_rows` flag, and [`PhysicalPlan::query_type`] uses it to tell [`QueryType::Write`] apart from
/// [`QueryType::ReadWrite`]. Co-located with [`contains_write`] so the two predicates share one
/// authoritative write-variant list and cannot drift.
pub(crate) fn root_is_write(op: &PhysicalOp) -> bool {
    matches!(
        op,
        PhysicalOp::Create { .. }
            | PhysicalOp::Merge { .. }
            | PhysicalOp::SetClause { .. }
            | PhysicalOp::Delete { .. }
            | PhysicalOp::Remove { .. }
            | PhysicalOp::Foreach { .. }
    )
}

/// Chooses the physical join for a logical [`Apply`](LogicalOp::Apply): hash join for an equi-join,
/// else nested-loop (`04 §7.1`).
///
/// **The rule (documented and rule-based, cost is Phase 2):**
///
/// - If the right branch is **correlated** — it reads the left row's bindings through an
///   [`Argument`](LogicalOp::Argument) leaf — only a [`NestedLoopJoin`](PhysicalOp::NestedLoopJoin)
///   can express the per-left-row evaluation (a hash join has no place to feed the correlation).
///   This is the common shape the logical planner emits for `OPTIONAL MATCH`, correlated `CALL`,
///   and comma-pattern components ([`crate::lower`]).
/// - Otherwise the two branches are **independent** and joined on the columns they **share by
///   name** (an equi-join on those keys). With at least one shared key, a
///   [`HashJoin`](PhysicalOp::HashJoin) on those keys is chosen; with **no** shared key (a cartesian
///   product) a [`NestedLoopJoin`](PhysicalOp::NestedLoopJoin) is the realisation.
///
/// **Soundness:** every branch computes the same row set regardless of strategy; hash vs nested-loop
/// is purely a performance decision.
pub fn choose_join(left: PhysicalOp, right: PhysicalOp, logical_right: &LogicalOp) -> PhysicalOp {
    if logical_op_is_correlated(logical_right) {
        return PhysicalOp::NestedLoopJoin {
            left: Box::new(left),
            right: Box::new(right),
        };
    }
    let left_cols = bound_var_names(&left);
    let right_cols = bound_var_names(&right);
    let join_keys: Vec<String> = left_cols
        .iter()
        .filter(|c| right_cols.contains(*c))
        .cloned()
        .collect();
    if join_keys.is_empty() {
        PhysicalOp::NestedLoopJoin {
            left: Box::new(left),
            right: Box::new(right),
        }
    } else {
        PhysicalOp::HashJoin {
            left: Box::new(left),
            right: Box::new(right),
            join_keys,
        }
    }
}

/// Whether a logical (sub)plan reads correlated bindings — i.e. it roots at, or contains on its
/// leftmost spine, an [`Argument`](LogicalOp::Argument) leaf. Such a branch must be nested-loop
/// joined (the [`Argument`](LogicalOp::Argument) is fed one left row at a time).
fn logical_op_is_correlated(op: &LogicalOp) -> bool {
    match op {
        LogicalOp::Argument { .. } => true,
        LogicalOp::Optional { input, .. }
        | LogicalOp::Filter { input, .. }
        | LogicalOp::Projection { input, .. }
        | LogicalOp::Aggregation { input, .. }
        | LogicalOp::Sort { input, .. }
        | LogicalOp::Skip { input, .. }
        | LogicalOp::Limit { input, .. }
        | LogicalOp::Unwind { input, .. }
        | LogicalOp::LoadCsv { input, .. }
        | LogicalOp::Expand { input, .. }
        // A var-length/shortest pattern bound to a path variable wraps its correlated traversal in
        // `NamedPath`/`ShortestPath`; both must be descended or a correlated `Apply` whose right branch
        // is `OPTIONAL MATCH p = (a)-[*]-(b)` (both endpoints pre-bound) would be mistaken for an
        // uncorrelated equi-join and planned as a `HashJoin`, dropping the driving row entirely (rmp #104).
        | LogicalOp::NamedPath { input, .. }
        | LogicalOp::ShortestPath { input, .. }
        | LogicalOp::Create { input, .. }
        | LogicalOp::Merge { input, .. }
        | LogicalOp::SetClause { input, .. }
        | LogicalOp::Delete { input, .. }
        | LogicalOp::Remove { input, .. } => logical_op_is_correlated(input),
        LogicalOp::ProcedureCall { input, .. } => {
            input.as_deref().is_some_and(logical_op_is_correlated)
        }
        // A binary operator is correlated if either side is (the correlation can sit in either).
        LogicalOp::Apply { left, right } | LogicalOp::Union { left, right, .. } => {
            logical_op_is_correlated(left) || logical_op_is_correlated(right)
        }
        _ => false,
    }
}

// =================================================================================================
// Cost-based optimiser (task #65): join reordering, build-side selection, seek-vs-scan
// =================================================================================================
//
// Entry point [`optimize`] takes the rule-based physical tree and rewrites it under the cost model
// (`crate::cost`). Every rewrite is bag-preserving (see the soundness arguments inline and in the
// module docs); the worst case is "no rewrite improved cost", in which the rule-based tree survives
// unchanged. The pass is a single bottom-up recursion: children are optimised first, then this node.

/// The maximum number of operands in a single join region the bottom-up DP will fully enumerate.
///
/// Exhaustive DP over join order is `O(3^n)` in the number of operands (the classic System-R subset
/// enumeration), and each subset visit here clones candidate sub-plans and re-estimates their cost,
/// so the real cost grows even faster than `3^n`. A hard cap is therefore the load-bearing defence
/// against a **plan-time CPU/memory DoS**: a query with very many comma-separated patterns (a long
/// cartesian region) would otherwise make *planning itself* blow up before execution begins.
///
/// Measured plan time for an `n`-operand cartesian region (in-memory statistics, release build) grows
/// ~3.6x per added operand: `~8 ms` at `n=6`, `~30 ms` at `n=7`, `~106 ms` at `n=8`, `~380 ms` at
/// `n=9`, `~1.3 s` at `n=10`. `8` is the knee where the DP is still comfortably bounded (≈ `10^2 ms`)
/// while sitting far above realistic query sizes — real Cypher rarely has more than a handful of
/// disconnected join components, so no normal query loses the optimal DP. (For comparison, PostgreSQL
/// switches from its exhaustive join DP to a heuristic search at `geqo_threshold = 12`; this cap is
/// deliberately more conservative because each visit here is heavier.)
///
/// Above the cap the region is re-planned by a **polynomial-time greedy** join order
/// ([`greedy_join_order`]) instead of the DP: still a correct, connectivity-respecting, bag-identical
/// plan — only optimality is traded — so planning stays bounded for pathological pattern counts while
/// large queries still get a far better-than-rule-based shape.
const MAX_JOIN_REGION_OPERANDS: usize = 8;

/// Rewrites the rule-based physical tree `op` into a cost-minimised, bag-equivalent tree, using
/// `catalog` for access-path alternatives and `stats` for the cost model.
///
/// The recursion optimises children first (so costs are measured over already-optimised inputs), then
/// applies, at this node: **(B)** cost-based access-path selection for a seek / scan-filter site, and
/// **(A)** join-region reordering + build-side selection when the node roots a reorderable join
/// region. Operators that are neither keep their rule-based form with optimised children.
fn optimize(op: PhysicalOp, catalog: &IndexCatalog, stats: &dyn Statistics) -> PhysicalOp {
    optimize_inner(op, catalog, stats, false)
}

/// The recursion behind [`optimize`]. `in_join_region` is `true` when an ancestor reorderable join
/// (with only reorderable joins on the spine between) will re-flatten and re-plan this node as part of
/// **its** region — in which case this node must NOT plan its own sub-region (the maximal region root
/// plans the whole region exactly once, avoiding `O(n)` redundant re-planning that turned a long
/// cartesian chain into an `O(n^4)` plan-time blow-up).
///
/// This is behaviour-preserving versus planning every sub-join bottom-up: a sub-region reorder is kept
/// only when it is strictly cheaper, and in that case the maximal-region DP/greedy — which enumerates a
/// superset of orders — finds an order at least as cheap, so it wins the `cheaper(..)` comparison
/// either way. When no sub-reorder helps, the deferred and the bottom-up baselines are the identical
/// rule-based shape.
fn optimize_inner(
    op: PhysicalOp,
    catalog: &IndexCatalog,
    stats: &dyn Statistics,
    in_join_region: bool,
) -> PhysicalOp {
    // Inside an ancestor's reorderable region: optimise the leaves (so the operands the root flattens
    // are themselves optimised) but defer this sub-region's own reordering to that root.
    if in_join_region && is_reorderable_join(&op) {
        return optimize_children(op, catalog, stats);
    }

    // First, optimise all children (bottom-up): the cost of a parent depends on its inputs' shapes.
    let op = optimize_children(op, catalog, stats);

    // (B) Access-path selection: a seek the rule-based planner chose may lose to a scan when the
    // predicate is non-selective; a scan+filter may win back a seek when selective. Handled at the
    // seek node and at the filter-over-scan node.
    let op = optimize_access_path(op, catalog, stats);

    // (C) Expand-direction reversal: a `Filter*`-over-`ExpandAll`-over-`label-scan` whose *far*
    // endpoint carries a seekable predicate can be re-anchored on that far endpoint — seek it (one
    // anchor) and walk the reverse incidence — which costs `seek + reverse-expand` against the
    // rule-based `scan + forward-expand`. Bag-preserving (same directed edge set, same columns).
    let op = optimize_expand_direction(op, catalog, stats);

    // (A) Join reordering: if this node roots a maximal reorderable join region, flatten and re-plan
    // it by DP (small regions) or greedy (large regions). (If it is not such a region root, this is a
    // no-op returning `op`.)
    optimize_join_region(op, stats)
}

/// Optimises every child subtree of `op` in place, leaving `op`'s own shape untouched.
///
/// A reorderable join's children inherit `in_join_region = true` (they continue the same region the
/// flattener will walk); every other operator resets it to `false` (its children are region leaves,
/// optimised in their own right). This mirrors [`flatten_join_region`], which descends only through
/// reorderable joins. The child enumeration itself lives once in [`map_children`].
fn optimize_children(op: PhysicalOp, catalog: &IndexCatalog, stats: &dyn Statistics) -> PhysicalOp {
    let child_in_region = is_reorderable_join(&op);
    map_children(op, &|child| {
        optimize_inner(child, catalog, stats, child_in_region)
    })
}

// -------------------------------------------------------------------------------------------------
// (B) Cost-based access-path selection (seek vs scan)
// -------------------------------------------------------------------------------------------------

/// Reconsiders the access path at `op` by costing the seek and the scan realisations and keeping the
/// cheaper. Two trigger shapes (the two forms the rule-based planner can emit from a
/// `Filter`-over-label-scan):
///
/// * a bare or residual-filtered **seek** — try reverting it to `(token/label scan) + filter`;
/// * a **`Filter` over a label/token scan** — try consuming a conjunct into a seek.
///
/// Either way the candidate realisations are *exactly the rows the predicate selects* (a seek returns
/// precisely the matching rows; the residual filter is preserved), so swapping between them is
/// bag-preserving. Non-trigger nodes are returned unchanged.
fn optimize_access_path(
    op: PhysicalOp,
    catalog: &IndexCatalog,
    stats: &dyn Statistics,
) -> PhysicalOp {
    // Case 1: a seek, optionally wrapped in a residual Filter -> consider reverting to scan + filter.
    if let Some(alt) = scan_alternative_for_seek(&op, catalog) {
        return cheaper(op, alt, stats);
    }
    // Case 2: a Filter directly over a label/token scan -> consider consuming a conjunct into a seek.
    if let Some(alt) = seek_alternative_for_filter(&op, catalog) {
        return cheaper(op, alt, stats);
    }
    op
}

/// Returns the equivalent `scan + filter` realisation of a seek (possibly under a residual `Filter`),
/// or `None` when `op` is not a seek site. The reconstructed predicate is the equality/range the seek
/// consumed, AND-ed under any residual filter that already sat above it.
fn scan_alternative_for_seek(op: &PhysicalOp, catalog: &IndexCatalog) -> Option<PhysicalOp> {
    // Peel an optional residual Filter sitting directly over the seek.
    let (residual, seek) = match op {
        PhysicalOp::Filter { input, predicate } => (Some(predicate.clone()), input.as_ref()),
        other => (None, other),
    };

    // A **correlated** seek (its value references an outer variable, `rmp` task #708 — the right branch
    // of a nested-loop join, keyed per driving row) must NEVER be reverted to a scan. The range revert
    // rebuilds the consumed predicate as a `Filter` in the correlated branch, where the outer variable
    // is out of scope (that branch's row carries only the seek's own node), yielding a wrong result;
    // and the equality revert is pointless — the per-row seek is already the tight, correct access path
    // (it also keeps the narrow SSI footprint of `rmp` #325). Keep the seek.
    if contains_correlated_seek(seek) {
        return None;
    }

    // Equality seek: the scan alternative is the **precise** `NodeLabelScanEq` access path (`rmp` task
    // #325), NOT a bare `NodeByLabelScan`/`TokenLookupScan` + equality `Filter`. The precise op consumes
    // the equality conjunct (narrowing the SSI read footprint to the matching rows) while re-attaching
    // any residual; this keeps the tight footprint even when the cost model reverts a non-selective
    // *indexed* equality to a scan (otherwise the abort storm would return for that case).
    if let PhysicalOp::NodeIndexSeek {
        variable,
        label,
        property,
        value,
        ..
    } = seek
    {
        let scan_eq = PhysicalOp::NodeLabelScanEq {
            variable: variable.clone(),
            label: label.clone(),
            property: property.clone(),
            value: value.clone(),
        };
        return Some(match residual {
            Some(r) => PhysicalOp::Filter {
                input: Box::new(scan_eq),
                predicate: r,
            },
            None => scan_eq,
        });
    }

    // Range seek: reconstruct the consumed range predicate and re-apply it (plus any residual) as a
    // full `Filter` over the label/token scan — a range has no precise predicate marker to register.
    let (variable, label, consumed_predicate) = seek_to_predicate(seek)?;
    let full = match residual {
        Some(r) => and_exprs(consumed_predicate, r),
        None => consumed_predicate,
    };
    let scan = label_or_token_scan(&variable, &label, catalog);
    Some(PhysicalOp::Filter {
        input: Box::new(scan),
        predicate: full,
    })
}

/// If `op` is a `NodeIndexSeek` / `NodeIndexRangeSeek`, reconstructs `(variable, label, predicate)`
/// where `predicate` is the `var.prop <op> value` expression the seek consumed.
fn seek_to_predicate(op: &PhysicalOp) -> Option<(Var, Label, Expr)> {
    match op {
        PhysicalOp::NodeIndexSeek {
            variable,
            label,
            property,
            value,
            ..
        } => {
            let pred = property_comparison_expr(variable, property, BinaryOp::Eq, value);
            Some((variable.clone(), label.clone(), pred))
        }
        PhysicalOp::NodeIndexRangeSeek {
            variable,
            label,
            property,
            bound,
            value,
            ..
        } => {
            let pred = property_comparison_expr(variable, property, bound.to_binary_op(), value);
            Some((variable.clone(), label.clone(), pred))
        }
        _ => None,
    }
}

/// Builds the predicate expression `variable.property <op> value` (property always on the left, which
/// is how the seek stored it). Spans come from `value` so diagnostics stay anchored to real source.
fn property_comparison_expr(variable: &Var, property: &str, op: BinaryOp, value: &Expr) -> Expr {
    let span = value.span;
    let var_expr = Expr::new(ExprKind::Variable(variable.name.clone()), span);
    let prop_expr = Expr::new(
        ExprKind::Property {
            base: Box::new(var_expr),
            key: property.to_owned(),
        },
        span,
    );
    Expr::new(
        ExprKind::Binary {
            op,
            lhs: Box::new(prop_expr),
            rhs: Box::new(value.clone()),
        },
        span,
    )
}

/// AND-combines two predicates into one (`lhs AND rhs`), spanning both.
/// If `input` is a (possibly nested) chain of [`Filter`](LogicalOp::Filter)s bottoming out at a
/// [`NodeByLabelScan`](LogicalOp::NodeByLabelScan), returns that scan (cloned) plus the **conjunction**
/// of `top` and every predicate in the chain (top-down order), so [`Planner::lower_filter`] can do
/// index selection over all conjuncts at once (`rmp` task #657). Returns [`None`] when `input` is not
/// such a chain (e.g. a filter over an expand), so the caller keeps its normal residual-filter path.
///
/// Only invoked when `input` is itself a `Filter` (a nested chain), so the folded result always has at
/// least two predicates — exactly the multi-key inline-map / stacked-filter shape a composite seek
/// needs to see together.
fn fold_label_scan_filter_chain(input: &LogicalOp, top: &Expr) -> Option<(LogicalOp, Expr)> {
    let mut predicates: Vec<Expr> = vec![top.clone()];
    let mut cur = input;
    loop {
        match cur {
            LogicalOp::NodeByLabelScan { .. } => {
                let mut it = predicates.into_iter();
                let mut acc = it.next()?; // always Some: `top` is pushed first.
                for p in it {
                    acc = and_exprs(acc, p);
                }
                return Some((cur.clone(), acc));
            }
            LogicalOp::Filter {
                input: inner,
                predicate,
            } => {
                predicates.push(predicate.clone());
                cur = inner;
            }
            _ => return None,
        }
    }
}

fn and_exprs(lhs: Expr, rhs: Expr) -> Expr {
    let span = crate::lexer::Span::new(lhs.span.start, rhs.span.end);
    Expr::new(
        ExprKind::Binary {
            op: BinaryOp::And,
            lhs: Box::new(lhs),
            rhs: Box::new(rhs),
        },
        span,
    )
}

/// If `input` is a (possibly nested) chain of [`Filter`](LogicalOp::Filter)s bottoming out at an
/// [`Apply`](LogicalOp::Apply), returns that apply's `(left, right)` branches plus the **conjunction**
/// of `top` and every predicate in the chain (top-down order), so [`Planner::lower_filter`] can drive
/// the correlated index seek over all conjuncts at once (`rmp` tasks #708 / #729). Returns [`None`]
/// when `input` is not such a chain (e.g. a filter over a label scan or expand), so the caller keeps
/// its normal residual-filter path.
///
/// A single `Filter` directly over the `Apply` (the `WHERE a AND b` / single-key inline-map shape)
/// yields exactly `top`; a stacked chain (the multi-key inline-map shape, one `Filter` per key) folds
/// every level together — exactly what a full composite key needs to be recognised as one tuple.
fn fold_apply_filter_chain<'a>(
    input: &'a LogicalOp,
    top: &Expr,
) -> Option<(&'a LogicalOp, &'a LogicalOp, Expr)> {
    let mut predicates: Vec<Expr> = vec![top.clone()];
    let mut cur = input;
    loop {
        match cur {
            LogicalOp::Apply { left, right } => {
                let mut it = predicates.into_iter();
                let mut acc = it.next()?; // always Some: `top` is pushed first.
                for p in it {
                    acc = and_exprs(acc, p);
                }
                return Some((left.as_ref(), right.as_ref(), acc));
            }
            LogicalOp::Filter {
                input: inner,
                predicate,
            } => {
                predicates.push(predicate.clone());
                cur = inner;
            }
            _ => return None,
        }
    }
}

/// If `input` is a (possibly nested) chain of [`Filter`](LogicalOp::Filter)s bottoming out at an
/// [`Expand`](LogicalOp::Expand), returns that expand plus **every** conjunct in the chain — `top`'s
/// and each chained filter's, each split on top-level `AND` (outer-to-inner order). This lets
/// [`Planner::try_rel_index_seek`] pick the relationship-equality conjunct out of a stacked
/// inline-property / `WHERE` filter (`rmp` task #659). Returns [`None`] when `input` is not such a
/// chain (the relationship-seek attempt then declines and the normal residual-filter path runs).
fn fold_expand_filter_chain<'a>(
    input: &'a LogicalOp,
    top: &'a Expr,
) -> Option<(&'a LogicalOp, Vec<&'a Expr>)> {
    let mut conjuncts: Vec<&Expr> = split_conjuncts(top);
    let mut cur = input;
    loop {
        match cur {
            LogicalOp::Expand { .. } => return Some((cur, conjuncts)),
            LogicalOp::Filter {
                input: inner,
                predicate,
            } => {
                conjuncts.extend(split_conjuncts(predicate));
                cur = inner;
            }
            _ => return None,
        }
    }
}

/// AND-combines a slice of conjunct references into one owned predicate (left-to-right), or [`None`]
/// when the slice is empty. Used by [`Planner::try_correlated_seek_through_expand`] (`rmp` task #730) to
/// rebuild the pushed-down and the residual predicates from their partitioned conjuncts.
fn conjunction_of(conjuncts: &[&Expr]) -> Option<Expr> {
    let mut it = conjuncts.iter().copied();
    let mut acc = it.next()?.clone();
    for c in it {
        acc = and_exprs(acc, c.clone());
    }
    Some(acc)
}

/// Rebuilds an [`Expand`](LogicalOp::Expand) chain, wrapping the [`Apply`](LogicalOp::Apply) it bottoms
/// out at in `Filter(pushed, Apply)` (`rmp` task #730). The chain is cloned link-by-link with the pushed
/// filter spliced directly over the `Apply`, so re-lowering the result drives the anchor seek beneath
/// the traversal. Returns [`None`] if `input` is not an `Expand`(s)-over-`Apply` chain (the caller then
/// declines) — the same structure [`Planner::try_correlated_seek_through_expand`] validated before
/// calling, so `None` here is a defensive belt, never expected.
fn push_filter_below_expands(input: &LogicalOp, pushed: Expr) -> Option<LogicalOp> {
    match input {
        LogicalOp::Apply { .. } => Some(LogicalOp::Filter {
            input: Box::new(input.clone()),
            predicate: pushed,
        }),
        LogicalOp::Expand {
            input: inner,
            from,
            relationship,
            to,
            direction,
            types,
            range,
            prior_rels,
            rel_props,
        } => Some(LogicalOp::Expand {
            input: Box::new(push_filter_below_expands(inner, pushed)?),
            from: from.clone(),
            relationship: relationship.clone(),
            to: to.clone(),
            direction: *direction,
            types: types.clone(),
            range: *range,
            prior_rels: prior_rels.clone(),
            rel_props: rel_props.clone(),
        }),
        _ => None,
    }
}

/// The label/token scan for a `(variable, label)` — a `TokenLookupScan` when the catalog has a
/// token-lookup index, else a `NodeByLabelScan` (mirrors [`Planner::lower_label_scan`]).
fn label_or_token_scan(variable: &Var, label: &Label, catalog: &IndexCatalog) -> PhysicalOp {
    if let Some(idx) = catalog.token_lookup(label) {
        PhysicalOp::TokenLookupScan {
            variable: variable.clone(),
            label: label.clone(),
            index: idx.id,
        }
    } else {
        PhysicalOp::NodeByLabelScan {
            variable: variable.clone(),
            label: label.clone(),
        }
    }
}

/// If `op` is a `Filter` over a label/token scan whose predicate can drive an index seek, returns the
/// equivalent `seek + residual filter` realisation; else `None`. This is the same construction the
/// rule-based [`Planner::lower_filter`] performs, lifted so the optimiser can re-derive a seek the
/// rule-based tree did not already pick (e.g. after a scan was reconstructed elsewhere).
fn seek_alternative_for_filter(op: &PhysicalOp, catalog: &IndexCatalog) -> Option<PhysicalOp> {
    let PhysicalOp::Filter { input, predicate } = op else {
        return None;
    };
    let (variable, label) = match input.as_ref() {
        PhysicalOp::NodeByLabelScan { variable, label } => (variable, label),
        PhysicalOp::TokenLookupScan {
            variable, label, ..
        } => (variable, label),
        _ => return None,
    };
    let conjuncts = split_conjuncts(predicate);
    for (i, conj) in conjuncts.iter().enumerate() {
        if let Some(pp) = analyze_property_predicate(conj, &variable.name) {
            if let Some(idx) = catalog.label_property(label, &pp.property) {
                let seek = build_seek(variable, label, &pp, idx.id);
                let residual: Vec<&Expr> = conjuncts
                    .iter()
                    .enumerate()
                    .filter(|(j, _)| *j != i)
                    .map(|(_, e)| *e)
                    .collect();
                return Some(attach_residual(seek, &residual));
            }
        }
    }
    None
}

// -------------------------------------------------------------------------------------------------
// (C) Cost-based expand-direction reversal (re-anchor a single hop on its seekable far endpoint)
// -------------------------------------------------------------------------------------------------

/// Reconsiders the **traversal anchor** of a single binary hop. The rule-based planner fixes the
/// anchor at the clause-order `from` endpoint, so `MATCH (a:Person)-[:KNOWS]->(b) WHERE b.id = $x`
/// scans **all** `:Person` and fans forward, even though seeking `b` (one anchor) and walking the
/// **reverse** incidence enumerates the very same edge set far more cheaply.
///
/// When `op` is a `Filter*`-over-`ExpandAll`-over-`label-scan` whose **far** endpoint (`to`) carries
/// an index-servable predicate, this builds the reversed realisation — `seek(to) → ExpandAll(to →
/// from, reversed direction)` with `from`'s label and every other conjunct re-applied as a residual
/// `Filter` above — and keeps it iff the [cost model](crate::cost) says it is cheaper.
///
/// **Soundness.** The pattern's relationship *direction* (`-[:KNOWS]->`) is preserved exactly: only
/// the anchor and the incidence walked change. A directed edge `a→b` is enumerated either as `b`'s
/// `Outgoing` incidence from anchor `a` (`LeftToRight`) or, identically, as `a`'s `Incoming`
/// incidence from anchor `b` (`RightToLeft`) — the *same* `RelId` reaching the *same* neighbour
/// (see [`crate::graph_access::GraphAccess::expand`] and the `bound_rel_expand` direction match in
/// the executor). This is the same relationship-set equality that makes
/// [`ExpandInto`](PhysicalOp::ExpandInto) sound (module-doc rule 2). The reversal binds the identical
/// `{from, relationship, to}` columns to the identical entities, so the result bag — and any
/// downstream `ORDER BY` over it — is byte-identical.
fn optimize_expand_direction(
    op: PhysicalOp,
    catalog: &IndexCatalog,
    stats: &dyn Statistics,
) -> PhysicalOp {
    match reverse_expand_alternative(&op, catalog) {
        Some(alt) => cheaper(op, alt, stats),
        None => op,
    }
}

/// Builds the seek-anchored, reverse-direction realisation of a `Filter*`-over-`ExpandAll`-over-
/// pure-label-scan subtree whose far endpoint is index-servable; `None` when `op` is not such a site.
fn reverse_expand_alternative(op: &PhysicalOp, catalog: &IndexCatalog) -> Option<PhysicalOp> {
    // Peel the stacked residual `Filter`s sitting directly over the expand, gathering their
    // conjuncts in plan order. The expand must be the immediate input below the stack.
    let mut conjuncts: Vec<Expr> = Vec::new();
    let mut cursor = op;
    while let PhysicalOp::Filter { input, predicate } = cursor {
        for c in split_conjuncts(predicate) {
            conjuncts.push(c.clone());
        }
        cursor = input.as_ref();
    }
    // We must have peeled at least one filter (otherwise there is no far-endpoint predicate to
    // anchor on, and nothing to reverse).
    if conjuncts.is_empty() {
        return None;
    }

    // The node below the filter stack must be a **fresh, fixed-length, single** ExpandAll: a
    // var-length range, a reused/bound relationship, prior-rel isomorphism set, or an inline
    // rel-property map all change what "anchor at the other end" means, so we decline them.
    let PhysicalOp::ExpandAll {
        input,
        from,
        relationship,
        to,
        direction,
        types,
        range,
        prior_rels,
        rel_props,
    } = cursor
    else {
        return None;
    };
    if range.is_some() || !prior_rels.is_empty() || rel_props.is_some() {
        return None;
    }

    // The expand's input must be a **pure label/all scan** binding *only* `from` (the original
    // anchor). A pure scan consumes no property predicate, so re-deriving `from`'s membership as a
    // residual label filter after reversal is exact. (A seek/`ExpandInto`/multi-hop input is not a
    // re-anchoring candidate and is declined.)
    let from_label: Option<Label> = match input.as_ref() {
        PhysicalOp::NodeByLabelScan { variable, label } if variable.name == from.name => {
            Some(label.clone())
        }
        PhysicalOp::TokenLookupScan {
            variable, label, ..
        } if variable.name == from.name => Some(label.clone()),
        PhysicalOp::AllNodesScan { variable } if variable.name == from.name => None,
        _ => return None,
    };

    // Find `to`'s label among the peeled conjuncts (a `HasLabels` predicate on `to`) — the far
    // endpoint needs a label to drive a `label_property` index seek.
    let to_label = conjuncts
        .iter()
        .find_map(|c| has_single_label(c, &to.name))?;

    // Find a conjunct on `to` that an index can serve, and reconstruct the seek over `to`.
    let idx = conjuncts.iter().position(|c| {
        analyze_property_predicate(c, &to.name)
            .and_then(|pp| catalog.label_property(&to_label, &pp.property))
            .is_some()
    })?;
    let pp = analyze_property_predicate(&conjuncts[idx], &to.name)?;
    let index = catalog.label_property(&to_label, &pp.property)?;
    let seek = build_seek(to, &to_label, &pp, index.id);

    // The reversed expand: anchor on `to`, bind `from` as the far endpoint, flip the arrow so the
    // SAME directed edge set is enumerated from the other side.
    let reversed = PhysicalOp::ExpandAll {
        input: Box::new(seek),
        from: to.clone(),
        relationship: relationship.clone(),
        to: from.clone(),
        direction: reverse_direction(*direction),
        types: types.clone(),
        range: None,
        prior_rels: Vec::new(),
        rel_props: None,
    };

    // Re-apply, as a single residual `Filter` above the reversed expand: every conjunct *except* the
    // one consumed by the seek, plus `from`'s label (which the rule-based plan had consumed into the
    // now-replaced anchor scan). This preserves exactly the rows the original tree selected.
    let mut residual: Vec<Expr> = conjuncts
        .iter()
        .enumerate()
        .filter(|(j, _)| *j != idx)
        .map(|(_, e)| e.clone())
        .collect();
    if let Some(label) = from_label {
        residual.push(has_labels_expr(from, &label));
    }
    let residual_refs: Vec<&Expr> = residual.iter().collect();
    Some(attach_residual(reversed, &residual_refs))
}

/// If `expr` is exactly `variable:Label` (a single-label `HasLabels` predicate), returns that label.
/// Multi-label predicates are declined: the reversal re-applies `from`'s label as a single
/// `HasLabels`, and a multi-label seed has no single catalog `label_property` to anchor on.
fn has_single_label(expr: &Expr, variable: &str) -> Option<Label> {
    if let ExprKind::HasLabels {
        operand,
        expr: label_expr,
    } = &expr.kind
    {
        if let ExprKind::Variable(name) = &operand.kind {
            if name == variable {
                return label_expr.as_single_leaf();
            }
        }
    }
    None
}

/// Builds the `variable:Label` label predicate, mirroring the logical lowering of a label scan into a
/// residual `HasLabels` filter.
fn has_labels_expr(variable: &Var, label: &Label) -> Expr {
    let span = crate::lexer::Span::new(0, 0);
    Expr::new(
        ExprKind::HasLabels {
            operand: Box::new(Expr::new(ExprKind::Variable(variable.name.clone()), span)),
            expr: LabelExpr::Leaf {
                name: label.name.clone(),
                span: label.span,
            },
        },
        span,
    )
}

/// Reverses a relationship pattern's traversal arrow: `->` becomes `<-` and vice versa, so anchoring
/// on the opposite endpoint enumerates the **same** directed edge set. `Undirected` is symmetric and
/// unchanged.
fn reverse_direction(d: crate::ast::RelDirection) -> crate::ast::RelDirection {
    use crate::ast::RelDirection::{LeftToRight, RightToLeft, Undirected};
    match d {
        LeftToRight => RightToLeft,
        RightToLeft => LeftToRight,
        Undirected => Undirected,
    }
}

/// Returns whichever of `a` / `b` has the lower total [cost](crate::cost), breaking ties toward `a`
/// (the incoming rule-based shape) for determinism.
fn cheaper(a: PhysicalOp, b: PhysicalOp, stats: &dyn Statistics) -> PhysicalOp {
    let ca = estimate_cost(&a, Some(stats)).cost;
    let cb = estimate_cost(&b, Some(stats)).cost;
    // Strictly-less keeps `a` on a tie: the rule-based shape is the deterministic default.
    if cb < ca { b } else { a }
}

// -------------------------------------------------------------------------------------------------
// (D) Provided-order Sort elision (`rmp` task #665, part B)
// -------------------------------------------------------------------------------------------------

/// Applies the provided-order [`Sort`](PhysicalOp::Sort) elision ([`elide_sort_over_ordered_index`])
/// at **every** node of `op`, bottom-up (`rmp` task #665, part B).
///
/// Run as the **final** pass over the fully-planned tree — after the cost-based optimiser (when stats
/// are supplied) has settled every access path — so a `Sort` is only elided when the subtree beneath
/// it really did keep an ordered-capable index access. It is the single entry point for the rewrite, so
/// it fires identically on the rule-based (`plan_physical`, no stats) and cost-based paths. It is
/// order- and bag-preserving: it only removes a redundant sort (delegating the order to the index
/// access) or leaves the tree untouched, never reorders or drops rows.
fn elide_provided_order_sorts(op: PhysicalOp) -> PhysicalOp {
    // Rewrite children first (a nested `Sort` — e.g. in a `WITH … ORDER BY`, a `UNION` branch or a
    // `CALL {}` subquery — is elided in its own right), then attempt elision at this node.
    let op = map_children(op, &|child| elide_provided_order_sorts(child));
    elide_sort_over_ordered_index(op)
}

/// Rebuilds `op` with `f` applied to each of its immediate child subplans, leaving `op`'s own shape
/// otherwise untouched. **The single place the plan recursion lists each operator's children** — every
/// variant appears exactly once, so a new operator variant is a compile error until classified here.
/// Shared by [`optimize_children`] (the cost-based pass) and [`elide_provided_order_sorts`] (the
/// provided-order pass), so the two walkers can never drift out of sync.
fn map_children(op: PhysicalOp, f: &dyn Fn(PhysicalOp) -> PhysicalOp) -> PhysicalOp {
    let go = |b: Box<PhysicalOp>| Box::new(f(*b));
    match op {
        // Leaves: no children.
        PhysicalOp::AllNodesScan { .. }
        | PhysicalOp::NodeByLabelScan { .. }
        | PhysicalOp::TokenLookupScan { .. }
        | PhysicalOp::NodeIndexSeek { .. }
        | PhysicalOp::NodeCompositeIndexSeek { .. }
        | PhysicalOp::NodeLabelScanEq { .. }
        | PhysicalOp::NodeIndexRangeSeek { .. }
        | PhysicalOp::NodeIndexScan { .. }
        | PhysicalOp::NodeIndexStartsWithSeek { .. }
        | PhysicalOp::SpatialIndexSeek { .. }
        | PhysicalOp::NodeTextIndexSeek { .. }
        | PhysicalOp::AllRelationshipsScan { .. }
        | PhysicalOp::RelIndexSeek { .. }
        | PhysicalOp::RelIndexRangeSeek { .. }
        | PhysicalOp::RelCompositeIndexSeek { .. }
        | PhysicalOp::RelSpatialIndexSeek { .. }
        | PhysicalOp::Argument { .. }
        | PhysicalOp::Empty => op,

        // Single-input operators.
        PhysicalOp::ExpandAll {
            input,
            from,
            relationship,
            to,
            direction,
            types,
            range,
            prior_rels,
            rel_props,
        } => PhysicalOp::ExpandAll {
            input: go(input),
            from,
            relationship,
            to,
            direction,
            types,
            range,
            prior_rels,
            rel_props,
        },
        PhysicalOp::ExpandInto {
            input,
            from,
            relationship,
            to,
            direction,
            types,
            range,
            prior_rels,
            rel_props,
        } => PhysicalOp::ExpandInto {
            input: go(input),
            from,
            relationship,
            to,
            direction,
            types,
            range,
            prior_rels,
            rel_props,
        },
        PhysicalOp::ShortestPath {
            input,
            from,
            to,
            relationship,
            path,
            direction,
            types,
            range,
            all,
        } => PhysicalOp::ShortestPath {
            input: go(input),
            from,
            to,
            relationship,
            path,
            direction,
            types,
            range,
            all,
        },
        PhysicalOp::QuantifiedPath {
            input,
            from,
            to,
            group_start,
            group_end,
            relationship,
            direction,
            types,
            extra_hops,
            min,
            max,
            prior_rels,
            interior_predicate,
            into,
        } => PhysicalOp::QuantifiedPath {
            input: go(input),
            from,
            to,
            group_start,
            group_end,
            relationship,
            direction,
            types,
            extra_hops,
            min,
            max,
            prior_rels,
            interior_predicate,
            into,
        },
        PhysicalOp::NamedPath {
            input,
            variable,
            start,
            steps,
        } => PhysicalOp::NamedPath {
            input: go(input),
            variable,
            start,
            steps,
        },
        PhysicalOp::Filter { input, predicate } => PhysicalOp::Filter {
            input: go(input),
            predicate,
        },
        PhysicalOp::Projection {
            input,
            items,
            distinct,
        } => PhysicalOp::Projection {
            input: go(input),
            items,
            distinct,
        },
        PhysicalOp::Aggregation {
            input,
            group_keys,
            aggregates,
        } => PhysicalOp::Aggregation {
            input: go(input),
            group_keys,
            aggregates,
        },
        PhysicalOp::Sort { input, keys } => PhysicalOp::Sort {
            input: go(input),
            keys,
        },
        PhysicalOp::TopN { input, keys, limit } => PhysicalOp::TopN {
            input: go(input),
            keys,
            limit,
        },
        PhysicalOp::Skip { input, count } => PhysicalOp::Skip {
            input: go(input),
            count,
        },
        PhysicalOp::Limit { input, count } => PhysicalOp::Limit {
            input: go(input),
            count,
        },
        PhysicalOp::Eager { input } => PhysicalOp::Eager { input: go(input) },
        PhysicalOp::Unwind {
            input,
            list,
            variable,
        } => PhysicalOp::Unwind {
            input: go(input),
            list,
            variable,
        },
        PhysicalOp::LoadCsv {
            input,
            with_headers,
            url,
            variable,
            field_terminator,
        } => PhysicalOp::LoadCsv {
            input: go(input),
            with_headers,
            url,
            variable,
            field_terminator,
        },
        PhysicalOp::Optional {
            input,
            null_variables,
        } => PhysicalOp::Optional {
            input: go(input),
            null_variables,
        },

        // Two-input operators.
        PhysicalOp::NestedLoopJoin { left, right } => PhysicalOp::NestedLoopJoin {
            left: go(left),
            right: go(right),
        },
        PhysicalOp::HashJoin {
            left,
            right,
            join_keys,
        } => PhysicalOp::HashJoin {
            left: go(left),
            right: go(right),
            join_keys,
        },
        PhysicalOp::Union { left, right, all } => PhysicalOp::Union {
            left: go(left),
            right: go(right),
            all,
        },

        // Write operators.
        PhysicalOp::Create { input, pattern } => PhysicalOp::Create {
            input: go(input),
            pattern,
        },
        PhysicalOp::Merge {
            input,
            pattern,
            on_create,
            on_match,
        } => PhysicalOp::Merge {
            input: go(input),
            pattern,
            on_create,
            on_match,
        },
        PhysicalOp::SetClause { input, ops } => PhysicalOp::SetClause {
            input: go(input),
            ops,
        },
        PhysicalOp::Delete {
            input,
            detach,
            exprs,
        } => PhysicalOp::Delete {
            input: go(input),
            detach,
            exprs,
        },
        PhysicalOp::Remove { input, ops } => PhysicalOp::Remove {
            input: go(input),
            ops,
        },
        PhysicalOp::Foreach {
            input,
            variable,
            body,
            list,
        } => PhysicalOp::Foreach {
            input: go(input),
            variable,
            body: go(body),
            list,
        },
        PhysicalOp::ProcedureCall {
            input,
            name,
            args,
            yields,
        } => PhysicalOp::ProcedureCall {
            input: input.map(go),
            name,
            args,
            yields,
        },
    }
}

/// Elides a redundant `Sort` when the plan beneath it already provides exactly the requested order.
///
/// Fires only for a **single ascending key** `v.p` (`ORDER BY v.p`) whose input is an ordered-capable
/// index access on `(v, p)` — a [`NodeIndexScan`](PhysicalOp::NodeIndexScan) /
/// [`NodeIndexRangeSeek`](PhysicalOp::NodeIndexRangeSeek) / [`NodeIndexSeek`](PhysicalOp::NodeIndexSeek)
/// — reached through a chain of strictly **order-preserving** passthroughs (a non-`DISTINCT`
/// [`Projection`](PhysicalOp::Projection) that carries `v` unchanged, and/or a
/// [`Filter`](PhysicalOp::Filter)). It marks that access `ordered` (so the executor emits its rows in
/// ascending Cypher `p` order, ties by node id — see [`order_ids_by_property`](crate::executor)) and
/// returns the input **without** the `Sort`.
///
/// # Soundness
///
/// An `ordered` index access materialises its result **sorted by `(cmp_values(p) ASC, node id ASC)`**,
/// which is a valid total order for `ORDER BY p ASC` (ORDER BY leaves ties unspecified, so the node-id
/// tie-break is a conforming choice). Every op we descend through preserves both row order and each
/// surviving row's `v`/`v.p`, so the ordered access's order reaches the elided `Sort`'s position
/// unchanged. It is additionally **byte-identical** to the retained `Sort` whenever the access's
/// pre-`Sort` emission order was node-id ascending (the indexed path's `out.sort_unstable()`), because
/// a *stable* sort by `p` of a node-id-ordered sequence equals `(p, node id)` order.
///
/// Deliberately **not** elided (each keeps its `Sort`): a `DESC` key (would need a reverse scan —
/// tracked as a follow-up), a multi-key or non-`v.p` `ORDER BY`, a renamed sort variable, a `DISTINCT`
/// projection or an [`Aggregation`](PhysicalOp::Aggregation) between (row-collapsing, not
/// order-preserving), and a subtree whose access path is a plain scan (no index to provide order).
fn elide_sort_over_ordered_index(op: PhysicalOp) -> PhysicalOp {
    let PhysicalOp::Sort { input, keys } = op else {
        return op;
    };
    // Single ascending key only; anything else keeps the Sort.
    let [key] = keys.as_slice() else {
        return PhysicalOp::Sort { input, keys };
    };
    if key.direction != SortDirection::Ascending {
        return PhysicalOp::Sort { input, keys };
    }
    let Some((sort_var, sort_prop)) = property_ref(&key.expr) else {
        return PhysicalOp::Sort { input, keys };
    };
    let (result, provided) = mark_ordered_index(*input, sort_var, sort_prop);
    if provided {
        // Provided in order: drop the Sort, keeping the (now-ordered) input.
        result
    } else {
        // Not provided: restore the Sort untouched (the subtree is rebuilt but behaviourally identical).
        PhysicalOp::Sort {
            input: Box::new(result),
            keys,
        }
    }
}

/// If `expr` is exactly `variable.property`, returns `(variable, property)`; else `None`. The
/// order-provided key must be a bare property access (a compound `ORDER BY v.p + 1` is not served by
/// a `(v, p)` index).
fn property_ref(expr: &Expr) -> Option<(&str, &str)> {
    let ExprKind::Property { base, key } = &expr.kind else {
        return None;
    };
    let ExprKind::Variable(var) = &base.kind else {
        return None;
    };
    Some((var.as_str(), key.as_str()))
}

/// Descends `op` through order-preserving passthroughs to an ordered-capable index access on
/// `(var, prop)`, returning `(op_with_access_marked_ordered, true)` when found, or `(op, false)`
/// (the subtree rebuilt but behaviourally unchanged) otherwise. Returned as a `(op, bool)` pair
/// rather than `Result<PhysicalOp, PhysicalOp>` because both outcomes carry a `PhysicalOp` (the two
/// arms are "transformed" vs "unchanged", not "ok" vs "error") and the large-by-value op would trip
/// `clippy::result_large_err`. See [`elide_sort_over_ordered_index`] for the soundness contract.
fn mark_ordered_index(op: PhysicalOp, var: &str, prop: &str) -> (PhysicalOp, bool) {
    match op {
        // The ordered-capable index accesses on a single property: mark them ordered when they key on
        // exactly `(var, prop)`.
        PhysicalOp::NodeIndexScan {
            variable,
            label,
            property,
            ordered: _,
            index,
        } if variable.name == var && property == prop => (
            PhysicalOp::NodeIndexScan {
                variable,
                label,
                property,
                ordered: true,
                index,
            },
            true,
        ),
        PhysicalOp::NodeIndexRangeSeek {
            variable,
            label,
            property,
            bound,
            value,
            ordered: _,
            index,
        } if variable.name == var && property == prop => (
            PhysicalOp::NodeIndexRangeSeek {
                variable,
                label,
                property,
                bound,
                value,
                ordered: true,
                index,
            },
            true,
        ),
        PhysicalOp::NodeIndexSeek {
            variable,
            label,
            property,
            value,
            ordered: _,
            index,
        } if variable.name == var && property == prop => (
            PhysicalOp::NodeIndexSeek {
                variable,
                label,
                property,
                value,
                ordered: true,
                index,
            },
            true,
        ),
        // A `Filter` preserves row order (it only drops rows), so descend and re-wrap.
        PhysicalOp::Filter { input, predicate } => {
            let (inner, provided) = mark_ordered_index(*input, var, prop);
            (
                PhysicalOp::Filter {
                    input: Box::new(inner),
                    predicate,
                },
                provided,
            )
        }
        // A non-`DISTINCT` projection is 1:1 and order-preserving. Descend only when it carries the sort
        // variable through **unchanged** (`var AS var`); a rename or a rebinding of `var` to a different
        // expression would mean the `Sort`'s `var.prop` is not the index's ordering key, so decline.
        PhysicalOp::Projection {
            input,
            items,
            distinct: false,
        } if projects_var_through(&items, var) => {
            let (inner, provided) = mark_ordered_index(*input, var, prop);
            (
                PhysicalOp::Projection {
                    input: Box::new(inner),
                    items,
                    distinct: false,
                },
                provided,
            )
        }
        // Any other operator is not a known order-preserving passthrough: decline (keep the Sort).
        other => (other, false),
    }
}

/// Whether `items` re-emits `var` **unchanged** — a column `var AS var` whose source expression is the
/// bare variable `var`. Only then does the `Sort`'s `var.prop` above the projection denote the same
/// node the index access below it ordered by.
fn projects_var_through(items: &[ProjectionColumn], var: &str) -> bool {
    items
        .iter()
        .any(|c| c.alias == var && matches!(&c.expr.kind, ExprKind::Variable(name) if name == var))
}

// -------------------------------------------------------------------------------------------------
// (A) Join reordering + build-side selection (System-R-style bottom-up DP)
// -------------------------------------------------------------------------------------------------

/// If `op` roots a maximal **reorderable join region**, re-plans that region by bottom-up DP and
/// returns the cheaper of (re-planned, original); otherwise returns `op` unchanged.
///
/// A region is a connected tree of binary joins that are all *reorderable*: a [`HashJoin`](PhysicalOp::HashJoin),
/// or a **cartesian** [`NestedLoopJoin`](PhysicalOp::NestedLoopJoin) (no shared join keys), whose two
/// sides are independent — neither correlated (no [`Argument`](PhysicalOp::Argument) on the spine) nor
/// write-bearing. A correlated nested-loop join, or any join touching a write, is **not** reorderable
/// and bounds the region; its operands are optimised as opaque leaves (their subtrees were already
/// optimised bottom-up).
fn optimize_join_region(op: PhysicalOp, stats: &dyn Statistics) -> PhysicalOp {
    if !is_reorderable_join(&op) {
        return op;
    }

    // Flatten the maximal region into its leaf operands and the join graph over them.
    let mut operands: Vec<PhysicalOp> = Vec::new();
    flatten_join_region(op.clone(), &mut operands);

    // A region must have >= 2 operands to reorder.
    if operands.len() < 2 {
        return op;
    }

    // Bound planning cost (plan-time DoS defence). Up to the cap, the exhaustive System-R DP finds the
    // optimal order. Above it, the DP's super-exponential subset enumeration would dominate planning
    // time, so re-plan with a polynomial greedy heuristic instead — a correct, connectivity-respecting,
    // bag-identical order (see `MAX_JOIN_REGION_OPERANDS` and `greedy_join_order`).
    let replanned = if operands.len() <= MAX_JOIN_REGION_OPERANDS {
        dp_join_order(&operands, stats)
    } else {
        greedy_join_order(&operands, stats)
    };
    // Keep whichever is cheaper; tie -> the original rule-based region (determinism).
    cheaper(op, replanned, stats)
}

/// Whether `op` is a join the optimiser may reorder: a hash join, or a cartesian nested-loop join,
/// with both sides independent (non-correlated, write-free).
fn is_reorderable_join(op: &PhysicalOp) -> bool {
    match op {
        PhysicalOp::HashJoin { left, right, .. } => sides_reorderable(left, right),
        PhysicalOp::NestedLoopJoin { left, right } => {
            // A nested-loop join is reorderable only as a *cartesian* product (no shared keys); a
            // correlated apply (the executor feeds the right branch per left row) must never move.
            shared_keys(left, right).is_empty() && sides_reorderable(left, right)
        }
        _ => false,
    }
}

/// Whether both join sides are safe to reorder: independent of a correlation argument (an
/// [`Argument`](PhysicalOp::Argument) leaf **or** a correlated seek keyed off an outer row, `rmp` task
/// #708) and free of any write operator (a write's side effects must run in the planned order, never
/// be reordered).
fn sides_reorderable(left: &PhysicalOp, right: &PhysicalOp) -> bool {
    !contains_argument(left)
        && !contains_argument(right)
        && !contains_correlated_seek(left)
        && !contains_correlated_seek(right)
        && !contains_write(left)
        && !contains_write(right)
}

/// Whether a physical (sub)plan contains a **correlated index seek** — a node property seek whose
/// value expression references a variable, so its key is only known per driving row and is fed
/// through the enclosing nested-loop join's correlation (`rmp` task #708, the
/// `UNWIND rows AS t MATCH (b:L {p: t.k})` shape). Unlike an [`Argument`](PhysicalOp::Argument) leaf,
/// this correlation is carried in the seek's *value*, not a distinct leaf — so [`contains_argument`]
/// misses it. The cost-based reorderer must treat such a subplan as immovable (never hoist it to the
/// outer side of a join, where the correlated key would be unbound), exactly as it does an argument.
fn contains_correlated_seek(op: &PhysicalOp) -> bool {
    // Only the node property seeks that carry an unevaluated value expression can be correlated (the
    // planner keys them off a value that may reference an outer variable). Every other leaf has no
    // value expression to correlate on.
    let seek_value_correlated = match op {
        PhysicalOp::NodeIndexSeek { value, .. }
        | PhysicalOp::NodeIndexRangeSeek { value, .. }
        | PhysicalOp::NodeLabelScanEq { value, .. } => expr_contains_variable(value),
        PhysicalOp::NodeCompositeIndexSeek { values, .. } => {
            values.iter().any(expr_contains_variable)
        }
        PhysicalOp::NodeIndexStartsWithSeek { prefix, .. } => expr_contains_variable(prefix),
        _ => false,
    };
    if seek_value_correlated {
        return true;
    }
    match op {
        PhysicalOp::AllNodesScan { .. }
        | PhysicalOp::NodeByLabelScan { .. }
        | PhysicalOp::TokenLookupScan { .. }
        | PhysicalOp::NodeIndexSeek { .. }
        | PhysicalOp::NodeCompositeIndexSeek { .. }
        | PhysicalOp::NodeLabelScanEq { .. }
        | PhysicalOp::NodeIndexRangeSeek { .. }
        | PhysicalOp::NodeIndexScan { .. }
        | PhysicalOp::NodeIndexStartsWithSeek { .. }
        | PhysicalOp::SpatialIndexSeek { .. }
        | PhysicalOp::NodeTextIndexSeek { .. }
        | PhysicalOp::AllRelationshipsScan { .. }
        | PhysicalOp::RelIndexSeek { .. }
        | PhysicalOp::RelIndexRangeSeek { .. }
        | PhysicalOp::RelCompositeIndexSeek { .. }
        | PhysicalOp::RelSpatialIndexSeek { .. }
        | PhysicalOp::Argument { .. }
        | PhysicalOp::Empty => false,
        PhysicalOp::Filter { input, .. }
        | PhysicalOp::Projection { input, .. }
        | PhysicalOp::Aggregation { input, .. }
        | PhysicalOp::Sort { input, .. }
        | PhysicalOp::TopN { input, .. }
        | PhysicalOp::Skip { input, .. }
        | PhysicalOp::Limit { input, .. }
        | PhysicalOp::Eager { input }
        | PhysicalOp::Unwind { input, .. }
        | PhysicalOp::LoadCsv { input, .. }
        | PhysicalOp::ExpandAll { input, .. }
        | PhysicalOp::ExpandInto { input, .. }
        | PhysicalOp::ShortestPath { input, .. }
        | PhysicalOp::QuantifiedPath { input, .. }
        | PhysicalOp::NamedPath { input, .. }
        | PhysicalOp::Optional { input, .. }
        | PhysicalOp::Create { input, .. }
        | PhysicalOp::Merge { input, .. }
        | PhysicalOp::SetClause { input, .. }
        | PhysicalOp::Delete { input, .. }
        | PhysicalOp::Remove { input, .. }
        | PhysicalOp::Foreach { input, .. } => contains_correlated_seek(input),
        PhysicalOp::NestedLoopJoin { left, right }
        | PhysicalOp::HashJoin { left, right, .. }
        | PhysicalOp::Union { left, right, .. } => {
            contains_correlated_seek(left) || contains_correlated_seek(right)
        }
        PhysicalOp::ProcedureCall { input, .. } => {
            input.as_deref().is_some_and(contains_correlated_seek)
        }
    }
}

/// Whether a physical (sub)plan contains an [`Argument`](PhysicalOp::Argument) anywhere — the
/// physical marker of correlation (the subplan reads an outer row). The cost-based reorderer must
/// never move such a subplan, since its meaning depends on the correlated feed.
fn contains_argument(op: &PhysicalOp) -> bool {
    match op {
        PhysicalOp::Argument { .. } => true,
        PhysicalOp::AllNodesScan { .. }
        | PhysicalOp::NodeByLabelScan { .. }
        | PhysicalOp::TokenLookupScan { .. }
        | PhysicalOp::NodeIndexSeek { .. }
        | PhysicalOp::NodeCompositeIndexSeek { .. }
        | PhysicalOp::NodeLabelScanEq { .. }
        | PhysicalOp::NodeIndexRangeSeek { .. }
        | PhysicalOp::NodeIndexScan { .. }
        | PhysicalOp::NodeIndexStartsWithSeek { .. }
        | PhysicalOp::SpatialIndexSeek { .. }
        | PhysicalOp::NodeTextIndexSeek { .. }
        | PhysicalOp::AllRelationshipsScan { .. }
        | PhysicalOp::RelIndexSeek { .. }
        | PhysicalOp::RelIndexRangeSeek { .. }
        | PhysicalOp::RelCompositeIndexSeek { .. }
        | PhysicalOp::RelSpatialIndexSeek { .. }
        | PhysicalOp::Empty => false,
        PhysicalOp::Filter { input, .. }
        | PhysicalOp::Projection { input, .. }
        | PhysicalOp::Aggregation { input, .. }
        | PhysicalOp::Sort { input, .. }
        | PhysicalOp::TopN { input, .. }
        | PhysicalOp::Skip { input, .. }
        | PhysicalOp::Limit { input, .. }
        | PhysicalOp::Eager { input }
        | PhysicalOp::Unwind { input, .. }
        | PhysicalOp::LoadCsv { input, .. }
        | PhysicalOp::ExpandAll { input, .. }
        | PhysicalOp::ExpandInto { input, .. }
        | PhysicalOp::ShortestPath { input, .. }
        | PhysicalOp::QuantifiedPath { input, .. }
        | PhysicalOp::NamedPath { input, .. }
        | PhysicalOp::Optional { input, .. }
        | PhysicalOp::Create { input, .. }
        | PhysicalOp::Merge { input, .. }
        | PhysicalOp::SetClause { input, .. }
        | PhysicalOp::Delete { input, .. }
        | PhysicalOp::Remove { input, .. }
        // FOREACH's `body` is intentionally Argument-rooted, but that Argument is internal — it is
        // resolved by FOREACH itself, exactly like a NestedLoopJoin's right branch. So the whole
        // FOREACH op is correlated iff its `input` is; the body's Argument must not leak out.
        | PhysicalOp::Foreach { input, .. } => contains_argument(input),
        PhysicalOp::NestedLoopJoin { left, right }
        | PhysicalOp::HashJoin { left, right, .. }
        | PhysicalOp::Union { left, right, .. } => {
            contains_argument(left) || contains_argument(right)
        }
        PhysicalOp::ProcedureCall { input, .. } => input.as_deref().is_some_and(contains_argument),
    }
}

/// Flattens a maximal reorderable join region rooted at `op` into its leaf operands (depth-first,
/// left-before-right, preserving a stable operand order for determinism). The caller guarantees `op`
/// is a reorderable join ([`is_reorderable_join`]); each side is recursed into when it is itself a
/// reorderable join, else pushed as an opaque region leaf.
fn flatten_join_region(op: PhysicalOp, operands: &mut Vec<PhysicalOp>) {
    debug_assert!(
        is_reorderable_join(&op),
        "flatten_join_region requires a reorderable join root"
    );
    match op {
        PhysicalOp::HashJoin { left, right, .. } | PhysicalOp::NestedLoopJoin { left, right } => {
            flatten_side(*left, operands);
            flatten_side(*right, operands);
        }
        // The caller's guard makes this unreachable; treat any other shape as a single leaf.
        other => operands.push(other),
    }
}

/// Flattens one join side: recurse when it is itself a reorderable join, else push it as an operand.
fn flatten_side(side: PhysicalOp, operands: &mut Vec<PhysicalOp>) {
    if is_reorderable_join(&side) {
        flatten_join_region(side, operands);
    } else {
        operands.push(side);
    }
}

/// The set of bound-variable names shared between two subplans (their equi-join keys), sorted &
/// de-duplicated for determinism. Empty ⇒ only a cartesian edge connects them.
fn shared_keys(left: &PhysicalOp, right: &PhysicalOp) -> Vec<String> {
    let left_cols: BTreeSet<String> = bound_var_names(left).into_iter().collect();
    let right_cols: BTreeSet<String> = bound_var_names(right).into_iter().collect();
    left_cols.intersection(&right_cols).cloned().collect()
}

/// A DP sub-result: the best (min-cost) plan over a specific subset of operands, with its cost and
/// estimated output cardinality cached so a parent join can score it without re-walking the subtree.
#[derive(Clone)]
struct DpEntry {
    /// The chosen physical plan for this operand subset.
    plan: PhysicalOp,
    /// Its total cost under the cost model.
    cost: f64,
    /// Its estimated output cardinality (drives build-side selection at the next join up).
    rows: f64,
}

/// Bottom-up dynamic programming over join order (System-R): build the min-cost plan for every
/// reachable subset of `operands`, combining smaller subsets, and return the plan for the full set.
///
/// The DP table is keyed by a **sorted operand-index set** (a `BTreeSet<usize>` inside a `BTreeMap`),
/// so iteration and tie-breaking are deterministic. For each subset, every split into two non-empty,
/// disjoint, covering sub-subsets is considered; the join is a [`HashJoin`](PhysicalOp::HashJoin) on
/// the shared keys when the two sides share any bound variable, else a cartesian
/// [`NestedLoopJoin`](PhysicalOp::NestedLoopJoin). The lower-cardinality side becomes the hash join's
/// **build** (left) input. Only the cheapest plan per subset is kept (pruning).
///
/// **Determinism:** subsets are enumerated by ascending size then by their sorted index set; among
/// equal-cost candidates for a subset the first encountered in that stable order wins. **Soundness:**
/// inner equi-join and cartesian product are commutative and associative, so every subset's plan
/// computes the same multiset regardless of the split chosen.
fn dp_join_order(operands: &[PhysicalOp], stats: &dyn Statistics) -> PhysicalOp {
    let n = operands.len();

    // Precompute each operand's leaf cost/rows once.
    let mut table: BTreeMap<BTreeSet<usize>, DpEntry> = BTreeMap::new();
    for (i, operand) in operands.iter().enumerate() {
        let est = estimate_cost(operand, Some(stats));
        let key: BTreeSet<usize> = std::iter::once(i).collect();
        table.insert(
            key,
            DpEntry {
                plan: operand.clone(),
                cost: est.cost,
                rows: est.rows,
            },
        );
    }

    // Build up subsets by increasing size. For each target subset, try every (proper, non-empty)
    // split into two halves whose best plans are already in the table.
    for size in 2..=n {
        for subset in subsets_of_size(n, size) {
            let mut best: Option<DpEntry> = None;
            for (lhs, rhs) in proper_splits(&subset) {
                let (Some(le), Some(re)) = (table.get(&lhs), table.get(&rhs)) else {
                    continue;
                };
                let candidate = join_entries(le, re, stats);
                // Keep the strictly-cheaper candidate; the stable split order makes ties deterministic.
                if best.as_ref().is_none_or(|b| candidate.cost < b.cost) {
                    best = Some(candidate);
                }
            }
            if let Some(entry) = best {
                table.insert(subset, entry);
            }
        }
    }

    let full: BTreeSet<usize> = (0..n).collect();
    table
        .get(&full)
        .map(|e| e.plan.clone())
        // Defensive: the DP always fills the full set for a connected region; if it somehow did not,
        // fall back to a left-deep join of the operands in order (still bag-correct).
        .unwrap_or_else(|| left_deep_fallback(operands))
}

/// Joins two DP sub-plans into one, choosing the strategy and build side:
///
/// * shared keys ⇒ [`HashJoin`](PhysicalOp::HashJoin) on those keys, building the **lower-cardinality**
///   side (so `COST_HASH_BUILD · |build|` is minimised);
/// * no shared key ⇒ cartesian [`NestedLoopJoin`](PhysicalOp::NestedLoopJoin), the lower-cardinality
///   side on the **left** (driving) so the quadratic term is computed over the smaller outer loop
///   first — bag-identical either way, this is purely the cost-minimising orientation.
fn join_entries(a: &DpEntry, b: &DpEntry, stats: &dyn Statistics) -> DpEntry {
    let keys = shared_keys(&a.plan, &b.plan);
    // Orient: the smaller side is the build/driver. On an exact tie, keep `a` left for determinism.
    let (small, large) = if b.rows < a.rows { (b, a) } else { (a, b) };

    let plan = if keys.is_empty() {
        PhysicalOp::NestedLoopJoin {
            left: Box::new(small.plan.clone()),
            right: Box::new(large.plan.clone()),
        }
    } else {
        PhysicalOp::HashJoin {
            left: Box::new(small.plan.clone()),
            right: Box::new(large.plan.clone()),
            join_keys: keys,
        }
    };
    let est = estimate_cost(&plan, Some(stats));
    DpEntry {
        plan,
        cost: est.cost,
        rows: est.rows,
    }
}

/// A left-deep join of all operands in their given order (a defensive fallback; the DP normally
/// supplies the optimal shape). Bag-correct: any join order over the same operands is equivalent.
fn left_deep_fallback(operands: &[PhysicalOp]) -> PhysicalOp {
    let mut iter = operands.iter().cloned();
    let mut acc = iter.next().expect("a region has >= 1 operand");
    for next in iter {
        let keys = shared_keys(&acc, &next);
        acc = if keys.is_empty() {
            PhysicalOp::NestedLoopJoin {
                left: Box::new(acc),
                right: Box::new(next),
            }
        } else {
            PhysicalOp::HashJoin {
                left: Box::new(acc),
                right: Box::new(next),
                join_keys: keys,
            }
        };
    }
    acc
}

/// A polynomial-time **greedy** join order for regions too large for the exhaustive DP
/// ([`MAX_JOIN_REGION_OPERANDS`]) — the plan-time DoS fallback.
///
/// This is the classic *greedy operator ordering*: maintain a working set of sub-plans (initially the
/// region's leaf operands) and repeatedly merge the pair whose join is cheapest under the cost model,
/// until one plan remains. At each step a **connected** pair (the two sides share a bound variable, so
/// the join is an equi-[`HashJoin`](PhysicalOp::HashJoin)) is always preferred over a cartesian one,
/// so the greedy never introduces a cartesian product where a connected join exists. Only when the
/// working set is fully disconnected (every pair cartesian) does it join two operands with no shared
/// key — and then it picks the two of smallest cardinality, which both minimises the intermediate
/// product (Huffman-style) and is the cheapest [`NestedLoopJoin`](PhysicalOp::NestedLoopJoin)
/// orientation.
///
/// **Complexity:** `O(n^3)` merge evaluations in the worst (densely-connected) case and `O(n)` per
/// step in the common all-cartesian case — polynomial either way, so planning time is bounded no
/// matter how many patterns the query lists.
///
/// **Soundness:** identical to the DP — inner equi-join and cartesian product are commutative and
/// associative, so any binary join tree over the same operands computes the same multiset. Greedy only
/// trades optimality of the *shape*, never correctness of the *bag*.
///
/// **Determinism:** the working set is scanned in index order and ties are broken toward the
/// lower-index pair, so the same region + statistics always yields the same plan.
fn greedy_join_order(operands: &[PhysicalOp], stats: &dyn Statistics) -> PhysicalOp {
    // Each working entry carries its cached cost/rows (so a parent join scores it without re-walking)
    // and its bound-variable set (so connectivity is an O(set) check, never a subtree re-walk).
    let mut entries: Vec<DpEntry> = Vec::with_capacity(operands.len());
    let mut varsets: Vec<BTreeSet<String>> = Vec::with_capacity(operands.len());
    for op in operands {
        let est = estimate_cost(op, Some(stats));
        entries.push(DpEntry {
            plan: op.clone(),
            cost: est.cost,
            rows: est.rows,
        });
        varsets.push(bound_var_names(op).into_iter().collect());
    }

    // Fast path — a **fully disconnected** region (no bound variable appears in more than one operand):
    // every join is cartesian and *stays* cartesian under merging, so the connectivity pre-filter would
    // never fire. This is the shape produced by comma-separated patterns — exactly the plan-time DoS
    // vector — so it gets a dedicated `O(n^2)` order (repeatedly merge the two smallest cardinalities)
    // instead of the general path's `O(n^3)` pair scan.
    if is_fully_disconnected(&varsets) {
        return greedy_cartesian_order(entries, stats);
    }

    while entries.len() > 1 {
        // Find the cheapest *connected* pair (shared bound variable ⇒ equi-join). The `is_disjoint`
        // pre-filter agrees with `join_entries`' own `shared_keys` test (both derive from
        // `bound_var_names`), so a non-disjoint pair is exactly the one `join_entries` realises as a
        // `HashJoin`.
        let mut best: Option<(usize, usize, DpEntry)> = None;
        for i in 0..entries.len() {
            for j in (i + 1)..entries.len() {
                if varsets[i].is_disjoint(&varsets[j]) {
                    continue; // cartesian — skip while any connected pair is available
                }
                let cand = join_entries(&entries[i], &entries[j], stats);
                if best.as_ref().is_none_or(|(_, _, b)| cand.cost < b.cost) {
                    best = Some((i, j, cand));
                }
            }
        }

        // No connected pair: the working set is fully disconnected. Join the two smallest-cardinality
        // sub-plans (an O(n) choice, no O(n^2) scan), minimising the cartesian blow-up at this step.
        let (i, j, joined) = best.unwrap_or_else(|| {
            let (i, j) = two_smallest_by_rows(&entries);
            (i, j, join_entries(&entries[i], &entries[j], stats))
        });

        debug_assert!(
            i < j,
            "merge indices must be ordered so removal keeps `i` valid"
        );
        // Merge: remove the higher index first so the lower stays valid, then push the joined entry.
        let merged_vars: BTreeSet<String> = varsets[i].union(&varsets[j]).cloned().collect();
        entries.remove(j);
        entries.remove(i);
        varsets.remove(j);
        varsets.remove(i);
        entries.push(joined);
        varsets.push(merged_vars);
    }

    entries.pop().expect("a region has >= 1 operand").plan
}

/// Whether no bound variable appears in more than one operand — i.e. every pair of operands is
/// variable-disjoint, so every possible join is a cartesian product. `O(total variables)`.
fn is_fully_disconnected(varsets: &[BTreeSet<String>]) -> bool {
    let mut seen: std::collections::HashSet<&str> = std::collections::HashSet::new();
    for vs in varsets {
        for v in vs {
            if !seen.insert(v.as_str()) {
                return false; // a variable shared by two operands ⇒ a connected (equi-join) pair exists
            }
        }
    }
    true
}

/// Greedy join order for a fully-disconnected (all-cartesian) region: repeatedly merge the two
/// smallest-cardinality sub-plans until one remains. For cartesian products this Huffman-style choice
/// minimises the sum of intermediate sizes, and joining the two smallest is also the cheapest
/// [`NestedLoopJoin`](PhysicalOp::NestedLoopJoin) orientation. `O(n^2)` — each of `n-1` merges scans
/// the working set once for its two smallest, with no `O(n^2)` connectivity probe.
fn greedy_cartesian_order(mut entries: Vec<DpEntry>, stats: &dyn Statistics) -> PhysicalOp {
    while entries.len() > 1 {
        let (i, j) = two_smallest_by_rows(&entries);
        let joined = join_entries(&entries[i], &entries[j], stats);
        debug_assert!(i < j, "two_smallest_by_rows returns ordered indices");
        // Remove the higher index first so the lower stays valid, then push the merged entry.
        entries.remove(j);
        entries.remove(i);
        entries.push(joined);
    }
    entries.pop().expect("a region has >= 1 operand").plan
}

/// The indices of the two smallest-cardinality entries, returned ordered (`i < j`). Ties keep
/// ascending-index order for determinism. Single pass, `O(n)`. The caller guarantees
/// `entries.len() >= 2`.
fn two_smallest_by_rows(entries: &[DpEntry]) -> (usize, usize) {
    debug_assert!(entries.len() >= 2);
    // `min1` is the smallest so far, `min2` the second smallest; both by (rows, then index) order.
    let less = |a: usize, b: usize| -> bool {
        entries[a].rows < entries[b].rows || (entries[a].rows == entries[b].rows && a < b)
    };
    let (mut min1, mut min2) = if less(0, 1) { (0, 1) } else { (1, 0) };
    for k in 2..entries.len() {
        if less(k, min1) {
            min2 = min1;
            min1 = k;
        } else if less(k, min2) {
            min2 = k;
        }
    }
    if min1 < min2 {
        (min1, min2)
    } else {
        (min2, min1)
    }
}

/// Every subset of `{0..n}` of exactly `size` elements, in ascending lexicographic order of the sorted
/// index vector (deterministic enumeration). Returned as `BTreeSet`s so they key the DP table.
fn subsets_of_size(n: usize, size: usize) -> Vec<BTreeSet<usize>> {
    let mut out = Vec::new();
    let mut current = Vec::with_capacity(size);
    fn recurse(
        start: usize,
        n: usize,
        size: usize,
        current: &mut Vec<usize>,
        out: &mut Vec<BTreeSet<usize>>,
    ) {
        if current.len() == size {
            out.push(current.iter().copied().collect());
            return;
        }
        for i in start..n {
            current.push(i);
            recurse(i + 1, n, size, current, out);
            current.pop();
        }
    }
    recurse(0, n, size, &mut current, &mut out);
    out
}

/// Every split of `subset` into an ordered pair of non-empty, disjoint halves whose union is `subset`.
///
/// To avoid scoring each unordered partition twice (and to keep enumeration deterministic), only
/// splits whose left half contains the subset's smallest element are produced; the right half is the
/// complement. This yields each partition exactly once, with a stable order.
fn proper_splits(subset: &BTreeSet<usize>) -> Vec<(BTreeSet<usize>, BTreeSet<usize>)> {
    let elems: Vec<usize> = subset.iter().copied().collect();
    let k = elems.len();
    let mut out = Vec::new();
    if k < 2 {
        return out;
    }
    let anchor = elems[0]; // The smallest element pins the left half (each partition produced once).
    // Enumerate non-empty proper subsets of the remaining elements to join the anchor on the left.
    let rest = &elems[1..];
    let m = rest.len();
    // 2^m bitmask over `rest`; left = {anchor} ∪ chosen, right = the unchosen. Both non-empty since
    // left always has the anchor and we skip the mask that takes *all* of rest (which would empty
    // right).
    for mask in 0..(1u32 << m) {
        let mut left: BTreeSet<usize> = std::iter::once(anchor).collect();
        let mut right: BTreeSet<usize> = BTreeSet::new();
        for (bit, &e) in rest.iter().enumerate() {
            if mask & (1 << bit) != 0 {
                left.insert(e);
            } else {
                right.insert(e);
            }
        }
        if right.is_empty() {
            continue;
        }
        out.push((left, right));
    }
    out
}

// -------------------------------------------------------------------------------------------------
// Index-dependency recomputation (the final tree may differ from the rule-based one)
// -------------------------------------------------------------------------------------------------

/// Walks a physical plan and collects every catalog [`IndexId`] its access paths actually use,
/// ascending & de-duplicated. Recomputed from the **final** optimised tree so a plan that dropped a
/// seek in favour of a scan no longer records that index dependency (and vice versa).
fn collect_index_dependencies(op: &PhysicalOp) -> BTreeSet<IndexId> {
    let mut deps = BTreeSet::new();
    gather_index_dependencies(op, &mut deps);
    deps
}

fn gather_index_dependencies(op: &PhysicalOp, deps: &mut BTreeSet<IndexId>) {
    match op {
        PhysicalOp::TokenLookupScan { index, .. }
        | PhysicalOp::NodeIndexSeek { index, .. }
        | PhysicalOp::NodeCompositeIndexSeek { index, .. }
        | PhysicalOp::NodeIndexRangeSeek { index, .. }
        | PhysicalOp::NodeIndexScan { index, .. }
        | PhysicalOp::NodeIndexStartsWithSeek { index, .. }
        | PhysicalOp::SpatialIndexSeek { index, .. }
        | PhysicalOp::NodeTextIndexSeek { index, .. }
        | PhysicalOp::RelIndexSeek { index, .. }
        | PhysicalOp::RelIndexRangeSeek { index, .. }
        | PhysicalOp::RelCompositeIndexSeek { index, .. }
        | PhysicalOp::RelSpatialIndexSeek { index, .. } => {
            deps.insert(*index);
        }
        // `NodeLabelScanEq` is a full store scan (no derived index), so it declares no index dependency.
        PhysicalOp::AllNodesScan { .. }
        | PhysicalOp::NodeByLabelScan { .. }
        | PhysicalOp::NodeLabelScanEq { .. }
        | PhysicalOp::AllRelationshipsScan { .. }
        | PhysicalOp::Argument { .. }
        | PhysicalOp::Empty => {}
        PhysicalOp::Filter { input, .. }
        | PhysicalOp::Projection { input, .. }
        | PhysicalOp::Aggregation { input, .. }
        | PhysicalOp::Sort { input, .. }
        | PhysicalOp::TopN { input, .. }
        | PhysicalOp::Skip { input, .. }
        | PhysicalOp::Limit { input, .. }
        | PhysicalOp::Eager { input }
        | PhysicalOp::Unwind { input, .. }
        | PhysicalOp::LoadCsv { input, .. }
        | PhysicalOp::ExpandAll { input, .. }
        | PhysicalOp::ExpandInto { input, .. }
        | PhysicalOp::ShortestPath { input, .. }
        | PhysicalOp::QuantifiedPath { input, .. }
        | PhysicalOp::NamedPath { input, .. }
        | PhysicalOp::Optional { input, .. }
        | PhysicalOp::Create { input, .. }
        | PhysicalOp::Merge { input, .. }
        | PhysicalOp::SetClause { input, .. }
        | PhysicalOp::Delete { input, .. }
        | PhysicalOp::Remove { input, .. } => gather_index_dependencies(input, deps),
        // FOREACH's body sub-plan may itself touch indexed entities (its writes), so collect from
        // both the driving input and the body.
        PhysicalOp::Foreach { input, body, .. } => {
            gather_index_dependencies(input, deps);
            gather_index_dependencies(body, deps);
        }
        PhysicalOp::NestedLoopJoin { left, right }
        | PhysicalOp::HashJoin { left, right, .. }
        | PhysicalOp::Union { left, right, .. } => {
            gather_index_dependencies(left, deps);
            gather_index_dependencies(right, deps);
        }
        PhysicalOp::ProcedureCall { input, .. } => {
            if let Some(input) = input {
                gather_index_dependencies(input, deps);
            }
        }
    }
}

// =================================================================================================
// Predicate analysis for index selection
// =================================================================================================

/// One index-usable single-property predicate extracted from a filter conjunct.
#[derive(Debug, Clone, PartialEq)]
struct PropertyPredicate {
    /// The property key (`p` in `n.p`).
    property: String,
    /// What kind of predicate it is.
    kind: PropertyPredicateKind,
}

#[derive(Debug, Clone, PartialEq)]
enum PropertyPredicateKind {
    /// `n.p = value` (equality seek).
    Equality { value: Expr },
    /// `n.p <op> value` for a comparison op (range seek). `bound` already accounts for the side the
    /// property appeared on.
    Range { bound: RangeBound, value: Expr },
}

/// Analyses a single conjunct: does it constrain `variable.<prop>` against a value, in a form an
/// index can serve? Returns the property and predicate kind, or `None`.
///
/// Recognised forms (with the property on either side of a comparison):
/// - `var.prop = value` and `value = var.prop` → equality.
/// - `var.prop <op> value` / `value <op> var.prop` for `<`, `>`, `<=`, `>=` → range.
///
/// The `value` side must **not** itself reference the same `variable` (an index seek needs a value
/// independent of the row being produced); a literal or parameter is the common case.
fn analyze_property_predicate(expr: &Expr, variable: &str) -> Option<PropertyPredicate> {
    let ExprKind::Binary { op, lhs, rhs } = &expr.kind else {
        return None;
    };

    // Property on the left: `var.prop <op> value`.
    if let Some(prop) = property_of(lhs, variable) {
        if !expr_references_var(rhs, variable) {
            return predicate_from(*op, prop, rhs, false);
        }
    }
    // Property on the right: `value <op> var.prop`.
    if let Some(prop) = property_of(rhs, variable) {
        if !expr_references_var(lhs, variable) {
            return predicate_from(*op, prop, lhs, true);
        }
    }
    None
}

/// If `expr` is `variable.<prop> STARTS WITH <prefix>` where `<prefix>` does **not** reference
/// `variable`, returns `(prop, prefix)` (`rmp` task #658). The prefix is the searched string (a
/// literal, or a `$param` after auto-parameterisation); it is evaluated by the executor at run time,
/// so a parameter prefix is served identically to a literal one.
///
/// `STARTS WITH` is **not symmetric**, so only the `property STARTS WITH value` orientation is
/// recognised (`value STARTS WITH n.p` treats the property as the *search* string, which no
/// range seek accelerates). A prefix that references `variable` is rejected — an index seek needs a
/// value independent of the row it produces. `ENDS WITH` / `CONTAINS` are deliberately not matched
/// (they need a text index, out of scope): a suffix/substring is not a contiguous key range.
fn analyze_starts_with_predicate<'a>(expr: &'a Expr, variable: &str) -> Option<(String, &'a Expr)> {
    let ExprKind::Predicate {
        op: PredicateOp::StartsWith,
        operand,
        rhs,
    } = &expr.kind
    else {
        return None;
    };
    let property = property_of(operand, variable)?;
    let prefix = rhs.as_deref()?;
    if expr_references_var(prefix, variable) {
        return None;
    }
    Some((property, prefix))
}

/// If `expr` is exactly `variable.<prop> IS NOT NULL`, returns `prop` (`rmp` task #665). Backs the
/// existence [`NodeIndexScan`](PhysicalOp::NodeIndexScan): every entry in a property index has a
/// present, non-null value, so a full index scan serves the existence predicate.
///
/// `IS NULL` is **not** matched — an index witnesses presence, never absence, so `IS NULL` stays a
/// full scan + filter. The operand must be a bare `variable.<prop>` access (a compound expression such
/// as `n.p + 1 IS NOT NULL` is not an index-usable existence predicate).
fn analyze_is_not_null(expr: &Expr, variable: &str) -> Option<String> {
    let ExprKind::Predicate {
        op: PredicateOp::IsNotNull,
        operand,
        rhs: _,
    } = &expr.kind
    else {
        return None;
    };
    property_of(operand, variable)
}

/// If `expr` is `variable.<prop> CONTAINS|ENDS WITH|STARTS WITH <needle>` where `<needle>` does **not**
/// reference `variable`, returns `(prop, op, needle)` (`rmp` task #662). Backs the text-index seek.
///
/// The three string predicates are **not symmetric**, so only the `property <op> value` orientation is
/// recognised (`value CONTAINS n.p` treats the property as the *search* string, which the trigram
/// index does not accelerate). A needle that references `variable` is rejected — an index seek needs a
/// value independent of the row it produces. The needle is evaluated by the executor at run time (a
/// literal, or a `$param` after auto-parameterisation), so a parameter is served identically to a
/// literal.
fn analyze_text_predicate<'a>(
    expr: &'a Expr,
    variable: &str,
) -> Option<(String, TextSeekOp, &'a Expr)> {
    let ExprKind::Predicate { op, operand, rhs } = &expr.kind else {
        return None;
    };
    let text_op = match op {
        PredicateOp::Contains => TextSeekOp::Contains,
        PredicateOp::EndsWith => TextSeekOp::EndsWith,
        PredicateOp::StartsWith => TextSeekOp::StartsWith,
        _ => return None,
    };
    let property = property_of(operand, variable)?;
    let needle = rhs.as_deref()?;
    if expr_references_var(needle, variable) {
        return None;
    }
    Some((property, text_op, needle))
}

/// Builds a [`PropertyPredicate`] from a comparison operator. `property_on_right` mirrors range
/// bounds (so `value < n.p` becomes `n.p > value`).
fn predicate_from(
    op: BinaryOp,
    property: String,
    value: &Expr,
    property_on_right: bool,
) -> Option<PropertyPredicate> {
    match op {
        BinaryOp::Eq => Some(PropertyPredicate {
            property,
            kind: PropertyPredicateKind::Equality {
                value: value.clone(),
            },
        }),
        BinaryOp::Gt | BinaryOp::Gte | BinaryOp::Lt | BinaryOp::Lte => {
            let mut bound = RangeBound::from_property_lhs(op)?;
            if property_on_right {
                bound = bound.mirrored();
            }
            Some(PropertyPredicate {
                property,
                kind: PropertyPredicateKind::Range {
                    bound,
                    value: value.clone(),
                },
            })
        }
        _ => None,
    }
}

/// If `expr` is exactly `variable.key`, returns `key`.
fn property_of(expr: &Expr, variable: &str) -> Option<String> {
    if let ExprKind::Property { base, key } = &expr.kind {
        if let ExprKind::Variable(name) = &base.kind {
            if name == variable {
                return Some(key.clone());
            }
        }
    }
    None
}

/// Whether `expr` references the variable `variable` anywhere (used to reject a seek value that
/// depends on the row being produced).
fn expr_references_var(expr: &Expr, variable: &str) -> bool {
    match &expr.kind {
        ExprKind::Variable(name) => name == variable,
        ExprKind::Literal(_) | ExprKind::Parameter(_) | ExprKind::CountStar => false,
        ExprKind::Binary { lhs, rhs, .. } => {
            expr_references_var(lhs, variable) || expr_references_var(rhs, variable)
        }
        ExprKind::Unary { operand, .. }
        | ExprKind::HasLabels { operand, .. }
        | ExprKind::TypePredicate { operand, .. }
        | ExprKind::NormalizedPredicate { operand, .. } => expr_references_var(operand, variable),
        ExprKind::Predicate { operand, rhs, .. } => {
            expr_references_var(operand, variable)
                || rhs
                    .as_deref()
                    .is_some_and(|r| expr_references_var(r, variable))
        }
        ExprKind::Property { base, .. } => expr_references_var(base, variable),
        ExprKind::Index { base, index } => {
            expr_references_var(base, variable) || expr_references_var(index, variable)
        }
        ExprKind::Slice { base, low, high } => {
            expr_references_var(base, variable)
                || low
                    .as_deref()
                    .is_some_and(|l| expr_references_var(l, variable))
                || high
                    .as_deref()
                    .is_some_and(|h| expr_references_var(h, variable))
        }
        ExprKind::FunctionCall { args, .. } => {
            args.iter().any(|a| expr_references_var(a, variable))
        }
        ExprKind::List(items) => items.iter().any(|i| expr_references_var(i, variable)),
        ExprKind::Map(entries) => entries
            .iter()
            .any(|(_, v)| expr_references_var(v, variable)),
        ExprKind::Case(case) => {
            case.subject
                .as_deref()
                .is_some_and(|s| expr_references_var(s, variable))
                || case.alternatives.iter().any(|alt| {
                    expr_references_var(&alt.when, variable)
                        || expr_references_var(&alt.then, variable)
                })
                || case
                    .else_expr
                    .as_deref()
                    .is_some_and(|e| expr_references_var(e, variable))
        }
        // Comprehensions, quantifiers, reduce, map projections and existential subqueries establish
        // their own scope (or read the graph); conservatively treat them as referencing the variable
        // so a seek is never built on a value that might shadow/close over it.
        ExprKind::ListComprehension(_)
        | ExprKind::PatternComprehension(_)
        | ExprKind::Quantifier(_)
        | ExprKind::Reduce(_)
        | ExprKind::MapProjection(_)
        | ExprKind::ExistsSubquery(_)
        | ExprKind::CountSubquery(_)
        | ExprKind::CollectSubquery(_) => true,
    }
}

/// Whether `expr` references **any** variable (`n`, `n.p`, `f(n)`, …). A seek whose value expression
/// satisfies this is a **correlated seek** (`rmp` task #708): its key is only known per driving row,
/// fed through the enclosing nested-loop join's correlation, so the reorderer must never move it (see
/// [`contains_correlated_seek`]). A literal-/parameter-only value references no variable and is safe
/// to reorder. Conservative for scope-establishing forms (comprehensions, subqueries): treated as
/// referencing a variable, so a seek built on one is pinned rather than risk being reordered.
fn expr_contains_variable(expr: &Expr) -> bool {
    match &expr.kind {
        ExprKind::Variable(_) => true,
        ExprKind::Literal(_) | ExprKind::Parameter(_) | ExprKind::CountStar => false,
        ExprKind::Binary { lhs, rhs, .. } => {
            expr_contains_variable(lhs) || expr_contains_variable(rhs)
        }
        ExprKind::Unary { operand, .. }
        | ExprKind::HasLabels { operand, .. }
        | ExprKind::TypePredicate { operand, .. }
        | ExprKind::NormalizedPredicate { operand, .. } => expr_contains_variable(operand),
        ExprKind::Predicate { operand, rhs, .. } => {
            expr_contains_variable(operand) || rhs.as_deref().is_some_and(expr_contains_variable)
        }
        ExprKind::Property { base, .. } => expr_contains_variable(base),
        ExprKind::Index { base, index } => {
            expr_contains_variable(base) || expr_contains_variable(index)
        }
        ExprKind::Slice { base, low, high } => {
            expr_contains_variable(base)
                || low.as_deref().is_some_and(expr_contains_variable)
                || high.as_deref().is_some_and(expr_contains_variable)
        }
        ExprKind::FunctionCall { args, .. } => args.iter().any(expr_contains_variable),
        ExprKind::List(items) => items.iter().any(expr_contains_variable),
        ExprKind::Map(entries) => entries.iter().any(|(_, v)| expr_contains_variable(v)),
        ExprKind::Case(case) => {
            case.subject.as_deref().is_some_and(expr_contains_variable)
                || case.alternatives.iter().any(|alt| {
                    expr_contains_variable(&alt.when) || expr_contains_variable(&alt.then)
                })
                || case
                    .else_expr
                    .as_deref()
                    .is_some_and(expr_contains_variable)
        }
        ExprKind::ListComprehension(_)
        | ExprKind::PatternComprehension(_)
        | ExprKind::Quantifier(_)
        | ExprKind::Reduce(_)
        | ExprKind::MapProjection(_)
        | ExprKind::ExistsSubquery(_)
        | ExprKind::CountSubquery(_)
        | ExprKind::CollectSubquery(_) => true,
    }
}

/// Builds the physical seek operator for a matched [`PropertyPredicate`]. The seek is created
/// `ordered: false` (emission order unspecified); [`elide_sort_over_ordered_index`] flips that on
/// later when a matching `ORDER BY` can be served from the index (`rmp` task #665).
fn build_seek(variable: &Var, label: &Label, pp: &PropertyPredicate, index: IndexId) -> PhysicalOp {
    match &pp.kind {
        PropertyPredicateKind::Equality { value } => PhysicalOp::NodeIndexSeek {
            variable: variable.clone(),
            label: label.clone(),
            property: pp.property.clone(),
            value: value.clone(),
            ordered: false,
            index,
        },
        PropertyPredicateKind::Range { bound, value } => PhysicalOp::NodeIndexRangeSeek {
            variable: variable.clone(),
            label: label.clone(),
            property: pp.property.clone(),
            bound: *bound,
            value: value.clone(),
            ordered: false,
            index,
        },
    }
}

/// The `Display` suffix marking a value-orderable index op as emitting in ascending key order
/// (`rmp` task #665). Empty for the default (order-unspecified) op, so existing plan renderings are
/// byte-identical; ` ordered asc` when the provided-order rewrite has elided a `Sort` onto it.
fn ordered_suffix(ordered: bool) -> &'static str {
    if ordered { " ordered asc" } else { "" }
}

/// Re-attaches the residual conjuncts (everything not consumed by a seek) as a single
/// [`Filter`](PhysicalOp::Filter) above `base`, AND-ing them in order. An empty residual leaves
/// `base` bare.
fn attach_residual(base: PhysicalOp, residual: &[&Expr]) -> PhysicalOp {
    let Some((first, rest)) = residual.split_first() else {
        return base;
    };
    let mut combined = (*first).clone();
    for e in rest {
        let span = crate::lexer::Span::new(combined.span.start, e.span.end);
        combined = Expr::new(
            ExprKind::Binary {
                op: BinaryOp::And,
                lhs: Box::new(combined),
                rhs: Box::new((*e).clone()),
            },
            span,
        );
    }
    PhysicalOp::Filter {
        input: Box::new(base),
        predicate: combined,
    }
}

/// Splits a predicate into its top-level `AND` conjuncts (left-to-right). A non-`AND` expression is
/// a single conjunct. The flattening lets the planner consume one conjunct into an index seek and
/// retain the rest as a residual filter.
fn split_conjuncts(expr: &Expr) -> Vec<&Expr> {
    let mut out = Vec::new();
    collect_conjuncts(expr, &mut out);
    out
}

fn collect_conjuncts<'a>(expr: &'a Expr, out: &mut Vec<&'a Expr>) {
    if let ExprKind::Binary {
        op: BinaryOp::And,
        lhs,
        rhs,
    } = &expr.kind
    {
        collect_conjuncts(lhs, out);
        collect_conjuncts(rhs, out);
    } else {
        out.push(expr);
    }
}

// =================================================================================================
// Spatial proximity predicate analysis (for the spatial index seek, `rmp` task #73)
// =================================================================================================

/// A proximity predicate `distance(var.<prop>, <const point>) <op> <const r>` recognised for a
/// [`SpatialIndexSeek`](PhysicalOp::SpatialIndexSeek): the property the index covers, the **constant**
/// centre's 2D projection, and the **constant** radius. Centre and radius are resolved to `f64`s at
/// plan time (see [`analyze_spatial_predicate`]).
struct SpatialPredicate {
    /// The point property key (`loc` in `n.loc`).
    property: String,
    /// The constant centre's `x` coordinate.
    center_x: f64,
    /// The constant centre's `y` coordinate.
    center_y: f64,
    /// The constant proximity radius.
    radius: f64,
    /// The CRS of the constant centre point. A geographic (WGS-84) CRS measures `distance` in
    /// great-circle metres while the spatial grid buckets the 2D projection in coordinate degrees, so
    /// the seek is only sound (degrees == distance units) for a Cartesian CRS (`rmp` #465).
    crs: Crs,
}

/// Analyses a conjunct: is it a proximity predicate the spatial index can serve as a candidate seek?
///
/// Recognised shapes (with `<op>` one of `<`, `<=` — an upper-bounded distance, the only shape a grid
/// proximity query accelerates; a `>`/`>=` proximity is unbounded and keeps the scan):
///
/// - `distance(var.prop, <const point>) <op> <const r>`
/// - `distance(<const point>, var.prop) <op> <const r>` (`distance` is symmetric)
/// - either of the above spelled with the namespaced `point.distance(...)` function (both names lower
///   to the same two-argument `FunctionCall`).
///
/// The centre point expression must evaluate to a **constant** `Value::Point` and the radius to a
/// **constant** number, both at plan time (no variable / parameter / property reference). When either
/// side is not a compile-time constant — or the centre is not a 2D-projectable point — this returns
/// [`None`] and the planner keeps the scan + filter (still correct, just not index-accelerated).
fn analyze_spatial_predicate(expr: &Expr, variable: &str) -> Option<SpatialPredicate> {
    let ExprKind::Binary { op, lhs, rhs } = &expr.kind else {
        return None;
    };
    // Only an *upper-bounded* distance is a grid proximity query (`distance(...) < r` / `<= r`). With
    // the comparison written `distance(...) <op> r`, accept `Lt`/`Lte` directly.
    if !matches!(op, BinaryOp::Lt | BinaryOp::Lte) {
        return None;
    }
    // Left side must be a `distance(...)` call over `var.prop` and a constant point; right side the
    // constant radius. (The radius-on-the-left form `r > distance(...)` is normalised by the parser to
    // property-on-left comparisons elsewhere; here we only recognise the canonical distance-on-left
    // shape, which is what `WHERE distance(n.p, c) < r` parses to.)
    let (property, center, crs) = distance_call_over_var(lhs, variable)?;
    let radius = const_number(rhs)?;
    Some(SpatialPredicate {
        property,
        center_x: center.0,
        center_y: center.1,
        radius,
        crs,
    })
}

/// If `expr` is a `distance(...)` (or `point.distance(...)`) call relating `var.<prop>` to a constant
/// point, returns `(prop, (center_x, center_y))`. Accepts the two-argument symmetric forms (either
/// argument may be the property or the constant point). Returns [`None`] otherwise.
fn distance_call_over_var(expr: &Expr, variable: &str) -> Option<(String, (f64, f64), Crs)> {
    let ExprKind::FunctionCall { name, args, .. } = &expr.kind else {
        return None;
    };
    let fname = name.join(".").to_ascii_lowercase();
    if fname != "distance" && fname != "point.distance" {
        return None;
    }
    if args.len() != 2 {
        return None;
    }
    // One argument must be `var.prop`; the other a constant point. Try both orderings (distance is
    // symmetric). The property argument must reference *only* the seek variable; the centre argument
    // must reference no row data at all (a plan-time constant).
    let try_sides = |prop_side: &Expr, center_side: &Expr| -> Option<(String, (f64, f64), Crs)> {
        let prop = property_of(prop_side, variable)?;
        let (cx, cy, crs) = const_point_xy(center_side)?;
        Some((prop, (cx, cy), crs))
    };
    try_sides(&args[0], &args[1]).or_else(|| try_sides(&args[1], &args[0]))
}

/// Evaluates a **constant** expression to its 2D `(x, y)` projection iff it is a constant
/// `Value::Point` (`rmp` task #73). Returns [`None`] for any non-constant or non-point expression, so
/// the planner declines a spatial seek it cannot pin to a literal centre.
fn const_point_xy(expr: &Expr) -> Option<(f64, f64, Crs)> {
    match const_value(expr)? {
        Value::Point(p) => Some((p.x(), p.y(), p.crs)),
        _ => None,
    }
}

/// Evaluates a **constant** expression to an `f64` iff it is a constant integer or float (including a
/// unary-minus literal). Returns [`None`] for any non-constant or non-numeric expression.
fn const_number(expr: &Expr) -> Option<f64> {
    match const_value(expr)? {
        Value::Integer(i) => Some(i as f64),
        Value::Float(f) => Some(f),
        _ => None,
    }
}

/// A pure, **graph-free** constant folder for the spatial-seek operands: evaluates `expr` to a
/// [`Value`] iff it is composed only of compile-time-constant pieces — literals, unary `+`/`-` over
/// numbers, list/map literals of constants, and the `point()` constructor over a constant map. Any
/// reference to a variable, parameter, property, or non-constant call yields [`None`].
///
/// This mirrors the runtime evaluation of these same operands ([`crate::spatial_fns::construct_point`]
/// is reused verbatim for `point()`), so the centre the planner folds is **identical** to the one the
/// residual filter recomputes at run time — which is what makes the seek's candidate set a true
/// superset of the filter's exact result. Anything it cannot fold is simply declined (the planner
/// then keeps the scan), so it never needs to be exhaustive over the expression grammar.
fn const_value(expr: &Expr) -> Option<Value> {
    match &expr.kind {
        ExprKind::Literal(lit) => const_literal(lit),
        ExprKind::Unary { op, operand } => {
            let v = const_value(operand)?;
            match (op, v) {
                (crate::ast::UnaryOp::Plus, v) => Some(v),
                (crate::ast::UnaryOp::Minus, Value::Integer(i)) => {
                    i.checked_neg().map(Value::Integer)
                }
                (crate::ast::UnaryOp::Minus, Value::Float(f)) => Some(Value::Float(-f)),
                _ => None,
            }
        }
        ExprKind::List(items) => {
            let mut out = Vec::with_capacity(items.len());
            for it in items {
                out.push(const_value(it)?);
            }
            Some(Value::List(out))
        }
        ExprKind::Map(entries) => {
            let mut out = Vec::with_capacity(entries.len());
            for (key, v) in entries {
                out.push((key.name.clone(), const_value(v)?));
            }
            Some(Value::Map(out))
        }
        ExprKind::FunctionCall { name, args, .. } => {
            // Only the `point()` constructor is folded (the one needed for a constant centre); fold its
            // single constant-map argument and reuse the runtime constructor so plan-time and run-time
            // points agree exactly.
            if name.join(".").eq_ignore_ascii_case("point") && args.len() == 1 {
                let arg = const_value(&args[0])?;
                crate::spatial_fns::construct_point(&arg).ok()
            } else {
                None
            }
        }
        _ => None,
    }
}

/// Folds an AST [`Literal`] into a constant [`Value`] (the const-eval subset of
/// [`crate::eval`]'s `literal_value`): an out-of-range integer or a `null` declines (a centre/radius
/// built from `null` cannot drive a seek), keeping the planner on the scan path.
fn const_literal(lit: &crate::ast::Literal) -> Option<Value> {
    use crate::ast::Literal;
    match lit {
        Literal::Integer(i) => Some(Value::Integer(*i)),
        Literal::Float(x) => Some(Value::Float(*x)),
        Literal::String(s) => Some(Value::String(s.clone())),
        Literal::Boolean(b) => Some(Value::Boolean(*b)),
        Literal::Null => None,
    }
}

// =================================================================================================
// Bound-variable analysis (for expand-into and join-key inference)
// =================================================================================================

/// Collects the variables a physical (sub)plan binds, in introduction order, de-duplicated by name.
///
/// Mirrors the logical planner's `collect_bound_vars` ([`crate::lower`]) over the physical operator
/// set: scans/expands/unwind introduce variables; projections/aggregations **reset** the visible set
/// to their output columns (the projection-boundary rule, `04 §7.3`).
fn bound_vars(plan: &PhysicalOp) -> Vec<Var> {
    let mut out = Vec::new();
    gather_bound_vars(plan, &mut out);
    out
}

/// The names of the variables a physical (sub)plan binds.
fn bound_var_names(plan: &PhysicalOp) -> Vec<String> {
    bound_vars(plan).into_iter().map(|v| v.name).collect()
}

fn push_unique(out: &mut Vec<Var>, var: Var) {
    if !out.iter().any(|v| v.name == var.name) {
        out.push(var);
    }
}

fn gather_bound_vars(plan: &PhysicalOp, out: &mut Vec<Var>) {
    match plan {
        PhysicalOp::AllNodesScan { variable }
        | PhysicalOp::NodeByLabelScan { variable, .. }
        | PhysicalOp::TokenLookupScan { variable, .. }
        | PhysicalOp::NodeIndexSeek { variable, .. }
        | PhysicalOp::NodeCompositeIndexSeek { variable, .. }
        | PhysicalOp::NodeLabelScanEq { variable, .. }
        | PhysicalOp::NodeIndexRangeSeek { variable, .. }
        | PhysicalOp::NodeIndexScan { variable, .. }
        | PhysicalOp::NodeIndexStartsWithSeek { variable, .. }
        | PhysicalOp::SpatialIndexSeek { variable, .. }
        | PhysicalOp::NodeTextIndexSeek { variable, .. } => push_unique(out, variable.clone()),
        PhysicalOp::AllRelationshipsScan {
            relationship,
            from,
            to,
            ..
        }
        | PhysicalOp::RelIndexSeek {
            relationship,
            from,
            to,
            ..
        }
        | PhysicalOp::RelIndexRangeSeek {
            relationship,
            from,
            to,
            ..
        }
        | PhysicalOp::RelCompositeIndexSeek {
            relationship,
            from,
            to,
            ..
        }
        | PhysicalOp::RelSpatialIndexSeek {
            relationship,
            from,
            to,
            ..
        } => {
            push_unique(out, from.clone());
            push_unique(out, relationship.clone());
            push_unique(out, to.clone());
        }
        PhysicalOp::Argument { arguments } => {
            for a in arguments {
                push_unique(out, a.clone());
            }
        }
        PhysicalOp::Empty => {}
        PhysicalOp::ExpandAll {
            input,
            relationship,
            to,
            ..
        }
        | PhysicalOp::ExpandInto {
            input,
            relationship,
            to,
            ..
        } => {
            gather_bound_vars(input, out);
            push_unique(out, relationship.clone());
            push_unique(out, to.clone());
        }
        PhysicalOp::ShortestPath {
            input,
            relationship,
            path,
            ..
        } => {
            // Both endpoints are bound by `input`; this op binds the relationship list and, when
            // named, the path variable.
            gather_bound_vars(input, out);
            push_unique(out, relationship.clone());
            if let Some(p) = path {
                push_unique(out, p.clone());
            }
        }
        PhysicalOp::QuantifiedPath {
            input,
            to,
            group_start,
            group_end,
            relationship,
            extra_hops,
            ..
        } => {
            // The anchor `from` is bound by `input`; this op binds the trailing boundary node and
            // every interior group variable (each iteration-start / iteration-end node list and each
            // relationship-trail slice, first hop plus every extra hop).
            gather_bound_vars(input, out);
            push_unique(out, to.clone());
            push_unique(out, group_start.clone());
            push_unique(out, group_end.clone());
            push_unique(out, relationship.clone());
            for step in extra_hops {
                push_unique(out, step.relationship.clone());
                push_unique(out, step.end_node.clone());
            }
        }
        PhysicalOp::Filter { input, .. }
        | PhysicalOp::Skip { input, .. }
        | PhysicalOp::Limit { input, .. }
        | PhysicalOp::Eager { input }
        | PhysicalOp::Sort { input, .. } => gather_bound_vars(input, out),
        PhysicalOp::TopN { input, .. } => gather_bound_vars(input, out),
        PhysicalOp::Unwind {
            input, variable, ..
        }
        | PhysicalOp::LoadCsv {
            input, variable, ..
        }
        | PhysicalOp::NamedPath {
            input, variable, ..
        } => {
            gather_bound_vars(input, out);
            push_unique(out, variable.clone());
        }
        PhysicalOp::Projection { items, .. } => {
            out.clear();
            for col in items {
                push_unique(out, Var::named(&col.alias));
            }
        }
        PhysicalOp::Aggregation {
            group_keys,
            aggregates,
            ..
        } => {
            out.clear();
            for col in group_keys.iter().chain(aggregates) {
                push_unique(out, Var::named(&col.alias));
            }
        }
        PhysicalOp::NestedLoopJoin { left, right } | PhysicalOp::HashJoin { left, right, .. } => {
            gather_bound_vars(left, out);
            gather_bound_vars(right, out);
        }
        PhysicalOp::Optional {
            input,
            null_variables,
        } => {
            gather_bound_vars(input, out);
            for v in null_variables {
                push_unique(out, v.clone());
            }
        }
        PhysicalOp::Union { left, .. } => gather_bound_vars(left, out),
        PhysicalOp::Create { input, pattern } | PhysicalOp::Merge { input, pattern, .. } => {
            gather_bound_vars(input, out);
            for part in pattern {
                match part {
                    CreatePart::Node { variable, .. }
                    | CreatePart::Relationship { variable, .. } => {
                        push_unique(out, variable.clone())
                    }
                }
            }
        }
        PhysicalOp::SetClause { input, .. }
        | PhysicalOp::Delete { input, .. }
        | PhysicalOp::Remove { input, .. }
        // FOREACH's loop variable is local; only the input's bindings survive downstream.
        | PhysicalOp::Foreach { input, .. } => gather_bound_vars(input, out),
        PhysicalOp::ProcedureCall { input, yields, .. } => {
            if let Some(input) = input {
                gather_bound_vars(input, out);
            }
            if let Some(yields) = yields {
                for y in yields {
                    push_unique(out, y.variable.clone());
                }
            }
        }
    }
}

// =================================================================================================
// Pretty-printer (diagnostics + golden tests, matching the logical Display style)
// =================================================================================================

impl fmt::Display for PhysicalOp {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.fmt_indented(f, 0)
    }
}

impl PhysicalOp {
    /// Recursive [`Display`] worker: header at `depth`, then inputs at `depth + 1`. Mirrors the
    /// logical [`Display`](crate::logical::LogicalOp) layout so the two read alike.
    fn fmt_indented(&self, f: &mut fmt::Formatter<'_>, depth: usize) -> fmt::Result {
        use crate::logical::display_helpers as h;
        for _ in 0..depth {
            f.write_str("  ")?;
        }
        match self {
            Self::AllNodesScan { variable } => writeln!(f, "AllNodesScan({variable})"),
            Self::NodeByLabelScan { variable, label } => {
                writeln!(f, "NodeByLabelScan({variable}:{})", label.name)
            }
            Self::TokenLookupScan {
                variable,
                label,
                index,
            } => writeln!(f, "TokenLookupScan({variable}:{} via {index})", label.name),
            Self::NodeIndexSeek {
                variable,
                label,
                property,
                value,
                ordered,
                index,
            } => writeln!(
                f,
                "NodeIndexSeek({variable}:{} {property} = {} via {index}{})",
                label.name,
                h::expr(value),
                ordered_suffix(*ordered),
            ),
            Self::NodeCompositeIndexSeek {
                variable,
                label,
                properties,
                values,
                index,
            } => {
                let keys = properties
                    .iter()
                    .zip(values.iter())
                    .map(|(p, v)| format!("{p} = {}", h::expr(v)))
                    .collect::<Vec<_>>()
                    .join(", ");
                writeln!(
                    f,
                    "NodeCompositeIndexSeek({variable}:{} {keys} via {index})",
                    label.name,
                )
            }
            Self::NodeLabelScanEq {
                variable,
                label,
                property,
                value,
            } => writeln!(
                f,
                "NodeLabelScanEq({variable}:{} {property} = {})",
                label.name,
                h::expr(value),
            ),
            Self::NodeIndexRangeSeek {
                variable,
                label,
                property,
                bound,
                value,
                ordered,
                index,
            } => writeln!(
                f,
                "NodeIndexRangeSeek({variable}:{} {property} {} {} via {index}{})",
                label.name,
                bound.symbol(),
                h::expr(value),
                ordered_suffix(*ordered),
            ),
            Self::NodeIndexScan {
                variable,
                label,
                property,
                ordered,
                index,
            } => writeln!(
                f,
                "NodeIndexScan({variable}:{} {property} via {index}{})",
                label.name,
                ordered_suffix(*ordered),
            ),
            Self::NodeIndexStartsWithSeek {
                variable,
                label,
                property,
                prefix,
                index,
            } => writeln!(
                f,
                "NodeIndexStartsWithSeek({variable}:{} {property} STARTS WITH {} via {index})",
                label.name,
                h::expr(prefix),
            ),
            Self::SpatialIndexSeek {
                variable,
                label,
                property,
                center_x,
                center_y,
                radius,
                index,
            } => writeln!(
                f,
                "SpatialIndexSeek({variable}:{} {property} within {radius} of ({center_x}, {center_y}) via {index})",
                label.name,
            ),
            Self::NodeTextIndexSeek {
                variable,
                label,
                property,
                op,
                needle,
                index,
            } => writeln!(
                f,
                "NodeTextIndexSeek({variable}:{} {property} {} {} via {index})",
                label.name,
                op.symbol(),
                h::expr(needle),
            ),
            Self::AllRelationshipsScan {
                relationship,
                from,
                to,
                direction,
                types,
            } => writeln!(
                f,
                "AllRelationshipsScan({}{relationship}{}{to} from {from}{})",
                h::arrow_left(*direction),
                h::arrow_right(*direction),
                h::types(types),
            ),
            Self::RelIndexSeek {
                relationship,
                from,
                to,
                rel_type,
                property,
                value,
                direction,
                index,
            } => writeln!(
                f,
                "RelIndexSeek({}{relationship}:{} {property} = {}{}{to} from {from} via {index})",
                h::arrow_left(*direction),
                rel_type.name,
                h::expr(value),
                h::arrow_right(*direction),
            ),
            Self::RelIndexRangeSeek {
                relationship,
                from,
                to,
                rel_type,
                property,
                bound,
                value,
                direction,
                index,
            } => writeln!(
                f,
                "RelIndexRangeSeek({}{relationship}:{} {property} {} {}{}{to} from {from} via {index})",
                h::arrow_left(*direction),
                rel_type.name,
                bound.symbol(),
                h::expr(value),
                h::arrow_right(*direction),
            ),
            Self::RelCompositeIndexSeek {
                relationship,
                from,
                to,
                rel_type,
                properties,
                values,
                direction,
                index,
            } => {
                let keys = properties
                    .iter()
                    .zip(values.iter())
                    .map(|(p, v)| format!("{p} = {}", h::expr(v)))
                    .collect::<Vec<_>>()
                    .join(", ");
                writeln!(
                    f,
                    "RelCompositeIndexSeek({}{relationship}:{} {keys}{}{to} from {from} via {index})",
                    h::arrow_left(*direction),
                    rel_type.name,
                    h::arrow_right(*direction),
                )
            }
            Self::RelSpatialIndexSeek {
                relationship,
                from,
                to,
                rel_type,
                property,
                center_x,
                center_y,
                radius,
                direction,
                index,
            } => writeln!(
                f,
                "RelSpatialIndexSeek({}{relationship}:{} {property} within {radius} of ({center_x}, {center_y}) {}{to} from {from} via {index})",
                h::arrow_left(*direction),
                rel_type.name,
                h::arrow_right(*direction),
            ),
            Self::Argument { arguments } => writeln!(f, "Argument({})", h::vars(arguments)),
            Self::Empty => writeln!(f, "Empty"),

            Self::ExpandAll {
                input,
                from,
                relationship,
                to,
                direction,
                types,
                range,
                prior_rels: _,
                rel_props: _,
            } => {
                writeln!(
                    f,
                    "ExpandAll({from}){}{relationship}{}{}{}({to})",
                    h::arrow_left(*direction),
                    h::types(types),
                    h::range(range),
                    h::arrow_right(*direction),
                )?;
                input.fmt_indented(f, depth + 1)
            }
            Self::ExpandInto {
                input,
                from,
                relationship,
                to,
                direction,
                types,
                range,
                prior_rels: _,
                rel_props: _,
            } => {
                writeln!(
                    f,
                    "ExpandInto({from}){}{relationship}{}{}{}({to})",
                    h::arrow_left(*direction),
                    h::types(types),
                    h::range(range),
                    h::arrow_right(*direction),
                )?;
                input.fmt_indented(f, depth + 1)
            }
            Self::ShortestPath {
                input,
                from,
                to,
                relationship,
                path,
                direction,
                types,
                range,
                all,
            } => {
                let name = if *all {
                    "AllShortestPaths"
                } else {
                    "ShortestPath"
                };
                let p = path.as_ref().map(|v| format!("{v} = ")).unwrap_or_default();
                writeln!(
                    f,
                    "{name}({p}({from}){}{relationship}{}{}{}({to}))",
                    h::arrow_left(*direction),
                    h::types(types),
                    h::range(&Some(*range)),
                    h::arrow_right(*direction),
                )?;
                input.fmt_indented(f, depth + 1)
            }

            Self::QuantifiedPath {
                input,
                from,
                to,
                group_start,
                group_end,
                relationship,
                direction,
                types,
                min,
                max,
                into,
                ..
            } => {
                let max_str = max.map_or_else(String::new, |m| m.to_string());
                let tag = if *into {
                    "QuantifiedPathInto"
                } else {
                    "QuantifiedPath"
                };
                writeln!(
                    f,
                    "{tag}(({from})(({group_start}){}{relationship}{}{}({group_end})){{{min},{max_str}}}({to}))",
                    h::arrow_left(*direction),
                    h::types(types),
                    h::arrow_right(*direction),
                )?;
                input.fmt_indented(f, depth + 1)
            }

            Self::NamedPath {
                input,
                variable,
                start,
                steps,
            } => {
                writeln!(f, "NamedPath({variable} = {start}, {})", h::vars(steps))?;
                input.fmt_indented(f, depth + 1)
            }

            Self::Filter { input, predicate } => {
                writeln!(f, "Filter({})", h::expr(predicate))?;
                input.fmt_indented(f, depth + 1)
            }
            Self::Projection {
                input,
                items,
                distinct,
            } => {
                writeln!(
                    f,
                    "Projection{}({})",
                    if *distinct { " DISTINCT" } else { "" },
                    h::columns(items),
                )?;
                input.fmt_indented(f, depth + 1)
            }
            Self::Aggregation {
                input,
                group_keys,
                aggregates,
            } => {
                writeln!(
                    f,
                    "Aggregation(keys=[{}], aggs=[{}])",
                    h::columns(group_keys),
                    h::columns(aggregates),
                )?;
                input.fmt_indented(f, depth + 1)
            }
            Self::Sort { input, keys } => {
                writeln!(f, "Sort({})", h::sort_keys(keys))?;
                input.fmt_indented(f, depth + 1)
            }
            Self::TopN { input, keys, limit } => {
                writeln!(f, "TopN({} LIMIT {})", h::sort_keys(keys), h::expr(limit))?;
                input.fmt_indented(f, depth + 1)
            }
            Self::Skip { input, count } => {
                writeln!(f, "Skip({})", h::expr(count))?;
                input.fmt_indented(f, depth + 1)
            }
            Self::Limit { input, count } => {
                writeln!(f, "Limit({})", h::expr(count))?;
                input.fmt_indented(f, depth + 1)
            }
            Self::Eager { input } => {
                writeln!(f, "Eager")?;
                input.fmt_indented(f, depth + 1)
            }
            Self::Unwind {
                input,
                list,
                variable,
            } => {
                writeln!(f, "Unwind({} AS {variable})", h::expr(list))?;
                input.fmt_indented(f, depth + 1)
            }
            Self::LoadCsv {
                input,
                with_headers,
                url,
                variable,
                field_terminator,
            } => {
                let headers = if *with_headers { " WITH HEADERS" } else { "" };
                let term = field_terminator
                    .map(|c| format!(" FIELDTERMINATOR {c:?}"))
                    .unwrap_or_default();
                writeln!(
                    f,
                    "LoadCsv({headers} FROM {} AS {variable}{term})",
                    h::expr(url)
                )?;
                input.fmt_indented(f, depth + 1)
            }

            Self::NestedLoopJoin { left, right } => {
                writeln!(f, "NestedLoopJoin")?;
                left.fmt_indented(f, depth + 1)?;
                right.fmt_indented(f, depth + 1)
            }
            Self::HashJoin {
                left,
                right,
                join_keys,
            } => {
                writeln!(f, "HashJoin(on=[{}])", join_keys.join(", "))?;
                left.fmt_indented(f, depth + 1)?;
                right.fmt_indented(f, depth + 1)
            }
            Self::Union { left, right, all } => {
                writeln!(f, "Union{}", if *all { " ALL" } else { "" })?;
                left.fmt_indented(f, depth + 1)?;
                right.fmt_indented(f, depth + 1)
            }
            Self::Optional {
                input,
                null_variables,
            } => {
                writeln!(f, "Optional(nulls=[{}])", h::vars(null_variables))?;
                input.fmt_indented(f, depth + 1)
            }

            Self::Create { input, pattern } => {
                writeln!(f, "Create({})", h::create_parts(pattern))?;
                input.fmt_indented(f, depth + 1)
            }
            Self::Merge {
                input,
                pattern,
                on_create,
                on_match,
            } => {
                writeln!(
                    f,
                    "Merge({}{}{})",
                    h::create_parts(pattern),
                    h::merge_actions("ON CREATE", on_create),
                    h::merge_actions("ON MATCH", on_match),
                )?;
                input.fmt_indented(f, depth + 1)
            }
            Self::SetClause { input, ops } => {
                writeln!(f, "Set({})", h::set_ops(ops))?;
                input.fmt_indented(f, depth + 1)
            }
            Self::Delete {
                input,
                detach,
                exprs,
            } => {
                let rendered: Vec<String> = exprs.iter().map(h::expr).collect();
                writeln!(
                    f,
                    "{}Delete({})",
                    if *detach { "Detach" } else { "" },
                    rendered.join(", "),
                )?;
                input.fmt_indented(f, depth + 1)
            }
            Self::Remove { input, ops } => {
                writeln!(f, "Remove({})", h::remove_ops(ops))?;
                input.fmt_indented(f, depth + 1)
            }
            Self::Foreach {
                input,
                variable,
                body,
                ..
            } => {
                writeln!(f, "Foreach({})", variable.name)?;
                body.fmt_indented(f, depth + 1)?;
                input.fmt_indented(f, depth + 1)
            }
            Self::ProcedureCall {
                input,
                name,
                args,
                yields,
            } => {
                writeln!(
                    f,
                    "ProcedureCall({}{}{})",
                    name.join("."),
                    h::call_args(args),
                    h::yields(yields),
                )?;
                if let Some(input) = input {
                    input.fmt_indented(f, depth + 1)?;
                }
                Ok(())
            }
        }
    }
}

/// One side of an owned range bound (`rmp` task #768): `(value, inclusive)`, or `None` for an open side.
pub type OwnedRangeSide = Option<(graphus_core::Value, bool)>;
/// One statically-knowable node-property RANGE seek, in name form (`rmp` task #768):
/// `(label, property, lower, upper)`, each bound an [`OwnedRangeSide`]. The coordinator resolves the
/// names to tokens for [`IndexSet::capture_node_property_range`].
pub type StaticRangeSeek = (String, String, OwnedRangeSide, OwnedRangeSide);
/// One statically-knowable node COMPOSITE equality seek, in name form (`rmp` task #768):
/// `(label, properties, values)`.
pub type StaticCompositeSeek = (String, Vec<String>, Vec<graphus_core::Value>);
/// One statically-knowable node TEXT (trigram) seek, in name form (`rmp` task #768):
/// `(label, property, op, needle)`.
pub type StaticTextSeek = (String, String, TextSeekOp, String);
/// One statically-knowable SPATIAL (point) proximity seek, in name form (`rmp` task #770), shared by
/// nodes and relationships: `(label_or_rel_type, property, center_x, center_y, radius)`. The centre and
/// radius are the plan-time-folded `f64` constants the [`SpatialIndexSeek`](PhysicalOp::SpatialIndexSeek)
/// / [`RelSpatialIndexSeek`](PhysicalOp::RelSpatialIndexSeek) operator carries (never a `$param`), so no
/// parameter resolution is involved. The coordinator resolves the name to a token for
/// [`IndexSet::capture_node_spatial`](crate::index_set::IndexSet::capture_node_spatial) /
/// [`capture_rel_spatial`](crate::index_set::IndexSet::capture_rel_spatial).
pub type StaticSpatialSeek = (String, String, f64, f64, f64);

/// The owned `(lower, upper)` bounds a [`RangeBound`] + seek value implies (`rmp` task #768) — the
/// owned twin of the executor's `range_bounds`, kept in lockstep so the capture and the executor form
/// byte-identical memo keys. A drift here only misses the acceleration (the reader declines to the exact
/// scan), never a row.
fn owned_range_bounds(
    bound: RangeBound,
    value: graphus_core::Value,
) -> (OwnedRangeSide, OwnedRangeSide) {
    match bound {
        RangeBound::GreaterThan => (Some((value, false)), None),
        RangeBound::GreaterOrEqual => (Some((value, true)), None),
        RangeBound::LessThan => (None, Some((value, false))),
        RangeBound::LessOrEqual => (None, Some((value, true))),
    }
}

/// Collects this operator's statically-knowable node-property RANGE seeks — over all three
/// range-index operators — then recurses into its sub-plans (`rmp` task #768). See
/// [`PhysicalPlan::static_node_index_range_seeks`]. Walks [`PhysicalOp::children`] so a nested seek is
/// never missed (a miss only costs the acceleration; the reader declines and scans).
fn collect_static_node_range_seeks(
    op: &PhysicalOp,
    params: &crate::binding::BoundParameters,
    out: &mut Vec<StaticRangeSeek>,
) {
    match op {
        PhysicalOp::NodeIndexRangeSeek {
            label,
            property,
            bound,
            value,
            ..
        } => {
            if let Some(v) = static_seek_value(value, params) {
                let (lower, upper) = owned_range_bounds(*bound, v);
                out.push((label.name.clone(), property.clone(), lower, upper));
            }
        }
        PhysicalOp::NodeIndexScan {
            label, property, ..
        } => {
            // `IS NOT NULL` lowers to the open `(None, None)` range: every index entry is a present,
            // non-null value, and the residual `IS NOT NULL` filter above restores exactness. No operand,
            // so it is always statically knowable — the executor unconditionally calls
            // `index_seek_range(None, None)` for this operator.
            out.push((label.name.clone(), property.clone(), None, None));
        }
        PhysicalOp::NodeIndexStartsWithSeek {
            label,
            property,
            prefix,
            ..
        } => {
            // `STARTS WITH <prefix>` lowers to `[prefix, successor(prefix))`, computed from the evaluated
            // string exactly as the executor does (a non-string prefix matches nothing and scans, so it is
            // not captured). Reuses the executor's `string_prefix_successor` so the upper bound cannot
            // drift from the one the executor forms.
            if let Some(graphus_core::Value::String(s)) = static_seek_value(prefix, params) {
                let lower = Some((graphus_core::Value::String(s.clone()), true));
                let upper = crate::executor::string_prefix_successor(&s)
                    .map(|succ| (graphus_core::Value::String(succ), false));
                out.push((label.name.clone(), property.clone(), lower, upper));
            }
        }
        _ => {}
    }
    for child in op.children() {
        collect_static_node_range_seeks(child, params, out);
    }
}

/// Collects this operator's statically-knowable node COMPOSITE equality seeks, then recurses
/// (`rmp` task #768). A tuple is emitted only when **every** per-key value is statically knowable. See
/// [`PhysicalPlan::static_node_composite_seeks`].
fn collect_static_node_composite_seeks(
    op: &PhysicalOp,
    params: &crate::binding::BoundParameters,
    out: &mut Vec<StaticCompositeSeek>,
) {
    if let PhysicalOp::NodeCompositeIndexSeek {
        label,
        properties,
        values,
        ..
    } = op
    {
        let resolved: Option<Vec<graphus_core::Value>> = values
            .iter()
            .map(|v| static_seek_value(v, params))
            .collect();
        if let Some(vals) = resolved {
            out.push((label.name.clone(), properties.clone(), vals));
        }
    }
    for child in op.children() {
        collect_static_node_composite_seeks(child, params, out);
    }
}

/// Collects this operator's statically-knowable node TEXT (trigram) seeks, then recurses
/// (`rmp` task #768). Emitted only for a string needle. See [`PhysicalPlan::static_node_text_seeks`].
fn collect_static_node_text_seeks(
    op: &PhysicalOp,
    params: &crate::binding::BoundParameters,
    out: &mut Vec<StaticTextSeek>,
) {
    if let PhysicalOp::NodeTextIndexSeek {
        label,
        property,
        op: text_op,
        needle,
        ..
    } = op
        && let Some(graphus_core::Value::String(s)) = static_seek_value(needle, params)
    {
        out.push((label.name.clone(), property.clone(), *text_op, s));
    }
    for child in op.children() {
        collect_static_node_text_seeks(child, params, out);
    }
}

/// Collects this operator's statically-knowable relationship EQUALITY seeks, then recurses
/// (`rmp` task #769). See [`PhysicalPlan::static_rel_index_eq_seeks`].
fn collect_static_rel_eq_seeks(
    op: &PhysicalOp,
    params: &crate::binding::BoundParameters,
    out: &mut Vec<(String, String, graphus_core::Value)>,
) {
    if let PhysicalOp::RelIndexSeek {
        rel_type,
        property,
        value,
        ..
    } = op
        && let Some(seek) = static_seek_value(value, params)
    {
        out.push((rel_type.name.clone(), property.clone(), seek));
    }
    for child in op.children() {
        collect_static_rel_eq_seeks(child, params, out);
    }
}

/// Collects this operator's statically-knowable relationship RANGE seeks, then recurses
/// (`rmp` task #769/#680). See [`PhysicalPlan::static_rel_index_range_seeks`].
fn collect_static_rel_range_seeks(
    op: &PhysicalOp,
    params: &crate::binding::BoundParameters,
    out: &mut Vec<StaticRangeSeek>,
) {
    if let PhysicalOp::RelIndexRangeSeek {
        rel_type,
        property,
        bound,
        value,
        ..
    } = op
        && let Some(v) = static_seek_value(value, params)
    {
        let (lower, upper) = owned_range_bounds(*bound, v);
        out.push((rel_type.name.clone(), property.clone(), lower, upper));
    }
    for child in op.children() {
        collect_static_rel_range_seeks(child, params, out);
    }
}

/// Collects this operator's statically-knowable relationship COMPOSITE seeks, then recurses
/// (`rmp` task #769/#666). Emitted only when every per-key value is statically knowable. See
/// [`PhysicalPlan::static_rel_composite_seeks`].
fn collect_static_rel_composite_seeks(
    op: &PhysicalOp,
    params: &crate::binding::BoundParameters,
    out: &mut Vec<StaticCompositeSeek>,
) {
    if let PhysicalOp::RelCompositeIndexSeek {
        rel_type,
        properties,
        values,
        ..
    } = op
    {
        let resolved: Option<Vec<graphus_core::Value>> = values
            .iter()
            .map(|v| static_seek_value(v, params))
            .collect();
        if let Some(vals) = resolved {
            out.push((rel_type.name.clone(), properties.clone(), vals));
        }
    }
    for child in op.children() {
        collect_static_rel_composite_seeks(child, params, out);
    }
}

/// Collects this operator's node SPATIAL (point) seeks, then recurses (`rmp` task #770). No `params`:
/// the centre + radius are the plan-time-folded `f64` constants the operator carries (never a `$param`).
/// See [`PhysicalPlan::static_node_spatial_seeks`].
fn collect_static_node_spatial_seeks(op: &PhysicalOp, out: &mut Vec<StaticSpatialSeek>) {
    if let PhysicalOp::SpatialIndexSeek {
        label,
        property,
        center_x,
        center_y,
        radius,
        ..
    } = op
    {
        out.push((
            label.name.clone(),
            property.clone(),
            *center_x,
            *center_y,
            *radius,
        ));
    }
    for child in op.children() {
        collect_static_node_spatial_seeks(child, out);
    }
}

/// Collects this operator's relationship SPATIAL (point) seeks, then recurses (`rmp` task #770/#664) —
/// the relationship twin of [`collect_static_node_spatial_seeks`]. See
/// [`PhysicalPlan::static_rel_spatial_seeks`].
fn collect_static_rel_spatial_seeks(op: &PhysicalOp, out: &mut Vec<StaticSpatialSeek>) {
    if let PhysicalOp::RelSpatialIndexSeek {
        rel_type,
        property,
        center_x,
        center_y,
        radius,
        ..
    } = op
    {
        out.push((
            rel_type.name.clone(),
            property.clone(),
            *center_x,
            *center_y,
            *radius,
        ));
    }
    for child in op.children() {
        collect_static_rel_spatial_seeks(child, out);
    }
}

/// Collects this operator's statically-knowable `NodeIndexSeek` keys, then recurses into its sub-plans
/// (`rmp` task #755, Slice S2). See [`PhysicalPlan::static_node_index_eq_seeks`].
///
/// The recursion walks [`PhysicalOp::children`] — the single, exhaustive definition of "the children of
/// a physical operator" — so a newly-added child-bearing operator is traversed here automatically and a
/// nested seek can never escape the capture by being missed. (Escaping only costs the acceleration: the
/// reader would decline and scan. The walk is shared so it stays right anyway.)
fn collect_static_node_index_eq_seeks(
    op: &PhysicalOp,
    params: &crate::binding::BoundParameters,
    out: &mut Vec<(String, String, graphus_core::Value)>,
) {
    if let PhysicalOp::NodeIndexSeek {
        label,
        property,
        value,
        ..
    } = op
        && let Some(seek) = static_seek_value(value, params)
    {
        out.push((label.name.clone(), property.clone(), seek));
    }
    for child in op.children() {
        collect_static_node_index_eq_seeks(child, params, out);
    }
}

/// The value of `expr` if — and only if — it is knowable at dispatch and guaranteed to equal what the
/// executor will evaluate: a literal, or a bound parameter. Everything else (a correlated `t.k`, a
/// function call, an arithmetic expression) yields [`None`], because it may depend on the row, the
/// clock, or the graph. See [`PhysicalPlan::static_node_index_eq_seeks`] for why this is the whole test.
fn static_seek_value(
    expr: &Expr,
    params: &crate::binding::BoundParameters,
) -> Option<graphus_core::Value> {
    match &expr.kind {
        ExprKind::Literal(lit) => crate::eval::literal_value(lit).ok(),
        ExprKind::Parameter(name) => params.get(name).cloned(),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::catalog::IndexCatalog;
    use crate::lexer::tokenize;
    use crate::lower::lower;
    use crate::parser::parse_tokens;
    use crate::semantics::analyze;

    fn physical(src: &str, catalog: &IndexCatalog) -> PhysicalPlan {
        let toks = tokenize(src).expect("lex");
        let ast = parse_tokens(&toks, src).expect("parse");
        let validated = analyze(&ast).expect("analyze");
        let logical = lower(&validated);
        plan_physical(&logical, catalog)
    }

    /// Compiles `src` only as far as the logical plan, so a test can plan it both with and without
    /// statistics and compare the cardinality estimate the planner records.
    fn logical_of(src: &str) -> LogicalOp {
        let toks = tokenize(src).expect("lex");
        let ast = parse_tokens(&toks, src).expect("parse");
        let validated = analyze(&ast).expect("analyze");
        lower(&validated)
    }

    // ---- QueryType classification (`rmp` task #511) -------------------------------------------

    /// The [`QueryType`] of `src` compiled against the empty catalog.
    fn query_type_of(src: &str) -> QueryType {
        physical(src, &IndexCatalog::empty()).query_type()
    }

    #[test]
    fn query_type_read_has_no_write_operator() {
        assert_eq!(query_type_of("MATCH (n) RETURN n"), QueryType::Read);
        // A read with aggregation / ordering is still a read.
        assert_eq!(
            query_type_of("MATCH (n) RETURN count(n) ORDER BY count(n)"),
            QueryType::Read
        );
    }

    #[test]
    fn query_type_write_root_emits_no_rows() {
        // A bare CREATE: the plan root IS the write operator (no RETURN above it).
        assert_eq!(query_type_of("CREATE (n)"), QueryType::Write);
        // MATCH then SET, no RETURN: the SetClause is the root.
        assert_eq!(query_type_of("MATCH (n) SET n.x = 1"), QueryType::Write);
        // DETACH DELETE with no RETURN: the Delete is the root.
        assert_eq!(
            query_type_of("MATCH (a)-[r]->(b) DETACH DELETE a"),
            QueryType::Write
        );
        // REMOVE with no RETURN.
        assert_eq!(query_type_of("MATCH (n) REMOVE n.x"), QueryType::Write);
    }

    #[test]
    fn query_type_read_write_when_a_return_sits_above_the_write() {
        // CREATE ... RETURN: a projection sits above the Create, so the statement returns rows.
        assert_eq!(query_type_of("CREATE (n) RETURN n"), QueryType::ReadWrite);
        // SET ... RETURN.
        assert_eq!(
            query_type_of("MATCH (n) SET n.x = 1 RETURN n"),
            QueryType::ReadWrite
        );
    }

    // ---- procedure-call detection for off-thread dispatch (`rmp` task #548) -------------------

    /// Whether `src`, planned against the empty catalog, is detected as invoking a procedure.
    fn calls_procedure_of(src: &str) -> bool {
        physical(src, &IndexCatalog::empty()).calls_procedure()
    }

    #[test]
    fn calls_procedure_is_false_for_a_plain_read() {
        assert!(!calls_procedure_of("MATCH (n) RETURN n"));
        assert!(!calls_procedure_of("MATCH (a)-[r]->(b) RETURN b"));
        assert!(!calls_procedure_of(
            "MATCH (n) WHERE n.x > 1 RETURN count(n) ORDER BY count(n)"
        ));
    }

    #[test]
    fn calls_procedure_detects_a_procedure_nested_under_a_previously_missed_operator() {
        // rmp #548 regression. `CALL db.index.fulltext.queryNodes(...) YIELD node MATCH (node)-->(m)`
        // plans as `Projection -> ExpandAll(from node) -> ProcedureCall`. The old server-side
        // `op_calls_procedure` did NOT recurse `ExpandAll` (its `_ => false` catch-all), so this
        // escaped detection and was mis-dispatched to the off-thread reader, where the declined
        // full-text seam surfaced as a spurious "no such index" error. The exhaustive
        // `contains_procedure_call` behind `calls_procedure()` must catch it.
        assert!(
            calls_procedure_of(
                "CALL db.index.fulltext.queryNodes('idx','term') YIELD node \
                 MATCH (node)-[r]->(m) RETURN m"
            ),
            "a ProcedureCall under an ExpandAll must be detected (the #543 off-thread escape)"
        );
        // A named path above the expand (`NamedPath`, another operator the old walk missed).
        assert!(
            calls_procedure_of(
                "CALL db.index.fulltext.queryNodes('idx','term') YIELD node \
                 MATCH p = (node)-[r]->(m) RETURN p"
            ),
            "a ProcedureCall under a NamedPath must be detected"
        );
        // The simple case (procedure at/near the root) was always detected — keep it covered so a
        // future refactor cannot silently regress it.
        assert!(calls_procedure_of(
            "CALL db.labels() YIELD label RETURN label"
        ));
    }

    // ---- reader-safe procedure classification for off-thread dispatch (`rmp` task #546) ---------

    #[test]
    fn reader_safe_gate_admits_a_read_that_calls_no_procedure() {
        use crate::procedure_registry::{ProcedureSet, builtins};
        // A plain read (no procedure) is vacuously all-reader-safe against ANY registry — including an
        // empty one — so it dispatches off-thread exactly as before this task.
        let empty = ProcedureSet::new();
        for src in [
            "MATCH (n) RETURN n",
            "MATCH (a)-[r]->(b) RETURN b",
            "MATCH (n) RETURN count(n) ORDER BY count(n)",
        ] {
            let plan = physical(src, &IndexCatalog::empty());
            assert!(plan.calls_only_reader_safe_procedures(builtins()));
            assert!(plan.calls_only_reader_safe_procedures(&empty));
        }
    }

    #[test]
    fn reader_safe_gate_admits_reader_safe_builtins_and_rejects_unclassified() {
        use crate::procedure_registry::{ProcedureSet, builtins};
        // `db.*` introspection + `db.index.fulltext.queryNodes` are registered reader-safe in the
        // engine's builtins, so a plan calling them (even nested under an `ExpandAll`) is admitted.
        for src in [
            "CALL db.labels() YIELD label RETURN label",
            "CALL db.propertyKeys() YIELD propertyKey RETURN propertyKey",
            "CALL db.index.fulltext.queryNodes('idx','term') YIELD node \
             MATCH (node)-[r]->(m) RETURN m",
        ] {
            let plan = physical(src, &IndexCatalog::empty());
            assert!(
                plan.calls_only_reader_safe_procedures(builtins()),
                "reader-safe builtin plan must be admitted off-thread: {src}"
            );
            // The SAME plan is REJECTED against a registry that does not classify the procedure
            // reader-safe (an empty registry ⇒ `is_reader_safe` conservatively `false`), so an
            // unknown/unclassified — potentially writing — procedure keeps the read inline.
            let empty = ProcedureSet::new();
            assert!(
                !plan.calls_only_reader_safe_procedures(&empty),
                "an unclassified procedure must keep the read inline: {src}"
            );
        }
    }

    #[test]
    fn reader_safe_gate_rejects_a_plan_mixing_safe_and_unsafe_procedures() {
        use crate::procedure_registry::{
            FieldSpec, FieldType, ProcedureRegistry, ProcedureSet, ProcedureSignature, ValueClass,
        };
        // A plan calling two procedures, classified against a registry where one is reader-safe and the
        // other is NOT — even one non-reader-safe call must pin the whole read inline. (Two builtins are
        // used so the plan compiles; the CLASSIFICATION registry is independent of the compile registry,
        // which is exactly how the server passes its live `ExtensionRegistry` in.)
        let string_out = |name: &str| {
            ProcedureSignature::new(
                name,
                Vec::new(),
                vec![FieldSpec::new(
                    "v",
                    FieldType {
                        class: ValueClass::String,
                        nullable: false,
                    },
                )],
            )
        };
        let mut reg = ProcedureSet::new();
        reg.register_reader_safe(string_out("db.labels"), Box::new(|_a, _g| Ok(Vec::new())));
        // `db.propertyKeys` registered with the conservative (non-reader-safe) `register`.
        reg.register(
            string_out("db.propertyKeys"),
            Box::new(|_a, _g| Ok(Vec::new())),
        );
        assert!(reg.is_reader_safe("db.labels"));
        assert!(!reg.is_reader_safe("db.propertyKeys"));

        // `CALL db.labels() YIELD label CALL db.propertyKeys() YIELD propertyKey RETURN …` — both
        // present; compiles against the builtins, classified against `reg`.
        let plan = physical(
            "CALL db.labels() YIELD label \
             CALL db.propertyKeys() YIELD propertyKey RETURN label, propertyKey",
            &IndexCatalog::empty(),
        );
        assert!(
            !plan.calls_only_reader_safe_procedures(&reg),
            "a plan calling even one non-reader-safe procedure must stay inline"
        );
        // Against the builtins (BOTH reader-safe) the same plan is admitted.
        assert!(
            plan.calls_only_reader_safe_procedures(crate::procedure_registry::builtins()),
            "a plan whose procedures are all reader-safe is admitted off-thread"
        );
    }

    #[test]
    fn single_pattern_plan_is_stable_under_statistics() {
        use crate::graph_access::{GraphAccess, MemGraph};
        use graphus_core::Value;

        let catalog = IndexCatalog::builder()
            .with_label_property("Person", "age")
            .build();
        // A single-pattern query with a *selective* equality (every age distinct): no joins to
        // reorder, and the index seek stays the cheapest access path, so the cost-based planner keeps
        // the rule-based tree byte-for-byte.
        let logical = logical_of("MATCH (n:Person) WHERE n.age = 30 RETURN n");

        let mut g = MemGraph::new();
        for i in 0..50 {
            g.add_node(["Person"], [("age", Value::Integer(i))]);
        }

        let without = plan_physical(&logical, &catalog);
        let with = plan_physical_with_stats(&logical, &catalog, g.statistics());

        // With nothing to reorder and a selective seek, the operator tree and the recorded index
        // dependencies are identical whether or not stats are supplied.
        assert_eq!(without.root, with.root);
        assert_eq!(
            without.index_dependencies().collect::<Vec<_>>(),
            with.index_dependencies().collect::<Vec<_>>()
        );
    }

    #[test]
    fn multi_pattern_plan_changes_under_skewed_statistics() {
        use crate::graph_access::{GraphAccess, MemGraph};
        use graphus_core::Value;

        // A three-component cartesian query: MATCH (a:Person), (b:Company), (c:Car) WHERE … . The
        // logical planner lowers this to `Filter(preds) over ((Person × Company) × Car)` — a left-deep
        // chain of cartesian NestedLoopJoins. Its *output* size is order-invariant, but the sum of the
        // intermediate pair-costs is NOT: joining the two small relations (Company × Car) first, then
        // the large one, dramatically shrinks the costly upper join. With skewed statistics (Person ≫
        // Company, Car) the cost-based planner must reorder to put the small operands inermost,
        // producing a different — and cheaper — tree.
        let catalog = IndexCatalog::empty();
        let logical = logical_of(
            "MATCH (a:Person), (b:Company), (c:Car) WHERE a.k = b.k AND b.j = c.j RETURN a, b, c",
        );

        let mut g = MemGraph::new();
        for i in 0..1000 {
            g.add_node(["Person"], [("k", Value::Integer(i))]);
        }
        for i in 0..3 {
            g.add_node(
                ["Company"],
                [("k", Value::Integer(i)), ("j", Value::Integer(i))],
            );
        }
        for i in 0..3 {
            g.add_node(["Car"], [("j", Value::Integer(i))]);
        }
        let stats = g.statistics();

        let without = plan_physical(&logical, &catalog);
        let with = plan_physical_with_stats(&logical, &catalog, stats);

        // The acceptance criterion: a multi-pattern query's tree DOES change with statistics …
        assert_ne!(
            without.root, with.root,
            "skewed stats must reshape the join:\nrule-based:\n{without}\ncost-based:\n{with}"
        );
        // … and the cost-based tree is strictly cheaper than the rule-based one (the reorder wins).
        let rule_cost = estimate_cost(&without.root, stats).cost;
        let opt_cost = estimate_cost(&with.root, stats).cost;
        assert!(
            opt_cost < rule_cost,
            "cost-based plan ({opt_cost}) must be cheaper than rule-based ({rule_cost})"
        );
    }

    #[test]
    fn estimated_rows_reflects_supplied_statistics() {
        use crate::graph_access::{GraphAccess, MemGraph};
        use graphus_core::Value;

        let catalog = IndexCatalog::empty();
        let logical = logical_of("MATCH (n:Person) RETURN n");

        let mut g = MemGraph::new();
        for i in 0..7 {
            g.add_node(["Person"], [("id", Value::Integer(i))]);
        }
        // A non-Person node, to prove the estimate uses the exact per-label count, not the total.
        g.add_node(["Company"], [("id", Value::Integer(0))]);

        let plan = plan_physical_with_stats(&logical, &catalog, g.statistics());
        // The label scan's exact count (7 :Person) flows unchanged through the RETURN projection.
        assert_eq!(plan.estimated_rows(), 7.0);
        // And the plan's estimate is exactly the estimator's verdict over the same logical plan.
        assert_eq!(
            plan.estimated_rows(),
            estimate_rows(&logical, g.statistics())
        );
    }

    #[test]
    fn plan_physical_uses_the_no_stats_fallback_estimate() {
        let catalog = IndexCatalog::empty();
        let logical = logical_of("MATCH (n) RETURN n");

        let plan = plan_physical(&logical, &catalog);
        // With no statistics the estimator's documented fallbacks apply; the result is finite and
        // positive, and equals a direct estimate with `None`.
        assert!(plan.estimated_rows().is_finite() && plan.estimated_rows() > 0.0);
        assert_eq!(plan.estimated_rows(), estimate_rows(&logical, None));

        // `plan_physical` is exactly `plan_physical_with_stats(.., None)` — same tree, same estimate.
        let explicit = plan_physical_with_stats(&logical, &catalog, None);
        assert_eq!(plan.root, explicit.root);
        assert_eq!(plan.estimated_rows(), explicit.estimated_rows());
    }

    #[test]
    fn limit_over_a_write_gets_an_eager_barrier() {
        let plan = physical("CREATE (n) RETURN n LIMIT 0", &IndexCatalog::empty());
        let rendered = plan.to_string();
        assert!(rendered.contains("Eager"), "{rendered}");
        // The barrier sits between the Limit and the write.
        let limit_pos = rendered.find("Limit").expect("limit");
        let eager_pos = rendered.find("Eager").expect("eager");
        let create_pos = rendered.find("Create").expect("create");
        assert!(
            limit_pos < eager_pos && eager_pos < create_pos,
            "{rendered}"
        );
    }

    #[test]
    fn limit_over_a_pure_read_has_no_eager_barrier() {
        let plan = physical("MATCH (n) RETURN n LIMIT 1", &IndexCatalog::empty());
        assert!(!plan.to_string().contains("Eager"), "{plan}");
    }

    #[test]
    fn equality_on_indexed_property_becomes_index_seek() {
        let catalog = IndexCatalog::builder()
            .with_label_property("Person", "age")
            .build();
        let plan = physical("MATCH (n:Person) WHERE n.age = 30 RETURN n", &catalog);
        assert!(plan.to_string().contains("NodeIndexSeek"), "{plan}");
        assert_eq!(plan.index_dependencies().count(), 1);
    }

    #[test]
    fn row_valued_correlated_equality_anchor_becomes_index_seek() {
        // `rmp` task #708 regression PIN. A row-valued (correlated) equality anchor —
        // `UNWIND rows AS t MATCH (b:Person {uid: t.uid})` — MUST lower to a per-left-row
        // `NodeIndexSeek` keyed off the correlation value, NOT fall back to an O(N)-per-row label
        // scan. This is the seek PATH (not the syntax), so every formulation the planner emits must
        // hold: inline pattern property, explicit `WHERE`, and a `WITH`-projected key. A future
        // change that silently drops the correlated anchor back to a `NodeByLabelScan` fails here.
        let catalog = IndexCatalog::builder()
            .with_label_property("Person", "uid")
            .build();

        for src in [
            "UNWIND $rows AS t MATCH (b:Person {uid: t.uid}) RETURN b",
            "UNWIND $rows AS t MATCH (b:Person) WHERE b.uid = t.uid RETURN b",
            "UNWIND $rows AS t WITH t.uid AS u MATCH (b:Person {uid: u}) RETURN b",
            "UNWIND [{uid: 1}, {uid: 2}] AS t MATCH (b:Person {uid: t.uid}) RETURN b",
        ] {
            let plan = physical(src, &catalog);
            let rendered = plan.to_string();
            assert!(
                rendered.contains("NodeIndexSeek"),
                "the correlated anchor must lower to an index seek: {src}\n{rendered}"
            );
            assert!(
                !rendered.contains("NodeByLabelScan"),
                "the correlated anchor must NOT fall back to a label scan: {src}\n{rendered}"
            );
            assert!(
                rendered.contains("NestedLoopJoin"),
                "the correlated seek is driven per-left-row by a nested-loop join: {src}\n{rendered}"
            );
            assert_eq!(
                plan.index_dependencies().count(),
                1,
                "the correlated seek records its IndexId dependency: {src}"
            );
        }
    }

    #[test]
    fn cost_based_optimizer_never_moves_or_reverts_the_correlated_seek() {
        // `rmp` task #708: the correlated seek's key is fed per driving row through the nested-loop
        // join, so the cost-based optimiser must treat it as immovable — never hoist it to the OUTER
        // (left) side of the join (where the key would be unbound), and never revert it to a scan (the
        // range revert would rebuild a `Filter` in the correlated branch where the outer variable is
        // out of scope). With a large `:Person` count the cost model would be tempted to reorder/revert
        // a normal join; here the cost-based tree must be byte-identical to the rule-based one.
        use crate::graph_access::{GraphAccess, MemGraph};
        use graphus_core::Value;

        let catalog = IndexCatalog::builder()
            .with_label_property("Person", "uid")
            .build();
        let mut g = MemGraph::new();
        for i in 0..2000 {
            g.add_node(["Person"], [("uid", Value::Integer(i))]);
        }

        for src in [
            "UNWIND $rows AS t MATCH (b:Person {uid: t.uid}) RETURN b",
            "UNWIND $rows AS t MATCH (b:Person) WHERE b.uid > t.uid RETURN b",
            "UNWIND $rows AS r MATCH (a:Person {uid: r.src}), (b:Person {uid: r.dst}) \
             CREATE (a)-[:KNOWS]->(b)",
        ] {
            let logical = logical_of(src);
            let rule_based = plan_physical(&logical, &catalog);
            let cost_based = plan_physical_with_stats(&logical, &catalog, g.statistics());
            assert_eq!(
                rule_based.root, cost_based.root,
                "the cost-based optimiser must not disturb the correlated seek: {src}\n\
                 rule-based:\n{rule_based}\ncost-based:\n{cost_based}"
            );
            // And the seek is genuinely there (an equality anchor keeps its `NodeIndexSeek`; the
            // range anchor a `NodeIndexRangeSeek`) — neither reverted to a bare label scan.
            let rendered = cost_based.to_string();
            assert!(
                rendered.contains("IndexSeek") || rendered.contains("IndexRangeSeek"),
                "the correlated anchor stays a seek under cost-based planning: {src}\n{rendered}"
            );
        }
    }

    #[test]
    fn two_anchor_correlated_create_seeks_both_anchors() {
        // `rmp` task #708 / the #312 family: the two-anchor bulk-edge shape
        // `UNWIND rows AS r MATCH (a:Person {uid: r.src}), (b:Person {uid: r.dst}) CREATE (a)-[…]->(b)`
        // nests two correlated `Filter`-over-`Apply`s; BOTH anchors must become index seeks (turning
        // O(E·N) bulk-over-Cypher into O(E)). Exactly two seeks, zero label scans.
        let catalog = IndexCatalog::builder()
            .with_label_property("Person", "uid")
            .build();
        let plan = physical(
            "UNWIND $rows AS r MATCH (a:Person {uid: r.src}), (b:Person {uid: r.dst}) \
             CREATE (a)-[:KNOWS]->(b)",
            &catalog,
        );
        let rendered = plan.to_string();
        assert_eq!(
            rendered.matches("NodeIndexSeek").count(),
            2,
            "both anchors must seek the index:\n{rendered}"
        );
        assert!(
            !rendered.contains("NodeByLabelScan"),
            "neither anchor may fall back to a label scan:\n{rendered}"
        );
    }

    #[test]
    fn correlated_equality_on_unindexed_property_stays_a_scan() {
        // The lowering fires only when a `(label, property)` index exists; with NO index the
        // correlated anchor must remain a label scan (no phantom seek). Guards that the new path is
        // gated on `match_index`, never firing speculatively.
        let catalog = IndexCatalog::empty();
        let plan = physical(
            "UNWIND $rows AS t MATCH (b:Person {uid: t.uid}) RETURN b",
            &catalog,
        );
        let rendered = plan.to_string();
        assert!(
            !rendered.contains("NodeIndexSeek"),
            "no index ⇒ no seek:\n{rendered}"
        );
        assert!(
            rendered.contains("NodeByLabelScan") || rendered.contains("NodeLabelScanEq"),
            "the anchor stays a scan when unindexed:\n{rendered}"
        );
    }

    #[test]
    fn inline_property_equality_becomes_index_seek() {
        // The LDBC point-lookup shape (rmp #58): an inline `{id: x}` map is hoisted to an equality
        // filter by the logical planner and must use the index, recording the IndexId dependency.
        let catalog = IndexCatalog::builder()
            .with_label_property("Person", "id")
            .build();
        let plan = physical("MATCH (n:Person {id: 5}) RETURN n", &catalog);
        let rendered = plan.to_string();
        assert!(rendered.contains("NodeIndexSeek"), "{rendered}");
        assert!(!rendered.contains("NodeByLabelScan"), "{rendered}");
        assert_eq!(plan.index_dependencies().count(), 1);

        // Multi-key inline map: one key drives the seek, the rest stay a residual filter.
        let plan = physical("MATCH (n:Person {id: 5, name: 'x'}) RETURN n", &catalog);
        let rendered = plan.to_string();
        assert!(rendered.contains("NodeIndexSeek"), "{rendered}");
        assert!(rendered.contains("Filter"), "{rendered}");

        // The anchored end of an expand uses the seek too.
        let plan = physical("MATCH (a:Person {id: 5})-[:KNOWS]->(b) RETURN b", &catalog);
        assert!(plan.to_string().contains("NodeIndexSeek"), "{plan}");
    }

    #[test]
    fn composite_full_key_equality_becomes_one_composite_seek() {
        // `rmp` task #657: a composite index on (a, b) and a query with equality on BOTH keys must fuse
        // into ONE `NodeCompositeIndexSeek`, consuming both conjuncts (no residual Filter), whether the
        // predicate is spelled as an inline map or as `WHERE ... AND ...`, and in either conjunct order.
        let catalog = IndexCatalog::builder()
            .with_label_composite("Person", ["a", "b"])
            .build();

        for src in [
            "MATCH (n:Person {a: 1, b: 2}) RETURN n",
            "MATCH (n:Person) WHERE n.a = 1 AND n.b = 2 RETURN n",
            "MATCH (n:Person) WHERE n.b = 2 AND n.a = 1 RETURN n",
        ] {
            let plan = physical(src, &catalog);
            let rendered = plan.to_string();
            assert!(
                rendered.contains("NodeCompositeIndexSeek"),
                "{src}: {rendered}"
            );
            assert!(!rendered.contains("Filter"), "{src}: {rendered}");
            assert!(!rendered.contains("NodeByLabelScan"), "{src}: {rendered}");
            assert_eq!(plan.index_dependencies().count(), 1, "{src}");
        }

        // A third, non-covered equality conjunct stays a residual Filter above the composite seek.
        let plan = physical(
            "MATCH (n:Person) WHERE n.a = 1 AND n.b = 2 AND n.c = 3 RETURN n",
            &catalog,
        );
        let rendered = plan.to_string();
        assert!(rendered.contains("NodeCompositeIndexSeek"), "{rendered}");
        assert!(rendered.contains("Filter"), "{rendered}");
    }

    #[test]
    fn composite_leading_key_only_does_not_use_composite_seek() {
        // `rmp` task #657: a predicate on ONLY the leading key does not emit a composite seek — the
        // composite serves it as a single-property leading-prefix (existing `label_property` behaviour),
        // which lowers to a `NodeIndexSeek` on the leading key (the seam falls back to a scan for a
        // composite-only tree, but the PLAN shape is the single-key seek, never the composite seek).
        let catalog = IndexCatalog::builder()
            .with_label_composite("Person", ["a", "b"])
            .build();
        let plan = physical("MATCH (n:Person {a: 1}) RETURN n", &catalog);
        let rendered = plan.to_string();
        assert!(
            !rendered.contains("NodeCompositeIndexSeek"),
            "leading-only must not use the composite seek: {rendered}"
        );
        assert!(rendered.contains("NodeIndexSeek"), "{rendered}");
    }

    #[test]
    fn composite_non_leading_key_only_stays_a_filter() {
        // `rmp` task #657: a predicate on ONLY a non-leading key (`b`) cannot use the composite (the
        // leading key `a` is unbound) — it stays a scan + filter (the precise `NodeLabelScanEq` here,
        // since it is a single equality), never a composite or single-key seek.
        let catalog = IndexCatalog::builder()
            .with_label_composite("Person", ["a", "b"])
            .build();
        let plan = physical("MATCH (n:Person {b: 2}) RETURN n", &catalog);
        let rendered = plan.to_string();
        assert!(
            !rendered.contains("CompositeIndexSeek"),
            "non-leading-only must not use the composite seek: {rendered}"
        );
        assert!(!rendered.contains("NodeIndexSeek"), "{rendered}");
        // A single non-leading equality still narrows the SSI footprint via the precise scan path.
        assert!(rendered.contains("NodeLabelScanEq"), "{rendered}");
    }

    #[test]
    fn correlated_composite_anchor_becomes_one_composite_seek() {
        // `rmp` task #729 (composite follow-up to #708): a row-valued (correlated) FULL-composite anchor
        // — `UNWIND rows AS t MATCH (b:L {a: t.x, b: t.y})` over a composite `(a, b)` index — must lower
        // to ONE per-left-row `NodeCompositeIndexSeek` driven by a nested-loop join, consuming BOTH keys
        // (no residual Filter on a covered key), NOT to a leading-prefix `NodeIndexSeek` on `a` + a
        // residual `Filter` on `b` (the #708 shape, which degrades to an O(N)-per-row scan because a
        // composite-only store has no single-key tree). Every formulation the planner emits must hold.
        let catalog = IndexCatalog::builder()
            .with_label_composite("Account", ["tenant", "extid"])
            .build();

        for src in [
            "UNWIND $rows AS t MATCH (b:Account {tenant: t.tn, extid: t.ex}) RETURN b",
            "UNWIND $rows AS t MATCH (b:Account) WHERE b.tenant = t.tn AND b.extid = t.ex RETURN b",
            "UNWIND $rows AS t MATCH (b:Account) WHERE b.extid = t.ex AND b.tenant = t.tn RETURN b",
            "UNWIND $rows AS t WITH t.tn AS tn, t.ex AS ex \
             MATCH (b:Account {tenant: tn, extid: ex}) RETURN b",
        ] {
            let plan = physical(src, &catalog);
            let rendered = plan.to_string();
            assert!(
                rendered.contains("NodeCompositeIndexSeek"),
                "the correlated composite anchor must lower to a composite seek: {src}\n{rendered}"
            );
            assert!(
                !rendered.contains("NodeIndexSeek"),
                "it must NOT fall back to a leading-prefix single-key seek: {src}\n{rendered}"
            );
            assert!(
                !rendered.contains("NodeByLabelScan"),
                "it must NOT fall back to a label scan: {src}\n{rendered}"
            );
            assert!(
                !rendered.contains("Filter"),
                "both keys are consumed by the composite seek — no residual filter: {src}\n{rendered}"
            );
            assert!(
                rendered.contains("NestedLoopJoin"),
                "the composite seek is driven per-left-row by a nested-loop join: {src}\n{rendered}"
            );
            assert_eq!(
                plan.index_dependencies().count(),
                1,
                "the correlated composite seek records exactly its one IndexId dependency: {src}"
            );
        }
    }

    #[test]
    fn correlated_partial_composite_anchor_stays_a_leading_prefix_seek() {
        // `rmp` task #729: a PARTIAL correlated composite match (only the leading key `tenant` bound) must
        // NOT lower to a composite seek — `label_composite_full_eq` declines, and the single-property
        // #708 path serves `tenant` as a leading-prefix `NodeIndexSeek`, exactly as today. A correlated
        // equality on ONLY a non-leading key (`extid`) cannot use the composite at all (leading key
        // unbound) and stays the precise scan path. This pins the "full key required" boundary.
        let catalog = IndexCatalog::builder()
            .with_label_composite("Account", ["tenant", "extid"])
            .build();

        // Leading key only -> leading-prefix single-key seek, never a composite seek.
        let plan = physical(
            "UNWIND $rows AS t MATCH (b:Account {tenant: t.tn}) RETURN b",
            &catalog,
        );
        let rendered = plan.to_string();
        assert!(
            !rendered.contains("NodeCompositeIndexSeek"),
            "a partial (leading-only) match must NOT use the composite seek:\n{rendered}"
        );
        assert!(
            rendered.contains("NodeIndexSeek"),
            "the leading key falls back to a leading-prefix single-key seek:\n{rendered}"
        );

        // Non-leading key only -> no seek (leading key unbound); stays a scan.
        let plan = physical(
            "UNWIND $rows AS t MATCH (b:Account {extid: t.ex}) RETURN b",
            &catalog,
        );
        let rendered = plan.to_string();
        assert!(
            !rendered.contains("CompositeIndexSeek"),
            "a non-leading-only correlated match must NOT use the composite seek:\n{rendered}"
        );
        assert!(
            !rendered.contains("NodeIndexSeek"),
            "a non-leading-only correlated match has no leading key to seek:\n{rendered}"
        );
    }

    #[test]
    fn cost_based_optimizer_never_moves_or_reverts_the_correlated_composite_seek() {
        // `rmp` task #729: the correlated composite seek's per-key values are fed per driving row through
        // the nested-loop join, so the cost-based optimiser must treat it as immovable (never hoist it to
        // the OUTER side, where the keys would be unbound; never revert it to a scan). `contains_correlated_seek`
        // already covers `NodeCompositeIndexSeek.values`, so the cost-based tree must be byte-identical to
        // the rule-based one even with a large `:Account` count that would tempt a reorder.
        use crate::graph_access::{GraphAccess, MemGraph};
        use graphus_core::Value;

        let catalog = IndexCatalog::builder()
            .with_label_composite("Account", ["tenant", "extid"])
            .build();
        let mut g = MemGraph::new();
        for i in 0..2000 {
            g.add_node(
                ["Account"],
                [
                    ("tenant", Value::Integer(i % 4)),
                    ("extid", Value::Integer(i)),
                ],
            );
        }

        for src in [
            "UNWIND $rows AS t MATCH (b:Account {tenant: t.tn, extid: t.ex}) RETURN b",
            "UNWIND $rows AS r MATCH (a:Account {tenant: r.t1, extid: r.e1}), \
             (b:Account {tenant: r.t2, extid: r.e2}) CREATE (a)-[:LINKS]->(b)",
        ] {
            let logical = logical_of(src);
            let rule_based = plan_physical(&logical, &catalog);
            let cost_based = plan_physical_with_stats(&logical, &catalog, g.statistics());
            assert_eq!(
                rule_based.root, cost_based.root,
                "the cost-based optimiser must not disturb the correlated composite seek: {src}\n\
                 rule-based:\n{rule_based}\ncost-based:\n{cost_based}"
            );
            let rendered = cost_based.to_string();
            assert!(
                rendered.contains("NodeCompositeIndexSeek"),
                "the correlated composite anchor stays a composite seek under cost-based planning: \
                 {src}\n{rendered}"
            );
        }
    }

    #[test]
    fn two_anchor_correlated_composite_create_seeks_both_anchors() {
        // `rmp` task #729 / the #312 family: the two-anchor bulk-edge shape keyed on a COMPOSITE business
        // key — `UNWIND rows AS r MATCH (a:Account {tenant: r.t1, extid: r.e1}),
        // (b:Account {tenant: r.t2, extid: r.e2}) CREATE (a)-[…]->(b)` — nests two correlated
        // `Filter`-over-`Apply`s; BOTH anchors must become composite seeks (turning O(E·N) bulk-over-Cypher
        // into O(E)). Exactly two composite seeks, zero label scans, zero single-key seeks.
        let catalog = IndexCatalog::builder()
            .with_label_composite("Account", ["tenant", "extid"])
            .build();
        let plan = physical(
            "UNWIND $rows AS r MATCH (a:Account {tenant: r.t1, extid: r.e1}), \
             (b:Account {tenant: r.t2, extid: r.e2}) CREATE (a)-[:LINKS]->(b)",
            &catalog,
        );
        let rendered = plan.to_string();
        assert_eq!(
            rendered.matches("NodeCompositeIndexSeek").count(),
            2,
            "both anchors must seek the composite index:\n{rendered}"
        );
        assert!(
            !rendered.contains("NodeByLabelScan"),
            "neither anchor may fall back to a label scan:\n{rendered}"
        );
        assert!(
            !rendered.contains("NodeIndexSeek"),
            "neither anchor may fall back to a leading-prefix single-key seek:\n{rendered}"
        );
    }

    #[test]
    fn correlated_anchor_over_expand_seeks_through_the_traversal() {
        // `rmp` task #730 (the expand follow-up to #708). A correlated equality on a per-row anchor that
        // then EXPANDS — spelled as a `WHERE` *after* the pattern, so the anchor's `Apply` is buried
        // beneath the `Expand` — must push the anchor equality down onto the scan and lower it to a
        // per-row `NodeIndexSeek`, NOT a per-row label scan. Every driving row then seeks its anchor and
        // expands from it, turning O(N)-per-row into O(1)-per-row. Single hop, two hops, and a residual
        // predicate on the expand's target all hold.
        let catalog = IndexCatalog::builder()
            .with_label_property("Person", "uid")
            .build();

        for src in [
            "UNWIND $rows AS t MATCH (b:Person)-[:R]->(c) WHERE b.uid = t.uid RETURN c",
            "UNWIND $rows AS t MATCH (b:Person)<-[:R]-(c) WHERE b.uid = t.uid RETURN c",
            "UNWIND $rows AS t MATCH (b:Person)-[:R]->(c)-[:S]->(d) WHERE b.uid = t.uid RETURN d",
            "UNWIND $rows AS t MATCH (b:Person)-[:R]->(c) WHERE b.uid = t.uid AND c.k = 5 RETURN c",
        ] {
            let plan = physical(src, &catalog);
            let rendered = plan.to_string();
            assert!(
                rendered.contains("NodeIndexSeek(b:Person uid = t.uid"),
                "the anchor beneath the expand must seek per row: {src}\n{rendered}"
            );
            assert!(
                !rendered.contains("NodeByLabelScan"),
                "the anchor must NOT stay a label scan: {src}\n{rendered}"
            );
            assert!(
                rendered.contains("ExpandAll"),
                "the traversal still runs from each seeked anchor: {src}\n{rendered}"
            );
            assert_eq!(
                plan.index_dependencies().count(),
                1,
                "the pushed seek records its IndexId dependency: {src}"
            );
        }

        // The residual predicate on the expand's target survives as a Filter ABOVE the traversal.
        let plan = physical(
            "UNWIND $rows AS t MATCH (b:Person)-[:R]->(c) WHERE b.uid = t.uid AND c.k = 5 RETURN c",
            &catalog,
        );
        assert!(plan.to_string().contains("Filter"), "{plan}");
    }

    #[test]
    fn correlated_inline_anchor_over_expand_still_seeks() {
        // `rmp` task #730 regression LOCK for the FR's own example. The inline-anchor-map form —
        // `MATCH (b:L {uid: t.uid})-[:R]->(c)` — ALREADY seeks (the logical planner places its `Filter`
        // directly over the `Apply`, below the `Expand`, so #708 fires). #730 must not disturb that
        // already-working path: this pins it so a future change to the push-down cannot regress it.
        let catalog = IndexCatalog::builder()
            .with_label_property("Person", "uid")
            .build();
        for src in [
            "UNWIND $rows AS t MATCH (b:Person {uid: t.uid})-[:R]->(c) RETURN c",
            "UNWIND $rows AS t MATCH (b:Person {uid: t.uid})-[:R]->(c)-[:S]->(d) RETURN d",
            "UNWIND $rows AS t MATCH (b:Person {uid: t.uid}) MATCH (b)-[:R]->(c) RETURN c",
        ] {
            let plan = physical(src, &catalog);
            let rendered = plan.to_string();
            assert!(
                rendered.contains("NodeIndexSeek(b:Person uid = t.uid"),
                "the inline-anchor form must still seek: {src}\n{rendered}"
            );
            assert!(
                !rendered.contains("NodeByLabelScan"),
                "the inline-anchor form must not regress to a scan: {src}\n{rendered}"
            );
        }
    }

    #[test]
    fn correlated_anchor_over_expand_value_bound_by_expand_stays_a_scan() {
        // `rmp` task #730 — THE critical correctness bar (the disjointness guard has teeth). A predicate
        // whose value references a variable bound INSIDE the traversal (`c`, the expand's target, or `r`,
        // the relationship) must NOT be pushed to the anchor — at the anchor that variable is unbound, so
        // pushing it would change the result. It stays a scan + residual Filter above the expand.
        let catalog = IndexCatalog::builder()
            .with_label_property("Person", "uid")
            .build();

        for src in [
            // value references the expand's TARGET `c`
            "UNWIND $rows AS t MATCH (b:Person)-[:R]->(c) WHERE b.uid = c.uid RETURN c",
            // value references the RELATIONSHIP `r`
            "UNWIND $rows AS t MATCH (b:Person)-[r:R]->(c) WHERE b.uid = r.w RETURN c",
        ] {
            let plan = physical(src, &catalog);
            let rendered = plan.to_string();
            assert!(
                !rendered.contains("NodeIndexSeek"),
                "a value bound by the traversal must NOT be pushed to a seek: {src}\n{rendered}"
            );
            assert!(
                rendered.contains("NodeByLabelScan(b:Person)"),
                "the anchor stays a scan when the predicate is not pushable: {src}\n{rendered}"
            );
            assert!(
                rendered.contains("Filter"),
                "the un-pushable predicate stays a residual filter: {src}\n{rendered}"
            );
        }
    }

    #[test]
    fn correlated_composite_anchor_over_expand_seeks_the_composite() {
        // `rmp` task #730 + #729 (the two orthogonal axes composed): a correlated COMPOSITE anchor that
        // then EXPANDS, spelled as a `WHERE`, must push BOTH keys down and lower to a
        // `NodeCompositeIndexSeek` beneath the traversal — the composite fusion falls out of the
        // re-lowering for free (the push produces the exact `Filter(a AND b, Apply)` shape #729 lowers).
        let catalog = IndexCatalog::builder()
            .with_label_composite("Account", ["tenant", "extid"])
            .build();
        let plan = physical(
            "UNWIND $rows AS t MATCH (b:Account)-[:R]->(c) \
             WHERE b.tenant = t.tn AND b.extid = t.ex RETURN c",
            &catalog,
        );
        let rendered = plan.to_string();
        assert!(
            rendered.contains("NodeCompositeIndexSeek"),
            "the correlated composite anchor beneath an expand must seek the composite:\n{rendered}"
        );
        assert!(
            !rendered.contains("NodeByLabelScan"),
            "the anchor must not stay a label scan:\n{rendered}"
        );
        assert!(rendered.contains("ExpandAll"), "{rendered}");
    }

    #[test]
    fn cost_based_optimizer_keeps_the_pushed_through_expand_seek() {
        // `rmp` task #730: the pushed correlated seek is fed per driving row through the nested-loop
        // join, so the cost-based optimiser must treat it as immovable exactly as for #708/#729 — the
        // rule-based and cost-based trees must be byte-identical even with a large `:Person` count.
        use crate::graph_access::{GraphAccess, MemGraph};
        use graphus_core::Value;

        let catalog = IndexCatalog::builder()
            .with_label_property("Person", "uid")
            .build();
        let mut g = MemGraph::new();
        for i in 0..2000 {
            g.add_node(["Person"], [("uid", Value::Integer(i))]);
        }

        let src = "UNWIND $rows AS t MATCH (b:Person)-[:R]->(c) WHERE b.uid = t.uid RETURN c";
        let logical = logical_of(src);
        let rule_based = plan_physical(&logical, &catalog);
        let cost_based = plan_physical_with_stats(&logical, &catalog, g.statistics());
        assert_eq!(
            rule_based.root, cost_based.root,
            "the cost-based optimiser must not disturb the pushed-through-expand seek:\n\
             rule-based:\n{rule_based}\ncost-based:\n{cost_based}"
        );
        assert!(
            cost_based
                .to_string()
                .contains("NodeIndexSeek(b:Person uid = t.uid"),
            "the anchor stays a seek under cost-based planning:\n{cost_based}"
        );
    }

    #[test]
    fn rel_composite_full_key_equality_becomes_one_composite_rel_seek() {
        // `rmp` task #666: a composite relationship index on (a, b) and a query with equality on BOTH
        // keys must fuse into ONE `RelCompositeIndexSeek`, consuming both conjuncts (no residual Filter),
        // whether spelled as an inline map or `WHERE ... AND ...`, in either conjunct order and either
        // arrow direction.
        let catalog = IndexCatalog::builder()
            .with_rel_composite("KNOWS", ["a", "b"])
            .build();
        for src in [
            "MATCH ()-[r:KNOWS {a: 1, b: 2}]-() RETURN r",
            "MATCH ()-[r:KNOWS]-() WHERE r.a = 1 AND r.b = 2 RETURN r",
            "MATCH ()-[r:KNOWS]-() WHERE r.b = 2 AND r.a = 1 RETURN r",
            "MATCH (x)-[r:KNOWS {a: 1, b: 2}]->(y) RETURN r",
        ] {
            let plan = physical(src, &catalog);
            let rendered = plan.to_string();
            assert!(
                rendered.contains("RelCompositeIndexSeek"),
                "{src}: {rendered}"
            );
            assert!(!rendered.contains("Filter"), "{src}: {rendered}");
            assert!(!rendered.contains("ExpandAll"), "{src}: {rendered}");
            assert_eq!(plan.index_dependencies().count(), 1, "{src}");
        }

        // A third, non-covered equality conjunct stays a residual Filter above the composite seek.
        let plan = physical(
            "MATCH ()-[r:KNOWS]-() WHERE r.a = 1 AND r.b = 2 AND r.c = 3 RETURN r",
            &catalog,
        );
        let rendered = plan.to_string();
        assert!(rendered.contains("RelCompositeIndexSeek"), "{rendered}");
        assert!(rendered.contains("Filter"), "{rendered}");
    }

    #[test]
    fn rel_composite_leading_key_only_uses_single_rel_seek() {
        // `rmp` task #666: a predicate on ONLY the leading key does not emit a composite rel seek — the
        // composite serves it as a single-property leading-prefix, which lowers to a `RelIndexSeek` on
        // the leading key (the seam falls back to a scan for a composite-only tree, but the PLAN shape is
        // the single-key seek, never the composite seek).
        let catalog = IndexCatalog::builder()
            .with_rel_composite("KNOWS", ["a", "b"])
            .build();
        let plan = physical("MATCH ()-[r:KNOWS {a: 1}]-() RETURN r", &catalog);
        let rendered = plan.to_string();
        assert!(
            !rendered.contains("RelCompositeIndexSeek"),
            "leading-only must not use the composite seek: {rendered}"
        );
        assert!(rendered.contains("RelIndexSeek"), "{rendered}");
    }

    #[test]
    fn rel_composite_non_leading_key_only_stays_a_scan() {
        // `rmp` task #666: a predicate on ONLY a non-leading key (`b`) cannot use the composite (the
        // leading key `a` is unbound) — it stays a scan + filter, never a composite or single-key seek.
        let catalog = IndexCatalog::builder()
            .with_rel_composite("KNOWS", ["a", "b"])
            .build();
        let plan = physical("MATCH ()-[r:KNOWS {b: 2}]-() RETURN r", &catalog);
        let rendered = plan.to_string();
        assert!(!rendered.contains("RelCompositeIndexSeek"), "{rendered}");
        assert!(!rendered.contains("RelIndexSeek"), "{rendered}");
        assert!(rendered.contains("ExpandAll"), "{rendered}");
    }

    #[test]
    fn no_index_equality_uses_precise_scan_filter_eq() {
        // With no index, an EQUALITY predicate over a label scan lowers to the precise full-scan
        // access path `NodeLabelScanEq` (`rmp` task #325), NOT the bare `NodeByLabelScan` + `Filter`:
        // the precise path narrows the SSI read footprint to the matching rows. It declares no index
        // dependency (it is a full store scan), and no residual `Filter` remains (the single equality
        // conjunct is fully consumed by the access path).
        let catalog = IndexCatalog::empty();
        let plan = physical("MATCH (n:Person) WHERE n.age = 30 RETURN n", &catalog);
        let rendered = plan.to_string();
        assert!(rendered.contains("NodeLabelScanEq"), "{rendered}");
        assert!(!rendered.contains("NodeByLabelScan"), "{rendered}");
        assert!(!rendered.contains("NodeIndexSeek"), "{rendered}");
        assert!(!rendered.contains("Filter"), "{rendered}");
        assert_eq!(plan.index_dependencies().count(), 0);

        // The inline-map equality spelling lowers identically (it is the same `n.id = const` predicate).
        let plan = physical("MATCH (n:Person {id: 5}) RETURN n", &catalog);
        let rendered = plan.to_string();
        assert!(rendered.contains("NodeLabelScanEq"), "{rendered}");
        assert!(!rendered.contains("NodeByLabelScan"), "{rendered}");

        // A multi-conjunct equality keeps the extra conjuncts as a residual filter above the precise
        // equality scan (the equality is consumed, the rest re-attach).
        let plan = physical(
            "MATCH (n:Person) WHERE n.age = 30 AND n.name = 'x' RETURN n",
            &catalog,
        );
        let rendered = plan.to_string();
        assert!(rendered.contains("NodeLabelScanEq"), "{rendered}");
        assert!(rendered.contains("Filter"), "{rendered}");
    }

    #[test]
    fn no_index_non_equality_falls_back_to_label_scan_and_filter() {
        // A non-equality predicate (here a function-call condition that is neither an equality nor a
        // range/spatial property predicate) has no precise predicate marker to register, so it keeps
        // the bare `NodeByLabelScan` + residual `Filter` shape.
        let catalog = IndexCatalog::empty();
        let plan = physical(
            "MATCH (n:Person) WHERE toUpper(n.name) = 'X' RETURN n",
            &catalog,
        );
        let rendered = plan.to_string();
        assert!(rendered.contains("NodeByLabelScan"), "{rendered}");
        assert!(rendered.contains("Filter"), "{rendered}");
        assert!(!rendered.contains("Seek"), "{rendered}");
        assert!(!rendered.contains("NodeLabelScanEq"), "{rendered}");
        assert_eq!(plan.index_dependencies().count(), 0);
    }

    #[test]
    fn range_predicate_becomes_range_seek() {
        let catalog = IndexCatalog::builder()
            .with_label_property("Person", "age")
            .build();
        let plan = physical("MATCH (n:Person) WHERE n.age > 18 RETURN n", &catalog);
        assert!(plan.to_string().contains("NodeIndexRangeSeek"), "{plan}");
    }

    #[test]
    fn proximity_on_spatial_indexed_property_becomes_spatial_seek() {
        // `rmp` task #73: a `distance(n.loc, <const point>) < r` predicate over a `(label, property)`
        // that has a spatial index lowers to a `SpatialIndexSeek` — with the exact `distance` predicate
        // RETAINED as a residual `Filter` (the grid is a geometric superset, so the filter restores
        // exactness).
        let catalog = IndexCatalog::builder()
            .with_label_spatial("City", "loc")
            .build();
        let plan = physical(
            "MATCH (n:City) WHERE distance(n.loc, point({x:0, y:0})) < 5 RETURN n",
            &catalog,
        );
        let rendered = plan.to_string();
        assert!(rendered.contains("SpatialIndexSeek"), "{rendered}");
        // The exact predicate is re-checked above the seek (never dropped).
        assert!(rendered.contains("Filter"), "{rendered}");
        assert!(rendered.contains("distance"), "{rendered}");
        assert!(!rendered.contains("NodeByLabelScan"), "{rendered}");
        assert_eq!(plan.index_dependencies().count(), 1);
    }

    #[test]
    fn text_predicates_on_text_indexed_property_become_text_seek_with_retained_residual() {
        // `rmp` task #662: with a TEXT index on `(Person, name)`, each of CONTAINS / ENDS WITH /
        // STARTS WITH lowers to a `NodeTextIndexSeek` — with the exact predicate RETAINED as a residual
        // `Filter` (the trigram index is a candidate superset, so the filter restores exactness).
        let catalog = IndexCatalog::builder()
            .with_label_text("Person", "name")
            .build();
        for (pred, needle) in [
            ("CONTAINS", "'ob'"),
            ("ENDS WITH", "'son'"),
            ("STARTS WITH", "'Ro'"),
        ] {
            let q = format!("MATCH (n:Person) WHERE n.name {pred} {needle} RETURN n");
            let plan = physical(&q, &catalog);
            let rendered = plan.to_string();
            assert!(rendered.contains("NodeTextIndexSeek"), "{pred}: {rendered}");
            // The exact predicate is re-checked above the seek (never dropped).
            assert!(rendered.contains("Filter"), "{pred}: {rendered}");
            assert!(rendered.contains(pred), "{pred}: {rendered}");
            assert!(!rendered.contains("NodeByLabelScan"), "{pred}: {rendered}");
            assert_eq!(plan.index_dependencies().count(), 1, "{pred}");
        }
    }

    #[test]
    fn text_predicates_without_text_index_stay_scan_and_filter() {
        // `rmp` task #662: without a TEXT index, CONTAINS / ENDS WITH keep the bare label scan + filter
        // (a range index cannot serve substring/suffix). A RANGE index on the same property does NOT
        // make them a text seek.
        let catalog = IndexCatalog::builder()
            .with_label_property("Person", "name")
            .build();
        for pred in ["CONTAINS", "ENDS WITH"] {
            let q = format!("MATCH (n:Person) WHERE n.name {pred} 'x' RETURN n");
            let plan = physical(&q, &catalog);
            let rendered = plan.to_string();
            assert!(rendered.contains("NodeByLabelScan"), "{pred}: {rendered}");
            assert!(rendered.contains("Filter"), "{pred}: {rendered}");
            assert!(!rendered.contains("TextIndexSeek"), "{pred}: {rendered}");
        }
    }

    #[test]
    fn starts_with_prefers_text_index_over_range_prefix_seek() {
        // `rmp` task #662: when BOTH a TEXT and a RANGE index cover `(label, property)`, `STARTS WITH`
        // routes to the TEXT seek (checked first). With only a RANGE index it stays the #658 prefix seek.
        let both = IndexCatalog::builder()
            .with_label_property("Person", "name")
            .with_label_text("Person", "name")
            .build();
        let plan = physical(
            "MATCH (n:Person) WHERE n.name STARTS WITH 'Ro' RETURN n",
            &both,
        );
        let rendered = plan.to_string();
        assert!(rendered.contains("NodeTextIndexSeek"), "{rendered}");
        assert!(!rendered.contains("NodeIndexStartsWithSeek"), "{rendered}");

        let range_only = IndexCatalog::builder()
            .with_label_property("Person", "name")
            .build();
        let plan = physical(
            "MATCH (n:Person) WHERE n.name STARTS WITH 'Ro' RETURN n",
            &range_only,
        );
        let rendered = plan.to_string();
        assert!(rendered.contains("NodeIndexStartsWithSeek"), "{rendered}");
        assert!(!rendered.contains("NodeTextIndexSeek"), "{rendered}");
    }

    #[test]
    fn proximity_recognises_symmetric_namespaced_and_lte_forms() {
        // `rmp` task #73: the symmetric argument order, the namespaced `point.distance(...)` function,
        // and the `<=` bound all drive the spatial seek (centre and radius are still plan-time
        // constants).
        let catalog = IndexCatalog::builder()
            .with_label_spatial("City", "loc")
            .build();
        // Symmetric: const point as the FIRST argument.
        let plan = physical(
            "MATCH (n:City) WHERE distance(point({x:1, y:2}), n.loc) < 3 RETURN n",
            &catalog,
        );
        assert!(plan.to_string().contains("SpatialIndexSeek"), "{plan}");
        // `<=` bound.
        let plan = physical(
            "MATCH (n:City) WHERE distance(n.loc, point({x:0, y:0})) <= 5 RETURN n",
            &catalog,
        );
        assert!(plan.to_string().contains("SpatialIndexSeek"), "{plan}");
        // The namespaced `point.distance(...)` spelling.
        let plan = physical(
            "MATCH (n:City) WHERE point.distance(n.loc, point({x:0, y:0})) < 5 RETURN n",
            &catalog,
        );
        assert!(plan.to_string().contains("SpatialIndexSeek"), "{plan}");
    }

    #[test]
    fn proximity_without_spatial_index_falls_back_to_scan_filter() {
        // No spatial index declared: the proximity predicate stays a residual `Filter` over a label
        // scan (still correct, just not index-accelerated) — never a seek.
        let catalog = IndexCatalog::empty();
        let plan = physical(
            "MATCH (n:City) WHERE distance(n.loc, point({x:0, y:0})) < 5 RETURN n",
            &catalog,
        );
        let rendered = plan.to_string();
        assert!(rendered.contains("NodeByLabelScan"), "{rendered}");
        assert!(rendered.contains("Filter"), "{rendered}");
        assert!(!rendered.contains("SpatialIndexSeek"), "{rendered}");
        assert_eq!(plan.index_dependencies().count(), 0);
    }

    #[test]
    fn proximity_on_geographic_crs_declines_the_spatial_seek() {
        // `rmp` #465 (CRITICAL regression gate): a geographic (WGS-84) centre measures `distance` in
        // great-circle metres while the grid buckets the projection in coordinate degrees, so a
        // degree-sized bbox cannot bound a metric radius near the antimeridian/poles — the grid would
        // silently drop true matches. The planner MUST decline the spatial seek for a geographic centre
        // and keep the exact predicate on the scan path (scan == the correct answer), even when a
        // spatial index is declared. The Cartesian sibling MUST still use the index (contrast).
        let catalog = IndexCatalog::builder()
            .with_label_spatial("City", "loc")
            .build();
        // WGS-84 centre (longitude/latitude keys → geographic CRS): NO seek, scan + Filter.
        let geo = physical(
            "MATCH (n:City) WHERE distance(n.loc, point({longitude:0, latitude:0})) < 5 RETURN n",
            &catalog,
        );
        let geo_s = geo.to_string();
        assert!(
            !geo_s.contains("SpatialIndexSeek"),
            "geographic CRS must NOT use the spatial seek: {geo_s}"
        );
        assert!(geo_s.contains("NodeByLabelScan"), "{geo_s}");
        assert!(geo_s.contains("Filter"), "{geo_s}");
        assert!(geo_s.contains("distance"), "{geo_s}");
        assert_eq!(geo.index_dependencies().count(), 0);
        // Contrast: the Cartesian centre over the SAME indexed property still lowers to a seek.
        let cart = physical(
            "MATCH (n:City) WHERE distance(n.loc, point({x:0, y:0})) < 5 RETURN n",
            &catalog,
        );
        assert!(
            cart.to_string().contains("SpatialIndexSeek"),
            "Cartesian CRS must still use the spatial seek: {cart}"
        );
    }

    #[test]
    fn proximity_with_non_constant_operands_declines_the_seek() {
        // The centre / radius must be plan-time constants: a `>`/`>=` (unbounded) proximity, a
        // non-constant radius, or a property-referencing centre all keep the scan + filter, never a
        // spatial seek (`rmp` task #73).
        let catalog = IndexCatalog::builder()
            .with_label_spatial("City", "loc")
            .build();
        // `>` is unbounded — not a grid proximity query.
        let plan = physical(
            "MATCH (n:City) WHERE distance(n.loc, point({x:0, y:0})) > 5 RETURN n",
            &catalog,
        );
        assert!(!plan.to_string().contains("SpatialIndexSeek"), "{plan}");
        // A radius that references the row is not a constant.
        let plan = physical(
            "MATCH (n:City) WHERE distance(n.loc, point({x:0, y:0})) < n.r RETURN n",
            &catalog,
        );
        assert!(!plan.to_string().contains("SpatialIndexSeek"), "{plan}");
    }

    #[test]
    fn relationship_proximity_lowers_to_rel_spatial_seek() {
        // `rmp` task #664: a standalone single-type fixed-length relationship pattern with a Cartesian
        // proximity predicate on the relationship variable, over a declared relationship spatial index,
        // lowers to a `RelSpatialIndexSeek` — the relationship analogue of the node `SpatialIndexSeek`.
        // The exact `distance` predicate is retained as a residual Filter (the grid is a superset).
        let catalog = IndexCatalog::builder()
            .with_rel_spatial("VISITED", "at")
            .build();
        for pattern in [
            "()-[r:VISITED]->()",
            "()<-[r:VISITED]-()",
            "()-[r:VISITED]-()",
        ] {
            let q =
                format!("MATCH {pattern} WHERE distance(r.at, point({{x:0, y:0}})) <= 5 RETURN r");
            let plan = physical(&q, &catalog);
            let rendered = plan.to_string();
            assert!(
                rendered.contains("RelSpatialIndexSeek"),
                "pattern {pattern}: {rendered}"
            );
            // The exact predicate is re-checked above the seek (never dropped), and the whole
            // Filter-over-Expand-over-AllNodesScan subtree is replaced (no bare AllNodesScan anchor).
            assert!(rendered.contains("Filter"), "{rendered}");
            assert!(rendered.contains("distance"), "{rendered}");
            assert!(!rendered.contains("ExpandAll"), "{rendered}");
            assert_eq!(plan.index_dependencies().count(), 1);
        }
        // The namespaced spelling + symmetric argument order also drive the seek.
        let plan = physical(
            "MATCH ()-[r:VISITED]-() WHERE point.distance(point({x:0, y:0}), r.at) < 3 RETURN r",
            &catalog,
        );
        assert!(plan.to_string().contains("RelSpatialIndexSeek"), "{plan}");
    }

    #[test]
    fn relationship_proximity_without_index_stays_scan_filter() {
        // `rmp` task #664: without a relationship spatial index the proximity predicate stays a residual
        // Filter over the Expand — never a `RelSpatialIndexSeek`. (A relationship-PROPERTY index on the
        // same key does NOT make it a spatial seek either.)
        for catalog in [
            IndexCatalog::empty(),
            IndexCatalog::builder()
                .with_rel_property("VISITED", "at")
                .build(),
        ] {
            let plan = physical(
                "MATCH ()-[r:VISITED]-() WHERE distance(r.at, point({x:0, y:0})) < 5 RETURN r",
                &catalog,
            );
            let rendered = plan.to_string();
            assert!(!rendered.contains("RelSpatialIndexSeek"), "{rendered}");
            assert!(rendered.contains("ExpandAll"), "{rendered}");
            assert!(rendered.contains("Filter"), "{rendered}");
        }
    }

    #[test]
    fn relationship_proximity_on_geographic_crs_declines_the_seek() {
        // `rmp` #664 / #465: a geographic (WGS-84) centre measures `distance` in metres while the grid
        // buckets degrees, so the relationship spatial seek MUST decline for a geographic centre (exactly
        // like the node seek) and keep the exact predicate on the scan path. The Cartesian sibling over
        // the same indexed key MUST still use the seek (contrast).
        let catalog = IndexCatalog::builder()
            .with_rel_spatial("VISITED", "at")
            .build();
        let geo = physical(
            "MATCH ()-[r:VISITED]-() WHERE distance(r.at, point({longitude:0, latitude:0})) < 5 RETURN r",
            &catalog,
        );
        let geo_s = geo.to_string();
        assert!(
            !geo_s.contains("RelSpatialIndexSeek"),
            "geographic: {geo_s}"
        );
        assert!(geo_s.contains("ExpandAll"), "{geo_s}");
        assert_eq!(geo.index_dependencies().count(), 0);
        let cart = physical(
            "MATCH ()-[r:VISITED]-() WHERE distance(r.at, point({x:0, y:0})) < 5 RETURN r",
            &catalog,
        );
        assert!(
            cart.to_string().contains("RelSpatialIndexSeek"),
            "Cartesian: {cart}"
        );
    }

    #[test]
    fn relationship_proximity_bbox_and_multi_type_and_labeled_anchor_decline() {
        // `rmp` task #664: shapes that do NOT lower to a relationship spatial seek — a `point.withinBBox`
        // predicate (the grid seek serves only upper-bounded `distance`, exactly like the node seek), a
        // multi-type pattern (no single-type index), and a label-constrained anchor (not a bare
        // AllNodesScan) — each keep the scan + filter.
        let catalog = IndexCatalog::builder()
            .with_rel_spatial("VISITED", "at")
            .build();
        // bbox: not an upper-bounded distance, so it stays scan + filter.
        let bbox = physical(
            "MATCH ()-[r:VISITED]-() \
             WHERE point.withinBBox(r.at, point({x:0, y:0}), point({x:9, y:9})) RETURN r",
            &catalog,
        );
        assert!(
            !bbox.to_string().contains("RelSpatialIndexSeek"),
            "bbox: {bbox}"
        );
        // multi-type: no single-type relationship spatial index applies.
        let multi = physical(
            "MATCH ()-[r:VISITED|RATED]-() WHERE distance(r.at, point({x:0, y:0})) < 5 RETURN r",
            &catalog,
        );
        assert!(
            !multi.to_string().contains("RelSpatialIndexSeek"),
            "multi-type: {multi}"
        );
        // labeled anchor: the anchor lowers to a NodeByLabelScan, not a bare AllNodesScan.
        let labeled = physical(
            "MATCH (a:P)-[r:VISITED]-() WHERE distance(r.at, point({x:0, y:0})) < 5 RETURN r",
            &catalog,
        );
        assert!(
            !labeled.to_string().contains("RelSpatialIndexSeek"),
            "labeled anchor: {labeled}"
        );
    }

    #[test]
    fn limit_over_sort_is_topn() {
        let catalog = IndexCatalog::empty();
        let plan = physical("MATCH (n) RETURN n ORDER BY n.age LIMIT 3", &catalog);
        assert!(plan.to_string().contains("TopN"), "{plan}");
    }

    #[test]
    fn limit_not_pushed_below_distinct() {
        let catalog = IndexCatalog::empty();
        let plan = physical("MATCH (n) RETURN DISTINCT n.age LIMIT 3", &catalog);
        let rendered = plan.to_string();
        // The Limit stays above the DISTINCT projection (not pushed below it).
        let limit_at = rendered.find("Limit").expect("has Limit");
        let proj_at = rendered
            .find("Projection DISTINCT")
            .expect("has DISTINCT proj");
        assert!(
            limit_at < proj_at,
            "Limit must be above DISTINCT: {rendered}"
        );
    }

    // ---- (A) existence via a full property-index scan (`rmp` task #665) -----------------------

    #[test]
    fn is_not_null_over_an_indexed_property_plans_a_node_index_scan_with_retained_residual() {
        let catalog = IndexCatalog::builder()
            .with_label_property("Person", "email")
            .build();
        let plan = physical(
            "MATCH (n:Person) WHERE n.email IS NOT NULL RETURN n",
            &catalog,
        );
        let rendered = plan.to_string();
        // The existence predicate is served by the index scan, not a full label scan.
        assert!(
            rendered.contains("NodeIndexScan(n:Person email"),
            "IS NOT NULL over an indexed property must plan a NodeIndexScan:\n{rendered}"
        );
        assert!(
            !rendered.contains("NodeByLabelScan"),
            "must not fall back to a bare label scan:\n{rendered}"
        );
        // The exact predicate is retained as a residual Filter above the scan (an index entry can be
        // stale, and the scan-fallback path is a full label scan that the filter trims).
        let filter_at = rendered.find("Filter").expect("residual filter present");
        let scan_at = rendered.find("NodeIndexScan").expect("scan present");
        assert!(
            filter_at < scan_at,
            "the residual IS NOT NULL Filter must sit above the NodeIndexScan:\n{rendered}"
        );
    }

    #[test]
    fn is_not_null_without_an_index_stays_scan_plus_filter() {
        // No index on `(Person, email)`: the existence predicate stays a full label scan + filter.
        let plan = physical(
            "MATCH (n:Person) WHERE n.email IS NOT NULL RETURN n",
            &IndexCatalog::empty(),
        );
        let rendered = plan.to_string();
        assert!(
            !rendered.contains("NodeIndexScan"),
            "an unindexed property must not plan a NodeIndexScan:\n{rendered}"
        );
        assert!(
            rendered.contains("NodeByLabelScan(n:Person)"),
            "an unindexed existence predicate stays a label scan + filter:\n{rendered}"
        );
    }

    #[test]
    fn is_null_never_uses_an_index_scan() {
        // An index witnesses *presence*, never *absence*: `IS NULL` must stay a scan + filter even
        // when `(Person, email)` is indexed.
        let catalog = IndexCatalog::builder()
            .with_label_property("Person", "email")
            .build();
        let plan = physical("MATCH (n:Person) WHERE n.email IS NULL RETURN n", &catalog);
        let rendered = plan.to_string();
        assert!(
            !rendered.contains("NodeIndexScan"),
            "IS NULL cannot be served by an index scan:\n{rendered}"
        );
        assert!(
            rendered.contains("NodeByLabelScan(n:Person)"),
            "IS NULL stays a label scan + filter:\n{rendered}"
        );
    }

    #[test]
    fn is_not_null_yields_to_a_more_selective_equality_seek() {
        // A same-filter equality on an indexed property must still drive the (more selective) seek,
        // with the existence predicate demoted to a residual filter.
        let catalog = IndexCatalog::builder()
            .with_label_property("Person", "email")
            .with_label_property("Person", "age")
            .build();
        let plan = physical(
            "MATCH (n:Person) WHERE n.email IS NOT NULL AND n.age = 30 RETURN n",
            &catalog,
        );
        let rendered = plan.to_string();
        assert!(
            rendered.contains("NodeIndexSeek(n:Person age = "),
            "the equality seek must win over the existence scan:\n{rendered}"
        );
        assert!(
            !rendered.contains("NodeIndexScan"),
            "a selective equality seek preempts the existence scan:\n{rendered}"
        );
    }

    // ---- (B) provided-order Sort elision (`rmp` task #665) ------------------------------------

    #[test]
    fn order_by_indexed_range_key_elides_the_sort() {
        let catalog = IndexCatalog::builder()
            .with_label_property("Person", "age")
            .build();
        let plan = physical(
            "MATCH (n:Person) WHERE n.age > 0 RETURN n ORDER BY n.age",
            &catalog,
        );
        let rendered = plan.to_string();
        // The range seek already visits keys in ascending order, so the Sort is elided and the seek is
        // marked ordered.
        assert!(
            !rendered.contains("Sort"),
            "ORDER BY on the range-seek key must elide the Sort:\n{rendered}"
        );
        assert!(
            rendered.contains("NodeIndexRangeSeek(n:Person age > ")
                && rendered.contains("ordered asc"),
            "the range seek must be marked ordered:\n{rendered}"
        );
    }

    #[test]
    fn order_by_indexed_existence_scan_key_elides_the_sort() {
        // The same provided-order elision applies over a NodeIndexScan (IS NOT NULL).
        let catalog = IndexCatalog::builder()
            .with_label_property("Person", "age")
            .build();
        let plan = physical(
            "MATCH (n:Person) WHERE n.age IS NOT NULL RETURN n ORDER BY n.age",
            &catalog,
        );
        let rendered = plan.to_string();
        assert!(
            !rendered.contains("Sort"),
            "ORDER BY on the index-scan key must elide the Sort:\n{rendered}"
        );
        assert!(
            rendered.contains("NodeIndexScan(n:Person age") && rendered.contains("ordered asc"),
            "the index scan must be marked ordered:\n{rendered}"
        );
    }

    #[test]
    fn order_by_desc_keeps_the_sort() {
        // ASC-only: a descending order would need a reverse scan (a documented follow-up).
        let catalog = IndexCatalog::builder()
            .with_label_property("Person", "age")
            .build();
        let plan = physical(
            "MATCH (n:Person) WHERE n.age > 0 RETURN n ORDER BY n.age DESC",
            &catalog,
        );
        let rendered = plan.to_string();
        assert!(
            rendered.contains("Sort"),
            "ORDER BY DESC must keep the Sort (no reverse scan yet):\n{rendered}"
        );
        assert!(
            !rendered.contains("ordered asc"),
            "the seek must not be marked ordered for a DESC order:\n{rendered}"
        );
    }

    #[test]
    fn order_by_a_non_index_key_keeps_the_sort() {
        // The seek orders by `age`; an ORDER BY on a different property is not provided by it.
        let catalog = IndexCatalog::builder()
            .with_label_property("Person", "age")
            .build();
        let plan = physical(
            "MATCH (n:Person) WHERE n.age > 0 RETURN n ORDER BY n.name",
            &catalog,
        );
        let rendered = plan.to_string();
        assert!(
            rendered.contains("Sort"),
            "ORDER BY a non-index key must keep the Sort:\n{rendered}"
        );
        assert!(
            !rendered.contains("ordered asc"),
            "the seek must not be marked ordered for a different key:\n{rendered}"
        );
    }

    #[test]
    fn multi_key_order_by_keeps_the_sort() {
        // A multi-key ORDER BY is not served by a single-key index order.
        let catalog = IndexCatalog::builder()
            .with_label_property("Person", "age")
            .build();
        let plan = physical(
            "MATCH (n:Person) WHERE n.age > 0 RETURN n ORDER BY n.age, n.name",
            &catalog,
        );
        let rendered = plan.to_string();
        assert!(
            rendered.contains("Sort"),
            "a multi-key ORDER BY must keep the Sort:\n{rendered}"
        );
        assert!(
            !rendered.contains("ordered asc"),
            "the seek must not be marked ordered for a multi-key order:\n{rendered}"
        );
    }
}
