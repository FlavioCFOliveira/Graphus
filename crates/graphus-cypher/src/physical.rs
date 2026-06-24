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
//! **range** node predicates, the **token-lookup** label scan, and single-property **relationship**
//! predicates routed through the catalog.
//!
//! **Cost-based (task #65), only when statistics are supplied:** selectivity-driven **access-path
//! choice** (index seek vs label/token scan, [the seek-vs-scan rule](self#cost-based-optimisation)),
//! **inner-join reordering** and **hash-join build-side selection** over independent, write-free join
//! regions (System-R-style bottom-up dynamic programming). Expand direction stays the rule-based
//! choice — the logical plan fixes the traversal anchor, so a cost-based *reversal* is out of scope.
//!
//! **Deferred, by name:** (1) **multi-predicate composite-index seeds** beyond a single leading-key
//! predicate, and general predicate pushdown (`04 §6.6`); (2) **`AllRelationshipsScan` index
//! routing** — a relationship-type-only scan keeps its logical form (the relationship-property seek
//! requires a property predicate, lowered when a [`Filter`] supplies one over an expand, which is
//! itself later territory); (3) **composite multi-key seeks** — only a composite's *leading* key
//! drives a seek here, matching the catalog's
//! [`label_property`](crate::catalog::IndexCatalog::label_property) contract; (4) **`IN`-list /
//! `STARTS WITH` index acceleration** — treated as residual filters in v1.
//!
//! # Cost-based optimisation
//!
//! [`plan_physical_with_stats`] with `stats = Some(..)` runs the rule-based planner, then a single
//! bottom-up optimisation pass over the resulting tree, applying two families of bag-preserving
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
//!
//! The optimiser recurses into every operand and child, so both rewrites apply throughout the tree.
//! Cost ties break on a stable structural key, so plan choice is deterministic for fixed statistics.

use crate::ast::{BinaryOp, Expr, ExprKind, Label, RelType};
use crate::cardinality::estimate_rows;
use crate::catalog::{IndexCatalog, IndexDescriptor, IndexId};
use crate::cost::estimate_cost;
use crate::logical::{
    CreatePart, LogicalOp, ProjectionColumn, RemoveOp, SetOp, SortKey, Var, YieldColumn,
};
use crate::statistics::Statistics;
use graphus_core::Value;
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
}

impl PhysicalPlan {
    /// The catalog [`IndexId`]s this plan depends on, ascending (`04 §6.6`).
    ///
    /// A change to any of these indexes (or a `schema_version` bump) must invalidate the cached
    /// plan ([`crate::plan_cache`]).
    pub fn index_dependencies(&self) -> impl Iterator<Item = IndexId> + '_ {
        self.index_dependencies.iter().copied()
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
/// * With **`stats = None`** this is exactly [`plan_physical`]: the rule-based operator tree, the
///   recorded index dependencies, and the result set are byte-for-byte identical, and the estimate
///   uses the estimator's documented constant fallbacks.
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
pub fn plan_physical_with_stats(
    logical: &LogicalOp,
    catalog: &IndexCatalog,
    stats: Option<&dyn Statistics>,
) -> PhysicalPlan {
    let estimated_rows = estimate_rows(logical, stats);
    let mut deps = BTreeSet::new();
    let rule_based = Planner { catalog }.lower(logical, &mut deps);

    // With statistics, refine the rule-based tree by the cost model; without, keep it verbatim (this
    // is exactly `plan_physical`, byte-for-byte). The optimiser is bag-preserving, so only the shape
    // changes — and the index dependencies are recomputed from the final tree it produces.
    let (root, index_dependencies) = match stats {
        Some(s) => {
            let optimized = optimize(rule_based, catalog, s);
            let deps = collect_index_dependencies(&optimized);
            (optimized, deps)
        }
        None => (rule_based, deps),
    };

    PhysicalPlan {
        root,
        index_dependencies,
        estimated_rows,
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
        // Index selection only fires directly over a label scan (the logical anchor of a labelled
        // node). Anything else: lower the input normally and keep the predicate as a residual filter.
        let LogicalOp::NodeByLabelScan { variable, label } = input else {
            return PhysicalOp::Filter {
                input: Box::new(self.lower(input, deps)),
                predicate: predicate.clone(),
            };
        };

        let conjuncts = split_conjuncts(predicate);
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

        // No index and no equality predicate: label scan (possibly token-lookup) + the full predicate as
        // a filter.
        let scan = self.lower_label_scan(variable, label, deps);
        PhysicalOp::Filter {
            input: Box::new(scan),
            predicate: predicate.clone(),
        }
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
        | PhysicalOp::NodeLabelScanEq { .. }
        | PhysicalOp::NodeIndexRangeSeek { .. }
        | PhysicalOp::SpatialIndexSeek { .. }
        | PhysicalOp::AllRelationshipsScan { .. }
        | PhysicalOp::ExpandAll { .. }
        | PhysicalOp::ExpandInto { .. }
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
        | PhysicalOp::NodeLabelScanEq { .. }
        | PhysicalOp::NodeIndexRangeSeek { .. }
        | PhysicalOp::SpatialIndexSeek { .. }
        | PhysicalOp::AllRelationshipsScan { .. }
        | PhysicalOp::Argument { .. }
        | PhysicalOp::Empty => false,
    }
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
/// enumeration), so a hard cap keeps planning time bounded on pathological inputs. Above the cap the
/// region falls back to the rule-based (already-correct) order for that region — the result bag is
/// identical, only the (un-optimised) shape differs. `10` operands ≈ 59 049 subset visits, a
/// comfortable ceiling for interactive planning; real queries rarely approach it.
const MAX_JOIN_REGION_OPERANDS: usize = 10;

/// Rewrites the rule-based physical tree `op` into a cost-minimised, bag-equivalent tree, using
/// `catalog` for access-path alternatives and `stats` for the cost model.
///
/// The recursion optimises children first (so costs are measured over already-optimised inputs), then
/// applies, at this node: **(B)** cost-based access-path selection for a seek / scan-filter site, and
/// **(A)** join-region reordering + build-side selection when the node roots a reorderable join
/// region. Operators that are neither keep their rule-based form with optimised children.
fn optimize(op: PhysicalOp, catalog: &IndexCatalog, stats: &dyn Statistics) -> PhysicalOp {
    // First, optimise all children (bottom-up): the cost of a parent depends on its inputs' shapes.
    let op = optimize_children(op, catalog, stats);

    // (B) Access-path selection: a seek the rule-based planner chose may lose to a scan when the
    // predicate is non-selective; a scan+filter may win back a seek when selective. Handled at the
    // seek node and at the filter-over-scan node.
    let op = optimize_access_path(op, catalog, stats);

    // (A) Join reordering: if this node roots a maximal reorderable join region, flatten and re-plan
    // it by bottom-up DP. (If it is not such a region root, this is a no-op returning `op`.)
    optimize_join_region(op, stats)
}

/// Optimises every child subtree of `op` in place, leaving `op`'s own shape untouched. The single
/// place the recursion descends, so each operator variant lists its children exactly once.
fn optimize_children(op: PhysicalOp, catalog: &IndexCatalog, stats: &dyn Statistics) -> PhysicalOp {
    let opt = |b: Box<PhysicalOp>| Box::new(optimize(*b, catalog, stats));
    match op {
        // Leaves: nothing to descend into.
        PhysicalOp::AllNodesScan { .. }
        | PhysicalOp::NodeByLabelScan { .. }
        | PhysicalOp::TokenLookupScan { .. }
        | PhysicalOp::NodeIndexSeek { .. }
        | PhysicalOp::NodeLabelScanEq { .. }
        | PhysicalOp::NodeIndexRangeSeek { .. }
        | PhysicalOp::SpatialIndexSeek { .. }
        | PhysicalOp::AllRelationshipsScan { .. }
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
            input: opt(input),
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
            input: opt(input),
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
            input: opt(input),
            from,
            to,
            relationship,
            path,
            direction,
            types,
            range,
            all,
        },
        PhysicalOp::NamedPath {
            input,
            variable,
            start,
            steps,
        } => PhysicalOp::NamedPath {
            input: opt(input),
            variable,
            start,
            steps,
        },
        PhysicalOp::Filter { input, predicate } => PhysicalOp::Filter {
            input: opt(input),
            predicate,
        },
        PhysicalOp::Projection {
            input,
            items,
            distinct,
        } => PhysicalOp::Projection {
            input: opt(input),
            items,
            distinct,
        },
        PhysicalOp::Aggregation {
            input,
            group_keys,
            aggregates,
        } => PhysicalOp::Aggregation {
            input: opt(input),
            group_keys,
            aggregates,
        },
        PhysicalOp::Sort { input, keys } => PhysicalOp::Sort {
            input: opt(input),
            keys,
        },
        PhysicalOp::TopN { input, keys, limit } => PhysicalOp::TopN {
            input: opt(input),
            keys,
            limit,
        },
        PhysicalOp::Skip { input, count } => PhysicalOp::Skip {
            input: opt(input),
            count,
        },
        PhysicalOp::Limit { input, count } => PhysicalOp::Limit {
            input: opt(input),
            count,
        },
        PhysicalOp::Eager { input } => PhysicalOp::Eager { input: opt(input) },
        PhysicalOp::Unwind {
            input,
            list,
            variable,
        } => PhysicalOp::Unwind {
            input: opt(input),
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
            input: opt(input),
            with_headers,
            url,
            variable,
            field_terminator,
        },
        PhysicalOp::Optional {
            input,
            null_variables,
        } => PhysicalOp::Optional {
            input: opt(input),
            null_variables,
        },

        // Two-input operators.
        PhysicalOp::NestedLoopJoin { left, right } => PhysicalOp::NestedLoopJoin {
            left: opt(left),
            right: opt(right),
        },
        PhysicalOp::HashJoin {
            left,
            right,
            join_keys,
        } => PhysicalOp::HashJoin {
            left: opt(left),
            right: opt(right),
            join_keys,
        },
        PhysicalOp::Union { left, right, all } => PhysicalOp::Union {
            left: opt(left),
            right: opt(right),
            all,
        },

        // Write operators (single input).
        PhysicalOp::Create { input, pattern } => PhysicalOp::Create {
            input: opt(input),
            pattern,
        },
        PhysicalOp::Merge {
            input,
            pattern,
            on_create,
            on_match,
        } => PhysicalOp::Merge {
            input: opt(input),
            pattern,
            on_create,
            on_match,
        },
        PhysicalOp::SetClause { input, ops } => PhysicalOp::SetClause {
            input: opt(input),
            ops,
        },
        PhysicalOp::Delete {
            input,
            detach,
            exprs,
        } => PhysicalOp::Delete {
            input: opt(input),
            detach,
            exprs,
        },
        PhysicalOp::Remove { input, ops } => PhysicalOp::Remove {
            input: opt(input),
            ops,
        },
        PhysicalOp::Foreach {
            input,
            variable,
            list,
            body,
        } => PhysicalOp::Foreach {
            input: opt(input),
            variable,
            list,
            // The body is a self-contained correlated sub-plan; optimise it like any other child.
            body: opt(body),
        },

        // Procedure call (optional input).
        PhysicalOp::ProcedureCall {
            input,
            name,
            args,
            yields,
        } => PhysicalOp::ProcedureCall {
            input: input.map(opt),
            name,
            args,
            yields,
        },
    }
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

/// Returns whichever of `a` / `b` has the lower total [cost](crate::cost), breaking ties toward `a`
/// (the incoming rule-based shape) for determinism.
fn cheaper(a: PhysicalOp, b: PhysicalOp, stats: &dyn Statistics) -> PhysicalOp {
    let ca = estimate_cost(&a, Some(stats)).cost;
    let cb = estimate_cost(&b, Some(stats)).cost;
    // Strictly-less keeps `a` on a tie: the rule-based shape is the deterministic default.
    if cb < ca { b } else { a }
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

    // A region must have >= 2 operands to reorder; a cap keeps the DP bounded.
    if operands.len() < 2 || operands.len() > MAX_JOIN_REGION_OPERANDS {
        // Too large (or degenerate): keep the rule-based region shape (already correct). Logged via the
        // cap constant's documentation; no behavioural change beyond skipping optimisation here.
        return op;
    }

    let replanned = dp_join_order(&operands, stats);
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

/// Whether both join sides are safe to reorder: independent of a correlation argument and free of any
/// write operator (a write's side effects must run in the planned order, never be reordered).
fn sides_reorderable(left: &PhysicalOp, right: &PhysicalOp) -> bool {
    !contains_argument(left)
        && !contains_argument(right)
        && !contains_write(left)
        && !contains_write(right)
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
        | PhysicalOp::NodeLabelScanEq { .. }
        | PhysicalOp::NodeIndexRangeSeek { .. }
        | PhysicalOp::SpatialIndexSeek { .. }
        | PhysicalOp::AllRelationshipsScan { .. }
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
        | PhysicalOp::NodeIndexRangeSeek { index, .. }
        | PhysicalOp::SpatialIndexSeek { index, .. } => {
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
        ExprKind::Unary { operand, .. } | ExprKind::HasLabels { operand, .. } => {
            expr_references_var(operand, variable)
        }
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
        // Comprehensions, quantifiers and existential subqueries establish their own scope;
        // conservatively treat them as referencing the variable so a seek is never built on a
        // value that might shadow/close over it.
        ExprKind::ListComprehension(_)
        | ExprKind::PatternComprehension(_)
        | ExprKind::Quantifier(_)
        | ExprKind::ExistsSubquery(_) => true,
    }
}

/// Builds the physical seek operator for a matched [`PropertyPredicate`].
fn build_seek(variable: &Var, label: &Label, pp: &PropertyPredicate, index: IndexId) -> PhysicalOp {
    match &pp.kind {
        PropertyPredicateKind::Equality { value } => PhysicalOp::NodeIndexSeek {
            variable: variable.clone(),
            label: label.clone(),
            property: pp.property.clone(),
            value: value.clone(),
            index,
        },
        PropertyPredicateKind::Range { bound, value } => PhysicalOp::NodeIndexRangeSeek {
            variable: variable.clone(),
            label: label.clone(),
            property: pp.property.clone(),
            bound: *bound,
            value: value.clone(),
            index,
        },
    }
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
    let (property, center) = distance_call_over_var(lhs, variable)?;
    let radius = const_number(rhs)?;
    Some(SpatialPredicate {
        property,
        center_x: center.0,
        center_y: center.1,
        radius,
    })
}

/// If `expr` is a `distance(...)` (or `point.distance(...)`) call relating `var.<prop>` to a constant
/// point, returns `(prop, (center_x, center_y))`. Accepts the two-argument symmetric forms (either
/// argument may be the property or the constant point). Returns [`None`] otherwise.
fn distance_call_over_var(expr: &Expr, variable: &str) -> Option<(String, (f64, f64))> {
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
    let try_sides = |prop_side: &Expr, center_side: &Expr| -> Option<(String, (f64, f64))> {
        let prop = property_of(prop_side, variable)?;
        let center = const_point_xy(center_side)?;
        Some((prop, center))
    };
    try_sides(&args[0], &args[1]).or_else(|| try_sides(&args[1], &args[0]))
}

/// Evaluates a **constant** expression to its 2D `(x, y)` projection iff it is a constant
/// `Value::Point` (`rmp` task #73). Returns [`None`] for any non-constant or non-point expression, so
/// the planner declines a spatial seek it cannot pin to a literal centre.
fn const_point_xy(expr: &Expr) -> Option<(f64, f64)> {
    match const_value(expr)? {
        Value::Point(p) => Some((p.x(), p.y())),
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
        | PhysicalOp::NodeLabelScanEq { variable, .. }
        | PhysicalOp::NodeIndexRangeSeek { variable, .. }
        | PhysicalOp::SpatialIndexSeek { variable, .. } => push_unique(out, variable.clone()),
        PhysicalOp::AllRelationshipsScan {
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
                index,
            } => writeln!(
                f,
                "NodeIndexSeek({variable}:{} {property} = {} via {index})",
                label.name,
                h::expr(value),
            ),
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
                index,
            } => writeln!(
                f,
                "NodeIndexRangeSeek({variable}:{} {property} {} {} via {index})",
                label.name,
                bound.symbol(),
                h::expr(value),
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
}
