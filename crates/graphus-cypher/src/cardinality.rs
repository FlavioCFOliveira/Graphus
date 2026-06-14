//! The Cypher **cardinality estimator** — a pure function from a [logical plan](crate::logical) to
//! an estimated output **row count** (`00-overview` §6, the Phase 2 cost-based-optimiser foundation).
//!
//! [`estimate_rows`] walks a [`LogicalOp`] tree and returns how many rows the operator is expected to
//! emit, reading the graph's *shape* through the optional [`Statistics`] seam ([`crate::statistics`]).
//! This is **additive groundwork**: the estimate is only *recorded*, never acted upon. The physical
//! planner ([`plan_physical_with_stats`](crate::physical::plan_physical_with_stats)) threads a
//! [`Statistics`] source through and attaches the root estimate to the plan
//! ([`PhysicalPlan::estimated_rows`](crate::physical::PhysicalPlan::estimated_rows)), but **no
//! plan-choice branches on it** (sub-task #80 keeps every operator tree byte-identical), so this
//! module changes no query result and no plan shape — only the value carried alongside the plan. A
//! later sub-task wires that estimate into a cost model.
//!
//! # Property-histogram filter selectivity (sub-task #81)
//!
//! A [`Filter`](LogicalOp::Filter) whose predicate is a single property comparison on a label-scanned
//! variable — `v.prop = lit`, or `v.prop </<=/>/>=  lit` (and the mirrored `lit <op> v.prop` forms) —
//! is estimated from a real **equi-depth histogram** read through the [`Statistics`] property-
//! selectivity seam ([`Statistics::estimate_nodes_label_property_eq`] /
//! [`estimate_nodes_label_property_range`](Statistics::estimate_nodes_label_property_range)), instead
//! of the flat [`DEFAULT_PREDICATE_SELECTIVITY`]. The detected predicate shapes mirror the physical
//! planner's index-selection detection ([`crate::physical`]) exactly, so the estimator recognises the
//! same predicates the planner can turn into index seeks. Every other predicate shape — a non-property
//! comparison, a non-literal operand, a filter not over a label scan, an unindexable literal, absent
//! statistics, or a `None` from the seam — **falls back** to the documented constant (see
//! [`estimate`]'s `Filter` arm for the full fallback matrix). The fallback is per-`Filter`: the
//! logical lowering splits a conjunction (`AND`) into **nested** `Filter`s, so each `Filter` here
//! carries a single conjunct, and a compound predicate composes per-filter selectivities naturally.
//!
//! # Why `f64`
//!
//! Cardinalities **compound** — an [`Expand`](LogicalOp::Expand) multiplies its input by an average
//! degree, a [`Filter`](LogicalOp::Filter) multiplies by a fractional selectivity, an
//! [`Apply`](LogicalOp::Apply) multiplies two sub-estimates. Using `f64` lets fractional
//! selectivities stay honest (a `0.3`-selective filter on 10 rows is `3.0`, not a prematurely
//! rounded `3`), keeps large compounded products from overflowing an integer, and gives the eventual
//! cost model a continuous quantity to optimise. The estimate is **never** rounded here; a consumer
//! that wants an integer row count rounds at its own boundary.
//!
//! # Guarantees
//!
//! The returned value is **always finite and non-negative** (`>= 0.0`, never `NaN`, never infinite).
//! Every recursive step clamps and guards so a pathological tree (e.g. a huge variable-length range)
//! can never produce `inf` or `NaN`; see [`clamp_estimate`].
//!
//! # The constants are deliberate "magic numbers"
//!
//! When [`Statistics`] is `None`, or a label/type count is unknown, the estimator falls back to the
//! documented selectivity constants in this module. They are the **conventional defaults** a planner
//! uses in the absence of histograms (the classic System R / textbook "magic constants"); each is
//! documented with its rationale. They exist precisely so the estimate stays *finite and ordered*
//! (more-selective operators estimate fewer rows than less-selective ones) even with zero statistics
//! — they are not claimed to be accurate, and sub-task #81 supersedes the predicate one with real
//! histograms.

use crate::ast::{BinaryOp, Expr, ExprKind, Literal, VarLengthRange};
use crate::logical::LogicalOp;
use crate::statistics::Statistics;
use graphus_core::Value;

// =================================================================================================
// Default constants (the textbook "magic numbers", used only when statistics are absent/unknown)
// =================================================================================================

/// Fraction of the total node count a [`NodeByLabelScan`](LogicalOp::NodeByLabelScan) is assumed to
/// keep when the label's exact count is **unknown** (`Statistics` is `None`, or
/// [`Statistics::nodes_with_label`] returned `None`).
///
/// `0.1` models the common case where a label partitions the graph into roughly a handful of classes
/// (so any one label covers ~10% of nodes) — a deliberately conservative middle ground: small enough
/// that a label scan estimates fewer rows than an all-nodes scan (preserving the *ordering* a cost
/// model relies on), but not so small that a labelled scan looks free.
pub const DEFAULT_LABEL_SELECTIVITY: f64 = 0.1;

/// Selectivity assumed for a single [`Filter`](LogicalOp::Filter) predicate **when no histogram
/// estimate is available**.
///
/// `0.3` is the classic textbook default for an unknown predicate with no histogram (System R used
/// `1/3` for an inequality and similar magic constants throughout; `0.3` is the widely-cited rounded
/// value). As of sub-task #81 the estimator prefers a property-histogram-driven estimate for a
/// recognised single-property comparison over a label-scanned variable (see [`estimate`]'s `Filter`
/// arm); this constant is the **fallback** for every other case — a non-property predicate, a
/// non-literal / unindexable operand, a filter not over a label scan, absent statistics, or a `None`
/// from the [`Statistics`] seam. It keeps such a filtered estimate strictly below its input (a filter
/// never adds rows) while leaving a meaningful fraction.
pub const DEFAULT_PREDICATE_SELECTIVITY: f64 = 0.3;

/// Assumed total node count when no [`Statistics`] source is available.
///
/// A small positive constant: it must be `> 0` so label selectivities and average degrees stay
/// finite and the operator *ordering* (scan < label-scan) is preserved, and small so a stats-less
/// estimate models a modest graph rather than an implausibly large one. The absolute value does not
/// matter for plan choice (nothing branches on it yet); it only has to be finite and positive.
pub const DEFAULT_TOTAL_NODES: f64 = 1_000.0;

/// Assumed total relationship count when no [`Statistics`] source is available.
///
/// As with [`DEFAULT_TOTAL_NODES`], a small positive constant. Chosen larger than the node default
/// because graphs are typically denser than they are wide (more edges than vertices), so the implied
/// average degree (`rels / nodes`) is a plausible small integer rather than a fraction.
pub const DEFAULT_TOTAL_RELATIONSHIPS: f64 = 10_000.0;

/// Assumed average list length for an [`Unwind`](LogicalOp::Unwind) whose list expression cannot be
/// inspected statically.
///
/// `UNWIND` emits one row per element of its list, so the multiplier is the average list length. The
/// list is an arbitrary runtime expression here, so `10.0` is a plain documented guess for a "typical"
/// small list; it has no statistics behind it.
pub const DEFAULT_LIST_LENGTH: f64 = 10.0;

/// Assumed number of records a [`LoadCsv`](LogicalOp::LoadCsv) source yields per driving row.
///
/// `LOAD CSV` streams an external file whose size is entirely unknown at planning time, so this is a
/// pure guess at a "modest file". It only has to be finite and positive.
pub const DEFAULT_CSV_RECORDS: f64 = 1_000.0;

/// Ratio of distinct groups to input rows for an [`Aggregation`](LogicalOp::Aggregation) **with**
/// grouping keys (and for `DISTINCT` projection).
///
/// Grouping can only ever produce *at most* as many rows as the input (one row per distinct key
/// combination), so the estimate is `input * ratio` clamped to `[1, input]`. `0.1` assumes grouping
/// collapses the input roughly ten-to-one — a conventional default in the absence of per-key
/// distinct-value statistics. The `>= 1` floor reflects that a non-empty input yields at least one
/// group.
pub const DEFAULT_DISTINCT_GROUP_RATIO: f64 = 0.1;

/// Fraction of input rows a `DISTINCT` [`Projection`](LogicalOp::Projection) is assumed to keep.
///
/// De-duplication can only remove rows, so this is `< 1.0`. `0.9` is deliberately conservative — most
/// projections have few exact duplicates — so a distinct projection estimates slightly fewer rows
/// than its input without pretending to know the true duplicate rate (which needs column statistics).
pub const DEFAULT_DISTINCT_PROJECTION_RATIO: f64 = 0.9;

/// Assumed number of rows a [`ProcedureCall`](LogicalOp::ProcedureCall) yields per driving row.
///
/// A procedure's output cardinality is unknowable without the procedure catalogue (which the
/// estimator does not consult), so this is a documented guess used for both a leading call (one
/// driving row) and a correlated call (per input row).
pub const DEFAULT_PROCEDURE_YIELD: f64 = 10.0;

/// Default upper bound applied to a variable-length [`Expand`](LogicalOp::Expand) whose range has no
/// `max` (e.g. `*` or `*2..`).
///
/// An unbounded traversal cannot be modelled with an infinite path length, so the open upper end is
/// **clamped** to this small cap purely for estimation. `5` keeps the degree exponent bounded (so the
/// estimate stays finite) while still reflecting that an unbounded expand reaches further than a
/// single hop. It does **not** affect execution — only the estimate.
pub const DEFAULT_VARLEN_MAX_HOPS: u64 = 5;

// =================================================================================================
// Public entry point
// =================================================================================================

/// Estimates the number of rows the logical operator `op` emits, given optional graph [`Statistics`].
///
/// The estimate is a **point-in-time, statistics-informed heuristic**, not a guarantee: see the
/// [module docs](self) for the per-operator model and the constants used when `stats` is `None` or a
/// count is unknown. The result is always finite and `>= 0.0`.
///
/// `stats` is `None` when the backend keeps no counts; the estimator then uses the documented
/// `DEFAULT_*` fallbacks throughout.
///
/// # Examples
///
/// ```
/// use graphus_cypher::cardinality::estimate_rows;
/// use graphus_cypher::logical::{LogicalOp, Var};
///
/// // With no statistics, an all-nodes scan estimates the documented default total.
/// let scan = LogicalOp::AllNodesScan { variable: Var::named("n") };
/// let rows = estimate_rows(&scan, None);
/// assert!(rows > 0.0 && rows.is_finite());
/// ```
#[must_use]
pub fn estimate_rows(op: &LogicalOp, stats: Option<&dyn Statistics>) -> f64 {
    let raw = estimate(op, stats);
    clamp_estimate(raw)
}

// =================================================================================================
// Internal: the per-operator model
// =================================================================================================

/// The total node count to scale against: the statistics value, or [`DEFAULT_TOTAL_NODES`].
///
/// Shared with the [cost model](crate::cost), which scales its physical access-path cardinalities
/// against the same total so the two estimators stay mutually consistent.
pub(crate) fn total_nodes(stats: Option<&dyn Statistics>) -> f64 {
    stats.map_or(DEFAULT_TOTAL_NODES, |s| s.total_nodes() as f64)
}

/// The total relationship count: the statistics value, or [`DEFAULT_TOTAL_RELATIONSHIPS`].
///
/// Shared with the [cost model](crate::cost) (see [`total_nodes`]).
pub(crate) fn total_relationships(stats: Option<&dyn Statistics>) -> f64 {
    stats.map_or(DEFAULT_TOTAL_RELATIONSHIPS, |s| {
        s.total_relationships() as f64
    })
}

/// The average node out-degree: `total_relationships / max(1, total_nodes)`.
///
/// `max(1, _)` guards against division by zero on an empty graph; with zero nodes the degree is
/// simply the relationship total (a degenerate but finite value). Shared with the
/// [cost model](crate::cost), whose `ExpandAll`/`ExpandInto` cardinality multiplies by this same
/// degree.
pub(crate) fn average_degree(stats: Option<&dyn Statistics>) -> f64 {
    let nodes = total_nodes(stats).max(1.0);
    total_relationships(stats) / nodes
}

/// Forces an estimate into the documented invariant: finite and `>= 0.0`.
///
/// A `NaN` collapses to `0.0` (the safe, smallest sensible count); a positive infinity clamps to
/// [`f64::MAX`] and a negative value clamps to `0.0`. This is the single choke point that upholds the
/// "never `NaN`, never infinite, never negative" guarantee in [`estimate_rows`].
pub(crate) fn clamp_estimate(x: f64) -> f64 {
    if x.is_nan() {
        0.0
    } else if x.is_infinite() {
        if x > 0.0 { f64::MAX } else { 0.0 }
    } else {
        x.max(0.0)
    }
}

/// Tries to read a non-negative integer row-count from a [`SKIP`](LogicalOp::Skip) /
/// [`LIMIT`](LogicalOp::Limit) count expression.
///
/// Only a bare integer **literal** is understood (the overwhelmingly common case). A parameter or a
/// computed expression cannot be evaluated at planning time without binding/constant-folding, so it
/// returns `None` and the caller treats the operator as a pass-through. The literal's value is a
/// `u128`; it is saturated into `f64` (an exact conversion for any realistic count).
pub(crate) fn literal_row_count(expr: &crate::ast::Expr) -> Option<f64> {
    match &expr.kind {
        ExprKind::Literal(Literal::Integer(int_lit)) => Some(int_lit.value as f64),
        _ => None,
    }
}

/// The midpoint hop count of a variable-length range, with documented clamping of open bounds.
///
/// `min` defaults to `1` (openCypher's implicit lower bound, matching [`VarLengthRange`]'s
/// documentation). `max` defaults to `min + DEFAULT_VARLEN_MAX_HOPS` when unbounded, so an open-ended
/// traversal still has a finite modelled length. The returned value is the midpoint `(min + max) / 2`,
/// the average path length used as the degree exponent.
pub(crate) fn average_path_length(range: &VarLengthRange) -> f64 {
    let min = range.min.unwrap_or(1);
    // An open upper bound is clamped relative to `min` so the exponent stays small and finite.
    let max = range
        .max
        .unwrap_or_else(|| min.saturating_add(DEFAULT_VARLEN_MAX_HOPS));
    // Defensive: a malformed `max < min` collapses to `min` so the average never goes below the floor.
    let max = max.max(min);
    (min as f64 + max as f64) / 2.0
}

/// The dispatch core: the unclamped per-operator estimate. [`estimate_rows`] clamps the result.
fn estimate(op: &LogicalOp, stats: Option<&dyn Statistics>) -> f64 {
    match op {
        // ---- leaves -------------------------------------------------------------------------------

        // A full node scan emits exactly one row per node.
        LogicalOp::AllNodesScan { .. } => total_nodes(stats),

        // A label scan emits the exact per-label count when known; otherwise a documented fraction
        // of the total (DEFAULT_LABEL_SELECTIVITY). An unknown label that statistics *do* track
        // legitimately returns Some(0) — that is an exact zero, not a fallback.
        LogicalOp::NodeByLabelScan { label, .. } => stats
            .and_then(|s| s.nodes_with_label(&label.name))
            .map(|c| c as f64)
            .unwrap_or_else(|| total_nodes(stats) * DEFAULT_LABEL_SELECTIVITY),

        // A relationship scan emits one row per relationship, refined by type when types are listed:
        // sum the known per-type counts; if a listed type's count is unknown, fall back to the total
        // scaled by the label selectivity for that one type (so a single unknown type does not make
        // the whole estimate collapse to the full total). With no type filter, the full total.
        LogicalOp::AllRelationshipsScan { types, .. } => {
            if types.is_empty() {
                total_relationships(stats)
            } else {
                types
                    .iter()
                    .map(|t| {
                        stats
                            .and_then(|s| s.relationships_with_type(&t.name))
                            .map(|c| c as f64)
                            .unwrap_or_else(|| {
                                total_relationships(stats) * DEFAULT_LABEL_SELECTIVITY
                            })
                    })
                    .sum()
            }
        }

        // The correlated-application argument leaf is a single row (the bindings of one outer row).
        LogicalOp::Argument { .. } => 1.0,

        // The neutral single-row input.
        LogicalOp::Empty => 1.0,

        // ---- graph --------------------------------------------------------------------------------

        // Expand multiplies the input by an average degree. When types are listed and known, the
        // degree is refined to (sum of those types' counts) / total_nodes; otherwise the graph-wide
        // average degree. For a variable-length range we compound by degree^(avg path length),
        // clamping an open upper bound (see `average_path_length`) so the result stays finite.
        LogicalOp::Expand {
            input,
            types,
            range,
            ..
        } => {
            let input_rows = estimate(input, stats);
            let nodes = total_nodes(stats).max(1.0);
            let degree = if types.is_empty() {
                average_degree(stats)
            } else {
                let typed_rels: f64 = types
                    .iter()
                    .map(|t| {
                        stats
                            .and_then(|s| s.relationships_with_type(&t.name))
                            .map(|c| c as f64)
                            .unwrap_or_else(|| {
                                total_relationships(stats) * DEFAULT_LABEL_SELECTIVITY
                            })
                    })
                    .sum();
                typed_rels / nodes
            };
            match range {
                None => input_rows * degree,
                Some(r) => {
                    // degree^(avg_len): a defensible, bounded model of multi-hop fan-out.
                    let avg_len = average_path_length(r);
                    input_rows * degree.powf(avg_len)
                }
            }
        }

        // A named path binds one path value per input row — cardinality is unchanged.
        LogicalOp::NamedPath { input, .. } => estimate(input, stats),

        // `shortestPath` yields at most one path per input row; `allShortestPaths` a small number.
        // Both endpoints are bound by the input, so the cardinality is modelled as a passthrough.
        LogicalOp::ShortestPath { input, .. } => estimate(input, stats),

        // ---- relational ---------------------------------------------------------------------------

        // A filter keeps at most its input (a filter never adds rows). When the predicate is a single
        // property comparison on a label-scanned variable AND statistics carry a histogram for that
        // label.property, the estimate comes from the histogram (clamped to the input — a stale stat
        // can never make a filter *grow* its input). Otherwise it falls back to a documented constant
        // fraction. See `estimate_filter` for the full detection + fallback matrix.
        LogicalOp::Filter { input, predicate } => estimate_filter(input, predicate, stats),

        // A non-distinct projection is a pure pass-through (one output row per input row). A DISTINCT
        // projection de-duplicates, so it keeps a documented fraction (<= input).
        LogicalOp::Projection {
            input, distinct, ..
        } => {
            let input_rows = estimate(input, stats);
            if *distinct {
                input_rows * DEFAULT_DISTINCT_PROJECTION_RATIO
            } else {
                input_rows
            }
        }

        // Aggregation with no grouping keys is a single global group => exactly one row. With keys,
        // the number of distinct groups is at most the input and at least one (for a non-empty input);
        // we estimate input * ratio clamped into [1, input].
        LogicalOp::Aggregation {
            input, group_keys, ..
        } => {
            let input_rows = estimate(input, stats);
            if group_keys.is_empty() {
                1.0
            } else {
                let groups = input_rows * DEFAULT_DISTINCT_GROUP_RATIO;
                groups.clamp(1.0, input_rows.max(1.0))
            }
        }

        // Sort only reorders rows; the count is unchanged.
        LogicalOp::Sort { input, .. } => estimate(input, stats),

        // SKIP n removes the first n rows: input - n, floored at 0, when n is a readable literal;
        // otherwise (parameter/expression) treated as a pass-through (we cannot evaluate it here).
        LogicalOp::Skip { input, count } => {
            let input_rows = estimate(input, stats);
            match literal_row_count(count) {
                Some(n) => (input_rows - n).max(0.0),
                None => input_rows,
            }
        }

        // LIMIT n keeps at most n rows: min(input, n) when n is a readable literal; otherwise a
        // pass-through.
        LogicalOp::Limit { input, count } => {
            let input_rows = estimate(input, stats);
            match literal_row_count(count) {
                Some(n) => input_rows.min(n),
                None => input_rows,
            }
        }

        // UNWIND emits one row per list element: input * average list length (a documented guess).
        LogicalOp::Unwind { input, .. } => estimate(input, stats) * DEFAULT_LIST_LENGTH,

        // LOAD CSV emits one row per record per driving row: input * a documented default file size.
        LogicalOp::LoadCsv { input, .. } => estimate(input, stats) * DEFAULT_CSV_RECORDS,

        // Apply is the correlated "join": for each left row, the right branch is re-evaluated with
        // that row's bindings. Under an independence/containment assumption we estimate
        // left_rows * estimate(right), where the right branch is rooted at an Argument leaf
        // (cardinality 1 per left row), so estimate(right) is the per-left-row fan-out.
        LogicalOp::Apply { left, right } => estimate(left, stats) * estimate(right, stats),

        // Optional (left-outer) guarantees at least one row per drive, so it is max(input, 1).
        LogicalOp::Optional { input, .. } => estimate(input, stats).max(1.0),

        // UNION (with or without ALL): the sum of both branches. For non-ALL the distinct result may
        // be smaller, but the sum is the documented upper-bound estimate (we do not model cross-branch
        // duplicate overlap).
        LogicalOp::Union { left, right, .. } => estimate(left, stats) + estimate(right, stats),

        // ---- write --------------------------------------------------------------------------------

        // Write clauses run once per input row and emit roughly one row each, so they pass the input
        // cardinality through. A leading write over `Empty` therefore estimates 1 (Empty => 1).
        LogicalOp::Create { input, .. }
        | LogicalOp::Merge { input, .. }
        | LogicalOp::SetClause { input, .. }
        | LogicalOp::Delete { input, .. }
        | LogicalOp::Remove { input, .. } => estimate(input, stats),

        // ---- procedure ----------------------------------------------------------------------------

        // A procedure's yield count is unknowable without the procedure catalogue (which the estimator
        // does not consult). A correlated call (Some input) emits a documented default per driving row;
        // a leading call (None) emits that default once.
        LogicalOp::ProcedureCall { input, .. } => match input {
            Some(inner) => estimate(inner, stats) * DEFAULT_PROCEDURE_YIELD,
            None => DEFAULT_PROCEDURE_YIELD,
        },
    }
}

// =================================================================================================
// Filter selectivity: histogram-driven where possible, constant fallback otherwise (sub-task #81)
// =================================================================================================

/// Estimates a [`Filter`](LogicalOp::Filter)'s output cardinality.
///
/// The model, in order:
///
/// 1. `input_rows = estimate(input)` — a filter never adds rows, so this is the ceiling.
/// 2. If the `predicate` is a single property comparison on a variable `v` (equality or a range, with
///    a bare, index-encodable literal operand), `v` is bound by a [`NodeByLabelScan`](LogicalOp::NodeByLabelScan)
///    somewhere on `input`'s spine, and `stats` carries a histogram for that `label.property`, the
///    estimate is the histogram's answer **clamped to `[0, input_rows]`** (clamping keeps the estimate
///    sound under stale statistics — a filter can never exceed its input).
/// 3. Otherwise (no property predicate, unresolved label, non-literal / unindexable operand, no
///    statistics, or `None` from the seam) the estimate is `input_rows * DEFAULT_PREDICATE_SELECTIVITY`.
///
/// The whole result is finite and non-negative; [`estimate_rows`] additionally clamps the tree.
fn estimate_filter(input: &LogicalOp, predicate: &Expr, stats: Option<&dyn Statistics>) -> f64 {
    let input_rows = estimate(input, stats);
    if let Some(count) = histogram_filter_estimate(input, predicate, stats) {
        // A filter never adds rows; clamp to the input so a stale histogram cannot make it grow.
        return count.clamp(0.0, input_rows);
    }
    input_rows * DEFAULT_PREDICATE_SELECTIVITY
}

/// Attempts a histogram-backed row estimate for a filter, returning `None` to request the constant
/// fallback. `None` is returned when **any** precondition fails: no statistics, the predicate is not a
/// recognised single-property comparison, the variable is not bound by a label scan on `input`, the
/// literal does not convert to an index-encodable [`Value`], or the [`Statistics`] seam returns `None`
/// (no histogram for this `label.property`, or an unindexable value).
fn histogram_filter_estimate(
    input: &LogicalOp,
    predicate: &Expr,
    stats: Option<&dyn Statistics>,
) -> Option<f64> {
    let stats = stats?;
    let pred = analyze_property_comparison(predicate)?;
    let label = label_for_var(input, &pred.variable)?;
    match pred.kind {
        ComparisonKind::Equality { value } => {
            stats.estimate_nodes_label_property_eq(&label, &pred.property, &value)
        }
        ComparisonKind::Range { bound, value } => {
            // Translate the one-sided bound into the histogram's (lo, hi, inclusive) range vocabulary.
            let (lo, lo_inc, hi, hi_inc) = bound.as_range(&value);
            stats.estimate_nodes_label_property_range(
                &label,
                &pred.property,
                lo,
                lo_inc,
                hi,
                hi_inc,
            )
        }
    }
}

/// A single property comparison usable for histogram estimation: `variable.property <op> value`.
///
/// Mirrors the physical planner's [`PropertyPredicate`](crate::physical) detection, but carries the
/// operand as an already-converted [`Value`] (the estimator needs the value, not the unevaluated AST)
/// and records the variable name (the estimator must resolve the variable's label).
struct PropertyComparison {
    /// The compared variable (`v` in `v.prop`).
    variable: String,
    /// The property key (`prop` in `v.prop`).
    property: String,
    /// Equality or a one-sided range.
    kind: ComparisonKind,
}

/// The two comparison shapes the histogram seam can serve.
enum ComparisonKind {
    /// `v.prop = value`.
    Equality { value: Value },
    /// `v.prop <op> value` for `<`, `<=`, `>`, `>=` (the `bound` already accounts for the side the
    /// property appeared on).
    Range { bound: RangeBound, value: Value },
}

/// A one-sided range bound on the property, matching the four comparison operators. Kept local to the
/// estimator (the physical planner has its own `RangeBound` for the *plan*; this one only models the
/// estimate) so the cardinality module has no dependency on the physical planner.
#[derive(Clone, Copy)]
enum RangeBound {
    /// `v.prop > value`.
    GreaterThan,
    /// `v.prop >= value`.
    GreaterOrEqual,
    /// `v.prop < value`.
    LessThan,
    /// `v.prop <= value`.
    LessOrEqual,
}

impl RangeBound {
    /// The bound implied by `v.prop <op> value` (property on the **left**); `None` for a non-range op.
    fn from_property_lhs(op: BinaryOp) -> Option<Self> {
        match op {
            BinaryOp::Gt => Some(Self::GreaterThan),
            BinaryOp::Gte => Some(Self::GreaterOrEqual),
            BinaryOp::Lt => Some(Self::LessThan),
            BinaryOp::Lte => Some(Self::LessOrEqual),
            _ => None,
        }
    }

    /// The symmetric bound when the property is on the **right** (`value <op> v.prop`).
    fn mirrored(self) -> Self {
        match self {
            Self::GreaterThan => Self::LessThan,
            Self::GreaterOrEqual => Self::LessOrEqual,
            Self::LessThan => Self::GreaterThan,
            Self::LessOrEqual => Self::GreaterOrEqual,
        }
    }

    /// Expresses this one-sided bound as the histogram's `(lo, lo_inclusive, hi, hi_inclusive)`
    /// argument tuple over `value`. A `>`/`>=` bound is a low bound with the high side open; a
    /// `<`/`<=` bound is a high bound with the low side open.
    fn as_range(self, value: &Value) -> (Option<&Value>, bool, Option<&Value>, bool) {
        match self {
            Self::GreaterThan => (Some(value), false, None, true),
            Self::GreaterOrEqual => (Some(value), true, None, true),
            Self::LessThan => (None, true, Some(value), false),
            Self::LessOrEqual => (None, true, Some(value), true),
        }
    }
}

/// Recognises a single property comparison `variable.property <op> literal` (or the mirrored
/// `literal <op> variable.property`) and converts the literal to a [`Value`].
///
/// Returns `None` unless the expression is a binary comparison (`=`, `<`, `<=`, `>`, `>=`) with
/// exactly one side a `variable.property` access and the other a **bare, index-encodable literal**.
/// Mirrors the physical planner's [`analyze_property_predicate`](crate::physical) shape detection so
/// the estimator and the planner recognise the same predicates; the estimator additionally requires
/// the operand to be a *literal* (a parameter's value is unknown at planning time, so no histogram
/// lookup is possible) and to convert to a `Value` (an out-of-`i64`-range integer, `null`, or any
/// non-scalar literal is rejected).
fn analyze_property_comparison(expr: &Expr) -> Option<PropertyComparison> {
    let ExprKind::Binary { op, lhs, rhs } = &expr.kind else {
        return None;
    };
    // Property on the left: `var.prop <op> literal`.
    if let Some((variable, property)) = property_access(lhs) {
        if let Some(value) = literal_value(rhs) {
            return comparison_from(*op, variable, property, value, false);
        }
    }
    // Property on the right: `literal <op> var.prop`.
    if let Some((variable, property)) = property_access(rhs) {
        if let Some(value) = literal_value(lhs) {
            return comparison_from(*op, variable, property, value, true);
        }
    }
    None
}

/// Builds a [`PropertyComparison`] from a comparison operator. `property_on_right` mirrors a range
/// bound (so `literal < v.prop` becomes the bound `v.prop > literal`). Returns `None` for a
/// non-comparison operator.
fn comparison_from(
    op: BinaryOp,
    variable: String,
    property: String,
    value: Value,
    property_on_right: bool,
) -> Option<PropertyComparison> {
    match op {
        BinaryOp::Eq => Some(PropertyComparison {
            variable,
            property,
            kind: ComparisonKind::Equality { value },
        }),
        BinaryOp::Gt | BinaryOp::Gte | BinaryOp::Lt | BinaryOp::Lte => {
            let mut bound = RangeBound::from_property_lhs(op)?;
            if property_on_right {
                bound = bound.mirrored();
            }
            Some(PropertyComparison {
                variable,
                property,
                kind: ComparisonKind::Range { bound, value },
            })
        }
        _ => None,
    }
}

/// If `expr` is exactly `variable.key`, returns `(variable, key)`.
fn property_access(expr: &Expr) -> Option<(String, String)> {
    if let ExprKind::Property { base, key } = &expr.kind {
        if let ExprKind::Variable(name) = &base.kind {
            return Some((name.clone(), key.clone()));
        }
    }
    None
}

/// Converts a **bare** scalar literal expression to a [`graphus_core::Value`], or `None`.
///
/// Only a directly-written literal is usable for a histogram lookup (a parameter or computed
/// expression has no value at planning time). An integer beyond `i64`'s range, the `null` literal,
/// and any non-scalar literal are rejected (`None`) — the caller then falls back to the constant
/// selectivity. The integer magnitude is a `u128` (the lexer keeps the sign as a separate unary
/// minus); since the property-comparison forms here have no unary minus folded in, only the
/// non-negative magnitude is convertible, which is the overwhelmingly common literal shape.
fn literal_value(expr: &Expr) -> Option<Value> {
    match &expr.kind {
        ExprKind::Literal(Literal::Integer(int_lit)) => {
            i64::try_from(int_lit.value).ok().map(Value::Integer)
        }
        ExprKind::Literal(Literal::Float(f)) => Some(Value::Float(*f)),
        ExprKind::Literal(Literal::String(s)) => Some(Value::String(s.clone())),
        ExprKind::Literal(Literal::Boolean(b)) => Some(Value::Boolean(*b)),
        // Null is not index-encodable; lists, maps, parameters, and computed expressions have no
        // bare value here.
        _ => None,
    }
}

/// Resolves the label of `variable` by searching `op`'s subtree for the
/// [`NodeByLabelScan`](LogicalOp::NodeByLabelScan) that binds it.
///
/// The estimator descends the **single-input** operator spine (filters, projections that pass the
/// variable through, sorts, skips/limits, and the graph/write operators that thread one input): a
/// label scan that binds `variable` may sit directly under the filter or a few hops down. Binary
/// operators ([`Apply`](LogicalOp::Apply) / [`Union`](LogicalOp::Union)) are searched on **both**
/// branches. Returns the first matching label found (a variable is bound by at most one scan in a
/// validated plan), or `None` if `variable` is not bound by a label scan (e.g. it comes from an
/// [`AllNodesScan`](LogicalOp::AllNodesScan), an expand, or `UNWIND`) — in which case no per-label
/// histogram applies and the caller falls back.
fn label_for_var(op: &LogicalOp, variable: &str) -> Option<String> {
    match op {
        LogicalOp::NodeByLabelScan { variable: v, label } if v.name == variable => {
            Some(label.name.clone())
        }
        // Single-input operators: recurse into the one child.
        LogicalOp::Filter { input, .. }
        | LogicalOp::Projection { input, .. }
        | LogicalOp::Aggregation { input, .. }
        | LogicalOp::Sort { input, .. }
        | LogicalOp::Skip { input, .. }
        | LogicalOp::Limit { input, .. }
        | LogicalOp::Unwind { input, .. }
        | LogicalOp::LoadCsv { input, .. }
        | LogicalOp::Expand { input, .. }
        | LogicalOp::ShortestPath { input, .. }
        | LogicalOp::NamedPath { input, .. }
        | LogicalOp::Optional { input, .. }
        | LogicalOp::Create { input, .. }
        | LogicalOp::Merge { input, .. }
        | LogicalOp::SetClause { input, .. }
        | LogicalOp::Delete { input, .. }
        | LogicalOp::Remove { input, .. } => label_for_var(input, variable),
        // Binary operators: the binding may be on either side.
        LogicalOp::Apply { left, right } | LogicalOp::Union { left, right, .. } => {
            label_for_var(left, variable).or_else(|| label_for_var(right, variable))
        }
        LogicalOp::ProcedureCall { input, .. } => {
            input.as_deref().and_then(|i| label_for_var(i, variable))
        }
        // Leaves that do not bind via a label scan (incl. a non-matching NodeByLabelScan).
        LogicalOp::NodeByLabelScan { .. }
        | LogicalOp::AllNodesScan { .. }
        | LogicalOp::AllRelationshipsScan { .. }
        | LogicalOp::Argument { .. }
        | LogicalOp::Empty => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ast::{Expr, Label, RelType};
    use crate::graph_access::{GraphAccess, MemGraph};
    use crate::lexer::{IntBase, IntLiteral, Span};
    use crate::logical::{LogicalOp, ProjectionColumn, Var};
    use graphus_core::Value;

    /// A zero-width span placeholder for AST nodes built by hand (the estimator never inspects spans).
    fn span() -> Span {
        Span::new(0, 0)
    }

    /// An integer-literal expression `n` for SKIP/LIMIT count tests.
    fn int_expr(n: u128) -> Expr {
        Expr::new(
            ExprKind::Literal(Literal::Integer(IntLiteral {
                value: n,
                base: IntBase::Decimal,
            })),
            span(),
        )
    }

    /// A `true` boolean-literal expression, used wherever an operator needs an arbitrary
    /// (estimator-ignored) predicate/list/url expression.
    fn dummy_expr() -> Expr {
        Expr::new(ExprKind::Literal(Literal::Boolean(true)), span())
    }

    fn label(name: &str) -> Label {
        Label {
            name: name.to_owned(),
            span: span(),
        }
    }

    fn rel_type(name: &str) -> RelType {
        RelType {
            name: name.to_owned(),
            span: span(),
        }
    }

    fn projection_col(name: &str) -> ProjectionColumn {
        ProjectionColumn {
            expr: dummy_expr(),
            alias: name.to_owned(),
        }
    }

    /// A deterministic seeded graph: 10 `:Person`, 3 `:Company`, 13 nodes total; 5 `:KNOWS`
    /// (Person→Person) and 4 `:WORKS_AT` (Person→Company) relationships, 9 total.
    fn seeded_graph() -> MemGraph {
        let mut g = MemGraph::new();
        let people: Vec<_> = (0..10)
            .map(|i| g.add_node(["Person"], [("id", Value::Integer(i))]))
            .collect();
        let companies: Vec<_> = (0..3)
            .map(|i| g.add_node(["Company"], [("id", Value::Integer(i))]))
            .collect();
        for w in people.windows(2).take(5) {
            g.add_rel("KNOWS", w[0], w[1], [] as [(&str, Value); 0]);
        }
        for (i, &p) in people.iter().take(4).enumerate() {
            g.add_rel(
                "WORKS_AT",
                p,
                companies[i % companies.len()],
                [] as [(&str, Value); 0],
            );
        }
        g
    }

    /// A stub that reports a node total but **no** per-label / per-type breakdown, to exercise the
    /// unknown-count fallback path deterministically.
    struct StubStats {
        nodes: u64,
        rels: u64,
    }

    impl Statistics for StubStats {
        fn total_nodes(&self) -> u64 {
            self.nodes
        }
        fn nodes_with_label(&self, _label: &str) -> Option<u64> {
            None
        }
        fn total_relationships(&self) -> u64 {
            self.rels
        }
        fn relationships_with_type(&self, _rel_type: &str) -> Option<u64> {
            None
        }
    }

    fn all_nodes() -> LogicalOp {
        LogicalOp::AllNodesScan {
            variable: Var::named("n"),
        }
    }

    #[test]
    fn all_nodes_scan_is_total_nodes() {
        let g = seeded_graph();
        let stats = g.statistics();
        assert_eq!(estimate_rows(&all_nodes(), stats), 13.0);
    }

    #[test]
    fn label_scan_uses_known_count() {
        let g = seeded_graph();
        let stats = g.statistics();
        let person = LogicalOp::NodeByLabelScan {
            variable: Var::named("p"),
            label: label("Person"),
        };
        assert_eq!(estimate_rows(&person, stats), 10.0);
        let company = LogicalOp::NodeByLabelScan {
            variable: Var::named("c"),
            label: label("Company"),
        };
        assert_eq!(estimate_rows(&company, stats), 3.0);
    }

    #[test]
    fn label_scan_unknown_label_via_mem_is_exact_zero() {
        // MemGraph knows its full contents, so an absent label is an exact Some(0), not a fallback.
        let g = seeded_graph();
        let stats = g.statistics();
        let missing = LogicalOp::NodeByLabelScan {
            variable: Var::named("x"),
            label: label("DoesNotExist"),
        };
        assert_eq!(estimate_rows(&missing, stats), 0.0);
    }

    #[test]
    fn label_scan_unknown_count_uses_selectivity_fallback() {
        // A stub that does not track per-label counts -> the DEFAULT_LABEL_SELECTIVITY fallback.
        let stub = StubStats {
            nodes: 1_000,
            rels: 5_000,
        };
        let person = LogicalOp::NodeByLabelScan {
            variable: Var::named("p"),
            label: label("Person"),
        };
        let expected = 1_000.0 * DEFAULT_LABEL_SELECTIVITY;
        assert_eq!(estimate_rows(&person, Some(&stub)), expected);
    }

    #[test]
    fn label_scan_no_stats_uses_default_total_and_selectivity() {
        let person = LogicalOp::NodeByLabelScan {
            variable: Var::named("p"),
            label: label("Person"),
        };
        let expected = DEFAULT_TOTAL_NODES * DEFAULT_LABEL_SELECTIVITY;
        assert_eq!(estimate_rows(&person, None), expected);
    }

    #[test]
    fn all_relationships_scan_is_total_relationships() {
        let g = seeded_graph();
        let stats = g.statistics();
        let scan = LogicalOp::AllRelationshipsScan {
            relationship: Var::named("r"),
            from: Var::named("a"),
            to: Var::named("b"),
            direction: crate::ast::RelDirection::LeftToRight,
            types: Vec::new(),
        };
        assert_eq!(estimate_rows(&scan, stats), 9.0);
    }

    #[test]
    fn all_relationships_scan_single_known_type() {
        let g = seeded_graph();
        let stats = g.statistics();
        let scan = LogicalOp::AllRelationshipsScan {
            relationship: Var::named("r"),
            from: Var::named("a"),
            to: Var::named("b"),
            direction: crate::ast::RelDirection::LeftToRight,
            types: vec![rel_type("KNOWS")],
        };
        assert_eq!(estimate_rows(&scan, stats), 5.0);
    }

    #[test]
    fn all_relationships_scan_multi_type_sums_known_counts() {
        let g = seeded_graph();
        let stats = g.statistics();
        let scan = LogicalOp::AllRelationshipsScan {
            relationship: Var::named("r"),
            from: Var::named("a"),
            to: Var::named("b"),
            direction: crate::ast::RelDirection::LeftToRight,
            types: vec![rel_type("KNOWS"), rel_type("WORKS_AT")],
        };
        // 5 KNOWS + 4 WORKS_AT.
        assert_eq!(estimate_rows(&scan, stats), 9.0);
    }

    #[test]
    fn single_hop_expand_is_input_times_average_degree() {
        let g = seeded_graph();
        let stats = g.statistics();
        let expand = LogicalOp::Expand {
            input: Box::new(all_nodes()),
            from: Var::named("n"),
            relationship: Var::named("r"),
            to: Var::named("m"),
            direction: crate::ast::RelDirection::LeftToRight,
            types: Vec::new(),
            range: None,
            prior_rels: Vec::new(),
            rel_props: None,
        };
        // total_nodes (13) * average_degree (9 rels / 13 nodes).
        let expected = 13.0 * (9.0 / 13.0);
        assert!((estimate_rows(&expand, stats) - expected).abs() < 1e-9);
    }

    #[test]
    fn filter_applies_predicate_selectivity() {
        let g = seeded_graph();
        let stats = g.statistics();
        let filter = LogicalOp::Filter {
            input: Box::new(all_nodes()),
            predicate: dummy_expr(),
        };
        let expected = 13.0 * DEFAULT_PREDICATE_SELECTIVITY;
        assert!((estimate_rows(&filter, stats) - expected).abs() < 1e-9);
    }

    #[test]
    fn aggregation_without_keys_is_one() {
        let g = seeded_graph();
        let stats = g.statistics();
        let agg = LogicalOp::Aggregation {
            input: Box::new(all_nodes()),
            group_keys: Vec::new(),
            aggregates: vec![projection_col("c")],
        };
        assert_eq!(estimate_rows(&agg, stats), 1.0);
    }

    #[test]
    fn aggregation_with_keys_is_clamped_into_range() {
        let g = seeded_graph();
        let stats = g.statistics();
        let agg = LogicalOp::Aggregation {
            input: Box::new(all_nodes()),
            group_keys: vec![projection_col("k")],
            aggregates: vec![projection_col("c")],
        };
        // 13 * 0.1 = 1.3, within [1, 13].
        let expected = (13.0 * DEFAULT_DISTINCT_GROUP_RATIO).clamp(1.0, 13.0);
        assert!((estimate_rows(&agg, stats) - expected).abs() < 1e-9);
    }

    #[test]
    fn union_sums_both_branches() {
        let g = seeded_graph();
        let stats = g.statistics();
        let union = LogicalOp::Union {
            left: Box::new(all_nodes()),
            right: Box::new(LogicalOp::NodeByLabelScan {
                variable: Var::named("p"),
                label: label("Person"),
            }),
            all: true,
        };
        // 13 (all nodes) + 10 (Person).
        assert_eq!(estimate_rows(&union, stats), 23.0);
    }

    #[test]
    fn optional_is_at_least_one() {
        let g = seeded_graph();
        let stats = g.statistics();
        // An Argument input estimates 1 row; Optional must keep >= 1.
        let opt = LogicalOp::Optional {
            input: Box::new(LogicalOp::Argument {
                arguments: vec![Var::named("a")],
            }),
            null_variables: vec![Var::named("b")],
        };
        assert_eq!(estimate_rows(&opt, stats), 1.0);
        // And over an empty (zero-row) label scan, still >= 1.
        let opt_empty = LogicalOp::Optional {
            input: Box::new(LogicalOp::NodeByLabelScan {
                variable: Var::named("x"),
                label: label("DoesNotExist"),
            }),
            null_variables: vec![Var::named("b")],
        };
        assert_eq!(estimate_rows(&opt_empty, stats), 1.0);
    }

    #[test]
    fn apply_multiplies_left_by_right() {
        let g = seeded_graph();
        let stats = g.statistics();
        let apply = LogicalOp::Apply {
            // left: Person scan (10 rows).
            left: Box::new(LogicalOp::NodeByLabelScan {
                variable: Var::named("p"),
                label: label("Person"),
            }),
            // right: a Company scan (3 rows) — independence heuristic gives 10 * 3.
            right: Box::new(LogicalOp::NodeByLabelScan {
                variable: Var::named("c"),
                label: label("Company"),
            }),
        };
        assert_eq!(estimate_rows(&apply, stats), 30.0);
    }

    #[test]
    fn skip_and_limit_read_integer_literals() {
        let g = seeded_graph();
        let stats = g.statistics();
        let skip = LogicalOp::Skip {
            input: Box::new(all_nodes()),
            count: int_expr(3),
        };
        assert_eq!(estimate_rows(&skip, stats), 10.0); // 13 - 3.

        let limit = LogicalOp::Limit {
            input: Box::new(all_nodes()),
            count: int_expr(5),
        };
        assert_eq!(estimate_rows(&limit, stats), 5.0); // min(13, 5).

        // SKIP beyond the input floors at 0.
        let skip_all = LogicalOp::Skip {
            input: Box::new(all_nodes()),
            count: int_expr(100),
        };
        assert_eq!(estimate_rows(&skip_all, stats), 0.0);
    }

    #[test]
    fn skip_and_limit_non_literal_pass_through() {
        let g = seeded_graph();
        let stats = g.statistics();
        // A parameter count is not a literal, so SKIP/LIMIT pass the input through.
        let skip = LogicalOp::Skip {
            input: Box::new(all_nodes()),
            count: Expr::new(ExprKind::Parameter("n".to_owned()), span()),
        };
        assert_eq!(estimate_rows(&skip, stats), 13.0);
    }

    #[test]
    fn unwind_and_loadcsv_multiply_by_defaults() {
        let unwind = LogicalOp::Unwind {
            input: Box::new(LogicalOp::Empty),
            list: dummy_expr(),
            variable: Var::named("x"),
        };
        assert_eq!(estimate_rows(&unwind, None), DEFAULT_LIST_LENGTH); // Empty (1) * default.

        let load = LogicalOp::LoadCsv {
            input: Box::new(LogicalOp::Empty),
            with_headers: true,
            url: dummy_expr(),
            variable: Var::named("row"),
            field_terminator: None,
        };
        assert_eq!(estimate_rows(&load, None), DEFAULT_CSV_RECORDS);
    }

    #[test]
    fn distinct_projection_reduces_non_distinct_passes_through() {
        let g = seeded_graph();
        let stats = g.statistics();
        let plain = LogicalOp::Projection {
            input: Box::new(all_nodes()),
            items: vec![projection_col("n")],
            distinct: false,
        };
        assert_eq!(estimate_rows(&plain, stats), 13.0);

        let distinct = LogicalOp::Projection {
            input: Box::new(all_nodes()),
            items: vec![projection_col("n")],
            distinct: true,
        };
        let expected = 13.0 * DEFAULT_DISTINCT_PROJECTION_RATIO;
        assert!((estimate_rows(&distinct, stats) - expected).abs() < 1e-9);
    }

    #[test]
    fn variable_length_expand_is_finite_and_bounded() {
        // An unbounded `*` expand must never produce inf/NaN.
        let stub = StubStats {
            nodes: 100,
            rels: 1_000, // average degree 10.
        };
        let expand = LogicalOp::Expand {
            input: Box::new(all_nodes()),
            from: Var::named("n"),
            relationship: Var::named("r"),
            to: Var::named("m"),
            direction: crate::ast::RelDirection::LeftToRight,
            types: Vec::new(),
            range: Some(VarLengthRange {
                min: None,
                max: None,
                exact: false,
            }),
            prior_rels: Vec::new(),
            rel_props: None,
        };
        let rows = estimate_rows(&expand, Some(&stub));
        assert!(rows.is_finite(), "variable-length estimate must be finite");
        assert!(rows >= 0.0);
    }

    #[test]
    fn estimate_is_never_nan_or_infinite() {
        // A degenerate stub (zero nodes/rels) must still yield a finite, non-negative estimate.
        let stub = StubStats { nodes: 0, rels: 0 };
        let expand = LogicalOp::Expand {
            input: Box::new(all_nodes()),
            from: Var::named("n"),
            relationship: Var::named("r"),
            to: Var::named("m"),
            direction: crate::ast::RelDirection::LeftToRight,
            types: Vec::new(),
            range: Some(VarLengthRange {
                min: Some(1),
                max: None,
                exact: false,
            }),
            prior_rels: Vec::new(),
            rel_props: None,
        };
        let rows = estimate_rows(&expand, Some(&stub));
        assert!(rows.is_finite() && !rows.is_nan() && rows >= 0.0);
    }

    // =============================================================================================
    // Filter selectivity: property-histogram path and fallback matrix (sub-task #81)
    // =============================================================================================

    /// A `var.key` property-access expression.
    fn prop(var: &str, key: &str) -> Expr {
        Expr::new(
            ExprKind::Property {
                base: Box::new(Expr::new(ExprKind::Variable(var.to_owned()), span())),
                key: key.to_owned(),
            },
            span(),
        )
    }

    /// A binary expression `lhs <op> rhs`.
    fn binary(op: crate::ast::BinaryOp, lhs: Expr, rhs: Expr) -> Expr {
        Expr::new(
            ExprKind::Binary {
                op,
                lhs: Box::new(lhs),
                rhs: Box::new(rhs),
            },
            span(),
        )
    }

    /// A `:Person` label scan binding `p`.
    fn person_scan() -> LogicalOp {
        LogicalOp::NodeByLabelScan {
            variable: Var::named("p"),
            label: label("Person"),
        }
    }

    /// 100 `:Person` nodes with `age` uniformly `0..100` (every value distinct, so the true equality
    /// count is exactly 1 and a range `[lo, hi)` count is exactly `hi - lo`).
    fn age_graph() -> MemGraph {
        let mut g = MemGraph::new();
        for i in 0..100 {
            g.add_node(["Person"], [("age", Value::Integer(i))]);
        }
        g
    }

    #[test]
    fn distinct_label_property_values_is_exact() {
        // 100 distinct ages -> 100 distinct indexed values.
        let g = age_graph();
        assert_eq!(g.distinct_label_property_values("Person", "age"), Some(100));
        // An absent column on a present label is an exact empty histogram (Some(0)), not unknown.
        assert_eq!(g.distinct_label_property_values("Person", "ghost"), Some(0));
        // A value method is None only for an unindexable query value.
        assert_eq!(
            g.estimate_nodes_label_property_eq("Person", "age", &Value::Null),
            None
        );
        assert_eq!(
            g.estimate_nodes_label_property_eq("Person", "age", &Value::List(vec![])),
            None
        );
    }

    #[test]
    fn filter_equality_uses_histogram() {
        let g = age_graph();
        let stats = g.statistics();
        // WHERE p.age = 42  over  (:Person) — 100 distinct values, true count == 1.
        let filter = LogicalOp::Filter {
            input: Box::new(person_scan()),
            predicate: binary(crate::ast::BinaryOp::Eq, prop("p", "age"), int_expr(42)),
        };
        let est = estimate_rows(&filter, stats);
        let input_rows = estimate_rows(&person_scan(), stats);
        // The histogram's equality estimate is count/distinct per bucket; with all-distinct values it
        // is ~1, and never exceeds the input (100). Bound generously around the true count of 1.
        assert!(
            est <= input_rows,
            "filter never adds rows ({est} <= {input_rows})"
        );
        assert!(
            (0.5..=2.0).contains(&est),
            "equality estimate {est} should track the true count of 1"
        );
        // It must differ from the flat fallback (100 * 0.3 = 30), proving the histogram path fired.
        assert!(
            (est - input_rows * DEFAULT_PREDICATE_SELECTIVITY).abs() > 1.0,
            "histogram estimate {est} must not equal the constant fallback"
        );
    }

    #[test]
    fn filter_equality_mirrored_literal_on_left() {
        // WHERE 42 = p.age — the mirrored form is recognised identically.
        let g = age_graph();
        let stats = g.statistics();
        let filter = LogicalOp::Filter {
            input: Box::new(person_scan()),
            predicate: binary(crate::ast::BinaryOp::Eq, int_expr(42), prop("p", "age")),
        };
        let est = estimate_rows(&filter, stats);
        assert!(
            (0.5..=2.0).contains(&est),
            "mirrored equality estimate {est} ~ 1"
        );
    }

    #[test]
    fn filter_range_tracks_true_filtered_count() {
        let g = age_graph();
        let stats = g.statistics();
        // WHERE p.age >= 50 — true count is 50 (ages 50..100).
        let filter = LogicalOp::Filter {
            input: Box::new(person_scan()),
            predicate: binary(crate::ast::BinaryOp::Gte, prop("p", "age"), int_expr(50)),
        };
        let est = estimate_rows(&filter, stats);
        let input_rows = estimate_rows(&person_scan(), stats);
        assert!(est <= input_rows, "filter never adds rows");
        // The equi-depth range estimate contributes half a bucket per partially-covered boundary, so
        // it is within ~one bucket depth of the true 50. With 100 rows over <=64 buckets a bucket
        // holds >=2 rows; allow a generous +/-15 band around the true count.
        assert!(
            (35.0..=65.0).contains(&est),
            "range estimate {est} should track the true filtered count of 50"
        );
    }

    #[test]
    fn filter_range_mirrored_form() {
        // WHERE 50 <= p.age  ==  p.age >= 50 — true count 50.
        let g = age_graph();
        let stats = g.statistics();
        let filter = LogicalOp::Filter {
            input: Box::new(person_scan()),
            predicate: binary(crate::ast::BinaryOp::Lte, int_expr(50), prop("p", "age")),
        };
        let est = estimate_rows(&filter, stats);
        assert!(
            (35.0..=65.0).contains(&est),
            "mirrored range estimate {est} ~ 50"
        );
    }

    #[test]
    fn filter_equality_value_outside_range_is_zero() {
        // WHERE p.age = 9999 — no node matches; an empty/out-of-range equality is an exact 0.
        let g = age_graph();
        let stats = g.statistics();
        let filter = LogicalOp::Filter {
            input: Box::new(person_scan()),
            predicate: binary(crate::ast::BinaryOp::Eq, prop("p", "age"), int_expr(9999)),
        };
        assert_eq!(estimate_rows(&filter, stats), 0.0);
    }

    #[test]
    fn filter_no_stats_uses_constant_fallback() {
        // With no statistics, the input is the default total and the filter applies the constant.
        let filter = LogicalOp::Filter {
            input: Box::new(person_scan()),
            predicate: binary(crate::ast::BinaryOp::Eq, prop("p", "age"), int_expr(42)),
        };
        let input_rows = estimate_rows(&person_scan(), None);
        let expected = input_rows * DEFAULT_PREDICATE_SELECTIVITY;
        assert!((estimate_rows(&filter, None) - expected).abs() < 1e-9);
    }

    #[test]
    fn filter_stub_stats_without_histogram_falls_back() {
        // StubStats returns None for the property methods (the default impl), so even a perfectly
        // formed property predicate falls back to the constant selectivity.
        let stub = StubStats {
            nodes: 1_000,
            rels: 0,
        };
        let filter = LogicalOp::Filter {
            // Person scan over the stub: per-label count is unknown -> 1000 * 0.1 = 100.
            input: Box::new(person_scan()),
            predicate: binary(crate::ast::BinaryOp::Eq, prop("p", "age"), int_expr(42)),
        };
        let input_rows = estimate_rows(&person_scan(), Some(&stub));
        let expected = input_rows * DEFAULT_PREDICATE_SELECTIVITY;
        assert!((estimate_rows(&filter, Some(&stub)) - expected).abs() < 1e-9);
    }

    #[test]
    fn filter_non_property_predicate_falls_back() {
        // A boolean-literal predicate is not a property comparison -> constant fallback.
        let g = age_graph();
        let stats = g.statistics();
        let filter = LogicalOp::Filter {
            input: Box::new(person_scan()),
            predicate: dummy_expr(),
        };
        let input_rows = estimate_rows(&person_scan(), stats);
        let expected = input_rows * DEFAULT_PREDICATE_SELECTIVITY;
        assert!((estimate_rows(&filter, stats) - expected).abs() < 1e-9);
    }

    #[test]
    fn filter_input_not_label_scan_falls_back() {
        // The property predicate is well-formed, but the variable is bound by an AllNodesScan (no
        // label), so no per-label histogram applies -> constant fallback.
        let g = age_graph();
        let stats = g.statistics();
        let filter = LogicalOp::Filter {
            input: Box::new(LogicalOp::AllNodesScan {
                variable: Var::named("p"),
            }),
            predicate: binary(crate::ast::BinaryOp::Eq, prop("p", "age"), int_expr(42)),
        };
        let input_rows = estimate_rows(
            &LogicalOp::AllNodesScan {
                variable: Var::named("p"),
            },
            stats,
        );
        let expected = input_rows * DEFAULT_PREDICATE_SELECTIVITY;
        assert!((estimate_rows(&filter, stats) - expected).abs() < 1e-9);
    }

    #[test]
    fn filter_non_literal_operand_falls_back() {
        // p.age = $param — a parameter has no value at planning time -> constant fallback.
        let g = age_graph();
        let stats = g.statistics();
        let param = Expr::new(ExprKind::Parameter("p".to_owned()), span());
        let filter = LogicalOp::Filter {
            input: Box::new(person_scan()),
            predicate: binary(crate::ast::BinaryOp::Eq, prop("p", "age"), param),
        };
        let input_rows = estimate_rows(&person_scan(), stats);
        let expected = input_rows * DEFAULT_PREDICATE_SELECTIVITY;
        assert!((estimate_rows(&filter, stats) - expected).abs() < 1e-9);
    }

    #[test]
    fn filter_estimate_is_finite_nonneg_and_bounded() {
        // The histogram path always yields a finite, non-negative estimate <= the input.
        let g = age_graph();
        let stats = g.statistics();
        let input_rows = estimate_rows(&person_scan(), stats);
        for k in [0, 1, 50, 99, 1000] {
            let filter = LogicalOp::Filter {
                input: Box::new(person_scan()),
                predicate: binary(crate::ast::BinaryOp::Lt, prop("p", "age"), int_expr(k)),
            };
            let est = estimate_rows(&filter, stats);
            assert!(
                est.is_finite() && est >= 0.0,
                "estimate {est} must be finite >= 0"
            );
            assert!(
                est <= input_rows,
                "estimate {est} must not exceed input {input_rows}"
            );
        }
    }

    #[test]
    fn filter_resolves_label_through_intervening_op() {
        // p is bound by a label scan two hops down (under a Sort); the label resolver must still find
        // it, so the histogram path fires (estimate ~ 1, not the constant 30).
        let g = age_graph();
        let stats = g.statistics();
        let sorted = LogicalOp::Sort {
            input: Box::new(person_scan()),
            keys: Vec::new(),
        };
        let filter = LogicalOp::Filter {
            input: Box::new(sorted),
            predicate: binary(crate::ast::BinaryOp::Eq, prop("p", "age"), int_expr(42)),
        };
        let est = estimate_rows(&filter, stats);
        assert!(
            (0.5..=2.0).contains(&est),
            "label resolved through Sort; histogram estimate {est} ~ 1"
        );
    }
}
