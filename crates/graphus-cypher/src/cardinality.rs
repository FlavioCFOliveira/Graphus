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
//! later sub-task wires that estimate into a cost model; sub-task #81 replaces the constant predicate
//! selectivity below with property histograms.
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

use crate::ast::{ExprKind, Literal, VarLengthRange};
use crate::logical::LogicalOp;
use crate::statistics::Statistics;

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

/// Selectivity assumed for a single [`Filter`](LogicalOp::Filter) predicate of unknown form.
///
/// `0.3` is the classic textbook default for an unknown predicate with no histogram (System R used
/// `1/3` for an inequality and similar magic constants throughout; `0.3` is the widely-cited rounded
/// value). It is intentionally a *guess*: sub-task #81 replaces it with property-histogram-driven
/// selectivities. Until then it keeps a filtered estimate strictly below its input (a filter never
/// adds rows) while leaving a meaningful fraction.
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
fn total_nodes(stats: Option<&dyn Statistics>) -> f64 {
    stats.map_or(DEFAULT_TOTAL_NODES, |s| s.total_nodes() as f64)
}

/// The total relationship count: the statistics value, or [`DEFAULT_TOTAL_RELATIONSHIPS`].
fn total_relationships(stats: Option<&dyn Statistics>) -> f64 {
    stats.map_or(DEFAULT_TOTAL_RELATIONSHIPS, |s| {
        s.total_relationships() as f64
    })
}

/// The average node out-degree: `total_relationships / max(1, total_nodes)`.
///
/// `max(1, _)` guards against division by zero on an empty graph; with zero nodes the degree is
/// simply the relationship total (a degenerate but finite value).
fn average_degree(stats: Option<&dyn Statistics>) -> f64 {
    let nodes = total_nodes(stats).max(1.0);
    total_relationships(stats) / nodes
}

/// Forces an estimate into the documented invariant: finite and `>= 0.0`.
///
/// A `NaN` collapses to `0.0` (the safe, smallest sensible count); a positive infinity clamps to
/// [`f64::MAX`] and a negative value clamps to `0.0`. This is the single choke point that upholds the
/// "never `NaN`, never infinite, never negative" guarantee in [`estimate_rows`].
fn clamp_estimate(x: f64) -> f64 {
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
fn literal_row_count(expr: &crate::ast::Expr) -> Option<f64> {
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
fn average_path_length(range: &VarLengthRange) -> f64 {
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

        // ---- relational ---------------------------------------------------------------------------

        // A filter keeps a documented fraction of its input (a filter never adds rows).
        LogicalOp::Filter { input, .. } => estimate(input, stats) * DEFAULT_PREDICATE_SELECTIVITY,

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
        };
        let rows = estimate_rows(&expand, Some(&stub));
        assert!(rows.is_finite() && !rows.is_nan() && rows >= 0.0);
    }
}
