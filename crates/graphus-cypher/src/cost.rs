//! The Cypher **cost model** — a pure function from a [physical plan](crate::physical) node to an
//! estimated `(rows, cost)` pair (`00-overview` §6; `04 §6.6`, task #65).
//!
//! Where the [cardinality estimator](crate::cardinality) answers "how many rows does this *logical*
//! operator emit?", this module answers "how many rows does this *physical* operator emit, and how
//! much work does producing them cost?". The two are deliberately consistent: the row half of a
//! [`CostEstimate`] reuses the cardinality estimator's formulas and constants (degrees, label/type
//! counts, histogram selectivity), refined with the **physical specialisations** the logical plan
//! does not have — an index seek touches only its matched rows where a label-scan-plus-filter touches
//! the whole label, a hash join's cost depends on which side it builds, a nested-loop join pays for
//! every left×right pair.
//!
//! The cost is an **abstract IO/CPU proxy**, not wall-clock time: the absolute numbers are
//! meaningless, only their *ordering* matters. The model is calibrated so that, for the same logical
//! result,
//!
//! * a **selective index seek** costs less than the equivalent **label scan + residual filter**;
//! * a **hash join** building its **smaller** input costs less than building its larger input;
//! * a **hash equi-join** costs less than the equivalent **nested-loop** (cartesian) join.
//!
//! Those three orderings are exactly the levers the [cost-based optimiser](crate::physical) pulls, and
//! each is asserted in this module's tests. Every constant below is documented with the rationale that
//! keeps the ordering true.
//!
//! # Determinism and totality
//!
//! [`estimate_cost`] is pure and total: it never panics, never allocates beyond a bounded recursion,
//! and — like the cardinality estimator — guarantees both fields are **finite and `>= 0.0`** (every
//! arithmetic result is funnelled through the same clamp the cardinality estimator uses). Given the
//! same physical tree and the same statistics it returns the same estimate, so the optimiser's
//! cost-tie-breaking is deterministic.

use crate::ast::{Expr, RelType};
use crate::cardinality::{
    DEFAULT_CSV_RECORDS, DEFAULT_DISTINCT_GROUP_RATIO, DEFAULT_DISTINCT_PROJECTION_RATIO,
    DEFAULT_LABEL_SELECTIVITY, DEFAULT_LIST_LENGTH, DEFAULT_PREDICATE_SELECTIVITY,
    DEFAULT_PROCEDURE_YIELD, average_degree, average_path_length, clamp_estimate,
    literal_row_count, total_nodes, total_relationships,
};
use crate::physical::{PhysicalOp, RangeBound};
use crate::statistics::Statistics;

// =================================================================================================
// Cost constants (abstract IO/CPU proxies — only the *ordering* between them is meaningful)
// =================================================================================================

/// Per-row cost of a **full or label store scan** — the work of touching one record on a sequential
/// access path ([`AllNodesScan`](PhysicalOp::AllNodesScan) /
/// [`NodeByLabelScan`](PhysicalOp::NodeByLabelScan) /
/// [`AllRelationshipsScan`](PhysicalOp::AllRelationshipsScan)).
///
/// `1.0` is the model's unit of work: every other constant is expressed relative to it. A scan pays
/// this for **every** row it examines, which is what makes an unselective scan expensive against a
/// selective seek (which pays it only per *matched* row, plus a one-off setup).
pub const COST_ROW_SCAN: f64 = 1.0;

/// One-off **setup cost** of an index seek ([`NodeIndexSeek`](PhysicalOp::NodeIndexSeek) /
/// [`NodeIndexRangeSeek`](PhysicalOp::NodeIndexRangeSeek) /
/// [`TokenLookupScan`](PhysicalOp::TokenLookupScan)) — the B-tree descent to the first matching key.
///
/// `2.0` (a couple of scan-rows' worth) models the logarithmic descent into the index before the
/// matched range is streamed. It is paid **once**, independent of how many rows match, so a seek that
/// returns few rows stays far cheaper than a scan over the whole label even after the setup — but a
/// seek that matches *almost everything* is not free, which is what lets a non-selective predicate
/// prefer the scan.
pub const COST_SEEK_SETUP: f64 = 2.0;

/// Per-**matched**-row cost of streaming a property index seek's results — the cost of a *random*
/// heap access per qualifying entry (the index gives a row pointer; fetching the row is a scattered
/// read).
///
/// Deliberately **more expensive than a sequential scan-plus-filter row** (`2.0` vs
/// `COST_ROW_SCAN + COST_ROW_FILTER = 1.5`): a seek pays worse locality per row, but touches only the
/// *matched* rows. This is the classic index/scan trade-off — the seek wins by **avoiding the
/// non-matching rows**, not by being cheaper per matched row. The crossover follows directly:
/// `COST_SEEK_SETUP + matched·2.0  <  all·1.5` holds only while `matched` is well below `all`, so a
/// **selective** predicate picks the seek and a **non-selective** one (the histogram says it matches
/// most rows) reverts to the sequential scan — exactly the seek-vs-scan rule the optimiser implements.
pub const COST_SEEK_PER_ROW: f64 = 2.0;

/// Per-row cost of a [`TokenLookupScan`](PhysicalOp::TokenLookupScan) — streaming a whole label's
/// nodes **sequentially** from the token-lookup index.
///
/// Cheaper than [`COST_ROW_SCAN`] (`0.8` vs `1.0`): unlike a property seek, a token-lookup scan is a
/// *sequential* range read in index order (no random heap hops), and it visits **only** the label's
/// nodes rather than filtering a full-store scan — so it beats a [`NodeByLabelScan`](PhysicalOp::NodeByLabelScan)
/// over the same label while still scaling with the label's size. (It does not use [`COST_SEEK_PER_ROW`]:
/// that models random per-matched-row access, which a full-label sequential stream does not pay.)
pub const COST_TOKEN_SCAN_PER_ROW: f64 = 0.8;

/// Per-build-row cost of a [`HashJoin`](PhysicalOp::HashJoin) — hashing one left row and **inserting**
/// it into the hash table.
///
/// `1.5`: building is the dominant phase of a hash join — an insert allocates a bucket entry and may
/// trigger a rehash, strictly more work than a probe's single lookup. Making it **more expensive than
/// [`COST_HASH_PROBE`]** is what gives the optimiser a reason to **build the smaller side**: with
/// `build` the lower-cardinality input, the heavier `COST_HASH_BUILD · |build|` term is minimised.
/// Equal build/probe costs would make build-side selection a no-op (the total is symmetric), so this
/// gap is load-bearing for the build-side rewrite — and physically faithful.
pub const COST_HASH_BUILD: f64 = 1.5;

/// Per-probe-row cost of a [`HashJoin`](PhysicalOp::HashJoin) — hashing one right row and **looking it
/// up** in the table.
///
/// `1.0`: a probe is a single hash + bucket walk, cheaper than an insert (see [`COST_HASH_BUILD`]).
/// Build and probe are individually linear, so the whole hash join is `O(|left| + |right|)` —
/// dramatically below the nested-loop's `O(|left|·|right|)` for any non-trivial input, which is
/// exactly why an equi-join lowers to a hash join.
pub const COST_HASH_PROBE: f64 = 1.0;

/// Per-(left × right)-**pair** cost of a [`NestedLoopJoin`](PhysicalOp::NestedLoopJoin) — evaluating
/// the right branch against one left row.
///
/// Deliberately `1.0` *per pair*: because the model multiplies it by `|left| · |right|`, a nested-loop
/// join is **quadratic** while the hash join is linear, so the cost model always prefers a hash join
/// for an equi-join. A nested-loop is only chosen when it must be (a correlated apply, which the
/// optimiser never reorders) or when there is genuinely no shared key (a cartesian product, where no
/// hash join is even expressible).
pub const COST_NL_PAIR: f64 = 1.0;

/// Per-expanded-edge cost of an [`ExpandAll`](PhysicalOp::ExpandAll) /
/// [`ExpandInto`](PhysicalOp::ExpandInto) traversal.
///
/// `1.0` per traversed relationship: an expand's cost scales with the number of edges it walks (its
/// output cardinality), the standard model for a neighbourhood traversal.
pub const COST_EXPAND_EDGE: f64 = 1.0;

/// Per-input-row cost of a [`Filter`](PhysicalOp::Filter) predicate evaluation.
///
/// `0.5`: evaluating a residual predicate is cheaper than a full row scan but not free. A filter pays
/// this for every row of its **input** (it must test them all), not its smaller output — which is part
/// of why `scan + filter` loses to a selective seek that never produces the rejected rows.
pub const COST_ROW_FILTER: f64 = 0.5;

/// Per-row cost of a [`Projection`](PhysicalOp::Projection) (and similar shape-only relational
/// operators: [`Skip`](PhysicalOp::Skip), [`Limit`](PhysicalOp::Limit), [`Unwind`](PhysicalOp::Unwind)
/// row emission, [`NamedPath`](PhysicalOp::NamedPath), [`Optional`](PhysicalOp::Optional)).
///
/// `0.1`: forming an output tuple is cheap relative to IO and joins. It is small enough that these
/// "passthrough-ish" operators never dominate a cost comparison (so the optimiser's decisions turn on
/// access paths and joins, where the real cost lives) yet non-zero so a deeper plan is never modelled
/// as *exactly* as cheap as a shallower one.
pub const COST_ROW_PROJECT: f64 = 0.1;

/// Per-row cost of a sort comparison contribution for [`Sort`](PhysicalOp::Sort) /
/// [`TopN`](PhysicalOp::TopN), applied as `n · ln(n)` (the comparison count of a comparison sort).
///
/// `0.2` per `n·ln n` unit: sorting is super-linear, so it is modelled above the linear passthrough
/// operators but the constant is modest because a single key comparison is cheap. `TopN` uses the same
/// per-comparison constant against its (bounded) heap size, so a `TopN` over a `LIMIT k` is cheaper
/// than a full sort, matching the rule-based `Sort`+`Limit` → `TopN` fusion.
pub const COST_SORT_PER_ROW_LOG: f64 = 0.2;

// =================================================================================================
// Public estimate
// =================================================================================================

/// A physical operator's estimated output size and the proxy cost of producing it.
///
/// Both fields are guaranteed **finite and `>= 0.0`** (clamped, like every cardinality estimate).
/// `cost` is cumulative — it includes the cost of every input subtree — so the `cost` of a plan's root
/// is the cost of the whole plan, which is the quantity the
/// [cost-based optimiser](crate::physical) minimises.
#[derive(Debug, Clone, Copy, PartialEq)]
#[must_use]
pub struct CostEstimate {
    /// The estimated number of rows this operator emits (its output cardinality).
    pub rows: f64,
    /// The cumulative proxy cost of producing those rows (this operator's own work plus the cost of
    /// all its inputs).
    pub cost: f64,
}

impl CostEstimate {
    /// A clamped estimate (both fields forced finite and non-negative).
    fn new(rows: f64, cost: f64) -> Self {
        Self {
            rows: clamp_estimate(rows),
            cost: clamp_estimate(cost),
        }
    }
}

/// Estimates the `(rows, cost)` of producing the output of physical operator `op`, reading graph shape
/// from the optional [`Statistics`].
///
/// The walk is bottom-up: each operator's estimate folds in the estimates of its inputs (so the root's
/// `cost` is the whole-plan cost). With `stats = None` the cardinality half uses the cardinality
/// estimator's documented `DEFAULT_*` fallbacks, exactly as [`estimate_rows`](crate::cardinality::estimate_rows)
/// does; the resulting costs are still ordered correctly, they are simply scaled against the default
/// totals.
///
/// Both returned fields are finite and `>= 0.0`.
///
/// # Examples
///
/// ```
/// use graphus_cypher::cost::estimate_cost;
/// use graphus_cypher::logical::Var;
/// use graphus_cypher::physical::PhysicalOp;
///
/// let scan = PhysicalOp::AllNodesScan { variable: Var::named("n") };
/// let est = estimate_cost(&scan, None);
/// assert!(est.rows.is_finite() && est.rows >= 0.0);
/// assert!(est.cost.is_finite() && est.cost >= 0.0);
/// ```
// `CostEstimate` is itself `#[must_use]`, so the return value is already guarded (no attribute here).
pub fn estimate_cost(op: &PhysicalOp, stats: Option<&dyn Statistics>) -> CostEstimate {
    match op {
        // ---- leaf access paths --------------------------------------------------------------------

        // A full node scan: one row per node, one scan-row of work each.
        PhysicalOp::AllNodesScan { .. } => {
            let rows = total_nodes(stats);
            CostEstimate::new(rows, rows * COST_ROW_SCAN)
        }

        // A label store scan: the exact per-label count (or the documented selectivity fallback), and
        // a scan-row of work per *scanned* node. Modelled as touching the whole label's worth of rows
        // (a label store scan visits every node of the label), which equals its output here.
        PhysicalOp::NodeByLabelScan { label, .. } => {
            let rows = label_scan_rows(&label.name, stats);
            CostEstimate::new(rows, rows * COST_ROW_SCAN)
        }

        // A token-lookup index scan: same output as a label scan, but it streams the label's nodes
        // sequentially from the token index rather than filtering a full store scan. It still emits the
        // whole label, so its cost is a seek setup plus a *sequential* per-row stream cost — strictly
        // cheaper than the equivalent NodeByLabelScan over a sizeable label.
        PhysicalOp::TokenLookupScan { label, .. } => {
            let rows = label_scan_rows(&label.name, stats);
            CostEstimate::new(rows, COST_SEEK_SETUP + rows * COST_TOKEN_SCAN_PER_ROW)
        }

        // An equality index seek: the histogram's equality estimate for the *concrete* seek value (or
        // the documented fallback), and a one-off setup plus a cheap per-matched-row stream. Using the
        // real value is what makes the seek-vs-scan decision selectivity-driven: a value that matches
        // almost the whole label costs nearly a full scan, so the optimiser prefers the plain scan.
        PhysicalOp::NodeIndexSeek {
            label,
            property,
            value,
            ..
        } => {
            let rows = seek_eq_rows(&label.name, property, value, stats);
            CostEstimate::new(rows, COST_SEEK_SETUP + rows * COST_SEEK_PER_ROW)
        }

        // A precise equality-filtered label scan (`rmp` task #325): it visits *every* node of the label
        // (full-scan work, like a `NodeByLabelScan`) but **emits** only the equality-selective rows — so
        // its row estimate is the seek's selective estimate while its cost is the full label scan. This
        // correctly keeps it no cheaper than a bare label scan in CPU work (it has no index to narrow the
        // read), yet its smaller output shrinks the cost of anything above it.
        PhysicalOp::NodeLabelScanEq {
            label,
            property,
            value,
            ..
        } => {
            let scanned = label_scan_rows(&label.name, stats);
            let rows = seek_eq_rows(&label.name, property, value, stats).min(scanned);
            CostEstimate::new(rows, scanned * COST_ROW_SCAN)
        }

        // A range index seek: the histogram's range estimate for the concrete bound + value (or the
        // fallback), same cost shape as the equality seek.
        PhysicalOp::NodeIndexRangeSeek {
            label,
            property,
            bound,
            value,
            ..
        } => {
            let rows = seek_range_rows(&label.name, property, *bound, value, stats);
            CostEstimate::new(rows, COST_SEEK_SETUP + rows * COST_SEEK_PER_ROW)
        }

        // A spatial proximity seek (`rmp` task #73): the grid returns a geometric superset of the
        // matching nodes, so — absent dedicated spatial histograms — we estimate its candidate count
        // with the same constant predicate-selectivity fallback a `label-scan + filter` would use,
        // and pay the seek setup plus a cheap per-candidate stream. This keeps the seek cheaper than
        // the full label scan it replaces while staying conservative (the residual `distance` filter
        // above it then trims the superset to the exact result).
        PhysicalOp::SpatialIndexSeek { label, .. } => {
            let rows = label_scan_rows(&label.name, stats) * DEFAULT_PREDICATE_SELECTIVITY;
            CostEstimate::new(rows, COST_SEEK_SETUP + rows * COST_SEEK_PER_ROW)
        }

        // A relationship scan: one row per relationship (refined by listed types), a scan-row each.
        PhysicalOp::AllRelationshipsScan { types, .. } => {
            let rows = rel_scan_rows(types, stats);
            CostEstimate::new(rows, rows * COST_ROW_SCAN)
        }

        // The correlated-apply argument leaf is a single row, produced for free (it is the outer row
        // handed in).
        PhysicalOp::Argument { .. } => CostEstimate::new(1.0, 0.0),

        // The neutral single-row input, free.
        PhysicalOp::Empty => CostEstimate::new(1.0, 0.0),

        // ---- graph traversal ----------------------------------------------------------------------

        // Expand multiplies the input by the average degree (compounded over a var-length range), and
        // pays one edge-cost per emitted edge.
        PhysicalOp::ExpandAll {
            input,
            types,
            range,
            ..
        }
        | PhysicalOp::ExpandInto {
            input,
            types,
            range,
            ..
        } => {
            let inner = estimate_cost(input, stats);
            let degree = typed_degree(types, stats);
            let rows = match range {
                None => inner.rows * degree,
                Some(r) => inner.rows * degree.powf(average_path_length(r)),
            };
            CostEstimate::new(rows, inner.cost + rows * COST_EXPAND_EDGE)
        }

        // A shortest-path BFS explores up to ~degree^avg_len edges per source row but yields a single
        // path (`shortestPath`) or a small number (`allShortestPaths`) — so its cardinality is modelled
        // as a passthrough of the input while its cost reflects the bounded traversal.
        PhysicalOp::ShortestPath {
            input,
            types,
            range,
            ..
        } => {
            let inner = estimate_cost(input, stats);
            let degree = typed_degree(types, stats);
            let explored = inner.rows * degree.powf(average_path_length(range));
            CostEstimate::new(inner.rows, inner.cost + explored * COST_EXPAND_EDGE)
        }

        // A named path binds one path value per input row — cardinality unchanged, a cheap per-row
        // projection.
        PhysicalOp::NamedPath { input, .. } => passthrough(input, stats, COST_ROW_PROJECT),

        // ---- relational ---------------------------------------------------------------------------

        // A filter keeps a fraction of its input and pays a predicate evaluation per *input* row.
        PhysicalOp::Filter { input, .. } => {
            let inner = estimate_cost(input, stats);
            let rows = inner.rows * DEFAULT_PREDICATE_SELECTIVITY;
            CostEstimate::new(rows, inner.cost + inner.rows * COST_ROW_FILTER)
        }

        // A projection is one output row per input row (DISTINCT de-duplicates a fraction); a cheap
        // per-row tuple build.
        PhysicalOp::Projection {
            input, distinct, ..
        } => {
            let inner = estimate_cost(input, stats);
            let rows = if *distinct {
                inner.rows * DEFAULT_DISTINCT_PROJECTION_RATIO
            } else {
                inner.rows
            };
            CostEstimate::new(rows, inner.cost + inner.rows * COST_ROW_PROJECT)
        }

        // Aggregation: one row with no keys, else input·ratio clamped into [1, input]; cost is a
        // per-input-row grouping probe (modelled as the project constant).
        PhysicalOp::Aggregation {
            input, group_keys, ..
        } => {
            let inner = estimate_cost(input, stats);
            let rows = if group_keys.is_empty() {
                1.0
            } else {
                (inner.rows * DEFAULT_DISTINCT_GROUP_RATIO).clamp(1.0, inner.rows.max(1.0))
            };
            CostEstimate::new(rows, inner.cost + inner.rows * COST_ROW_PROJECT)
        }

        // A full sort: rows unchanged, an n·ln(n) comparison cost.
        PhysicalOp::Sort { input, .. } => {
            let inner = estimate_cost(input, stats);
            CostEstimate::new(inner.rows, inner.cost + sort_cost(inner.rows))
        }

        // TopN keeps at most `limit` rows; the comparison cost is bounded by the (smaller) kept set —
        // n·ln(k) — so a TopN(k) is cheaper than a full Sort over the same input, matching the
        // rule-based Sort+Limit fusion.
        PhysicalOp::TopN { input, limit, .. } => {
            let inner = estimate_cost(input, stats);
            let k = literal_row_count(limit).unwrap_or(inner.rows);
            let rows = inner.rows.min(k);
            // Maintaining a bounded heap of size k over n rows costs ~ n·ln(max(k,2)).
            let cost = inner.cost + topn_cost(inner.rows, rows);
            CostEstimate::new(rows, cost)
        }

        // SKIP removes a literal prefix; pass-through cost.
        PhysicalOp::Skip { input, count } => {
            let inner = estimate_cost(input, stats);
            let rows = match literal_row_count(count) {
                Some(n) => (inner.rows - n).max(0.0),
                None => inner.rows,
            };
            CostEstimate::new(rows, inner.cost + inner.rows * COST_ROW_PROJECT)
        }

        // LIMIT keeps at most a literal count; pass-through cost.
        PhysicalOp::Limit { input, count } => {
            let inner = estimate_cost(input, stats);
            let rows = match literal_row_count(count) {
                Some(n) => inner.rows.min(n),
                None => inner.rows,
            };
            CostEstimate::new(rows, inner.cost + inner.rows * COST_ROW_PROJECT)
        }

        // An eager barrier drains its input fully; row count and cost pass through (it only changes
        // *when* the input runs, not how much it costs).
        PhysicalOp::Eager { input } => {
            let inner = estimate_cost(input, stats);
            CostEstimate::new(inner.rows, inner.cost)
        }

        // UNWIND multiplies by an average list length; one tuple build per emitted element.
        PhysicalOp::Unwind { input, .. } => {
            let inner = estimate_cost(input, stats);
            let rows = inner.rows * DEFAULT_LIST_LENGTH;
            CostEstimate::new(rows, inner.cost + rows * COST_ROW_PROJECT)
        }

        // LOAD CSV streams a file per driving row; a scan-row of work per record (it is IO, not a cheap
        // projection).
        PhysicalOp::LoadCsv { input, .. } => {
            let inner = estimate_cost(input, stats);
            let rows = inner.rows * DEFAULT_CSV_RECORDS;
            CostEstimate::new(rows, inner.cost + rows * COST_ROW_SCAN)
        }

        // ---- joins --------------------------------------------------------------------------------

        // A hash join: build the LEFT side, probe with the RIGHT. Output is the equi-join estimate; the
        // cost is build·|left| + probe·|right| plus both input costs. Because build dominates, the
        // optimiser builds the smaller side (lower |left|) to minimise this.
        PhysicalOp::HashJoin {
            left,
            right,
            join_keys,
        } => {
            let l = estimate_cost(left, stats);
            let r = estimate_cost(right, stats);
            let rows = hash_join_rows(l.rows, r.rows, join_keys.len(), stats);
            let cost = l.cost + r.cost + l.rows * COST_HASH_BUILD + r.rows * COST_HASH_PROBE;
            CostEstimate::new(rows, cost)
        }

        // A nested-loop join: for each left row, re-evaluate the right branch. Output is the product
        // (cartesian) or the correlated estimate; the cost is the quadratic |left|·|right| pair cost
        // plus inputs — always above the equivalent hash join, which is why an equi-join never lowers
        // here.
        PhysicalOp::NestedLoopJoin { left, right } => {
            let l = estimate_cost(left, stats);
            let r = estimate_cost(right, stats);
            let rows = l.rows * r.rows;
            let cost = l.cost + r.cost + l.rows * r.rows * COST_NL_PAIR;
            CostEstimate::new(rows, cost)
        }

        // UNION concatenates both branches (sum of rows); cost is both inputs plus a per-row emit.
        PhysicalOp::Union { left, right, .. } => {
            let l = estimate_cost(left, stats);
            let r = estimate_cost(right, stats);
            let rows = l.rows + r.rows;
            CostEstimate::new(rows, l.cost + r.cost + rows * COST_ROW_PROJECT)
        }

        // OPTIONAL guarantees at least one row per drive; cheap per-row.
        PhysicalOp::Optional { input, .. } => {
            let inner = estimate_cost(input, stats);
            CostEstimate::new(
                inner.rows.max(1.0),
                inner.cost + inner.rows * COST_ROW_PROJECT,
            )
        }

        // ---- write --------------------------------------------------------------------------------

        // Write clauses run once per input row and emit ~one row each: cardinality passes through, with
        // a per-row write cost (modelled as a scan-row — a write touches the store).
        PhysicalOp::Create { input, .. }
        | PhysicalOp::Merge { input, .. }
        | PhysicalOp::SetClause { input, .. }
        | PhysicalOp::Delete { input, .. }
        | PhysicalOp::Remove { input, .. } => {
            let inner = estimate_cost(input, stats);
            CostEstimate::new(inner.rows, inner.cost + inner.rows * COST_ROW_SCAN)
        }

        // FOREACH passes each input row through unchanged (cardinality = input's), but runs the body
        // sub-plan once per (input row, list element). Model the body's per-element cost over an
        // assumed list length, so a body of heavy writes is costed proportionally to the iterations.
        PhysicalOp::Foreach { input, body, .. } => {
            let inner = estimate_cost(input, stats);
            let body_cost = estimate_cost(body, stats).cost;
            let iterations = inner.rows * DEFAULT_LIST_LENGTH;
            CostEstimate::new(inner.rows, inner.cost + iterations * body_cost)
        }

        // ---- procedure ----------------------------------------------------------------------------

        // A correlated call yields a default per driving row; a leading call yields the default once.
        // Cost is a per-yielded-row projection over the (unknowable) procedure output.
        PhysicalOp::ProcedureCall { input, .. } => match input {
            Some(inner) => {
                let inner = estimate_cost(inner, stats);
                let rows = inner.rows * DEFAULT_PROCEDURE_YIELD;
                CostEstimate::new(rows, inner.cost + rows * COST_ROW_PROJECT)
            }
            None => CostEstimate::new(
                DEFAULT_PROCEDURE_YIELD,
                DEFAULT_PROCEDURE_YIELD * COST_ROW_PROJECT,
            ),
        },
    }
}

// =================================================================================================
// Cardinality helpers (the physical specialisations; the rest reuse cardinality.rs formulas)
// =================================================================================================

/// Rows a label scan emits: the exact per-label count, or the documented selectivity fallback.
fn label_scan_rows(label: &str, stats: Option<&dyn Statistics>) -> f64 {
    stats
        .and_then(|s| s.nodes_with_label(label))
        .map(|c| c as f64)
        .unwrap_or_else(|| total_nodes(stats) * DEFAULT_LABEL_SELECTIVITY)
}

/// Rows an equality index seek for the concrete `value` emits: the histogram's equality estimate
/// (clamped to the label count so a stale histogram can never exceed the input), or — when no
/// histogram exists, or `value` is a non-literal / unindexable expression — the same
/// constant-selectivity fallback a `label-scan + filter` would use, so the seek-vs-scan comparison is
/// fair when statistics are absent.
fn seek_eq_rows(label: &str, property: &str, value: &Expr, stats: Option<&dyn Statistics>) -> f64 {
    let label_rows = label_scan_rows(label, stats);
    let estimate = stats
        .zip(literal_value(value))
        .and_then(|(s, v)| s.estimate_nodes_label_property_eq(label, property, &v));
    match estimate {
        Some(rows) => rows.clamp(0.0, label_rows),
        None => label_rows * DEFAULT_PREDICATE_SELECTIVITY,
    }
}

/// Rows a range index seek for the concrete `bound`/`value` emits: the histogram's range estimate
/// (clamped to the label count), or the constant-selectivity fallback when no histogram exists or
/// `value` is non-literal / unindexable. Translating the one-sided [`RangeBound`] into the histogram's
/// `(lo, lo_inclusive, hi, hi_inclusive)` vocabulary mirrors the cardinality estimator exactly.
fn seek_range_rows(
    label: &str,
    property: &str,
    bound: RangeBound,
    value: &Expr,
    stats: Option<&dyn Statistics>,
) -> f64 {
    let label_rows = label_scan_rows(label, stats);
    let estimate = stats.zip(literal_value(value)).and_then(|(s, v)| {
        let (lo, lo_inc, hi, hi_inc) = range_bound_to_histogram_args(bound, &v);
        s.estimate_nodes_label_property_range(label, property, lo, lo_inc, hi, hi_inc)
    });
    match estimate {
        Some(rows) => rows.clamp(0.0, label_rows),
        None => label_rows * DEFAULT_PREDICATE_SELECTIVITY,
    }
}

/// Translates a one-sided [`RangeBound`] over `value` into the histogram seam's
/// `(lo, lo_inclusive, hi, hi_inclusive)` argument tuple. A `>`/`>=` bound is a low bound (high side
/// open); a `<`/`<=` bound is a high bound (low side open). Mirrors `cardinality::RangeBound::as_range`.
fn range_bound_to_histogram_args(
    bound: RangeBound,
    value: &graphus_core::Value,
) -> (
    Option<&graphus_core::Value>,
    bool,
    Option<&graphus_core::Value>,
    bool,
) {
    match bound {
        RangeBound::GreaterThan => (Some(value), false, None, true),
        RangeBound::GreaterOrEqual => (Some(value), true, None, true),
        RangeBound::LessThan => (None, true, Some(value), false),
        RangeBound::LessOrEqual => (None, true, Some(value), true),
    }
}

/// Converts a **bare** scalar literal seek-value expression to an index-encodable
/// [`graphus_core::Value`], or `None` for a parameter / computed / unindexable expression (the caller
/// then uses the constant-selectivity fallback, since the histogram cannot be queried without a value).
/// Mirrors the cardinality estimator's `literal_value` so the two recognise the same literals.
fn literal_value(expr: &Expr) -> Option<graphus_core::Value> {
    use crate::ast::{ExprKind, Literal};
    use graphus_core::Value;
    match &expr.kind {
        ExprKind::Literal(Literal::Integer(i)) => Some(Value::Integer(*i)),
        ExprKind::Literal(Literal::Float(f)) => Some(Value::Float(*f)),
        ExprKind::Literal(Literal::String(s)) => Some(Value::String(s.clone())),
        ExprKind::Literal(Literal::Boolean(b)) => Some(Value::Boolean(*b)),
        _ => None,
    }
}

/// Rows a relationship scan emits (mirrors the cardinality estimator's `AllRelationshipsScan` arm).
fn rel_scan_rows(types: &[RelType], stats: Option<&dyn Statistics>) -> f64 {
    if types.is_empty() {
        total_relationships(stats)
    } else {
        types.iter().map(|t| typed_rel_count(&t.name, stats)).sum()
    }
}

/// The count of relationships of one type: the exact per-type count, or the documented fallback.
fn typed_rel_count(rel_type: &str, stats: Option<&dyn Statistics>) -> f64 {
    stats
        .and_then(|s| s.relationships_with_type(rel_type))
        .map(|c| c as f64)
        .unwrap_or_else(|| total_relationships(stats) * DEFAULT_LABEL_SELECTIVITY)
}

/// The expand fan-out degree: graph-wide average when no types are listed, else (sum of those types'
/// counts) / total_nodes (mirrors the cardinality estimator's `Expand` arm).
fn typed_degree(types: &[RelType], stats: Option<&dyn Statistics>) -> f64 {
    if types.is_empty() {
        average_degree(stats)
    } else {
        let nodes = total_nodes(stats).max(1.0);
        let typed: f64 = types.iter().map(|t| typed_rel_count(&t.name, stats)).sum();
        typed / nodes
    }
}

/// The output cardinality of an equi-join (or cartesian product when there are no keys), under the
/// independence assumption.
///
/// With `key_count == 0` the join is a cartesian product: `|left| · |right|`. With shared keys, the
/// classic equi-join estimate is `|left| · |right| / max(distinct keys)`; lacking per-key distinct
/// statistics here we approximate the join-key domain by the larger side's cardinality (the standard
/// "the larger relation bounds the distinct join-key values" heuristic), giving
/// `|left|·|right| / max(|left|,|right|)  =  min(|left|, |right|)`. That is the well-known result that
/// a key-preserving equi-join of two relations produces about `min` rows — independent of which side
/// builds, so the **output** is build-side-invariant (only the *cost* differs), preserving the result
/// bag.
fn hash_join_rows(left: f64, right: f64, key_count: usize, stats: Option<&dyn Statistics>) -> f64 {
    let _ = stats;
    if key_count == 0 {
        left * right
    } else {
        left.min(right)
    }
}

/// `n · ln(max(n, 2))` scaled by [`COST_SORT_PER_ROW_LOG`] — a comparison sort's work over `n` rows.
fn sort_cost(n: f64) -> f64 {
    n * n.max(2.0).ln() * COST_SORT_PER_ROW_LOG
}

/// `n · ln(max(k, 2))` scaled by [`COST_SORT_PER_ROW_LOG`] — maintaining a bounded heap of size `k`
/// over `n` input rows (the TopN work). With `k < n` this is below [`sort_cost`], so TopN is the
/// cheaper realisation of `Sort` + `Limit`.
fn topn_cost(n: f64, k: f64) -> f64 {
    n * k.max(2.0).ln() * COST_SORT_PER_ROW_LOG
}

/// A row-count-preserving operator: rows pass through, cost adds `per_row · rows` of input work.
fn passthrough(input: &PhysicalOp, stats: Option<&dyn Statistics>, per_row: f64) -> CostEstimate {
    let inner = estimate_cost(input, stats);
    CostEstimate::new(inner.rows, inner.cost + inner.rows * per_row)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ast::{Expr, ExprKind, Label, Literal};
    use crate::catalog::IndexId;
    use crate::graph_access::{GraphAccess, MemGraph};
    use crate::lexer::Span;
    use crate::logical::Var;
    use graphus_core::Value;

    fn span() -> Span {
        Span::new(0, 0)
    }

    fn label(name: &str) -> Label {
        Label {
            name: name.to_owned(),
            span: span(),
        }
    }

    fn int_expr(n: i64) -> Expr {
        Expr::new(ExprKind::Literal(Literal::Integer(n)), span())
    }

    /// 1000 `:Person` (every `age` distinct over 0..1000) and 5 `:Company`. A deliberately skewed
    /// distribution so the cost differences are large and unambiguous.
    fn skewed_graph() -> MemGraph {
        let mut g = MemGraph::new();
        for i in 0..1000 {
            g.add_node(["Person"], [("age", Value::Integer(i))]);
        }
        for i in 0..5 {
            g.add_node(["Company"], [("id", Value::Integer(i))]);
        }
        g
    }

    fn person_label_scan() -> PhysicalOp {
        PhysicalOp::NodeByLabelScan {
            variable: Var::named("p"),
            label: label("Person"),
        }
    }

    fn person_seek() -> PhysicalOp {
        PhysicalOp::NodeIndexSeek {
            variable: Var::named("p"),
            label: label("Person"),
            property: "age".to_owned(),
            value: int_expr(42),
            index: IndexId(0),
        }
    }

    #[test]
    fn estimate_is_always_finite_and_nonnegative() {
        let g = skewed_graph();
        let stats = g.statistics();
        for op in [
            PhysicalOp::AllNodesScan {
                variable: Var::named("n"),
            },
            person_label_scan(),
            person_seek(),
        ] {
            let e = estimate_cost(&op, stats);
            assert!(e.rows.is_finite() && e.rows >= 0.0, "rows {:?}", e);
            assert!(e.cost.is_finite() && e.cost >= 0.0, "cost {:?}", e);
        }
        // And with no statistics.
        let e = estimate_cost(&person_seek(), None);
        assert!(e.rows.is_finite() && e.cost.is_finite());
    }

    #[test]
    fn selective_seek_costs_less_than_label_scan_plus_filter() {
        // The acceptance property: a NodeIndexSeek returning few rows is cheaper than the
        // NodeByLabelScan + Filter over the same selective predicate.
        let g = skewed_graph();
        let stats = g.statistics();

        let seek = person_seek();
        let scan_filter = PhysicalOp::Filter {
            input: Box::new(person_label_scan()),
            predicate: Expr::new(
                ExprKind::Binary {
                    op: crate::ast::BinaryOp::Eq,
                    lhs: Box::new(Expr::new(
                        ExprKind::Property {
                            base: Box::new(Expr::new(ExprKind::Variable("p".to_owned()), span())),
                            key: "age".to_owned(),
                        },
                        span(),
                    )),
                    rhs: Box::new(int_expr(42)),
                },
                span(),
            ),
        };

        let seek_cost = estimate_cost(&seek, stats).cost;
        let scan_cost = estimate_cost(&scan_filter, stats).cost;
        assert!(
            seek_cost < scan_cost,
            "seek {seek_cost} should be cheaper than scan+filter {scan_cost}"
        );
        // The seek's row estimate tracks the true equality count (~1 over 1000 distinct ages).
        let seek_rows = estimate_cost(&seek, stats).rows;
        assert!(
            seek_rows <= 5.0,
            "selective equality seek estimate {seek_rows} should be tiny"
        );
    }

    #[test]
    fn hash_join_building_smaller_side_is_cheaper() {
        // Building the small (Company, 5 rows) side beats building the large (Person, 1000 rows) side.
        let g = skewed_graph();
        let stats = g.statistics();
        let person = person_label_scan();
        let company = PhysicalOp::NodeByLabelScan {
            variable: Var::named("c"),
            label: label("Company"),
        };

        let build_small = PhysicalOp::HashJoin {
            left: Box::new(company.clone()),
            right: Box::new(person.clone()),
            join_keys: vec!["k".to_owned()],
        };
        let build_large = PhysicalOp::HashJoin {
            left: Box::new(person),
            right: Box::new(company),
            join_keys: vec!["k".to_owned()],
        };

        let small = estimate_cost(&build_small, stats);
        let large = estimate_cost(&build_large, stats);
        assert!(
            small.cost < large.cost,
            "build-small {} should cost less than build-large {}",
            small.cost,
            large.cost
        );
        // The output bag is build-side invariant: both estimate the same row count.
        assert!(
            (small.rows - large.rows).abs() < 1e-9,
            "join output is symmetric"
        );
    }

    #[test]
    fn hash_join_is_cheaper_than_nested_loop_for_equi_join() {
        let g = skewed_graph();
        let stats = g.statistics();
        let person = person_label_scan();
        let company = PhysicalOp::NodeByLabelScan {
            variable: Var::named("c"),
            label: label("Company"),
        };

        let hash = PhysicalOp::HashJoin {
            left: Box::new(company.clone()),
            right: Box::new(person.clone()),
            join_keys: vec!["k".to_owned()],
        };
        let nl = PhysicalOp::NestedLoopJoin {
            left: Box::new(company),
            right: Box::new(person),
        };

        let hash_cost = estimate_cost(&hash, stats).cost;
        let nl_cost = estimate_cost(&nl, stats).cost;
        assert!(
            hash_cost < nl_cost,
            "hash join {hash_cost} should be cheaper than nested-loop {nl_cost}"
        );
    }

    #[test]
    fn topn_is_cheaper_than_full_sort() {
        let g = skewed_graph();
        let stats = g.statistics();
        let keys = Vec::new();
        let sort = PhysicalOp::Sort {
            input: Box::new(person_label_scan()),
            keys: keys.clone(),
        };
        let topn = PhysicalOp::TopN {
            input: Box::new(person_label_scan()),
            keys,
            limit: int_expr(3),
        };
        assert!(
            estimate_cost(&topn, stats).cost < estimate_cost(&sort, stats).cost,
            "TopN must be cheaper than a full Sort over the same input"
        );
    }

    #[test]
    fn token_lookup_scan_beats_label_store_scan() {
        // The token-lookup index streams the label cheaper than a full-store label scan.
        let g = skewed_graph();
        let stats = g.statistics();
        let token = PhysicalOp::TokenLookupScan {
            variable: Var::named("p"),
            label: label("Person"),
            index: IndexId(0),
        };
        assert!(
            estimate_cost(&token, stats).cost < estimate_cost(&person_label_scan(), stats).cost,
            "token-lookup scan should beat the full-store label scan"
        );
        // Same output cardinality either way.
        assert!(
            (estimate_cost(&token, stats).rows - estimate_cost(&person_label_scan(), stats).rows)
                .abs()
                < 1e-9
        );
    }

    #[test]
    fn no_stats_costs_are_ordered_too() {
        // Even without statistics the seek-vs-scan ordering holds (both scale against the defaults).
        let seek = person_seek();
        let scan = person_label_scan();
        // The seek's fallback selectivity (0.3) over the label fallback makes it return fewer rows and
        // cost less than scanning the whole label.
        assert!(estimate_cost(&seek, None).cost < estimate_cost(&scan, None).cost);
    }
}
