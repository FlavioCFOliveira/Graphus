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

use crate::ast::{BinaryOp, Expr, ExprKind, Label, PredicateOp, RelType};
use crate::cardinality::{
    DEFAULT_CSV_RECORDS, DEFAULT_DISTINCT_GROUP_RATIO, DEFAULT_DISTINCT_PROJECTION_RATIO,
    DEFAULT_LABEL_SELECTIVITY, DEFAULT_LIST_LENGTH, DEFAULT_PREDICATE_SELECTIVITY,
    DEFAULT_PROCEDURE_YIELD, average_degree, average_path_length, clamp_estimate,
    literal_row_count, predicate_selectivity, total_nodes, total_relationships,
};
use crate::logical::Var;
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
/// `1.0` per traversed relationship: an expand's cost scales with the number of edges it **walks**,
/// the standard model for a neighbourhood traversal. For an expand-**all** the edges walked are also
/// the rows emitted, so cost and cardinality coincide; for an expand-**into** they do not — it walks
/// the same incidence but emits only the edges landing on the already-bound `to`, so it is charged the
/// full traversal against a much smaller output (see the `ExpandInto` arm of [`estimate_cost`]).
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

        // A multi-value equality seek (`rmp` task #868): `k` independent index descents, unioned. Costed
        // exactly as the task specifies — **`k` seek setups plus the summed matched rows**
        // ([`multi_seek_eq_rows`]) — so `k·COST_SEEK_SETUP` grows linearly in `k` while the scan
        // alternative's cost is fixed at the label's size, and past the crossover
        // `optimize_access_path` reverts a large `IN` list to the scan (the `rmp` #868 acceptance
        // criterion).
        PhysicalOp::NodeIndexMultiSeek {
            label,
            property,
            values,
            ..
        } => {
            let rows = multi_seek_eq_rows(&label.name, property, values, stats);
            let setups = values.len() as f64 * COST_SEEK_SETUP;
            CostEstimate::new(rows, setups + rows * COST_SEEK_PER_ROW)
        }

        // A composite (multi-property) equality seek (`rmp` task #657): the selectivity is the product of
        // the per-key equality selectivities (independence assumption), so a full-key composite seek is
        // highly selective — far cheaper than any single-key seek + residual filters. The estimate is
        // floored at one candidate so the seek stays a cheap-but-nonzero leaf access path.
        PhysicalOp::NodeCompositeIndexSeek {
            label,
            properties,
            values,
            ..
        } => {
            let label_rows = label_scan_rows(&label.name, stats).max(1.0);
            let mut rows = label_rows;
            for (property, value) in properties.iter().zip(values.iter()) {
                let key_sel = seek_eq_rows(&label.name, property, value, stats) / label_rows;
                rows *= key_sel;
            }
            let rows = rows.max(1.0);
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

        // A full property-index scan (`rmp` task #665): serves `IS NOT NULL` by streaming every entry of
        // the order-preserving index for `(label, property)`. Absent per-property null-fraction
        // statistics, its candidate count is estimated as the whole label (the property may be present
        // on every node), and its cost is a seek setup plus a cheap per-candidate index stream —
        // strictly cheaper *per row* than the full store scan a `NodeByLabelScan + Filter` would pay,
        // which is why the index scan wins when the property is sparse.
        PhysicalOp::NodeIndexScan { label, .. } => {
            let rows = label_scan_rows(&label.name, stats);
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

        // A string-prefix seek (`rmp` task #658): the bounded range `[prefix, successor)` returns a
        // superset of the matching strings, so — absent prefix histograms — we estimate its candidate
        // count with the same constant predicate-selectivity fallback a `label-scan + filter` would
        // use, plus the seek setup and a cheap per-candidate stream. This keeps the seek cheaper than
        // the full label scan it replaces while staying conservative (the residual `STARTS WITH`
        // filter above then trims the superset to the exact result).
        PhysicalOp::NodeIndexStartsWithSeek { label, .. } => {
            let rows = label_scan_rows(&label.name, stats) * DEFAULT_PREDICATE_SELECTIVITY;
            CostEstimate::new(rows, COST_SEEK_SETUP + rows * COST_SEEK_PER_ROW)
        }

        // A text (trigram) seek (`rmp` task #662): the trigram intersection returns a superset of the
        // matching strings, so — absent substring-selectivity statistics — we estimate its candidate
        // count with the same constant predicate-selectivity fallback a `label-scan + filter` would
        // use, plus the seek setup and a cheap per-candidate stream. This keeps the seek cheaper than
        // the full label scan it replaces while staying conservative (the residual `CONTAINS` /
        // `ENDS WITH` / `STARTS WITH` filter above then trims the superset to the exact result).
        PhysicalOp::NodeTextIndexSeek { label, .. } => {
            let rows = label_scan_rows(&label.name, stats) * DEFAULT_PREDICATE_SELECTIVITY;
            CostEstimate::new(rows, COST_SEEK_SETUP + rows * COST_SEEK_PER_ROW)
        }

        // A relationship scan: one row per relationship (refined by listed types), a scan-row each. An
        // **undirected** pattern binds each non-self relationship in both orientations (`rmp` task #867
        // — the same two-orientation rule the relationship seeks below apply), so double the row
        // estimate; the *cost* still tracks the rows the operator emits.
        PhysicalOp::AllRelationshipsScan {
            types, direction, ..
        } => {
            let mut rows = rel_scan_rows(types, stats);
            if matches!(direction, crate::ast::RelDirection::Undirected) {
                rows *= 2.0;
            }
            CostEstimate::new(rows, rows * COST_ROW_SCAN)
        }

        // A relationship-property equality seek (`rmp` task #659): absent per-property relationship
        // histograms, estimate its candidate count with the same constant predicate-selectivity a
        // `rel-scan + filter` would use over the single covered type, and pay the seek setup plus a
        // cheap per-candidate stream. An undirected pattern surfaces each relationship twice, so double
        // the estimate to match the scan-path `Filter`-over-`ExpandAll` cardinality it replaces. This
        // keeps the seek cheaper than the full typed relationship scan it replaces while staying
        // conservative (the executor's re-check trims the candidate set to the exact result).
        PhysicalOp::RelIndexSeek {
            rel_type,
            direction,
            ..
        } => {
            let type_slice = std::slice::from_ref(rel_type);
            let mut rows = rel_scan_rows(type_slice, stats) * DEFAULT_PREDICATE_SELECTIVITY;
            if matches!(direction, crate::ast::RelDirection::Undirected) {
                rows *= 2.0;
            }
            CostEstimate::new(rows, COST_SEEK_SETUP + rows * COST_SEEK_PER_ROW)
        }

        // A multi-value relationship-property seek (`rmp` task #868): the relationship analogue of
        // `NodeIndexMultiSeek`, and `k` repetitions of the `RelIndexSeek` arm above. The [`Statistics`]
        // seam exposes NO per-relationship-property histograms, so — like the relationship equality seek
        // above, and like the `IN` `Filter` this replaces — the row estimate is the flat
        // constant-selectivity one, independent of `k`; only the `k` seek setups distinguish the cost.
        // An undirected pattern surfaces each relationship twice, so the estimate is doubled, matching
        // the scan-path cardinality this replaces.
        PhysicalOp::RelIndexMultiSeek {
            rel_type,
            values,
            direction,
            ..
        } => {
            let type_slice = std::slice::from_ref(rel_type);
            let mut rows = rel_scan_rows(type_slice, stats) * DEFAULT_PREDICATE_SELECTIVITY;
            if matches!(direction, crate::ast::RelDirection::Undirected) {
                rows *= 2.0;
            }
            let setups = values.len() as f64 * COST_SEEK_SETUP;
            CostEstimate::new(rows, setups + rows * COST_SEEK_PER_ROW)
        }

        // A relationship-property RANGE seek (`rmp` task #680): the relationship analogue of
        // `NodeIndexRangeSeek`. The [`Statistics`] seam exposes **no** per-relationship-property
        // histograms (`estimate_nodes_label_property_range` is node-only), so — exactly like the
        // relationship *equality* seek above — estimate its candidate count with the constant
        // predicate-selectivity a `rel-scan + filter` would use over the single covered type, and pay the
        // seek setup plus a cheap per-candidate stream. An undirected pattern surfaces each relationship
        // twice, so double the estimate to match the scan-path `Filter`-over-`ExpandAll` cardinality it
        // replaces. This keeps the seek cheaper than the full typed relationship scan it replaces
        // (`COST_SEEK_SETUP + rows·COST_SEEK_PER_ROW` < `type_rows·COST_ROW_SCAN` while the predicate is
        // selective), which is what makes the planner prefer it; the executor's re-check trims the
        // candidate set to the exact result.
        PhysicalOp::RelIndexRangeSeek {
            rel_type,
            direction,
            ..
        } => {
            let type_slice = std::slice::from_ref(rel_type);
            let mut rows = rel_scan_rows(type_slice, stats) * DEFAULT_PREDICATE_SELECTIVITY;
            if matches!(direction, crate::ast::RelDirection::Undirected) {
                rows *= 2.0;
            }
            CostEstimate::new(rows, COST_SEEK_SETUP + rows * COST_SEEK_PER_ROW)
        }

        // A composite (multi-property) relationship equality seek (`rmp` task #666): the selectivity is
        // the product of the per-key constant predicate-selectivities (independence assumption), so a
        // full-key composite relationship seek is far more selective than any single-key seek + residual
        // filters — matching how the node composite seek estimates. An undirected pattern surfaces each
        // relationship twice, so double the estimate; floored at one candidate so the seek stays a
        // cheap-but-nonzero access path.
        PhysicalOp::RelCompositeIndexSeek {
            rel_type,
            properties,
            direction,
            ..
        } => {
            let type_slice = std::slice::from_ref(rel_type);
            let type_rows = rel_scan_rows(type_slice, stats).max(1.0);
            let mut rows = type_rows;
            for _ in properties {
                rows *= DEFAULT_PREDICATE_SELECTIVITY;
            }
            if matches!(direction, crate::ast::RelDirection::Undirected) {
                rows *= 2.0;
            }
            let rows = rows.max(1.0);
            CostEstimate::new(rows, COST_SEEK_SETUP + rows * COST_SEEK_PER_ROW)
        }

        // A relationship spatial proximity seek (`rmp` task #664): the grid returns a geometric superset
        // of the matching relationships, so — absent per-type relationship spatial statistics — estimate
        // its candidate count with the same constant predicate-selectivity a `rel-scan + filter` would
        // use over the single covered type, plus the seek setup and a cheap per-candidate stream, and —
        // like the relationship-property seek — double it for an undirected pattern (each relationship
        // surfaces twice). The residual `distance` filter above trims the superset to the exact result.
        PhysicalOp::RelSpatialIndexSeek {
            rel_type,
            direction,
            ..
        } => {
            let type_slice = std::slice::from_ref(rel_type);
            let mut rows = rel_scan_rows(type_slice, stats) * DEFAULT_PREDICATE_SELECTIVITY;
            if matches!(direction, crate::ast::RelDirection::Undirected) {
                rows *= 2.0;
            }
            CostEstimate::new(rows, COST_SEEK_SETUP + rows * COST_SEEK_PER_ROW)
        }

        // The correlated-apply argument leaf is a single row, produced for free (it is the outer row
        // handed in).
        PhysicalOp::Argument { .. } => CostEstimate::new(1.0, 0.0),

        // The neutral single-row input, free.
        PhysicalOp::Empty => CostEstimate::new(1.0, 0.0),

        // ---- graph traversal ----------------------------------------------------------------------

        // Expand-all multiplies the input by the average degree (compounded over a var-length range),
        // and pays one edge-cost per emitted edge — every edge it walks is an edge it emits.
        PhysicalOp::ExpandAll {
            input,
            from,
            types,
            range,
            direction,
            ..
        } => {
            let inner = estimate_cost(input, stats);
            let degree = anchored_degree(input, from, types, *direction, stats);
            let rows = match range {
                None => inner.rows * degree,
                Some(r) => inner.rows * degree.powf(average_path_length(r)),
            };
            CostEstimate::new(rows, inner.cost + rows * COST_EXPAND_EDGE)
        }

        // Expand-**into** has BOTH endpoints already bound, so it is a *selection*, not a fan-out: it
        // walks the same incidence an expand-all would — and therefore pays the same traversal cost —
        // but emits only the edges that land on the one node `to` is already bound to (`rmp` task
        // #863). Sharing the expand-all arm, as this used to, over-estimated its **output** by the
        // whole degree factor, and every operator costed above it inherited that error, so any plan
        // that closes a cycle looked far more expensive than it is. Rows and cost are different
        // quantities here and only the rows were wrong.
        PhysicalOp::ExpandInto {
            input,
            from,
            to,
            types,
            range,
            direction,
            ..
        } => {
            let inner = estimate_cost(input, stats);
            let degree = anchored_degree(input, from, types, *direction, stats);
            // Edges the traversal actually visits — identical to the expand-all fan-out.
            let walked = match range {
                None => inner.rows * degree,
                Some(r) => inner.rows * degree.powf(average_path_length(r)),
            };
            // Under the estimator's standing uniformity assumption, the chance that a walked neighbour
            // is the specific node `to` is bound to is one in however many nodes `to` could be. That
            // candidate count is the population of `to`'s label when the access path binding it states
            // one (`rmp` task #886, which #863 recorded in-code as the accurate denominator), and the
            // whole graph otherwise — a far looser bound, since a labelled `to` is a much smaller
            // haystack than every node.
            let candidates = physical_label_for_var(input, &to.name)
                .map(|label| label_scan_rows(&label, stats))
                .unwrap_or_else(|| total_nodes(stats));
            let selected = walked / candidates.max(1.0);
            // Floor a fed selection at one row (PostgreSQL's `clamp_row_est`, `costsize.c`: "force a
            // row-count estimate to a sane value ... clamp to one row" ). Without this the fraction
            // above goes sub-unitary on any sizeable graph, and because every operator costed *above*
            // an expand-into multiplies through that fraction, its whole sub-tree would be costed as
            // if it were free — the exact mirror of the over-estimate #863 removes, and just as
            // capable of steering the search wrong. Measured on a closed-triangle ring of 64 nodes:
            // 0.72 estimated against 64 rows produced (`tests/expand_into_selectivity.rs`). An empty
            // input still estimates empty: a selection cannot invent rows it was never fed.
            let rows = if inner.rows >= 1.0 {
                selected.max(1.0)
            } else {
                selected
            };
            CostEstimate::new(rows, inner.cost + walked * COST_EXPAND_EDGE)
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

        // A quantified path pattern is a trail walk that compounds like a var-length expand: it fans
        // out by `degree^(avg edges)` per input row and pays one edge-cost per explored edge. A
        // multi-relationship interior traverses `1 + extra_hops.len()` edges per iteration, so the
        // effective path length scales by the hops-per-iteration.
        PhysicalOp::QuantifiedPath {
            input,
            types,
            extra_hops,
            min,
            max,
            ..
        } => {
            let inner = estimate_cost(input, stats);
            let degree = typed_degree(types, stats);
            let range = crate::ast::VarLengthRange {
                min: Some(*min),
                max: *max,
                exact: false,
            };
            let hops_per_iter = (1 + extra_hops.len()) as f64;
            let rows = inner.rows * degree.powf(average_path_length(&range) * hops_per_iter);
            CostEstimate::new(rows, inner.cost + rows * COST_EXPAND_EDGE)
        }

        // A named path binds one path value per input row — cardinality unchanged, a cheap per-row
        // projection.
        PhysicalOp::NamedPath { input, .. } => passthrough(input, stats, COST_ROW_PROJECT),

        // ---- relational ---------------------------------------------------------------------------

        // A filter keeps a fraction of its input and pays a predicate evaluation per *input* row.
        // A filter keeps the fraction of its input the shared predicate model estimates, and pays one
        // predicate evaluation per input row. Until `rmp` task #864 this arm applied the flat 0.3
        // constant to *every* predicate, so a residual `Filter` shrank its input by exactly 3.3x
        // whatever it tested — including a label check the access path beneath had already guaranteed,
        // which removes nothing. Two such filters in a two-hop pattern under-estimated the downstream
        // cardinality by ~11x (measured; `tests/expand_into_selectivity.rs`), and every cost comparison
        // above them inherited the error.
        PhysicalOp::Filter {
            input, predicate, ..
        } => {
            let inner = estimate_cost(input, stats);
            let resolver = |variable: &str| physical_label_for_var(input, variable);
            let rows = inner.rows * predicate_selectivity(predicate, stats, &resolver);
            let per_row = COST_ROW_FILTER * filter_width(predicate);
            CostEstimate::new(rows, inner.cost + inner.rows * per_row)
        }

        // A semi-join (`rmp` task #869). Before this task the same shape was a `Filter` over an opaque
        // `EXISTS{…}` predicate, which `predicate_selectivity` could say nothing useful about and whose
        // per-row work — a whole correlated sub-plan — was modelled as ONE `COST_ROW_FILTER`. Both
        // numbers are now derived from the branch that actually runs.
        //
        // CARDINALITY. `right.rows` is the estimate for **one** driving row (the branch is rooted at an
        // `Argument`, which the estimator treats as a single row), i.e. the expected number of inner
        // matches per driving row. Capping it at 1 turns that expectation into the probability of "at
        // least one", which is what a semi-join tests: an expectation below 1 is a lower bound on that
        // probability, and above 1 the cap says "near certain". Anti takes the complement, which is
        // sound for the same reason the operator itself is: `EXISTS` is two-valued, so a driving row is
        // either kept by the semi-join or by the anti-, never by both and never by neither.
        //
        // COST. The executor stops the branch at its FIRST row, so a driving row that matches pays only
        // its way to that row — `right.cost / right.rows` amortised — while one that does not match
        // pays the branch out in full. Weighting those two by the same probability is the whole reason
        // a selective `EXISTS` is now cheap in the model and not merely in the executor.
        PhysicalOp::SemiApply {
            input, inner, anti, ..
        } => {
            let left = estimate_cost(input, stats);
            let right = estimate_cost(inner, stats);
            let matches = right.rows.clamp(0.0, 1.0);
            let kept = if *anti { 1.0 - matches } else { matches };
            // `max(1.0)` guards the amortisation against a branch estimated at fewer than one row: the
            // executor still has to run it to discover the first row (or its absence), so the
            // short-circuited cost can never be modelled as more than the full branch.
            let first_row_cost = right.cost / right.rows.max(1.0);
            let per_driving_row = matches * first_row_cost + (1.0 - matches) * right.cost;
            CostEstimate::new(left.rows * kept, left.cost + left.rows * per_driving_row)
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

        // One row, one catalogue read, no per-row work (`rmp` task #866). The fallback subtree's cost is
        // deliberately NOT added: this operator is not a choice the cost model makes — the recognizer
        // wraps a qualifying shape unconditionally and the seam decides at execution time — so charging
        // for a subtree that usually does not run would misprice every plan containing one.
        PhysicalOp::NodeCountFromCountStore { .. }
        | PhysicalOp::RelationshipCountFromCountStore { .. } => {
            CostEstimate::new(1.0, COST_SEEK_SETUP)
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

        // Opening the next statement is likewise a pure barrier (`rmp` #972): it drains its input and
        // bumps a per-transaction counter. Rows and cost pass through unchanged.
        PhysicalOp::AdvanceCommand { input } => {
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
            let rows = hash_join_rows(
                l.rows,
                r.rows,
                join_keys.len(),
                single_key_domain(left, right, join_keys, stats),
                stats,
            );
            let cost = l.cost + r.cost + l.rows * COST_HASH_BUILD + r.rows * COST_HASH_PROBE;
            CostEstimate::new(rows, cost)
        }

        // A value hash join (`rmp` task #865): linear in both inputs, like the name-keyed hash join, and
        // costed the same way. Its OUTPUT is estimated as a single-key equi-join, because that is what
        // it is — one equality between two expressions — regardless of how many columns each side has.
        PhysicalOp::ValueHashJoin { left, right, .. } => {
            let l = estimate_cost(left, stats);
            let r = estimate_cost(right, stats);
            // Its key is an arbitrary *expression*, not a bound node variable, so there is no label
            // whose population bounds the distinct-key count: the key-preserving heuristic stands.
            let rows = hash_join_rows(l.rows, r.rows, 1, None, stats);
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

        // The fused one-hop `OPTIONAL MATCH` (`rmp` task #882) — costed as what it is: an expand,
        // then the inside-`WHERE` predicates, then the left-outer guarantee. Composing the three
        // arms above rather than inventing a formula is the point of the operator existing at all:
        // the `NestedLoopJoin`-over-`Optional` shape it replaces was opaque to the model (a
        // nested-loop over a sub-plan), so the model could not see that the right side is one hop.
        //
        // The guarantee is per DRIVING row, not per plan: an input row whose expansion survives
        // nothing still emits one row, so the output can never fall below `inner.rows` — which is
        // also why a selective predicate here does NOT reduce cardinality the way a `Filter` does.
        PhysicalOp::OptionalExpand {
            input,
            from,
            to,
            types,
            direction,
            into,
            predicates,
            ..
        } => {
            let inner = estimate_cost(input, stats);
            let degree = anchored_degree(input, from, types, *direction, stats);
            let walked = inner.rows * degree;
            // Expand-into is a selection on the already-bound `to`, expand-all a fan-out — the same
            // distinction the `ExpandAll` / `ExpandInto` arms above draw, with the same estimator
            // (`rmp` #863: sharing the fan-out arm over-estimated an expand-into's OUTPUT by the
            // whole degree factor, and everything costed above it inherited the error).
            let expanded = if *into {
                // The expand-into denominator of `rmp` #863/#886: the population `to` could be drawn
                // from — its label's, when the access path binding it states one; the whole graph
                // otherwise.
                let candidates = physical_label_for_var(input, &to.name)
                    .map(|label| label_scan_rows(&label, stats))
                    .unwrap_or_else(|| total_nodes(stats));
                walked / candidates.max(1.0)
            } else {
                walked
            };
            let resolver = |variable: &str| physical_label_for_var(input, variable);
            let selectivity: f64 = predicates
                .iter()
                .map(|p| predicate_selectivity(p, stats, &resolver))
                .product();
            let filter_per_row: f64 = predicates
                .iter()
                .map(|p| COST_ROW_FILTER * filter_width(p))
                .sum();
            let rows = (expanded * selectivity).max(inner.rows);
            let cost = inner.cost
                + walked * COST_EXPAND_EDGE
                + expanded * filter_per_row
                + inner.rows * COST_ROW_PROJECT;
            CostEstimate::new(rows, cost)
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
///
/// Delegates to [`crate::cardinality::label_rows`] so this estimator and the logical one compute a
/// label's population identically — and so the *denominator* of a label predicate's selectivity is the
/// same number as the label scan's row count (`rmp` task #864).
fn label_scan_rows(label: &str, stats: Option<&dyn Statistics>) -> f64 {
    crate::cardinality::label_rows(label, stats)
}

/// The average number of relationships of `types` a row of `input` traverses out of anchor `from` in
/// `direction` (`rmp` task #886).
///
/// Prefers the **directional** degree for the anchor's own label — the `(label, type)` or
/// `(type, label)` counter of task #856, divided by that label's population. Falls back to the
/// graph-wide [`typed_degree`] when the anchor's label is not stated by any access path on the input,
/// when the catalogue carries no directional counters, or for an untyped hop (which has no per-type
/// counter to read).
///
/// The fallback is what keeps the estimate *degrading* rather than failing: a plan over a database that
/// predates the counters, or one never backfilled, is costed exactly as it was before this task.
fn anchored_degree(
    input: &PhysicalOp,
    from: &Var,
    types: &[RelType],
    direction: crate::ast::RelDirection,
    stats: Option<&dyn Statistics>,
) -> f64 {
    let anchor_label = physical_label_for_var(input, &from.name);
    crate::cardinality::directional_degree(anchor_label.as_deref(), types, direction, stats)
        .unwrap_or_else(|| typed_degree(types, stats))
}

/// The label that binds `variable` on this physical plan, if any access path on the spine states one.
///
/// The physical counterpart of the logical estimator's `label_for_var`, and the one input
/// [`crate::cardinality::predicate_selectivity`] cannot derive for itself (`rmp` task #864). Every
/// node access path carries the label it scans or seeks, so a residual `Filter` above one can tell
/// whether it is re-testing a label the access path already guaranteed — the case that produced the
/// worst measured estimate error, since the flat constant charged it a 70% row removal for testing
/// nothing.
///
/// Recursion follows the binding: single-input operators pass through to their child, and a binary
/// operator may bind the variable on either side (the first side that does wins, which is sound because
/// a variable is bound once per plan). A `Union` is deliberately **not** searched: its two branches may
/// bind the same variable through different labels, so no single answer is correct and `None` — the
/// constant fallback — is the honest result.
fn physical_label_for_var(op: &PhysicalOp, variable: &str) -> Option<String> {
    /// Matches an access path's `(variable, label)` pair against the variable being resolved.
    fn bound(v: &Var, label: &Label, variable: &str) -> Option<String> {
        (v.name == variable).then(|| label.name.clone())
    }
    match op {
        // ---- access paths that state a label -------------------------------------------------------
        PhysicalOp::NodeByLabelScan { variable: v, label }
        | PhysicalOp::TokenLookupScan {
            variable: v, label, ..
        }
        | PhysicalOp::NodeIndexSeek {
            variable: v, label, ..
        }
        | PhysicalOp::NodeCompositeIndexSeek {
            variable: v, label, ..
        }
        | PhysicalOp::NodeLabelScanEq {
            variable: v, label, ..
        }
        | PhysicalOp::NodeIndexRangeSeek {
            variable: v, label, ..
        }
        | PhysicalOp::NodeIndexScan {
            variable: v, label, ..
        }
        | PhysicalOp::NodeIndexStartsWithSeek {
            variable: v, label, ..
        }
        | PhysicalOp::SpatialIndexSeek {
            variable: v, label, ..
        }
        | PhysicalOp::NodeTextIndexSeek {
            variable: v, label, ..
        } => bound(v, label, variable),

        // ---- single-input operators: the binding is below ------------------------------------------
        PhysicalOp::ExpandAll { input, .. }
        | PhysicalOp::ExpandInto { input, .. }
        // `rmp` #882: the fused one-hop `OPTIONAL MATCH` states no label of its own; the anchor's
        // (and, for an expand-into, the far endpoint's) label scan is in its driving relation. Listed
        // explicitly rather than left to the `_ => None` catch-all below, which would blind the cost
        // model to every label stated underneath an `OPTIONAL MATCH`.
        | PhysicalOp::OptionalExpand { input, .. }
        // `rmp` #869: same reason, and the same trap. A semi-join states no label of its own — the
        // driving relation does — so it MUST be listed here. Left to the `_ => None` catch-all the cost
        // model would be blind to every label underneath a `WHERE EXISTS { … }`, which is exactly the
        // defect #882 found under `OPTIONAL MATCH`: not a wrong answer, a wrong DECISION, and one no
        // result assertion would ever catch.
        | PhysicalOp::SemiApply { input, .. }
        | PhysicalOp::NamedPath { input, .. }
        | PhysicalOp::ShortestPath { input, .. }
        | PhysicalOp::QuantifiedPath { input, .. }
        | PhysicalOp::Filter { input, .. }
        | PhysicalOp::Projection { input, .. }
        | PhysicalOp::Aggregation { input, .. }
        // `rmp` task #866: recurse into the fallback, so a label stated by the scan underneath a
        // count-store operator is still discoverable.
        | PhysicalOp::NodeCountFromCountStore { fallback: input, .. }
        | PhysicalOp::RelationshipCountFromCountStore { fallback: input, .. }
        | PhysicalOp::Sort { input, .. }
        | PhysicalOp::TopN { input, .. }
        | PhysicalOp::Skip { input, .. }
        | PhysicalOp::Limit { input, .. }
        | PhysicalOp::Eager { input, .. }
        | PhysicalOp::Unwind { input, .. }
        | PhysicalOp::LoadCsv { input, .. }
        | PhysicalOp::Optional { input, .. }
        | PhysicalOp::Create { input, .. }
        | PhysicalOp::Merge { input, .. }
        | PhysicalOp::SetClause { input, .. }
        | PhysicalOp::Delete { input, .. }
        | PhysicalOp::Remove { input, .. }
        | PhysicalOp::Foreach { input, .. } => physical_label_for_var(input, variable),

        // ---- binary operators: either side may bind it ---------------------------------------------
        PhysicalOp::NestedLoopJoin { left, right }
        | PhysicalOp::HashJoin { left, right, .. }
        | PhysicalOp::ValueHashJoin { left, right, .. } => physical_label_for_var(left, variable)
            .or_else(|| physical_label_for_var(right, variable)),

        // ---- leaves and shapes with no single answer -----------------------------------------------
        _ => None,
    }
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

/// How many times more expensive one row of `predicate` is than a plain single-term filter
/// (`rmp` task #868). Multiplies [`COST_ROW_FILTER`] in the [`PhysicalOp::Filter`] estimate.
///
/// # Why this exists
///
/// `x IN [e₁ … e_k]` is defined as the `OR`-fold of `=` over the list, so a `Filter` carrying it does
/// **`k` comparisons per row**, not one — the residual filter of a reverted multi-value seek costs
/// `O(rows · k)` while the seek it replaced costs `O(k)` descents. Charging every filter a flat
/// per-row constant made the seek-vs-scan comparison claim the scan was cheaper for a large `IN` list
/// on a large label, and the plan it chose was **measured at 39.1 s against the seek's 51 ms** on a
/// 50 000-node label with `k = 20 000` (`rmp` #868). The comparison was not wrong about arithmetic; it
/// was comparing a term it had priced at zero.
///
/// Deliberately narrow: only an `IN` whose right side is a **syntactic list** contributes, and it
/// contributes its own length. Every other predicate — including a conjunction, a disjunction and an
/// `IN` over a parameter — yields exactly `1.0`, so every plan the cost model chose before this task is
/// costed byte-identically and no unrelated plan shape can move.
fn filter_width(predicate: &Expr) -> f64 {
    fn extra_terms(e: &Expr) -> usize {
        match &e.kind {
            // Conjuncts are evaluated in sequence; sum their widths.
            ExprKind::Binary {
                op: BinaryOp::And,
                lhs,
                rhs,
            } => extra_terms(lhs) + extra_terms(rhs),
            ExprKind::Predicate {
                op: PredicateOp::In,
                rhs: Some(list),
                ..
            } => match &list.kind {
                // `k` comparisons instead of one, i.e. `k - 1` extra.
                ExprKind::List(items) => items.len().saturating_sub(1),
                _ => 0,
            },
            _ => 0,
        }
    }
    1.0 + extra_terms(predicate) as f64
}

/// Rows a **multi-value** equality seek emits (`rmp` task #868): the union of the per-value match sets.
///
/// # Why this is not simply `k ×` the single-value estimate
///
/// The row estimate is a property of the **predicate**, not of the access path: the same
/// `n.p IN [a, b, c]` must estimate the same cardinality whether it is realised as this seek or as the
/// residual `Filter` over a scan that [`scan_alternative_for_seek`](crate::physical) reverts it to —
/// otherwise the two realisations would be compared on different row counts and every operator *above*
/// the access path would be mis-costed depending on which one won. So:
///
/// * **With a histogram for every alternative** — sum the per-value equality estimates and clamp to the
///   label. The alternatives are distinct values of a single property, so their match sets are provably
///   disjoint and the sum is the union exactly (the clamp only guards against stale statistics).
/// * **Otherwise** — the flat [`DEFAULT_PREDICATE_SELECTIVITY`], which is precisely what
///   [`predicate_selectivity`](crate::cardinality) gives the equivalent `IN` `Filter` (an `IN` is not a
///   recognised property *comparison*, so it takes the documented constant fallback). Multiplying that
///   constant by `k` instead would claim a 3-element `IN` list matches 90% of the label and would make
///   every multi-value seek lose to the scan the moment statistics existed but histograms did not.
///
/// A single-element list therefore estimates exactly what [`seek_eq_rows`] does, in both branches.
fn multi_seek_eq_rows(
    label: &str,
    property: &str,
    values: &[Expr],
    stats: Option<&dyn Statistics>,
) -> f64 {
    let label_rows = label_scan_rows(label, stats);
    let mut sum = 0.0;
    for value in values {
        let Some(s) = stats else {
            return label_rows * DEFAULT_PREDICATE_SELECTIVITY;
        };
        let Some(v) = literal_value(value) else {
            return label_rows * DEFAULT_PREDICATE_SELECTIVITY;
        };
        let Some(rows) = s.estimate_nodes_label_property_eq(label, property, &v) else {
            return label_rows * DEFAULT_PREDICATE_SELECTIVITY;
        };
        sum += rows;
    }
    // An EMPTY list matches nothing (`x IN []` is FALSE for every `x`), and the loop leaves `sum` at 0 —
    // the estimate the operator's zero descents genuinely produce.
    sum.clamp(0.0, label_rows)
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
/// classic equi-join estimate is `|left| · |right| / max(D_left, D_right)`, where `D_side` is the
/// number of **distinct** join-key values on that side.
///
/// # Why the distinct-key domain needs `key_domain`
///
/// Approximating `max(D_left, D_right)` by `max(|left|, |right|)` — the standard "the larger relation
/// bounds the distinct join-key values" heuristic — reduces the formula to `min(|left|, |right|)`, and
/// that is right only when the key is (nearly) **unique** on the larger side. A graph pattern joined on
/// a shared node is the opposite case: both sides are relationship enumerations, so the same node
/// recurs on each of them and `D` is bounded by the node **population**, not by the row count.
///
/// Measured (`rmp` task #880, on the uniform 100-node digraph of `tests/expand_into_selectivity.rs`):
/// the join under `MATCH (a:Person)-[r1:KNOWS]->(b:Person)-[r2:KNOWS]->(c:Person)` really emits
/// **39 472** rows, and each side estimates 1 980 — so `min(|left|, |right|)` predicted 1 980, a
/// **20x** under-estimate. It propagated into every operator above: the `ExpandInto` on top of it
/// estimated 117.6 rows against 7 741 measured, **65x** out, which is what
/// `uniform_random_graph_estimate_is_within_an_order_of_magnitude` now forbids.
///
/// `key_domain` supplies the missing bound — the population of the join key's label — so the estimate
/// becomes `max( min(|left|,|right|), |left|·|right| / domain )`, which predicts 39 204 against the
/// 39 472 actually emitted (0.7% low). It can only **raise** the estimate, and it collapses to the
/// previous expression exactly when the domain is at least as large as the bigger side (a key that
/// really is unique there), so a join whose key was already being estimated as key-preserving is
/// costed byte-identically.
///
/// # Build-side invariance, and its one precondition
///
/// `min`, `left * right` and `left * right / domain` are all symmetric in the two sides, so swapping
/// build and probe cannot change the output estimate — **provided `key_domain` is itself symmetric**.
/// It is: [`single_key_domain`] resolves the key's label from the left side and falls back to the
/// right, and a variable is bound once per plan, so at most one side can state a label for it and the
/// answer does not depend on which side is asked first. Were that ever to change — two sides
/// disagreeing about the key's label — the estimate would become orientation-dependent while the
/// result bag stayed invariant, which is a defect worth naming here rather than discovering later.
fn hash_join_rows(
    left: f64,
    right: f64,
    key_count: usize,
    key_domain: Option<f64>,
    stats: Option<&dyn Statistics>,
) -> f64 {
    let _ = stats;
    if key_count == 0 {
        return left * right;
    }
    let key_preserving = left.min(right);
    match key_domain {
        // A domain below 1 would divide the product upward without bound; a domain that big means the
        // join key is not repeated at all, which is the key-preserving case already covered.
        Some(domain) if domain >= 1.0 => key_preserving.max(left * right / domain),
        _ => key_preserving,
    }
}

/// How many distinct values a **single**-column join key can take, when that column is a node variable
/// whose label some access path on either side states (`rmp` task #880).
///
/// The bound is the label's population: a join key bound to a `:Person` node cannot take more than
/// `|Person|` distinct values, however many rows carry it. With no label stated the honest bound is the
/// whole node population, which is still a bound — it is only useless when the sides are smaller than
/// the graph, in which case [`hash_join_rows`] falls back to the key-preserving estimate anyway.
///
/// Deliberately restricted to a single key. A composite key's domain is the product of its columns'
/// domains, which no statistic here measures, and using one column's domain for a two-column key would
/// *over*-estimate — the one direction that must not be guessed. A multi-column join therefore keeps
/// the key-preserving estimate it has always had.
fn single_key_domain(
    left: &PhysicalOp,
    right: &PhysicalOp,
    join_keys: &[String],
    stats: Option<&dyn Statistics>,
) -> Option<f64> {
    let [key] = join_keys else {
        return None;
    };
    if let Some(label) =
        physical_label_for_var(left, key).or_else(|| physical_label_for_var(right, key))
    {
        // A label was stated by an access path, which also proves the key is a node column.
        return Some(label_scan_rows(&label, stats));
    }
    // No label stated. The node population is still a bound — but only if the key really is a node.
    // `choose_join` derives its keys from shared column NAMES, and a column can hold a relationship
    // (two `MATCH` clauses may share a relationship variable), for which `total_nodes` is simply the
    // wrong population. Positively identify the key as node-bound before using it; anything not
    // recognised keeps the key-preserving estimate, which is what this function returned before the
    // bound existed.
    if binds_var_as_node(left, key) || binds_var_as_node(right, key) {
        return Some(total_nodes(stats));
    }
    None
}

/// Whether any operator in `op` binds `variable` to a **node**.
///
/// Deliberately positive-only: an operator this does not recognise answers `false`, so the caller
/// falls back to an estimate that needs no domain at all. The alternative polarity — assuming node
/// unless proven otherwise — would silently apply a node population to a relationship column the day a
/// new binding operator was added.
fn binds_var_as_node(op: &PhysicalOp, variable: &str) -> bool {
    let bound_here = match op {
        // Node access paths bind their `variable` as a node.
        PhysicalOp::AllNodesScan { variable: v }
        | PhysicalOp::NodeByLabelScan { variable: v, .. }
        | PhysicalOp::TokenLookupScan { variable: v, .. }
        | PhysicalOp::NodeIndexSeek { variable: v, .. }
        | PhysicalOp::NodeIndexMultiSeek { variable: v, .. }
        | PhysicalOp::NodeCompositeIndexSeek { variable: v, .. }
        | PhysicalOp::NodeLabelScanEq { variable: v, .. }
        | PhysicalOp::NodeIndexRangeSeek { variable: v, .. }
        | PhysicalOp::NodeIndexScan { variable: v, .. }
        | PhysicalOp::NodeIndexStartsWithSeek { variable: v, .. }
        | PhysicalOp::SpatialIndexSeek { variable: v, .. }
        | PhysicalOp::NodeTextIndexSeek { variable: v, .. } => v.name == variable,
        // An expansion binds both endpoints as nodes (its `relationship` is deliberately not matched).
        PhysicalOp::ExpandAll { from, to, .. }
        | PhysicalOp::ExpandInto { from, to, .. }
        | PhysicalOp::OptionalExpand { from, to, .. }
        | PhysicalOp::AllRelationshipsScan { from, to, .. }
        | PhysicalOp::RelIndexSeek { from, to, .. }
        | PhysicalOp::RelIndexMultiSeek { from, to, .. }
        | PhysicalOp::RelIndexRangeSeek { from, to, .. }
        | PhysicalOp::RelCompositeIndexSeek { from, to, .. }
        | PhysicalOp::RelSpatialIndexSeek { from, to, .. } => {
            from.name == variable || to.name == variable
        }
        _ => false,
    };
    bound_here
        || op
            .children()
            .into_iter()
            .any(|child| binds_var_as_node(child, variable))
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
            ordered: false,
            cached_property: false,
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

    // ---- Filter selectivity: histograms and labels, not a flat constant (`rmp` task #864) -----

    /// `p.age = n` as a filter predicate.
    fn age_eq(n: i64) -> Expr {
        Expr::new(
            ExprKind::Binary {
                op: crate::ast::BinaryOp::Eq,
                lhs: Box::new(Expr::new(
                    ExprKind::Property {
                        base: Box::new(Expr::new(ExprKind::Variable("p".to_owned()), span())),
                        key: "age".to_owned(),
                    },
                    span(),
                )),
                rhs: Box::new(int_expr(n)),
            },
            span(),
        )
    }

    /// `p:Name` as a filter predicate.
    fn has_label(name: &str) -> Expr {
        has_label_on("p", name)
    }

    /// `<variable>:Name` as a filter predicate.
    fn has_label_on(variable: &str, name: &str) -> Expr {
        Expr::new(
            ExprKind::HasLabels {
                operand: Box::new(Expr::new(ExprKind::Variable(variable.to_owned()), span())),
                expr: crate::ast::LabelExpr::Leaf {
                    name: name.to_owned(),
                    span: span(),
                },
            },
            span(),
        )
    }

    fn filter_over(input: PhysicalOp, predicate: Expr) -> PhysicalOp {
        PhysicalOp::Filter {
            input: Box::new(input),
            predicate,
        }
    }

    #[test]
    fn label_filter_the_access_path_already_guarantees_removes_nothing() {
        // The worst case the flat 0.3 constant produced: `Filter(p:Person)` directly over a
        // `NodeByLabelScan(p:Person)` re-tests what the scan guaranteed, so it removes NOTHING — yet it
        // was estimated to drop 70% of the rows, and every operator costed above inherited that error.
        let g = skewed_graph();
        let stats = g.statistics();
        let scan_rows = estimate_cost(&person_label_scan(), stats).rows;
        let filtered = estimate_cost(
            &filter_over(person_label_scan(), has_label("Person")),
            stats,
        );
        assert!(scan_rows > 0.0, "premise: the scan must produce rows");
        assert!(
            (filtered.rows - scan_rows).abs() < 1e-9,
            "a redundant label filter must pass everything through: {} of {scan_rows}",
            filtered.rows
        );
        // It is still charged for evaluating the predicate on every row — free rows, not free work.
        assert!(
            filtered.cost > estimate_cost(&person_label_scan(), stats).cost,
            "the filter must still pay its per-row evaluation"
        );
    }

    #[test]
    fn label_filter_for_a_different_label_uses_that_label_population() {
        // A label the access path does NOT guarantee is estimated from its share of all nodes, not from
        // the constant. `Company` is 5 of 1005 nodes in the corpus, so the filter is far MORE selective
        // than the flat 0.3 claimed — the error runs in both directions.
        let g = skewed_graph();
        let stats = g.statistics();
        let scan_rows = estimate_cost(&person_label_scan(), stats).rows;
        let filtered = estimate_cost(
            &filter_over(person_label_scan(), has_label("Company")),
            stats,
        );
        let expected = scan_rows * (5.0 / 1005.0);
        assert!(
            (filtered.rows - expected).abs() < 1e-6,
            "expected {expected} from Company's population share, got {}",
            filtered.rows
        );
        assert!(
            filtered.rows < scan_rows * DEFAULT_PREDICATE_SELECTIVITY,
            "and it must be more selective than the constant it replaced"
        );
    }

    #[test]
    fn property_filter_uses_the_histogram_not_the_constant() {
        // 1000 distinct ages, so an equality keeps about one row — nothing like 30%.
        let g = skewed_graph();
        let stats = g.statistics();
        let scan_rows = estimate_cost(&person_label_scan(), stats).rows;
        let filtered = estimate_cost(&filter_over(person_label_scan(), age_eq(42)), stats);
        assert!(
            filtered.rows <= 5.0,
            "a selective equality must estimate a handful of rows, got {}",
            filtered.rows
        );
        assert!(
            filtered.rows < scan_rows * DEFAULT_PREDICATE_SELECTIVITY,
            "and it must beat the flat constant it replaced"
        );
    }

    #[test]
    fn the_two_estimators_agree_on_the_same_predicate() {
        // The agreement property #864 exists to establish: the physical cost model and the logical
        // cardinality estimator now share ONE predicate model, so the same predicate over an equivalent
        // input must produce the same row estimate. They used to disagree by construction — this module
        // applied a flat constant while `cardinality` resolved histograms.
        use crate::cardinality::estimate_rows;
        use crate::logical::LogicalOp;

        let g = skewed_graph();
        let stats = g.statistics();
        let logical_scan = LogicalOp::NodeByLabelScan {
            variable: Var::named("p"),
            label: label("Person"),
        };
        for (name, predicate) in [
            ("property equality", age_eq(42)),
            ("redundant label", has_label("Person")),
            ("other label", has_label("Company")),
            (
                "conjunction of both",
                Expr::new(
                    ExprKind::Binary {
                        op: crate::ast::BinaryOp::And,
                        lhs: Box::new(age_eq(42)),
                        rhs: Box::new(has_label("Person")),
                    },
                    span(),
                ),
            ),
        ] {
            let physical =
                estimate_cost(&filter_over(person_label_scan(), predicate.clone()), stats).rows;
            let logical = estimate_rows(
                &LogicalOp::Filter {
                    input: Box::new(logical_scan.clone()),
                    predicate,
                },
                stats,
            );
            assert!(
                (physical - logical).abs() < 1e-6,
                "estimators disagree on `{name}`: physical={physical} logical={logical}"
            );
        }
    }

    #[test]
    fn unrecognised_predicate_still_falls_back_to_the_documented_constant() {
        // The constant is kept as the fallback, not deleted. A predicate neither model recognises — here
        // a disjunction, which needs inclusion-exclusion terms this model does not have — must still be
        // costed by it, so the estimator never returns a guessed-at number for a shape it cannot read.
        let g = skewed_graph();
        let stats = g.statistics();
        let scan_rows = estimate_cost(&person_label_scan(), stats).rows;
        let disjunction = Expr::new(
            ExprKind::Binary {
                op: crate::ast::BinaryOp::Or,
                lhs: Box::new(age_eq(1)),
                rhs: Box::new(age_eq(2)),
            },
            span(),
        );
        let filtered = estimate_cost(&filter_over(person_label_scan(), disjunction), stats);
        assert!(
            (filtered.rows - scan_rows * DEFAULT_PREDICATE_SELECTIVITY).abs() < 1e-6,
            "an unrecognised predicate must use the constant: got {} want {}",
            filtered.rows,
            scan_rows * DEFAULT_PREDICATE_SELECTIVITY
        );
    }

    #[test]
    fn filter_selectivity_needs_no_statistics_and_stays_bounded() {
        // With no statistics there is no population to read, so every shape falls back — and must stay
        // finite, non-negative and never above its input, which is what makes the estimate safe to
        // propagate through the operators above it.
        let scan_rows = estimate_cost(&person_label_scan(), None).rows;
        for predicate in [age_eq(42), has_label("Person"), has_label("Company")] {
            let e = estimate_cost(&filter_over(person_label_scan(), predicate), None);
            assert!(e.rows.is_finite() && e.rows >= 0.0, "rows {}", e.rows);
            assert!(
                e.rows <= scan_rows + 1e-9,
                "a filter must never be estimated above its input: {} > {scan_rows}",
                e.rows
            );
        }
    }

    #[test]
    fn a_label_filter_above_an_expand_is_not_charged_a_removal_it_does_not_make() {
        // The measured 11x case, in its real shape: the filtered variable is bound by an EXPAND, not by
        // a label scan, so the access path guarantees nothing and the estimate falls to the label's
        // population share. `connected_graph` is used rather than `skewed_graph` because the latter has
        // no relationships at all — the expand would estimate zero rows and the comparison below would
        // hold vacuously. `Person` is 1002 of its 1007 nodes, so the filter passes ~99.5% through, where
        // the flat constant claimed 30%.
        let g = connected_graph();
        let stats = g.statistics();
        let expand = PhysicalOp::ExpandAll {
            input: Box::new(person_label_scan()),
            from: Var::named("p"),
            relationship: Var::named("r"),
            to: Var::named("q"),
            direction: crate::ast::RelDirection::LeftToRight,
            types: Vec::new(),
            range: None,
            prior_rels: Vec::new(),
            rel_props: None,
            to_predicate: None,
            pruning: false,
        };
        let expand_rows = estimate_cost(&expand, stats).rows;
        assert!(
            expand_rows > 1.0,
            "non-vacuity: the expand must fan out, else the comparison proves nothing (got \
             {expand_rows})"
        );

        // `q` is the expand's TARGET: no access path states its label, so the estimate falls to the
        // label's share of all nodes — 1002 of 1007, so ~99.5% passes through where the flat constant
        // claimed 30%.
        let on_target = estimate_cost(
            &filter_over(expand.clone(), has_label_on("q", "Person")),
            stats,
        )
        .rows;
        let share = 1002.0 / 1007.0;
        assert!(
            (on_target - expand_rows * share).abs() < 1e-6,
            "expected ~{}% pass-through on the expand target, got {on_target} of {expand_rows}",
            share * 100.0
        );
        assert!(
            on_target > expand_rows * 0.9,
            "a label covering nearly every node must pass nearly everything through: {on_target} of \
             {expand_rows}"
        );

        // `p` is the expand's SOURCE, still bound by the label scan below it. Resolution follows the
        // binding through the expand, so this filter is recognised as fully redundant — a stricter
        // answer than the population share, and the one the flat constant got most wrong.
        let on_source =
            estimate_cost(&filter_over(expand, has_label_on("p", "Person")), stats).rows;
        assert!(
            (on_source - expand_rows).abs() < 1e-9,
            "a label the scan below already guarantees must remove nothing: {on_source} of \
             {expand_rows}"
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

    /// 100 `:Hub` nodes, each with ten outgoing `LINKS` — an average degree of ten, so a relationship
    /// enumeration out of the label emits ten times the node population and the join key really does
    /// repeat. (`skewed_graph` has no edges at all, and `connected_graph`'s degree is below one, so
    /// neither can distinguish the two join estimates.)
    fn dense_graph() -> MemGraph {
        /// A typed empty property list, so the property generic infers at the empty case.
        const NO_PROPS_COST: [(&str, Value); 0] = [];
        let mut g = MemGraph::new();
        let ids: Vec<_> = (0..100)
            .map(|i| g.add_node(["Hub"], [("k", Value::Integer(i))]))
            .collect();
        for (i, &from) in ids.iter().enumerate() {
            for step in 1..=10 {
                g.add_rel("LINKS", from, ids[(i + step) % ids.len()], NO_PROPS_COST);
            }
        }
        g
    }

    /// A relationship enumeration out of every `:Hub`, binding `from` and `to`. Two of these joined on
    /// `to` is the shape a pattern cut produces, and the shape whose output the key-preserving heuristic
    /// alone got wrong (`rmp` task #880).
    fn expand_binding(from: &str, to: &str, rel: &str) -> PhysicalOp {
        PhysicalOp::ExpandAll {
            input: Box::new(PhysicalOp::NodeByLabelScan {
                variable: Var::named(from),
                label: label("Hub"),
            }),
            from: Var::named(from),
            relationship: Var::named(rel),
            to: Var::named(to),
            direction: crate::ast::RelDirection::LeftToRight,
            types: Vec::new(),
            range: None,
            prior_rels: Vec::new(),
            rel_props: None,
            to_predicate: None,
            pruning: false,
        }
    }

    #[test]
    fn a_join_key_repeated_on_both_sides_is_not_estimated_key_preserving() {
        // `rmp` task #880. `min(|left|, |right|)` is the equi-join estimate only when the key is nearly
        // UNIQUE on the larger side. Two relationship enumerations meeting on a shared node are the
        // opposite: the same node recurs on each side, so the distinct-key count is bounded by the node
        // population and the join really emits `|left|.|right|/population` rows.
        let g = dense_graph();
        let stats = g.statistics();
        let left = expand_binding("p", "t", "r1");
        let right = expand_binding("q", "t", "r2");
        let join = PhysicalOp::HashJoin {
            left: Box::new(left.clone()),
            right: Box::new(right.clone()),
            join_keys: vec!["t".to_owned()],
        };
        let l = estimate_cost(&left, stats).rows;
        let r = estimate_cost(&right, stats).rows;
        let joined = estimate_cost(&join, stats).rows;
        assert!(
            joined >= l.min(r),
            "the domain bound may only RAISE the estimate: {joined} against min {}",
            l.min(r)
        );
        assert!(
            joined > l.min(r) * 1.001,
            "a key repeated on both sides must estimate above the key-preserving figure: {joined} \
             against min {}",
            l.min(r)
        );
        // And the output is still independent of which side builds.
        let swapped = PhysicalOp::HashJoin {
            left: Box::new(right),
            right: Box::new(left),
            join_keys: vec!["t".to_owned()],
        };
        assert!(
            (joined - estimate_cost(&swapped, stats).rows).abs() < 1e-9,
            "join output must stay build-side invariant"
        );
    }

    #[test]
    fn a_multi_column_join_keeps_the_key_preserving_estimate() {
        // The domain of a composite key is the product of its columns' domains, which no statistic here
        // measures — so using one column's domain would OVER-estimate. Such a join is left exactly as it
        // was costed before `rmp` task #880.
        let g = dense_graph();
        let stats = g.statistics();
        let left = expand_binding("p", "t", "r1");
        let right = expand_binding("q", "t", "r2");
        let l = estimate_cost(&left, stats).rows;
        let r = estimate_cost(&right, stats).rows;
        let join = PhysicalOp::HashJoin {
            left: Box::new(left),
            right: Box::new(right),
            join_keys: vec!["t".to_owned(), "r1".to_owned()],
        };
        assert!(
            (estimate_cost(&join, stats).rows - l.min(r)).abs() < 1e-9,
            "a composite key must keep the key-preserving estimate"
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

    // ---- Expand-into is a selection, not a fan-out (`rmp` task #863) -------------------------

    /// Builds an expand over `input` between `from` and `to`; `into` selects expand-into.
    fn expand(
        input: PhysicalOp,
        into: bool,
        range: Option<crate::ast::VarLengthRange>,
    ) -> PhysicalOp {
        let (from, relationship, to) = (Var::named("p"), Var::named("r"), Var::named("q"));
        let types = vec![crate::ast::RelType {
            name: "KNOWS".to_owned(),
            span: span(),
        }];
        if into {
            PhysicalOp::ExpandInto {
                input: Box::new(input),
                from,
                relationship,
                to,
                direction: crate::ast::RelDirection::LeftToRight,
                types,
                range,
                prior_rels: Vec::new(),
                rel_props: None,
            }
        } else {
            PhysicalOp::ExpandAll {
                input: Box::new(input),
                from,
                relationship,
                to,
                direction: crate::ast::RelDirection::LeftToRight,
                types,
                range,
                prior_rels: Vec::new(),
                rel_props: None,
                to_predicate: None,
                pruning: false,
            }
        }
    }

    /// A graph with a real relationship population, so `typed_degree` is not the zero degenerate.
    fn connected_graph() -> MemGraph {
        let mut g = skewed_graph();
        let a = g.add_node(["Person"], [("age", Value::Integer(9999))]);
        let b = g.add_node(["Person"], [("age", Value::Integer(9998))]);
        for _ in 0..500 {
            g.add_rel("KNOWS", a, b, [("w", Value::Integer(1))]);
        }
        g
    }

    #[test]
    fn expand_into_emits_far_fewer_rows_than_expand_all() {
        // Both endpoints are bound, so an expand-into is a connection CHECK: it emits the edges that
        // land on one specific node, not the anchor's whole fan-out. Sharing the expand-all arm made
        // it claim the full degree, and every operator above inherited that over-estimate.
        let g = connected_graph();
        let stats = g.statistics();
        let all = estimate_cost(&expand(person_label_scan(), false, None), stats);
        let into = estimate_cost(&expand(person_label_scan(), true, None), stats);
        assert!(
            into.rows < all.rows,
            "expand-into must emit fewer rows than expand-all: into={} all={}",
            into.rows,
            all.rows
        );
        // Specifically, by the uniformity assumption: one neighbour in `total_nodes` is the bound one,
        // floored at a single row because a fed selection may not be costed as emitting nothing.
        let expected = (all.rows / total_nodes(stats).max(1.0)).max(1.0);
        assert!(
            (into.rows - expected).abs() < 1e-9,
            "into.rows should be all.rows / total_nodes, floored at 1: got {} want {expected}",
            into.rows
        );
    }

    #[test]
    fn fed_expand_into_never_estimates_below_one_row() {
        // PostgreSQL's `clamp_row_est` rule. A sub-unitary estimate here would zero out the cost of
        // every operator above the expand-into, since they all multiply through this row count — the
        // mirror image of the over-estimate #863 removes.
        let g = connected_graph();
        let into = estimate_cost(&expand(person_label_scan(), true, None), g.statistics());
        assert!(
            into.rows >= 1.0,
            "a selection fed real rows must be costed as emitting at least one: {}",
            into.rows
        );
    }

    #[test]
    fn unfed_expand_into_still_estimates_empty() {
        // The floor applies to a *fed* selection only: over an empty input the operator emits nothing,
        // and claiming a row would over-estimate every plan built on an empty branch.
        let g = MemGraph::new(); // no nodes at all, so the label scan beneath yields zero rows
        let stats = g.statistics();
        let inner = estimate_cost(&person_label_scan(), stats);
        assert!(inner.rows < 1.0, "premise: the input must be sub-unitary");
        let into = estimate_cost(&expand(person_label_scan(), true, None), stats);
        assert!(
            into.rows < 1.0,
            "an unfed selection must not be floored up to a row: {}",
            into.rows
        );
    }

    #[test]
    fn expand_into_pays_the_same_traversal_cost_as_expand_all() {
        // It walks the same incidence — only its OUTPUT is smaller. Charging it less traversal work
        // would be the opposite error.
        let g = connected_graph();
        let stats = g.statistics();
        let all = estimate_cost(&expand(person_label_scan(), false, None), stats);
        let into = estimate_cost(&expand(person_label_scan(), true, None), stats);
        assert!(
            (into.cost - all.cost).abs() < 1e-9,
            "traversal cost must match: into={} all={}",
            into.cost,
            all.cost
        );
    }

    #[test]
    fn var_length_expand_into_is_also_a_selection() {
        let g = connected_graph();
        let stats = g.statistics();
        let range = Some(crate::ast::VarLengthRange {
            min: Some(1),
            max: Some(3),
            exact: false,
        });
        let all = estimate_cost(&expand(person_label_scan(), false, range), stats);
        let into = estimate_cost(&expand(person_label_scan(), true, range), stats);
        assert!(
            into.rows < all.rows,
            "var-length into must also select down"
        );
        assert!(
            (into.cost - all.cost).abs() < 1e-9,
            "var-length into walks the same frontier"
        );
        assert!(into.rows.is_finite() && into.rows >= 0.0);
    }

    #[test]
    fn expand_into_estimate_stays_finite_without_statistics() {
        // The no-stats path must not divide by zero or produce NaN/inf.
        let into = estimate_cost(&expand(person_label_scan(), true, None), None);
        assert!(
            into.rows.is_finite() && into.rows >= 0.0,
            "rows {}",
            into.rows
        );
        assert!(
            into.cost.is_finite() && into.cost >= 0.0,
            "cost {}",
            into.cost
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
