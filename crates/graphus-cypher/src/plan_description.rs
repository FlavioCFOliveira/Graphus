//! The **plan description** a client reads back for `EXPLAIN` / `PROFILE` (`rmp` task #752).
//!
//! This is the *rendering* half of the query-prefix feature ([`crate::profile`] is the measurement half).
//! It turns a compiled [`PhysicalPlan`] — optionally annotated with a profiled run's measured counters —
//! into a protocol-neutral [`Value`] tree that the Bolt and REST seams merely serialise. Rendering lives
//! here, in the crate that owns [`PhysicalOp`], so there is exactly **one** renderer: no wire layer knows
//! anything about operators, and the two protocols can never disagree about a plan.
//!
//! # The wire shape (Neo4j 5.x, verbatim)
//!
//! The Bolt specification declares only `plan::Dictionary` / `profile::Dictionary` in the result-summary
//! metadata and does **not** define the dictionary's contents; the shape below is the de-facto contract
//! defined jointly by the Neo4j server's `DefaultMetadataHandler.generateExecutionPlan` and by what the
//! official drivers parse (`InternalPlan` / `InternalProfiledPlan` in the Java driver,
//! `result-summary.ts` in the JavaScript driver, `_work/summary.py` in the Python driver). Graphus
//! reproduces it exactly:
//!
//! ```text
//! {
//!   operatorType: String,          // REQUIRED — drivers read it with no null check
//!   args:         Dictionary,      // the wire key is `args`, never `arguments`
//!   identifiers:  List<String>,
//!   children:     List<plan>,      // OMITTED entirely when the operator is a leaf
//!   // PROFILE only, as TOP-LEVEL siblings (not nested in `args`):
//!   rows:         Integer,
//!   dbHits:       Integer,
//! }
//! ```
//!
//! Three details of that contract are easy to get wrong and are deliberately honoured here:
//!
//! 1. **`plan` and `profile` are mutually exclusive.** Neo4j emits `profile` for a `PROFILE` and `plan` for
//!    an `EXPLAIN`, never both. [`PlanDescription::metadata_key`] returns the one key to use.
//! 2. **`children` is omitted on a leaf**, not sent as an empty list.
//! 3. **`rows` / `dbHits` are top-level**, and are absent from an `EXPLAIN` (nothing ran, so there is
//!    nothing to report — Graphus never fabricates a runtime counter).
//!
//! Neo4j additionally reports `pageCacheHits`, `pageCacheMisses`, `pageCacheHitRatio` and `time`. Graphus
//! does **not** measure those, so it omits them rather than inventing values; every official driver treats
//! them as optional and defaults them to `0`.
//!
//! # What goes into `args`
//!
//! `args` is opaque to every official driver (none of them reads a key from it), so it carries what a human
//! or a plan-asserting test needs, and **only facts the engine actually knows**:
//!
//! | Key | Where | Meaning |
//! |-----|-------|---------|
//! | `Details` | every operator | The operator's own rendered detail line — the exact text [`PhysicalOp`]'s [`Display`](std::fmt::Display) prints for it, so a plan description can never drift from the plan dump. |
//! | `Rows` / `DbHits` | every operator, `PROFILE` only | The same measured counters as the top-level `rows` / `dbHits`. Neo4j duplicates them here (it is what `cypher-shell` renders); so does Graphus. |
//! | `EstimatedRows` | **root only** | The planner's cardinality estimate for the whole plan. Neo4j reports a per-operator estimate; Graphus's cardinality estimator produces a single estimate for the plan's result, and a per-operator number would have to be **invented** — so it is reported where it is real, and omitted where it is not. |
//! | `planner` | root only | `"COST"` when graph statistics drove the cost-based optimiser, `"RULE"` when only the rule-based lowering ran ([`PhysicalPlan::cost_based`]). |
//! | `runtime` | root only | `"VOLCANO"` — Graphus's iterator-model executor. |
//! | `CandidatesExamined` | `PROFILE`, when non-zero | Candidate records the operator decoded and re-verified. An index access path is a candidate list **plus** a re-verification (the index is derived and MVCC-unaware, so it answers with a superset), and `DbHits` charges only what was *matched* — so without this a seek that examined a million candidates to return ten rows reads exactly like one that examined ten (`rmp` #991). |
//! | `CandidatesRejectedByVisibility` | `PROFILE`, when non-zero | Of those, how many the MVCC visibility re-check dropped. |
//! | `CandidatesRejectedByFilter` | `PROFILE`, when non-zero | Of those, how many the access path's own predicate re-check dropped (label bitmap, current value vs seek value or range bounds, relationship type, traversal direction). PostgreSQL reports the same distinction as *"Rows Removed by Filter"*. |
//! | `ReadMarkers` / `PredicateMarkers` | `PROFILE`, when non-zero | SIREAD markers the operator emitted, counted at the point of emission. This is what exposes the blanket `mark_all_live_nodes` footprint every non-equality node seek registers: one marker per live node, whatever the seek returns. |
//!
//! The five `rmp` #991 counters are emitted **only when non-zero** — the rule the result-summary `stats`
//! map already follows (`06-bolt-and-error-shapes.md` §3.1) — so an operator that touches no storage seam
//! does not carry five zeros. On a seam that measures (`RecordStoreGraph` and the off-thread
//! `ReadOnlyGraph`) their absence therefore means *"measured, and it was zero"*. On a seam that keeps the
//! `ReadCounts::ZERO` default — in-tree only [`MemGraph`](crate::graph_access::MemGraph), a test-only
//! backend — no candidate counter appears at all, and there absence means *"not measured"*. Both differ
//! from the permanently-omitted `pageCache*` / `time` above, which are not measured on any seam and so are
//! never reported under any circumstances.
//!
//! # Examples
//!
//! ```
//! use graphus_cypher::{
//!     catalog::IndexCatalog, lexer::tokenize, lower::lower, parser::parse_tokens,
//!     physical::plan_physical, plan_description::PlanDescription, semantics::analyze,
//! };
//!
//! let src = "EXPLAIN MATCH (n:Person) RETURN n";
//! let toks = tokenize(src).unwrap();
//! let ast = parse_tokens(&toks, src).unwrap();
//! let plan = plan_physical(&lower(&analyze(&ast).unwrap()), &IndexCatalog::empty())
//!     .with_prefix(ast.prefix());
//!
//! let desc = PlanDescription::explain(&plan);
//! assert_eq!(desc.metadata_key(), "plan");
//! assert_eq!(desc.root().operator_type, "Projection");
//! assert_eq!(desc.root().children[0].operator_type, "NodeByLabelScan");
//! // An EXPLAIN carries no runtime counters — nothing ran.
//! assert!(desc.root().rows.is_none());
//! ```

use graphus_core::Value;

use crate::physical::{PhysicalOp, PhysicalPlan};
use crate::profile::{OpId, ProfileRecorder};
use crate::read_source::ReadCounts;

/// The Bolt / REST result-summary key an `EXPLAIN` plan is delivered under.
pub const PLAN_KEY: &str = "plan";
/// The Bolt / REST result-summary key a `PROFILE` plan is delivered under.
pub const PROFILE_KEY: &str = "profile";

/// The maximum operator depth the plan description renders before truncating with a sentinel node
/// (`rmp` task #752 hardening).
///
/// A rendered plan nests one map inside a `children` list per operator, so its [`Value`] depth is about
/// **twice** the operator depth. The wire encoders cap `Value` depth at `1000` (Bolt's
/// `MAX_ENCODE_DEPTH`, the REST encoder's [`crate::value_depth`] policy, SEC-190): past that, Bolt would
/// silently substitute `Null` and the REST encoder would recurse uncapped. A maximally-deep *legal* query
/// (bounded by [`crate::MAX_QUERY_CLAUSES`] ≈ 1024 clauses) can lower to an operator chain far deeper than
/// `400`, so its plan `Value` would exceed `1000` and hit that truncation.
///
/// Bounding the *rendered plan* here — comfortably under half the wire cap, so the doubled `Value` depth
/// (≈ `2 × depth`) stays well under it with margin —
/// makes the plan safe on both wires and, unlike the encoders' silent `Null` substitution, **honest**: the
/// deepest rendered operator carries a single [`TRUNCATED_OPERATOR`] child that says the plan was cut. A
/// plan this deep is only reachable by an adversarially nested query (no human-written query approaches it),
/// so no real diagnostic is affected.
pub const MAX_PLAN_DEPTH: usize = 400;

/// The `operatorType` of the sentinel node that marks where [`MAX_PLAN_DEPTH`] truncated the plan.
pub const TRUNCATED_OPERATOR: &str = "PlanTruncated";

/// One operator of a rendered plan description — the map a client receives (see the [module docs](self)).
#[derive(Debug, Clone, PartialEq)]
#[must_use]
pub struct PlanNode {
    /// The operator's type name (`"RelIndexRangeSeek"`, `"AllRelationshipsScan"`, …). Always present.
    pub operator_type: &'static str,
    /// The variables this operator's rows bind, in introduction order.
    pub identifiers: Vec<String>,
    /// The operator's arguments (`Details`, and — where real — `EstimatedRows`, `planner`, `runtime`,
    /// `Rows`, `DbHits`).
    pub args: Vec<(String, Value)>,
    /// The operator's sub-plans, in the planner's canonical order. Empty for a leaf (and then omitted
    /// from the wire map entirely).
    pub children: Vec<PlanNode>,
    /// Rows this operator actually emitted — `Some` only for a `PROFILE`.
    pub rows: Option<u64>,
    /// Storage-seam records this operator actually obtained — `Some` only for a `PROFILE`. See
    /// [`crate::profile`] for the exact, measured definition.
    pub db_hits: Option<u64>,
}

impl PlanNode {
    /// This node as the [`Value::Map`] the wire carries.
    #[must_use]
    pub fn to_value(&self) -> Value {
        let mut map: Vec<(String, Value)> = Vec::with_capacity(6);
        map.push((
            "operatorType".to_owned(),
            Value::String(self.operator_type.to_owned()),
        ));
        map.push(("args".to_owned(), Value::Map(self.args.clone())));
        map.push((
            "identifiers".to_owned(),
            Value::List(
                self.identifiers
                    .iter()
                    .map(|i| Value::String(i.clone()))
                    .collect(),
            ),
        ));
        // Neo4j omits `children` entirely for a leaf operator rather than sending an empty list.
        if !self.children.is_empty() {
            map.push((
                "children".to_owned(),
                Value::List(self.children.iter().map(PlanNode::to_value).collect()),
            ));
        }
        // The profiled counters are TOP-LEVEL siblings, and absent unless the statement really ran.
        // The wire carries a signed 64-bit integer; the counters are unsigned. A saturating conversion
        // keeps a (physically impossible) overflow from wrapping into a NEGATIVE count — a nonsense number
        // is worse than a clamped one.
        if let Some(rows) = self.rows {
            map.push(("rows".to_owned(), Value::Integer(clamp(rows))));
        }
        if let Some(db_hits) = self.db_hits {
            map.push(("dbHits".to_owned(), Value::Integer(clamp(db_hits))));
        }
        Value::Map(map)
    }
}

/// A rendered query plan, ready for the result-summary metadata (`rmp` #752).
///
/// Build it with [`explain`](Self::explain) (a plan that was **not** executed — estimates only) or with
/// [`profile`](Self::profile) (a plan that ran, annotated with the measured per-operator counters).
#[derive(Debug, Clone, PartialEq)]
#[must_use]
pub struct PlanDescription {
    root: PlanNode,
    profiled: bool,
}

impl PlanDescription {
    /// Renders `plan` as an **`EXPLAIN`** description: operator tree + estimates, no runtime counters.
    pub fn explain(plan: &PhysicalPlan) -> Self {
        Self {
            root: render(&plan.root, plan, None, 0, true, 0),
            profiled: false,
        }
    }

    /// Renders the plan a [`ProfileRecorder`] measured as a **`PROFILE`** description: the same operator
    /// tree, annotated with each operator's measured `rows` and `dbHits`.
    pub fn profile(rec: &ProfileRecorder) -> Self {
        let plan = rec.plan();
        Self {
            root: render(&plan.root, plan, Some(rec), 0, true, 0),
            profiled: true,
        }
    }

    /// The root operator of the plan (the last operator to run; data flows leaves → root).
    pub fn root(&self) -> &PlanNode {
        &self.root
    }

    /// Whether this description carries measured runtime counters (a `PROFILE`) or only estimates (an
    /// `EXPLAIN`).
    #[must_use]
    pub fn is_profiled(&self) -> bool {
        self.profiled
    }

    /// The result-summary metadata key this description is delivered under: `"profile"` for a profiled
    /// plan, `"plan"` otherwise. Exactly one of the two is ever sent, as Neo4j does.
    #[must_use]
    pub fn metadata_key(&self) -> &'static str {
        if self.profiled { PROFILE_KEY } else { PLAN_KEY }
    }

    /// The whole description as the [`Value::Map`] the wire carries.
    #[must_use]
    pub fn to_value(&self) -> Value {
        self.root.to_value()
    }

    /// Whether the plan contains an operator of type `operator_type` anywhere (a convenience for the
    /// plan-assertion tests and examples that must prove a query is index-backed).
    #[must_use]
    pub fn contains_operator(&self, operator_type: &str) -> bool {
        fn walk(n: &PlanNode, want: &str) -> bool {
            n.operator_type == want || n.children.iter().any(|c| walk(c, want))
        }
        walk(&self.root, operator_type)
    }
}

/// Renders one operator (and, recursively, its sub-plans) at pre-order id `id`.
///
/// `rec` is `Some` for a profiled run; `is_root` gates the arguments Neo4j reports only on the root.
fn render(
    op: &PhysicalOp,
    plan: &PhysicalPlan,
    rec: Option<&ProfileRecorder>,
    id: OpId,
    is_root: bool,
    depth: usize,
) -> PlanNode {
    // Bound the rendered depth (`rmp` #752 hardening — SEC-190 wire-encoder parity): past `MAX_PLAN_DEPTH`
    // emit a single sentinel leaf instead of recursing, so a pathologically deep (but legal) query cannot
    // nest the plan `Value` past the wire encoders' depth cap. Honest, not silent: the marker says so.
    if depth >= MAX_PLAN_DEPTH {
        return PlanNode {
            operator_type: TRUNCATED_OPERATOR,
            identifiers: Vec::new(),
            args: vec![(
                "Details".to_owned(),
                Value::String(format!(
                    "plan truncated at depth {MAX_PLAN_DEPTH} (the remaining operators are not rendered)"
                )),
            )],
            children: Vec::new(),
            rows: None,
            db_hits: None,
        };
    }
    let mut args: Vec<(String, Value)> = vec![("Details".to_owned(), Value::String(detail(op)))];
    if is_root {
        // The cardinality estimate is a property of the whole plan — the only place it is a real number.
        args.push((
            "EstimatedRows".to_owned(),
            Value::Float(plan.estimated_rows()),
        ));
        args.push((
            "planner".to_owned(),
            Value::String(if plan.cost_based() { "COST" } else { "RULE" }.to_owned()),
        ));
        args.push(("runtime".to_owned(), Value::String("VOLCANO".to_owned())));
    }
    let (rows, db_hits) = match rec {
        Some(rec) => {
            let (rows, hits) = (rec.rows(id), rec.db_hits(id));
            // Neo4j duplicates the counters inside `args` (PascalCase) as well as at the top level; that
            // is what `cypher-shell` renders its table from.
            args.push(("Rows".to_owned(), Value::Integer(clamp(rows))));
            args.push(("DbHits".to_owned(), Value::Integer(clamp(hits))));
            push_candidate_args(&mut args, rec.read_counts(id));
            (Some(rows), Some(hits))
        }
        None => (None, None),
    };

    let mut children = Vec::new();
    let mut next = id + 1;
    for child in op.children() {
        children.push(render(child, plan, rec, next, false, depth + 1));
        next += child.subtree_len();
    }

    PlanNode {
        operator_type: op.operator_type(),
        identifiers: op.identifiers(),
        args,
        children,
        rows,
        db_hits,
    }
}

/// Appends the measured **candidate-examination** arguments of one operator (`rmp` task #991).
///
/// # What these are
///
/// Graphus's index access paths are *candidate lists plus a re-verification* (the index is derived and
/// MVCC-unaware, so it answers with a superset that the read body re-reads and re-checks). `DbHits`
/// charges what the operator **matched**, so on its own it cannot distinguish a seek that examined ten
/// candidates from one that examined a million to return the same ten rows. These four do, and they are
/// counted where the work happens, never inferred from one another:
///
/// * `CandidatesExamined` — candidate records decoded and tested by the re-verification.
/// * `CandidatesRejectedByVisibility` — of those, dropped because the version is invisible to this
///   snapshot.
/// * `CandidatesRejectedByFilter` — of those, dropped by the access path's own predicate re-check (the
///   label bitmap, the current property value against the seek value or range bounds, the relationship
///   type or the traversal direction). PostgreSQL reports the same distinction as
///   *"Rows Removed by Filter"* in `EXPLAIN ANALYZE`.
/// * `ReadMarkers` / `PredicateMarkers` — SIREAD markers this operator emitted, counted at the point of
///   emission. This is what exposes the blanket `mark_all_live_nodes` footprint every non-equality seek
///   registers: one marker per live node, whatever the seek returns.
///
/// The three candidate counters are **disjoint**, so
/// `CandidatesExamined - CandidatesRejectedByVisibility - CandidatesRejectedByFilter` is the number of
/// candidates that **survived the re-verification** — a statement about candidates, not about the
/// operator's rows. De-duplication (a stale and a live index entry naming one id) collapses two
/// survivors into one row, and a self-loop matched undirected is one survivor reported on both of its
/// sides; both are measured in
/// `tests/candidate_instrumentation.rs::surviving_candidates_are_not_rows_991`.
///
/// # Absence means a measured zero — for a seam that measures
///
/// A counter is emitted only when it is **non-zero** — the rule the result-summary `stats` map already
/// follows (`06-bolt-and-error-shapes.md` §3.1), and the reason a `Projection` does not carry five zeros.
/// For the store-backed seams (`RecordStoreGraph` and the off-thread `ReadOnlyGraph`), absence therefore
/// means "measured, and it was zero": an operator that touches no storage seam genuinely examines no
/// candidate.
///
/// The qualification matters for a seam that does **not** implement
/// [`GraphAccess::take_read_tally`](crate::graph_access::GraphAccess::take_read_tally) and keeps the
/// `ZERO` default — in-tree that is only [`MemGraph`](crate::graph_access::MemGraph), reachable from
/// `graphus-cypher`/`graphus-tck` tests and never in production. Its plans carry no candidate counter
/// anywhere, and there the absence means "not measured". Nothing is fabricated either way, which is the
/// property that matters; but the blanket reading "absent ⇒ measured zero" is only sound for a seam that
/// measures.
///
/// Both are different again from the permanently-omitted `pageCacheHits` / `time`, which Graphus does not
/// measure on **any** seam and so never reports (decision `D-query-prefixes`).
fn push_candidate_args(args: &mut Vec<(String, Value)>, counts: ReadCounts) {
    for (key, value) in [
        ("CandidatesExamined", counts.candidates_examined),
        (
            "CandidatesRejectedByVisibility",
            counts.rejected_by_visibility,
        ),
        ("CandidatesRejectedByFilter", counts.rejected_by_predicate),
        ("ReadMarkers", counts.read_markers),
        ("PredicateMarkers", counts.predicate_markers),
    ] {
        if value != 0 {
            args.push((key.to_owned(), Value::Integer(clamp(value))));
        }
    }
}

/// A `u64` counter as the signed integer the wire carries, saturating rather than wrapping.
fn clamp(n: u64) -> i64 {
    i64::try_from(n).unwrap_or(i64::MAX)
}

/// The operator's own detail line: the first line of its [`Display`](std::fmt::Display) rendering, which is
/// the operator's header (its sub-plans are the lines below it).
///
/// Reusing the [`PhysicalOp`] pretty-printer — rather than re-implementing a second rendering of every
/// operator's parameters — guarantees that the `Details` a client reads and the plan dump the engine's own
/// tests assert on are the *same text*, and cannot drift apart as operators gain fields.
fn detail(op: &PhysicalOp) -> String {
    op.to_string()
        .lines()
        .next()
        .unwrap_or_default()
        .trim_end()
        .to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::catalog::IndexCatalog;
    use crate::lexer::tokenize;
    use crate::lower::lower;
    use crate::parser::parse_tokens;
    use crate::physical::plan_physical;
    use crate::semantics::analyze;

    fn plan(src: &str, catalog: &IndexCatalog) -> PhysicalPlan {
        let toks = tokenize(src).expect("lex");
        let ast = parse_tokens(&toks, src).expect("parse");
        let validated = analyze(&ast).expect("analyze");
        plan_physical(&lower(&validated), catalog).with_prefix(ast.prefix())
    }

    /// The one map key set a driver depends on (`operatorType` is mandatory; `args`/`identifiers`/
    /// `children` are optional but must be spelled exactly).
    fn map_of(v: &Value) -> Vec<(String, Value)> {
        match v {
            Value::Map(m) => m.clone(),
            other => panic!("expected a map, got {other:?}"),
        }
    }

    fn key<'v>(m: &'v [(String, Value)], k: &str) -> Option<&'v Value> {
        m.iter().find(|(name, _)| name == k).map(|(_, v)| v)
    }

    #[test]
    fn explain_shape_matches_the_neo4j_contract() {
        let p = plan("EXPLAIN MATCH (n:Person) RETURN n", &IndexCatalog::empty());
        let desc = PlanDescription::explain(&p);
        assert_eq!(desc.metadata_key(), "plan");
        let root = map_of(&desc.to_value());

        // Mandatory + exactly-spelled keys.
        assert_eq!(
            key(&root, "operatorType"),
            Some(&Value::String("Projection".to_owned()))
        );
        assert!(key(&root, "args").is_some(), "the wire key is `args`");
        assert!(key(&root, "arguments").is_none(), "never `arguments`");
        assert!(matches!(key(&root, "identifiers"), Some(Value::List(_))));
        // An EXPLAIN reports no runtime counters at all.
        assert!(key(&root, "rows").is_none());
        assert!(key(&root, "dbHits").is_none());

        // The root's args carry the real, known facts.
        let args = map_of(key(&root, "args").expect("args"));
        assert!(matches!(key(&args, "EstimatedRows"), Some(Value::Float(_))));
        assert_eq!(
            key(&args, "planner"),
            Some(&Value::String("RULE".to_owned())),
            "no statistics were supplied, so the rule-based planner ran"
        );
        assert!(key(&args, "Details").is_some());

        // Children: present on an inner operator, absent (not empty) on a leaf.
        let Some(Value::List(children)) = key(&root, "children") else {
            panic!("an inner operator carries `children`");
        };
        assert_eq!(children.len(), 1);
        let leaf = map_of(&children[0]);
        assert_eq!(
            key(&leaf, "operatorType"),
            Some(&Value::String("NodeByLabelScan".to_owned()))
        );
        assert!(
            key(&leaf, "children").is_none(),
            "a leaf omits `children` entirely, as Neo4j does"
        );
    }

    #[test]
    fn details_are_the_operators_own_rendering() {
        let p = plan("EXPLAIN MATCH (n:Person) RETURN n", &IndexCatalog::empty());
        let desc = PlanDescription::explain(&p);
        let leaf = &desc.root().children[0];
        let Some((_, Value::String(details))) =
            leaf.args.iter().find(|(k, _)| k == "Details").cloned()
        else {
            panic!("every operator carries Details");
        };
        assert_eq!(details, "NodeByLabelScan(n:Person)");
        assert_eq!(leaf.identifiers, vec!["n".to_owned()]);
    }

    #[test]
    fn a_pathologically_deep_plan_is_truncated_with_an_honest_marker() {
        // A deeply-nested boxed operator tree needs a large stack for its recursive construction /
        // `Drop` (the same reason the engine runs deep queries on a big worker stack); render it there.
        std::thread::Builder::new()
            .stack_size(64 * 1024 * 1024)
            .spawn(deep_plan_truncation_body)
            .expect("spawn")
            .join()
            .expect("the deep-plan test thread");
    }

    fn deep_plan_truncation_body() {
        use crate::physical::PhysicalOp;
        // Build a deeper-than-cap operator chain DIRECTLY (a stack of `Eager` over a leaf), assembled
        // iteratively so neither construction nor this test's own recursion overflows. Compiling a real
        // query this deep would need the engine's large worker stack (that is what `MAX_QUERY_CLAUSES`
        // and the server's stack sizing are for); here we test only the RENDER cap.
        let depth = super::MAX_PLAN_DEPTH + 50;
        let mut op = PhysicalOp::AllNodesScan {
            variable: crate::logical::Var::named("n"),
        };
        for _ in 0..depth {
            op = PhysicalOp::Eager {
                input: Box::new(op),
            };
        }
        // A physical plan carrying this deep tree (rendered directly, not compiled).
        let toks = tokenize("EXPLAIN MATCH (n) RETURN n").expect("lex");
        let ast = parse_tokens(&toks, "EXPLAIN MATCH (n) RETURN n").expect("parse");
        let mut p = plan_physical(
            &lower(&analyze(&ast).expect("analyze")),
            &IndexCatalog::empty(),
        )
        .with_prefix(ast.prefix());
        p.root = op;
        let desc = PlanDescription::explain(&p);

        // Walk to the deepest node and confirm exactly one truncation marker appears, at the cap depth.
        fn depth_and_has_marker(n: &PlanNode) -> (usize, bool) {
            if n.operator_type == super::TRUNCATED_OPERATOR {
                return (1, true);
            }
            let mut d = 0;
            let mut marker = false;
            for c in &n.children {
                let (cd, cm) = depth_and_has_marker(c);
                d = d.max(cd);
                marker |= cm;
            }
            (d + 1, marker)
        }
        let (depth, has_marker) = depth_and_has_marker(desc.root());
        assert!(
            has_marker,
            "a deeper-than-cap plan carries the truncation marker"
        );
        assert!(
            depth <= super::MAX_PLAN_DEPTH + 1,
            "the rendered plan is bounded at the cap ({depth} <= {})",
            super::MAX_PLAN_DEPTH + 1
        );

        // And it still serialises to a `Value` whose depth is under the 1000 wire-encoder cap.
        fn value_depth(v: &Value) -> usize {
            match v {
                Value::Map(entries) => {
                    1 + entries
                        .iter()
                        .map(|(_, x)| value_depth(x))
                        .max()
                        .unwrap_or(0)
                }
                Value::List(items) => 1 + items.iter().map(value_depth).max().unwrap_or(0),
                _ => 1,
            }
        }
        assert!(
            value_depth(&desc.to_value()) < 1000,
            "the serialised plan stays under the wire encoders' depth cap"
        );
    }

    #[test]
    fn an_index_backed_plan_reports_the_seek_operator() {
        let catalog = IndexCatalog::builder()
            .with_label_property("Person", "name")
            .build();
        let seek = plan("EXPLAIN MATCH (n:Person {name: 'Ada'}) RETURN n", &catalog);
        assert!(PlanDescription::explain(&seek).contains_operator("NodeIndexSeek"));
        // The same query with no index declared falls back to a scan — the regression an operator must be
        // able to detect.
        let scan = plan(
            "EXPLAIN MATCH (n:Person {name: 'Ada'}) RETURN n",
            &IndexCatalog::empty(),
        );
        let scan = PlanDescription::explain(&scan);
        assert!(!scan.contains_operator("NodeIndexSeek"));
        assert!(scan.contains_operator("NodeLabelScanEq"));
    }
}
