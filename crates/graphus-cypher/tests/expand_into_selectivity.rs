//! **Expand-into is costed as a connection check, measured against reality** (`rmp` task #863).
//!
//! An [`ExpandInto`](graphus_cypher::physical::PhysicalOp::ExpandInto) has *both* endpoints already
//! bound, so it is a selection — it emits only the edges landing on the node `to` is already bound
//! to — while an [`ExpandAll`](graphus_cypher::physical::PhysicalOp::ExpandAll) fans the input out by
//! the average degree. Until task #863 the cost model estimated both with the same expression, so
//! every plan that closed a cycle inherited an output over-estimate of a whole degree factor and the
//! cost-based search systematically avoided exactly the plans that close a cycle early.
//!
//! These tests are **empirical**: each one plans a real query over a real graph, pulls the
//! `ExpandInto` sub-plan out of the chosen plan, and compares the estimator's row estimate against
//! the row count the executor actually produces at that point. The pattern is written so nothing
//! above the `ExpandInto` filters, which makes the query's final row count exactly the operator's
//! output — the same quantity `PROFILE` reports as its `Rows`.

use graphus_core::Value;
use graphus_cypher::binding::{Parameters, bind_parameters};
use graphus_cypher::catalog::IndexCatalog;
use graphus_cypher::cost::estimate_cost;
use graphus_cypher::executor::execute;
use graphus_cypher::graph_access::{GraphAccess, MemGraph};
use graphus_cypher::lexer::tokenize;
use graphus_cypher::lower::lower;
use graphus_cypher::parser::parse_tokens;
use graphus_cypher::physical::{PhysicalOp, plan_physical_with_stats};
use graphus_cypher::semantics::analyze;

// =================================================================================================
// Harness
// =================================================================================================

/// A typed empty property list, so the property generic can be inferred at the empty case.
const NO_PROPS: [(&str, Value); 0] = [];

/// Compiles `src` against `graph`'s own statistics, so the cost-based optimiser really runs.
fn plan(src: &str, graph: &MemGraph) -> PhysicalOp {
    let toks = tokenize(src).unwrap_or_else(|e| panic!("lex `{src}`: {e:?}"));
    let ast = parse_tokens(&toks, src).unwrap_or_else(|e| panic!("parse `{src}`: {e:?}"));
    let validated = analyze(&ast).unwrap_or_else(|e| panic!("analyze `{src}`: {e:?}"));
    plan_physical_with_stats(
        &lower(&validated),
        &IndexCatalog::empty(),
        graph.statistics(),
    )
    .root
    .clone()
}

/// Runs `src` and returns the number of rows it produced.
fn measured_rows(src: &str, graph: &mut MemGraph) -> usize {
    let toks = tokenize(src).unwrap();
    let ast = parse_tokens(&toks, src).unwrap();
    let validated = analyze(&ast).unwrap();
    let physical = plan_physical_with_stats(
        &lower(&validated),
        &IndexCatalog::empty(),
        graph.statistics(),
    );
    let bound = bind_parameters(&physical, &Parameters::new()).expect("bind");
    execute(&physical, &bound, graph)
        .unwrap_or_else(|e| panic!("open `{src}`: {e:?}"))
        .collect_all()
        .unwrap_or_else(|e| panic!("run `{src}`: {e:?}"))
        .len()
}

/// Finds the **topmost** operator of the given kind in `op`, searching root-first.
fn find(op: &PhysicalOp, want_into: bool) -> Option<&PhysicalOp> {
    let matches = match op {
        PhysicalOp::ExpandInto { .. } => want_into,
        PhysicalOp::ExpandAll { .. } => !want_into,
        _ => false,
    };
    if matches {
        return Some(op);
    }
    // Only the linear spine matters for these patterns; every operator here has one input.
    child(op).and_then(|c| find(c, want_into))
}

/// The single input of a linear operator, if it has one.
fn child(op: &PhysicalOp) -> Option<&PhysicalOp> {
    match op {
        PhysicalOp::ExpandAll { input, .. }
        | PhysicalOp::ExpandInto { input, .. }
        | PhysicalOp::Filter { input, .. }
        | PhysicalOp::Projection { input, .. }
        | PhysicalOp::Aggregation { input, .. }
        | PhysicalOp::Limit { input, .. }
        | PhysicalOp::Skip { input, .. }
        | PhysicalOp::Sort { input, .. } => Some(input),
        _ => None,
    }
}

/// A ring of `n` `Person` nodes where every node also knows the node two steps ahead, so every
/// consecutive triple `(a)->(b)->(c)` is closed by a real `(a)->(c)` edge: each triangle exists, and
/// so an expand-into over this pattern emits exactly one row per triple.
fn triangle_ring(n: usize) -> MemGraph {
    let mut g = MemGraph::new();
    let ids: Vec<_> = (0..n)
        .map(|i| g.add_node(["Person"], [("i", Value::Integer(i as i64))]))
        .collect();
    for i in 0..n {
        g.add_rel("KNOWS", ids[i], ids[(i + 1) % n], NO_PROPS);
        g.add_rel("KNOWS", ids[i], ids[(i + 2) % n], NO_PROPS);
    }
    g
}

// =================================================================================================
// Tests
// =================================================================================================

/// The triangle pattern: two hops out and one hop **back into** an already-bound node.
///
/// `(a)-[r1]->(b)-[r2]->(c)` fans out; `(a)-[r3]->(c)` closes the cycle and must be an expand-into,
/// because both `a` and `c` are bound by then. Returning the three nodes (rather than a `count`)
/// keeps the expand-into at the top of the row-producing spine, so the query's row count *is* the
/// operator's output.
const TRIANGLE: &str = "MATCH (a:Person)-[r1:KNOWS]->(b:Person)-[r2:KNOWS]->(c:Person), \
                        (a)-[r3:KNOWS]->(c) RETURN a, b, c";

#[test]
fn triangle_closing_hop_is_planned_as_an_expand_into() {
    // The premise of every other test here: if the planner did not choose an expand-into, the
    // estimates below would be measuring something else entirely.
    let g = triangle_ring(64);
    let p = plan(TRIANGLE, &g);
    assert!(
        find(&p, true).is_some(),
        "the cycle-closing hop must be an expand-into, else this suite is vacuous:\n{p:#?}"
    );
}

#[test]
fn expand_into_estimate_is_far_below_the_expand_all_it_sits_on() {
    // The defect #863 fixes, stated as a plan-level property: the connection check must not claim
    // the whole fan-out of the expand it consumes.
    let g = triangle_ring(64);
    let p = plan(TRIANGLE, &g);
    let stats = g.statistics();
    let into = estimate_cost(find(&p, true).expect("expand-into"), stats);
    let all = estimate_cost(find(&p, false).expect("expand-all"), stats);
    assert!(
        into.rows < all.rows,
        "expand-into must estimate below the expand-all beneath it: into={} all={}",
        into.rows,
        all.rows
    );
}

#[test]
fn expand_into_estimate_does_not_collapse_to_zero() {
    // The opposite failure mode of the one #863 fixed, and the reason the estimate is floored: an
    // estimate that collapses to ~0 zeroes the cost of every operator above it, which would make the
    // search prefer a cycle-closing plan just as blindly as it used to reject one. A selection that
    // is fed rows must be allowed to emit rows. Before the floor this measured 0.72 estimated against
    // 64 rows produced.
    let mut g = triangle_ring(64);
    let p = plan(TRIANGLE, &g);
    let est = estimate_cost(find(&p, true).expect("expand-into"), g.statistics()).rows;
    let real = measured_rows(TRIANGLE, &mut g) as f64;
    assert!(
        real > 0.0,
        "the corpus must close real triangles, else the comparison is vacuous"
    );
    assert!(
        est >= 1.0,
        "estimate collapsed below one row (est={est}, measured={real})"
    );
}

/// A deterministic Erdős–Rényi digraph: `n` `Person` nodes, each ordered pair joined with
/// probability `num/den`, no self-loops and no parallel edges.
///
/// Uniform by construction, which is exactly the assumption the cost model states. That makes it the
/// corpus on which the estimator's accuracy is a fair question at all — see
/// [`uniform_random_graph_estimate_is_within_an_order_of_magnitude`]. The generator is a plain LCG
/// with a fixed seed (no clock, no RNG crate), so every run plans and measures the identical graph.
fn uniform_digraph(n: usize, num: u64, den: u64) -> MemGraph {
    let mut g = MemGraph::new();
    let ids: Vec<_> = (0..n)
        .map(|i| g.add_node(["Person"], [("i", Value::Integer(i as i64))]))
        .collect();
    let mut state: u64 = 0x2545_F491_4F6C_DD1D;
    for a in 0..n {
        for b in 0..n {
            if a == b {
                continue;
            }
            // Numerical Recipes' LCG constants; the top bits are the well-mixed ones.
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            if (state >> 33) % den < num {
                g.add_rel("KNOWS", ids[a], ids[b], NO_PROPS);
            }
        }
    }
    g
}

/// The same triangle with the redundant label predicates on `b` and `c` dropped.
///
/// Every node in the uniform corpus carries `:Person`, so `(b:Person)` and `(c:Person)` select
/// nothing — but the cost model still charges each of them the flat `0.3` filter constant, which
/// alone shrinks the estimate by `0.09` and would swamp the quantity under test here. That constant
/// is `rmp` task **#864**; the accuracy of the expand-into formula is a separate question and this
/// spelling asks it in isolation.
const TRIANGLE_UNLABELLED: &str = "MATCH (a:Person)-[r1:KNOWS]->(b)-[r2:KNOWS]->(c), \
                                   (a)-[r3:KNOWS]->(c) RETURN a, b, c";

#[test]
fn uniform_random_graph_estimate_is_within_an_order_of_magnitude() {
    // The accuracy criterion of #863, asked where the model's own assumption holds. On a uniform
    // digraph the probability that a walked neighbour is the bound `to` really is degree/|V|, so the
    // estimate must track the measured rows closely — and it is this test, not the triangle ring
    // below, that would catch a wrong formula.
    let mut g = uniform_digraph(100, 1, 5);
    let p = plan(TRIANGLE_UNLABELLED, &g);
    let est = estimate_cost(find(&p, true).expect("expand-into"), g.statistics()).rows;
    let real = measured_rows(TRIANGLE_UNLABELLED, &mut g) as f64;
    assert!(
        real > 100.0,
        "non-vacuity: the corpus must close many triangles, got {real}"
    );
    let ratio = if est > real { est / real } else { real / est };
    assert!(
        ratio <= 10.0,
        "estimate diverged by more than an order of magnitude on a uniform corpus: \
         est={est} measured={real} ratio={ratio}"
    );
}

#[test]
fn flat_filter_constant_is_what_still_skews_the_labelled_spelling() {
    // Attribution test, so the residual error is pinned to its real cause rather than blamed on the
    // expand-into formula. The two spellings describe the same pattern over a corpus where every node
    // is a `Person`, so they must measure the same rows; only the labelled one pays the flat `0.3`
    // filter constant, twice. This test fails the day task #864 replaces that constant — at which
    // point the labelled spelling should be folded back into the accuracy test above.
    let mut g = uniform_digraph(100, 1, 5);
    let labelled = measured_rows(TRIANGLE, &mut g) as f64;
    let plain = measured_rows(TRIANGLE_UNLABELLED, &mut g) as f64;
    assert_eq!(
        labelled, plain,
        "premise: the two spellings must match the same rows on this corpus"
    );
    let stats = g.statistics();
    let est_labelled = estimate_cost(find(&plan(TRIANGLE, &g), true).expect("into"), stats).rows;
    let est_plain = estimate_cost(
        find(&plan(TRIANGLE_UNLABELLED, &g), true).expect("into"),
        stats,
    )
    .rows;
    assert!(
        est_labelled < est_plain / 5.0,
        "the flat filter constant should be shrinking the labelled estimate by ~0.09: \
         labelled={est_labelled} plain={est_plain} (measured {plain})"
    );
}

#[test]
fn correlated_corpus_under_estimates_and_that_is_a_model_limit_not_a_defect() {
    // Documented, measured limitation. A triangle ring is maximally *correlated*: every triple its
    // pattern enumerates is closed, so the operator emits one row per input row while a uniformity
    // estimator predicts degree/|V| of them. No estimator without correlation statistics can close
    // this gap — neither Neo4j's nor Memgraph's does — so the direction and the size of the error are
    // pinned here rather than papered over. What matters for plan choice is that the error is on the
    // *low* side and bounded below by the floor, both asserted above.
    let mut g = triangle_ring(64);
    let p = plan(TRIANGLE, &g);
    let est = estimate_cost(find(&p, true).expect("expand-into"), g.statistics()).rows;
    let real = measured_rows(TRIANGLE, &mut g) as f64;
    assert!(real > 0.0, "non-vacuity: the pattern must match");
    assert!(
        est <= real,
        "a uniformity estimator cannot exceed a fully-closed corpus: est={est} measured={real}"
    );
}

#[test]
fn expand_into_never_over_estimates_the_expand_all_it_replaced() {
    // A sparser corpus, where most triples are *not* closed: the selection is genuinely selective
    // here, and the estimate must stay on the low side of the fan-out rather than tracking it.
    let mut g = MemGraph::new();
    let ids: Vec<_> = (0..200)
        .map(|i| g.add_node(["Person"], [("i", Value::Integer(i as i64))]))
        .collect();
    // A long chain plus a handful of closing edges: the chain supplies plenty of open triples.
    for i in 0..199 {
        g.add_rel("KNOWS", ids[i], ids[i + 1], NO_PROPS);
    }
    for i in (0..190).step_by(10) {
        g.add_rel("KNOWS", ids[i], ids[i + 2], NO_PROPS);
    }
    let p = plan(TRIANGLE, &g);
    let stats = g.statistics();
    let into = estimate_cost(find(&p, true).expect("expand-into"), stats);
    let all = estimate_cost(find(&p, false).expect("expand-all"), stats);
    let real = measured_rows(TRIANGLE, &mut g) as f64;
    assert!(real > 0.0, "non-vacuity: some triples must close");
    assert!(
        into.rows <= all.rows,
        "a selection cannot emit more than the fan-out feeding it: into={} all={}",
        into.rows,
        all.rows
    );
}

#[test]
fn expand_into_is_charged_the_traversal_it_performs() {
    // Costing it as a selection must not become costing it as free: it walks the same incidence an
    // expand-all would, so its cost must exceed its own input's cost by real traversal work.
    let g = triangle_ring(64);
    let p = plan(TRIANGLE, &g);
    let stats = g.statistics();
    let into_op = find(&p, true).expect("expand-into");
    let into = estimate_cost(into_op, stats);
    let inner = estimate_cost(child(into_op).expect("input"), stats);
    assert!(
        into.cost > inner.cost,
        "expand-into must be charged for the edges it walks: {} vs input {}",
        into.cost,
        inner.cost
    );
}
