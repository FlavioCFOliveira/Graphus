//! **Asymmetric expand degrees** (`rmp` task #886): the estimated fan-out of a hop comes from the
//! anchor's own `(label, type)` / `(type, label)` counter, not from one graph-wide degree per type.
//!
//! Why it matters, measured on the evaluation store: `LIKES` yields an estimated degree of 9.7 from
//! *any* anchor, while the true out-degree is about 10 from a `USER` and about 333 from an `ARTICLE`.
//! Given symmetric degrees a cost-based planner cannot tell a selective anchor from a fan-out one, so
//! the anchor and expansion-order search of #858 would compare candidates blindly.
//!
//! The corpus here is deliberately **asymmetric**: 60 `USER`s each like 2 of 3 `ARTICLE`s, so the true
//! out-degree from a user is 2 while the in-degree of an article is 40. A symmetric model must report
//! the same number for both directions; a directional one must not — and that difference is what every
//! test below asserts, alongside the measured out-degree the estimate has to match.

use graphus_core::Value;
use graphus_cypher::catalog::IndexCatalog;
use graphus_cypher::cost::estimate_cost;
use graphus_cypher::graph_access::{GraphAccess, MemGraph};
use graphus_cypher::lexer::tokenize;
use graphus_cypher::lower::lower;
use graphus_cypher::parser::parse_tokens;
use graphus_cypher::physical::{PhysicalOp, plan_physical_with_stats};
use graphus_cypher::semantics::analyze;

const NO_PROPS: [(&str, Value); 0] = [];
const USERS: usize = 60;
const ARTICLES: usize = 3;
const LIKES_PER_USER: usize = 2;

/// `USERS` users each liking `LIKES_PER_USER` of `ARTICLES` articles.
///
/// True out-degree from a `USER` is `LIKES_PER_USER` (2); true in-degree of an `ARTICLE` is
/// `USERS * LIKES_PER_USER / ARTICLES` (40). The graph-wide degree is `120 / 63 ≈ 1.9`, which matches
/// neither — that is the defect.
fn asymmetric_graph() -> MemGraph {
    let mut g = MemGraph::new();
    let users: Vec<_> = (0..USERS)
        .map(|i| g.add_node(["USER"], [("i", Value::Integer(i as i64))]))
        .collect();
    let articles: Vec<_> = (0..ARTICLES)
        .map(|i| g.add_node(["ARTICLE"], [("i", Value::Integer(i as i64))]))
        .collect();
    for (i, &u) in users.iter().enumerate() {
        for k in 0..LIKES_PER_USER {
            g.add_rel("LIKES", u, articles[(i + k) % ARTICLES], NO_PROPS);
        }
    }
    g
}

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

/// The topmost expand (all or into) on the plan's linear spine.
fn find_expand(op: &PhysicalOp) -> Option<&PhysicalOp> {
    match op {
        PhysicalOp::ExpandAll { .. } | PhysicalOp::ExpandInto { .. } => Some(op),
        PhysicalOp::Filter { input, .. }
        | PhysicalOp::Projection { input, .. }
        | PhysicalOp::Aggregation { input, .. }
        | PhysicalOp::Limit { input, .. }
        | PhysicalOp::Skip { input, .. }
        | PhysicalOp::Sort { input, .. } => find_expand(input),
        _ => None,
    }
}

/// The estimated rows the topmost expand of `src` emits.
fn expand_rows(src: &str, graph: &MemGraph) -> f64 {
    let p = plan(src, graph);
    let expand = find_expand(&p).unwrap_or_else(|| panic!("no expand in the plan for `{src}`"));
    estimate_cost(expand, graph.statistics()).rows
}

// =================================================================================================
// The asymmetry
// =================================================================================================

#[test]
fn the_seam_reports_asymmetric_counts() {
    // The premise every test below rests on. If the counters themselves were symmetric there would be
    // nothing for the estimator to read.
    let g = asymmetric_graph();
    let stats = g.statistics().expect("MemGraph always has statistics");
    let out_of_user = stats.rels_from_label_with_type("USER", "LIKES");
    let into_article = stats.rels_with_type_to_label("LIKES", "ARTICLE");
    assert_eq!(out_of_user, Some((USERS * LIKES_PER_USER) as u64));
    assert_eq!(into_article, Some((USERS * LIKES_PER_USER) as u64));
    // Same edge total from each side — the *degrees* differ because the populations do.
    assert_eq!(stats.nodes_with_label("USER"), Some(USERS as u64));
    assert_eq!(stats.nodes_with_label("ARTICLE"), Some(ARTICLES as u64));
}

#[test]
fn out_of_a_user_estimates_the_true_out_degree() {
    // 60 users x 2 likes = 120 edges over 60 users => degree 2, and the label scan emits 60 rows, so
    // the expand must estimate 120 rows. The graph-wide model would have said 60 * (120/63) ≈ 114.
    let g = asymmetric_graph();
    let rows = expand_rows("MATCH (u:USER)-[:LIKES]->(a:ARTICLE) RETURN u, a", &g);
    let expected = (USERS * LIKES_PER_USER) as f64;
    assert!(
        (rows - expected).abs() < 1e-6,
        "expected {expected} rows out of USER, got {rows}"
    );
}

#[test]
fn into_an_article_estimates_the_true_in_degree() {
    // Anchored on the ARTICLE side and walking backwards: 120 edges over 3 articles => degree 40, and
    // the label scan emits 3 rows, so 120 rows again. The KEY point is not the total but that the
    // per-anchor degree is 40 here versus 2 above — a symmetric model cannot produce both.
    let g = asymmetric_graph();
    let rows = expand_rows("MATCH (a:ARTICLE)<-[:LIKES]-(u:USER) RETURN a, u", &g);
    let expected = (USERS * LIKES_PER_USER) as f64;
    assert!(
        (rows - expected).abs() < 1e-6,
        "expected {expected} rows into ARTICLE, got {rows}"
    );
}

#[test]
fn the_two_anchors_produce_different_per_anchor_degrees() {
    // The property that a graph-wide degree cannot have, stated directly. Both spellings walk the same
    // 120 edges, but one starts from 60 rows and the other from 3 — so if the estimator were using one
    // symmetric degree, the two estimates could not both be right, and one would be 20x off.
    let g = asymmetric_graph();
    let from_user = expand_rows("MATCH (u:USER)-[:LIKES]->(a:ARTICLE) RETURN u, a", &g);
    let from_article = expand_rows("MATCH (a:ARTICLE)<-[:LIKES]-(u:USER) RETURN a, u", &g);
    // Same edge set, so the row estimates agree...
    assert!((from_user - from_article).abs() < 1e-6);
    // ...but only because the per-anchor degrees differ by exactly the population ratio.
    let user_scan = USERS as f64;
    let article_scan = ARTICLES as f64;
    let degree_from_user = from_user / user_scan;
    let degree_from_article = from_article / article_scan;
    assert!(
        (degree_from_user - LIKES_PER_USER as f64).abs() < 1e-6,
        "out-degree from a USER should be {LIKES_PER_USER}, got {degree_from_user}"
    );
    let expected_in = (USERS * LIKES_PER_USER / ARTICLES) as f64;
    assert!(
        (degree_from_article - expected_in).abs() < 1e-6,
        "in-degree of an ARTICLE should be {expected_in}, got {degree_from_article}"
    );
    assert!(
        (degree_from_user - degree_from_article).abs() > 1.0,
        "the two directions must differ, else nothing was gained: {degree_from_user} vs \
         {degree_from_article}"
    );
}

#[test]
fn an_undirected_hop_sums_both_projections() {
    // An undirected traversal leaves along an edge either way, so both projections contribute. From a
    // USER that is 2 out + 0 in = 2; from an ARTICLE 0 out + 40 in = 40.
    let g = asymmetric_graph();
    let from_user = expand_rows("MATCH (u:USER)-[:LIKES]-(a) RETURN u, a", &g) / USERS as f64;
    let from_article =
        expand_rows("MATCH (a:ARTICLE)-[:LIKES]-(u) RETURN a, u", &g) / ARTICLES as f64;
    assert!(
        (from_user - LIKES_PER_USER as f64).abs() < 1e-6,
        "undirected from a USER walks only its out-edges here: got {from_user}"
    );
    let expected_in = (USERS * LIKES_PER_USER / ARTICLES) as f64;
    assert!(
        (from_article - expected_in).abs() < 1e-6,
        "undirected from an ARTICLE walks only its in-edges here: got {from_article}"
    );
}

// =================================================================================================
// Fallbacks — proven, not assumed
// =================================================================================================

#[test]
fn an_unlabelled_anchor_falls_back_to_the_graph_wide_degree() {
    // No access path states the anchor's label, so there is no directional counter to read. The
    // estimate must degrade to the graph-wide degree — finite, non-negative, and equal to what the
    // pre-#886 model produced for this shape.
    let g = asymmetric_graph();
    let rows = expand_rows("MATCH (n)-[:LIKES]->(m) RETURN n, m", &g);
    let total_nodes = (USERS + ARTICLES) as f64;
    let all_likes = (USERS * LIKES_PER_USER) as f64;
    // Graph-wide typed degree = edges of that type / total nodes; input is the all-nodes scan.
    let expected = total_nodes * (all_likes / total_nodes);
    assert!(
        (rows - expected).abs() < 1e-6,
        "expected the graph-wide fallback {expected}, got {rows}"
    );
}

#[test]
fn an_untyped_hop_falls_back_to_the_average_degree() {
    // With no relationship type there is no per-type counter to read at all, so the average degree is
    // the only available model. The estimate must still be finite and non-negative.
    let g = asymmetric_graph();
    let rows = expand_rows("MATCH (u:USER)-->(a) RETURN u, a", &g);
    assert!(rows.is_finite() && rows >= 0.0, "rows {rows}");
    let total_nodes = (USERS + ARTICLES) as f64;
    let expected = USERS as f64 * ((USERS * LIKES_PER_USER) as f64 / total_nodes);
    assert!(
        (rows - expected).abs() < 1e-6,
        "expected the average-degree fallback {expected}, got {rows}"
    );
}

#[test]
fn a_type_with_no_edges_from_that_label_estimates_zero_not_a_fallback() {
    // `Some(0)` from the seam is an exact answer and must be used as one: an ARTICLE has no OUT-going
    // LIKES in this corpus, so anchoring there and walking forwards really does emit nothing. Falling
    // back to the graph-wide degree here would invent a fan-out that does not exist.
    let g = asymmetric_graph();
    let rows = expand_rows("MATCH (a:ARTICLE)-[:LIKES]->(x) RETURN a, x", &g);
    assert!(
        rows.abs() < 1e-9,
        "an ARTICLE has no outgoing LIKES, so the estimate must be 0, got {rows}"
    );
}

#[test]
fn estimates_stay_finite_without_statistics() {
    // The no-stats path must not divide by zero or produce NaN: `directional_degree` returns `None`
    // without statistics and the graph-wide fallback takes over.
    let src = "MATCH (u:USER)-[:LIKES]->(a:ARTICLE) RETURN u, a";
    let toks = tokenize(src).unwrap();
    let ast = parse_tokens(&toks, src).unwrap();
    let validated = analyze(&ast).unwrap();
    let p = plan_physical_with_stats(&lower(&validated), &IndexCatalog::empty(), None)
        .root
        .clone();
    let expand = find_expand(&p).expect("expand");
    let e = estimate_cost(expand, None);
    assert!(e.rows.is_finite() && e.rows >= 0.0, "rows {}", e.rows);
    assert!(e.cost.is_finite() && e.cost >= 0.0, "cost {}", e.cost);
}

#[test]
fn a_type_spanning_two_start_labels_is_estimated_per_pair_not_from_a_sum() {
    // The counter is per `(label, type)` pair, so an anchor reads exactly its own pair. If the estimator
    // summed the type's counters across labels it would report the same inflated degree from both
    // anchors — which is the very symmetry #886 removes.
    let mut g = MemGraph::new();
    // 10 As with 3 outgoing T each; 5 Bs with 1 outgoing T each. Same type, different degrees.
    let a_nodes: Vec<_> = (0..10)
        .map(|i| g.add_node(["A"], [("i", Value::Integer(i))]))
        .collect();
    let b_nodes: Vec<_> = (0..5)
        .map(|i| g.add_node(["B"], [("i", Value::Integer(100 + i))]))
        .collect();
    let sinks: Vec<_> = (0..4)
        .map(|i| g.add_node(["S"], [("i", Value::Integer(200 + i))]))
        .collect();
    for (i, &a) in a_nodes.iter().enumerate() {
        for k in 0..3 {
            g.add_rel("T", a, sinks[(i + k) % sinks.len()], NO_PROPS);
        }
    }
    for (i, &b) in b_nodes.iter().enumerate() {
        g.add_rel("T", b, sinks[i % sinks.len()], NO_PROPS);
    }

    let from_a = expand_rows("MATCH (a:A)-[:T]->(s:S) RETURN a, s", &g) / 10.0;
    let from_b = expand_rows("MATCH (b:B)-[:T]->(s:S) RETURN b, s", &g) / 5.0;
    assert!(
        (from_a - 3.0).abs() < 1e-6,
        "degree out of an A must be 3, got {from_a}"
    );
    assert!(
        (from_b - 1.0).abs() < 1e-6,
        "degree out of a B must be 1, got {from_b}"
    );
    // A summing estimator would report (30 + 5) / population for both, which is neither 3 nor 1.
    assert!(
        (from_a - from_b).abs() > 1.0,
        "the two labels must estimate different degrees for the same type"
    );
}

#[test]
fn plan_choice_stays_deterministic_for_fixed_statistics() {
    // The estimator feeds a cost-based optimiser, so the same graph must always produce the same plan;
    // a directional read that depended on map iteration order would break that.
    let g = asymmetric_graph();
    let src = "MATCH (u:USER)-[:LIKES]->(a:ARTICLE) RETURN u, a";
    let first = format!("{:?}", plan(src, &g));
    for _ in 0..4 {
        assert_eq!(first, format!("{:?}", plan(src, &g)), "plan must be stable");
    }
}
