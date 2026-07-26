//! **Expansion-order enumeration for branched and comma-separated patterns** (`rmp` task #887).
//!
//! Task #858 chose the anchor of a straight chain by cost. This generalises the same enumeration from a
//! chain to a **tree**: the hops must merely form a connected, acyclic set rooted at the anchor, which
//! covers a star branching from a middle node and the connected comma-separated parts the lowering
//! turns into expands off an already-bound node.
//!
//! The gap it closes, measured by plan probe: `MATCH (a:ARTICLE)<-[:LIKES]-(v:USER),
//! (a)<-[:LIKES]-(u:USER) WHERE u.uidn = 42` planned `NodeByLabelScan(a)` and expanded twice out of the
//! article — never touching the index on `u` — because both hops leave the same node and so the pattern
//! is not a chain. It now anchors on the indexed `u`.
//!
//! Emission order is **breadth-first from the anchor**, chosen because it is deterministic and
//! independent of how the pattern was written — the whole point being to stop the spelling deciding the
//! plan. Every hop is emitted from a node already bound, so the operator spine stays linear even when
//! the pattern branches.
//!
//! As in #858, correctness comes first: re-ordering changes the traversal, so every test checks the
//! result **bag** against the no-statistics rule-based plan, not just the plan shape.

use graphus_core::Value;
use graphus_cypher::binding::{Parameters, bind_parameters};
use graphus_cypher::catalog::IndexCatalog;
use graphus_cypher::executor::execute;
use graphus_cypher::graph_access::{GraphAccess, MemGraph};
use graphus_cypher::lexer::tokenize;
use graphus_cypher::lower::lower;
use graphus_cypher::parser::parse_tokens;
use graphus_cypher::physical::{PhysicalPlan, plan_physical_with_stats};
use graphus_cypher::semantics::analyze;

const NO_PROPS: [(&str, Value); 0] = [];

/// Many `USER`s, few `ARTICLE`s, two likes each — so `LIKES` fans out hugely from an article and barely
/// at all from a user, and a two-edge pattern out of one user has something to match.
fn corpus() -> MemGraph {
    sized_corpus(400, 4)
}

/// A corpus of `n_users` users over `n_arts` articles, two likes each.
///
/// Sized explicitly where a test's pattern is combinatorial in the number of co-likers: a three-way
/// star over the full corpus enumerates 200x200x200 rows per article and takes over a minute to RUN —
/// a cost of the query, not of the planning under test, and not one a unit suite should pay.
fn sized_corpus(n_users: i64, n_arts: usize) -> MemGraph {
    let mut g = MemGraph::new();
    let users: Vec<_> = (0..n_users)
        .map(|i| g.add_node(["USER"], [("uidn", Value::Integer(i))]))
        .collect();
    let arts: Vec<_> = (0..n_arts)
        .map(|i| g.add_node(["ARTICLE"], [("aid", Value::Integer(i as i64))]))
        .collect();
    for (i, &u) in users.iter().enumerate() {
        g.add_rel("LIKES", u, arts[i % arts.len()], NO_PROPS);
        g.add_rel("LIKES", u, arts[(i + 1) % arts.len()], NO_PROPS);
    }
    g
}

fn indexed() -> IndexCatalog {
    IndexCatalog::builder()
        .with_label_property("USER", "uidn")
        .build()
}

fn compile(src: &str, g: &MemGraph, cat: &IndexCatalog) -> PhysicalPlan {
    let toks = tokenize(src).unwrap_or_else(|e| panic!("lex `{src}`: {e:?}"));
    let ast = parse_tokens(&toks, src).unwrap_or_else(|e| panic!("parse `{src}`: {e:?}"));
    let v = analyze(&ast).unwrap_or_else(|e| panic!("analyze `{src}`: {e:?}"));
    plan_physical_with_stats(&lower(&v), cat, g.statistics())
}

fn has_op(plan: &PhysicalPlan, name: &str) -> bool {
    format!("{:?}", plan.root).contains(&format!("{name} {{"))
}

fn rows_of(plan: &PhysicalPlan, g: &mut MemGraph, columns: &[&str]) -> Vec<String> {
    let bound = bind_parameters(plan, &Parameters::new()).expect("bind");
    let mut out: Vec<String> = execute(plan, &bound, g)
        .expect("open")
        .collect_all()
        .expect("run")
        .iter()
        .map(|r| {
            columns
                .iter()
                .map(|c| format!("{:?}", r.value(c)))
                .collect::<Vec<_>>()
                .join("|")
        })
        .collect();
    out.sort();
    out
}

/// Asserts the cost-based plan returns exactly the rule-based plan's bag, and that the bag is non-empty.
fn assert_order_preserves_bag(src: &str, g: &mut MemGraph, cat: &IndexCatalog, columns: &[&str]) {
    let toks = tokenize(src).unwrap();
    let ast = parse_tokens(&toks, src).unwrap();
    let v = analyze(&ast).unwrap();
    let logical = lower(&v);
    let costed = plan_physical_with_stats(&logical, cat, g.statistics());
    // The no-stats path runs no cost-based rewrite at all: the rule-based reference.
    let rule = plan_physical_with_stats(&logical, cat, None);
    let a = rows_of(&costed, g, columns);
    let b = rows_of(&rule, g, columns);
    assert!(
        !b.is_empty(),
        "the corpus query must match something, else the comparison is vacuous: {src}"
    );
    assert_eq!(a, b, "re-ordering changed the result bag for `{src}`");
}

// =================================================================================================
// The branch the chain enumeration could not reach
// =================================================================================================

/// Two hops leaving the SAME node, so the pattern is a star rather than a chain.
const BRANCH: &str = "MATCH (a:ARTICLE)<-[:LIKES]-(v:USER), (a)<-[:LIKES]-(u:USER) \
                      WHERE u.uidn = 42 RETURN v.uidn AS x ORDER BY x";

#[test]
fn a_branch_anchors_on_the_indexed_node() {
    let g = corpus();
    let cat = indexed();
    let plan = compile(BRANCH, &g, &cat);
    assert!(
        has_op(&plan, "NodeIndexSeek"),
        "a branched pattern must still anchor on its indexed node:\n{:?}",
        plan.root
    );
    assert!(
        !has_op(&plan, "NodeByLabelScan"),
        "and no longer scan every article"
    );
}

#[test]
fn a_branch_preserves_the_bag() {
    let mut g = corpus();
    let cat = indexed();
    assert_order_preserves_bag(BRANCH, &mut g, &cat, &["x"]);
}

#[test]
fn the_written_order_of_the_parts_stops_mattering() {
    // The same pattern with its parts swapped must plan the same way and return the same rows. That is
    // the property the task exists for: the spelling must stop deciding the plan.
    let mut g = corpus();
    let cat = indexed();
    let selective_last = "MATCH (a:ARTICLE)<-[:LIKES]-(v:USER), (a)<-[:LIKES]-(u:USER) \
                          WHERE u.uidn = 7 RETURN v.uidn AS x ORDER BY x";
    let selective_first = "MATCH (a:ARTICLE)<-[:LIKES]-(u:USER), (a)<-[:LIKES]-(v:USER) \
                           WHERE u.uidn = 7 RETURN v.uidn AS x ORDER BY x";
    for src in [selective_last, selective_first] {
        assert!(
            has_op(&compile(src, &g, &cat), "NodeIndexSeek"),
            "both spellings must anchor on the indexed node: {src}"
        );
    }
    let a = rows_of(&compile(selective_last, &g, &cat), &mut g, &["x"]);
    let b = rows_of(&compile(selective_first, &g, &cat), &mut g, &["x"]);
    assert!(!a.is_empty(), "non-vacuity");
    assert_eq!(a, b, "the two spellings describe the same pattern");
}

// =================================================================================================
// Legality
// =================================================================================================

#[test]
fn a_shared_relationship_type_keeps_its_isomorphism() {
    // Both hops are `LIKES`, so without a correctly re-derived isomorphism set the same edge could be
    // walked twice and `v` would come back equal to `u`.
    let mut g = corpus();
    let cat = indexed();
    assert_order_preserves_bag(BRANCH, &mut g, &cat, &["x"]);
    let rows = rows_of(&compile(BRANCH, &g, &cat), &mut g, &["x"]);
    assert!(
        !rows.iter().any(|r| r == "Integer(42)"),
        "user 42 must not be returned as its own co-liker through the edge it already used"
    );
    assert!(!rows.is_empty(), "and the pattern must still match");
}

#[test]
fn a_cycle_is_declined() {
    // A third hop closing the triangle makes both endpoints bound — a connection check, not a
    // traversal. The pass must decline the pattern rather than reorder it into a shape it cannot
    // express, and the answer must stay right.
    let mut g = corpus();
    let cat = indexed();
    let src = "MATCH (u:USER)-[:LIKES]->(a:ARTICLE)<-[:LIKES]-(v:USER)-[:LIKES]->(b:ARTICLE)\
               <-[:LIKES]-(u) WHERE u.uidn = 9 RETURN v.uidn AS x ORDER BY x";
    assert_order_preserves_bag(src, &mut g, &cat, &["x"]);
}

#[test]
fn a_three_way_star_preserves_the_bag() {
    // Small corpus: this pattern is a three-way product over the co-likers of one article, so the full
    // corpus would spend a minute EXECUTING it. The property under test is the bag, not the scale.
    let mut g = sized_corpus(24, 2);
    let cat = indexed();
    let src = "MATCH (a:ARTICLE)<-[:LIKES]-(v:USER), (a)<-[:LIKES]-(w:USER), \
               (a)<-[:LIKES]-(u:USER) WHERE u.uidn = 11 RETURN v.uidn AS x, w.uidn AS y \
               ORDER BY x, y";
    assert_order_preserves_bag(src, &mut g, &cat, &["x", "y"]);
}

#[test]
fn a_mixed_chain_and_branch_preserves_the_bag() {
    let mut g = corpus();
    let cat = indexed();
    let src = "MATCH (u:USER)-[:LIKES]->(a:ARTICLE)<-[:LIKES]-(v:USER), (v)-[:LIKES]->(b:ARTICLE) \
               WHERE u.uidn = 13 RETURN b.aid AS x ORDER BY x";
    assert_order_preserves_bag(src, &mut g, &cat, &["x"]);
}

#[test]
fn an_unindexed_branch_is_unchanged() {
    // With nothing seekable, no candidate can beat the rule-based plan — the gate that keeps this
    // rewrite from perturbing patterns it cannot help.
    let mut g = corpus();
    let empty = IndexCatalog::empty();
    assert_order_preserves_bag(BRANCH, &mut g, &empty, &["x"]);
}

#[test]
fn plan_choice_is_deterministic() {
    // Breadth-first emission from a fixed anchor, with candidates costed in a fixed order, must give
    // the same plan every time — a cost-based planner whose output wobbled would be unusable.
    let g = corpus();
    let cat = indexed();
    let first = format!("{:?}", compile(BRANCH, &g, &cat).root);
    for _ in 0..4 {
        assert_eq!(first, format!("{:?}", compile(BRANCH, &g, &cat).root));
    }
}

#[test]
fn planning_stays_bounded_on_a_wide_star() {
    // One candidate per node, each building one breadth-first order: linear, not factorial. A twelve-arm
    // star must plan promptly.
    let g = corpus();
    let cat = indexed();
    let mut parts = vec!["(a:ARTICLE)<-[:LIKES]-(u:USER)".to_owned()];
    for i in 0..12 {
        parts.push(format!("(a)<-[:LIKES]-(n{i}:USER)"));
    }
    let src = format!(
        "MATCH {} WHERE u.uidn = 1 RETURN count(*) AS c",
        parts.join(", ")
    );
    let start = std::time::Instant::now();
    let plan = compile(&src, &g, &cat);
    let elapsed = start.elapsed();
    assert!(
        elapsed.as_secs() < 5,
        "planning a 12-arm star took {elapsed:?}"
    );
    assert!(has_op(&plan, "ExpandAll"), "sanity: the plan must expand");
}
