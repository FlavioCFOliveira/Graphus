//! **A re-anchored plan must not seek on a key it has not bound yet** (`rmp` task #880, regression).
//!
//! Two cost-based rewrites move an index seek to the **bottom** of a pipeline: the single-hop
//! expand-direction reversal (`rmp` task #366) and the multi-hop chain re-anchoring that generalises it
//! (`rmp` task #858). Both pick the seek out of the peeled `Filter` stack by asking
//! `analyze_property_predicate` whether a conjunct constrains the node they want to anchor on — and
//! that function only proves the key expression does not reference **that node**. It says nothing about
//! the *other* nodes of the same pattern.
//!
//! So a conjunct joining two nodes of one pattern by a property — `WHERE c.cname = p.pid` — qualified
//! as a seek site, and the seek was planted underneath the very expand that binds `p`. At run time the
//! key evaluated to `null`, the seek matched nothing, and the query returned an **empty result where
//! the rule-based plan returned 50 rows**. Silent, total row loss, on a plan the cost model chose
//! because it looked cheap.
//!
//! The repair is a precondition on both rewrites: a conjunct may seed the bottom seek only when it
//! reads no other variable of the pattern. Otherwise it stays an ordinary residual filter — slower,
//! and right.
//!
//! Every assertion here compares against the statistics-free plan, never against a hand-written
//! expectation.

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

/// 600 people over 50 cities, so `p.pid = c.cname` is satisfied by exactly the 50 people whose id
/// equals the name of the city they live in — a non-empty answer the broken plan reported as empty.
fn corpus() -> MemGraph {
    let mut g = MemGraph::new();
    let topics: Vec<_> = (0..4)
        .map(|i| g.add_node(["TOPIC"], [("tid", Value::Integer(i))]))
        .collect();
    let cities: Vec<_> = (0..50)
        .map(|i| g.add_node(["CITY"], [("cname", Value::Integer(i))]))
        .collect();
    for i in 0..600i64 {
        let p = g.add_node(["PERSON"], [("pid", Value::Integer(i))]);
        g.add_rel("FOLLOWS", p, topics[(i % 4) as usize], NO_PROPS);
        g.add_rel("LIVES_IN", p, cities[(i % 50) as usize], NO_PROPS);
    }
    g
}

fn indexed() -> IndexCatalog {
    IndexCatalog::builder()
        .with_label_property("PERSON", "pid")
        .with_label_property("CITY", "cname")
        .build()
}

fn plan(src: &str, g: &MemGraph, cat: &IndexCatalog, stats: bool) -> PhysicalPlan {
    let toks = tokenize(src).unwrap_or_else(|e| panic!("lex `{src}`: {e:?}"));
    let ast = parse_tokens(&toks, src).unwrap_or_else(|e| panic!("parse `{src}`: {e:?}"));
    let v = analyze(&ast).unwrap_or_else(|e| panic!("analyze `{src}`: {e:?}"));
    plan_physical_with_stats(&lower(&v), cat, if stats { g.statistics() } else { None })
}

fn rows(p: &PhysicalPlan, g: &mut MemGraph) -> Vec<String> {
    let bound = bind_parameters(p, &Parameters::new()).expect("bind");
    let mut out: Vec<String> = execute(p, &bound, g)
        .unwrap_or_else(|e| panic!("open: {e:?}"))
        .collect_all()
        .unwrap_or_else(|e| panic!("run: {e:?}"))
        .iter()
        .map(|r| format!("{:?}", r.value("x")))
        .collect();
    out.sort();
    out
}

/// Every spelling of the defect: the joining conjunct written both ways round, over the single-hop
/// reversal (`rmp` #366) and over the multi-hop chain (`rmp` #858), plus the same shape with a third
/// hop so the chain has a real choice of anchors.
const JOINING_PREDICATES: &[&str] = &[
    "MATCH (p:PERSON)-[:LIVES_IN]->(c:CITY) WHERE c.cname = p.pid RETURN p.pid AS x ORDER BY x",
    "MATCH (p:PERSON)-[:LIVES_IN]->(c:CITY) WHERE p.pid = c.cname RETURN p.pid AS x ORDER BY x",
    "MATCH (t:TOPIC)<-[:FOLLOWS]-(p:PERSON)-[:LIVES_IN]->(c:CITY) \
     WHERE c.cname = p.pid RETURN p.pid AS x ORDER BY x",
    "MATCH (t:TOPIC)<-[:FOLLOWS]-(p:PERSON)-[:LIVES_IN]->(c:CITY) \
     WHERE p.pid = c.cname RETURN p.pid AS x ORDER BY x",
    "MATCH (t:TOPIC)<-[:FOLLOWS]-(p:PERSON)-[:LIVES_IN]->(c:CITY) \
     WHERE p.pid = c.cname AND t.tid = 1 RETURN p.pid AS x ORDER BY x",
];

#[test]
fn a_predicate_joining_two_pattern_nodes_never_becomes_the_bottom_seek() {
    let mut g = corpus();
    let cat = indexed();
    for src in JOINING_PREDICATES {
        let cost_based = rows(&plan(src, &g, &cat, true), &mut g);
        let reference = rows(&plan(src, &g, &cat, false), &mut g);
        assert!(
            !reference.is_empty(),
            "non-vacuity: the corpus query must match something: {src}"
        );
        assert_eq!(
            cost_based, reference,
            "the cost-based plan lost rows for `{src}`"
        );
    }
}

#[test]
fn the_defect_shows_as_a_seek_whose_key_reads_a_variable_bound_above_it() {
    // The plan-level statement of the same property, so a future rewrite that re-introduces the shape
    // is caught even on a corpus where the row loss happens to be invisible. A `NodeIndexSeek` renders
    // its key expression, so a key mentioning another pattern variable is exactly the broken shape.
    let g = corpus();
    let cat = indexed();
    for src in JOINING_PREDICATES {
        let text = plan(src, &g, &cat, true).root.to_string();
        for line in text.lines().filter(|l| l.contains("NodeIndexSeek")) {
            assert!(
                !line.contains("p.pid") || !line.contains("c:CITY"),
                "a seek must not key on a property of a node bound above it:\n{src}\n{text}"
            );
            assert!(
                !line.contains("c.cname") || !line.contains("p:PERSON"),
                "a seek must not key on a property of a node bound above it:\n{src}\n{text}"
            );
        }
    }
}

#[test]
fn an_independent_predicate_still_becomes_a_seek() {
    // The other half of the gate: it must decline only the joining conjunct, not every conjunct. If it
    // over-declined, the whole re-anchoring optimisation would quietly stop firing and nothing above
    // would notice.
    let g = corpus();
    let cat = indexed();
    let text = plan(
        "MATCH (t:TOPIC)<-[:FOLLOWS]-(p:PERSON)-[:LIVES_IN]->(c:CITY) \
         WHERE c.cname = 7 RETURN p.pid AS x ORDER BY x",
        &g,
        &cat,
        true,
    )
    .root
    .to_string();
    assert!(
        text.contains("NodeIndexSeek(c:CITY cname = 7"),
        "a literal-keyed predicate must still anchor the plan:\n{text}"
    );
}
