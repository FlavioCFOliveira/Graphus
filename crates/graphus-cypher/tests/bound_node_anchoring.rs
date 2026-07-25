//! **Bag-equality proof for bound-node anchoring** (`rmp` task #862).
//!
//! When a pattern part's written leading node is not yet bound but a *later* node of the same part
//! is, the lowering anchors the traversal on that bound node and walks out from it — backwards to
//! the leading node (mirroring each arrow) and then forwards. That is a pure access-path change, so
//! it must never alter the rows a query produces.
//!
//! Every test here is an **A/B pair over one graph**: the same pattern written twice, once so the
//! shared node leads its part (the historical lowering, which re-uses the binding directly) and once
//! so the shared node trails or sits inside it (the re-anchored lowering). Both spellings describe
//! the identical pattern, so their result **bags** must be identical — that is the property under
//! test, and it is what makes the rewrite safe to apply unconditionally.
//!
//! Both spellings are kept inside the **same** `MATCH` clause wherever isomorphism matters:
//! relationship isomorphism spans a whole `MATCH` (every comma-separated part shares one
//! already-traversed set), so moving a part to its own clause would legitimately change the bag and
//! would not be a fair comparison.

use graphus_core::Value;
use graphus_cypher::binding::{Parameters, bind_parameters};
use graphus_cypher::catalog::IndexCatalog;
use graphus_cypher::executor::execute;
use graphus_cypher::graph_access::MemGraph;
use graphus_cypher::lexer::tokenize;
use graphus_cypher::lower::lower;
use graphus_cypher::parser::parse_tokens;
use graphus_cypher::physical::plan_physical;
use graphus_cypher::runtime::Row;
use graphus_cypher::semantics::analyze;

// =================================================================================================
// Harness
// =================================================================================================

/// Compiles and runs `src` over `graph`, returning its rows.
fn run(src: &str, graph: &mut MemGraph) -> Vec<Row> {
    let toks = tokenize(src).unwrap_or_else(|e| panic!("lex `{src}`: {e:?}"));
    let ast = parse_tokens(&toks, src).unwrap_or_else(|e| panic!("parse `{src}`: {e:?}"));
    let validated = analyze(&ast).unwrap_or_else(|e| panic!("analyze `{src}`: {e:?}"));
    let plan = plan_physical(&lower(&validated), &IndexCatalog::empty());
    let bound = bind_parameters(&plan, &Parameters::new()).expect("bind");
    execute(&plan, &bound, graph)
        .unwrap_or_else(|e| panic!("open `{src}`: {e:?}"))
        .collect_all()
        .unwrap_or_else(|e| panic!("run `{src}`: {e:?}"))
}

/// The rows of `src` as a **sorted multiset** of their column renderings, so two spellings can be
/// compared as bags (row order is unspecified without `ORDER BY`).
fn bag(src: &str, graph: &mut MemGraph, columns: &[&str]) -> Vec<String> {
    let mut out: Vec<String> = run(src, graph)
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

/// Asserts the two spellings produce the identical result bag, and that the bag is **non-empty** —
/// two plans that both return nothing would agree vacuously and prove nothing.
fn assert_same_bag(graph: &mut MemGraph, columns: &[&str], leading: &str, reanchored: &str) {
    let a = bag(leading, graph, columns);
    let b = bag(reanchored, graph, columns);
    assert!(
        !a.is_empty(),
        "the corpus query must match something, else the comparison is vacuous:\n  {leading}"
    );
    assert_eq!(
        a, b,
        "bag mismatch between spellings\n  leading-node:  {leading}\n  re-anchored:   {reanchored}"
    );
}

/// A typed empty property list, so `add_rel`'s key-type generic can be inferred at the empty case.
const NO_PROPS: [(&str, Value); 0] = [];

/// A small graph that is deliberately awkward: shared targets (so a part can be re-anchored), a
/// cycle, an undirected-friendly type, a chain for a middle anchor, and typed/propertied edges.
fn seed() -> MemGraph {
    let mut g = MemGraph::new();
    let alice = g.add_node(["Person"], [("name", Value::String("alice".into()))]);
    let bob = g.add_node(["Person"], [("name", Value::String("bob".into()))]);
    let carol = g.add_node(["Robot"], [("name", Value::String("carol".into()))]);
    let post1 = g.add_node(["Post"], [("title", Value::String("p1".into()))]);
    let post2 = g.add_node(["Post"], [("title", Value::String("p2".into()))]);
    let tag = g.add_node(["Tag"], [("name", Value::String("rust".into()))]);

    // Shared targets: three people like two posts, so `(v)-[:LIKES]->(a)` has several matches per `a`.
    for (p, post) in [(alice, post1), (bob, post1), (carol, post1), (alice, post2)] {
        g.add_rel("LIKES", p, post, [("w", Value::Integer(1))]);
    }
    g.add_rel("LIKES", bob, post2, [("w", Value::Integer(2))]);
    // A cycle and a symmetric-looking type.
    g.add_rel("KNOWS", alice, bob, NO_PROPS);
    g.add_rel("KNOWS", bob, carol, NO_PROPS);
    g.add_rel("KNOWS", carol, alice, NO_PROPS);
    // A chain so a middle node can be the anchor: post -TAGGED-> tag, and person -WROTE-> post.
    g.add_rel("TAGGED", post1, tag, NO_PROPS);
    g.add_rel("TAGGED", post2, tag, NO_PROPS);
    g.add_rel("WROTE", alice, post1, NO_PROPS);
    g.add_rel("WROTE", bob, post2, NO_PROPS);
    g
}

// =================================================================================================
// The corpus
// =================================================================================================

#[test]
fn trailing_bound_node_directed() {
    let mut g = seed();
    assert_same_bag(
        &mut g,
        &["un", "vn"],
        "MATCH (u)-[:LIKES]->(a), (a)<-[:LIKES]-(v) RETURN u.name AS un, v.name AS vn",
        "MATCH (u)-[:LIKES]->(a), (v)-[:LIKES]->(a) RETURN u.name AS un, v.name AS vn",
    );
}

#[test]
fn trailing_bound_node_undirected() {
    let mut g = seed();
    assert_same_bag(
        &mut g,
        &["un", "vn"],
        "MATCH (u)-[:KNOWS]-(a), (a)-[:KNOWS]-(v) RETURN u.name AS un, v.name AS vn",
        "MATCH (u)-[:KNOWS]-(a), (v)-[:KNOWS]-(a) RETURN u.name AS un, v.name AS vn",
    );
}

#[test]
fn middle_bound_node_walks_both_ways() {
    let mut g = seed();
    // `p` is bound by the first part and sits in the MIDDLE of the second: the walk goes backwards
    // to `w` (arrow mirrored) and forwards to `t`.
    assert_same_bag(
        &mut g,
        &["wn", "tn"],
        "MATCH (x)-[:LIKES]->(p), (p)<-[:WROTE]-(w), (p)-[:TAGGED]->(t) \
         RETURN w.name AS wn, t.name AS tn",
        "MATCH (x)-[:LIKES]->(p), (w)-[:WROTE]->(p)-[:TAGGED]->(t) \
         RETURN w.name AS wn, t.name AS tn",
    );
}

#[test]
fn reached_node_labels_are_enforced() {
    let mut g = seed();
    // The re-anchored walk reaches `v` through the relationship, so `v`'s label must be applied as a
    // filter rather than by a scan — a label that would silently vanish is exactly the regression
    // this pins.
    assert_same_bag(
        &mut g,
        &["un", "vn"],
        "MATCH (u)-[:LIKES]->(a), (a)<-[:LIKES]-(v:Person) RETURN u.name AS un, v.name AS vn",
        "MATCH (u)-[:LIKES]->(a), (v:Person)-[:LIKES]->(a) RETURN u.name AS un, v.name AS vn",
    );
}

#[test]
fn reached_node_inline_properties_are_enforced() {
    let mut g = seed();
    assert_same_bag(
        &mut g,
        &["un", "vn"],
        "MATCH (u)-[:LIKES]->(a), (a)<-[:LIKES]-(v {name: 'bob'}) RETURN u.name AS un, v.name AS vn",
        "MATCH (u)-[:LIKES]->(a), (v {name: 'bob'})-[:LIKES]->(a) RETURN u.name AS un, v.name AS vn",
    );
}

#[test]
fn relationship_inline_properties_are_enforced() {
    let mut g = seed();
    assert_same_bag(
        &mut g,
        &["un", "vn"],
        "MATCH (u)-[:LIKES]->(a), (a)<-[r:LIKES {w: 2}]-(v) RETURN u.name AS un, v.name AS vn",
        "MATCH (u)-[:LIKES]->(a), (v)-[r:LIKES {w: 2}]->(a) RETURN u.name AS un, v.name AS vn",
    );
}

#[test]
fn variable_length_hop_reversed() {
    let mut g = seed();
    assert_same_bag(
        &mut g,
        &["tn", "cn"],
        "MATCH (x)-[:LIKES]->(p)-[:TAGGED]->(t), (t)<-[:TAGGED*1..2]-(c) \
         RETURN t.name AS tn, c.title AS cn",
        "MATCH (x)-[:LIKES]->(p)-[:TAGGED]->(t), (c)-[:TAGGED*1..2]->(t) \
         RETURN t.name AS tn, c.title AS cn",
    );
}

#[test]
fn optional_match_reanchors_and_still_null_fills() {
    let mut g = seed();
    // The optional pattern's later node is bound by the driving row, so it re-anchors; the left-outer
    // null-fill must survive it (the `Tag` node has no `LIKES`, so it exercises the no-match row).
    assert_same_bag(
        &mut g,
        &["an", "vn"],
        "MATCH (a) OPTIONAL MATCH (a)<-[:LIKES]-(v) RETURN a.title AS an, v.name AS vn",
        "MATCH (a) OPTIONAL MATCH (v)-[:LIKES]->(a) RETURN a.title AS an, v.name AS vn",
    );
}

#[test]
fn cycle_back_to_the_anchor() {
    let mut g = seed();
    // The second part closes a cycle back onto an already-bound node at BOTH ends.
    assert_same_bag(
        &mut g,
        &["un", "vn"],
        "MATCH (u)-[:KNOWS]->(v), (v)-[:KNOWS]->(w) RETURN u.name AS un, w.name AS vn",
        "MATCH (u)-[:KNOWS]->(v), (w)<-[:KNOWS]-(v) RETURN u.name AS un, w.name AS vn",
    );
}

#[test]
fn disconnected_part_is_still_a_cartesian_product() {
    let mut g = seed();
    // Nothing is shared, so no re-anchoring is possible and the part keeps its own scan: the bag is
    // the full cross product, which this pins so the rewrite cannot silently drop it.
    let rows = run(
        "MATCH (p:Person), (t:Tag) RETURN p.name AS pn, t.name AS tn",
        &mut g,
    );
    assert_eq!(rows.len(), 2, "2 Person x 1 Tag = 2 rows, got {rows:?}");
}
