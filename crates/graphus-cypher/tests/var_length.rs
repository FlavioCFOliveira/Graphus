//! End-to-end tests for **variable-length relationship patterns** (`-[*]->`, `-[*m..n]->`) over a
//! seeded [`MemGraph`], asserting the exact openCypher semantics (`rmp` #125).
//!
//! Each test runs the full pipeline — parse → semantic-analyse → lower → physical-plan → bind →
//! execute — and checks the produced rows against the openCypher rules:
//!
//! * a bare `*` is `1..∞` (at least one hop; never the zero-length self-path);
//! * an explicit lower bound of `0` (`*0..n`) admits the **zero-length** trail (the anchor itself,
//!   bound to an empty relationship list);
//! * bounds are inclusive on both ends (`*m..n` = hop counts `m, m+1, …, n`);
//! * **relationship isomorphism**: no relationship is repeated within a single path (nodes *may*
//!   repeat), so an unbounded `*` terminates on any graph including cycles;
//! * direction (`->`, `<-`, `-`) and the relationship-type filter are honoured per hop.
//!
//! These guard the engine independently of the openCypher TCK corpus.

use graphus_core::Value;
use graphus_cypher::binding::{Parameters, bind_parameters};
use graphus_cypher::catalog::IndexCatalog;
use graphus_cypher::executor::execute;
use graphus_cypher::graph_access::{MemGraph, NodeId};
use graphus_cypher::lexer::tokenize;
use graphus_cypher::lower::lower;
use graphus_cypher::parser::parse_tokens;
use graphus_cypher::physical::plan_physical;
use graphus_cypher::runtime::Row;
use graphus_cypher::semantics::analyze;

/// Compiles and runs `src` over `graph`, returning all result rows.
fn run(src: &str, graph: &mut MemGraph) -> Vec<Row> {
    let toks = tokenize(src).expect("lex");
    let ast = parse_tokens(&toks, src).expect("parse");
    let validated = analyze(&ast).expect("analyze");
    let plan = plan_physical(&lower(&validated), &IndexCatalog::empty());
    let bound = bind_parameters(&plan, &Parameters::new()).expect("bind");
    execute(&plan, &bound, graph)
        .expect("open cursor")
        .collect_all()
        .expect("rows")
}

fn s(v: &str) -> Value {
    Value::String(v.to_owned())
}
const NO_PROPS: [(&str, Value); 0] = [];

/// The `name` column of every row, sorted — the natural key of the fixtures below.
fn names(rows: &[Row], col: &str) -> Vec<String> {
    let mut out: Vec<String> = rows
        .iter()
        .map(|r| match r.value(col) {
            Value::String(s) => s,
            other => panic!("expected a string, got {other:?}"),
        })
        .collect();
    out.sort();
    out
}

/// A directed binary tree of depth 3 over `:LIKES`, rooted at the single `:A` node — the openCypher
/// `Match5` fixture shape (one root, two B, four C, eight D), keyed by `name`.
///
/// ```text
///            n0(:A)
///          /        \
///       n00(:B)    n01(:B)
///       /   \       /   \
///   n000   n001  n010   n011        (:C)
///   /  \   /  \   /  \   /  \
/// …eight :D leaves…
/// ```
fn binary_tree() -> (MemGraph, NodeId) {
    let mut g = MemGraph::new();
    let n0 = g.add_node(["A"], [("name", s("n0"))]);
    let n00 = g.add_node(["B"], [("name", s("n00"))]);
    let n01 = g.add_node(["B"], [("name", s("n01"))]);
    let leaf = |g: &mut MemGraph, parent: NodeId, name: &str, label: &str| {
        let n = g.add_node([label], [("name", s(name))]);
        g.add_rel("LIKES", parent, n, NO_PROPS);
        n
    };
    let n000 = leaf(&mut g, n00, "n000", "C");
    let n001 = leaf(&mut g, n00, "n001", "C");
    let n010 = leaf(&mut g, n01, "n010", "C");
    let n011 = leaf(&mut g, n01, "n011", "C");
    g.add_rel("LIKES", n0, n00, NO_PROPS);
    g.add_rel("LIKES", n0, n01, NO_PROPS);
    for (parent, base) in [
        (n000, "n000"),
        (n001, "n001"),
        (n010, "n010"),
        (n011, "n011"),
    ] {
        leaf(&mut g, parent, &format!("{base}0"), "D");
        leaf(&mut g, parent, &format!("{base}1"), "D");
    }
    (g, n0)
}

/// A bare `*` is `1..∞`: every descendant reachable in **one or more** hops, never the root itself.
#[test]
fn unbounded_star_is_one_to_infinity() {
    let (mut g, _root) = binary_tree();
    let rows = run(
        "MATCH (a:A) MATCH (a)-[:LIKES*]->(c) RETURN c.name AS n",
        &mut g,
    );
    // 2 + 4 + 8 = 14 descendants; the root (n0) is never returned (no zero-length path).
    assert_eq!(rows.len(), 14, "every descendant, exactly once");
    assert!(!names(&rows, "n").contains(&"n0".to_owned()));
}

/// `*1..1` (single bounded) returns only the **direct** children — the openCypher `Match5` [3] case.
#[test]
fn single_bounded_one() {
    let (mut g, _root) = binary_tree();
    let rows = run(
        "MATCH (a:A) MATCH (a)-[:LIKES*1..1]->(c) RETURN c.name AS n",
        &mut g,
    );
    assert_eq!(names(&rows, "n"), vec!["n00".to_owned(), "n01".to_owned()]);
}

/// `*2` (exact two hops): only the four grandchildren — `Match5` [4]/[10].
#[test]
fn exact_two_hops() {
    let (mut g, _root) = binary_tree();
    let rows = run(
        "MATCH (a:A) MATCH (a)-[:LIKES*2]->(c) RETURN c.name AS n",
        &mut g,
    );
    assert_eq!(
        names(&rows, "n"),
        vec!["n000", "n001", "n010", "n011"]
            .into_iter()
            .map(str::to_owned)
            .collect::<Vec<_>>()
    );
}

/// `*1..2` (upper and lower bounded): the two children **and** the four grandchildren — `Match5` [6].
#[test]
fn upper_and_lower_bounded() {
    let (mut g, _root) = binary_tree();
    let rows = run(
        "MATCH (a:A) MATCH (a)-[:LIKES*1..2]->(c) RETURN c.name AS n",
        &mut g,
    );
    assert_eq!(rows.len(), 2 + 4, "children + grandchildren");
}

/// `*2..3` (lower bounded above 1): grandchildren (4) and great-grandchildren (8) — `Match5` [16]-style.
#[test]
fn lower_bounded_above_one() {
    let (mut g, _root) = binary_tree();
    let rows = run(
        "MATCH (a:A) MATCH (a)-[:LIKES*2..3]->(c) RETURN c.name AS n",
        &mut g,
    );
    assert_eq!(rows.len(), 4 + 8);
}

/// `*0..0` (symmetrically bounded at zero): the **zero-length** trail only — the anchor itself, with
/// an empty relationship list. `Match5` [8]: exactly one row, `c == a`.
#[test]
fn zero_bounds_yield_the_anchor() {
    let (mut g, _root) = binary_tree();
    let rows = run(
        "MATCH (a:A) MATCH (a)-[:LIKES*0..0]->(c) RETURN c.name AS n",
        &mut g,
    );
    assert_eq!(
        names(&rows, "n"),
        vec!["n0".to_owned()],
        "the anchor, zero hops"
    );
}

/// `*0..1` includes the anchor (zero hops) **and** its direct children (one hop).
#[test]
fn zero_lower_bound_includes_anchor() {
    let (mut g, _root) = binary_tree();
    let rows = run(
        "MATCH (a:A) MATCH (a)-[:LIKES*0..1]->(c) RETURN c.name AS n",
        &mut g,
    );
    assert_eq!(
        names(&rows, "n"),
        vec!["n0".to_owned(), "n00".to_owned(), "n01".to_owned()]
    );
}

/// Direction is honoured: a reverse-arrow var-length from a leaf walks **up** to the root.
#[test]
fn direction_is_honoured() {
    let mut g = MemGraph::new();
    let a = g.add_node(["A"], [("name", s("a"))]);
    let b = g.add_node(["N"], [("name", s("b"))]);
    let c = g.add_node(["N"], [("name", s("c"))]);
    g.add_rel("R", a, b, NO_PROPS);
    g.add_rel("R", b, c, NO_PROPS);

    // Forward from `a`: reaches b, c.
    let fwd = run(
        "MATCH (a:A) MATCH (a)-[:R*]->(x) RETURN x.name AS n",
        &mut g,
    );
    assert_eq!(names(&fwd, "n"), vec!["b".to_owned(), "c".to_owned()]);

    // Backward from `c`: reaches b, a.
    let bwd = run(
        "MATCH (c:N {name:'c'}) MATCH (c)<-[:R*]-(x) RETURN x.name AS n",
        &mut g,
    );
    assert_eq!(names(&bwd, "n"), vec!["a".to_owned(), "b".to_owned()]);
}

/// The relationship-type filter is applied per hop: a `:KNOWS*` walk never crosses a `:LIKES` edge.
#[test]
fn relationship_type_filter_is_honoured() {
    let mut g = MemGraph::new();
    let a = g.add_node(["A"], [("name", s("a"))]);
    let b = g.add_node(["N"], [("name", s("b"))]);
    let c = g.add_node(["N"], [("name", s("c"))]);
    g.add_rel("KNOWS", a, b, NO_PROPS);
    g.add_rel("LIKES", b, c, NO_PROPS); // wrong type — the walk must stop at b.

    let rows = run(
        "MATCH (a:A) MATCH (a)-[:KNOWS*]->(x) RETURN x.name AS n",
        &mut g,
    );
    assert_eq!(
        names(&rows, "n"),
        vec!["b".to_owned()],
        "must not cross the LIKES edge"
    );
}

/// **Relationship isomorphism** on a cycle: an unbounded `*` over a 3-node ring terminates (no
/// relationship is reused within a path) and enumerates each reachable node once per distinct trail.
/// The ring `a→b→c→a` from `a` yields trails ending at b (a→b), c (a→b→c) and a (a→b→c→a) — every
/// edge used at most once — so the walk is finite.
#[test]
fn unbounded_on_a_cycle_terminates_and_is_relationship_unique() {
    let mut g = MemGraph::new();
    let a = g.add_node(["A"], [("name", s("a"))]);
    let b = g.add_node(["N"], [("name", s("b"))]);
    let c = g.add_node(["N"], [("name", s("c"))]);
    g.add_rel("R", a, b, NO_PROPS);
    g.add_rel("R", b, c, NO_PROPS);
    g.add_rel("R", c, a, NO_PROPS);

    // Each of the three edges is traversed at most once, so the longest trail is length 3 (a→b→c→a),
    // giving endpoints {b, c, a}. Without relationship-uniqueness this would loop forever.
    let rows = run(
        "MATCH (a:A) MATCH (a)-[:R*]->(x) RETURN x.name AS n",
        &mut g,
    );
    assert_eq!(
        names(&rows, "n"),
        vec!["a".to_owned(), "b".to_owned(), "c".to_owned()]
    );
}

/// A var-length hop chained with a fixed hop: `(a)-[*1..2]->()-[]->()` composes correctly
/// (`Match5` [21]-style "variable length + standard relationship in chain").
#[test]
fn varlength_chained_with_fixed_hop() {
    let (mut g, _root) = binary_tree();
    // a -[*1]-> (child) -[]-> (grandchild): the four grandchildren.
    let rows = run(
        "MATCH (a:A) MATCH (a)-[:LIKES*1..1]->()-[:LIKES]->(c) RETURN c.name AS n",
        &mut g,
    );
    assert_eq!(
        rows.len(),
        4,
        "the four grandchildren via 1 var hop + 1 fixed hop"
    );
}
