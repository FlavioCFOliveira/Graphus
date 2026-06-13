//! End-to-end tests for `shortestPath` / `allShortestPaths` (rmp #102).
//!
//! Each test runs the full pipeline — parse → semantic-analyse → lower → physical-plan → bind →
//! execute over a seeded [`MemGraph`] — and asserts the openCypher semantics: `shortestPath` returns
//! one minimal-length path; `allShortestPaths` returns every minimal-length path; both honour the
//! relationship-type set, direction and upper bound, are node-unique, terminate on cycles, and
//! produce no row when the endpoints are disconnected within the bounds.

use graphus_core::Value;
use graphus_cypher::binding::{Parameters, bind_parameters};
use graphus_cypher::catalog::IndexCatalog;
use graphus_cypher::executor::execute;
use graphus_cypher::graph_access::{MemGraph, NodeId};
use graphus_cypher::lexer::tokenize;
use graphus_cypher::lower::lower;
use graphus_cypher::parser::parse_tokens;
use graphus_cypher::physical::plan_physical;
use graphus_cypher::runtime::{Row, RowValue};
use graphus_cypher::semantics::analyze;

/// Compiles and runs `src` over `graph`, returning all result rows.
fn run(src: &str, graph: &mut MemGraph) -> Vec<Row> {
    let toks = tokenize(src).expect("lex");
    let ast = parse_tokens(&toks, src).expect("parse");
    let validated = analyze(&ast).expect("analyze");
    let plan = plan_physical(&lower(&validated), &IndexCatalog::empty());
    let params = Parameters::new();
    let bound = bind_parameters(&plan, &params).expect("bind");
    execute(&plan, &bound, graph)
        .expect("open cursor")
        .collect_all()
        .expect("rows")
}

fn s(v: &str) -> Value {
    Value::String(v.to_owned())
}

const NO_PROPS: [(&str, Value); 0] = [];

/// A node labelled `N` with a `name` property (the test fixtures key on `name`).
fn node(g: &mut MemGraph, name: &str) -> NodeId {
    g.add_node(["N"], [("name", s(name))])
}

/// `len(p)` column of every row, ascending — the hop count of each returned shortest path.
fn lengths(rows: &[Row]) -> Vec<i64> {
    let mut out: Vec<i64> = rows
        .iter()
        .map(|r| match r.value("len") {
            Value::Integer(n) => n,
            other => panic!("len should be an integer, got {other:?}"),
        })
        .collect();
    out.sort_unstable();
    out
}

/// A diamond: two distinct shortest paths of length 2 from `a` to `d` (`a-b-d`, `a-c-d`), plus a
/// strictly longer detour `a-e-f-d` (length 3) that must never be chosen.
fn diamond() -> (MemGraph, NodeId, NodeId) {
    let mut g = MemGraph::new();
    let a = node(&mut g, "a");
    let b = node(&mut g, "b");
    let c = node(&mut g, "c");
    let d = node(&mut g, "d");
    let e = node(&mut g, "e");
    let f = node(&mut g, "f");
    g.add_rel("R", a, b, NO_PROPS);
    g.add_rel("R", b, d, NO_PROPS);
    g.add_rel("R", a, c, NO_PROPS);
    g.add_rel("R", c, d, NO_PROPS);
    g.add_rel("R", a, e, NO_PROPS);
    g.add_rel("R", e, f, NO_PROPS);
    g.add_rel("R", f, d, NO_PROPS);
    (g, a, d)
}

#[test]
fn shortest_path_returns_one_minimal_path() {
    let (mut g, ..) = diamond();
    let rows = run(
        "MATCH (a:N {name:'a'}), (d:N {name:'d'}), p = shortestPath((a)-[:R*]-(d)) \
         RETURN length(p) AS len",
        &mut g,
    );
    assert_eq!(rows.len(), 1, "shortestPath returns exactly one path");
    assert_eq!(
        lengths(&rows),
        vec![2],
        "the minimal length is 2, not the detour's 3"
    );
}

#[test]
fn all_shortest_paths_returns_every_minimal_path() {
    let (mut g, ..) = diamond();
    let rows = run(
        "MATCH (a:N {name:'a'}), (d:N {name:'d'}), p = allShortestPaths((a)-[:R*]-(d)) \
         RETURN length(p) AS len",
        &mut g,
    );
    assert_eq!(
        lengths(&rows),
        vec![2, 2],
        "both length-2 paths (a-b-d and a-c-d) are returned; the length-3 detour is excluded"
    );
}

#[test]
fn shortest_path_honours_upper_bound() {
    let (mut g, ..) = diamond();
    // The endpoints are 2 hops apart; an upper bound of 1 admits no connecting path.
    let rows = run(
        "MATCH (a:N {name:'a'}), (d:N {name:'d'}), p = shortestPath((a)-[:R*..1]-(d)) \
         RETURN length(p) AS len",
        &mut g,
    );
    assert!(
        rows.is_empty(),
        "no path within the length bound yields no row"
    );
}

#[test]
fn shortest_path_disconnected_yields_no_row() {
    let mut g = MemGraph::new();
    let a = node(&mut g, "a");
    let b = node(&mut g, "b");
    let _z = node(&mut g, "z"); // isolated
    g.add_rel("R", a, b, NO_PROPS);
    let rows = run(
        "MATCH (a:N {name:'a'}), (z:N {name:'z'}), p = shortestPath((a)-[:R*]-(z)) \
         RETURN length(p) AS len",
        &mut g,
    );
    assert!(
        rows.is_empty(),
        "disconnected endpoints produce no row under MATCH"
    );
}

/// `shortestPath` composes with `OPTIONAL MATCH` **identically** to a variable-length expand. This
/// engine's handling of `OPTIONAL MATCH` connecting two already-bound nodes (a comma pattern, so the
/// optional pattern introduces no new node) is a pre-existing, engine-wide behaviour — independent of
/// `shortestPath`. The test asserts the two compose the same way for both a connected and a
/// disconnected pre-bound pair, so `shortestPath` introduces no divergence and a future fix to the
/// optional-correlation handling updates both in lock-step.
#[test]
fn optional_match_shortest_path_mirrors_varlength() {
    let mut g = MemGraph::new();
    let a = node(&mut g, "a");
    let b = node(&mut g, "b");
    let _z = node(&mut g, "z"); // isolated
    g.add_rel("R", a, b, NO_PROPS);

    // Connected pre-bound pair (a, b).
    let vl_conn = run(
        "MATCH (a:N {name:'a'}), (b:N {name:'b'}) OPTIONAL MATCH p = (a)-[:R*1..3]-(b) RETURN p",
        &mut g,
    );
    let sp_conn = run(
        "MATCH (a:N {name:'a'}), (b:N {name:'b'}) OPTIONAL MATCH p = shortestPath((a)-[:R*]-(b)) RETURN p",
        &mut g,
    );
    assert_eq!(
        sp_conn.len(),
        vl_conn.len(),
        "connected: shortestPath composes with OPTIONAL MATCH exactly like a var-length expand"
    );

    // Disconnected pre-bound pair (a, z).
    let vl_disc = run(
        "MATCH (a:N {name:'a'}), (z:N {name:'z'}) OPTIONAL MATCH p = (a)-[:R*1..3]-(z) RETURN p",
        &mut g,
    );
    let sp_disc = run(
        "MATCH (a:N {name:'a'}), (z:N {name:'z'}) OPTIONAL MATCH p = shortestPath((a)-[:R*]-(z)) RETURN p",
        &mut g,
    );
    assert_eq!(
        sp_disc.len(),
        vl_disc.len(),
        "disconnected: shortestPath composes with OPTIONAL MATCH exactly like a var-length expand"
    );
}

#[test]
fn shortest_path_self_pair_zero_length() {
    let mut g = MemGraph::new();
    let a = node(&mut g, "a");
    g.add_rel("R", a, a, NO_PROPS);
    // A lower bound of 0 admits the zero-length path (the node itself).
    let rows = run(
        "MATCH (a:N {name:'a'}), p = shortestPath((a)-[:R*0..]-(a)) RETURN length(p) AS len",
        &mut g,
    );
    assert_eq!(
        lengths(&rows),
        vec![0],
        "the shortest path from a node to itself is empty"
    );
}

#[test]
fn shortest_path_respects_direction() {
    // A forward chain a -> b -> d.
    let mut g = MemGraph::new();
    let a = node(&mut g, "a");
    let b = node(&mut g, "b");
    let d = node(&mut g, "d");
    g.add_rel("R", a, b, NO_PROPS);
    g.add_rel("R", b, d, NO_PROPS);

    // Forward: a ->* d exists (length 2).
    let fwd = run(
        "MATCH (a:N {name:'a'}), (d:N {name:'d'}), p = shortestPath((a)-[:R*]->(d)) \
         RETURN length(p) AS len",
        &mut g,
    );
    assert_eq!(lengths(&fwd), vec![2], "the directed forward path is found");

    // Reverse direction: d ->* a does not exist.
    let rev = run(
        "MATCH (a:N {name:'a'}), (d:N {name:'d'}), p = shortestPath((d)-[:R*]->(a)) \
         RETURN length(p) AS len",
        &mut g,
    );
    assert!(rev.is_empty(), "there is no forward path d ->* a");

    // Undirected: the same pair connects regardless of arrow.
    let undirected = run(
        "MATCH (a:N {name:'a'}), (d:N {name:'d'}), p = shortestPath((d)-[:R*]-(a)) \
         RETURN length(p) AS len",
        &mut g,
    );
    assert_eq!(
        lengths(&undirected),
        vec![2],
        "undirected traversal connects d and a"
    );
}

#[test]
fn shortest_path_respects_relationship_type() {
    // a -R-> b -R-> d (length 2 over R), plus a direct a -X-> d (length 1 over X).
    let mut g = MemGraph::new();
    let a = node(&mut g, "a");
    let b = node(&mut g, "b");
    let d = node(&mut g, "d");
    g.add_rel("R", a, b, NO_PROPS);
    g.add_rel("R", b, d, NO_PROPS);
    g.add_rel("X", a, d, NO_PROPS);

    // Constrained to R: the X shortcut is invisible, so the shortest is length 2.
    let only_r = run(
        "MATCH (a:N {name:'a'}), (d:N {name:'d'}), p = shortestPath((a)-[:R*]-(d)) \
         RETURN length(p) AS len",
        &mut g,
    );
    assert_eq!(lengths(&only_r), vec![2], ":R only ignores the :X shortcut");

    // Any type: the direct X edge is the shortest (length 1).
    let any = run(
        "MATCH (a:N {name:'a'}), (d:N {name:'d'}), p = shortestPath((a)-[*]-(d)) \
         RETURN length(p) AS len",
        &mut g,
    );
    assert_eq!(
        lengths(&any),
        vec![1],
        "the untyped shortest path uses the direct X edge"
    );
}

#[test]
fn all_shortest_paths_enumerates_parallel_edges() {
    // Two parallel R edges a => b: a multigraph, so two distinct length-1 shortest paths.
    let mut g = MemGraph::new();
    let a = node(&mut g, "a");
    let b = node(&mut g, "b");
    g.add_rel("R", a, b, NO_PROPS);
    g.add_rel("R", a, b, NO_PROPS);
    let rows = run(
        "MATCH (a:N {name:'a'}), (b:N {name:'b'}), p = allShortestPaths((a)-[:R*]->(b)) \
         RETURN length(p) AS len",
        &mut g,
    );
    assert_eq!(
        lengths(&rows),
        vec![1, 1],
        "each parallel edge is a distinct shortest path (multigraph)"
    );
}

#[test]
fn shortest_path_binds_relationships_and_path_value() {
    let (mut g, _a, d) = diamond();
    let rows = run(
        "MATCH (a:N {name:'a'}), (d:N {name:'d'}), p = shortestPath((a)-[:R*]-(d)) \
         RETURN relationships(p) AS rs, nodes(p) AS ns, p AS path",
        &mut g,
    );
    assert_eq!(rows.len(), 1);
    let Some(RowValue::List(rs)) = rows[0].get("rs") else {
        panic!("relationships(p) is a structural list");
    };
    assert_eq!(rs.len(), 2, "a length-2 path has two relationships");
    let path = rows[0]
        .get("path")
        .and_then(RowValue::as_path)
        .expect("p is a structural path value");
    assert_eq!(path.len(), 2);
    assert_eq!(
        path.steps.last().expect("last step").node,
        d,
        "the path arrives at d"
    );
}

#[test]
fn shortest_path_terminates_on_a_cycle() {
    // A cycle a -> b -> c -> a, with d hanging off c: an unbounded `*` must terminate (node-unique)
    // and find a -> b -> c -> d (length 3).
    let mut g = MemGraph::new();
    let a = node(&mut g, "a");
    let b = node(&mut g, "b");
    let c = node(&mut g, "c");
    let d = node(&mut g, "d");
    g.add_rel("R", a, b, NO_PROPS);
    g.add_rel("R", b, c, NO_PROPS);
    g.add_rel("R", c, a, NO_PROPS);
    g.add_rel("R", c, d, NO_PROPS);
    let rows = run(
        "MATCH (a:N {name:'a'}), (d:N {name:'d'}), p = shortestPath((a)-[:R*]->(d)) \
         RETURN length(p) AS len",
        &mut g,
    );
    assert_eq!(
        lengths(&rows),
        vec![3],
        "the cycle is escaped; the path is a-b-c-d"
    );
}
