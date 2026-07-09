//! End-to-end tests for **quantified path patterns** (QPP, GPM / Neo4j 5.9+): the parenthesized
//! interior path pattern with a quantifier `((x)-[r]->(y) [WHERE p]){q}`, its **group variables**
//! (interior node/relationship variables become lists in the outer scope), **trail** semantics (no
//! relationship traversed twice), boundary-node juxtaposition, and the `+ | * | {n} | {n,m} | {n,} |
//! {,m}` quantifiers.
//!
//! Each test runs the full `parse → semantics → plan → execute` pipeline over a seeded
//! [`MemGraph`], exactly like `executor.rs` / `label_expressions.rs`, so it proves the whole stack —
//! the parser's QPP grammar, the semantic group-variable binding, the planner's repetition operator,
//! and the executor's trail walk — end to end. Semantics is pinned to Neo4j 5.x GPM (quantified path
//! patterns; greedy, trail, inclusive ranges, group variables).

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

// =================================================================================================
// Harness
// =================================================================================================

fn i(n: i64) -> Value {
    Value::Integer(n)
}
const NO_PROPS: [(&str, Value); 0] = [];

/// Runs `src` over `graph` and returns all result rows (empty catalog, no params).
fn run(src: &str, graph: &mut MemGraph) -> Vec<Row> {
    run_params(src, graph, &Parameters::new())
}

fn run_params(src: &str, graph: &mut MemGraph, params: &Parameters) -> Vec<Row> {
    let toks = tokenize(src).expect("lex");
    let ast = parse_tokens(&toks, src).expect("parse");
    let validated = analyze(&ast).unwrap_or_else(|e| panic!("analyze `{src}`: {e:?}"));
    let plan = plan_physical(&lower(&validated), &IndexCatalog::empty());
    let bound = bind_parameters(&plan, params).expect("bind");
    execute(&plan, &bound, graph)
        .expect("open cursor")
        .collect_all()
        .expect("rows")
}

/// Parses `src`, returning `Ok(())` or the parser error string.
fn parse_only(src: &str) -> Result<(), String> {
    let toks = tokenize(src).map_err(|e| format!("{e}"))?;
    parse_tokens(&toks, src)
        .map(|_| ())
        .map_err(|e| format!("{e}"))
}

/// Compiles `src` through semantic analysis, returning the error `Debug` string (or panics if it
/// unexpectedly succeeds). Used to assert an illegal construct is rejected.
fn compile_err(src: &str) -> String {
    let toks = tokenize(src).expect("lex");
    let ast = match parse_tokens(&toks, src) {
        Ok(ast) => ast,
        Err(e) => return format!("{e:?}"),
    };
    match analyze(&ast) {
        Err(e) => format!("{e:?}"),
        Ok(_) => panic!("expected `{src}` to be rejected, but it compiled"),
    }
}

/// The single-column integer value of each row, sorted, for order-insensitive comparison.
fn ints(rows: &[Row], col: &str) -> Vec<i64> {
    let mut out: Vec<i64> = rows
        .iter()
        .map(|r| match r.value(col) {
            Value::Integer(n) => n,
            other => panic!("expected an int in `{col}`, got {other:?}"),
        })
        .collect();
    out.sort_unstable();
    out
}

/// The `RowValue` of a named column (to inspect list group variables directly).
fn col<'a>(row: &'a Row, name: &str) -> &'a RowValue {
    let idx = row
        .columns()
        .iter()
        .position(|c| c == name)
        .unwrap_or_else(|| panic!("no column `{name}` in {:?}", row.columns()));
    &row.values()[idx]
}

/// The length of a `List` group variable on `row`.
fn list_len(row: &Row, name: &str) -> usize {
    match col(row, name) {
        RowValue::List(items) => items.len(),
        other => panic!("expected a list in `{name}`, got {other:?}"),
    }
}

// =================================================================================================
// Fixtures
// =================================================================================================

/// A directed chain `c0 -[:R w=k]-> c1 -[:R]-> c2 -[:R]-> c3`, plus a branch `c1 -[:R w=9]-> c4`.
/// Every node carries an integer `id`.
fn seed_chain() -> (MemGraph, Vec<NodeId>) {
    let mut g = MemGraph::new();
    let c: Vec<NodeId> = (0..4).map(|k| g.add_node(["N"], [("id", i(k))])).collect();
    for k in 0..3 {
        g.add_rel("R", c[k], c[k + 1], [("w", i(k as i64))]);
    }
    let c4 = g.add_node(["N"], [("id", i(4))]);
    g.add_rel("R", c[1], c4, [("w", i(9))]);
    let mut ids = c;
    ids.push(c4);
    (g, ids)
}

/// A directed triangle `t0 -[:E]-> t1 -[:E]-> t2 -[:E]-> t0`.
fn seed_triangle() -> MemGraph {
    let mut g = MemGraph::new();
    let t: Vec<NodeId> = (0..3).map(|k| g.add_node(["T"], [("id", i(k))])).collect();
    g.add_rel("E", t[0], t[1], NO_PROPS);
    g.add_rel("E", t[1], t[2], NO_PROPS);
    g.add_rel("E", t[2], t[0], NO_PROPS);
    g
}

// =================================================================================================
// Parsing
// =================================================================================================

#[test]
fn parses_every_quantifier_form() {
    for q in [
        "MATCH (a)((x)-[:R]->(y))+(b) RETURN a",
        "MATCH (a)((x)-[:R]->(y))*(b) RETURN a",
        "MATCH (a)((x)-[:R]->(y)){2}(b) RETURN a",
        "MATCH (a)((x)-[:R]->(y)){1,3}(b) RETURN a",
        "MATCH (a)((x)-[:R]->(y)){2,}(b) RETURN a",
        "MATCH (a)((x)-[:R]->(y)){,4}(b) RETURN a",
        "MATCH (a)((x)-[r:R]->(y) WHERE x.age > 18){1,3}(b) RETURN a",
        "MATCH ((x)-[:R]->(y))+ RETURN x",
        "MATCH (a) ((n)-[e:KNOWS]->(m))+ (b) RETURN n",
        "MATCH p = (a)((x)-[:R]->(y)){2,}(b) RETURN p",
        "MATCH (a)-[:R]->(m)((x)-[:S]->(y))+(b) RETURN a",
        "MATCH (a)((x)-[:R]->(y))+(m)((u)-[:S]->(v))+(b) RETURN a",
    ] {
        parse_only(q).unwrap_or_else(|e| panic!("expected `{q}` to parse: {e}"));
    }
}

#[test]
fn parses_multi_relationship_interior() {
    // A multi-relationship interior (Neo4j 5.x GPM) parses: the first hop lives on the link's flat
    // fields, every further hop in `QppInfo::interior_extra`.
    for q in [
        "MATCH (a)((x)-[r1:R]->(m)-[r2:S]->(y))+(b) RETURN a",
        "MATCH (a)((x)-[:R]->(m)-[:S]->(y)){1,3}(b) RETURN a",
        "MATCH (a)((x)-[:R]->(m)<-[:S]-(y))*(b) RETURN a",
        "MATCH (a)((x)-[:R]->(m)-[:S]->(n)-[:T]->(y))+(b) RETURN a", // three hops
        "MATCH (a)((x)-[r1:R]->(m)-[r2:S]->(y) WHERE r1.w < r2.w){2}(b) RETURN a",
        "MATCH ((x)-[:R]->(m)-[:S]->(y))+ RETURN x", // leading QPP, synth boundaries
    ] {
        parse_only(q).unwrap_or_else(|e| panic!("expected `{q}` to parse: {e}"));
    }
}

#[test]
fn rejects_nested_quantified_path_at_parse() {
    let err = parse_only("MATCH (a)(((x)-[r]->(y))+)+(b) RETURN a")
        .expect_err("nested QPP must be rejected");
    assert!(err.contains("nested"), "got: {err}");
    // A nested QPP is still rejected even when it follows another interior hop.
    let err2 = parse_only("MATCH (a)((x)-[:R]->(m)((u)-[:S]->(v))+(y))+(b) RETURN a")
        .expect_err("nested QPP inside a multi-hop interior must be rejected");
    assert!(err2.contains("nested"), "got: {err2}");
}

// =================================================================================================
// Execution — quantifiers over a linear chain
// =================================================================================================

#[test]
fn plus_enumerates_all_trail_endpoints() {
    let (mut g, _) = seed_chain();
    // From c0: reach c1, c2, c3 along the main chain, and c4 via the branch.
    let rows = run(
        "MATCH (a {id:0})((x)-[:R]->(y))+(b) RETURN b.id AS bid",
        &mut g,
    );
    assert_eq!(ints(&rows, "bid"), vec![1, 2, 3, 4]);
}

#[test]
fn exact_count_reaches_only_that_depth() {
    let (mut g, _) = seed_chain();
    // Exactly two hops from c0: c2 (via c1) and c4 (via c1).
    let rows = run(
        "MATCH (a {id:0})((x)-[:R]->(y)){2}(b) RETURN b.id AS bid",
        &mut g,
    );
    assert_eq!(ints(&rows, "bid"), vec![2, 4]);
}

#[test]
fn inclusive_range_covers_both_bounds() {
    let (mut g, _) = seed_chain();
    // 1..2 hops from c0: c1 (1 hop), c2 & c4 (2 hops).
    let rows = run(
        "MATCH (a {id:0})((x)-[:R]->(y)){1,2}(b) RETURN b.id AS bid",
        &mut g,
    );
    assert_eq!(ints(&rows, "bid"), vec![1, 2, 4]);
}

#[test]
fn lower_bounded_range_is_unbounded_above() {
    let (mut g, _) = seed_chain();
    // {2,}: two-or-more hops from c0 → c2, c3, c4.
    let rows = run(
        "MATCH (a {id:0})((x)-[:R]->(y)){2,}(b) RETURN b.id AS bid",
        &mut g,
    );
    assert_eq!(ints(&rows, "bid"), vec![2, 3, 4]);
}

#[test]
fn upper_bounded_range_starts_at_one_iteration() {
    let (mut g, _) = seed_chain();
    // {,2}: zero-or-one-or-two hops. Zero hops → c0 itself; then c1, c2, c4.
    let rows = run(
        "MATCH (a {id:0})((x)-[:R]->(y)){,2}(b) RETURN b.id AS bid",
        &mut g,
    );
    assert_eq!(ints(&rows, "bid"), vec![0, 1, 2, 4]);
}

#[test]
fn star_includes_the_zero_length_walk() {
    let (mut g, _) = seed_chain();
    // `*` (0+): the zero-iteration walk binds the boundary to the anchor itself (c0), plus all
    // positive-length endpoints.
    let rows = run(
        "MATCH (a {id:0})((x)-[:R]->(y))*(b) RETURN b.id AS bid",
        &mut g,
    );
    assert_eq!(ints(&rows, "bid"), vec![0, 1, 2, 3, 4]);
}

// =================================================================================================
// Group variables
// =================================================================================================

#[test]
fn group_variables_are_ordered_lists_per_iteration() {
    let (mut g, _) = seed_chain();
    // The three-hop main-chain walk c0→c1→c2→c3: x = [c0,c1,c2], y = [c1,c2,c3], r has 3 rels.
    let rows = run(
        "MATCH (a {id:0})((x)-[r:R]->(y))+(b) WHERE b.id = 3 RETURN x, y, r",
        &mut g,
    );
    assert_eq!(rows.len(), 1);
    assert_eq!(list_len(&rows[0], "x"), 3);
    assert_eq!(list_len(&rows[0], "y"), 3);
    assert_eq!(list_len(&rows[0], "r"), 3);
    // The group lists are readable as ordinary Cypher lists via list functions / indexing.
    let rows2 = run(
        "MATCH (a {id:0})((x)-[r:R]->(y))+(b) WHERE b.id = 3 \
         RETURN [n IN x | n.id] AS xs, [n IN y | n.id] AS ys, size(r) AS rc",
        &mut g,
    );
    assert_eq!(rows2.len(), 1);
    assert_eq!(rows2[0].value("rc"), i(3));
    assert_eq!(rows2[0].value("xs"), Value::List(vec![i(0), i(1), i(2)]),);
    assert_eq!(rows2[0].value("ys"), Value::List(vec![i(1), i(2), i(3)]),);
}

#[test]
fn boundary_nodes_are_scalar_singletons() {
    let (mut g, _) = seed_chain();
    // `a` and `b` are singletons even though `x`/`y` are group lists: a is the fixed anchor.
    let rows = run(
        "MATCH (a {id:0})((x)-[:R]->(y))+(b) WHERE b.id = 2 RETURN a.id AS aid, b.id AS bid",
        &mut g,
    );
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].value("aid"), i(0));
    assert_eq!(rows[0].value("bid"), i(2));
}

// =================================================================================================
// Trail semantics
// =================================================================================================

#[test]
fn trail_semantics_forbid_reusing_a_relationship() {
    let mut g = seed_triangle();
    // Directed triangle from t0: t0→t1, t0→t1→t2, t0→t1→t2→t0 (3 distinct edges). A fourth hop would
    // reuse the first edge, which trail semantics forbid — so exactly three walks.
    let rows = run(
        "MATCH (a {id:0})((x)-[:E]->(y))+(b) RETURN count(*) AS c",
        &mut g,
    );
    assert_eq!(rows[0].value("c"), i(3));
}

#[test]
fn undirected_trail_walks_both_ways_without_reusing_edges() {
    let mut g = seed_triangle();
    // Undirected, exactly three hops from t0: the two ways around the triangle, both ending at t0.
    let rows = run(
        "MATCH (a {id:0})((x)-[:E]-(y)){3}(b) RETURN b.id AS bid",
        &mut g,
    );
    assert_eq!(rows.len(), 2);
    assert!(rows.iter().all(|r| r.value("bid") == i(0)));
}

// =================================================================================================
// Interior predicates
// =================================================================================================

#[test]
fn inner_where_prunes_per_iteration() {
    let (mut g, _) = seed_chain();
    // Only relationships with w < 2 may participate: r(c0→c1, w=0) and r(c1→c2, w=1). The branch
    // edge (w=9) and c2→c3 (w=2) are excluded, so reachable b ∈ {c1, c2}.
    let rows = run(
        "MATCH (a {id:0})((x)-[r:R]->(y) WHERE r.w < 2)+(b) RETURN b.id AS bid",
        &mut g,
    );
    assert_eq!(ints(&rows, "bid"), vec![1, 2]);
}

#[test]
fn inner_where_may_relate_the_iteration_endpoints() {
    let (mut g, _) = seed_chain();
    // Every hop advances id by 1 on the main chain (y.id = x.id + 1); the branch edge c1→c4 jumps
    // 1→4 and fails the predicate, so only the main chain is walked.
    let rows = run(
        "MATCH (a {id:0})((x)-[:R]->(y) WHERE y.id = x.id + 1)+(b) RETURN b.id AS bid",
        &mut g,
    );
    assert_eq!(ints(&rows, "bid"), vec![1, 2, 3]);
}

#[test]
fn interior_node_labels_and_props_constrain_each_iteration() {
    let mut g = MemGraph::new();
    // p0 -[:R]-> p1(:VIP) -[:R]-> p2(:VIP) -[:R]-> p3
    let p: Vec<NodeId> = (0..4)
        .map(|k| {
            let labels: &[&str] = if k == 1 || k == 2 {
                &["N", "VIP"]
            } else {
                &["N"]
            };
            g.add_node(labels.iter().copied(), [("id", i(k))])
        })
        .collect();
    for k in 0..3 {
        g.add_rel("R", p[k], p[k + 1], NO_PROPS);
    }
    // Require every iteration's END node to be a :VIP. From p0: p0→p1 (p1 VIP ✓), p0→p1→p2 (p2 VIP ✓).
    // Extending to p3 fails (p3 not VIP), so reachable b ∈ {p1, p2}.
    let rows = run(
        "MATCH (a {id:0})((x)-[:R]->(y:VIP))+(b) RETURN b.id AS bid",
        &mut g,
    );
    assert_eq!(ints(&rows, "bid"), vec![1, 2]);
}

#[test]
fn interior_relationship_property_filter() {
    let (mut g, _) = seed_chain();
    // Inline relationship property map on the interior hop: only w=0 edges. Just c0→c1 qualifies.
    let rows = run(
        "MATCH (a {id:0})((x)-[r:R {w:0}]->(y))+(b) RETURN b.id AS bid",
        &mut g,
    );
    assert_eq!(ints(&rows, "bid"), vec![1]);
}

#[test]
fn inner_where_reads_a_parameter() {
    let (mut g, _) = seed_chain();
    let mut params = Parameters::new();
    params.insert("cap", i(2));
    let rows = run_params(
        "MATCH (a {id:0})((x)-[r:R]->(y) WHERE r.w < $cap)+(b) RETURN b.id AS bid",
        &mut g,
        &params,
    );
    assert_eq!(ints(&rows, "bid"), vec![1, 2]);
}

// =================================================================================================
// Boundary nodes & into-binding
// =================================================================================================

#[test]
fn trailing_boundary_node_label_and_property_filter() {
    let (mut g, _) = seed_chain();
    // The trailing boundary constrains only the final node: b must have id = 3.
    let rows = run(
        "MATCH (a {id:0})((x)-[:R]->(y))+(b {id:3}) RETURN count(*) AS c, b.id AS bid",
        &mut g,
    );
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].value("c"), i(1));
    assert_eq!(rows[0].value("bid"), i(3));
}

#[test]
fn into_binding_keeps_only_walks_reaching_the_bound_boundary() {
    let (mut g, _) = seed_chain();
    // `b` is bound before the QPP: only walks ending at c3 are kept (the single 3-hop trail).
    let rows = run(
        "MATCH (a {id:0}), (b {id:3}) MATCH (a)((x)-[r:R]->(y))+(b) RETURN size(r) AS rc",
        &mut g,
    );
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].value("rc"), i(3));
}

// =================================================================================================
// Composition with ordinary pattern factors
// =================================================================================================

#[test]
fn qpp_composes_after_a_fixed_relationship() {
    let (mut g, _) = seed_chain();
    // `(a)-[:R]->(m)((x)-[:R]->(y))+(b)`: one fixed hop from c0 to c1, then a QPP from c1.
    let rows = run(
        "MATCH (a {id:0})-[:R]->(m)((x)-[:R]->(y))+(b) RETURN b.id AS bid",
        &mut g,
    );
    // From c1: reach c2, c3, c4.
    assert_eq!(ints(&rows, "bid"), vec![2, 3, 4]);
}

#[test]
fn relationship_isomorphism_spans_qpp_and_neighbouring_hops() {
    // a -[:R]-> b, with a QPP that could otherwise walk the same edge back undirected.
    let mut g = MemGraph::new();
    let a = g.add_node(["N"], [("id", i(0))]);
    let b = g.add_node(["N"], [("id", i(1))]);
    g.add_rel("R", a, b, NO_PROPS);
    // `(a)-[e:R]-(m)((x)-[:R]-(y))+(z)`: the fixed hop consumes the only edge; the undirected QPP
    // from m=b cannot reuse it (trail spans the whole pattern), so it yields no additional hop and
    // the `+` (min 1) makes the whole match fail.
    let rows = run(
        "MATCH (a {id:0})-[e:R]-(m)((x)-[:R]-(y))+(z) RETURN count(*) AS c",
        &mut g,
    );
    assert_eq!(rows[0].value("c"), i(0));
}

// =================================================================================================
// Errors
// =================================================================================================

#[test]
fn rejects_qpp_in_create() {
    let err = compile_err("CREATE (a)((x)-[r:R]->(y))+(b)");
    assert!(err.contains("InvalidQuantifiedPath"), "got: {err}");
    assert!(err.contains("CREATE or MERGE"), "got: {err}");
}

#[test]
fn rejects_qpp_in_merge() {
    let err = compile_err("MERGE (a)((x)-[r:R]->(y))+(b)");
    assert!(err.contains("InvalidQuantifiedPath"), "got: {err}");
}

#[test]
fn rejects_inconsistent_quantifier_bounds() {
    let err = compile_err("MATCH (a)((x)-[r:R]->(y)){3,1}(b) RETURN a");
    assert!(err.contains("InvalidQuantifiedPath"), "got: {err}");
    assert!(err.contains("exceeds its upper bound"), "got: {err}");
}

#[test]
fn rejects_interior_endpoints_sharing_a_variable() {
    // `((x)-[r]->(x))` would require a per-iteration self-loop that one group binding cannot model.
    let err = compile_err("MATCH (a)((x)-[r:R]->(x))+(b) RETURN x");
    assert!(err.contains("InvalidQuantifiedPath"), "got: {err}");
    assert!(err.contains("self-loop"), "got: {err}");
}

#[test]
fn rejects_qpp_in_pattern_form_exists_subquery() {
    let err = compile_err("MATCH (a) WHERE EXISTS { (a)((x)-[r]->(y))+(b) } RETURN a");
    assert!(err.contains("InvalidQuantifiedPath"), "got: {err}");
}

#[test]
fn rejects_qpp_in_pattern_form_count_subquery() {
    let err = compile_err("MATCH (a) WHERE COUNT { (a)((x)-[r]->(y))+(b) } > 0 RETURN a");
    assert!(err.contains("InvalidQuantifiedPath"), "got: {err}");
}

#[test]
fn full_query_exists_subquery_supports_qpp() {
    let (mut g, _) = seed_chain();
    // The full-query form of EXISTS goes through the planner, which supports QPP.
    let rows = run(
        "MATCH (a {id:0}) WHERE EXISTS { MATCH (a)((x)-[:R]->(y))+(b {id:3}) RETURN b } \
         RETURN a.id AS aid",
        &mut g,
    );
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].value("aid"), i(0));
}

// =================================================================================================
// Relationship-type filters
// =================================================================================================

#[test]
fn disjunctive_interior_relationship_types() {
    let mut g = MemGraph::new();
    let n: Vec<NodeId> = (0..4).map(|k| g.add_node(["N"], [("id", i(k))])).collect();
    g.add_rel("A", n[0], n[1], NO_PROPS);
    g.add_rel("B", n[1], n[2], NO_PROPS);
    g.add_rel("C", n[2], n[3], NO_PROPS); // a type outside the alternation
    // Interior `:A|B` walks the first two hops but not the C edge, so b ∈ {n1, n2}.
    let rows = run(
        "MATCH (a {id:0})((x)-[:A|B]->(y))+(b) RETURN b.id AS bid",
        &mut g,
    );
    assert_eq!(ints(&rows, "bid"), vec![1, 2]);
}

// =================================================================================================
// Multi-relationship interior (Neo4j 5.x GPM): the interior is a longer path repeated per iteration
// =================================================================================================

/// An alternating chain `0 -[R w:0]-> 1 -[S w:1]-> 2 -[R w:2]-> 3 -[S w:3]-> 4`. A two-relationship
/// interior `(x)-[:R]->(m)-[:S]->(y)` advances one `R` then one `S` per iteration: from `0`, one
/// iteration reaches `2`, two iterations reach `4`.
fn seed_rs_chain() -> MemGraph {
    let mut g = MemGraph::new();
    let n: Vec<NodeId> = (0..5).map(|k| g.add_node(["N"], [("id", i(k))])).collect();
    g.add_rel("R", n[0], n[1], [("w", i(0))]);
    g.add_rel("S", n[1], n[2], [("w", i(1))]);
    g.add_rel("R", n[2], n[3], [("w", i(2))]);
    g.add_rel("S", n[3], n[4], [("w", i(3))]);
    g
}

#[test]
fn multi_hop_plus_enumerates_iteration_endpoints() {
    let mut g = seed_rs_chain();
    // Each iteration is a full `R`→`S` interior. From `0`: one iteration → `2`, two iterations → `4`.
    let rows = run(
        "MATCH (a {id:0})((x)-[:R]->(m)-[:S]->(y))+(b) RETURN b.id AS bid",
        &mut g,
    );
    assert_eq!(ints(&rows, "bid"), vec![2, 4]);
}

#[test]
fn multi_hop_exact_and_range_counts() {
    let mut g = seed_rs_chain();
    let one = run(
        "MATCH (a {id:0})((x)-[:R]->(m)-[:S]->(y)){1}(b) RETURN b.id AS bid",
        &mut g,
    );
    assert_eq!(ints(&one, "bid"), vec![2]);
    let two = run(
        "MATCH (a {id:0})((x)-[:R]->(m)-[:S]->(y)){2}(b) RETURN b.id AS bid",
        &mut g,
    );
    assert_eq!(ints(&two, "bid"), vec![4]);
    let range = run(
        "MATCH (a {id:0})((x)-[:R]->(m)-[:S]->(y)){1,2}(b) RETURN b.id AS bid",
        &mut g,
    );
    assert_eq!(ints(&range, "bid"), vec![2, 4]);
}

#[test]
fn multi_hop_star_includes_the_zero_iteration_walk() {
    let mut g = seed_rs_chain();
    // `*` (0+): the zero-iteration walk binds the boundary to the anchor `0`, plus the positive
    // endpoints `2` and `4`.
    let rows = run(
        "MATCH (a {id:0})((x)-[:R]->(m)-[:S]->(y))*(b) RETURN b.id AS bid",
        &mut g,
    );
    assert_eq!(ints(&rows, "bid"), vec![0, 2, 4]);
}

#[test]
fn multi_hop_group_variables_aggregate_per_iteration() {
    let mut g = seed_rs_chain();
    // The two-iteration walk `0→1→2→3→4`. Every interior variable is a group list with **one element
    // per iteration** (not per hop): x=[0,2], m=[1,3], y=[2,4], and each relationship group has 2.
    let rows = run(
        "MATCH (a {id:0})((x)-[r1:R]->(m)-[r2:S]->(y))+(b) WHERE b.id = 4 \
         RETURN [n IN x | n.id] AS xs, [n IN m | n.id] AS ms, [n IN y | n.id] AS ys, \
                size(r1) AS r1c, size(r2) AS r2c",
        &mut g,
    );
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].value("xs"), Value::List(vec![i(0), i(2)]));
    assert_eq!(rows[0].value("ms"), Value::List(vec![i(1), i(3)]));
    assert_eq!(rows[0].value("ys"), Value::List(vec![i(2), i(4)]));
    assert_eq!(rows[0].value("r1c"), i(2));
    assert_eq!(rows[0].value("r2c"), i(2));
}

#[test]
fn multi_hop_boundary_nodes_stay_scalar() {
    let mut g = seed_rs_chain();
    let rows = run(
        "MATCH (a {id:0})((x)-[:R]->(m)-[:S]->(y))+(b) WHERE b.id = 4 \
         RETURN a.id AS aid, b.id AS bid",
        &mut g,
    );
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].value("aid"), i(0));
    assert_eq!(rows[0].value("bid"), i(4));
}

#[test]
fn multi_hop_inner_where_spans_both_hop_relationships() {
    let mut g = seed_rs_chain();
    // The inner `WHERE` references both interior relationships of the iteration. On the RS chain the
    // first iteration has `r1.w + r2.w = 0 + 1 = 1 < 5` (kept), the second `2 + 3 = 5` (pruned), so
    // only the single-iteration endpoint `2` survives.
    let rows = run(
        "MATCH (a {id:0})((x)-[r1:R]->(m)-[r2:S]->(y) WHERE r1.w + r2.w < 5)+(b) RETURN b.id AS bid",
        &mut g,
    );
    assert_eq!(ints(&rows, "bid"), vec![2]);
}

#[test]
fn multi_hop_extra_hop_node_label_constrains_each_iteration() {
    // 0 -[R]-> 1 -[S]-> 2(:VIP) -[R]-> 3 -[S]-> 4  (only node 2 is a :VIP)
    let mut g = MemGraph::new();
    let n: Vec<NodeId> = (0..5)
        .map(|k| {
            let labels: &[&str] = if k == 2 { &["N", "VIP"] } else { &["N"] };
            g.add_node(labels.iter().copied(), [("id", i(k))])
        })
        .collect();
    g.add_rel("R", n[0], n[1], NO_PROPS);
    g.add_rel("S", n[1], n[2], NO_PROPS);
    g.add_rel("R", n[2], n[3], NO_PROPS);
    g.add_rel("S", n[3], n[4], NO_PROPS);
    // Require the extra hop's END node `(y)` to be a :VIP. Iteration one ends at `2` (:VIP ✓); a
    // second iteration would end at `4` (not :VIP), so it is pruned — reachable b ∈ {2}.
    let rows = run(
        "MATCH (a {id:0})((x)-[:R]->(m)-[:S]->(y:VIP))+(b) RETURN b.id AS bid",
        &mut g,
    );
    assert_eq!(ints(&rows, "bid"), vec![2]);
}

#[test]
fn multi_hop_extra_hop_relationship_property_filter() {
    let mut g = seed_rs_chain();
    // Inline property map on the **second** interior hop: only `S` edges with `w = 1`. Iteration one
    // uses the S edge `1→2` (w=1 ✓); a second iteration would use `3→4` (w=3 ✗), so it is pruned.
    let rows = run(
        "MATCH (a {id:0})((x)-[:R]->(m)-[r2:S {w:1}]->(y))+(b) RETURN b.id AS bid",
        &mut g,
    );
    assert_eq!(ints(&rows, "bid"), vec![2]);
}

#[test]
fn multi_hop_mixed_direction_interior() {
    // 0 -[R]-> 1 <-[S]- 2, and 2 -[R]-> 3 <-[S]- 4. The interior `(x)-[:R]->(m)<-[:S]-(y)` walks one
    // outgoing R then one incoming S per iteration.
    let mut g = MemGraph::new();
    let n: Vec<NodeId> = (0..5).map(|k| g.add_node(["N"], [("id", i(k))])).collect();
    g.add_rel("R", n[0], n[1], NO_PROPS);
    g.add_rel("S", n[2], n[1], NO_PROPS); // incoming to 1 from 2
    g.add_rel("R", n[2], n[3], NO_PROPS);
    g.add_rel("S", n[4], n[3], NO_PROPS); // incoming to 3 from 4
    // From 0: iter1 `0-R->1<-S-2` (y=2); iter2 `2-R->3<-S-4` (y=4).
    let rows = run(
        "MATCH (a {id:0})((x)-[:R]->(m)<-[:S]-(y))+(b) RETURN b.id AS bid",
        &mut g,
    );
    assert_eq!(ints(&rows, "bid"), vec![2, 4]);
}

#[test]
fn multi_hop_trail_forbids_reusing_a_relationship_across_hops() {
    // A 2-cycle `0 -[R]-> 1 -[S]-> 0`. The interior `(x)-[:R]->(m)-[:S]->(y)` completes exactly one
    // iteration `0→1→0`; a second iteration would have to reuse the `R` edge `0→1` (already in the
    // trail), which trail semantics forbid — so exactly the one endpoint `0`.
    let mut g = MemGraph::new();
    let a = g.add_node(["N"], [("id", i(0))]);
    let b = g.add_node(["N"], [("id", i(1))]);
    g.add_rel("R", a, b, NO_PROPS);
    g.add_rel("S", b, a, NO_PROPS);
    let plus = run(
        "MATCH (a {id:0})((x)-[:R]->(m)-[:S]->(y))+(b) RETURN b.id AS bid",
        &mut g,
    );
    assert_eq!(ints(&plus, "bid"), vec![0]);
    // Two iterations are impossible without reusing an edge → no rows.
    let two = run(
        "MATCH (a {id:0})((x)-[:R]->(m)-[:S]->(y)){2}(b) RETURN count(*) AS c",
        &mut g,
    );
    assert_eq!(two[0].value("c"), i(0));
}

#[test]
fn multi_hop_into_binding_keeps_only_walks_reaching_the_bound_boundary() {
    let mut g = seed_rs_chain();
    // `b` is bound (id=4) before the QPP: only the two-iteration walk ending at `4` is kept.
    let rows = run(
        "MATCH (a {id:0}), (b {id:4}) MATCH (a)((x)-[:R]->(m)-[:S]->(y))+(b) RETURN size(y) AS yc",
        &mut g,
    );
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].value("yc"), i(2));
}

#[test]
fn multi_hop_composes_after_a_fixed_relationship() {
    let mut g = seed_rs_chain();
    // One fixed `R` hop from `0` to `1`, then a two-relationship QPP from `1` (starting with `S`).
    let rows = run(
        "MATCH (a {id:0})-[:R]->(m0)((x)-[:S]->(mid)-[:R]->(y))+(b) RETURN b.id AS bid",
        &mut g,
    );
    // From 1: iter1 `1-S->2-R->3` (y=3). A second iteration from 3 needs an S edge out of 3 (none), so
    // just `3`.
    assert_eq!(ints(&rows, "bid"), vec![3]);
}

#[test]
fn three_hop_interior_executes_and_binds_group_lists() {
    // 0 -[R]-> 1 -[S]-> 2 -[T]-> 3 -[R]-> 4 -[S]-> 5 -[T]-> 6
    let mut g = MemGraph::new();
    let n: Vec<NodeId> = (0..7).map(|k| g.add_node(["N"], [("id", i(k))])).collect();
    for (k, t) in (0..6).zip(["R", "S", "T", "R", "S", "T"]) {
        g.add_rel(t, n[k], n[k + 1], NO_PROPS);
    }
    // Each iteration is a full `R`→`S`→`T` interior. From 0: one iteration → 3, two → 6.
    let rows = run(
        "MATCH (a {id:0})((x)-[:R]->(m)-[:S]->(p)-[:T]->(y))+(b) RETURN b.id AS bid",
        &mut g,
    );
    assert_eq!(ints(&rows, "bid"), vec![3, 6]);
    // Group lists on the two-iteration walk: one element per iteration for every interior variable.
    let g2 = run(
        "MATCH (a {id:0})((x)-[r1:R]->(m)-[r2:S]->(p)-[r3:T]->(y))+(b) WHERE b.id = 6 \
         RETURN [z IN x | z.id] AS xs, [z IN m | z.id] AS ms, [z IN p | z.id] AS ps, \
                [z IN y | z.id] AS ys, size(r1) AS r1c, size(r2) AS r2c, size(r3) AS r3c",
        &mut g,
    );
    assert_eq!(g2.len(), 1);
    assert_eq!(g2[0].value("xs"), Value::List(vec![i(0), i(3)]));
    assert_eq!(g2[0].value("ms"), Value::List(vec![i(1), i(4)]));
    assert_eq!(g2[0].value("ps"), Value::List(vec![i(2), i(5)]));
    assert_eq!(g2[0].value("ys"), Value::List(vec![i(3), i(6)]));
    assert_eq!(g2[0].value("r1c"), i(2));
    assert_eq!(g2[0].value("r2c"), i(2));
    assert_eq!(g2[0].value("r3c"), i(2));
}

#[test]
fn multi_hop_rejects_sharing_an_interior_variable() {
    // Two interior elements sharing a variable (`m` as both the second and the third node) cannot be
    // represented by a single group binding — rejected with a clear error.
    let err = compile_err("MATCH (a)((x)-[r1:R]->(m)-[r2:S]->(m))+(b) RETURN a");
    assert!(err.contains("InvalidQuantifiedPath"), "got: {err}");
    assert!(err.contains("share the variable"), "got: {err}");
    // A relationship variable reused across hops is likewise rejected.
    let err2 = compile_err("MATCH (a)((x)-[r:R]->(m)-[r:S]->(y))+(b) RETURN a");
    assert!(err2.contains("InvalidQuantifiedPath"), "got: {err2}");
}

#[test]
fn multi_hop_rejected_in_create_and_pattern_form_exists() {
    let create = compile_err("CREATE (a)((x)-[:R]->(m)-[:S]->(y))+(b)");
    assert!(create.contains("InvalidQuantifiedPath"), "got: {create}");
    let exists =
        compile_err("MATCH (a) WHERE EXISTS { (a)((x)-[:R]->(m)-[:S]->(y))+(b) } RETURN a");
    assert!(exists.contains("InvalidQuantifiedPath"), "got: {exists}");
}
