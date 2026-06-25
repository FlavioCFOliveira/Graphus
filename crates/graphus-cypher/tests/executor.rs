//! End-to-end executor tests (`04-technical-design.md` §7.4, §7.7).
//!
//! Each test runs the **full pipeline** — parse a query string, semantic-analyse, lower to a logical
//! plan, plan physically, bind parameters, then execute over a seeded
//! [`MemGraph`](graphus_cypher::graph_access::MemGraph) — and asserts the exact result rows. This is
//! the capstone proof that `parse → semantics → plan → execute` runs real Cypher end to end and
//! returns correct results.

use graphus_core::Value;
use graphus_cypher::EvalError;
use graphus_cypher::binding::{Parameters, bind_parameters};
use graphus_cypher::catalog::IndexCatalog;
use graphus_cypher::executor::{CancellationToken, ExecError, Executor, execute};
use graphus_cypher::graph_access::{GraphAccess, MemGraph, NodeId};
use graphus_cypher::lexer::tokenize;
use graphus_cypher::lower::lower;
use graphus_cypher::parser::parse_tokens;
use graphus_cypher::physical::plan_physical;
use graphus_cypher::runtime::{Row, RowValue};
use graphus_cypher::semantics::analyze;

// =================================================================================================
// Harness
// =================================================================================================

/// Compiles `src` against `catalog` and `params`, executes over `graph`, and returns all rows.
fn run_params(
    src: &str,
    graph: &mut MemGraph,
    catalog: &IndexCatalog,
    params: &Parameters,
) -> Vec<Row> {
    let toks = tokenize(src).expect("lex");
    let ast = parse_tokens(&toks, src).expect("parse");
    let validated = analyze(&ast).expect("analyze");
    let plan = plan_physical(&lower(&validated), catalog);
    let mut all = params.clone();
    // Auto-parameters (lifted literals) are not used here — we plan from the raw AST, not the
    // normalised cache form — so `params` is the user-supplied set only.
    let bound = bind_parameters(&plan, &all).expect("bind");
    let _ = &mut all;
    execute(&plan, &bound, graph)
        .expect("open cursor")
        .collect_all()
        .expect("rows")
}

/// Compiles and runs `src` (no params, empty catalog) and returns all rows.
fn run(src: &str, graph: &mut MemGraph) -> Vec<Row> {
    run_params(src, graph, &IndexCatalog::empty(), &Parameters::new())
}

fn run_cat(src: &str, graph: &mut MemGraph, catalog: &IndexCatalog) -> Vec<Row> {
    run_params(src, graph, catalog, &Parameters::new())
}

fn s(v: &str) -> Value {
    Value::String(v.to_owned())
}

fn i(n: i64) -> Value {
    Value::Integer(n)
}

/// A typed empty property list, so `add_node`'s key-type generic can be inferred at the empty case.
const NO_PROPS: [(&str, Value); 0] = [];

/// Extracts a single named column from rows as a `Vec<Value>` (property-valued columns).
fn col(rows: &[Row], name: &str) -> Vec<Value> {
    rows.iter().map(|r| r.value(name)).collect()
}

/// Seeds a small social graph: three Person nodes, a Company, and KNOWS / WORKS_AT relationships.
fn seed_social() -> (MemGraph, NodeId, NodeId, NodeId, NodeId) {
    let mut g = MemGraph::new();
    let ada = g.add_node(["Person"], [("name", s("Ada")), ("age", i(36))]);
    let bob = g.add_node(["Person"], [("name", s("Bob")), ("age", i(28))]);
    let cara = g.add_node(["Person"], [("name", s("Cara")), ("age", i(36))]);
    let acme = g.add_node(["Company"], [("name", s("Acme"))]);
    g.add_rel("KNOWS", ada, bob, [("since", i(2010))]);
    g.add_rel("KNOWS", bob, cara, [("since", i(2015))]);
    g.add_rel("WORKS_AT", ada, acme, [] as [(&str, Value); 0]);
    (g, ada, bob, cara, acme)
}

// =================================================================================================
// Reads: MATCH / RETURN / property access
// =================================================================================================

#[test]
fn match_all_nodes_returns_every_node() {
    let (mut g, ..) = seed_social();
    let rows = run("MATCH (n) RETURN n", &mut g);
    assert_eq!(rows.len(), 4, "one row per node");
    assert!(
        rows.iter().all(|r| r.get("n").unwrap().as_node().is_some()),
        "every row binds a node"
    );
}

#[test]
fn match_labelled_returns_property() {
    let (mut g, ..) = seed_social();
    let rows = run("MATCH (n:Person) RETURN n.name AS name", &mut g);
    let mut names = col(&rows, "name");
    names.sort_by(|a, b| format!("{a:?}").cmp(&format!("{b:?}")));
    assert_eq!(names, vec![s("Ada"), s("Bob"), s("Cara")]);
    assert_eq!(rows[0].columns(), &["name".to_owned()]);
}

#[test]
fn missing_property_is_null() {
    let mut g = MemGraph::new();
    g.add_node(["Person"], [("name", s("Ada"))]);
    let rows = run("MATCH (n:Person) RETURN n.nonexistent AS x", &mut g);
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].value("x"), Value::Null);
}

#[test]
fn return_literal_expression_without_match() {
    let mut g = MemGraph::new();
    let rows = run("RETURN 1 + 2 AS sum, 'hi' AS greeting", &mut g);
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].value("sum"), i(3));
    assert_eq!(rows[0].value("greeting"), s("hi"));
}

// =================================================================================================
// Traversal: ExpandAll / ExpandInto / OPTIONAL MATCH
// =================================================================================================

#[test]
fn traversal_yields_correct_pairs() {
    let (mut g, ..) = seed_social();
    let rows = run(
        "MATCH (a:Person)-[:KNOWS]->(b:Person) RETURN a.name AS from, b.name AS to",
        &mut g,
    );
    let mut pairs: Vec<(Value, Value)> = rows
        .iter()
        .map(|r| (r.value("from"), r.value("to")))
        .collect();
    pairs.sort_by(|a, b| format!("{a:?}").cmp(&format!("{b:?}")));
    assert_eq!(pairs, vec![(s("Ada"), s("Bob")), (s("Bob"), s("Cara"))]);
}

#[test]
fn traversal_with_relationship_property() {
    let (mut g, ..) = seed_social();
    let rows = run(
        "MATCH (a:Person)-[r:KNOWS]->(b:Person) WHERE r.since > 2012 RETURN a.name AS from, r.since AS since",
        &mut g,
    );
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].value("from"), s("Bob"));
    assert_eq!(rows[0].value("since"), i(2015));
}

#[test]
fn expand_into_checks_known_pair() {
    let (mut g, ada, bob, ..) = seed_social();
    // Bind both endpoints, then check the connection between the specific Ada→Bob pair.
    let _ = (ada, bob);
    let rows = run(
        "MATCH (a:Person)-[:KNOWS]->(b:Person)-[:KNOWS]->(c:Person) RETURN a.name AS a, c.name AS c",
        &mut g,
    );
    // Ada -KNOWS-> Bob -KNOWS-> Cara is the only 2-hop KNOWS chain.
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].value("a"), s("Ada"));
    assert_eq!(rows[0].value("c"), s("Cara"));
}

#[test]
fn optional_match_yields_null_when_no_match() {
    let mut g = MemGraph::new();
    let _lonely = g.add_node(["Person"], [("name", s("Zoe"))]);
    // Zoe has no KNOWS edge → OPTIONAL MATCH binds the optional vars to null but keeps the row.
    let rows = run(
        "MATCH (a:Person) OPTIONAL MATCH (a)-[:KNOWS]->(b) RETURN a.name AS a, b AS b",
        &mut g,
    );
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].value("a"), s("Zoe"));
    assert!(rows[0].get("b").unwrap().is_null(), "no match → null b");
}

#[test]
fn optional_match_yields_matches_when_present() {
    let (mut g, ..) = seed_social();
    let rows = run(
        "MATCH (a:Person {name: 'Ada'}) OPTIONAL MATCH (a)-[:KNOWS]->(b) RETURN b.name AS b",
        &mut g,
    );
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].value("b"), s("Bob"));
}

// =================================================================================================
// WHERE with three-valued logic
// =================================================================================================

#[test]
fn where_drops_null_predicate_rows() {
    let mut g = MemGraph::new();
    g.add_node(["P"], [("age", i(30))]);
    g.add_node(["P"], NO_PROPS); // no age → n.age = 30 is NULL → row dropped (3VL)
    let rows = run("MATCH (n:P) WHERE n.age = 30 RETURN n.age AS age", &mut g);
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].value("age"), i(30));
}

#[test]
fn where_in_list_and_string_predicates() {
    let (mut g, ..) = seed_social();
    let rows = run(
        "MATCH (n:Person) WHERE n.name IN ['Ada', 'Cara'] RETURN n.name AS name",
        &mut g,
    );
    let mut names = col(&rows, "name");
    names.sort_by(|a, b| format!("{a:?}").cmp(&format!("{b:?}")));
    assert_eq!(names, vec![s("Ada"), s("Cara")]);

    let rows2 = run(
        "MATCH (n:Person) WHERE n.name STARTS WITH 'A' RETURN n.name AS name",
        &mut g,
    );
    assert_eq!(col(&rows2, "name"), vec![s("Ada")]);
}

#[test]
fn where_comparison_and_and_or() {
    let (mut g, ..) = seed_social();
    let rows = run(
        "MATCH (n:Person) WHERE n.age >= 30 AND n.age <= 40 RETURN n.name AS name",
        &mut g,
    );
    let mut names = col(&rows, "name");
    names.sort_by(|a, b| format!("{a:?}").cmp(&format!("{b:?}")));
    assert_eq!(names, vec![s("Ada"), s("Cara")]);
}

// =================================================================================================
// DISTINCT, ORDER BY, SKIP/LIMIT
// =================================================================================================

#[test]
fn return_distinct_dedups_by_equivalence() {
    let (mut g, ..) = seed_social();
    // Two people share age 36; DISTINCT collapses them.
    let rows = run("MATCH (n:Person) RETURN DISTINCT n.age AS age", &mut g);
    let mut ages = col(&rows, "age");
    ages.sort_by(|a, b| format!("{a:?}").cmp(&format!("{b:?}")));
    assert_eq!(ages, vec![i(28), i(36)]);
}

#[test]
fn order_by_ascending_and_descending() {
    let (mut g, ..) = seed_social();
    let asc = run(
        "MATCH (n:Person) RETURN n.age AS age ORDER BY age ASC",
        &mut g,
    );
    assert_eq!(col(&asc, "age"), vec![i(28), i(36), i(36)]);
    let desc = run(
        "MATCH (n:Person) RETURN n.age AS age ORDER BY age DESC",
        &mut g,
    );
    assert_eq!(col(&desc, "age"), vec![i(36), i(36), i(28)]);
}

#[test]
fn order_by_places_null_last_ascending() {
    let mut g = MemGraph::new();
    g.add_node(["P"], [("v", i(1))]);
    g.add_node(["P"], NO_PROPS); // null v
    g.add_node(["P"], [("v", i(2))]);
    let rows = run("MATCH (n:P) RETURN n.v AS v ORDER BY v ASC", &mut g);
    // Ascending: NULL is the largest, so it sorts last (`04 §7.6`).
    assert_eq!(col(&rows, "v"), vec![i(1), i(2), Value::Null]);
}

#[test]
fn skip_and_limit() {
    let mut g = MemGraph::new();
    for n in 0..5 {
        g.add_node(["P"], [("v", i(n))]);
    }
    let rows = run(
        "MATCH (n:P) RETURN n.v AS v ORDER BY v SKIP 1 LIMIT 2",
        &mut g,
    );
    assert_eq!(col(&rows, "v"), vec![i(1), i(2)]);
}

#[test]
fn topn_fuses_order_by_limit() {
    let mut g = MemGraph::new();
    for n in [5, 1, 4, 2, 3] {
        g.add_node(["P"], [("v", i(n))]);
    }
    let rows = run("MATCH (n:P) RETURN n.v AS v ORDER BY v ASC LIMIT 3", &mut g);
    assert_eq!(col(&rows, "v"), vec![i(1), i(2), i(3)]);
}

// =================================================================================================
// Aggregation
// =================================================================================================

#[test]
fn count_star_and_count_property() {
    let (mut g, ..) = seed_social();
    let rows = run("MATCH (n:Person) RETURN count(*) AS c", &mut g);
    assert_eq!(rows[0].value("c"), i(3));

    let mut g2 = MemGraph::new();
    g2.add_node(["P"], [("x", i(1))]);
    g2.add_node(["P"], NO_PROPS); // null x → count(n.x) ignores it
    let rows2 = run("MATCH (n:P) RETURN count(n.x) AS c", &mut g2);
    assert_eq!(rows2[0].value("c"), i(1));
}

/// Regression: `count(<node/relationship variable>)` must count the bound entities, not 0.
///
/// A bound node/relationship is a non-null value; counting it is the common `MATCH (n) RETURN
/// count(n)` idiom. The aggregation previously evaluated its argument with the *value*-collapsing
/// path, which turns an entity reference into `Value::Null`, so `count(n)` wrongly skipped every row
/// and returned 0 (while `count(*)` worked). This pins the entity-aware behaviour.
#[test]
fn count_of_entity_variable_counts_bound_entities() {
    let (mut g, ..) = seed_social();
    // 3 Person + 1 Company = 4 nodes.
    let rows = run("MATCH (n) RETURN count(n) AS c", &mut g);
    assert_eq!(rows[0].value("c"), i(4), "count(node) counts every node");

    let labelled = run("MATCH (n:Person) RETURN count(n) AS c", &mut g);
    assert_eq!(
        labelled[0].value("c"),
        i(3),
        "count(node) honours the label scan"
    );

    // 3 relationships (2 KNOWS + 1 WORKS_AT). `count(r)` counts the bound relationships.
    let rels = run("MATCH ()-[r]->() RETURN count(r) AS c", &mut g);
    assert_eq!(
        rels[0].value("c"),
        i(3),
        "count(relationship) counts every rel"
    );

    // DISTINCT must dedupe entities by identity: the same node reached twice counts once.
    let mut g2 = MemGraph::new();
    let a = g2.add_node(["N"], NO_PROPS);
    let b = g2.add_node(["N"], NO_PROPS);
    g2.add_rel("E", a, b, NO_PROPS);
    g2.add_rel("E", b, a, NO_PROPS);
    // `a` is the start of one edge and the end of another, so an undirected-ish double count would
    // see it twice; DISTINCT collapses to the 2 distinct nodes.
    let distinct = run("MATCH (x)-[]->() RETURN count(DISTINCT x) AS c", &mut g2);
    assert_eq!(
        distinct[0].value("c"),
        i(2),
        "count(DISTINCT node) dedupes by identity"
    );
}

#[test]
fn sum_avg_min_max_collect() {
    let (mut g, ..) = seed_social();
    let rows = run(
        "MATCH (n:Person) RETURN sum(n.age) AS s, avg(n.age) AS a, min(n.age) AS lo, max(n.age) AS hi",
        &mut g,
    );
    assert_eq!(rows[0].value("s"), i(36 + 28 + 36));
    assert_eq!(
        rows[0].value("a"),
        Value::Float((36 + 28 + 36) as f64 / 3.0)
    );
    assert_eq!(rows[0].value("lo"), i(28));
    assert_eq!(rows[0].value("hi"), i(36));

    let collected = run("MATCH (n:Person) RETURN collect(n.age) AS ages", &mut g);
    let Value::List(ages) = collected[0].value("ages") else {
        panic!("collect should produce a list");
    };
    assert_eq!(ages.len(), 3);
}

#[test]
fn aggregation_with_grouping_key() {
    let (mut g, ..) = seed_social();
    // Group by age: age 36 has 2 people, age 28 has 1.
    let rows = run(
        "MATCH (n:Person) RETURN n.age AS age, count(*) AS c",
        &mut g,
    );
    let mut pairs: Vec<(Value, Value)> = rows
        .iter()
        .map(|r| (r.value("age"), r.value("c")))
        .collect();
    pairs.sort_by(|a, b| format!("{a:?}").cmp(&format!("{b:?}")));
    assert_eq!(pairs, vec![(i(28), i(1)), (i(36), i(2))]);
}

#[test]
fn count_distinct() {
    let (mut g, ..) = seed_social();
    let rows = run("MATCH (n:Person) RETURN count(DISTINCT n.age) AS c", &mut g);
    assert_eq!(rows[0].value("c"), i(2));
}

// =================================================================================================
// Path & aggregation functions: collect(), nodes(), relationships(), named paths (#63)
// =================================================================================================

/// `collect(n)` over an entity keeps its elements **structural** (a [`RowValue::List`] of nodes),
/// not a property list of nulls.
#[test]
fn collect_preserves_node_entities() {
    let (mut g, ada, bob, cara, _) = seed_social();
    let rows = run("MATCH (n:Person) RETURN collect(n) AS ns", &mut g);
    let Some(RowValue::List(items)) = rows[0].get("ns") else {
        panic!("collect(n) should be a structural list of nodes");
    };
    let mut ids: Vec<NodeId> = items
        .iter()
        .map(|it| it.as_node().expect("each element is a node"))
        .collect();
    ids.sort();
    let mut want = [ada, bob, cara];
    want.sort();
    assert_eq!(ids, want);
}

/// `nodes(p)` / `relationships(p)` / `length(p)` over a named path bound by `MATCH p = …`.
#[test]
fn nodes_relationships_length_of_named_path() {
    let (mut g, ada, bob, ..) = seed_social();
    let rows = run(
        "MATCH p = (a:Person {name:'Ada'})-[:KNOWS]->(b:Person) \
         RETURN nodes(p) AS ns, relationships(p) AS rs, length(p) AS len",
        &mut g,
    );
    assert_eq!(rows.len(), 1);

    let Some(RowValue::List(ns)) = rows[0].get("ns") else {
        panic!("nodes(p) should be a structural list");
    };
    let node_ids: Vec<NodeId> = ns.iter().map(|n| n.as_node().expect("node")).collect();
    assert_eq!(node_ids, vec![ada, bob]);

    let Some(RowValue::List(rs)) = rows[0].get("rs") else {
        panic!("relationships(p) should be a structural list");
    };
    assert_eq!(rs.len(), 1);
    assert!(rs[0].as_rel().is_some());

    assert_eq!(rows[0].value("len"), i(1));
}

/// A named path binds the structural [`RowValue::Path`] value itself: start node, one forward hop.
#[test]
fn named_path_binds_path_value() {
    let (mut g, ada, bob, ..) = seed_social();
    let rows = run(
        "MATCH p = (a:Person {name:'Ada'})-[:KNOWS]->(b:Person) RETURN p",
        &mut g,
    );
    assert_eq!(rows.len(), 1);
    let path = rows[0]
        .get("p")
        .and_then(RowValue::as_path)
        .expect("p is a path");
    assert_eq!(path.start, ada);
    assert_eq!(path.len(), 1);
    assert!(path.steps[0].forward, "Ada-[:KNOWS]->Bob is a forward hop");
    assert_eq!(path.steps[0].node, bob);
}

/// A named path bound **inside a pattern comprehension** is usable in its projection (`length(p)`).
#[test]
fn named_path_in_pattern_comprehension() {
    let (mut g, ..) = seed_social();
    let rows = run(
        "MATCH (a:Person {name:'Ada'}) RETURN [p = (a)-[:KNOWS]->(b) | length(p)] AS lens",
        &mut g,
    );
    assert_eq!(rows[0].value("lens"), Value::List(vec![i(1)]));
}

/// A variable-length named path enumerates trails; `length(p)` reports each hop count, and the
/// path's relationship list grows with depth (Ada→Bob, Ada→Bob→Cara).
#[test]
fn variable_length_named_path_lengths() {
    let (mut g, ..) = seed_social();
    let rows = run(
        "MATCH p = (a:Person {name:'Ada'})-[:KNOWS*1..2]->(b:Person) \
         RETURN length(p) AS len ORDER BY len",
        &mut g,
    );
    assert_eq!(col(&rows, "len"), vec![i(1), i(2)]);
}

// =================================================================================================
// UNWIND, UNION / UNION ALL
// =================================================================================================

#[test]
fn unwind_expands_list_to_rows() {
    let mut g = MemGraph::new();
    let rows = run("UNWIND [1, 2, 3] AS x RETURN x", &mut g);
    assert_eq!(col(&rows, "x"), vec![i(1), i(2), i(3)]);
}

#[test]
fn unwind_correlated_with_match() {
    let mut g = MemGraph::new();
    g.add_node(["P"], [("name", s("A"))]);
    g.add_node(["P"], [("name", s("B"))]);
    // One row per (person, element) pair.
    let rows = run(
        "MATCH (n:P) UNWIND [1, 2] AS x RETURN n.name AS name, x",
        &mut g,
    );
    assert_eq!(rows.len(), 4);
}

#[test]
fn union_all_keeps_duplicates_union_dedups() {
    let mut g = MemGraph::new();
    let all = run("RETURN 1 AS x UNION ALL RETURN 1 AS x", &mut g);
    assert_eq!(col(&all, "x"), vec![i(1), i(1)]);

    let dedup = run("RETURN 1 AS x UNION RETURN 1 AS x", &mut g);
    assert_eq!(col(&dedup, "x"), vec![i(1)]);
}

// =================================================================================================
// Writes: CREATE / MERGE / SET / DELETE / REMOVE
// =================================================================================================

#[test]
fn create_node_and_return_it() {
    let mut g = MemGraph::new();
    let rows = run(
        "CREATE (n:Person {name: 'Eve', age: 22}) RETURN n.name AS name, n.age AS age",
        &mut g,
    );
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].value("name"), s("Eve"));
    assert_eq!(rows[0].value("age"), i(22));
    assert_eq!(g.node_count(), 1, "the node was actually created");
}

#[test]
fn create_relationship_between_matched_nodes() {
    let mut g = MemGraph::new();
    g.add_node(["P"], [("name", s("A"))]);
    g.add_node(["P"], [("name", s("B"))]);
    let rows = run(
        "MATCH (a:P {name: 'A'}), (b:P {name: 'B'}) CREATE (a)-[r:LINK {w: 5}]->(b) RETURN r.w AS w",
        &mut g,
    );
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].value("w"), i(5));
    assert_eq!(g.rel_count(), 1);
}

#[test]
fn merge_creates_when_absent_then_matches() {
    let mut g = MemGraph::new();
    // First MERGE creates.
    let r1 = run(
        "MERGE (n:City {name: 'Lisbon'}) RETURN n.name AS name",
        &mut g,
    );
    assert_eq!(r1[0].value("name"), s("Lisbon"));
    assert_eq!(g.node_count(), 1);
    // Second MERGE on the same key matches the existing node (no new node).
    let r2 = run(
        "MERGE (n:City {name: 'Lisbon'}) RETURN n.name AS name",
        &mut g,
    );
    assert_eq!(r2[0].value("name"), s("Lisbon"));
    assert_eq!(g.node_count(), 1, "MERGE must not create a duplicate");
}

#[test]
fn merge_on_create_and_on_match_actions() {
    let mut g = MemGraph::new();
    // First time: ON CREATE fires.
    run(
        "MERGE (n:City {name: 'Porto'}) ON CREATE SET n.created = true ON MATCH SET n.seen = true RETURN n",
        &mut g,
    );
    let after_create = run("MATCH (n:City) RETURN n.created AS c, n.seen AS s", &mut g);
    assert_eq!(after_create[0].value("c"), Value::Boolean(true));
    assert_eq!(after_create[0].value("s"), Value::Null);
    // Second time: ON MATCH fires.
    run(
        "MERGE (n:City {name: 'Porto'}) ON CREATE SET n.created = true ON MATCH SET n.seen = true RETURN n",
        &mut g,
    );
    let after_match = run("MATCH (n:City) RETURN n.seen AS s", &mut g);
    assert_eq!(after_match[0].value("s"), Value::Boolean(true));
    assert_eq!(g.node_count(), 1);
}

#[test]
fn set_property_updates_graph() {
    let mut g = MemGraph::new();
    g.add_node(["P"], [("name", s("A")), ("age", i(20))]);
    let rows = run("MATCH (n:P) SET n.age = 21 RETURN n.age AS age", &mut g);
    assert_eq!(rows[0].value("age"), i(21));
    // Re-read from the graph confirms persistence within the transaction.
    let reread = run("MATCH (n:P) RETURN n.age AS age", &mut g);
    assert_eq!(reread[0].value("age"), i(21));
}

#[test]
fn set_labels_and_remove_them() {
    let mut g = MemGraph::new();
    let a = g.add_node(["P"], NO_PROPS);
    run("MATCH (n:P) SET n:Admin RETURN n", &mut g);
    assert!(g.node_labels(a).unwrap().iter().any(|l| l == "Admin"));
    run("MATCH (n:Admin) REMOVE n:Admin RETURN n", &mut g);
    assert!(!g.node_labels(a).unwrap().iter().any(|l| l == "Admin"));
}

#[test]
fn remove_property() {
    let mut g = MemGraph::new();
    let a = g.add_node(["P"], [("temp", i(9))]);
    run("MATCH (n:P) REMOVE n.temp RETURN n", &mut g);
    assert_eq!(g.node_property(a, "temp"), None);
}

/// `SET n.p = null` removes the property (openCypher `Set1` semantics, via `set_node_property`'s
/// null-removes contract). The property must be gone afterwards.
#[test]
fn set_property_to_null_removes_it() {
    let mut g = MemGraph::new();
    let a = g.add_node(["P"], [("age", i(20))]);
    run("MATCH (n:P) SET n.age = null RETURN n", &mut g);
    assert_eq!(g.node_property(a, "age"), None);
}

/// `SET n = {map}` with a null value in the map drops that key while applying the rest
/// (`clauses/set/Set4` [3] — null values in a property map are removed).
#[test]
fn set_overriding_map_drops_null_valued_keys() {
    let mut g = MemGraph::new();
    let a = g.add_node(["X"], [("name", s("A")), ("name2", s("B"))]);
    run(
        "MATCH (n:X) SET n = {name: 'B', name2: null, baz: 'C'} RETURN n",
        &mut g,
    );
    assert_eq!(g.node_property(a, "name"), Some(s("B")));
    assert_eq!(g.node_property(a, "name2"), None);
    assert_eq!(g.node_property(a, "baz"), Some(s("C")));
}

/// `SET n += {map}` with an explicit null value removes that key while retaining the rest
/// (`clauses/set/Set5` [4] — explicit null values in a map remove old values).
#[test]
fn set_appending_map_null_value_removes_key() {
    let mut g = MemGraph::new();
    let a = g.add_node(["X"], [("name", s("A")), ("name2", s("B"))]);
    run("MATCH (n:X) SET n += {name: null} RETURN n", &mut g);
    assert_eq!(g.node_property(a, "name"), None);
    assert_eq!(g.node_property(a, "name2"), Some(s("B")));
}

/// `REMOVE n.p` on a node that lacks `p` is a silent no-op, not an error
/// (`clauses/remove/Remove1` [7] — remove a missing node property).
#[test]
fn remove_missing_property_is_noop() {
    let mut g = MemGraph::new();
    let a = g.add_node(["P"], [("keep", i(1))]);
    let rows = run("MATCH (n:P) REMOVE n.absent RETURN n", &mut g);
    assert_eq!(rows.len(), 1);
    assert_eq!(g.node_property(a, "keep"), Some(i(1)));
}

/// `SET`/`REMOVE` whose target is a null entity (an `OPTIONAL MATCH` that found nothing) is a silent
/// no-op: the driving row survives with the target still null, and no entity error is raised
/// (`clauses/set/Set1` [8], `Set4` [5], `Set5` [1]; `clauses/remove/Remove1` [5], `Remove2` [5]).
#[test]
fn set_remove_on_null_target_is_noop() {
    for query in [
        "OPTIONAL MATCH (a:DoesNotExist) SET a.num = 42 RETURN a",
        "OPTIONAL MATCH (a:DoesNotExist) SET a = {num: 42} RETURN a",
        "OPTIONAL MATCH (a:DoesNotExist) SET a += {num: 42} RETURN a",
        "OPTIONAL MATCH (a:DoesNotExist) SET a:L RETURN a",
        "OPTIONAL MATCH (a:DoesNotExist) REMOVE a.num RETURN a",
        "OPTIONAL MATCH (a:DoesNotExist) REMOVE a:L RETURN a",
    ] {
        let mut g = MemGraph::new();
        let rows = run(query, &mut g);
        assert_eq!(
            rows.len(),
            1,
            "query should keep the null-filled row: {query}"
        );
        assert_eq!(
            rows[0].value("a"),
            Value::Null,
            "target must stay null: {query}"
        );
        assert_eq!(g.node_count(), 0, "no entity may be created: {query}");
    }
}

#[test]
fn delete_node_without_relationships() {
    let mut g = MemGraph::new();
    g.add_node(["P"], [("name", s("A"))]);
    run("MATCH (n:P) DELETE n", &mut g);
    assert_eq!(g.node_count(), 0);
}

#[test]
fn detach_delete_removes_relationships_too() {
    let (mut g, ..) = seed_social();
    let before = g.rel_count();
    assert!(before > 0);
    // DETACH DELETE Ada (who has KNOWS + WORKS_AT edges).
    run("MATCH (n:Person {name: 'Ada'}) DETACH DELETE n", &mut g);
    // Ada and her two incident edges are gone.
    assert_eq!(g.scan_nodes_by_label("Person").len(), 2);
    assert_eq!(g.rel_count(), before - 2);
}

#[test]
fn delete_connected_node_without_detach_is_runtime_error() {
    let (mut g, ..) = seed_social();
    let src = "MATCH (n:Person {name: 'Ada'}) DELETE n";
    let toks = tokenize(src).unwrap();
    let ast = parse_tokens(&toks, src).unwrap();
    let plan = plan_physical(&lower(&analyze(&ast).unwrap()), &IndexCatalog::empty());
    let bound = bind_parameters(&plan, &Parameters::new()).unwrap();
    let mut cursor = execute(&plan, &bound, &mut g).unwrap();
    let err = cursor.collect_all().unwrap_err();
    assert_eq!(err, ExecError::DeleteConnectedNode);
}

// =================================================================================================
// Eager writes under LIMIT (regression for rmp #52): openCypher write clauses are eager — LIMIT
// bounds the returned rows, never the side effects.
// =================================================================================================

#[test]
fn create_under_limit_zero_still_creates_the_node() {
    let mut g = MemGraph::new();
    let rows = run("CREATE (n) RETURN n LIMIT 0", &mut g);
    assert_eq!(rows.len(), 0, "LIMIT 0 returns no rows");
    assert_eq!(g.node_count(), 1, "the CREATE side effect must still run");
}

#[test]
fn create_per_row_under_limit_one_runs_every_write() {
    let mut g = MemGraph::new();
    let rows = run(
        "UNWIND [1, 2, 3] AS x CREATE (n:T {v: x}) RETURN x LIMIT 1",
        &mut g,
    );
    assert_eq!(rows.len(), 1, "LIMIT 1 returns one row");
    assert_eq!(g.node_count(), 3, "CREATE must run once per input row");
}

#[test]
fn merge_under_limit_zero_still_creates() {
    let mut g = MemGraph::new();
    let rows = run("MERGE (n:City {name: 'Faro'}) RETURN n LIMIT 0", &mut g);
    assert_eq!(rows.len(), 0);
    assert_eq!(
        g.node_count(),
        1,
        "the MERGE-create side effect must still run"
    );
}

#[test]
fn set_under_limit_zero_still_applies() {
    let mut g = MemGraph::new();
    let a = g.add_node(["P"], [("age", i(20))]);
    let b = g.add_node(["P"], [("age", i(30))]);
    let rows = run("MATCH (n:P) SET n.age = 99 RETURN n LIMIT 0", &mut g);
    assert_eq!(rows.len(), 0);
    assert_eq!(g.node_property(a, "age"), Some(i(99)));
    assert_eq!(
        g.node_property(b, "age"),
        Some(i(99)),
        "SET must run for every matched row"
    );
}

#[test]
fn delete_under_limit_zero_still_deletes() {
    let mut g = MemGraph::new();
    g.add_node(["P"], NO_PROPS);
    g.add_node(["P"], NO_PROPS);
    let rows = run("MATCH (n:P) DELETE n RETURN n LIMIT 0", &mut g);
    assert_eq!(rows.len(), 0);
    assert_eq!(g.node_count(), 0, "DELETE must run for every matched row");
}

#[test]
fn create_under_order_by_limit_runs_every_write() {
    // ORDER BY + LIMIT fuses into TopN, which drains its input; pin that writes still all run.
    let mut g = MemGraph::new();
    let rows = run(
        "UNWIND [3, 1, 2] AS x CREATE (n:T {v: x}) RETURN x ORDER BY x LIMIT 1",
        &mut g,
    );
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].value("x"), i(1));
    assert_eq!(
        g.node_count(),
        3,
        "CREATE must run once per input row under TopN"
    );
}

#[test]
fn create_under_skip_past_end_still_creates() {
    let mut g = MemGraph::new();
    let rows = run("CREATE (n) RETURN n SKIP 1", &mut g);
    assert_eq!(rows.len(), 0);
    assert_eq!(
        g.node_count(),
        1,
        "SKIP must not suppress the CREATE side effect"
    );
}

// =================================================================================================
// Quantifiers, comprehensions and existential subqueries (rmp #54)
// =================================================================================================

#[test]
fn quantifiers_follow_kleene_three_valued_logic() {
    let mut g = MemGraph::new();
    // Empty list: all/none are vacuously true, any is false, single is false.
    let rows = run(
        "RETURN all(x IN [] WHERE x > 0) AS a, any(x IN [] WHERE x > 0) AS b, \
         none(x IN [] WHERE x > 0) AS c, single(x IN [] WHERE x > 0) AS d",
        &mut g,
    );
    assert_eq!(rows[0].value("a"), Value::Boolean(true));
    assert_eq!(rows[0].value("b"), Value::Boolean(false));
    assert_eq!(rows[0].value("c"), Value::Boolean(true));
    assert_eq!(rows[0].value("d"), Value::Boolean(false));

    // Definite short-circuits beat nulls; otherwise a null leaves the result unknown.
    let rows = run(
        "RETURN any(x IN [1, null, 3] WHERE x = 3) AS hit, \
         none(x IN [2, null] WHERE x = 2) AS miss, \
         all(x IN [1, null] WHERE x > 0) AS unknown, \
         single(x IN [3, null] WHERE x = 3) AS maybe",
        &mut g,
    );
    assert_eq!(
        rows[0].value("hit"),
        Value::Boolean(true),
        "a true decides any()"
    );
    assert_eq!(
        rows[0].value("miss"),
        Value::Boolean(false),
        "a true decides none()"
    );
    assert_eq!(
        rows[0].value("unknown"),
        Value::Null,
        "a null leaves all() unknown"
    );
    assert_eq!(
        rows[0].value("maybe"),
        Value::Null,
        "a null could be a second match"
    );

    // single: exactly one definite match.
    let rows = run(
        "RETURN single(x IN [1, 2, 3] WHERE x = 2) AS one, \
         single(x IN [2, 2] WHERE x = 2) AS two",
        &mut g,
    );
    assert_eq!(rows[0].value("one"), Value::Boolean(true));
    assert_eq!(rows[0].value("two"), Value::Boolean(false));
}

#[test]
fn list_comprehension_filters_and_projects() {
    let mut g = MemGraph::new();
    let rows = run(
        "RETURN [x IN [1, 2, 3, 4] WHERE x > 1 | x * 10] AS both, \
         [x IN [1, 2, 3] WHERE x <> 2] AS filter_only, \
         [x IN [1, 2] | x + 1] AS map_only, \
         [x IN null | x] AS null_list",
        &mut g,
    );
    assert_eq!(
        rows[0].value("both"),
        Value::List(vec![i(20), i(30), i(40)])
    );
    assert_eq!(rows[0].value("filter_only"), Value::List(vec![i(1), i(3)]));
    assert_eq!(rows[0].value("map_only"), Value::List(vec![i(2), i(3)]));
    assert_eq!(rows[0].value("null_list"), Value::Null);
}

#[test]
fn pattern_comprehension_collects_matches_from_the_outer_binding() {
    let (mut g, ..) = seed_social();
    // Ada KNOWS Bob; collect the names of everyone Ada knows.
    let rows = run(
        "MATCH (a:Person {name: 'Ada'}) RETURN [(a)-[:KNOWS]->(b) | b.name] AS known",
        &mut g,
    );
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].value("known"), Value::List(vec![s("Bob")]));
    // With a WHERE filter that rejects every match: empty list.
    let rows = run(
        "MATCH (a:Person {name: 'Ada'}) RETURN [(a)-[:KNOWS]->(b) WHERE b.age > 99 | b.name] AS known",
        &mut g,
    );
    assert_eq!(rows[0].value("known"), Value::List(vec![]));
}

#[test]
fn exists_subquery_tests_pattern_existence() {
    let (mut g, ..) = seed_social();
    // Everyone with an outgoing KNOWS edge: Ada and Bob (Cara only receives).
    let rows = run(
        "MATCH (n:Person) WHERE exists { (n)-[:KNOWS]->() } RETURN n.name AS name ORDER BY name",
        &mut g,
    );
    assert_eq!(col(&rows, "name"), vec![s("Ada"), s("Bob")]);
    // The WHERE inside the subquery constrains the match; MATCH keyword optional.
    let rows = run(
        "MATCH (n:Person) WHERE exists { MATCH (n)-[:KNOWS]->(m) WHERE m.age = 36 } \
         RETURN n.name AS name",
        &mut g,
    );
    assert_eq!(
        col(&rows, "name"),
        vec![s("Bob")],
        "only Bob knows a 36-year-old"
    );
}

// =================================================================================================
// Temporal types (rmp #53): constructors, components, arithmetic, comparison
// =================================================================================================

#[test]
fn temporal_constructors_from_strings_and_maps() {
    let mut g = MemGraph::new();
    let rows = run(
        "RETURN toString(date('2015-07-21')) AS d, \
         toString(date({year: 1984, month: 10, day: 11})) AS dm, \
         toString(localtime('12:31:14.645')) AS t, \
         toString(localdatetime({year: 1984, month: 10, day: 11, hour: 12, minute: 31})) AS ldt, \
         toString(datetime({year: 1984, month: 10, day: 11, hour: 12, timezone: '+01:00'})) AS zdt, \
         toString(duration({days: 14, hours: 16, minutes: 12})) AS dur",
        &mut g,
    );
    assert_eq!(rows[0].value("d"), s("2015-07-21"));
    assert_eq!(rows[0].value("dm"), s("1984-10-11"));
    assert_eq!(rows[0].value("t"), s("12:31:14.645"));
    assert_eq!(rows[0].value("ldt"), s("1984-10-11T12:31"));
    assert_eq!(rows[0].value("zdt"), s("1984-10-11T12:00+01:00"));
    assert_eq!(rows[0].value("dur"), s("P14DT16H12M"));
}

#[test]
fn temporal_component_access() {
    let mut g = MemGraph::new();
    let rows = run(
        "WITH date({year: 1984, month: 10, day: 11}) AS d \
         RETURN d.year AS y, d.quarter AS q, d.month AS m, d.week AS w, d.weekDay AS wd, \
                d.ordinalDay AS od, d.dayOfQuarter AS dq",
        &mut g,
    );
    assert_eq!(rows[0].value("y"), i(1984));
    assert_eq!(rows[0].value("q"), i(4));
    assert_eq!(rows[0].value("m"), i(10));
    assert_eq!(rows[0].value("w"), i(41));
    assert_eq!(rows[0].value("wd"), i(4), "1984-10-11 was a Thursday");
    assert_eq!(rows[0].value("od"), i(285));
    assert_eq!(rows[0].value("dq"), i(11));
    let rows = run(
        "WITH duration({days: 1, hours: 12, minutes: 30}) AS dur \
         RETURN dur.days AS d, dur.hours AS h, dur.minutesOfHour AS moh",
        &mut g,
    );
    assert_eq!(rows[0].value("d"), i(1));
    assert_eq!(rows[0].value("h"), i(12));
    assert_eq!(rows[0].value("moh"), i(30));
}

#[test]
fn temporal_arithmetic_and_comparison() {
    let mut g = MemGraph::new();
    // Calendar-aware addition clamps the day-of-month (Jan 31 + 1 month = Feb 29 in a leap year).
    let rows = run(
        "RETURN toString(date('2020-01-31') + duration({months: 1})) AS clamped, \
         toString(date('2015-07-21') - duration({days: 20})) AS back, \
         toString(duration({hours: 1}) + duration({minutes: 30})) AS dsum, \
         toString(duration({hours: 4}) / 2) AS dhalf, \
         date('1980-12-24') < date('1984-10-11') AS lt",
        &mut g,
    );
    assert_eq!(rows[0].value("clamped"), s("2020-02-29"));
    assert_eq!(rows[0].value("back"), s("2015-07-01"));
    assert_eq!(rows[0].value("dsum"), s("PT1H30M"));
    assert_eq!(rows[0].value("dhalf"), s("PT2H"));
    assert_eq!(rows[0].value("lt"), Value::Boolean(true));
}

#[test]
fn temporal_between_and_truncate() {
    let mut g = MemGraph::new();
    let rows = run(
        "RETURN toString(duration.between(date('1984-10-11'), date('2015-07-21'))) AS between, \
         toString(duration.inDays(date('2015-07-21'), date('2015-08-21'))) AS days, \
         toString(date.truncate('month', date('2015-07-21'))) AS month, \
         toString(datetime.truncate('day', datetime({year: 2015, month: 7, day: 21, hour: 14, timezone: '+02:00'}))) AS day",
        &mut g,
    );
    assert_eq!(rows[0].value("between"), s("P30Y9M10D"));
    assert_eq!(rows[0].value("days"), s("P31D"));
    assert_eq!(rows[0].value("month"), s("2015-07-01"));
    assert_eq!(rows[0].value("day"), s("2015-07-21T00:00+02:00"));
}

#[test]
fn temporal_values_round_trip_as_properties() {
    let mut g = MemGraph::new();
    run(
        "CREATE (:Event {at: date('2015-07-21'), dur: duration({hours: 2})})",
        &mut g,
    );
    let rows = run(
        "MATCH (e:Event) RETURN toString(e.at) AS at, toString(e.dur) AS dur, e.at.year AS y",
        &mut g,
    );
    assert_eq!(rows[0].value("at"), s("2015-07-21"));
    assert_eq!(rows[0].value("dur"), s("PT2H"));
    assert_eq!(rows[0].value("y"), i(2015));
}

// =================================================================================================
// Parameters
// =================================================================================================

#[test]
fn parameters_bind_and_are_used() {
    let (mut g, ..) = seed_social();
    let params = Parameters::new().with("min_age", i(30));
    let rows = run_params(
        "MATCH (n:Person) WHERE n.age >= $min_age RETURN n.name AS name",
        &mut g,
        &IndexCatalog::empty(),
        &params,
    );
    let mut names = col(&rows, "name");
    names.sort_by(|a, b| format!("{a:?}").cmp(&format!("{b:?}")));
    assert_eq!(names, vec![s("Ada"), s("Cara")]);
}

#[test]
fn parameter_drives_limit() {
    let mut g = MemGraph::new();
    for n in 0..10 {
        g.add_node(["P"], [("v", i(n))]);
    }
    let params = Parameters::new().with("top", i(4));
    let rows = run_params(
        "MATCH (n:P) RETURN n.v AS v ORDER BY v LIMIT $top",
        &mut g,
        &IndexCatalog::empty(),
        &params,
    );
    assert_eq!(rows.len(), 4);
}

// =================================================================================================
// Index seek (via the catalog → executor seek path; falls back to scan+filter for MemGraph)
// =================================================================================================

#[test]
fn index_seek_path_returns_same_rows_as_scan() {
    let (mut g, ..) = seed_social();
    // With an index declared, the planner emits a NodeIndexSeek; MemGraph has no index, so the
    // executor falls back to scan+filter — and must return identical rows.
    let catalog = IndexCatalog::builder()
        .with_label_property("Person", "age")
        .build();
    let rows = run_cat(
        "MATCH (n:Person) WHERE n.age = 36 RETURN n.name AS name",
        &mut g,
        &catalog,
    );
    let mut names = col(&rows, "name");
    names.sort_by(|a, b| format!("{a:?}").cmp(&format!("{b:?}")));
    assert_eq!(names, vec![s("Ada"), s("Cara")]);
}

#[test]
fn index_range_seek_path() {
    let (mut g, ..) = seed_social();
    let catalog = IndexCatalog::builder()
        .with_label_property("Person", "age")
        .build();
    let rows = run_cat(
        "MATCH (n:Person) WHERE n.age > 30 RETURN n.name AS name",
        &mut g,
        &catalog,
    );
    let mut names = col(&rows, "name");
    names.sort_by(|a, b| format!("{a:?}").cmp(&format!("{b:?}")));
    assert_eq!(names, vec![s("Ada"), s("Cara")]);
}

// =================================================================================================
// PULL semantics (lazy, bounded)
// =================================================================================================

#[test]
fn pull_in_batches_yields_all_rows() {
    let mut g = MemGraph::new();
    for n in 0..7 {
        g.add_node(["P"], [("v", i(n))]);
    }
    let src = "MATCH (n:P) RETURN n.v AS v ORDER BY v";
    let toks = tokenize(src).unwrap();
    let ast = parse_tokens(&toks, src).unwrap();
    let plan = plan_physical(&lower(&analyze(&ast).unwrap()), &IndexCatalog::empty());
    let bound = bind_parameters(&plan, &Parameters::new()).unwrap();
    let mut cursor = execute(&plan, &bound, &mut g).unwrap();

    let batch1 = cursor.pull(3).unwrap();
    let batch2 = cursor.pull(3).unwrap();
    let batch3 = cursor.pull(3).unwrap(); // only 1 left
    assert_eq!(batch1.len(), 3);
    assert_eq!(batch2.len(), 3);
    assert_eq!(batch3.len(), 1);
    // Pulling past the end yields nothing.
    assert!(cursor.pull(3).unwrap().is_empty());

    let all: Vec<Value> = batch1
        .iter()
        .chain(&batch2)
        .chain(&batch3)
        .map(|r| r.value("v"))
        .collect();
    assert_eq!(all, (0..7).map(i).collect::<Vec<_>>());
}

#[test]
fn limit_stops_pipeline_early_without_scanning_all() {
    // A streaming LIMIT over a streaming MATCH must stop after `limit` rows. We can observe this
    // through the row count; the laziness is what makes a huge graph bounded (`04 §7.4`).
    let mut g = MemGraph::new();
    for _ in 0..1000 {
        g.add_node(["P"], NO_PROPS);
    }
    let rows = run("MATCH (n:P) RETURN n LIMIT 5", &mut g);
    assert_eq!(rows.len(), 5);
}

// =================================================================================================
// Cancellation
// =================================================================================================

#[test]
fn cancelled_query_returns_cancellation_error_not_panic() {
    let mut g = MemGraph::new();
    for _ in 0..50 {
        g.add_node(["P"], NO_PROPS);
    }
    let src = "MATCH (n:P) RETURN n";
    let toks = tokenize(src).unwrap();
    let ast = parse_tokens(&toks, src).unwrap();
    let plan = plan_physical(&lower(&analyze(&ast).unwrap()), &IndexCatalog::empty());
    let bound = bind_parameters(&plan, &Parameters::new()).unwrap();

    let token = CancellationToken::new();
    let executor = Executor::new(plan, bound);
    let mut cursor = executor.open(&mut g, token.clone()).unwrap();

    // Pull one row, then cancel; the next pull must return the cancellation error, cleanly.
    let first = cursor.next().unwrap();
    assert!(first.is_some());
    token.cancel();
    let err = cursor.next().unwrap_err();
    assert_eq!(err, ExecError::Cancelled);
    // After an error the cursor is spent (no panic, no further rows).
    assert!(cursor.next().unwrap().is_none());
}

#[test]
fn cancellation_before_open_trips_immediately() {
    let mut g = MemGraph::new();
    g.add_node(["P"], NO_PROPS);
    let src = "MATCH (n:P) RETURN n";
    let toks = tokenize(src).unwrap();
    let ast = parse_tokens(&toks, src).unwrap();
    let plan = plan_physical(&lower(&analyze(&ast).unwrap()), &IndexCatalog::empty());
    let bound = bind_parameters(&plan, &Parameters::new()).unwrap();

    let token = CancellationToken::new();
    token.cancel();
    let executor = Executor::new(plan, bound);
    // Opening builds the leaf scan (a safe point) — a pre-cancelled token surfaces on first pull.
    let mut cursor = executor.open(&mut g, token).unwrap();
    assert_eq!(cursor.next().unwrap_err(), ExecError::Cancelled);
}

// =================================================================================================
// Golden suite: representative queries with expected results
// =================================================================================================

/// One golden case: a query plus an assertion over its result rows.
type GoldenCase = (&'static str, fn(&[Row]));

#[test]
fn golden_suite_representative_queries() {
    // Each entry: (query, assertion on the resulting rows). The graph is re-seeded fresh per query
    // so the cases are independent and deterministic.
    let cases: Vec<GoldenCase> = vec![
        ("MATCH (n:Person) RETURN count(*) AS c", |rows| {
            assert_eq!(rows[0].value("c"), Value::Integer(3));
        }),
        (
            "MATCH (a:Person)-[:KNOWS]->(b) RETURN a.name AS a ORDER BY a",
            |rows| {
                assert_eq!(
                    col_static(rows, "a"),
                    vec![Value::String("Ada".into()), Value::String("Bob".into())]
                );
            },
        ),
        (
            "MATCH (n:Person) WHERE n.age = 36 RETURN n.name AS name ORDER BY name",
            |rows| {
                assert_eq!(
                    col_static(rows, "name"),
                    vec![Value::String("Ada".into()), Value::String("Cara".into())]
                );
            },
        ),
        (
            "MATCH (n:Person) RETURN n.name AS name, n.age AS age ORDER BY age DESC, name ASC",
            |rows| {
                // age DESC then name ASC: (36 Ada),(36 Cara),(28 Bob).
                assert_eq!(
                    col_static(rows, "name"),
                    vec![
                        Value::String("Ada".into()),
                        Value::String("Cara".into()),
                        Value::String("Bob".into())
                    ]
                );
            },
        ),
        ("UNWIND [10, 20, 30] AS x RETURN sum(x) AS total", |rows| {
            assert_eq!(rows[0].value("total"), Value::Integer(60));
        }),
        (
            "MATCH (n:Person) RETURN n.name AS name ORDER BY name SKIP 1 LIMIT 1",
            |rows| {
                assert_eq!(col_static(rows, "name"), vec![Value::String("Bob".into())]);
            },
        ),
    ];

    for (query, assert_fn) in cases {
        let (mut g, ..) = seed_social();
        let rows = run(query, &mut g);
        assert_fn(&rows);
    }
}

/// Like [`col`] but usable from the `fn` pointers in the golden table (no closure capture).
fn col_static(rows: &[Row], name: &str) -> Vec<Value> {
    rows.iter().map(|r| r.value(name)).collect()
}

// =================================================================================================
// Row / RowValue shape sanity
// =================================================================================================

#[test]
fn result_columns_reflect_projection() {
    let mut g = MemGraph::new();
    g.add_node(["P"], [("name", s("A"))]);
    let src = "MATCH (n:P) RETURN n.name AS name, n.name AS again";
    let toks = tokenize(src).unwrap();
    let ast = parse_tokens(&toks, src).unwrap();
    let plan = plan_physical(&lower(&analyze(&ast).unwrap()), &IndexCatalog::empty());
    let bound = bind_parameters(&plan, &Parameters::new()).unwrap();
    let executor = Executor::new(plan, bound);
    assert_eq!(
        executor.columns(),
        vec!["name".to_owned(), "again".to_owned()]
    );
    let cursor = executor.open(&mut g, CancellationToken::new()).unwrap();
    assert_eq!(cursor.columns(), &["name".to_owned(), "again".to_owned()]);
}

/// Compiles `src` and returns the executor's result column names (no execution needed).
fn columns_of(src: &str) -> Vec<String> {
    let toks = tokenize(src).unwrap();
    let ast = parse_tokens(&toks, src).unwrap();
    let plan = plan_physical(&lower(&analyze(&ast).unwrap()), &IndexCatalog::empty());
    let bound = bind_parameters(&plan, &Parameters::new()).unwrap();
    Executor::new(plan, bound).columns()
}

#[test]
fn unaliased_columns_are_named_by_verbatim_source_text() {
    // openCypher: an un-aliased projection column is named by the exact source text of its
    // expression (regression for rmp #55).
    assert_eq!(columns_of("MATCH (n:P) RETURN n.age"), vec!["n.age"]);
    assert_eq!(columns_of("RETURN 1 + 2"), vec!["1 + 2"]);
    assert_eq!(
        columns_of("RETURN 1+2"),
        vec!["1+2"],
        "spacing is preserved verbatim"
    );
    assert_eq!(columns_of("RETURN count(*)"), vec!["count(*)"]);
    assert_eq!(
        columns_of("MATCH (n:P) RETURN size(n.name)"),
        vec!["size(n.name)"]
    );
    assert_eq!(columns_of("RETURN [1, 2][0]"), vec!["[1, 2][0]"]);
}

#[test]
fn return_star_projects_variables_alphabetically_without_synthetics() {
    let mut g = MemGraph::new();
    let a = g.add_node(["P"], [("name", s("A"))]);
    let b = g.add_node(["P"], [("name", s("B"))]);
    g.add_rel("T", b, a, [] as [(&str, Value); 0]);
    // `*` orders columns alphabetically by variable name, and never projects the planner's
    // synthetic (anonymous-pattern) variables.
    let src = "MATCH (x:P)-[r:T]->(m:P) RETURN *";
    let rows = run(src, &mut g);
    assert_eq!(rows.len(), 1);
    assert_eq!(
        rows[0].columns(),
        &["m".to_owned(), "r".to_owned(), "x".to_owned()]
    );
    // An anonymous relationship must not surface through `*`.
    let anon = run("MATCH (x:P)-[:T]->(m:P) RETURN *", &mut g);
    assert_eq!(anon[0].columns(), &["m".to_owned(), "x".to_owned()]);
}

#[test]
fn aggregation_columns_keep_source_order() {
    let mut g = MemGraph::new();
    g.add_node(["P"], [("dept", s("eng")), ("team", s("db"))]);
    // The Aggregation operator computes keys then aggregates; the result shape must still be the
    // source order (dept, count, team).
    let rows = run(
        "MATCH (n:P) RETURN n.dept AS d, count(*) AS c, n.team AS t",
        &mut g,
    );
    assert_eq!(rows.len(), 1);
    assert_eq!(
        rows[0].columns(),
        &["d".to_owned(), "c".to_owned(), "t".to_owned()]
    );
    assert_eq!(rows[0].value("c"), i(1));
}

#[test]
fn node_binding_round_trips_through_id_function() {
    let mut g = MemGraph::new();
    let a = g.add_node(["P"], NO_PROPS);
    let rows = run("MATCH (n:P) RETURN id(n) AS id", &mut g);
    assert_eq!(rows[0].value("id"), Value::Integer(a.0 as i64));
    // And the bound column itself is a node reference (structural value).
    let rows2 = run("MATCH (n:P) RETURN n", &mut g);
    assert!(matches!(rows2[0].get("n"), Some(RowValue::Node(_))));
}

// =================================================================================================
// Procedure calls (`CALL … [YIELD …]`, rmp #57; `tck/features/clauses/call/**`)
// =================================================================================================

mod procedures {
    use super::{NO_PROPS, col, i, run, s};
    use graphus_core::Value;
    use graphus_cypher::binding::{Parameters, bind_parameters};
    use graphus_cypher::catalog::IndexCatalog;
    use graphus_cypher::executor::execute_with_procedures;
    use graphus_cypher::graph_access::MemGraph;
    use graphus_cypher::lexer::tokenize;
    use graphus_cypher::lower::lower;
    use graphus_cypher::parser::parse_tokens;
    use graphus_cypher::procedure_registry::{
        FieldSpec, FieldType, ProcedureRegistry, ProcedureSet, ProcedureSignature, ValueClass,
    };
    use graphus_cypher::runtime::Row;
    use graphus_cypher::semantics::analyze_with_procedures;

    /// Compiles and executes `src` against `registry` (compile **and** execute over the same
    /// registry — the load-bearing contract), returning the result columns and rows.
    fn run_with(
        src: &str,
        graph: &mut MemGraph,
        registry: &dyn ProcedureRegistry,
        params: &Parameters,
    ) -> (Vec<String>, Vec<Row>) {
        let toks = tokenize(src).expect("lex");
        let ast = parse_tokens(&toks, src).expect("parse");
        let validated = analyze_with_procedures(&ast, registry).expect("analyze");
        let plan = plan_physical(&lower(&validated), &IndexCatalog::empty());
        let bound = bind_parameters(&plan, params).expect("bind");
        let mut cursor = execute_with_procedures(&plan, &bound, graph, registry).expect("open");
        let columns = cursor.columns().to_vec();
        let rows = cursor.collect_all().expect("rows");
        (columns, rows)
    }

    use graphus_cypher::physical::plan_physical;

    /// The TCK Call2 fixture: `test.my.proc(name :: STRING?, id :: INTEGER?) ::
    /// (city :: STRING?, country_code :: INTEGER?)`.
    fn city_registry() -> ProcedureSet {
        let mut set = ProcedureSet::with_builtins();
        set.register_table(
            ProcedureSignature::new(
                "test.my.proc",
                vec![
                    FieldSpec::new("name", FieldType::nullable(ValueClass::String)),
                    FieldSpec::new("id", FieldType::nullable(ValueClass::Integer)),
                ],
                vec![
                    FieldSpec::new("city", FieldType::nullable(ValueClass::String)),
                    FieldSpec::new("country_code", FieldType::nullable(ValueClass::Integer)),
                ],
            ),
            vec![
                (vec![s("Andres"), i(1)], vec![s("Malmö"), i(46)]),
                (vec![s("Stefan"), i(1)], vec![s("Berlin"), i(49)]),
                (vec![s("Stefan"), i(2)], vec![s("München"), i(49)]),
            ],
        )
        .expect("fixture");
        set
    }

    /// `test.labels() :: (label :: STRING?)` yielding A, B, C in table order (TCK Call1 [5]).
    fn labels_registry() -> ProcedureSet {
        let mut set = ProcedureSet::with_builtins();
        set.register_table(
            ProcedureSignature::new(
                "test.labels",
                Vec::new(),
                vec![FieldSpec::new(
                    "label",
                    FieldType::nullable(ValueClass::String),
                )],
            ),
            vec![
                (Vec::new(), vec![s("A")]),
                (Vec::new(), vec![s("B")]),
                (Vec::new(), vec![s("C")]),
            ],
        )
        .expect("fixture");
        set
    }

    /// The void `test.doNothing() :: ()` (TCK Call1 [1]–[4]).
    fn void_registry() -> ProcedureSet {
        let mut set = ProcedureSet::with_builtins();
        set.register_table(
            ProcedureSignature::new("test.doNothing", Vec::new(), Vec::new()),
            Vec::new(),
        )
        .expect("fixture");
        set
    }

    #[test]
    fn standalone_call_yields_the_signature_columns() {
        // TCK Call2 [2]: no YIELD — the declared outputs are the result columns.
        let mut g = MemGraph::new();
        let (columns, rows) = run_with(
            "CALL test.my.proc('Stefan', 1)",
            &mut g,
            &city_registry(),
            &Parameters::new(),
        );
        assert_eq!(columns, ["city", "country_code"]);
        assert_eq!(col(&rows, "city"), vec![s("Berlin")]);
        assert_eq!(col(&rows, "country_code"), vec![i(49)]);
    }

    #[test]
    fn standalone_call_with_yield_star_and_ordered_results() {
        // TCK Call5 [8] (`YIELD *`) and Call1 [5] (table order is preserved).
        let mut g = MemGraph::new();
        let (columns, rows) = run_with(
            "CALL test.labels() YIELD *",
            &mut g,
            &labels_registry(),
            &Parameters::new(),
        );
        assert_eq!(columns, ["label"]);
        assert_eq!(col(&rows, "label"), vec![s("A"), s("B"), s("C")]);
    }

    #[test]
    fn in_query_call_with_yield_and_rename() {
        // TCK Call5 [4]: `YIELD city AS c` binds the renamed column.
        let mut g = MemGraph::new();
        let (_, rows) = run_with(
            "CALL test.my.proc('Stefan', 1) YIELD city AS c, country_code RETURN c, country_code",
            &mut g,
            &city_registry(),
            &Parameters::new(),
        );
        assert_eq!(col(&rows, "c"), vec![s("Berlin")]);
        assert_eq!(col(&rows, "country_code"), vec![i(49)]);
    }

    #[test]
    fn in_query_call_fans_results_across_driving_rows() {
        // TCK Call6 [1] shape: a leading CALL is a row source; a mid-query CALL multiplies rows.
        let mut g = MemGraph::new();
        let (_, rows) = run_with(
            "CALL test.labels() YIELD label WITH count(*) AS c CALL test.labels() YIELD label \
             RETURN c, label",
            &mut g,
            &labels_registry(),
            &Parameters::new(),
        );
        assert_eq!(col(&rows, "c"), vec![i(3), i(3), i(3)]);
        assert_eq!(col(&rows, "label"), vec![s("A"), s("B"), s("C")]);
    }

    #[test]
    fn void_procedure_passes_driving_rows_through() {
        // TCK Call1 [4]: a void CALL preserves cardinality and adds no columns.
        let mut g = MemGraph::new();
        let _ = g.add_node(["A"], [("name", s("a"))]);
        let _ = g.add_node(["B"], [("name", s("b"))]);
        let (_, rows) = run_with(
            "MATCH (n) CALL test.doNothing() RETURN n.name AS name",
            &mut g,
            &void_registry(),
            &Parameters::new(),
        );
        let mut names = col(&rows, "name");
        names.sort_by(|a, b| format!("{a:?}").cmp(&format!("{b:?}")));
        assert_eq!(names, vec![s("a"), s("b")]);
    }

    #[test]
    fn standalone_void_call_produces_one_empty_row() {
        // TCK Call1 [1]: zero result columns; the single unit row carries no client-visible data
        // (the client result set is empty — zero columns).
        let mut g = MemGraph::new();
        let (columns, rows) = run_with(
            "CALL test.doNothing()",
            &mut g,
            &void_registry(),
            &Parameters::new(),
        );
        assert!(columns.is_empty());
        assert_eq!(rows.len(), 1);
    }

    #[test]
    fn implicit_call_takes_arguments_from_parameters() {
        // TCK Call2 [3]: `CALL test.my.proc` with parameters `name`/`id`.
        let mut g = MemGraph::new();
        let mut params = Parameters::new();
        params.insert("name".to_owned(), s("Stefan"));
        params.insert("id".to_owned(), i(1));
        let (columns, rows) = run_with("CALL test.my.proc", &mut g, &city_registry(), &params);
        assert_eq!(columns, ["city", "country_code"]);
        assert_eq!(col(&rows, "city"), vec![s("Berlin")]);
    }

    #[test]
    fn null_argument_matches_null_fixture_row() {
        // TCK Call4: `CALL test.my.proc(null)` matches the `| null | 'nix' |` row.
        let mut set = ProcedureSet::with_builtins();
        set.register_table(
            ProcedureSignature::new(
                "test.nullable",
                vec![FieldSpec::new(
                    "in",
                    FieldType::nullable(ValueClass::Integer),
                )],
                vec![FieldSpec::new(
                    "out",
                    FieldType::nullable(ValueClass::String),
                )],
            ),
            vec![(vec![Value::Null], vec![s("nix")])],
        )
        .expect("fixture");
        let mut g = MemGraph::new();
        let (_, rows) = run_with(
            "CALL test.nullable(null) YIELD out RETURN out",
            &mut g,
            &set,
            &Parameters::new(),
        );
        assert_eq!(col(&rows, "out"), vec![s("nix")]);
    }

    #[test]
    fn builtin_db_labels_runs_through_the_default_pipeline() {
        // The registry-less `execute` resolves the engine built-ins.
        let mut g = MemGraph::new();
        let _ = g.add_node(["B"], NO_PROPS);
        let _ = g.add_node(["A", "B"], NO_PROPS);
        let rows = run("CALL db.labels() YIELD label RETURN label", &mut g);
        assert_eq!(col(&rows, "label"), vec![s("A"), s("B")]);
    }
}

// =================================================================================================
// Spatial: point() / distance() / accessors end to end (`rmp` task #73)
// =================================================================================================

#[test]
fn point_constructor_and_accessors_run_end_to_end() {
    use graphus_core::value::spatial::{Crs, Point};
    let mut g = MemGraph::new();

    // A Cartesian 2D point, projected back with its accessors.
    let rows = run(
        "RETURN point({x: 3, y: 4}) AS p, point({x: 3, y: 4}).x AS x, point({x: 3, y: 4}).srid AS srid",
        &mut g,
    );
    assert_eq!(rows.len(), 1);
    assert_eq!(
        rows[0].value("p"),
        Value::Point(Point::new_2d(Crs::Cartesian, 3.0, 4.0))
    );
    assert_eq!(rows[0].value("x"), Value::Float(3.0));
    assert_eq!(rows[0].value("srid"), Value::Integer(7203));

    // A WGS-84 point from longitude/latitude with its named accessors.
    let rows = run(
        "RETURN point({longitude: -8.61, latitude: 41.15}).crs AS crs, \
         point({longitude: -8.61, latitude: 41.15}).longitude AS lon",
        &mut g,
    );
    assert_eq!(rows[0].value("crs"), s("wgs-84"));
    assert_eq!(rows[0].value("lon"), Value::Float(-8.61));
}

#[test]
fn distance_runs_end_to_end_for_both_crs() {
    let mut g = MemGraph::new();
    // Cartesian Euclidean.
    let rows = run(
        "RETURN distance(point({x: 0, y: 0}), point({x: 3, y: 4})) AS d",
        &mut g,
    );
    assert_eq!(rows[0].value("d"), Value::Float(5.0));

    // Cross-CRS distance is null.
    let rows = run(
        "RETURN distance(point({x: 0, y: 0}), point({longitude: 0, latitude: 0})) AS d",
        &mut g,
    );
    assert_eq!(rows[0].value("d"), Value::Null);

    // WGS-84 great-circle distance is a positive number in metres (London → Paris ~343 km).
    let rows = run(
        "RETURN distance(point({longitude: -0.1278, latitude: 51.5074}), \
         point({longitude: 2.3522, latitude: 48.8566})) AS d",
        &mut g,
    );
    let Value::Float(d) = rows[0].value("d") else {
        panic!("expected a float distance, got {:?}", rows[0].value("d"));
    };
    assert!(
        (d - 343_556.0).abs() < 1_000.0,
        "London–Paris distance was {d} m"
    );
}

#[test]
fn a_point_property_round_trips_through_a_node() {
    use graphus_core::value::spatial::{Crs, Point};
    // A point stored as a node property is read back identically (the MemGraph property path).
    let mut g = MemGraph::new();
    let _ = g.add_node(
        ["City"],
        [("loc", Value::Point(Point::new_2d(Crs::Wgs84, -8.61, 41.15)))],
    );
    let rows = run(
        "MATCH (c:City) RETURN c.loc AS loc, c.loc.latitude AS lat",
        &mut g,
    );
    assert_eq!(rows.len(), 1);
    assert_eq!(
        rows[0].value("loc"),
        Value::Point(Point::new_2d(Crs::Wgs84, -8.61, 41.15))
    );
    assert_eq!(rows[0].value("lat"), Value::Float(41.15));
}

// =================================================================================================
// Pattern predicates (rmp #126): `(n)-[]->()` as a boolean, desugaring to an existential. Mirrors
// `tck/features/expressions/pattern/Pattern1.feature`, executed end to end over a MemGraph.
// =================================================================================================

/// The Pattern1 fixture: `(a:A)-[:REL1]->(b:B), (b)-[:REL2]->(a), (a)-[:REL3]->(:C),
/// (a)-[:REL1]->(:D)`. Returns the graph and the A/B node ids.
fn seed_pattern1() -> (MemGraph, NodeId, NodeId) {
    let mut g = MemGraph::new();
    let a = g.add_node(["A"], NO_PROPS);
    let b = g.add_node(["B"], NO_PROPS);
    let c = g.add_node(["C"], NO_PROPS);
    let d = g.add_node(["D"], NO_PROPS);
    g.add_rel("REL1", a, b, NO_PROPS);
    g.add_rel("REL2", b, a, NO_PROPS);
    g.add_rel("REL3", a, c, NO_PROPS);
    g.add_rel("REL1", a, d, NO_PROPS);
    (g, a, b)
}

/// The set of node ids returned in column `n`.
fn node_id_set(rows: &[Row]) -> std::collections::BTreeSet<NodeId> {
    rows.iter()
        .map(|r| r.get("n").unwrap().as_node().expect("column n is a node"))
        .collect()
}

#[test]
fn pattern_predicate_outgoing_existence() {
    // `WHERE (n)-[]->()` keeps only nodes with at least one outgoing relationship: A and B.
    let (mut g, a, b) = seed_pattern1();
    let rows = run("MATCH (n) WHERE (n)-[]->() RETURN n", &mut g);
    assert_eq!(node_id_set(&rows), [a, b].into_iter().collect());
}

#[test]
fn pattern_predicate_typed_outgoing() {
    // `WHERE (n)-[:REL1]->()` — only A has an outgoing REL1.
    let (mut g, a, _b) = seed_pattern1();
    let rows = run("MATCH (n) WHERE (n)-[:REL1]->() RETURN n", &mut g);
    assert_eq!(node_id_set(&rows), [a].into_iter().collect());
}

#[test]
fn pattern_predicate_negated() {
    // `WHERE NOT (n)-[:REL2]-()` — every node *except* the two REL2 endpoints (A and B).
    let (mut g, a, b) = seed_pattern1();
    let rows = run("MATCH (n) WHERE NOT (n)-[:REL2]-() RETURN n", &mut g);
    let got = node_id_set(&rows);
    assert!(
        !got.contains(&a) && !got.contains(&b),
        "A and B are excluded"
    );
    assert_eq!(got.len(), 2, "the two REL2-free nodes (C and D) remain");
}

#[test]
fn pattern_predicate_conjunction_and_disjunction() {
    let (mut g, a, b) = seed_pattern1();
    // AND: outgoing REL1 *and* (incoming) REL2 — only A satisfies both.
    let rows = run(
        "MATCH (n) WHERE (n)-[:REL1]->() AND (n)-[:REL2]-() RETURN n",
        &mut g,
    );
    assert_eq!(node_id_set(&rows), [a].into_iter().collect());
    // OR: REL1 either direction or REL3 — A, B, and the REL1 targets.
    let rows = run(
        "MATCH (n) WHERE (n)-[:REL1]-() OR (n)-[:REL2]-() RETURN n",
        &mut g,
    );
    let got = node_id_set(&rows);
    assert!(got.contains(&a) && got.contains(&b));
}

#[test]
fn pattern_predicate_between_two_bound_nodes() {
    // `WHERE (n)-[:REL1]->(m)` constrains an existing pair — A→B is the only REL1 forward edge
    // to a labelled-as-matched node here besides A→D.
    let (mut g, a, b) = seed_pattern1();
    let rows = run("MATCH (n), (m) WHERE (n)-[:REL1]->(m) RETURN n, m", &mut g);
    // Every result row's n is A (the sole REL1 source).
    assert!(
        rows.iter()
            .all(|r| r.get("n").unwrap().as_node() == Some(a)),
        "n is always A"
    );
    // B is among the reachable m's.
    assert!(
        rows.iter()
            .any(|r| r.get("m").unwrap().as_node() == Some(b)),
        "B is a REL1 target of A"
    );
}

// =================================================================================================
// WITH ... WHERE dual scope (rmp #128): the trailing WHERE of a WITH sees BOTH the projected
// aliases AND the input variables dropped by the projection (openCypher `WithWhere7`,
// `TriadicSelection1`). The engine carries the referenced input variables across the projection so
// the filter applies, then narrows the row back to the declared output columns.
// =================================================================================================

/// Seeds the triadic-selection shape: `a -KNOWS-> b -KNOWS-> c`, plus a *direct* `a -KNOWS-> cdir`.
/// The anti-join `MATCH (a)-[:KNOWS]->(b)-->(c) OPTIONAL MATCH (a)-[r:KNOWS]->(c) WITH c WHERE r IS
/// NULL` must return the friends-of-friends that `a` does **not** know directly — i.e. `c` but not
/// `cdir`.
fn seed_triadic() -> MemGraph {
    let mut g = MemGraph::new();
    let a = g.add_node(["A"], [("name", s("a"))]);
    let b = g.add_node([] as [&str; 0], [("name", s("b"))]);
    let c = g.add_node([] as [&str; 0], [("name", s("c"))]);
    let cdir = g.add_node([] as [&str; 0], [("name", s("cdir"))]);
    // Friend-of-friend chains: a -> b -> c, and a -> b -> cdir (both c and cdir are FoFs).
    g.add_rel("KNOWS", a, b, [] as [(&str, Value); 0]);
    g.add_rel("KNOWS", b, c, [] as [(&str, Value); 0]);
    g.add_rel("KNOWS", b, cdir, [] as [(&str, Value); 0]);
    // a knows cdir DIRECTLY -> cdir must be excluded by the anti-join.
    g.add_rel("KNOWS", a, cdir, [] as [(&str, Value); 0]);
    g
}

#[test]
fn with_where_triadic_anti_join_references_dropped_relationship() {
    let mut g = seed_triadic();
    let rows = run(
        "MATCH (a:A)-[:KNOWS]->(b)-->(c) \
         OPTIONAL MATCH (a)-[r:KNOWS]->(c) \
         WITH c WHERE r IS NULL \
         RETURN c.name AS name",
        &mut g,
    );
    let names = col(&rows, "name");
    // Only `c` survives: `cdir` is known directly by `a`, so its OPTIONAL `r` is non-null.
    assert_eq!(
        names,
        vec![s("c")],
        "anti-join drops the directly-known FoF"
    );
    // The carried `r` must NOT leak into the output columns — the row is narrowed to `name` only.
    assert_eq!(rows[0].columns(), &["name".to_owned()]);
}

#[test]
fn with_where_sees_variable_dropped_by_projection() {
    // WithWhere7 [1]: `WITH a.name2 AS name WHERE a.name2 = 'B'` — WHERE reads the pre-projection
    // `a`, the projection emits only `name`.
    let mut g = MemGraph::new();
    for n in ["A", "B", "C"] {
        g.add_node([] as [&str; 0], [("name2", s(n))]);
    }
    let rows = run(
        "MATCH (a) WITH a.name2 AS name WHERE a.name2 = 'B' RETURN name",
        &mut g,
    );
    assert_eq!(col(&rows, "name"), vec![s("B")]);
    assert_eq!(rows[0].columns(), &["name".to_owned()]);
}

#[test]
fn with_where_sees_projected_alias() {
    // WithWhere7 [2]: `WITH a.name2 AS name WHERE name = 'B'` — WHERE reads the projected alias.
    let mut g = MemGraph::new();
    for n in ["A", "B", "C"] {
        g.add_node([] as [&str; 0], [("name2", s(n))]);
    }
    let rows = run(
        "MATCH (a) WITH a.name2 AS name WHERE name = 'B' RETURN name",
        &mut g,
    );
    assert_eq!(col(&rows, "name"), vec![s("B")]);
}

#[test]
fn with_where_sees_both_dropped_and_projected() {
    // WithWhere7 [3]: `WHERE name = 'B' OR a.name2 = 'C'` — both scopes in one predicate.
    let mut g = MemGraph::new();
    for n in ["A", "B", "C"] {
        g.add_node([] as [&str; 0], [("name2", s(n))]);
    }
    let rows = run(
        "MATCH (a) WITH a.name2 AS name WHERE name = 'B' OR a.name2 = 'C' RETURN name",
        &mut g,
    );
    let mut names = col(&rows, "name");
    names.sort_by(|x, y| format!("{x:?}").cmp(&format!("{y:?}")));
    assert_eq!(names, vec![s("B"), s("C")]);
}

#[test]
fn with_where_alias_shadows_input_variable_of_same_name() {
    // An alias that re-binds an input name shadows it: in `WITH a.tag AS a WHERE a = 'keep'`, the
    // `a` in WHERE is the projected *string* alias, not the input node. So no input carry is needed
    // and the filter is on the alias value.
    let mut g = MemGraph::new();
    g.add_node([] as [&str; 0], [("tag", s("keep"))]);
    g.add_node([] as [&str; 0], [("tag", s("drop"))]);
    let rows = run(
        "MATCH (a) WITH a.tag AS a WHERE a = 'keep' RETURN a",
        &mut g,
    );
    assert_eq!(col(&rows, "a"), vec![s("keep")]);
    assert_eq!(rows[0].columns(), &["a".to_owned()]);
}

#[test]
fn with_where_filters_before_pagination_is_unaffected_by_carry() {
    // A WHERE that references a dropped variable still narrows correctly when combined with a
    // computed projected column used elsewhere. Here `keep` is projected and `a.name2` is dropped;
    // both are referenced in the WHERE.
    let mut g = MemGraph::new();
    for (name, k) in [("A", true), ("B", false), ("C", true)] {
        g.add_node(
            [] as [&str; 0],
            [("name2", s(name)), ("k", Value::Boolean(k))],
        );
    }
    let rows = run(
        "MATCH (a) WITH a.name2 AS label, a.k AS keep WHERE keep AND a.name2 <> 'X' \
         RETURN label ORDER BY label",
        &mut g,
    );
    assert_eq!(col(&rows, "label"), vec![s("A"), s("C")]);
    assert_eq!(rows[0].columns(), &["label".to_owned()]);
}

// =================================================================================================
// Pattern-matching semantics (rmp #136): undirected, self-loops, named-path directions, UNWIND of
// structural lists, structural list concatenation.
// =================================================================================================

#[test]
fn undirected_relationship_matches_both_directions() {
    // (:A)-[:T1]->(:Looper)-[:LOOP]->(:Looper)(self), (:Looper)-[:T2]->(:B).
    let mut g = MemGraph::new();
    let a = g.add_node(["A"], NO_PROPS);
    let l = g.add_node(["Looper"], NO_PROPS);
    let b = g.add_node(["B"], NO_PROPS);
    g.add_rel("T1", a, l, NO_PROPS);
    g.add_rel("LOOP", l, l, NO_PROPS);
    g.add_rel("T2", l, b, NO_PROPS);
    // Fully undirected two-hop walk from every node (TCK Match3 [16] = 6 rows).
    let rows = run("MATCH (x)-[r1]-(y)-[r2]-(z) RETURN x, r1, y, r2, z", &mut g);
    assert_eq!(
        rows.len(),
        6,
        "every undirected two-hop walk, relationship-unique"
    );
}

#[test]
fn self_loop_is_matched_once_per_relationship() {
    let mut g = MemGraph::new();
    let a = g.add_node(["A"], NO_PROPS);
    let l = g.add_node(["Looper"], NO_PROPS);
    let b = g.add_node(["B"], NO_PROPS);
    g.add_rel("T1", a, l, NO_PROPS);
    g.add_rel("LOOP", l, l, NO_PROPS);
    g.add_rel("T2", l, b, NO_PROPS);
    // Directed first hop, undirected second (TCK Match3 [15] = 2 rows): the LOOP and the T2.
    let rows = run(
        "MATCH (x:A)-[r1]->(y)-[r2]-(z) RETURN x, r1, y, r2, z",
        &mut g,
    );
    assert_eq!(rows.len(), 2, "the self-loop and the onward T2");
}

#[test]
fn bidirectional_arrowheads_parse_as_undirected() {
    // `<-->` / `<-[r]->` denote undirected (TCK Match6 [12]).
    let mut g = MemGraph::new();
    let a = g.add_node(["A"], NO_PROPS);
    let b = g.add_node(["B"], NO_PROPS);
    g.add_rel("T1", a, b, NO_PROPS);
    g.add_rel("T2", b, a, NO_PROPS);
    let rows = run("MATCH p = (n)<-->(k)<-->(n) RETURN p", &mut g);
    assert_eq!(rows.len(), 4, "four bidirectional two-hop cycles");
}

#[test]
fn named_path_preserves_alternating_directions() {
    // (b)-[:T]->(a), (c)-[:T]->(b); `(n)-->(m)--(o)` is one path written C..B..A (TCK Match6 [10]).
    let mut g = MemGraph::new();
    let a = g.add_node(["A"], NO_PROPS);
    let b = g.add_node(["B"], NO_PROPS);
    let c = g.add_node(["C"], NO_PROPS);
    g.add_rel("T", b, a, NO_PROPS);
    g.add_rel("T", c, b, NO_PROPS);
    let rows = run("MATCH p = (n)-->(m)--(o) RETURN p", &mut g);
    assert_eq!(rows.len(), 1, "exactly the C->B->A path");
}

#[test]
fn unwind_preserves_structural_list_elements() {
    // `UNWIND collect(n) AS x` must keep nodes, not collapse them to null (regression guard).
    let (mut g, ..) = seed_social();
    let rows = run(
        "MATCH (n:Person) WITH collect(n) AS ns UNWIND ns AS x RETURN x",
        &mut g,
    );
    assert_eq!(rows.len(), 3, "one row per collected Person");
    assert!(
        rows.iter().all(|r| r.get("x").unwrap().as_node().is_some()),
        "each unwound element is still a node"
    );
}

#[test]
fn list_concatenation_preserves_structural_elements() {
    // `[a] + collect(n) + [b]` must keep the nodes (regression guard for `+` on structural lists).
    let mut g = MemGraph::new();
    g.add_node(["A"], NO_PROPS);
    let rows = run(
        "MATCH (a:A) MATCH (n) WITH a, [a] + collect(n) AS xs UNWIND xs AS x RETURN x",
        &mut g,
    );
    assert_eq!(rows.len(), 2, "the anchor plus the one collected node");
    assert!(
        rows.iter().all(|r| r.get("x").unwrap().as_node().is_some()),
        "concatenation kept the node references"
    );
}

// =================================================================================================
// FOREACH (rmp #122): a per-row side-effect that runs its update body once per list element. It does
// not change row cardinality and the loop variable does not escape.
// =================================================================================================

#[test]
fn foreach_creates_one_node_per_list_element() {
    let mut g = MemGraph::new();
    let rows = run("FOREACH (x IN [1, 2, 3] | CREATE (:N {v: x}))", &mut g);
    assert_eq!(
        rows.len(),
        0,
        "a bare FOREACH is a write root: zero result rows"
    );
    assert_eq!(g.node_count(), 3, "one node created per list element");
    let mut vs: Vec<Value> = g
        .scan_nodes_by_label("N")
        .into_iter()
        .map(|id| g.node_property(id, "v").unwrap())
        .collect();
    vs.sort_by_key(|v| match v {
        Value::Integer(n) => *n,
        _ => panic!("expected integer property"),
    });
    assert_eq!(vs, vec![i(1), i(2), i(3)]);
}

#[test]
fn foreach_set_mutates_an_outer_bound_node_per_element() {
    let mut g = MemGraph::new();
    let n = g.add_node(["Acc"], [("total", i(0))]);
    // For each element, overwrite `total` with that element; the last element wins.
    run(
        "MATCH (n:Acc) FOREACH (x IN [10, 20, 30] | SET n.total = x)",
        &mut g,
    );
    assert_eq!(
        g.node_property(n, "total"),
        Some(i(30)),
        "SET inside FOREACH mutated the outer node, last element wins"
    );
}

#[test]
fn foreach_delete_removes_collected_nodes() {
    let mut g = MemGraph::new();
    g.add_node(["Doomed"], NO_PROPS);
    g.add_node(["Doomed"], NO_PROPS);
    g.add_node(["Keep"], NO_PROPS);
    // Collect the doomed nodes into a list, then delete each one inside FOREACH.
    run(
        "MATCH (n:Doomed) WITH collect(n) AS ns FOREACH (n IN ns | DELETE n)",
        &mut g,
    );
    assert_eq!(
        g.scan_nodes_by_label("Doomed").len(),
        0,
        "all doomed deleted"
    );
    assert_eq!(
        g.scan_nodes_by_label("Keep").len(),
        1,
        "the keeper survives"
    );
    assert_eq!(g.node_count(), 1);
}

#[test]
fn nested_foreach_flattens_and_creates() {
    let mut g = MemGraph::new();
    run(
        "FOREACH (x IN [[1, 2], [3]] | FOREACH (y IN x | CREATE (:N {v: y})))",
        &mut g,
    );
    assert_eq!(
        g.node_count(),
        3,
        "nested FOREACH creates one node per leaf element"
    );
    let mut vs: Vec<i64> = g
        .scan_nodes_by_label("N")
        .into_iter()
        .map(|id| match g.node_property(id, "v").unwrap() {
            Value::Integer(n) => n,
            _ => panic!("expected integer"),
        })
        .collect();
    vs.sort_unstable();
    assert_eq!(vs, vec![1, 2, 3]);
}

#[test]
fn foreach_over_empty_list_is_a_no_op() {
    let mut g = MemGraph::new();
    let rows = run("FOREACH (x IN [] | CREATE (:N {v: x}))", &mut g);
    assert_eq!(rows.len(), 0);
    assert_eq!(g.node_count(), 0, "an empty list yields zero iterations");
}

#[test]
fn foreach_over_null_is_a_no_op() {
    let mut g = MemGraph::new();
    let n = g.add_node(["Host"], NO_PROPS); // no `items` property → n.items is null
    // FOREACH over a null list performs zero iterations and leaves the graph untouched.
    run(
        "MATCH (n:Host) FOREACH (x IN n.items | CREATE (:N {v: x}))",
        &mut g,
    );
    assert_eq!(g.node_count(), 1, "only the pre-existing host node remains");
    assert_eq!(g.scan_nodes_by_label("N").len(), 0);
    let _ = n;
}

#[test]
fn foreach_preserves_input_cardinality() {
    let mut g = MemGraph::new();
    g.add_node(["Driver"], [("name", s("a"))]);
    g.add_node(["Driver"], [("name", s("b"))]);
    // Two driving rows; FOREACH runs its body per row and passes BOTH rows through to RETURN.
    let rows = run(
        "MATCH (d:Driver) FOREACH (x IN [1] | CREATE (:Made)) RETURN d.name AS name",
        &mut g,
    );
    let mut names: Vec<Value> = rows.iter().map(|r| r.value("name")).collect();
    names.sort_by_key(|v| match v {
        Value::String(s) => s.clone(),
        _ => panic!("expected string"),
    });
    assert_eq!(
        names,
        vec![s("a"), s("b")],
        "both driving rows pass through"
    );
    assert_eq!(
        g.scan_nodes_by_label("Made").len(),
        2,
        "the body ran once per driving row (cardinality preserved)"
    );
}

#[test]
fn foreach_loop_variable_does_not_escape_into_returned_row() {
    let mut g = MemGraph::new();
    // The loop variable `x` is local; the body's SET captures it, but it never appears on the row.
    let n = g.add_node(["Acc"], NO_PROPS);
    let rows = run(
        "MATCH (n:Acc) FOREACH (x IN [7] | SET n.v = x) RETURN n.v AS v",
        &mut g,
    );
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].value("v"), i(7));
    assert_eq!(g.node_property(n, "v"), Some(i(7)));
}

#[test]
fn foreach_over_non_list_is_a_runtime_type_error() {
    let mut g = MemGraph::new();
    let src = "FOREACH (x IN 5 | CREATE (:N {v: x}))";
    let toks = tokenize(src).unwrap();
    let ast = parse_tokens(&toks, src).unwrap();
    let plan = plan_physical(&lower(&analyze(&ast).unwrap()), &IndexCatalog::empty());
    let bound = bind_parameters(&plan, &Parameters::new()).unwrap();
    let mut cursor = execute(&plan, &bound, &mut g).unwrap();
    let err = cursor.collect_all().unwrap_err();
    assert!(
        matches!(err, ExecError::Eval(_)),
        "FOREACH over a non-list value is a runtime TypeError, got {err:?}"
    );
    assert_eq!(g.node_count(), 0, "no side effect ran for the bad list");
}

// =================================================================================================
// Percentile aggregates — boundary safety (`rmp` task #400)
// =================================================================================================

/// Compiles and runs `src`, returning the first row's first column as a `Value`, panicking on any
/// runtime error. Used to assert percentile boundary values never panic and return an in-set value.
fn run_one(src: &str, graph: &mut MemGraph) -> Value {
    let rows = run(src, graph);
    assert_eq!(rows.len(), 1, "expected a single aggregate row for {src:?}");
    let row = &rows[0];
    row.value("p")
}

/// Compiles and runs `src`, returning the captured runtime error (expects one).
fn run_expect_err(src: &str, graph: &mut MemGraph) -> ExecError {
    let toks = tokenize(src).expect("lex");
    let ast = parse_tokens(&toks, src).expect("parse");
    let plan = plan_physical(&lower(&analyze(&ast).unwrap()), &IndexCatalog::empty());
    let bound = bind_parameters(&plan, &Parameters::new()).expect("bind");
    // The percentile range is validated at intake (`Accumulator::update`), which runs as the
    // aggregation consumes its input — surfacing either when the cursor is opened (eager aggregate
    // drive) or on `collect_all`. Capture from whichever stage raises it.
    match execute(&plan, &bound, graph) {
        Err(e) => e,
        Ok(mut cursor) => cursor
            .collect_all()
            .expect_err("expected a runtime error from the percentile query"),
    }
}

#[test]
fn percentile_disc_boundaries_never_panic_and_return_in_set_value() {
    // The `rmp` #400 consumer-side bound, exercised at the dangerous edges. A LARGE group (so the
    // `perc * count` index arithmetic is non-trivial) of the integers 0..1000; percentileDisc must
    // return a real member of the set for every boundary `p` and never panic on an out-of-range index.
    let mut g = MemGraph::new();
    // p = 0.0 → smallest element (0).
    assert_eq!(
        run_one(
            "UNWIND range(0, 999) AS x RETURN percentileDisc(x, 0.0) AS p",
            &mut g
        ),
        i(0),
        "percentileDisc(_, 0.0) is the minimum element"
    );
    // p = 1.0 → largest element (999). This is the index = count-1 boundary the clamp guards.
    assert_eq!(
        run_one(
            "UNWIND range(0, 999) AS x RETURN percentileDisc(x, 1.0) AS p",
            &mut g
        ),
        i(999),
        "percentileDisc(_, 1.0) is the maximum element"
    );
    // p = 0.9999999 → very close to 1.0 but not equal: the index must still be in-set (== 999 by
    // nearest-rank), and must NOT round up to an out-of-bounds index.
    assert_eq!(
        run_one(
            "UNWIND range(0, 999) AS x RETURN percentileDisc(x, 0.9999999) AS p",
            &mut g
        ),
        i(999),
        "percentileDisc near 1.0 stays in-set (no OOB index)"
    );
    // A mid value is a genuine set member. By Neo4j's nearest-rank algorithm over 1000 elements,
    // `float_idx = 0.5 * 1000 = 500.0` is an exact integer, so the rank is `500 - 1 = 499` (element
    // value 499). The point is that it is a real member of the set, never an OOB index.
    assert_eq!(
        run_one(
            "UNWIND range(0, 999) AS x RETURN percentileDisc(x, 0.5) AS p",
            &mut g
        ),
        i(499),
        "percentileDisc(_, 0.5) is a real set member (Neo4j nearest-rank)"
    );
}

#[test]
fn percentile_cont_boundaries_never_panic_and_return_in_set_value() {
    // percentileCont over the same large group: every boundary `p` yields a defined Float within the
    // value range [0, 999], never an OOB index panic.
    let mut g = MemGraph::new();
    assert_eq!(
        run_one(
            "UNWIND range(0, 999) AS x RETURN percentileCont(x, 0.0) AS p",
            &mut g
        ),
        Value::Float(0.0),
        "percentileCont(_, 0.0) is the minimum"
    );
    assert_eq!(
        run_one(
            "UNWIND range(0, 999) AS x RETURN percentileCont(x, 1.0) AS p",
            &mut g
        ),
        Value::Float(999.0),
        "percentileCont(_, 1.0) is the maximum"
    );
    // p just under 1.0: interpolates between 998 and 999, strictly inside the range — and crucially
    // the `ceil` index is clamped so it can never index past count-1.
    match run_one(
        "UNWIND range(0, 999) AS x RETURN percentileCont(x, 0.9999999) AS p",
        &mut g,
    ) {
        Value::Float(v) => assert!(
            (998.0..=999.0).contains(&v),
            "percentileCont near 1.0 stays in [998, 999], got {v}"
        ),
        other => panic!("percentileCont returns a Float, got {other:?}"),
    }
}

#[test]
fn percentile_out_of_range_is_number_out_of_range_error() {
    // p > 1.0 and NaN must be rejected with `NumberOutOfRange` (the validator at intake), never reach
    // the index path. NaN is rejected because it is not in `[0.0, 1.0]`.
    let mut g = MemGraph::new();
    let err = run_expect_err(
        "UNWIND range(0, 999) AS x RETURN percentileDisc(x, 1.5) AS p",
        &mut g,
    );
    assert!(
        matches!(err, ExecError::Eval(EvalError::NumberOutOfRange { .. })),
        "p > 1.0 is NumberOutOfRange, got {err:?}"
    );
    let err = run_expect_err(
        "UNWIND range(0, 999) AS x RETURN percentileCont(x, (0.0/0.0)) AS p",
        &mut g,
    );
    assert!(
        matches!(err, ExecError::Eval(EvalError::NumberOutOfRange { .. })),
        "NaN percentile is NumberOutOfRange, got {err:?}"
    );
}
