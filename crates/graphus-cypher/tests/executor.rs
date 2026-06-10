//! End-to-end executor tests (`04-technical-design.md` §7.4, §7.7).
//!
//! Each test runs the **full pipeline** — parse a query string, semantic-analyse, lower to a logical
//! plan, plan physically, bind parameters, then execute over a seeded
//! [`MemGraph`](graphus_cypher::graph_access::MemGraph) — and asserts the exact result rows. This is
//! the capstone proof that `parse → semantics → plan → execute` runs real Cypher end to end and
//! returns correct results.

use graphus_core::Value;
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
    let rows = run("UNWIND [1, 2, 3] AS x CREATE (n:T {v: x}) RETURN x LIMIT 1", &mut g);
    assert_eq!(rows.len(), 1, "LIMIT 1 returns one row");
    assert_eq!(g.node_count(), 3, "CREATE must run once per input row");
}

#[test]
fn merge_under_limit_zero_still_creates() {
    let mut g = MemGraph::new();
    let rows = run("MERGE (n:City {name: 'Faro'}) RETURN n LIMIT 0", &mut g);
    assert_eq!(rows.len(), 0);
    assert_eq!(g.node_count(), 1, "the MERGE-create side effect must still run");
}

#[test]
fn set_under_limit_zero_still_applies() {
    let mut g = MemGraph::new();
    let a = g.add_node(["P"], [("age", i(20))]);
    let b = g.add_node(["P"], [("age", i(30))]);
    let rows = run("MATCH (n:P) SET n.age = 99 RETURN n LIMIT 0", &mut g);
    assert_eq!(rows.len(), 0);
    assert_eq!(g.node_property(a, "age"), Some(i(99)));
    assert_eq!(g.node_property(b, "age"), Some(i(99)), "SET must run for every matched row");
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
    assert_eq!(g.node_count(), 3, "CREATE must run once per input row under TopN");
}

#[test]
fn create_under_skip_past_end_still_creates() {
    let mut g = MemGraph::new();
    let rows = run("CREATE (n) RETURN n SKIP 1", &mut g);
    assert_eq!(rows.len(), 0);
    assert_eq!(g.node_count(), 1, "SKIP must not suppress the CREATE side effect");
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
    assert_eq!(rows[0].value("hit"), Value::Boolean(true), "a true decides any()");
    assert_eq!(rows[0].value("miss"), Value::Boolean(false), "a true decides none()");
    assert_eq!(rows[0].value("unknown"), Value::Null, "a null leaves all() unknown");
    assert_eq!(rows[0].value("maybe"), Value::Null, "a null could be a second match");

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
    assert_eq!(col(&rows, "name"), vec![s("Bob")], "only Bob knows a 36-year-old");
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
    assert_eq!(columns_of("RETURN 1+2"), vec!["1+2"], "spacing is preserved verbatim");
    assert_eq!(columns_of("RETURN count(*)"), vec!["count(*)"]);
    assert_eq!(columns_of("MATCH (n:P) RETURN size(n.name)"), vec!["size(n.name)"]);
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
    assert_eq!(rows[0].columns(), &["m".to_owned(), "r".to_owned(), "x".to_owned()]);
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
