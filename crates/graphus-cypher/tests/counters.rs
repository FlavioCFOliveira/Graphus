//! Exact side-effect [`QueryCounters`] over the reference [`MemGraph`] backend (`rmp` task #510).
//!
//! These tests run the full Cypher pipeline (`parse → analyze → plan → bind → execute`) against a
//! [`MemGraph`] and assert the side-effect counters drained afterwards via
//! [`GraphAccess::write_counters`], covering every Neo4j operation-count rule the seam implements.
//! [`MemGraph`] is the executor's reference backend, and its counters are instrumented to match the
//! live `RecordStoreGraph` event-for-event (the `RecordStoreGraph` equivalence is proven in
//! `tests/record_store_graph.rs`).
//!
//! Each assertion uses [`delta`], which snapshots the counters before the statement and returns only
//! the increments attributable to it — so setup writes (seeding the graph) never leak into the
//! assertion, and every counter field is checked exhaustively (an unexpected increment fails).

use graphus_cypher::QueryCounters;
use graphus_cypher::binding::{Parameters, bind_parameters};
use graphus_cypher::catalog::IndexCatalog;
use graphus_cypher::executor::execute;
use graphus_cypher::graph_access::{GraphAccess, MemGraph};
use graphus_cypher::lexer::tokenize;
use graphus_cypher::lower::lower;
use graphus_cypher::parser::parse_tokens;
use graphus_cypher::physical::plan_physical;
use graphus_cypher::semantics::analyze;

/// Runs `src` to completion (draining the cursor, so all writes apply) against `graph`.
fn run(src: &str, graph: &mut MemGraph) {
    let toks = tokenize(src).expect("lex");
    let ast = parse_tokens(&toks, src).expect("parse");
    let plan = plan_physical(
        &lower(&analyze(&ast).expect("analyze")),
        &IndexCatalog::empty(),
    );
    let params = bind_parameters(&plan, &Parameters::new()).expect("bind");
    execute(&plan, &params, graph)
        .expect("open cursor")
        .collect_all()
        .expect("collect rows");
}

/// The counters attributable to running `src` against `graph`: the field-wise difference between the
/// tally after and before the run. Robust against `MemGraph` accumulating counters across statements.
fn delta(graph: &mut MemGraph, src: &str) -> QueryCounters {
    let before = graph.write_counters();
    run(src, graph);
    let after = graph.write_counters();
    QueryCounters {
        nodes_created: after.nodes_created - before.nodes_created,
        nodes_deleted: after.nodes_deleted - before.nodes_deleted,
        relationships_created: after.relationships_created - before.relationships_created,
        relationships_deleted: after.relationships_deleted - before.relationships_deleted,
        properties_set: after.properties_set - before.properties_set,
        labels_added: after.labels_added - before.labels_added,
        labels_removed: after.labels_removed - before.labels_removed,
    }
}

#[test]
fn create_node_counts_node_labels_and_properties() {
    let mut g = MemGraph::new();
    assert_eq!(
        delta(&mut g, "CREATE (n:A:B {x:1})"),
        QueryCounters {
            nodes_created: 1,
            labels_added: 2,
            properties_set: 1,
            ..Default::default()
        }
    );
}

#[test]
fn create_relationship_counts_two_nodes_one_rel_one_property() {
    let mut g = MemGraph::new();
    assert_eq!(
        delta(&mut g, "CREATE (a)-[:R {w:1}]->(b)"),
        QueryCounters {
            nodes_created: 2,
            relationships_created: 1,
            properties_set: 1,
            ..Default::default()
        }
    );
}

#[test]
fn set_property_to_same_value_still_counts_once_per_matched_node() {
    let mut g = MemGraph::new();
    // Three nodes, each carrying `x`; `SET n.x = n.x` re-sets each to its current (non-null) value.
    run("CREATE (:N {x:1}), (:N {x:2}), (:N {x:3})", &mut g);
    assert_eq!(
        delta(&mut g, "MATCH (n) SET n.x = n.x"),
        QueryCounters {
            properties_set: 3,
            ..Default::default()
        }
    );
}

#[test]
fn set_property_to_null_is_a_removal_and_does_not_count() {
    let mut g = MemGraph::new();
    run("CREATE (:N {x:1})", &mut g);
    assert_eq!(
        delta(&mut g, "MATCH (n) SET n.x = null"),
        QueryCounters::default()
    );
}

#[test]
fn remove_property_does_not_count_as_a_set() {
    let mut g = MemGraph::new();
    run("CREATE (:N {x:1})", &mut g);
    assert_eq!(
        delta(&mut g, "MATCH (n) REMOVE n.x"),
        QueryCounters::default()
    );
}

#[test]
fn adding_an_already_present_label_counts_zero() {
    let mut g = MemGraph::new();
    run("CREATE (:A)", &mut g);
    assert_eq!(delta(&mut g, "MATCH (n) SET n:A"), QueryCounters::default());
}

#[test]
fn removing_an_absent_label_counts_zero() {
    let mut g = MemGraph::new();
    run("CREATE (:A)", &mut g);
    assert_eq!(
        delta(&mut g, "MATCH (n) REMOVE n:B"),
        QueryCounters::default()
    );
}

#[test]
fn removing_a_present_label_counts_one() {
    let mut g = MemGraph::new();
    run("CREATE (:A:B)", &mut g);
    // `REMOVE n:A:C`: A is present (counts 1), C is absent (counts 0).
    assert_eq!(
        delta(&mut g, "MATCH (n) REMOVE n:A:C"),
        QueryCounters {
            labels_removed: 1,
            ..Default::default()
        }
    );
}

#[test]
fn merge_that_matches_creates_nothing() {
    let mut g = MemGraph::new();
    run("CREATE (:Person {name:'Ada'})", &mut g);
    // The pattern already exists, so MERGE matches and creates nothing.
    assert_eq!(
        delta(&mut g, "MERGE (n:Person {name:'Ada'})"),
        QueryCounters::default()
    );
}

#[test]
fn merge_that_creates_counts_the_create() {
    let mut g = MemGraph::new();
    // No such node exists, so MERGE takes the create branch (1 node, 1 label, 1 property).
    assert_eq!(
        delta(&mut g, "MERGE (n:Person {name:'Bob'})"),
        QueryCounters {
            nodes_created: 1,
            labels_added: 1,
            properties_set: 1,
            ..Default::default()
        }
    );
}

#[test]
fn detach_delete_counts_node_once_and_each_incident_relationship() {
    let mut g = MemGraph::new();
    // `a` is a shared start node with two outgoing relationships, so `MATCH (a)-[r]->(b)` binds two
    // rows that both target `a` for deletion — exercising "delete the same node twice counts once".
    run(
        "CREATE (a:A), (b1:B), (b2:B), (a)-[:R]->(b1), (a)-[:R]->(b2)",
        &mut g,
    );
    assert_eq!(
        delta(&mut g, "MATCH (a)-[r]->(b) DETACH DELETE a"),
        QueryCounters {
            nodes_deleted: 1,
            relationships_deleted: 2,
            ..Default::default()
        }
    );
}

#[test]
fn set_map_replace_counts_each_non_null_key() {
    let mut g = MemGraph::new();
    run("CREATE (:N {a:1})", &mut g);
    // `SET n = {b:2, c:3}` clears `a` (a bulk removal, not counted) and sets `b`, `c` (2 sets). A null
    // value in the map would be dropped and not counted; here both are non-null.
    assert_eq!(
        delta(&mut g, "MATCH (n) SET n = {b:2, c:3}"),
        QueryCounters {
            properties_set: 2,
            ..Default::default()
        }
    );
}

#[test]
fn set_map_merge_counts_non_null_keys_only() {
    let mut g = MemGraph::new();
    run("CREATE (:N {a:1})", &mut g);
    // `SET n += {b:2, a:null}` sets `b` (1) and removes `a` via the null value (0).
    assert_eq!(
        delta(&mut g, "MATCH (n) SET n += {b:2, a:null}"),
        QueryCounters {
            properties_set: 1,
            ..Default::default()
        }
    );
}

#[test]
fn create_then_delete_counts_both_operations() {
    // The Bolt operation-count model (NOT the openCypher observability model): `CREATE (n) DELETE n`
    // is one create AND one delete, even though the net graph change is nothing.
    let mut g = MemGraph::new();
    assert_eq!(
        delta(&mut g, "CREATE (n) DELETE n"),
        QueryCounters {
            nodes_created: 1,
            nodes_deleted: 1,
            ..Default::default()
        }
    );
}

#[test]
fn read_only_statement_records_no_counters() {
    let mut g = MemGraph::new();
    run("CREATE (:N {x:1}), (:N {x:2})", &mut g);
    let d = delta(&mut g, "MATCH (n) RETURN n.x");
    assert!(d.is_empty());
    assert!(!d.contains_updates());
}

#[test]
fn null_property_on_create_is_not_stored_and_not_counted() {
    let mut g = MemGraph::new();
    // `{x:1, y:null}`: only `x` is persisted and counted; the null `y` is neither stored nor counted.
    assert_eq!(
        delta(&mut g, "CREATE (n {x:1, y:null})"),
        QueryCounters {
            nodes_created: 1,
            properties_set: 1,
            ..Default::default()
        }
    );
}

#[test]
fn fresh_graph_reports_empty_counters() {
    // A graph that has applied no writes reports the empty tally.
    let g = MemGraph::new();
    let c = g.write_counters();
    assert_eq!(c, QueryCounters::default());
    assert!(c.is_empty());
    assert!(!c.contains_updates());
}
