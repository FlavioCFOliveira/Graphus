//! `EXPLAIN` / `PROFILE` query prefixes, end to end through the compile + execute pipeline
//! (`rmp` task #752).
//!
//! Four properties are pinned here, in order of importance:
//!
//! 1. **`EXPLAIN` does not execute.** Not "does not return rows" — does not *run*: an
//!    `EXPLAIN CREATE (:X)` leaves the graph byte-for-byte unchanged, and an `EXPLAIN` of a read makes
//!    no store access at all. The plan comes back with estimates only.
//! 2. **`PROFILE` executes and measures.** It returns the statement's real rows, and every operator of
//!    the returned plan carries the `rows` it emitted and the `dbHits` it really made — measured, never
//!    guessed.
//! 3. **A seek-vs-scan regression is detectable.** The same query, planned with and without the backing
//!    index, reports a different `operatorType` **and** a different `dbHits` — which is the whole point
//!    of the feature: a silent planner regression to a full scan can be caught.
//! 4. **The prefix is not a reserved word.** `explain` / `profile` keep working as identifiers, labels,
//!    property keys and aliases; the openCypher TCK depends on it.

use graphus_core::Value;
use graphus_cypher::ast::QueryPrefix;
use graphus_cypher::binding::{Parameters, bind_parameters};
use graphus_cypher::catalog::IndexCatalog;
use graphus_cypher::executor::execute;
use graphus_cypher::graph_access::{GraphAccess, MemGraph};
use graphus_cypher::lexer::tokenize;
use graphus_cypher::lower::lower;
use graphus_cypher::parser::parse_tokens;
use graphus_cypher::physical::{PhysicalPlan, plan_physical};
use graphus_cypher::plan_description::PlanDescription;
use graphus_cypher::semantics::analyze;

// =================================================================================================
// Harness
// =================================================================================================

/// Compiles `src` against `catalog`, carrying its `EXPLAIN` / `PROFILE` prefix onto the plan exactly as
/// the server's compile pipeline does.
fn compile(src: &str, catalog: &IndexCatalog) -> PhysicalPlan {
    let toks = tokenize(src).expect("lex");
    let ast = parse_tokens(&toks, src).expect("parse");
    let validated = analyze(&ast).expect("analyze");
    plan_physical(&lower(&validated), catalog).with_prefix(ast.prefix())
}

/// Runs `src` over `graph` and returns `(rows, the plan description if the statement carried a prefix)`.
fn run(
    src: &str,
    catalog: &IndexCatalog,
    graph: &mut MemGraph,
) -> (usize, Option<PlanDescription>) {
    let plan = compile(src, catalog);
    let params = bind_parameters(&plan, &Parameters::new()).expect("bind");
    let mut cursor = execute(&plan, &params, graph).expect("open");
    let rows = cursor.collect_all().expect("drain").len();
    let description = match plan.prefix() {
        Some(QueryPrefix::Explain) => Some(PlanDescription::explain(&plan)),
        Some(QueryPrefix::Profile) => Some(PlanDescription::profile(
            cursor
                .profile()
                .expect("a PROFILEd statement has a recorder"),
        )),
        None => None,
    };
    (rows, description)
}

/// A graph of `n` `:Person` nodes with a distinct `name` each, plus one `:Other` node.
fn people(n: i64) -> MemGraph {
    let mut g = MemGraph::new();
    for i in 0..n {
        g.add_node(["Person"], [("name", Value::String(format!("p{i}")))]);
    }
    g.add_node(["Other"], [("name", Value::String("x".into()))]);
    g
}

fn indexed() -> IndexCatalog {
    IndexCatalog::builder()
        .with_label_property("Person", "name")
        .build()
}

// =================================================================================================
// 1. EXPLAIN does not execute
// =================================================================================================

#[test]
fn explain_create_creates_nothing() {
    let mut graph = MemGraph::new();
    let before = graph.scan_nodes().len();

    let (rows, plan) = run(
        "EXPLAIN CREATE (:X {a: 1})",
        &IndexCatalog::empty(),
        &mut graph,
    );

    assert_eq!(rows, 0, "EXPLAIN returns no records");
    assert_eq!(
        graph.scan_nodes().len(),
        before,
        "EXPLAIN CREATE must not create a node — the statement is planned, never run"
    );
    assert!(graph.write_counters().is_empty(), "no write was applied");
    let plan = plan.expect("EXPLAIN reports a plan");
    assert_eq!(plan.metadata_key(), "plan");
    assert!(
        plan.contains_operator("Create"),
        "the plan shows the Create"
    );
    // Nothing ran, so nothing is measured — an EXPLAIN never fabricates a runtime counter.
    assert!(plan.root().rows.is_none());
    assert!(plan.root().db_hits.is_none());
}

#[test]
fn explain_of_a_write_leaves_every_kind_of_side_effect_unapplied() {
    let mut graph = MemGraph::new();
    let a = graph.add_node(["Person"], [("name", Value::String("Ada".into()))]);
    let b = graph.add_node(["Person"], [("name", Value::String("Bob".into()))]);
    graph.add_rel("KNOWS", a, b, [("since", Value::Integer(2020))]);
    // The seam's counters are cumulative and the seeding above used them; snapshot, so what we assert is
    // that the EXPLAINs below added nothing.
    let seeded = graph.write_counters();

    for src in [
        "EXPLAIN MATCH (n:Person) SET n.name = 'zzz'",
        "EXPLAIN MATCH (n:Person) REMOVE n:Person",
        "EXPLAIN MATCH (n:Person) DETACH DELETE n",
        "EXPLAIN MATCH (a:Person), (b:Person) MERGE (a)-[:NEW]->(b)",
    ] {
        let (rows, _) = run(src, &IndexCatalog::empty(), &mut graph);
        assert_eq!(rows, 0, "{src} returns no records");
    }

    // The graph is exactly as it was seeded.
    assert_eq!(graph.scan_nodes().len(), 2);
    assert_eq!(
        graph.node_property(a, "name"),
        Some(Value::String("Ada".into()))
    );
    assert_eq!(graph.node_labels(a), Some(vec!["Person".to_owned()]));
    assert_eq!(graph.incident_rels(a).len(), 1);
    assert_eq!(
        graph.write_counters(),
        seeded,
        "not one write operation was applied by the four EXPLAINed writes"
    );
}

#[test]
fn explain_of_a_read_returns_the_columns_but_no_rows() {
    let mut graph = people(5);
    let plan = compile("EXPLAIN MATCH (n:Person) RETURN n.name AS name", &indexed());
    let params = bind_parameters(&plan, &Parameters::new()).expect("bind");
    let mut cursor = execute(&plan, &params, &mut graph).expect("open");

    // Neo4j reports the statement's real `fields` for an EXPLAIN and simply streams no record.
    assert_eq!(cursor.columns(), ["name"]);
    assert!(cursor.collect_all().expect("drain").is_empty());
    assert!(
        cursor.profile().is_none(),
        "an EXPLAIN records no runtime counters"
    );
}

// =================================================================================================
// 2. PROFILE executes and measures
// =================================================================================================

#[test]
fn profile_returns_the_rows_and_measures_every_operator() {
    let mut graph = people(4);
    let (rows, plan) = run(
        "PROFILE MATCH (n:Person) RETURN n.name AS name",
        &indexed(),
        &mut graph,
    );

    assert_eq!(rows, 4, "PROFILE runs the query and returns its records");
    let plan = plan.expect("PROFILE reports a plan");
    assert_eq!(plan.metadata_key(), "profile");
    assert!(plan.is_profiled());

    // The root projection emitted one row per person…
    assert_eq!(plan.root().rows, Some(4));
    // …and every operator carries a measured dbHit count.
    assert!(plan.root().db_hits.is_some());
    let leaf = &plan.root().children[0];
    assert_eq!(leaf.operator_type, "NodeByLabelScan");
    assert_eq!(leaf.rows, Some(4), "the scan emitted the 4 :Person nodes");
    assert!(
        leaf.db_hits.unwrap_or(0) >= 4,
        "the scan obtained at least the 4 records it emitted, got {:?}",
        leaf.db_hits
    );
}

#[test]
fn profile_of_a_write_applies_the_write() {
    let mut graph = MemGraph::new();
    let (rows, plan) = run(
        "PROFILE CREATE (n:X {a: 1}) RETURN n.a AS a",
        &IndexCatalog::empty(),
        &mut graph,
    );

    assert_eq!(rows, 1);
    assert_eq!(graph.scan_nodes().len(), 1, "PROFILE really writes");
    assert_eq!(graph.write_counters().nodes_created, 1);
    let plan = plan.expect("a plan");
    assert!(plan.contains_operator("Create"));
    // The Create operator's own storage work was measured (one create + the property writes).
    let create = plan
        .root()
        .children
        .first()
        .expect("the Create sits under the projection");
    assert_eq!(create.operator_type, "Create");
    assert!(create.db_hits.unwrap_or(0) >= 1);
}

// =================================================================================================
// 3. A seek-vs-scan regression is detectable
// =================================================================================================

#[test]
fn a_regression_from_an_index_seek_to_a_scan_is_visible_in_the_plan_and_in_db_hits() {
    let query = "PROFILE MATCH (n:Person {name: 'p7'}) RETURN n";

    // With the index: a seek that touches a handful of records.
    let mut graph = people(200);
    let (seek_rows, seek_plan) = run(query, &indexed(), &mut graph);
    let seek_plan = seek_plan.expect("a plan");

    // Without it (the regression): the same rows, from a full label scan.
    let mut graph = people(200);
    let (scan_rows, scan_plan) = run(query, &IndexCatalog::empty(), &mut graph);
    let scan_plan = scan_plan.expect("a plan");

    // The results are IDENTICAL — which is exactly why the plan is the only way to catch this.
    assert_eq!(seek_rows, 1);
    assert_eq!(scan_rows, 1);

    // The operator type tells them apart…
    assert!(seek_plan.contains_operator("NodeIndexSeek"));
    assert!(!seek_plan.contains_operator("NodeLabelScanEq"));
    assert!(scan_plan.contains_operator("NodeLabelScanEq"));
    assert!(!scan_plan.contains_operator("NodeIndexSeek"));

    // The measured cost is EQUAL here, and that is itself a true and useful report: `MemGraph` has no
    // index structure, so it *declines* the seek and the executor falls back to a scan — the plan says
    // `NodeIndexSeek`, the storage really scanned, and `dbHits` says so. `dbHits` reports what the SEAM
    // did, never what the plan hoped for. The seek's real storage saving is proven against the store-backed
    // seam, which has a real index, in `profile_db_hits_prove_the_index_seek_reads_less_of_the_store`.
    assert_eq!(total_db_hits(&seek_plan), total_db_hits(&scan_plan));
    assert!(
        total_db_hits(&scan_plan) >= 200,
        "the fused scan+filter reports the records it EXAMINED (200 nodes), not just the 1 it matched"
    );
}

/// Sums the measured `dbHits` of every operator of a profiled plan.
fn total_db_hits(p: &PlanDescription) -> u64 {
    fn walk(n: &graphus_cypher::plan_description::PlanNode) -> u64 {
        n.db_hits.unwrap_or(0) + n.children.iter().map(walk).sum::<u64>()
    }
    walk(p.root())
}

#[test]
fn a_relationship_range_seek_is_distinguishable_from_a_relationship_scan() {
    // The shape `rmp` #746 must assert on: a rel-property RANGE predicate served by the rel index
    // (`RelIndexRangeSeek`) versus the scan it degrades to when the index is absent.
    let build = || {
        let mut g = MemGraph::new();
        let a = g.add_node(["Person"], [("id", Value::Integer(0))]);
        let b = g.add_node(["Person"], [("id", Value::Integer(1))]);
        for day in 1..=40 {
            g.add_rel("LIKE", a, b, [("date", Value::Integer(day))]);
        }
        g
    };
    let query = "PROFILE MATCH ()-[r:LIKE]->() WHERE r.date >= 38 RETURN r.date AS d";

    let catalog = IndexCatalog::builder()
        .with_rel_property("LIKE", "date")
        .build();
    let mut g = build();
    let (rows, seek) = run(query, &catalog, &mut g);
    let seek = seek.expect("a plan");

    let mut g = build();
    let (scan_rows, scan) = run(query, &IndexCatalog::empty(), &mut g);
    let scan = scan.expect("a plan");

    assert_eq!(rows, 3, "dates 38, 39, 40");
    assert_eq!(scan_rows, 3, "the scan path returns exactly the same rows");
    assert!(
        seek.contains_operator("RelIndexRangeSeek"),
        "the declared rel RANGE index must be used, got {:?}",
        seek.root()
    );
    assert!(
        !scan.contains_operator("RelIndexRangeSeek"),
        "with no index the query falls back to a scan — the regression an example must catch"
    );
    // The scan fallback is the whole `Filter` over `ExpandAll` over `AllNodesScan` subtree the rel seek
    // replaces (see `PhysicalOp::RelIndexRangeSeek`): visibly different, which is the point.
    assert!(scan.contains_operator("ExpandAll"));
    assert!(scan.contains_operator("AllNodesScan"));
}

// =================================================================================================
// 4. EXPLAIN / PROFILE are not reserved words (TCK conformance)
// =================================================================================================

#[test]
fn explain_and_profile_remain_ordinary_identifiers() {
    let mut graph = MemGraph::new();
    graph.add_node(["Profile"], [("explain", Value::Integer(7))]);

    for (src, expected_rows) in [
        // As an alias.
        ("RETURN 1 AS explain", 1),
        ("RETURN 1 AS profile", 1),
        // As a variable.
        ("WITH 2 AS explain RETURN explain", 1),
        ("UNWIND [1, 2] AS profile RETURN profile", 2),
        // As a label and a property key.
        ("MATCH (n:Profile) RETURN n.explain AS x", 1),
        // As a bound variable in a pattern.
        ("MATCH (explain:Profile) RETURN explain.explain AS x", 1),
    ] {
        let (rows, plan) = run(src, &IndexCatalog::empty(), &mut graph);
        assert_eq!(rows, expected_rows, "`{src}` must still run unchanged");
        assert!(
            plan.is_none(),
            "`{src}` carries no query prefix — `explain`/`profile` here are identifiers"
        );
    }
}

#[test]
fn the_prefix_is_recognised_only_as_the_first_token() {
    let src = "EXPLAIN MATCH (n) RETURN n";
    let toks = tokenize(src).expect("lex");
    let ast = parse_tokens(&toks, src).expect("parse");
    assert_eq!(ast.prefix(), Some(QueryPrefix::Explain));

    let src = "profile match (n) return n";
    let toks = tokenize(src).expect("lex");
    let ast = parse_tokens(&toks, src).expect("parse");
    assert_eq!(
        ast.prefix(),
        Some(QueryPrefix::Profile),
        "the prefix is case-insensitive, like every other Cypher keyword"
    );

    // A backtick-escaped identifier is never a keyword: `` `EXPLAIN` `` stays an identifier, so the
    // statement is the syntax error it always was rather than a silently-accepted prefix.
    let src = "`EXPLAIN` MATCH (n) RETURN n";
    let toks = tokenize(src).expect("lex");
    assert!(parse_tokens(&toks, src).is_err());

    // A prefix on its own is not a statement.
    for src in ["EXPLAIN", "PROFILE"] {
        let toks = tokenize(src).expect("lex");
        assert!(parse_tokens(&toks, src).is_err(), "`{src}` is not a query");
    }

    // Only one prefix may be present.
    let src = "EXPLAIN PROFILE MATCH (n) RETURN n";
    let toks = tokenize(src).expect("lex");
    assert!(
        parse_tokens(&toks, src).is_err(),
        "EXPLAIN and PROFILE cannot be combined (Neo4j: conflicting options)"
    );

    // …and it binds the WHOLE statement, ahead of a `USE` selector.
    let src = "EXPLAIN USE neo4j MATCH (n) RETURN n";
    let toks = tokenize(src).expect("lex");
    let ast = parse_tokens(&toks, src).expect("parse");
    assert_eq!(ast.prefix(), Some(QueryPrefix::Explain));
    assert!(ast.use_graph().is_some());
}

// =================================================================================================
// The plan description's own shape (the wire contract)
// =================================================================================================

#[test]
fn the_plan_carries_the_operator_tree_with_details_and_identifiers() {
    let plan = compile(
        "EXPLAIN MATCH (n:Person) WHERE n.name STARTS WITH 'p' RETURN n.name AS name",
        &IndexCatalog::empty(),
    );
    let desc = PlanDescription::explain(&plan);

    let root = desc.root();
    assert_eq!(root.operator_type, "Projection");
    assert_eq!(root.identifiers, ["name"]);
    // The root carries the planner's real estimate + the planner/runtime it actually used.
    let arg = |k: &str| {
        root.args
            .iter()
            .find(|(n, _)| n == k)
            .map(|(_, v)| v.clone())
    };
    assert!(matches!(arg("EstimatedRows"), Some(Value::Float(_))));
    assert_eq!(arg("planner"), Some(Value::String("RULE".to_owned())));
    assert_eq!(arg("runtime"), Some(Value::String("VOLCANO".to_owned())));

    let filter = &root.children[0];
    assert_eq!(filter.operator_type, "Filter");
    assert_eq!(filter.children[0].operator_type, "NodeByLabelScan");
    assert!(
        filter.children[0].children.is_empty(),
        "a leaf has no child"
    );

    // Every operator's `Details` is its own rendering — never a second, drifting description.
    for node in [root, filter, &filter.children[0]] {
        let details = node
            .args
            .iter()
            .find(|(k, _)| k == "Details")
            .map(|(_, v)| v.clone());
        let Some(Value::String(d)) = details else {
            panic!("{} carries no Details", node.operator_type);
        };
        assert!(
            d.starts_with(node.operator_type),
            "Details must render the operator: {d}"
        );
    }
}

#[test]
fn profiling_does_not_change_the_result() {
    // The PROFILE prefix must be observationally neutral: same rows, same order, same side effects.
    let query = "MATCH (n:Person) RETURN n.name AS name ORDER BY name";
    let mut plain_graph = people(20);
    let mut profiled_graph = people(20);

    let plan = compile(query, &indexed());
    let params = bind_parameters(&plan, &Parameters::new()).expect("bind");
    let plain: Vec<Value> = execute(&plan, &params, &mut plain_graph)
        .expect("open")
        .collect_all()
        .expect("drain")
        .iter()
        .map(|r| r.value("name"))
        .collect();

    let plan = compile(&format!("PROFILE {query}"), &indexed());
    let params = bind_parameters(&plan, &Parameters::new()).expect("bind");
    let profiled: Vec<Value> = execute(&plan, &params, &mut profiled_graph)
        .expect("open")
        .collect_all()
        .expect("drain")
        .iter()
        .map(|r| r.value("name"))
        .collect();

    assert_eq!(plain, profiled);
    assert_eq!(plain.len(), 20);
}

#[test]
fn a_nested_loop_join_template_accumulates_into_one_counter_per_rebuild() {
    // The right branch of a nested-loop join is rebuilt per left row from a CLONE of the plan subtree.
    // Its operators must still be attributed to the plan's own operators — otherwise a correlated
    // subquery's work would be invisible (an under-count, which is a lie).
    let mut graph = MemGraph::new();
    for i in 0..3 {
        graph.add_node(["Person"], [("name", Value::String(format!("p{i}")))]);
    }
    let (rows, plan) = run(
        "PROFILE UNWIND ['p0', 'p1'] AS want MATCH (n:Person {name: want}) RETURN n.name AS name",
        &indexed(),
        &mut graph,
    );
    assert_eq!(rows, 2);
    let plan = plan.expect("a plan");

    // The seek in the join's right branch ran twice (once per driving row) and both runs landed on the
    // SAME operator: two rows, and a non-zero measured cost.
    fn find<'p>(
        n: &'p graphus_cypher::plan_description::PlanNode,
        want: &str,
    ) -> Option<&'p graphus_cypher::plan_description::PlanNode> {
        if n.operator_type == want {
            return Some(n);
        }
        n.children.iter().find_map(|c| find(c, want))
    }
    let seek = find(plan.root(), "NodeIndexSeek").expect("the correlated seek is in the plan");
    assert_eq!(
        seek.rows,
        Some(2),
        "one row per rebuild, accumulated into one counter"
    );
    assert!(seek.db_hits.unwrap_or(0) >= 2);
}

// =================================================================================================
// The store-backed seam: an index seek really reads less of the store than the scan it replaces
// =================================================================================================

/// The MemGraph seam has no index structure, so it declines every seek and the executor falls back to a
/// scan. This test therefore runs the same comparison against the **real store** seam
/// ([`TxnCoordinator`] over a [`RecordStore`], with the derived index the coordinator maintains), where
/// the seek is genuinely served — so the `dbHits` a client reads back are the storage engine's real work,
/// and the seek's advantage is measured, not assumed.
#[test]
fn profile_db_hits_prove_the_index_seek_reads_less_of_the_store() {
    use graphus_cypher::coordinator::TxnCoordinator;
    use graphus_io::MemBlockDevice;
    use graphus_storage::RecordStore;
    use graphus_wal::{MemLogSink, WalManager};

    let device = MemBlockDevice::new(0);
    let wal = WalManager::create(MemLogSink::new()).expect("wal");
    let store = RecordStore::create(device, wal, 64, 1).expect("store");
    let mut coord = TxnCoordinator::new(store);

    // Seed 200 :Person nodes.
    let seed = "UNWIND range(0, 199) AS i CREATE (:Person {name: 'p' + toString(i)})";
    let plan = compile(seed, &IndexCatalog::empty());
    let params = bind_parameters(&plan, &Parameters::new()).expect("bind");
    let txn = coord.begin_serializable();
    {
        let mut graph = coord.statement(txn).expect("statement");
        execute(&plan, &params, &mut graph)
            .expect("open")
            .collect_all()
            .expect("drain");
    }
    coord.commit(txn).expect("commit");

    // Declare the index the planner will use, and let it build.
    coord
        .create_node_property_index("Person", "name")
        .expect("index");

    let query = "PROFILE MATCH (n:Person {name: 'p7'}) RETURN n.name AS name";
    let run_it = |coord: &mut TxnCoordinator<MemBlockDevice, MemLogSink>,
                  catalog: &IndexCatalog| {
        let plan = compile(query, catalog);
        let params = bind_parameters(&plan, &Parameters::new()).expect("bind");
        let txn = coord.begin_serializable();
        let (rows, description) = {
            let mut graph = coord.statement(txn).expect("statement");
            let mut cursor = execute(&plan, &params, &mut graph).expect("open");
            let rows = cursor.collect_all().expect("drain").len();
            let description = PlanDescription::profile(cursor.profile().expect("recorder"));
            (rows, description)
        };
        coord.commit(txn).expect("commit");
        (rows, description)
    };

    // The index-aware plan, served by the coordinator's real index.
    let catalog = coord.catalog();
    let (seek_rows, seek) = run_it(&mut coord, &catalog);
    // The same query planned with no index: the fused scan+filter over the whole store.
    let (scan_rows, scan) = run_it(&mut coord, &IndexCatalog::empty());

    assert_eq!(seek_rows, 1, "the seek finds the one matching person");
    assert_eq!(scan_rows, 1, "the scan finds exactly the same row");
    assert!(seek.contains_operator("NodeIndexSeek"));
    assert!(scan.contains_operator("NodeLabelScanEq"));

    let seek_hits = total_db_hits(&seek);
    let scan_hits = total_db_hits(&scan);
    assert!(
        scan_hits >= 200,
        "the scan read the whole store ({scan_hits} records over 200 nodes)"
    );
    assert!(
        seek_hits * 4 < scan_hits,
        "the index seek must read a fraction of what the scan reads: seek={seek_hits} scan={scan_hits}"
    );
}
