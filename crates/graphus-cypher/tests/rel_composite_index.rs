//! Composite (multi-property) relationship index end-to-end (`rmp` task #666): the durable catalog +
//! synchronous online build, per-write maintenance, the planner's full-key composite relationship seek,
//! execution parity against the typed-scan+filter fallback (including undirected + self-loop
//! semantics), and crash recovery.
//!
//! The relationship analogue of `tests/composite_index.rs`. The **execution parity** tests are the
//! black-box witness that the composite relationship seek returns exactly the scan+filter row multiset:
//! `read_triples(..)` runs the SAME read query twice — once compiled against the coordinator's catalog
//! (the `RelCompositeIndexSeek` path) and once against the empty catalog (the typed-scan + filter path)
//! — and asserts the `(id(a), id(r), id(b))` triples are identical (capturing relationship identity AND
//! endpoint orientation, so an undirected pattern's two orientations and a self-loop are distinguished).

use graphus_core::Value;
use graphus_cypher::binding::{Parameters, bind_parameters};
use graphus_cypher::catalog::IndexCatalog;
use graphus_cypher::coordinator::TxnCoordinator;
use graphus_cypher::executor::execute;
use graphus_cypher::lexer::tokenize;
use graphus_cypher::lower::lower;
use graphus_cypher::parser::parse_tokens;
use graphus_cypher::physical::{PhysicalPlan, plan_physical};
use graphus_cypher::runtime::Row;
use graphus_cypher::semantics::analyze;
use graphus_io::MemBlockDevice;
use graphus_storage::recovery::recover_device;
use graphus_storage::{IndexState, RecordStore};
use graphus_wal::{LogSink, MemLogSink, WalManager};

type Store = RecordStore<MemBlockDevice, MemLogSink>;
type Coord = TxnCoordinator<MemBlockDevice, MemLogSink>;

// =================================================================================================
// Harness
// =================================================================================================

fn fresh_store() -> Store {
    let device = MemBlockDevice::new(0);
    let wal = WalManager::create(MemLogSink::new()).expect("create wal");
    RecordStore::create(device, wal, 64, 1).expect("create store")
}

fn fresh_coord() -> Coord {
    TxnCoordinator::new(fresh_store())
}

fn compile_with(src: &str, catalog: &IndexCatalog) -> PhysicalPlan {
    let toks = tokenize(src).expect("lex");
    let ast = parse_tokens(&toks, src).expect("parse");
    let validated = analyze(&ast).expect("analyze");
    plan_physical(&lower(&validated), catalog)
}

/// Runs a write statement and **commits** it, asserting it succeeded with no captured error.
fn run_write(coord: &mut Coord, src: &str) {
    let plan = compile_with(src, &IndexCatalog::empty());
    let txn = coord.begin_serializable();
    let bound = bind_parameters(&plan, &Parameters::new()).expect("bind");
    let captured = {
        let mut graph = coord.statement(txn).expect("statement");
        let _rows: Vec<Row> = {
            let mut cursor = execute(&plan, &bound, &mut graph).expect("open cursor");
            cursor.collect_all().expect("collect")
        };
        graph.take_error()
    };
    assert!(
        captured.is_none(),
        "write {src:?} must succeed: {captured:?}"
    );
    coord.commit(txn).expect("write commits");
}

fn as_int(v: &Value) -> i64 {
    match v {
        Value::Integer(i) => *i,
        other => panic!("expected an integer, got {other:?}"),
    }
}

/// Runs the read `src` (which must `RETURN id(a) AS a, id(r) AS rr, id(b) AS b`) compiled against
/// `catalog`, returning the sorted `(a, rr, b)` triples. Passing the coordinator's catalog exercises the
/// composite relationship seek; the empty catalog exercises the typed-scan + filter fallback.
fn read_triples(coord: &mut Coord, src: &str, catalog: &IndexCatalog) -> Vec<(i64, i64, i64)> {
    let plan = compile_with(src, catalog);
    let txn = coord.begin_serializable();
    let bound = bind_parameters(&plan, &Parameters::new()).expect("bind");
    let rows = {
        let mut graph = coord.statement(txn).expect("statement");
        let mut cursor = execute(&plan, &bound, &mut graph).expect("open cursor");
        cursor.collect_all().expect("collect")
    };
    coord.commit(txn).expect("read commits");
    let mut out: Vec<(i64, i64, i64)> = rows
        .iter()
        .map(|r| {
            (
                as_int(&r.value("a")),
                as_int(&r.value("rr")),
                as_int(&r.value("b")),
            )
        })
        .collect();
    out.sort_unstable();
    out
}

/// Asserts the composite-seek plan (compiled against `coord.catalog()`) uses the composite relationship
/// seek and returns the **identical** triple set as the empty-catalog typed-scan + filter plan.
fn assert_seek_matches_scan(coord: &mut Coord, src: &str) -> Vec<(i64, i64, i64)> {
    let catalog = coord.catalog();
    let plan = compile_with(src, &catalog);
    assert!(
        plan.to_string().contains("RelCompositeIndexSeek"),
        "expected a composite relationship seek for {src:?}, got:\n{plan}"
    );
    let seek = read_triples(coord, src, &catalog);
    let scan = read_triples(coord, src, &IndexCatalog::empty());
    assert_eq!(
        seek, scan,
        "composite relationship seek rows must equal scan+filter rows for {src:?}"
    );
    seek
}

/// Deterministically reopens `store` from its durable WAL prefix (the `rmp` #90/#657 recovery probe).
fn recover_no_force(store: &Store) -> Store {
    let log = store.with_wal(|w| w.sink().durable_bytes().to_vec());
    let mut sink = MemLogSink::new();
    sink.append(&log);
    sink.sync().expect("sync log prefix");
    let mut device = MemBlockDevice::new(0);
    let mut wal = WalManager::open(sink.clone()).expect("open wal");
    recover_device(&mut wal, &mut device).expect("recover");
    let wal = WalManager::open(sink).expect("reopen wal");
    RecordStore::open(device, wal, 64).expect("open store")
}

/// Seeds five `:P` nodes and a set of `:KNOWS` relationships with `(a, b)` tuples exercising duplicate
/// tuples, distinct values, a self-loop, an incomplete tuple and a wrong-type edge.
fn seed_graph(coord: &mut Coord) {
    run_write(
        coord,
        "CREATE (:P {n: 1}), (:P {n: 2}), (:P {n: 3}), (:P {n: 4}), (:P {n: 5})",
    );
    // (a=10, b=20) — three matching edges, one of them a duplicate tuple, one a self-loop.
    run_write(
        coord,
        "MATCH (x:P {n: 1}), (y:P {n: 2}) CREATE (x)-[:KNOWS {a: 10, b: 20}]->(y)",
    );
    run_write(
        coord,
        "MATCH (x:P {n: 2}), (y:P {n: 3}) CREATE (x)-[:KNOWS {a: 10, b: 20}]->(y)",
    );
    // Self-loop with the matching tuple: undirected must bind it exactly once.
    run_write(
        coord,
        "MATCH (x:P {n: 1}) CREATE (x)-[:KNOWS {a: 10, b: 20}]->(x)",
    );
    // Same leading key, different b — must NOT match (10, 20).
    run_write(
        coord,
        "MATCH (x:P {n: 1}), (y:P {n: 3}) CREATE (x)-[:KNOWS {a: 10, b: 30}]->(y)",
    );
    // Same b, different a — must NOT match (10, 20).
    run_write(
        coord,
        "MATCH (x:P {n: 4}), (y:P {n: 5}) CREATE (x)-[:KNOWS {a: 11, b: 20}]->(y)",
    );
    // Incomplete tuple (no b): never a match.
    run_write(
        coord,
        "MATCH (x:P {n: 2}), (y:P {n: 4}) CREATE (x)-[:KNOWS {a: 10}]->(y)",
    );
    // Wrong-type edge with the matching tuple: never a match.
    run_write(
        coord,
        "MATCH (x:P {n: 3}), (y:P {n: 5}) CREATE (x)-[:LIKES {a: 10, b: 20}]->(y)",
    );
}

// =================================================================================================
// Tests
// =================================================================================================

#[test]
fn rel_composite_index_is_durable_listed_idempotent_and_survives_reopen() {
    let mut coord = fresh_coord();
    seed_graph(&mut coord);

    let created = coord
        .begin_online_rel_composite_index_named(
            None,
            "KNOWS",
            &["a".to_owned(), "b".to_owned()],
            false,
        )
        .expect("create composite relationship index");
    assert!(created, "a fresh create mutates");

    // SHOW INDEXES surface: properties is the multi-element tuple, state Online, deterministic name.
    let listed = coord.list_rel_composite_indexes();
    assert_eq!(
        listed,
        vec![(
            "rel_index_KNOWS_a_b".to_owned(),
            "KNOWS".to_owned(),
            vec!["a".to_owned(), "b".to_owned()],
            IndexState::Online
        )],
        "the composite relationship index is Online, named and carries the ordered tuple"
    );

    // IF NOT EXISTS equivalence: a re-declare of the SAME ordered tuple errors without the flag...
    let err = coord
        .begin_online_rel_composite_index_named(
            None,
            "KNOWS",
            &["a".to_owned(), "b".to_owned()],
            false,
        )
        .expect_err("an equivalent composite without IF NOT EXISTS errors");
    assert!(err.to_string().contains("equivalent index"), "{err:?}");
    // ...and is an idempotent no-op with it.
    assert!(
        !coord
            .begin_online_rel_composite_index_named(
                None,
                "KNOWS",
                &["a".to_owned(), "b".to_owned()],
                true,
            )
            .expect("IF NOT EXISTS is a clean no-op"),
        "IF NOT EXISTS on an existing composite does not mutate"
    );
    // Order is significant: (b, a) is a DIFFERENT schema rule and is created.
    assert!(
        coord
            .begin_online_rel_composite_index_named(
                None,
                "KNOWS",
                &["b".to_owned(), "a".to_owned()],
                false,
            )
            .expect("the reversed tuple is a distinct composite"),
        "(b, a) is not equivalent to (a, b)"
    );

    // A name collision with an existing index errors without IF NOT EXISTS.
    let err = coord
        .begin_online_rel_composite_index_named(
            Some("rel_index_KNOWS_a_b"),
            "KNOWS",
            &["a".to_owned(), "c".to_owned()],
            false,
        )
        .expect_err("a name collision errors");
    assert!(
        err.to_string().contains("index or constraint named"),
        "{err:?}"
    );

    // Crash + reopen: the durable catalog reload re-registers and repopulates the composites.
    let store = coord.into_store();
    assert_eq!(
        store.rel_composite_indexes().len(),
        2,
        "both composite relationship registrations survive the reopen (durable catalog)"
    );
    let reopened = recover_no_force(&store);
    let coord2 = TxnCoordinator::new(reopened);
    let mut listed2 = coord2.list_rel_composite_indexes();
    listed2.sort();
    assert_eq!(listed2.len(), 2, "both composites are fully recovered");
    assert!(
        listed2
            .iter()
            .all(|(_, ty, _, state)| ty == "KNOWS" && *state == IndexState::Online),
        "recovered composites are Online relationship indexes: {listed2:?}"
    );
}

#[test]
fn rel_composite_seek_matches_scan_across_directions_and_self_loops() {
    let mut coord = fresh_coord();
    seed_graph(&mut coord);
    coord
        .begin_online_rel_composite_index_named(
            None,
            "KNOWS",
            &["a".to_owned(), "b".to_owned()],
            false,
        )
        .expect("create composite relationship index");

    // A directed, reverse-directed and undirected full-key equality all agree with the scan path (the
    // undirected pattern binds both endpoint orientations of a non-self edge and one row for a self-loop).
    for pattern in [
        "MATCH (a)-[r:KNOWS {a: 10, b: 20}]->(b) RETURN id(a) AS a, id(r) AS rr, id(b) AS b",
        "MATCH (a)<-[r:KNOWS {a: 10, b: 20}]-(b) RETURN id(a) AS a, id(r) AS rr, id(b) AS b",
        "MATCH (a)-[r:KNOWS {a: 10, b: 20}]-(b) RETURN id(a) AS a, id(r) AS rr, id(b) AS b",
        "MATCH (a)-[r:KNOWS]-(b) WHERE r.a = 10 AND r.b = 20 RETURN id(a) AS a, id(r) AS rr, id(b) AS b",
    ] {
        let rows = assert_seek_matches_scan(&mut coord, pattern);
        assert!(!rows.is_empty(), "{pattern} should match something");
    }

    // A tuple no relationship holds returns empty from both paths.
    assert!(
        assert_seek_matches_scan(
            &mut coord,
            "MATCH (a)-[r:KNOWS {a: 99, b: 99}]->(b) RETURN id(a) AS a, id(r) AS rr, id(b) AS b"
        )
        .is_empty()
    );

    // Cross-type value equality (`10` vs `10.0`) matches element-wise, exactly like the single-key seek.
    run_write(
        &mut coord,
        "MATCH (x:P {n: 4}), (y:P {n: 1}) CREATE (x)-[:KNOWS {a: 10.0, b: 20.0}]->(y)",
    );
    let float_match = assert_seek_matches_scan(
        &mut coord,
        "MATCH (a)-[r:KNOWS {a: 10, b: 20}]->(b) RETURN id(a) AS a, id(r) AS rr, id(b) AS b",
    );
    assert_eq!(
        float_match.len(),
        4,
        "three integer edges + the Cypher-equal float edge match (10, 20)"
    );
}

#[test]
fn rel_composite_seek_survives_reopen_and_still_seeks() {
    let store = {
        let mut coord = fresh_coord();
        seed_graph(&mut coord);
        coord
            .begin_online_rel_composite_index_named(
                None,
                "KNOWS",
                &["a".to_owned(), "b".to_owned()],
                false,
            )
            .expect("create composite relationship index");
        recover_no_force(&coord.into_store())
    };
    let mut coord = TxnCoordinator::new(store);

    // The rebuilt backing tree still serves the seek correctly (parity with scan)...
    let before = assert_seek_matches_scan(
        &mut coord,
        "MATCH (a)-[r:KNOWS {a: 10, b: 20}]->(b) RETURN id(a) AS a, id(r) AS rr, id(b) AS b",
    );
    // ...and a write made AFTER recovery is maintained in the index (the new edge becomes seekable).
    run_write(
        &mut coord,
        "MATCH (x:P {n: 3}), (y:P {n: 4}) CREATE (x)-[:KNOWS {a: 10, b: 20}]->(y)",
    );
    let after = assert_seek_matches_scan(
        &mut coord,
        "MATCH (a)-[r:KNOWS {a: 10, b: 20}]->(b) RETURN id(a) AS a, id(r) AS rr, id(b) AS b",
    );
    assert_eq!(
        after.len(),
        before.len() + 1,
        "a post-recovery write is maintained in the composite relationship index"
    );
}

#[test]
fn drop_rel_composite_by_name_and_by_target_are_idempotent() {
    let mut coord = fresh_coord();
    seed_graph(&mut coord);
    coord
        .begin_online_rel_composite_index_named(
            Some("ix_ab"),
            "KNOWS",
            &["a".to_owned(), "b".to_owned()],
            false,
        )
        .expect("create");

    // Drop by name (the globally-unique-name resolver dispatches to the composite relationship catalog).
    assert!(
        coord
            .drop_property_index_by_name("ix_ab", false)
            .expect("drop by name"),
        "an existing composite relationship index is removed by name"
    );
    assert!(coord.list_rel_composite_indexes().is_empty());
    // A second by-name drop with IF EXISTS is a clean no-op.
    assert!(
        !coord
            .drop_property_index_by_name("ix_ab", true)
            .expect("IF EXISTS no-op")
    );

    // Recreate, then drop by target (the ordered tuple).
    coord
        .begin_online_rel_composite_index_named(
            None,
            "KNOWS",
            &["a".to_owned(), "b".to_owned()],
            false,
        )
        .expect("recreate");
    assert!(
        coord
            .drop_rel_composite_index("KNOWS", &["a".to_owned(), "b".to_owned()])
            .expect("drop by target"),
        "an existing composite relationship index is removed by target"
    );
    assert!(coord.list_rel_composite_indexes().is_empty());
    // A by-target drop of a missing composite is a clean no-op.
    assert!(
        !coord
            .drop_rel_composite_index("KNOWS", &["a".to_owned(), "b".to_owned()])
            .expect("missing target no-op")
    );
}
