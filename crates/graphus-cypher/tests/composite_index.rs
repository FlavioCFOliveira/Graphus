//! Composite (multi-property) node index end-to-end (`rmp` task #657): DDL
//! (`CREATE INDEX FOR (n:L) ON (n.a, n.b)`), the durable catalog + synchronous online build, per-write
//! maintenance, the planner's full-key composite seek, execution parity against the scan fallback, and
//! crash recovery.
//!
//! The harness mirrors `tests/rel_property_index.rs`: a `TxnCoordinator` over an in-memory store with a
//! `run_write` commit probe and the `recover_no_force` deterministic reopen. The **execution parity**
//! tests are the black-box witness that the composite index seek returns exactly the scan+filter set —
//! `read_ids(..)` runs the SAME read query twice, once compiled against the coordinator's catalog (the
//! composite `NodeCompositeIndexSeek` path) and once against the empty catalog (the scan+filter path),
//! and asserts the id sets are identical.

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

/// Runs a read `src` (which must `RETURN n.id AS id`) compiled against `catalog`, returning the sorted
/// `id`s. Passing the coordinator's catalog exercises the composite seek; the empty catalog exercises
/// the scan+filter fallback — the two must agree.
fn read_ids(coord: &mut Coord, src: &str, catalog: &IndexCatalog) -> Vec<i64> {
    let plan = compile_with(src, catalog);
    let txn = coord.begin_serializable();
    let bound = bind_parameters(&plan, &Parameters::new()).expect("bind");
    let rows = {
        let mut graph = coord.statement(txn).expect("statement");
        let mut cursor = execute(&plan, &bound, &mut graph).expect("open cursor");
        cursor.collect_all().expect("collect")
    };
    coord.commit(txn).expect("read commits");
    let mut ids: Vec<i64> = rows
        .iter()
        .map(|r| match r.value("id") {
            Value::Integer(i) => i,
            other => panic!("expected an integer id, got {other:?}"),
        })
        .collect();
    ids.sort_unstable();
    ids
}

/// Asserts the composite-seek plan (compiled against `coord.catalog()`) and the scan+filter plan
/// (compiled against the empty catalog) return the **identical** id set for `src`, and returns it.
fn assert_seek_matches_scan(coord: &mut Coord, src: &str) -> Vec<i64> {
    let catalog = coord.catalog();
    // Sanity: the catalog plan actually uses the composite seek (else the parity check is vacuous).
    let plan = compile_with(src, &catalog);
    assert!(
        plan.to_string().contains("NodeCompositeIndexSeek"),
        "expected a composite seek for {src:?}, got:\n{plan}"
    );
    let seek_ids = read_ids(coord, src, &catalog);
    let scan_ids = read_ids(coord, src, &IndexCatalog::empty());
    assert_eq!(
        seek_ids, scan_ids,
        "composite seek rows must equal scan+filter rows for {src:?}"
    );
    seek_ids
}

/// Deterministically reopens `store` from its durable WAL prefix (the `rmp` #90/#99/#646 recovery probe).
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

/// Seeds five `Person` nodes with `(id, a, b)` tuples exercising duplicate leading keys, cross-type
/// equality and incomplete tuples.
fn seed_people(coord: &mut Coord) {
    run_write(coord, "CREATE (:Person {id: 1, a: 10, b: 20})");
    run_write(coord, "CREATE (:Person {id: 2, a: 10, b: 30})"); // same leading key, different b
    run_write(coord, "CREATE (:Person {id: 3, a: 11, b: 20})"); // same b, different a
    run_write(coord, "CREATE (:Person {id: 4, a: 10, b: 20})"); // an exact duplicate tuple of id 1
    run_write(coord, "CREATE (:Person {id: 5, a: 10})"); // incomplete tuple (no b): never a match
}

// =================================================================================================
// Tests
// =================================================================================================

#[test]
fn composite_index_is_durable_listed_idempotent_and_survives_reopen() {
    let mut coord = fresh_coord();
    seed_people(&mut coord);

    // Declare a composite index over the existing data; an auto-name is assigned.
    let created = coord
        .begin_online_node_composite_index_named(
            None,
            "Person",
            &["a".to_owned(), "b".to_owned()],
            false,
        )
        .expect("create composite index");
    assert!(created, "a fresh create mutates");

    // SHOW INDEXES surface: properties is the multi-element tuple, state Online, deterministic name.
    let listed = coord.list_composite_indexes();
    assert_eq!(
        listed,
        vec![(
            "index_Person_a_b".to_owned(),
            "Person".to_owned(),
            vec!["a".to_owned(), "b".to_owned()],
            IndexState::Online
        )],
        "the composite index is Online, named and carries the ordered tuple"
    );

    // IF NOT EXISTS equivalence: a re-declare of the SAME ordered tuple errors without the flag...
    let err = coord
        .begin_online_node_composite_index_named(
            None,
            "Person",
            &["a".to_owned(), "b".to_owned()],
            false,
        )
        .expect_err("an equivalent composite without IF NOT EXISTS errors");
    assert!(err.to_string().contains("equivalent index"), "{err:?}");
    // ...and is an idempotent no-op with it.
    assert!(
        !coord
            .begin_online_node_composite_index_named(
                None,
                "Person",
                &["a".to_owned(), "b".to_owned()],
                true,
            )
            .expect("IF NOT EXISTS is a clean no-op"),
        "IF NOT EXISTS on an existing composite does not mutate"
    );
    // Order is significant: (b, a) is a DIFFERENT schema rule and is created.
    assert!(
        coord
            .begin_online_node_composite_index_named(
                None,
                "Person",
                &["b".to_owned(), "a".to_owned()],
                false,
            )
            .expect("the reversed tuple is a distinct composite"),
        "(b, a) is not equivalent to (a, b)"
    );

    // A name collision with an existing index errors without IF NOT EXISTS.
    let err = coord
        .begin_online_node_composite_index_named(
            Some("index_Person_a_b"),
            "Person",
            &["a".to_owned(), "c".to_owned()],
            false,
        )
        .expect_err("a name collision errors");
    assert!(
        err.to_string().contains("index or constraint named"),
        "{err:?}"
    );

    // Crash + reopen: the durable catalog reload re-registers and repopulates the composite indexes.
    let store = coord.into_store();
    assert_eq!(
        store.composite_indexes().len(),
        2,
        "both composite registrations survive the reopen (durable catalog)"
    );
    let reopened = recover_no_force(&store);
    let coord2 = TxnCoordinator::new(reopened);
    let mut listed2 = coord2.list_composite_indexes();
    listed2.sort();
    assert_eq!(listed2.len(), 2, "both composites are fully recovered");
    assert!(
        listed2
            .iter()
            .all(|(_, label, _, state)| label == "Person" && *state == IndexState::Online),
        "recovered composites are Online node indexes: {listed2:?}"
    );
}

#[test]
fn composite_seek_matches_scan_and_filter() {
    let mut coord = fresh_coord();
    seed_people(&mut coord);
    coord
        .begin_online_node_composite_index_named(
            None,
            "Person",
            &["a".to_owned(), "b".to_owned()],
            false,
        )
        .expect("create composite index");

    // Full-key equality (inline map): ids 1 and 4 share (a=10, b=20); the seek must find exactly them.
    let ids = assert_seek_matches_scan(
        &mut coord,
        "MATCH (n:Person {a: 10, b: 20}) RETURN n.id AS id",
    );
    assert_eq!(ids, vec![1, 4]);

    // The WHERE spelling, in either conjunct order, agrees with the scan and yields the same set.
    assert_eq!(
        assert_seek_matches_scan(
            &mut coord,
            "MATCH (n:Person) WHERE n.a = 10 AND n.b = 20 RETURN n.id AS id"
        ),
        vec![1, 4]
    );
    assert_eq!(
        assert_seek_matches_scan(
            &mut coord,
            "MATCH (n:Person) WHERE n.b = 30 AND n.a = 10 RETURN n.id AS id"
        ),
        vec![2]
    );

    // A tuple no node holds returns empty from both paths.
    assert_eq!(
        assert_seek_matches_scan(
            &mut coord,
            "MATCH (n:Person {a: 99, b: 99}) RETURN n.id AS id"
        ),
        Vec::<i64>::new()
    );
}

#[test]
fn composite_seek_cross_type_equality_matches_scan() {
    // Cross-type value equality parity (`1` vs `1.0`), element-wise, exactly like the single-property
    // seek: `seek_composite_eq` compares by Cypher value equality.
    let mut coord = fresh_coord();
    run_write(&mut coord, "CREATE (:Person {id: 1, a: 1, b: 2})"); // integers
    run_write(&mut coord, "CREATE (:Person {id: 2, a: 1.0, b: 2.0})"); // floats, Cypher-equal
    run_write(&mut coord, "CREATE (:Person {id: 3, a: 1, b: 3})");
    coord
        .begin_online_node_composite_index_named(
            None,
            "Person",
            &["a".to_owned(), "b".to_owned()],
            false,
        )
        .expect("create composite index");

    // Seeking with integer literals must find BOTH the integer node and the Cypher-equal float node.
    let ids = assert_seek_matches_scan(
        &mut coord,
        "MATCH (n:Person {a: 1, b: 2}) RETURN n.id AS id",
    );
    assert_eq!(ids, vec![1, 2]);
}

#[test]
fn composite_seek_survives_reopen_and_still_seeks() {
    let store = {
        let mut coord = fresh_coord();
        seed_people(&mut coord);
        coord
            .begin_online_node_composite_index_named(
                None,
                "Person",
                &["a".to_owned(), "b".to_owned()],
                false,
            )
            .expect("create composite index");
        recover_no_force(&coord.into_store())
    };
    let mut coord = TxnCoordinator::new(store);

    // The rebuilt backing tree still serves the seek correctly (parity with scan), and a write made
    // AFTER recovery is maintained in the index (id 6 becomes seekable).
    assert_eq!(
        assert_seek_matches_scan(
            &mut coord,
            "MATCH (n:Person {a: 10, b: 20}) RETURN n.id AS id"
        ),
        vec![1, 4]
    );
    run_write(&mut coord, "CREATE (:Person {id: 6, a: 10, b: 20})");
    assert_eq!(
        assert_seek_matches_scan(
            &mut coord,
            "MATCH (n:Person {a: 10, b: 20}) RETURN n.id AS id"
        ),
        vec![1, 4, 6],
        "a post-recovery write is maintained in the composite index"
    );
}

#[test]
fn drop_composite_by_name_and_by_target_are_idempotent() {
    let mut coord = fresh_coord();
    seed_people(&mut coord);
    coord
        .begin_online_node_composite_index_named(
            Some("ix_ab"),
            "Person",
            &["a".to_owned(), "b".to_owned()],
            false,
        )
        .expect("create");

    // Drop by name (the globally-unique-name resolver dispatches to the composite catalog).
    assert!(
        coord
            .drop_property_index_by_name("ix_ab", false)
            .expect("drop by name"),
        "an existing composite index is removed by name"
    );
    assert!(coord.list_composite_indexes().is_empty());
    // A second by-name drop with IF EXISTS is a clean no-op.
    assert!(
        !coord
            .drop_property_index_by_name("ix_ab", true)
            .expect("IF EXISTS no-op")
    );

    // Recreate, then drop by target (the ordered tuple).
    coord
        .begin_online_node_composite_index_named(
            None,
            "Person",
            &["a".to_owned(), "b".to_owned()],
            false,
        )
        .expect("recreate");
    assert!(
        coord
            .drop_node_composite_index("Person", &["a".to_owned(), "b".to_owned()])
            .expect("drop by target"),
        "an existing composite index is removed by target"
    );
    assert!(coord.list_composite_indexes().is_empty());
    // A by-target drop of a missing composite is a clean no-op; the reversed tuple never matched.
    assert!(
        !coord
            .drop_node_composite_index("Person", &["a".to_owned(), "b".to_owned()])
            .expect("missing target no-op")
    );
}
