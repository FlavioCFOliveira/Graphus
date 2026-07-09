//! Relationship-property index end-to-end (`rmp` task #646): DDL (`CREATE INDEX FOR ()-[r:T]-() ON
//! (r.p)`), the durable catalog + online build, per-write maintenance, index-backed relationship
//! **uniqueness** enforcement (replacing the `rmp` #638 `O(rels-of-type)` scan), and crash recovery.
//!
//! The harness mirrors `tests/constraint_coordinator.rs`: a `TxnCoordinator` over an in-memory store
//! with the same `run_write` / `try_write` commit-or-capture probe and the `recover_no_force`
//! deterministic reopen. A relationship uniqueness constraint's *behaviour* (a duplicate is rejected,
//! a distinct value allowed) is the black-box witness that the index-backed enforcement path is
//! correct; `list_rel_property_indexes` witnesses the durable explicit-index catalog.

use graphus_core::{GraphusError, Value};
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
use graphus_cypher::{CONSTRAINT_VIOLATION_PREFIX, ConstraintKind};
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

fn compile(src: &str) -> PhysicalPlan {
    let toks = tokenize(src).expect("lex");
    let ast = parse_tokens(&toks, src).expect("parse");
    let validated = analyze(&ast).expect("analyze");
    plan_physical(&lower(&validated), &IndexCatalog::empty())
}

/// Runs a write statement and **commits** it, asserting it succeeded with no captured error.
fn run_write(coord: &mut Coord, src: &str) {
    try_write(coord, src).unwrap_or_else(|e| panic!("write {src:?} must succeed, got {e:?}"));
}

/// Runs a write statement, returning the captured runtime error (rolled back) or `Ok(())` (committed).
fn try_write(coord: &mut Coord, src: &str) -> Result<(), GraphusError> {
    let plan = compile(src);
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
    match captured {
        Some(e) => {
            coord.rollback(txn).expect("rollback after captured error");
            Err(e)
        }
        None => {
            coord.commit(txn).expect("write commits");
            Ok(())
        }
    }
}

/// The number of relationships of type `KNOWS` currently visible (a quick "nothing was created" gate).
fn knows_count(coord: &mut Coord) -> usize {
    let plan = compile("MATCH ()-[r:KNOWS]->() RETURN count(r) AS c");
    let txn = coord.begin_serializable();
    let bound = bind_parameters(&plan, &Parameters::new()).expect("bind");
    let rows = {
        let mut graph = coord.statement(txn).expect("statement");
        let mut cursor = execute(&plan, &bound, &mut graph).expect("open cursor");
        cursor.collect_all().expect("collect")
    };
    coord.commit(txn).expect("read commits");
    match rows[0].value("c") {
        Value::Integer(i) => i as usize,
        other => panic!("expected an integer count, got {other:?}"),
    }
}

/// Deterministically reopens `store` from its durable WAL prefix (the `rmp` #90/#99 recovery probe).
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

fn assert_constraint_violation(e: &GraphusError) {
    let msg = e.to_string();
    assert!(
        msg.contains(CONSTRAINT_VIOLATION_PREFIX),
        "expected a constraint-violation error, got: {msg}"
    );
}

// =================================================================================================
// Tests
// =================================================================================================

#[test]
fn explicit_rel_index_is_durable_and_listed_and_survives_reopen() {
    let mut coord = fresh_coord();
    // Seed a couple of typed relationships, then declare the index over the existing data.
    run_write(&mut coord, "CREATE (:P)-[:KNOWS {since: 2020}]->(:P)");
    run_write(&mut coord, "CREATE (:P)-[:KNOWS {since: 2021}]->(:P)");

    let created = coord
        .create_rel_property_index_named(Some("ix_since"), "KNOWS", "since", false)
        .expect("create rel-property index");
    assert!(created, "a fresh create mutates");

    let listed = coord.list_rel_property_indexes();
    assert_eq!(
        listed,
        vec![(
            "ix_since".to_owned(),
            "KNOWS".to_owned(),
            "since".to_owned(),
            IndexState::Online
        )],
        "the explicit rel index is Online and named"
    );

    // A duplicate declaration is the equivalent-schema error without IF NOT EXISTS...
    let err = coord
        .create_rel_property_index_named(None, "KNOWS", "since", false)
        .expect_err("an equivalent index without IF NOT EXISTS errors");
    assert!(err.to_string().contains("equivalent index"), "{err:?}");
    // ...and an idempotent no-op with it.
    assert!(
        !coord
            .create_rel_property_index_named(None, "KNOWS", "since", true)
            .expect("IF NOT EXISTS is a clean no-op"),
        "IF NOT EXISTS on an existing index does not mutate"
    );

    // Crash + reopen: the durable catalog reload re-registers and repopulates the index.
    let store = coord.into_store();
    let reopened = recover_no_force(&store);
    assert_eq!(
        reopened.rel_property_indexes().len(),
        1,
        "the rel index registration survives the reopen"
    );
    assert!(
        reopened.rel_property_index_name("ix_since").is_some(),
        "the durable name resolves after the reopen"
    );
    let coord2 = TxnCoordinator::new(reopened);
    assert_eq!(
        coord2.list_rel_property_indexes(),
        vec![(
            "ix_since".to_owned(),
            "KNOWS".to_owned(),
            "since".to_owned(),
            IndexState::Online
        )],
        "the rel index is fully recovered after reopen"
    );
}

#[test]
fn drop_rel_index_by_name_and_by_target_are_idempotent() {
    let mut coord = fresh_coord();
    run_write(&mut coord, "CREATE (:P)-[:RATED {stars: 5}]->(:P)");
    coord
        .create_rel_property_index_named(Some("ix_stars"), "RATED", "stars", false)
        .expect("create");

    // Drop by name (the globally-unique-name resolver dispatches to the rel catalog).
    assert!(
        coord
            .drop_property_index_by_name("ix_stars", false)
            .expect("drop by name"),
        "an existing rel index is removed by name"
    );
    assert!(coord.list_rel_property_indexes().is_empty());
    // A second by-name drop with IF EXISTS is a clean no-op.
    assert!(
        !coord
            .drop_property_index_by_name("ix_stars", true)
            .expect("IF EXISTS no-op")
    );

    // Recreate, then drop by target.
    coord
        .create_rel_property_index_named(None, "RATED", "stars", false)
        .expect("recreate");
    assert!(
        coord
            .drop_rel_property_index("RATED", "stars")
            .expect("drop by target"),
        "an existing rel index is removed by target"
    );
    assert!(coord.list_rel_property_indexes().is_empty());
    // A by-target drop of a missing index is a clean no-op.
    assert!(
        !coord
            .drop_rel_property_index("RATED", "stars")
            .expect("missing target no-op")
    );
}

#[test]
fn rel_uniqueness_is_enforced_index_backed_and_maintained_on_writes() {
    let mut coord = fresh_coord();
    // Conforming seed, then a relationship uniqueness constraint (registers an Online backing rel
    // index; enforcement seeks it instead of scanning every KNOWS relationship, `rmp` #646).
    run_write(&mut coord, "CREATE (:P)-[:KNOWS {since: 2020}]->(:P)");
    coord
        .create_constraint_general(
            "uniq_since",
            "KNOWS",
            &["since"],
            ConstraintKind::RelUnique,
            None,
        )
        .expect("create rel uniqueness constraint over conforming data");

    // A duplicate `since` is rejected (index-backed conflict find) and nothing is created.
    let err = try_write(&mut coord, "CREATE (:P)-[:KNOWS {since: 2020}]->(:P)")
        .expect_err("a duplicate rel property value must be rejected");
    assert_constraint_violation(&err);
    assert_eq!(
        knows_count(&mut coord),
        1,
        "the rejected CREATE created nothing"
    );

    // A distinct value succeeds and is itself maintained in the index (so it becomes a conflict target).
    run_write(&mut coord, "CREATE (:P)-[:KNOWS {since: 2021}]->(:P)");
    assert_eq!(knows_count(&mut coord), 2);
    let err = try_write(&mut coord, "CREATE (:P)-[:KNOWS {since: 2021}]->(:P)")
        .expect_err("the newly-created value is now a duplicate");
    assert_constraint_violation(&err);

    // A `SET` that changes a value to a free one is allowed; changing it to an existing one is not
    // (the `reindex_rel` maintenance keeps the new value seekable for the next check).
    run_write(&mut coord, "CREATE (:P)-[:KNOWS {since: 3000}]->(:P)");
    run_write(
        &mut coord,
        "MATCH ()-[r:KNOWS {since: 3000}]->() SET r.since = 4000",
    );
    let err = try_write(
        &mut coord,
        "MATCH ()-[r:KNOWS {since: 4000}]->() SET r.since = 2020",
    )
    .expect_err("setting a value onto an existing one violates uniqueness");
    assert_constraint_violation(&err);
}

#[test]
fn rel_uniqueness_survives_a_crash_and_still_enforces_after_reopen() {
    // The constraint catalog is durable; its backing rel-property index is ephemeral and re-registered
    // + repopulated from the recovered relationships on reopen (`rmp` #646). Enforcement must still
    // reject a duplicate after the crash — the index rebuild's candidate set is complete.
    let store = {
        let mut coord = fresh_coord();
        run_write(&mut coord, "CREATE (:P)-[:KNOWS {since: 2020}]->(:P)");
        run_write(&mut coord, "CREATE (:P)-[:KNOWS {since: 2021}]->(:P)");
        coord
            .create_constraint_general(
                "uniq_since",
                "KNOWS",
                &["since"],
                ConstraintKind::RelUnique,
                None,
            )
            .expect("create rel uniqueness constraint");
        recover_no_force(&coord.into_store())
    };
    let mut coord = TxnCoordinator::new(store);

    // A duplicate of a recovered value is still rejected (the backing index was rebuilt).
    let err = try_write(&mut coord, "CREATE (:P)-[:KNOWS {since: 2020}]->(:P)")
        .expect_err("a duplicate of a recovered value is rejected after reopen");
    assert_constraint_violation(&err);
    assert_eq!(
        knows_count(&mut coord),
        2,
        "no new relationship was created"
    );

    // A distinct value still succeeds after recovery.
    run_write(&mut coord, "CREATE (:P)-[:KNOWS {since: 2099}]->(:P)");
    assert_eq!(knows_count(&mut coord), 3);
}
