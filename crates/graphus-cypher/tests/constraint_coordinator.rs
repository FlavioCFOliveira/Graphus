//! Constraint subsystem over the **real** storage-backed `TxnCoordinator` (`rmp` task #99).
//!
//! Where the server-level `tests/constraints.rs` proves the end-to-end DDL + wire-error path over a
//! booted server, these tests prove the storage-backed engine lifecycle directly on the coordinator:
//! durable catalog registration, **creation-time validation** of existing data, **write-time
//! enforcement** of uniqueness and existence on `CREATE`/`SET`, and — the headline durability AC —
//! that a constraint survives a crash + reopen (the catalog is durable, a uniqueness constraint's
//! backing index is rebuilt from the recovered store) and **still enforces** afterwards. This is the
//! constraint analogue of `tests/spatial_coordinator.rs` / `tests/fulltext_coordinator.rs`.

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
use graphus_storage::{ConstraintTypeDescriptor, RecordStore};
use graphus_wal::{LogSink, MemLogSink, WalManager};

type Store = RecordStore<MemBlockDevice, MemLogSink>;
type Coord = TxnCoordinator<MemBlockDevice, MemLogSink>;

// =================================================================================================
// Harness (mirrors tests/spatial_coordinator.rs)
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
///
/// This is the constraint-enforcement probe: a constraint violation is captured on the statement
/// seam, so a violating write rolls the transaction back and returns the error here — exactly what
/// the server's `stream_rows` surfaces to the wire.
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

/// The number of `Person` nodes currently visible (a quick count for "nothing was created").
fn person_count(coord: &mut Coord) -> usize {
    let plan = compile("MATCH (n:Person) RETURN count(n) AS c");
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

/// Asserts an error is a constraint violation (its message carries the wire sentinel).
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
fn uniqueness_create_rejects_duplicate_and_allows_distinct() {
    let mut coord = fresh_coord();
    run_write(&mut coord, "CREATE (:Person {email: 'a@x.com', name: 'A'})");
    coord
        .create_constraint("uniq_email", "Person", "email", ConstraintKind::Unique)
        .expect("create uniqueness constraint over conforming data");

    // A duplicate email is rejected (and nothing is created).
    let err = try_write(&mut coord, "CREATE (:Person {email: 'a@x.com', name: 'B'})")
        .expect_err("duplicate email must be rejected");
    assert_constraint_violation(&err);
    assert_eq!(
        person_count(&mut coord),
        1,
        "the rejected CREATE created nothing"
    );

    // A distinct email succeeds.
    run_write(&mut coord, "CREATE (:Person {email: 'b@x.com', name: 'B'})");
    assert_eq!(person_count(&mut coord), 2);
}

#[test]
fn uniqueness_enforced_on_set() {
    let mut coord = fresh_coord();
    run_write(&mut coord, "CREATE (:Person {email: 'a@x.com'})");
    run_write(&mut coord, "CREATE (:Person {email: 'b@x.com'})");
    coord
        .create_constraint("uniq_email", "Person", "email", ConstraintKind::Unique)
        .expect("create constraint");

    // SET the second node's email to collide with the first → rejected.
    let err = try_write(
        &mut coord,
        "MATCH (n:Person {email: 'b@x.com'}) SET n.email = 'a@x.com'",
    )
    .expect_err("SET to a duplicate must be rejected");
    assert_constraint_violation(&err);

    // The original value is intact (the rejected SET rolled back).
    let plan = compile("MATCH (n:Person {email: 'b@x.com'}) RETURN count(n) AS c");
    let txn = coord.begin_serializable();
    let bound = bind_parameters(&plan, &Parameters::new()).expect("bind");
    let rows = {
        let mut graph = coord.statement(txn).expect("statement");
        let mut cursor = execute(&plan, &bound, &mut graph).expect("cursor");
        cursor.collect_all().expect("collect")
    };
    coord.commit(txn).expect("read commits");
    assert_eq!(rows[0].value("c"), Value::Integer(1), "b@x.com must remain");
}

#[test]
fn existence_create_rejects_missing_and_null() {
    let mut coord = fresh_coord();
    run_write(&mut coord, "CREATE (:Person {name: 'A'})");
    coord
        .create_constraint("name_exists", "Person", "name", ConstraintKind::Existence)
        .expect("create existence constraint over conforming data");

    // A CREATE that omits `name` is rejected.
    let err = try_write(&mut coord, "CREATE (:Person {email: 'x'})")
        .expect_err("missing required property must be rejected");
    assert_constraint_violation(&err);

    // A CREATE that sets `name` to null is rejected.
    let err = try_write(&mut coord, "CREATE (:Person {name: null})")
        .expect_err("null required property must be rejected");
    assert_constraint_violation(&err);

    // A SET that removes the required property (SET n.name = null) is rejected.
    let err = try_write(&mut coord, "MATCH (n:Person {name: 'A'}) SET n.name = null")
        .expect_err("removing a required property must be rejected");
    assert_constraint_violation(&err);

    // A conforming CREATE succeeds.
    run_write(&mut coord, "CREATE (:Person {name: 'B'})");
    assert_eq!(person_count(&mut coord), 2);
}

#[test]
fn create_uniqueness_over_existing_duplicate_fails_with_clear_report() {
    let mut coord = fresh_coord();
    run_write(&mut coord, "CREATE (:Person {email: 'a@x.com'})");
    run_write(&mut coord, "CREATE (:Person {email: 'a@x.com'})"); // a pre-existing duplicate

    let err = coord
        .create_constraint("uniq_email", "Person", "email", ConstraintKind::Unique)
        .expect_err("constraint creation over duplicate data must fail");
    assert_constraint_violation(&err);
    assert!(
        err.to_string().contains("email"),
        "the report names the offending property: {err}"
    );
    // The failed creation left no constraint declared.
    assert!(coord.list_constraints().is_empty());
    // The store still works: the duplicate data is intact (creation had no side effects).
    assert_eq!(person_count(&mut coord), 2);
}

#[test]
fn create_existence_over_missing_data_fails() {
    let mut coord = fresh_coord();
    run_write(&mut coord, "CREATE (:Person {name: 'A'})");
    run_write(&mut coord, "CREATE (:Person {email: 'x'})"); // no `name`

    let err = coord
        .create_constraint("name_exists", "Person", "name", ConstraintKind::Existence)
        .expect_err("existence constraint over data missing the property must fail");
    assert_constraint_violation(&err);
    assert!(coord.list_constraints().is_empty());
}

#[test]
fn list_constraints_reports_declared_constraints() {
    let mut coord = fresh_coord();
    coord
        .create_constraint("uniq_email", "Person", "email", ConstraintKind::Unique)
        .expect("create unique");
    coord
        .create_constraint("name_exists", "Person", "name", ConstraintKind::Existence)
        .expect("create existence");

    let mut listed = coord.list_constraints();
    listed.sort_by(|a, b| a.name.cmp(&b.name));
    assert_eq!(listed.len(), 2);
    assert_eq!(listed[0].name, "name_exists");
    assert_eq!(listed[0].label, "Person");
    assert_eq!(listed[0].properties, vec!["name".to_owned()]);
    assert_eq!(listed[0].kind, ConstraintKind::Existence);
    assert_eq!(listed[0].type_descriptor, None);
    assert_eq!(listed[1].name, "uniq_email");
    assert_eq!(listed[1].label, "Person");
    assert_eq!(listed[1].properties, vec!["email".to_owned()]);
    assert_eq!(listed[1].kind, ConstraintKind::Unique);
    assert_eq!(listed[1].type_descriptor, None);
}

#[test]
fn drop_constraint_removes_enforcement() {
    let mut coord = fresh_coord();
    run_write(&mut coord, "CREATE (:Person {email: 'a@x.com'})");
    coord
        .create_constraint("uniq_email", "Person", "email", ConstraintKind::Unique)
        .expect("create constraint");
    // Enforced: a duplicate is rejected.
    try_write(&mut coord, "CREATE (:Person {email: 'a@x.com'})").expect_err("enforced before drop");

    coord
        .drop_constraint("uniq_email")
        .expect("drop constraint");
    assert!(coord.list_constraints().is_empty());

    // After the drop the duplicate is allowed.
    run_write(&mut coord, "CREATE (:Person {email: 'a@x.com'})");
    assert_eq!(person_count(&mut coord), 2);

    // Dropping a never-declared constraint is an idempotent no-op success.
    coord.drop_constraint("never").expect("idempotent drop");
}

#[test]
fn constraints_survive_a_crash_and_still_enforce_after_reopen() {
    // Build a store with both kinds of constraint, "crash" (recover from the durable WAL prefix), and
    // reopen a fresh coordinator. The durable catalog is reloaded, a uniqueness constraint's backing
    // index is rebuilt from the recovered store, and BOTH constraints still enforce.
    let recovered = {
        let mut coord = fresh_coord();
        run_write(&mut coord, "CREATE (:Person {email: 'a@x.com', name: 'A'})");
        coord
            .create_constraint("uniq_email", "Person", "email", ConstraintKind::Unique)
            .expect("create unique");
        coord
            .create_constraint("name_exists", "Person", "name", ConstraintKind::Existence)
            .expect("create existence");
        let store = coord.into_store();
        recover_no_force(&store)
    };

    let mut coord = TxnCoordinator::new(recovered);

    // The constraints survived the crash.
    assert_eq!(coord.list_constraints().len(), 2);

    // Uniqueness still enforces against the recovered data (the duplicate must be rejected).
    let err = try_write(
        &mut coord,
        "CREATE (:Person {email: 'a@x.com', name: 'Dup'})",
    )
    .expect_err("uniqueness must still enforce after restart");
    assert_constraint_violation(&err);

    // Existence still enforces (a CREATE missing `name` is rejected).
    let err = try_write(&mut coord, "CREATE (:Person {email: 'z@x.com'})")
        .expect_err("existence must still enforce after restart");
    assert_constraint_violation(&err);

    // A fully-conforming CREATE still succeeds after restart.
    run_write(&mut coord, "CREATE (:Person {email: 'b@x.com', name: 'B'})");
    assert_eq!(person_count(&mut coord), 2);
}

// =================================================================================================
// NODE KEY (composite uniqueness + existence) — `rmp` task #100
// =================================================================================================

/// Declares a composite node key over `(Person.first, Person.last)`.
fn create_person_node_key(coord: &mut Coord, name: &str) {
    coord
        .create_constraint_general(
            name,
            "Person",
            &["first", "last"],
            ConstraintKind::NodeKey,
            None,
        )
        .expect("create node key over conforming data");
}

#[test]
fn node_key_rejects_missing_component_and_duplicate_tuple() {
    let mut coord = fresh_coord();
    run_write(
        &mut coord,
        "CREATE (:Person {first: 'Ada', last: 'Lovelace'})",
    );
    create_person_node_key(&mut coord, "person_key");

    // A CREATE missing one key component (existence half) is rejected.
    let err = try_write(&mut coord, "CREATE (:Person {first: 'Grace'})")
        .expect_err("missing key component must be rejected");
    assert_constraint_violation(&err);

    // A CREATE whose full tuple duplicates an existing one (uniqueness half) is rejected.
    let err = try_write(
        &mut coord,
        "CREATE (:Person {first: 'Ada', last: 'Lovelace'})",
    )
    .expect_err("duplicate composite tuple must be rejected");
    assert_constraint_violation(&err);
    assert_eq!(person_count(&mut coord), 1);

    // A tuple that differs in only one component is allowed (the key is composite).
    run_write(&mut coord, "CREATE (:Person {first: 'Ada', last: 'Byron'})");
    run_write(
        &mut coord,
        "CREATE (:Person {first: 'Grace', last: 'Hopper'})",
    );
    assert_eq!(person_count(&mut coord), 3);

    // A SET that makes a tuple collide is rejected.
    let err = try_write(
        &mut coord,
        "MATCH (p:Person {first: 'Grace', last: 'Hopper'}) SET p.first = 'Ada', p.last = 'Byron'",
    )
    .expect_err("SET to a duplicate tuple must be rejected");
    assert_constraint_violation(&err);
}

#[test]
fn node_key_creation_time_validation() {
    // Existing data with a duplicate composite tuple: the node key cannot be created.
    let mut coord = fresh_coord();
    run_write(
        &mut coord,
        "CREATE (:Person {first: 'Ada', last: 'Lovelace'})",
    );
    run_write(
        &mut coord,
        "CREATE (:Person {first: 'Ada', last: 'Lovelace'})",
    );
    let err = coord
        .create_constraint_general(
            "person_key",
            "Person",
            &["first", "last"],
            ConstraintKind::NodeKey,
            None,
        )
        .expect_err("node key over duplicate tuples must be rejected");
    assert_constraint_violation(&err);
    assert!(coord.list_constraints().is_empty());

    // Existing data missing a component: the node key cannot be created.
    let mut coord = fresh_coord();
    run_write(&mut coord, "CREATE (:Person {first: 'Grace'})");
    let err = coord
        .create_constraint_general(
            "person_key",
            "Person",
            &["first", "last"],
            ConstraintKind::NodeKey,
            None,
        )
        .expect_err("node key over data missing a component must be rejected");
    assert_constraint_violation(&err);
    assert!(coord.list_constraints().is_empty());

    // Conforming data: the node key is created and listed with its whole tuple.
    let mut coord = fresh_coord();
    run_write(
        &mut coord,
        "CREATE (:Person {first: 'Ada', last: 'Lovelace'})",
    );
    create_person_node_key(&mut coord, "person_key");
    let listed = coord.list_constraints();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].kind, ConstraintKind::NodeKey);
    assert_eq!(
        listed[0].properties,
        vec!["first".to_owned(), "last".to_owned()]
    );
}

#[test]
fn node_key_survives_a_crash_and_still_enforces() {
    let recovered = {
        let mut coord = fresh_coord();
        run_write(
            &mut coord,
            "CREATE (:Person {first: 'Ada', last: 'Lovelace'})",
        );
        create_person_node_key(&mut coord, "person_key");
        let store = coord.into_store();
        recover_no_force(&store)
    };
    let mut coord = TxnCoordinator::new(recovered);
    assert_eq!(coord.list_constraints().len(), 1);

    // The duplicate tuple must still be rejected (the backing composite index was rebuilt).
    let err = try_write(
        &mut coord,
        "CREATE (:Person {first: 'Ada', last: 'Lovelace'})",
    )
    .expect_err("node key must still enforce after restart");
    assert_constraint_violation(&err);

    // A missing component must still be rejected.
    let err = try_write(&mut coord, "CREATE (:Person {first: 'Solo'})")
        .expect_err("node-key existence must still enforce after restart");
    assert_constraint_violation(&err);

    // A distinct, complete tuple still succeeds.
    run_write(
        &mut coord,
        "CREATE (:Person {first: 'Grace', last: 'Hopper'})",
    );
    assert_eq!(person_count(&mut coord), 2);
}

// =================================================================================================
// PROPERTY TYPE — `rmp` task #100
// =================================================================================================

#[test]
fn property_type_rejects_wrong_type_and_allows_correct_or_absent() {
    let mut coord = fresh_coord();
    coord
        .create_constraint_general(
            "age_int",
            "Person",
            &["age"],
            ConstraintKind::PropertyType,
            Some(ConstraintTypeDescriptor::Integer),
        )
        .expect("create property-type constraint");

    // A STRING where INTEGER is required is rejected.
    let err = try_write(&mut coord, "CREATE (:Person {age: 'old'})")
        .expect_err("wrong type must be rejected");
    assert_constraint_violation(&err);

    // The correct type succeeds.
    run_write(&mut coord, "CREATE (:Person {age: 42})");
    // A node that omits the property entirely is allowed (property-type does not imply existence).
    run_write(&mut coord, "CREATE (:Person {name: 'No Age'})");
    assert_eq!(person_count(&mut coord), 2);

    // A SET that stores the wrong type is rejected.
    let err = try_write(&mut coord, "MATCH (p:Person {age: 42}) SET p.age = 'nope'")
        .expect_err("SET to wrong type must be rejected");
    assert_constraint_violation(&err);
}

#[test]
fn property_type_creation_time_validation_and_restart() {
    // Existing wrong-typed data: the constraint cannot be created.
    let recovered = {
        let mut coord = fresh_coord();
        run_write(&mut coord, "CREATE (:Person {score: 'high'})");
        let err = coord
            .create_constraint_general(
                "score_int",
                "Person",
                &["score"],
                ConstraintKind::PropertyType,
                Some(ConstraintTypeDescriptor::Integer),
            )
            .expect_err("property-type over wrong-typed data must be rejected");
        assert_constraint_violation(&err);
        assert!(coord.list_constraints().is_empty());

        // Now seed only conforming data and create the constraint, then crash + reopen.
        let mut coord = fresh_coord();
        run_write(&mut coord, "CREATE (:Person {score: 99})");
        coord
            .create_constraint_general(
                "score_int",
                "Person",
                &["score"],
                ConstraintKind::PropertyType,
                Some(ConstraintTypeDescriptor::Integer),
            )
            .expect("create over conforming data");
        let store = coord.into_store();
        recover_no_force(&store)
    };

    let mut coord = TxnCoordinator::new(recovered);
    assert_eq!(coord.list_constraints().len(), 1);
    assert_eq!(
        coord.list_constraints()[0].type_descriptor,
        Some(ConstraintTypeDescriptor::Integer)
    );

    // The type rule still enforces after the restart.
    let err = try_write(&mut coord, "CREATE (:Person {score: 'bad'})")
        .expect_err("property-type must still enforce after restart");
    assert_constraint_violation(&err);
    run_write(&mut coord, "CREATE (:Person {score: 7})");
}
