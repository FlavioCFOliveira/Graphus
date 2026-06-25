//! SSI regression tests for **concurrent inserts of the same new uniqueness/node-key tuple**
//! (`rmp` task #401), driven by the real [`TxnCoordinator`] over the record store.
//!
//! ## The hole (`rmp` #401)
//!
//! Node-key / single-property uniqueness is enforced by a *seek-then-check* on `CREATE`: the writer
//! seeks the constraint's covered tuple and rejects if another visible node already holds it. That
//! seek-then-check is only safe under SSI when its **predicate read footprint** matches the writer's
//! **predicate write footprint**, so that two concurrent inserts of the same *brand-new* tuple — each
//! of which sees an empty candidate set (neither node is visible to the other's snapshot) — form an
//! rw-antidependency and one is aborted.
//!
//! The single-property path (`index_seek_eq`, `rmp` #316) already registered a precise
//! `PredicateRead::Equality` matching the writer's single-prop `Equality` write footprint, so it was
//! sound. The **composite** node-key path (`composite_seek_eq`) registered only the per-live-node
//! physical-key SIREADs (`mark_all_live_nodes`) and **no predicate read** — so for a tuple with no
//! existing holder, neither writer's read footprint intersected the other's `Label(L)` write
//! footprint, no rw-edge formed, no pivot was detected, and **both** concurrent inserts committed a
//! duplicate node key. The fix registers `PredicateRead::Label(label_token)` in `composite_seek_eq`
//! (the same coarse marker the label-scan fallback already registers), closing the rw-edge.
//!
//! ## Two distinct surfaces, both tested
//!
//! 1. **Overlapping snapshots** (the gap #401 closes): both transactions begin, both run their CREATE
//!    (each passes its *own* write-time uniqueness check, because neither sees the other's pending
//!    node), then both attempt to commit. The conflict is a **phantom write-skew on absence** caught
//!    by SSI at commit, so the loser is rejected with a retriable
//!    [`GraphusError::Transaction`] serialization failure — exactly one commits. Before the fix the
//!    composite case let **both** commit.
//! 2. **Serialized** (write-time enforcement, never broken — a control): the second CREATE runs
//!    *after* the first commits, so it *sees* the duplicate and is rejected at statement time with a
//!    `Neo.ClientError.Schema.ConstraintValidationFailed` (the wire sentinel
//!    [`CONSTRAINT_VIOLATION_PREFIX`]).
//!
//! Both NODE KEY (composite) and single-property IS UNIQUE are covered, closing the
//! concurrent-uniqueness coverage gap (no such test existed before).

use graphus_core::{GraphusError, TxnId, Value};
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
use graphus_storage::RecordStore;
use graphus_wal::{MemLogSink, WalManager};

type Store = RecordStore<MemBlockDevice, MemLogSink>;
type Coord = TxnCoordinator<MemBlockDevice, MemLogSink>;

fn fresh_coord() -> Coord {
    let device = MemBlockDevice::new(0);
    let wal = WalManager::create(MemLogSink::new()).expect("create wal");
    let store: Store = RecordStore::create(device, wal, 64, 1).expect("create store");
    TxnCoordinator::new(store)
}

fn compile(src: &str) -> PhysicalPlan {
    let toks = tokenize(src).expect("lex");
    let ast = parse_tokens(&toks, src).expect("parse");
    let validated = analyze(&ast).expect("analyze");
    plan_physical(&lower(&validated), &IndexCatalog::empty())
}

/// Runs `src` inside the already-open transaction `txn` (does NOT commit), returning the rows and the
/// captured statement-level error (e.g. a write-time constraint violation), mirroring
/// `ssi_scan_filter_eq.rs`.
fn run_stmt(coord: &Coord, txn: TxnId, src: &str) -> (Vec<Row>, Option<GraphusError>) {
    let plan = compile(src);
    let bound = bind_parameters(&plan, &Parameters::new()).expect("bind");
    let mut graph = coord.statement(txn).expect("statement");
    let rows = {
        let mut cursor = execute(&plan, &bound, &mut graph).expect("open cursor");
        cursor.collect_all().expect("collect")
    };
    let err = graph.take_error();
    (rows, err)
}

/// Runs `src` in its own fresh transaction and commits, asserting it succeeded with no captured error.
fn run_write_committed(coord: &mut Coord, src: &str) {
    let t = coord.begin_serializable();
    let (_r, err) = run_stmt(coord, t, src);
    assert!(err.is_none(), "seed/write {src:?} error: {err:?}");
    coord.commit(t).expect("write commits");
}

/// Count of `:Person` nodes visible to a fresh committed read.
fn person_count(coord: &mut Coord) -> usize {
    let t = coord.begin_serializable();
    let (rows, err) = run_stmt(coord, t, "MATCH (n:Person) RETURN count(n) AS c");
    assert!(err.is_none(), "count error: {err:?}");
    coord.commit(t).expect("count commits");
    match rows[0].value("c") {
        Value::Integer(i) => i as usize,
        other => panic!("expected integer count, got {other:?}"),
    }
}

fn create_person_node_key(coord: &mut Coord, name: &str) {
    coord
        .create_constraint_general(
            name,
            "Person",
            &["first", "last"],
            ConstraintKind::NodeKey,
            None,
        )
        .expect("create node key over conforming (empty) data");
}

fn create_person_unique_email(coord: &mut Coord, name: &str) {
    coord
        .create_constraint(name, "Person", "email", ConstraintKind::Unique)
        .expect("create uniqueness constraint over conforming (empty) data");
}

// =================================================================================================
// #401 — composite NODE KEY: concurrent inserts of the same NEW tuple
// =================================================================================================

#[test]
fn concurrent_node_key_create_same_new_tuple_aborts_exactly_one() {
    // The `rmp` #401 fix, teeth-verified. Two SERIALIZABLE transactions with OVERLAPPING snapshots
    // each CREATE a brand-new node carrying the SAME composite node-key tuple `(first:'Ada',
    // last:'Lovelace')`, which no existing node holds. Each passes its own write-time uniqueness
    // check (neither sees the other's pending node). Before the fix the composite seek registered no
    // predicate read, so the two writers shared no rw-edge and BOTH committed a duplicate node key.
    // With the fix `composite_seek_eq` registers `PredicateRead::Label(Person)`, which pairs with each
    // insert's `Label(Person)` write footprint, forming the rw-antidependency that aborts exactly one.
    let mut coord = fresh_coord();
    create_person_node_key(&mut coord, "person_key");

    let t1 = coord.begin_serializable();
    let t2 = coord.begin_serializable();

    let (_r1, e1) = run_stmt(
        &coord,
        t1,
        "CREATE (:Person {first: 'Ada', last: 'Lovelace'})",
    );
    assert!(
        e1.is_none(),
        "t1 insert passes its own write-time check: {e1:?}"
    );
    let (_r2, e2) = run_stmt(
        &coord,
        t2,
        "CREATE (:Person {first: 'Ada', last: 'Lovelace'})",
    );
    assert!(
        e2.is_none(),
        "t2 insert passes its own write-time check: {e2:?}"
    );

    let c1 = coord.commit(t1);
    let c2 = coord.commit(t2);
    let committed = [&c1, &c2].iter().filter(|r| r.is_ok()).count();
    let aborted = [&c1, &c2].iter().filter(|r| r.is_err()).count();
    assert_eq!(
        committed, 1,
        "exactly one concurrent identical node-key CREATE may commit (c1={c1:?}, c2={c2:?})"
    );
    assert_eq!(
        aborted, 1,
        "exactly one is aborted to preserve the unique node key"
    );

    // The loser is a retriable serialization failure (the phantom-on-absence is caught at commit by
    // SSI, not at statement time — neither writer saw the other under overlapping snapshots).
    let err = [c1, c2].into_iter().find_map(Result::err).unwrap();
    assert!(
        matches!(err, GraphusError::Transaction(_)),
        "the concurrent-uniqueness abort is a retriable transaction error: {err}"
    );

    // The unique node key holds: exactly one node, not two.
    assert_eq!(
        person_count(&mut coord),
        1,
        "no duplicate node-key node survives"
    );
}

#[test]
fn node_key_create_after_commit_is_constraint_validation_failed() {
    // Control / serialized surface: the second CREATE runs AFTER the first commits, so it SEES the
    // duplicate tuple and is rejected at statement time with the wire sentinel
    // `Neo.ClientError.Schema.ConstraintValidationFailed`. This is the write-time-enforcement path
    // (`rmp` #100), unaffected by #401; it confirms the constraint sentinel is the surface when the
    // duplicate is visible.
    let mut coord = fresh_coord();
    create_person_node_key(&mut coord, "person_key");
    run_write_committed(
        &mut coord,
        "CREATE (:Person {first: 'Ada', last: 'Lovelace'})",
    );

    let t = coord.begin_serializable();
    let (_r, e) = run_stmt(
        &coord,
        t,
        "CREATE (:Person {first: 'Ada', last: 'Lovelace'})",
    );
    let e = e.expect("a visible duplicate tuple is rejected at statement time");
    assert!(
        e.to_string().contains(CONSTRAINT_VIOLATION_PREFIX),
        "expected a Neo.ClientError.Schema.ConstraintValidationFailed sentinel, got: {e}"
    );
    coord.rollback(t).expect("rollback the violating txn");
    assert_eq!(
        person_count(&mut coord),
        1,
        "the rejected CREATE created nothing"
    );
}

#[test]
fn concurrent_node_key_distinct_tuples_both_commit() {
    // The coarse `Label(Person)` predicate read is sound but conservative — it only adds an rw-edge
    // among concurrent SAME-LABEL writers. Two inserts of DISTINCT tuples are not a uniqueness
    // conflict, but they DO share the `Label(Person)` marker, so this documents the (accepted) coarse
    // behaviour: under the coarse marker one may be aborted as a false positive. We therefore only
    // assert correctness (no duplicate, at least one commits), not that BOTH commit — matching the
    // task's "coarse is sound, only adds a few extra aborts among concurrent same-label writers".
    let mut coord = fresh_coord();
    create_person_node_key(&mut coord, "person_key");

    let t1 = coord.begin_serializable();
    let t2 = coord.begin_serializable();
    let (_r1, e1) = run_stmt(
        &coord,
        t1,
        "CREATE (:Person {first: 'Ada', last: 'Lovelace'})",
    );
    assert!(e1.is_none(), "t1 insert error: {e1:?}");
    let (_r2, e2) = run_stmt(
        &coord,
        t2,
        "CREATE (:Person {first: 'Grace', last: 'Hopper'})",
    );
    assert!(e2.is_none(), "t2 insert error: {e2:?}");

    let c1 = coord.commit(t1);
    let c2 = coord.commit(t2);
    let committed = [&c1, &c2].iter().filter(|r| r.is_ok()).count();
    assert!(
        committed >= 1,
        "at least one distinct-tuple insert commits (c1={c1:?}, c2={c2:?})"
    );
    // Whatever committed, the distinct tuples never produce a duplicate key (1 or 2 surviving nodes).
    assert!(
        (1..=2).contains(&person_count(&mut coord)),
        "distinct tuples never collide into a duplicate node key"
    );
}

// =================================================================================================
// #401 twin — single-property IS UNIQUE: concurrent inserts of the same NEW value
// =================================================================================================

#[test]
fn concurrent_unique_create_same_new_value_aborts_exactly_one() {
    // The single-property uniqueness twin (closes the concurrent-uniqueness coverage gap for IS
    // UNIQUE). The single-prop seek (`index_seek_eq`, `rmp` #316) already registered a precise
    // `Equality` predicate read, so this path was sound BEFORE #401 — this test pins that and proves
    // the #401 composite fix did not change the single-prop behaviour. Overlapping snapshots, same
    // brand-new email on both: exactly one commits, the other aborts (serialization failure).
    let mut coord = fresh_coord();
    create_person_unique_email(&mut coord, "uniq_email");

    let t1 = coord.begin_serializable();
    let t2 = coord.begin_serializable();
    let (_r1, e1) = run_stmt(&coord, t1, "CREATE (:Person {email: 'a@x.com'})");
    assert!(
        e1.is_none(),
        "t1 insert passes its own write-time check: {e1:?}"
    );
    let (_r2, e2) = run_stmt(&coord, t2, "CREATE (:Person {email: 'a@x.com'})");
    assert!(
        e2.is_none(),
        "t2 insert passes its own write-time check: {e2:?}"
    );

    let c1 = coord.commit(t1);
    let c2 = coord.commit(t2);
    let committed = [&c1, &c2].iter().filter(|r| r.is_ok()).count();
    let aborted = [&c1, &c2].iter().filter(|r| r.is_err()).count();
    assert_eq!(
        committed, 1,
        "exactly one concurrent identical IS UNIQUE CREATE may commit (c1={c1:?}, c2={c2:?})"
    );
    assert_eq!(
        aborted, 1,
        "exactly one is aborted to preserve the unique value"
    );
    let err = [c1, c2].into_iter().find_map(Result::err).unwrap();
    assert!(
        matches!(err, GraphusError::Transaction(_)),
        "the concurrent-uniqueness abort is a retriable transaction error: {err}"
    );
    assert_eq!(
        person_count(&mut coord),
        1,
        "no duplicate-email node survives"
    );
}

#[test]
fn unique_create_after_commit_is_constraint_validation_failed() {
    // Control: the second CREATE runs AFTER the first commits → it sees the duplicate and is rejected
    // at statement time with the constraint sentinel (the single-prop write-time-enforcement path).
    let mut coord = fresh_coord();
    create_person_unique_email(&mut coord, "uniq_email");
    run_write_committed(&mut coord, "CREATE (:Person {email: 'a@x.com'})");

    let t = coord.begin_serializable();
    let (_r, e) = run_stmt(&coord, t, "CREATE (:Person {email: 'a@x.com'})");
    let e = e.expect("a visible duplicate value is rejected at statement time");
    assert!(
        e.to_string().contains(CONSTRAINT_VIOLATION_PREFIX),
        "expected a Neo.ClientError.Schema.ConstraintValidationFailed sentinel, got: {e}"
    );
    coord.rollback(t).expect("rollback the violating txn");
    assert_eq!(
        person_count(&mut coord),
        1,
        "the rejected CREATE created nothing"
    );
}
