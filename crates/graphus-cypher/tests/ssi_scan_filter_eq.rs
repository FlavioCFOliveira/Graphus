//! SSI regression tests for the **precise equality-filtered label scan** access path (`rmp` task
//! #325), driven by the real [`TxnCoordinator`] over the record store.
//!
//! Background. `MATCH (h:Hot {id: k})` over an **unindexed** label lowers to a full store scan that
//! evaluates the equality predicate. Before #325 that scan registered a *blanket* SIREAD marker on
//! **every** live node (the conservative label-scan footprint), so two transactions matching
//! **disjoint** keys (`{id: 1}` vs `{id: 2}`) each created a read dependency on the *other's* node and
//! formed a reciprocal rw-antidependency structure — one was falsely aborted on every contended
//! statement (measured: fraud-oltp `abort_rate ≈ 0.97`). #325 routes the path through the
//! `scan_filter_eq` seam, which SIREAD-marks **only the matching nodes** plus the precise
//! [`graphus_txn::PredicateRead::Equality`] predicate marker — the scan-path twin of the indexed
//! `index_seek_eq` footprint (`rmp` #316).
//!
//! These tests are **teeth-verified**: they assert (1) disjoint-key writers BOTH commit (the abort
//! storm is gone) **and** that the access path under test is actually `NodeLabelScanEq` (so the test
//! cannot silently pass by taking a different plan), and (2) a genuine write-skew / phantom on the
//! same scan path still aborts one transaction (the precision did not open a serializability hole).

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
    // No index catalog: the equality-filtered label scan therefore lowers to the precise full-scan
    // access path (`NodeLabelScanEq`), exactly the path #325 hardens.
    plan_physical(&lower(&validated), &IndexCatalog::empty())
}

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

/// Seeds two `:Hot` accounts with disjoint ids and commits them.
fn seed_two_hot(coord: &mut Coord) {
    let t = coord.begin_serializable();
    let (_r, err) = run_stmt(
        coord,
        t,
        "CREATE (:Hot {id: 1, bal: 0}), (:Hot {id: 2, bal: 0})",
    );
    assert!(err.is_none(), "seed error: {err:?}");
    coord.commit(t).expect("seed commits");
}

/// The `bal` of the `:Hot` account whose `id` is `id`, read in a fresh committed transaction.
fn read_bal(coord: &mut Coord, id: i64) -> i64 {
    let txn = coord.begin_serializable();
    let (rows, err) = run_stmt(
        coord,
        txn,
        &format!("MATCH (h:Hot {{id: {id}}}) RETURN h.bal AS bal"),
    );
    assert!(err.is_none(), "read error: {err:?}");
    coord.commit(txn).expect("read commits");
    match rows.first().map(|r| r.value("bal")) {
        Some(Value::Integer(b)) => b,
        other => panic!("expected one Integer bal for id={id}, got {other:?}"),
    }
}

/// Teeth: assert that `MATCH (h:Hot {id: k}) ...` actually lowers to the precise `NodeLabelScanEq`
/// access path. If the planner ever changed shape (e.g. fell back to `NodeByLabelScan` + `Filter`),
/// the disjoint-key test below could pass for the wrong reason — this guards against that.
#[test]
fn equality_label_scan_lowers_to_precise_scan_filter_eq() {
    let plan = compile("MATCH (h:Hot {id: 1}) SET h.bal = 10");
    let rendered = plan.to_string();
    assert!(
        rendered.contains("NodeLabelScanEq(h:Hot id = 1)"),
        "equality-over-label-scan must use the precise NodeLabelScanEq access path; got:\n{rendered}"
    );
    assert!(
        !rendered.contains("NodeByLabelScan"),
        "the bare (blanket-marking) NodeByLabelScan must NOT be used for the equality path; got:\n{rendered}"
    );
}

#[test]
fn disjoint_key_equality_scans_both_commit_no_false_abort() {
    // The `rmp` #325 fix, teeth-verified. Two concurrent SERIALIZABLE transactions each match a
    // DISJOINT hot account by equality and write only their own match:
    //   T1: MATCH (h:Hot {id: 1}) SET h.bal = 10   -> reads/writes ONLY node id=1
    //   T2: MATCH (h:Hot {id: 2}) SET h.bal = 20   -> reads/writes ONLY node id=2
    // With the precise footprint, T1's read depends on node id=1 only and T2's on id=2 only, so there
    // is NO rw-antidependency between them: BOTH must commit. Before #325 the blanket label-scan
    // marker made each read depend on the other's node, manufacturing a reciprocal structure that
    // falsely aborted one of them.
    let mut coord = fresh_coord();
    seed_two_hot(&mut coord);

    let t1 = coord.begin_serializable();
    let t2 = coord.begin_serializable();

    let (_r1, e1) = run_stmt(&coord, t1, "MATCH (h:Hot {id: 1}) SET h.bal = 10");
    assert!(
        e1.is_none(),
        "t1 statement should not capture an error: {e1:?}"
    );
    let (_r2, e2) = run_stmt(&coord, t2, "MATCH (h:Hot {id: 2}) SET h.bal = 20");
    assert!(
        e2.is_none(),
        "t2 statement should not capture an error: {e2:?}"
    );

    // Both commit: disjoint equality keys do not conflict.
    coord
        .commit(t1)
        .expect("t1 commits (disjoint key, no false abort)");
    coord
        .commit(t2)
        .expect("t2 commits (disjoint key, no false abort)");

    // Both writes took effect (each on its own account).
    assert_eq!(read_bal(&mut coord, 1), 10, "T1's write to id=1 stands");
    assert_eq!(read_bal(&mut coord, 2), 20, "T2's write to id=2 stands");
}

#[test]
fn same_key_equality_scan_write_skew_still_aborts_one() {
    // Precision must NOT open a serializability hole. The classic write-skew over the SAME equality
    // predicate: two transactions each read the matching account by equality and each update it
    // (a first-updater-wins write-write conflict here, since both target the same node). Exactly one
    // must be rejected with a retriable serialization failure.
    let mut coord = fresh_coord();
    seed_two_hot(&mut coord);

    let t1 = coord.begin_serializable();
    let t2 = coord.begin_serializable();

    let (_r1, e1) = run_stmt(&coord, t1, "MATCH (h:Hot {id: 1}) SET h.bal = 100");
    assert!(e1.is_none(), "first updater of id=1 succeeds: {e1:?}");
    let (_r2, e2) = run_stmt(&coord, t2, "MATCH (h:Hot {id: 1}) SET h.bal = 200");
    let e2 = e2.expect("second updater of the SAME matched node captures a conflict");
    assert!(
        matches!(e2, GraphusError::Transaction(_)),
        "the conflict is a retriable transaction error: {e2}"
    );

    coord.rollback(t2).expect("rollback the conflicting txn");
    coord.commit(t1).expect("first updater commits");
    assert_eq!(read_bal(&mut coord, 1), 100, "first updater's value stands");
}

#[test]
fn phantom_insert_into_equality_predicate_still_aborts() {
    // The precise `Equality` predicate marker must still cover **phantoms** — the property #325's doc
    // calls out as the non-negotiable correctness requirement. Two transactions each read the SAME
    // equality predicate that currently matches NOTHING (`{id: 5}` does not exist) and then each
    // INSERT a node that makes it match. Under SERIALIZABLE this is a phantom write-skew: each
    // transaction's read of the predicate's *absence* is invalidated by the other's insert. The
    // precise reader-side `Equality{Hot, id, enc(5)}` marker pairs with the writer's post-image
    // predicate footprint (same canonical encoding), so the dangerous structure is detected and at
    // least one transaction is aborted (no livelock; the other commits).
    let mut coord = fresh_coord();
    // Seed so the `Hot` label + `id` property tokens already exist (so the precise Equality marker is
    // formed on the read; the empty match is genuine, not a missing-token coarse fallback).
    seed_two_hot(&mut coord);

    let t1 = coord.begin_serializable();
    let t2 = coord.begin_serializable();

    // Each reads the (currently empty) equality predicate, then inserts a matching node.
    let (r1, er1) = run_stmt(&coord, t1, "MATCH (h:Hot {id: 5}) RETURN h.id AS id");
    assert!(er1.is_none(), "t1 read error: {er1:?}");
    assert!(r1.is_empty(), "id=5 must not match yet (t1)");
    let (r2, er2) = run_stmt(&coord, t2, "MATCH (h:Hot {id: 5}) RETURN h.id AS id");
    assert!(er2.is_none(), "t2 read error: {er2:?}");
    assert!(r2.is_empty(), "id=5 must not match yet (t2)");

    let (_w1, ew1) = run_stmt(&coord, t1, "CREATE (:Hot {id: 5, bal: 1})");
    assert!(ew1.is_none(), "t1 insert statement error: {ew1:?}");
    let (_w2, ew2) = run_stmt(&coord, t2, "CREATE (:Hot {id: 5, bal: 2})");
    assert!(ew2.is_none(), "t2 insert statement error: {ew2:?}");

    // Exactly one commit is rejected: the phantom write-skew is caught.
    let c1 = coord.commit(t1);
    let c2 = coord.commit(t2);
    let aborted = [&c1, &c2].iter().filter(|r| r.is_err()).count();
    let committed = [&c1, &c2].iter().filter(|r| r.is_ok()).count();
    assert_eq!(
        aborted, 1,
        "exactly one transaction aborts on the phantom (c1={c1:?}, c2={c2:?})"
    );
    assert_eq!(committed, 1, "exactly one transaction commits");
    let err = [c1, c2].into_iter().find_map(Result::err).unwrap();
    assert!(
        matches!(err, GraphusError::Transaction(_)),
        "the phantom abort is a retriable transaction error: {err}"
    );
}
