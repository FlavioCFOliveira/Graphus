//! Regression: a rolled-back LABEL change must not destroy a concurrently-committed PROPERTY write
//! on the same node record (`rmp` #772).
//!
//! ## The defect
//!
//! `add_label` / `remove_label` changed only the node record's `labels` word, but persisted the
//! change with a **whole-record** pre-image undo (`RecordStore::write_node` -> `write_region`). A
//! concurrent transaction's `SET n.prop` pushes onto the SAME record's `first_prop` head (via the
//! compare-and-set `write_chain_head`, `rmp` #220/#172) and MVCC-tombstones the old property. When
//! the label writer aborted AFTER that concurrent transaction committed, replaying the whole-record
//! pre-image reverted `first_prop` to its pre-commit value — orphaning the committed property version
//! (whose predecessor the committer had tombstoned on a byte region the whole-record undo does not
//! restore). The committed value read back as `Null`: an atomicity + durability breach.
//!
//! Reachable only through the direct coordinator API under [`IsolationLevel::Snapshot`] writes (an
//! internal opt-in used by bulk loaders/benches); the default Serializable SSI path aborts the second
//! writer, so it is not wire-reachable. Both directions are pinned here.
//!
//! ## The fix
//!
//! `add_label` / `remove_label` now scope the write and its undo to the `labels` word alone, with the
//! same compare-and-set logical undo the three chain-participating node-record writes already use
//! (`RecordStore::write_node_labels`). The undo reverts only this transaction's own label change and
//! never a concurrently-committed writer's `first_prop` / `first_rel` / MVCC word.

use graphus_core::{TxnId, Value};
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
use graphus_txn::IsolationLevel;
use graphus_wal::{MemLogSink, WalManager};

type Coord = TxnCoordinator<MemBlockDevice, MemLogSink>;

fn fresh_coord() -> Coord {
    let device = MemBlockDevice::new(0);
    let wal = WalManager::create(MemLogSink::new()).expect("create wal");
    TxnCoordinator::new(RecordStore::create(device, wal, 64, 1).expect("create store"))
}

fn compile(src: &str) -> PhysicalPlan {
    let toks = tokenize(src).expect("lex");
    let ast = parse_tokens(&toks, src).expect("parse");
    let validated = analyze(&ast).expect("analyze");
    plan_physical(&lower(&validated), &IndexCatalog::empty())
}

/// Runs `plan` under `txn` to completion. Returns `(rows, statement_error)` — the error surfaces via
/// `graph.take_error()`, NOT the row iterator, so a constraint/conflict is only observable here (the
/// probe trap noted in `rmp` #772).
fn run_stmt(coord: &Coord, txn: TxnId, plan: &PhysicalPlan) -> (Vec<Row>, Option<String>) {
    let bound = bind_parameters(plan, &Parameters::new()).expect("bind");
    let mut graph = coord.statement(txn).expect("statement");
    let rows = {
        let mut cursor = execute(plan, &bound, &mut graph).expect("open cursor");
        cursor.collect_all().expect("collect")
    };
    let err = graph
        .has_error()
        .then(|| format!("{:?}", graph.take_error()));
    (rows, err)
}

fn read_scalar(coord: &mut Coord, src: &str, col: &str) -> Value {
    let reader = coord.begin_serializable();
    let (rows, err) = run_stmt(coord, reader, &compile(src));
    assert!(err.is_none(), "reader saw error: {err:?}");
    assert_eq!(rows.len(), 1, "expected exactly one row, got {rows:?}");
    rows[0].value(col).clone()
}

fn seed_person(coord: &mut Coord) {
    let t0 = coord.begin_serializable();
    let (_r, err) = run_stmt(
        coord,
        t0,
        &compile("CREATE (:Person {email: 'original@x.io'})"),
    );
    assert!(err.is_none(), "seed CREATE errored: {err:?}");
    coord.commit(t0).expect("seed commits");
}

/// SI direction (the fix): W1's rolled-back label removal must NOT clobber W2's committed property
/// write. After W1 rolls back, the property equals W2's committed value, and W1's own label change is
/// cleanly undone (the label is back).
#[test]
fn si_label_rollback_preserves_concurrent_committed_property() {
    let mut coord = fresh_coord();
    seed_person(&mut coord);

    // W1: remove the label, left UNCOMMITTED (holds an undo image of the record).
    let w1 = coord.begin_at(IsolationLevel::Snapshot, 0);
    let (_r, err) = run_stmt(&coord, w1, &compile("MATCH (n:Person) REMOVE n:Person"));
    assert!(err.is_none(), "W1 REMOVE errored: {err:?}");

    // W2: a DIFFERENT transaction tries to set a property on the same node.
    //
    // `rmp` #968 ANSWERED THE QUESTION THIS COMMENT USED TO LEAVE OPEN. It said the write-lock layer
    // only *flagged* the write-write conflict under `IsolationLevel::Snapshot` while the mutation
    // still landed, and that whether SI should enforce first-updater-wins was "a separate
    // isolation-semantics question". It is no longer separate and no longer optional: a label change
    // now links a delta onto the node's undo chain, so W1 holds the node, and the STORAGE layer
    // refuses W2 at every isolation level (`D-write-conflict-detection`). The `rmp` #772 anomaly is
    // consequently unreachable rather than survived — the stronger of the two outcomes.
    let w2 = coord.begin_at(IsolationLevel::Snapshot, 0);
    let (_r, err) = run_stmt(
        &coord,
        w2,
        &compile("MATCH (n) SET n.email = 'committed@x.io'"),
    );
    let err = err.expect("W2's write must be refused while W1 holds the node's undo chain");
    assert!(
        err.to_string().contains("conflict"),
        "the refusal must name the write-write conflict, so a driver retries rather than failing \
         the transaction outright: {err}",
    );
    coord.rollback(w2).expect("W2 abandons the refused attempt");

    // Non-vacuity: the refusal really did stop the write — the property still holds the seeded value.
    assert_eq!(
        read_scalar(&mut coord, "MATCH (n) RETURN n.email AS e", "e"),
        Value::String("original@x.io".to_owned()),
        "the refused write must not have landed"
    );

    // W1 rolls back. Its undo must touch ONLY the labels word.
    coord.rollback(w1).expect("W1 rollback");

    // And with no holder, the very same write now succeeds and commits.
    let w3 = coord.begin_at(IsolationLevel::Snapshot, 0);
    let (_r, err) = run_stmt(
        &coord,
        w3,
        &compile("MATCH (n) SET n.email = 'committed@x.io'"),
    );
    assert!(err.is_none(), "W3 SET errored: {err:?}");
    coord.commit(w3).expect("W3 commits");

    // The committed property survives (was `Null` pre-fix — the orphaned-version anomaly).
    assert_eq!(
        read_scalar(&mut coord, "MATCH (n) RETURN n.email AS e", "e"),
        Value::String("committed@x.io".to_owned()),
        "the committed property must survive W1's label rollback (rmp #772)"
    );
    // W1's OWN change is cleanly undone: the label it removed is back.
    assert_eq!(
        read_scalar(&mut coord, "MATCH (n) RETURN labels(n) AS l", "l"),
        Value::List(vec![Value::String("Person".to_owned())]),
        "W1's own label removal was not cleanly undone"
    );
}

/// Serializable direction (the protection that must NOT regress): the SSI/write-lock path refuses the
/// second writer, so this scenario never reaches a rollback with both writes present. Pinning it
/// ensures the fix does not let the protection silently degrade into data destruction.
#[test]
fn serializable_label_write_refuses_concurrent_property_writer() {
    let mut coord = fresh_coord();
    seed_person(&mut coord);

    let w1 = coord.begin_serializable();
    let (_r, err) = run_stmt(&coord, w1, &compile("MATCH (n:Person) REMOVE n:Person"));
    assert!(err.is_none(), "W1 REMOVE errored: {err:?}");

    let w2 = coord.begin_serializable();
    // The write-write conflict surfaces at statement time (W1 holds the node's write lock).
    let (_r, err) = run_stmt(
        &coord,
        w2,
        &compile("MATCH (n) SET n.email = 'committed@x.io'"),
    );
    assert!(
        err.is_some(),
        "Serializable must refuse the second concurrent writer at statement time"
    );
    // And its commit is a serialization failure.
    assert!(
        coord.commit(w2).is_err(),
        "Serializable must not let the second writer commit"
    );

    coord.rollback(w1).expect("W1 rollback");

    // Correct serializable outcome: both losers nullified, only the seed survives.
    assert_eq!(
        read_scalar(&mut coord, "MATCH (n) RETURN n.email AS e", "e"),
        Value::String("original@x.io".to_owned()),
        "the seed value must survive both aborts"
    );
    assert_eq!(
        read_scalar(&mut coord, "MATCH (n) RETURN labels(n) AS l", "l"),
        Value::List(vec![Value::String("Person".to_owned())]),
        "the seed label must survive both aborts"
    );
}
