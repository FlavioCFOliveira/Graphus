//! Serializable Snapshot Isolation regression tests for concurrent Cypher transactions over the
//! real store, driven by the [`TxnCoordinator`] (`04-technical-design.md` §5.4/§5.7; `rmp` task #46).
//!
//! The classic **write-skew** anomaly: two concurrent transactions each read a pair of records and
//! each update one of them. Under plain Snapshot Isolation both commit (the anomaly is permitted);
//! under Serializable Snapshot Isolation the dangerous structure is detected and one transaction is
//! aborted with a retriable serialization failure, so at least one commits (no livelock). We also
//! cover the write-write first-updater-wins conflict and prove serial / disjoint transactions are
//! never falsely aborted.

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
use graphus_txn::IsolationLevel;
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

/// Runs one statement of `txn` over the coordinator, returning its rows and any captured deferred /
/// conflict error (the per-statement seam is dropped before returning, so the transaction stays
/// open but no longer borrows the store).
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

/// Reads property `v` of every node carrying `label`, as sorted integers, in a fresh transaction.
fn read_vs(coord: &mut Coord, label: &str) -> Vec<i64> {
    let txn = coord.begin_serializable();
    let (rows, err) = run_stmt(coord, txn, &format!("MATCH (n:{label}) RETURN n.v AS v"));
    assert!(err.is_none(), "read captured an error: {err:?}");
    coord.commit(txn).expect("read commits");
    let mut vs: Vec<i64> = rows
        .iter()
        .filter_map(|r| match r.value("v") {
            Value::Integer(k) => Some(k),
            _ => None,
        })
        .collect();
    vs.sort_unstable();
    vs
}

/// Seeds two nodes `(:A {v:1})` and `(:B {v:1})` and commits them.
fn seed(coord: &mut Coord) {
    let t = coord.begin_serializable();
    let (_rows, err) = run_stmt(coord, t, "CREATE (:A {v: 1}), (:B {v: 1})");
    assert!(err.is_none(), "seed error: {err:?}");
    coord.commit(t).expect("seed commits");
}

#[test]
fn write_skew_aborts_one_under_serializable() {
    let mut coord = fresh_coord();
    seed(&mut coord);

    // Two concurrent SERIALIZABLE transactions. Each MATCHes a label (a full scan with no index, so
    // it reads *every* node — both A and B) and then writes its own node: T1 writes A, T2 writes B.
    // That is the write-skew shape: T1 read B that T2 wrote, T2 read A that T1 wrote -> a pivot.
    let t1 = coord.begin_serializable();
    let t2 = coord.begin_serializable();

    let (_r, e1) = run_stmt(&coord, t1, "MATCH (a:A) SET a.v = 0");
    assert!(
        e1.is_none(),
        "t1 statement should not capture an error: {e1:?}"
    );
    let (_r, e2) = run_stmt(&coord, t2, "MATCH (b:B) SET b.v = 0");
    assert!(
        e2.is_none(),
        "t2 statement should not capture an error: {e2:?}"
    );

    // Exactly one of the two commits is rejected with a retriable serialization failure; the other
    // commits. (The first committer is the pivot whose outbound partner is still concurrent, so it
    // aborts itself; the second then commits because the aborted partner is gone.)
    let c1 = coord.commit(t1);
    let c2 = coord.commit(t2);
    let aborted = [&c1, &c2].iter().filter(|r| r.is_err()).count();
    let committed = [&c1, &c2].iter().filter(|r| r.is_ok()).count();
    assert_eq!(
        aborted, 1,
        "exactly one transaction aborts (c1={c1:?}, c2={c2:?})"
    );
    assert_eq!(committed, 1, "exactly one transaction commits");
    // The abort is a (retriable) transaction error, not a storage fault.
    let err = [c1, c2].into_iter().find_map(Result::err).unwrap();
    assert!(
        matches!(err, GraphusError::Transaction(_)),
        "the SSI abort is a retriable transaction error: {err}"
    );

    // Serializability preserved: the two updates did NOT both take effect. Exactly one of A.v / B.v
    // is now 0 (the committer's), the other still 1 (the abortee's update was rolled back).
    let a = read_vs(&mut coord, "A");
    let b = read_vs(&mut coord, "B");
    assert_eq!(a.len(), 1);
    assert_eq!(b.len(), 1);
    let zeros = [a[0], b[0]].iter().filter(|&&v| v == 0).count();
    assert_eq!(
        zeros, 1,
        "exactly one of A.v / B.v became 0 (no write-skew); got A={a:?} B={b:?}"
    );
}

#[test]
fn write_skew_both_commit_under_snapshot_isolation() {
    let mut coord = fresh_coord();
    seed(&mut coord);

    // The documented weaker opt-in: plain Snapshot Isolation runs no SSI validation, so the same
    // write-skew history commits both transactions (the anomaly is permitted, `04 §5.4`).
    let t1 = coord.begin(IsolationLevel::Snapshot);
    let t2 = coord.begin(IsolationLevel::Snapshot);

    let (_r, e1) = run_stmt(&coord, t1, "MATCH (a:A) SET a.v = 0");
    assert!(e1.is_none(), "{e1:?}");
    let (_r, e2) = run_stmt(&coord, t2, "MATCH (b:B) SET b.v = 0");
    assert!(e2.is_none(), "{e2:?}");

    coord.commit(t1).expect("snapshot t1 commits");
    coord.commit(t2).expect("snapshot t2 commits");

    // Both updates took effect: the write-skew is permitted under Snapshot Isolation.
    assert_eq!(read_vs(&mut coord, "A"), vec![0]);
    assert_eq!(read_vs(&mut coord, "B"), vec![0]);
}

#[test]
fn write_write_conflict_is_first_updater_wins() {
    let mut coord = fresh_coord();
    seed(&mut coord);

    // Two concurrent transactions update the SAME node: the first to write holds the lock, the
    // second's write captures a retriable serialization (write-write) conflict (`04 §5.7`).
    let t1 = coord.begin_serializable();
    let t2 = coord.begin_serializable();

    let (_r, e1) = run_stmt(&coord, t1, "MATCH (a:A) SET a.v = 10");
    assert!(e1.is_none(), "first updater succeeds: {e1:?}");
    let (_r, e2) = run_stmt(&coord, t2, "MATCH (a:A) SET a.v = 20");
    let e2 = e2.expect("second updater of the same node captures a write-write conflict");
    assert!(
        matches!(e2, GraphusError::Transaction(_)),
        "write-write conflict is a retriable transaction error: {e2}"
    );

    // The conflicting transaction rolls back; the first updater commits.
    coord.rollback(t2).expect("rollback the conflicting txn");
    coord.commit(t1).expect("first updater commits");
    assert_eq!(
        read_vs(&mut coord, "A"),
        vec![10],
        "first updater's value stands"
    );
}

#[test]
fn read_only_transaction_commits_concurrently_with_a_writer() {
    // No false positives for a read-only transaction (the SSI read-only optimization, `04 §5.4`): a
    // concurrent reader and a writer of the same node are serializable (reader-before-writer), so
    // both commit. Only a transaction that *both* read a concurrently-overwritten record *and* wrote
    // a concurrently-read one (a pivot) is aborted — a lone reader never is.
    //
    // Note on granularity: read markers are at node/relationship level and a label/all-nodes scan
    // (no index yet) reads *every* node, so two concurrent *writers* always form a structure and one
    // aborts (a safe over-abort). Finer predicate / index-range markers that avoid that are the
    // index-wiring follow-up (#48); they only ever *reduce* aborts, never permit an anomaly.
    let mut coord = fresh_coord();
    seed(&mut coord);

    let reader = coord.begin_serializable();
    let writer = coord.begin_serializable();

    let (rows, er) = run_stmt(&coord, reader, "MATCH (a:A) RETURN a.v AS v");
    assert!(er.is_none(), "reader error: {er:?}");
    assert_eq!(
        rows.iter()
            .filter_map(|r| match r.value("v") {
                Value::Integer(k) => Some(k),
                _ => None,
            })
            .collect::<Vec<_>>(),
        vec![1],
        "the reader sees the seeded value on its snapshot"
    );
    let (_r, ew) = run_stmt(&coord, writer, "MATCH (a:A) SET a.v = 2");
    assert!(ew.is_none(), "writer error: {ew:?}");

    // The read-only transaction is never the pivot; both commit.
    coord.commit(reader).expect("read-only transaction commits");
    coord.commit(writer).expect("writer commits");
    assert_eq!(read_vs(&mut coord, "A"), vec![2]);
}

/// `rmp` #442 — positive serializability gate for the #220-sibling class: a `DETACH DELETE n`
/// concurrent with a `CREATE ()-[:T]->(n)` (an edge touching the deleted node's `first_rel`) must NOT
/// commit a non-serializable outcome. The suspected hole (`create_rel`/`delete_rel` not SSI-marking
/// the endpoint nodes) was REFUTED by running it (reliability audit 2026-06-27): `incident_rels`
/// SIREAD-marks the new edge *pre-visibility* and `create_rel` checks the raw live bit, so SSI aborts
/// exactly one transaction. This pins that guarantee so a future refactor (statement granularity /
/// marker changes) cannot silently regress it. (The referential `DanglingRel` invariant is also
/// covered by the graphus-dst checker.)
#[test]
fn detach_delete_vs_create_edge_is_serializable() {
    let mut coord = fresh_coord();
    let s = coord.begin_serializable();
    let (_r, e) = run_stmt(&coord, s, "CREATE (:N {id: 5}), (:B {id: 9})");
    assert!(e.is_none(), "seed error: {e:?}");
    coord.commit(s).expect("seed commits");

    let t1 = coord.begin_serializable();
    let t2 = coord.begin_serializable();
    // CREATE the edge first (n is live on every snapshot), then DETACH DELETE n — both statements run
    // locally; the conflict surfaces only at commit.
    let (_r2, e2) = run_stmt(
        &coord,
        t2,
        "MATCH (n2:N {id: 5}), (b:B {id: 9}) CREATE (n2)-[:T]->(b)",
    );
    let (_r1, e1) = run_stmt(&coord, t1, "MATCH (n:N {id: 5}) DETACH DELETE n");
    assert!(
        e1.is_none() && e2.is_none(),
        "both statements run: e1={e1:?} e2={e2:?}"
    );

    let c1 = coord.commit(t1);
    let c2 = coord.commit(t2);
    // SSI must abort EXACTLY ONE: committing both would be the non-serializable "n deleted yet a live
    // :T edge dangles off it" outcome.
    let aborts = [c1.is_err(), c2.is_err()].iter().filter(|&&x| x).count();
    assert_eq!(aborts, 1, "exactly one must abort: c1={c1:?} c2={c2:?}");
}

/// `rmp` #442 control: a DISJOINT delete + create (no shared endpoint) must NOT be falsely aborted —
/// proving the SSI footprint that catches the conflicting case above is PRECISE, not a blanket
/// over-abort.
#[test]
fn disjoint_delete_and_create_edge_both_commit() {
    let mut coord = fresh_coord();
    let s = coord.begin_serializable();
    let (_r, e) = run_stmt(&coord, s, "CREATE (:N {id: 5}), (:C {id: 1}), (:D {id: 2})");
    assert!(e.is_none(), "seed error: {e:?}");
    coord.commit(s).expect("seed commits");

    let t1 = coord.begin_serializable();
    let t2 = coord.begin_serializable();
    let (_r2, e2) = run_stmt(
        &coord,
        t2,
        "MATCH (c:C {id: 1}), (d:D {id: 2}) CREATE (c)-[:T]->(d)",
    );
    let (_r1, e1) = run_stmt(&coord, t1, "MATCH (n:N {id: 5}) DETACH DELETE n");
    assert!(
        e1.is_none() && e2.is_none(),
        "both statements run: e1={e1:?} e2={e2:?}"
    );
    let c2 = coord.commit(t2);
    let c1 = coord.commit(t1);
    assert!(
        c1.is_ok() && c2.is_ok(),
        "disjoint delete + create must both commit: c1={c1:?} c2={c2:?}"
    );
}
