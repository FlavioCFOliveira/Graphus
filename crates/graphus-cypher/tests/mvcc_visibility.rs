//! MVCC snapshot-visibility regression tests for the Cypher engine over the real store
//! (`04-technical-design.md` §5.2/§5.3; `rmp` task #45).
//!
//! These prove the read-side of MVCC-native execution end-to-end through [`RecordStoreGraph`]: a
//! query reads from a consistent point-in-time snapshot, so it sees only versions committed at or
//! before its begin timestamp (plus its own writes), never a concurrent transaction's later commit,
//! and still sees a version another transaction has since deleted but that committed *after* the
//! reader's snapshot. Concurrency over the single-threaded store is modelled by choosing an explicit
//! snapshot timestamp ([`RecordStoreGraph::begin_at_snapshot`]) below or above a record's commit
//! timestamp — exactly the relationship an older / newer concurrent reader would have.
//!
//! Crash survival of committed effects (and rollback of in-flight losers) is covered by the
//! crash-recovery tests in `record_store_graph.rs`, which now run over the MVCC-native store and
//! prove a fresh post-recovery snapshot still sees committed data (the eager commit-time settling
//! makes committed headers self-describing without an in-memory table).

use graphus_core::{Timestamp, TxnId, Value};
use graphus_cypher::binding::{Parameters, bind_parameters};
use graphus_cypher::catalog::IndexCatalog;
use graphus_cypher::executor::execute;
use graphus_cypher::graph_access::GraphAccess;
use graphus_cypher::lexer::tokenize;
use graphus_cypher::lower::lower;
use graphus_cypher::parser::parse_tokens;
use graphus_cypher::physical::plan_physical;
use graphus_cypher::record_graph::RecordStoreGraph;
use graphus_cypher::runtime::Row;
use graphus_cypher::semantics::analyze;
use graphus_io::MemBlockDevice;
use graphus_storage::RecordStore;
use graphus_wal::{MemLogSink, WalManager};

type Store = RecordStore<MemBlockDevice, MemLogSink>;

fn fresh_store() -> Store {
    let device = MemBlockDevice::new(0);
    let wal = WalManager::create(MemLogSink::new()).expect("create wal");
    RecordStore::create(device, wal, 64, 1).expect("create store")
}

fn compile(src: &str) -> graphus_cypher::physical::PhysicalPlan {
    let toks = tokenize(src).expect("lex");
    let ast = parse_tokens(&toks, src).expect("parse");
    let validated = analyze(&ast).expect("analyze");
    plan_physical(&lower(&validated), &IndexCatalog::empty())
}

/// Runs a write query under `txn` and commits it (advancing the store's commit timestamp).
fn run_commit(src: &str, store: Store, txn: u64) -> Store {
    let plan = compile(src);
    let bound = bind_parameters(&plan, &Parameters::new()).expect("bind");
    let mut graph = RecordStoreGraph::begin(store, TxnId(txn));
    {
        let mut cursor = execute(&plan, &bound, &mut graph).expect("open cursor");
        cursor.collect_all().expect("collect");
    }
    assert!(!graph.has_error(), "captured error: {:?}", graph.take_error());
    graph.commit().expect("commit")
}

/// Runs a read-only query at an explicit MVCC snapshot timestamp `ts` and returns its rows (the
/// store is reclaimed without committing — a read does not advance time).
fn read_at(src: &str, store: Store, txn: u64, ts: u64) -> (Vec<Row>, Store) {
    let plan = compile(src);
    let bound = bind_parameters(&plan, &Parameters::new()).expect("bind");
    let mut graph = RecordStoreGraph::begin_at_snapshot(store, TxnId(txn), Timestamp(ts));
    let rows = {
        let mut cursor = execute(&plan, &bound, &mut graph).expect("open cursor");
        cursor.collect_all().expect("collect")
    };
    assert!(!graph.has_error(), "captured error: {:?}", graph.take_error());
    (rows, graph.into_store())
}

fn ints(rows: &[Row], col: &str) -> Vec<i64> {
    let mut vs: Vec<i64> = rows
        .iter()
        .filter_map(|r| match r.value(col) {
            Value::Integer(k) => Some(k),
            _ => None,
        })
        .collect();
    vs.sort_unstable();
    vs
}

#[test]
fn older_snapshot_does_not_see_a_later_committed_insert() {
    // txn 1 commits one node at commit timestamp 1.
    let store = run_commit("CREATE (:N {n: 1})", fresh_store(), 1);

    // A reader whose snapshot began before that commit (ts = 0) sees nothing: the node's xmin
    // committed at 1 > 0, so it is invisible (`04 §5.3` clause 1).
    let (rows, store) = read_at("MATCH (n) RETURN n.n AS v", store, 2, 0);
    assert!(
        rows.is_empty(),
        "a snapshot older than the insert must not see it, got {rows:?}"
    );

    // A reader at or after the commit (ts = 1) sees the node.
    let (rows, _store) = read_at("MATCH (n) RETURN n.n AS v", store, 3, 1);
    assert_eq!(ints(&rows, "v"), vec![1], "a snapshot at/after the insert sees it");
}

#[test]
fn older_snapshot_still_sees_a_concurrently_deleted_node() {
    // txn 1 commits node {n:1} at ts 1; txn 2 deletes it at ts 2 (MVCC tombstone: xmin=1, xmax=2).
    let store = run_commit("CREATE (:N {n: 1})", fresh_store(), 1);
    let store = run_commit("MATCH (n:N) DELETE n", store, 2);

    // A reader whose snapshot is at ts 1 (it began before the delete committed) still sees the
    // node: xmin committed at 1 <= 1, and the deletion's xmax committed at 2 > 1, so it does not
    // hide the version (`04 §5.3` clause 2) — no torn read of a concurrent delete.
    let (rows, store) = read_at("MATCH (n) RETURN n.n AS v", store, 3, 1);
    assert_eq!(
        ints(&rows, "v"),
        vec![1],
        "a snapshot older than the delete still sees the pre-delete version"
    );

    // A reader at or after the delete (ts = 2) does not see it: the deletion's xmax 2 <= 2 hides it.
    let (rows, _store) = read_at("MATCH (n) RETURN n.n AS v", store, 4, 2);
    assert!(
        rows.is_empty(),
        "a snapshot at/after the delete must not see the node, got {rows:?}"
    );
}

#[test]
fn a_transaction_sees_its_own_uncommitted_writes() {
    // Within one uncommitted transaction, a node it just created is visible to its own reads
    // (`04 §5.3`: a transaction always sees its own in-flight writes), even though no other snapshot
    // could see it yet. Exercised directly over the GraphAccess seam, then rolled back.
    let store = fresh_store();
    let mut graph = RecordStoreGraph::begin(store, TxnId(1));
    let node = graph.create_node(&["N".to_owned()], &[("n".to_owned(), Value::Integer(7))]);
    assert!(!graph.has_error(), "create failed: {:?}", graph.take_error());

    assert!(
        graph.node_exists(node),
        "a transaction's own freshly-created node exists for itself"
    );
    assert_eq!(
        graph.scan_nodes(),
        vec![node],
        "the own-write node shows up in the transaction's own scan"
    );
    assert_eq!(
        graph.node_property(node, "n"),
        Some(Value::Integer(7)),
        "the own-write node's property reads back within the same transaction"
    );

    // Rolling back discards it; a fresh transaction over the recovered store then sees nothing.
    let store = graph.rollback().expect("rollback");
    let (rows, _store) = read_at("MATCH (n) RETURN n.n AS v", store, 2, u64::MAX >> 1);
    assert!(
        rows.is_empty(),
        "after rollback the uncommitted node is gone, got {rows:?}"
    );
}
