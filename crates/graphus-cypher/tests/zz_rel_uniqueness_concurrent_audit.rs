//! AUDIT-ONLY probe (rmp #646 re-assessment): concurrent inserts of the SAME new relationship
//! property value under a RelUnique constraint. Mirrors ssi_node_key_concurrent.rs but for the
//! relationship-uniqueness enforcement path. If SSI is sound, exactly one commits.

use graphus_core::{GraphusError, TxnId, Value};
use graphus_cypher::ConstraintKind;
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

fn run_write_committed(coord: &mut Coord, src: &str) {
    let t = coord.begin_serializable();
    let (_r, err) = run_stmt(coord, t, src);
    assert!(err.is_none(), "seed/write {src:?} error: {err:?}");
    coord.commit(t).expect("write commits");
}

fn knows_count(coord: &mut Coord) -> usize {
    let t = coord.begin_serializable();
    let (rows, err) = run_stmt(coord, t, "MATCH ()-[r:KNOWS]->() RETURN count(r) AS c");
    assert!(err.is_none(), "count error: {err:?}");
    coord.commit(t).expect("count commits");
    match rows[0].value("c") {
        Value::Integer(i) => i as usize,
        other => panic!("expected integer count, got {other:?}"),
    }
}

#[test]
fn concurrent_rel_unique_same_new_value_must_abort_exactly_one() {
    let mut coord = fresh_coord();
    // Constraint over conforming (empty) data.
    coord
        .create_constraint_general(
            "uniq_since",
            "KNOWS",
            &["since"],
            ConstraintKind::RelUnique,
            None,
        )
        .expect("create rel uniqueness constraint");

    let t1 = coord.begin_serializable();
    let t2 = coord.begin_serializable();

    // Each concurrent txn creates its own endpoints + a KNOWS edge with the SAME `since`.
    let (_r1, e1) = run_stmt(&coord, t1, "CREATE (:P)-[:KNOWS {since: 2020}]->(:P)");
    assert!(e1.is_none(), "t1 passes its own write-time check: {e1:?}");
    let (_r2, e2) = run_stmt(&coord, t2, "CREATE (:P)-[:KNOWS {since: 2020}]->(:P)");
    assert!(e2.is_none(), "t2 passes its own write-time check: {e2:?}");

    let c1 = coord.commit(t1);
    let c2 = coord.commit(t2);
    let committed = [&c1, &c2].iter().filter(|r| r.is_ok()).count();
    let aborted = [&c1, &c2].iter().filter(|r| r.is_err()).count();

    let surviving = knows_count(&mut coord);
    println!(
        "AUDIT: committed={committed} aborted={aborted} surviving_KNOWS={surviving} c1={c1:?} c2={c2:?}"
    );

    assert_eq!(
        surviving, 1,
        "UNIQUENESS BYPASS: two concurrent identical rel values both survived (count={surviving})"
    );
    assert_eq!(
        committed, 1,
        "exactly one concurrent identical rel CREATE may commit"
    );
    assert_eq!(
        aborted, 1,
        "exactly one must be aborted to preserve the unique value"
    );
}

#[test]
fn concurrent_rel_modify_into_value_is_caught() {
    // The scenario the commit message CLAIMS is caught: an existing rel modified INTO the value
    // concurrently with an insert of that value. Control to show the modify-into-value pivot.
    let mut coord = fresh_coord();
    coord
        .create_constraint_general(
            "uniq_since",
            "KNOWS",
            &["since"],
            ConstraintKind::RelUnique,
            None,
        )
        .expect("create rel uniqueness constraint");
    // Seed one edge with since=1 (will be modified into 2020 by t1).
    run_write_committed(&mut coord, "CREATE (:P)-[:KNOWS {since: 1}]->(:P)");

    let t1 = coord.begin_serializable();
    let t2 = coord.begin_serializable();

    // t1 modifies the existing edge INTO 2020; t2 inserts a NEW edge with 2020.
    let (_r1, e1) = run_stmt(
        &coord,
        t1,
        "MATCH ()-[r:KNOWS {since: 1}]->() SET r.since = 2020",
    );
    assert!(e1.is_none(), "t1 modify passes its own check: {e1:?}");
    let (_r2, e2) = run_stmt(&coord, t2, "CREATE (:P)-[:KNOWS {since: 2020}]->(:P)");
    assert!(e2.is_none(), "t2 insert passes its own check: {e2:?}");

    let c1 = coord.commit(t1);
    let c2 = coord.commit(t2);
    let committed = [&c1, &c2].iter().filter(|r| r.is_ok()).count();
    let surviving_2020 = {
        let t = coord.begin_serializable();
        let (rows, _e) = run_stmt(
            &coord,
            t,
            "MATCH ()-[r:KNOWS {since: 2020}]->() RETURN count(r) AS c",
        );
        coord.commit(t).ok();
        match rows[0].value("c") {
            Value::Integer(i) => i as usize,
            o => panic!("{o:?}"),
        }
    };
    println!(
        "AUDIT modify-into-value: committed={committed} surviving_2020={surviving_2020} c1={c1:?} c2={c2:?}"
    );
    assert!(
        surviving_2020 <= 1,
        "modify-into-value must not leave two rels at 2020 (got {surviving_2020})"
    );
}
