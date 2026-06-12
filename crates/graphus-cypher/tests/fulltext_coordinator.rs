//! Full-text index over the **real** storage-backed `TxnCoordinator` (`rmp` task #72).
//!
//! Where `tests/fulltext_index.rs` proves the executor + procedure + materialization wiring against
//! the [`MemGraph`](graphus_cypher::graph_access::MemGraph) reference backend, these tests prove the
//! storage-backed path: per-write inverted-index maintenance, the candidate-set + MVCC re-check (a
//! deleted / other-transaction node never matches), the non-blocking online build, and — the headline
//! durability AC — that the index survives a crash + reopen (the catalog is durable, the inverted
//! index is rebuilt from the recovered store).
//!
//! The harness mirrors `tests/online_index_build.rs`.

use graphus_core::{TxnId, Value};
use graphus_cypher::binding::{Parameters, bind_parameters};
use graphus_cypher::catalog::IndexCatalog;
use graphus_cypher::coordinator::TxnCoordinator;
use graphus_cypher::executor::execute;
use graphus_cypher::lexer::tokenize;
use graphus_cypher::lower::lower;
use graphus_cypher::parser::parse_tokens;
use graphus_cypher::physical::{PhysicalPlan, plan_physical};
use graphus_cypher::runtime::{Row, RowValue};
use graphus_cypher::semantics::analyze;
use graphus_index::fulltext::Analyzer;
use graphus_io::MemBlockDevice;
use graphus_storage::RecordStore;
use graphus_storage::recovery::recover_device;
use graphus_wal::{LogSink, MemLogSink, WalManager};

type Store = RecordStore<MemBlockDevice, MemLogSink>;
type Coord = TxnCoordinator<MemBlockDevice, MemLogSink>;

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

fn run_plan(coord: &Coord, txn: TxnId, plan: &PhysicalPlan) -> Vec<Row> {
    let bound = bind_parameters(plan, &Parameters::new()).expect("bind");
    let mut graph = coord.statement(txn).expect("statement");
    let rows = {
        let mut cursor = execute(plan, &bound, &mut graph).expect("open cursor");
        cursor.collect_all().expect("collect")
    };
    assert!(
        !graph.has_error(),
        "statement captured an error: {:?}",
        graph.take_error()
    );
    rows
}

fn write(coord: &mut Coord, src: &str) {
    let plan = compile(src);
    let txn = coord.begin_serializable();
    let _ = run_plan(coord, txn, &plan);
    coord.commit(txn).expect("commit write");
}

/// Runs the full-text query procedure and returns the matching node ids (the `node` column's id),
/// sorted, against a freshly-begun-and-committed read transaction.
fn query_ids(coord: &mut Coord, index: &str, search: &str) -> Vec<u64> {
    let src =
        format!("CALL db.index.fulltext.queryNodes('{index}', '{search}') YIELD node RETURN node");
    let plan = compile(&src);
    let txn = coord.begin_serializable();
    let rows = run_plan(coord, txn, &plan);
    coord.commit(txn).expect("read commits");
    let mut ids: Vec<u64> = rows
        .iter()
        .filter_map(|r| match r.get("node") {
            Some(RowValue::Node(n)) => Some(n.id.0),
            _ => None,
        })
        .collect();
    ids.sort_unstable();
    ids
}

/// Returns the single node id created by `CREATE (... ) RETURN id(n)`-style seeding — here we just
/// read it back by a property query so the test does not depend on id assignment.
fn id_of(coord: &mut Coord, label: &str, name: &str) -> u64 {
    let src = format!("MATCH (n:{label} {{name: '{name}'}}) RETURN id(n) AS id");
    let plan = compile(&src);
    let txn = coord.begin_serializable();
    let rows = run_plan(coord, txn, &plan);
    coord.commit(txn).expect("read commits");
    match rows[0].value("id") {
        Value::Integer(i) => i as u64,
        other => panic!("expected an integer id, got {other:?}"),
    }
}

fn create_index(coord: &mut Coord) {
    coord
        .create_fulltext_index("ft", "Article", &["title".to_owned()], Analyzer::Standard)
        .expect("create fulltext index");
    // Drive the (tiny) online build to completion so the index is Online.
    while coord.has_pending_index_builds() {
        coord.advance_index_builds(64);
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

// =================================================================================================
// Tests
// =================================================================================================

#[test]
fn create_then_query_returns_matching_nodes() {
    let mut coord = fresh_coord();
    write(
        &mut coord,
        "CREATE (:Article {title: 'Graph databases are great', name: 'a1'})",
    );
    write(
        &mut coord,
        "CREATE (:Article {title: 'Relational databases', name: 'a2'})",
    );
    write(
        &mut coord,
        "CREATE (:Article {title: 'Graph theory', name: 'a3'})",
    );
    create_index(&mut coord);

    let a1 = id_of(&mut coord, "Article", "a1");
    let a2 = id_of(&mut coord, "Article", "a2");
    let a3 = id_of(&mut coord, "Article", "a3");

    let mut databases = query_ids(&mut coord, "ft", "databases");
    databases.sort_unstable();
    assert_eq!(databases, vec![a1.min(a2), a1.max(a2)]); // a1 + a2
    assert_eq!(query_ids(&mut coord, "ft", "theory"), vec![a3]);
    // Stop-word-only search matches nothing.
    assert!(query_ids(&mut coord, "ft", "the are").is_empty());
}

#[test]
fn writes_after_index_creation_are_maintained() {
    let mut coord = fresh_coord();
    create_index(&mut coord); // empty store, then write
    write(
        &mut coord,
        "CREATE (:Article {title: 'graph database', name: 'a1'})",
    );
    let a1 = id_of(&mut coord, "Article", "a1");
    // A node created AFTER the index exists is indexed by per-write maintenance.
    assert_eq!(query_ids(&mut coord, "ft", "database"), vec![a1]);
}

#[test]
fn updates_and_deletes_are_reflected() {
    let mut coord = fresh_coord();
    write(
        &mut coord,
        "CREATE (:Article {title: 'graph database', name: 'a1'})",
    );
    create_index(&mut coord);
    let a1 = id_of(&mut coord, "Article", "a1");
    assert_eq!(query_ids(&mut coord, "ft", "database"), vec![a1]);

    // Update the title: the stale term must no longer match, the new term must.
    write(
        &mut coord,
        "MATCH (n:Article {name: 'a1'}) SET n.title = 'graph theory'",
    );
    assert!(query_ids(&mut coord, "ft", "database").is_empty());
    assert_eq!(query_ids(&mut coord, "ft", "theory"), vec![a1]);

    // Delete the node: it disappears (candidate-set + MVCC re-check drops the invisible version).
    write(&mut coord, "MATCH (n:Article {name: 'a1'}) DELETE n");
    assert!(query_ids(&mut coord, "ft", "theory").is_empty());
}

#[test]
fn uncommitted_write_in_another_transaction_is_not_matched() {
    let mut coord = fresh_coord();
    write(
        &mut coord,
        "CREATE (:Article {title: 'visible', name: 'a1'})",
    );
    create_index(&mut coord);

    // Open a writer that creates a node but does NOT commit.
    let writer = coord.begin_serializable();
    {
        let plan = compile("CREATE (:Article {title: 'secret hidden', name: 'a2'})");
        let _ = run_plan(&coord, writer, &plan);
    }

    // A separate reader's snapshot must NOT see the uncommitted 'secret' node — even though the
    // writer's per-write maintenance inserted it as a candidate, the MVCC re-check filters it.
    let reader = coord.begin_serializable();
    let plan = compile("CALL db.index.fulltext.queryNodes('ft', 'secret') YIELD node RETURN node");
    let rows = run_plan(&coord, reader, &plan);
    coord.commit(reader).expect("reader commits");
    assert!(
        rows.is_empty(),
        "an uncommitted node from another transaction must not match"
    );

    // Roll the writer back; 'secret' never becomes visible.
    coord.rollback(writer).expect("rollback");
    assert!(query_ids(&mut coord, "ft", "secret").is_empty());
}

#[test]
fn online_build_indexes_a_populated_store() {
    let mut coord = fresh_coord();
    // Seed many nodes first, THEN create the index so the online build has work to do.
    for n in 0..50 {
        write(
            &mut coord,
            &format!("CREATE (:Article {{title: 'document number {n} graph', name: 'a{n}'}})"),
        );
    }
    coord
        .create_fulltext_index("ft", "Article", &["title".to_owned()], Analyzer::Standard)
        .expect("create");
    assert!(coord.has_pending_index_builds());
    // Drive the build in small chunks (the interleaving point).
    let mut iters = 0;
    while coord.has_pending_index_builds() {
        coord.advance_index_builds(7);
        iters += 1;
        assert!(iters < 10_000, "build must terminate");
    }
    // Every seeded node mentions "graph" -> all 50 match.
    assert_eq!(query_ids(&mut coord, "ft", "graph").len(), 50);
    // A specific document number matches exactly one.
    assert_eq!(query_ids(&mut coord, "ft", "42").len(), 1);
}

#[test]
fn index_survives_a_crash_and_reopen() {
    // Build a store with an Article + a full-text index, then "crash" (recover from the durable WAL
    // prefix) and reopen a fresh coordinator. The catalog is durable and the inverted index is
    // rebuilt from the recovered store, so the index still returns correct matches (the durability AC).
    let recovered = {
        let mut coord = fresh_coord();
        write(
            &mut coord,
            "CREATE (:Article {title: 'graph database survives', name: 'a1'})",
        );
        write(
            &mut coord,
            "CREATE (:Article {title: 'relational only', name: 'a2'})",
        );
        create_index(&mut coord);
        // Sanity: the index works before the crash.
        assert_eq!(query_ids(&mut coord, "ft", "survives").len(), 1);

        let store = coord.into_store();
        recover_no_force(&store)
    };

    // Reopen: a fresh coordinator over the recovered store rebuilds the index from the durable
    // catalog + records — no manual re-creation.
    let mut coord = TxnCoordinator::new(recovered);

    // The index is still declared (catalog survived) and online.
    let listed = coord.list_fulltext_indexes();
    assert_eq!(
        listed.len(),
        1,
        "the full-text index must survive the crash"
    );
    assert_eq!(listed[0].0, "ft");

    // And it still returns the correct matches (inverted index rebuilt from the recovered store).
    assert_eq!(query_ids(&mut coord, "ft", "survives").len(), 1);
    assert_eq!(query_ids(&mut coord, "ft", "database").len(), 1);
    assert!(query_ids(&mut coord, "ft", "relational").len() == 1);
    assert!(query_ids(&mut coord, "ft", "graph").len() == 1);
}

#[test]
fn drop_index_then_query_errors() {
    let mut coord = fresh_coord();
    write(&mut coord, "CREATE (:Article {title: 'graph', name: 'a1'})");
    create_index(&mut coord);
    assert_eq!(query_ids(&mut coord, "ft", "graph").len(), 1);

    coord.drop_fulltext_index("ft").expect("drop");
    // Querying a dropped index is a clear error (the procedure surfaces it), not silently-empty rows.
    let plan = compile("CALL db.index.fulltext.queryNodes('ft', 'graph') YIELD node RETURN node");
    let txn = coord.begin_serializable();
    let bound = bind_parameters(&plan, &Parameters::new()).expect("bind");
    let result = {
        let mut graph = coord.statement(txn).expect("statement");
        let mut cursor = execute(&plan, &bound, &mut graph).expect("open");
        cursor.collect_all()
    };
    assert!(
        result.is_err(),
        "querying a dropped full-text index must error, not return empty results"
    );
    coord.rollback(txn).ok();
}
