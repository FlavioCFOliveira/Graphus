//! Text (trigram) node index end-to-end (`rmp` task #662): DDL (`CREATE TEXT INDEX FOR (n:L) ON
//! (n.p)`), the durable catalog + synchronous online build, per-write maintenance, the planner's
//! `CONTAINS` / `ENDS WITH` / `STARTS WITH` seek, execution parity against the scan+filter fallback,
//! and crash recovery.
//!
//! The harness mirrors `tests/composite_index.rs`: a `TxnCoordinator` over an in-memory store with a
//! `run_write` commit probe and the `recover_no_force` deterministic reopen. The **execution parity**
//! tests are the black-box witness that the text index seek returns exactly the scan+filter set —
//! `read_ids(..)` runs the SAME read query twice, once compiled against the coordinator's catalog (the
//! `NodeTextIndexSeek` path) and once against the empty catalog (the scan+filter path), and asserts
//! the id sets are identical.

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
/// `id`s. Passing the coordinator's catalog exercises the text seek; the empty catalog exercises the
/// scan+filter fallback — the two must agree.
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

/// Asserts the text-seek plan (compiled against `coord.catalog()`) and the scan+filter plan (compiled
/// against the empty catalog) return the **identical** id set for `src`, and returns it.
fn assert_seek_matches_scan(coord: &mut Coord, src: &str) -> Vec<i64> {
    let catalog = coord.catalog();
    // Sanity: the catalog plan actually uses the text seek (else the parity check is vacuous).
    let plan = compile_with(src, &catalog);
    assert!(
        plan.to_string().contains("NodeTextIndexSeek"),
        "expected a text seek for {src:?}, got:\n{plan}"
    );
    let seek_ids = read_ids(coord, src, &catalog);
    let scan_ids = read_ids(coord, src, &IndexCatalog::empty());
    assert_eq!(
        seek_ids, scan_ids,
        "text seek rows must equal scan+filter rows for {src:?}"
    );
    seek_ids
}

/// Deterministically reopens `store` from its durable WAL prefix (the recovery probe).
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

/// Seeds `Person` nodes with `(id, name)` exercising case, substrings, a unicode value, a mixed-type
/// `name` (an integer), and a node missing `name` entirely.
fn seed_people(coord: &mut Coord) {
    run_write(coord, "CREATE (:Person {id: 1, name: 'Robert'})");
    run_write(coord, "CREATE (:Person {id: 2, name: 'roberta'})");
    run_write(coord, "CREATE (:Person {id: 3, name: 'Bobby'})");
    run_write(coord, "CREATE (:Person {id: 4, name: 'Álvaro'})"); // unicode scalar values
    run_write(coord, "CREATE (:Person {id: 5, name: 42})"); // mixed-type property (not a string)
    run_write(coord, "CREATE (:Person {id: 6, age: 30})"); // no name at all
}

// =================================================================================================
// Tests
// =================================================================================================

#[test]
fn text_index_is_durable_listed_idempotent_and_survives_reopen() {
    let mut coord = fresh_coord();
    seed_people(&mut coord);

    // Declare a text index over the existing data (synchronous, always Online).
    let created = coord
        .create_text_index("tx_person_name", "Person", "name", false)
        .expect("create text index");
    assert!(created, "a fresh create mutates");

    // SHOW-source surface: (name, label, property, Online).
    assert_eq!(
        coord.list_text_indexes(),
        vec![(
            "tx_person_name".to_owned(),
            "Person".to_owned(),
            "name".to_owned(),
            IndexState::Online,
        )],
        "the text index is Online and covers (Person, name)"
    );

    // IF NOT EXISTS equivalence: a re-declare of the same (label, property) errors without the flag...
    let err = coord
        .create_text_index("other_name", "Person", "name", false)
        .expect_err("an equivalent text index without IF NOT EXISTS errors");
    assert!(err.to_string().contains("equivalent index"), "{err:?}");
    // ...and is an idempotent no-op with it (a different name over the same schema).
    assert!(
        !coord
            .create_text_index("other_name", "Person", "name", true)
            .expect("IF NOT EXISTS is a clean no-op"),
        "IF NOT EXISTS on an equivalent text index does not mutate"
    );

    // A name collision with a DIFFERENT catalog errors without IF NOT EXISTS. Declare a range index of
    // a distinct name is fine (different kind, different schema), but reusing THIS text name for a
    // different-target text index is caught as a duplicate-name.
    coord
        .begin_online_node_property_index_named(Some("range_email"), "Person", "email", false)
        .expect("a range index of a distinct name coexists");
    let err = coord
        .create_text_index("range_email", "Person", "bio", false)
        .expect_err("a cross-catalog name collision errors");
    assert!(err.to_string().contains("named"), "{err:?}");

    // Crash + reopen: the durable catalog reload re-registers and repopulates the text index.
    let store = coord.into_store();
    assert_eq!(
        store.text_indexes().len(),
        1,
        "the text registration survives the reopen (durable catalog)"
    );
    let reopened = recover_no_force(&store);
    let mut coord2 = TxnCoordinator::new(reopened);
    assert_eq!(
        coord2.list_text_indexes(),
        vec![(
            "tx_person_name".to_owned(),
            "Person".to_owned(),
            "name".to_owned(),
            IndexState::Online,
        )],
        "the text index is fully recovered Online after reopen"
    );

    // The recovered index still serves the seek and agrees with the scan — and a post-recovery write is
    // maintained by the rebuilt index (id 7 "Roberto" matches CONTAINS 'obe' too).
    let before = assert_seek_matches_scan(
        &mut coord2,
        "MATCH (n:Person) WHERE n.name CONTAINS 'obe' RETURN n.id AS id",
    );
    assert_eq!(
        before,
        vec![1, 2],
        "Robert + roberta match 'obe' after reopen"
    );
    run_write(&mut coord2, "CREATE (:Person {id: 7, name: 'Roberto'})");
    let after = assert_seek_matches_scan(
        &mut coord2,
        "MATCH (n:Person) WHERE n.name CONTAINS 'obe' RETURN n.id AS id",
    );
    assert_eq!(
        after,
        vec![1, 2, 7],
        "the post-recovery write is maintained by the rebuilt text index"
    );
}

#[test]
fn text_seek_equals_scan_across_predicates_unicode_and_edge_cases() {
    let mut coord = fresh_coord();
    seed_people(&mut coord);
    coord
        .create_text_index("tx_person_name", "Person", "name", false)
        .expect("create text index");

    // CONTAINS.
    assert_eq!(
        assert_seek_matches_scan(
            &mut coord,
            "MATCH (n:Person) WHERE n.name CONTAINS 'obe' RETURN n.id AS id"
        ),
        vec![1, 2],
    );
    assert_eq!(
        assert_seek_matches_scan(
            &mut coord,
            "MATCH (n:Person) WHERE n.name CONTAINS 'bb' RETURN n.id AS id"
        ),
        vec![3],
    );
    // ENDS WITH — anchored at the tail, so 'ert' matches Robert but not roberta.
    assert_eq!(
        assert_seek_matches_scan(
            &mut coord,
            "MATCH (n:Person) WHERE n.name ENDS WITH 'ert' RETURN n.id AS id"
        ),
        vec![1],
    );
    assert_eq!(
        assert_seek_matches_scan(
            &mut coord,
            "MATCH (n:Person) WHERE n.name ENDS WITH 'ta' RETURN n.id AS id"
        ),
        vec![2],
    );
    // STARTS WITH — case-sensitive (raw match).
    assert_eq!(
        assert_seek_matches_scan(
            &mut coord,
            "MATCH (n:Person) WHERE n.name STARTS WITH 'Rob' RETURN n.id AS id"
        ),
        vec![1],
    );
    assert_eq!(
        assert_seek_matches_scan(
            &mut coord,
            "MATCH (n:Person) WHERE n.name STARTS WITH 'rob' RETURN n.id AS id"
        ),
        vec![2],
    );
    // Unicode: 'lvar' is a raw substring of "Álvaro".
    assert_eq!(
        assert_seek_matches_scan(
            &mut coord,
            "MATCH (n:Person) WHERE n.name CONTAINS 'lvar' RETURN n.id AS id"
        ),
        vec![4],
    );
    // No match — the seek narrows to nothing, agreeing with the scan.
    assert_eq!(
        assert_seek_matches_scan(
            &mut coord,
            "MATCH (n:Person) WHERE n.name CONTAINS 'zzz' RETURN n.id AS id"
        ),
        Vec::<i64>::new(),
    );
}

#[test]
fn short_needle_and_empty_needle_fall_back_but_still_match_the_scan() {
    // A needle too short to form a trigram makes the seam decline (scan fallback); the residual predicate
    // still yields exactly the scan result. The seek path is chosen by the planner (the plan routes
    // through `NodeTextIndexSeek`), but at run time the seam falls back to the label scan — transparent
    // to the caller. We can't assert `assert_seek_matches_scan` (it requires the plan to route through
    // the seek — which it does), so verify the parity directly.
    let mut coord = fresh_coord();
    seed_people(&mut coord);
    coord
        .create_text_index("tx_person_name", "Person", "name", false)
        .expect("create text index");

    for q in [
        "MATCH (n:Person) WHERE n.name CONTAINS 'o' RETURN n.id AS id", // 1-char (< 3)
        "MATCH (n:Person) WHERE n.name CONTAINS 'ob' RETURN n.id AS id", // 2-char (< 3)
        "MATCH (n:Person) WHERE n.name CONTAINS '' RETURN n.id AS id",  // empty needle
        "MATCH (n:Person) WHERE n.name STARTS WITH 'R' RETURN n.id AS id", // 1-char prefix (< 2)
        "MATCH (n:Person) WHERE n.name ENDS WITH 'o' RETURN n.id AS id", // 1-char suffix (< 2)
    ] {
        // The plan routes through the text seek (the catalog covers (Person, name))...
        let catalog = coord.catalog();
        assert!(
            compile_with(q, &catalog)
                .to_string()
                .contains("NodeTextIndexSeek"),
            "the plan should route through the text seek for {q:?}"
        );
        // ...and the seek result (with the run-time scan fallback for the short needle) equals the pure
        // scan result.
        let seek = read_ids(&mut coord, q, &catalog);
        let scan = read_ids(&mut coord, q, &IndexCatalog::empty());
        assert_eq!(
            seek, scan,
            "short/empty-needle seek must match the scan for {q:?}"
        );
    }
}

#[test]
fn drop_text_index_removes_it_and_ddl_is_idempotent() {
    let mut coord = fresh_coord();
    seed_people(&mut coord);
    coord
        .create_text_index("tx_person_name", "Person", "name", false)
        .expect("create text index");
    assert_eq!(coord.list_text_indexes().len(), 1);

    // DROP removes it (durable + in-memory); the catalog no longer surfaces a text seek.
    assert!(
        coord
            .drop_text_index("tx_person_name", false)
            .expect("drop"),
        "dropping an existing index mutates"
    );
    assert!(coord.list_text_indexes().is_empty());
    let plan = compile_with(
        "MATCH (n:Person) WHERE n.name CONTAINS 'obe' RETURN n.id AS id",
        &coord.catalog(),
    );
    assert!(
        !plan.to_string().contains("NodeTextIndexSeek"),
        "after DROP, the planner no longer routes through the text seek:\n{plan}"
    );

    // A second DROP of the now-missing index errors without IF EXISTS and is a no-op with it.
    assert!(
        coord.drop_text_index("tx_person_name", false).is_err(),
        "dropping a missing index without IF EXISTS errors"
    );
    assert!(
        !coord
            .drop_text_index("tx_person_name", true)
            .expect("IF EXISTS is a clean no-op"),
        "dropping a missing index with IF EXISTS does not mutate"
    );
}
