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
    compile_cat(src, &IndexCatalog::empty())
}

/// Compiles `src` against a specific `catalog` (so a query can be planned with vs without the
/// relationship-property index available), for the `rmp` #659 seek tests.
fn compile_cat(src: &str, catalog: &IndexCatalog) -> PhysicalPlan {
    let toks = tokenize(src).expect("lex");
    let ast = parse_tokens(&toks, src).expect("parse");
    let validated = analyze(&ast).expect("analyze");
    plan_physical(&lower(&validated), catalog)
}

/// Whether a physical plan uses a [`RelIndexSeek`] anywhere (rendered via the plan's Display).
fn is_rel_seek(plan: &PhysicalPlan) -> bool {
    plan.root.to_string().contains("RelIndexSeek")
}

/// Runs a read query in its own committed transaction, returning the raw result rows (`rmp` #659).
fn run_read(coord: &mut Coord, plan: &PhysicalPlan, params: &Parameters) -> Vec<Row> {
    let txn = coord.begin_serializable();
    let bound = bind_parameters(plan, params).expect("bind");
    let rows = {
        let mut graph = coord.statement(txn).expect("statement");
        let mut cursor = execute(plan, &bound, &mut graph).expect("open cursor");
        cursor.collect_all().expect("collect")
    };
    coord.commit(txn).expect("read commits");
    rows
}

fn as_int(v: &Value) -> i64 {
    match v {
        Value::Integer(i) => *i,
        other => panic!("expected an integer, got {other:?}"),
    }
}

/// The sorted `(id(a), id(r), id(b))` triples of rows projected as `a`/`rr`/`b` — the row-identity
/// witness for the seek-vs-scan parity comparison (captures relationship identity AND endpoint
/// orientation, so an undirected pattern's two orientations and a self-loop are distinguished).
fn triples(rows: &[Row]) -> Vec<(i64, i64, i64)> {
    let mut out: Vec<(i64, i64, i64)> = rows
        .iter()
        .map(|r| {
            (
                as_int(&r.value("a")),
                as_int(&r.value("rr")),
                as_int(&r.value("b")),
            )
        })
        .collect();
    out.sort_unstable();
    out
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

// =================================================================================================
// Relationship-property index SEEK (`rmp` task #659)
// =================================================================================================

#[test]
fn rel_equality_lowers_to_seek_only_when_the_index_is_present() {
    // A standalone single-type, fixed-length relationship-equality — via the inline map *or* an
    // explicit `WHERE` — seeks the rel-property index when it covers `(type, property)`; with no such
    // index (or on a non-covered property/type) it stays a scan + filter (`rmp` task #659).
    let indexed = IndexCatalog::builder()
        .with_rel_property("KNOWS", "since")
        .build();
    let empty = IndexCatalog::empty();

    for src in [
        "MATCH ()-[r:KNOWS {since: $x}]-() RETURN r",
        "MATCH ()-[r:KNOWS]-() WHERE r.since = $x RETURN r",
        "MATCH (a)-[r:KNOWS {since: $x}]->(b) RETURN r",
    ] {
        assert!(
            is_rel_seek(&compile_cat(src, &indexed)),
            "expected a RelIndexSeek with the index present: {src}"
        );
        assert!(
            !is_rel_seek(&compile_cat(src, &empty)),
            "without the index the same query must stay a scan + filter: {src}"
        );
    }

    // The index covers only `(KNOWS, since)`: a different property or a different type stays a scan.
    for src in [
        "MATCH ()-[r:KNOWS {note: $x}]-() RETURN r", // property not indexed
        "MATCH ()-[r:LIKES {since: $x}]-() RETURN r", // type not indexed
    ] {
        assert!(
            !is_rel_seek(&compile_cat(src, &indexed)),
            "a non-covered (type, property) must not seek: {src}"
        );
    }
}

#[test]
fn non_seekable_rel_shapes_stay_scans() {
    // Shapes the equality-only, single-type, standalone rel seek must NOT claim (`rmp` task #659):
    // variable-length, multiple types (no single-type index), a range predicate, `OPTIONAL MATCH`
    // (its anchor is an `Apply`-over-`Argument`, never a bare all-nodes scan), and a label-constrained
    // anchor (a label scan, not an all-nodes scan). Each must remain a scan + filter.
    let indexed = IndexCatalog::builder()
        .with_rel_property("KNOWS", "since")
        .build();
    for src in [
        "MATCH ()-[r:KNOWS*]-() WHERE r.since = $x RETURN r",
        "MATCH ()-[r:KNOWS|LIKES {since: $x}]-() RETURN r",
        "MATCH ()-[r:KNOWS]-() WHERE r.since > $x RETURN r",
        "OPTIONAL MATCH ()-[r:KNOWS {since: $x}]-() RETURN r",
        "MATCH (a:P)-[r:KNOWS {since: $x}]->(b) RETURN r",
    ] {
        let plan = compile_cat(src, &indexed);
        assert!(
            !is_rel_seek(&plan),
            "this shape must stay a scan, got a seek: {src}\n{}",
            plan.root
        );
    }
}

#[test]
fn rel_seek_rows_match_the_scan_filter_rows_across_directions_and_self_loops() {
    // Execution parity: the `RelIndexSeek` returns the identical row multiset as the
    // `IndexCatalog::empty()` typed-scan + filter plan over the same populated relationship index —
    // for a directed, a reverse-directed, and an undirected pattern (the last binding both endpoint
    // orientations), with a duplicate value, a distinct value, a self-loop and a wrong-type edge in
    // the graph to exercise every branch (`rmp` task #659).
    let mut coord = fresh_coord();
    run_write(&mut coord, "CREATE (:P {n: 1}), (:P {n: 2}), (:P {n: 3})");
    run_write(
        &mut coord,
        "MATCH (a:P {n: 1}), (b:P {n: 2}) CREATE (a)-[:KNOWS {since: 2020}]->(b)",
    );
    run_write(
        &mut coord,
        "MATCH (a:P {n: 2}), (b:P {n: 3}) CREATE (a)-[:KNOWS {since: 2020}]->(b)",
    );
    run_write(
        &mut coord,
        "MATCH (a:P {n: 1}), (b:P {n: 3}) CREATE (a)-[:KNOWS {since: 2021}]->(b)",
    );
    // A self-loop with the matching value: undirected must bind it exactly once (not twice).
    run_write(
        &mut coord,
        "MATCH (a:P {n: 1}) CREATE (a)-[:KNOWS {since: 2020}]->(a)",
    );
    // A wrong-type edge with the matching value: never matched.
    run_write(
        &mut coord,
        "MATCH (a:P {n: 2}), (b:P {n: 3}) CREATE (a)-[:LIKES {since: 2020}]->(b)",
    );
    coord
        .create_rel_property_index_named(Some("ix_since"), "KNOWS", "since", false)
        .expect("create rel-property index");

    let indexed = coord.catalog();
    let empty = IndexCatalog::empty();
    let params = Parameters::new().with("x", Value::Integer(2020));

    for pattern in [
        "MATCH (a)-[r:KNOWS {since: $x}]->(b) RETURN id(a) AS a, id(r) AS rr, id(b) AS b",
        "MATCH (a)<-[r:KNOWS {since: $x}]-(b) RETURN id(a) AS a, id(r) AS rr, id(b) AS b",
        "MATCH (a)-[r:KNOWS {since: $x}]-(b) RETURN id(a) AS a, id(r) AS rr, id(b) AS b",
    ] {
        let seek_plan = compile_cat(pattern, &indexed);
        let scan_plan = compile_cat(pattern, &empty);
        assert!(
            is_rel_seek(&seek_plan),
            "expected a seek for: {pattern}\n{}",
            seek_plan.root
        );
        assert!(
            !is_rel_seek(&scan_plan),
            "the empty-catalog plan must scan: {pattern}"
        );

        let seek_rows = triples(&run_read(&mut coord, &seek_plan, &params));
        let scan_rows = triples(&run_read(&mut coord, &scan_plan, &params));
        assert!(!seek_rows.is_empty(), "{pattern} should match something");
        assert_eq!(
            seek_rows, scan_rows,
            "seek and scan+filter rows must be identical for: {pattern}"
        );
    }
}

#[test]
fn rel_seek_excludes_a_deleted_relationship() {
    // MVCC re-check: after a matching relationship is deleted, the seek's candidate re-check (via
    // `rel_data`) drops it even though a stale index entry may still name it — so a deleted
    // relationship is never returned (`rmp` task #659).
    let mut coord = fresh_coord();
    run_write(
        &mut coord,
        "CREATE (:P {n: 1})-[:KNOWS {since: 2020}]->(:P {n: 2})",
    );
    coord
        .create_rel_property_index_named(Some("ix_since"), "KNOWS", "since", false)
        .expect("create rel-property index");
    let indexed = coord.catalog();
    let params = Parameters::new().with("x", Value::Integer(2020));
    let plan = compile_cat(
        "MATCH ()-[r:KNOWS {since: $x}]->() RETURN id(r) AS rr",
        &indexed,
    );
    assert!(is_rel_seek(&plan), "expected a seek:\n{}", plan.root);

    assert_eq!(
        run_read(&mut coord, &plan, &params).len(),
        1,
        "the live relationship is seeked"
    );
    run_write(&mut coord, "MATCH ()-[r:KNOWS {since: 2020}]->() DELETE r");
    assert!(
        run_read(&mut coord, &plan, &params).is_empty(),
        "a deleted relationship must not be returned by the seek"
    );
}

#[test]
fn rel_seek_hides_an_uncommitted_relationship_from_a_concurrent_reader() {
    // MVCC visibility: a concurrent writer's UNCOMMITTED matching relationship is already present in
    // the shared in-memory rel index (maintained at write time), yet the seek's per-candidate
    // visibility re-check drops it for a reader whose snapshot predates the (never-committed) write —
    // so an uncommitted relationship is never returned (`rmp` task #659).
    let mut coord = fresh_coord();
    run_write(&mut coord, "CREATE (:P {n: 1}), (:P {n: 2})");
    run_write(
        &mut coord,
        "MATCH (a:P {n: 1}), (b:P {n: 2}) CREATE (a)-[:KNOWS {since: 2020}]->(b)",
    );
    coord
        .create_rel_property_index_named(Some("ix_since"), "KNOWS", "since", false)
        .expect("create rel-property index");
    let indexed = coord.catalog();
    let params = Parameters::new().with("x", Value::Integer(2020));
    let plan = compile_cat(
        "MATCH ()-[r:KNOWS {since: $x}]->() RETURN id(r) AS rr",
        &indexed,
    );
    assert!(is_rel_seek(&plan), "expected a seek:\n{}", plan.root);

    assert_eq!(
        run_read(&mut coord, &plan, &params).len(),
        1,
        "one committed match"
    );

    // A concurrent writer adds a SECOND matching relationship but does not commit; its maintenance
    // has already inserted the value into the shared in-memory index.
    let writer = coord.begin_serializable();
    {
        let wplan =
            compile("MATCH (a:P {n: 1}), (b:P {n: 2}) CREATE (a)-[:KNOWS {since: 2020}]->(b)");
        let bound = bind_parameters(&wplan, &Parameters::new()).expect("bind");
        let mut graph = coord.statement(writer).expect("statement");
        let mut cursor = execute(&wplan, &bound, &mut graph).expect("open cursor");
        let _ = cursor.collect_all().expect("collect");
    }
    assert_eq!(
        run_read(&mut coord, &plan, &params).len(),
        1,
        "the uncommitted relationship must be invisible to the seek"
    );
    coord.rollback(writer).expect("rollback the writer");
    assert_eq!(
        run_read(&mut coord, &plan, &params).len(),
        1,
        "after rollback only the original committed relationship remains"
    );
}
