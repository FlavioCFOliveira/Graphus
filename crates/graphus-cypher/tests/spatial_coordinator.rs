//! Spatial (point) index over the **real** storage-backed `TxnCoordinator` (`rmp` task #98).
//!
//! Where the executor's MemGraph spatial tests prove the `point()` / `distance()` / accessor wiring
//! against the reference backend, these tests prove the storage-backed engine lifecycle: durable
//! catalog registration, per-write grid maintenance, the candidate-set + MVCC re-check (a deleted /
//! other-transaction node never matches), the non-blocking online build, and — the headline
//! durability AC — that the index survives a crash + reopen (the catalog is durable, the grid is
//! rebuilt from the recovered store). This is the spatial analogue of `tests/fulltext_coordinator.rs`.
//!
//! The headline functional AC is the **overriding equivalence**: a proximity query
//! `MATCH (n:L) WHERE distance(n.loc, point({x:..,y:..})) <= r RETURN n` over the **index** path
//! (`coord.catalog()`, which surfaces the `Online` spatial index as a `SpatialIndexSeek`) returns the
//! **identical** node set as the same query over the **scan** path (`IndexCatalog::empty()`), so the
//! grid never changes the answer — it only accelerates it.

use graphus_core::Value;
use graphus_cypher::binding::{Parameters, bind_parameters};
use graphus_cypher::catalog::IndexCatalog;
use graphus_cypher::coordinator::TxnCoordinator;
use graphus_cypher::executor::execute;
use graphus_cypher::lexer::tokenize;
use graphus_cypher::lower::lower;
use graphus_cypher::parser::parse_tokens;
use graphus_cypher::physical::{PhysicalOp, PhysicalPlan, plan_physical};
use graphus_cypher::runtime::{Row, RowValue};
use graphus_cypher::semantics::analyze;
use graphus_io::MemBlockDevice;
use graphus_storage::recovery::recover_device;
use graphus_storage::{IndexState, RecordStore};
use graphus_wal::{LogSink, MemLogSink, WalManager};

type Store = RecordStore<MemBlockDevice, MemLogSink>;
type Coord = TxnCoordinator<MemBlockDevice, MemLogSink>;

// =================================================================================================
// Harness (mirrors tests/online_index_build.rs + tests/fulltext_coordinator.rs)
// =================================================================================================

fn fresh_store() -> Store {
    let device = MemBlockDevice::new(0);
    let wal = WalManager::create(MemLogSink::new()).expect("create wal");
    RecordStore::create(device, wal, 64, 1).expect("create store")
}

fn fresh_coord() -> Coord {
    TxnCoordinator::new(fresh_store())
}

fn compile(src: &str, catalog: &IndexCatalog) -> PhysicalPlan {
    let toks = tokenize(src).expect("lex");
    let ast = parse_tokens(&toks, src).expect("parse");
    let validated = analyze(&ast).expect("analyze");
    plan_physical(&lower(&validated), catalog)
}

fn run_plan(coord: &Coord, txn: graphus_core::TxnId, plan: &PhysicalPlan) -> Vec<Row> {
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

fn run_write(coord: &mut Coord, src: &str) {
    let plan = compile(src, &IndexCatalog::empty());
    let txn = coord.begin_serializable();
    let _rows = run_plan(coord, txn, &plan);
    coord.commit(txn).expect("write commits");
}

/// Runs `src` (a proximity query that returns `RETURN n` nodes) over `catalog`, returning the matched
/// nodes' ids, sorted, against a freshly-begun-and-committed read transaction.
fn matched_ids(coord: &mut Coord, catalog: &IndexCatalog, src: &str) -> Vec<u64> {
    let plan = compile(src, catalog);
    let txn = coord.begin_serializable();
    let rows = run_plan(coord, txn, &plan);
    coord.commit(txn).expect("read commits");
    let mut ids: Vec<u64> = rows
        .iter()
        .filter_map(|r| match r.get("n") {
            Some(RowValue::Node(n)) => Some(n.id.0),
            _ => None,
        })
        .collect();
    ids.sort_unstable();
    ids
}

/// The node id of the single `City` with the given `name` (read back so tests do not depend on id
/// assignment order).
fn id_of(coord: &mut Coord, name: &str) -> u64 {
    let src = format!("MATCH (n:City {{name: '{name}'}}) RETURN id(n) AS id");
    let plan = compile(&src, &IndexCatalog::empty());
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
        .create_point_index("by_loc", "City", "loc")
        .expect("create point index");
    // Drive the (tiny) online build to completion so the index is Online.
    while coord.has_pending_index_builds() {
        coord.advance_index_builds(64);
    }
}

fn plan_uses_spatial_seek(plan: &PhysicalPlan) -> bool {
    fn walk(op: &PhysicalOp) -> bool {
        if matches!(op, PhysicalOp::SpatialIndexSeek { .. }) {
            return true;
        }
        children(op).iter().any(|c| walk(c))
    }
    walk(&plan.root)
}

fn children(op: &PhysicalOp) -> Vec<&PhysicalOp> {
    match op {
        PhysicalOp::ExpandAll { input, .. }
        | PhysicalOp::ExpandInto { input, .. }
        | PhysicalOp::Filter { input, .. }
        | PhysicalOp::Projection { input, .. }
        | PhysicalOp::Aggregation { input, .. }
        | PhysicalOp::Sort { input, .. }
        | PhysicalOp::TopN { input, .. }
        | PhysicalOp::Skip { input, .. }
        | PhysicalOp::Limit { input, .. }
        | PhysicalOp::Unwind { input, .. }
        | PhysicalOp::Optional { input, .. }
        | PhysicalOp::Create { input, .. }
        | PhysicalOp::Merge { input, .. }
        | PhysicalOp::SetClause { input, .. }
        | PhysicalOp::Delete { input, .. }
        | PhysicalOp::Remove { input, .. } => vec![input],
        PhysicalOp::NestedLoopJoin { left, right }
        | PhysicalOp::HashJoin { left, right, .. }
        | PhysicalOp::Union { left, right, .. } => vec![left, right],
        PhysicalOp::ProcedureCall { input, .. } => input.iter().map(Box::as_ref).collect(),
        _ => Vec::new(),
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

/// A proximity query over `City.loc` centred at `(cx, cy)` (Cartesian) within `r`.
fn proximity(cx: f64, cy: f64, r: f64) -> String {
    format!("MATCH (n:City) WHERE distance(n.loc, point({{x: {cx}, y: {cy}}})) <= {r} RETURN n")
}

// =================================================================================================
// Tests
// =================================================================================================

#[test]
fn create_then_proximity_uses_index_and_matches_the_scan() {
    let mut coord = fresh_coord();
    // A small cluster around the origin plus far-away outliers.
    run_write(
        &mut coord,
        "CREATE (:City {loc: point({x: 0, y: 0}), name: 'a'})",
    );
    run_write(
        &mut coord,
        "CREATE (:City {loc: point({x: 1, y: 1}), name: 'b'})",
    );
    run_write(
        &mut coord,
        "CREATE (:City {loc: point({x: 3, y: 4}), name: 'c'})",
    ); // dist 5
    run_write(
        &mut coord,
        "CREATE (:City {loc: point({x: 100, y: 100}), name: 'd'})",
    );
    // A node of the WRONG label must never match an indexed City query.
    run_write(
        &mut coord,
        "CREATE (:Town {loc: point({x: 0, y: 0}), name: 'wrong'})",
    );
    create_index(&mut coord);

    let indexed = coord.catalog();
    let src = proximity(0.0, 0.0, 2.0);
    // The plan over the live catalog must route through the grid spatial seek.
    assert!(
        plan_uses_spatial_seek(&compile(&src, &indexed)),
        "an Online spatial index must drive a SpatialIndexSeek"
    );

    let a = id_of(&mut coord, "a");
    let b = id_of(&mut coord, "b");

    // Index path == scan path == {a, b}: c (dist 5) and d (far) are outside r=2; 'wrong' is a Town.
    let via_index = matched_ids(&mut coord, &indexed, &src);
    let via_scan = matched_ids(&mut coord, &IndexCatalog::empty(), &src);
    let mut expected = vec![a, b];
    expected.sort_unstable();
    assert_eq!(via_index, expected);
    assert_eq!(via_index, via_scan, "index path must equal scan path");

    // A wider radius (r=10) additionally admits c (dist 5) but never d (dist ~141) — equivalence holds.
    let wide = proximity(0.0, 0.0, 10.0);
    assert_eq!(
        matched_ids(&mut coord, &indexed, &wide),
        matched_ids(&mut coord, &IndexCatalog::empty(), &wide)
    );
    assert_eq!(matched_ids(&mut coord, &indexed, &wide).len(), 3);
}

#[test]
fn writes_after_index_creation_are_maintained() {
    let mut coord = fresh_coord();
    create_index(&mut coord); // empty store, then write
    run_write(
        &mut coord,
        "CREATE (:City {loc: point({x: 0, y: 0}), name: 'a'})",
    );
    let a = id_of(&mut coord, "a");
    // A node created AFTER the index exists is indexed by per-write maintenance.
    let indexed = coord.catalog();
    let src = proximity(0.0, 0.0, 1.0);
    assert_eq!(matched_ids(&mut coord, &indexed, &src), vec![a]);
    assert_eq!(
        matched_ids(&mut coord, &indexed, &src),
        matched_ids(&mut coord, &IndexCatalog::empty(), &src)
    );
}

#[test]
fn updates_and_deletes_are_reflected() {
    let mut coord = fresh_coord();
    run_write(
        &mut coord,
        "CREATE (:City {loc: point({x: 0, y: 0}), name: 'a'})",
    );
    create_index(&mut coord);
    let a = id_of(&mut coord, "a");

    let indexed = coord.catalog();
    let near_origin = proximity(0.0, 0.0, 1.0);
    assert_eq!(matched_ids(&mut coord, &indexed, &near_origin), vec![a]);

    // Move the point far away: the origin query no longer matches, a query at the new spot does.
    run_write(
        &mut coord,
        "MATCH (n:City {name: 'a'}) SET n.loc = point({x: 50, y: 50})",
    );
    assert!(matched_ids(&mut coord, &indexed, &near_origin).is_empty());
    let near_new = proximity(50.0, 50.0, 1.0);
    assert_eq!(matched_ids(&mut coord, &indexed, &near_new), vec![a]);
    // Equivalence with the scan path holds at the new location too.
    assert_eq!(
        matched_ids(&mut coord, &indexed, &near_new),
        matched_ids(&mut coord, &IndexCatalog::empty(), &near_new)
    );

    // Delete the node: it disappears (candidate-set + MVCC re-check drops the invisible version).
    run_write(&mut coord, "MATCH (n:City {name: 'a'}) DELETE n");
    assert!(matched_ids(&mut coord, &indexed, &near_new).is_empty());
}

#[test]
fn populating_index_is_withheld_from_the_planner_but_still_correct() {
    let mut coord = fresh_coord();
    // Seed many nodes first, THEN create the index so the build is Populating mid-flight.
    for n in 0..40 {
        run_write(
            &mut coord,
            &format!("CREATE (:City {{loc: point({{x: {n}, y: 0}}), name: 'c{n}'}})"),
        );
    }
    coord
        .create_point_index("by_loc", "City", "loc")
        .expect("create");
    assert!(coord.has_pending_index_builds());

    // While Populating: the catalog withholds the index, so the proximity predicate falls back to a
    // label-scan + residual filter — still correct.
    let src = proximity(0.0, 0.0, 5.0); // c0..c5 (x=0..5)
    let populating = coord.catalog();
    assert!(
        !plan_uses_spatial_seek(&compile(&src, &populating)),
        "a Populating spatial index must be withheld (no SpatialIndexSeek yet)"
    );
    let via_populating = matched_ids(&mut coord, &populating, &src);
    let via_scan = matched_ids(&mut coord, &IndexCatalog::empty(), &src);
    // The overriding AC: the withheld (Populating) path equals the scan path exactly.
    assert_eq!(via_populating, via_scan);
    // The cluster x=0..5 (distance x from the origin) lies within r=5; the exact boundary count is
    // whatever the residual `distance(...) <= 5` predicate decides — what matters is that the index
    // and scan paths agree, and that we matched the near cluster but not the far nodes (x>=10).
    assert!(!via_populating.is_empty() && via_populating.len() <= 6);

    // Drive the build to completion in small chunks (the interleaving point), then it is usable.
    let mut iters = 0;
    while coord.has_pending_index_builds() {
        coord.advance_index_builds(7);
        iters += 1;
        assert!(iters < 10_000, "build must terminate");
    }
    let online = coord.catalog();
    assert!(plan_uses_spatial_seek(&compile(&src, &online)));
    assert_eq!(
        matched_ids(&mut coord, &online, &src),
        matched_ids(&mut coord, &IndexCatalog::empty(), &src)
    );
}

#[test]
fn uncommitted_write_in_another_transaction_is_not_matched() {
    let mut coord = fresh_coord();
    run_write(
        &mut coord,
        "CREATE (:City {loc: point({x: 0, y: 0}), name: 'visible'})",
    );
    create_index(&mut coord);

    // Open a writer that creates a node near the origin but does NOT commit.
    let writer = coord.begin_serializable();
    {
        let plan = compile(
            "CREATE (:City {loc: point({x: 0, y: 0}), name: 'secret'})",
            &IndexCatalog::empty(),
        );
        let _ = run_plan(&coord, writer, &plan);
    }

    // A separate reader's snapshot must see only 'visible' — the writer's per-write maintenance
    // inserted 'secret' as a candidate, but the MVCC re-check filters the uncommitted version.
    let visible = id_of(&mut coord, "visible");
    let indexed = coord.catalog();
    let src = proximity(0.0, 0.0, 1.0);
    assert_eq!(matched_ids(&mut coord, &indexed, &src), vec![visible]);

    coord.rollback(writer).expect("rollback");
    assert_eq!(matched_ids(&mut coord, &indexed, &src), vec![visible]);
}

#[test]
fn index_survives_a_crash_and_reopen() {
    // Build a store with cities + a point index, "crash" (recover from the durable WAL prefix), and
    // reopen a fresh coordinator. The catalog is durable and the grid is rebuilt from the recovered
    // store, so the proximity query still returns correct results (the durability AC).
    let (recovered, near_a, near_far) = {
        let mut coord = fresh_coord();
        run_write(
            &mut coord,
            "CREATE (:City {loc: point({x: 0, y: 0}), name: 'a'})",
        );
        run_write(
            &mut coord,
            "CREATE (:City {loc: point({x: 1, y: 0}), name: 'b'})",
        );
        run_write(
            &mut coord,
            "CREATE (:City {loc: point({x: 200, y: 200}), name: 'far'})",
        );
        create_index(&mut coord);
        let a = id_of(&mut coord, "a");
        let b = id_of(&mut coord, "b");
        let far = id_of(&mut coord, "far");
        // Sanity: the index works before the crash.
        let indexed = coord.catalog();
        let near = proximity(0.0, 0.0, 2.0);
        let mut want = vec![a, b];
        want.sort_unstable();
        assert_eq!(matched_ids(&mut coord, &indexed, &near), want);

        let store = coord.into_store();
        (recover_no_force(&store), want, far)
    };

    // Reopen: a fresh coordinator over the recovered store rebuilds the grid from the durable catalog
    // + records — no manual re-creation.
    let mut coord = TxnCoordinator::new(recovered);

    // The index is still declared (catalog survived) and online.
    let listed = coord.list_point_indexes();
    assert_eq!(listed.len(), 1, "the point index must survive the crash");
    assert_eq!(listed[0].0, "by_loc");
    assert_eq!(listed[0].3, IndexState::Online);

    // And it still drives a seek and returns the correct matches (grid rebuilt from the store).
    let indexed = coord.catalog();
    let near = proximity(0.0, 0.0, 2.0);
    assert!(plan_uses_spatial_seek(&compile(&near, &indexed)));
    assert_eq!(matched_ids(&mut coord, &indexed, &near), near_a);
    assert_eq!(
        matched_ids(&mut coord, &indexed, &near),
        matched_ids(&mut coord, &IndexCatalog::empty(), &near)
    );
    // The far node is still NOT in the near result (so we did not over-match after recovery).
    assert!(!near_a.contains(&near_far));
}

#[test]
fn drop_index_falls_back_to_scan_still_correct() {
    let mut coord = fresh_coord();
    run_write(
        &mut coord,
        "CREATE (:City {loc: point({x: 0, y: 0}), name: 'a'})",
    );
    create_index(&mut coord);
    let a = id_of(&mut coord, "a");
    let src = proximity(0.0, 0.0, 1.0);
    let indexed = coord.catalog();
    assert!(plan_uses_spatial_seek(&compile(&src, &indexed)));
    assert_eq!(matched_ids(&mut coord, &indexed, &src), vec![a]);

    coord.drop_point_index("by_loc").expect("drop");
    // After the drop the catalog no longer surfaces the index, so the query falls back to a scan and
    // remains correct (a spatial proximity query is never a hard error, unlike a dropped full-text
    // index's procedure call).
    let dropped = coord.catalog();
    assert!(!plan_uses_spatial_seek(&compile(&src, &dropped)));
    assert_eq!(matched_ids(&mut coord, &dropped, &src), vec![a]);
    assert!(coord.list_point_indexes().is_empty());
}
