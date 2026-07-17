//! Non-blocking ("online") node-property index builds (`rmp` task #91, EPIC #66): a `CREATE INDEX`
//! starts a background build that indexes a snapshot of the live nodes in bounded chunks while the
//! engine stays responsive, then promotes the index to `Online`.
//!
//! The correctness model is the candidate-set + read-time re-check contract (`crate::index_set`):
//! every seek returns a **superset** of the matching ids and the executor re-checks MVCC visibility,
//! the current label, and the current value, so a duplicate/stale candidate is harmless — a
//! **missing** candidate is the only error. These tests prove the online build never misses a result
//! even when writes (creates / value changes / deletes) interleave with the build, and that an
//! interrupted build recovers `Online` after a crash.
//!
//! The harness mirrors `tests/index_wiring.rs`: a `TxnCoordinator` over an in-memory store, the same
//! `compile` / `run_plan` / `has_index_seek` / `seed_people` / `recover_no_force` helpers, and the
//! same overriding equivalence assertion (index path == scan + residual-filter path, as a set).

use graphus_core::Value;
use graphus_cypher::binding::{Parameters, bind_parameters};
use graphus_cypher::catalog::IndexCatalog;
use graphus_cypher::coordinator::TxnCoordinator;
use graphus_cypher::executor::execute;
use graphus_cypher::lexer::tokenize;
use graphus_cypher::lower::lower;
use graphus_cypher::parser::parse_tokens;
use graphus_cypher::physical::{PhysicalOp, PhysicalPlan, plan_physical};
use graphus_cypher::runtime::Row;
use graphus_cypher::semantics::analyze;
use graphus_index::fulltext::Analyzer;
use graphus_io::MemBlockDevice;
use graphus_storage::recovery::recover_device;
use graphus_storage::{IndexState, RecordStore};
use graphus_wal::{LogSink, MemLogSink, WalManager};

type Store = RecordStore<MemBlockDevice, MemLogSink>;
type Coord = TxnCoordinator<MemBlockDevice, MemLogSink>;

// =================================================================================================
// Harness (mirrors tests/index_wiring.rs)
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

fn read_sorted_ints(coord: &mut Coord, catalog: &IndexCatalog, src: &str, col: &str) -> Vec<i64> {
    let plan = compile(src, catalog);
    let txn = coord.begin_serializable();
    let rows = run_plan(coord, txn, &plan);
    coord.commit(txn).expect("read commits");
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

fn run_write(coord: &mut Coord, src: &str) {
    let plan = compile(src, &IndexCatalog::empty());
    let txn = coord.begin_serializable();
    let _rows = run_plan(coord, txn, &plan);
    coord.commit(txn).expect("write commits");
}

fn plan_contains(plan: &PhysicalPlan, pred: &dyn Fn(&PhysicalOp) -> bool) -> bool {
    fn walk(op: &PhysicalOp, pred: &dyn Fn(&PhysicalOp) -> bool) -> bool {
        if pred(op) {
            return true;
        }
        children(op).iter().any(|c| walk(c, pred))
    }
    walk(&plan.root, pred)
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

fn has_index_seek(plan: &PhysicalPlan) -> bool {
    plan_contains(plan, &|op| matches!(op, PhysicalOp::NodeIndexSeek { .. }))
}

fn has_index_range_seek(plan: &PhysicalPlan) -> bool {
    plan_contains(plan, &|op| {
        matches!(op, PhysicalOp::NodeIndexRangeSeek { .. })
    })
}

fn has_token_lookup(plan: &PhysicalPlan) -> bool {
    plan_contains(plan, &|op| matches!(op, PhysicalOp::TokenLookupScan { .. }))
}

/// Seeds a representative graph: many `(:Person {age: N})`, a couple without `age`, and non-Person
/// nodes that must never leak into a `:Person` result whether scanned or sought.
fn seed_people(coord: &mut Coord) {
    for age in 20..=40 {
        run_write(coord, &format!("CREATE (:Person {{age: {age}}})"));
    }
    run_write(coord, "CREATE (:Person {age: 30})"); // duplicate value 30
    run_write(coord, "CREATE (:Person {name: 'no-age-1'})");
    run_write(coord, "CREATE (:Person {name: 'no-age-2'})");
    run_write(coord, "CREATE (:Company {age: 30})"); // non-Person carrying `age` 30
    run_write(coord, "CREATE (:Company {founded: 1999})");
}

/// Recovers a no-force crash (mirrors `tests/index_wiring.rs::recover_no_force`).
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

/// Drives the front pending build to completion in **small** chunks, asserting the index is
/// `Populating` until the very last chunk flips it `Online`.
fn drive_build_to_completion(coord: &mut Coord) {
    // A deliberately small chunk so the build spans several `advance` calls (the interleaving point).
    const CHUNK: usize = 3;
    let mut iterations = 0;
    while coord.has_pending_index_builds() {
        coord.advance_index_builds(CHUNK);
        iterations += 1;
        assert!(iterations < 100_000, "build must terminate");
    }
}

// =================================================================================================
// (a) Online build + concurrent writes == scan/full-rebuild, ending Online
// =================================================================================================

#[test]
fn online_build_with_interleaved_writes_equals_scan_and_ends_online() {
    let mut coord = fresh_coord();
    seed_people(&mut coord);

    // Start the NON-BLOCKING build: it returns promptly with the index `Populating`.
    coord
        .begin_online_node_property_index("Person", "age")
        .expect("begin online index");
    assert!(coord.has_pending_index_builds(), "build is enqueued");

    // Drive the build in small chunks while interleaving concurrent committed writes between chunks:
    // a brand-new Person, a value change (SET), and a delete. Each is captured by `reindex_node` /
    // the candidate re-check, so none can be missed at completion.
    const CHUNK: usize = 4;
    let mut step = 0;
    while coord.has_pending_index_builds() {
        coord.advance_index_builds(CHUNK);
        match step {
            // A new node created after the snapshot (not in it — must still be indexed via the write).
            1 => run_write(&mut coord, "CREATE (:Person {age: 25})"),
            // Move the unique Person aged 40 to a fresh value 999 (old value becomes a stale candidate).
            2 => run_write(
                &mut coord,
                "MATCH (n:Person) WHERE n.age = 40 SET n.age = 999",
            ),
            // Delete every Person aged exactly 21 (their index entries linger as stale candidates).
            3 => run_write(&mut coord, "MATCH (n:Person) WHERE n.age = 21 DELETE n"),
            _ => {}
        }
        step += 1;
    }

    // The build completed: state is Online (durable catalog, surfaced via SHOW INDEXES) and the
    // planner now routes seeks.
    assert_eq!(
        coord.list_node_property_indexes(),
        vec![(
            "index_Person_age".to_owned(),
            "Person".to_owned(),
            "age".to_owned(),
            IndexState::Online
        )],
        "the durable catalog must read Online after the build completes"
    );
    let indexed = coord.catalog();
    let seek_plan = compile(
        "MATCH (n:Person) WHERE n.age = 30 RETURN n.age AS a",
        &indexed,
    );
    assert!(
        has_index_seek(&seek_plan),
        "after completion the planner must use a NodeIndexSeek:\n{seek_plan}"
    );

    // The KEY equivalence: every query against the freshly-built index returns EXACTLY the scan +
    // residual-filter rows, despite the concurrent writes during the build.
    for src in [
        "MATCH (n:Person) WHERE n.age = 30 RETURN n.age AS a", // duplicate survivors
        "MATCH (n:Person) WHERE n.age = 40 RETURN n.age AS a", // moved away → empty
        "MATCH (n:Person) WHERE n.age = 999 RETURN n.age AS a", // the moved node
        "MATCH (n:Person) WHERE n.age = 21 RETURN n.age AS a", // deleted → empty
        "MATCH (n:Person) WHERE n.age = 25 RETURN n.age AS a", // the new node + the seeded 25
        "MATCH (n:Person) WHERE n.age > 30 RETURN n.age AS a", // range over the changed region
        "MATCH (n:Person) RETURN n.age AS a",                  // bare label scan
    ] {
        let indexed = coord.catalog();
        let via_index = read_sorted_ints(&mut coord, &indexed, src, "a");
        let via_scan = read_sorted_ints(&mut coord, &IndexCatalog::empty(), src, "a");
        assert_eq!(
            via_index, via_scan,
            "`{src}`: online-built index must equal scan+filter (zero missed results)"
        );
    }
}

// =================================================================================================
// (b) While Populating, the planner does NOT use the index; once Online it does
// =================================================================================================

#[test]
fn populating_build_is_not_planner_visible_until_online() {
    let mut coord = fresh_coord();
    seed_people(&mut coord);

    coord
        .begin_online_node_property_index("Person", "age")
        .expect("begin online index");

    // While Populating: the catalog withholds the *property* index, so an eq/range predicate falls
    // back — but STILL returns exactly the scan rows. The eq predicate uses the precise full-scan
    // `NodeLabelScanEq` access path (`rmp` task #325; narrows the SSI footprint to the matches), the
    // range predicate uses the always-present label token-lookup + a residual `Filter`. Neither routes
    // a NodeIndexSeek/NodeIndexRangeSeek (the property index is invisible while Populating).
    let indexed = coord.catalog();
    for (src, is_eq) in [
        ("MATCH (n:Person) WHERE n.age = 30 RETURN n.age AS a", true),
        ("MATCH (n:Person) WHERE n.age > 30 RETURN n.age AS a", false),
    ] {
        let plan = compile(src, &indexed);
        assert!(
            !has_index_seek(&plan) && !has_index_range_seek(&plan),
            "a Populating index must NOT drive an index seek:\n{plan}"
        );
        if is_eq {
            assert!(
                plan.to_string().contains("NodeLabelScanEq"),
                "the Populating equality fallback must use the precise NodeLabelScanEq:\n{plan}"
            );
        } else {
            assert!(
                has_token_lookup(&plan),
                "the Populating range fallback must use a TokenLookupScan + Filter:\n{plan}"
            );
        }
        let via_catalog = read_sorted_ints(&mut coord, &indexed, src, "a");
        let via_scan = read_sorted_ints(&mut coord, &IndexCatalog::empty(), src, "a");
        assert_eq!(
            via_catalog, via_scan,
            "`{src}`: Populating fallback must equal scan+filter"
        );
    }

    // Drive the build to completion; now the planner routes seeks.
    drive_build_to_completion(&mut coord);
    let indexed = coord.catalog();
    assert!(
        has_index_seek(&compile(
            "MATCH (n:Person) WHERE n.age = 30 RETURN n.age AS a",
            &indexed
        )),
        "after promotion the planner must use a NodeIndexSeek"
    );
    assert!(
        has_index_range_seek(&compile(
            "MATCH (n:Person) WHERE n.age > 30 RETURN n.age AS a",
            &indexed
        )),
        "after promotion the planner must use a NodeIndexRangeSeek"
    );
    let via_index = read_sorted_ints(
        &mut coord,
        &indexed,
        "MATCH (n:Person) WHERE n.age = 30 RETURN n.age AS a",
        "a",
    );
    assert_eq!(via_index, vec![30, 30], "two Persons aged 30");
}

// =================================================================================================
// (c) A build interrupted by a crash recovers Online
// =================================================================================================

#[test]
fn build_interrupted_by_crash_recovers_online() {
    let mut coord = fresh_coord();
    // Seed FIRST so the build's snapshot is non-empty (otherwise a single advance completes it).
    seed_people(&mut coord);
    coord
        .begin_online_node_property_index("Person", "age")
        .expect("begin online index");

    // Advance only PART of the build (a tiny chunk over a multi-node snapshot), so the durable
    // catalog entry is still `Populating` when we crash.
    coord.advance_index_builds(2);
    assert!(
        coord.has_pending_index_builds(),
        "the build must still be in progress (partial advance)"
    );

    // Crash: reclaim the store and recover from the durable WAL alone. The catalog entry recovers
    // `Populating`; the fresh coordinator's `new` repopulates it fully and promotes it `Online`.
    let store = coord.into_store();
    let recovered = recover_no_force(&store);
    let mut coord2 = TxnCoordinator::new(recovered);

    assert!(
        !coord2.has_pending_index_builds(),
        "recovery completes the build synchronously: nothing left pending"
    );

    // The recovered index must be Online and planner-visible.
    let indexed = coord2.catalog();
    assert!(
        has_index_seek(&compile(
            "MATCH (n:Person) WHERE n.age = 30 RETURN n.age AS a",
            &indexed
        )),
        "the recovered index must be Online and drive a NodeIndexSeek"
    );

    for src in [
        "MATCH (n:Person) WHERE n.age = 30 RETURN n.age AS a",
        "MATCH (n:Person) WHERE n.age > 30 RETURN n.age AS a",
        "MATCH (n:Person) RETURN n.age AS a",
    ] {
        let indexed = coord2.catalog();
        let via_index = read_sorted_ints(&mut coord2, &indexed, src, "a");
        let via_scan = read_sorted_ints(&mut coord2, &IndexCatalog::empty(), src, "a");
        assert_eq!(
            via_index, via_scan,
            "`{src}`: post-recovery index must equal scan+filter over the recovered graph"
        );
    }

    // Sanity: the committed seed survived, so the equivalence above is not vacuous.
    let indexed = coord2.catalog();
    let any = read_sorted_ints(
        &mut coord2,
        &indexed,
        "MATCH (n:Person) WHERE n.age = 30 RETURN n.age AS a",
        "a",
    );
    assert_eq!(any, vec![30, 30], "the committed seed survived recovery");
}

// =================================================================================================
// DROP INDEX: removes the index (durable + in-memory) so the planner stops using it
// =================================================================================================

#[test]
fn drop_index_removes_it_from_planner_and_catalog() {
    let mut coord = fresh_coord();
    seed_people(&mut coord);
    coord
        .begin_online_node_property_index("Person", "age")
        .expect("begin online index");
    drive_build_to_completion(&mut coord);

    // The index is Online and used.
    let indexed = coord.catalog();
    assert!(has_index_seek(&compile(
        "MATCH (n:Person) WHERE n.age = 30 RETURN n.age AS a",
        &indexed
    )));
    assert_eq!(
        coord.list_node_property_indexes(),
        vec![(
            "index_Person_age".to_owned(),
            "Person".to_owned(),
            "age".to_owned(),
            IndexState::Online
        )],
        "SHOW INDEXES lists the online index with its auto-name"
    );

    // Drop it: the planner must stop routing seeks, the catalog is empty, and queries still answer
    // correctly via the scan path.
    coord
        .drop_node_property_index("Person", "age")
        .expect("drop index");
    assert!(
        coord.list_node_property_indexes().is_empty(),
        "the dropped index is gone from SHOW INDEXES"
    );
    let indexed = coord.catalog();
    let plan = compile(
        "MATCH (n:Person) WHERE n.age = 30 RETURN n.age AS a",
        &indexed,
    );
    assert!(
        !has_index_seek(&plan),
        "after DROP the planner must not use a NodeIndexSeek:\n{plan}"
    );
    let via_catalog = read_sorted_ints(
        &mut coord,
        &indexed,
        "MATCH (n:Person) WHERE n.age = 30 RETURN n.age AS a",
        "a",
    );
    assert_eq!(
        via_catalog,
        vec![30, 30],
        "scan path still correct after DROP"
    );

    // Dropping an absent index is a clean no-op.
    coord
        .drop_node_property_index("Person", "age")
        .expect("drop absent index is a no-op");
    coord
        .drop_node_property_index("Ghost", "nope")
        .expect("drop unknown tokens is a no-op");
}

// =================================================================================================
// A second build queues behind the first and both complete in order
// =================================================================================================

#[test]
fn two_builds_queue_and_complete_in_order() {
    let mut coord = fresh_coord();
    run_write(&mut coord, "CREATE (:Person {age: 1})");
    run_write(&mut coord, "CREATE (:Tag {name: 'x'})");

    coord
        .begin_online_node_property_index("Person", "age")
        .expect("begin first");
    coord
        .begin_online_node_property_index("Tag", "name")
        .expect("begin second");

    drive_build_to_completion(&mut coord);

    let mut listed = coord.list_node_property_indexes();
    listed.sort();
    assert_eq!(
        listed,
        vec![
            (
                "index_Person_age".to_owned(),
                "Person".to_owned(),
                "age".to_owned(),
                IndexState::Online
            ),
            (
                "index_Tag_name".to_owned(),
                "Tag".to_owned(),
                "name".to_owned(),
                IndexState::Online
            ),
        ],
        "both queued builds complete Online, each with its deterministic auto-name"
    );
}

// =================================================================================================
// Build progress (`rmp` task #573)
// =================================================================================================

/// `rmp` task #573: `index_build_progress` must report the build's REAL cursor against its snapshot —
/// the numerator and denominator `SHOW INDEXES`' `populationPercent` is computed from.
///
/// Non-vacuity: the progress is sampled at three points that must differ from one another (fresh, part
/// way, complete). An implementation that reported a constant — which is exactly what `populationPercent`
/// did before this task — cannot satisfy all three.
#[test]
fn index_build_progress_reports_the_real_cursor() {
    let mut coord = fresh_coord();
    seed_people(&mut coord);

    coord
        .begin_online_node_property_index("Person", "age")
        .expect("declare the build");

    // Fresh: the cursor is at zero and the snapshot covers every live node.
    let fresh = coord.index_build_progress();
    assert_eq!(fresh.len(), 1, "one build in flight: {fresh:?}");
    assert_eq!(fresh[0].done, 0, "a fresh build has indexed nothing");
    let total = fresh[0].total;
    assert!(
        total > 4,
        "the snapshot must span several nodes (got {total})"
    );
    assert!(!fresh[0].poisoned, "a healthy build is not poisoned");
    assert_eq!(
        fresh[0].name,
        graphus_cypher::auto_index_name("Person", "age"),
        "the build is reported under the name SHOW INDEXES lists it by"
    );

    // Part way: the cursor advanced by exactly the budget, and the totals agree.
    coord.advance_index_builds(3);
    let mid = coord.index_build_progress();
    assert_eq!(mid.len(), 1, "still one build: {mid:?}");
    assert_eq!(mid[0].done, 3, "the cursor advanced by the budget");
    assert_eq!(
        mid[0].total, total,
        "the denominator is stable within a build"
    );
    let totals = coord.index_build_totals();
    assert_eq!(totals.pending, 1);
    assert_eq!(totals.parked, 0);
    assert_eq!(
        totals.entities_remaining,
        total - 3,
        "the aggregate remainder tracks the same cursor"
    );

    // Complete: the build is dequeued, so it reports no progress at all — and the index is Online, which
    // is what makes `populationPercent` 100.0.
    while coord.advance_index_builds(4) {}
    assert!(
        coord.index_build_progress().is_empty(),
        "a completed build is dequeued"
    );
    assert_eq!(coord.index_build_totals(), Default::default());
    assert_eq!(
        coord.list_node_property_indexes()[0].3,
        IndexState::Online,
        "the drained build is promoted"
    );
}

/// **A pre-existing overflow this task's first mid-build test surfaced** (`rmp` task #573).
///
/// `advance_index_builds(usize::MAX)` — the documented "finish this build" budget, and the one
/// `LocalEngine::drain_index_builds` (`LOCAL_INDEX_BUILD_BUDGET`) passes — computed its chunk end as
/// `cursor + budget`. From cursor `0` that is fine; from any **non-zero** cursor it overflows: a panic in
/// debug, and in release a wrap to `end < start` that panics on the slice range immediately below. Either
/// way a public API panics the engine thread on a documented argument.
///
/// # Scope
///
/// This is a **live** engine-thread panic in the DST driver, not a theoretical one:
/// `index_fail_closed.rs::the_dst_drain_loop_does_not_overflow_on_a_build_parked_at_the_degraded_gate`
/// reaches it through `LocalEngine::drain_index_builds` verbatim, using only in-tree calls. The
/// production server is NOT exposed — it passes the finite `INDEX_BUILD_CHUNK` (512) — but the DST driver,
/// `graphus-social-gen` and `graphus-iot-gen` all pass `usize::MAX`.
///
/// This test covers the **arithmetic** directly, for all three incremental build kinds — node-property
/// (`rmp` #91), full-text (#72) and spatial (#98) — because all three had it. Each is advanced by a small
/// budget FIRST (so the cursor is non-zero), then asked to finish with `usize::MAX`. The companion test
/// above covers the reachable *path*.
#[test]
fn advancing_a_started_build_to_completion_does_not_overflow() {
    // Node-property.
    let mut coord = fresh_coord();
    seed_people(&mut coord);
    coord
        .begin_online_node_property_index("Person", "age")
        .expect("declare the build");
    coord.advance_index_builds(2);
    assert_eq!(
        coord.index_build_progress()[0].done,
        2,
        "the cursor must be NON-ZERO for this regression to bite"
    );
    while coord.advance_index_builds(usize::MAX) {} // panicked here before the fix
    assert_eq!(
        coord.list_node_property_indexes()[0].3,
        IndexState::Online,
        "the build completes"
    );

    // Full-text.
    let mut coord = fresh_coord();
    seed_people(&mut coord);
    coord
        .create_fulltext_index(
            "ft",
            &["Person".to_owned()],
            &["name".to_owned()],
            Analyzer::from_name("standard").expect("known analyzer"),
            false,
        )
        .expect("declare the full-text build");
    coord.advance_index_builds(2);
    while coord.advance_index_builds(usize::MAX) {}
    assert!(
        coord.index_build_progress().is_empty(),
        "the full-text build completes"
    );

    // Spatial.
    let mut coord = fresh_coord();
    seed_people(&mut coord);
    run_write(
        &mut coord,
        "CREATE (:City {loc: point({x: 1.0, y: 2.0})}), (:City {loc: point({x: 3.0, y: 4.0})})",
    );
    coord
        .create_point_index("pt", "City", "loc", false)
        .expect("declare the spatial build");
    coord.advance_index_builds(1);
    while coord.advance_index_builds(usize::MAX) {}
    assert!(
        coord.index_build_progress().is_empty(),
        "the spatial build completes"
    );
}
