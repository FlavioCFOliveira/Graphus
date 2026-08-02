//! End-to-end tests for the **zone-map data-skipping sidecar** (`rmp` tasks #331, #958): a per-zone
//! min/max summary over the node-id space that lets a non-indexed equality predicate scan skip whole id
//! zones whose `[min, max]` cannot match.
//!
//! The overriding correctness property is **equivalence**: the zone-skipping scan returns **exactly**
//! the node set the authoritative row path matches at the same snapshot, whether the column is
//! clustered (most zones skipped) or unclustered (no zone skipped) — the skip is conservative and the
//! per-row re-check is authoritative and snapshot-correct. Mirrors `tests/columnar_analytical.rs`.
//!
//! # Where the skip query lives, and why (`rmp` task #958)
//!
//! The zone map itself prunes id ranges and decides nothing else. The *rows* are decided by
//! [`RecordStoreGraph::zone_scan_eq`], a **statement** seam, because deciding needs the reader's
//! `(Snapshot, CommitRegistry)` pair and the coordinator has neither. The previous coordinator-level
//! `zone_scan_eq` re-checked its candidates against the raw live label word and `mvcc.in_use()`, which
//! is a dirty read in both directions; [`an_uncommitted_writer_cannot_change_the_zone_routed_answer`]
//! is the regression that holds it closed.

use std::collections::BTreeSet;

use graphus_core::{TxnId, Value};
use graphus_cypher::binding::{Parameters, bind_parameters};
use graphus_cypher::catalog::IndexCatalog;
use graphus_cypher::coordinator::TxnCoordinator;
use graphus_cypher::executor::execute;
use graphus_cypher::graph_access::KeyValues;
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
        "captured error: {:?}",
        graph.take_error()
    );
    rows
}
fn run_write(coord: &mut Coord, src: &str) {
    let plan = compile(src);
    let txn = coord.begin_serializable();
    let _ = run_plan(coord, txn, &plan);
    coord.commit(txn).expect("write commits");
}

/// Row-path truth **inside `txn`**: the sorted set of node ids matching `query` (must
/// `RETURN id(n) AS id`). The zone map is not consulted by any planner path, so this is literally the
/// "zone maps disabled" answer at `txn`'s snapshot.
fn row_path_ids_in(coord: &Coord, txn: TxnId, query: &str) -> BTreeSet<u64> {
    let plan = compile(query);
    run_plan(coord, txn, &plan)
        .iter()
        .map(|r| match r.value("id") {
            Value::Integer(i) => i as u64,
            other => panic!("id(n) Integer expected, got {other:?}"),
        })
        .collect()
}

/// Row-path truth at a fresh snapshot of its own.
fn row_path_ids(coord: &mut Coord, query: &str) -> BTreeSet<u64> {
    let txn = coord.begin_serializable();
    let ids = row_path_ids_in(coord, txn, query);
    coord.commit(txn).expect("read commits");
    ids
}

/// The zone-map-routed answer **inside `txn`**: the ids
/// [`RecordStoreGraph::zone_scan_eq`] returns for `label.property = value`, at `txn`'s snapshot.
///
/// Panics when the seam declines: every caller below has declared the column, so a decline would make
/// the comparison vacuous (it would be a scan measured against nothing).
fn zone_ids_in(
    coord: &Coord,
    txn: TxnId,
    label: &str,
    property: &str,
    value: &Value,
) -> BTreeSet<u64> {
    let graph = coord.statement(txn).expect("statement");
    let hits = graph
        .zone_scan_eq(label, property, value, KeyValues::Discard)
        .expect("the zone map must serve a declared, summarized column");
    assert!(
        !graph.has_error(),
        "captured error: {:?}",
        graph.take_error()
    );
    hits.matched.iter().map(|n| n.0).collect()
}

/// The zone-map-routed answer at a fresh snapshot of its own.
fn zone_ids(coord: &mut Coord, label: &str, property: &str, value: &Value) -> BTreeSet<u64> {
    let txn = coord.begin_serializable();
    let ids = zone_ids_in(coord, txn, label, property, value);
    coord.commit(txn).expect("read commits");
    ids
}

/// Seeds `n` `:Event` nodes whose `ts` is **monotonic in node id** (the clustered/append-only case),
/// batched so the per-transaction undo footprint stays bounded.
fn seed_monotonic_events(coord: &mut Coord, n: i64) {
    const BATCH: i64 = 2_000;
    let mut lo = 0;
    while lo < n {
        let hi = (lo + BATCH).min(n);
        run_write(
            coord,
            &format!(
                "UNWIND range({lo}, {}) AS i CREATE (:Event {{ts: i}})",
                hi - 1
            ),
        );
        lo = hi;
    }
}

#[test]
fn zone_scan_equals_row_path_on_clustered_column() {
    let mut coord = fresh_coord();
    seed_monotonic_events(&mut coord, 8_000);
    coord.declare_zone_map("Event", "ts").expect("declare");

    // A value deep in the id space: most zones must be skipped, result must match the row path.
    let target = 5_000i64;
    let zone = zone_ids(&mut coord, "Event", "ts", &Value::Integer(target));
    let row = row_path_ids(
        &mut coord,
        &format!("MATCH (n:Event) WHERE n.ts = {target} RETURN id(n) AS id"),
    );
    assert_eq!(zone, row, "zone-skip scan must equal the row path");
    // The skip actually fired (clustered column): far more zones skipped than scanned.
    assert!(
        coord.zone_map_zones_skipped() > coord.zone_map_zones_scanned(),
        "a clustered column must skip most zones (skipped={}, scanned={})",
        coord.zone_map_zones_skipped(),
        coord.zone_map_zones_scanned()
    );
}

#[test]
fn zone_scan_equals_row_path_on_unclustered_column() {
    let mut coord = fresh_coord();
    // `bucket = id % 5` — every zone spans all 5 values, so NO zone can be skipped (honest worst case).
    const BATCH: i64 = 2_000;
    let mut lo = 0;
    while lo < 6_000 {
        let hi = (lo + BATCH).min(6_000);
        run_write(
            &mut coord,
            &format!(
                "UNWIND range({lo}, {}) AS i CREATE (:Item {{bucket: i % 5}})",
                hi - 1
            ),
        );
        lo = hi;
    }
    coord.declare_zone_map("Item", "bucket").expect("declare");

    let zone = zone_ids(&mut coord, "Item", "bucket", &Value::Integer(3));
    let row = row_path_ids(
        &mut coord,
        "MATCH (n:Item) WHERE n.bucket = 3 RETURN id(n) AS id",
    );
    assert_eq!(
        zone, row,
        "unclustered: zone scan must still equal the row path"
    );
    // Graceful degradation: nothing skipped, but correct.
    assert_eq!(
        coord.zone_map_zones_skipped(),
        0,
        "unclustered column skips no zone"
    );
}

#[test]
fn zone_scan_stays_correct_after_writes() {
    let mut coord = fresh_coord();
    seed_monotonic_events(&mut coord, 4_000);
    coord.declare_zone_map("Event", "ts").expect("declare");
    // Overwrite a value INTO a zone that previously could not contain it (widens the zone), and insert
    // a fresh node. The authoritative re-check must keep the result exactly equal to the row path.
    run_write(
        &mut coord,
        "MATCH (n:Event) WHERE n.ts = 10 SET n.ts = 3000",
    );
    run_write(&mut coord, "CREATE (:Event {ts: 3000})");

    let zone = zone_ids(&mut coord, "Event", "ts", &Value::Integer(3000));
    let row = row_path_ids(
        &mut coord,
        "MATCH (n:Event) WHERE n.ts = 3000 RETURN id(n) AS id",
    );
    assert_eq!(zone, row, "after writes, zone scan must equal the row path");
}

/// **THE `rmp` #958 REGRESSION.** A zone-map-routed query must return the same bag as the same query
/// with zone maps disabled, across an interleaving with an **uncommitted** writer that both creates and
/// removes matching rows.
///
/// Three independent dirty reads are exercised at once, each on its own target value, and each one a
/// distinct failure of the pre-fix coordinator-level re-check:
///
/// | direction | the writer's uncommitted statement | pre-fix answer | why |
/// |---|---|---|---|
/// | phantom row | `CREATE (:Event {ts: 99999})` | 1 row | `mvcc.in_use()` is true for a record no snapshot can see |
/// | label removal | `REMOVE n:Event` on `ts = 5000` | 0 rows | the live label word already has the bit cleared |
/// | value overwrite | `SET n.ts = -1` on `ts = 6000` | 0 rows | the chain head is the uncommitted version |
///
/// The reader's own ground truth is the ordinary Cypher row path **at the same snapshot**, which no
/// planner routes through the zone map — so the two answers agreeing is a real check, not a tautology.
#[test]
fn an_uncommitted_writer_cannot_change_the_zone_routed_answer() {
    const CREATED: i64 = 99_999;
    const RELABELLED: i64 = 5_000;
    const OVERWRITTEN: i64 = 6_000;

    let mut coord = fresh_coord();
    seed_monotonic_events(&mut coord, 8_000);
    coord.declare_zone_map("Event", "ts").expect("declare");

    // A writer that creates a matching row, hides a matching row by label, and hides another by value —
    // and STAYS OPEN. Every one of these writes maintains the zone map (widening), so the zones that
    // hold the affected ids are kept, and the candidates really do reach the re-check.
    let writer = coord.begin_serializable();
    let _ = run_plan(
        &coord,
        writer,
        &compile(&format!("CREATE (:Event {{ts: {CREATED}}})")),
    );
    let _ = run_plan(
        &coord,
        writer,
        &compile(&format!(
            "MATCH (n:Event) WHERE n.ts = {RELABELLED} REMOVE n:Event"
        )),
    );
    let _ = run_plan(
        &coord,
        writer,
        &compile(&format!(
            "MATCH (n:Event) WHERE n.ts = {OVERWRITTEN} SET n.ts = -1"
        )),
    );

    // A concurrent reader, at its own snapshot, while the writer is still open.
    let reader = coord.begin_serializable();
    let created_zone = zone_ids_in(&coord, reader, "Event", "ts", &Value::Integer(CREATED));
    let created_row = row_path_ids_in(
        &coord,
        reader,
        &format!("MATCH (n:Event) WHERE n.ts = {CREATED} RETURN id(n) AS id"),
    );
    let relabelled_zone = zone_ids_in(&coord, reader, "Event", "ts", &Value::Integer(RELABELLED));
    let relabelled_row = row_path_ids_in(
        &coord,
        reader,
        &format!("MATCH (n:Event) WHERE n.ts = {RELABELLED} RETURN id(n) AS id"),
    );
    let overwritten_zone = zone_ids_in(&coord, reader, "Event", "ts", &Value::Integer(OVERWRITTEN));
    let overwritten_row = row_path_ids_in(
        &coord,
        reader,
        &format!("MATCH (n:Event) WHERE n.ts = {OVERWRITTEN} RETURN id(n) AS id"),
    );

    // NON-VACUITY: the row path must be describing the state this test believes it set up. Without
    // these, "zone == row" could be two identical wrong answers.
    assert!(
        created_row.is_empty(),
        "non-vacuity: the uncommitted CREATE must be invisible to the row path too",
    );
    assert_eq!(
        relabelled_row.len(),
        1,
        "non-vacuity: the committed row hidden by an uncommitted REMOVE must still be visible",
    );
    assert_eq!(
        overwritten_row.len(),
        1,
        "non-vacuity: the committed value hidden by an uncommitted SET must still be visible",
    );

    assert_eq!(
        created_zone, created_row,
        "`rmp` #958 (phantom): the zone-routed scan returned a row an uncommitted writer created and \
         may roll back — a dirty read the caller cannot repair, because rows were returned rather \
         than candidates",
    );
    assert_eq!(
        relabelled_zone, relabelled_row,
        "`rmp` #958 (label): the zone-routed scan dropped a committed row because the LIVE label word \
         carried an uncommitted REMOVE — the re-check must resolve the label through `label_bitmap_at` \
         at the reader's snapshot",
    );
    assert_eq!(
        overwritten_zone, overwritten_row,
        "`rmp` #958 (value): the zone-routed scan dropped a committed row because the property chain \
         HEAD was an uncommitted version — the re-check must fold `is_visible` over the chain",
    );

    // Seal the writer and confirm the other direction is intact: what it committed must now be seen.
    coord.commit(writer).expect("the writer commits");
    for target in [CREATED, RELABELLED, OVERWRITTEN] {
        let zone = zone_ids(&mut coord, "Event", "ts", &Value::Integer(target));
        let row = row_path_ids(
            &mut coord,
            &format!("MATCH (n:Event) WHERE n.ts = {target} RETURN id(n) AS id"),
        );
        assert_eq!(
            zone, row,
            "after the writer committed, the zone-routed answer must follow the row path for \
             ts = {target}",
        );
    }
}

/// A committed writer's `REMOVE`/`SET` must genuinely disappear from the zone-routed answer too: the
/// re-check drops rows, so the trap that fails if visibility is ever loosened the other way.
#[test]
fn a_committed_writer_is_reflected_in_the_zone_routed_answer() {
    let mut coord = fresh_coord();
    seed_monotonic_events(&mut coord, 4_000);
    coord.declare_zone_map("Event", "ts").expect("declare");

    let before = zone_ids(&mut coord, "Event", "ts", &Value::Integer(2_000));
    assert_eq!(before.len(), 1, "non-vacuity: the seeded row is findable");

    run_write(
        &mut coord,
        "MATCH (n:Event) WHERE n.ts = 2000 REMOVE n:Event",
    );

    let after = zone_ids(&mut coord, "Event", "ts", &Value::Integer(2_000));
    let row = row_path_ids(
        &mut coord,
        "MATCH (n:Event) WHERE n.ts = 2000 RETURN id(n) AS id",
    );
    assert!(
        after.is_empty(),
        "a COMMITTED label removal must remove the row from the zone-routed answer",
    );
    assert_eq!(after, row);
}

/// **THE `rmp` #958 REBUILD REGRESSION, rollback arm.** `rebuild_zone_column` must summarise **every
/// version** of the property, not the chain head.
///
/// `ts = 3999` is the maximum of its zone *and* of the whole column, so it is the one value whose loss
/// narrows a zone measurably. An open writer moves it out of the way, the rebuild runs, and the writer
/// rolls back — restoring the record but not the summary, because nothing repairs a zone map. A rebuild
/// that summarised the chain head alone therefore prunes every zone for that value, for the life of the
/// process.
#[test]
fn a_rebuild_summarizes_every_version_not_the_chain_head() {
    const MAX_TS: i64 = 3_999;
    let mut coord = fresh_coord();
    seed_monotonic_events(&mut coord, MAX_TS + 1);

    // An open writer moves the column's maximum out of its zone, and stays open.
    let writer = coord.begin_serializable();
    let _ = run_plan(
        &coord,
        writer,
        &compile(&format!(
            "MATCH (n:Event) WHERE n.ts = {MAX_TS} SET n.ts = 0"
        )),
    );

    // The rebuild happens WHILE that writer is open: it must widen the zone with the committed 3999 as
    // well as the uncommitted 0.
    coord.declare_zone_map("Event", "ts").expect("declare");

    // The writer rolls back. The record is restored; the summary is not, so a rebuild that narrowed the
    // zone has lost the row permanently.
    coord.rollback(writer).expect("the writer rolls back");

    let row = row_path_ids(
        &mut coord,
        &format!("MATCH (n:Event) WHERE n.ts = {MAX_TS} RETURN id(n) AS id"),
    );
    assert_eq!(
        row.len(),
        1,
        "non-vacuity: the rolled-back SET must leave the committed value in place",
    );
    let zone = zone_ids(&mut coord, "Event", "ts", &Value::Integer(MAX_TS));
    assert_eq!(
        zone, row,
        "`rmp` #958: the rebuild summarised only the chain head — an UNCOMMITTED overwrite — so the \
         zone holding the committed value was narrowed below it and the whole id range was pruned \
         before any re-check could run. Nothing rebuilds a zone map, so the row was gone for good",
    );
}

/// **THE `rmp` #958 REBUILD REGRESSION, MVCC arm.** The same narrowing needs no rollback at all: a
/// *committed* overwrite still leaves an older reader resolving the older version (`rmp` #50,
/// newest-**visible**-wins), so a rebuild that summarises the chain head prunes that reader's row.
#[test]
fn a_rebuild_keeps_the_version_an_older_reader_still_resolves() {
    const MAX_TS: i64 = 3_999;
    let mut coord = fresh_coord();
    seed_monotonic_events(&mut coord, MAX_TS + 1);

    // A reader pins its snapshot BEFORE the overwrite.
    let reader = coord.begin_serializable();

    // A different transaction moves the column's maximum away, and COMMITS.
    run_write(
        &mut coord,
        &format!("MATCH (n:Event) WHERE n.ts = {MAX_TS} SET n.ts = 0"),
    );

    // The rebuild runs after that commit. The chain head is now `0`; the older reader still resolves
    // `3999`, so the summary must still cover it.
    coord.declare_zone_map("Event", "ts").expect("declare");

    let row = row_path_ids_in(
        &coord,
        reader,
        &format!("MATCH (n:Event) WHERE n.ts = {MAX_TS} RETURN id(n) AS id"),
    );
    assert_eq!(
        row.len(),
        1,
        "non-vacuity: the older reader's snapshot must still resolve the pre-overwrite value",
    );
    let zone = zone_ids_in(&coord, reader, "Event", "ts", &Value::Integer(MAX_TS));
    assert_eq!(
        zone, row,
        "`rmp` #958: the rebuild summarised the newest COMMITTED version only, narrowing the zone \
         below a value an existing reader can still see — a pruning structure may only narrow on \
         state that holds for every live snapshot",
    );
    let _ = coord.rollback(reader);
}

/// The decline contract (`rmp` #680/#738/#958): a column the zone map cannot serve returns `None`
/// ("scan normally"), never `Some(empty)` ("nothing matches"). An undeclared column is the reachable
/// case; the unsummarized one is covered by `zone_map`'s own unit tests.
#[test]
fn an_undeclared_column_declines_instead_of_answering_empty() {
    let mut coord = fresh_coord();
    seed_monotonic_events(&mut coord, 2_000);
    // NO `declare_zone_map` here.
    let txn = coord.begin_serializable();
    {
        let graph = coord.statement(txn).expect("statement");
        assert!(
            graph
                .zone_scan_eq("Event", "ts", &Value::Integer(1_000), KeyValues::Discard)
                .is_none(),
            "an undeclared column must DECLINE to the exact scan, never answer with an empty set",
        );
        // A declared-but-different column must decline too, rather than answer for the wrong pair.
        assert!(
            graph
                .zone_scan_eq("Event", "nope", &Value::Integer(1), KeyValues::Discard)
                .is_none(),
        );
    }
    coord.commit(txn).expect("read commits");
}

#[test]
#[ignore = "measurement, not a correctness gate; run with --release --ignored --nocapture"]
fn measure_zone_skip_fraction() {
    const N: i64 = 50_000;
    let mut coord = fresh_coord();
    seed_monotonic_events(&mut coord, N);
    coord.declare_zone_map("Event", "ts").expect("declare");

    let _ = zone_ids(&mut coord, "Event", "ts", &Value::Integer(N / 2));
    let skipped = coord.zone_map_zones_skipped();
    let scanned = coord.zone_map_zones_scanned();
    let total = skipped + scanned;
    eprintln!("\n=== rmp #331 measurement (N={N} monotonic :Event.ts, ZONE_SIZE=1024) ===");
    eprintln!("zones total={total}  skipped={skipped}  scanned={scanned}");
    eprintln!(
        "page/zone-skip fraction on a clustered column: {:.1}%\n",
        100.0 * skipped as f64 / total.max(1) as f64
    );
}
