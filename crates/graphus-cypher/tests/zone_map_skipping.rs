//! End-to-end tests for the **zone-map data-skipping sidecar** (`rmp` task #331): a per-zone min/max
//! summary over the node-id space that lets a non-indexed equality/range predicate scan skip whole id
//! zones whose `[min, max]` cannot match. The overriding correctness property is **equivalence**: the
//! zone-skipping scan returns **exactly** the committed node set the authoritative row path matches,
//! whether the column is clustered (most zones skipped) or unclustered (no zone skipped) — the skip is
//! conservative and the per-row re-check is authoritative. Mirrors `tests/columnar_analytical.rs`.

use std::collections::BTreeSet;

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
fn run_plan(coord: &Coord, txn: graphus_core::TxnId, plan: &PhysicalPlan) -> Vec<Row> {
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
/// Row-path truth: the sorted set of node ids matching `query` (must `RETURN id(n) AS id`).
fn row_path_ids(coord: &mut Coord, query: &str) -> BTreeSet<u64> {
    let plan = compile(query);
    let txn = coord.begin_serializable();
    let rows = run_plan(coord, txn, &plan);
    coord.commit(txn).expect("read commits");
    rows.iter()
        .map(|r| match r.value("id") {
            Value::Integer(i) => i as u64,
            other => panic!("id(n) Integer expected, got {other:?}"),
        })
        .collect()
}
fn as_set(ids: Vec<u64>) -> BTreeSet<u64> {
    ids.into_iter().collect()
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
    let zone = coord
        .zone_scan_eq("Event", "ts", &Value::Integer(target))
        .expect("zone map declared");
    let row = row_path_ids(
        &mut coord,
        &format!("MATCH (n:Event) WHERE n.ts = {target} RETURN id(n) AS id"),
    );
    assert_eq!(as_set(zone), row, "zone-skip scan must equal the row path");
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

    let zone = coord
        .zone_scan_eq("Item", "bucket", &Value::Integer(3))
        .expect("declared");
    let row = row_path_ids(
        &mut coord,
        "MATCH (n:Item) WHERE n.bucket = 3 RETURN id(n) AS id",
    );
    assert_eq!(
        as_set(zone),
        row,
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

    let zone = coord
        .zone_scan_eq("Event", "ts", &Value::Integer(3000))
        .expect("declared");
    let row = row_path_ids(
        &mut coord,
        "MATCH (n:Event) WHERE n.ts = 3000 RETURN id(n) AS id",
    );
    assert_eq!(
        as_set(zone),
        row,
        "after writes, zone scan must equal the row path"
    );
}

#[test]
#[ignore = "measurement, not a correctness gate; run with --release --ignored --nocapture"]
fn measure_zone_skip_fraction() {
    const N: i64 = 50_000;
    let mut coord = fresh_coord();
    seed_monotonic_events(&mut coord, N);
    coord.declare_zone_map("Event", "ts").expect("declare");

    let _ = coord.zone_scan_eq("Event", "ts", &Value::Integer(N / 2));
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
