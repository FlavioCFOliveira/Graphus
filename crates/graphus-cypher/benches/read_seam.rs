//! The **storage read seam's** per-candidate hot path — the cost of the "candidate + re-verification"
//! access model (`rmp` task #991).
//!
//! This benchmark exists to hold one specific line: the candidate instrumentation added by `rmp` #991
//! (candidates examined, candidates rejected by the MVCC visibility re-check, candidates rejected by the
//! access path's own predicate re-check, and SIREAD markers emitted) must cost **nothing measurable** on
//! the ordinary, **unprofiled** path. A statement with no `PROFILE` prefix builds no [`ProfileRecorder`]
//! and never drains the seam's tally, but the seam still *keeps* it — so this is the number that must not
//! move, and it is measured, not assumed.
//!
//! Unlike `executor_row_path.rs` (which is deliberately seam-light, over a `MemGraph`, to isolate the
//! executor's per-row work), every query here runs against the **real** persistent record store through a
//! `TxnCoordinator`, so each row costs a genuine record decode, an MVCC visibility test and a SIREAD
//! marker — exactly the work the instrumentation sits next to.
//!
//! Four shapes, chosen because they are the four access paths `rmp` #991 must establish a baseline for:
//!
//! * `seek_eq_selective` — an indexed equality seek that returns **one** row. The candidate list is
//!   short, so this is the shape where a fixed per-call overhead would show up worst.
//! * `seek_range_unselective` — an indexed range seek whose bounds match **every** node. It carries the
//!   blanket `mark_all_live_nodes` predicate footprint, so it is the marker-heaviest read in the engine.
//! * `label_scan` — `MATCH (n:Label)`, the fallback every declined seek degrades to: one record decode
//!   plus one marker per live node, twice over (blanket marker pass + candidate pass).
//! * `expand_untyped` — an untyped traversal, the one shape whose candidates are relationships rather
//!   than nodes.
//!
//! `Throughput::Elements` is the number of **rows the query returns**, so Criterion reports rows/sec.
//!
//! Run with `cargo bench -p graphus-cypher --bench read_seam`.

use std::hint::black_box;
use std::time::Duration;

use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use graphus_cypher::binding::{Parameters, bind_parameters};
use graphus_cypher::catalog::IndexCatalog;
use graphus_cypher::coordinator::TxnCoordinator;
use graphus_cypher::executor::execute;
use graphus_cypher::lexer::tokenize;
use graphus_cypher::lower::lower;
use graphus_cypher::parser::parse_tokens;
use graphus_cypher::physical::{PhysicalPlan, plan_physical};
use graphus_cypher::semantics::analyze;
use graphus_io::MemBlockDevice;
use graphus_storage::RecordStore;
use graphus_wal::{MemLogSink, WalManager};

type Coord = TxnCoordinator<MemBlockDevice, MemLogSink>;

/// The fixture size. Large enough that the per-candidate work dominates the fixed per-statement cost
/// (so an added per-candidate instruction would be visible), small enough that the fixture builds in a
/// couple of seconds and the whole benchmark stays under a minute.
const NODES: i64 = 1_000;

/// The buffer-pool capacity (frames). Sized so the whole fixture stays resident and the benchmark
/// measures the read seam rather than page eviction.
const POOL_FRAMES: usize = 4_096;

fn fresh_coord() -> Coord {
    let device = MemBlockDevice::new(0);
    let wal = WalManager::create(MemLogSink::new()).expect("wal");
    TxnCoordinator::new(RecordStore::create(device, wal, POOL_FRAMES, 1).expect("store"))
}

fn compile(src: &str, catalog: &IndexCatalog) -> PhysicalPlan {
    let toks = tokenize(src).expect("lex");
    let ast = parse_tokens(&toks, src).expect("parse");
    let validated = analyze(&ast).expect("analyze");
    plan_physical(&lower(&validated), catalog).with_prefix(ast.prefix())
}

/// Runs `src` in its own committed transaction, returning the row count.
fn run(coord: &mut Coord, plan: &PhysicalPlan) -> usize {
    let bound = bind_parameters(plan, &Parameters::new()).expect("bind");
    let txn = coord.begin_serializable();
    let n = {
        let mut graph = coord.statement(txn).expect("statement");
        let mut cursor = execute(plan, &bound, &mut graph).expect("open");
        let rows = cursor.collect_all().expect("collect");
        assert!(graph.take_error().is_none(), "captured a storage error");
        rows.len()
    };
    coord.commit(txn).expect("commit");
    n
}

/// `NODES` `:Person` nodes in a ring of `:KNOWS` edges, with `name` and `age` indexed.
fn fixture() -> (Coord, IndexCatalog) {
    let mut coord = fresh_coord();
    // One statement per node keeps the builder on the ordinary commit path (the same path a client
    // would drive) rather than a bulk seam the read side never sees.
    for i in 0..NODES {
        let plan = compile(
            &format!("CREATE (:Person {{name: 'p{i}', age: {i}}})"),
            &IndexCatalog::empty(),
        );
        run(&mut coord, &plan);
    }
    for i in 0..NODES {
        let j = (i + 1) % NODES;
        let plan = compile(
            &format!(
                "MATCH (a:Person {{name: 'p{i}'}}), (b:Person {{name: 'p{j}'}}) CREATE (a)-[:KNOWS]->(b)"
            ),
            &IndexCatalog::empty(),
        );
        run(&mut coord, &plan);
    }
    coord
        .create_node_property_index("Person", "name")
        .expect("name index");
    coord
        .create_node_property_index("Person", "age")
        .expect("age index");
    while coord.has_pending_index_builds() {
        coord.advance_index_builds(10_000);
    }
    let catalog = coord.catalog();
    (coord, catalog)
}

fn bench_read_seam(c: &mut Criterion) {
    let (mut coord, catalog) = fixture();

    let mut group = c.benchmark_group("read_seam");
    group.sample_size(30);
    group.warm_up_time(Duration::from_millis(500));
    group.measurement_time(Duration::from_secs(3));

    // A selective indexed equality seek: one row out of `NODES` candidates.
    let mid = NODES / 2;
    let seek_eq = compile(
        &format!("MATCH (n:Person {{name: 'p{mid}'}}) RETURN n.name AS name"),
        &catalog,
    );
    assert_eq!(run(&mut coord, &seek_eq), 1, "the selective seek finds one");
    group.throughput(Throughput::Elements(1));
    group.bench_function("seek_eq_selective", |b| {
        b.iter(|| black_box(run(&mut coord, &seek_eq)));
    });

    // An unselective indexed range seek: every node satisfies the bound.
    let seek_range = compile(
        "MATCH (n:Person) WHERE n.age >= 0 RETURN n.age AS age",
        &catalog,
    );
    assert_eq!(
        run(&mut coord, &seek_range),
        NODES as usize,
        "the unselective range seek returns every node"
    );
    group.throughput(Throughput::Elements(NODES as u64));
    group.bench_function("seek_range_unselective", |b| {
        b.iter(|| black_box(run(&mut coord, &seek_range)));
    });

    // A bare label scan: the path every declined seek degrades to.
    let scan = compile("MATCH (n:Person) RETURN n.name AS name", &catalog);
    assert_eq!(run(&mut coord, &scan), NODES as usize, "the scan sees all");
    group.throughput(Throughput::Elements(NODES as u64));
    group.bench_function("label_scan", |b| {
        b.iter(|| black_box(run(&mut coord, &scan)));
    });

    // An untyped traversal: relationship candidates rather than node candidates.
    let expand = compile(
        "MATCH (a:Person)-[]->(b:Person) RETURN b.name AS name",
        &catalog,
    );
    assert_eq!(
        run(&mut coord, &expand),
        NODES as usize,
        "the ring yields one out-edge per node"
    );
    group.throughput(Throughput::Elements(NODES as u64));
    group.bench_function("expand_untyped", |b| {
        b.iter(|| black_box(run(&mut coord, &expand)));
    });

    group.finish();
}

criterion_group!(benches, bench_read_seam);
criterion_main!(benches);
