//! **Mode B engine-thread fairness** (`08-network-bulk-import.md` §7.2.6/§8, `rmp` #520): a real,
//! non-deterministic, real-OS-thread proof that a large Mode B import genuinely **yields the single
//! engine thread** between chunks, so concurrent ordinary client traffic against the SAME database is
//! never starved for the whole batch's duration — the hard requirement `08` §7.2.6 states explicitly:
//! "the batch driver must yield the engine thread at small sub-batch... granularity, never submit an
//! entire...batch as one uninterruptible engine command."
//!
//! ## Why this is a real-thread integration test, not a DST scenario
//!
//! The deterministic `LocalEngine` DST driver runs on **one cooperative thread with no real clock**
//! (`specification/07-dst-simulator.md` §5.1), so it cannot observe real wall-clock latency at all —
//! there is no "concurrent" foreground/background race to measure. `network_bulk_ingest_mode_b`
//! (`crates/graphus-dst/src/scenarios.rs`) instead proves the **mechanism** directly (a chunk
//! dispatch's row count is bounded by the configured `chunk_rows`) and its own doc comment cites this
//! file as the real-latency proof, mirroring the exact DST/integration split
//! `network_bulk_ingest_mode_a`'s own doc comment already established for Mode A's HTTP-transport
//! concerns ("`08-network-bulk-import.md`'s HTTP-transport and `DatabaseCatalog`/`Loading`-state
//! layers are DST's structural non-goals... covered instead by...
//! `graphus-server/tests/bulk_import_endpoint.rs`").
//!
//! ## What this proves
//!
//! A real threaded engine ([`spawn_engine`]) runs a large (tens-of-thousands-of-rows) Mode B batch
//! (via the REAL async [`drive_mode_b_batch`] driver, chunked at the small, production-realistic
//! `mode_b_chunk_rows` granularity) on a background task, **while** a foreground task repeatedly runs
//! small, fast ordinary Cypher queries against the SAME engine and measures each one's round-trip
//! latency. The import is genuinely `100x+` larger (in row count) than what an uninterrupted
//! whole-batch dispatch would let through in the time a single foreground query's deadline allows, so
//! a regression that submitted the whole batch as one uninterruptible engine command would make every
//! concurrent query block for the batch's *entire* duration — this test's latency ceiling would then
//! fail immediately and unambiguously, not marginally.
//!
//! Intentionally non-deterministic (the OS scheduler picks the exact interleaving) and **not** part of
//! the deterministic seed-replay gate: it asserts a *property* (a bounded latency envelope), never a
//! fragile absolute timing.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use graphus_bulk::{ColumnRole, NodeHeader, PropertyType, ScalarType};
use graphus_core::capability::Clock;
use graphus_io::MemBlockDevice;
use graphus_server::bulk_import_mode_b::{BatchRows, ModeBSession, drive_mode_b_batch};
use graphus_server::config::BulkImportConfig;
use graphus_server::engine::command::AccessMode;
use graphus_server::engine::{Engine, spawn_engine};
use graphus_sim::SharedClock;
use graphus_storage::RecordStore;
use graphus_wal::{MemLogSink, WalManager};

/// How many node rows the background Mode B batch imports — deliberately large relative to the
/// per-chunk granularity (`mode_b_chunk_rows`, production default 25) so a regression to
/// whole-batch-as-one-command dispatch would starve the foreground loop for a clearly-observable,
/// many-second stall rather than a marginal one.
const BATCH_ROWS: usize = 40_000;

/// The per-chunk granularity under test — the production default (`BulkImportConfig::default()`'s
/// `mode_b_chunk_rows`), not an artificially small value chosen to make the test pass trivially.
const CHUNK_ROWS: u64 = 25;

/// The foreground query's latency ceiling: generous enough to absorb ordinary CI scheduling jitter,
/// yet far below what even a handful of un-yielded whole-batch chunks would cost (`BATCH_ROWS` /
/// `CHUNK_ROWS` = 1,600 chunks; a single uninterruptible dispatch of the WHOLE batch would take
/// orders of magnitude longer than this ceiling).
const MAX_FOREGROUND_LATENCY: Duration = Duration::from_millis(500);

fn engine(reader_threads: usize, pool_pages: usize, queue_cap: usize) -> Engine {
    let clock: Arc<dyn Clock + Send + Sync> = Arc::new(SharedClock::new(0));
    let metrics = Arc::new(graphus_server::metrics::Metrics::new());
    spawn_engine::<MemBlockDevice, MemLogSink, _>(
        Arc::<str>::from("mode-b-fairness"),
        move || {
            let device = MemBlockDevice::new(0);
            let wal = WalManager::create(MemLogSink::new())?;
            let store = RecordStore::create(device, wal, pool_pages, 1)?;
            Ok(graphus_cypher::TxnCoordinator::new(store))
        },
        queue_cap,
        256,
        reader_threads,
        metrics,
        clock,
        std::sync::Arc::new(graphus_server::txn_registry::TransactionRegistry::new()),
    )
    .expect("spawn test engine")
}

fn node_header() -> Arc<NodeHeader> {
    Arc::new(NodeHeader {
        columns: vec![
            ColumnRole::Id,
            ColumnRole::Label,
            ColumnRole::Property {
                key: "seq".to_owned(),
                ty: PropertyType::Scalar(ScalarType::Integer),
            },
        ],
        id_index: 0,
        id_name: None,
    })
}

fn node_row(i: usize) -> csv::StringRecord {
    csv::StringRecord::from(vec![i.to_string(), "Entity".to_owned(), i.to_string()])
}

/// Drives a large Mode B batch to completion in the background — the load the foreground loop must
/// stay responsive through.
async fn run_background_import(engine: graphus_server::engine::EngineHandle) {
    let cfg = BulkImportConfig {
        mode_b_chunk_rows: CHUNK_ROWS,
        mode_b_batch_rows: BATCH_ROWS as u64,
        ..BulkImportConfig::default()
    };
    let mut session = ModeBSession::new("mode-b-fairness".to_owned());
    let rows = BatchRows::Nodes {
        header: node_header(),
        records: (0..BATCH_ROWS).map(node_row).collect(),
    };
    drive_mode_b_batch(&engine, &mut session, &rows, &cfg)
        .await
        .expect("the background Mode B batch commits cleanly");
}

/// Repeatedly runs a small, fast auto-commit query against `engine` until `stop` is set, recording
/// each call's wall-clock latency.
async fn run_foreground_probe(
    engine: graphus_server::engine::EngineHandle,
    stop: Arc<AtomicBool>,
) -> Vec<Duration> {
    let mut latencies = Vec::new();
    while !stop.load(Ordering::Relaxed) {
        let started = Instant::now();
        let ticket = engine
            .begin_auto_commit(AccessMode::Read)
            .await
            .expect("begin foreground probe");
        let mut reply = engine
            .run(
                ticket,
                "MATCH (n) RETURN count(n) AS c".to_owned(),
                vec![],
                true,
                None,
                None,
            )
            .await
            .expect("foreground probe runs");
        while reply.rows.next().expect("drain foreground probe").is_some() {}
        latencies.push(started.elapsed());
        // A brief yield between probes: this test measures RESPONSIVENESS under load, not raw probe
        // throughput — a tight spin would itself contend for the engine's admission/channel capacity
        // in a way unrelated to the property under test.
        tokio::time::sleep(Duration::from_millis(2)).await;
    }
    latencies
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_traffic_stays_responsive_during_a_large_mode_b_import() {
    let eng = engine(2, 512, 256);
    let handle = eng.handle.clone();

    let stop = Arc::new(AtomicBool::new(false));
    let probe = tokio::spawn(run_foreground_probe(handle.clone(), Arc::clone(&stop)));

    // Give the probe loop a moment to establish a baseline before the import starts.
    tokio::time::sleep(Duration::from_millis(20)).await;

    let import_started = Instant::now();
    run_background_import(handle.clone()).await;
    let import_elapsed = import_started.elapsed();

    stop.store(true, Ordering::Relaxed);
    let latencies = probe.await.expect("foreground probe task");

    assert!(
        latencies.len() >= 5,
        "the foreground probe must have run several times during the import (got {}); the import \
         may have completed suspiciously fast or the probe never got scheduled",
        latencies.len()
    );

    let max_latency = latencies.iter().copied().max().unwrap_or_default();
    let over_ceiling: Vec<&Duration> = latencies
        .iter()
        .filter(|d| **d > MAX_FOREGROUND_LATENCY)
        .collect();
    assert!(
        over_ceiling.is_empty(),
        "foreground query latency exceeded the {MAX_FOREGROUND_LATENCY:?} ceiling {} time(s) \
         during a {BATCH_ROWS}-row Mode B import (chunk_rows={CHUNK_ROWS}); max observed = \
         {max_latency:?}; import wall-clock = {import_elapsed:?}. A regression to whole-batch-as-\
         one-uninterruptible-command dispatch would fail this assertion by orders of magnitude, not \
         marginally: {over_ceiling:?}",
        over_ceiling.len()
    );

    let _ = eng.handle.shutdown().await;
}
