//! The sustained ingest + retention churn workload + storage-reclamation engine for
//! `examples/iot-timeseries`, driving the **REAL** Graphus engine inline + single-threaded.
//!
//! This module is the shared, library-level core that three consumers reuse so the engine-driving
//! logic lives in exactly one place:
//!
//! - the `iot_churn` binary (the demonstration + its own pass/fail assertions),
//! - the `iot_evidence` binary (which wraps a run with the harness's RSS sampler + a standardized
//!   [`EvidenceReport`](graphus_examples_harness::EvidenceReport)),
//! - the hermetic `tests/churn_plateau.rs` cargo test (the default-`cargo test` reclamation gate).
//!
//! # Why this drives the engine INLINE (not over Bolt/TCP) — and why that is still the real engine
//!
//! Graphus's MVCC garbage collection ([`RecordStore::gc`]) is a **maintenance operation**: it is
//! WAL-logged and crash-safe, but the live server has **no automatic, scheduled, or wire-reachable
//! trigger** for it (there is no GC `EngineCommand`, Cypher procedure, or admin statement — verified
//! against `graphus-server`'s command surface; filed as improvement `rmp #305`). Without a GC pass
//! the delete-old/insert-new churn only tombstones records, so the footprint grows **linearly** with
//! total-ingested. The reclamation this example proves therefore requires invoking GC, reachable only
//! through the in-process store seam ([`TxnCoordinator::with_store_mut`]). So the workload drives the
//! **production command-dispatch code path** — `TxnCoordinator::statement` + `execute`, *exactly*
//! what the server's `handle_run` calls per `RUN` — inline and single-threaded (the same approach
//! `graphus-fraud-gen`'s `dst_contention` and `graphus-dst` use), interleaving the GC maintenance
//! pass. This is the real engine, real Cypher, real WAL-logged storage — just driven deterministically
//! in one process so the steady-state and plateau are reproducible and assertable.

use graphus_core::{TxnId, Value};
use graphus_cypher::coordinator::TxnCoordinator;
use graphus_cypher::{
    IndexCatalog, Parameters, Row, RowValue, analyze, bind_parameters, execute, lower,
    parse_tokens, plan_physical, tokenize,
};
use graphus_io::{BlockDevice, MemBlockDevice, PAGE_SIZE};
use graphus_storage::RecordStore;
use graphus_wal::{MemLogSink, WalManager};

use crate::{GenConfig, Generator};

type Store = RecordStore<MemBlockDevice, MemLogSink>;
type Coord = TxnCoordinator<MemBlockDevice, MemLogSink>;

/// A monotonic source of GC transaction ids, kept clear of the coordinator's own txn ids (which it
/// allocates densely from 1). GC passes use ids in a high, disjoint range so they never collide.
const GC_TXN_BASE: u64 = 1 << 40;

/// One sampled round of the churn workload — the machine-readable per-tick result the evidence
/// tooling and the README curve consume.
#[derive(Debug, Clone, Copy)]
pub struct RoundSample {
    /// 0-based tick index.
    pub tick: u64,
    /// Cumulative readings ingested up to and including this tick.
    pub total_ingested: u64,
    /// Live `:Reading` count after this tick's insert + delete (+ GC) applied.
    pub live_readings: u64,
    /// Durable on-disk footprint in bytes after this tick = device page high-water × page size.
    pub footprint_bytes: u64,
    /// Equivalent whole-page count of the footprint (`footprint_bytes / PAGE_SIZE`).
    pub pages: u64,
    /// Physical record versions reclaimed by this tick's GC pass (`0` when GC is disabled).
    pub reclaimed: u64,
}

/// The full run outcome — the per-tick samples plus the derived structural summary the reclamation
/// proof and the evidence report assert on.
#[derive(Debug, Clone)]
pub struct ChurnOutcome {
    /// The resolved generation config the run executed.
    pub cfg: GenConfig,
    /// Whether the MVCC GC maintenance pass ran each tick (the reclamation path) or not (the honest
    /// linear-growth contrast).
    pub gc_enabled: bool,
    /// The per-tick samples, in tick order.
    pub samples: Vec<RoundSample>,
    /// The page high-water mark (the maximum durable page count observed across the run).
    pub page_high_water: u64,
    /// The maximum footprint in bytes observed across the run.
    pub footprint_high_water_bytes: u64,
    /// The post-warmup footprint band: minimum bytes observed AFTER the warmup boundary.
    pub steady_min_bytes: u64,
    /// The post-warmup footprint band: maximum bytes observed AFTER the warmup boundary.
    pub steady_max_bytes: u64,
    /// The tick index at which warmup ends (the window has filled and one GC pass has run).
    pub warmup_ticks: u64,
}

impl ChurnOutcome {
    /// Total readings ingested over the whole run (the last sample's cumulative count).
    #[must_use]
    pub fn total_ingested(&self) -> u64 {
        self.samples.last().map_or(0, |s| s.total_ingested)
    }

    /// The post-warmup plateau ratio: `steady_max_bytes / steady_min_bytes`. A value at or near
    /// `1.0` means the footprint is flat (fully reclaimed); a large value means growth. `1.0` when
    /// the band is degenerate.
    #[must_use]
    pub fn plateau_ratio(&self) -> f64 {
        self.steady_max_bytes as f64 / self.steady_min_bytes.max(1) as f64
    }

    /// How many times the retention window the run ingested in total (`total_ingested / window`).
    /// The plateau is only meaningful when this is comfortably `> 1` (the proof requires `>= 3×`).
    #[must_use]
    pub fn ingest_to_window(&self) -> f64 {
        self.total_ingested() as f64 / self.cfg.window.max(1) as f64
    }

    /// The steady-state live `:Reading` count (the last post-warmup sample's live count, which holds
    /// in `[window, window + rate)`), or the last sample's when the run was shorter than warmup.
    #[must_use]
    pub fn steady_live_count(&self) -> u64 {
        self.samples
            .iter()
            .rev()
            .find(|s| s.tick >= self.warmup_ticks)
            .or_else(|| self.samples.last())
            .map_or(0, |s| s.live_readings)
    }
}

fn fresh_coord() -> Coord {
    let device = MemBlockDevice::new(0);
    let wal = WalManager::create(MemLogSink::new()).expect("create wal");
    let store: Store = RecordStore::create(device, wal, 256, 1).expect("create store");
    TxnCoordinator::new(store)
}

/// Runs one Cypher statement to completion inside `txn` over the coordinator's statement seam (the
/// production code path), returning the materialised rows. Panics if the statement captured an
/// engine error — every statement in this workload is well-formed by construction.
fn run_stmt(coord: &Coord, txn: TxnId, src: &str) -> Vec<Row> {
    let toks = tokenize(src).expect("lex");
    let ast = parse_tokens(&toks, src).expect("parse");
    let validated = analyze(&ast).expect("analyze");
    let plan = plan_physical(&lower(&validated), &IndexCatalog::empty());
    let bound = bind_parameters(&plan, &Parameters::new()).expect("bind");
    let mut graph = coord.statement(txn).expect("statement");
    let rows = {
        let mut cursor = execute(&plan, &bound, &mut graph).expect("open cursor");
        cursor.collect_all().expect("collect")
    };
    assert!(
        !graph.has_error(),
        "captured engine error: {:?}",
        graph.take_error()
    );
    rows
}

/// Runs `src` in its own committed serializable auto-commit transaction.
fn exec_commit(coord: &mut Coord, src: &str) {
    let txn = coord.begin_serializable();
    let _ = run_stmt(coord, txn, src);
    coord.commit(txn).expect("commit");
}

/// The current live `Reading` count, read in its own committed snapshot transaction.
fn live_readings(coord: &mut Coord) -> u64 {
    let txn = coord.begin_serializable();
    let rows = run_stmt(coord, txn, "MATCH (r:Reading) RETURN count(r) AS c");
    coord.commit(txn).expect("commit count");
    match rows.first().and_then(|r| r.values().first()) {
        Some(RowValue::Value(Value::Integer(n))) => *n as u64,
        other => panic!("unexpected count row: {other:?}"),
    }
}

/// The durable footprint in bytes = device page high-water × page size. This is the on-disk size the
/// example reports; with the in-memory DST device it is deterministic and reproducible.
fn footprint_bytes(coord: &Coord) -> u64 {
    coord.with_store_mut(|s| s.with_device_mut(|d| d.page_count()) * PAGE_SIZE as u64)
}

/// Runs one MVCC GC maintenance pass: begin a GC txn (id in the disjoint high range), GC at the
/// current snapshot watermark (no live readers here, so the latest commit is a safe watermark —
/// every committed deletion becomes reclaimable), commit, and flush so the durable image reflects
/// the reclaim. Returns the number of physical versions reclaimed. Mirrors the DST harness's
/// `gc_after_recovery`.
fn gc_pass(coord: &Coord, gc_seq: &mut u64) -> u64 {
    let tid = TxnId(GC_TXN_BASE + *gc_seq);
    *gc_seq += 1;
    coord.with_store_mut(|s| {
        let watermark = s.snapshot_ts();
        s.begin(tid);
        let report = s.gc(tid, watermark).expect("gc pass");
        s.commit(tid).expect("gc commit");
        s.flush().expect("flush after gc");
        report.reclaimed as u64
    })
}

/// Runs the sustained ingest + retention churn workload to completion, returning the structural
/// outcome. The default entry point for callers that do not need a per-tick hook.
///
/// See [`run_churn_observed`] for the variant that calls a closure after each tick is sampled — used
/// by the evidence binary to interleave an RSS sample over the same loop.
#[must_use]
pub fn run_churn(cfg: GenConfig, gc_enabled: bool) -> ChurnOutcome {
    run_churn_observed(cfg, gc_enabled, |_| {})
}

/// Like [`run_churn`] but invokes `on_tick(&RoundSample)` after each tick's sample has been recorded.
///
/// The hook is the seam the evidence binary uses to take an RSS sample at exactly the same cadence as
/// the footprint series, so the two time series are aligned tick-for-tick. The closure must not
/// touch the engine; it is purely an observation point.
pub fn run_churn_observed<F>(cfg: GenConfig, gc_enabled: bool, mut on_tick: F) -> ChurnOutcome
where
    F: FnMut(&RoundSample),
{
    let mut coord = fresh_coord();
    let mut generator = Generator::new(cfg.clone());
    let mut gc_seq: u64 = 0;

    // Bootstrap: the sensor fleet, each in its own auto-commit txn. (The index DDL the full
    // `stream.cypher` / a server run executes is a separate engine-command path, not the row-executor
    // seam this inline workload drives; the retention DELETE is correct either way — index or scan.)
    for stmt in generator.sensor_cypher() {
        exec_commit(&mut coord, &stmt);
    }

    // Warmup boundary: the window fills after ceil(window / rate) ticks; we treat the first such
    // tick (plus one) as warmup, and assert the steady state on the ticks AFTER it.
    let warmup_ticks = cfg.window.div_ceil(cfg.rate.max(1)) + 1;

    let mut samples = Vec::with_capacity(cfg.ticks as usize);
    let mut total_ingested = 0u64;
    let mut page_high_water = 0u64;
    let mut footprint_high_water_bytes = 0u64;
    let mut steady_min_bytes = u64::MAX;
    let mut steady_max_bytes = 0u64;

    while let Some(t) = generator.tick() {
        // Insert this tick's new readings, each in its own committed txn (the realistic per-event
        // ingest shape).
        for ins in &t.inserts {
            exec_commit(&mut coord, ins);
            total_ingested += 1;
        }
        // Apply the retention DELETE (aged-out readings) in its own committed txn.
        if let Some(del) = &t.delete {
            exec_commit(&mut coord, del);
        }
        // GC maintenance pass: reclaim the tombstoned slots so new inserts reuse them.
        let reclaimed = if gc_enabled {
            gc_pass(&coord, &mut gc_seq)
        } else {
            0
        };

        let footprint = footprint_bytes(&coord);
        let pages = footprint / PAGE_SIZE as u64;
        page_high_water = page_high_water.max(pages);
        footprint_high_water_bytes = footprint_high_water_bytes.max(footprint);

        let live = live_readings(&mut coord);

        if t.tick >= warmup_ticks {
            steady_min_bytes = steady_min_bytes.min(footprint);
            steady_max_bytes = steady_max_bytes.max(footprint);
        }

        let sample = RoundSample {
            tick: t.tick,
            total_ingested,
            live_readings: live,
            footprint_bytes: footprint,
            pages,
            reclaimed,
        };
        on_tick(&sample);
        samples.push(sample);
    }

    if steady_min_bytes == u64::MAX {
        // Degenerate: the run was shorter than warmup; fall back to the last sample.
        steady_min_bytes = samples.last().map_or(0, |s| s.footprint_bytes);
        steady_max_bytes = steady_min_bytes;
    }

    ChurnOutcome {
        cfg,
        gc_enabled,
        samples,
        page_high_water,
        footprint_high_water_bytes,
        steady_min_bytes,
        steady_max_bytes,
        warmup_ticks,
    }
}

/// Serialises the per-round samples + summary to a compact JSON object (no serde derive needed — a
/// flat, hand-rolled writer keeps the output stable and dependency-light). This is the
/// machine-readable result the `iot_churn` binary and `run.sh` consume.
#[must_use]
pub fn samples_json(out: &ChurnOutcome) -> String {
    use std::fmt::Write as _;
    let mut s = String::with_capacity(256 + out.samples.len() * 96);
    s.push('{');
    let _ = write!(s, "\"gc_enabled\":{},", out.gc_enabled);
    let _ = write!(s, "\"seed\":{},", out.cfg.seed);
    let _ = write!(s, "\"sensors\":{},", out.cfg.sensors);
    let _ = write!(s, "\"rate\":{},", out.cfg.rate);
    let _ = write!(s, "\"window\":{},", out.cfg.window);
    let _ = write!(s, "\"ticks\":{},", out.cfg.ticks);
    let _ = write!(s, "\"warmup_ticks\":{},", out.warmup_ticks);
    let _ = write!(s, "\"total_ingested\":{},", out.total_ingested());
    let _ = write!(s, "\"page_high_water\":{},", out.page_high_water);
    let _ = write!(
        s,
        "\"footprint_high_water_bytes\":{},",
        out.footprint_high_water_bytes
    );
    let _ = write!(s, "\"steady_min_bytes\":{},", out.steady_min_bytes);
    let _ = write!(s, "\"steady_max_bytes\":{},", out.steady_max_bytes);
    s.push_str("\"rounds\":[");
    for (i, r) in out.samples.iter().enumerate() {
        if i > 0 {
            s.push(',');
        }
        let _ = write!(
            s,
            "{{\"tick\":{},\"total_ingested\":{},\"live\":{},\"footprint_bytes\":{},\"pages\":{},\"reclaimed\":{}}}",
            r.tick, r.total_ingested, r.live_readings, r.footprint_bytes, r.pages, r.reclaimed
        );
    }
    s.push_str("]}");
    s
}
