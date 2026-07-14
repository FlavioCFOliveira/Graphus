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
//! # What this module is — and what it is NOT
//!
//! This is the **deterministic, in-memory mirror** of the reclamation proof: it drives the real engine
//! inline over an in-memory device + WAL ([`MemBlockDevice`] / [`MemLogSink`]) so the footprint curve is
//! byte-reproducible for a fixed seed and can be asserted exactly (`tests/churn_plateau.rs` runs in the
//! default `cargo test`). It drives the **production command-dispatch code path** — `TxnCoordinator::
//! statement` + `execute`, *exactly* what the server's `handle_run` calls per `RUN` — single-threaded,
//! and interleaves the same GC maintenance pass the server's checkpoint runs. Real engine, real Cypher,
//! real WAL-logged storage; just driven in one process so the plateau is reproducible.
//!
//! It is **not** the storage evidence. Because the device and WAL are in memory there is no store file
//! and no WAL file: durable bytes, WAL/store amplification and fsync volume are structurally
//! unmeasurable here. Those are measured by the FILE-BACKED `iot_wire` run, which drives the same
//! workload over a real Bolt wire against a real `graphus-server` (real `FileBlockDevice` + real
//! segmented WAL) and samples the on-disk footprint and the server's `/metrics`.
//!
//! # Reclamation has an operator trigger AND an automatic cadence (`rmp` #305 — shipped)
//!
//! An earlier revision of this example claimed the MVCC GC maintenance pass had "no automatic,
//! scheduled, or wire-reachable trigger". **That is no longer true**, and every file that said so has
//! been corrected. As of `rmp` #305 the live server reclaims through two real, operator-visible paths:
//!
//! 1. **`CHECKPOINT DATABASE <name>`** — a parsed admin statement (`graphus-server`'s
//!    `admin::parse_admin_statement` → `AdminCommand::CheckpointDatabase` → `DbCatalog::checkpoint` →
//!    `EngineCommand::Checkpoint`), issuable over Bolt or REST like any other statement. It runs a
//!    reader-safe GC pass plus a sharp checkpoint, and now increments
//!    `graphus_maintenance_checkpoints_total` / `_versions_reclaimed_total` (`rmp` #694).
//! 2. **A background maintenance cadence** — `graphus-server`'s engine loop runs the same pass
//!    automatically once the WAL has grown by `clamp(4 × store_bytes, 8 MiB, 256 MiB)` since the last
//!    one (`engine::maintenance_interval_bytes`, `rmp` #556), with no operator action at all.
//!
//! The in-process GC pass below ([`gc_pass`]) is therefore not a workaround for a missing trigger: it
//! is the *deterministic stand-in* for those two paths, letting the mirror place a reclaim at an exact,
//! reproducible point in the tick loop. The wire run exercises the real triggers.

use std::time::{Duration, Instant};

use graphus_core::{TxnId, Value};
use graphus_cypher::coordinator::TxnCoordinator;
use graphus_cypher::{
    ConstraintKind, IndexCatalog, Parameters, Row, RowValue, analyze, bind_parameters, execute,
    lower, parse_tokens, plan_physical, tokenize,
};
use graphus_io::{BlockDevice, MemBlockDevice, PAGE_SIZE};
use graphus_storage::{ConstraintTypeDescriptor, RecordStore};
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
    /// Real end-to-end latency (ns) of every single-reading ingest statement (plan + execute + commit),
    /// in execution order. Machine-variant, never gated — but **measured**, never invented.
    pub insert_latencies_ns: Vec<u64>,
    /// Real end-to-end latency (ns) of every per-tick retention `DETACH DELETE`, in execution order.
    /// Kept separate from the ingest family: a windowed delete is a structurally different (and far
    /// more expensive) statement, so folding both into one percentile would misreport both.
    pub delete_latencies_ns: Vec<u64>,
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

    /// The `permille`-th percentile (`500` = p50, `990` = p99, `999` = p99.9) of the **ingest**
    /// statement latencies, in milliseconds, or `None` when nothing was ingested. Real measurements —
    /// an empty family yields `None` rather than a fabricated `0.0`.
    #[must_use]
    pub fn insert_latency_ms(&self, permille: u32) -> Option<f64> {
        percentile_ms(&self.insert_latencies_ns, permille)
    }

    /// The `permille`-th percentile of the per-tick **retention `DETACH DELETE`** latencies, in
    /// milliseconds, or `None` when the window never filled (no delete ever ran).
    #[must_use]
    pub fn delete_latency_ms(&self, permille: u32) -> Option<f64> {
        percentile_ms(&self.delete_latencies_ns, permille)
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

/// The `permille`-th percentile of `latencies_ns`, in milliseconds — `None` for an empty sample (an
/// unmeasured family must never be reported as `0.0`). Nearest-rank on a copy sorted in place.
fn percentile_ms(latencies_ns: &[u64], permille: u32) -> Option<f64> {
    if latencies_ns.is_empty() {
        return None;
    }
    let mut sorted = latencies_ns.to_vec();
    sorted.sort_unstable();
    // Nearest-rank: index = ceil(permille/1000 * n) - 1, clamped into range.
    let n = sorted.len();
    let rank = ((u64::from(permille) * n as u64).div_ceil(1000)).max(1) as usize;
    let ns = sorted[rank.min(n) - 1];
    Some(ns as f64 / 1e6)
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
///
/// `catalog` is the coordinator's **populated** [`IndexCatalog`] ([`TxnCoordinator::catalog`]) — the
/// same snapshot the server's `handle_run` hands the physical planner. `rmp` #694: this driver used to
/// plan against `IndexCatalog::empty()`, so the schema it so carefully declares (a `RANGE` index on
/// `Reading.seq`, a composite on `Reading(sensor, seq)`, a `POINT` index on `Sensor.location`) was
/// invisible to the planner and **every** statement fell back to a full label scan — including the
/// per-tick retention `DELETE`, whose whole point is to seek the `Reading.seq` range index. The driver
/// was measuring an unindexed engine while the README described an indexed one.
fn run_stmt(coord: &Coord, txn: TxnId, src: &str, catalog: &IndexCatalog) -> Vec<Row> {
    let toks = tokenize(src).expect("lex");
    let ast = parse_tokens(&toks, src).expect("parse");
    let validated = analyze(&ast).expect("analyze");
    let plan = plan_physical(&lower(&validated), catalog);
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

/// Runs `src` in its own committed serializable auto-commit transaction, returning the statement's
/// end-to-end latency (plan + execute + commit) — the real per-operation cost this driver observes.
fn exec_commit(coord: &mut Coord, src: &str, catalog: &IndexCatalog) -> Duration {
    let started = Instant::now();
    let txn = coord.begin_serializable();
    let _ = run_stmt(coord, txn, src, catalog);
    coord.commit(txn).expect("commit");
    started.elapsed()
}

/// Applies the geo/time **schema** ([`Generator::schema_ddl`]) through the coordinator's typed schema
/// seam, before any data lands, so every sensor CREATE and every churn insert is constraint-checked
/// and index-maintained.
///
/// The typed coordinator calls here are the exact methods the server's admin-DDL surface dispatches
/// to after parsing the equivalent `CREATE INDEX` / `CREATE CONSTRAINT` statement — the string form
/// this driver's `schema_ddl()` emits is proven to parse to precisely this schema by the hermetic
/// `graphus-server/tests/iot_timeseries_schema.rs`, which drives those statements through
/// `parse_admin_statement` → `LocalEngine::{index_ddl, constraint_ddl}`. Each `IF NOT EXISTS`-style
/// call is idempotent, matching the DDL block's `IF NOT EXISTS` forms.
fn apply_schema(coord: &mut Coord) {
    // POINT (spatial) index on Sensor.location — a Cartesian grid over the fleet's geo positions.
    coord
        .create_point_index("sensor_location_point", "Sensor", "location", true)
        .expect("create POINT index on Sensor.location");
    // Composite RANGE index on Reading(sensor, seq) — per-sensor windowed reads.
    coord
        .begin_online_node_composite_index_named(
            Some("reading_sensor_seq"),
            "Reading",
            &["sensor".to_owned(), "seq".to_owned()],
            true,
        )
        .expect("create composite RANGE index on Reading(sensor, seq)");
    // Single-property RANGE retention index on Reading.seq — the aged-out DELETE key.
    coord
        .begin_online_node_property_index_named(Some("reading_seq"), "Reading", "seq", true)
        .expect("create RANGE index on Reading.seq");
    // RANGE index on the TEMPORAL Reading.ts — the `ts ∈ [t0, t1)` window read's seek key (`rmp` #745).
    // The RANGE key codec orders `Value::ZonedDateTime` natively, so this is a real temporal index.
    coord
        .begin_online_node_property_index_named(Some("reading_ts"), "Reading", "ts", true)
        .expect("create RANGE index on the temporal Reading.ts");
    // NODE KEY on Sensor.id (present + unique).
    coord
        .create_constraint_general(
            "sensor_id_key",
            "Sensor",
            &["id"],
            ConstraintKind::NodeKey,
            None,
        )
        .expect("create NODE KEY on Sensor.id");
    // Existence: every Reading carries a value.
    coord
        .create_constraint_general(
            "reading_value_exists",
            "Reading",
            &["value"],
            ConstraintKind::Existence,
            None,
        )
        .expect("create existence constraint on Reading.value");
    // Property-type: Reading.ts is a real temporal (`ZONED DATETIME`), never a bare epoch-ms integer.
    coord
        .create_constraint_general(
            "reading_ts_datetime",
            "Reading",
            &["ts"],
            ConstraintKind::PropertyType,
            Some(ConstraintTypeDescriptor::ZonedDateTime),
        )
        .expect("create property-type constraint on the temporal Reading.ts");

    // `rmp` #694 — DRIVE THE ONLINE INDEX BUILDS TO COMPLETION.
    //
    // `begin_online_node_property_index_named` and `create_point_index` start **non-blocking** builds:
    // the index is registered `Populating`, and is promoted to `Online` — and therefore becomes visible
    // to the planner at all ([`TxnCoordinator::catalog`] deliberately WITHHOLDS a `Populating` index, so
    // a seek is never routed to a half-built structure) — only once `advance_index_builds` has walked its
    // snapshot to the end. In the live server the engine loop pumps that queue every tick
    // (`engine::LOCAL_INDEX_BUILD_BUDGET`).
    //
    // This driver never pumped it. So the `Reading.seq` RANGE index and the `Sensor.location` POINT index
    // sat `Populating` for the ENTIRE run — not merely unused by the planner, but never finished. Nothing
    // failed, because the scan fallback returns identical results, so the example passed every assertion
    // it had while describing an indexed engine it had never actually built. Pumping here (the store is
    // still empty, so it completes instantly) is exactly what the server does, and what
    // `graphus-social-gen`'s loader does.
    while coord.advance_index_builds(usize::MAX) {}
}

/// The current live `Reading` count, read in its own committed snapshot transaction.
fn live_readings(coord: &mut Coord, catalog: &IndexCatalog) -> u64 {
    let txn = coord.begin_serializable();
    let rows = run_stmt(
        coord,
        txn,
        "MATCH (r:Reading) RETURN count(r) AS c",
        catalog,
    );
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

    // Bootstrap: apply the geo/time schema (constraints + indexes) through the typed coordinator
    // seam, then create the sensor fleet, each in its own auto-commit txn. The schema is applied
    // FIRST so the sensor fleet — and every subsequent churn insert/delete — is constraint-checked
    // and index-maintained, exercising the write-path enforcement + index maintenance under churn.
    apply_schema(&mut coord);

    // The planner's view of that schema (`rmp` #694). Snapshotted ONCE, after the DDL and before any
    // data: the schema never changes during the churn, so one snapshot is exactly what every statement
    // must plan against — and it is the same `IndexCatalog` the server's engine hands its planner. It
    // is asserted non-empty because a silently-empty catalog is precisely the defect this fixes: the
    // driver would still pass every functional assertion while secretly full-scanning.
    let catalog = coord.catalog();
    assert!(
        !catalog.indexes().is_empty(),
        "the coordinator's IndexCatalog must be populated after the schema DDL — an empty catalog \
         means every statement would fall back to a full label scan (rmp #694)"
    );

    for stmt in generator.sensor_cypher() {
        exec_commit(&mut coord, &stmt, &catalog);
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
    // Real, per-statement latencies (nanoseconds), kept apart because the two statement shapes have
    // wildly different costs: a single-reading CREATE vs a windowed retention DELETE. Mixing them into
    // one percentile family would be dishonest evidence.
    let mut insert_latencies_ns: Vec<u64> = Vec::with_capacity(cfg.total_readings() as usize);
    let mut delete_latencies_ns: Vec<u64> = Vec::with_capacity(cfg.ticks as usize);

    while let Some(t) = generator.tick() {
        // Insert this tick's new readings, each in its own committed txn (the realistic per-event
        // ingest shape). Every statement's real end-to-end latency is recorded.
        for ins in &t.inserts {
            insert_latencies_ns.push(exec_commit(&mut coord, ins, &catalog).as_nanos() as u64);
            total_ingested += 1;
        }
        // Apply the retention DELETE (aged-out readings) in its own committed txn. It seeks the
        // `Reading.seq` RANGE index (the planner sees it — `rmp` #694).
        if let Some(del) = &t.delete {
            delete_latencies_ns.push(exec_commit(&mut coord, del, &catalog).as_nanos() as u64);
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

        let live = live_readings(&mut coord, &catalog);

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
        insert_latencies_ns,
        delete_latencies_ns,
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

/// Builds a fresh coordinator, applies the geo/time schema DDL through the typed seam, and returns the
/// resulting **planner catalog** — the exact [`IndexCatalog`] every statement in [`run_churn`] is
/// planned against. Exposed so the plan-shape regression below (and any future caller) can assert what
/// the planner actually sees, rather than trusting that the DDL "worked".
pub fn schema_catalog() -> IndexCatalog {
    let mut coord = fresh_coord();
    apply_schema(&mut coord);
    coord.catalog()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Renders the physical plan of `src` under `catalog` as its `Debug` shape.
    fn plan_shape(src: &str, catalog: &IndexCatalog) -> String {
        let toks = tokenize(src).expect("lex");
        let ast = parse_tokens(&toks, src).expect("parse");
        let validated = analyze(&ast).expect("analyze");
        format!("{:?}", plan_physical(&lower(&validated), catalog))
    }

    /// **Regression for `rmp` #694.** The schema DDL this driver declares must actually reach the
    /// PLANNER, not merely the catalog.
    ///
    /// The driver used to plan every statement against `IndexCatalog::empty()`. Nothing failed: the
    /// results were identical, the steady-state and plateau assertions all held, and the README happily
    /// described an index-backed retention sweep — while the engine was in fact FULL-SCANNING every
    /// `:Reading` on every tick. The example was measuring an unindexed engine and reporting an indexed
    /// one, which is the worst kind of wrong evidence: the kind that passes.
    ///
    /// The load-bearing statement is the retention `DELETE`. It is a `seq < cutoff` range predicate, and
    /// the whole point of the `Reading.seq` RANGE index is that the sweep SEEKS it. This test asserts
    /// the planned shape: an index range seek under the populated catalog, and — to prove the test
    /// itself has teeth — a scan under the empty one.
    #[test]
    fn the_retention_delete_plans_as_an_index_range_seek_not_a_scan() {
        const RETENTION: &str = "MATCH (r:Reading) WHERE r.seq < 1000 DETACH DELETE r";

        let catalog = schema_catalog();
        assert!(
            !catalog.indexes().is_empty(),
            "the schema DDL must populate the planner's IndexCatalog"
        );

        let planned = plan_shape(RETENTION, &catalog);
        assert!(
            planned.contains("NodeIndexRangeSeek"),
            "the retention DELETE must SEEK the Reading.seq RANGE index; planned as:\n{planned}"
        );

        // Teeth: under the empty catalog the SAME statement degrades to a scan. This is precisely what
        // the driver was doing before the fix — and it is why a purely functional assertion could never
        // have caught it.
        let unplanned = plan_shape(RETENTION, &IndexCatalog::empty());
        assert!(
            !unplanned.contains("NodeIndexRangeSeek"),
            "control: with an EMPTY catalog the retention DELETE must NOT be index-backed (if it is, \
             this test proves nothing); planned as:\n{unplanned}"
        );
    }

    /// The per-sensor windowed read (a leading `sensor` equality plus a `seq` range) must use the
    /// composite `RANGE` index on `Reading(sensor, seq)` — the second index the schema declares, and the
    /// one the README claims accelerates per-sensor reads.
    #[test]
    fn the_per_sensor_windowed_read_uses_the_composite_index() {
        let catalog = schema_catalog();
        let planned = plan_shape(
            "MATCH (r:Reading) WHERE r.sensor = 's-0' AND r.seq >= 10 AND r.seq < 20 RETURN r.value",
            &catalog,
        );
        assert!(
            planned.contains("Index"),
            "the per-sensor windowed read must be index-backed; planned as:\n{planned}"
        );
    }

    /// **`rmp` #745.** The TEMPORAL window read — `ts ∈ [t0, t1)` over a real `DATETIME` property — must
    /// SEEK the `Reading.ts` RANGE index, not scan every reading. This is the query a time-series
    /// database exists to serve, and until #745 the schema *forbade* `ts` from being a temporal at all
    /// (`IS :: INTEGER`), so neither the index nor the Bolt temporal path was ever exercised.
    #[test]
    fn the_temporal_window_read_seeks_the_reading_ts_range_index() {
        const WINDOW: &str = "MATCH (r:Reading) \
             WHERE r.ts >= datetime({epochMillis: 1704067200000}) \
               AND r.ts < datetime({epochMillis: 1704067260000}) \
             RETURN r.seq";

        let catalog = schema_catalog();
        let planned = plan_shape(WINDOW, &catalog);
        assert!(
            planned.contains("NodeIndexRangeSeek"),
            "the temporal window read must SEEK the Reading.ts RANGE index; planned as:\n{planned}"
        );

        // Teeth: with an EMPTY catalog the same statement degrades to a scan, so the assertion above is
        // testing the index and not merely the shape of the plan renderer.
        let unplanned = plan_shape(WINDOW, &IndexCatalog::empty());
        assert!(
            !unplanned.contains("NodeIndexRangeSeek"),
            "control: with no index the temporal window read must NOT be index-backed:\n{unplanned}"
        );
    }

    /// Latency percentiles must be REAL: an empty family is NOT MEASURED (`None`), never a fabricated
    /// `0.0` (`rmp` #699).
    #[test]
    fn percentiles_are_none_for_an_unmeasured_family() {
        assert!(percentile_ms(&[], 500).is_none());
        // Nearest-rank over a known sample: p50 of [1, 2, 3, 4] ms is the 2nd value.
        let ns = [1_000_000u64, 2_000_000, 3_000_000, 4_000_000];
        assert!((percentile_ms(&ns, 500).expect("measured") - 2.0).abs() < 1e-9);
        assert!((percentile_ms(&ns, 999).expect("measured") - 4.0).abs() < 1e-9);
    }
}
