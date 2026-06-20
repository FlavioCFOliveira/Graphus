//! `iot_churn` — the sustained ingest + retention churn workload + storage-reclamation proof for
//! `examples/iot-timeseries` (`rmp` tasks #295 + #296), driving the REAL Graphus engine.
//!
//! # What it proves
//!
//! 1. **Sustained ingest + retention to a steady state (#295).** A long-running loop feeds the
//!    deterministic [`Generator`] tick-by-tick into the engine: each tick inserts `rate` new
//!    `:Reading`s and `DETACH DELETE`s the readings that aged out of the retention window. After the
//!    window fills, the live `Reading` count **stabilises** within `[window, window + rate)` — the
//!    steady state — and stays there for the rest of the run, with no error.
//!
//! 2. **Storage reclamation: a plateaued footprint, not unbounded growth (#296).** The durable
//!    on-disk footprint (device page high-water × page size) is sampled every tick. Under churn the
//!    MVCC engine *tombstones* deleted records and a **GC maintenance pass** physically reclaims
//!    their slots into a free-list that new inserts reuse, so the footprint reaches a **plateau**:
//!    bounded despite total-ingested ≫ window. The proof asserts the late-run footprint is within a
//!    small constant factor of the post-warmup footprint while many× more readings have been
//!    ingested than the window ever holds, and reports the page high-water mark.
//!
//! # Why this drives the engine INLINE (not over Bolt/TCP) — and why that is still the real engine
//!
//! Graphus's MVCC garbage collection ([`RecordStore::gc`]) is a **maintenance operation**: it is
//! WAL-logged and crash-safe, but the live server has **no automatic, scheduled, or wire-reachable
//! trigger** for it (there is no GC `EngineCommand`, Cypher procedure, or admin statement — verified
//! against `graphus-server`'s command surface). Without a GC pass the delete-old/insert-new churn
//! only tombstones records, so the footprint grows **linearly** with total-ingested (this binary
//! demonstrates that "no-GC" curve too, as the honest contrast). The reclamation the example proves
//! therefore requires invoking GC, which is reachable only through the in-process store seam
//! ([`TxnCoordinator::with_store_mut`]). So the workload drives the **production command-dispatch
//! code path** — `TxnCoordinator::statement` + `execute`, *exactly* what the server's `handle_run`
//! calls per `RUN` — inline and single-threaded (the same approach `graphus-fraud-gen`'s
//! `dst_contention` and `graphus-dst` use), interleaving the GC maintenance pass. This is the real
//! engine, real Cypher, real WAL-logged storage — just driven deterministically in one process so
//! the steady-state and plateau are reproducible and assertable.
//!
//! Usage:
//!   cargo run -p graphus-iot-gen --features churn --bin iot_churn -- --profile fast
//!   cargo run -p graphus-iot-gen --features churn --bin iot_churn -- --profile fast --json <path>
//!   cargo run -p graphus-iot-gen --features churn --bin iot_churn -- --profile large --no-gc

use std::path::PathBuf;
use std::process::ExitCode;

use graphus_core::{TxnId, Value};
use graphus_cypher::coordinator::TxnCoordinator;
use graphus_cypher::{
    IndexCatalog, Parameters, Row, RowValue, analyze, bind_parameters, execute, lower,
    parse_tokens, plan_physical, tokenize,
};
use graphus_io::{BlockDevice, MemBlockDevice, PAGE_SIZE};
use graphus_iot_gen::{GenConfig, Generator};
use graphus_storage::RecordStore;
use graphus_wal::{MemLogSink, WalManager};

type Store = RecordStore<MemBlockDevice, MemLogSink>;
type Coord = TxnCoordinator<MemBlockDevice, MemLogSink>;

/// A monotonic source of GC transaction ids, kept clear of the coordinator's own txn ids (which it
/// allocates densely from 1). GC passes use ids in a high, disjoint range so they never collide.
const GC_TXN_BASE: u64 = 1 << 40;

/// One sampled round of the churn workload — the machine-readable per-tick result the evidence
/// tooling (#297-300) and the README curve consume.
struct RoundSample {
    tick: u64,
    total_ingested: u64,
    live_readings: u64,
    footprint_bytes: u64,
    pages: u64,
    reclaimed: u64,
}

/// The full run outcome.
struct ChurnOutcome {
    cfg: GenConfig,
    gc_enabled: bool,
    samples: Vec<RoundSample>,
    /// The page high-water mark (the maximum durable page count observed across the run).
    page_high_water: u64,
    /// The maximum footprint in bytes observed across the run.
    footprint_high_water_bytes: u64,
    /// The post-warmup footprint band: (min, max) bytes observed AFTER the warmup boundary.
    steady_min_bytes: u64,
    steady_max_bytes: u64,
    /// The tick index at which warmup ends (the window has filled and one GC pass has run).
    warmup_ticks: u64,
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
    // with_store_mut borrows the store; device_mut is the `dst`-gated accessor that exposes the
    // durable device so we can read its page high-water (the same metric a real file's length /
    // PAGE_SIZE would give).
    coord.with_store_mut(|s| s.device_mut().page_count() * PAGE_SIZE as u64)
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

fn run_churn(cfg: GenConfig, gc_enabled: bool) -> ChurnOutcome {
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

        samples.push(RoundSample {
            tick: t.tick,
            total_ingested,
            live_readings: live,
            footprint_bytes: footprint,
            pages,
            reclaimed,
        });
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
/// flat, hand-rolled writer keeps the binary's dep surface minimal and the output stable). This is
/// the machine-readable result the evidence harness (#297-300) and `run.sh` consume.
fn samples_json(out: &ChurnOutcome) -> String {
    let mut s = String::with_capacity(256 + out.samples.len() * 96);
    s.push('{');
    s.push_str(&format!("\"gc_enabled\":{},", out.gc_enabled));
    s.push_str(&format!("\"seed\":{},", out.cfg.seed));
    s.push_str(&format!("\"sensors\":{},", out.cfg.sensors));
    s.push_str(&format!("\"rate\":{},", out.cfg.rate));
    s.push_str(&format!("\"window\":{},", out.cfg.window));
    s.push_str(&format!("\"ticks\":{},", out.cfg.ticks));
    s.push_str(&format!("\"warmup_ticks\":{},", out.warmup_ticks));
    s.push_str(&format!(
        "\"total_ingested\":{},",
        out.samples.last().map_or(0, |x| x.total_ingested)
    ));
    s.push_str(&format!("\"page_high_water\":{},", out.page_high_water));
    s.push_str(&format!(
        "\"footprint_high_water_bytes\":{},",
        out.footprint_high_water_bytes
    ));
    s.push_str(&format!("\"steady_min_bytes\":{},", out.steady_min_bytes));
    s.push_str(&format!("\"steady_max_bytes\":{},", out.steady_max_bytes));
    s.push_str("\"rounds\":[");
    for (i, r) in out.samples.iter().enumerate() {
        if i > 0 {
            s.push(',');
        }
        s.push_str(&format!(
            "{{\"tick\":{},\"total_ingested\":{},\"live\":{},\"footprint_bytes\":{},\"pages\":{},\"reclaimed\":{}}}",
            r.tick, r.total_ingested, r.live_readings, r.footprint_bytes, r.pages, r.reclaimed
        ));
    }
    s.push_str("]}");
    s
}

fn main() -> ExitCode {
    let mut profile = String::from("fast");
    let mut window_override: Option<u64> = None;
    let mut ticks_override: Option<u64> = None;
    let mut gc_enabled = true;
    let mut json_path: Option<PathBuf> = None;
    // Plateau tolerance: the post-warmup footprint max must be within FACTOR × its min.
    let mut plateau_factor: f64 = 1.5;

    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        match a.as_str() {
            "--profile" => match args.next() {
                Some(v) => profile = v,
                None => return fail("--profile requires a value"),
            },
            "--window" => match args.next().map(|v| v.parse::<u64>()) {
                Some(Ok(w)) if w > 0 => window_override = Some(w),
                _ => return fail("--window requires a positive integer"),
            },
            "--ticks" => match args.next().map(|v| v.parse::<u64>()) {
                Some(Ok(t)) if t > 0 => ticks_override = Some(t),
                _ => return fail("--ticks requires a positive integer"),
            },
            "--no-gc" => gc_enabled = false,
            "--json" => match args.next() {
                Some(v) => json_path = Some(PathBuf::from(v)),
                None => return fail("--json requires a path"),
            },
            "--plateau-factor" => match args.next().map(|v| v.parse::<f64>()) {
                Some(Ok(f)) if f > 1.0 => plateau_factor = f,
                _ => return fail("--plateau-factor requires a float > 1.0"),
            },
            "-h" | "--help" => {
                eprintln!(
                    "usage: iot_churn --profile <fast|large> [--window N] [--ticks N] [--no-gc] \
                     [--plateau-factor F] [--json <path>]"
                );
                return ExitCode::SUCCESS;
            }
            other => return fail(&format!("unexpected argument '{other}'")),
        }
    }

    let mut cfg = GenConfig::from_profile(&profile);
    if let Some(w) = window_override {
        cfg.window = w;
    }
    if let Some(t) = ticks_override {
        cfg.ticks = t;
    }

    let out = run_churn(cfg.clone(), gc_enabled);

    // ---------------------------------------------------------------------------------------------
    // Report the curve (footprint vs total-ingested), then assert the two claims.
    // ---------------------------------------------------------------------------------------------
    println!(
        "iot_churn: profile={profile} gc_enabled={gc_enabled} seed={} sensors={} rate={} window={} ticks={} total_ingested={}",
        cfg.seed,
        cfg.sensors,
        cfg.rate,
        cfg.window,
        cfg.ticks,
        out.samples.last().map_or(0, |s| s.total_ingested),
    );
    println!("  tick  total_ingested   live   footprint_B   pages   reclaimed");
    for r in &out.samples {
        if r.tick % 5 == 0 || r.tick == cfg.ticks - 1 {
            println!(
                "  {:4}  {:14}  {:5}  {:11}  {:6}  {:9}",
                r.tick, r.total_ingested, r.live_readings, r.footprint_bytes, r.pages, r.reclaimed
            );
        }
    }

    if let Some(path) = &json_path {
        if let Err(e) = std::fs::write(path, samples_json(&out)) {
            return fail(&format!("cannot write --json {}: {e}", path.display()));
        }
        println!("  wrote machine-readable samples to {}", path.display());
    } else {
        // Always emit the JSON on a sentinel line so a calling script can capture it without a file.
        println!("GRAPHUS_IOT_SAMPLES {}", samples_json(&out));
    }

    let mut failures = 0u32;

    // --- Claim 1 (#295): steady-state live count within [window, window + rate) after warmup. ---
    let band_lo = cfg.window;
    let band_hi = cfg.window + cfg.rate;
    let mut steady_ok = true;
    let mut steady_observed = 0u64;
    for r in &out.samples {
        if r.tick >= out.warmup_ticks {
            steady_observed += 1;
            if r.live_readings < band_lo || r.live_readings >= band_hi {
                steady_ok = false;
                eprintln!(
                    "FAIL: tick {} live={} outside steady band [{}, {})",
                    r.tick, r.live_readings, band_lo, band_hi
                );
            }
        }
    }
    if steady_observed == 0 {
        steady_ok = false;
        eprintln!("FAIL: run too short to observe any post-warmup steady-state tick");
    }
    if steady_ok {
        println!(
            "  ✓ steady-state live count held in [{band_lo}, {band_hi}) for {steady_observed} post-warmup ticks"
        );
    } else {
        failures += 1;
    }

    // --- Claim 2 (#296): footprint plateau (GC enabled) vs unbounded growth (GC disabled). ---
    let total_ingested = out.samples.last().map_or(0, |s| s.total_ingested);
    let ingest_to_window = total_ingested as f64 / cfg.window.max(1) as f64;
    if gc_enabled {
        // The post-warmup footprint must be bounded: its max within `plateau_factor` of its min,
        // despite total-ingested being many× the window.
        let ratio = out.steady_max_bytes as f64 / out.steady_min_bytes.max(1) as f64;
        let bounded = ratio <= plateau_factor;
        // And the late-run footprint must be far below what linear growth would imply: compare the
        // final footprint to the footprint right after warmup — they should be essentially equal.
        println!(
            "  storage: page_high_water={} footprint_high_water={}B steady_band=[{}, {}]B plateau_ratio={:.3} (≤{:.2}) total_ingested/window={:.1}×",
            out.page_high_water,
            out.footprint_high_water_bytes,
            out.steady_min_bytes,
            out.steady_max_bytes,
            ratio,
            plateau_factor,
            ingest_to_window,
        );
        if bounded && ingest_to_window >= 3.0 {
            println!(
                "  ✓ footprint PLATEAUED: bounded within {plateau_factor:.2}× while ingesting {ingest_to_window:.1}× the window (reclaimed space reused)"
            );
        } else {
            if !bounded {
                eprintln!(
                    "FAIL: footprint did NOT plateau — post-warmup max {}B is {:.2}× the min {}B (> {:.2}×). Reclamation is not keeping up => potential unbounded growth.",
                    out.steady_max_bytes, ratio, out.steady_min_bytes, plateau_factor
                );
            }
            if ingest_to_window < 3.0 {
                eprintln!(
                    "FAIL: run did not ingest enough (total/window={ingest_to_window:.1}× < 3×) to make the plateau meaningful"
                );
            }
            failures += 1;
        }
    } else {
        // The honest contrast: with no GC the footprint grows with total-ingested. Report the growth
        // factor; this mode is informational (no pass/fail) and is what the README uses to motivate
        // why GC maintenance is required.
        let first = out.samples.first().map_or(0, |s| s.footprint_bytes);
        let last = out.samples.last().map_or(0, |s| s.footprint_bytes);
        let growth = last as f64 / first.max(1) as f64;
        println!(
            "  (no-GC contrast) footprint grew {first}B -> {last}B ({growth:.1}×) over {total_ingested} ingested — tombstones accrue without a GC pass; this is the curve GC flattens"
        );
    }

    println!();
    if failures == 0 {
        if gc_enabled {
            println!(
                "GRAPHUS_IOT_CHURN_OK — sustained ingest+retention reached steady state and the on-disk footprint PLATEAUED under churn (reclaimed slots reused)."
            );
        } else {
            println!("GRAPHUS_IOT_CHURN_OK — no-GC contrast run completed (informational).");
        }
        ExitCode::SUCCESS
    } else {
        eprintln!("iot_churn: {failures} claim(s) failed");
        ExitCode::FAILURE
    }
}

fn fail(msg: &str) -> ExitCode {
    eprintln!("iot_churn: error: {msg}");
    ExitCode::FAILURE
}
