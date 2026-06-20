//! `iot_churn` — the sustained ingest + retention churn workload + storage-reclamation proof for
//! `examples/iot-timeseries` (`rmp` tasks #295 + #296), driving the REAL Graphus engine.
//!
//! # What it proves
//!
//! 1. **Sustained ingest + retention to a steady state (#295).** A long-running loop feeds the
//!    deterministic [`Generator`](graphus_iot_gen::Generator) tick-by-tick into the engine: each tick
//!    inserts `rate` new `:Reading`s and `DETACH DELETE`s the readings that aged out of the retention
//!    window. After the window fills, the live `Reading` count **stabilises** within
//!    `[window, window + rate)` — the steady state — and stays there for the rest of the run, with no
//!    error.
//!
//! 2. **Storage reclamation: a plateaued footprint, not unbounded growth (#296).** The durable
//!    on-disk footprint (device page high-water × page size) is sampled every tick. Under churn the
//!    MVCC engine *tombstones* deleted records and a **GC maintenance pass** physically reclaims
//!    their slots into a free-list that new inserts reuse, so the footprint reaches a **plateau**:
//!    bounded despite total-ingested ≫ window. The proof asserts the late-run footprint is within a
//!    small constant factor of the post-warmup footprint while many× more readings have been
//!    ingested than the window ever holds, and reports the page high-water mark.
//!
//! The engine-driving logic lives in [`graphus_iot_gen::churn`] (shared with `iot_evidence` and the
//! hermetic `churn_plateau` cargo test); this binary owns the CLI, the human-readable curve, and the
//! pass/fail assertions. See that module's docs for why the workload drives the engine inline (the
//! GC maintenance pass has no over-the-wire trigger — `rmp #305`).
//!
//! Usage:
//!   cargo run -p graphus-iot-gen --features churn --bin iot_churn -- --profile fast
//!   cargo run -p graphus-iot-gen --features churn --bin iot_churn -- --profile fast --json <path>
//!   cargo run -p graphus-iot-gen --features churn --bin iot_churn -- --profile large --no-gc

use std::path::PathBuf;
use std::process::ExitCode;

use graphus_iot_gen::GenConfig;
use graphus_iot_gen::churn::{run_churn, samples_json};

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
        out.total_ingested(),
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
    let total_ingested = out.total_ingested();
    let ingest_to_window = out.ingest_to_window();
    if gc_enabled {
        // The post-warmup footprint must be bounded: its max within `plateau_factor` of its min,
        // despite total-ingested being many× the window.
        let ratio = out.plateau_ratio();
        let bounded = ratio <= plateau_factor;
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
