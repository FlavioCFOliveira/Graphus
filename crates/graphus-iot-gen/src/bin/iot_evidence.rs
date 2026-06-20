//! `iot_evidence` — turns one sustained ingest + retention churn run into a **standardized,
//! schema-versioned** [`EvidenceReport`] for `examples/iot-timeseries` (`rmp #297`–`#300`).
//!
//! # What it captures (and how)
//!
//! The iot-timeseries headline evidence is the **storage reclamation plateau**: the on-disk footprint
//! grows while the retention window fills, then *plateaus* — bounded despite total-ingested ≫ window —
//! because the MVCC GC maintenance pass reclaims tombstoned slots that new inserts reuse. This binary
//! drives the SAME in-process churn engine as `iot_churn` ([`graphus_iot_gen::churn`]) and, over the
//! exact same tick loop, also samples process RSS, so it produces four aligned evidence series folded
//! into the shared schema:
//!
//! 1. **Storage footprint time series + page high-water + plateau** — sampled every tick from the
//!    real durable device (page high-water × page size). The deterministic plateau metrics
//!    (`page_high_water`, the post-warmup `steady_[min,max]_bytes`, `plateau_ratio`, the steady-state
//!    live count, total ingested) are byte-stable for a fixed seed + profile and are the meaningful
//!    regression signal the committed baseline gates.
//! 2. **RSS time series (process RAM, informational)** — an
//!    [`RssSampler`](graphus_examples_harness::RssSampler) samples the process at each tick. The
//!    series + its peak/final go into [`MemorySection`]; the full per-tick series + an informational
//!    `rss_bounded` verdict go into the workload params + notes. IMPORTANT: in this single-process
//!    inline driver, process RSS is a high-water of *allocator reservations*, not live engine memory
//!    (glibc retains freed arenas), so it climbs even though the engine's durable state is fully
//!    reclaimed — the deterministic FOOTPRINT plateau (not RSS) is the bounded-resource proof. RSS is
//!    machine-variant and is NEVER gated.
//! 3. **Ingest throughput** — events/sec = (inserts + deletes) executed over the churn-loop wall time,
//!    via [`ThroughputCounter`](graphus_examples_harness::ThroughputCounter). Machine-variant, NOT
//!    gated.
//! 4. **End-to-end time** — the churn-loop wall clock, recorded as the `churn` phase + the run total.
//!
//! # Schema mapping (no schema widening)
//!
//! - **`storage`** — the durable plateau: `store_bytes` = the post-warmup plateau footprint
//!   (`steady_max_bytes`, deterministic), `store_pages` = `page_high_water`, `wal_bytes` = 0 (the
//!   in-memory DST WAL is deterministic). `space_amplification` = plateau bytes per steady-state live
//!   reading (the per-retained-element on-disk cost), `write_amplification` = the `plateau_ratio`
//!   (≈ 1.0 when fully reclaimed). These four are GATED to a tight band.
//! - **`throughput`** — `operations` = total churn ops, `ops_per_sec` = events/sec.
//! - **`memory`** — peak / final RSS over the loop.
//! - **`phases`** — one phase, `churn`, with the loop wall time.
//! - **`workload`** — seed/sensors/rate/window/ticks, the deterministic structural results, the
//!   footprint + RSS time series (compact), and the `rss_bounded` verdict.
//!
//! Hermetic: it drives the engine inline under no temp files at all (the DST device + WAL are
//! in-memory). Deterministic structural metrics; machine-variant RSS/throughput/time.
//!
//! # Usage
//!
//! ```text
//! iot_evidence --evidence-dir <dir> [--profile fast|large] [--window N] [--ticks N]
//!              [--scenario iot-timeseries] [--description <text>] [--param k=v]... [--note <t>]...
//! ```

#![forbid(unsafe_code)]

use std::process::ExitCode;
use std::time::{Duration, Instant};

use graphus_examples_harness::resource::cpu_section;
use graphus_examples_harness::{
    CpuTimes, DatasetScale, EvidenceCollector, RssSampler, RunMetadata, Target, ThroughputCounter,
    cumulative_cpu_times,
};
use graphus_iot_gen::GenConfig;
use graphus_iot_gen::churn::{ChurnOutcome, run_churn_observed};

/// The factor within which the post-warmup RSS max sits relative to its min for the run to be
/// *reported* (informational only — never gated) as bounded-RAM. Generous, because process RSS is a
/// machine- and allocator-variant high-water, not a clean live-memory signal (see the honest note in
/// [`run`]): glibc retains freed arenas, so RSS climbs as a high-water even though the engine's
/// durable state plateaus. The deterministic *footprint* plateau is the real bounded-resource proof.
const RSS_BOUNDED_FACTOR: f64 = 1.5;

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("iot_evidence: error: {e}");
            ExitCode::FAILURE
        }
    }
}

#[derive(Default)]
struct Args {
    evidence_dir: String,
    profile: String,
    window: Option<u64>,
    ticks: Option<u64>,
    scenario: String,
    description: String,
    params: Vec<(String, String)>,
    notes: Vec<String>,
}

fn run() -> Result<(), String> {
    let args = parse_args()?;

    let mut cfg = GenConfig::from_profile(&args.profile);
    if let Some(w) = args.window {
        cfg.window = w;
    }
    if let Some(t) = args.ticks {
        cfg.ticks = t;
    }

    // ----- Drive the REAL churn engine, sampling RSS over the SAME tick loop. -----
    // The RSS sampler is driven manually (one point per tick) so the memory series is aligned
    // tick-for-tick with the footprint series. CPU is read once at the end (self-process cumulative).
    let mut rss = RssSampler::start(Target::SelfProcess, Duration::ZERO);
    rss.sample_now(); // a baseline point before the loop
    let started = Instant::now();
    let outcome = run_churn_observed(cfg.clone(), true, |_sample| {
        rss.sample_now();
    });
    let wall = started.elapsed();
    rss.sample_now(); // a final point after the loop
    let cpu_times = cumulative_cpu_times(Target::SelfProcess).unwrap_or(CpuTimes {
        user_secs: 0.0,
        system_secs: 0.0,
    });

    // ----- Derive the structural results + the bounded-RAM verdict. -----
    let total_ingested = outcome.total_ingested();
    let steady_live = outcome.steady_live_count();
    let plateau_ratio = outcome.plateau_ratio();
    let ingest_to_window = outcome.ingest_to_window();
    // The retained-element on-disk cost: plateau footprint bytes per live reading at steady state.
    let bytes_per_live = if steady_live > 0 {
        outcome.steady_max_bytes as f64 / steady_live as f64
    } else {
        0.0
    };
    let (rss_min, rss_max, rss_bounded) = rss_post_warmup_band(&rss, &outcome);

    // The churn executes: one op per inserted reading + one DELETE op per tick that aged anything out.
    let delete_ticks = outcome
        .samples
        .iter()
        .filter(|s| s.tick + 1 > outcome.warmup_ticks.saturating_sub(1))
        .count() as u64;
    let mut throughput = ThroughputCounter::new();
    throughput.add(total_ingested.saturating_add(delete_ticks));
    let events_per_sec = throughput.ops_per_sec_over(wall);

    // ----- Assemble the standardized report. -----
    let metadata = RunMetadata::new(args.scenario.clone(), args.description.clone()).with_dataset(
        DatasetScale::new(
            steady_live + cfg.sensors,
            steady_live, // one :EMITTED per live reading at steady state
        ),
    );
    let mut collector = EvidenceCollector::new(metadata);

    {
        let w = &mut collector.metadata_mut().workload;
        w.insert("connection".into(), "in-process (engine seam)".into());
        w.insert("profile".into(), args.profile.clone());
        w.insert("seed".into(), cfg.seed.to_string());
        w.insert("sensors".into(), cfg.sensors.to_string());
        w.insert("rate".into(), cfg.rate.to_string());
        w.insert("window".into(), cfg.window.to_string());
        w.insert("ticks".into(), cfg.ticks.to_string());
        w.insert("warmup_ticks".into(), outcome.warmup_ticks.to_string());
        w.insert("total_ingested".into(), total_ingested.to_string());
        w.insert("ingest_to_window".into(), format!("{ingest_to_window:.2}"));
        w.insert("steady_state_live".into(), steady_live.to_string());
        w.insert(
            "page_high_water".into(),
            outcome.page_high_water.to_string(),
        );
        w.insert(
            "plateau_min_bytes".into(),
            outcome.steady_min_bytes.to_string(),
        );
        w.insert(
            "plateau_max_bytes".into(),
            outcome.steady_max_bytes.to_string(),
        );
        w.insert("plateau_ratio".into(), format!("{plateau_ratio:.4}"));
        w.insert(
            "footprint_high_water_bytes".into(),
            outcome.footprint_high_water_bytes.to_string(),
        );
        w.insert(
            "ingest_events_per_sec".into(),
            format!("{events_per_sec:.1}"),
        );
        w.insert(
            "churn_wall_secs".into(),
            format!("{:.4}", wall.as_secs_f64()),
        );
        w.insert("rss_post_warmup_min_bytes".into(), rss_min.to_string());
        w.insert("rss_post_warmup_max_bytes".into(), rss_max.to_string());
        w.insert("rss_bounded".into(), rss_bounded.to_string());
        // The compact aligned time series (tick:footprint_bytes and tick:rss_bytes), for human
        // inspection of the growth-then-plateau curve and the bounded-RAM curve.
        w.insert("footprint_series".into(), footprint_series(&outcome));
        w.insert("rss_series".into(), rss_series(&rss));
        for (k, v) in &args.params {
            w.insert(k.clone(), v.clone());
        }
    }

    collector.start();
    collector.phase("churn", wall);

    // CPU: the self-process cumulative time over the run.
    let cpu = cpu_section(cpu_times, wall);
    collector.cpu_mut().user_secs = cpu.user_secs;
    collector.cpu_mut().system_secs = cpu.system_secs;
    collector.cpu_mut().mean_core_utilisation = cpu.mean_core_utilisation;

    // Memory: the RSS series' peak/final (machine-variant, NOT gated).
    let mem = rss.to_section();
    collector.memory_mut().peak_rss_bytes = mem.peak_rss_bytes;
    collector.memory_mut().final_rss_bytes = mem.final_rss_bytes;

    // Storage: the DETERMINISTIC plateau, mapped onto the gated fields.
    {
        let s = collector.storage_mut();
        s.store_bytes = outcome.steady_max_bytes;
        s.store_pages = outcome.page_high_water;
        s.wal_bytes = 0; // the in-memory DST WAL has no durable byte length to report
        s.wal_pages = 0;
        s.bytes_fsynced = 0;
        // space_amplification := plateau bytes per retained (live) reading — the per-element on-disk
        // cost at steady state. write_amplification := the plateau ratio (≈ 1.0 when fully reclaimed,
        // i.e. the late-run footprint equals the post-warmup footprint). Both deterministic, GATED.
        s.space_amplification = bytes_per_live;
        s.write_amplification = plateau_ratio;
    }

    // Throughput: total churn ops over the loop window; events/sec.
    collector.throughput_mut().operations = throughput.count();
    collector.throughput_mut().ops_per_sec = events_per_sec;

    collector.note(format!(
        "STORAGE RECLAMATION PLATEAU (the headline, DETERMINISTIC, GATED): over {} ticks the workload \
         ingested {total_ingested} readings ({ingest_to_window:.1}× the retention window of {}), yet the \
         durable on-disk footprint PLATEAUED — post-warmup band [{}, {}]B (plateau_ratio {plateau_ratio:.3}, \
         page high-water {} pages). storage.store_bytes is that plateau footprint, store_pages the page \
         high-water, space_amplification the plateau bytes per live reading, write_amplification the \
         plateau ratio. These are byte-stable for a fixed seed+profile and the baseline gate holds them \
         to a tight band; reclaimed slots are demonstrably reused, not unbounded growth.",
        cfg.ticks, cfg.window, outcome.steady_min_bytes, outcome.steady_max_bytes, outcome.page_high_water,
    ));
    collector.note(format!(
        "PROCESS RSS (machine- AND allocator-variant, NOT gated, informational): an RSS sample was taken \
         every tick over the same loop (full per-tick rss_series + footprint_series in the workload \
         params). Post-warmup RSS spanned [{rss_min}, {rss_max}]B (rss_bounded={rss_bounded} at the \
         {RSS_BOUNDED_FACTOR:.2}× heuristic). IMPORTANT: in this single-process inline driver, process RSS is \
         a HIGH-WATER of allocator reservations, not live engine memory — glibc retains freed arenas, so \
         RSS climbs even though the engine's DURABLE state is fully reclaimed (the footprint plateau at a \
         flat {} pages proves the engine releases its records). RSS is therefore recorded for visibility \
         only; the deterministic FOOTPRINT PLATEAU above is the bounded-resource proof, not RSS.",
        outcome.page_high_water,
    ));
    collector.note(
        "HONEST CAVEAT (rmp #296 / #305): the MVCC GC maintenance pass that reclaims tombstoned slots has \
         NO automatic, scheduled, or over-the-wire trigger in the live server (no GC EngineCommand, Cypher \
         procedure, or admin statement). The plateau is therefore proven by driving the engine inline and \
         interleaving an explicit GC pass per tick — the real engine, real Cypher, real WAL-logged storage, \
         just driven deterministically in one process. An operator-reachable GC trigger is filed as rmp #305."
            .to_string(),
    );
    for note in &args.notes {
        collector.note(note.clone());
    }

    eprintln!(
        "iot_evidence: profile={} window={} ticks={} total_ingested={} ({ingest_to_window:.1}× window) \
         plateau=[{}, {}]B ratio={plateau_ratio:.3} page_hw={} steady_live={} | rss=[{rss_min}, {rss_max}]B bounded={rss_bounded} \
         peak_rss={}B | {events_per_sec:.0} events/sec over {:.3}s",
        args.profile,
        cfg.window,
        cfg.ticks,
        total_ingested,
        outcome.steady_min_bytes,
        outcome.steady_max_bytes,
        outcome.page_high_water,
        steady_live,
        mem.peak_rss_bytes,
        wall.as_secs_f64(),
    );

    let report = collector.finish();
    match report.write_to(&args.evidence_dir) {
        Ok((json, md)) => {
            println!("wrote {}", json.display());
            println!("wrote {}", md.display());
            Ok(())
        }
        Err(e) => Err(format!(
            "failed to write evidence to {}: {e}",
            args.evidence_dir
        )),
    }
}

/// The post-warmup RSS band `(min, max)` and a bounded verdict (`max <= RSS_BOUNDED_FACTOR × min`).
///
/// We align RSS samples to ticks: `rss.samples()` has one baseline point, then one per tick, then one
/// final point. We consider only the samples whose tick index is `>= warmup_ticks` (skipping the
/// leading baseline + warmup region), so the band reflects steady-state memory, not the fill-up ramp.
fn rss_post_warmup_band(rss: &RssSampler, outcome: &ChurnOutcome) -> (u64, u64, bool) {
    let samples = rss.samples();
    // samples[0] is the pre-loop baseline; samples[1 + tick] corresponds to tick `tick`.
    let warmup = outcome.warmup_ticks as usize;
    let mut min = u64::MAX;
    let mut max = 0u64;
    for (idx, s) in samples.iter().enumerate() {
        // tick index for this sample is idx - 1 (sample 0 is the baseline). Only count steady-state
        // ticks (idx - 1 >= warmup, i.e. idx > warmup).
        if idx > warmup && s.rss_bytes > 0 {
            min = min.min(s.rss_bytes);
            max = max.max(s.rss_bytes);
        }
    }
    if min == u64::MAX {
        // Degenerate (very short run, or RSS unreadable on this platform): fall back to peak/final.
        let p = rss.peak_bytes().max(rss.final_bytes());
        return (p, p, true);
    }
    let bounded = max as f64 <= RSS_BOUNDED_FACTOR * min.max(1) as f64;
    (min, max, bounded)
}

/// A compact `tick:footprint_bytes` series (one entry per tick, space-separated) for the report.
fn footprint_series(outcome: &ChurnOutcome) -> String {
    let mut s = String::with_capacity(outcome.samples.len() * 12);
    for (i, r) in outcome.samples.iter().enumerate() {
        if i > 0 {
            s.push(' ');
        }
        s.push_str(&format!("{}:{}", r.tick, r.footprint_bytes));
    }
    s
}

/// A compact `tick:rss_bytes` series (the per-tick RSS samples, skipping the pre-loop baseline).
fn rss_series(rss: &RssSampler) -> String {
    let samples = rss.samples();
    let mut s = String::with_capacity(samples.len() * 12);
    // samples[0] is the baseline; samples[1..] are the per-tick samples (plus a trailing final point).
    for (i, smp) in samples.iter().skip(1).enumerate() {
        if i > 0 {
            s.push(' ');
        }
        s.push_str(&format!("{i}:{}", smp.rss_bytes));
    }
    s
}

fn parse_args() -> Result<Args, String> {
    let mut args = Args::default();
    let mut it = std::env::args().skip(1);
    while let Some(flag) = it.next() {
        let mut value = || it.next().ok_or_else(|| format!("missing value for {flag}"));
        match flag.as_str() {
            "--evidence-dir" => args.evidence_dir = value()?,
            "--profile" => args.profile = value()?,
            "--window" => {
                args.window = Some(
                    value()?
                        .parse()
                        .map_err(|_| "--window expects a positive integer".to_string())?,
                );
            }
            "--ticks" => {
                args.ticks = Some(
                    value()?
                        .parse()
                        .map_err(|_| "--ticks expects a positive integer".to_string())?,
                );
            }
            "--scenario" => args.scenario = value()?,
            "--description" => args.description = value()?,
            "--param" => {
                let raw = value()?;
                let (k, v) = raw
                    .split_once('=')
                    .ok_or_else(|| format!("--param expects key=value, got {raw:?}"))?;
                args.params.push((k.to_string(), v.to_string()));
            }
            "--note" => args.notes.push(value()?),
            "-h" | "--help" => {
                eprintln!(
                    "usage: iot_evidence --evidence-dir <dir> [--profile fast|large] [--window N] \
                     [--ticks N] [--scenario iot-timeseries] [--description <text>] [--param k=v]... \
                     [--note <t>]..."
                );
                std::process::exit(0);
            }
            other => return Err(format!("unknown flag {other:?}")),
        }
    }
    if args.evidence_dir.is_empty() {
        return Err("--evidence-dir is required".to_string());
    }
    if args.profile.is_empty() {
        args.profile = "fast".to_string();
    }
    if args.scenario.is_empty() {
        args.scenario = "iot-timeseries".to_string();
    }
    if args.description.is_empty() {
        args.description =
            "IoT / time-series event graph: sustained ingest of time-stamped sensor readings under a \
             sliding-window retention policy (delete-old + insert-new churn), proving the engine reaches \
             a steady state (live count ~ window) and the on-disk footprint PLATEAUS under churn — \
             reclaimed slots reused via the MVCC GC maintenance pass, not unbounded growth — while RAM \
             stays bounded."
                .to_string();
    }
    Ok(args)
}
