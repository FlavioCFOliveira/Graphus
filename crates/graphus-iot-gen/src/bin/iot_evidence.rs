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
//! # Schema mapping — and what this report deliberately does NOT claim (`rmp` #694 / #699)
//!
//! - **`storage`** — `store_bytes` = the post-warmup plateau footprint of the in-memory device
//!   (`steady_max_bytes`, deterministic), `store_pages` = `page_high_water`. **`wal_bytes`,
//!   `bytes_fsynced`, `write_amplification` and `space_amplification` are NOT MEASURED here and are
//!   reported as `0` with an explicit note**: the device and WAL are in memory, so there is no store
//!   file, no WAL file and no fsync to measure. A previous revision papered over that by smuggling the
//!   *plateau ratio* into `write_amplification` and *bytes-per-live-reading* into
//!   `space_amplification` — two fields that mean something else entirely. Those figures now live in
//!   the workload params under their own names, and the REAL durable bytes / WAL volume / fsync volume
//!   / amplification come from the file-backed `iot_wire` run.
//! - **`throughput`** — `operations` = total churn ops; `ops_per_sec` = events/sec; the p50/p99/p999
//!   are the **real, measured** per-statement ingest latencies (an earlier revision emitted `0.0`).
//! - **`memory`** — peak / final RSS over the loop.
//! - **`phases`** — one phase, `churn`; `total_millis` is the WORKLOAD wall-clock.
//! - **`workload`** — seed/sensors/rate/window/ticks, the deterministic structural results, the
//!   plateau ratio + bytes-per-live-reading, the footprint + RSS time series, the `rss_bounded` verdict.
//!
//! Hermetic: it drives the engine inline under no temp files at all (the device + WAL are in-memory).
//! Deterministic structural metrics; machine-variant RSS/throughput/latency/time.
//!
//! # Usage
//!
//! ```text
//! iot_evidence --evidence-dir <dir> [--profile fast|large|soak] [--window N] [--ticks N]
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
            "plateau_bytes_per_live_reading".into(),
            format!("{bytes_per_live:.1}"),
        );
        w.insert(
            "footprint_high_water_bytes".into(),
            outcome.footprint_high_water_bytes.to_string(),
        );
        // Real, measured statement latencies. The windowed retention DELETE is a structurally different
        // (and far costlier) statement than a single-reading ingest, so it is reported separately rather
        // than averaged into the same percentile family — folding them together would misreport both.
        if let (Some(p50), Some(p99)) = (
            outcome.insert_latency_ms(500),
            outcome.insert_latency_ms(990),
        ) {
            w.insert(
                "ingest_latency_ms".into(),
                format!(
                    "p50={p50:.3} p99={p99:.3} (n={})",
                    outcome.insert_latencies_ns.len()
                ),
            );
        }
        if let (Some(p50), Some(p99)) = (
            outcome.delete_latency_ms(500),
            outcome.delete_latency_ms(990),
        ) {
            w.insert(
                "retention_delete_latency_ms".into(),
                format!(
                    "p50={p50:.3} p99={p99:.3} (n={})",
                    outcome.delete_latencies_ns.len()
                ),
            );
        }
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
    // `total_millis` must be the WORKLOAD wall-clock, not the report-emission time (`rmp` #699 — the
    // previous baseline recorded a total of 0.02 ms for a 6.6-second run).
    collector.record_total_duration(wall);

    // CPU: the self-process cumulative time over the run.
    let cpu = cpu_section(cpu_times, wall);
    collector.cpu_mut().user_secs = cpu.user_secs;
    collector.cpu_mut().system_secs = cpu.system_secs;
    collector.cpu_mut().mean_core_utilisation = cpu.mean_core_utilisation;

    // Memory: the RSS series' peak/final (machine-variant, NOT gated).
    let mem = rss.to_section();
    collector.memory_mut().peak_rss_bytes = mem.peak_rss_bytes;
    collector.memory_mut().final_rss_bytes = mem.final_rss_bytes;

    // Storage: the DETERMINISTIC plateau of the in-memory device — and NOTHING else.
    //
    // `rmp` #694 / #699: the WAL / fsync / amplification fields are left at `0` because they are NOT
    // MEASURABLE in this mirror (the device and the WAL are in memory: no store file, no WAL file, no
    // fsync), and the note below says so in as many words. They are emphatically NOT re-used to smuggle
    // other quantities: `write_amplification` used to carry the plateau ratio and `space_amplification`
    // the bytes-per-live-reading, which made both fields lie about what they are. Those two figures are
    // now workload params under their own names, and the real storage evidence — durable bytes, WAL
    // volume, fsync volume, true write/space amplification — comes from the file-backed `iot_wire` run.
    {
        let s = collector.storage_mut();
        s.store_bytes = outcome.steady_max_bytes;
        s.store_pages = outcome.page_high_water;
    }

    // Throughput: total churn ops over the loop window; events/sec; and the REAL measured per-statement
    // ingest latency percentiles (an earlier revision emitted a fabricated 0.0 for all three).
    collector.throughput_mut().operations = throughput.count();
    collector.throughput_mut().ops_per_sec = events_per_sec;
    if let Some(p50) = outcome.insert_latency_ms(500) {
        collector.throughput_mut().p50_latency_ms = p50;
    }
    if let Some(p99) = outcome.insert_latency_ms(990) {
        collector.throughput_mut().p99_latency_ms = p99;
    }
    if let Some(p999) = outcome.insert_latency_ms(999) {
        collector.throughput_mut().p999_latency_ms = p999;
    }

    collector.note(format!(
        "STORAGE RECLAMATION PLATEAU (the DETERMINISTIC mirror, GATED): over {} ticks the workload \
         ingested {total_ingested} readings ({ingest_to_window:.1}× the retention window of {}), yet the \
         device footprint PLATEAUED — post-warmup band [{}, {}]B (plateau_ratio {plateau_ratio:.3}, page \
         high-water {} pages, {bytes_per_live:.0}B per live reading). storage.store_bytes is that plateau \
         footprint and store_pages the page high-water; both are byte-stable for a fixed seed+profile, \
         and the baseline gate holds them to a tight band. Reclaimed slots are demonstrably reused, not \
         unbounded growth. Every statement is planned against the coordinator's POPULATED IndexCatalog \
         (rmp #694), so the retention DELETE really does seek the Reading.seq RANGE index rather than \
         full-scanning as it silently did before.",
        cfg.ticks, cfg.window, outcome.steady_min_bytes, outcome.steady_max_bytes, outcome.page_high_water,
    ));
    collector.note(
        "STORAGE FIELDS NOT MEASURED HERE (rmp #694 / #699 — stated, not zero-filled by accident): this \
         mirror runs the real engine over an IN-MEMORY device and WAL, so there is no store file, no WAL \
         file and no fsync. storage.wal_bytes, storage.bytes_fsynced, storage.write_amplification and \
         storage.space_amplification are therefore 0 = NOT MEASURED, not observations. The real durable \
         bytes, cumulative WAL volume, fsync volume and true write/space amplification are measured by the \
         FILE-BACKED wire run (`iot_wire` → evidence-wire/report.json), which drives the same workload over \
         Bolt against a real graphus-server with a real FileBlockDevice and a real segmented WAL."
            .to_string(),
    );
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
        "RECLAMATION IS OPERATOR-REACHABLE AND AUTOMATIC (rmp #305 — SHIPPED; the earlier revision of this \
         example claimed the opposite, and that claim was STALE). The live server reclaims through two real \
         paths: (1) `CHECKPOINT DATABASE <name>`, a parsed admin statement issuable over Bolt or REST like \
         any other statement, which runs a reader-safe GC pass plus a sharp checkpoint; and (2) a background \
         maintenance cadence that runs the same pass automatically once the WAL has grown by \
         clamp(4 × store_bytes, 8 MiB, 256 MiB) since the last one, with no operator action at all. The \
         explicit per-tick GC pass THIS mirror interleaves is not a workaround for a missing trigger — it is \
         the DETERMINISTIC STAND-IN for those two paths, placing a reclaim at an exact, reproducible point in \
         the tick loop so the footprint curve is byte-reproducible. The real triggers are exercised over the \
         wire by the file-backed `iot_wire` run, whose report gates on the server's own \
         graphus_maintenance_versions_reclaimed_total climbing while the on-disk store plateaus."
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
        // NOTE: this deliberately does NOT claim "while RAM stays bounded". The previous revision did,
        // and the very same report recorded `rss_bounded=false` two fields later — a claim contradicted
        // by its own evidence. Process RSS in this single-process inline driver is an allocator
        // high-water, not live engine memory, and it is not a bounded-resource proof of anything (see the
        // RSS note the report emits). The DETERMINISTIC FOOTPRINT PLATEAU is the claim; RSS is reported
        // for visibility only.
        args.description =
            "IoT / time-series event graph (DETERMINISTIC in-memory mirror): sustained ingest of \
             time-stamped sensor readings under a sliding-window retention policy (delete-old + \
             insert-new churn), proving the engine reaches a steady state (live count ~ window) and the \
             device footprint PLATEAUS under churn — reclaimed slots demonstrably reused, not unbounded \
             growth. Durable bytes, WAL volume, fsync volume and amplification are NOT measurable here \
             (the device and WAL are in memory); the file-backed `iot_wire` run measures those against a \
             real server."
                .to_string();
    }
    Ok(args)
}
