//! `measure_server` — meter a **running** Graphus server process and emit a standardized evidence
//! report (`report.json` + `report.md`).
//!
//! Where [`emit_evidence`](../emit_evidence.rs) injects representative figures (it boots no server),
//! this driver measures a *real, live* server: a shell example (e.g.
//! `examples/social-network-uds/run.sh`) boots `graphus-server`, drives a workload against it, and
//! then invokes this binary with the server's **PID** and **store/WAL paths** plus the workload
//! statistics it tracked. The binary reads the server process's cumulative CPU and current RSS, the
//! on-disk store/WAL footprint, computes the amplification ratios, and writes the evidence directory.
//!
//! It is the dev-only bridge that lets a portable `bash` example collect the same standardized,
//! schema-versioned evidence the Rust harness produces — the heavy `/proc` + `getrusage` metering and
//! the report emitter all live here, in the harness crate, not duplicated in shell.
//!
//! ## Usage
//!
//! ```text
//! measure_server \
//!   --evidence-dir <dir> \
//!   --scenario <id> --description <text> \
//!   --pid <server-pid> --uptime-secs <f64> \
//!   --store <store-file-or-dir> --wal <wal-file-or-dir> \
//!   --nodes <u64> --rels <u64> \
//!   [--peak-rss-bytes <u64>] \
//!   [--workload-ops <u64> --workload-secs <f64>] \
//!   [--p50-ms <f64> --p99-ms <f64> --p999-ms <f64>] [--abort-rate <f64>] \
//!   [--logical-bytes-written <u64>] [--logical-graph-bytes <u64>] \
//!   [--param key=value]... [--note <text>]... [--phase name=millis]...
//! ```
//!
//! The latency-percentile and abort-rate inputs (`rmp #253`) let a shell example feed the figures
//! its driver measured (e.g. the official Neo4j-driver workload's per-operation latencies and SSI
//! abort tally) straight into the standardized [`ThroughputSection`]. Each is optional and defaults
//! to `0.0` ("not measured") so an example that cannot supply them stays honest.
//!
//! [`ThroughputSection`]: graphus_examples_harness::ThroughputSection
//!
//! Every flag is parsed defensively: a missing or malformed value is a hard error (the example must
//! pass real measured inputs), but every *metric* the server cannot supply is honestly left at its
//! zero default rather than fabricated.

use std::process::ExitCode;
use std::time::Duration;

use graphus_examples_harness::resource::cpu_section;
use graphus_examples_harness::{
    CpuSection, DatasetScale, EvidenceCollector, RunMetadata, Target, cumulative_cpu_times,
    current_rss_bytes,
};

/// Parsed command-line inputs. Required fields have no default; optional metrics default to "not
/// measured" (zero), which the report renders honestly.
#[derive(Debug, Default)]
struct Args {
    evidence_dir: String,
    scenario: String,
    description: String,
    pid: u32,
    uptime_secs: f64,
    store: String,
    wal: String,
    nodes: u64,
    rels: u64,
    /// Peak RSS the *example* observed by sampling the live server during the workload (the server's
    /// RSS after teardown is unreadable, so the example samples it while alive and passes the high
    /// watermark here). `None` ⇒ fall back to the single end-of-run RSS read this binary takes.
    peak_rss_bytes: Option<u64>,
    workload_ops: Option<u64>,
    workload_secs: Option<f64>,
    /// Per-operation latency percentiles, in milliseconds, as measured by the example's driver.
    /// `None` ⇒ left at the section default (`0.0`).
    p50_ms: Option<f64>,
    p99_ms: Option<f64>,
    p999_ms: Option<f64>,
    /// Transaction abort / conflict rate in `[0.0, 1.0]` the example's concurrency driver observed.
    abort_rate: Option<f64>,
    logical_bytes_written: Option<u64>,
    logical_graph_bytes: Option<u64>,
    params: Vec<(String, String)>,
    notes: Vec<String>,
    phases: Vec<(String, f64)>,
}

fn main() -> ExitCode {
    let args = match parse_args() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("measure_server: {e}");
            return ExitCode::FAILURE;
        }
    };

    let target = Target::Pid(args.pid);

    // --- CPU: the server is dedicated to this workload for its whole lifetime, so its cumulative
    // since-boot CPU IS the workload's CPU. Pair it with the process's wall-clock uptime to derive
    // mean core utilisation. If the PID has already gone (it should not — the example holds it open),
    // the section honestly stays zero.
    let cpu: CpuSection = match cumulative_cpu_times(target) {
        Some(times) => cpu_section(times, Duration::from_secs_f64(args.uptime_secs.max(0.0))),
        None => {
            eprintln!(
                "measure_server: warning: could not read CPU for pid {} (already exited?); \
                 leaving CPU section zeroed",
                args.pid
            );
            CpuSection::default()
        }
    };

    // --- Memory: one current RSS read of the live server (the "final" RSS). The peak is the high
    // watermark the example sampled while the server was alive (preferred); fall back to this read.
    let final_rss = current_rss_bytes(target).unwrap_or(0);
    let peak_rss = args.peak_rss_bytes.unwrap_or(0).max(final_rss);

    let metadata = RunMetadata::new(args.scenario.clone(), args.description.clone())
        .with_dataset(DatasetScale::new(args.nodes, args.rels));
    let mut collector = EvidenceCollector::new(metadata);
    for (k, v) in &args.params {
        collector
            .metadata_mut()
            .workload
            .insert(k.clone(), v.clone());
    }
    collector.start();

    for (name, millis) in &args.phases {
        collector.phase(name.clone(), Duration::from_secs_f64(millis / 1_000.0));
    }

    collector.cpu_mut().user_secs = cpu.user_secs;
    collector.cpu_mut().system_secs = cpu.system_secs;
    collector.cpu_mut().mean_core_utilisation = cpu.mean_core_utilisation;
    collector.memory_mut().peak_rss_bytes = peak_rss;
    collector.memory_mut().final_rss_bytes = final_rss;

    // --- Storage: measure the real on-disk store + WAL footprint, defaulting bytes_fsynced to the
    // WAL byte count (the faithful proxy the collector documents).
    if let Err(e) = collector.record_storage(&args.store, &args.wal, None) {
        eprintln!("measure_server: failed to measure storage: {e}");
        return ExitCode::FAILURE;
    }
    // --- Amplification: only when the example supplied the logical figures.
    let logical_written = args.logical_bytes_written.unwrap_or(0);
    let logical_graph = args.logical_graph_bytes.unwrap_or(0);
    if logical_written > 0 || logical_graph > 0 {
        collector.record_amplification(logical_written, logical_graph);
    }

    // --- Throughput: only when the example timed a workload window.
    if let (Some(ops), Some(secs)) = (args.workload_ops, args.workload_secs) {
        if secs > 0.0 {
            collector.throughput_mut().operations = ops;
            collector.throughput_mut().ops_per_sec = ops as f64 / secs;
        }
    }
    // --- Latency percentiles + abort rate: the figures the example's driver measured directly
    // (the harness cannot read per-operation latency / SSI aborts from the server's PID). Each is
    // applied only when supplied, so an unmeasured percentile stays at its honest 0.0 default.
    if let Some(p50) = args.p50_ms {
        collector.throughput_mut().p50_latency_ms = p50;
    }
    if let Some(p99) = args.p99_ms {
        collector.throughput_mut().p99_latency_ms = p99;
    }
    if let Some(p999) = args.p999_ms {
        collector.throughput_mut().p999_latency_ms = p999;
    }
    if let Some(rate) = args.abort_rate {
        collector.throughput_mut().abort_rate = rate;
    }

    for note in &args.notes {
        collector.note(note.clone());
    }
    collector.note(format!(
        "Live measurement of graphus-server pid {} over {:.3}s uptime; CPU is the server's \
         cumulative since-boot usage (the process is dedicated to this workload), RSS is sampled \
         from the live process.",
        args.pid, args.uptime_secs
    ));

    let report = collector.finish();
    match report.write_to(&args.evidence_dir) {
        Ok((json, md)) => {
            println!("wrote {}", json.display());
            println!("wrote {}", md.display());
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!(
                "measure_server: failed to write evidence to {}: {e}",
                args.evidence_dir
            );
            ExitCode::FAILURE
        }
    }
}

/// Parses the `--flag value` command line into [`Args`], validating required fields.
fn parse_args() -> Result<Args, String> {
    let mut args = Args::default();
    let mut it = std::env::args().skip(1);
    let mut seen_pid = false;
    let mut seen_store = false;
    let mut seen_wal = false;

    while let Some(flag) = it.next() {
        let mut value = || it.next().ok_or_else(|| format!("missing value for {flag}"));
        match flag.as_str() {
            "--evidence-dir" => args.evidence_dir = value()?,
            "--scenario" => args.scenario = value()?,
            "--description" => args.description = value()?,
            "--pid" => {
                args.pid = value()?.parse().map_err(|e| format!("--pid: {e}"))?;
                seen_pid = true;
            }
            "--uptime-secs" => {
                args.uptime_secs = value()?
                    .parse()
                    .map_err(|e| format!("--uptime-secs: {e}"))?;
            }
            "--store" => {
                args.store = value()?;
                seen_store = true;
            }
            "--wal" => {
                args.wal = value()?;
                seen_wal = true;
            }
            "--nodes" => args.nodes = value()?.parse().map_err(|e| format!("--nodes: {e}"))?,
            "--rels" => args.rels = value()?.parse().map_err(|e| format!("--rels: {e}"))?,
            "--peak-rss-bytes" => {
                args.peak_rss_bytes = Some(
                    value()?
                        .parse()
                        .map_err(|e| format!("--peak-rss-bytes: {e}"))?,
                );
            }
            "--workload-ops" => {
                args.workload_ops = Some(
                    value()?
                        .parse()
                        .map_err(|e| format!("--workload-ops: {e}"))?,
                );
            }
            "--workload-secs" => {
                args.workload_secs = Some(
                    value()?
                        .parse()
                        .map_err(|e| format!("--workload-secs: {e}"))?,
                );
            }
            "--p50-ms" => {
                args.p50_ms = Some(value()?.parse().map_err(|e| format!("--p50-ms: {e}"))?);
            }
            "--p99-ms" => {
                args.p99_ms = Some(value()?.parse().map_err(|e| format!("--p99-ms: {e}"))?);
            }
            "--p999-ms" => {
                args.p999_ms = Some(value()?.parse().map_err(|e| format!("--p999-ms: {e}"))?);
            }
            "--abort-rate" => {
                args.abort_rate = Some(value()?.parse().map_err(|e| format!("--abort-rate: {e}"))?);
            }
            "--logical-bytes-written" => {
                args.logical_bytes_written = Some(
                    value()?
                        .parse()
                        .map_err(|e| format!("--logical-bytes-written: {e}"))?,
                );
            }
            "--logical-graph-bytes" => {
                args.logical_graph_bytes = Some(
                    value()?
                        .parse()
                        .map_err(|e| format!("--logical-graph-bytes: {e}"))?,
                );
            }
            "--param" => {
                let raw = value()?;
                let (k, v) = raw
                    .split_once('=')
                    .ok_or_else(|| format!("--param expects key=value, got {raw:?}"))?;
                args.params.push((k.to_string(), v.to_string()));
            }
            "--note" => args.notes.push(value()?),
            "--phase" => {
                let raw = value()?;
                let (name, millis) = raw
                    .split_once('=')
                    .ok_or_else(|| format!("--phase expects name=millis, got {raw:?}"))?;
                let millis: f64 = millis
                    .parse()
                    .map_err(|e| format!("--phase millis for {name:?}: {e}"))?;
                args.phases.push((name.to_string(), millis));
            }
            other => return Err(format!("unknown flag {other:?}")),
        }
    }

    if args.evidence_dir.is_empty() {
        return Err("--evidence-dir is required".to_string());
    }
    if args.scenario.is_empty() {
        return Err("--scenario is required".to_string());
    }
    if !seen_pid {
        return Err("--pid is required".to_string());
    }
    if !seen_store {
        return Err("--store is required".to_string());
    }
    if !seen_wal {
        return Err("--wal is required".to_string());
    }
    Ok(args)
}
