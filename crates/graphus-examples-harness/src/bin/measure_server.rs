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
//!   [--total-millis <f64>] \
//!   [--cpu-user-secs <f64> --cpu-system-secs <f64> --cpu-window-secs <f64>] \
//!   [--workload-ops <u64> --workload-secs <f64>] \
//!   [--p50-ms <f64> --p99-ms <f64> --p999-ms <f64>] [--abort-rate <f64>] \
//!   [--logical-bytes-written <u64>] [--logical-graph-bytes <u64>] \
//!   [--param key=value]... [--note <text>]... [--phase name=millis]...
//! ```
//!
//! `--total-millis` (`rmp` #697) is the report's `total_millis`: the wall-clock duration of the
//! example's WORKLOAD, as the example measured it. Without it the collector would time only its own
//! (millisecond-scale) report-building window and emit *that* as the run's duration — a number that
//! describes nothing. It is optional, so an example that does not track a workload window simply
//! leaves `total_millis` at the collector's own bracket rather than reporting a fabricated one.
//!
//! `--cpu-user-secs` / `--cpu-system-secs` / `--cpu-window-secs` (`rmp` #697) exist for the same
//! reason on the CPU vector: an example that RESTARTS or CRASHES its server measures a process that
//! no longer exists by the time this binary runs, so `--pid`'s cumulative CPU would describe only the
//! surviving (post-recovery) process. Such an example accumulates the real per-lifetime CPU itself and
//! passes it here; the three flags must be supplied together and then take precedence over the pid.
//!
//! The latency-percentile and abort-rate inputs (`rmp #253`) let a shell example feed the figures
//! its driver measured (e.g. the official Neo4j-driver workload's per-operation latencies and SSI
//! abort tally) straight into the standardized [`ThroughputSection`]. Each is optional and defaults
//! to `0.0` ("not measured") so an example that cannot supply them stays honest.
//!
//! [`ThroughputSection`]: graphus_examples_harness::ThroughputSection
//!
//! ## `--total-millis`: the workload's wall-time, not this binary's (`rmp #699`)
//!
//! This binary is invoked **after** the example's workload has already finished, so the collector
//! cannot bracket it: a `start()`-to-`finish()` interval here measures the few hundredths of a
//! millisecond spent *building the report*. Every example that calls this MUST therefore pass the
//! workload wall-time it measured via `--total-millis`. When it is absent, `--workload-secs` (the
//! timed throughput window) is used as the honest fallback; when neither is given, `total_millis`
//! stays at `0.0` ("not measured") and a note records that — never a fabricated near-zero.
//!
//! Every flag is parsed defensively: a missing or malformed value is a hard error (the example must
//! pass real measured inputs), but every *metric* the server cannot supply is honestly left at its
//! zero default rather than fabricated.

use std::process::ExitCode;
use std::time::Duration;

use graphus_examples_harness::resource::cpu_section;
use graphus_examples_harness::{
    CpuSection, CpuTimes, DatasetScale, EvidenceCollector, RunMetadata, Target,
    cumulative_cpu_times, current_rss_bytes,
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
    /// The workload's measured wall-time, in milliseconds. This binary runs *after* the workload, so
    /// it cannot bracket it — see the module docs. `None` ⇒ fall back to `workload_secs`, else
    /// "not measured".
    total_millis: Option<f64>,
    /// CPU seconds the example *itself* accumulated for the measured server(s) (`rmp` #697). An
    /// example that RESTARTS or CRASHES its server cannot get this from `--pid`: by the time this
    /// binary runs, the process that did the work is gone and the surviving pid only accounts for its
    /// own (post-recovery) lifetime. Such an example samples `/proc/<pid>/stat` before each shutdown
    /// and passes the totals here; they override the pid read. All three must be given together.
    cpu_user_secs: Option<f64>,
    cpu_system_secs: Option<f64>,
    cpu_window_secs: Option<f64>,
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
    let args = match parse_args(std::env::args().skip(1)) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("measure_server: {e}");
            return ExitCode::FAILURE;
        }
    };

    let target = Target::Pid(args.pid);

    // --- CPU. Two sources, in priority order:
    //
    // 1. The example's OWN accounting (`--cpu-user-secs` / `--cpu-system-secs` / `--cpu-window-secs`).
    //    Mandatory for an example that restarts or CRASHES its server: the process that executed the
    //    workload no longer exists, so reading `--pid` would attribute the run's CPU to the surviving
    //    (post-recovery) process — a real number describing the wrong thing (`rmp` #697).
    // 2. Otherwise the pid's cumulative since-boot CPU, which IS the workload's CPU when the server
    //    lived for exactly the workload. If the pid has already gone, the section honestly stays zero.
    let cpu: CpuSection = match (
        args.cpu_user_secs,
        args.cpu_system_secs,
        args.cpu_window_secs,
    ) {
        (Some(user), Some(system), Some(window)) => cpu_section(
            CpuTimes {
                user_secs: user.max(0.0),
                system_secs: system.max(0.0),
            },
            Duration::from_secs_f64(window.max(0.0)),
        ),
        _ => match cumulative_cpu_times(target) {
            Some(times) => cpu_section(times, Duration::from_secs_f64(args.uptime_secs.max(0.0))),
            None => {
                eprintln!(
                    "measure_server: warning: could not read CPU for pid {} (already exited?); \
                     leaving CPU section zeroed",
                    args.pid
                );
                CpuSection::default()
            }
        },
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
    // The workload already ran (and was timed) before this binary was invoked, so the collector could
    // not bracket it: hand it the wall-time the example measured. Otherwise total_millis would time
    // this report's own emission — a few hundredths of a millisecond that read as if measured.
    collector.record_total_duration_from(args.total_millis, args.workload_secs);

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
    // --- Total wall-clock (rmp #699): the report's `total_millis` must be the WORKLOAD's duration, not
    // this binary's own start()→finish() window. Without this it reported the time it took to *build the
    // report* — microseconds — as if it were the run's duration, which is a fabricated figure. The
    // workload window the example measured is the honest total; when the example supplied none, the
    // collector's own window stands (and is labelled as such by the phases it did record).
    if let Some(secs) = args.workload_secs {
        if secs > 0.0 {
            collector.record_total_duration(Duration::from_secs_f64(secs));
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

    // --- Total wall-clock: the example's measured WORKLOAD window (`rmp` #697), never this binary's
    // own report-building time. Only set when the example supplied it.
    if let Some(millis) = args.total_millis {
        if millis > 0.0 {
            collector.record_total_duration(Duration::from_secs_f64(millis / 1_000.0));
        }
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
///
/// Takes the argument iterator (rather than reading `std::env::args()` itself) so the parsing —
/// including the `rmp` #697 `--total-millis` flag — is unit-testable.
fn parse_args<I: Iterator<Item = String>>(argv: I) -> Result<Args, String> {
    let mut args = Args::default();
    let mut it = argv;
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
            "--total-millis" => {
                args.total_millis = Some(
                    value()?
                        .parse()
                        .map_err(|e| format!("--total-millis: {e}"))?,
                );
            }
            "--cpu-user-secs" => {
                args.cpu_user_secs = Some(
                    value()?
                        .parse()
                        .map_err(|e| format!("--cpu-user-secs: {e}"))?,
                );
            }
            "--cpu-system-secs" => {
                args.cpu_system_secs = Some(
                    value()?
                        .parse()
                        .map_err(|e| format!("--cpu-system-secs: {e}"))?,
                );
            }
            "--cpu-window-secs" => {
                args.cpu_window_secs = Some(
                    value()?
                        .parse()
                        .map_err(|e| format!("--cpu-window-secs: {e}"))?,
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

#[cfg(test)]
mod tests {
    use super::*;
    use graphus_examples_harness::EvidenceCollector;

    fn argv(args: &[&str]) -> impl Iterator<Item = String> + use<> {
        args.iter()
            .map(|s| (*s).to_string())
            .collect::<Vec<_>>()
            .into_iter()
    }

    /// The minimal required flag set, so each test can bolt its own optional flags onto it.
    fn required() -> Vec<&'static str> {
        vec![
            "--evidence-dir",
            "/tmp/evidence",
            "--scenario",
            "unit-test",
            "--pid",
            "1",
            "--store",
            "/tmp/store",
            "--wal",
            "/tmp/wal",
        ]
    }

    /// `rmp` #697 regression: `--total-millis` must be accepted and carried through, so an example
    /// can report the WORKLOAD's wall-clock as `total_millis` instead of this binary's own
    /// report-building window (the fabricated figure the `social-network-uds` audit found).
    #[test]
    fn total_millis_flag_is_parsed() {
        let mut a = required();
        a.extend_from_slice(&["--total-millis", "24680.5"]);
        let parsed = parse_args(argv(&a)).expect("parses");
        assert_eq!(parsed.total_millis, Some(24680.5));
    }

    /// Absent the flag, the field stays `None` — the binary then leaves `total_millis` to the
    /// collector's own bracket rather than inventing a workload duration.
    #[test]
    fn total_millis_defaults_to_none() {
        let parsed = parse_args(argv(&required())).expect("parses");
        assert_eq!(parsed.total_millis, None);
    }

    /// A malformed value is a hard error: an example must pass a real measurement, never a silently
    /// swallowed one.
    #[test]
    fn total_millis_rejects_a_malformed_value() {
        let mut a = required();
        a.extend_from_slice(&["--total-millis", "not-a-number"]);
        let err = parse_args(argv(&a)).expect_err("must reject");
        assert!(err.contains("--total-millis"), "unexpected error: {err}");
    }

    /// The end-to-end effect of the flag: `record_total_duration` overrides the collector's own
    /// start-to-finish bracket, so the emitted report carries the workload's duration.
    #[test]
    fn recorded_total_duration_lands_in_the_report() {
        let mut collector = EvidenceCollector::new(graphus_examples_harness::RunMetadata::new(
            "unit-test",
            "total-millis wiring",
        ));
        collector.start();
        collector.record_total_duration(Duration::from_secs_f64(12.5));
        let report = collector.finish();
        assert!(
            (report.total_millis - 12_500.0).abs() < 1.0,
            "total_millis should be the recorded workload window, got {}",
            report.total_millis
        );
    }

    /// `rmp` #697 regression: an example that CRASHES and restarts its server must be able to supply
    /// the CPU it accumulated across the server's lifetimes, because the pid this binary can read is
    /// the post-recovery process — it never executed the workload.
    #[test]
    fn explicit_cpu_overrides_the_pid_read() {
        let mut a = required();
        a.extend_from_slice(&[
            "--cpu-user-secs",
            "9.5",
            "--cpu-system-secs",
            "2.5",
            "--cpu-window-secs",
            "6.0",
        ]);
        let parsed = parse_args(argv(&a)).expect("parses");
        assert_eq!(parsed.cpu_user_secs, Some(9.5));
        assert_eq!(parsed.cpu_system_secs, Some(2.5));
        assert_eq!(parsed.cpu_window_secs, Some(6.0));

        // …and the section they build reports 12 CPU-seconds over a 6 s window = 2 cores' worth.
        let section = cpu_section(
            CpuTimes {
                user_secs: parsed.cpu_user_secs.unwrap(),
                system_secs: parsed.cpu_system_secs.unwrap(),
            },
            Duration::from_secs_f64(parsed.cpu_window_secs.unwrap()),
        );
        assert!((section.user_secs - 9.5).abs() < 1e-9);
        assert!((section.system_secs - 2.5).abs() < 1e-9);
        assert!(
            (section.mean_core_utilisation - 2.0).abs() < 1e-9,
            "12 CPU-seconds over 6 wall-seconds is 2.0 cores, got {}",
            section.mean_core_utilisation
        );
    }

    /// The latency percentiles remain OPTIONAL: an example that cannot measure them must be able to
    /// omit them (they then stay at the honest `0.0` "not measured" default) rather than pass zeros
    /// that read as a measurement. This guards the other half of the `rmp` #697 evidence-honesty fix.
    #[test]
    fn latency_percentiles_are_optional_and_parse_when_given() {
        let parsed = parse_args(argv(&required())).expect("parses");
        assert_eq!(parsed.p50_ms, None);
        assert_eq!(parsed.p99_ms, None);
        assert_eq!(parsed.p999_ms, None);

        let mut a = required();
        a.extend_from_slice(&[
            "--p50-ms",
            "18.5",
            "--p99-ms",
            "210.0",
            "--p999-ms",
            "412.25",
            "--abort-rate",
            "0.625",
        ]);
        let parsed = parse_args(argv(&a)).expect("parses");
        assert_eq!(parsed.p50_ms, Some(18.5));
        assert_eq!(parsed.p99_ms, Some(210.0));
        assert_eq!(parsed.p999_ms, Some(412.25));
        assert_eq!(parsed.abort_rate, Some(0.625));
    }
}
