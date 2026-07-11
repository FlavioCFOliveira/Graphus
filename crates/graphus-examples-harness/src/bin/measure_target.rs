//! `measure_target` — the **external-target** sibling of [`measure_server`](./measure_server.rs).
//!
//! Where `measure_server` meters a **co-located** server (reading its `/proc/<pid>` CPU/RSS and
//! walking its on-disk store/WAL), `measure_target` meters a server the example is **attached to**
//! over the wire — a running instance that may be **remote** or simply not owned by
//! the example. There is no local PID and no local filesystem to read, so the process-level vectors
//! (CPU, RSS) and the on-disk storage vector are **not collectable** and are honestly left at their
//! zero defaults with an explicit N/A note. What *is* collectable everywhere:
//!
//!   * **client-side** throughput + latency percentiles + abort rate — measured by the example's
//!     driver and passed in (identical to `measure_server`);
//!   * **server-side** counters scraped from the target's Prometheus `/metrics` **before and after**
//!     the workload — committed/aborted txns, slow queries, the query-duration histogram, and the
//!     health invariants (statement panics, recovery panics, force-detached) — computed as deltas by
//!     [`ServerMetricsSection::from_snapshots`], attributed to the run's dedicated database when the
//!     per-database series are present.
//!
//! The report is tagged [`MeasurementMode::External`] so nobody misreads a remote run as a host
//! baseline. It performs **no** `/proc` or store-path reads.
//!
//! ## Usage
//!
//! ```text
//! measure_target \
//!   --evidence-dir <dir> \
//!   --scenario <id> --description <text> \
//!   --database <name> \
//!   --metrics-before <file> --metrics-after <file> \
//!   [--nodes <u64> --rels <u64>] \
//!   [--total-millis <f64>] \
//!   [--workload-ops <u64> --workload-secs <f64>] \
//!   [--p50-ms <f64> --p99-ms <f64> --p999-ms <f64>] [--abort-rate <f64>] \
//!   [--param key=value]... [--note <text>]... [--phase name=millis]... \
//!   [--assert] [--max-abort-rate <f64>]
//! ```
//!
//! The two `--metrics-*` files are the raw Prometheus text captured by the shell harness
//! (`harness_scrape_metrics`) immediately before and after the workload window.
//!
//! `--total-millis` is the workload's measured wall-time. Like `measure_server`, this binary runs
//! *after* the workload, so an unbracketed `start()`/`finish()` would time the report's own emission
//! rather than the run (`rmp #699`); `--workload-secs` is the fallback and, absent both, `total_millis`
//! stays at `0.0` = **not measured**.
//!
//! ## External-mode invariant gate (`--assert`)
//!
//! With `--assert`, the binary exits non-zero if any **host-independent** health invariant is
//! violated over the window — replacing the host-specific baseline diff, which is meaningless against
//! a foreign host. Enforced:
//!   * `statement_panics == 0`, `engine_recovery_panics == 0`, `engine_force_detached == 0`,
//!     `engine_force_detached_active == 0` (a healthy server never panics a statement or wedges an
//!     engine);
//!   * the server actually **observed** the workload (committed txns delta `> 0` **or** query-count
//!     delta `> 0`) — so an attach that silently hit the wrong endpoint fails loudly;
//!   * `abort_rate <= --max-abort-rate` when that bound is supplied.
//!
//! Note we deliberately do **not** assert `query_count == ops`: standalone auto-commit reads run
//! under snapshot isolation and are *not* always recorded in the query-duration histogram, so a
//! strict equality would false-fail a read workload. The "server saw the workload" check is the
//! honest, robust substitute.

use std::process::ExitCode;

use graphus_examples_harness::{
    DatasetScale, EvidenceCollector, MeasurementMode, RunMetadata, ServerMetricsSection, scrape,
};

/// Parsed command-line inputs. Required fields have no default; optional metrics default to "not
/// measured" (zero), which the report renders honestly.
#[derive(Debug, Default)]
struct Args {
    evidence_dir: String,
    scenario: String,
    description: String,
    database: String,
    metrics_before: String,
    metrics_after: String,
    nodes: u64,
    rels: u64,
    peak_rss_bytes: Option<u64>,
    /// The workload's measured wall-time, in milliseconds (see the module docs). `None` ⇒ fall back
    /// to `workload_secs`, else "not measured".
    total_millis: Option<f64>,
    workload_ops: Option<u64>,
    workload_secs: Option<f64>,
    p50_ms: Option<f64>,
    p99_ms: Option<f64>,
    p999_ms: Option<f64>,
    abort_rate: Option<f64>,
    params: Vec<(String, String)>,
    notes: Vec<String>,
    phases: Vec<(String, f64)>,
    assert_invariants: bool,
    max_abort_rate: Option<f64>,
}

fn main() -> ExitCode {
    let args = match parse_args() {
        Ok(a) => a,
        Err(e) => {
            eprintln!("measure_target: {e}");
            return ExitCode::FAILURE;
        }
    };

    // --- Server-side evidence: parse the two Prometheus snapshots and diff them.
    let before_text = match std::fs::read_to_string(&args.metrics_before) {
        Ok(t) => t,
        Err(e) => {
            eprintln!(
                "measure_target: cannot read --metrics-before {}: {e}",
                args.metrics_before
            );
            return ExitCode::FAILURE;
        }
    };
    let after_text = match std::fs::read_to_string(&args.metrics_after) {
        Ok(t) => t,
        Err(e) => {
            eprintln!(
                "measure_target: cannot read --metrics-after {}: {e}",
                args.metrics_after
            );
            return ExitCode::FAILURE;
        }
    };
    let before = scrape::parse(&before_text);
    let after = scrape::parse(&after_text);
    let server = ServerMetricsSection::from_snapshots(&before, &after, &args.database);

    // --- Assemble the report in EXTERNAL mode: cpu / memory / storage stay at their zero defaults
    // (no co-located PID or filesystem), with an explicit N/A note so nobody misreads them.
    let metadata = RunMetadata::new(args.scenario.clone(), args.description.clone())
        .with_dataset(DatasetScale::new(args.nodes, args.rels));
    let mut collector = EvidenceCollector::new(metadata);
    collector.set_measurement_mode(MeasurementMode::External);
    for (k, v) in &args.params {
        collector
            .metadata_mut()
            .workload
            .insert(k.clone(), v.clone());
    }
    collector.start();
    // The workload already ran before this binary was invoked: hand the collector the wall-time the
    // example measured, so total_millis is the RUN's duration and not this report's emission time.
    collector.record_total_duration_from(args.total_millis, args.workload_secs);

    for (name, millis) in &args.phases {
        collector.phase(
            name.clone(),
            std::time::Duration::from_secs_f64(millis / 1_000.0),
        );
    }

    collector.record_server_metrics(server.clone());

    // --- Throughput / latency: the figures the example's driver measured client-side (the only
    // place they can come from in external mode). Applied only when supplied; an unsupplied figure
    // stays ABSENT (`rmp #711`), never a zero that reads like a measurement.
    if let (Some(ops), Some(secs)) = (args.workload_ops, args.workload_secs) {
        if secs > 0.0 {
            collector.throughput_mut().operations = Some(ops);
            collector.throughput_mut().ops_per_sec = Some(ops as f64 / secs);
        }
    }
    if let Some(p50) = args.p50_ms {
        collector.throughput_mut().p50_latency_ms = Some(p50);
    }
    if let Some(p99) = args.p99_ms {
        collector.throughput_mut().p99_latency_ms = Some(p99);
    }
    if let Some(p999) = args.p999_ms {
        collector.throughput_mut().p999_latency_ms = Some(p999);
    }
    // A measured zero abort rate IS evidence (a write workload with no conflict), so it is recorded
    // as the real 0.0 it is; an unsupplied one stays absent.
    if let Some(rate) = args.abort_rate {
        collector.throughput_mut().abort_rate = Some(rate);
    }

    for note in &args.notes {
        collector.note(note.clone());
    }
    collector.note(format!(
        "External-target measurement (measurement_mode=external): the server is NOT co-located, so \
         the cpu / memory / storage vectors are N/A (no /proc, no store-path access) and are ABSENT \
         from this report — including the per-element durable costs, which are derived from a store \
         image this run cannot read. They are not zeroed: an unmeasured vector must never be \
         reported as a measured zero (rmp #711). Server-side evidence is the /metrics before/after \
         delta for database {:?}; throughput/latency are client-measured.",
        args.database
    ));
    if !server.scope_note.is_empty() {
        collector.note(server.scope_note.clone());
    }
    // peak_rss_bytes is accepted for CLI symmetry with measure_server but is not applicable here.
    let _ = args.peak_rss_bytes;

    let report = collector.finish();
    if let Err(e) = report.write_to(&args.evidence_dir) {
        eprintln!(
            "measure_target: failed to write evidence to {}: {e}",
            args.evidence_dir
        );
        return ExitCode::FAILURE;
    }
    println!(
        "wrote {}/report.json + report.md (external mode, database {:?})",
        args.evidence_dir, args.database
    );

    // --- External-mode invariant gate.
    if args.assert_invariants {
        match check_invariants(&server, args.max_abort_rate) {
            Ok(()) => println!("measure_target: external invariants OK"),
            Err(violations) => {
                for v in &violations {
                    eprintln!("measure_target: INVARIANT VIOLATION: {v}");
                }
                return ExitCode::FAILURE;
            }
        }
    }

    ExitCode::SUCCESS
}

/// Checks the host-independent health invariants that replace the baseline diff in external mode.
/// Returns `Err` with one message per violated invariant.
fn check_invariants(
    server: &ServerMetricsSection,
    max_abort_rate: Option<f64>,
) -> Result<(), Vec<String>> {
    let mut v = Vec::new();
    if server.statement_panics != 0 {
        v.push(format!(
            "statement_panics = {} (expected 0)",
            server.statement_panics
        ));
    }
    if server.engine_recovery_panics != 0 {
        v.push(format!(
            "engine_recovery_panics = {} (expected 0)",
            server.engine_recovery_panics
        ));
    }
    if server.engine_force_detached != 0 {
        v.push(format!(
            "engine_force_detached = {} (expected 0)",
            server.engine_force_detached
        ));
    }
    if server.engine_force_detached_active != 0 {
        v.push(format!(
            "engine_force_detached_active = {} (expected 0)",
            server.engine_force_detached_active
        ));
    }
    if server.transactions_committed == 0 && server.query_count == 0 {
        v.push(
            "server observed no committed transactions and no queries over the window — did the \
             workload reach this endpoint/database?"
                .to_string(),
        );
    }
    if let Some(max) = max_abort_rate {
        if server.abort_rate > max {
            v.push(format!(
                "abort_rate = {:.4} exceeds --max-abort-rate {:.4}",
                server.abort_rate, max
            ));
        }
    }
    if v.is_empty() { Ok(()) } else { Err(v) }
}

/// Parses the `--flag value` command line into [`Args`], validating required fields.
fn parse_args() -> Result<Args, String> {
    let mut args = Args::default();
    let mut it = std::env::args().skip(1);
    while let Some(flag) = it.next() {
        let mut value = || it.next().ok_or_else(|| format!("{flag} requires a value"));
        match flag.as_str() {
            "--evidence-dir" => args.evidence_dir = value()?,
            "--scenario" => args.scenario = value()?,
            "--description" => args.description = value()?,
            "--database" => args.database = value()?,
            "--metrics-before" => args.metrics_before = value()?,
            "--metrics-after" => args.metrics_after = value()?,
            "--nodes" => args.nodes = value()?.parse().map_err(|e| format!("--nodes: {e}"))?,
            "--rels" => args.rels = value()?.parse().map_err(|e| format!("--rels: {e}"))?,
            "--peak-rss-bytes" => {
                args.peak_rss_bytes = Some(
                    value()?
                        .parse()
                        .map_err(|e| format!("--peak-rss-bytes: {e}"))?,
                )
            }
            "--total-millis" => {
                args.total_millis = Some(
                    value()?
                        .parse()
                        .map_err(|e| format!("--total-millis: {e}"))?,
                )
            }
            "--workload-ops" => {
                args.workload_ops = Some(
                    value()?
                        .parse()
                        .map_err(|e| format!("--workload-ops: {e}"))?,
                )
            }
            "--workload-secs" => {
                args.workload_secs = Some(
                    value()?
                        .parse()
                        .map_err(|e| format!("--workload-secs: {e}"))?,
                )
            }
            "--p50-ms" => {
                args.p50_ms = Some(value()?.parse().map_err(|e| format!("--p50-ms: {e}"))?)
            }
            "--p99-ms" => {
                args.p99_ms = Some(value()?.parse().map_err(|e| format!("--p99-ms: {e}"))?)
            }
            "--p999-ms" => {
                args.p999_ms = Some(value()?.parse().map_err(|e| format!("--p999-ms: {e}"))?)
            }
            "--abort-rate" => {
                args.abort_rate = Some(value()?.parse().map_err(|e| format!("--abort-rate: {e}"))?)
            }
            "--max-abort-rate" => {
                args.max_abort_rate = Some(
                    value()?
                        .parse()
                        .map_err(|e| format!("--max-abort-rate: {e}"))?,
                )
            }
            "--assert" => args.assert_invariants = true,
            "--param" => {
                let kv = value()?;
                let (k, v) = kv
                    .split_once('=')
                    .ok_or_else(|| format!("--param expects key=value, got {kv:?}"))?;
                args.params.push((k.to_string(), v.to_string()));
            }
            "--note" => args.notes.push(value()?),
            "--phase" => {
                let kv = value()?;
                let (name, millis) = kv
                    .split_once('=')
                    .ok_or_else(|| format!("--phase expects name=millis, got {kv:?}"))?;
                let millis: f64 = millis.parse().map_err(|e| format!("--phase millis: {e}"))?;
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
    if args.database.is_empty() {
        return Err("--database is required".to_string());
    }
    if args.metrics_before.is_empty() || args.metrics_after.is_empty() {
        return Err("--metrics-before and --metrics-after are required".to_string());
    }
    Ok(args)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn section(text_before: &str, text_after: &str, db: &str) -> ServerMetricsSection {
        ServerMetricsSection::from_snapshots(
            &scrape::parse(text_before),
            &scrape::parse(text_after),
            db,
        )
    }

    #[test]
    fn invariants_pass_on_healthy_active_window() {
        // committed advanced, no panics/detach.
        let s = section(
            "graphus_transactions_committed_total 10\ngraphus_statement_panics_total 0\n",
            "graphus_transactions_committed_total 25\ngraphus_statement_panics_total 0\n",
            "graphus",
        );
        assert!(check_invariants(&s, None).is_ok());
    }

    #[test]
    fn invariants_fail_on_statement_panic() {
        let s = section(
            "graphus_statement_panics_total 0\ngraphus_transactions_committed_total 1\n",
            "graphus_statement_panics_total 1\ngraphus_transactions_committed_total 2\n",
            "graphus",
        );
        let err = check_invariants(&s, None).unwrap_err();
        assert!(err.iter().any(|m| m.contains("statement_panics")));
    }

    #[test]
    fn invariants_fail_on_force_detach() {
        let s = section(
            "graphus_engine_force_detached_total 0\ngraphus_transactions_committed_total 1\n",
            "graphus_engine_force_detached_total 2\ngraphus_transactions_committed_total 2\n",
            "graphus",
        );
        let err = check_invariants(&s, None).unwrap_err();
        assert!(err.iter().any(|m| m.contains("engine_force_detached")));
    }

    #[test]
    fn invariants_fail_when_server_saw_no_work() {
        let s = section(
            "graphus_transactions_committed_total 5\n",
            "graphus_transactions_committed_total 5\n",
            "graphus",
        );
        let err = check_invariants(&s, None).unwrap_err();
        assert!(err.iter().any(|m| m.contains("no committed transactions")));
    }

    #[test]
    fn invariants_fail_when_abort_rate_exceeds_bound() {
        // 3 aborts / (1 committed + 3 aborted) = 0.75 > 0.5.
        let s = section(
            "graphus_transactions_committed_total 0\ngraphus_transactions_aborted_total 0\n",
            "graphus_transactions_committed_total 1\ngraphus_transactions_aborted_total 3\n",
            "graphus",
        );
        let err = check_invariants(&s, Some(0.5)).unwrap_err();
        assert!(err.iter().any(|m| m.contains("abort_rate")));
    }
}
