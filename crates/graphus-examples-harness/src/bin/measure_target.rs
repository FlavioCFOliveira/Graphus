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
//!   [--p50-ms <f64> --p99-ms <f64> --p999-ms <f64>] [--latency-samples-secs <file>] \
//!   [--abort-rate <f64>] \
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
use std::time::Duration;

use graphus_examples_harness::{
    DatasetScale, EvidenceCollector, LatencyCollector, MeasurementMode, RunMetadata,
    ServerMetricsSection, scrape,
};

/// Which latency percentiles a sample of `n` timed requests can HONESTLY support.
///
/// A tail percentile computed over too small a sample is not a tail measurement — it is the maximum
/// (or the second-highest value) wearing a percentile's name, and publishing it tells a reader
/// something the run never measured. That is the same family of lie as a `0.0` placeholder, so the
/// unsupported percentiles are **omitted** from the report and the reason is recorded in a note
/// (`rmp` #711/#716 — measure it or omit it).
///
/// The thresholds, and the actual reasons for them:
///
/// - **p50** — any sample at all has a median. `n >= 1`.
/// - **p99** — `n >= 100`. A 99th percentile is only *supported* when at least **1% of the sample
///   lies above it** (1% of 100 = one whole sample). This is the binding constraint and it is
///   stricter than the merely-degenerate one: with this crate's nearest-rank rule
///   (`rank = round(p * (n - 1))`, mirroring `graphus_bench::ldbc::percentile`) the p99 is literally
///   the **maximum** for all `n <= 51`, and for `52..=99` it is the *second*-highest value — a "tail"
///   estimated from a single point. 100 is the conventional minimum, and the one we hold to.
/// - **p999** — `n >= 1000`, by exactly the same 0.1%-of-the-sample argument.
///
/// Returns `(p50, p99, p999)`: whether each may be published.
fn percentiles_supported_by(n: usize) -> (bool, bool, bool) {
    (n >= 1, n >= 100, n >= 1000)
}

/// Reads a file of per-request durations — **one f64 of SECONDS per line** — into a
/// [`LatencyCollector`]. Blank lines are skipped; a malformed line is an error, never a silently
/// dropped sample (a latency file that half-parses would publish a percentile over an unknown subset).
///
/// Seconds, because that is the unit `curl -w '%{time_total}'` emits — and it emits it C-locale
/// formatted (a `.` decimal point) regardless of the caller's locale, which is what makes this file a
/// safe interchange format for a shell-driven example.
fn read_latency_samples(path: &str) -> Result<LatencyCollector, String> {
    let text = std::fs::read_to_string(path).map_err(|e| e.to_string())?;
    let mut collector = LatencyCollector::new();
    for (i, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let secs: f64 = line
            .parse()
            .map_err(|e| format!("line {}: {line:?} is not a float of seconds: {e}", i + 1))?;
        if !secs.is_finite() || secs < 0.0 {
            return Err(format!(
                "line {}: {secs} is not a valid duration in seconds",
                i + 1
            ));
        }
        collector.record(Duration::from_secs_f64(secs));
    }
    Ok(collector)
}

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
    /// A file of per-request durations (one f64 of SECONDS per line) the driver timed. Percentiles
    /// are computed from it here, and only the ones the sample size supports are published.
    latency_samples_secs: Option<String>,
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
    // --- Latency from a RAW SAMPLE FILE (`rmp #716`): the honest way for a shell-driven example to
    // report percentiles. The driver times each request and appends one duration per line; we compute
    // the percentiles here with the project's own nearest-rank implementation, and — crucially — only
    // publish a percentile the SAMPLE SIZE can actually support (see `percentiles_supported_by`).
    if let Some(path) = &args.latency_samples_secs {
        match read_latency_samples(path) {
            Ok(collector_samples) => {
                let n = collector_samples.count();
                let (p50, p99, p999) = collector_samples.percentiles();
                let ms = |d: std::time::Duration| d.as_secs_f64() * 1_000.0;
                let (want50, want99, want999) = percentiles_supported_by(n);
                if want50 {
                    collector.throughput_mut().p50_latency_ms = Some(ms(p50));
                }
                if want99 {
                    collector.throughput_mut().p99_latency_ms = Some(ms(p99));
                }
                if want999 {
                    collector.throughput_mut().p999_latency_ms = Some(ms(p999));
                }
                collector
                    .metadata_mut()
                    .workload
                    .insert("latency_samples".into(), n.to_string());
                let mut note = format!(
                    "LATENCY: p50{} computed from {n} REAL per-request samples (each one timed \
                     request/response over the wire), with the project's nearest-rank percentile.",
                    match (want99, want999) {
                        (true, true) => "/p99/p999",
                        (true, false) => "/p99",
                        _ => "",
                    }
                );
                if !want999 {
                    note.push_str(&format!(
                        " p999 is ABSENT: a nearest-rank p999 needs at least 1000 samples to be \
                         distinct from the maximum, and this run took {n}. Reporting one anyway \
                         would be the maximum wearing a percentile's name — a number that reads \
                         like a tail measurement and is not one (rmp #711/#716: measure it or omit \
                         it)."
                    ));
                }
                if !want99 {
                    note.push_str(&format!(
                        " p99 is ABSENT for the same reason: it needs at least 100 samples, and this \
                         run took {n}."
                    ));
                }
                collector.note(note);
            }
            Err(e) => {
                eprintln!("measure_target: cannot read --latency-samples-secs {path}: {e}");
                return ExitCode::FAILURE;
            }
        }
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
            "--latency-samples-secs" => args.latency_samples_secs = Some(value()?),
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

    // ---- The latency-sample honesty gate (`rmp` #716) ----

    #[test]
    fn a_percentile_needs_a_sample_size_that_can_support_it() {
        // The rule the whole gate exists for: a nearest-rank percentile over too small a sample is
        // just the MAXIMUM wearing a percentile's name. Publishing it would tell a reader something
        // the run never measured — the same family of lie as a 0.0 placeholder.
        assert_eq!(percentiles_supported_by(0), (false, false, false));
        assert_eq!(percentiles_supported_by(1), (true, false, false));
        assert_eq!(percentiles_supported_by(99), (true, false, false));
        assert_eq!(percentiles_supported_by(100), (true, true, false));
        assert_eq!(percentiles_supported_by(165), (true, true, false)); // a `default`-profile run
        assert_eq!(percentiles_supported_by(999), (true, true, false));
        assert_eq!(percentiles_supported_by(1000), (true, true, true));
        assert_eq!(percentiles_supported_by(2631), (true, true, true)); // a `huge`-profile run
    }

    /// The crate's nearest-rank rule, replicated so the test pins the real arithmetic.
    fn p99_rank(n: usize) -> usize {
        (0.99_f64 * (n as f64 - 1.0)).round() as usize
    }

    #[test]
    fn the_p99_threshold_is_justified_by_the_arithmetic_not_by_taste() {
        // (a) The DEGENERATE bound: with nearest rank, the p99 is literally the MAXIMUM up to n = 51.
        //     Anything published there would be the slowest request relabelled as a tail percentile.
        for n in 1..=51usize {
            assert_eq!(
                p99_rank(n),
                n - 1,
                "with {n} samples the nearest-rank p99 IS the maximum"
            );
        }
        assert!(
            p99_rank(52) < 51,
            "at n=52 the p99 stops being the maximum (it becomes the 2nd-highest)"
        );

        // (b) The BINDING bound, and the one we actually gate on: a 99th percentile is only supported
        //     when at least 1% of the sample lies ABOVE it — one whole sample at n = 100. Between 52
        //     and 99 the p99 is the second-highest value: a "tail" estimated from a single point.
        //     That is why the threshold is 100 and not 52.
        let above = |n: usize| n - 1 - p99_rank(n); // samples strictly above the reported rank
        assert_eq!(
            above(52),
            1,
            "at n=52 exactly one sample lies above the p99"
        );
        assert!(
            above(100) >= 1,
            "at n=100 at least one whole sample must lie above the p99"
        );

        // (c) And the gate itself enforces exactly that.
        assert!(
            !percentiles_supported_by(99).1,
            "99 samples must NOT gate a p99"
        );
        assert!(
            percentiles_supported_by(100).1,
            "100 samples must gate a p99"
        );
    }

    #[test]
    fn latency_samples_parse_from_a_seconds_per_line_file() {
        let dir = std::env::temp_dir().join(format!("mt-lat-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("samples.txt");
        // Seconds per line, with a blank line — exactly what `curl -w '%{time_total}'` appends.
        std::fs::write(&path, "0.010\n0.020\n\n0.030\n").unwrap();
        let c = read_latency_samples(path.to_str().unwrap()).unwrap();
        assert_eq!(
            c.count(),
            3,
            "the blank line is skipped, the 3 samples are not"
        );
        let (p50, _, _) = c.percentiles();
        assert!((p50.as_secs_f64() - 0.020).abs() < 1e-9, "p50 = {p50:?}");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_malformed_latency_line_is_an_error_not_a_dropped_sample() {
        // A file that half-parses would publish a percentile over an unknown subset of the run.
        let dir = std::env::temp_dir().join(format!("mt-bad-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("bad.txt");
        std::fs::write(&path, "0.010\nnot-a-number\n0.030\n").unwrap();
        assert!(read_latency_samples(path.to_str().unwrap()).is_err());
        // …and a negative "duration" is not a duration.
        std::fs::write(&path, "0.010\n-1.0\n").unwrap();
        assert!(read_latency_samples(path.to_str().unwrap()).is_err());
        std::fs::remove_dir_all(&dir).ok();
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
