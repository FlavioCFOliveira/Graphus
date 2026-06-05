//! The command-line runner over the harness: argument parsing and a deterministic run summary.
//!
//! `graphus-dst [--seed N] [--runs M] [--start S]` runs one or more scenarios and prints a summary
//! that is a pure function of the inputs (no wall clock, no entropy), so the same arguments produce
//! the same output. A failing run prints its seed so it reproduces with `--seed <that>`
//! (`specification/04-technical-design.md` §11.1: "a failing seed is a one-line reproducer").
//!
//! Argument parsing is hand-rolled over [`std::env::args`] to keep the binary dependency-light (no
//! arg-parsing crate), matching the house preference for `std` where it suffices.

use std::collections::BTreeMap;
use std::fmt::Write as _;

use crate::fault::{DeferredFault, FaultKind};
use crate::harness::{self, ScenarioReport};

/// Parsed CLI configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CliConfig {
    /// The first seed to run.
    pub start_seed: u64,
    /// How many seeds to run (consecutive from `start_seed`).
    pub runs: u64,
    /// When set, run exactly this one seed (overrides `start_seed`/`runs`).
    pub single_seed: Option<u64>,
}

impl Default for CliConfig {
    fn default() -> Self {
        Self {
            start_seed: 1,
            runs: 50,
            single_seed: None,
        }
    }
}

/// An argument parse error (a bad flag or a non-numeric value).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseError(pub String);

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl std::error::Error for ParseError {}

/// Parses CLI arguments (excluding the program name) into a [`CliConfig`].
///
/// Accepted flags: `--seed N` (run exactly seed N), `--runs M` (run M seeds), `--start S` (first
/// seed), `--help`/`-h` (prints usage and yields a config that the caller may special-case).
///
/// # Errors
/// Returns a [`ParseError`] on an unknown flag, a missing value, or a non-numeric value.
pub fn parse_args<I, S>(args: I) -> Result<CliConfig, ParseError>
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    let mut cfg = CliConfig::default();
    let mut it = args.into_iter().peekable();

    while let Some(arg) = it.next() {
        let arg = arg.as_ref();
        match arg {
            "--seed" => {
                let v = next_value(&mut it, "--seed")?;
                cfg.single_seed = Some(parse_u64(&v, "--seed")?);
            }
            "--runs" => {
                let v = next_value(&mut it, "--runs")?;
                cfg.runs = parse_u64(&v, "--runs")?;
            }
            "--start" => {
                let v = next_value(&mut it, "--start")?;
                cfg.start_seed = parse_u64(&v, "--start")?;
            }
            "--help" | "-h" => {
                return Err(ParseError(usage()));
            }
            other => {
                return Err(ParseError(format!(
                    "unknown argument '{other}'\n\n{}",
                    usage()
                )));
            }
        }
    }
    Ok(cfg)
}

fn next_value<I, S>(it: &mut std::iter::Peekable<I>, flag: &str) -> Result<String, ParseError>
where
    I: Iterator<Item = S>,
    S: AsRef<str>,
{
    it.next()
        .map(|s| s.as_ref().to_owned())
        .ok_or_else(|| ParseError(format!("{flag} requires a value")))
}

fn parse_u64(s: &str, flag: &str) -> Result<u64, ParseError> {
    s.parse::<u64>()
        .map_err(|_| ParseError(format!("{flag} expects a non-negative integer, got '{s}'")))
}

/// The usage string.
#[must_use]
pub fn usage() -> String {
    "graphus-dst — deterministic simulation harness for the Graphus storage/WAL/txn engine\n\
     \n\
     USAGE:\n    \
     graphus-dst [--seed N] [--runs M] [--start S]\n\
     \n\
     OPTIONS:\n    \
     --seed N    run exactly seed N (a one-line reproducer for a failure)\n    \
     --start S   first seed to run (default 1)\n    \
     --runs M    number of consecutive seeds to run (default 50)\n    \
     -h, --help  print this help\n"
        .to_owned()
}

/// Runs the scenarios `cfg` selects and returns the aggregate run report as a string, plus the
/// number of failures. The returned report is deterministic for a given `cfg`.
#[must_use]
pub fn run(cfg: CliConfig) -> (String, u64) {
    let reports: Vec<ScenarioReport> = match cfg.single_seed {
        Some(seed) => vec![harness::run_scenario(seed)],
        None => (cfg.start_seed..cfg.start_seed + cfg.runs)
            .map(harness::run_scenario)
            .collect(),
    };
    let summary = summarize(&reports, &cfg);
    let failures = reports.iter().filter(|r| !r.passed()).count() as u64;
    (summary, failures)
}

/// Renders the aggregate, deterministic summary for a batch of scenario reports.
#[must_use]
pub fn summarize(reports: &[ScenarioReport], cfg: &CliConfig) -> String {
    let mut out = String::new();
    let runs = reports.len();
    let passed = reports.iter().filter(|r| r.passed()).count();
    let failed = runs - passed;

    let total_ops: u64 = reports.iter().map(|r| r.ops_applied).sum();
    let total_commits: u64 = reports
        .iter()
        .map(|r| r.ledger.acknowledged_commits())
        .sum();
    let total_rollbacks: u64 = reports.iter().map(|r| r.ledger.rolled_back()).sum();
    let total_in_flight: u64 = reports.iter().map(|r| r.ledger.in_flight_at_crash()).sum();
    let total_recovery_losers: usize = reports.iter().map(|r| r.recovery_losers).sum();
    let non_vacuous = reports.iter().filter(|r| r.non_vacuous).count();

    // Faults injected, tallied by type (deterministic order).
    let mut by_fault: BTreeMap<&'static str, u64> = BTreeMap::new();
    for label in FaultKind::all_labels() {
        by_fault.insert(label, 0);
    }
    for r in reports {
        *by_fault.entry(r.fault.label()).or_insert(0) += 1;
    }

    let _ = writeln!(out, "graphus-dst deterministic simulation summary");
    let _ = writeln!(out, "===========================================");
    match cfg.single_seed {
        Some(seed) => {
            let _ = writeln!(out, "mode            : single seed {seed}");
        }
        None => {
            let _ = writeln!(
                out,
                "mode            : seeds {}..{}",
                cfg.start_seed,
                cfg.start_seed + cfg.runs
            );
        }
    }
    let _ = writeln!(out, "runs            : {runs}");
    let _ = writeln!(out, "ops applied     : {total_ops}");
    let _ = writeln!(out, "acked commits   : {total_commits}");
    let _ = writeln!(out, "rolled back     : {total_rollbacks}");
    let _ = writeln!(out, "in-flight@crash : {total_in_flight}");
    let _ = writeln!(out, "recovery losers : {total_recovery_losers}");
    let _ = writeln!(
        out,
        "non-vacuous runs: {non_vacuous}/{runs} (commit present AND work rolled back)"
    );

    let _ = writeln!(out, "\nfaults injected by type:");
    for (label, count) in &by_fault {
        let _ = writeln!(out, "  {label:<16}: {count}");
    }

    let _ = writeln!(out, "\ninvariants checked each run:");
    let _ = writeln!(
        out,
        "  1. durability   — every acknowledged commit present & correct"
    );
    let _ = writeln!(
        out,
        "  2. atomicity    — no in-flight/rolled-back effect survives"
    );
    let _ = writeln!(
        out,
        "  3. integrity    — adjacency well-formed, page checksums valid"
    );
    let _ = writeln!(
        out,
        "  4. determinism  — same seed => identical recovered state"
    );

    let _ = writeln!(out, "\nfault types deferred (NOT exercised here):");
    for f in DeferredFault::all() {
        let _ = writeln!(out, "  {:<26}: {}", f.label(), f.reason());
    }

    let _ = writeln!(out, "\nresult: {passed} PASSED, {failed} FAILED");
    if failed > 0 {
        let _ = writeln!(out, "\nFAILED seeds (reproduce with --seed <N>):");
        for r in reports.iter().filter(|r| !r.passed()) {
            if let Err(e) = &r.result {
                let _ = writeln!(out, "  seed {} [{}]: {e}", r.seed, r.fault.label());
            }
        }
        let _ = writeln!(out, "\nOVERALL: FAIL");
    } else {
        let _ = writeln!(out, "OVERALL: PASS");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_defaults() {
        let cfg = parse_args(Vec::<String>::new()).unwrap();
        assert_eq!(cfg, CliConfig::default());
    }

    #[test]
    fn parses_seed_runs_start() {
        let cfg = parse_args(["--seed", "42"]).unwrap();
        assert_eq!(cfg.single_seed, Some(42));

        let cfg = parse_args(["--runs", "10", "--start", "5"]).unwrap();
        assert_eq!(cfg.runs, 10);
        assert_eq!(cfg.start_seed, 5);
        assert_eq!(cfg.single_seed, None);
    }

    #[test]
    fn rejects_unknown_and_missing_and_nonnumeric() {
        assert!(parse_args(["--nope"]).is_err());
        assert!(parse_args(["--seed"]).is_err());
        assert!(parse_args(["--runs", "abc"]).is_err());
    }

    #[test]
    fn help_yields_usage_error() {
        let err = parse_args(["--help"]).unwrap_err();
        assert!(err.to_string().contains("USAGE"));
    }

    #[test]
    fn summary_is_deterministic_and_reports_pass() {
        let cfg = CliConfig {
            start_seed: 1,
            runs: 8,
            single_seed: None,
        };
        let (a, fa) = run(cfg);
        let (b, fb) = run(cfg);
        assert_eq!(a, b, "summary must be deterministic");
        assert_eq!(fa, fb);
        assert_eq!(fa, 0, "the default scenarios must pass");
        assert!(a.contains("OVERALL: PASS"));
        assert!(a.contains("deferred"));
    }

    #[test]
    fn single_seed_summary_mentions_the_seed() {
        let (s, fails) = run(CliConfig {
            start_seed: 1,
            runs: 1,
            single_seed: Some(7),
        });
        assert_eq!(fails, 0);
        assert!(s.contains("single seed 7"));
    }
}
