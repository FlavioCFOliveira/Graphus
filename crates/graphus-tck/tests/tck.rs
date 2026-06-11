//! The openCypher TCK conformance run: discover every vendored scenario, run it through the real
//! Graphus engine, print a summary, and assert a no-regression ratchet (`CLAUDE.md`: measure to
//! decide; the TCK is an inviolable target).
//!
//! This is **one** integration test (`tck_conformance`) so the corpus is parsed and walked once. It
//! prints a single machine-greppable line —
//! `TCK: <passed>/<total> (<pct>%) — baseline <BASELINE>` — plus a per-category breakdown and
//! triage samples, then asserts `passed >= BASELINE`. Raising the ratchet after an engine
//! improvement is a one-line edit to [`BASELINE`].
//!
//! Run it verbosely to see the report:
//!
//! ```text
//! cargo test -p graphus-tck --test tck -- --nocapture
//! ```

use std::path::{Path, PathBuf};

use graphus_tck::feature::load_feature;
use graphus_tck::report::Report;
use graphus_tck::runner::run_scenario;

/// The no-regression ratchet: the exact number of scenarios passing today.
///
/// Measured empirically by this very test (run once with the printed `passed` count, then pinned
/// here). A future engine improvement that raises the pass count should bump this so the gain is
/// locked in; a regression that drops below it fails the build.
///
/// Current ratchet: **3324 / 3884 scenarios pass (85.58 %)**, with 0 panics and 0 scenarios
/// skipped as unsupported. This rose from 3130 (+194, all in `expressions/temporal`) when `rmp`
/// task #60 added **IANA time-zone resolution** ([`graphus_cypher::timezone`], the embedded
/// vanilla-tzdata TZif tables of `jiff-tzdb` queried through `tz-rs`): named zones in the
/// `datetime()`/`time()` constructors and `[Zone]` string suffixes now resolve historical
/// offsets and DST (gap/overlap per `java.time.ZonedDateTime.ofLocal`), zone conversion
/// preserves the instant, `duration.*` interprets a local operand in the zoned operand's named
/// zone, and truncation re-resolves the offset. The same cycle fixed adjacent pre-existing
/// component-map bugs the temporal triage surfaced (week/ordinal/quarter overrides over a base
/// date, positional sub-second truncation overrides, time-axis-only `duration.between` with a
/// time-only operand). The gain came from the *engine-raised-an-error* (−111) and
/// *bag-mismatch* (−82) buckets plus one init-query fix, with every other failure bucket
/// unchanged (measured: zero regressions). Prior rise: 2996 → 3130 (#61, compile-time
/// expression type checking via [`graphus_cypher::static_type`]). Earlier: 2944 → 2996 (#57,
/// `CALL` procedures); 2614 → 2944 (#56, TCK-faithful error classification); 1782 → 2614 (#53,
/// temporal types); 1192 → 1782 (#54, quantifiers/comprehensions/EXISTS); 1112 → 1192 (#55,
/// verbatim column names). Remaining failures are honest gaps: property-access typing that
/// needs `WITH`-projection type-flow (`WITH 1 AS x … x.p`), float-parameter `SKIP`/`LIMIT`, the
/// transaction-clock constructors (`datetime()`, `date.statement()`, …), and the full-query
/// `EXISTS { ... RETURN ... }` form.
const BASELINE: usize = 3324;

/// Recursively collects every `*.feature` file under `root`, returning `(absolute_path,
/// path_relative_to_root)` pairs sorted for a stable run order.
fn discover_features(root: &Path) -> Vec<(PathBuf, String)> {
    let mut out = Vec::new();
    collect(root, root, &mut out);
    out.sort_by(|a, b| a.1.cmp(&b.1));
    out
}

/// Depth-first directory walk gathering feature files.
fn collect(dir: &Path, root: &Path, out: &mut Vec<(PathBuf, String)>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect(&path, root, out);
        } else if path.extension().is_some_and(|e| e == "feature") {
            if let Ok(rel) = path.strip_prefix(root) {
                out.push((path.clone(), rel.to_string_lossy().replace('\\', "/")));
            }
        }
    }
}

#[test]
fn tck_conformance() {
    let root = graphus_tck::tck_root();
    let features_dir = root.join("features");
    let graphs_dir = root.join("graphs");

    assert!(
        features_dir.is_dir(),
        "TCK features directory not found at {} — is the corpus vendored?",
        features_dir.display()
    );

    let mut features = discover_features(&features_dir);
    assert!(
        !features.is_empty(),
        "no .feature files discovered under {}",
        features_dir.display()
    );

    // Optional triage filter: `TCK_ONLY=expressions/mathematical` restricts the run to features
    // whose relative path contains the substring. It does not affect the committed run (the env var
    // is unset there) but makes drilling into one category fast during development.
    if let Ok(filter) = std::env::var("TCK_ONLY") {
        if !filter.is_empty() {
            features.retain(|(_, rel)| rel.contains(&filter));
            eprintln!("TCK_ONLY={filter}: {} feature(s) selected", features.len());
        }
    }

    let mut report = Report::new();
    let mut feature_parse_failures = 0usize;

    // Optional full dump: `TCK_DUMP=/path/to/file` writes every failure/error/unsupported outcome
    // (uncapped) for offline triage. Unset in the committed run.
    let mut dump = String::new();
    let dump_path = std::env::var("TCK_DUMP").ok().filter(|p| !p.is_empty());

    for (path, rel) in &features {
        let scenarios = match load_feature(path, rel) {
            Ok(s) => s,
            Err(e) => {
                // A feature file that does not parse is itself a harness/corpus problem, not an
                // engine result; count it but do not abort the run.
                eprintln!("WARN: could not parse feature {rel}: {e}");
                feature_parse_failures += 1;
                continue;
            }
        };
        for scenario in &scenarios {
            let outcome = run_scenario(scenario, &graphs_dir);
            if dump_path.is_some() {
                use std::fmt::Write as _;
                // Flatten any multi-line reason to a single TSV line so the dump stays grep-able.
                let line = |tag: &str, reason: &str| {
                    format!(
                        "{tag}\t{rel}\t{}\t{}\n",
                        scenario.name,
                        reason.replace('\n', " ⏎ ")
                    )
                };
                match &outcome {
                    graphus_tck::runner::Outcome::Passed => {}
                    graphus_tck::runner::Outcome::Failed(r) => {
                        let _ = dump.write_str(&line("FAIL", r));
                    }
                    graphus_tck::runner::Outcome::Errored(r) => {
                        let _ = dump.write_str(&line("ERR", r));
                    }
                    graphus_tck::runner::Outcome::Unsupported(r) => {
                        let _ = dump.write_str(&line("UNSUP", r));
                    }
                }
            }
            report.record(scenario.category(), &scenario.name, &outcome);
        }
    }

    if let Some(path) = &dump_path {
        std::fs::write(path, &dump).expect("write TCK_DUMP file");
        eprintln!("TCK_DUMP written to {path}");
    }

    // Print the full report (visible with `-- --nocapture`).
    println!("{}", report.render(BASELINE));
    println!(
        "TCK: {}/{} ({:.2}%) — baseline {BASELINE}",
        report.overall.passed,
        report.total(),
        report.pass_rate()
    );
    if feature_parse_failures > 0 {
        println!("WARN: {feature_parse_failures} feature file(s) failed to parse");
    }

    // The ratchet: never regress below the measured baseline.
    assert!(
        report.overall.passed >= BASELINE,
        "TCK regression: {} scenarios passed, but the baseline is {BASELINE}. \
         Investigate the drop (a real regression) before lowering the baseline.",
        report.overall.passed
    );
}
