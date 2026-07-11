//! `inject_server_metrics` — augment a **local-mode** evidence report with the server-side
//! `/metrics` delta (`rmp #689`).
//!
//! The [`measure_server`] harness binary meters a co-located server's process CPU/RSS + on-disk
//! store/WAL and writes `report.json`, but it does **not** scrape `/metrics`, so its report carries no
//! `server_metrics` section. In external (attach) mode [`measure_target`] already folds the `/metrics`
//! before/after delta into the report; this binary gives the **local** path the same server-side
//! evidence without modifying the harness: it loads the `measure_server` report, computes
//! [`ServerMetricsSection::from_snapshots`] from two Prometheus snapshots the shell harness scraped,
//! attaches it, and re-emits `report.json` + `report.md` in place.
//!
//! It is hermetic (only the harness lib — no engine, no network), so it is always available.
//!
//! ## Usage
//!
//! ```text
//! inject_server_metrics <evidence-dir> <metrics-before> <metrics-after> <database>
//! ```
//!
//! `<evidence-dir>/report.json` is read, augmented, and rewritten (alongside `report.md`). A failure
//! is non-fatal to the caller by exit code only if the caller chooses to ignore it; this binary itself
//! exits non-zero on any error so a wrapper can decide.
//!
//! [`measure_server`]: ../measure_server.rs
//! [`measure_target`]: ../../graphus-examples-harness/src/bin/measure_target.rs

use std::process::ExitCode;

use graphus_examples_harness::{EvidenceReport, ServerMetricsSection, scrape};

fn main() -> ExitCode {
    let mut args = std::env::args().skip(1);
    let (evidence_dir, before_path, after_path, database) = match (
        args.next(),
        args.next(),
        args.next(),
        args.next(),
    ) {
        (Some(a), Some(b), Some(c), Some(d)) => (a, b, c, d),
        _ => {
            eprintln!(
                "usage: inject_server_metrics <evidence-dir> <metrics-before> <metrics-after> <database>"
            );
            return ExitCode::FAILURE;
        }
    };

    let report_path = format!("{}/report.json", evidence_dir.trim_end_matches('/'));
    let mut report = match EvidenceReport::load(&report_path) {
        Ok(r) => r,
        Err(e) => {
            eprintln!("inject_server_metrics: cannot load {report_path}: {e}");
            return ExitCode::FAILURE;
        }
    };

    let before_text = match std::fs::read_to_string(&before_path) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("inject_server_metrics: cannot read --metrics-before {before_path}: {e}");
            return ExitCode::FAILURE;
        }
    };
    let after_text = match std::fs::read_to_string(&after_path) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("inject_server_metrics: cannot read --metrics-after {after_path}: {e}");
            return ExitCode::FAILURE;
        }
    };

    let before = scrape::parse(&before_text);
    let after = scrape::parse(&after_text);
    let section = ServerMetricsSection::from_snapshots(&before, &after, &database);

    let scope = section.scope_note.clone();
    report.server_metrics = Some(section);
    report.notes.push(format!(
        "server_metrics folded in from the local /metrics before/after delta for database {database:?} \
         (rmp #689 inject_server_metrics); process CPU/RSS + store/WAL are the co-located measure_server figures."
    ));
    if !scope.is_empty() {
        report.notes.push(scope);
    }

    match report.write_to(&evidence_dir) {
        Ok((json, _md)) => {
            println!("inject_server_metrics: augmented {}", json.display());
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("inject_server_metrics: failed to rewrite report in {evidence_dir}: {e}");
            ExitCode::FAILURE
        }
    }
}
