//! Aggregation and printing of scenario [`Outcome`]s into a TCK conformance
//! report: totals, pass-rate, a per-top-level-category breakdown, the ratchet line, and (capped)
//! samples of failures / errors / unsupported step forms for triage.

use std::collections::BTreeMap;
use std::fmt::Write as _;

use crate::runner::Outcome;

/// Per-category tallies (`clauses` / `expressions` / `useCases`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CategoryStats {
    /// Scenarios that passed.
    pub passed: usize,
    /// Scenarios that ran but produced the wrong answer / wrong error.
    pub failed: usize,
    /// Scenarios that panicked (isolated by the runner).
    pub errored: usize,
    /// Scenarios skipped because a step form is not implemented.
    pub unsupported: usize,
}

impl CategoryStats {
    /// The total number of scenarios in this category.
    #[must_use]
    pub fn total(&self) -> usize {
        self.passed + self.failed + self.errored + self.unsupported
    }
}

/// An aggregated TCK run: global tallies plus the per-category breakdown and triage samples.
#[derive(Debug, Clone, Default)]
pub struct Report {
    /// Global tally across all categories.
    pub overall: CategoryStats,
    /// Per-top-level-category tallies, keyed by category name (sorted by the `BTreeMap`).
    pub by_category: BTreeMap<String, CategoryStats>,
    /// A capped sample of `(scenario, reason)` failures, for triage.
    pub failure_samples: Vec<(String, String)>,
    /// A capped sample of `(scenario, panic message)` errors.
    pub error_samples: Vec<(String, String)>,
    /// The distinct unsupported step forms encountered, with how many scenarios each gated.
    pub unsupported_forms: BTreeMap<String, usize>,
    /// A histogram of **all** failures by a normalised reason category (uncapped), so the dominant
    /// failure shapes are visible even when the per-sample list is capped.
    pub failure_reasons: BTreeMap<String, usize>,
}

/// Normalises a failure reason into a coarse category for the histogram (the leading phrase before
/// any specifics).
fn reason_category(reason: &str) -> &'static str {
    let r = reason.trim_start();
    if r.starts_with("column mismatch") {
        "column-name mismatch (un-aliased projection / shape)"
    } else if r.starts_with("error TYPE mismatch") {
        "error TYPE mismatch (engine raised a different error class)"
    } else if r.starts_with("error PHASE mismatch") {
        "error PHASE mismatch (compile-time vs runtime)"
    } else if r.starts_with("error DETAIL mismatch") {
        "error DETAIL mismatch"
    } else if r.starts_with("expected a") && r.contains("but the query produced") {
        "expected an error, engine produced rows"
    } else if r.starts_with("expected rows, but the query raised") {
        "expected rows, engine raised an error"
    } else if r.starts_with("expected an empty result") {
        "expected empty result, engine produced rows/error"
    } else if r.starts_with("row count mismatch") {
        "row-count mismatch"
    } else if r.starts_with("no one-to-one") {
        "unordered bag mismatch (wrong row values)"
    } else if r.starts_with("ordered row") {
        "ordered-row mismatch (wrong value/order)"
    } else if r.starts_with("side effects mismatch") {
        "side-effects mismatch"
    } else if r.starts_with("expected-value parse error") {
        "expected-value parse error (harness mini-language gap)"
    } else if r.contains("seed") && r.contains("failed") {
        "named-graph seed failed"
    } else if r.starts_with("init query failed") {
        "init query failed"
    } else if r.starts_with("parameter") || r.contains("parameter table") {
        "parameter binding/table issue"
    } else {
        "other"
    }
}

/// How many failure/error samples to retain (the full list would bury the signal).
const SAMPLE_CAP: usize = 40;

impl Report {
    /// An empty report.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Folds one scenario `outcome` (from `category`, named `name`) into the report.
    pub fn record(&mut self, category: &str, name: &str, outcome: &Outcome) {
        let cat = self.by_category.entry(category.to_owned()).or_default();
        match outcome {
            Outcome::Passed => {
                self.overall.passed += 1;
                cat.passed += 1;
            }
            Outcome::Failed(reason) => {
                self.overall.failed += 1;
                cat.failed += 1;
                *self
                    .failure_reasons
                    .entry(reason_category(reason).to_owned())
                    .or_insert(0) += 1;
                if self.failure_samples.len() < SAMPLE_CAP {
                    self.failure_samples
                        .push((format!("{category}/{name}"), reason.clone()));
                }
            }
            Outcome::Errored(msg) => {
                self.overall.errored += 1;
                cat.errored += 1;
                if self.error_samples.len() < SAMPLE_CAP {
                    self.error_samples
                        .push((format!("{category}/{name}"), msg.clone()));
                }
            }
            Outcome::Unsupported(form) => {
                self.overall.unsupported += 1;
                cat.unsupported += 1;
                *self.unsupported_forms.entry(form.clone()).or_insert(0) += 1;
            }
        }
    }

    /// The total number of scenarios recorded.
    #[must_use]
    pub fn total(&self) -> usize {
        self.overall.total()
    }

    /// The pass-rate as a percentage of all scenarios (0.0 if none recorded).
    #[must_use]
    pub fn pass_rate(&self) -> f64 {
        let total = self.total();
        if total == 0 {
            0.0
        } else {
            100.0 * self.overall.passed as f64 / total as f64
        }
    }

    /// Renders the full human-readable report, including the ratchet line for `baseline`.
    #[must_use]
    pub fn render(&self, baseline: usize) -> String {
        let mut s = String::new();
        let total = self.total();
        let _ = writeln!(
            s,
            "================ openCypher TCK conformance ================"
        );
        let _ = writeln!(
            s,
            "TCK: {}/{} ({:.2}%) — baseline {}",
            self.overall.passed,
            total,
            self.pass_rate(),
            baseline
        );
        let _ = writeln!(
            s,
            "  passed={}  failed={}  errored={}  unsupported={}",
            self.overall.passed,
            self.overall.failed,
            self.overall.errored,
            self.overall.unsupported
        );
        let _ = writeln!(s, "----------- by category -----------");
        for (cat, stats) in &self.by_category {
            let cat_total = stats.total();
            let pct = if cat_total == 0 {
                0.0
            } else {
                100.0 * stats.passed as f64 / cat_total as f64
            };
            let _ = writeln!(
                s,
                "  {cat:<14} {:>4}/{:<4} ({pct:>6.2}%)  failed={:<4} errored={:<3} unsupported={}",
                stats.passed, cat_total, stats.failed, stats.errored, stats.unsupported
            );
        }

        if !self.unsupported_forms.is_empty() {
            let _ = writeln!(s, "----------- unsupported step forms -----------");
            // Sort by descending count for readability.
            let mut forms: Vec<(&String, &usize)> = self.unsupported_forms.iter().collect();
            forms.sort_by(|a, b| b.1.cmp(a.1).then_with(|| a.0.cmp(b.0)));
            for (form, count) in forms {
                let _ = writeln!(s, "  [{count:>4}] {form}");
            }
        }

        if !self.failure_reasons.is_empty() {
            let _ = writeln!(s, "----------- failure reasons (all failures) -----------");
            let mut reasons: Vec<(&String, &usize)> = self.failure_reasons.iter().collect();
            reasons.sort_by(|a, b| b.1.cmp(a.1).then_with(|| a.0.cmp(b.0)));
            for (reason, count) in reasons {
                let _ = writeln!(s, "  [{count:>5}] {reason}");
            }
        }

        if !self.failure_samples.is_empty() {
            let _ = writeln!(
                s,
                "----------- failure samples (first {}) -----------",
                self.failure_samples.len()
            );
            for (name, reason) in &self.failure_samples {
                let first_line = reason.lines().next().unwrap_or(reason);
                let _ = writeln!(s, "  FAIL {name}: {first_line}");
            }
        }

        if !self.error_samples.is_empty() {
            let _ = writeln!(
                s,
                "----------- panic samples (first {}) -----------",
                self.error_samples.len()
            );
            for (name, msg) in &self.error_samples {
                let first_line = msg.lines().next().unwrap_or(msg);
                let _ = writeln!(s, "  PANIC {name}: {first_line}");
            }
        }
        let _ = writeln!(
            s,
            "==========================================================="
        );
        s
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tallies_and_pass_rate() {
        let mut r = Report::new();
        r.record("clauses", "a", &Outcome::Passed);
        r.record("clauses", "b", &Outcome::Failed("wrong rows".to_owned()));
        r.record("expressions", "c", &Outcome::Passed);
        r.record("expressions", "d", &Outcome::Errored("boom".to_owned()));
        r.record(
            "expressions",
            "e",
            &Outcome::Unsupported("CALL procedure".to_owned()),
        );

        assert_eq!(r.total(), 5);
        assert_eq!(r.overall.passed, 2);
        assert_eq!(r.overall.failed, 1);
        assert_eq!(r.overall.errored, 1);
        assert_eq!(r.overall.unsupported, 1);
        assert!((r.pass_rate() - 40.0).abs() < 1e-9);

        assert_eq!(r.by_category["clauses"].passed, 1);
        assert_eq!(r.by_category["clauses"].failed, 1);
        assert_eq!(r.by_category["expressions"].passed, 1);
        assert_eq!(r.unsupported_forms["CALL procedure"], 1);
    }

    #[test]
    fn render_includes_the_ratchet_line() {
        let mut r = Report::new();
        r.record("clauses", "a", &Outcome::Passed);
        let out = r.render(1);
        assert!(out.contains("TCK: 1/1 (100.00%) — baseline 1"));
        assert!(out.contains("clauses"));
    }
}
