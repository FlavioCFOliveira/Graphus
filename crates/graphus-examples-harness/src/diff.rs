//! Baseline-diff regression detection for evidence reports (`rmp #248`).
//!
//! [`compare`] diffs a candidate run against a committed **baseline** and flags a **regression** when
//! any key metric degrades by more than a configurable threshold (default **10%**). It is the gate an
//! example (or CI) uses to catch a performance/footprint regression before it lands.
//!
//! ## What "worse" means per metric
//!
//! Each metric has a fixed direction of "badness", so the helper knows which way a change is a
//! regression:
//!
//! | Metric | Worse when |
//! |--------|-----------|
//! | `throughput.ops_per_sec`     | **lower** (less work per second) |
//! | `throughput.p50/p99/p999`    | **higher** (slower) |
//! | `memory.peak_rss_bytes`      | **higher** (more RAM) |
//! | `storage.store_bytes` / `wal_bytes` | **higher** (more disk) |
//! | `storage.write_amplification` / `space_amplification` | **higher** (more overhead) |
//! | `cpu.user_secs + system_secs`| **higher** (more CPU) |
//!
//! A metric regresses when its **fractional degradation** exceeds the threshold, e.g. with the
//! default 10%: ops/sec dropping from 1000 to 850 (−15%) regresses; dropping to 950 (−5%) does not.
//!
//! ## Usage
//!
//! ```
//! use graphus_examples_harness::{EvidenceReport, RegressionThresholds};
//!
//! # fn doc(run: &EvidenceReport, baseline: &EvidenceReport) {
//! let cmp = run.compare_to_baseline(baseline, &RegressionThresholds::default());
//! if cmp.regressed {
//!     eprintln!("{}", cmp.summary());
//!     // a CI gate would exit non-zero here
//! }
//! # }
//! ```

use serde::{Deserialize, Serialize};

use crate::EvidenceReport;

/// The fractional degradation each metric may tolerate before it counts as a regression.
///
/// A value of `0.10` means "flag a regression once the metric is more than 10% worse than the
/// baseline". Thresholds are per metric **family** so latency can be held to a tighter (or looser)
/// bound than, say, storage footprint.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct RegressionThresholds {
    /// Max tolerated **drop** in `ops_per_sec` (e.g. `0.10` = a >10% throughput drop regresses).
    pub throughput_drop: f64,
    /// Max tolerated **rise** in any latency percentile.
    pub latency_rise: f64,
    /// Max tolerated **rise** in peak RSS.
    pub memory_rise: f64,
    /// Max tolerated **rise** in on-disk storage bytes.
    pub storage_rise: f64,
    /// Max tolerated **rise** in an amplification ratio.
    pub amplification_rise: f64,
    /// Max tolerated **rise** in total CPU seconds.
    pub cpu_rise: f64,
}

impl Default for RegressionThresholds {
    /// A uniform **10%** tolerance on every metric family — the project default.
    fn default() -> Self {
        Self::uniform(0.10)
    }
}

impl RegressionThresholds {
    /// Thresholds with the same `fraction` applied to every metric family.
    #[must_use]
    pub fn uniform(fraction: f64) -> Self {
        Self {
            throughput_drop: fraction,
            latency_rise: fraction,
            memory_rise: fraction,
            storage_rise: fraction,
            amplification_rise: fraction,
            cpu_rise: fraction,
        }
    }
}

/// The direction in which a metric gets *worse*.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Direction {
    /// The metric is worse when it **increases** (latency, memory, storage, CPU, amplification).
    HigherIsWorse,
    /// The metric is worse when it **decreases** (throughput).
    LowerIsWorse,
}

/// The diff of a single metric between baseline and candidate.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MetricDelta {
    /// Stable metric key, e.g. `"throughput.ops_per_sec"`.
    pub metric: String,
    /// The baseline value.
    pub baseline: f64,
    /// The candidate (current run) value.
    pub candidate: f64,
    /// Signed fractional change `(candidate - baseline) / baseline`. `0.0` when the baseline is `0`.
    pub fractional_change: f64,
    /// The fractional **degradation** (always `>= 0`): how much *worse* the candidate is, accounting
    /// for [`Direction`]. `0.0` when the candidate is equal-or-better.
    pub degradation: f64,
    /// The threshold this metric was held to.
    pub threshold: f64,
    /// Which direction is "worse" for this metric.
    pub direction: Direction,
    /// `true` when `degradation > threshold` — i.e. this metric regressed.
    pub regressed: bool,
}

/// The structured outcome of comparing a run against a baseline.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ComparisonReport {
    /// The baseline scenario id this comparison was made against.
    pub baseline_scenario: String,
    /// The candidate scenario id.
    pub candidate_scenario: String,
    /// One [`MetricDelta`] per compared metric, in a stable order.
    pub deltas: Vec<MetricDelta>,
    /// `true` if **any** metric regressed beyond its threshold.
    pub regressed: bool,
}

impl ComparisonReport {
    /// The subset of [`deltas`](Self::deltas) that regressed.
    #[must_use]
    pub fn regressions(&self) -> Vec<&MetricDelta> {
        self.deltas.iter().filter(|d| d.regressed).collect()
    }

    /// A short human-readable summary: an overall PASS/REGRESSED line, then one line per offending
    /// metric (baseline → candidate, percentage worse, threshold).
    #[must_use]
    pub fn summary(&self) -> String {
        use std::fmt::Write as _;
        let mut s = String::with_capacity(256);
        let regressions = self.regressions();
        if regressions.is_empty() {
            let _ = writeln!(
                s,
                "PASS — no regression vs baseline `{}` ({} metrics within threshold)",
                self.baseline_scenario,
                self.deltas.len()
            );
        } else {
            let _ = writeln!(
                s,
                "REGRESSED — {} of {} metrics worse than baseline `{}` beyond threshold:",
                regressions.len(),
                self.deltas.len(),
                self.baseline_scenario
            );
            for d in regressions {
                let _ = writeln!(
                    s,
                    "  - {}: {:.4} -> {:.4} ({:+.1}% worse, threshold {:.1}%)",
                    d.metric,
                    d.baseline,
                    d.candidate,
                    d.degradation * 100.0,
                    d.threshold * 100.0,
                );
            }
        }
        s
    }
}

/// Diffs `candidate` against `baseline` using `thresholds`, returning the structured comparison.
///
/// See the module docs for the per-metric "worse" direction and the regression rule.
#[must_use]
pub fn compare(
    baseline: &EvidenceReport,
    candidate: &EvidenceReport,
    thresholds: &RegressionThresholds,
) -> ComparisonReport {
    use Direction::{HigherIsWorse, LowerIsWorse};

    let mut deltas = Vec::with_capacity(10);
    let push = |metric: &str,
                base: f64,
                cand: f64,
                dir: Direction,
                threshold: f64,
                out: &mut Vec<MetricDelta>| {
        out.push(metric_delta(metric, base, cand, dir, threshold));
    };

    // Throughput: ops/sec lower is worse; latencies higher is worse.
    push(
        "throughput.ops_per_sec",
        baseline.throughput.ops_per_sec,
        candidate.throughput.ops_per_sec,
        LowerIsWorse,
        thresholds.throughput_drop,
        &mut deltas,
    );
    for (key, base, cand) in [
        (
            "throughput.p50_latency_ms",
            baseline.throughput.p50_latency_ms,
            candidate.throughput.p50_latency_ms,
        ),
        (
            "throughput.p99_latency_ms",
            baseline.throughput.p99_latency_ms,
            candidate.throughput.p99_latency_ms,
        ),
        (
            "throughput.p999_latency_ms",
            baseline.throughput.p999_latency_ms,
            candidate.throughput.p999_latency_ms,
        ),
    ] {
        push(
            key,
            base,
            cand,
            HigherIsWorse,
            thresholds.latency_rise,
            &mut deltas,
        );
    }

    // Memory: peak RSS higher is worse.
    push(
        "memory.peak_rss_bytes",
        baseline.memory.peak_rss_bytes as f64,
        candidate.memory.peak_rss_bytes as f64,
        HigherIsWorse,
        thresholds.memory_rise,
        &mut deltas,
    );

    // Storage footprint + amplification: higher is worse.
    push(
        "storage.store_bytes",
        baseline.storage.store_bytes as f64,
        candidate.storage.store_bytes as f64,
        HigherIsWorse,
        thresholds.storage_rise,
        &mut deltas,
    );
    push(
        "storage.wal_bytes",
        baseline.storage.wal_bytes as f64,
        candidate.storage.wal_bytes as f64,
        HigherIsWorse,
        thresholds.storage_rise,
        &mut deltas,
    );
    push(
        "storage.write_amplification",
        baseline.storage.write_amplification,
        candidate.storage.write_amplification,
        HigherIsWorse,
        thresholds.amplification_rise,
        &mut deltas,
    );
    push(
        "storage.space_amplification",
        baseline.storage.space_amplification,
        candidate.storage.space_amplification,
        HigherIsWorse,
        thresholds.amplification_rise,
        &mut deltas,
    );

    // CPU: total seconds higher is worse.
    push(
        "cpu.total_secs",
        baseline.cpu.user_secs + baseline.cpu.system_secs,
        candidate.cpu.user_secs + candidate.cpu.system_secs,
        HigherIsWorse,
        thresholds.cpu_rise,
        &mut deltas,
    );

    let regressed = deltas.iter().any(|d| d.regressed);
    ComparisonReport {
        baseline_scenario: baseline.metadata.scenario.clone(),
        candidate_scenario: candidate.metadata.scenario.clone(),
        deltas,
        regressed,
    }
}

/// Builds a [`MetricDelta`], computing the signed change, the direction-aware degradation, and the
/// regression flag.
fn metric_delta(
    metric: &str,
    baseline: f64,
    candidate: f64,
    direction: Direction,
    threshold: f64,
) -> MetricDelta {
    // Signed fractional change relative to the baseline. A zero baseline has no meaningful ratio:
    // treat any positive candidate as a full +1.0 (100%) change, and an equal (0 -> 0) as no change.
    let fractional_change = if baseline != 0.0 {
        (candidate - baseline) / baseline.abs()
    } else if candidate == 0.0 {
        0.0
    } else if candidate > 0.0 {
        1.0
    } else {
        -1.0
    };

    // Degradation is how much WORSE the candidate is, per direction; clamped at 0 (an improvement is
    // not a degradation).
    let degradation = match direction {
        Direction::HigherIsWorse => fractional_change.max(0.0),
        Direction::LowerIsWorse => (-fractional_change).max(0.0),
    };

    MetricDelta {
        metric: metric.to_string(),
        baseline,
        candidate,
        fractional_change,
        degradation,
        threshold,
        direction,
        regressed: degradation > threshold,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        CpuSection, EvidenceCollector, MemorySection, RunMetadata, StorageSection,
        ThroughputSection,
    };

    /// A baseline report with healthy round figures.
    fn baseline() -> EvidenceReport {
        let mut c = EvidenceCollector::new(RunMetadata::new("fraud-oltp", "baseline"));
        *c.throughput_mut() = ThroughputSection {
            operations: 100_000,
            ops_per_sec: 10_000.0,
            p50_latency_ms: 1.0,
            p99_latency_ms: 5.0,
            p999_latency_ms: 10.0,
        };
        *c.memory_mut() = MemorySection {
            peak_rss_bytes: 100_000_000,
            final_rss_bytes: 80_000_000,
        };
        *c.storage_mut() = StorageSection {
            store_bytes: 1_000_000,
            wal_bytes: 200_000,
            store_pages: 123,
            wal_pages: 25,
            bytes_fsynced: 200_000,
            write_amplification: 1.5,
            space_amplification: 2.0,
        };
        *c.cpu_mut() = CpuSection {
            user_secs: 4.0,
            system_secs: 1.0,
            mean_core_utilisation: 0.5,
        };
        c.finish()
    }

    #[test]
    fn worse_run_is_flagged_with_offending_metrics() {
        let base = baseline();
        let mut worse = base.clone();
        worse.metadata.scenario = "fraud-oltp".to_string();
        // ops/sec down 20% (10000 -> 8000): a throughput regression.
        worse.throughput.ops_per_sec = 8_000.0;
        // p99 up 40% (5 -> 7): a latency regression.
        worse.throughput.p99_latency_ms = 7.0;
        // peak RSS up 30% (100MB -> 130MB): a memory regression.
        worse.memory.peak_rss_bytes = 130_000_000;

        let cmp = compare(&base, &worse, &RegressionThresholds::default());
        assert!(cmp.regressed, "a clearly-worse run must be flagged");

        let regressed: Vec<&str> = cmp
            .regressions()
            .iter()
            .map(|d| d.metric.as_str())
            .collect();
        assert!(regressed.contains(&"throughput.ops_per_sec"));
        assert!(regressed.contains(&"throughput.p99_latency_ms"));
        assert!(regressed.contains(&"memory.peak_rss_bytes"));
        // The summary names the offenders.
        let summary = cmp.summary();
        assert!(summary.contains("REGRESSED"));
        assert!(summary.contains("throughput.ops_per_sec"));
    }

    #[test]
    fn within_threshold_run_is_not_flagged() {
        let base = baseline();
        let mut ok = base.clone();
        // ops/sec down only 5% (within the 10% tolerance).
        ok.throughput.ops_per_sec = 9_500.0;
        // p99 up only 8%.
        ok.throughput.p99_latency_ms = 5.4;
        // peak RSS up only 9%.
        ok.memory.peak_rss_bytes = 109_000_000;

        let cmp = compare(&base, &ok, &RegressionThresholds::default());
        assert!(!cmp.regressed, "within-threshold deltas must not regress");
        assert!(cmp.regressions().is_empty());
        assert!(cmp.summary().contains("PASS"));
    }

    #[test]
    fn improvements_are_never_regressions() {
        let base = baseline();
        let mut better = base.clone();
        better.throughput.ops_per_sec = 20_000.0; // doubled throughput
        better.throughput.p99_latency_ms = 1.0; // far lower latency
        better.memory.peak_rss_bytes = 50_000_000; // half the RAM
        better.storage.store_bytes = 500_000; // half the disk

        let cmp = compare(&base, &better, &RegressionThresholds::default());
        assert!(!cmp.regressed);
        // Every degradation is clamped at zero for an improvement.
        for d in &cmp.deltas {
            assert_eq!(
                d.degradation, 0.0,
                "{} should show no degradation",
                d.metric
            );
        }
    }

    #[test]
    fn zero_baseline_does_not_panic_and_flags_a_new_positive_cost() {
        // Baseline has 0 store_bytes; candidate has some -> a +100% change on a higher-is-worse
        // metric, which exceeds the 10% threshold.
        let mut base = baseline();
        base.storage.store_bytes = 0;
        let mut cand = base.clone();
        cand.storage.store_bytes = 1_000_000;

        let cmp = compare(&base, &cand, &RegressionThresholds::default());
        let store = cmp
            .deltas
            .iter()
            .find(|d| d.metric == "storage.store_bytes")
            .unwrap();
        assert!(store.regressed);
        assert_eq!(store.fractional_change, 1.0);
    }
}
