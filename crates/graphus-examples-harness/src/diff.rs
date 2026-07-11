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
//! | `throughput.abort_rate`      | **higher** (more transactions lost to conflict) |
//!
//! A metric regresses when its **fractional degradation** exceeds the threshold, e.g. with the
//! default 10%: ops/sec dropping from 1000 to 850 (−15%) regresses; dropping to 950 (−5%) does not.
//!
//! ## A gate over an unmeasured metric is SKIPPED, not passed (`rmp #711`)
//!
//! Every metric in the schema is an `Option`: **absent means not measured** (see the crate docs). A
//! gate can only compare what both sides measured, so a metric that is absent on **either** side is
//! moved to [`ComparisonReport::skipped`] — named, with the reason — instead of being folded into the
//! deltas.
//!
//! This exists because the alternative is worse than no gate at all. `storage.bytes_per_node` used to
//! be a dead field, `0.0` in every report ever emitted; the gate dutifully compared `0.0` against
//! `0.0`, found no degradation, and reported PASS. A gate that *cannot fire* is a lie of exactly the
//! same family as a zero placeholder — it wears a green tick while checking nothing. A skipped gate
//! says so out loud, in [`ComparisonReport::summary`], so the absence is visible and can be fixed by
//! capturing the missing measurement.
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
    /// Max tolerated **rise** in the transaction abort / conflict rate (`rmp #253`).
    pub abort_rate_rise: f64,
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
            abort_rate_rise: fraction,
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

/// Why a metric's gate could not run: which side did not measure it.
///
/// A gate needs a figure on **both** sides. Absent means *not measured* (schema `3`+, `rmp #711`), so
/// the honest outcome is neither PASS nor REGRESSED — it is **skipped**, and said out loud.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SkipReason {
    /// The baseline never measured this metric (e.g. a pre-`rmp #711` baseline, whose unmeasured
    /// metrics were zero placeholders and are normalised to "absent" on load). Re-capture the baseline
    /// from a real run to arm the gate.
    NotMeasuredInBaseline,
    /// The run being gated did not measure this metric, so there is nothing to compare.
    NotMeasuredInCandidate,
    /// Neither side measured it. Emphatically **not** a pass: this is the `0.0` vs `0.0` comparison
    /// that used to report "within threshold" while checking nothing at all.
    NotMeasuredInEither,
}

impl SkipReason {
    /// A short human phrase for [`ComparisonReport::summary`].
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NotMeasuredInBaseline => "not measured in the baseline",
            Self::NotMeasuredInCandidate => "not measured in this run",
            Self::NotMeasuredInEither => "not measured on either side",
        }
    }
}

/// A metric whose gate did not run, and why.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SkippedMetric {
    /// Stable metric key, e.g. `"storage.bytes_per_node"`.
    pub metric: String,
    /// Which side (or both) failed to measure it.
    pub reason: SkipReason,
}

/// The structured outcome of comparing a run against a baseline.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ComparisonReport {
    /// The baseline scenario id this comparison was made against.
    pub baseline_scenario: String,
    /// The candidate scenario id.
    pub candidate_scenario: String,
    /// One [`MetricDelta`] per **compared** metric (measured on both sides), in a stable order.
    pub deltas: Vec<MetricDelta>,
    /// The metrics whose gate could NOT run because one side (or both) did not measure them
    /// (`rmp #711`). Never silently dropped: a gate that cannot fire must be visible.
    #[serde(default)]
    pub skipped: Vec<SkippedMetric>,
    /// `true` if **any** compared metric regressed beyond its threshold.
    pub regressed: bool,
}

impl ComparisonReport {
    /// The subset of [`deltas`](Self::deltas) that regressed.
    #[must_use]
    pub fn regressions(&self) -> Vec<&MetricDelta> {
        self.deltas.iter().filter(|d| d.regressed).collect()
    }

    /// A short human-readable summary: an overall PASS/REGRESSED line, one line per offending metric
    /// (baseline → candidate, percentage worse, threshold), and — always — one line per **skipped**
    /// gate, so a metric nobody measured can never masquerade as a metric that passed.
    #[must_use]
    pub fn summary(&self) -> String {
        use std::fmt::Write as _;
        let mut s = String::with_capacity(256);
        let regressions = self.regressions();
        if regressions.is_empty() {
            let _ = writeln!(
                s,
                "PASS — no regression vs baseline `{}` ({} metrics compared within threshold, {} \
                 skipped)",
                self.baseline_scenario,
                self.deltas.len(),
                self.skipped.len()
            );
        } else {
            let _ = writeln!(
                s,
                "REGRESSED — {} of {} compared metrics worse than baseline `{}` beyond threshold ({} \
                 skipped):",
                regressions.len(),
                self.deltas.len(),
                self.baseline_scenario,
                self.skipped.len()
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
        for skip in &self.skipped {
            let _ = writeln!(
                s,
                "  ~ {}: SKIPPED — {} (not gated)",
                skip.metric,
                skip.reason.as_str()
            );
        }
        s
    }
}

/// Diffs `candidate` against `baseline` using `thresholds`, returning the structured comparison.
///
/// See the module docs for the per-metric "worse" direction, the regression rule, and why a metric
/// that either side did not measure is **skipped** rather than compared.
#[must_use]
pub fn compare(
    baseline: &EvidenceReport,
    candidate: &EvidenceReport,
    thresholds: &RegressionThresholds,
) -> ComparisonReport {
    use Direction::{HigherIsWorse, LowerIsWorse};

    let mut deltas = Vec::with_capacity(12);
    let mut skipped = Vec::new();

    // One gate. It runs only when BOTH sides measured the metric; otherwise it is skipped, named, and
    // reasoned — never silently folded into the deltas as a 0-vs-0 "pass".
    let mut gate = |metric: &str,
                    base: Option<f64>,
                    cand: Option<f64>,
                    dir: Direction,
                    threshold: f64| {
        match (base, cand) {
            (Some(b), Some(c)) => deltas.push(metric_delta(metric, b, c, dir, threshold)),
            (None, None) => skipped.push(SkippedMetric {
                metric: metric.to_string(),
                reason: SkipReason::NotMeasuredInEither,
            }),
            (None, Some(_)) => skipped.push(SkippedMetric {
                metric: metric.to_string(),
                reason: SkipReason::NotMeasuredInBaseline,
            }),
            (Some(_), None) => skipped.push(SkippedMetric {
                metric: metric.to_string(),
                reason: SkipReason::NotMeasuredInCandidate,
            }),
        }
    };

    // Throughput: ops/sec lower is worse; latencies higher is worse.
    gate(
        "throughput.ops_per_sec",
        baseline.throughput.ops_per_sec,
        candidate.throughput.ops_per_sec,
        LowerIsWorse,
        thresholds.throughput_drop,
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
        gate(key, base, cand, HigherIsWorse, thresholds.latency_rise);
    }

    // Memory: peak RSS higher is worse.
    gate(
        "memory.peak_rss_bytes",
        baseline.memory.peak_rss_bytes.map(|b| b as f64),
        candidate.memory.peak_rss_bytes.map(|b| b as f64),
        HigherIsWorse,
        thresholds.memory_rise,
    );

    // Storage footprint + amplification: higher is worse.
    gate(
        "storage.store_bytes",
        baseline.storage.store_bytes.map(|b| b as f64),
        candidate.storage.store_bytes.map(|b| b as f64),
        HigherIsWorse,
        thresholds.storage_rise,
    );
    gate(
        "storage.wal_bytes",
        baseline.storage.wal_bytes.map(|b| b as f64),
        candidate.storage.wal_bytes.map(|b| b as f64),
        HigherIsWorse,
        thresholds.storage_rise,
    );
    gate(
        "storage.write_amplification",
        baseline.storage.write_amplification,
        candidate.storage.write_amplification,
        HigherIsWorse,
        thresholds.amplification_rise,
    );
    gate(
        "storage.space_amplification",
        baseline.storage.space_amplification,
        candidate.storage.space_amplification,
        HigherIsWorse,
        thresholds.amplification_rise,
    );
    // Per-element durable cost: a deterministic, machine-independent footprint signal (record layout,
    // free-list slack, token-catalog growth). Held to the same band as the amplification ratios — this
    // is what an example that tracks element counts actually wants gated, and it no longer has to
    // smuggle the figure into an amplification field to get that.
    gate(
        "storage.bytes_per_node",
        baseline.storage.bytes_per_node,
        candidate.storage.bytes_per_node,
        HigherIsWorse,
        thresholds.amplification_rise,
    );
    gate(
        "storage.bytes_per_relationship",
        baseline.storage.bytes_per_relationship,
        candidate.storage.bytes_per_relationship,
        HigherIsWorse,
        thresholds.amplification_rise,
    );
    // Retention plateau: growing further beyond the steady state is worse. Present only for the
    // workloads that actually reach one (a retention/GC scenario), skipped everywhere else.
    gate(
        "storage.plateau_ratio",
        baseline.storage.plateau_ratio,
        candidate.storage.plateau_ratio,
        HigherIsWorse,
        thresholds.amplification_rise,
    );

    // CPU: total seconds higher is worse.
    gate(
        "cpu.total_secs",
        baseline.cpu.total_secs(),
        candidate.cpu.total_secs(),
        HigherIsWorse,
        thresholds.cpu_rise,
    );

    // Abort / conflict rate: a higher rate is worse (more contention loss). It is concurrency- and
    // timing-dependent, so consumers that compare across machines should hold it to a generous
    // `abort_rate_rise` (or omit it) to avoid flakiness — see the example's documented choice. Note
    // this is the one metric whose measured value may legitimately BE `0.0` (no conflicts), which is
    // why it is `Some(0.0)` when measured, not absent.
    gate(
        "throughput.abort_rate",
        baseline.throughput.abort_rate,
        candidate.throughput.abort_rate,
        HigherIsWorse,
        thresholds.abort_rate_rise,
    );

    let regressed = deltas.iter().any(|d| d.regressed);
    ComparisonReport {
        baseline_scenario: baseline.metadata.scenario.clone(),
        candidate_scenario: candidate.metadata.scenario.clone(),
        deltas,
        skipped,
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

    /// A baseline report with healthy round figures — every gated metric MEASURED, so each test below
    /// controls exactly which gate it exercises.
    fn baseline() -> EvidenceReport {
        let mut c = EvidenceCollector::new(RunMetadata::new("fraud-oltp", "baseline"));
        *c.throughput_mut() = ThroughputSection {
            operations: Some(100_000),
            ops_per_sec: Some(10_000.0),
            p50_latency_ms: Some(1.0),
            p99_latency_ms: Some(5.0),
            p999_latency_ms: Some(10.0),
            abort_rate: Some(0.02),
        };
        *c.memory_mut() = MemorySection {
            peak_rss_bytes: Some(100_000_000),
            final_rss_bytes: Some(80_000_000),
        };
        *c.storage_mut() = StorageSection {
            store_bytes: Some(1_000_000),
            wal_bytes: Some(200_000),
            store_pages: Some(123),
            wal_pages: Some(25),
            bytes_fsynced: Some(200_000),
            write_amplification: Some(1.5),
            space_amplification: Some(2.0),
            bytes_per_node: Some(500.0),
            bytes_per_relationship: Some(125.0),
            plateau_ratio: None,
        };
        *c.cpu_mut() = CpuSection {
            user_secs: Some(4.0),
            system_secs: Some(1.0),
            mean_core_utilisation: Some(0.5),
        };
        c.finish()
    }

    #[test]
    fn worse_run_is_flagged_with_offending_metrics() {
        let base = baseline();
        let mut worse = base.clone();
        worse.metadata.scenario = "fraud-oltp".to_string();
        // ops/sec down 20% (10000 -> 8000): a throughput regression.
        worse.throughput.ops_per_sec = Some(8_000.0);
        // p99 up 40% (5 -> 7): a latency regression.
        worse.throughput.p99_latency_ms = Some(7.0);
        // peak RSS up 30% (100MB -> 130MB): a memory regression.
        worse.memory.peak_rss_bytes = Some(130_000_000);

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
        ok.throughput.ops_per_sec = Some(9_500.0);
        // p99 up only 8%.
        ok.throughput.p99_latency_ms = Some(5.4);
        // peak RSS up only 9%.
        ok.memory.peak_rss_bytes = Some(109_000_000);

        let cmp = compare(&base, &ok, &RegressionThresholds::default());
        assert!(!cmp.regressed, "within-threshold deltas must not regress");
        assert!(cmp.regressions().is_empty());
        assert!(cmp.summary().contains("PASS"));
    }

    #[test]
    fn improvements_are_never_regressions() {
        let base = baseline();
        let mut better = base.clone();
        better.throughput.ops_per_sec = Some(20_000.0); // doubled throughput
        better.throughput.p99_latency_ms = Some(1.0); // far lower latency
        better.memory.peak_rss_bytes = Some(50_000_000); // half the RAM
        better.storage.store_bytes = Some(500_000); // half the disk

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
        // A MEASURED zero baseline (the store really was empty) against a candidate that grew: a +100%
        // change on a higher-is-worse metric, which exceeds the 10% threshold. Distinct from an ABSENT
        // baseline, which is skipped (see the tests below).
        let mut base = baseline();
        base.storage.store_bytes = Some(0);
        let mut cand = base.clone();
        cand.storage.store_bytes = Some(1_000_000);

        let cmp = compare(&base, &cand, &RegressionThresholds::default());
        let store = cmp
            .deltas
            .iter()
            .find(|d| d.metric == "storage.store_bytes")
            .unwrap();
        assert!(store.regressed);
        assert_eq!(store.fractional_change, 1.0);
    }

    // -- Unmeasured metrics are SKIPPED, never silently "passed" (`rmp #711`) --------------------

    /// **The defect this task exists for.** `storage.bytes_per_node` was a dead field: `0.0` in every
    /// report, on both sides of every diff. The gate compared `0.0` to `0.0`, found no degradation,
    /// and printed PASS — a gate that could not fire, wearing a green tick. Absent on both sides must
    /// now be reported as SKIPPED and must NOT count as a compared metric.
    #[test]
    fn a_metric_absent_on_both_sides_is_skipped_not_passed() {
        let mut base = baseline();
        let mut cand = baseline();
        base.storage.bytes_per_node = None;
        cand.storage.bytes_per_node = None;

        let cmp = compare(&base, &cand, &RegressionThresholds::default());

        assert!(
            !cmp.deltas
                .iter()
                .any(|d| d.metric == "storage.bytes_per_node"),
            "an unmeasured metric must not appear as a compared delta"
        );
        let skip = cmp
            .skipped
            .iter()
            .find(|s| s.metric == "storage.bytes_per_node")
            .expect("the gate must be REPORTED as skipped, not silently dropped");
        assert_eq!(skip.reason, SkipReason::NotMeasuredInEither);
        // …and it is visible to a human reading the gate's output.
        let summary = cmp.summary();
        assert!(summary.contains("storage.bytes_per_node: SKIPPED"));
        assert!(summary.contains("not measured on either side"));
    }

    /// Absent in the BASELINE only (the common case for a baseline captured before the metric existed):
    /// there is nothing to gate against, so the gate is skipped and says which side is missing.
    #[test]
    fn a_metric_absent_in_the_baseline_is_skipped_with_that_reason() {
        let mut base = baseline();
        base.storage.bytes_per_node = None;
        let cand = baseline(); // measured: 500.0

        let cmp = compare(&base, &cand, &RegressionThresholds::default());
        let skip = cmp
            .skipped
            .iter()
            .find(|s| s.metric == "storage.bytes_per_node")
            .expect("skipped");
        assert_eq!(skip.reason, SkipReason::NotMeasuredInBaseline);
        assert!(!cmp.regressed, "an unmeasured baseline is not a regression");
        assert!(cmp.summary().contains("not measured in the baseline"));
    }

    /// Absent in the CANDIDATE only: the run stopped measuring something the baseline has. That is not
    /// a regression in the metric (there is no figure to compare) but it MUST be surfaced — a silently
    /// disappearing metric is how a gate quietly stops gating.
    #[test]
    fn a_metric_absent_in_the_candidate_is_skipped_with_that_reason() {
        let base = baseline(); // measured
        let mut cand = baseline();
        cand.storage.bytes_per_node = None;

        let cmp = compare(&base, &cand, &RegressionThresholds::default());
        let skip = cmp
            .skipped
            .iter()
            .find(|s| s.metric == "storage.bytes_per_node")
            .expect("skipped");
        assert_eq!(skip.reason, SkipReason::NotMeasuredInCandidate);
        assert!(cmp.summary().contains("not measured in this run"));
    }

    /// A fully-measured pair still gates: the per-element cost is a real, tight-band regression signal
    /// once both sides have it (the whole point of populating it).
    #[test]
    fn a_measured_per_element_cost_still_regresses() {
        let base = baseline(); // 500.0 B/node
        let mut cand = baseline();
        cand.storage.bytes_per_node = Some(700.0); // +40% durable bytes per node

        let cmp = compare(&base, &cand, &RegressionThresholds::default());
        let d = cmp
            .deltas
            .iter()
            .find(|d| d.metric == "storage.bytes_per_node")
            .expect("both sides measured it, so it MUST be gated");
        assert!(d.regressed);
        assert!(cmp.regressed);
    }

    /// A run whose whole storage vector is N/A (an external target) skips every storage gate and
    /// regresses on none of them — but reports all of them as skipped.
    #[test]
    fn an_unmeasured_vector_skips_every_one_of_its_gates() {
        let base = baseline();
        let mut cand = baseline();
        cand.storage = StorageSection::default();

        let cmp = compare(&base, &cand, &RegressionThresholds::default());
        assert!(!cmp.regressed);
        for metric in [
            "storage.store_bytes",
            "storage.wal_bytes",
            "storage.write_amplification",
            "storage.space_amplification",
            "storage.bytes_per_node",
            "storage.bytes_per_relationship",
        ] {
            assert!(
                cmp.skipped.iter().any(|s| s.metric == metric),
                "{metric} must be reported as skipped"
            );
            assert!(
                !cmp.deltas.iter().any(|d| d.metric == metric),
                "{metric} must not be compared"
            );
        }
    }
}
