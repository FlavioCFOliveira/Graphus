//! `graphus-durability-demo` — the **deterministic core** of the `durability-crash-recovery` example.
//!
//! The example demonstrates Graphus's two inviolable durability guarantees — **no acknowledged commit
//! is ever lost across a crash**, and **no in-flight effect ever survives one** — under a concurrent
//! OLTP workload, a seeded mid-workload crash, and ARIES recovery. Per `CLAUDE.md` (the DST mandate:
//! *"any test that can be expressed as a deterministic scenario MUST be driven through the DST
//! simulator"*), the scenario is **driven entirely by the existing DST simulator** in
//! [`graphus_dst`] — this crate REUSES that machinery rather than reimplementing it:
//!
//! | Concern (rmp task) | Reused `graphus-dst` machinery |
//! |--------------------|--------------------------------|
//! | OLTP workload + shadow model (#271) | the VOPR cooperative interleaver under `VoprConfig::safety` (overlapping explicit transactions, write-heavy create/relate/property/delete mix) + the committed-only `ShadowGraph` reference LPG |
//! | crash injection + ARIES recovery (#272) | the crash fault + `crash_restart` woven mid-workload, classified per restart by `CrashSplit` |
//! | durability oracle (#273) | the four-property `run_safety` bundle (serializability / durability / atomicity / reference-model equivalence) asserted on the *recovered* engine |
//! | one-command replay (#277) | the `ReplayArtifact` + `FailurePredicate` machinery (the `durability_replay` binary) |
//!
//! Everything is a pure function of the seed: same seed ⇒ identical workload, identical crash
//! schedule, identical recovered state, identical verdict. This crate is a **dev-only leaf**:
//! `graphus-server` does not depend on it, so the production binary is untouched.
#![forbid(unsafe_code)]

use graphus_dst::vopr::run_safety;
use graphus_dst::{SafetyProperty, SafetyReport, VoprConfig};

/// The acked-vs-in-flight partition captured at one mid-workload crash + ARIES restart — the empirical
/// proof of the committed-or-nothing contract for a single seed.
///
/// At the crash instant, every virtual client's transaction is exactly one of **acked** (the engine
/// acknowledged its `COMMIT` before the crash — it is in the durable WAL and ARIES redo MUST replay it)
/// or **in-flight** (still open, never acknowledged — ARIES undo/no-redo MUST discard it). These counts
/// are taken on the one deterministic timeline, so two replays of the same seed produce identical
/// partitions. Mirrors [`graphus_dst::SafetyReport`]'s per-crash `CrashSplit`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CrashPartition {
    /// The dispatched-step ordinal the crash fired at (the canonical timeline index).
    pub fire_step: u64,
    /// Commits the engine acknowledged **before** this crash — these MUST survive recovery.
    pub acked_commits: usize,
    /// Transactions still open at the crash — these MUST NOT survive recovery.
    pub inflight_txns: usize,
    /// A stable hash of the engine state after this crash's ARIES recovery (the determinism witness).
    pub recovered_state_hash: u64,
}

/// The deterministic verdict of one durability scenario run for a single `seed`.
///
/// Built entirely from the underlying [`SafetyReport`] (the DST four-property oracle). It surfaces the
/// per-crash acked/in-flight partition and the durability/atomicity verdict the example asserts.
#[derive(Debug, Clone)]
pub struct DurabilityRun {
    /// The seed this run replays from.
    pub seed: u64,
    /// `true` iff all four safety properties held on the recovered engine (no violation).
    pub durable: bool,
    /// The number of committed/recovered transactions the serializability checker ruled on.
    pub recovered_txns: usize,
    /// How many crash + ARIES restarts fired mid-workload (the durability stressor).
    pub crash_restarts: u32,
    /// Disk + clock + transport faults the scheduler injected during the interleaved work.
    pub faults_injected: u32,
    /// `:Person` rows actually present after recovery — must equal [`committed_nodes`](Self::committed_nodes).
    pub recovered_nodes: i64,
    /// Distinct `:Person` ids whose creating transaction committed — the durability obligation.
    pub committed_nodes: i64,
    /// The per-crash acked/in-flight partition, in fire order (empty only if no crash fired).
    pub crashes: Vec<CrashPartition>,
    /// Each violated safety property's stable name + detail (empty iff [`durable`](Self::durable)).
    pub violations: Vec<(&'static str, String)>,
    /// The canonical event-trace hash of the run (the byte-identity / determinism witness).
    pub trace_hash: u64,
}

impl DurabilityRun {
    /// Builds a [`DurabilityRun`] from a finished [`SafetyReport`].
    fn from_report(r: &SafetyReport) -> Self {
        let crashes = r
            .run
            .crash_splits
            .iter()
            .map(|s| CrashPartition {
                fire_step: s.fire_step,
                acked_commits: s.acked_commits,
                inflight_txns: s.inflight_txns,
                recovered_state_hash: s.recovered_state_hash,
            })
            .collect();
        Self {
            seed: r.seed(),
            durable: r.safe,
            recovered_txns: r.checked_txns,
            crash_restarts: r.run.crash_restarts,
            faults_injected: r.run.disk_faults + r.run.clock_faults + r.run.transport_faults,
            recovered_nodes: r.run.persisted_nodes,
            committed_nodes: r.run.created_nodes,
            crashes,
            violations: r
                .violations
                .iter()
                .map(|v| (v.property.name(), v.detail.clone()))
                .collect(),
            trace_hash: r.run.trace_hash,
        }
    }

    /// The total acked commits at the last crash — the cumulative durable set that survived recovery.
    #[must_use]
    pub fn acked_at_last_crash(&self) -> usize {
        self.crashes.last().map_or(0, |c| c.acked_commits)
    }

    /// The total in-flight transactions summed across crashes — the set ARIES undo discarded.
    #[must_use]
    pub fn total_inflight_discarded(&self) -> usize {
        self.crashes.iter().map(|c| c.inflight_txns).sum()
    }

    /// `true` iff this run actually exercised the durability contract non-vacuously: at least one
    /// crash fired AND at least one commit was acked AND at least one transaction was in flight at a
    /// crash (so both halves of committed-or-nothing were under test).
    #[must_use]
    pub fn non_vacuous(&self) -> bool {
        !self.crashes.is_empty()
            && self.crashes.iter().any(|c| c.acked_commits > 0)
            && self.crashes.iter().any(|c| c.inflight_txns > 0)
    }
}

/// Runs the deterministic durability scenario for a single `seed`: the OLTP interleaver under faults +
/// a mid-workload crash, ARIES recovery, and the four-property durability oracle on the recovered
/// engine. A pure function of the seed (same seed ⇒ identical [`DurabilityRun`]).
#[must_use]
pub fn run_seed(seed: u64) -> DurabilityRun {
    let report = run_safety(VoprConfig::safety(seed));
    DurabilityRun::from_report(&report)
}

/// The aggregate verdict of a durability sweep over `start..start+count`.
#[derive(Debug, Clone)]
pub struct SweepReport {
    /// The first seed run (inclusive).
    pub start: u64,
    /// The number of seeds run.
    pub count: u64,
    /// The per-seed runs, in seed order.
    pub runs: Vec<DurabilityRun>,
    /// How many seeds had a determinism mismatch (a re-run produced a different report).
    pub nondeterministic: u64,
}

impl SweepReport {
    /// Seeds whose durability oracle reported a violation.
    #[must_use]
    pub fn unsafe_seeds(&self) -> Vec<u64> {
        self.runs
            .iter()
            .filter(|r| !r.durable)
            .map(|r| r.seed)
            .collect()
    }

    /// `true` iff every seed was durable AND deterministic — the zero-violation gate.
    #[must_use]
    pub fn all_safe(&self) -> bool {
        self.unsafe_seeds().is_empty() && self.nondeterministic == 0
    }

    /// Total crash + ARIES restarts across the sweep.
    #[must_use]
    pub fn total_crashes(&self) -> u32 {
        self.runs.iter().map(|r| r.crash_restarts).sum()
    }

    /// Total faults injected across the sweep.
    #[must_use]
    pub fn total_faults(&self) -> u32 {
        self.runs.iter().map(|r| r.faults_injected).sum()
    }

    /// Total acked commits proven durable across the sweep (summed final acked-at-last-crash).
    #[must_use]
    pub fn total_acked_durable(&self) -> usize {
        self.runs
            .iter()
            .map(DurabilityRun::acked_at_last_crash)
            .sum()
    }

    /// Total in-flight transactions discarded by ARIES undo across the sweep.
    #[must_use]
    pub fn total_inflight_discarded(&self) -> usize {
        self.runs
            .iter()
            .map(DurabilityRun::total_inflight_discarded)
            .sum()
    }

    /// How many sweep runs exercised the durability contract non-vacuously (see
    /// [`DurabilityRun::non_vacuous`]).
    #[must_use]
    pub fn non_vacuous_runs(&self) -> usize {
        self.runs.iter().filter(|r| r.non_vacuous()).count()
    }
}

/// Runs the durability sweep over `start..start+count`, re-running each seed once to certify
/// determinism (same seed ⇒ identical report). A pure function of the inputs.
#[must_use]
pub fn run_sweep(start: u64, count: u64) -> SweepReport {
    let mut runs = Vec::with_capacity(count as usize);
    let mut nondeterministic = 0u64;
    for seed in start..start.saturating_add(count) {
        let first = run_safety(VoprConfig::safety(seed));
        let second = run_safety(VoprConfig::safety(seed));
        if first != second {
            nondeterministic += 1;
        }
        runs.push(DurabilityRun::from_report(&first));
    }
    SweepReport {
        start,
        count,
        runs,
        nondeterministic,
    }
}

/// The four durability/ACID properties this scenario certifies on every recovered engine — surfaced so
/// the example README and report can name them stably. Mirrors [`SafetyProperty`].
#[must_use]
pub fn certified_properties() -> [&'static str; 4] {
    [
        SafetyProperty::Serializability.name(),
        SafetyProperty::Durability.name(),
        SafetyProperty::Atomicity.name(),
        SafetyProperty::ReferenceModel.name(),
    ]
}

/// The **planted-failure replay round-trip** (rmp #277).
///
/// The real Graphus engine has **no failing seed** — every durability scenario recovers correctly (see
/// [`run_sweep`]). So to demonstrate that the one-command replay tooling genuinely round-trips a failure
/// to a byte-identical reproduction, we plant a *synthetic*, config-level failure using the existing
/// #242 [`FailurePredicate`](graphus_dst::FailurePredicate) path — exactly the mechanism the DST
/// shrinker tests use to exercise the replay machinery without a real engine bug.
///
/// The planted predicate is a pure function of the [`VoprConfig`]: it "fails" whenever the workload is
/// genuinely concurrent (`clients >= 3`) and does real work (`ops_per_client >= 10`). Because it depends
/// only on the config — which the [`ReplayArtifact`](graphus_dst::ReplayArtifact) records — a separate
/// `--replay` invocation reconstructs the identical predicate and reproduces the identical verdict.
pub mod planted {
    use graphus_dst::vopr::run;
    use graphus_dst::{ReplayArtifact, ReplayMode, ReplayOutcome, VoprConfig};

    /// A stable sentinel embedded in the artifact's `failure_summary` so a later `--replay` recognises
    /// a planted (synthetic) reproducer and reconstructs the same predicate.
    pub const PLANTED_TAG: &str = "PLANTED-SYNTHETIC-FAILURE/clients>=3&&ops>=10";

    /// The planted, deterministic failure predicate over a config: a stand-in for a real engine bug.
    /// Pure function of the config, so it is reconstructible from the recorded artifact.
    #[must_use]
    pub fn predicate(cfg: &VoprConfig) -> bool {
        cfg.clients >= 3 && cfg.ops_per_client >= 10
    }

    /// Captures a planted-failure [`ReplayArtifact`] for `seed`: runs the config (a standard VOPR run,
    /// to record the canonical trace/state hashes), confirms the planted predicate "fails", and builds
    /// an artifact whose hashes are the real run's hashes and whose summary carries [`PLANTED_TAG`].
    ///
    /// Returns `None` if the planted predicate does not fire for the seed's config (it always does for
    /// the safety preset, whose `clients == 6` and `ops_per_client == 24`).
    #[must_use]
    pub fn capture(seed: u64) -> Option<ReplayArtifact> {
        let config = VoprConfig::safety(seed);
        if !predicate(&config) {
            return None;
        }
        let report = run(config);
        Some(ReplayArtifact {
            version: graphus_dst::vopr_repro::ARTIFACT_VERSION,
            mode: ReplayMode::Standard,
            config,
            expected_trace_hash: report.trace_hash,
            expected_state_hash: report.state_hash,
            failure_summary: format!(
                "{PLANTED_TAG}: synthetic failure (clients={} ops={}) — a stand-in for a real engine \
                 bug, used to prove the replay round-trip (the real engine has no failing seed)",
                config.clients, config.ops_per_client
            ),
        })
    }

    /// Replays a planted artifact and classifies the reproduction the SAME WAY [`graphus_dst`]'s replay
    /// does — but under the **reconstructed planted predicate** rather than the engine's (passing) real
    /// verdict. A faithful reproduction means: the re-run's trace+state hashes equal the recorded ones
    /// byte-for-byte (determinism), AND the planted predicate still fires (the failure survives).
    ///
    /// This is the in-process core of the `--replay` command; it mirrors
    /// [`graphus_dst::vopr_repro::replay_artifact`] but swaps the failure notion for the planted one, so
    /// a synthetic failure round-trips to [`ReplayOutcome::Reproduced`] deterministically.
    #[must_use]
    pub fn replay(artifact: &ReplayArtifact) -> ReplayOutcome {
        let report = run(artifact.config);
        let actual = (report.trace_hash, report.state_hash);
        let expected = (artifact.expected_trace_hash, artifact.expected_state_hash);
        if actual != expected {
            return ReplayOutcome::HashMismatch { expected, actual };
        }
        if !predicate(&artifact.config) {
            return ReplayOutcome::NoLongerFails { hashes: actual };
        }
        ReplayOutcome::Reproduced {
            trace_hash: report.trace_hash,
            state_hash: report.state_hash,
            summary: artifact.failure_summary.clone(),
        }
    }

    /// `true` iff `artifact` is a planted (synthetic) reproducer (its summary carries [`PLANTED_TAG`]).
    #[must_use]
    pub fn is_planted(artifact: &ReplayArtifact) -> bool {
        artifact.failure_summary.contains(PLANTED_TAG)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_seed_is_durable_and_deterministic() {
        let a = run_seed(7);
        let b = run_seed(7);
        assert!(a.durable, "seed 7 must recover durably: {:?}", a.violations);
        assert_eq!(
            a.trace_hash, b.trace_hash,
            "same seed must produce an identical trace (determinism)"
        );
        assert_eq!(a.crashes.len(), b.crashes.len());
        for (x, y) in a.crashes.iter().zip(&b.crashes) {
            assert_eq!(
                x.recovered_state_hash, y.recovered_state_hash,
                "same seed must recover an identical state at each crash"
            );
        }
    }

    #[test]
    fn safety_preset_actually_crashes_and_recovers() {
        // The scenario must be non-vacuous: a crash fires, acked commits coexist with in-flight work,
        // and recovery upholds the contract (acked survive == created == persisted).
        let r = run_seed(7);
        assert!(r.crash_restarts >= 1, "a crash must fire mid-workload");
        assert!(
            !r.crashes.is_empty(),
            "the crash must be classified into an acked/in-flight partition"
        );
        assert_eq!(
            r.recovered_nodes, r.committed_nodes,
            "every acked create must survive and no in-flight create may persist"
        );
    }

    #[test]
    fn small_sweep_is_all_safe() {
        let s = run_sweep(1, 12);
        assert!(
            s.all_safe(),
            "the durability oracle must pass for every seed; unsafe={:?} nondet={}",
            s.unsafe_seeds(),
            s.nondeterministic
        );
        assert!(
            s.non_vacuous_runs() > 0,
            "at least one sweep run must exercise the contract non-vacuously"
        );
    }

    #[test]
    fn durability_oracle_surfaces_an_injected_violation() {
        // MUTATION / TEETH (example level): the real engine never violates, so we take a genuine
        // SafetyReport and INJECT a durability violation (a regressed acked-commit count + a missing
        // recovered :Person row, as if recovery had lost an acknowledged commit). `from_report` must
        // surface it as NON-durable and carry the violation through — proving the example would NOT
        // mask a real regression. (The cell-by-cell oracle arms themselves are proven to have teeth in
        // `graphus-dst`: `evaluate_safety_has_teeth_per_property`, `oracle_catches_an_injected_extra_edge`,
        // `oracle_catches_a_phantom_node`, `serializability_arm_catches_a_fabricated_cycle`.)
        use graphus_dst::{SafetyProperty, SafetyViolation};

        let mut report = run_safety(VoprConfig::safety(7));
        assert!(report.safe, "the unmutated run must be durable");

        // Inject the violation a lost-acked-commit recovery bug would produce.
        report.safe = false;
        report.run.persisted_nodes -= 1; // a recovered :Person row vanished
        report.violations.push(SafetyViolation {
            property: SafetyProperty::Durability,
            detail: "INJECTED: acked-commit count regressed across recovery".to_owned(),
        });

        let run = DurabilityRun::from_report(&report);
        assert!(
            !run.durable,
            "the injected violation must make the run non-durable"
        );
        assert_ne!(
            run.recovered_nodes, run.committed_nodes,
            "the injected lost row must show as a committed-or-nothing breach"
        );
        assert!(
            run.violations.iter().any(|(p, _)| *p == "durability"),
            "the durability violation must be surfaced by name: {:?}",
            run.violations
        );
    }

    #[test]
    fn planted_failure_round_trips_to_identical_reproduction() {
        use graphus_dst::ReplayOutcome;

        let artifact =
            planted::capture(7).expect("planted predicate must fire for the safety preset");
        assert!(planted::is_planted(&artifact));

        // The artifact survives a JSON round-trip (it is the on-disk reproducer the README documents).
        let json = artifact.to_json().expect("serialize");
        let back = graphus_dst::ReplayArtifact::from_json(&json).expect("deserialize");
        assert_eq!(artifact, back, "the reproducer must serialize losslessly");

        // Replaying it reproduces the IDENTICAL failure byte-for-byte.
        match planted::replay(&back) {
            ReplayOutcome::Reproduced {
                trace_hash,
                state_hash,
                ..
            } => {
                assert_eq!(trace_hash, artifact.expected_trace_hash);
                assert_eq!(state_hash, artifact.expected_state_hash);
            }
            other => panic!("planted reproducer must reproduce identically, got {other:?}"),
        }
    }

    #[test]
    fn planted_replay_detects_a_corrupted_artifact_as_a_mismatch() {
        use graphus_dst::ReplayOutcome;

        let mut artifact = planted::capture(7).expect("capture");
        // Corrupt the recorded hash: the replay must catch the determinism mismatch (teeth on the
        // byte-identity gate), not silently pass.
        artifact.expected_trace_hash ^= 0xDEAD_BEEF;
        assert!(matches!(
            planted::replay(&artifact),
            ReplayOutcome::HashMismatch { .. }
        ));
    }

    #[test]
    fn certified_properties_are_the_four_acid_durability_properties() {
        let p = certified_properties();
        assert_eq!(p.len(), 4);
        assert!(p.contains(&"durability"));
        assert!(p.contains(&"atomicity"));
        assert!(p.contains(&"serializability"));
        assert!(p.contains(&"reference-model-equivalence"));
    }
}
