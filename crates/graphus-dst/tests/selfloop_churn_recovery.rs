//! Large-seed crash-recovery sweep for interleaved self-loop incidence-chain churn (`rmp` #468,
//! originally DST seed 11731).
//!
//! Each seed drives, through the real storage/WAL/txn engine, two loser transactions that
//! statement-interleave self-loop prepends onto a shared committed node's incidence chain — one
//! rolled back **live**, the other left **in flight** at a crash — then runs ARIES recovery and
//! asserts every DST integrity invariant still holds (committed self-loops survive; the recovered
//! incidence chain is a well-formed forward thread, never "malformed (cycle?)"). See
//! [`graphus_dst::selfloop_churn`] for the scenario shape and why the generic harness cannot reach
//! it.
//!
//! The sweep is large (>= 10_000 seeds) so the broad family of interleavings, loser counts, crash
//! kinds, and corpse-run shapes around the seed-11731 defect is covered, not just the one seed. It
//! also asserts the sweep is **non-vacuous**: at least one seed reaches the exact vulnerable
//! post-recovery state the defect mishandled (the shared node's `first_rel` pointing at a dead-link
//! corpse, with committed self-loops threaded below it).

use graphus_dst::run_selfloop_churn_crash;

/// The number of seeds swept. Kept as a named constant so the non-vacuity assertions can reference it.
const SEEDS: u64 = 10_000;

#[test]
fn selfloop_churn_crash_recovery_holds_across_ten_thousand_seeds() {
    let mut corpse_head_hits = 0u64;
    let mut loser_hits = 0u64;
    let mut committed_total = 0u64;

    for seed in 1..=SEEDS {
        let report = run_selfloop_churn_crash(seed);
        assert!(
            report.passed(),
            "seed {seed} violated an integrity invariant after self-loop-churn crash recovery \
             (steal={}): {:?}\nreproduce with: \
             graphus_dst::run_selfloop_churn_crash({seed})",
            report.steal,
            report.result
        );
        assert!(
            report.committed_rels >= 1,
            "seed {seed}: every run must commit at least one survivor relationship"
        );

        // Determinism: re-running the same seed must reproduce the identical report.
        let again = run_selfloop_churn_crash(seed);
        assert_eq!(report, again, "seed {seed} is not deterministic");

        if report.head_pointed_at_corpse {
            corpse_head_hits += 1;
        }
        if report.recovery_losers > 0 {
            loser_hits += 1;
        }
        committed_total += report.committed_rels as u64;
    }

    // Non-vacuity: the sweep must actually reach the vulnerable post-recovery state the `rmp` #468
    // defect mishandled — a corpse head with committed self-loops below it — and must actually
    // exercise recovery undo, or it proves nothing.
    assert!(
        corpse_head_hits > 0,
        "no seed reached a corpse head: the sweep never exercised the rmp #468 condition \
         (the committed self-loop below an uncovered corpse run)"
    );
    assert!(
        loser_hits > 0,
        "no seed produced a recovery loser: the in-flight loser was never undone by recovery"
    );
    assert!(
        committed_total > 0,
        "the sweep committed no survivor relationships: nothing was at risk"
    );
}
