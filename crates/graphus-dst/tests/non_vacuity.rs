//! Non-vacuity acceptance test (task brief: "the scenario is not trivially empty").
//!
//! A green DST suite is worthless if the scenarios never actually exercise the dangerous conditions.
//! This test proves, across many seeds, that the harness really:
//!
//! * acknowledges commits (durability obligations exist to lose),
//! * leaves work in flight at the crash (atomicity has something to roll back), and
//! * makes recovery's undo phase genuinely run (recovery rolled back loser transactions),
//!
//! and that, simultaneously, the acknowledged commits survive. If any of these were zero the
//! "all invariants hold" result would be vacuous.

use graphus_dst::{run_crash_scenario, run_scenario};

/// Across a spread of seeds, the crash scenario must produce acknowledged commits, in-flight work at
/// the crash, and recovery losers — and still pass every invariant.
#[test]
fn crash_scenarios_are_non_vacuous_in_aggregate() {
    let mut total_commits = 0u64;
    let mut total_in_flight = 0u64;
    let mut total_recovery_losers = 0usize;
    let mut non_vacuous_runs = 0u64;
    let n = 150u64;

    for seed in 1..=n {
        let r = run_crash_scenario(seed);
        assert!(r.passed(), "seed {seed} failed: {:?}", r.result);
        total_commits += r.ledger.acknowledged_commits();
        total_in_flight += r.ledger.in_flight_at_crash();
        total_recovery_losers += r.recovery_losers;
        if r.non_vacuous {
            non_vacuous_runs += 1;
        }
    }

    assert!(
        total_commits > 0,
        "no acknowledged commits across {n} seeds — durability check is vacuous"
    );
    assert!(
        total_in_flight > 0,
        "no in-flight work at crash across {n} seeds — atomicity check is vacuous"
    );
    assert!(
        total_recovery_losers > 0,
        "recovery never rolled work back across {n} seeds — undo phase untested"
    );
    // The vast majority of runs should be individually non-vacuous (commit present AND work rolled
    // back); require a strong majority rather than 100% to stay robust to a degenerate seed.
    assert!(
        non_vacuous_runs * 4 >= n * 3,
        "only {non_vacuous_runs}/{n} runs were non-vacuous; the scenario mix is too weak"
    );
}

/// Every seed-selected scenario must inject exactly one of the supported fault kinds (no run sneaks
/// past with no fault).
#[test]
fn every_run_injects_a_supported_fault() {
    use graphus_dst::FaultKind;
    for seed in 1..=150u64 {
        let r = run_scenario(seed);
        let label = r.fault.label();
        assert!(
            FaultKind::all_labels().contains(&label),
            "seed {seed} injected an unrecognised fault '{label}'"
        );
    }
}

/// At least one seed must produce each of the three supported fault kinds, so the fault scheduler is
/// genuinely exercising the whole catalogue rather than one branch.
#[test]
fn all_supported_fault_kinds_occur() {
    use std::collections::BTreeSet;
    let kinds: BTreeSet<&'static str> = (1..=200u64)
        .map(|s| run_scenario(s).fault.label())
        .collect();
    assert!(
        kinds.contains("crash(no-force)"),
        "no no-force crash occurred"
    );
    assert!(kinds.contains("crash(steal)"), "no steal crash occurred");
    assert!(kinds.contains("torn-wal-tail"), "no torn-WAL-tail occurred");
}
