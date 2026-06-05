//! Determinism acceptance test (`specification/04-technical-design.md` §11.1: "fully reproducible
//! from a seed").
//!
//! Running the same seed twice must yield byte-identical outcomes: the same workload, the same
//! injected fault, the same recovered state, and the same pass/fail. This is the property that makes
//! a failing seed a one-line reproducer.

use graphus_dst::{CliConfig, run, run_crash_scenario, run_scenario};

/// The same seed produces an identical scenario report (workload + fault + recovery + verdict).
#[test]
fn same_seed_yields_identical_scenario_report() {
    for seed in 1..=120u64 {
        let a = run_scenario(seed);
        let b = run_scenario(seed);
        assert_eq!(a, b, "seed {seed}: run_scenario is not deterministic");

        let c = run_crash_scenario(seed);
        let d = run_crash_scenario(seed);
        assert_eq!(c, d, "seed {seed}: run_crash_scenario is not deterministic");
    }
}

/// The CLI's aggregate summary is a pure function of its configuration.
#[test]
fn cli_summary_is_deterministic() {
    let cfg = CliConfig {
        start_seed: 1,
        runs: 64,
        single_seed: None,
    };
    let (a, fa) = run(cfg);
    let (b, fb) = run(cfg);
    assert_eq!(a, b, "CLI summary differs between identical runs");
    assert_eq!(fa, fb);
    assert_eq!(fa, 0, "the default scenarios must all pass");
}

/// Two different seeds should (overwhelmingly) drive different workloads, so the harness is not
/// accidentally seed-independent.
#[test]
fn different_seeds_diverge() {
    // Compare the per-seed op counts; if the harness ignored the seed these would all be equal.
    let counts: Vec<u64> = (1..=40u64).map(|s| run_scenario(s).ops_applied).collect();
    let first = counts[0];
    assert!(
        counts.iter().any(|&c| c != first),
        "all seeds produced the same op count — the harness may be seed-independent"
    );
}
