//! Multi-seed crash-fault acceptance test (`rmp` task #26; `specification/04-technical-design.md`
//! §11.1).
//!
//! Runs the crash-fault scenario across many seeds and asserts all four DST invariants every time:
//! durability (no acknowledged commit lost), atomicity (no in-flight/rolled-back effect survives),
//! integrity (adjacency well-formed, page checksums valid — all folded into
//! [`graphus_dst::verify`]), and determinism (a re-run of the same seed yields the identical
//! report). A failing seed is printed for one-line reproduction (`--seed <N>`).

use graphus_dst::{run_crash_scenario, run_scenario};

/// Every crash-fault seed must satisfy all four invariants.
#[test]
fn crash_fault_holds_all_invariants_across_many_seeds() {
    for seed in 1..=200u64 {
        let report = run_crash_scenario(seed);
        assert!(
            report.passed(),
            "seed {seed} [{}] violated an invariant: {:?}\n\
             reproduce with: cargo run -p graphus-dst -- --seed {seed}",
            report.fault.label(),
            report.result
        );
        // Determinism: the same seed must reproduce the identical report.
        let again = run_crash_scenario(seed);
        assert_eq!(report, again, "seed {seed} is not deterministic");
    }
}

/// The seed-selected fault mix (crash no-force / crash steal / torn-WAL-tail) must also hold across
/// many seeds — this is the exact path the CLI drives.
#[test]
fn seed_selected_fault_mix_holds_across_many_seeds() {
    for seed in 1..=200u64 {
        let report = run_scenario(seed);
        assert!(
            report.passed(),
            "seed {seed} [{}] violated an invariant: {:?}\n\
             reproduce with: cargo run -p graphus-dst -- --seed {seed}",
            report.fault.label(),
            report.result
        );
    }
}
