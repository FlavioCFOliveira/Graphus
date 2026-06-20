//! Hermetic cargo mirror of the durability-crash-recovery example (rmp #276).
//!
//! This is the **default-`cargo test`** guard for the example's deterministic core: it runs the DST
//! OLTP crash/recovery scenario across a SMALL seed sweep and asserts the durability oracle on every
//! recovered engine — exactly what `examples/durability-crash-recovery/run.sh` proves at scale, but
//! fast, in-process, and with NO server, NO Bolt driver, NO Node, NO network. It REUSES the
//! `graphus-durability-demo` library (which in turn drives `graphus_dst::vopr::run_safety`), so the
//! cargo run and the shell example exercise the identical oracle.
//!
//! The real-server SIGKILL phase (rmp #275) is intentionally NOT mirrored here: it boots a real
//! `graphus-server` process and is therefore the shell example's job, kept out of the hermetic
//! default test run.
//!
//! Why a small sweep: the `run.sh` default is 30 seeds (CI-fast) / 100 (evidence scale); each seed is
//! a full concurrent-OLTP + crash + ARIES-recovery + four-property-oracle scenario. A 16-seed sweep
//! here keeps `cargo test` snappy while still crossing the contract non-vacuously (acked commits and
//! in-flight transactions coexisting at a crash) on multiple seeds.

#![forbid(unsafe_code)]

use graphus_durability_demo::{certified_properties, run_seed, run_sweep};

/// The fast-profile seed sweep mirrored into the default test run. Small enough to stay snappy, wide
/// enough to exercise the contract non-vacuously on several seeds.
const SWEEP_START: u64 = 1;
const SWEEP_COUNT: u64 = 16;

#[test]
fn fast_sweep_upholds_the_durability_oracle_on_every_recovered_engine() {
    let sweep = run_sweep(SWEEP_START, SWEEP_COUNT);

    // The oracle (serializability / durability / atomicity / reference-model equivalence) must hold on
    // every recovered engine, and every seed must be deterministic (re-run == first run).
    assert!(
        sweep.all_safe(),
        "the durability oracle must pass for every seed in {SWEEP_START}..{}: unsafe={:?} \
         non-deterministic={}",
        SWEEP_START + SWEEP_COUNT,
        sweep.unsafe_seeds(),
        sweep.nondeterministic,
    );

    // The scenario must be non-vacuous on at least one seed: a crash fired with acked commits AND
    // in-flight transactions coexisting, so both halves of committed-or-nothing were under test.
    assert!(
        sweep.non_vacuous_runs() > 0,
        "at least one sweep seed must exercise the contract non-vacuously"
    );

    // Aggregate evidence the example reports must be present: crashes fired, acked commits proven
    // durable, and in-flight transactions discarded by ARIES undo.
    assert!(
        sweep.total_crashes() >= 1,
        "the sweep must fire at least one mid-workload crash"
    );
    assert!(
        sweep.total_acked_durable() >= 1,
        "the sweep must prove at least one acked commit durable across a crash"
    );
    assert!(
        sweep.total_inflight_discarded() >= 1,
        "the sweep must discard at least one in-flight transaction via ARIES undo"
    );
}

#[test]
fn every_recovered_engine_satisfies_committed_or_nothing() {
    // The durability obligation, cell-checked per seed: every acked `:Person` create survives recovery
    // and no in-flight create persists, so recovered rows == distinct committed ids on every seed.
    let sweep = run_sweep(SWEEP_START, SWEEP_COUNT);
    for run in &sweep.runs {
        assert!(
            run.durable,
            "seed {} must recover durably: {:?}",
            run.seed, run.violations
        );
        assert_eq!(
            run.recovered_nodes, run.committed_nodes,
            "seed {}: every acked create must survive and no in-flight create may persist",
            run.seed
        );
    }
}

#[test]
fn the_scenario_is_deterministic_per_seed() {
    // Same seed => identical recovered state at every crash and an identical canonical trace. This is
    // the example's regression gate (any change to recovery flips a hash and fails here).
    for seed in [3, 7, 11] {
        let a = run_seed(seed);
        let b = run_seed(seed);
        assert_eq!(
            a.trace_hash, b.trace_hash,
            "seed {seed}: same seed must produce an identical canonical trace"
        );
        assert_eq!(
            a.crashes.len(),
            b.crashes.len(),
            "seed {seed}: same seed must fire the same number of crashes"
        );
        for (x, y) in a.crashes.iter().zip(&b.crashes) {
            assert_eq!(
                x.recovered_state_hash, y.recovered_state_hash,
                "seed {seed}: same seed must recover an identical state at each crash"
            );
        }
    }
}

#[test]
fn the_four_acid_durability_properties_are_certified() {
    // The example names the exact four properties it asserts; the mirror pins them so a property
    // rename in the simulator does not silently weaken the example's claim.
    let props = certified_properties();
    assert_eq!(props.len(), 4);
    for expected in [
        "serializability",
        "durability",
        "atomicity",
        "reference-model-equivalence",
    ] {
        assert!(
            props.contains(&expected),
            "the certified properties must include {expected:?}: {props:?}"
        );
    }
}
