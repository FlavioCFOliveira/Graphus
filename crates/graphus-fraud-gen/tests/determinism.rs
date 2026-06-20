//! Determinism guard: the generator MUST produce byte-identical artifacts for a given profile
//! (the fraud-oltp example's #250 acceptance criterion). This is the regression gate for the
//! "BYTE-IDENTICAL graphs for a given seed/scale" requirement.

use graphus_fraud_gen::{GenConfig, Profile, generate};

/// Both profiles emit byte-identical Cypher + ground-truth JSON across independent generations.
#[test]
fn profiles_are_byte_identical_across_runs() {
    for profile in [Profile::Fast, Profile::Large] {
        let cfg = profile.config();
        let a = generate(cfg, profile.name());
        let b = generate(cfg, profile.name());

        assert_eq!(
            a.to_cypher(),
            b.to_cypher(),
            "{} profile: graph.cypher diverged between runs",
            profile.name()
        );
        assert_eq!(
            a.ground_truth_json().unwrap(),
            b.ground_truth_json().unwrap(),
            "{} profile: ground_truth.json diverged between runs",
            profile.name()
        );
    }
}

/// A custom config also reproduces byte-for-byte (the determinism is in `generate`, not just the
/// two named profiles).
#[test]
fn custom_config_is_byte_identical() {
    let cfg = GenConfig {
        seed: 0xDEAD_BEEF_CAFE_0001,
        legit_accounts: 50,
        benign_transfers: 120,
        ring_count: 4,
        ring_len: 3,
        mule_count: 3,
        mule_fan_in: 5,
        mule_fan_out: 4,
    };
    let a = generate(cfg, "custom");
    let b = generate(cfg, "custom");
    assert_eq!(a.to_cypher(), b.to_cypher());
    assert_eq!(
        a.ground_truth_json().unwrap(),
        b.ground_truth_json().unwrap()
    );
}

/// Changing the seed changes the output (sanity: the seed is actually load-bearing).
#[test]
fn seed_changes_output() {
    let mut cfg = Profile::Fast.config();
    let a = generate(cfg, "fast");
    cfg.seed ^= 0xFFFF_FFFF;
    let b = generate(cfg, "fast");
    assert_ne!(
        a.to_cypher(),
        b.to_cypher(),
        "a different seed must change the benign-transfer structure"
    );
}
