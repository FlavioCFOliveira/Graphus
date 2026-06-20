//! Determinism guard: the generator MUST produce byte-identical artifacts for a given profile
//! (the knowledge-graph-rest example's #279 acceptance criterion). This is the regression gate for
//! the "BYTE-IDENTICAL graphs for a given seed/scale" requirement.

use graphus_kg_gen::{GenConfig, Profile, generate};

/// Both profiles emit byte-identical Cypher + reference JSON across independent generations.
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
            a.reference_json().unwrap(),
            b.reference_json().unwrap(),
            "{} profile: reference.json diverged between runs",
            profile.name()
        );
    }
}

/// A custom config also reproduces byte-for-byte (the determinism is in `generate`, not just the two
/// named profiles).
#[test]
fn custom_config_is_byte_identical() {
    let cfg = GenConfig {
        seed: 0xDEAD_BEEF_CAFE_0001,
        topic_count: 4,
        concept_count: 30,
        author_count: 40,
        document_count: 100,
        concepts_per_document: 3,
        citations_per_document: 2,
        related_per_concept: 2,
    };
    let a = generate(cfg, "custom");
    let b = generate(cfg, "custom");
    assert_eq!(a.to_cypher(), b.to_cypher());
    assert_eq!(a.reference_json().unwrap(), b.reference_json().unwrap());
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
        "a different seed must change the generated structure"
    );
}

/// The reference subgraph (and therefore every reference query answer) is **identical across
/// profiles**: its ids are fixed (`ref-`-prefixed) and disjoint from the scaling background, so the
/// REST workload's reference assertions are profile-independent.
#[test]
fn reference_is_scale_invariant() {
    let fast = generate(Profile::Fast.config(), "fast");
    let large = generate(Profile::Large.config(), "large");
    assert_eq!(
        fast.reference, large.reference,
        "the reference subgraph must be identical at every scale"
    );
    assert_eq!(
        fast.reference_json().unwrap(),
        large.reference_json().unwrap()
    );
}
