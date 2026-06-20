//! Determinism guard: the generator MUST produce byte-identical artifacts for a given profile
//! (the gds-analytics example's #257 acceptance criterion). This is the regression gate for the
//! "BYTE-IDENTICAL graphs for a given seed/scale" requirement.

use graphus_gds_gen::{GenConfig, Profile, generate};

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

/// A custom config also reproduces byte-for-byte (the determinism is in `generate`, not just the
/// two named profiles).
#[test]
fn custom_config_is_byte_identical() {
    let cfg = GenConfig {
        seed: 0xDEAD_BEEF_CAFE_0001,
        community_count: 3,
        field_size: 20,
        intra_citations_per_author: 5,
        inter_citations_per_author: 1,
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
        "a different seed must change the citation structure"
    );
}

/// The reference subgraph is identical across profiles (only the benign background scales), so the
/// workload's reference assertions are profile-independent — EXCEPT the ref ids, which are anchored
/// past the author block and therefore differ by scale. The STRUCTURE (degrees, communities,
/// distances expressed as offsets) is invariant; we assert the offsets here.
#[test]
fn reference_structure_is_scale_invariant() {
    let fast = generate(Profile::Fast.config(), "fast");
    let large = generate(Profile::Large.config(), "large");

    // Re-base both references to offsets from their first ref id, then compare.
    let rebase = |r: &graphus_gds_gen::Reference| {
        let base = r.ref_ids[0];
        let ids: Vec<i64> = r.ref_ids.iter().map(|&x| x - base).collect();
        let degs: Vec<(i64, i64)> = r.degrees.iter().map(|&(x, d)| (x - base, d)).collect();
        let dists: Vec<(i64, i64)> = r
            .shortest_paths_from_first
            .iter()
            .map(|&(x, d)| (x - base, d))
            .collect();
        let tops: Vec<i64> = r.top_betweenness_nodes.iter().map(|&x| x - base).collect();
        (ids, degs, dists, tops)
    };
    assert_eq!(rebase(&fast.reference), rebase(&large.reference));
}
