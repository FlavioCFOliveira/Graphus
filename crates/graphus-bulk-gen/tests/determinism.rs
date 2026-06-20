//! Determinism guard: the generator MUST produce byte-identical CSV + manifest for a given profile
//! (the bulk-etl example's #264 acceptance criterion — "byte-identical CSVs per seed"). This is the
//! regression gate for the reproducibility requirement.

use graphus_bulk_gen::{GenConfig, Profile, generate};

/// Both profiles emit byte-identical node/relationship CSV + manifest JSON across independent
/// generations.
#[test]
fn profiles_are_byte_identical_across_runs() {
    for profile in [Profile::Fast, Profile::Large] {
        let cfg = profile.config();
        let a = generate(cfg, profile.name());
        let b = generate(cfg, profile.name());

        assert_eq!(
            a.node_files.len(),
            b.node_files.len(),
            "{} profile: node-file set diverged",
            profile.name()
        );
        for (fa, fb) in a.node_files.iter().zip(&b.node_files) {
            assert_eq!(fa.name, fb.name);
            assert_eq!(
                fa.csv,
                fb.csv,
                "{} profile: node CSV {} diverged between runs",
                profile.name(),
                fa.name
            );
        }
        for (fa, fb) in a.rel_files.iter().zip(&b.rel_files) {
            assert_eq!(fa.name, fb.name);
            assert_eq!(
                fa.csv,
                fb.csv,
                "{} profile: relationship CSV {} diverged between runs",
                profile.name(),
                fa.name
            );
        }
        assert_eq!(
            a.manifest_json().unwrap(),
            b.manifest_json().unwrap(),
            "{} profile: manifest.json diverged between runs",
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
        persons: 50,
        forums: 8,
        posts_per_forum: 4,
        comments_per_post: 2,
        knows_per_person: 4,
        members_per_forum: 6,
        likes_per_person: 3,
    };
    let a = generate(cfg, "custom");
    let b = generate(cfg, "custom");
    for (fa, fb) in a.node_files.iter().zip(&b.node_files) {
        assert_eq!(fa.csv, fb.csv);
    }
    for (fa, fb) in a.rel_files.iter().zip(&b.rel_files) {
        assert_eq!(fa.csv, fb.csv);
    }
    assert_eq!(a.manifest_json().unwrap(), b.manifest_json().unwrap());
}

/// Changing the seed changes the output (sanity: the seed is load-bearing).
#[test]
fn seed_changes_output() {
    let mut cfg = Profile::Fast.config();
    let a = generate(cfg, "fast");
    cfg.seed ^= 0xFFFF_FFFF;
    let b = generate(cfg, "fast");
    // The KNOWS / membership / likes edge tables are seed-driven, so they must differ.
    let knows_a = &a
        .rel_files
        .iter()
        .find(|r| r.rel_type == "KNOWS")
        .unwrap()
        .csv;
    let knows_b = &b
        .rel_files
        .iter()
        .find(|r| r.rel_type == "KNOWS")
        .unwrap()
        .csv;
    assert_ne!(
        knows_a, knows_b,
        "a different seed must change the KNOWS edges"
    );
}
