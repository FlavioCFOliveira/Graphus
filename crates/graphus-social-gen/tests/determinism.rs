//! Determinism + model-invariant contract for the social-network graph generator (`rmp` task #307).
//!
//! The generator's whole value as an example fixture is reproducibility: the same [`GenConfig`] must
//! produce a **byte-identical** Cypher graph on every run, host, and platform, so the example's
//! CPU / RAM / storage performance claims are pinned to a fixed input. These tests assert the
//! byte-identity, the configuration-model degree band, count consistency, and the node-property
//! contracts (bounded UTF-8 names, unique non-negative `u64` ids). Kept on the `fast` profile so it is
//! quick.

use std::collections::HashMap;

use graphus_social_gen::{DegreeDist, GenConfig, Generator, MAX_NAME_BYTES};

/// A `fast`-scale power-law config with a wide degree band, for the supernode / determinism tests.
fn power_law_cfg() -> GenConfig {
    GenConfig {
        friend_min: 1,
        friend_max: 500,
        degree_dist: DegreeDist::PowerLaw { exponent: 2 },
        ..GenConfig::fast()
    }
}

#[test]
fn power_law_generation_is_byte_identical_across_runs() {
    // The power-law degree draw is pure-integer (no `powf`, no float), so a power-law graph must be
    // just as byte-reproducible as the uniform one — the property the example's supernode evidence is
    // pinned to.
    let a = Generator::new(power_law_cfg()).emit_all();
    let b = Generator::new(power_law_cfg()).emit_all();
    assert_eq!(a, b, "power-law generation must be byte-identical per seed");
    // The summary line (degree histogram included) is likewise stable.
    let s1 = Generator::new(power_law_cfg()).summary_line();
    let s2 = Generator::new(power_law_cfg()).summary_line();
    assert_eq!(s1, s2, "power-law summary/histogram must be deterministic");
}

#[test]
fn power_law_produces_supernodes_a_uniform_band_cannot() {
    // The whole point of the power-law mode: a heavy tail of hubs. Compared with a uniform draw over
    // the SAME band, the power law must reach a materially higher maximum degree (a supernode) while
    // its median user stays sparse — the shape a real social graph has and the uniform model lacks.
    let power = Generator::new(power_law_cfg()).summary();
    let uniform = Generator::new(GenConfig {
        degree_dist: DegreeDist::Uniform,
        ..power_law_cfg()
    })
    .summary();

    // A uniform draw over [1, 500] concentrates every user near the band's mean (~250); the power law
    // pushes the MAX far above the uniform mean while pulling the typical degree far below it.
    assert!(
        power.degree_max > uniform.degree_avg_x1000 / 1000,
        "power-law max degree {} should exceed the uniform mean {} (a supernode)",
        power.degree_max,
        uniform.degree_avg_x1000 / 1000,
    );
    // Most users are sparse under the power law: its mean degree is well below the uniform mean.
    assert!(
        power.degree_avg_x1000 < uniform.degree_avg_x1000 / 2,
        "power-law mean degree x1000 {} should be far below the uniform mean x1000 {}",
        power.degree_avg_x1000,
        uniform.degree_avg_x1000,
    );

    // The log-2 histogram must have a long tail: at least one occupied bucket at/above degree 64 that
    // the uniform draw (max ~500 but concentrated near 250) does not spread into so sparsely.
    let hist = Generator::new(power_law_cfg()).degree_histogram();
    let tail_buckets = hist.iter().filter(|&&(floor, _)| floor >= 64).count();
    assert!(
        tail_buckets >= 2,
        "power-law degree histogram should have a heavy tail (>=2 buckets at/above degree 64): {hist:?}"
    );
    // And the sparse head must dominate: the smallest bucket holds more users than any tail bucket.
    let head = hist.first().map_or(0, |&(_, c)| c);
    let heaviest_tail = hist
        .iter()
        .filter(|&&(floor, _)| floor >= 64)
        .map(|&(_, c)| c)
        .max()
        .unwrap_or(0);
    assert!(
        head > heaviest_tail,
        "the sparse head bucket ({head}) should dominate the heaviest tail bucket ({heaviest_tail})"
    );
}

#[test]
fn uniform_config_omitting_degree_dist_deserializes_to_uniform() {
    // Forward-compat: an older serialized GenConfig without the `degree_dist` field must still load,
    // defaulting to Uniform, so no committed baseline / persisted config is invalidated.
    let json = r#"{"seed":1,"users":10,"articles":2,"friend_min":2,"friend_max":4,"avg_likes_per_user":1}"#;
    let cfg: GenConfig =
        serde_json::from_str(json).expect("legacy config without degree_dist loads");
    assert_eq!(cfg.degree_dist, DegreeDist::Uniform);
}

#[test]
fn fast_profile_is_byte_identical_across_runs() {
    let a = Generator::new(GenConfig::fast()).emit_all();
    let b = Generator::new(GenConfig::fast()).emit_all();
    assert_eq!(a, b, "identical config must yield byte-identical graphs");
    // And independently of how many times a single generator is asked (emit_all is non-consuming).
    let g = Generator::new(GenConfig::fast());
    assert_eq!(g.emit_all(), g.emit_all());
}

#[test]
fn profiles_resolve_and_diverge() {
    assert!(GenConfig::profile("fast").is_some());
    assert!(GenConfig::profile("large").is_some());
    assert!(GenConfig::profile("huge").is_some());
    assert!(GenConfig::profile("nope").is_none());

    // A different seed must change the graph.
    let mut c = GenConfig::fast();
    c.seed ^= 0xDEAD_BEEF;
    assert_ne!(
        Generator::new(GenConfig::fast()).emit_all(),
        Generator::new(c).emit_all(),
        "a different seed must change the emitted graph"
    );
}

#[test]
fn realised_friend_degree_is_within_band_for_every_user() {
    // Compute the realised per-user FRIEND degree histogram from the GENERATED edge text, then assert
    // every user's degree lands in [friend_min, friend_max] (the configuration-model contract).
    let cfg = GenConfig::fast();
    let g = Generator::new(cfg.clone());
    let text = g.emit_all();

    // Map every user id back to its index so we can attribute degrees.
    let mut id_to_user: HashMap<u64, u64> = HashMap::new();
    for u in 0..cfg.users {
        id_to_user.insert(Generator::user_id(u), u);
    }

    let mut degree = vec![0u64; cfg.users as usize];
    for line in text.lines() {
        if !line.contains("[:FRIEND") {
            continue;
        }
        // Each FRIEND line is: MATCH (a:USER {id: X}), (b:USER {id: Y}) CREATE (a)-[:FRIEND ...
        let ids = extract_ids(line);
        assert_eq!(
            ids.len(),
            2,
            "a FRIEND line names exactly two user ids: {line}"
        );
        for id in ids {
            let u = *id_to_user
                .get(&id)
                .unwrap_or_else(|| panic!("FRIEND endpoint id not a known USER: {id}"));
            degree[u as usize] += 1;
        }
    }

    for (u, &d) in degree.iter().enumerate() {
        assert!(
            d >= cfg.friend_min && d <= cfg.friend_max,
            "user {u} realised degree {d} outside [{}, {}]",
            cfg.friend_min,
            cfg.friend_max
        );
    }
}

#[test]
fn summary_counts_match_the_generated_text() {
    let g = Generator::new(GenConfig::fast());
    let s = g.summary();
    let text = g.emit_all();

    let users = text.matches("(:USER ").count() as u64;
    let articles = text.matches("(:ARTICLE ").count() as u64;
    let friend = text.matches("[:FRIEND").count() as u64;
    let like = text.matches("[:LIKE").count() as u64;

    assert_eq!(users, s.users, "USER node count");
    assert_eq!(articles, s.articles, "ARTICLE node count");
    assert_eq!(friend, s.friend_edges, "FRIEND edge count");
    assert_eq!(like, s.like_edges, "LIKE edge count");

    // And the config-declared node counts are honoured.
    assert_eq!(users, GenConfig::fast().users);
    assert_eq!(articles, GenConfig::fast().articles);
}

#[test]
fn every_user_name_is_bounded_valid_utf8() {
    let cfg = GenConfig::fast();
    for u in 0..cfg.users {
        let name = Generator::user_name(cfg.seed, u);
        assert!(
            name.len() <= MAX_NAME_BYTES,
            "user {u} name exceeds {MAX_NAME_BYTES} bytes: {name:?}"
        );
        assert!(!name.is_empty(), "user {u} name is empty");
        // A `String` is valid UTF-8 by construction; assert it round-trips through bytes.
        assert_eq!(
            String::from_utf8(name.clone().into_bytes()).unwrap(),
            name,
            "user {u} name must be valid UTF-8"
        );
        assert!(
            !name.contains('\''),
            "user {u} name must not contain a quote"
        );
    }
}

#[test]
fn every_id_is_a_unique_nonnegative_integer() {
    use std::collections::HashSet;
    let cfg = GenConfig::fast();

    // Every USER / ARTICLE id is a distinct, non-negative `i64` (bit 63 clear), and the two label id
    // spaces are disjoint — the invariants the `REQUIRE n.id IS UNIQUE` constraints enforce at load.
    let mut users = HashSet::new();
    for u in 0..cfg.users {
        let id = Generator::user_id(u);
        assert!(
            id < (1u64 << 63),
            "USER {u} id must fit a non-negative i64: {id}"
        );
        assert!(users.insert(id), "USER {u} id {id} is a duplicate");
    }
    let mut articles = HashSet::new();
    for a in 0..cfg.articles {
        let id = Generator::article_id(a);
        assert!(
            id < (1u64 << 63),
            "ARTICLE {a} id must fit a non-negative i64: {id}"
        );
        assert!(articles.insert(id), "ARTICLE {a} id {id} is a duplicate");
    }
    assert!(
        users.is_disjoint(&articles),
        "no USER id may equal an ARTICLE id"
    );
}

/// Extracts every `id: <integer>` value on a line, in order (the two `USER` endpoint ids of a FRIEND
/// statement, now unquoted `u64` integers). Matches the `id: ` key exactly, so the `since:` property is
/// not mistaken for an id.
fn extract_ids(line: &str) -> Vec<u64> {
    let mut out = Vec::new();
    let mut rest = line;
    while let Some(pos) = rest.find("id: ") {
        let after = &rest[pos + "id: ".len()..];
        let digits: String = after.chars().take_while(char::is_ascii_digit).collect();
        if let Ok(v) = digits.parse::<u64>() {
            out.push(v);
        }
        rest = &after[digits.len()..];
    }
    out
}
