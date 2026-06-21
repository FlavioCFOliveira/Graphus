//! Determinism + model-invariant contract for the social-network graph generator (`rmp` task #307).
//!
//! The generator's whole value as an example fixture is reproducibility: the same [`GenConfig`] must
//! produce a **byte-identical** Cypher graph on every run, host, and platform, so the example's
//! CPU / RAM / storage performance claims are pinned to a fixed input. These tests assert the
//! byte-identity, the configuration-model degree band, count consistency, and the node-property
//! contracts (bounded UTF-8 names, 24-lowercase-hex ids). Kept on the `fast` profile so it is quick.

use std::collections::HashMap;

use graphus_social_gen::{GenConfig, Generator, MAX_NAME_BYTES};

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
    let mut id_to_user: HashMap<String, u64> = HashMap::new();
    for u in 0..cfg.users {
        id_to_user.insert(Generator::user_id(u), u);
    }

    let mut degree = vec![0u64; cfg.users as usize];
    for line in text.lines() {
        if !line.contains("[:FRIEND") {
            continue;
        }
        // Each FRIEND line is: MATCH (a:USER {id: 'X'}), (b:USER {id: 'Y'}) CREATE (a)-[:FRIEND ...
        let ids = extract_quoted(line);
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
fn every_id_is_24_lowercase_hex_chars() {
    let cfg = GenConfig::fast();
    let is_lc_hex = |id: &str| {
        id.len() == 24
            && id
                .chars()
                .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c))
    };
    for u in 0..cfg.users {
        let id = Generator::user_id(u);
        assert!(is_lc_hex(&id), "USER {u} id not 24 lowercase hex: {id}");
    }
    for a in 0..cfg.articles {
        let id = Generator::article_id(a);
        assert!(is_lc_hex(&id), "ARTICLE {a} id not 24 lowercase hex: {id}");
    }
}

/// Extracts the contents of every `'…'` single-quoted literal on a line, in order.
fn extract_quoted(line: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut chars = line.char_indices().peekable();
    while let Some((_, c)) = chars.next() {
        if c == '\'' {
            let mut s = String::new();
            for (_, c2) in chars.by_ref() {
                if c2 == '\'' {
                    break;
                }
                s.push(c2);
            }
            out.push(s);
        }
    }
    out
}
