//! Determinism + model-invariant contract for the product-recommendation graph generator
//! (`rmp` task #539).
//!
//! The generator's whole value as an example fixture is reproducibility: the same [`GenConfig`] must
//! produce a **byte-identical** CSV file set on every run, host, and platform, so the example's
//! CPU / RAM / storage performance claims are pinned to a fixed input. These tests assert the
//! byte-identity of all four CSV streams, that a different seed changes at least one stream, and the
//! configuration-model degree band. Kept on the `fast` profile so it is quick.

use std::collections::HashMap;

use graphus_reco_gen::{GenConfig, Generator};

/// Collects a full CSV stream (header + all data chunks) into one byte buffer.
fn collect_csv(stream: impl FnOnce(&mut dyn FnMut(Vec<u8>))) -> Vec<u8> {
    let mut out = Vec::new();
    let mut sink = |chunk: Vec<u8>| out.extend_from_slice(&chunk);
    stream(&mut sink);
    out
}

/// The four CSV streams (users, products, friends, purchased) collected into one array, in a fixed
/// order.
fn all_streams(g: &Generator) -> [Vec<u8>; 4] {
    [
        collect_csv(|s| g.stream_user_csv(s)),
        collect_csv(|s| g.stream_product_csv(s)),
        collect_csv(|s| {
            g.stream_friend_csv(s);
        }),
        collect_csv(|s| {
            g.stream_purchased_csv(s);
        }),
    ]
}

#[test]
fn fast_profile_csv_streams_are_byte_identical_across_runs() {
    let a = all_streams(&Generator::new(GenConfig::fast()));
    let b = all_streams(&Generator::new(GenConfig::fast()));
    assert_eq!(
        a, b,
        "identical config must yield byte-identical CSV streams"
    );
}

#[test]
fn profiles_resolve_and_diverge() {
    assert!(GenConfig::profile("fast").is_some());
    assert!(GenConfig::profile("large").is_some());
    assert!(GenConfig::profile("huge").is_some());
    assert!(GenConfig::profile("nope").is_none());

    // A different seed must change at least one of the four streams.
    let mut c = GenConfig::fast();
    c.seed ^= 0xDEAD_BEEF;
    assert_ne!(
        all_streams(&Generator::new(GenConfig::fast())),
        all_streams(&Generator::new(c)),
        "a different seed must change at least one emitted stream"
    );
}

#[test]
fn realised_friend_degree_is_within_band_for_every_user() {
    // Compute the realised per-user FRIEND degree histogram from the GENERATED friends.csv, then assert
    // every user's degree lands in [friend_min, friend_max] (the configuration-model contract).
    let cfg = GenConfig::fast();
    let g = Generator::new(cfg.clone());

    // Map every user id back to its index so we can attribute degrees.
    let mut id_to_user: HashMap<String, u64> = HashMap::new();
    for u in 0..cfg.users {
        id_to_user.insert(Generator::user_id(u), u);
    }

    let friend_csv = String::from_utf8(collect_csv(|s| {
        g.stream_friend_csv(s);
    }))
    .unwrap();

    let mut degree = vec![0u64; cfg.users as usize];
    // Each FRIEND data row is: <start_id>,<end_id>,FRIEND,<since>
    for line in friend_csv.lines().skip(1) {
        let mut cols = line.split(',');
        let (Some(a), Some(b)) = (cols.next(), cols.next()) else {
            panic!("malformed FRIEND row: {line}");
        };
        for id in [a, b] {
            let u = *id_to_user
                .get(id)
                .unwrap_or_else(|| panic!("FRIEND endpoint id not a known User: {id}"));
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
