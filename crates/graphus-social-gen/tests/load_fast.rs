//! Hermetic engine-load test for `examples/social-network` (the `fast` profile).
//!
//! Runs the full large-graph load + read-query battery through the REAL Graphus engine over an
//! on-disk store in a per-process temp directory, then asserts the shape invariants the
//! `social_load` binary asserts plus the determinism of the realised graph. Gated on the `engine`
//! feature (the crate's default), so it runs under a plain `cargo test -p graphus-social-gen` exactly
//! like `graphus-iot-gen`'s `churn_plateau.rs` reclamation gate runs under its default `churn`
//! feature. No `#[ignore]`, no skips.

#![cfg(feature = "engine")]

use std::path::PathBuf;

use graphus_social_gen::load::{LoadOpts, run_load_isolated};
use graphus_social_gen::{GenConfig, Generator};

/// A fresh, unique temp directory for one test, removed on drop so the suite leaves no artifacts.
struct TempDir {
    path: PathBuf,
}

impl TempDir {
    fn new(tag: &str) -> Self {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let path = std::env::temp_dir().join(format!(
            "graphus-social-load-test-{tag}-{}-{nanos}",
            std::process::id()
        ));
        std::fs::create_dir_all(&path).expect("create temp dir");
        Self { path }
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

#[test]
fn fast_profile_loads_and_traverses() {
    let cfg = GenConfig::fast();
    let predicted = Generator::new(cfg.clone()).summary();

    let dir = TempDir::new("shape");
    let out = run_load_isolated(&cfg, &dir.path, LoadOpts::default());

    // --- Shape read back from the engine matches the generator's prediction exactly. -------------
    assert_eq!(out.user_count, cfg.users, "USER count");
    assert_eq!(out.article_count, cfg.articles, "ARTICLE count");
    assert_eq!(
        out.friend_count, predicted.friend_edges,
        "FRIEND edge count matches generator"
    );
    assert_eq!(
        out.like_count, predicted.like_edges,
        "LIKE edge count matches generator"
    );
    assert_eq!(
        out.nodes_phase.items,
        cfg.users + cfg.articles,
        "node phase item count matches USER + ARTICLE"
    );
    assert_eq!(
        out.rels_phase.items,
        predicted.friend_edges + predicted.like_edges,
        "relationship phase item count matches realised FRIEND + LIKE edges"
    );

    // --- The store is indexed and left real bytes on disk. ---------------------------------------
    assert!(out.indexed, "id indexes were built");
    assert!(out.device_bytes > 0, "device file is non-empty on disk");
    assert!(out.wal_bytes > 0, "WAL directory is non-empty on disk");

    // --- The read-query battery is present and well-formed. --------------------------------------
    let friends = out.query("friends").expect("friends probe");
    let fof = out.query("fof").expect("fof probe");
    let mutual = out.query("mutual").expect("mutual probe");
    let top = out.query("top_liked").expect("top_liked probe");
    let degree = out.query("degree").expect("degree probe");

    assert!(
        friends.scalar.unwrap_or(0) > 0,
        "direct friends non-empty: {friends:?}"
    );
    assert!(
        fof.scalar.unwrap_or(0) > 0,
        "friend-of-friend non-empty: {fof:?}"
    );
    assert_eq!(mutual.rows, 1, "mutual-friends returns one scalar row");
    assert!(
        top.rows >= 1,
        "top-liked returns at least one article: {top:?}"
    );
    assert!(
        degree.scalar.unwrap_or(0) > 0,
        "degree non-empty: {degree:?}"
    );
    // The degree (count of FRIEND *edges*) is at least the distinct-friend count (a true multigraph
    // can have multi-edges, so degree ≥ distinct neighbours; they coincide when no multi-edge touches
    // the seed user).
    assert!(
        degree.scalar.unwrap_or(0) >= friends.scalar.unwrap_or(0),
        "degree (edges) >= distinct friends: degree={degree:?} friends={friends:?}"
    );
    // The realised degree of the seed user must lie within the configured band.
    let d = degree.scalar.unwrap_or(0) as u64;
    assert!(
        d >= cfg.friend_min && d <= cfg.friend_max,
        "seed user degree {d} within [{}, {}]",
        cfg.friend_min,
        cfg.friend_max
    );
}

#[test]
fn fast_profile_load_is_deterministic() {
    // Two independent loads of the same config into two independent on-disk stores must read back the
    // identical realised shape and identical query answers — the load is a pure function of the
    // deterministic generator driven single-threaded inline.
    let cfg = GenConfig::fast();

    let dir_a = TempDir::new("det-a");
    let dir_b = TempDir::new("det-b");
    let a = run_load_isolated(&cfg, &dir_a.path, LoadOpts::default());
    let b = run_load_isolated(&cfg, &dir_b.path, LoadOpts::default());

    assert_eq!(a.user_count, b.user_count, "USER count stable");
    assert_eq!(a.article_count, b.article_count, "ARTICLE count stable");
    assert_eq!(a.friend_count, b.friend_count, "FRIEND count stable");
    assert_eq!(a.like_count, b.like_count, "LIKE count stable");

    for name in ["friends", "fof", "mutual", "top_liked", "degree"] {
        let qa = a.query(name).expect("probe a");
        let qb = b.query(name).expect("probe b");
        assert_eq!(qa.rows, qb.rows, "{name} row count stable");
        assert_eq!(qa.scalar, qb.scalar, "{name} scalar stable");
    }

    // The durable device footprint is also deterministic (same graph, same on-disk layout).
    assert_eq!(
        a.device_bytes, b.device_bytes,
        "device footprint deterministic across independent loads"
    );
}
