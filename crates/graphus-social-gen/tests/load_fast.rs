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
fn fast_profile_declares_search_schema_and_searches_headlines() {
    let cfg = GenConfig::fast();

    let dir = TempDir::new("schema");
    let out = run_load_isolated(&cfg, &dir.path, LoadOpts::default());

    // --- The production-realistic search schema is declared, correctly typed, and Online. ---------
    assert!(out.schema_applied, "the search schema must be applied");
    let online = |name: &str, kind: &str, entity: &str| {
        let idx = out
            .index(name)
            .unwrap_or_else(|| panic!("index {name} present: {:?}", out.indexes));
        assert_eq!(idx.kind, kind, "{name} type");
        assert_eq!(idx.entity, entity, "{name} entity");
        assert_eq!(idx.state, "ONLINE", "{name} state");
    };
    // The two always-on token LOOKUP indexes are surfaced.
    online("node_label_lookup_index", "LOOKUP", "NODE");
    online("rel_type_lookup_index", "LOOKUP", "RELATIONSHIP");
    // The new index kinds: TEXT + FULLTEXT (node), relationship RANGE, composite (node) RANGE.
    online("article_name_text", "TEXT", "NODE");
    online("article_headline_fulltext", "FULLTEXT", "NODE");
    online("like_date_range", "RANGE", "RELATIONSHIP");
    online("article_catalog_composite", "RANGE", "NODE");
    // The id read-path is now backed by UNIQUENESS constraints (below), not standalone RANGE indexes:
    // a constraint's backing index is NOT listed by SHOW INDEXES, so neither id index appears here.
    assert!(
        out.index("user_id_range").is_none() && out.index("article_id_range").is_none(),
        "the id RANGE indexes were replaced by uniqueness constraints (backings are not listed): {:?}",
        out.indexes
    );

    // The existence constraint on ARTICLE.name is declared.
    let cons = out
        .constraint("article_name_exists")
        .expect("existence constraint present");
    assert_eq!(cons.kind, "NODE_PROPERTY_EXISTENCE");
    assert_eq!(cons.properties, vec!["name".to_owned()]);

    // The id UNIQUENESS constraints are declared (enforce the unique key AND back the `(:USER {id})` /
    // `(:ARTICLE {id})` point-seeks).
    for (name, label) in [("user_id_unique", "USER"), ("article_id_unique", "ARTICLE")] {
        let c = out.constraint(name).unwrap_or_else(|| {
            panic!(
                "uniqueness constraint {name} present: {:?}",
                out.constraints
            )
        });
        assert_eq!(
            c.kind, "NODE_PROPERTY_UNIQUENESS",
            "{label}.id constraint kind"
        );
        assert_eq!(
            c.properties,
            vec!["id".to_owned()],
            "{label}.id constraint property"
        );
    }

    // --- The headline search: TEXT CONTAINS and FULLTEXT queryNodes return the SAME, generator-
    //     derived article set (the term is a single-token subject word). ---------------------------
    assert!(
        out.search_expected > 1,
        "the headline term must match multiple articles: {} -> {}",
        out.search_term,
        out.search_expected
    );
    let text = out.query("text_contains").expect("text_contains probe");
    let ft = out.query("fulltext").expect("fulltext probe");
    assert_eq!(
        text.scalar,
        Some(out.search_expected as i64),
        "TEXT CONTAINS '{}' returns the generator's {} articles",
        out.search_term,
        out.search_expected
    );
    assert_eq!(
        ft.scalar,
        Some(out.search_expected as i64),
        "FULLTEXT queryNodes('{}') returns the same {} articles (analyzer lowercases, no stemming)",
        out.search_term.to_lowercase(),
        out.search_expected
    );

    // --- The LIKE.date recent-window range predicate (a `RelIndexRangeSeek` on the like_date_range
    //     rel RANGE index since `rmp` #680) returns a non-trivial recent slice: 0 < recent < |LIKE|. --
    let recent = out.query("like_recent").expect("like_recent probe");
    let recent_n = recent.scalar.unwrap_or(-1);
    assert!(
        recent_n > 0 && (recent_n as u64) < out.like_count,
        "LIKE.date recent-half range is a non-trivial slice: 0 < {recent_n} < {}",
        out.like_count
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

    for name in [
        "friends",
        "fof",
        "mutual",
        "top_liked",
        "degree",
        "text_contains",
        "fulltext",
        "like_recent",
    ] {
        let qa = a.query(name).expect("probe a");
        let qb = b.query(name).expect("probe b");
        assert_eq!(qa.rows, qb.rows, "{name} row count stable");
        assert_eq!(qa.scalar, qb.scalar, "{name} scalar stable");
    }

    // The declared search schema + the headline ground truth are deterministic too.
    assert_eq!(a.search_term, b.search_term, "search term stable");
    assert_eq!(
        a.search_expected, b.search_expected,
        "search expected stable"
    );
    assert_eq!(a.indexes, b.indexes, "index listing stable");
    assert_eq!(a.constraints, b.constraints, "constraint listing stable");

    // The durable device footprint is also deterministic (same graph, same on-disk layout).
    assert_eq!(
        a.device_bytes, b.device_bytes,
        "device footprint deterministic across independent loads"
    );
}
