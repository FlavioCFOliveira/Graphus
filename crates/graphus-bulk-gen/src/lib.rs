//! Deterministic, seeded **LDBC-SNB-like social-network generator** for the `examples/bulk-etl`
//! demonstration: it emits node and relationship CSV files in the **exact**
//! `neo4j-admin import`-flavoured format the offline [`graphus-bulk`](graphus_bulk) importer consumes,
//! at two parametrizable scales, with the **logical element counts known by construction** so the
//! round-trip and footprint drivers can assert against them.
//!
//! # The dataset model
//!
//! A directed Label Property Graph modelling an online social network (a small, honest subset of the
//! [LDBC Social Network Benchmark](https://ldbcouncil.org/benchmarks/snb/) schema):
//!
//! - `(:Person {id, firstName, lastName, gender, age, locationIP, browserUsed, tags:string[]})`
//! - `(:Forum {id, title, createdAt})`
//! - `(:Post {id, content, length, createdAt, language})`
//! - `(:Comment {id, content, length, createdAt})`
//!
//! Relationships (each carries at least one typed property so the importer's property path is
//! exercised):
//!
//! - `(:Person)-[:KNOWS {since:int}]->(:Person)` — the friendship graph (emitted once per pair).
//! - `(:Forum)-[:HAS_MEMBER {joinedAt:int}]->(:Person)` — forum membership.
//! - `(:Forum)-[:CONTAINER_OF {addedAt:int}]->(:Post)` — a post belongs to a forum.
//! - `(:Post)-[:HAS_CREATOR {weight:int}]->(:Person)` — post authorship.
//! - `(:Comment)-[:HAS_CREATOR {weight:int}]->(:Person)` — comment authorship.
//! - `(:Comment)-[:REPLY_OF {depth:int}]->(:Post)` — a comment replies to a post.
//! - `(:Person)-[:LIKES {creationDate:int}]->(:Post)` — a like on a post.
//!
//! Splitting the dataset across **one node CSV per label** and **one relationship CSV per type** is
//! the `neo4j-admin import` convention and lets the importer's [`BulkImporter::import_nodes`] /
//! [`BulkImporter::import_relationships`] passes be driven file-by-file, exactly as the CLI does.
//!
//! # External-id convention
//!
//! Every node carries a **globally-unique** external `:ID` string with a per-label prefix
//! (`p<i>` Person, `f<i>` Forum, `po<i>` Post, `c<i>` Comment). `graphus-bulk` keeps a single shared
//! `external :ID -> physical node id` map across all node files, so the prefixes guarantee no
//! cross-label id collision (which the importer would reject under its strict duplicate-`:ID` policy).
//!
//! # Determinism
//!
//! Generation is a pure function of `(seed, scale)`: the only randomness is an internal
//! [`SplitMix64`] PRNG seeded from `seed`. For a given [`GenConfig`] every emitted CSV byte and the
//! manifest are **byte-identical** across runs, hosts, and platforms — no float in the graph
//! structure, no `HashMap` iteration, no clock, no thread scheduling. Asserted by
//! `tests/determinism.rs`.
//!
//! # Known logical counts (the assertion contract)
//!
//! Because every count is derived from the config (not sampled), the [`Manifest`] records the exact
//! number of nodes per label, relationships per type, total nodes/relationships, and the total typed
//! property assignments — the ground truth the round-trip driver checks `graphus-bulk`'s reported
//! [`ImportStats`](graphus_bulk::ImportStats) against.
//!
//! # Indexes / constraints — an honest note
//!
//! The offline `graphus-bulk` importer builds a **fresh store directly** through the low-level record
//! API (`create_node` / `set_node_labels` / `set_node_property_value` / `create_rel` / …). It does
//! **not** build secondary indexes or enforce constraints — there is no index/constraint code in the
//! crate. The dataset *implies* a `UNIQUE` constraint on each label's `id` (the external-id join key)
//! and lookup indexes on it; those would be **declared via DDL on a live server** (`CREATE
//! CONSTRAINT … REQUIRE … IS UNIQUE`, `CREATE INDEX …`) after a bulk load, not built by the offline
//! importer. The generator guarantees the dataset *satisfies* that unique-id invariant by
//! construction (every `:ID` is distinct); see [`Manifest::implied_constraints`].

#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};
use std::fmt::Write as _;

pub mod content_hash;
pub mod store_io;

/// A tiny, fully-deterministic PRNG (SplitMix64 — Steele, Lea & Flood 2014). A pure integer mixing
/// function: identical output for identical seeds on every platform, no global state, no float, no
/// allocation. We never use the standard library's `HashMap`-based randomness or any clock, so the
/// whole generator is reproducible byte-for-byte.
#[derive(Debug, Clone)]
pub struct SplitMix64 {
    state: u64,
}

impl SplitMix64 {
    /// Seeds the generator. Any `u64` seed is valid.
    #[must_use]
    pub fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    /// Returns the next pseudo-random `u64`.
    pub fn next_u64(&mut self) -> u64 {
        // SplitMix64 reference constants.
        self.state = self.state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// Returns a value in `[0, n)` (n > 0) with negligible modulo bias for our small ranges.
    pub fn below(&mut self, n: u64) -> u64 {
        debug_assert!(n > 0, "below(0) is undefined");
        self.next_u64() % n
    }

    /// Returns an `i64` in the inclusive range `[lo, hi]`.
    pub fn range_i64(&mut self, lo: i64, hi: i64) -> i64 {
        debug_assert!(lo <= hi);
        let span = (hi - lo) as u64 + 1;
        lo + (self.below(span) as i64)
    }
}

/// The two generation profiles: a small `Fast` dataset for CI/E2E assertions, and a larger `Large`
/// dataset for evidence collection. Both pin their own seed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Profile {
    /// Small, fast dataset for CI and the hermetic round-trip/footprint assertions.
    Fast,
    /// Larger dataset for evidence collection (storage/throughput footprint at volume).
    Large,
}

impl Profile {
    /// Parses a profile name (`fast` / `large`), case-insensitively.
    ///
    /// # Errors
    /// Returns `Err` with the offending name if it is neither `fast` nor `large`.
    pub fn parse(name: &str) -> Result<Self, String> {
        match name.to_ascii_lowercase().as_str() {
            "fast" => Ok(Self::Fast),
            "large" => Ok(Self::Large),
            other => Err(format!(
                "unknown profile '{other}' (expected 'fast' or 'large')"
            )),
        }
    }

    /// The stable string name of this profile.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::Fast => "fast",
            Self::Large => "large",
        }
    }

    /// The scale knobs for this profile. Kept here (not in the binary) so the determinism test and
    /// the binary agree by construction.
    #[must_use]
    pub fn config(self) -> GenConfig {
        match self {
            // Small but non-trivial: a few hundred persons + their forums/posts/comments — enough to
            // exercise every node label, every relationship type, arrays, and multi-batch commits,
            // yet fast enough for a CI round-trip in well under a second.
            Self::Fast => GenConfig {
                seed: 0x50C1_A1B0_17E7_0001,
                persons: 200,
                forums: 24,
                posts_per_forum: 6,
                comments_per_post: 3,
                knows_per_person: 8,
                members_per_forum: 12,
                likes_per_person: 5,
            },
            // ~20x larger, for evidence: thousands of persons, tens of thousands of edges.
            // Deliberately bounded so the example completes promptly while still producing a
            // meaningful on-disk footprint to characterise (bytes/node, bytes/edge, amplification).
            Self::Large => GenConfig {
                seed: 0x50C1_A1B0_17E7_0001,
                persons: 4_000,
                forums: 400,
                posts_per_forum: 10,
                comments_per_post: 4,
                knows_per_person: 12,
                members_per_forum: 30,
                likes_per_person: 10,
            },
        }
    }
}

/// The full set of generation knobs. A [`Dataset`] is a pure function of this struct, so two configs
/// that compare equal produce byte-identical output.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct GenConfig {
    /// PRNG seed: the single source of all randomness.
    pub seed: u64,
    /// Number of `:Person` nodes.
    pub persons: u64,
    /// Number of `:Forum` nodes.
    pub forums: u64,
    /// `:Post` nodes minted per forum (total posts = `forums * posts_per_forum`).
    pub posts_per_forum: u64,
    /// `:Comment` nodes minted per post (total comments = `posts * comments_per_post`).
    pub comments_per_post: u64,
    /// Outgoing `:KNOWS` edges minted per person (best-effort distinct; self/duplicate skipped).
    pub knows_per_person: u64,
    /// `:HAS_MEMBER` edges minted per forum.
    pub members_per_forum: u64,
    /// `:LIKES` edges minted per person (each targets a random post).
    pub likes_per_person: u64,
}

impl GenConfig {
    /// Total `:Post` nodes.
    #[must_use]
    pub fn post_count(&self) -> u64 {
        self.forums * self.posts_per_forum
    }

    /// Total `:Comment` nodes.
    #[must_use]
    pub fn comment_count(&self) -> u64 {
        self.post_count() * self.comments_per_post
    }
}

/// A node label, used as the external-id prefix and the CSV `:LABEL` cell.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Label {
    Person,
    Forum,
    Post,
    Comment,
}

impl Label {
    /// The external-id prefix (keeps `:ID`s globally unique across labels).
    fn prefix(self) -> &'static str {
        match self {
            Self::Person => "p",
            Self::Forum => "f",
            Self::Post => "po",
            Self::Comment => "c",
        }
    }

    /// The `:LABEL` cell value.
    fn name(self) -> &'static str {
        match self {
            Self::Person => "Person",
            Self::Forum => "Forum",
            Self::Post => "Post",
            Self::Comment => "Comment",
        }
    }

    /// The external `:ID` of the `i`-th node of this label.
    fn id(self, i: u64) -> String {
        format!("{}{i}", self.prefix())
    }
}

/// A small fixed vocabulary the generator draws deterministic strings from.
const FIRST_NAMES: [&str; 8] = [
    "Ada", "Bjarne", "Cleo", "Dijkstra", "Edsger", "Fran", "Grace", "Hedy",
];
const LAST_NAMES: [&str; 8] = [
    "Lovelace",
    "Stroustrup",
    "Hopper",
    "Turing",
    "Knuth",
    "Liskov",
    "Lamport",
    "Hamilton",
];
const BROWSERS: [&str; 4] = ["Firefox", "Chrome", "Safari", "Edge"];
const LANGUAGES: [&str; 4] = ["en", "pt", "de", "fr"];
const TAG_VOCAB: [&str; 6] = [
    "graphs",
    "databases",
    "rust",
    "systems",
    "ml",
    "distributed",
];

/// A fully-materialized dataset: the four node tables and the seven relationship tables, plus the
/// manifest of known logical counts. Produced by [`generate`].
#[derive(Debug, Clone)]
pub struct Dataset {
    /// The generation config that produced this dataset.
    pub config: GenConfig,
    /// The profile name (free-form label carried into the manifest).
    pub profile: String,
    /// The manifest of known logical counts (the assertion contract).
    pub manifest: Manifest,
    /// One node CSV per label, in load order.
    pub node_files: Vec<NodeFile>,
    /// One relationship CSV per type, in load order.
    pub rel_files: Vec<RelFile>,
}

/// One generated node CSV file: its logical file name and its full CSV text (header + rows).
#[derive(Debug, Clone)]
pub struct NodeFile {
    /// The file's base name (e.g. `persons.csv`).
    pub name: String,
    /// The node label this file holds.
    pub label: String,
    /// The complete CSV text (header row + one row per node).
    pub csv: String,
    /// The number of node rows (excluding the header).
    pub rows: u64,
}

/// One generated relationship CSV file: its logical file name and its full CSV text.
#[derive(Debug, Clone)]
pub struct RelFile {
    /// The file's base name (e.g. `knows.csv`).
    pub name: String,
    /// The relationship type this file holds.
    pub rel_type: String,
    /// The complete CSV text (header row + one row per relationship).
    pub csv: String,
    /// The number of relationship rows (excluding the header).
    pub rows: u64,
}

/// The known logical element counts of a generated dataset — the ground truth the round-trip driver
/// asserts `graphus-bulk`'s reported [`ImportStats`](graphus_bulk::ImportStats) against.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Manifest {
    /// The profile name.
    pub profile: String,
    /// The generation config (so a consumer can reproduce the dataset).
    pub config: GenConfig,
    /// Node count per label, as `(label, count)` pairs in load order.
    pub nodes_by_label: Vec<(String, u64)>,
    /// Relationship count per type, as `(type, count)` pairs in load order.
    pub relationships_by_type: Vec<(String, u64)>,
    /// Total `:Node` count across all labels.
    pub total_nodes: u64,
    /// Total relationship count across all types.
    pub total_relationships: u64,
    /// Total typed property assignments (node + relationship), the figure `ImportStats.properties`
    /// must equal. An empty (skipped) optional cell does **not** count — the importer skips empty
    /// cells — so this is the count of *non-empty* property cells the generator emitted.
    pub total_properties: u64,
    /// The logical, uncompressed byte size of the dataset content (sum of every emitted CSV file's
    /// length). The space-amplification denominator: on-disk store bytes / this.
    pub logical_csv_bytes: u64,
    /// The constraints/indexes the dataset *implies* but the OFFLINE importer does **not** build
    /// (they would be declared via DDL on a live server). Honest documentation, not a built artifact.
    pub implied_constraints: Vec<String>,
}

/// Generates a [`Dataset`] from a [`GenConfig`].
///
/// The emission order is fixed so output is byte-stable:
/// 1. node tables: persons, forums, posts, comments (each in ascending id order);
/// 2. relationship tables: `KNOWS`, `HAS_MEMBER`, `CONTAINER_OF`, `HAS_CREATOR` (posts then
///    comments, merged into one file), `REPLY_OF`, `LIKES` — each minted by a deterministic walk over
///    the node ranges.
#[must_use]
pub fn generate(config: GenConfig, profile: &str) -> Dataset {
    let mut rng = SplitMix64::new(config.seed);

    let post_count = config.post_count();
    let comment_count = config.comment_count();

    // ---- Property accounting: count every NON-EMPTY property cell we emit. ----
    let mut props: u64 = 0;

    // ===== Node tables ===========================================================================
    // -- Person --
    // Header: id, label, firstName, lastName, gender, age, locationIP, browserUsed, tags:string[].
    let mut person_csv = String::with_capacity(config.persons as usize * 96);
    person_csv.push_str(
        "id:ID,:LABEL,firstName:string,lastName:string,gender:string,age:int,\
         locationIP:string,browserUsed:string,tags:string[]\n",
    );
    for i in 0..config.persons {
        let first = FIRST_NAMES[(rng.below(FIRST_NAMES.len() as u64)) as usize];
        let last = LAST_NAMES[(rng.below(LAST_NAMES.len() as u64)) as usize];
        let gender = if rng.below(2) == 0 { "female" } else { "male" };
        let age = rng.range_i64(16, 80);
        let ip = format!(
            "{}.{}.{}.{}",
            rng.below(256),
            rng.below(256),
            rng.below(256),
            rng.below(256)
        );
        let browser = BROWSERS[(rng.below(BROWSERS.len() as u64)) as usize];
        // 1..=3 distinct-ish tags (a `;`-separated array cell).
        let tag_count = rng.range_i64(1, 3) as u64;
        let mut tags: Vec<&str> = Vec::with_capacity(tag_count as usize);
        for _ in 0..tag_count {
            tags.push(TAG_VOCAB[(rng.below(TAG_VOCAB.len() as u64)) as usize]);
        }
        let _ = writeln!(
            person_csv,
            "{},Person,{first},{last},{gender},{age},{ip},{browser},{}",
            Label::Person.id(i),
            tags.join(";")
        );
        // 6 always-present scalar props (firstName, lastName, gender, age, locationIP, browserUsed)
        // + 1 always-present array prop (tags) = 7 per person.
        props += 7;
    }

    // -- Forum --
    let mut forum_csv = String::with_capacity(config.forums as usize * 48);
    forum_csv.push_str("id:ID,:LABEL,title:string,createdAt:int\n");
    for i in 0..config.forums {
        let created = 1_500_000_000 + rng.range_i64(0, 50_000_000);
        let _ = writeln!(
            forum_csv,
            "{},Forum,forum-{i},{created}",
            Label::Forum.id(i)
        );
        props += 2; // title, createdAt
    }

    // -- Post --
    let mut post_csv = String::with_capacity(post_count as usize * 64);
    post_csv.push_str("id:ID,:LABEL,content:string,length:int,createdAt:int,language:string\n");
    for i in 0..post_count {
        let length = rng.range_i64(10, 2000);
        let created = 1_500_000_000 + rng.range_i64(0, 50_000_000);
        let lang = LANGUAGES[(rng.below(LANGUAGES.len() as u64)) as usize];
        let _ = writeln!(
            post_csv,
            "{},Post,post-content-{i},{length},{created},{lang}",
            Label::Post.id(i)
        );
        props += 4; // content, length, createdAt, language
    }

    // -- Comment --
    let mut comment_csv = String::with_capacity(comment_count as usize * 56);
    comment_csv.push_str("id:ID,:LABEL,content:string,length:int,createdAt:int\n");
    for i in 0..comment_count {
        let length = rng.range_i64(5, 500);
        let created = 1_500_000_000 + rng.range_i64(0, 50_000_000);
        let _ = writeln!(
            comment_csv,
            "{},Comment,comment-content-{i},{length},{created}",
            Label::Comment.id(i)
        );
        props += 3; // content, length, createdAt
    }

    // ===== Relationship tables ===================================================================
    // -- KNOWS (Person -> Person), property since:int. Emitted once per ordered (a, target) draw. --
    let mut knows_csv = String::new();
    knows_csv.push_str(":START_ID,:END_ID,:TYPE,since:int\n");
    let mut knows_rows: u64 = 0;
    if config.persons >= 2 {
        for a in 0..config.persons {
            for _ in 0..config.knows_per_person {
                let target = rng.below(config.persons);
                if target == a {
                    continue; // no self-knows
                }
                let since = 2000 + rng.range_i64(0, 24);
                let _ = writeln!(
                    knows_csv,
                    "{},{},KNOWS,{since}",
                    Label::Person.id(a),
                    Label::Person.id(target)
                );
                knows_rows += 1;
                props += 1;
            }
        }
    }

    // -- HAS_MEMBER (Forum -> Person), property joinedAt:int. --
    let mut member_csv = String::new();
    member_csv.push_str(":START_ID,:END_ID,:TYPE,joinedAt:int\n");
    let mut member_rows: u64 = 0;
    if config.persons >= 1 {
        for f in 0..config.forums {
            for _ in 0..config.members_per_forum {
                let person = rng.below(config.persons);
                let joined = 1_500_000_000 + rng.range_i64(0, 50_000_000);
                let _ = writeln!(
                    member_csv,
                    "{},{},HAS_MEMBER,{joined}",
                    Label::Forum.id(f),
                    Label::Person.id(person)
                );
                member_rows += 1;
                props += 1;
            }
        }
    }

    // -- CONTAINER_OF (Forum -> Post), property addedAt:int. Each post belongs to its forum. --
    let mut container_csv = String::new();
    container_csv.push_str(":START_ID,:END_ID,:TYPE,addedAt:int\n");
    let mut container_rows: u64 = 0;
    for f in 0..config.forums {
        for k in 0..config.posts_per_forum {
            let post = f * config.posts_per_forum + k;
            let added = 1_500_000_000 + rng.range_i64(0, 50_000_000);
            let _ = writeln!(
                container_csv,
                "{},{},CONTAINER_OF,{added}",
                Label::Forum.id(f),
                Label::Post.id(post)
            );
            container_rows += 1;
            props += 1;
        }
    }

    // -- HAS_CREATOR (Post -> Person and Comment -> Person), property weight:int. One file, both
    //    source labels (the importer joins by external :ID regardless of source label). --
    let mut creator_csv = String::new();
    creator_csv.push_str(":START_ID,:END_ID,:TYPE,weight:int\n");
    let mut creator_rows: u64 = 0;
    if config.persons >= 1 {
        for post in 0..post_count {
            let person = rng.below(config.persons);
            let weight = rng.range_i64(1, 100);
            let _ = writeln!(
                creator_csv,
                "{},{},HAS_CREATOR,{weight}",
                Label::Post.id(post),
                Label::Person.id(person)
            );
            creator_rows += 1;
            props += 1;
        }
        for comment in 0..comment_count {
            let person = rng.below(config.persons);
            let weight = rng.range_i64(1, 100);
            let _ = writeln!(
                creator_csv,
                "{},{},HAS_CREATOR,{weight}",
                Label::Comment.id(comment),
                Label::Person.id(person)
            );
            creator_rows += 1;
            props += 1;
        }
    }

    // -- REPLY_OF (Comment -> Post), property depth:int. Each comment replies to its parent post. --
    let mut reply_csv = String::new();
    reply_csv.push_str(":START_ID,:END_ID,:TYPE,depth:int\n");
    let mut reply_rows: u64 = 0;
    for comment in 0..comment_count {
        // Comment `comment` belongs to post `comment / comments_per_post`.
        let post = comment / config.comments_per_post;
        let depth = rng.range_i64(1, 5);
        let _ = writeln!(
            reply_csv,
            "{},{},REPLY_OF,{depth}",
            Label::Comment.id(comment),
            Label::Post.id(post)
        );
        reply_rows += 1;
        props += 1;
    }

    // -- LIKES (Person -> Post), property creationDate:int. --
    let mut likes_csv = String::new();
    likes_csv.push_str(":START_ID,:END_ID,:TYPE,creationDate:int\n");
    let mut likes_rows: u64 = 0;
    if post_count >= 1 {
        for person in 0..config.persons {
            for _ in 0..config.likes_per_person {
                let post = rng.below(post_count);
                let created = 1_500_000_000 + rng.range_i64(0, 50_000_000);
                let _ = writeln!(
                    likes_csv,
                    "{},{},LIKES,{created}",
                    Label::Person.id(person),
                    Label::Post.id(post)
                );
                likes_rows += 1;
                props += 1;
            }
        }
    }

    // ===== Assemble the node/relationship file tables ============================================
    let node_files = vec![
        NodeFile {
            name: "persons.csv".to_owned(),
            label: Label::Person.name().to_owned(),
            csv: person_csv,
            rows: config.persons,
        },
        NodeFile {
            name: "forums.csv".to_owned(),
            label: Label::Forum.name().to_owned(),
            csv: forum_csv,
            rows: config.forums,
        },
        NodeFile {
            name: "posts.csv".to_owned(),
            label: Label::Post.name().to_owned(),
            csv: post_csv,
            rows: post_count,
        },
        NodeFile {
            name: "comments.csv".to_owned(),
            label: Label::Comment.name().to_owned(),
            csv: comment_csv,
            rows: comment_count,
        },
    ];

    let rel_files = vec![
        RelFile {
            name: "knows.csv".to_owned(),
            rel_type: "KNOWS".to_owned(),
            csv: knows_csv,
            rows: knows_rows,
        },
        RelFile {
            name: "has_member.csv".to_owned(),
            rel_type: "HAS_MEMBER".to_owned(),
            csv: member_csv,
            rows: member_rows,
        },
        RelFile {
            name: "container_of.csv".to_owned(),
            rel_type: "CONTAINER_OF".to_owned(),
            csv: container_csv,
            rows: container_rows,
        },
        RelFile {
            name: "has_creator.csv".to_owned(),
            rel_type: "HAS_CREATOR".to_owned(),
            csv: creator_csv,
            rows: creator_rows,
        },
        RelFile {
            name: "reply_of.csv".to_owned(),
            rel_type: "REPLY_OF".to_owned(),
            csv: reply_csv,
            rows: reply_rows,
        },
        RelFile {
            name: "likes.csv".to_owned(),
            rel_type: "LIKES".to_owned(),
            csv: likes_csv,
            rows: likes_rows,
        },
    ];

    // ===== Manifest ==============================================================================
    let nodes_by_label: Vec<(String, u64)> = node_files
        .iter()
        .map(|n| (n.label.clone(), n.rows))
        .collect();
    let relationships_by_type: Vec<(String, u64)> = rel_files
        .iter()
        .map(|r| (r.rel_type.clone(), r.rows))
        .collect();
    let total_nodes: u64 = nodes_by_label.iter().map(|(_, c)| c).sum();
    let total_relationships: u64 = relationships_by_type.iter().map(|(_, c)| c).sum();
    let logical_csv_bytes: u64 = node_files
        .iter()
        .map(|n| n.csv.len() as u64)
        .chain(rel_files.iter().map(|r| r.csv.len() as u64))
        .sum();

    let implied_constraints = vec![
        "CREATE CONSTRAINT person_id FOR (n:Person) REQUIRE n.id IS UNIQUE".to_owned(),
        "CREATE CONSTRAINT forum_id FOR (n:Forum) REQUIRE n.id IS UNIQUE".to_owned(),
        "CREATE CONSTRAINT post_id FOR (n:Post) REQUIRE n.id IS UNIQUE".to_owned(),
        "CREATE CONSTRAINT comment_id FOR (n:Comment) REQUIRE n.id IS UNIQUE".to_owned(),
    ];

    let manifest = Manifest {
        profile: profile.to_owned(),
        config,
        nodes_by_label,
        relationships_by_type,
        total_nodes,
        total_relationships,
        total_properties: props,
        logical_csv_bytes,
        implied_constraints,
    };

    Dataset {
        config,
        profile: profile.to_owned(),
        manifest,
        node_files,
        rel_files,
    }
}

impl Dataset {
    /// Serializes the [`Manifest`] as pretty JSON (deterministic key order via struct field order).
    ///
    /// # Errors
    /// Returns a `serde_json` error only if serialization fails (it cannot for this plain data).
    pub fn manifest_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(&self.manifest)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn splitmix_is_deterministic() {
        let mut a = SplitMix64::new(123);
        let mut b = SplitMix64::new(123);
        for _ in 0..1000 {
            assert_eq!(a.next_u64(), b.next_u64());
        }
    }

    #[test]
    fn fast_profile_byte_identical_per_seed() {
        let cfg = Profile::Fast.config();
        let d1 = generate(cfg, "fast");
        let d2 = generate(cfg, "fast");
        for (a, b) in d1.node_files.iter().zip(&d2.node_files) {
            assert_eq!(a.csv, b.csv, "node file {} diverged", a.name);
        }
        for (a, b) in d1.rel_files.iter().zip(&d2.rel_files) {
            assert_eq!(a.csv, b.csv, "rel file {} diverged", a.name);
        }
        assert_eq!(d1.manifest_json().unwrap(), d2.manifest_json().unwrap());
    }

    #[test]
    fn manifest_counts_match_config() {
        let cfg = Profile::Fast.config();
        let d = generate(cfg, "fast");
        let m = &d.manifest;
        // Node counts are exact functions of the config.
        assert_eq!(
            m.total_nodes,
            cfg.persons + cfg.forums + cfg.post_count() + cfg.comment_count()
        );
        // Forum/post/comment-derived rel counts are exact.
        let container = cfg.post_count();
        let creator = cfg.post_count() + cfg.comment_count();
        let reply = cfg.comment_count();
        let member = cfg.forums * cfg.members_per_forum;
        let likes = cfg.persons * cfg.likes_per_person;
        // KNOWS is best-effort distinct (self-loops skipped), so it is <= the upper bound.
        let knows_upper = cfg.persons * cfg.knows_per_person;
        let by: std::collections::BTreeMap<_, _> =
            m.relationships_by_type.iter().cloned().collect();
        assert_eq!(by["CONTAINER_OF"], container);
        assert_eq!(by["HAS_CREATOR"], creator);
        assert_eq!(by["REPLY_OF"], reply);
        assert_eq!(by["HAS_MEMBER"], member);
        assert_eq!(by["LIKES"], likes);
        assert!(by["KNOWS"] <= knows_upper);
        // total_relationships is the sum of the per-type rows.
        let sum: u64 = m.relationships_by_type.iter().map(|(_, c)| c).sum();
        assert_eq!(m.total_relationships, sum);
    }

    #[test]
    fn every_external_id_is_globally_unique() {
        let cfg = Profile::Fast.config();
        let d = generate(cfg, "fast");
        let mut ids = std::collections::HashSet::new();
        for nf in &d.node_files {
            for line in nf.csv.lines().skip(1) {
                let id = line.split(',').next().unwrap();
                assert!(ids.insert(id.to_owned()), "duplicate external :ID {id}");
            }
        }
        // One id per node, all distinct (the strict-duplicate-policy precondition).
        assert_eq!(ids.len() as u64, d.manifest.total_nodes);
    }

    #[test]
    fn total_properties_counts_only_nonempty_cells() {
        let cfg = Profile::Fast.config();
        let d = generate(cfg, "fast");
        // The generator never emits an empty optional cell, so total_properties equals the count of
        // typed value columns across every emitted row. Verify it matches a manual count of node
        // property columns + one property per relationship.
        let node_props: u64 = 7 * cfg.persons        // Person: 6 scalar + 1 array
            + 2 * cfg.forums                          // Forum
            + 4 * cfg.post_count()                    // Post
            + 3 * cfg.comment_count(); // Comment
        let rel_props: u64 = d.manifest.total_relationships; // exactly one property per rel
        assert_eq!(d.manifest.total_properties, node_props + rel_props);
    }

    #[test]
    fn different_profiles_differ() {
        let fast = generate(Profile::Fast.config(), "fast");
        let large = generate(Profile::Large.config(), "large");
        assert!(large.manifest.total_nodes > fast.manifest.total_nodes);
    }

    #[test]
    fn seed_changes_output() {
        let mut cfg = Profile::Fast.config();
        let a = generate(cfg, "fast");
        cfg.seed ^= 0xFFFF_FFFF;
        let b = generate(cfg, "fast");
        assert_ne!(
            a.node_files[0].csv, b.node_files[0].csv,
            "a different seed must change the person table"
        );
    }
}
