//! Deterministic, seeded **knowledge-graph generator** for the `examples/knowledge-graph-rest`
//! demonstration, plus a small **analytically-known reference subgraph** the REST discovery workload
//! asserts its query answers against.
//!
//! # The knowledge-graph model
//!
//! A directed Label Property Graph modelling a research **knowledge graph** — documents, the people
//! who wrote them, the concepts they discuss, and the topics they are about:
//!
//! | Node label | Key properties | Meaning |
//! | --- | --- | --- |
//! | `(:Author {id, name, affiliation})` | `id` UNIQUE | a researcher / writer |
//! | `(:Document {id, title, year})` | `id` UNIQUE | a paper / article |
//! | `(:Concept {id, name})` | `id` UNIQUE | a domain concept / term |
//! | `(:Topic {id, name})` | `id` UNIQUE | a broad subject area |
//!
//! Semantic relationships (all directed, typed):
//!
//! | Relationship | Direction | Meaning |
//! | --- | --- | --- |
//! | `:AUTHORED` | `(:Author)->(:Document)` | the author wrote the document |
//! | `:MENTIONS {count}` | `(:Document)->(:Concept)` | the document discusses the concept |
//! | `:CITES` | `(:Document)->(:Document)` | the document cites another document |
//! | `:ABOUT` | `(:Document)->(:Topic)` | the document's broad subject |
//! | `:RELATED_TO {weight}` | `(:Concept)->(:Concept)` | a semantic link between two concepts |
//!
//! Every entity carries a globally-unique string id (`a-<n>`, `d-<n>`, `c-<n>`, `t-<n>`), which the
//! workload declares a `UNIQUE` constraint on so entity lookups are an indexed seek.
//!
//! # The reference subgraph (known discovery-query answers)
//!
//! On top of the benign generated background sits a small, **fixed** reference subgraph whose
//! discovery-query answers are hand-derived and emitted as [`Reference`] (→ `reference.json`). The
//! REST workload runs the same queries over the live server and asserts the answers match exactly.
//! The reference covers the five canonical knowledge-graph discovery patterns:
//!
//! 1. **Entity lookup** — a `:Concept` by its unique id returns its known name.
//! 2. **Multi-hop semantic traversal** — the distinct concepts reachable from a reference author via
//!    `(:Author)-[:AUTHORED]->(:Document)-[:MENTIONS]->(:Concept)` (a 2-hop path).
//! 3. **Recommendation** — documents that share at least one mentioned concept with a seed document
//!    (a co-mention "more like this"), ranked by the number of shared concepts.
//! 4. **Aggregation** — the reference author's document count, and the most-mentioned concept across
//!    the reference documents (a `count` aggregation with a known winner).
//! 5. **Concept path** — the known `:RELATED_TO` chain length between two reference concepts.
//!
//! # Determinism
//!
//! Generation is a pure function of `(seed, scale)`: the only randomness is an internal
//! [`SplitMix64`] PRNG seeded from `seed`. For a given [`GenConfig`] the emitted Cypher script and
//! reference JSON are **byte-identical** across runs, hosts, and platforms (no floats in the graph
//! structure, no `HashMap` iteration, no clock, no thread scheduling). This is asserted by
//! `tests/determinism.rs`. The reference subgraph is anchored at **fixed, low ids** that never
//! collide with the generated background (which uses a disjoint high id range), so the reference
//! answers are identical at every scale.

#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};
use std::fmt::Write as _;

/// A tiny, fast, fully-deterministic PRNG (SplitMix64 — Steele, Lea & Flood 2014). Chosen because it
/// is a *pure* integer mixing function: identical output for identical seeds on every platform, with
/// no global state, no float, and no allocation. We never use the standard library's `HashMap`-based
/// randomness or any clock, so the whole generator is reproducible byte-for-byte.
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

/// The two generation profiles: a small `Fast` graph for CI/E2E assertions, and a larger `Large`
/// graph for evidence collection. Both inject the *same* reference subgraph (at the same fixed ids),
/// so the reference assertions are identical at both scales.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Profile {
    /// Small, fast graph for CI and the REST E2E assertions.
    Fast,
    /// Larger graph for evidence collection (storage/CPU/RAM footprint + NDJSON streaming volume).
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
            // Small but non-trivial: a few hundred documents — enough to make multi-hop traversal,
            // recommendation, and aggregation queries meaningful, yet fast enough for the REST E2E
            // (load + the full discovery suite + an NDJSON stream) to run in a few seconds.
            Self::Fast => GenConfig {
                seed: 0x4B47_5245_5354_0001, // "KGREST\0\1"
                topic_count: 6,
                concept_count: 80,
                author_count: 120,
                document_count: 400,
                concepts_per_document: 4,
                citations_per_document: 3,
                related_per_concept: 2,
            },
            // Several times larger, for evidence + a bigger NDJSON stream. Deliberately bounded so the
            // example completes promptly. The Cypher loader resolves `MATCH (a:Author {id:x})` by a
            // label scan for the edge-creation pattern, so load time grows with nodes×edges; the
            // `large` profile is sized to stay within a few seconds on a developer machine.
            Self::Large => GenConfig {
                seed: 0x4B47_5245_5354_0001,
                topic_count: 10,
                concept_count: 300,
                author_count: 400,
                document_count: 1500,
                concepts_per_document: 5,
                citations_per_document: 4,
                related_per_concept: 3,
            },
        }
    }
}

/// The full set of generation knobs. A [`Dataset`] is a pure function of this struct, so two configs
/// that compare equal produce byte-identical output.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GenConfig {
    /// PRNG seed: the single source of all randomness.
    pub seed: u64,
    /// Number of `:Topic` nodes (broad subject areas).
    pub topic_count: u64,
    /// Number of `:Concept` nodes (domain terms).
    pub concept_count: u64,
    /// Number of `:Author` nodes (researchers).
    pub author_count: u64,
    /// Number of `:Document` nodes (papers).
    pub document_count: u64,
    /// Concepts each document `:MENTIONS` (best-effort distinct).
    pub concepts_per_document: u64,
    /// Documents each document `:CITES` (best-effort distinct, only earlier documents).
    pub citations_per_document: u64,
    /// `:RELATED_TO` edges minted per concept.
    pub related_per_concept: u64,
}

/// A generated author.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Author {
    /// Unique author id (`a-<n>` in Cypher; `n` here).
    pub n: i64,
    /// Display name (`Author <n>`; deterministic).
    pub name: String,
    /// Affiliation, drawn deterministically from a fixed list.
    pub affiliation: String,
}

/// A generated document.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Document {
    /// Unique document ordinal (`d-<n>`).
    pub n: i64,
    /// Title (`Document <n>`; deterministic).
    pub title: String,
    /// Publication year (deterministic, in a fixed range).
    pub year: i64,
    /// The author ordinal that `:AUTHORED` this document.
    pub author: i64,
    /// The topic ordinal this document is `:ABOUT`.
    pub topic: i64,
    /// The concept ordinals this document `:MENTIONS`, each with a mention `count`.
    pub mentions: Vec<(i64, i64)>,
    /// The document ordinals this document `:CITES` (always earlier docs, so the citation graph is a
    /// DAG).
    pub cites: Vec<i64>,
}

/// A generated concept.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Concept {
    /// Unique concept ordinal (`c-<n>`).
    pub n: i64,
    /// Concept name (`concept-<n>`; deterministic).
    pub name: String,
    /// The `:RELATED_TO` concept ordinals (directed), each with a `weight`.
    pub related: Vec<(i64, i64)>,
}

/// A generated topic.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Topic {
    /// Unique topic ordinal (`t-<n>`).
    pub n: i64,
    /// Topic name, drawn from a fixed list.
    pub name: String,
}

/// The analytically-known reference subgraph + the hand-derived answers to the five canonical
/// discovery queries the REST workload runs against the live server.
///
/// All reference ids are **string ids with a `ref-` prefix** (e.g. `ref-c-0`), disjoint from the
/// generated background's `a-`/`d-`/`c-`/`t-` ids, so the reference answers never depend on the
/// background and are identical at every scale.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Reference {
    /// (1) Entity lookup — the id of the reference concept to look up, and...
    pub lookup_concept_id: String,
    /// ...its known `name` (the expected query answer).
    pub lookup_concept_name: String,

    /// (2) Multi-hop traversal — the reference author whose reachable concepts are known...
    pub traversal_author_id: String,
    /// ...and the sorted set of distinct concept ids reachable via
    /// `(:Author {id})-[:AUTHORED]->(:Document)-[:MENTIONS]->(:Concept)`.
    pub traversal_reachable_concept_ids: Vec<String>,

    /// (3) Recommendation — the seed document id...
    pub recommend_seed_document_id: String,
    /// ...and the documents sharing ≥1 mentioned concept with it, as `(document_id, shared_count)`
    /// pairs sorted by `shared_count` DESC then `document_id` ASC (the workload's ORDER BY).
    pub recommend_results: Vec<(String, i64)>,

    /// (4a) Aggregation — the reference author's id...
    pub agg_author_id: String,
    /// ...and the known number of documents they authored in the reference subgraph.
    pub agg_author_document_count: i64,
    /// (4b) Aggregation — the most-mentioned concept id across the reference documents...
    pub agg_top_concept_id: String,
    /// ...and its total mention `count` (the winning aggregate value).
    pub agg_top_concept_total_mentions: i64,

    /// (5) Concept path — the two endpoint concept ids of the known `:RELATED_TO` chain...
    pub path_from_concept_id: String,
    pub path_to_concept_id: String,
    /// ...and the known length (number of `:RELATED_TO` hops) of the shortest path between them.
    pub path_length: i64,
}

/// A fully-materialized dataset: the nodes, the edges, and the reference subgraph. Produced by
/// [`generate`].
#[derive(Debug, Clone)]
pub struct Dataset {
    /// The generation config that produced this dataset.
    pub config: GenConfig,
    /// The profile name.
    pub profile: String,
    /// The topics.
    pub topics: Vec<Topic>,
    /// The concepts.
    pub concepts: Vec<Concept>,
    /// The authors.
    pub authors: Vec<Author>,
    /// The documents.
    pub documents: Vec<Document>,
    /// The analytically-known reference subgraph + its known discovery-query answers.
    pub reference: Reference,
}

/// A small fixed set of affiliations, indexed deterministically.
const AFFILIATIONS: [&str; 6] = [
    "Institute of Graph Science",
    "Database Systems Lab",
    "Centre for Knowledge Engineering",
    "Distributed Computing Group",
    "Semantic Web Institute",
    "Applied Algorithms Lab",
];

/// A small fixed set of topic names, indexed by topic ordinal.
const TOPIC_NAMES: [&str; 10] = [
    "Graph Databases",
    "Information Retrieval",
    "Knowledge Representation",
    "Machine Learning",
    "Distributed Systems",
    "Query Optimization",
    "Natural Language Processing",
    "Data Integration",
    "Semantic Web",
    "Recommender Systems",
];

/// Builds the **reference subgraph** as explicit Cypher and the known query answers.
///
/// The reference subgraph (all ids carry a `ref-` prefix so they never collide with the generated
/// background):
///
/// ```text
///   Author ref-a-0 ("Ada Lovelace")
///     ├─AUTHORED→ Document ref-d-0  ─MENTIONS{3}→ Concept ref-c-0 ("graphs")
///     │                             ─MENTIONS{1}→ Concept ref-c-1 ("indexing")
///     │                             ─ABOUT→       Topic   ref-t-0
///     └─AUTHORED→ Document ref-d-1  ─MENTIONS{2}→ Concept ref-c-0 ("graphs")
///                                   ─MENTIONS{5}→ Concept ref-c-2 ("traversal")
///   Document ref-d-2 (by ref-a-1)   ─MENTIONS{1}→ Concept ref-c-0 ("graphs")
///                                   ─MENTIONS{1}→ Concept ref-c-3 ("storage")
///   Citations: ref-d-1 ─CITES→ ref-d-0 ; ref-d-2 ─CITES→ ref-d-0
///   Concept chain: ref-c-0 ─RELATED_TO→ ref-c-1 ─RELATED_TO→ ref-c-2 (─RELATED_TO→ ref-c-3)
/// ```
///
/// # Known answers
///
/// - **(1) Lookup** `ref-c-0` → name `"graphs"`.
/// - **(2) Traversal** from `ref-a-0`: documents `ref-d-0`,`ref-d-1` → concepts
///   `{ref-c-0, ref-c-1, ref-c-2}` (distinct, sorted).
/// - **(3) Recommendation** for seed `ref-d-0` (mentions `ref-c-0, ref-c-1`): `ref-d-1` shares
///   `ref-c-0` (1), `ref-d-2` shares `ref-c-0` (1). Tie on shared_count → ordered by id ASC:
///   `[(ref-d-1, 1), (ref-d-2, 1)]`.
/// - **(4a) Aggregation** `ref-a-0` authored `2` documents.
/// - **(4b) Aggregation** most-mentioned concept across `ref-d-0,ref-d-1,ref-d-2`: `ref-c-0` with
///   total mentions `3 + 2 + 1 = 6` (beats `ref-c-2`'s 5, `ref-c-1`'s 1, `ref-c-3`'s 1).
/// - **(5) Path** `ref-c-0` → `ref-c-3` along `:RELATED_TO`: `c-0→c-1→c-2→c-3` = `3` hops.
fn reference_cypher() -> (String, Reference) {
    let mut s = String::new();
    s.push_str("// reference subgraph (fixed ids, disjoint from the generated background)\n");

    // Topics.
    s.push_str("CREATE (:Topic {id: 'ref-t-0', name: 'Reference Topic'});\n");

    // Concepts (named).
    let concept_names = [
        ("ref-c-0", "graphs"),
        ("ref-c-1", "indexing"),
        ("ref-c-2", "traversal"),
        ("ref-c-3", "storage"),
    ];
    for (id, name) in concept_names {
        let _ = writeln!(s, "CREATE (:Concept {{id: '{id}', name: '{name}'}});");
    }

    // Authors.
    s.push_str(
        "CREATE (:Author {id: 'ref-a-0', name: 'Ada Lovelace', affiliation: 'Reference Lab'});\n",
    );
    s.push_str(
        "CREATE (:Author {id: 'ref-a-1', name: 'Alan Turing', affiliation: 'Reference Lab'});\n",
    );

    // Documents.
    s.push_str("CREATE (:Document {id: 'ref-d-0', title: 'On Graph Storage', year: 2020});\n");
    s.push_str("CREATE (:Document {id: 'ref-d-1', title: 'Traversal Methods', year: 2021});\n");
    s.push_str("CREATE (:Document {id: 'ref-d-2', title: 'Indexed Graphs', year: 2022});\n");

    // AUTHORED.
    for (a, d) in [
        ("ref-a-0", "ref-d-0"),
        ("ref-a-0", "ref-d-1"),
        ("ref-a-1", "ref-d-2"),
    ] {
        let _ = writeln!(
            s,
            "MATCH (a:Author {{id: '{a}'}}), (d:Document {{id: '{d}'}}) CREATE (a)-[:AUTHORED]->(d);"
        );
    }

    // ABOUT.
    let _ = writeln!(
        s,
        "MATCH (d:Document {{id: 'ref-d-0'}}), (t:Topic {{id: 'ref-t-0'}}) CREATE (d)-[:ABOUT]->(t);"
    );

    // MENTIONS {count}.
    let mentions = [
        ("ref-d-0", "ref-c-0", 3),
        ("ref-d-0", "ref-c-1", 1),
        ("ref-d-1", "ref-c-0", 2),
        ("ref-d-1", "ref-c-2", 5),
        ("ref-d-2", "ref-c-0", 1),
        ("ref-d-2", "ref-c-3", 1),
    ];
    for (d, c, count) in mentions {
        let _ = writeln!(
            s,
            "MATCH (d:Document {{id: '{d}'}}), (c:Concept {{id: '{c}'}}) CREATE (d)-[:MENTIONS {{count: {count}}}]->(c);"
        );
    }

    // CITES.
    for (from, to) in [("ref-d-1", "ref-d-0"), ("ref-d-2", "ref-d-0")] {
        let _ = writeln!(
            s,
            "MATCH (a:Document {{id: '{from}'}}), (b:Document {{id: '{to}'}}) CREATE (a)-[:CITES]->(b);"
        );
    }

    // RELATED_TO chain: c-0 → c-1 → c-2 → c-3.
    let related = [
        ("ref-c-0", "ref-c-1", 9),
        ("ref-c-1", "ref-c-2", 7),
        ("ref-c-2", "ref-c-3", 5),
    ];
    for (from, to, w) in related {
        let _ = writeln!(
            s,
            "MATCH (a:Concept {{id: '{from}'}}), (b:Concept {{id: '{to}'}}) CREATE (a)-[:RELATED_TO {{weight: {w}}}]->(b);"
        );
    }

    let reference = Reference {
        lookup_concept_id: "ref-c-0".to_owned(),
        lookup_concept_name: "graphs".to_owned(),

        traversal_author_id: "ref-a-0".to_owned(),
        // ref-d-0 mentions {c-0, c-1}; ref-d-1 mentions {c-0, c-2} → distinct {c-0, c-1, c-2}.
        traversal_reachable_concept_ids: vec![
            "ref-c-0".to_owned(),
            "ref-c-1".to_owned(),
            "ref-c-2".to_owned(),
        ],

        recommend_seed_document_id: "ref-d-0".to_owned(),
        // ref-d-0 mentions {c-0, c-1}. ref-d-1 shares c-0 (1); ref-d-2 shares c-0 (1). Tie → id ASC.
        recommend_results: vec![("ref-d-1".to_owned(), 1), ("ref-d-2".to_owned(), 1)],

        agg_author_id: "ref-a-0".to_owned(),
        agg_author_document_count: 2,
        agg_top_concept_id: "ref-c-0".to_owned(),
        agg_top_concept_total_mentions: 6, // 3 + 2 + 1

        path_from_concept_id: "ref-c-0".to_owned(),
        path_to_concept_id: "ref-c-3".to_owned(),
        path_length: 3,
    };

    (s, reference)
}

/// Generates a [`Dataset`] from a [`GenConfig`].
///
/// The layout is intentionally ordered so output is byte-stable:
/// 1. topics, then concepts (with their `:RELATED_TO` edges), then authors, then documents (each
///    with its `:AUTHORED`/`:ABOUT`/`:MENTIONS`/`:CITES` edges);
/// 2. all background ids are minted in contiguous ordinal blocks and rendered with a label prefix
///    (`t-`, `c-`, `a-`, `d-`), disjoint from the `ref-`-prefixed reference subgraph;
///
/// so the emitted Cypher and JSON are a deterministic function of the config alone.
#[must_use]
pub fn generate(config: GenConfig, profile: &str) -> Dataset {
    let mut rng = SplitMix64::new(config.seed);

    // Topics.
    let topics: Vec<Topic> = (0..config.topic_count)
        .map(|n| Topic {
            n: n as i64,
            name: TOPIC_NAMES[(n as usize) % TOPIC_NAMES.len()].to_owned(),
        })
        .collect();

    // Concepts + their RELATED_TO edges (to other concepts, best-effort distinct, no self).
    let mut concepts: Vec<Concept> = Vec::with_capacity(config.concept_count as usize);
    for n in 0..config.concept_count {
        let mut related: Vec<(i64, i64)> = Vec::new();
        if config.concept_count >= 2 {
            for _ in 0..config.related_per_concept {
                let target = rng.below(config.concept_count) as i64;
                if target == n as i64 {
                    continue;
                }
                let weight = rng.range_i64(1, 10);
                related.push((target, weight));
            }
        }
        concepts.push(Concept {
            n: n as i64,
            name: format!("concept-{n}"),
            related,
        });
    }

    // Authors.
    let authors: Vec<Author> = (0..config.author_count)
        .map(|n| {
            let affiliation =
                AFFILIATIONS[rng.below(AFFILIATIONS.len() as u64) as usize].to_owned();
            Author {
                n: n as i64,
                name: format!("Author {n}"),
                affiliation,
            }
        })
        .collect();

    // Documents + their AUTHORED/ABOUT/MENTIONS/CITES edges.
    let mut documents: Vec<Document> = Vec::with_capacity(config.document_count as usize);
    for n in 0..config.document_count {
        let author = rng.below(config.author_count.max(1)) as i64;
        let topic = rng.below(config.topic_count.max(1)) as i64;
        let year = rng.range_i64(2000, 2024);

        // MENTIONS: best-effort distinct concepts.
        let mut mentions: Vec<(i64, i64)> = Vec::new();
        if config.concept_count >= 1 {
            for _ in 0..config.concepts_per_document {
                let c = rng.below(config.concept_count) as i64;
                let count = rng.range_i64(1, 9);
                mentions.push((c, count));
            }
        }

        // CITES: only earlier documents (keeps the citation graph acyclic).
        let mut cites: Vec<i64> = Vec::new();
        if n >= 1 {
            for _ in 0..config.citations_per_document {
                let target = rng.below(n) as i64;
                cites.push(target);
            }
        }

        documents.push(Document {
            n: n as i64,
            title: format!("Document {n}"),
            year,
            author,
            topic,
            mentions,
            cites,
        });
    }

    let (_, reference) = reference_cypher();

    Dataset {
        config,
        profile: profile.to_owned(),
        topics,
        concepts,
        authors,
        documents,
        reference,
    }
}

impl Dataset {
    /// Renders the dataset as a deterministic Cypher load script.
    ///
    /// The script is a flat sequence of statements separated by `;\n`, so the loader can split on
    /// `;` and run each as its own auto-commit statement (the schema DDL **must** run in auto-commit,
    /// never inside an explicit transaction — Graphus rejects admin DDL inside an open txn).
    ///
    /// Order: schema DDL → topics → concepts → authors → documents → background edges → reference
    /// subgraph. Every value is a literal (no parameters) so the file is self-contained and
    /// replayable by any client.
    #[must_use]
    pub fn to_cypher(&self) -> String {
        let mut s = String::with_capacity(
            self.documents.len() * 192 + self.concepts.len() * 64 + self.authors.len() * 64,
        );

        // --- Schema (admin DDL — runs as auto-commit statements). Forms verified against the
        // graphus-server admin matcher: `CREATE CONSTRAINT <name> FOR (n:L) REQUIRE n.p IS UNIQUE`
        // and `CREATE INDEX FOR (n:L) ON (n.p)` (no `IF NOT EXISTS`, INDEX takes no name). ---
        s.push_str("// schema — unique id constraints (indexed entity lookup) + a topic index\n");
        s.push_str("CREATE CONSTRAINT author_id_unique FOR (a:Author) REQUIRE a.id IS UNIQUE;\n");
        s.push_str(
            "CREATE CONSTRAINT document_id_unique FOR (d:Document) REQUIRE d.id IS UNIQUE;\n",
        );
        s.push_str("CREATE CONSTRAINT concept_id_unique FOR (c:Concept) REQUIRE c.id IS UNIQUE;\n");
        s.push_str("CREATE CONSTRAINT topic_id_unique FOR (t:Topic) REQUIRE t.id IS UNIQUE;\n");
        s.push_str("CREATE INDEX FOR (d:Document) ON (d.year);\n");

        // --- Topics ---
        s.push_str("// topics\n");
        for t in &self.topics {
            let _ = writeln!(
                s,
                "CREATE (:Topic {{id: 't-{n}', name: '{name}'}});",
                n = t.n,
                name = t.name
            );
        }

        // --- Concepts ---
        s.push_str("// concepts\n");
        for c in &self.concepts {
            let _ = writeln!(
                s,
                "CREATE (:Concept {{id: 'c-{n}', name: '{name}'}});",
                n = c.n,
                name = c.name
            );
        }

        // --- Authors ---
        s.push_str("// authors\n");
        for a in &self.authors {
            let _ = writeln!(
                s,
                "CREATE (:Author {{id: 'a-{n}', name: '{name}', affiliation: '{aff}'}});",
                n = a.n,
                name = a.name,
                aff = a.affiliation
            );
        }

        // --- Documents ---
        s.push_str("// documents\n");
        for d in &self.documents {
            let _ = writeln!(
                s,
                "CREATE (:Document {{id: 'd-{n}', title: '{title}', year: {year}}});",
                n = d.n,
                title = d.title,
                year = d.year
            );
        }

        // --- AUTHORED + ABOUT edges ---
        s.push_str("// authored + about edges\n");
        for d in &self.documents {
            let _ = writeln!(
                s,
                "MATCH (a:Author {{id: 'a-{author}'}}), (d:Document {{id: 'd-{n}'}}) CREATE (a)-[:AUTHORED]->(d);",
                author = d.author,
                n = d.n
            );
            let _ = writeln!(
                s,
                "MATCH (d:Document {{id: 'd-{n}'}}), (t:Topic {{id: 't-{topic}'}}) CREATE (d)-[:ABOUT]->(t);",
                n = d.n,
                topic = d.topic
            );
        }

        // --- MENTIONS edges ---
        s.push_str("// mentions edges\n");
        for d in &self.documents {
            for &(c, count) in &d.mentions {
                let _ = writeln!(
                    s,
                    "MATCH (d:Document {{id: 'd-{n}'}}), (c:Concept {{id: 'c-{c}'}}) CREATE (d)-[:MENTIONS {{count: {count}}}]->(c);",
                    n = d.n
                );
            }
        }

        // --- CITES edges ---
        s.push_str("// cites edges\n");
        for d in &self.documents {
            for &to in &d.cites {
                let _ = writeln!(
                    s,
                    "MATCH (a:Document {{id: 'd-{n}'}}), (b:Document {{id: 'd-{to}'}}) CREATE (a)-[:CITES]->(b);",
                    n = d.n
                );
            }
        }

        // --- RELATED_TO edges ---
        s.push_str("// related_to edges\n");
        for c in &self.concepts {
            for &(target, weight) in &c.related {
                let _ = writeln!(
                    s,
                    "MATCH (a:Concept {{id: 'c-{n}'}}), (b:Concept {{id: 'c-{target}'}}) CREATE (a)-[:RELATED_TO {{weight: {weight}}}]->(b);",
                    n = c.n
                );
            }
        }

        // --- Reference subgraph (fixed ids) ---
        let (ref_cypher, _) = reference_cypher();
        s.push_str(&ref_cypher);

        s
    }

    /// Serializes the reference subgraph + its known answers as pretty JSON (deterministic key order
    /// via the struct field order; `serde_json` preserves struct field order and sorts nothing).
    ///
    /// # Errors
    /// Returns a `serde_json` error only if serialization fails (it cannot for this plain data).
    pub fn reference_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(&self.reference)
    }

    /// The total number of nodes this dataset produces (background + the 10 reference nodes:
    /// 1 topic + 4 concepts + 2 authors + 3 documents).
    #[must_use]
    pub fn node_count(&self) -> usize {
        self.topics.len() + self.concepts.len() + self.authors.len() + self.documents.len() + 10
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
        assert_eq!(
            d1.to_cypher(),
            d2.to_cypher(),
            "cypher must be byte-identical"
        );
        assert_eq!(
            d1.reference_json().unwrap(),
            d2.reference_json().unwrap(),
            "reference must be byte-identical"
        );
    }

    #[test]
    fn citations_are_acyclic_only_earlier_docs() {
        let d = generate(Profile::Fast.config(), "fast");
        for doc in &d.documents {
            for &to in &doc.cites {
                assert!(to < doc.n, "doc {} cites later/self doc {}", doc.n, to);
            }
        }
    }

    #[test]
    fn reference_answers_are_internally_consistent() {
        let d = generate(Profile::Fast.config(), "fast");
        let r = &d.reference;
        // The recommendation tie-break is shared_count DESC then id ASC.
        assert_eq!(
            r.recommend_results,
            vec![("ref-d-1".to_owned(), 1), ("ref-d-2".to_owned(), 1)]
        );
        // Top concept total = 3 (d0) + 2 (d1) + 1 (d2) = 6.
        assert_eq!(r.agg_top_concept_total_mentions, 6);
        // Traversal reachable set is sorted + distinct.
        let mut sorted = r.traversal_reachable_concept_ids.clone();
        sorted.sort();
        sorted.dedup();
        assert_eq!(sorted, r.traversal_reachable_concept_ids);
    }

    #[test]
    fn reference_ids_are_disjoint_from_background() {
        // Every reference id carries the `ref-` prefix; the background never does.
        let cypher = generate(Profile::Fast.config(), "fast").to_cypher();
        assert!(cypher.contains("'ref-c-0'"));
        // Background ids look like 'c-0' (no ref- prefix); ensure such a literal exists too.
        assert!(cypher.contains("'c-0'"));
    }
}
