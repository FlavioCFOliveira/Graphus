//! Deterministic, seeded **influence/citation-network generator** for the `examples/gds-analytics`
//! demonstration, plus a small **analytically-known reference subgraph** the workload asserts the
//! graph-data-science algorithms against.
//!
//! # What it produces
//!
//! A directed, weighted Label Property Graph modelling an academic **influence network**:
//!
//! - `(:Author {id, name, field, h_index})` — a researcher, assigned to one of `community_count`
//!   planted research **fields** (the known community structure).
//! - `(:Author)-[:CITES {weight}]->(:Author)` — a directed **intra-field** citation; `weight` is the
//!   citation count. These are dense (authors mostly cite within their own field).
//! - `(:Author)-[:CROSS {weight}]->(:Author)` — a sparse directed **inter-field** citation, linking
//!   the planted fields into one weakly-connected influence network.
//!
//! Splitting intra-field (`:CITES`) from inter-field (`:CROSS`) edges by **relationship type** is a
//! deliberate, honest design choice: it lets a community-detection projection over **`:CITES` only**
//! recover the planted field blocks exactly via weakly-connected components, while a projection over
//! **both** types sees the fully-linked influence network for PageRank / centrality / shortest paths.
//! This sidesteps a measured limitation of Graphus's synchronous Label Propagation, which has no
//! modularity-resolution parameter and collapses even two dense cliques joined by a single edge into
//! one community (see the example README's "Community detection" note).
//!
//! On top of that benign background sits a small, fixed **reference subgraph** of `(:Ref)` nodes
//! whose PageRank / centrality / connected-component / community / shortest-path results are
//! analytically known (two 3-cliques joined by a single bridge edge — see the `reference_subgraph`
//! constructor),
//! emitted as [`Reference`] (→ `reference.json`) so the workload can assert ground truth within a
//! documented tolerance.
//!
//! # Determinism
//!
//! Generation is a pure function of `(seed, scale)`: the only randomness is an internal
//! [`SplitMix64`] PRNG seeded from `seed`. For a given [`GenConfig`] the emitted Cypher script and
//! reference JSON are **byte-identical** across runs, hosts, and platforms (no floats in the graph
//! structure, no `HashMap` iteration, no clock, no thread scheduling). This is asserted by
//! `tests/determinism.rs`.
//!
//! # Known community structure
//!
//! Authors are partitioned into `community_count` equal-sized fields by construction: author `i`
//! belongs to field `i % community_count` is **not** how it is laid out — instead authors are minted
//! field-by-field in contiguous blocks, so field `f` owns the id range
//! `[f * field_size, (f + 1) * field_size)`. Intra-field citation density is high and inter-field
//! density is low, so a community-detection algorithm (label propagation / WCC on a thresholded
//! projection) recovers the planted blocks. The planted partition is emitted in [`Reference`] for the
//! workload to compare against.

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
/// graph for evidence collection. Both inject the *same* reference subgraph, only the benign
/// influence-network background scales, so the reference assertions are identical at both scales.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Profile {
    /// Small, fast graph for CI and the official-driver E2E assertion.
    Fast,
    /// Larger graph for evidence collection (storage/CPU/RAM footprint at volume).
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
            // Small but non-trivial: a few hundred authors across a handful of fields — enough to
            // make the planted community structure visible, yet fast enough for the official-driver
            // E2E (load + the full algorithm suite) to run in a few seconds.
            Self::Fast => GenConfig {
                seed: 0x06D5_A11C_5000_D001,
                community_count: 4,
                field_size: 40,
                intra_citations_per_author: 6,
                inter_citations_per_author: 1,
            },
            // Several times larger, for evidence: ~600 authors, ~5 k citation edges. Deliberately
            // bounded so the example completes promptly. The Cypher loader issues one `MATCH ... MATCH
            // ... CREATE` per edge, and the engine resolves `MATCH (a:Author {id:x})` by a *label
            // scan* (the unique constraint is not used as an index seek for this pattern — measured at
            // ~345 edges/s over a 1 600-node graph), so load time grows with nodes×edges. The
            // in-process `gds_sweep` separately exercises the GDS algorithms at 4 320-node /
            // 86 k-edge scale, where the projection + algorithms (not the loader) are what is measured.
            Self::Large => GenConfig {
                seed: 0x06D5_A11C_5000_D001,
                community_count: 6,
                field_size: 100,
                intra_citations_per_author: 7,
                inter_citations_per_author: 1,
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
    /// Number of planted research fields (communities).
    pub community_count: u64,
    /// Number of authors per field. Total authors = `community_count * field_size`.
    pub field_size: u64,
    /// Mean number of intra-field (same-community) citations minted per author.
    pub intra_citations_per_author: u64,
    /// Mean number of inter-field (cross-community) citations minted per author.
    pub inter_citations_per_author: u64,
}

impl GenConfig {
    /// The total number of `:Author` nodes the config produces.
    #[must_use]
    pub fn author_count(&self) -> u64 {
        self.community_count * self.field_size
    }
}

/// A generated author (a node in the influence network).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Author {
    /// Unique author id (the workload declares a `UNIQUE` constraint on it).
    pub id: i64,
    /// Display name (`author-<id>`; deterministic).
    pub name: String,
    /// The planted research field (community id) this author belongs to.
    pub field: i64,
    /// A coarse, deterministic h-index proxy in `[0, 100]`.
    pub h_index: i64,
}

/// A generated directed citation edge `from -> to` ("`from` cites `to`").
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Citation {
    /// The citing author id.
    pub from: i64,
    /// The cited author id.
    pub to: i64,
    /// Citation weight (a deterministic citation count in `[1, 10]`).
    pub weight: i64,
    /// Whether this is an **intra**-field citation (`:CITES`, `true`) or an **inter**-field one
    /// (`:CROSS`, `false`). The relationship type is chosen from this flag in [`Dataset::to_cypher`].
    pub intra: bool,
}

/// The analytically-known reference subgraph: two 3-cliques joined by a single bridge edge, plus the
/// known outputs of the graph-data-science algorithms over its **undirected** projection.
///
/// See the `reference_subgraph` constructor for the construction and the proof of each value.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Reference {
    /// The number of planted research fields (communities) in the influence network. A
    /// weakly-connected-components run over the **`:CITES`-only** projection (intra-field edges)
    /// recovers exactly this many components — the planted field blocks.
    pub planted_field_count: i64,
    /// The number of `:Author` nodes in each planted field block (fields are equal-sized and
    /// contiguous: field `f` owns author ids `[f*field_size, (f+1)*field_size)`).
    pub planted_field_size: i64,
    /// The `:Ref` node ids in the subgraph, in construction order (`ref_ids[0]` … `ref_ids[5]`).
    pub ref_ids: Vec<i64>,
    /// The undirected `:LINKS` edges as `(a, b)` id pairs (each emitted once; the projection
    /// symmetrises them).
    pub links: Vec<(i64, i64)>,
    /// The two planted cliques (the reference subgraph's community structure), each a sorted list of
    /// `:Ref` ids. Each clique is a triangle, so a `triangleCount` run gives every node exactly one
    /// triangle, identifying the two dense blocks. (Note: Graphus's synchronous Label Propagation
    /// over-merges this tiny symmetric structure into a single community — the planted **field**
    /// blocks of the influence network are instead recovered via WCC over the `:CITES`-only
    /// projection; see [`Reference::planted_field_count`].)
    pub communities: Vec<Vec<i64>>,
    /// The single weakly-connected component: all six ref ids (the bridge links the cliques).
    pub component: Vec<i64>,
    /// The two **bridge endpoints** — the nodes with the strictly highest betweenness centrality
    /// (every shortest path between the two cliques crosses the bridge, so both endpoints lie on the
    /// most such paths).
    pub top_betweenness_nodes: Vec<i64>,
    /// Per-node degree in the undirected projection, as `(id, degree)` pairs (sorted by id). A
    /// clique-internal node has degree 2; a bridge endpoint has degree 3.
    pub degrees: Vec<(i64, i64)>,
    /// Known unweighted shortest-path distances from `ref_ids[0]` (a clique-A node), as
    /// `(id, distance)` pairs sorted by id. Hand-derived: 0,1,1 within clique A; 2 to the far bridge
    /// endpoint; 3 to the two remaining clique-B nodes.
    pub shortest_paths_from_first: Vec<(i64, i64)>,
}

/// A fully-materialized dataset: the nodes, the edges, the planted communities, and the reference
/// subgraph. Produced by [`generate`].
#[derive(Debug, Clone)]
pub struct Dataset {
    /// The generation config that produced this dataset.
    pub config: GenConfig,
    /// The profile name.
    pub profile: String,
    /// All authors (the influence-network nodes), in id order.
    pub authors: Vec<Author>,
    /// All citation edges.
    pub citations: Vec<Citation>,
    /// The analytically-known reference subgraph + its known algorithm outputs.
    pub reference: Reference,
}

/// Builds the analytically-known reference subgraph, anchored at the id `base` (the first `:Ref` id).
///
/// # Construction
///
/// Six nodes `b+0 … b+5`, two cliques joined by a bridge (all edges **undirected**, emitted once and
/// symmetrised by the projection):
///
/// ```text
///   clique A: (b0)──(b1)──(b2)──(b0)        clique B: (b3)──(b4)──(b5)──(b3)
///                              │   bridge   │
///                             (b2)─────────(b3)
/// ```
///
/// # Known outputs (over the undirected projection)
///
/// - **WCC**: one component `{b0..b5}` (the bridge connects the cliques).
/// - **Communities** (label propagation): `{b0,b1,b2}` and `{b3,b4,b5}` — the two cliques.
/// - **Degree**: `b2` and `b3` have degree 3 (two clique edges + the bridge); the other four have
///   degree 2.
/// - **Betweenness**: `b2` and `b3` are strictly highest — every shortest path from a clique-A node
///   to a clique-B node traverses the `b2─b3` bridge, so both endpoints sit on the maximal number of
///   shortest paths; no clique-internal node lies on any inter-clique shortest path.
/// - **Shortest paths from `b0`** (unweighted): `b0=0, b1=1, b2=1, b3=2, b4=3, b5=3`.
fn reference_subgraph(base: i64, config: &GenConfig) -> Reference {
    let b = |off: i64| base + off;
    let ref_ids: Vec<i64> = (0..6).map(b).collect();

    // Two 3-cliques + one bridge edge. Each undirected edge is emitted ONCE; the projection
    // symmetrises it (undirected orientation).
    let links: Vec<(i64, i64)> = vec![
        // clique A
        (b(0), b(1)),
        (b(1), b(2)),
        (b(0), b(2)),
        // clique B
        (b(3), b(4)),
        (b(4), b(5)),
        (b(3), b(5)),
        // bridge
        (b(2), b(3)),
    ];

    let communities = vec![vec![b(0), b(1), b(2)], vec![b(3), b(4), b(5)]];
    let component = ref_ids.clone();
    // The two bridge endpoints, sorted.
    let top_betweenness_nodes = vec![b(2), b(3)];
    // Degrees: bridge endpoints (b2, b3) have degree 3, the rest degree 2.
    let degrees = vec![
        (b(0), 2),
        (b(1), 2),
        (b(2), 3),
        (b(3), 3),
        (b(4), 2),
        (b(5), 2),
    ];
    // Unweighted shortest paths from b0.
    let shortest_paths_from_first = vec![
        (b(0), 0),
        (b(1), 1),
        (b(2), 1),
        (b(3), 2),
        (b(4), 3),
        (b(5), 3),
    ];

    Reference {
        planted_field_count: config.community_count as i64,
        planted_field_size: config.field_size as i64,
        ref_ids,
        links,
        communities,
        component,
        top_betweenness_nodes,
        degrees,
        shortest_paths_from_first,
    }
}

/// A small fixed set of research-field display names, indexed by field id.
const FIELD_NAMES: [&str; 8] = [
    "graph-theory",
    "databases",
    "machine-learning",
    "distributed-systems",
    "cryptography",
    "compilers",
    "networking",
    "bioinformatics",
];

/// Generates a [`Dataset`] from a [`GenConfig`].
///
/// The layout is intentionally ordered so output is byte-stable:
/// 1. authors are minted field-by-field in contiguous id blocks (`field f` owns
///    `[f*field_size, (f+1)*field_size)`), so the planted communities are contiguous and the
///    reference partition is exact;
/// 2. the six `:Ref` reference-subgraph nodes are minted immediately after the authors;
/// 3. citation edges are minted author-by-author (intra-field first, then inter-field), then the
///    reference `:LINKS` edges,
///
/// so the emitted Cypher and JSON are a deterministic function of the config alone.
#[must_use]
pub fn generate(config: GenConfig, profile: &str) -> Dataset {
    let mut rng = SplitMix64::new(config.seed);

    let author_count = config.author_count();
    let mut authors: Vec<Author> = Vec::with_capacity(author_count as usize);
    let mut citations: Vec<Citation> = Vec::new();

    // 1. Authors, minted field-by-field in contiguous blocks.
    for field in 0..config.community_count {
        for _ in 0..config.field_size {
            let id = authors.len() as i64;
            // A coarse, deterministic h-index. Drawn from the PRNG so it varies, but reproducibly.
            let h_index = rng.range_i64(0, 100);
            authors.push(Author {
                id,
                name: format!("author-{id}"),
                field: field as i64,
                h_index,
            });
        }
    }

    // 2. The reference subgraph is anchored just past the last author id.
    let ref_base = authors.len() as i64;
    let reference = reference_subgraph(ref_base, &config);

    // 3a. Citation edges. For each author, mint a bounded number of intra-field citations (to other
    //     authors in the SAME field block) and a smaller number of inter-field citations (to authors
    //     in OTHER fields). Drawing endpoints from the field blocks keeps the planted community
    //     structure: intra-field density >> inter-field density.
    let cc = config.community_count;
    let fs = config.field_size;
    for a in 0..author_count {
        let field = a / fs; // which contiguous block this author is in
        let field_start = field * fs;

        // Intra-field citations: cite `intra` distinct same-field authors (best-effort distinctness;
        // a rare self/duplicate is skipped, keeping the count an upper bound — documented).
        for _ in 0..config.intra_citations_per_author {
            if fs < 2 {
                break;
            }
            let target = field_start + rng.below(fs);
            if target == a {
                continue; // no self-citation
            }
            let weight = rng.range_i64(1, 10);
            citations.push(Citation {
                from: a as i64,
                to: target as i64,
                weight,
                intra: true,
            });
        }

        // Inter-field citations: cite `inter` authors in a DIFFERENT field.
        for _ in 0..config.inter_citations_per_author {
            if cc < 2 {
                break;
            }
            // Pick a different field, then a random author in it.
            let mut other_field = rng.below(cc);
            if other_field == field {
                other_field = (other_field + 1) % cc;
            }
            let target = other_field * fs + rng.below(fs);
            let weight = rng.range_i64(1, 10);
            citations.push(Citation {
                from: a as i64,
                to: target as i64,
                weight,
                intra: false,
            });
        }
    }

    Dataset {
        config,
        profile: profile.to_owned(),
        authors,
        citations,
        reference,
    }
}

impl Dataset {
    /// The display name of a field id (cycles through [`FIELD_NAMES`] for large field counts).
    fn field_name(field: i64) -> &'static str {
        let idx = (field as usize) % FIELD_NAMES.len();
        FIELD_NAMES[idx]
    }

    /// Renders the dataset as a deterministic Cypher load script.
    ///
    /// The script is a flat sequence of statements separated by `;\n`, so the loader can split on
    /// `;` and run each as its own auto-commit statement (the schema DDL **must** run in auto-commit,
    /// never inside an explicit transaction — Graphus rejects admin DDL inside an open txn).
    ///
    /// Order: schema DDL → authors → `:Ref` nodes → CITES edges → reference `:LINKS` edges. Every
    /// value is a literal (no parameters) so the file is self-contained and replayable by any Bolt
    /// client.
    #[must_use]
    pub fn to_cypher(&self) -> String {
        let mut s = String::with_capacity(self.authors.len() * 96 + self.citations.len() * 96);

        // --- Schema (admin DDL — runs as auto-commit statements). Forms verified against the
        // graphus-server admin matcher: `CREATE CONSTRAINT <name> FOR (n:L) REQUIRE n.p IS UNIQUE`
        // and `CREATE INDEX FOR (n:L) ON (n.p)`. ---
        s.push_str("// schema\n");
        s.push_str("CREATE CONSTRAINT author_id_unique FOR (a:Author) REQUIRE a.id IS UNIQUE;\n");
        s.push_str("CREATE INDEX FOR (a:Author) ON (a.field);\n");

        // --- Authors ---
        s.push_str("// authors\n");
        for a in &self.authors {
            let _ = writeln!(
                s,
                "CREATE (:Author {{id: {}, name: '{}', field: {}, field_name: '{}', h_index: {}}});",
                a.id,
                a.name,
                a.field,
                Self::field_name(a.field),
                a.h_index
            );
        }

        // --- Reference subgraph nodes (:Ref) ---
        s.push_str("// reference subgraph nodes\n");
        for &rid in &self.reference.ref_ids {
            let _ = writeln!(s, "CREATE (:Ref {{id: {rid}}});");
        }

        // --- CITES (intra-field) + CROSS (inter-field) edges (directed, weighted) ---
        s.push_str("// citations (intra-field :CITES, inter-field :CROSS)\n");
        for c in &self.citations {
            let rel_type = if c.intra { "CITES" } else { "CROSS" };
            let _ = writeln!(
                s,
                "MATCH (a:Author {{id: {from}}}), (b:Author {{id: {to}}}) CREATE (a)-[:{rel_type} {{weight: {weight}}}]->(b);",
                from = c.from,
                to = c.to,
                weight = c.weight
            );
        }

        // --- Reference :LINKS edges (undirected in meaning; emitted once, the projection
        // symmetrises). ---
        s.push_str("// reference links\n");
        for &(x, y) in &self.reference.links {
            let _ = writeln!(
                s,
                "MATCH (a:Ref {{id: {x}}}), (b:Ref {{id: {y}}}) CREATE (a)-[:LINKS]->(b);"
            );
        }

        s
    }

    /// Serializes the reference subgraph + its known outputs as pretty JSON (deterministic key order
    /// via the struct field order; `serde_json` preserves struct field order and sorts nothing).
    ///
    /// # Errors
    /// Returns a `serde_json` error only if serialization fails (it cannot for this plain data).
    pub fn reference_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(&self.reference)
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
    fn authors_are_partitioned_into_contiguous_field_blocks() {
        let cfg = Profile::Fast.config();
        let d = generate(cfg, "fast");
        assert_eq!(d.authors.len() as u64, cfg.author_count());
        // Field f owns the id range [f*field_size, (f+1)*field_size).
        for a in &d.authors {
            let expected_field = a.id / cfg.field_size as i64;
            assert_eq!(
                a.field, expected_field,
                "author {} is in the wrong field block",
                a.id
            );
        }
    }

    #[test]
    fn citations_respect_planted_community_density() {
        let cfg = Profile::Fast.config();
        let d = generate(cfg, "fast");
        let fs = cfg.field_size as i64;
        let field_of = |id: i64| id / fs;

        let mut intra = 0u64;
        let mut inter = 0u64;
        for c in &d.citations {
            if field_of(c.from) == field_of(c.to) {
                intra += 1;
            } else {
                inter += 1;
            }
        }
        // Intra-field citations must dominate (the planted community signal), by construction
        // (intra_citations_per_author > inter_citations_per_author).
        assert!(
            intra > inter,
            "intra-field citations ({intra}) must dominate inter-field ({inter})"
        );
    }

    #[test]
    fn reference_subgraph_invariants_hold() {
        let cfg = Profile::Fast.config();
        let d = generate(cfg, "fast");
        let r = &d.reference;

        // Six ref nodes, anchored just past the authors.
        assert_eq!(r.ref_ids.len(), 6);
        assert_eq!(r.ref_ids[0], cfg.author_count() as i64);

        // Two communities of three, partitioning the six nodes.
        assert_eq!(r.communities.len(), 2);
        let mut all: Vec<i64> = r.communities.iter().flatten().copied().collect();
        all.sort_unstable();
        assert_eq!(all, r.ref_ids);

        // One component containing all six.
        assert_eq!(r.component, r.ref_ids);

        // Seven undirected links (3 + 3 + 1 bridge).
        assert_eq!(r.links.len(), 7);

        // The two bridge endpoints are the highest-betweenness nodes (b2, b3).
        assert_eq!(r.top_betweenness_nodes, vec![r.ref_ids[2], r.ref_ids[3]]);

        // Degree sum = 2 * edges = 14.
        let deg_sum: i64 = r.degrees.iter().map(|&(_, d)| d).sum();
        assert_eq!(deg_sum, 14);
        // Bridge endpoints degree 3, the rest degree 2.
        for &(id, deg) in &r.degrees {
            let expected = if id == r.ref_ids[2] || id == r.ref_ids[3] {
                3
            } else {
                2
            };
            assert_eq!(deg, expected, "node {id} has the wrong degree");
        }

        // Shortest paths from b0: 0,1,1,2,3,3.
        let dists: Vec<i64> = r
            .shortest_paths_from_first
            .iter()
            .map(|&(_, d)| d)
            .collect();
        assert_eq!(dists, vec![0, 1, 1, 2, 3, 3]);
    }

    #[test]
    fn different_profiles_differ() {
        let fast = generate(Profile::Fast.config(), "fast");
        let large = generate(Profile::Large.config(), "large");
        assert_ne!(fast.to_cypher(), large.to_cypher());
        assert!(large.authors.len() > fast.authors.len());
    }

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
}
