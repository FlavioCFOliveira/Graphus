//! The SNB-*flavoured* operation catalog: a handful of representative Interactive-style read queries
//! plus one short write, each expressed in the Cypher subset the Graphus engine currently supports
//! (simple `MATCH`/label-scan/expand/`WHERE`/aggregate/`CREATE` — **no** path functions, variable-
//! length patterns, `OPTIONAL MATCH`, `UNWIND`, comprehensions, or temporal types, which the young
//! engine does not yet support; see `LDBC.md` for the mapping to the official IC/IS queries and
//! which are deferred).
//!
//! Each [`Operation`] carries a stable id, a human label, the parametric Cypher template, and a
//! closure that produces concrete parameter *bindings* (as inline literals) for one invocation given
//! the graph scale — so the harness can drive many invocations with varying anchors. The harness
//! runs each operation, records latency, and reports throughput; an operation whose query the engine
//! rejects is reported as **deferred** rather than failing the run.

use crate::ldbc::generator::GraphStats;

/// One benchmarkable operation.
pub struct Operation {
    /// A short stable identifier, e.g. `"IS3-friends"`.
    pub id: &'static str,
    /// A one-line human description.
    pub label: &'static str,
    /// Which official SNB query (family) inspired it, for the provenance table in the report.
    pub inspired_by: &'static str,
    /// Whether this operation mutates the graph (so the harness can separate read vs write
    /// throughput and run writes against a disposable coordinator if desired).
    pub is_write: bool,
    /// Builds the concrete Cypher for invocation `i` given the graph stats. Returns a fully-inlined
    /// statement (parameters substituted as literals) so it goes straight through the pipeline.
    pub build: fn(i: u64, stats: &GraphStats) -> String,
}

/// The full catalog of SNB-flavoured operations the harness exercises.
#[must_use]
pub fn catalog() -> Vec<Operation> {
    vec![
        // --- IS1-style: profile lookup by person id (point read + projection) -------------------
        Operation {
            id: "IS1-profile",
            label: "Person profile by id (point lookup + projection)",
            inspired_by: "IS1 (ProfileOfPerson)",
            is_write: false,
            build: |i, s| {
                let pid = pick(i, s.persons);
                format!("MATCH (p:Person {{id: {pid}}}) RETURN p.name AS name, p.age AS age")
            },
        },
        // --- IS3-style: a person's friends (one-hop expand over KNOWS) --------------------------
        Operation {
            id: "IS3-friends",
            label: "Friends of a person (1-hop KNOWS expand)",
            inspired_by: "IS3 (FriendsOfPerson)",
            is_write: false,
            build: |i, s| {
                let pid = pick(i, s.persons);
                format!(
                    "MATCH (p:Person {{id: {pid}}})-[:KNOWS]->(f:Person) \
                     RETURN f.id AS fid, f.name AS fname ORDER BY fid ASC"
                )
            },
        },
        // --- IC-style friends-of-friends: two-hop expand (the canonical SNB traversal) ----------
        Operation {
            id: "IC-fof",
            label: "Friends-of-friends (2-hop KNOWS expand)",
            inspired_by: "IC1/IC2 (k-hop friendship neighbourhood)",
            is_write: false,
            build: |i, s| {
                let pid = pick(i, s.persons);
                format!(
                    "MATCH (p:Person {{id: {pid}}})-[:KNOWS]->(:Person)-[:KNOWS]->(fof:Person) \
                     RETURN fof.id AS id ORDER BY id ASC"
                )
            },
        },
        // --- IS2-style: recent posts/comments by a person (author expand) -----------------------
        Operation {
            id: "IS2-authored",
            label: "Posts authored by a person (incoming HAS_CREATOR)",
            inspired_by: "IS2 (RecentMessagesOfPerson)",
            is_write: false,
            build: |i, s| {
                let pid = pick(i, s.persons);
                format!(
                    "MATCH (msg)-[:HAS_CREATOR]->(p:Person {{id: {pid}}}) \
                     RETURN msg.id AS mid ORDER BY mid ASC"
                )
            },
        },
        // --- Label scan + aggregation: count + average age over all persons ---------------------
        Operation {
            id: "AGG-persons",
            label: "Aggregate over all persons (label scan + count/avg)",
            inspired_by: "BI-style population aggregate",
            is_write: false,
            build: |_i, _s| {
                "MATCH (p:Person) RETURN count(*) AS people, avg(p.age) AS avg_age, \
                 max(p.age) AS oldest"
                    .to_owned()
            },
        },
        // --- Filtered scan: posts above a view threshold (scan + WHERE + count) -----------------
        Operation {
            id: "FILTER-posts",
            label: "Popular posts (scan + WHERE views > t + count)",
            inspired_by: "BI popularity filter",
            is_write: false,
            build: |i, _s| {
                // Vary the threshold a little per invocation so it is not constant-folded away.
                let threshold = 5_000 + (i % 5) * 500;
                format!("MATCH (p:Post) WHERE p.views > {threshold} RETURN count(*) AS popular")
            },
        },
        // --- Degree: a forum's post count (expand + count), an IC-style structural metric -------
        Operation {
            id: "DEG-forum",
            label: "Forum post count (CONTAINER_OF expand + count)",
            inspired_by: "IC structural degree",
            is_write: false,
            build: |i, s| {
                let fid = pick(i, s.forums.max(1));
                format!(
                    "MATCH (f:Forum {{id: {fid}}})-[:CONTAINER_OF]->(p:Post) \
                     RETURN count(p) AS posts"
                )
            },
        },
        // --- IU-style insert: add a Comment replying to a post, by an author (short write) ------
        Operation {
            id: "IU-comment",
            label: "Insert a comment on a post (short write transaction)",
            inspired_by: "IU (insert) / IS short write",
            is_write: true,
            build: |i, s| {
                // Synthetic ids well above the generated range so inserts never collide.
                let comment_id = 1_000_000 + i;
                let post = pick(i, (s.posts).max(1));
                let author = pick(i.wrapping_mul(2654435761), s.persons);
                format!(
                    "MATCH (p:Post {{id: {post}}}), (a:Person {{id: {author}}}) \
                     CREATE (c:Comment {{id: {comment_id}}}), \
                            (c)-[:REPLY_OF]->(p), (c)-[:HAS_CREATOR]->(a)"
                )
            },
        },
    ]
}

/// Maps an invocation index to an anchor id in `0..n` with a multiplicative hash, so successive
/// invocations spread across the id space (rather than hammering id 0) without needing a PRNG.
fn pick(i: u64, n: u64) -> u64 {
    if n == 0 {
        return 0;
    }
    i.wrapping_mul(0x9E37_79B9_7F4A_7C15) % n
}
