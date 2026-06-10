//! A small, deterministic, LDBC-SNB-*flavoured* synthetic social graph generator.
//!
//! # Provenance (be honest about what this is)
//!
//! This is **not** the official LDBC SNB data generator (Datagen / Spark) and produces **no**
//! LDBC-conformant CSVs. It is an *inspired, scaled-down* generator that builds a social-network
//! shape — `Person`s linked by `KNOWS`, `Forum`s containing `Post`s, `Post`s and `Comment`s with a
//! `HAS_CREATOR` author and `Comment`s `REPLY_OF` a post — purely so the macro harness has a
//! realistic, connected property graph to run SNB-style read/write operations against. The official
//! benchmark (its exact schema, power-law degree distributions, correlated dimensions, and the
//! Interactive/BI query set) is a far larger artifact; see `crates/graphus-bench/LDBC.md`.
//!
//! # Determinism
//!
//! All randomness comes from a tiny SplitMix64 PRNG seeded from the scale factor, so a given
//! [`ScaleFactor`] always yields the byte-identical graph. That keeps the benchmark reproducible and
//! its query result counts stable across runs (the harness asserts a few of them).
//!
//! # Schema
//!
//! | Label     | Properties                          | Edges                                            |
//! | --------- | ----------------------------------- | ------------------------------------------------ |
//! | `Person`  | `id:int`, `name:string`, `age:int`  | `(:Person)-[:KNOWS]->(:Person)` (symmetric pair) |
//! | `Forum`   | `id:int`, `title:string`            | `(:Forum)-[:CONTAINER_OF]->(:Post)`              |
//! | `Post`    | `id:int`, `views:int`               | `(:Post)-[:HAS_CREATOR]->(:Person)`              |
//! | `Comment` | `id:int`                            | `(:Comment)-[:HAS_CREATOR]->(:Person)`, `(:Comment)-[:REPLY_OF]->(:Post)` |
//!
//! Every value is an inline scalar or a short `String`, all within the engine's stored-property
//! subtype (`05 §7.2`). All `CREATE`s go through the real commit path in batches.

use crate::ldbc::driver::{Coord, RunError, run_write};

/// A SplitMix64 PRNG — tiny, fast, and fully deterministic from its seed. Used only to shape the
/// synthetic graph (which person knows whom, how many posts a forum has); never security-sensitive.
struct SplitMix64(u64);

impl SplitMix64 {
    fn new(seed: u64) -> Self {
        Self(seed)
    }

    fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// A `u64` in `0..n` (`n > 0`).
    fn below(&mut self, n: u64) -> u64 {
        self.next_u64() % n
    }
}

/// The size knob for the synthetic graph. The default is deliberately tiny so the whole harness
/// (generate + run every operation) finishes in a few seconds even under an unoptimized build; the
/// `medium` factor is for an explicit heavier run.
#[derive(Debug, Clone, Copy)]
pub struct ScaleFactor {
    /// Number of `Person` nodes.
    pub persons: u64,
    /// Average outgoing `KNOWS` edges per person (the friendship fan-out).
    pub knows_per_person: u64,
    /// Number of `Forum` nodes.
    pub forums: u64,
    /// Average `Post`s contained per forum.
    pub posts_per_forum: u64,
    /// Average `Comment`s replying to each post.
    pub comments_per_post: u64,
    /// How many CREATE statements to batch into one committed transaction.
    pub batch: u64,
}

impl ScaleFactor {
    /// The default tiny scale — a few seconds in a **release** build (sub-second load), the scale the
    /// `ldbc_snb` binary reports at.
    ///
    /// Sized deliberately small because edge creation matches endpoints by an `id` *property*, and
    /// the engine has no property index yet, so each `MATCH (:Person {id: x})` is an O(persons)
    /// label scan: the load is ~O(persons² · knows). 60 persons keeps that tractable while still
    /// producing a well-connected graph (every person has friends, posts have authors and comments),
    /// which is what the macro harness needs. **Under a debug build this still takes ~1.5 min** — see
    /// [`Self::micro`] for the scale the self-checking test uses. The `--medium` scale (and faster
    /// release builds) push it higher; see `LDBC.md` for the cost characterisation and index follow-up.
    #[must_use]
    pub fn tiny() -> Self {
        Self {
            persons: 60,
            knows_per_person: 4,
            forums: 6,
            posts_per_forum: 6,
            comments_per_post: 2,
            batch: 64,
        }
    }

    /// A micro scale (~24 persons) used by the self-checking unit test, so it runs in a few seconds
    /// even under the unoptimized test build despite the O(persons²) id-keyed load. Still fully
    /// connected (every person has friends, posts have authors, comments reply to posts), so it
    /// exercises every operation — including the 2-hop friends-of-friends traversal — for real.
    #[must_use]
    pub fn micro() -> Self {
        Self {
            persons: 24,
            knows_per_person: 3,
            forums: 3,
            posts_per_forum: 4,
            comments_per_post: 2,
            batch: 32,
        }
    }

    /// A heavier scale for an explicit, longer run (~2k persons). Still well under the storage
    /// single-page-catalog envelope when committed in batches (the harness recreates nothing; this
    /// is for a deliberate, longer measurement on capable hardware).
    #[must_use]
    pub fn medium() -> Self {
        Self {
            persons: 2_000,
            knows_per_person: 10,
            forums: 50,
            posts_per_forum: 20,
            comments_per_post: 4,
            batch: 128,
        }
    }
}

/// Summary statistics of the generated graph — the actual element counts, returned so the harness
/// report can state the realized scale (the *average* knobs above produce these exact totals).
#[derive(Debug, Clone, Default)]
pub struct GraphStats {
    pub persons: u64,
    pub knows_edges: u64,
    pub forums: u64,
    pub posts: u64,
    pub comments: u64,
    /// Total committed write transactions used to build the graph.
    pub load_txns: u64,
}

impl GraphStats {
    /// Total nodes created.
    #[must_use]
    pub fn nodes(&self) -> u64 {
        self.persons + self.forums + self.posts + self.comments
    }

    /// Total relationships created.
    #[must_use]
    pub fn rels(&self) -> u64 {
        // KNOWS + CONTAINER_OF(forum->post) + HAS_CREATOR(post->person) + HAS_CREATOR(comment->person)
        // + REPLY_OF(comment->post).
        self.knows_edges + self.posts + self.posts + self.comments + self.comments
    }
}

/// A simple batch accumulator that flushes `CREATE` statements to the coordinator in `batch`-sized
/// committed transactions, so the data load itself goes through the real group-commit path rather
/// than one giant transaction (which would also blow the single-page catalog envelope).
struct Batcher<'a> {
    coord: &'a mut Coord,
    batch: u64,
    pending: Vec<String>,
    txns: u64,
}

impl<'a> Batcher<'a> {
    fn new(coord: &'a mut Coord, batch: u64) -> Self {
        Self {
            coord,
            batch,
            pending: Vec::new(),
            txns: 0,
        }
    }

    /// Queue one CREATE clause (no trailing semicolon), flushing if the batch is full.
    fn push(&mut self, create_clause: String) -> Result<(), RunError> {
        self.pending.push(create_clause);
        if self.pending.len() as u64 >= self.batch {
            self.flush()?;
        }
        Ok(())
    }

    /// Commit the queued clauses as one transaction: a single `CREATE a, b, c, …` statement so the
    /// whole batch is one commit. Each clause is an independent pattern (its own fresh variables),
    /// which keeps the statement within the engine's comma-separated `CREATE` support.
    fn flush(&mut self) -> Result<(), RunError> {
        if self.pending.is_empty() {
            return Ok(());
        }
        let stmt = format!("CREATE {}", self.pending.join(", "));
        run_write(self.coord, &stmt)?;
        self.txns += 1;
        self.pending.clear();
        Ok(())
    }
}

/// Generates the synthetic social graph into `coord` at the given [`ScaleFactor`], committing it in
/// batches through the real engine pipeline. Returns the realized [`GraphStats`].
///
/// The graph is built in dependency order so every relationship's endpoints are matched by a stable
/// `id` property:
///   1. `Person` nodes (with `id`/`name`/`age`).
///   2. `KNOWS` edges between persons (a deterministic pseudo-random partner set, made symmetric).
///   3. `Forum` nodes, their `Post`s (`CONTAINER_OF`), each post's author (`HAS_CREATOR`).
///   4. `Comment`s replying to posts (`REPLY_OF`), each with an author (`HAS_CREATOR`).
///
/// Edges are created with a `MATCH … MATCH … CREATE` statement keyed on the `id` properties (the
/// engine supports multi-`MATCH` + `CREATE` of a relationship between bound nodes), so the harness
/// never needs the store's physical ids.
///
/// # Errors
/// Propagates the first [`RunError`] from any `CREATE`/`MATCH…CREATE`. A failure here means a
/// generator statement is outside the engine's supported subset and must be simplified — it is a
/// harness bug, not an expected condition.
pub fn generate(coord: &mut Coord, sf: ScaleFactor) -> Result<GraphStats, RunError> {
    // Seed derived from the scale so each scale is byte-reproducible but distinct.
    let mut rng = SplitMix64::new(0x1DBC_5EED_u64.wrapping_add(sf.persons));
    let mut stats = GraphStats::default();

    // -- 1. Person nodes (batched bare CREATEs) --------------------------------------------------
    {
        let mut b = Batcher::new(coord, sf.batch);
        for pid in 0..sf.persons {
            let name = person_name(pid);
            let age = 18 + (pid % 60);
            b.push(format!(
                "(:Person {{id: {pid}, name: '{name}', age: {age}}})"
            ))?;
        }
        b.flush()?;
        stats.persons = sf.persons;
        stats.load_txns += b.txns;
    }

    // -- 2. KNOWS edges (symmetric). Each edge is a MATCH two persons by id + CREATE the rel. -----
    //    Batching edges into one statement is awkward (each needs its own MATCH), so edges are one
    //    statement each but committed in `batch`-sized groups via an explicit transaction is not
    //    available through the single-statement seam here; instead we rely on group commit
    //    amortizing per-statement commits. To keep the load fast we cap KNOWS with a dedup set.
    {
        let mut knows = 0u64;
        let mut seen: std::collections::HashSet<(u64, u64)> = std::collections::HashSet::new();
        for a in 0..sf.persons {
            for _ in 0..sf.knows_per_person {
                let bp = rng.below(sf.persons);
                if bp == a {
                    continue;
                }
                let key = if a < bp { (a, bp) } else { (bp, a) };
                if !seen.insert(key) {
                    continue;
                }
                // Symmetric KNOWS: create both directions so friends-of-friends traversal works
                // regardless of edge direction (LDBC KNOWS is undirected; we model it as a pair).
                run_write(
                    coord,
                    &format!(
                        "MATCH (a:Person {{id: {a}}}), (b:Person {{id: {bp}}}) \
                         CREATE (a)-[:KNOWS]->(b), (b)-[:KNOWS]->(a)"
                    ),
                )?;
                stats.load_txns += 1;
                knows += 2;
            }
        }
        stats.knows_edges = knows;
    }

    // -- 3. Forums, their Posts (CONTAINER_OF), each Post's author (HAS_CREATOR) ------------------
    let mut next_post_id = 0u64;
    {
        // Forum nodes first (batched).
        let mut b = Batcher::new(coord, sf.batch);
        for fid in 0..sf.forums {
            let title = format!("Forum-{fid}");
            b.push(format!("(:Forum {{id: {fid}, title: '{title}'}})"))?;
        }
        b.flush()?;
        stats.forums = sf.forums;
        stats.load_txns += b.txns;
    }
    for fid in 0..sf.forums {
        for _ in 0..sf.posts_per_forum {
            let post_id = next_post_id;
            next_post_id += 1;
            let views = rng.below(10_000);
            let author = rng.below(sf.persons);
            // Create the Post and wire CONTAINER_OF from its forum + HAS_CREATOR to its author. The
            // forum and author already exist, so MATCH them; CREATE the post and both edges.
            run_write(
                coord,
                &format!(
                    "MATCH (f:Forum {{id: {fid}}}), (a:Person {{id: {author}}}) \
                     CREATE (p:Post {{id: {post_id}, views: {views}}}), \
                            (f)-[:CONTAINER_OF]->(p), (p)-[:HAS_CREATOR]->(a)"
                ),
            )?;
            stats.load_txns += 1;
            stats.posts += 1;
        }
    }

    // -- 4. Comments: each replies to a post and has an author -----------------------------------
    let total_posts = next_post_id;
    let mut next_comment_id = 0u64;
    if total_posts > 0 {
        for _ in 0..(total_posts * sf.comments_per_post) {
            let comment_id = next_comment_id;
            next_comment_id += 1;
            let post = rng.below(total_posts);
            let author = rng.below(sf.persons);
            run_write(
                coord,
                &format!(
                    "MATCH (p:Post {{id: {post}}}), (a:Person {{id: {author}}}) \
                     CREATE (c:Comment {{id: {comment_id}}}), \
                            (c)-[:REPLY_OF]->(p), (c)-[:HAS_CREATOR]->(a)"
                ),
            )?;
            stats.load_txns += 1;
            stats.comments += 1;
        }
    }

    Ok(stats)
}

/// A short deterministic display name for a person id (no allocation-heavy faker — just a stable
/// label so `name` is a real `String` property exercising the overflow-heap path for short values).
fn person_name(pid: u64) -> String {
    const FIRST: [&str; 8] = [
        "Ada", "Bjarne", "Carol", "Dijkstra", "Erlang", "Frances", "Grace", "Hopper",
    ];
    let first = FIRST[(pid as usize) % FIRST.len()];
    format!("{first}{pid}")
}
