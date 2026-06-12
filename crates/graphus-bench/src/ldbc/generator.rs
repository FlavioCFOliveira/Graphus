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
//! # Determinism, and why it is the *substitute for official validation*
//!
//! All randomness comes from a tiny SplitMix64 PRNG seeded from the scale factor, so a given
//! [`ScaleFactor`] always yields the byte-identical graph. That keeps the benchmark reproducible and
//! its query result counts stable across runs.
//!
//! Crucially, this determinism is also the foundation of the **offline correctness harness**
//! ([`crate::ldbc::correctness`]). The official LDBC validation compares an engine's answers against
//! an *audited* result set computed from the official dataset; that dataset and its validation
//! parameters are not available offline. We substitute a *self-consistent* validation: because the
//! graph is generated deterministically, the entire structure is also captured — without touching
//! Cypher — in a pure-Rust [`SnbModel`]. Each benchmark operation then has a Rust function that
//! computes its **expected** answer directly from that model, and the correctness test asserts the
//! real engine's Cypher answer equals it. The model and the loaded graph cannot drift because
//! [`generate`] *emits the loader's Cypher from the very same model* it returns — there is one source
//! of structure, used both to load the engine and to compute ground truth.
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
    /// the engine has no property index yet, so each `MATCH (:Person {id: x})` is an O(persons) label
    /// scan: the load is ~O(persons² · knows). 60 persons keeps that tractable while still
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

    /// A micro scale (~24 persons) used by the self-checking correctness test, so it runs in a few
    /// seconds even under the unoptimized test build despite the O(persons²) id-keyed load. Still
    /// fully connected (every person has friends, posts have authors, comments reply to posts), so it
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

/// A `Post` in the structural model: its stable `id`, its containing forum, its author, and its view
/// count. Captured exactly as the generator drew them.
#[derive(Debug, Clone, Copy)]
pub struct Post {
    pub id: u64,
    pub forum: u64,
    pub author: u64,
    pub views: u64,
}

/// A `Comment` in the structural model: its stable `id`, the post it replies to, and its author.
#[derive(Debug, Clone, Copy)]
pub struct Comment {
    pub id: u64,
    pub post: u64,
    pub author: u64,
}

/// The **pure-Rust structural model** of the generated graph — the offline ground-truth oracle.
///
/// This is the single source of the graph's structure: [`generate`] builds one of these by running
/// the deterministic PRNG, then emits the loader's Cypher *from this model*, so the engine's graph
/// and this model are guaranteed identical. The [`crate::ldbc::correctness`] harness queries the
/// methods here to compute each operation's expected answer **without** running Cypher, which is the
/// offline substitute for the official audited validation set (see the module docs).
///
/// All collections are kept in a deterministic order (insertion order, matching the generator's
/// loops), and the adjacency is the *symmetric* `KNOWS` neighbour set per person (the generator
/// creates both directed edges of each friendship).
#[derive(Debug, Clone, Default)]
pub struct SnbModel {
    /// `persons[i]` describes person `i`; `id == i` by construction. Each entry holds `(name, age)`.
    persons: Vec<(String, u64)>,
    /// `knows[i]` is the **sorted, de-duplicated** set of person ids that person `i` directly knows
    /// (the symmetric `KNOWS` neighbour set). A friendship `(a, b)` puts `b` in `knows[a]` and `a` in
    /// `knows[b]`, mirroring the two directed edges the generator creates.
    knows: Vec<Vec<u64>>,
    /// Forum ids `0..forums`; each `forums[f]` holds the forum title.
    forums: Vec<String>,
    /// Posts in creation order (post id == index).
    posts: Vec<Post>,
    /// Comments in creation order (comment id == index).
    comments: Vec<Comment>,
}

impl SnbModel {
    /// The number of `Person` nodes.
    #[must_use]
    pub fn persons(&self) -> u64 {
        self.persons.len() as u64
    }

    /// The number of `Forum` nodes.
    #[must_use]
    pub fn forums(&self) -> u64 {
        self.forums.len() as u64
    }

    /// The number of `Post` nodes.
    #[must_use]
    pub fn post_count(&self) -> u64 {
        self.posts.len() as u64
    }

    /// The number of `Comment` nodes.
    #[must_use]
    pub fn comment_count(&self) -> u64 {
        self.comments.len() as u64
    }

    /// The `(name, age)` of person `id`, if it exists.
    #[must_use]
    pub fn person(&self, id: u64) -> Option<&(String, u64)> {
        self.persons.get(id as usize)
    }

    /// The sorted, de-duplicated direct `KNOWS` neighbours of person `id` (empty if out of range).
    #[must_use]
    pub fn friends(&self, id: u64) -> &[u64] {
        self.knows.get(id as usize).map_or(&[], Vec::as_slice)
    }

    /// All posts, in creation order.
    #[must_use]
    pub fn posts(&self) -> &[Post] {
        &self.posts
    }

    /// All comments, in creation order.
    #[must_use]
    pub fn comments(&self) -> &[Comment] {
        &self.comments
    }

    /// The title of forum `id`, if it exists.
    #[must_use]
    pub fn forum_title(&self, id: u64) -> Option<&str> {
        self.forums.get(id as usize).map(String::as_str)
    }

    /// The [`GraphStats`] this model corresponds to (counts only; `load_txns` is filled by the
    /// loader, since it depends on batching, not structure).
    #[must_use]
    fn stats(&self) -> GraphStats {
        let knows_edges = self.knows.iter().map(|n| n.len() as u64).sum();
        GraphStats {
            persons: self.persons(),
            knows_edges,
            forums: self.forums(),
            posts: self.post_count(),
            comments: self.comment_count(),
            load_txns: 0,
        }
    }
}

/// Builds the deterministic structural model for `sf` — the same PRNG, in the same draw order, that
/// [`generate`] uses to emit the loader's Cypher. This is the **single point** where the graph's
/// shape is decided; both the engine load and the ground-truth oracle derive from it, so they cannot
/// disagree.
///
/// The draw order is load-bearing for determinism and must mirror [`generate`] exactly:
///   1. `Person` ids `0..persons` (names/ages are pure functions of the id — no PRNG draw).
///   2. For each person `a`, `knows_per_person` partner draws (`rng.below(persons)`), self-loops and
///      duplicates skipped via a `seen` set keyed on the unordered pair.
///   3. `Forum` ids `0..forums` (titles are pure functions of the id — no PRNG draw).
///   4. For each forum, for each of `posts_per_forum` posts: a `views` draw then an `author` draw.
///   5. For each of `total_posts * comments_per_post` comments: a `post` draw then an `author` draw.
#[must_use]
pub fn build_model(sf: ScaleFactor) -> SnbModel {
    let mut rng = SplitMix64::new(0x1DBC_5EED_u64.wrapping_add(sf.persons));
    let mut model = SnbModel {
        persons: Vec::with_capacity(sf.persons as usize),
        knows: vec![Vec::new(); sf.persons as usize],
        forums: Vec::with_capacity(sf.forums as usize),
        posts: Vec::new(),
        comments: Vec::new(),
    };

    // -- 1. Person nodes -------------------------------------------------------------------------
    for pid in 0..sf.persons {
        model.persons.push((person_name(pid), 18 + (pid % 60)));
    }

    // -- 2. KNOWS edges (symmetric, de-duplicated) -----------------------------------------------
    {
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
                model.knows[a as usize].push(bp);
                model.knows[bp as usize].push(a);
            }
        }
        // Keep each neighbour set sorted + de-duplicated so the model's `friends()` is canonical
        // (the dedup set above already prevents duplicate friendships, but sorting makes ground-truth
        // ordering match `ORDER BY` queries without re-sorting at every call site).
        for nbrs in &mut model.knows {
            nbrs.sort_unstable();
            nbrs.dedup();
        }
    }

    // -- 3. Forums, then their Posts (with views + author) ---------------------------------------
    for fid in 0..sf.forums {
        model.forums.push(format!("Forum-{fid}"));
    }
    let mut next_post_id = 0u64;
    for fid in 0..sf.forums {
        for _ in 0..sf.posts_per_forum {
            let post_id = next_post_id;
            next_post_id += 1;
            let views = rng.below(10_000);
            let author = rng.below(sf.persons);
            model.posts.push(Post {
                id: post_id,
                forum: fid,
                author,
                views,
            });
        }
    }

    // -- 4. Comments (reply to a post, with an author) -------------------------------------------
    //     The comment id is the creation index; the `post`/`author` draws happen in that index order
    //     (load-bearing for determinism — see the draw-order contract above).
    let total_posts = next_post_id;
    if total_posts > 0 {
        for comment_id in 0..(total_posts * sf.comments_per_post) {
            let post = rng.below(total_posts);
            let author = rng.below(sf.persons);
            model.comments.push(Comment {
                id: comment_id,
                post,
                author,
            });
        }
    }

    model
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
/// batches through the real engine pipeline. Returns the [`SnbModel`] (the ground-truth oracle) and
/// the realized [`GraphStats`].
///
/// The graph is built from a single deterministic [`SnbModel`] (see [`build_model`]); the loader
/// emits Cypher *from that model*, so the engine's graph and the returned model are identical by
/// construction. The build proceeds in dependency order so every relationship's endpoints are matched
/// by a stable `id` property:
///   1. `Person` nodes (with `id`/`name`/`age`).
///   2. `KNOWS` edges between persons (the model's symmetric neighbour sets, each friendship once).
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
pub fn generate(coord: &mut Coord, sf: ScaleFactor) -> Result<(SnbModel, GraphStats), RunError> {
    let model = build_model(sf);
    let mut stats = model.stats();

    // -- 1. Person nodes (batched bare CREATEs) --------------------------------------------------
    {
        let mut b = Batcher::new(coord, sf.batch);
        for (pid, (name, age)) in model.persons.iter().enumerate() {
            b.push(format!(
                "(:Person {{id: {pid}, name: '{name}', age: {age}}})"
            ))?;
        }
        b.flush()?;
        stats.load_txns += b.txns;
    }

    // -- 2. KNOWS edges (symmetric). Emit each friendship once, creating both directed edges. ----
    //    Each friendship `(a, b)` with `a < b` is emitted exactly once (the model's neighbour sets
    //    are symmetric, so we walk only the `a < b` half to avoid double-creation).
    {
        for a in 0..model.persons() {
            for &b in model.friends(a) {
                if a < b {
                    run_write(
                        coord,
                        &format!(
                            "MATCH (a:Person {{id: {a}}}), (b:Person {{id: {b}}}) \
                             CREATE (a)-[:KNOWS]->(b), (b)-[:KNOWS]->(a)"
                        ),
                    )?;
                    stats.load_txns += 1;
                }
            }
        }
    }

    // -- 3. Forum nodes, then each Post wired to its forum + author -------------------------------
    {
        let mut b = Batcher::new(coord, sf.batch);
        for (fid, title) in model.forums.iter().enumerate() {
            b.push(format!("(:Forum {{id: {fid}, title: '{title}'}})"))?;
        }
        b.flush()?;
        stats.load_txns += b.txns;
    }
    for post in model.posts() {
        let Post {
            id,
            forum,
            author,
            views,
        } = *post;
        run_write(
            coord,
            &format!(
                "MATCH (f:Forum {{id: {forum}}}), (a:Person {{id: {author}}}) \
                 CREATE (p:Post {{id: {id}, views: {views}}}), \
                        (f)-[:CONTAINER_OF]->(p), (p)-[:HAS_CREATOR]->(a)"
            ),
        )?;
        stats.load_txns += 1;
    }

    // -- 4. Comments: each replies to a post and has an author ------------------------------------
    for comment in model.comments() {
        let Comment { id, post, author } = *comment;
        run_write(
            coord,
            &format!(
                "MATCH (p:Post {{id: {post}}}), (a:Person {{id: {author}}}) \
                 CREATE (c:Comment {{id: {id}}}), \
                        (c)-[:REPLY_OF]->(p), (c)-[:HAS_CREATOR]->(a)"
            ),
        )?;
        stats.load_txns += 1;
    }

    Ok((model, stats))
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
