//! The SNB-*flavoured* operation catalog: a broad, representative slice of the official LDBC SNB
//! Interactive-Short (IS), Interactive-Complex (IC) and Business-Intelligence (BI) query *shapes*,
//! each expressed in the Cypher subset the Graphus engine supports and each paired with an
//! independently-computed **ground-truth** answer.
//!
//! # What each operation carries
//!
//! Every [`Operation`] holds:
//!   * a stable id and human label, plus the official query it is `inspired_by` (e.g. `"IC2
//!     (RecentMessagesByFriends)"`), for the provenance table in the report and the offline-scope
//!     disclosure in `LDBC.md`;
//!   * [`Operation::build`] — a closure producing the fully-inlined Cypher for invocation `i` (so it
//!     goes straight through the real pipeline); and
//!   * [`Operation::expected`] — a closure producing the **expected** result for invocation `i`,
//!     computed directly from the deterministic [`SnbModel`] *without running Cypher*.
//!
//! The correctness harness ([`crate::ldbc::correctness`]) runs `build`'s Cypher through the engine
//! and asserts the rows equal `expected`'s rows. Because the model is the same structure the loader
//! built the engine's graph from, this is a self-consistent verification against known ground truth —
//! the offline substitute for the official audited LDBC validation set.
//!
//! # The "fully ordered" comparison contract
//!
//! Every read operation's Cypher ends in a **total `ORDER BY`** (a tiebreaker on a unique key where
//! needed), and the matching `expected` closure returns rows in that same total order. The harness
//! then compares the two row sequences **positionally** — the strongest possible assertion (it
//! catches a wrong value, a missing row, an extra row, *and* a wrong order). Operations whose natural
//! result is a single scalar/aggregate row need no `ORDER BY`.
//!
//! # Cypher subset
//!
//! The engine supports (verified end-to-end against the real pipeline): `WITH` projection pipelines
//! with aggregation and post-aggregation `WHERE`, `UNWIND`, `OPTIONAL MATCH`, `ORDER BY`/`SKIP`/
//! `LIMIT`, `DISTINCT` (including `count(DISTINCT …)`/`collect(DISTINCT …)`), all standard aggregates
//! and `collect`, **variable-length patterns** (`-[:KNOWS*1..3]->`), `CASE`, list comprehensions,
//! string/math functions, `EXISTS { … }` subqueries, relationship-type disjunction, relationship
//! variables, temporal types, and the write clauses (`CREATE`/`SET`/`MERGE`/`DELETE`). It does **not**
//! support `shortestPath`/`allShortestPaths` or `FOREACH`; operations needing those are documented as
//! deferred in `LDBC.md` (and listed in [`deferred_official_queries`]).

use std::collections::{BTreeMap, HashSet};

use graphus_core::Value;

use crate::ldbc::generator::SnbModel;

/// One column of an expected row: a column name and its expected [`Value`].
pub type ExpectedCell = (&'static str, Value);

/// One expected row — a vector of named cells, in the operation's projected column order.
pub type ExpectedRow = Vec<ExpectedCell>;

/// The full expected result of one operation invocation: the ordered sequence of rows the engine
/// must produce, computed from ground truth.
pub type ExpectedResult = Vec<ExpectedRow>;

/// One benchmarkable, ground-truth-checked operation.
pub struct Operation {
    /// A short stable identifier, e.g. `"IS3-friends"`.
    pub id: &'static str,
    /// A one-line human description.
    pub label: &'static str,
    /// Which official SNB query (family) inspired it, for the provenance table in the report.
    pub inspired_by: &'static str,
    /// Whether this operation mutates the graph (so the harness can separate read vs write
    /// throughput and verify the write's effect with a follow-up read).
    pub is_write: bool,
    /// Builds the concrete Cypher for invocation `i` given the model. Returns a fully-inlined
    /// statement (parameters substituted as literals) so it goes straight through the pipeline.
    pub build: fn(i: u64, model: &SnbModel) -> String,
    /// Computes the **expected** result for invocation `i` from the model, *without* running Cypher.
    /// For a write operation this is the result the harness's *verification read* must return after
    /// the write commits (see [`Operation::verify`]).
    pub expected: fn(i: u64, model: &SnbModel) -> ExpectedResult,
    /// For a write operation only: the read query that observes the write's effect, parameterised by
    /// `i` exactly as `build` was. `None` for read operations. The harness runs `build` (the write),
    /// then runs `verify` (the read) and asserts its rows equal `expected`.
    pub verify: Option<fn(i: u64, model: &SnbModel) -> String>,
}

/// The full catalog of SNB-flavoured, ground-truth-checked operations the harness exercises.
///
/// Breadth target: a representative slice across IS (short reads), IC (complex traversals/aggregates)
/// and BI (business-intelligence aggregates), plus the write path. Every entry runs correctly against
/// the engine at the harness scales; the official queries we cannot express (variable-length shortest
/// paths, temporal `creationDate` filters that need per-message timestamps the synthetic schema omits)
/// are listed in [`deferred_official_queries`].
#[must_use]
pub fn catalog() -> Vec<Operation> {
    vec![
        // ════════════════════════════ Interactive Short (IS) ════════════════════════════════════
        // --- IS1: profile of a person (point lookup + projection) -------------------------------
        Operation {
            id: "IS1-profile",
            label: "Person profile by id (point lookup + projection)",
            inspired_by: "IS1 (ProfileOfPerson)",
            is_write: false,
            build: |i, m| {
                let pid = pick(i, m.persons());
                format!("MATCH (p:Person {{id: {pid}}}) RETURN p.name AS name, p.age AS age")
            },
            expected: |i, m| {
                let pid = pick(i, m.persons());
                match m.person(pid) {
                    Some((name, age)) => vec![vec![
                        ("name", Value::String(name.clone())),
                        ("age", Value::Integer(*age as i64)),
                    ]],
                    None => vec![],
                }
            },
            verify: None,
        },
        // --- IS3: a person's friends (1-hop KNOWS expand) ----------------------------------------
        Operation {
            id: "IS3-friends",
            label: "Friends of a person (1-hop KNOWS expand)",
            inspired_by: "IS3 (FriendsOfPerson)",
            is_write: false,
            build: |i, m| {
                let pid = pick(i, m.persons());
                format!(
                    "MATCH (p:Person {{id: {pid}}})-[:KNOWS]->(f:Person) \
                     RETURN f.id AS fid, f.name AS fname ORDER BY fid ASC"
                )
            },
            expected: |i, m| {
                let pid = pick(i, m.persons());
                m.friends(pid)
                    .iter()
                    .map(|&f| {
                        let name = m.person(f).map(|(n, _)| n.clone()).unwrap_or_default();
                        vec![
                            ("fid", Value::Integer(f as i64)),
                            ("fname", Value::String(name)),
                        ]
                    })
                    .collect()
            },
            verify: None,
        },
        // --- IS2: messages a person authored (incoming HAS_CREATOR over posts + comments) --------
        Operation {
            id: "IS2-authored",
            label: "Messages authored by a person (incoming HAS_CREATOR)",
            inspired_by: "IS2 (RecentMessagesOfPerson)",
            is_write: false,
            build: |i, m| {
                let pid = pick(i, m.persons());
                format!(
                    "MATCH (msg)-[:HAS_CREATOR]->(p:Person {{id: {pid}}}) \
                     RETURN msg.id AS mid ORDER BY mid ASC"
                )
            },
            expected: |i, m| {
                let pid = pick(i, m.persons());
                // A message is any Post or Comment whose author is `pid`. Both carry an `id`; the
                // query orders by that id ascending across the merged set. (Post and Comment id
                // spaces overlap — both start at 0 — so the merged order can interleave equal ids;
                // `ORDER BY mid` with equal keys is order-among-ties-unspecified, so we sort the
                // ground truth the same stable way the engine's scan does: by id, and the harness's
                // comparison tolerates tie order — see `correctness::rows_match`.)
                let mut ids: Vec<i64> = Vec::new();
                ids.extend(
                    m.posts()
                        .iter()
                        .filter(|p| p.author == pid)
                        .map(|p| p.id as i64),
                );
                ids.extend(
                    m.comments()
                        .iter()
                        .filter(|c| c.author == pid)
                        .map(|c| c.id as i64),
                );
                ids.sort_unstable();
                ids.into_iter()
                    .map(|id| vec![("mid", Value::Integer(id))])
                    .collect()
            },
            verify: None,
        },
        // --- IS5: a comment's author (HAS_CREATOR projection) ------------------------------------
        Operation {
            id: "IS5-creator",
            label: "Author of a comment (HAS_CREATOR projection)",
            inspired_by: "IS5 (CreatorOfMessage)",
            is_write: false,
            build: |i, m| {
                let cid = pick(i, m.comment_count().max(1));
                format!(
                    "MATCH (c:Comment {{id: {cid}}})-[:HAS_CREATOR]->(a:Person) \
                     RETURN a.id AS aid, a.name AS aname"
                )
            },
            expected: |i, m| {
                let cid = pick(i, m.comment_count().max(1));
                match m.comments().iter().find(|c| c.id == cid) {
                    Some(c) => {
                        let name = m
                            .person(c.author)
                            .map(|(n, _)| n.clone())
                            .unwrap_or_default();
                        vec![vec![
                            ("aid", Value::Integer(c.author as i64)),
                            ("aname", Value::String(name)),
                        ]]
                    }
                    None => vec![],
                }
            },
            verify: None,
        },
        // --- IS6: the forum a post belongs to (incoming CONTAINER_OF) ----------------------------
        Operation {
            id: "IS6-forum",
            label: "Forum containing a post (incoming CONTAINER_OF)",
            inspired_by: "IS6 (ForumOfMessage)",
            is_write: false,
            build: |i, m| {
                let post = pick(i, m.post_count().max(1));
                format!(
                    "MATCH (f:Forum)-[:CONTAINER_OF]->(p:Post {{id: {post}}}) \
                     RETURN f.id AS fid, f.title AS ftitle"
                )
            },
            expected: |i, m| {
                let post = pick(i, m.post_count().max(1));
                match m.posts().iter().find(|p| p.id == post) {
                    Some(p) => {
                        let title = m.forum_title(p.forum).unwrap_or_default().to_owned();
                        vec![vec![
                            ("fid", Value::Integer(p.forum as i64)),
                            ("ftitle", Value::String(title)),
                        ]]
                    }
                    None => vec![],
                }
            },
            verify: None,
        },
        // ═══════════════════════════ Interactive Complex (IC) ════════════════════════════════════
        // --- IC-fof: friends-of-friends, 2-hop KNOWS expand (the canonical SNB traversal) --------
        //     Semantics matched to the engine (verified empirically): relationship-uniqueness applies
        //     (each KNOWS edge used at most once per 2-path) but nodes may be revisited, so the start
        //     person reappears once per neighbour (`p -e1-> m -e2-> p` via the symmetric reverse edge
        //     `e2 ≠ e1`). The result is the *multiset* of such endpoints, then `DISTINCT`-ed and
        //     ordered, exactly mirroring the official "k-hop neighbourhood" shape.
        Operation {
            id: "IC-fof",
            label: "Friends-of-friends, distinct (2-hop KNOWS expand)",
            inspired_by: "IC1/IC2 (k-hop friendship neighbourhood)",
            is_write: false,
            build: |i, m| {
                let pid = pick(i, m.persons());
                format!(
                    "MATCH (p:Person {{id: {pid}}})-[:KNOWS]->(:Person)-[:KNOWS]->(fof:Person) \
                     RETURN DISTINCT fof.id AS id ORDER BY id ASC"
                )
            },
            expected: |i, m| {
                let pid = pick(i, m.persons());
                let mut set: HashSet<u64> = HashSet::new();
                for &mid in m.friends(pid) {
                    for &f in m.friends(mid) {
                        set.insert(f);
                    }
                }
                let mut ids: Vec<u64> = set.into_iter().collect();
                ids.sort_unstable();
                ids.into_iter()
                    .map(|id| vec![("id", Value::Integer(id as i64))])
                    .collect()
            },
            verify: None,
        },
        // --- IC-fof-strict: friends-of-friends excluding self and direct friends (true 2-hop ring)
        Operation {
            id: "IC-fof-strict",
            label: "Friends-of-friends excluding self + direct friends",
            inspired_by: "IC1 (friends and friends-of-friends, strict ring)",
            is_write: false,
            build: |i, m| {
                let pid = pick(i, m.persons());
                // Exclude the start person and anyone already a direct friend, leaving the strict
                // 2-hop ring — the projection the official IC1 distance bands separate out.
                format!(
                    "MATCH (p:Person {{id: {pid}}})-[:KNOWS]->(:Person)-[:KNOWS]->(fof:Person) \
                     WHERE fof.id <> {pid} AND NOT fof.id IN \
                       [(p)-[:KNOWS]->(d:Person) | d.id] \
                     RETURN DISTINCT fof.id AS id ORDER BY id ASC"
                )
            },
            expected: |i, m| {
                let pid = pick(i, m.persons());
                let direct: HashSet<u64> = m.friends(pid).iter().copied().collect();
                let mut set: HashSet<u64> = HashSet::new();
                for &mid in m.friends(pid) {
                    for &f in m.friends(mid) {
                        if f != pid && !direct.contains(&f) {
                            set.insert(f);
                        }
                    }
                }
                let mut ids: Vec<u64> = set.into_iter().collect();
                ids.sort_unstable();
                ids.into_iter()
                    .map(|id| vec![("id", Value::Integer(id as i64))])
                    .collect()
            },
            verify: None,
        },
        // --- IC2: recent messages by a person's friends (1-hop friends → their authored messages) -
        //     Official IC2: "for a person's friends, their most recent messages." We drop the
        //     date ordering (no per-message timestamp in the synthetic schema — see deferrals) and
        //     keep the structural core: friend → message they authored.
        Operation {
            id: "IC2-friend-msgs",
            label: "Messages authored by a person's friends",
            inspired_by: "IC2 (RecentMessagesByFriends)",
            is_write: false,
            build: |i, m| {
                let pid = pick(i, m.persons());
                format!(
                    "MATCH (p:Person {{id: {pid}}})-[:KNOWS]->(f:Person)<-[:HAS_CREATOR]-(msg) \
                     RETURN f.id AS fid, msg.id AS mid ORDER BY fid ASC, mid ASC"
                )
            },
            expected: |i, m| {
                let pid = pick(i, m.persons());
                let friends: HashSet<u64> = m.friends(pid).iter().copied().collect();
                // For each (friend, message-they-authored) pair, ordered by friend id then message id.
                let mut pairs: Vec<(u64, u64)> = Vec::new();
                for p in m.posts() {
                    if friends.contains(&p.author) {
                        pairs.push((p.author, p.id));
                    }
                }
                for c in m.comments() {
                    if friends.contains(&c.author) {
                        pairs.push((c.author, c.id));
                    }
                }
                pairs.sort_unstable();
                pairs
                    .into_iter()
                    .map(|(fid, mid)| {
                        vec![
                            ("fid", Value::Integer(fid as i64)),
                            ("mid", Value::Integer(mid as i64)),
                        ]
                    })
                    .collect()
            },
            verify: None,
        },
        // --- IC-degree: per-person friend count via OPTIONAL MATCH + WITH (degree centrality) ----
        Operation {
            id: "IC-degree",
            label: "Friend count per person (degree, OPTIONAL MATCH + WITH)",
            inspired_by: "IC-style degree / centrality",
            is_write: false,
            build: |_i, _m| {
                "MATCH (p:Person) OPTIONAL MATCH (p)-[:KNOWS]->(f:Person) \
                 WITH p, count(f) AS deg \
                 RETURN p.id AS id, deg AS degree ORDER BY id ASC"
                    .to_owned()
            },
            expected: |_i, m| {
                (0..m.persons())
                    .map(|p| {
                        vec![
                            ("id", Value::Integer(p as i64)),
                            ("degree", Value::Integer(m.friends(p).len() as i64)),
                        ]
                    })
                    .collect()
            },
            verify: None,
        },
        // --- IC-top-degree: the most-connected people (WITH + post-aggregation ORDER BY + LIMIT) --
        Operation {
            id: "IC-top-degree",
            label: "Top-5 most-connected people (WITH + ORDER BY deg DESC + LIMIT)",
            inspired_by: "IC-style top-N influencers",
            is_write: false,
            build: |_i, _m| {
                "MATCH (p:Person)-[:KNOWS]->(f:Person) \
                 WITH p, count(f) AS deg \
                 RETURN p.id AS id, deg AS degree ORDER BY degree DESC, id ASC LIMIT 5"
                    .to_owned()
            },
            expected: |_i, m| {
                // count(f) over the expand only yields persons with at least one friend (the official
                // top-N over an inner join). Rank by degree desc, id asc; take 5.
                let mut ranked: Vec<(u64, usize)> = (0..m.persons())
                    .map(|p| (p, m.friends(p).len()))
                    .filter(|(_, d)| *d > 0)
                    .collect();
                ranked.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
                ranked
                    .into_iter()
                    .take(5)
                    .map(|(id, deg)| {
                        vec![
                            ("id", Value::Integer(id as i64)),
                            ("degree", Value::Integer(deg as i64)),
                        ]
                    })
                    .collect()
            },
            verify: None,
        },
        // --- IC-mutual: count mutual friends between a person and each friend-of-friend -----------
        Operation {
            id: "IC-common-friends",
            label: "Friends a person shares with each 2-hop contact (mutual-friend count)",
            inspired_by: "IC-style friend recommendation (common connections)",
            is_write: false,
            build: |i, m| {
                let pid = pick(i, m.persons());
                // For the anchor's friends-of-friends, count how many of the anchor's friends they
                // also know — the "people you may know" mutual-connection signal.
                format!(
                    "MATCH (p:Person {{id: {pid}}})-[:KNOWS]->(mid:Person)-[:KNOWS]->(fof:Person) \
                     WHERE fof.id <> {pid} \
                     WITH fof, count(DISTINCT mid) AS mutual \
                     RETURN fof.id AS id, mutual AS mutual ORDER BY mutual DESC, id ASC"
                )
            },
            expected: |i, m| {
                let pid = pick(i, m.persons());
                let direct: Vec<u64> = m.friends(pid).to_vec();
                // For each fof (≠ pid), the number of `pid`'s direct friends that fof also knows.
                // Mirrors `count(DISTINCT mid)` grouped by fof, where mid ranges over the anchor's
                // friends that link to fof.
                let mut mutual: BTreeMap<u64, HashSet<u64>> = BTreeMap::new();
                for &mid in &direct {
                    for &fof in m.friends(mid) {
                        if fof != pid {
                            mutual.entry(fof).or_default().insert(mid);
                        }
                    }
                }
                let mut ranked: Vec<(u64, usize)> =
                    mutual.into_iter().map(|(k, v)| (k, v.len())).collect();
                ranked.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
                ranked
                    .into_iter()
                    .map(|(id, mutual)| {
                        vec![
                            ("id", Value::Integer(id as i64)),
                            ("mutual", Value::Integer(mutual as i64)),
                        ]
                    })
                    .collect()
            },
            verify: None,
        },
        // --- IC-varlen-reach: people reachable within 1..2 hops (bounded variable-length path) ----
        Operation {
            id: "IC-reach-2",
            label: "People reachable within 1..2 KNOWS hops (variable-length path)",
            inspired_by: "IC1/IC13 (bounded-distance reachability)",
            is_write: false,
            build: |i, m| {
                let pid = pick(i, m.persons());
                format!(
                    "MATCH (p:Person {{id: {pid}}})-[:KNOWS*1..2]->(r:Person) \
                     RETURN DISTINCT r.id AS id ORDER BY id ASC"
                )
            },
            expected: |i, m| {
                let pid = pick(i, m.persons());
                // Distinct set reachable in exactly 1 hop ∪ exactly 2 hops. With relationship
                // uniqueness but node revisiting, exactly-2-hop can include pid itself; the union is
                // {direct friends} ∪ {friends of friends}.
                let mut set: HashSet<u64> = HashSet::new();
                for &f in m.friends(pid) {
                    set.insert(f);
                    for &g in m.friends(f) {
                        set.insert(g);
                    }
                }
                let mut ids: Vec<u64> = set.into_iter().collect();
                ids.sort_unstable();
                ids.into_iter()
                    .map(|id| vec![("id", Value::Integer(id as i64))])
                    .collect()
            },
            verify: None,
        },
        // ═══════════════════════════ Business Intelligence (BI) ══════════════════════════════════
        // --- BI population aggregate: count + avg + max over all persons -------------------------
        Operation {
            id: "BI-pop",
            label: "Population aggregate over all persons (count/avg/max)",
            inspired_by: "BI-style population aggregate",
            is_write: false,
            build: |_i, _m| {
                "MATCH (p:Person) \
                 RETURN count(*) AS people, avg(p.age) AS avg_age, max(p.age) AS oldest"
                    .to_owned()
            },
            expected: |_i, m| {
                let n = m.persons();
                let ages: Vec<u64> = (0..n)
                    .filter_map(|p| m.person(p).map(|(_, a)| *a))
                    .collect();
                let sum: u64 = ages.iter().sum();
                let avg = if ages.is_empty() {
                    0.0
                } else {
                    sum as f64 / ages.len() as f64
                };
                let oldest = ages.iter().copied().max().unwrap_or(0);
                vec![vec![
                    ("people", Value::Integer(n as i64)),
                    ("avg_age", Value::Float(avg)),
                    ("oldest", Value::Integer(oldest as i64)),
                ]]
            },
            verify: None,
        },
        // --- BI popular posts: scan + WHERE views > t + count ------------------------------------
        Operation {
            id: "BI-popular-posts",
            label: "Popular posts (scan + WHERE views > t + count)",
            inspired_by: "BI popularity filter",
            is_write: false,
            build: |i, _m| {
                let threshold = view_threshold(i);
                format!("MATCH (p:Post) WHERE p.views > {threshold} RETURN count(*) AS popular")
            },
            expected: |i, m| {
                let threshold = view_threshold(i) as u64;
                let popular = m.posts().iter().filter(|p| p.views > threshold).count();
                vec![vec![("popular", Value::Integer(popular as i64))]]
            },
            verify: None,
        },
        // --- BI forum sizes: post count per forum, ranked (the canonical BI "top forums") --------
        Operation {
            id: "BI-forum-sizes",
            label: "Posts per forum, ranked (CONTAINER_OF expand + group + ORDER BY)",
            inspired_by: "BI4/BI-style top forums by activity",
            is_write: false,
            build: |_i, _m| {
                "MATCH (f:Forum)-[:CONTAINER_OF]->(p:Post) \
                 RETURN f.id AS fid, count(p) AS posts ORDER BY posts DESC, fid ASC"
                    .to_owned()
            },
            expected: |_i, m| {
                let mut by_forum: BTreeMap<u64, u64> = BTreeMap::new();
                for p in m.posts() {
                    *by_forum.entry(p.forum).or_default() += 1;
                }
                let mut ranked: Vec<(u64, u64)> = by_forum.into_iter().collect();
                ranked.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
                ranked
                    .into_iter()
                    .map(|(fid, posts)| {
                        vec![
                            ("fid", Value::Integer(fid as i64)),
                            ("posts", Value::Integer(posts as i64)),
                        ]
                    })
                    .collect()
            },
            verify: None,
        },
        // --- BI prolific authors: posts authored per person, top-10 -----------------------------
        Operation {
            id: "BI-prolific-authors",
            label: "Top-10 most prolific post authors (group + ORDER BY + LIMIT)",
            inspired_by: "BI-style top contributors",
            is_write: false,
            build: |_i, _m| {
                "MATCH (p:Post)-[:HAS_CREATOR]->(a:Person) \
                 RETURN a.id AS aid, count(p) AS posts ORDER BY posts DESC, aid ASC LIMIT 10"
                    .to_owned()
            },
            expected: |_i, m| {
                let mut by_author: BTreeMap<u64, u64> = BTreeMap::new();
                for p in m.posts() {
                    *by_author.entry(p.author).or_default() += 1;
                }
                let mut ranked: Vec<(u64, u64)> = by_author.into_iter().collect();
                ranked.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
                ranked
                    .into_iter()
                    .take(10)
                    .map(|(aid, posts)| {
                        vec![
                            ("aid", Value::Integer(aid as i64)),
                            ("posts", Value::Integer(posts as i64)),
                        ]
                    })
                    .collect()
            },
            verify: None,
        },
        // --- BI commenters: comments authored per person, top-10 --------------------------------
        Operation {
            id: "BI-top-commenters",
            label: "Top-10 most active commenters (group + ORDER BY + LIMIT)",
            inspired_by: "BI-style top contributors (comments)",
            is_write: false,
            build: |_i, _m| {
                "MATCH (c:Comment)-[:HAS_CREATOR]->(a:Person) \
                 RETURN a.id AS aid, count(c) AS comments ORDER BY comments DESC, aid ASC LIMIT 10"
                    .to_owned()
            },
            expected: |_i, m| {
                let mut by_author: BTreeMap<u64, u64> = BTreeMap::new();
                for c in m.comments() {
                    *by_author.entry(c.author).or_default() += 1;
                }
                let mut ranked: Vec<(u64, u64)> = by_author.into_iter().collect();
                ranked.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
                ranked
                    .into_iter()
                    .take(10)
                    .map(|(aid, comments)| {
                        vec![
                            ("aid", Value::Integer(aid as i64)),
                            ("comments", Value::Integer(comments as i64)),
                        ]
                    })
                    .collect()
            },
            verify: None,
        },
        // --- BI reply targets: comments grouped by the post they reply to, top-10 ---------------
        Operation {
            id: "BI-replied-posts",
            label: "Top-10 most-replied-to posts (REPLY_OF group + ORDER BY + LIMIT)",
            inspired_by: "BI-style most-discussed content",
            is_write: false,
            build: |_i, _m| {
                "MATCH (c:Comment)-[:REPLY_OF]->(p:Post) \
                 RETURN p.id AS pid, count(c) AS replies ORDER BY replies DESC, pid ASC LIMIT 10"
                    .to_owned()
            },
            expected: |_i, m| {
                let mut by_post: BTreeMap<u64, u64> = BTreeMap::new();
                for c in m.comments() {
                    *by_post.entry(c.post).or_default() += 1;
                }
                let mut ranked: Vec<(u64, u64)> = by_post.into_iter().collect();
                ranked.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
                ranked
                    .into_iter()
                    .take(10)
                    .map(|(pid, replies)| {
                        vec![
                            ("pid", Value::Integer(pid as i64)),
                            ("replies", Value::Integer(replies as i64)),
                        ]
                    })
                    .collect()
            },
            verify: None,
        },
        // --- BI age histogram: persons bucketed into age bands with CASE -------------------------
        Operation {
            id: "BI-age-bands",
            label: "Person count per age band (CASE bucketing + group)",
            inspired_by: "BI-style demographic histogram",
            is_write: false,
            build: |_i, _m| {
                "MATCH (p:Person) \
                 WITH CASE WHEN p.age < 30 THEN 'young' \
                           WHEN p.age < 50 THEN 'mid' \
                           ELSE 'senior' END AS band \
                 RETURN band AS band, count(*) AS n ORDER BY band ASC"
                    .to_owned()
            },
            expected: |_i, m| {
                let mut counts: BTreeMap<&'static str, u64> = BTreeMap::new();
                for p in 0..m.persons() {
                    if let Some((_, age)) = m.person(p) {
                        let band = if *age < 30 {
                            "young"
                        } else if *age < 50 {
                            "mid"
                        } else {
                            "senior"
                        };
                        *counts.entry(band).or_default() += 1;
                    }
                }
                // BTreeMap iterates in ascending key order = the query's `ORDER BY band ASC`.
                counts
                    .into_iter()
                    .map(|(band, n)| {
                        vec![
                            ("band", Value::String(band.to_owned())),
                            ("n", Value::Integer(n as i64)),
                        ]
                    })
                    .collect()
            },
            verify: None,
        },
        // --- BI forum view sum: total post views per forum, ranked ------------------------------
        Operation {
            id: "BI-forum-views",
            label: "Total post views per forum, ranked (sum aggregate)",
            inspired_by: "BI-style engagement aggregate",
            is_write: false,
            build: |_i, _m| {
                "MATCH (f:Forum)-[:CONTAINER_OF]->(p:Post) \
                 RETURN f.id AS fid, sum(p.views) AS views ORDER BY views DESC, fid ASC"
                    .to_owned()
            },
            expected: |_i, m| {
                let mut by_forum: BTreeMap<u64, u64> = BTreeMap::new();
                for p in m.posts() {
                    *by_forum.entry(p.forum).or_default() += p.views;
                }
                let mut ranked: Vec<(u64, u64)> = by_forum.into_iter().collect();
                ranked.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
                ranked
                    .into_iter()
                    .map(|(fid, views)| {
                        vec![
                            ("fid", Value::Integer(fid as i64)),
                            ("views", Value::Integer(views as i64)),
                        ]
                    })
                    .collect()
            },
            verify: None,
        },
        // --- BI isolated persons: persons with no friends (OPTIONAL MATCH + WHERE IS NULL) -------
        Operation {
            id: "BI-isolated",
            label: "Persons with no friends (anti-join via OPTIONAL MATCH)",
            inspired_by: "BI-style anti-join / inactive accounts",
            is_write: false,
            build: |_i, _m| {
                "MATCH (p:Person) \
                 OPTIONAL MATCH (p)-[:KNOWS]->(f:Person) \
                 WITH p, count(f) AS deg WHERE deg = 0 \
                 RETURN p.id AS id ORDER BY id ASC"
                    .to_owned()
            },
            expected: |_i, m| {
                (0..m.persons())
                    .filter(|&p| m.friends(p).is_empty())
                    .map(|p| vec![("id", Value::Integer(p as i64))])
                    .collect()
            },
            verify: None,
        },
        // --- DEG-forum: a single forum's post count (point expand + count) -----------------------
        Operation {
            id: "DEG-forum",
            label: "Forum post count (CONTAINER_OF expand + count)",
            inspired_by: "IC structural degree (single anchor)",
            is_write: false,
            build: |i, m| {
                let fid = pick(i, m.forums().max(1));
                format!(
                    "MATCH (f:Forum {{id: {fid}}})-[:CONTAINER_OF]->(p:Post) \
                     RETURN count(p) AS posts"
                )
            },
            expected: |i, m| {
                let fid = pick(i, m.forums().max(1));
                let posts = m.posts().iter().filter(|p| p.forum == fid).count();
                vec![vec![("posts", Value::Integer(posts as i64))]]
            },
            verify: None,
        },
        // --- IC-collect-friends: a person's friend-name list (collect aggregate) -----------------
        Operation {
            id: "IC-collect-friends",
            label: "A person's friend ids as a list (collect)",
            inspired_by: "IS-style neighbour materialisation",
            is_write: false,
            build: |i, m| {
                let pid = pick(i, m.persons());
                // Order inside the collected list is unspecified in Cypher, so sort the friends first
                // with a WITH so the produced list is deterministic and matches ground truth.
                format!(
                    "MATCH (p:Person {{id: {pid}}})-[:KNOWS]->(f:Person) \
                     WITH f.id AS fid ORDER BY fid ASC \
                     RETURN collect(fid) AS friends"
                )
            },
            expected: |i, m| {
                let pid = pick(i, m.persons());
                let list: Vec<Value> = m
                    .friends(pid)
                    .iter()
                    .map(|&f| Value::Integer(f as i64))
                    .collect();
                // collect over an empty input still yields one row with an empty list.
                vec![vec![("friends", Value::List(list))]]
            },
            verify: None,
        },
        // ════════════════════════════════ Write (IU / IS short write) ════════════════════════════
        // --- IU-comment: insert a comment on a post by an author, verified by reading it back -----
        Operation {
            id: "IU-comment",
            label: "Insert a comment on a post (short write), verified by read-back",
            inspired_by: "IU (insert) / IS short write",
            is_write: true,
            build: |i, m| {
                let (comment_id, post, author) = insert_comment_params(i, m);
                format!(
                    "MATCH (p:Post {{id: {post}}}), (a:Person {{id: {author}}}) \
                     CREATE (c:Comment {{id: {comment_id}}}), \
                            (c)-[:REPLY_OF]->(p), (c)-[:HAS_CREATOR]->(a)"
                )
            },
            expected: |i, m| {
                let (_comment_id, post, author) = insert_comment_params(i, m);
                vec![vec![
                    ("post", Value::Integer(post as i64)),
                    ("author", Value::Integer(author as i64)),
                ]]
            },
            // After the write commits, this read observes the new comment: it must REPLY_OF the right
            // post and HAS_CREATOR the right author. The `expected` result above encodes exactly that.
            verify: Some(|i, m| {
                let (comment_id, _post, _author) = insert_comment_params(i, m);
                format!(
                    "MATCH (c:Comment {{id: {comment_id}}})-[:REPLY_OF]->(p:Post), \
                           (c)-[:HAS_CREATOR]->(a:Person) \
                     RETURN p.id AS post, a.id AS author"
                )
            }),
        },
    ]
}

/// The synthetic ids the [`"IU-comment"`](catalog) write uses, kept in one place so `build`, `verify`
/// and `expected` cannot disagree. Comment ids start well above the generated range so an insert
/// never collides with a generated comment; the target post and author are spread across the id space.
fn insert_comment_params(i: u64, m: &SnbModel) -> (u64, u64, u64) {
    let comment_id = 1_000_000 + i;
    let post = pick(i, m.post_count().max(1));
    let author = pick(i.wrapping_mul(2_654_435_761), m.persons());
    (comment_id, post, author)
}

/// The per-invocation view threshold for `BI-popular-posts`, varied a little so it is not
/// constant-folded; shared by `build` and `expected` so they cannot diverge.
fn view_threshold(i: u64) -> i64 {
    5_000 + (i % 5) as i64 * 500
}

/// The official IC/BI queries this offline harness does **not** attempt, with the precise reason —
/// surfaced in the report and `LDBC.md` so the offline scope is transparent (no fake conformance).
#[must_use]
pub fn deferred_official_queries() -> Vec<(&'static str, &'static str)> {
    vec![
        (
            "IC13 (SinglePairShortestPath) / IC14 (PathBetweenPersons)",
            "need shortestPath/allShortestPaths, which the engine does not implement; \
             bounded variable-length reachability is exercised instead (see IC-reach-2).",
        ),
        (
            "IC3/IC4/IC5/IC6/IC9 (time-windowed message/tag analytics)",
            "filter messages by a creationDate window; the synthetic schema has no per-message \
             timestamp property, so the time predicate cannot be expressed faithfully.",
        ),
        (
            "IS4 (MessageContent) / IS7 (RepliesOfMessage thread)",
            "need a message `content`/`creationDate` and reply-thread chains the synthetic schema \
             omits (posts/comments carry only an id/views).",
        ),
        (
            "IC1 (full friend search with workplaces/universities)",
            "needs Organisation/Place dimensions (universities, companies, cities) absent from the \
             synthetic schema; the friendship-distance core is exercised by IC-fof / IC-reach-2.",
        ),
        (
            "BI tag/country correlations (BI2, BI5, BI10, …)",
            "need Tag/TagClass/Country dimensions and message timestamps the synthetic schema omits; \
             the structural BI aggregates (forum sizes, view sums, contributor rankings) are kept.",
        ),
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
