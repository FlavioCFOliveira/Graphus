# LDBC-SNB-flavoured macro benchmark + offline correctness harness

This document describes the macro harness in `crates/graphus-bench/src/ldbc/` and its runner binary
`ldbc_snb`. It began as `rmp` task #27 (the standing verification suite's "LDBC SNB" deliverable),
was broadened under `rmp` task #78 into a wider IS/IC/BI query set with an **offline correctness
harness** verified against the deterministic generator's known ground truth, and was extended under
`rmp` task #103 (which enriched the synthetic schema with per-message `creationDate`/`content`,
`Tag`s, `Place`s and `Organisation`s, and translated the previously-deferred shortest-path,
time-windowed and tag/country/organisation official queries — now 34 ground-truth-checked operations).

## What it is — and is not

It is a **scaled, inspired** Social-Network-Benchmark workload that exercises the Graphus engine
end to end: it generates a small synthetic social graph and runs a broad slice of representative
SNB-style read and write operations through the *real* pipeline
(`tokenize → parse → analyze → lower → plan_physical → bind → begin → statement → execute → commit`,
the same path the TCK runner and the Cypher engine's own end-to-end tests use), then (a) **verifies
each operation's answer against ground truth** and (b) reports throughput and latency percentiles.

It is **NOT** the official LDBC Social Network Benchmark:

- It does **not** use the official LDBC Datagen (Hadoop/Spark) data generator, and produces no
  LDBC-conformant CSV dataset.
- It does **not** implement the official Interactive (IC/IS/IU) or Business-Intelligence (BI) query
  set verbatim, nor the official driver, validation, or audited result reporting.
- Its scale knobs are **not** the official SNB scale factors (SF1, SF3, SF10, …).

The official benchmark is a far larger artifact with power-law degree distributions, correlated
dimensions, a fixed schema, and an audited driver. This harness deliberately borrows only the
*shape* — a social graph of people, forums, posts and comments — so the Graphus engine has a
realistic, connected property graph to run representative graph queries against. Treat the numbers
as a **relative** Graphus-vs-Graphus regression/characterisation signal, not as comparable to
published LDBC results.

Provenance reference: LDBC SNB specification, Erling et al., "The LDBC Social Network Benchmark:
Interactive Workload" (SIGMOD 2015); <https://ldbcouncil.org/benchmarks/snb/>.

## Offline scope (`rmp` #78) — and how correctness is established without the official dataset

The project owner explicitly approved an **offline scope** for the conformance/benchmark work. The
official LDBC Datagen needs Hadoop/Spark, and neither the official audited dataset nor its validation
parameters are available offline. So instead of validating against the official audited result set,
this harness validates against the **deterministic synthetic generator's known ground truth**:

1. The synthetic graph is generated **deterministically** from a SplitMix64 PRNG seeded by the scale
   (see [Determinism](#determinism)). The generator captures the entire structure in a pure-Rust
   `SnbModel` — the *same* model it emits the loader's Cypher from, so the engine's graph and the
   model are **identical by construction** (one source of structure, used to load the engine *and* to
   compute ground truth).
2. Each operation carries an `expected` function that computes its answer **directly from the model
   in Rust** — never by running Cypher.
3. The correctness harness (`src/ldbc/correctness.rs`) runs each operation's Cypher through the real
   engine pipeline and asserts the engine's rows equal the model-derived expected rows.

Because the engine and the oracle reach the same answer by two fully independent routes (a graph
traversal in the storage/executor stack vs. a closed-form computation over the model), agreement is
strong evidence the engine answered correctly. **This is the offline substitute for the official
audited validation set. It is *not* a claim of official LDBC conformance** — it is a rigorous,
repeatable, deterministic correctness gate against the synthetic dataset's ground truth. Run it with:

```sh
cargo test -p graphus-bench         # includes the ground-truth correctness suite (a few seconds)
```

### How the comparison works

Each operation's `expected` rows are produced in the operation's exact `ORDER BY` order with a unique
tiebreaker (or project only the ordering key, so any tied rows are byte-identical), making the
expected order **total**. The harness compares **positionally** — the strongest single assertion: it
catches a wrong value, a missing/extra row, a wrong multiplicity, *and* a wrong `ORDER BY`. When the
positional check fails, the harness re-compares as sorted multisets to report *why*: a content
mismatch (the engine returned wrong rows — a real correctness bug) vs. an order-only mismatch (right
rows, wrong order — an `ORDER BY` bug). Neither is ever silently tolerated; floats (e.g. `avg`) use a
small relative+absolute tolerance, everything else exact `Value` equality.

As of `rmp` #103, **all 34 catalog operations match ground truth** at the micro and tiny scales (0
disagreements; no engine correctness bug was surfaced by the broadened set — including the new
shortest-path, time-windowed and tag/country/organisation shapes).

## Schema (the synthetic graph)

| Label          | Properties                                                  | Edges                                                                                              |
| -------------- | ---------------------------------------------------------- | -------------------------------------------------------------------------------------------------- |
| `Person`       | `id:int`, `name:string`, `age:int`                         | `(:Person)-[:KNOWS]->(:Person)` (symmetric pair), `-[:IS_LOCATED_IN]->(:Place)`, `-[:WORK_AT]->(:Organisation)` |
| `Forum`        | `id:int`, `title:string`                                   | `(:Forum)-[:CONTAINER_OF]->(:Post)`                                                                |
| `Post`         | `id:int`, `views:int`, `creationDate:int`, `content:string`| `(:Post)-[:HAS_CREATOR]->(:Person)`, `(:Post)-[:HAS_TAG]->(:Tag)`                                  |
| `Comment`      | `id:int`, `creationDate:int`, `content:string`             | `(:Comment)-[:HAS_CREATOR]->(:Person)`, `(:Comment)-[:REPLY_OF]->(:Post)`, `(:Comment)-[:HAS_TAG]->(:Tag)` |
| `Tag`          | `id:int`, `name:string`                                    | (target of `HAS_TAG`)                                                                              |
| `Place`        | `id:int`, `name:string`, `type:string` (all `Country`)     | (target of `IS_LOCATED_IN`)                                                                        |
| `Organisation` | `id:int`, `name:string`, `type:string` (`University`/`Company`) | (target of `WORK_AT`)                                                                         |

Every value is an inline scalar or a short `String`, all within the engine's stored-property subtype
(`05 §7.2`). The graph is built deterministically from a SplitMix64 PRNG seeded by the scale factor,
so a given scale always yields the byte-identical graph (stable result counts across runs).

> **The `rmp` #103 dimensions and how they preserve determinism.** The `Tag`/`Place`/`Organisation`
> nodes, the `HAS_TAG`/`IS_LOCATED_IN`/`WORK_AT` edges, and the per-message `creationDate`/`content`
> are all **pure deterministic functions of a node's `id`** (`message_creation_date`,
> `message_content`, `message_tag`, `person_place`, `person_org`) — they draw **no** PRNG values. They
> are appended after every existing structural draw, so the original Person/KNOWS/Post/Comment
> structure is byte-identical to before #103 and every pre-#103 operation keeps passing unchanged. The
> `creationDate` is an **integer** epoch-like ordinal (posts in band `1_000_000+id`, comments in
> `2_000_000+id`), so time-window predicates `WHERE m.creationDate >= a AND m.creationDate < b` index
> and filter cleanly with no temporal-function overhead.

## Scale factors

Two built-in scales (`src/ldbc/generator.rs`):

| Scale            | persons | knows/person | forums | posts/forum | comments/post |
| ---------------- | ------: | -----------: | -----: | ----------: | ------------: |
| `tiny` (default) |      60 |            4 |      6 |           6 |             2 |
| `medium`         |   2,000 |           10 |     50 |          20 |             4 |

The default is deliberately **tiny**. The *data load* matches edge endpoints by an `id` *property*
**before** the property indexes are built (they cannot exist until the nodes do), so each
`MATCH (:Person {id: x})` during the load is an O(persons) label scan and the load is ~O(persons² ·
knows). 60 persons keeps that load to well under a second even under a debug build while still
producing a fully-connected graph (every person has friends, every post has an author and comments).
The realized `tiny` graph is **191 nodes / 898 relationships** built in 506 committed write
transactions (the #103 Tag/Place/Organisation dimensions add the extra nodes + ~one edge per
message/person; the cardinalities are kept small so the load stays sub-second).

> **Index seeks are now active for queries.** After the load, the harness builds the standard
> SNB-style `id` property indexes (`Person.id`, `Forum.id`, `Post.id`) and the planner chooses an
> index **seek** for `{id: x}` lookups (`rmp` #58/#82), so id-anchored point reads (`IS1-profile`,
> `IS4-content`) are the **fastest** shapes in the catalog by a wide margin — they touch one indexed
> node instead of scanning. The remaining costs are the aggregates and multi-hop traversals that have
> no `id` anchor and still scan; they will drop further as more index/join strategies are wired into
> planning, and this harness is the instrument that will show it. The load itself is unindexed by
> construction (see above), which is why it remains the dominant cost at these tiny scales. (Absolute
> µs depend on the CPU governor — the #103 re-capture in §9 ran under `powersave`, so its numbers are
> higher than the #78 capture's; the relative ordering of the shapes is what matters offline.)

## Operations and their SNB provenance

`src/ldbc/operations.rs` defines the catalog: **34 operations** (7 IS short reads, 12 IC complex
traversals/aggregates, 14 BI aggregates, and 1 write), each expressed in the Cypher subset the engine
supports — verified end-to-end against the real pipeline (`WITH` projection pipelines with
post-aggregation `WHERE`, `OPTIONAL MATCH`, `UNWIND`, `DISTINCT`/`count(DISTINCT …)`/
`collect(DISTINCT …)`, variable-length patterns `-[:KNOWS*1..3]->`, **`shortestPath`/
`allShortestPaths`** (`rmp` #102), `CASE`, list comprehensions, `EXISTS { … }`, ranking with
`ORDER BY … LIMIT`, integer `creationDate`-window predicates, and the write clauses). Each operation
carries both a `build` (its Cypher) and an `expected` (its ground-truth answer in Rust). The harness
runs every operation and reports it **measured** or **deferred** (if the engine rejects a form) — it
never fails the run on an unsupported form.

`rmp` #103 added 10 operations that the pre-#103 catalog deferred: the shortest-path shapes (IC13/IC14,
unblocked by the #102 operator) and the time-windowed / tag / country / organisation shapes
(IS4/IS7, IC3/IC4, and the BI tag/country/org correlations, unblocked by the enriched schema).

### Interactive Short (IS)

| id              | what it does                                     | inspired by (official SNB)   |
| --------------- | ------------------------------------------------ | ---------------------------- |
| `IS1-profile`   | person profile by id (point lookup + projection) | IS1 ProfileOfPerson          |
| `IS2-authored`  | messages a person authored (incoming creator)    | IS2 RecentMessagesOfPerson   |
| `IS3-friends`   | a person's friends (1-hop `KNOWS` expand)        | IS3 FriendsOfPerson          |
| `IS4-content`   | a message's `content` + `creationDate` by id     | IS4 MessageContent           |
| `IS5-creator`   | a comment's author (`HAS_CREATOR` projection)    | IS5 CreatorOfMessage         |
| `IS6-forum`     | the forum a post belongs to (`CONTAINER_OF`)     | IS6 ForumOfMessage           |
| `IS7-replies`   | a post's `REPLY_OF` comments (content + date)    | IS7 RepliesOfMessage         |

### Interactive Complex (IC)

| id                  | what it does                                                  | inspired by (official SNB)             |
| ------------------- | ------------------------------------------------------------ | -------------------------------------- |
| `IC-fof`            | friends-of-friends, distinct (2-hop `KNOWS` expand)          | IC1/IC2 k-hop friendship neighbourhood |
| `IC-fof-strict`     | friends-of-friends excluding self + direct friends (ring)    | IC1 (strict distance band)             |
| `IC2-friend-msgs`   | messages authored by a person's friends                      | IC2 RecentMessagesByFriends            |
| `IC-degree`         | friend count per person (`OPTIONAL MATCH` + `WITH`)          | IC-style degree / centrality           |
| `IC-top-degree`     | top-5 most-connected people (`WITH` + `ORDER BY` + `LIMIT`)  | IC-style top-N influencers             |
| `IC-common-friends` | mutual-friend count per 2-hop contact (recommendation)       | IC-style "people you may know"         |
| `IC-reach-2`        | people within 1..2 hops (variable-length path)               | IC1/IC13 bounded reachability          |
| `IC13-shortest-path`| shortest `KNOWS` path length between two persons             | IC13 SinglePairShortestPath            |
| `IC14-path-between` | distinct shortest-path length between two persons            | IC14 PathBetweenPersons                |
| `IC3-window-msgs`   | friends' messages within a `creationDate` window             | IC3/IC9 time-windowed messages         |
| `IC4-tag-window`    | tags on friends' messages within a window, ranked            | IC4/IC6 time-windowed tag analytics    |
| `IC-collect-friends`| a person's friend ids as a list (`collect`)                  | IS-style neighbour materialisation     |
| `DEG-forum`         | a single forum's post count (expand + count)                 | IC structural degree (single anchor)   |

### Business Intelligence (BI)

| id                   | what it does                                            | inspired by (official SNB)          |
| -------------------- | ------------------------------------------------------ | ----------------------------------- |
| `BI-pop`             | population aggregate (count / avg / max age)           | BI-style population aggregate       |
| `BI-popular-posts`   | popular posts (scan + `WHERE views > t` + count)       | BI popularity filter                |
| `BI-forum-sizes`     | posts per forum, ranked                                | BI4/BI top forums by activity       |
| `BI-prolific-authors`| top-10 most prolific post authors                      | BI top contributors                 |
| `BI-top-commenters`  | top-10 most active commenters                          | BI top contributors (comments)      |
| `BI-replied-posts`   | top-10 most-replied-to posts (`REPLY_OF` group)        | BI most-discussed content           |
| `BI-age-bands`       | person count per age band (`CASE` bucketing)           | BI demographic histogram            |
| `BI-forum-views`     | total post views per forum, ranked (`sum`)             | BI engagement aggregate             |
| `BI-isolated`        | persons with no friends (anti-join via `OPTIONAL MATCH`)| BI anti-join / inactive accounts    |
| `BI-tag-popularity`  | messages per `Tag`, ranked (`HAS_TAG` group)           | BI2-style tag popularity            |
| `BI-country-population`| persons per country, ranked (`IS_LOCATED_IN` group)  | BI5/BI10-style country correlation  |
| `BI-country-messages`| messages per author-country, ranked                    | BI5/BI10-style country/message corr.|
| `BI-org-distribution`| persons per organisation type, ranked (`WORK_AT`)      | BI/IC1-style organisation corr.     |

### Write

| id            | what it does                                            | inspired by (official SNB)  |
| ------------- | ------------------------------------------------------- | --------------------------- |
| `IU-comment`  | insert a comment on a post; verified by read-back       | IU insert / IS short write  |

As of `rmp` #103, the engine supports **all 34** at the tiny scale (0 deferred), and every one matches
ground truth.

### Deferred official queries (and why)

`rmp` #103 **closed** the prior shortest-path and dimension deferrals: the engine gained
`shortestPath`/`allShortestPaths` (#102) and the synthetic schema gained per-message
`creationDate`/`content`, `Tag`s, `Place`s (countries) and `Organisation`s, so IC13/IC14, the
time-windowed shapes (IS4/IS7, IC3/IC4/IC6/IC9) and the BI tag/country/organisation correlations are
now **translated and ground-truth-checked** (see the catalog tables above). The shortest-path closure
came with a precise, documented modelling note for IC14 (see below).

What genuinely **remains** out of scope is no longer an engine or simple-schema gap — it is inherent
to an *offline, synthetic* harness. (`operations.rs` exposes this list programmatically via
`deferred_official_queries()`, and the report footer prints it.)

- **Official audited validation** — the official LDBC validates against an *audited* result set
  computed from the official Datagen dataset with official validation parameters; neither is available
  offline. We substitute the self-consistent ground-truth check against the deterministic generator
  (see [Offline scope](#offline-scope-rmp-78--and-how-correctness-is-established-without-the-official-dataset)).
  This is the one inviolable offline limitation — every individual query *shape* is now expressed.
- **BI hierarchical TagClass roll-ups** — the official BI tag queries roll tags up a `TagClass`
  hierarchy (`isSubclassOf` chains). The synthetic schema models flat `Tag`s only, so the hierarchical
  roll-up is not modelled; the **flat** per-`Tag` correlation *is* exercised (`BI-tag-popularity`). A
  `TagClass` tree is a schema-enrichment follow-up, not an engine gap.
- **Power-law / correlated distributions and official SF scale factors** — the generator draws a
  uniform, deterministically-seeded graph (not the official power-law degree / correlated-dimension
  distributions at SF1/SF3/SF10). The query *shapes* are faithful; the data *distribution* is not, so
  the absolute numbers stay a relative Graphus-vs-Graphus signal.

> **IC14 modelling note (precise, honest).** `IC14-path-between` uses `allShortestPaths` and projects
> `RETURN DISTINCT length(p) AS len`. Over the *symmetric multigraph* `KNOWS` (each friendship is two
> directed edges, `a→b` and `b→a`), the engine — correctly, per the openCypher multigraph semantics —
> enumerates one path *per directed edge per hop*, so the raw `allShortestPaths` row count is an
> engine artefact (`2^length` for a simple chain), not a clean structural path count. The **distinct
> length** of those paths, however, is exactly the BFS distance. So the faithful, precise assertion is:
> a connected pair yields exactly **one** row carrying the shortest-path length; a disconnected pair
> yields **no** row. The ground truth (`SnbModel::shortest_knows_distance`, a plain BFS) computes that
> distance independently in Rust. (`IC13-shortest-path` uses `shortestPath`, which returns the single
> minimal path, so its row is the length directly.)

## Running

```sh
# Tiny scale perf run (a few seconds, even debug):
cargo run -p graphus-bench --bin ldbc_snb

# Heavier medium scale, release (recommended for medium):
cargo run -p graphus-bench --release --bin ldbc_snb -- --medium

# The standing test suite: the ground-truth CORRECTNESS gate + the completion test (a few seconds):
cargo test -p graphus-bench --lib ldbc
```

The runner prints a report to stdout and a one-line progress note to stderr. Exit status is `0` on a
successful run, `1` only if graph generation itself fails (a harness bug).

The `cargo test` path is the **correctness** half (the offline substitute for official LDBC
validation): `ldbc::correctness::tests::every_operation_matches_ground_truth_at_micro_scale` asserts
every one of the 34 operations' engine answers equals the ground truth computed from the deterministic
generator; the `ldbc_snb` binary is the **measurement** half (latency/throughput).

## Example report (tiny scale, release, this machine class — see RESULTS.md §1 and §9)

A condensed view of the §9 baseline (the full 34-row table is in `RESULTS.md` §9.3):

```
 scale: persons=60 knows/p=4 forums=6 posts/forum=6 comments/post=2 batch=64
 graph: 191 nodes (60 persons, 6 forums, 36 posts, 72 comments, 8 tags, 5 places, 4 orgs), 898 rels (454 KNOWS)
 load:  506 write transactions in 0.885s (572 commits/s)
 index: 3 property indexes built in 0.011s (Person.id, Forum.id, Post.id)
 each operation timed over 200 invocations
 operation            rw   p50(us)   p99(us)   max(us)        ops/s   rows
 IS1-profile           R   1284.26   1424.98   1555.60          774      1
 IS4-content           R   1868.30   2176.27   2223.93          531      1
 IC-fof                R   4965.37   7233.18   7474.18          193     37
 IC13-shortest-path    R  10271.97  21028.16  21391.78           77      1
 IC4-tag-window        R   7678.81  10764.60  10982.69          126      8
 BI-tag-popularity     R  49569.83  51277.04  51416.92           20      8
 IU-comment            W  21131.04  28630.49  28794.17           48      0
 …(34 operations total; see RESULTS.md §9.3)…
 34/34 operations supported and measured; the rest are deferred (unsupported Cypher).
 Correctness: every operation is checked against the deterministic generator's ground truth …
```

Id-anchored point reads (`IS1-profile`, `IS4-content`) are the **fastest** shapes because the harness
builds the standard SNB-style `id` property indexes, so `MATCH (:Person {id: x})` is an index seek
rather than a full label scan. The slowest are the index-free `HAS_TAG`/`IS_LOCATED_IN` relationship
scans (`BI-tag-popularity`, `BI-country-messages`) and the full-population `OPTIONAL MATCH` anti-join
(`BI-isolated`); the shortest-path shapes (`IC13`/`IC14`) sit in between, running a real BFS over the
KNOWS graph. The numbers are stable run to run thanks to the deterministic generator, and the harness
is the instrument that will demonstrate further speed-ups as more index seeks and join strategies are
wired into planning. Remember the **offline scope**: these are a relative Graphus-vs-Graphus signal,
not comparable to published LDBC results.
