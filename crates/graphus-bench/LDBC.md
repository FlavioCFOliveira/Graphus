# LDBC-SNB-flavoured macro benchmark + offline correctness harness

This document describes the macro harness in `crates/graphus-bench/src/ldbc/` and its runner binary
`ldbc_snb`. It began as `rmp` task #27 (the standing verification suite's "LDBC SNB" deliverable) and
was broadened under `rmp` task #78 into a wider IS/IC/BI query set with an **offline correctness
harness** verified against the deterministic generator's known ground truth.

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

As of `rmp` #78, **all 24 catalog operations match ground truth** at the micro and tiny scales (0
disagreements; no engine correctness bug was surfaced by the broadened set).

## Schema (the synthetic graph)

| Label     | Properties                          | Edges                                                          |
| --------- | ----------------------------------- | -------------------------------------------------------------- |
| `Person`  | `id:int`, `name:string`, `age:int`  | `(:Person)-[:KNOWS]->(:Person)` (created as a symmetric pair)  |
| `Forum`   | `id:int`, `title:string`            | `(:Forum)-[:CONTAINER_OF]->(:Post)`                            |
| `Post`    | `id:int`, `views:int`               | `(:Post)-[:HAS_CREATOR]->(:Person)`                            |
| `Comment` | `id:int`                            | `(:Comment)-[:HAS_CREATOR]->(:Person)`, `(:Comment)-[:REPLY_OF]->(:Post)` |

Every value is an inline scalar or a short `String`, all within the engine's stored-property subtype
(`05 §7.2`). The graph is built deterministically from a SplitMix64 PRNG seeded by the scale factor,
so a given scale always yields the byte-identical graph (stable result counts across runs).

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
The realized `tiny` graph is **174 nodes / 670 relationships** built in 337 committed write
transactions.

> **Index seeks are now active for queries.** After the load, the harness builds the standard
> SNB-style `id` property indexes (`Person.id`, `Forum.id`, `Post.id`) and the planner chooses an
> index **seek** for `{id: x}` lookups (`rmp` #58/#82), so id-anchored point reads are sub-millisecond
> (e.g. `IS1-profile` p50 ≈ 0.78 ms vs ≈ 1.41 ms before the seek was wired in — see RESULTS.md §9.3).
> The remaining millisecond-range costs are the aggregates and multi-hop traversals that have no `id`
> anchor and still scan; they will drop further as more index/join strategies are wired into planning,
> and this harness is the instrument that will show it. The load itself is unindexed by construction
> (see above), which is why it remains the dominant cost at these tiny scales.

## Operations and their SNB provenance

`src/ldbc/operations.rs` defines the catalog: **24 operations** (5 IS short reads, 9 IC complex
traversals/aggregates, 9 BI aggregates, and 1 write), each expressed in the Cypher subset the engine
supports — verified end-to-end against the real pipeline (`WITH` projection pipelines with
post-aggregation `WHERE`, `OPTIONAL MATCH`, `UNWIND`, `DISTINCT`/`count(DISTINCT …)`/
`collect(DISTINCT …)`, variable-length patterns `-[:KNOWS*1..3]->`, `CASE`, list comprehensions,
`EXISTS { … }`, ranking with `ORDER BY … LIMIT`, and the write clauses). Each operation carries both
a `build` (its Cypher) and an `expected` (its ground-truth answer in Rust). The harness runs every
operation and reports it **measured** or **deferred** (if the engine rejects a form) — it never fails
the run on an unsupported form.

### Interactive Short (IS)

| id              | what it does                                     | inspired by (official SNB)   |
| --------------- | ------------------------------------------------ | ---------------------------- |
| `IS1-profile`   | person profile by id (point lookup + projection) | IS1 ProfileOfPerson          |
| `IS2-authored`  | messages a person authored (incoming creator)    | IS2 RecentMessagesOfPerson   |
| `IS3-friends`   | a person's friends (1-hop `KNOWS` expand)        | IS3 FriendsOfPerson          |
| `IS5-creator`   | a comment's author (`HAS_CREATOR` projection)    | IS5 CreatorOfMessage         |
| `IS6-forum`     | the forum a post belongs to (`CONTAINER_OF`)     | IS6 ForumOfMessage           |

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

### Write

| id            | what it does                                            | inspired by (official SNB)  |
| ------------- | ------------------------------------------------------- | --------------------------- |
| `IU-comment`  | insert a comment on a post; verified by read-back       | IU insert / IS short write  |

As of `rmp` #78, the engine supports **all 24** at the tiny scale (0 deferred), and every one matches
ground truth.

### Deferred official queries (and why)

These official IC/IS/BI queries are **not** attempted, for a documented reason — either an engine
feature gap or a synthetic-schema gap. They are honest deferrals, not faked. (`operations.rs`
exposes the same list programmatically via `deferred_official_queries()`, and the report footer
prints it.)

- **IC13 (SinglePairShortestPath) / IC14 (PathBetweenPersons)** — need
  `shortestPath`/`allShortestPaths`, which the engine does not implement. *Bounded* variable-length
  reachability **is** exercised instead (`IC-reach-2`, `-[:KNOWS*1..2]->`).
- **IC3/IC4/IC5/IC6/IC9 (time-windowed message/tag analytics)** — filter messages by a `creationDate`
  window; the synthetic schema has no per-message timestamp, so the time predicate cannot be
  expressed faithfully. (The engine *does* support temporal types — this is a dataset gap, not an
  engine gap.)
- **IS4 (MessageContent) / IS7 (RepliesOfMessage thread)** — need a message `content`/`creationDate`
  and reply-thread chains the synthetic schema omits (posts/comments carry only `id`/`views`).
- **IC1 (full friend search with workplaces/universities)** — needs Organisation/Place dimensions
  absent from the synthetic schema; the friendship-distance core is exercised by `IC-fof` /
  `IC-reach-2`.
- **BI tag/country correlations (BI2, BI5, BI10, …)** — need Tag/TagClass/Country dimensions and
  message timestamps the synthetic schema omits; the structural BI aggregates (forum sizes, view
  sums, contributor rankings) are kept.

> Most of the deferrals are now **synthetic-schema** gaps (missing timestamps, tags, places), not
> engine Cypher gaps: since the original #27 harness was written, the engine gained `WITH` pipelines,
> `OPTIONAL MATCH`, `UNWIND`, variable-length patterns, `CASE`, comprehensions, `EXISTS`, and
> temporal types, all of which the broadened #78 catalog now uses. Closing the remaining deferrals is
> mostly a matter of enriching the synthetic schema (add timestamps/tags/places) plus implementing
> `shortestPath`.

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
every one of the 24 operations' engine answers equals the ground truth computed from the deterministic
generator; the `ldbc_snb` binary is the **measurement** half (latency/throughput).

## Example report (tiny scale, release, this machine class — see RESULTS.md §1 and §9)

A condensed view of the §9 baseline (the full 24-row table is in `RESULTS.md` §9.3):

```
 scale: persons=60 knows/p=4 forums=6 posts/forum=6 comments/post=2 batch=64
 graph: 174 nodes (60 persons, 6 forums, 36 posts, 72 comments), 670 rels (454 KNOWS)
 load:  337 write transactions in 0.326s (1034 commits/s)
 index: 3 property indexes built in 0.008s (Person.id, Forum.id, Post.id)
 each operation timed over 200 invocations
 operation       rw   p50(us)   p99(us)   max(us)        ops/s   rows
 IS1-profile      R    778.98   1079.08   1168.10         1270      1
 IS3-friends      R    969.68   1144.29   1215.99         1017      7
 IC-fof           R   2129.43   3172.44   3735.32          445     37
 BI-forum-sizes   R   2961.08   3237.38   3389.49          335      6
 IU-comment       W  13606.77  18295.04  21142.72           75      0
 …(24 operations total; see RESULTS.md §9.3)…
 24/24 operations supported and measured; the rest are deferred (unsupported Cypher).
 Correctness: every operation is checked against the deterministic generator's ground truth …
```

Id-anchored point reads (`IS1-profile`) are now **sub-millisecond** because the harness builds the
standard SNB-style `id` property indexes, so `MATCH (:Person {id: x})` is an index seek rather than a
full label scan. The remaining millisecond-range costs are the aggregates and multi-hop traversals
that still scan (no `id` anchor); the numbers are stable run to run thanks to the deterministic
generator, and the harness is the instrument that will demonstrate further speed-ups as more index
seeks and join strategies are wired into planning. Remember the **offline scope**: these are a
relative Graphus-vs-Graphus signal, not comparable to published LDBC results.
