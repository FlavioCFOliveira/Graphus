# LDBC-SNB-flavoured macro benchmark harness

This document describes the macro benchmark harness in `crates/graphus-bench/src/ldbc/` and its
runner binary `ldbc_snb` (`rmp` task #27, the standing verification suite's "LDBC SNB" deliverable).

## What it is — and is not

It is a **scaled, inspired** Social-Network-Benchmark workload that exercises the Graphus engine
end to end: it generates a small synthetic social graph and runs a handful of representative
SNB-style read and write operations through the *real* pipeline
(`tokenize → parse → analyze → lower → plan_physical → bind → begin → statement → execute → commit`,
the same path the TCK runner and the Cypher engine's own end-to-end tests use), then reports
throughput and latency percentiles.

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

The default is deliberately **tiny**. Edge creation matches endpoints by an `id` *property*, and the
engine has **no property index yet**, so every `MATCH (:Person {id: x})` is an O(persons) label
scan; the data load is therefore ~O(persons² · knows). 60 persons keeps that load to well under a
second even under a debug build while still producing a fully-connected graph (every person has
friends, every post has an author and comments). The realized `tiny` graph is **174 nodes / 670
relationships** built in 337 committed write transactions.

> **Follow-up (filed, not fixed here):** once a property/label secondary index is wired into planning
> (`graphus-index` exists; the planner does not yet choose an index seek for `{id: x}` lookups), the
> per-operation latencies below — currently dominated by full label scans — will drop by orders of
> magnitude, and `medium`/larger scales become cheap. This harness is the instrument that will show
> that improvement.

## Operations and their SNB provenance

`src/ldbc/operations.rs` defines the catalog. Each is expressed in the Cypher subset the engine
currently supports. The harness runs every operation and reports it as **measured** or **deferred**
(if the engine rejects the query form) — it never fails the run on an unsupported form.

| id              | what it does                                   | inspired by (official SNB)            |
| --------------- | ---------------------------------------------- | ------------------------------------- |
| `IS1-profile`   | person profile by id (point lookup)            | IS1 ProfileOfPerson                   |
| `IS3-friends`   | a person's friends (1-hop `KNOWS` expand)      | IS3 FriendsOfPerson                   |
| `IC-fof`        | friends-of-friends (2-hop `KNOWS` expand)      | IC1/IC2 k-hop friendship neighbourhood|
| `IS2-authored`  | messages a person authored (incoming creator)  | IS2 RecentMessagesOfPerson            |
| `AGG-persons`   | population aggregate (label scan + count/avg)  | BI-style aggregate                    |
| `FILTER-posts`  | popular posts (scan + `WHERE views > t`)       | BI popularity filter                  |
| `DEG-forum`     | a forum's post count (expand + count)          | IC structural degree                  |
| `IU-comment`    | insert a comment on a post (short write)       | IU insert / IS short write            |

As of this writing, the engine supports **all 8** at the tiny scale (0 deferred).

### Deferred official queries (and why)

The official IC/BI queries that this harness does **not** attempt, because they need Cypher the
engine does not yet support (the TCK baseline is ~28%):

- Variable-length / shortest-path patterns (`-[:KNOWS*1..3]->`, `shortestPath(...)`) — used by most
  IC complex reads.
- `OPTIONAL MATCH`, `UNWIND`, list/pattern comprehensions, `CASE` — pervasive in IC/BI projections.
- Temporal types and arithmetic (`date`, `datetime`, duration filters) — IC reads filter by
  `creationDate`; the engine's stored-property subtype excludes temporal values today.
- Multi-stage `WITH` pipelines with re-aggregation — IC top-N-by-score shapes.

These are honest deferrals tracked against the engine's growing Cypher coverage, not harness gaps.

## Running

```sh
# Tiny scale (a few seconds, even debug):
cargo run -p graphus-bench --bin ldbc_snb

# Heavier medium scale, release (recommended for medium):
cargo run -p graphus-bench --release --bin ldbc_snb -- --medium

# As a test (asserts the harness runs to completion and core ops are supported):
cargo test -p graphus-bench --lib ldbc
```

The runner prints a report to stdout and a one-line progress note to stderr. Exit status is `0` on a
successful run, `1` only if graph generation itself fails (a harness bug).

## Example report (tiny scale, release, this machine class — see RESULTS.md §1)

```
 scale: persons=60 knows/p=4 forums=6 posts/forum=6 comments/post=2 batch=64
 graph: 174 nodes (60 persons, 6 forums, 36 posts, 72 comments), 670 rels (454 KNOWS)
 load:  337 write transactions in 0.343s (983 commits/s)
 each operation timed over 200 invocations
 operation       rw   p50(us)   p99(us)   max(us)        ops/s   rows
 IS1-profile      R   1409.89   1477.08   1883.70          709      1
 IS3-friends      R   1632.90   1789.56   1791.23          608      7
 IC-fof           R   2544.40   3821.53   3965.47          374     55
 IS2-authored     R  10111.96  10513.83  10549.52           99      2
 AGG-persons      R   2316.44   2862.11   2955.56          428      1
 FILTER-posts     R   1601.75   2265.18   2516.19          612      1
 DEG-forum        R   1372.25   2077.72   2222.64          717      1
 IU-comment       W   8197.95  12376.79  12789.42          127      1
 8/8 operations supported and measured; the rest are deferred (unsupported Cypher).
```

Latencies are in the **millisecond** range because each id-keyed `MATCH` is a full label scan (no
property index yet — see the follow-up note above). The numbers are stable run to run thanks to the
deterministic generator, and the harness is the instrument that will demonstrate the speed-up once an
index seek is wired into planning.
