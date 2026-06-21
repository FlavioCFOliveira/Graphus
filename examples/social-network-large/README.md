# social-network-large — performance under a LARGE social graph

This example evaluates Graphus's behaviour on a **big graph**. It builds a social network of
**`USER`** nodes befriended by an **undirected multigraph** `FRIEND` relationship, a corpus of
**`ARTICLE`** nodes carrying realistic headlines, and **`LIKE`** edges from users to articles — then
**bulk-loads it at scale** into a real on-disk store and measures a **Cypher traversal battery** over
it, collecting explicit evidence across every performance vector (throughput, storage, RAM, CPU, and
per-query latency).

It is both a runnable **demonstration** and an executable **E2E test**: every step asserts its
expected result and `run.sh` exits non-zero if any assertion fails.

## The graph model (a multigraph LPG)

| Element | Shape | Meaning |
|---------|-------|---------|
| `(:USER {id, name, registered})` | `id` = 24 hex chars, `name` ≤ 64 chars (realistic Portuguese full names, with diacritics), `registered` = unix ts | a person |
| `(:ARTICLE {id, name, registered})` | `id` = 24 hex chars, `name` = a realistic news-style headline, `registered` = unix ts | a published article |
| `(:USER)-[:FRIEND {since}]-(:USER)` | **undirected multigraph**; each `USER` has between `friend_min` and `friend_max` friends | a friendship |
| `(:USER)-[:LIKE {date}]->(:ARTICLE)` | directed; each user likes a random set of articles | a like |

The model mirrors the goal literally — e.g.
`CREATE (:USER {id:'000000000000000000000000', name:'José António da Silva e Carvalho', registered:1781876640})`
and `(:USER)-[:FRIEND {since:1781876640}]-(:USER)`.

### Realistic, deterministic data

The generator (`graphus-social-gen`, a dev-only leaf crate) is **fully deterministic**: the entire
graph is a pure function of `(seed, profile)`, so it is **byte-identical per seed** across runs,
hosts, and platforms (a seeded `SplitMix64` PRNG; no clock, no float in any emitted text, no hash-map
iteration). Names are assembled from European-Portuguese given-name / surname / particle pools
(diacritics preserved, bounded to 64 bytes on a char boundary); article titles are assembled from
realistic headline-fragment pools so they "tend to contain real information".

The `FRIEND` relationship is built with the **configuration model** (stub pairing): each user draws a
target degree in `[friend_min, friend_max]`, the stubs are deterministically shuffled (Fisher–Yates)
and paired, with self-loops avoided and multi-edges allowed (Graphus is a multigraph). This yields a
realised per-user degree **within the configured band** — `O(E)` and scalable to a million users.

## Scale profiles

| Profile | Users | Friends / user | Articles | ≈ FRIEND edges | Use |
|---------|-------|----------------|----------|----------------|-----|
| `fast`  | 2,000 | 6–24 | 200 | ~15k | CI gate — runs in **seconds**; the committed baseline |
| `large` | 50,000 | 20–120 | 3,000 | ~1.75M | bounded **evidence** run (release; ~tens of seconds) |
| `huge`  | **1,000,000** | **200–2000** | **30,000** | **~550M** | the **literal target**; opt-in, heavy (tens of GB, long) |

Select with `SOCIAL_PROFILE=<fast|large|huge>`. The `fast` profile is the default and the only one
gated against the committed baseline (the others are different scales and are not baseline-comparable).
The `huge` profile is the full target the example is built around; the loader is structurally capable
of it (the generator streams the data batch-by-batch, and ingest is `O(E)`), but it is opt-in because
of its size.

## What it exercises

| # | Capability | How it is shown |
|---|------------|-----------------|
| 1 | **Deterministic large-graph generation** | `social_gen` emits the graph twice and the bytes are diffed identical. |
| 2 | **High-throughput bulk ingest at scale** | The graph is loaded via the production **`graphus-bulk`** path (`O(E)` endpoint resolution) into an on-disk store — nodes then relationships, in committed batches. |
| 3 | **Index-backed point lookups** | `:USER(id)` and `:ARTICLE(id)` property indexes are built so each `MATCH (:USER {id: …})` is an index **seek**. |
| 4 | **Traversals on a large graph** | A Cypher read battery: direct friends, **friend-of-friend** (2-hop), **mutual friends**, **top-liked articles** (aggregation + `ORDER BY` + `LIMIT`), and degree. |
| 5 | **The same model over the wire** | An opt-in Bolt-over-UDS slice creates a small slice of the identical model via `graphus-cli` against a booted `graphus-server` and runs a friend-of-friend + top-liked query over the socket. |
| 6 | **Explicit evidence** | A schema-versioned `report.json` + `report.md`: ingest throughput, durable on-disk footprint + amplification, peak RSS, CPU, and per-query latency. |

## Transport — why the load + read battery run in-process

The bulk ingest path (`graphus-bulk`) and the MVCC engine are driven **in-process, single-threaded**
over an **on-disk** `FileBlockDevice` + WAL — the same durable on-disk layout the production server
uses. This is the real engine, real bulk import, real WAL-logged storage, just driven deterministically
in one process so the footprint and structural metrics are reproducible and assertable. Step 4 then
proves the **same Cypher model** round-trips over the real **Bolt-over-UDS wire** via `graphus-cli`.

> **Why bulk-load instead of per-edge `CREATE`?** Loading hundreds of millions of edges by
> `MATCH (a:USER {id:X}), (b:USER {id:Y}) CREATE (a)-[:FRIEND]->(b)` is `O(E·N)` today: the planner
> index-seeks only **one** of the two anchors (the second equality lands as a filter above the
> cartesian product, out of reach of the index-selection rewrite — filed as an improvement). The
> `graphus-bulk` importer resolves each endpoint through an internal id→id hash map (`O(1)` per
> endpoint ⇒ `O(E)` total), which is the correct, production way to load a large graph and lets this
> example actually reach scale.

## Running it

```bash
# From the repository root. Builds the binaries if they are not already present.
examples/social-network-large/run.sh
```

```bash
# Use pre-built release binaries, run the bounded evidence-scale profile, skip the wire slice:
cargo build --release -p graphus-social-gen --features engine -p graphus-server -p graphus-cli
GRAPHUS_BIN_DIR=target/release SOCIAL_PROFILE=large RUN_WIRE=0 examples/social-network-large/run.sh
```

Knobs: `SOCIAL_PROFILE` (`fast` default), `RUN_WIRE` (`1` default; `0` skips the Bolt/UDS slice),
`GRAPHUS_BIN_DIR` (where to find/place the binaries).

A successful `fast` run ends with:

```
13 checks run, 0 failures.
SOCIAL-NETWORK-LARGE DEMONSTRATION PASSED — ...
```

## The evidence it collects

Each run writes a standardized, schema-versioned report to the **git-ignored** `evidence/` directory
(`report.json` for tooling, `report.md` for humans), via the shared `graphus-examples-harness`. The
headline figures for the committed `fast` profile (machine-variant numbers will differ on your host):

| Vector | `fast`-profile evidence |
|--------|--------------------------|
| **Graph** | 2,000 USER + 200 ARTICLE nodes; 15,047 FRIEND + 10,020 LIKE edges; realised degree ∈ [6, 24] |
| **Ingest throughput** | ~120k nodes/s and ~245k rels/s over the production `O(E)` bulk path |
| **Durable footprint** | store image **4,579,328 B (559 pages)**; store-only space amplification **2.43×** over 1.89 MB logical CSV — *deterministic & gated* |
| **WAL** | ~28 MB transient redo log — *machine-variant, not gated* |
| **RAM** | peak RSS ~166 MB |
| **Read latency** | friends ~3.2 ms, friend-of-friend ~3.4 ms, mutual ~3.6 ms, degree ~3.2 ms, top-liked (full aggregation scan) ~27 ms |

### The baseline regression gate

The `fast` profile is compared against the committed `baseline.json` by `social_baseline_cmp`, which
gates **only the stable, deterministic structural metrics** (node / relationship / USER / ARTICLE /
FRIEND / LIKE counts, durable store bytes + pages, and store-only space amplification). The
machine-variant families (RSS, throughput, CPU, wall-time, and the transient WAL) are given an
effectively-infinite tolerance, so the gate flags a genuine storage-engine or generator regression
without flaking on hardware differences.

## CI coverage

The crate's own `cargo test` (which runs under the project's default `cargo test --all`) exercises the
`fast`-profile bulk load + the read-query battery + the shape invariants (`tests/load_fast.rs`) and the
generator's byte-identical determinism + degree-band + id/name invariants (`tests/determinism.rs`), so
the example's guarantees are protected against regression on every build.
