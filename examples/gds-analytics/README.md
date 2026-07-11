# Graph Data Science analytics

A realistic, end-to-end demonstration of **graph data science (GDS) analytics** on Graphus: load a
seeded **academic influence / citation network**, run the full `gds.*` algorithm suite over the
in-memory CSR projection through the **procedure surface**, assert the results against an
**analytically-known reference subgraph**, and characterise how the **multi-threaded** GDS engine
scales — both with graph size (per-algorithm time + CSR footprint) and, at a fixed size, with **core
count** (a real sequential-vs-parallel speedup that is deterministic across thread widths).

The official **Neo4j driver** (Node.js, `bolt://` / `bolt+ssc://`) drives the live workload, exactly
as the driver ecosystem would — against a **self-booted local server** *or* an **already-running
instance** (local or remote) via the shared external-target seam (see
[Running against an external target](#running-against-an-external-target-attach-mode)). A **hermetic
cargo mirror** (`crates/graphus-server/tests/gds_analytics.rs`) asserts the same reference ground truth
in-process, in the default `cargo test` run, with no Node/network.

## What it demonstrates

- **The `gds.*` procedure surface end to end** — `gds.graph.project` → the algorithm procedures in
  **every execution mode** (`.stream`, `.stats`, `.mutate`, `.write`) → `gds.graph.drop`, over a real
  persistent store via the official driver.
- **Weighted vs unweighted analytics** — the headline of a real GDS workload: PageRank and Dijkstra run
  **weighted** (`relationshipWeightProperty='weight'`) and **unweighted** over the same influence
  network, and the example asserts the two genuinely differ and reports both top rankings (see
  [Weighted vs unweighted](#weighted-vs-unweighted)).
- **The write / mutate / stats execution modes** — `gds.pageRank.write{writeProperty:'pagerank'}` then
  a `MATCH…WHERE pagerank>x ORDER BY pagerank` readback (asserting `nodePropertiesWritten == authorCount`),
  a `.stats` summary, and a `.mutate` + `gds.graph.nodeProperty.stream` readback (see
  [Execution modes](#execution-modes-write--mutate--stats)).
- **A production-realistic schema** — a node `UNIQUE`, two node **property-type** constraints
  (`field_name :: STRING`, `h_index :: INTEGER`), a node `RANGE` index and a **relationship** `RANGE`
  index (`CITES.weight`), loaded schema-first (idempotent `IF NOT EXISTS`) and enforced on every write
  (see [Schema exercised](#schema-exercised-constraints--indexes)).
- **The full algorithm library**: PageRank, degree / betweenness / closeness centrality, weakly- and
  strongly-connected components (WCC / SCC), triangle counting, Label Propagation community
  detection, and weighted shortest paths (Dijkstra / Bellman-Ford).
- **Correctness against ground truth** — a small reference subgraph with hand-derived outputs the
  workload asserts EXACTLY (within a documented float tolerance).
- **Attach to any running instance, isolated & idempotent** — set `GRAPHUS_TARGET_*` and the SAME
  workload runs against a live server in a dedicated **isolated database**, tears down after itself
  (so two consecutive runs both pass), and collects **server-side evidence** from the target's
  Prometheus `/metrics` into `report.json` (`measurement_mode=external`).
- **Honest performance characterisation** (local mode) — a scalability + CSR-footprint + parallelism
  sweep that reports only what is *actually* measured on the run: per-algorithm scaling with graph
  size, and a **real sequential-vs-parallel speedup** across thread widths (proven bit-identical across
  widths) — never a fabricated curve — captured into a standardized, schema-versioned evidence report.

## Algorithms covered (and the honest notes)

The example exercises the complete `gds.*.stream` surface Graphus registers:

| `gds.*` procedure | What it computes | Notes |
|-------------------|------------------|-------|
| `gds.pageRank.stream`        | PageRank influence score | iterative, near-linear `O(k·(n+m))` |
| `gds.degree.stream`          | degree centrality | `O(n)` |
| `gds.betweenness.stream`     | Brandes betweenness | the heavy one, `O(n·m)`; undirected scaling halves the raw pair count to match Neo4j's convention |
| `gds.closeness.stream`       | closeness centrality | BFS from every node |
| `gds.wcc.stream`             | weakly-connected components | |
| `gds.scc.stream`             | strongly-connected components | iterative Tarjan (directed projection) |
| `gds.triangleCount.stream`   | per-node triangle count | |
| `gds.labelPropagation.stream`| community detection | see the honest note below |
| `gds.dijkstra.stream`        | single-source weighted shortest path | |
| `gds.bellmanFord.stream`     | single-source shortest path (handles negative-ish weights) | |

**Honest note 1 — GDS is multi-threaded, with a deterministic core knob.** As of `rmp` #342/#559
`graphus-gds` fans each parallelisable algorithm across cores with `rayon`, driven by a deterministic
[`Execution`](../../crates/graphus-gds/src/execution.rs) knob (`Sequential` / `Parallel` +
`min_parallel_work` threshold). **Parallel today:** PageRank, Brandes betweenness, closeness, WCC
(lock-free union-find), triangle counting, out-degree, Label Propagation (a distinct *synchronous*
parallel variant) and multi-source Dijkstra. **Sequential by construction (documented):** SCC (Tarjan
DFS) and single-source Dijkstra / Bellman-Ford. Crucially, the knob's only axis is *how many cores* —
**never whether the answer is stable**: every parallel result is **bit-identical across pool widths**
(exact for the integer algorithms, matching the sequential result to a documented `f64` tolerance for
PageRank / centrality), which the DST simulator relies on. So the sweep varies **two** meaningful
dimensions: **graph size** (see below) *and* **core count** — measuring the real speedup and proving
determinism, never fabricating a curve.

**Honest note 2 — no Louvain / node-similarity.** The original brief mentioned *Louvain* and *node
similarity*; **neither procedure exists in Graphus** (verified: the engine returns "there is no
procedure registered as gds.louvain.stream" / "gds.nodeSimilarity.stream"). Community detection uses
**`gds.labelPropagation.stream`**, and the planted **field** partition is recovered exactly via **WCC
over the `:CITES`-only projection**. Graphus's Label Propagation is synchronous with no
modularity-resolution parameter, so on small/dense graphs it **over-merges** (it collapses even two
dense cliques joined by a single edge into one community — measured); WCC over the intra-field-only
projection is the exact, deterministic recovery path the example uses for the planted communities.

## The network model (LPG)

An academic influence network with a **known planted community structure**:

| Element | Shape |
|---------|-------|
| `(:Author {id, name, field, field_name, h_index})` | A researcher, assigned to one of `community_count` planted research **fields**. Authors are minted field-by-field in contiguous id blocks, so field `f` owns ids `[f·field_size, (f+1)·field_size)`. |
| `(:Author)-[:CITES {weight}]->(:Author)` | A directed **intra-field** citation (dense). `weight` is the citation count. |
| `(:Author)-[:CROSS {weight}]->(:Author)` | A sparse directed **inter-field** citation, linking the fields into one weakly-connected network. |
| `(:Ref {id})` + `(:Ref)-[:LINKS]->(:Ref)` | The **reference subgraph**: two 3-cliques joined by a single bridge edge (analytically-known outputs). |

Intra-field (`:CITES`) and inter-field (`:CROSS`) citations are split by **relationship type** on
purpose: a community projection over **`:CITES` only** recovers the planted field blocks exactly via
WCC, while a projection over **all** rel types sees the fully-linked influence network for PageRank /
centrality / shortest paths.

### Schema exercised (constraints & indexes)

The graph is loaded **schema-first**: the generated `graph.cypher` opens with a DDL block the workload
runs as auto-commit admin statements over Bolt, so every subsequent write is constraint-checked and
index-maintained. It rounds out the campaign's constraint/index coverage with a **node property-type**
constraint and a **relationship RANGE** index:

| DDL | Kind | Why |
|-----|------|-----|
| `CREATE CONSTRAINT author_id_unique IF NOT EXISTS FOR (a:Author) REQUIRE a.id IS UNIQUE` | node `UNIQUE` | every author id is distinct (owns a backing RANGE index) |
| `CREATE CONSTRAINT author_field_name_string IF NOT EXISTS FOR (a:Author) REQUIRE a.field_name IS :: STRING` | node **property-type** (`STRING`) | the research-field **label** is always a string |
| `CREATE CONSTRAINT author_h_index_integer IF NOT EXISTS FOR (a:Author) REQUIRE a.h_index IS :: INTEGER` | node **property-type** (`INTEGER`) | the h-index is always an integer |
| `CREATE INDEX author_field_range IF NOT EXISTS FOR (a:Author) ON (a.field)` | node `RANGE` | the community filter / grouping access path |
| `CREATE INDEX cites_weight_range IF NOT EXISTS FOR ()-[c:CITES]-() ON (c.weight)` | **relationship** `RANGE` | a "high-weight citations" access path on the citation count |

> **Idempotent + version-tolerant load (`rmp` #690).** Every schema statement carries `IF NOT EXISTS`,
> so a second consecutive run against the same database — or an operator-owned shared one — is a no-op
> rather than a duplicate-object error. `data/analyze.js` also applies the DDL **version-tolerantly**:
> if the target is an **older build** that cannot parse a clause (a server predating `IF NOT EXISTS`,
> named indexes, or relationship indexes), it retries the plain form and, failing that, **skips the
> statement with a note** and continues — the analysis does not depend on the indexes, and the
> property-type / uniqueness constraints (which older builds still support un-claused) are recovered by
> the retry so their enforcement demo still runs. The same script therefore loads on a current build
> and on an older instance alike.

> **Property-name note.** The model stores the planted community as an **integer** `field` id
> (`0..community_count`) and its human-readable **string** label as `field_name` (e.g.
> `'graph-theory'`). The `STRING` property-type constraint therefore sits on `field_name`, and the
> node RANGE index on the integer `field` id — not the other way round — so a schema-first load
> succeeds by construction.

> **Relationship RANGE index — honest planner note (`rmp` #680).** Graphus serves an **equality**
> predicate on a relationship property from the index (`WHERE c.weight = 5` lowers to a `RelIndexSeek`),
> but a **range** predicate (`WHERE c.weight >= 5`) stays a full `ExpandAll` + `Filter` scan. This is
> asserted honestly by `crates/graphus-server/tests/gds_analytics_schema.rs` against the real planner.

The live workload (`data/analyze.js`) additionally captures the live `SHOW CONSTRAINTS` / `SHOW
INDEXES` catalog as evidence and proves the property-type constraint **rejects** a non-string
`field_name` write (failing loudly if the engine were to accept it).

### Two profiles

| Profile | Authors | Fields | Citations (approx.) | Purpose |
|---------|---------|--------|---------------------|---------|
| `fast`  | 160 (4 × 40)    | 4 | ~1.1 k | CI + the official-driver E2E assertion |
| `large` | 600 (6 × 100)   | 6 | ~4 k   | evidence-scale footprint |

Both inject the **same** reference subgraph, so the reference assertions are profile-independent.

## The reference subgraph (analytically-known ground truth)

Two 3-cliques `{b0,b1,b2}` and `{b3,b4,b5}` joined by a single bridge `b2─b3` (all `:LINKS` edges
undirected; the projection symmetrises them):

```
  clique A: (b0)──(b1)──(b2)──(b0)        clique B: (b3)──(b4)──(b5)──(b3)
                             └──────── bridge ────────┘
```

Over the undirected projection the outputs are hand-derivable, and `reference.json` carries them for
both the official-driver workload (`data/analyze.js`) and the hermetic cargo mirror to assert (all
**verified against the real engine**):

| Algorithm | Known ground truth |
|-----------|--------------------|
| **WCC** | one component = `{b0..b5}` (the bridge connects the cliques) |
| **Degree** | bridge endpoints `b2,b3` have degree 3; the other four have degree 2 |
| **Betweenness** | `b2,b3` are **strictly** highest (every inter-clique shortest path crosses the bridge) |
| **Closeness** | `b2,b3` are most central (highest closeness) |
| **triangleCount** | every node is in exactly **1** triangle (the two planted 3-cliques) |
| **PageRank** | bridge endpoints hold the max; structural symmetry `PR(b0)=PR(b1)`, `PR(b4)=PR(b5)`, `PR(b2)=PR(b3)` (within `1e-9`) |
| **Dijkstra from `b0`** (unit weights) | hop distances `0,1,1,2,3,3` |
| **Community (planted fields)** | WCC over the `:CITES`-only projection recovers exactly `community_count` components, each of size `field_size` |

## Weighted vs unweighted

`relationshipWeightProperty` is a **projection-time** knob: a graph projected with it is *weighted*,
and the algorithms then use the edge `weight` (the citation count). The workload projects the directed
influence network twice — unweighted and weighted (`relationshipWeightProperty='weight'`) — and:

- **PageRank** — streams the **full** `(nodeId, score)` result set for both, asserts the two score
  vectors genuinely differ (weighted PageRank distributes a node's rank in proportion to edge weight,
  not uniformly), and reports both top-5 author rankings and how many authors' scores changed. On the
  fast profile a typical run changes ~158/160 authors' scores and reorders the top-5.
- **Dijkstra** — single-source distances from author 0, weighted (cumulative edge weight as cost) vs
  unweighted (hop count), asserting the distance vectors differ.

> **Honest note — betweenness is unweighted here.** Graphus's betweenness is Brandes over **unweighted
> BFS** (`crates/graphus-gds/src/algo/centrality.rs`) — it ignores edge weights — so the example
> deliberately does **not** claim a weighted betweenness. PageRank, Dijkstra and closeness are the
> weight-aware algorithms.

## Execution modes (write / mutate / stats)

Beyond `.stream`, each node-property algorithm registers three more Neo4j-GDS execution modes, which
the workload exercises on the weighted projection (feature-detected — see the note below):

- **`.write`** — `gds.pageRank.write{writeProperty:'pagerank'}` writes the score back to the database.
  The example asserts `nodePropertiesWritten == authorCount`, then reads it back with a
  `MATCH (a:Author) WHERE a.pagerank > x RETURN … ORDER BY a.pagerank DESC` query (every author received
  a strictly-positive score) and prints the top-5 most-influential authors.
- **`.stats`** — `gds.pageRank.stats` returns summary statistics only (no write); the example asserts a
  summary field (`ranIterations ≥ 1`, `didConverge` a boolean).
- **`.mutate`** — `gds.pageRank.mutate{mutateProperty:'pr_mut'}` writes the score into the **in-memory
  projection**; the example reads it back with `gds.graph.nodeProperty.stream` and asserts the mutated
  values equal the ones just written to the database (same computation).

> **Version note.** The `.write` / `.stats` / `.mutate` modes and `gds.graph.nodeProperty.stream` are a
> newer procedure surface (`rmp` #643). Against an **older instance** that does not register them the
> example **feature-detects their absence and skips this section with a clear note** — the reference
> ground truth and the weighted-vs-unweighted comparison still run and still assert. To exercise the
> execution modes over the wire, attach to a current build (v0.0.9+).

## How to run it

From the repository root:

```bash
examples/gds-analytics/run.sh                      # LOCAL: fast profile; official driver if node/npm present
GDS_PROFILE=large examples/gds-analytics/run.sh    # LOCAL: evidence-scale dataset
RUN_DRIVER=0      examples/gds-analytics/run.sh     # LOCAL: skip the official-driver step (hermetic only)
GDS_SWEEP_SIZES=40,120,360 examples/gds-analytics/run.sh   # LOCAL: custom sweep field sizes
```

> The committed baseline gate (below) is a **fast-profile** reference recorded with the **default**
> sweep sizes (`40,120,360,1080`). Run with a custom `GDS_SWEEP_SIZES` or `GDS_PROFILE=large` and the
> structural graph-size check is skipped/relaxed accordingly — keep the defaults for the gated run.

Reuse pre-built binaries:

```bash
cargo build --release -p graphus-server -p graphus-gds-gen
GRAPHUS_BIN_DIR=target/release examples/gds-analytics/run.sh
```

The script:

1. generates the deterministic graph + `reference.json` (and proves byte-identical regeneration);
2. runs the hermetic multi-threaded scalability + CSR-footprint + parallelism sweep
   (`evidence/sweep.json`), asserting a real, non-fabricated multi-core speedup that is deterministic
   across thread widths;
3. (opt-in) boots a real `graphus-server` over Bolt-TCP + TLS, loads + analyses over Bolt via the
   official `neo4j-driver`, asserting the reference ground truth and recovering the planted
   communities;
4. emits the standardized `report.json` + `report.md` (per-algorithm timings + CPU/RAM/storage) and
   gates a fresh fast-profile run against the committed `baseline.json`;
5. tears everything down (trap-driven: the server is killed and the private temp dir removed on exit)
   and exits non-zero if any assertion failed.

### Running against an external target (attach mode)

Set any of `GRAPHUS_TARGET_{BOLT,REST,UDS}` and the SAME workload attaches to an **already-running**
instance instead of self-booting — the shared seam in `examples/_harness/harness.sh`. The example does
**not** touch the operator's data: it carves out a dedicated, **isolated database**, runs the analysis
over the wire, and drops that database again on exit. Because the server is not co-located, the process
CPU/RSS and on-disk storage vectors are **N/A** (no `/proc`, no store path) and the local sweep +
baseline gate are skipped; the evidence is the server's own Prometheus **`/metrics`**, scraped **before
and after** the workload and turned into `report.json` (`measurement_mode=external`, `server_metrics`
deltas) by the `measure_target` harness binary.

```bash
# Attach to a remote instance (here a Raspberry-Pi 5 over Tailscale). BOLT drives the driver; REST
# handles login, the isolated-DB DDL and /metrics.
GRAPHUS_TARGET_BOLT=bolt+ssc://100.89.148.30:7687 \
GRAPHUS_TARGET_REST=https://100.89.148.30:7474 \
GRAPHUS_TARGET_USER=graphus GRAPHUS_TARGET_PASSWORD=graphus-local \
GRAPHUS_TARGET_TLS_INSECURE=1 \
examples/gds-analytics/run.sh
```

| Environment | Meaning |
|-------------|---------|
| `GRAPHUS_TARGET_BOLT`         | Bolt endpoint the official driver connects to (`bolt://` or `bolt+ssc://` for a self-signed cert). **Required** for attach mode (the driver speaks Bolt). |
| `GRAPHUS_TARGET_REST`         | REST base URL — used for `/auth/login`, the isolated-DB DDL, and `/metrics`. **Required** for attach mode. |
| `GRAPHUS_TARGET_USER/PASSWORD`| login (defaults `graphus` / `graphus-local`). |
| `GRAPHUS_TARGET_DB`           | when set, use this **existing** database and never create/drop one (the operator owns it); the workload still tears down its own data. When unset, a unique `ex_gds-analytics_<epoch>_<pid>` DB is created and dropped. |
| `GRAPHUS_TARGET_TLS_INSECURE` | `1` to accept a self-signed TLS cert on the target (REST `curl -k`). |

The attach run asserts: the workload reached the instance (`GRAPHUS_GDS_OK`), the `/metrics` snapshots
were captured, `measure_target`'s **external invariants** held (no statement/recovery panics, no
force-detach, and the server actually observed committed transactions over the window), and the report
is tagged `measurement_mode=external` with a `server_metrics` block. The isolated database is dropped on
exit.

> Attach mode is what `examples/CLAUDE.md` mandates for every example (“runnable against an
> already-running Graphus instance — local or remote”). It is **version-tolerant**: against an older
> instance the schema DDL and the write/mutate/stats modes it cannot honour are skipped with a note (see
> the schema and execution-mode version notes above), while the reference ground truth and the
> weighted-vs-unweighted comparison still run and assert.

### The hermetic default-`cargo test` mirror

`crates/graphus-server/tests/gds_analytics.rs` is the **npm-free, default-run** counterpart of
`analyze.js`: it generates the same seeded fast-profile graph via `graphus-gds-gen`, loads it into the
real engine **in process** via `LocalEngine` (the `gds.*` procedures are registered by default at
engine boot), projects + runs the suite through the same `Run` path Bolt/REST use, and asserts the
reference outputs (WCC partition, degree sequence, strictly-highest-betweenness bridge endpoints,
closeness ordering, triangle signature, PageRank symmetry/ordering, the shortest-path vector, and the
planted-field community recovery). It runs in the default `cargo test` — no Node, no network:

```bash
cargo test -p graphus-server --test gds_analytics
```

A companion hermetic test, `crates/graphus-server/tests/gds_analytics_schema.rs`, proves the **schema**
the example declares works end-to-end: it drives the generated DDL block through the real engine's
admin path, loads the influence network schema-first, and asserts `SHOW CONSTRAINTS` / `SHOW INDEXES`
report the constraints and indexes with the right kinds/types/entities (all `ONLINE`), that the
relationship RANGE index serves an equality seek but not a `>=` range (`rmp` #680), and that the
property-type / uniqueness constraints reject non-conforming writes:

```bash
cargo test -p graphus-server --test gds_analytics_schema
```

## Scalability, footprint & parallelism — what we measure (and why)

`gds_sweep` (a hermetic, deterministic binary) emits **two** honest measurements.

### 1. The graph-SIZE sweep

Varies **graph size** and reports, per size, with the library's **default** execution (parallel above
its threshold — exactly how the server runs the algorithms):

- the **wall time** of every algorithm (so PageRank's near-linear `O(k·(n+m))` and betweenness's
  `O(n·m)` cost are visible as the graph grows), and
- the **CSR-projection footprint** via `CsrGraph::memory_bytes()`, reduced to **bytes-per-node** and
  **bytes-per-edge**.

Measured CSR footprint is **~110–120 bytes/node and ~5.5–6.0 bytes/edge**, stable across sizes (a CSR
is a linear structure); betweenness time scales near-quadratically with size while PageRank stays
near-linear, exactly as the complexity bounds predict.

### 2. The parallelism demonstration (varies CORE COUNT)

At a single fixed graph size the sweep times each apples-to-apples parallel algorithm — PageRank,
betweenness, closeness, WCC, triangle counting, out-degree — under `Execution::sequential()` and under
`Execution::parallel_with_threshold(0)` inside **fixed-width `rayon` thread pools** (1, 2 and all
cores), and reports, into `sweep.json`'s `parallelism` object:

- per algorithm: `seq_ms`, `par_ms_by_width`, the `best_width`, `best_par_ms`, the real measured
  `speedup` (`seq_ms / best_par_ms`), and whether it was `deterministic` across widths;
- `max_speedup` — the headline speedup — and `deterministic_across_widths`.

Every number is measured **on the run** — the example never hardcodes a curve. On the reference
machine (linux/x86_64, 16 cores) the heavy per-source centralities show the clearest gains — e.g.
**closeness ~6.9× and Brandes betweenness ~6.7×** at the fast demo size — while the cheap,
memory-bandwidth-bound algorithms (out-degree, PageRank on a tiny graph) honestly show ~1× or below,
because at that size the `rayon` fan-out cost is not amortised. The magnitude varies with the host and
its load (which is why the gate only asserts a *real* speedup `> 1.0` on a multi-core host, never a
fixed figure); the **determinism is invariant** — the parallel result is identical to the sequential
one across every thread width, on every run.

## Evidence collected — how to read it

`evidence/` (git-ignored) holds:

- **`sweep.json`** — the raw per-size sweep (per-algorithm `timings_ms` + `csr_bytes`,
  `bytes_per_node`, `bytes_per_edge`) **plus** the `parallelism` object (the sequential-vs-parallel
  speedup across thread widths + the `deterministic_across_widths` verdict).
- **`report.json` / `report.md`** — the **standardized, schema-versioned** evidence report (the same
  `graphus-examples-harness` schema every `examples/*` emits).

### How per-algorithm metrics are represented in the standardized report

The harness `EvidenceReport` has fixed sections (cpu / memory / storage / throughput) with no native
"per-algorithm" row, and the example deliberately does **not** widen the schema. Instead it uses the
schema's existing flexible carriers:

- **`phases`** — **one phase per algorithm**, at the *reference* (largest swept) graph size, each
  phase's `millis` being that algorithm's wall time. This reads naturally in the report.md
  "Phase timings" table. *Per-algorithm wall time lives here.*
- **`workload`** params — the deterministic CSR-projection footprint at the reference size
  (`reference_csr_bytes`, `reference_csr_bytes_per_node`, `reference_csr_bytes_per_edge`), the swept
  sizes (`sweep_field_sizes`), the `algorithm_count`, the sweep's `sweep_measurements` count, and the
  loaded influence-network size (`loaded_network_nodes/rels`). *The structural footprint lives here —
  and this is what the baseline gate reads.*
- **`storage`** section — the live server's **real on-disk footprint**: the `graphus.store` image and
  the `graphus.wal` **directory** of `seg.<lsn>` segment files, with real `write_amplification` /
  `space_amplification` ratios against the generator's logical `graph.cypher` bytes. On the hermetic
  path there is no server, so the section is honestly zero (= not measured).
- **`dataset`** — the reference (largest swept) graph size (byte-stable for a fixed sweep seed).
- **`cpu` / `memory`** — the live server's real CPU seconds + peak RSS **when the driver path ran**;
  honest zeros on the hermetic path.
- **`throughput`** — the analyze workload's real `operations`, `ops_per_sec` and `p50/p99/p999`, from
  the driver's measured per-operation latencies. Honestly zero on the hermetic path (the sweep reports
  per-algorithm *wall time* — the `phases` above — not an operation rate).
- **`total_millis`** — the run's real wall-clock (sweep + driver load/analyze), passed in explicitly:
  the evidence binary runs *after* the workload and cannot bracket it.

> **Evidence honesty (`rmp #699`).** The `storage` section used to be populated *exclusively* from the
> CSR projection: `store_bytes` carried the projection's **resident** size while being documented as
> the on-disk store, `space_amplification` carried CSR **bytes-per-node** and `write_amplification`
> CSR **bytes-per-edge**, and `wal_bytes` was left at `0` — so the report claimed the run wrote no
> redo log at all, and the committed baseline read `space_amplification: 119.06` (a per-element cost
> sitting in a ratio field). The CSR figures were always *also* published, correctly named, as the
> `reference_csr_*` workload params, so the gate now reads them from there — same numbers, same 15%
> band, every field meaning what it says.

### Documented variance

The metrics fall into two stability classes:

- **Deterministic (byte-stable for a fixed seed + sweep sizes)** — the dataset graph size, the
  `algorithm_count`, and the CSR footprint (`reference_csr_bytes` / `reference_csr_bytes_per_node` /
  `reference_csr_bytes_per_edge`). These are identical across runs and hosts and across the
  driver/hermetic paths. *These are what the baseline gate holds to a tight band.*
- **Machine-/timing-variant** — per-algorithm wall time (the `phases`), CPU seconds, peak RSS, and
  the latency percentiles. These vary with CPU speed, the allocator, OS scheduling, and the live
  server's on-disk WAL. *These are NOT gated.* On the reference machine (linux/x86_64, 16 cores)
  betweenness dominates at ~1.8 s for the 4 320-node reference size while PageRank is ~2 ms and the
  cheap algorithms are sub-millisecond — useful as an order-of-magnitude shape, not an exact figure.

### The baseline regression gate

`baseline.json` (committed, at a non-git-ignored path) is a fast-profile reference run.
`gds_baseline_cmp` (in `graphus-gds-gen`) gates a fresh fast-profile run against it in two layers:

1. **Structural equality** — the reference graph size (`dataset.nodes/relationships`) and the
   `algorithm_count` must match the baseline **exactly** (integer-stable for a fixed seed). A drift
   here means the generator or the procedure surface changed.
2. **Tight-band CSR footprint** — the deterministic projection (`reference_csr_bytes`,
   `reference_csr_bytes_per_node`, `reference_csr_bytes_per_edge`, read from the workload params) is
   held to **15%**. The report's own sections are all machine- or path-variant here — the `storage`
   section is the live server's on-disk footprint, huge under the driver path and absent hermetically
   — so they are printed for visibility but nothing in them gates.

**Why 15% / why structural-only:** for a fixed seed + profile the generated graph — and therefore the
CSR projection — is byte-stable, so its footprint is the meaningful, reproducible regression signal; a
footprint drift beyond 15% is a genuine GDS-engine regression worth failing. CPU, RAM, and wall time
are machine-dependent, so gating them across the machines a baseline is shared between would be flaky.
The 15% band matches the fraud-oltp storage gate and absorbs the small `f64` re-serialisation
rounding a report round-trip can introduce.

## Components exercised

`graphus-server` (Bolt-TCP + TLS; the admin DDL path for `CREATE CONSTRAINT` / `CREATE INDEX` +
`SHOW CONSTRAINTS` / `SHOW INDEXES`), `graphus-bolt` + PackStream (the wire path), `graphus-cypher`
(the `gds.*` procedure surface + `CALL`/`YIELD`, the node property-type + uniqueness constraint
enforcement, and the relationship-index planner utilisation), `graphus-gds` (the CSR projection +
algorithm library), `graphus-storage` + `graphus-wal` (the durable store the projection is drained
from, plus the durable constraint/index catalog and the node/relationship RANGE indexes), and
`graphus-auth` (Bolt basic-auth over TLS). The hermetic mirror exercises the same `gds.*` semantics
in-process via `LocalEngine`; the evidence is produced by the dev-only `graphus-examples-harness` +
`graphus-gds-gen` (`gds_sweep`, `gds_evidence`, `gds_baseline_cmp` for local mode; `measure_target` +
the `harness.sh` external-target seam for attach mode) — none of which enter the production
`graphus-server` build.

In **attach mode** the exercised surface shifts to the wire + control plane: `graphus-server`'s REST
`/auth/login`, the `CREATE/STOP/DROP DATABASE` DDL that carves out and reclaims the isolated database,
and the Prometheus `/metrics` endpoint (the per-database transaction / query-duration / health-invariant
counters the server-side evidence is computed from) — all over the same Bolt+TLS driver path.
