# Graph Data Science analytics

A realistic, end-to-end demonstration of **graph data science (GDS) analytics** on Graphus: load a
seeded **academic influence / citation network**, run the full `gds.*` algorithm suite over the
in-memory CSR projection through the **procedure surface**, assert the results against an
**analytically-known reference subgraph**, and characterise how the single-threaded GDS engine scales
with graph size (per-algorithm time + CSR footprint).

The official **Neo4j driver** (Node.js, `bolt+ssc://`) drives the live workload, exactly as the
driver ecosystem would. A **hermetic cargo mirror** (`crates/graphus-server/tests/gds_analytics.rs`)
asserts the same reference ground truth in-process, in the default `cargo test` run, with no
Node/network.

## What it demonstrates

- **The `gds.*` procedure surface end to end** — `gds.graph.project` → the algorithm `*.stream`
  procedures → `gds.graph.drop`, over a real persistent store via the official driver.
- **The full algorithm library**: PageRank, degree / betweenness / closeness centrality, weakly- and
  strongly-connected components (WCC / SCC), triangle counting, Label Propagation community
  detection, and weighted shortest paths (Dijkstra / Bellman-Ford).
- **Correctness against ground truth** — a small reference subgraph with hand-derived outputs the
  workload asserts EXACTLY (within a documented float tolerance).
- **Honest performance characterisation** — a scalability + CSR-footprint sweep that reports what is
  *actually* measurable for a single-threaded engine, never a fabricated speedup curve, captured into
  a standardized, schema-versioned evidence report.

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

**Honest note 1 — GDS is single-threaded.** `graphus-gds` is a zero-runtime-dependency,
**single-threaded** crate: there is **no rayon, no thread pool, and no core-count knob** anywhere in
the algorithm library or the `gds.*` surface, and the server drives `Run` single-threaded. A
speedup-vs-cores curve would therefore be a fabrication, so the scalability sweep varies the one
dimension that *is* meaningful — **graph size** (see below).

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

## How to run it

From the repository root:

```bash
examples/gds-analytics/run.sh                      # fast profile; official driver if node/npm present
GDS_PROFILE=large examples/gds-analytics/run.sh    # evidence-scale dataset
RUN_DRIVER=0      examples/gds-analytics/run.sh     # skip the official-driver step (hermetic only)
GDS_SWEEP_SIZES=40,120,360 examples/gds-analytics/run.sh   # custom sweep field sizes
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
2. runs the hermetic single-threaded scalability + CSR-footprint sweep (`evidence/sweep.json`);
3. (opt-in) boots a real `graphus-server` over Bolt-TCP + TLS, loads + analyses over Bolt via the
   official `neo4j-driver`, asserting the reference ground truth and recovering the planted
   communities;
4. emits the standardized `report.json` + `report.md` (per-algorithm timings + CPU/RAM/storage) and
   gates a fresh fast-profile run against the committed `baseline.json`;
5. tears everything down (trap-driven: the server is killed and the private temp dir removed on exit)
   and exits non-zero if any assertion failed.

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

## Scalability & footprint — what we measure (and why)

`gds_sweep` (a hermetic, deterministic binary) varies **graph size** — the only meaningful dimension
for a single-threaded engine — and reports, per size:

- the **wall time** of every algorithm (so PageRank's near-linear `O(k·(n+m))` and betweenness's
  `O(n·m)` cost are visible as the graph grows), and
- the **CSR-projection footprint** via `CsrGraph::memory_bytes()`, reduced to **bytes-per-node** and
  **bytes-per-edge**.

Measured CSR footprint is **~110–120 bytes/node and ~5.5–6.0 bytes/edge**, stable across sizes (a CSR
is a linear structure); betweenness time scales near-quadratically with size while PageRank stays
near-linear, exactly as the complexity bounds predict.

## Evidence collected — how to read it

`evidence/` (git-ignored) holds:

- **`sweep.json`** — the raw per-size sweep (per-algorithm `timings_ms` + `csr_bytes`,
  `bytes_per_node`, `bytes_per_edge`).
- **`report.json` / `report.md`** — the **standardized, schema-versioned** evidence report (the same
  `graphus-examples-harness` schema every `examples/*` emits).

### How per-algorithm metrics are represented in the standardized report

The harness `EvidenceReport` has fixed sections (cpu / memory / storage / throughput) with no native
"per-algorithm" row, and the example deliberately does **not** widen the schema. Instead it uses the
schema's existing flexible carriers:

- **`phases`** — **one phase per algorithm**, at the *reference* (largest swept) graph size, each
  phase's `millis` being that algorithm's wall time. This reads naturally in the report.md
  "Phase timings" table. *Per-algorithm wall time lives here.*
- **`workload`** params — the structural CSR footprint at the reference size (`reference_csr_bytes`,
  `reference_csr_bytes_per_node`, `reference_csr_bytes_per_edge`), the swept sizes
  (`sweep_field_sizes`), the `algorithm_count`, the loaded influence-network size
  (`loaded_network_nodes/rels`), and — when the driver path ran — the live server's on-disk footprint
  (`server_store_bytes` / `server_wal_bytes`). *Structural/footprint metrics live here.*
- **`storage`** section — populated **exclusively** from the deterministic CSR footprint:
  `store_bytes` = reference CSR total bytes, `space_amplification` = CSR bytes-per-node,
  `write_amplification` = CSR bytes-per-edge. (The live server's on-disk store/WAL is path-dependent —
  huge under the driver path, zero hermetically — so it is *not* put in the gated storage section,
  only in the workload params above.)
- **`dataset`** — the reference (largest swept) graph size (byte-stable for a fixed sweep seed).
- **`cpu` / `memory`** — the live server's real CPU seconds + peak RSS **when the driver path ran**;
  honest zeros on the hermetic path.
- **`throughput`** — `operations` = the analyze-workload op count (driver path) or the sweep
  measurement count (hermetic); `p50/p99/p999` from the driver's measured per-operation latencies.

### Documented variance

The metrics fall into two stability classes:

- **Deterministic (byte-stable for a fixed seed + sweep sizes)** — the dataset graph size, the
  `algorithm_count`, and the CSR footprint (`store_bytes` / `bytes_per_node` / `bytes_per_edge`).
  These are identical across runs and hosts and across the driver/hermetic paths. *These are what the
  baseline gate holds to a tight band.*
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
2. **Tight-band footprint** — the deterministic CSR footprint (`storage.store_bytes`,
   `space_amplification` = bytes/node, `write_amplification` = bytes/edge) is held to **15%** via the
   harness's `compare_to_baseline`; throughput / latency / CPU / memory are given an effectively
   infinite tolerance.

**Why 15% / why structural-only:** for a fixed seed + profile the generated graph — and therefore the
CSR projection — is byte-stable, so its footprint is the meaningful, reproducible regression signal; a
footprint drift beyond 15% is a genuine GDS-engine regression worth failing. CPU, RAM, and wall time
are machine-dependent, so gating them across the machines a baseline is shared between would be flaky.
The 15% band matches the fraud-oltp storage gate and absorbs the small `f64` re-serialisation
rounding a report round-trip can introduce.

## Components exercised

`graphus-server` (Bolt-TCP + TLS), `graphus-bolt` + PackStream (the wire path), `graphus-cypher` (the
`gds.*` procedure surface + `CALL`/`YIELD`), `graphus-gds` (the CSR projection + algorithm library),
`graphus-storage` + `graphus-wal` (the durable store the projection is drained from), and
`graphus-auth` (Bolt basic-auth over TLS). The hermetic mirror exercises the same `gds.*` semantics
in-process via `LocalEngine`; the evidence is produced by the dev-only `graphus-examples-harness` +
`graphus-gds-gen` (`gds_sweep`, `gds_evidence`, `gds_baseline_cmp`) — none of which enter the
production `graphus-server` build.
