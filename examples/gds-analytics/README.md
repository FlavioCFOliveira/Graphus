# Graph Data Science analytics

> **Status:** this README is a **stub** delivered with `rmp #257`–`#259` (scenario design, generator,
> reference subgraph, the full algorithm workload, and the scalability/footprint sweep). The
> evidence-report wiring, the human-readable findings, and the final polish land with `rmp #260`–
> `#263`.

A realistic, end-to-end demonstration of **graph data science (GDS) analytics** on Graphus: load a
seeded **academic influence / citation network**, run the full `gds.*` algorithm suite over the
in-memory CSR projection through the **procedure surface**, assert the results against an
**analytically-known reference subgraph**, and measure how the single-threaded GDS engine scales with
graph size (time + CSR footprint).

The official **Neo4j driver** (Node.js, `bolt+ssc://`) drives the live workload, exactly as the
driver ecosystem would.

## What it demonstrates

- **The `gds.*` procedure surface end to end** — `gds.graph.project` → the algorithm `*.stream`
  procedures → `gds.graph.drop`, over a real persistent store via the official driver.
- **The full algorithm library**: PageRank, degree / betweenness / closeness centrality, weakly- and
  strongly-connected components (WCC / SCC), triangle counting, Label Propagation community
  detection, and weighted shortest paths (Dijkstra / Bellman-Ford).
- **Correctness against ground truth** — a small reference subgraph with hand-derived outputs the
  workload asserts within a documented tolerance.
- **Honest performance characterisation** — a scalability + CSR-footprint sweep that reports what is
  *actually* measurable for a single-threaded engine, never a fabricated speedup curve.

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
| `large` | 4 000 (8 × 500) | 8 | ~48 k  | evidence-scale footprint |

Both inject the **same** reference subgraph, so the reference assertions are profile-independent.

## The reference subgraph (analytically-known ground truth)

Two 3-cliques `{b0,b1,b2}` and `{b3,b4,b5}` joined by a single bridge `b2─b3` (all `:LINKS` edges
undirected; the projection symmetrises them):

```
  clique A: (b0)──(b1)──(b2)──(b0)        clique B: (b3)──(b4)──(b5)──(b3)
                             └──────── bridge ────────┘
```

Over the undirected projection the outputs are hand-derivable, and `reference.json` carries them for
the workload to assert (all **verified against the real engine** during development):

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

### Community detection — an honest note

Graphus exposes **`gds.labelPropagation.stream`** for community detection. The task brief mentioned
*Louvain* and *node similarity*; **neither procedure exists in Graphus** (verified: the engine returns
`there is no procedure registered as gds.louvain.stream` / `gds.nodeSimilarity.stream`). The available
community algorithm is Label Propagation.

Graphus's Label Propagation is **synchronous and has no modularity-resolution parameter**, so on
small/dense graphs it **over-merges** (it collapses even two dense cliques joined by a single edge
into one community — measured). The example therefore recovers the planted **field** communities via
**WCC over the `:CITES`-only projection** (which is exact and deterministic), and runs
`labelPropagation` over the full network as part of the suite for completeness.

## How to run it

From the repository root:

```bash
examples/gds-analytics/run.sh                      # fast profile; official driver if node/npm present
GDS_PROFILE=large examples/gds-analytics/run.sh    # evidence-scale dataset
RUN_DRIVER=0      examples/gds-analytics/run.sh     # skip the official-driver step (hermetic only)
GDS_SWEEP_SIZES=40,120,360 examples/gds-analytics/run.sh   # custom sweep field sizes
```

Reuse pre-built binaries:

```bash
cargo build --release -p graphus-server -p graphus-gds-gen
GRAPHUS_BIN_DIR=target/release examples/gds-analytics/run.sh
```

The script:

1. generates the deterministic graph + `reference.json` (and proves byte-identical regeneration);
2. boots a real `graphus-server` over Bolt-TCP + TLS;
3. (opt-in) loads + analyses over Bolt via the official `neo4j-driver`, asserting the reference
   ground truth and recovering the planted communities;
4. runs the hermetic single-threaded scalability + CSR-footprint sweep.

## Scalability & footprint — what we measure (and why)

`graphus-gds` is a **zero-runtime-dependency, single-threaded** crate: there is **no rayon, no thread
pool, and no core-count knob** (no `RAYON_NUM_THREADS`, no config) anywhere in the algorithm library
or the `gds.*` procedure surface, and the server drives `Run` single-threaded. A speedup-vs-cores
curve would therefore be a fabrication.

Instead, `gds_sweep` (a hermetic, deterministic binary) varies the dimension that **is** meaningful —
**graph size** — and reports, per size:

- the **wall time** of every algorithm (so PageRank's near-linear `O(k·(n+m))` and betweenness's
  `O(n·m)` cost are visible as the graph grows), and
- the **CSR-projection footprint** via `CsrGraph::memory_bytes()`, reduced to **bytes-per-node** and
  **bytes-per-edge**.

The sweep writes `evidence/sweep.json` (machine-readable) for the evidence report. Measured CSR
footprint is **~110–120 bytes/node and ~5.5–6.0 bytes/edge**, stable across sizes (a CSR is a linear
structure); betweenness time scales near-quadratically with size while PageRank stays near-linear, as
the complexity bounds predict.

## Evidence collected

`evidence/` (git-ignored) holds the sweep JSON and — once `rmp #260`–`#263` wire it — the
standardized `report.json` + `report.md` covering CPU / memory / storage / throughput, plus the
human-readable findings.

## Components exercised

`graphus-server` (Bolt-TCP + TLS), `graphus-bolt` + PackStream (the wire path), `graphus-cypher` (the
`gds.*` procedure surface + `CALL`/`YIELD`), `graphus-gds` (the CSR projection + algorithm library),
`graphus-storage` + `graphus-wal` (the durable store the projection is drained from), and
`graphus-auth` (Bolt basic-auth over TLS).
