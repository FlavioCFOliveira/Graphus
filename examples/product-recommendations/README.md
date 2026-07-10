# Product recommendations — a read-heavy concurrency evaluation

A realistic, end-to-end demonstration of Graphus serving a **product-recommendation service** under
**many concurrent read-only connections and a trickle of writes**. Its purpose is to put the
**efficiency of concurrent connections, IO and response time** to the test and to **expose the
server's read-path bottlenecks** — where throughput saturates, where latency explodes, and whether
reads scale across CPU cores or hit the single-engine-thread ceiling.

It boots a **real `graphus-server`**, loads a large graph over the wire, drives a **concurrency
ladder** of simultaneous Bolt-over-UDS clients issuing recommendation queries, and collects explicit
evidence across every performance vector (CPU, RAM, storage, throughput, latency).

## What it demonstrates

1. **A recommendation domain modelled as a multigraph LPG** and the queries a real service runs.
2. **Loading a large graph over the network** with the ratified network bulk-import (Mode A) —
   `CREATE DATABASE` → streaming CSV upload → `START DATABASE` — rather than the `O(E·N)` per-edge
   Cypher path that does not scale.
3. **A production-realistic read-path schema** declared over the loaded graph — a **`VECTOR`** (HNSW)
   index for "similar products" ANN retrieval, a **`TEXT`** index for name search, and identity/type
   **constraints** (see [The recommendation schema](#the-recommendation-schema)).
4. **Read scaling under concurrency**: a ladder of increasing simultaneous connections, each running
   a weighted mix of simple point reads and heavy multi-hop / collaborative-filtering traversals,
   with the server's own CPU / RSS / IO sampled per rung so the **saturation knee** is visible.
5. **A read-heavy / write-light mix**: a small, rate-limited stream of new purchases runs
   concurrently with the reads (MVCC readers never block on the writer), so the scenario is a
   realistic "mostly reads" service rather than a pure read benchmark.

## The graph model

A multigraph Label Property Graph modelling a customer base and its purchasing behaviour:

| Node | Key properties | Meaning |
| --- | --- | --- |
| `(:User {id, name, country, signup})` | `id` (24-hex, unique) | a customer |
| `(:Product {id, name, category, price, embedding})` | `id` (24-hex, unique) | a catalogue item (`price` in cents; `embedding` a category-clustered `LIST<FLOAT>`) |

| Relationship | Direction | Meaning |
| --- | --- | --- |
| `:FRIEND {since}` | `(:User)-(:User)` undirected | a friendship (configuration-model multigraph, multi-edges kept) |
| `:PURCHASED {ts, qty}` | `(:User)->(:Product)` | the customer bought the product |

Purchases are drawn from a **popularity-skewed** distribution (a handful of products accrue most of
the sales), so dense **co-purchase clusters** emerge — the structure the "similar consumption
profile" recommendation needs to be meaningful. Each product also carries a small **`embedding`**
vector, **clustered by category** (one orthogonal axis per category), so a nearest-neighbour query at
a category centroid retrieves that category's products — the substrate for content-based "similar
products" retrieval. The generator (`reco_gen`) is fully deterministic: identical seed ⇒ byte-identical
CSV, across runs and platforms (integer-only math, no floats on the wire — the `embedding` too is
emitted through fixed-decimal integer formatting).

## The recommendation schema

Once the graph is online the loader declares the production-realistic **read-path schema** — the same
DDL the hermetic cargo mirror (`crates/graphus-server/tests/product_recommendations_schema.rs`)
drives — exercising the new index & constraint kinds a real recommendation service relies on:

| Object | Kind | Purpose |
| --- | --- | --- |
| `product_embedding` | **`VECTOR`** (HNSW, cosine) index on `Product.embedding` | "similar products" **k-NN** retrieval via `db.index.vector.queryNodes` |
| `product_name_text` | **`TEXT`** (trigram) index on `Product.name` | fast `p.name CONTAINS '…'` catalogue search |
| `user_id_key` | **`NODE KEY`** on `User.id` | present + unique customer identity; backs the `(:User {id})` anchor seek |
| `product_id_unique` | **`UNIQUE`** on `Product.id` | unique catalogue identity; backs the `(:Product {id})` anchor seek |
| `product_price_integer` | **property-type** `Product.price IS :: INTEGER` | `price` is an integer number of cents, never a float |

The loader then asserts, against the known dataset, that these index-backed paths behave correctly: a
**vector k-NN** seek at a category centroid returns that category's products; a **`TEXT` `CONTAINS`**
search resolves a product by a fragment of its name; and two **enforcement negatives** — a duplicate
`Product.id` and a non-integer `price` — are rejected. The `SHOW INDEXES` / `SHOW CONSTRAINTS` dump is
captured to `evidence/schema.txt`. (Identity constraints back the anchor seeks through the engine's
in-memory index set; like every constraint backing they surface under `SHOW CONSTRAINTS`, not
`SHOW INDEXES`, which lists only the durable index declarations — the two always-on `LOOKUP` indexes
plus the `TEXT` and `VECTOR` indexes.)

## The recommendation read battery

Every query anchors on `(:User {id: $id})`, an index seek (backed by the `user_id_key` `NODE KEY`),
with `$id` varying per operation (see [`src/queries.rs`](../../crates/graphus-reco-gen/src/queries.rs)):

| Family | Kind | What it computes |
| --- | --- | --- |
| `s_user` | point read | a customer's name + country |
| `s_purchases` | point read | a customer's own purchases |
| `s_degree` | point read | a customer's friend count |
| `r1_friends` | 1-hop rec. | products bought by **direct friends** the customer hasn't bought, ranked |
| `r2_fof` | 2-hop rec. | the same for **friend-of-friend** (2nd-level) reach |
| `r3_fof3` | 3-hop rec. | the same for **3rd-level** reach (the heaviest social traversal) |
| `r4_similar` | collaborative | **customers with a similar consumption profile** (co-purchase) → what they bought that you didn't |

The read mix is weighted ~45% cheap point reads / ~55% recommendation traversals (heaviest families
least frequent), modelling a real read-heavy service. The single write shape is a new
`(:User)-[:PURCHASED]->(:Product)` edge.

## How to run

```bash
examples/product-recommendations/run.sh                 # fast profile (CI-sized), builds if needed
RECO_PROFILE=large  examples/product-recommendations/run.sh    # evidence-scale sweep
RECO_READER_THREADS=4  examples/product-recommendations/run.sh # pin the reader pool to observe its effect
GRAPHUS_BIN_DIR=target/release  examples/product-recommendations/run.sh   # use pre-built binaries
```

The script is self-contained and doubles as an executable E2E test: it builds the binaries, generates
the graph, boots a real server (Bolt-over-UDS for the read driver + plaintext-loopback REST for the
bulk-import upload), loads the graph and declares the read-path schema, asserts the shape, the
index-backed query paths (vector k-NN + `TEXT` `CONTAINS`) and constraint enforcement, drives the
concurrency ladder, writes the evidence (including `evidence/schema.txt`), gates the fast profile
against the committed baseline, and exits non-zero the moment any assertion fails.

> **Platform note.** The per-rung **server** CPU / RSS / IO sampling reads `/proc/<pid>`, so the
> richest evidence is collected on **Linux**. On macOS the run still completes and reports client
> throughput + latency, but the server-side resource evidence is skipped.

### Profiles

| Profile | Users | Products | Ladder (connections) | Ops/rung | Writes |
| --- | --- | --- | --- | --- | --- |
| `fast` | ~2 000 | ~400 | 1, 2, 4, 8 | 1 500 | off |
| `large` | ~120 000 | ~8 000 | 1, 2, 4, 8, 16, 32, 64 | 20 000 | 1 / 50 ms |

## The pieces

All live in the dev-only leaf crate
[`graphus-reco-gen`](../../crates/graphus-reco-gen) (depended upon by nothing in the shipped server):

- **`reco_gen`** — the deterministic generator: streams the graph as neo4j-admin-import-flavoured CSV
  (`users.csv`, `products.csv`, `friends.csv`, `purchased.csv`) + a summary line.
- **`reco_load`** — the REST-only loader: `POST /auth/login` → `CREATE DATABASE` → streaming
  bulk-import (Mode A) → `START DATABASE` → declares the read-path schema (`VECTOR` + `TEXT` indexes,
  `NODE KEY` + `UNIQUE` + property-type constraints, shared via `graphus_reco_gen::schema`) → shape +
  vector-k-NN + `TEXT`-`CONTAINS` + constraint-enforcement + recommendation-query asserts.
- **`reco_bench`** — the concurrent UDS-Bolt read driver: sweeps the ladder, records throughput +
  latency percentiles per rung and per family, samples the server's CPU (total + per-thread), RSS and
  IO, and diagnoses the saturation knee.
- **`reco_baseline_cmp`** — the structural-metric regression gate.

## The evidence it collects

Written at run time to the git-ignored `evidence/` directory as `report.json` (the stable, versioned
schema shared by every example) + `report.md` (human-readable) + `schema.txt` (the `SHOW INDEXES` /
`SHOW CONSTRAINTS` dump proving the exercised index/constraint kinds):

- **Throughput / latency** — per-rung operations-per-second and p50 / p90 / p99 / p99.9 / max latency,
  overall and per query family; the write abort rate when the writer is on.
- **CPU** — the server's user / system CPU-seconds and **mean core utilisation** at the best rung;
  the per-rung busy-thread count and busiest-thread core-fraction (the single-engine-thread vs
  reader-pool signal).
- **Memory** — the server's peak and final RSS.
- **The knee** — an explicit diagnosis of the rung at which throughput saturated, whether p99 kept
  climbing past it, and how many cores/threads the server actually used at saturation.

The `fast` profile's committed [`baseline.json`](baseline.json) is gated on the **structural**
metrics only (realised node / relationship + per-label counts, deterministic for a fixed seed +
profile); the machine- and timing-variant families (throughput, latency, CPU, RSS) are informational,
never a pass/fail.

## Reading the result

The point of the ladder is to make a bottleneck **visible**:

- If throughput keeps climbing with connections and multiple server cores stay busy, off-thread
  concurrent reads (the reader pool) are scaling.
- If throughput plateaus early while p99 latency climbs and only ~1 server core is pinned, the
  workload is funnelling through a single thread — the exact ceiling to investigate.

Either way the evidence is empirical: compare the per-rung table and the `report.md` knee diagnosis,
and try `RECO_READER_THREADS` to see the reader pool's effect directly.
