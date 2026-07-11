# Product recommendations — a read-heavy concurrency evaluation

A realistic, end-to-end demonstration of Graphus serving a **product-recommendation service** under
**many concurrent read-only connections and a trickle of writes**. Its purpose is to put the
**efficiency of concurrent connections, IO and response time** to the test and to **expose the
server's read-path bottlenecks** — where throughput saturates, where latency explodes, and whether
reads scale across CPU cores or hit the single-engine-thread ceiling.

It runs in two modes. **Local** (default) boots a **real `graphus-server`**, loads a large graph over
the wire, and drives a **concurrency ladder** of simultaneous Bolt-over-UDS clients while sampling the
server's per-thread CPU/RSS/IO from `/proc`. **External / attach** (any `GRAPHUS_TARGET_*` set) drives
the *same* ladder against an **already-running instance** (local or remote, e.g. pi516) over
**Bolt-over-TCP + TLS**, in a dedicated isolated database, and collects server-side evidence from the
target's Prometheus `/metrics` (there is no co-located pid to sample). Either way it collects explicit
evidence across the performance vectors it can observe (throughput, latency, and — locally — CPU / RAM
/ IO).

> **Re-captured on current main.** The concurrency verdict here was re-measured **after** the
> sprint-47 lock-free snapshot-isolation landing (`#543`/`#545`), which routes standalone auto-commit
> reads off the single engine thread onto the reader pool. The old committed narrative — reads pinned
> to a single-thread ceiling — predates that work; on a current server the read ladder **scales across
> cores** off the reader pool (see [Reading the result](#reading-the-result)).

## What it demonstrates

1. **A recommendation domain modelled as a multigraph LPG** and the queries a real service runs.
2. **Loading a large graph over the network** with the ratified network bulk-import (Mode A) —
   `CREATE DATABASE` → streaming CSV upload → `START DATABASE` — rather than the `O(E·N)` per-edge
   Cypher path that does not scale.
3. **A production-realistic read-path schema** declared over the loaded graph — a **`VECTOR`** (HNSW)
   index for "similar products" ANN retrieval, a **`TEXT`** index for name search, and identity/type
   **constraints** (see [The recommendation schema](#the-recommendation-schema)).
4. **Read scaling under concurrency**: a ladder of increasing simultaneous connections, each running
   a weighted mix of simple point reads and heavy multi-hop / collaborative-filtering traversals. In
   local mode the server's own CPU / RSS / IO is sampled per rung so the **saturation knee** and the
   cores-busy-at-saturation are visible; in attach mode the same signal comes from the client-side
   throughput-vs-concurrency curve plus the `/metrics` before/after delta.
5. **A read-heavy / write-light mix**: a small, rate-limited stream of new purchases runs
   concurrently with the reads (MVCC readers never block on the writer), so the scenario is a
   realistic "mostly reads" service rather than a pure read benchmark. The `--writers N` knob scales
   the concurrent-writer count for MVCC/SSI contention.
6. **Two load-generation regimes**: the default **closed-loop** zero-think-time saturation probe, and
   an **open-loop** fixed-arrival-rate mode (`--target-rps`) that measures latency from each op's
   *scheduled* time, so a slow server surfaces as growing latency rather than a throttled arrival rate
   (eliminating coordinated omission).

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

### Local (self-booted server)

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

### Attach to an already-running instance (Bolt-TCP + TLS)

Setting any of `GRAPHUS_TARGET_{BOLT,REST,UDS}` switches to **external** mode: no server is booted, the
work is isolated in a dedicated database that is dropped on exit, and server-side evidence comes from
the target's `/metrics`. The graph is loaded over Bolt with `UNWIND`-batched writes and a
**version-tolerant** minimal schema (range indexes on the anchor properties; the modern
VECTOR/property-type DDL is skipped — an older server may not support it), so the reader-pool-scaling
ladder runs against whatever schema the target accepts.

```bash
GRAPHUS_TARGET_BOLT=bolt+ssc://100.89.148.30:7687 \
GRAPHUS_TARGET_REST=https://100.89.148.30:7474 \
GRAPHUS_TARGET_USER=graphus GRAPHUS_TARGET_PASSWORD=graphus-local \
GRAPHUS_TARGET_TLS_INSECURE=1 \
  examples/product-recommendations/run.sh
```

`bolt+ssc://` accepts a self-signed certificate (the traffic stays encrypted; the peer is not
authenticated) — the mode for demo boxes like pi516; use `bolt+s://` against a server whose cert
chains to a public root. External-mode knobs (all optional): `RECO_EXTERNAL_LADDER` (default
`1,2,4,8,16`), `RECO_EXTERNAL_OPS` (default `2000`), `RECO_WRITERS` (default `0`),
`RECO_WRITE_EVERY_MS` (default `0`), `RECO_TARGET_RPS` (default `0` = closed-loop),
`RECO_MIN_OPS_PER_CLIENT` (default `150`), `RECO_AUTO_EXTEND` (default `1`).

### Profiles

| Profile | Users | Products | Ladder (connections) | Ops/rung | Writes |
| --- | --- | --- | --- | --- | --- |
| `tiny` (external default) | ~300 | ~50 | 1, 2, 4, 8, 16 (+ auto-extend) | 2 000 | off |
| `fast` (local) | ~2 000 | ~400 | 1, 2, 4, 8 | 1 500 | off |
| `large` (local) | ~120 000 | ~8 000 | 1, 2, 4, 8, 16, 32, 64 | 20 000 | 1 / 50 ms |

Attach mode defaults to the small **`tiny`** graph so the whole graph loads quickly over Bolt
`UNWIND` writes even against a small/remote box or an older server whose planner does not index-seek
on an `UNWIND`-row-valued anchor (it falls back to a scan). Set `RECO_EXTERNAL_PROFILE=fast` against a
current server for the full-size graph.

### Driver knobs (both modes)

- `--ladder`/`RECO_EXTERNAL_LADDER` — the concurrency ladder; **`--auto-extend`** keeps doubling the
  client count past the top rung until throughput plateaus, so the knee is found even past the host's
  core count.
- `--min-ops-per-client` — a per-client op floor (`clients × N`) that keeps per-family sample counts
  from collapsing as the ladder widens (the effective per-rung budget is `max(ops_per_rung, clients ×
  N)`).
- `--writers N` — the number of concurrent low-rate writers (MVCC/SSI contention against the readers).
- `--target-rps R` — open-loop mode: a fixed total arrival rate; latency is measured from each op's
  scheduled time (coordinated-omission-free). `0` = closed-loop saturation.

## The pieces

All live in the dev-only leaf crate
[`graphus-reco-gen`](../../crates/graphus-reco-gen) (depended upon by nothing in the shipped server):

- **`reco_gen`** — the deterministic generator: streams the graph as neo4j-admin-import-flavoured CSV
  (`users.csv`, `products.csv`, `friends.csv`, `purchased.csv`) + a summary line.
- **`reco_load`** — the loader, two transports. **`--rest`** (local): `POST /auth/login` →
  `CREATE DATABASE` → streaming bulk-import (Mode A) → `START DATABASE` → declares the full read-path
  schema (`VECTOR` + `TEXT` indexes, `NODE KEY` + `UNIQUE` + property-type constraints, shared via
  `graphus_reco_gen::schema`) → shape + vector-k-NN + `TEXT`-`CONTAINS` + constraint-enforcement +
  recommendation-query asserts. **`--bolt`** (attach): loads into the harness-created isolated DB over
  Bolt-TCP+TLS with `UNWIND`-batched writes + best-effort range indexes (version-tolerant), then
  asserts the shape + that every recommendation family returns a well-formed result.
- **`reco_bench`** — the concurrent Bolt read driver over **`--socket`** (UDS, local) or **`--bolt`**
  (TCP+TLS, attach): sweeps the ladder, records throughput + latency percentiles per rung and per
  family; in local mode it samples the server's CPU (total + per-thread), RSS and IO and diagnoses the
  saturation knee; in attach mode it prints machine-readable client-side stats sentinels that `run.sh`
  folds into the `measure_target` report. Supports open-loop (`--target-rps`), multiple writers
  (`--writers`), a per-family sample floor (`--min-ops-per-client`), and ladder auto-extension
  (`--auto-extend`).
- **`reco_baseline_cmp`** — the structural-metric regression gate (local fast profile).
- **`measure_target`** (shared harness binary) — emits the external-mode `report.json` from the two
  `/metrics` snapshots + the client-measured throughput/latency, and runs the host-independent
  invariant gate (`--assert`).

## The evidence it collects

Written at run time to the git-ignored `evidence/` directory as `report.json` (the stable, versioned
schema shared by every example) + `report.md` (human-readable), plus `schema.txt` in local mode (the
`SHOW INDEXES` / `SHOW CONSTRAINTS` dump proving the exercised index/constraint kinds).

**Local mode** (`measurement_mode: "host"`) — the full co-located evidence:

- **Throughput / latency** — per-rung operations-per-second and p50 / p90 / p99 / p99.9 / max latency,
  overall and per query family; the write abort rate when the writer is on.
- **CPU** — the server's user / system CPU-seconds and **mean core utilisation** at the best rung;
  the per-rung busy-thread count and busiest-thread core-fraction (the single-engine-thread vs
  reader-pool signal).
- **Memory** — the server's peak and final RSS.
- **Storage** — the recommendation database's real on-disk footprint: the `graphus.store` image and
  the `graphus.wal` **directory** of `seg.<lsn>` segment files, plus real `write_amplification` /
  `space_amplification` ratios against the generator's logical CSV bytes.
- **The knee** — an explicit diagnosis of the rung at which throughput saturated, whether p99 kept
  climbing past it, and how many cores/threads the server actually used at saturation.

> **Evidence honesty (`rmp #699`).** The whole storage section used to be left at **zero** — store
> bytes, WAL bytes and both amplification ratios — even though a real store sat on disk for the entire
> ladder, so the report asserted a durable-write workload had no durable footprint. `total_millis` was
> likewise the report's own *emission* time (the committed baseline read `0.027` ms for a ~16-second
> ladder); it is now the ladder's real wall-clock.

**Attach mode** (`measurement_mode: "external"`) — process CPU/RSS and on-disk storage are **N/A**
(the server is remote/not owned), so they are honestly zeroed. The evidence is:

- **Client-side** throughput + latency percentiles (best rung) and the full per-rung scaling curve
  (as report notes), plus the client-side scaling verdict.
- **Server-side** the `/metrics` before/after delta (`server_metrics`): committed / aborted
  transactions, the query-duration histogram, and the health invariants (statement panics, recovery
  panics, force-detached). `measure_target --assert` fails the run if any invariant is violated or the
  server observed no work over the window.

The `fast` profile's committed [`baseline.json`](baseline.json) is gated (local mode only) on the
**structural** metrics only (realised node / relationship + per-label counts, deterministic for a
fixed seed + profile); the machine- and timing-variant families (throughput, latency, CPU, RSS) are
informational, never a pass/fail. Attach mode gates on the host-independent invariants instead.

## Reading the result

The point of the ladder is to make the read-path behaviour **visible**:

- If throughput keeps climbing with connections and multiple server cores stay busy, off-thread
  concurrent reads (the reader pool) are scaling.
- If throughput plateaus early while p99 latency climbs and only ~1 server core is pinned, the
  workload is funnelling through a single thread — the ceiling to investigate.

**What the re-captured baseline shows.** The read ladder was re-measured on current `main`, i.e.
**after** the sprint-47 lock-free snapshot-isolation landing (`#543`/`#545`) that dispatches standalone
auto-commit reads off the single engine thread onto the **reader pool**. Where the *old* committed
narrative recorded a single-thread ceiling (peak throughput at ~1 client, ~1.0 server cores busy),
reads now **scale with concurrency**: throughput keeps rising as clients are added and the server
spreads the work across cores until it saturates the available cores rather than one engine thread.
The exact numbers are host-dependent (they vary with core count, allocator, and load) — which is why
the committed baseline gates only on the *structural* counts and the performance figures are read off
each run's `report.md` / `report.json`.

In **attach mode** against a remote box (e.g. pi516, a 4-core Raspberry Pi), the same signal appears
as the client-side throughput-vs-concurrency curve rising to a plateau near the host's core count,
corroborated by the `/metrics` `server_metrics` delta (the committed-transaction count climbing with
the workload). There is no `/proc` per-thread breakdown remotely, so the client-side scaling verdict
and the `/metrics` delta are the core-scaling evidence.

Either way the evidence is empirical: compare the per-rung table and the `report.md` / report notes,
and (locally) try `RECO_READER_THREADS` to see the reader pool's effect directly.
