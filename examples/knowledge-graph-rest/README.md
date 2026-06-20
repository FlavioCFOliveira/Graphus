# knowledge-graph-rest

A realistic, end-to-end demonstration of serving a **knowledge graph over the Graphus REST API**.
It boots a real `graphus-server` exposing the REST transactional API over **HTTPS + Bearer-JWT
auth**, loads a deterministic, seeded knowledge graph, and drives the five canonical
knowledge-graph **discovery** queries against it from a **pure-stdlib `python3` client** — asserting
every answer against a known reference, demonstrating transactional begin/commit/rollback, streaming
a large result as **NDJSON**, negotiating **CBOR vs JSON**, and sustaining **concurrent** clients.

It doubles as an executable E2E test: `run.sh` exits non-zero the moment any assertion fails.

## What it demonstrates

| Capability | How |
| --- | --- |
| REST transactional API | autocommit (`POST /db/{db}/tx/commit`) + explicit tx (`/tx` → `/tx/{id}` → `/tx/{id}/commit`) + rollback (`DELETE /tx/{id}`) |
| TLS | the REST listener terminates TLS with a self-signed cert (production REST requires TLS) |
| Bearer-JWT auth | the client mints an HS256 JWT out of band and sends `Authorization: Bearer …`; an unauthenticated request is rejected `401` |
| Schema DDL over REST | `CREATE CONSTRAINT … REQUIRE … IS UNIQUE` (indexed entity lookup) + `CREATE INDEX … ON …` |
| Knowledge-graph discovery | entity lookup, multi-hop semantic traversal, recommendation, aggregation, concept-path — asserted against a known reference |
| NDJSON streaming | `Accept: application/x-ndjson` → one JSON object per line, parsed incrementally client-side |
| Content negotiation | the same query as JSON and CBOR, both decoding to the same logical result, with payload-size comparison |
| Concurrency | many concurrent HTTPS clients issuing the discovery workload with zero errors |

## The knowledge-graph model

A directed Label Property Graph modelling a research knowledge graph — documents, the people who
wrote them, the concepts they discuss, and the topics they are about:

| Node label | Key properties | Meaning |
| --- | --- | --- |
| `(:Author {id, name, affiliation})` | `id` UNIQUE | a researcher / writer |
| `(:Document {id, title, year})` | `id` UNIQUE | a paper / article |
| `(:Concept {id, name})` | `id` UNIQUE | a domain concept / term |
| `(:Topic {id, name})` | `id` UNIQUE | a broad subject area |

| Relationship | Direction | Meaning |
| --- | --- | --- |
| `:AUTHORED` | `(:Author)→(:Document)` | the author wrote the document |
| `:MENTIONS {count}` | `(:Document)→(:Concept)` | the document discusses the concept |
| `:CITES` | `(:Document)→(:Document)` | the document cites another document (acyclic — only earlier docs) |
| `:ABOUT` | `(:Document)→(:Topic)` | the document's broad subject |
| `:RELATED_TO {weight}` | `(:Concept)→(:Concept)` | a semantic link between two concepts |

Every entity carries a globally-unique string id (`a-<n>`, `d-<n>`, `c-<n>`, `t-<n>`). The loader
declares a `UNIQUE` constraint on each id, so entity lookups (`MATCH (c:Concept {id:…})`) are an
indexed seek, and a `Document.year` range index is declared too.

### The reference subgraph (known discovery answers)

On top of the generated background sits a small, **fixed** reference subgraph (all ids carry a
`ref-` prefix, disjoint from the background, so its answers are identical at every scale). The
workload runs the five discovery queries over the live server and asserts the answers match the
generator's `reference.json` exactly:

| # | Discovery pattern | Query shape | Known answer |
| --- | --- | --- | --- |
| 1 | **Entity lookup** | `MATCH (c:Concept {id:'ref-c-0'}) RETURN c.name` | `graphs` |
| 2 | **Multi-hop traversal** | `(:Author {id:'ref-a-0'})-[:AUTHORED]->(:Document)-[:MENTIONS]->(c:Concept)` distinct | `[ref-c-0, ref-c-1, ref-c-2]` |
| 3 | **Recommendation** | docs co-mentioning a concept with seed `ref-d-0`, ranked by shared count | `[(ref-d-1,1), (ref-d-2,1)]` |
| 4a | **Aggregation** | `count` of `ref-a-0`'s authored documents | `2` |
| 4b | **Aggregation** | most-mentioned concept across the reference docs (`sum(count)`) | `ref-c-0` (total `6`) |
| 5 | **Concept path** | `shortestPath` over `:RELATED_TO*` from `ref-c-0` to `ref-c-3` | length `3` |

## The deterministic generator — `crates/graphus-kg-gen`

A **dev-only leaf crate** (`publish = false`, depended upon by nothing — in particular **not**
`graphus-server`, so it adds zero overhead to the shipped binary). It emits:

- `graph.cypher` — the schema DDL + node/edge `CREATE` statements (one per line, `;`-terminated),
  followed by the fixed reference subgraph;
- `reference.json` — the reference subgraph + the hand-derived discovery answers above.

Generation is a pure function of `(seed, scale)` (an internal `SplitMix64` PRNG; no floats in the
graph structure, no `HashMap` iteration, no clock), so the artifacts are **byte-identical** across
runs, hosts, and platforms. `cargo test -p graphus-kg-gen` proves this. Two profiles:

| Profile | Topics | Concepts | Authors | Documents | Use |
| --- | --- | --- | --- | --- | --- |
| `fast` (default) | 6 | 80 | 120 | 400 | CI + the REST E2E assertions |
| `large` | 10 | 300 | 400 | 1500 | evidence-scale (bigger NDJSON stream) |

```bash
cargo run -p graphus-kg-gen --bin kg_gen -- --profile fast --out-dir /tmp/kg
```

## How the REST API is used

### Authentication (Bearer JWT, minted out of band)

Graphus's REST API has **no login endpoint** — Bearer tokens are minted out of band by anyone
holding the server's `jwt_secret`. The token is an **HS256 JWT** (`crates/graphus-auth/src/token.rs`)
carrying `sub` (the username), `exp`/`iat`, `iss`/`aud` (both `"graphus"`), a random `jti`, and a
credential-epoch `ver`. The server validates the signature, the `iss`/`aud` binding, that `sub`
names a live catalog user (the bootstrap admin qualifies), and that `ver ≥` the user's epoch (a fresh
admin is at epoch `0`). The python client mints this with the **standard library only**
(`hmac`/`hashlib`/`base64`/`json`) — no `PyJWT` dependency. An unauthenticated request is rejected
`401`, which the workload asserts.

### Request / response shapes (verified against `crates/graphus-rest`)

| Method & path | Purpose | Request body | Response |
| --- | --- | --- | --- |
| `POST /db/{db}/tx/commit` | one-shot autocommit | `{"statements":[{"statement":"…","parameters":{…}}]}` | `200` `{"results":[{"fields":[…],"data":[[…]],"summary":{…}}]}` |
| `POST /db/{db}/tx` | open explicit tx | `{"statements":[],"access_mode":"WRITE"}` | `201` `{"id":"tx-1","commit":"…","expires_at_nanos":…,"access_mode":"WRITE"}` |
| `POST /db/{db}/tx/{id}` | run in tx | `{"statements":[…]}` | `200` `{"results":[…],"id":"tx-1","expires_at_nanos":…}` |
| `POST /db/{db}/tx/{id}/commit` | commit | `{"statements":[]}` | `200` `{"results":[…]}` |
| `DELETE /db/{db}/tx/{id}` | rollback | — | `200` |

Request `parameters` may be **sparse** plain JSON (`{"id":"ref-c-0"}`). Response scalars are
**strict Jolt** sigil objects — `{"Z":"1"}` integer, `{"U":"x"}` string, `{"R":"1.5"}` float,
`{"?":"true"}` boolean — which the client decodes back. (See `crates/graphus-rest/src/value.rs`.)

### Content negotiation (`crates/graphus-rest/src/negotiate.rs`)

| `Accept` | Response |
| --- | --- |
| `application/json` / `*/*` / absent | Jolt typed JSON (default) |
| `application/cbor` | CBOR (RFC 8949) — the same logical structure, more compact |
| `application/x-ndjson` | NDJSON: a `{"fields":…}` line, one `{"row":…}` line per row, then a `{"summary":…}` line |

NDJSON is selected only when the client explicitly accepts `application/x-ndjson` **and** the request
carries exactly one statement.

> **Honest note on NDJSON memory.** The NDJSON **wire format** is one JSON object per line, and the
> python client parses it **incrementally** (it iterates the HTTP response line-by-line, never
> materializing the whole result before processing rows). The server-side row pump is *pull-based*
> (`ResultStream::next_row`), which is the seam a future async cursor would flush through per line;
> **today**, however, the router assembles the NDJSON body fully before responding
> (`stream_single_statement_ndjson` in `crates/graphus-rest/src/router.rs`), so current server-side
> memory for an NDJSON response is proportional to the result size. This example demonstrates the
> incremental **wire format + client-side streaming**, not yet bounded server-side memory; the README
> states this rather than overclaiming.

### Loading the graph

The schema DDL (`CREATE CONSTRAINT` / `CREATE INDEX`) runs as **standalone autocommit** statements
(Graphus rejects admin DDL inside an explicit transaction). The data then loads in **batched
autocommit transactions** — many `CREATE`/`MATCH…CREATE` statements per HTTP request — which is both
a transactional-semantics demonstration (each batch commits atomically) and a ~40× speedup over
one statement per request (measured: 1.9 s batched vs 85 s unbatched for the `fast` profile, where
edge creation resolves endpoints by a label scan).

## Running it

From the repository root:

```bash
examples/knowledge-graph-rest/run.sh
```

Reuse pre-built binaries and tune the workload:

```bash
cargo build --release -p graphus-server -p graphus-kg-gen
GRAPHUS_BIN_DIR=target/release \
  KG_PROFILE=large KG_CLIENTS=32 KG_OPS=40 \
  examples/knowledge-graph-rest/run.sh
```

| Env var | Default | Meaning |
| --- | --- | --- |
| `GRAPHUS_BIN_DIR` | `target/release` | where to find `graphus-server` / `kg_gen` (built if missing) |
| `KG_PROFILE` | `fast` | dataset scale (`fast` / `large`) |
| `KG_CLIENTS` | `16` | concurrent HTTP clients in the concurrency phase |
| `KG_OPS` | `20` | discovery queries per client |
| `KG_BATCH` | `200` | statements per load batch |

**Requirements:** a Unix host (Linux/macOS), `bash`, `openssl` (self-signed cert), and `python3`
(3.8+, **stdlib only** — no pip packages). The generator is hermetic and CI-runnable on its own; if
`openssl` or `python3` is absent, the REST workload is skipped with a clear note while the
byte-identical-generator assertion still runs.

## Evidence

The python client emits a single machine-readable `GRAPHUS_STATS {…}` line; `run.sh` parses it and
feeds it — together with the **live server process's** CPU + peak RSS and the on-disk store/WAL
footprint — into the dev-only `measure_server` harness, which writes the standardized, schema-versioned
**`evidence/report.json` + `evidence/report.md`** (the `evidence/` dir is git-ignored). The path is
printed in the run summary.

### What is measured

| Vector | Source | Example (`fast` profile, one developer machine) |
| --- | --- | --- |
| **HTTP requests/sec** | concurrency driver ops over the uptime window | ≈ 490 ops/s |
| **Latency p50 / p99 / p999** | per-request, measured client-side | ≈ 24.9 / 33.3 / 43.6 ms |
| **NDJSON streaming throughput** | rows/sec + bytes/sec of the streamed result | ≈ 403 rows, ≈ 348k rows/s, ≈ 13 MB/s |
| **Payload size per encoding** | response bytes for the SAME query as JSON vs CBOR | JSON `11665` B, CBOR `7207` B → **CBOR ≈ 61.8 % of JSON** |
| **Server CPU** | the live server PID's cumulative user+system seconds | ≈ 2.0 user + 0.2 sys s |
| **Peak server RAM (RSS)** | sampled from the live PID during the workload | ≈ 205 MB |
| **Storage footprint** | on-disk store + WAL bytes/pages after the load | store ≈ 0.72 MB, WAL ≈ 5.2 MB |
| **Dataset size** | nodes + relationships in the loaded graph | `616` nodes, `3770` relationships |

The headline `GRAPHUS_STATS` line (parsed into the report's `workload` + `throughput` sections):

```jsonc
{
  "loaded_statements": 4391, "load_secs": 1.83,
  "ndjson_rows": 403, "ndjson_bytes": 14869,
  "ndjson_rows_per_sec": 347513, "ndjson_bytes_per_sec": 12821774,
  "json_bytes": 11665, "cbor_bytes": 7207, "cbor_ratio": 0.618,  // CBOR ≈ 62% of JSON
  "concurrency_clients": 16, "concurrency_ops": 320, "concurrency_errors": 0,
  "ops_per_sec": 477, "p50_ms": 25.4, "p99_ms": 44.6, "p999_ms": 45.1
}
```

### How to read it — the STABLE vs MACHINE-VARIANT split

The evidence splits cleanly into two families, and the committed-baseline regression gate treats them
very differently:

- **Deterministic / structural** — byte-stable for a fixed seed + profile, so a drift is a genuine
  regression and they are gated **tightly** (exact, or a tiny band):
  - the **dataset size** (`616` nodes / `3770` relationships),
  - the **payload sizes per encoding** (`json_bytes`, `cbor_bytes`, `ndjson_rows`, `ndjson_bytes`) and
    the **CBOR/JSON ratio** (`cbor_ratio`, gated to ±0.01) — the headline numbers above,
  - the **on-disk store/WAL footprint** (gated to 15 %).
- **Machine- and timing-variant** — depend on the host's CPU speed, scheduler, allocator and OS, so
  they are **NOT gated** (they will differ run-to-run and machine-to-machine):
  - HTTP throughput (`ops_per_sec`), latency (`p50`/`p99`/`p999`), NDJSON rows/sec + bytes/sec,
  - server CPU seconds, peak RSS.

### Committed baseline + regression gate

`examples/knowledge-graph-rest/baseline.json` is a committed `fast`-profile reference report. On every
`fast`-profile run, `run.sh` compares the fresh report against it via the `kg_baseline_cmp` helper
(`crates/graphus-kg-gen/src/bin/kg_baseline_cmp.rs`): it holds the **deterministic** metrics above to
their tight bounds and ignores the **machine-variant** families, then prints `GRAPHUS_BASELINE_OK` and
asserts the gate passed. A drift in the payload bytes per encoding, the CBOR/JSON ratio, the dataset
size, or the storage footprint **fails the run**.

## Hermetic cargo mirror (default `cargo test`)

The example's REST scenario also runs as a **default-run, python-free, socket-free** cargo test:
`crates/graphus-server/tests/knowledge_graph_rest.rs`. It generates the SAME seeded `fast`-profile
graph (`graphus-kg-gen`), boots the **real** `graphus_rest` axum router over a real `LocalEngine` (via
the server's `RestEngineAdapter`) and drives it with `tower::ServiceExt::oneshot` — **no TLS, no
socket, no python**. It loads the graph over `POST /db/{db}/tx/commit`, asserts all five discovery
answers against the generator's reference, asserts the **NDJSON** framing, and asserts the **CBOR**
body decodes to the *same logical result* as the JSON body (the content-negotiation proof). Auth is
still live: the request carries a real Bearer JWT minted from the live `SecurityCatalog`, and an
unauthenticated request is asserted to be rejected `401`. Run it with:

```bash
cargo test -p graphus-server --test knowledge_graph_rest
```

Where this hermetic test proves the **REST router semantics + serialization** in CI, the shell
`run.sh` proves the full **wire path** (HTTPS + Bearer-JWT over a real socket, driven by the stdlib
python client) plus the standardized evidence collection.
