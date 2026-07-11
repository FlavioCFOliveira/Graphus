# knowledge-graph-rest

A realistic, end-to-end demonstration of serving a **knowledge graph over the Graphus REST API**.
It boots a real `graphus-server` exposing the REST transactional API over **HTTPS + Bearer-JWT
auth** (obtained from **`POST /auth/login`**), loads a deterministic, seeded knowledge graph
**schema-first** (a **FULLTEXT** title-search index, a `Document.year` **RANGE** index, four unique-id
constraints and node **property-type** + **existence** constraints), and drives the canonical
knowledge-graph **discovery** queries against it from a **pure-stdlib `python3` client** — asserting
every answer against a known reference, running the **full-text title search** and proving
property-type/existence violations are **rejected**, demonstrating transactional
begin/commit/rollback, streaming a large result as **NDJSON**, negotiating **CBOR vs JSON**, and
sustaining **concurrent READ** clients (each read carries `access_mode: "READ"` so it engages the
server's **off-thread reader pool** and scales across cores).

It doubles as an executable E2E test: `run.sh` exits non-zero the moment any assertion fails. It runs
either against a **self-booted** local server (default) or, via the shared external-target seam,
against an **already-running** instance — local or remote — isolated in a dedicated database (see
[Running against an external target](#running-against-an-external-target)).

## What it demonstrates

| Capability | How |
| --- | --- |
| REST transactional API | autocommit (`POST /db/{db}/tx/commit`) + explicit tx (`/tx` → `/tx/{id}` → `/tx/{id}/commit`) + rollback (`DELETE /tx/{id}`) |
| TLS | the REST listener terminates TLS with a self-signed cert (production REST requires TLS) |
| Bearer-JWT auth | the client obtains a token from `POST /auth/login` (username + password) and sends `Authorization: Bearer …`; an unauthenticated request is rejected `401` |
| Schema DDL over REST | `CREATE CONSTRAINT … REQUIRE … IS UNIQUE` (indexed entity lookup), node **property-type** (`… IS :: INTEGER`) + **existence** (`… IS NOT NULL`) constraints, a `Document.year` **RANGE** index, and a **FULLTEXT** title index (`CREATE FULLTEXT INDEX … ON EACH [d.title]`) |
| Schema evidence | `SHOW INDEXES` / `SHOW CONSTRAINTS` captured to `evidence/schema_evidence.json`, asserting the FULLTEXT/RANGE indexes and the constraints are declared and `ONLINE` |
| Full-text search | `CALL db.index.fulltext.queryNodes('document_fulltext', '<term>')` — analyzer-tokenized, relevance-ranked title search asserted against the known reference documents |
| Constraint enforcement | a Document with a non-integer `year` (property-type) and one with a missing `title` (existence) are each rejected `400` (RFC 9457 problem+json) |
| Knowledge-graph discovery | entity lookup, multi-hop semantic traversal, recommendation, aggregation, concept-path — asserted against a known reference |
| NDJSON streaming | `Accept: application/x-ndjson` → one JSON object per line, parsed incrementally client-side |
| Content negotiation | the same query as JSON and CBOR, both decoding to the same logical result, with payload-size comparison |
| Concurrency | many concurrent HTTPS clients issuing the discovery workload with zero errors — each read sent `access_mode: "READ"` so it dispatches to the **off-thread reader pool**, over a **keep-alive** connection per client |

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
indexed seek.

### The search schema (declared over REST, schema-first)

Beyond the unique-id constraints, the loader declares a production-realistic **search + integrity**
schema. The seed data conforms to every constraint, so the schema-first load succeeds:

| DDL | Kind | Purpose |
| --- | --- | --- |
| `CREATE FULLTEXT INDEX document_fulltext FOR (d:Document) ON EACH [d.title]` | **FULLTEXT** index | the canonical knowledge-graph **title search** — analyzer-tokenized, relevance-ranked, over the whole corpus |
| `CREATE INDEX document_year_range FOR (d:Document) ON (d.year)` | **RANGE** index | accelerate year filters / sorts |
| `CREATE CONSTRAINT document_year_integer FOR (d:Document) REQUIRE d.year IS :: INTEGER` | node **property-type** | every `Document.year` is an `INTEGER` (never a `FLOAT`) |
| `CREATE CONSTRAINT document_title_exists FOR (d:Document) REQUIRE d.title IS NOT NULL` | node **existence** | every `Document` carries a `title` |
| `CREATE CONSTRAINT <label>_id_unique FOR (x:<Label>) REQUIRE x.id IS UNIQUE` (×4) | node **uniqueness** | indexed entity lookup by id |

**Full-text title search.** The FULLTEXT index is queried with the built-in procedure:

```cypher
CALL db.index.fulltext.queryNodes('document_fulltext', 'graph') YIELD node, score
  RETURN node.id AS id, score
```

The `standard` analyzer tokenizes on non-alphanumeric boundaries, lowercases, and drops stop-words,
but **does not stem** — so `graph` and `graphs` are *distinct* terms. Over the fixed reference
documents (`ref-d-0` "On Graph Storage", `ref-d-1` "Traversal Methods", `ref-d-2` "Indexed Graphs")
the workload asserts the exact, enumerable answer for each term (the `Document <n>` background titles
never contain these terms):

| Search term | Matches | Why |
| --- | --- | --- |
| `graph` | `[ref-d-0]` | "On **Graph** Storage" — **not** "Indexed Graphs" (`graphs` ≠ `graph`, no stemming) |
| `graphs` | `[ref-d-2]` | "Indexed **Graphs**" — the no-stemming contrast to `graph` |
| `storage` | `[ref-d-0]` | "On Graph **Storage**" |
| `traversal` | `[ref-d-1]` | "**Traversal** Methods" |
| `on` | `[]` | a stop-word-only query matches nothing |

**Constraint enforcement (negative tests).** The workload also proves the constraints are *enforced*,
not merely declared: a `Document` written with a non-integer `year` (property-type) and one written
without a `title` (existence) are each **rejected `400`** (an RFC 9457 problem+json), and the count of
`Document` nodes is unchanged (the rejected writes rolled back atomically).

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

### Authentication (Bearer JWT via `POST /auth/login`)

Graphus's REST API exposes a **login endpoint**: `POST /auth/login` (`crates/graphus-rest`, rmp #499)
takes a JSON `{"username","password"}` body and returns `{"token","token_type":"Bearer",
"expires_at_unix_secs"}`. The python client posts the admin credentials and uses the returned token as
`Authorization: Bearer …` on every subsequent request — **no client-side token minting and no shared
`jwt_secret` on the client**. (The server still needs a non-default `jwt_secret` to *sign* the token
it mints; the client never sees it.)

The token is an **HS256 JWT** (`crates/graphus-auth/src/token.rs`) carrying `sub` (the username),
`exp`/`iat`, `iss`/`aud` (both `"graphus"`), a random `jti`, and a credential-epoch `ver`. The server
validates the signature, the `iss`/`aud` binding, that `sub` names a live catalog user (the bootstrap
admin qualifies), and that `ver ≥` the user's epoch. An unauthenticated request to a transactional
endpoint is rejected `401`, which the workload asserts. The client uses the **standard library only**
(`http.client` + `ssl` + `json`) — no `PyJWT`, no `requests`.

### Reads engage the off-thread reader pool (`access_mode: "READ"`)

Every read the client issues — the five discovery queries, the full-text search, the `SHOW INDEXES` /
`SHOW CONSTRAINTS` introspection, and the concurrency worker query — is sent as a **single-statement
auto-commit with `access_mode: "READ"`**. That is what makes the router run it through the engine's
own auto-commit READ path so it **dispatches to the off-thread reader pool** and scales across the
reader threads (rmp #527/#543). An auto-commit **without** `access_mode` defaults to `WRITE` and runs
inline on the single engine thread — a ~1-core ceiling under concurrency, and the reason a naive
"concurrency" driver can report a 1-core result as if it were a success. The write path (the batched
graph load, the explicit-transaction demo, and the negative constraint writes) is left in `WRITE`
mode, exactly as it must be.

### Keep-alive connections

Each client keeps **one persistent (keep-alive) HTTPS connection** (`http.client.HTTPSConnection`,
reused across requests) rather than opening a fresh TCP+TLS connection per operation. Every
concurrency worker owns its own connection (the connection object is not thread-safe), so the reported
latency/throughput reflect the server and the reader pool — not a per-operation TLS handshake.

### Request / response shapes (verified against `crates/graphus-rest`)

| Method & path | Purpose | Request body | Response |
| --- | --- | --- | --- |
| `POST /db/{db}/tx/commit` | one-shot autocommit (reads add `"access_mode":"READ"`) | `{"statements":[{"statement":"…","parameters":{…}}],"access_mode":"READ"}` | `200` `{"results":[{"fields":[…],"data":[[…]],"summary":{…}}]}` |
| `POST /auth/login` | obtain a Bearer token | `{"username":"…","password":"…"}` | `200` `{"token":"…","token_type":"Bearer","expires_at_unix_secs":…}` |
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

The schema DDL (`CREATE CONSTRAINT` / `CREATE INDEX` / `CREATE FULLTEXT INDEX`) runs as **standalone
autocommit** statements (Graphus rejects admin DDL inside an explicit transaction, and a DDL statement
may not share an auto-commit batch with data writes — the loader's DDL splitter recognises every
`CREATE … INDEX` form, including `FULLTEXT`). The data then loads in **batched autocommit
transactions** — many `CREATE`/`MATCH…CREATE` statements per HTTP request — which is both
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

**Requirements:** a Unix host (Linux/macOS), `bash`, and `python3` (3.8+, **stdlib only** — no pip
packages). A **local** run also needs `openssl` (self-signed cert); an **external** run also needs
`curl` (the harness uses it for `/metrics` + database DDL). The generator is hermetic and CI-runnable
on its own; if the tools for the selected mode are absent, the REST workload is skipped with a clear
note while the byte-identical-generator assertion still runs.

### Running against an external target

By default the example self-boots a local server. Set any of `GRAPHUS_TARGET_{BOLT,REST,UDS}` and it
switches to **attach mode** instead: it does **not** boot a server, authenticates to the
already-running instance via `POST /auth/login`, carves out an **isolated dedicated database**, drives
the same discovery + concurrency workload into it, scrapes the target's Prometheus `/metrics`
before + after, emits the server-side evidence via the `measure_target` harness
(`measurement_mode=external`), and **DROPs the database on exit** — leaving the target exactly as it
was found. This is the shared external-target seam in `examples/_harness/harness.sh`; see the
"Running against an external target" section of `examples/README.md` for the full `GRAPHUS_TARGET_*`
contract.

```bash
# attach to an already-running instance, isolated + cleaned up:
GRAPHUS_TARGET_REST=https://graphus.example.com:7474 \
  GRAPHUS_TARGET_USER=graphus GRAPHUS_TARGET_PASSWORD=graphus-local \
  GRAPHUS_TARGET_TLS_INSECURE=1 \
  examples/knowledge-graph-rest/run.sh
```

| `GRAPHUS_TARGET_*` | Meaning |
| --- | --- |
| `GRAPHUS_TARGET_REST` | REST base URL (`https://host:7474`) — setting it enables attach mode |
| `GRAPHUS_TARGET_USER` / `GRAPHUS_TARGET_PASSWORD` | login credentials (defaults `graphus` / `graphus-local`) |
| `GRAPHUS_TARGET_TLS_INSECURE` | `1` to accept a self-signed TLS cert (`curl -k` / no client verification) |
| `GRAPHUS_TARGET_DB` | reuse an existing DB (never created/dropped); unset → an isolated DB is created + dropped |
| `GRAPHUS_TARGET_SYSTEM_DB` | DB through which the `CREATE/STOP/DROP DATABASE` DDL routes (default `graphus`) |

The local report carries `storage.bytes_per_node` / `storage.bytes_per_relationship`: the measured
durable store image amortised over the seeded graph. The workload is **read-only** (discovery queries,
NDJSON streaming, content negotiation, concurrent readers), so the store holds exactly the seeded
`dataset.nodes` / `dataset.relationships` and the two inputs provably describe the same graph. Each
amortises the WHOLE image over one element count, so the two figures are two views of one image and do
not sum to `store_bytes`.

In attach mode the process CPU/RSS and on-disk store/WAL vectors are **N/A** (no `/proc` or store-path
access on a remote host) and the host-specific baseline gate is skipped; the server-side evidence is
the `/metrics` counter delta (below). The workload exercises current-HEAD Cypher/DDL (named indexes,
`SHOW … YIELD`, property-type constraints), so an attach target must run a server at least as new as
that feature set.

## Evidence

The python client emits a single machine-readable `GRAPHUS_STATS {…}` line; `run.sh` parses it and
feeds it — together with the **live server process's** CPU + peak RSS and the on-disk store/WAL
footprint (local mode only) — into the dev-only `measure_server` harness, which writes the
standardized, schema-versioned **`evidence/report.json` + `evidence/report.md`** (the `evidence/` dir
is git-ignored). The client also emits a machine-readable `GRAPHUS_SCHEMA {…}` line — the
`SHOW INDEXES` / `SHOW CONSTRAINTS` snapshot — which `run.sh` persists to
**`evidence/schema_evidence.json`**. The paths are printed in the run summary.

**Server-side `/metrics` evidence.** In **both** modes `run.sh` scrapes the server's Prometheus
`/metrics` immediately **before** and **after** the workload window and computes the before → after
delta, attributed to the run's database:

- **External mode** — the delta is the *primary* server-side evidence: `measure_target` writes it into
  `evidence/report.json` as a top-level `measurement_mode: "external"` plus a `server_metrics` section
  (committed / aborted transactions, abort rate, slow queries, the query-duration histogram, the SSI
  gauge, and the health invariants). The run **fails** if any statement panicked, an engine was
  force-detached, or the abort rate exceeds the bound (`--assert`).
- **Local mode** — the co-located `measure_server` report (CPU/RSS/storage + the baseline gate) stays
  the primary `evidence/report.json`; the same `/metrics` delta is additionally written to
  `evidence/server-metrics/report.json` as a companion (best-effort, needs `curl`).

The `server_metrics` section from a real attach run (into an isolated database):

```jsonc
{
  "database": "ex_knowledge-graph-rest_…",
  "transactions_committed": 370, "transactions_aborted": 3, "abort_rate": 0.008,
  "slow_queries": 0,
  "statement_panics": 0, "engine_recovery_panics": 0,
  "engine_force_detached": 0, "engine_force_detached_active": 0,
  "ssi_tracked_before": 1, "ssi_tracked_after": 371,
  "query_count": 4390, "query_duration_mean_ms": 0.03,
  "query_duration_p50_ms": 0.25, "query_duration_p99_ms": 0.50
}
```

### What is measured

| Vector | Source | Example (`fast` profile, one developer machine) |
| --- | --- | --- |
| **HTTP requests/sec** | concurrent READ driver over a keep-alive connection per client | ≈ 1200 ops/s (machine-variant; `access_mode READ` + keep-alive engage the reader pool) |
| **Latency p50 / p99 / p999** | per-request, measured client-side | ≈ 3 / 8 / 10 ms (machine-variant) |
| **NDJSON streaming throughput** | rows/sec + bytes/sec of the streamed result | ≈ 403 rows, tens–hundreds of k rows/s (machine-variant) |
| **Payload size per encoding** | response bytes for the SAME query as JSON vs CBOR | JSON `11664` B, CBOR `7208` B → **CBOR ≈ 61.8 % of JSON** (deterministic) |
| **Declared schema** | `SHOW INDEXES` / `SHOW CONSTRAINTS` counts (`evidence/schema_evidence.json`) | `4` indexes (FULLTEXT + RANGE + 2 always-on LOOKUP), `6` constraints |
| **Server-side counters** | `/metrics` before → after delta (`server_metrics` section) | committed / aborted txns, slow queries, query-duration histogram, SSI gauge, panic/force-detach invariants |
| **Server CPU** *(local mode)* | the live server PID's cumulative user+system seconds | ≈ 2.0 user + 0.2 sys s |
| **Peak server RAM (RSS)** *(local mode)* | sampled from the live PID during the workload | ≈ 205 MB |
| **Storage footprint** *(local mode)* | on-disk store + WAL bytes/pages after the load | store ≈ 0.72 MB, WAL ≈ 5.2 MB |
| **Dataset size** | nodes + relationships in the loaded graph | `616` nodes, `3770` relationships |

The headline `GRAPHUS_STATS` line (parsed into the report's `workload` + `throughput` sections):

```jsonc
{
  "loaded_statements": 4394, "load_secs": 0.46,
  "indexes_total": 4, "constraints_total": 6,
  "ndjson_rows": 403, "ndjson_bytes": 14868,
  "ndjson_rows_per_sec": 347513, "ndjson_bytes_per_sec": 12821774,
  "json_bytes": 11664, "cbor_bytes": 7208, "cbor_ratio": 0.618,  // CBOR ≈ 62% of JSON
  "concurrency_clients": 16, "concurrency_ops": 320, "concurrency_errors": 0,
  "ops_per_sec": 477, "p50_ms": 25.4, "p99_ms": 44.6, "p999_ms": 45.1
}
```

Alongside it the client emits a `GRAPHUS_SCHEMA {…}` line — the declared indexes + constraints —
persisted to `evidence/schema_evidence.json`:

```jsonc
{
  "indexes": [["document_fulltext","FULLTEXT","NODE"], ["document_year_range","RANGE","NODE"], …],
  "constraints": [["document_year_integer","NODE_PROPERTY_TYPE","NODE"],
                  ["document_title_exists","NODE_PROPERTY_EXISTENCE","NODE"], …]
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

> **Evidence honesty (`rmp #699`).** `ops_per_sec` is the concurrency workload's requests over the
> window they were **actually issued in** (`concurrency_secs`, measured by the python client). It used
> to be divided by the whole **server uptime**, which mixed two different windows and understated req/s
> by roughly an order of magnitude (the old baseline read `106.7`; the same workload really sustains
> ~1250/s). The amplification denominator was an invented `nodes*256 + rels*128` formula and
> `write_amplification` was a `0.0` placeholder — both are now real, computed against the logical
> `graph.cypher` bytes. `total_millis` (`0.029` ms) timed the report's own emission and is now the
> workload's wall-clock.

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

A second hermetic test, `crates/graphus-server/tests/knowledge_graph_rest_schema.rs`, proves the
**search schema** end-to-end against the real engine (no REST, no python): it drives the generator's
DDL block through the admin seam (`parse_admin_statement` → `LocalEngine::{index_ddl,
constraint_ddl}`), loads the graph **schema-first**, then asserts (a) `SHOW INDEXES` / `SHOW
CONSTRAINTS` list the FULLTEXT + RANGE indexes and the property-type / existence / unique constraints
as `ONLINE`; (b) `CALL db.index.fulltext.queryNodes('document_fulltext', …)` returns exactly the known
reference documents for each term (including the empirically-verified **no-stemming** behaviour —
`graph` ≠ `graphs`); and (c) a non-integer `year` and a missing `title` are each **rejected** with the
constraint-violation error class. Run it with:

```bash
cargo test -p graphus-server --test knowledge_graph_rest_schema
```

Where these hermetic tests prove the **REST router semantics + serialization** and the **schema** in
CI, the shell `run.sh` proves the full **wire path** (HTTPS + Bearer-JWT over a real socket, driven by
the stdlib python client) plus the standardized evidence collection.
