# bulk-etl — high-throughput bulk ingest & ETL (offline core + network wire step)

> **Status:** complete. `rmp #264` (dataset + generator), `#265` (import / export / round-trip),
> `#266` (storage footprint + amplification), `#267` (evidence instrumentation), `#268` (`run.sh`),
> `#269` (dev-only cargo mirror), `#270` (evidence report + committed baseline + this README),
> `#678` (online schema-hardening: the constraint & index kinds an operator declares after a bulk
> load), `#695` (**network bulk-import (Mode A) wire step + server-side `/metrics` evidence**), and
> `#716` (**production-shaped scale + the REOPEN cost + a real per-batch ingest latency**) are all
> implemented and proven.

> **`rmp #716` — why this example was rescaled.** Its default workload used to be **47 milliseconds**
> long (4,829 elements). A bulk-ETL pipeline that finishes in a twentieth of a second cannot stress a
> single thing an ETL actually stresses: sustained ingest, WAL amplification under load, or the cost of
> **reopening** the store it just built. It passed, so it looked healthy, and it told us nothing. The
> default is now production-**shaped** at a **moderate** size (~164k elements, ~19 s), the two halves of
> a bulk load — the **import** *and* the **reopen** — are both measured and asserted, and the ingest
> latency is measured where a request boundary genuinely exists (over the wire) rather than emitted as a
> zero. At that scale the example immediately exposed a real server defect: see
> [What the new scale exposed](#what-the-new-scale-exposed).

This example demonstrates Graphus's **bulk data pipeline**, end to end and in two stages:

1. an **offline core** — the `graphus-bulk` CLI that **imports** node/relationship CSV into a fresh
   store and **dumps** a whole graph back to CSV, with **no server and no Bolt driver** in the loop.
   It is the path you use to load a dataset before the server ever starts, and to export it for backup
   / migration / interchange. This core is **fully offline and hermetic** — the simplest thing to run
   and the easiest to reason about for storage characterisation.
2. a **network bulk-import wire step** (`rmp #695`) — the SAME generated CSVs streamed into a
   **running server** over the ratified network bulk-import **Mode A** path
   (`POST /admin/db/{db}/bulk-import?phase=nodes|relationships` then `?end=true`), proving the server's
   own final ingest tally **and** the queried row counts equal the manifest, and collecting
   **server-side evidence** from the target's Prometheus `/metrics`. It runs against a self-booted
   local plaintext-loopback REST server by default, or **attaches** to an already-running instance
   (local OR remote) via the shared external-target seam (see
   [Network bulk-import over the wire](#network-bulk-import-over-the-wire-mode-a--rmp-695)).

On top of both, the example also documents the **online schema-hardening** that follows a bulk load in
production (`rmp #678`): the constraints and indexes an operator declares once the freshly-loaded data
is online — proven by an always-run hermetic cargo mirror (see
[Online schema-hardening](#online-schema-hardening--the-production-sequel-to-a-bulk-load-rmp-678)).

## What it demonstrates

1. **A deterministic, seeded LDBC-SNB-like social dataset** generated as loader-ready CSV.
2. **Bulk import** of that CSV into a fresh store via the real `graphus-bulk import` binary, loading
   the **full dataset with the correct node / relationship / property counts** (asserted against a
   generated `manifest.json`).
3. A **lossless `import → dump → re-import` round-trip**: the whole graph is dumped back to CSV and
   re-imported into a second fresh store, and the two stores are proven identical by an
   **id-independent content hash** (same labels, relationship types, property values, and
   connectivity — independent of physical id assignment).
4. **Storage footprint + write/space amplification** characterisation of the loaded store
   (bytes-per-node, bytes-per-edge, durable-store vs total-with-WAL space amplification, write
   amplification, and the **WAL residual** the load leaves behind), emitted as machine-readable JSON
   for the evidence report.
5. **The COST OF REOPENING the loaded store** (`rmp #716`) — the other half of a bulk load, and the
   half nothing here used to measure. A load is not finished when the importer exits: the next process
   to open that store must replay the redo log the load left behind. The example times that reopen
   (WAL recovery + `RecordStore::open`), records its peak RSS, and **asserts the reopened store still
   holds the whole graph** — so a reopen that came back fast because it came back *empty* can never be
   reported as a good number. This is the `rmp #576` / `#579` path, reproduced and quantified at a
   scale the example can afford to run on every gate.
6. **A real per-batch ingest latency** — measured over the wire, where a request boundary exists (each
   uploaded batch is one timed HTTP request), and **omitted** from the offline report, where one
   structurally does not. See [Reading the evidence honestly](#reading-the-evidence-honestly).

## The dataset model

A directed Label Property Graph modelling an online social network — a small, honest subset of the
[LDBC Social Network Benchmark](https://ldbcouncil.org/benchmarks/snb/) schema.

### Node labels (one CSV file each)

| Label     | File           | Typed properties |
|-----------|----------------|------------------|
| `Person`  | `persons.csv`  | `firstName:string`, `lastName:string`, `gender:string`, `age:int`, `locationIP:string`, `browserUsed:string`, `tags:string[]` |
| `Forum`   | `forums.csv`   | `title:string`, `createdAt:int` |
| `Post`    | `posts.csv`    | `content:string`, `length:int`, `createdAt:int`, `language:string` |
| `Comment` | `comments.csv` | `content:string`, `length:int`, `createdAt:int` |

Every node carries a **globally-unique** external `:ID` with a per-label prefix (`p…` Person,
`f…` Forum, `po…` Post, `c…` Comment), so `graphus-bulk`'s single shared `:ID → node` map never
collides across labels (which its strict duplicate-`:ID` policy would otherwise reject).

### Relationship types (one CSV file each)

| Type           | File              | Endpoints              | Typed property      |
|----------------|-------------------|------------------------|---------------------|
| `KNOWS`        | `knows.csv`       | `Person → Person`      | `since:int`         |
| `HAS_MEMBER`   | `has_member.csv`  | `Forum → Person`       | `joinedAt:int`      |
| `CONTAINER_OF` | `container_of.csv`| `Forum → Post`         | `addedAt:int`       |
| `HAS_CREATOR`  | `has_creator.csv` | `Post/Comment → Person`| `weight:int`        |
| `REPLY_OF`     | `reply_of.csv`    | `Comment → Post`       | `depth:int`         |
| `LIKES`        | `likes.csv`       | `Person → Post`        | `creationDate:int`  |

### CSV header format (`neo4j-admin import`-flavoured)

Verified empirically against `graphus-bulk` (`crates/graphus-bulk/src/header.rs`):

- **Node file header** — exactly one id column `<name>:ID`, an optional `:LABEL` column (a
  `;`-separated label set per row), and typed property columns `<key>:<type>` where `<type>` is one
  of `string` / `int` / `float` / `boolean` (and `<type>[]` array forms; a bare `<key>` defaults to
  `string`). Example:
  ```
  id:ID,:LABEL,firstName:string,lastName:string,gender:string,age:int,locationIP:string,browserUsed:string,tags:string[]
  p0,Person,Ada,Lovelace,female,36,1.2.3.4,Firefox,graphs;rust
  ```
- **Relationship file header** — `:START_ID`, `:END_ID`, `:TYPE`, then typed property columns. The
  `:START_ID`/`:END_ID` cells match node `:ID` values. Example:
  ```
  :START_ID,:END_ID,:TYPE,since:int
  p0,p1,KNOWS,2014
  ```

### The profile ladder (`BULK_PROFILE`)

**One production-shaped graph at four sizes.** The *shape* is what makes the example representative —
every rung shares the same seed, the same labels and relationship types, the same degrees, and the same
schema; only the **population** scales. A bigger run is therefore *the same graph, only more of it*, so
its footprint and amplification figures are directly comparable with the rung below.

| `BULK_PROFILE` | Persons | Forums | Posts   | Comments | Total nodes | Total relationships | Logical CSV | Purpose |
|----------------|--------:|-------:|--------:|---------:|------------:|--------------------:|------------:|---------|
| `fast`         | 200     | 24     | 144     | 432      | **800**     | **4,029**           | 134 KiB     | The crate's hermetic tests + a smoke run. **NOT an evidence scale.** |
| **`default`**  | 4,000   | 400    | 4,000   | 16,000   | **24,400**  | **139,989**         | 4.8 MiB     | **The default.** Production-shaped, moderate. The baseline's profile. |
| `large`        | 16,000  | 1,600  | 16,000  | 64,000   | **97,600**  | **559,989**         | 19.8 MiB    | Opt-in: real evaluation scale. |
| `huge`         | 64,000  | 6,400  | 64,000  | 256,000  | **390,400** | **2,239,991**       | 82 MiB      | Opt-in: the memory / WAL ceiling of a genuinely big import. |

**The default is `default`, and that is a deliberate trade.** `fast` was the default until `rmp #716`,
and at 4,829 elements it produced a **47-millisecond** workload — a run in which no storage or
durability vector means anything. `default` is the smallest size at which they all do: its load leaves a
WAL residual **5.8x larger than the durable store it just wrote**, amplifies writes **~42x** over the
logical input, and obliges a **reopen that costs 0.86x the import itself**. It keeps the whole examples
suite inside its gate budget (`scripts/examples-gate.sh`); the rungs above it are for evaluation, not
for the gate.

**Every number in this README is labelled with the profile that produced it.** A figure measured at
`fast` is never presented as a production figure, and a `default` run does not claim production scale —
it claims to be production-*shaped*.

The generator is a **pure function of `(seed, scale)`** (an internal SplitMix64 PRNG — no clock, no
float in the graph structure, no `HashMap` iteration), so the CSVs are **byte-identical per
seed/scale** across runs and platforms. All logical counts are **derivable from the config** and
emitted to `manifest.json` (nodes per label, relationships per type, total properties, logical CSV
bytes) — the ground truth every assertion checks against.

## Online schema-hardening — the production sequel to a bulk load (`rmp #678`)

The offline importer builds a **fresh store directly** through the low-level record API
(`create_node` / `set_node_labels` / `set_node_property_value` / `create_rel` / …). It does **not**
build secondary indexes and does **not** enforce constraints — there is no index/constraint code in
the crate. (It *does* fail-closed on a duplicate non-empty external `:ID` — a data-integrity guard,
not a graph constraint.) What follows a bulk load in production is **online schema-hardening**: you
bring the freshly-loaded data online and **declare, via DDL on the live server, the constraints and
indexes it is now ready to carry.**

The generator is built so that **every rule** in that production schema is *satisfied by
construction*, so each creation-time validation passes cleanly. The full palette is recorded verbatim
in `manifest.json` under `implied_schema` — honest documentation of what an operator would declare,
not a built artifact:

| Kind | Statement | Why it holds on this data |
|------|-----------|---------------------------|
| **NODE KEY** | `CREATE CONSTRAINT person_id_key FOR (n:Person) REQUIRE n.id IS NODE KEY` | every `Person.id` is present and distinct |
| **composite UNIQUE** | `CREATE CONSTRAINT post_id_created_unique FOR (n:Post) REQUIRE (n.id, n.createdAt) IS UNIQUE` | trivially unique via the distinct `Post.id` |
| **UNIQUE** | `CREATE CONSTRAINT forum_id_unique FOR (n:Forum) REQUIRE n.id IS UNIQUE` | every `Forum.id` is distinct |
| **UNIQUE** | `CREATE CONSTRAINT comment_id_unique FOR (n:Comment) REQUIRE n.id IS UNIQUE` | every `Comment.id` is distinct |
| **node property-type** | `CREATE CONSTRAINT post_length_integer FOR (n:Post) REQUIRE n.length IS :: INTEGER` | `Post.length` is always an `int` |
| **relationship existence** | `CREATE CONSTRAINT likes_created_exists FOR ()-[r:LIKES]-() REQUIRE r.creationDate IS NOT NULL` | every `LIKES` carries a `creationDate` |
| **relationship property-type** | `CREATE CONSTRAINT has_creator_weight_integer FOR ()-[r:HAS_CREATOR]-() REQUIRE r.weight IS :: INTEGER` | `HAS_CREATOR.weight` is always an `int` |
| **TEXT index** | `CREATE TEXT INDEX post_content_text FOR (n:Post) ON (n.content)` | substring search over post content |
| **FULLTEXT index** | `CREATE FULLTEXT INDEX post_content_fulltext FOR (n:Post) ON EACH [n.content]` | tokenized word search over post content |
| **composite RANGE index** | `CREATE INDEX post_catalog_composite FOR (n:Post) ON (n.createdAt, n.id)` | ordered "catalog by time" read path |

The id read path is served by the **backing indexes** of the id constraints (a `NODE KEY` / `UNIQUE`
constraint owns a RANGE index; the composite `UNIQUE`'s leading key is `id`). **No relationship
property is naturally unique** — every relationship type here carries exactly one, non-key property —
so the schema uses a relationship *existence* + *property-type* constraint rather than a
`RELATIONSHIP KEY`.

### How it is proven

- **Hermetic cargo mirror** (always-run, `cargo test -p graphus-server --test bulk_etl_schema`): loads
  the SAME seeded model **schema-first** through the real engine (the admin-DDL command path +
  `LocalEngine`), then asserts `SHOW INDEXES` / `SHOW CONSTRAINTS` list every kind `ONLINE` with the
  right type strings/entities/properties; that a composite-`UNIQUE` duplicate, a `NODE KEY` duplicate,
  and a `LIKES` edge missing `creationDate` are each **rejected**; and that the search paths return the
  exact generator-derived sets (a `TEXT CONTAINS` substring set — lowering to a `NodeTextIndexSeek` —
  and `FULLTEXT queryNodes` for the shared token / a unique number token / an absent term) plus a
  composite `(createdAt, id)` seek — lowering to a `NodeCompositeIndexSeek`.
- **Live network wire step** (`run.sh` Step 6, opt-in via `RUN_WIRE`, default on): streams the SAME
  generated CSVs into a **running server** over the network bulk-import Mode A path and, over that
  actually-loaded data, applies a **version-tolerant** subset of the palette and captures
  `SHOW CONSTRAINTS` / `SHOW INDEXES` into `evidence/wire/`. See
  [Network bulk-import over the wire](#network-bulk-import-over-the-wire-mode-a--rmp-695) for the full
  step, including which DDL is applied over bulk-imported data and why.

  **Empirical note — the CSV `:ID` is a join key, not a stored property** (verified against a live
  server): neither the offline importer nor the network Mode-A import persists the CSV `:ID` column as
  a queryable node property — it is consumed only as the physical-id join key, so a loaded
  `(:Person)` carries `keys(n) = [age, browserUsed, firstName, gender, lastName, locationIP, tags]`
  with **no `id`**. The **id-anchored** palette above (a `NODE KEY` / `UNIQUE` on `.id`, the composite
  `UNIQUE` whose leading key is `id`) therefore applies to a graph where `id` has been **materialised
  as a real property** (as an online client would after a load), which is exactly what the hermetic
  `bulk_etl_schema.rs` mirror does — it is the rigorous end-to-end proof of the full palette over the
  generator's exact dataset. The wire step, running over the un-materialised bulk-imported data,
  exercises the DDL that *is* meaningful there (see below).

## Network bulk-import over the wire (Mode A) — `rmp #695`, batched by `rmp #716`

After the offline core characterises the load, `run.sh` **Step 6** brings the SAME data online the way
an operator does in production: it streams the generator's node + relationship CSVs into a **running
server** over the ratified network bulk-import **Mode A** happy path
(`specification/08-network-bulk-import.md`), asserts the server's own ingest tally **and** the queried
row counts equal the manifest, and folds **server-side** evidence from the target's Prometheus
`/metrics` into a wire `report.json`.

### Streamed in REALISTIC BATCHES — which is also where the latency comes from

The CSVs are uploaded in **`BULK_BATCH_ROWS`-row chunks** (default **1,000**), not as ten whole files.
Two reasons, both substantive:

- it is **what an ETL pipeline actually does** — bounded batches, not one 79 MiB request body; and
- **every chunk is one request/response, so every chunk is a real per-batch INGEST LATENCY sample.**

That second point is the whole answer to "why did this example never report a latency?". A one-shot
offline import has **no per-operation boundary to time** — so its report **omits** latency rather than
inventing a `0.0` that reads as *instantaneous*. Over the wire the boundary genuinely exists, so the
latency is genuinely measured. Each chunk carries the file's header plus a slice of its rows, which is
exactly the shape the endpoint documents (§4.2: node and relationship files are separate request bodies
against the same session; a resumed call "resends the header plus every row not yet reflected").

`measure_target` then publishes **only the percentiles the sample size can honestly support**: with the
165 batches of a `default` run it reports **p50 and p99**, and **omits p999**. A 99.9th percentile is
only *supported* when at least 0.1% of the sample lies above it — one whole sample at n = 1,000 — and a
nearest-rank p999 over 165 samples is simply the **maximum** wearing a percentile's name. The report
says so in a note rather than printing a number nobody measured. (At the `huge` rung the batch count
crosses 1,000 and the p999 duly appears: the gate is a function of the sample size, not a hard-coded
omission.)

### The wire sequence

1. **Isolated database.** A dedicated, uniquely-named database (`ex_bulk-etl_<epoch>_<pid>`) is created
   via the shared external-target seam (`harness_target_ensure_db`) and **dropped on exit**
   (`harness_target_drop_db`, from the `trap`) — so a run never touches an operator's data and leaves no
   residue, local or remote.
2. **Stream the batches.** Every node chunk is streamed as one
   `POST /admin/db/{db}/bulk-import?phase=nodes` (`Content-Type: text/csv`), then every relationship
   chunk as `?phase=relationships` — **all** nodes land before **any** relationship, as the importer
   requires. The first call takes the empty database over exclusively (the `Loading` state); every
   subsequent call continues the same session. Each response reports the session's cumulative
   `{"nodes","relationships","properties"}`, and **each is timed**.
3. **End + bring online.** `?end=true` returns the final cumulative tally and moves the database to
   `Offline`; `START DATABASE` then brings it `Online`.
4. **Assert against the manifest.** Both the server's **end-of-session ingest tally** *and* the
   **queried** counts (`MATCH (n) RETURN count(n)`, `MATCH ()-[r]->() RETURN count(r)`) must equal the
   generator manifest — nodes, relationships, and (for the ingest tally) the property count. Every batch
   must have returned **HTTP 200**, and the latency sample count must equal the batch count.
5. **Server-side evidence.** `/metrics` is scraped **before** and **after** the wire workload and the
   deltas are folded into `evidence/wire/report.json` via the shared `measure_target` binary
   (`measurement_mode = external`): committed/aborted transactions attributed to the run's database, the
   query-duration histogram, and the health invariants (`statement_panics`, `engine_recovery_panics`,
   `engine_force_detached*` — all asserted `0` by `measure_target --assert`).

All batches of a phase go out from **one curl process driven by a config file**, so the connection is
reused across them exactly as a real ETL client pools it. The config file is not a cosmetic choice:
`--next` starts every request with a *clean option slate*, so a `-k` supplied once up front would apply
only to the **first** request — which is exactly how a self-signed TLS target accepts batch 1 and
rejects every batch after it (this bug was real, and attach mode caught it). It also keeps the whole
upload clear of `ARG_MAX` at the `huge` rung (**2,631 batches** at the default batch size; macOS caps a
command line at 256 KiB), and keeps the Bearer token out of the process argv, where `ps` would show it
to any local user.

At `huge` the batch count crosses 1,000, so `measure_target` then reports a **p999** as well: the
honesty gate is a function of the sample size, not a hard-coded omission.

### Two ways to run it

- **Local self-boot (default).** With no `GRAPHUS_TARGET_*` set, Step 6 boots a real `graphus-server`
  exposing a **plaintext-loopback REST** listener (`allow_insecure_network = true`, so the upload needs
  no TLS/cert) plus a UDS socket, points the seam at `http://127.0.0.1:<port>`, runs the wire sequence,
  and stops the server on exit.
- **Attach to a running instance.** Set a `GRAPHUS_TARGET_REST` endpoint and Step 6 **attaches** to it
  instead of booting anything — local or remote (e.g. a staging box). TLS with a self-signed
  cert is accepted with `GRAPHUS_TARGET_TLS_INSECURE=1`.

  ```bash
  GRAPHUS_TARGET_REST=https://graphus.example.com:7474 \
    GRAPHUS_TARGET_USER=graphus GRAPHUS_TARGET_PASSWORD=graphus-local \
    GRAPHUS_TARGET_TLS_INSECURE=1 \
    examples/bulk-etl/run.sh
  ```

  Both modes are verified on every gate run (`scripts/examples-gate.sh` runs the suite local **and**
  attached).

### DDL over bulk-imported data (version-tolerant)

Because the CSV `:ID` is the physical join key and **not** a stored property (see the empirical note
above), the id-anchored palette (`NODE KEY` / `UNIQUE` on `.id`) is **not** applied over the wire
directly — it is documented in `manifest.json` and proven by the hermetic mirror over a graph where
`id` is materialised. What the wire step *does* exercise over the actually-loaded data, best-effort and
**non-fatal**, is the DDL that is meaningful there: a **RANGE index** on a real timeline property
(`Post.createdAt`) and **property-type constraints** (`Post.length IS :: INTEGER`, satisfied by
construction). Each accepted statement is counted (`online_ddl_accepted` in the report), and the plain
`SHOW CONSTRAINTS` / `SHOW INDEXES` listings are captured to `evidence/wire/schema_*.json`.

### Verified against an older server

The wire step was validated against a live, **older** Graphus build over REST + TLS. Findings:

- **The network Mode-A path is fully supported by the older build.** The complete sequence — login,
  `CREATE DATABASE`, streaming `?phase=nodes|relationships` (`text/csv`), `?end=true`, `START DATABASE`,
  the count queries, the `/metrics` scrape, and `STOP`+`DROP` — all succeed, and the server's ingest
  tally (`800` nodes / `4,029` relationships / `7,349` properties) matched the manifest **exactly**.
- **The older build rejects some modern DDL** (why the wire schema step is version-tolerant): typed
  index DDL such as `CREATE TEXT INDEX …` is a **syntax error** on that older build, and the `SHOW CONSTRAINTS /
  SHOW INDEXES … YIELD …` projection form is rejected — so the wire step avoids both (plain `SHOW`, no
  typed-index DDL) and the full modern palette is validated against a **current** server (local mode)
  and the hermetic mirror. Relationship property-type DDL was also not accepted by that older build
  (`2/3` version-tolerant statements applied there); this is recorded, not failed.

### `rmp #681` — the offline store is not directly server-openable (surfaced, not sidestepped)

**STILL OPEN, and the example says so on every run.** `run.sh` **Step 7** probes the *real* store the
metered import produced (no extra import) and checks its layout: the offline importer writes a **flat**
`graph.store` + `graph.wal` pair, whereas a `graphus-server` resolves its store as
`<store_path>/databases/<name>/graphus.store` (plus a database catalog). So an offline-produced store is
**not** directly openable by a server — the probe prints `server-openable directly: no`.

This is why the online demo reaches the same data through the **network bulk-import path** (Step 6)
rather than by pointing a server at the offline store. The example does not paper over the gap; it
prints it as a standing finding every time it runs.

## How it is built — the dev-only generator crate

The dataset generator and the import/round-trip/footprint/reopen drivers live in
`crates/graphus-bulk-gen` — a **dev-only leaf crate** (`publish = false`), in the same spirit as
`graphus-gds-gen` / `graphus-fraud-gen`. **Nothing in the production build depends on it** (in
particular `graphus-server` does not), so it adds zero overhead to the shipped binary.

It exposes five binaries:

| Binary              | Purpose |
|---------------------|---------|
| `bulk_gen`          | Writes the per-label node CSVs + per-type relationship CSVs + `manifest.json` for a `--profile` (`fast`/`default`/`large`/`huge`). Byte-identical per seed. |
| `bulk_roundtrip`    | Drives the **real `graphus-bulk` binary** through `import → dump → re-import`, asserting counts vs the manifest and proving losslessness by content hash. |
| `bulk_evidence`     | **One metered import, measured for everything.** Runs the real `graphus-bulk import` as a metered child (ingest throughput, peak RAM, CPU, wall time), then measures the on-disk footprint **of the store that child just wrote**, then measures **the cost of reopening it** (via `bulk_reopen`), and writes `storage.json` + the standardized `report.json` / `report.md`. |
| `bulk_reopen`       | **The reopen cost** (`rmp #716`): reopens a bulk-loaded store — WAL recovery (`recover_device`) + `RecordStore::open` — timed, with its own peak RSS, **asserting the reopened store still holds the whole graph**. A separate process, so every figure is attributable to the reopen alone. |
| `bulk_baseline_cmp` | Gates a fresh `report.json` against the committed `baseline.json` (structural metrics only); prints `GRAPHUS_BASELINE_OK` and exits `0` on success, else exits `1`. |

> **One import, not three.** `bulk_evidence` used to *time* an import into one store while a separate
> `bulk_storage` binary *measured* a second store built from a re-import of the same dataset — so the
> per-element costs it published were, strictly, a footprint of one store amortised over the element
> count of another. Deterministic, therefore numerically equal, and still the wrong shape: the examples'
> evidence-honesty rules require a per-element cost whose two inputs describe the **same graph**.
> `bulk_storage` is gone; its measurement logic moved to `graphus_bulk_gen::footprint`, and
> `bulk_evidence` now meters one import for time, footprint **and** reopen — over one store image. That
> also removed two redundant imports of the whole dataset from every run, which is what made the bigger
> profiles affordable.

The library is covered by unit + integration tests in the DEFAULT `cargo test`:

- `tests/determinism.rs` — byte-identical CSVs per seed, manifest counts == config, globally-unique
  ids, seed sensitivity;
- `tests/hermetic_roundtrip.rs` — the **dev-only cargo mirror** (`rmp #269`): an in-process,
  no-subprocess, no-disk (`MemBlockDevice`) `generate → import → dump → re-import` through the real
  `graphus-bulk` **library** API (`BulkImporter`), asserting the re-imported **counts** and the
  id-independent **content hash** match the original — the same losslessness the core proves, run
  hermetically on every `cargo test`;
- `graphus-server/tests/bulk_etl_schema.rs` — the **online schema-hardening mirror** (`rmp #678`):
  loads the SAME seeded model schema-first through the real engine and asserts the full constraint +
  index palette is declared `ONLINE`, enforced (negative writes rejected), and utilised by the planner
  (`SHOW INDEXES` / `SHOW CONSTRAINTS`, `TEXT CONTAINS`, `FULLTEXT queryNodes`, composite seek) — also
  on every `cargo test`.

## Capabilities exercised

| Capability | How it is exercised | Evidence |
|------------|---------------------|----------|
| **Deterministic dataset generation** | `bulk_gen` (seeded SplitMix64; pure function of profile) | regenerate-and-diff in `run.sh`; `tests/determinism.rs` |
| **Offline bulk import** | the real `graphus-bulk import` binary builds a fresh store | reported counts asserted == `manifest.json` |
| **Whole-graph export** | `graphus-bulk dump` serialises the store back to CSV | non-empty dump asserted; re-import counts asserted |
| **Lossless round-trip** | `import → dump → re-import`, compared by id-independent content hash | `GRAPHUS_BULK_ROUNDTRIP_OK` + content hash equality |
| **Ingest throughput** | metered `graphus-bulk import` child | `report.json` `throughput.ops_per_sec` (elements/sec) + `workload.ingest_mb_per_sec` |
| **Peak RAM / CPU / time** | poll the import child's PID (`/proc` / `ps`) | `report.json` `memory.peak_rss_bytes`, `cpu.*`, `phases[import]` |
| **Storage footprint + amplification + WAL residual** | `bulk_evidence` walks the store + WAL **of the store its own metered import just wrote** (`graphus_bulk_gen::footprint`) | `report.json` `storage.*` + `storage.json`; asserted by `run.sh` Step 4 |
| **Store REOPEN cost** (`rmp #716`) | `bulk_reopen`: WAL recovery + `RecordStore::open` on that same store, timed, own peak RSS, counts asserted | `workload.reopen_wall_secs` / `reopen_over_import_ratio` / `reopen_peak_rss_bytes`, `phases[reopen]` |
| **Per-batch ingest latency** (`rmp #716`) | each wire batch is one timed HTTP request; `measure_target` publishes only the percentiles the sample size supports | `evidence/wire/report.json` `throughput.p50_latency_ms` / `p99_latency_ms` (p999 omitted, with reason) |
| **Regression gate** | `bulk_baseline_cmp` vs committed `baseline.json` | `GRAPHUS_BASELINE_OK` |
| **Network bulk-import (Mode A)** (`rmp #695`) | stream the SAME CSVs into a running server (`POST /admin/db/{db}/bulk-import?phase=…` / `?end=true`); local self-boot or external attach | server ingest tally + queried counts asserted == `manifest.json` |
| **Isolated database + teardown** (`rmp #695`) | `harness_target_ensure_db` creates a dedicated DB; `harness_target_drop_db` (from the `trap`) drops it on exit | leaves the target clean, local or remote |
| **Server-side `/metrics` evidence** (`rmp #695`) | `/metrics` scraped before/after the wire load; deltas folded in by `measure_target` (`--assert` health gate) | `evidence/wire/report.json` (`measurement_mode=external`, `server_metrics`) |
| **Online schema-hardening** (`rmp #678`) | hermetic `bulk_etl_schema.rs` (full palette) + version-tolerant DDL over the wire-loaded data (`run.sh` Step 6) | `SHOW CONSTRAINTS` / `SHOW INDEXES` list the palette `ONLINE`; enforcement rejections; `evidence/wire/schema_*.json` |

## Running it

The standardized, self-asserting entry point is `run.sh`. Its offline core (Steps 1–5) needs no
server, driver, or network; the network bulk-import **wire step** (Step 6) streams the SAME CSVs into a
running server and is enabled by default (`RUN_WIRE=1`) — booting a local plaintext-loopback REST
server, or attaching to a `GRAPHUS_TARGET_REST` endpoint when one is set. It builds the binaries if
needed, runs the whole pipeline, prints an `N checks run, M failures` summary + the evidence paths, and
exits non-zero on any failed assertion. A `trap` removes the temp workspace **and drops any isolated
wire database** on exit (success **or** failure), so it leaves no residue — local or remote.

The seven steps:

| Step | What it does |
|------|--------------|
| 1 | Generate the deterministic dataset; prove it is **byte-identical per seed** by regenerating and diffing. |
| 2 | Prove the **lossless** `import → dump → re-import` round-trip on the real `graphus-bulk` binary (content hash). |
| 3 | **One metered import**: ingest throughput / CPU / peak RAM, the on-disk footprint + WAL residual, and **the cost of reopening** the store it just built — all over the *same* store image. |
| 4 | **Assert the storage + reopen vectors** (non-empty store, real bytes/element, the load *was* WAL-logged, amplification under a blow-up ceiling, the reopen was measured and did not degenerate). |
| 5 | **Regression gate** vs the committed `baseline.json` (`default` profile only). |
| 6 | **Network bulk-import (Mode A)** in realistic batches, with a **real per-batch ingest latency**, the server's tally + queried counts asserted against the manifest, and server-side `/metrics` evidence. |
| 7 | The **`rmp #681`** probe: is the offline-produced store server-openable? (It is not — reported, not hidden.) |

```bash
# DEFAULT profile: 24,400 nodes / 139,989 rels — production-shaped, moderate. ~19s. Baseline-gated.
# Also runs the network bulk-import wire step (Step 6) against a self-booted local server.
examples/bulk-etl/run.sh

# Offline core only — skip the wire step (a host without a server build, or an offline CI).
RUN_WIRE=0 examples/bulk-etl/run.sh

# Stream the wire step into an ALREADY-RUNNING instance (local OR remote) over REST + TLS.
GRAPHUS_TARGET_REST=https://graphus.example.com:7474 \
  GRAPHUS_TARGET_USER=graphus GRAPHUS_TARGET_PASSWORD=graphus-local \
  GRAPHUS_TARGET_TLS_INSECURE=1 \
  examples/bulk-etl/run.sh

# A SMOKE run (800 nodes / 4,029 rels). NOT an evidence scale — no storage figure from it means anything.
BULK_PROFILE=fast examples/bulk-etl/run.sh

# OPT-IN evaluation scales. `large` ~2m35s; `huge` is the memory/WAL ceiling of a big import.
# Neither is baseline-gated: a baseline can only gate the workload it was captured from.
BULK_PROFILE=large examples/bulk-etl/run.sh
BULK_PROFILE=huge  examples/bulk-etl/run.sh

# The wire batch size (rows per bulk-import request) — the unit each latency sample is measured over.
BULK_BATCH_ROWS=5000 examples/bulk-etl/run.sh

# Point at a pre-built bin dir to skip the build step.
GRAPHUS_BIN_DIR=target/release examples/bulk-etl/run.sh
```

The pieces can also be run directly (what `run.sh` orchestrates):

```bash
cargo build --release -p graphus-bulk --bin graphus-bulk -p graphus-bulk-gen --bins
BD=target/release; WD=$(mktemp -d)
$BD/bulk_gen        --profile default --out-dir "$WD/data"
$BD/bulk_roundtrip  --bulk-bin "$BD/graphus-bulk" --data-dir "$WD/data"
# ONE metered import: throughput + CPU/RAM + footprint + the reopen cost, over one store image.
$BD/bulk_evidence   --bulk-bin "$BD/graphus-bulk" --reopen-bin "$BD/bulk_reopen" \
                    --data-dir "$WD/data" --storage-out "$WD/storage.json" \
                    --keep-store "$WD/store" \
                    --evidence-dir examples/bulk-etl/evidence --param profile=default
# …or measure the reopen of an existing bulk-loaded store on its own:
$BD/bulk_reopen     --db "$WD/store" --expect-nodes 24400 --expect-rels 139989
rm -rf "$WD"
```

## Evidence

`run.sh` emits a standardized, schema-versioned `report.json` + `report.md` into the git-ignored
`evidence/` directory (the shared `graphus-examples-harness` schema — same shape as every other
example), assembled by `bulk_evidence`. The headline metrics:

| Report field | Meaning |
|--------------|---------|
| `throughput.operations` / `throughput.ops_per_sec` | elements (nodes + rels) loaded / **elements per second** |
| `throughput.p50/p99/p999_latency_ms` | **ABSENT by design** — a one-shot offline import has no per-operation boundary to time. The real per-batch ingest latency is in the **wire** report. |
| `workload.ingest_mb_per_sec` | input-CSV **MB per second** the loader sustained |
| `memory.peak_rss_bytes` | **peak RAM** of the import process (polled while it ran) |
| `cpu.user_secs` / `cpu.system_secs` / `cpu.mean_core_utilisation` | **CPU time** of the import process |
| `phases[import].millis` | the **import** wall time |
| `phases[reopen].millis` | the **REOPEN** wall time — the second half of a bulk load (`rmp #716`) |
| `total_millis` | the whole measured workload: import **+** reopen |
| `storage.store_bytes` / `store_pages` | the durable `graph.store` image |
| `storage.wal_bytes` / `wal_pages` | the **WAL residual** the completed load left behind — exactly what a reopen must replay |
| `storage.bytes_per_node` / `bytes_per_relationship` | on-disk **store per-element costs** (the gated, deterministic figures), over the *same* image |
| `storage.space_amplification` / `write_amplification` | the **real amplification ratios** — durable bytes vs the logical CSV input |
| `workload.reopen_wall_secs` / `reopen_scan_secs` | the store **open** (WAL recovery + `RecordStore::open`) and, separately, a full id scan — so the open cost is never inflated by the read-back |
| `workload.reopen_over_import_ratio` | **the headline `rmp #716` figure**: what fraction of the load's cost you pay *again*, every time the store is opened |
| `workload.reopen_peak_rss_bytes` | peak RSS of a process that did nothing but reopen the store (the `rmp #579` vector) |
| `workload.wal_residual_bytes` / `wal_to_store_ratio` | the redo log the load left behind, and how many times the durable graph it re-wrote into it |
| `workload.store_space_amplification` / `total_space_amplification` / `csv_write_amplification` | the same CSV-relative amplifications, split store-only vs with-WAL (human visibility) |
| `workload.content_hash` | the round-trip content hash (lossless evidence) |

> **Every field carries the quantity its name promises (`rmp #699`).** This example used to **overload**
> the amplification fields to smuggle the per-element costs it wanted gated: `space_amplification`
> carried bytes-per-node and `write_amplification` carried bytes-per-edge. The committed baseline
> therefore read `"space_amplification": 1239.04` — anyone (or any gate) trusting the field name would
> have concluded the store had **1239× space amplification**, when the real figure is **46.78×**. The
> schema now has dedicated `bytes_per_node` / `bytes_per_relationship` fields, the harness diff gates
> those per-element costs directly, and the amplification fields carry only amplification.

### Wire (server-side) evidence — `evidence/wire/`

The network bulk-import wire step (Step 6) writes a **separate** report so it never clobbers the offline
one: `evidence/wire/report.json` + `report.md` (via `measure_target`, `measurement_mode = external`)
plus `schema_constraints.json` / `schema_indexes.json`. Its headline block is `server_metrics` — the
target's `/metrics` **before → after deltas**, attributed to the run's isolated database:

| `server_metrics` field | Meaning |
|------------------------|---------|
| `database` | the isolated run database the deltas are attributed to (per-database `graphus_db_*` series) |
| `transactions_committed` / `transactions_aborted` / `abort_rate` | write activity the server saw over the wire window |
| `query_count` / `query_duration_{mean,p50,p99}_ms` | the query-duration histogram delta |
| `statement_panics` / `engine_recovery_panics` / `engine_force_detached{,_active}` | health invariants — a healthy server keeps these `0` (asserted by `measure_target --assert`) |
| `ssi_tracked_before` / `ssi_tracked_after` | retained SSI conflict records around the window |

Process CPU/RSS and on-disk storage are **N/A** in this external mode (no co-located PID or store path)
and are therefore **absent** from the wire report, with an explicit note (`rmp #711` — an unmeasured
vector is omitted, never zero-filled) — the honest, portable channel against a remote server is
`/metrics`. The workload params carry the server's ingest tally (`server_ingest_{nodes,relationships,
properties}`) and the count of accepted version-tolerant DDL statements (`online_ddl_accepted`).

`bulk_evidence` also writes the lower-level `storage.json` (`--storage-out`) — the machine-readable
footprint + reopen figures `run.sh` Step 4 asserts on: `store_bytes` / `wal_bytes`, `bytes_per_node` /
`bytes_per_edge`, `store_space_amplification` / `space_amplification` / `write_amplification`,
`wal_to_store_ratio`, and `reopen_secs` / `reopen_peak_rss_bytes`.

### Reading the evidence honestly

- **Latency is measured where a boundary exists, and omitted where one does not.** The **offline**
  report carries **no** `p50/p99/p999` — a one-shot batch import has no per-operation request/response
  boundary to time, and a `0.0` there would read as *instantaneous*. The **wire** report carries a real
  `p50`/`p99`, measured per uploaded batch, and **omits `p999`** because 165 samples cannot support a
  nearest-rank p999. Both absences are stated, with their reason, in the report's own `notes`.
- **The offline import is fully deterministic.** `store_bytes`, `store_pages`, `wal_bytes`, and
  `wal_pages` are **byte-identical across runs and hosts** (the importer batches commits
  deterministically; no clock-driven checkpointing), which is why the baseline gate can hold them to
  a tight band.
- **Per-element costs describe the same graph they are amortised over.** `bytes_per_node` /
  `bytes_per_relationship` are the durable **store image** divided by the node / relationship count of
  **that same image** — one import, metered for both. They are two *views* of one image and do **not**
  sum to `store_bytes`.
- **Amplification.** The durable graph image is ~6× the logical CSV size (fixed-record padding,
  free-list slack, token catalogs). The much larger *total* figure (`store + WAL`) is dominated by the
  **retained WAL**. That redo log is transient **in principle** — but only if something reclaims it, and
  after an offline bulk load **nothing does**: see the WAL residual below.
- **Throughput / CPU / RAM / wall time / reopen seconds are machine-variant** and are recorded for human
  visibility but **NOT** gated to a tight band. `run.sh` asserts *invariants* over them instead (the
  reopen was measured; it did not degenerate past a generous ceiling; it did not lose data).

### Measured envelope

Release build; host `linux/x86_64`, 16 cores, NVMe. **Each column names the profile that produced it.**
The `fast` column is included only to show what a smoke-scale run *cannot* tell you.

| Metric | `fast` (800n / 4,029r) | **`default`** (24,400n / 139,989r) | `large` (97,600n / 559,989r) |
|--------|----------------------:|-----------------------------------:|------------------------------:|
| Logical CSV input | 134 KiB | 4.78 MiB | 19.8 MiB |
| **Import wall time** | 0.05 s | **1.24 s** | 21.3 s |
| **Ingest throughput** | ~97k elem/s | **133,066 elem/s** (3.87 MB/s) | **30,877 elem/s** ⚠️ |
| Peak RAM (import) | ~8 MB | 31.1 MB | 52.4 MB |
| Store image | 991,232 B | **30,801,920 B** (3,760 pages) | 123,150,336 B |
| **WAL residual after the load** | 5,420,487 B | **178,412,518 B** (21,779 pages) | 720,742,543 B |
| **WAL ÷ store** | ~5.5× | **5.79×** | 5.85× |
| Bytes / node (store) | ~1,239 B | **1,262.4 B** | 1,261.8 B |
| Bytes / relationship (store) | ~246 B | **220.0 B** | 219.9 B |
| Store space amplification | ~7.2× | **6.15×** | 5.93× |
| **Write amplification** (store+WAL ÷ CSV) | ~46.8× | **41.76×** | 40.62× |
| **REOPEN of the loaded store** | — | **1.07 s** | 3.00 s |
| **Reopen ÷ import** | — | **0.86×** | 0.10× (only because the *import* degraded) |
| Reopen peak RSS | — | 8.5 MB | 13.3 MB |
| **Wire: per-batch ingest latency** (1,000-row batches) | — | **p50 7.7 ms / p99 50.2 ms** | — |
| Wire load (Mode A, over REST) | — | 164,389 elem in 1.71 s (165 batches) | 657,589 elem in 45.2 s (658 batches) |
| **`run.sh` wall time** | ~2 s | **~19 s** | ~2 m 35 s |

Round-trip losslessness is proven by content hash at every scale (`default =
ef61b4b3a9ebb44de27ff88c2c14433e`).

### The committed baseline + regression gate

`baseline.json` (committed, non-git-ignored) is a **`default`-profile reference run**, captured by
**running the example** — never by hand-editing numbers. `run.sh` gates a fresh `default` run against it
with `bulk_baseline_cmp`, which holds only the **stable structural** metrics:

- **exact equality**: `dataset.nodes` / `dataset.relationships` and `workload.imported_elements`
  (integer-stable for a fixed seed);
- **within 15%**: `storage.store_bytes`, `storage.wal_bytes`, `storage.bytes_per_node`,
  `storage.bytes_per_relationship`, `storage.space_amplification`, `storage.write_amplification`.

The gate is **skipped, and says so**, for any other profile: a baseline can only compare against the
workload it was captured from, and diffing a `large` run against a `default` baseline would call a
different graph a regression.

**Why these thresholds.** The footprint is deterministic here, so 15% is comfortably loose enough to
absorb `f64` re-serialization rounding and any future minor record-layout/free-list slack, yet tight
enough to catch a real footprint regression. The structural counts are gated at exact equality
because a change means the generator drifted. Throughput, CPU, peak RAM, wall-time and reopen seconds
are machine-/host-variant and are deliberately **ungated** (held at `∞`) so the shared baseline is never
flaky across the developer/CI machines it travels between — the same gating philosophy as the
`gds-analytics` and `fraud-oltp` examples. `run.sh` Step 4 asserts *invariants* over those
machine-variant vectors instead.

**The baseline moved with `rmp #716`** (the default workload changed from `fast` to `default`, and the
report gained a `reopen` phase). It was re-captured by running the example; the figures are the
`default` column of [Measured envelope](#measured-envelope).

> Note on the round-trip property count: `graphus-bulk dump` unifies every property key across all
> node labels into one CSV file, so a node is written with empty cells for keys other labels carry.
> On re-import, an empty `string`/`string[]` cell becomes a present-but-empty property (graphus-bulk's
> documented value semantics), so the *populated-property count* after a dump is higher than the
> original. This is a property of the importer/dumper pair, not data loss — the content hash
> canonicalises these present-but-empty values away, which is why the round-trip is provably lossless
> while the raw property counts differ.

## What the new scale exposed

The point of rescaling this example was to make it capable of exposing what it could not see before.
It did so immediately. **These are server findings, reproduced and quantified by the example — they are
a success of the example, not a failure of it.**

### 1. The offline importer is QUADRATIC — `rmp #718` (NEW, filed by this work)

Look at the throughput row above: **133,066 elem/s at `default` collapses to 30,877 elem/s at
`large`** — 4× the data for **16.8× the time**, i.e. **O(N²·⁰)**. Measured standalone, outside the
harness, and reproducible:

| Profile | Elements | Import | Throughput |
|---------|---------:|-------:|-----------:|
| `fast` | 4,829 | 0.05 s | 96,636 elem/s |
| `default` | 164,389 | 1.27 s | 129,403 elem/s |
| `large` | 657,589 | **21.30 s** | **30,877 elem/s** |

**Root cause (confirmed, not inferred):** `crates/graphus-bulk/src/bin/graphus_bulk.rs:59` hard-codes
`const POOL_PAGES: usize = 256` — a **2 MiB** buffer pool — on the premise (stated in its own comment)
that "a bulk load is sequential-write heavy". That premise is **false for the relationship phase**:
`create_rel` prepends each edge into the incident-relationship chain of **both** endpoint nodes, and the
endpoints are scattered across the whole node store. The relationship phase is **random-access over the
entire store**. Once the store outgrows the 2 MiB pool the miss rate approaches 100% and every edge
insert evicts and re-reads pages.

**Proof:** rebuilding the identical binary with only `POOL_PAGES = 32768` (a 256 MiB pool) cuts the
`large` import from **21.30 s → 8.96 s — 2.38× faster**. The server already has adaptive,
hardware-aware pool sizing (`graphus-sysres`, `rmp #617`); the `graphus-bulk` CLI simply bypasses it.
Filed as **`rmp #718`**.

*A 47-millisecond example could never have seen this.* That is the entire argument for the rescale.

### 2. The WAL residual nothing reclaims — corroborates `rmp #576`

A completed offline load leaves a redo log **5.8× larger than the durable store it just wrote**
(178 MB of WAL for a 30 MB store at `default`; 721 MB for 123 MB at `large`), and **nothing reclaims
it**. That residual *is* the reopen cost: the next process to open the store must replay all of it. At
`default` the reopen costs **0.86× the import itself** — reopening the store is nearly as expensive as
building it. This is the same root cause as **`rmp #576`** ("large store reopen … deferred loading-end
WAL not yet reclaimed", still open); the example now quantifies it on every run and asserts it does not
degenerate.

### 3. `rmp #579` (the ~25 GB reopen RSS blow-up) is CONFIRMED FIXED

The reopen's peak RSS is **8.5 MB** at `default` and **13.3 MB** at `large` — flat, and ~4 orders of
magnitude below the ~25 GB that `#579` recorded. The windowed/streaming recovery that closed it
(`rmp #599`) **holds** at this scale. The example now measures this every run, so a regression would be
caught rather than rediscovered.

### 4. `rmp #681` is still open

The offline-produced store is still **not** directly openable by a `graphus-server` (flat
`graph.store` + `graph.wal` vs the server's `databases/<name>/graphus.store` layout). Step 7 probes the
real store and prints the finding on every run.
