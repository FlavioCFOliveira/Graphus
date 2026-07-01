# 08 — Network Bulk Import (Remote Streaming Bulk Load)

This document specifies **network bulk import**: a capability that lets an operator load a
large graph dataset (target scale: millions of nodes, hundreds of millions of relationships)
into a Graphus database over the network, while the target server process is already running
(locally or remotely). It complements the existing **offline** bulk importer (`FR-BK-2`,
`graphus-bulk`), which only ever operates on store files that no running server process has
open.

This document specifies design decision **`D-bulk-import-network`**, registered in
`02-decision-register.md`. **Status: ratified by the project owner on 2026-07-01**, with two
explicit choices that this revision documents in full:

1. **RBAC:** the global `Admin` privilege (§6) — the recommended option, unchanged.
2. **Target-database scope:** network bulk import must support **both** a fresh/empty database
   (§5.2, "Mode A") **and** an already-live, already-serving database under ordinary concurrent
   Bolt/REST client traffic (§5.3, "Mode B"). **This is the non-recommended, higher-risk option**
   from the original proposal — the owner explicitly chose it over the fresh/empty-database-only
   recommendation. This revision replaces the original §5/§7 (which scoped the capability to Mode
   A only) with the full concurrency-safe design for Mode B, validated by an independent audit
   (`storage-systems-auditor`, 2026-07-01) against the actual `graphus-txn`/`graphus-cypher`
   concurrency-control code. That audit surfaced one **pre-existing, must-fix correctness bug**
   in `graphus-bulk` that this capability's retry semantics would otherwise turn into a live data
   -corruption risk — see §7.2.

## 1. Motivation and problem statement

An empirical load test against the live Graphus instance on host `pi516` (2026-06-30, using
`examples/social-network-large`) established that **it is not possible today to load a
large-scale dataset (order of 1,000,000 users, hundreds of millions of edges) into an
already-running Graphus server**, whether local or remote. Three independent gaps were
confirmed by reading the code:

1. **The offline bulk importer never runs against a live server.** `graphus-bulk` (component
   `bulk-importer`, `FR-BK-2`) opens a `FileBlockDevice`/`FileLogSink` pair **directly** on a
   local directory and requires that the directory **not already contain a store** — it is a
   separate, offline process for cold, empty-database initial load, not a client of a running
   engine. There is no code path that lets it attach to a store a live `graphus-server` process
   already has open, and no code path that lets it send its input over a network connection.
2. **`BACKUP DATABASE` / `RESTORE DATABASE` only address local files.** Both admin statements
   (`crates/graphus-server/src/admin.rs`) take a bare filesystem `path` string interpreted on the
   server's own host; there is no upload/download transport for the backup artifact
   (`05-storage-format.md` §11). They are also not the right tool for this problem even if they
   had a transport: `RESTORE DATABASE` replaces a database's entire content and requires the
   database to be stopped first (`FR-BR` domain); it is not an incremental-load primitive.
3. **Cypher over Bolt does not scale to this size.** The only network-reachable write path today
   is ordinary parameterized Cypher (`MATCH ... MATCH ... CREATE` with `UNWIND` for batching).
   Measured live against `pi516`: creating a relationship that anchors on two node lookups costs
   tens of milliseconds, and this cost **does not improve** with larger client-side batches or
   with client concurrency, because all writes against one database serialize onto that
   database's single engine thread (the ratified single-writer model, `D-storage-arch`;
   `D-read-parallelism` deferred read-parallelism, not write-parallelism). At this rate, loading
   1,000,000 users' worth of relationships would take years. This matches a related, already
   diagnosed planner limitation: per-edge `CREATE` with two id-anchored `MATCH` clauses is `O(E ·
   N)`, because the rule-based planner index-seeks only the first anchor — documented in
   `crates/graphus-social-gen/src/load.rs` and the reason the `social-network-large` example's own
   loader uses `graphus-bulk`'s `BulkImporter` (an `O(E)` internal hash-map endpoint resolution)
   instead of Cypher for ingest, but only because that loader runs **in the same process**, over a
   store it opens itself — the option this document adds a network-reachable equivalent of.

**Scope note.** This document does not propose changing the single-writer-engine-thread model,
and does not revisit `D-read-parallelism` (rmp #146, deferred) or the per-edge Cypher planner
limitation. Network bulk import reaches large scale by **batching** — amortizing the fixed
per-commit cost (WAL group commit, catalog write, and, for Mode B, SSI/index-maintenance
bookkeeping) across thousands of records instead of paying it per Cypher statement — not by
parallelizing writes. Mode A (§5.1) reaches this via the same **direct, low-level store writes**
the existing offline importer already uses; Mode B (§5.3) batches through the ordinary
transactional write path instead, because it must remain serializable against concurrent traffic
(§7.2) — see §9 for how this changes the two modes' expected throughput.

## 2. Relationship to existing specification

- **`FR-BK-2`** (offline bulk importer) gains one required correctness fix as a prerequisite of
  this capability (§7.2.2, the `id_map` staging fix), applying to `graphus-bulk` itself, but its
  own behavior and CLI surface are otherwise unchanged. Network bulk import is additive on top:
  Mode A (§5.1) reuses the same low-level server-side ingestion logic reached over a new transport
  (§4); Mode B (§5.3) reuses the same external-id→physical-id resolution strategy but drives it
  through the ordinary `TxnCoordinator`/`record_graph` write path instead (§7.2), because it must
  participate in MVCC/SSI conflict detection and inline index maintenance against concurrent
  traffic.
- **`FR-BK-5`** (`[ADV]` "Incremental/resumable import") is **promoted from aspirational to a
  hard requirement for the network case, both modes** (§7.1): a network transfer of a
  hundreds-of-GB dataset can and will be interrupted, and the operator must be able to resume
  without restarting from zero.
- **`D-bulk-import-non-atomic`** (rmp #403, ratified) — "bulk import is non-atomic (per-batch
  commit); document + DST-gate, no temp-rename" — already governs the offline importer. §7.1 of
  this document **extends that ratified decision to the network case** rather than contradicting
  it: the same per-batch-commit model is reused, and the network transport's inherent
  unreliability is exactly why resumability (not all-or-nothing atomicity) is the right shape,
  consistent with the rationale already recorded for `D-bulk-import-non-atomic`.
- **`D-security-scope`**, **`D-auth-scheme`** (ratified) — network bulk import is gated by the
  same shared RBAC model (`graphus-auth`) as every other interface; see §6.
- **`D-multi-db`** (ratified) — Mode A's exclusivity (§5.2) is scoped to the one target database;
  every other database on the server is unaffected, per the existing containment/isolation
  requirement. Mode B has no exclusivity mechanism at all (§5.3) and relies entirely on MVCC/SSI
  for correctness, same as any other concurrent traffic against a `D-multi-db`-isolated database.
- **`D-read-parallelism`** (rmp #146, deferred) — the original proposal flagged live-database bulk
  load as "the same risk family" as this deferred decision (large writes contending with
  concurrent access) and recommended against it for that reason. The owner ratified it anyway;
  §7.2 is the concurrency-safe design that makes it sound **without** touching
  `D-read-parallelism` or the single-writer-engine-thread model it defers changing — Mode B adds a
  new, careful **write**-side client of the existing coordinator, it does not parallelize reads or
  change the engine's threading model. This decision remains independently deferred and
  unaffected by this document.
- **`bulk-gcol-format`** (rmp #327) — the existing lossless columnar `.gcol` format is reused as
  one of the two accepted wire payload formats (§4).

## 3. Transport

### 3.1 Options considered

- **(a) Bolt protocol extension.** Add a new Bolt message type (e.g. a `BULK_CHUNK` /
  session-open / session-commit triad) to stream payload bytes over an existing Bolt (UDS or TCP)
  connection.
- **(b) Bolt, reusing only standard messages.** Drive the transfer as many bounded,
  session-scoped `RUN`/`PULL` calls (the same pattern `BACKUP DATABASE`/`RESTORE DATABASE`
  already use — a plain string parsed by the admin grammar, executed through the ordinary Bolt
  message set, no protocol change), each carrying a bounded-size payload chunk as a PackStream
  parameter.
- **(c) REST/HTTP streaming upload.** A new, dedicated REST endpoint that accepts a
  chunked-transfer-encoded (or `Content-Length`-declared) request body and reads it
  incrementally, never buffering the whole payload in memory.

### 3.2 Findings (grounded in the official Bolt/PackStream specification)

Consulted against the authoritative Bolt message and PackStream specifications
(`03-sources.md`, "Neo4j Bolt protocol" — already an authoritative source for `04-technical-design.md`
§8.1 and `06-bolt-and-error-shapes.md`):

- **Bolt has no client-to-server multi-message streaming primitive.** Chunking (`04` §8.1) is
  purely transport-level framing for **one logical message** (a 2-byte length header per chunk,
  max 65,535 payload bytes, terminated by a zero-length chunk); it does not let a client
  accumulate a payload across multiple requests as one unit. The `RECORD`-based streaming model
  (§7.7) is server-to-client only; there is no reverse equivalent.
- **PackStream has a hard, spec-mandated size ceiling.** The largest PackStream size tier
  (`BYTES_32`/`STRING_32`/etc., a 32-bit size field) is capped by the specification itself at
  **2,147,483,647 bytes** (signed `int32` max, ~2 GiB) — not the full unsigned range, and not a
  server-side tuning knob. A single PackStream value cannot carry a 100+ GB payload at all, and
  the size prefix must be known and written **before** the content — there is no
  unknown-length/incremental PackStream encoding. This rules out option (a)'s naive form (one
  giant value) outright, independent of any implementation choice.
- **A new Bolt message type is a genuine compliance violation, not a gray area.** The Bolt
  specification enumerates a **closed set** of message signature bytes and documents **no
  reserved or private-use extension range**. Adding an undocumented signature byte means the
  server's protocol surface would no longer match the specification — this is squarely what
  `CLAUDE.md`'s inviolable "100% Bolt protocol compliant, no deviations" requirement forbids, not
  a matter of degree. Option (a) is therefore **rejected**, independent of scale.
- **Option (b) is spec-conformant but architecturally the wrong tool.** Bounded, session-scoped
  `RUN`/`PULL` chunk calls use only standard, fully-defined Bolt messages (no compliance risk),
  the same way `BACKUP`/`RESTORE`/`CHECKPOINT DATABASE` already extend the *admin statement*
  surface without touching the wire protocol. It would work, but every chunk pays a full
  RUN→SUCCESS/PULL→RECORD/SUCCESS round trip and a PackStream re-encode of what is, at that
  point, just an opaque byte blob — overhead that buys nothing, since Bolt's per-message
  serialization is designed for typed, structured Cypher values, not for moving raw bytes.
- **REST/HTTP has no such ceiling and is the standards-native fit.** HTTP/1.1 chunked
  transfer-encoding (RFC 9112, already a cited source) and HTTP/2 (RFC 9113) are designed
  precisely for large, incrementally-produced/consumed bodies, with no PackStream-style size
  cap. `graphus-rest` already establishes the pattern this capability needs on the **opposite**
  data direction: the `rest-unbounded-egress-oom` finding (rmp #475, fixed) replaced full
  in-memory result buffering with a streamed response body (`Body::from_stream` over a bounded
  channel) precisely to keep server memory bounded for large result sets. Network bulk import
  needs the **symmetric ingress-side** treatment.

### 3.3 Recommendation

★ **Option (c): a dedicated REST streaming-upload endpoint.** Bolt is not used for the bulk
payload itself, for the compliance and architectural reasons in §3.2. This is the single most
consequential call in this proposal and needs explicit ratification (see the summary at the end
of this document).

Design:

- A new route, e.g. `POST /admin/db/{db}/bulk-import`, added to `graphus-rest`'s router
  (`crates/graphus-rest/src/router.rs`), distinct from the existing `/db/{db}/tx*` transactional
  Cypher surface (§8.2 of `04-technical-design.md`) — this is an **operator/admin** endpoint, not
  a data-plane query endpoint, matching how `BACKUP`/`RESTORE`/`CREATE DATABASE` are
  administrative rather than query operations.
- The request body is read as an **async byte stream**, never buffered whole. It is **exempt**
  from the general `MAX_REQUEST_BODY_BYTES` (4 MiB) `DefaultBodyLimit` that governs the
  transactional Cypher routes — that limit exists to bound an ordinary query payload, and does
  not apply to a purpose-built bulk-data channel with its own bounded, chunked ingestion and its
  own resource limits (§8).
- `Transfer-Encoding: chunked` (or a declared `Content-Length` for tooling that cannot stream) is
  accepted; TLS is mandatory beyond loopback, matching `FR-SE-4` and every other REST route.
- The endpoint is authenticated and authorized exactly like the Bolt/CLI admin surface (§6), so
  operators who already script `BACKUP`/`RESTORE`/`CREATE DATABASE` over Bolt gain a REST path
  for this one operation without a new authentication model.

**Explicitly deferred, not rejected outright:** a Bolt-side **session control** surface (status,
progress, cancel — small, bounded messages, not the payload itself) mirroring the
`BACKUP`/`RESTORE`/`CHECKPOINT DATABASE` admin-statement pattern (option (b), applied only to
control messages) is a reasonable Phase-2 addition for Bolt-only operator tooling. It is **out of
scope for this proposal** to keep the delivered surface minimal and self-contained; the REST
endpoint alone is sufficient to unblock the motivating need in §1.

## 4. Payload format

### 4.1 Options considered

- **(a) Reuse the existing local import formats.** The `neo4j-admin import`-flavoured CSV format
  (`graphus-bulk`'s `header`/`import` modules) and the columnar `.gcol` format (rmp #327,
  `bulk-gcol-format`) that `graphus-bulk import --format csv|gcol` already parses.
- **(b) Define a new network-specific binary format.**

### 4.2 Recommendation

★ **Option (a).** No new wire format is invented. The HTTP request body **is** a CSV or `.gcol`
byte stream in exactly the shape `BulkImporter`/`csv_to_gcol`/`gcol_to_csv` already consume and
produce locally; `Content-Type: text/csv` or `application/vnd.graphus.gcol` selects the decoder,
mirroring the existing `--format csv|gcol` CLI flag. This means the server-side ingestion logic
(header parsing, typed-column decoding, the external-`:ID`→physical-id hash map, batched
low-level store writes) is **shared, unmodified code** between the offline tool and the network
endpoint — only the byte source changes, from a local `File` to a network stream reader. This
directly serves the "measure to decide" and "production-grade" project rules: reusing
already-certified (`bulk-importer`, certified sprint 7) parsing/import logic carries far less
risk than inventing and hardening a new format under a deadline. `.gcol` is recommended as the
default for large transfers (it is the more compact, lossless, columnar encoding); CSV remains
available for tooling that cannot produce `.gcol`.

Node and relationship files are sent as **separate request bodies** (separate calls against the
same bulk-import session), matching the existing `--nodes`/`--relationships` file-set model —
nodes must fully land before relationships that reference them, exactly as today's `BulkImporter`
requires.

## 5. Session lifecycle and database exclusivity

**Ratified scope (2026-07-01): two supported target-database modes.** The owner selected the
non-recommended option: network bulk import must work against **both** a fresh/empty database
(**Mode A**) **and** an already-live, already-serving database under ordinary concurrent traffic
(**Mode B**). The two modes have different exclusivity models and, as a direct consequence,
different implementations underneath the shared transport/format/RBAC surface (§3/§4/§6) — Mode A
keeps the low-level, single-writer, no-conflict-detection fast path (closest to today's offline
`BulkImporter`); Mode B is a materially different code path, detailed in §5.3 and §7, because it
must never violate serializability against concurrent client transactions.

A bulk-import session declares its mode explicitly when it opens (it is never inferred), so the
server can pick the correct code path up front rather than detect contention after the fact.

### 5.1 Mode A — fresh, empty target database (exclusive)

Network bulk import targets a database created for the purpose (`CREATE DATABASE <name>`,
`FR-MT-2`) and **not yet started for ordinary traffic** — the same precondition the offline
importer already enforces ("it must not already contain a store"). This is the lower-risk,
higher-throughput mode and is what the motivating measurement (§1) actually needs (a large
*initial* load for load testing); it remains fully specified and recommended as the default
choice whenever an operator does not specifically need to load into a database that is already
serving traffic.

### 5.2 Mode A's lifecycle state — `Loading`

The durable database catalog (`crates/graphus-server/src/dbcatalog.rs`) today models exactly two
states, `DbState::Online` / `DbState::Offline` (the same enum `START DATABASE`/`STOP DATABASE`
drive, and the one `RESTORE DATABASE` requires `Offline` for). Mode A adds a third state:

- **`Loading`** — the engine for the target database **is running** (so it can receive the
  stream and commit batches through the normal WAL/commit path) but the database is **not open
  to ordinary Bolt/REST client traffic**. Any client attempt to run a query against a `Loading`
  database is rejected with a typed, retriable error (the REST/Bolt analogue of the existing
  "database is stopped" class of error), not silently queued.
- A database enters `Loading` when a Mode A session opens against it (requiring it to be freshly
  created — see §5.1) and leaves `Loading` only through an explicit operator action on session
  completion — **not automatically** — mirroring the existing `RESTORE DATABASE` precedent
  (stopped first, started explicitly by the operator afterward). This gives the operator a
  deliberate checkpoint to build indexes (`FR-IX`) or run validation before opening the
  freshly-loaded database to traffic, and keeps the state machine simple: `Loading` only ever
  transitions to `Offline` (session ended, clean or not), never directly to `Online`.
- **Exactly one Mode A session per database at a time**, enforced by the `Loading` state itself (a
  second session against the same database is rejected). **Other databases on the same server are
  entirely unaffected** — this is a per-database exclusivity mechanism, not a server-wide one,
  matching `D-multi-db`'s containment model.

### 5.3 Mode B — already-live database (concurrent, no exclusivity)

Mode B targets a database that is `Online` and stays `Online` for the whole session: it is **not**
stopped, not moved to `Loading`, and continues serving ordinary Bolt/REST reads and writes from
other clients throughout the import. There is **no new lifecycle state** for Mode B — this is a
deliberate consequence of the requirement, not an oversight: the whole point of Mode B is that the
database is never taken out of service.

- **No exclusivity mechanism exists or is needed.** Correctness under concurrency is instead
  guaranteed entirely by routing every row the session ingests through the **same MVCC + SSI
  machinery** every other write already goes through — detailed in §7. This is the fundamental
  difference from Mode A: Mode A is safe *because* it has no concurrent access to reason about;
  Mode B is safe *because* it participates fully in the concurrency control that already makes
  ordinary concurrent Cypher transactions safe.
- **Multiple Mode B sessions may run concurrently against the same database** (e.g. one importing
  nodes of one label set while another imports a different one), and against different databases,
  subject only to the resource limits in §8 — there is no per-database "one session" restriction
  in Mode B, because there is no exclusive state to contend over.
- **Precondition:** the target database exists and is `Online`. Mode B does not require the
  database to be empty; it is explicitly designed for incremental load into a populated graph.

## 6. Security and RBAC

★ **Recommendation: require the global `Admin` privilege** (`Privilege::admin_database()` in
`graphus-auth`), the same single gate `authorize_admin` already applies to `CREATE`/`DROP`/
`START`/`STOP DATABASE`, `BACKUP`/`RESTORE`/`CHECKPOINT DATABASE`, and all user/role management
(`crates/graphus-server/src/admin.rs`). **Ratified for both modes, unchanged.** Rationale:
network bulk import is, like those operations, an **operator-level** action in either mode — it
can write hundreds of millions of records and consume proportionate disk/memory/CPU, and it is
opened as a distinct session outside the ordinary per-statement Cypher write path (so it does not
automatically inherit the fine-grained `Write`/`Schema` RBAC checks that gate ordinary data
mutation, even though Mode B's *rows* are, per §7.2, driven through the same underlying
`record_graph` write seam as an ordinary Cypher write for SSI/index-maintenance correctness) — so
it must not be reachable by a principal who only holds data-level `Write` on some label/property
scope. Mode A additionally takes exclusive control of the target database (§5.2); Mode B does
not (§5.3), but still requires `Admin` because opening an import session at all — regardless of
whether it takes the database offline — is the operator-level action being gated, not the
exclusivity itself. This is consistent with, not an exception to, the existing RBAC containment
model (`crates/graphus-auth/src/rbac.rs`): `Admin` over `Resource::Database` already implies
authority over everything, everywhere.

- The new REST endpoint (§3.3) is authenticated with the same Bearer/JWT scheme as every other
  REST route (`D-auth-scheme`) and denies with the same `Neo.ClientError.Security.Forbidden` /
  HTTP 403 shape the admin surface already uses, so tooling that already handles admin-endpoint
  authorization errors needs no special case.
- Every session-lifecycle event (open, resume, complete, abort) is audited via the existing
  `AuditClass::AdminChange` channel (`crates/graphus-server/src/audit.rs`) — the same class
  `CREATE`/`START`/`STOP DATABASE` already use — with the acting principal, the target database,
  and the outcome recorded; a denial is audited as `AuthzDenied` before any side effect, matching
  the existing `authorize_admin` → `execute` sequencing.
- TLS is mandatory for the endpoint beyond loopback (`FR-SE-4`); the endpoint's own request-size
  behavior (§8) is itself part of the `FR-SE-6` "request hardening" requirement (body-size
  limits, timeouts, rate limiting) already declared in the needs survey, applied to this new,
  deliberately oversized-body-tolerant route.

**Alternative considered and not recommended:** a new, narrower privilege (e.g. `Action::Write`
scoped to the target `Graph(db)`) so a delegated data-loading role need not hold full server-wide
`Admin`. This is not recommended for the initial delivery: for Mode A it does not compose cleanly
with the exclusivity model in §5.2 — taking a whole database offline for ordinary traffic is
itself an administrative action regardless of who performs it; for Mode B it does not compose
cleanly with the resource impact and audit posture operators expect of a session that can write
at import scale against a live, multi-tenant server (§8) — a capability with this much blast
radius is deliberately kept behind the same gate as the rest of the operator surface, even though
Mode B's individual row writes are themselves SSI/RBAC-consistent with ordinary `Write` grants at
the data level. If the owner wants delegated, non-admin bulk-load access later, a graph-scoped
variant (mirroring how `Action::Schema` was carved out of the `Admin` super-action for DDL, rmp
#457) can be proposed as a follow-up once the core capability is in production.

## 7. ACID and consistency semantics

This section **extends `D-bulk-import-non-atomic`** (rmp #403, ratified for the offline case) to
the network case; it introduces no new exception to the inviolable "100% ACID compliant"
requirement, in **either** mode. Mode B's design (§7.2 onward) was independently validated by the
`storage-systems-auditor` agent against the actual `graphus-txn`/`graphus-cypher`/`graphus-bulk`
code on 2026-07-01; its verdict ("structurally sound; ship it") and the one required fix it
surfaced are both incorporated below.

### 7.1 Mode A (fresh, empty database) — unchanged

- **Per-batch atomicity, whole-session non-atomicity.** The network endpoint feeds the same
  `BulkImporter` batching model (`DEFAULT_BATCH_SIZE = 10,000` records) through the same
  WAL/group-commit path as every other transaction. Each committed batch is fully durable and
  internally consistent the moment it is acknowledged; the import **as a whole** is not
  all-or-nothing, exactly as already ratified and documented for the offline tool. This is not a
  new risk introduced by the network transport — it is the existing, already-DST-gated behavior,
  reused.
- **Resumability is a hard requirement (promotes `FR-BK-5` from `[ADV]`/aspirational to required
  for this capability, both modes).** A network transfer of a multi-hundred-GB dataset will,
  eventually, be interrupted by a dropped connection. The server durably records, **in the same
  commit as the data**, a session checkpoint (session id, last successfully committed batch
  sequence number, byte offset into the current source file) — so the checkpoint is
  crash-consistent with the data it describes by construction, never a separate, driftable
  bookkeeping write. A client that reconnects with the same session id resumes from the recorded
  checkpoint; the server never re-applies bytes already committed. **This requires the
  id-map-staging fix in §7.2.2**, which applies to both modes even though it is load-bearing only
  for Mode B today (Mode A has no concurrent writers, so it has never needed to retry a batch).
- **Recovery on unresumable failure.** If a session cannot be resumed (abandoned past a retention
  window, or the operator chooses not to resume), the documented recovery is the same as the
  offline importer's: **drop the partially-loaded database and retry** (`D-bulk-import-non-atomic`'s
  existing rationale — no temp-directory/atomic-rename scheme; the cost of building one was
  already rejected for the offline case, and nothing about the network transport changes that
  trade-off, since the database was never open to other traffic during the `Loading` state, so a
  drop-and-retry has no externally-visible consistency cost).
- **Crash recovery of a `Loading` database uses the same ARIES machinery as any other database**
  (`04-technical-design.md` §4.8): on restart, a database found in the `Loading` state replays its
  WAL like any other, recovers to the last committed batch, and stays `Loading` (not `Online`) —
  an operator must still explicitly resume or abandon the session, consistent with "explicit, not
  automatic" state transitions in §5.2.

### 7.2 Mode B (already-live database) — the concurrency-safe design

**The single governing rule: a Mode B batch is a first-class `TxnCoordinator` transaction, never
a raw `RecordStore` write.** Today's offline `BulkImporter` calls
`RecordStore::create_node`/`create_rel`/`set_node_property_value` **directly**
(`crates/graphus-bulk/src/import.rs`), bypassing `graphus-cypher::TxnCoordinator` — the layer that
owns the shared `SsiTracker` (SIREAD markers, rw-antidependency edges, pivot-abort-at-commit) and
`LockTable` (first-updater-wins write-write conflicts) that let many concurrent transactions
safely interleave over one store (`04-technical-design.md` §5.4/§5.7). That bypass is exactly why
`BulkImporter` is fast today, and exactly why it is **only safe against a store with zero
concurrent access** — it registers no conflict-detection state at all. Mode B has concurrent
access by definition, so it **must** go through the coordinator:

- Each Mode B batch opens as `TxnCoordinator::begin_serializable()`; its rows are applied through
  the **same write seam the Cypher executor already uses**, `graphus-cypher::record_graph`
  (`create_node`/`create_rel`/`set_node_property`, driven directly — not via a full Cypher
  parse/plan — but calling the identical functions, so every write registers its SIREAD/predicate
  markers and takes its write lock exactly as an equivalent Cypher `CREATE` would). **A
  "bulk-optimized" reimplementation that skips these calls for speed is explicitly disallowed** —
  the audit confirmed this is the one point where cutting a corner reopens a real serializability
  hole.
- The batch closes with `TxnCoordinator::commit(txn)`, which runs the same SSI validation as any
  other transaction and may abort it as a **pivot**, with the same PostgreSQL-style safe-retry
  victim selection already used for every other transaction (`04` §5.4) — bulk-import batches are
  just one more kind of transaction in that graph, with no special exemption.
- **Index maintenance happens inline, batch-by-batch, not deferred to session end.** A live
  database already has active indexes serving concurrent queries; unlike Mode A (where indexes
  are built by the operator only after the whole import finishes, matching today's offline
  workflow), Mode B must call `reindex_node` (the same function ordinary Cypher writes already
  trigger) for every node/relationship it creates, or a concurrent index-based query would observe
  incomplete or stale results for the imported data — a correctness bug, not merely a staleness
  one. This is the second reason the coordinator/`record_graph` seam is mandatory: it is where
  `reindex_node` already lives.

#### 7.2.1 Where real conflicts come from (audited finding)

The audit traced the actual predicate-marker code (`graphus-txn/src/ssi.rs`,
`graphus-cypher/src/record_graph.rs`) and found the dominant, **correct** (not spurious) source of
contention is **not** hot individual nodes — it is **relationship-type-wide** predicate markers.
`create_rel` registers a marker against the *type-wide* `RelType`/`AnyRel` predicate, not (only)
against the two endpoint nodes' own keys. This means: **a Mode B session inserting many edges of a
given relationship type will genuinely, correctly conflict with any concurrent query that scans or
counts that whole type** (e.g. `MATCH ()-[:FRIEND]->() RETURN count(*)`), independent of which
physical nodes either transaction touches. This is expected SSI behavior protecting a real
serialization anomaly (the concurrent scan and the concurrent insert are a genuine rw-antidependency
pair), not a bug — but it is the direct, load-bearing reason batch size and abort-retry behavior
need deliberate design for Mode B, unlike Mode A's contention-free environment:

- **Batch size for Mode B is measurement-gated and expected to differ from Mode A's** default
  `DEFAULT_BATCH_SIZE = 10,000`. A larger in-flight batch has a larger SIREAD/write-lock footprint
  held open for longer, raising both the probability of a pivot abort against concurrent
  type-wide scans and the wasted work ("blast radius") of a whole-batch retry when one occurs. The
  exact default is **not asserted here** (project rule: "measure to decide") and must be tuned
  empirically once implemented, against a workload that mixes bulk import with concurrent
  analytics-style scans over the same relationship types.
- **Operator guidance** (to be surfaced in the implementation, not enforced by the server): running
  a large Mode B import concurrently with heavy analytics scans over the *same* relationship
  types/labels it is populating will produce a higher abort/retry rate than importing types the
  live workload does not currently scan. This is documented behavior, not a defect to fix.

#### 7.2.2 Required prerequisite fix: batch retry is not yet idempotent

The audit found a **pre-existing, must-fix correctness bug** in `graphus-bulk::BulkImporter`
(`crates/graphus-bulk/src/import.rs`) that Mode B's retry requirement turns from latent into
load-bearing:

- `ingest_node_record` binds `id_map[external_id] = node_id` **immediately** after
  `store.create_node` succeeds — **before** the enclosing transaction commits.
- `rollback()` calls `store.rollback(txn)` but **never reverts `id_map`**.
- Consequence: on an SSI pivot abort of a batch (an expected, ordinary event under Mode B — see
  §7.2.1), every row already ingested in that attempt has already polluted `id_map` with bindings
  to now-rolled-back, no-longer-existent node ids. Retrying the same rows then either (a) fails
  every time with a spurious "duplicate `:ID`" error under `DuplicatePolicy::Strict` — turning a
  rare, auto-retried event into an import that reliably poisons itself on its first conflict — or
  (b) under `DuplicatePolicy::SkipDuplicate`, silently creates orphan nodes unreachable by external
  id while `id_map` still points at garbage ids from the rolled-back attempt, so a later
  relationship-pass join against that map produces **wrong relationships or silently dropped
  ones** — genuine data corruption, not just an error.

**Required fix (a prerequisite for shipping Mode B, and a strict improvement for Mode A too):**
any in-process state a batch accumulates outside the store transaction — chiefly `id_map` — must
be staged per attempt (e.g. a scratch map local to the current attempt) and merged into the
durable, session-scoped map **only after `commit()` succeeds**. It must never be mutated eagerly
during row ingestion. This makes whole-batch retry actually safe and idempotent: a retried attempt
starts from the last-known-good durable map, re-ingests the same external ids into a fresh scratch
map, and only publishes them once its own commit succeeds.

This is registered as a Finding in the project Knowledge Graph
(`bulk-idmap-not-abort-safe`, `graphus-bulk`, severity high, status open) and **must be fixed
before Mode B's automatic batch retry is enabled**; it is a precondition of this capability's
acceptance criteria (§11), not a follow-up.

#### 7.2.3 Batch-abort/retry semantics

- On a pivot abort, **none** of the batch's writes are visible (full transactional rollback,
  standard ACID atomicity — already a required property of every aborting transaction today,
  independent of this feature). The session's durable checkpoint offset (§7.1) only advances past
  a batch once it actually commits.
- The server automatically retries an aborted batch, bounded by a configurable retry count, once
  §7.2.2's fix makes retry idempotent. If a batch keeps aborting past the retry bound (a
  persistently hot contended relationship type/predicate), the session surfaces a retriable error
  to the client rather than looping forever, so a pathological contention case is observable
  instead of silently stalling.

#### 7.2.4 Reader visibility during a Mode B session

No new visibility mechanism is introduced; standard MVCC snapshot semantics already answer every
question here, because Mode B batches are ordinary committed transactions:

- A concurrent reader with a snapshot begin timestamp **before** a batch's commit does not see
  that batch's rows; a reader whose snapshot begins **after** does. This is exactly today's
  visibility rule (`04-technical-design.md` §5.3), unconditionally.
- A reader can therefore observe a graph that is **partially imported** — e.g. 3,000,000 of an
  eventual 5,000,000 nodes, or nodes without their relationships yet if the node pass has not
  finished (§4.2's two-pass, node-file-before-relationship-file model still applies within Mode B).
  This is **not** an inconsistent or corrupt state: every batch that committed is fully valid and
  internally consistent; the reader simply sees "however much has committed so far," which is the
  same guarantee any other long-running sequence of committed transactions already provides. Making
  the whole import invisible until the session ends would require new machinery (an artificial
  visibility veil over already-committed data) that is unnecessary complexity and arguably
  contradicts "once committed, durable and visible" — incremental, per-batch visibility is
  recommended and requires no new mechanism.
- **Dense/hot pre-existing nodes.** If the imported dataset attaches many new relationships to a
  small number of pre-existing supernodes, those writes inherit whatever concurrent-append behavior
  already exists for ordinary concurrent Cypher writes to a dense node (`04-technical-design.md`
  §2.5; the existing `concurrent_supernode`/`supernode_fanout` DST scenarios already exercise this
  path for two ordinary writers). Mode B introduces no new dense-node mechanism; it is simply
  another concurrent writer to that structure, at potentially much higher write volume than a
  typical client — flagged in §8/§10 as a throughput hazard to measure, not a correctness gap.

#### 7.2.5 WAL, checkpoint, and recovery

Because Mode B batches are ordinary `TxnCoordinator` transactions, they participate in the
**existing** WAL/group-commit/ARIES recovery machinery automatically, interleaved with every other
concurrent transaction exactly as the recovery design already assumes (`04-technical-design.md`
§4.8: recovery already handles arbitrary interleaving of many transactions' commits). **No new
recovery mechanism is required.** The session checkpoint (§7.1) is written as an ordinary part of
each batch's commit, so it is crash-consistent with the data by the same mechanism, not a special
case.

#### 7.2.6 Single-writer engine thread: a fairness requirement, not a correctness one

The audit confirmed the single-writer-engine-thread model is real (`graphus-server/src/engine/mod.rs`,
a `std::sync::mpsc` `EngineCommand` queue: one OS thread executes one statement/commit at a time
for a given database). This changes **nothing** about Mode B's correctness — SSI already handles
arbitrary interleaving of many transactions' statements on one thread, which is exactly what
already happens for ordinary concurrent client traffic today. It **does** directly determine
Mode B's impact on concurrent client latency: **the batch driver must yield the engine thread at
small sub-batch (ideally per-row or a tight, small chunk) granularity, never submit an entire
10,000-row batch as one uninterruptible engine command.** Otherwise a Mode B import — even though
fully serializable and correct — would starve concurrent live Bolt/REST traffic for the duration
of each batch, defeating the purpose of choosing Mode B (staying online) in the first place. This
is a **hard requirement**, not a later optimization; it is included in the acceptance criteria
(§11).

## 8. Denial-of-service and resource limits

The project has a documented history of exactly this class of finding (`rest-unbounded-egress-oom`,
rmp #475; the pre-auth PackStream recursion and slow-consumer findings of sprint 41/42). A
purpose-built large-body endpoint must not reopen that class of risk on the ingress side.

- **Never buffer the whole upload.** The request body is decoded and imported in bounded chunks
  as bytes arrive (the same `DEFAULT_BATCH_SIZE` batching already used locally), with
  **backpressure**: the server stops reading further bytes from the socket while a batch is
  committing, so an unbounded producer cannot force unbounded server-side buffering — this is the
  ingress-side mirror of the `Body::from_stream` bounded-channel pattern the rmp #475 egress fix
  already established.
- **A configurable total byte quota per session**, enforced as bytes are consumed (not
  after-the-fact), so a session cannot silently grow past an operator-set ceiling.
- **A disk-space preflight and an ongoing check.** Refuse to open a session (or abort an
  in-progress one) when free space on the target device is insufficient, rather than running the
  device out of space mid-import (torn-write and fsync-failure handling, `04` §4.5/§4.9, still
  applies underneath, but an operator-facing disk-exhaustion guard is a distinct, cheaper
  first line of defense).
- **Per-session idle timeout and maximum session duration**, so an abandoned or deliberately
  slow-loris'd session does not pin resources (the `Loading` state for Mode A, or an open
  `TxnCoordinator` transaction/lock/SIREAD footprint for Mode B) indefinitely.
- **Reachable only by `Admin`-privileged, authenticated principals** (§6) — unlike the general
  REST/Bolt query surface, this endpoint is never reachable pre-auth or by an untrusted,
  low-privilege caller, which materially narrows the DoS surface compared to, e.g., the
  pre-auth findings of sprint 41.
- **Mode A: one session per database (§5.2) plus a small, server-wide cap on concurrently
  `Loading` databases**, so a multi-tenant server cannot have all its I/O/CPU/memory budget
  claimed by simultaneous bulk-import sessions against different databases.
- **Mode B: a server-wide cap on concurrently open Mode B sessions (across all databases)**,
  since Mode B has no exclusivity mechanism to naturally bound concurrency (§5.3) — the cap exists
  purely to bound aggregate resource consumption (memory for in-flight batches/id-maps, SSI
  tracker footprint, engine-thread contention) against ordinary live traffic, not for correctness.
- **Engine-thread yielding (§7.2.6) is itself a DoS control for Mode B**, not just a fairness
  nicety: without it, a single Mode B session could starve every other client of the engine thread
  for a batch's whole duration — a self-inflicted denial of service against the server's own live
  traffic. This is why §7.2.6 states it as a hard requirement.

## 9. Performance model and non-goals

- **Mode A** reaches high throughput by reusing `BulkImporter`'s existing `O(E)` strategy — direct
  low-level store writes plus an in-session external-id→physical-id hash map — **not** by
  parallelizing writes or by changing the single-writer-engine-thread model. This is consistent
  with `D-storage-arch` and the still-deferred `D-read-parallelism` (rmp #146): this proposal does
  not touch either.
- **Mode B keeps the same `O(E)` id-map strategy for endpoint resolution** (avoiding the Cypher
  planner's per-edge index-seek cost, §1) but pays two real, necessary costs Mode A does not: SSI
  bookkeeping (SIREAD markers, write locks) and inline index maintenance (`reindex_node`) on every
  row, per §7.2. **Mode B throughput is therefore expected to be measurably lower than Mode A's**,
  and variable under contention (§7.2.1) — this is the correct, expected cost of staying online
  during the import, not a defect. Expected numbers are not asserted here and must be measured.
- **Explicit non-goal:** this capability does not make ordinary Cypher `CREATE`/`MERGE` fast at
  scale, and it does not address the separately-tracked planner limitation (single-anchor index
  selection across a join in two-anchor relationship `CREATE`, noted in
  `crates/graphus-social-gen/src/load.rs`). Both remain open, independently trackable items if
  the owner wants them pursued; they are out of scope here.
- Expected throughput should be validated empirically once implemented (project rule: "measure to
  decide"), against the same LDBC-flavoured / social-network-large workload used for the
  motivating measurement. For Mode A, isolate network transport overhead (chunked HTTP read +
  backpressure) from the underlying `BulkImporter` cost already measured for the offline path. For
  Mode B, additionally measure throughput and abort/retry rate as a function of (a) batch size and
  (b) the intensity of concurrent live traffic over the same labels/relationship types being
  imported (§7.2.1), to set the measurement-gated default batch size.

## 10. Testing (DST requirement)

Per `CLAUDE.md`, any test scenario touching concurrency, faults, or crash/recovery **must** be
driven through the DST/VOPR simulator (`07-dst-simulator.md`). The existing `bulk_ingest` DST
scenario (§ "OLTP / ingest / serving") exercises write-heavy ingest through the ordinary
transactional path; the existing `contended_writes`/`concurrent_supernode`/`snapshot_isolation`
scenarios (§ "Isolation / concurrency") exercise two ordinary concurrent writers/readers. None of
these exercise this capability's specific new surfaces — a bulk-import session's own batching,
retry, and checkpoint behavior interleaved with live traffic. **Two new DST scenarios are
required**, one per mode:

### 10.1 `network_bulk_ingest_mode_a` (fresh, empty database)

- A full session against a simulated transport with the seeded transport-fault models
  `07-dst-simulator.md` already provides (mid-stream disconnect, partial-chunk delivery),
  asserting the resume-from-checkpoint behavior in §7.1 is byte-for-byte deterministic and
  lossless (`created == persisted`, no duplicated or skipped records across a resume) — this is
  also the regression test for the §7.2.2 id-map-staging fix (a retried batch under a simulated
  abort must not corrupt or duplicate the id map).
- A crash (disk/clock fault injection) while a database is `Loading`, asserting recovery leaves it
  `Loading` (not `Online`, not silently `Offline` with data loss) at exactly the last committed
  batch, per §7.1.
- A concurrency check that ordinary client traffic against a `Loading` database is cleanly
  rejected, and that traffic against every **other** database on the same server is completely
  unaffected (the `D-multi-db` isolation claim in §5.2), for the duration of the session.
- A resource-limit check that the byte-quota, disk-preflight, and session-timeout guards in §8
  fire deterministically under a seeded oversized/slow-producer scenario, exercising the same
  class of oracle the rmp #475 egress fix already established for the opposite direction.

### 10.2 `network_bulk_ingest_mode_b` (already-live database, concurrent) — the higher-priority scenario

This scenario carries the real correctness risk of the ratified scope and must give the
serializability guarantee the same DST-grade proof every other concurrency claim in this project
gets (`07-dst-simulator.md`'s oracles: the strong reference model and the Elle isolation checker),
not just an ad-hoc integration test:

- **Interleave a Mode B session with ordinary concurrent Cypher writers and readers** over the
  same database, including at least one concurrent writer/reader that touches the **same**
  relationship type(s) the import is populating, to exercise the type-wide predicate-marker
  contention in §7.2.1 — asserting every committed batch and every committed concurrent
  transaction is jointly serializable (Elle-checkable), with no lost updates and no phantom.
- **A seeded pivot abort of an in-progress batch**, asserting the batch-retry path (§7.2.3) is
  idempotent end to end — re-run against the id-map-staging fix (§7.2.2): the retried batch must
  produce exactly the same committed rows as a batch that never aborted, with no duplicate nodes,
  no orphaned nodes, and no corrupted relationship-pass joins.
- **Concurrent readers at various snapshot begin timestamps** across the session's lifetime,
  asserting each reader's view is exactly "every batch committed before my snapshot began, fully
  valid, nothing partial or torn" (§7.2.4) — the reference-model oracle should assert this
  precisely, not just "no crash."
- **A dense/hot pre-existing node targeted by both the import and concurrent live traffic**,
  reusing the existing `concurrent_supernode` scenario's oracle shape (§7.2.4's dense-node note)
  but with the import as one of the concurrent writers, at import-scale write volume.
- **An engine-thread fairness assertion** (§7.2.6/§8): concurrent live-traffic request latency
  during an active Mode B session stays within a bounded envelope (no multi-second stalls caused
  by an uninterruptible batch), proving the per-row/small-chunk yielding requirement is actually
  honored, not just specified.
- **A crash mid-batch** while other, unrelated transactions are concurrently committing, asserting
  recovery reconciles the interleaved WAL correctly (§7.2.5) with no special-casing failure.

## 11. Acceptance criteria

Network bulk import is considered specified (specification complete) now that:

1. `D-bulk-import-network` is **ratified** by the project owner (2026-07-01; see
   `02-decision-register.md`): global `Admin` RBAC, and **both** Mode A (fresh/empty database) and
   Mode B (already-live database, concurrent) in scope.
2. This document, `01-needs-survey.md` (`FR-BK-7`), and `02-decision-register.md` are internally
   consistent and contain no contradiction with the already-ratified `D-bulk-import-non-atomic`,
   `D-multi-db`, `D-security-scope`, `D-auth-scheme`, or `D-read-parallelism`.
3. Mode B's concurrency/ACID design (§7.2) has been independently validated against the actual
   `graphus-txn`/`graphus-cypher`/`graphus-bulk` code (`storage-systems-auditor`, 2026-07-01).

It is considered **implemented** (a separate, later milestone, tracked in `rmp`) once, for **both**
modes unless a criterion is explicitly scoped to one:

1. **Prerequisite (blocks Mode B specifically):** the id-map-staging fix (§7.2.2) is implemented
   in `graphus-bulk` and covered by a regression test proving batch retry is idempotent. Mode B's
   automatic batch retry must not be enabled before this lands.
2. The REST endpoint (§3.3) streams an upload of at least the scale in §1 (1,000,000 nodes,
   hundreds of millions of relationships) — into a fresh database for Mode A, and into a database
   under concurrent synthetic live traffic for Mode B — with bounded server memory (empirically
   measured, not assumed).
3. A session interrupted mid-transfer resumes without re-importing already-committed batches
   (§7.1), verified by `network_bulk_ingest_mode_a` (§10.1).
4. Mode B's batches are proven serializable against concurrent live traffic (no isolation
   violation, correct incremental visibility, correct behavior under a seeded pivot abort and
   retry, bounded impact on concurrent client latency), verified by `network_bulk_ingest_mode_b`
   (§10.2).
5. RBAC denies the endpoint to any principal not holding the `Admin` privilege (§6), and every
   session-lifecycle event is audited (§6).
6. The byte-quota, disk-preflight, timeout, and (for Mode B) concurrent-session-cap guards (§8)
   are exercised and proven to fire by the relevant DST scenario in §10.
7. The whole Cypher TCK (3880/3880 scenarios) and the full DST safety/liveness/swarm certification
   remain green — this capability must not regress either inviolable requirement.
