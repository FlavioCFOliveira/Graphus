# 01 — Global Needs Survey

This is the exhaustive enumeration of every need of Graphus, derived from the project
definition and from authoritative sources (`03-sources.md`). Each need carries an identifier
`FR-<DOMAIN>-<n>` and a tier:

- **[CORE]** — essential for the first solid deliverable (Phase 1 / v1).
- **[ADV]** — advanced or optional; deferred to Phase 2/3 unless a decision moves it.
- **[LIB]** — committed graph-algorithms-library workstream (dedicated phase), per `D-graph-algos`.

Tiering reflects the ratified decisions in `02-decision-register.md` (all 24 ratified 2026-06-05).

---

## 1. Data Model (DM)

The model is the **industry LPG model** (openCypher / GQL / Neo4j semantics), not the more
permissive academic set-semantics.

- **FR-DM-1** [CORE] **Nodes** with a set of zero or more **labels** and zero or more properties.
- **FR-DM-2** [CORE] **Relationships** that are directed (source → target), carry **exactly one
  relationship type**, have their own identity, and zero or more properties.
- **FR-DM-3** [CORE] **Multigraph semantics:** parallel relationships (same source, target, and
  type) and **self-loops** are valid; relationships are distinguished by identity. Storage must
  represent relationships as first-class records with incidence multisets, never collapse a
  `(source, target, type)` key.
- **FR-DM-4** [CORE] **Directed storage with undirected matching:** relationships are stored
  directed; query patterns may match them without specifying direction.
- **FR-DM-5** [CORE] **Property model:** a property key maps to exactly one value per element;
  multi-value is expressed as a single homogeneous list value.
- **FR-DM-6** [CORE] **Property value types:** BOOLEAN; INTEGER (64-bit signed, `i64`); FLOAT
  (IEEE-754 64-bit, `f64`); STRING (Unicode); and homogeneous LIST of scalar types (no nulls,
  no nesting). Maps and nested/heterogeneous lists are **not** storable as property values.
- **FR-DM-7** [ADV] **Temporal property types:** DATE, LOCAL TIME, ZONED TIME, LOCAL DATETIME,
  ZONED DATETIME (nanosecond precision; IANA + offset zones), and DURATION (months/days/seconds/nanos).
- **FR-DM-8** [ADV] **Spatial property type:** POINT with the four CRSs (cartesian 7203,
  cartesian-3d 9157, WGS-84 4326, WGS-84-3d 4979); CRS-aware comparison rules (points are not
  orderable with `<`/`>`; cross-CRS points are incomparable).
- **FR-DM-9** [CORE] **`null` handling:** properties never store `null`; setting a property to
  `null` removes it. `null` participates in three-valued logic in expressions.
- **FR-DM-10** [CORE] **Element identity:** stable element identifiers exposed to clients; an
  internal physical identifier for storage. Equality of nodes/relationships is identity-based,
  not structural. (ID scheme is decision `D-element-id`.)
- **FR-DM-11** [CORE] **Tokens:** labels, relationship types, and property keys are non-empty
  Unicode strings in three disjoint namespaces; interned in a dictionary.
- **FR-DM-12** [ADV] **Graph types / typed schema (GQL):** optional declarative graph types
  (node/edge types, property types, endpoint typing) with open/closed semantics.

## 2. Query Language — Cypher (QL)

Target: **100% Cypher TCK compliant** on a pinned openCypher snapshot (decision `D-cypher-line`).

- **FR-QL-1** [CORE] **Reading clauses:** `MATCH`, `OPTIONAL MATCH`, `WHERE`, `WITH` (with
  `DISTINCT`/`ORDER BY`/`SKIP`/`LIMIT`/`WHERE`), `UNWIND`, `RETURN` (with `DISTINCT`/`*`),
  `ORDER BY`, `SKIP`, `LIMIT`, `UNION`/`UNION ALL`, `CALL … YIELD`.
- **FR-QL-2** [CORE] **Writing clauses:** `CREATE`, `MERGE` (with `ON CREATE SET`/`ON MATCH SET`),
  `SET` (`=`, `+=`, label add), `REMOVE` (property, label), `DELETE`, `DETACH DELETE`, `FOREACH`.
- **FR-QL-3** [CORE] **Pattern syntax:** node patterns (labels, inline properties); relationship
  patterns (directed/undirected, typed, multi-type `:A|B`, inline properties); variable-length
  paths (`*`, `*m..n`); path variables; honoring multigraph semantics.
- **FR-QL-4** [CORE] **Expressions & operators:** arithmetic (`+ - * / % ^`), comparison,
  `IS [NOT] NULL`, boolean under three-valued logic, string predicates (`STARTS WITH`,
  `ENDS WITH`, `CONTAINS`, `=~`), list ops (`IN`, indexing, slicing, `+`), map/property access,
  `CASE`, quantified predicates (`ALL`/`ANY`/`NONE`/`SINGLE`), list & pattern comprehensions,
  existential subqueries (`EXISTS { … }`), and correct operator precedence.
- **FR-QL-5** [CORE] **Type/value system:** property, structural (NODE/RELATIONSHIP/PATH), and
  constructed (heterogeneous LIST/MAP) types; coercion rules (INTEGER→FLOAT widening; explicit
  `toInteger`/`toFloat`/`toString`/`toBoolean`).
- **FR-QL-6** [CORE] **Functions:** predicate, scalar, aggregating (`count`/`collect`/`sum`/
  `avg`/`min`/`max`/`stDev*`/`percentile*`), list, mathematical (numeric/log/trig), and string
  functions, scoped to the pinned TCK snapshot. Temporal/spatial functions tier with FR-DM-7/8.
- **FR-QL-7** [CORE] **Parameters & literals:** `$name` parameter binding; integer/float/string/
  boolean/null/list/map literals; a missing parameter raises `ParameterMissing`.
- **FR-QL-8** [CORE] **Exact TCK semantics:** three-valued logic; null equality vs grouping
  equivalence; `null` ordering (last asc / first desc); total ordering across types; NaN
  comparability vs orderability; aggregation grouping keys and empty-input results; `MERGE`
  whole-pattern semantics; 0-based list indexing with out-of-range → `null`; 64-bit integer
  overflow → `ArithmeticError`; codepoint-correct Unicode string handling.
- **FR-QL-9** [CORE] **Two-phase error model:** `SyntaxError`/`SemanticError`/`ParameterMissing`
  raised at **compile time** before any execution begins; `TypeError`/`ArithmeticError`/
  `EntityNotFound`/constraint errors at **runtime**. The TCK asserts the phase.
- **FR-QL-10** [CORE] **Side-effect accounting:** report net-observable created/removed counts
  for nodes, relationships, properties, and labels exactly as the TCK expects.
- **FR-QL-11** [CORE] **Query planner/optimizer:** parse → AST → logical plan → physical plan;
  index selection and expansion-direction choice. A rule-based planner (or a basic cost-based
  planner) is sufficient for v1.
- **FR-QL-12** [ADV] **Cost-based optimizer (CBO):** statistics/cardinality-driven plan selection.
- **FR-QL-13** [CORE] **`EXPLAIN`** (plan without execution) and **`PROFILE`** (execute with
  per-operator rows/db-hits/timing).
- **FR-QL-14** [CORE] **Plan cache:** cache compiled plans keyed on normalized parameterized AST.
- **FR-QL-15** [CORE] **Query timeout and cancellation:** per-query/transaction timeout; list and
  kill running queries.
- **FR-QL-16** [CORE] **Lazy result streaming:** stream records rather than materializing whole
  result sets.
- **FR-QL-17** [ADV] **GQL-aligned constructs (2024.x line):** label expressions, quantified path
  patterns, element-pattern `WHERE`, `SHORTEST` — included only if `D-cypher-line` targets 2024.x.

## 3. Transactions & ACID (TX)

- **FR-TX-1** [CORE] **Atomicity:** all-or-nothing for single- and multi-statement transactions;
  no partial effects after abort or crash.
- **FR-TX-2** [CORE] **Consistency:** the engine preserves all declared constraints and internal
  structural invariants (valid endpoints, well-formed adjacency, dictionary integrity);
  multigraph parallel edges are a valid state.
- **FR-TX-3** [CORE] **Isolation:** concurrent transactions are isolated at the documented level
  (decision `D-isolation-level`; recommended default Serializable via SSI, with Snapshot
  Isolation opt-in). The level and its guarantees are documented and verified.
- **FR-TX-4** [CORE] **Durability:** once a commit is acknowledged, it survives any subsequent
  crash. Acknowledgement waits for the WAL to reach stable storage.
- **FR-TX-5** [CORE] **Explicit transactions:** `BEGIN`/`COMMIT`/`ROLLBACK` over both interfaces.
- **FR-TX-6** [CORE] **Implicit/auto-commit** single-statement transactions.
- **FR-TX-7** [CORE] **MVCC:** multi-version concurrency so readers never block writers and vice
  versa; obsolete-version garbage collection.
- **FR-TX-8** [CORE] **Transaction introspection:** list active transactions with duration, owner,
  and status; transaction (inactivity) timeout with automatic rollback.
- **FR-TX-9** [CORE] **Deadlock handling:** detect and resolve write-write deadlocks (victim abort)
  or prevent them by design.

## 4. Storage Engine & Durability (ST)

- **FR-ST-1** [CORE] **Native graph storage** with **index-free adjacency** so traversal cost is
  independent of total graph size; relationships stored as first-class records with incidence chains.
- **FR-ST-2** [CORE] **Write-Ahead Log (WAL):** redo (+undo) records flushed (prefer `fdatasync`)
  before commit acknowledgement; steal + no-force buffer policy.
- **FR-ST-3** [CORE] **Group commit:** batch concurrent commits into a shared flush to amortize
  fsync cost without weakening durability (durability mode is decision `D-durability-mode`).
- **FR-ST-4** [CORE] **Crash recovery:** on restart, repeat history (redo) then undo losers to a
  consistent state; idempotent redo via per-page LSN; compensation records for restart-safe undo.
- **FR-ST-5** [CORE] **Checkpointing:** periodic (fuzzy) checkpoints bound recovery time.
- **FR-ST-6** [CORE] **Torn-write protection:** full-page-writes (or a doublewrite area) plus
  per-page checksums so partial writes are detected and repaired on recovery.
- **FR-ST-7** [CORE] **fsync-failure safety:** on an fsync error, do not trust a retried success —
  fail safe (PANIC) and recover from the WAL.
- **FR-ST-8** [CORE] **Buffer management:** a self-managed buffer pool (not pure `mmap`) for control
  over eviction ordering, async I/O, and torn-write protection (decision `D-buffer-mgmt`).
- **FR-ST-9** [CORE] **Storage page size decoupled from OS page size:** OS page size queried at
  runtime; mmap/alignment computed from it (Apple Silicon uses 16 KB pages, not 4 KB).
- **FR-ST-10** [CORE] **Record-level write coordination:** fine-grained (node/relationship)
  concurrency for high throughput; lock-free structures on hot paths where justified and validated.
- **FR-ST-11** [CORE] **Defined on-disk byte order:** little-endian assumed and documented; byte
  order fixed in the format so a future big-endian port is not silently broken.

## 5. Connectivity (CN)

**Three** interfaces (per ratified decisions `D-wire-protocol`/`D-bolt-compat`), all strictly
standards-following. They **share the executor and value model** but differ in transport/wire
format: **Bolt over UDS**, **Bolt over TCP**, and the **Web REST API**.

### UDS (Bolt)

- **FR-CN-1** [CORE] **Pathname `SOCK_STREAM` socket** under a dedicated directory, portable across
  Linux/macOS/Raspberry Pi OS; access controlled by socket-file permissions.
- **FR-CN-2** [CORE] **Length-prefixed framing** supporting arbitrarily large streamed result sets.
- **FR-CN-3** [CORE] **Peer-credential authentication** (`SO_PEERCRED` / `LOCAL_PEERCRED`) mapping
  OS uid/gid to a Graphus role (passwordless local trust).
- **FR-CN-4** [CORE] **Bolt protocol over UDS** (decision `D-wire-protocol`: adopt Neo4j Bolt
  directly, PackStream serialization): versioned handshake; `HELLO`/`LOGON`; parameterized `RUN`;
  fetch-size-driven `PULL`/`DISCARD` record streaming; `BEGIN`/`COMMIT`/`ROLLBACK`; structured
  `FAILURE` with code/message/diagnostics; fail-then-ignore-until-`RESET` under pipelining.

### Bolt over TCP

- **FR-CN-13** [CORE] **Bolt TCP listener** (`bolt://`) exposing the same Bolt protocol over the
  network for the standard Neo4j driver ecosystem (decision `D-bolt-compat`).
- **FR-CN-14** [CORE] **TLS + network hardening for Bolt TCP** (`bolt+s://`): TLS 1.3, Bolt-native
  authentication (`HELLO`/`LOGON`), connection/rate limits, and the same RBAC as the other interfaces.

### Web REST API

- **FR-CN-5** [CORE] **HTTP semantics** per RFC 9110/9112 with HTTP/2 (RFC 9113) support; correct
  status-code usage.
- **FR-CN-6** [CORE] **Transactional Cypher lifecycle over REST** (Neo4j Query API as reference):
  begin → run further statements → commit; rollback via `DELETE`; inactivity auto-rollback;
  transaction id + expiry; `Idempotency-Key` support for safe retries.
- **FR-CN-7** [CORE] **Request/response JSON** with content negotiation; **RFC 9457
  `application/problem+json`** error model carrying Cypher error code/diagnostics.
- **FR-CN-8** [CORE] **Streaming of large results** via NDJSON + chunked transfer encoding; cursor
  pagination for bounded queries; `gzip`/`br` compression; configurable CORS.
- **FR-CN-9** [CORE] **OpenAPI 3.1 contract** published as the authoritative, machine-readable API
  document (contract-first).
- **FR-CN-10** [CORE] **URI path versioning** for the API.

### Serialization

- **FR-CN-11** [CORE] **Lossless value serialization** of all graph values (nodes, relationships,
  paths, 64-bit integers, lists, maps, and — when enabled — temporal/spatial). **PackStream** on
  the Bolt paths (UDS + TCP); **typed JSON (Jolt-style)** on REST. Solve the JSON int53 problem
  from day one (string-encode 64-bit integers).
- **FR-CN-12** [ADV] **CBOR** offered via content negotiation for compact binary without int53 hazard.

## 6. Architecture & Performance (AR)

- **FR-AR-1** [CORE] **Async runtime** that runs on all targets (Tokio multi-thread baseline;
  decision `D-runtime-model`); CPU-heavy query execution kept off runtime workers (dedicated pool).
- **FR-AR-2** [CORE] **Portable I/O backend** (epoll/kqueue baseline) with an **optional io_uring
  fast path on Linux**, selected at runtime with graceful fallback (io_uring is absent on macOS and
  blocked by default seccomp in common container runtimes) — decision `D-io-backend`.
- **FR-AR-3** [CORE] **Durability I/O off the executor:** fsync/WAL flush on dedicated I/O threads
  or via io_uring; never block runtime workers.
- **FR-AR-4** [CORE] **Cross-architecture correctness:** use the weakest *correct* atomic ordering,
  justified per use; no reliance on x86 TSO. All lock-free/unsafe code tested on aarch64.
- **FR-AR-5** [CORE] **Cache-line correctness:** cache-padding via `CachePadded`/`#[repr(align)]`,
  never a hard-coded 64 (ARM/Apple Silicon use 128-byte alignment behavior).
- **FR-AR-6** [CORE] **Hardware adaptivity:** runtime CPU/core detection; configurable worker/shard
  counts; the same binary scales from a 4-core Raspberry Pi 5 to many-core servers.
- **FR-AR-7** [ADV] **SIMD acceleration** feature-gated with scalar fallback and runtime feature
  dispatch (NEON/AVX); never hard-required.
- **FR-AR-8** [CORE] **Allocator strategy:** system allocator by default; mimalloc/jemalloc adopted
  only with before/after numbers per target (decision `D-allocator`).
- **FR-AR-9** [CORE] **Robustness under load:** bounded queues everywhere; admission control via
  semaphores; explicit load shedding (HTTP 429/503 with `Retry-After`; equivalent UDS busy
  response); per-operation deadlines; per-query/transaction memory budgets; graceful drain on SIGTERM.
- **FR-AR-10** [CORE] **Defined target matrix** (decision `D-target-matrix`): Linux x86_64 + aarch64
  and macOS aarch64 as tier-1-tested; 64-bit only; CI on both an x86 and an aarch64 runner.

## 7. Indexing & Constraints (IX)

- **FR-IX-1** [CORE] **Token-lookup index:** label→nodes and type→relationships.
- **FR-IX-2** [CORE] **Range / B-tree property index** (equality + range), single-property.
- **FR-IX-3** [CORE] **Composite (multi-property) index.**
- **FR-IX-4** [CORE] **Relationship-property index** (type + property), required for a multigraph engine.
- **FR-IX-5** [CORE] **Index-backed lookups:** the planner rewrites `MATCH`+`WHERE` to index seeks.
- **FR-IX-6** [ADV] **Online/concurrent index build** (no write blocking).
- **FR-IX-7** [ADV] **Full-text index** (analyzers; phrase/fuzzy/boolean queries).
- **FR-IX-8** [ADV] **Point/spatial index** (distance, bounding-box).
- **FR-IX-9** [ADV] **Vector/similarity index** (ANN/HNSW) — decision `D-vector-index`.
- **FR-IX-10** [ADV] **Index hints** (`USING INDEX`).
- **FR-IX-11** [CORE] **Uniqueness constraint** (per label/type property), index-backed.
- **FR-IX-12** [CORE] **Existence / mandatory-property constraint.**
- **FR-IX-13** [ADV] **Node-key constraint** (composite uniqueness + existence).
- **FR-IX-14** [ADV] **Type/datatype constraint.**
- **FR-IX-15** [CORE] **DDL via Cypher:** `CREATE`/`DROP INDEX`, `CREATE`/`DROP CONSTRAINT`,
  `SHOW INDEXES`/`SHOW CONSTRAINTS`.
- **FR-IX-16** [CORE] **Pre-commit constraint enforcement** integrated with the transaction manager.

## 8. Procedures & Functions (PR)

- **FR-PR-1** [CORE] **Built-in Cypher functions** (covered by FR-QL-6, part of TCK).
- **FR-PR-2** [CORE] **Built-in procedures (`CALL`)** for management/introspection: list
  indexes/constraints/queries, schema introspection, kill query.
- **FR-PR-3** [ADV] **User-defined functions (UDF).**
- **FR-PR-4** [ADV] **User-defined procedures (UDP).**
- **FR-PR-5** [ADV] **Safe extension/plugin mechanism** with allowlisting.
- **FR-PR-6** [ADV] **Cypher-defined named procedures.**

## 9. Bulk Import & Export (BK)

- **FR-BK-1** [CORE] **`LOAD CSV`** transactional in-query ingestion.
- **FR-BK-2** [CORE] **Offline bulk importer** for high-throughput initial load into an empty DB.
- **FR-BK-3** [CORE] **Bulk export / dump** of the whole graph (CSV/JSON/native).
- **FR-BK-4** [CORE] **Measured initial-load performance** (empirical, per the project rules).
- **FR-BK-5** [ADV] **Incremental/resumable import.**
- **FR-BK-6** [ADV] **Parquet/JSON import; streaming ingestion.**

## 10. Backup & Restore (BR)

- **FR-BR-1** [CORE] **Offline backup/dump and restore (load).**
- **FR-BR-2** [CORE] **Consistent snapshots** (overlaps with checkpointing).
- **FR-BR-3** [CORE] **Backup verification** (integrity / restorability).
- **FR-BR-4** [ADV] **Online/hot backup** (no write stop).
- **FR-BR-5** [ADV] **Incremental backup.**
- **FR-BR-6** [ADV] **Point-in-time recovery** (snapshot + WAL replay to a timestamp).

## 11. Security (SE)

- **FR-SE-1** [CORE] **Authentication** with pluggable backends (native first).
- **FR-SE-2** [CORE] **Authorization / RBAC:** roles with privileges mapped to users.
- **FR-SE-3** [CORE] **User/role management API** (create/alter/drop, grant/revoke).
- **FR-SE-4** [CORE] **TLS for REST** (TLS 1.3) when exposed beyond loopback; UDS relies on
  filesystem permissions + peer credentials.
- **FR-SE-5** [CORE] **Injection safety** via mandatory parameterization.
- **FR-SE-6** [CORE] **Request hardening:** body-size limits, max statements per transaction,
  connection/request/transaction timeouts, per-identity rate limiting.
- **FR-SE-7** [ADV] **Fine-grained (label/property) access control.**
- **FR-SE-8** [ADV] **Encryption at rest.**
- **FR-SE-9** [ADV] **Audit logging** of auth, transaction lifecycle, and admin operations.

## 12. Multi-database & Tenancy (MT)

- **FR-MT-1** [CORE] **Catalog abstraction designed in** (catalog → schema → graph), even if v1
  ships a single database (decision `D-multi-db`).
- **FR-MT-2** [ADV] **Multiple named databases** per server with lifecycle DDL
  (`CREATE`/`START`/`STOP`/`DROP DATABASE`).
- **FR-MT-3** [ADV] **Per-database configuration** and **strict isolation** between databases.
- **FR-MT-4** [ADV] **Composite/federated queries** across databases.

## 13. Observability & Operations (OB)

- **FR-OB-1** [CORE] **Metrics** (Prometheus/OpenMetrics): QPS, latency histograms (p50/p99/p99.9),
  transaction durations, error rates, active connections vs the cap, cache hit rates, memory.
- **FR-OB-2** [CORE] **Structured logging** (JSON) with request/transaction IDs.
- **FR-OB-3** [CORE] **Query log / slow-query log** with durations and parameters.
- **FR-OB-4** [CORE] **Liveness and readiness endpoints** (`/health/live`, `/health/ready`).
- **FR-OB-5** [CORE] **Admin / management API:** status, kill query, index/constraint ops.
- **FR-OB-6** [CORE] **Configuration management:** file + validated runtime-tunable settings.
- **FR-OB-7** [CORE] **Runtime introspection** (`SHOW` commands for DB state/transactions/settings).
- **FR-OB-8** [ADV] **Distributed tracing** (OpenTelemetry spans across the request lifecycle).

## 14. Graph Algorithms (GA)

Decision `D-graph-algos` ratifies a **full GDS-style library** as a committed, dedicated
workstream (its own phase), beyond the native path functions. `[LIB]` marks items in that
workstream (committed, but not part of the Phase 1 correctness core).

- **FR-GA-1** [CORE] **Native Cypher path functions:** `shortestPath`/`allShortestPaths`,
  variable-length expansion (part of Cypher/TCK).
- **FR-GA-2** [LIB] **Weighted shortest path** (Dijkstra/A*).
- **FR-GA-3** [LIB] **Centrality** (PageRank, betweenness, closeness, degree).
- **FR-GA-4** [LIB] **Community detection** (Louvain, Label Propagation, WCC).
- **FR-GA-5** [LIB] **Similarity / link prediction; embeddings (Node2Vec, FastRP).**
- **FR-GA-6** [LIB] **In-memory graph projection engine** for parallel algorithm execution.

## 15. Quality & Testing (QA)

- **FR-QA-1** [CORE] **Unit tests** for every module (parser, planner, storage, txn manager,
  indexes). **No skipped/ignored tests.**
- **FR-QA-2** [CORE] **openCypher TCK harness:** consume the `.feature` files; assert results
  (ordered/unordered), side-effect counts, and error type+phase; 100% pass as a hard CI gate.
  A periodic JVM ground-truth cross-check is the tie-breaker oracle (decision `D-tck-harness`).
- **FR-QA-3** [CORE] **Integration / E2E tests** over **both** UDS and REST (full request →
  response → durability round-trips; multi-statement transactions; bulk import/export).
- **FR-QA-4** [CORE] **Regression tests:** every fixed bug gets a permanent test.
- **FR-QA-5** [CORE] **ACID / isolation verification:** Jepsen/Elle-style anomaly checking of
  generated concurrent histories (detect G0/G1/G2/G-single).
- **FR-QA-6** [CORE] **Deterministic Simulation Testing (DST):** run the engine in a deterministic
  simulator with fault injection (crashes, I/O errors, torn writes, fsync EIO), reproducible from a
  seed (decision `D-dst-investment`: scaffold from the start).
- **FR-QA-7** [CORE] **Crash-consistency / fault injection:** kill/power-cut at every WAL/checkpoint
  boundary; recovery yields only committed-or-nothing; run the consistency checker afterward.
- **FR-QA-8** [CORE] **Property-based testing** (`proptest`) of invariants (recovery, constraint
  enforcement, adjacency well-formedness).
- **FR-QA-9** [CORE] **Fuzzing** (`cargo-fuzz`) of the Cypher parser, wire protocol, and import parsers.
- **FR-QA-10** [CORE] **Micro-benchmarks** (Criterion) on hot paths with regression gates in CI.
- **FR-QA-11** [CORE] **Macro load benchmark:** LDBC Social Network Benchmark (Interactive; BI later)
  to demonstrate extreme-load readiness; optional Graph500.
- **FR-QA-12** [CORE] **Stress / soak tests:** sustained high-concurrency mixed workloads watching
  for leaks, latency drift, and contention.
- **FR-QA-13** [CORE] **Concurrency validation:** loom (or Shuttle) + Miri for every lock-free/unsafe
  unit; sanitizers (TSan/ASan) under stress.
- **FR-QA-14** [CORE] **Cross-platform CI matrix:** Linux + macOS, x86_64 + aarch64, including a
  Raspberry Pi 5 target; TCK pass-rate, Jepsen/DST suites, and Criterion regression gates as required checks.
- **FR-QA-15** [CORE] **Consistency checker** as a first-class tool: validate store ↔ index
  agreement, no dangling relationships, checksum integrity; runnable offline and at startup.

---

## Coverage note

Every `[ADV]` item is tracked but deferred per the phased roadmap (`00-overview.md` §6) unless a
ratified decision in `02-decision-register.md` promotes it into Phase 1. Nothing in this survey is
dropped silently; deferral is explicit.
