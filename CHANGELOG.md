# Changelog

All notable changes to **Graphus** are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.0.6] - 2026-07-07

This release is a **reliability and performance hardening** pass. It fixes a series of
critical **ACID / durability** defects that could silently lose committed data under extreme
multi-core concurrency, bounds several **memory and liveness** failure modes so that
adversarial or interrupted workloads degrade gracefully instead of aborting the server, and
continues to **scale reads, writes, and graph analytics across cores**. It is a **drop-in
upgrade** from v0.0.5: no public Cypher, Bolt, or REST contract changed and no new user-facing
feature was added. The four inviolable guarantees held throughout — **100% ACID**, **100%
openCypher TCK (3914 / 3914)**, **100% Bolt protocol**, and **100% PackStream**.

### Changed

- **A single heavy read now scales across cores.** The off-thread reader pool uses an adaptive
  morsel width, so even one large frontier-seeded traversal — such as a friends-of-friends
  recommendation query — is split across the reader pool instead of running on a single worker.
- **Writes coalesce further under concurrency.** Auto-commit write fsyncs are coalesced through
  group commit, and the commit pipeline is deepened past the previous batch-width ceiling, so
  more concurrent committers share a single durable `fdatasync`. Every durability invariant is
  preserved: a committer is acknowledged only after the fsync covering its commit record
  completes.
- **Graph Data Science algorithms run in parallel.** The PageRank, weakly-connected-components,
  and degree-centrality parallelism gaps were closed, and seven previously single-threaded
  algorithms were parallelized across cores.
- **Parallel group-by aggregation.** A group-by-over-expand aggregation — for example, counting
  each node's neighbours — is now executed across cores instead of on the engine thread alone.
- **Reader-safe procedures dispatched off-thread.** Reader-safe procedures (including full-text
  and spatial procedures feeding an expansion) are dispatched to the off-thread reader pool and
  capture their index state in the read view, so they no longer serialize on the engine thread.
- **Bounded write-ahead-log-to-store ratio.** Background maintenance now runs at a
  store-proportional cadence built on an incremental, `O(Δ)` freeze sweep, bounding the
  WAL-to-store size ratio without reintroducing the `O(store)` per-checkpoint cost that a
  create-only workload would otherwise accrue.
- **Durability invariants promoted to release-active.** The two load-bearing durability
  invariants (doublewrite and seed-flush ordering) are now asserted in release builds, not only
  in debug builds.
- **Honest, multi-core example.** The GDS-analytics example was corrected so that it
  demonstrates real multi-core execution rather than overstating it.
- **Leaner, better-scoped CI.** The GitHub Actions pipeline no longer runs the DST / soak gate
  on plain feature-branch pushes (a feature branch reaches CI through its pull request), splits
  the fast cross-platform test job from a dedicated DST gate, adds incremental build caching,
  and cancels superseded runs. A trigger and permissions security audit added least-privilege
  `contents: read` permissions and hardened several workflow-input paths. The
  `.github/dependabot.yml` file was removed by request.

### Fixed

- **Silent loss of a committed value under incremental garbage collection (critical, ACID).**
  With an explicit `BEGIN … COMMIT` transaction in flight, a maintenance garbage-collection pass
  could advance its freeze frontier past the in-flight writer's records and then forget the
  writer, so once it committed a reader at the latest snapshot resolved its value as aborted —
  permanently losing a committed value with **no crash required**. The freeze frontier now tests
  live writer membership and keeps a writer's records unfrozen until it commits.
- **Lost committed edges under concurrent off-thread reads (critical, ACID isolation).** A
  maintenance garbage collection could reclaim and reuse a record slot while a lock-free
  off-thread reader still held a pointer into it, so the reader decoded a foreign record and a
  committed live edge became invisible. A freed slot is now shadow-held from physical reuse until
  every transaction that predates the free has retired (an epoch / QSBR barrier), while remaining
  immediately reusable after a restart, when no readers are in flight.
- **Chain corruption from physical-id double-allocation on live rollback (critical, ACID
  durability).** Under statement-interleaved SSI write load, restoring a rolling-back
  transaction's free list to the last committed image could hand a freed id to a concurrent
  writer twice, producing a self-cyclic property or incidence chain and losing the data threaded
  below the cycle. Rollback now restores the in-memory free lists around the catalog reload and
  withdraws only the aborting transaction's own pushes. Two related MVCC-stamp undo fixes landed
  alongside it: a non-LIFO-safe compare-and-set undo for tombstone stamps, and reclaiming an
  aborting transaction's own reused-id pops on rollback.
- **A transient write error could brick store reopen (critical, ACID / availability).** A
  transient device error on a new page's unlogged seed flush left an all-zero, checksum-invalid
  page that no store mapped and no WAL record covered, so the next open failed checksum
  verification and a healthy database could never reopen. Cold-open reconstruction now classifies
  such an orphan page: an all-zero aborted-allocation phantom is safely skipped, while a non-zero
  bad checksum still fails closed as genuine corruption, preserving the never-serve-an-untrusted-page
  mandate.
- **Torn page during crash recovery.** A page torn mid-write while recovery is running is now
  healed by checksum-gating its page LSN, instead of propagating a partially written page.
- **Crash recovery could exhaust memory on a large or interrupted load (critical,
  recoverability).** A large Mode A network bulk-import interrupted by a crash, kill, power loss,
  or force-detach left the entire retained WAL un-reclaimed, so crash recovery read gigabytes into
  memory and the out-of-memory killer aborted the reopen — committed data stayed correct but the
  database could not come back online without a larger host. Reopen memory is now bounded to the
  retained window for all large-WAL reopens, a mid-load maintenance pass reclaims the WAL prefix,
  and a force-detach can no longer corrupt the store on reopen.
- **A deep query could stack-overflow-abort the whole server (critical, availability).** A single
  authenticated Cypher query could drive native recursion deeper than the engine / reader-pool
  stack and trigger an uncatchable stack-overflow abort of the entire process, taking down every
  hosted database and connection. Query recursion depth is now bounded across all deep-recursion
  input shapes — runtime value nesting, clause chains, and long `MATCH` paths — and turned into a
  recoverable error; on aarch64 the runtime threads run on an 8 MiB stack so a deeply nested REST
  value cannot overflow the server.
- **A stalled reader or slow consumer could wedge the server or pin garbage collection.** A
  stalled off-thread reader's egress wait is now bounded so it can no longer pin the
  garbage-collection watermark forever; the group-commit drain is bounded and reader GC-pins are
  released mid-storm; and parked slow-consumer statements now resume between hardened
  group-commit batches instead of stalling.
- **Adversarial or oversized inputs bounded.** The `.gcol` bulk-upload path is bounded so one
  large or adversarial upload cannot exhaust server memory, and a RAII pin-guard ensures a
  panicking visit closure can no longer strand a buffer-pool frame.
- **Reliability residuals closed.** Five remaining bounded reliability residuals were closed and
  a Mode A checkpoint-sentinel leak was fixed.

## [0.0.5] - 2026-07-03

This release makes Graphus **scale reads and writes across cores**, adds a **network
bulk-import** path for loading data over the wire, and closes a **certification pass** that
fixed a critical encrypted-at-rest disk leak and several pre-authentication denial-of-service
vectors. It is a **drop-in upgrade** from v0.0.4: no public Cypher, Bolt, or REST contract
changed. The four inviolable guarantees held throughout — **100% ACID**, **100% openCypher
TCK (3914 / 3914)**, **100% Bolt protocol**, and **100% PackStream**.

### Added

- **Network bulk-import over REST.** A new `POST /admin/db/{db}/bulk-import` endpoint streams
  CSV / `.gcol` data straight into a database without buffering the payload, gated by the same
  Admin RBAC check as `BACKUP` / `RESTORE` / `CREATE DATABASE` and protected by a per-byte
  quota, an ongoing free-disk-space check, and a session timeout (all configurable). Two
  ingestion modes are supported: **Mode A** loads a new or empty database through the
  low-level bulk-write path with a crash-durable per-batch checkpoint sentinel, and **Mode B**
  loads an already-live, serving database concurrently with ordinary Bolt/REST traffic —
  correctness coming entirely from participating in the same MVCC/SSI machinery every ordinary
  Cypher transaction uses, with automatic bounded retry of a batch that loses a serialization
  conflict. Ratified as decision `D-bulk-import-network` and specified in
  `specification/08-network-bulk-import.md`.
- **Product-recommendations example.** A self-contained, runnable end-to-end example
  (`examples/product-recommendations`) that boots a real server, network-bulk-loads a
  recommendation multigraph over the wire, and drives a concurrency ladder of many
  simultaneous Bolt-over-UDS clients running a realistic read battery (direct-friend,
  second- and third-level, and collaborative-filtering "similar consumption profile"
  traversals) plus a few concurrent writes, while sampling the server's CPU, RSS, and I/O to
  expose read-path bottlenecks. Backed by a new deterministic recommendation-graph generator
  and client tooling (`graphus-reco-gen`).
- **Server startup banner.** The server now logs a single structured startup line naming the
  application, its version, the build platform (OS / architecture / pointer width), and the
  pid — mirroring the PostgreSQL / Redis convention — so operators can confirm exactly which
  binary is running.
- **`docs/transactions.md`.** New documentation of the transaction model: autocommit by
  default, explicit `BEGIN … COMMIT` transactions, lock-free reads, the per-work isolation
  table, and how to opt a read back into serializable isolation.

### Changed

- **Reads are now lock-free and scale across cores.** A standalone auto-commit read is treated
  as what it is — a read — and dispatched across the off-thread reader pool by the query's
  structural type rather than the client-declared access mode, so a bare `MATCH` sent without
  a routing hint is no longer pinned to the single engine thread. Every read is a lock-free
  Snapshot-Isolation snapshot read that takes **no serializability overhead and can never
  cause a writer to abort**, matching the MySQL / MariaDB / SQL-Server autocommit model, while
  still pinning the GC watermark for the versions it reads (a consistent MVCC snapshot with no
  premature reclamation). **Writes and explicit `BEGIN … COMMIT` transactions are unchanged —
  full Serializable SSI**; a read that needs serializable isolation can opt in by running
  inside an explicit transaction.
- **Read throughput scales with concurrency.** The off-thread reader pool is now engaged for
  single-statement REST reads as well (previously every REST read ran inline on the engine
  thread), and a read-only transaction performs **zero WAL append and zero `fdatasync`** across
  its whole lifecycle (it has nothing durable to persist). Together these lift server CPU on a
  concurrent REST read workload from roughly one core to nearly five, and trivial reads from a
  ~450 requests/s fsync-bound ceiling to tens of thousands per second, with heavy scans now
  bounded by the reader pool rather than a serial per-read fsync.
- **Write throughput scales with concurrency.** Explicit-transaction commits now use
  **cross-transaction group commit** — pending commit records are batched into a single
  `write()` + single `fdatasync` — and the batch fsync is **pipelined off the engine thread**
  so the engine overlaps it with preparing the next batch and retiring off-thread reads. Under
  concurrency this scales committed-write throughput several-fold on durable storage (the
  larger the fsync latency, the larger the gain), with every durability invariant preserved: a
  committer is acknowledged only after the fsync covering its commit record completes.
- **Lower per-statement engine cost.** Compiled query plans are now `Arc`-shared through the
  plan cache and executor, so a plan-cache hit ships a reference-count bump instead of a deep
  tree clone (a ~64–233× reduction in the per-statement clone cost that dominates the
  parameterized-repeated production case).
- **Cheaper bulk loading.** During a Mode A bulk-import session the background
  maintenance-checkpoint interval is widened 16× (a bulk load only ever creates rows, so each
  full-store GC pass reclaims almost nothing yet grows more expensive as the store grows),
  cutting maintenance overhead by the same factor; every other workload keeps the unchanged,
  frequent reclamation cadence.

### Fixed

- **Encrypted write-ahead-log disk leak (critical).** On an encryption-at-rest database the
  encrypted WAL stored its sink header in the first backing segment, which the prefix-only
  segment reclaimer could never free — so the encrypted WAL grew on disk **without bound**, and
  a heavily-reclaimed log could not be reopened after a crash. The header is relocated into the
  never-deleted anchor (matching the plaintext layout) so segment reclamation frees leading
  segments again; the on-disk sink version is bumped and an old-layout encrypted WAL is rejected
  fail-closed at open. AEAD framing, nonce-budget resume, and key-check fail-closed are
  preserved exactly.
- **Crash-recovery out-of-memory on a long-lived WAL.** Several crash-recovery scans read the
  WAL from offset zero, sizing their buffer by the log's absolute lifetime rather than the small
  retained window — so a long-lived, heavily-reclaimed log demanded many times its retained size
  on reopen and could abort with an out-of-memory error, leaving the database unable to reopen (a
  direct ACID violation). Recovery now reads only from the reclaimed floor, so its allocation
  tracks the retained window; behaviour is byte-identical when nothing has been reclaimed.
- **Pre-authentication denial-of-service vectors (PackStream).** Decoding an attacker-supplied
  message before authentication could burn minutes of CPU (a many-key map decoded in O(N²);
  now an order-preserving O(N) accumulator, ~780× faster) or amplify a few megabytes into
  gigabytes of heap (a deeply-sized collection with no breadth budget; now a per-message
  decoded-element budget caps decoded heap at a small multiple of the framing limit).
- **Availability and correctness hardening (certification pass).** A Bolt `PULL` of a full
  result no longer buffers the entire result in the per-connection write buffer before
  flushing (now bounded, buffered-writer semantics); an off-thread reader whose consumer stops
  draining now aborts at its statement deadline instead of blocking forever and pinning the GC
  watermark; the coordinator's serialization-conflict tracker is now pruned from the
  maintenance checkpoint instead of leaking an entry per committed transaction and per read;
  and a full-text/spatial procedure feeding an expansion is no longer mis-dispatched off-thread
  into a spurious "no such index" error.
- **REST conflict handling.** A conflicting single-statement write auto-commit now returns a
  retriable `409` with the connection kept alive, instead of dropping the HTTP connection
  mid-stream — a single-statement write is buffered and its status decided from its commit
  outcome, while single-statement reads still stream. The buffered write result is bounded
  (16 MiB) so a large authenticated write cannot exhaust memory; it never commits half-way and
  never silently truncates.
- **Bulk-import retry safety.** The offline bulk importer now stages each batch's external-id
  bindings and row-count statistics separately and merges them only after the batch durably
  commits, so an aborted batch can be retried without falsely rejecting a duplicate id or
  resolving relationships against rolled-back physical ids — the invariant the network
  bulk-import's automatic per-batch retry relies on.

## [0.0.4] - 2026-06-30

### Fixed

- **Query result summary (side-effect counters + query type).** Both the Bolt and REST interfaces now
  populate the per-statement result summary that was previously always empty — every query reported
  zero update counters and a null query type even though writes persisted, breaking conformance with
  the Bolt/Cypher contract and the Neo4j driver ecosystem. The trailing summary now carries the query
  `type` (`r` read, `w` write, `rw` read-write, `s` schema/admin) and the Neo4j-compatible `stats`
  counters (`nodes-created`/`-deleted`, `relationships-created`/`-deleted`, `properties-set`,
  `labels-added`/`-removed`, `indexes-added`/`-removed`, `constraints-added`/`-removed`,
  `system-updates`, `contains-updates`, `contains-system-updates`), present only when non-empty.
  Counters follow Neo4j's operation-count model and use kebab-case keys; over REST they are plain JSON
  numbers (e.g. `"nodes-created": 1`), matching the Neo4j HTTP API. Verified end to end against a
  locally-built server with the official Neo4j driver (Bolt) and the REST API.

## [0.0.3] - 2026-06-30

### Added

- **`POST /auth/login` REST endpoint.** Exchange a username + password for a short-lived
  HS256 Bearer JWT, so the authenticated REST WebAPI is usable from any HTTP client without
  distributing the server's `jwt_secret`. The credential is verified with Argon2 (the same
  path as Bolt `LOGON`); failed attempts are rate-limited per account, and unknown-user and
  wrong-password failures return an identical `401`.
- **Usage documentation** under [`docs/`](docs/) (getting started, REST WebAPI, Bolt
  over TCP/UDS, security and RBAC, configuration) and **Go client examples** under
  [`examples/clients-go/`](examples/clients-go) for all three interfaces (REST, Bolt-over-TCP
  via the official Neo4j Go driver, and Bolt-over-UDS via a dependency-free raw client).
- **Docker Hub image publishing.** A new GitHub Actions workflow
  (`.github/workflows/dockerhub.yml`) builds the multi-architecture (`linux/amd64` +
  `linux/arm64`) image and publishes it to Docker Hub, alongside the existing GitHub
  Container Registry (GHCR) workflow. It runs only on a manual dispatch or when a GitHub
  Release is published, authenticating with the `DOCKERHUB_USERNAME` and `DOCKERHUB_TOKEN`
  repository secrets, and always publishes conformant tags — `:latest` plus a `:vX.Y.Z`
  version (never a commit-sha or branch tag). A community-standard repository overview
  ships in [`docker/dockerhub-overview.md`](docker/dockerhub-overview.md).

### Changed

- **CI GitHub Actions updated to their latest major versions** across `ci.yml`,
  `docker.yml`, and `nightly-fuzz.yml` (`actions/checkout` v7, `actions/upload-artifact`
  v7, and the Docker `setup-qemu`/`setup-buildx`/`login`/`metadata`/`build-push` actions),
  keeping the pipeline on maintained, Node 24-based action runtimes.

## [0.0.2] - 2026-06-29

A **hardening, performance, and production-readiness** release. Graphus matured across
reliability, performance, and denial-of-service resistance, while the four inviolable
guarantees held throughout: **100% ACID**, **100% openCypher TCK (3914/3914)**, **100%
Bolt protocol**, and **100% PackStream**. No public Cypher, Bolt, or REST API contract
changed, so this release is a drop-in upgrade from 0.0.1.

### Added

- **Native columnar storage subsystem.** A dependency-light columnar codec
  (`graphus-columnar`), a `.gcol` bulk dump/import format, a complementary columnar
  property store with vectorized aggregation, a zone-map data-skipping sidecar for
  non-indexed scans, a Roaring-bitmap secondary index for low-cardinality columns, an
  immutable columnar cold tier for aged time-series, internal-id-aligned numeric GDS node
  columns with zero-copy export, and a native columnar REST result channel.
- **Intra-query and off-thread parallelism.** Morsel-driven intra-query parallelism for
  grouped aggregation, for `scan → filter → project` with a stable `ORDER BY`/top-k, and
  for `ExpandAll`; off-thread concurrent read execution backed by a reader pool; a
  `Send + Sync` read path (`GraphSnapshot`, `StoreReadView`, `ReadOnlyGraph`); a
  concurrency-ready SSI tracker; and a loom-validated concurrent buffer pool wired in as
  the production pool.
- **Deterministic Simulation Testing (DST) simulator maturation.** First-class VOPR
  **safety** and **liveness** modes, a deterministic cooperative interleaver, a unified
  seeded fault scheduler (disk, clock, and transport fault models), crash + ARIES restart
  woven into the interleave, a strong cell-by-cell reference-model oracle, swarm testing,
  failing-seed minimization with replayable artifacts, and a continuous time-budgeted
  multi-core fuzzer. Safety, liveness, and determinism sweeps now gate pull requests, and a
  nightly swarmed fuzz job runs in CI.
- **Demonstrative examples suite (`examples/*`).** A shared evidence harness plus realistic
  end-to-end scenarios — social-network over UDS, social-network-large (1M-user target),
  fraud-oltp, gds-analytics, bulk-etl, durability-crash-recovery, knowledge-graph-rest,
  security-multitenant, and iot-timeseries — each instrumented to collect CPU, RAM, and
  storage evidence against committed baselines.
- **End-to-end official Neo4j-driver coverage** for full CRUD over nodes and relationships.

### Changed

- The storage read path was refactored to a `&self`, `Send + Sync` model over a shared
  buffer pool and a metadata snapshot, enabling concurrent and off-thread reads without
  duplicating the visibility logic.
- The Tokio blocking pool is now sized from `max_connections`, so Bolt sessions no longer
  starve beyond 512 concurrent connections.
- REST result egress is now streamed incrementally rather than fully buffered before send.

### Fixed

- **Durability and crash recovery.** The doublewrite buffer is wired into the production
  checkpoint and open paths with disjoint checkpoint-batch and eviction regions, a
  per-eviction serialized `stage → home-write → sync`, a persisted checkpoint-floor LSN
  gate, a multi-slot eviction ring, WAL-before-data enforcement, and an orphan-page check
  on open — closing several committed-data-loss windows under crash × disk-fault. Committed
  nodes and self-loops are now recovered after interleaved live-rollback plus crash-undo.
- **ARIES recovery.** Fixed double-crash recovery defects, including transaction-id reuse
  across recovery, and caught a double-panic in recovery rollback.
- **Transaction isolation.** Closed a concurrent `NODE KEY` duplicate commit, scrubbed
  dangling SSI read-write edges, released in-memory abort state unconditionally so a
  panicking undo cannot leak a transaction, and fixed a cross-type equality seek (`1 = 1.0`)
  that admitted duplicates and missed the index.
- **Index correctness.** MVCC-correct full-text and spatial indexed reads (a cross-snapshot
  stale-read false-negative), bitmap abort/delete de-indexing, a decline-to-scan for
  geographic (WGS-84) spatial seeks, full-text Unicode normalization, and the `=~` operator.
- **Bolt and PackStream conformance.** Reject an absent `PULL`/`DISCARD n`, reject an
  invalid `TELEMETRY` API value, roll back on explicit `GOODBYE`, cap structure lengths to
  `i32`, roll back an abandoned transaction on disconnect, and guard the `LOGOFF` state.
- **Server robustness.** Query-panic isolation so a single statement can no longer brick the
  engine, a per-engine degraded flag with a clean startup and shutdown lifecycle, a
  monotonic clock, a REST transaction idle sweep with a principal-bound registry, and
  bounded REST open transactions.
- **UDS peer-credential authentication on macOS / Apple Silicon.** UDS peer-credential
  resolution was gated to Linux (`SO_PEERCRED`) and refused every Unix-domain-socket
  connection on other platforms; it now uses Tokio's cross-platform `peer_cred()`
  (`getpeereid` on macOS/BSD), so the UDS (IPC) interface works on every Tier-1 target,
  Apple Silicon included.
- **Cryptography.** The buffered nonce CSPRNG is now fork-safe via a PID-stamped reseed.
- **Graph Data Science.** Simple-graph betweenness, an order-stable reduction, weighted
  PageRank, personalized-PageRank weight validation, control-character escaping, and a
  checked date render.
- **Columnar, bulk, and cold store.** Controlled errors on malformed `.gcol` input, CRC with
  atomic and durable I/O, clamped and validated forged counts, and a CRC32C integrity
  trailer for cold segments.
- **Audit log and checker.** Opt-in data-change fsync, sequence recovery across rotations, a
  cold-open checker contract, audit sequence ordering, schema DDL enforcement, and an
  authentication throttle.
- **Buffer pool.** Escalating backoff on a contended victim sweep (a fetch livelock) and an
  additive pin publish that prevents a lost-pin wrong-page read under eviction.
- **Backup and point-in-time recovery.** The backup base LSN now covers in-flight
  transaction undo, with a more robust PITR cut.

### Performance

- **Query execution.** Hash-bucket aggregation grouping that removes an O(rows × groups)
  cliff, schema-shared positional rows, reduced per-row allocation in hot loops, a
  move-not-clone of result cells into Bolt and REST values, cost-based expand-direction
  reversal, integer relationship-type filtering, and a late-materialization single-key
  property probe.
- **Concurrency and scaling.** A sharded `RwLock` device buffer pool for concurrent
  cache-miss reads, a reverse SSI write-index that makes `record_read` O(writers-of-key), a
  `TimestampOracle` BTreeMap multiset with O(log N) release, a bounded compute-thread
  budget, plan-cache reuse on the `RUN` path, a per-statement effective-privilege snapshot
  with a borrowed RBAC probe, and cache-padded multi-writer metrics.
- **Storage, I/O, and WAL.** A page-batched scan primitive, coalesced batched write-back
  with a copy-free `pwritev` fast path, inline-buffer WAL patches with borrowed redo,
  amortized B+-tree validation, streaming range iteration, a live-engine checkpoint trigger
  with memory-freeing log-sink reclaim that bounds RAM and WAL growth, a typed single-pass
  incidence walk with opt-in CSR adjacency, and a resumable inline cursor that never parks
  on a slow consumer.
- **Cryptography.** Per-target AES/GHASH compilation with in-place WAL frame sealing, and a
  buffered ChaCha20 CSPRNG nonce source that eliminates a per-nonce `getrandom` syscall.
- **Graph Data Science.** Parallelized betweenness and closeness centrality, and a shared
  flat-CSR adjacency built once per sweep.

### Security

- **Denial-of-service resistance.** A production-confidence audit campaign added a full
  suite of resource bounds: a per-statement execution timeout (default 2 minutes), a
  per-transaction maximum-age cap (default 1 hour), a per-source-IP connection cap with a
  cumulative pre-authentication deadline, a pre-authentication read deadline against
  slow-loris clients, a per-value materialized-size budget (extended to list and string
  builtins and to list `+` concatenation, map literals, and `properties()`), a bounded
  join-order planner (greedy fallback above 8 operands), bounded expression depth, a
  PackStream struct-decode depth guard (`MAX_DECODE_DEPTH` lowered from 256 to 64) with a
  tighter decode-bomb preallocation ceiling (16 MiB to 512 KiB), incremental REST egress
  against remote out-of-memory, and bounded multi-statement inline suspend/resume with
  isolated resume-batch panics.
- **Access control.** Fixed a graph-scoped RBAC defect, discovered through the
  security-multitenant example, where the REST interface false-denied every per-tenant
  grant.

## [0.0.1] - 2026-06-15

First tagged release of Graphus, a Label Property Graph (LPG) database server written
in Rust. This release packages the single-node correctness core together with a
production-grade, multi-architecture container image, giving adopters a reproducible way
to build, run, and evaluate the server.

### Added

- **Single-node correctness core.** ACID transactions backed by MVCC with Serializable
  Snapshot Isolation, an ARIES-style write-ahead log with group commit and checkpoints,
  and crash recovery. Storage uses a record store with index-free adjacency; indexing
  provides B+-tree, token-lookup, composite, and relationship-property indexes plus
  constraints.
- **Cypher query engine** targeting 100% openCypher TCK compliance (pinned target
  `2024.3`), covering the parse → plan → execute pipeline.
- **Bolt protocol over UDS and TCP.** Bolt 5.x with PackStream serialization, exposed both
  over Unix Domain Sockets (IPC) and over TCP (`bolt://`) for the standard Neo4j driver
  ecosystem. TCP transport is secured with TLS.
- **Web REST API.** HTTP transactional interface with an OpenAPI document, liveness and
  readiness endpoints, and Bearer (JWT, HS256) authentication on transactional routes.
- **Authentication and RBAC.** Peer-credential, JWT/Bearer authentication and fine-grained
  role-based access control, shared across all listeners with a durable, crash-safe
  security catalogue.
- **Encryption at rest.** AES-256-GCM for store pages, WAL frames, and backup envelopes,
  with crash-safe key rotation.
- **Observability.** Metrics and an audit log built into the server process, alongside
  admission control.
- **Deterministic Simulation Testing (DST).** A VOPR-style deterministic simulator with a
  scenario battery, fault injection, and Elle/Adya isolation checking, used to reproduce
  realistic production situations and verify correctness and durability guarantees.
- **Multi-architecture Docker deployment.** A production-grade container image of
  `graphus-server` for `linux/amd64` and `linux/arm64` (Raspberry Pi 5 and Apple Silicon
  included via Docker's Linux/arm64 runtime). Includes a `Dockerfile`, a
  `docker-compose.yml`, and an entrypoint that, on first boot, provisions a self-signed TLS
  certificate and a random JWT secret under `/data` so that Bolt and REST run encrypted out
  of the box. All durable state lives under `/data`.
- **GHCR multi-arch CI.** A GitHub Actions workflow (`.github/workflows/docker.yml`) that
  builds both architectures on every change and publishes a multi-architecture manifest to
  the GitHub Container Registry on `v*` tags, with provenance and SBOM attestations.

### Security

- The container quickstart ships **local-sandbox defaults only**: a self-signed
  certificate and a well-known admin password. These are not suitable for production.
  Supply a CA-issued certificate, a strong admin password, and a real JWT secret before
  any non-sandbox use. See the README "Production / TLS" section.

[Unreleased]: https://github.com/FlavioCFOliveira/Graphus/compare/v0.0.6...HEAD
[0.0.6]: https://github.com/FlavioCFOliveira/Graphus/compare/v0.0.5...v0.0.6
[0.0.5]: https://github.com/FlavioCFOliveira/Graphus/compare/v0.0.4...v0.0.5
[0.0.4]: https://github.com/FlavioCFOliveira/Graphus/compare/v0.0.3...v0.0.4
[0.0.3]: https://github.com/FlavioCFOliveira/Graphus/compare/v0.0.2...v0.0.3
[0.0.2]: https://github.com/FlavioCFOliveira/Graphus/compare/v0.0.1...v0.0.2
[0.0.1]: https://github.com/FlavioCFOliveira/Graphus/releases/tag/v0.0.1
