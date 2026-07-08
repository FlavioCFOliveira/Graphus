# 02 — Decision Register

These are the open design decisions surfaced by the needs survey and the supporting research.
Per the project rule "you are not authorized to make decisions on your own", each is presented
with options and a recommendation, and **must be ratified by the project owner** before the
detailed per-domain functional specification and the implementation sprints are finalized.

Each decision is a `Decision` node in the Knowledge Graph (status `open`) with an `AFFECTS` edge
to the domain/component it constrains. On ratification, the chosen option is recorded on the node
and its status set to `ratified`.

> **Status: all 24 decisions ratified on 2026-06-05.** The chosen option is recorded on each
> `Decision` node (`status: ratified`, property `chosen`). The ratified outcomes are summarized in
> the next section; the options tables below are kept for the rationale and trade-offs.

Legend: ★ = recommended option.

## Ratified outcomes (2026-06-05)

| ID | Ratified choice |
| --- | --- |
| D-cypher-line | openCypher 2024.x line, feature-flagged; certify the M-series milestone first; pin a tagged commit |
| D-tck-harness | Rust `cucumber` crate for CI + periodic JVM `tck-api` as ground-truth oracle |
| D-element-id | Internal compact physical IDs + a stable, never-reused public element ID (ULID/UUIDv7) |
| D-temporal-spatial | All temporal types in v1; spatial `POINT` deferred to a later phase |
| D-concurrency-control | MVCC + Serializable Snapshot Isolation (SSI) |
| D-isolation-level | Serializable (SSI) default; Snapshot Isolation as an opt-in documented mode |
| D-durability-mode | Group commit + `fdatasync` default; per-transaction synchronous available; torn-write protection + page checksums + PANIC-on-fsync-failure |
| D-buffer-mgmt | Custom self-managed buffer pool (not pure `mmap`) |
| **D-storage-arch** | **Custom record store with index-free adjacency from day one; transactional + recovery layer built in-house** *(override of recommended staged-hybrid; raises storage-correctness risk — reinforces DST)* |
| D-runtime-model | Hybrid: Tokio multi-thread baseline + a sharded write/ACID path (validate on a traversal-heavy benchmark) |
| D-io-backend | Portable epoll/kqueue baseline + optional io_uring fast path on Linux with runtime fallback |
| D-allocator | System allocator first; adopt mimalloc/jemalloc only with per-target before/after benchmarks |
| D-target-matrix | Linux x86_64 + aarch64 and macOS aarch64 as Tier 1 tested; 64-bit only; CI on x86 + aarch64 |
| **D-wire-protocol** | **Adopt Neo4j Bolt directly as the UDS wire protocol (PackStream)** *(override of recommended custom protocol)* |
| **D-bolt-compat** | **Add a Bolt TCP listener (`bolt://`) for the Neo4j driver ecosystem — a third network interface beyond the originally-stated UDS + REST** *(override; requires TLS + network security for the Bolt TCP endpoint)* |
| D-serialization | Typed JSON (Jolt-style) for REST + CBOR via negotiation; PackStream for Bolt (UDS + TCP); fix int53 from day one |
| D-auth-scheme | UDS `SO_PEERCRED` + socket perms; REST Bearer/JWT over TLS + RBAC; Bolt TCP native auth over TLS; shared RBAC |
| D-v1-topology | Single-node only in v1, clustering-ready internal interfaces |
| D-v1-index-types | Token-lookup + range/B-tree + composite (incl. relationship-property) indexes in v1 |
| **D-graph-algos** | **Full GDS-style graph-algorithms library (centrality, community detection, similarity, embeddings, in-memory projection engine)** *(override of recommended native-only; a large dedicated workstream/phase orthogonal to the ACID/TCK core)* |
| D-multi-db | Single database in v1; catalog abstraction (catalog→schema→graph) designed in |
| D-vector-index | Out of scope for v1; deferred to a later phase |
| D-security-scope | Auth + RBAC + TLS (REST + Bolt) + user/role management in v1; fine-grained access control / encryption-at-rest / auditing in Phase 2 |
| D-dst-investment | Scaffold a deterministic simulation testing harness from the start with fault injection |
| **D-vopr** | **External, totally-deterministic VOPR simulator: drive the REAL Bolt/PackStream + REST protocol stacks and the REAL engine over a SIMULATED transport + clock + disk (seed-reproducible), with misbehaved-client / fault / load coverage and four oracles (ref-model, Elle isolation, invariants/liveness, crash-durability)** *(extends D-dst-investment to the connectivity/protocol layer; "external" = real protocols, no backdoor, over an in-memory transport — not real OS sockets. See `07-dst-simulator.md`.)* |
| **D-read-parallelism** | **DEFER read-query parallelism for single-node production; keep the single-writer-thread engine model.** Lock-free snapshot reads are the long-term direction, but parallelizing reads is a large, high-risk change to the inviolable ACID guarantees, gated on a prerequisite migration. *(Post-ratification, sprint 19, 2026-06-15. Accepted-as-is; tracked as rmp #146. See note below.)* |
| **D-perf-deferrals** | **DEFER three higher-risk efficiency optimizations (per-commit catalog write, per-row slot model, streaming SHOW INDEXES/CONSTRAINTS).** Each is either a durability/identity risk, a TCK-correctness-sensitive executor rewrite, or a negligible-benefit change. *(Post-ratification, sprint 19, 2026-06-15. Accepted-as-is; tracked as rmp #159. See note below.)* |

**Four owner overrides of the recommendation** (recorded with a `note` on their KG nodes) reshape the
scope and are propagated into `00-overview.md` and `01-needs-survey.md`:
1. **D-storage-arch → custom from day one.** The transactional/recovery engine (WAL/ARIES/SSI) is
   built in-house from the start; this is the highest-risk work and is the reason DST (D-dst-investment)
   and the full verification arsenal are scaffolded immediately.
2. **D-wire-protocol → Bolt directly**, and **D-bolt-compat → add a Bolt TCP listener.** Graphus now
   exposes **three interfaces**: Bolt over UDS, Bolt over TCP (`bolt://`), and the Web REST API. These
   decisions extended the two-interface model in the original project definition; `CLAUDE.md` now
   records the three-interface model (see the note in `00-overview.md`).
3. **D-graph-algos → full library.** A complete graph-algorithms library plus an in-memory projection
   engine is committed as a dedicated workstream (its own phase), in addition to the ACID/TCK core.

> **Post-ratification note (2026-06-12) — `D-v1-index-types`.** The ratified outcome remains
> **option (a)** (token-lookup + range/B-tree + composite incl. relationship-property), and the v1
> index baseline is **not** re-ratified. The **full-text** capability of option (b) was nevertheless
> **delivered early by rmp #72**, ahead of its Phase-2 schedule, in the same manner as the other
> Phase-2 capabilities already shipped in this codebase without re-baselining (encryption at rest,
> fine-grained RBAC, and incremental backup + PITR). It is specified in `04-technical-design.md` §6.7
> and tracked as `FR-IX-7` (still `[ADV]`); it adds a capability without altering the four-kind core
> set that option (a) ratifies.

> **Post-ratification note (2026-07-08) — `D-named-index-autoname` (named node-property indexes).**
> This note records a **design decision**, not a scope change: node-property indexes and their Cypher
> DDL (`CREATE`/`DROP INDEX`, `SHOW INDEXES`) were always part of the v1 core set (`FR-IX-15`,
> ratified) and of `D-v1-index-types` option (a). Named node-property indexes (rmp #623–#626) make
> that DDL **Neo4j-conformant**: an index carries a name (`CREATE INDEX [<name>] [IF NOT EXISTS]
> FOR (n:Label) ON (n.property)`, `DROP INDEX <name> [IF EXISTS]`), `SHOW INDEXES` returns the Neo4j
> driver columns, and `IF NOT EXISTS`/`IF EXISTS` are idempotent no-ops.
> **`D-named-index-autoname`** captures the specific design choice for how the anonymous and legacy
> `CREATE INDEX ON :Label(property)` forms are named: a **deterministic, stable** auto-name of the
> form `index_<label>_<property>` (a pure function of the label and property tokens), disambiguated by
> a deterministic token suffix and, if needed, a counter, until the name is free in every schema
> catalog; the resolved name is then persisted durably, so it is computed at most once and stays
> stable across restarts. Names are globally unique across the schema's index and constraint catalogs,
> and the name catalog is durable (an append-only block in the storage `Statistics` image, crash-atomic
> with the index catalog; pre-existing anonymous indexes are backfilled with an auto-name on open). No
> ratified outcome changes; this is the completion of an already-ratified core requirement. Specified in
> `04-technical-design.md` §6.8 and recorded as a `Decision` node in the KG.

> **Post-ratification note (2026-06-15) — sprint-19 performance/architecture deferrals.**
> Two performance/architecture findings were evaluated during the sprint-19
> production-readiness closure and **deferred** (accepted-as-is for the single-node
> production sign-off, scheduled as future work). Both dispositions are
> measurement-/audit-grounded and follow the project's "measure to decide" rule and the
> inviolable ACID requirement: a certified-green engine is not destabilized for
> non-correctness gains. Each finding is recorded as a `Decision` node
> (`status: deferred`) tracked against its `rmp` task.
>
> **`D-read-parallelism` (rmp #146) — DEFER read-query parallelism.**
> An architectural audit found that all queries, reads included, currently funnel through
> a single engine OS thread via an `mpsc` channel, which serializes them; a stress test
> measured about 166 connections per second under 400-way concurrency on a trivial read.
> Parallelizing reads is the documented long-term direction (lock-free snapshot reads):
> the pure `is_visible` MVCC snapshot algebra in `graphus-txn` already exists, and a
> loom-verified `ConcurrentBufferPool` already exists. It is nevertheless a large to
> very-large, high-risk change to the inviolable ACID guarantees, and it is gated on a
> prerequisite migration. The live `RecordStore` read path is `&mut self` over the
> single-threaded `BufferPool`, and the store, index, token, and commit-registry views
> are `Rc<RefCell<…>>` (`!Send` / `!Sync`). The single-writer model currently delivers
> 100% ACID cleanly. The recommended path is a prerequisite epic:
> (a) migrate `RecordStore` reads onto `ConcurrentBufferPool`;
> (b) publish snapshot-consistent read views;
> (c) add the off-thread read executor and the engine routing — reassessed only after (a).
> **Status:** accepted-as-is for single-node production; tracked as rmp #146.
>
> **`D-perf-deferrals` (rmp #159) — DEFER three higher-risk efficiency optimizations.**
> Each of the three is deferred for its own reason:
> 1. **Per-commit catalog write (A1).** `RecordStore::commit` unconditionally rewrites the
>    whole catalog every commit (it clones the `TokenStore` and `Statistics`, serializes,
>    and page-writes). A dirty-flag gate is high-risk because the catalog persists
>    monotonic high-water marks — `commit_ts_hw`, `element_id_next`, the per-store physical
>    id high-water, and the token dictionary — that are not all WAL-recoverable; a missed
>    dirty-set is a silent durability or identity-reuse bug. The only genuinely
>    catalog-clean commit is a read-only one, whose payoff is marginal.
> 2. **Per-row slot model (B1/B2).** `Row` is a parallel `Vec<String>` with linear-scan
>    name lookup and a full clone per row. Resolving names to plan-time slot indices is a
>    large, TCK-correctness-sensitive (column order and rebind semantics), non-incremental
>    executor rewrite that belongs with the future cost-based-planner / typed-schema work.
>    A cheap, low-risk interim — an `Arc<[Arc<str>]>` shared column schema to remove the
>    per-row name-vector deep clone — is noted as a possible separate small task.
> 3. **Streaming SHOW INDEXES / CONSTRAINTS (C11).** The handler collects rows into a `Vec`
>    before replying, but the result is bounded by schema cardinality (tens of rows) and
>    the source is already an in-memory `Vec`; the benefit is negligible. Accept-as-is.
> **Status:** accepted-as-is for production; tracked as rmp #159.

## Ratified decision (2026-07-01) — `D-bulk-import-network`

> **`D-bulk-import-network` — Network bulk import (remote streaming bulk load).** Unlike the two
> sprint-19 entries above, this decision was **not** dispositioned by an internal audit against an
> already-ratified requirement — it was a genuinely new capability, proposed after an empirical
> load test (2026-06-30, host `pi516`) established that no existing mechanism can load a
> large-scale dataset (order of 1,000,000 nodes, hundreds of millions of relationships) into an
> already-running Graphus server, local or remote (`08-network-bulk-import.md` §1). It was
> presented with options and a recommendation on six facets, and the two highest-impact,
> least-reversible facets were flagged for sequential owner ratification. **The project owner
> ratified this decision on 2026-07-01**, confirming the recommended RBAC option and — on the
> target-database-scope facet — selecting the **non-recommended, higher-risk option**: network
> bulk import must support an already-live, already-serving database, not only a fresh/empty one.
> Full rationale, the resulting concurrency-safe design, and its independent validation
> (`storage-systems-auditor`, 2026-07-01) are in `08-network-bulk-import.md`; this entry is the
> register's summary of that document.
>
> **Status: ratified.**
>
> | Facet | Options | Ratified choice |
> | --- | --- | --- |
> | Transport | (a) new Bolt message type; (b) Bolt, bounded chunks over standard `RUN`/`PULL` only; ★(c) dedicated REST streaming-upload endpoint, exempt from the general 4 MiB body limit | **(c), as recommended.** Option (a) is a genuine Bolt-spec compliance violation (no reserved extension range in the spec) and PackStream's `BYTES_32` size tier is capped at ~2 GiB by the specification itself, ruling out a single large payload value regardless. Option (b) is spec-conformant but pays a full RUN/PULL/PackStream round trip per chunk for what is, at that point, opaque bytes. HTTP chunked transfer-encoding (RFC 9112/9113) has no such ceiling and is the standards-native fit; `graphus-rest` already established the symmetric egress-streaming pattern (rmp #475). See `08` §3. |
> | Payload format | (a) reuse the existing local CSV / `.gcol` formats `graphus-bulk` already parses; (b) a new network-specific binary format | **(a), as recommended.** Reuses already-certified (sprint 7) parsing/import logic unmodified; only the byte source changes. See `08` §4. |
> | Target-database scope | (a) fresh, empty database only (matches today's offline-importer precondition); **(b) — RATIFIED, the non-recommended option** — support incremental load into an already-live, already-serving database, in addition to (a) | **Both (a) and (b) — the owner chose to add (b) on top of, not instead of, (a).** (b) requires the low-level import path to participate in MVCC/SSI conflict detection and inline index maintenance against concurrent transactions — flagged as being in the same risk family as the already-deferred `D-read-parallelism` (rmp #146). Unlike that deferral, this was ratified: `08` §7.2 is the resulting concurrency-safe design (every batch is a first-class, SSI-participating `TxnCoordinator` transaction, never a raw low-level store bypass), independently validated against the actual concurrency-control code before being written into the spec. Named **Mode A** ((a), exclusive, `08` §5.1–§5.2) and **Mode B** ((b), concurrent, `08` §5.3) in the spec. |
> | Exclusivity mechanism | Mode A: ★a new `Loading` database lifecycle state (engine running, ordinary client traffic rejected) alongside the existing `Online`/`Offline`; Mode B: no exclusivity mechanism, correctness from MVCC/SSI alone | **Both, one per mode — as designed.** Mode A mirrors the existing `RESTORE DATABASE` precedent (stopped first, started explicitly after) while keeping the engine alive to receive the stream; scoped to one database, every other database unaffected (`D-multi-db`). Mode B stays `Online` throughout and relies entirely on the same SSI machinery that already protects ordinary concurrent Cypher transactions. See `08` §5.2/§5.3. |
> | RBAC privilege | ★(a) the existing global `Admin` privilege (same gate as `BACKUP`/`RESTORE`/`CREATE DATABASE`), for both modes; (b) a new, narrower graph-scoped privilege | **(a), as recommended — confirmed by the owner, no change, applies to both Mode A and Mode B.** The operation can take exclusive control of a database (Mode A) or write at import scale against live traffic while bypassing the ordinary Cypher write path's fine-grained RBAC checks (Mode B), so it should not be reachable by a data-level `Write` grant alone. A narrower privilege remains a possible follow-up once the core capability is in production. See `08` §6. |
> | Atomicity / resumability | ★(a) extend the already-ratified `D-bulk-import-non-atomic` (per-batch commit, whole session non-atomic) and add mandatory, crash-consistent session-checkpoint resumability; (b) require the whole import to be all-or-nothing | **(a), as recommended, both modes.** Does not weaken the inviolable ACID requirement: every committed batch is a fully durable, consistent transaction; only the *session as a whole* is non-atomic, exactly as already ratified for the offline case. Resumability is the correct response to network unreliability, not a workaround for it. **Mode B additionally requires** a prerequisite fix in `graphus-bulk` (the `id_map` staging bug, `08` §7.2.2) before its automatic batch retry can be enabled safely — see the note below. See `08` §7. |
>
> **Prerequisite fix required before Mode B ships.** The independent validation
> (`storage-systems-auditor`, 2026-07-01) surfaced a **pre-existing, must-fix correctness bug** in
> `graphus-bulk::BulkImporter`: its external-id→physical-id map is mutated eagerly during row
> ingestion, before the enclosing transaction commits, and is never reverted on rollback. This is
> harmless for today's offline, no-retry, empty-database path, but Mode B's batch-retry-on-abort
> requirement (an expected, ordinary event under live-database concurrency, `08` §7.2.1) would
> turn it into a live data-corruption risk (spurious duplicate-id failures, or silently orphaned
> nodes and corrupted relationship-pass joins under `DuplicatePolicy::SkipDuplicate`). Registered
> as KG Finding `bulk-idmap-not-abort-safe` (severity high, status open). **This fix is a
> precondition of Mode B's acceptance criteria** (`08` §11), not a follow-up.
>
> DoS/resource-limit requirements (byte quotas, disk-space preflight, session timeouts,
> backpressure, engine-thread-yielding fairness for Mode B) and the two required new DST scenarios
> (`network_bulk_ingest_mode_a`, `network_bulk_ingest_mode_b`) are specified in
> `08-network-bulk-import.md` §8 and §10 respectively; they are implementation requirements of the
> ratified design, not separate decisions.

## Ratified decision (2026-07-08) — `D-hw-autotune`

> **`D-hw-autotune` — Hardware-aware startup auto-tuning.** At startup the server probes the host
> hardware (logical CPUs, total/available physical RAM, and the store filesystem's capacity/free
> space plus an SSD-vs-rotational hint) and derives sane defaults for its resource-sizing parameters,
> while every value stays operator-overridable. It is motivated by `FR-AR-6` (the same binary must
> scale from a 4-core Raspberry Pi 5 to a many-core server without hand-tuning) and by the observation
> that `buffer_pool_pages` shipped as a fixed 4096-page (32 MiB) default regardless of host RAM,
> whereas `reader_threads` / `morsel_parallelism` already auto-sized from the CPU count. This decision
> unifies both under one detection path and one precedence rule. The full design is
> `04-technical-design.md` §9.5.
>
> **Status: ratified.**
>
> | Facet | Ratified choice |
> | --- | --- |
> | Precedence & sentinel | **The `0 = auto` sentinel plus a strict three-level precedence — operator configuration (TOML file or `GRAPHUS_*` env var) > hardware-derived value > built-in floor — is adopted as the project-wide auto-tuning convention.** A value the operator sets explicitly always wins; a parameter left at its `0` sentinel is hardware-derived; a built-in floor guarantees a safe minimum when a probe fails. This generalizes the already-shipped `reader_threads` / `morsel_parallelism` behavior (`04` §9.3) to the memory dimension. |
> | Buffer-pool sizing | **Auto `buffer_pool_pages = clamp( floor(0.125 × available_RAM_bytes ÷ 8192), 4096, 262144 )` — a conservative 1/8 of *available* RAM (falling back to total RAM, then to the floor), floored at 4096 pages (32 MiB) and capped at 262144 pages (2 GiB).** The 1/8 fraction is deliberately conservative **because the buffer pool is per-database** (each opened database gets its own pool) and RAM is shared with the WAL, indexes, result buffers, and the OS; the floor equals today's fixed default, so auto is never worse than the status quo, and the ceiling bounds worst-case resident-set growth. |
> | Probe isolation | **All OS-specific and `unsafe` hardware probing is isolated in a new, independently-audited `graphus-sysres` leaf crate** (`04` §1.2), so `graphus-server` stays `#![forbid(unsafe_code)]`. Every probe is best-effort with graceful degradation (a failed probe yields `None` and the floor is used); detection never panics or blocks server start. |
>
> **Scope note.** In this first cut, the detected storage capacity/free space and the rotational/SSD
> hint are **detected and reported in the startup log only**; they may inform future tuning but drive
> no automatic parameter change yet (`04` §9.5). The resolved values and their provenance
> (operator-overridden, hardware-derived, or floor) are recorded in a single structured startup log
> line.

## TCK target (pinned — closes `D-cypher-line` open question 1)

The "100% Cypher TCK" target is pinned to the **openCypher `2024.3`** tag (commit `677cbaf`,
dated 2026-03-20), the latest release on the GQL-convergent 2024.x line. **`1.0.0-M23`** is the
first-milestone snapshot.

Scenario counts. The `D-cypher-line` comparison below was made on 2026-06-05 by cloning each tag and
parsing its `features/**/*.feature`:

| Snapshot | `.feature` files | `Scenario` + `Scenario Outline` blocks | Executable scenarios (outline examples expanded) |
| --- | --- | --- | --- |
| **2024.3 (target)** | 220 | 1615 (1339 + 276) | 3880 (1339 plain + 2541 example rows) |
| 1.0.0-M23 (milestone) | 220 | 1615 (1339 + 276) | 3880 |

The two tags coincide in totals but differ in content (the scenarios were revised, not net-added,
along this path), so the 2024.x language surface (label expressions, quantified path patterns,
`SHORTEST`, element-pattern `WHERE`) is delivered behind feature flags while certifying the same
scenario budget. The pinned 2024.3 corpus is **vendored** at `crates/graphus-tck/tck/features` (221
feature files) and is the authoritative certification target: the `graphus-tck` runner executes and
passes **all 3914 executable scenarios** (1356 plain + 2558 outline example rows), asserted by the
`BASELINE` constant in `crates/graphus-tck/tests/tck.rs`. (The corpus grew by 34 scenarios — 17 plain
and 17 outline example rows — between the 2026-06-05 estimate and the vendored snapshot the harness
certifies.) "100% TCK compliant" = **all 3914 executable scenarios of the pinned, vendored corpus
pass** (correct result bag/order, correct side-effect counts, correct error type at the correct
phase).
The verbatim result/failure shapes and the error-classification table were read and frozen by
SPIKE #9 (`06-bolt-and-error-shapes.md` §2–§3; resolves open question 2 and `04-technical-design.md`
§12 item 13).

| ID | Decision | Options | Affects |
| --- | --- | --- | --- |
| **D-cypher-line** | Cypher version / TCK snapshot | (a) openCypher 9 (M23), frozen, smaller surface; (b) openCypher 2024.x (GQL-convergent), larger surface; ★(c) implement 2024.x but feature-gate the newest constructs and certify the M-series milestone first — **pin a specific tagged commit and count its scenarios** | Query Language |
| **D-tck-harness** | How to run the TCK from Rust | ★(a) Rust `cucumber` for CI + (b) periodic JVM `tck-api` as ground-truth oracle; (c) bespoke Rust step interpreter | Testing |
| **D-storage-arch** | Storage architecture | (a) custom record store + index-free adjacency from day one; (b) build on an embedded transactional KV engine (redb/sled/RocksDB); ★(c) **staged hybrid** — validate correctness on `redb`, then migrate the traversal hot path to a custom index-free-adjacency store. **High-impact; discuss explicitly.** | Storage Engine |
| **D-concurrency-control** | Concurrency-control scheme | (a) strict 2PL; (b) MVCC + Snapshot Isolation; ★(c) MVCC + SSI (serializable correctness at SI speed) | Transaction Manager |
| **D-isolation-level** | Default isolation level | (a) Read Committed; (b) Snapshot Isolation; ★(c) Serializable (via SSI) default, with Snapshot Isolation as an opt-in documented mode | Transaction Manager |
| **D-durability-mode** | Durability mode | (a) synchronous fsync per commit; ★(b) group commit + `fdatasync` default, per-transaction synchronous available; (c) async commit — **rejected** (breaks durability). Mandatory: torn-write protection + page checksums + PANIC-on-fsync-failure | WAL |
| **D-buffer-mgmt** | Buffer management | (a) `mmap`; ★(b) custom buffer pool (control over eviction, async I/O, torn-write protection) | Storage Engine |
| **D-runtime-model** | Async runtime / concurrency model | (a) Tokio multi-thread work-stealing; (b) thread-per-core share-nothing (glommio/monoio, Linux-only); ★(c) hybrid — Tokio baseline (runs on macOS too) + sharded write/ACID path. **Validate on a traversal-heavy benchmark.** | Architecture |
| **D-io-backend** | I/O backend | (a) epoll/kqueue only; (b) io_uring only (breaks macOS/seccomp); ★(c) portable epoll/kqueue baseline + optional io_uring on Linux with runtime fallback | Architecture |
| **D-allocator** | Memory allocator | ★(a) start with system default and benchmark; (b) mimalloc; (c) jemalloc — adopt (b)/(c) only with per-target numbers (jemalloc has historical Apple-Silicon friction) | Architecture |
| **D-target-matrix** | Target-triple matrix | (a) Linux x86_64 only; ★(b) Linux x86_64 + aarch64 + macOS aarch64 (all Rust Tier 1), 64-bit only, CI on x86 + aarch64; (c) also Intel macOS (Tier 2) + 32-bit ARM | Architecture |
| **D-wire-protocol** | UDS wire protocol | ★(a) custom binary, length-prefixed, Bolt-inspired semantics; (b) adopt Bolt directly; (c) custom + optional Bolt transport | Wire Protocol |
| **D-bolt-compat** | Bolt protocol compatibility | (a) yes, as an optional later transport (free Neo4j-driver ecosystem); ★(b) no for v1 (not part of the TCK; revisit in Phase 2) | Connectivity |
| **D-serialization** | Serialization formats | ★(a) typed JSON (Jolt-style) for REST + CBOR via negotiation; PackStream/CBOR for UDS; **fix int53 from day one**; (b) plain JSON only (lossy); (c) protobuf everywhere | Serialization |
| **D-auth-scheme** | Auth scheme per interface | ★(a) UDS = `SO_PEERCRED` + socket permissions; REST = Bearer/JWT over TLS + RBAC (optional Basic); (b) token auth on both | Auth |
| **D-v1-topology** | v1 topology | ★(a) single-node only, clustering-ready interfaces; (b) single-node + design clustering in; (c) single-node + early read replicas | Architecture |
| **D-v1-index-types** | v1 index types | ★(a) token-lookup + range/B-tree + composite; (b) + full-text; (c) + full-text + spatial + vector | Index Manager |
| **D-graph-algos** | Graph algorithms library | ★(a) native Cypher path functions only in v1; (b) small built-in set (Dijkstra, PageRank, WCC); (c) full library | Graph Algorithms |
| **D-multi-db** | Multi-database support | ★(a) single DB in v1, catalog abstraction designed in; (b) multi-database in v1 | Multi-tenancy |
| **D-vector-index** | Vector/similarity index | ★(a) out of scope for v1; (b) in v1 | Indexing & Constraints |
| **D-security-scope** | Security scope for v1 | ★(a) auth + RBAC + TLS(REST) + user/role mgmt; (b) + fine-grained access control; (c) + encryption at rest + auditing | Security |
| **D-dst-investment** | DST investment | ★(a) scaffold a deterministic simulation harness from the start; (b) add it in Phase 2 | Testing |
| **D-element-id** | Element ID scheme | (a) Neo4j-style numeric `id()` reused on delete + string `elementId`; ★ internal compact IDs + a **stable, never-reused** public ID (ULID/UUIDv7) for operational safety. **Tension to rule on:** TCK literal ID-reuse vs ACID-grade stability | Data Model |
| **D-temporal-spatial** | Temporal/spatial type scope | (a) full temporal set + full spatial in v1; ★ full temporal in v1, spatial deferred unless required at launch; (c) integers/epoch only | Data Model |
| **D-read-parallelism** | Read-query parallelism (post-ratification, sprint 19) | ★(a) **DEFER** — keep the single-writer-thread engine; accept-as-is for single-node production, schedule the parallel-reads epic as future work (rmp #146); (b) parallelize reads now — rejected for this sign-off (large/very-large, high-risk change to inviolable ACID, with an unfinished prerequisite migration) | Architecture / Transaction Manager |
| **D-perf-deferrals** | Three higher-risk efficiency optimizations (post-ratification, sprint 19) | ★(a) **DEFER all three** — accept-as-is for production, schedule as future work (rmp #159); (b) apply them now — rejected (per-commit catalog dirty-gating is a durability/identity-reuse risk, the per-row slot model is a TCK-correctness-sensitive executor rewrite, and streaming SHOW INDEXES/CONSTRAINTS has negligible benefit) | Architecture / Storage Engine / Executor |

## Cross-cutting notes

- **Inviolable and mutually reinforcing:** `D-isolation-level` (Serializable via SSI) and
  `D-durability-mode` (group commit + torn-write protection + PANIC-on-fsync-failure). Anything
  weaker contradicts "data must never be corrupted or in an invalid state."
- **Highest-risk, highest-impact:** `D-storage-arch`. It dominates cost, risk, and timeline.
- **Measurement-gated:** `D-runtime-model`, `D-io-backend`, and `D-allocator` must be confirmed by
  benchmark on a representative workload before being locked (project rule: "measure to decide").
- **Verification is a deliverable, not an afterthought:** `D-tck-harness` + `D-dst-investment` are
  how the ACID and Cypher TCK inviolable requirements are *proven empirically* rather than
  asserted; protocol-conformance and driver-interoperability tests against the official driver
  ecosystem prove the Bolt protocol and PackStream requirements the same way.

## Open questions for the owner to close before locking the spec

1. Pin the exact openCypher TCK tag and record its scenario/feature count (do not quote a number
   from memory). **Resolved** in the "TCK target" section above: pinned to openCypher `2024.3`
   (commit `677cbaf`).
2. Read the verbatim TCK result / failure shapes and lock the error-classification table.
   **Resolved (2026-06-09) by SPIKE #9 — see `06-bolt-and-error-shapes.md` §2 and §3.** The
   compile-time error-classification table is frozen with `(phase, type, detail)` triples whose
   detail strings are verbatim from `tck/features/**`, grounded in the implemented
   `crates/graphus-cypher/src/errors.rs`; the Bolt `SUCCESS`/`RECORD`/`FAILURE` result and failure
   shapes and their REST RFC 9457 equivalent are documented there. **Deferred:** the Neo4j
   two-letter Bolt status codes (a Neo4j surface, not part of the openCypher TCK triple) need the
   pinned TCK and certified driver artifacts to map verbatim and are not invented (`06` §2.4).
3. Resolve the `D-element-id` tension (TCK ID-reuse literalism vs stable never-reused IDs).
4. Decide whether spatial types ship in v1 (`D-temporal-spatial`).
5. Confirm REST read/write access-mode selection (the Bolt `BEGIN` field has no documented REST
   equivalent). **Resolved (2026-06-09) by SPIKE #9 — see `06-bolt-and-error-shapes.md` §4.** The
   REST transactional API declares access mode through an `access_mode` request member with values
   `"READ"` / `"WRITE"`, defaulting to `"WRITE"` when absent, validated as a client error otherwise,
   matching the Bolt `BEGIN` semantics.
6. Ratify `D-bulk-import-network` (see the "Ratified decision (2026-07-01)" section above and
   `08-network-bulk-import.md`). **Resolved (2026-07-01).** The owner confirmed the recommended
   REST-streaming transport and the global `Admin` RBAC gate, and selected the non-recommended
   option on database scope: both a fresh/empty database (Mode A) and an already-live database
   under concurrent traffic (Mode B) are in scope. Mode B's concurrency-safe design (`08` §7.2)
   was independently validated by `storage-systems-auditor` before being finalized; that audit
   also surfaced a prerequisite `graphus-bulk` correctness fix (`08` §7.2.2, KG Finding
   `bulk-idmap-not-abort-safe`) that must land before Mode B's automatic batch retry ships.
