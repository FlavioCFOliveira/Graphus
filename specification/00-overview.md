# 00 — Overview

## 1. Project definition

**Graphus** is an **LPG (Label Property Graph) database server** written in **Rust**.
It is designed to operate **exemplarily and without failure under extreme load and
concurrency**. By default the graph is a **multigraph**.

Graphus has two inviolable requirements:

- **100% ACID compliant** — full reliability and safety when processing transactions,
  even under power failure, errors, or system faults. Data must **never** become corrupted
  or be left in an invalid state after an operation.
- **100% Cypher TCK compliant** — fully compliant with the official openCypher
  specification: any query written in Cypher behaves exactly as expected, with no
  unexpected behavior or syntax failure.

Both requirements are **absolutely inviolable** and constrain every design decision.

## 2. Goals

- A correct, durable, high-performance **single-node** LPG server (distribution is a later phase).
- Two connection interfaces, both following official industry standards:
  - **UDS** — Unix Domain Sockets (IPC) for clients on the same operating system.
  - **Web REST API** — HTTP for standardized, remote, interoperable access.
- Runs flawlessly on **Linux, macOS, and Raspberry Pi OS** across **x86_64, arm64, and
  aarch64**, explicitly including **Apple Silicon, x86 processors, and Raspberry Pi 5+**.
- Maximum performance across all supported hardware, from the most basic to the most advanced.
- An extensive test suite proving correctness as a whole and per component (unit, E2E,
  stress/load), and empirically proving the two inviolable requirements.

## 3. Scope boundaries (v1)

In scope for the first solid deliverable (Phase 1):

- Native LPG multigraph storage; full property type/value model.
- CRUD via Cypher and via the native UDS API.
- A Cypher engine targeting 100% TCK: parser → semantic analysis → planner → executor.
- Token-lookup, range/B-tree, and composite indexes; index-backed lookups.
- Uniqueness and existence constraints; DDL via Cypher.
- ACID transactions: explicit and implicit, multi-statement, MVCC, a documented isolation
  level, WAL + checkpointing + crash recovery.
- Both interfaces (UDS + REST), one reference driver, and a CLI/shell.
- `LOAD CSV` + offline bulk importer + dump/export.
- Offline backup/restore + snapshots + restore verification.
- Baseline security: authentication, RBAC, user/role management, TLS for REST.
- Observability: metrics (Prometheus/OpenMetrics), structured + query/slow-query logs,
  health checks, admin API, configuration management.
- Reliability: consistency checker, page/record checksums, startup integrity verification.

Out of scope for v1 (deferred — see `01-needs-survey.md` and the phased roadmap):

- Clustering, replication, sharding, distributed transactions.
- Full-text, spatial, and vector/similarity indexes.
- A graph-algorithms library beyond native Cypher path functions.
- Multiple databases / multi-tenancy (the catalog abstraction is designed in, not shipped).
- User-defined functions/procedures and a plugin mechanism.
- Bolt-protocol compatibility (optional later transport; not part of the TCK).

## 4. Glossary

- **LPG (Label Property Graph):** a directed, vertex-labeled, edge-labeled **multigraph**
  with self-edges, where edges have their own identity.
- **Node:** a first-class entity with a set of zero or more **labels** and zero or more properties.
- **Relationship (edge):** a directed connection between exactly two nodes, with **exactly
  one relationship type**, its own identity, and zero or more properties.
- **Multigraph:** parallel edges (multiple relationships between the same node pair, possibly
  of the same type) and self-loops are allowed; edges are distinguished by identity.
- **Property:** a (key, value) pair on a node or relationship; a key maps to exactly one value
  (which may be a homogeneous list).
- **Cypher TCK:** the openCypher **Technology Compatibility Kit**, a Cucumber/Gherkin suite of
  scenarios that certify a Cypher implementation's observable behavior.
- **GQL:** ISO/IEC 39075:2024, the ISO graph query-language standard; Cypher is its principal ancestor.
- **WAL:** Write-Ahead Log. **MVCC:** Multi-Version Concurrency Control. **SSI:** Serializable
  Snapshot Isolation. **UDS:** Unix Domain Socket. **DST:** Deterministic Simulation Testing.

## 5. Non-functional / quality requirements

| ID | Requirement |
| --- | --- |
| **NFR-1** | **Durability:** no acknowledged commit is ever lost; no corruption after power loss, OS crash, or process kill. Verified by crash-consistency and deterministic simulation testing. |
| **NFR-2** | **Atomicity & isolation:** transactions are all-or-nothing and isolated at the documented level with zero anomalies for the default level. Verified by Jepsen/Elle-style anomaly checking. |
| **NFR-3** | **Cypher conformance:** 100% pass rate on a pinned openCypher TCK snapshot, enforced as a hard CI gate. |
| **NFR-4** | **Concurrency:** sustains extreme concurrent read/write load without corruption, deadlock-storms, or unbounded memory growth; readers do not block writers. |
| **NFR-5** | **Graceful degradation:** under overload the server sheds load explicitly (bounded queues, admission control, fast rejection) rather than collapsing or running out of memory. |
| **NFR-6** | **Portability:** identical behavior and clean test runs on Linux/macOS/Raspberry Pi OS across x86_64 and aarch64 (incl. Apple Silicon 16 KB pages, ARM weak memory model). |
| **NFR-7** | **Performance is empirical:** every performance claim is backed by benchmarks (Criterion + macro LDBC SNB); CI fails on statistically significant regressions. |
| **NFR-8** | **Standards compliance:** UDS and REST interfaces strictly follow the cited official standards (RFCs, OpenAPI, openCypher). |
| **NFR-9** | **Concurrency-code safety:** every `unsafe`/lock-free unit ships with documented invariants, Miri-clean, loom/Shuttle coverage, and an aarch64 test run. |
| **NFR-10** | **Observability:** liveness/readiness, metrics, structured logs, slow-query log, and admin introspection are available in production. |
| **NFR-11** | **Documentation:** accurate, complete, flawless English, faithful to the code, kept in step with each change. |
| **NFR-12** | **No partial work:** no skipped/ignored tests; every fixed bug gets a permanent regression test. |

## 6. Phased roadmap

- **Phase 0 — Specification (current):** global needs survey, decision register, sources,
  roadmap and Knowledge Graph established.
- **Phase 1 — Single-node correctness core:** the v1 scope in §3; the first solid deliverable,
  fully ACID, fully recoverable, targeting 100% TCK on the pinned snapshot.
- **Phase 2 — Production hardening & ecosystem:** cost-based optimizer with statistics;
  full-text/spatial indexes; online index builds; node-key/type constraints; online/hot and
  incremental backup + PITR; fine-grained access control, encryption at rest, auditing;
  UDFs/UDPs + extension mechanism; multi-database; visualization; Bolt compatibility; full LDBC SNB.
- **Phase 3 — Distribution & advanced analytics:** replication, read replicas, consensus,
  failover, sharding, distributed transactions; graph-algorithms library; vector/similarity
  indexes; streaming ingestion; GQL conformance alongside Cypher.

## 7. Traceability

Every need, component, decision, phase, and source in this specification is represented as a
node in the `rmp` Knowledge Graph (roadmap `graphus`) and linked by typed edges
(`HAS_REQUIREMENT`, `HAS_DOMAIN`, `INCLUDES`, `DEPENDS_ON`, `AFFECTS`, `PRECEDES`,
`VERIFIED_BY`, `DOCUMENTED_IN`). The graph is the queryable index of the project and is
updated on every commit.
