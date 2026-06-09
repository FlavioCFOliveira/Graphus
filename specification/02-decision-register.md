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

**Four owner overrides of the recommendation** (recorded with a `note` on their KG nodes) reshape the
scope and are propagated into `00-overview.md` and `01-needs-survey.md`:
1. **D-storage-arch → custom from day one.** The transactional/recovery engine (WAL/ARIES/SSI) is
   built in-house from the start; this is the highest-risk work and is the reason DST (D-dst-investment)
   and the full verification arsenal are scaffolded immediately.
2. **D-wire-protocol → Bolt directly**, and **D-bolt-compat → add a Bolt TCP listener.** Graphus now
   exposes **three interfaces**: Bolt over UDS, Bolt over TCP (`bolt://`), and the Web REST API. This
   extends the two-interface model in the project definition (`CLAUDE.md`); see the note in `00-overview.md`.
3. **D-graph-algos → full library.** A complete graph-algorithms library plus an in-memory projection
   engine is committed as a dedicated workstream (its own phase), in addition to the ACID/TCK core.

## TCK target (pinned — closes `D-cypher-line` open question 1)

The "100% Cypher TCK" target is pinned to the **openCypher `2024.3`** tag (commit `677cbaf`,
dated 2026-03-20), the latest release on the GQL-convergent 2024.x line. **`1.0.0-M23`** is the
first-milestone snapshot.

Scenario counts (measured by cloning each tag and parsing `tck/features/**/*.feature` on 2026-06-05):

| Snapshot | `.feature` files | `Scenario` + `Scenario Outline` blocks | Executable scenarios (outline examples expanded) |
| --- | --- | --- | --- |
| **2024.3 (target)** | 220 | 1615 (1339 + 276) | **3880** (1339 plain + 2541 example rows) |
| 1.0.0-M23 (milestone) | 220 | 1615 (1339 + 276) | 3880 |

The two tags coincide in totals but differ in content (the scenarios were revised, not net-added,
along this path), so the 2024.x language surface (label expressions, quantified path patterns,
`SHORTEST`, element-pattern `WHERE`) is delivered behind feature flags while certifying the same
scenario budget. "100% TCK compliant" = **all 3880 executable scenarios of the pinned tag pass**
(correct result bag/order, correct side-effect counts, correct error type at the correct phase).
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

## Cross-cutting notes

- **Inviolable and mutually reinforcing:** `D-isolation-level` (Serializable via SSI) and
  `D-durability-mode` (group commit + torn-write protection + PANIC-on-fsync-failure). Anything
  weaker contradicts "data must never be corrupted or in an invalid state."
- **Highest-risk, highest-impact:** `D-storage-arch`. It dominates cost, risk, and timeline.
- **Measurement-gated:** `D-runtime-model`, `D-io-backend`, and `D-allocator` must be confirmed by
  benchmark on a representative workload before being locked (project rule: "measure to decide").
- **Verification is a deliverable, not an afterthought:** `D-tck-harness` + `D-dst-investment` are
  how the two inviolable requirements are *proven empirically* rather than asserted.

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
