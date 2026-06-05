# 02 — Decision Register

These are the open design decisions surfaced by the needs survey and the supporting research.
Per the project rule "you are not authorized to make decisions on your own", each is presented
with options and a recommendation, and **must be ratified by the project owner** before the
detailed per-domain functional specification and the implementation sprints are finalized.

Each decision is a `Decision` node in the Knowledge Graph (status `open`) with an `AFFECTS` edge
to the domain/component it constrains. On ratification, the chosen option is recorded on the node
and its status set to `ratified`.

Legend: ★ = recommended option.

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
   from memory).
2. Read the verbatim TCK `QueryType` / result / failure shapes from the pinned tag before locking
   the Rust harness design.
3. Resolve the `D-element-id` tension (TCK ID-reuse literalism vs stable never-reused IDs).
4. Decide whether spatial types ship in v1 (`D-temporal-spatial`).
5. Confirm REST read/write access-mode selection (the Bolt `BEGIN` field has no documented REST equivalent).
