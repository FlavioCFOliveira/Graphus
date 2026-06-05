# 03 — Authoritative Sources

Every requirement in this specification is grounded in the official standards, peer-reviewed
papers, authoritative books, and reference vendor documentation below. These are mirrored as
`Source` nodes in the Knowledge Graph, linked to the domains they document (`DOCUMENTED_IN`).

## Data model & query language

- openCypher — Property Graph Model — https://github.com/opencypher/openCypher/blob/master/docs/property-graph-model.adoc
- openCypher TCK — https://github.com/opencypher/openCypher/tree/master/tck
- openCypher resources (Cypher 9 reference; 2024.x line; TCK M-series) — https://opencypher.org/resources/
- Cypher Query Language Reference, Version 9 — https://s3.amazonaws.com/artifacts.opencypher.org/openCypher9.pdf
- openCypher type-system CIP — https://github.com/opencypher/openCypher/blob/master/cip/1.accepted/CIP2015-09-16-public-type-system-type-annotation.adoc
- Renzo Angles, *The Property Graph Database Model* (AMW 2018) — https://ceur-ws.org/Vol-2100/paper26.pdf
- ISO/IEC 39075:2024 (GQL) — https://www.iso.org/standard/76120.html
- JTC1 informational article on GQL — https://jtc1info.org/wp-content/uploads/2024/04/2024-Article-39075-Database-Language-GQL.docx.pdf
- Neo4j Cypher Manual — values & types (property/structural/constructed; temporal; spatial; ordering/equality) — https://neo4j.com/docs/cypher-manual/current/values-and-types/property-structural-constructed/
- Neo4j Cypher Manual — functions — https://neo4j.com/docs/cypher-manual/current/functions/
- Neo4j Cypher Manual — GQL conformance appendix — https://neo4j.com/docs/cypher-manual/current/appendix/gql-conformance/

## Transactions, ACID, storage & durability

- Berenson et al., *A Critique of ANSI SQL Isolation Levels* (SIGMOD 1995) — https://mwhittaker.github.io/papers/html/berenson1995critique.html
- ARIES recovery algorithm — https://en.wikipedia.org/wiki/Algorithms_for_Recovery_and_Isolation_Exploiting_Semantics
- Cahill/Röhm/Fekete — Serializable Snapshot Isolation; Ports & Grittner, *SSI in PostgreSQL* (VLDB 2012) — https://arxiv.org/abs/1208.4179
- PostgreSQL SSI wiki / README-SSI — https://wiki.postgresql.org/wiki/Serializable · https://github.com/postgres/postgres/blob/master/src/backend/storage/lmgr/README-SSI
- Write-Ahead Logging & ARIES (Sookocheff) — https://sookocheff.com/post/databases/write-ahead-logging/
- CMU 15-445 Crash Recovery — https://15445.courses.cs.cmu.edu/fall2023/notes/20-recovery.pdf
- Fsyncgate (durability / fsync failure) — https://danluu.com/fsyncgate/ · https://wiki.postgresql.org/wiki/Fsync_Errors
- Torn pages, PostgreSQL vs MySQL (Percona) — https://www.percona.com/blog/a-tale-of-two-databases-how-postgresql-and-mysql-handle-torn-pages/
- Durability: Linux file APIs (Evan Jones) — https://www.evanjones.ca/durability-filesystem.html
- Crotty/Leis/Pavlo, *Are You Sure You Want to Use MMAP in Your DBMS?* (CIDR 2022) — https://db.cs.cmu.edu/mmap-cidr2022/
- Neo4j storage internals & concurrent data access — https://gauravsarma1992.medium.com/neo4j-storage-internals-be8d150028db · https://neo4j.com/docs/operations-manual/current/database-internals/concurrent-data-access/
- Memgraph storage / MVCC / durability — https://deepwiki.com/memgraph/memgraph/3-storage-system · https://memgraph.com/blog/how-does-memgraph-ensure-data-durability
- B-tree vs LSM (TiKV) — https://tikv.org/deep-dive/key-value-engine/b-tree-vs-lsm/
- redb (pure-Rust copy-on-write B+-tree, ACID) — https://github.com/cberner/redb
- B+-tree / KV alternatives: sled — https://github.com/spacejam/sled

## Connectivity (UDS + REST), protocol & serialization

- `unix(7)` Linux man page (socket types, `sun_path`, `SO_PEERCRED`) — https://man7.org/linux/man-pages/man7/unix.7.html
- Neo4j Bolt protocol (handshake, messages, PackStream) — https://neo4j.com/docs/bolt/current/
- Neo4j transactional Cypher HTTP / Query API — https://neo4j.com/docs/query-api/current/transactions/ · https://neo4j.com/docs/http-api/current/transactions/
- Neo4j HTTP API result formats / Jolt typed JSON — https://neo4j.com/docs/http-api/current/result-formats/
- RFC 9110 (HTTP Semantics), RFC 9112 (HTTP/1.1), RFC 9113 (HTTP/2) — https://www.rfc-editor.org/info/rfc9110/
- RFC 9457 (Problem Details for HTTP APIs) — https://www.rfc-editor.org/rfc/rfc9457.html
- RFC 8259 (JSON), RFC 8949 (CBOR) — https://www.rfc-editor.org/rfc/rfc8259 · https://www.rfc-editor.org/rfc/rfc8949
- RFC 6749 (OAuth2), RFC 6750 (Bearer), RFC 7519 (JWT) — https://www.rfc-editor.org/rfc/rfc6750.html
- Idempotency-Key HTTP header (IETF draft) — https://datatracker.ietf.org/doc/html/draft-ietf-httpapi-idempotency-key-header-07
- OpenAPI Specification 3.1 — https://spec.openapis.org/oas/v3.1.0.html
- Redis RESP3 — https://github.com/redis/redis-specifications/blob/master/protocol/RESP3.md
- Tokio graceful shutdown / backpressure / semaphore — https://tokio.rs/tokio/topics/shutdown
- axum / hyper / tonic / tower — https://docs.rs/axum/latest/axum/
- OpenTelemetry & Prometheus / health probes — https://opentelemetry.io/

## Architecture, performance & portability

- Tokio runtime & scheduler internals — https://docs.rs/tokio/latest/tokio/runtime/index.html · https://tokio.rs/blog/2019-10-scheduler
- ScyllaDB/Seastar shard-per-core / shared-nothing — https://www.scylladb.com/product/technology/shard-per-core-architecture/ · https://seastar.io/shared-nothing/
- The State of Async Rust: runtimes (tokio/glommio/monoio) — https://corrode.dev/blog/async/
- io_uring: tokio-uring; DBMS paper; seccomp constraints — https://tokio.rs/blog/2021-07-tokio-uring · https://arxiv.org/pdf/2512.04859 · https://github.com/moby/moby/issues/47532
- mimalloc — https://microsoft.github.io/mimalloc/
- crossbeam `CachePadded` (per-arch cache-line sizes) — https://docs.rs/crossbeam-utils/latest/crossbeam_utils/struct.CachePadded.html
- Transparent Huge Pages for databases (Percona) — https://www.percona.com/blog/settling-the-myth-of-transparent-hugepages-for-databases/
- ARM vs x86 memory models with Rust — https://www.nickwilcox.com/blog/arm_vs_x86_memory_model/
- *Rust Atomics and Locks* (Mara Bos), ch. 7 — https://mara.nl/atomics/hardware.html
- `std::sync::atomic::Ordering` — https://doc.rust-lang.org/std/sync/atomic/enum.Ordering.html
- Portable SIMD / runtime dispatch (`std::simd`, `multiversion`) — https://doc.rust-lang.org/std/simd/index.html · https://docs.rs/multiversion/latest/multiversion/
- Rust Platform Support / target tiers — https://doc.rust-lang.org/rustc/platform-support.html
- Raspberry Pi 5 / BCM2712 (Cortex-A76) — https://www.raspberrypi.com/documentation/computers/processors.html
- The Rust Performance Book — build configuration — https://nnethercote.github.io/perf-book/build-configuration.html

## Verification, testing & benchmarking

- Jepsen / Elle (isolation anomaly checking) — https://jepsen.io/analyses/postgresql-12.3 · https://arxiv.org/pdf/2003.10554
- Deterministic Simulation Testing — https://antithesis.com/docs/resources/deterministic_simulation_testing/ · https://notes.eatonphil.com/2024-08-20-deterministic-simulation-testing.html · https://github.com/madsim-rs/madsim
- loom (exhaustive interleavings) / Miri — https://github.com/tokio-rs/loom · https://github.com/rust-lang/miri
- Property-based testing / fuzzing in Rust — https://github.com/BurntSushi/quickcheck · https://github.com/rust-fuzz/cargo-fuzz
- Criterion.rs / continuous benchmarking — https://bheisler.github.io/criterion.rs/book/ · https://bencher.dev/
- LDBC Social Network Benchmark — https://ldbcouncil.org/benchmarks/snb/ · https://arxiv.org/abs/2001.02299

## Reference graph databases (feature landscape)

- Neo4j (operations & Cypher manuals, GDS, APOC) — https://neo4j.com/docs/
- Memgraph — https://memgraph.com/docs/
- Amazon Neptune — https://aws.amazon.com/neptune/features/
- KùzuDB — https://github.com/kuzudb/kuzu
- FalkorDB / RedisGraph — https://docs.falkordb.com/
- ArangoDB — https://docs.arangodb.com/
- *Graph Databases* (Robinson, Webber, Eifrem) — https://graphdatabases.com/
