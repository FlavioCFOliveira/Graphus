# Graphus

Graphus is a **Label Property Graph (LPG) database server** written in Rust, designed to
operate exemplarily under extreme load and concurrency. It is built to be **100% ACID
compliant** and **100% Cypher TCK compliant**, with a **multigraph** model by default.

It exposes three connection interfaces — **Bolt over UDS**, **Bolt over TCP** (`bolt://`),
and a **Web REST API** — and targets Linux, macOS, and Raspberry Pi OS on x86_64 and
aarch64 (including Apple Silicon and Raspberry Pi 5+).

## Status

Early development. The **specification** is complete (see [`specification/`](specification/)):
a global needs survey, 24 ratified design decisions, the technical design, and the pinned
openCypher `2024.3` TCK target. Phase 1 (the single-node correctness core) is planned in the
`rmp` roadmap `graphus`; the workspace is scaffolded below.

## Repository layout

| Path | Contents |
| --- | --- |
| `specification/` | The functional + technical specification (the single source of truth for *what* and *how*). |
| `crates/` | The Cargo workspace (see below). |
| `CLAUDE.md` | Operating instructions for the AI agent working on the project. |

## Workspace

A single Cargo workspace (Rust edition 2024). Crates follow the layered architecture in
`specification/04-technical-design.md`:

| Crate | Responsibility |
| --- | --- |
| `graphus-core` | Shared IDs, the Cypher value model, errors, capability traits, constants. |
| `graphus-sim` | Deterministic + production capability implementations for DST. |
| `graphus-io` | Async file/socket I/O (epoll/kqueue + optional io_uring); fsync threads. |
| `graphus-wal` | ARIES write-ahead log, group commit, checkpoints, recovery. |
| `graphus-bufpool` | Self-managed buffer pool, page format, checksums. |
| `graphus-storage` | Record store with index-free adjacency, tokens, element-ID map. |
| `graphus-index` | B+-tree, token-lookup, composite and relationship-property indexes; constraints. |
| `graphus-txn` | MVCC + Serializable Snapshot Isolation transaction manager. |
| `graphus-cypher` | Cypher parse → plan → execute pipeline (targets 100% TCK). |
| `graphus-bolt` | Bolt protocol + PackStream over UDS and TCP. |
| `graphus-rest` | HTTP transactional API (typed JSON / CBOR, NDJSON streaming). |
| `graphus-auth` | Peer-credential, JWT/Bearer auth and RBAC, shared across listeners. |
| `graphus-server` | The server process: wiring, admission control, observability. |
| `graphus-cli` | Interactive shell and admin client. |
| `graphus-tck` | openCypher TCK harness. |
| `graphus-dst` | Deterministic simulation scenarios and fault injection. |
| `graphus-bench` | Criterion micro-benchmarks and the LDBC SNB macro harness. |
| `graphus-elle` | Isolation-anomaly (Elle/Jepsen-style) checking. |

## Building

```sh
cargo build
cargo test
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
```

## License

See [`LICENSE`](LICENSE).
