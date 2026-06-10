//! `graphus-bench` — Criterion micro-benchmarks and the LDBC-SNB-flavoured macro harness for Graphus.
//!
//! ## Two kinds of measurement live here
//!
//! 1. **Criterion micro-benchmarks** (in `benches/`) isolate one path each. The storage/WAL/IO
//!    crates they drive are `[dev-dependencies]`, and because a crate's own `src/` cannot see its
//!    dev-dependencies, those benchmarks' shared *fixtures* live in `benches/common.rs` (included by
//!    each target via a `#[path]` module), not in this `src/`:
//!    - `benches/commit_path.rs` — the transactional commit path (SPIKE #8 / `04 §9.1`, §12 item 8):
//!      throughput and per-commit tail latency of the single-log-shard + group-commit write path,
//!      swept over WAL-volume-per-commit to characterize the log-tail serialization point.
//!    - `benches/read_path.rs` — the lock-free read side (traversal / scan) for contrast.
//!
//!    A small **regression gate** (`src/bin/bench_gate.rs`) measures representative slices of these
//!    paths against a committed baseline (`baseline.toml`) and fails CI on a regression beyond a
//!    documented threshold. See `crates/graphus-bench/RESULTS.md` for the recorded numbers.
//!
//! 2. **The LDBC-SNB macro harness** ([`ldbc`]) runs a whole social-network workload through the
//!    *real* engine pipeline (`TxnCoordinator` over a `RecordStore`) and reports end-to-end
//!    throughput/latency. Unlike the Criterion benches, this harness lives in `src/` so it is a
//!    first-class, testable library component; that is why the engine crates it drives
//!    (`graphus-cypher`, `graphus-txn`, `graphus-storage`, …) are **normal** dependencies of this
//!    crate. `graphus-bench` is an internal, unpublished benchmark crate (a workspace leaf nothing
//!    depends on), so a broad normal-dependency surface costs nothing. Run it via
//!    `cargo run -p graphus-bench --bin ldbc_snb`. See `crates/graphus-bench/LDBC.md`.

#![forbid(unsafe_code)]

pub mod ldbc;
