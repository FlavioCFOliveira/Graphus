//! `graphus-bench` — Criterion micro-benchmarks and LDBC SNB macro harness for Graphus.
//!
//! The crate is intentionally a **thin lib**: the storage/WAL/IO crates that the benchmarks drive
//! are `[dev-dependencies]` (so the published library surface stays minimal and the heavy engine
//! crates are not normal dependencies of `graphus-bench`). Because a crate's own `src/` cannot see
//! its dev-dependencies, the benchmark *fixtures* live in `benches/common.rs` and are shared by the
//! benchmark targets via a `#[path]` module include — not here.
//!
//! The measurements themselves are in `benches/`:
//!
//! - `benches/commit_path.rs` — the transactional commit path (SPIKE #8 / `04 §9.1`, §12 item 8):
//!   throughput and per-commit tail latency of the single-log-shard + group-commit write path,
//!   swept over WAL-volume-per-commit to characterize the log-tail serialization point.
//! - `benches/read_path.rs` — the lock-free read side (traversal / scan) for contrast.
//!
//! See `crates/graphus-bench/RESULTS.md` for the recorded numbers and the SPIKE #8 recommendation.

#![forbid(unsafe_code)]
