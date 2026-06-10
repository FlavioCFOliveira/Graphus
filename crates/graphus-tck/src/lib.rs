//! The openCypher **Technology Compatibility Kit (TCK)** harness for Graphus.
//!
//! This crate is a *measurement instrument*, not a feature of the database. It discovers the
//! vendored, pinned openCypher feature corpus under `tck/features/**` (220 `.feature` files), runs
//! every scenario through the **real** Graphus Cypher engine
//! (`parse → analyze → lower → plan → bind → execute`, driven over the production
//! [`TxnCoordinator`](graphus_cypher::TxnCoordinator) seam onto the real persistent record store),
//! and compares the result against the scenario's embedded expectation using the **same**
//! value-model semantics the engine ships ([`equivalent`](graphus_cypher::equivalent)). The output
//! is a faithful conformance pass-rate plus a per-category breakdown — and a no-regression ratchet
//! (`tests/tck.rs`).
//!
//! # Why the engine's own comparison code
//!
//! `CLAUDE.md` is categorical: *measure to decide*, *never guess*, *never reinvent the value
//! semantics*. A TCK that re-implemented Cypher equivalence/ordering would be measuring its own
//! re-implementation, not the engine. So the harness builds each expected cell into a
//! [`graphus_core::Value`] where it maps cleanly and asserts the engine's
//! [`equivalent`](graphus_cypher::equivalent) against the value the engine actually produced;
//! structural elements (nodes / relationships / paths), which have no `Value` form, are matched
//! structurally (labels/type as a set, properties as a map, path shape per step) — the only honest
//! option since the core does not yet carry the structural [`Value`](graphus_core::Value) variants
//! (`graphus_cypher::runtime` documents that deferral).
//!
//! # Module map
//!
//! - [`value`] — the TCK expected-result mini-language parser (`tck/README.adoc`
//!   §"Format of the expected results"): turns a table cell such as `(:L {p: 1})` or
//!   `<(:A)-[:T]->(:B)>` into an [`ExpectedValue`] tree.
//! - [`compare`] — matches an [`ExpectedValue`] against a concrete result cell resolved from the
//!   engine, and decides result-set assertions (ordered / bag / empty).
//! - [`feature`] — the Gherkin model: parse a `.feature` file via the `gherkin` crate, **expand**
//!   `Scenario Outline` / `Examples` into concrete scenarios (the crate does not auto-expand), and
//!   classify each step into the TCK step vocabulary.
//! - [`runner`] — runs one scenario end-to-end over a fresh
//!   [`TxnCoordinator`](graphus_cypher::TxnCoordinator), isolated in
//!   [`std::panic::catch_unwind`], and yields an [`Outcome`].
//! - [`report`] — aggregates outcomes into a printable summary with a per-top-level-category
//!   breakdown and the ratchet line.
//! - [`graphs`] — loads the TCK named graphs (`binary-tree-1`, `binary-tree-2`, `yago`) from
//!   `tck/graphs/**` as their seed Cypher.
#![forbid(unsafe_code)]

pub mod compare;
pub mod feature;
pub mod graphs;
pub mod procedures;
pub mod report;
pub mod runner;
pub mod value;

pub use feature::{Scenario, Step, StepKind, load_feature, load_feature_str};
pub use report::{CategoryStats, Report};
pub use runner::{Outcome, run_scenario};
pub use value::{ExpectedValue, parse_expected};

/// The absolute path to the vendored TCK corpus root (`crates/graphus-tck/tck`).
///
/// Resolved from `CARGO_MANIFEST_DIR` so it is correct regardless of the working directory a test
/// runner uses (`CLAUDE.md`: agent threads reset cwd between calls; tests must use absolute paths).
#[must_use]
pub fn tck_root() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tck")
}
