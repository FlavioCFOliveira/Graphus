//! `graphus-dst` — the **Deterministic Simulation Testing** harness for Graphus
//! (`specification/04-technical-design.md` §11; decision `D-dst-investment`).
//!
//! This crate drives the storage / WAL / transaction engine under seeded random workloads and
//! **fault injection**, then proves the two inviolable durability guarantees empirically (CLAUDE.md:
//! 100% ACID; `04 §11.1`: "crash-consistency of ARIES recovery … no acknowledged commit lost …
//! absence of torn-page corruption"). Everything is reproducible from a seed: same seed ⇒ identical
//! workload, identical fault schedule, identical recovered state, identical pass/fail.
//!
//! ## Modules
//!
//! - [`rng`] — deterministic random primitives over the project's [`graphus_sim::SimRng`].
//! - [`model`] — the independent reference model of the committed graph and the
//!   acknowledged-commit ledger (the durability obligations).
//! - [`workload`] — seeded generation of random transactions (create/relate/property/delete,
//!   including parallel edges and self-loops), with commit / rollback / leave-in-flight outcomes.
//! - [`fault`] — the fault schedule and an honest catalogue of exercised vs deferred faults.
//! - [`checker`] — verification of the four invariants (durability, atomicity, integrity,
//!   determinism) against a recovered store, written to *have teeth*.
//! - [`harness`] — the driver that ties it together: build engine → apply workload → inject fault →
//!   recover → verify.
//! - [`cli`] — the dependency-light command-line runner and the deterministic run summary.
//!
//! ## The four invariants (checked after every fault + recovery)
//!
//! 1. **Durability** — every transaction whose `commit()` returned `Ok` is fully present and
//!    correct after recovery.
//! 2. **Atomicity (committed-or-nothing)** — no partial effect of an un-acknowledged, in-flight, or
//!    rolled-back transaction survives.
//! 3. **Integrity** — the recovered graph is internally consistent: adjacency chains well-formed,
//!    incidence sets match degrees, no dangling/dead relationship ids, page checksums valid.
//! 4. **Determinism** — running the same seed twice yields identical recovered state and identical
//!    pass/fail.
//!
//! See [`fault`] for the precise, audited list of which fault types are actually exercised and which
//! are deferred (with reasons) — the project forbids claiming coverage it does not have.
#![forbid(unsafe_code)]

pub mod checker;
pub mod cli;
pub mod fault;
pub mod harness;
pub mod mix;
pub mod model;
pub mod rng;
pub mod vopr;
pub mod wire;
pub mod workload;

pub use checker::{CheckFailure, CheckResult, verify};
pub use cli::{CliConfig, run, summarize};
pub use fault::{DeferredFault, FaultKind};
pub use harness::{ScenarioReport, run_crash_scenario, run_scenario, run_with_fault};
pub use model::{AckLedger, Model};
pub use rng::DetRng;
// The wire-level VOPR core (rmp #162). Its `run`/`summarize` are kept module-qualified (`vopr::run`)
// so they do not clash with the storage harness's crate-root `run`/`summarize`.
pub use vopr::{VoprConfig, VoprReport};
pub use workload::{Op, PlannedTxn, TxnOutcome, WorkloadConfig};
