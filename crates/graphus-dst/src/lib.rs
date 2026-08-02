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

pub mod catalog_rollback_undo;
pub mod checker;
pub mod cli;
pub mod count_txn_undo;
pub mod fault;
pub mod faults;
pub mod freelist_reuse;
pub mod harness;
pub mod index_refill_label_gate;
pub mod isolation;
pub mod label_rollback_clobber;
pub mod label_snapshot_visibility;
pub mod misbehave;
pub mod mix;
pub mod mode_b_batch_size_measurement;
pub mod model;
pub mod reader_store_growth;
pub mod rng;
pub mod rollback_undo_fault;
pub mod scenarios;
pub mod selfloop_churn;
pub mod spatial_build_uncommitted;
pub mod vector_build_uncommitted;
pub mod vopr;
pub mod vopr_fault;
pub mod vopr_fuzz;
pub mod vopr_oracle;
pub mod vopr_property;
pub mod vopr_repro;
pub mod wire;
pub mod workload;
pub mod zone_map_dirty_read;

pub use catalog_rollback_undo::{
    AOutcome, BEnding, CatalogRollbackReport, Crash, run_catalog_rollback_undo,
    run_checkpoint_excludes_pending_ddl, run_multi_holder_out_of_order_abort,
};
pub use checker::{CheckFailure, CheckResult, verify};
pub use cli::{CliConfig, run, summarize};
// The `rmp` #866 live-record-count undo scenarios (the counts-half twin of `catalog_rollback_undo`).
// They reuse that module's `Crash` enum, re-exported above, so a caller drives both with one type.
pub use count_txn_undo::{
    BystanderEnding, CheckpointFaultReport, CommitRecordFate, CountReport, Counters,
    StolenCheckpointReport, run_crash_between_checkpoint_and_commit_harden,
    run_io_error_at_catalog_checkpoint, run_stolen_pages_vs_checkpointed_counts,
};
pub use fault::{DeferredFault, FaultKind};
pub use freelist_reuse::{
    FreelistReuseCrashReport, FreelistReuseReport, Target as FreelistReuseTarget,
    run_freelist_reuse_after_rollback, run_freelist_reuse_crash,
};
pub use harness::{ScenarioReport, run_crash_scenario, run_scenario, run_with_fault};
// The `rmp` #904 scenarios: an index refill must gate node membership on the live-OR-retained label
// superset, so a rebuild run while a writer holds an uncommitted `REMOVE n:L` neither loses the
// committed row nor lets a live `IS UNIQUE` constraint admit a duplicate.
pub use index_refill_label_gate::{
    SeekReport, UniqueReport, run_seek_across_a_committed_relabel,
    run_seek_across_a_rolled_back_relabel, run_unique_across_a_rolled_back_relabel,
};
pub use model::{AckLedger, Model};
pub use rng::DetRng;
// The `rmp` #955 half-undone-transaction scenarios: a rollback or commit that fails part-way must
// leave a fully-formed OPEN writer, never a transaction that has vanished from the active set with
// its effects still on the page.
pub use rollback_undo_fault::{
    CommitFaultReport, GuardReport, RollbackFaultReport, WriterVisibility,
    run_bystander_survives_failed_rollback, run_failed_commit_publishes_no_registry_entry,
    run_guard_across_failed_commit, run_guard_across_failed_rollback,
    run_io_error_at_commit_of_a_label_writer, run_wal_sync_failure_during_rollback,
};
pub use selfloop_churn::{SelfLoopChurnReport, run_selfloop_churn_crash};
pub use spatial_build_uncommitted::{
    SpatialBuildReport, WriterEnding, run_spatial_build_uncommitted,
};
// `WriterEnding` is re-exported under a qualified name: the vector scenario declares its own enum,
// structurally identical to the spatial one above but a DISTINCT type. Re-exporting it bare would let
// the crate-root `WriterEnding` (spatial's) be passed to `run_vector_build_uncommitted`, which does not
// accept it — a confusing type error at the call site rather than at the definition.
pub use vector_build_uncommitted::{
    VectorBuildReport, WriterEnding as VectorWriterEnding, run_vector_build_uncommitted,
};
// The wire-level VOPR core (rmp #162). Its `run`/`summarize` are kept module-qualified (`vopr::run`)
// so they do not clash with the storage harness's crate-root `run`/`summarize`.
// The safety oracle bundle (rmp #239) and the liveness oracle (rmp #240) are re-exported by type; the
// runners `vopr::run_safety` / `vopr::run_safety_cli` / `vopr::run_liveness` / `vopr::run_liveness_cli`
// stay module-qualified beside `vopr::run` (avoiding the crate-root `run` clash).
pub use vopr::{
    LivenessFailure, LivenessReport, SafetyProperty, SafetyReport, SafetyViolation, VoprConfig,
    VoprReport,
};
pub use vopr_fault::{FaultBudget, FaultScheduler, VoprFaultKind};
// The continuous, time-budgeted, multi-core soak fuzzer (rmp #243). Module-qualified runners
// (`vopr_fuzz::fuzz` / `vopr_fuzz::sweep_range` / `vopr_fuzz::run_fuzz_cli`) stay beside the types.
pub use vopr_fuzz::{
    FuzzBudget, FuzzFailure, FuzzPredicate, FuzzReport, FuzzRun, SeedVerdict, SweepRange,
};
// The replay-artifact + deterministic shrinker tools (rmp #242). Module-qualified runners
// (`vopr_repro::run_repro_cli` / `vopr_repro::shrink` / `vopr_repro::replay_from_file`) stay beside the
// re-exported types.
pub use vopr_oracle::{
    OracleError, ShadowGraph, SurfacedFault, assert_equivalent, is_surfaced_injected_latent_fault,
};
pub use vopr_repro::{FailurePredicate, ReplayArtifact, ReplayMode, ReplayOutcome, ShrinkOutcome};
pub use workload::{Op, PlannedTxn, TxnOutcome, WorkloadConfig};
// The `rmp` #958 zone-map scenarios: a pruning structure may only prune, and the per-candidate re-check
// that turns its candidates into rows must run at the reader's snapshot. `WriterEnding` is re-exported
// under a qualified name for the same reason the vector scenario's is — it is a DISTINCT type from the
// spatial one, structurally identical, and re-exporting it bare would let the wrong one be passed.
pub use zone_map_dirty_read::{
    WriterEnding as ZoneWriterEnding, ZoneDirtyReadReport, ZoneRebuildReport, ZoneVsRow,
    run_zone_map_dirty_read, run_zone_rebuild_across_an_open_overwrite,
};
