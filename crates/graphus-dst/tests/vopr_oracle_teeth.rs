//! The VOPR strong reference-model oracle must have teeth (rmp #238; mirrors the style of
//! `checker_teeth.rs`).
//!
//! An oracle that always passes is worse than none. This suite drives the **real engine** through the
//! committed workload ops, then deliberately perturbs either the shadow model or the engine and
//! asserts [`graphus_dst::assert_equivalent`] catches the divergence with the precise diff — and that
//! it passes (no false positive) when the two genuinely agree.
//!
//! The engine side is the same in-memory `LocalEngine` the VOPR loop runs, so the oracle is exercised
//! against genuine engine state, not a mock.

use graphus_core::capability::Clock;
use graphus_dst::vopr_oracle::OracleError;
use graphus_dst::{ShadowGraph, assert_equivalent};
use graphus_io::MemBlockDevice;
use graphus_server::engine::LocalEngine;
use graphus_server::engine::command::AccessMode;
use graphus_sim::SharedClock;
use graphus_wal::MemLogSink;
use std::sync::Arc;

use graphus_dst::mix::WorkloadOp;

type Eng = LocalEngine<MemBlockDevice, MemLogSink>;

/// A fresh in-memory engine over the simulated device + log.
fn engine() -> Eng {
    let clock = SharedClock::new(0);
    LocalEngine::in_memory(Arc::new(clock) as Arc<dyn Clock + Send + Sync>, 256)
        .expect("build in-memory engine")
}

/// Applies a committed op to BOTH the engine (auto-commit) and the model, keeping them in lockstep —
/// the same one-statement-transaction path the VOPR loop's auto-commit mode uses.
fn apply_both(eng: &mut Eng, model: &mut ShadowGraph, op: WorkloadOp) {
    let (stmt, params) = op.to_cypher();
    let mode = if op.is_write() {
        AccessMode::Write
    } else {
        AccessMode::Read
    };
    let ticket = eng.begin_auto_commit(mode).expect("begin");
    let mut reply = eng.run(ticket, stmt, params, true, None).expect("run");
    while reply.rows.next().expect("drain").is_some() {}
    model.apply(op);
}

/// A small, faithful committed graph: three persons (one duplicated id) and a couple of edges.
fn build(eng: &mut Eng) -> ShadowGraph {
    let mut model = ShadowGraph::new();
    apply_both(eng, &mut model, WorkloadOp::CreateNode { id: 0 });
    apply_both(eng, &mut model, WorkloadOp::CreateNode { id: 1 });
    apply_both(eng, &mut model, WorkloadOp::CreateNode { id: 2 });
    apply_both(eng, &mut model, WorkloadOp::CreateEdge { a: 0, b: 1 });
    apply_both(eng, &mut model, WorkloadOp::CreateEdge { a: 1, b: 2 });
    model
}

/// No false positives: the oracle passes on a faithful model.
#[test]
fn oracle_passes_on_faithful_model() {
    let mut eng = engine();
    let model = build(&mut eng);
    assert_eq!(
        assert_equivalent(&mut eng, &model),
        Ok(()),
        "the oracle must pass when model and engine agree cell-by-cell"
    );
    let _ = eng.shutdown();
}

/// Teeth: an injected EXTRA parallel edge in the model (the engine never made it) is caught, naming
/// the exact edge and the count divergence — the canonical "wrong result, right cardinality elsewhere"
/// failure the old count+hash oracle could miss.
#[test]
fn oracle_catches_an_injected_extra_edge() {
    let mut eng = engine();
    let mut model = build(&mut eng);
    // Perturb ONLY the model: claim a second (0,1) edge the engine never created.
    model.apply(WorkloadOp::CreateEdge { a: 0, b: 1 });
    assert_eq!(
        assert_equivalent(&mut eng, &model),
        Err(OracleError::EdgeMultisetMismatch {
            edge: (0, 1),
            model: 2,
            engine: 1,
        }),
        "an injected parallel edge must fail the oracle"
    );
    let _ = eng.shutdown();
}

/// Teeth: an injected MISSING edge — the engine has an edge the model dropped — is caught (the diff is
/// symmetric: `model: 0, engine: 1`).
#[test]
fn oracle_catches_a_missing_edge() {
    let mut eng = engine();
    let model = build(&mut eng);
    // Perturb the ENGINE: add a (2,0) edge the model does not know about.
    apply_both_engine_only(&mut eng, WorkloadOp::CreateEdge { a: 2, b: 0 });
    assert_eq!(
        assert_equivalent(&mut eng, &model),
        Err(OracleError::EdgeMultisetMismatch {
            edge: (2, 0),
            model: 0,
            engine: 1,
        }),
        "an edge present only in the engine must fail the oracle"
    );
    let _ = eng.shutdown();
}

/// Teeth: an injected phantom node in the model (an id the engine never created) is caught with the
/// exact id and multiplicities.
#[test]
fn oracle_catches_a_phantom_node() {
    let mut eng = engine();
    let mut model = build(&mut eng);
    model.apply(WorkloadOp::CreateNode { id: 99 }); // phantom: model only
    assert_eq!(
        assert_equivalent(&mut eng, &model),
        Err(OracleError::NodeMultisetMismatch {
            id: 99,
            model: 1,
            engine: 0,
        }),
        "a phantom node must fail the oracle"
    );
    let _ = eng.shutdown();
}

/// Teeth: a node the ENGINE has but the model dropped is caught (the engine-surplus direction).
#[test]
fn oracle_catches_a_dropped_node() {
    let mut eng = engine();
    let model = build(&mut eng);
    // Engine gains a node id=5 the model never recorded.
    apply_both_engine_only(&mut eng, WorkloadOp::CreateNode { id: 5 });
    assert_eq!(
        assert_equivalent(&mut eng, &model),
        Err(OracleError::NodeMultisetMismatch {
            id: 5,
            model: 0,
            engine: 1,
        }),
        "a node present only in the engine must fail the oracle"
    );
    let _ = eng.shutdown();
}

/// Regression (rmp #238): seed 4 reproduced an `EdgeMultisetMismatch { edge: (44,18), model:1,
/// engine:0 }` — an auto-commit `CREATE (44)-[:KNOWS]->(18)` whose post-stream COMMIT was SSI-aborted
/// (a dangerous structure with the concurrent open transactions) but reported a **silent success** to
/// the consumer, so the harness counted it as committed and the model recorded an edge the engine had
/// rolled back. The fix surfaces the auto-commit COMMIT failure to the consumer (a terminal stream
/// error), so a rolled-back auto-commit is no longer acknowledged. The full VOPR loop at seed 4 must
/// now run to completion with the reference-model oracle agreeing cell-by-cell.
#[test]
fn vopr_seed4_autocommit_abort_no_longer_diverges() {
    let report = graphus_dst::vopr::run(graphus_dst::vopr::VoprConfig::for_seed(4));
    assert!(
        report.oracle.is_none(),
        "seed 4 reference-model oracle must agree after the auto-commit-abort fix, got: {:?}",
        report.oracle
    );
    // Determinism: the same seed reproduces the identical report.
    let again = graphus_dst::vopr::run(graphus_dst::vopr::VoprConfig::for_seed(4));
    assert_eq!(
        report.trace_hash, again.trace_hash,
        "seed 4 must be deterministic (trace hash)"
    );
    assert_eq!(
        report.state_hash, again.state_hash,
        "seed 4 must be deterministic (state hash)"
    );
}

/// Applies a committed op to the engine **only** (not the model), to inject an engine-side surplus.
fn apply_both_engine_only(eng: &mut Eng, op: WorkloadOp) {
    let (stmt, params) = op.to_cypher();
    let mode = if op.is_write() {
        AccessMode::Write
    } else {
        AccessMode::Read
    };
    let ticket = eng.begin_auto_commit(mode).expect("begin");
    let mut reply = eng.run(ticket, stmt, params, true, None).expect("run");
    while reply.rows.next().expect("drain").is_some() {}
}
