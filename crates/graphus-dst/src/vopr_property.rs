//! `vopr_property` — the **property-value + secondary-index oracle** driver (rmp #461).
//!
//! The default contended VOPR workload ([`crate::mix::WorkloadGen`]) issues only four ops
//! (`CreateNode`/`CreateEdge`/`CountNodes`/`Neighbors`), so the strong reference-model oracle
//! ([`crate::vopr_oracle`]) certifies only **structural** Person/KNOWS multiset equivalence. It is
//! blind to two classes a concurrency bug can corrupt:
//!
//! 1. a **wrong property value** on a surviving node (e.g. an SSI rollback restoring a stale `rank`
//!    pre-image over a committed `SET`), and
//! 2. a **secondary-index-vs-base-store divergence** (a stale or missing index entry — the surface of
//!    rmp #313 / #316), because no index is ever **built or queried** under the contended path.
//!
//! This module closes both gaps with a self-contained, deterministic driver that:
//!
//! - declares a real `(Person, rank)` secondary index up front (on the empty graph, so it promotes to
//!   `Online` immediately and is then maintained incrementally by every later `CREATE`/`SET`/
//!   `DELETE`);
//! - drives **overlapping explicit transactions** that `CREATE` nodes, `SET` their `rank`, create
//!   `:KNOWS` edges, and `DETACH DELETE` nodes — the extended [`WorkloadOp`] vocabulary (rmp #461);
//! - mirrors every committed transaction in the extended [`ShadowGraph`] (which now tracks `rank` per
//!   id and cascades deletes); and
//! - on every commit runs [`assert_equivalent`], whose step 5 (rmp #461) now cross-checks **property
//!   values** and an **indexed-seek-vs-full-scan** consistency probe against the model.
//!
//! It is **not** wired into the `vopr` interleaver's RNG draw path, so the seed-replay determinism
//! gate stays byte-identical (the default workload's draw arithmetic is untouched — see
//! [`crate::mix::WorkloadOp`]). It is its own pure `fn(seed) -> ScenarioOutcome`, exposed through the
//! [`crate::scenarios`] catalogue and swept in CI.

use std::sync::Arc;

// `Value` is only needed by the test-only `auto_commit` helper and the teeth tests; gating the import
// keeps the non-test build warning-free.
#[cfg(test)]
use graphus_core::Value;
use graphus_io::MemBlockDevice;
use graphus_server::engine::LocalEngine;
use graphus_server::engine::command::AccessMode;
use graphus_sim::{SharedClock, SimRng};
use graphus_wal::MemLogSink;

use crate::mix::WorkloadOp;
use crate::vopr_oracle::{ShadowGraph, assert_equivalent};

/// The simulated engine type (must match [`crate::vopr`]'s alias).
type Eng = LocalEngine<MemBlockDevice, MemLogSink>;

/// The outcome of one property/index oracle run at one seed (mirrors
/// [`crate::scenarios::ScenarioOutcome`] shape without depending on it).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PropertyOracleOutcome {
    /// Whether the property/index oracle held for every commit in the run.
    pub ok: bool,
    /// A short, reproducible detail line (the first divergence, or a pass summary).
    pub detail: String,
}

impl PropertyOracleOutcome {
    fn pass(detail: impl Into<String>) -> Self {
        Self {
            ok: true,
            detail: detail.into(),
        }
    }
    fn fail(detail: impl Into<String>) -> Self {
        Self {
            ok: false,
            detail: detail.into(),
        }
    }
}

/// Builds the in-memory simulated engine with a generously sized pool (the property workload is small
/// and must stay RAM-resident so the run is a pure function of the seed).
fn engine() -> Eng {
    LocalEngine::in_memory(Arc::new(SharedClock::new(0)), 512).expect("engine")
}

/// Declares the `(Person, rank)` secondary index on the (empty) graph. `LocalEngine` drives the
/// non-blocking build to completion **after** the DDL command (its `drain_index_builds`), so with an
/// empty snapshot the index is `Online` immediately; from then on it is maintained incrementally by
/// every `CREATE`/`SET`/`DELETE` — exactly the index that the consistency check cross-references
/// against a full scan. Issued through the engine's index-DDL command path (the Cypher executor does
/// not parse `CREATE INDEX`; that is an engine/catalog command).
fn declare_rank_index(eng: &mut Eng) -> bool {
    eng.index_ddl(
        graphus_server::engine::IndexCommand::CreateNodePropertyIndex {
            label: "Person".to_owned(),
            property: "rank".to_owned(),
        },
    )
    .is_ok()
}

/// Runs an auto-commit **write** statement to completion, returning whether it committed. (The
/// property workload's auto-commit statements — `CREATE`, `SET`, `DETACH DELETE` — are all writes; the
/// oracle's read-backs run through their own read transactions in [`crate::vopr_oracle`].) Used by the
/// teeth tests to set up engine state in lockstep with the model.
#[cfg(test)]
fn auto_commit(eng: &mut Eng, stmt: &str, params: Vec<(String, Value)>) -> bool {
    let Ok(ticket) = eng.begin_auto_commit(AccessMode::Write) else {
        return false;
    };
    match eng.run(ticket, stmt, params, true, None) {
        Ok(mut reply) => {
            while let Ok(Some(_)) = reply.rows.next() {}
            true
        }
        Err(_) => false,
    }
}

/// Runs `op` inside an already-open explicit transaction `ticket`, returning whether the statement
/// succeeded (so the caller stages it only on success — mirroring the `vopr` interleaver's contract).
fn run_in(eng: &mut Eng, ticket: graphus_server::engine::TxTicket, op: WorkloadOp) -> bool {
    let (stmt, params) = op.to_cypher();
    match eng.run(ticket, stmt, params, false, None) {
        Ok(mut reply) => {
            while let Ok(Some(_)) = reply.rows.next() {}
            true
        }
        Err(_) => false,
    }
}

/// One scripted explicit transaction: a small list of ops committed (or rolled back) as a unit. The
/// driver stages a transaction's ops in the model and flushes them via
/// [`ShadowGraph::commit_transaction`] **only** on a successful commit.
struct Txn {
    ops: Vec<WorkloadOp>,
    rollback: bool,
}

/// Generates a deterministic, contended property/index workload from `seed`: a seed of `CREATE`s, then
/// a mix of `SET rank`, `CREATE edge`, and `DETACH DELETE` over a small id space, organised into
/// **overlapping** explicit transactions (so their lifetimes interleave, exactly the
/// commutative-overlap shape the rest of the VOPR battery uses — see
/// [`crate::vopr_oracle::ShadowGraph::commit_transaction`]).
///
/// Each transaction keeps every id it touches at multiplicity ≤ 1 (one node per id), so the SET/DELETE
/// semantics are unambiguous and the property/index read-back is exact. The mix is bounded small to
/// stay fast in a debug build while still exercising SET-over-existing, edge creation, and delete
/// churn under interleaving.
fn workload(seed: u64) -> Vec<Txn> {
    let mut rng = SimRng::new(seed);
    const IDS: i64 = 12;
    let mut txns = Vec::new();

    // Phase 1: create the id space (one node per id), each its own committed transaction.
    for id in 0..IDS {
        txns.push(Txn {
            ops: vec![WorkloadOp::CreateNode { id }],
            rollback: false,
        });
    }

    // Phase 2: a bounded mix of writes. Each transaction batches 1–3 ops and either commits or rolls
    // back (a rolled-back SET must NOT change the committed rank — the property-rollback case).
    let rounds = 24u32;
    for _ in 0..rounds {
        let n_ops = rng.range_inclusive(1, 3) as usize;
        let mut ops = Vec::with_capacity(n_ops);
        for _ in 0..n_ops {
            let id = rng.below(IDS as u64) as i64;
            match rng.below(4) {
                // SET the rank of an existing id to a small bounded value.
                0 | 1 => {
                    let val = rng.below(5) as i64;
                    ops.push(WorkloadOp::SetProperty { id, val });
                }
                // Create a KNOWS edge to another id.
                2 => {
                    let b = rng.below(IDS as u64) as i64;
                    ops.push(WorkloadOp::CreateEdge { a: id, b });
                }
                // Delete an id (and recreate it next time it is SET — the workload tolerates a missing
                // id: a SET/edge against an absent id simply matches nothing, in both engine and model).
                _ => {
                    ops.push(WorkloadOp::DeleteNode { id });
                }
            }
        }
        // ~1 in 4 transactions rolls back, so a staged SET/DELETE that is rolled back must leave the
        // committed model (and the index) unchanged — the rollback-isolation property.
        let rollback = rng.chance(250);
        txns.push(Txn { ops, rollback });
    }

    txns
}

/// Drives the property/index oracle workload for `seed` and checks the extended oracle on **every**
/// commit (rmp #461). Returns the first divergence, or a pass summary.
///
/// The check on each commit is [`assert_equivalent`], whose step 5 now verifies, in addition to the
/// node/edge multisets and counts: each id's `rank` property value, the indexed `rank` seek against
/// the model, and the indexed seek against a forced full scan (index-vs-base-store).
#[must_use]
pub fn run(seed: u64) -> PropertyOracleOutcome {
    let mut eng = engine();
    if !declare_rank_index(&mut eng) {
        return PropertyOracleOutcome::fail("declaring the (Person, rank) index failed");
    }

    let mut model = ShadowGraph::new();
    let txns = workload(seed);

    for (i, txn) in txns.into_iter().enumerate() {
        let Ok(ticket) = eng.begin(AccessMode::Write) else {
            return PropertyOracleOutcome::fail(format!("begin txn {i} failed"));
        };
        // Capture the begin-snapshot for the model's MVCC-faithful commit, then run + stage each op.
        let snapshot = model.node_snapshot();
        let mut staged = Vec::with_capacity(txn.ops.len());
        for op in &txn.ops {
            if run_in(&mut eng, ticket, *op) {
                staged.push(*op);
            }
        }
        if txn.rollback {
            let _ = eng.rollback(ticket);
            // Discard: the staged ops never became durable.
        } else if eng.commit(ticket).is_ok() {
            // Flush the committed ops into the model under snapshot-isolation semantics.
            model.commit_transaction(&snapshot, &staged);
            // The whole point: cross-check property values + index-vs-scan on every commit.
            if let Err(e) = assert_equivalent(&mut eng, &model) {
                return PropertyOracleOutcome::fail(format!("commit {i}: {e:?}"));
            }
        }
        // A failed commit (e.g. SSI abort) applies nothing — the model is left untouched, matching the
        // engine. (The property workload's transactions are commutative at commit, so a real engine
        // commits all of them; an abort would simply leave the model correct for what did commit.)
    }

    PropertyOracleOutcome::pass("property + index-vs-scan consistent on every commit")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::vopr_oracle::OracleError;

    /// The property/index oracle holds across a seed sweep, and replays identically per seed
    /// (determinism). This is the live regression gate: a real property-value or index divergence under
    /// the contended SET/DELETE workload makes some seed fail here.
    #[test]
    fn property_index_oracle_holds_across_seeds() {
        for seed in 1u64..=16 {
            let a = run(seed);
            let b = run(seed);
            assert_eq!(
                a, b,
                "property oracle must replay identically for seed {seed}"
            );
            assert!(
                a.ok,
                "engine must keep property + index consistent at seed {seed}: {}",
                a.detail
            );
        }
    }

    /// The workload actually exercises SET + DELETE (non-vacuous): otherwise the new oracle checks
    /// would never run and the "regression gate" would be empty.
    #[test]
    fn workload_exercises_set_and_delete() {
        let txns = workload(7);
        let mut sets = 0;
        let mut deletes = 0;
        for t in &txns {
            for op in &t.ops {
                match op {
                    WorkloadOp::SetProperty { .. } => sets += 1,
                    WorkloadOp::DeleteNode { .. } => deletes += 1,
                    _ => {}
                }
            }
        }
        assert!(sets > 0, "the property workload must issue SET ops");
        assert!(deletes > 0, "the property workload must issue DELETE ops");
    }

    /// **Teeth (property value).** The oracle catches a wrong `rank` value: we drive a node, `SET` its
    /// rank in the engine to one value, but record a **different** value in the model, and assert the
    /// oracle fires a [`OracleError::PropertyMismatch`] naming the exact id and the two values. This is
    /// the class the structural multiset check is blind to — proving step 5 has teeth.
    #[test]
    fn oracle_catches_a_seeded_property_divergence() {
        let mut eng = engine();
        assert!(declare_rank_index(&mut eng), "declare index");

        let mut model = ShadowGraph::new();
        // Create id=3 and set its engine rank to 9.
        assert!(auto_commit(&mut eng, "CREATE (:Person {id: 3})", vec![]));
        model.apply(WorkloadOp::CreateNode { id: 3 });
        assert!(auto_commit(
            &mut eng,
            "MATCH (n:Person {id: 3}) SET n.rank = 9",
            vec![]
        ));
        // Record a DIFFERENT rank in the model (the "bug": a stale pre-image survived).
        model.apply(WorkloadOp::SetProperty { id: 3, val: 7 });

        let err = assert_equivalent(&mut eng, &model).expect_err("must diverge on the wrong rank");
        assert_eq!(
            err,
            OracleError::PropertyMismatch {
                id: 3,
                model_rank: Some(7),
                engine_rank: Some(9),
            },
            "the oracle must name the exact id and the model-vs-engine rank"
        );
        let _ = eng.shutdown();
    }

    /// **Teeth (delete).** The oracle catches a stale node the engine deleted but the model still
    /// believes lives — and vice versa. Here we delete id=2 in the engine but NOT in the model; the
    /// node-multiset check fires (the model claims a node the engine no longer has), proving the delete
    /// path is genuinely cross-checked.
    #[test]
    fn oracle_catches_a_missed_delete() {
        let mut eng = engine();
        assert!(declare_rank_index(&mut eng), "declare index");
        let mut model = ShadowGraph::new();
        for id in [1i64, 2, 3] {
            assert!(auto_commit(
                &mut eng,
                "CREATE (:Person {id: $id})",
                vec![("id".to_owned(), Value::Integer(id))]
            ));
            model.apply(WorkloadOp::CreateNode { id });
        }
        // Delete id=2 in the engine only.
        assert!(auto_commit(
            &mut eng,
            "MATCH (n:Person {id: 2}) DETACH DELETE n",
            vec![]
        ));
        let err =
            assert_equivalent(&mut eng, &model).expect_err("must diverge on the missed delete");
        assert_eq!(
            err,
            OracleError::NodeMultisetMismatch {
                id: 2,
                model: 1,
                engine: 0,
            },
            "the oracle must catch a node the model kept but the engine deleted"
        );
        let _ = eng.shutdown();
    }
}
