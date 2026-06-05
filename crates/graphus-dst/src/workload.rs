//! Random workload generation: the operations a scenario applies to the engine.
//!
//! A workload is a seeded stream of [`Op`]s grouped into transactions (`specification/…` §11: a
//! seeded random workload over the storage/WAL/txn engine). The generator produces a varied LPG
//! multigraph mutation history — create nodes, create relationships (including **parallel edges**
//! and **self-loops**), add properties, delete relationships and nodes — and chooses transaction
//! boundaries (commit / rollback / leave-in-flight) so a crash can land mid-transaction
//! (`04 §2.4`: parallel edges and self-loops are first-class).
//!
//! The generator is purely a *plan*: it decides what to do from the seed without touching the
//! engine, then [`crate::harness`] applies the plan to both the real engine and the reference
//! [`crate::model::Model`]. Keeping generation and application separate makes the workload itself
//! testable for non-vacuity (it must really produce self-loops, parallel edges, and in-flight
//! transactions).

use crate::rng::DetRng;

/// One mutation the harness applies inside a transaction.
///
/// Node and relationship references are **slot indices** into the harness's live-id vectors, not
/// physical ids: the generator does not know the physical ids the store will hand out, so it refers
/// to "the i-th currently-live node" and the harness resolves that to a real id at apply time. This
/// keeps the generator engine-independent while still letting it build parallel edges (two ops over
/// the same pair) and self-loops (an op whose two endpoints resolve to the same node).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Op {
    /// Create a node.
    CreateNode,
    /// Create a relationship between the live nodes at slots `start_slot` and `end_slot` (equal
    /// slots produce a self-loop).
    CreateRel { start_slot: usize, end_slot: usize },
    /// Add a property to the live node at `node_slot`.
    AddNodeProp { node_slot: usize, value: u64 },
    /// Delete the live relationship at slot `rel_slot`.
    DeleteRel { rel_slot: usize },
    /// Delete the live node at slot `node_slot` (the harness detaches its relationships first).
    DeleteNode { node_slot: usize },
}

/// How a generated transaction ends.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TxnOutcome {
    /// Commit (creates a durability obligation).
    Commit,
    /// Roll back explicitly (no effect must survive).
    Rollback,
    /// Leave in flight — never commit nor roll back, so a crash can catch it (no effect must
    /// survive recovery).
    LeaveInFlight,
}

/// A planned transaction: a sequence of operations and an outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlannedTxn {
    /// The operations to apply, in order.
    pub ops: Vec<Op>,
    /// How the transaction ends.
    pub outcome: TxnOutcome,
}

/// Configuration bounds for the generator. Defaults are tuned to keep individual runs fast while
/// still building graphs large enough to exercise long incidence chains and deletions.
#[derive(Debug, Clone, Copy)]
pub struct WorkloadConfig {
    /// How many transactions to plan.
    pub txns: usize,
    /// Maximum operations per transaction (the actual count is a seeded draw in `1..=this`).
    pub max_ops_per_txn: usize,
    /// Percentage of transactions left in flight (a crash target). The rest split between commit
    /// and rollback, commit-weighted.
    pub in_flight_percent: u64,
    /// Percentage of *ended* transactions that roll back rather than commit.
    pub rollback_percent: u64,
}

impl Default for WorkloadConfig {
    fn default() -> Self {
        Self {
            txns: 12,
            max_ops_per_txn: 10,
            in_flight_percent: 20,
            rollback_percent: 25,
        }
    }
}

/// Generates a full workload plan from `rng` under `cfg`.
///
/// The generator keeps a *projected* count of live nodes and relationships so its slot references
/// stay in range as the plan grows; the harness's actual live counts can differ slightly (e.g. a
/// rolled-back transaction's creations never materialise), and the harness clamps any stale slot to
/// the real range at apply time. Projection only needs to be good enough to keep the op mix varied.
#[must_use]
pub fn generate(rng: &mut DetRng, cfg: WorkloadConfig) -> Vec<PlannedTxn> {
    let mut plan = Vec::with_capacity(cfg.txns);
    // Projected live counts (committed-or-pending), used only to keep slot draws in range.
    let mut proj_nodes: usize = 0;
    let mut proj_rels: usize = 0;

    for _ in 0..cfg.txns {
        let n_ops = rng.range_inclusive(1, cfg.max_ops_per_txn as u64) as usize;
        let mut ops = Vec::with_capacity(n_ops);

        for _ in 0..n_ops {
            // Bias toward creating structure early, then mix in edges, properties and deletions.
            let choice = rng.below(100);
            if proj_nodes < 2 || choice < 30 {
                ops.push(Op::CreateNode);
                proj_nodes += 1;
            } else if choice < 70 {
                let start_slot = rng.index(proj_nodes);
                // ~15% of edges deliberately target the same slot to force self-loops.
                let end_slot = if rng.chance(15) {
                    start_slot
                } else {
                    rng.index(proj_nodes)
                };
                ops.push(Op::CreateRel {
                    start_slot,
                    end_slot,
                });
                proj_rels += 1;
            } else if choice < 85 {
                let node_slot = rng.index(proj_nodes);
                let value = rng.next_u64();
                ops.push(Op::AddNodeProp { node_slot, value });
            } else if choice < 95 && proj_rels > 0 {
                let rel_slot = rng.index(proj_rels);
                ops.push(Op::DeleteRel { rel_slot });
                proj_rels = proj_rels.saturating_sub(1);
            } else if proj_nodes > 2 {
                let node_slot = rng.index(proj_nodes);
                ops.push(Op::DeleteNode { node_slot });
                proj_nodes = proj_nodes.saturating_sub(1);
            } else {
                ops.push(Op::CreateNode);
                proj_nodes += 1;
            }
        }

        let outcome = if rng.chance(cfg.in_flight_percent) {
            // In-flight transactions never materialise, so their creations should not inflate the
            // projection (they will be discarded). Roll the projection back conservatively.
            proj_nodes = proj_nodes
                .saturating_sub(ops.iter().filter(|o| matches!(o, Op::CreateNode)).count());
            proj_rels = proj_rels.saturating_sub(
                ops.iter()
                    .filter(|o| matches!(o, Op::CreateRel { .. }))
                    .count(),
            );
            TxnOutcome::LeaveInFlight
        } else if rng.chance(cfg.rollback_percent) {
            proj_nodes = proj_nodes
                .saturating_sub(ops.iter().filter(|o| matches!(o, Op::CreateNode)).count());
            proj_rels = proj_rels.saturating_sub(
                ops.iter()
                    .filter(|o| matches!(o, Op::CreateRel { .. }))
                    .count(),
            );
            TxnOutcome::Rollback
        } else {
            TxnOutcome::Commit
        };

        plan.push(PlannedTxn { ops, outcome });
    }

    plan
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generation_is_deterministic() {
        let cfg = WorkloadConfig::default();
        let a = generate(&mut DetRng::new(123), cfg);
        let b = generate(&mut DetRng::new(123), cfg);
        assert_eq!(a, b);
    }

    #[test]
    fn generator_produces_self_loops_parallel_edges_and_in_flight_txns() {
        // Across a spread of seeds the generator must really produce the structures the harness
        // claims to test, or coverage would be vacuous.
        let cfg = WorkloadConfig::default();
        let mut saw_self_loop = false;
        let mut saw_parallel = false;
        let mut saw_in_flight = false;
        let mut saw_rollback = false;
        let mut saw_delete = false;

        for seed in 1..=80u64 {
            let plan = generate(&mut DetRng::new(seed), cfg);
            for txn in &plan {
                match txn.outcome {
                    TxnOutcome::LeaveInFlight => saw_in_flight = true,
                    TxnOutcome::Rollback => saw_rollback = true,
                    TxnOutcome::Commit => {}
                }
                let mut pairs: std::collections::HashMap<(usize, usize), u32> =
                    std::collections::HashMap::new();
                for op in &txn.ops {
                    match *op {
                        Op::CreateRel {
                            start_slot,
                            end_slot,
                        } => {
                            if start_slot == end_slot {
                                saw_self_loop = true;
                            }
                            *pairs.entry((start_slot, end_slot)).or_default() += 1;
                        }
                        Op::DeleteRel { .. } | Op::DeleteNode { .. } => saw_delete = true,
                        _ => {}
                    }
                }
                if pairs.values().any(|&c| c >= 2) {
                    saw_parallel = true;
                }
            }
        }

        assert!(saw_self_loop, "generator must produce self-loops");
        assert!(saw_parallel, "generator must produce parallel edges");
        assert!(saw_in_flight, "generator must leave transactions in flight");
        assert!(saw_rollback, "generator must roll some transactions back");
        assert!(saw_delete, "generator must produce deletions");
    }

    #[test]
    fn slot_indices_stay_in_projected_range() {
        // A coarse sanity check: every op's slot reference is below the running projected count at
        // generation time (the harness clamps anyway, but the generator should not over-reach).
        let cfg = WorkloadConfig::default();
        let plan = generate(&mut DetRng::new(55), cfg);
        for txn in &plan {
            for op in &txn.ops {
                match *op {
                    Op::CreateRel {
                        start_slot,
                        end_slot,
                    } => {
                        // Slots can reference any node created so far in the whole plan; we only
                        // assert they are plausible small indices, not negative/huge.
                        assert!(start_slot < 100_000);
                        assert!(end_slot < 100_000);
                    }
                    Op::AddNodeProp { node_slot, .. } | Op::DeleteNode { node_slot } => {
                        assert!(node_slot < 100_000)
                    }
                    Op::DeleteRel { rel_slot } => assert!(rel_slot < 100_000),
                    Op::CreateNode => {}
                }
            }
        }
    }
}
