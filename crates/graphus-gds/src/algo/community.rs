//! Community detection via Label Propagation (LPA).
//!
//! Each node adopts the label most frequent among its neighbours; ties are broken
//! **deterministically** by choosing the smallest candidate label, which makes the algorithm
//! reproducible (the classic LPA breaks ties at random, sacrificing determinism). Iteration is
//! capped and convergence is detected when a full sweep changes no label.
//!
//! Labels are seeded from each node's own internal id, so the final labels are canonical-ish (a
//! community is named by one of its members' ids). The algorithm is treated as **undirected** for
//! the purpose of "neighbours" — it folds the projection into simple undirected adjacency.
//!
//! # Two sweep variants (`rmp` #342 / #559)
//!
//! LPA's sweep can read *either* the labels updated so far in the current sweep, *or* only the labels
//! from the end of the previous sweep. That choice is the crux of parallelising it:
//!
//! - **Sequential (default) — semi-synchronous.** Nodes are visited in ascending id order and update
//!   `label` **in place**, so a node sees the just-updated labels of earlier nodes. This is inherently
//!   order-dependent (node `i` depends on nodes `0..i`), hence irreducibly sequential, but it
//!   typically converges in fewer sweeps.
//! - **Parallel — synchronous.** Every node in a sweep reads the **previous** sweep's labels and all
//!   write the next sweep's labels; the nodes of a sweep are therefore independent and fan out across
//!   cores. It is deterministic (same result every run, on any pool width), but is a *distinct
//!   algorithm*: on some graphs (e.g. bipartite) it can oscillate with period two, so it relies on
//!   `max_iter` to terminate, and its labelling may differ from the semi-synchronous one. Both
//!   labellings are valid community assignments.
//!
//! Because the two variants are genuinely different algorithms, their outputs are **not** required to
//! be bit-identical (unlike the other GDS algorithms, where parallel == sequential). Each is
//! internally deterministic; the [`Execution`] knob selects between them.

use crate::cancel::Cancel;
use crate::csr::{CsrGraph, InternalId, SimpleUndirectedCsr};
use crate::error::{GdsError, Result};
use crate::execution::Execution;
use std::collections::HashMap;

/// Configuration for [`label_propagation`].
#[derive(Debug, Clone, Copy)]
pub struct LabelPropagationConfig {
    /// Maximum number of sweeps over all nodes.
    pub max_iter: u32,
}

impl Default for LabelPropagationConfig {
    fn default() -> Self {
        Self { max_iter: 100 }
    }
}

/// The result of label propagation.
#[derive(Debug, Clone)]
pub struct CommunityResult {
    /// `label[i]` = community label of node `i` (an internal id of some community member).
    pub label: Vec<InternalId>,
    /// Number of distinct communities.
    pub count: usize,
    /// Sweeps performed.
    pub iterations: u32,
    /// Whether a stable labelling was reached before `max_iter`.
    pub converged: bool,
}

/// Runs deterministic Label Propagation with the default [`Execution`].
///
/// A thin wrapper over [`label_propagation_with`].
///
/// # Errors
/// See [`label_propagation_with`].
pub fn label_propagation(
    graph: &CsrGraph,
    config: LabelPropagationConfig,
    cancel: &Cancel<'_>,
) -> Result<CommunityResult> {
    label_propagation_with(graph, config, Execution::default(), cancel)
}

/// Runs deterministic Label Propagation with an explicit [`Execution`] knob.
///
/// [`Execution::sequential`] runs the semi-synchronous sweep; [`Execution::parallel`] runs the
/// synchronous sweep across cores (see the module docs for why these are distinct, each-deterministic
/// variants).
///
/// # Complexity
/// Time `O(k · (n + m))` for `k` sweeps (each sweep visits every node and its neighbours once), space
/// `O(n + m)`. Self-loops and parallel edges are folded away by the simple-adjacency step.
///
/// # Errors
/// - [`GdsError::InvalidArgument`] if `max_iter` is zero.
/// - [`GdsError::Cancelled`] if `cancel` fires (checked per sweep).
pub fn label_propagation_with(
    graph: &CsrGraph,
    config: LabelPropagationConfig,
    exec: Execution,
    cancel: &Cancel<'_>,
) -> Result<CommunityResult> {
    if config.max_iter == 0 {
        return Err(GdsError::InvalidArgument("max_iter must be >= 1".into()));
    }
    let n = graph.node_count();
    if n == 0 {
        return Ok(CommunityResult {
            label: Vec::new(),
            count: 0,
            iterations: 0,
            converged: true,
        });
    }

    // Shared, built-once flat-CSR simple-undirected adjacency (`rmp` #379): deduplicated, self-loop
    // free, each run sorted ascending — the same set semantics LPA needs for neighbour tallies, and
    // reused (not rebuilt) if `triangle_count` already ran over this projection.
    let adj = graph.simple_undirected_csr();

    let (label, iterations, converged) = if exec.is_parallel(n) {
        run_synchronous(adj, n, config.max_iter, cancel)?
    } else {
        run_semi_synchronous(adj, n, config.max_iter, cancel)?
    };

    // Count distinct labels.
    let distinct: std::collections::HashSet<InternalId> = label.iter().copied().collect();

    Ok(CommunityResult {
        label,
        count: distinct.len(),
        iterations,
        converged,
    })
}

/// Semi-synchronous sweeps: ascending visitation with in-place updates (the classic, sequential
/// default). Returns `(labels, iterations, converged)`.
fn run_semi_synchronous(
    adj: &SimpleUndirectedCsr,
    n: usize,
    max_iter: u32,
    cancel: &Cancel<'_>,
) -> Result<(Vec<InternalId>, u32, bool)> {
    let mut label: Vec<InternalId> = (0..n as InternalId).collect();
    let mut iterations = 0u32;
    let mut converged = false;

    // Reusable tally, hoisted and `.clear()`ed per node so its allocation is retained across sweeps.
    let mut counts: HashMap<InternalId, u32> = HashMap::new();

    while iterations < max_iter {
        cancel.check()?;
        iterations += 1;
        let mut changed = false;

        for v in 0..n {
            let best = best_label(adj, &label, v as InternalId, label[v], &mut counts);
            if best != label[v] {
                label[v] = best;
                changed = true;
            }
        }

        if !changed {
            converged = true;
            break;
        }
    }
    Ok((label, iterations, converged))
}

/// Synchronous sweeps: every node reads the previous sweep's labels; the sweep fans across cores
/// (`rmp` #342 / #559). Deterministic on any pool width — each `next[v]` is an independent function of
/// the frozen `label` snapshot. Returns `(labels, iterations, converged)`.
fn run_synchronous(
    adj: &SimpleUndirectedCsr,
    n: usize,
    max_iter: u32,
    cancel: &Cancel<'_>,
) -> Result<(Vec<InternalId>, u32, bool)> {
    use rayon::prelude::*;

    let mut label: Vec<InternalId> = (0..n as InternalId).collect();
    let mut iterations = 0u32;
    let mut converged = false;

    while iterations < max_iter {
        // Cancellation is checked per sweep; a sweep is one bounded `O(n + m)` unit of work.
        cancel.check()?;
        iterations += 1;

        // Compute the whole next labelling from the frozen `label` snapshot. Each worker reuses a
        // private tally map (`map_init`) so no allocation happens per node. `collect` preserves index
        // order, so `next` is identical regardless of how the range was split.
        let label_ref = &label;
        let next: Vec<InternalId> = (0..n)
            .into_par_iter()
            .map_init(HashMap::new, |counts, v| {
                best_label(adj, label_ref, v as InternalId, label_ref[v], counts)
            })
            .collect();

        let changed = next != label;
        label = next;

        if !changed {
            converged = true;
            break;
        }
    }
    Ok((label, iterations, converged))
}

/// The label node `v` should adopt: the most frequent label among its neighbours (read from
/// `labels`), ties broken by the **smallest** label id (determinism). Isolated nodes keep
/// `own_label`. `counts` is a caller-owned scratch map, cleared on entry so its capacity is retained
/// across calls.
fn best_label(
    adj: &SimpleUndirectedCsr,
    labels: &[InternalId],
    v: InternalId,
    own_label: InternalId,
    counts: &mut HashMap<InternalId, u32>,
) -> InternalId {
    let neighbors = adj.neighbors(v).unwrap_or(&[]);
    if neighbors.is_empty() {
        return own_label; // isolated node keeps its own label
    }
    counts.clear();
    for &u in neighbors {
        *counts.entry(labels[u as usize]).or_insert(0) += 1;
    }
    let mut best_label = own_label;
    let mut best_count = 0u32;
    for (&lab, &cnt) in counts.iter() {
        if cnt > best_count || (cnt == best_count && lab < best_label) {
            best_count = cnt;
            best_label = lab;
        }
    }
    best_label
}
