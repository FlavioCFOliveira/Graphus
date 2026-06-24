//! Community detection via synchronous-ish Label Propagation (LPA).
//!
//! Each node adopts the label most frequent among its neighbours; ties are broken
//! **deterministically** by choosing the smallest candidate label, which makes the algorithm
//! reproducible (the classic LPA breaks ties at random, sacrificing determinism). Iteration is
//! capped and convergence is detected when a full sweep changes no label.
//!
//! Labels are seeded from each node's own internal id, so the final labels are canonical-ish (a
//! community is named by one of its members' ids). The algorithm is treated as **undirected** for
//! the purpose of "neighbours" — it folds the projection into simple undirected adjacency.

use crate::cancel::Cancel;
use crate::csr::{CsrGraph, InternalId};
use crate::error::{GdsError, Result};
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

/// Runs deterministic Label Propagation.
///
/// # Complexity
/// Time `O(k · (n + m))` for `k` sweeps (each sweep visits every node and its neighbours once),
/// space `O(n + m)`. Self-loops and parallel edges are folded away by the simple-adjacency step, so
/// the multigraph does not skew label frequencies.
///
/// # Errors
/// - [`GdsError::InvalidArgument`] if `max_iter` is zero.
/// - [`GdsError::Cancelled`] if `cancel` fires (checked per sweep).
pub fn label_propagation(
    graph: &CsrGraph,
    config: LabelPropagationConfig,
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
    let mut label: Vec<InternalId> = (0..n as InternalId).collect();

    let mut iterations = 0u32;
    let mut converged = false;

    // Reusable label tally, hoisted out of the hot loops and `.clear()`ed per node so its
    // allocation (and capacity) is retained across the O(k·n) inner iterations instead of being
    // freshly allocated for every node on every sweep.
    let mut counts: HashMap<InternalId, u32> = HashMap::new();

    // Deterministic node visitation order (ascending) with in-place updates (semi-synchronous).
    while iterations < config.max_iter {
        cancel.check()?;
        iterations += 1;
        let mut changed = false;

        for v in 0..n {
            let neighbors = adj.neighbors(v as InternalId).unwrap_or(&[]);
            if neighbors.is_empty() {
                continue; // isolated node keeps its own label
            }
            // Tally neighbour labels (reuse the hoisted map; clearing keeps its capacity).
            counts.clear();
            for &u in neighbors {
                *counts.entry(label[u as usize]).or_insert(0) += 1;
            }
            // Pick the most frequent label; break ties by smallest label id (determinism).
            let mut best_label = label[v];
            let mut best_count = 0u32;
            for (&lab, &cnt) in &counts {
                if cnt > best_count || (cnt == best_count && lab < best_label) {
                    best_count = cnt;
                    best_label = lab;
                }
            }
            if best_label != label[v] {
                label[v] = best_label;
                changed = true;
            }
        }

        if !changed {
            converged = true;
            break;
        }
    }

    // Count distinct labels.
    let distinct: std::collections::HashSet<InternalId> = label.iter().copied().collect();

    Ok(CommunityResult {
        label,
        count: distinct.len(),
        iterations,
        converged,
    })
}
