//! PageRank with correct dangling-node handling.
//!
//! Iterative power method on the (row-stochastic) transition matrix with damping. Dangling nodes
//! (zero out-degree) would otherwise leak rank mass; here their mass is collected each iteration and
//! redistributed uniformly, so the rank vector stays a probability distribution summing to one.

use crate::cancel::Cancel;
use crate::csr::{CsrGraph, InternalId};
use crate::error::{GdsError, Result};

/// Configuration for [`pagerank`].
#[derive(Debug, Clone, Copy)]
pub struct PageRankConfig {
    /// Damping factor (probability of following an edge vs. teleporting). Classic value `0.85`.
    pub damping: f64,
    /// Maximum number of power-iterations.
    pub max_iter: u32,
    /// L1 convergence tolerance: stop when the summed absolute change drops below this.
    pub tolerance: f64,
}

impl Default for PageRankConfig {
    fn default() -> Self {
        Self {
            damping: 0.85,
            max_iter: 100,
            tolerance: 1e-9,
        }
    }
}

/// The outcome of a PageRank run.
#[derive(Debug, Clone)]
pub struct PageRankResult {
    /// `rank[i]` is the PageRank of node `i`; the vector sums to (approximately) `1.0`.
    pub rank: Vec<f64>,
    /// Iterations actually performed.
    pub iterations: u32,
    /// Whether the L1 tolerance was reached before `max_iter`.
    pub converged: bool,
}

/// Computes PageRank.
///
/// # Complexity
/// Time `O(k · (n + m))` for `k` iterations, space `O(n)`. Self-loops and parallel edges contribute
/// to a node's out-degree exactly as the transition matrix dictates; the multigraph needs no
/// special handling.
///
/// # Errors
/// - [`GdsError::InvalidArgument`] if `damping` is not in `[0, 1)` or `tolerance` is negative.
/// - [`GdsError::Cancelled`] if `cancel` fires (checked once per iteration).
pub fn pagerank(
    graph: &CsrGraph,
    config: PageRankConfig,
    cancel: &Cancel<'_>,
) -> Result<PageRankResult> {
    if !(0.0..1.0).contains(&config.damping) || !config.damping.is_finite() {
        return Err(GdsError::InvalidArgument(
            "damping must be in [0, 1)".into(),
        ));
    }
    if config.tolerance < 0.0 || config.tolerance.is_nan() {
        return Err(GdsError::InvalidArgument("tolerance must be >= 0".into()));
    }

    let n = graph.node_count();
    if n == 0 {
        return Ok(PageRankResult {
            rank: Vec::new(),
            iterations: 0,
            converged: true,
        });
    }

    let nf = n as f64;
    let base = 1.0 / nf;
    let mut rank = vec![base; n];
    let mut next = vec![0.0f64; n];

    let d = config.damping;
    let teleport = (1.0 - d) / nf;

    let mut iterations = 0u32;
    let mut converged = false;

    while iterations < config.max_iter {
        cancel.check()?;
        iterations += 1;

        // Collect dangling mass (nodes with no out-edges keep all their rank, which we redistribute).
        let mut dangling_sum = 0.0f64;
        for (i, &r) in rank.iter().enumerate() {
            if graph.out_degree(i as InternalId).unwrap_or(0) == 0 {
                dangling_sum += r;
            }
        }
        let dangling_share = d * dangling_sum / nf;

        for slot in next.iter_mut() {
            *slot = teleport + dangling_share;
        }

        for (src, neis) in graph.iter_adjacency() {
            let deg = neis.len();
            if deg == 0 {
                continue;
            }
            let share = d * rank[src as usize] / deg as f64;
            for &dst in neis {
                if let Some(slot) = next.get_mut(dst as usize) {
                    *slot += share;
                }
            }
        }

        let mut delta = 0.0f64;
        for (nv, rv) in next.iter().zip(rank.iter()) {
            delta += (nv - rv).abs();
        }
        core::mem::swap(&mut rank, &mut next);

        if delta <= config.tolerance {
            converged = true;
            break;
        }
    }

    Ok(PageRankResult {
        rank,
        iterations,
        converged,
    })
}
