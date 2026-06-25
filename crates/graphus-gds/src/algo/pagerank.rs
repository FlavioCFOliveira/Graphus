//! PageRank with correct dangling-node handling.
//!
//! Iterative power method on the (row-stochastic) transition matrix with damping. Dangling nodes
//! (zero out-degree) would otherwise leak rank mass; here their mass is collected each iteration and
//! redistributed uniformly, so the rank vector stays a probability distribution summing to one.

use crate::cancel::Cancel;
use crate::csr::{CsrGraph, InternalId};
use crate::error::{GdsError, Result};

use super::shortest_path::validate_weights_non_negative;

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
/// # Weighted vs. unweighted (`rmp` #422)
/// The contract follows the projection: if the projection is **weighted**
/// ([`CsrGraph::is_weighted`]), this computes **weight-normalized PageRank** — a node `src`
/// distributes its rank to each out-neighbour `dst` in proportion to the edge weight,
/// `share(src → dst) ∝ w(src → dst) / Σ_k w(src → ·)` — so a heavier edge carries more rank. If the
/// projection is **unweighted**, every out-edge carries equal share `1 / out_degree(src)` (the
/// classic uniform transition). A node whose total out-weight is zero (or which has no out-edges) is
/// **dangling**: its rank is collected and redistributed uniformly each iteration, exactly as in the
/// unweighted case, so the rank vector stays a probability distribution summing to one.
///
/// Self-loops and parallel edges are folded into the transition naturally: each contributes its own
/// (uniform or weighted) share, matching the multigraph's stochastic matrix.
///
/// # Complexity
/// Time `O(k · (n + m))` for `k` iterations, space `O(n)`.
///
/// # Errors
/// - [`GdsError::InvalidArgument`] if `damping` is not in `[0, 1)` or `tolerance` is negative, or if
///   the projection is weighted and carries a negative or non-finite edge weight (a weighted PageRank
///   transition requires non-negative finite weights).
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
    // `rmp` #422: a weighted transition needs non-negative finite weights, else the per-node weight
    // normalization is meaningless (negative shares, NaN). Validate once up front.
    if graph.is_weighted() {
        validate_weights_non_negative(graph)?;
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
    let weighted = graph.is_weighted();

    // `rmp` #422: for a weighted projection, precompute each node's total out-weight once. It serves
    // two purposes per iteration: (1) a node is dangling iff its out-weight sum is `0` (no usable
    // out-edge to carry rank), and (2) the per-edge share is normalized by it. Unweighted projections
    // fall back to neighbour count (the classic uniform transition); `out_weight` is unused then.
    let out_weight: Vec<f64> = if weighted {
        (0..n)
            .map(|i| {
                graph
                    .neighbor_weights(i as InternalId)
                    .map_or(0.0, |ws| ws.iter().copied().sum())
            })
            .collect()
    } else {
        Vec::new()
    };

    // A node carries rank forward iff it has a usable out-transition; otherwise it is dangling.
    let is_dangling = |i: usize| -> bool {
        if weighted {
            out_weight[i] <= 0.0
        } else {
            graph.out_degree(i as InternalId).unwrap_or(0) == 0
        }
    };

    let mut iterations = 0u32;
    let mut converged = false;

    while iterations < config.max_iter {
        cancel.check()?;
        iterations += 1;

        // Collect dangling mass (nodes with no usable out-edge keep all their rank, redistributed).
        let mut dangling_sum = 0.0f64;
        for (i, &r) in rank.iter().enumerate() {
            if is_dangling(i) {
                dangling_sum += r;
            }
        }
        let dangling_share = d * dangling_sum / nf;

        for slot in next.iter_mut() {
            *slot = teleport + dangling_share;
        }

        for (src, neis) in graph.iter_adjacency() {
            let si = src as usize;
            if neis.is_empty() {
                continue;
            }
            if weighted {
                let total = out_weight[si];
                if total <= 0.0 {
                    continue; // dangling: its mass is handled via `dangling_share` above
                }
                // Weight-normalized transition: heavier edges carry more rank (`rmp` #422).
                let mass = d * rank[si];
                let ws = graph.neighbor_weights(src).unwrap_or(&[]);
                for (&dst, &w) in neis.iter().zip(ws.iter()) {
                    if let Some(slot) = next.get_mut(dst as usize) {
                        *slot += mass * (w / total);
                    }
                }
            } else {
                let share = d * rank[si] / neis.len() as f64;
                for &dst in neis {
                    if let Some(slot) = next.get_mut(dst as usize) {
                        *slot += share;
                    }
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

/// **Personalized (seeded) PageRank** (`rmp` task #333): a PageRank whose teleport mass returns to a
/// caller-supplied **seed distribution** instead of uniformly to all nodes. The seed vector is an
/// internal-id-aligned numeric node column ([`CsrGraph::node_column`]) — read **O(1)** per node from
/// the cached projection rather than re-walking each node's authoritative property chain — so this is
/// exactly the class of property-driven algorithm the columnar node columns unlock.
///
/// `seed_column` names a non-negative numeric node column; it is normalized to a probability
/// distribution internally (so the result still sums to ~1). A node's seed weight biases both the
/// teleport target and the dangling-mass redistribution toward it, yielding rank personalized to the
/// seed set. With a uniform seed column this reduces exactly to [`pagerank`].
///
/// # Errors
/// - [`GdsError::InvalidArgument`] if `damping`/`tolerance` are out of range (as [`pagerank`]), if
///   `seed_column` is not an attached column, or if the seed column has no positive mass / a negative
///   or non-finite entry (it cannot form a teleport distribution).
/// - [`GdsError::Cancelled`] if `cancel` fires.
pub fn personalized_pagerank(
    graph: &CsrGraph,
    seed_column: &str,
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
    let seed = graph.node_column(seed_column).ok_or_else(|| {
        GdsError::InvalidArgument(format!("seed column `{seed_column}` is not attached"))
    })?;

    // Normalize the seed column to a teleport probability distribution (O(1)-read per node).
    let mut total = 0.0f64;
    for &s in seed {
        if !s.is_finite() || s < 0.0 {
            return Err(GdsError::InvalidArgument(
                "seed column must be non-negative and finite".into(),
            ));
        }
        total += s;
    }
    if total <= 0.0 {
        return Err(GdsError::InvalidArgument(
            "seed column must have positive total mass".into(),
        ));
    }
    let teleport_dist: Vec<f64> = seed.iter().map(|&s| s / total).collect();

    let mut rank = teleport_dist.clone();
    let mut next = vec![0.0f64; n];
    let d = config.damping;
    let mut iterations = 0u32;
    let mut converged = false;

    while iterations < config.max_iter {
        cancel.check()?;
        iterations += 1;

        // Dangling mass is redistributed along the SEED distribution (personalized), not uniformly.
        let mut dangling_sum = 0.0f64;
        for (i, &r) in rank.iter().enumerate() {
            if graph.out_degree(i as InternalId).unwrap_or(0) == 0 {
                dangling_sum += r;
            }
        }
        let dangling = d * dangling_sum;

        // Base mass for node i = (teleport + personalized dangling) * seed_i.
        for (slot, &p) in next.iter_mut().zip(teleport_dist.iter()) {
            *slot = (1.0 - d) * p + dangling * p;
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
