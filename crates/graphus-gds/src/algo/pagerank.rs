//! PageRank with correct dangling-node handling.
//!
//! Iterative power method on the (row-stochastic) transition matrix with damping. Dangling nodes
//! (zero out-degree) would otherwise leak rank mass; here their mass is collected each iteration and
//! redistributed uniformly, so the rank vector stays a probability distribution summing to one.
//!
//! # Parallelism: the pull/gather formulation (`rmp` #342 / #559, tuned in #580)
//!
//! The natural "scatter" update — each source *pushes* `d · rank[src] / deg` onto every
//! out-neighbour's slot — races when parallelised: many sources write the same `next[dst]`. This
//! module instead computes the mathematically identical **pull/gather** update: each output node
//! `dst` *pulls* the contributions of its **in-neighbours**,
//! `next[dst] = base + d · Σ_{src → dst} rank[src] · factor(src → dst)`. Every output slot is written
//! by exactly one task from a **fixed** per-node summation order, so the result is:
//!
//! - **bit-identical** whether the gather runs on 1 core or 64, and whether run serially or in
//!   parallel (each `next[dst]` is an independent, order-fixed reduction), and
//! - independent of the `rayon` pool width — the DST-reproducibility guarantee.
//!
//! ## Pre-scaling the source contribution (`rmp` #580)
//!
//! The per-edge transition `factor(src → dst)` depends only on the **source**: for an unweighted
//! projection it is the constant `1 / out_degree(src)` for every out-edge of `src`. Storing that
//! constant once per **edge** (an `f64` parallel to the source-id array) doubled the transpose's
//! memory footprint and, because PageRank's gather is **memory-bandwidth bound** (a sparse SpMV that
//! streams the whole transpose every iteration), that redundant `8 · m`-byte stream was the dominant
//! cost and capped multi-core scaling — extra cores only contend harder for the same memory bus.
//!
//! So the source factor is **hoisted out of the edge loop**: once per iteration a cheap `O(n)` pass
//! forms `contrib[src] = rank[src] · scale[src]` (with `scale[src] = 1 / out_degree(src)` unweighted,
//! or `1 / out_weight(src)` weighted; `0` for dangling sources), and the gather becomes the pure
//! reduction `next[dst] = base + d · Σ_{src → dst} contrib[src] · w?`. The transpose then stores only
//! the source id per edge (plus the **raw** weight for a weighted projection) — halving (unweighted)
//! the bytes streamed per iteration and giving each core more bandwidth headroom, which is what lets
//! the gather actually scale across cores. For the unweighted path the summed terms are the *same*
//! products in the *same* order as before, so the result stays **bit-identical**.
//!
//! Pulling requires the **in-adjacency**, which the CSR (out-edges only) does not store, so a compact
//! transpose is built once per call in `O(n + m)` — negligible against the `O(k · (n + m))` iteration
//! cost. The per-iteration scalar reductions (dangling mass, L1 convergence delta) are computed in a
//! fixed ascending-id order on a single thread; they are `O(n)` and keep the whole algorithm
//! bit-identical across pool widths while the `O(m)` gather (and the `O(n)` pre-scale) run across all
//! cores.

use crate::cancel::Cancel;
use crate::csr::{CsrGraph, InternalId};
use crate::error::{GdsError, Result};
use crate::execution::Execution;

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

/// Computes PageRank with the default [`Execution`] (parallel above the crate threshold).
///
/// This is a thin wrapper over [`pagerank_with`]; see that function and the module docs for the
/// weighted/unweighted contract, complexity, and errors.
///
/// # Errors
/// See [`pagerank_with`].
pub fn pagerank(
    graph: &CsrGraph,
    config: PageRankConfig,
    cancel: &Cancel<'_>,
) -> Result<PageRankResult> {
    pagerank_with(graph, config, Execution::default(), cancel)
}

/// Computes PageRank with an explicit [`Execution`] knob.
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
/// # Determinism (`rmp` #342 / #559)
/// The result is **bit-identical** regardless of the [`Execution`] mode or the `rayon` pool width: the
/// gather writes each output slot exactly once from a fixed summation order, the `O(n)` pre-scale pass
/// writes each slot once, and the scalar reductions run in a fixed ascending-id order.
/// `Execution::sequential()` and `Execution::parallel()` therefore produce the same bytes; only the
/// number of cores used differs.
///
/// # Complexity
/// Time `O(n + m)` to build the transpose plus `O(k · (n + m))` for `k` iterations, space `O(n + m)`.
///
/// # Errors
/// - [`GdsError::InvalidArgument`] if `damping` is not in `[0, 1)` or `tolerance` is negative, or if
///   the projection is weighted and carries a negative or non-finite edge weight (a weighted PageRank
///   transition requires non-negative finite weights).
/// - [`GdsError::Cancelled`] if `cancel` fires (checked once per iteration).
pub fn pagerank_with(
    graph: &CsrGraph,
    config: PageRankConfig,
    exec: Execution,
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
    let d = config.damping;
    let teleport = (1.0 - d) / nf;
    let weighted = graph.is_weighted();

    // `rmp` #422: for a weighted projection, precompute each node's total out-weight once. A node is
    // dangling iff its out-weight sum is `0` (no usable out-edge to carry rank), and the per-source
    // scale is its reciprocal. Unweighted projections use neighbour count.
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

    // A node carries rank forward iff it has a usable out-transition; otherwise it is dangling and its
    // mass is redistributed uniformly. Materialize the mask once (read every iteration).
    let dangling: Vec<bool> = (0..n)
        .map(|i| {
            if weighted {
                out_weight[i] <= 0.0
            } else {
                graph.out_degree(i as InternalId).unwrap_or(0) == 0
            }
        })
        .collect();
    // `rmp` #580: the (ascending) list of dangling node ids. The per-iteration dangling-mass fold sums
    // only these — `O(#dangling)`, not `O(n)` — and in ascending id order, so the sum is bit-identical
    // to a full masked scan while costing nothing when the graph has few/no dangling nodes.
    let dangling_idx: Vec<usize> = (0..n).filter(|&i| dangling[i]).collect();

    // `rmp` #580: the per-source transition scale, hoisted out of the per-edge gather. For a
    // non-dangling source it is `1 / out_degree` (unweighted) or `1 / out_weight` (weighted); a
    // dangling source is `0` (its mass flows through the uniform redistribution, never the transition,
    // so it is excluded from the transpose and its `scale` is never read — `0` is just defensive).
    let scale: Vec<f64> = (0..n)
        .map(|i| {
            if dangling[i] {
                0.0
            } else if weighted {
                1.0 / out_weight[i]
            } else {
                // `out_degree` counts self-loops and parallel edges, matching the stochastic matrix.
                1.0 / graph.out_degree(i as InternalId).unwrap_or(0) as f64
            }
        })
        .collect();

    // Build the transpose (in-adjacency) storing only the source id per in-edge (plus the raw weight
    // when weighted); the source scale lives in `scale` and enters via the per-iteration `contrib`.
    let t = Transpose::build(graph, weighted, &dangling);

    let base_rank = 1.0 / nf;
    let mut rank = vec![base_rank; n];
    let mut next = vec![0.0f64; n];
    // `contrib[i] = rank[i] * scale[i]`, recomputed each iteration by a parallel `O(n)` pass.
    let mut contrib = vec![0.0f64; n];

    let mut iterations = 0u32;
    let mut converged = false;

    while iterations < config.max_iter {
        cancel.check()?;
        iterations += 1;

        // Dangling mass, summed over the dangling ids in ascending order (bit-identical across pool
        // widths). `O(#dangling)` rather than a full `O(n)` masked scan.
        let mut dangling_sum = 0.0f64;
        for &i in &dangling_idx {
            dangling_sum += rank[i];
        }
        // Uniform base every node receives: teleport + its equal share of the damped dangling mass.
        let base = teleport + d * dangling_sum / nf;

        // Pre-scale: `contrib[src] = rank[src] * scale[src]` (each slot written once => deterministic
        // and safely parallel). Hoists the source factor out of the `O(m)` gather.
        let rank_ref = &rank;
        let scale_ref = &scale;
        exec.map_into(&mut contrib, |i| rank_ref[i] * scale_ref[i]);

        // Gather: each output node pulls its in-neighbours' damped, pre-scaled contributions. Written
        // once per slot from a fixed order => identical serial vs parallel vs any pool width.
        let contrib_ref = &contrib;
        let t_ref = &t;
        exec.map_into(&mut next, |dst| base + d * t_ref.gather(dst, contrib_ref));

        // L1 convergence delta via the deterministic fixed-block reduction (parallel above threshold,
        // bit-identical across pool widths).
        let next_ref = &next;
        let rank_ref2 = &rank;
        let delta = exec.det_reduce(n, |i| (next_ref[i] - rank_ref2[i]).abs());
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

/// The **transpose** (in-adjacency) of a projection, enabling the race-free, deterministic pull/gather
/// update (see the module docs). Built once per PageRank call.
///
/// Each in-edge `src → dst` records its source `src` in `in_src` (grouped by destination via
/// `in_offsets`). For a **weighted** projection the in-edge also records its **raw** edge weight
/// `w(src → dst)` in `in_weight`, parallel to `in_src`; for an **unweighted** projection `in_weight`
/// is empty (the transition is the uniform `1 / out_degree(src)`, applied through the caller's
/// per-source `contrib`). Edges out of a **dangling** source are excluded — their mass flows through
/// the dangling redistribution, never through the transition.
///
/// Storing only the source id (`rmp` #580), rather than a per-edge `f64` transition factor, halves the
/// unweighted transpose footprint. Since PageRank's gather is memory-bandwidth bound, that directly
/// lifts multi-core scaling.
struct Transpose {
    /// CSR row offsets over the *in*-edges, length `node_count + 1`.
    in_offsets: Vec<usize>,
    /// The source node of each in-edge, grouped by destination.
    in_src: Vec<InternalId>,
    /// The **raw** edge weight of each in-edge, parallel to `in_src`. Empty for an unweighted
    /// projection (the uniform transition needs no per-edge weight).
    in_weight: Vec<f64>,
}

impl Transpose {
    fn build(graph: &CsrGraph, weighted: bool, dangling: &[bool]) -> Self {
        let n = graph.node_count();

        // Pass 1: count retained in-edges per destination (edges out of a dangling source excluded).
        let mut counts = vec![0usize; n];
        for (src, neis) in graph.iter_adjacency() {
            if dangling[src as usize] {
                continue;
            }
            for &dst in neis {
                if let Some(c) = counts.get_mut(dst as usize) {
                    *c += 1;
                }
            }
        }

        // Prefix-sum into offsets.
        let mut in_offsets = vec![0usize; n + 1];
        for i in 0..n {
            in_offsets[i + 1] = in_offsets[i] + counts[i];
        }
        let total = in_offsets[n];

        let mut in_src = vec![0 as InternalId; total];
        // Only weighted projections carry per-edge weights; unweighted leaves this empty.
        let mut in_weight = if weighted {
            vec![0.0f64; total]
        } else {
            Vec::new()
        };

        // Pass 2: scatter each retained out-edge into its destination's in-run.
        let mut cursor = in_offsets[..n].to_vec();
        for (src, neis) in graph.iter_adjacency() {
            let si = src as usize;
            if dangling[si] {
                continue;
            }
            let ws = if weighted {
                graph.neighbor_weights(src)
            } else {
                None
            };
            for (ei, &dst) in neis.iter().enumerate() {
                if let Some(pos) = cursor.get_mut(dst as usize) {
                    let p = *pos;
                    in_src[p] = src;
                    if weighted {
                        in_weight[p] = ws.and_then(|w| w.get(ei).copied()).unwrap_or(0.0);
                    }
                    *pos = p + 1;
                }
            }
        }

        Self {
            in_offsets,
            in_src,
            in_weight,
        }
    }

    /// The un-damped gathered contribution of `dst`'s in-neighbours: `Σ contrib[src] · w?`, where
    /// `contrib[src] = rank[src] · scale[src]` is precomputed by the caller and `w` is the raw edge
    /// weight (weighted projections only). The summation order is fixed (the in-run order), so this is
    /// bit-identical regardless of which task evaluates it.
    #[inline]
    fn gather(&self, dst: usize, contrib: &[f64]) -> f64 {
        let start = self.in_offsets[dst];
        let end = self.in_offsets[dst + 1];
        let mut acc = 0.0f64;
        if self.in_weight.is_empty() {
            // Unweighted: the uniform `1 / out_degree(src)` is already folded into `contrib`.
            for e in start..end {
                acc += contrib[self.in_src[e] as usize];
            }
        } else {
            // Weighted: `contrib` carries `rank / out_weight`; multiply by the raw edge weight.
            for e in start..end {
                acc += contrib[self.in_src[e] as usize] * self.in_weight[e];
            }
        }
        acc
    }
}

/// **Personalized (seeded) PageRank** (`rmp` task #333): a PageRank whose teleport mass returns to a
/// caller-supplied **seed distribution** instead of uniformly to all nodes. The seed vector is an
/// internal-id-aligned numeric node column ([`CsrGraph::node_column`]) — read **O(1)** per node from
/// the cached projection rather than re-walking each node's authoritative property chain — so this is
/// exactly the class of property-driven algorithm the columnar node columns unlock.
///
/// A thin wrapper over [`personalized_pagerank_with`] using the default [`Execution`].
///
/// `seed_column` names a non-negative numeric node column; it is normalized to a probability
/// distribution internally (so the result still sums to ~1). A node's seed weight biases both the
/// teleport target and the dangling-mass redistribution toward it, yielding rank personalized to the
/// seed set. With a uniform seed column this reduces exactly to [`pagerank`].
///
/// # Errors
/// See [`personalized_pagerank_with`].
pub fn personalized_pagerank(
    graph: &CsrGraph,
    seed_column: &str,
    config: PageRankConfig,
    cancel: &Cancel<'_>,
) -> Result<PageRankResult> {
    personalized_pagerank_with(graph, seed_column, config, Execution::default(), cancel)
}

/// **Personalized (seeded) PageRank** with an explicit [`Execution`] knob (`rmp` #333, parallelised
/// under `rmp` #342 / #559 via the same deterministic pull/gather as [`pagerank_with`]).
///
/// # Edge weights (ignored magnitudes; same validity contract as [`pagerank_with`])
/// Personalized PageRank uses a **uniform** `1 / out_degree(src)` transition: a node distributes its
/// rank **equally** to its out-neighbours, so edge-weight **magnitudes are ignored** (only topology
/// and the seed column shape the result; a self-loop or a parallel edge still contributes its own
/// equal share, as in the unweighted [`pagerank_with`] path). The personalization enters solely
/// through the seed distribution, never through edge weights.
///
/// Even though magnitudes are ignored, the **validity** contract is identical to [`pagerank_with`]: a
/// weighted projection carrying a **negative or non-finite** edge weight is rejected with
/// [`GdsError::InvalidArgument`] — the same data [`pagerank_with`] rejects.
///
/// # Determinism
/// Bit-identical across [`Execution`] modes and pool widths, exactly as [`pagerank_with`].
///
/// # Errors
/// - [`GdsError::InvalidArgument`] if `damping`/`tolerance` are out of range; if the projection is
///   weighted and carries a negative or non-finite edge weight; if `seed_column` is not an attached
///   column; or if the seed column has no positive mass / a negative or non-finite entry.
/// - [`GdsError::Cancelled`] if `cancel` fires.
pub fn personalized_pagerank_with(
    graph: &CsrGraph,
    seed_column: &str,
    config: PageRankConfig,
    exec: Execution,
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
    // Mirror `pagerank`'s weight-validity contract exactly (magnitudes ignored, validity enforced).
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

    // Uniform transition (magnitudes ignored): dangling iff no out-edge. Build the transpose over the
    // *unweighted* adjacency so the gather is the pure pre-scaled reduction.
    let dangling: Vec<bool> = (0..n)
        .map(|i| graph.out_degree(i as InternalId).unwrap_or(0) == 0)
        .collect();
    let dangling_idx: Vec<usize> = (0..n).filter(|&i| dangling[i]).collect();
    // `rmp` #580: per-source uniform scale `1 / out_degree` (0 for dangling), hoisted out of gather.
    let scale: Vec<f64> = (0..n)
        .map(|i| {
            if dangling[i] {
                0.0
            } else {
                1.0 / graph.out_degree(i as InternalId).unwrap_or(0) as f64
            }
        })
        .collect();
    let t = Transpose::build(graph, false, &dangling);

    let mut rank = teleport_dist.clone();
    let mut next = vec![0.0f64; n];
    let mut contrib = vec![0.0f64; n];
    let d = config.damping;
    let mut iterations = 0u32;
    let mut converged = false;

    while iterations < config.max_iter {
        cancel.check()?;
        iterations += 1;

        // Dangling mass, summed over the dangling ids in ascending order (`O(#dangling)`).
        let mut dangling_sum = 0.0f64;
        for &i in &dangling_idx {
            dangling_sum += rank[i];
        }
        // Base mass for node i is redistributed along the SEED distribution (personalized):
        // (teleport + personalized dangling) · seed_i.
        let dangling_mass = d * dangling_sum;
        let base_coeff = (1.0 - d) + dangling_mass;

        // Pre-scale (each slot written once => deterministic and safely parallel).
        let rank_ref = &rank;
        let scale_ref = &scale;
        exec.map_into(&mut contrib, |i| rank_ref[i] * scale_ref[i]);

        let contrib_ref = &contrib;
        let t_ref = &t;
        let dist_ref = &teleport_dist;
        exec.map_into(&mut next, |i| {
            base_coeff * dist_ref[i] + d * t_ref.gather(i, contrib_ref)
        });

        // L1 convergence delta via the deterministic fixed-block reduction.
        let next_ref = &next;
        let rank_ref2 = &rank;
        let delta = exec.det_reduce(n, |i| (next_ref[i] - rank_ref2[i]).abs());
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
