//! Closeness and betweenness centrality.
//!
//! - **Closeness** uses BFS for unweighted graphs and Dijkstra for weighted ones. The convention is
//!   the *Wasserman-Faust* improved closeness, which is well defined on disconnected graphs:
//!   `C(v) = (r-1)/(n-1) · (r-1)/sum_of_distances_to_reachable`, where `r` is the number of nodes
//!   reachable from `v` (including `v`). For a fully connected graph this reduces to the classic
//!   `(n-1)/sum_of_distances`.
//! - **Betweenness** uses **Brandes' algorithm** (unweighted BFS accumulation). Scores are the
//!   standard *raw* betweenness (sum over all ordered source-target pairs of the fraction of
//!   shortest paths through `v`). For an undirected projection each unordered pair is counted twice;
//!   divide by two externally if you need the undirected convention (the tests state which they use).
//!
//! ## Multigraph σ semantics (`rmp` #416)
//!
//! Brandes' shortest-path count `σ` is defined over a **simple** graph: the number of *distinct
//! shortest paths*. A multigraph projection may carry **parallel edges** (`k` edges `u → v`) and
//! **self-loops**, but those do **not** create extra shortest paths — `k` parallel edges between
//! adjacent nodes still form **one** shortest hop, and a self-loop never lies on a shortest path
//! between two distinct nodes. Betweenness therefore traverses the **simple** adjacency of the
//! projection (parallel edges deduplicated, self-loops dropped), honouring the projection's
//! orientation: an [`Orientation::Undirected`] projection uses
//! [`CsrGraph::simple_undirected_csr`](crate::csr::CsrGraph::simple_undirected_csr) and a
//! [`Orientation::Directed`] one uses
//! [`CsrGraph::simple_directed_csr`](crate::csr::CsrGraph::simple_directed_csr). Consequently a graph
//! and the same graph with any edge duplicated yield **identical** betweenness — the multiplicity of
//! the multigraph is collapsed to its simple structure, as the algorithm's definition requires.
//!
//! Closeness is **multiplicity-invariant by construction**: it scores via BFS/Dijkstra *distances*,
//! and parallel edges or self-loops never shorten a distance (they only add redundant relaxations of
//! an already-discovered node), so it needs no de-duplication and is left to traverse the raw
//! adjacency.

use crate::cancel::Cancel;
use crate::csr::{CsrGraph, InternalId, Orientation, SimpleUndirectedCsr};
use crate::error::{GdsError, Result};
use rayon::prelude::*;
use std::collections::VecDeque;

use super::shortest_path::{dijkstra_validated, validate_weights_non_negative};

/// Closeness centrality, indexed by internal id.
///
/// # Complexity
/// Unweighted: `O(n · (n + m))` (a BFS per node). Weighted: `O(n · (n + m) log n)` (a Dijkstra per
/// node). Space `O(n)` per source plus the result vector.
///
/// # Errors
/// - [`crate::error::GdsError::Cancelled`] if `cancel` fires (checked per source).
/// - Propagates Dijkstra precondition errors (negative weights) for weighted graphs.
pub fn closeness_centrality(graph: &CsrGraph, cancel: &Cancel<'_>) -> Result<Vec<f64>> {
    let n = graph.node_count();
    if n <= 1 {
        return Ok(vec![0.0f64; n]);
    }
    let nf = (n - 1) as f64;

    // SEC-209: validate the non-negativity precondition ONCE, not once per source. Previously the
    // per-source Dijkstra re-scanned all `m` edges on every call, making the validation alone
    // `O(n·m)` on a weighted graph. With the single up-front scan the per-source path uses
    // `dijkstra_validated`, which skips the rescan.
    if graph.is_weighted() {
        validate_weights_non_negative(graph)?;
    }

    // Each source's closeness is computed independently over the immutable CSR and lands in its own
    // result slot, so the per-source loop is data-parallel (rayon) with no shared mutable state and
    // a deterministic, order-independent result (each slot is written exactly once).
    (0..n)
        .into_par_iter()
        .map(|s| -> Result<f64> {
            cancel.check()?;
            // distances from s
            let (sum, reachable) = if graph.is_weighted() {
                let sp = dijkstra_validated(graph, s as InternalId, cancel)?;
                let mut sum = 0.0f64;
                let mut reachable = 0usize;
                for d in sp.dist.into_iter().flatten() {
                    sum += d;
                    reachable += 1;
                }
                (sum, reachable)
            } else {
                bfs_distance_sum(graph, s as InternalId)
            };

            // reachable includes s itself (distance 0). Need at least one other reachable node.
            Ok(if reachable > 1 && sum > 0.0 {
                let r_minus_1 = (reachable - 1) as f64;
                // Wasserman-Faust: (r-1)/(n-1) * (r-1)/sum
                (r_minus_1 / nf) * (r_minus_1 / sum)
            } else {
                0.0
            })
        })
        .collect()
}

/// BFS from `source`; returns `(sum_of_distances, reachable_node_count_including_source)`.
fn bfs_distance_sum(graph: &CsrGraph, source: InternalId) -> (f64, usize) {
    let n = graph.node_count();
    let mut dist = vec![u64::MAX; n];
    let mut queue = VecDeque::new();
    dist[source as usize] = 0;
    queue.push_back(source);
    let mut sum = 0.0f64;
    let mut reachable = 0usize;
    while let Some(v) = queue.pop_front() {
        let dv = dist[v as usize];
        sum += dv as f64;
        reachable += 1;
        if let Some(neis) = graph.neighbors(v) {
            for &w in neis {
                if dist[w as usize] == u64::MAX {
                    dist[w as usize] = dv.saturating_add(1);
                    queue.push_back(w);
                }
            }
        }
    }
    (sum, reachable)
}

/// Raw betweenness centrality via Brandes' algorithm (unweighted, BFS-based).
///
/// The returned scores are *raw* (un-normalized) betweenness: for directed graphs they sum over all
/// ordered `(s, t)` pairs; for an undirected projection each unordered pair is implicitly counted in
/// both directions, so the conventional undirected score is `raw / 2` (the tests divide accordingly
/// and document the choice).
///
/// # Complexity
/// Time `O(n · m)`, space `O(n + m)` per source (BFS layers, sigma, delta, predecessor lists). This
/// is the classic Brandes bound; no all-pairs distance matrix is materialized.
///
/// # Errors
/// [`crate::error::GdsError::Cancelled`] if `cancel` fires (checked per source).
pub fn betweenness_centrality(graph: &CsrGraph, cancel: &Cancel<'_>) -> Result<Vec<f64>> {
    let n = graph.node_count();
    if n == 0 {
        return Ok(Vec::new());
    }

    // `rmp` #416: σ counts *distinct* shortest paths over a *simple* graph, so the BFS must traverse
    // the de-duplicated (parallel-edge-free, self-loop-free) adjacency that honours the projection's
    // orientation — not the raw multigraph CSR.
    let adj: &SimpleUndirectedCsr = match graph.orientation() {
        Orientation::Undirected => graph.simple_undirected_csr(),
        Orientation::Directed => graph.simple_directed_csr(),
    };

    // Brandes accumulates an independent single-source dependency per source `s`; the sources are
    // data-parallel over the immutable adjacency. Each rayon task carries private scratch buffers
    // (`BrandesScratch`) and produces that source's *own* dependency contribution as a private
    // `Vec<f64>`.
    //
    // `rmp` #421 — determinism: the per-source contributions are summed in a **fixed (ascending
    // source-id) order**, independent of how rayon splits the work. We collect the per-source delta
    // vectors into a source-indexed `Vec` (`into_par_iter().map(...).collect()` preserves input
    // order) and fold them serially in id order. f64 addition is non-associative, so a
    // split-dependent reduction order (the previous `try_reduce`) made the result thread-count
    // dependent; fixing the fold order makes the betweenness **bit-identical** across pool widths.
    // The expensive per-source BFS + dependency accumulation stays fully parallel; only the final
    // O(n²) accumulation is serialized into a deterministic order.
    let per_source: Vec<Vec<f64>> = (0..n)
        .into_par_iter()
        .map_init(
            || BrandesScratch::new(n),
            |scratch, s| -> Result<Vec<f64>> {
                cancel.check()?;
                scratch.run_source(adj, s)?;
                Ok(scratch.acc.clone())
            },
        )
        .collect::<Result<Vec<Vec<f64>>>>()?;

    let mut acc = vec![0.0f64; n];
    for contribution in &per_source {
        for (x, y) in acc.iter_mut().zip(contribution.iter()) {
            *x += *y;
        }
    }
    Ok(acc)
}

/// Per-task scratch + private accumulator for the data-parallel Brandes betweenness. Reused across
/// every source a rayon task processes (allocated once per task, not per source).
struct BrandesScratch {
    n: usize,
    sigma: Vec<f64>,
    dist: Vec<i64>,
    delta: Vec<f64>,
    predecessors: Vec<Vec<u32>>,
    stack: Vec<u32>,
    queue: VecDeque<u32>,
    /// The current source's dependency contribution (`rmp` #421). Reset at the start of every
    /// [`Self::run_source`] and cloned out per source, so the caller can sum contributions in a
    /// deterministic (ascending source-id) order rather than in a rayon-split-dependent one.
    acc: Vec<f64>,
}

impl BrandesScratch {
    fn new(n: usize) -> Self {
        Self {
            n,
            sigma: vec![0.0f64; n],
            dist: vec![-1i64; n],
            delta: vec![0.0f64; n],
            predecessors: vec![Vec::new(); n],
            stack: Vec::with_capacity(n),
            queue: VecDeque::new(),
            acc: vec![0.0f64; n],
        }
    }

    /// Runs Brandes' single-source dependency accumulation from `s` over the **simple** adjacency
    /// `adj` (`rmp` #416), writing this source's dependency contribution into [`Self::acc`].
    ///
    /// `acc` is **reset** on entry so it holds *only* this source's contribution: the caller (`rmp`
    /// #421) clones it per source and sums the contributions in a deterministic id order, so each
    /// `run_source` must be self-contained rather than folding into a running total.
    fn run_source(&mut self, adj: &SimpleUndirectedCsr, s: usize) -> Result<()> {
        let n = self.n;
        // Reset all per-source scratch, including the contribution accumulator.
        for v in 0..n {
            self.sigma[v] = 0.0;
            self.dist[v] = -1;
            self.delta[v] = 0.0;
            self.predecessors[v].clear();
            self.acc[v] = 0.0;
        }
        self.stack.clear();
        self.queue.clear();

        self.sigma[s] = 1.0;
        self.dist[s] = 0;
        self.queue.push_back(s as u32);

        // BFS, recording shortest-path counts and predecessors.
        while let Some(v) = self.queue.pop_front() {
            self.stack.push(v);
            let dv = self.dist[v as usize];
            if let Some(neis) = adj.neighbors(v) {
                for &w in neis {
                    let wi = w as usize;
                    if self.dist[wi] < 0 {
                        self.dist[wi] = dv + 1;
                        self.queue.push_back(w);
                    }
                    if self.dist[wi] == dv + 1 {
                        self.sigma[wi] += self.sigma[v as usize];
                        self.predecessors[wi].push(v);
                    }
                }
            }
        }

        // Back-propagation of dependencies (reverse BFS order).
        while let Some(w) = self.stack.pop() {
            let wi = w as usize;
            // SEC-205: on a graph engineered to have a super-exponential number of shortest paths
            // (e.g. a layered lattice), `sigma` can overflow f64 to +inf; the division below would
            // then yield NaN/0 and silently corrupt *every* score. Detect the non-finite count and
            // surface a clean Overflow error instead of emitting corrupted betweenness values.
            // A node on the stack was reached by the BFS, so `sigma[wi] >= 1.0` unless it overflowed
            // to +inf; checking finiteness is therefore exactly the overflow test.
            if !self.sigma[wi].is_finite() {
                return Err(GdsError::Overflow(
                    "betweenness shortest-path count exceeded f64 range",
                ));
            }
            let coeff = (1.0 + self.delta[wi]) / self.sigma[wi];
            for &v in &self.predecessors[wi] {
                self.delta[v as usize] += self.sigma[v as usize] * coeff;
            }
            if wi != s {
                self.acc[wi] += self.delta[wi];
            }
        }
        Ok(())
    }
}

/// Convenience: scale raw betweenness for an undirected projection (divide by two), a no-op for a
/// directed projection.
#[must_use]
pub fn undirected_scale(graph: &CsrGraph, mut raw: Vec<f64>) -> Vec<f64> {
    if graph.orientation() == Orientation::Undirected {
        for x in &mut raw {
            *x /= 2.0;
        }
    }
    raw
}
