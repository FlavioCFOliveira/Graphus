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

use crate::cancel::Cancel;
use crate::csr::{CsrGraph, InternalId, Orientation};
use crate::error::{GdsError, Result};
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
    let mut result = vec![0.0f64; n];
    if n <= 1 {
        return Ok(result);
    }
    let nf = (n - 1) as f64;

    // SEC-209: validate the non-negativity precondition ONCE, not once per source. Previously the
    // per-source Dijkstra re-scanned all `m` edges on every call, making the validation alone
    // `O(n·m)` on a weighted graph. With the single up-front scan the per-source path uses
    // `dijkstra_validated`, which skips the rescan.
    if graph.is_weighted() {
        validate_weights_non_negative(graph)?;
    }

    for (s, slot) in result.iter_mut().enumerate() {
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
        if reachable > 1 && sum > 0.0 {
            let r_minus_1 = (reachable - 1) as f64;
            // Wasserman-Faust: (r-1)/(n-1) * (r-1)/sum
            *slot = (r_minus_1 / nf) * (r_minus_1 / sum);
        }
    }
    Ok(result)
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
    let mut betweenness = vec![0.0f64; n];
    if n == 0 {
        return Ok(betweenness);
    }

    // Reusable buffers.
    let mut sigma = vec![0.0f64; n];
    let mut dist = vec![-1i64; n];
    let mut delta = vec![0.0f64; n];
    let mut predecessors: Vec<Vec<u32>> = vec![Vec::new(); n];
    let mut stack: Vec<u32> = Vec::with_capacity(n);
    let mut queue: VecDeque<u32> = VecDeque::new();

    for s in 0..n {
        cancel.check()?;

        // Reset.
        for v in 0..n {
            sigma[v] = 0.0;
            dist[v] = -1;
            delta[v] = 0.0;
            predecessors[v].clear();
        }
        stack.clear();
        queue.clear();

        sigma[s] = 1.0;
        dist[s] = 0;
        queue.push_back(s as u32);

        // BFS, recording shortest-path counts and predecessors.
        while let Some(v) = queue.pop_front() {
            stack.push(v);
            let dv = dist[v as usize];
            if let Some(neis) = graph.neighbors(v) {
                for &w in neis {
                    let wi = w as usize;
                    if dist[wi] < 0 {
                        dist[wi] = dv + 1;
                        queue.push_back(w);
                    }
                    if dist[wi] == dv + 1 {
                        sigma[wi] += sigma[v as usize];
                        predecessors[wi].push(v);
                    }
                }
            }
        }

        // Back-propagation of dependencies (reverse BFS order).
        while let Some(w) = stack.pop() {
            let wi = w as usize;
            // SEC-205: on a graph engineered to have a super-exponential number of shortest paths
            // (e.g. a layered lattice), `sigma` can overflow f64 to +inf; the division below would
            // then yield NaN/0 and silently corrupt *every* score. Detect the non-finite count and
            // surface a clean Overflow error instead of emitting corrupted betweenness values.
            // A node on the stack was reached by the BFS, so `sigma[wi] >= 1.0` unless it overflowed
            // to +inf; checking finiteness is therefore exactly the overflow test.
            if !sigma[wi].is_finite() {
                return Err(GdsError::Overflow(
                    "betweenness shortest-path count exceeded f64 range",
                ));
            }
            let coeff = (1.0 + delta[wi]) / sigma[wi];
            for &v in &predecessors[wi] {
                delta[v as usize] += sigma[v as usize] * coeff;
            }
            if wi != s {
                betweenness[wi] += delta[wi];
            }
        }
    }

    Ok(betweenness)
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
