//! Weighted single-source shortest paths: Dijkstra and Bellman-Ford.
//!
//! Both honour the projection's orientation (they traverse the stored out-edges, which for an
//! undirected projection are already symmetric) and use the projection's weights when present;
//! an unweighted projection is treated as uniform weight `1.0`.

use crate::cancel::Cancel;
use crate::csr::{CsrGraph, InternalId};
use crate::error::{GdsError, Result};
use std::cmp::Ordering;
use std::collections::BinaryHeap;

/// A single-source shortest-path result. `dist[i]` is `None` when node `i` is unreachable.
#[derive(Debug, Clone)]
pub struct ShortestPaths {
    /// `dist[i]` = shortest distance from the source to node `i`, or `None` if unreachable.
    pub dist: Vec<Option<f64>>,
    /// `predecessor[i]` = the node preceding `i` on a shortest path, or `None` for the source and
    /// unreachable nodes. Lets callers reconstruct paths.
    pub predecessor: Vec<Option<InternalId>>,
}

/// A min-heap entry ordered by ascending distance (via `Reverse`-style manual `Ord`).
#[derive(Debug, Clone, Copy)]
struct HeapItem {
    dist: f64,
    node: u32,
}

impl PartialEq for HeapItem {
    fn eq(&self, other: &Self) -> bool {
        self.dist == other.dist
    }
}
impl Eq for HeapItem {}
impl PartialOrd for HeapItem {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}
impl Ord for HeapItem {
    fn cmp(&self, other: &Self) -> Ordering {
        // Reverse so BinaryHeap (a max-heap) pops the smallest distance. NaN can't occur: weights
        // are validated finite & non-negative before any item is pushed.
        other
            .dist
            .partial_cmp(&self.dist)
            .unwrap_or(Ordering::Equal)
    }
}

fn weight_at(graph: &CsrGraph, node: u32, edge_index: usize) -> f64 {
    graph
        .neighbor_weights(node)
        .and_then(|w| w.get(edge_index).copied())
        .unwrap_or(1.0)
}

/// Verifies Dijkstra's precondition — every stored weight is finite and non-negative — in a single
/// `O(m)` scan over all edges (`SEC-209`).
///
/// Exposed within the crate so a caller that runs **many** single-source Dijkstras over the same
/// immutable graph (e.g. [`closeness_centrality`](crate::algo::centrality::closeness_centrality), one
/// per node) can validate the weights **once** up front and then call [`dijkstra_validated`],
/// avoiding the `O(n·m)` cost of re-scanning every edge on every source.
///
/// # Errors
///
/// [`GdsError::InvalidArgument`] if any stored weight is negative or non-finite.
pub fn validate_weights_non_negative(graph: &CsrGraph) -> Result<()> {
    if graph.is_weighted() {
        let n = graph.node_count();
        for node in 0..n {
            if let Some(ws) = graph.neighbor_weights(node as InternalId) {
                for &w in ws {
                    if !w.is_finite() || w < 0.0 {
                        return Err(GdsError::InvalidArgument(
                            "Dijkstra requires non-negative finite edge weights".into(),
                        ));
                    }
                }
            }
        }
    }
    Ok(())
}

/// Dijkstra's single-source shortest paths.
///
/// # Precondition
/// All edge weights must be **non-negative and finite**. This is verified up front; a negative or
/// non-finite weight yields [`GdsError::InvalidArgument`].
///
/// # Complexity
/// Time `O((n + m) · log n)` with a binary heap, space `O(n)`. Self-loops (weight ≥ 0) and parallel
/// edges are harmless — they can never improve a tentative distance.
///
/// # Errors
/// - [`GdsError::InvalidArgument`] if `source` is out of range or any weight is negative/non-finite.
/// - [`GdsError::Cancelled`] if `cancel` fires (checked per settled node).
pub fn dijkstra(
    graph: &CsrGraph,
    source: InternalId,
    cancel: &Cancel<'_>,
) -> Result<ShortestPaths> {
    // Verify the non-negativity precondition once, over all stored weights.
    validate_weights_non_negative(graph)?;
    dijkstra_validated(graph, source, cancel)
}

/// Dijkstra's single-source shortest paths, **assuming the weights were already validated** by
/// [`validate_weights_non_negative`] (`SEC-209`).
///
/// This is the per-source core that [`closeness_centrality`](crate::algo::centrality::closeness_centrality)
/// drives `n` times after a single up-front validation, instead of paying the `O(m)` weight scan on
/// every source. Calling it on a graph with a negative/non-finite weight is a logic error on the
/// caller's part (the heap ordering assumes non-negative edges); it will not panic, but the result is
/// only meaningful for a validated graph.
///
/// # Errors
///
/// [`GdsError::InvalidArgument`] if `source` is out of range. [`GdsError::Cancelled`] if `cancel`
/// fires.
pub fn dijkstra_validated(
    graph: &CsrGraph,
    source: InternalId,
    cancel: &Cancel<'_>,
) -> Result<ShortestPaths> {
    let n = graph.node_count();
    if (source as usize) >= n {
        return Err(GdsError::InvalidArgument("source node out of range".into()));
    }

    let mut dist = vec![None; n];
    let mut predecessor = vec![None; n];
    let mut best = vec![f64::INFINITY; n];
    let mut heap = BinaryHeap::new();

    best[source as usize] = 0.0;
    dist[source as usize] = Some(0.0);
    heap.push(HeapItem {
        dist: 0.0,
        node: source,
    });

    while let Some(HeapItem { dist: d, node }) = heap.pop() {
        cancel.check()?;
        if d > best[node as usize] {
            continue; // stale heap entry
        }
        let neighbors = graph.neighbors(node).unwrap_or(&[]);
        for (ei, &to) in neighbors.iter().enumerate() {
            let w = weight_at(graph, node, ei);
            let nd = d + w;
            let to_i = to as usize;
            if nd < best[to_i] {
                best[to_i] = nd;
                dist[to_i] = Some(nd);
                predecessor[to_i] = Some(node);
                heap.push(HeapItem { dist: nd, node: to });
            }
        }
    }

    Ok(ShortestPaths { dist, predecessor })
}

/// Bellman-Ford single-source shortest paths, with negative-cycle detection.
///
/// Handles negative edge weights (unlike Dijkstra). Performs `n - 1` relaxation rounds; a successful
/// relaxation in an `n`-th round proves a reachable negative-weight cycle.
///
/// # Complexity
/// Time `O(n · m)`, space `O(n + m)` (a flattened edge list is built once). Self-loops with negative
/// weight are themselves negative cycles and are reported as such.
///
/// # Errors
/// - [`GdsError::InvalidArgument`] if `source` is out of range.
/// - [`GdsError::NegativeCycle`] if a reachable negative-weight cycle exists.
/// - [`GdsError::Cancelled`] if `cancel` fires (checked per relaxation round).
pub fn bellman_ford(
    graph: &CsrGraph,
    source: InternalId,
    cancel: &Cancel<'_>,
) -> Result<ShortestPaths> {
    let n = graph.node_count();
    if (source as usize) >= n {
        return Err(GdsError::InvalidArgument("source node out of range".into()));
    }

    // Flatten edges once: (from, to, weight).
    let mut edges: Vec<(u32, u32, f64)> = Vec::new();
    edges
        .try_reserve(graph.edge_count())
        .map_err(|_| GdsError::Overflow("edge list allocation"))?;
    for (from, neis) in graph.iter_adjacency() {
        for (ei, &to) in neis.iter().enumerate() {
            edges.push((from, to, weight_at(graph, from, ei)));
        }
    }

    let mut best = vec![f64::INFINITY; n];
    let mut predecessor = vec![None; n];
    best[source as usize] = 0.0;

    // n - 1 rounds (saturating for n == 0, though n >= 1 here since source is in range).
    let rounds = n.saturating_sub(1);
    for _ in 0..rounds {
        cancel.check()?;
        let mut changed = false;
        for &(u, v, w) in &edges {
            let du = best[u as usize];
            if du.is_finite() {
                let nd = du + w;
                if nd < best[v as usize] {
                    best[v as usize] = nd;
                    predecessor[v as usize] = Some(u);
                    changed = true;
                }
            }
        }
        if !changed {
            break; // early exit: fixpoint reached
        }
    }

    // One more round: any relaxation means a reachable negative cycle.
    for &(u, v, w) in &edges {
        let du = best[u as usize];
        if du.is_finite() && du + w < best[v as usize] {
            return Err(GdsError::NegativeCycle);
        }
    }

    let dist = best
        .into_iter()
        .map(|d| if d.is_finite() { Some(d) } else { None })
        .collect();

    Ok(ShortestPaths { dist, predecessor })
}
