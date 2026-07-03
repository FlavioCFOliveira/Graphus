//! Triangle counting and the local clustering coefficient.
//!
//! Both treat the graph as **undirected and simple**: each edge's endpoints are folded into a
//! per-node deduplicated neighbour set (dropping self-loops and parallel edges), so a directed or
//! multigraph projection still yields the standard simple-graph triangle/clustering values. For a
//! correct global count, project the graph as [`crate::csr::Orientation::Undirected`].
//!
//! # Parallelism (`rmp` #342 / #559)
//!
//! Two equivalent enumeration strategies back the two execution modes, chosen so the parallel path is
//! **race-free and bit-identical** to the sequential one:
//!
//! - **Sequential** uses the classic *edge-iterator*: scan each undirected edge `(u, v)` with `u < v`
//!   once, count common neighbours `w > v`, and increment `triangles[u]`, `triangles[v]`,
//!   `triangles[w]`. Each triangle is enumerated exactly once — minimal work.
//! - **Parallel** uses the *node-centric* form: `triangles[u]` is computed **independently** per node
//!   `u` as the number of adjacent pairs among `u`'s neighbours. Each node writes only its own slot,
//!   so there is no scatter and no reduction — the loop is embarrassingly parallel and deterministic.
//!   Each triangle is examined once per vertex (three times total), so the global total is
//!   `Σ triangles[u] / 3`. The extra constant factor is amply repaid across cores.
//!
//! Both strategies produce **identical** `triangles`, `coefficient`, and `total_triangles` (integer
//! exact), so `Execution::sequential()` and `Execution::parallel()` agree bit-for-bit.

use crate::cancel::Cancel;
use crate::csr::{CsrGraph, InternalId, SimpleUndirectedCsr};
use crate::error::Result;
use crate::execution::Execution;

/// Triangle/clustering output.
#[derive(Debug, Clone)]
pub struct TriangleResult {
    /// `triangles[i]` = number of triangles node `i` participates in.
    pub triangles: Vec<u64>,
    /// `coefficient[i]` = local clustering coefficient of node `i` in `[0, 1]` (0 for degree < 2).
    pub coefficient: Vec<f64>,
    /// Total distinct triangles in the graph.
    pub total_triangles: u64,
}

/// Counts triangles and computes local clustering coefficients with the default [`Execution`].
///
/// A thin wrapper over [`triangle_count_with`].
///
/// # Errors
/// See [`triangle_count_with`].
pub fn triangle_count(graph: &CsrGraph, cancel: &Cancel<'_>) -> Result<TriangleResult> {
    triangle_count_with(graph, Execution::default(), cancel)
}

/// Counts triangles and computes local clustering coefficients with an explicit [`Execution`] knob.
///
/// # Determinism
/// Bit-identical across [`Execution`] modes and `rayon` pool widths (integer-exact per-node counts;
/// see the module docs).
///
/// # Complexity
/// Building the simple neighbour sets is `O(n + m)`; the enumeration is `O(sum over edges of
/// min(deg(u), deg(v)))`, near `O(m^{3/2})` in practice. Space `O(n + m)` for the deduplicated
/// adjacency sets.
///
/// # Errors
/// [`crate::error::GdsError::Cancelled`] if `cancel` fires (checked per source node).
pub fn triangle_count_with(
    graph: &CsrGraph,
    exec: Execution,
    cancel: &Cancel<'_>,
) -> Result<TriangleResult> {
    let n = graph.node_count();

    // Shared, built-once flat-CSR simple-undirected adjacency (`rmp` #379): deduplicated, self-loop
    // free, each node's run sorted ascending. Reused by `label_propagation` on the same projection.
    let adj = graph.simple_undirected_csr();

    let (triangles, total) = if exec.is_parallel(n) {
        // Node-centric: each `triangles[u]` computed independently (no scatter). Total = Σ / 3, since
        // every triangle is counted once at each of its three vertices.
        let triangles = exec.try_map(n, |u| {
            cancel.check()?;
            Ok(triangles_at(adj, u as InternalId))
        })?;
        let sum: u64 = triangles.iter().copied().fold(0u64, u64::saturating_add);
        (triangles, sum / 3)
    } else {
        // Edge-iterator: each triangle enumerated exactly once (u < v < w). Minimal serial work.
        let mut triangles = vec![0u64; n];
        let mut total = 0u64;
        for u in 0..n {
            cancel.check()?;
            let nu = adj.neighbors(u as InternalId).unwrap_or(&[]);
            for &v in nu {
                if (v as usize) <= u {
                    continue;
                }
                let nv = adj.neighbors(v).unwrap_or(&[]);
                let (small, large) = if nu.len() <= nv.len() {
                    (nu, nv)
                } else {
                    (nv, nu)
                };
                for &w in small {
                    if w > v && large.binary_search(&w).is_ok() {
                        total = total.saturating_add(1);
                        triangles[u] = triangles[u].saturating_add(1);
                        triangles[v as usize] = triangles[v as usize].saturating_add(1);
                        triangles[w as usize] = triangles[w as usize].saturating_add(1);
                    }
                }
            }
        }
        (triangles, total)
    };

    let mut coefficient = vec![0.0f64; n];
    for i in 0..n {
        let deg = adj.degree(i as InternalId) as u64;
        if deg >= 2 {
            // possible pairs = deg*(deg-1)/2; coefficient = triangles / possible_pairs.
            let pairs = deg * (deg - 1) / 2;
            coefficient[i] = triangles[i] as f64 / pairs as f64;
        }
    }

    Ok(TriangleResult {
        triangles,
        coefficient,
        total_triangles: total,
    })
}

/// The number of triangles node `u` participates in, computed independently over the simple-undirected
/// adjacency `adj`. For every neighbour `v` of `u`, counts the common neighbours `w` of `u` and `v`
/// with `w > v` — so each unordered pair `{v, w}` of `u`'s neighbours that is itself an edge is
/// counted exactly once. Writes nothing outside its return value, so a parallel map over `u` is
/// race-free and deterministic.
fn triangles_at(adj: &SimpleUndirectedCsr, u: InternalId) -> u64 {
    let nu = adj.neighbors(u).unwrap_or(&[]);
    let mut cnt = 0u64;
    for &v in nu {
        let nv = adj.neighbors(v).unwrap_or(&[]);
        // Intersect nu and nv (both sorted ascending), counting matches `w > v`. Binary-search the
        // smaller list into the larger — the same per-pair cost as the edge-iterator's inner loop.
        let (small, large) = if nu.len() <= nv.len() {
            (nu, nv)
        } else {
            (nv, nu)
        };
        for &w in small {
            if w > v && large.binary_search(&w).is_ok() {
                cnt = cnt.saturating_add(1);
            }
        }
    }
    cnt
}

// The simple-undirected adjacency is built once and cached on the projection itself
// ([`CsrGraph::simple_undirected_csr`], `rmp` #379) as a single flat CSR, replacing the prior helper
// that allocated `n` per-node `Vec`s freshly for every consumer.
