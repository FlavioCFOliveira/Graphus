//! Triangle counting and the local clustering coefficient.
//!
//! Both treat the graph as **undirected and simple**: each edge's endpoints are folded into a
//! per-node deduplicated neighbour set (dropping self-loops and parallel edges), so a directed or
//! multigraph projection still yields the standard simple-graph triangle/clustering values. For a
//! correct global count, project the graph as [`crate::csr::Orientation::Undirected`].

use crate::cancel::Cancel;
use crate::csr::{CsrGraph, InternalId};
use crate::error::Result;

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

/// Counts triangles and computes local clustering coefficients.
///
/// # Complexity
/// Building the simple neighbour sets is `O(n + m)`; the triangle enumeration is `O(sum over
/// edges of min(deg(u), deg(v)))`, bounded by `O(m · d_max)` and in practice near `O(m^{3/2})`.
/// Space `O(n + m)` for the deduplicated adjacency sets.
///
/// # Errors
/// [`crate::error::GdsError::Cancelled`] if `cancel` fires (checked per source node).
pub fn triangle_count(graph: &CsrGraph, cancel: &Cancel<'_>) -> Result<TriangleResult> {
    let n = graph.node_count();

    // Build deduplicated, self-loop-free undirected neighbour lists, each sorted ascending.
    let adj = simple_undirected_adjacency(graph);

    let mut triangles = vec![0u64; n];
    let mut total = 0u64;

    // For each undirected edge (u < v) count common neighbours; each triangle {u,v,w} is found
    // exactly once when scanning the edge (u,v) with u < v and w > v.
    for u in 0..n {
        cancel.check()?;
        let nu = &adj[u];
        for &v in nu {
            if (v as usize) <= u {
                continue;
            }
            let nv = &adj[v as usize];
            // Intersect nu and nv, only counting w > v to avoid triple-counting. Both lists are
            // sorted ascending, so binary-search the smaller into the larger (the `w > v` filter
            // matches the original set-based version exactly).
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

    let mut coefficient = vec![0.0f64; n];
    for i in 0..n {
        let deg = adj[i].len() as u64;
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

/// Helper used by other modules: the deduplicated, self-loop-free undirected neighbour lists, each
/// sorted in ascending [`InternalId`] order.
///
/// Returns contiguous `Vec<u32>` per node (rather than `BTreeSet`) for cache-friendly intersection
/// (binary search / two-pointer merge) while preserving the same set semantics: each list is
/// self-loop-free, has no duplicates, and is ascending — exactly the iteration order a `BTreeSet`
/// would yield.
#[must_use]
pub(crate) fn simple_undirected_adjacency(graph: &CsrGraph) -> Vec<Vec<InternalId>> {
    let n = graph.node_count();
    let mut adj: Vec<Vec<InternalId>> = vec![Vec::new(); n];
    for (u, neis) in graph.iter_adjacency() {
        for &v in neis {
            if u == v {
                continue; // drop self-loops
            }
            adj[u as usize].push(v);
            if let Some(list) = adj.get_mut(v as usize) {
                list.push(u);
            }
        }
    }
    // Sort + dedup each list: ascending order with parallel edges collapsed, matching the prior
    // BTreeSet semantics exactly.
    for list in &mut adj {
        list.sort_unstable();
        list.dedup();
    }
    adj
}
