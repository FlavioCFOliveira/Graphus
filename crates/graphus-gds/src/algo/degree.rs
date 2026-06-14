//! Degree centrality.
//!
//! For a directed projection, out-degree is read directly from CSR offsets; in-degree is computed
//! by a single pass over the targets array. For an undirected projection the CSR already holds both
//! directions, so out- and in-degree coincide and equal the total degree.

use crate::csr::{CsrGraph, InternalId, Orientation};

/// The direction a degree is measured in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Direction {
    /// Outgoing edges only.
    Out,
    /// Incoming edges only.
    In,
    /// Both directions summed (for undirected graphs this equals either single direction).
    Total,
}

/// Per-node degree centrality, indexed by internal id.
///
/// # Complexity
/// Time `O(n + m)`, space `O(n)` (`n` nodes, `m` stored directed edges). Self-loops and parallel
/// edges are counted with their multiplicity, faithfully reflecting the multigraph.
#[must_use]
pub fn degree_centrality(graph: &CsrGraph, direction: Direction) -> Vec<u64> {
    let n = graph.node_count();
    let mut out = vec![0u64; n];

    // Out-degree from offsets.
    for (i, slot) in out.iter_mut().enumerate() {
        *slot = graph.out_degree(i as InternalId).unwrap_or(0) as u64;
    }

    match direction {
        Direction::Out => out,
        Direction::In => {
            // Undirected CSR is symmetric, so in == out and the extra pass is redundant.
            if graph.orientation() == Orientation::Undirected {
                return out;
            }
            let mut indeg = vec![0u64; n];
            for (src, _) in graph.iter_adjacency() {
                if let Some(neis) = graph.neighbors(src) {
                    for &t in neis {
                        if let Some(slot) = indeg.get_mut(t as usize) {
                            *slot = slot.saturating_add(1);
                        }
                    }
                }
            }
            indeg
        }
        Direction::Total => {
            if graph.orientation() == Orientation::Undirected {
                return out;
            }
            let mut total = out;
            for (src, _) in graph.iter_adjacency() {
                if let Some(neis) = graph.neighbors(src) {
                    for &t in neis {
                        if let Some(slot) = total.get_mut(t as usize) {
                            *slot = slot.saturating_add(1);
                        }
                    }
                }
            }
            total
        }
    }
}
