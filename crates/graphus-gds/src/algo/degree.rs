//! Degree centrality.
//!
//! For a directed projection, out-degree is read directly from CSR offsets; in-degree is computed
//! by a single pass over the targets array. For an undirected projection the CSR already holds both
//! directions, so out- and in-degree coincide and equal the total degree.
//!
//! # Parallelism (`rmp` #342 / #559)
//!
//! Degree centrality is `O(n + m)` with trivial per-element work — a subtraction of two offsets
//! (out-degree) or a single increment (in-degree histogram). It is memory-bandwidth bound, so
//! parallelism helps only the strictly *per-node-independent* part:
//!
//! - **Out-degree** (and undirected total/in, which equals it) is `out[i] = offsets[i+1] - offsets[i]`
//!   — each node writes its own slot, so it fans across cores when large enough. Bit-identical to the
//!   sequential result.
//! - **Directed in-degree / total** requires a **scatter** into `indeg[target]` — a histogram with
//!   write contention. A race-free parallel histogram needs `O(threads · n)` private scratch and its
//!   per-element cost (one add) is dominated by memory traffic, so it does **not** beat the serial
//!   single pass in practice. That pass is therefore kept **sequential** (documented here rather than
//!   parallelised for its own sake). It is deterministic regardless.

use crate::csr::{CsrGraph, InternalId, Orientation};
use crate::execution::Execution;

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

/// Per-node degree centrality with the default [`Execution`], indexed by internal id.
///
/// A thin wrapper over [`degree_centrality_with`].
///
/// # Complexity
/// Time `O(n + m)`, space `O(n)`. Self-loops and parallel edges are counted with their multiplicity,
/// faithfully reflecting the multigraph.
#[must_use]
pub fn degree_centrality(graph: &CsrGraph, direction: Direction) -> Vec<u64> {
    degree_centrality_with(graph, direction, Execution::default())
}

/// Per-node degree centrality with an explicit [`Execution`] knob, indexed by internal id.
///
/// # Determinism
/// Bit-identical across [`Execution`] modes and pool widths (integer counts written once per node, or
/// a fixed-order histogram).
///
/// # Complexity
/// Time `O(n + m)`, space `O(n)`. Self-loops and parallel edges are counted with their multiplicity.
#[must_use]
pub fn degree_centrality_with(graph: &CsrGraph, direction: Direction, exec: Execution) -> Vec<u64> {
    let n = graph.node_count();
    let mut out = vec![0u64; n];

    // Out-degree from offsets: per-node independent, so parallel when large enough.
    exec.map_into(&mut out, |i| {
        graph.out_degree(i as InternalId).unwrap_or(0) as u64
    });

    match direction {
        Direction::Out => out,
        Direction::In => {
            // Undirected CSR is symmetric, so in == out and the extra pass is redundant.
            if graph.orientation() == Orientation::Undirected {
                return out;
            }
            // Directed in-degree: sequential histogram scatter (see the module docs).
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
            // Directed total = out + in-degree (sequential histogram scatter atop the out counts).
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
