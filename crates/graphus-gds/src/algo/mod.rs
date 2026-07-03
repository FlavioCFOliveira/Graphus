//! The algorithm library over the immutable CSR projection.
//!
//! Every algorithm in this module is **panic-free on every degenerate graph shape** (empty graph,
//! isolated node, self-loop, parallel edges / multigraph, disconnected graph): there is no
//! `unwrap`/`expect`/`panic` and no unchecked indexing reachable from graph data, integer
//! arithmetic is checked or saturating, and any DFS whose depth scales with the graph (Tarjan SCC)
//! uses an explicit heap stack rather than recursion. Each iterative algorithm takes an iteration
//! cap / tolerance and a cooperative [`crate::cancel::Cancel`] check.
//!
//! # Multi-core execution (`rmp` #342 / #559)
//!
//! Each algorithm exposes a `*_with([`crate::execution::Execution`])` variant that selects sequential
//! vs data-parallel (`rayon`) execution; the un-suffixed entry points use the parallel default. Every
//! parallel path is **deterministic by construction** — bit-identical to the sequential result for the
//! integer/exact algorithms and reproducible across `rayon` pool widths for the floating-point ones —
//! so parallelism never costs reproducibility (the DST guarantee). See [`crate::execution`] for the
//! per-algorithm determinism contract and which algorithms remain sequential (SCC's Tarjan DFS,
//! single-source Dijkstra / Bellman-Ford) and why.

pub mod centrality;
pub mod community;
pub mod degree;
pub mod pagerank;
pub mod scc;
pub mod shortest_path;
pub mod triangles;
pub mod wcc;
