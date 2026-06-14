//! The algorithm library over the immutable CSR projection.
//!
//! Every algorithm in this module is **panic-free on every degenerate graph shape** (empty graph,
//! isolated node, self-loop, parallel edges / multigraph, disconnected graph): there is no
//! `unwrap`/`expect`/`panic` and no unchecked indexing reachable from graph data, integer
//! arithmetic is checked or saturating, and any DFS whose depth scales with the graph (Tarjan SCC)
//! uses an explicit heap stack rather than recursion. Each iterative algorithm takes an iteration
//! cap / tolerance and a cooperative [`crate::cancel::Cancel`] check.

pub mod centrality;
pub mod community;
pub mod degree;
pub mod pagerank;
pub mod scc;
pub mod shortest_path;
pub mod triangles;
pub mod wcc;
