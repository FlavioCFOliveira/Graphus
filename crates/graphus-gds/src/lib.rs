//! `graphus-gds` — an in-memory graph data science engine for Graphus.
//!
//! This crate provides two layers:
//!
//! - An **immutable CSR projection** ([`csr`]): external `u64` node ids are mapped to a contiguous
//!   internal index space and stored as compressed sparse rows (offsets + targets, with optional
//!   parallel `f64` weights). Projections support directed and undirected (symmetrized) orientation,
//!   carry an explicit [`CsrGraph::memory_bytes`] accounting, and expose only bounds-checked
//!   accessors. A small [`catalog`] provides the `project` / `list` / `drop` named-graph lifecycle.
//!
//! - A library of **production-grade graph algorithms** ([`algo`]): PageRank, Weakly/Strongly
//!   Connected Components, degree/closeness/betweenness centrality, triangle counting and clustering
//!   coefficient, Label Propagation community detection, and weighted shortest paths (Dijkstra and
//!   Bellman-Ford). Every algorithm is panic-free on degenerate input, supports cooperative
//!   cancellation, and documents its time/space complexity.
//!
//! # Design constraints
//!
//! - **No `unsafe`.** The crate is `#![forbid(unsafe_code)]`, matching the workspace mandate.
//! - **Never panic on data.** No `unwrap`/`expect`/`panic`, no unchecked indexing, checked/saturating
//!   integer arithmetic, and explicit heap stacks instead of data-depth recursion (Tarjan SCC).
//! - **Zero runtime dependencies.** The crate depends on nothing outside `std`, so it can be
//!   unit-tested in isolation. Its own [`error::GdsError`] mirrors the hand-written-`Display` style
//!   of `graphus-core`'s `GraphusError`; the integration layer maps it into `GraphusError` later.
//!
//! # Snapshot consistency (integration contract)
//!
//! A projection is a point-in-time snapshot. When wired to the live store, the caller MUST drain the
//! source under a single consistent MVCC read snapshot so the node and edge sets agree. See [`csr`].

#![forbid(unsafe_code)]

pub mod algo;
pub mod cancel;
pub mod catalog;
pub mod csr;
pub mod error;

pub use cancel::Cancel;
pub use catalog::GraphCatalog;
pub use csr::{CsrBuilder, CsrGraph, ExternalId, GraphSource, InternalId, Orientation};
pub use error::{GdsError, Result};

/// A tiny in-memory [`GraphSource`] backed by owned vectors, primarily for tests and examples.
///
/// It declares an explicit node list plus an edge list of `(src, dst, weight)`. For unweighted use,
/// pass `1.0` (or build the projection with [`CsrBuilder::weighted(false)`](CsrBuilder::weighted)).
#[derive(Debug, Clone, Default)]
pub struct VecGraphSource {
    /// External node ids.
    pub nodes: Vec<ExternalId>,
    /// Edges as `(src, dst, weight)`.
    pub edges: Vec<(ExternalId, ExternalId, f64)>,
}

impl GraphSource for VecGraphSource {
    type Nodes = std::vec::IntoIter<ExternalId>;
    type Edges = std::vec::IntoIter<(ExternalId, ExternalId, f64)>;

    fn nodes(self) -> Self::Nodes {
        self.nodes.into_iter()
    }

    fn edges(self) -> Self::Edges {
        self.edges.into_iter()
    }
}

impl VecGraphSource {
    /// Builds a [`CsrGraph`] from this source with the given orientation and weightedness.
    ///
    /// # Errors
    /// Propagates [`GdsError::UnknownNode`] for edges referencing undeclared endpoints and
    /// [`GdsError::Overflow`] from the builder. Unknown endpoints are auto-registered, so in
    /// practice this is infallible for well-formed inputs.
    pub fn build(self, orientation: Orientation, weighted: bool) -> Result<CsrGraph> {
        let mut builder = CsrBuilder::new(orientation)
            .weighted(weighted)
            .allow_implicit_nodes(true);
        for id in self.nodes {
            builder.add_node(id);
        }
        for (s, d, w) in self.edges {
            builder.add_edge(s, d, w)?;
        }
        builder.build()
    }
}
