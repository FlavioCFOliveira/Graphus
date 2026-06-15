//! The immutable CSR (compressed sparse row) graph projection and its builder.
//!
//! # Snapshot consistency (integration contract)
//!
//! A projection is an immutable in-memory snapshot. When this crate is wired to the real
//! transactional store, the caller **MUST** build the projection under a single consistent read
//! snapshot — i.e. drain the source iterators against one MVCC timestamp — so that the node set and
//! the edge set agree with each other. This crate cannot enforce that on its own (it only sees
//! iterators); it is a precondition the integration layer guarantees. Once built, a [`CsrGraph`] is
//! frozen and shared by `Arc`, so reads never observe a torn snapshot.

use crate::error::{GdsError, Result};
// SECURITY (SEC-210, CWE-407): `index_of` below is keyed by `ExternalId` — a `u64` drawn from
// CLIENT-CONTROLLED node ids. It MUST stay on a DoS-resistant, randomly-seeded hasher. `std`'s
// `HashMap` uses SipHash 1-3 with a per-process random seed, which resists hash-flooding, so it is
// the correct default here. Do NOT swap this map to a fixed-seed fast hasher (e.g. `FxHashMap`, or
// `ahash` without random keys): the page-table elsewhere in the workspace uses `FxHashMap` for
// perf, but that pattern is unsafe over client-derived keys and must not be copied onto this map.
use std::collections::HashMap;

/// The external (caller-facing) node identifier type.
///
/// In standalone tests these are arbitrary `u64` keys; in the future store integration they are the
/// physical/element ids drawn from the live store under a read snapshot.
pub type ExternalId = u64;

/// The internal, contiguous node index in the range `0..node_count`.
///
/// CSR addressing is done entirely with these dense indices; the mapping back to [`ExternalId`] is
/// held in [`CsrGraph::external_ids`].
pub type InternalId = u32;

/// The orientation a projection is built with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Orientation {
    /// Edges are kept as given: `(src -> dst)` produces one out-edge on `src`.
    Directed,
    /// Each input edge `(a, b)` is symmetrized into both `a -> b` and `b -> a`. A self-loop
    /// `(a, a)` is, by convention, materialized **once** (not duplicated) so that degree counts of
    /// undirected self-loops stay intuitive.
    Undirected,
}

/// A single declared edge prior to compression.
#[derive(Debug, Clone, Copy)]
struct RawEdge {
    src: ExternalId,
    dst: ExternalId,
    weight: f64,
}

/// A trait for anything that can feed a [`CsrBuilder`].
///
/// Implement this to project from a custom source (in tests, from in-memory vectors; in production,
/// from a store cursor under a read snapshot — see the module-level snapshot contract). The two
/// methods are pull-based so a source can stream without materializing everything at once.
///
/// The default [`CsrBuilder`]-based path ([`CsrBuilder::from_source`]) declares every node first,
/// then every edge, so an edge may reference a node id that the source yields in `nodes()`.
pub trait GraphSource {
    /// The iterator of external node ids this source declares.
    type Nodes: IntoIterator<Item = ExternalId>;
    /// The iterator of edges this source declares, as `(src, dst, weight)`.
    type Edges: IntoIterator<Item = (ExternalId, ExternalId, f64)>;

    /// Yields the node ids. Duplicates are tolerated (deduplicated by the builder).
    fn nodes(self) -> Self::Nodes;

    /// Yields the edges. Must be callable after [`Self::nodes`]; see [`GraphSource`] note. Because
    /// `self` is consumed by `nodes`, sources that need both should be cheap to clone or should be
    /// driven through [`CsrBuilder`] directly.
    fn edges(self) -> Self::Edges;
}

/// An incremental builder for a [`CsrGraph`].
///
/// Nodes can be added explicitly or are auto-registered the first time an edge references them when
/// [`CsrBuilder::allow_implicit_nodes`] is set. Edges are buffered and compressed in
/// [`CsrBuilder::build`].
#[derive(Debug)]
pub struct CsrBuilder {
    orientation: Orientation,
    weighted: bool,
    allow_implicit_nodes: bool,
    /// external id -> internal index, assigned in declaration order.
    ///
    /// SEC-210: keyed by client-controlled `ExternalId`; keep the DoS-resistant SipHash default (see
    /// the security note on the `HashMap` import).
    index_of: HashMap<ExternalId, InternalId>,
    /// internal index -> external id.
    external: Vec<ExternalId>,
    edges: Vec<RawEdge>,
}

impl CsrBuilder {
    /// Creates a builder with the given orientation. Defaults to unweighted (weight `1.0`) and to
    /// rejecting edges that reference an undeclared node.
    #[must_use]
    pub fn new(orientation: Orientation) -> Self {
        Self {
            orientation,
            weighted: false,
            allow_implicit_nodes: false,
            index_of: HashMap::new(),
            external: Vec::new(),
            edges: Vec::new(),
        }
    }

    /// Marks the projection as carrying edge weights. When unset, the weights array is omitted and
    /// every edge is treated as weight `1.0`.
    #[must_use]
    pub fn weighted(mut self, weighted: bool) -> Self {
        self.weighted = weighted;
        self
    }

    /// When set, an edge that references an unknown node auto-registers that node instead of
    /// returning [`GdsError::UnknownNode`].
    #[must_use]
    pub fn allow_implicit_nodes(mut self, allow: bool) -> Self {
        self.allow_implicit_nodes = allow;
        self
    }

    /// Registers a node, returning its internal index (idempotent for repeated ids).
    pub fn add_node(&mut self, id: ExternalId) -> InternalId {
        Self::intern(&mut self.index_of, &mut self.external, id)
    }

    fn intern(
        index_of: &mut HashMap<ExternalId, InternalId>,
        external: &mut Vec<ExternalId>,
        id: ExternalId,
    ) -> InternalId {
        if let Some(&idx) = index_of.get(&id) {
            return idx;
        }
        // `external.len()` is bounded by the number of distinct node ids; a graph with more than
        // u32::MAX nodes is out of scope for an in-memory projection, and `as` truncation is guarded
        // by `build` (which re-checks the count). We keep the index space at u32 for cache density.
        let idx = external.len() as InternalId;
        index_of.insert(id, idx);
        external.push(id);
        idx
    }

    /// Buffers an edge. With an unweighted builder the supplied `weight` is ignored.
    ///
    /// # Errors
    /// Returns [`GdsError::UnknownNode`] if either endpoint is undeclared and implicit nodes are
    /// disabled.
    pub fn add_edge(&mut self, src: ExternalId, dst: ExternalId, weight: f64) -> Result<()> {
        for endpoint in [src, dst] {
            if !self.index_of.contains_key(&endpoint) {
                if self.allow_implicit_nodes {
                    self.add_node(endpoint);
                } else {
                    return Err(GdsError::UnknownNode(endpoint));
                }
            }
        }
        let weight = if self.weighted { weight } else { 1.0 };
        self.edges.push(RawEdge { src, dst, weight });
        Ok(())
    }

    /// Builds the projection from a [`GraphSource`], registering all nodes then all edges.
    ///
    /// # Errors
    /// Propagates [`GdsError::UnknownNode`] from edges referencing undeclared nodes (unless implicit
    /// nodes are enabled) and [`GdsError::Overflow`] from [`CsrBuilder::build`].
    pub fn from_source<S>(
        mut self,
        source_nodes: S::Nodes,
        source_edges: S::Edges,
    ) -> Result<CsrGraph>
    where
        S: GraphSource,
    {
        for id in source_nodes {
            self.add_node(id);
        }
        for (src, dst, w) in source_edges {
            self.add_edge(src, dst, w)?;
        }
        self.build()
    }

    /// Compresses the buffered nodes and edges into an immutable [`CsrGraph`].
    ///
    /// # Errors
    /// Returns [`GdsError::Overflow`] if the node count exceeds [`InternalId`]'s range or the edge
    /// count exceeds `usize`.
    pub fn build(self) -> Result<CsrGraph> {
        let n = self.external.len();
        if n > InternalId::MAX as usize {
            return Err(GdsError::Overflow("node count exceeds u32 index space"));
        }

        // Materialize the directed adjacency, symmetrizing for undirected.
        let mut expanded: Vec<RawEdge> = Vec::new();
        let want = match self.orientation {
            Orientation::Directed => self.edges.len(),
            Orientation::Undirected => self.edges.len().saturating_mul(2),
        };
        expanded
            .try_reserve(want)
            .map_err(|_| GdsError::Overflow("edge buffer allocation"))?;
        for e in &self.edges {
            expanded.push(*e);
            if self.orientation == Orientation::Undirected && e.src != e.dst {
                expanded.push(RawEdge {
                    src: e.dst,
                    dst: e.src,
                    weight: e.weight,
                });
            }
        }

        let m = expanded.len();
        // CSR offsets hold values in `0..=m` (cumulative edge counts). We keep them as `u32` for
        // cache density (4 bytes/node instead of 8), so the edge count must fit in `u32` — mirror
        // the node-count guard above.
        if m > u32::MAX as usize {
            return Err(GdsError::Overflow("edge count exceeds u32 offset space"));
        }
        // Counting sort by source into CSR offsets.
        let mut offsets = vec![0u32; n + 1];
        for e in &expanded {
            // `src` is guaranteed interned (add_edge/intern), so the lookup is infallible; we still
            // avoid `unwrap` and skip defensively rather than panic.
            if let Some(&s) = self.index_of.get(&e.src) {
                offsets[s as usize + 1] += 1;
            }
        }
        for i in 0..n {
            offsets[i + 1] += offsets[i];
        }

        let mut targets = vec![0 as InternalId; m];
        let mut weights = if self.weighted {
            vec![1.0f64; m]
        } else {
            Vec::new()
        };
        let mut cursor = offsets.clone();
        for e in &expanded {
            let (Some(&s), Some(&d)) = (self.index_of.get(&e.src), self.index_of.get(&e.dst))
            else {
                continue;
            };
            let pos = cursor[s as usize] as usize;
            targets[pos] = d;
            if self.weighted {
                weights[pos] = e.weight;
            }
            cursor[s as usize] += 1;
        }

        Ok(CsrGraph {
            orientation: self.orientation,
            external: self.external,
            index_of: self.index_of,
            offsets,
            targets,
            weights,
        })
    }
}

/// An immutable CSR graph projection.
///
/// Nodes are dense internal indices `0..node_count`; out-edges of node `i` live in
/// `targets[offsets[i]..offsets[i+1]]` with parallel `weights` (when weighted). Reverse lookups go
/// through [`CsrGraph::external_ids`] / [`CsrGraph::internal_id`].
///
/// The structure is read-only and cheap to share by `Arc`. All accessors are bounds-checked and
/// return `Option`/slices — there is no indexing path reachable from graph data that can panic.
#[derive(Debug, Clone)]
pub struct CsrGraph {
    orientation: Orientation,
    external: Vec<ExternalId>,
    index_of: HashMap<ExternalId, InternalId>,
    /// CSR row offsets, length `node_count + 1`, values in `0..=edge_count`. Stored as `u32` (not
    /// `usize`) for cache density; the edge-count fit is guaranteed by the build-time guard.
    offsets: Vec<u32>,
    targets: Vec<InternalId>,
    weights: Vec<f64>,
}

impl CsrGraph {
    /// The number of nodes.
    #[must_use]
    pub fn node_count(&self) -> usize {
        self.external.len()
    }

    /// The number of directed edges actually stored (after undirected symmetrization).
    #[must_use]
    pub fn edge_count(&self) -> usize {
        self.targets.len()
    }

    /// Whether parallel weights are present.
    #[must_use]
    pub fn is_weighted(&self) -> bool {
        !self.weights.is_empty()
    }

    /// The orientation the projection was built with.
    #[must_use]
    pub fn orientation(&self) -> Orientation {
        self.orientation
    }

    /// The external id of an internal index, or `None` if out of range.
    #[must_use]
    pub fn external_id(&self, internal: InternalId) -> Option<ExternalId> {
        self.external.get(internal as usize).copied()
    }

    /// The full external-id table indexed by internal id.
    #[must_use]
    pub fn external_ids(&self) -> &[ExternalId] {
        &self.external
    }

    /// The internal index of an external id, or `None` if absent.
    #[must_use]
    pub fn internal_id(&self, external: ExternalId) -> Option<InternalId> {
        self.index_of.get(&external).copied()
    }

    /// The out-neighbour internal indices of `node`, or `None` if `node` is out of range.
    #[must_use]
    pub fn neighbors(&self, node: InternalId) -> Option<&[InternalId]> {
        let i = node as usize;
        let start = *self.offsets.get(i)? as usize;
        let end = *self.offsets.get(i + 1)? as usize;
        self.targets.get(start..end)
    }

    /// The out-edge weights of `node` parallel to [`CsrGraph::neighbors`], or `None` if `node` is
    /// out of range or the graph is unweighted.
    #[must_use]
    pub fn neighbor_weights(&self, node: InternalId) -> Option<&[f64]> {
        if self.weights.is_empty() {
            return None;
        }
        let i = node as usize;
        let start = *self.offsets.get(i)? as usize;
        let end = *self.offsets.get(i + 1)? as usize;
        self.weights.get(start..end)
    }

    /// The out-degree of `node` (counting parallel edges and self-loops), or `None` if out of range.
    #[must_use]
    pub fn out_degree(&self, node: InternalId) -> Option<usize> {
        let i = node as usize;
        let start = *self.offsets.get(i)? as usize;
        let end = *self.offsets.get(i + 1)? as usize;
        end.checked_sub(start)
    }

    /// An iterator over `(internal_id, neighbors_slice)` for every node, in id order.
    pub fn iter_adjacency(&self) -> impl Iterator<Item = (InternalId, &[InternalId])> {
        (0..self.node_count()).map(move |i| {
            let start = self.offsets[i] as usize;
            let end = self.offsets[i + 1] as usize;
            (i as InternalId, &self.targets[start..end])
        })
    }

    /// An exact accounting of the heap bytes held by this projection (excluding the `HashMap`'s
    /// internal load-factor slack, which is implementation-defined, but including its key/value
    /// storage estimate).
    #[must_use]
    pub fn memory_bytes(&self) -> usize {
        let id = core::mem::size_of::<ExternalId>();
        let idx = core::mem::size_of::<InternalId>();
        let off = core::mem::size_of::<u32>();
        let f = core::mem::size_of::<f64>();

        let external = self.external.capacity().saturating_mul(id);
        let offsets = self.offsets.capacity().saturating_mul(off);
        let targets = self.targets.capacity().saturating_mul(idx);
        let weights = self.weights.capacity().saturating_mul(f);
        // HashMap stores (ExternalId, InternalId) pairs; approximate at capacity.
        let map = self
            .index_of
            .capacity()
            .saturating_mul(id.saturating_add(idx));

        external
            .saturating_add(offsets)
            .saturating_add(targets)
            .saturating_add(weights)
            .saturating_add(map)
            .saturating_add(core::mem::size_of::<Self>())
    }
}
