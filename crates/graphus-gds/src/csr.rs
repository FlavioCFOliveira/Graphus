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
use std::sync::OnceLock;

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
            node_columns: HashMap::new(),
            simple_undirected: OnceLock::new(),
        })
    }
}

/// The **simple-undirected adjacency** of a projection, materialized as one flat CSR (`rmp` #379).
///
/// Each node `i`'s neighbour run is `targets[offsets[i]..offsets[i + 1]]`, **sorted ascending and
/// deduplicated**, with **self-loops dropped** and **direction ignored** (every input edge `(u, v)`,
/// `u != v`, contributes `v` to `u`'s run and `u` to `v`'s run). These are exactly the set semantics
/// of the prior `Vec<BTreeSet>` / per-node-`Vec` form, but laid out as two contiguous buffers so the
/// triangle-intersection binary search runs over cache-dense slices and the whole structure is one
/// pair of allocations instead of `n` fragmented per-node `Vec`s.
#[derive(Debug, Clone)]
pub struct SimpleUndirectedCsr {
    /// CSR row offsets, length `node_count + 1`, values in `0..=2m`.
    offsets: Vec<u32>,
    /// Flattened, per-node sorted+deduped, self-loop-free undirected neighbour ids.
    targets: Vec<InternalId>,
}

impl SimpleUndirectedCsr {
    /// The deduplicated, ascending, self-loop-free undirected neighbour ids of `node`. Returns an
    /// empty slice for any `node` in `0..node_count` with no neighbours, or `None` if out of range.
    #[must_use]
    pub fn neighbors(&self, node: InternalId) -> Option<&[InternalId]> {
        let i = node as usize;
        let start = *self.offsets.get(i)? as usize;
        let end = *self.offsets.get(i + 1)? as usize;
        self.targets.get(start..end)
    }

    /// The degree (size of the simple-undirected neighbour run) of `node`, or `0` if out of range.
    #[must_use]
    pub fn degree(&self, node: InternalId) -> usize {
        self.neighbors(node).map_or(0, <[InternalId]>::len)
    }

    /// The number of nodes covered (`offsets.len() - 1`), or `0` if empty.
    #[must_use]
    pub fn node_count(&self) -> usize {
        self.offsets.len().saturating_sub(1)
    }

    /// Heap bytes held by the two CSR buffers (`rmp` #379), counted toward the projection quota once
    /// this cache is materialized.
    #[must_use]
    fn memory_bytes(&self) -> usize {
        let off = core::mem::size_of::<u32>();
        let idx = core::mem::size_of::<InternalId>();
        self.offsets
            .capacity()
            .saturating_mul(off)
            .saturating_add(self.targets.capacity().saturating_mul(idx))
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
    /// Optional **internal-id-aligned numeric node-property columns** (`rmp` task #328/#333), keyed by
    /// name. Each column is a dense `Vec<f64>` of length [`node_count`](CsrGraph::node_count): the
    /// value of that property for internal id `i` is `column[i]`, an **O(1)** read that amortizes the
    /// authoritative row-store property-chain walk across every algorithm run over the cached
    /// projection. These columns unlock property-/degree-weighted and **seeded / personalized**
    /// algorithms (e.g. [`personalized_pagerank`](crate::algo::pagerank::personalized_pagerank)) that
    /// must read a per-node scalar. Only numeric columns are held here (a string seed would need a
    /// dictionary column); the authoritative store is untouched, and the column is derived/rebuilt with
    /// the projection.
    node_columns: HashMap<String, Vec<f64>>,
    /// Lazily-built **simple-undirected adjacency** as a single flat CSR (`rmp` task #379), shared by
    /// every consumer that folds this projection into simple-undirected neighbour sets (triangle
    /// counting, label propagation, ...). A GDS sweep that runs several such algorithms over the same
    /// projection previously rebuilt the deduplicated adjacency once **per consumer**, allocating `n`
    /// small per-node `Vec`s each time (heap-fragmenting and `O(m log d)`). This [`OnceLock`] builds the
    /// flat `offsets + targets` CSR exactly once on first request and hands back a borrow on every
    /// subsequent call — lock-free after init. The projection is frozen (immutable after `build`, shared
    /// by `Arc`), so a once-built cache needs **no invalidation**: there is no edge-mutation path that
    /// could stale it. Excluded from [`CsrGraph::memory_bytes`] until materialized (it is `O(n + m)`
    /// when present); see [`CsrGraph::simple_undirected_csr`].
    simple_undirected: OnceLock<SimpleUndirectedCsr>,
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

    /// The shared [`SimpleUndirectedCsr`] for this projection (`rmp` #379), built lazily **exactly
    /// once** and reused on every subsequent call.
    ///
    /// Several algorithms (triangle counting, label propagation, ...) treat the projection as
    /// *undirected and simple*: they fold every edge's endpoints into a per-node deduplicated,
    /// self-loop-free, ascending neighbour set. Before this cache, each such consumer rebuilt that
    /// adjacency from scratch — `n` per-node `Vec`s sorted + deduped, `O(m log d)` — so a sweep running
    /// `k` of them paid the build `k` times and fragmented the heap. This accessor materializes a single
    /// flat CSR (`offsets + targets`) on first request and returns a borrow thereafter; the projection
    /// is frozen (immutable after `build`), so the cache never needs invalidation. The build is
    /// deterministic, so the returned adjacency is identical regardless of which consumer triggers it.
    #[must_use]
    pub fn simple_undirected_csr(&self) -> &SimpleUndirectedCsr {
        self.simple_undirected
            .get_or_init(|| self.build_simple_undirected())
    }

    /// Whether the simple-undirected CSR cache has already been materialized (`rmp` #379). Lets a
    /// caller (e.g. a sweep, or a test asserting the once-built property) observe reuse without forcing
    /// the build.
    #[must_use]
    pub fn has_simple_undirected_csr(&self) -> bool {
        self.simple_undirected.get().is_some()
    }

    /// Builds the simple-undirected adjacency as one flat CSR (`rmp` #379): drop self-loops, symmetrize
    /// (direction ignored), then per node sort ascending + dedup. Two passes over the directed
    /// adjacency — first count each node's undirected degree to lay out `offsets`, then scatter targets
    /// — followed by an in-place sort+dedup of each node's run. The per-node runs that result are
    /// **byte-identical** (same ids, same ascending order) to the prior per-node-`Vec` form.
    fn build_simple_undirected(&self) -> SimpleUndirectedCsr {
        let n = self.node_count();

        // Pass 1: count the (pre-dedup) undirected degree of every node so we can size the run for each.
        // Self-loops are dropped; every other edge bumps both endpoints. Counts include parallel edges
        // (collapsed later by dedup) so the layout is an upper bound on the deduped length.
        let mut counts = vec![0u32; n];
        for (u, neis) in self.iter_adjacency() {
            for &v in neis {
                if u == v {
                    continue; // drop self-loops, exactly as the prior helper did
                }
                counts[u as usize] = counts[u as usize].saturating_add(1);
                if let Some(c) = counts.get_mut(v as usize) {
                    *c = c.saturating_add(1);
                }
            }
        }

        // Prefix-sum the counts into offsets (length n + 1, values in 0..=2m). u32 is sufficient: the
        // directed edge count already fits in u32 (build-time guard), and undirected symmetrization is
        // bounded by 2m which also fits given the guard rejects m > u32::MAX/... — we saturate to stay
        // panic-free under any pathological count.
        let mut offsets = vec![0u32; n + 1];
        for i in 0..n {
            offsets[i + 1] = offsets[i].saturating_add(counts[i]);
        }

        let total = *offsets.last().unwrap_or(&0) as usize;
        let mut targets = vec![0 as InternalId; total];

        // Pass 2: scatter each undirected endpoint into its node's run, using a moving cursor per node.
        let mut cursor: Vec<u32> = offsets[..n].to_vec();
        for (u, neis) in self.iter_adjacency() {
            for &v in neis {
                if u == v {
                    continue;
                }
                if let Some(pos) = cursor.get_mut(u as usize) {
                    targets[*pos as usize] = v;
                    *pos = pos.saturating_add(1);
                }
                if let Some(pos) = cursor.get_mut(v as usize) {
                    targets[*pos as usize] = u;
                    *pos = pos.saturating_add(1);
                }
            }
        }

        // Per-node sort ascending + dedup, then compact the (now shorter, deduped) runs into a tight
        // CSR. This rewrites `offsets`/`targets` in place: `write` is the compacted write cursor.
        let mut new_offsets = vec![0u32; n + 1];
        let mut write = 0usize;
        for i in 0..n {
            let start = offsets[i] as usize;
            let end = offsets[i + 1] as usize;
            let run = &mut targets[start..end];
            run.sort_unstable();
            // Dedup in place within this run, copying survivors down to `write`.
            let mut last: Option<InternalId> = None;
            for k in start..end {
                let val = targets[k];
                if last != Some(val) {
                    targets[write] = val;
                    write += 1;
                    last = Some(val);
                }
            }
            // `write` is monotonic and <= start by construction (runs only shrink), so `new_offsets`
            // never exceeds u32 range — the value is bounded by `total` which fit in u32 above.
            new_offsets[i + 1] = write as u32;
        }
        targets.truncate(write);
        targets.shrink_to_fit();

        SimpleUndirectedCsr {
            offsets: new_offsets,
            targets,
        }
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

        // Internal-id-aligned numeric node columns (`rmp` #333): each is a dense `Vec<f64>` of length
        // `node_count`, plus its name string — counted so the SEC-204 projection memory quota covers
        // them (a weighted/seeded run must not silently exceed the cap).
        let columns: usize = self
            .node_columns
            .iter()
            .map(|(name, col)| {
                name.capacity()
                    .saturating_add(col.capacity().saturating_mul(f))
            })
            .fold(0usize, usize::saturating_add);

        // Simple-undirected CSR cache (`rmp` #379): counted only once materialized, so an idle
        // projection is not charged for an adjacency it never built.
        let simple_undirected = self
            .simple_undirected
            .get()
            .map_or(0, SimpleUndirectedCsr::memory_bytes);

        external
            .saturating_add(offsets)
            .saturating_add(targets)
            .saturating_add(weights)
            .saturating_add(map)
            .saturating_add(columns)
            .saturating_add(simple_undirected)
            .saturating_add(core::mem::size_of::<Self>())
    }

    // --------------------------------------------------------------------------------------------
    // Internal-id-aligned numeric node columns (`rmp` task #333)
    // --------------------------------------------------------------------------------------------

    /// Attaches an internal-id-aligned numeric node column `name`, where `values[i]` is the property
    /// value of internal id `i`. The projection is mutable only before it is shared by `Arc`, so this
    /// is the natural point to derive a column from the same snapshot scan that built the CSR.
    ///
    /// # Errors
    /// [`GdsError::InvalidArgument`] if `values.len() != node_count` (a column must cover every node).
    pub fn attach_node_column(&mut self, name: impl Into<String>, values: Vec<f64>) -> Result<()> {
        if values.len() != self.node_count() {
            return Err(GdsError::InvalidArgument(format!(
                "node column must have one value per node ({} != {})",
                values.len(),
                self.node_count()
            )));
        }
        self.node_columns.insert(name.into(), values);
        Ok(())
    }

    /// Builds an internal-id-aligned column from a per-**external-id** value function and attaches it
    /// under `name` (`rmp` #333). The closure is called once per node in internal-id order with that
    /// node's external id; a node the function has no value for uses `default`. Convenience for the
    /// projection scan, which knows external ids.
    pub fn attach_node_column_from(
        &mut self,
        name: impl Into<String>,
        default: f64,
        mut value_of: impl FnMut(ExternalId) -> Option<f64>,
    ) {
        let values: Vec<f64> = self
            .external
            .iter()
            .map(|&ext| value_of(ext).unwrap_or(default))
            .collect();
        // Length is `node_count` by construction, so the insert cannot violate the invariant.
        self.node_columns.insert(name.into(), values);
    }

    /// The internal-id-aligned column `name`, or `None` if no such column is attached. `column[i]` is
    /// internal id `i`'s value — an O(1) read.
    #[must_use]
    pub fn node_column(&self, name: &str) -> Option<&[f64]> {
        self.node_columns.get(name).map(Vec::as_slice)
    }

    /// Internal id `node`'s value of column `name`, or `None` if the column or id is absent — O(1).
    #[must_use]
    pub fn node_value(&self, name: &str, node: InternalId) -> Option<f64> {
        self.node_columns.get(name)?.get(node as usize).copied()
    }

    // --------------------------------------------------------------------------------------------
    // Zero-copy columnar projection export (`rmp` task #333)
    // --------------------------------------------------------------------------------------------

    /// A **zero-copy** columnar view of the projection's contiguous buffers (`rmp` #333): the CSR
    /// offsets + targets are exactly an Arrow-`ListArray`-shaped adjacency (offsets buffer + values
    /// buffer), and the external-id / weight / node columns are plain primitive columns. Handing these
    /// borrowed slices to a consumer is an **O(number-of-buffers)** operation — no per-edge work —
    /// versus an **O(E)** CSV/row serialization. The borrow keeps it allocation-free; a consumer that
    /// needs ownership copies the slices it wants.
    #[must_use]
    pub fn columnar_export(&self) -> CsrColumnarExport<'_> {
        CsrColumnarExport {
            node_count: self.node_count(),
            edge_count: self.edge_count(),
            offsets: &self.offsets,
            targets: &self.targets,
            weights: (!self.weights.is_empty()).then_some(self.weights.as_slice()),
            external: &self.external,
            node_columns: &self.node_columns,
        }
    }
}

/// A borrowed, zero-copy columnar view of a [`CsrGraph`] for export (`rmp` task #333). All fields are
/// slices into the projection's own buffers — constructing this is O(1) in the edge count. The
/// `offsets` + `targets` pair is layout-compatible with an Arrow `ListArray` (a 32-bit offsets buffer
/// over an `Int32`/`UInt32` values buffer), so a downstream Arrow bridge can wrap them without a copy;
/// `weights` and each `node_columns` entry are primitive `f64` columns.
#[derive(Debug, Clone, Copy)]
pub struct CsrColumnarExport<'a> {
    /// Number of nodes (length of `external` and of each node column; `offsets.len() == node_count+1`).
    pub node_count: usize,
    /// Number of directed edges stored (length of `targets` and, when present, `weights`).
    pub edge_count: usize,
    /// CSR row offsets, length `node_count + 1` (the Arrow `ListArray` offsets buffer).
    pub offsets: &'a [u32],
    /// Flattened out-neighbour internal ids (the Arrow `ListArray` values buffer).
    pub targets: &'a [InternalId],
    /// Parallel edge weights (length `edge_count`), or `None` when the projection is unweighted.
    pub weights: Option<&'a [f64]>,
    /// Internal-id → external-id table (length `node_count`).
    pub external: &'a [ExternalId],
    /// The attached internal-id-aligned numeric node columns, keyed by name (each length `node_count`).
    pub node_columns: &'a HashMap<String, Vec<f64>>,
}
