//! A frozen, owned, `Send + Sync` **read-only graph snapshot** (`rmp` task #350, slice 1 of #335).
//!
//! # Why this exists — the parallel-read enabler
//!
//! Graphus runs **one `!Send` thread per database**: the live graph
//! ([`RecordStoreGraph`](crate::record_graph::RecordStoreGraph)) holds `Rc<RefCell<…>>`, so every
//! read and write serializes on roughly one core regardless of how many the machine has (a heavy
//! read battery was measured at ~0.98 of 16 cores). The proven escape hatch already in the workspace
//! is [`graphus-gds`](graphus_gds): it projects an immutable `Send + Sync` `CsrGraph` **off the live
//! store, on the engine thread**, then runs rayon-parallel algorithms over that frozen copy
//! (measured 6.2–8.4× speedup). [`GraphSnapshot`] **generalizes that projection** into a reusable
//! read-only view that carries not just topology but labels and selected property columns, so future
//! work (`rmp` #336/#340) can run **query reads and aggregations** across all cores against a
//! consistent snapshot.
//!
//! This module is deliberately **additive and self-contained**: it does not touch the executor, the
//! engine loop, or any [`GraphAccess`] implementation. It proves the pattern in isolation; wiring it
//! into the read path is a later task.
//!
//! # Snapshot-consistency contract
//!
//! [`GraphSnapshot::project`] performs **one consistent pass** over a `&dyn GraphAccess`, mirroring
//! [`crate::gds_procedures`]'s `project_from_graph`: it drains the visible node set
//! ([`GraphAccess::scan_nodes`]), builds a membership set, then [`expand`](GraphAccess::expand)s each
//! node exactly once and captures the requested label/property columns. Because the seam handed in is
//! the per-statement [`RecordStoreGraph`](crate::record_graph::RecordStoreGraph) /
//! [`AuthorizedGraph`](crate::authorized_graph::AuthorizedGraph) — which already resolves MVCC
//! visibility and RBAC — **the resulting snapshot is a frozen committed view as of the projecting
//! transaction**: every node, edge, label and property value in it was visible to (and authorized
//! for) that one transaction, and they agree with each other. The caller MUST drive the projection
//! under a single read snapshot (it inherently is, being one synchronous pass on the engine thread).
//! Once [`project`](GraphSnapshot::project) returns, the snapshot is **immutable** — it owns all its
//! data and can be shared by value or `Arc` across threads with no risk of a torn read.
//!
//! # Selective property columns (a RAM contract)
//!
//! Materializing **every** property of every node would duplicate the whole property store in RAM and
//! defeat the purpose. The snapshot therefore captures **only the `(label, property)` columns the
//! caller declares** in the [`SnapshotSpec`]. A node that lacks a declared property contributes
//! [`None`] in that column (so a column is dense — one slot per internal node — and absence is
//! explicit, never confused with a present value). Topology and labels are always captured in full
//! (they are compact); property *values* are opt-in.
//!
//! # `Send + Sync` contract
//!
//! [`GraphSnapshot`] owns plain `Vec`/`HashMap`/`String`/[`Value`] data — **no `Rc`, `RefCell`,
//! `Cell`, or borrows**. Every field is `Send + Sync`, so the whole struct is too; this is asserted
//! at compile time at the bottom of this module. All read methods take `&self` and operate purely on
//! owned data, so any number of threads may read the same snapshot concurrently (e.g. via
//! [`rayon`]'s `par_iter`).
//!
//! # Identifier spaces
//!
//! The snapshot keeps a **dense internal index space** `[0..node_count)` ([`SnapId`]) for
//! cache-friendly, allocation-free addressing, and maps it both ways to the external opaque
//! [`NodeId`] (the [`GraphAccess`] handle): `external[i]` is internal `i`'s [`NodeId`], and
//! `index_of` resolves a [`NodeId`] back to its internal index. Labels and relationship types are
//! **interned** to small `u32` ids ([`LabelId`] / [`RelTypeId`]) so per-node label sets and per-edge
//! type tags are compact integers, not repeated strings.

use std::collections::HashMap;

use graphus_core::Value;

use crate::graph_access::{ExpandDirection, GraphAccess, NodeId, RelId};

/// The dense internal node index of a [`GraphSnapshot`], in the range `0..node_count`.
///
/// CSR addressing and every column are keyed by this index; the mapping back to the external
/// [`NodeId`] is [`GraphSnapshot::external_id`].
pub type SnapId = u32;

/// An interned label id, small and dense (`0..label_count`). Resolve to text with
/// [`GraphSnapshot::label_name`].
pub type LabelId = u32;

/// An interned relationship-type id, small and dense (`0..rel_type_count`). Resolve to text with
/// [`GraphSnapshot::rel_type_name`].
pub type RelTypeId = u32;

// SECURITY (mirrors `graphus_gds::csr` SEC-210, CWE-407): `index_of` is keyed by the external
// `NodeId.0` — a `u64` that, in production, derives from store/element ids that can be influenced by
// client-created data. It MUST stay on a DoS-resistant, randomly-seeded hasher. `std`'s `HashMap`
// uses SipHash 1-3 with a per-process random seed, which resists hash-flooding. Do NOT swap this for
// a fixed-seed fast hasher (`FxHashMap`/`ahash`-without-random-keys): the workspace page-table uses
// `FxHashMap` for perf, but that pattern is unsafe over client-derived keys and must not be copied
// here. The interning maps (`label_ids`/`rel_type_ids`) are keyed by server-side schema strings
// (labels / rel-types), not client values, but stay on the same default for uniformity.
type NodeIndex = HashMap<u64, SnapId>;

/// The set of `(label, property)` columns to materialize when projecting a [`GraphSnapshot`].
///
/// Topology and labels are always captured in full; this spec selects which **property value
/// columns** to additionally materialize (see the module-level "selective property columns" note).
///
/// # Examples
///
/// ```
/// use graphus_cypher::snapshot::SnapshotSpec;
///
/// // Capture the `age` column for `:Person` and the `size` column for `:Company`.
/// let spec = SnapshotSpec::new()
///     .with_column("Person", "age")
///     .with_column("Company", "size");
/// assert_eq!(spec.columns().len(), 2);
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[must_use]
pub struct SnapshotSpec {
    /// The `(label, property)` pairs whose values to materialize as dense columns. Deduplicated,
    /// insertion order is irrelevant (the snapshot keys columns by interned ids).
    columns: Vec<(String, String)>,
}

impl SnapshotSpec {
    /// An empty spec: capture topology and labels, but no property columns.
    pub fn new() -> Self {
        Self::default()
    }

    /// Declares a `(label, property)` column to materialize. Idempotent — re-declaring the same pair
    /// is a no-op, so callers may union specs freely.
    pub fn with_column(mut self, label: impl Into<String>, property: impl Into<String>) -> Self {
        let pair = (label.into(), property.into());
        if !self.columns.contains(&pair) {
            self.columns.push(pair);
        }
        self
    }

    /// The declared `(label, property)` column pairs.
    #[must_use]
    pub fn columns(&self) -> &[(String, String)] {
        &self.columns
    }
}

/// One out-edge or in-edge in the snapshot's CSR adjacency: the neighbour's internal index, the
/// traversed relationship's external [`RelId`], and its interned [`RelTypeId`] (for type-filtering in
/// [`GraphSnapshot::expand`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct CsrEdge {
    /// The internal index of the node at the far end of the edge.
    neighbour: SnapId,
    /// The traversed relationship's external id.
    rel: RelId,
    /// The interned type of the traversed relationship.
    rel_type: RelTypeId,
}

/// One incident relationship discovered by [`GraphSnapshot::expand`]: the relationship, its type, and
/// the **external** [`NodeId`] reached through it. The external id keeps the snapshot a drop-in
/// vocabulary match for [`crate::graph_access::Incident`] (same `rel`/neighbour shape) while also
/// surfacing the resolved type for free.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use]
pub struct SnapIncident {
    /// The traversed relationship's external id.
    pub rel: RelId,
    /// The node at the far end of the relationship (external id).
    pub neighbour: NodeId,
    /// The interned type of the traversed relationship (resolve with
    /// [`GraphSnapshot::rel_type_name`]).
    pub rel_type: RelTypeId,
}

/// A frozen, owned, `Send + Sync` read-only view of a graph, projected off a [`GraphAccess`] seam.
///
/// See the [module documentation](crate::snapshot) for the snapshot-consistency, selective-column,
/// and `Send + Sync` contracts. Construct one with [`GraphSnapshot::project`].
///
/// # Layout
///
/// * **Topology** — dense internal indices `0..node_count`; out-edges of internal `i` live in
///   `out_targets[out_offsets[i]..out_offsets[i+1]]` and in-edges in the parallel `in_*` arrays.
///   Each [`CsrEdge`] carries the relationship id and interned type, so [`expand`](Self::expand) can
///   type-filter without a second lookup.
/// * **Labels** — interned [`LabelId`]s; `node_labels[i]` is internal `i`'s sorted label set, and
///   `label_members[l]` is the sorted internal-id list carrying label `l` (for
///   [`scan_nodes_by_label`](Self::scan_nodes_by_label)).
/// * **Property columns** — `columns[(l, p)][i]` is internal `i`'s value of property `p` *when it
///   carries label `l`* (and [`None`] when absent), for each declared `(label, property)`.
#[derive(Debug, Clone)]
#[must_use]
pub struct GraphSnapshot {
    // ---- identity mapping ----
    /// internal index -> external [`NodeId`] (length `node_count`).
    external: Vec<NodeId>,
    /// external `NodeId.0` -> internal index. SipHash-seeded (see [`NodeIndex`] security note).
    index_of: NodeIndex,

    // ---- CSR out-adjacency ----
    /// Out-edge row offsets, length `node_count + 1`, values in `0..=out_targets.len()`.
    out_offsets: Vec<u32>,
    /// Flattened out-edges in internal-id order.
    out_targets: Vec<CsrEdge>,

    // ---- CSR in-adjacency ----
    /// In-edge row offsets, length `node_count + 1`, values in `0..=in_targets.len()`.
    in_offsets: Vec<u32>,
    /// Flattened in-edges in internal-id order.
    in_targets: Vec<CsrEdge>,

    // ---- labels ----
    /// Label text by interned id (internal index -> name), length `label_count`.
    label_names: Vec<String>,
    /// Label text -> interned id.
    label_ids: HashMap<String, LabelId>,
    /// Per-node sorted label sets (length `node_count`).
    node_labels: Vec<Vec<LabelId>>,
    /// Per-label sorted internal-id member lists (length `label_count`).
    label_members: Vec<Vec<SnapId>>,

    // ---- relationship types ----
    /// Rel-type text by interned id, length `rel_type_count`.
    rel_type_names: Vec<String>,
    /// Rel-type text -> interned id.
    rel_type_ids: HashMap<String, RelTypeId>,

    // ---- property columns ----
    /// Declared `(label, property)` value columns, each dense over internal ids (length
    /// `node_count`). `columns[&(l, p)][i]` is `Some(v)` when internal `i` carries label `l` and has
    /// property `p = v`, else `None`.
    columns: HashMap<(LabelId, PropId), Vec<Option<Value>>>,
    /// Property-name text -> interned id. Property columns are addressed by `(label, property)`
    /// *names* in the public API, so only this forward map is kept (no id->name reverse table is
    /// needed — unlike labels/rel-types, a `PropId` never surfaces publicly).
    prop_ids: HashMap<String, PropId>,
}

/// An interned property-name id, used only as a compact key into [`GraphSnapshot::columns`]. Private
/// because property columns are addressed by `(label, property)` *names* in the public API.
type PropId = u32;

impl GraphSnapshot {
    /// Projects a frozen, owned read-only snapshot off `graph`, capturing the topology, labels, and
    /// the property columns declared in `spec`, under one consistent pass.
    ///
    /// See the [module documentation](crate::snapshot) for the snapshot-consistency and
    /// selective-column contracts. The pass mirrors [`crate::gds_procedures`]'s `project_from_graph`:
    /// drain [`scan_nodes`](GraphAccess::scan_nodes), intern the node set, then
    /// [`expand`](GraphAccess::expand) each node **once** (in both directions) and capture the
    /// requested columns. An edge is included only when **both** endpoints are in the visible node
    /// set, so the snapshot is self-contained.
    ///
    /// Relationship types are read via [`rel_data`](GraphAccess::rel_data) (the
    /// [`Incident`](crate::graph_access::Incident) returned by `expand` does not carry the type); an
    /// edge whose relationship has vanished from the seam between the `expand` and the `rel_data`
    /// (it cannot, within one synchronous snapshot) is conservatively skipped rather than guessed.
    pub fn project(graph: &dyn GraphAccess, spec: &SnapshotSpec) -> Self {
        // ---- nodes: drain the visible set and assign dense internal ids -----------------------
        let node_ids = graph.scan_nodes();
        let n = node_ids.len();

        let mut external: Vec<NodeId> = Vec::with_capacity(n);
        let mut index_of: NodeIndex = HashMap::with_capacity(n);
        for id in &node_ids {
            // `scan_nodes` yields each visible node once, so no de-dup is needed; guard anyway so a
            // hypothetical duplicate maps to the first slot rather than corrupting the index space.
            // The `Entry::Vacant` arm assigns the next dense id only on first sight.
            if let std::collections::hash_map::Entry::Vacant(slot) = index_of.entry(id.0) {
                slot.insert(external.len() as SnapId);
                external.push(*id);
            }
        }
        let n = external.len();

        // ---- labels + property columns: one pass over the node set ----------------------------
        let mut label_names: Vec<String> = Vec::new();
        let mut label_ids: HashMap<String, LabelId> = HashMap::new();
        let mut node_labels: Vec<Vec<LabelId>> = Vec::with_capacity(n);

        // Intern the requested property columns up front (their (LabelId, PropId) keys), so the
        // per-node capture is a small set of integer lookups. A spec column naming a label that no
        // node carries still produces an (empty-by-absence) dense column — a faithful "captured but
        // all None" view, distinct from "not captured".
        let mut prop_ids: HashMap<String, PropId> = HashMap::new();
        let mut columns: HashMap<(LabelId, PropId), Vec<Option<Value>>> = HashMap::new();
        // We pre-intern the label and property of each requested column so the keys are stable; the
        // owned `prop` name is carried alongside for the per-node `node_property` read below.
        let mut requested: Vec<(LabelId, PropId, String)> = Vec::with_capacity(spec.columns.len());
        for (label, prop) in &spec.columns {
            let lid = intern(&mut label_names, &mut label_ids, label);
            let pid = intern_id(&mut prop_ids, prop);
            columns.entry((lid, pid)).or_insert_with(|| vec![None; n]);
            requested.push((lid, pid, prop.clone()));
        }

        for (internal, ext) in external.iter().enumerate() {
            // Labels: intern and sort for deterministic, binary-searchable membership tests.
            let mut labels: Vec<LabelId> = graph
                .node_labels(*ext)
                .unwrap_or_default()
                .iter()
                .map(|l| intern(&mut label_names, &mut label_ids, l))
                .collect();
            labels.sort_unstable();
            labels.dedup();

            // Property columns: for each requested (label, prop), capture the value iff this node
            // carries that label. Reading `node_property` only when the label matches keeps the
            // column semantically "the value for label-carrying nodes" and avoids a wasted read.
            for (lid, pid, prop_name) in &requested {
                if labels.binary_search(lid).is_ok() {
                    let value = graph.node_property(*ext, prop_name);
                    // Key is guaranteed present (inserted above); index is in-bounds (`internal < n`).
                    if let Some(col) = columns.get_mut(&(*lid, *pid)) {
                        col[internal] = value;
                    }
                }
            }

            node_labels.push(labels);
        }

        // Build per-label member lists from the now-complete per-node label sets.
        let label_count = label_names.len();
        let mut label_members: Vec<Vec<SnapId>> = vec![Vec::new(); label_count];
        for (internal, labels) in node_labels.iter().enumerate() {
            for &lid in labels {
                label_members[lid as usize].push(internal as SnapId);
            }
        }
        // Each member list is built in ascending internal-id order already (outer loop is in id
        // order), so it is sorted by construction — no explicit sort needed.

        // ---- topology: expand each node once per direction ------------------------------------
        let mut rel_type_names: Vec<String> = Vec::new();
        let mut rel_type_ids: HashMap<String, RelTypeId> = HashMap::new();

        // Out-adjacency: directed out-edges (anchor is the start node).
        let (out_offsets, out_targets) = Self::build_adjacency(
            graph,
            &external,
            &index_of,
            ExpandDirection::Outgoing,
            &mut rel_type_names,
            &mut rel_type_ids,
        );
        // In-adjacency: directed in-edges (anchor is the end node).
        let (in_offsets, in_targets) = Self::build_adjacency(
            graph,
            &external,
            &index_of,
            ExpandDirection::Incoming,
            &mut rel_type_names,
            &mut rel_type_ids,
        );

        Self {
            external,
            index_of,
            out_offsets,
            out_targets,
            in_offsets,
            in_targets,
            label_names,
            label_ids,
            node_labels,
            label_members,
            rel_type_names,
            rel_type_ids,
            columns,
            prop_ids,
        }
    }

    /// Builds one CSR adjacency (offsets + edges) by expanding every node once in `direction`,
    /// interning rel-types as they appear. An edge to a node outside the visible set is dropped (the
    /// far endpoint has no internal index), keeping the snapshot self-contained.
    fn build_adjacency(
        graph: &dyn GraphAccess,
        external: &[NodeId],
        index_of: &NodeIndex,
        direction: ExpandDirection,
        rel_type_names: &mut Vec<String>,
        rel_type_ids: &mut HashMap<String, RelTypeId>,
    ) -> (Vec<u32>, Vec<CsrEdge>) {
        let n = external.len();
        // First pass per node yields its edge list; we collect into a Vec-of-Vecs then flatten so
        // offsets are exact and the flat buffer is allocated once. (n is bounded by the node count;
        // the temporary per-node Vecs are freed as we flatten.)
        let mut per_node: Vec<Vec<CsrEdge>> = Vec::with_capacity(n);
        let mut total: usize = 0;
        for ext in external {
            let mut edges: Vec<CsrEdge> = Vec::new();
            // Empty `types` = any type (mirrors `GraphAccess::expand`).
            for inc in graph.expand(*ext, direction, &[]) {
                let Some(&neighbour) = index_of.get(&inc.neighbour.0) else {
                    // Far endpoint is outside the visible set — drop the edge.
                    continue;
                };
                // The type comes from `rel_data` (the `Incident` does not carry it). A relationship
                // that cannot be resolved is skipped rather than guessed; within one synchronous
                // snapshot this never happens, but we stay panic-free and self-consistent.
                let Some(data) = graph.rel_data(inc.rel) else {
                    continue;
                };
                let rel_type = intern(rel_type_names, rel_type_ids, &data.rel_type);
                edges.push(CsrEdge {
                    neighbour,
                    rel: inc.rel,
                    rel_type,
                });
            }
            total = total.saturating_add(edges.len());
            per_node.push(edges);
        }

        let mut offsets: Vec<u32> = Vec::with_capacity(n + 1);
        let mut targets: Vec<CsrEdge> = Vec::with_capacity(total);
        offsets.push(0);
        for edges in per_node {
            targets.extend(edges);
            // `targets.len()` is bounded by `total <= edge count`, which fits `u32` for an in-memory
            // projection (mirrors the `graphus_gds` CSR offset width).
            offsets.push(targets.len() as u32);
        }
        (offsets, targets)
    }

    // ---- counts -------------------------------------------------------------------------------

    /// The number of nodes in the snapshot.
    #[must_use]
    pub fn node_count(&self) -> usize {
        self.external.len()
    }

    /// The number of directed out-edges stored (equal to the number of in-edges).
    #[must_use]
    pub fn edge_count(&self) -> usize {
        self.out_targets.len()
    }

    /// The number of interned labels.
    #[must_use]
    pub fn label_count(&self) -> usize {
        self.label_names.len()
    }

    /// The number of interned relationship types.
    #[must_use]
    pub fn rel_type_count(&self) -> usize {
        self.rel_type_names.len()
    }

    // ---- id mapping ---------------------------------------------------------------------------

    /// The external [`NodeId`] of an internal index, or `None` if out of range.
    #[must_use]
    pub fn external_id(&self, internal: SnapId) -> Option<NodeId> {
        self.external.get(internal as usize).copied()
    }

    /// The internal index of an external [`NodeId`], or `None` if the node is not in the snapshot.
    #[must_use]
    pub fn internal_id(&self, node: NodeId) -> Option<SnapId> {
        self.index_of.get(&node.0).copied()
    }

    /// The text of an interned [`LabelId`], or `None` if out of range.
    #[must_use]
    pub fn label_name(&self, label: LabelId) -> Option<&str> {
        self.label_names.get(label as usize).map(String::as_str)
    }

    /// The text of an interned [`RelTypeId`], or `None` if out of range.
    #[must_use]
    pub fn rel_type_name(&self, rel_type: RelTypeId) -> Option<&str> {
        self.rel_type_names
            .get(rel_type as usize)
            .map(String::as_str)
    }

    // ---- reads (the GraphAccess-shaped surface, all `&self`, owned, thread-safe) --------------

    /// All node ids in the snapshot, in internal-id (deterministic) order.
    ///
    /// Mirrors [`GraphAccess::scan_nodes`]. The order is the snapshot's frozen internal order, which
    /// is the order [`scan_nodes`](GraphAccess::scan_nodes) yielded at projection time.
    #[must_use]
    pub fn scan_nodes(&self) -> Vec<NodeId> {
        self.external.clone()
    }

    /// All node ids carrying `label`, in internal-id order — or an empty vec if no node carries it.
    ///
    /// Mirrors [`GraphAccess::scan_nodes_by_label`]. O(members) via the precomputed member list, not
    /// a full scan.
    #[must_use]
    pub fn scan_nodes_by_label(&self, label: &str) -> Vec<NodeId> {
        let Some(&lid) = self.label_ids.get(label) else {
            return Vec::new();
        };
        match self.label_members.get(lid as usize) {
            Some(members) => members
                .iter()
                .filter_map(|&i| self.external.get(i as usize).copied())
                .collect(),
            None => Vec::new(),
        }
    }

    /// The relationships incident to `node` in `direction`, filtered to `types` (empty = any type),
    /// each as a [`SnapIncident`] (relationship, far endpoint, interned type).
    ///
    /// Mirrors [`GraphAccess::expand`], including its self-loop convention: a self-loop is reported
    /// **once per direction it matches**, so an [`ExpandDirection::Both`] expansion over a self-loop
    /// yields it twice (the caller deduplicates by [`RelId`] where distinctness is required). Returns
    /// an empty vec for an unknown node.
    #[must_use]
    pub fn expand(
        &self,
        node: NodeId,
        direction: ExpandDirection,
        types: &[&str],
    ) -> Vec<SnapIncident> {
        let Some(internal) = self.internal_id(node) else {
            return Vec::new();
        };
        // Resolve the requested type names to interned ids once. A requested type that the snapshot
        // never interned (no edge has it) makes the filter trivially exclude everything; collecting
        // only the *known* ids and treating an unknown name as "no match" is equivalent.
        let wanted: Option<Vec<RelTypeId>> = if types.is_empty() {
            None
        } else {
            Some(
                types
                    .iter()
                    .filter_map(|t| self.rel_type_ids.get(*t).copied())
                    .collect(),
            )
        };
        let keep = |e: &CsrEdge| match &wanted {
            None => true,
            Some(ids) => ids.contains(&e.rel_type),
        };

        let mut out = Vec::new();
        let want_out = matches!(direction, ExpandDirection::Outgoing | ExpandDirection::Both);
        let want_in = matches!(direction, ExpandDirection::Incoming | ExpandDirection::Both);
        if want_out {
            for e in self.out_edges(internal) {
                if keep(e) {
                    out.push(self.to_incident(e));
                }
            }
        }
        if want_in {
            for e in self.in_edges(internal) {
                if keep(e) {
                    out.push(self.to_incident(e));
                }
            }
        }
        out
    }

    /// The labels of `node` (sorted), or `None` if the node is not in the snapshot.
    ///
    /// Mirrors [`GraphAccess::node_labels`]. The returned names are resolved from interned ids.
    #[must_use]
    pub fn node_labels(&self, node: NodeId) -> Option<Vec<String>> {
        let internal = self.internal_id(node)?;
        let labels = self.node_labels.get(internal as usize)?;
        Some(
            labels
                .iter()
                .filter_map(|&l| self.label_name(l).map(str::to_owned))
                .collect(),
        )
    }

    /// The value of `node`'s `property`, restricted to a captured `(label, property)` column.
    ///
    /// When `label` is `Some(l)`, returns the value from the captured `(l, property)` column (i.e.
    /// the value the node has *as an `l`-labelled node*), or `None` if that column was not captured,
    /// the node is absent, or the value is absent. When `label` is `None`, searches **every captured
    /// column** for `property` and returns the first present value for this node (so a caller that
    /// does not care which label the column belongs to can still read it). Absent columns and absent
    /// values are both `None` — distinguish them with [`has_column`](Self::has_column) if needed.
    ///
    /// Unlike [`GraphAccess::node_property`], this reads **only materialized columns**: a property
    /// not named in the [`SnapshotSpec`] is always `None` here (it was deliberately not captured —
    /// see the module's selective-column note).
    #[must_use]
    pub fn node_property(
        &self,
        label: Option<&str>,
        node: NodeId,
        property: &str,
    ) -> Option<Value> {
        let internal = self.internal_id(node)? as usize;
        let pid = self.prop_ids.get(property).copied()?;
        match label {
            Some(l) => {
                let lid = self.label_ids.get(l).copied()?;
                self.columns
                    .get(&(lid, pid))?
                    .get(internal)
                    .cloned()
                    .flatten()
            }
            None => {
                // Search every captured column on this property id; return the first present value.
                self.columns
                    .iter()
                    .filter(|((_, p), _)| *p == pid)
                    .find_map(|(_, col)| col.get(internal).cloned().flatten())
            }
        }
    }

    /// Whether a `(label, property)` column was materialized in this snapshot.
    #[must_use]
    pub fn has_column(&self, label: &str, property: &str) -> bool {
        let (Some(&lid), Some(&pid)) = (self.label_ids.get(label), self.prop_ids.get(property))
        else {
            return false;
        };
        self.columns.contains_key(&(lid, pid))
    }

    /// The total degree of `node` (out-degree + in-degree), or `0` if the node is not in the
    /// snapshot. A self-loop contributes to both, so it counts **twice** (consistent with
    /// [`expand`](Self::expand)`(Both)` reporting it twice).
    #[must_use]
    pub fn degree(&self, node: NodeId) -> usize {
        match self.internal_id(node) {
            Some(i) => self.out_degree_internal(i) + self.in_degree_internal(i),
            None => 0,
        }
    }

    /// The out-degree of `node`, or `0` if the node is not in the snapshot.
    #[must_use]
    pub fn out_degree(&self, node: NodeId) -> usize {
        self.internal_id(node)
            .map_or(0, |i| self.out_degree_internal(i))
    }

    /// The in-degree of `node`, or `0` if the node is not in the snapshot.
    #[must_use]
    pub fn in_degree(&self, node: NodeId) -> usize {
        self.internal_id(node)
            .map_or(0, |i| self.in_degree_internal(i))
    }

    /// A captured `(label, property)` column as `(NodeId, Value)` rows for **aggregation**: one row
    /// per node that carries `label` **and** has a present value for `property`, in internal-id
    /// order. Returns an empty vec if the column was not captured.
    ///
    /// This is the snapshot analogue of
    /// [`GraphAccess::columnar_label_property_scan`](crate::graph_access::GraphAccess::columnar_label_property_scan)'s
    /// `rows`: it is exactly the `(node, value)` set a `MATCH (n:label) WHERE n.property IS NOT NULL
    /// RETURN n, n.property` would produce against this frozen view, ready to fold (`sum`/`count`/…)
    /// in parallel.
    #[must_use]
    pub fn label_property_rows(&self, label: &str, property: &str) -> Vec<(NodeId, Value)> {
        let (Some(&lid), Some(&pid)) = (self.label_ids.get(label), self.prop_ids.get(property))
        else {
            return Vec::new();
        };
        let Some(col) = self.columns.get(&(lid, pid)) else {
            return Vec::new();
        };
        col.iter()
            .enumerate()
            .filter_map(|(i, v)| {
                let value = v.clone()?;
                let node = self.external.get(i)?;
                Some((*node, value))
            })
            .collect()
    }

    // ---- internal helpers ---------------------------------------------------------------------

    /// The out-edges of internal index `i` (empty slice if out of range).
    fn out_edges(&self, i: SnapId) -> &[CsrEdge] {
        Self::row(&self.out_offsets, &self.out_targets, i)
    }

    /// The in-edges of internal index `i` (empty slice if out of range).
    fn in_edges(&self, i: SnapId) -> &[CsrEdge] {
        Self::row(&self.in_offsets, &self.in_targets, i)
    }

    fn out_degree_internal(&self, i: SnapId) -> usize {
        self.out_edges(i).len()
    }

    fn in_degree_internal(&self, i: SnapId) -> usize {
        self.in_edges(i).len()
    }

    /// The CSR row for internal index `i`, bounds-checked to an empty slice (never panics).
    fn row<'a>(offsets: &[u32], targets: &'a [CsrEdge], i: SnapId) -> &'a [CsrEdge] {
        let i = i as usize;
        let (Some(&start), Some(&end)) = (offsets.get(i), offsets.get(i + 1)) else {
            return &[];
        };
        targets.get(start as usize..end as usize).unwrap_or(&[])
    }

    /// Resolves a [`CsrEdge`] to a public [`SnapIncident`] (mapping the neighbour back to external).
    fn to_incident(&self, e: &CsrEdge) -> SnapIncident {
        // `e.neighbour` is an internal index we ourselves assigned, so `external_id` is infallible;
        // fall back defensively to the same id rather than panicking if ever out of range.
        let neighbour = self
            .external_id(e.neighbour)
            .unwrap_or(NodeId(u64::from(e.neighbour)));
        SnapIncident {
            rel: e.rel,
            neighbour,
            rel_type: e.rel_type,
        }
    }
}

/// Interns `value` into a `names`/`ids` pair (keeping both directions), returning its dense id
/// (idempotent). Shared by the label and rel-type interning, which expose an id->name reverse lookup.
fn intern(names: &mut Vec<String>, ids: &mut HashMap<String, u32>, value: &str) -> u32 {
    if let Some(&id) = ids.get(value) {
        return id;
    }
    // `names.len()` is bounded by the number of distinct interned strings, which is far below
    // `u32::MAX` for any realistic schema; the `as` cast is safe in that domain.
    let id = names.len() as u32;
    ids.insert(value.to_owned(), id);
    names.push(value.to_owned());
    id
}

/// Interns `value` into a name->id map alone, returning its dense id (idempotent). Used for property
/// names, which never need an id->name reverse lookup (the public API addresses columns by name).
fn intern_id(ids: &mut HashMap<String, u32>, value: &str) -> u32 {
    if let Some(&id) = ids.get(value) {
        return id;
    }
    // The next dense id is the current map size (ids are assigned 0,1,2,… on first sight).
    let id = ids.len() as u32;
    ids.insert(value.to_owned(), id);
    id
}

// `GraphSnapshot` owns only `Send + Sync` data (Vec / HashMap / String / Value, all of which are
// `Send + Sync`) — no `Rc`, `RefCell`, `Cell`, or borrows. This compile-time assertion pins that:
// if a future field re-introduces a non-thread-safe type, the build fails here rather than at a
// distant `rayon`/`spawn` call site. (No `unsafe`: this is a pure trait-bound check.)
const _: fn() = || {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<GraphSnapshot>();
    assert_send_sync::<SnapshotSpec>();
    assert_send_sync::<SnapIncident>();
};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graph_access::MemGraph;
    use std::collections::BTreeSet;

    /// A non-trivial source graph: `count` `:Person` nodes (each with a numeric `age`), `count / 4`
    /// `:Company` nodes (each with a numeric `size`), plus a deterministic web of `KNOWS` (person→
    /// person) and `WORKS_AT` (person→company) relationships and a couple of self-loops.
    fn build_source(count: usize) -> (MemGraph, Vec<NodeId>, Vec<NodeId>) {
        let mut g = MemGraph::new();
        let mut people = Vec::with_capacity(count);
        for i in 0..count {
            let p = g.add_node(["Person"], [("age", Value::Integer((i % 80) as i64 + 18))]);
            people.push(p);
        }
        let mut companies = Vec::new();
        for i in 0..(count / 4).max(1) {
            let c = g.add_node(
                ["Company"],
                [("size", Value::Integer((i as i64 + 1) * 100))],
            );
            companies.push(c);
        }
        // KNOWS: a deterministic ring + chords so degrees vary.
        for i in 0..people.len() {
            let a = people[i];
            let b = people[(i + 1) % people.len()];
            g.add_rel("KNOWS", a, b, [] as [(&str, Value); 0]);
            if i % 3 == 0 {
                let c = people[(i + 7) % people.len()];
                g.add_rel("KNOWS", a, c, [] as [(&str, Value); 0]);
            }
        }
        // WORKS_AT: each person to one company.
        if !companies.is_empty() {
            for (i, &p) in people.iter().enumerate() {
                g.add_rel(
                    "WORKS_AT",
                    p,
                    companies[i % companies.len()],
                    [] as [(&str, Value); 0],
                );
            }
        }
        // A self-loop on the first person, to exercise the twice-counted degree convention.
        if let Some(&p0) = people.first() {
            g.add_rel("KNOWS", p0, p0, [] as [(&str, Value); 0]);
        }
        (g, people, companies)
    }

    fn person_age_spec() -> SnapshotSpec {
        SnapshotSpec::new()
            .with_column("Person", "age")
            .with_column("Company", "size")
    }

    /// Ground-truth sum+count of `age` over `:Person`, computed directly over the source graph, with
    /// a **fixed reduction order** (ascending node id) so a floating-point fold is deterministic.
    fn ground_truth_age(g: &MemGraph) -> (i64, usize) {
        let mut nodes = g.scan_nodes_by_label("Person");
        nodes.sort_unstable();
        let mut sum = 0i64;
        let mut count = 0usize;
        for n in nodes {
            if let Some(Value::Integer(a)) = g.node_property(n, "age") {
                sum += a;
                count += 1;
            }
        }
        (sum, count)
    }

    #[test]
    fn projects_topology_labels_and_columns() {
        let (g, people, companies) = build_source(40);
        let snap = GraphSnapshot::project(&g, &person_age_spec());

        // Node set matches the source (same count, same ids).
        assert_eq!(snap.node_count(), g.node_count());
        let snap_nodes: BTreeSet<u64> = snap.scan_nodes().iter().map(|n| n.0).collect();
        let src_nodes: BTreeSet<u64> = g.scan_nodes().iter().map(|n| n.0).collect();
        assert_eq!(snap_nodes, src_nodes);

        // Label scans match the source.
        let snap_people: BTreeSet<u64> = snap
            .scan_nodes_by_label("Person")
            .iter()
            .map(|n| n.0)
            .collect();
        let src_people: BTreeSet<u64> = g
            .scan_nodes_by_label("Person")
            .iter()
            .map(|n| n.0)
            .collect();
        assert_eq!(snap_people, src_people);
        assert_eq!(snap.scan_nodes_by_label("Person").len(), people.len());
        assert_eq!(snap.scan_nodes_by_label("Company").len(), companies.len());
        // An absent label yields an empty scan, not a panic.
        assert!(snap.scan_nodes_by_label("Nonexistent").is_empty());

        // Captured columns are present; an un-captured one is not.
        assert!(snap.has_column("Person", "age"));
        assert!(snap.has_column("Company", "size"));
        assert!(!snap.has_column("Person", "name"));

        // Property values match the source for captured columns.
        for &p in &people {
            assert_eq!(
                snap.node_property(Some("Person"), p, "age"),
                g.node_property(p, "age"),
                "age mismatch for {p:?}"
            );
            // Label-agnostic read finds the same value.
            assert_eq!(
                snap.node_property(None, p, "age"),
                g.node_property(p, "age")
            );
        }
        // An un-captured property reads as None even though the source has it.
        assert_eq!(snap.node_property(Some("Person"), people[0], "name"), None);
    }

    #[test]
    fn expand_matches_source_with_type_filter_and_self_loop() {
        let (g, people, _companies) = build_source(20);
        let snap = GraphSnapshot::project(&g, &person_age_spec());

        for &p in &people {
            // Outgoing KNOWS: same neighbour multiset as the source.
            let mut snap_out: Vec<u64> = snap
                .expand(p, ExpandDirection::Outgoing, &["KNOWS"])
                .iter()
                .map(|i| i.neighbour.0)
                .collect();
            let mut src_out: Vec<u64> = g
                .expand(p, ExpandDirection::Outgoing, &["KNOWS".to_owned()])
                .iter()
                .map(|i| i.neighbour.0)
                .collect();
            snap_out.sort_unstable();
            src_out.sort_unstable();
            assert_eq!(snap_out, src_out, "outgoing KNOWS mismatch for {p:?}");

            // Both directions, any type: same neighbour multiset.
            let mut snap_both: Vec<u64> = snap
                .expand(p, ExpandDirection::Both, &[])
                .iter()
                .map(|i| i.neighbour.0)
                .collect();
            let mut src_both: Vec<u64> = g
                .expand(p, ExpandDirection::Both, &[])
                .iter()
                .map(|i| i.neighbour.0)
                .collect();
            snap_both.sort_unstable();
            src_both.sort_unstable();
            assert_eq!(snap_both, src_both, "both-direction mismatch for {p:?}");
        }

        // The self-loop on person[0] is reported twice under Both (once per side), matching MemGraph.
        let p0 = people[0];
        let self_loops = snap
            .expand(p0, ExpandDirection::Both, &["KNOWS"])
            .iter()
            .filter(|i| i.neighbour == p0)
            .count();
        assert_eq!(
            self_loops, 2,
            "self-loop must be reported once per direction"
        );

        // Resolved rel-type names round-trip.
        let inc = snap.expand(p0, ExpandDirection::Outgoing, &["KNOWS"]);
        assert!(!inc.is_empty());
        assert!(
            inc.iter()
                .all(|i| snap.rel_type_name(i.rel_type) == Some("KNOWS"))
        );

        // A type the snapshot never interned excludes everything (no panic).
        assert!(
            snap.expand(p0, ExpandDirection::Outgoing, &["NEVER_SEEN"])
                .is_empty()
        );
    }

    #[test]
    fn degree_matches_source() {
        let (g, people, _companies) = build_source(30);
        let snap = GraphSnapshot::project(&g, &person_age_spec());

        for &p in &people {
            // Ground-truth total degree from the source: incident rels in BOTH directions, with the
            // self-loop counted twice (it touches as start AND end).
            let src_both = g.expand(p, ExpandDirection::Both, &[]).len();
            assert_eq!(snap.degree(p), src_both, "degree mismatch for {p:?}");
            let src_out = g.expand(p, ExpandDirection::Outgoing, &[]).len();
            assert_eq!(snap.out_degree(p), src_out);
            let src_in = g.expand(p, ExpandDirection::Incoming, &[]).len();
            assert_eq!(snap.in_degree(p), src_in);
        }
    }

    #[test]
    fn label_property_rows_match_source() {
        let (g, _people, _companies) = build_source(50);
        let snap = GraphSnapshot::project(&g, &person_age_spec());

        let mut rows = snap.label_property_rows("Person", "age");
        rows.sort_by_key(|(n, _)| n.0);
        // Every Person with a present age appears exactly once with the right value.
        for (n, v) in &rows {
            assert_eq!(g.node_property(*n, "age"), Some(v.clone()));
        }
        let (_, count) = ground_truth_age(&g);
        assert_eq!(rows.len(), count);
        // An un-captured column yields no rows.
        assert!(snap.label_property_rows("Person", "name").is_empty());
    }

    /// THE ACCEPTANCE PROOF: serial and rayon-parallel folds over the snapshot are bit-identical to
    /// each other and to a ground truth computed over the source.
    #[test]
    fn parallel_and_serial_aggregations_are_bit_identical() {
        use rayon::prelude::*;

        let (g, people, _companies) = build_source(500);
        let snap = GraphSnapshot::project(&g, &person_age_spec());

        let (gt_sum, gt_count) = ground_truth_age(&g);

        // --- label-property aggregation (sum + count of age over :Person) ---
        // Rows in a fixed (internal-id) order so the sum's reduction order is deterministic.
        let rows = snap.label_property_rows("Person", "age");
        assert_eq!(rows.len(), gt_count);

        // Serial fold.
        let serial_sum: i64 = rows
            .iter()
            .map(|(_, v)| match v {
                Value::Integer(a) => *a,
                _ => 0,
            })
            .sum();
        let serial_count = rows.len();

        // Parallel fold. Integer addition is associative AND commutative, so any rayon reduction
        // tree yields the identical sum regardless of split — bit-identical to the serial result.
        let parallel_sum: i64 = rows
            .par_iter()
            .map(|(_, v)| match v {
                Value::Integer(a) => *a,
                _ => 0,
            })
            .sum();
        let parallel_count = rows.par_iter().count();

        assert_eq!(serial_sum, parallel_sum, "serial vs parallel sum");
        assert_eq!(serial_count, parallel_count, "serial vs parallel count");
        assert_eq!(serial_sum, gt_sum, "snapshot sum vs ground truth");
        assert_eq!(serial_count, gt_count, "snapshot count vs ground truth");

        // --- per-node degree for ALL nodes, serial vs parallel vs source ---
        let nodes = snap.scan_nodes();
        let serial_degrees: Vec<(u64, usize)> =
            nodes.iter().map(|&n| (n.0, snap.degree(n))).collect();
        let parallel_degrees: Vec<(u64, usize)> =
            nodes.par_iter().map(|&n| (n.0, snap.degree(n))).collect();
        assert_eq!(
            serial_degrees, parallel_degrees,
            "serial vs parallel degree vectors must be identical (same input order)"
        );
        // And each equals the source's both-direction incident count.
        for &p in &people {
            let want = g.expand(p, ExpandDirection::Both, &[]).len();
            let got = snap.degree(p);
            assert_eq!(got, want, "degree vs source for {p:?}");
        }
    }

    /// The snapshot is `Send + Sync` enough to move into `rayon::scope` and read from worker threads.
    #[test]
    fn snapshot_moves_into_rayon_scope() {
        let (g, _people, _companies) = build_source(64);
        let snap = GraphSnapshot::project(&g, &person_age_spec());

        let total_degree = std::sync::atomic::AtomicUsize::new(0);
        rayon::scope(|s| {
            // Borrow the snapshot across threads (shared &T requires T: Sync).
            let snap_ref = &snap;
            let counter = &total_degree;
            for chunk in snap_ref.scan_nodes().chunks(8) {
                let chunk = chunk.to_vec();
                s.spawn(move |_| {
                    let local: usize = chunk.iter().map(|&n| snap_ref.degree(n)).sum();
                    counter.fetch_add(local, std::sync::atomic::Ordering::Relaxed);
                });
            }
        });

        // Sum of all degrees = 2 * edge_count for out+in adjacency (each stored directed edge is one
        // out-edge for its source and one in-edge for its target).
        let expected: usize = snap.scan_nodes().iter().map(|&n| snap.degree(n)).sum();
        assert_eq!(
            total_degree.load(std::sync::atomic::Ordering::Relaxed),
            expected
        );
    }

    /// Projecting twice from the same (unchanged) source yields identical snapshots.
    #[test]
    fn projection_is_deterministic() {
        let (g, people, _companies) = build_source(40);
        let spec = person_age_spec();
        let a = GraphSnapshot::project(&g, &spec);
        let b = GraphSnapshot::project(&g, &spec);

        assert_eq!(a.node_count(), b.node_count());
        assert_eq!(a.edge_count(), b.edge_count());
        assert_eq!(a.label_count(), b.label_count());
        assert_eq!(a.rel_type_count(), b.rel_type_count());

        // Same internal id space (scan order is the source's frozen order, identical across runs).
        assert_eq!(a.scan_nodes(), b.scan_nodes());

        // Same labels, degrees, expansions, and column values per node.
        for &p in &people {
            assert_eq!(a.node_labels(p), b.node_labels(p));
            assert_eq!(a.degree(p), b.degree(p));
            assert_eq!(
                a.node_property(Some("Person"), p, "age"),
                b.node_property(Some("Person"), p, "age")
            );
            let mut ea: Vec<u64> = a
                .expand(p, ExpandDirection::Both, &[])
                .iter()
                .map(|i| i.neighbour.0)
                .collect();
            let mut eb: Vec<u64> = b
                .expand(p, ExpandDirection::Both, &[])
                .iter()
                .map(|i| i.neighbour.0)
                .collect();
            ea.sort_unstable();
            eb.sort_unstable();
            assert_eq!(ea, eb);
        }

        // The aggregation rows are identical (same order, same values).
        assert_eq!(
            a.label_property_rows("Person", "age"),
            b.label_property_rows("Person", "age")
        );
    }

    #[test]
    fn empty_graph_projects_cleanly() {
        let g = MemGraph::new();
        let snap = GraphSnapshot::project(&g, &person_age_spec());
        assert_eq!(snap.node_count(), 0);
        assert_eq!(snap.edge_count(), 0);
        assert!(snap.scan_nodes().is_empty());
        assert!(snap.scan_nodes_by_label("Person").is_empty());
        assert_eq!(snap.degree(NodeId(0)), 0);
        assert!(snap.label_property_rows("Person", "age").is_empty());
    }

    #[test]
    fn spec_dedups_columns() {
        let spec = SnapshotSpec::new()
            .with_column("Person", "age")
            .with_column("Person", "age")
            .with_column("Company", "size");
        assert_eq!(spec.columns().len(), 2);
    }

    #[test]
    fn unknown_node_reads_are_safe() {
        let (g, _people, _companies) = build_source(8);
        let snap = GraphSnapshot::project(&g, &person_age_spec());
        let ghost = NodeId(u64::MAX);
        assert_eq!(snap.internal_id(ghost), None);
        assert!(snap.node_labels(ghost).is_none());
        assert_eq!(snap.node_property(Some("Person"), ghost, "age"), None);
        assert_eq!(snap.degree(ghost), 0);
        assert!(snap.expand(ghost, ExpandDirection::Both, &[]).is_empty());
    }
}
