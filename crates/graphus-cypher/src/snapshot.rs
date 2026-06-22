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
//! caller declares** in the [`SnapshotSpec`] — for nodes via [`SnapshotSpec::with_column`] and for
//! relationships via [`SnapshotSpec::with_rel_column`]. An entity that lacks a declared property
//! contributes [`None`] in that column (so a column is dense — one slot per internal node / per
//! distinct relationship — and absence is explicit, never confused with a present value). Topology
//! and labels are always captured in full (they are compact); property *values* are opt-in.
//!
//! Every captured value is a full [`graphus_core::Value`], stored verbatim, so **every** value
//! variant — `Integer`, `Float`, `String`, `Boolean`, `Bytes`, `List`, `Map`, the temporal classes
//! (`Date`/`LocalTime`/`ZonedTime`/`LocalDateTime`/`ZonedDateTime`/`Duration`) and `Point` — round-
//! trips losslessly through the snapshot (proven by the `every_value_variant_round_trips` test).
//!
//! # Derived equality lookup (the read-only "index" piece)
//!
//! Beyond the dense columns, [`project`](GraphSnapshot::project) builds an in-memory
//! `(label, property, value-key) -> [node]` map so that [`snapshot_seek_eq`](GraphSnapshot::snapshot_seek_eq)
//! answers `MATCH (n:label) WHERE n.property = $v` in (bucket-sized) time instead of scanning the
//! whole column. The *value-key* is built so that **Cypher-equal values collide** (so `Integer(1)`
//! and `Float(1.0)` share a bucket, `-0.0` and `+0.0` share a bucket), and the bucket is then re-
//! checked against the exact three-valued [`crate::equality::equals`] operator, so the result is **bit-
//! identical to a scan-and-filter** over the same column (proven by the
//! `seek_eq_matches_scan_and_filter` test). See [`snapshot_seek_eq`](GraphSnapshot::snapshot_seek_eq)
//! for how `NaN`/`Null`/`List`/`Map` targets are handled.
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
use graphus_index::keycodec;

use crate::equality::equals;
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

/// The set of property columns to materialize when projecting a [`GraphSnapshot`].
///
/// Topology and labels are always captured in full; this spec selects which **property value
/// columns** to additionally materialize (see the module-level "selective property columns" note) —
/// both **node** columns keyed by `(label, property)` ([`with_column`](Self::with_column)) and
/// **relationship** columns keyed by `(rel_type, property)` ([`with_rel_column`](Self::with_rel_column)).
///
/// # Examples
///
/// ```
/// use graphus_cypher::snapshot::SnapshotSpec;
///
/// // Capture the `age` column for `:Person`, the `size` column for `:Company`, and the `since`
/// // column for the `KNOWS` relationship.
/// let spec = SnapshotSpec::new()
///     .with_column("Person", "age")
///     .with_column("Company", "size")
///     .with_rel_column("KNOWS", "since");
/// assert_eq!(spec.columns().len(), 2);
/// assert_eq!(spec.rel_columns().len(), 1);
/// ```
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[must_use]
pub struct SnapshotSpec {
    /// The `(label, property)` pairs whose **node** values to materialize as dense columns.
    /// Deduplicated, insertion order is irrelevant (the snapshot keys columns by interned ids).
    columns: Vec<(String, String)>,
    /// The `(rel_type, property)` pairs whose **relationship** values to materialize as dense
    /// columns. Deduplicated; same contract as [`columns`](Self::columns) but keyed by rel-type.
    rel_columns: Vec<(String, String)>,
}

impl SnapshotSpec {
    /// An empty spec: capture topology and labels, but no property columns.
    pub fn new() -> Self {
        Self::default()
    }

    /// Declares a `(label, property)` **node** column to materialize. Idempotent — re-declaring the
    /// same pair is a no-op, so callers may union specs freely.
    pub fn with_column(mut self, label: impl Into<String>, property: impl Into<String>) -> Self {
        let pair = (label.into(), property.into());
        if !self.columns.contains(&pair) {
            self.columns.push(pair);
        }
        self
    }

    /// Declares a `(rel_type, property)` **relationship** column to materialize. Idempotent — re-
    /// declaring the same pair is a no-op. The column is dense over the snapshot's distinct
    /// relationships (one slot per [`RelId`]), capturing the value the relationship holds *when it is
    /// of `rel_type`* (and [`None`] when it is a different type or lacks the property).
    pub fn with_rel_column(
        mut self,
        rel_type: impl Into<String>,
        property: impl Into<String>,
    ) -> Self {
        let pair = (rel_type.into(), property.into());
        if !self.rel_columns.contains(&pair) {
            self.rel_columns.push(pair);
        }
        self
    }

    /// The declared `(label, property)` **node** column pairs.
    #[must_use]
    pub fn columns(&self) -> &[(String, String)] {
        &self.columns
    }

    /// The declared `(rel_type, property)` **relationship** column pairs.
    #[must_use]
    pub fn rel_columns(&self) -> &[(String, String)] {
        &self.rel_columns
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
///   carries label `l`* (and [`None`] when absent), for each declared `(label, property)`;
///   `rel_columns[(t, p)][e]` is the value of property `p` on the relationship at internal edge
///   index `e` *when it is of type `t`* (and [`None`] when absent), for each declared
///   `(rel_type, property)`.
/// * **Equality index** — `eq_index[(l, p)]` maps a Cypher-equality value-key to the internal ids of
///   the `l`-labelled nodes whose `p` equals that key, the lookup structure behind
///   [`snapshot_seek_eq`](Self::snapshot_seek_eq).
#[derive(Debug, Clone)]
#[must_use]
pub struct GraphSnapshot {
    // ---- node identity mapping ----
    /// internal index -> external [`NodeId`] (length `node_count`).
    external: Vec<NodeId>,
    /// external `NodeId.0` -> internal index. SipHash-seeded (see [`NodeIndex`] security note).
    index_of: NodeIndex,

    // ---- relationship identity mapping ----
    /// internal edge index -> external [`RelId`] (length `edge_count`, one slot per **distinct**
    /// relationship). A relationship that appears in both adjacencies (every non-dangling edge does:
    /// once out of its start, once into its end) occupies a single internal edge index.
    rel_external: Vec<RelId>,
    /// external `RelId.0` -> internal edge index. SipHash-seeded (see [`NodeIndex`] security note;
    /// rel ids are client-influenced just like node ids).
    rel_index_of: NodeIndex,

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
    columns: NodeColumns,
    /// Property-name text -> interned id. Property columns are addressed by `(label, property)` and
    /// `(rel_type, property)` *names* in the public API, so only this forward map is kept (no
    /// id->name reverse table is needed — unlike labels/rel-types, a `PropId` never surfaces
    /// publicly). Shared by node and relationship columns (a property name interns once).
    prop_ids: HashMap<String, PropId>,

    // ---- relationship property columns ----
    /// Declared `(rel_type, property)` value columns, each dense over internal edge ids (length
    /// `edge_count`). `rel_columns[&(t, p)][e]` is `Some(v)` when the relationship at internal edge
    /// `e` is of type `t` and has property `p = v`, else `None`.
    rel_columns: RelColumns,

    // ---- derived equality lookup index ----
    /// `(LabelId, PropId, value-key) -> sorted internal ids`: the nodes carrying that label whose
    /// value of that property is Cypher-equal to the value the key encodes. Built from the node
    /// `columns` at projection time; the key (see [`equality_key`]) collides Cypher-equal values so a
    /// seek for `Integer(1)` finds a stored `Float(1.0)`. The candidate list is re-checked against
    /// the exact [`equals`] operator inside [`snapshot_seek_eq`](Self::snapshot_seek_eq), so it is
    /// exact even where the key over-approximates.
    eq_index: EqIndex,
}

/// An interned property-name id, used only as a compact key into [`GraphSnapshot::columns`]. Private
/// because property columns are addressed by `(label, property)` *names* in the public API.
type PropId = u32;

/// The materialized **node** property columns: `(label, property) -> dense per-node value column`.
type NodeColumns = HashMap<(LabelId, PropId), Vec<Option<Value>>>;

/// The materialized **relationship** property columns: `(rel_type, property) -> dense per-edge value
/// column` (dense over the snapshot's distinct-relationship internal edge-id space).
type RelColumns = HashMap<(RelTypeId, PropId), Vec<Option<Value>>>;

/// The derived equality lookup index: `(label, property, value-key) -> sorted internal node ids`.
type EqIndex = HashMap<(LabelId, PropId, Vec<u8>), Vec<SnapId>>;

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
        let mut columns: NodeColumns = HashMap::new();
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

        // ---- relationship identity + property columns -----------------------------------------
        // A dense internal edge-id space keyed by RelId, captured in one pass over every included
        // relationship (each visible node's outgoing expansion visits its out-edges once; an edge is
        // included only when both endpoints are visible, so every snapshot edge appears here exactly
        // once). This is independent of the CSR layout above (which keys edges by external RelId), so
        // it does not perturb that code path.
        let (rel_external, rel_index_of, rel_columns) = Self::build_rel_columns(
            graph,
            &external,
            &index_of,
            spec,
            &mut rel_type_names,
            &mut rel_type_ids,
            &mut prop_ids,
        );

        // ---- derived equality lookup index ----------------------------------------------------
        let eq_index = build_eq_index(&columns);

        Self {
            external,
            index_of,
            rel_external,
            rel_index_of,
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
            rel_columns,
            eq_index,
        }
    }

    /// Builds a **single-column** snapshot directly from an already-scanned label column (`rmp` task
    /// #352, phase 1 of #336): the parallel-read enabler's lean projection.
    ///
    /// Unlike [`project`](Self::project), which performs its own full pass over a `&dyn GraphAccess`
    /// (capturing topology + every requested column, and registering its own read footprint), this
    /// constructor takes the result of the seam's **own** authoritative candidate pass — the exact same
    /// pass the serial columnar scan runs, which has *already* registered the identical SSI / predicate
    /// read-markers on the engine thread — and freezes it into an owned, `Send + Sync` view. It is the
    /// bridge that lets the executor fold a `MATCH (n:label) RETURN <agg>(n.property)` across all cores
    /// while keeping serializability byte-for-byte what the serial path would produce (see
    /// [`RecordStoreGraph::project_snapshot`](crate::record_graph::RecordStoreGraph) and the
    /// [`GraphAccess::project_snapshot`](crate::graph_access::GraphAccess::project_snapshot) contract).
    ///
    /// # Inputs
    ///
    /// * `members` — **every** visible node carrying `label` (present-property or not). This is the
    ///   `scan_nodes_by_label(label)` set, so [`scan_nodes_by_label`](Self::scan_nodes_by_label)`.len()`
    ///   on the result is the exact `count(*)` value.
    /// * `rows` — the `(node, value)` pairs whose `property` is **present** (a subset of `members`),
    ///   exactly what the row path would yield; they become the `(label, property)` column and the
    ///   payload of [`label_property_rows`](Self::label_property_rows).
    ///
    /// # Topology
    ///
    /// No edges are captured — the parallel aggregation reads only the label membership and the one
    /// property column. The result is therefore a faithful **node + single-column** view: `expand`,
    /// `degree`, and relationship columns are all empty on it, which is correct for the aggregation it
    /// serves (it never traverses).
    ///
    /// # Panics
    ///
    /// Never. A `row` whose node is not in `members` (which cannot happen for a single consistent pass,
    /// since every present-property node is also a member) is simply ignored rather than panicking,
    /// keeping the constructor total.
    pub(crate) fn from_label_column(
        label: &str,
        property: &str,
        members: Vec<NodeId>,
        rows: Vec<(NodeId, Value)>,
    ) -> Self {
        let n = members.len();

        // Dense internal id space over the label members (the snapshot's whole node set).
        let mut external: Vec<NodeId> = Vec::with_capacity(n);
        let mut index_of: NodeIndex = HashMap::with_capacity(n);
        for id in &members {
            if let std::collections::hash_map::Entry::Vacant(slot) = index_of.entry(id.0) {
                slot.insert(external.len() as SnapId);
                external.push(*id);
            }
        }
        let n = external.len();

        // One interned label; every member carries it (they came from a label scan), so the per-node
        // label set is the single label id and the member list is the full id space in order.
        let mut label_names: Vec<String> = Vec::new();
        let mut label_ids: HashMap<String, LabelId> = HashMap::new();
        let lid = intern(&mut label_names, &mut label_ids, label);
        let node_labels: Vec<Vec<LabelId>> = vec![vec![lid]; n];
        let label_members: Vec<Vec<SnapId>> = vec![(0..n as SnapId).collect()];

        // One interned property; the dense column is filled from the present rows.
        let mut prop_ids: HashMap<String, PropId> = HashMap::new();
        let pid = intern_id(&mut prop_ids, property);
        let mut column: Vec<Option<Value>> = vec![None; n];
        for (node, value) in rows {
            // A present-property node is necessarily a member; ignore a stray id defensively (total).
            if let Some(&internal) = index_of.get(&node.0) {
                column[internal as usize] = Some(value);
            }
        }
        let mut columns: NodeColumns = HashMap::new();
        columns.insert((lid, pid), column);

        // The derived equality lookup over the single column (so `snapshot_seek_eq` keeps working).
        let eq_index = build_eq_index(&columns);

        // No topology / relationships captured (the aggregation never traverses): empty CSR + rel maps.
        let out_offsets = vec![0u32; n + 1];
        let in_offsets = vec![0u32; n + 1];

        Self {
            external,
            index_of,
            rel_external: Vec::new(),
            rel_index_of: HashMap::new(),
            out_offsets,
            out_targets: Vec::new(),
            in_offsets,
            in_targets: Vec::new(),
            label_names,
            label_ids,
            node_labels,
            label_members,
            rel_type_names: Vec::new(),
            rel_type_ids: HashMap::new(),
            columns,
            prop_ids,
            rel_columns: HashMap::new(),
            eq_index,
        }
    }

    /// Builds the relationship identity map (`RelId` -> dense internal edge id) and the declared
    /// `(rel_type, property)` value columns, dense over that edge-id space.
    ///
    /// Walks each visible node's **outgoing** expansion once; an edge is included only when its far
    /// endpoint is also visible (matching [`build_adjacency`]), so every relationship in the snapshot
    /// is interned exactly once. For each requested `(rel_type, property)` column, the value is read
    /// (via [`GraphAccess::rel_property`]) only when the relationship is of that type — so the column
    /// is "the value for `rel_type`-typed relationships", and a different-typed relationship is a
    /// faithful [`None`]. Rel-types encountered here are interned into the shared
    /// `rel_type_names`/`rel_type_ids` (already populated by [`build_adjacency`], so this is mostly
    /// idempotent lookups).
    #[allow(clippy::too_many_arguments)]
    fn build_rel_columns(
        graph: &dyn GraphAccess,
        external: &[NodeId],
        index_of: &NodeIndex,
        spec: &SnapshotSpec,
        rel_type_names: &mut Vec<String>,
        rel_type_ids: &mut HashMap<String, RelTypeId>,
        prop_ids: &mut HashMap<String, PropId>,
    ) -> (Vec<RelId>, NodeIndex, RelColumns) {
        // Intern the requested rel columns up front: each becomes a `(RelTypeId, PropId)` key plus
        // the owned property name carried alongside for the per-edge read.
        let mut requested: Vec<(RelTypeId, PropId, String)> =
            Vec::with_capacity(spec.rel_columns.len());
        for (rel_type, prop) in &spec.rel_columns {
            let tid = intern(rel_type_names, rel_type_ids, rel_type);
            let pid = intern_id(prop_ids, prop);
            requested.push((tid, pid, prop.clone()));
        }

        // First, intern every included relationship into the dense edge-id space (one slot per
        // distinct RelId). We must know the full edge count before sizing the dense columns.
        let mut rel_external: Vec<RelId> = Vec::new();
        let mut rel_index_of: NodeIndex = HashMap::new();
        // Carry the resolved type id per internal edge so the column capture below need not re-read
        // `rel_data` once we know the edge set (the type was already resolved while interning).
        let mut edge_type: Vec<RelTypeId> = Vec::new();
        for ext in external {
            for inc in graph.expand(*ext, ExpandDirection::Outgoing, &[]) {
                // Far endpoint must be visible (keeps the snapshot self-contained, like the CSR).
                if !index_of.contains_key(&inc.neighbour.0) {
                    continue;
                }
                if let std::collections::hash_map::Entry::Vacant(slot) =
                    rel_index_of.entry(inc.rel.0)
                {
                    // Resolve and intern the type once, here, while we have the edge in hand.
                    let Some(data) = graph.rel_data(inc.rel) else {
                        // A relationship that cannot be resolved is skipped rather than guessed
                        // (cannot happen within one synchronous snapshot; stays panic-free).
                        continue;
                    };
                    let tid = intern(rel_type_names, rel_type_ids, &data.rel_type);
                    slot.insert(rel_external.len() as SnapId);
                    rel_external.push(inc.rel);
                    edge_type.push(tid);
                }
            }
        }
        let edge_count = rel_external.len();

        // Allocate the dense columns and fill them. A column reads the value only for relationships
        // of its declared type (the rest stay `None`).
        let mut rel_columns: RelColumns = HashMap::new();
        for (tid, pid, _) in &requested {
            rel_columns
                .entry((*tid, *pid))
                .or_insert_with(|| vec![None; edge_count]);
        }
        if !requested.is_empty() {
            for (e, rel) in rel_external.iter().enumerate() {
                let this_type = edge_type[e];
                for (tid, pid, prop_name) in &requested {
                    if *tid == this_type {
                        let value = graph.rel_property(*rel, prop_name);
                        if let Some(col) = rel_columns.get_mut(&(*tid, *pid)) {
                            col[e] = value;
                        }
                    }
                }
            }
        }

        (rel_external, rel_index_of, rel_columns)
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

    /// Whether a `(label, property)` **node** column was materialized in this snapshot.
    #[must_use]
    pub fn has_column(&self, label: &str, property: &str) -> bool {
        let (Some(&lid), Some(&pid)) = (self.label_ids.get(label), self.prop_ids.get(property))
        else {
            return false;
        };
        self.columns.contains_key(&(lid, pid))
    }

    /// The value of `rel`'s `property`, restricted to a captured `(rel_type, property)` column.
    ///
    /// When `rel_type` is `Some(t)`, returns the value from the captured `(t, property)` column (i.e.
    /// the value the relationship has *as a `t`-typed relationship*), or `None` if that column was
    /// not captured, the relationship is absent from the snapshot, or the value is absent. When
    /// `rel_type` is `None`, searches **every captured relationship column** for `property` and
    /// returns the first present value for this relationship. Absent columns and absent values are
    /// both `None` — distinguish them with [`has_rel_column`](Self::has_rel_column) if needed.
    ///
    /// Like [`node_property`](Self::node_property), this reads **only materialized columns**: a
    /// relationship property not named in the [`SnapshotSpec`] via
    /// [`with_rel_column`](SnapshotSpec::with_rel_column) is always `None` here.
    #[must_use]
    pub fn rel_property(
        &self,
        rel_type: Option<&str>,
        rel: RelId,
        property: &str,
    ) -> Option<Value> {
        let edge = *self.rel_index_of.get(&rel.0)? as usize;
        let pid = self.prop_ids.get(property).copied()?;
        match rel_type {
            Some(t) => {
                let tid = self.rel_type_ids.get(t).copied()?;
                self.rel_columns
                    .get(&(tid, pid))?
                    .get(edge)
                    .cloned()
                    .flatten()
            }
            None => {
                // Search every captured rel column on this property id; return the first present.
                self.rel_columns
                    .iter()
                    .filter(|((_, p), _)| *p == pid)
                    .find_map(|(_, col)| col.get(edge).cloned().flatten())
            }
        }
    }

    /// Whether a `(rel_type, property)` **relationship** column was materialized in this snapshot.
    #[must_use]
    pub fn has_rel_column(&self, rel_type: &str, property: &str) -> bool {
        let (Some(&tid), Some(&pid)) =
            (self.rel_type_ids.get(rel_type), self.prop_ids.get(property))
        else {
            return false;
        };
        self.rel_columns.contains_key(&(tid, pid))
    }

    /// A captured `(rel_type, property)` column as `(RelId, Value)` rows for **aggregation**: one row
    /// per relationship of `rel_type` that has a present value for `property`, in internal edge-id
    /// order. Returns an empty vec if the column was not captured.
    ///
    /// The relationship analogue of [`label_property_rows`](Self::label_property_rows): exactly the
    /// `(rel, value)` set a `MATCH ()-[r:rel_type]->() WHERE r.property IS NOT NULL RETURN r,
    /// r.property` would produce against this frozen view, ready to fold in parallel.
    #[must_use]
    pub fn rel_property_rows(&self, rel_type: &str, property: &str) -> Vec<(RelId, Value)> {
        let (Some(&tid), Some(&pid)) =
            (self.rel_type_ids.get(rel_type), self.prop_ids.get(property))
        else {
            return Vec::new();
        };
        let Some(col) = self.rel_columns.get(&(tid, pid)) else {
            return Vec::new();
        };
        col.iter()
            .enumerate()
            .filter_map(|(e, v)| {
                let value = v.clone()?;
                let rel = self.rel_external.get(e)?;
                Some((*rel, value))
            })
            .collect()
    }

    /// The number of **distinct relationships** captured in the snapshot (one per [`RelId`]).
    ///
    /// Equal to [`edge_count`](Self::edge_count) (each included edge is one out-edge of its start),
    /// but expressed against the relationship identity space the relationship columns are dense over.
    #[must_use]
    pub fn rel_count(&self) -> usize {
        self.rel_external.len()
    }

    // ---- derived equality lookup (the read-only "index") --------------------------------------

    /// The node ids of `label` whose `property` is **Cypher-equal** to `value`, in internal-id order.
    ///
    /// This is the snapshot's read-only equality **index**: it returns **exactly** the set a scan-
    /// and-filter would (`scan_nodes_by_label(label)` kept where `equals(node.property, value)` is
    /// [`Ternary::True`](crate::ternary::Ternary::True), using [`crate::equality::equals`]), but in
    /// bucket-sized time via the derived equality index where possible.
    ///
    /// # Semantics (matches Cypher `=`)
    ///
    /// * **Numeric cross-type** — a seek for `Integer(1)` returns nodes storing `Float(1.0)` and vice
    ///   versa (the value-key collides them), and `-0.0`/`+0.0` are one value.
    /// * **`NaN`** — `NaN = x` is `FALSE` for every `x` (CIP §Equality), so a `NaN` target matches
    ///   nothing: the method returns an empty vec without scanning.
    /// * **`Null`** — `Null = x` is `NULL` (never a definite match), so a `Null` target returns empty.
    /// * **`List`/`Map`** — these are not key-encodable, so the fast index cannot bucket them; the
    ///   method **falls back to a scan-and-filter** over the column, preserving exact equality
    ///   (including three-valued list/map element comparison) at scan cost. This keeps the result
    ///   unconditionally identical to scan-and-filter for **every** value type.
    /// * A column that was not captured (the `(label, property)` pair is absent from the spec) yields
    ///   an empty vec — there is nothing to seek.
    #[must_use]
    pub fn snapshot_seek_eq(&self, label: &str, property: &str, value: &Value) -> Vec<NodeId> {
        let (Some(&lid), Some(&pid)) = (self.label_ids.get(label), self.prop_ids.get(property))
        else {
            return Vec::new();
        };
        let Some(col) = self.columns.get(&(lid, pid)) else {
            return Vec::new();
        };

        match equality_key(value) {
            // Key-encodable target: probe the derived bucket, then re-check exact Cypher equality.
            // The key collides every Cypher-equal value into one bucket, so the bucket is a superset
            // of the true match set; the `equals` re-check trims it to exactly the matches (it can
            // only ever drop a candidate, never add one). The bucket lists are already sorted in
            // ascending internal-id order (built in id order), so the output is too.
            KeyOutcome::Key(key) => match self.eq_index.get(&(lid, pid, key)) {
                None => Vec::new(),
                Some(candidates) => candidates
                    .iter()
                    .filter_map(|&i| {
                        let stored = col.get(i as usize)?.as_ref()?;
                        equals(stored, value)
                            .is_true()
                            .then(|| self.external.get(i as usize).copied())
                            .flatten()
                    })
                    .collect(),
            },
            // No definite match is possible (NaN / Null target): empty, no scan needed.
            KeyOutcome::NoMatch => Vec::new(),
            // Not key-encodable (List / Map): exact scan-and-filter over the column.
            KeyOutcome::Scan => col
                .iter()
                .enumerate()
                .filter_map(|(i, slot)| {
                    let stored = slot.as_ref()?;
                    equals(stored, value)
                        .is_true()
                        .then(|| self.external.get(i).copied())
                        .flatten()
                })
                .collect(),
        }
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

/// The outcome of trying to compute an equality bucket key for a seek/index value.
enum KeyOutcome {
    /// A Cypher-equality-canonical byte key: two Cypher-equal values produce identical bytes here.
    Key(Vec<u8>),
    /// The value can never form a definite equality match (`NaN` or `Null`): a seek returns empty
    /// and the value contributes no index entry.
    NoMatch,
    /// The value is comparable under Cypher `=` but **not** key-encodable (`List` / `Map`): callers
    /// must fall back to an exact scan-and-filter rather than bucket it.
    Scan,
}

/// Computes a value's **Cypher-equality bucket key**: two values that are Cypher-equal map to the
/// same bytes, two unequal values (almost always) to different bytes — and the rare residual
/// collision is harmless because every bucket hit is re-checked with [`equals`].
///
/// Built on [`graphus_index::keycodec::encode_equality_canonical`] (the workspace's proven SSI
/// equality-marker encoder, which already collapses Cypher-equal `Integer`/`Float` onto one key and
/// rejects `NaN`/`Null`/`List`/`Map`), with **one extra normalization**: `-0.0` is folded to `+0.0`
/// before encoding, because Cypher equality treats them as equal (`equals(-0.0, +0.0)` is `TRUE`)
/// whereas the canonical encoder — built for *ordering*-derived markers — keeps them distinct. Folding
/// the sign of zero guarantees the bucket is a **superset** of the true match set for every type, so
/// the [`equals`] re-check never has a missing candidate to find.
fn equality_key(value: &Value) -> KeyOutcome {
    // Normalize signed zero so `-0.0` and `+0.0` share a bucket (Cypher equality). Only the exact
    // `-0.0` bit pattern is rewritten; all other floats (incl. NaN, handled below by the encoder)
    // pass through untouched.
    let normalized;
    let v = match value {
        Value::Float(f) if *f == 0.0 && f.is_sign_negative() => {
            normalized = Value::Float(0.0);
            &normalized
        }
        other => other,
    };
    match keycodec::encode_equality_canonical(v) {
        Ok(key) => KeyOutcome::Key(key),
        // The encoder rejects exactly: NaN (never equal to anything ⇒ NoMatch), Null (never a
        // definite match ⇒ NoMatch), and List/Map (comparable but not key-encodable ⇒ Scan).
        Err(_) => match v {
            Value::List(_) | Value::Map(_) => KeyOutcome::Scan,
            _ => KeyOutcome::NoMatch, // Null, NaN, or any future unindexable scalar
        },
    }
}

/// Builds the derived equality lookup index from the materialized node columns.
///
/// For every captured `(label, property)` column and every node with a present, key-encodable value,
/// records the node's internal id under `(label, property, equality_key(value))`. A node whose value
/// is not key-encodable (a stored `List`/`Map`, or a `NaN`) is **omitted from the index** — a seek
/// for such a value goes through the scan-and-filter / no-match paths in
/// [`GraphSnapshot::snapshot_seek_eq`] instead, so omitting it here costs nothing and keeps the index
/// to bucketable scalars/temporals/points. Because the outer iteration is in ascending internal-id
/// order, each bucket's id list is sorted by construction.
fn build_eq_index(columns: &NodeColumns) -> EqIndex {
    let mut index: EqIndex = HashMap::new();
    for (&(lid, pid), col) in columns {
        for (i, slot) in col.iter().enumerate() {
            let Some(value) = slot else { continue };
            // Only bucketable values get an index entry; `Scan`/`NoMatch` values are served by the
            // seek's fallback paths, so they need none.
            if let KeyOutcome::Key(key) = equality_key(value) {
                index.entry((lid, pid, key)).or_default().push(i as SnapId);
            }
        }
    }
    index
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
    use crate::graph_access::{Incident, MemGraph, RelData};
    use std::collections::BTreeSet;

    /// A minimal **adjacency-list-backed** [`GraphAccess`] used *only* by the measurement harness, so
    /// projecting a 200k-node snapshot is `O(N + E)` rather than the `O(N · E)` that
    /// [`MemGraph::expand`] (a full relationship scan per node) would impose at that scale. It is a
    /// read-only fixture: every write method is `unreachable!` because the harness never mutates it.
    struct FastGraph {
        /// Per-node `(labels, age)` — every node is a `:Person` with an `age`.
        ages: Vec<i64>,
        /// `out[i]` = outgoing `(rel_id, neighbour_internal)` of node `i`.
        out: Vec<Vec<(u64, u32)>>,
        /// `inc[i]` = incoming `(rel_id, neighbour_internal)` of node `i` (the reverse edges).
        inc: Vec<Vec<(u64, u32)>>,
        /// `rel_endpoints[r]` = `(start_internal, end_internal)` for relationship id `r`.
        rel_endpoints: Vec<(u32, u32)>,
    }

    impl FastGraph {
        /// A ring of `n` `:Person { age }` nodes wired with a `KNOWS` ring + `+7` chords (mirroring
        /// the shape of [`build_source`]'s KNOWS web), so degrees vary and the topology is realistic.
        fn ring(n: usize) -> Self {
            let mut g = FastGraph {
                ages: (0..n).map(|i| (i % 80) as i64 + 18).collect(),
                out: vec![Vec::new(); n],
                inc: vec![Vec::new(); n],
                rel_endpoints: Vec::new(),
            };
            let add = |g: &mut FastGraph, a: usize, b: usize| {
                let r = g.rel_endpoints.len() as u64;
                g.rel_endpoints.push((a as u32, b as u32));
                g.out[a].push((r, b as u32));
                g.inc[b].push((r, a as u32));
            };
            for i in 0..n {
                add(&mut g, i, (i + 1) % n);
                if i % 3 == 0 {
                    add(&mut g, i, (i + 7) % n);
                }
            }
            g
        }
    }

    impl GraphAccess for FastGraph {
        fn scan_nodes(&self) -> Vec<NodeId> {
            (0..self.ages.len() as u64).map(NodeId).collect()
        }
        fn scan_nodes_by_label(&self, label: &str) -> Vec<NodeId> {
            if label == "Person" {
                self.scan_nodes()
            } else {
                Vec::new()
            }
        }
        fn expand(
            &self,
            node: NodeId,
            direction: ExpandDirection,
            _types: &[String],
        ) -> Vec<Incident> {
            let i = node.0 as usize;
            let mut out = Vec::new();
            let want_out = matches!(direction, ExpandDirection::Outgoing | ExpandDirection::Both);
            let want_in = matches!(direction, ExpandDirection::Incoming | ExpandDirection::Both);
            if want_out {
                if let Some(es) = self.out.get(i) {
                    out.extend(es.iter().map(|&(r, nb)| Incident {
                        rel: RelId(r),
                        neighbour: NodeId(u64::from(nb)),
                    }));
                }
            }
            if want_in {
                if let Some(es) = self.inc.get(i) {
                    out.extend(es.iter().map(|&(r, nb)| Incident {
                        rel: RelId(r),
                        neighbour: NodeId(u64::from(nb)),
                    }));
                }
            }
            out
        }
        fn node_exists(&self, node: NodeId) -> bool {
            (node.0 as usize) < self.ages.len()
        }
        fn rel_exists(&self, rel: RelId) -> bool {
            (rel.0 as usize) < self.rel_endpoints.len()
        }
        fn node_labels(&self, node: NodeId) -> Option<Vec<String>> {
            self.node_exists(node).then(|| vec!["Person".to_owned()])
        }
        fn rel_data(&self, rel: RelId) -> Option<RelData> {
            self.rel_endpoints
                .get(rel.0 as usize)
                .map(|&(s, e)| RelData {
                    rel_type: "KNOWS".to_owned(),
                    start: NodeId(u64::from(s)),
                    end: NodeId(u64::from(e)),
                })
        }
        fn node_property(&self, node: NodeId, key: &str) -> Option<Value> {
            if key == "age" {
                self.ages.get(node.0 as usize).map(|&a| Value::Integer(a))
            } else {
                None
            }
        }
        fn rel_property(&self, _rel: RelId, _key: &str) -> Option<Value> {
            None
        }
        fn node_properties(&self, node: NodeId) -> Option<Vec<(String, Value)>> {
            self.node_property(node, "age")
                .map(|v| vec![("age".to_owned(), v)])
        }
        fn rel_properties(&self, rel: RelId) -> Option<Vec<(String, Value)>> {
            self.rel_exists(rel).then(Vec::new)
        }
        // ---- writes: the harness is read-only, so these are never called ----
        fn create_node(&mut self, _labels: &[String], _properties: &[(String, Value)]) -> NodeId {
            unreachable!("FastGraph is read-only")
        }
        fn create_rel(
            &mut self,
            _rel_type: &str,
            _start: NodeId,
            _end: NodeId,
            _properties: &[(String, Value)],
        ) -> RelId {
            unreachable!("FastGraph is read-only")
        }
        fn set_node_property(&mut self, _node: NodeId, _key: &str, _value: Value) {
            unreachable!("FastGraph is read-only")
        }
        fn set_rel_property(&mut self, _rel: RelId, _key: &str, _value: Value) {
            unreachable!("FastGraph is read-only")
        }
        fn add_labels(&mut self, _node: NodeId, _labels: &[String]) {
            unreachable!("FastGraph is read-only")
        }
        fn remove_labels(&mut self, _node: NodeId, _labels: &[String]) {
            unreachable!("FastGraph is read-only")
        }
        fn remove_node_property(&mut self, _node: NodeId, _key: &str) {
            unreachable!("FastGraph is read-only")
        }
        fn remove_rel_property(&mut self, _rel: RelId, _key: &str) {
            unreachable!("FastGraph is read-only")
        }
        fn replace_node_properties(&mut self, _node: NodeId, _properties: &[(String, Value)]) {
            unreachable!("FastGraph is read-only")
        }
        fn merge_node_properties(&mut self, _node: NodeId, _properties: &[(String, Value)]) {
            unreachable!("FastGraph is read-only")
        }
        fn replace_rel_properties(&mut self, _rel: RelId, _properties: &[(String, Value)]) {
            unreachable!("FastGraph is read-only")
        }
        fn merge_rel_properties(&mut self, _rel: RelId, _properties: &[(String, Value)]) {
            unreachable!("FastGraph is read-only")
        }
        fn incident_rels(&self, _node: NodeId) -> Vec<RelId> {
            unreachable!("FastGraph is read-only")
        }
        fn delete_rel(&mut self, _rel: RelId) {
            unreachable!("FastGraph is read-only")
        }
        fn delete_node(&mut self, _node: NodeId) {
            unreachable!("FastGraph is read-only")
        }
    }

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
        // KNOWS: a deterministic ring + chords so degrees vary. Each KNOWS carries a numeric `since`
        // year so the relationship property columns have data to capture.
        for i in 0..people.len() {
            let a = people[i];
            let b = people[(i + 1) % people.len()];
            g.add_rel(
                "KNOWS",
                a,
                b,
                [("since", Value::Integer(2000 + (i % 20) as i64))],
            );
            if i % 3 == 0 {
                let c = people[(i + 7) % people.len()];
                g.add_rel(
                    "KNOWS",
                    a,
                    c,
                    [("since", Value::Integer(1990 + (i % 10) as i64))],
                );
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
            .with_rel_column("KNOWS", "since")
    }

    /// Ground-truth scan-and-filter: the node ids of `label` whose `property` is Cypher-equal to
    /// `value`, computed directly over the source graph with [`equals`] (the exact reference
    /// [`GraphSnapshot::snapshot_seek_eq`] must match). Sorted ascending for set comparison.
    fn scan_and_filter_eq(g: &MemGraph, label: &str, property: &str, value: &Value) -> Vec<u64> {
        let mut out: Vec<u64> = g
            .scan_nodes_by_label(label)
            .into_iter()
            .filter(|&n| match g.node_property(n, property) {
                Some(stored) => equals(&stored, value).is_true(),
                None => false,
            })
            .map(|n| n.0)
            .collect();
        out.sort_unstable();
        out
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

    /// `from_label_column` (`rmp` task #352): the lean single-column constructor must surface
    /// `members` as `scan_nodes_by_label(label)` (the exact `count(*)` support) and the present `rows`
    /// as `label_property_rows(label, property)` — and capture **no** topology (the parallel
    /// aggregation never traverses).
    #[test]
    fn from_label_column_surfaces_members_and_rows() {
        // 5 members; 3 carry a present `age` (nodes 10, 20, 40), 2 do not (30, 50).
        let members = vec![NodeId(10), NodeId(20), NodeId(30), NodeId(40), NodeId(50)];
        let rows = vec![
            (NodeId(10), Value::Integer(1)),
            (NodeId(20), Value::Integer(2)),
            (NodeId(40), Value::Integer(4)),
        ];
        let snap = GraphSnapshot::from_label_column("Person", "age", members.clone(), rows.clone());

        // `scan_nodes_by_label` is the full member set (so its `.len()` is the exact count(*)).
        let mut got_members = snap.scan_nodes_by_label("Person");
        got_members.sort_unstable();
        assert_eq!(got_members, members, "members == scan_nodes_by_label");
        assert_eq!(
            snap.scan_nodes_by_label("Person").len(),
            5,
            "count(*) support"
        );
        // A label the snapshot does not carry yields nothing.
        assert!(snap.scan_nodes_by_label("Company").is_empty());

        // `label_property_rows` is exactly the present rows (in internal-id order, which matches the
        // members' order here).
        assert_eq!(
            snap.label_property_rows("Person", "age"),
            rows,
            "present rows == label_property_rows"
        );
        // node_count is the member count; no edges/relationships captured.
        assert_eq!(snap.node_count(), 5);
        assert_eq!(snap.edge_count(), 0);
        assert_eq!(snap.rel_count(), 0);
        // A property-absent member reads `None` for the column; a present one reads its value.
        assert_eq!(
            snap.node_property(Some("Person"), NodeId(30), "age"),
            None,
            "property-absent member"
        );
        assert_eq!(
            snap.node_property(Some("Person"), NodeId(20), "age"),
            Some(Value::Integer(2))
        );

        // The derived equality index still works over the single column.
        assert_eq!(
            snap.snapshot_seek_eq("Person", "age", &Value::Integer(4)),
            vec![NodeId(40)]
        );
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

    // ---- relationship property columns --------------------------------------------------------

    #[test]
    fn rel_property_columns_match_source() {
        let (g, _people, _companies) = build_source(40);
        let snap = GraphSnapshot::project(&g, &person_age_spec());

        // The KNOWS/since column is captured; an undeclared one is not.
        assert!(snap.has_rel_column("KNOWS", "since"));
        assert!(!snap.has_rel_column("KNOWS", "weight"));
        assert!(!snap.has_rel_column("WORKS_AT", "since"));

        // The distinct-relationship count equals the directed-edge count (no dangling edges).
        assert_eq!(snap.rel_count(), snap.edge_count());

        // Every captured relationship value matches the source, by both the typed and the
        // type-agnostic accessor.
        let rows = snap.rel_property_rows("KNOWS", "since");
        assert!(!rows.is_empty());
        for (rel, v) in &rows {
            assert_eq!(g.rel_property(*rel, "since"), Some(v.clone()));
            assert_eq!(
                snap.rel_property(Some("KNOWS"), *rel, "since"),
                Some(v.clone())
            );
            assert_eq!(snap.rel_property(None, *rel, "since"), Some(v.clone()));
        }

        // The row count equals the number of KNOWS rels with a present `since` in the source.
        let want = g
            .scan_nodes()
            .iter()
            .flat_map(|&n| g.expand(n, ExpandDirection::Outgoing, &["KNOWS".to_owned()]))
            .filter(|inc| g.rel_property(inc.rel, "since").is_some())
            .count();
        assert_eq!(rows.len(), want);

        // A WORKS_AT relationship has no `since` column captured, so a typed read is None even
        // though that relationship exists in the snapshot.
        let some_works_at = g
            .scan_nodes()
            .iter()
            .flat_map(|&n| g.expand(n, ExpandDirection::Outgoing, &["WORKS_AT".to_owned()]))
            .map(|inc| inc.rel)
            .next();
        if let Some(rel) = some_works_at {
            assert_eq!(snap.rel_property(Some("WORKS_AT"), rel, "since"), None);
        }

        // An undeclared column yields no rows.
        assert!(snap.rel_property_rows("KNOWS", "weight").is_empty());
        // An unknown relationship reads as None (no panic).
        assert_eq!(
            snap.rel_property(Some("KNOWS"), RelId(u64::MAX), "since"),
            None
        );
    }

    /// Serial and rayon-parallel aggregations over a **relationship** property column are bit-
    /// identical to each other and to a ground truth over the source.
    #[test]
    fn rel_property_parallel_and_serial_are_bit_identical() {
        use rayon::prelude::*;

        let (g, _people, _companies) = build_source(600);
        let snap = GraphSnapshot::project(&g, &person_age_spec());

        let rows = snap.rel_property_rows("KNOWS", "since");
        assert!(!rows.is_empty());

        // Ground truth: sum + count of KNOWS.since over the source, in a fixed (rel-id) reduction
        // order so a hypothetical float fold would be deterministic too.
        let mut gt: Vec<(u64, i64)> = g
            .scan_nodes()
            .iter()
            .flat_map(|&n| g.expand(n, ExpandDirection::Outgoing, &["KNOWS".to_owned()]))
            .filter_map(|inc| match g.rel_property(inc.rel, "since") {
                Some(Value::Integer(s)) => Some((inc.rel.0, s)),
                _ => None,
            })
            .collect();
        gt.sort_unstable();
        let gt_sum: i64 = gt.iter().map(|(_, s)| *s).sum();
        let gt_count = gt.len();

        let serial_sum: i64 = rows
            .iter()
            .map(|(_, v)| match v {
                Value::Integer(s) => *s,
                _ => 0,
            })
            .sum();
        // Integer addition is associative + commutative, so the rayon reduction tree is bit-
        // identical to the serial sum regardless of how the work splits.
        let parallel_sum: i64 = rows
            .par_iter()
            .map(|(_, v)| match v {
                Value::Integer(s) => *s,
                _ => 0,
            })
            .sum();

        assert_eq!(serial_sum, parallel_sum, "serial vs parallel rel sum");
        assert_eq!(
            rows.len(),
            rows.par_iter().count(),
            "serial vs parallel count"
        );
        assert_eq!(serial_sum, gt_sum, "snapshot rel sum vs ground truth");
        assert_eq!(rows.len(), gt_count, "snapshot rel count vs ground truth");
    }

    // ---- all Value variants round-trip --------------------------------------------------------

    /// Every [`Value`] variant captured in a node and a relationship column round-trips losslessly
    /// through the snapshot (the columns store the value verbatim).
    #[test]
    fn every_value_variant_round_trips() {
        use graphus_core::value::spatial::{Crs, Point};
        use graphus_core::{Date, Duration, LocalDateTime, LocalTime, ZonedDateTime, ZonedTime};

        // One representative of every Value variant (including nested list/map and both Point arities).
        let variants: Vec<Value> = vec![
            Value::Null,
            Value::Boolean(true),
            Value::Boolean(false),
            Value::Integer(i64::MIN),
            Value::Integer(0),
            Value::Integer(i64::MAX),
            Value::Float(-0.0),
            Value::Float(3.5),
            Value::Float(f64::INFINITY),
            Value::Float(f64::NEG_INFINITY),
            Value::String(String::new()),
            Value::String("héllo, world \u{1f600}".to_owned()),
            Value::Bytes(vec![]),
            Value::Bytes(vec![0u8, 1, 2, 255]),
            Value::List(vec![
                Value::Integer(1),
                Value::String("x".to_owned()),
                Value::Null,
            ]),
            Value::Map(vec![
                ("k".to_owned(), Value::Integer(7)),
                (
                    "nested".to_owned(),
                    Value::List(vec![Value::Boolean(false)]),
                ),
            ]),
            Value::Date(Date {
                days_since_epoch: -19000,
            }),
            Value::LocalTime(LocalTime {
                nanos_of_day: 123_456_789,
            }),
            Value::ZonedTime(ZonedTime {
                time: LocalTime {
                    nanos_of_day: 3_600_000_000_000,
                },
                offset_seconds: -3600,
            }),
            Value::LocalDateTime(LocalDateTime {
                epoch_seconds: -42,
                nanos: 500,
            }),
            Value::zoned_date_time(ZonedDateTime {
                local: LocalDateTime {
                    epoch_seconds: 1_700_000_000,
                    nanos: 1,
                },
                offset_seconds: 3600,
                zone_id: "Europe/Lisbon".to_owned(),
            }),
            Value::Duration(Duration {
                months: 1,
                days: 2,
                seconds: 3,
                nanos: 4,
            }),
            Value::Point(Point::new_2d(Crs::Cartesian, 1.5, -2.5)),
            Value::Point(Point::new_3d(Crs::Wgs84_3D, 10.0, 20.0, 30.0)),
        ];

        // Build a graph where node i carries `:T { p: variants[i] }` and is the start of a self-
        // loop `:R { p: variants[i] }`. A Null value is not stored (Cypher does not persist null
        // properties), so it round-trips as "absent" → None, which we assert separately.
        let mut g = MemGraph::new();
        let mut nodes = Vec::new();
        let mut rels = Vec::new();
        for v in &variants {
            let n = g.add_node(["T"], [("p", v.clone())]);
            nodes.push(n);
            let r = g.add_rel("R", n, n, [("p", v.clone())]);
            rels.push(r);
        }

        let spec = SnapshotSpec::new()
            .with_column("T", "p")
            .with_rel_column("R", "p");
        let snap = GraphSnapshot::project(&g, &spec);

        for (idx, v) in variants.iter().enumerate() {
            let want = if v.is_null() { None } else { Some(v.clone()) };
            assert_eq!(
                snap.node_property(Some("T"), nodes[idx], "p"),
                want.clone(),
                "node variant {v:?} did not round-trip"
            );
            assert_eq!(
                snap.rel_property(Some("R"), rels[idx], "p"),
                want,
                "rel variant {v:?} did not round-trip"
            );
        }
    }

    // ---- derived equality lookup index --------------------------------------------------------

    #[test]
    fn seek_eq_matches_scan_and_filter() {
        // A graph whose `:Item.code` column exercises the tricky equality cases: integers, the
        // matching float twin, signed zero, a string, and duplicates (so a bucket has >1 member).
        let mut g = MemGraph::new();
        g.add_node(["Item"], [("code", Value::Integer(1))]);
        g.add_node(["Item"], [("code", Value::Integer(1))]); // duplicate of 1
        g.add_node(["Item"], [("code", Value::Float(1.0))]); // Cypher-equal to Integer(1)
        g.add_node(["Item"], [("code", Value::Integer(2))]);
        g.add_node(["Item"], [("code", Value::Float(2.5))]);
        g.add_node(["Item"], [("code", Value::Float(-0.0))]); // equal to +0.0 and Integer(0)
        g.add_node(["Item"], [("code", Value::Integer(0))]);
        g.add_node(["Item"], [("code", Value::String("x".to_owned()))]);
        g.add_node(["Item"], [("code", Value::Float(f64::NAN))]); // never equal to anything
        g.add_node(["Item"], [] as [(&str, Value); 0]); // no code → contributes to nothing
        g.add_node(["Other"], [("code", Value::Integer(1))]); // wrong label → never matched

        let snap = GraphSnapshot::project(&g, &SnapshotSpec::new().with_column("Item", "code"));

        // Each probe must equal the scan-and-filter reference exactly (same set, same order).
        let probes = [
            Value::Integer(1),  // finds the two Integer(1) AND the Float(1.0)
            Value::Float(1.0),  // same set as Integer(1)
            Value::Integer(2),  // finds Integer(2) but NOT Float(2.5)
            Value::Float(2.5),  // finds Float(2.5)
            Value::Integer(0),  // finds Integer(0) AND Float(-0.0)
            Value::Float(0.0),  // same set as Integer(0)
            Value::Float(-0.0), // same set as Integer(0)
            Value::String("x".to_owned()),
            Value::Integer(999),                  // absent → empty
            Value::Float(f64::NAN),               // NaN matches nothing (incl. the stored NaN)
            Value::Null,                          // Null is never a definite match → empty
            Value::List(vec![Value::Integer(1)]), // not key-encodable → scan path, empty here
        ];
        for p in &probes {
            let mut got: Vec<u64> = snap
                .snapshot_seek_eq("Item", "code", p)
                .iter()
                .map(|n| n.0)
                .collect();
            got.sort_unstable();
            let want = scan_and_filter_eq(&g, "Item", "code", p);
            assert_eq!(got, want, "seek_eq != scan_and_filter for probe {p:?}");
        }

        // Spot-check the cross-type bucket is genuinely non-trivial (1, 1, 1.0 → three nodes).
        assert_eq!(
            snap.snapshot_seek_eq("Item", "code", &Value::Integer(1))
                .len(),
            3
        );
        // Signed-zero + integer-zero collapse into one bucket (Integer(0), Float(-0.0)).
        assert_eq!(
            snap.snapshot_seek_eq("Item", "code", &Value::Float(0.0))
                .len(),
            2
        );
        // An uncaptured column seeks to empty.
        assert!(
            snap.snapshot_seek_eq("Item", "name", &Value::Integer(1))
                .is_empty()
        );
        // An unknown label seeks to empty.
        assert!(
            snap.snapshot_seek_eq("Ghost", "code", &Value::Integer(1))
                .is_empty()
        );
    }

    /// **Measured parallel-speedup harness** (the deliverable's headline number).
    ///
    /// Builds a large snapshot (200k `:Person` nodes plus a relationship web), then runs the same
    /// label-property aggregation **serially** and via **`rayon::par_iter`**, printing `serial_ms`,
    /// `parallel_ms` and `speedup`. The work per node is a small CPU kernel over the node's property
    /// and degree (representative of a query read that touches each row), so the run is compute-bound
    /// enough for the parallel scaling to show; the result is asserted bit-identical between the two
    /// paths (integer fold ⇒ order-independent) so the harness also doubles as a correctness check.
    ///
    /// Honours `RAYON_NUM_THREADS`. `#[ignore]`d so it never runs in the normal suite; run it with:
    ///
    /// ```text
    /// RAYON_NUM_THREADS=1  cargo test -p graphus-cypher --release --lib \
    ///     snapshot::tests::measure_parallel_speedup -- --ignored --nocapture
    /// RAYON_NUM_THREADS=16 cargo test -p graphus-cypher --release --lib \
    ///     snapshot::tests::measure_parallel_speedup -- --ignored --nocapture
    /// ```
    #[test]
    #[ignore = "measurement harness: run with --ignored --nocapture and RAYON_NUM_THREADS set"]
    fn measure_parallel_speedup() {
        use rayon::prelude::*;
        use std::hint::black_box;
        use std::time::Instant;

        // 200k :Person { age } nodes wired in a KNOWS ring + chords. `FastGraph` gives O(N+E)
        // projection (vs MemGraph's O(N·E) full-scan expand), so building the snapshot is sub-second
        // and the timed work below is purely the aggregation.
        const N: usize = 200_000;
        let g = FastGraph::ring(N);
        let snap = GraphSnapshot::project(&g, &SnapshotSpec::new().with_column("Person", "age"));
        let nodes = snap.scan_nodes();
        assert_eq!(nodes.len(), N, "expected exactly {N} nodes");

        // A per-node kernel representative of a query read: pull the node's age (column read), its
        // degree (CSR read), and mix them through a few cheap arithmetic ops. Returns an i64 so the
        // fold is associative/commutative ⇒ identical serial vs parallel.
        let kernel = |&n: &NodeId| -> i64 {
            let age = match snap.node_property(Some("Person"), n, "age") {
                Some(Value::Integer(a)) => a,
                _ => 0,
            };
            let deg = snap.degree(n) as i64;
            // A handful of integer ops so the per-row cost is non-trivial but data-driven (not
            // optimised away — inputs come from the snapshot, output is summed).
            let mut acc = age.wrapping_mul(31).wrapping_add(deg);
            for _ in 0..32 {
                acc = acc.wrapping_mul(1_000_003).wrapping_add(deg).rotate_left(7);
            }
            acc ^ (age & deg)
        };

        // Warm both paths once (touch caches, spin up the rayon pool) before timing.
        let warm_s: i64 = nodes.iter().map(kernel).sum();
        let warm_p: i64 = nodes.par_iter().map(kernel).sum();
        assert_eq!(warm_s, warm_p, "warmup serial vs parallel must agree");

        // Repeat a few rounds and keep the best (least-noisy) wall-clock of each path.
        const ROUNDS: usize = 5;
        let mut serial_best = f64::INFINITY;
        let mut parallel_best = f64::INFINITY;
        let (mut s_sum, mut p_sum) = (0i64, 0i64);
        for _ in 0..ROUNDS {
            let t = Instant::now();
            let s: i64 = nodes.iter().map(kernel).sum();
            serial_best = serial_best.min(t.elapsed().as_secs_f64() * 1e3);
            s_sum = black_box(s);

            let t = Instant::now();
            let p: i64 = nodes.par_iter().map(kernel).sum();
            parallel_best = parallel_best.min(t.elapsed().as_secs_f64() * 1e3);
            p_sum = black_box(p);
        }
        assert_eq!(
            s_sum, p_sum,
            "serial and parallel aggregation must be bit-identical"
        );

        let threads = rayon::current_num_threads();
        let speedup = serial_best / parallel_best;
        println!(
            "snapshot parallel-read aggregation over {nodes} nodes | rayon_threads={threads} | \
             serial_ms={serial_best:.3} parallel_ms={parallel_best:.3} speedup={speedup:.2}x",
            nodes = nodes.len(),
        );
    }

    /// The equality index agrees with scan-and-filter across a larger, mixed-type column, and the
    /// seek is `Send + Sync`-safe to run from rayon workers.
    #[test]
    fn seek_eq_matches_scan_and_filter_at_scale() {
        use rayon::prelude::*;

        let mut g = MemGraph::new();
        // 2000 nodes: alternating Integer / matching-Float so cross-type buckets are populated, plus
        // a string tail. Values repeat (mod 50) so buckets carry many members.
        for i in 0..2000i64 {
            let v = match i % 3 {
                0 => Value::Integer(i % 50),
                1 => Value::Float((i % 50) as f64), // Cypher-equal to the Integer twin
                _ => Value::String(format!("s{}", i % 50)),
            };
            g.add_node(["K"], [("v", v)]);
        }
        let snap = GraphSnapshot::project(&g, &SnapshotSpec::new().with_column("K", "v"));

        // Probe every distinct value form and confirm the snapshot's seek equals scan-and-filter.
        let probes: Vec<Value> = (0..50i64)
            .flat_map(|k| {
                [
                    Value::Integer(k),
                    Value::Float(k as f64),
                    Value::String(format!("s{k}")),
                ]
            })
            .collect();

        // Run all probes in parallel — the snapshot is Sync, so workers share &snap.
        let mismatches: usize = probes
            .par_iter()
            .filter(|p| {
                let mut got: Vec<u64> = snap
                    .snapshot_seek_eq("K", "v", p)
                    .iter()
                    .map(|n| n.0)
                    .collect();
                got.sort_unstable();
                got != scan_and_filter_eq(&g, "K", "v", p)
            })
            .count();
        assert_eq!(
            mismatches, 0,
            "every parallel seek must match scan-and-filter"
        );
    }
}
