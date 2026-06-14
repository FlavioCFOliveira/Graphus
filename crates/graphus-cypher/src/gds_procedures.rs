//! The **Graph Data Science (`gds.*`) procedure surface** (`rmp` task #133).
//!
//! This module is the seam where the dependency-free [`graphus_gds`] engine (the immutable CSR
//! projection + named-graph catalog + algorithm library) meets the live Cypher executor. It exposes
//! the engine as a set of [`ProcedureRegistry`](crate::procedure_registry::ProcedureRegistry)
//! procedures so a client can run, over the **real** persistent store:
//!
//! ```cypher
//! CALL gds.graph.project('g', 'Person', 'KNOWS')
//! CALL gds.pageRank.stream('g') YIELD nodeId, score RETURN nodeId, score
//! ```
//!
//! # Snapshot consistency
//!
//! A projection is taken in [`gds.graph.project`](register_gds_procedures) by draining the **visible**
//! nodes and relationships of the live [`GraphAccess`] seam **in a single pass**. That seam is the
//! per-statement [`RecordStoreGraph`](crate::record_graph::RecordStoreGraph) (or an
//! [`AuthorizedGraph`](crate::authorized_graph::AuthorizedGraph) wrapping it), so the drained graph is
//! exactly the MVCC-consistent, RBAC-filtered point-in-time view the surrounding transaction reads —
//! the projection is therefore a consistent committed snapshot, never a torn one. The
//! [`graphus_gds::CsrGraph`] is then frozen and reused by later `gds.*.stream` calls regardless of
//! what the live graph does afterwards.
//!
//! # Identity mapping
//!
//! [`graphus_gds`] uses a dense internal index space; the projection records the external store ids
//! (the [`NodeId`]'s `u64`). Every streamed row maps the algorithm's internal id back to the external
//! `nodeId` (a [`Value::Integer`], as Neo4j's `gds.*.stream` does), so a client always sees real node
//! ids, never the projection's internal indices.
//!
//! # The named-graph catalog
//!
//! Named graphs outlive a single `CALL`: `gds.graph.project` registers one, `gds.pageRank.stream`
//! reads it, `gds.graph.drop` removes it. The catalog therefore lives behind a shared
//! [`GdsCatalogHandle`] (an `Arc<Mutex<…>>`) captured by every procedure closure, built once per
//! engine and shared across statements. Access is serialized by the engine's single-threaded `Run`
//! loop anyway; the `Mutex` only satisfies the `Send + Sync` bound the procedure-handler type
//! requires and guards against any future concurrent driver.
//!
//! # No panics
//!
//! Every procedure validates its name, arity and argument types and returns a typed
//! [`ProcedureFailure`] on any misuse (unknown graph, bad parameter, negative weight, …). There is no
//! indexing or `unwrap` that can panic on user input; a [`GdsError`] is mapped to a `ProcedureFailure`
//! at the boundary.

use std::sync::{Arc, Mutex};

use graphus_core::Value;
use graphus_gds::algo::centrality::{
    betweenness_centrality, closeness_centrality, undirected_scale,
};
use graphus_gds::algo::community::{LabelPropagationConfig, label_propagation};
use graphus_gds::algo::degree::{Direction, degree_centrality};
use graphus_gds::algo::pagerank::{PageRankConfig, pagerank};
use graphus_gds::algo::scc::strongly_connected_components;
use graphus_gds::algo::shortest_path::{bellman_ford, dijkstra};
use graphus_gds::algo::triangles::triangle_count;
use graphus_gds::algo::wcc::weakly_connected_components;
use graphus_gds::{Cancel, CsrBuilder, CsrGraph, GdsError, GraphCatalog, Orientation};

use crate::graph_access::{ExpandDirection, GraphAccess, NodeId};
use crate::procedure_registry::{
    FieldSpec, FieldType, ProcedureFailure, ProcedureSet, ProcedureSignature, ValueClass,
};

/// The shared, engine-lifetime named-graph catalog handle captured by every `gds.*` procedure
/// closure. `Arc<Mutex<…>>` because the procedure-handler type is `Send + Sync`; the engine drives
/// `Run` single-threaded, so the lock is uncontended in practice.
pub type GdsCatalogHandle = Arc<Mutex<GraphCatalog>>;

/// Creates a fresh, empty GDS named-graph catalog handle. One per engine.
#[must_use]
pub fn new_catalog() -> GdsCatalogHandle {
    Arc::new(Mutex::new(GraphCatalog::new()))
}

// =================================================================================================
// Error mapping
// =================================================================================================

/// Maps a [`GdsError`] to a [`ProcedureFailure`] for the named procedure (the crate boundary mapping
/// the GDS module docs promise). Never panics.
fn gds_failure(name: &str, err: GdsError) -> ProcedureFailure {
    ProcedureFailure::new(name, err.to_string())
}

/// Locks the shared catalog, mapping a poisoned mutex to a [`ProcedureFailure`] rather than panicking
/// (a poisoned lock means a prior handler panicked — defensive, should never happen on the
/// panic-free path).
fn lock_catalog<'a>(
    name: &str,
    catalog: &'a GdsCatalogHandle,
) -> Result<std::sync::MutexGuard<'a, GraphCatalog>, ProcedureFailure> {
    catalog
        .lock()
        .map_err(|_| ProcedureFailure::new(name, "GDS catalog lock poisoned"))
}

// =================================================================================================
// Projection from the live GraphAccess seam
// =================================================================================================

/// Builds a [`CsrGraph`] from the **visible** nodes and relationships of `graph`, optionally filtered
/// by a node label and a relationship type, under one consistent pass (the snapshot-consistency
/// contract — see the module docs).
///
/// `node_filter` restricts the projected node set to those carrying that label (a relationship is
/// projected only when **both** endpoints are in the node set). `rel_filter` restricts the projected
/// edges to that relationship type. `weighted` carries the relationship's `weight_property` value as
/// the edge weight when present (defaulting to `1.0`); otherwise the projection is unweighted.
///
/// The orientation is **undirected** by default (GDS projections are symmetric unless asked
/// otherwise), matching the most common centrality/community use; directed algorithms (PageRank, SCC)
/// still operate correctly because the undirected projection adds the reverse edges they would
/// otherwise miss only when `undirected` is set. When `undirected` is `false` the directed adjacency
/// is preserved exactly.
fn project_from_graph(
    name: &str,
    graph: &dyn GraphAccess,
    node_filter: Option<&str>,
    rel_filter: Option<&str>,
    weight_property: Option<&str>,
    undirected: bool,
) -> Result<CsrGraph, ProcedureFailure> {
    let orientation = if undirected {
        Orientation::Undirected
    } else {
        Orientation::Directed
    };
    let weighted = weight_property.is_some();
    let mut builder = CsrBuilder::new(orientation)
        .weighted(weighted)
        .allow_implicit_nodes(false);

    // --- nodes: the visible node set, label-filtered if requested ---
    let node_ids: Vec<NodeId> = match node_filter {
        Some(label) => graph.scan_nodes_by_label(label),
        None => graph.scan_nodes(),
    };
    // A membership set so an edge is projected only when both endpoints are in the node set, and so
    // the relationship scan does not re-add a node the filter excluded.
    let mut members = std::collections::HashSet::with_capacity(node_ids.len());
    for id in &node_ids {
        members.insert(id.0);
        builder.add_node(id.0);
    }

    // --- edges: walk each projected node's outgoing relationships once ---
    let rel_types: Vec<String> = match rel_filter {
        Some(t) => vec![t.to_owned()],
        None => Vec::new(), // empty = any type
    };
    for id in &node_ids {
        for inc in graph.expand(*id, ExpandDirection::Outgoing, &rel_types) {
            // Project the edge only if the far endpoint is also a projected node (so a relationship to
            // a label-excluded node is dropped, keeping the projection self-contained).
            if !members.contains(&inc.neighbour.0) {
                continue;
            }
            let weight = match weight_property {
                Some(prop) => rel_weight(graph, inc.rel, prop),
                None => 1.0,
            };
            // Endpoints are pre-declared (both are members), so `add_edge` cannot fail on an unknown
            // node; map any builder error defensively rather than unwrapping.
            builder
                .add_edge(id.0, inc.neighbour.0, weight)
                .map_err(|e| gds_failure(name, e))?;
        }
    }

    builder.build().map_err(|e| gds_failure(name, e))
}

/// Reads a relationship's numeric weight property, defaulting to `1.0` when the property is absent or
/// not a number (so a missing/typo'd weight never aborts the projection — it degrades to unweighted
/// for that edge, matching Neo4j's `defaultValue` behaviour).
fn rel_weight(graph: &dyn GraphAccess, rel: crate::graph_access::RelId, prop: &str) -> f64 {
    match graph.rel_property(rel, prop) {
        Some(Value::Integer(i)) => i as f64,
        Some(Value::Float(f)) => f,
        _ => 1.0,
    }
}

// =================================================================================================
// Argument parsing helpers (no panics)
// =================================================================================================

/// The first argument as a graph name (a non-empty string).
fn arg_graph_name<'a>(name: &str, args: &'a [Value]) -> Result<&'a str, ProcedureFailure> {
    match args.first() {
        Some(Value::String(s)) if !s.is_empty() => Ok(s.as_str()),
        _ => Err(ProcedureFailure::new(
            name,
            "the first argument must be a non-empty graph name (a string)",
        )),
    }
}

/// An optional string-or-null filter argument at `idx` (a label or relationship type). A `null`,
/// an empty string, or an absent argument means "no filter".
fn arg_opt_string(args: &[Value], idx: usize) -> Option<String> {
    match args.get(idx) {
        Some(Value::String(s)) if !s.is_empty() => Some(s.clone()),
        _ => None,
    }
}

/// Reads a numeric configuration value from the optional trailing **config map** argument by key,
/// returning `None` when the map or key is absent (so the algorithm uses its default).
fn config_f64(args: &[Value], map_idx: usize, key: &str) -> Option<f64> {
    let Some(Value::Map(entries)) = args.get(map_idx) else {
        return None;
    };
    entries.iter().find(|(k, _)| k == key).and_then(|(_, v)| match v {
        Value::Integer(i) => Some(*i as f64),
        Value::Float(f) => Some(*f),
        _ => None,
    })
}

/// Reads a node-id configuration value (`sourceNode`) from the optional trailing config map.
fn config_node_id(args: &[Value], map_idx: usize, key: &str) -> Option<u64> {
    let Some(Value::Map(entries)) = args.get(map_idx) else {
        return None;
    };
    entries
        .iter()
        .find(|(k, _)| k == key)
        .and_then(|(_, v)| match v {
            Value::Integer(i) if *i >= 0 => Some(*i as u64),
            _ => None,
        })
}

// =================================================================================================
// Registration
// =================================================================================================

/// One `STRING` input field spec (non-nullable).
fn string_in(name: &str) -> FieldSpec {
    FieldSpec::new(
        name,
        FieldType {
            class: ValueClass::String,
            nullable: false,
        },
    )
}

/// One nullable `ANY` input field spec (used for optional filter / config-map arguments).
fn any_in(name: &str) -> FieldSpec {
    FieldSpec::new(name, FieldType::nullable(ValueClass::Any))
}

/// One non-nullable output field of `class`.
fn out(name: &str, class: ValueClass) -> FieldSpec {
    FieldSpec::new(
        name,
        FieldType {
            class,
            nullable: false,
        },
    )
}

/// Registers every `gds.*` procedure into `set`, all sharing the one `catalog` handle (`rmp` task
/// #133). Idempotent registration is not required — call once per [`ProcedureSet`].
///
/// The registered surface:
///
/// - **Lifecycle:** `gds.graph.project(name, nodeFilter, relFilter)`, `gds.graph.list()`,
///   `gds.graph.exists(name)`, `gds.graph.drop(name)`.
/// - **Centrality (stream):** `gds.pageRank.stream`, `gds.degree.stream`, `gds.closeness.stream`,
///   `gds.betweenness.stream`.
/// - **Community (stream):** `gds.wcc.stream`, `gds.scc.stream`, `gds.labelPropagation.stream`,
///   `gds.triangleCount.stream`.
/// - **Pathfinding (stream):** `gds.dijkstra.stream`, `gds.bellmanFord.stream` (single-source from a
///   `sourceNode` config key, yielding `nodeId, distance`).
pub fn register_gds_procedures(set: &mut ProcedureSet, catalog: GdsCatalogHandle) {
    register_lifecycle(set, &catalog);
    register_centrality(set, &catalog);
    register_community(set, &catalog);
    register_pathfinding(set, &catalog);
}

/// Registers the graph-lifecycle procedures.
fn register_lifecycle(set: &mut ProcedureSet, catalog: &GdsCatalogHandle) {
    // gds.graph.project(name, nodeFilter?, relFilter?, config?) :: (graphName, nodeCount, relationshipCount)
    let cat = Arc::clone(catalog);
    set.register(
        ProcedureSignature::new(
            "gds.graph.project",
            vec![
                string_in("graphName"),
                any_in("nodeFilter"),
                any_in("relFilter"),
                any_in("config"),
            ],
            vec![
                out("graphName", ValueClass::String),
                out("nodeCount", ValueClass::Integer),
                out("relationshipCount", ValueClass::Integer),
            ],
        ),
        Box::new(move |args, graph| {
            const NAME: &str = "gds.graph.project";
            let name = arg_graph_name(NAME, args)?;
            let node_filter = arg_opt_string(args, 1);
            let rel_filter = arg_opt_string(args, 2);
            // Config map (4th arg): `orientation: 'NATURAL'|'UNDIRECTED'` and `relationshipWeightProperty`.
            let undirected = config_orientation_undirected(args, 3);
            let weight_property = config_string(args, 3, "relationshipWeightProperty");

            let projected = project_from_graph(
                NAME,
                graph,
                node_filter.as_deref(),
                rel_filter.as_deref(),
                weight_property.as_deref(),
                undirected,
            )?;
            let node_count = projected.node_count() as i64;
            let rel_count = projected.edge_count() as i64;

            let mut cat = lock_catalog(NAME, &cat)?;
            // Replace an existing projection of the same name (idempotent re-project), so a client can
            // re-project without an explicit drop.
            if cat.contains(name) {
                let _ = GraphCatalog::drop(&mut cat, name);
            }
            cat.project(name, projected).map_err(|e| gds_failure(NAME, e))?;
            Ok(vec![vec![
                Value::String(name.to_owned()),
                Value::Integer(node_count),
                Value::Integer(rel_count),
            ]])
        }),
    );

    // gds.graph.list() :: (graphName, nodeCount, relationshipCount)
    let cat = Arc::clone(catalog);
    set.register(
        ProcedureSignature::new(
            "gds.graph.list",
            Vec::new(),
            vec![
                out("graphName", ValueClass::String),
                out("nodeCount", ValueClass::Integer),
                out("relationshipCount", ValueClass::Integer),
            ],
        ),
        Box::new(move |_args, _graph| {
            const NAME: &str = "gds.graph.list";
            let cat = lock_catalog(NAME, &cat)?;
            let mut names = cat.list();
            names.sort_unstable(); // deterministic order
            let mut rows = Vec::with_capacity(names.len());
            for n in names {
                // `get` cannot fail for a name `list()` just returned, but map defensively.
                let g = cat.get(&n).map_err(|e| gds_failure(NAME, e))?;
                rows.push(vec![
                    Value::String(n),
                    Value::Integer(g.node_count() as i64),
                    Value::Integer(g.edge_count() as i64),
                ]);
            }
            Ok(rows)
        }),
    );

    // gds.graph.exists(name) :: (graphName, exists)
    let cat = Arc::clone(catalog);
    set.register(
        ProcedureSignature::new(
            "gds.graph.exists",
            vec![string_in("graphName")],
            vec![
                out("graphName", ValueClass::String),
                out("exists", ValueClass::Boolean),
            ],
        ),
        Box::new(move |args, _graph| {
            const NAME: &str = "gds.graph.exists";
            let name = arg_graph_name(NAME, args)?;
            let cat = lock_catalog(NAME, &cat)?;
            Ok(vec![vec![
                Value::String(name.to_owned()),
                Value::Boolean(cat.contains(name)),
            ]])
        }),
    );

    // gds.graph.drop(name) :: (graphName, nodeCount, relationshipCount)
    let cat = Arc::clone(catalog);
    set.register(
        ProcedureSignature::new(
            "gds.graph.drop",
            vec![string_in("graphName")],
            vec![
                out("graphName", ValueClass::String),
                out("nodeCount", ValueClass::Integer),
                out("relationshipCount", ValueClass::Integer),
            ],
        ),
        Box::new(move |args, _graph| {
            const NAME: &str = "gds.graph.drop";
            let name = arg_graph_name(NAME, args)?;
            let mut cat = lock_catalog(NAME, &cat)?;
            let dropped = GraphCatalog::drop(&mut cat, name).map_err(|e| gds_failure(NAME, e))?;
            Ok(vec![vec![
                Value::String(name.to_owned()),
                Value::Integer(dropped.node_count() as i64),
                Value::Integer(dropped.edge_count() as i64),
            ]])
        }),
    );
}

/// Reads `orientation` from the config map: `'UNDIRECTED'` ⇒ undirected (the default), `'NATURAL'` ⇒
/// directed. Absent ⇒ undirected (the GDS-typical default for centrality/community).
fn config_orientation_undirected(args: &[Value], map_idx: usize) -> bool {
    // Undirected unless the config explicitly asks for `NATURAL` (directed).
    !matches!(
        config_string(args, map_idx, "orientation"),
        Some(s) if s.eq_ignore_ascii_case("NATURAL")
    )
}

/// Reads a string configuration value from the optional config map by key.
fn config_string(args: &[Value], map_idx: usize, key: &str) -> Option<String> {
    let Some(Value::Map(entries)) = args.get(map_idx) else {
        return None;
    };
    entries.iter().find(|(k, _)| k == key).and_then(|(_, v)| match v {
        Value::String(s) if !s.is_empty() => Some(s.clone()),
        _ => None,
    })
}

/// Looks up a projected graph by name from the shared catalog, mapping an unknown name to a clear
/// [`ProcedureFailure`] (so a typo is a hard error, never silently-empty results).
fn get_projected(
    name: &str,
    catalog: &GdsCatalogHandle,
    args: &[Value],
) -> Result<Arc<CsrGraph>, ProcedureFailure> {
    let graph_name = arg_graph_name(name, args)?;
    let cat = lock_catalog(name, catalog)?;
    cat.get(graph_name).map_err(|e| gds_failure(name, e))
}

/// Builds `(nodeId, score)` rows from a per-internal-id score vector, mapping each internal id back to
/// its external `nodeId`. Skips an internal id with no external mapping (defensive — every projected
/// node has one).
fn id_score_rows(graph: &CsrGraph, scores: &[f64]) -> Vec<Vec<Value>> {
    let externals = graph.external_ids();
    let mut rows = Vec::with_capacity(scores.len());
    for (i, &score) in scores.iter().enumerate() {
        if let Some(&ext) = externals.get(i) {
            rows.push(vec![Value::Integer(ext as i64), Value::Float(score)]);
        }
    }
    rows
}

/// Builds `(nodeId, componentId)` rows, mapping both the node and the component representative back to
/// external ids. `component[i]` holds an **internal** representative id, remapped here.
fn id_component_rows(graph: &CsrGraph, component: &[u32]) -> Vec<Vec<Value>> {
    let externals = graph.external_ids();
    let mut rows = Vec::with_capacity(component.len());
    for (i, &comp) in component.iter().enumerate() {
        let Some(&ext) = externals.get(i) else {
            continue;
        };
        // The component id is itself a node-id label in Neo4j's stream form; expose the external id of
        // the representative when it maps to a node, else the raw internal id (still a stable label).
        let comp_ext = externals.get(comp as usize).copied().unwrap_or(comp as u64);
        rows.push(vec![
            Value::Integer(ext as i64),
            Value::Integer(comp_ext as i64),
        ]);
    }
    rows
}

/// Registers the centrality streaming procedures.
fn register_centrality(set: &mut ProcedureSet, catalog: &GdsCatalogHandle) {
    // gds.pageRank.stream(name, config?) :: (nodeId, score)
    let cat = Arc::clone(catalog);
    set.register(
        ProcedureSignature::new(
            "gds.pageRank.stream",
            vec![string_in("graphName"), any_in("config")],
            vec![out("nodeId", ValueClass::Integer), out("score", ValueClass::Float)],
        ),
        Box::new(move |args, _graph| {
            const NAME: &str = "gds.pageRank.stream";
            let g = get_projected(NAME, &cat, args)?;
            let mut config = PageRankConfig::default();
            if let Some(d) = config_f64(args, 1, "dampingFactor") {
                config.damping = d;
            }
            if let Some(m) = config_f64(args, 1, "maxIterations") {
                config.max_iter = m.max(0.0) as u32;
            }
            if let Some(t) = config_f64(args, 1, "tolerance") {
                config.tolerance = t;
            }
            let result = pagerank(&g, config, &Cancel::never()).map_err(|e| gds_failure(NAME, e))?;
            Ok(id_score_rows(&g, &result.rank))
        }),
    );

    // gds.degree.stream(name) :: (nodeId, score)
    let cat = Arc::clone(catalog);
    set.register(
        ProcedureSignature::new(
            "gds.degree.stream",
            vec![string_in("graphName"), any_in("config")],
            vec![out("nodeId", ValueClass::Integer), out("score", ValueClass::Float)],
        ),
        Box::new(move |args, _graph| {
            const NAME: &str = "gds.degree.stream";
            let g = get_projected(NAME, &cat, args)?;
            let degrees = degree_centrality(&g, Direction::Out);
            let scores: Vec<f64> = degrees.iter().map(|&d| d as f64).collect();
            Ok(id_score_rows(&g, &scores))
        }),
    );

    // gds.closeness.stream(name) :: (nodeId, score)
    let cat = Arc::clone(catalog);
    set.register(
        ProcedureSignature::new(
            "gds.closeness.stream",
            vec![string_in("graphName"), any_in("config")],
            vec![out("nodeId", ValueClass::Integer), out("score", ValueClass::Float)],
        ),
        Box::new(move |args, _graph| {
            const NAME: &str = "gds.closeness.stream";
            let g = get_projected(NAME, &cat, args)?;
            let scores =
                closeness_centrality(&g, &Cancel::never()).map_err(|e| gds_failure(NAME, e))?;
            Ok(id_score_rows(&g, &scores))
        }),
    );

    // gds.betweenness.stream(name) :: (nodeId, score)
    //
    // Convention (resolved per `rmp` task #133): the raw Brandes accumulation sums over ordered
    // (s, t) pairs, so on an UNDIRECTED projection each unordered pair {s, t} is counted twice. The
    // Neo4j GDS / networkx undirected convention counts each unordered pair **once**, i.e. the score
    // is the raw accumulation divided by two. `undirected_scale` applies exactly that (and is a no-op
    // for a directed projection), so the streamed score matches Neo4j's undirected betweenness.
    let cat = Arc::clone(catalog);
    set.register(
        ProcedureSignature::new(
            "gds.betweenness.stream",
            vec![string_in("graphName"), any_in("config")],
            vec![out("nodeId", ValueClass::Integer), out("score", ValueClass::Float)],
        ),
        Box::new(move |args, _graph| {
            const NAME: &str = "gds.betweenness.stream";
            let g = get_projected(NAME, &cat, args)?;
            let raw =
                betweenness_centrality(&g, &Cancel::never()).map_err(|e| gds_failure(NAME, e))?;
            let scores = undirected_scale(&g, raw);
            Ok(id_score_rows(&g, &scores))
        }),
    );
}

/// Registers the community / connectivity streaming procedures.
fn register_community(set: &mut ProcedureSet, catalog: &GdsCatalogHandle) {
    // gds.wcc.stream(name) :: (nodeId, componentId)
    let cat = Arc::clone(catalog);
    set.register(
        ProcedureSignature::new(
            "gds.wcc.stream",
            vec![string_in("graphName"), any_in("config")],
            vec![
                out("nodeId", ValueClass::Integer),
                out("componentId", ValueClass::Integer),
            ],
        ),
        Box::new(move |args, _graph| {
            const NAME: &str = "gds.wcc.stream";
            let g = get_projected(NAME, &cat, args)?;
            let result = weakly_connected_components(&g, &Cancel::never())
                .map_err(|e| gds_failure(NAME, e))?;
            Ok(id_component_rows(&g, &result.component))
        }),
    );

    // gds.scc.stream(name) :: (nodeId, componentId)
    let cat = Arc::clone(catalog);
    set.register(
        ProcedureSignature::new(
            "gds.scc.stream",
            vec![string_in("graphName"), any_in("config")],
            vec![
                out("nodeId", ValueClass::Integer),
                out("componentId", ValueClass::Integer),
            ],
        ),
        Box::new(move |args, _graph| {
            const NAME: &str = "gds.scc.stream";
            let g = get_projected(NAME, &cat, args)?;
            let result = strongly_connected_components(&g, &Cancel::never())
                .map_err(|e| gds_failure(NAME, e))?;
            Ok(id_component_rows(&g, &result.component))
        }),
    );

    // gds.labelPropagation.stream(name, config?) :: (nodeId, communityId)
    let cat = Arc::clone(catalog);
    set.register(
        ProcedureSignature::new(
            "gds.labelPropagation.stream",
            vec![string_in("graphName"), any_in("config")],
            vec![
                out("nodeId", ValueClass::Integer),
                out("communityId", ValueClass::Integer),
            ],
        ),
        Box::new(move |args, _graph| {
            const NAME: &str = "gds.labelPropagation.stream";
            let g = get_projected(NAME, &cat, args)?;
            let mut config = LabelPropagationConfig::default();
            if let Some(m) = config_f64(args, 1, "maxIterations") {
                let m = m.max(1.0) as u32;
                config.max_iter = m;
            }
            let result =
                label_propagation(&g, config, &Cancel::never()).map_err(|e| gds_failure(NAME, e))?;
            Ok(id_component_rows(&g, &result.label))
        }),
    );

    // gds.triangleCount.stream(name) :: (nodeId, triangleCount)
    let cat = Arc::clone(catalog);
    set.register(
        ProcedureSignature::new(
            "gds.triangleCount.stream",
            vec![string_in("graphName"), any_in("config")],
            vec![
                out("nodeId", ValueClass::Integer),
                out("triangleCount", ValueClass::Integer),
            ],
        ),
        Box::new(move |args, _graph| {
            const NAME: &str = "gds.triangleCount.stream";
            let g = get_projected(NAME, &cat, args)?;
            let result =
                triangle_count(&g, &Cancel::never()).map_err(|e| gds_failure(NAME, e))?;
            let externals = g.external_ids();
            let mut rows = Vec::with_capacity(result.triangles.len());
            for (i, &count) in result.triangles.iter().enumerate() {
                if let Some(&ext) = externals.get(i) {
                    rows.push(vec![
                        Value::Integer(ext as i64),
                        Value::Integer(count as i64),
                    ]);
                }
            }
            Ok(rows)
        }),
    );
}

/// Registers the single-source weighted shortest-path streaming procedures.
fn register_pathfinding(set: &mut ProcedureSet, catalog: &GdsCatalogHandle) {
    // gds.dijkstra.stream(name, config) :: (nodeId, distance) — single-source from config.sourceNode.
    let cat = Arc::clone(catalog);
    set.register(
        ProcedureSignature::new(
            "gds.dijkstra.stream",
            vec![string_in("graphName"), any_in("config")],
            vec![
                out("nodeId", ValueClass::Integer),
                out("distance", ValueClass::Float),
            ],
        ),
        Box::new(move |args, _graph| {
            const NAME: &str = "gds.dijkstra.stream";
            shortest_path_rows(NAME, &cat, args, false)
        }),
    );

    // gds.bellmanFord.stream(name, config) :: (nodeId, distance) — single-source, handles negatives.
    let cat = Arc::clone(catalog);
    set.register(
        ProcedureSignature::new(
            "gds.bellmanFord.stream",
            vec![string_in("graphName"), any_in("config")],
            vec![
                out("nodeId", ValueClass::Integer),
                out("distance", ValueClass::Float),
            ],
        ),
        Box::new(move |args, _graph| {
            const NAME: &str = "gds.bellmanFord.stream";
            shortest_path_rows(NAME, &cat, args, true)
        }),
    );
}

/// Shared body for `gds.dijkstra.stream` / `gds.bellmanFord.stream`: resolves the projected graph and
/// the `sourceNode` config key, runs the single-source algorithm (`bellman` selects Bellman-Ford over
/// Dijkstra), and yields one `(nodeId, distance)` row per **reachable** node.
fn shortest_path_rows(
    name: &str,
    catalog: &GdsCatalogHandle,
    args: &[Value],
    bellman: bool,
) -> Result<Vec<Vec<Value>>, ProcedureFailure> {
    let g = get_projected(name, catalog, args)?;
    let Some(source_ext) = config_node_id(args, 1, "sourceNode") else {
        return Err(ProcedureFailure::new(
            name,
            "the config map must carry an integer `sourceNode` (an external node id)",
        ));
    };
    // Map the external source id to the projection's internal index; an id not in the projection is a
    // clear error (the source must be a projected node).
    let Some(source_internal) = g.internal_id(source_ext) else {
        return Err(ProcedureFailure::new(
            name,
            format!("sourceNode {source_ext} is not a node of the projected graph"),
        ));
    };

    let paths = if bellman {
        bellman_ford(&g, source_internal, &Cancel::never())
    } else {
        dijkstra(&g, source_internal, &Cancel::never())
    }
    .map_err(|e| gds_failure(name, e))?;

    let externals = g.external_ids();
    let mut rows = Vec::new();
    for (i, dist) in paths.dist.iter().enumerate() {
        // Only reachable nodes (a finite distance) are yielded, matching Neo4j's path-stream shape.
        if let (Some(&ext), Some(d)) = (externals.get(i), dist) {
            rows.push(vec![Value::Integer(ext as i64), Value::Float(*d)]);
        }
    }
    Ok(rows)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graph_access::MemGraph;
    use crate::procedure_registry::ProcedureRegistry;

    /// A small undirected triangle + a pendant: a-b-c-a, plus d hanging off a.
    fn triangle_graph() -> (MemGraph, [NodeId; 4]) {
        let mut g = MemGraph::new();
        let a = g.add_node(["N"], [] as [(&str, Value); 0]);
        let b = g.add_node(["N"], [] as [(&str, Value); 0]);
        let c = g.add_node(["N"], [] as [(&str, Value); 0]);
        let d = g.add_node(["N"], [] as [(&str, Value); 0]);
        g.add_rel("R", a, b, [] as [(&str, Value); 0]);
        g.add_rel("R", b, c, [] as [(&str, Value); 0]);
        g.add_rel("R", c, a, [] as [(&str, Value); 0]);
        g.add_rel("R", a, d, [] as [(&str, Value); 0]);
        (g, [a, b, c, d])
    }

    fn registry_with_catalog() -> (ProcedureSet, GdsCatalogHandle) {
        let catalog = new_catalog();
        let mut set = ProcedureSet::new();
        register_gds_procedures(&mut set, Arc::clone(&catalog));
        (set, catalog)
    }

    #[test]
    fn project_list_drop_lifecycle() {
        let (mut graph, _) = triangle_graph();
        let (set, _cat) = registry_with_catalog();

        // project
        let rows = set
            .invoke(
                "gds.graph.project",
                &[
                    Value::String("g".into()),
                    Value::String("N".into()),
                    Value::String("R".into()),
                    Value::Null,
                ],
                &mut graph,
            )
            .expect("project");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0][0], Value::String("g".into()));
        assert_eq!(rows[0][1], Value::Integer(4)); // 4 nodes
        // Undirected projection symmetrizes 4 input edges -> 8 stored directed edges.
        assert_eq!(rows[0][2], Value::Integer(8));

        // exists
        let rows = set
            .invoke(
                "gds.graph.exists",
                &[Value::String("g".into())],
                &mut graph,
            )
            .expect("exists");
        assert_eq!(rows[0][1], Value::Boolean(true));

        // list
        let rows = set
            .invoke("gds.graph.list", &[], &mut graph)
            .expect("list");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0][0], Value::String("g".into()));

        // drop
        set.invoke("gds.graph.drop", &[Value::String("g".into())], &mut graph)
            .expect("drop");
        let rows = set
            .invoke(
                "gds.graph.exists",
                &[Value::String("g".into())],
                &mut graph,
            )
            .expect("exists");
        assert_eq!(rows[0][1], Value::Boolean(false));
    }

    #[test]
    fn stream_on_unknown_graph_errors() {
        let (mut graph, _) = triangle_graph();
        let (set, _cat) = registry_with_catalog();
        let err = set
            .invoke(
                "gds.pageRank.stream",
                &[Value::String("nope".into()), Value::Null],
                &mut graph,
            )
            .expect_err("unknown graph must error");
        assert!(format!("{err}").contains("nope"));
    }

    #[test]
    fn pagerank_and_degree_stream() {
        let (mut graph, ids) = triangle_graph();
        let (set, _cat) = registry_with_catalog();
        set.invoke(
            "gds.graph.project",
            &[
                Value::String("g".into()),
                Value::String("N".into()),
                Value::String("R".into()),
                Value::Null,
            ],
            &mut graph,
        )
        .expect("project");

        // degree: a has degree 3 (b, c, d), d has degree 1.
        let rows = set
            .invoke(
                "gds.degree.stream",
                &[Value::String("g".into()), Value::Null],
                &mut graph,
            )
            .expect("degree");
        assert_eq!(rows.len(), 4);
        let deg_of = |node: NodeId| {
            rows.iter()
                .find(|r| r[0] == Value::Integer(node.0 as i64))
                .map(|r| r[1].clone())
        };
        assert_eq!(deg_of(ids[0]), Some(Value::Float(3.0)));
        assert_eq!(deg_of(ids[3]), Some(Value::Float(1.0)));

        // pagerank: every projected node appears once, scores finite and positive.
        let rows = set
            .invoke(
                "gds.pageRank.stream",
                &[Value::String("g".into()), Value::Null],
                &mut graph,
            )
            .expect("pagerank");
        assert_eq!(rows.len(), 4);
        for r in &rows {
            match &r[1] {
                Value::Float(f) => assert!(f.is_finite() && *f > 0.0),
                other => panic!("expected float score, got {other:?}"),
            }
        }
    }

    #[test]
    fn wcc_groups_connected_nodes() {
        // Two disjoint edges: a-b and c-d. WCC -> two components.
        let mut graph = MemGraph::new();
        let a = graph.add_node(["N"], [] as [(&str, Value); 0]);
        let b = graph.add_node(["N"], [] as [(&str, Value); 0]);
        let c = graph.add_node(["N"], [] as [(&str, Value); 0]);
        let d = graph.add_node(["N"], [] as [(&str, Value); 0]);
        graph.add_rel("R", a, b, [] as [(&str, Value); 0]);
        graph.add_rel("R", c, d, [] as [(&str, Value); 0]);
        let (set, _cat) = registry_with_catalog();
        set.invoke(
            "gds.graph.project",
            &[
                Value::String("g".into()),
                Value::String("N".into()),
                Value::String("R".into()),
                Value::Null,
            ],
            &mut graph,
        )
        .expect("project");

        let rows = set
            .invoke(
                "gds.wcc.stream",
                &[Value::String("g".into()), Value::Null],
                &mut graph,
            )
            .expect("wcc");
        assert_eq!(rows.len(), 4);
        // a and b share a component; c and d share a different one.
        let comp = |node: NodeId| {
            rows.iter()
                .find(|r| r[0] == Value::Integer(node.0 as i64))
                .map(|r| r[1].clone())
                .expect("row")
        };
        assert_eq!(comp(a), comp(b));
        assert_eq!(comp(c), comp(d));
        assert_ne!(comp(a), comp(c));
    }

    #[test]
    fn dijkstra_stream_weighted() {
        // a -1-> b -1-> c, and a -5-> c. Shortest a..c == 2.
        let mut graph = MemGraph::new();
        let a = graph.add_node(["N"], [] as [(&str, Value); 0]);
        let b = graph.add_node(["N"], [] as [(&str, Value); 0]);
        let c = graph.add_node(["N"], [] as [(&str, Value); 0]);
        graph.add_rel("R", a, b, [("w", Value::Float(1.0))]);
        graph.add_rel("R", b, c, [("w", Value::Float(1.0))]);
        graph.add_rel("R", a, c, [("w", Value::Float(5.0))]);
        let (set, _cat) = registry_with_catalog();
        // Directed, weighted projection.
        set.invoke(
            "gds.graph.project",
            &[
                Value::String("g".into()),
                Value::String("N".into()),
                Value::String("R".into()),
                Value::Map(vec![
                    ("orientation".into(), Value::String("NATURAL".into())),
                    (
                        "relationshipWeightProperty".into(),
                        Value::String("w".into()),
                    ),
                ]),
            ],
            &mut graph,
        )
        .expect("project");

        let rows = set
            .invoke(
                "gds.dijkstra.stream",
                &[
                    Value::String("g".into()),
                    Value::Map(vec![(
                        "sourceNode".into(),
                        Value::Integer(a.0 as i64),
                    )]),
                ],
                &mut graph,
            )
            .expect("dijkstra");
        let dist = |node: NodeId| {
            rows.iter()
                .find(|r| r[0] == Value::Integer(node.0 as i64))
                .map(|r| r[1].clone())
        };
        assert_eq!(dist(a), Some(Value::Float(0.0)));
        assert_eq!(dist(b), Some(Value::Float(1.0)));
        assert_eq!(dist(c), Some(Value::Float(2.0))); // via b, not the direct weight-5 edge
    }

    #[test]
    fn betweenness_undirected_convention_halves_raw() {
        // Path a-b-c (undirected). Only b lies on the shortest path a..c.
        // Raw Brandes (ordered pairs) gives b a score of 2.0; undirected convention halves it to 1.0.
        let mut graph = MemGraph::new();
        let a = graph.add_node(["N"], [] as [(&str, Value); 0]);
        let b = graph.add_node(["N"], [] as [(&str, Value); 0]);
        let c = graph.add_node(["N"], [] as [(&str, Value); 0]);
        graph.add_rel("R", a, b, [] as [(&str, Value); 0]);
        graph.add_rel("R", b, c, [] as [(&str, Value); 0]);
        let (set, _cat) = registry_with_catalog();
        set.invoke(
            "gds.graph.project",
            &[
                Value::String("g".into()),
                Value::String("N".into()),
                Value::String("R".into()),
                Value::Null,
            ],
            &mut graph,
        )
        .expect("project");
        let rows = set
            .invoke(
                "gds.betweenness.stream",
                &[Value::String("g".into()), Value::Null],
                &mut graph,
            )
            .expect("betweenness");
        let score = |node: NodeId| {
            rows.iter()
                .find(|r| r[0] == Value::Integer(node.0 as i64))
                .map(|r| r[1].clone())
                .expect("row")
        };
        assert_eq!(score(a), Value::Float(0.0));
        assert_eq!(score(b), Value::Float(1.0)); // halved undirected convention
        assert_eq!(score(c), Value::Float(0.0));
    }
}
