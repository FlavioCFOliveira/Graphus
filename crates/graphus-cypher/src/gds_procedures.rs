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

use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant};

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
use graphus_gds::{
    Cancel, CsrBuilder, CsrGraph, GdsError, GraphCatalog, NodePropertyValues, Orientation,
};

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
// Resource policy (SEC-201/202/204): timeouts, iteration ceilings, projection quotas
// =================================================================================================

/// The process-wide GDS resource policy. `None` until the server installs one; the fail-safe default
/// ([`GdsResourcePolicy::default`]) is used otherwise — it already bounds every algorithm.
static GLOBAL_GDS_POLICY: OnceLock<GdsResourcePolicy> = OnceLock::new();

/// Installs the process-wide GDS resource policy (`SEC-201/202/204`). The **first** call wins
/// ([`OnceLock`] semantics); the server installs one at startup.
///
/// # Errors
///
/// Returns the already-installed [`GdsResourcePolicy`] if one was set.
pub fn set_global_gds_policy(policy: GdsResourcePolicy) -> Result<(), GdsResourcePolicy> {
    GLOBAL_GDS_POLICY.set(policy)
}

/// The GDS resource policy in force, or the bounded default when none was installed.
#[must_use]
pub fn global_gds_policy() -> &'static GdsResourcePolicy {
    GLOBAL_GDS_POLICY.get_or_init(GdsResourcePolicy::default)
}

/// Resource limits applied to every `gds.*` algorithm invocation (`SEC-201/202/204`).
///
/// All limits default to *bounded* values, so even a server that never configures a policy is
/// protected from a single adversarial query pinning a core forever (CPU DoS) or OOM-ing the host:
///
/// - **`algorithm_timeout`** — wall-clock deadline threaded into a real [`Cancel`], so an
///   `O(n·m)`/`O(n²)` run aborts with [`GdsError::Cancelled`] instead of burning a core indefinitely
///   (`SEC-201`).
/// - **`max_iterations`** — a ceiling on client-supplied `maxIterations` (`SEC-202`), so a request
///   like `{maxIterations: 4000000000}` is clamped to a sane bound.
/// - **`max_nodes` / `max_edges` / `max_memory_bytes`** — projection quotas enforced at
///   `gds.graph.project` time (`SEC-204`), so an attacker cannot materialise an unbounded in-memory
///   projection that downstream `O(n²)` algorithms then blow up into OOM.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GdsResourcePolicy {
    /// Wall-clock deadline for one algorithm run. `None` disables the timeout (not recommended in
    /// production). Default: 30 s.
    pub algorithm_timeout: Option<Duration>,
    /// Hard ceiling on the iteration count of iterative algorithms (PageRank, label propagation).
    /// Default: 1000.
    pub max_iterations: u32,
    /// Maximum node count of a projection. Default: 50 million.
    pub max_nodes: usize,
    /// Maximum (post-symmetrisation) edge count of a projection. Default: 200 million.
    pub max_edges: usize,
    /// Maximum estimated heap footprint of a projection, in bytes. Default: 4 GiB.
    pub max_memory_bytes: usize,
}

impl Default for GdsResourcePolicy {
    fn default() -> Self {
        Self {
            algorithm_timeout: Some(Duration::from_secs(30)),
            max_iterations: 1_000,
            max_nodes: 50_000_000,
            max_edges: 200_000_000,
            max_memory_bytes: 4 * 1024 * 1024 * 1024,
        }
    }
}

impl GdsResourcePolicy {
    /// Clamps a client-requested iteration count to [`Self::max_iterations`] (`SEC-202`).
    #[must_use]
    pub fn clamp_iterations(&self, requested: u32) -> u32 {
        requested.min(self.max_iterations)
    }

    /// Validates a freshly-built projection against the node/edge/memory quotas (`SEC-204`).
    ///
    /// # Errors
    ///
    /// [`GdsError::InvalidArgument`] when any quota is exceeded.
    fn check_projection(&self, g: &CsrGraph) -> std::result::Result<(), GdsError> {
        if g.node_count() > self.max_nodes {
            return Err(GdsError::InvalidArgument(format!(
                "projection has {} nodes, exceeding the configured limit of {}",
                g.node_count(),
                self.max_nodes
            )));
        }
        if g.edge_count() > self.max_edges {
            return Err(GdsError::InvalidArgument(format!(
                "projection has {} edges, exceeding the configured limit of {}",
                g.edge_count(),
                self.max_edges
            )));
        }
        let bytes = g.memory_bytes();
        if bytes > self.max_memory_bytes {
            return Err(GdsError::InvalidArgument(format!(
                "projection needs ~{bytes} bytes, exceeding the configured limit of {}",
                self.max_memory_bytes
            )));
        }
        Ok(())
    }
}

/// Runs `f`, supplying it a real [`Cancel`] that fires when the policy's wall-clock deadline elapses
/// (`SEC-201`). The algorithms check the `Cancel` cooperatively (per source / per iteration), so a
/// runaway `O(n·m)`/`O(n²)` run aborts with [`GdsError::Cancelled`] rather than pinning a core.
///
/// When no timeout is configured the supplied `Cancel` never fires (the algorithms still terminate
/// by their own bounds).
fn with_deadline<T>(
    f: impl FnOnce(&Cancel<'_>) -> Result<T, ProcedureFailure>,
) -> Result<T, ProcedureFailure> {
    match global_gds_policy().algorithm_timeout {
        Some(timeout) => {
            let deadline = Instant::now() + timeout;
            // `from_fn` is cheap: a single `Instant::now()` comparison per cooperative check.
            let cancel = Cancel::from_fn(move || Instant::now() >= deadline);
            f(&cancel)
        }
        None => f(&Cancel::never()),
    }
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

/// Validates and clamps a client-supplied `maxIterations` float to the policy ceiling (`SEC-202`).
///
/// Rejects a non-finite or negative value with a clear [`ProcedureFailure`] (rather than letting a
/// saturating `as u32` turn `f64::INFINITY` into `u32::MAX`), then clamps the rounded value to
/// [`GdsResourcePolicy::max_iterations`]. A fractional request is floored.
///
/// # Errors
///
/// [`ProcedureFailure`] when `m` is NaN, infinite, or negative.
fn clamp_max_iter(name: &str, m: f64) -> Result<u32, ProcedureFailure> {
    if !m.is_finite() || m < 0.0 {
        return Err(ProcedureFailure::new(
            name,
            "maxIterations must be a finite, non-negative integer",
        ));
    }
    // `m` is finite and >= 0 here; floor then saturate into u32 before clamping to the ceiling.
    let requested = if m >= f64::from(u32::MAX) {
        u32::MAX
    } else {
        m as u32
    };
    Ok(global_gds_policy().clamp_iterations(requested))
}

/// Reads a numeric configuration value from the optional trailing **config map** argument by key,
/// returning `None` when the map or key is absent (so the algorithm uses its default).
fn config_f64(args: &[Value], map_idx: usize, key: &str) -> Option<f64> {
    let Some(Value::Map(entries)) = args.get(map_idx) else {
        return None;
    };
    entries
        .iter()
        .find(|(k, _)| k == key)
        .and_then(|(_, v)| match v {
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
///
/// Every `gds.*` procedure is registered **reader-safe** (`rmp` task #546): its body only *reads* the
/// graph through the [`GraphAccess`](crate::graph_access::GraphAccess) seam
/// (`scan_nodes`/`scan_nodes_by_label`/`expand`/`rel_property`) and mutates only the shared
/// `Arc<Mutex<GraphCatalog>>` — never the transactional store — so a read-only auto-commit `CALL gds.*`
/// may run on the off-thread reader pool (where the algorithm's own `rmp` #342 rayon parallelism then
/// nests). The `Mutex` makes concurrent projections/streams across reader threads safe.
pub fn register_gds_procedures(set: &mut ProcedureSet, catalog: GdsCatalogHandle) {
    register_lifecycle(set, &catalog);
    register_centrality(set, &catalog);
    register_community(set, &catalog);
    register_pathfinding(set, &catalog);
    register_execution_modes(set, &catalog);
}

/// Registers the graph-lifecycle procedures.
fn register_lifecycle(set: &mut ProcedureSet, catalog: &GdsCatalogHandle) {
    // gds.graph.project(name, nodeFilter?, relFilter?, config?) :: (graphName, nodeCount, relationshipCount)
    let cat = Arc::clone(catalog);
    set.register_reader_safe(
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
            // SEC-204: enforce the projection quota (nodes / edges / estimated bytes) before the
            // projection is registered, so an unbounded in-memory graph (and the O(n^2) algorithms
            // that would run over it) is refused with a clean error rather than OOM-ing the host.
            global_gds_policy()
                .check_projection(&projected)
                .map_err(|e| gds_failure(NAME, e))?;
            let node_count = projected.node_count() as i64;
            let rel_count = projected.edge_count() as i64;

            let mut cat = lock_catalog(NAME, &cat)?;
            // Replace an existing projection of the same name (idempotent re-project), so a client can
            // re-project without an explicit drop.
            if cat.contains(name) {
                let _ = GraphCatalog::drop(&mut cat, name);
            }
            cat.project(name, projected)
                .map_err(|e| gds_failure(NAME, e))?;
            Ok(vec![vec![
                Value::String(name.to_owned()),
                Value::Integer(node_count),
                Value::Integer(rel_count),
            ]])
        }),
    );

    // gds.graph.list() :: (graphName, nodeCount, relationshipCount)
    let cat = Arc::clone(catalog);
    set.register_reader_safe(
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
    set.register_reader_safe(
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
    set.register_reader_safe(
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
    entries
        .iter()
        .find(|(k, _)| k == key)
        .and_then(|(_, v)| match v {
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
    set.register_reader_safe(
        ProcedureSignature::new(
            "gds.pageRank.stream",
            vec![string_in("graphName"), any_in("config")],
            vec![
                out("nodeId", ValueClass::Integer),
                out("score", ValueClass::Float),
            ],
        ),
        Box::new(move |args, _graph| {
            const NAME: &str = "gds.pageRank.stream";
            let g = get_projected(NAME, &cat, args)?;
            let mut config = PageRankConfig::default();
            if let Some(d) = config_f64(args, 1, "dampingFactor") {
                config.damping = d;
            }
            if let Some(m) = config_f64(args, 1, "maxIterations") {
                // SEC-202: clamp the client-supplied iteration count to the policy ceiling and reject
                // a non-finite / negative value explicitly (a saturating `as u32` would silently turn
                // `f64::INFINITY` into u32::MAX — the worst case).
                config.max_iter = clamp_max_iter(NAME, m)?;
            }
            if let Some(t) = config_f64(args, 1, "tolerance") {
                config.tolerance = t;
            }
            // SEC-201: a real deadline-backed Cancel aborts a runaway run. `rmp` #342/#559: PageRank is
            // now data-parallel; route it onto the SHARED analytics pool (as centrality is, `rmp` #376)
            // so the morsel + GDS thread budget stays bounded. Determinism is unaffected — the gather is
            // bit-identical across pool widths.
            let result = with_deadline(|cancel| {
                crate::morsel::run_on_analytics_pool(|| {
                    pagerank(&g, config, cancel).map_err(|e| gds_failure(NAME, e))
                })
            })?;
            Ok(id_score_rows(&g, &result.rank))
        }),
    );

    // gds.degree.stream(name) :: (nodeId, score)
    let cat = Arc::clone(catalog);
    set.register_reader_safe(
        ProcedureSignature::new(
            "gds.degree.stream",
            vec![string_in("graphName"), any_in("config")],
            vec![
                out("nodeId", ValueClass::Integer),
                out("score", ValueClass::Float),
            ],
        ),
        Box::new(move |args, _graph| {
            const NAME: &str = "gds.degree.stream";
            let g = get_projected(NAME, &cat, args)?;
            // `rmp` #342/#559: out-degree is now data-parallel; run it on the shared analytics pool.
            let degrees =
                crate::morsel::run_on_analytics_pool(|| degree_centrality(&g, Direction::Out));
            let scores: Vec<f64> = degrees.iter().map(|&d| d as f64).collect();
            Ok(id_score_rows(&g, &scores))
        }),
    );

    // gds.closeness.stream(name) :: (nodeId, score)
    let cat = Arc::clone(catalog);
    set.register_reader_safe(
        ProcedureSignature::new(
            "gds.closeness.stream",
            vec![string_in("graphName"), any_in("config")],
            vec![
                out("nodeId", ValueClass::Integer),
                out("score", ValueClass::Float),
            ],
        ),
        Box::new(move |args, _graph| {
            const NAME: &str = "gds.closeness.stream";
            let g = get_projected(NAME, &cat, args)?;
            // `rmp` task #376: run the data-parallel centrality on the SHARED analytics pool (the same
            // bounded `min(N,16)`-thread pool the morsel tier uses), not the global `rayon` pool, so the
            // morsel + GDS peak runnable-thread sum stays `≈` core count. Determinism is unaffected:
            // `install` changes only which workers run the `par_iter`, not the decomposition or the
            // order-independent reduction (see `morsel::run_on_analytics_pool`).
            let scores = with_deadline(|cancel| {
                crate::morsel::run_on_analytics_pool(|| {
                    closeness_centrality(&g, cancel).map_err(|e| gds_failure(NAME, e))
                })
            })?;
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
    set.register_reader_safe(
        ProcedureSignature::new(
            "gds.betweenness.stream",
            vec![string_in("graphName"), any_in("config")],
            vec![
                out("nodeId", ValueClass::Integer),
                out("score", ValueClass::Float),
            ],
        ),
        Box::new(move |args, _graph| {
            const NAME: &str = "gds.betweenness.stream";
            let g = get_projected(NAME, &cat, args)?;
            // `rmp` task #376: run on the SHARED analytics pool (see gds.closeness.stream above) — bounds
            // the morsel + GDS thread budget; determinism preserved (Brandes reduces by element-wise f64
            // addition whose per-source contributions are exact, independent of worker count).
            let raw = with_deadline(|cancel| {
                crate::morsel::run_on_analytics_pool(|| {
                    betweenness_centrality(&g, cancel).map_err(|e| gds_failure(NAME, e))
                })
            })?;
            let scores = undirected_scale(&g, raw);
            Ok(id_score_rows(&g, &scores))
        }),
    );
}

/// Registers the community / connectivity streaming procedures.
fn register_community(set: &mut ProcedureSet, catalog: &GdsCatalogHandle) {
    // gds.wcc.stream(name) :: (nodeId, componentId)
    let cat = Arc::clone(catalog);
    set.register_reader_safe(
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
            // `rmp` #342/#559: WCC uses a lock-free parallel union-find; run it on the analytics pool.
            let result = with_deadline(|cancel| {
                crate::morsel::run_on_analytics_pool(|| {
                    weakly_connected_components(&g, cancel).map_err(|e| gds_failure(NAME, e))
                })
            })?;
            Ok(id_component_rows(&g, &result.component))
        }),
    );

    // gds.scc.stream(name) :: (nodeId, componentId)
    let cat = Arc::clone(catalog);
    set.register_reader_safe(
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
            let result = with_deadline(|cancel| {
                strongly_connected_components(&g, cancel).map_err(|e| gds_failure(NAME, e))
            })?;
            Ok(id_component_rows(&g, &result.component))
        }),
    );

    // gds.labelPropagation.stream(name, config?) :: (nodeId, communityId)
    let cat = Arc::clone(catalog);
    set.register_reader_safe(
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
                // SEC-202: validate, clamp to the policy ceiling, and keep >= 1 (LPA requires it).
                config.max_iter = clamp_max_iter(NAME, m)?.max(1);
            }
            // `rmp` #342/#559: the parallel synchronous LPA variant runs on the analytics pool.
            let result = with_deadline(|cancel| {
                crate::morsel::run_on_analytics_pool(|| {
                    label_propagation(&g, config, cancel).map_err(|e| gds_failure(NAME, e))
                })
            })?;
            Ok(id_component_rows(&g, &result.label))
        }),
    );

    // gds.triangleCount.stream(name) :: (nodeId, triangleCount)
    let cat = Arc::clone(catalog);
    set.register_reader_safe(
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
            // `rmp` #342/#559: triangle counting is now node-parallel; run it on the analytics pool.
            let result = with_deadline(|cancel| {
                crate::morsel::run_on_analytics_pool(|| {
                    triangle_count(&g, cancel).map_err(|e| gds_failure(NAME, e))
                })
            })?;
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
    set.register_reader_safe(
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
    set.register_reader_safe(
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

    let paths = with_deadline(|cancel| {
        if bellman {
            bellman_ford(&g, source_internal, cancel)
        } else {
            dijkstra(&g, source_internal, cancel)
        }
        .map_err(|e| gds_failure(name, e))
    })?;

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

// =================================================================================================
// Execution modes: `.stats`, `.mutate`, `.write` for the node-property algorithms (`rmp` task #643)
// =================================================================================================
//
// Neo4j GDS runs each algorithm in one of four execution modes: `stream` (already registered above),
// `stats` (summary statistics only, no writes), `mutate` (write the result as a node property into
// the **in-memory projection**), and `write` (write the result as a node property back to the
// **database**). This section adds `stats`/`mutate`/`write` for the node-property-producing
// algorithms (the path algorithms `dijkstra`/`bellmanFord` write *relationships*/paths, a different
// seam, and keep their `stream` form only — a documented follow-up).
//
// # Faithful, curated column set (CLAUDE.md: never guess; scope and document)
//
// Neo4j's YIELD column set is algorithm- and mode-specific and includes distribution *histograms*
// (`centralityDistribution` / `componentDistribution`) computed with an internal HdrHistogram. This
// engine emits a **faithful curated subset** whose column **names and types match Neo4j exactly**
// (so a driver's `YIELD nodePropertiesWritten, computeMillis, …` binds by name), and computes the
// distribution maps **honestly** from the result vector (a well-defined nearest-rank percentile —
// see [`distribution_map`] — rather than fabricating Neo4j's exact histogram). The column **order**
// is normalized across algorithms (Cypher binds `YIELD` by name, so order affects only a standalone
// `CALL` display). Mode millis are measured; the `preProcessingMillis`/`postProcessingMillis` phases
// are reported honestly (0 for the negligible ones).

/// A GDS execution mode with a node-property result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mode {
    /// Summary statistics only — no property is written anywhere.
    Stats,
    /// Write the property into the in-memory projection (the GDS catalog).
    Mutate,
    /// Write the property back to the database (through the transactional [`GraphAccess`] seam).
    Write,
}

/// The algorithm-specific column shape shared by an algorithm's three mode procedures.
#[derive(Debug, Clone, Copy)]
struct ModeColumns {
    /// Leading summary columns (name + class), matching [`NodePropOutcome::summary`] in order. For
    /// pageRank this is `[("ranIterations", Integer), ("didConverge", Boolean)]`; for wcc/scc it is
    /// `[("componentCount", Integer)]`; etc.
    summary: &'static [(&'static str, ValueClass)],
    /// The distribution column name, if the algorithm produces one (`"centralityDistribution"` /
    /// `"componentDistribution"` / `"communityDistribution"`), else `None`.
    distribution: Option<&'static str>,
}

/// The result of one node-property algorithm run, ready for the stats/mutate/write emitters.
struct NodePropOutcome {
    /// Per-internal-id property values (Double for scores, Long for community/component/count ids),
    /// sized == the projection's node count.
    values: NodePropertyValues,
    /// Summary column **values**, in the order declared by [`ModeColumns::summary`].
    summary: Vec<Value>,
    /// The distribution map value — present iff [`ModeColumns::distribution`] is `Some`.
    distribution: Option<Value>,
}

/// A node-property algorithm's compute step: resolve config from `args`, run the algorithm on the
/// projected `graph`, and produce the [`NodePropOutcome`]. Shared by an algorithm's three modes.
type ComputeFn = Arc<
    dyn Fn(&str, &CsrGraph, &[Value]) -> Result<NodePropOutcome, ProcedureFailure> + Send + Sync,
>;

/// One non-nullable `ANY`-classed output field (used for the `Map`-valued columns — [`ValueClass`]
/// has no dedicated `Map` class, and a [`Value::Map`] egresses through `Any`).
fn out_map(name: &str) -> FieldSpec {
    FieldSpec::new(name, FieldType::required(ValueClass::Any))
}

/// One nullable `ANY`-classed output field (the distribution map, `null` on an empty graph).
fn out_map_nullable(name: &str) -> FieldSpec {
    FieldSpec::new(name, FieldType::nullable(ValueClass::Any))
}

/// Builds the ordered output field list for `mode` given the algorithm's `cols` (kept in lockstep
/// with [`mode_row`]).
fn mode_output_fields(cols: &ModeColumns, mode: Mode) -> Vec<FieldSpec> {
    let mut fields = Vec::new();
    for (name, class) in cols.summary {
        fields.push(out(name, *class));
    }
    if mode != Mode::Stats {
        fields.push(out("nodePropertiesWritten", ValueClass::Integer));
    }
    fields.push(out("preProcessingMillis", ValueClass::Integer));
    fields.push(out("computeMillis", ValueClass::Integer));
    match mode {
        Mode::Write => fields.push(out("writeMillis", ValueClass::Integer)),
        Mode::Mutate => fields.push(out("mutateMillis", ValueClass::Integer)),
        Mode::Stats => {}
    }
    fields.push(out("postProcessingMillis", ValueClass::Integer));
    if let Some(dist) = cols.distribution {
        fields.push(out_map_nullable(dist));
    }
    fields.push(out_map("configuration"));
    fields
}

/// The timing components of a mode run (all in whole milliseconds).
struct ModeTiming {
    pre_ms: i64,
    compute_ms: i64,
    /// The write/mutate phase (ignored for `stats`).
    mode_ms: i64,
    post_ms: i64,
}

/// Builds the single result row for `mode` (kept in lockstep with [`mode_output_fields`]).
fn mode_row(
    outcome: &NodePropOutcome,
    cols: &ModeColumns,
    mode: Mode,
    node_props_written: i64,
    timing: &ModeTiming,
    configuration: Value,
) -> Vec<Value> {
    let mut row = outcome.summary.clone();
    if mode != Mode::Stats {
        row.push(Value::Integer(node_props_written));
    }
    row.push(Value::Integer(timing.pre_ms));
    row.push(Value::Integer(timing.compute_ms));
    match mode {
        Mode::Write | Mode::Mutate => row.push(Value::Integer(timing.mode_ms)),
        Mode::Stats => {}
    }
    row.push(Value::Integer(timing.post_ms));
    if cols.distribution.is_some() {
        row.push(outcome.distribution.clone().unwrap_or(Value::Null));
    }
    row.push(configuration);
    row
}

/// Whole milliseconds elapsed since `start`, saturated into `i64` (never negative, never overflows).
fn elapsed_ms(start: Instant) -> i64 {
    i64::try_from(start.elapsed().as_millis()).unwrap_or(i64::MAX)
}

/// Echoes the resolved `configuration` map: the user's config map (if any) plus the mode's resolved
/// property key (`writeProperty` / `mutateProperty`), the latter overriding a user duplicate.
fn config_echo(args: &[Value], extra: &[(&str, Value)]) -> Value {
    let mut entries: Vec<(String, Value)> = match args.get(1) {
        Some(Value::Map(m)) => m.clone(),
        _ => Vec::new(),
    };
    for (k, v) in extra {
        entries.retain(|(ek, _)| ek != k);
        entries.push(((*k).to_owned(), v.clone()));
    }
    Value::Map(entries)
}

/// Extracts a required non-empty string config value (`writeProperty` / `mutateProperty`) from the
/// config map, erroring clearly when it is absent (write/mutate require it, like Neo4j GDS).
fn required_property(name: &str, args: &[Value], key: &str) -> Result<String, ProcedureFailure> {
    config_string(args, 1, key).ok_or_else(|| {
        ProcedureFailure::new(
            name,
            format!("the config map must carry a non-empty `{key}` string"),
        )
    })
}

/// A well-defined distribution summary of `values`: `{min, mean, max, p50, p75, p90, p95, p99,
/// p999}`. Percentiles use the **nearest-rank** method on a sorted copy (NaN-safe via
/// [`f64::total_cmp`]). An empty input yields an empty map. This is the honest, independently-computed
/// analogue of Neo4j's `centralityDistribution` / `componentDistribution` (whose exact HdrHistogram
/// values an independent implementation neither can nor should reproduce).
fn distribution_map(values: &[f64]) -> Value {
    if values.is_empty() {
        return Value::Map(Vec::new());
    }
    let mut sorted: Vec<f64> = values.to_vec();
    sorted.sort_by(f64::total_cmp);
    let n = sorted.len();
    let sum: f64 = sorted.iter().sum();
    let mean = sum / n as f64;
    // Nearest-rank percentile: the value at ceil(p/100 · n), 1-based, clamped into range.
    let percentile = |p: f64| -> f64 {
        let rank = ((p / 100.0) * n as f64).ceil() as usize;
        sorted[rank.saturating_sub(1).min(n - 1)]
    };
    Value::Map(vec![
        ("min".to_owned(), Value::Float(sorted[0])),
        ("mean".to_owned(), Value::Float(mean)),
        ("max".to_owned(), Value::Float(sorted[n - 1])),
        ("p50".to_owned(), Value::Float(percentile(50.0))),
        ("p75".to_owned(), Value::Float(percentile(75.0))),
        ("p90".to_owned(), Value::Float(percentile(90.0))),
        ("p95".to_owned(), Value::Float(percentile(95.0))),
        ("p99".to_owned(), Value::Float(percentile(99.0))),
        ("p999".to_owned(), Value::Float(percentile(99.9))),
    ])
}

/// The per-community aggregation shared by wcc / scc / labelPropagation: the property values (each
/// node's community/component external id), the distinct community count, and the distribution of
/// community **sizes**. `component[i]` is the internal representative id of node `i`.
struct CommunityAgg {
    /// Per-internal-id external community id (the representative's external id).
    values: Vec<i64>,
    /// The number of distinct communities.
    count: i64,
    /// The distribution of community sizes.
    distribution: Value,
}

fn aggregate_communities(graph: &CsrGraph, component: &[u32]) -> CommunityAgg {
    let externals = graph.external_ids();
    // Count nodes per representative.
    let mut sizes: std::collections::HashMap<u32, u64> = std::collections::HashMap::new();
    for &c in component {
        *sizes.entry(c).or_insert(0) += 1;
    }
    let count = sizes.len() as i64;
    let size_vec: Vec<f64> = sizes.values().map(|&s| s as f64).collect();
    let distribution = distribution_map(&size_vec);
    // Map each node's representative to its external id (falling back to the raw internal id when the
    // representative has no external mapping — defensive; every projected node has one).
    let values: Vec<i64> = component
        .iter()
        .map(|&c| externals.get(c as usize).copied().unwrap_or(u64::from(c)) as i64)
        .collect();
    CommunityAgg {
        values,
        count,
        distribution,
    }
}

/// Writes `values` back to the database as node property `property` (write mode), through the
/// transactional [`GraphAccess`] seam. Returns the number of nodes written (the projection node
/// count). Each internal id maps back to its external id, which is the node's [`NodeId`].
fn write_node_property(
    graph: &mut dyn GraphAccess,
    csr: &CsrGraph,
    property: &str,
    values: &NodePropertyValues,
) -> i64 {
    let externals = csr.external_ids();
    let mut written = 0i64;
    match values {
        NodePropertyValues::Double(v) => {
            for (i, &val) in v.iter().enumerate() {
                if let Some(&ext) = externals.get(i) {
                    graph.set_node_property(NodeId(ext), property, Value::Float(val));
                    written += 1;
                }
            }
        }
        NodePropertyValues::Long(v) => {
            for (i, &val) in v.iter().enumerate() {
                if let Some(&ext) = externals.get(i) {
                    graph.set_node_property(NodeId(ext), property, Value::Integer(val));
                    written += 1;
                }
            }
        }
    }
    written
}

/// Registers the `.stats`, `.mutate` and `.write` procedures of one node-property algorithm sharing
/// the `compute` step and column shape `cols`. `base` is the dotted prefix (e.g. `"gds.pageRank"`).
fn register_execution_modes_for(
    set: &mut ProcedureSet,
    catalog: &GdsCatalogHandle,
    base: &'static str,
    cols: ModeColumns,
    compute: ComputeFn,
) {
    // ---- .stats (read-only: no property written) ----
    {
        let cat = Arc::clone(catalog);
        let compute = Arc::clone(&compute);
        let name = format!("{base}.stats");
        let handler_name = name.clone();
        set.register_reader_safe(
            ProcedureSignature::new(
                name,
                vec![string_in("graphName"), any_in("config")],
                mode_output_fields(&cols, Mode::Stats),
            ),
            Box::new(move |args, _graph| {
                let pre = Instant::now();
                let g = get_projected(&handler_name, &cat, args)?;
                let pre_ms = elapsed_ms(pre);
                let compute_start = Instant::now();
                let outcome = compute(&handler_name, &g, args)?;
                let compute_ms = elapsed_ms(compute_start);
                let timing = ModeTiming {
                    pre_ms,
                    compute_ms,
                    mode_ms: 0,
                    post_ms: 0,
                };
                let config = config_echo(args, &[]);
                Ok(vec![mode_row(
                    &outcome,
                    &cols,
                    Mode::Stats,
                    0,
                    &timing,
                    config,
                )])
            }),
        );
    }

    // ---- .mutate (write into the in-memory projection) ----
    {
        let cat = Arc::clone(catalog);
        let compute = Arc::clone(&compute);
        let name = format!("{base}.mutate");
        let handler_name = name.clone();
        set.register_reader_safe(
            ProcedureSignature::new(
                name,
                vec![string_in("graphName"), any_in("config")],
                mode_output_fields(&cols, Mode::Mutate),
            ),
            Box::new(move |args, _graph| {
                let graph_name = arg_graph_name(&handler_name, args)?.to_owned();
                let mutate_property = required_property(&handler_name, args, "mutateProperty")?;
                let pre = Instant::now();
                let g = get_projected(&handler_name, &cat, args)?;
                let pre_ms = elapsed_ms(pre);
                let compute_start = Instant::now();
                let outcome = compute(&handler_name, &g, args)?;
                let compute_ms = elapsed_ms(compute_start);
                let mutate_start = Instant::now();
                let written = {
                    let mut catalog = lock_catalog(&handler_name, &cat)?;
                    catalog
                        .mutate_node_property(&graph_name, &mutate_property, outcome.values.clone())
                        .map_err(|e| gds_failure(&handler_name, e))?
                } as i64;
                let mode_ms = elapsed_ms(mutate_start);
                let timing = ModeTiming {
                    pre_ms,
                    compute_ms,
                    mode_ms,
                    post_ms: 0,
                };
                let config = config_echo(
                    args,
                    &[("mutateProperty", Value::String(mutate_property.clone()))],
                );
                Ok(vec![mode_row(
                    &outcome,
                    &cols,
                    Mode::Mutate,
                    written,
                    &timing,
                    config,
                )])
            }),
        );
    }

    // ---- .write (write back to the database) ----
    // NOT reader-safe: it mutates the transactional store, so the executor keeps it on the engine
    // thread with the writable `&mut dyn GraphAccess`.
    {
        let cat = Arc::clone(catalog);
        let compute = Arc::clone(&compute);
        let name = format!("{base}.write");
        let handler_name = name.clone();
        set.register(
            ProcedureSignature::new(
                name,
                vec![string_in("graphName"), any_in("config")],
                mode_output_fields(&cols, Mode::Write),
            ),
            Box::new(move |args, graph| {
                let write_property = required_property(&handler_name, args, "writeProperty")?;
                let pre = Instant::now();
                let g = get_projected(&handler_name, &cat, args)?;
                let pre_ms = elapsed_ms(pre);
                let compute_start = Instant::now();
                let outcome = compute(&handler_name, &g, args)?;
                let compute_ms = elapsed_ms(compute_start);
                let write_start = Instant::now();
                let written = write_node_property(graph, &g, &write_property, &outcome.values);
                let mode_ms = elapsed_ms(write_start);
                let timing = ModeTiming {
                    pre_ms,
                    compute_ms,
                    mode_ms,
                    post_ms: 0,
                };
                let config = config_echo(
                    args,
                    &[("writeProperty", Value::String(write_property.clone()))],
                );
                Ok(vec![mode_row(
                    &outcome,
                    &cols,
                    Mode::Write,
                    written,
                    &timing,
                    config,
                )])
            }),
        );
    }
}

/// Registers the `.stats`/`.mutate`/`.write` modes for every node-property algorithm (`rmp` #643).
fn register_execution_modes(set: &mut ProcedureSet, catalog: &GdsCatalogHandle) {
    // Centrality (Float score; centralityDistribution). pageRank additionally reports its
    // iteration/convergence summary.
    register_execution_modes_for(
        set,
        catalog,
        "gds.pageRank",
        ModeColumns {
            summary: &[
                ("ranIterations", ValueClass::Integer),
                ("didConverge", ValueClass::Boolean),
            ],
            distribution: Some("centralityDistribution"),
        },
        Arc::new(pagerank_outcome),
    );
    register_execution_modes_for(
        set,
        catalog,
        "gds.degree",
        ModeColumns {
            summary: &[],
            distribution: Some("centralityDistribution"),
        },
        Arc::new(degree_outcome),
    );
    register_execution_modes_for(
        set,
        catalog,
        "gds.closeness",
        ModeColumns {
            summary: &[],
            distribution: Some("centralityDistribution"),
        },
        Arc::new(closeness_outcome),
    );
    register_execution_modes_for(
        set,
        catalog,
        "gds.betweenness",
        ModeColumns {
            summary: &[],
            distribution: Some("centralityDistribution"),
        },
        Arc::new(betweenness_outcome),
    );

    // Community / connectivity (Long community/component id; componentDistribution).
    register_execution_modes_for(
        set,
        catalog,
        "gds.wcc",
        ModeColumns {
            summary: &[("componentCount", ValueClass::Integer)],
            distribution: Some("componentDistribution"),
        },
        Arc::new(wcc_outcome),
    );
    register_execution_modes_for(
        set,
        catalog,
        "gds.scc",
        ModeColumns {
            summary: &[("componentCount", ValueClass::Integer)],
            distribution: Some("componentDistribution"),
        },
        Arc::new(scc_outcome),
    );
    register_execution_modes_for(
        set,
        catalog,
        "gds.labelPropagation",
        ModeColumns {
            summary: &[
                ("ranIterations", ValueClass::Integer),
                ("didConverge", ValueClass::Boolean),
                ("communityCount", ValueClass::Integer),
            ],
            distribution: Some("communityDistribution"),
        },
        Arc::new(labelprop_outcome),
    );

    // Triangle counting (Long per-node triangle count; no distribution — Neo4j reports the global
    // count and node count instead).
    register_execution_modes_for(
        set,
        catalog,
        "gds.triangleCount",
        ModeColumns {
            summary: &[
                ("globalTriangleCount", ValueClass::Integer),
                ("nodeCount", ValueClass::Integer),
            ],
            distribution: None,
        },
        Arc::new(triangle_outcome),
    );

    register_node_property_readback(set, catalog);
}

// ---- per-algorithm compute steps (mirror the `.stream` config parsing / algorithm calls) --------

fn pagerank_outcome(
    name: &str,
    g: &CsrGraph,
    args: &[Value],
) -> Result<NodePropOutcome, ProcedureFailure> {
    let mut config = PageRankConfig::default();
    if let Some(d) = config_f64(args, 1, "dampingFactor") {
        config.damping = d;
    }
    if let Some(m) = config_f64(args, 1, "maxIterations") {
        config.max_iter = clamp_max_iter(name, m)?;
    }
    if let Some(t) = config_f64(args, 1, "tolerance") {
        config.tolerance = t;
    }
    let result = with_deadline(|cancel| {
        crate::morsel::run_on_analytics_pool(|| {
            pagerank(g, config, cancel).map_err(|e| gds_failure(name, e))
        })
    })?;
    let distribution = Some(distribution_map(&result.rank));
    Ok(NodePropOutcome {
        summary: vec![
            Value::Integer(i64::from(result.iterations)),
            Value::Boolean(result.converged),
        ],
        distribution,
        values: NodePropertyValues::Double(result.rank),
    })
}

fn degree_outcome(
    _name: &str,
    g: &CsrGraph,
    _args: &[Value],
) -> Result<NodePropOutcome, ProcedureFailure> {
    let degrees = crate::morsel::run_on_analytics_pool(|| degree_centrality(g, Direction::Out));
    let scores: Vec<f64> = degrees.iter().map(|&d| d as f64).collect();
    let distribution = Some(distribution_map(&scores));
    Ok(NodePropOutcome {
        summary: Vec::new(),
        distribution,
        values: NodePropertyValues::Double(scores),
    })
}

fn closeness_outcome(
    name: &str,
    g: &CsrGraph,
    _args: &[Value],
) -> Result<NodePropOutcome, ProcedureFailure> {
    let scores = with_deadline(|cancel| {
        crate::morsel::run_on_analytics_pool(|| {
            closeness_centrality(g, cancel).map_err(|e| gds_failure(name, e))
        })
    })?;
    let distribution = Some(distribution_map(&scores));
    Ok(NodePropOutcome {
        summary: Vec::new(),
        distribution,
        values: NodePropertyValues::Double(scores),
    })
}

fn betweenness_outcome(
    name: &str,
    g: &CsrGraph,
    _args: &[Value],
) -> Result<NodePropOutcome, ProcedureFailure> {
    let raw = with_deadline(|cancel| {
        crate::morsel::run_on_analytics_pool(|| {
            betweenness_centrality(g, cancel).map_err(|e| gds_failure(name, e))
        })
    })?;
    let scores = undirected_scale(g, raw);
    let distribution = Some(distribution_map(&scores));
    Ok(NodePropOutcome {
        summary: Vec::new(),
        distribution,
        values: NodePropertyValues::Double(scores),
    })
}

fn wcc_outcome(
    name: &str,
    g: &CsrGraph,
    _args: &[Value],
) -> Result<NodePropOutcome, ProcedureFailure> {
    let result = with_deadline(|cancel| {
        crate::morsel::run_on_analytics_pool(|| {
            weakly_connected_components(g, cancel).map_err(|e| gds_failure(name, e))
        })
    })?;
    let agg = aggregate_communities(g, &result.component);
    Ok(NodePropOutcome {
        summary: vec![Value::Integer(agg.count)],
        distribution: Some(agg.distribution),
        values: NodePropertyValues::Long(agg.values),
    })
}

fn scc_outcome(
    name: &str,
    g: &CsrGraph,
    _args: &[Value],
) -> Result<NodePropOutcome, ProcedureFailure> {
    let result = with_deadline(|cancel| {
        strongly_connected_components(g, cancel).map_err(|e| gds_failure(name, e))
    })?;
    let agg = aggregate_communities(g, &result.component);
    Ok(NodePropOutcome {
        summary: vec![Value::Integer(agg.count)],
        distribution: Some(agg.distribution),
        values: NodePropertyValues::Long(agg.values),
    })
}

fn labelprop_outcome(
    name: &str,
    g: &CsrGraph,
    args: &[Value],
) -> Result<NodePropOutcome, ProcedureFailure> {
    let mut config = LabelPropagationConfig::default();
    if let Some(m) = config_f64(args, 1, "maxIterations") {
        config.max_iter = clamp_max_iter(name, m)?.max(1);
    }
    let result = with_deadline(|cancel| {
        crate::morsel::run_on_analytics_pool(|| {
            label_propagation(g, config, cancel).map_err(|e| gds_failure(name, e))
        })
    })?;
    let agg = aggregate_communities(g, &result.label);
    Ok(NodePropOutcome {
        summary: vec![
            Value::Integer(i64::from(result.iterations)),
            Value::Boolean(result.converged),
            Value::Integer(agg.count),
        ],
        distribution: Some(agg.distribution),
        values: NodePropertyValues::Long(agg.values),
    })
}

fn triangle_outcome(
    name: &str,
    g: &CsrGraph,
    _args: &[Value],
) -> Result<NodePropOutcome, ProcedureFailure> {
    let result = with_deadline(|cancel| {
        crate::morsel::run_on_analytics_pool(|| {
            triangle_count(g, cancel).map_err(|e| gds_failure(name, e))
        })
    })?;
    // Each triangle is counted once at each of its three vertices, so the global count is the
    // per-node sum divided by three.
    let per_node_sum: u64 = result
        .triangles
        .iter()
        .copied()
        .fold(0, u64::saturating_add);
    let global = (per_node_sum / 3) as i64;
    let node_count = result.triangles.len() as i64;
    let values: Vec<i64> = result.triangles.iter().map(|&t| t as i64).collect();
    Ok(NodePropOutcome {
        summary: vec![Value::Integer(global), Value::Integer(node_count)],
        distribution: None,
        values: NodePropertyValues::Long(values),
    })
}

/// Registers `gds.graph.nodeProperty.stream(graphName, nodeProperty)` :: (nodeId, propertyValue),
/// which streams a **mutated** node property back out of the in-memory projection so a `mutate`-mode
/// result is observable (and testable) end-to-end (Neo4j `gds.graph.nodeProperty.stream`).
fn register_node_property_readback(set: &mut ProcedureSet, catalog: &GdsCatalogHandle) {
    let cat = Arc::clone(catalog);
    set.register_reader_safe(
        ProcedureSignature::new(
            "gds.graph.nodeProperty.stream",
            vec![string_in("graphName"), string_in("nodeProperty")],
            vec![
                out("nodeId", ValueClass::Integer),
                // A GDS node property is scalar (Float or Integer); `Any` egresses either.
                out("propertyValue", ValueClass::Any),
            ],
        ),
        Box::new(move |args, _graph| {
            const NAME: &str = "gds.graph.nodeProperty.stream";
            let graph_name = arg_graph_name(NAME, args)?.to_owned();
            let Some(Value::String(property)) = args.get(1).filter(|v| {
                matches!(v, Value::String(s) if !s.is_empty())
            }) else {
                return Err(ProcedureFailure::new(
                    NAME,
                    "the second argument must be a non-empty node-property name (a string)",
                ));
            };
            let cat = lock_catalog(NAME, &cat)?;
            let g = cat.get(&graph_name).map_err(|e| gds_failure(NAME, e))?;
            let externals = g.external_ids();
            let Some(values) = cat.node_property(&graph_name, property) else {
                return Err(ProcedureFailure::new(
                    NAME,
                    format!(
                        "node property '{property}' does not exist in the in-memory graph '{graph_name}'"
                    ),
                ));
            };
            let mut rows = Vec::with_capacity(externals.len());
            match values {
                NodePropertyValues::Double(v) => {
                    for (i, &val) in v.iter().enumerate() {
                        if let Some(&ext) = externals.get(i) {
                            rows.push(vec![Value::Integer(ext as i64), Value::Float(val)]);
                        }
                    }
                }
                NodePropertyValues::Long(v) => {
                    for (i, &val) in v.iter().enumerate() {
                        if let Some(&ext) = externals.get(i) {
                            rows.push(vec![Value::Integer(ext as i64), Value::Integer(val)]);
                        }
                    }
                }
            }
            Ok(rows)
        }),
    );
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
            .invoke("gds.graph.exists", &[Value::String("g".into())], &mut graph)
            .expect("exists");
        assert_eq!(rows[0][1], Value::Boolean(true));

        // list
        let rows = set.invoke("gds.graph.list", &[], &mut graph).expect("list");
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0][0], Value::String("g".into()));

        // drop
        set.invoke("gds.graph.drop", &[Value::String("g".into())], &mut graph)
            .expect("drop");
        let rows = set
            .invoke("gds.graph.exists", &[Value::String("g".into())], &mut graph)
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
                    Value::Map(vec![("sourceNode".into(), Value::Integer(a.0 as i64))]),
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

    // =============================================================================================
    // Security regression tests for the resource policy (SEC-201/202/204).
    //
    // These exercise the policy logic directly (not the process-global `OnceLock`, which is shared
    // across the whole test binary and must not be perturbed) so they are deterministic and isolated.
    // =============================================================================================

    /// Regression: SEC-202 — a client-supplied `maxIterations` is clamped to the policy ceiling, and
    /// a non-finite / negative value is rejected rather than saturating to `u32::MAX`.
    #[test]
    fn sec202_max_iterations_is_clamped_and_validated() {
        let policy = GdsResourcePolicy {
            max_iterations: 50,
            ..GdsResourcePolicy::default()
        };
        // Clamp: a huge request is capped at the ceiling.
        assert_eq!(policy.clamp_iterations(4_000_000_000), 50);
        // A modest request passes through unchanged.
        assert_eq!(policy.clamp_iterations(10), 10);

        // The float coercion rejects non-finite / negative values (the worst case the old
        // `as u32` cast silently turned into u32::MAX).
        assert!(clamp_max_iter("test", f64::INFINITY).is_err());
        assert!(clamp_max_iter("test", f64::NAN).is_err());
        assert!(clamp_max_iter("test", -1.0).is_err());
        // A finite value is floored then clamped against the GLOBAL policy ceiling (default 1000).
        let v = clamp_max_iter("test", 3.9).expect("finite value is accepted");
        assert_eq!(v, 3);
    }

    /// Regression: SEC-204 — a projection exceeding the node/edge/memory quota is rejected with a
    /// clean error rather than being registered (and later blown up by an O(n^2) algorithm).
    #[test]
    fn sec204_projection_quota_is_enforced() {
        // Build a small real projection via the procedure layer.
        let (mut graph, _) = triangle_graph();
        let g =
            project_from_graph("test", &graph, Some("N"), Some("R"), None, true).expect("project");
        let _ = &mut graph;

        // A generous policy admits it.
        let ok = GdsResourcePolicy::default();
        assert!(ok.check_projection(&g).is_ok());

        // A node quota of zero rejects any non-empty projection.
        let tight_nodes = GdsResourcePolicy {
            max_nodes: 0,
            ..GdsResourcePolicy::default()
        };
        let err = tight_nodes
            .check_projection(&g)
            .expect_err("node quota must reject");
        assert!(matches!(err, GdsError::InvalidArgument(_)));

        // A memory quota of 1 byte rejects on the bytes basis.
        let tight_mem = GdsResourcePolicy {
            max_memory_bytes: 1,
            ..GdsResourcePolicy::default()
        };
        assert!(matches!(
            tight_mem.check_projection(&g),
            Err(GdsError::InvalidArgument(_))
        ));
    }

    /// Regression: SEC-201 — `with_deadline` builds a real, deadline-backed [`Cancel`]; an algorithm
    /// run against an already-elapsed deadline aborts with `Cancelled` instead of running to
    /// completion. We prove the wiring directly (a `from_fn` Cancel that is already past its
    /// deadline), since the procedure body now threads exactly such a token.
    #[test]
    fn sec201_deadline_cancel_aborts_a_run() {
        let (mut graph, _) = triangle_graph();
        let g =
            project_from_graph("test", &graph, Some("N"), Some("R"), None, true).expect("project");
        let _ = &mut graph;

        // An already-expired deadline: the cooperative check fires on the first poll.
        let past = Instant::now() - Duration::from_secs(1);
        let cancel = Cancel::from_fn(move || Instant::now() >= past);
        let err = betweenness_centrality(&g, &cancel)
            .expect_err("an expired deadline must abort the run");
        assert_eq!(err, GdsError::Cancelled);
    }

    // ---- execution modes: `.stats` / `.mutate` / `.write` (`rmp` task #643) -------------------

    /// Projects the `triangle_graph` fixture as the named graph `"g"`.
    fn project_g(set: &ProcedureSet, graph: &mut MemGraph) {
        set.invoke(
            "gds.graph.project",
            &[
                Value::String("g".into()),
                Value::String("N".into()),
                Value::String("R".into()),
                Value::Null,
            ],
            graph,
        )
        .expect("project");
    }

    /// Reads a named output column from a single-row mode result via the procedure signature (so the
    /// test binds by column name, exactly as a `YIELD` would).
    fn col(set: &ProcedureSet, proc: &str, row: &[Value], name: &str) -> Value {
        let sig = set.signature(proc).expect("signature");
        let idx = sig
            .outputs
            .iter()
            .position(|f| f.name == name)
            .unwrap_or_else(|| panic!("column {name} not found in {proc}"));
        row[idx].clone()
    }

    /// A config map `{key: value}`.
    fn cfg(pairs: &[(&str, Value)]) -> Value {
        Value::Map(
            pairs
                .iter()
                .map(|(k, v)| ((*k).to_owned(), v.clone()))
                .collect(),
        )
    }

    #[test]
    fn pagerank_stats_reports_summary_and_distribution() {
        let (mut graph, _) = triangle_graph();
        let (set, _cat) = registry_with_catalog();
        project_g(&set, &mut graph);

        let rows = set
            .invoke(
                "gds.pageRank.stats",
                &[Value::String("g".into()), Value::Null],
                &mut graph,
            )
            .expect("stats");
        assert_eq!(rows.len(), 1);
        let row = &rows[0];
        // Summary columns present and honestly typed.
        assert!(matches!(
            col(&set, "gds.pageRank.stats", row, "ranIterations"),
            Value::Integer(n) if n >= 1
        ));
        assert!(matches!(
            col(&set, "gds.pageRank.stats", row, "didConverge"),
            Value::Boolean(_)
        ));
        assert!(matches!(
            col(&set, "gds.pageRank.stats", row, "computeMillis"),
            Value::Integer(_)
        ));
        // The distribution is a non-empty map with the documented keys.
        let Value::Map(dist) = col(&set, "gds.pageRank.stats", row, "centralityDistribution")
        else {
            panic!("centralityDistribution must be a map");
        };
        assert!(dist.iter().any(|(k, _)| k == "max"));
        assert!(dist.iter().any(|(k, _)| k == "p99"));
        // stats writes nothing: there is no nodePropertiesWritten column.
        assert!(
            set.signature("gds.pageRank.stats")
                .unwrap()
                .outputs
                .iter()
                .all(|f| f.name != "nodePropertiesWritten")
        );
    }

    #[test]
    fn pagerank_write_sets_node_property_and_counts() {
        let (mut graph, ids) = triangle_graph();
        let (set, _cat) = registry_with_catalog();
        project_g(&set, &mut graph);

        let rows = set
            .invoke(
                "gds.pageRank.write",
                &[
                    Value::String("g".into()),
                    cfg(&[("writeProperty", Value::String("pr".into()))]),
                ],
                &mut graph,
            )
            .expect("write");
        // 4 node properties written.
        assert_eq!(
            col(
                &set,
                "gds.pageRank.write",
                &rows[0],
                "nodePropertiesWritten"
            ),
            Value::Integer(4)
        );
        assert!(matches!(
            col(&set, "gds.pageRank.write", &rows[0], "writeMillis"),
            Value::Integer(_)
        ));
        // The property landed on the actual nodes (through the write seam), as a Float.
        for id in ids {
            assert!(matches!(
                graph.node_property(id, "pr"),
                Some(Value::Float(f)) if f.is_finite() && f > 0.0
            ));
        }
        // The echoed configuration carries the resolved writeProperty.
        let Value::Map(config) = col(&set, "gds.pageRank.write", &rows[0], "configuration") else {
            panic!("configuration must be a map");
        };
        assert!(
            config
                .iter()
                .any(|(k, v)| k == "writeProperty" && *v == Value::String("pr".into()))
        );
    }

    #[test]
    fn pagerank_write_requires_write_property() {
        let (mut graph, _) = triangle_graph();
        let (set, _cat) = registry_with_catalog();
        project_g(&set, &mut graph);
        // No writeProperty in the config -> clean error, nothing written.
        let err = set
            .invoke(
                "gds.pageRank.write",
                &[Value::String("g".into()), Value::Null],
                &mut graph,
            )
            .expect_err("write requires writeProperty");
        assert!(format!("{err}").contains("writeProperty"));
    }

    #[test]
    fn pagerank_mutate_then_read_back() {
        let (mut graph, ids) = triangle_graph();
        let (set, _cat) = registry_with_catalog();
        project_g(&set, &mut graph);

        let rows = set
            .invoke(
                "gds.pageRank.mutate",
                &[
                    Value::String("g".into()),
                    cfg(&[("mutateProperty", Value::String("pr".into()))]),
                ],
                &mut graph,
            )
            .expect("mutate");
        assert_eq!(
            col(
                &set,
                "gds.pageRank.mutate",
                &rows[0],
                "nodePropertiesWritten"
            ),
            Value::Integer(4)
        );
        assert!(matches!(
            col(&set, "gds.pageRank.mutate", &rows[0], "mutateMillis"),
            Value::Integer(_)
        ));
        // The mutate wrote into the in-memory projection, NOT the database (a real node has no `pr`).
        assert!(graph.node_property(ids[0], "pr").is_none());

        // Read the mutated property back out of the projection.
        let back = set
            .invoke(
                "gds.graph.nodeProperty.stream",
                &[Value::String("g".into()), Value::String("pr".into())],
                &mut graph,
            )
            .expect("read back");
        assert_eq!(back.len(), 4);
        for r in &back {
            assert!(matches!(r[1], Value::Float(f) if f.is_finite() && f > 0.0));
        }

        // A second mutate under the same property name is rejected (Neo4j GDS semantics).
        let err = set
            .invoke(
                "gds.pageRank.mutate",
                &[
                    Value::String("g".into()),
                    cfg(&[("mutateProperty", Value::String("pr".into()))]),
                ],
                &mut graph,
            )
            .expect_err("duplicate mutate property");
        assert!(format!("{err}").contains("already exists"));
    }

    #[test]
    fn wcc_modes_report_component_count_and_write_ids() {
        // Two disjoint components: a triangle {a,b,c}+pendant d (component 0) and an isolated pair.
        let mut graph = MemGraph::new();
        let a = graph.add_node(["N"], [] as [(&str, Value); 0]);
        let b = graph.add_node(["N"], [] as [(&str, Value); 0]);
        let c = graph.add_node(["N"], [] as [(&str, Value); 0]);
        let e = graph.add_node(["N"], [] as [(&str, Value); 0]);
        let f = graph.add_node(["N"], [] as [(&str, Value); 0]);
        graph.add_rel("R", a, b, [] as [(&str, Value); 0]);
        graph.add_rel("R", b, c, [] as [(&str, Value); 0]);
        graph.add_rel("R", e, f, [] as [(&str, Value); 0]);
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

        // stats: exactly two components.
        let rows = set
            .invoke(
                "gds.wcc.stats",
                &[Value::String("g".into()), Value::Null],
                &mut graph,
            )
            .expect("wcc stats");
        assert_eq!(
            col(&set, "gds.wcc.stats", &rows[0], "componentCount"),
            Value::Integer(2)
        );

        // write: each node gets an Integer component id property.
        let rows = set
            .invoke(
                "gds.wcc.write",
                &[
                    Value::String("g".into()),
                    cfg(&[("writeProperty", Value::String("comp".into()))]),
                ],
                &mut graph,
            )
            .expect("wcc write");
        assert_eq!(
            col(&set, "gds.wcc.write", &rows[0], "nodePropertiesWritten"),
            Value::Integer(5)
        );
        // a, b, c share a component; e, f share the other; the two differ.
        let comp = |id: NodeId| match graph.node_property(id, "comp") {
            Some(Value::Integer(v)) => v,
            other => panic!("expected an Integer component id, got {other:?}"),
        };
        assert_eq!(comp(a), comp(b));
        assert_eq!(comp(b), comp(c));
        assert_eq!(comp(e), comp(f));
        assert_ne!(comp(a), comp(e));
    }

    #[test]
    fn triangle_count_stats_reports_global_and_node_count() {
        let (mut graph, _) = triangle_graph();
        let (set, _cat) = registry_with_catalog();
        project_g(&set, &mut graph);
        let rows = set
            .invoke(
                "gds.triangleCount.stats",
                &[Value::String("g".into()), Value::Null],
                &mut graph,
            )
            .expect("triangleCount stats");
        // The fixture has exactly one triangle (a-b-c) and 4 nodes.
        assert_eq!(
            col(
                &set,
                "gds.triangleCount.stats",
                &rows[0],
                "globalTriangleCount"
            ),
            Value::Integer(1)
        );
        assert_eq!(
            col(&set, "gds.triangleCount.stats", &rows[0], "nodeCount"),
            Value::Integer(4)
        );
    }

    #[test]
    fn all_node_property_algorithms_register_three_modes() {
        let (set, _cat) = registry_with_catalog();
        for base in [
            "gds.pageRank",
            "gds.degree",
            "gds.closeness",
            "gds.betweenness",
            "gds.wcc",
            "gds.scc",
            "gds.labelPropagation",
            "gds.triangleCount",
        ] {
            for mode in ["stats", "mutate", "write"] {
                let proc = format!("{base}.{mode}");
                assert!(set.signature(&proc).is_some(), "missing procedure {proc}");
            }
        }
        // The mutate read-back procedure is registered too.
        assert!(set.signature("gds.graph.nodeProperty.stream").is_some());
        // `.write` is NOT reader-safe (it mutates the store); the read-only modes are.
        assert!(!set.is_reader_safe("gds.pageRank.write"));
        assert!(set.is_reader_safe("gds.pageRank.stats"));
        assert!(set.is_reader_safe("gds.pageRank.mutate"));
    }

    #[test]
    fn distribution_map_percentiles_are_well_defined() {
        // 1..=10: min 1, max 10, mean 5.5; nearest-rank p50 = 5, p90 = 9, p99/p999 = 10.
        let values: Vec<f64> = (1..=10).map(|n| n as f64).collect();
        let Value::Map(m) = distribution_map(&values) else {
            panic!("expected a map");
        };
        let get = |k: &str| {
            m.iter()
                .find(|(key, _)| key == k)
                .map(|(_, v)| v.clone())
                .unwrap()
        };
        assert_eq!(get("min"), Value::Float(1.0));
        assert_eq!(get("max"), Value::Float(10.0));
        assert_eq!(get("mean"), Value::Float(5.5));
        assert_eq!(get("p50"), Value::Float(5.0));
        assert_eq!(get("p90"), Value::Float(9.0));
        assert_eq!(get("p999"), Value::Float(10.0));
        // An empty input yields an empty map (no panic).
        assert_eq!(distribution_map(&[]), Value::Map(Vec::new()));
    }
}
