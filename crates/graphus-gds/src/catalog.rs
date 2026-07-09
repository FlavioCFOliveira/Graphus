//! A simple in-memory named-graph catalog (`project` / `list` / `drop`).
//!
//! Projections are stored behind `Arc` so a long-running algorithm can keep reading a graph after
//! it has been dropped from the catalog (the `Arc` keeps it alive until the last reader finishes).
//!
//! # Mutated node properties (the `mutate` execution mode)
//!
//! Besides the immutable [`CsrGraph`] projections, the catalog holds the **mutated node properties**
//! written by a `mutate`-mode algorithm run (e.g. `gds.pageRank.mutate`). Unlike `write` mode (which
//! writes back to the transactional store), `mutate` mode writes into the *in-memory projection* so a
//! later step (or a `gds.graph.nodeProperty.stream` read-back) can consume the result without
//! touching the database. Mutated properties are keyed by graph name then property name and indexed
//! by **internal id** (aligned with [`CsrGraph::external_ids`]); they are cleared when the graph is
//! dropped or re-projected.

use crate::csr::CsrGraph;
use crate::error::{GdsError, Result};
use std::collections::HashMap;
use std::sync::Arc;

/// Node-property values produced by a `mutate` run, stored in the in-memory projection.
///
/// Values are indexed by **internal id** (position `i` is the value for the node whose external id
/// is [`CsrGraph::external_ids`]`()[i]`). A GDS node property is numeric; the two variants keep the
/// natural type so a `Long` community/component id is never lossily widened through an `f64`.
#[derive(Debug, Clone, PartialEq)]
pub enum NodePropertyValues {
    /// A floating-point property (e.g. a centrality score).
    Double(Vec<f64>),
    /// An integer property (e.g. a component / community id, or a per-node count).
    Long(Vec<i64>),
}

impl NodePropertyValues {
    /// The number of node values held.
    #[must_use]
    pub fn len(&self) -> usize {
        match self {
            Self::Double(v) => v.len(),
            Self::Long(v) => v.len(),
        }
    }

    /// Whether no node values are held.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// An in-memory registry of named [`CsrGraph`] projections plus their mutated node properties.
#[derive(Debug, Default)]
pub struct GraphCatalog {
    graphs: HashMap<String, Arc<CsrGraph>>,
    /// Mutated node properties, keyed by graph name then property name (see the module docs).
    mutated: HashMap<String, HashMap<String, NodePropertyValues>>,
}

impl GraphCatalog {
    /// Creates an empty catalog.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers `graph` under `name`.
    ///
    /// # Errors
    /// Returns [`GdsError::GraphAlreadyExists`] if `name` is already taken. Use
    /// [`GraphCatalog::drop`] first to replace it.
    pub fn project(&mut self, name: impl Into<String>, graph: CsrGraph) -> Result<Arc<CsrGraph>> {
        let name = name.into();
        if self.graphs.contains_key(&name) {
            return Err(GdsError::GraphAlreadyExists(name));
        }
        let arc = Arc::new(graph);
        self.graphs.insert(name, Arc::clone(&arc));
        Ok(arc)
    }

    /// Returns a shared handle to the named graph.
    ///
    /// # Errors
    /// Returns [`GdsError::GraphNotFound`] if `name` is not registered.
    pub fn get(&self, name: &str) -> Result<Arc<CsrGraph>> {
        self.graphs
            .get(name)
            .map(Arc::clone)
            .ok_or_else(|| GdsError::GraphNotFound(name.to_owned()))
    }

    /// Whether a named graph is registered.
    #[must_use]
    pub fn contains(&self, name: &str) -> bool {
        self.graphs.contains_key(name)
    }

    /// Removes a named graph, returning its handle. Existing readers keep their `Arc`. Any mutated
    /// node properties held for the graph are discarded with it.
    ///
    /// # Errors
    /// Returns [`GdsError::GraphNotFound`] if `name` is not registered.
    pub fn drop(&mut self, name: &str) -> Result<Arc<CsrGraph>> {
        let g = self
            .graphs
            .remove(name)
            .ok_or_else(|| GdsError::GraphNotFound(name.to_owned()))?;
        // Discard the graph's mutated properties too (a re-project starts from a clean slate).
        self.mutated.remove(name);
        Ok(g)
    }

    /// Records the node-property `values` a `mutate` run produced for `graph` under `property`.
    ///
    /// Returns the number of node values written (the projection's node count). The values are
    /// indexed by internal id (see [`NodePropertyValues`]).
    ///
    /// # Errors
    /// - [`GdsError::GraphNotFound`] if `graph` is not registered.
    /// - [`GdsError::InvalidArgument`] if `property` already exists on `graph` (mirroring Neo4j GDS,
    ///   which refuses to overwrite an existing mutated property) or if the value count does not
    ///   match the graph's node count.
    pub fn mutate_node_property(
        &mut self,
        graph: &str,
        property: &str,
        values: NodePropertyValues,
    ) -> Result<usize> {
        let node_count = self
            .graphs
            .get(graph)
            .ok_or_else(|| GdsError::GraphNotFound(graph.to_owned()))?
            .node_count();
        if values.len() != node_count {
            return Err(GdsError::InvalidArgument(format!(
                "mutate produced {} values for a {node_count}-node graph",
                values.len()
            )));
        }
        let props = self.mutated.entry(graph.to_owned()).or_default();
        if props.contains_key(property) {
            return Err(GdsError::InvalidArgument(format!(
                "node property '{property}' already exists in the in-memory graph '{graph}'"
            )));
        }
        let written = values.len();
        props.insert(property.to_owned(), values);
        Ok(written)
    }

    /// Reads back a mutated node property, or `None` if the graph or property is unknown.
    #[must_use]
    pub fn node_property(&self, graph: &str, property: &str) -> Option<&NodePropertyValues> {
        self.mutated.get(graph)?.get(property)
    }

    /// The registered graph names, in unspecified order.
    #[must_use]
    pub fn list(&self) -> Vec<String> {
        self.graphs.keys().cloned().collect()
    }

    /// The number of registered graphs.
    #[must_use]
    pub fn len(&self) -> usize {
        self.graphs.len()
    }

    /// Whether the catalog is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.graphs.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::csr::{CsrBuilder, Orientation};

    /// A 3-node directed projection `0 -> 1 -> 2` for the mutate-store tests.
    fn three_node_graph() -> CsrGraph {
        let mut b = CsrBuilder::new(Orientation::Directed).weighted(false);
        b.add_node(10);
        b.add_node(20);
        b.add_node(30);
        b.add_edge(10, 20, 1.0).unwrap();
        b.add_edge(20, 30, 1.0).unwrap();
        b.build().unwrap()
    }

    #[test]
    fn mutate_node_property_stores_and_reads_back() {
        let mut cat = GraphCatalog::new();
        cat.project("g", three_node_graph()).unwrap();
        let written = cat
            .mutate_node_property("g", "rank", NodePropertyValues::Double(vec![0.1, 0.2, 0.3]))
            .unwrap();
        assert_eq!(written, 3);
        assert_eq!(
            cat.node_property("g", "rank"),
            Some(&NodePropertyValues::Double(vec![0.1, 0.2, 0.3]))
        );
        // A second, different property coexists.
        cat.mutate_node_property("g", "comp", NodePropertyValues::Long(vec![0, 0, 1]))
            .unwrap();
        assert_eq!(
            cat.node_property("g", "comp"),
            Some(&NodePropertyValues::Long(vec![0, 0, 1]))
        );
        assert!(cat.node_property("g", "absent").is_none());
        assert!(cat.node_property("absent", "rank").is_none());
    }

    #[test]
    fn mutate_rejects_duplicate_property_and_unknown_graph() {
        let mut cat = GraphCatalog::new();
        cat.project("g", three_node_graph()).unwrap();
        cat.mutate_node_property("g", "rank", NodePropertyValues::Double(vec![1.0, 2.0, 3.0]))
            .unwrap();
        // Duplicate property name is rejected (Neo4j GDS semantics).
        assert!(matches!(
            cat.mutate_node_property("g", "rank", NodePropertyValues::Double(vec![9.0, 9.0, 9.0])),
            Err(GdsError::InvalidArgument(_))
        ));
        // Unknown graph is rejected.
        assert!(matches!(
            cat.mutate_node_property("nope", "rank", NodePropertyValues::Double(vec![1.0])),
            Err(GdsError::GraphNotFound(_))
        ));
    }

    #[test]
    fn mutate_rejects_wrong_length() {
        let mut cat = GraphCatalog::new();
        cat.project("g", three_node_graph()).unwrap();
        assert!(matches!(
            cat.mutate_node_property("g", "rank", NodePropertyValues::Double(vec![1.0, 2.0])),
            Err(GdsError::InvalidArgument(_))
        ));
    }

    #[test]
    fn drop_clears_mutated_properties() {
        let mut cat = GraphCatalog::new();
        cat.project("g", three_node_graph()).unwrap();
        cat.mutate_node_property("g", "rank", NodePropertyValues::Double(vec![1.0, 2.0, 3.0]))
            .unwrap();
        cat.drop("g").unwrap();
        assert!(cat.node_property("g", "rank").is_none());
        // Re-projecting under the same name starts with a clean property slate.
        cat.project("g", three_node_graph()).unwrap();
        assert!(cat.node_property("g", "rank").is_none());
    }
}
