//! A simple in-memory named-graph catalog (`project` / `list` / `drop`).
//!
//! Projections are stored behind `Arc` so a long-running algorithm can keep reading a graph after
//! it has been dropped from the catalog (the `Arc` keeps it alive until the last reader finishes).

use crate::csr::CsrGraph;
use crate::error::{GdsError, Result};
use std::collections::HashMap;
use std::sync::Arc;

/// An in-memory registry of named [`CsrGraph`] projections.
#[derive(Debug, Default)]
pub struct GraphCatalog {
    graphs: HashMap<String, Arc<CsrGraph>>,
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

    /// Removes a named graph, returning its handle. Existing readers keep their `Arc`.
    ///
    /// # Errors
    /// Returns [`GdsError::GraphNotFound`] if `name` is not registered.
    pub fn drop(&mut self, name: &str) -> Result<Arc<CsrGraph>> {
        self.graphs
            .remove(name)
            .ok_or_else(|| GdsError::GraphNotFound(name.to_owned()))
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
