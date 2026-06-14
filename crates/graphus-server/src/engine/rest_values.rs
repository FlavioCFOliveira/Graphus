//! Mapping from the engine's [`MaterializedValue`] result cells onto the REST structural value
//! ([`RestValue`]) the router encodes as self-describing JSON (`04-technical-design.md` §8.3; rmp
//! #76/#96/#77).
//!
//! The single authoritative mapping shared by the production REST seam ([`super::seam_rest`]) and the
//! deterministic VOPR REST client (`graphus-dst`'s wire simulator, rmp #164), so the simulator
//! serializes results identically to the real server.

use graphus_cypher::{MaterializedNode, MaterializedPath, MaterializedRel, MaterializedValue};
use graphus_rest::restvalue::{RestNode, RestPath, RestRelationship, RestValue};

/// Maps a materialized result cell onto the REST structural value the router encodes as a
/// self-describing JSON object. A property value passes through; a structural list recurses.
#[must_use]
pub fn materialized_to_rest(value: &MaterializedValue) -> RestValue {
    match value {
        MaterializedValue::Value(v) => RestValue::Value(v.clone()),
        MaterializedValue::Node(n) => RestValue::Node(node_to_rest(n)),
        MaterializedValue::Relationship(r) => RestValue::Relationship(materialized_rel_to_rest(r)),
        MaterializedValue::Path(p) => RestValue::Path(materialized_path_to_rest(p)),
        MaterializedValue::List(items) => {
            RestValue::List(items.iter().map(materialized_to_rest).collect())
        }
    }
}

/// Maps a materialized relationship onto a REST relationship.
#[must_use]
pub fn materialized_rel_to_rest(r: &MaterializedRel) -> RestRelationship {
    RestRelationship {
        id: i64::try_from(r.id).unwrap_or(i64::MAX),
        start: i64::try_from(r.start).unwrap_or(i64::MAX),
        end: i64::try_from(r.end).unwrap_or(i64::MAX),
        rel_type: r.rel_type.clone(),
        properties: r.properties.clone(),
    }
}

/// Maps a materialized path onto a REST path: nodes and relationships in traversal order (the REST
/// shape is the ordered walk, not the Bolt distinct-lists-plus-indices form).
#[must_use]
pub fn materialized_path_to_rest(p: &MaterializedPath) -> RestPath {
    let mut nodes = Vec::with_capacity(p.steps.len() + 1);
    nodes.push(node_to_rest(&p.start));
    let mut relationships = Vec::with_capacity(p.steps.len());
    for step in &p.steps {
        relationships.push(materialized_rel_to_rest(&step.rel));
        nodes.push(node_to_rest(&step.node));
    }
    RestPath {
        nodes,
        relationships,
    }
}

/// Maps a materialized node onto a REST node.
#[must_use]
pub fn node_to_rest(n: &MaterializedNode) -> RestNode {
    RestNode {
        id: i64::try_from(n.id).unwrap_or(i64::MAX),
        labels: n.labels.clone(),
        properties: n.properties.clone(),
    }
}
