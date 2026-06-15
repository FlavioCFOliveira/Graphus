//! **Structural result values** for REST (`04-technical-design.md` §8.2 typed JSON; rmp #76/#96/#77).
//!
//! A query result cell may be a graph entity (`Node` / `Relationship` / `Path`), which
//! [`graphus_core::Value`] cannot represent — `04 §7.2` defers the structural classes to their owning
//! subsystems. The executor (`graphus-cypher`) resolves an entity's labels / type / endpoints /
//! properties at the result boundary, and the server seam maps that onto a [`RestValue`]: either a
//! property [`Value`] (encoded by [`crate::value`]'s Jolt/CBOR codec, unchanged) or a structural
//! entity encoded here as a self-describing JSON object.
//!
//! # The structural JSON shape (documented; also serves rmp #77)
//!
//! Graph entities are emitted as plain, self-describing JSON objects rather than scalars, so a REST
//! client receives the full entity (not a flattened id):
//!
//! | entity | JSON shape |
//! | --- | --- |
//! | node | `{ "id": <int>, "labels": [ <str>… ], "properties": { <k>: <jolt-value>… } }` |
//! | relationship | `{ "id", "type": <str>, "start": <int>, "end": <int>, "properties": { … } }` |
//! | path | `{ "nodes": [ <node>… ], "relationships": [ <relationship>… ] }` (in traversal order) |
//!
//! Inside `properties` (and any structural list element), property values are encoded with the
//! existing strict-Jolt codec ([`crate::value::value_to_jolt`]) — so the int53 fix, temporal `T`
//! sigil, etc. all still apply. The `id`/`start`/`end` integers are emitted as **plain JSON
//! numbers**: an entity id is an internal handle (well within 2^53 in practice) and is not subject to
//! the property int53 contract, keeping the entity envelope readable. Scalar cells are unchanged from
//! before this change.
//!
//! The whole REST response is serialised once by the router (to JSON or CBOR via serde over the
//! `Json` tree), so a structural cell needs **no** separate CBOR path: the `Json` object this module
//! produces serialises uniformly into either wire format.
//!
//! # Graph projection (rmp #77)
//!
//! For the graph-visualisation endpoint, the same resolved structural values are folded into a
//! **deduplicated graph**: distinct nodes (by id) and distinct relationships (by id), regardless of
//! how many rows, lists, or paths mentioned them. [`GraphProjection`] is the accumulator; it walks
//! every cell of every row recursively (into [`RestValue::List`] and [`RestValue::Path`]) and emits
//! the rendering-friendly `{ nodes, relationships }` object documented on [`GraphProjection::to_json`].

use std::collections::HashSet;

use graphus_core::Value;
use serde_json::{Map as JsonMap, Value as Json};

use crate::value::value_to_jolt;

/// A resolved node in a [`RestValue`]: id, labels, and properties.
#[derive(Debug, Clone, PartialEq)]
pub struct RestNode {
    /// The node id.
    pub id: i64,
    /// The node's labels.
    pub labels: Vec<String>,
    /// The node's properties (ordered `(key, value)`).
    pub properties: Vec<(String, Value)>,
}

/// A resolved relationship in a [`RestValue`]: id, endpoints, type, and properties.
#[derive(Debug, Clone, PartialEq)]
pub struct RestRelationship {
    /// The relationship id.
    pub id: i64,
    /// The start (source) node id.
    pub start: i64,
    /// The end (target) node id.
    pub end: i64,
    /// The relationship type name.
    pub rel_type: String,
    /// The relationship's properties (ordered `(key, value)`).
    pub properties: Vec<(String, Value)>,
}

/// A resolved path in a [`RestValue`]: its nodes and relationships in traversal order.
#[derive(Debug, Clone, PartialEq)]
pub struct RestPath {
    /// The nodes along the path, start first (`relationships.len() + 1` entries).
    pub nodes: Vec<RestNode>,
    /// The relationships along the path, in traversal order.
    pub relationships: Vec<RestRelationship>,
}

/// A **result-row cell** for a REST response: a property value or a graph entity (`04 §8.3`).
///
/// Scalars/temporals/lists/maps stay [`RestValue::Value`] and encode exactly as before; the
/// structural variants encode the self-describing JSON objects documented at the module level.
#[derive(Debug, Clone, PartialEq)]
pub enum RestValue {
    /// A property value (scalar/string/bytes/list/map/temporal/null).
    Value(Value),
    /// A node.
    Node(RestNode),
    /// A relationship.
    Relationship(RestRelationship),
    /// A path.
    Path(RestPath),
    /// A structural list whose elements are each a [`RestValue`].
    List(Vec<RestValue>),
}

impl From<Value> for RestValue {
    fn from(v: Value) -> Self {
        RestValue::Value(v)
    }
}

/// Encodes a [`RestValue`] result cell into JSON: a property [`Value`] via the strict-Jolt codec, or
/// the structural entity object (`04 §8.2`; see the module docs for the shape).
#[must_use]
pub fn restvalue_to_jolt(value: &RestValue) -> Json {
    match value {
        RestValue::Value(v) => value_to_jolt(v),
        RestValue::Node(n) => node_to_json(n),
        RestValue::Relationship(r) => relationship_to_json(r),
        RestValue::Path(p) => path_to_json(p),
        RestValue::List(items) => Json::Array(items.iter().map(restvalue_to_jolt).collect()),
    }
}

/// Encodes an ordered `(key, value)` property list as a JSON object of strict-Jolt values.
fn properties_to_json(properties: &[(String, Value)]) -> Json {
    let mut obj = JsonMap::with_capacity(properties.len());
    for (k, v) in properties {
        obj.insert(k.clone(), value_to_jolt(v));
    }
    Json::Object(obj)
}

fn node_to_json(node: &RestNode) -> Json {
    let mut obj = JsonMap::with_capacity(3);
    obj.insert("id".to_owned(), Json::from(node.id));
    obj.insert(
        "labels".to_owned(),
        Json::Array(
            node.labels
                .iter()
                .map(|l| Json::String(l.clone()))
                .collect(),
        ),
    );
    obj.insert(
        "properties".to_owned(),
        properties_to_json(&node.properties),
    );
    Json::Object(obj)
}

fn relationship_to_json(rel: &RestRelationship) -> Json {
    let mut obj = JsonMap::with_capacity(5);
    obj.insert("id".to_owned(), Json::from(rel.id));
    obj.insert("type".to_owned(), Json::String(rel.rel_type.clone()));
    obj.insert("start".to_owned(), Json::from(rel.start));
    obj.insert("end".to_owned(), Json::from(rel.end));
    obj.insert("properties".to_owned(), properties_to_json(&rel.properties));
    Json::Object(obj)
}

fn path_to_json(path: &RestPath) -> Json {
    let mut obj = JsonMap::with_capacity(2);
    obj.insert(
        "nodes".to_owned(),
        Json::Array(path.nodes.iter().map(node_to_json).collect()),
    );
    obj.insert(
        "relationships".to_owned(),
        Json::Array(
            path.relationships
                .iter()
                .map(relationship_to_json)
                .collect(),
        ),
    );
    Json::Object(obj)
}

// =============================== graph projection (rmp #77) ====================================

/// A **deduplicated graph projection** of a query result, for graph-rendering front-ends (rmp #77).
///
/// It accumulates the distinct graph entities mentioned anywhere in a result: feed it every cell of
/// every row with [`add_value`](Self::add_value) (which recurses into [`RestValue::List`] and
/// [`RestValue::Path`]), then render the rendering-friendly JSON object with
/// [`to_json`](Self::to_json).
///
/// ## Deduplication
///
/// A node is keyed by its [`RestNode::id`] and a relationship by its [`RestRelationship::id`]: the
/// **first** occurrence is kept and every later occurrence of the same id is ignored. So a node
/// shared by many rows, list elements, or path positions appears exactly once, and the entity's
/// labels/type/properties are those of its first sighting (a given id resolves to one entity, so all
/// sightings agree). Insertion order is preserved (a node/relationship appears in the output in the
/// order it was first seen), which keeps the projection stable and diff-friendly for a front-end.
///
/// ## What is *not* collected
///
/// Scalar/temporal/map cells ([`RestValue::Value`]) carry no graph entity and contribute nothing —
/// a scalar-only result projects to empty `nodes` and `relationships`. A path contributes **all**
/// its nodes and relationships (in traversal order), each subject to the same dedup.
#[derive(Debug, Default)]
pub struct GraphProjection {
    /// Distinct nodes in first-seen order.
    nodes: Vec<RestNode>,
    /// The ids of nodes already collected (dedup guard for `nodes`).
    seen_nodes: HashSet<i64>,
    /// Distinct relationships in first-seen order.
    relationships: Vec<RestRelationship>,
    /// The ids of relationships already collected (dedup guard for `relationships`).
    seen_relationships: HashSet<i64>,
}

impl GraphProjection {
    /// An empty projection.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Folds one result cell into the projection, recursing into lists and paths.
    ///
    /// - [`RestValue::Node`] / [`RestValue::Relationship`] add that entity (deduplicated by id).
    /// - [`RestValue::Path`] adds every node and relationship along the path.
    /// - [`RestValue::List`] recurses into each element (so nested structural lists are walked).
    /// - [`RestValue::Value`] (a scalar/temporal/map property value) contributes nothing.
    pub fn add_value(&mut self, value: RestValue) {
        // PERF (C14): consumes the value so structural entities move into the projection rather than
        // being cloned (the caller drops the row immediately after). Behaviour is unchanged.
        match value {
            RestValue::Node(node) => self.add_node(node),
            RestValue::Relationship(rel) => self.add_relationship(rel),
            RestValue::Path(path) => {
                for node in path.nodes {
                    self.add_node(node);
                }
                for rel in path.relationships {
                    self.add_relationship(rel);
                }
            }
            RestValue::List(items) => {
                for item in items {
                    self.add_value(item);
                }
            }
            // A property value carries no graph entity.
            RestValue::Value(_) => {}
        }
    }

    /// Folds one whole result row (each cell) into the projection, consuming the row.
    pub fn add_row(&mut self, row: Vec<RestValue>) {
        for cell in row {
            self.add_value(cell);
        }
    }

    /// Adds a node unless its id was already collected (keeping the first sighting).
    fn add_node(&mut self, node: RestNode) {
        // PERF (C14): move the owned node in instead of cloning a borrowed one.
        if self.seen_nodes.insert(node.id) {
            self.nodes.push(node);
        }
    }

    /// Adds a relationship unless its id was already collected (keeping the first sighting).
    fn add_relationship(&mut self, rel: RestRelationship) {
        // PERF (C14): move the owned relationship in instead of cloning a borrowed one.
        if self.seen_relationships.insert(rel.id) {
            self.relationships.push(rel);
        }
    }

    /// The number of distinct nodes collected so far.
    #[must_use]
    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }

    /// The number of distinct relationships collected so far.
    #[must_use]
    pub fn relationship_count(&self) -> usize {
        self.relationships.len()
    }

    /// Renders the deduplicated graph as the documented JSON object (rmp #77):
    ///
    /// ```json
    /// {
    ///   "nodes": [
    ///     { "id": <int>, "labels": [ <str>… ], "properties": { <k>: <jolt-value>… } }
    ///   ],
    ///   "relationships": [
    ///     { "id": <int>, "type": <str>, "startNode": <int>, "endNode": <int>,
    ///       "properties": { <k>: <jolt-value>… } }
    ///   ]
    /// }
    /// ```
    ///
    /// Property values inside `properties` use the same **strict-Jolt** codec
    /// ([`crate::value::value_to_jolt`]) as every other REST value (so the int53 contract, the
    /// temporal `T` sigil, etc. all hold). Entity `id`/`startNode`/`endNode` are plain JSON numbers
    /// (internal handles, not subject to the property int53 contract) — consistent with how a
    /// structural [`RestValue`] renders entity ids ([`restvalue_to_jolt`]). The relationship
    /// endpoints are named `startNode`/`endNode` (the id of the start/end node), the convention
    /// graph-rendering front-ends expect.
    #[must_use]
    pub fn to_json(&self) -> Json {
        let nodes: Vec<Json> = self.nodes.iter().map(node_to_json).collect();
        let relationships: Vec<Json> = self
            .relationships
            .iter()
            .map(relationship_to_viz_json)
            .collect();
        let mut obj = JsonMap::with_capacity(2);
        obj.insert("nodes".to_owned(), Json::Array(nodes));
        obj.insert("relationships".to_owned(), Json::Array(relationships));
        Json::Object(obj)
    }
}

/// Encodes a relationship for the **graph-projection** shape: like [`relationship_to_json`] but with
/// the endpoints named `startNode`/`endNode` (rmp #77), the convention rendering front-ends expect.
fn relationship_to_viz_json(rel: &RestRelationship) -> Json {
    let mut obj = JsonMap::with_capacity(5);
    obj.insert("id".to_owned(), Json::from(rel.id));
    obj.insert("type".to_owned(), Json::String(rel.rel_type.clone()));
    obj.insert("startNode".to_owned(), Json::from(rel.start));
    obj.insert("endNode".to_owned(), Json::from(rel.end));
    obj.insert("properties".to_owned(), properties_to_json(&rel.properties));
    Json::Object(obj)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn scalar_passes_through_to_jolt() {
        // A scalar cell encodes byte-identically to the existing Jolt codec (int53 string form).
        assert_eq!(
            restvalue_to_jolt(&RestValue::Value(Value::Integer(1))),
            json!({ "Z": "1" })
        );
    }

    #[test]
    fn node_has_id_labels_properties_shape() {
        let node = RestNode {
            id: 7,
            labels: vec!["Person".to_owned(), "Admin".to_owned()],
            properties: vec![("name".to_owned(), Value::String("Ada".to_owned()))],
        };
        let j = restvalue_to_jolt(&RestValue::Node(node));
        assert_eq!(j["id"], json!(7));
        assert_eq!(j["labels"], json!(["Person", "Admin"]));
        // Properties carry strict-Jolt values (string sigil `U`).
        assert_eq!(j["properties"]["name"], json!({ "U": "Ada" }));
    }

    #[test]
    fn relationship_has_id_type_endpoints_properties_shape() {
        let rel = RestRelationship {
            id: 3,
            start: 1,
            end: 2,
            rel_type: "KNOWS".to_owned(),
            properties: vec![("since".to_owned(), Value::Integer(2010))],
        };
        let j = restvalue_to_jolt(&RestValue::Relationship(rel));
        assert_eq!(j["id"], json!(3));
        assert_eq!(j["type"], json!("KNOWS"));
        assert_eq!(j["start"], json!(1));
        assert_eq!(j["end"], json!(2));
        assert_eq!(j["properties"]["since"], json!({ "Z": "2010" }));
    }

    #[test]
    fn path_has_ordered_nodes_and_relationships() {
        let path = RestPath {
            nodes: vec![
                RestNode {
                    id: 10,
                    labels: vec!["P".to_owned()],
                    properties: vec![],
                },
                RestNode {
                    id: 11,
                    labels: vec!["P".to_owned()],
                    properties: vec![],
                },
            ],
            relationships: vec![RestRelationship {
                id: 100,
                start: 10,
                end: 11,
                rel_type: "R".to_owned(),
                properties: vec![],
            }],
        };
        let j = restvalue_to_jolt(&RestValue::Path(path));
        assert_eq!(j["nodes"].as_array().unwrap().len(), 2);
        assert_eq!(j["relationships"].as_array().unwrap().len(), 1);
        assert_eq!(j["nodes"][0]["id"], json!(10));
        assert_eq!(j["relationships"][0]["type"], json!("R"));
    }

    #[test]
    fn structural_list_encodes_element_wise() {
        let node = RestNode {
            id: 1,
            labels: vec![],
            properties: vec![],
        };
        let list = RestValue::List(vec![
            RestValue::Value(Value::Integer(42)),
            RestValue::Node(node),
        ]);
        let j = restvalue_to_jolt(&list);
        let arr = j.as_array().unwrap();
        assert_eq!(arr[0], json!({ "Z": "42" }));
        assert_eq!(arr[1]["id"], json!(1));
    }

    // ---- graph projection (rmp #77) -----------------------------------------------------------

    fn node(id: i64, label: &str) -> RestNode {
        RestNode {
            id,
            labels: vec![label.to_owned()],
            properties: vec![("name".to_owned(), Value::String(format!("n{id}")))],
        }
    }

    fn rel(id: i64, start: i64, end: i64) -> RestRelationship {
        RestRelationship {
            id,
            start,
            end,
            rel_type: "KNOWS".to_owned(),
            properties: vec![("since".to_owned(), Value::Integer(2020))],
        }
    }

    #[test]
    fn projection_collects_nodes_and_relationships() {
        // A row `(a)-[r]->(b)` projects to two nodes + one relationship with correct endpoints.
        let mut proj = GraphProjection::new();
        proj.add_row(vec![
            RestValue::Node(node(1, "Person")),
            RestValue::Relationship(rel(100, 1, 2)),
            RestValue::Node(node(2, "Person")),
        ]);
        let j = proj.to_json();
        assert_eq!(j["nodes"].as_array().unwrap().len(), 2);
        assert_eq!(j["relationships"].as_array().unwrap().len(), 1);
        // The relationship endpoints use the `startNode`/`endNode` viz convention.
        let r = &j["relationships"][0];
        assert_eq!(r["id"], json!(100));
        assert_eq!(r["type"], json!("KNOWS"));
        assert_eq!(r["startNode"], json!(1));
        assert_eq!(r["endNode"], json!(2));
        // Properties carry strict-Jolt values.
        assert_eq!(r["properties"]["since"], json!({ "Z": "2020" }));
        assert_eq!(j["nodes"][0]["properties"]["name"], json!({ "U": "n1" }));
    }

    #[test]
    fn projection_dedups_shared_node_across_rows() {
        // The same node id appears in two rows; it must collapse to one entry.
        let mut proj = GraphProjection::new();
        proj.add_row(vec![
            RestValue::Node(node(7, "A")),
            RestValue::Node(node(8, "B")),
        ]);
        proj.add_row(vec![
            RestValue::Node(node(7, "A")),
            RestValue::Node(node(9, "C")),
        ]);
        assert_eq!(proj.node_count(), 3, "node 7 collapses to one entry");
        let ids: Vec<i64> = proj
            .to_json()
            .get("nodes")
            .unwrap()
            .as_array()
            .unwrap()
            .iter()
            .map(|n| n["id"].as_i64().unwrap())
            .collect();
        // First-seen order is preserved.
        assert_eq!(ids, vec![7, 8, 9]);
    }

    #[test]
    fn projection_dedups_shared_relationship() {
        let mut proj = GraphProjection::new();
        proj.add_value(RestValue::Relationship(rel(100, 1, 2)));
        proj.add_value(RestValue::Relationship(rel(100, 1, 2)));
        assert_eq!(proj.relationship_count(), 1);
    }

    #[test]
    fn projection_walks_paths_and_lists() {
        // A path contributes all its nodes + rels; a node also present in a sibling list dedups.
        let path = RestPath {
            nodes: vec![node(1, "P"), node(2, "P"), node(3, "P")],
            relationships: vec![rel(10, 1, 2), rel(11, 2, 3)],
        };
        let mut proj = GraphProjection::new();
        proj.add_row(vec![
            RestValue::Path(path),
            // A list re-mentioning node 2 (dedup) and adding node 4.
            RestValue::List(vec![
                RestValue::Node(node(2, "P")),
                RestValue::Node(node(4, "P")),
            ]),
        ]);
        assert_eq!(proj.node_count(), 4, "nodes 1,2,3,4 (2 deduped)");
        assert_eq!(proj.relationship_count(), 2, "rels 10,11 from the path");
    }

    #[test]
    fn projection_of_scalar_only_result_is_empty() {
        let mut proj = GraphProjection::new();
        proj.add_row(vec![
            RestValue::Value(Value::Integer(1)),
            RestValue::Value(Value::String("hello".to_owned())),
            // A non-structural list of scalars contributes nothing either.
            RestValue::List(vec![RestValue::Value(Value::Integer(2))]),
        ]);
        let j = proj.to_json();
        assert_eq!(j["nodes"].as_array().unwrap().len(), 0);
        assert_eq!(j["relationships"].as_array().unwrap().len(), 0);
    }
}
