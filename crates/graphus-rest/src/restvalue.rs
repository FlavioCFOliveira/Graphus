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
}
