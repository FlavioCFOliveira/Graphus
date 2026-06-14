//! Mapping from the engine's [`MaterializedValue`] result cells onto the Bolt structural value
//! ([`BoltValue`]) the PackStream encoder packs (`04-technical-design.md` §8.3; rmp #76/#96).
//!
//! This is the single, authoritative result-cell mapping shared by the production Bolt seam
//! ([`super::seam_bolt`]) and the deterministic VOPR Bolt client (`graphus-dst`'s wire simulator,
//! rmp #163), so the simulator packs results **byte-identically** to the real server — the only way a
//! DST run can certify PackStream conformance of the engine's output.

use graphus_bolt::packstream::{BoltNode, BoltPath, BoltRelationship, BoltValue};
use graphus_cypher::{MaterializedPath, MaterializedRel, MaterializedValue};

/// Maps a materialized result cell (entity already resolved through the cursor's graph seam) onto the
/// Bolt structural value the PackStream encoder packs. A property value passes through; a structural
/// list recurses.
#[must_use]
pub fn materialized_to_bolt(value: &MaterializedValue) -> BoltValue {
    match value {
        MaterializedValue::Value(v) => BoltValue::Value(v.clone()),
        MaterializedValue::Node(n) => BoltValue::Node(BoltNode {
            // The opaque id is a `u64`; Bolt ids are `i64`. The id is a small internal handle, so the
            // saturating cast never actually clamps in practice — defensive only.
            id: i64::try_from(n.id).unwrap_or(i64::MAX),
            labels: n.labels.clone(),
            properties: n.properties.clone(),
        }),
        MaterializedValue::Relationship(r) => BoltValue::Relationship(materialized_rel_to_bolt(r)),
        MaterializedValue::Path(p) => BoltValue::Path(materialized_path_to_bolt(p)),
        MaterializedValue::List(items) => {
            BoltValue::List(items.iter().map(materialized_to_bolt).collect())
        }
    }
}

/// Maps a materialized relationship onto a Bolt relationship.
#[must_use]
pub fn materialized_rel_to_bolt(r: &MaterializedRel) -> BoltRelationship {
    BoltRelationship {
        id: i64::try_from(r.id).unwrap_or(i64::MAX),
        start: i64::try_from(r.start).unwrap_or(i64::MAX),
        end: i64::try_from(r.end).unwrap_or(i64::MAX),
        rel_type: r.rel_type.clone(),
        properties: r.properties.clone(),
    }
}

/// Maps a materialized path onto a Bolt `Path`, decomposing it into the distinct nodes, distinct
/// unbound relationships, and the signed/1-based index sequence the Bolt `Path` structure packs
/// (delegated to [`MaterializedPath::bolt_path_components`]).
#[must_use]
pub fn materialized_path_to_bolt(p: &MaterializedPath) -> BoltPath {
    let (nodes, rels, indices) = p.bolt_path_components();
    BoltPath {
        nodes: nodes
            .into_iter()
            .map(|n| BoltNode {
                id: i64::try_from(n.id).unwrap_or(i64::MAX),
                labels: n.labels.clone(),
                properties: n.properties.clone(),
            })
            .collect(),
        rels: rels.into_iter().map(materialized_rel_to_bolt).collect(),
        indices,
    }
}
