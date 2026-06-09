//! The executor's **runtime value and row model** (`04-technical-design.md` §7.2, §7.4).
//!
//! The compile pipeline operates on [`graphus_core::Value`], the *property* value space. The
//! executor additionally needs the **structural** value classes — `Node`, `Relationship`, `Path` —
//! that `04 §7.2` lists as *"only in results, never persisted as property values"*. Those variants
//! are **not yet** on [`graphus_core::Value`] (`graphus-core`'s docs explicitly defer them to "the
//! executor sub-task"), and this crate's boundary forbids editing `graphus-core`. So the executor
//! works over a thin superset, [`RowValue`], that is **either** a property [`Value`] **or** an
//! entity reference ([`NodeRef`] / [`RelRef`]). This keeps the structural classes local to the query
//! runtime exactly as the value-model split intends, without touching the shared core type. When the
//! core gains the structural variants, [`RowValue`] collapses back into `Value` mechanically.
//!
//! # Why a reference, not an embedded snapshot
//!
//! A [`NodeRef`]/[`RelRef`] is an **opaque id plus the seam handle's identity**: properties and
//! labels are read **lazily** through [`GraphAccess`](crate::graph_access::GraphAccess) when a
//! projection asks for them (`04 §7.2` calls node/rel values "lazy"). The runtime never eagerly
//! snapshots an entity's whole property set into a row — it carries the id and resolves on demand —
//! so a row stays cheap and a later `SET` is observed by a later read of the same entity within the
//! transaction.

use std::cmp::Ordering;
use std::collections::BTreeMap;

use graphus_core::Value;

use crate::graph_access::{NodeId, RelId};
use crate::{cmp_values, equivalent};

/// A reference to a graph **node** carried in a result row (`04 §7.2` structural `Node`).
///
/// Holds the opaque [`NodeId`]; labels and properties are resolved lazily through the graph seam
/// when projected, so the reference itself is `Copy` and cheap.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[must_use]
pub struct NodeRef {
    /// The opaque node id.
    pub id: NodeId,
}

/// A reference to a graph **relationship** carried in a result row (`04 §7.2` structural
/// `Relationship`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[must_use]
pub struct RelRef {
    /// The opaque relationship id.
    pub id: RelId,
}

/// A value flowing through the executor: a property [`Value`] or a structural entity reference
/// (`04 §7.2`).
///
/// This is the cell type of a [`Row`]. Scalars, lists and maps are [`RowValue::Value`]; a bound
/// node or relationship is [`RowValue::Node`] / [`RowValue::Rel`]. Expression evaluation
/// ([`mod@crate::eval`]) collapses a `RowValue` to a property [`Value`] (resolving entity properties
/// through the seam) wherever the Cypher value-model operations (`=`, ordering, …) require it.
#[derive(Debug, Clone, PartialEq)]
#[must_use]
pub enum RowValue {
    /// A property value (scalar, list, map, temporal, null).
    Value(Value),
    /// A bound node.
    Node(NodeRef),
    /// A bound relationship.
    Rel(RelRef),
}

impl RowValue {
    /// The canonical `null` row value.
    pub const NULL: RowValue = RowValue::Value(Value::Null);

    /// Whether this is the null value.
    #[must_use]
    pub fn is_null(&self) -> bool {
        matches!(self, RowValue::Value(Value::Null))
    }

    /// Borrows the inner property [`Value`] if this is a [`RowValue::Value`].
    #[must_use]
    pub fn as_value(&self) -> Option<&Value> {
        match self {
            RowValue::Value(v) => Some(v),
            _ => None,
        }
    }

    /// The node id if this is a [`RowValue::Node`].
    #[must_use]
    pub fn as_node(&self) -> Option<NodeId> {
        match self {
            RowValue::Node(n) => Some(n.id),
            _ => None,
        }
    }

    /// The relationship id if this is a [`RowValue::Rel`].
    #[must_use]
    pub fn as_rel(&self) -> Option<RelId> {
        match self {
            RowValue::Rel(r) => Some(r.id),
            _ => None,
        }
    }
}

impl From<Value> for RowValue {
    fn from(v: Value) -> Self {
        RowValue::Value(v)
    }
}

/// The integer rank used to order **across** the `RowValue` cases for `ORDER BY` and tie-breaking.
///
/// Entities slot above property scalars but below `null`, consistent with the openCypher class order
/// (`Node`/`Relationship` rank above the property classes, `04 §7.6` / [`crate::ordering`]). Within
/// each entity case the id orders deterministically so the result is total.
fn row_value_rank(v: &RowValue) -> u8 {
    match v {
        RowValue::Node(_) => 0,
        RowValue::Rel(_) => 1,
        RowValue::Value(_) => 2,
    }
}

/// Total ordering over [`RowValue`]s for `ORDER BY` (`04 §7.6`).
///
/// Property values use the Cypher orderability [`cmp_values`]; entity references order by id with a
/// stable cross-case rank, so the relation is total even when a column mixes entities and scalars.
#[must_use]
pub fn cmp_row_values(a: &RowValue, b: &RowValue) -> Ordering {
    match (a, b) {
        (RowValue::Value(x), RowValue::Value(y)) => cmp_values(x, y),
        (RowValue::Node(x), RowValue::Node(y)) => x.id.cmp(&y.id),
        (RowValue::Rel(x), RowValue::Rel(y)) => x.id.cmp(&y.id),
        _ => row_value_rank(a).cmp(&row_value_rank(b)),
    }
}

/// Grouping/`DISTINCT` equivalence over [`RowValue`]s (`04 §7.6`).
///
/// Property values use Cypher [`equivalent`]; two entity references are equivalent iff they denote
/// the same id. Mixed cases are never equivalent.
#[must_use]
pub fn row_values_equivalent(a: &RowValue, b: &RowValue) -> bool {
    match (a, b) {
        (RowValue::Value(x), RowValue::Value(y)) => equivalent(x, y),
        (RowValue::Node(x), RowValue::Node(y)) => x.id == y.id,
        (RowValue::Rel(x), RowValue::Rel(y)) => x.id == y.id,
        _ => false,
    }
}

/// A single executor result row: a positional tuple of [`RowValue`]s plus the variable names bound
/// in each column (`04 §7.4`).
///
/// A row is a **name → value binding** realised as parallel `columns`/`values` vectors (positional
/// access is the executor's hot path; the names let operators resolve variables by name and let the
/// final projection label result columns). Column order is the introduction order of the binding.
#[derive(Debug, Clone, Default, PartialEq)]
#[must_use]
pub struct Row {
    columns: Vec<String>,
    values: Vec<RowValue>,
}

impl Row {
    /// An empty row (no bindings) — the single row produced by an
    /// [`Empty`](crate::physical::PhysicalOp::Empty) leaf.
    pub fn empty() -> Self {
        Self::default()
    }

    /// Builds a row from parallel `(name, value)` pairs, preserving order.
    pub fn from_pairs(pairs: impl IntoIterator<Item = (String, RowValue)>) -> Self {
        let mut row = Self::default();
        for (name, value) in pairs {
            row.set(name, value);
        }
        row
    }

    /// The bound column names, in order.
    #[must_use]
    pub fn columns(&self) -> &[String] {
        &self.columns
    }

    /// The values, in column order.
    pub fn values(&self) -> &[RowValue] {
        &self.values
    }

    /// The number of bound columns.
    #[must_use]
    pub fn len(&self) -> usize {
        self.columns.len()
    }

    /// Whether the row binds no columns.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.columns.is_empty()
    }

    /// The value bound to `name`, if any.
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&RowValue> {
        self.columns
            .iter()
            .position(|c| c == name)
            .map(|i| &self.values[i])
    }

    /// Whether `name` is bound in this row.
    #[must_use]
    pub fn contains(&self, name: &str) -> bool {
        self.columns.iter().any(|c| c == name)
    }

    /// Binds `name` to `value`, **overwriting** an existing binding for the same name in place (so a
    /// re-bind keeps its original column position). A new name is appended.
    pub fn set(&mut self, name: impl Into<String>, value: RowValue) {
        let name = name.into();
        if let Some(i) = self.columns.iter().position(|c| *c == name) {
            self.values[i] = value;
        } else {
            self.columns.push(name);
            self.values.push(value);
        }
    }

    /// Returns a clone of `self` extended with `(name, value)` (functional update, used to fan a
    /// driving row out across produced bindings).
    pub fn with(&self, name: impl Into<String>, value: RowValue) -> Self {
        let mut next = self.clone();
        next.set(name, value);
        next
    }

    /// The value bound to `name` as a property [`Value`], or `Value::Null` for an absent binding.
    ///
    /// Entity references are **not** coerced here (they are not property values); a caller that needs
    /// to compare/order an entity uses [`RowValue`] directly. This accessor is for plain
    /// property-typed columns.
    #[must_use]
    pub fn value(&self, name: &str) -> Value {
        match self.get(name) {
            Some(RowValue::Value(v)) => v.clone(),
            _ => Value::Null,
        }
    }
}

/// Renders a [`Row`] as an order-independent `BTreeMap` of name → [`RowValue`] for assertions.
///
/// A convenience for tests that want to compare rows by binding regardless of column order.
#[must_use]
pub fn row_bindings(row: &Row) -> BTreeMap<String, RowValue> {
    row.columns()
        .iter()
        .cloned()
        .zip(row.values().iter().cloned())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::graph_access::NodeId;

    #[test]
    fn row_set_get_and_rebind_in_place() {
        let mut r = Row::empty();
        r.set("a", RowValue::Value(Value::Integer(1)));
        r.set("b", RowValue::Value(Value::Integer(2)));
        assert_eq!(r.columns(), &["a".to_owned(), "b".to_owned()]);
        // Re-binding `a` keeps its position.
        r.set("a", RowValue::Value(Value::Integer(10)));
        assert_eq!(r.columns(), &["a".to_owned(), "b".to_owned()]);
        assert_eq!(r.get("a"), Some(&RowValue::Value(Value::Integer(10))));
    }

    #[test]
    fn ordering_mixes_entities_and_scalars_totally() {
        let n = RowValue::Node(NodeRef { id: NodeId(1) });
        let r = RowValue::Rel(RelRef {
            id: crate::graph_access::RelId(1),
        });
        let v = RowValue::Value(Value::Integer(5));
        // Node < Rel < Value by cross-case rank.
        assert_eq!(cmp_row_values(&n, &r), Ordering::Less);
        assert_eq!(cmp_row_values(&r, &v), Ordering::Less);
        assert_eq!(cmp_row_values(&v, &v), Ordering::Equal);
    }

    #[test]
    fn equivalence_by_identity_for_entities() {
        let a = RowValue::Node(NodeRef { id: NodeId(7) });
        let b = RowValue::Node(NodeRef { id: NodeId(7) });
        let c = RowValue::Node(NodeRef { id: NodeId(8) });
        assert!(row_values_equivalent(&a, &b));
        assert!(!row_values_equivalent(&a, &c));
    }
}
