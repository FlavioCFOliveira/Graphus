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

/// A **path** value carried in a result row (`04 §7.2` structural `Path`): the start node followed
/// by the traversed hops, in traversal order.
///
/// Like [`NodeRef`]/[`RelRef`], a path holds opaque ids only — labels/properties resolve lazily
/// through the seam. Two paths are equal iff they traverse the same nodes and relationships in the
/// same order and orientation (openCypher path equality).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[must_use]
pub struct PathValue {
    /// The first node of the path.
    pub start: NodeId,
    /// The subsequent hops, in traversal order. Empty for a zero-length path (a single node).
    pub steps: Vec<PathStep>,
}

/// One hop of a [`PathValue`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[must_use]
pub struct PathStep {
    /// `true` when the relationship was traversed start→end (its stored direction), `false` when
    /// traversed against it. Self-loops are always recorded as forward.
    pub forward: bool,
    /// The traversed relationship.
    pub rel: RelId,
    /// The node this hop arrives at.
    pub node: NodeId,
}

impl PathValue {
    /// The nodes along the path, in order (start first; `steps.len() + 1` entries).
    #[must_use]
    pub fn nodes(&self) -> Vec<NodeId> {
        let mut out = Vec::with_capacity(self.steps.len() + 1);
        out.push(self.start);
        out.extend(self.steps.iter().map(|s| s.node));
        out
    }

    /// The relationships along the path, in traversal order.
    #[must_use]
    pub fn rels(&self) -> Vec<RelId> {
        self.steps.iter().map(|s| s.rel).collect()
    }

    /// The path's length (its number of relationships; openCypher `length()`).
    #[must_use]
    pub fn len(&self) -> usize {
        self.steps.len()
    }

    /// Whether the path is zero-length (a single node, no relationships).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.steps.is_empty()
    }
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
    /// A bound path (`MATCH p = …`, named paths in pattern comprehensions, var-length traversals).
    Path(PathValue),
    /// A **structural** list — one that (transitively) contains a node, relationship or path, which
    /// the property [`Value::List`] cannot carry. Build through [`RowValue::list`], which keeps the
    /// invariant that a pure-property list always collapses to [`RowValue::Value`]`(Value::List)`,
    /// so each list has exactly one canonical representation.
    List(Vec<RowValue>),
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

    /// The path if this is a [`RowValue::Path`].
    #[must_use]
    pub fn as_path(&self) -> Option<&PathValue> {
        match self {
            RowValue::Path(p) => Some(p),
            _ => None,
        }
    }

    /// Builds the canonical list value over `items`: a pure-property list collapses to
    /// [`RowValue::Value`]`(Value::List)`, while a list with any structural element (node /
    /// relationship / path / nested structural list) stays a [`RowValue::List`].
    ///
    /// This is the **only** sanctioned way to build a list `RowValue`, so every list has exactly
    /// one representation and equivalence/ordering never have to unify a pure list across the two
    /// variants.
    pub fn list(items: Vec<RowValue>) -> RowValue {
        if items.iter().all(|it| matches!(it, RowValue::Value(_))) {
            RowValue::Value(Value::List(
                items
                    .into_iter()
                    .map(|it| match it {
                        RowValue::Value(v) => v,
                        // Unreachable by the `all` check above; kept total for safety.
                        _ => Value::Null,
                    })
                    .collect(),
            ))
        } else {
            RowValue::List(items)
        }
    }

    /// Borrows this value as a sequence of list elements, when it is a list of either
    /// representation: a structural [`RowValue::List`] borrows directly; a property
    /// [`Value::List`] lifts each element into a [`RowValue::Value`] (cloning the elements).
    #[must_use]
    pub fn as_list_elems(&self) -> Option<Vec<RowValue>> {
        match self {
            RowValue::List(items) => Some(items.clone()),
            RowValue::Value(Value::List(items)) => {
                Some(items.iter().cloned().map(RowValue::Value).collect())
            }
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
        RowValue::Path(_) => 2,
        // A structural list shares the property-value rank so it interleaves with `Value::List`
        // (the two list representations must order as one class; see `cmp_row_values`).
        RowValue::List(_) | RowValue::Value(_) => 3,
    }
}

/// Total ordering over [`RowValue`]s for `ORDER BY` (`04 §7.6`).
///
/// Property values use the Cypher orderability [`cmp_values`]; entity references order by id with a
/// stable cross-case rank, so the relation is total even when a column mixes entities and scalars.
/// Lists of either representation compare elementwise (shorter is less on a common prefix); paths
/// compare by (start, steps). A structural list against a non-list property value compares through
/// its property collapse (structural elements become null), keeping the relation total.
#[must_use]
pub fn cmp_row_values(a: &RowValue, b: &RowValue) -> Ordering {
    match (a, b) {
        // List-kind values (either representation) compare elementwise as one class.
        _ if is_list_kind(a) && is_list_kind(b) => cmp_row_lists(a, b),
        (RowValue::Value(x), RowValue::Value(y)) => cmp_values(x, y),
        (RowValue::Node(x), RowValue::Node(y)) => x.id.cmp(&y.id),
        (RowValue::Rel(x), RowValue::Rel(y)) => x.id.cmp(&y.id),
        (RowValue::Path(x), RowValue::Path(y)) => x.cmp(y),
        // A structural list against a non-list property value: compare through the property
        // collapse (structural elements become null) so the class order matches `Value::List`'s.
        (RowValue::List(_), RowValue::Value(y)) => cmp_values(&collapse_for_ordering(a), y),
        (RowValue::Value(x), RowValue::List(_)) => cmp_values(x, &collapse_for_ordering(b)),
        _ => row_value_rank(a).cmp(&row_value_rank(b)),
    }
}

/// Whether `v` is a list of either representation.
fn is_list_kind(v: &RowValue) -> bool {
    matches!(v, RowValue::List(_) | RowValue::Value(Value::List(_)))
}

/// Elementwise list comparison across the two list representations (both args are list-kind).
fn cmp_row_lists(a: &RowValue, b: &RowValue) -> Ordering {
    let xs = a.as_list_elems().unwrap_or_default();
    let ys = b.as_list_elems().unwrap_or_default();
    for (x, y) in xs.iter().zip(ys.iter()) {
        let ord = cmp_row_values(x, y);
        if ord != Ordering::Equal {
            return ord;
        }
    }
    xs.len().cmp(&ys.len())
}

/// The property collapse of a structural value for ordering against non-list property values:
/// entities/paths become null, lists collapse elementwise (mirrors `eval`'s value-context rule).
fn collapse_for_ordering(v: &RowValue) -> Value {
    match v {
        RowValue::Value(x) => x.clone(),
        RowValue::List(items) => Value::List(items.iter().map(collapse_for_ordering).collect()),
        RowValue::Node(_) | RowValue::Rel(_) | RowValue::Path(_) => Value::Null,
    }
}

/// Grouping/`DISTINCT` equivalence over [`RowValue`]s (`04 §7.6`).
///
/// Property values use Cypher [`equivalent`]; two entity references are equivalent iff they denote
/// the same id; paths are equivalent iff they traverse the same ids in the same order and
/// orientation; lists are equivalent elementwise. Mixed cases are never equivalent (a structural
/// [`RowValue::List`] always holds a structural element — the [`RowValue::list`] invariant — so it
/// can never be equivalent to a pure property list).
#[must_use]
pub fn row_values_equivalent(a: &RowValue, b: &RowValue) -> bool {
    match (a, b) {
        (RowValue::Value(x), RowValue::Value(y)) => equivalent(x, y),
        (RowValue::Node(x), RowValue::Node(y)) => x.id == y.id,
        (RowValue::Rel(x), RowValue::Rel(y)) => x.id == y.id,
        (RowValue::Path(x), RowValue::Path(y)) => x == y,
        (RowValue::List(x), RowValue::List(y)) => {
            x.len() == y.len()
                && x.iter()
                    .zip(y)
                    .all(|(ex, ey)| row_values_equivalent(ex, ey))
        }
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
