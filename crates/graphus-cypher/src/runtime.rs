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
    /// A **structural** map — one whose values (transitively) contain a node, relationship or path,
    /// which the property [`Value::Map`] cannot carry. Build through [`RowValue::map`], which keeps
    /// the invariant that a pure-property map always collapses to [`RowValue::Value`]`(Value::Map)`,
    /// so each map has exactly one canonical representation. This is what lets `m.key`, `m['key']`
    /// and `m.key[0]` recover a graph element a map literal holds (openCypher `DELETE`-through-map;
    /// `clauses/delete/Delete5.feature`).
    Map(Vec<(String, RowValue)>),
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

    /// Builds the canonical map value over `entries`: a pure-property map collapses to
    /// [`RowValue::Value`]`(Value::Map)`, while a map with any structural value (node / relationship
    /// / path / nested structural list or map) stays a [`RowValue::Map`].
    ///
    /// This is the **only** sanctioned way to build a map `RowValue`, mirroring [`RowValue::list`],
    /// so every map has exactly one representation and equivalence/ordering never have to unify a
    /// pure map across the two variants.
    pub fn map(entries: Vec<(String, RowValue)>) -> RowValue {
        if entries.iter().all(|(_, v)| matches!(v, RowValue::Value(_))) {
            RowValue::Value(Value::Map(
                entries
                    .into_iter()
                    .map(|(k, v)| match v {
                        RowValue::Value(v) => (k, v),
                        // Unreachable by the `all` check above; kept total for safety.
                        _ => (k, Value::Null),
                    })
                    .collect(),
            ))
        } else {
            RowValue::Map(entries)
        }
    }

    /// Borrows this value as a sequence of map entries, when it is a map of either representation: a
    /// structural [`RowValue::Map`] borrows directly; a property [`Value::Map`] lifts each value
    /// into a [`RowValue::Value`] (cloning the entries).
    #[must_use]
    pub fn as_map_entries(&self) -> Option<Vec<(String, RowValue)>> {
        match self {
            RowValue::Map(entries) => Some(entries.clone()),
            RowValue::Value(Value::Map(entries)) => Some(
                entries
                    .iter()
                    .cloned()
                    .map(|(k, v)| (k, RowValue::Value(v)))
                    .collect(),
            ),
            _ => None,
        }
    }
}

impl From<Value> for RowValue {
    fn from(v: Value) -> Self {
        RowValue::Value(v)
    }
}

/// The **unified global class rank** of a [`RowValue`] for `ORDER BY`, interleaving the structural
/// classes (`Node`/`Relationship`/`Path` — which exist only at the `RowValue` level) into the very
/// same CIP2016-06-14 §Orderability order the property classes use (`04 §7.6`).
///
/// The ascending order is `Map < Node < Relationship < List < Path < Point < {temporals} < String <
/// Bytes < Boolean < Number < null` (the structural entities slot **between** `Map` and `List`, not
/// above every property scalar — `ReturnOrderBy1.feature` [11]/[12], whose expected total order is
/// `{map} < (:Node) < [:Rel] < [list] < <path> < 'string' < boolean < number < NaN < null`). `NaN`
/// is folded into the number class by [`cmp_values`]/[`total_f64`] (just below `null`), so it needs
/// no rank of its own.
///
/// A structural list/map (`RowValue::List`/`RowValue::Map`) shares the rank of the corresponding
/// `Value::List`/`Value::Map`, so the two representations of each collection class order as one
/// (their *within-class* comparison is the elementwise / collapsed path below).
fn row_value_rank(v: &RowValue) -> u8 {
    match v {
        // Structural entities take the reserved CIP slots 1/2/4 (see `ordering::class_rank`), which sit
        // between `Map` (0) and the rest of the property classes.
        RowValue::Node(_) => 1,
        RowValue::Rel(_) => 2,
        RowValue::Path(_) => 4,
        // A structural list/map ranks as its property-`Value` class (`List` = 3, `Map` = 0), so it
        // interleaves with the matching `Value::List`/`Value::Map`.
        RowValue::List(_) => crate::ordering::class_rank(&Value::List(vec![])),
        RowValue::Map(_) => crate::ordering::class_rank(&Value::Map(vec![])),
        // A property value uses the shared CIP class rank directly.
        RowValue::Value(x) => crate::ordering::class_rank(x),
    }
}

/// Total ordering over [`RowValue`]s for `ORDER BY` (`04 §7.6`).
///
/// Cross-class comparisons are decided by the unified [`row_value_rank`] (which interleaves the
/// structural `Node`/`Relationship`/`Path` classes into the CIP property-class order), so a column
/// mixing entities, lists, scalars and `null` is totally ordered exactly as openCypher requires
/// (`ReturnOrderBy1.feature` [11]/[12]). Within one class: property values use the Cypher
/// orderability [`cmp_values`]; entity references order by id; lists of either representation compare
/// elementwise (shorter is less on a common prefix); paths compare by (start, steps); maps compare
/// through their property collapse.
#[must_use]
pub fn cmp_row_values(a: &RowValue, b: &RowValue) -> Ordering {
    // Decide across classes by the unified global rank first; an unequal rank settles the order
    // (this is what places `Map < Node < Rel < List < Path < … < Number < null`).
    let (ra, rb) = (row_value_rank(a), row_value_rank(b));
    if ra != rb {
        return ra.cmp(&rb);
    }
    // Same class: compare within it.
    match (a, b) {
        // List-kind values (either representation) compare elementwise as one class.
        _ if is_list_kind(a) && is_list_kind(b) => cmp_row_lists(a, b),
        (RowValue::Value(x), RowValue::Value(y)) => cmp_values(x, y),
        (RowValue::Node(x), RowValue::Node(y)) => x.id.cmp(&y.id),
        (RowValue::Rel(x), RowValue::Rel(y)) => x.id.cmp(&y.id),
        (RowValue::Path(x), RowValue::Path(y)) => x.cmp(y),
        // A structural map (or a structural map vs `Value::Map`) compares through its property
        // collapse, so the within-`Map`-class order matches `Value::Map`'s.
        (RowValue::Map(_), _) | (_, RowValue::Map(_)) => {
            cmp_values(&collapse_for_ordering(a), &collapse_for_ordering(b))
        }
        // Same rank but distinct representations not covered above (defensive): fall back to the
        // collapsed property order, which is total.
        _ => cmp_values(&collapse_for_ordering(a), &collapse_for_ordering(b)),
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
        RowValue::Map(entries) => Value::Map(
            entries
                .iter()
                .map(|(k, val)| (k.clone(), collapse_for_ordering(val)))
                .collect(),
        ),
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
        (RowValue::Map(x), RowValue::Map(y)) => {
            // Map equivalence is key-set + per-key value equivalence, order-independent (mirrors the
            // property-map equivalence in [`equivalent`]).
            x.len() == y.len()
                && x.iter().all(|(kx, vx)| {
                    y.iter()
                        .find(|(ky, _)| ky == kx)
                        .is_some_and(|(_, vy)| row_values_equivalent(vx, vy))
                })
        }
        _ => false,
    }
}

/// Feeds a [`RowValue`] into `state` so the hash is **consistent with [`row_values_equivalent`]**:
/// whenever two row-values are equivalent they hash equal. Collisions only share a bucket;
/// [`row_values_equivalent`] always decides membership. Used to bucket grouping / `DISTINCT` keys
/// in O(1) amortised (`rmp` #314). Nodes/relationships hash by identity (id), mirroring their
/// equivalence; paths fold to a single bucket (rare as a grouping key — the equivalence fallback
/// stays correct), structural lists hash in order, structural maps hash order-independently.
pub fn hash_row_value<H: std::hash::Hasher>(v: &RowValue, state: &mut H) {
    use std::hash::{Hash, Hasher};
    match v {
        RowValue::Value(x) => {
            0u8.hash(state);
            crate::equivalence::hash_value(x, state);
        }
        RowValue::Node(n) => {
            1u8.hash(state);
            n.id.hash(state);
        }
        RowValue::Rel(r) => {
            2u8.hash(state);
            r.id.hash(state);
        }
        RowValue::Path(_) => {
            // Paths are essentially never grouping keys; collapse to one bucket and let
            // `row_values_equivalent` decide. Correct, just not selective for this rare case.
            3u8.hash(state);
        }
        RowValue::List(xs) => {
            4u8.hash(state);
            xs.len().hash(state);
            for x in xs {
                hash_row_value(x, state);
            }
        }
        RowValue::Map(entries) => {
            5u8.hash(state);
            entries.len().hash(state);
            let mut acc: u64 = 0;
            for (k, val) in entries {
                let mut h = std::collections::hash_map::DefaultHasher::new();
                k.hash(&mut h);
                hash_row_value(val, &mut h);
                acc ^= h.finish();
            }
            acc.hash(state);
        }
    }
}

/// The **shared schema** of a [`Row`]: the ordered column names (`rmp` task #364).
///
/// A schema is **immutable and shared** behind an [`Arc`]: every row produced from a parent shares
/// the parent's schema by a cheap refcount bump, so cloning a row never re-allocates the column
/// names. Names live here, once, instead of being deep-cloned per row. Operators that introduce a
/// new column derive a fresh schema (copy-on-write) — but only **once per distinct row shape**, not
/// per row, because the hot loops hoist the derivation out (see [`Row::extend`]).
///
/// # Why a linear name scan, not a hash map
///
/// [`Row::get`] resolves a variable to a positional index by scanning the name slice. Result rows are
/// **narrow** — a query binds a handful of columns (typically 1–10) — and at that width a few short
/// `String` comparisons are measurably faster than hashing the lookup key (a `SipHash` of a `&str`
/// dominates the cost when N is tiny; an empirical bench at N=8 showed a hash map ~8× *slower*). The
/// name slice is also already needed for the result labels, so a parallel index map would only add
/// allocation to every schema derivation for no gain. Operators that resolve a column once and then
/// touch it per row use [`index_of_pub`](RowSchema::index_of_pub) + positional access to pay the scan
/// a single time per shape.
#[derive(Debug, Default, PartialEq)]
pub struct RowSchema {
    names: Vec<String>,
}

impl RowSchema {
    /// The empty schema (no columns).
    fn empty() -> Self {
        Self::default()
    }

    /// The bound column names, in order.
    #[inline]
    fn names(&self) -> &[String] {
        &self.names
    }

    /// The positional index of `name`, if bound (a linear scan — see the type docs for why this beats
    /// a hash map at result-row widths).
    #[inline]
    fn index_of(&self, name: &str) -> Option<usize> {
        self.names.iter().position(|c| c == name)
    }

    /// The positional index of `name`, if bound (public for compile-time index resolution in hot
    /// loops that pre-resolve a variable once, then access by index per row — `rmp` task #364).
    #[inline]
    #[must_use]
    pub fn index_of_pub(&self, name: &str) -> Option<usize> {
        self.index_of(name)
    }

    /// The number of columns.
    #[inline]
    #[must_use]
    pub fn len(&self) -> usize {
        self.names.len()
    }

    /// Whether the schema binds no columns.
    #[inline]
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.names.is_empty()
    }

    /// Builds a schema from an ordered name sequence, **dropping** a repeated name (keeping its first
    /// position) so the resulting `len()` is the count of distinct columns. A caller compares the
    /// resulting `len()` against the input count to detect (and specially handle) duplicate names —
    /// see [`Row`]'s projection path (`rmp` task #364).
    #[must_use]
    pub fn from_names(names: impl IntoIterator<Item = String>) -> Self {
        let mut schema = Self::empty();
        for name in names {
            if !schema.names.contains(&name) {
                schema.names.push(name);
            }
        }
        schema
    }

    /// Derives a new schema with `name` appended (the caller guarantees `name` is not already bound).
    fn appended(&self, name: String) -> Self {
        let mut names = Vec::with_capacity(self.names.len() + 1);
        names.extend_from_slice(&self.names);
        names.push(name);
        Self { names }
    }
}

/// A single executor result row: a positional tuple of [`RowValue`]s over a **shared** [`RowSchema`]
/// (`04 §7.4`, `rmp` task #364).
///
/// A row is a **name → value binding** realised as a positional `values` vector indexed through an
/// `Arc<RowSchema>`. Positional access is the executor's hot path; the shared schema lets operators
/// resolve variables by name (a linear scan of the shared name slice — never a per-row `String`
/// clone) and labels the final result columns. Column order is the introduction order of the binding.
///
/// # Why the schema is shared (`rmp` task #364)
///
/// Previously a row owned `columns: Vec<String>`, so every `clone` — done once per produced edge in
/// `expand`, once per merged row in a join — deep-cloned every column **name** (a heap allocation per
/// name per row). Carrying the names in an `Arc<RowSchema>` makes a clone a refcount bump: **no
/// per-row column-name allocation remains**. Only the `values` are cloned, which is unavoidable.
#[derive(Debug, Clone, Default)]
#[must_use]
pub struct Row {
    schema: std::sync::Arc<RowSchema>,
    values: Vec<RowValue>,
}

impl PartialEq for Row {
    /// Two rows are equal when they bind the same names **in the same order** to equal values — the
    /// exact semantics of the previous derived `PartialEq` over parallel `columns`/`values` vectors.
    /// Schemas are compared structurally (not by `Arc` identity) so independently built rows with the
    /// same shape still compare equal.
    fn eq(&self, other: &Self) -> bool {
        std::sync::Arc::ptr_eq(&self.schema, &other.schema)
            || self.schema.names() == other.schema.names() && self.values == other.values
    }
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

    /// The shared schema of this row.
    pub fn schema(&self) -> &std::sync::Arc<RowSchema> {
        &self.schema
    }

    /// Builds a row directly from a pre-built shared `schema` and the matching positional `values`
    /// (`rmp` task #364). The fast path for operators (projection) whose output schema is identical
    /// for every emitted row: the schema is built once and shared, only `values` differ per row.
    ///
    /// # Panics
    ///
    /// Panics (debug builds) if `values.len()` does not equal `schema.len()` — the two must be the
    /// same positional arity.
    pub fn from_schema_values(schema: std::sync::Arc<RowSchema>, values: Vec<RowValue>) -> Self {
        debug_assert_eq!(
            schema.len(),
            values.len(),
            "from_schema_values: schema arity must match values arity"
        );
        Self { schema, values }
    }

    /// The bound column names, in order.
    #[must_use]
    pub fn columns(&self) -> &[String] {
        self.schema.names()
    }

    /// The values, in column order.
    pub fn values(&self) -> &[RowValue] {
        &self.values
    }

    /// The number of bound columns.
    #[must_use]
    pub fn len(&self) -> usize {
        self.values.len()
    }

    /// Whether the row binds no columns.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.values.is_empty()
    }

    /// The value bound to `name`, if any. Resolves the name to a positional index by a linear scan of
    /// the **shared** schema's name slice (fast at result-row widths — see [`RowSchema`]), then indexes
    /// the positional `values`. The names are no longer cloned per row (`rmp` task #364).
    #[must_use]
    pub fn get(&self, name: &str) -> Option<&RowValue> {
        self.schema.index_of(name).map(|i| &self.values[i])
    }

    /// The value at positional column `i`, if in range (the hottest accessor once a variable has been
    /// resolved to an index once).
    #[inline]
    #[must_use]
    pub fn get_at(&self, i: usize) -> Option<&RowValue> {
        self.values.get(i)
    }

    /// Overwrites the value at the already-existing positional column `i` (`rmp` task #364). Touches
    /// **only** `values` — the shared schema is untouched, so no allocation. Used by hot loops that
    /// pre-resolved a column index against the template schema and now stamp many rows.
    ///
    /// # Panics
    ///
    /// Panics if `i` is out of range — callers resolve `i` from the same schema the row carries, so
    /// this is an invariant violation, not an expected runtime condition.
    #[inline]
    pub fn set_at(&mut self, i: usize, value: RowValue) {
        self.values[i] = value;
    }

    /// Whether `name` is bound in this row.
    #[must_use]
    pub fn contains(&self, name: &str) -> bool {
        self.schema.index_of(name).is_some()
    }

    /// Binds `name` to `value`, **overwriting** an existing binding for the same name in place (so a
    /// re-bind keeps its original column position). A new name derives an extended schema and appends
    /// the value.
    ///
    /// Re-binding an existing column touches only `values` (the schema is untouched, no allocation).
    /// Adding a new column derives a new schema via copy-on-write. Hot loops that add the **same**
    /// new column to many rows should hoist that derivation with [`Row::extend`] /
    /// [`Row::with_schema`] to amortise it to one allocation per row shape.
    pub fn set(&mut self, name: impl Into<String>, value: RowValue) {
        let name = name.into();
        if let Some(i) = self.schema.index_of(&name) {
            self.values[i] = value;
        } else {
            self.schema = std::sync::Arc::new(self.schema.appended(name));
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

    /// Builds the schema this row would have after appending `name` (or the existing schema if `name`
    /// is already bound), **without** cloning the row's values. Hoist this out of a fan-out loop to
    /// allocate the derived schema **once** and stamp it onto every produced row via
    /// [`Row::with_schema_value`].
    pub fn extend(&self, name: &str) -> std::sync::Arc<RowSchema> {
        if self.schema.index_of(name).is_some() {
            std::sync::Arc::clone(&self.schema)
        } else {
            std::sync::Arc::new(self.schema.appended(name.to_owned()))
        }
    }

    /// Produces a row that is a clone of `self`'s values with one trailing `value` appended under the
    /// pre-derived `schema` (from [`Row::extend`]). The schema must be `self`'s schema extended by
    /// exactly one new trailing column; this is the per-row-cheap path used in fan-out loops (one
    /// `Arc` bump + one value clone + one push, **no** schema allocation per row).
    pub fn with_schema_value(&self, schema: &std::sync::Arc<RowSchema>, value: RowValue) -> Self {
        debug_assert_eq!(
            schema.len(),
            self.values.len() + 1,
            "with_schema_value expects a schema extended by exactly one new column"
        );
        let mut values = Vec::with_capacity(schema.len());
        values.extend_from_slice(&self.values);
        values.push(value);
        Self {
            schema: std::sync::Arc::clone(schema),
            values,
        }
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
    fn map_collapses_to_value_when_pure_property() {
        // A map of only property values is canonicalised to `Value::Map`, so a pure map has exactly
        // one representation (mirrors `RowValue::list`).
        let m = RowValue::map(vec![
            ("a".to_owned(), RowValue::Value(Value::Integer(1))),
            (
                "b".to_owned(),
                RowValue::Value(Value::String("x".to_owned())),
            ),
        ]);
        match m {
            RowValue::Value(Value::Map(entries)) => {
                assert_eq!(entries.len(), 2);
                assert_eq!(entries[0], ("a".to_owned(), Value::Integer(1)));
            }
            other => panic!("expected a collapsed property map, got {other:?}"),
        }
    }

    #[test]
    fn map_stays_structural_when_holding_an_entity() {
        // A map with a node value keeps the structural representation, so `m.key` can recover the
        // node reference for `DELETE` (Delete5.feature).
        let node = RowValue::Node(NodeRef { id: NodeId(3) });
        let m = RowValue::map(vec![("key".to_owned(), node)]);
        let RowValue::Map(entries) = &m else {
            panic!("expected a structural map, got {m:?}");
        };
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].1.as_node(), Some(NodeId(3)));
        // `as_map_entries` borrows the structural entries unchanged.
        let borrowed = m.as_map_entries().expect("map entries");
        assert_eq!(borrowed[0].1.as_node(), Some(NodeId(3)));
    }

    #[test]
    fn structural_map_equivalence_is_order_independent() {
        let a = RowValue::Map(vec![
            ("k".to_owned(), RowValue::Node(NodeRef { id: NodeId(1) })),
            ("j".to_owned(), RowValue::Value(Value::Integer(2))),
        ]);
        let b = RowValue::Map(vec![
            ("j".to_owned(), RowValue::Value(Value::Integer(2))),
            ("k".to_owned(), RowValue::Node(NodeRef { id: NodeId(1) })),
        ]);
        assert!(row_values_equivalent(&a, &b));
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
    fn order_by_across_distinct_types_follows_cip_total_order() {
        // The CIP/TCK ascending total order across classes (ReturnOrderBy1.feature [11]):
        //   {map} < (:Node) < [:Rel] < [list] < <path> < 'string' < boolean < number < NaN < null
        let map = RowValue::Value(Value::Map(vec![(
            "a".to_owned(),
            Value::String("map".to_owned()),
        )]));
        let node = RowValue::Node(NodeRef { id: NodeId(1) });
        let rel = RowValue::Rel(RelRef {
            id: crate::graph_access::RelId(1),
        });
        let list = RowValue::Value(Value::List(vec![Value::String("list".to_owned())]));
        let path = RowValue::Path(PathValue {
            start: NodeId(1),
            steps: Vec::new(),
        });
        let string = RowValue::Value(Value::String("text".to_owned()));
        let boolean = RowValue::Value(Value::Boolean(false));
        let number = RowValue::Value(Value::Float(1.5));
        let nan = RowValue::Value(Value::Float(f64::NAN));
        let null = RowValue::NULL;

        let ascending = [
            &map, &node, &rel, &list, &path, &string, &boolean, &number, &nan, &null,
        ];
        // Every adjacent pair is strictly increasing, and antisymmetric.
        for w in ascending.windows(2) {
            assert_eq!(
                cmp_row_values(w[0], w[1]),
                Ordering::Less,
                "{:?} should be < {:?}",
                w[0],
                w[1]
            );
            assert_eq!(
                cmp_row_values(w[1], w[0]),
                Ordering::Greater,
                "antisymmetry for {:?},{:?}",
                w[0],
                w[1]
            );
        }
        // Within the number class, an integer interleaves with floats by value (no #130 regression).
        assert_eq!(
            cmp_row_values(
                &RowValue::Value(Value::Integer(1)),
                &RowValue::Value(Value::Float(1.5))
            ),
            Ordering::Less
        );
        // NaN sits just below null (the largest number-ish value).
        assert_eq!(cmp_row_values(&nan, &null), Ordering::Less);
        assert_eq!(cmp_row_values(&number, &nan), Ordering::Less);
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
