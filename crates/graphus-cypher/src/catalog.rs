//! The **index catalog** the physical planner consults (`04-technical-design.md` §6.6).
//!
//! `04 §6.6` says the planner *"consults the **index catalog** (a system structure listing indexes,
//! their keys, and selectivity hints) during physical planning to choose index seeks/scans over
//! full scans"*, that v1 is *"heuristic/rule-based with index awareness"*, and that *"plans record
//! which indexes they depend on so the **plan cache** is invalidated on schema/index change"*. This
//! module is that catalog **abstraction**, sized for the planner's needs and nothing more.
//!
//! # What this is, and what it is not
//!
//! The **real** catalog is populated from the live schema by the index/transaction layer later (the
//! four concrete index structures already live in `graphus-index`'s `kinds` module:
//! `TokenIndex`, `PropertyIndex`, `CompositeIndex`, `RelPropertyIndex`). `graphus-cypher` must stay
//! a closed query-layer crate (the dependency rule of `04 §1.2` forbids the storage/index core from
//! depending on the query layer, and we keep the converse cheap too: the planner needs only the
//! *shape* of the available indexes, never their pages). So this catalog is a **plain in-memory
//! description** — a list of [`IndexDescriptor`]s — with:
//!
//! - a [builder](IndexCatalogBuilder) so tests and the eventual schema-loader can populate it
//!   declaratively, and
//! - lookup helpers ([`IndexCatalog::label_property`], [`IndexCatalog::token_lookup`], …) shaped
//!   exactly around the planner's index-selection rules ([`crate::physical`]).
//!
//! The four [`IndexKind`]s deliberately mirror the `D-v1-index-types` set (`04 §6.2`) so the
//! vocabulary is identical across the query and index layers.
//!
//! # Cache invalidation
//!
//! Every [`IndexDescriptor`] carries a stable [`IndexId`]. A physical plan records the set of
//! [`IndexId`]s it depends on (see [`crate::physical::PhysicalPlan::index_dependencies`]); the plan
//! cache (`04 §7.5`, [`crate::plan_cache`]) is keyed on a `schema_version` that the schema layer
//! bumps whenever an index is created or dropped, so a plan compiled against a stale catalog is
//! never reused (`04 §6.6`). Recording the precise [`IndexId`]s in addition lets a future,
//! finer-grained invalidation drop only the plans that touched a *changed* index.

use crate::ast::{Label, RelType};

/// A stable identifier for one index in the [`IndexCatalog`].
///
/// Assigned by the [`IndexCatalogBuilder`] in declaration order (and, for the real catalog, by the
/// schema layer). A [physical plan](crate::physical::PhysicalPlan) records the [`IndexId`]s it
/// depends on so the plan cache can be invalidated when those indexes change (`04 §6.6`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[must_use]
pub struct IndexId(pub u32);

impl std::fmt::Display for IndexId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "idx#{}", self.0)
    }
}

/// The kind of an index, mirroring the four v1 index kinds of `04 §6.2` / `D-v1-index-types`.
///
/// The planner reads the kind to decide *which* access path an index enables:
///
/// - [`TokenLookup`](Self::TokenLookup) backs a bare `MATCH (n:Label)` (a label/token scan, no
///   property predicate).
/// - [`Property`](Self::Property) (range/B-tree) backs an equality **or** range predicate on a
///   single labelled property.
/// - [`Composite`](Self::Composite) backs multi-property equality and **leading-prefix** range
///   predicates over a labelled property tuple.
/// - [`RelProperty`](Self::RelProperty) is the property index over relationship records, keyed by
///   relationship type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[must_use]
pub enum IndexKind {
    /// Label / relationship-type scan store (`TokenIndex` in `graphus-index`): enables
    /// `MATCH (n:Label)` without a full store scan (`04 §6.2`).
    TokenLookup,
    /// Range/B-tree property index over **node** records, keyed `(label, value)`: equality and
    /// range predicates (`04 §6.2`).
    Property,
    /// Composite index over **node** records, keyed `(label, v1, …, vk)` in declared order:
    /// multi-property equality and leading-prefix range (`04 §6.2`).
    Composite,
    /// Range/B-tree property index over **relationship** records, keyed `(reltype, value)`
    /// (`04 §6.2`, required by `D-v1-index-types`).
    RelProperty,
}

impl IndexKind {
    /// A short stable tag used in diagnostics and plan rendering.
    #[must_use]
    pub const fn tag(self) -> &'static str {
        match self {
            Self::TokenLookup => "token-lookup",
            Self::Property => "property",
            Self::Composite => "composite",
            Self::RelProperty => "rel-property",
        }
    }
}

/// The entity domain an index covers: nodes (by label) or relationships (by type).
///
/// Kept distinct from [`IndexKind`] because a property index and a token-lookup index can both be
/// node-scoped, while the token they key on (a label vs a relationship type) is what tells the
/// planner whether the index can serve a given pattern element.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[must_use]
pub enum IndexTarget {
    /// A node index covering nodes carrying `label`.
    Label(String),
    /// A relationship index covering relationships of `rel_type`.
    RelType(String),
}

impl IndexTarget {
    /// Builds a node (label) target from a `&str`.
    pub fn label(name: impl Into<String>) -> Self {
        Self::Label(name.into())
    }

    /// Builds a relationship (type) target from a `&str`.
    pub fn rel_type(name: impl Into<String>) -> Self {
        Self::RelType(name.into())
    }

    /// The label name this target covers, if it is a node target.
    #[must_use]
    pub fn as_label(&self) -> Option<&str> {
        match self {
            Self::Label(name) => Some(name),
            Self::RelType(_) => None,
        }
    }

    /// The relationship-type name this target covers, if it is a relationship target.
    #[must_use]
    pub fn as_rel_type(&self) -> Option<&str> {
        match self {
            Self::RelType(name) => Some(name),
            Self::Label(_) => None,
        }
    }
}

/// One index entry in the catalog: its [`IndexId`], [`IndexKind`], the [`IndexTarget`] it covers,
/// and the **ordered** property keys it indexes (`04 §6.6`: *"indexes, their keys, …"*).
///
/// `properties` is empty for a [`IndexKind::TokenLookup`] (it has no property key), holds exactly
/// one key for a [`IndexKind::Property`] / [`IndexKind::RelProperty`], and holds the declared key
/// order for a [`IndexKind::Composite`].
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[must_use]
pub struct IndexDescriptor {
    /// The stable identity used for plan dependency tracking and cache invalidation.
    pub id: IndexId,
    /// The kind of index (which access paths it enables).
    pub kind: IndexKind,
    /// The entity domain (label or relationship type) the index covers.
    pub target: IndexTarget,
    /// The ordered property keys the index covers; empty for a token-lookup index.
    pub properties: Vec<String>,
}

impl IndexDescriptor {
    /// Whether this descriptor covers `label` as a node index.
    #[must_use]
    fn covers_label(&self, label: &str) -> bool {
        self.target.as_label() == Some(label)
    }

    /// Whether this descriptor covers `rel_type` as a relationship index.
    #[must_use]
    fn covers_rel_type(&self, rel_type: &str) -> bool {
        self.target.as_rel_type() == Some(rel_type)
    }
}

/// The set of indexes available to the physical planner (`04 §6.6`).
///
/// Construct one with [`IndexCatalog::builder`] (tests and the schema-loader path) or
/// [`IndexCatalog::empty`] (no indexes — everything falls back to scans). The lookup helpers are the
/// exact queries the planner's index-selection rules issue ([`crate::physical`]); they all return
/// the most-specific match so the planner can pick the strongest available access path.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[must_use]
pub struct IndexCatalog {
    indexes: Vec<IndexDescriptor>,
}

impl IndexCatalog {
    /// An empty catalog — no indexes. Every access compiles to a scan (`04 §6.6` fallback).
    pub fn empty() -> Self {
        Self::default()
    }

    /// Starts building a catalog declaratively.
    pub fn builder() -> IndexCatalogBuilder {
        IndexCatalogBuilder::default()
    }

    /// All descriptors in the catalog, in declaration order.
    pub fn indexes(&self) -> &[IndexDescriptor] {
        &self.indexes
    }

    /// The descriptor with the given [`IndexId`], if present.
    #[must_use]
    pub fn get(&self, id: IndexId) -> Option<&IndexDescriptor> {
        self.indexes.iter().find(|d| d.id == id)
    }

    /// The token-lookup index covering `label`, if one exists (`04 §6.2` label scan store).
    ///
    /// Backs a bare `MATCH (n:Label)`: a per-token range scan instead of a full all-nodes scan.
    #[must_use]
    pub fn token_lookup(&self, label: &Label) -> Option<&IndexDescriptor> {
        self.indexes
            .iter()
            .find(|d| d.kind == IndexKind::TokenLookup && d.covers_label(&label.name))
    }

    /// A single-property node index on `(label, property)` usable for an equality **or** range
    /// predicate.
    ///
    /// Returns a [`IndexKind::Property`] index whose sole key is `property`, **or** a
    /// [`IndexKind::Composite`] index whose **leading** key is `property` (a composite can serve a
    /// predicate on its first key as a leading-prefix seek, `04 §6.2`). A pure [`IndexKind::Property`]
    /// match is preferred when both exist, since it is the most selective for a single-property
    /// predicate.
    #[must_use]
    pub fn label_property(&self, label: &Label, property: &str) -> Option<&IndexDescriptor> {
        // Prefer an exact single-property index.
        let exact = self.indexes.iter().find(|d| {
            d.kind == IndexKind::Property
                && d.covers_label(&label.name)
                && d.properties.first().map(String::as_str) == Some(property)
        });
        if exact.is_some() {
            return exact;
        }
        // Otherwise a composite whose leading key matches can serve a leading-prefix seek.
        self.indexes.iter().find(|d| {
            d.kind == IndexKind::Composite
                && d.covers_label(&label.name)
                && d.properties.first().map(String::as_str) == Some(property)
        })
    }

    /// A relationship-property index on `(rel_type, property)` for an equality or range predicate
    /// (`04 §6.2`).
    #[must_use]
    pub fn rel_property(&self, rel_type: &RelType, property: &str) -> Option<&IndexDescriptor> {
        self.indexes.iter().find(|d| {
            d.kind == IndexKind::RelProperty
                && d.covers_rel_type(&rel_type.name)
                && d.properties.first().map(String::as_str) == Some(property)
        })
    }
}

/// A declarative builder for an [`IndexCatalog`] (`04 §6.6`).
///
/// Each `with_*` call appends a descriptor and assigns the next [`IndexId`] in order. The builder is
/// the population path for tests today and a clean target for the schema-loader later.
///
/// # Examples
///
/// ```
/// use graphus_cypher::catalog::{IndexCatalog, IndexKind};
///
/// let catalog = IndexCatalog::builder()
///     .with_token_lookup("Person")
///     .with_label_property("Person", "name")
///     .with_label_composite("Person", ["first", "last"])
///     .with_rel_property("KNOWS", "since")
///     .build();
///
/// assert_eq!(catalog.indexes().len(), 4);
/// assert_eq!(catalog.indexes()[0].kind, IndexKind::TokenLookup);
/// ```
#[derive(Debug, Clone, Default)]
#[must_use]
pub struct IndexCatalogBuilder {
    indexes: Vec<IndexDescriptor>,
}

impl IndexCatalogBuilder {
    /// The [`IndexId`] the next appended descriptor will receive.
    fn next_id(&self) -> IndexId {
        // The cast is infallible in practice (a catalog never holds 2^32 indexes); `as` here is a
        // total widening of the count into the id space and carries no overflow risk for any real
        // schema.
        IndexId(self.indexes.len() as u32)
    }

    /// Appends a fully-specified descriptor (escape hatch for the schema-loader / unusual shapes).
    pub fn with_descriptor(
        mut self,
        kind: IndexKind,
        target: IndexTarget,
        properties: Vec<String>,
    ) -> Self {
        let id = self.next_id();
        self.indexes.push(IndexDescriptor {
            id,
            kind,
            target,
            properties,
        });
        self
    }

    /// Appends a token-lookup (label scan) index over `label`.
    pub fn with_token_lookup(self, label: impl Into<String>) -> Self {
        self.with_descriptor(
            IndexKind::TokenLookup,
            IndexTarget::label(label),
            Vec::new(),
        )
    }

    /// Appends a single-property node index over `(label, property)`.
    pub fn with_label_property(
        self,
        label: impl Into<String>,
        property: impl Into<String>,
    ) -> Self {
        self.with_descriptor(
            IndexKind::Property,
            IndexTarget::label(label),
            vec![property.into()],
        )
    }

    /// Appends a composite node index over `(label, properties…)` in declared order.
    pub fn with_label_composite<I, S>(self, label: impl Into<String>, properties: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let props: Vec<String> = properties.into_iter().map(Into::into).collect();
        self.with_descriptor(IndexKind::Composite, IndexTarget::label(label), props)
    }

    /// Appends a relationship-property index over `(rel_type, property)`.
    pub fn with_rel_property(
        self,
        rel_type: impl Into<String>,
        property: impl Into<String>,
    ) -> Self {
        self.with_descriptor(
            IndexKind::RelProperty,
            IndexTarget::rel_type(rel_type),
            vec![property.into()],
        )
    }

    /// Finalises the catalog.
    pub fn build(self) -> IndexCatalog {
        IndexCatalog {
            indexes: self.indexes,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lexer::Span;

    fn label(name: &str) -> Label {
        Label {
            name: name.to_owned(),
            span: Span::new(0, 0),
        }
    }

    fn rel_type(name: &str) -> RelType {
        RelType {
            name: name.to_owned(),
            span: Span::new(0, 0),
        }
    }

    #[test]
    fn builder_assigns_ids_in_declaration_order() {
        let catalog = IndexCatalog::builder()
            .with_token_lookup("A")
            .with_label_property("A", "p")
            .build();
        assert_eq!(catalog.indexes()[0].id, IndexId(0));
        assert_eq!(catalog.indexes()[1].id, IndexId(1));
        assert_eq!(catalog.get(IndexId(1)).unwrap().kind, IndexKind::Property);
        assert!(catalog.get(IndexId(99)).is_none());
    }

    #[test]
    fn token_lookup_matches_only_its_label() {
        let catalog = IndexCatalog::builder().with_token_lookup("Person").build();
        assert!(catalog.token_lookup(&label("Person")).is_some());
        assert!(catalog.token_lookup(&label("Company")).is_none());
    }

    #[test]
    fn label_property_prefers_exact_over_composite_leading_key() {
        let catalog = IndexCatalog::builder()
            .with_label_composite("Person", ["name", "age"])
            .with_label_property("Person", "name")
            .build();
        let chosen = catalog.label_property(&label("Person"), "name").unwrap();
        assert_eq!(chosen.kind, IndexKind::Property);
    }

    #[test]
    fn label_property_falls_back_to_composite_leading_prefix() {
        let catalog = IndexCatalog::builder()
            .with_label_composite("Person", ["name", "age"])
            .build();
        // The leading key `name` is servable by the composite as a leading-prefix seek.
        let chosen = catalog.label_property(&label("Person"), "name").unwrap();
        assert_eq!(chosen.kind, IndexKind::Composite);
        // A non-leading key (`age`) is NOT servable from a single-predicate lookup.
        assert!(catalog.label_property(&label("Person"), "age").is_none());
    }

    #[test]
    fn rel_property_keyed_by_type() {
        let catalog = IndexCatalog::builder()
            .with_rel_property("KNOWS", "since")
            .build();
        assert!(catalog.rel_property(&rel_type("KNOWS"), "since").is_some());
        assert!(catalog.rel_property(&rel_type("KNOWS"), "weight").is_none());
        assert!(catalog.rel_property(&rel_type("LIKES"), "since").is_none());
    }

    #[test]
    fn empty_catalog_finds_nothing() {
        let catalog = IndexCatalog::empty();
        assert!(catalog.token_lookup(&label("A")).is_none());
        assert!(catalog.label_property(&label("A"), "p").is_none());
        assert!(catalog.indexes().is_empty());
    }
}
