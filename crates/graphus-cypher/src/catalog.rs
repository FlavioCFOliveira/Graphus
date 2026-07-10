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
    /// Spatial grid index over a **node** point property, keyed `(label, point-property)`: backs
    /// proximity (`distance(n.loc, $p) <= r`) and bounding-box predicates (`rmp` task #73). Like a
    /// full-text index its backing structure is derived/ephemeral (`graphus_index::SpatialIndex`);
    /// the descriptor records only its shape for planning.
    Spatial,
    /// Text (trigram) index over a **node** string property, keyed `(label, string-property)`: backs
    /// the `CONTAINS` / `ENDS WITH` / `STARTS WITH` predicates a forward-ordered range index cannot
    /// serve (substring/suffix are not a contiguous key range) (`rmp` task #662). Like a full-text /
    /// spatial index its backing structure is derived/ephemeral (`graphus_index::TrigramIndex`); the
    /// descriptor records only its shape for planning.
    Text,
    /// Spatial grid index over a **relationship** point property, keyed `(reltype, point-property)`:
    /// backs a proximity (`distance(r.loc, $p) <= r`) predicate on a typed relationship point property
    /// (`rmp` task #664) — the relationship analogue of [`Spatial`](Self::Spatial). Like it, the backing
    /// grid is derived/ephemeral (`graphus_index::SpatialIndex` over relationship ids); the descriptor
    /// records only its shape for planning.
    RelSpatial,
    /// Composite index over **relationship** records, keyed `(reltype, v1, …, vk)` in declared order:
    /// multi-property equality and leading-prefix range over a typed relationship property tuple
    /// (`rmp` task #666) — the relationship analogue of [`Composite`](Self::Composite). Like the node
    /// composite its backing B+-tree is derived/ephemeral (rebuilt from the store on open); the
    /// descriptor records only its shape for planning.
    RelComposite,
    /// Vector (HNSW) index over a **node** embedding property, keyed `(label, embedding-property)`:
    /// backs an approximate-nearest-neighbour (k-NN) query over a dense `f32` embedding (`rmp` task
    /// #669). Its backing structure is a derived/ephemeral HNSW graph (`graphus_index::VectorIndex`);
    /// the descriptor records only its shape for planning (the query planner is `rmp` #671).
    Vector,
    /// Vector (HNSW) index over a **relationship** embedding property, keyed `(reltype,
    /// embedding-property)` (`rmp` task #669) — the relationship analogue of [`Vector`](Self::Vector).
    RelVector,
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
            Self::Spatial => "spatial",
            Self::Text => "text",
            Self::RelSpatial => "rel-spatial",
            Self::RelComposite => "rel-composite",
            Self::Vector => "vector",
            Self::RelVector => "rel-vector",
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

    /// A composite node index on `label` whose **full ordered property tuple** is entirely covered by
    /// the equality-predicate properties `available` (`rmp` task #657).
    ///
    /// Returns a [`IndexKind::Composite`] index (arity ≥ 2) whose every key appears in `available` — so
    /// a `MATCH (n:L {a: …, b: …})` (both keys have an equality conjunct) drives one full-key composite
    /// seek. When several composites qualify, the one with the **most** keys is preferred (the most
    /// selective). A composite whose leading key alone is present (a strict prefix) is **not** returned
    /// here — that case is served by [`label_property`](Self::label_property)'s leading-prefix contract.
    #[must_use]
    pub fn label_composite_full_eq(
        &self,
        label: &Label,
        available: &[&str],
    ) -> Option<&IndexDescriptor> {
        self.indexes
            .iter()
            .filter(|d| {
                d.kind == IndexKind::Composite
                    && d.covers_label(&label.name)
                    && d.properties.len() >= 2
                    && d.properties.iter().all(|p| available.contains(&p.as_str()))
            })
            .max_by_key(|d| d.properties.len())
    }

    /// A spatial index on `(label, point-property)` usable for a proximity / bounding-box predicate
    /// (`rmp` task #73). The planner consults this for a `distance(n.prop, $p) <= r` or
    /// coordinate-range predicate on a labelled point property.
    #[must_use]
    pub fn label_spatial(&self, label: &Label, property: &str) -> Option<&IndexDescriptor> {
        self.indexes.iter().find(|d| {
            d.kind == IndexKind::Spatial
                && d.covers_label(&label.name)
                && d.properties.first().map(String::as_str) == Some(property)
        })
    }

    /// A text (trigram) index on `(label, string-property)` usable for a `CONTAINS` / `ENDS WITH` /
    /// `STARTS WITH` predicate (`rmp` task #662). The planner consults this for a substring / suffix /
    /// prefix predicate on a labelled string property; when present it is preferred over the range-index
    /// prefix seek for `STARTS WITH` (a text index also serves the substring and suffix forms a range
    /// index cannot).
    #[must_use]
    pub fn label_text(&self, label: &Label, property: &str) -> Option<&IndexDescriptor> {
        self.indexes.iter().find(|d| {
            d.kind == IndexKind::Text
                && d.covers_label(&label.name)
                && d.properties.first().map(String::as_str) == Some(property)
        })
    }

    /// A relationship-property index on `(rel_type, property)` for an equality or range predicate
    /// (`04 §6.2`).
    ///
    /// Returns a [`IndexKind::RelProperty`] index whose sole key is `property`, **or** a
    /// [`IndexKind::RelComposite`] index whose **leading** key is `property` (a composite relationship
    /// index can serve a predicate on its first key as a leading-prefix seek, `rmp` task #666). A pure
    /// [`IndexKind::RelProperty`] match is preferred when both exist, since it is the most selective for
    /// a single-property predicate — mirroring [`label_property`](Self::label_property).
    #[must_use]
    pub fn rel_property(&self, rel_type: &RelType, property: &str) -> Option<&IndexDescriptor> {
        // Prefer an exact single-property relationship index.
        let exact = self.indexes.iter().find(|d| {
            d.kind == IndexKind::RelProperty
                && d.covers_rel_type(&rel_type.name)
                && d.properties.first().map(String::as_str) == Some(property)
        });
        if exact.is_some() {
            return exact;
        }
        // Otherwise a composite relationship index whose leading key matches serves a leading-prefix
        // seek (the plan shape is a single-key `RelIndexSeek`; the executor falls back to a scan for a
        // composite-only tree, exactly like the node leading-prefix case).
        self.indexes.iter().find(|d| {
            d.kind == IndexKind::RelComposite
                && d.covers_rel_type(&rel_type.name)
                && d.properties.first().map(String::as_str) == Some(property)
        })
    }

    /// A composite relationship index on `rel_type` whose **full ordered property tuple** is entirely
    /// covered by the equality-predicate properties `available` (`rmp` task #666) — the relationship
    /// analogue of [`label_composite_full_eq`](Self::label_composite_full_eq).
    ///
    /// Returns a [`IndexKind::RelComposite`] index (arity ≥ 2) whose every key appears in `available` —
    /// so a `MATCH ()-[r:T {a: …, b: …}]-()` (both keys have an equality conjunct) drives one full-key
    /// composite relationship seek. When several composites qualify, the one with the **most** keys is
    /// preferred (the most selective). A composite whose leading key alone is present (a strict prefix)
    /// is **not** returned here — that case is served by [`rel_property`](Self::rel_property)'s
    /// leading-prefix contract.
    #[must_use]
    pub fn rel_composite_full_eq(
        &self,
        rel_type: &RelType,
        available: &[&str],
    ) -> Option<&IndexDescriptor> {
        self.indexes
            .iter()
            .filter(|d| {
                d.kind == IndexKind::RelComposite
                    && d.covers_rel_type(&rel_type.name)
                    && d.properties.len() >= 2
                    && d.properties.iter().all(|p| available.contains(&p.as_str()))
            })
            .max_by_key(|d| d.properties.len())
    }

    /// A relationship spatial index on `(rel_type, point-property)` usable for a proximity predicate
    /// (`rmp` task #664) — the relationship analogue of [`label_spatial`](Self::label_spatial). The
    /// planner consults this for a `distance(r.prop, $p) <= r` predicate on a typed relationship point
    /// property.
    #[must_use]
    pub fn rel_spatial(&self, rel_type: &RelType, property: &str) -> Option<&IndexDescriptor> {
        self.indexes.iter().find(|d| {
            d.kind == IndexKind::RelSpatial
                && d.covers_rel_type(&rel_type.name)
                && d.properties.first().map(String::as_str) == Some(property)
        })
    }

    /// A vector (HNSW) index on `(label, embedding-property)` usable for an approximate-nearest-neighbour
    /// (k-NN) query over a dense embedding (`rmp` task #669). The query planner (`rmp` #671) consults
    /// this to route a k-NN query on a labelled embedding property to a vector index seek.
    #[must_use]
    pub fn label_vector(&self, label: &Label, property: &str) -> Option<&IndexDescriptor> {
        self.indexes.iter().find(|d| {
            d.kind == IndexKind::Vector
                && d.covers_label(&label.name)
                && d.properties.first().map(String::as_str) == Some(property)
        })
    }

    /// A relationship vector (HNSW) index on `(rel_type, embedding-property)` usable for a k-NN query
    /// (`rmp` task #669) — the relationship analogue of [`label_vector`](Self::label_vector).
    #[must_use]
    pub fn rel_vector(&self, rel_type: &RelType, property: &str) -> Option<&IndexDescriptor> {
        self.indexes.iter().find(|d| {
            d.kind == IndexKind::RelVector
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

    /// Appends a spatial index over `(label, point-property)` (`rmp` task #73).
    pub fn with_label_spatial(self, label: impl Into<String>, property: impl Into<String>) -> Self {
        self.with_descriptor(
            IndexKind::Spatial,
            IndexTarget::label(label),
            vec![property.into()],
        )
    }

    /// Appends a text (trigram) index over `(label, string-property)` (`rmp` task #662).
    pub fn with_label_text(self, label: impl Into<String>, property: impl Into<String>) -> Self {
        self.with_descriptor(
            IndexKind::Text,
            IndexTarget::label(label),
            vec![property.into()],
        )
    }

    /// Appends a relationship spatial index over `(rel_type, point-property)` (`rmp` task #664).
    pub fn with_rel_spatial(
        self,
        rel_type: impl Into<String>,
        property: impl Into<String>,
    ) -> Self {
        self.with_descriptor(
            IndexKind::RelSpatial,
            IndexTarget::rel_type(rel_type),
            vec![property.into()],
        )
    }

    /// Appends a composite relationship index over `(rel_type, properties…)` in declared order
    /// (`rmp` task #666).
    pub fn with_rel_composite<I, S>(self, rel_type: impl Into<String>, properties: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        let props: Vec<String> = properties.into_iter().map(Into::into).collect();
        self.with_descriptor(
            IndexKind::RelComposite,
            IndexTarget::rel_type(rel_type),
            props,
        )
    }

    /// Appends a vector (HNSW) index over `(label, embedding-property)` (`rmp` task #669).
    pub fn with_label_vector(self, label: impl Into<String>, property: impl Into<String>) -> Self {
        self.with_descriptor(
            IndexKind::Vector,
            IndexTarget::label(label),
            vec![property.into()],
        )
    }

    /// Appends a relationship vector (HNSW) index over `(rel_type, embedding-property)`
    /// (`rmp` task #669).
    pub fn with_rel_vector(self, rel_type: impl Into<String>, property: impl Into<String>) -> Self {
        self.with_descriptor(
            IndexKind::RelVector,
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
    fn composite_full_eq_needs_every_key_available() {
        // `rmp` task #657: a composite (a, b) is returned only when BOTH keys are available equality
        // predicates; a strict prefix (only `a`) is not (that is `label_property`'s leading-prefix job).
        let catalog = IndexCatalog::builder()
            .with_label_composite("Person", ["a", "b"])
            .build();
        let l = label("Person");
        assert!(catalog.label_composite_full_eq(&l, &["a", "b"]).is_some());
        // Order of availability is irrelevant (it is a set membership test); extra keys are fine.
        assert!(
            catalog
                .label_composite_full_eq(&l, &["b", "a", "c"])
                .is_some()
        );
        // A strict prefix (only the leading key) does NOT match.
        assert!(catalog.label_composite_full_eq(&l, &["a"]).is_none());
        assert!(catalog.label_composite_full_eq(&l, &["b"]).is_none());
        // Wrong label / a single-property index never qualifies.
        assert!(
            catalog
                .label_composite_full_eq(&label("Other"), &["a", "b"])
                .is_none()
        );
        let single = IndexCatalog::builder()
            .with_label_property("Person", "a")
            .build();
        assert!(single.label_composite_full_eq(&l, &["a", "b"]).is_none());
    }

    #[test]
    fn rel_composite_full_eq_needs_every_key_available() {
        // `rmp` task #666: a composite relationship index (a, b) is returned only when BOTH keys are
        // available equality predicates; a strict prefix (only `a`) is not (that is `rel_property`'s
        // leading-prefix job).
        let catalog = IndexCatalog::builder()
            .with_rel_composite("KNOWS", ["a", "b"])
            .build();
        let t = rel_type("KNOWS");
        assert!(catalog.rel_composite_full_eq(&t, &["a", "b"]).is_some());
        assert!(
            catalog
                .rel_composite_full_eq(&t, &["b", "a", "c"])
                .is_some()
        );
        // A strict prefix (only the leading key) does NOT match the full-key resolver.
        assert!(catalog.rel_composite_full_eq(&t, &["a"]).is_none());
        assert!(catalog.rel_composite_full_eq(&t, &["b"]).is_none());
        // But the leading key IS servable as a single-property leading-prefix seek via `rel_property`.
        let leading = catalog.rel_property(&t, "a").unwrap();
        assert_eq!(leading.kind, IndexKind::RelComposite);
        // A non-leading key alone is not servable from a single-predicate lookup.
        assert!(catalog.rel_property(&t, "b").is_none());
        // Wrong type / a single-property rel index never qualifies for the full-key resolver.
        assert!(
            catalog
                .rel_composite_full_eq(&rel_type("LIKES"), &["a", "b"])
                .is_none()
        );
        let single = IndexCatalog::builder()
            .with_rel_property("KNOWS", "a")
            .build();
        assert!(single.rel_composite_full_eq(&t, &["a", "b"]).is_none());
    }

    #[test]
    fn rel_property_prefers_exact_over_composite_leading_key() {
        // A pure single-property rel index is preferred over a composite whose leading key matches,
        // mirroring the node `label_property` preference (`rmp` task #666).
        let catalog = IndexCatalog::builder()
            .with_rel_composite("KNOWS", ["since", "weight"])
            .with_rel_property("KNOWS", "since")
            .build();
        let chosen = catalog.rel_property(&rel_type("KNOWS"), "since").unwrap();
        assert_eq!(chosen.kind, IndexKind::RelProperty);
    }

    #[test]
    fn composite_full_eq_prefers_the_widest_key() {
        // When two composites qualify, the one with the most keys (most selective) is preferred.
        let catalog = IndexCatalog::builder()
            .with_label_composite("Person", ["a", "b"])
            .with_label_composite("Person", ["a", "b", "c"])
            .build();
        let chosen = catalog
            .label_composite_full_eq(&label("Person"), &["a", "b", "c"])
            .unwrap();
        assert_eq!(chosen.properties, vec!["a", "b", "c"]);
    }

    #[test]
    fn empty_catalog_finds_nothing() {
        let catalog = IndexCatalog::empty();
        assert!(catalog.token_lookup(&label("A")).is_none());
        assert!(catalog.label_property(&label("A"), "p").is_none());
        assert!(catalog.label_spatial(&label("A"), "loc").is_none());
        assert!(catalog.indexes().is_empty());
    }

    #[test]
    fn spatial_index_is_found_by_label_and_property() {
        let catalog = IndexCatalog::builder()
            .with_label_spatial("City", "loc")
            .build();
        let chosen = catalog.label_spatial(&label("City"), "loc").unwrap();
        assert_eq!(chosen.kind, IndexKind::Spatial);
        assert_eq!(chosen.kind.tag(), "spatial");
        // Not matched for a different label or property.
        assert!(catalog.label_spatial(&label("Other"), "loc").is_none());
        assert!(catalog.label_spatial(&label("City"), "name").is_none());
        // A spatial index is NOT returned by the (B-tree) property lookup.
        assert!(catalog.label_property(&label("City"), "loc").is_none());
    }

    #[test]
    fn text_index_is_found_by_label_and_property() {
        let catalog = IndexCatalog::builder()
            .with_label_text("Person", "name")
            .build();
        let chosen = catalog.label_text(&label("Person"), "name").unwrap();
        assert_eq!(chosen.kind, IndexKind::Text);
        assert_eq!(chosen.kind.tag(), "text");
        // Not matched for a different label or property.
        assert!(catalog.label_text(&label("Other"), "name").is_none());
        assert!(catalog.label_text(&label("Person"), "age").is_none());
        // A text index is NOT returned by the (B-tree) property lookup, and a range index is NOT
        // returned by the text lookup — they are distinct kinds serving distinct predicates.
        assert!(catalog.label_property(&label("Person"), "name").is_none());
        let range = IndexCatalog::builder()
            .with_label_property("Person", "name")
            .build();
        assert!(range.label_text(&label("Person"), "name").is_none());
    }
}
