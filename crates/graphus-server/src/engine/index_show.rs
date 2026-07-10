//! The unified `SHOW INDEXES` rendering + `YIELD`/`WHERE`/`RETURN` translation (`rmp` task #660),
//! shared by the Bolt ([`crate::engine::BoltEngineExecutor`]) and REST ([`crate::engine::
//! RestEngineAdapter`]) seams so both spell every column, `type` string and translation identically.
//! It is the index-side twin of [`crate::engine::constraint_show`] (`rmp` #653) and follows the same
//! mechanism.
//!
//! Graphus renders `SHOW INDEXES` as a Neo4j-5.x-faithful **unified** listing of *every* index kind —
//! node-property and relationship-property `RANGE`, composite `RANGE`, `FULLTEXT`, `POINT`, and the two
//! always-on token `LOOKUP` indexes Neo4j always lists. The engine's index-DDL handler produces the
//! **full column** row set ([`COLUMNS_FULL`] — the `YIELD *` shape) filtered by the requested
//! [`IndexTypeFilter`]; the seams then:
//!
//! * for a **bare** `SHOW INDEXES` (no tail) — project to the [`COLUMNS_DEFAULT`] columns (dropping
//!   `options` / `failureMessage` / `createStatement`, exactly as Neo4j's bare listing does) and stream
//!   them as a buffered admin result;
//! * for a `SHOW INDEXES YIELD …` / `… WHERE …` (a tail) — bind the full rows as the `$__indexes`
//!   parameter (a `List<Map>`) and **re-run a translated Cypher read query** over them
//!   ([`compose_query`]), streaming the result exactly as a normal query. The translation replaces the
//!   leading `YIELD` with `WITH` (Cypher's `WITH items [ORDER BY][SKIP][LIMIT][WHERE]` grammar matches
//!   `YIELD`'s) and appends a `RETURN *` when the tail carries no top-level `RETURN`; a terse `WHERE` is
//!   appended after the base `WITH` with an explicit `RETURN` of the default columns.
//!
//! The re-run goes through the normal read-query path (structurally read-only: `UNWIND` + `WITH` +
//! `RETURN`, no graph access), so it preserves the read-only nature; authorization is the schema-read
//! gate the seams already apply before rendering. [`finish`] centralises the whole decision so neither
//! seam duplicates it. The generic tail-translation string helpers (`quote_ident`, `strip_leading_kw`,
//! `contains_top_level_return`) are reused from [`crate::engine::constraint_show`] so the quote-aware
//! scanner is single-sourced.
//!
//! ## Derived columns
//!
//! * `id` — Graphus has no durable index id reachable from the listing APIs, so a **stable-within-a-
//!   listing** integer is assigned deterministically in build order: the two token `LOOKUP` indexes get
//!   the low ids `1` (node) and `2` (relationship, matching Neo4j), and every subsequent index gets the
//!   next id from `3`. Ids are assigned over the *unfiltered* order, so a given index keeps its id
//!   regardless of the [`IndexTypeFilter`]. Real drivers do not depend on the exact value.
//! * `state` — the **UPPER-CASE** Neo4j string `ONLINE` / `POPULATING`.
//! * `populationPercent` — `100.0` when `Online`, else `0.0` (Graphus does not surface a fractional
//!   build progress from the listing APIs; a `Populating` index reports `0.0`).
//! * `type` — one of `RANGE` / `TEXT` / `FULLTEXT` / `POINT` / `LOOKUP` (`TEXT` is a distinct native
//!   string index for `CONTAINS` / `ENDS WITH` / `STARTS WITH`, `rmp` task #662; Graphus has no
//!   `VECTOR` index kind yet — those arrive later).
//! * `indexProvider` — a Neo4j-like provider string per kind: `range-1.0`, `text-1.0`,
//!   `token-lookup-1.0`, `fulltext-1.0`, `point-1.0`.
//! * `owningConstraint` — for a **single-property** `RANGE` index that is a uniqueness / key
//!   constraint's backing index, the constraint's name (matched by covered `(entityType, token,
//!   property)`, `rmp` #653); `Null` otherwise (composite, fulltext, point, lookup).
//! * `options` — the empty map `{}` for most kinds; for a `FULLTEXT` index, the analyzer config
//!   `{ indexConfig: { \`fulltext.analyzer\`: "<name>" } }` (the Neo4j shape).
//! * `createStatement` — a Graphus-native, round-trippable `CREATE … INDEX` DDL that recreates the
//!   index ([`create_range_node`] / [`create_range_rel`] / [`create_fulltext`] / [`create_point`]);
//!   the two synthetic `LOOKUP` rows carry the Neo4j-standard `CREATE LOOKUP INDEX … ON EACH labels(n)`
//!   / `type(r)` strings (which are informational — Graphus maintains the token lookups implicitly and
//!   does not accept their DDL).
//! * `failureMessage` — the empty string (Graphus never surfaces a `FAILED` index state).
//! * `lastRead` / `readCount` — `Null` (index-usage statistics are untracked).

use graphus_core::{GraphusError, Value};
use graphus_cypher::{Analyzer, ConstraintInfo, FulltextEntity, FulltextIndexListing};
use graphus_storage::{ConstraintKind, IndexState};

use crate::admin::AdminResult;

use super::command::{IndexDdlReply, IndexTypeFilter, RunSummary};
use super::constraint_show::{contains_top_level_return, quote_ident, strip_leading_kw};

/// The full column set of a `SHOW INDEXES YIELD *` (`rmp` task #660), in order — the Neo4j-5.x column
/// names, exactly. The engine's index-DDL handler always renders this shape; a bare listing is
/// projected to [`COLUMNS_DEFAULT`].
pub(crate) const COLUMNS_FULL: [&str; 15] = [
    "id",
    "name",
    "state",
    "populationPercent",
    "type",
    "entityType",
    "labelsOrTypes",
    "properties",
    "indexProvider",
    "owningConstraint",
    "options",
    "failureMessage",
    "createStatement",
    "lastRead",
    "readCount",
];

/// The default columns of a bare `SHOW INDEXES` (drops the `YIELD *` extras `options` /
/// `failureMessage` / `createStatement`), in Neo4j's bare-listing order.
pub(crate) const COLUMNS_DEFAULT: [&str; 12] = [
    "id",
    "name",
    "state",
    "populationPercent",
    "type",
    "entityType",
    "labelsOrTypes",
    "properties",
    "indexProvider",
    "owningConstraint",
    "lastRead",
    "readCount",
];

/// The index into a [`COLUMNS_FULL`] row of each [`COLUMNS_DEFAULT`] column (`rmp` #660). Unlike the
/// constraint listing — whose default is a prefix of the full row — the index default drops three
/// *interior* columns (`options` / `failureMessage` / `createStatement` at positions 10..13), so the
/// projection selects positions explicitly. Kept consistent with [`COLUMNS_DEFAULT`] by
/// `default_columns_map_matches` (a unit test).
const DEFAULT_COL_INDICES: [usize; 12] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 13, 14];

/// The id of the always-on node-label token `LOOKUP` index (matches Neo4j's `1`).
const LOOKUP_NODE_ID: i64 = 1;
/// The id of the always-on relationship-type token `LOOKUP` index (matches Neo4j's `2`).
const LOOKUP_REL_ID: i64 = 2;
/// The first id assigned to a user-declared index (after the two token `LOOKUP` indexes).
const FIRST_USER_ID: i64 = 3;

/// The bound parameter name the translated read query pulls the index rows from.
const PARAM_NAME: &str = "__indexes";

/// The base of the translated read query: `UNWIND`s the `$__indexes` `List<Map>` and re-exposes each
/// column as a `WITH` variable so the `YIELD`/`WHERE`/`RETURN` tail can reference it by name.
const BASE_QUERY: &str = "UNWIND $__indexes AS __i \
     WITH __i.id AS id, __i.name AS name, __i.state AS state, \
     __i.populationPercent AS populationPercent, __i.type AS type, __i.entityType AS entityType, \
     __i.labelsOrTypes AS labelsOrTypes, __i.properties AS properties, \
     __i.indexProvider AS indexProvider, __i.owningConstraint AS owningConstraint, \
     __i.options AS options, __i.failureMessage AS failureMessage, \
     __i.createStatement AS createStatement, __i.lastRead AS lastRead, __i.readCount AS readCount";

/// The `RETURN` clause of a terse `SHOW INDEXES WHERE …` — the [`COLUMNS_DEFAULT`] columns in order.
const DEFAULT_RETURN: &str = "RETURN id, name, state, populationPercent, type, entityType, \
     labelsOrTypes, properties, indexProvider, owningConstraint, lastRead, readCount";

/// The coordinator-sourced inputs for a unified `SHOW INDEXES` render (`rmp` #660). The engine
/// populates each field from the target database's [`graphus_cypher::TxnCoordinator`] listing APIs;
/// keeping them here (rather than borrowing the coordinator) makes [`build_rows`] a pure, unit-testable
/// function with no engine dependency — exactly like [`crate::engine::constraint_show::build_rows`].
pub(crate) struct IndexSources {
    /// `(name, label, property, state)` per single-property node `RANGE` index.
    pub node_property: Vec<(String, String, String, IndexState)>,
    /// `(name, label, properties, state)` per composite (multi-property) node `RANGE` index.
    pub composite: Vec<(String, String, Vec<String>, IndexState)>,
    /// `(name, rel_type, property, state)` per relationship-property `RANGE` index.
    pub rel_property: Vec<(String, String, String, IndexState)>,
    /// `(name, entity, labels_or_types, properties, analyzer, state)` per `FULLTEXT` index — node or
    /// relationship, one or more covered labels/types (`rmp` task #663).
    pub fulltext: Vec<FulltextIndexListing>,
    /// `(name, label, property, state)` per `POINT` index.
    pub point: Vec<(String, String, String, IndexState)>,
    /// `(name, label, property, state)` per `TEXT` (trigram) index (`rmp` task #662).
    pub text: Vec<(String, String, String, IndexState)>,
    /// Every declared constraint, for the `owningConstraint` attribution.
    pub constraints: Vec<ConstraintInfo>,
}

/// A typed, pre-`Value` row (`rmp` #660). Building typed specs first lets [`build_rows`] filter on the
/// `type_str` field directly (rather than digging a string out of a `Value` row) and keeps
/// [`RowSpec::into_values`] the single place the [`COLUMNS_FULL`] order is spelled.
struct RowSpec {
    id: i64,
    name: String,
    state: IndexState,
    type_str: &'static str,
    entity_type: &'static str,
    labels_or_types: Vec<String>,
    properties: Vec<String>,
    index_provider: &'static str,
    owning_constraint: Value,
    options: Value,
    create_statement: String,
}

impl RowSpec {
    /// Renders the spec into a [`COLUMNS_FULL`]-ordered `Value` row.
    fn into_values(self) -> Vec<Value> {
        vec![
            Value::Integer(self.id),
            Value::String(self.name),
            Value::String(state_string(self.state).to_owned()),
            Value::Float(population_percent(self.state)),
            Value::String(self.type_str.to_owned()),
            Value::String(self.entity_type.to_owned()),
            Value::List(
                self.labels_or_types
                    .into_iter()
                    .map(Value::String)
                    .collect(),
            ),
            Value::List(self.properties.into_iter().map(Value::String).collect()),
            Value::String(self.index_provider.to_owned()),
            self.owning_constraint,
            self.options,
            // `failureMessage`: Graphus never surfaces a FAILED index, so an empty string.
            Value::String(String::new()),
            Value::String(self.create_statement),
            // `lastRead` / `readCount`: index-usage statistics are untracked.
            Value::Null,
            Value::Null,
        ]
    }
}

/// The UPPER-CASE Neo4j `state` string for an [`IndexState`] (`rmp` #660).
const fn state_string(state: IndexState) -> &'static str {
    match state {
        IndexState::Online => "ONLINE",
        IndexState::Populating => "POPULATING",
    }
}

/// The `populationPercent` for an [`IndexState`]: `100.0` when built, else `0.0` (`rmp` #660).
const fn population_percent(state: IndexState) -> f64 {
    match state {
        IndexState::Online => 100.0,
        IndexState::Populating => 0.0,
    }
}

/// The `owningConstraint` for a **single-property** `RANGE` index (`rmp` #653/#660): the name of the
/// uniqueness / key constraint whose backing index this is (matched by covered `(entityType, covering
/// token, single property)`), or [`Value::Null`]. Only a single-property index can be a constraint's
/// backing index, so a composite / fulltext / point / lookup row is always `Null`.
fn owning_constraint(
    constraints: &[ConstraintInfo],
    is_rel: bool,
    token: &str,
    property: &str,
) -> Value {
    constraints
        .iter()
        .find(|c| {
            let kind_ok = if is_rel {
                matches!(c.kind, ConstraintKind::RelUnique | ConstraintKind::RelKey)
            } else {
                matches!(c.kind, ConstraintKind::Unique | ConstraintKind::NodeKey)
            };
            kind_ok && c.label == token && c.properties.len() == 1 && c.properties[0] == property
        })
        .map_or(Value::Null, |c| Value::String(c.name.clone()))
}

/// The `options` map for a `FULLTEXT` index (`rmp` #660): the analyzer under Neo4j's
/// `indexConfig.`​`fulltext.analyzer`​`` key.
fn fulltext_options(analyzer: Analyzer) -> Value {
    Value::Map(vec![(
        "indexConfig".to_owned(),
        Value::Map(vec![(
            "fulltext.analyzer".to_owned(),
            Value::String(analyzer.name().to_owned()),
        )]),
    )])
}

/// A round-trippable `CREATE RANGE INDEX` DDL for a node-property index (`rmp` #660). Single or
/// composite (`properties.len() >= 1`); re-parsing it through [`crate::admin::parse_admin_statement`]
/// yields an equivalent `CreateNodePropertyIndex` (regression-tested).
#[must_use]
pub(crate) fn create_range_node(name: &str, label: &str, properties: &[String]) -> String {
    let props = properties
        .iter()
        .map(|p| format!("n.{}", quote_ident(p)))
        .collect::<Vec<_>>()
        .join(", ");
    format!(
        "CREATE RANGE INDEX {} FOR (n:{}) ON ({props})",
        quote_ident(name),
        quote_ident(label)
    )
}

/// A round-trippable `CREATE RANGE INDEX` DDL for a relationship-property index (`rmp` #660). Re-parsing
/// it yields an equivalent `CreateRelPropertyIndex`.
#[must_use]
pub(crate) fn create_range_rel(name: &str, rel_type: &str, property: &str) -> String {
    format!(
        "CREATE RANGE INDEX {} FOR ()-[r:{}]-() ON (r.{})",
        quote_ident(name),
        quote_ident(rel_type),
        quote_ident(property)
    )
}

/// A round-trippable `CREATE FULLTEXT INDEX` DDL (`rmp` #660, #663). Uses Graphus's native
/// `OPTIONS { analyzer: '<name>' }` clause (not Neo4j's `indexConfig` map) so it re-parses through the
/// admin grammar to an equivalent `CreateFulltextIndex`. Renders a node pattern `(v:A|B)` or an
/// undirected relationship pattern `()-[v:A|B]-()` per `entity`, with the variable bound to `n` (node)
/// / `r` (relationship) so the `ON EACH [<var>.<prop>]` references match.
#[must_use]
pub(crate) fn create_fulltext(
    name: &str,
    entity: FulltextEntity,
    labels_or_types: &[String],
    properties: &[String],
    analyzer: Analyzer,
) -> String {
    let var = if entity.is_relationship() { "r" } else { "n" };
    let tokens = labels_or_types
        .iter()
        .map(|t| quote_ident(t))
        .collect::<Vec<_>>()
        .join("|");
    let pattern = if entity.is_relationship() {
        format!("()-[{var}:{tokens}]-()")
    } else {
        format!("({var}:{tokens})")
    };
    let props = properties
        .iter()
        .map(|p| format!("{var}.{}", quote_ident(p)))
        .collect::<Vec<_>>()
        .join(", ");
    format!(
        "CREATE FULLTEXT INDEX {} FOR {pattern} ON EACH [{props}] OPTIONS {{ analyzer: '{}' }}",
        quote_ident(name),
        analyzer.name()
    )
}

/// A round-trippable `CREATE POINT INDEX` DDL (`rmp` #660). Re-parsing it yields an equivalent
/// `CreatePointIndex`.
#[must_use]
pub(crate) fn create_point(name: &str, label: &str, property: &str) -> String {
    format!(
        "CREATE POINT INDEX {} FOR (n:{}) ON (n.{})",
        quote_ident(name),
        quote_ident(label),
        quote_ident(property)
    )
}

/// A round-trippable `CREATE TEXT INDEX` DDL (`rmp` task #662). Re-parsing it yields an equivalent
/// `CreateTextIndex`.
#[must_use]
pub(crate) fn create_text(name: &str, label: &str, property: &str) -> String {
    format!(
        "CREATE TEXT INDEX {} FOR (n:{}) ON (n.{})",
        quote_ident(name),
        quote_ident(label),
        quote_ident(property)
    )
}

/// The Neo4j-standard `createStatement` for a synthetic token `LOOKUP` row (`rmp` #660). Informational
/// only — Graphus maintains node-label / relationship-type lookups implicitly and does not accept their
/// DDL, so this does **not** round-trip through the admin grammar.
fn create_lookup(name: &str, is_rel: bool) -> String {
    if is_rel {
        format!(
            "CREATE LOOKUP INDEX {} FOR ()-[r]-() ON EACH type(r)",
            quote_ident(name)
        )
    } else {
        format!(
            "CREATE LOOKUP INDEX {} FOR (n) ON EACH labels(n)",
            quote_ident(name)
        )
    }
}

/// The always-on token `LOOKUP` row for one entity dimension (`rmp` #660). Neo4j always lists both;
/// they cover no specific label/type, so `labelsOrTypes` / `properties` are empty lists and
/// `owningConstraint` is `Null`.
fn lookup_spec(id: i64, name: &str, is_rel: bool) -> RowSpec {
    RowSpec {
        id,
        name: name.to_owned(),
        state: IndexState::Online,
        type_str: "LOOKUP",
        entity_type: if is_rel { "RELATIONSHIP" } else { "NODE" },
        labels_or_types: Vec::new(),
        properties: Vec::new(),
        index_provider: "token-lookup-1.0",
        owning_constraint: Value::Null,
        options: Value::Map(Vec::new()),
        create_statement: create_lookup(name, is_rel),
    }
}

/// Builds the full [`COLUMNS_FULL`] rows for every index kind, filtered by `filter` (`rmp` #660).
///
/// Ids are assigned over the **unfiltered** build order (the two token `LOOKUP` indexes first, at ids
/// `1`/`2`, then each user index from `3`), so a given index keeps its id regardless of the filter; the
/// filter then retains only the rows whose `type` the filter selects. The input order within each kind
/// is preserved (the coordinator returns each kind ordered by name).
#[must_use]
pub(crate) fn build_rows(filter: IndexTypeFilter, sources: IndexSources) -> Vec<Vec<Value>> {
    let IndexSources {
        node_property,
        composite,
        rel_property,
        fulltext,
        point,
        text,
        constraints,
    } = sources;

    let mut specs: Vec<RowSpec> = Vec::new();

    // The two always-on token LOOKUP indexes Neo4j always lists (ids 1/2).
    specs.push(lookup_spec(
        LOOKUP_NODE_ID,
        "node_label_lookup_index",
        false,
    ));
    specs.push(lookup_spec(LOOKUP_REL_ID, "rel_type_lookup_index", true));

    let mut next_id = FIRST_USER_ID;
    let mut alloc = || {
        let id = next_id;
        next_id += 1;
        id
    };

    // Node-property RANGE (single). `owningConstraint` may name a backing uniqueness/key constraint.
    for (name, label, property, state) in node_property {
        let owning = owning_constraint(&constraints, false, &label, &property);
        let create = create_range_node(&name, &label, std::slice::from_ref(&property));
        specs.push(RowSpec {
            id: alloc(),
            name,
            state,
            type_str: "RANGE",
            entity_type: "NODE",
            labels_or_types: vec![label],
            properties: vec![property],
            index_provider: "range-1.0",
            owning_constraint: owning,
            options: Value::Map(Vec::new()),
            create_statement: create,
        });
    }
    // Composite node RANGE — a standalone composite is never a constraint's backing index.
    for (name, label, properties, state) in composite {
        let create = create_range_node(&name, &label, &properties);
        specs.push(RowSpec {
            id: alloc(),
            name,
            state,
            type_str: "RANGE",
            entity_type: "NODE",
            labels_or_types: vec![label],
            properties,
            index_provider: "range-1.0",
            owning_constraint: Value::Null,
            options: Value::Map(Vec::new()),
            create_statement: create,
        });
    }
    // Relationship-property RANGE.
    for (name, rel_type, property, state) in rel_property {
        let owning = owning_constraint(&constraints, true, &rel_type, &property);
        let create = create_range_rel(&name, &rel_type, &property);
        specs.push(RowSpec {
            id: alloc(),
            name,
            state,
            type_str: "RANGE",
            entity_type: "RELATIONSHIP",
            labels_or_types: vec![rel_type],
            properties: vec![property],
            index_provider: "range-1.0",
            owning_constraint: owning,
            options: Value::Map(Vec::new()),
            create_statement: create,
        });
    }
    // FULLTEXT — node or relationship (`rmp` #663); the analyzer goes into the `options` map.
    for (name, entity, labels_or_types, properties, analyzer, state) in fulltext {
        let create = create_fulltext(&name, entity, &labels_or_types, &properties, analyzer);
        specs.push(RowSpec {
            id: alloc(),
            name,
            state,
            type_str: "FULLTEXT",
            entity_type: if entity.is_relationship() {
                "RELATIONSHIP"
            } else {
                "NODE"
            },
            labels_or_types,
            properties,
            index_provider: "fulltext-1.0",
            owning_constraint: Value::Null,
            options: fulltext_options(analyzer),
            create_statement: create,
        });
    }
    // POINT.
    for (name, label, property, state) in point {
        let create = create_point(&name, &label, &property);
        specs.push(RowSpec {
            id: alloc(),
            name,
            state,
            type_str: "POINT",
            entity_type: "NODE",
            labels_or_types: vec![label],
            properties: vec![property],
            index_provider: "point-1.0",
            owning_constraint: Value::Null,
            options: Value::Map(Vec::new()),
            create_statement: create,
        });
    }
    // TEXT (trigram) — a distinct native string index (`rmp` task #662), never a constraint's backing
    // index.
    for (name, label, property, state) in text {
        let create = create_text(&name, &label, &property);
        specs.push(RowSpec {
            id: alloc(),
            name,
            state,
            type_str: "TEXT",
            entity_type: "NODE",
            labels_or_types: vec![label],
            properties: vec![property],
            index_provider: "text-1.0",
            owning_constraint: Value::Null,
            options: Value::Map(Vec::new()),
            create_statement: create,
        });
    }

    specs
        .into_iter()
        .filter(|s| filter.matches(s.type_str))
        .map(RowSpec::into_values)
        .collect()
}

/// Binds the full rows as the `$__indexes` `List<Map>` parameter (`rmp` #660): each row becomes a map
/// keyed by the [`COLUMNS_FULL`] names, so the translated query can read `__i.<column>`.
#[must_use]
fn build_indexes_param(rows: &[Vec<Value>]) -> Value {
    Value::List(
        rows.iter()
            .map(|row| {
                Value::Map(
                    COLUMNS_FULL
                        .iter()
                        .zip(row.iter())
                        .map(|(col, val)| ((*col).to_owned(), val.clone()))
                        .collect(),
                )
            })
            .collect(),
    )
}

/// Projects the full rows down to the [`COLUMNS_DEFAULT`] columns (`rmp` #660), selecting the
/// [`DEFAULT_COL_INDICES`] positions (unlike the constraint listing, the default is not a prefix).
#[must_use]
fn project_default(rows: Vec<Vec<Value>>) -> Vec<Vec<Value>> {
    rows.into_iter()
        .map(|row| {
            DEFAULT_COL_INDICES
                .iter()
                .map(|&i| row[i].clone())
                .collect()
        })
        .collect()
}

/// Composes the translated read query for a `SHOW INDEXES` tail (`rmp` #660), mirroring
/// [`crate::engine::constraint_show::compose_query`].
///
/// * A `YIELD …` tail becomes `<base> WITH <yield-body>` (Cypher's `WITH` shares `YIELD`'s
///   `items [ORDER BY][SKIP][LIMIT][WHERE]` grammar), with ` RETURN *` appended when the tail carries no
///   top-level `RETURN`.
/// * A terse `WHERE …` tail is appended after the base `WITH`, followed by an explicit `RETURN` of the
///   default columns.
#[must_use]
pub(crate) fn compose_query(tail: &str) -> String {
    let trimmed = tail.trim();
    if let Some(rest) = strip_leading_kw(trimmed, "YIELD") {
        let mut q = format!("{BASE_QUERY} WITH {rest}");
        if !contains_top_level_return(trimmed) {
            q.push_str(" RETURN *");
        }
        q
    } else {
        // The admin parser guarantees a captured tail begins with YIELD or WHERE, so this is the WHERE
        // arm: attach it to the base `WITH`, then RETURN the default columns.
        format!("{BASE_QUERY} {trimmed} {DEFAULT_RETURN}")
    }
}

/// Finishes a `SHOW INDEXES` after the engine rendered the full-column `reply` (`rmp` #660), shared by
/// both seams (their stream types differ, so the "run a read query" and "wrap an admin result" steps
/// are supplied as closures):
///
/// * `tail == Some(_)` — bind the rows as `$__indexes` and re-run the translated read query via
///   `run_read` (the seam's normal auto-commit read path), streaming its result.
/// * `tail == None` — project to the default columns and wrap them as a buffered admin result via
///   `as_admin`, carrying the read summary (query type `r`, no counters).
pub(crate) fn finish<S>(
    reply: IndexDdlReply,
    tail: Option<&str>,
    run_read: impl FnOnce(String, Vec<(String, Value)>) -> Result<S, GraphusError>,
    as_admin: impl FnOnce(AdminResult) -> S,
) -> Result<S, GraphusError> {
    match tail {
        Some(tail) => {
            let params = vec![(PARAM_NAME.to_owned(), build_indexes_param(&reply.rows))];
            run_read(compose_query(tail), params)
        }
        None => {
            let fields = COLUMNS_DEFAULT.iter().map(|c| (*c).to_owned()).collect();
            let rows = project_default(reply.rows);
            Ok(as_admin(AdminResult {
                fields,
                rows,
                summary: RunSummary {
                    query_type: Some("r".to_owned()),
                    stats: Vec::new(),
                },
            }))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::admin::{AdminParse, parse_admin_statement};
    use crate::engine::IndexCommand;

    fn empty_sources() -> IndexSources {
        IndexSources {
            node_property: Vec::new(),
            composite: Vec::new(),
            rel_property: Vec::new(),
            fulltext: Vec::new(),
            point: Vec::new(),
            text: Vec::new(),
            constraints: Vec::new(),
        }
    }

    fn analyzer(name: &str) -> Analyzer {
        Analyzer::from_name(name).expect("known analyzer")
    }

    /// The default projection map must stay consistent with the two column arrays.
    #[test]
    fn default_columns_map_matches() {
        assert_eq!(DEFAULT_COL_INDICES.len(), COLUMNS_DEFAULT.len());
        for (k, &i) in DEFAULT_COL_INDICES.iter().enumerate() {
            assert_eq!(
                COLUMNS_DEFAULT[k], COLUMNS_FULL[i],
                "default column {k} maps to the wrong full column"
            );
        }
        // The dropped columns are exactly options / failureMessage / createStatement.
        let kept: std::collections::HashSet<usize> = DEFAULT_COL_INDICES.iter().copied().collect();
        for (i, name) in COLUMNS_FULL.iter().enumerate() {
            let dropped = matches!(*name, "options" | "failureMessage" | "createStatement");
            assert_eq!(
                !kept.contains(&i),
                dropped,
                "column {name} kept/dropped wrong"
            );
        }
    }

    /// A bare (empty-schema) unified listing still carries the two always-on token LOOKUP rows, with
    /// the low ids 1/2 and the correct type/entityType, and the full column count.
    #[test]
    fn empty_schema_lists_the_two_lookup_indexes() {
        let rows = build_rows(IndexTypeFilter::All, empty_sources());
        assert_eq!(
            rows.len(),
            2,
            "the two token LOOKUP indexes are always listed"
        );
        for row in &rows {
            assert_eq!(row.len(), COLUMNS_FULL.len(), "full column set: {row:?}");
        }
        // Row 0 — node label lookup.
        assert_eq!(rows[0][0], Value::Integer(LOOKUP_NODE_ID));
        assert_eq!(
            rows[0][1],
            Value::String("node_label_lookup_index".to_owned())
        );
        assert_eq!(rows[0][2], Value::String("ONLINE".to_owned()), "UPPER-CASE");
        assert_eq!(rows[0][3], Value::Float(100.0), "populationPercent");
        assert_eq!(rows[0][4], Value::String("LOOKUP".to_owned()));
        assert_eq!(rows[0][5], Value::String("NODE".to_owned()));
        assert_eq!(rows[0][6], Value::List(Vec::new()), "no labelsOrTypes");
        assert_eq!(rows[0][7], Value::List(Vec::new()), "no properties");
        assert_eq!(rows[0][8], Value::String("token-lookup-1.0".to_owned()));
        assert_eq!(rows[0][9], Value::Null, "no owningConstraint");
        assert_eq!(rows[0][13], Value::Null, "lastRead untracked");
        assert_eq!(rows[0][14], Value::Null, "readCount untracked");
        // Row 1 — relationship type lookup.
        assert_eq!(rows[1][0], Value::Integer(LOOKUP_REL_ID));
        assert_eq!(
            rows[1][1],
            Value::String("rel_type_lookup_index".to_owned())
        );
        assert_eq!(rows[1][5], Value::String("RELATIONSHIP".to_owned()));
    }

    /// A unified listing spans every kind with the correct `type` / `entityType`, and a composite index
    /// renders `properties = [a, b]`. Ids are assigned over the whole order from 3.
    #[test]
    fn unified_listing_spans_every_kind() {
        let sources = IndexSources {
            node_property: vec![(
                "ix_person_name".to_owned(),
                "Person".to_owned(),
                "name".to_owned(),
                IndexState::Online,
            )],
            composite: vec![(
                "ix_person_first_last".to_owned(),
                "Person".to_owned(),
                vec!["first".to_owned(), "last".to_owned()],
                IndexState::Populating,
            )],
            rel_property: vec![(
                "rel_since".to_owned(),
                "KNOWS".to_owned(),
                "since".to_owned(),
                IndexState::Online,
            )],
            fulltext: vec![(
                "articles".to_owned(),
                FulltextEntity::Node,
                vec!["Article".to_owned()],
                vec!["title".to_owned(), "body".to_owned()],
                analyzer("standard"),
                IndexState::Online,
            )],
            point: vec![(
                "by_loc".to_owned(),
                "City".to_owned(),
                "loc".to_owned(),
                IndexState::Online,
            )],
            text: vec![(
                "tx_person_name".to_owned(),
                "Person".to_owned(),
                "name".to_owned(),
                IndexState::Online,
            )],
            constraints: Vec::new(),
        };
        let rows = build_rows(IndexTypeFilter::All, sources);
        // 2 lookups + 6 declared indexes.
        assert_eq!(rows.len(), 8);
        // Ids: lookups 1/2, then 3..9 in build order.
        let ids: Vec<i64> = rows
            .iter()
            .map(|r| match r[0] {
                Value::Integer(n) => n,
                _ => panic!("id must be an integer"),
            })
            .collect();
        assert_eq!(ids, vec![1, 2, 3, 4, 5, 6, 7, 8]);

        // The composite row: type RANGE, entityType NODE, properties = [first, last], Populating.
        let composite = rows
            .iter()
            .find(|r| r[1] == Value::String("ix_person_first_last".to_owned()))
            .expect("composite listed");
        assert_eq!(composite[4], Value::String("RANGE".to_owned()));
        assert_eq!(composite[5], Value::String("NODE".to_owned()));
        assert_eq!(
            composite[7],
            Value::List(vec![
                Value::String("first".to_owned()),
                Value::String("last".to_owned()),
            ]),
            "composite properties render as a multi-element list"
        );
        assert_eq!(composite[2], Value::String("POPULATING".to_owned()));
        assert_eq!(composite[3], Value::Float(0.0), "Populating → 0.0");

        // The relationship index carries entityType RELATIONSHIP.
        let rel = rows
            .iter()
            .find(|r| r[1] == Value::String("rel_since".to_owned()))
            .expect("rel index listed");
        assert_eq!(rel[5], Value::String("RELATIONSHIP".to_owned()));
        assert_eq!(rel[8], Value::String("range-1.0".to_owned()));

        // The fulltext index: type FULLTEXT, provider fulltext-1.0, analyzer in options.
        let ft = rows
            .iter()
            .find(|r| r[1] == Value::String("articles".to_owned()))
            .expect("fulltext listed");
        assert_eq!(ft[4], Value::String("FULLTEXT".to_owned()));
        assert_eq!(ft[8], Value::String("fulltext-1.0".to_owned()));
        assert_eq!(
            ft[10],
            Value::Map(vec![(
                "indexConfig".to_owned(),
                Value::Map(vec![(
                    "fulltext.analyzer".to_owned(),
                    Value::String("standard".to_owned()),
                )]),
            )]),
            "the analyzer surfaces in options.indexConfig"
        );

        // The point index: type POINT, provider point-1.0.
        let pt = rows
            .iter()
            .find(|r| r[1] == Value::String("by_loc".to_owned()))
            .expect("point listed");
        assert_eq!(pt[4], Value::String("POINT".to_owned()));
        assert_eq!(pt[8], Value::String("point-1.0".to_owned()));

        // The text index (`rmp` task #662): type TEXT (distinct from RANGE), entityType NODE, provider
        // text-1.0, single property, no owning constraint.
        let tx = rows
            .iter()
            .find(|r| r[1] == Value::String("tx_person_name".to_owned()))
            .expect("text listed");
        assert_eq!(tx[4], Value::String("TEXT".to_owned()));
        assert_eq!(tx[5], Value::String("NODE".to_owned()));
        assert_eq!(tx[8], Value::String("text-1.0".to_owned()));
        assert_eq!(
            tx[7],
            Value::List(vec![Value::String("name".to_owned())]),
            "text index covers a single property"
        );
        assert_eq!(tx[9], Value::Null, "a text index has no owning constraint");
    }

    /// Each filter selects only the matching `type`, and the ids stay stable (assigned over the full
    /// unfiltered order) regardless of the filter.
    #[test]
    fn filter_selects_by_type_and_ids_are_stable() {
        let sources = || IndexSources {
            node_property: vec![(
                "ix".to_owned(),
                "Person".to_owned(),
                "name".to_owned(),
                IndexState::Online,
            )],
            point: vec![(
                "by_loc".to_owned(),
                "City".to_owned(),
                "loc".to_owned(),
                IndexState::Online,
            )],
            text: vec![(
                "tx".to_owned(),
                "Person".to_owned(),
                "name".to_owned(),
                IndexState::Online,
            )],
            ..empty_sources()
        };
        // RANGE → only the node index (id 3); LOOKUP filtered out.
        let range = build_rows(IndexTypeFilter::Range, sources());
        assert_eq!(range.len(), 1);
        assert_eq!(range[0][1], Value::String("ix".to_owned()));
        assert_eq!(range[0][0], Value::Integer(3), "id stable across filters");
        // POINT → only the point index (id 4).
        let point = build_rows(IndexTypeFilter::Point, sources());
        assert_eq!(point.len(), 1);
        assert_eq!(point[0][0], Value::Integer(4), "id stable across filters");
        // TEXT → only the text index (id 5), a distinct kind (`rmp` task #662).
        let text = build_rows(IndexTypeFilter::Text, sources());
        assert_eq!(text.len(), 1);
        assert_eq!(text[0][1], Value::String("tx".to_owned()));
        assert_eq!(text[0][4], Value::String("TEXT".to_owned()));
        assert_eq!(text[0][0], Value::Integer(5), "id stable across filters");
        // LOOKUP → the two always-on lookups.
        let lookup = build_rows(IndexTypeFilter::Lookup, sources());
        assert_eq!(lookup.len(), 2);
        assert!(
            lookup
                .iter()
                .all(|r| r[4] == Value::String("LOOKUP".to_owned()))
        );
        // VECTOR → empty (Graphus has no distinct VECTOR index kind yet).
        assert!(build_rows(IndexTypeFilter::Vector, sources()).is_empty());
    }

    /// A single-property RANGE index that backs a uniqueness constraint names it in `owningConstraint`.
    #[test]
    fn owning_constraint_attributes_a_backing_index() {
        use graphus_cypher::ConstraintInfo;
        let sources = IndexSources {
            node_property: vec![(
                "uq_email".to_owned(),
                "Person".to_owned(),
                "email".to_owned(),
                IndexState::Online,
            )],
            constraints: vec![ConstraintInfo {
                name: "uq_email".to_owned(),
                label: "Person".to_owned(),
                properties: vec!["email".to_owned()],
                kind: ConstraintKind::Unique,
                type_descriptor: None,
            }],
            ..empty_sources()
        };
        let rows = build_rows(IndexTypeFilter::Range, sources);
        assert_eq!(rows.len(), 1);
        assert_eq!(
            rows[0][9],
            Value::String("uq_email".to_owned()),
            "the backing index names its owning constraint"
        );
    }

    /// Every reconstructed `createStatement` re-parses to an equivalent index-DDL command.
    #[test]
    fn create_statements_round_trip() {
        // Node RANGE single.
        assert_eq!(
            parse_index(&create_range_node(
                "ix",
                "Person",
                std::slice::from_ref(&"name".to_owned())
            )),
            IndexCommand::CreateNodePropertyIndex {
                name: Some("ix".to_owned()),
                label: "Person".to_owned(),
                properties: vec!["name".to_owned()],
                if_not_exists: false,
            }
        );
        // Node RANGE composite.
        assert_eq!(
            parse_index(&create_range_node(
                "ix2",
                "Person",
                &["first".to_owned(), "last".to_owned()]
            )),
            IndexCommand::CreateNodePropertyIndex {
                name: Some("ix2".to_owned()),
                label: "Person".to_owned(),
                properties: vec!["first".to_owned(), "last".to_owned()],
                if_not_exists: false,
            }
        );
        // Relationship RANGE.
        assert_eq!(
            parse_index(&create_range_rel("rel_since", "KNOWS", "since")),
            IndexCommand::CreateRelPropertyIndex {
                name: Some("rel_since".to_owned()),
                rel_type: "KNOWS".to_owned(),
                property: "since".to_owned(),
                if_not_exists: false,
            }
        );
        // FULLTEXT (node, single label).
        assert_eq!(
            parse_index(&create_fulltext(
                "articles",
                FulltextEntity::Node,
                &["Article".to_owned()],
                &["title".to_owned()],
                analyzer("standard")
            )),
            IndexCommand::CreateFulltextIndex {
                name: "articles".to_owned(),
                entity: FulltextEntity::Node,
                labels_or_types: vec!["Article".to_owned()],
                properties: vec!["title".to_owned()],
                analyzer: "standard".to_owned(),
                if_not_exists: false,
            }
        );
        // FULLTEXT (relationship, multi-type) — round-trips through the entity-aware create DDL
        // (`rmp` #663).
        assert_eq!(
            parse_index(&create_fulltext(
                "rel_ft",
                FulltextEntity::Relationship,
                &["KNOWS".to_owned(), "RATED".to_owned()],
                &["note".to_owned()],
                analyzer("standard")
            )),
            IndexCommand::CreateFulltextIndex {
                name: "rel_ft".to_owned(),
                entity: FulltextEntity::Relationship,
                labels_or_types: vec!["KNOWS".to_owned(), "RATED".to_owned()],
                properties: vec!["note".to_owned()],
                analyzer: "standard".to_owned(),
                if_not_exists: false,
            }
        );
        // POINT.
        assert_eq!(
            parse_index(&create_point("by_loc", "City", "loc")),
            IndexCommand::CreatePointIndex {
                name: "by_loc".to_owned(),
                label: "City".to_owned(),
                property: "loc".to_owned(),
                if_not_exists: false,
            }
        );
    }

    fn parse_index(stmt: &str) -> IndexCommand {
        match parse_admin_statement(stmt) {
            AdminParse::Index(cmd) => cmd,
            other => panic!("createStatement {stmt:?} must re-parse to index DDL, got {other:?}"),
        }
    }

    #[test]
    fn compose_query_yield_becomes_with_and_appends_return_star() {
        let q = compose_query("YIELD name, type");
        assert!(q.starts_with(BASE_QUERY), "keeps the UNWIND base: {q}");
        assert!(q.contains("WITH name, type"), "YIELD → WITH: {q}");
        assert!(
            q.trim_end().ends_with("RETURN *"),
            "appends RETURN * when no RETURN: {q}"
        );
    }

    #[test]
    fn compose_query_terse_where_returns_the_default_columns() {
        let q = compose_query("WHERE type = 'POINT'");
        assert!(q.contains("WHERE type = 'POINT'"), "{q}");
        assert!(
            q.trim_end().ends_with(DEFAULT_RETURN),
            "terse WHERE returns the default columns: {q}"
        );
    }

    #[test]
    fn project_default_drops_the_yield_star_extras() {
        let full = build_rows(IndexTypeFilter::All, empty_sources());
        let default = project_default(full);
        assert_eq!(default[0].len(), COLUMNS_DEFAULT.len());
        // id, name, state, populationPercent, type, entityType, labelsOrTypes, properties,
        // indexProvider, owningConstraint, lastRead, readCount — the createStatement is gone.
        assert_eq!(default[0][0], Value::Integer(LOOKUP_NODE_ID));
        assert_eq!(
            default[0][1],
            Value::String("node_label_lookup_index".to_owned())
        );
        assert_eq!(
            default[0][10],
            Value::Null,
            "lastRead is the 11th default column"
        );
        assert_eq!(
            default[0][11],
            Value::Null,
            "readCount is the 12th default column"
        );
    }
}
