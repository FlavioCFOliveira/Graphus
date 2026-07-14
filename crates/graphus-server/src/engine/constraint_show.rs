//! The `SHOW CONSTRAINTS` rendering + `YIELD`/`WHERE`/`RETURN` translation (`rmp` task #653), shared by
//! the Bolt ([`crate::engine::BoltEngineExecutor`]) and REST ([`crate::engine::RestEngineAdapter`])
//! seams so both spell every column, `type` string and translation identically.
//!
//! Graphus renders `SHOW CONSTRAINTS` as a Neo4j-5.x-faithful listing. The engine's constraint-DDL
//! handler produces the **full 10-column** row set ([`COLUMNS_FULL`] — the `YIELD *` shape) filtered by
//! the requested [`ConstraintTypeFilter`]; the seams then:
//!
//! * for a **bare** `SHOW CONSTRAINTS` (no tail) — project to the 8 default columns ([`COLUMNS_DEFAULT`],
//!   dropping `options` + `createStatement`) and stream them as a buffered admin result;
//! * for a `SHOW CONSTRAINTS YIELD …` / `… WHERE …` (a tail) — bind the 10-column rows as the
//!   `$__constraints` parameter (a `List<Map>`) and **re-run a translated Cypher read query** over them
//!   ([`compose_query`]), streaming the result exactly as a normal query. The translation replaces the
//!   leading `YIELD` with `WITH` (Cypher's `WITH items [ORDER BY][SKIP][LIMIT][WHERE]` grammar matches
//!   `YIELD`'s) and appends a `RETURN *` when the tail carries no top-level `RETURN`; a terse `WHERE` is
//!   appended after the base `WITH` with an explicit `RETURN` of the 8 default columns.
//!
//! The re-run goes through the normal read-query path (structurally read-only: `UNWIND` + `WITH` +
//! `RETURN`, no graph access), so it preserves the read-only nature; authorization is the schema-read
//! gate the seams already apply before rendering. [`finish`] centralises the whole decision so neither
//! seam duplicates it — each supplies just its own "run a read query" and "wrap an admin result"
//! closures (their stream types differ).
//!
//! ## Derived columns
//!
//! * `id` — Graphus has **no durable constraint id**, so [`stable_id`] derives a deterministic
//!   non-negative `i64` from the (durable) constraint name via an FNV-1a-64 hash masked to 63 bits. It
//!   is therefore stable across restarts.
//! * `ownedIndex` — for the uniqueness / key kinds (which are enforced by a backing index) this is the
//!   constraint's own name; `Null` for existence and property-type (which own no index).
//! * `propertyType` — for the property-type kinds, the canonical type string
//!   ([`graphus_cypher::constraint::type_descriptor_name`]); `Null` otherwise.
//! * `options` — the empty map `{}` (Graphus has a single built-in index provider, so there are no
//!   provider/config options to surface).
//! * `createStatement` — a round-trippable `CREATE CONSTRAINT` DDL that recreates the constraint
//!   ([`create_statement`]); re-parsing it through the admin grammar yields an equivalent
//!   `CreateConstraint` (regression-tested).

use graphus_core::{GraphusError, Value};
use graphus_cypher::ConstraintInfo;
use graphus_storage::ConstraintKind;

use crate::admin::AdminResult;

use super::command::{ConstraintTypeFilter, IndexDdlReply, RunSummary};

/// The full 10-column set of a `SHOW CONSTRAINTS YIELD *` (`rmp` task #653), in order. The engine's
/// constraint-DDL handler always renders this shape; a bare listing is projected to [`COLUMNS_DEFAULT`].
pub(crate) const COLUMNS_FULL: [&str; 10] = [
    "id",
    "name",
    "type",
    "entityType",
    "labelsOrTypes",
    "properties",
    "ownedIndex",
    "propertyType",
    "options",
    "createStatement",
];

/// The 8 default columns of a bare `SHOW CONSTRAINTS` (drops `options` + `createStatement`), the first
/// eight of [`COLUMNS_FULL`].
pub(crate) const COLUMNS_DEFAULT: [&str; 8] = [
    "id",
    "name",
    "type",
    "entityType",
    "labelsOrTypes",
    "properties",
    "ownedIndex",
    "propertyType",
];

/// The bound parameter name the translated read query pulls the constraint rows from.
const PARAM_NAME: &str = "__constraints";

/// The base of the translated read query: `UNWIND`s the `$__constraints` `List<Map>` and re-exposes
/// each column as a `WITH` variable so the `YIELD`/`WHERE`/`RETURN` tail can reference it by name.
const BASE_QUERY: &str = "UNWIND $__constraints AS __c \
     WITH __c.id AS id, __c.name AS name, __c.type AS type, __c.entityType AS entityType, \
     __c.labelsOrTypes AS labelsOrTypes, __c.properties AS properties, __c.ownedIndex AS ownedIndex, \
     __c.propertyType AS propertyType, __c.options AS options, __c.createStatement AS createStatement";

/// A STABLE positive per-constraint id derived from the constraint's name (`rmp` task #653). Graphus
/// has no durable constraint id, so this FNV-1a-64 hash of the (durable) name, masked to a non-negative
/// `i64` (top bit cleared), gives a deterministic id that survives restarts. Distinct names collide
/// only on a 63-bit hash collision (negligible for the small constraint counts a schema holds).
#[must_use]
pub(crate) fn stable_id(name: &str) -> i64 {
    // FNV-1a 64-bit — a small, stable, dependency-free hash (mirrors `admin::auto_constraint_name`).
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for &b in name.as_bytes() {
        h ^= u64::from(b);
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    // Clear the sign bit so the id is always a non-negative `i64` (a Cypher/PackStream integer).
    (h & 0x7fff_ffff_ffff_ffff) as i64
}

/// The Neo4j-5.x `type` string for a constraint kind (`rmp` task #653) — exactly one of the eight
/// canonical names. Distinct from the durable `ConstraintKind` discriminants; the property type (for
/// the `*_PROPERTY_TYPE` kinds) is carried separately in the `propertyType` column, not folded here.
#[must_use]
pub(crate) fn constraint_type_string(kind: ConstraintKind) -> &'static str {
    match kind {
        ConstraintKind::Unique => "NODE_PROPERTY_UNIQUENESS",
        ConstraintKind::RelUnique => "RELATIONSHIP_PROPERTY_UNIQUENESS",
        ConstraintKind::Existence => "NODE_PROPERTY_EXISTENCE",
        ConstraintKind::RelExistence => "RELATIONSHIP_PROPERTY_EXISTENCE",
        ConstraintKind::NodeKey => "NODE_KEY",
        ConstraintKind::RelKey => "RELATIONSHIP_KEY",
        ConstraintKind::PropertyType => "NODE_PROPERTY_TYPE",
        ConstraintKind::RelPropertyType => "RELATIONSHIP_PROPERTY_TYPE",
    }
}

/// Whether a constraint of `kind` owns a backing index — the uniqueness / key kinds, whose `ownedIndex`
/// column is the constraint's own name. Existence and property-type own no index (`ownedIndex` `Null`).
#[must_use]
pub(crate) fn owns_backing_index(kind: ConstraintKind) -> bool {
    matches!(
        kind,
        ConstraintKind::Unique
            | ConstraintKind::RelUnique
            | ConstraintKind::NodeKey
            | ConstraintKind::RelKey
    )
}

/// Backtick-quotes an identifier for a round-trippable `createStatement`, escaping an embedded backtick
/// by doubling it (the Cypher rule) so a driver / Neo4j re-parses it faithfully.
///
/// Note: the doubled-backtick escape is the correct Cypher rendering for external consumers, but
/// Graphus's own admin lexer does not un-escape it, so an identifier containing a backtick does not
/// round-trip back through [`crate::admin::parse_admin_statement`] (identifiers with backticks do not
/// occur in practice). Identifiers with spaces or keyword collisions round-trip normally.
///
/// Shared with [`crate::engine::index_show`] (`rmp` #660) so the backtick-quoting is single-sourced.
pub(crate) fn quote_ident(id: &str) -> String {
    format!("`{}`", id.replace('`', "``"))
}

/// A round-trippable `CREATE CONSTRAINT` DDL string that recreates `info` (`rmp` task #653). Re-parsing
/// it through [`crate::admin::parse_admin_statement`] yields an equivalent `CreateConstraint`
/// (regression-tested). The name, label/type and every property are backtick-quoted; the variable stays
/// bare (`n` for a node, `r` for a relationship), and the `REQUIRE` list is always parenthesised.
#[must_use]
pub(crate) fn create_statement(info: &ConstraintInfo) -> String {
    let is_rel = info.kind.is_relationship();
    let var = if is_rel { "r" } else { "n" };
    let for_clause = if is_rel {
        format!("FOR ()-[{var}:{}]-()", quote_ident(&info.label))
    } else {
        format!("FOR ({var}:{})", quote_ident(&info.label))
    };
    let props = info
        .properties
        .iter()
        .map(|p| format!("{var}.{}", quote_ident(p)))
        .collect::<Vec<_>>()
        .join(", ");
    let is_clause = match info.kind {
        ConstraintKind::Unique | ConstraintKind::RelUnique => "IS UNIQUE".to_owned(),
        ConstraintKind::Existence | ConstraintKind::RelExistence => "IS NOT NULL".to_owned(),
        ConstraintKind::NodeKey => "IS NODE KEY".to_owned(),
        ConstraintKind::RelKey => "IS RELATIONSHIP KEY".to_owned(),
        ConstraintKind::PropertyType | ConstraintKind::RelPropertyType => {
            // A property-type constraint always carries a descriptor; `ANY` is a defensive placeholder
            // only (never reached for a well-formed catalog entry).
            let ty = info.type_descriptor.as_ref().map_or_else(
                || "ANY".to_owned(),
                graphus_cypher::constraint::type_descriptor_name,
            );
            format!("IS :: {ty}")
        }
    };
    format!(
        "CREATE CONSTRAINT {} {for_clause} REQUIRE ({props}) {is_clause}",
        quote_ident(&info.name)
    )
}

/// The full 10-column row for one constraint (`rmp` task #653), in [`COLUMNS_FULL`] order.
fn build_row(info: &ConstraintInfo) -> Vec<Value> {
    let entity_type = if info.kind.is_relationship() {
        "RELATIONSHIP"
    } else {
        "NODE"
    };
    let owned_index = if owns_backing_index(info.kind) {
        Value::String(info.name.clone())
    } else {
        Value::Null
    };
    let property_type = match &info.type_descriptor {
        Some(d) => Value::String(graphus_cypher::constraint::type_descriptor_name(d)),
        None => Value::Null,
    };
    vec![
        Value::Integer(stable_id(&info.name)),
        Value::String(info.name.clone()),
        Value::String(constraint_type_string(info.kind).to_owned()),
        Value::String(entity_type.to_owned()),
        Value::List(vec![Value::String(info.label.clone())]),
        Value::List(info.properties.iter().cloned().map(Value::String).collect()),
        owned_index,
        property_type,
        // `options`: Graphus has a single built-in index provider, so no provider/config options.
        Value::Map(Vec::new()),
        Value::String(create_statement(info)),
    ]
}

/// Builds the full 10-column rows for the constraints matching `filter` (`rmp` task #653), preserving
/// the input order (the coordinator returns constraints ordered by name).
#[must_use]
pub(crate) fn build_rows(
    constraints: Vec<ConstraintInfo>,
    filter: ConstraintTypeFilter,
) -> Vec<Vec<Value>> {
    constraints
        .into_iter()
        .filter(|info| filter.matches(info.kind))
        .map(|info| build_row(&info))
        .collect()
}

/// Binds the 10-column rows as the `$__constraints` `List<Map>` parameter (`rmp` task #653): each row
/// becomes a map keyed by the [`COLUMNS_FULL`] names, so the translated query can read `__c.<column>`.
#[must_use]
fn build_constraints_param(rows: &[Vec<Value>]) -> Value {
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

/// Projects the full 10-column rows down to the 8 default columns (drops `options` + `createStatement`),
/// which are the leading eight of [`COLUMNS_FULL`].
#[must_use]
fn project_default(rows: Vec<Vec<Value>>) -> Vec<Vec<Value>> {
    rows.into_iter()
        .map(|mut row| {
            row.truncate(COLUMNS_DEFAULT.len());
            row
        })
        .collect()
}

/// Composes the translated read query for a `SHOW CONSTRAINTS` tail (`rmp` task #653).
///
/// * A `YIELD …` tail becomes `<base> WITH <yield-body>` (Cypher's `WITH` shares `YIELD`'s
///   `items [ORDER BY][SKIP][LIMIT][WHERE]` grammar), with ` RETURN *` appended when the tail carries no
///   top-level `RETURN`.
/// * A terse `WHERE …` tail is appended after the base `WITH`, followed by an explicit `RETURN` of the 8
///   default columns.
///
/// # Limitation
///
/// The "carries a top-level `RETURN`" test is a string-literal-aware word scan (it skips single/double/
/// backtick-quoted spans but does not otherwise parse the tail), so a `RETURN` appearing as an
/// unquoted identifier fragment could be mis-detected — an accepted, documented approximation.
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
        // A terse `WHERE …` (the admin parser guarantees the tail begins with YIELD or WHERE, so this is
        // the WHERE arm): attach it to the base `WITH`, then RETURN the 8 default columns.
        format!(
            "{BASE_QUERY} {trimmed} RETURN id, name, type, entityType, labelsOrTypes, properties, \
             ownedIndex, propertyType"
        )
    }
}

/// Strips a leading keyword `kw` (ASCII case-insensitive) from `s`, requiring a word boundary after it,
/// and returns the trimmed remainder. `None` when `s` does not begin with `kw` at a word boundary.
///
/// Shared with [`crate::engine::index_show`] (`rmp` #660).
pub(crate) fn strip_leading_kw<'a>(s: &'a str, kw: &str) -> Option<&'a str> {
    let s = s.trim_start();
    let head = s.get(..kw.len())?;
    if !head.eq_ignore_ascii_case(kw) {
        return None;
    }
    let rest = &s[kw.len()..];
    match rest.chars().next() {
        None => Some(""),
        Some(c) if !c.is_alphanumeric() && c != '_' => Some(rest.trim_start()),
        Some(_) => None,
    }
}

/// Whether `s` contains the word `RETURN` (case-insensitive) at a word boundary, outside any
/// single/double/backtick-quoted span. A `\`-escape inside a quoted span skips the next byte.
///
/// Shared with [`crate::engine::index_show`] (`rmp` #660) so the quote-aware scanner is single-sourced.
pub(crate) fn contains_top_level_return(s: &str) -> bool {
    let bytes = s.as_bytes();
    let n = bytes.len();
    let mut i = 0;
    let mut quote: Option<u8> = None;
    while i < n {
        let b = bytes[i];
        if let Some(q) = quote {
            if b == b'\\' {
                i += 2;
                continue;
            }
            if b == q {
                quote = None;
            }
            i += 1;
            continue;
        }
        if b == b'\'' || b == b'"' || b == b'`' {
            quote = Some(b);
            i += 1;
            continue;
        }
        if i + 6 <= n && bytes[i..i + 6].eq_ignore_ascii_case(b"RETURN") {
            let before_ok = i == 0 || !is_word_byte(bytes[i - 1]);
            let after_ok = i + 6 == n || !is_word_byte(bytes[i + 6]);
            if before_ok && after_ok {
                return true;
            }
        }
        i += 1;
    }
    false
}

/// Whether `b` is an ASCII identifier byte (for the word-boundary test in [`contains_top_level_return`]).
fn is_word_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

/// Finishes a `SHOW CONSTRAINTS` after the engine rendered the full 10-column `reply` (`rmp` task #653),
/// shared by both seams (their stream types differ, so the "run a read query" and "wrap an admin result"
/// steps are supplied as closures):
///
/// * `tail == Some(_)` — bind the rows as `$__constraints` and re-run the translated read query via
///   `run_read` (the seam's normal auto-commit read path), streaming its result.
/// * `tail == None` — project to the 8 default columns and wrap them as a buffered admin result via
///   `as_admin`, carrying the read summary (query type `r`, no counters).
pub(crate) fn finish<S>(
    reply: IndexDdlReply,
    tail: Option<&str>,
    run_read: impl FnOnce(String, Vec<(String, Value)>) -> Result<S, GraphusError>,
    as_admin: impl FnOnce(AdminResult) -> S,
) -> Result<S, GraphusError> {
    match tail {
        Some(tail) => {
            let params = vec![(PARAM_NAME.to_owned(), build_constraints_param(&reply.rows))];
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
                    plan: None,
                },
            }))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::admin::{AdminParse, parse_admin_statement};
    use crate::engine::{
        ConstraintCommand, ConstraintCreateKind, ConstraintEntity, CreateConstraint,
    };
    use graphus_storage::ConstraintTypeDescriptor as T;

    fn info(
        name: &str,
        label: &str,
        properties: &[&str],
        kind: ConstraintKind,
        type_descriptor: Option<T>,
    ) -> ConstraintInfo {
        ConstraintInfo {
            name: name.to_owned(),
            label: label.to_owned(),
            properties: properties.iter().map(|p| (*p).to_owned()).collect(),
            kind,
            type_descriptor,
        }
    }

    #[test]
    fn stable_id_is_deterministic_and_non_negative() {
        assert_eq!(
            stable_id("uq_email"),
            stable_id("uq_email"),
            "deterministic"
        );
        assert_ne!(stable_id("a"), stable_id("b"), "distinct names differ");
        for name in ["", "a", "constraint_00ff", "☃", "with a space"] {
            assert!(stable_id(name) >= 0, "id must be non-negative for {name:?}");
        }
    }

    #[test]
    fn type_strings_are_the_eight_canonical_neo4j_names() {
        use ConstraintKind as K;
        assert_eq!(
            constraint_type_string(K::Unique),
            "NODE_PROPERTY_UNIQUENESS"
        );
        assert_eq!(
            constraint_type_string(K::RelUnique),
            "RELATIONSHIP_PROPERTY_UNIQUENESS"
        );
        assert_eq!(
            constraint_type_string(K::Existence),
            "NODE_PROPERTY_EXISTENCE"
        );
        assert_eq!(
            constraint_type_string(K::RelExistence),
            "RELATIONSHIP_PROPERTY_EXISTENCE"
        );
        assert_eq!(constraint_type_string(K::NodeKey), "NODE_KEY");
        assert_eq!(constraint_type_string(K::RelKey), "RELATIONSHIP_KEY");
        assert_eq!(
            constraint_type_string(K::PropertyType),
            "NODE_PROPERTY_TYPE"
        );
        assert_eq!(
            constraint_type_string(K::RelPropertyType),
            "RELATIONSHIP_PROPERTY_TYPE"
        );
    }

    #[test]
    fn full_row_shape_and_derived_columns() {
        // A node uniqueness constraint: ownedIndex = its name, propertyType = Null, options = {}.
        let rows = build_rows(
            vec![info(
                "uq_email",
                "Person",
                &["email"],
                ConstraintKind::Unique,
                None,
            )],
            ConstraintTypeFilter::All,
        );
        assert_eq!(rows.len(), 1);
        let row = &rows[0];
        assert_eq!(row.len(), COLUMNS_FULL.len());
        assert_eq!(row[0], Value::Integer(stable_id("uq_email")));
        assert_eq!(row[1], Value::String("uq_email".to_owned()));
        assert_eq!(row[2], Value::String("NODE_PROPERTY_UNIQUENESS".to_owned()));
        assert_eq!(row[3], Value::String("NODE".to_owned()));
        assert_eq!(
            row[4],
            Value::List(vec![Value::String("Person".to_owned())])
        );
        assert_eq!(row[5], Value::List(vec![Value::String("email".to_owned())]));
        assert_eq!(row[6], Value::String("uq_email".to_owned()), "ownedIndex");
        assert_eq!(row[7], Value::Null, "propertyType");
        assert_eq!(row[8], Value::Map(Vec::new()), "options");

        // An existence constraint owns no index (ownedIndex Null); a property-type constraint carries a
        // propertyType and owns no index.
        let ex = build_rows(
            vec![info(
                "ex_name",
                "Person",
                &["name"],
                ConstraintKind::Existence,
                None,
            )],
            ConstraintTypeFilter::All,
        );
        assert_eq!(ex[0][6], Value::Null, "existence owns no index");
        assert_eq!(ex[0][7], Value::Null);

        let ty = build_rows(
            vec![info(
                "ty_age",
                "Person",
                &["age"],
                ConstraintKind::PropertyType,
                Some(T::Integer),
            )],
            ConstraintTypeFilter::All,
        );
        assert_eq!(ty[0][2], Value::String("NODE_PROPERTY_TYPE".to_owned()));
        assert_eq!(ty[0][6], Value::Null, "property-type owns no index");
        assert_eq!(
            ty[0][7],
            Value::String("INTEGER".to_owned()),
            "propertyType"
        );
    }

    #[test]
    fn filter_selects_only_matching_kinds() {
        let all = vec![
            info("u", "Person", &["email"], ConstraintKind::Unique, None),
            info("ru", "RATED", &["ref"], ConstraintKind::RelUnique, None),
            info("k", "Person", &["a", "b"], ConstraintKind::NodeKey, None),
            info("rk", "RATED", &["a", "b"], ConstraintKind::RelKey, None),
        ];
        // KEY selects node + rel key only.
        let keys = build_rows(all.clone(), ConstraintTypeFilter::Key);
        assert_eq!(keys.len(), 2);
        assert!(
            keys.iter()
                .all(|r| r[2] == Value::String("NODE_KEY".to_owned())
                    || r[2] == Value::String("RELATIONSHIP_KEY".to_owned()))
        );
        // NODE KEY selects only the node key.
        let node_keys = build_rows(all.clone(), ConstraintTypeFilter::NodeKey);
        assert_eq!(node_keys.len(), 1);
        assert_eq!(node_keys[0][1], Value::String("k".to_owned()));
        // UNIQUENESS selects node + rel uniqueness.
        assert_eq!(build_rows(all, ConstraintTypeFilter::Unique).len(), 2);
    }

    #[test]
    fn project_default_drops_options_and_create_statement() {
        let full = build_rows(
            vec![info(
                "uq",
                "Person",
                &["email"],
                ConstraintKind::Unique,
                None,
            )],
            ConstraintTypeFilter::All,
        );
        let default = project_default(full.clone());
        assert_eq!(default[0].len(), COLUMNS_DEFAULT.len());
        // The kept columns are identical to the leading eight of the full row.
        assert_eq!(default[0], full[0][..COLUMNS_DEFAULT.len()].to_vec());
    }

    /// Maps a parsed `CreateConstraint` back to the durable `(ConstraintKind, descriptor)` pair so a
    /// round-trip can be asserted against the original catalog entry.
    fn storage_kind(create: &CreateConstraint) -> (ConstraintKind, Option<T>) {
        let is_rel = create.entity.is_relationship();
        match (&create.kind, is_rel) {
            (ConstraintCreateKind::Unique, false) => (ConstraintKind::Unique, None),
            (ConstraintCreateKind::Existence, false) => (ConstraintKind::Existence, None),
            (ConstraintCreateKind::Key, false) => (ConstraintKind::NodeKey, None),
            (ConstraintCreateKind::PropertyType { declared_type }, false) => {
                (ConstraintKind::PropertyType, Some(declared_type.clone()))
            }
            (ConstraintCreateKind::Unique, true) => (ConstraintKind::RelUnique, None),
            (ConstraintCreateKind::Existence, true) => (ConstraintKind::RelExistence, None),
            (ConstraintCreateKind::Key, true) => (ConstraintKind::RelKey, None),
            (ConstraintCreateKind::PropertyType { declared_type }, true) => {
                (ConstraintKind::RelPropertyType, Some(declared_type.clone()))
            }
        }
    }

    fn assert_round_trips(info: &ConstraintInfo) {
        let stmt = create_statement(info);
        let parsed = match parse_admin_statement(&stmt) {
            AdminParse::Constraint(ConstraintCommand::Create(c)) => c,
            other => panic!(
                "createStatement {stmt:?} must re-parse to a CREATE CONSTRAINT, got {other:?}"
            ),
        };
        assert_eq!(parsed.name, info.name, "name round-trips: {stmt:?}");
        let covering = match &parsed.entity {
            ConstraintEntity::Node { label } => label.clone(),
            ConstraintEntity::Relationship { rel_type } => rel_type.clone(),
        };
        assert_eq!(covering, info.label, "covering token round-trips: {stmt:?}");
        assert_eq!(
            parsed.properties, info.properties,
            "properties round-trip: {stmt:?}"
        );
        assert_eq!(
            parsed.entity.is_relationship(),
            info.kind.is_relationship(),
            "entity dimension round-trips: {stmt:?}"
        );
        let (kind, descriptor) = storage_kind(&parsed);
        assert_eq!(kind, info.kind, "kind round-trips: {stmt:?}");
        assert_eq!(
            descriptor, info.type_descriptor,
            "type descriptor round-trips: {stmt:?}"
        );
        assert!(
            !parsed.if_not_exists && !parsed.or_replace,
            "no idempotency flags: {stmt:?}"
        );
    }

    #[test]
    fn create_statement_round_trips_for_every_kind() {
        // Node: uniqueness, existence, composite key, property type (incl. a nested LIST and a union).
        assert_round_trips(&info(
            "uq_email",
            "Person",
            &["email"],
            ConstraintKind::Unique,
            None,
        ));
        assert_round_trips(&info(
            "ex_name",
            "Person",
            &["name"],
            ConstraintKind::Existence,
            None,
        ));
        assert_round_trips(&info(
            "nk",
            "Person",
            &["first", "last"],
            ConstraintKind::NodeKey,
            None,
        ));
        assert_round_trips(&info(
            "ty_age",
            "Person",
            &["age"],
            ConstraintKind::PropertyType,
            Some(T::Integer),
        ));
        assert_round_trips(&info(
            "ty_tags",
            "Person",
            &["tags"],
            ConstraintKind::PropertyType,
            Some(T::List(Box::new(T::String))),
        ));
        assert_round_trips(&info(
            "ty_union",
            "Person",
            &["v"],
            ConstraintKind::PropertyType,
            Some(T::Union(vec![T::Integer, T::String])),
        ));
        // Relationship: uniqueness, existence, composite key, property type.
        assert_round_trips(&info(
            "ru",
            "RATED",
            &["ref"],
            ConstraintKind::RelUnique,
            None,
        ));
        assert_round_trips(&info(
            "re",
            "RATED",
            &["at"],
            ConstraintKind::RelExistence,
            None,
        ));
        assert_round_trips(&info(
            "rk",
            "RATED",
            &["a", "b"],
            ConstraintKind::RelKey,
            None,
        ));
        assert_round_trips(&info(
            "rt",
            "RATED",
            &["score"],
            ConstraintKind::RelPropertyType,
            Some(T::Float),
        ));
        // Identifiers needing backtick-quoting: a space, and identifiers colliding with keywords
        // (`KEY` / `FOR` / `IS`) — the backtick-quoting keeps them distinct from the grammar keywords.
        // (An identifier containing an embedded backtick is a documented limitation of the admin lexer,
        // which does not un-escape a doubled backtick — see `quote_ident` — so it is not round-tripped.)
        assert_round_trips(&info(
            "weird name",
            "Label With Space",
            &["a prop"],
            ConstraintKind::Unique,
            None,
        ));
        assert_round_trips(&info("KEY", "FOR", &["IS"], ConstraintKind::NodeKey, None));
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
    fn compose_query_yield_keeps_an_explicit_return() {
        let q = compose_query("YIELD name, type WHERE type = 'NODE_KEY' RETURN name");
        assert!(
            q.contains("WITH name, type WHERE type = 'NODE_KEY' RETURN name"),
            "{q}"
        );
        // The explicit RETURN suppresses the auto-appended `RETURN *`.
        assert_eq!(q.matches("RETURN").count(), 1, "no extra RETURN *: {q}");
    }

    #[test]
    fn compose_query_yield_star_returns_all_columns() {
        let q = compose_query("YIELD *");
        assert!(q.contains("WITH *"), "YIELD * → WITH *: {q}");
        assert!(q.trim_end().ends_with("RETURN *"), "{q}");
    }

    #[test]
    fn compose_query_terse_where_returns_the_default_columns() {
        let q = compose_query("WHERE entityType = 'NODE'");
        assert!(q.contains("WHERE entityType = 'NODE'"), "{q}");
        assert!(
            q.trim_end().ends_with(
                "RETURN id, name, type, entityType, labelsOrTypes, properties, ownedIndex, propertyType"
            ),
            "terse WHERE returns the 8 default columns: {q}"
        );
    }

    #[test]
    fn top_level_return_scan_ignores_quoted_spans() {
        assert!(contains_top_level_return("YIELD name RETURN name"));
        assert!(!contains_top_level_return("YIELD name"));
        // A `RETURN` inside a string literal is not a top-level RETURN.
        assert!(!contains_top_level_return("WHERE name = 'RETURN'"));
        assert!(!contains_top_level_return("WHERE name = \"a RETURN b\""));
        // Not a word boundary → not a match.
        assert!(!contains_top_level_return("YIELD RETURNS"));
    }
}
