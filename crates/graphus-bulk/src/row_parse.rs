//! Store-independent CSV row parsing for **network bulk-import Mode B**
//! (`08-network-bulk-import.md` §7.2, `rmp` #520).
//!
//! Mode B must apply every row through the ordinary `graphus_cypher::GraphAccess` write seam
//! (`create_node`/`create_rel`) — never a raw [`graphus_storage::RecordStore`] call — so it cannot
//! reuse [`crate::import::ingest_node_row`]/[`crate::import::ingest_rel_row`] (`08` §7.2: "a
//! 'bulk-optimized' reimplementation that skips these calls for speed is explicitly disallowed").
//! Those functions are store-coupled by construction: they take `&mut RecordStore`, a `TxnId`, and a
//! label/type token memo, and they write directly.
//!
//! This module extracts the **parsing** half only — walking a record's columns by [`ColumnRole`],
//! decoding each `Property` cell via [`crate::value_parse::parse_cell`] — into pure functions that
//! produce owned `String`/`Value` collections, with no store, no transaction, no token interning. The
//! caller (`graphus-server`'s Mode B engine command handler) then drives `GraphAccess::create_node`/
//! `create_rel`, which intern their own tokens internally.

use std::fmt;

use graphus_core::Value;

use crate::header::{ColumnRole, NodeHeader, RelHeader};
use crate::value_parse::{ParseLimits, ValueParseError, parse_cell_with_limits};

/// One parsed node row, store-independent: owned labels + `(key, value)` properties, ready to hand to
/// `GraphAccess::create_node(&labels, &properties)`.
#[derive(Debug, Clone, PartialEq)]
pub struct ParsedNodeRow {
    /// The row's external `:ID` cell (may be empty — an unreferenceable node, same convention as the
    /// offline importer).
    pub external_id: String,
    /// The row's `:LABEL` cell, split on `;` (deduplicated, insertion order, empty entries dropped).
    pub labels: Vec<String>,
    /// The row's typed property cells, in header column order. A `null`/empty non-string cell is
    /// omitted (mirrors [`crate::value_parse::parse_cell`]'s "absent value" convention).
    pub properties: Vec<(String, Value)>,
}

/// One parsed relationship row, store-independent: owned endpoint external ids, the relationship type
/// name, and `(key, value)` properties, ready to resolve endpoints and hand to
/// `GraphAccess::create_rel(&rel_type, start, end, &properties)`.
#[derive(Debug, Clone, PartialEq)]
pub struct ParsedRelRow {
    /// The row's `:START_ID` cell (the external id of the start node).
    pub start_external_id: String,
    /// The row's `:END_ID` cell (the external id of the end node).
    pub end_external_id: String,
    /// The row's `:TYPE` cell.
    pub rel_type: String,
    /// The row's typed property cells, in header column order.
    pub properties: Vec<(String, Value)>,
}

/// A row-parse failure: which column failed and why.
#[derive(Debug, Clone, PartialEq)]
pub struct RowParseError {
    /// The property key whose cell failed to parse (empty for a non-property failure — there are
    /// none today, but the field is kept for a uniform, informative `Display`).
    pub key: String,
    /// The underlying value-parse failure.
    pub source: ValueParseError,
}

impl fmt::Display for RowParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.source)
    }
}

impl std::error::Error for RowParseError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.source)
    }
}

impl From<RowParseError> for graphus_core::GraphusError {
    fn from(e: RowParseError) -> Self {
        graphus_core::GraphusError::from(e.source)
    }
}

/// Parses one node CSV `record` against `header`'s column schema into a store-independent
/// [`ParsedNodeRow`], using the default [`ParseLimits`] (SEC-195: bounded array/cell sizes — the same
/// safety ceiling [`crate::import::ingest_node_row`] applies).
///
/// # Errors
/// [`RowParseError`] if a typed property cell does not match its declared scalar type, or exceeds a
/// resource limit.
pub fn parse_node_row(
    header: &NodeHeader,
    record: &csv::StringRecord,
) -> Result<ParsedNodeRow, RowParseError> {
    parse_node_row_with_limits(header, record, ParseLimits::default())
}

/// Like [`parse_node_row`] but with explicit resource [`ParseLimits`] (SEC-195).
///
/// # Errors
/// As [`parse_node_row`].
pub fn parse_node_row_with_limits(
    header: &NodeHeader,
    record: &csv::StringRecord,
    limits: ParseLimits,
) -> Result<ParsedNodeRow, RowParseError> {
    let external_id = record.get(header.id_index).unwrap_or("").to_owned();
    let mut labels: Vec<String> = Vec::new();
    let mut properties: Vec<(String, Value)> = Vec::new();

    for (i, role) in header.columns.iter().enumerate() {
        let cell = record.get(i).unwrap_or("");
        match role {
            ColumnRole::Label => {
                for label in cell.split(';').map(str::trim).filter(|s| !s.is_empty()) {
                    if !labels.iter().any(|l| l == label) {
                        labels.push(label.to_owned());
                    }
                }
            }
            ColumnRole::Property { key, ty } => {
                if let Some(value) =
                    parse_cell_with_limits(cell, *ty, key, limits).map_err(|source| {
                        RowParseError {
                            key: key.clone(),
                            source,
                        }
                    })?
                {
                    properties.push((key.clone(), value));
                }
            }
            // `:ID` is consumed via `header.id_index`; reserved rel roles never appear in a node
            // header; `Ignore` columns are skipped.
            ColumnRole::Id
            | ColumnRole::StartId
            | ColumnRole::EndId
            | ColumnRole::Type
            | ColumnRole::Ignore => {}
        }
    }

    Ok(ParsedNodeRow {
        external_id,
        labels,
        properties,
    })
}

/// Parses one relationship CSV `record` against `header`'s column schema into a store-independent
/// [`ParsedRelRow`], using the default [`ParseLimits`].
///
/// # Errors
/// As [`parse_node_row`].
pub fn parse_rel_row(
    header: &RelHeader,
    record: &csv::StringRecord,
) -> Result<ParsedRelRow, RowParseError> {
    parse_rel_row_with_limits(header, record, ParseLimits::default())
}

/// Like [`parse_rel_row`] but with explicit resource [`ParseLimits`] (SEC-195).
///
/// # Errors
/// As [`parse_node_row`].
pub fn parse_rel_row_with_limits(
    header: &RelHeader,
    record: &csv::StringRecord,
    limits: ParseLimits,
) -> Result<ParsedRelRow, RowParseError> {
    let start_external_id = record.get(header.start_index).unwrap_or("").to_owned();
    let end_external_id = record.get(header.end_index).unwrap_or("").to_owned();
    let rel_type = record.get(header.type_index).unwrap_or("").to_owned();
    let mut properties: Vec<(String, Value)> = Vec::new();

    for (i, role) in header.columns.iter().enumerate() {
        if let ColumnRole::Property { key, ty } = role {
            let cell = record.get(i).unwrap_or("");
            if let Some(value) =
                parse_cell_with_limits(cell, *ty, key, limits).map_err(|source| RowParseError {
                    key: key.clone(),
                    source,
                })?
            {
                properties.push((key.clone(), value));
            }
        }
    }

    Ok(ParsedRelRow {
        start_external_id,
        end_external_id,
        rel_type,
        properties,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::header::{PropertyType, ScalarType};

    fn node_header() -> NodeHeader {
        NodeHeader {
            columns: vec![
                ColumnRole::Id,
                ColumnRole::Label,
                ColumnRole::Property {
                    key: "name".to_owned(),
                    ty: PropertyType::Scalar(ScalarType::String),
                },
                ColumnRole::Property {
                    key: "age".to_owned(),
                    ty: PropertyType::Scalar(ScalarType::Integer),
                },
            ],
            id_index: 0,
            id_name: None,
        }
    }

    fn rel_header() -> RelHeader {
        RelHeader {
            columns: vec![
                ColumnRole::StartId,
                ColumnRole::EndId,
                ColumnRole::Type,
                ColumnRole::Property {
                    key: "since".to_owned(),
                    ty: PropertyType::Scalar(ScalarType::Integer),
                },
            ],
            start_index: 0,
            end_index: 1,
            type_index: 2,
        }
    }

    fn record(fields: &[&str]) -> csv::StringRecord {
        csv::StringRecord::from(fields.to_vec())
    }

    #[test]
    fn parses_a_well_formed_node_row() {
        let h = node_header();
        let r = record(&["n1", "Person;Employee", "Ada", "30"]);
        let parsed = parse_node_row(&h, &r).expect("parses");
        assert_eq!(parsed.external_id, "n1");
        assert_eq!(
            parsed.labels,
            vec!["Person".to_owned(), "Employee".to_owned()]
        );
        assert_eq!(
            parsed.properties,
            vec![
                ("name".to_owned(), Value::String("Ada".to_owned())),
                ("age".to_owned(), Value::Integer(30)),
            ]
        );
    }

    #[test]
    fn multi_label_cell_splits_on_semicolon_and_dedups() {
        let h = node_header();
        let r = record(&["n1", "Person;Person;Employee", "Ada", ""]);
        let parsed = parse_node_row(&h, &r).expect("parses");
        assert_eq!(
            parsed.labels,
            vec!["Person".to_owned(), "Employee".to_owned()]
        );
        // An empty non-string cell (age:int) is omitted entirely, not stored as null.
        assert_eq!(
            parsed.properties,
            vec![("name".to_owned(), Value::String("Ada".to_owned()))]
        );
    }

    #[test]
    fn empty_external_id_is_preserved_as_empty_string() {
        let h = node_header();
        let r = record(&["", "Person", "Nameless", "1"]);
        let parsed = parse_node_row(&h, &r).expect("parses");
        assert_eq!(parsed.external_id, "");
    }

    #[test]
    fn a_null_valued_property_cell_is_omitted_not_stored() {
        let h = node_header();
        // age:int is empty -> None -> omitted (matches `parse_cell`'s "absent value" convention).
        let r = record(&["n1", "Person", "Ada", ""]);
        let parsed = parse_node_row(&h, &r).expect("parses");
        assert!(!parsed.properties.iter().any(|(k, _)| k == "age"));
    }

    #[test]
    fn unparseable_typed_cell_surfaces_a_clean_error() {
        let h = node_header();
        let r = record(&["n1", "Person", "Ada", "not-a-number"]);
        let err = parse_node_row(&h, &r).unwrap_err();
        assert_eq!(err.key, "age");
        assert_eq!(err.source.key, "age");
        assert_eq!(err.source.expected, "integer");
        // The `Display`/`GraphusError` conversions do not panic and carry the offending detail.
        let msg = err.to_string();
        assert!(
            msg.contains("age"),
            "message should name the property: {msg}"
        );
        let ge: graphus_core::GraphusError = err.into();
        assert!(matches!(ge, graphus_core::GraphusError::Storage(_)));
    }

    #[test]
    fn parses_a_well_formed_rel_row() {
        let h = rel_header();
        let r = record(&["n1", "n2", "KNOWS", "2020"]);
        let parsed = parse_rel_row(&h, &r).expect("parses");
        assert_eq!(parsed.start_external_id, "n1");
        assert_eq!(parsed.end_external_id, "n2");
        assert_eq!(parsed.rel_type, "KNOWS");
        assert_eq!(
            parsed.properties,
            vec![("since".to_owned(), Value::Integer(2020))]
        );
    }

    #[test]
    fn rel_row_unparseable_property_surfaces_a_clean_error() {
        let h = rel_header();
        let r = record(&["n1", "n2", "KNOWS", "not-a-year"]);
        let err = parse_rel_row(&h, &r).unwrap_err();
        assert_eq!(err.key, "since");
    }

    #[test]
    fn respects_explicit_parse_limits() {
        let h = node_header();
        // A 1-byte cell limit rejects "Ada" (3 bytes) on the `name` string column.
        let limits = ParseLimits {
            max_array_elems: 8,
            max_cell_bytes: 1,
        };
        let r = record(&["n1", "Person", "Ada", "1"]);
        let err = parse_node_row_with_limits(&h, &r, limits).unwrap_err();
        assert_eq!(err.key, "name");
    }
}
