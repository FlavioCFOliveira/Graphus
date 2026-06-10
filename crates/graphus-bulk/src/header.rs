//! CSV **header schema** parsing for the offline bulk importer (FR-BK; `rmp` task #22).
//!
//! The header row of a bulk-import CSV declares, column by column, what each field means — the
//! Neo4j-`neo4j-admin import`-flavoured convention this importer reads:
//!
//! - A **node** file declares exactly one **id** column `<name>:ID` (the external id used to join
//!   relationships to nodes), an optional **label** column `:LABEL` (a `;`-separated label list per
//!   row), and zero or more **typed property** columns `<key>:<type>` (or bare `<key>`, defaulting to
//!   `string`).
//! - A **relationship** file declares a `:START_ID` and an `:END_ID` column (matching node `:ID`
//!   values), a `:TYPE` column (the relationship type per row), and zero or more typed property
//!   columns.
//!
//! The recognised types are `string`, `int`/`long`/`integer`, `float`/`double`, `boolean`/`bool`,
//! and their `<type>[]` array variants (a `;`-separated list of the element type). An unknown type is
//! a [`HeaderError`]. Column matching is case-insensitive for the type and the reserved `:`-prefixed
//! roles; a property key keeps its written case.

use std::fmt;

/// The scalar value type a typed property column declares.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScalarType {
    /// `string` (the default when a column has no `:type`).
    String,
    /// `int` / `integer` / `long` (stored as `i64`).
    Integer,
    /// `float` / `double` (stored as `f64`).
    Float,
    /// `boolean` / `bool`.
    Boolean,
}

impl ScalarType {
    /// Parses a scalar type token (case-insensitive), or `None` if unrecognised.
    fn parse(token: &str) -> Option<Self> {
        match token.to_ascii_lowercase().as_str() {
            "string" => Some(Self::String),
            "int" | "integer" | "long" => Some(Self::Integer),
            "float" | "double" => Some(Self::Float),
            "boolean" | "bool" => Some(Self::Boolean),
            _ => None,
        }
    }
}

/// The declared type of a property column: a scalar, or an array (`type[]`) of a scalar.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PropertyType {
    /// A single scalar value.
    Scalar(ScalarType),
    /// A `;`-separated array (openCypher `List`) of a scalar element type.
    Array(ScalarType),
}

/// The role a single CSV column plays, decoded from one header cell.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ColumnRole {
    /// The node external-id column (`:ID` or `<name>:ID`).
    Id,
    /// The node label-list column (`:LABEL`); the cell is a `;`-separated set of labels.
    Label,
    /// The relationship start-node external-id column (`:START_ID`).
    StartId,
    /// The relationship end-node external-id column (`:END_ID`).
    EndId,
    /// The relationship type column (`:TYPE`); the cell is the type name.
    Type,
    /// A typed property column; carries the property key and its declared type.
    Property {
        /// The property key (case preserved from the header).
        key: String,
        /// The declared value type.
        ty: PropertyType,
    },
    /// A column the importer ignores (an explicit `:IGNORE`, or an empty header cell).
    Ignore,
}

/// A parse error for a malformed CSV header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HeaderError {
    /// A column declares a property type the importer does not recognise.
    UnknownType {
        /// The offending header cell.
        column: String,
        /// The unrecognised type token.
        ty: String,
    },
    /// A node header has no `:ID` column (cannot join relationships).
    MissingId,
    /// A node header has more than one `:ID` column.
    DuplicateId,
    /// A relationship header is missing `:START_ID`, `:END_ID`, or `:TYPE`.
    MissingRelColumn {
        /// Which reserved column is missing.
        which: &'static str,
    },
}

impl fmt::Display for HeaderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnknownType { column, ty } => {
                write!(f, "header column `{column}` declares unknown type `{ty}`")
            }
            Self::MissingId => f.write_str("node header has no `:ID` column"),
            Self::DuplicateId => f.write_str("node header has more than one `:ID` column"),
            Self::MissingRelColumn { which } => {
                write!(f, "relationship header is missing the `{which}` column")
            }
        }
    }
}

impl std::error::Error for HeaderError {}

impl From<HeaderError> for graphus_core::GraphusError {
    fn from(e: HeaderError) -> Self {
        graphus_core::GraphusError::Storage(format!("bulk-import header: {e}"))
    }
}

/// Decodes a single header cell into its [`ColumnRole`].
///
/// The grammar of a cell is `<name>:<type-or-role>` or a bare `<name>` (a `string` property) or a
/// bare `:<role>` (a reserved column with no name). A leading reserved role (`ID`, `LABEL`,
/// `START_ID`, `END_ID`, `TYPE`, `IGNORE`) is matched case-insensitively after the `:`.
fn parse_header_cell(cell: &str) -> Result<ColumnRole, HeaderError> {
    let cell = cell.trim();
    if cell.is_empty() {
        return Ok(ColumnRole::Ignore);
    }
    // Split on the *last* colon so a property key containing a colon is not misread (rare, but the
    // type/role suffix is always the trailing `:token`).
    let (name, suffix) = match cell.rsplit_once(':') {
        Some((name, suffix)) => (name, Some(suffix.trim())),
        None => (cell, None),
    };
    let name = name.trim();

    match suffix {
        // Bare `<name>` → a string property keyed by the name.
        None => Ok(ColumnRole::Property {
            key: name.to_owned(),
            ty: PropertyType::Scalar(ScalarType::String),
        }),
        Some(suffix) => {
            // Reserved roles first (case-insensitive), then a property type.
            match suffix.to_ascii_uppercase().as_str() {
                "ID" => Ok(ColumnRole::Id),
                "LABEL" => Ok(ColumnRole::Label),
                "START_ID" => Ok(ColumnRole::StartId),
                "END_ID" => Ok(ColumnRole::EndId),
                "TYPE" => Ok(ColumnRole::Type),
                "IGNORE" => Ok(ColumnRole::Ignore),
                _ => {
                    // A property type, possibly an array (`type[]`).
                    let (ty, is_array) = match suffix.strip_suffix("[]") {
                        Some(inner) => (inner.trim(), true),
                        None => (suffix, false),
                    };
                    let scalar = ScalarType::parse(ty).ok_or_else(|| HeaderError::UnknownType {
                        column: cell.to_owned(),
                        ty: ty.to_owned(),
                    })?;
                    let ty = if is_array {
                        PropertyType::Array(scalar)
                    } else {
                        PropertyType::Scalar(scalar)
                    };
                    Ok(ColumnRole::Property {
                        key: name.to_owned(),
                        ty,
                    })
                }
            }
        }
    }
}

/// The decoded schema of a **node** CSV file: the per-column roles plus the `:ID` column index.
#[derive(Debug, Clone)]
pub struct NodeHeader {
    /// One role per column, in column order.
    pub columns: Vec<ColumnRole>,
    /// The index of the `:ID` column.
    pub id_index: usize,
}

impl NodeHeader {
    /// Parses a node CSV header row.
    ///
    /// # Errors
    ///
    /// [`HeaderError::MissingId`] if no `:ID` column is present, [`HeaderError::DuplicateId`] if more
    /// than one is, or [`HeaderError::UnknownType`] for an unrecognised property type.
    pub fn parse<'a>(cells: impl IntoIterator<Item = &'a str>) -> Result<Self, HeaderError> {
        let columns = cells
            .into_iter()
            .map(parse_header_cell)
            .collect::<Result<Vec<_>, _>>()?;
        let mut id_index = None;
        for (i, role) in columns.iter().enumerate() {
            if *role == ColumnRole::Id {
                if id_index.is_some() {
                    return Err(HeaderError::DuplicateId);
                }
                id_index = Some(i);
            }
        }
        let id_index = id_index.ok_or(HeaderError::MissingId)?;
        Ok(Self { columns, id_index })
    }
}

/// The decoded schema of a **relationship** CSV file: the per-column roles plus the indices of the
/// reserved `:START_ID`, `:END_ID`, and `:TYPE` columns.
#[derive(Debug, Clone)]
pub struct RelHeader {
    /// One role per column, in column order.
    pub columns: Vec<ColumnRole>,
    /// The index of the `:START_ID` column.
    pub start_index: usize,
    /// The index of the `:END_ID` column.
    pub end_index: usize,
    /// The index of the `:TYPE` column.
    pub type_index: usize,
}

impl RelHeader {
    /// Parses a relationship CSV header row.
    ///
    /// # Errors
    ///
    /// [`HeaderError::MissingRelColumn`] if `:START_ID`, `:END_ID`, or `:TYPE` is absent, or
    /// [`HeaderError::UnknownType`] for an unrecognised property type.
    pub fn parse<'a>(cells: impl IntoIterator<Item = &'a str>) -> Result<Self, HeaderError> {
        let columns = cells
            .into_iter()
            .map(parse_header_cell)
            .collect::<Result<Vec<_>, _>>()?;
        let find = |role: &ColumnRole| columns.iter().position(|c| c == role);
        let start_index = find(&ColumnRole::StartId)
            .ok_or(HeaderError::MissingRelColumn { which: ":START_ID" })?;
        let end_index =
            find(&ColumnRole::EndId).ok_or(HeaderError::MissingRelColumn { which: ":END_ID" })?;
        let type_index =
            find(&ColumnRole::Type).ok_or(HeaderError::MissingRelColumn { which: ":TYPE" })?;
        Ok(Self {
            columns,
            start_index,
            end_index,
            type_index,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_typed_property_columns() {
        assert_eq!(
            parse_header_cell("name:string").unwrap(),
            ColumnRole::Property {
                key: "name".to_owned(),
                ty: PropertyType::Scalar(ScalarType::String),
            }
        );
        assert_eq!(
            parse_header_cell("age:int").unwrap(),
            ColumnRole::Property {
                key: "age".to_owned(),
                ty: PropertyType::Scalar(ScalarType::Integer),
            }
        );
        // A bare column defaults to string.
        assert_eq!(
            parse_header_cell("title").unwrap(),
            ColumnRole::Property {
                key: "title".to_owned(),
                ty: PropertyType::Scalar(ScalarType::String),
            }
        );
        // Array form.
        assert_eq!(
            parse_header_cell("tags:string[]").unwrap(),
            ColumnRole::Property {
                key: "tags".to_owned(),
                ty: PropertyType::Array(ScalarType::String),
            }
        );
    }

    #[test]
    fn recognises_reserved_roles_case_insensitively() {
        assert_eq!(parse_header_cell("personId:ID").unwrap(), ColumnRole::Id);
        assert_eq!(parse_header_cell(":LABEL").unwrap(), ColumnRole::Label);
        assert_eq!(parse_header_cell(":start_id").unwrap(), ColumnRole::StartId);
        assert_eq!(parse_header_cell(":END_ID").unwrap(), ColumnRole::EndId);
        assert_eq!(parse_header_cell(":Type").unwrap(), ColumnRole::Type);
        assert_eq!(parse_header_cell("").unwrap(), ColumnRole::Ignore);
    }

    #[test]
    fn unknown_type_errors() {
        let err = parse_header_cell("x:widget").unwrap_err();
        assert!(matches!(err, HeaderError::UnknownType { .. }));
    }

    #[test]
    fn node_header_requires_exactly_one_id() {
        let ok = NodeHeader::parse(["id:ID", ":LABEL", "name:string"]).unwrap();
        assert_eq!(ok.id_index, 0);
        assert!(matches!(
            NodeHeader::parse(["name:string"]).unwrap_err(),
            HeaderError::MissingId
        ));
        assert!(matches!(
            NodeHeader::parse(["a:ID", "b:ID"]).unwrap_err(),
            HeaderError::DuplicateId
        ));
    }

    #[test]
    fn rel_header_requires_start_end_type() {
        let ok = RelHeader::parse([":START_ID", ":END_ID", ":TYPE", "since:int"]).unwrap();
        assert_eq!((ok.start_index, ok.end_index, ok.type_index), (0, 1, 2));
        assert!(matches!(
            RelHeader::parse([":START_ID", ":TYPE"]).unwrap_err(),
            HeaderError::MissingRelColumn { which: ":END_ID" }
        ));
    }
}
