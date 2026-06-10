//! Parsing a CSV string cell into a typed [`graphus_core::Value`] (FR-BK; `rmp` task #22).
//!
//! Each typed property column ([`PropertyType`]) drives how its cell text is decoded: a scalar is
//! parsed to the declared scalar type; an array (`type[]`) splits the cell on `;` and parses each
//! element. An **empty** cell is the absence of a value (`None`) — the importer simply does not write
//! that property for the row (matching `neo4j-admin import`, which skips empty property cells rather
//! than storing an empty string).

use graphus_core::Value;

use crate::header::{PropertyType, ScalarType};

/// A value-parse error: a cell did not match its declared scalar type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValueParseError {
    /// The property key whose cell failed.
    pub key: String,
    /// The offending cell text.
    pub cell: String,
    /// The scalar type that was expected.
    pub expected: &'static str,
}

impl std::fmt::Display for ValueParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "property `{}`: cannot parse `{}` as {}",
            self.key, self.cell, self.expected
        )
    }
}

impl std::error::Error for ValueParseError {}

impl From<ValueParseError> for graphus_core::GraphusError {
    fn from(e: ValueParseError) -> Self {
        graphus_core::GraphusError::Storage(format!("bulk-import value: {e}"))
    }
}

/// The human name of a scalar type for error messages.
fn scalar_name(t: ScalarType) -> &'static str {
    match t {
        ScalarType::String => "string",
        ScalarType::Integer => "integer",
        ScalarType::Float => "float",
        ScalarType::Boolean => "boolean",
    }
}

/// Parses one scalar `cell` as `ty`, attributing a failure to property `key`.
fn parse_scalar(cell: &str, ty: ScalarType, key: &str) -> Result<Value, ValueParseError> {
    match ty {
        ScalarType::String => Ok(Value::String(cell.to_owned())),
        ScalarType::Integer => {
            cell.trim()
                .parse::<i64>()
                .map(Value::Integer)
                .map_err(|_| ValueParseError {
                    key: key.to_owned(),
                    cell: cell.to_owned(),
                    expected: scalar_name(ty),
                })
        }
        ScalarType::Float => {
            cell.trim()
                .parse::<f64>()
                .map(Value::Float)
                .map_err(|_| ValueParseError {
                    key: key.to_owned(),
                    cell: cell.to_owned(),
                    expected: scalar_name(ty),
                })
        }
        ScalarType::Boolean => match cell.trim().to_ascii_lowercase().as_str() {
            "true" => Ok(Value::Boolean(true)),
            "false" => Ok(Value::Boolean(false)),
            _ => Err(ValueParseError {
                key: key.to_owned(),
                cell: cell.to_owned(),
                expected: scalar_name(ty),
            }),
        },
    }
}

/// Parses a property `cell` according to its declared [`PropertyType`], or `Ok(None)` for an empty
/// cell (the property is omitted for that row).
///
/// `key` is the property name, used only to attribute a parse failure.
///
/// # Errors
///
/// Returns [`ValueParseError`] when a non-empty cell (or an array element) does not match the
/// declared scalar type.
pub fn parse_cell(
    cell: &str,
    ty: PropertyType,
    key: &str,
) -> Result<Option<Value>, ValueParseError> {
    match ty {
        PropertyType::Scalar(s) => {
            // A string column keeps an empty cell as the empty string (it is a valid string); any
            // other scalar treats empty as "no value".
            if cell.is_empty() && s != ScalarType::String {
                return Ok(None);
            }
            Ok(Some(parse_scalar(cell, s, key)?))
        }
        PropertyType::Array(s) => {
            if cell.is_empty() {
                // An empty array cell is an empty list (a present-but-empty collection).
                return Ok(Some(Value::List(Vec::new())));
            }
            let mut items = Vec::new();
            for element in cell.split(';') {
                items.push(parse_scalar(element, s, key)?);
            }
            Ok(Some(Value::List(items)))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_scalars() {
        assert_eq!(
            parse_cell("hi", PropertyType::Scalar(ScalarType::String), "k").unwrap(),
            Some(Value::String("hi".to_owned()))
        );
        assert_eq!(
            parse_cell("42", PropertyType::Scalar(ScalarType::Integer), "k").unwrap(),
            Some(Value::Integer(42))
        );
        assert_eq!(
            parse_cell("1.5", PropertyType::Scalar(ScalarType::Float), "k").unwrap(),
            Some(Value::Float(1.5))
        );
        assert_eq!(
            parse_cell("TRUE", PropertyType::Scalar(ScalarType::Boolean), "k").unwrap(),
            Some(Value::Boolean(true))
        );
    }

    #[test]
    fn empty_non_string_cell_is_none() {
        assert_eq!(
            parse_cell("", PropertyType::Scalar(ScalarType::Integer), "k").unwrap(),
            None
        );
        // An empty string cell stays an empty string.
        assert_eq!(
            parse_cell("", PropertyType::Scalar(ScalarType::String), "k").unwrap(),
            Some(Value::String(String::new()))
        );
    }

    #[test]
    fn parses_arrays() {
        assert_eq!(
            parse_cell("1;2;3", PropertyType::Array(ScalarType::Integer), "k").unwrap(),
            Some(Value::List(vec![
                Value::Integer(1),
                Value::Integer(2),
                Value::Integer(3)
            ]))
        );
        assert_eq!(
            parse_cell("", PropertyType::Array(ScalarType::String), "k").unwrap(),
            Some(Value::List(Vec::new()))
        );
    }

    #[test]
    fn bad_scalar_errors() {
        let err = parse_cell("nope", PropertyType::Scalar(ScalarType::Integer), "age").unwrap_err();
        assert_eq!(err.key, "age");
        assert_eq!(err.expected, "integer");
    }
}
