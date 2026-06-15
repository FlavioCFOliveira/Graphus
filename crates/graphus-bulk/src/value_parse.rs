//! Parsing a CSV string cell into a typed [`graphus_core::Value`] (FR-BK; `rmp` task #22).
//!
//! Each typed property column ([`PropertyType`]) drives how its cell text is decoded: a scalar is
//! parsed to the declared scalar type; an array (`type[]`) splits the cell on `;` and parses each
//! element. An **empty** cell is the absence of a value (`None`) — the importer simply does not write
//! that property for the row (matching `neo4j-admin import`, which skips empty property cells rather
//! than storing an empty string).

use graphus_core::Value;

use crate::header::{PropertyType, ScalarType};

/// The default ceiling on the number of elements a single `type[]` array cell may produce
/// (SEC-195, CWE-789/400). A single CSV cell with millions of `;` separators would otherwise
/// materialise a multi-million-element `Value::List` from one line, an out-of-band OOM/DoS vector
/// for a malicious import (or `LOAD CSV`) file even with row batching. Chosen generous enough for any
/// legitimate array property yet far below what threatens the host; override via [`ParseLimits`].
pub const DEFAULT_MAX_ARRAY_ELEMS: usize = 65_536;

/// The default ceiling on the byte length of a single CSV cell (SEC-195). The `csv` crate imposes no
/// native per-field cap, so a single field of many megabytes can itself be a memory-amplification
/// vector; reject an over-long cell before parsing. Override via [`ParseLimits`].
pub const DEFAULT_MAX_CELL_BYTES: usize = 1 << 20; // 1 MiB

/// Resource-safety limits applied while parsing a CSV cell (SEC-195). Both default to safe, generous
/// values ([`DEFAULT_MAX_ARRAY_ELEMS`], [`DEFAULT_MAX_CELL_BYTES`]).
#[derive(Debug, Clone, Copy)]
pub struct ParseLimits {
    /// Maximum number of elements a single `type[]` cell may yield.
    pub max_array_elems: usize,
    /// Maximum byte length of a single cell.
    pub max_cell_bytes: usize,
}

impl Default for ParseLimits {
    fn default() -> Self {
        Self {
            max_array_elems: DEFAULT_MAX_ARRAY_ELEMS,
            max_cell_bytes: DEFAULT_MAX_CELL_BYTES,
        }
    }
}

/// A value-parse error: a cell did not match its declared scalar type, or violated a resource limit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValueParseError {
    /// The property key whose cell failed.
    pub key: String,
    /// The offending cell text (truncated in the message for an over-long cell).
    pub cell: String,
    /// The scalar type that was expected, or a description of the limit violated.
    pub expected: &'static str,
}

impl std::fmt::Display for ValueParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Avoid echoing a multi-megabyte offending cell back into the error string.
        const MAX_SHOWN: usize = 120;
        if self.cell.len() > MAX_SHOWN {
            // Clamp to a UTF-8 char boundary so slicing a multibyte cell never panics.
            let mut cut = MAX_SHOWN;
            while cut > 0 && !self.cell.is_char_boundary(cut) {
                cut -= 1;
            }
            write!(
                f,
                "property `{}`: cannot parse `{}…` ({} bytes) as {}",
                self.key,
                &self.cell[..cut],
                self.cell.len(),
                self.expected
            )
        } else {
            write!(
                f,
                "property `{}`: cannot parse `{}` as {}",
                self.key, self.cell, self.expected
            )
        }
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

/// The formula-trigger characters the dumper neutralises with a leading `'` (SEC-194). Mirrors
/// `dump::FORMULA_TRIGGERS`; kept in sync so a dump → import round-trip is lossless.
const FORMULA_TRIGGERS: [char; 6] = ['=', '+', '-', '@', '\t', '\r'];

/// Reverses the export-side formula-injection neutralisation (SEC-194) for a **string** cell so a
/// dump → import round-trip preserves the logical value.
///
/// The dumper prefixes a `'` to any string cell that begins with a [formula trigger](FORMULA_TRIGGERS);
/// this strips exactly that one convention quote when it is immediately followed by a trigger (the
/// only shape the dumper produces). This mirrors how spreadsheets treat a leading `'` as a
/// text-format marker rather than data: typing `'=1` stores `=1`. A genuine value that legitimately
/// begins with `'` followed by a trigger (e.g. a hand-authored `'=x`) is the inherent, documented
/// ambiguity of the convention; all other strings (including a lone `'`, or `'` followed by a
/// non-trigger) pass through untouched.
fn unescape_formula_guard(cell: &str) -> &str {
    let mut chars = cell.chars();
    if chars.next() == Some('\'') && chars.next().is_some_and(|c| FORMULA_TRIGGERS.contains(&c)) {
        // Drop exactly the leading `'` (one UTF-8 byte).
        &cell[1..]
    } else {
        cell
    }
}

/// Parses one scalar `cell` as `ty`, attributing a failure to property `key`.
fn parse_scalar(cell: &str, ty: ScalarType, key: &str) -> Result<Value, ValueParseError> {
    match ty {
        ScalarType::String => Ok(Value::String(unescape_formula_guard(cell).to_owned())),
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
    parse_cell_with_limits(cell, ty, key, ParseLimits::default())
}

/// Like [`parse_cell`] but with explicit resource [`ParseLimits`] (SEC-195).
///
/// # Errors
///
/// Returns [`ValueParseError`] when a non-empty cell (or an array element) does not match the
/// declared scalar type, when the cell exceeds [`ParseLimits::max_cell_bytes`], or when an array
/// cell would yield more than [`ParseLimits::max_array_elems`] elements.
pub fn parse_cell_with_limits(
    cell: &str,
    ty: PropertyType,
    key: &str,
    limits: ParseLimits,
) -> Result<Option<Value>, ValueParseError> {
    // SEC-195: reject an over-long cell up front (the `csv` crate has no native per-field cap), so a
    // single multi-megabyte field cannot be amplified into a huge in-memory value.
    if cell.len() > limits.max_cell_bytes {
        return Err(ValueParseError {
            key: key.to_owned(),
            cell: cell.to_owned(),
            expected: "a cell within the configured size limit",
        });
    }
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
            // SEC-195: bound the element count *before* materialising the list. `split(';')` yields
            // `separators + 1` elements; reject when that would exceed the cap, so a cell with
            // millions of `;` cannot allocate a giant `Vec`. We count separators by bytes (`;` is a
            // single ASCII byte) without allocating.
            let sep_count = cell.as_bytes().iter().filter(|&&b| b == b';').count();
            let elem_count = sep_count + 1;
            if elem_count > limits.max_array_elems {
                return Err(ValueParseError {
                    key: key.to_owned(),
                    cell: if cell.len() > 120 {
                        format!("<{} elements>", elem_count)
                    } else {
                        cell.to_owned()
                    },
                    expected: "an array within the configured element-count limit",
                });
            }
            let mut items = Vec::with_capacity(elem_count);
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
    fn unescapes_formula_guard_quote_on_string_import() {
        // Regression: SEC-194. A `'`-followed-by-trigger (the dumper's neutralisation shape) is
        // stripped, so a dump → import round-trip is lossless for formula-trigger strings.
        for (input, want) in [
            ("'=1+1", "=1+1"),
            ("'+x", "+x"),
            ("'-2+3", "-2+3"),
            ("'@SUM", "@SUM"),
            ("'\t=1", "\t=1"),
        ] {
            assert_eq!(
                parse_cell(input, PropertyType::Scalar(ScalarType::String), "k").unwrap(),
                Some(Value::String(want.to_owned())),
                "convention quote before a trigger must be stripped for {input:?}"
            );
        }
        // A lone `'`, or `'` before a NON-trigger, is genuine data and passes through untouched.
        for keep in ["'hello", "'", "''", "no quote"] {
            assert_eq!(
                parse_cell(keep, PropertyType::Scalar(ScalarType::String), "k").unwrap(),
                Some(Value::String(keep.to_owned())),
                "non-neutralisation `'` must be preserved verbatim for {keep:?}"
            );
        }
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
