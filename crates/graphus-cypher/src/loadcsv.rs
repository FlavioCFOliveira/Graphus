//! The runtime backing of the `LOAD CSV` source clause (`04-technical-design.md` §7.4; FR-BK).
//!
//! `LOAD CSV [WITH HEADERS] FROM <url> AS <var> [FIELDTERMINATOR <c>]` is a *driving source* clause,
//! like `UNWIND`: each CSV record becomes one row bound to `<var>`. This module owns the two pieces
//! the executor's [`Operator::LoadCsv`](crate::executor) needs: the URL → local-file resolution and
//! the **streaming** reader state that yields one [`RowValue`] per record.
//!
//! # Row shape
//!
//! - **Without `WITH HEADERS`** each record is a `List` of its fields as strings (openCypher's
//!   header-less `LOAD CSV` row).
//! - **With `WITH HEADERS`** the first record names the columns and each subsequent record is a
//!   `Map{header -> value}`. A field present but empty maps to the empty string; a header with **no**
//!   corresponding field in a short record maps to `null`; fields beyond the header count are dropped
//!   (the Neo4j `LOAD CSV WITH HEADERS` contract).
//!
//! # Security model
//!
//! Neo4j's `LOAD CSV` restricts the source to file/HTTP URLs and gates remote access behind server
//! configuration. Graphus's engine resolves **only local files**: a bare or relative path, or a
//! `file:`/`file://` URL. Any other scheme (`http`, `https`, `ftp`, …) is rejected with a clear
//! runtime error rather than silently fetched — remote ingestion is a deliberate non-feature of the
//! in-query clause (bulk/offline ingestion is the `graphus-bulk` crate's job, over trusted local
//! files). This keeps the query engine from being a request-forgery vector.
//!
//! # Streaming
//!
//! The reader is a [`csv::Reader`] over a buffered [`File`], pulled one [`csv::StringRecord`] at a
//! time, so a multi-gigabyte file is never materialised in memory — only the current record is. The
//! ingestion runs inside the statement transaction (the executor threads the same `&mut dyn
//! GraphAccess`), so `LOAD CSV ... CREATE ...` is transactional: a failure rolls the whole statement
//! back.

use std::fs::File;
use std::io::BufReader;
use std::path::{Path, PathBuf};

use graphus_core::Value;

use crate::executor::ExecError;
use crate::runtime::RowValue;

/// The open, streaming state of one `LOAD CSV` evaluation: the reader plus, when `WITH HEADERS` was
/// requested, the decoded header names.
///
/// Held by [`Operator::LoadCsv`](crate::executor) for the current driving row; dropping it closes the
/// file. The reader streams record-by-record, so this struct's footprint is independent of file size.
pub struct LoadCsvState {
    /// The driving row this CSV stream fans out across (its bindings are carried onto every emitted
    /// row, exactly as `UNWIND` carries the input row).
    pub base: crate::runtime::Row,
    /// The streaming CSV reader over the resolved local file.
    reader: csv::Reader<BufReader<File>>,
    /// The header names, present iff `WITH HEADERS` was given. Each record becomes a
    /// `Map{header -> value}`; without headers each record is a `List`.
    headers: Option<Vec<String>>,
}

impl LoadCsvState {
    /// Opens the CSV source named by `url_value`, returning the streaming state ready to yield rows.
    ///
    /// `field_terminator` is the single-byte field separator (defaults to `b','` upstream).
    /// `with_headers` decides the row shape and, when set, consumes the first record as the header.
    ///
    /// # Errors
    ///
    /// Returns [`ExecError::LoadCsv`] when `url_value` is not a string, names a non-`file` scheme,
    /// the file cannot be opened, or the header record cannot be read.
    pub fn open(
        base: crate::runtime::Row,
        url_value: &Value,
        field_terminator: u8,
        with_headers: bool,
    ) -> Result<Self, ExecError> {
        let path = resolve_local_path(url_value)?;
        let file = File::open(&path).map_err(|e| ExecError::LoadCsv {
            reason: format!("cannot open `{}`: {e}", path.display()),
        })?;
        let mut reader = csv::ReaderBuilder::new()
            // We manage headers ourselves so the no-header form returns every record (including the
            // first) as data, and the header form exposes the decoded header names.
            .has_headers(false)
            .delimiter(field_terminator)
            // Tolerate ragged rows: a short record maps missing headers to null; a long one drops
            // the surplus. Without this the `csv` crate would error on an uneven field count.
            .flexible(true)
            .from_reader(BufReader::new(file));

        let headers = if with_headers {
            let mut first = csv::StringRecord::new();
            // An empty file with `WITH HEADERS` yields no header row and therefore no data rows.
            let has_header = reader
                .read_record(&mut first)
                .map_err(|e| ExecError::LoadCsv {
                    reason: format!("reading header of `{}`: {e}", path.display()),
                })?;
            let names = if has_header {
                first.iter().map(str::to_owned).collect()
            } else {
                Vec::new()
            };
            Some(names)
        } else {
            None
        };

        Ok(Self {
            base,
            reader,
            headers,
        })
    }

    /// Pulls the next CSV record, returning the row value it binds (a `List` of fields, or a
    /// `Map{header -> value}` under `WITH HEADERS`), or `None` at end of file.
    ///
    /// # Errors
    ///
    /// Returns [`ExecError::LoadCsv`] if a record cannot be read/parsed.
    pub fn next_record(&mut self) -> Result<Option<RowValue>, ExecError> {
        let mut record = csv::StringRecord::new();
        let has_more = self
            .reader
            .read_record(&mut record)
            .map_err(|e| ExecError::LoadCsv {
                reason: format!("reading CSV record: {e}"),
            })?;
        if !has_more {
            return Ok(None);
        }
        let value = match &self.headers {
            // WITH HEADERS: zip each header with its field; a missing field (short record) → null.
            Some(headers) => {
                let mut map = Vec::with_capacity(headers.len());
                for (i, header) in headers.iter().enumerate() {
                    let cell = record
                        .get(i)
                        .map_or(Value::Null, |s| Value::String(s.to_owned()));
                    map.push((header.clone(), cell));
                }
                Value::Map(map)
            }
            // No headers: a List of the record's string fields.
            None => Value::List(record.iter().map(|s| Value::String(s.to_owned())).collect()),
        };
        Ok(Some(RowValue::Value(value)))
    }
}

/// Resolves a `LOAD CSV` URL [`Value`] to a local filesystem [`PathBuf`].
///
/// Accepts a bare/relative path, a `file:` URL, or a `file://[host]/path` URL; rejects any other
/// scheme (the security model documented at the module level) and a non-string value.
///
/// # Errors
///
/// Returns [`ExecError::LoadCsv`] for a non-string value or a non-`file` scheme.
fn resolve_local_path(url_value: &Value) -> Result<PathBuf, ExecError> {
    let url = match url_value {
        Value::String(s) => s.as_str(),
        other => {
            return Err(ExecError::LoadCsv {
                reason: format!(
                    "the source URL must be a string, but a {} was given",
                    value_kind(other)
                ),
            });
        }
    };
    parse_file_url(url).map(PathBuf::from)
}

/// Extracts the filesystem path from a `LOAD CSV` URL string, enforcing the file-only scheme policy.
///
/// - A bare path with no `scheme:` prefix (e.g. `data/people.csv`, `/abs/path.csv`) is returned
///   verbatim.
/// - `file:/path`, `file://host/path`, and `file:///path` all resolve to `/path` (the host, when
///   present, is ignored — the common `file://` localhost form). `file:relative` resolves to
///   `relative`.
/// - Any other `scheme:` prefix (`http`, `https`, `ftp`, …) is rejected.
fn parse_file_url(url: &str) -> Result<String, ExecError> {
    // No scheme prefix → a bare local path. A Windows drive letter (`C:\...`) is intentionally
    // treated as a path, not a scheme, by requiring a multi-char scheme before the colon.
    let Some((scheme, rest)) = split_scheme(url) else {
        return Ok(url.to_owned());
    };
    if !scheme.eq_ignore_ascii_case("file") {
        return Err(ExecError::LoadCsv {
            reason: format!(
                "unsupported URL scheme `{scheme}`: LOAD CSV reads local files only \
                 (use a `file://` URL or a path)"
            ),
        });
    }
    // `rest` is everything after `file:`. Strip the authority for the `file://[host]/path` form.
    let path = match rest.strip_prefix("//") {
        Some(after_slashes) => {
            // `//host/path` → `/path`; `///path` → `/path`; `//path` (no host) → `/path` is
            // ambiguous, but matches the dominant `file:///path` and `file://localhost/path` forms.
            match after_slashes.find('/') {
                Some(slash) => &after_slashes[slash..],
                // `file://path` with no further slash: treat the whole remainder as the path.
                None => after_slashes,
            }
        }
        // `file:/path` or `file:relative` — the remainder is the path as written.
        None => rest,
    };
    Ok(path.to_owned())
}

/// Splits a `scheme:rest` URL into `(scheme, rest)`, or `None` when there is no `scheme:` prefix.
///
/// A scheme is `ALPHA *( ALPHA / DIGIT / "+" / "-" / "." )` (RFC 3986) and must be at least two
/// characters so a Windows drive letter (`C:`) is not mistaken for a scheme. The split is on the
/// first `:`.
fn split_scheme(url: &str) -> Option<(&str, &str)> {
    let colon = url.find(':')?;
    let scheme = &url[..colon];
    if scheme.len() >= 2
        && scheme.starts_with(|c: char| c.is_ascii_alphabetic())
        && scheme
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'))
    {
        Some((scheme, &url[colon + 1..]))
    } else {
        None
    }
}

/// Best-effort name of a [`Value`]'s class for an error message (the URL-not-a-string case).
fn value_kind(v: &Value) -> &'static str {
    match v {
        Value::Null => "null",
        Value::Boolean(_) => "boolean",
        Value::Integer(_) => "integer",
        Value::Float(_) => "float",
        Value::String(_) => "string",
        Value::Bytes(_) => "byte string",
        Value::List(_) => "list",
        Value::Map(_) => "map",
        Value::Date(_)
        | Value::LocalTime(_)
        | Value::ZonedTime(_)
        | Value::LocalDateTime(_)
        | Value::ZonedDateTime(_)
        | Value::Duration(_) => "temporal value",
    }
}

/// Whether `path` denotes an existing regular file (a convenience for callers/tests).
#[must_use]
pub fn is_readable_file(path: &Path) -> bool {
    path.is_file()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bare_paths_pass_through() {
        assert_eq!(
            parse_file_url("data/people.csv").unwrap(),
            "data/people.csv"
        );
        assert_eq!(
            parse_file_url("/abs/people.csv").unwrap(),
            "/abs/people.csv"
        );
        assert_eq!(parse_file_url("./rel.csv").unwrap(), "./rel.csv");
    }

    #[test]
    fn file_urls_resolve_to_paths() {
        assert_eq!(parse_file_url("file:///tmp/x.csv").unwrap(), "/tmp/x.csv");
        assert_eq!(
            parse_file_url("file://localhost/tmp/x.csv").unwrap(),
            "/tmp/x.csv"
        );
        assert_eq!(parse_file_url("file:/tmp/x.csv").unwrap(), "/tmp/x.csv");
        assert_eq!(parse_file_url("file:rel.csv").unwrap(), "rel.csv");
        // Scheme match is case-insensitive.
        assert_eq!(parse_file_url("FILE:///tmp/x.csv").unwrap(), "/tmp/x.csv");
    }

    #[test]
    fn non_file_schemes_are_rejected() {
        for url in [
            "http://example.com/x.csv",
            "https://example.com/x.csv",
            "ftp://host/x.csv",
            "s3://bucket/x.csv",
        ] {
            let err = parse_file_url(url).expect_err("non-file scheme must be rejected");
            let ExecError::LoadCsv { reason } = err else {
                panic!("expected a LoadCsv error");
            };
            assert!(
                reason.contains("local files only"),
                "reason should explain the file-only policy, got: {reason}"
            );
        }
    }

    #[test]
    fn windows_drive_letter_is_a_path_not_a_scheme() {
        // A single-letter "scheme" is not a scheme: `C:\data\x.csv` is a path.
        assert_eq!(
            parse_file_url(r"C:\data\x.csv").unwrap(),
            r"C:\data\x.csv".to_owned()
        );
    }

    #[test]
    fn non_string_url_value_errors() {
        let err = resolve_local_path(&Value::Integer(42)).expect_err("non-string URL must error");
        let ExecError::LoadCsv { reason } = err else {
            panic!("expected a LoadCsv error");
        };
        assert!(reason.contains("must be a string"), "got: {reason}");
    }
}
