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
//! ## Import-directory confinement (`SEC-189`, CWE-22)
//!
//! Resolving "any local file" is **not** enough: a path such as `file:///etc/passwd`, or a
//! `..`-laden relative path, would otherwise let any client that can run `LOAD CSV` read — and
//! exfiltrate to itself as result rows — any file the server process can read. To close that, every
//! resolved file path is confined to a configurable **import root** (Neo4j's
//! `dbms.directories.import` model, chroot-style), enforced by [`CsvImportPolicy`]:
//!
//! - The path the query names is joined under the import root, fully **canonicalised**, and then
//!   checked to still live inside the (canonicalised) root. A path that escapes the root via `..`
//!   segments, an absolute path, or a symlink pointing outside the root is **rejected**
//!   ([`ExecError::LoadCsv`]) — fail-closed.
//! - The policy is **fail-closed by default**: until the server explicitly configures an import root
//!   ([`set_global_import_policy`]), `LOAD CSV` from local files is **denied** outright. A server
//!   that wants the feature opts in by pointing the policy at a dedicated, trusted directory.
//!
//! This mirrors Neo4j, where `LOAD CSV` is confined to the `import/` directory by default and only
//! the operator can widen it.
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
use std::path::{Component, Path, PathBuf};
use std::sync::OnceLock;

use graphus_core::Value;

use crate::eval::EvalError;
use crate::executor::ExecError;
use crate::runtime::RowValue;

/// The process-wide `LOAD CSV` import policy (`SEC-189`).
///
/// `None` until the server installs one; an uninstalled policy means **deny** (fail-closed). The
/// server installs a single policy at startup via [`set_global_import_policy`].
static GLOBAL_IMPORT_POLICY: OnceLock<CsvImportPolicy> = OnceLock::new();

/// Installs the process-wide `LOAD CSV` import policy. Idempotent in the sense of [`OnceLock`]: the
/// **first** call wins; later calls are ignored and report `Err` with the policy that is in force.
///
/// The server is expected to call this exactly once at startup. If it never calls it, `LOAD CSV`
/// from local files is denied (the fail-closed default).
///
/// # Errors
///
/// Returns the already-installed [`CsvImportPolicy`] (by clone) if a policy was already set.
pub fn set_global_import_policy(policy: CsvImportPolicy) -> Result<(), CsvImportPolicy> {
    GLOBAL_IMPORT_POLICY.set(policy)
}

/// The import policy in force, or the fail-closed default ([`CsvImportPolicy::denied`]) when the
/// server has not installed one.
#[must_use]
pub fn global_import_policy() -> &'static CsvImportPolicy {
    GLOBAL_IMPORT_POLICY.get_or_init(CsvImportPolicy::denied)
}

/// Where `LOAD CSV` is allowed to read local files (`SEC-189`, CWE-22).
///
/// Construct with [`CsvImportPolicy::with_import_root`] to confine reads to a directory, or
/// [`CsvImportPolicy::denied`] to forbid local-file reads entirely (the default). The policy
/// canonicalises both the import root and the requested path and rejects anything that escapes the
/// root — via `..`, an absolute path, or a symlink leading outside the root.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct CsvImportPolicy {
    /// The canonical import root. `None` ⇒ local-file `LOAD CSV` is denied (fail-closed).
    root: Option<PathBuf>,
}

impl CsvImportPolicy {
    /// A policy that **denies** every local-file `LOAD CSV`. The fail-closed default.
    #[must_use]
    pub fn denied() -> Self {
        Self { root: None }
    }

    /// A policy confining `LOAD CSV` to `root` (and its subtree).
    ///
    /// `root` is canonicalised eagerly; if it cannot be canonicalised (does not exist, or is
    /// unreadable) the policy still records the path as given, and resolution will fail-closed when a
    /// query tries to use it. Prefer passing an existing, canonical directory.
    #[must_use]
    pub fn with_import_root(root: impl Into<PathBuf>) -> Self {
        let root = root.into();
        let canonical = std::fs::canonicalize(&root).unwrap_or(root);
        Self {
            root: Some(canonical),
        }
    }

    /// Whether local-file `LOAD CSV` is allowed at all under this policy.
    #[must_use]
    pub fn allows_local_files(&self) -> bool {
        self.root.is_some()
    }

    /// Resolves a query-supplied path to a concrete, **confined** filesystem path, or rejects it.
    ///
    /// The supplied `requested` path (already stripped of any `file:` scheme by
    /// [`parse_file_url`]) is interpreted **relative to the import root** — a leading `/` and any
    /// `..`/`.` components are stripped so the join can never climb above the root by construction —
    /// then the result is canonicalised and re-checked to live inside the canonical root. Any path
    /// that still escapes (e.g. through a symlink) is rejected.
    ///
    /// # Errors
    ///
    /// [`ExecError::LoadCsv`] when local-file reads are denied, when the path escapes the import
    /// root, or when the path cannot be canonicalised (it does not resolve to a readable file under
    /// the root).
    fn resolve(&self, requested: &str) -> Result<PathBuf, ExecError> {
        let Some(root) = &self.root else {
            return Err(ExecError::LoadCsv {
                reason: "LOAD CSV from local files is disabled: no import directory is configured \
                         (set one to enable confined CSV import)"
                    .to_owned(),
            });
        };

        // Re-anchor the requested path under the root, dropping every component that could climb
        // out (`RootDir`, `Prefix`, `ParentDir`, `CurDir`). What remains is a strictly-descending
        // sequence of normal segments, so the lexical join cannot escape the root.
        let mut confined = root.clone();
        for comp in Path::new(requested).components() {
            match comp {
                Component::Normal(seg) => confined.push(seg),
                // Reject explicit traversal rather than silently dropping it, so a `..`-laden path
                // is a hard error (CWE-22), not a quietly-rewritten read.
                Component::ParentDir => {
                    return Err(ExecError::LoadCsv {
                        reason: format!(
                            "LOAD CSV path `{requested}` contains a `..` segment, which is not \
                             allowed (paths are confined to the import directory)"
                        ),
                    });
                }
                // A leading `/`, a Windows prefix, or a `.` carries no descent — ignore it.
                Component::RootDir | Component::Prefix(_) | Component::CurDir => {}
            }
        }

        // Canonicalise and verify containment: this is what defeats a symlink inside the root that
        // points back out. `canonicalize` also requires the file to exist, giving a clean error.
        let canonical = std::fs::canonicalize(&confined).map_err(|e| ExecError::LoadCsv {
            reason: format!("cannot resolve `{requested}` under the import directory: {e}"),
        })?;
        if !canonical.starts_with(root) {
            return Err(ExecError::LoadCsv {
                reason: format!(
                    "LOAD CSV path `{requested}` resolves outside the import directory and is \
                     rejected"
                ),
            });
        }
        Ok(canonical)
    }
}

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
        let path = resolve_local_path(url_value, global_import_policy())?;
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
            // No headers: a List of the record's string fields. Bound the field count against the
            // per-value budget before collecting one `Value::String` per field (`SEC-191`, CWE-770 /
            // CWE-789): a hostile single wide record (millions of fields on one line, under the import
            // policy) would otherwise materialise one `Value` slot per field with no budget. O(1) check,
            // mirroring `split`/`keys`.
            None => {
                let limit = crate::value_size::max_list_elements();
                if record.len() > limit {
                    return Err(ExecError::Eval(EvalError::ResourceLimit {
                        detail: format!(
                            "LOAD CSV record has {} fields (limit {limit} per value)",
                            record.len()
                        ),
                    }));
                }
                Value::List(record.iter().map(|s| Value::String(s.to_owned())).collect())
            }
        };
        Ok(Some(RowValue::Value(value)))
    }
}

/// Resolves a `LOAD CSV` URL [`Value`] to a confined local filesystem [`PathBuf`] under `policy`.
///
/// Accepts a bare/relative path, a `file:` URL, or a `file://[host]/path` URL; rejects any other
/// scheme (the security model documented at the module level) and a non-string value. The extracted
/// path is then confined to the configured import root via [`CsvImportPolicy::resolve`]
/// (`SEC-189`): an absolute path, a `..` traversal, or a symlink escaping the root is rejected, and
/// when no import root is configured every local-file read is denied.
///
/// # Errors
///
/// Returns [`ExecError::LoadCsv`] for a non-string value, a non-`file` scheme, a path that escapes
/// the import directory, or (fail-closed) when local-file reads are disabled.
fn resolve_local_path(url_value: &Value, policy: &CsvImportPolicy) -> Result<PathBuf, ExecError> {
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
    let path = parse_file_url(url)?;
    policy.resolve(&path)
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
        Value::Point(_) => "point",
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
        let err = resolve_local_path(&Value::Integer(42), &CsvImportPolicy::denied())
            .expect_err("non-string URL must error");
        let ExecError::LoadCsv { reason } = err else {
            panic!("expected a LoadCsv error");
        };
        assert!(reason.contains("must be a string"), "got: {reason}");
    }

    #[test]
    fn denied_policy_rejects_every_local_path() {
        // Regression: SEC-189 — with no import root configured (the fail-closed default), even an
        // innocuous-looking relative path is refused.
        let policy = CsvImportPolicy::denied();
        let err = resolve_local_path(&Value::String("data/people.csv".to_owned()), &policy)
            .expect_err("a denied policy must refuse local files");
        let ExecError::LoadCsv { reason } = err else {
            panic!("expected a LoadCsv error");
        };
        assert!(reason.contains("disabled"), "got: {reason}");
    }

    #[test]
    fn confined_policy_allows_a_file_inside_the_root_and_rejects_escapes() {
        // Regression: SEC-189 — a path inside the import root resolves; absolute paths, `..`
        // traversal, and `file://<abs>` all escape the root and are rejected.
        let root = std::env::temp_dir().join(format!(
            "graphus_loadcsv_unit_{}_{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        std::fs::create_dir_all(&root).expect("mkdir root");
        let inside = root.join("ok.csv");
        std::fs::write(&inside, b"a,b\n1,2\n").expect("write inside file");

        // A secret file OUTSIDE the root.
        let outside =
            std::env::temp_dir().join(format!("graphus_loadcsv_secret_{}.txt", std::process::id()));
        std::fs::write(&outside, b"SECRET").expect("write secret");

        let policy = CsvImportPolicy::with_import_root(&root);

        // Inside the root: allowed, resolved to the canonical path.
        let resolved = resolve_local_path(&Value::String("ok.csv".to_owned()), &policy)
            .expect("a file inside the root resolves");
        assert!(resolved.ends_with("ok.csv"));

        // Absolute path to the secret: rejected (re-anchored under root, then canonicalize fails or
        // containment check fails).
        let abs = outside.to_string_lossy().to_string();
        assert!(
            resolve_local_path(&Value::String(abs.clone()), &policy).is_err(),
            "an absolute path to a file outside the root must be rejected"
        );

        // file:// URL to the secret: rejected.
        let url = format!("file://{abs}");
        assert!(
            resolve_local_path(&Value::String(url), &policy).is_err(),
            "a file:// URL to a file outside the root must be rejected"
        );

        // Explicit `..` traversal: rejected.
        assert!(
            resolve_local_path(&Value::String("../escape.csv".to_owned()), &policy).is_err(),
            "a `..` traversal must be rejected"
        );

        let _ = std::fs::remove_file(&outside);
        let _ = std::fs::remove_dir_all(&root);
    }
}
