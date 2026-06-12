//! The **query-execution seam** — the trait the Bolt server drives to run Cypher, plus the result
//! stream and transaction-control vocabulary (`04-technical-design.md` §8.3 "one executor, one value
//! model"; §7.7 result streaming; rmp #20 wires graphus-cypher's coordinator behind it).
//!
//! `graphus-bolt` knows nothing about parsing, planning, MVCC, or storage. It only needs something
//! that turns a query string + parameters into a stream of result rows, inside an explicit or
//! implicit transaction. That contract is [`BoltExecutor`]. The engine (rmp #20, via
//! `graphus-cypher`'s `TxnCoordinator`) implements it; tests here implement a mock.
//!
//! ## The result-cell model
//!
//! `04 §8.3` mandates **one value model** behind every listener: query *parameters* in are
//! `graphus_core::Value`. Result *cells* out are a small superset, [`crate::packstream::BoltValue`]:
//! a property `Value` **or** a graph entity (`Node`/`Relationship`/`Path`). The structural classes
//! are not `graphus_core::Value` variants (`04 §7.2` defers them to their owning subsystems), so the
//! executor (`graphus-cypher`) resolves a bound entity's labels / type / endpoints / properties at
//! the result boundary (`graphus_cypher::MaterializedValue`) and the server seam maps that onto a
//! [`crate::packstream::BoltValue`]. A stock Neo4j driver thus receives a proper Bolt
//! `Node`/`Relationship`/`Path` (rmp #76/#96), not a flattened id. A scalar/temporal/list/map cell is
//! carried unchanged as `BoltValue::Value` and packs exactly as before. So [`Record`] rows are
//! `Vec<BoltValue>`.
//!
//! ## Streaming and fetch size (`04 §7.7`)
//!
//! [`RecordStream::next_record`] is **pull-based**: the server calls it once per record it owes the
//! client, honouring the client's `PULL n` fetch size (`-1` = all). The stream reports completion
//! and the result summary so the server can emit the trailing `SUCCESS` (`06 §3.1`).

use graphus_core::{GraphusError, Value};

use crate::packstream::BoltValue;

/// The access mode of a transaction (`04 §8.4`; `06 §4` for the REST mirror). Bolt `BEGIN`/`RUN`
/// carry this in their `mode` field (`"r"` / `"w"`); it defaults to write.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AccessMode {
    /// Read-only: write statements are rejected.
    Read,
    /// Read-write (the default).
    #[default]
    Write,
}

/// A single result row: the row's cells in the order declared by the query's `fields` metadata
/// (`06 §3.1`). Each cell is a [`BoltValue`] — a property `Value` or a graph entity
/// (`Node`/`Relationship`/`Path`), so a result row may carry structural values (rmp #76/#96).
pub type Record = Vec<BoltValue>;

/// The summary metadata for a finished result, emitted in the trailing `SUCCESS` (`06 §3.1`).
///
/// v1 carries the query `type` (e.g. `"r"`, `"rw"`, `"w"`, `"s"`) and a `stats` map of side-effect
/// counters; richer summary fields (plan, profile, notifications) are added as the executor exposes
/// them. The `has_more` indicator is **not** here — the server derives it from whether the stream is
/// exhausted after a bounded `PULL n` (`06 §3.1`).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct QuerySummary {
    /// The query type code for the `type` metadata key (`"r"`/`"rw"`/`"w"`/`"s"`), if known.
    pub query_type: Option<String>,
    /// Side-effect counters for the `stats` metadata key (e.g. `nodes-created`), in order.
    pub stats: Vec<(String, Value)>,
}

/// A lazily-produced stream of result records for one `RUN` (`04 §7.7`).
///
/// The server pulls records one at a time with [`RecordStream::next_record`], honouring the
/// client's fetch size. When the stream is exhausted, `next_record` returns `Ok(None)`; the server
/// then reads [`RecordStream::summary`] for the trailing `SUCCESS` metadata.
///
/// Field names are fixed at `RUN` time (the executor knows the projection's columns before the
/// first row) and are read once via [`RecordStream::fields`].
pub trait RecordStream {
    /// The result column names, in order — the `fields` metadata for the `RUN` `SUCCESS` (`06 §3.1`).
    fn fields(&self) -> &[String];

    /// Produces the next record, or `Ok(None)` when the result is exhausted.
    ///
    /// # Errors
    /// [`GraphusError`] for a **runtime** error during row production (`06 §2.3`); it may arrive
    /// after some records have already streamed (`06 §3.2`).
    fn next_record(&mut self) -> Result<Option<Record>, GraphusError>;

    /// The result summary, read after the stream is exhausted (or after a `DISCARD`).
    ///
    /// Calling this before the stream is exhausted yields the summary for the records produced so
    /// far; implementations should make it cheap and idempotent.
    fn summary(&self) -> QuerySummary;
}

/// What the server asks the executor to do with the surrounding transaction when running a query.
///
/// Bolt has two transaction shapes (`04 §8.1` state machine): **auto-commit** (a bare `RUN` outside
/// an explicit transaction commits on its own) and **explicit** (`BEGIN` … `RUN`* … `COMMIT`/`ROLLBACK`).
/// The server tells the executor which is in play so the executor (the coordinator) manages the
/// transaction lifecycle correctly.
///
/// Both shapes carry the target **database** from the message's `extra` map (Bolt 5.x `db` field):
/// `None` means the field was absent or empty — the executor targets its default database. For
/// [`TxControl::InExplicit`] the database is informational only — the transaction was already
/// pinned to a database at `BEGIN` — and a *different* non-empty name is an error (a transaction
/// cannot switch databases mid-flight); the executor enforces that rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TxControl {
    /// Run as a standalone auto-commit statement in `mode` (committed when its result is consumed).
    AutoCommit {
        /// The statement's access mode.
        mode: AccessMode,
        /// The target database from the `RUN` extra's `db` field (`None` = absent/empty = the
        /// executor's default database).
        db: Option<String>,
    },
    /// Run inside the currently-open explicit transaction (opened by a prior `BEGIN`).
    InExplicit {
        /// The `db` field from the `RUN` extra, if any. The transaction is already pinned to the
        /// database named at `BEGIN`; a different non-empty name here is an error.
        db: Option<String>,
    },
}

/// The query-execution interface the Bolt server drives (`04 §8.3`; rmp #20).
///
/// One instance backs one Bolt connection's lifetime. The server calls:
///
/// - [`begin`](BoltExecutor::begin) on `BEGIN`, [`commit`](BoltExecutor::commit) on `COMMIT`,
///   [`rollback`](BoltExecutor::rollback) on `ROLLBACK` — the explicit-transaction lifecycle;
/// - [`run`](BoltExecutor::run) on `RUN`, getting back a [`RecordStream`] the server pulls from per
///   the client's fetch size.
///
/// All methods return the engine's [`GraphusError`] on failure, which the server maps to a Bolt
/// `FAILURE` via [`crate::error::failure_from_error`] and then enters the fail-then-ignore state
/// (`06 §3.2`).
pub trait BoltExecutor {
    /// The concrete result stream this executor yields. (An associated type keeps the seam free of
    /// boxing; the engine picks its cursor type.)
    type Stream: RecordStream;

    /// Runs `query` with `parameters` under `tx`, returning a lazy result stream.
    ///
    /// # Errors
    /// [`GraphusError::Compile`] for a compile-time error (raised before any record — `06 §2.1`),
    /// [`GraphusError::Runtime`] for an immediate runtime error, or a transaction error.
    fn run(
        &mut self,
        query: &str,
        parameters: Vec<(String, Value)>,
        tx: TxControl,
    ) -> Result<Self::Stream, GraphusError>;

    /// Opens an explicit transaction in `mode` (a `BEGIN`) against `db` (the `BEGIN` extra's `db`
    /// field; `None` = absent/empty = the executor's default database). The transaction stays
    /// pinned to that database for its whole lifetime (Bolt 5.x semantics).
    ///
    /// # Errors
    /// [`GraphusError::Transaction`] if a transaction is already open or cannot be started, or
    /// [`GraphusError::Protocol`] if `db` names no servable database.
    fn begin(&mut self, mode: AccessMode, db: Option<&str>) -> Result<(), GraphusError>;

    /// Commits the open explicit transaction (a `COMMIT`).
    ///
    /// # Errors
    /// [`GraphusError::Transaction`] if no transaction is open, or on a serialization failure
    /// (retriable; `04 §5.4`).
    fn commit(&mut self) -> Result<QuerySummary, GraphusError>;

    /// Rolls back the open explicit transaction (a `ROLLBACK`).
    ///
    /// # Errors
    /// [`GraphusError::Transaction`] if no transaction is open.
    fn rollback(&mut self) -> Result<(), GraphusError>;

    /// Informs the executor of the session's authenticated identity: the server calls it with
    /// `Some(principal)` after a successful `LOGON` and with `None` on `LOGOFF` (`04 §8.4`).
    ///
    /// The default implementation is a no-op for executors that do not act on identity. An
    /// executor that performs authorization (e.g. the server's seam gating administrative
    /// statements — rmp #84) overrides it to track the principal.
    fn set_principal(&mut self, principal: Option<&str>) {
        let _ = principal;
    }

    /// **Audit-observation hook (rmp #70):** the session calls this at `LOGON` resolution when
    /// authentication **succeeds**, with the authenticated `principal`, so an audit-aware executor
    /// (the server's seam) can record an `auth_success` event.
    ///
    /// The default implementation is a no-op, keeping the protocol core audit-agnostic — only an
    /// executor that wants the trail overrides it. The credential is **never** passed; only the
    /// username (which is not a secret).
    fn on_auth_success(&mut self, principal: &str) {
        let _ = principal;
    }

    /// **Audit-observation hook (rmp #70):** the session calls this at `LOGON` resolution when
    /// authentication **fails**, with the attempted `principal` (if the client supplied one) and a
    /// short, secret-free `reason`, so an audit-aware executor can record an `auth_failure` event.
    ///
    /// The default implementation is a no-op (protocol core stays audit-agnostic). The attempted
    /// username is not a secret and may be `None`; **credentials are never passed**.
    fn on_auth_failure(&mut self, principal: Option<&str>, reason: &str) {
        let _ = (principal, reason);
    }
}

#[cfg(test)]
pub(crate) mod mock {
    //! A scriptable in-memory [`BoltExecutor`] for the state-machine tests.

    use super::{AccessMode, BoltExecutor, QuerySummary, Record, RecordStream, TxControl};
    use crate::packstream::BoltValue;
    use graphus_core::{GraphusError, Value};
    use std::collections::HashMap;

    /// A canned result: the fields and the rows to stream (or an error to raise on `run`).
    #[derive(Clone)]
    pub struct CannedResult {
        pub fields: Vec<String>,
        pub rows: Vec<Record>,
        pub summary: QuerySummary,
    }

    impl CannedResult {
        /// Builds a canned scalar result. Rows are given as plain [`Value`] cells (the common test
        /// case) and lifted into the [`Record`]'s [`BoltValue`] cells.
        pub fn rows(fields: &[&str], rows: Vec<Vec<Value>>) -> Self {
            let rows: Vec<Record> = rows
                .into_iter()
                .map(|row| row.into_iter().map(BoltValue::Value).collect())
                .collect();
            Self {
                fields: fields.iter().map(|s| (*s).to_owned()).collect(),
                rows,
                summary: QuerySummary {
                    query_type: Some("r".to_owned()),
                    stats: Vec::new(),
                },
            }
        }
    }

    /// A mock executor: maps query text → canned result (or error), and records the
    /// begin/commit/rollback/principal calls it received so tests can assert the transaction
    /// lifecycle and the identity plumbing.
    #[derive(Default)]
    pub struct MockExecutor {
        results: HashMap<String, CannedResult>,
        errors: HashMap<String, GraphusError>,
        default_result: Option<CannedResult>,
        pub tx_open: bool,
        pub log: Vec<String>,
        pub commit_fails_with: Option<GraphusError>,
        /// The principal last announced via [`BoltExecutor::set_principal`] (None until LOGON).
        pub principal: Option<String>,
    }

    impl MockExecutor {
        pub fn new() -> Self {
            Self::default()
        }

        /// Canned rows for an exact query string.
        pub fn on_query(mut self, query: &str, result: CannedResult) -> Self {
            self.results.insert(query.to_owned(), result);
            self
        }

        /// A `GraphusError` raised when `query` runs (e.g. a compile error).
        pub fn on_query_error(mut self, query: &str, err: GraphusError) -> Self {
            self.errors.insert(query.to_owned(), err);
            self
        }

        /// A fallback result for any unscripted query.
        pub fn with_default(mut self, result: CannedResult) -> Self {
            self.default_result = Some(result);
            self
        }
    }

    /// The mock's [`RecordStream`]: drains a `Vec` of canned rows.
    #[derive(Debug)]
    pub struct MockStream {
        fields: Vec<String>,
        rows: std::vec::IntoIter<Record>,
        summary: QuerySummary,
    }

    impl RecordStream for MockStream {
        fn fields(&self) -> &[String] {
            &self.fields
        }

        fn next_record(&mut self) -> Result<Option<Record>, GraphusError> {
            Ok(self.rows.next())
        }

        fn summary(&self) -> QuerySummary {
            self.summary.clone()
        }
    }

    impl BoltExecutor for MockExecutor {
        type Stream = MockStream;

        fn run(
            &mut self,
            query: &str,
            _parameters: Vec<(String, Value)>,
            tx: TxControl,
        ) -> Result<Self::Stream, GraphusError> {
            self.log.push(format!("run({query}, {tx:?})"));
            if let Some(err) = self.errors.get(query) {
                return Err(clone_error(err));
            }
            let canned = self
                .results
                .get(query)
                .cloned()
                .or_else(|| self.default_result.clone())
                .unwrap_or_else(|| CannedResult::rows(&[], vec![]));
            Ok(MockStream {
                fields: canned.fields,
                rows: canned.rows.into_iter(),
                summary: canned.summary,
            })
        }

        fn begin(&mut self, mode: AccessMode, db: Option<&str>) -> Result<(), GraphusError> {
            self.log.push(format!("begin({mode:?}, db={db:?})"));
            if self.tx_open {
                return Err(GraphusError::Transaction(
                    "transaction already open".to_owned(),
                ));
            }
            self.tx_open = true;
            Ok(())
        }

        fn commit(&mut self) -> Result<QuerySummary, GraphusError> {
            self.log.push("commit".to_owned());
            if !self.tx_open {
                return Err(GraphusError::Transaction("no open transaction".to_owned()));
            }
            if let Some(err) = &self.commit_fails_with {
                self.tx_open = false;
                return Err(clone_error(err));
            }
            self.tx_open = false;
            Ok(QuerySummary::default())
        }

        fn rollback(&mut self) -> Result<(), GraphusError> {
            self.log.push("rollback".to_owned());
            if !self.tx_open {
                return Err(GraphusError::Transaction("no open transaction".to_owned()));
            }
            self.tx_open = false;
            Ok(())
        }

        fn set_principal(&mut self, principal: Option<&str>) {
            self.log.push(format!("set_principal({principal:?})"));
            self.principal = principal.map(str::to_owned);
        }
    }

    /// `GraphusError` is not `Clone`; reproduce a variant for the mock's scripted-error map.
    fn clone_error(e: &GraphusError) -> GraphusError {
        match e {
            GraphusError::Storage(m) => GraphusError::Storage(m.clone()),
            GraphusError::Transaction(m) => GraphusError::Transaction(m.clone()),
            GraphusError::Compile(m) => GraphusError::Compile(m.clone()),
            GraphusError::Runtime(m) => GraphusError::Runtime(m.clone()),
            GraphusError::Protocol(m) => GraphusError::Protocol(m.clone()),
            // `#[non_exhaustive]`: any future variant maps to a protocol error for the mock.
            other => GraphusError::Protocol(format!("{other}")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::mock::{CannedResult, MockExecutor};
    use super::*;

    #[test]
    fn access_mode_defaults_to_write() {
        assert_eq!(AccessMode::default(), AccessMode::Write);
    }

    #[test]
    fn mock_streams_canned_rows_then_summary() {
        let mut exec = MockExecutor::new().on_query(
            "RETURN 1",
            CannedResult::rows(&["x"], vec![vec![Value::Integer(1)]]),
        );
        let mut stream = exec
            .run(
                "RETURN 1",
                vec![],
                TxControl::AutoCommit {
                    mode: AccessMode::Read,
                    db: None,
                },
            )
            .unwrap();
        assert_eq!(stream.fields(), &["x".to_owned()]);
        assert_eq!(
            stream.next_record().unwrap(),
            Some(vec![BoltValue::Value(Value::Integer(1))])
        );
        assert_eq!(stream.next_record().unwrap(), None);
        assert_eq!(stream.summary().query_type.as_deref(), Some("r"));
    }

    #[test]
    fn mock_tracks_transaction_lifecycle() {
        let mut exec = MockExecutor::new();
        assert!(!exec.tx_open);
        exec.begin(AccessMode::Write, None).unwrap();
        assert!(exec.tx_open);
        // A second begin without commit is an error.
        assert!(exec.begin(AccessMode::Write, None).is_err());
        exec.commit().unwrap();
        assert!(!exec.tx_open);
        assert!(exec.rollback().is_err()); // nothing open
    }

    #[test]
    fn mock_raises_scripted_error() {
        let mut exec =
            MockExecutor::new().on_query_error("BAD", GraphusError::Compile("syntax".to_owned()));
        let err = exec
            .run(
                "BAD",
                vec![],
                TxControl::AutoCommit {
                    mode: AccessMode::Write,
                    db: None,
                },
            )
            .unwrap_err();
        assert!(matches!(err, GraphusError::Compile(_)));
    }

    #[test]
    fn mock_tracks_principal_announcements() {
        let mut exec = MockExecutor::new();
        assert_eq!(exec.principal, None);
        exec.set_principal(Some("alice"));
        assert_eq!(exec.principal.as_deref(), Some("alice"));
        exec.set_principal(None); // LOGOFF clears it.
        assert_eq!(exec.principal, None);
    }
}
