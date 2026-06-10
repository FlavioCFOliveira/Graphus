//! The **query-execution seam** — the trait the Bolt server drives to run Cypher, plus the result
//! stream and transaction-control vocabulary (`04-technical-design.md` §8.3 "one executor, one value
//! model"; §7.7 result streaming; rmp #20 wires graphus-cypher's coordinator behind it).
//!
//! `graphus-bolt` knows nothing about parsing, planning, MVCC, or storage. It only needs something
//! that turns a query string + parameters into a stream of result rows, inside an explicit or
//! implicit transaction. That contract is [`BoltExecutor`]. The engine (rmp #20, via
//! `graphus-cypher`'s `TxnCoordinator`) implements it; tests here implement a mock.
//!
//! ## Why rows are `graphus_core::Value`
//!
//! `04 §8.3` mandates **one `Value` model** behind every listener: parameters in and result cells
//! out are the same `graphus_core::Value`. The executor (`graphus-cypher`) carries a richer internal
//! cell type (`RowValue`, with bound `Node`/`Relationship` references) through its operators, but it
//! **projects** those down to the public `Value` model at the result boundary — which is exactly the
//! seam this trait sits on. So [`Record`] rows are `Vec<Value>`.
//!
//! ### `Value::Node` is deferred (documented)
//!
//! `graphus_core::Value` does **not** yet have `Node`/`Relationship`/`Path`/`Point` variants
//! (`04 §7.2` defers them to their owning subsystems). Until it does, an executor projecting a bound
//! node into a result row can only expose what the `Value` model can represent — e.g. the node's id
//! as a [`Value::Integer`], or its properties as a [`Value::Map`]. When the structural `Value`
//! variants land, the executor will yield them and [`crate::packstream`] already has the structure
//! encoders ([`crate::packstream::tag`]) to put a real Bolt `Node`/`Relationship`/`Path` on the
//! wire. The seam itself does not change.
//!
//! ## Streaming and fetch size (`04 §7.7`)
//!
//! [`RecordStream::next_record`] is **pull-based**: the server calls it once per record it owes the
//! client, honouring the client's `PULL n` fetch size (`-1` = all). The stream reports completion
//! and the result summary so the server can emit the trailing `SUCCESS` (`06 §3.1`).

use graphus_core::{GraphusError, Value};

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
/// (`06 §3.1`).
pub type Record = Vec<Value>;

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
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TxControl {
    /// Run as a standalone auto-commit statement in `mode` (committed when its result is consumed).
    AutoCommit {
        /// The statement's access mode.
        mode: AccessMode,
    },
    /// Run inside the currently-open explicit transaction (opened by a prior `BEGIN`).
    InExplicit,
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

    /// Opens an explicit transaction in `mode` (a `BEGIN`).
    ///
    /// # Errors
    /// [`GraphusError::Transaction`] if a transaction is already open or cannot be started.
    fn begin(&mut self, mode: AccessMode) -> Result<(), GraphusError>;

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
}

#[cfg(test)]
pub(crate) mod mock {
    //! A scriptable in-memory [`BoltExecutor`] for the state-machine tests.

    use super::{AccessMode, BoltExecutor, QuerySummary, Record, RecordStream, TxControl};
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
        pub fn rows(fields: &[&str], rows: Vec<Record>) -> Self {
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
    /// begin/commit/rollback calls it received so tests can assert the transaction lifecycle.
    #[derive(Default)]
    pub struct MockExecutor {
        results: HashMap<String, CannedResult>,
        errors: HashMap<String, GraphusError>,
        default_result: Option<CannedResult>,
        pub tx_open: bool,
        pub log: Vec<String>,
        pub commit_fails_with: Option<GraphusError>,
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

        fn begin(&mut self, mode: AccessMode) -> Result<(), GraphusError> {
            self.log.push(format!("begin({mode:?})"));
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
                },
            )
            .unwrap();
        assert_eq!(stream.fields(), &["x".to_owned()]);
        assert_eq!(stream.next_record().unwrap(), Some(vec![Value::Integer(1)]));
        assert_eq!(stream.next_record().unwrap(), None);
        assert_eq!(stream.summary().query_type.as_deref(), Some("r"));
    }

    #[test]
    fn mock_tracks_transaction_lifecycle() {
        let mut exec = MockExecutor::new();
        assert!(!exec.tx_open);
        exec.begin(AccessMode::Write).unwrap();
        assert!(exec.tx_open);
        // A second begin without commit is an error.
        assert!(exec.begin(AccessMode::Write).is_err());
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
                },
            )
            .unwrap_err();
        assert!(matches!(err, GraphusError::Compile(_)));
    }
}
