//! The **query-execution seam** the REST router drives — the HTTP analogue of
//! `graphus_bolt::executor` (`04-technical-design.md` §8.3 "one executor, one value model"; §7.7
//! result streaming; rmp #20 wires graphus-cypher's `TxnCoordinator` behind it).
//!
//! `graphus-rest` knows nothing about parsing, planning, MVCC, or storage. It only needs something
//! that turns statements into a stream of result rows, inside an explicit or auto-commit
//! transaction. That contract is [`RestEngine`]. The engine (rmp #20, via `graphus-cypher`)
//! implements it; tests here implement a mock engine.
//!
//! ## Why this mirrors the Bolt seam rather than reusing it
//!
//! Bolt and REST converge on **one executor** in the real server (`04 §8.3`): rmp #20 wires the same
//! `graphus-cypher` coordinator behind both `graphus_bolt`'s `BoltExecutor` and
//! [`RestEngine`]. The two seams are kept as separate traits (not one shared trait) because the two
//! protocols drive a transaction differently: Bolt is a stateful per-connection message stream
//! (`BEGIN`/`RUN`/`PULL`/`COMMIT` on one socket), whereas REST is **stateless request/response** —
//! an HTTP request names its transaction by URL and may land on any worker. So the REST seam is
//! keyed by an explicit [`TxHandle`] passed on every call, rather than the implicit
//! "currently-open transaction" the Bolt session owns. Both seams speak the same
//! [`graphus_core::Value`] and [`GraphusError`], so the engine behind them is one.
//!
//! ## Why rows are `graphus_core::Value`
//!
//! `04 §8.3` mandates **one `Value` model** behind every listener: parameters in and result cells
//! out are the same [`graphus_core::Value`]. The executor carries a richer internal cell type
//! through its operators but **projects** down to the public `Value` model at the result boundary —
//! which is exactly the seam this trait sits on. So a [`ResultStream`] row is a `Vec<Value>`.
//!
//! ## Streaming (`04 §7.7`, §8.2)
//!
//! [`ResultStream::next_row`] is **pull-based**: the router calls it once per row it serialises,
//! which is the HTTP analogue of Bolt's `PULL n`. This is what lets a large result stream out as
//! NDJSON with bounded memory ([`crate::router`](mod@crate::router)) instead of being buffered
//! whole.

use graphus_core::{GraphusError, Value};

/// The access mode of a transaction (`06 §4`; mirrors `graphus_bolt`'s `AccessMode`).
///
/// REST declares it through the `access_mode` request member (`"READ"` / `"WRITE"`), defaulting to
/// [`AccessMode::Write`] when absent (`06 §4`). A [`AccessMode::Read`] transaction rejects write
/// statements.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum AccessMode {
    /// Read-only: write statements are rejected (`06 §4` enforcement).
    Read,
    /// Read-write (the default when `access_mode` is absent — `06 §4`).
    #[default]
    Write,
}

impl AccessMode {
    /// The canonical wire spelling (`"READ"` / `"WRITE"`), as sent in the `access_mode` member.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Read => "READ",
            Self::Write => "WRITE",
        }
    }
}

/// A single result row: the row's cells in the order declared by [`ResultStream::fields`].
pub type Row = Vec<Value>;

/// The summary metadata for a finished result, surfaced after the rows (the REST analogue of the
/// trailing Bolt `SUCCESS` summary — `06 §3.1`).
///
/// v1 carries the query `type` (e.g. `"r"`, `"rw"`, `"w"`, `"s"`) and a `stats` map of side-effect
/// counters; richer summary fields (plan, profile, notifications) are added as the executor exposes
/// them.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct RunSummary {
    /// The query type code for the `type` summary key (`"r"`/`"rw"`/`"w"`/`"s"`), if known.
    pub query_type: Option<String>,
    /// Side-effect counters for the `stats` summary key (e.g. `nodes-created`), in order.
    pub stats: Vec<(String, Value)>,
}

/// A lazily-produced stream of result rows for one statement (`04 §7.7`).
///
/// The router pulls rows one at a time with [`ResultStream::next_row`]; when the stream is
/// exhausted, `next_row` returns `Ok(None)` and the router then reads [`ResultStream::summary`].
/// Field names are fixed before the first row (the executor knows the projection's columns up
/// front) and read once via [`ResultStream::fields`].
pub trait ResultStream {
    /// The result column names, in order — the `fields` of the result envelope.
    fn fields(&self) -> &[String];

    /// Produces the next row, or `Ok(None)` when the result is exhausted.
    ///
    /// # Errors
    /// [`GraphusError`] for a **runtime** error during row production (`06 §2.3`); it may arrive
    /// after some rows have already streamed (`06 §3.3`).
    fn next_row(&mut self) -> Result<Option<Row>, GraphusError>;

    /// The result summary, read after the stream is exhausted.
    ///
    /// Implementations should make it cheap and idempotent.
    fn summary(&self) -> RunSummary;
}

/// An opaque handle to a transaction the engine opened, returned by [`RestEngine::begin`].
///
/// REST is stateless, so the router cannot rely on an "open transaction" living inside the engine
/// the way the Bolt session does. Instead [`RestEngine::begin`] hands back this handle, the router
/// stores it in the [`crate::registry::TxRegistry`] keyed by the public transaction id it minted,
/// and every later `run`/`commit`/`rollback` passes the handle back so the engine can resume the
/// right transaction. It is deliberately a thin newtype over a `u64` ticket the engine assigns; the
/// public, URL-facing id is a separate value the router owns (so the engine's internal ticket is
/// never exposed to clients).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TxHandle(pub u64);

/// The query-execution interface the REST router drives (`04 §8.3`; rmp #20).
///
/// One instance backs the whole REST listener (it is shared across requests behind the router's
/// state). The router calls:
///
/// - [`begin`](RestEngine::begin) for `POST /db/{db}/tx`, getting a [`TxHandle`] it tracks;
/// - [`run`](RestEngine::run) for statements in an open tx or the auto-commit shortcut, getting a
///   [`ResultStream`] it pulls rows from;
/// - [`commit`](RestEngine::commit) / [`rollback`](RestEngine::rollback) to finish an explicit tx.
///
/// All methods return the engine's [`GraphusError`] on failure, which the router maps to an RFC 9457
/// problem+json response via [`crate::problem::Problem::from_graphus_error`] (`06 §3.3`).
///
/// ## Thread-safety
///
/// axum shares one piece of state across all worker tasks, so the engine is held as
/// `Arc<dyn RestEngine>` and must be `Send + Sync`. The methods take `&self` (not `&mut self`,
/// unlike the per-connection `graphus_bolt` `BoltExecutor`) precisely because many in-flight HTTP
/// requests share the one engine; the engine manages its own interior synchronisation (the real
/// coordinator funnels writes through the sharded ACID path — `04 §9.1`).
pub trait RestEngine: Send + Sync {
    /// The concrete result stream this engine yields. (An associated type keeps the seam free of
    /// per-row boxing; the engine picks its cursor type.)
    type Stream: ResultStream;

    /// Opens an explicit transaction against `db` in `mode`, returning its [`TxHandle`].
    ///
    /// # Errors
    /// [`GraphusError::Transaction`] if a transaction cannot be started, or
    /// [`GraphusError::Storage`] if `db` does not exist.
    fn begin(&self, db: &str, mode: AccessMode) -> Result<TxHandle, GraphusError>;

    /// Runs `query` with `parameters` inside the transaction identified by `tx`, returning a lazy
    /// result stream.
    ///
    /// `tx` is the handle from a prior [`begin`](RestEngine::begin). For the auto-commit shortcut
    /// (`POST /db/{db}/tx/commit`) the router opens a transaction, runs, then commits — so this is
    /// always called against a live handle.
    ///
    /// # Errors
    /// [`GraphusError::Compile`] for a compile-time error (raised before any row — `06 §2.1`),
    /// [`GraphusError::Runtime`] for an immediate runtime error, or [`GraphusError::Transaction`]
    /// if `tx` is unknown or a **write statement is run in a `READ` transaction** (`06 §4`).
    fn run(
        &self,
        tx: TxHandle,
        query: &str,
        parameters: Vec<(String, Value)>,
    ) -> Result<Self::Stream, GraphusError>;

    /// Commits the transaction identified by `tx`.
    ///
    /// # Errors
    /// [`GraphusError::Transaction`] if `tx` is unknown, or on a serialization failure (retriable;
    /// `04 §5.4`).
    fn commit(&self, tx: TxHandle) -> Result<RunSummary, GraphusError>;

    /// Rolls back the transaction identified by `tx`.
    ///
    /// Rolling back an unknown handle is **not** an error: rollback is idempotent so the registry's
    /// inactivity sweep (`04 §8.2`) and an explicit `DELETE` can both target the same handle without
    /// racing into a spurious failure.
    ///
    /// # Errors
    /// [`GraphusError::Transaction`] only for a genuine engine fault while rolling back.
    fn rollback(&self, tx: TxHandle) -> Result<(), GraphusError>;
}

#[cfg(test)]
pub(crate) mod mock {
    //! A scriptable in-memory [`RestEngine`] for the router tests.
    //!
    //! It records the lifecycle calls it receives (`begin`/`run`/`commit`/`rollback`) so tests can
    //! assert the router drove the seam correctly (e.g. that `DELETE` rolled back, that the
    //! auto-commit shortcut both ran and committed), and it enforces the `READ`-rejects-write rule so
    //! the access-mode test exercises real seam behaviour rather than a router-only check.

    use std::collections::HashMap;
    use std::sync::Mutex;

    use graphus_core::{GraphusError, Value};

    use super::{AccessMode, RestEngine, ResultStream, Row, RunSummary, TxHandle};

    /// A canned result: the fields and the rows to stream (or an error to raise on `run`).
    #[derive(Clone)]
    pub struct Canned {
        pub fields: Vec<String>,
        pub rows: Vec<Row>,
        pub summary: RunSummary,
    }

    impl Canned {
        /// Canned rows with the given field names and a default read summary.
        pub fn rows(fields: &[&str], rows: Vec<Row>) -> Self {
            Self {
                fields: fields.iter().map(|s| (*s).to_owned()).collect(),
                rows,
                summary: RunSummary {
                    query_type: Some("r".to_owned()),
                    stats: Vec::new(),
                },
            }
        }
    }

    /// The mock's per-transaction state.
    struct TxState {
        mode: AccessMode,
        committed: bool,
    }

    /// A scriptable engine. Maps an exact query string → canned result (or error); any unscripted
    /// query yields an empty result. Treats a query starting (case-insensitively) with `CREATE`,
    /// `MERGE`, `SET`, or `DELETE` as a *write* for the `READ`-rejects-write rule.
    #[derive(Default)]
    pub struct MockEngine {
        results: HashMap<String, Canned>,
        errors: HashMap<String, GraphusError>,
        inner: Mutex<Inner>,
    }

    #[derive(Default)]
    struct Inner {
        next_handle: u64,
        txns: HashMap<u64, TxState>,
        /// The ordered log of lifecycle calls, for test assertions.
        log: Vec<String>,
    }

    impl MockEngine {
        #[must_use]
        pub fn new() -> Self {
            Self::default()
        }

        /// Canned rows for an exact query string.
        #[must_use]
        pub fn on_query(mut self, query: &str, result: Canned) -> Self {
            self.results.insert(query.to_owned(), result);
            self
        }

        /// A `GraphusError` raised when `query` runs (e.g. a compile error).
        #[must_use]
        pub fn on_query_error(mut self, query: &str, err: GraphusError) -> Self {
            self.errors.insert(query.to_owned(), err);
            self
        }

        /// A snapshot of the lifecycle-call log, for assertions.
        pub fn log(&self) -> Vec<String> {
            self.inner
                .lock()
                .expect("INVARIANT: log mutex un-poisoned")
                .log
                .clone()
        }

        /// Whether a write query (`CREATE`/`MERGE`/`SET`/`DELETE` prefix) — used by the
        /// `READ`-rejects-write rule.
        fn is_write(query: &str) -> bool {
            let head = query.trim_start().to_ascii_uppercase();
            ["CREATE", "MERGE", "SET", "DELETE", "REMOVE"]
                .iter()
                .any(|kw| head.starts_with(kw))
        }
    }

    /// The mock's [`ResultStream`]: drains a `Vec` of canned rows.
    #[derive(Debug)]
    pub struct MockStream {
        fields: Vec<String>,
        rows: std::vec::IntoIter<Row>,
        summary: RunSummary,
    }

    impl ResultStream for MockStream {
        fn fields(&self) -> &[String] {
            &self.fields
        }

        fn next_row(&mut self) -> Result<Option<Row>, GraphusError> {
            Ok(self.rows.next())
        }

        fn summary(&self) -> RunSummary {
            self.summary.clone()
        }
    }

    impl RestEngine for MockEngine {
        type Stream = MockStream;

        fn begin(&self, db: &str, mode: AccessMode) -> Result<TxHandle, GraphusError> {
            let mut inner = self.inner.lock().expect("INVARIANT: mutex un-poisoned");
            inner.next_handle += 1;
            let h = inner.next_handle;
            inner
                .log
                .push(format!("begin(db={db}, mode={mode:?}) -> {h}"));
            inner.txns.insert(
                h,
                TxState {
                    mode,
                    committed: false,
                },
            );
            Ok(TxHandle(h))
        }

        fn run(
            &self,
            tx: TxHandle,
            query: &str,
            _parameters: Vec<(String, Value)>,
        ) -> Result<Self::Stream, GraphusError> {
            {
                let mut inner = self.inner.lock().expect("INVARIANT: mutex un-poisoned");
                inner.log.push(format!("run(tx={}, q={query})", tx.0));
                let Some(state) = inner.txns.get(&tx.0) else {
                    return Err(GraphusError::Transaction(format!(
                        "unknown transaction handle {}",
                        tx.0
                    )));
                };
                // `06 §4`: a READ transaction rejects any write statement.
                if state.mode == AccessMode::Read && Self::is_write(query) {
                    return Err(GraphusError::Transaction(
                        "writing in read-only transaction is not allowed".to_owned(),
                    ));
                }
            }
            if let Some(err) = self.errors.get(query) {
                return Err(clone_error(err));
            }
            let canned = self
                .results
                .get(query)
                .cloned()
                .unwrap_or_else(|| Canned::rows(&[], vec![]));
            Ok(MockStream {
                fields: canned.fields,
                rows: canned.rows.into_iter(),
                summary: canned.summary,
            })
        }

        fn commit(&self, tx: TxHandle) -> Result<RunSummary, GraphusError> {
            let mut inner = self.inner.lock().expect("INVARIANT: mutex un-poisoned");
            inner.log.push(format!("commit(tx={})", tx.0));
            match inner.txns.get_mut(&tx.0) {
                Some(state) => {
                    state.committed = true;
                    Ok(RunSummary::default())
                }
                None => Err(GraphusError::Transaction(format!(
                    "unknown transaction handle {}",
                    tx.0
                ))),
            }
        }

        fn rollback(&self, tx: TxHandle) -> Result<(), GraphusError> {
            let mut inner = self.inner.lock().expect("INVARIANT: mutex un-poisoned");
            inner.log.push(format!("rollback(tx={})", tx.0));
            // Idempotent: rolling back an unknown/closed handle is a no-op success.
            inner.txns.remove(&tx.0);
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
    use super::mock::{Canned, MockEngine};
    use super::*;

    #[test]
    fn access_mode_defaults_to_write() {
        assert_eq!(AccessMode::default(), AccessMode::Write);
        assert_eq!(AccessMode::Write.as_str(), "WRITE");
        assert_eq!(AccessMode::Read.as_str(), "READ");
    }

    #[test]
    fn mock_streams_canned_rows_then_summary() {
        let engine = MockEngine::new().on_query(
            "RETURN 1",
            Canned::rows(&["x"], vec![vec![Value::Integer(1)]]),
        );
        let tx = engine.begin("neo4j", AccessMode::Read).unwrap();
        let mut stream = engine.run(tx, "RETURN 1", vec![]).unwrap();
        assert_eq!(stream.fields(), &["x".to_owned()]);
        assert_eq!(stream.next_row().unwrap(), Some(vec![Value::Integer(1)]));
        assert_eq!(stream.next_row().unwrap(), None);
        assert_eq!(stream.summary().query_type.as_deref(), Some("r"));
    }

    #[test]
    fn mock_read_tx_rejects_write_statement() {
        let engine = MockEngine::new();
        let tx = engine.begin("neo4j", AccessMode::Read).unwrap();
        let err = engine.run(tx, "CREATE (n)", vec![]).unwrap_err();
        assert!(matches!(err, GraphusError::Transaction(_)));
    }

    #[test]
    fn mock_tracks_lifecycle_and_rollback_is_idempotent() {
        let engine = MockEngine::new();
        let tx = engine.begin("neo4j", AccessMode::Write).unwrap();
        engine.run(tx, "RETURN 1", vec![]).unwrap();
        engine.rollback(tx).unwrap();
        // Rolling back again (e.g. the inactivity sweep racing a DELETE) is still Ok.
        engine.rollback(tx).unwrap();
        let log = engine.log();
        assert!(log.iter().any(|l| l.starts_with("begin")));
        assert!(log.iter().any(|l| l.starts_with("run")));
        assert_eq!(log.iter().filter(|l| l.starts_with("rollback")).count(), 2);
    }
}
