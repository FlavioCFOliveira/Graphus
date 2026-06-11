//! The engine driver: runs one Cypher statement end to end over a real [`RecordStore`] wrapped in a
//! [`TxnCoordinator`], through the exact pipeline the rest of Graphus uses
//! (`crates/graphus-tck/src/runner.rs`, `crates/graphus-cypher/tests/record_store_graph.rs`):
//!
//! ```text
//! tokenize → parse_tokens → analyze → lower → plan_physical_with_stats(coord.statistics())
//!          → bind_parameters
//!          → coord.begin(_serializable) → coord.statement → execute → collect_all → commit
//! ```
//!
//! Planning is **stats-aware** (`rmp` task #82): the coordinator's statistics seam feeds the
//! cost-based optimiser (`rmp` task #65) exactly as the production server does, so the benchmark
//! measures the plans real deployments run.
//!
//! A statement that fails at any stage (lex / parse / analyze / bind / execute, or a captured
//! deferred store error) is rolled back and surfaced as [`RunError`] — the harness reports such a
//! query as *deferred* (an unsupported Cypher form for this young engine) rather than crashing, so
//! the macro benchmark always runs to completion and is honest about coverage.

use std::time::{Duration, Instant};

use graphus_core::Value;
use graphus_cypher::TxnCoordinator;
use graphus_cypher::binding::{Parameters, bind_parameters};
use graphus_cypher::executor::execute;
use graphus_cypher::lexer::tokenize;
use graphus_cypher::lower::lower;
use graphus_cypher::parser::parse_tokens;
use graphus_cypher::physical::plan_physical_with_stats;
use graphus_cypher::runtime::Row;
use graphus_cypher::semantics::analyze;
use graphus_io::MemBlockDevice;
use graphus_storage::RecordStore;
use graphus_txn::IsolationLevel;
use graphus_wal::{MemLogSink, WalManager};

/// The store type the harness runs over: a real [`RecordStore`] on the in-memory
/// Deterministic-Simulation-Testing device + log sink — identical construction to the engine's own
/// end-to-end tests, so the commit path exercises the real WAL group-commit serialization point with
/// no disk noise.
pub type Store = RecordStore<MemBlockDevice, MemLogSink>;

/// The coordinator type over that store (the production transaction seam, `rmp` task #46).
pub type Coord = TxnCoordinator<MemBlockDevice, MemLogSink>;

/// A fresh, empty record store on an in-memory DST device + log (copied from
/// `crates/graphus-cypher/tests/record_store_graph.rs::fresh_store`, the canonical construction).
///
/// # Panics
/// Panics if store creation fails — a harness fixture, so a failure is a programming error, not a
/// condition to handle (mirrors the project `unwrap` policy for fatal init).
#[must_use]
pub fn fresh_store() -> Store {
    let device = MemBlockDevice::new(0);
    let wal = WalManager::create(MemLogSink::new()).expect("create wal");
    RecordStore::create(device, wal, 4096, 1).expect("create store")
}

/// A fresh coordinator wrapping a fresh store.
#[must_use]
pub fn fresh_coord() -> Coord {
    TxnCoordinator::new(fresh_store())
}

/// The outcome of running one statement: the result rows and the wall-clock latency of the whole
/// statement (compile + execute + commit), or a classified failure.
pub struct StatementResult {
    /// The result rows the query produced (empty for a write-only statement).
    pub rows: Vec<Row>,
    /// End-to-end latency of the statement (compile → execute → commit).
    pub latency: Duration,
}

/// A classified statement failure. The harness treats every one as "this Cypher form is not yet
/// supported by the engine" — it never panics the run.
#[derive(Debug, Clone)]
pub enum RunError {
    /// Lex / parse / semantic analysis rejected the query (an unsupported syntactic/semantic form).
    Compile(String),
    /// Parameter binding failed.
    Bind(String),
    /// The executor returned an error, or a deferred store error was captured on the seam.
    Execute(String),
    /// The commit itself failed (e.g. an SSI abort under contention).
    Commit(String),
}

impl std::fmt::Display for RunError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RunError::Compile(m) => write!(f, "compile: {m}"),
            RunError::Bind(m) => write!(f, "bind: {m}"),
            RunError::Execute(m) => write!(f, "execute: {m}"),
            RunError::Commit(m) => write!(f, "commit: {m}"),
        }
    }
}

/// Runs `src` with `params` at the given isolation level through the full pipeline, committing on
/// success and rolling back on any failure. Returns the rows + latency, or a classified [`RunError`].
///
/// This is the single choke point every LDBC operation and the graph generator go through, so the
/// benchmark and the data load exercise exactly the production transaction path.
pub fn run_statement(
    coord: &mut Coord,
    src: &str,
    params: &Parameters,
    isolation: IsolationLevel,
) -> Result<StatementResult, RunError> {
    let start = Instant::now();

    // ---- compile (lex → parse → analyze → lower → physical plan) -------------------------------
    let tokens = tokenize(src).map_err(|e| RunError::Compile(e.to_string()))?;
    let ast = parse_tokens(&tokens, src).map_err(|e| RunError::Compile(e.to_string()))?;
    let validated = analyze(&ast).map_err(|e| RunError::Compile(e.to_string()))?;
    // Stats-aware planning (`rmp` task #82): the same cost-based optimiser path the server runs.
    let stats = coord.statistics();
    let plan = plan_physical_with_stats(&lower(&validated), &coord.catalog(), Some(&stats));
    let bound = bind_parameters(&plan, params).map_err(|e| RunError::Bind(e.to_string()))?;

    // ---- run inside one transaction ------------------------------------------------------------
    let txn = coord.begin(isolation);
    let run: Result<Vec<Row>, RunError> = (|| {
        let mut graph = coord
            .statement(txn)
            .map_err(|e| RunError::Execute(e.to_string()))?;
        let rows = {
            let mut cursor =
                execute(&plan, &bound, &mut graph).map_err(|e| RunError::Execute(e.to_string()))?;
            cursor
                .collect_all()
                .map_err(|e| RunError::Execute(e.to_string()))?
        };
        // A deferred store error (e.g. a non-storable property subtype) is captured on the seam
        // rather than returned; surface it as an execute failure.
        if graph.has_error() {
            return Err(RunError::Execute(format!(
                "captured store error: {:?}",
                graph.take_error()
            )));
        }
        Ok(rows)
    })();

    match run {
        Ok(rows) => {
            coord
                .commit(txn)
                .map_err(|e| RunError::Commit(e.to_string()))?;
            Ok(StatementResult {
                rows,
                latency: start.elapsed(),
            })
        }
        Err(e) => {
            let _ = coord.rollback(txn);
            Err(e)
        }
    }
}

/// Convenience: run a parameter-free write/seed statement at `SERIALIZABLE`, discarding rows.
///
/// Used by the graph generator, where every statement is a `CREATE` that must succeed; a failure is
/// a generator bug and is surfaced to the caller.
pub fn run_write(coord: &mut Coord, src: &str) -> Result<Duration, RunError> {
    run_statement(coord, src, &Parameters::new(), IsolationLevel::Serializable).map(|r| r.latency)
}

/// Extracts the first row's named column as an [`i64`], if present and integer-typed. A small helper
/// the operations use to sanity-check aggregate results (e.g. a `count(*)`).
#[must_use]
pub fn first_i64(rows: &[Row], col: &str) -> Option<i64> {
    match rows.first().map(|r| r.value(col)) {
        Some(Value::Integer(v)) => Some(v),
        _ => None,
    }
}
