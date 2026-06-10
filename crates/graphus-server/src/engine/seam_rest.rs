//! [`graphus_rest::RestEngine`] over the engine channel — the thin client the REST router uses
//! (`04-technical-design.md` §8.3 one executor, §9.1 the shard funnel).
//!
//! Unlike the Bolt seam, the REST seam is **shared** (`Arc<dyn RestEngine>`) across all in-flight
//! requests and is `Send + Sync` with `&self` methods, because REST is stateless: a request names its
//! transaction by URL ([`graphus_rest::TxHandle`]) and may land on any worker. So this adapter holds
//! no per-connection state — only the shared [`EngineHandle`] — and maps the router's `TxHandle`
//! 1:1 onto the engine's [`TxTicket`] (both `u64` newtypes).
//!
//! The router's row-pull (`ResultStream::next_row`) and the `run`/`commit`/`rollback` calls are
//! synchronous; the server drives each REST connection's router future to completion on a
//! `spawn_blocking` thread (see [`crate::listeners::rest`]), so these blocking submits never park a
//! Tokio runtime worker (`04 §9.1`).

use graphus_core::{GraphusError, Value};
use graphus_rest::engine::{
    AccessMode as RestAccessMode, RestEngine, ResultStream, Row, RunSummary as RestRunSummary,
    TxHandle,
};

use super::command::AccessMode;
use super::handle::AdmissionPermit;
use super::stream::RowReceiver;
use super::{EngineHandle, RunSummary, TxTicket};

/// The shared REST engine: a wrapper over the engine handle (held behind an `Arc` by the router).
pub struct RestEngineAdapter {
    handle: EngineHandle,
}

impl RestEngineAdapter {
    /// A REST engine over the shared engine `handle`.
    #[must_use]
    pub fn new(handle: EngineHandle) -> Self {
        Self { handle }
    }
}

/// Maps the REST crate's access mode onto the engine's neutral one.
fn from_rest_mode(mode: RestAccessMode) -> AccessMode {
    match mode {
        RestAccessMode::Read => AccessMode::Read,
        RestAccessMode::Write => AccessMode::Write,
    }
}

/// Maps the engine's neutral summary onto the REST crate's.
fn to_rest_summary(s: RunSummary) -> RestRunSummary {
    RestRunSummary {
        query_type: s.query_type,
        stats: s.stats,
    }
}

/// The REST result stream: pulls rows from the engine's bounded channel and holds the admission
/// permit until exhausted/dropped.
pub struct RestEngineStream {
    fields: Vec<String>,
    rows: RowReceiver,
    summary: RestRunSummary,
    /// Held for the stream's lifetime; dropping it releases the admission slot (`04 §9.3`).
    _permit: AdmissionPermit,
}

impl ResultStream for RestEngineStream {
    fn fields(&self) -> &[String] {
        &self.fields
    }

    fn next_row(&mut self) -> Result<Option<Row>, GraphusError> {
        self.rows.next()
    }

    fn summary(&self) -> RestRunSummary {
        self.summary.clone()
    }
}

impl RestEngine for RestEngineAdapter {
    type Stream = RestEngineStream;

    fn begin(&self, _db: &str, mode: RestAccessMode) -> Result<TxHandle, GraphusError> {
        // v1 is single-database; the `{db}` path segment is informational (`04 §8.2`). The ticket the
        // engine mints is the router's opaque handle.
        let ticket = self.handle.begin_blocking(from_rest_mode(mode))?;
        Ok(TxHandle(ticket.0))
    }

    fn run(
        &self,
        tx: TxHandle,
        query: &str,
        parameters: Vec<(String, Value)>,
    ) -> Result<Self::Stream, GraphusError> {
        // Admission control first: fast-reject when saturated (`04 §9.3`). The router maps the error
        // to a `503` problem+json; the permit is held by the returned stream for the whole result.
        let permit = self
            .handle
            .try_admit()
            .map_err(|busy| GraphusError::Transaction(busy.to_string()))?;

        // REST always runs against an already-open handle (the router opens the auto-commit
        // transaction itself for the commit shortcut), so this is never auto-commit at the engine.
        let reply = self.handle.run_blocking(
            TxTicket(tx.0),
            query.to_owned(),
            parameters,
            /* auto_commit */ false,
        )?;
        Ok(RestEngineStream {
            fields: reply.fields,
            rows: reply.rows,
            summary: RestRunSummary::default(),
            _permit: permit,
        })
    }

    fn commit(&self, tx: TxHandle) -> Result<RestRunSummary, GraphusError> {
        let summary = self.handle.commit_blocking(TxTicket(tx.0))?;
        Ok(to_rest_summary(summary))
    }

    fn rollback(&self, tx: TxHandle) -> Result<(), GraphusError> {
        // Idempotent at the engine (an unknown ticket is `Ok(())`), matching the trait contract.
        self.handle.rollback_blocking(TxTicket(tx.0))
    }
}
