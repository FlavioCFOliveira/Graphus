//! [`graphus_bolt::BoltExecutor`] over the engine channel — the thin client one Bolt connection uses
//! (`04-technical-design.md` §8.3 one executor, §9.1 the shard funnel).
//!
//! `graphus_bolt::BoltSession` owns one `BoltExecutor` for the connection's lifetime and calls it
//! with `&mut self` as it drives `BEGIN`/`RUN`/`COMMIT`/`ROLLBACK`. So this adapter is **per
//! connection**: it tracks the connection's single current explicit transaction (the engine keys
//! every transaction by an opaque [`TxTicket`]). All execution is funnelled to the single engine
//! task via the shared [`EngineHandle`]; this type adds only the per-connection transaction state and
//! the admission gate.
//!
//! The Bolt session runs on a **blocking task** (see the `listeners::bolt` module), so this adapter
//! uses the handle's `*_blocking` submit methods — they may park the blocking thread on the bounded
//! channel (the intended backpressure), never a Tokio runtime worker (`04 §9.1`).

use graphus_bolt::executor::{
    AccessMode as BoltAccessMode, BoltExecutor, QuerySummary, Record, RecordStream, TxControl,
};
use graphus_core::{GraphusError, Value};

use super::command::AccessMode;
use super::handle::AdmissionPermit;
use super::stream::RowReceiver;
use super::{EngineHandle, RunSummary, TxTicket};

/// One Bolt connection's view of the engine: the shared handle plus this connection's current
/// explicit transaction (if a `BEGIN` is open).
pub struct BoltEngineExecutor {
    handle: EngineHandle,
    /// The open explicit transaction's ticket, set on `BEGIN`, cleared on `COMMIT`/`ROLLBACK`.
    current_tx: Option<TxTicket>,
}

impl BoltEngineExecutor {
    /// A fresh per-connection executor over the shared engine `handle`.
    #[must_use]
    pub fn new(handle: EngineHandle) -> Self {
        Self {
            handle,
            current_tx: None,
        }
    }
}

/// Maps the Bolt crate's access mode onto the engine's neutral one.
fn from_bolt_mode(mode: BoltAccessMode) -> AccessMode {
    match mode {
        BoltAccessMode::Read => AccessMode::Read,
        BoltAccessMode::Write => AccessMode::Write,
    }
}

/// Maps the engine's neutral summary onto the Bolt crate's.
fn to_bolt_summary(s: RunSummary) -> QuerySummary {
    QuerySummary {
        query_type: s.query_type,
        stats: s.stats,
    }
}

/// The Bolt result stream backing the engine: pulls rows from the engine's bounded channel and holds
/// the admission permit until exhausted/dropped (so a slot is occupied for the whole result).
pub struct BoltEngineStream {
    fields: Vec<String>,
    rows: RowReceiver,
    summary: QuerySummary,
    /// Held for the stream's lifetime; dropping it releases the admission slot (`04 §9.3`).
    _permit: AdmissionPermit,
}

impl RecordStream for BoltEngineStream {
    fn fields(&self) -> &[String] {
        &self.fields
    }

    fn next_record(&mut self) -> Result<Option<Record>, GraphusError> {
        self.rows.next()
    }

    fn summary(&self) -> QuerySummary {
        self.summary.clone()
    }
}

impl BoltExecutor for BoltEngineExecutor {
    type Stream = BoltEngineStream;

    fn run(
        &mut self,
        query: &str,
        parameters: Vec<(String, Value)>,
        tx: TxControl,
    ) -> Result<Self::Stream, GraphusError> {
        // Admission control first: fast-reject when saturated (`04 §9.3`). The permit is held by the
        // returned stream for the whole result.
        let permit = self
            .handle
            .try_admit()
            .map_err(|busy| GraphusError::Transaction(busy.to_string()))?;

        // Resolve which transaction to run in.
        let (ticket, auto_commit) = match tx {
            TxControl::AutoCommit { mode } => {
                // Open an internal auto-commit transaction the engine finalises on stream drain.
                let ticket = self
                    .handle
                    .begin_auto_commit_blocking(from_bolt_mode(mode))?;
                (ticket, true)
            }
            TxControl::InExplicit => {
                let ticket = self.current_tx.ok_or_else(|| {
                    GraphusError::Transaction(
                        "RUN in explicit transaction but none is open".to_owned(),
                    )
                })?;
                (ticket, false)
            }
        };

        let reply = self
            .handle
            .run_blocking(ticket, query.to_owned(), parameters, auto_commit)?;
        Ok(BoltEngineStream {
            fields: reply.fields,
            rows: reply.rows,
            // v1 summary: the query type is not yet surfaced by the executor; an empty summary is a
            // valid `SUCCESS` body (`06 §3.1`). Richer summaries arrive with executor stats.
            summary: QuerySummary::default(),
            _permit: permit,
        })
    }

    fn begin(&mut self, mode: BoltAccessMode) -> Result<(), GraphusError> {
        if self.current_tx.is_some() {
            return Err(GraphusError::Transaction(
                "a transaction is already open".to_owned(),
            ));
        }
        let ticket = self.handle.begin_blocking(from_bolt_mode(mode))?;
        self.current_tx = Some(ticket);
        Ok(())
    }

    fn commit(&mut self) -> Result<QuerySummary, GraphusError> {
        let ticket = self.current_tx.take().ok_or_else(|| {
            GraphusError::Transaction("COMMIT with no open transaction".to_owned())
        })?;
        let summary = self.handle.commit_blocking(ticket)?;
        Ok(to_bolt_summary(summary))
    }

    fn rollback(&mut self) -> Result<(), GraphusError> {
        let ticket = self.current_tx.take().ok_or_else(|| {
            GraphusError::Transaction("ROLLBACK with no open transaction".to_owned())
        })?;
        self.handle.rollback_blocking(ticket)
    }
}
