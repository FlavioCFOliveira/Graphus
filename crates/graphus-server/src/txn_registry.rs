//! The server-wide **live transaction registry** (`rmp` #637), backing `SHOW TRANSACTIONS` and
//! `TERMINATE TRANSACTIONS`.
//!
//! # What it tracks
//!
//! Graphus has no single place that knows every open transaction: the per-database engine runs on
//! its own thread and both connectivity seams (Bolt-over-UDS/TCP and REST) keep their own
//! per-connection transaction state. This registry is the one shared, cross-seam view of the
//! **explicit (managed) transactions** — the ones a client opens with `BEGIN` (Bolt) or
//! `POST …/tx` (REST) and later `COMMIT`/`ROLLBACK`s. Each seam [`register`](TransactionRegistry::register)s
//! a transaction when it begins and lets the returned [`TxnGuard`] deregister it (RAII) on
//! commit/rollback/drop, so a dropped connection can never leak an entry.
//!
//! Transient **auto-commit** statements (a bare `RUN`/single-statement `POST …/tx/commit`) are
//! deliberately **not** registered: they live for a single statement, are frequently dispatched
//! off-thread to the reader pool, and are never the target of an operator's `SHOW`/`TERMINATE`.
//! This mirrors what an administrator cares about — long-running or idle-in-transaction managed
//! transactions.
//!
//! # Identity
//!
//! Every entry gets a process-unique, monotonic id rendered Neo4j-style as
//! `"<database>-transaction-<n>"` (e.g. `"graphus-transaction-42"`). The numeric part is globally
//! unique (a single server-wide counter), so `TERMINATE TRANSACTIONS '<id>'` addresses exactly one
//! transaction even across databases.
//!
//! # Termination
//!
//! [`terminate`](TransactionRegistry::terminate) sets a per-transaction `terminated` flag (an
//! [`AtomicBool`]). The owning seam observes it — at each statement boundary via
//! [`TxnGuard::is_terminated`], and (where wired) through the executor's cancellation token for an
//! in-flight statement — then rolls the transaction back and fails the client's next interaction.
//! The registry itself performs **no** engine I/O: it is pure, lock-guarded bookkeeping, so it can
//! be shared cheaply by every seam without touching the single-threaded engine.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};

use crate::audit::AuditSource;
use crate::engine::AccessMode;

/// The rendered protocol label for a transaction's originating seam.
#[must_use]
fn protocol_label(source: AuditSource) -> &'static str {
    match source {
        AuditSource::BoltUds => "bolt-uds",
        AuditSource::BoltTcp => "bolt-tcp",
        AuditSource::Rest => "http",
        AuditSource::Internal => "internal",
    }
}

/// Immutable + interior-mutable state of one live explicit transaction. Shared (`Arc`) between the
/// owning seam (which updates the current query and observes termination) and the registry (which
/// enumerates and terminates).
#[derive(Debug)]
struct TxnHandle {
    /// The client-facing id string, `"<database>-transaction-<n>"`.
    id: String,
    /// The numeric id (globally unique, monotonic).
    seq: u64,
    /// The target database.
    database: String,
    /// The authenticated principal (user), if any.
    principal: Option<String>,
    /// The originating seam (protocol).
    source: AuditSource,
    /// The transaction access mode (READ / WRITE).
    mode: AccessMode,
    /// The peer/client address, if the seam supplied one (`None` when not tracked).
    client_address: Option<String>,
    /// Monotonic start instant, for the elapsed time.
    started_instant: Instant,
    /// Wall-clock start, for the reported `startTime`.
    started_wall: SystemTime,
    /// The most recently executed statement text (the "current query"); `None` before the first
    /// statement runs in the transaction.
    current_query: Mutex<Option<String>>,
    /// Set to `true` by [`TransactionRegistry::terminate`]; observed by the owning seam.
    terminated: AtomicBool,
}

/// A read-only snapshot of one live transaction, for `SHOW TRANSACTIONS`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TxnSnapshot {
    /// The client-facing transaction id (`"<database>-transaction-<n>"`).
    pub id: String,
    /// The target database.
    pub database: String,
    /// The authenticated principal (user), if any.
    pub username: Option<String>,
    /// The originating protocol label (`"bolt-uds"`, `"bolt-tcp"`, `"http"`).
    pub protocol: &'static str,
    /// The access mode, `"READ"` or `"WRITE"`.
    pub mode: &'static str,
    /// The current/last statement text, if one has run.
    pub current_query: Option<String>,
    /// The transaction status, `"Running"` or `"Terminated"`.
    pub status: &'static str,
    /// Wall-clock start time (UTC).
    pub started_wall: SystemTime,
    /// Elapsed time since the transaction began.
    pub elapsed: Duration,
    /// The client/peer address, if tracked (`None` otherwise).
    pub client_address: Option<String>,
}

impl TxnHandle {
    fn snapshot(&self) -> TxnSnapshot {
        let terminated = self.terminated.load(Ordering::Acquire);
        TxnSnapshot {
            id: self.id.clone(),
            database: self.database.clone(),
            username: self.principal.clone(),
            protocol: protocol_label(self.source),
            mode: match self.mode {
                AccessMode::Read => "READ",
                AccessMode::Write => "WRITE",
            },
            current_query: self
                .current_query
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone(),
            status: if terminated { "Terminated" } else { "Running" },
            started_wall: self.started_wall,
            elapsed: self.started_instant.elapsed(),
            client_address: self.client_address.clone(),
        }
    }
}

/// The shared, server-wide registry of live explicit transactions. Cheap to `Arc`-clone; every
/// connectivity seam holds a clone.
#[derive(Debug, Default)]
pub struct TransactionRegistry {
    /// The live transactions, keyed by numeric id.
    inner: Mutex<HashMap<u64, Arc<TxnHandle>>>,
    /// The monotonic id counter (never reused within a process).
    next_seq: AtomicU64,
}

/// The outcome of a `TERMINATE TRANSACTIONS '<id>'` for one requested id.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TerminateOutcome {
    /// The id as requested by the client.
    pub id: String,
    /// The database of the terminated transaction, if it was found.
    pub database: Option<String>,
    /// The user of the terminated transaction, if it was found.
    pub username: Option<String>,
    /// `"Terminated"` when the id matched a live transaction, `"Transaction not found"` otherwise —
    /// mirroring Neo4j's `message` column.
    pub message: &'static str,
}

impl TransactionRegistry {
    /// Builds an empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers a newly-begun explicit transaction and returns an RAII [`TxnGuard`]. Dropping the
    /// guard (on commit/rollback, or if the connection task ends/panics) deregisters the entry, so
    /// the registry can never leak a stale transaction.
    #[must_use]
    pub fn register(
        self: &Arc<Self>,
        database: &str,
        principal: Option<&str>,
        source: AuditSource,
        mode: AccessMode,
        client_address: Option<String>,
    ) -> TxnGuard {
        let seq = self.next_seq.fetch_add(1, Ordering::Relaxed);
        let id = format!("{database}-transaction-{seq}");
        let handle = Arc::new(TxnHandle {
            id,
            seq,
            database: database.to_owned(),
            principal: principal.map(str::to_owned),
            source,
            mode,
            client_address,
            started_instant: Instant::now(),
            started_wall: SystemTime::now(),
            current_query: Mutex::new(None),
            terminated: AtomicBool::new(false),
        });
        self.lock().insert(seq, Arc::clone(&handle));
        TxnGuard {
            registry: Arc::clone(self),
            handle,
        }
    }

    /// A snapshot of every live transaction, ordered by numeric id (stable, ascending) for a
    /// deterministic `SHOW TRANSACTIONS`.
    #[must_use]
    pub fn snapshot(&self) -> Vec<TxnSnapshot> {
        let mut handles: Vec<Arc<TxnHandle>> = self.lock().values().map(Arc::clone).collect();
        handles.sort_by_key(|h| h.seq);
        handles.iter().map(|h| h.snapshot()).collect()
    }

    /// Marks each requested transaction id for termination, returning one [`TerminateOutcome`] per
    /// requested id (found ⇒ `"Terminated"`, unknown ⇒ `"Transaction not found"`). The flag is set
    /// atomically; the owning seam performs the actual rollback at its next safe point.
    #[must_use]
    pub fn terminate(&self, ids: &[String]) -> Vec<TerminateOutcome> {
        let guard = self.lock();
        ids.iter()
            .map(
                |requested| match guard.values().find(|h| h.id == *requested) {
                    Some(handle) => {
                        handle.terminated.store(true, Ordering::Release);
                        TerminateOutcome {
                            id: requested.clone(),
                            database: Some(handle.database.clone()),
                            username: handle.principal.clone(),
                            message: "Terminated",
                        }
                    }
                    None => TerminateOutcome {
                        id: requested.clone(),
                        database: None,
                        username: None,
                        message: "Transaction not found",
                    },
                },
            )
            .collect()
    }

    /// The number of live transactions (test / observability aid).
    #[must_use]
    pub fn len(&self) -> usize {
        self.lock().len()
    }

    /// Whether the registry currently holds no live transactions.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.lock().is_empty()
    }

    /// Locks the map, recovering from a poisoned lock (a panic while another thread held it must not
    /// wedge the whole registry — the map invariant is preserved regardless).
    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<u64, Arc<TxnHandle>>> {
        self.inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

/// An RAII handle to a registered live transaction. Held by the owning seam for the transaction's
/// lifetime: it updates the current query, checks for termination, and — on drop — removes the
/// transaction from the registry.
#[derive(Debug)]
pub struct TxnGuard {
    registry: Arc<TransactionRegistry>,
    handle: Arc<TxnHandle>,
}

impl TxnGuard {
    /// The client-facing transaction id (`"<database>-transaction-<n>"`).
    #[must_use]
    pub fn id(&self) -> &str {
        &self.handle.id
    }

    /// Records the statement text as this transaction's current/last query (called by the seam on
    /// each `RUN`). The text is stored verbatim; the wire renderers never leak it into the audit log.
    pub fn set_current_query(&self, query: &str) {
        *self
            .handle
            .current_query
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(query.to_owned());
    }

    /// Whether this transaction has been marked for termination by a `TERMINATE TRANSACTIONS`. The
    /// seam polls this at each statement boundary and aborts when it returns `true`.
    #[must_use]
    pub fn is_terminated(&self) -> bool {
        self.handle.terminated.load(Ordering::Acquire)
    }
}

impl Drop for TxnGuard {
    fn drop(&mut self) {
        self.registry.lock().remove(&self.handle.seq);
    }
}

/// The client-facing error a seam returns when it detects that its transaction was terminated by
/// `TERMINATE TRANSACTIONS` (`rmp` #637).
///
/// A **non-retryable** client error ([`GraphusError::Runtime`](graphus_core::GraphusError::Runtime)
/// ⇒ a `Neo.ClientError.*` class, best-effort per `06 §2.4`): the transaction was deliberately
/// killed by an operator, so a driver must **not** auto-retry it (unlike the transient,
/// retryable serialization abort that [`GraphusError::Transaction`](graphus_core::GraphusError::Transaction)
/// carries).
#[must_use]
pub fn terminated_error() -> graphus_core::GraphusError {
    graphus_core::GraphusError::Runtime(
        "the transaction has been terminated by an administrator (TERMINATE TRANSACTIONS)"
            .to_owned(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn reg() -> Arc<TransactionRegistry> {
        Arc::new(TransactionRegistry::new())
    }

    #[test]
    fn register_snapshot_and_raii_deregister() {
        let r = reg();
        assert!(r.is_empty());
        {
            let g = r.register(
                "graphus",
                Some("alice"),
                AuditSource::BoltUds,
                AccessMode::Write,
                None,
            );
            assert_eq!(g.id(), "graphus-transaction-0");
            let snap = r.snapshot();
            assert_eq!(snap.len(), 1);
            assert_eq!(snap[0].id, "graphus-transaction-0");
            assert_eq!(snap[0].database, "graphus");
            assert_eq!(snap[0].username.as_deref(), Some("alice"));
            assert_eq!(snap[0].protocol, "bolt-uds");
            assert_eq!(snap[0].mode, "WRITE");
            assert_eq!(snap[0].status, "Running");
            assert_eq!(snap[0].current_query, None);
        }
        // Guard dropped => deregistered.
        assert!(r.is_empty());
    }

    #[test]
    fn current_query_is_recorded() {
        let r = reg();
        let g = r.register("db", None, AuditSource::Rest, AccessMode::Read, None);
        g.set_current_query("MATCH (n) RETURN n");
        let snap = r.snapshot();
        assert_eq!(snap[0].current_query.as_deref(), Some("MATCH (n) RETURN n"));
        assert_eq!(snap[0].protocol, "http");
        assert_eq!(snap[0].mode, "READ");
    }

    #[test]
    fn terminate_sets_flag_and_reports_outcomes() {
        let r = reg();
        let g = r.register(
            "graphus",
            Some("bob"),
            AuditSource::BoltTcp,
            AccessMode::Write,
            None,
        );
        let id = g.id().to_owned();
        assert!(!g.is_terminated());

        let outcomes = r.terminate(&[id.clone(), "graphus-transaction-999".to_owned()]);
        assert_eq!(outcomes.len(), 2);
        assert_eq!(outcomes[0].id, id);
        assert_eq!(outcomes[0].message, "Terminated");
        assert_eq!(outcomes[0].database.as_deref(), Some("graphus"));
        assert_eq!(outcomes[0].username.as_deref(), Some("bob"));
        assert_eq!(outcomes[1].message, "Transaction not found");
        assert_eq!(outcomes[1].database, None);

        assert!(g.is_terminated());
        // A terminated (still-open) transaction reports the Terminated status.
        assert_eq!(r.snapshot()[0].status, "Terminated");
    }

    #[test]
    fn ids_are_unique_and_monotonic_across_databases() {
        let r = reg();
        let g0 = r.register("a", None, AuditSource::BoltUds, AccessMode::Read, None);
        let g1 = r.register("b", None, AuditSource::BoltUds, AccessMode::Read, None);
        assert_eq!(g0.id(), "a-transaction-0");
        assert_eq!(g1.id(), "b-transaction-1");
        assert_eq!(r.len(), 2);
    }
}
