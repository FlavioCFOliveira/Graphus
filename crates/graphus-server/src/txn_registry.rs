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
//! One class of **server-internal** transaction is registered too (`rmp` task #903): the validating
//! `CREATE CONSTRAINT` DDL, through [`TransactionRegistry::register_internal`]. It has no client seam
//! behind it — the engine runs it synchronously on its own thread — yet it reads every entity carrying
//! the covered token, so it is both the schema work an operator most needs to *see* and the walk they
//! most need to be able to *stop*. It is distinguished from client work by the `protocol` column
//! already in the schema, which renders it as `"internal"`.
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
//! [`AtomicBool`]). For a **client** transaction the owning seam observes it at each statement
//! boundary via [`TxnGuard::is_terminated`], then rolls the transaction back and fails the client's
//! next interaction; a client statement that is already executing runs to completion. For an
//! **internal** transaction the flag is not enough — nothing would look at it until the work had
//! already finished — so `terminate` additionally cancels the [`CancellationToken`] that entry carries,
//! which the running work polls itself. The registry performs **no** engine I/O either way: it is
//! pure, lock-guarded bookkeeping plus two atomic stores, so it can be shared cheaply by every seam,
//! and terminating never blocks on the engine thread it may be interrupting.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime};

use graphus_cypher::CancellationToken;

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
    /// An optional **cooperative cancellation hook** [`TransactionRegistry::terminate`] trips in
    /// addition to the flag above (`rmp` task #903), for work that is already executing and would
    /// otherwise run to completion before anything looked at the flag.
    ///
    /// `None` for a client transaction registered through [`TransactionRegistry::register`]: those are
    /// driven by a seam that observes `terminated` at its next statement boundary, and attaching a
    /// token to them would change when an in-flight client statement is interrupted — a behavioural
    /// change this field deliberately does not make. `Some` for a server-internal transaction
    /// registered through [`TransactionRegistry::register_internal`], which has no seam to observe
    /// anything on its behalf because it is running synchronously on the engine thread.
    cancel: Option<CancellationToken>,
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
            // A client transaction is driven by a seam that polls `terminated`; see the field docs for
            // why no token is attached here.
            cancel: None,
        });
        self.lock().insert(seq, Arc::clone(&handle));
        TxnGuard {
            registry: Arc::clone(self),
            handle,
            never_cancelled: CancellationToken::new(),
        }
    }

    /// Registers a **server-internal** transaction — one the engine runs on its own thread with no
    /// client seam behind it — and returns the RAII [`TxnGuard`] that deregisters it (`rmp` task #903).
    ///
    /// Today this is the validating `CREATE CONSTRAINT` DDL, whose walk reads every entity carrying the
    /// covered token. It is registered for two reasons, and both are the operator's:
    ///
    /// * **Visibility.** The walk reads arbitrary property values. An unregistered transaction leaves no
    ///   trace in `SHOW TRANSACTIONS`, so schema work that touches user data was the one class of
    ///   database activity an administrator could not see while it happened.
    /// * **Terminability.** The walk is O(entities carrying the token), so a `CREATE CONSTRAINT` on a
    ///   large label is exactly the runaway an operator needs to be able to stop.
    ///
    /// # How it differs from a client entry
    ///
    /// * `source` is [`AuditSource::Internal`], which the existing [`protocol_label`] already renders as
    ///   `"internal"` — so `SHOW TRANSACTIONS` distinguishes internal schema work from user work in the
    ///   column that already exists for exactly this purpose. No new column is introduced.
    /// * `client_address` is [`None`]: there is no peer. The connection that *asked* for the DDL is a
    ///   different transaction with its own entry, if it has one.
    /// * `cancel` is `Some`, so [`terminate`](Self::terminate) can interrupt work that is already
    ///   running rather than only work that is between statements.
    ///
    /// `principal` is the authenticated user the seam authorised the DDL for, so an operator can still
    /// see who asked for the schema change even though the transaction itself is the server's.
    #[must_use]
    pub fn register_internal(
        self: &Arc<Self>,
        database: &str,
        principal: Option<&str>,
        mode: AccessMode,
        cancel: CancellationToken,
    ) -> TxnGuard {
        let seq = self.next_seq.fetch_add(1, Ordering::Relaxed);
        let id = format!("{database}-transaction-{seq}");
        let handle = Arc::new(TxnHandle {
            id,
            seq,
            database: database.to_owned(),
            principal: principal.map(str::to_owned),
            source: AuditSource::Internal,
            mode,
            client_address: None,
            started_instant: Instant::now(),
            started_wall: SystemTime::now(),
            current_query: Mutex::new(None),
            terminated: AtomicBool::new(false),
            cancel: Some(cancel),
        });
        self.lock().insert(seq, Arc::clone(&handle));
        TxnGuard {
            registry: Arc::clone(self),
            handle,
            never_cancelled: CancellationToken::new(),
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
    ///
    /// For an entry registered through [`register_internal`](Self::register_internal) the attached
    /// [`CancellationToken`] is cancelled as well (`rmp` task #903), which is what makes an *already
    /// executing* internal transaction stop rather than run to completion. Setting the flag before
    /// cancelling the token is deliberate: an observer that sees the cancellation and then reads the
    /// flag must find it set, never the other way round.
    ///
    /// This method still performs **no** engine I/O — it flips an `AtomicBool` and, for internal
    /// entries, one more `AtomicBool` inside the token — so it never blocks on the engine thread it may
    /// be interrupting.
    #[must_use]
    pub fn terminate(&self, ids: &[String]) -> Vec<TerminateOutcome> {
        let guard = self.lock();
        ids.iter()
            .map(
                |requested| match guard.values().find(|h| h.id == *requested) {
                    Some(handle) => {
                        handle.terminated.store(true, Ordering::Release);
                        if let Some(cancel) = &handle.cancel {
                            cancel.cancel();
                        }
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
    /// The token [`cancellation`](Self::cancellation) hands out for a **client** entry, which carries
    /// no hook of its own. Owned by the guard (never registered, never reachable by
    /// [`TransactionRegistry::terminate`]) so it can only ever read as "not cancelled".
    never_cancelled: CancellationToken,
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
    /// The [`CancellationToken`] this entry carries, for a transaction registered through
    /// [`TransactionRegistry::register_internal`] (`rmp` task #903) — the token
    /// [`TransactionRegistry::terminate`] cancels, which the running work polls itself.
    ///
    /// A client entry carries none, so this returns a token that is never cancelled. That is the right
    /// answer rather than an [`Option`]: a caller that holds a guard and wants to pass a token onward
    /// always has one to pass, and passing the never-cancelled token is exactly the "no cancellation
    /// requested" behaviour. `TERMINATE TRANSACTIONS` still reaches a client transaction through
    /// [`is_terminated`](Self::is_terminated), which its seam polls at each statement boundary.
    pub fn cancellation(&self) -> &CancellationToken {
        self.handle.cancel.as_ref().unwrap_or(&self.never_cancelled)
    }

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

    // --------------------------------------------------------------------------------------------
    // Server-internal transactions (`rmp` task #903)
    // --------------------------------------------------------------------------------------------

    /// An internal entry is a full participant in `SHOW TRANSACTIONS`, distinguished from client work
    /// by the `protocol` column the schema already carries — no new column, and no ambiguity about
    /// which rows are the server's own.
    #[test]
    fn an_internal_transaction_is_listed_and_labelled_internal() {
        let r = reg();
        let g = r.register_internal(
            "graphus",
            Some("alice"),
            AccessMode::Write,
            CancellationToken::new(),
        );
        g.set_current_query("CREATE CONSTRAINT u FOR (:P) REQUIRE (email) IS NODE UNIQUE");

        let snap = r.snapshot();
        assert_eq!(snap.len(), 1);
        assert_eq!(snap[0].id, "graphus-transaction-0");
        assert_eq!(
            snap[0].protocol, "internal",
            "internal schema work must be distinguishable from user work"
        );
        assert_eq!(snap[0].database, "graphus");
        assert_eq!(
            snap[0].username.as_deref(),
            Some("alice"),
            "the transaction is the server's, but the operator still needs to see who asked for it"
        );
        assert_eq!(
            snap[0].client_address, None,
            "an internal transaction has no peer"
        );
        assert_eq!(snap[0].mode, "WRITE");
        assert_eq!(snap[0].status, "Running");
        assert!(
            snap[0]
                .current_query
                .as_deref()
                .is_some_and(|q| q.starts_with("CREATE CONSTRAINT")),
            "the rendered statement is what an operator reads in the currentQuery column"
        );

        // RAII: the entry disappears when the work finishes, on every path out.
        drop(g);
        assert!(r.is_empty(), "an internal entry must not outlive its work");
    }

    /// `TERMINATE TRANSACTIONS` against an internal entry must cancel its token, not merely set the
    /// flag: nothing would ever read the flag, because the work it names is executing synchronously on
    /// the engine thread with no seam to poll anything on its behalf.
    #[test]
    fn terminating_an_internal_transaction_cancels_its_token() {
        let r = reg();
        let cancel = CancellationToken::new();
        let g = r.register_internal("graphus", None, AccessMode::Write, cancel.clone());
        assert!(
            !cancel.is_cancelled(),
            "non-vacuity: the token must start clear"
        );

        let outcomes = r.terminate(&["graphus-transaction-0".to_owned()]);
        assert_eq!(outcomes.len(), 1);
        assert_eq!(outcomes[0].message, "Terminated");

        assert!(
            cancel.is_cancelled(),
            "the running work polls the token, so terminate must cancel it"
        );
        assert!(g.is_terminated(), "and the flag is set as well");
        assert!(
            g.cancellation().is_cancelled(),
            "the guard hands out the same token the registry cancelled"
        );
        assert_eq!(r.snapshot()[0].status, "Terminated");
    }

    /// Terminating a **client** transaction must NOT start cancelling in-flight statements: those
    /// entries carry no token, and attaching one would change when a running client query is
    /// interrupted. The guard still hands out a token — so a caller always has one to pass on — and it
    /// is one that can never be cancelled.
    #[test]
    fn terminating_a_client_transaction_leaves_its_cancellation_inert() {
        let r = reg();
        let g = r.register(
            "graphus",
            Some("bob"),
            AuditSource::Rest,
            AccessMode::Write,
            None,
        );
        let _ = r.terminate(&["graphus-transaction-0".to_owned()]);

        assert!(g.is_terminated(), "the flag its seam polls is set");
        assert!(
            !g.cancellation().is_cancelled(),
            "a client entry carries no cancellation hook, so nothing interrupts a running statement"
        );
    }

    /// An internal entry is terminable only while it exists. Once the work has finished and the guard
    /// has dropped, the id is gone — an operator terminating a completed DDL gets the ordinary
    /// "not found", never a spurious success.
    #[test]
    fn a_finished_internal_transaction_is_no_longer_terminable() {
        let r = reg();
        let cancel = CancellationToken::new();
        {
            let _g = r.register_internal("graphus", None, AccessMode::Write, cancel.clone());
        }
        let outcomes = r.terminate(&["graphus-transaction-0".to_owned()]);
        assert_eq!(outcomes[0].message, "Transaction not found");
        assert!(
            !cancel.is_cancelled(),
            "a deregistered entry's token must not be reachable"
        );
    }
}
