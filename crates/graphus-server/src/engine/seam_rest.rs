//! [`graphus_rest::RestEngine`] over the engine channel — the thin client the REST router uses
//! (`04-technical-design.md` §8.3 one executor, §9.1 the shard funnel; rmp #84 `{db}` routing +
//! the administrative surface).
//!
//! Unlike the Bolt seam, the REST seam is **shared** (`Arc<dyn RestEngine>`) across all in-flight
//! requests and is `Send + Sync` with `&self` methods, because REST is stateless: a request names
//! its transaction by URL ([`graphus_rest::TxHandle`]) and may land on any worker.
//!
//! ## Database routing (rmp #84)
//!
//! The router's `{db}` path segment reaches [`RestEngine::begin`], where it resolves through the
//! shared [`AdminContext`]: the segment naming the configured default database takes the captured
//! default handle (the unchanged single-db fast path); any other name resolves through the
//! catalog's concurrent registry to that database's own admission-limited [`EngineHandle`]
//! (per-database admission + metrics). An unknown/offline/failed database fails `begin` with a
//! clear error and no side effects.
//!
//! Because each database's engine mints its tickets **independently** (two engines can mint the
//! same ticket number), this adapter mints its own [`TxHandle`] ids from an atomic counter and
//! keeps a `TxHandle → (engine handle, ticket, db, principal, explicit)` table — the database a
//! transaction was opened against is pinned for its lifetime, and the principal/origin recorded at
//! `begin` drive the admin authorization at `run` time. The table is behind a plain
//! `std::sync::Mutex`: entries are touched briefly (clone-out / remove), never across an engine
//! call.
//!
//! ## Administrative statements (rmp #84)
//!
//! Both [`RestEngine::run`] and [`RestEngine::run_autocommit`] match the statement against the strict
//! admin grammar before the engine sees it, through the shared [`RestEngineAdapter::dispatch_admin`]
//! (see [`crate::admin`]). Admin statements require the global `Admin` privilege, are rejected inside
//! an explicit (client-managed) transaction, and execute immediately — outside any engine transaction
//! (they are not transactional). The single-statement auto-commit shortcut (rmp #527) runs through
//! `run_autocommit`, which never opens an engine transaction for an admin statement; a multi-statement
//! batch still opens one, and an admin statement inside it commits that transaction empty afterwards.
//!
//! The router's row-pull (`ResultStream::next_row`) and the `run`/`commit`/`rollback` calls are
//! synchronous; the server drives each REST connection's router future to completion on a
//! `spawn_blocking` thread (see [`crate::listeners::rest`]), so these blocking submits never park a
//! Tokio runtime worker (`04 §9.1`).

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, PoisonError};

use graphus_core::{GraphusError, Value};
use graphus_rest::engine::{
    AccessMode as RestAccessMode, RestEngine, ResultStream, Row, RunSummary as RestRunSummary,
    TxHandle, TxOrigin,
};
use graphus_rest::restvalue::RestValue;

use crate::admin::{AdminContext, AdminParse, AdminResult};
use crate::audit::{
    AuditClass, AuditEvent, AuditOutcome, AuditSource, data_change_detail,
    redact_constraint_detail, redact_index_detail,
};

use super::command::{AccessMode, constraint_ddl_summary, index_ddl_summary};
use super::constraint_show;
use super::handle::AdmissionPermit;
use super::index_show;
use super::managed::ManagedTx;
use super::privileges::EffectivePrivileges;
use super::stream::{RowReceiver, SummarySink};
use super::{EngineHandle, RunSummary, TxTicket};

/// The shared REST engine: database routing + admin statements over the per-database engines
/// (held behind an `Arc` by the router).
pub struct RestEngineAdapter {
    /// Database targeting + administrative statements, shared with the Bolt seam.
    context: AdminContext,
    /// Open transactions, keyed by the adapter-minted [`TxHandle`] id (module docs: each
    /// database's engine mints tickets independently, so the engine ticket alone is ambiguous).
    txns: Mutex<HashMap<u64, OpenTx>>,
    /// The next [`TxHandle`] id (the router never sees engine tickets).
    next_id: AtomicU64,
}

/// One open REST transaction: the engine it lives on, its ticket there, and the session facts
/// recorded at `begin` (the authenticated principal, explicit vs. auto-commit). The database
/// pinning is the `handle` itself — every later statement runs on the engine resolved at `begin`
/// (the router does not re-route the `{db}` segment of follow-up URLs; the transaction id is
/// authoritative).
#[derive(Clone)]
struct OpenTx {
    handle: EngineHandle,
    ticket: TxTicket,
    /// The principal that opened the transaction — authorizes admin statements at `run` time and
    /// scopes the fine-grained query privileges resolved per statement (rmp #93).
    principal: String,
    /// The canonical database the transaction is pinned to (resolved at `begin`). Scopes the
    /// principal's label/relationship/property privileges for every statement (rmp #93).
    db: String,
    /// Whether this is a client-managed explicit transaction (admin statements are rejected).
    explicit: bool,
    /// The access mode the transaction was begun in — so a `RUN` inside it can be classified as a
    /// data change (a write) for audit (rmp #70).
    mode: AccessMode,
    /// The **admission permit `BEGIN` acquired**, held for the transaction's whole lifetime (`rmp` #448,
    /// CWE-770). An explicit REST transaction outlives its connection and pins a GC-watermark snapshot,
    /// so admitting it against the engine's per-database concurrency budget (`max_concurrent_queries`) —
    /// and *keeping* the permit until the transaction is taken (committed/rolled back) — bounds how many
    /// open transactions one principal can hold on a shared engine. `Arc` so `OpenTx` stays `Clone` (the
    /// `lookup` path clones an entry out); the permit is released — its `Drop` returns the semaphore
    /// slot — when the last clone drops, i.e. once the entry is `take`n AND no in-flight `run` clone of it
    /// remains. Paired with the registry's open-transaction cap (the URL-facing bound), this is the
    /// engine-side bound on the `seam_rest.txns` map.
    _permit: std::sync::Arc<AdmissionPermit>,
    /// The live-transaction-registry entry (`rmp` #637): registered on `BEGIN`, it makes this
    /// transaction visible to `SHOW TRANSACTIONS`, records its current query, and carries the
    /// `TERMINATE TRANSACTIONS` flag. Held behind an `Arc` (exactly like `_permit`) so `OpenTx`
    /// stays `Clone`: the guard deregisters the transaction only when the **last** clone drops —
    /// i.e. once the table entry is `take`n (committed/rolled back/terminated) and no in-flight
    /// `run` clone of it remains.
    txn: std::sync::Arc<crate::txn_registry::TxnGuard>,
}

impl RestEngineAdapter {
    /// A REST engine over the shared `context`.
    #[must_use]
    pub fn new(context: AdminContext) -> Self {
        Self {
            context,
            txns: Mutex::new(HashMap::new()),
            next_id: AtomicU64::new(0),
        }
    }

    /// The transaction table's guard, recovering from poisoning (the map holds only cheap
    /// handles; recovering beats cascading a panic through every request).
    fn txns(&self) -> std::sync::MutexGuard<'_, HashMap<u64, OpenTx>> {
        self.txns.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Looks up (clones out) the open transaction for `tx`, briefly holding the table lock.
    fn lookup(&self, tx: TxHandle) -> Result<OpenTx, GraphusError> {
        // A spent/unknown handle is a permanent client fault, not a serialization abort (`rmp` #988):
        // `Neo.ClientError.Transaction.TransactionNotFound`, which the REST renderer answers with
        // **404**, the same status `Problem::unknown_transaction` already uses for the twin the router
        // detects.
        self.txns().get(&tx.0).cloned().ok_or_else(|| {
            graphus_core::status::transaction_not_found(&format!("transaction handle {}", tx.0))
        })
    }

    /// Drops the table entry for `tx` — the seam-side bookkeeping a transaction the engine has already
    /// finished must not outlive (`rmp` task #957).
    ///
    /// Removing the entry is what eventually releases the admission permit and deregisters the
    /// live-registry entry: both are held behind an `Arc` shared with any in-flight `run` clone, so
    /// they are freed when the **last** clone drops, not necessarily here. The public handle is spent
    /// either way — a later `run`/`commit` against it reports the unknown-handle error.
    fn discard(&self, tx: TxHandle) {
        self.txns().remove(&tx.0);
    }

    /// The shared resumption guard (`rmp` task #957) plus this seam's own cleanup: if `open` has been
    /// terminated by `TERMINATE TRANSACTIONS` (rmp #637), the engine transaction is rolled back, the
    /// table entry is dropped, and the non-retryable terminated error is returned.
    ///
    /// The rule itself lives in [`ManagedTx`], shared verbatim with the Bolt seam — this wrapper only
    /// adds the table bookkeeping the Bolt seam does not have.
    fn resume(&self, tx: TxHandle, open: &OpenTx) -> Result<(), GraphusError> {
        if let Err(e) = ManagedTx::new(&open.handle, open.ticket, &open.txn).resume() {
            self.discard(tx);
            return Err(e);
        }
        Ok(())
    }

    /// Emits a config-gated `data_change` audit event (rmp #70) for a **write** statement on REST.
    ///
    /// Called only when the transaction is write-mode and only when
    /// [`crate::audit::AuditLog::data_changes_enabled`] is set, so the default-off case costs
    /// nothing. The `detail` is a category word only (never the query text or any literal — see
    /// [`data_change_detail`]). `DataChange` events are not `fsync`'d per event (batched).
    fn audit_data_change_if_enabled(
        &self,
        principal: &str,
        db: &str,
        query: &str,
        mode: AccessMode,
        outcome: AuditOutcome,
    ) {
        if mode != AccessMode::Write || !self.context.audit().data_changes_enabled() {
            return;
        }
        self.context.audit().record(
            AuditEvent::new(AuditClass::DataChange, outcome, AuditSource::Rest)
                .actor(Some(principal))
                .database(Some(db))
                .detail(data_change_detail(query, None)),
        );
    }

    /// Intercepts an administrative / index-DDL / constraint-DDL statement BEFORE Cypher compilation
    /// (rmp #84/#91), shared by [`RestEngine::run`] (explicit + auto-commit shortcut) and
    /// [`RestEngine::run_autocommit`] (rmp #527) so both surfaces handle admin identically.
    ///
    /// Returns `Some(result)` when the statement was claimed by the admin grammar (executed, or an
    /// error), and `None` when it is ordinary Cypher (the caller runs it through the engine). Admin
    /// statements are not transactional: they are rejected inside an `explicit` transaction, authorized
    /// against `principal`/`db`, audited at the single funnel (rmp #70), and their result is streamed as
    /// buffered admin rows carrying the `rmp` #513 summary.
    fn dispatch_admin(
        &self,
        query: &str,
        principal: &str,
        db: &str,
        handle: &EngineHandle,
        explicit: bool,
    ) -> Option<Result<RestEngineStream, GraphusError>> {
        match crate::admin::parse_admin_statement(query) {
            AdminParse::Command(cmd) => {
                if explicit {
                    return Some(Err(admin_in_explicit_tx()));
                }
                // `execute` audits the change/denial at the single admin funnel (rmp #70) with the
                // REST source.
                Some(
                    self.context
                        .execute(Some(principal), AuditSource::Rest, &cmd)
                        .map(RestEngineStream::admin),
                )
            }
            // An index-DDL statement (rmp #91): authorize like a database command, then route it to
            // the engine the transaction was opened against (the index catalog lives on the
            // coordinator). Rejected inside an explicit transaction, behind the admin-privilege gate.
            AdminParse::Index(cmd) => {
                if explicit {
                    return Some(Err(admin_in_explicit_tx()));
                }
                // Authorization first — no side effects on denial. Index DDL requires the SCHEMA
                // privilege on the transaction's pinned database (`Admin` still satisfies it via RBAC
                // containment), so `GRANT SCHEMA ON GRAPH x` can delegate DDL without full Admin (rmp
                // #457). The seam audits the index-DDL denial / schema change itself (rmp #70).
                if let Err(e) = self.context.authorize_schema(Some(principal), db) {
                    self.context.audit().record(
                        AuditEvent::new(
                            AuditClass::AuthzDenied,
                            AuditOutcome::Failure,
                            AuditSource::Rest,
                        )
                        .actor(Some(principal))
                        .database(Some(db))
                        .detail(redact_index_detail(&cmd)),
                    );
                    return Some(Err(e));
                }
                // The unified `SHOW INDEXES` (every filter form) is read-only — only the mutating
                // CREATE/DROP are schema changes (`rmp` task #660 folds full-text / point SHOW into it).
                let mutating = !matches!(cmd, crate::engine::IndexCommand::ShowIndexes { .. });
                let detail = redact_index_detail(&cmd);
                // Keep the command shape for the post-outcome summary (counters depend on whether the
                // DDL actually mutated — `reply.mutated`) and to detect the `SHOW INDEXES` tail.
                let summary_cmd = cmd.clone();
                let outcome = handle.index_ddl_blocking(cmd);
                if mutating {
                    self.context.audit().record(
                        AuditEvent::new(
                            AuditClass::SchemaChange,
                            if outcome.is_ok() {
                                AuditOutcome::Success
                            } else {
                                AuditOutcome::Failure
                            },
                            AuditSource::Rest,
                        )
                        .actor(Some(principal))
                        .database(Some(db))
                        .detail(detail),
                    );
                }
                let reply = match outcome {
                    Ok(reply) => reply,
                    Err(e) => return Some(Err(e)),
                };
                // A `SHOW INDEXES` finishes through the shared helper (`rmp` #660): a `YIELD`/`WHERE`
                // tail re-runs a translated read query over the rendered rows; a bare listing projects
                // to the default columns. CREATE/DROP fall through to the mutation summary below.
                if let crate::engine::IndexCommand::ShowIndexes { tail, .. } = &summary_cmd {
                    let tail = tail.clone();
                    return Some(index_show::finish(
                        reply,
                        tail.as_deref(),
                        |query, params| {
                            // Re-run as a normal auto-commit READ on the transaction's pinned engine.
                            let permit = handle
                                .try_admit()
                                .map_err(|busy| GraphusError::Transaction(busy.to_string()))?;
                            let ticket = handle.begin_auto_commit_blocking(AccessMode::Read)?;
                            let privileges = Some(EffectivePrivileges::resolve(
                                std::sync::Arc::clone(self.context.security()),
                                Some(principal),
                                db,
                            ));
                            let reply = handle.run_blocking(
                                ticket, query, params, /* auto_commit */ true, privileges,
                                // REST carries no per-request statement budget (`rmp` #909): the
                                // client-settable `tx_timeout` is a Bolt `extra` field. The operator's
                                // configured per-statement timeout governs, exactly as before.
                                None,
                            )?;
                            Ok(RestEngineStream {
                                fields: reply.fields,
                                source: RowSource::Engine {
                                    rows: reply.rows,
                                    _permit: permit,
                                },
                                summary: reply.summary,
                            })
                        },
                        RestEngineStream::admin,
                    ));
                }
                // Query type `s` + `indexes-added`/`indexes-removed` for a real CREATE/DROP, or the `0`
                // counter shape for an idempotent no-op (`rmp` #626 follow-up).
                let summary = index_ddl_summary(&summary_cmd, reply.mutated);
                Some(Ok(RestEngineStream::admin(AdminResult {
                    fields: reply.fields,
                    rows: reply.rows,
                    summary,
                })))
            }
            // A constraint-DDL statement (`rmp` task #99): routed identically to an index command.
            AdminParse::Constraint(cmd) => {
                if explicit {
                    return Some(Err(admin_in_explicit_tx()));
                }
                // Authorization first — no side effects on denial. Constraint DDL requires SCHEMA on
                // the transaction's pinned database (`Admin` still satisfies it via RBAC containment;
                // rmp #457).
                if let Err(e) = self.context.authorize_schema(Some(principal), db) {
                    self.context.audit().record(
                        AuditEvent::new(
                            AuditClass::AuthzDenied,
                            AuditOutcome::Failure,
                            AuditSource::Rest,
                        )
                        .actor(Some(principal))
                        .database(Some(db))
                        .detail(redact_constraint_detail(&cmd)),
                    );
                    return Some(Err(e));
                }
                // `SHOW CONSTRAINTS` is read-only — only the mutating CREATE/DROP are schema changes.
                let mutating = !matches!(cmd, crate::engine::ConstraintCommand::Show { .. });
                let detail = redact_constraint_detail(&cmd);
                // Keep the command shape for the post-outcome summary (counters depend on
                // `reply.mutated`) and to detect the `SHOW CONSTRAINTS` tail.
                let summary_cmd = cmd.clone();
                let outcome = handle.constraint_ddl_blocking(cmd, Some(principal.to_owned()));
                if mutating {
                    self.context.audit().record(
                        AuditEvent::new(
                            AuditClass::SchemaChange,
                            if outcome.is_ok() {
                                AuditOutcome::Success
                            } else {
                                AuditOutcome::Failure
                            },
                            AuditSource::Rest,
                        )
                        .actor(Some(principal))
                        .database(Some(db))
                        .detail(detail),
                    );
                }
                let reply = match outcome {
                    Ok(reply) => reply,
                    Err(e) => return Some(Err(e)),
                };
                // A `SHOW CONSTRAINTS` finishes through the shared helper (`rmp` #653): a `YIELD`/`WHERE`
                // tail re-runs a translated read query over the rendered rows; a bare listing projects
                // to the 8 default columns. CREATE/DROP fall through to the mutation summary below.
                if let crate::engine::ConstraintCommand::Show { tail, .. } = &summary_cmd {
                    let tail = tail.clone();
                    return Some(constraint_show::finish(
                        reply,
                        tail.as_deref(),
                        |query, params| {
                            // Re-run as a normal auto-commit READ on the transaction's pinned engine.
                            let permit = handle
                                .try_admit()
                                .map_err(|busy| GraphusError::Transaction(busy.to_string()))?;
                            let ticket = handle.begin_auto_commit_blocking(AccessMode::Read)?;
                            let privileges = Some(EffectivePrivileges::resolve(
                                std::sync::Arc::clone(self.context.security()),
                                Some(principal),
                                db,
                            ));
                            let reply = handle.run_blocking(
                                ticket, query, params, /* auto_commit */ true, privileges,
                                // REST carries no per-request statement budget (`rmp` #909): the
                                // client-settable `tx_timeout` is a Bolt `extra` field. The operator's
                                // configured per-statement timeout governs, exactly as before.
                                None,
                            )?;
                            Ok(RestEngineStream {
                                fields: reply.fields,
                                source: RowSource::Engine {
                                    rows: reply.rows,
                                    _permit: permit,
                                },
                                summary: reply.summary,
                            })
                        },
                        RestEngineStream::admin,
                    ));
                }
                // Query type `s` + `constraints-added`/`constraints-removed` for a real CREATE/DROP,
                // or the `0` counter shape for a no-op drop (`rmp` #626 follow-up).
                let summary = constraint_ddl_summary(&summary_cmd, reply.mutated);
                Some(Ok(RestEngineStream::admin(AdminResult {
                    fields: reply.fields,
                    rows: reply.rows,
                    summary,
                })))
            }
            AdminParse::Invalid(msg) => Some(Err(GraphusError::Compile(msg))),
            AdminParse::NotAdmin => None,
        }
    }
}

/// The "admin command inside an explicit transaction" rejection, shared by the database (rmp #84)
/// and index (rmp #91) surfaces — neither is transactional.
fn admin_in_explicit_tx() -> GraphusError {
    GraphusError::Protocol(
        "administrative commands cannot run inside an explicit transaction; \
         commit or roll back first"
            .to_owned(),
    )
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
        // The `EXPLAIN` / `PROFILE` plan (`rmp` #752) — the same rendered plan the Bolt seam reports, under
        // the same key.
        plan: s.plan.map(|p| graphus_rest::QueryPlan {
            profiled: p.profiled,
            description: p.description,
        }),
    }
}

// The materialized-cell → REST structural value mapping lives in [`super::rest_values`] so the
// deterministic VOPR REST client (rmp #164) serializes results identically to this seam.
use super::rest_values::materialized_to_rest;

/// Where a REST result's rows come from: the engine's bounded channel (a query) or a buffered
/// administrative result (rmp #84) — both stream through the same [`ResultStream`] seam.
enum RowSource {
    /// A query result: rows pulled from the engine, the admission permit held until done.
    Engine {
        rows: RowReceiver,
        /// Held for the stream's lifetime; dropping it releases the admission slot (`04 §9.3`).
        _permit: AdmissionPermit,
    },
    /// A buffered administrative result (e.g. `SHOW DATABASES` rows). No permit: admin commands
    /// never enter the engine, and the catalog serializes them itself.
    Admin(std::vec::IntoIter<Vec<Value>>),
}

/// The REST result stream: engine rows (holding the admission permit until exhausted/dropped) or
/// a buffered admin result, behind one [`ResultStream`].
pub struct RestEngineStream {
    fields: Vec<String>,
    source: RowSource,
    /// The result summary, read AFTER the rows drain (`rmp` #512). For an engine query this is the
    /// shared sink the engine fills in `finalize_inflight`; for an admin result it is an empty sink.
    summary: SummarySink,
}

impl RestEngineStream {
    /// Wraps a buffered administrative result, carrying its result summary (`rmp` #513): the query
    /// type (`s` for a schema/system change, `r` for a `SHOW *` read) and any schema/system counters,
    /// published into a fresh sink so [`Self::summary`] surfaces it exactly as an engine query's sink
    /// does (admin rows are produced synchronously, so the sink is filled here before any row drains —
    /// no cross-thread ordering to observe).
    fn admin(result: AdminResult) -> Self {
        let summary = SummarySink::new();
        summary.set(result.summary);
        Self {
            fields: result.fields,
            source: RowSource::Admin(result.rows.into_iter()),
            summary,
        }
    }
}

impl ResultStream for RestEngineStream {
    fn fields(&self) -> &[String] {
        &self.fields
    }

    fn next_row(&mut self) -> Result<Option<Row>, GraphusError> {
        match &mut self.source {
            // A query row arrives as materialized cells (entities already resolved through the
            // cursor's graph seam, so RBAC/MVCC are applied — rmp #93); map each onto the REST
            // structural value the router serialises.
            RowSource::Engine { rows, .. } => Ok(rows
                .next()?
                .map(|cells| cells.into_iter().map(materialized_to_rest).collect())),
            // A buffered admin row is plain property values; lift each into a `RestValue::Value`.
            RowSource::Admin(rows) => Ok(rows
                .next()
                .map(|row| row.into_iter().map(RestValue::Value).collect())),
        }
    }

    fn summary(&self) -> RestRunSummary {
        to_rest_summary(self.summary.get())
    }
}

/// The server-side [`graphus_rest::router::AuthObserver`] (rmp #70): records REST Bearer-validation
/// outcomes to the shared [`AuditLog`](crate::audit::AuditLog) with the `Rest` source.
///
/// Graphus REST has no login endpoint — tokens are minted out of band — so the only REST auth event
/// is per-request Bearer validation. Per-request success events can be high-volume; that is accepted
/// for v1 (no sampling, to keep the trail simple and complete). The attempted principal is not
/// recoverable from a bearer token cheaply, so an `AuthFailure` carries `actor = null`.
pub struct RestAuthObserver {
    audit: std::sync::Arc<crate::audit::AuditLog>,
}

impl RestAuthObserver {
    /// Builds the observer over the shared audit log.
    #[must_use]
    pub fn new(audit: std::sync::Arc<crate::audit::AuditLog>) -> Self {
        Self { audit }
    }
}

impl graphus_rest::router::AuthObserver for RestAuthObserver {
    fn on_auth_success(&self, principal: &str) {
        self.audit.record(
            AuditEvent::new(
                AuditClass::AuthSuccess,
                AuditOutcome::Success,
                AuditSource::Rest,
            )
            .actor(Some(principal))
            .detail("REST bearer auth"),
        );
    }

    fn on_auth_failure(&self, attempted: Option<&str>, reason: &str) {
        self.audit.record(
            AuditEvent::new(
                AuditClass::AuthFailure,
                AuditOutcome::Failure,
                AuditSource::Rest,
            )
            .actor(attempted)
            .detail(format!("REST bearer auth: {reason}")),
        );
    }
}

impl RestEngine for RestEngineAdapter {
    type Stream = RestEngineStream;

    fn begin(
        &self,
        db: &str,
        mode: RestAccessMode,
        origin: TxOrigin<'_>,
    ) -> Result<TxHandle, GraphusError> {
        // Resolve the `{db}` segment (rmp #84): the configured default name is the default
        // database; anything else goes through the catalog. Unknown/offline → a clear error, and
        // no transaction is opened. The canonical `name` pins the transaction's database for the
        // privilege scoping of every later statement (rmp #93).
        let (name, handle) = self.context.resolve(Some(db))?;
        let engine_mode = from_rest_mode(mode);
        // `BEGIN` consumes an **admission permit** held for the transaction's lifetime (`rmp` #448,
        // CWE-770): an explicit REST transaction outlives its connection and pins a GC-watermark
        // snapshot, so it must count against the engine's per-database concurrency budget. Acquire it
        // BEFORE opening the engine transaction so a budget-exhausted server sheds the `BEGIN` without
        // ever opening (and having to roll back) a coordinator transaction. A `ServerBusy` is a retriable
        // load-shed (the router maps it to a `429`/`503`-class retriable error).
        let permit = handle
            .try_admit()
            .map_err(|busy| GraphusError::Transaction(busy.to_string()))?;
        let ticket = handle.begin_blocking(engine_mode)?;
        // Register the managed transaction in the server-wide live-transaction registry (rmp #637)
        // now visible to `SHOW TRANSACTIONS` and addressable by `TERMINATE TRANSACTIONS`. Held as an
        // `Arc` so the `Clone` `OpenTx` deregisters only when its last clone drops.
        let txn = std::sync::Arc::new(self.context.transactions().register(
            &name,
            Some(origin.principal),
            AuditSource::Rest,
            engine_mode,
            None,
        ));
        // Mint the public id only after the engine accepted the begin (no orphan table entries).
        let id = self.next_id.fetch_add(1, Ordering::Relaxed) + 1;
        self.txns().insert(
            id,
            OpenTx {
                handle,
                ticket,
                principal: origin.principal.to_owned(),
                db: name,
                explicit: origin.explicit,
                mode: engine_mode,
                _permit: std::sync::Arc::new(permit),
                txn,
            },
        );
        Ok(TxHandle(id))
    }

    fn run(
        &self,
        tx: TxHandle,
        query: &str,
        parameters: Vec<(String, Value)>,
    ) -> Result<Self::Stream, GraphusError> {
        let open = self.lookup(tx)?;

        // The resumption guard (`rmp` task #957): a transaction terminated by `TERMINATE TRANSACTIONS`
        // (rmp #637) is rolled back here, its table entry dropped, and the statement fails with the
        // non-retryable terminated error — the same rule, from the same code, as the Bolt seam.
        self.resume(tx, &open)?;
        // Record the statement as this transaction's current query for `SHOW TRANSACTIONS`.
        open.txn.set_current_query(query);

        // Administrative statements are intercepted BEFORE Cypher compilation (rmp #84/#91); see the
        // module docs for the explicit-vs-auto-commit rule. Shared with `run_autocommit` (rmp #527).
        if let Some(result) = self.dispatch_admin(
            query,
            &open.principal,
            &open.db,
            &open.handle,
            open.explicit,
        ) {
            return result;
        }

        // Admission control on the TARGET database's handle (per-db limits, `04 §9.3`); the
        // router maps the busy error to a retriable status. The permit is held by the stream.
        let permit = open
            .handle
            .try_admit()
            .map_err(|busy| GraphusError::Transaction(busy.to_string()))?;

        // Resolve the principal's effective privileges for the pinned database once per statement,
        // against the LIVE security catalog (rmp #93) — a runtime grant/revoke is in effect on the
        // next statement. No principal / admin ⇒ unrestricted pass-through.
        let privileges = Some(EffectivePrivileges::resolve(
            std::sync::Arc::clone(self.context.security()),
            Some(&open.principal),
            &open.db,
        ));

        // REST always runs against an already-open handle (the router opens the auto-commit
        // transaction itself for the commit shortcut), so this is never auto-commit at the engine.
        let outcome = open.handle.run_blocking(
            open.ticket,
            query.to_owned(),
            parameters,
            /* auto_commit */ false,
            privileges,
            // No REST-side statement budget (`rmp` #909) — see the note at the admin re-run above.
            None,
        );
        // Data-change audit (rmp #70, config-gated): a write that the engine ACCEPTED is audited at
        // this seam (the row stream is lazy; acceptance is the cheap, correct point). Full query
        // text is NEVER logged — only the category. Read transactions are not data changes.
        self.audit_data_change_if_enabled(
            &open.principal,
            &open.db,
            query,
            open.mode,
            if outcome.is_ok() {
                AuditOutcome::Success
            } else {
                AuditOutcome::Failure
            },
        );
        let reply = outcome?;
        Ok(RestEngineStream {
            fields: reply.fields,
            source: RowSource::Engine {
                rows: reply.rows,
                _permit: permit,
            },
            // Read from the shared sink AFTER the rows drain; the engine fills it before `row_tx`
            // drops (`rmp` #512).
            summary: reply.summary,
        })
    }

    fn run_autocommit(
        &self,
        db: &str,
        mode: RestAccessMode,
        origin: TxOrigin<'_>,
        query: &str,
        parameters: Vec<(String, Value)>,
    ) -> Result<Self::Stream, GraphusError> {
        // Resolve the `{db}` segment (rmp #84), exactly as `begin` does: the configured default name
        // is the default database; anything else goes through the catalog. Unknown/offline → a clear
        // error, and no transaction is opened. The canonical `name` scopes the privileges below.
        let (name, handle) = self.context.resolve(Some(db))?;
        let engine_mode = from_rest_mode(mode);

        // Admin / index-DDL / constraint-DDL statements run OUTSIDE any engine transaction (rmp
        // #84/#91), exactly as `run` handles them — shared through `dispatch_admin`. `origin.explicit`
        // is `false` for the auto-commit shortcut, so an admin statement is permitted here (never the
        // "cannot run inside an explicit transaction" rejection).
        if let Some(result) =
            self.dispatch_admin(query, origin.principal, &name, &handle, origin.explicit)
        {
            return result;
        }

        // A regular query: run it as a TRUE engine auto-commit (rmp #527) — `run_blocking` with
        // `auto_commit = true`. The engine's Run handler dispatches a `Read` to the off-thread reader
        // pool (`exec.rs` gate: `mode == Read && auto_commit`) and finalises (commits on success, rolls
        // back on error) when the result stream drains, so this seam issues NO separate commit. A
        // commit-time serialization abort is surfaced as the stream's terminal error (never swallowed —
        // rmp #238), so the router observes it via `next_row`.
        //
        // Admission is acquired BEFORE the begin so a saturated engine sheds the statement without
        // opening (and having to finalise) a transaction; the permit rides the returned stream for its
        // whole lifetime (`04 §9.3`). `begin_auto_commit_blocking` is followed by the infallible
        // privilege resolution and then `run_blocking`, so there is no error gap that could leak an
        // opened auto-commit transaction (a `run_blocking` error is finalised by the engine itself).
        let permit = handle
            .try_admit()
            .map_err(|busy| GraphusError::Transaction(busy.to_string()))?;
        let ticket = handle.begin_auto_commit_blocking(engine_mode)?;
        // Resolve the principal's effective privileges for the pinned database once, against the LIVE
        // security catalog (rmp #93) — a runtime grant/revoke is in effect on this very statement. No
        // principal / admin ⇒ an unrestricted pass-through.
        let privileges = Some(EffectivePrivileges::resolve(
            std::sync::Arc::clone(self.context.security()),
            Some(origin.principal),
            &name,
        ));
        let outcome = handle.run_blocking(
            ticket,
            query.to_owned(),
            parameters,
            /* auto_commit */ true,
            privileges,
            // No REST-side statement budget (`rmp` #909) — see the note at the admin re-run above.
            None,
        );
        // Data-change audit (rmp #70, config-gated): a write that the engine ACCEPTED is audited at
        // this seam (the row stream is lazy; acceptance is the cheap, correct point). Full query text is
        // NEVER logged — only the category. Read auto-commits are not data changes.
        self.audit_data_change_if_enabled(
            origin.principal,
            &name,
            query,
            engine_mode,
            if outcome.is_ok() {
                AuditOutcome::Success
            } else {
                AuditOutcome::Failure
            },
        );
        let reply = outcome?;
        Ok(RestEngineStream {
            fields: reply.fields,
            source: RowSource::Engine {
                rows: reply.rows,
                _permit: permit,
            },
            // Read from the shared sink AFTER the rows drain; the engine fills it (with the committed
            // side-effect counters) before `row_tx` drops (`rmp` #512).
            summary: reply.summary,
        })
    }

    fn ensure_live(&self, tx: TxHandle) -> Result<(), GraphusError> {
        // An unknown handle is not this guard's concern: `run`/`commit` already report it, and the
        // caller (the keep-alive) has just resolved the id through its own registry. Reporting only
        // termination here keeps the guard's meaning exact.
        let Ok(open) = self.lookup(tx) else {
            return Ok(());
        };
        self.resume(tx, &open)
    }

    fn commit(&self, tx: TxHandle) -> Result<RestRunSummary, GraphusError> {
        // Remove first: whatever the engine answers, the public handle is spent.
        let open = self.txns().remove(&tx.0).ok_or_else(|| {
            graphus_core::status::transaction_not_found(&format!(
                "COMMIT of transaction handle {}",
                tx.0
            ))
        })?;
        // Through the shared guard (`rmp` task #957): a transaction terminated by
        // `TERMINATE TRANSACTIONS` (rmp #637) is rolled back and fails with the non-retryable
        // terminated error instead of committing. This is the check the REST commit path was missing
        // while the Bolt one had it — an operator was told the transaction had been stopped and it
        // committed anyway. The rule now comes from the same code on both interfaces.
        let summary = ManagedTx::new(&open.handle, open.ticket, &open.txn).commit()?;
        Ok(to_rest_summary(summary))
    }

    fn rollback(&self, tx: TxHandle) -> Result<(), GraphusError> {
        // Idempotent, matching the trait contract: an unknown/already-finished handle is Ok(())
        // (the registry's inactivity sweep and an explicit DELETE can race safely).
        let Some(open) = self.txns().remove(&tx.0) else {
            return Ok(());
        };
        // Unconditional, terminated or not — rolling a terminated transaction back is exactly what the
        // operator asked for (see [`super::managed`]).
        ManagedTx::new(&open.handle, open.ticket, &open.txn).rollback()
    }
}
