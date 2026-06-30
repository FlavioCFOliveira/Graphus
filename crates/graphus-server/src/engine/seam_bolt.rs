//! [`graphus_bolt::BoltExecutor`] over the engine channel — the thin client one Bolt connection uses
//! (`04-technical-design.md` §8.3 one executor, §9.1 the shard funnel; rmp #84 session database
//! selection + the administrative surface).
//!
//! `graphus_bolt::BoltSession` owns one `BoltExecutor` for the connection's lifetime and calls it
//! with `&mut self` as it drives `BEGIN`/`RUN`/`COMMIT`/`ROLLBACK`. So this adapter is **per
//! connection**: it tracks the connection's single current explicit transaction (the engine keys
//! every transaction by an opaque [`TxTicket`]) and the session's authenticated principal (set by
//! `LOGON`, cleared by `LOGOFF`).
//!
//! ## Database targeting (rmp #84, Bolt 5.x `db` field)
//!
//! The session resolves its target database **at transaction begin** — an explicit `BEGIN` or an
//! auto-commit `RUN` — through the shared [`AdminContext`]: an absent/empty `db` is the configured
//! default database (served from a captured handle, the unchanged single-db fast path); a named
//! database resolves through the catalog's concurrent registry to that database's own
//! admission-limited [`EngineHandle`] (so admission control and metrics stay per database). An
//! explicit transaction is **pinned** to its database for its whole lifetime; a `RUN` inside it
//! naming a *different* database is an error. An unknown/offline/failed database fails the request
//! with a clear FAILURE and no side effects — the session recovers with `RESET` per the Bolt state
//! machine.
//!
//! ## Administrative statements (rmp #84)
//!
//! Before anything touches the engine, the query text is matched against the strict admin grammar
//! ([`crate::admin::parse_admin_statement`]). A recognised statement never reaches Cypher: it is
//! authorized against the session principal (global `Admin` privilege) and executed on the
//! catalog; its (buffered) result streams back through the same [`RecordStream`] mechanism as a
//! query result. Admin statements are rejected inside an explicit transaction — they are not
//! transactional.
//!
//! The Bolt session runs on a **blocking task** (see the `listeners::bolt` module), so this adapter
//! uses the handle's `*_blocking` submit methods — they may park the blocking thread on the bounded
//! channel (the intended backpressure), never a Tokio runtime worker (`04 §9.1`).

use graphus_bolt::executor::{
    AccessMode as BoltAccessMode, BoltExecutor, QuerySummary, Record, RecordStream, TxControl,
};
use graphus_bolt::packstream::BoltValue;
use graphus_core::{GraphusError, Value};

use crate::admin::{AdminContext, AdminParse, AdminResult};
use crate::audit::{
    AuditClass, AuditEvent, AuditOutcome, AuditSource, data_change_detail,
    redact_constraint_detail, redact_index_detail,
};

use super::command::{AccessMode, constraint_ddl_summary, index_ddl_summary};
use super::handle::AdmissionPermit;
use super::privileges::EffectivePrivileges;
use super::stream::{RowReceiver, SummarySink};
use super::{EngineHandle, RunSummary, TxTicket};

/// One Bolt connection's view of the server: the shared database-targeting/admin context, the
/// session principal, and this connection's current explicit transaction (if a `BEGIN` is open).
pub struct BoltEngineExecutor {
    /// Database targeting + administrative statements, shared across connections.
    context: AdminContext,
    /// The connection's audit source (rmp #70): `BoltUds` or `BoltTcp`, set at construction by the
    /// accept loop so every audited event records the right transport.
    source: AuditSource,
    /// The authenticated principal (`LOGON` sets it, `LOGOFF` clears it).
    principal: Option<String>,
    /// The open explicit transaction, set on `BEGIN`, cleared on `COMMIT`/`ROLLBACK`.
    current_tx: Option<OpenTx>,
}

/// The connection's open explicit transaction: the engine ticket plus the database it is pinned
/// to (handle + canonical name) for its whole lifetime.
struct OpenTx {
    ticket: TxTicket,
    handle: EngineHandle,
    db: String,
    /// The access mode the transaction was begun in — so a `RUN` inside it can be classified as a
    /// data change (a write) for audit (rmp #70).
    mode: AccessMode,
}

impl BoltEngineExecutor {
    /// A fresh per-connection executor over the shared `context`. `source` is the connection's
    /// transport (`BoltUds`/`BoltTcp`), recorded on every audit event this connection emits (rmp
    /// #70).
    #[must_use]
    pub fn new(context: AdminContext, source: AuditSource) -> Self {
        Self {
            context,
            source,
            principal: None,
            current_tx: None,
        }
    }

    /// Emits a config-gated `data_change` audit event (rmp #70) for a **write** statement.
    ///
    /// Called only when the run is a write (an auto-commit write or an explicit-tx write) and only
    /// when [`crate::audit::AuditLog::data_changes_enabled`] is set, so the default-off case costs
    /// nothing. The `detail` is a category word only (never the query text or any literal — see
    /// [`data_change_detail`]). `DataChange` events are not `fsync`'d per event (batched).
    fn audit_data_change_if_enabled(
        &self,
        db: &str,
        query: &str,
        mode: AccessMode,
        outcome: AuditOutcome,
    ) {
        if mode != AccessMode::Write || !self.context.audit().data_changes_enabled() {
            return;
        }
        self.context.audit().record(
            AuditEvent::new(AuditClass::DataChange, outcome, self.source)
                .actor(self.principal.as_deref())
                .database(Some(db))
                .detail(data_change_detail(query, None)),
        );
    }

    /// The "admin command inside an explicit transaction" rejection, shared by the database (rmp
    /// #84) and index (rmp #91) surfaces — neither is transactional.
    fn admin_in_explicit_tx() -> GraphusError {
        GraphusError::Protocol(
            "administrative commands cannot run inside an explicit transaction; \
             commit or roll back first"
                .to_owned(),
        )
    }

    /// Admits and runs one statement on `handle` inside `ticket` against database `db`, wrapping the
    /// engine reply as the Bolt stream. Admission is taken on the **target database's** handle (per-db
    /// limits).
    ///
    /// `db` is the canonical session database the statement runs against; it scopes the principal's
    /// fine-grained privileges (rmp #93), resolved once here from the shared live security catalog and
    /// threaded into the engine so the executor enforces label/relationship/property access uniformly.
    fn run_on(
        &self,
        handle: &EngineHandle,
        ticket: TxTicket,
        db: &str,
        query: &str,
        parameters: Vec<(String, Value)>,
        auto_commit: bool,
    ) -> Result<BoltEngineStream, GraphusError> {
        // Admission control: fast-reject when saturated (`04 §9.3`). The permit is held by the
        // returned stream for the whole result.
        let permit = handle
            .try_admit()
            .map_err(|busy| GraphusError::Transaction(busy.to_string()))?;
        // Resolve the principal's effective privileges for this database once per statement, against
        // the LIVE security catalog (rmp #93). A grant/revoke an admin just applied is therefore in
        // effect on this very next statement. No principal / admin ⇒ an unrestricted pass-through.
        let privileges = Some(EffectivePrivileges::resolve(
            std::sync::Arc::clone(self.context.security()),
            self.principal.as_deref(),
            db,
        ));
        let reply = handle.run_blocking(
            ticket,
            query.to_owned(),
            parameters,
            auto_commit,
            privileges,
        )?;
        Ok(BoltEngineStream {
            fields: reply.fields,
            source: RowSource::Engine {
                rows: reply.rows,
                _permit: permit,
            },
            // The result summary (query type + side-effect counters) is read from this sink AFTER the
            // rows drain: the engine fills it in `finalize_inflight` before `row_tx` drops (`rmp` #512).
            summary: reply.summary,
        })
    }
}

impl Drop for BoltEngineExecutor {
    /// Final backstop against a leaked explicit transaction (rmp #388): if the session ends while a
    /// `BEGIN` is still open — an abrupt disconnect the EOF arm did not reach, or a **panic** inside
    /// the session loop unwinding through this executor — best-effort roll it back so it stops
    /// pinning the GC watermark and blocking concurrent writers.
    ///
    /// Safe to run from `Drop`: `rollback_blocking` is synchronous (no async, no executor parking on
    /// a Tokio worker — the Bolt session runs on a blocking task) and `rollback_open_tx` swallows any
    /// error, so this never panics-in-drop. Idempotent via `current_tx.take()`: a clean
    /// COMMIT/ROLLBACK/RESET or the EOF arm already emptied it, leaving nothing to do here.
    fn drop(&mut self) {
        if self.current_tx.is_some() {
            self.rollback_open_tx();
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

// The materialized-cell → Bolt structural value mapping lives in [`super::bolt_values`] so the
// deterministic VOPR Bolt client (rmp #163) packs results byte-identically to this seam. Re-exported
// under the original private names so the call sites below read unchanged.
use super::bolt_values::materialized_to_bolt;

/// Where a Bolt result's rows come from: the engine's bounded channel (a query) or a buffered
/// administrative result (rmp #84) — both stream through the same [`RecordStream`] seam.
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

/// The Bolt result stream: engine rows (holding the admission permit until exhausted/dropped) or
/// a buffered admin result, behind one [`RecordStream`].
pub struct BoltEngineStream {
    fields: Vec<String>,
    source: RowSource,
    /// The result summary, read AFTER the rows drain (`rmp` #512). For an engine query this is the
    /// shared sink the engine fills in `finalize_inflight`; for an admin result it is an empty sink.
    summary: SummarySink,
}

impl BoltEngineStream {
    /// Wraps a buffered administrative result, carrying its result summary (`rmp` #513): the query
    /// type (`s` for a schema/system change, `r` for a `SHOW *` read) and any schema/system counters,
    /// published into a fresh sink so [`Self::summary`] surfaces it exactly as an engine query's sink
    /// does (the admin path produces all rows synchronously, so there is no cross-thread ordering to
    /// observe — the sink is filled here, before any row drains).
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

impl RecordStream for BoltEngineStream {
    fn fields(&self) -> &[String] {
        &self.fields
    }

    fn next_record(&mut self) -> Result<Option<Record>, GraphusError> {
        match &mut self.source {
            // A query row arrives as materialized cells (entities already resolved through the
            // cursor's graph seam, so RBAC/MVCC are applied — rmp #93); map each onto the Bolt
            // structural value the PackStream encoder packs.
            RowSource::Engine { rows, .. } => Ok(rows
                .next()?
                .map(|cells| cells.into_iter().map(materialized_to_bolt).collect())),
            // A buffered admin row is plain property values; lift each into a `BoltValue::Value`.
            RowSource::Admin(rows) => Ok(rows
                .next()
                .map(|row| row.into_iter().map(BoltValue::Value).collect())),
        }
    }

    fn summary(&self) -> QuerySummary {
        to_bolt_summary(self.summary.get())
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
        // Administrative statements are intercepted BEFORE Cypher compilation (rmp #84/#91): the
        // grammar is strict, so regular Cypher always falls through to the engine untouched.
        match crate::admin::parse_admin_statement(query) {
            AdminParse::Command(cmd) => {
                if matches!(tx, TxControl::InExplicit { .. }) {
                    return Err(Self::admin_in_explicit_tx());
                }
                // `execute` audits the change/denial at the single admin funnel (rmp #70), with this
                // connection's source.
                let result = self
                    .context
                    .execute(self.principal.as_deref(), self.source, &cmd)?;
                return Ok(BoltEngineStream::admin(result));
            }
            // An index-DDL statement (rmp #91): authorize like a database command, then route it to
            // the target database's engine (the index catalog lives on the coordinator, not the
            // off-engine database catalog). Rejected inside an explicit transaction (not
            // transactional), behind the same admin-privilege gate, results streamed as admin rows.
            AdminParse::Index(cmd) => {
                if matches!(tx, TxControl::InExplicit { .. }) {
                    return Err(Self::admin_in_explicit_tx());
                }
                // The index command runs against the database this auto-commit RUN targets. Resolve
                // it FIRST so authorization is scoped to the *target* database (rmp #457): the
                // SCHEMA privilege is graph-scoped, so we must know the canonical database name
                // before we can ask whether the principal may run DDL on it.
                let db = match &tx {
                    TxControl::AutoCommit { db, .. } => db.as_deref(),
                    // Rejected above; this arm is unreachable, but keep it total.
                    TxControl::InExplicit { .. } => None,
                };
                let (name, handle) = self.context.resolve(db)?;
                // Authorization next — no side effects on denial. Index/constraint DDL requires the
                // SCHEMA privilege on the target database (`Admin` still satisfies it via RBAC
                // containment); this lets `GRANT SCHEMA ON GRAPH x` delegate DDL without full Admin
                // (rmp #457). The index command isn't an `AdminCommand`, so the seam audits its own
                // denial / schema change (rmp #70) via `context.audit()`.
                if let Err(e) = self
                    .context
                    .authorize_schema(self.principal.as_deref(), &name)
                {
                    self.context.audit().record(
                        AuditEvent::new(
                            AuditClass::AuthzDenied,
                            AuditOutcome::Failure,
                            self.source,
                        )
                        .actor(self.principal.as_deref())
                        .database(Some(&name))
                        .detail(redact_index_detail(&cmd)),
                    );
                    return Err(e);
                }
                // `SHOW (FULLTEXT|POINT) INDEXES` is read-only — only the mutating CREATE/DROP are
                // schema changes (`rmp` task #72/#98 add the full-text / point SHOW to the read-only
                // set).
                let mutating = !matches!(
                    cmd,
                    crate::engine::IndexCommand::ShowIndexes
                        | crate::engine::IndexCommand::ShowFulltextIndexes
                        | crate::engine::IndexCommand::ShowPointIndexes
                );
                let detail = redact_index_detail(&cmd);
                // The result summary (`rmp` #513): query type `s` + `indexes-added`/`indexes-removed`
                // for a CREATE/DROP, or type `r` for a `SHOW`. Built from the command before it is
                // moved into the engine; only the success path reaches the stream (a failure returns
                // via `outcome?` below), so `ok = true`.
                let summary = index_ddl_summary(&cmd, true);
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
                            self.source,
                        )
                        .actor(self.principal.as_deref())
                        .database(Some(&name))
                        .detail(detail),
                    );
                }
                let reply = outcome?;
                return Ok(BoltEngineStream::admin(AdminResult {
                    fields: reply.fields,
                    rows: reply.rows,
                    summary,
                }));
            }
            // A constraint-DDL statement (`rmp` task #99): routed exactly like an index command — same
            // admin-privilege gate, same target-database resolution, same schema-change audit — but
            // submitted as a constraint command (the constraint catalog lives on the coordinator). A
            // `CREATE CONSTRAINT` over violating existing data fails with a constraint-validation error.
            AdminParse::Constraint(cmd) => {
                if matches!(tx, TxControl::InExplicit { .. }) {
                    return Err(Self::admin_in_explicit_tx());
                }
                // Resolve the target database FIRST so authorization is scoped to it (rmp #457).
                let db = match &tx {
                    TxControl::AutoCommit { db, .. } => db.as_deref(),
                    TxControl::InExplicit { .. } => None,
                };
                let (name, handle) = self.context.resolve(db)?;
                // Authorization next — no side effects on denial. Constraint DDL requires SCHEMA on
                // the target database (`Admin` still satisfies it via RBAC containment; rmp #457).
                if let Err(e) = self
                    .context
                    .authorize_schema(self.principal.as_deref(), &name)
                {
                    self.context.audit().record(
                        AuditEvent::new(
                            AuditClass::AuthzDenied,
                            AuditOutcome::Failure,
                            self.source,
                        )
                        .actor(self.principal.as_deref())
                        .database(Some(&name))
                        .detail(redact_constraint_detail(&cmd)),
                    );
                    return Err(e);
                }
                // `SHOW CONSTRAINTS` is read-only — only the mutating CREATE/DROP are schema changes.
                let mutating = !matches!(cmd, crate::engine::ConstraintCommand::Show);
                let detail = redact_constraint_detail(&cmd);
                // The result summary (`rmp` #513): query type `s` +
                // `constraints-added`/`constraints-removed` for a CREATE/DROP, or type `r` for a
                // `SHOW`. Built before the command is moved into the engine; only the success path
                // reaches the stream (a failure returns via `outcome?`), so `ok = true`.
                let summary = constraint_ddl_summary(&cmd, true);
                let outcome = handle.constraint_ddl_blocking(cmd);
                if mutating {
                    self.context.audit().record(
                        AuditEvent::new(
                            AuditClass::SchemaChange,
                            if outcome.is_ok() {
                                AuditOutcome::Success
                            } else {
                                AuditOutcome::Failure
                            },
                            self.source,
                        )
                        .actor(self.principal.as_deref())
                        .database(Some(&name))
                        .detail(detail),
                    );
                }
                let reply = outcome?;
                return Ok(BoltEngineStream::admin(AdminResult {
                    fields: reply.fields,
                    rows: reply.rows,
                    summary,
                }));
            }
            // Claimed by the admin grammar but malformed: a compile-time (syntax) error. The
            // claimed prefixes are never valid Cypher, so this steals nothing from the language.
            AdminParse::Invalid(msg) => return Err(GraphusError::Compile(msg)),
            AdminParse::NotAdmin => {}
        }

        match tx {
            TxControl::AutoCommit { mode, db } => {
                // Resolve the target database at transaction begin (rmp #84): absent/empty `db`
                // is the default database; a named one resolves through the catalog.
                let (name, handle) = self.context.resolve(db.as_deref())?;
                let engine_mode = from_bolt_mode(mode);
                // Open an internal auto-commit transaction the engine finalises on stream drain.
                let ticket = handle.begin_auto_commit_blocking(engine_mode)?;
                let stream = self.run_on(
                    &handle, ticket, &name, query, parameters, /* auto_commit */ true,
                );
                // Data-change audit (rmp #70, config-gated): a write that the engine ACCEPTED is
                // audited at this seam (the row stream is lazy; acceptance is the correct,
                // cheap point). A failed run is outcome=Failure. Full query text is NEVER logged —
                // only the category. Read runs are not data changes.
                self.audit_data_change_if_enabled(
                    &name,
                    query,
                    engine_mode,
                    if stream.is_ok() {
                        AuditOutcome::Success
                    } else {
                        AuditOutcome::Failure
                    },
                );
                stream
            }
            TxControl::InExplicit { db } => {
                let open = self.current_tx.as_ref().ok_or_else(|| {
                    GraphusError::Transaction(
                        "RUN in explicit transaction but none is open".to_owned(),
                    )
                })?;
                // A transaction is pinned to its database: a different non-empty `db` on a RUN
                // inside it is an error (rmp #84 — no mid-transaction database switch). The names
                // compare case-insensitively (the catalog's rule).
                if let Some(requested) = db.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
                    if !requested.eq_ignore_ascii_case(&open.db) {
                        return Err(GraphusError::Protocol(format!(
                            "cannot switch database inside an explicit transaction: the \
                             transaction is pinned to {:?} but RUN requested {requested:?}",
                            open.db
                        )));
                    }
                }
                let (handle, ticket, pinned_db, tx_mode) =
                    (open.handle.clone(), open.ticket, open.db.clone(), open.mode);
                let stream = self.run_on(
                    &handle, ticket, &pinned_db, query, parameters, /* auto_commit */ false,
                );
                // Data-change audit (rmp #70, config-gated): a write inside a write-mode explicit
                // transaction is a data change at acceptance, exactly as the auto-commit path.
                self.audit_data_change_if_enabled(
                    &pinned_db,
                    query,
                    tx_mode,
                    if stream.is_ok() {
                        AuditOutcome::Success
                    } else {
                        AuditOutcome::Failure
                    },
                );
                stream
            }
        }
    }

    fn begin(&mut self, mode: BoltAccessMode, db: Option<&str>) -> Result<(), GraphusError> {
        if self.current_tx.is_some() {
            return Err(GraphusError::Transaction(
                "a transaction is already open".to_owned(),
            ));
        }
        // Resolve at begin; the transaction stays pinned to this database (rmp #84).
        let (name, handle) = self.context.resolve(db)?;
        let engine_mode = from_bolt_mode(mode);
        let ticket = handle.begin_blocking(engine_mode)?;
        self.current_tx = Some(OpenTx {
            ticket,
            handle,
            db: name,
            mode: engine_mode,
        });
        Ok(())
    }

    fn commit(&mut self) -> Result<QuerySummary, GraphusError> {
        let open = self.current_tx.take().ok_or_else(|| {
            GraphusError::Transaction("COMMIT with no open transaction".to_owned())
        })?;
        let summary = open.handle.commit_blocking(open.ticket)?;
        Ok(to_bolt_summary(summary))
    }

    fn rollback(&mut self) -> Result<(), GraphusError> {
        let open = self.current_tx.take().ok_or_else(|| {
            GraphusError::Transaction("ROLLBACK with no open transaction".to_owned())
        })?;
        open.handle.rollback_blocking(open.ticket)
    }

    fn set_principal(&mut self, principal: Option<&str>) {
        self.principal = principal.map(str::to_owned);
    }

    fn rollback_open_tx(&mut self) {
        // Best-effort: roll back any explicit transaction this connection still holds. Idempotent —
        // `current_tx.take()` means a prior explicit ROLLBACK/RESET (which already cleared it) makes
        // this a no-op, so the session's EOF arm and `Drop` cannot double-roll-back.
        if let Some(open) = self.current_tx.take() {
            let _ = open.handle.rollback_blocking(open.ticket);
        }
    }

    fn on_auth_success(&mut self, principal: &str) {
        // Record the successful LOGON (rmp #70). Security-relevant ⇒ fsync'd before returning. Only
        // the username is recorded; credentials are never seen here.
        self.context.audit().record(
            AuditEvent::new(AuditClass::AuthSuccess, AuditOutcome::Success, self.source)
                .actor(Some(principal))
                .detail("LOGON basic"),
        );
    }

    fn on_auth_failure(&mut self, principal: Option<&str>, reason: &str) {
        // Record the failed LOGON (rmp #70). ALWAYS audited (security-relevant ⇒ fsync'd). The
        // attempted username may be `None`; credentials are NEVER passed/logged.
        self.context.audit().record(
            AuditEvent::new(AuditClass::AuthFailure, AuditOutcome::Failure, self.source)
                .actor(principal)
                .detail(format!("LOGON basic: {reason}")),
        );
    }
}
