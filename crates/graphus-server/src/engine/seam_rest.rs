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
//! [`RestEngine::run`] matches the statement against the strict admin grammar before the engine
//! sees it (see [`crate::admin`]). Admin statements require the global `Admin` privilege, are
//! rejected inside an explicit (client-managed) transaction, and on the auto-commit shortcut they
//! execute immediately — outside the surrounding engine transaction (they are not transactional;
//! the engine transaction the router opened simply commits empty afterwards).
//!
//! The router's row-pull (`ResultStream::next_row`) and the `run`/`commit`/`rollback` calls are
//! synchronous; the server drives each REST connection's router future to completion on a
//! `spawn_blocking` thread (see [`crate::listeners::rest`]), so these blocking submits never park a
//! Tokio runtime worker (`04 §9.1`).

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, PoisonError};

use graphus_core::{GraphusError, Value};
use graphus_cypher::{MaterializedPath, MaterializedValue};
use graphus_rest::engine::{
    AccessMode as RestAccessMode, RestEngine, ResultStream, Row, RunSummary as RestRunSummary,
    TxHandle, TxOrigin,
};
use graphus_rest::restvalue::{RestNode, RestPath, RestRelationship, RestValue};

use crate::admin::{AdminContext, AdminParse, AdminResult};
use crate::audit::{
    AuditClass, AuditEvent, AuditOutcome, AuditSource, data_change_detail, redact_index_detail,
};

use super::command::AccessMode;
use super::handle::AdmissionPermit;
use super::privileges::EffectivePrivileges;
use super::stream::RowReceiver;
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
        self.txns().get(&tx.0).cloned().ok_or_else(|| {
            GraphusError::Transaction(format!("unknown transaction handle {}", tx.0))
        })
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
    }
}

/// Maps a materialized result cell ([`MaterializedValue`], entity already resolved through the
/// cursor's graph seam) onto the REST structural value ([`RestValue`]) the router encodes as a
/// self-describing JSON object (`04 §8.3`; rmp #76/#96/#77). A property value passes through.
fn materialized_to_rest(value: &MaterializedValue) -> RestValue {
    match value {
        MaterializedValue::Value(v) => RestValue::Value(v.clone()),
        MaterializedValue::Node(n) => RestValue::Node(RestNode {
            id: i64::try_from(n.id).unwrap_or(i64::MAX),
            labels: n.labels.clone(),
            properties: n.properties.clone(),
        }),
        MaterializedValue::Relationship(r) => RestValue::Relationship(materialized_rel_to_rest(r)),
        MaterializedValue::Path(p) => RestValue::Path(materialized_path_to_rest(p)),
        MaterializedValue::List(items) => {
            RestValue::List(items.iter().map(materialized_to_rest).collect())
        }
    }
}

/// Maps a materialized relationship onto a REST relationship.
fn materialized_rel_to_rest(r: &graphus_cypher::MaterializedRel) -> RestRelationship {
    RestRelationship {
        id: i64::try_from(r.id).unwrap_or(i64::MAX),
        start: i64::try_from(r.start).unwrap_or(i64::MAX),
        end: i64::try_from(r.end).unwrap_or(i64::MAX),
        rel_type: r.rel_type.clone(),
        properties: r.properties.clone(),
    }
}

/// Maps a materialized path onto a REST path: nodes and relationships in traversal order (the REST
/// shape is the ordered walk, not the Bolt distinct-lists-plus-indices form).
fn materialized_path_to_rest(p: &MaterializedPath) -> RestPath {
    let mut nodes = Vec::with_capacity(p.steps.len() + 1);
    nodes.push(node_to_rest(&p.start));
    let mut relationships = Vec::with_capacity(p.steps.len());
    for step in &p.steps {
        relationships.push(materialized_rel_to_rest(&step.rel));
        nodes.push(node_to_rest(&step.node));
    }
    RestPath {
        nodes,
        relationships,
    }
}

/// Maps a materialized node onto a REST node.
fn node_to_rest(n: &graphus_cypher::MaterializedNode) -> RestNode {
    RestNode {
        id: i64::try_from(n.id).unwrap_or(i64::MAX),
        labels: n.labels.clone(),
        properties: n.properties.clone(),
    }
}

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
    summary: RestRunSummary,
}

impl RestEngineStream {
    /// Wraps a buffered administrative result.
    fn admin(result: AdminResult) -> Self {
        Self {
            fields: result.fields,
            source: RowSource::Admin(result.rows.into_iter()),
            summary: RestRunSummary::default(),
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
                .map(|cells| cells.iter().map(materialized_to_rest).collect())),
            // A buffered admin row is plain property values; lift each into a `RestValue::Value`.
            RowSource::Admin(rows) => Ok(rows
                .next()
                .map(|row| row.into_iter().map(RestValue::Value).collect())),
        }
    }

    fn summary(&self) -> RestRunSummary {
        self.summary.clone()
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
        let ticket = handle.begin_blocking(engine_mode)?;
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

        // Administrative statements are intercepted BEFORE Cypher compilation (rmp #84/#91); see the
        // module docs for the explicit-vs-auto-commit rule.
        match crate::admin::parse_admin_statement(query) {
            AdminParse::Command(cmd) => {
                if open.explicit {
                    return Err(admin_in_explicit_tx());
                }
                // `execute` audits the change/denial at the single admin funnel (rmp #70) with the
                // REST source.
                let result =
                    self.context
                        .execute(Some(&open.principal), AuditSource::Rest, &cmd)?;
                return Ok(RestEngineStream::admin(result));
            }
            // An index-DDL statement (rmp #91): authorize like a database command, then route it to
            // the engine the transaction was opened against (the index catalog lives on the
            // coordinator). Rejected inside an explicit transaction, behind the admin-privilege gate.
            AdminParse::Index(cmd) => {
                if open.explicit {
                    return Err(admin_in_explicit_tx());
                }
                // Authorization first — no side effects on denial (shared gate with the DB surface).
                // The seam audits the index-DDL denial / schema change itself (rmp #70).
                if let Err(e) = self.context.authorize_admin(Some(&open.principal)) {
                    self.context.audit().record(
                        AuditEvent::new(
                            AuditClass::AuthzDenied,
                            AuditOutcome::Failure,
                            AuditSource::Rest,
                        )
                        .actor(Some(&open.principal))
                        .detail(redact_index_detail(&cmd)),
                    );
                    return Err(e);
                }
                // `SHOW (FULLTEXT) INDEXES` is read-only — only the mutating CREATE/DROP are schema
                // changes (`rmp` task #72 adds the full-text SHOW to the read-only set).
                let mutating = !matches!(
                    cmd,
                    crate::engine::IndexCommand::ShowIndexes
                        | crate::engine::IndexCommand::ShowFulltextIndexes
                );
                let detail = redact_index_detail(&cmd);
                let outcome = open.handle.index_ddl_blocking(cmd);
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
                        .actor(Some(&open.principal))
                        .database(Some(&open.db))
                        .detail(detail),
                    );
                }
                let reply = outcome?;
                return Ok(RestEngineStream::admin(AdminResult {
                    fields: reply.fields,
                    rows: reply.rows,
                }));
            }
            AdminParse::Invalid(msg) => return Err(GraphusError::Compile(msg)),
            AdminParse::NotAdmin => {}
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
            summary: RestRunSummary::default(),
        })
    }

    fn commit(&self, tx: TxHandle) -> Result<RestRunSummary, GraphusError> {
        // Remove first: whatever the engine answers, the public handle is spent.
        let open = self.txns().remove(&tx.0).ok_or_else(|| {
            GraphusError::Transaction(format!("unknown transaction handle {}", tx.0))
        })?;
        let summary = open.handle.commit_blocking(open.ticket)?;
        Ok(to_rest_summary(summary))
    }

    fn rollback(&self, tx: TxHandle) -> Result<(), GraphusError> {
        // Idempotent, matching the trait contract: an unknown/already-finished handle is Ok(())
        // (the registry's inactivity sweep and an explicit DELETE can race safely).
        let Some(open) = self.txns().remove(&tx.0) else {
            return Ok(());
        };
        open.handle.rollback_blocking(open.ticket)
    }
}
