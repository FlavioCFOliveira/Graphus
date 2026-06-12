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
use graphus_bolt::packstream::{BoltNode, BoltPath, BoltRelationship, BoltValue};
use graphus_core::{GraphusError, Value};
use graphus_cypher::{MaterializedPath, MaterializedValue};

use crate::admin::{AdminContext, AdminParse, AdminResult};

use super::command::AccessMode;
use super::handle::AdmissionPermit;
use super::privileges::EffectivePrivileges;
use super::stream::RowReceiver;
use super::{EngineHandle, RunSummary, TxTicket};

/// One Bolt connection's view of the server: the shared database-targeting/admin context, the
/// session principal, and this connection's current explicit transaction (if a `BEGIN` is open).
pub struct BoltEngineExecutor {
    /// Database targeting + administrative statements, shared across connections.
    context: AdminContext,
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
}

impl BoltEngineExecutor {
    /// A fresh per-connection executor over the shared `context`.
    #[must_use]
    pub fn new(context: AdminContext) -> Self {
        Self {
            context,
            principal: None,
            current_tx: None,
        }
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
            // v1 summary: the query type is not yet surfaced by the executor; an empty summary is a
            // valid `SUCCESS` body (`06 §3.1`). Richer summaries arrive with executor stats.
            summary: QuerySummary::default(),
        })
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

/// Maps a materialized result cell ([`MaterializedValue`], entity already resolved through the
/// cursor's graph seam) onto the Bolt structural value ([`BoltValue`]) the PackStream encoder packs
/// (`04 §8.3`; rmp #76/#96). A property value passes through; a structural list recurses.
fn materialized_to_bolt(value: &MaterializedValue) -> BoltValue {
    match value {
        MaterializedValue::Value(v) => BoltValue::Value(v.clone()),
        MaterializedValue::Node(n) => BoltValue::Node(BoltNode {
            // The opaque id is a `u64`; Bolt ids are `i64`. The id is a small internal handle, so the
            // saturating cast never actually clamps in practice — defensive only.
            id: i64::try_from(n.id).unwrap_or(i64::MAX),
            labels: n.labels.clone(),
            properties: n.properties.clone(),
        }),
        MaterializedValue::Relationship(r) => BoltValue::Relationship(materialized_rel_to_bolt(r)),
        MaterializedValue::Path(p) => BoltValue::Path(materialized_path_to_bolt(p)),
        MaterializedValue::List(items) => {
            BoltValue::List(items.iter().map(materialized_to_bolt).collect())
        }
    }
}

/// Maps a materialized relationship onto a Bolt relationship.
fn materialized_rel_to_bolt(r: &graphus_cypher::MaterializedRel) -> BoltRelationship {
    BoltRelationship {
        id: i64::try_from(r.id).unwrap_or(i64::MAX),
        start: i64::try_from(r.start).unwrap_or(i64::MAX),
        end: i64::try_from(r.end).unwrap_or(i64::MAX),
        rel_type: r.rel_type.clone(),
        properties: r.properties.clone(),
    }
}

/// Maps a materialized path onto a Bolt `Path`, decomposing it into the distinct nodes, distinct
/// unbound relationships, and the signed/1-based index sequence the Bolt `Path` structure packs
/// (delegated to [`MaterializedPath::bolt_path_components`]).
fn materialized_path_to_bolt(p: &MaterializedPath) -> BoltPath {
    let (nodes, rels, indices) = p.bolt_path_components();
    BoltPath {
        nodes: nodes
            .into_iter()
            .map(|n| BoltNode {
                id: i64::try_from(n.id).unwrap_or(i64::MAX),
                labels: n.labels.clone(),
                properties: n.properties.clone(),
            })
            .collect(),
        rels: rels.into_iter().map(materialized_rel_to_bolt).collect(),
        indices,
    }
}

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
    summary: QuerySummary,
}

impl BoltEngineStream {
    /// Wraps a buffered administrative result.
    fn admin(result: AdminResult) -> Self {
        Self {
            fields: result.fields,
            source: RowSource::Admin(result.rows.into_iter()),
            summary: QuerySummary::default(),
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
                .map(|cells| cells.iter().map(materialized_to_bolt).collect())),
            // A buffered admin row is plain property values; lift each into a `BoltValue::Value`.
            RowSource::Admin(rows) => Ok(rows
                .next()
                .map(|row| row.into_iter().map(BoltValue::Value).collect())),
        }
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
        // Administrative statements are intercepted BEFORE Cypher compilation (rmp #84/#91): the
        // grammar is strict, so regular Cypher always falls through to the engine untouched.
        match crate::admin::parse_admin_statement(query) {
            AdminParse::Command(cmd) => {
                if matches!(tx, TxControl::InExplicit { .. }) {
                    return Err(Self::admin_in_explicit_tx());
                }
                let result = self.context.execute(self.principal.as_deref(), &cmd)?;
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
                // Authorization first — no side effects on denial (shared gate with the DB surface).
                self.context.authorize_admin(self.principal.as_deref())?;
                // The index command runs against the database this auto-commit RUN targets.
                let db = match &tx {
                    TxControl::AutoCommit { db, .. } => db.as_deref(),
                    // Rejected above; this arm is unreachable, but keep it total.
                    TxControl::InExplicit { .. } => None,
                };
                let (_name, handle) = self.context.resolve(db)?;
                let reply = handle.index_ddl_blocking(cmd)?;
                return Ok(BoltEngineStream::admin(AdminResult {
                    fields: reply.fields,
                    rows: reply.rows,
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
                // Open an internal auto-commit transaction the engine finalises on stream drain.
                let ticket = handle.begin_auto_commit_blocking(from_bolt_mode(mode))?;
                self.run_on(
                    &handle, ticket, &name, query, parameters, /* auto_commit */ true,
                )
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
                let (handle, ticket, pinned_db) =
                    (open.handle.clone(), open.ticket, open.db.clone());
                self.run_on(
                    &handle, ticket, &pinned_db, query, parameters, /* auto_commit */ false,
                )
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
        let ticket = handle.begin_blocking(from_bolt_mode(mode))?;
        self.current_tx = Some(OpenTx {
            ticket,
            handle,
            db: name,
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
}
