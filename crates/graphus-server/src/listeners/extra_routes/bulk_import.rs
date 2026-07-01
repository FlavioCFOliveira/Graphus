//! `POST /admin/db/{db}/bulk-import` — the network bulk-import streaming upload endpoint, **Mode A**
//! (`08-network-bulk-import.md`, decision `D-bulk-import-network`, `rmp` #518/#519).
//!
//! Mode A drives [`graphus_bulk`]'s low-level, offline-importer-equivalent ingestion (via
//! [`crate::engine::bulk_load`]) against an **empty** database taken over exclusively (the `Loading`
//! state, `08` §5.2) for the duration of the session. A non-empty, live-serving database is out of
//! scope here — that is Mode B (`rmp` #520, not yet implemented), and this endpoint `409`s cleanly
//! rather than attempting it.
//!
//! ## Wire protocol
//!
//! One HTTP session = one or more `POST` calls against the same `{db}`, distinguished by a query
//! parameter (the transport-level session/phase signaling `08` §4.2 deliberately left unspecified;
//! query parameters are the simplest, most REST-native, `curl`-friendly choice — no new route):
//!
//! - `?phase=nodes` / `?phase=relationships` — this call's body is one CSV (or `.gcol`) **file**
//!   (`Content-Type: text/csv` or `application/vnd.graphus.gcol`). The **first** such call against a
//!   given `{db}` implicitly **begins** the session (see "Session lifecycle" below); every subsequent
//!   call against the same, already-`Loading` `{db}` **continues** it. Response: `200 OK` with the
//!   session's cumulative `{"nodes":N,"relationships":M,"properties":P}` once this call's whole file
//!   has been durably ingested (batch-by-batch; see "Streaming and batching").
//! - `?end=true` — ends the session: durably deletes the checkpoint sentinel, moves the database from
//!   `Loading` to `Offline` (never straight back to `Online` — `08` §5.2; the operator issues
//!   `START DATABASE` once satisfied with the load), and returns the final cumulative stats. Empty
//!   body, no `Content-Type` required. **Idempotent**: calling it when no session is active (never
//!   begun, or already ended) is a `200` no-op reporting zero stats, never an error.
//!
//! A request naming neither a recognized `phase` nor `end=true` is `400`.
//!
//! ## Session lifecycle and the empty-database precondition
//!
//! The precondition check ("Mode A requires an empty database") runs **only on the call that begins
//! the session** — i.e. when `{db}` is not already `Loading`. It resolves the database's *ordinary*
//! (not-yet-`Loading`) handle, runs `MATCH (n) RETURN count(n)` through it, and `409`s if the count is
//! non-zero, **before** calling [`crate::dbcatalog::DatabaseCatalog::begin_loading`]. A subsequent call
//! against an already-`Loading` `{db}` skips this check entirely (obviously — the database is by then
//! non-empty by design) and simply reuses [`crate::dbcatalog::DatabaseCatalog::loading_handle`].
//!
//! **Known, accepted race**: the count check and `begin_loading` are two separate engine round-trips,
//! not one atomic operation — a write landing on the *ordinary* handle in the brief window between
//! them would not be caught. Closing this fully would need the precondition check to run *inside* the
//! same admission step that flips the database to `Loading` (a deeper `dbcatalog` change than this
//! stage's scope); it is called out here rather than silently accepted.
//!
//! `CatalogError` → HTTP status (`catalog_error_response`, this module — deliberately **not** reusing
//! `admin.rs`'s private `graphus_error_from_catalog`, which collapses every client fault to a generic
//! `400`/Bolt-`ArgumentError` shape for the Cypher admin-statement surface; this REST-native endpoint
//! wants the more specific statuses a bulk-import client can branch on): `NotLoadable` → `409`
//! (already loading / not online — a concurrent session lost the race, or the database is offline),
//! `DefaultDatabase` → `400` (consistent with every other admin surface's treatment of "the default
//! database can't do that" as a client-fault `400`, not a `403` — this is a resource-shape rejection,
//! not an authorization failure; RBAC already passed), `UnknownDatabase` → `404`, `InvalidName` →
//! `400`, everything else (`Io`/`Corrupt`/`Encode`/`Engine`) → `500`.
//!
//! ## Streaming and batching
//!
//! Each `phase=...` call's body is parsed as ONE CSV file (`text/csv`) — or transcoded from `.gcol`
//! into the same CSV shape first (see "`.gcol` handling" below) — and its rows are accumulated into
//! batches of up to [`graphus_bulk::DEFAULT_BATCH_SIZE`], each submitted as one
//! [`crate::engine::EngineHandle::bulk_import_batch`] call, so the engine thread is never blocked for
//! the whole upload. The file's header (first CSV record) is parsed once per call and its
//! `Arc<NodeHeader>`/`Arc<RelHeader>` is reused (via `Arc::clone`) for every batch of that call, so
//! [`crate::engine::bulk_load::LoadingSession`]'s `Arc::ptr_eq` per-file token-cache refresh check
//! works as intended. The final (possibly empty, if the file had a header but no remaining data rows —
//! a legitimate resumed call) batch of a call is **always** submitted, mirroring
//! `graphus_bulk::BulkImporter`'s own unconditional final commit, so a call's response always reports
//! accurate, current cumulative stats even when it ingested zero rows.
//!
//! The async request-handling task and the synchronous `csv::Reader` batch loop run on two different
//! tasks, bridged by a small bounded `tokio::sync::mpsc` channel of raw [`bytes::Bytes`] chunks (see
//! [`ChunkReader`]): the async task polls [`http_body_util::BodyExt::frame`] and forwards each chunk
//! (after the byte-quota/disk-space checks below), while a [`tokio::task::spawn_blocking`] task reads
//! from the channel through a `std::io::Read` adapter, drives `csv::Reader`, and — for each full batch
//! — calls back into the (async) engine via `tokio::runtime::Handle::block_on`. Calling `block_on` from
//! inside `spawn_blocking` (never on a runtime worker) is the same established, already-audited pattern
//! this codebase's own `command.rs` module docs describe for the synchronous Bolt/REST seams: "REST
//! whose synchronous handlers run inside a `Handle::block_on` on a blocking thread". The channel's
//! small fixed capacity is exactly the backpressure `08` §8 asks for: a slow (or currently-committing)
//! batch stalls `tx.send`, which stalls the frame-poll loop, which stops the server reading further
//! socket bytes — no unbounded buffering on either side of the bridge.
//!
//! ## `.gcol` handling
//!
//! `.gcol`'s CRC-32C-at-the-end framing ([`graphus_bulk::gcol_to_csv`]) makes it structurally
//! impossible to decode incrementally — the whole blob must be present before any row can be produced.
//! For `Content-Type: application/vnd.graphus.gcol` the body is therefore buffered whole (still
//! byte-quota-bounded — never unbounded), transcoded to CSV bytes in one call, and those bytes are fed
//! through the **exact same** batch loop the streaming CSV path uses (`run_batch_loop`, generic over
//! `std::io::Read` — a `ChunkReader` for CSV, a `std::io::Cursor` for the already-in-memory `.gcol`
//! transcode). This is a deliberate, spec-consistent trade-off, not an implementation gap: `.gcol`'s
//! wire-compactness benefit (`08` §4.2) is orthogonal to incremental parseability, which the format
//! itself forecloses.
//!
//! ## Dropped-connection / retry behavior
//!
//! If the client's connection drops mid-file (whether due to a network blip or the client aborting), a
//! partially-in-flight batch is rolled back by the engine (`crate::engine::bulk_load`'s abort-safety
//! invariant — a batch's `id_map`/stats bindings only land once its commit succeeds) and the database
//! **stays `Loading`** — this handler never calls `end_loading` except on an explicit `?end=true`, so a
//! mid-file failure never forecloses resuming. The client simply retries the **same** `phase=nodes` /
//! `phase=relationships` call, resending the header plus **every row not yet reflected in the last
//! successful response's cumulative counts** (rows from earlier, already-committed batches of the same
//! call are safe and must not be resent — the session's `id_map`/token caches are still live on the
//! engine thread for as long as the process itself has not restarted). This endpoint does **not** track
//! byte offsets or implement a checkpoint-resume protocol beyond that — a fuller offset-tracking scheme
//! was judged out of scope for this stage (see `crate::engine::bulk_load`'s module docs on the deeper,
//! **process-restart** case: a fresh, empty `id_map` after a crash cannot safely re-ingest a file whose
//! earlier bytes were already committed before the crash, so a client resuming after a full server
//! restart must resume from the last **fully durable file boundary**, never mid-file — this stage
//! forecloses that hazard the simple way, by documenting the contract rather than adding new
//! byte-offset bookkeeping), consistent with the already-ratified `08` §7.1 non-atomic per-batch-commit
//! model (`D-bulk-import-non-atomic`, `rmp` #403).
//!
//! ## Scope decisions
//!
//! [`BulkImportConfig`](crate::config::BulkImportConfig)'s doc comments describe `max_bytes_per_session`
//! and the session timeout as spanning a **whole** (potentially multi-call) bulk-import session. This
//! stage enforces both **per HTTP call** (per file) instead: each `phase=...`/`end=true` call gets its
//! own fresh quota/timeout budget, exactly as the scaffolding milestone (`rmp` #518) already did before
//! the multi-call protocol existed. True cross-call accounting would require new state threaded across
//! HTTP requests (a database-keyed bytes-used/session-start ledger) — a reasonable follow-up, but one
//! this stage deliberately does not add, to keep the session-lifecycle change this task already makes
//! (single-call → multi-call) from also having to invent new cross-request bookkeeping in the same
//! change. Each individual file is still fully bounded, so this is not an unbounded-resource regression
//! — only a narrower interpretation of "session" than the config doc's wording literally states.
//!
//! ## RBAC
//!
//! Unchanged from the scaffolding milestone: gated by the exact same [`require_admin`](super::require_admin)
//! (global `Admin` privilege) check as `/admin/status`, `/admin/users/{name}` and `/admin/shutdown`. A
//! denial is audited as [`AuditClass::AuthzDenied`] before any side effect.
//!
//! ## The 4 MiB body-limit exemption
//!
//! Unchanged: this route is deliberately **not** behind
//! [`graphus_rest::router::MAX_REQUEST_BODY_BYTES`]'s `DefaultBodyLimit` layer (`08` §3.3) — its own
//! purpose-built byte quota governs it instead.

use std::io::{Cursor, Read};
use std::path::{Path as FsPath, PathBuf};
use std::sync::Arc;

use axum::body::Body;
use axum::extract::{Path, RawQuery, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use bytes::Bytes;
use graphus_bulk::{DEFAULT_BATCH_SIZE, ImportStats, NodeHeader, RelHeader, gcol_to_csv};
use graphus_core::{GraphusError, Value};
use graphus_cypher::MaterializedValue;
use http_body_util::BodyExt;

use crate::audit::{AuditClass, AuditEvent, AuditOutcome, AuditSource};
use crate::dbcatalog::CatalogError;
use crate::engine::{AccessMode, BulkImportBatchInput, EngineHandle};

use super::{ExtraState, require_admin};

/// The two payload formats `graphus-bulk`'s low-level ingestion already understands (`08` §4.2):
/// selected by `Content-Type`, mirroring the existing `graphus-bulk import --format csv|gcol` CLI
/// flag.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BulkImportFormat {
    /// The `neo4j-admin import`-flavoured CSV format (`Content-Type: text/csv`).
    Csv,
    /// The lossless columnar `.gcol` format (`rmp` #327; `Content-Type:
    /// application/vnd.graphus.gcol`).
    Gcol,
}

impl BulkImportFormat {
    /// The canonical lowercase name, for audit details and response/error bodies.
    fn as_str(self) -> &'static str {
        match self {
            Self::Csv => "csv",
            Self::Gcol => "gcol",
        }
    }

    /// Detects the payload format from the request's `Content-Type` header (`08` §4.2). The media
    /// type is matched on its essence only (a trailing `; charset=...` parameter, if any, is
    /// ignored) and case-insensitively, matching ordinary HTTP media-type comparison rules
    /// (RFC 9110 §8.3.1).
    ///
    /// # Errors
    /// A short, client-facing message naming the missing/unrecognized `Content-Type`.
    fn from_headers(headers: &HeaderMap) -> Result<Self, String> {
        let raw = headers
            .get(header::CONTENT_TYPE)
            .ok_or_else(|| {
                "missing Content-Type: send text/csv or application/vnd.graphus.gcol".to_owned()
            })?
            .to_str()
            .map_err(|_| "Content-Type header is not valid UTF-8/ASCII".to_owned())?;
        let essence = raw.split(';').next().unwrap_or(raw).trim();
        match essence.to_ascii_lowercase().as_str() {
            "text/csv" => Ok(Self::Csv),
            "application/vnd.graphus.gcol" => Ok(Self::Gcol),
            _ => Err(format!(
                "unsupported Content-Type {essence:?}: expected text/csv or \
                 application/vnd.graphus.gcol"
            )),
        }
    }
}

/// Which file a `phase=...` call's body carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    Nodes,
    Relationships,
}

impl Phase {
    fn as_str(self) -> &'static str {
        match self {
            Self::Nodes => "nodes",
            Self::Relationships => "relationships",
        }
    }
}

/// What this call is asking the server to do, decoded from the query string.
#[derive(Debug)]
enum Op {
    Phase(Phase),
    End,
}

/// Parses `raw_query` (the request's raw query string, `None` if absent) into an [`Op`].
///
/// Recognized parameters: `phase` (`"nodes"` or `"relationships"`) and `end` (`"true"`; any other
/// value, or its absence, means "not ending"). `end=true` takes precedence if somehow both are
/// present (defensive — a well-behaved client never sends both). Every other query parameter is
/// ignored. Values are compared verbatim (no percent-decoding): the three accepted literals never
/// need it, and a client that needlessly encodes them gets a clear `400` rather than a silent
/// misparse.
///
/// # Errors
/// A short, client-facing message when neither a recognized `phase` nor `end=true` is present.
fn parse_op(raw_query: Option<&str>) -> Result<Op, String> {
    let mut phase: Option<&str> = None;
    let mut end = false;
    for pair in raw_query.unwrap_or_default().split('&') {
        if pair.is_empty() {
            continue;
        }
        let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
        match key {
            "phase" => phase = Some(value),
            "end" => end = value == "true",
            _ => {}
        }
    }
    if end {
        return Ok(Op::End);
    }
    match phase {
        Some("nodes") => Ok(Op::Phase(Phase::Nodes)),
        Some("relationships") => Ok(Op::Phase(Phase::Relationships)),
        Some(other) => Err(format!(
            "invalid phase={other:?}: expected \"nodes\" or \"relationships\""
        )),
        None => Err(
            "missing query parameter: specify ?phase=nodes, ?phase=relationships, or ?end=true"
                .to_owned(),
        ),
    }
}

/// `POST /admin/db/{db}/bulk-import` — see the module docs for the wire protocol.
pub(super) async fn admin_bulk_import(
    State(state): State<ExtraState>,
    Path(db): Path<String>,
    headers: HeaderMap,
    RawQuery(raw_query): RawQuery,
    body: Body,
) -> Response {
    let who = match require_admin(&state, &headers) {
        Ok(w) => w,
        Err(resp) => {
            state.audit.record(
                AuditEvent::new(
                    AuditClass::AuthzDenied,
                    AuditOutcome::Failure,
                    AuditSource::Rest,
                )
                .database(Some(&db))
                .detail("bulk-import session denied (missing/invalid Bearer or Admin privilege)"),
            );
            return *resp;
        }
    };

    let op = match parse_op(raw_query.as_deref()) {
        Ok(op) => op,
        Err(msg) => return (StatusCode::BAD_REQUEST, msg).into_response(),
    };

    let Ok(db_name) = crate::dbcatalog::normalize_db_name(&db) else {
        return (
            StatusCode::BAD_REQUEST,
            format!("invalid database name: {db:?}"),
        )
            .into_response();
    };
    if !state.catalog.exists(&db_name).await {
        return (
            StatusCode::NOT_FOUND,
            format!("no such database: {db_name:?}"),
        )
            .into_response();
    }

    match op {
        Op::End => handle_end(&state, &who, &db_name).await,
        Op::Phase(phase) => {
            let format = match BulkImportFormat::from_headers(&headers) {
                Ok(f) => f,
                Err(msg) => return (StatusCode::UNSUPPORTED_MEDIA_TYPE, msg).into_response(),
            };
            handle_phase(&state, &who, &db_name, phase, format, body).await
        }
    }
}

/// Maps a [`CatalogError`] onto this endpoint's HTTP status split — see the module docs for why this
/// is a dedicated mapping rather than reusing `admin.rs`'s private, more generic one.
fn catalog_error_response(e: CatalogError) -> (StatusCode, String) {
    let status = match &e {
        CatalogError::DefaultDatabase { .. } | CatalogError::InvalidName(_) => {
            StatusCode::BAD_REQUEST
        }
        CatalogError::NotLoadable(_)
        | CatalogError::AlreadyExists(_)
        | CatalogError::NotOffline(_)
        | CatalogError::Backup(_) => StatusCode::CONFLICT,
        CatalogError::UnknownDatabase(_) => StatusCode::NOT_FOUND,
        CatalogError::Io { .. }
        | CatalogError::Corrupt { .. }
        | CatalogError::Encode(_)
        | CatalogError::Engine(_) => StatusCode::INTERNAL_SERVER_ERROR,
    };
    (status, e.to_string())
}

/// Runs the Mode A empty-database precondition query through `engine`'s already-open ordinary handle:
/// `MATCH (n) RETURN count(n)`, admitted like any other query (`04 §9.3`) since it is a genuine
/// compile→execute→stream round trip, not a control-plane call.
///
/// # Errors
/// [`GraphusError`] if the query itself fails to compile/execute/stream.
async fn count_all_nodes(engine: &EngineHandle) -> Result<i64, GraphusError> {
    let ticket = engine.begin_auto_commit(AccessMode::Read).await?;
    let mut reply = engine
        .run(
            ticket,
            "MATCH (n) RETURN count(n) AS c".to_owned(),
            Vec::new(),
            true,
            None,
        )
        .await?;
    let mut count = 0i64;
    while let Some(row) = reply.rows.next()? {
        if let Some(MaterializedValue::Value(Value::Integer(n))) = row.into_iter().next() {
            count = n;
        }
    }
    Ok(count)
}

/// Begins a Mode A session against `db_name`: the empty-database precondition check, then
/// [`crate::dbcatalog::DatabaseCatalog::begin_loading`]. Called only when `db_name` is not already
/// `Loading` (the caller checks via [`crate::dbcatalog::DatabaseCatalog::loading_handle`] first).
///
/// # Errors
/// `(status, message)` for every rejection: the database is not resolvable as an ordinary online
/// handle, the server is at its admission limit, the precondition query itself fails, the database is
/// not empty, or `begin_loading` itself is refused (see [`catalog_error_response`]).
async fn begin_session(
    state: &ExtraState,
    db_name: &str,
) -> Result<EngineHandle, (StatusCode, String)> {
    let Some(ordinary) = state.catalog.handle(db_name) else {
        return Err((
            StatusCode::CONFLICT,
            format!(
                "database {db_name:?} is not currently online (it is offline, or another \
                 bulk-import session is already loading it); a Mode A session requires an online \
                 database"
            ),
        ));
    };

    let permit = ordinary
        .try_admit()
        .map_err(|busy| (StatusCode::SERVICE_UNAVAILABLE, busy.to_string()))?;
    let count = count_all_nodes(&ordinary).await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("bulk-import precondition check failed: {e}"),
        )
    })?;
    drop(permit);

    if count != 0 {
        return Err((
            StatusCode::CONFLICT,
            format!(
                "database {db_name:?} is not empty ({count} node(s) found); Mode A network \
                 bulk-import requires an empty database. For a live, non-empty database, Mode B \
                 (`rmp` #520) is the option — not yet implemented."
            ),
        ));
    }

    state
        .catalog
        .begin_loading(db_name)
        .await
        .map_err(catalog_error_response)
}

/// Renders `stats` as the endpoint's JSON response body.
fn stats_json(stats: &ImportStats) -> String {
    format!(
        "{{\"nodes\":{},\"relationships\":{},\"properties\":{}}}",
        stats.nodes, stats.relationships, stats.properties
    )
}

/// Queries the free/available bytes on the filesystem holding `dir` (`fs4::available_space`, a
/// `statvfs`-backed, pure-Rust — no raw `libc`/`unsafe` at this crate's boundary — syscall), off
/// the async runtime: `statvfs` is a blocking syscall, so it must never run on a runtime worker
/// (`04 §9.1`).
///
/// # Errors
/// A short, client-facing message when the blocking task panics or the syscall itself fails (e.g.
/// the directory does not exist yet).
async fn check_free_space(dir: &FsPath) -> Result<u64, String> {
    let probe = dir.to_path_buf();
    let display = probe.display().to_string();
    tokio::task::spawn_blocking(move || fs4::available_space(&probe))
        .await
        .map_err(|_| format!("disk-space check for {display} panicked"))?
        .map_err(|e| format!("disk-space check failed for {display}: {e}"))
}

/// Bytes consumed since the last disk-space re-check, before another check is due (`08` §8's
/// "ongoing check"): cheap enough to run every 64 MiB without materially slowing ingestion, tight
/// enough that a fast producer cannot run the device far past the reserve between checks.
const DISK_RECHECK_INTERVAL_BYTES: u64 = 64 * 1024 * 1024;

/// Why an in-flight bulk-import call was aborted, or why the underlying ingestion itself failed.
enum BulkIngestError {
    /// The client disconnected, or hyper reported a framing/transport error mid-body.
    Transport(String),
    /// The running byte total (this call) crossed [`BulkImportConfig::max_bytes_per_session`]
    /// (`crate::config::BulkImportConfig`; enforced per call — see the module docs' "Scope
    /// decisions").
    QuotaExceeded { quota: u64, received: u64 },
    /// A periodic disk-space re-check found free space below the configured reserve.
    DiskExhausted { free: u64, min_free: u64 },
    /// A periodic disk-space re-check itself failed (syscall error / panicked blocking task).
    DiskCheckFailed(String),
    /// A malformed CSV record.
    Csv(String),
    /// A malformed node/relationship CSV header.
    Header(String),
    /// A malformed/truncated `.gcol` payload. Reported directly as a `400` with the specific reason
    /// (not laundered through `graphus_bulk::ColumnarError`'s own `From<ColumnarError> for
    /// GraphusError` impl, which maps to `GraphusError::Storage` — a 500-class, detail-hidden server
    /// fault — the right call for OTHER callers of that conversion, but wrong here: a malformed
    /// upload is the client's fault, and this endpoint already gives every other format/quota error a
    /// specific, client-facing message).
    Gcol(String),
    /// The uploaded file has no header row (an empty body on a `phase=...` call).
    EmptyFile,
    /// A header/value-parse/storage error from the batch ingestion itself, or the underlying commit
    /// failure (`crate::engine::EngineHandle::bulk_import_batch`).
    Engine(GraphusError),
    /// The blocking ingest task panicked.
    JoinPanicked(String),
}

impl std::fmt::Display for BulkIngestError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Transport(e) => write!(f, "error reading upload body: {e}"),
            Self::QuotaExceeded { quota, received } => write!(
                f,
                "bulk-import upload exceeded the configured quota ({quota} bytes) after {received} \
                 bytes were received; the call was aborted"
            ),
            Self::DiskExhausted { free, min_free } => write!(
                f,
                "bulk-import upload aborted: free disk space dropped to {free} bytes, below the \
                 configured {min_free}-byte reserve"
            ),
            Self::DiskCheckFailed(e) => write!(f, "{e}"),
            Self::Csv(e) => write!(f, "CSV parse error: {e}"),
            Self::Header(e) => write!(f, "invalid CSV header: {e}"),
            Self::Gcol(e) => write!(f, "invalid .gcol payload: {e}"),
            Self::EmptyFile => write!(
                f,
                "the uploaded file has no header row (an empty body); resend the header plus any \
                 remaining rows, or call ?end=true if the session is complete"
            ),
            Self::Engine(e) => write!(f, "{e}"),
            Self::JoinPanicked(e) => write!(f, "bulk-import worker task failed: {e}"),
        }
    }
}

impl BulkIngestError {
    /// The HTTP status + client-facing message for this failure.
    fn into_response_parts(self) -> (StatusCode, String) {
        match &self {
            Self::Transport(_)
            | Self::Csv(_)
            | Self::Header(_)
            | Self::Gcol(_)
            | Self::EmptyFile => (StatusCode::BAD_REQUEST, self.to_string()),
            Self::QuotaExceeded { .. } => (StatusCode::PAYLOAD_TOO_LARGE, self.to_string()),
            Self::DiskExhausted { .. } => (StatusCode::INSUFFICIENT_STORAGE, self.to_string()),
            Self::DiskCheckFailed(_) | Self::JoinPanicked(_) => {
                (StatusCode::INTERNAL_SERVER_ERROR, self.to_string())
            }
            Self::Engine(e) => {
                let problem = graphus_rest::problem::Problem::from_graphus_error(e);
                let detail = problem
                    .detail
                    .clone()
                    .unwrap_or_else(|| problem.title.clone());
                (problem.status_code(), detail)
            }
        }
    }
}

/// Enforces the byte quota and periodic disk-space re-check on one HTTP call's raw upload bytes, as
/// they are consumed (`08` §8) — shared by both the streaming CSV path and the `.gcol`
/// buffer-then-transcode path so the two byte sources share one enforcement point. `min_free == 0`
/// disables the periodic disk-space re-check.
struct QuotaGuard {
    total: u64,
    quota: u64,
    since_last_check: u64,
    min_free: u64,
    target_dir: PathBuf,
}

impl QuotaGuard {
    fn new(quota: u64, min_free: u64, target_dir: PathBuf) -> Self {
        Self {
            total: 0,
            quota,
            since_last_check: 0,
            min_free,
            target_dir,
        }
    }

    /// Observes `len` more raw bytes, failing closed on a crossed quota or an exhausted disk reserve.
    async fn observe(&mut self, len: u64) -> Result<(), BulkIngestError> {
        self.total = self.total.saturating_add(len);
        if self.total > self.quota {
            return Err(BulkIngestError::QuotaExceeded {
                quota: self.quota,
                received: self.total,
            });
        }
        self.since_last_check += len;
        if self.min_free > 0 && self.since_last_check >= DISK_RECHECK_INTERVAL_BYTES {
            self.since_last_check = 0;
            let free = check_free_space(&self.target_dir)
                .await
                .map_err(BulkIngestError::DiskCheckFailed)?;
            if free < self.min_free {
                return Err(BulkIngestError::DiskExhausted {
                    free,
                    min_free: self.min_free,
                });
            }
        }
        Ok(())
    }
}

/// One message on the async-producer → blocking-consumer chunk channel (see the module docs'
/// "Streaming and batching").
enum ChunkMsg {
    /// One more raw chunk of the request body, in order.
    Data(Bytes),
    /// The producer aborted (transport/quota/disk-space failure) — turned into an [`std::io::Error`]
    /// so `csv::Reader` fails cleanly instead of silently truncating the file.
    Err(String),
}

/// Bridges the chunk channel into a synchronous [`std::io::Read`] for `csv::Reader`, used from inside
/// [`tokio::task::spawn_blocking`] — [`Receiver::blocking_recv`](tokio::sync::mpsc::Receiver::blocking_recv)
/// is safe here specifically because this never runs on a Tokio runtime worker.
struct ChunkReader {
    rx: tokio::sync::mpsc::Receiver<ChunkMsg>,
    current: Bytes,
    pos: usize,
}

impl ChunkReader {
    fn new(rx: tokio::sync::mpsc::Receiver<ChunkMsg>) -> Self {
        Self {
            rx,
            current: Bytes::new(),
            pos: 0,
        }
    }
}

impl Read for ChunkReader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        loop {
            if self.pos < self.current.len() {
                let n = buf.len().min(self.current.len() - self.pos);
                buf[..n].copy_from_slice(&self.current[self.pos..self.pos + n]);
                self.pos += n;
                return Ok(n);
            }
            match self.rx.blocking_recv() {
                Some(ChunkMsg::Data(b)) => {
                    self.current = b;
                    self.pos = 0;
                }
                Some(ChunkMsg::Err(msg)) => return Err(std::io::Error::other(msg)),
                None => return Ok(0), // channel closed: clean EOF
            }
        }
    }
}

/// The shared batch-ingestion core: parses `reader`'s header, then streams+batches its data rows into
/// [`crate::engine::EngineHandle::bulk_import_batch`] calls of up to
/// [`graphus_bulk::DEFAULT_BATCH_SIZE`] rows. Generic over [`Read`] so the SAME loop backs both the
/// streaming-CSV [`ChunkReader`] and the `.gcol` path's in-memory [`Cursor`] (module docs' "`.gcol`
/// handling"). Runs entirely off the async runtime (called from inside `spawn_blocking`); `rt.block_on`
/// is the sanctioned off-worker pattern this codebase already documents elsewhere (module docs).
///
/// Always submits at least one (possibly empty) final batch, so the caller learns the session's
/// current cumulative stats even when this call's file had a header but zero remaining data rows.
///
/// # Errors
/// [`BulkIngestError::EmptyFile`] if the reader yields no header row at all,
/// [`BulkIngestError::Header`]/[`BulkIngestError::Csv`] for a malformed header/record, or
/// [`BulkIngestError::Engine`] for a row/storage/commit failure from the engine.
fn run_batch_loop<R: Read>(
    reader: R,
    phase: Phase,
    engine: &EngineHandle,
    rt: &tokio::runtime::Handle,
) -> Result<ImportStats, BulkIngestError> {
    let mut csv_reader = csv::ReaderBuilder::new()
        .has_headers(false)
        .delimiter(b',')
        .flexible(true)
        .from_reader(reader);

    let mut header_record = csv::StringRecord::new();
    if !csv_reader
        .read_record(&mut header_record)
        .map_err(|e| BulkIngestError::Csv(e.to_string()))?
    {
        return Err(BulkIngestError::EmptyFile);
    }

    let make_batch: Box<dyn Fn(Vec<csv::StringRecord>) -> BulkImportBatchInput> = match phase {
        Phase::Nodes => {
            let header = Arc::new(
                NodeHeader::parse(header_record.iter())
                    .map_err(|e| BulkIngestError::Header(e.to_string()))?,
            );
            Box::new(move |records| BulkImportBatchInput::Nodes {
                header: Arc::clone(&header),
                records,
            })
        }
        Phase::Relationships => {
            let header = Arc::new(
                RelHeader::parse(header_record.iter())
                    .map_err(|e| BulkIngestError::Header(e.to_string()))?,
            );
            Box::new(move |records| BulkImportBatchInput::Relationships {
                header: Arc::clone(&header),
                records,
            })
        }
    };

    let mut batch: Vec<csv::StringRecord> = Vec::with_capacity(DEFAULT_BATCH_SIZE);
    let mut record = csv::StringRecord::new();
    loop {
        let more = csv_reader
            .read_record(&mut record)
            .map_err(|e| BulkIngestError::Csv(e.to_string()))?;
        if !more {
            break;
        }
        batch.push(record.clone());
        if batch.len() >= DEFAULT_BATCH_SIZE {
            let input = make_batch(std::mem::take(&mut batch));
            // Full intermediate batches are committed for throughput (so the engine thread is never
            // blocked on the whole file); only the FINAL flush's stats are reported below, so an
            // intermediate outcome is intentionally discarded here.
            rt.block_on(engine.bulk_import_batch(input))
                .map_err(BulkIngestError::Engine)?;
        }
    }
    // Always flush the final (possibly empty) batch: mirrors `BulkImporter::import_nodes`'s
    // unconditional final commit (see the doc comment above). Its outcome carries the session's
    // cumulative stats.
    let outcome = rt
        .block_on(engine.bulk_import_batch(make_batch(batch)))
        .map_err(BulkIngestError::Engine)?;

    Ok(outcome.stats)
}

/// The chunk channel's bound: small enough that a stalled batch (e.g. mid-commit) throttles the
/// producer within a handful of chunks — the `08` §8 backpressure — large enough to avoid needless
/// wake-up churn on an ordinary fast upload.
const CHUNK_CHANNEL_CAPACITY: usize = 8;

/// Streams `body` as one CSV file, batching + ingesting it via [`run_batch_loop`] on a blocking task
/// bridged by a bounded chunk channel (module docs' "Streaming and batching").
async fn ingest_csv_stream(
    engine: EngineHandle,
    phase: Phase,
    mut body: Body,
    quota: u64,
    min_free: u64,
    target_dir: PathBuf,
) -> Result<ImportStats, BulkIngestError> {
    let (tx, rx) = tokio::sync::mpsc::channel::<ChunkMsg>(CHUNK_CHANNEL_CAPACITY);
    let rt = tokio::runtime::Handle::current();
    let blocking = tokio::task::spawn_blocking(move || {
        run_batch_loop(ChunkReader::new(rx), phase, &engine, &rt)
    });

    let mut guard = QuotaGuard::new(quota, min_free, target_dir);
    let mut abort: Option<BulkIngestError> = None;
    loop {
        match body.frame().await {
            None => break,
            Some(Err(e)) => {
                let err = BulkIngestError::Transport(e.to_string());
                let _ = tx.send(ChunkMsg::Err(err.to_string())).await;
                abort = Some(err);
                break;
            }
            Some(Ok(frame)) => {
                let Some(data) = frame.data_ref() else {
                    continue; // A trailer frame carries no data.
                };
                if let Err(err) = guard.observe(data.len() as u64).await {
                    let _ = tx.send(ChunkMsg::Err(err.to_string())).await;
                    abort = Some(err);
                    break;
                }
                if tx.send(ChunkMsg::Data(data.clone())).await.is_err() {
                    // The blocking task already ended (its own error will surface via the join
                    // below); stop reading further.
                    break;
                }
            }
        }
    }
    drop(tx); // signals clean EOF to `ChunkReader` when the loop ended without an abort.

    let joined = blocking.await;
    if let Some(err) = abort {
        // Prefer our own precise transport/quota/disk-space diagnosis over whatever csv::Reader
        // derived from the resulting broken pipe.
        return Err(err);
    }
    match joined {
        Err(join_err) => Err(BulkIngestError::JoinPanicked(join_err.to_string())),
        Ok(inner) => inner,
    }
}

/// Buffers `body` whole (still quota-bounded), transcodes it from `.gcol` to CSV, then runs the SAME
/// [`run_batch_loop`] the streaming path uses (module docs' "`.gcol` handling").
async fn ingest_gcol_buffered(
    engine: EngineHandle,
    phase: Phase,
    mut body: Body,
    quota: u64,
    min_free: u64,
    target_dir: PathBuf,
) -> Result<ImportStats, BulkIngestError> {
    let mut guard = QuotaGuard::new(quota, min_free, target_dir);
    let mut buf: Vec<u8> = Vec::new();
    loop {
        match body.frame().await {
            None => break,
            Some(Err(e)) => return Err(BulkIngestError::Transport(e.to_string())),
            Some(Ok(frame)) => {
                let Some(data) = frame.data_ref() else {
                    continue;
                };
                guard.observe(data.len() as u64).await?;
                buf.extend_from_slice(data);
            }
        }
    }

    let rt = tokio::runtime::Handle::current();
    let joined = tokio::task::spawn_blocking(move || -> Result<ImportStats, BulkIngestError> {
        let csv_bytes = gcol_to_csv(&buf).map_err(|e| BulkIngestError::Gcol(e.to_string()))?;
        run_batch_loop(Cursor::new(csv_bytes), phase, &engine, &rt)
    })
    .await;
    match joined {
        Err(join_err) => Err(BulkIngestError::JoinPanicked(join_err.to_string())),
        Ok(inner) => inner,
    }
}

/// Handles one `?phase=nodes`/`?phase=relationships` call: resolves (continuing or beginning) the
/// session's engine handle, runs the disk-space preflight, then streams + ingests the body under the
/// call's own quota/timeout budget (module docs' "Scope decisions").
async fn handle_phase(
    state: &ExtraState,
    who: &str,
    db_name: &str,
    phase: Phase,
    format: BulkImportFormat,
    body: Body,
) -> Response {
    // Captured ONCE (not re-queried) to avoid a TOCTOU race: a concurrent `?end=true` could flip
    // `loading_handle` from `Some` to `None` between an initial presence check and a second lookup,
    // which would make a second, separate `loading_handle` call incorrectly panic/fall through.
    let (engine, began_session) = match state.catalog.loading_handle(db_name) {
        Some(h) => (h, false),
        None => match begin_session(state, db_name).await {
            Ok(h) => (h, true),
            Err((status, msg)) => {
                state.audit.record(
                    AuditEvent::new(
                        AuditClass::AdminChange,
                        AuditOutcome::Failure,
                        AuditSource::Rest,
                    )
                    .actor(Some(who))
                    .database(Some(db_name))
                    .detail(format!(
                        "bulk-import session could not begin (phase={}): {msg}",
                        phase.as_str()
                    )),
                );
                return (status, msg).into_response();
            }
        },
    };

    let target_dir = state.catalog.database_dir(db_name);
    let min_free = state.bulk_import.min_free_disk_bytes;
    if min_free > 0 {
        match check_free_space(&target_dir).await {
            Ok(free) if free < min_free => {
                state.audit.record(
                    AuditEvent::new(
                        AuditClass::AdminChange,
                        AuditOutcome::Failure,
                        AuditSource::Rest,
                    )
                    .actor(Some(who))
                    .database(Some(db_name))
                    .detail(format!(
                        "bulk-import phase={} refused: disk-space preflight failed",
                        phase.as_str()
                    )),
                );
                return (
                    StatusCode::INSUFFICIENT_STORAGE,
                    format!(
                        "insufficient free disk space on database {db_name:?}'s volume: {free} \
                         bytes available, {min_free} required"
                    ),
                )
                    .into_response();
            }
            Ok(_) => {}
            Err(msg) => return (StatusCode::INTERNAL_SERVER_ERROR, msg).into_response(),
        }
    }

    let quota = state.bulk_import.max_bytes_per_session;
    let session_timeout = state.bulk_import.session_timeout();
    let outcome = match format {
        BulkImportFormat::Csv => {
            tokio::time::timeout(
                session_timeout,
                ingest_csv_stream(engine, phase, body, quota, min_free, target_dir),
            )
            .await
        }
        BulkImportFormat::Gcol => {
            tokio::time::timeout(
                session_timeout,
                ingest_gcol_buffered(engine, phase, body, quota, min_free, target_dir),
            )
            .await
        }
    };

    match outcome {
        Ok(Ok(stats)) => {
            state.audit.record(
                AuditEvent::new(
                    AuditClass::AdminChange,
                    AuditOutcome::Success,
                    AuditSource::Rest,
                )
                .actor(Some(who))
                .database(Some(db_name))
                .detail(format!(
                    "bulk-import phase={} batch accepted{}: {} nodes, {} relationships, {} \
                     properties (format {})",
                    phase.as_str(),
                    if began_session {
                        " (session begun)"
                    } else {
                        ""
                    },
                    stats.nodes,
                    stats.relationships,
                    stats.properties,
                    format.as_str()
                )),
            );
            (
                StatusCode::OK,
                [(header::CONTENT_TYPE, "application/json")],
                stats_json(&stats),
            )
                .into_response()
        }
        Ok(Err(err)) => {
            let (status, msg) = err.into_response_parts();
            state.audit.record(
                AuditEvent::new(
                    AuditClass::AdminChange,
                    AuditOutcome::Failure,
                    AuditSource::Rest,
                )
                .actor(Some(who))
                .database(Some(db_name))
                .detail(format!(
                    "bulk-import phase={} aborted: {msg}",
                    phase.as_str()
                )),
            );
            (status, msg).into_response()
        }
        Err(_elapsed) => {
            state.audit.record(
                AuditEvent::new(
                    AuditClass::AdminChange,
                    AuditOutcome::Failure,
                    AuditSource::Rest,
                )
                .actor(Some(who))
                .database(Some(db_name))
                .detail(format!(
                    "bulk-import phase={} aborted: session timeout exceeded",
                    phase.as_str()
                )),
            );
            (
                StatusCode::REQUEST_TIMEOUT,
                "bulk-import call exceeded its configured timeout",
            )
                .into_response()
        }
    }
}

/// Handles `?end=true`: idempotently ends the session (module docs).
async fn handle_end(state: &ExtraState, who: &str, db_name: &str) -> Response {
    let Some(engine) = state.catalog.loading_handle(db_name) else {
        // No active session: a no-op success, never an error (module docs' idempotency contract).
        return (
            StatusCode::OK,
            [(header::CONTENT_TYPE, "application/json")],
            stats_json(&ImportStats::default()),
        )
            .into_response();
    };

    let outcome = tokio::time::timeout(
        state.bulk_import.session_timeout(),
        engine.bulk_import_batch(BulkImportBatchInput::End),
    )
    .await;

    match outcome {
        Ok(Ok(reply)) => match state.catalog.end_loading(db_name).await {
            Ok(()) => {
                state.audit.record(
                    AuditEvent::new(
                        AuditClass::AdminChange,
                        AuditOutcome::Success,
                        AuditSource::Rest,
                    )
                    .actor(Some(who))
                    .database(Some(db_name))
                    .detail(format!(
                        "bulk-import session ended: {} nodes, {} relationships, {} properties",
                        reply.stats.nodes, reply.stats.relationships, reply.stats.properties
                    )),
                );
                (
                    StatusCode::OK,
                    [(header::CONTENT_TYPE, "application/json")],
                    stats_json(&reply.stats),
                )
                    .into_response()
            }
            Err(e) => {
                let (status, msg) = catalog_error_response(e);
                state.audit.record(
                    AuditEvent::new(
                        AuditClass::AdminChange,
                        AuditOutcome::Failure,
                        AuditSource::Rest,
                    )
                    .actor(Some(who))
                    .database(Some(db_name))
                    .detail(format!(
                        "bulk-import session finished but leaving Loading failed: {msg}"
                    )),
                );
                (status, msg).into_response()
            }
        },
        Ok(Err(e)) => {
            let (status, msg) = BulkIngestError::Engine(e).into_response_parts();
            state.audit.record(
                AuditEvent::new(
                    AuditClass::AdminChange,
                    AuditOutcome::Failure,
                    AuditSource::Rest,
                )
                .actor(Some(who))
                .database(Some(db_name))
                .detail(format!("bulk-import end failed: {msg}")),
            );
            (status, msg).into_response()
        }
        Err(_elapsed) => {
            state.audit.record(
                AuditEvent::new(
                    AuditClass::AdminChange,
                    AuditOutcome::Failure,
                    AuditSource::Rest,
                )
                .actor(Some(who))
                .database(Some(db_name))
                .detail("bulk-import end exceeded its configured timeout"),
            );
            (
                StatusCode::REQUEST_TIMEOUT,
                "bulk-import end exceeded its configured timeout",
            )
                .into_response()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn headers_with_content_type(value: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(header::CONTENT_TYPE, value.parse().unwrap());
        headers
    }

    #[test]
    fn detects_csv_content_type() {
        assert_eq!(
            BulkImportFormat::from_headers(&headers_with_content_type("text/csv")).unwrap(),
            BulkImportFormat::Csv
        );
    }

    #[test]
    fn detects_gcol_content_type() {
        assert_eq!(
            BulkImportFormat::from_headers(&headers_with_content_type(
                "application/vnd.graphus.gcol"
            ))
            .unwrap(),
            BulkImportFormat::Gcol
        );
    }

    #[test]
    fn content_type_matching_is_case_insensitive_and_ignores_parameters() {
        assert_eq!(
            BulkImportFormat::from_headers(&headers_with_content_type("TEXT/CSV; charset=utf-8"))
                .unwrap(),
            BulkImportFormat::Csv
        );
    }

    #[test]
    fn missing_content_type_is_rejected() {
        let err = BulkImportFormat::from_headers(&HeaderMap::new()).unwrap_err();
        assert!(err.contains("missing Content-Type"), "message: {err}");
    }

    #[test]
    fn unknown_content_type_is_rejected_with_a_clear_message() {
        let err = BulkImportFormat::from_headers(&headers_with_content_type("application/json"))
            .unwrap_err();
        assert!(err.contains("application/json"), "message: {err}");
        assert!(err.contains("text/csv"), "message: {err}");
    }

    #[test]
    fn format_as_str_round_trips_the_canonical_name() {
        assert_eq!(BulkImportFormat::Csv.as_str(), "csv");
        assert_eq!(BulkImportFormat::Gcol.as_str(), "gcol");
    }

    #[test]
    fn parse_op_recognizes_phase_nodes() {
        assert!(matches!(
            parse_op(Some("phase=nodes")),
            Ok(Op::Phase(Phase::Nodes))
        ));
    }

    #[test]
    fn parse_op_recognizes_phase_relationships() {
        assert!(matches!(
            parse_op(Some("phase=relationships")),
            Ok(Op::Phase(Phase::Relationships))
        ));
    }

    #[test]
    fn parse_op_recognizes_end_true() {
        assert!(matches!(parse_op(Some("end=true")), Ok(Op::End)));
    }

    #[test]
    fn parse_op_end_true_takes_precedence_over_phase() {
        assert!(matches!(
            parse_op(Some("phase=nodes&end=true")),
            Ok(Op::End)
        ));
    }

    #[test]
    fn parse_op_rejects_missing_query() {
        let err = parse_op(None).unwrap_err();
        assert!(err.contains("phase=nodes"), "message: {err}");
        assert!(err.contains("end=true"), "message: {err}");
    }

    #[test]
    fn parse_op_rejects_empty_query() {
        assert!(parse_op(Some("")).is_err());
    }

    #[test]
    fn parse_op_rejects_invalid_phase_value() {
        let err = parse_op(Some("phase=bogus")).unwrap_err();
        assert!(err.contains("bogus"), "message: {err}");
    }

    #[test]
    fn parse_op_end_false_falls_back_to_phase() {
        assert!(matches!(
            parse_op(Some("end=false&phase=nodes")),
            Ok(Op::Phase(Phase::Nodes))
        ));
    }

    #[test]
    fn parse_op_ignores_unknown_parameters() {
        assert!(matches!(
            parse_op(Some("foo=bar&phase=relationships&baz=qux")),
            Ok(Op::Phase(Phase::Relationships))
        ));
    }
}
