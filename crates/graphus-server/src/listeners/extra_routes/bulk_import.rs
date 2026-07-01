//! `POST /admin/db/{db}/bulk-import` — the network bulk-import streaming upload endpoint
//! (`08-network-bulk-import.md`, decision `D-bulk-import-network`, `rmp` #518).
//!
//! This is the **scaffolding** milestone only: RBAC, streaming ingestion with a byte quota, a
//! disk-space preflight + ongoing check, a session timeout, and payload-format detection. It does
//! **not** yet hand the ingested bytes to `graphus_bulk::BulkImporter` (Mode A, `rmp` #519) or
//! drive them through `TxnCoordinator`/`record_graph` (Mode B, `rmp` #520) — every consumed chunk
//! is currently counted and discarded (see the `TODO(#519)` in [`consume_stream`]). Session
//! lifecycle (the `Loading` database state, Mode A/B selection, resumability, `08` §5/§7) is
//! likewise out of scope here; this milestone only prepares the entry point those tasks build on.
//!
//! ## RBAC
//!
//! Gated by the exact same [`require_admin`](super::require_admin) (global `Admin` privilege)
//! check as `/admin/status`, `/admin/users/{name}` and `/admin/shutdown`, and — per `08` §6 — the
//! same gate `BACKUP DATABASE`/`RESTORE DATABASE`/`CREATE DATABASE` use over Bolt/UDS/REST
//! (`crate::admin::AdminContext::execute`). A denial is audited as [`AuditClass::AuthzDenied`]
//! before any side effect, matching that existing `authorize` → `execute` sequencing.
//!
//! ## Streaming and the 4 MiB body-limit exemption
//!
//! The request body is polled one [`http_body_util::BodyExt::frame`] at a time and never buffered
//! whole — the ingress-side mirror of the `Body::from_stream` egress-streaming pattern rmp #475
//! established. This route is deliberately **not** behind
//! [`graphus_rest::router::MAX_REQUEST_BODY_BYTES`]'s `DefaultBodyLimit` layer: that layer is
//! wired only onto the `graphus_rest` transactional router
//! (`crates/graphus-rest/src/router.rs`), and this route is merged from the server's own, separate
//! `Router` ([`super::routes`]), which carries no such layer — a deliberate, documented exemption
//! (`08` §3.3), not an oversight. Its own purpose-built limits (below) govern it instead.
//!
//! ## Quota, disk-space, and session-timeout enforcement
//!
//! See [`BulkImportConfig`]. The byte quota and the periodic disk-space re-check are enforced **as
//! bytes are consumed** (`08` §8), so an oversized or disk-exhausting upload is aborted mid-stream
//! without ever materializing the excess in memory or running the target device out of space. The
//! session timeout ([`tokio::time::timeout`], the same real-time mechanism
//! [`crate::config::TimingConfig::handshake_timeout_ms`] and
//! [`crate::config::TimingConfig::header_read_timeout_ms`] already use for other connection-level
//! deadlines) bounds the whole upload's wall-clock duration.

use std::path::{Path as FsPath, PathBuf};

use axum::body::Body;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use http_body_util::BodyExt;

use crate::audit::{AuditClass, AuditEvent, AuditOutcome, AuditSource};

use super::{ExtraState, require_admin};

/// The two payload formats `graphus-bulk`'s `BulkImporter` already parses (`08` §4.2): selected by
/// `Content-Type`, mirroring the existing `graphus-bulk import --format csv|gcol` CLI flag so the
/// server-side ingestion logic can eventually be shared, unmodified, between the offline tool and
/// this endpoint (`08` §4.2) — only the byte source changes.
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

/// `POST /admin/db/{db}/bulk-import` — see the module docs for scope and the milestone boundary.
///
/// Order of checks: RBAC first (denial audited, no side effects) → payload-format detection (cheap,
/// header-only) → target-database existence (`08` §5.3's Mode-B precondition; this scaffolding
/// milestone does not yet distinguish Mode A/B, so any *existing* database is accepted) →
/// disk-space preflight → the timed, streamed, quota-enforced body consumption.
pub(super) async fn admin_bulk_import(
    State(state): State<ExtraState>,
    Path(db): Path<String>,
    headers: HeaderMap,
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

    let format = match BulkImportFormat::from_headers(&headers) {
        Ok(f) => f,
        Err(msg) => return (StatusCode::UNSUPPORTED_MEDIA_TYPE, msg).into_response(),
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

    let target_dir = state.catalog.database_dir(&db_name);
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
                    .actor(Some(&who))
                    .database(Some(&db_name))
                    .detail("bulk-import session refused: disk-space preflight failed"),
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
    let outcome = tokio::time::timeout(
        session_timeout,
        consume_stream(body, quota, min_free, target_dir),
    )
    .await;

    match outcome {
        Ok(Ok(stats)) => {
            state.audit.record(
                AuditEvent::new(
                    AuditClass::AdminChange,
                    AuditOutcome::Success,
                    AuditSource::Rest,
                )
                .actor(Some(&who))
                .database(Some(&db_name))
                .detail(format!(
                    "bulk-import upload accepted: {} bytes, format {}",
                    stats.bytes,
                    format.as_str()
                )),
            );
            (
                StatusCode::ACCEPTED,
                [(header::CONTENT_TYPE, "application/json")],
                format!(
                    "{{\"accepted_bytes\":{},\"format\":{:?}}}",
                    stats.bytes,
                    format.as_str()
                ),
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
                .actor(Some(&who))
                .database(Some(&db_name))
                .detail(format!("bulk-import session aborted: {msg}")),
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
                .actor(Some(&who))
                .database(Some(&db_name))
                .detail("bulk-import session aborted: session timeout exceeded"),
            );
            (
                StatusCode::REQUEST_TIMEOUT,
                "bulk-import session exceeded its configured timeout",
            )
                .into_response()
        }
    }
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

/// What [`consume_stream`] observed once the body was fully drained.
struct ConsumeStats {
    /// Total bytes read from the request body.
    bytes: u64,
}

/// Why [`consume_stream`] stopped before draining the body.
enum ConsumeError {
    /// The client disconnected, or hyper reported a framing/transport error mid-body.
    Transport(String),
    /// The running byte total crossed [`BulkImportConfig::max_bytes_per_session`].
    QuotaExceeded { quota: u64, received: u64 },
    /// A periodic disk-space re-check found free space below the configured reserve.
    DiskExhausted { free: u64, min_free: u64 },
    /// A periodic disk-space re-check itself failed (syscall error / panicked blocking task).
    DiskCheckFailed(String),
}

impl ConsumeError {
    /// The HTTP status + client-facing message for this failure.
    fn into_response_parts(self) -> (StatusCode, String) {
        match self {
            Self::Transport(e) => (
                StatusCode::BAD_REQUEST,
                format!("error reading upload body: {e}"),
            ),
            Self::QuotaExceeded { quota, received } => (
                StatusCode::PAYLOAD_TOO_LARGE,
                format!(
                    "bulk-import upload exceeded the configured quota ({quota} bytes) after \
                     {received} bytes were received; the session was aborted"
                ),
            ),
            Self::DiskExhausted { free, min_free } => (
                StatusCode::INSUFFICIENT_STORAGE,
                format!(
                    "bulk-import upload aborted: free disk space dropped to {free} bytes, below \
                     the configured {min_free}-byte reserve"
                ),
            ),
            Self::DiskCheckFailed(e) => (StatusCode::INTERNAL_SERVER_ERROR, e),
        }
    }
}

/// Streams `body` to completion, counting bytes and enforcing `quota` + `min_free` **as they are
/// consumed** (`08` §8) — the request body is never buffered whole; each frame is inspected and
/// dropped as it arrives. `min_free == 0` disables the periodic disk-space re-check
/// ([`BulkImportConfig::min_free_disk_bytes`]).
///
/// TODO(#519): hand each consumed chunk to `BulkImporter`'s streaming CSV/`.gcol` ingestion (Mode
/// A) instead of discarding it. TODO(#520): route it through `TxnCoordinator`/`record_graph`
/// instead (Mode B). Both are out of scope for this scaffolding milestone (`rmp` #518).
async fn consume_stream(
    mut body: Body,
    quota: u64,
    min_free: u64,
    target_dir: PathBuf,
) -> Result<ConsumeStats, ConsumeError> {
    let mut total: u64 = 0;
    let mut since_last_check: u64 = 0;
    while let Some(frame) = body
        .frame()
        .await
        .transpose()
        .map_err(|e| ConsumeError::Transport(e.to_string()))?
    {
        let Some(data) = frame.data_ref() else {
            continue; // A trailer frame carries no data.
        };
        let len = data.len() as u64;
        total = total.saturating_add(len);
        if total > quota {
            return Err(ConsumeError::QuotaExceeded {
                quota,
                received: total,
            });
        }
        // TODO(#519): hand `data` to BulkImporter's streaming ingestion here.
        since_last_check += len;
        if min_free > 0 && since_last_check >= DISK_RECHECK_INTERVAL_BYTES {
            since_last_check = 0;
            let free = check_free_space(&target_dir)
                .await
                .map_err(ConsumeError::DiskCheckFailed)?;
            if free < min_free {
                return Err(ConsumeError::DiskExhausted { free, min_free });
            }
        }
    }
    Ok(ConsumeStats { bytes: total })
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
}
