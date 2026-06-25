//! The server's own HTTP routes merged onto the REST API router: observability (`/metrics`,
//! `/health/live`, `/health/ready`) and a minimal admin surface (`/admin/*`)
//! (`04-technical-design.md` §9 / NFR-10, §8.2).
//!
//! These live in `graphus-server` (not `graphus-rest`) because they are operational, not part of the
//! transactional graph API: the metrics registry, the readiness flag, and the admin shutdown trigger
//! are server-process concerns. They are merged onto the `graphus_rest` router so a single TCP+TLS
//! listener serves the whole HTTP surface.
//!
//! ## Admin surface scope
//!
//! These REST routes hold the **live** [`crate::security::SecurityCatalog`] and resolve every
//! Bearer-token auth check + RBAC read through it (a brief read lock per call, rmp #94), so a user
//! created/changed/dropped at runtime is reflected here immediately — exactly as on the Bolt/REST
//! transactional authentication path. They cover inspection + process control:
//!
//! - `GET  /admin/status` — server status (open transactions, readiness).
//! - `GET  /admin/users/{name}` — inspect a named user's roles (RBAC inspection).
//! - `POST /admin/shutdown` — trigger graceful shutdown (`04 §9.4`).
//!
//! All `/admin/*` routes require an authenticated principal with the global `Admin` privilege.
//!
//! **Live user/role *mutation*** (create/drop/grant) is delivered by the same durable, lock-guarded
//! [`crate::security::SecurityCatalog`] and the administrative-statement surface
//! ([`crate::admin`], rmp #92): `CREATE USER`, `GRANT`, … run over Bolt/UDS/REST and persist to
//! `security.toml`, and — since these routes read the live catalog — take effect for this surface's
//! authentication immediately.

use std::sync::Arc;

use axum::Router;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use graphus_auth::Privilege;

use crate::dbcatalog::DatabaseCatalog;
use crate::engine::EngineHandle;
use crate::metrics::Metrics;
use crate::security::SecurityCatalog;
use crate::shutdown::ShutdownCoordinator;

/// Shared state for the server's own routes.
#[derive(Clone)]
struct ExtraState {
    metrics: Arc<Metrics>,
    engine: EngineHandle,
    /// The database catalog, for **per-database** readiness aggregation (`rmp` #414/#430): which
    /// running databases are engine-degraded, and how many configured databases failed to open.
    catalog: Arc<DatabaseCatalog>,
    /// The LIVE security catalog (rmp #94): every `/admin/*` Bearer check + RBAC read resolves
    /// through it under a brief read lock, so runtime user/role mutations are visible at once.
    security: Arc<SecurityCatalog>,
    clock: Arc<dyn graphus_core::capability::Clock + Send + Sync>,
    shutdown: ShutdownCoordinator,
    readiness: crate::observability::Readiness,
    /// Optional Prometheus scrape token (rmp #149). `None` ⇒ `/metrics` requires an **admin Bearer**;
    /// `Some(token)` ⇒ `/metrics` also accepts `Authorization: Bearer <token>` (constant-time match).
    metrics_scrape_token: Option<Arc<str>>,
}

/// Builds the observability + admin routes as a standalone `Router` to be merged onto the REST API
/// router.
#[allow(clippy::too_many_arguments)] // The server routes legitimately aggregate the shared services.
pub fn routes(
    metrics: Arc<Metrics>,
    engine: EngineHandle,
    catalog: Arc<DatabaseCatalog>,
    security: Arc<SecurityCatalog>,
    clock: Arc<dyn graphus_core::capability::Clock + Send + Sync>,
    shutdown: ShutdownCoordinator,
    readiness: crate::observability::Readiness,
    metrics_scrape_token: Option<Arc<str>>,
) -> Router {
    let state = ExtraState {
        metrics,
        engine,
        catalog,
        security,
        clock,
        shutdown,
        readiness,
        metrics_scrape_token,
    };
    Router::new()
        .route("/metrics", get(metrics_handler))
        .route("/health/live", get(health_live))
        .route("/health/ready", get(health_ready))
        .route("/admin/status", get(admin_status))
        .route("/admin/users/{name}", get(admin_user))
        .route("/admin/shutdown", post(admin_shutdown))
        .with_state(state)
}

/// `GET /metrics` — Prometheus text exposition (`04 §9` / NFR-10). **Fail-closed** (rmp #149): a
/// scrape must authenticate, either with the configured scrape token (`Authorization: Bearer
/// <token>`, constant-time compared) or — when no token is configured — with a valid **admin Bearer**
/// (the same gate as `/admin/*`). It exposes only aggregate counters (no data), but an unauthenticated
/// metrics endpoint leaks operational signal (query volumes, error rates, tenant activity) and is a
/// production hazard, so it is closed by default. The `/health/*` probes stay open.
async fn metrics_handler(State(state): State<ExtraState>, headers: HeaderMap) -> Response {
    if let Err(resp) = authorize_metrics(&state, &headers) {
        return *resp;
    }
    let body = state.metrics.render_prometheus();
    (
        StatusCode::OK,
        [(
            header::CONTENT_TYPE,
            "text/plain; version=0.0.4; charset=utf-8",
        )],
        body,
    )
        .into_response()
}

/// Authorizes a `/metrics` scrape (rmp #149): accept a configured scrape token (constant-time
/// compared) when present, otherwise fall back to requiring an admin Bearer (the `/admin/*` gate).
/// Returns the boxed error response on failure (a `Response` is large — see [`require_admin`]).
fn authorize_metrics(state: &ExtraState, headers: &HeaderMap) -> Result<(), Box<Response>> {
    if let (Some(expected), Some(presented)) =
        (state.metrics_scrape_token.as_deref(), bearer_token(headers))
    {
        if constant_time_eq(expected.as_bytes(), presented.as_bytes()) {
            return Ok(());
        }
    }
    // No (matching) scrape token: require an admin Bearer. `require_admin` records an auth failure
    // metric on a bad/missing token and returns the boxed 401/403, so a probe with neither a valid
    // scrape token nor an admin Bearer is fail-closed.
    require_admin(state, headers).map(|_who| ())
}

/// Constant-time byte-slice equality, so a scrape-token comparison does not leak the secret's length
/// or a matching prefix through timing. Returns `false` immediately on a length mismatch (the length
/// of a *rejected* guess is not the secret's length), then folds every byte of equal-length inputs.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// `GET /health/live` — liveness: always `200 OK` while the process runs (`04 §9`).
async fn health_live() -> Response {
    (StatusCode::OK, "live").into_response()
}

/// `GET /health/ready` — readiness: `200 OK` once the store is verified + the engine is serving, and
/// `503` while starting up or shutting down (`04 §9`).
///
/// Also reports `503` when **reclamation is degraded** (`rmp` #394): if the background maintenance
/// checkpoint has failed `K` times consecutively, reclamation has stalled (RAM/disk/version slots stop
/// being freed while writes accrue — a slow-motion OOM). Surfacing it through readiness lets an
/// orchestrator stop routing writes to a node that would otherwise keep accepting them behind a green
/// probe until it OOMs. The gauge clears the moment a checkpoint succeeds, so the node recovers
/// readiness automatically once reclamation resumes.
///
/// Reports `503` when the **default database's engine is degraded** (`rmp` #409/#414): a statement
/// panicked and the rollback/commit recovering it *also* panicked, so a deep storage/MVCC invariant is
/// broken and that engine's in-memory state can no longer be trusted. The default database is the one
/// the listeners structurally depend on, so its degradation is a node-level not-ready. A **secondary**
/// database's degradation does **not** take the node down (`rmp` #414 multi-tenant isolation): the node
/// stays `200` and serviceable for the default + every healthy database, while the response body names
/// the degraded secondary database(s) so an orchestrator can act. Engine degradation does **not**
/// auto-clear — a controlled engine/process restart is the only safe recovery.
///
/// Also reports `503` when **one or more configured (non-default) databases failed to open** at boot
/// (`rmp` #430): previously such a failure was logged but readiness stayed unconditionally green,
/// hiding a catalog whose secondary databases all failed to open. The count is surfaced so an
/// orchestrator can tell a configured database is not serving.
async fn health_ready(State(state): State<ExtraState>) -> Response {
    if !state.readiness.is_ready() {
        return (StatusCode::SERVICE_UNAVAILABLE, "not ready").into_response();
    }
    if state.metrics.is_maintenance_degraded() {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            "not ready: storage reclamation degraded",
        )
            .into_response();
    }
    // Per-database engine-degradation aggregation (`rmp` #414). The default database failing is a
    // node-level not-ready (the listeners depend on it); a degraded *secondary* database is reported
    // without taking the node down so a healthy database stays serviceable.
    if state.catalog.default_database_degraded() {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            "not ready: default database engine degraded (recovery double-panic)",
        )
            .into_response();
    }
    let degraded = state.catalog.degraded_databases();
    let failed_open = state.catalog.failed_open_database_count();
    // A non-default database failing to open (`rmp` #430) is a degraded signal: the node still serves
    // the default + healthy databases, but readiness must report not-ready so an orchestrator can tell.
    if failed_open > 0 {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            format!("not ready: {failed_open} configured database(s) failed to open"),
        )
            .into_response();
    }
    // A degraded *secondary* database does not take the node down, but it is surfaced (named) through
    // readiness so an orchestrator sees which database is unhealthy. The default stays serviceable.
    if !degraded.is_empty() {
        return (
            StatusCode::SERVICE_UNAVAILABLE,
            format!(
                "not ready: database(s) engine-degraded: {}",
                degraded.join(", ")
            ),
        )
            .into_response();
    }
    (StatusCode::OK, "ready").into_response()
}

/// Authenticates the request's Bearer token and requires the global `Admin` privilege, returning the
/// principal on success or an error response (`04 §8.4`). The clock drives JWT expiry deterministically.
///
/// The error response is boxed: a `Response` is large, and an admin handler returning it by value in
/// a `Result::Err` would otherwise trip `clippy::result_large_err`. Admin routes are not hot paths,
/// so a small boxed allocation on the (rare) auth-failure branch is the clean choice.
fn require_admin(state: &ExtraState, headers: &HeaderMap) -> Result<String, Box<Response>> {
    let token = bearer_token(headers).ok_or_else(|| {
        Box::new(
            (
                StatusCode::UNAUTHORIZED,
                "missing or malformed Authorization: Bearer",
            )
                .into_response(),
        )
    })?;
    // JWT validity is an ABSOLUTE timestamp, so it reads the wall clock (`now_unix_nanos`), not the
    // monotonic `now_nanos` (rmp #395 — the monotonic timeline is for elapsed/idle measurement only).
    let now_unix_secs = state.clock.now_unix_nanos() / 1_000_000_000;
    // Resolve the Bearer check + admin gate through the LIVE catalog (one brief read lock, rmp #94),
    // so a runtime-created admin is accepted at once and a just-dropped one is refused at once.
    let claims = state
        .security
        .with_auth(|auth| auth.authenticate_bearer(token, now_unix_secs))
        .map_err(|_| {
            state.metrics.record_auth_failure();
            Box::new((StatusCode::UNAUTHORIZED, "invalid or expired token").into_response())
        })?;
    state
        .security
        .with_auth(|auth| auth.require(&claims.sub, &Privilege::admin_database()))
        .map_err(|_| {
            Box::new((StatusCode::FORBIDDEN, "admin privilege required").into_response())
        })?;
    Ok(claims.sub)
}

/// Extracts a `Bearer <token>` from the `Authorization` header.
fn bearer_token(headers: &HeaderMap) -> Option<&str> {
    headers
        .get(header::AUTHORIZATION)?
        .to_str()
        .ok()?
        .strip_prefix("Bearer ")
        .map(str::trim)
}

/// `GET /admin/status` — open-transaction count + readiness (admin only).
async fn admin_status(State(state): State<ExtraState>, headers: HeaderMap) -> Response {
    if let Err(resp) = require_admin(&state, &headers) {
        return *resp;
    }
    let open = state.engine.status_open_txns().await.unwrap_or(0);
    let body = format!(
        "{{\"ready\":{},\"open_transactions\":{}}}",
        state.readiness.is_ready(),
        open
    );
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/json")],
        body,
    )
        .into_response()
}

/// `GET /admin/users/{name}` — inspect a named user's roles (admin only). `404` if no such user.
async fn admin_user(
    State(state): State<ExtraState>,
    headers: HeaderMap,
    Path(name): Path<String>,
) -> Response {
    if let Err(resp) = require_admin(&state, &headers) {
        return *resp;
    }
    // Read the user's roles/name/password-presence off the LIVE catalog under a brief read lock
    // (rmp #94), returning owned data so nothing borrows across the lock boundary.
    let found = state.security.with_auth(|auth| {
        auth.catalog().user(&name).map(|user| {
            let roles: Vec<String> = user.roles.iter().cloned().collect();
            (user.name.clone(), roles, user.password_hash.is_some())
        })
    });
    match found {
        Some((user_name, roles, has_password)) => {
            let body = format!(
                "{{\"user\":{user_name:?},\"roles\":{roles:?},\"has_password\":{has_password}}}"
            );
            (
                StatusCode::OK,
                [(header::CONTENT_TYPE, "application/json")],
                body,
            )
                .into_response()
        }
        None => (StatusCode::NOT_FOUND, "no such user").into_response(),
    }
}

/// `POST /admin/shutdown` — trigger graceful shutdown (admin only, `04 §9.4`). Returns `202 Accepted`
/// immediately; the drain proceeds in the background.
async fn admin_shutdown(State(state): State<ExtraState>, headers: HeaderMap) -> Response {
    let who = match require_admin(&state, &headers) {
        Ok(w) => w,
        Err(resp) => return *resp,
    };
    tracing::info!(admin = %who, "admin-triggered graceful shutdown");
    state.shutdown.trigger();
    (StatusCode::ACCEPTED, "shutting down").into_response()
}
