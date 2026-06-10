//! The server's own HTTP routes merged onto the REST API router: observability (`/metrics`,
//! `/health/live`, `/health/ready`) and a minimal admin surface (`/admin/*`)
//! (`04-technical-design.md` §9 / NFR-10, §8.2).
//!
//! These live in `graphus-server` (not `graphus-rest`) because they are operational, not part of the
//! transactional graph API: the metrics registry, the readiness flag, and the admin shutdown trigger
//! are server-process concerns. They are merged onto the `graphus_rest` router so a single TCP+TLS
//! listener serves the whole HTTP surface.
//!
//! ## Admin surface scope (honest minimalism)
//!
//! The shared [`graphus_auth::Authenticator`] is held as `Arc<Authenticator>` because every auth
//! check (Bolt, REST, UDS) borrows it immutably and the connectivity seams fix that shape. So the
//! admin surface here covers what the immutable-shared catalog allows plus process control:
//!
//! - `GET  /admin/status` — server status (open transactions, readiness).
//! - `GET  /admin/users/{name}` — inspect a named user's roles (RBAC inspection).
//! - `POST /admin/shutdown` — trigger graceful shutdown (`04 §9.4`).
//!
//! All `/admin/*` routes require an authenticated principal with the global `Admin` privilege.
//! **Live user/role *mutation*** (create/drop/grant) needs the auth core behind a lock so the
//! running, shared authenticator can be mutated; that is a documented follow-up requiring a
//! `graphus-auth`/`graphus-rest` seam change (out of this crate's boundary). The inspection +
//! shutdown surface is real and authenticated.

use std::sync::Arc;

use axum::Router;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use graphus_auth::{Authenticator, Privilege};

use crate::engine::EngineHandle;
use crate::metrics::Metrics;
use crate::shutdown::ShutdownCoordinator;

/// Shared state for the server's own routes.
#[derive(Clone)]
struct ExtraState {
    metrics: Arc<Metrics>,
    engine: EngineHandle,
    auth: Arc<Authenticator>,
    clock: Arc<dyn graphus_core::capability::Clock + Send + Sync>,
    shutdown: ShutdownCoordinator,
    readiness: crate::observability::Readiness,
}

/// Builds the observability + admin routes as a standalone `Router` to be merged onto the REST API
/// router.
pub fn routes(
    metrics: Arc<Metrics>,
    engine: EngineHandle,
    auth: Arc<Authenticator>,
    clock: Arc<dyn graphus_core::capability::Clock + Send + Sync>,
    shutdown: ShutdownCoordinator,
    readiness: crate::observability::Readiness,
) -> Router {
    let state = ExtraState {
        metrics,
        engine,
        auth,
        clock,
        shutdown,
        readiness,
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

/// `GET /metrics` — Prometheus text exposition (`04 §9` / NFR-10). Unauthenticated by design: it is a
/// scrape endpoint, conventionally bound on a trusted network; it exposes only aggregate counters,
/// no data.
async fn metrics_handler(State(state): State<ExtraState>) -> Response {
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

/// `GET /health/live` — liveness: always `200 OK` while the process runs (`04 §9`).
async fn health_live() -> Response {
    (StatusCode::OK, "live").into_response()
}

/// `GET /health/ready` — readiness: `200 OK` once the store is verified + the engine is serving, and
/// `503` while starting up or shutting down (`04 §9`).
async fn health_ready(State(state): State<ExtraState>) -> Response {
    if state.readiness.is_ready() {
        (StatusCode::OK, "ready").into_response()
    } else {
        (StatusCode::SERVICE_UNAVAILABLE, "not ready").into_response()
    }
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
    let now_unix_secs = state.clock.now_nanos() / 1_000_000_000;
    let claims = state
        .auth
        .authenticate_bearer(token, now_unix_secs)
        .map_err(|_| {
            state.metrics.record_auth_failure();
            Box::new((StatusCode::UNAUTHORIZED, "invalid or expired token").into_response())
        })?;
    state
        .auth
        .require(&claims.sub, &Privilege::admin_database())
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
    match state.auth.catalog().user(&name) {
        Some(user) => {
            let roles: Vec<String> = user.roles.iter().cloned().collect();
            let body = format!(
                "{{\"user\":{:?},\"roles\":{:?},\"has_password\":{}}}",
                user.name,
                roles,
                user.password_hash.is_some()
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
