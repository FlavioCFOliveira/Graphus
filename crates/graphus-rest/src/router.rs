//! The axum [`Router`] and request handlers — the REST transactional API wired together
//! (`04-technical-design.md` §8.2, `06-bolt-and-error-shapes.md` §4).
//!
//! This is the connectivity surface: it owns no query/storage logic (that is the [`RestEngine`]
//! seam), no value-encoding logic ([`crate::value`]), and no error-shape logic
//! ([`crate::problem`]) — it only routes HTTP, authenticates (the [`AuthProvider`] seam), drives the
//! transaction lifecycle through the [`TxRegistry`], and negotiates the wire format. The same
//! executor and `Value` model sit behind it as behind Bolt (`04 §8.3`).
//!
//! # Route table (`04 §8.2`)
//!
//! | Method & path | Handler | Purpose |
//! | --- | --- | --- |
//! | `POST /db/{db}/tx` | `begin` | open an explicit transaction (reads `access_mode`) |
//! | `POST /db/{db}/tx/{id}` | `run_in_tx` | run statements in the open tx (resets the timeout) |
//! | `POST /db/{db}/tx/{id}/commit` | `commit_tx` | run final statements + commit |
//! | `DELETE /db/{db}/tx/{id}` | `rollback_tx` | roll back |
//! | `POST /db/{db}/tx/commit` | `auto_commit` | single-shot auto-commit (reads `access_mode`) |
//! | `POST /db/{db}/graph` | `graph_viz` | run a read query, return a deduplicated graph projection (rmp #77) |
//! | `GET /openapi.json` | `openapi_doc` | the static OpenAPI 3.1 document |
//!
//! # No sockets here
//!
//! Per the hard rule, this module builds a `Router` and drives it; binding a listener and
//! terminating TLS is the server's job (rmp #20). The tests exercise the router fully in-process via
//! `tower::ServiceExt::oneshot`, so the API is certified independently of the I/O layer (mirroring
//! how `graphus-bolt` certifies its state machine over in-memory transports).
//!
//! # The `Built` response intermediate
//!
//! Every handler produces a `Built` (`status` + `content_type` + buffered `body` bytes) rather
//! than an opaque `axum::Response` directly. This makes the **`Idempotency-Key`** cache trivial and
//! correct — the bytes to cache *are* the response — and keeps the conversion to `axum::Response` in
//! one place. The single exception is the NDJSON streaming path, which builds its body
//! line-by-line and is not idempotency-cached (see below).
//!
//! # Streaming (`04 §8.2`, §7.7)
//!
//! When the client `Accept`s `application/x-ndjson`, a single-statement result is framed as
//! NDJSON — a `fields` header line, then one line per row, then a `summary` line — pulled lazily
//! from the [`ResultStream`]. Otherwise the result is buffered into a typed-JSON or CBOR
//! [`RunResponse`].
//!
//! # Idempotency (`04 §8.2`)
//!
//! The transaction-*finalising* entry points (`begin`, `commit`, `auto_commit`) honour an
//! `Idempotency-Key`: the first `Built` response under a key is cached and a retry replays it
//! verbatim rather than re-executing — exactly the retries that matter (a client that resends a
//! commit must not commit twice). The NDJSON streaming path is not cached (a byte-replayable cache
//! of an unbounded stream would defeat the bounded-memory goal); a client wanting idempotent
//! semantics uses the buffered response by not requesting NDJSON.

use std::sync::Arc;

use axum::Router;
use axum::body::{Body, Bytes};
use axum::extract::{DefaultBodyLimit, Path, State};
use axum::response::Response;
use axum::routing::{get, post};
use graphus_auth::{AuthError, AuthProvider, Privilege};
use graphus_core::capability::Clock;
use graphus_core::{GraphusError, Value};
use http::header::{ACCEPT, AUTHORIZATION, CONTENT_TYPE};
use http::{HeaderMap, HeaderValue, StatusCode};
use serde_json::{Value as Json, json};
use tower_http::compression::CompressionLayer;
use tower_http::cors::CorsLayer;

use crate::engine::{AccessMode, RestEngine, ResultStream, RunSummary, TxHandle, TxOrigin};
use crate::negotiate::{Decode, Wire, request_decode, response_wire};
use crate::problem::{PROBLEM_JSON, Problem};
use crate::protocol::{
    BeginResponse, RunRequest, RunResponse, Statement, StatementResult, parse_access_mode,
};
use crate::registry::{CachedResponse, TxRegistry};
use crate::value::{self, ValueCodecError};

/// Nanoseconds per second, for deriving the JWT clock's `now_unix_secs` from the injected [`Clock`].
const NANOS_PER_SEC: u64 = 1_000_000_000;

/// The default inactivity TTL for an explicit transaction (`04 §8.2`): 30 seconds, in nanoseconds on
/// the injected clock's timeline. The server (rmp #20) makes this configurable; this is the default.
pub const DEFAULT_TX_TTL_NANOS: u64 = 30 * NANOS_PER_SEC;

/// The `Idempotency-Key` request header name (`04 §8.2`).
const IDEMPOTENCY_KEY: &str = "idempotency-key";

// =============================== built response ================================================

/// A fully-buffered response: status + `Content-Type` + body bytes.
///
/// Handlers return this so the `Idempotency-Key` cache stores the exact bytes and the conversion to
/// an `axum::Response` happens in exactly one place ([`Built::into_response`]).
#[derive(Clone)]
struct Built {
    status: StatusCode,
    content_type: String,
    body: Vec<u8>,
}

impl Built {
    fn new(status: StatusCode, content_type: &str, body: Vec<u8>) -> Self {
        Self {
            status,
            content_type: content_type.to_owned(),
            body,
        }
    }

    /// Serialises `value` as JSON into a `Built`.
    fn json(status: StatusCode, value: &Json) -> Self {
        let body = serde_json::to_vec(value).unwrap_or_else(|_| b"{}".to_vec());
        Self::new(status, "application/json", body)
    }

    /// A `Built` from an RFC 9457 [`Problem`] (`application/problem+json`).
    ///
    /// Takes the `Problem` by value so it composes directly with `Result::unwrap_or_else`.
    fn problem(problem: Problem) -> Self {
        let body = serde_json::to_vec(&problem).unwrap_or_else(|_| b"{}".to_vec());
        Self::new(problem.status_code(), PROBLEM_JSON, body)
    }

    /// Converts to the final `axum::Response`.
    fn into_response(self) -> Response {
        Response::builder()
            .status(self.status)
            .header(CONTENT_TYPE, self.content_type)
            .body(Body::from(self.body))
            // The status/header/body are all values we control, so this only fails on an internal
            // invariant violation; fall back to a bare 500 rather than panic.
            .unwrap_or_else(|_| {
                let mut resp = Response::new(Body::empty());
                *resp.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
                resp
            })
    }

    fn cached(&self) -> CachedResponse {
        CachedResponse {
            status: self.status.as_u16(),
            content_type: self.content_type.clone(),
            body: self.body.clone(),
        }
    }
}

impl From<Problem> for Built {
    fn from(p: Problem) -> Self {
        Built::problem(p)
    }
}

// =============================== state =========================================================

/// Observes REST authentication outcomes for audit (rmp #70). Implemented by the server (which
/// records an audit event); the REST router stays audit-agnostic and merely notifies an observer if
/// one is wired in.
///
/// The router has no login endpoint (Bearer tokens are minted out of band), so the only REST auth
/// event is per-request Bearer validation. The attempted principal is **not** recoverable from a
/// bearer token cheaply, so [`on_auth_failure`](Self::on_auth_failure) receives `None`. **Credentials
/// are never passed** — only the resolved username on success.
pub trait AuthObserver: Send + Sync {
    /// Called when a request's Bearer token validates, with the resolved principal (subject).
    fn on_auth_success(&self, principal: &str);
    /// Called when Bearer validation fails, with the attempted principal (usually `None` — not
    /// recoverable from a token) and a short, secret-free reason.
    fn on_auth_failure(&self, attempted: Option<&str>, reason: &str);
}

/// The shared application state every handler reads (cloned per request — all fields are `Arc`).
///
/// Generic over the concrete [`RestEngine`] so the seam stays boxing-free; the server constructs it
/// with `graphus-cypher`'s coordinator (rmp #20) and the tests with the mock engine.
pub struct AppState<E: RestEngine> {
    engine: Arc<E>,
    /// The authentication seam (rmp #94): a `dyn` so the server can back it with a **live**
    /// security-catalog view (a runtime user create/change/drop takes effect for Bearer auth at
    /// once), while the tests back it with a plain snapshot `Authenticator`.
    auth: Arc<dyn AuthProvider>,
    registry: Arc<TxRegistry>,
    clock: Arc<dyn Clock + Send + Sync>,
    /// An optional audit observer (rmp #70): when set, [`authenticate`] notifies it of each
    /// Bearer-validation outcome. `None` keeps the router byte-for-byte audit-free (e.g. the tests).
    auth_observer: Option<Arc<dyn AuthObserver>>,
}

// Manual `Clone` (deriving would wrongly require `E: Clone`; the fields are all `Arc`).
impl<E: RestEngine> Clone for AppState<E> {
    fn clone(&self) -> Self {
        Self {
            engine: Arc::clone(&self.engine),
            auth: Arc::clone(&self.auth),
            registry: Arc::clone(&self.registry),
            clock: Arc::clone(&self.clock),
            auth_observer: self.auth_observer.clone(),
        }
    }
}

impl<E: RestEngine + 'static> AppState<E> {
    /// Builds the shared state from the engine, authenticator, registry, and injected clock. No
    /// audit observer is wired by default (the router stays audit-agnostic); attach one with
    /// [`with_auth_observer`](Self::with_auth_observer).
    pub fn new(
        engine: Arc<E>,
        auth: Arc<dyn AuthProvider>,
        registry: Arc<TxRegistry>,
        clock: Arc<dyn Clock + Send + Sync>,
    ) -> Self {
        Self {
            engine,
            auth,
            registry,
            clock,
            auth_observer: None,
        }
    }

    /// Attaches an [`AuthObserver`] so each Bearer-validation outcome is reported for audit (rmp
    /// #70). Returns `self` for chaining at construction. Existing call sites that do not need
    /// auditing leave it unset.
    #[must_use]
    pub fn with_auth_observer(mut self, observer: Arc<dyn AuthObserver>) -> Self {
        self.auth_observer = Some(observer);
        self
    }
}

// Clock accessors live in a non-`'static` block so the request helpers (`<E: RestEngine>`) can call
// them without an unnecessary `'static` bound (only `new`'s `Arc<E>` storage needs `'static`).
impl<E: RestEngine> AppState<E> {
    /// The current injected-clock value in nanoseconds.
    fn now_nanos(&self) -> u64 {
        self.clock.now_nanos()
    }

    /// The JWT expiry clock (`now_unix_secs`) derived from the injected clock (`04 §8.4`: the server
    /// derives `now_unix_secs` from its production `Clock`). The clock is monotonic nanoseconds.
    fn now_unix_secs(&self) -> u64 {
        self.now_nanos() / NANOS_PER_SEC
    }
}

/// Maximum size, in bytes, of a request body the REST API will buffer before rejecting it `413`.
///
/// Every handler reads the whole body into memory (the [`Bytes`] extractor) to decode it as a single
/// JSON/CBOR request, so an unbounded body is a memory-exhaustion DoS reachable from one request.
/// axum applies an implicit 2 MiB cap, but it is neither tunable nor auditable; this constant makes
/// the limit **explicit and documented** and is wired with [`DefaultBodyLimit::max`] below. 4 MiB
/// comfortably accommodates a large statement batch with inline parameters while staying small enough
/// that a flood of max-size bodies cannot exhaust server memory. A body past this limit is refused
/// with `413 Payload Too Large` before any decoding runs.
pub const MAX_REQUEST_BODY_BYTES: usize = 4 * 1024 * 1024;

/// Builds the REST [`Router`] with all routes and the HTTP-niceties layers wired (`04 §8.2`).
///
/// The returned router is ready to be served by a listener (rmp #20) or driven in-process by
/// `tower::ServiceExt::oneshot` (the tests). HTTP/2 is supported by the underlying hyper server when
/// the listener enables it (axum's `http2` feature is on); **CORS** and **response compression** are
/// wired here as `tower-http` layers. The request body is capped at [`MAX_REQUEST_BODY_BYTES`]
/// (`413` past the cap) so untrusted input cannot exhaust memory.
pub fn router<E: RestEngine + Send + Sync + 'static>(state: AppState<E>) -> Router {
    Router::new()
        .route("/openapi.json", get(openapi_doc))
        .route("/db/{db}/tx", post(begin::<E>))
        .route("/db/{db}/tx/commit", post(auto_commit::<E>))
        .route("/db/{db}/graph", post(graph_viz::<E>))
        .route(
            "/db/{db}/tx/{id}",
            post(run_in_tx::<E>).delete(rollback_tx::<E>),
        )
        .route("/db/{db}/tx/{id}/commit", post(commit_tx::<E>))
        // Bound the buffered request body explicitly (`413` past the cap) so untrusted input cannot
        // exhaust server memory. Replaces axum's implicit, un-auditable 2 MiB default.
        .layer(DefaultBodyLimit::max(MAX_REQUEST_BODY_BYTES))
        // HTTP niceties (`04 §8.2`): permissive CORS + gzip response compression, wired for
        // production use. Their exhaustive behaviour is tower-http's, not re-tested here.
        .layer(CompressionLayer::new())
        .layer(CorsLayer::permissive())
        .with_state(state)
}

// =============================== handlers ======================================================

/// `GET /openapi.json` → the static OpenAPI 3.1 document (`04 §8.2`). Unauthenticated (a public API
/// description).
async fn openapi_doc() -> Response {
    Built::json(StatusCode::OK, &crate::openapi::document()).into_response()
}

/// `POST /db/{db}/tx` → open an explicit transaction (`04 §8.2`, `06 §4`).
async fn begin<E: RestEngine + 'static>(
    State(state): State<AppState<E>>,
    Path(db): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    with_idempotency(&state, &headers, |state| {
        let identity = authenticate(state, &headers)?;
        let req = decode_request(&headers, &body)?;
        // `06 §4`: validate access_mode; an invalid value is a 400 and the tx is NOT opened.
        let mode = parse_access_mode(&req.access_mode).map_err(|bad| {
            Problem::bad_request(format!(
                "invalid access_mode {bad}: expected \"READ\" or \"WRITE\""
            ))
        })?;
        authorize_mode(state, &identity, mode)?;

        let handle = state
            .engine
            .begin(
                &db,
                mode,
                TxOrigin {
                    principal: &identity,
                    explicit: true,
                },
            )
            .map_err(|e| Problem::from_graphus_error(&e))?;
        let now = state.now_nanos();
        let (id, expires_at_nanos) = state.registry.open(handle, &db, mode, now);

        Ok(serializable_built(
            &headers,
            StatusCode::CREATED,
            &BeginResponse {
                id: id.clone(),
                commit: format!("/db/{db}/tx/{id}"),
                expires_at_nanos,
                access_mode: mode.as_str().to_owned(),
            },
        ))
    })
}

/// `POST /db/{db}/tx/{id}` → run statements in the open transaction (resets the timeout)
/// (`04 §8.2`).
async fn run_in_tx<E: RestEngine + 'static>(
    State(state): State<AppState<E>>,
    Path((_db, id)): Path<(String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    // The streaming path cannot be uniformly buffered for the idempotency cache, and `run` is not a
    // finalising endpoint, so it is handled directly (not via `with_idempotency`).
    let outcome = (|| {
        let identity = authenticate(&state, &headers)?;
        let req = decode_request(&headers, &body)?;
        let now = state.now_nanos();
        // Touch: refresh the deadline, or reap + 404 if expired (`04 §8.2`).
        let Some(info) = state.registry.touch(&id, now, state.engine.as_ref()) else {
            return Err(Problem::unknown_transaction(&id));
        };
        authorize_mode(&state, &identity, info.mode)?;
        Ok((req, info))
    })();

    let (req, info) = match outcome {
        Ok(v) => v,
        Err(p) => return Built::from(p).into_response(),
    };

    run_statements(
        &state,
        &headers,
        info.handle,
        &req.statements,
        Finalise::KeepOpen {
            id,
            expires_at_nanos: info.deadline_nanos,
        },
    )
}

/// `POST /db/{db}/tx/{id}/commit` → run final statements and commit (`04 §8.2`).
async fn commit_tx<E: RestEngine + 'static>(
    State(state): State<AppState<E>>,
    Path((_db, id)): Path<(String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    // If idempotency-cached, replay before any side effect.
    if let Some(replay) = replay_idempotent(&state, &headers) {
        return replay.into_response();
    }

    let outcome: Result<(RunRequest, TxHandle), Problem> = (|| {
        let identity = authenticate(&state, &headers)?;
        let req = decode_request(&headers, &body)?;
        let now = state.now_nanos();
        // Reap first if expired (so a long-idle commit fails as gone rather than committing stale).
        if state
            .registry
            .touch(&id, now, state.engine.as_ref())
            .is_none()
        {
            return Err(Problem::unknown_transaction(&id));
        }
        let Some((handle, _db, mode)) = state.registry.take(&id) else {
            return Err(Problem::unknown_transaction(&id));
        };
        if let Err(p) = authorize_mode(&state, &identity, mode) {
            // Unauthorized: roll the taken handle back (idempotent) and surface the authz failure.
            let _ = state.engine.rollback(handle);
            return Err(p);
        }
        Ok((req, handle))
    })();

    let (req, handle) = match outcome {
        Ok(v) => v,
        Err(p) => return Built::from(p).into_response(),
    };

    // Streaming commit goes direct (not cached); buffered commit is cached.
    let wire = match response_wire(header_str(&headers, &ACCEPT)) {
        Some(w) => w,
        None => {
            return Built::from(Problem::not_acceptable("no acceptable representation"))
                .into_response();
        }
    };
    if wire == Wire::Ndjson && req.statements.len() == 1 {
        return stream_single_statement_ndjson(
            &state,
            handle,
            &req.statements[0],
            Finalise::Commit,
        );
    }

    let built = run_statements_buffered(
        &state,
        &headers,
        handle,
        &req.statements,
        Finalise::Commit,
        wire,
    )
    .unwrap_or_else(Built::problem);
    cache_and_respond(&state, &headers, built)
}

/// `DELETE /db/{db}/tx/{id}` → roll back the open transaction (`04 §8.2`).
async fn rollback_tx<E: RestEngine + 'static>(
    State(state): State<AppState<E>>,
    Path((_db, id)): Path<(String, String)>,
    headers: HeaderMap,
) -> Response {
    let built = (|| {
        let identity = authenticate(&state, &headers)?;
        let Some((handle, _db, mode)) = state.registry.take(&id) else {
            return Err(Problem::unknown_transaction(&id));
        };
        if let Err(p) = authorize_mode(&state, &identity, mode) {
            // Still discard the transaction (the caller asked to), but report the authz failure.
            let _ = state.engine.rollback(handle);
            return Err(p);
        }
        state
            .engine
            .rollback(handle)
            .map_err(|e| Problem::from_graphus_error(&e))?;
        Ok(Built::json(StatusCode::OK, &json!({ "rolled_back": true })))
    })();
    into_response(built)
}

/// `POST /db/{db}/tx/commit` → single-statement auto-commit shortcut (`04 §8.2`, `06 §4`).
async fn auto_commit<E: RestEngine + 'static>(
    State(state): State<AppState<E>>,
    Path(db): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if let Some(replay) = replay_idempotent(&state, &headers) {
        return replay.into_response();
    }

    let outcome: Result<(RunRequest, TxHandle), Problem> = (|| {
        let identity = authenticate(&state, &headers)?;
        let req = decode_request(&headers, &body)?;
        let mode = parse_access_mode(&req.access_mode).map_err(|bad| {
            Problem::bad_request(format!(
                "invalid access_mode {bad}: expected \"READ\" or \"WRITE\""
            ))
        })?;
        authorize_mode(&state, &identity, mode)?;
        let handle = state
            .engine
            .begin(
                &db,
                mode,
                TxOrigin {
                    principal: &identity,
                    explicit: false,
                },
            )
            .map_err(|e| Problem::from_graphus_error(&e))?;
        Ok((req, handle))
    })();

    let (req, handle) = match outcome {
        Ok(v) => v,
        Err(p) => return Built::from(p).into_response(),
    };

    let wire = match response_wire(header_str(&headers, &ACCEPT)) {
        Some(w) => w,
        None => {
            let _ = state.engine.rollback(handle);
            return Built::from(Problem::not_acceptable("no acceptable representation"))
                .into_response();
        }
    };
    if wire == Wire::Ndjson && req.statements.len() == 1 {
        return stream_single_statement_ndjson(
            &state,
            handle,
            &req.statements[0],
            Finalise::Commit,
        );
    }
    let built = run_statements_buffered(
        &state,
        &headers,
        handle,
        &req.statements,
        Finalise::Commit,
        wire,
    )
    .unwrap_or_else(Built::problem);
    cache_and_respond(&state, &headers, built)
}

/// `POST /db/{db}/graph` → run a read query and return a **deduplicated graph projection** of its
/// result, for graph-rendering front-ends (rmp #77).
///
/// # Behaviour
///
/// The request body is a [`RunRequest`] (the same `{ statements: [{ statement, parameters }] }` shape
/// the transactional endpoints accept). All statements run inside **one auto-managed `READ`
/// transaction** — the access mode is **forced to `READ`** (this is a visualisation read; an
/// `access_mode` member in the body is ignored), so a write statement is rejected by the engine
/// exactly as in any read transaction (`06 §4`). On success the transaction is committed (a read
/// commit has no side effects) and the projection is returned; on the first statement error the
/// transaction is rolled back and an RFC 9457 problem is returned (`06 §3.3`) — the same error model
/// as every other endpoint.
///
/// # Projection (the documented response shape)
///
/// Every cell of every result row is walked recursively (into `List`s and `Path`s) and folded into a
/// graph of **distinct** entities — nodes deduplicated by node id, relationships by relationship id,
/// so a node shared across rows/paths appears once ([`GraphProjection`]). The response body is:
///
/// ```json
/// {
///   "nodes": [
///     { "id": <int>, "labels": [ <str>… ], "properties": { <k>: <jolt-value>… } }
///   ],
///   "relationships": [
///     { "id": <int>, "type": <str>, "startNode": <int>, "endNode": <int>,
///       "properties": { <k>: <jolt-value>… } }
///   ]
/// }
/// ```
///
/// Property values use the strict-Jolt codec (int53-safe), exactly as the transactional results do;
/// entity `id`/`startNode`/`endNode` are plain JSON numbers (see [`GraphProjection::to_json`]). The
/// response is content-negotiated (JSON by default, CBOR via `Accept: application/cbor`); it is a
/// single buffered aggregate, so it is not streamed as NDJSON and is not idempotency-cached (a read
/// projection is naturally repeatable).
///
/// # Access control, database selection, and RBAC
///
/// Authentication, the `{db}` database selection, and fine-grained RBAC are honoured **identically**
/// to [`auto_commit`]: the request is Bearer-authenticated, `READ` is authorized against the
/// database, and the transaction is opened on the named database through the same [`RestEngine`]
/// seam. An RBAC-hidden node, relationship, or property is already absent from the resolved
/// [`RestValue`] cells the engine yields (the seam applies fine-grained filtering before the result
/// boundary), so the projection inherits that filtering for free — a forbidden entity simply never
/// reaches the accumulator.
async fn graph_viz<E: RestEngine + 'static>(
    State(state): State<AppState<E>>,
    Path(db): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    // Resolve the wire format up front (the projection is always a buffered aggregate — JSON or
    // CBOR; an NDJSON `Accept` falls back to JSON, since there is no row stream to frame).
    let wire = match response_wire(header_str(&headers, &ACCEPT)) {
        Some(Wire::Ndjson) | None => Wire::Json,
        Some(w) => w,
    };

    let outcome: Result<(RunRequest, TxHandle), Problem> = (|| {
        let identity = authenticate(&state, &headers)?;
        let req = decode_request(&headers, &body)?;
        // A visualisation query is always a READ (the safe, spec-consistent default — Neo4j's viz
        // surfaces run read). Any `access_mode` in the body is ignored.
        authorize_mode(&state, &identity, AccessMode::Read)?;
        let handle = state
            .engine
            .begin(
                &db,
                AccessMode::Read,
                TxOrigin {
                    principal: &identity,
                    explicit: false,
                },
            )
            .map_err(|e| Problem::from_graphus_error(&e))?;
        Ok((req, handle))
    })();

    let (req, handle) = match outcome {
        Ok(v) => v,
        Err(p) => return Built::from(p).into_response(),
    };

    let built = project_graph(&state, handle, &req.statements, wire).unwrap_or_else(Built::problem);
    built.into_response()
}

/// Runs `statements` in the (read) transaction `handle`, folding every row of every statement into
/// one [`GraphProjection`], then commits and returns the projection as a [`Built`] response in
/// `wire`. On the first statement/runtime error the transaction is rolled back and the error is
/// surfaced as a [`Problem`] (no partial result — `06 §3.3`).
fn project_graph<E: RestEngine>(
    state: &AppState<E>,
    handle: TxHandle,
    statements: &[Statement],
    wire: Wire,
) -> Result<Built, Problem> {
    let mut projection = crate::restvalue::GraphProjection::new();
    for stmt in statements {
        if let Err(e) = collect_into_projection(state, handle, stmt, &mut projection) {
            let _ = state.engine.rollback(handle);
            return Err(Problem::from_graphus_error(&e));
        }
    }

    // A read transaction commit has no side effects; do it so the engine releases the handle.
    state
        .engine
        .commit(handle)
        .map_err(|e| Problem::from_graphus_error(&e))?;

    Ok(graph_built(projection.to_json(), wire))
}

/// Runs one statement and folds each of its rows into `projection` (pulling rows lazily from the
/// [`ResultStream`] seam, the same pull the transactional path uses).
fn collect_into_projection<E: RestEngine>(
    state: &AppState<E>,
    handle: TxHandle,
    stmt: &Statement,
    projection: &mut crate::restvalue::GraphProjection,
) -> Result<(), GraphusError> {
    let params = bind_parameters(stmt).map_err(|e| GraphusError::Runtime(e.to_string()))?;
    let mut stream = state.engine.run(handle, &stmt.statement, params)?;
    while let Some(row) = stream.next_row()? {
        projection.add_row(row);
    }
    Ok(())
}

/// Serialises the graph-projection JSON object into a [`Built`] in the negotiated `wire` (JSON or
/// CBOR). A serialisation failure (an internal invariant) degrades to a `500` problem.
fn graph_built(graph: Json, wire: Wire) -> Built {
    match wire {
        Wire::Cbor => {
            let mut buf = Vec::new();
            if ciborium::into_writer(&graph, &mut buf).is_err() {
                return Built::problem(Problem::from_graphus_error(&GraphusError::Protocol(
                    "failed to encode CBOR graph projection".to_owned(),
                )));
            }
            Built::new(StatusCode::OK, Wire::Cbor.content_type(), buf)
        }
        // NDJSON never reaches here (the handler maps it to JSON); JSON is the default.
        _ => Built::json(StatusCode::OK, &graph),
    }
}

// =============================== run + finalise ================================================

/// What to do with the transaction after the statements run.
enum Finalise {
    /// Keep the transaction open; echo its id and refreshed expiry.
    KeepOpen { id: String, expires_at_nanos: u64 },
    /// Commit the transaction after the last statement.
    Commit,
}

/// Dispatches a `run` to the streaming or buffered path based on the negotiated wire format, then
/// converts to a `Response`. Used by `run_in_tx` (which does not idempotency-cache).
fn run_statements<E: RestEngine>(
    state: &AppState<E>,
    headers: &HeaderMap,
    handle: TxHandle,
    statements: &[Statement],
    finalise: Finalise,
) -> Response {
    let wire = match response_wire(header_str(headers, &ACCEPT)) {
        Some(w) => w,
        None => {
            return Built::from(Problem::not_acceptable("no acceptable representation"))
                .into_response();
        }
    };
    if wire == Wire::Ndjson && statements.len() == 1 {
        return stream_single_statement_ndjson(state, handle, &statements[0], finalise);
    }
    run_statements_buffered(state, headers, handle, statements, finalise, wire)
        .unwrap_or_else(Built::problem)
        .into_response()
}

/// Runs `statements` against `handle` in the buffered path, collecting typed-encoded results, then
/// finalises. Returns the `Built` response, or a [`Problem`] on the first error (after rolling the
/// transaction back — no partial commit, `06 §3.3`).
fn run_statements_buffered<E: RestEngine>(
    state: &AppState<E>,
    headers: &HeaderMap,
    handle: TxHandle,
    statements: &[Statement],
    finalise: Finalise,
    wire: Wire,
) -> Result<Built, Problem> {
    let mut results = Vec::with_capacity(statements.len());
    for stmt in statements {
        match run_one(state, handle, stmt, wire) {
            Ok(result) => results.push(result),
            Err(e) => {
                let _ = state.engine.rollback(handle);
                return Err(Problem::from_graphus_error(&e));
            }
        }
    }

    let (id, expires_at_nanos) = match finalise {
        Finalise::Commit => {
            state
                .engine
                .commit(handle)
                .map_err(|e| Problem::from_graphus_error(&e))?;
            (None, None)
        }
        Finalise::KeepOpen {
            id,
            expires_at_nanos,
        } => (Some(id), Some(expires_at_nanos)),
    };

    Ok(serializable_built(
        headers,
        StatusCode::OK,
        &RunResponse {
            results,
            id,
            expires_at_nanos,
        },
    ))
}

/// **Deterministic synchronous entry** for the VOPR simulator (rmp #164): runs an auto-commit
/// statement batch through the **same** request core the axum `auto_commit` handler uses
/// (`run_statements_buffered`), returning the serialized response as a [`CachedResponse`]
/// (status + content-type + body bytes).
///
/// This bypasses only the axum/tower/hyper HTTP transport (generic plumbing, covered by the
/// integration tests) and the auth/idempotency layers — everything Graphus-specific about a REST
/// request (statement binding, the engine tx lifecycle, result serialization in `accept`'s wire
/// format, and RFC 9457 problem mapping on error) runs verbatim. It needs no `Send`/async, so the
/// single-threaded deterministic engine (rmp #160) drives it reproducibly.
///
/// `mode` is the transaction access mode; on a begin error a problem+json response is returned.
pub fn execute_autocommit<E: RestEngine>(
    state: &AppState<E>,
    db: &str,
    principal: &str,
    mode: AccessMode,
    accept: Wire,
    statements: &[Statement],
) -> CachedResponse {
    let handle = match state.engine.begin(
        db,
        mode,
        TxOrigin {
            principal,
            explicit: false,
        },
    ) {
        Ok(h) => h,
        Err(e) => return Built::problem(Problem::from_graphus_error(&e)).cached(),
    };
    // `serializable_built` re-derives the wire format from the `Accept` header, so synthesise one
    // carrying the requested format.
    let mut headers = HeaderMap::new();
    if let Ok(v) = HeaderValue::from_str(accept.content_type()) {
        headers.insert(ACCEPT, v);
    }
    run_statements_buffered(state, &headers, handle, statements, Finalise::Commit, accept)
        .unwrap_or_else(Built::problem)
        .cached()
}

/// Runs one statement and returns its typed-encoded [`StatementResult`] (the buffered path).
fn run_one<E: RestEngine>(
    state: &AppState<E>,
    handle: TxHandle,
    stmt: &Statement,
    _wire: Wire,
) -> Result<StatementResult, GraphusError> {
    let params = bind_parameters(stmt).map_err(|e| GraphusError::Runtime(e.to_string()))?;
    let mut stream = state.engine.run(handle, &stmt.statement, params)?;
    let fields = stream.fields().to_vec();
    let mut data = Vec::new();
    while let Some(row) = stream.next_row()? {
        data.push(Json::Array(
            row.iter()
                .map(crate::restvalue::restvalue_to_jolt)
                .collect(),
        ));
    }
    let summary = encode_summary(&stream.summary());
    Ok(StatementResult {
        fields,
        data,
        summary,
    })
}

/// Frames a single statement's result as NDJSON (`04 §8.2`): a `fields` line, one line per row, then
/// a `summary` line. Rows are pulled lazily from the [`ResultStream`] seam.
///
/// The engine's [`ResultStream`] is synchronous (not `Send`-across-await), so the body is assembled
/// here line-by-line; the **pull-based seam** is what lets a future async-cursor engine flush each
/// line without buffering the whole result. The NDJSON framing is identical either way, and a client
/// parses it incrementally. This path is not idempotency-cached (see the module docs).
fn stream_single_statement_ndjson<E: RestEngine>(
    state: &AppState<E>,
    handle: TxHandle,
    stmt: &Statement,
    finalise: Finalise,
) -> Response {
    let params = match bind_parameters(stmt) {
        Ok(p) => p,
        Err(e) => return Built::from(Problem::from_codec_error(&e)).into_response(),
    };
    let mut stream = match state.engine.run(handle, &stmt.statement, params) {
        Ok(s) => s,
        Err(e) => {
            let _ = state.engine.rollback(handle);
            return Built::from(Problem::from_graphus_error(&e)).into_response();
        }
    };

    let mut out = Vec::new();
    push_ndjson_line(&mut out, &json!({ "fields": stream.fields() }));
    loop {
        match stream.next_row() {
            Ok(Some(row)) => {
                let encoded: Vec<Json> = row
                    .iter()
                    .map(crate::restvalue::restvalue_to_jolt)
                    .collect();
                push_ndjson_line(&mut out, &json!({ "row": encoded }));
            }
            Ok(None) => break,
            Err(e) => {
                // A runtime error mid-stream: emit a problem line (rows may already have streamed —
                // `06 §3.3`), roll back, and stop. The body stays well-formed NDJSON.
                let problem = Problem::from_graphus_error(&e);
                push_ndjson_line(
                    &mut out,
                    &serde_json::to_value(&problem).unwrap_or(Json::Null),
                );
                let _ = state.engine.rollback(handle);
                return Built::new(StatusCode::OK, "application/x-ndjson", out).into_response();
            }
        }
    }
    push_ndjson_line(
        &mut out,
        &json!({ "summary": encode_summary(&stream.summary()) }),
    );

    if matches!(finalise, Finalise::Commit) {
        if let Err(e) = state.engine.commit(handle) {
            return Built::from(Problem::from_graphus_error(&e)).into_response();
        }
    }
    Built::new(StatusCode::OK, "application/x-ndjson", out).into_response()
}

// =============================== auth + decode helpers =========================================

/// Authenticates the request's `Authorization: Bearer` token against the [`AuthProvider`] seam,
/// returning the principal's username, or an RFC 9457 [`Problem`] (`401`/`403`) on failure
/// (`04 §8.4`, `06 §3.3`).
fn authenticate<E: RestEngine>(
    state: &AppState<E>,
    headers: &HeaderMap,
) -> Result<String, Problem> {
    let Some(value) = header_str(headers, &AUTHORIZATION) else {
        notify_auth_failure(state, "missing Authorization header");
        return Err(Problem::from_auth_error(&AuthError::Unauthenticated));
    };
    let Some(token) = value
        .strip_prefix("Bearer ")
        .or_else(|| value.strip_prefix("bearer "))
    else {
        notify_auth_failure(state, "Authorization header is not a Bearer token");
        return Err(Problem::from_auth_error(&AuthError::BadToken {
            detail: "Authorization header is not a Bearer token".to_owned(),
        }));
    };
    match state
        .auth
        .authenticate_bearer(token.trim(), state.now_unix_secs())
    {
        Ok(claims) => {
            // Notify the audit observer (rmp #70) of the successful Bearer validation.
            if let Some(observer) = &state.auth_observer {
                observer.on_auth_success(&claims.sub);
            }
            Ok(claims.sub)
        }
        Err(e) => {
            notify_auth_failure(state, "bearer authentication failed");
            Err(Problem::from_auth_error(&e))
        }
    }
}

/// Notifies the audit observer (if any) of a REST authentication failure (rmp #70). The attempted
/// principal is not recoverable from a bearer token cheaply, so `None` is reported; the `reason` is
/// a short, secret-free string.
fn notify_auth_failure<E: RestEngine>(state: &AppState<E>, reason: &str) {
    if let Some(observer) = &state.auth_observer {
        observer.on_auth_failure(None, reason);
    }
}

/// Authorizes `identity` for the privilege implied by `mode` (`04 §8.4`): a `WRITE` transaction
/// needs database `Write`, a `READ` transaction needs database `Read`.
fn authorize_mode<E: RestEngine>(
    state: &AppState<E>,
    identity: &str,
    mode: AccessMode,
) -> Result<(), Problem> {
    let privilege = match mode {
        AccessMode::Read => Privilege::read_database(),
        AccessMode::Write => Privilege::write_database(),
    };
    state
        .auth
        .require(identity, &privilege)
        .map_err(|e| Problem::from_auth_error(&e))
}

/// Decodes the request body into a [`RunRequest`], honouring `Content-Type` (`415` for an
/// undecodable type) (`04 §8.2`). An empty body is an empty request.
fn decode_request(headers: &HeaderMap, body: &Bytes) -> Result<RunRequest, Problem> {
    let decode = request_decode(header_str(headers, &CONTENT_TYPE)).ok_or_else(|| {
        Problem::unsupported_media_type("Content-Type must be application/json or application/cbor")
    })?;
    if body.is_empty() {
        return Ok(RunRequest::default());
    }
    match decode {
        Decode::Json => serde_json::from_slice::<RunRequest>(body).map_err(|e| {
            Problem::from_codec_error(&ValueCodecError::Malformed {
                detail: e.to_string(),
            })
        }),
        // Bound deserialization recursion explicitly (defence-in-depth): a body within the size cap
        // can still nest CBOR arrays/maps deeply enough to overflow the stack, and ciborium's own
        // default limit is implicit. Cap at the same audited depth the typed-value codec enforces
        // (`value::MAX_CBOR_DEPTH`); over-deep input becomes a controlled `Malformed`, never a panic.
        Decode::Cbor => ciborium::de::from_reader_with_recursion_limit::<RunRequest, _>(
            body.as_ref(),
            value::MAX_CBOR_DEPTH,
        )
        .map_err(|e| {
            Problem::from_codec_error(&ValueCodecError::Malformed {
                detail: e.to_string(),
            })
        }),
    }
}

/// Binds a statement's `parameters` (raw JSON) into `(name, Value)` pairs via the typed-value codec.
fn bind_parameters(stmt: &Statement) -> Result<Vec<(String, Value)>, ValueCodecError> {
    match &stmt.parameters {
        None | Some(Json::Null) => Ok(Vec::new()),
        Some(Json::Object(obj)) => {
            let mut out = Vec::with_capacity(obj.len());
            for (k, v) in obj {
                out.push((k.clone(), value::jolt_to_value(v)?));
            }
            Ok(out)
        }
        Some(_) => Err(ValueCodecError::Malformed {
            detail: "`parameters` must be a JSON object".to_owned(),
        }),
    }
}

// =============================== encoding helpers ==============================================

/// Encodes a [`RunSummary`] as a typed object (`type` + `stats`).
fn encode_summary(summary: &RunSummary) -> Json {
    let mut stats = serde_json::Map::new();
    for (k, v) in &summary.stats {
        stats.insert(k.clone(), value::value_to_jolt(v));
    }
    json!({
        "type": summary.query_type,
        "stats": Json::Object(stats),
    })
}

/// Serialises `body` into a [`Built`] in the wire format the `Accept` header negotiated (JSON or
/// CBOR; an NDJSON `Accept` on these scalar envelope bodies falls back to JSON).
fn serializable_built<T: serde::Serialize>(
    headers: &HeaderMap,
    status: StatusCode,
    body: &T,
) -> Built {
    match response_wire(header_str(headers, &ACCEPT)).unwrap_or(Wire::Json) {
        Wire::Cbor => {
            let mut buf = Vec::new();
            if ciborium::into_writer(body, &mut buf).is_err() {
                return Built::problem(Problem::from_graphus_error(&GraphusError::Protocol(
                    "failed to encode CBOR response".to_owned(),
                )));
            }
            Built::new(status, Wire::Cbor.content_type(), buf)
        }
        _ => match serde_json::to_vec(body) {
            Ok(buf) => Built::new(status, "application/json", buf),
            Err(e) => Built::problem(Problem::from_graphus_error(&GraphusError::Protocol(
                format!("failed to encode JSON response: {e}"),
            ))),
        },
    }
}

/// Appends a JSON object as one NDJSON line (object + `\n`) to `out`.
fn push_ndjson_line(out: &mut Vec<u8>, value: &Json) {
    if let Ok(mut bytes) = serde_json::to_vec(value) {
        out.append(&mut bytes);
        out.push(b'\n');
    }
}

/// Reads a header as a `&str`, if present and valid UTF-8.
fn header_str<'h>(headers: &'h HeaderMap, name: &http::header::HeaderName) -> Option<&'h str> {
    headers.get(name).and_then(|v| v.to_str().ok())
}

/// Converts a `Result<Built, Problem>` into a `Response`.
fn into_response(built: Result<Built, Problem>) -> Response {
    built.unwrap_or_else(Built::problem).into_response()
}

// =============================== idempotency ===================================================

/// Runs `f` (a finalising handler body) with `Idempotency-Key` dedup wrapped around it: replays a
/// cached response if the key was seen, otherwise runs `f`, caches its `Built`, and returns it
/// (`04 §8.2`). `f` returns `Result<Built, Problem>`; either is cached so a retry replays the exact
/// first outcome (success *or* the first error).
fn with_idempotency<E, F>(state: &AppState<E>, headers: &HeaderMap, f: F) -> Response
where
    E: RestEngine,
    F: FnOnce(&AppState<E>) -> Result<Built, Problem>,
{
    if let Some(replay) = replay_idempotent(state, headers) {
        return replay.into_response();
    }
    let built = f(state).unwrap_or_else(Built::problem);
    cache_and_respond(state, headers, built)
}

/// Caches `built` under the request's `Idempotency-Key` (if any) and returns it as a `Response`.
fn cache_and_respond<E: RestEngine>(
    state: &AppState<E>,
    headers: &HeaderMap,
    built: Built,
) -> Response {
    if let Some(key) = headers.get(IDEMPOTENCY_KEY).and_then(|v| v.to_str().ok()) {
        state.registry.store_response(key, built.cached());
    }
    built.into_response()
}

/// If the request carries an `Idempotency-Key` already seen, returns the cached [`Built`] to replay
/// (`04 §8.2`); otherwise `None`.
fn replay_idempotent<E: RestEngine>(state: &AppState<E>, headers: &HeaderMap) -> Option<Built> {
    let key = headers.get(IDEMPOTENCY_KEY)?.to_str().ok()?;
    let cached = state.registry.cached_response(key)?;
    Some(Built::new(
        StatusCode::from_u16(cached.status).unwrap_or(StatusCode::OK),
        &cached.content_type,
        cached.body,
    ))
}

#[cfg(test)]
mod tests;
