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
//! | `POST /db/{db}/query/columnar` | `query_columnar` | run a read query, return an **analytical columnar** result body (rmp #334) |
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
//! Most handlers produce a `Built` (`status` + `content_type` + buffered `body` bytes) rather
//! than an opaque `axum::Response` directly. This makes the **`Idempotency-Key`** cache trivial and
//! correct — the bytes to cache *are* the response — and keeps the conversion to `axum::Response` in
//! one place. The exception is the **incremental streaming path** (rmp #475), which never
//! materialises the whole body and is therefore not idempotency-cached (see below).
//!
//! # Streaming with bounded memory (`04 §8.2`, §7.7, §9.3; rmp #475)
//!
//! A single-statement result whose negotiated wire is **NDJSON** or **JSON** is streamed
//! **incrementally**: rows are pulled one at a time from the [`ResultStream`], serialized, flushed,
//! and dropped before the next is pulled, so **server memory stays bounded regardless of the
//! result-set size** — exactly the Bolt `PULL` property (each `RECORD` ships as produced). This
//! closes the egress-DoS where a tiny request asking for a huge result forced the whole body into
//! RAM (an OOM vector that also starved co-tenants on the shared process). The mechanics:
//!
//! - The synchronous [`ResultStream`] is drained on a `tokio::task::spawn_blocking` producer (its
//!   `next_row` blocks the engine's bounded egress channel — never a runtime worker, `04 §9.1`).
//! - Each serialized chunk is `blocking_send`-ed into a **bounded** [`tokio::sync::mpsc`] channel,
//!   so a slow client throttles production (backpressure) rather than buffering the result (`04
//!   §9.3`). The response [`Body`] is fed from the receiver via [`Body::from_stream`].
//! - **NDJSON** frames a `fields` header line, one `row` line per row, then a `summary` line.
//!   **JSON** streams the [`RunResponse`] envelope incrementally — the `[…]` `data` array is emitted
//!   element-by-element — producing **byte-identical** output to the buffered serializer.
//!
//! **Commit-after-drain (ACID).** For an auto-commit / committing statement the COMMIT runs **only
//! after** the result has fully streamed (mirroring Bolt, whose auto-commit finalises at the trailing
//! `SUCCESS`). A row-production error *mid-stream* — which can only arise after the `200` status and
//! the first bytes are already on the wire — rolls the transaction back (no partial commit) and
//! surfaces in-band: NDJSON appends a trailing problem line (a Bolt-`FAILURE`-after-records analogue);
//! JSON terminates the body as a transport error so the client sees an incomplete document. A
//! statement error *before* the first byte still maps to the correct problem+json status, unchanged.
//!
//! CBOR, multi-statement batches, and idempotency-keyed committing requests stay on the buffered
//! path (CBOR cannot be length-prefix-streamed byte-identically; an idempotency replay must cache the
//! exact bytes — see [`with_idempotency`]). These are not the measured DoS vector (one huge result).
//!
//! # Idempotency (`04 §8.2`)
//!
//! The transaction-*finalising* entry points (`begin`, `commit`, `auto_commit`) honour an
//! `Idempotency-Key`: the first `Built` response under a key is cached and a retry replays it
//! verbatim rather than re-executing — exactly the retries that matter (a client that resends a
//! commit must not commit twice). The incremental streaming path is not cached — a byte-replayable
//! cache of an unbounded stream would defeat the bounded-memory goal — so a committing request that
//! carries an `Idempotency-Key` is served from the **buffered** path (which the cache can store)
//! rather than streamed: NDJSON streams unconditionally (never cached, as before), JSON streams only
//! when no key is present, and a keyed JSON commit keeps its exact prior buffered-and-cached
//! behaviour. A client wanting idempotent replay simply sends the key (or omits `x-ndjson`).

use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use axum::Router;
use axum::body::{Body, Bytes};
use axum::extract::{DefaultBodyLimit, Path, State};
use axum::response::Response;
use axum::routing::{get, post};
use graphus_auth::{Action, AuthError, AuthProvider, AuthThrottle, Privilege};
use graphus_core::capability::Clock;
use graphus_core::{GraphusError, Value};
use http::header::{ACCEPT, AUTHORIZATION, CACHE_CONTROL, CONTENT_TYPE};
use http::{HeaderMap, HeaderName, HeaderValue, Method, StatusCode};
use serde_json::{Value as Json, json};
use tower_http::compression::CompressionLayer;
use tower_http::cors::{AllowOrigin, CorsLayer};

use crate::engine::{AccessMode, RestEngine, ResultStream, RunSummary, TxHandle, TxOrigin};
use crate::negotiate::{Decode, Wire, request_decode, response_wire};
use crate::problem::{PROBLEM_JSON, Problem};
use crate::protocol::{
    BeginResponse, DEFAULT_LOGIN_TOKEN_TTL_SECS, LoginRequest, LoginResponse, RunRequest,
    RunResponse, Statement, StatementResult, parse_access_mode,
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

/// `X-Content-Type-Options` header name (rmp #188). Not a constant in `http::header`.
const X_CONTENT_TYPE_OPTIONS: HeaderName = HeaderName::from_static("x-content-type-options");
/// `Referrer-Policy` header name (rmp #188). Not a constant in `http::header`.
const REFERRER_POLICY: HeaderName = HeaderName::from_static("referrer-policy");

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

    /// Converts to the final `axum::Response`, injecting defence-in-depth security headers (rmp #188,
    /// CWE-693/CWE-525) on **every** REST response — including idempotency replays, since this is the
    /// single conversion point:
    ///
    /// - `X-Content-Type-Options: nosniff` — stop MIME sniffing of typed bodies/problem+json.
    /// - `Cache-Control: no-store` — keep dynamic/authenticated results out of intermediary and
    ///   browser caches (a result or cached idempotent body must not be stored downstream).
    /// - `Referrer-Policy: no-referrer` — never leak the request URL (which carries the `{db}` and
    ///   transaction id) cross-origin.
    fn into_response(self) -> Response {
        Response::builder()
            .status(self.status)
            .header(CONTENT_TYPE, self.content_type)
            .header(X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"))
            .header(CACHE_CONTROL, HeaderValue::from_static("no-store"))
            .header(REFERRER_POLICY, HeaderValue::from_static("no-referrer"))
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

// =============================== CORS policy ===================================================

/// The cross-origin resource-sharing policy the router applies (rmp #186, CWE-942).
///
/// **Fail-closed by default**: [`CorsConfig::default`] / [`CorsConfig::same_origin_only`] emit **no**
/// `Access-Control-Allow-Origin`, so a browser refuses any cross-origin read of this authenticated,
/// state-mutating database API. A wildcard is never produced. Cross-origin access is opt-in via an
/// explicit allow-list of trusted origins ([`CorsConfig::allow_origins`]); credentials are advertised
/// only when an allow-list is set (never with a wildcard, which the CORS spec forbids anyway).
///
/// The server (rmp #20) constructs this from configuration and passes it to the router via
/// [`AppState::with_cors`]; the previous unconditional `CorsLayer::permissive()` is gone.
#[derive(Debug, Clone, Default)]
pub struct CorsConfig {
    /// The exact origins allowed to make cross-origin requests (scheme + host + optional port, e.g.
    /// `https://app.example`). Empty ⇒ same-origin only (no CORS headers emitted).
    allowed_origins: Vec<HeaderValue>,
    /// Whether to advertise `Access-Control-Allow-Credentials: true`. Honoured only when
    /// `allowed_origins` is non-empty (credentials with a wildcard are invalid CORS).
    allow_credentials: bool,
}

impl CorsConfig {
    /// The secure default: **same-origin only**, no cross-origin sharing (no CORS headers). Identical
    /// to [`CorsConfig::default`]; named for call-site clarity.
    #[must_use]
    pub fn same_origin_only() -> Self {
        Self::default()
    }

    /// Allow cross-origin requests **only** from the given exact origins (an allow-list). Each origin
    /// is a full origin string (`https://app.example`); malformed entries are silently dropped (they
    /// can never match a real `Origin` header, so they are inert rather than a panic).
    #[must_use]
    pub fn allow_origins<I, S>(origins: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let allowed_origins = origins
            .into_iter()
            .filter_map(|o| HeaderValue::from_str(o.as_ref()).ok())
            .collect();
        Self {
            allowed_origins,
            allow_credentials: false,
        }
    }

    /// Advertise `Access-Control-Allow-Credentials: true` (builder). No effect unless an allow-list is
    /// set — credentials with a wildcard origin are invalid per the Fetch standard and never emitted.
    #[must_use]
    pub fn with_credentials(mut self, allow: bool) -> Self {
        self.allow_credentials = allow;
        self
    }

    /// Builds the `tower-http` [`CorsLayer`] for this policy. With no allow-list, the layer carries
    /// no `allow_origin`, so it never emits `Access-Control-Allow-Origin` (fail-closed).
    fn into_layer(self) -> CorsLayer {
        let layer = CorsLayer::new()
            .allow_methods([Method::GET, Method::POST, Method::DELETE])
            .allow_headers([AUTHORIZATION, CONTENT_TYPE, ACCEPT]);
        if self.allowed_origins.is_empty() {
            // Same-origin only: do NOT set allow_origin → no ACAO header at all.
            layer
        } else {
            let layer = layer.allow_origin(AllowOrigin::list(self.allowed_origins));
            // Credentials only ever paired with an explicit allow-list (never a wildcard).
            if self.allow_credentials {
                layer.allow_credentials(true)
            } else {
                layer
            }
        }
    }
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
    /// The CORS policy (rmp #186). Defaults to **fail-closed** same-origin only; the server configures
    /// an allow-list via [`with_cors`](Self::with_cors).
    cors: CorsConfig,
    /// The per-account failed-login throttle (rmp #458) consulted by the [`login`] handler **before**
    /// the expensive Argon2 verification. Defaults to a **disabled** throttle (every attempt allowed)
    /// — the server enables it with configured limits via [`with_auth_throttle`](Self::with_auth_throttle).
    /// Shared (`Arc`) because the bucket map is process-wide state, behind an internal `std::sync::Mutex`
    /// whose critical section never spans an `.await`.
    auth_throttle: Arc<AuthThrottle>,
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
            cors: self.cors.clone(),
            auth_throttle: Arc::clone(&self.auth_throttle),
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
            // Fail-closed by default (rmp #186): no cross-origin sharing unless the server opts in.
            cors: CorsConfig::default(),
            // Disabled by default: the login throttle's limits are a deployment policy, so the server
            // enables it via `with_auth_throttle`. A disabled throttle allows every attempt (the
            // tests, and any in-process embedding that does not configure one, are unaffected).
            auth_throttle: Arc::new(AuthThrottle::disabled()),
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

    /// Sets the CORS policy (rmp #186). The default is fail-closed same-origin only; the server passes
    /// a configured allow-list here. Returns `self` for chaining at construction.
    #[must_use]
    pub fn with_cors(mut self, cors: CorsConfig) -> Self {
        self.cors = cors;
        self
    }

    /// Wires the per-account failed-login throttle (rmp #458) the [`login`] handler consults before
    /// Argon2. The default is a **disabled** throttle (every attempt allowed); the server passes a
    /// configured, enabled [`AuthThrottle`] here. Returns `self` for chaining at construction.
    #[must_use]
    pub fn with_auth_throttle(mut self, throttle: Arc<AuthThrottle>) -> Self {
        self.auth_throttle = throttle;
        self
    }
}

// Clock accessors live in a non-`'static` block so the request helpers (`<E: RestEngine>`) can call
// them without an unnecessary `'static` bound (only `new`'s `Arc<E>` storage needs `'static`).
impl<E: RestEngine> AppState<E> {
    /// The current **monotonic** clock value in nanoseconds — the timeline transaction-idle expiry
    /// (rmp #389) is measured against. Never decreases (rmp #395).
    fn now_nanos(&self) -> u64 {
        self.clock.now_nanos()
    }

    /// The JWT validity clock (`now_unix_secs`) — an **absolute** wall-clock timestamp (`04 §8.4`: the
    /// server derives `now_unix_secs` from its production `Clock`). Reads
    /// [`now_unix_nanos`](Clock::now_unix_nanos), the wall-clock timeline, NOT the monotonic
    /// `now_nanos` used for transaction-idle expiry (rmp #395 — never measure absolute time on the
    /// monotonic timeline, never measure an interval on the wall clock).
    fn now_unix_secs(&self) -> u64 {
        self.clock.now_unix_nanos() / NANOS_PER_SEC
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
pub fn router<E: RestEngine + Send + Sync + 'static>(state: AppState<E>) -> Router
where
    // The incremental streaming egress (rmp #475) drains the engine's `ResultStream` on a
    // `spawn_blocking` producer, so the stream must cross to that thread. The production
    // `RestEngineAdapter::Stream` (a channel receiver + admission permit) and every test stream are
    // already `Send`; the deterministic VOPR engine (`!Send`) never builds a `router` — it drives
    // the synchronous `execute_autocommit` core directly — so this bound does not reach it.
    E::Stream: Send,
{
    // Take the configured CORS policy out of the state before it is moved into the router; the policy
    // is a layer-construction input, not per-request state.
    let cors_layer = state.cors.clone().into_layer();
    Router::new()
        .route("/openapi.json", get(openapi_doc))
        // The authentication entry point (rmp #499): UNAUTHENTICATED by design — it mints the very
        // Bearer token the other routes require, so it does not (and must not) go through `authenticate`.
        .route("/auth/login", post(login::<E>))
        .route("/db/{db}/tx", post(begin::<E>))
        .route("/db/{db}/tx/commit", post(auto_commit::<E>))
        .route("/db/{db}/graph", post(graph_viz::<E>))
        .route("/db/{db}/query/columnar", post(query_columnar::<E>))
        .route(
            "/db/{db}/tx/{id}",
            post(run_in_tx::<E>).delete(rollback_tx::<E>),
        )
        .route("/db/{db}/tx/{id}/commit", post(commit_tx::<E>))
        // Bound the buffered request body explicitly (`413` past the cap) so untrusted input cannot
        // exhaust server memory. Replaces axum's implicit, un-auditable 2 MiB default.
        .layer(DefaultBodyLimit::max(MAX_REQUEST_BODY_BYTES))
        // HTTP niceties (`04 §8.2`): a **fail-closed, allow-list** CORS policy (rmp #186 — never
        // `permissive()`/wildcard) + gzip response compression, wired for production use. The CORS
        // policy comes from `AppState::with_cors` (default: same-origin only).
        .layer(CompressionLayer::new())
        .layer(cors_layer)
        .with_state(state)
}

// =============================== handlers ======================================================

/// `GET /openapi.json` → the static OpenAPI 3.1 document (`04 §8.2`). Unauthenticated (a public API
/// description).
async fn openapi_doc() -> Response {
    Built::json(StatusCode::OK, &crate::openapi::document()).into_response()
}

/// `POST /auth/login` → exchange a username + password for a short-lived Bearer JWT (rmp #499).
///
/// This is the REST **authentication entry point**, so it is the one route that is **not** itself
/// Bearer-authenticated and does **not** participate in the idempotency cache: an honest client (curl,
/// a Go `net/http` program, …) presents its credentials and receives a token to use on every other
/// route, without ever needing the server's JWT signing secret. The token is minted through the
/// [`AuthProvider`] seam ([`AuthProvider::issue_token`]), so the router stays free of any token/crypto
/// logic — the live server backs the seam with its read-locked security catalog.
///
/// # Flow (the order is security-load-bearing)
///
/// 1. **Decode** the [`LoginRequest`] (JSON or CBOR, content-negotiated). A malformed body, a missing
///    field, or an undecodable `Content-Type` is a `400`/`415` problem+json *before* any auth work.
/// 2. **Throttle gate** (rmp #458): the per-account failed-login bucket is consulted **before** the
///    expensive Argon2 verification, keyed by the submitted `username`. An exhausted bucket is a
///    retriable **`429`** (and an audited failure) — this blunts targeted online password-guessing and
///    the per-account Argon2 CPU-exhaustion vector. (Cross-account flooding is independently bounded by
///    the listener's per-source-IP connection cap + pre-auth deadline, rmp #478; the router layer has no
///    peer IP, so the throttle keys by account only — see the type docs for [`AuthThrottle`].)
/// 3. **Verify** the password ([`AuthProvider::authenticate_password`], constant-time Argon2). On
///    failure → debit the throttle, audit the failure, and return a **uniform `401`**
///    ([`Problem::invalid_credentials`]): the *same* message for a wrong password and an unknown user,
///    so the endpoint is never a user-existence oracle (CWE-204). On success the throttle is **not**
///    debited (a correct credential never counts against a legitimate client's rate).
/// 4. **Issue** the token for the resolved principal, valid for [`DEFAULT_LOGIN_TOKEN_TTL_SECS`] from
///    the server's `now_unix_secs`, audit the success, and return `200` with a [`LoginResponse`].
async fn login<E: RestEngine + 'static>(
    State(state): State<AppState<E>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    // (1) Decode before any auth/throttle work, so a bad body is a clean 400/415.
    let req: LoginRequest = match decode_body(&headers, &body) {
        Ok(r) => r,
        Err(p) => return Built::from(p).into_response(),
    };

    // (2) Throttle gate BEFORE Argon2 (rmp #458), keyed by the submitted account. The injected clock
    // (monotonic timeline) drives the token bucket — never the wall clock — so the window is
    // deterministic in tests. The lock inside `permit_attempt` is a tiny, non-`await` critical section.
    if !state
        .auth_throttle
        .permit_attempt(&req.username, state.clock.as_ref())
    {
        notify_auth_failure(&state, "login attempt throttled");
        return Built::from(Problem::too_many_login_attempts(
            "too many failed login attempts for this account; retry after the throttle window refills",
        ))
        .into_response();
    }

    // (3) Verify the credential. Any failure is a UNIFORM 401 with no user-exists oracle.
    match state
        .auth
        .authenticate_password(&req.username, &req.password)
    {
        Ok(user) => {
            // (4) Success: do NOT debit the throttle. Mint a token for the resolved principal.
            let now = state.now_unix_secs();
            let token = match state
                .auth
                .issue_token(&user, now, DEFAULT_LOGIN_TOKEN_TTL_SECS)
            {
                Ok(t) => t,
                // Post-authentication, this is essentially unreachable (the user just authenticated and
                // the signing secret was validated at startup); a token-issue failure here can only be a
                // race where the user was dropped between verify and issue, or an encoding fault. Surface
                // it through the same auth-error mapping the rest of the surface uses.
                Err(e) => return Built::from(Problem::from_auth_error(&e)).into_response(),
            };
            if let Some(observer) = &state.auth_observer {
                observer.on_auth_success(&user);
            }
            serializable_built(
                &headers,
                StatusCode::OK,
                &LoginResponse {
                    token,
                    token_type: "Bearer".to_owned(),
                    expires_at_unix_secs: now + DEFAULT_LOGIN_TOKEN_TTL_SECS,
                },
            )
            .into_response()
        }
        Err(_e) => {
            // Failure: debit the per-account bucket (this attempt counts toward the throttle), audit
            // it, and return the uniform 401 — identical for a wrong password and an unknown user.
            state
                .auth_throttle
                .note_failure(&req.username, state.clock.as_ref());
            notify_auth_failure(&state, "login authentication failed");
            Built::from(Problem::invalid_credentials()).into_response()
        }
    }
}

/// `POST /db/{db}/tx` → open an explicit transaction (`04 §8.2`, `06 §4`).
async fn begin<E: RestEngine + 'static>(
    State(state): State<AppState<E>>,
    Path(db): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    with_idempotency(&state, &headers, |state, identity| {
        let req = decode_request(&headers, &body)?;
        // `06 §4`: validate access_mode; an invalid value is a 400 and the tx is NOT opened.
        let mode = parse_access_mode(&req.access_mode).map_err(|bad| {
            Problem::bad_request(format!(
                "invalid access_mode {bad}: expected \"READ\" or \"WRITE\""
            ))
        })?;
        authorize_mode(state, identity, &db, mode)?;

        let handle = state
            .engine
            .begin(
                &db,
                mode,
                TxOrigin {
                    principal: identity,
                    explicit: true,
                },
            )
            .map_err(|e| Problem::from_graphus_error(&e))?;
        let now = state.now_nanos();
        // Bind the transaction to its authenticated opener (rmp #390): only `identity` may touch,
        // run, commit or roll it back; another principal targeting this id gets a 404.
        //
        // The capped open path (rmp #448, CWE-770) refuses past `max_open_transactions` with a
        // retriable `429`, bounding the number of GC-watermark-pinning snapshots one principal can hold.
        // The engine transaction was already opened above, so on a cap rejection we MUST roll it back
        // here — otherwise the engine-side transaction (and its pinned snapshot) would leak with no
        // registry entry to ever reap it. `rollback` is idempotent, so this is always safe.
        let (id, expires_at_nanos) = match state.registry.try_open(handle, identity, &db, mode, now)
        {
            Ok(opened) => opened,
            Err(too_many) => {
                let _ = state.engine.rollback(handle);
                return Err(Problem::too_many_transactions(too_many.to_string()));
            }
        };

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
async fn run_in_tx<E: RestEngine + Send + Sync + 'static>(
    State(state): State<AppState<E>>,
    Path((db, id)): Path<(String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> Response
where
    E::Stream: Send,
{
    // The streaming path cannot be uniformly buffered for the idempotency cache, and `run` is not a
    // finalising endpoint, so it is handled directly (not via `with_idempotency`).
    let outcome = (|| {
        let identity = authenticate(&state, &headers)?;
        let req = decode_request(&headers, &body)?;
        let now = state.now_nanos();
        // Touch, bound to the authenticated principal (rmp #390): refresh the deadline, or 404 if
        // expired OR owned by another principal (no cross-principal adoption). The engine seam applies
        // the OPENER's fine-grained RBAC, so this ownership check is what stops a hijack.
        let Some(info) = state
            .registry
            .touch(&id, &identity, now, state.engine.as_ref())
        else {
            return Err(Problem::unknown_transaction(&id));
        };
        authorize_mode(&state, &identity, &db, info.mode)?;
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
async fn commit_tx<E: RestEngine + Send + Sync + 'static>(
    State(state): State<AppState<E>>,
    Path((_db, id)): Path<(String, String)>,
    headers: HeaderMap,
    body: Bytes,
) -> Response
where
    E::Stream: Send,
{
    // Authenticate BEFORE any idempotency replay (rmp #182): an anonymous caller never reaches the
    // cache, and the replay below is scoped to this principal so it can only return this user's body.
    let identity = match authenticate(&state, &headers) {
        Ok(id) => id,
        Err(p) => return Built::from(p).into_response(),
    };
    // If idempotency-cached for this principal, replay before any side effect.
    if let Some(replay) = replay_idempotent(&state, &headers, &identity) {
        return replay.into_response();
    }

    let outcome: Result<(RunRequest, TxHandle), Problem> = (|| {
        let req = decode_request(&headers, &body)?;
        let now = state.now_nanos();
        // Reap first if expired (so a long-idle commit fails as gone rather than committing stale).
        // Bound to the authenticated principal (rmp #390): a commit targeting another user's tx 404s
        // and leaves the victim's transaction intact.
        if state
            .registry
            .touch(&id, &identity, now, state.engine.as_ref())
            .is_none()
        {
            return Err(Problem::unknown_transaction(&id));
        }
        let Some((handle, db, mode)) = state.registry.take(&id, &identity) else {
            return Err(Problem::unknown_transaction(&id));
        };
        if let Err(p) = authorize_mode(&state, &identity, &db, mode) {
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
    if let Some(framing) = stream_framing(wire, &req.statements, &headers) {
        return stream_single_statement(
            &state,
            framing,
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
    cache_and_respond(&state, &headers, &identity, built)
}

/// `DELETE /db/{db}/tx/{id}` → roll back the open transaction (`04 §8.2`).
async fn rollback_tx<E: RestEngine + 'static>(
    State(state): State<AppState<E>>,
    Path((_db, id)): Path<(String, String)>,
    headers: HeaderMap,
) -> Response {
    let built = (|| {
        let identity = authenticate(&state, &headers)?;
        // Bound to the authenticated principal (rmp #390): a DELETE targeting another user's tx 404s
        // and leaves the victim's transaction intact.
        let Some((handle, db, mode)) = state.registry.take(&id, &identity) else {
            return Err(Problem::unknown_transaction(&id));
        };
        if let Err(p) = authorize_mode(&state, &identity, &db, mode) {
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
async fn auto_commit<E: RestEngine + Send + Sync + 'static>(
    State(state): State<AppState<E>>,
    Path(db): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Response
where
    E::Stream: Send,
{
    // Authenticate BEFORE any idempotency replay (rmp #182): anonymous callers never reach the cache,
    // and the replay below is scoped to this principal.
    let identity = match authenticate(&state, &headers) {
        Ok(id) => id,
        Err(p) => return Built::from(p).into_response(),
    };
    if let Some(replay) = replay_idempotent(&state, &headers, &identity) {
        return replay.into_response();
    }

    let outcome: Result<(RunRequest, TxHandle), Problem> = (|| {
        let req = decode_request(&headers, &body)?;
        let mode = parse_access_mode(&req.access_mode).map_err(|bad| {
            Problem::bad_request(format!(
                "invalid access_mode {bad}: expected \"READ\" or \"WRITE\""
            ))
        })?;
        authorize_mode(&state, &identity, &db, mode)?;
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
    if let Some(framing) = stream_framing(wire, &req.statements, &headers) {
        return stream_single_statement(
            &state,
            framing,
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
    cache_and_respond(&state, &headers, &identity, built)
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
        authorize_mode(&state, &identity, &db, AccessMode::Read)?;
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

// =============================== analytical columnar channel (rmp #334) =======================

/// `POST /db/{db}/query/columnar` → run a read query and return its result encoded **column-wise**
/// as the analytical `gcol-result` body (rmp #334), `Content-Type: application/x-graphus-columnar`.
///
/// This is the **analytical / export** channel, deliberately separate from the row-wise
/// JSON/CBOR/NDJSON paths and the inviolable Bolt/PackStream OLTP path. The rows of the statement
/// batch are transposed into columns and each column is encoded with the type-appropriate native
/// [`graphus_columnar`] codec (no Arrow dependency) plus a present/null bitmap — materially smaller
/// on a large, low-cardinality, wide result than the repeated-key JSON body, while reusing the exact
/// strict-Jolt codec for any structural / heterogeneous / non-scalar column (lossless). See
/// [`crate::columnar`] for the wire format and the codec-selection table.
///
/// # Behaviour
///
/// Like [`graph_viz`], this is a **read** surface: the access mode is **forced to `READ`** (an
/// analytical/export query is a read; any `access_mode` in the body is ignored), all statements run
/// inside one auto-managed `READ` transaction, the transaction is committed on success (a read commit
/// has no side effects) and rolled back on the first statement error (an RFC 9457 problem is
/// returned, `06 §3.3`). The batch is treated as **one tabular result**: the column names are the
/// first statement's `fields`, and every statement's rows are appended (the common case is a single
/// analytical query; a same-schema paged batch also composes). Authentication, the `{db}` selection,
/// and fine-grained RBAC are honoured **identically** to [`auto_commit`]/[`graph_viz`] — an
/// RBAC-hidden node/relationship/property is already absent from the resolved cells, so the columnar
/// body inherits that filtering for free.
///
/// # Why no content negotiation on the transactional endpoints
///
/// The OLTP path is inviolable, so the columnar encoding is exposed only on its **own** endpoint
/// rather than as an `Accept` on `…/tx/commit` — a transactional client can never accidentally trip
/// into the analytical encoding, and the analytical intent (a large buffered result) is explicit in
/// the URL. A client still signals the format by posting here (or, equivalently, the response carries
/// the [`crate::columnar::GCOL_RESULT_MEDIA_TYPE`] `Content-Type`).
async fn query_columnar<E: RestEngine + 'static>(
    State(state): State<AppState<E>>,
    Path(db): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let outcome: Result<(RunRequest, TxHandle), Problem> = (|| {
        let identity = authenticate(&state, &headers)?;
        let req = decode_request(&headers, &body)?;
        // An analytical/export query is always a READ (the safe, spec-consistent default). Any
        // `access_mode` in the body is ignored — a write is rejected by the engine as in any read tx.
        authorize_mode(&state, &identity, &db, AccessMode::Read)?;
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

    encode_columnar_result(&state, handle, &req.statements)
        .unwrap_or_else(Built::problem)
        .into_response()
}

/// Runs `statements` in the (read) transaction `handle`, accumulating every row of every statement
/// into one tabular result (column names from the first statement), then commits and returns the
/// `gcol-result` columnar body (rmp #334). On the first statement/runtime error the transaction is
/// rolled back and the error is surfaced as a [`Problem`] (no partial result — `06 §3.3`).
fn encode_columnar_result<E: RestEngine>(
    state: &AppState<E>,
    handle: TxHandle,
    statements: &[Statement],
) -> Result<Built, Problem> {
    let mut fields: Vec<String> = Vec::new();
    let mut rows: Vec<crate::engine::Row> = Vec::new();
    // The summary of the **last** statement (matching how a single-statement analytical query reads);
    // defaults to an empty read summary for an empty batch.
    let mut summary = RunSummary::default();

    for (idx, stmt) in statements.iter().enumerate() {
        let params = match bind_parameters(stmt) {
            Ok(p) => p,
            Err(e) => {
                let _ = state.engine.rollback(handle);
                return Err(Problem::from_codec_error(&e));
            }
        };
        let mut stream = match state.engine.run(handle, &stmt.statement, params) {
            Ok(s) => s,
            Err(e) => {
                let _ = state.engine.rollback(handle);
                return Err(Problem::from_graphus_error(&e));
            }
        };
        if idx == 0 {
            fields = stream.fields().to_vec();
        }
        loop {
            match stream.next_row() {
                Ok(Some(row)) => rows.push(row),
                Ok(None) => break,
                Err(e) => {
                    let _ = state.engine.rollback(handle);
                    return Err(Problem::from_graphus_error(&e));
                }
            }
        }
        summary = stream.summary();
    }

    // A read transaction commit has no side effects; do it so the engine releases the handle.
    state
        .engine
        .commit(handle)
        .map_err(|e| Problem::from_graphus_error(&e))?;

    let summary_json = encode_summary(&summary);
    let body = crate::columnar::encode_result(&fields, &rows, &summary_json);
    Ok(Built::new(
        StatusCode::OK,
        crate::columnar::GCOL_RESULT_MEDIA_TYPE,
        body,
    ))
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
/// converts to a `Response`. Used by `run_in_tx` (which does not idempotency-cache, so streaming is
/// chosen for a single-statement NDJSON or JSON result with no key check needed).
fn run_statements<E: RestEngine + Send + Sync + 'static>(
    state: &AppState<E>,
    headers: &HeaderMap,
    handle: TxHandle,
    statements: &[Statement],
    finalise: Finalise,
) -> Response
where
    E::Stream: Send,
{
    let wire = match response_wire(header_str(headers, &ACCEPT)) {
        Some(w) => w,
        None => {
            return Built::from(Problem::not_acceptable("no acceptable representation"))
                .into_response();
        }
    };
    if let Some(framing) = stream_framing(wire, statements, headers) {
        return stream_single_statement(state, framing, handle, &statements[0], finalise);
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
    run_statements_buffered(
        state,
        &headers,
        handle,
        statements,
        Finalise::Commit,
        accept,
    )
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

// =============================== incremental streaming egress (rmp #475) =======================

/// The depth of the bounded egress channel backing a streamed body. Each slot holds one already-
/// serialized chunk (≈ [`STREAM_FLUSH_BYTES`]); a full channel throttles the producer (backpressure,
/// `04 §9.3`). Small on purpose — the goal is a flat footprint, not a deep buffer.
const STREAM_CHANNEL_CAP: usize = 8;

/// The producer batches serialized rows into a reusable buffer and flushes a chunk once it reaches
/// this size (16 KiB), amortising the per-row channel overhead over many rows while keeping the
/// in-flight bytes bounded at ≈ `(STREAM_CHANNEL_CAP + 1) * STREAM_FLUSH_BYTES` — **independent of
/// the result-set size**.
const STREAM_FLUSH_BYTES: usize = 16 * 1024;

/// Which wire framing a streamed single-statement result uses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Framing {
    /// NDJSON: a `fields` line, one `row` line per row, then a `summary` line (`application/x-ndjson`).
    Ndjson,
    /// The [`RunResponse`] envelope, streamed element-by-element, **byte-identical** to the buffered
    /// serializer (`application/json`).
    Json,
}

/// Decides whether a `run`/commit response should be **streamed** (and in which framing) rather than
/// buffered: only a **single-statement** NDJSON or JSON result streams. JSON additionally requires no
/// `Idempotency-Key` (a keyed committing request keeps its exact buffered-and-cached behaviour;
/// `run_in_tx` passes no key, so its single-statement JSON always streams). CBOR, multi-statement,
/// and empty batches return `None` (buffered).
fn stream_framing(wire: Wire, statements: &[Statement], headers: &HeaderMap) -> Option<Framing> {
    if statements.len() != 1 {
        return None;
    }
    match wire {
        Wire::Ndjson => Some(Framing::Ndjson),
        Wire::Json if headers.get(IDEMPOTENCY_KEY).is_none() => Some(Framing::Json),
        _ => None,
    }
}

impl Framing {
    /// The `Content-Type` the streamed body is sent with.
    fn content_type(self) -> &'static str {
        match self {
            Framing::Ndjson => "application/x-ndjson",
            Framing::Json => "application/json",
        }
    }

    /// Writes the leading bytes (before any row): NDJSON's `fields` line, or JSON's
    /// `{"results":[{"fields":<fields>,"data":[` envelope opener.
    fn prefix(self, fields: &[String], out: &mut Vec<u8>) {
        match self {
            Framing::Ndjson => push_ndjson_line(out, &json!({ "fields": fields })),
            Framing::Json => {
                out.extend_from_slice(b"{\"results\":[{\"fields\":");
                append_json(out, fields);
                out.extend_from_slice(b",\"data\":[");
            }
        }
    }

    /// Writes one row: NDJSON's `{"row":[…]}` line, or the next JSON `data` array element
    /// (comma-separated, exactly as `serde_json` serializes a `Vec<Json>`).
    fn row(self, cells: &[crate::restvalue::RestValue], first: bool, out: &mut Vec<u8>) {
        let encoded: Vec<Json> = cells
            .iter()
            .map(crate::restvalue::restvalue_to_jolt)
            .collect();
        match self {
            Framing::Ndjson => push_ndjson_line(out, &json!({ "row": encoded })),
            Framing::Json => {
                if !first {
                    out.push(b',');
                }
                append_json(out, &Json::Array(encoded));
            }
        }
    }

    /// Writes the trailing bytes after a fully-drained, committed result: NDJSON's `summary` line, or
    /// the JSON envelope close `],"summary":<summary>}]` followed by the `RunResponse` tail (`}` for a
    /// closed transaction, or `,"id":…,"expires_at_nanos":…}` while it stays open). The bytes match
    /// `serde_json::to_vec(&RunResponse { … })` exactly.
    fn success_tail(self, summary: &Json, finalise: &Finalise, out: &mut Vec<u8>) {
        match self {
            Framing::Ndjson => push_ndjson_line(out, &json!({ "summary": summary })),
            Framing::Json => {
                out.extend_from_slice(b"],\"summary\":");
                append_json(out, summary);
                out.extend_from_slice(b"}]");
                match finalise {
                    Finalise::Commit => out.push(b'}'),
                    Finalise::KeepOpen {
                        id,
                        expires_at_nanos,
                    } => {
                        out.extend_from_slice(b",\"id\":");
                        append_json(out, &Json::String(id.clone()));
                        out.extend_from_slice(b",\"expires_at_nanos\":");
                        out.extend_from_slice(expires_at_nanos.to_string().as_bytes());
                        out.push(b'}');
                    }
                }
            }
        }
    }

    /// Surfaces an error that arrives **after** the `200` status and the first bytes are on the wire
    /// (a mid-stream row error, or a post-drain commit failure). NDJSON appends a trailing problem
    /// line — well-formed NDJSON, the Bolt-`FAILURE`-after-records analogue — and returns `true` (the
    /// body ends normally). JSON cannot retroactively turn a `200` array into a problem document, so
    /// it returns `false`: the caller aborts the body as a transport error and the client observes an
    /// incomplete JSON document (and, crucially, the transaction was rolled back — no partial commit).
    fn mid_error(self, problem: &Problem, out: &mut Vec<u8>) -> bool {
        match self {
            Framing::Ndjson => {
                push_ndjson_line(out, &serde_json::to_value(problem).unwrap_or(Json::Null));
                true
            }
            Framing::Json => false,
        }
    }
}

/// The producer's write end: batches serialized bytes and `blocking_send`s a chunk once it reaches
/// [`STREAM_FLUSH_BYTES`]. Every send is **blocking** — the producer runs on a `spawn_blocking`
/// thread, so this never parks a runtime worker (`04 §9.1`). A send error means the consumer (client)
/// dropped the body; the producer then stops and cleans up.
struct ChunkSink {
    tx: tokio::sync::mpsc::Sender<Result<Bytes, std::io::Error>>,
    buf: Vec<u8>,
}

impl ChunkSink {
    fn new(tx: tokio::sync::mpsc::Sender<Result<Bytes, std::io::Error>>) -> Self {
        Self {
            tx,
            buf: Vec::with_capacity(STREAM_FLUSH_BYTES + 1024),
        }
    }

    /// Flush a chunk if the buffer has grown past the threshold. `Err(())` ⇒ the consumer is gone.
    fn maybe_flush(&mut self) -> Result<(), ()> {
        if self.buf.len() >= STREAM_FLUSH_BYTES {
            self.flush()
        } else {
            Ok(())
        }
    }

    /// Send whatever is buffered as one chunk (a no-op when empty). `Err(())` ⇒ the consumer is gone.
    fn flush(&mut self) -> Result<(), ()> {
        if self.buf.is_empty() {
            return Ok(());
        }
        let chunk = Bytes::from(std::mem::take(&mut self.buf));
        self.tx.blocking_send(Ok(chunk)).map_err(|_| ())
    }

    /// Terminate the body as a transport error — the JSON mid-stream failure signal. Flushes any
    /// buffered bytes, then sends an `Err` so `Body::from_stream` aborts the response (the client sees
    /// an incomplete document rather than a falsely-complete one).
    fn abort(&mut self) {
        let _ = self.flush();
        let _ = self.tx.blocking_send(Err(std::io::Error::other(
            "result stream aborted by a mid-stream error",
        )));
    }
}

/// The streaming response body: a [`futures_core::Stream`] over the bounded egress channel's receive
/// end. Hyper polls it on a runtime worker (the producer feeds it from a `spawn_blocking` thread), so
/// each chunk is written to the socket and dropped as it arrives — bounded memory, no runtime-worker
/// blocking.
struct ChannelBody {
    rx: tokio::sync::mpsc::Receiver<Result<Bytes, std::io::Error>>,
}

impl futures_core::Stream for ChannelBody {
    type Item = Result<Bytes, std::io::Error>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        // `ChannelBody`'s only field is a `Receiver`, which is `Unpin`, so projecting to `&mut self`
        // through `Pin::get_mut` is sound.
        self.get_mut().rx.poll_recv(cx)
    }
}

/// Runs `stmt` and streams its single result incrementally in `framing` with **bounded server
/// memory** (rmp #475). A statement error raised **before** the first byte (compile / immediate
/// runtime / READ-tx rejection) still maps to the correct problem+json status and rolls back; only
/// once rows begin streaming does an error become an in-band, post-`200` signal (see
/// [`produce_stream`]). The COMMIT (for [`Finalise::Commit`]) runs **only after** the result has
/// fully drained.
fn stream_single_statement<E>(
    state: &AppState<E>,
    framing: Framing,
    handle: TxHandle,
    stmt: &Statement,
    finalise: Finalise,
) -> Response
where
    E: RestEngine + Send + Sync + 'static,
    E::Stream: Send,
{
    let params = match bind_parameters(stmt) {
        Ok(p) => p,
        Err(e) => return Built::from(Problem::from_codec_error(&e)).into_response(),
    };
    // The error path BEFORE the first byte keeps the exact problem+json status (e.g. a write in a
    // READ tx → 409): the response has not begun, so it is a normal buffered error, unchanged.
    let stream = match state.engine.run(handle, &stmt.statement, params) {
        Ok(s) => s,
        Err(e) => {
            let _ = state.engine.rollback(handle);
            return Built::from(Problem::from_graphus_error(&e)).into_response();
        }
    };

    let (tx, rx) = tokio::sync::mpsc::channel::<Result<Bytes, std::io::Error>>(STREAM_CHANNEL_CAP);
    let engine = Arc::clone(&state.engine);
    // Drain the synchronous `ResultStream` OFF the runtime: `next_row` blocks the engine's bounded
    // egress channel, which `04 §9.1` forbids on a runtime worker. The producer is bound to the
    // response body's lifetime — when the body is fully read or dropped, the receiver drops and the
    // producer's next `blocking_send` returns `Err`, so it stops and cleans up (no orphan task).
    tokio::task::spawn_blocking(move || {
        produce_stream(
            engine.as_ref(),
            framing,
            handle,
            stream,
            finalise,
            ChunkSink::new(tx),
        );
    });

    streaming_response(
        framing.content_type(),
        Body::from_stream(ChannelBody { rx }),
    )
}

/// The streamed-egress producer (runs on a `spawn_blocking` thread). Drains `stream` row by row,
/// serializing each into `sink` (flushed in bounded chunks), then finalises:
///
/// - **clean drain** → COMMIT (for [`Finalise::Commit`]) *after* the full drain, then the trailing
///   summary/closing bytes — the commit-after-drain ACID order (mirrors Bolt's auto-commit, which
///   finalises at the trailing `SUCCESS`);
/// - **row error mid-stream** → roll back (no partial commit) and surface in-band (NDJSON problem
///   line / JSON transport-abort) — the post-`200` `06 §3.3` case;
/// - **client disconnect** (a send fails) → drain the engine egress and, for a `Commit`, roll back
///   the owned handle so no engine transaction leaks (a `KeepOpen` handle stays registered for the
///   inactivity sweep — the same lifetime it would have on a buffered response);
/// - **commit failure** after a clean drain → roll back and surface in-band (the Bolt
///   `FAILURE`-after-records analogue).
fn produce_stream<E: RestEngine>(
    engine: &E,
    framing: Framing,
    handle: TxHandle,
    mut stream: E::Stream,
    finalise: Finalise,
    mut sink: ChunkSink,
) {
    framing.prefix(stream.fields(), &mut sink.buf);
    let mut first = true;
    loop {
        match stream.next_row() {
            Ok(Some(row)) => {
                framing.row(&row, first, &mut sink.buf);
                first = false;
                drop(row); // free the row before pulling the next — the memory-bounding step
                if sink.maybe_flush().is_err() {
                    // Client dropped the body mid-stream: drain the engine egress (so its bounded
                    // `send` unblocks) and, for an owned committing handle, roll back to avoid a leak.
                    drop(stream);
                    if matches!(finalise, Finalise::Commit) {
                        let _ = engine.rollback(handle);
                    }
                    return;
                }
            }
            Ok(None) => break,
            Err(e) => {
                // A runtime error after some rows already streamed (`06 §3.3`): roll back (no partial
                // commit), surface in-band, and stop.
                let _ = engine.rollback(handle);
                emit_terminal_error(framing, &mut sink, &Problem::from_graphus_error(&e));
                return;
            }
        }
    }

    // Clean drain. Commit-after-drain, then the trailing summary/closing bytes.
    let summary = encode_summary(&stream.summary());
    if let Finalise::Commit = finalise {
        if let Err(e) = engine.commit(handle) {
            // Commit failed after the rows shipped: roll back and surface in-band (the status is
            // already `200`, so this cannot become a problem+json status — see [`Framing::mid_error`]).
            let _ = engine.rollback(handle);
            emit_terminal_error(framing, &mut sink, &Problem::from_graphus_error(&e));
            return;
        }
    }
    framing.success_tail(&summary, &finalise, &mut sink.buf);
    let _ = sink.flush();
    // `sink` drops here → the sender drops → the body sees EOF.
}

/// Emits a post-`200` terminal error (mid-stream row error or commit failure) in the right framing,
/// then flushes/aborts the body. NDJSON appends a trailing problem line and flushes; JSON aborts the
/// body as a transport error.
fn emit_terminal_error(framing: Framing, sink: &mut ChunkSink, problem: &Problem) {
    if framing.mid_error(problem, &mut sink.buf) {
        let _ = sink.flush();
    } else {
        sink.abort();
    }
}

/// Builds a streamed `200 OK` response carrying `body` with `content_type` and the **same**
/// defence-in-depth security headers [`Built::into_response`] injects (rmp #188): `nosniff`,
/// `Cache-Control: no-store`, `Referrer-Policy: no-referrer`. Kept in lock-step with
/// [`Built::into_response`] so a streamed result is indistinguishable from a buffered one at the
/// header level.
fn streaming_response(content_type: &str, body: Body) -> Response {
    Response::builder()
        .status(StatusCode::OK)
        .header(CONTENT_TYPE, content_type)
        .header(X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"))
        .header(CACHE_CONTROL, HeaderValue::from_static("no-store"))
        .header(REFERRER_POLICY, HeaderValue::from_static("no-referrer"))
        .body(body)
        .unwrap_or_else(|_| {
            let mut resp = Response::new(Body::empty());
            *resp.status_mut() = StatusCode::INTERNAL_SERVER_ERROR;
            resp
        })
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
/// The coarse, **fail-fast** transaction-mode gate: before a transaction is opened on `db`, the
/// principal must hold at least `Read` (for a `READ` transaction) or `Write` (for a `WRITE`
/// transaction) **scoped to that database**.
///
/// The privilege is checked against [`Privilege::on_graph`] — the *target database's* graph scope —
/// **not** the server-wide [`graphus_auth::Resource::Database`] scope. This is what makes per-tenant
/// (graph-scoped) grants usable over REST: a principal granted `WRITE ON GRAPH tenant_a` can open a
/// `WRITE` transaction on `/db/tenant_a/...` but not on `/db/tenant_b/...`. A broader server-wide
/// `Database` grant (e.g. the bootstrap `readwrite` role) still satisfies this through the RBAC
/// containment rule (`Database ⊇ Graph(db)`), so existing deployments are unaffected.
///
/// This is only the coarse "may you open *any* transaction here" gate; the engine's fine-grained,
/// per-element RBAC (label/relationship/property filtering) still applies to every statement run
/// inside the transaction. The two compose: this rejects a principal with no access to the database
/// up front (a fast, cheap deny), and the fine-grained layer filters what a principal *with* access
/// may actually see and change.
fn authorize_mode<E: RestEngine>(
    state: &AppState<E>,
    identity: &str,
    db: &str,
    mode: AccessMode,
) -> Result<(), Problem> {
    let action = match mode {
        AccessMode::Read => Action::Read,
        AccessMode::Write => Action::Write,
    };
    state
        .auth
        .require(identity, &Privilege::on_graph(action, db))
        .map_err(|e| Problem::from_auth_error(&e))
}

/// Decodes a request body into any deserializable `T`, honouring `Content-Type` (`415` for an
/// undecodable type) and the recursion-bounded CBOR limit (`04 §8.2`). The shared decode core behind
/// [`decode_request`] (the statement batch) and [`login`] (the [`LoginRequest`]).
///
/// Unlike [`decode_request`], an **empty body is not special-cased**: it is fed to the decoder and so
/// fails for a `T` with required fields (e.g. [`LoginRequest`]) — a missing-field `400`, not a silent
/// default. `decode_request` layers its empty-body-means-default behaviour on top of this.
fn decode_body<T: serde::de::DeserializeOwned>(
    headers: &HeaderMap,
    body: &Bytes,
) -> Result<T, Problem> {
    let decode = request_decode(header_str(headers, &CONTENT_TYPE)).ok_or_else(|| {
        Problem::unsupported_media_type("Content-Type must be application/json or application/cbor")
    })?;
    match decode {
        Decode::Json => serde_json::from_slice::<T>(body).map_err(|e| {
            Problem::from_codec_error(&ValueCodecError::Malformed {
                detail: e.to_string(),
            })
        }),
        // Bound deserialization recursion explicitly (defence-in-depth): a body within the size cap
        // can still nest CBOR arrays/maps deeply enough to overflow the stack, and ciborium's own
        // default limit is implicit. Cap at the same audited depth the typed-value codec enforces
        // (`value::MAX_CBOR_DEPTH`); over-deep input becomes a controlled `Malformed`, never a panic.
        Decode::Cbor => ciborium::de::from_reader_with_recursion_limit::<T, _>(
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

/// Decodes the request body into a [`RunRequest`], honouring `Content-Type` (`415` for an
/// undecodable type) (`04 §8.2`). An empty body is an empty (default) request.
fn decode_request(headers: &HeaderMap, body: &Bytes) -> Result<RunRequest, Problem> {
    if body.is_empty() {
        // An empty body is a valid empty request (every `RunRequest` field defaults), but an
        // undecodable `Content-Type` is still a `415` — validate it before short-circuiting.
        request_decode(header_str(headers, &CONTENT_TYPE)).ok_or_else(|| {
            Problem::unsupported_media_type(
                "Content-Type must be application/json or application/cbor",
            )
        })?;
        return Ok(RunRequest::default());
    }
    decode_body(headers, body)
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
        // Summary counters are plain JSON scalars (`"nodes-created": 1`), not Jolt-typed cells — the
        // Neo4j HTTP API / `docs/rest-api.md` contract a client reads counts from directly (`rmp` #512).
        stats.insert(k.clone(), value::summary_value_to_json(v));
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
    append_json(out, value);
    out.push(b'\n');
}

/// Appends `value` as **compact** JSON to `out`, serialized directly into the buffer (no intermediate
/// `Vec`). A serialize failure — which a well-formed `Value` / `&[String]` cannot trigger (writing to
/// a `Vec` never does I/O) — degrades to `null` so the streaming producer keeps progressing rather
/// than panicking. The bytes are identical to `serde_json::to_vec(value)`, which is what makes the
/// incrementally-streamed JSON envelope byte-for-byte equal to the buffered [`RunResponse`].
fn append_json<T: serde::Serialize + ?Sized>(out: &mut Vec<u8>, value: &T) {
    if serde_json::to_writer(&mut *out, value).is_err() {
        out.extend_from_slice(b"null");
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

/// Runs `f` (a finalising handler body) with `Idempotency-Key` dedup wrapped around it, **after**
/// authentication (rmp #182).
///
/// Security ordering: the request is authenticated **first** — an unauthenticated caller can never
/// reach the idempotency cache, so a cached (authenticated) response is never replayed to an
/// anonymous caller (CWE-306). The cache is then consulted scoped by the **resolved principal**, so a
/// key collision across users misses (CWE-639 IDOR). `f` receives the authenticated `identity` and
/// returns `Result<Built, Problem>`; either is cached so a retry replays the exact first outcome.
fn with_idempotency<E, F>(state: &AppState<E>, headers: &HeaderMap, f: F) -> Response
where
    E: RestEngine,
    F: FnOnce(&AppState<E>, &str) -> Result<Built, Problem>,
{
    // Authenticate BEFORE any replay (rmp #182): an unauthenticated request fails here with 401 and
    // never observes another caller's cached body.
    let identity = match authenticate(state, headers) {
        Ok(id) => id,
        Err(p) => return Built::from(p).into_response(),
    };
    if let Some(replay) = replay_idempotent(state, headers, &identity) {
        return replay.into_response();
    }
    let built = f(state, &identity).unwrap_or_else(Built::problem);
    cache_and_respond(state, headers, &identity, built)
}

/// Caches `built` under the request's `(principal, Idempotency-Key)` (if a key is present) and
/// returns it as a `Response` (rmp #182: principal-scoped; rmp #184: bounded by the registry).
fn cache_and_respond<E: RestEngine>(
    state: &AppState<E>,
    headers: &HeaderMap,
    principal: &str,
    built: Built,
) -> Response {
    if let Some(key) = headers.get(IDEMPOTENCY_KEY).and_then(|v| v.to_str().ok()) {
        state
            .registry
            .store_response(principal, key, state.now_nanos(), built.cached());
    }
    built.into_response()
}

/// If the request carries an `Idempotency-Key` already seen **for this authenticated principal**,
/// returns the cached [`Built`] to replay (`04 §8.2`, rmp #182); otherwise `None`.
///
/// The lookup is namespaced by `principal`, so it can only ever return a response this same principal
/// produced — never another tenant's body.
fn replay_idempotent<E: RestEngine>(
    state: &AppState<E>,
    headers: &HeaderMap,
    principal: &str,
) -> Option<Built> {
    let key = headers.get(IDEMPOTENCY_KEY)?.to_str().ok()?;
    let cached = state
        .registry
        .cached_response(principal, key, state.now_nanos())?;
    Some(Built::new(
        StatusCode::from_u16(cached.status).unwrap_or(StatusCode::OK),
        &cached.content_type,
        cached.body,
    ))
}

#[cfg(test)]
mod tests;
