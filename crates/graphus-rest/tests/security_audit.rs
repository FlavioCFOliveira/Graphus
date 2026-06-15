//! Red-team security audit for `graphus-rest` — the external, untrusted HTTP surface.
//!
//! Each test drives the **real** public [`graphus_rest::router`] in-process via
//! `tower::ServiceExt::oneshot` (no sockets/TLS, the project's hard rule), with a self-contained
//! mock [`RestEngine`] and a real [`Authenticator`]/[`Clock`]. The in-crate `mock` engine is
//! `#[cfg(test)] pub(crate)`, hence not reachable from an integration test, so this file defines its
//! own minimal engine.
//!
//! ## Convention
//!
//! Findings registered in `rmp` are tagged `// Regression: SEC-<task-id>`. Each test asserts the
//! **secure** behaviour after the fix: it passes with the patched production code and would fail if
//! the vulnerability ever regressed. No test is `#[ignore]`d or skipped, so `cargo test -p
//! graphus-rest` stays green and guards the hardened attack surface (rmp #182/#184/#186/#187/#188).

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use axum::Router;
use axum::body::Body;
use http::{Request, Response, StatusCode, header};
use http_body_util::BodyExt;
use serde_json::{Value as Json, json};
use tower::ServiceExt;

use graphus_auth::{AuthProvider, Authenticator, Privilege};
use graphus_core::capability::Clock;
use graphus_core::{GraphusError, Value};

use graphus_rest::engine::{
    AccessMode, RestEngine, ResultStream, Row, RunSummary, TxHandle, TxOrigin,
};
use graphus_rest::registry::TxRegistry;
use graphus_rest::restvalue::RestValue;
use graphus_rest::router::{AppState, router};

// ============================ self-contained mock engine =======================================

/// A minimal in-memory engine. Records the lifecycle calls it received and streams canned rows for
/// a fixed query. It enforces the READ-rejects-write rule so the authz tests are realistic.
#[derive(Default)]
struct MockEngine {
    inner: std::sync::Mutex<MockInner>,
}

#[derive(Default)]
struct MockInner {
    next: u64,
    modes: std::collections::HashMap<u64, AccessMode>,
    log: Vec<String>,
}

impl MockEngine {
    fn new() -> Self {
        Self::default()
    }
    fn log(&self) -> Vec<String> {
        self.inner.lock().unwrap().log.clone()
    }
    fn is_write(q: &str) -> bool {
        let h = q.trim_start().to_ascii_uppercase();
        ["CREATE", "MERGE", "SET", "DELETE", "REMOVE"]
            .iter()
            .any(|k| h.starts_with(k))
    }
}

struct MockStream {
    fields: Vec<String>,
    rows: std::vec::IntoIter<Row>,
    summary: RunSummary,
}

impl ResultStream for MockStream {
    fn fields(&self) -> &[String] {
        &self.fields
    }
    fn next_row(&mut self) -> Result<Option<Row>, GraphusError> {
        Ok(self.rows.next())
    }
    fn summary(&self) -> RunSummary {
        self.summary.clone()
    }
}

impl RestEngine for MockEngine {
    type Stream = MockStream;

    fn begin(
        &self,
        db: &str,
        mode: AccessMode,
        origin: TxOrigin<'_>,
    ) -> Result<TxHandle, GraphusError> {
        let mut g = self.inner.lock().unwrap();
        g.next += 1;
        let h = g.next;
        g.log.push(format!(
            "begin(db={db}, mode={mode:?}, principal={})",
            origin.principal
        ));
        g.modes.insert(h, mode);
        Ok(TxHandle(h))
    }

    fn run(
        &self,
        tx: TxHandle,
        query: &str,
        _params: Vec<(String, Value)>,
    ) -> Result<Self::Stream, GraphusError> {
        let g = self.inner.lock().unwrap();
        if g.modes.get(&tx.0) == Some(&AccessMode::Read) && Self::is_write(query) {
            return Err(GraphusError::Transaction(
                "writing in read-only transaction is not allowed".to_owned(),
            ));
        }
        drop(g);
        self.inner
            .lock()
            .unwrap()
            .log
            .push(format!("run(q={query})"));
        // Echo a single row carrying the query text so a replay leak is observable in the body.
        Ok(MockStream {
            fields: vec!["x".to_owned()],
            rows: vec![vec![RestValue::Value(Value::String(format!(
                "ran:{query}"
            )))]]
            .into_iter(),
            summary: RunSummary {
                query_type: Some("r".to_owned()),
                stats: Vec::new(),
            },
        })
    }

    fn commit(&self, tx: TxHandle) -> Result<RunSummary, GraphusError> {
        self.inner
            .lock()
            .unwrap()
            .log
            .push(format!("commit(tx={})", tx.0));
        Ok(RunSummary::default())
    }

    fn rollback(&self, tx: TxHandle) -> Result<(), GraphusError> {
        self.inner
            .lock()
            .unwrap()
            .log
            .push(format!("rollback(tx={})", tx.0));
        Ok(())
    }
}

// ============================ harness ==========================================================

struct TestClock(AtomicU64);
impl TestClock {
    fn new(v: u64) -> Self {
        Self(AtomicU64::new(v))
    }
    fn set(&self, v: u64) {
        self.0.store(v, Ordering::Relaxed);
    }
}
impl Clock for TestClock {
    fn now_nanos(&self) -> u64 {
        self.0.load(Ordering::Relaxed)
    }
}

const JWT_SECRET: &[u8] = b"a-test-jwt-signing-secret-at-least-32b!!";
const TTL: u64 = 1_000_000_000;

/// `alice` (read+write) and `bob` (read only).
fn fixture_auth() -> Authenticator {
    let mut a = Authenticator::new(JWT_SECRET).unwrap();
    a.catalog_mut().create_user("alice").unwrap();
    a.catalog_mut().create_user("bob").unwrap();
    a.catalog_mut().create_role("rw").unwrap();
    a.catalog_mut().create_role("ro").unwrap();
    a.catalog_mut()
        .grant_privilege("rw", Privilege::read_database())
        .unwrap();
    a.catalog_mut()
        .grant_privilege("rw", Privilege::write_database())
        .unwrap();
    a.catalog_mut()
        .grant_privilege("ro", Privilege::read_database())
        .unwrap();
    a.catalog_mut().grant_role("alice", "rw").unwrap();
    a.catalog_mut().grant_role("bob", "ro").unwrap();
    a
}

struct Harness {
    router: Router,
    engine: Arc<MockEngine>,
    #[allow(dead_code)]
    registry: Arc<TxRegistry>,
    clock: Arc<TestClock>,
    auth: Arc<Authenticator>,
}

impl Harness {
    fn new() -> Self {
        let engine = Arc::new(MockEngine::new());
        let auth = Arc::new(fixture_auth());
        let registry = Arc::new(TxRegistry::new(TTL));
        let clock = Arc::new(TestClock::new(1_000_000_000));
        let state = AppState::new(
            Arc::clone(&engine),
            Arc::clone(&auth) as Arc<dyn AuthProvider>,
            Arc::clone(&registry),
            Arc::clone(&clock) as Arc<dyn Clock + Send + Sync>,
        );
        Self {
            router: router(state),
            engine,
            registry,
            clock,
            auth,
        }
    }

    fn token(&self, user: &str) -> String {
        let now = self.clock.0.load(Ordering::Relaxed) / 1_000_000_000;
        self.auth.issue_token(user, now, 3600).unwrap()
    }

    async fn send(&self, req: Request<Body>) -> Response<Body> {
        self.router.clone().oneshot(req).await.unwrap()
    }
}

async fn body_bytes(resp: Response<Body>) -> Vec<u8> {
    resp.into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes()
        .to_vec()
}
async fn body_json(resp: Response<Body>) -> Json {
    serde_json::from_slice(&body_bytes(resp).await).unwrap()
}

fn post(uri: &str, token: Option<&str>, ctype: &str, body: Vec<u8>) -> Request<Body> {
    let mut b = Request::builder()
        .method("POST")
        .uri(uri)
        .header(header::CONTENT_TYPE, ctype);
    if let Some(t) = token {
        b = b.header(header::AUTHORIZATION, format!("Bearer {t}"));
    }
    b.body(Body::from(body)).unwrap()
}

// ============================================================================================
//  SEC-182 — Idempotency-Key replay happens BEFORE authentication (unauthenticated cache read)
// ============================================================================================
//
// FINDING: in `commit_tx`/`auto_commit`/`begin`, `replay_idempotent` runs before `authenticate`
// (router.rs:385, :478, :300/1083). A cached response is returned to ANY caller that presents a
// previously-seen `Idempotency-Key` — with no Bearer token at all. CWE-306 / CWE-639.

/// Regression: SEC-182 — replay now requires successful authentication FIRST, so an unauthenticated
/// retry presenting a previously-cached `Idempotency-Key` is rejected `401` and never observes the
/// first (authenticated) caller's body. CWE-306.
#[tokio::test]
async fn sec1_idempotency_replay_without_auth_is_rejected() {
    let h = Harness::new();
    let alice = h.token("alice");

    // Alice opens a tx with an idempotency key. Her response (containing the tx id) is cached.
    let first = h
        .send(
            Request::builder()
                .method("POST")
                .uri("/db/neo4j/tx")
                .header(header::AUTHORIZATION, format!("Bearer {alice}"))
                .header(header::CONTENT_TYPE, "application/json")
                .header("Idempotency-Key", "shared-key-42")
                .body(Body::from(serde_json::to_vec(&json!({})).unwrap()))
                .unwrap(),
        )
        .await;
    assert_eq!(first.status(), StatusCode::CREATED);

    // An attacker with NO token presents the same key.
    let attack = h
        .send(
            Request::builder()
                .method("POST")
                .uri("/db/neo4j/tx")
                .header(header::CONTENT_TYPE, "application/json")
                .header("Idempotency-Key", "shared-key-42")
                .body(Body::from(serde_json::to_vec(&json!({})).unwrap()))
                .unwrap(),
        )
        .await;

    // Authentication runs before any replay: the anonymous caller is rejected, not served.
    assert_eq!(
        attack.status(),
        StatusCode::UNAUTHORIZED,
        "SEC-182: unauthenticated replay must be 401, never the cached 201"
    );
}

/// Regression: SEC-182 — the `Idempotency-Key` cache is now scoped per principal, so user `bob`
/// presenting the key alice used misses alice's entry and gets his OWN response (no cross-tenant
/// IDOR). CWE-639.
#[tokio::test]
async fn sec1_idempotency_key_is_scoped_per_principal_no_cross_user_leak() {
    let h = Harness::new();
    let alice = h.token("alice");
    let bob = h.token("bob");

    let first = h
        .send(
            Request::builder()
                .method("POST")
                .uri("/db/neo4j/tx/commit")
                .header(header::AUTHORIZATION, format!("Bearer {alice}"))
                .header(header::CONTENT_TYPE, "application/json")
                .header("Idempotency-Key", "collide")
                .body(Body::from(
                    serde_json::to_vec(&json!({
                        "access_mode": "READ",
                        "statements": [{ "statement": "RETURN secret_of_alice" }],
                    }))
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await;
    assert_eq!(first.status(), StatusCode::OK);
    let alice_body = body_bytes(first).await;

    // Bob reuses the same key with a DIFFERENT statement.
    let bob_resp = h
        .send(
            Request::builder()
                .method("POST")
                .uri("/db/neo4j/tx/commit")
                .header(header::AUTHORIZATION, format!("Bearer {bob}"))
                .header(header::CONTENT_TYPE, "application/json")
                .header("Idempotency-Key", "collide")
                .body(Body::from(
                    serde_json::to_vec(&json!({
                        "access_mode": "READ",
                        "statements": [{ "statement": "RETURN bobs_own_thing" }],
                    }))
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await;
    assert_eq!(bob_resp.status(), StatusCode::OK);
    let bob_body = body_bytes(bob_resp).await;

    // Bob's key is scoped to bob: he gets his own result, never alice's.
    assert_ne!(
        bob_body, alice_body,
        "SEC-182: bob must not replay alice's body"
    );
    let bob_text = String::from_utf8_lossy(&bob_body);
    assert!(
        !bob_text.contains("secret_of_alice"),
        "SEC-182: alice's query result must not leak to bob: {bob_text}"
    );
    assert!(
        bob_text.contains("bobs_own_thing"),
        "SEC-182: bob must see his own query result: {bob_text}"
    );
}

// ============================================================================================
//  SEC-184 — Idempotency cache is bounded (memory-exhaustion DoS fixed)
// ============================================================================================
//
// FIX: `TxRegistry` now bounds the idempotency cache by a deterministic TTL on the injected clock
// (IDEMPOTENCY_TTL_NANOS) and a hard entry cap (IDEMPOTENCY_MAX_ENTRIES, FIFO eviction). An entry
// past its TTL is pruned on the next access, so a key re-fired after the window re-executes rather
// than replaying forever. CWE-770.

/// Regression: SEC-184 — within the TTL a key replays; after the injected clock advances past the
/// TTL the entry is pruned and the SAME key re-executes (proving entries do not live forever, so the
/// cache cannot grow without bound). CWE-770.
#[tokio::test]
async fn sec2_idempotency_cache_is_bounded_by_ttl() {
    let h = Harness::new();
    let alice = h.token("alice");

    let fire = |body: Json| {
        let alice = alice.clone();
        Request::builder()
            .method("POST")
            .uri("/db/neo4j/tx/commit")
            .header(header::AUTHORIZATION, format!("Bearer {alice}"))
            .header(header::CONTENT_TYPE, "application/json")
            .header("Idempotency-Key", "ttl-key")
            .body(Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap()
    };

    // First call caches the (empty) result under `ttl-key`.
    let first = h.send(fire(json!({ "statements": [] }))).await;
    assert_eq!(first.status(), StatusCode::OK);

    // In-window retry with a DIFFERENT body still replays the cached empty result (not re-executed).
    let replay = h
        .send(fire(
            json!({ "statements": [{ "statement": "RETURN in_window" }] }),
        ))
        .await;
    let replay_text = String::from_utf8_lossy(&body_bytes(replay).await).into_owned();
    assert!(
        !replay_text.contains("in_window"),
        "SEC-184: in-window retry must replay the cached result, not re-execute: {replay_text}"
    );

    // Advance the injected clock past the TTL: the entry must be pruned.
    let now = h.clock.0.load(Ordering::Relaxed);
    h.clock
        .set(now + graphus_rest::registry::IDEMPOTENCY_TTL_NANOS + 1);

    // Same key, new body: with the entry expired it must RE-EXECUTE (bounded retention proven).
    let after = h
        .send(fire(
            json!({ "statements": [{ "statement": "RETURN re_executed" }] }),
        ))
        .await;
    assert_eq!(after.status(), StatusCode::OK);
    let after_text = String::from_utf8_lossy(&body_bytes(after).await).into_owned();
    assert!(
        after_text.contains("re_executed"),
        "SEC-184: a key re-fired past the TTL must re-execute (entry was evicted): {after_text}"
    );
}

// ============================================================================================
//  SEC-186 — CORS is fail-closed (no wildcard) on the authenticated API
// ============================================================================================
//
// FIX: the router no longer wires `CorsLayer::permissive()`. The CORS policy is configurable via
// `AppState::with_cors`, defaulting to fail-closed same-origin only — no `Access-Control-Allow-Origin`
// header is emitted, and a wildcard is never produced. An explicit allow-list is honoured; an
// un-allow-listed origin is never reflected. CWE-942.

/// Regression: SEC-186 — the default policy emits NO `Access-Control-Allow-Origin` (no wildcard), so
/// an arbitrary attacker origin is not granted cross-origin access to the authenticated API. CWE-942.
#[tokio::test]
async fn sec3_cors_default_is_not_wildcard() {
    let h = Harness::new(); // default fail-closed CORS
    let preflight = Request::builder()
        .method("OPTIONS")
        .uri("/db/neo4j/tx/commit")
        .header(header::ORIGIN, "https://evil.example")
        .header("Access-Control-Request-Method", "POST")
        .body(Body::empty())
        .unwrap();
    let resp = h.send(preflight).await;
    let acao = resp
        .headers()
        .get("access-control-allow-origin")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    assert_ne!(
        acao.as_deref(),
        Some("*"),
        "SEC-186: CORS must never reflect a wildcard origin"
    );
    assert!(
        acao.is_none(),
        "SEC-186: fail-closed default must emit no Access-Control-Allow-Origin, got {acao:?}"
    );
}

/// Regression: SEC-186 — with a configured allow-list, only the trusted origin is reflected; an
/// un-allow-listed origin is NOT echoed (no wildcard, no reflection of arbitrary origins). CWE-942.
#[tokio::test]
async fn sec3_cors_allowlist_only_reflects_trusted_origin() {
    use graphus_rest::router::CorsConfig;

    let engine = Arc::new(MockEngine::new());
    let auth = Arc::new(fixture_auth());
    let registry = Arc::new(TxRegistry::new(TTL));
    let clock = Arc::new(TestClock::new(1_000_000_000));
    let state = AppState::new(
        engine,
        Arc::clone(&auth) as Arc<dyn AuthProvider>,
        registry,
        Arc::clone(&clock) as Arc<dyn Clock + Send + Sync>,
    )
    .with_cors(CorsConfig::allow_origins(["https://app.trusted"]));
    let app = router(state);

    // A trusted origin is reflected exactly (never `*`).
    let trusted = app
        .clone()
        .oneshot(
            Request::builder()
                .method("OPTIONS")
                .uri("/db/neo4j/tx/commit")
                .header(header::ORIGIN, "https://app.trusted")
                .header("Access-Control-Request-Method", "POST")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(
        trusted
            .headers()
            .get("access-control-allow-origin")
            .and_then(|v| v.to_str().ok()),
        Some("https://app.trusted"),
        "SEC-186: a trusted allow-listed origin must be reflected"
    );

    // An untrusted origin is NOT reflected.
    let untrusted = app
        .oneshot(
            Request::builder()
                .method("OPTIONS")
                .uri("/db/neo4j/tx/commit")
                .header(header::ORIGIN, "https://evil.example")
                .header("Access-Control-Request-Method", "POST")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();
    let acao = untrusted
        .headers()
        .get("access-control-allow-origin")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    assert_ne!(acao.as_deref(), Some("*"), "SEC-186: never a wildcard");
    assert_ne!(
        acao.as_deref(),
        Some("https://evil.example"),
        "SEC-186: an un-allow-listed origin must not be reflected, got {acao:?}"
    );
}

// ============================================================================================
//  SEC-188 — No security headers on responses
// ============================================================================================
//
// FINDING: responses carry no `X-Content-Type-Options`, `Cache-Control`, `Content-Security-Policy`,
// `Referrer-Policy`, etc. (Built::into_response, router.rs:125). A problem+json error or a result
// body can be cached by intermediaries or MIME-sniffed. CWE-693 / CWE-525.

/// Regression: SEC-188 — dynamic responses now carry `X-Content-Type-Options: nosniff`,
/// `Cache-Control: no-store` and `Referrer-Policy: no-referrer`. CWE-693, CWE-525.
#[tokio::test]
async fn sec4_responses_carry_security_headers() {
    let h = Harness::new();
    let alice = h.token("alice");
    let resp = h
        .send(post(
            "/db/neo4j/tx/commit",
            Some(&alice),
            "application/json",
            serde_json::to_vec(&json!({ "statements": [{ "statement": "RETURN 1" }] })).unwrap(),
        ))
        .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let headers = resp.headers();
    assert_eq!(
        headers
            .get("x-content-type-options")
            .and_then(|v| v.to_str().ok()),
        Some("nosniff"),
        "SEC-188: X-Content-Type-Options: nosniff must be present"
    );
    assert_eq!(
        headers.get("cache-control").and_then(|v| v.to_str().ok()),
        Some("no-store"),
        "SEC-188: Cache-Control: no-store must be present"
    );
    assert_eq!(
        headers.get("referrer-policy").and_then(|v| v.to_str().ok()),
        Some("no-referrer"),
        "SEC-188: Referrer-Policy: no-referrer must be present"
    );
}

// ============================================================================================
//  SEC-187 — Storage/internal error `detail` is reflected to the client (info disclosure)
// ============================================================================================
//
// FINDING: `Problem::from_graphus_error` puts the raw engine message into `detail` for EVERY
// variant including `Storage` → 500 (problem.rs:113, :133). A storage/internal fault surfaces its
// internal message (paths, low-level cause) to the untrusted client. CWE-209.

/// Regression: SEC-187 — a 500 (Storage) response now carries a GENERIC `detail`; the internal path
/// and offset are redacted from the wire (logged server-side only). CWE-209.
#[tokio::test]
async fn sec5_storage_error_detail_is_redacted_from_client() {
    // An engine whose `run` fails with a Storage error carrying an "internal-looking" message.
    struct FailingEngine;
    struct EmptyStream;
    impl ResultStream for EmptyStream {
        fn fields(&self) -> &[String] {
            &[]
        }
        fn next_row(&mut self) -> Result<Option<Row>, GraphusError> {
            Ok(None)
        }
        fn summary(&self) -> RunSummary {
            RunSummary::default()
        }
    }
    impl RestEngine for FailingEngine {
        type Stream = EmptyStream;
        fn begin(
            &self,
            _db: &str,
            _mode: AccessMode,
            _o: TxOrigin<'_>,
        ) -> Result<TxHandle, GraphusError> {
            Ok(TxHandle(1))
        }
        fn run(
            &self,
            _tx: TxHandle,
            _q: &str,
            _p: Vec<(String, Value)>,
        ) -> Result<Self::Stream, GraphusError> {
            Err(GraphusError::Storage(
                "page fault at /var/lib/graphus/data/store.0001 offset 0xDEADBEEF".to_owned(),
            ))
        }
        fn commit(&self, _tx: TxHandle) -> Result<RunSummary, GraphusError> {
            Ok(RunSummary::default())
        }
        fn rollback(&self, _tx: TxHandle) -> Result<(), GraphusError> {
            Ok(())
        }
    }

    let auth = Arc::new(fixture_auth());
    let clock = Arc::new(TestClock::new(1_000_000_000));
    let registry = Arc::new(TxRegistry::new(TTL));
    let state = AppState::new(
        Arc::new(FailingEngine),
        Arc::clone(&auth) as Arc<dyn AuthProvider>,
        registry,
        Arc::clone(&clock) as Arc<dyn Clock + Send + Sync>,
    );
    let app = router(state);
    let token = auth.issue_token("alice", 1, 3600).unwrap();

    let resp = app
        .oneshot(post(
            "/db/neo4j/tx/commit",
            Some(&token),
            "application/json",
            serde_json::to_vec(&json!({ "statements": [{ "statement": "RETURN 1" }] })).unwrap(),
        ))
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR);
    let problem = body_json(resp).await;
    let detail = problem["detail"].as_str().unwrap_or("");
    // The internal storage path/offset must NOT reach the client.
    assert!(
        !detail.contains("/var/lib/graphus") && !detail.contains("0xDEADBEEF"),
        "SEC-187: internal storage detail must be redacted from the client, got: {detail:?}"
    );
    // The client gets a stable generic message instead.
    assert_eq!(
        detail, "an internal error occurred",
        "SEC-187: 5xx detail must be the generic redacted message"
    );
}

// ============================================================================================
//  Defensive controls that ALREADY HOLD — kept as regression guards (must stay GREEN)
// ============================================================================================

/// Body-size cap is enforced (DoS defence already present): an oversized body is 413 before decode.
#[tokio::test]
async fn ok_oversized_body_is_413() {
    let h = Harness::new();
    let token = h.token("alice");
    let huge = "X".repeat(graphus_rest::router::MAX_REQUEST_BODY_BYTES + 1);
    let body = serde_json::to_vec(&json!({ "statements": [{ "statement": huge }] })).unwrap();
    let resp = h
        .send(post(
            "/db/neo4j/tx/commit",
            Some(&token),
            "application/json",
            body,
        ))
        .await;
    assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
    assert!(h.engine.log().is_empty());
}

/// Deeply nested CBOR is rejected as a controlled 400, never a stack-overflow (DoS defence present).
#[tokio::test]
async fn ok_deeply_nested_cbor_is_400_not_panic() {
    let h = Harness::new();
    let token = h.token("alice");
    let mut nested = ciborium::Value::Integer(0.into());
    for _ in 0..(graphus_rest::value::MAX_CBOR_DEPTH + 50) {
        nested = ciborium::Value::Array(vec![nested]);
    }
    let req = ciborium::Value::Map(vec![(
        ciborium::Value::Text("statements".to_owned()),
        ciborium::Value::Array(vec![ciborium::Value::Map(vec![
            (
                ciborium::Value::Text("statement".to_owned()),
                ciborium::Value::Text("RETURN $x".to_owned()),
            ),
            (
                ciborium::Value::Text("parameters".to_owned()),
                ciborium::Value::Map(vec![(ciborium::Value::Text("x".to_owned()), nested)]),
            ),
        ])]),
    )]);
    let mut body = Vec::new();
    ciborium::into_writer(&req, &mut body).unwrap();
    let resp = h
        .send(post(
            "/db/neo4j/tx/commit",
            Some(&token),
            "application/cbor",
            body,
        ))
        .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}

/// Authentication is enforced on the data path (no token ⇒ 401, no engine call).
#[tokio::test]
async fn ok_missing_bearer_is_401_no_engine_call() {
    let h = Harness::new();
    let resp = h
        .send(post(
            "/db/neo4j/tx",
            None,
            "application/json",
            serde_json::to_vec(&json!({})).unwrap(),
        ))
        .await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    assert!(h.engine.log().is_empty());
}

/// RBAC is enforced: a read-only principal cannot open a WRITE transaction (403).
#[tokio::test]
async fn ok_rbac_blocks_write_for_read_only_user() {
    let h = Harness::new();
    let bob = h.token("bob");
    let resp = h
        .send(post(
            "/db/neo4j/tx",
            Some(&bob),
            "application/json",
            serde_json::to_vec(&json!({})).unwrap(),
        ))
        .await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    // bob never reached `begin` (authz precedes engine).
    assert!(h.engine.log().is_empty());
}

/// An expired Bearer token is rejected via the injected clock (401). Guards the auth-time path.
#[tokio::test]
async fn ok_expired_bearer_is_401() {
    let h = Harness::new();
    let token = h.token("alice");
    h.clock
        .set(h.clock.0.load(Ordering::Relaxed) + 3601 * 1_000_000_000);
    let resp = h
        .send(post(
            "/db/neo4j/tx",
            Some(&token),
            "application/json",
            serde_json::to_vec(&json!({})).unwrap(),
        ))
        .await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}
