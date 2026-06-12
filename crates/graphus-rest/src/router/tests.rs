//! In-process tests for the REST router (`04-technical-design.md` §8.2, `06 §4`).
//!
//! Every test drives the real axum [`Router`] via `tower::ServiceExt::oneshot` — **no sockets, no
//! TLS** (the hard rule). The engine is the scriptable [`MockEngine`]; time is the deterministic
//! [`TestClock`] (advanced explicitly, never wall-clock). Together they cover the lifecycle, the
//! serialization formats, streaming, the error shape, auth, access mode, idempotency, and the
//! OpenAPI document.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use axum::Router;
use axum::body::Body;
use http::{Request, Response, StatusCode, header};
use http_body_util::BodyExt;
use serde_json::{Value as Json, json};
use tower::ServiceExt;

use graphus_auth::{AuthProvider, Authenticator, Privilege};
use graphus_core::Value;
use graphus_core::capability::Clock;

use crate::engine::{Row, RunSummary, mock::Canned, mock::MockEngine};
use crate::registry::TxRegistry;
use crate::restvalue::{RestNode, RestPath, RestRelationship, RestValue};
use crate::router::{AppState, router};

// ---- deterministic clock ----------------------------------------------------------------------

/// A `Clock` whose nanosecond value the test sets explicitly (deterministic — no wall-clock).
struct TestClock(AtomicU64);

impl TestClock {
    fn new(start: u64) -> Self {
        Self(AtomicU64::new(start))
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

// ---- fixtures ---------------------------------------------------------------------------------

const JWT_SECRET: &[u8] = b"a-test-jwt-signing-secret-at-least-32b!!";
const TTL: u64 = 1_000_000_000; // 1s, in clock nanos

/// An authenticator with `alice` (DB Read + Write) and `bob` (DB Read only), so tests can exercise
/// both authorized and forbidden access modes. No passwords needed (REST uses Bearer).
fn fixture_auth() -> Authenticator {
    let mut a = Authenticator::new(JWT_SECRET);
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

/// The pieces a test holds onto: the router plus the shared engine/registry/clock/auth so it can
/// assert on the seam and advance time.
struct Harness {
    router: Router,
    engine: Arc<MockEngine>,
    registry: Arc<TxRegistry>,
    clock: Arc<TestClock>,
    auth: Arc<Authenticator>,
}

impl Harness {
    fn with_engine(engine: MockEngine) -> Self {
        let engine = Arc::new(engine);
        let auth = Arc::new(fixture_auth());
        let registry = Arc::new(TxRegistry::new(TTL));
        let clock = Arc::new(TestClock::new(1_000_000_000)); // start at t=1s
        let state = AppState::new(
            Arc::clone(&engine),
            // `AppState::new` now takes `Arc<dyn AuthProvider>` (rmp #94); the fixture is a concrete
            // `Authenticator`, so the unsizing coercion is spelled out explicitly here (it is not
            // inferred through `Arc::clone`'s `Self`-determined return type). The harness keeps its
            // own `Arc<Authenticator>` for `issue_token`, which is not on the seam trait.
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

    fn new() -> Self {
        Self::with_engine(MockEngine::new())
    }

    /// A valid Bearer token for `user`, minted against the fixture clock's current second.
    fn token(&self, user: &str) -> String {
        let now_secs = self.clock.now_nanos() / 1_000_000_000;
        self.auth.issue_token(user, now_secs, 3600).unwrap()
    }

    /// Sends one request through the router (consuming a clone, so the harness stays usable).
    async fn send(&self, req: Request<Body>) -> Response<Body> {
        self.router.clone().oneshot(req).await.unwrap()
    }
}

// ---- request/response helpers -----------------------------------------------------------------

/// A `POST` with a JSON body and a Bearer token.
fn post_json(uri: &str, token: &str, body: Json) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(uri)
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap()
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

fn content_type(resp: &Response<Body>) -> String {
    resp.headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_owned()
}

// =============================== lifecycle =====================================================

#[tokio::test]
async fn open_run_commit_happy_path() {
    let engine = MockEngine::new().on_query(
        "RETURN 1 AS x",
        Canned::rows(&["x"], vec![vec![Value::Integer(1)]]),
    );
    let h = Harness::with_engine(engine);
    let token = h.token("alice");

    // 1) Open.
    let resp = h.send(post_json("/db/neo4j/tx", &token, json!({}))).await;
    assert_eq!(resp.status(), StatusCode::CREATED);
    let begin = body_json(resp).await;
    assert_eq!(begin["access_mode"], "WRITE"); // default
    let id = begin["id"].as_str().unwrap().to_owned();
    let commit_url = begin["commit"].as_str().unwrap().to_owned();
    assert_eq!(commit_url, format!("/db/neo4j/tx/{id}"));

    // 2) Run in the open tx.
    let resp = h
        .send(post_json(
            &format!("/db/neo4j/tx/{id}"),
            &token,
            json!({ "statements": [{ "statement": "RETURN 1 AS x" }] }),
        ))
        .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let run = body_json(resp).await;
    assert_eq!(run["results"][0]["fields"][0], "x");
    // The int53-encoded integer row cell.
    assert_eq!(run["results"][0]["data"][0][0], json!({ "Z": "1" }));
    assert_eq!(run["id"], id); // tx still open

    // 3) Commit (no final statements).
    let resp = h
        .send(post_json(
            &format!("/db/neo4j/tx/{id}/commit"),
            &token,
            json!({}),
        ))
        .await;
    assert_eq!(resp.status(), StatusCode::OK);

    // The engine saw begin → run → commit, and the registry is empty.
    let log = h.engine.log();
    assert!(log.iter().any(|l| l.starts_with("begin")));
    assert!(
        log.iter()
            .any(|l| l.contains("run(") && l.contains("RETURN 1 AS x"))
    );
    assert!(log.iter().any(|l| l.starts_with("commit")));
    assert_eq!(h.registry.open_count(), 0);
}

#[tokio::test]
async fn delete_rolls_back_the_transaction() {
    let h = Harness::new();
    let token = h.token("alice");

    let begin = body_json(h.send(post_json("/db/neo4j/tx", &token, json!({}))).await).await;
    let id = begin["id"].as_str().unwrap().to_owned();
    assert_eq!(h.registry.open_count(), 1);

    let req = Request::builder()
        .method("DELETE")
        .uri(format!("/db/neo4j/tx/{id}"))
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap();
    let resp = h.send(req).await;
    assert_eq!(resp.status(), StatusCode::OK);

    assert_eq!(h.registry.open_count(), 0);
    assert!(h.engine.log().iter().any(|l| l.starts_with("rollback")));
}

#[tokio::test]
async fn delete_unknown_transaction_is_404_problem() {
    let h = Harness::new();
    let token = h.token("alice");
    let req = Request::builder()
        .method("DELETE")
        .uri("/db/neo4j/tx/tx-does-not-exist")
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap();
    let resp = h.send(req).await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    assert_eq!(content_type(&resp), crate::problem::PROBLEM_JSON);
}

#[tokio::test]
async fn auto_commit_shortcut_runs_and_commits() {
    let engine = MockEngine::new().on_query(
        "CREATE (n) RETURN n",
        Canned::rows(&["n"], vec![vec![Value::Integer(42)]]),
    );
    let h = Harness::with_engine(engine);
    let token = h.token("alice");

    let resp = h
        .send(post_json(
            "/db/neo4j/tx/commit",
            &token,
            json!({ "statements": [{ "statement": "CREATE (n) RETURN n" }] }),
        ))
        .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let run = body_json(resp).await;
    assert_eq!(run["results"][0]["data"][0][0], json!({ "Z": "42" }));
    // No open tx remains (auto-commit closed it).
    assert!(run.get("id").is_none() || run["id"].is_null());
    assert_eq!(h.registry.open_count(), 0);

    let log = h.engine.log();
    assert!(log.iter().any(|l| l.starts_with("begin")));
    assert!(log.iter().any(|l| l.starts_with("commit")));
}

// =============================== inactivity auto-rollback =======================================

#[tokio::test]
async fn inactivity_auto_rollback_on_touch_after_expiry() {
    let h = Harness::new();
    let token = h.token("alice");

    let begin = body_json(h.send(post_json("/db/neo4j/tx", &token, json!({}))).await).await;
    let id = begin["id"].as_str().unwrap().to_owned();
    assert_eq!(h.registry.open_count(), 1);

    // Advance the injected clock past the TTL, then touch the tx by running: it must be reaped and
    // the request must 404 (the tx auto-rolled back). Deterministic — we moved the clock, not waited.
    h.clock.set(h.clock.now_nanos() + TTL + 1);
    let resp = h
        .send(post_json(
            &format!("/db/neo4j/tx/{id}"),
            &token,
            json!({ "statements": [{ "statement": "RETURN 1" }] }),
        ))
        .await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    assert_eq!(h.registry.open_count(), 0);
    assert!(h.engine.log().iter().any(|l| l.starts_with("rollback")));
}

#[tokio::test]
async fn sweep_reaps_expired_via_clock() {
    let h = Harness::new();
    let token = h.token("alice");
    let _ = body_json(h.send(post_json("/db/neo4j/tx", &token, json!({}))).await).await;
    assert_eq!(h.registry.open_count(), 1);

    // A direct sweep after advancing the clock reaps it (the server runs this on a tick).
    h.clock.set(h.clock.now_nanos() + TTL + 1);
    let reaped = h
        .registry
        .sweep_expired(h.clock.now_nanos(), h.engine.as_ref());
    assert_eq!(reaped.len(), 1);
    assert_eq!(h.registry.open_count(), 0);
}

#[tokio::test]
async fn activity_resets_the_inactivity_timeout() {
    let h = Harness::new();
    let token = h.token("alice");
    let begin = body_json(h.send(post_json("/db/neo4j/tx", &token, json!({}))).await).await;
    let id = begin["id"].as_str().unwrap().to_owned();

    // Touch just before expiry: the deadline must be pushed forward so a later touch (still within
    // one TTL of the *second* touch) keeps the tx alive past the original deadline.
    h.clock.set(h.clock.now_nanos() + TTL - 1);
    let resp = h
        .send(post_json(
            &format!("/db/neo4j/tx/{id}"),
            &token,
            json!({ "statements": [] }),
        ))
        .await;
    assert_eq!(resp.status(), StatusCode::OK);

    // Now advance another TTL-1 from the refreshed deadline: still alive.
    h.clock.set(h.clock.now_nanos() + TTL - 1);
    let resp = h
        .send(post_json(
            &format!("/db/neo4j/tx/{id}"),
            &token,
            json!({ "statements": [] }),
        ))
        .await;
    assert_eq!(
        resp.status(),
        StatusCode::OK,
        "activity should have reset the timeout"
    );
}

// =============================== idempotency ===================================================

#[tokio::test]
async fn idempotency_key_replays_first_response() {
    let h = Harness::new();
    let token = h.token("alice");

    let req_with_key = |body: Json| {
        Request::builder()
            .method("POST")
            .uri("/db/neo4j/tx")
            .header(header::AUTHORIZATION, format!("Bearer {token}"))
            .header(header::CONTENT_TYPE, "application/json")
            .header("Idempotency-Key", "key-abc")
            .body(Body::from(serde_json::to_vec(&body).unwrap()))
            .unwrap()
    };

    // First open with the key.
    let first = body_json(h.send(req_with_key(json!({}))).await).await;
    let first_id = first["id"].as_str().unwrap().to_owned();
    assert_eq!(h.registry.open_count(), 1);

    // Replaying the same key returns the *same* response body (same tx id) and does NOT open a
    // second transaction.
    let second = body_json(h.send(req_with_key(json!({}))).await).await;
    assert_eq!(second["id"].as_str().unwrap(), first_id);
    assert_eq!(
        h.registry.open_count(),
        1,
        "replay must not re-execute begin"
    );

    // Exactly one begin reached the engine.
    assert_eq!(
        h.engine
            .log()
            .iter()
            .filter(|l| l.starts_with("begin"))
            .count(),
        1
    );
}

// =============================== access mode (06 §4) ===========================================

#[tokio::test]
async fn access_mode_defaults_to_write_when_absent() {
    let h = Harness::new();
    let token = h.token("alice");
    let begin = body_json(h.send(post_json("/db/neo4j/tx", &token, json!({}))).await).await;
    assert_eq!(begin["access_mode"], "WRITE");
}

#[tokio::test]
async fn access_mode_read_is_honoured() {
    let h = Harness::new();
    let token = h.token("alice");
    let begin = body_json(
        h.send(post_json(
            "/db/neo4j/tx",
            &token,
            json!({ "access_mode": "READ" }),
        ))
        .await,
    )
    .await;
    assert_eq!(begin["access_mode"], "READ");
}

#[tokio::test]
async fn invalid_access_mode_is_400_and_tx_not_opened() {
    let h = Harness::new();
    let token = h.token("alice");
    let resp = h
        .send(post_json(
            "/db/neo4j/tx",
            &token,
            json!({ "access_mode": "readwrite" }),
        ))
        .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    assert_eq!(content_type(&resp), crate::problem::PROBLEM_JSON);
    // `06 §4`: the transaction must NOT be opened.
    assert_eq!(h.registry.open_count(), 0);
    assert!(
        h.engine.log().is_empty(),
        "engine.begin must not have been called"
    );
}

#[tokio::test]
async fn read_transaction_rejects_write_statement() {
    let h = Harness::new();
    let token = h.token("alice"); // alice can read AND write, so authz passes; the engine enforces READ.

    let begin = body_json(
        h.send(post_json(
            "/db/neo4j/tx",
            &token,
            json!({ "access_mode": "READ" }),
        ))
        .await,
    )
    .await;
    let id = begin["id"].as_str().unwrap().to_owned();

    // A write statement in a READ tx is rejected by the engine and surfaces as a problem+json.
    let resp = h
        .send(post_json(
            &format!("/db/neo4j/tx/{id}"),
            &token,
            json!({ "statements": [{ "statement": "CREATE (n)" }] }),
        ))
        .await;
    assert_eq!(resp.status(), StatusCode::CONFLICT); // transaction error → 409
    assert_eq!(content_type(&resp), crate::problem::PROBLEM_JSON);
    let problem = body_json(resp).await;
    assert!(problem["detail"].as_str().unwrap().contains("read-only"));
}

#[tokio::test]
async fn write_mode_forbidden_for_read_only_user() {
    let h = Harness::new();
    let token = h.token("bob"); // bob has Read only.
    // Opening a WRITE tx (the default) requires Write → 403 for bob.
    let resp = h.send(post_json("/db/neo4j/tx", &token, json!({}))).await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    assert_eq!(content_type(&resp), crate::problem::PROBLEM_JSON);
    // But a READ tx is allowed.
    let resp = h
        .send(post_json(
            "/db/neo4j/tx",
            &token,
            json!({ "access_mode": "READ" }),
        ))
        .await;
    assert_eq!(resp.status(), StatusCode::CREATED);
}

// =============================== serialization =================================================

#[tokio::test]
async fn jolt_int53_round_trip_above_2_pow_53_as_string() {
    let big = (1_i64 << 53) + 1; // 9007199254740993
    let engine = MockEngine::new().on_query(
        "RETURN big",
        Canned::rows(&["big"], vec![vec![Value::Integer(big)]]),
    );
    let h = Harness::with_engine(engine);
    let token = h.token("alice");

    let resp = h
        .send(post_json(
            "/db/neo4j/tx/commit",
            &token,
            json!({ "statements": [{ "statement": "RETURN big" }] }),
        ))
        .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let run = body_json(resp).await;
    let cell = &run["results"][0]["data"][0][0];
    // The big integer is carried as a STRING under the `Z` sigil — no f64 precision loss.
    assert_eq!(cell, &json!({ "Z": "9007199254740993" }));
    assert!(cell["Z"].is_string());
}

#[tokio::test]
async fn cbor_negotiation_round_trip() {
    let big = (1_i64 << 53) + 1;
    let engine = MockEngine::new().on_query(
        "RETURN x",
        Canned::rows(&["x"], vec![vec![Value::Integer(big)]]),
    );
    let h = Harness::with_engine(engine);
    let token = h.token("alice");

    let req = Request::builder()
        .method("POST")
        .uri("/db/neo4j/tx/commit")
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::ACCEPT, "application/cbor")
        .body(Body::from(
            serde_json::to_vec(&json!({ "statements": [{ "statement": "RETURN x" }] })).unwrap(),
        ))
        .unwrap();
    let resp = h.send(req).await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(content_type(&resp), "application/cbor");

    // Decode the CBOR response and confirm the row cell is a native (lossless) integer.
    let bytes = body_bytes(resp).await;
    let decoded: ciborium::Value = ciborium::from_reader(bytes.as_slice()).unwrap();
    // Navigate: { results: [ { fields, data: [ [ <cell> ] ], summary } ] }
    let map = match &decoded {
        ciborium::Value::Map(m) => m,
        _ => panic!("expected a CBOR map"),
    };
    let results = map
        .iter()
        .find(|(k, _)| matches!(k, ciborium::Value::Text(t) if t == "results"))
        .map(|(_, v)| v)
        .unwrap();
    let first = match results {
        ciborium::Value::Array(a) => &a[0],
        _ => panic!("results not an array"),
    };
    let data = match first {
        ciborium::Value::Map(m) => m
            .iter()
            .find(|(k, _)| matches!(k, ciborium::Value::Text(t) if t == "data"))
            .map(|(_, v)| v)
            .unwrap(),
        _ => panic!("statement result not a map"),
    };
    // data[0][0] is the cell — but note the buffered envelope encodes rows as Jolt JSON values
    // first, so in CBOR the cell is the CBOR encoding of the Jolt object {"Z":"..."}. Assert the
    // round-trip preserves the string form (the int53 guarantee holds across CBOR too).
    let cell = match data {
        ciborium::Value::Array(rows) => match &rows[0] {
            ciborium::Value::Array(cells) => &cells[0],
            _ => panic!("row not an array"),
        },
        _ => panic!("data not an array"),
    };
    // The cell is the CBOR map {"Z": "9007199254740993"}.
    let val = crate::value::cbor_to_value(cell).unwrap();
    assert_eq!(
        val,
        Value::Map(vec![(
            "Z".to_owned(),
            Value::String("9007199254740993".to_owned())
        )])
    );
}

#[tokio::test]
async fn ndjson_streaming_of_multiple_rows() {
    let engine = MockEngine::new().on_query(
        "UNWIND [1,2,3] AS n RETURN n",
        Canned::rows(
            &["n"],
            vec![
                vec![Value::Integer(1)],
                vec![Value::Integer(2)],
                vec![Value::Integer(3)],
            ],
        ),
    );
    let h = Harness::with_engine(engine);
    let token = h.token("alice");

    let req = Request::builder()
        .method("POST")
        .uri("/db/neo4j/tx/commit")
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::ACCEPT, "application/x-ndjson")
        .body(Body::from(
            serde_json::to_vec(
                &json!({ "statements": [{ "statement": "UNWIND [1,2,3] AS n RETURN n" }] }),
            )
            .unwrap(),
        ))
        .unwrap();
    let resp = h.send(req).await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(content_type(&resp), "application/x-ndjson");

    let text = String::from_utf8(body_bytes(resp).await).unwrap();
    let lines: Vec<&str> = text.lines().filter(|l| !l.is_empty()).collect();
    // fields line + 3 row lines + summary line.
    assert_eq!(
        lines.len(),
        5,
        "expected fields + 3 rows + summary, got {text:?}"
    );

    let fields: Json = serde_json::from_str(lines[0]).unwrap();
    assert_eq!(fields["fields"][0], "n");
    // Each row line is { "row": [ {"Z":"N"} ] }.
    for (i, expected) in [1, 2, 3].iter().enumerate() {
        let row: Json = serde_json::from_str(lines[i + 1]).unwrap();
        assert_eq!(row["row"][0], json!({ "Z": expected.to_string() }));
    }
    let summary: Json = serde_json::from_str(lines[4]).unwrap();
    assert!(summary.get("summary").is_some());
}

// =============================== errors ========================================================

#[tokio::test]
async fn compile_error_is_rfc9457_problem_json_400() {
    let engine = MockEngine::new().on_query_error(
        "RETURN",
        graphus_core::GraphusError::Compile("Unexpected end of input".to_owned()),
    );
    let h = Harness::with_engine(engine);
    let token = h.token("alice");

    let resp = h
        .send(post_json(
            "/db/neo4j/tx/commit",
            &token,
            json!({ "statements": [{ "statement": "RETURN" }] }),
        ))
        .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    assert_eq!(content_type(&resp), crate::problem::PROBLEM_JSON);
    let problem = body_json(resp).await;
    // RFC 9457 members.
    assert_eq!(problem["status"], 400);
    assert!(
        problem["type"]
            .as_str()
            .unwrap()
            .starts_with("urn:graphus:error:")
    );
    assert!(problem["title"].is_string());
    assert_eq!(problem["detail"], "Unexpected end of input");
    // The shared engine code (mirrors the Bolt FAILURE classification).
    assert_eq!(problem["code"], "Neo.ClientError.Statement.SyntaxError");
}

#[tokio::test]
async fn malformed_json_body_is_400_problem() {
    let h = Harness::new();
    let token = h.token("alice");
    let req = Request::builder()
        .method("POST")
        .uri("/db/neo4j/tx/commit")
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(b"{ this is not json".to_vec()))
        .unwrap();
    let resp = h.send(req).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    assert_eq!(content_type(&resp), crate::problem::PROBLEM_JSON);
}

#[tokio::test]
async fn unsupported_content_type_is_415() {
    let h = Harness::new();
    let token = h.token("alice");
    let req = Request::builder()
        .method("POST")
        .uri("/db/neo4j/tx")
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header(header::CONTENT_TYPE, "text/plain")
        .body(Body::from(b"hello".to_vec()))
        .unwrap();
    let resp = h.send(req).await;
    assert_eq!(resp.status(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
}

// =============================== auth ==========================================================

#[tokio::test]
async fn missing_bearer_is_401_problem() {
    let h = Harness::new();
    let req = Request::builder()
        .method("POST")
        .uri("/db/neo4j/tx")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(b"{}".to_vec()))
        .unwrap();
    let resp = h.send(req).await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(content_type(&resp), crate::problem::PROBLEM_JSON);
}

#[tokio::test]
async fn bad_bearer_token_is_401_problem() {
    let h = Harness::new();
    let resp = h
        .send(post_json("/db/neo4j/tx", "not.a.valid.jwt", json!({})))
        .await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn valid_bearer_is_accepted() {
    let h = Harness::new();
    let token = h.token("alice");
    let resp = h.send(post_json("/db/neo4j/tx", &token, json!({}))).await;
    assert_eq!(resp.status(), StatusCode::CREATED);
}

#[tokio::test]
async fn expired_bearer_is_rejected_via_injected_clock() {
    let h = Harness::new();
    // Mint a token at the current second, then advance the injected clock past its 1h ttl.
    let token = h.token("alice");
    h.clock.set(h.clock.now_nanos() + 3601 * 1_000_000_000);
    let resp = h.send(post_json("/db/neo4j/tx", &token, json!({}))).await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

// =============================== openapi =======================================================

#[tokio::test]
async fn openapi_doc_is_valid_31_and_declares_tx_paths() {
    let h = Harness::new();
    let req = Request::builder()
        .method("GET")
        .uri("/openapi.json")
        .body(Body::empty())
        .unwrap();
    let resp = h.send(req).await;
    assert_eq!(resp.status(), StatusCode::OK);
    let doc = body_json(resp).await;
    assert_eq!(doc["openapi"], "3.1.0");
    assert!(doc["paths"].get("/db/{db}/tx").is_some());
    assert!(doc["paths"].get("/db/{db}/tx/{id}/commit").is_some());
    assert!(doc["paths"].get("/db/{db}/tx/commit").is_some());
    // The graph-projection path (rmp #77) is declared too.
    assert!(doc["paths"].get("/db/{db}/graph").is_some());
}

// =============================== graph projection (rmp #77) =====================================

/// A node `RestValue` with one `name` property, for the viz tests.
fn viz_node(id: i64, label: &str, name: &str) -> RestValue {
    RestValue::Node(RestNode {
        id,
        labels: vec![label.to_owned()],
        properties: vec![("name".to_owned(), Value::String(name.to_owned()))],
    })
}

/// A relationship `RestValue` between `start` and `end`, for the viz tests.
fn viz_rel(id: i64, start: i64, end: i64, ty: &str) -> RestValue {
    RestValue::Relationship(RestRelationship {
        id,
        start,
        end,
        rel_type: ty.to_owned(),
        properties: vec![],
    })
}

/// A `Canned` result from already-built structural rows (the `Canned::rows` helper only lifts
/// scalar `Value`s; the viz tests need `Node`/`Relationship`/`Path` cells).
fn canned_structural(fields: &[&str], rows: Vec<Row>) -> Canned {
    Canned {
        fields: fields.iter().map(|s| (*s).to_owned()).collect(),
        rows,
        summary: RunSummary {
            query_type: Some("r".to_owned()),
            stats: Vec::new(),
        },
    }
}

#[tokio::test]
async fn graph_viz_projects_nodes_and_relationships() {
    // A row `(a)-[r]->(b)` projects to two nodes + one relationship with correct endpoints.
    let query = "MATCH (a)-[r]->(b) RETURN a, r, b";
    let engine = MockEngine::new().on_query(
        query,
        canned_structural(
            &["a", "r", "b"],
            vec![vec![
                viz_node(1, "Person", "Ada"),
                viz_rel(100, 1, 2, "KNOWS"),
                viz_node(2, "Person", "Bob"),
            ]],
        ),
    );
    let h = Harness::with_engine(engine);
    let token = h.token("alice");

    let resp = h
        .send(post_json(
            "/db/neo4j/graph",
            &token,
            json!({ "statements": [{ "statement": query }] }),
        ))
        .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let graph = body_json(resp).await;

    let nodes = graph["nodes"].as_array().unwrap();
    let rels = graph["relationships"].as_array().unwrap();
    assert_eq!(nodes.len(), 2);
    assert_eq!(rels.len(), 1);
    // Node shape: id / labels / strict-Jolt properties.
    assert_eq!(nodes[0]["id"], json!(1));
    assert_eq!(nodes[0]["labels"], json!(["Person"]));
    assert_eq!(nodes[0]["properties"]["name"], json!({ "U": "Ada" }));
    // Relationship endpoints are present and correct (startNode/endNode).
    assert_eq!(rels[0]["id"], json!(100));
    assert_eq!(rels[0]["type"], json!("KNOWS"));
    assert_eq!(rels[0]["startNode"], json!(1));
    assert_eq!(rels[0]["endNode"], json!(2));

    // It ran as a READ auto-commit through the same seam (begin READ → run → commit).
    let log = h.engine.log();
    assert!(log.iter().any(|l| l.contains("mode=Read")));
    assert!(log.iter().any(|l| l.starts_with("commit")));
    assert_eq!(h.registry.open_count(), 0);
}

#[tokio::test]
async fn graph_viz_dedups_shared_node_across_rows() {
    // Node 1 is returned in two rows; it must collapse to a single projected node.
    let query = "MATCH (a)-->(b) RETURN a, b";
    let engine = MockEngine::new().on_query(
        query,
        canned_structural(
            &["a", "b"],
            vec![
                vec![viz_node(1, "P", "hub"), viz_node(2, "P", "x")],
                vec![viz_node(1, "P", "hub"), viz_node(3, "P", "y")],
            ],
        ),
    );
    let h = Harness::with_engine(engine);
    let token = h.token("alice");

    let resp = h
        .send(post_json(
            "/db/neo4j/graph",
            &token,
            json!({ "statements": [{ "statement": query }] }),
        ))
        .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let graph = body_json(resp).await;
    let ids: Vec<i64> = graph["nodes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|n| n["id"].as_i64().unwrap())
        .collect();
    assert_eq!(
        ids,
        vec![1, 2, 3],
        "node 1 appears once, in first-seen order"
    );
    assert_eq!(graph["relationships"].as_array().unwrap().len(), 0);
}

#[tokio::test]
async fn graph_viz_projects_a_path_with_all_nodes_and_rels() {
    // A single `path` cell contributes all its nodes + relationships.
    let query = "MATCH p = (a)-[*]->(z) RETURN p";
    let path = RestValue::Path(RestPath {
        nodes: vec![
            RestNode {
                id: 10,
                labels: vec!["P".to_owned()],
                properties: vec![],
            },
            RestNode {
                id: 11,
                labels: vec!["P".to_owned()],
                properties: vec![],
            },
            RestNode {
                id: 12,
                labels: vec!["P".to_owned()],
                properties: vec![],
            },
        ],
        relationships: vec![
            RestRelationship {
                id: 100,
                start: 10,
                end: 11,
                rel_type: "R".to_owned(),
                properties: vec![],
            },
            RestRelationship {
                id: 101,
                start: 11,
                end: 12,
                rel_type: "R".to_owned(),
                properties: vec![],
            },
        ],
    });
    let engine = MockEngine::new().on_query(query, canned_structural(&["p"], vec![vec![path]]));
    let h = Harness::with_engine(engine);
    let token = h.token("alice");

    let resp = h
        .send(post_json(
            "/db/neo4j/graph",
            &token,
            json!({ "statements": [{ "statement": query }] }),
        ))
        .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let graph = body_json(resp).await;
    assert_eq!(graph["nodes"].as_array().unwrap().len(), 3);
    assert_eq!(graph["relationships"].as_array().unwrap().len(), 2);
    assert_eq!(graph["relationships"][1]["startNode"], json!(11));
    assert_eq!(graph["relationships"][1]["endNode"], json!(12));
}

#[tokio::test]
async fn graph_viz_scalar_only_result_is_empty_graph() {
    let query = "RETURN 1 AS x";
    let engine =
        MockEngine::new().on_query(query, Canned::rows(&["x"], vec![vec![Value::Integer(1)]]));
    let h = Harness::with_engine(engine);
    let token = h.token("alice");

    let resp = h
        .send(post_json(
            "/db/neo4j/graph",
            &token,
            json!({ "statements": [{ "statement": query }] }),
        ))
        .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let graph = body_json(resp).await;
    assert_eq!(graph["nodes"].as_array().unwrap().len(), 0);
    assert_eq!(graph["relationships"].as_array().unwrap().len(), 0);
}

#[tokio::test]
async fn graph_viz_forces_read_so_a_write_is_rejected() {
    // The handler forces READ; a write statement is rejected by the engine (→ 409 problem).
    let h = Harness::new();
    let token = h.token("alice"); // alice may write; the READ forcing still rejects the statement.
    let resp = h
        .send(post_json(
            "/db/neo4j/graph",
            &token,
            json!({ "statements": [{ "statement": "CREATE (n)" }] }),
        ))
        .await;
    assert_eq!(resp.status(), StatusCode::CONFLICT);
    assert_eq!(content_type(&resp), crate::problem::PROBLEM_JSON);
    // The transaction was opened READ then rolled back; nothing leaks.
    let log = h.engine.log();
    assert!(log.iter().any(|l| l.contains("mode=Read")));
    assert!(log.iter().any(|l| l.starts_with("rollback")));
    assert_eq!(h.registry.open_count(), 0);
}

#[tokio::test]
async fn graph_viz_requires_bearer() {
    let h = Harness::new();
    let req = Request::builder()
        .method("POST")
        .uri("/db/neo4j/graph")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(
            serde_json::to_vec(&json!({ "statements": [{ "statement": "MATCH (n) RETURN n" }] }))
                .unwrap(),
        ))
        .unwrap();
    let resp = h.send(req).await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(content_type(&resp), crate::problem::PROBLEM_JSON);
    // No transaction was opened without a valid principal.
    assert!(h.engine.log().is_empty());
}

#[tokio::test]
async fn graph_viz_compile_error_is_problem_json() {
    let query = "MATCH";
    let engine = MockEngine::new().on_query_error(
        query,
        graphus_core::GraphusError::Compile("Unexpected end of input".to_owned()),
    );
    let h = Harness::with_engine(engine);
    let token = h.token("alice");
    let resp = h
        .send(post_json(
            "/db/neo4j/graph",
            &token,
            json!({ "statements": [{ "statement": query }] }),
        ))
        .await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    assert_eq!(content_type(&resp), crate::problem::PROBLEM_JSON);
    // The read transaction was rolled back after the error.
    assert!(h.engine.log().iter().any(|l| l.starts_with("rollback")));
    assert_eq!(h.registry.open_count(), 0);
}
