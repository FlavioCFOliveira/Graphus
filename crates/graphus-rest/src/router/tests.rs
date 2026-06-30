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

use graphus_auth::{AuthProvider, AuthThrottle, Authenticator, Privilege};
use graphus_core::Value;
use graphus_core::capability::Clock;

use crate::engine::{Row, RunSummary, mock::Canned, mock::MockEngine};
use crate::protocol::{DEFAULT_LOGIN_TOKEN_TTL_SECS, LoginResponse};
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

/// Passwords for the `POST /auth/login` (password-auth) tests, each ≥ `MIN_PASSWORD_LEN` (8) so
/// `set_password` accepts them. The Bearer-only lifecycle tests are unaffected — see `fixture_auth`.
const ALICE_PASSWORD: &str = "alice-strong-pw";
const BOB_PASSWORD: &str = "bob-strong-pw-2";

/// An authenticator with `alice` (DB Read + Write) and `bob` (DB Read only), so tests can exercise
/// both authorized and forbidden access modes. `alice`/`bob` also get a password (rmp #499) so the
/// `POST /auth/login` tests can authenticate them; `carol` stays password-less.
///
/// It also seeds `carol`, a **per-tenant** (graph-scoped) principal granted `READ`/`WRITE` on
/// `GRAPH neo4j` **only** (not server-wide `Resource::Database`). She is the regression fixture for
/// the per-tenant REST authorization bug: the coarse transaction-mode gate must check the privilege
/// scoped to the *target* database, so a graph-scoped grant authorizes its own database and nothing
/// else — see [`graph_scoped_grant_authorizes_its_own_database_over_rest`].
fn fixture_auth() -> Authenticator {
    let mut a = Authenticator::new(JWT_SECRET).expect("JWT_SECRET is >= 32 bytes");
    a.catalog_mut().create_user("alice").unwrap();
    a.catalog_mut().create_user("bob").unwrap();
    a.catalog_mut().create_user("carol").unwrap();
    a.catalog_mut().create_role("rw").unwrap();
    a.catalog_mut().create_role("ro").unwrap();
    a.catalog_mut().create_role("tenant_neo4j").unwrap();
    a.catalog_mut()
        .grant_privilege("rw", Privilege::read_database())
        .unwrap();
    a.catalog_mut()
        .grant_privilege("rw", Privilege::write_database())
        .unwrap();
    a.catalog_mut()
        .grant_privilege("ro", Privilege::read_database())
        .unwrap();
    // carol's role is scoped to ONE database (the graph `neo4j`), never server-wide.
    a.catalog_mut()
        .grant_privilege(
            "tenant_neo4j",
            Privilege::on_graph(graphus_auth::Action::Read, "neo4j"),
        )
        .unwrap();
    a.catalog_mut()
        .grant_privilege(
            "tenant_neo4j",
            Privilege::on_graph(graphus_auth::Action::Write, "neo4j"),
        )
        .unwrap();
    a.catalog_mut().grant_role("alice", "rw").unwrap();
    a.catalog_mut().grant_role("bob", "ro").unwrap();
    a.catalog_mut().grant_role("carol", "tenant_neo4j").unwrap();
    // rmp #499: `/auth/login` authenticates by password. Setting an INITIAL password keeps each user's
    // credential epoch at its baseline (0), so the Bearer tokens the other tests mint via `issue_token`
    // (also epoch 0) stay valid — the credentials are additive, not a perturbation of those tests.
    a.set_password("alice", ALICE_PASSWORD).unwrap();
    a.set_password("bob", BOB_PASSWORD).unwrap();
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
        // The default cap (rmp #448) is high; the lifecycle tests never approach it, so this is the
        // unchanged behaviour. The cap-specific gate uses `with_engine_and_cap`.
        Self::with_engine_and_cap(engine, crate::registry::DEFAULT_MAX_OPEN_TRANSACTIONS)
    }

    /// Builds a harness whose registry caps the number of concurrently-open transactions at `cap`
    /// (rmp #448), so the open-transaction-cap gate can exhaust it with a handful of `BEGIN`s. The
    /// login throttle is **disabled** (the lifecycle/cap tests do not exercise `/auth/login`).
    fn with_engine_and_cap(engine: MockEngine, cap: usize) -> Self {
        Self::with_engine_cap_throttle(engine, cap, Arc::new(AuthThrottle::disabled()))
    }

    /// Builds a harness with an explicit login throttle (rmp #458/#499), so the `/auth/login`
    /// throttle test can drive an enabled bucket against the deterministic clock. `cap` is the
    /// open-transaction cap as in [`with_engine_and_cap`](Self::with_engine_and_cap).
    fn with_engine_cap_throttle(
        engine: MockEngine,
        cap: usize,
        throttle: Arc<AuthThrottle>,
    ) -> Self {
        let engine = Arc::new(engine);
        let auth = Arc::new(fixture_auth());
        let registry = Arc::new(TxRegistry::new(TTL).with_max_open_transactions(cap));
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
        )
        .with_auth_throttle(throttle);
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

/// rmp #448 REGRESSION GATE (HTTP-level, CWE-770): an authenticated principal opening explicit
/// transactions in a loop (`POST /db/{db}/tx`) without committing is **`429`-rejected past the configured
/// `max_open_transactions`** — the slow-OOM bound. Mirrors the registry-level
/// `try_open_is_capped_and_rejects_past_the_limit`, but end-to-end through the real router (so it proves
/// the router wires `try_open` and renders the cap rejection as a retriable `429`). Freeing a slot
/// (committing one open transaction) admits a new `BEGIN` again — the cap bounds the LIVE count.
#[tokio::test]
async fn open_transaction_cap_rejects_excess_begins_with_429() {
    const CAP: usize = 3;
    let h = Harness::with_engine_and_cap(MockEngine::new(), CAP);
    let token = h.token("alice");

    // Open exactly the cap as one principal — every BEGIN is `201 Created`.
    let mut ids = Vec::new();
    for _ in 0..CAP {
        let resp = h.send(post_json("/db/neo4j/tx", &token, json!({}))).await;
        assert_eq!(
            resp.status(),
            StatusCode::CREATED,
            "under the cap, BEGIN is admitted"
        );
        ids.push(body_json(resp).await["id"].as_str().unwrap().to_owned());
    }
    assert_eq!(h.registry.open_count(), CAP);

    // The NEXT `BEGIN` (same principal, no commits in between) is rejected `429 Too Many Requests`,
    // as an RFC 9457 problem body — a retriable load-shed, not a crash or a silent unbounded admit.
    let resp = h.send(post_json("/db/neo4j/tx", &token, json!({}))).await;
    assert_eq!(
        resp.status(),
        StatusCode::TOO_MANY_REQUESTS,
        "past the cap, BEGIN must be 429-rejected (rmp #448)"
    );
    assert_eq!(content_type(&resp), crate::problem::PROBLEM_JSON);
    // The rejection did NOT leak an engine transaction: the live count is still exactly the cap, and the
    // router rolled back the engine handle it had opened before the cap check (so no orphan engine tx).
    assert_eq!(h.registry.open_count(), CAP);
    let rollbacks = h
        .engine
        .log()
        .iter()
        .filter(|l| l.starts_with("rollback"))
        .count();
    assert_eq!(
        rollbacks, 1,
        "the cap-rejected BEGIN must roll back the engine transaction it opened (no leak)"
    );

    // Commit one open transaction to free a slot, then a fresh BEGIN is admitted again.
    let freed = &ids[0];
    let resp = h
        .send(post_json(
            &format!("/db/neo4j/tx/{freed}/commit"),
            &token,
            json!({}),
        ))
        .await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(h.registry.open_count(), CAP - 1);
    let resp = h.send(post_json("/db/neo4j/tx", &token, json!({}))).await;
    assert_eq!(
        resp.status(),
        StatusCode::CREATED,
        "a freed slot admits a new BEGIN — the cap is on the live count"
    );
}

/// rmp #390 GATE: a transaction opened by `alice` cannot be run, committed, or rolled back by `bob`,
/// even though Bob is fully authorized for coarse access to the database. The transaction id is a
/// guessable sequential value, so without the principal binding Bob could drive statements inside
/// Alice's transaction under Alice's (the opener's) fine-grained privileges. Every cross-principal
/// operation must 404 (indistinguishable from an unknown id) and leave Alice's transaction intact.
#[tokio::test]
async fn tx_opened_by_alice_cannot_be_run_committed_or_rolled_back_by_bob() {
    let h = Harness::new();
    let alice = h.token("alice");
    // Bob holds the `ro` role: full coarse READ access to the database, so his `authorize_mode`
    // passes for a READ transaction — isolating the ownership check from the access-mode gate.
    let bob = h.token("bob");

    // Alice opens a READ transaction.
    let begin = body_json(
        h.send(post_json(
            "/db/neo4j/tx",
            &alice,
            json!({ "access_mode": "READ" }),
        ))
        .await,
    )
    .await;
    let id = begin["id"].as_str().unwrap().to_owned();
    assert_eq!(h.registry.open_count(), 1);

    // Bob tries to RUN inside Alice's tx → 404, and Alice's tx is untouched.
    let resp = h
        .send(post_json(
            &format!("/db/neo4j/tx/{id}"),
            &bob,
            json!({ "statements": [{ "statement": "RETURN 1 AS x" }] }),
        ))
        .await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    assert_eq!(content_type(&resp), crate::problem::PROBLEM_JSON);
    assert_eq!(
        h.registry.open_count(),
        1,
        "Bob's RUN must not reap Alice's tx"
    );

    // Bob tries to COMMIT Alice's tx → 404, still untouched.
    let resp = h
        .send(post_json(
            &format!("/db/neo4j/tx/{id}/commit"),
            &bob,
            json!({}),
        ))
        .await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    assert_eq!(
        h.registry.open_count(),
        1,
        "Bob's COMMIT must not finalise Alice's tx"
    );

    // Bob tries to DELETE (roll back) Alice's tx → 404, still untouched.
    let req = Request::builder()
        .method("DELETE")
        .uri(format!("/db/neo4j/tx/{id}"))
        .header(header::AUTHORIZATION, format!("Bearer {bob}"))
        .body(Body::empty())
        .unwrap();
    let resp = h.send(req).await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    assert_eq!(
        h.registry.open_count(),
        1,
        "Bob's DELETE must not roll back Alice's tx"
    );
    // The engine never saw a rollback for Alice's transaction from Bob's attempts.
    assert!(
        !h.engine.log().iter().any(|l| l.starts_with("rollback")),
        "no rollback should have been issued by Bob's cross-principal attempts"
    );

    // Alice still owns it and can commit normally.
    let resp = h
        .send(post_json(
            &format!("/db/neo4j/tx/{id}/commit"),
            &alice,
            json!({}),
        ))
        .await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(h.registry.open_count(), 0);
}

/// rmp #390 GATE: because Bob cannot adopt Alice's transaction at all (it 404s, above), he can never
/// run a statement that the engine seam would execute under Alice's (the opener's) fine-grained
/// privileges. This asserts the *consequence*: the engine never receives a `run` carrying Alice's
/// ticket on Bob's behalf — the privilege-escalation surface is structurally closed.
#[tokio::test]
async fn adopted_tx_does_not_use_openers_fine_grained_privileges() {
    let h = Harness::new();
    let alice = h.token("alice");
    let bob = h.token("bob");

    // Alice opens a tx; capture how many `run` calls the engine has seen so far.
    let begin = body_json(
        h.send(post_json(
            "/db/neo4j/tx",
            &alice,
            json!({ "access_mode": "READ" }),
        ))
        .await,
    )
    .await;
    let id = begin["id"].as_str().unwrap().to_owned();
    let runs_before = h
        .engine
        .log()
        .iter()
        .filter(|l| l.starts_with("run("))
        .count();

    // Bob attempts to run inside Alice's tx.
    let resp = h
        .send(post_json(
            &format!("/db/neo4j/tx/{id}"),
            &bob,
            json!({ "statements": [{ "statement": "MATCH (n) RETURN n" }] }),
        ))
        .await;
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);

    // The engine executed NO new statement on Bob's behalf inside Alice's transaction: the seam (which
    // applies the opener's RBAC) was never reached, so Alice's privileges were never lent to Bob.
    let runs_after = h
        .engine
        .log()
        .iter()
        .filter(|l| l.starts_with("run("))
        .count();
    assert_eq!(
        runs_after, runs_before,
        "Bob's hijack attempt must not reach the engine seam at all"
    );
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

/// rmp #389 GATE: a transaction begun and then abandoned (never touched again) is rolled back by the
/// inactivity sweep once the clock advances past its idle deadline — the open-transaction count
/// returns to 0, so an abandoned transaction cannot leak (pinning the GC watermark / growing memory).
#[tokio::test]
async fn idle_transaction_is_reaped_by_the_inactivity_sweep() {
    let h = Harness::new();
    let token = h.token("alice");

    // Begin and then abandon (no further touch).
    let begin = body_json(h.send(post_json("/db/neo4j/tx", &token, json!({}))).await).await;
    let _id = begin["id"].as_str().unwrap().to_owned();
    assert_eq!(h.registry.open_count(), 1);

    // Before the deadline a sweep reaps nothing.
    let reaped = h
        .registry
        .sweep_expired(h.clock.now_nanos(), h.engine.as_ref());
    assert!(reaped.is_empty(), "a live transaction must not be reaped");
    assert_eq!(h.registry.open_count(), 1);

    // Advance the (injectable, deterministic) clock past the idle timeout, then run the sweep — the
    // exact operation the server's background task performs. The abandoned transaction is rolled back.
    h.clock.set(h.clock.now_nanos() + TTL + 1);
    let reaped = h
        .registry
        .sweep_expired(h.clock.now_nanos(), h.engine.as_ref());
    assert_eq!(reaped.len(), 1, "the idle transaction must be reaped");
    assert_eq!(
        h.registry.open_count(),
        0,
        "the open-transaction count must return to 0 after the sweep"
    );
    // The engine actually rolled it back (not merely dropped from the map).
    assert!(
        h.engine.log().iter().any(|l| l.starts_with("rollback")),
        "the sweep must roll the abandoned transaction back at the engine"
    );
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

/// Regression: the coarse transaction-mode gate must authorize against the **target database's**
/// graph scope, not the server-wide `Resource::Database` scope. A per-tenant principal granted only
/// `READ`/`WRITE ON GRAPH neo4j` must be able to open transactions on `/db/neo4j/...` and be
/// **forbidden** on any other database.
///
/// Before the fix, `authorize_mode` required the server-wide `read_database()`/`write_database()`
/// privilege, so a graph-scoped grant was rejected with `403` even on its own database — making
/// per-tenant RBAC entirely non-functional over REST (a false-denial security bug). The RBAC
/// containment rule (`Database ⊇ Graph(db)`) means a broader server-wide grant still satisfies this
/// gate, so [`alice`]/[`bob`] (server-wide) are unaffected (the tests above still pass).
#[tokio::test]
async fn graph_scoped_grant_authorizes_its_own_database_over_rest() {
    let h = Harness::new();
    let token = h.token("carol"); // granted READ+WRITE on GRAPH neo4j only.

    // A WRITE tx on her own database (`neo4j`) is authorized (graph-scoped Write satisfies the gate).
    let resp = h.send(post_json("/db/neo4j/tx", &token, json!({}))).await;
    assert_eq!(
        resp.status(),
        StatusCode::CREATED,
        "a graph-scoped WRITE grant must authorize a WRITE tx on its own database"
    );

    // A READ tx on her own database is likewise authorized (Write ⊇ Read; either grant suffices).
    let resp = h
        .send(post_json(
            "/db/neo4j/tx",
            &token,
            json!({ "access_mode": "READ" }),
        ))
        .await;
    assert_eq!(resp.status(), StatusCode::CREATED);

    // But she holds NO grant on a different database (`other`): both READ and WRITE are forbidden —
    // a graph-scoped grant never crosses a database boundary (no privilege escalation).
    let resp = h.send(post_json("/db/other/tx", &token, json!({}))).await;
    assert_eq!(
        resp.status(),
        StatusCode::FORBIDDEN,
        "a graph-scoped grant must NOT authorize a different database (cross-tenant)"
    );
    let resp = h
        .send(post_json(
            "/db/other/tx",
            &token,
            json!({ "access_mode": "READ" }),
        ))
        .await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);

    // No transaction on `other` was ever opened (the gate is fail-fast, before `engine.begin`).
    assert!(
        !h.engine.log().iter().any(|e| e.contains("other")),
        "engine.begin must never run for a forbidden database: {:?}",
        h.engine.log()
    );
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

// =============================== incremental streaming (rmp #475) ==============================
//
// The single-statement JSON and NDJSON paths now stream the response body incrementally with bounded
// server memory (rmp #475). The hard requirement is **byte-identity**: a streamed body must be
// byte-for-byte equal to what the buffered serializer produced, so no driver/client sees any wire
// difference. These tests pin that with the router itself as the oracle.

/// BYTE-IDENTITY (auto-commit / `Finalise::Commit`): a JSON auto-commit with **no** `Idempotency-Key`
/// now STREAMS; the **same** request WITH a key stays on the BUFFERED+cached path. The two bodies
/// must be byte-for-byte identical. Exercises every cell class — a big int (int53 string form), a
/// plain string, a structural node, and a null — so the streamed envelope is proven equal to the
/// buffered `RunResponse` across the full encoding surface.
#[tokio::test]
async fn streamed_json_autocommit_is_byte_identical_to_buffered() {
    let query = "RETURN mix";
    let rows = vec![
        vec![
            RestValue::Value(Value::Integer((1_i64 << 53) + 1)),
            RestValue::Value(Value::String("hi \"quoted\"".to_owned())),
        ],
        vec![viz_node(7, "Person", "Ada"), RestValue::Value(Value::Null)],
    ];
    let engine = MockEngine::new().on_query(query, canned_structural(&["a", "b"], rows));
    let h = Harness::with_engine(engine);
    let token = h.token("alice");
    let body = json!({ "statements": [{ "statement": query }] });

    // Streamed (no Idempotency-Key).
    let streamed_resp = h
        .send(post_json("/db/neo4j/tx/commit", &token, body.clone()))
        .await;
    assert_eq!(content_type(&streamed_resp), "application/json");
    let streamed = body_bytes(streamed_resp).await;

    // Buffered (an Idempotency-Key routes to the buffered, cacheable path — the prior behaviour).
    let buffered_req = Request::builder()
        .method("POST")
        .uri("/db/neo4j/tx/commit")
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header(header::CONTENT_TYPE, "application/json")
        .header("Idempotency-Key", "buffered-key-1")
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();
    let buffered = body_bytes(h.send(buffered_req).await).await;

    assert_eq!(
        streamed,
        buffered,
        "streamed JSON must be byte-identical to the buffered RunResponse:\n  streamed={}\n  buffered={}",
        String::from_utf8_lossy(&streamed),
        String::from_utf8_lossy(&buffered),
    );
    // The streamed body is a complete, valid envelope (not a truncated stream).
    let doc: Json = serde_json::from_slice(&streamed).unwrap();
    assert_eq!(doc["results"][0]["data"].as_array().unwrap().len(), 2);

    // COMMIT-AFTER-DRAIN: the commit was issued by the producer only after the result fully streamed,
    // so by the time the body is collected the engine has seen begin → run → commit (in that order).
    let log = h.engine.log();
    let pos = |p: &str| log.iter().position(|l| l.starts_with(p));
    assert!(pos("begin") < pos("run") && pos("run") < pos("commit"));
}

/// BYTE-IDENTITY (`run_in_tx` / `Finalise::KeepOpen`): a single-statement JSON `run` inside an open
/// transaction streams the `RunResponse` envelope **including** the trailing `"id"` /
/// `"expires_at_nanos"` members. The streamed bytes must equal `serde_json::to_vec(&RunResponse{…})`
/// built from the public structs (the buffered serializer), so the open-tx tail framing is pinned.
#[tokio::test]
async fn streamed_json_keepopen_is_byte_identical_to_runresponse() {
    let query = "RETURN n";
    let engine = MockEngine::new().on_query(
        query,
        Canned::rows(
            &["x"],
            vec![vec![Value::Integer(1)], vec![Value::Integer(2)]],
        ),
    );
    let h = Harness::with_engine(engine);
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
    let id = begin["id"].as_str().unwrap().to_owned();

    let resp = h
        .send(post_json(
            &format!("/db/neo4j/tx/{id}"),
            &token,
            json!({ "statements": [{ "statement": query }] }),
        ))
        .await;
    assert_eq!(content_type(&resp), "application/json");
    let streamed = body_bytes(resp).await;

    // Reconstruct the expected buffered envelope from the PUBLIC structs, using the exact id/expiry
    // the streamed response carried (the framing — not the values — is what we are pinning).
    let doc: Json = serde_json::from_slice(&streamed).unwrap();
    let got_id = doc["id"].as_str().unwrap().to_owned();
    let got_exp = doc["expires_at_nanos"].as_u64().unwrap();
    let data: Vec<Json> = vec![
        Json::Array(vec![crate::restvalue::restvalue_to_jolt(
            &RestValue::Value(Value::Integer(1)),
        )]),
        Json::Array(vec![crate::restvalue::restvalue_to_jolt(
            &RestValue::Value(Value::Integer(2)),
        )]),
    ];
    let expected = serde_json::to_vec(&crate::protocol::RunResponse {
        results: vec![crate::protocol::StatementResult {
            fields: vec!["x".to_owned()],
            data,
            // The mock's read summary, exactly as `encode_summary` renders it.
            summary: json!({ "type": "r", "stats": {} }),
        }],
        id: Some(got_id),
        expires_at_nanos: Some(got_exp),
    })
    .unwrap();

    assert_eq!(
        streamed,
        expected,
        "streamed KeepOpen JSON must equal the buffered RunResponse byte-for-byte:\n  streamed={}\n  expected={}",
        String::from_utf8_lossy(&streamed),
        String::from_utf8_lossy(&expected),
    );
}

/// An idempotency-keyed JSON commit is still BUFFERED and CACHED — streaming must not silently break
/// the `Idempotency-Key` replay. The first keyed request runs once; a replay returns the same bytes
/// without re-executing (exactly one `begin`/`commit` reaches the engine).
#[tokio::test]
async fn idempotency_keyed_json_commit_is_buffered_and_cached() {
    let query = "CREATE (n) RETURN n";
    let engine =
        MockEngine::new().on_query(query, Canned::rows(&["n"], vec![vec![Value::Integer(42)]]));
    let h = Harness::with_engine(engine);
    let token = h.token("alice");

    let keyed = || {
        Request::builder()
            .method("POST")
            .uri("/db/neo4j/tx/commit")
            .header(header::AUTHORIZATION, format!("Bearer {token}"))
            .header(header::CONTENT_TYPE, "application/json")
            .header("Idempotency-Key", "commit-key-1")
            .body(Body::from(
                serde_json::to_vec(&json!({ "statements": [{ "statement": query }] })).unwrap(),
            ))
            .unwrap()
    };

    let first = body_bytes(h.send(keyed()).await).await;
    let second = body_bytes(h.send(keyed()).await).await; // replay
    assert_eq!(
        first, second,
        "keyed commit must replay the exact first body"
    );

    // Exactly one begin and one commit reached the engine — the replay did NOT re-execute.
    let log = h.engine.log();
    assert_eq!(log.iter().filter(|l| l.starts_with("begin")).count(), 1);
    assert_eq!(log.iter().filter(|l| l.starts_with("commit")).count(), 1);
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

// =============================== DoS hardening (untrusted HTTP input) ============================
//
// Two input-driven DoS vectors fixed in graphus-rest, each pinned by a regression test below:
//   1. A request body over the explicit cap is rejected `413` before any decoding/buffering grows
//      memory unbounded (`crate::router::MAX_REQUEST_BODY_BYTES`, `DefaultBodyLimit`).
//   2. A deeply nested CBOR body — small on the wire, but recursive to decode — is refused as a
//      controlled `400` (problem+json `Malformed`), never a stack-overflow panic
//      (`crate::value::MAX_CBOR_DEPTH`, both the request-path deserializer and `cbor_to_value`).

/// A body larger than [`crate::router::MAX_REQUEST_BODY_BYTES`] is rejected `413 Payload Too Large`
/// before it is buffered, so an oversized body cannot exhaust server memory (regression: the router
/// previously relied on axum's implicit, un-auditable 2 MiB default). The body here is otherwise a
/// well-formed JSON request — only its size triggers the rejection.
#[tokio::test]
async fn oversized_request_body_is_rejected_413() {
    let h = Harness::new();
    let token = h.token("alice");

    // One statement whose Cypher string alone exceeds the cap → the serialized body is over the
    // limit. The body is valid JSON; the size, not the shape, is what must be rejected.
    let huge_query = "X".repeat(crate::router::MAX_REQUEST_BODY_BYTES + 1);
    let body = serde_json::to_vec(&json!({
        "statements": [{ "statement": huge_query }]
    }))
    .unwrap();
    assert!(body.len() > crate::router::MAX_REQUEST_BODY_BYTES);

    let req = Request::builder()
        .method("POST")
        .uri("/db/neo4j/tx/commit")
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body))
        .unwrap();
    let resp = h.send(req).await;

    assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
    // The body never reached the engine — nothing ran.
    assert!(h.engine.log().is_empty());
    assert_eq!(h.registry.open_count(), 0);
}

/// A request body just under the cap is accepted (the `413` boundary is exclusive of legitimate
/// payloads): the limit rejects abuse without clipping a large-but-valid statement batch.
#[tokio::test]
async fn body_under_the_cap_is_accepted() {
    let engine = MockEngine::new().on_query("RETURN 1", Canned::rows(&["n"], vec![]));
    let h = Harness::with_engine(engine);
    let token = h.token("alice");

    let req = Request::builder()
        .method("POST")
        .uri("/db/neo4j/tx/commit")
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(
            serde_json::to_vec(&json!({ "statements": [{ "statement": "RETURN 1" }] })).unwrap(),
        ))
        .unwrap();
    let resp = h.send(req).await;
    assert_eq!(resp.status(), StatusCode::OK);
}

/// A deeply nested CBOR request body — far past [`crate::value::MAX_CBOR_DEPTH`], yet a few KiB on
/// the wire — is refused as a controlled `400` problem+json, **not** a stack-overflow panic. Before
/// the fix the request-path deserializer recursed without an audited bound, so a single small body
/// could crash the worker thread. The body fits comfortably under the size cap, proving the depth
/// guard (not the size guard) is what catches it.
#[tokio::test]
async fn deeply_nested_cbor_body_is_rejected_not_panic() {
    let h = Harness::new();
    let token = h.token("alice");

    // Build `parameters` = [[[ ... ]]] nested well past MAX_CBOR_DEPTH, then CBOR-encode the whole
    // RunRequest. Each level is one array marker byte, so this stays tiny on the wire.
    let depth = crate::value::MAX_CBOR_DEPTH + 50;
    let mut nested = ciborium::Value::Integer(0.into());
    for _ in 0..depth {
        nested = ciborium::Value::Array(vec![nested]);
    }
    let request = ciborium::Value::Map(vec![(
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
    ciborium::into_writer(&request, &mut body).unwrap();
    assert!(
        body.len() < crate::router::MAX_REQUEST_BODY_BYTES,
        "the deep body must be small on the wire ({} bytes) so the depth guard, not the size guard, \
         is what rejects it",
        body.len()
    );

    let req = Request::builder()
        .method("POST")
        .uri("/db/neo4j/tx/commit")
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header(header::CONTENT_TYPE, "application/cbor")
        .body(Body::from(body))
        .unwrap();
    // If this returns at all (rather than aborting the runtime), the recursion was bounded.
    let resp = h.send(req).await;

    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    assert_eq!(content_type(&resp), crate::problem::PROBLEM_JSON);
    assert!(h.engine.log().is_empty());
}

// =============================== analytical columnar channel (rmp #334) =========================
//
// The `POST /db/{db}/query/columnar` endpoint runs through the SAME engine seam as the row-wise
// paths (begin READ → run → commit) and returns the native `gcol-result` columnar body. These tests
// drive the real `Router` in-process (no sockets) and round-trip the columnar body back to rows,
// asserting equality with the row-wise JSON the existing path would emit — proving the analytical
// channel is lossless and that the OLTP paths are untouched.

use crate::columnar::{GCOL_RESULT_MEDIA_TYPE, decode_result};

/// Decodes a `gcol-result` body's rows. The decoder already yields strict-Jolt JSON cells (the same
/// shape the row-wise `data` arrays use), so this is a thin wrapper for the comparison tests.
fn columnar_body_as_jolt_rows(body: &[u8]) -> Vec<Vec<Json>> {
    decode_result(body).expect("decode gcol-result body").rows
}

#[tokio::test]
async fn columnar_endpoint_round_trips_a_multi_row_multi_column_result() {
    // The core acceptance test: a multi-row, multi-column result encoded columnar, then decoded back
    // to rows, equals the row-wise result — AND the columnar body is smaller than the JSON body on
    // this low-cardinality wide shape (both sizes printed).
    let query = "MATCH (p:Person) RETURN p.id AS id, p.tier AS tier, p.active AS active";
    let tiers = ["gold", "silver", "bronze"];
    let n = 2_000;
    let rows: Vec<Row> = (0..n)
        .map(|i| {
            vec![
                RestValue::Value(Value::Integer(i as i64)),
                RestValue::Value(Value::String(tiers[i % tiers.len()].to_owned())),
                RestValue::Value(Value::Boolean(i % 2 == 0)),
            ]
        })
        .collect();
    let engine = MockEngine::new().on_query(
        query,
        canned_structural(&["id", "tier", "active"], rows.clone()),
    );
    let h = Harness::with_engine(engine);
    let token = h.token("alice");

    // 1) Columnar response.
    let resp = h
        .send(post_json(
            "/db/neo4j/query/columnar",
            &token,
            json!({ "statements": [{ "statement": query }] }),
        ))
        .await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(content_type(&resp), GCOL_RESULT_MEDIA_TYPE);
    let columnar_body = body_bytes(resp).await;

    // 2) The same query over the row-wise JSON auto-commit path, for the equality + size comparison.
    let resp_json = h
        .send(post_json(
            "/db/neo4j/tx/commit",
            &token,
            json!({ "statements": [{ "statement": query }] }),
        ))
        .await;
    assert_eq!(resp_json.status(), StatusCode::OK);
    let json_body = body_bytes(resp_json).await;
    let json_doc: Json = serde_json::from_slice(&json_body).unwrap();
    let json_data = json_doc["results"][0]["data"].as_array().unwrap();

    // 3) Decode the columnar body back to rows and assert cell-for-cell equality with the JSON rows.
    let decoded_rows = columnar_body_as_jolt_rows(&columnar_body);
    assert_eq!(decoded_rows.len(), n, "row count must match");
    assert_eq!(decoded_rows.len(), json_data.len());
    for (i, (col_row, json_row)) in decoded_rows.iter().zip(json_data).enumerate() {
        let json_row = json_row.as_array().unwrap();
        assert_eq!(col_row, json_row, "row {i} columnar vs JSON cell mismatch");
    }

    // 4) The header fields match the query projection.
    let header = decode_result(&columnar_body).unwrap().header;
    assert_eq!(header.fields, vec!["id", "tier", "active"]);
    assert_eq!(header.columns[0].codec, "i64");
    assert_eq!(header.columns[1].codec, "str");
    assert_eq!(header.columns[2].codec, "bool");

    // 5) Measured size win (printed for the record).
    println!(
        "[rmp #334] /query/columnar end-to-end: {n} rows x 3 cols | columnar = {} B | json = {} B | ratio = {:.2}x smaller",
        columnar_body.len(),
        json_body.len(),
        json_body.len() as f64 / columnar_body.len() as f64,
    );
    assert!(
        columnar_body.len() < json_body.len(),
        "columnar ({}) must be smaller than JSON ({}) on this analytical result",
        columnar_body.len(),
        json_body.len()
    );

    // 6) It ran as a READ auto-commit through the same seam (begin READ → run → commit), and the
    // registry is empty — the OLTP transaction machinery is reused unchanged.
    let log = h.engine.log();
    assert!(log.iter().any(|l| l.contains("mode=Read")));
    assert!(log.iter().any(|l| l.starts_with("commit")));
    assert_eq!(h.registry.open_count(), 0);
}

#[tokio::test]
async fn columnar_endpoint_round_trips_structural_and_null_cells() {
    // A result mixing a structural (node) column, a scalar column, and a column with nulls — the
    // lossless fallback + present-bitmap paths, end to end through the router.
    let query = "MATCH (p) OPTIONAL MATCH (p)-[:R]->(m) RETURN p, p.score AS score";
    let rows: Vec<Row> = vec![
        vec![
            viz_node(1, "Person", "Ada"),
            RestValue::Value(Value::Integer(10)),
        ],
        vec![
            viz_node(2, "Person", "Bob"),
            RestValue::Value(Value::Null), // a null scalar cell
        ],
    ];
    let engine = MockEngine::new().on_query(query, canned_structural(&["p", "score"], rows));
    let h = Harness::with_engine(engine);
    let token = h.token("alice");

    let resp = h
        .send(post_json(
            "/db/neo4j/query/columnar",
            &token,
            json!({ "statements": [{ "statement": query }] }),
        ))
        .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let body = body_bytes(resp).await;

    let decoded = decode_result(&body).unwrap();
    assert_eq!(decoded.header.columns[0].codec, "json"); // structural node → fallback
    assert_eq!(decoded.header.columns[1].codec, "i64"); // scalar (+ a null) → typed i64

    // The structural cell decodes to the same Jolt node object the row-wise path emits.
    let jolt_rows = columnar_body_as_jolt_rows(&body);
    assert_eq!(jolt_rows[0][0]["id"], json!(1));
    assert_eq!(jolt_rows[0][0]["labels"], json!(["Person"]));
    assert_eq!(jolt_rows[0][0]["properties"]["name"], json!({ "U": "Ada" }));
    // The scalar column: int then null.
    assert_eq!(jolt_rows[0][1], json!({ "Z": "10" }));
    assert_eq!(jolt_rows[1][1], Json::Null);
}

#[tokio::test]
async fn columnar_endpoint_forces_read_so_a_write_is_rejected() {
    // Like graph_viz, the analytical channel forces READ — a write statement is rejected by the
    // engine and rolled back (no partial side effect), surfaced as a problem+json.
    let query = "CREATE (n:Person) RETURN n";
    let h = Harness::new(); // unscripted write query; the mock's READ tx rejects it
    let token = h.token("alice"); // alice has WRITE, but the endpoint forces READ regardless

    let resp = h
        .send(post_json(
            "/db/neo4j/query/columnar",
            &token,
            json!({ "statements": [{ "statement": query }] }),
        ))
        .await;
    // A write in a READ tx is a `GraphusError::Transaction` → 409 Conflict (the HTTP mapping every
    // REST endpoint uses for a transaction error, `06 §3.3`).
    assert_eq!(resp.status(), StatusCode::CONFLICT);
    assert_eq!(content_type(&resp), crate::problem::PROBLEM_JSON);

    // It opened a READ tx (forced) and rolled back on the write rejection.
    let log = h.engine.log();
    assert!(log.iter().any(|l| l.contains("mode=Read")));
    assert!(log.iter().any(|l| l.starts_with("rollback")));
    assert_eq!(h.registry.open_count(), 0);
}

#[tokio::test]
async fn columnar_endpoint_requires_bearer() {
    // Auth is reused unchanged: no Bearer ⇒ 401 problem+json, and the engine is never touched.
    let h = Harness::new();
    let req = Request::builder()
        .method("POST")
        .uri("/db/neo4j/query/columnar")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(
            serde_json::to_vec(&json!({ "statements": [{ "statement": "MATCH (n) RETURN n" }] }))
                .unwrap(),
        ))
        .unwrap();
    let resp = h.send(req).await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(content_type(&resp), crate::problem::PROBLEM_JSON);
    assert!(h.engine.log().is_empty());
}

#[tokio::test]
async fn columnar_endpoint_enforces_rbac_for_a_database_the_user_cannot_read() {
    // `carol` is granted READ/WRITE only on GRAPH `neo4j`; a columnar read against another database
    // is forbidden by the same coarse transaction-mode gate the other endpoints use (403), and no
    // transaction is opened.
    let h = Harness::new();
    let token = h.token("carol");
    let resp = h
        .send(post_json(
            "/db/other_db/query/columnar",
            &token,
            json!({ "statements": [{ "statement": "MATCH (n) RETURN n" }] }),
        ))
        .await;
    assert_eq!(resp.status(), StatusCode::FORBIDDEN);
    assert_eq!(content_type(&resp), crate::problem::PROBLEM_JSON);
    // The forbidden request never reached the engine (no begin).
    assert!(!h.engine.log().iter().any(|l| l.starts_with("begin")));
}

#[tokio::test]
async fn columnar_endpoint_handles_an_empty_result() {
    // A query returning no rows still produces a well-formed columnar body that decodes to zero rows.
    let query = "MATCH (n:Nonexistent) RETURN n.id AS id";
    let engine = MockEngine::new().on_query(query, canned_structural(&["id"], vec![]));
    let h = Harness::with_engine(engine);
    let token = h.token("alice");
    let resp = h
        .send(post_json(
            "/db/neo4j/query/columnar",
            &token,
            json!({ "statements": [{ "statement": query }] }),
        ))
        .await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(content_type(&resp), GCOL_RESULT_MEDIA_TYPE);
    let decoded = decode_result(&body_bytes(resp).await).unwrap();
    assert_eq!(decoded.header.row_count, 0);
    assert_eq!(decoded.header.fields, vec!["id"]);
    assert!(decoded.rows.is_empty());
}

#[tokio::test]
async fn columnar_endpoint_does_not_affect_the_json_path() {
    // Zero-regression guard: the SAME query over the row-wise JSON path yields the exact JSON it did
    // before this endpoint existed (the columnar channel is purely additive).
    let query = "RETURN 1 AS x";
    let engine = MockEngine::new().on_query(
        query,
        canned_structural(&["x"], vec![vec![RestValue::Value(Value::Integer(1))]]),
    );
    let h = Harness::with_engine(engine);
    let token = h.token("alice");
    let resp = h
        .send(post_json(
            "/db/neo4j/tx/commit",
            &token,
            json!({ "statements": [{ "statement": query }] }),
        ))
        .await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(content_type(&resp), "application/json");
    let doc = body_json(resp).await;
    assert_eq!(doc["results"][0]["fields"][0], "x");
    assert_eq!(doc["results"][0]["data"][0][0], json!({ "Z": "1" }));
}

// =============================== POST /auth/login (rmp #499) ====================================

/// A `POST /auth/login` with a JSON credential body and **no** `Authorization` header (the route is
/// the unauthenticated entry point).
fn post_login_json(username: &str, password: &str) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri("/auth/login")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(
            serde_json::to_vec(&json!({ "username": username, "password": password })).unwrap(),
        ))
        .unwrap()
}

#[tokio::test]
async fn login_returns_a_bearer_token_with_expiry() {
    let h = Harness::new();
    let resp = h.send(post_login_json("alice", ALICE_PASSWORD)).await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(content_type(&resp), "application/json");
    let body = body_json(resp).await;
    assert!(
        body["token"].as_str().is_some_and(|t| !t.is_empty()),
        "a non-empty token is returned"
    );
    assert_eq!(body["token_type"], "Bearer");
    // `expires_at_unix_secs == now_unix_secs + TTL`. The fixture clock starts at t=1s (1e9 ns), so
    // `now_unix_secs` is 1 and the expiry is `1 + DEFAULT_LOGIN_TOKEN_TTL_SECS`.
    assert_eq!(
        body["expires_at_unix_secs"].as_u64().unwrap(),
        1 + DEFAULT_LOGIN_TOKEN_TTL_SECS
    );
}

#[tokio::test]
async fn login_token_is_accepted_by_a_transactional_route() {
    // The whole point of the endpoint: a token minted from credentials authorises a real request.
    let engine = MockEngine::new().on_query(
        "RETURN 1 AS x",
        Canned::rows(&["x"], vec![vec![Value::Integer(1)]]),
    );
    let h = Harness::with_engine(engine);

    let login = body_json(h.send(post_login_json("alice", ALICE_PASSWORD)).await).await;
    let token = login["token"].as_str().unwrap().to_owned();

    // Use the minted Bearer on an auto-commit query — it must be accepted (not 401) and run.
    let resp = h
        .send(post_json(
            "/db/neo4j/tx/commit",
            &token,
            json!({ "statements": [{ "statement": "RETURN 1 AS x" }] }),
        ))
        .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let doc = body_json(resp).await;
    assert_eq!(doc["results"][0]["data"][0][0], json!({ "Z": "1" }));
}

#[tokio::test]
async fn login_wrong_password_and_unknown_user_are_the_same_uniform_401() {
    // rmp #499 (CWE-204): a wrong password and an unknown user must be INDISTINGUISHABLE — same
    // status and byte-identical body — so the endpoint is never a user-existence oracle.
    let h = Harness::new();

    let wrong_pw = h
        .send(post_login_json("alice", "not-alices-password"))
        .await;
    assert_eq!(wrong_pw.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(content_type(&wrong_pw), "application/problem+json");
    let wrong_pw_bytes = body_bytes(wrong_pw).await;

    let unknown = h.send(post_login_json("ghost", "any-password-here")).await;
    assert_eq!(unknown.status(), StatusCode::UNAUTHORIZED);
    let unknown_bytes = body_bytes(unknown).await;

    assert_eq!(
        wrong_pw_bytes, unknown_bytes,
        "the wrong-password and unknown-user 401 bodies must be byte-identical (no oracle)"
    );
    let problem: Json = serde_json::from_slice(&wrong_pw_bytes).unwrap();
    assert_eq!(problem["detail"], "invalid username or password");
    assert_eq!(problem["status"], 401);
}

#[tokio::test]
async fn login_throttle_returns_429_then_refills() {
    // rmp #458/#499: after `max_failures` failed attempts for one account, the next attempt is
    // rejected with a retriable 429 BEFORE Argon2; the bucket refills over the injected clock.
    let throttle = Arc::new(AuthThrottle::new(2, 1).expect("non-zero throttle limits"));
    let h = Harness::with_engine_cap_throttle(
        MockEngine::new(),
        crate::registry::DEFAULT_MAX_OPEN_TRANSACTIONS,
        throttle,
    );

    // Two wrong-password attempts: each reaches Argon2 and fails with the uniform 401 (and debits).
    for _ in 0..2 {
        let resp = h.send(post_login_json("alice", "wrong-password")).await;
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }
    // The third attempt is rejected up front — the bucket is empty — with a retriable 429.
    let throttled = h.send(post_login_json("alice", "wrong-password")).await;
    assert_eq!(throttled.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(content_type(&throttled), "application/problem+json");
    let problem = body_json(throttled).await;
    assert_eq!(
        problem["code"],
        "Neo.ClientError.Security.AuthenticationRateLimit"
    );

    // Advance the injected clock by one second: the bucket refills one slot (rate = 1/s), so the
    // next attempt is permitted through to the (failing) credential check again — proving the refill.
    h.clock.set(2_000_000_000); // t = 2s
    let after_refill = h.send(post_login_json("alice", "wrong-password")).await;
    assert_eq!(
        after_refill.status(),
        StatusCode::UNAUTHORIZED,
        "after the throttle window refills, the attempt reaches the credential check again (401, not 429)"
    );

    // A throttle keyed on `alice` must not bleed onto another account: `bob` is never throttled here.
    let bob = h.send(post_login_json("bob", BOB_PASSWORD)).await;
    assert_eq!(bob.status(), StatusCode::OK, "the throttle is per-account");
}

#[tokio::test]
async fn login_throttle_never_blocks_a_correct_credential() {
    // A successful login must NOT debit the bucket — a legitimate client is never throttled by its
    // own (correct) attempt rate, even repeated many times within the window.
    let throttle = Arc::new(AuthThrottle::new(2, 1).expect("non-zero throttle limits"));
    let h = Harness::with_engine_cap_throttle(
        MockEngine::new(),
        crate::registry::DEFAULT_MAX_OPEN_TRANSACTIONS,
        throttle,
    );
    for _ in 0..5 {
        let resp = h.send(post_login_json("alice", ALICE_PASSWORD)).await;
        assert_eq!(
            resp.status(),
            StatusCode::OK,
            "a correct credential is never throttled (success does not debit the bucket)"
        );
    }
}

#[tokio::test]
async fn login_malformed_body_is_400() {
    let h = Harness::new();

    // Missing required fields → a 400 problem (serde rejects the body at the decode boundary).
    let missing = Request::builder()
        .method("POST")
        .uri("/auth/login")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&json!({})).unwrap()))
        .unwrap();
    let resp = h.send(missing).await;
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    assert_eq!(content_type(&resp), "application/problem+json");

    // An empty body is likewise a 400 (unlike a statement batch, login has no valid empty form).
    let empty = Request::builder()
        .method("POST")
        .uri("/auth/login")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::empty())
        .unwrap();
    assert_eq!(h.send(empty).await.status(), StatusCode::BAD_REQUEST);

    // An undecodable Content-Type is a 415.
    let bad_ct = Request::builder()
        .method("POST")
        .uri("/auth/login")
        .header(header::CONTENT_TYPE, "text/plain")
        .body(Body::from("username=alice".as_bytes().to_vec()))
        .unwrap();
    assert_eq!(
        h.send(bad_ct).await.status(),
        StatusCode::UNSUPPORTED_MEDIA_TYPE
    );
}

#[tokio::test]
async fn login_cbor_request_and_response_round_trip() {
    let h = Harness::new();

    // Encode the credentials as a CBOR map and ask for a CBOR response.
    let mut body = Vec::new();
    ciborium::into_writer(
        &json!({ "username": "alice", "password": ALICE_PASSWORD }),
        &mut body,
    )
    .unwrap();
    let req = Request::builder()
        .method("POST")
        .uri("/auth/login")
        .header(header::CONTENT_TYPE, "application/cbor")
        .header(header::ACCEPT, "application/cbor")
        .body(Body::from(body))
        .unwrap();

    let resp = h.send(req).await;
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(content_type(&resp), "application/cbor");
    let bytes = body_bytes(resp).await;
    let decoded: LoginResponse = ciborium::from_reader(bytes.as_slice()).unwrap();
    assert_eq!(decoded.token_type, "Bearer");
    assert!(!decoded.token.is_empty());
    assert_eq!(
        decoded.expires_at_unix_secs,
        1 + DEFAULT_LOGIN_TOKEN_TTL_SECS
    );
}
