//! **REST `POST /auth/login` over the real server stack** (`rmp` #499).
//!
//! The router tests in `graphus-rest` certify the login handler against a snapshot `Authenticator`.
//! This test closes the remaining gap: it boots the REAL REST stack in process — the production
//! `graphus_rest` axum [`Router`] over a real [`LocalEngine`] via the server's [`RestEngineAdapter`],
//! with the **live** [`LiveAuth`] over a real [`SecurityCatalog`] and the production login throttle
//! wired — and drives it with [`tower::ServiceExt::oneshot`] (the established integration style here;
//! the socket/TLS plumbing is generic and covered by the listener tests). It proves the
//! end-to-end path:
//!
//! * `POST /auth/login` with the bootstrap admin's username + password returns `200` and a
//!   [`LoginResponse`]-shaped body whose token the **live** `LiveAuth::issue_token` (the new
//!   `AuthProvider` trait method) minted through the read-locked catalog;
//! * that Bearer token is then **accepted** by a real transactional route (`/db/graphus/tx/commit`),
//!   running an actual Cypher query — so login → token → query works wire-to-wire over the real auth
//!   stack, not a mock;
//! * a wrong password and an unknown user both return the **same uniform `401`** (no user-existence
//!   oracle), proving the live `authenticate_password` path surfaces failures uniformly.

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use axum::Router;
use axum::body::Body;
use http::{Request, StatusCode, header};
use http_body_util::BodyExt;
use serde_json::{Value as Json, json};
use tower::ServiceExt;

use graphus_auth::{AuthProvider, AuthThrottle};
use graphus_core::capability::Clock;
use graphus_rest::registry::TxRegistry;
use graphus_rest::router::{AppState, DEFAULT_TX_TTL_NANOS, router};
use graphus_server::AuditConfig;
use graphus_server::admin::AdminContext;
use graphus_server::audit::AuditLog;
use graphus_server::config::{
    AdmissionConfig, AuthBootstrap, ServerConfig, TimingConfig, TlsConfig,
};
use graphus_server::dbcatalog::DatabaseCatalog;
use graphus_server::engine::RestEngineAdapter;
use graphus_server::metrics::Metrics;
use graphus_server::security::{LiveAuth, SecurityCatalog};

const JWT_SECRET: &str = "rest-login-jwt-signing-secret-min-32-bytes!";
const ADMIN_USER: &str = "neo4j";
const ADMIN_PASSWORD: &str = "rest-login-admin-pw-123";
/// The default database name (`config.rs` `DEFAULT_DATABASE_NAME`).
const DB: &str = "graphus";
const FIXED_SECS: u64 = 1_700_000_000;
const FIXED_NANOS: u64 = FIXED_SECS * 1_000_000_000;

/// A `Clock` pinned to a fixed instant so the minted token's `exp` and the router's validation clock
/// agree deterministically (no wall-clock flakiness).
struct FixedClock(AtomicU64);
impl Clock for FixedClock {
    fn now_nanos(&self) -> u64 {
        self.0.load(Ordering::Relaxed)
    }
}

/// A unique temp directory for the test's data root (auto-removed on drop).
struct TempStore {
    path: PathBuf,
}
impl TempStore {
    fn new() -> Self {
        // A monotonic per-process counter makes the path unique even when two parallel
        // tests read the *same* coarse `SystemTime` — macOS clocks can repeat an
        // `as_nanos()` value, which previously let both tests resolve the same temp dir
        // and race on the atomic `security.toml` publish (the loser saw ENOENT on
        // `rename` because the winner had already moved the shared `.tmp`).
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let mut path = std::env::temp_dir();
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system clock after epoch")
            .as_nanos();
        let seq = SEQ.fetch_add(1, Ordering::Relaxed);
        path.push(format!(
            "graphus-rest-login-{nanos}-{}-{seq}",
            std::process::id()
        ));
        std::fs::create_dir_all(&path).expect("create temp dir");
        Self { path }
    }
}
impl Drop for TempStore {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

/// A UDS-only config (no network listener) that bootstraps the admin user with a known password, so
/// `POST /auth/login` can authenticate it.
fn config(temp: &TempStore) -> ServerConfig {
    ServerConfig {
        store_path: temp.path.join("store"),
        default_database: DB.to_owned(),
        buffer_pool_pages: 256,
        bolt_tcp_addr: None,
        advertised_bolt_address: None,
        rest_addr: None,
        uds_path: Some(temp.path.join("graphus.sock")),
        tls: TlsConfig::default(),
        admission: AdmissionConfig {
            max_concurrent_queries: 16,
            engine_queue_capacity: 256,
            result_buffer_capacity: 64,
            ..AdmissionConfig::default()
        },
        timing: TimingConfig {
            slow_query_threshold_ms: 1_000,
            shutdown_drain_deadline_ms: 5_000,
            ..TimingConfig::default()
        },
        jwt_secret: JWT_SECRET.to_owned(),
        auth: AuthBootstrap {
            admin_user: ADMIN_USER.to_owned(),
            admin_password: ADMIN_PASSWORD.to_owned(),
            admin_uid: None,
            users: Vec::new(),
        },
        encryption: graphus_server::config::EncryptionConfig::default(),
        audit: AuditConfig::default(),
        allow_insecure_network: false,
        metrics_scrape_token: None,
    }
}

/// Boots the real REST router over a real engine behind `RestEngineAdapter` with the **live**
/// `LiveAuth` and the production login throttle wired (mirroring `build_rest_router`).
async fn boot(temp: &TempStore) -> Router {
    let cfg = config(temp);
    let metrics = Arc::new(Metrics::new());

    let security = Arc::new(SecurityCatalog::load(&cfg).expect("load security catalog"));
    let auth: Arc<dyn AuthProvider> = Arc::new(LiveAuth::new(Arc::clone(&security)));
    let audit = AuditLog::open(&cfg.audit, &cfg.store_path).expect("open audit log");

    let catalog =
        Arc::new(DatabaseCatalog::load(&cfg, Arc::clone(&metrics)).expect("load db catalog"));
    let handle = catalog.start_default().await.expect("start default db");

    let context = AdminContext::new(
        Arc::clone(&catalog),
        Arc::clone(&security),
        audit,
        tokio::runtime::Handle::current(),
        handle,
    );

    let clock: Arc<dyn Clock + Send + Sync> = Arc::new(FixedClock(AtomicU64::new(FIXED_NANOS)));
    let rest_engine = Arc::new(RestEngineAdapter::new(context));
    let registry = Arc::new(TxRegistry::new(DEFAULT_TX_TTL_NANOS));
    // The production login throttle (rmp #458): wired so the happy path is exercised against an
    // *enabled* throttle (a correct credential must never be throttled).
    let throttle = Arc::new(AuthThrottle::new(5, 1).expect("non-zero throttle limits"));
    let app =
        router(AppState::new(rest_engine, auth, registry, clock).with_auth_throttle(throttle));

    drop(catalog);
    drop(security);
    app
}

/// Drives one request to completion on a blocking task and returns `(status, json_body)`. The
/// adapter's begin/run/commit are synchronous blocking submits, so production drives the router on a
/// `spawn_blocking` thread; the test mirrors that to avoid parking a runtime worker.
async fn one(app: &Router, req: Request<Body>) -> (StatusCode, Json) {
    let app = app.clone();
    tokio::task::spawn_blocking(move || {
        tokio::runtime::Handle::current().block_on(async move {
            let resp = app.oneshot(req).await.unwrap();
            let status = resp.status();
            let bytes = resp.into_body().collect().await.unwrap().to_bytes();
            let json = serde_json::from_slice(&bytes).unwrap_or(Json::Null);
            (status, json)
        })
    })
    .await
    .unwrap()
}

/// `POST /auth/login` with a JSON credential body (no `Authorization` header).
async fn login(app: &Router, username: &str, password: &str) -> (StatusCode, Json) {
    one(
        app,
        Request::builder()
            .method("POST")
            .uri("/auth/login")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(
                serde_json::to_vec(&json!({ "username": username, "password": password })).unwrap(),
            ))
            .unwrap(),
    )
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn login_over_real_stack_mints_a_token_accepted_by_a_query() {
    let temp = TempStore::new();
    let app = boot(&temp).await;

    // 1) Log in with the bootstrap admin's real credentials → 200 + a Bearer token from LiveAuth.
    let (status, body) = login(&app, ADMIN_USER, ADMIN_PASSWORD).await;
    assert_eq!(status, StatusCode::OK, "valid credentials authenticate");
    assert_eq!(body["token_type"], "Bearer");
    assert_eq!(
        body["expires_at_unix_secs"].as_u64().unwrap(),
        FIXED_SECS + graphus_rest::DEFAULT_LOGIN_TOKEN_TTL_SECS
    );
    let token = body["token"]
        .as_str()
        .filter(|t| !t.is_empty())
        .expect("a non-empty Bearer token")
        .to_owned();

    // 2) Use the minted token on a REAL transactional route — it must be accepted and run the query.
    let (status, body) = one(
        &app,
        Request::builder()
            .method("POST")
            .uri(format!("/db/{DB}/tx/commit"))
            .header(header::AUTHORIZATION, format!("Bearer {token}"))
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(
                serde_json::to_vec(&json!({
                    "statements": [{ "statement": "RETURN 1 AS one" }],
                    "access_mode": "READ"
                }))
                .unwrap(),
            ))
            .unwrap(),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::OK,
        "the login-minted Bearer is accepted by a real query route"
    );
    // The int53-encoded scalar result proves the query actually executed under the token's identity.
    assert_eq!(body["results"][0]["fields"][0], "one");
    assert_eq!(body["results"][0]["data"][0][0], json!({ "Z": "1" }));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn login_wrong_password_and_unknown_user_are_the_same_401_over_real_stack() {
    let temp = TempStore::new();
    let app = boot(&temp).await;

    // A wrong password for the real admin user.
    let (wrong_status, wrong_body) = login(&app, ADMIN_USER, "definitely-not-the-password").await;
    assert_eq!(wrong_status, StatusCode::UNAUTHORIZED);
    assert_eq!(wrong_body["detail"], "invalid username or password");

    // An unknown user — the SAME uniform 401 (no user-existence oracle, CWE-204).
    let (unknown_status, unknown_body) = login(&app, "nonexistent-user", "any-password").await;
    assert_eq!(unknown_status, StatusCode::UNAUTHORIZED);
    assert_eq!(unknown_body, wrong_body, "no user-existence oracle");
}
