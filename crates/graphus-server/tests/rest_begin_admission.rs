//! **REST `BEGIN` admission-permit gate** (`rmp` #448, CWE-770).
//!
//! A REST explicit transaction is stateless and URL-named: it outlives the connection that opened it
//! and (until its inactivity TTL) pins an MVCC GC-watermark snapshot, growing memory + version slots on
//! a **shared** engine. Two complementary bounds keep one authenticated principal from accumulating an
//! unbounded number of them (the `rmp` #448 slow-OOM): the registry's `max_open_transactions` cap (the
//! URL-facing bound, gated end-to-end in `graphus-rest`'s `router::tests`), and — proven here — an
//! **admission permit consumed at `BEGIN` and held for the transaction's lifetime**, so an open REST
//! transaction counts against the engine's per-database concurrency budget (`max_concurrent_queries`).
//!
//! This test boots the REAL REST stack in process (the production `graphus_rest` axum [`Router`] over a
//! real [`LocalEngine`] via the server's [`RestEngineAdapter`]) — no TLS, no socket — with a small
//! admission budget and a *large* open-transaction cap, so the **admission permit** is the binding
//! constraint. It asserts:
//!
//! * opening `max_concurrent_queries` explicit transactions succeeds, and each **holds** a permit
//!   (`graphus_admission_in_flight` rises to the budget);
//! * the next `BEGIN` is **rejected** (the budget is exhausted — the adapter's `try_admit` fails before
//!   it opens any engine transaction), with no permit leak;
//! * committing one open transaction **releases** its permit (`graphus_admission_in_flight` drops), and
//!   a fresh `BEGIN` is admitted again — proving the permit is held for the transaction's whole lifetime,
//!   not just the instant of `BEGIN`.

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use axum::Router;
use axum::body::Body;
use http::{Request, StatusCode, header};
use http_body_util::BodyExt;
use serde_json::{Value as Json, json};
use tower::ServiceExt;

use graphus_core::capability::Clock;
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

use graphus_auth::AuthProvider;
use graphus_rest::registry::TxRegistry;
use graphus_rest::router::{AppState, DEFAULT_TX_TTL_NANOS, router};

const JWT_SECRET: &str = "rest-begin-admission-jwt-secret-min-32b!";
const ADMIN_USER: &str = "neo4j";
const DB: &str = "graphus";
const FIXED_SECS: u64 = 1_700_000_000;
const FIXED_NANOS: u64 = FIXED_SECS * 1_000_000_000;

/// The small admission budget that makes the permit the binding constraint (well below the
/// open-transaction cap below). Opening this many explicit transactions exhausts the budget.
const ADMISSION_BUDGET: usize = 2;

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
        let mut path = std::env::temp_dir();
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system clock after epoch")
            .as_nanos();
        path.push(format!(
            "graphus-rest-begin-admission-{nanos}-{}",
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

/// A UDS-only config (no network listener) with a small `max_concurrent_queries`, so the admission
/// permit `BEGIN` consumes is the binding constraint (not the much-larger open-transaction cap).
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
            max_concurrent_queries: ADMISSION_BUDGET,
            engine_queue_capacity: 256,
            result_buffer_capacity: 64,
            // A large open-transaction cap so the ADMISSION permit (not the registry cap) is what bounds
            // these `BEGIN`s — this test isolates the permit mechanism.
            max_open_transactions: 1024,
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
            admin_password: "rest-begin-admission-pw8".to_owned(),
            admin_uid: None,
            users: Vec::new(),
        },
        encryption: graphus_server::config::EncryptionConfig::default(),
        audit: AuditConfig::default(),
        allow_insecure_network: false,
        metrics_scrape_token: None,
    }
}

/// Boots the real REST router over a real engine behind `RestEngineAdapter`, returning the router, a
/// valid admin Bearer token, and the shared `Metrics` (kept so the test can read
/// `graphus_admission_in_flight` to prove permits are held).
async fn boot(temp: &TempStore) -> (Router, String, Arc<Metrics>) {
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
    let app = router(AppState::new(rest_engine, auth, registry, clock));

    let token = security
        .with_auth(|a| a.issue_token(ADMIN_USER, FIXED_SECS, 3600))
        .expect("issue admin token");

    // The adapter's `AdminContext` already holds `catalog`/`security`, so dropping our local clones is
    // fine; the router keeps them alive for the test.
    drop(catalog);
    drop(security);
    (app, token, metrics)
}

/// `POST /db/{DB}/tx` with a Bearer token, on a blocking task (the adapter's begin/commit are
/// synchronous blocking submits — production drives the router on a `spawn_blocking` thread for exactly
/// this reason). Returns the response status.
async fn begin(app: &Router, token: &str) -> (StatusCode, Json) {
    one(
        app,
        Request::builder()
            .method("POST")
            .uri(format!("/db/{DB}/tx"))
            .header(header::AUTHORIZATION, format!("Bearer {token}"))
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(serde_json::to_vec(&json!({})).unwrap()))
            .unwrap(),
    )
    .await
}

/// `POST /db/{DB}/tx/{id}/commit` — finalises an open transaction (releasing its admission permit).
async fn commit(app: &Router, token: &str, id: &str) -> StatusCode {
    one(
        app,
        Request::builder()
            .method("POST")
            .uri(format!("/db/{DB}/tx/{id}/commit"))
            .header(header::AUTHORIZATION, format!("Bearer {token}"))
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(serde_json::to_vec(&json!({})).unwrap()))
            .unwrap(),
    )
    .await
    .0
}

/// Drives one request to completion on a blocking task and returns `(status, json_body)`.
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

/// The current `graphus_admission_in_flight` gauge value parsed out of the rendered exposition — the
/// number of admission permits currently held (an open REST transaction holds one for its lifetime).
fn in_flight(metrics: &Metrics) -> u64 {
    let text = metrics.render_prometheus();
    text.lines()
        .find_map(|l| l.strip_prefix("graphus_admission_in_flight "))
        .and_then(|v| v.trim().parse().ok())
        .expect("graphus_admission_in_flight is rendered")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rest_begin_consumes_and_holds_an_admission_permit() {
    let temp = TempStore::new();
    let (app, token, metrics) = boot(&temp).await;

    assert_eq!(in_flight(&metrics), 0, "no permits held before any BEGIN");

    // Open exactly the admission budget — every BEGIN succeeds and HOLDS its permit.
    let mut ids = Vec::new();
    for i in 0..ADMISSION_BUDGET {
        let (status, body) = begin(&app, &token).await;
        assert_eq!(
            status,
            StatusCode::CREATED,
            "BEGIN #{i} within the admission budget must succeed"
        );
        ids.push(body["id"].as_str().unwrap().to_owned());
        assert_eq!(
            in_flight(&metrics),
            (i + 1) as u64,
            "each open BEGIN holds an admission permit (rmp #448)"
        );
    }
    assert_eq!(
        in_flight(&metrics),
        ADMISSION_BUDGET as u64,
        "all {ADMISSION_BUDGET} open transactions hold their permits simultaneously"
    );

    // The NEXT BEGIN is rejected — the admission budget is exhausted (the adapter's `try_admit` fails
    // BEFORE opening any engine transaction). It is a retriable error class (a busy/transaction error),
    // and it leaks no permit: the in-flight count stays at the budget.
    let (status, _) = begin(&app, &token).await;
    assert!(
        status.is_client_error() || status.is_server_error(),
        "BEGIN past the admission budget must be rejected, got {status}"
    );
    assert_eq!(
        in_flight(&metrics),
        ADMISSION_BUDGET as u64,
        "a rejected BEGIN must not consume (leak) a permit"
    );

    // Committing one open transaction RELEASES its permit — proving the permit was held for the
    // transaction's lifetime, not just the instant of BEGIN.
    assert_eq!(commit(&app, &token, &ids[0]).await, StatusCode::OK);
    assert_eq!(
        in_flight(&metrics),
        (ADMISSION_BUDGET - 1) as u64,
        "committing an open transaction releases its admission permit"
    );

    // With a slot freed, a fresh BEGIN is admitted again.
    let (status, _) = begin(&app, &token).await;
    assert_eq!(
        status,
        StatusCode::CREATED,
        "a freed admission slot admits a new BEGIN (rmp #448)"
    );
    assert_eq!(in_flight(&metrics), ADMISSION_BUDGET as u64);
}
