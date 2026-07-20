//! **The `rmp` #780 vector-index defect is WIRE-REACHABLE** — proven here over the real REST stack.
//!
//! The task that filed #780 recorded it as "NOT wire-reachable (server writes are Serializable)". That
//! premise is false, and this test is the evidence that it is false, which is why it exists as a
//! server-level test rather than only as a coordinator one.
//!
//! ## Why Serializability does not prevent it
//!
//! Two independent reasons, both verified against the code:
//!
//! 1. **The index build is not an SSI transaction at all.** `begin_online_vector_index_named` mints its
//!    catalog transaction by hand rather than through `begin_inner`, which is the only place that
//!    registers a transaction with the SSI tracker. It then commits the catalog and fills the HNSW
//!    *outside any transaction*, reading raw physical state (`in_use()` only — no xmin/xmax check).
//!    There is no conflict for SSI to detect, so nothing aborts.
//! 2. **A REST transaction is a detached, URL-named server-side handle.** It outlives the connection
//!    that opened it, so a client does not need two concurrent connections, or to win any race: it can
//!    open a transaction, write, leave it open, and issue the DDL as a *separate, later* request. The
//!    engine processes commands sequentially, but the open transaction sits in the Active Transaction
//!    Table across all of them, which is the whole precondition of the defect.
//!
//! The only DDL guard in the server is per-session: it rejects DDL when *the issuing session itself* is
//! inside an explicit transaction. Another transaction being open is invisible to it.
//!
//! ## What this test drives
//!
//! A **single sequential client**, no concurrency, no race:
//!
//! 1. auto-commit: seed two `:Doc` embeddings, `x` exactly on the query direction (score 1.0) and `y` at
//!    cosine 0.9 (score 0.95);
//! 2. `POST /db/graphus/tx` — open `tx-1`;
//! 3. inside `tx-1`: `SET x.embedding = [0,0,1]` — and **leave it open**;
//! 4. auto-commit: `CREATE VECTOR INDEX doc_vec …` — the production build route, driven Online;
//! 5. auto-commit: `CALL db.index.vector.queryNodes('doc_vec', 1, [1,0,0])`.
//!
//! Before the fix, step 5 returned `y` — a fresh auto-commit reader given the wrong nearest neighbour,
//! ranked by an embedding no committed transaction ever wrote. It must return `x`.

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

const JWT_SECRET: &str = "vector-uncommitted-wire-jwt-secret-min-32b!";
const ADMIN_USER: &str = "neo4j";
const DB: &str = "graphus";
const FIXED_SECS: u64 = 1_700_000_000;
const FIXED_NANOS: u64 = FIXED_SECS * 1_000_000_000;

struct FixedClock(AtomicU64);
impl Clock for FixedClock {
    fn now_nanos(&self) -> u64 {
        self.0.load(Ordering::Relaxed)
    }
}

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
            "graphus-vector-wire-{nanos}-{}",
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

fn config(temp: &TempStore) -> ServerConfig {
    ServerConfig {
        store_path: temp.path.join("store"),
        default_database: DB.to_owned(),
        buffer_pool_pages: 256,
        bolt_tcp_addr: None,
        advertised_bolt_address: None,
        bolt_server_agent: None,
        rest_addr: None,
        uds_path: Some(temp.path.join("graphus.sock")),
        tls: TlsConfig::default(),
        admission: AdmissionConfig {
            max_concurrent_queries: 8,
            engine_queue_capacity: 256,
            result_buffer_capacity: 64,
            max_open_transactions: 64,
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
            admin_password: "vector-uncommitted-wire-pw8".to_owned(),
            admin_uid: None,
            users: Vec::new(),
        },
        encryption: graphus_server::config::EncryptionConfig::default(),
        audit: AuditConfig::default(),
        allow_insecure_network: false,
        bulk_import: graphus_server::config::BulkImportConfig::default(),
        metrics_scrape_token: None,
    }
}

async fn boot(temp: &TempStore) -> (Router, String) {
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
        Arc::new(ServerConfig::default()),
        Arc::new(graphus_server::txn_registry::TransactionRegistry::new()),
    );
    let clock: Arc<dyn Clock + Send + Sync> = Arc::new(FixedClock(AtomicU64::new(FIXED_NANOS)));
    let rest_engine = Arc::new(RestEngineAdapter::new(context));
    let registry = Arc::new(TxRegistry::new(DEFAULT_TX_TTL_NANOS));
    let app = router(AppState::new(rest_engine, auth, registry, clock));
    let token = security
        .with_auth(|a| a.issue_token(ADMIN_USER, FIXED_SECS, 3600))
        .expect("issue admin token");
    drop(catalog);
    drop(security);
    (app, token)
}

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

fn post(uri: String, token: &str, body: Json) -> Request<Body> {
    Request::builder()
        .method("POST")
        .uri(uri)
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap()
}

fn statements(cypher: &str) -> Json {
    json!({ "statements": [{ "statement": cypher }] })
}

/// An auto-commit statement: `POST /db/{DB}/tx/commit`.
async fn auto_commit(app: &Router, token: &str, cypher: &str) -> (StatusCode, Json) {
    one(
        app,
        post(format!("/db/{DB}/tx/commit"), token, statements(cypher)),
    )
    .await
}

/// Opens an explicit transaction and returns its URL-name (the id the registry hands back).
async fn begin(app: &Router, token: &str) -> String {
    let (status, body) = one(app, post(format!("/db/{DB}/tx"), token, json!({}))).await;
    assert_eq!(status, StatusCode::CREATED, "BEGIN must succeed: {body}");
    // The commit URL carries the id as its LAST segment: "/db/{db}/tx/{id}".
    let commit_url = body["commit"]
        .as_str()
        .unwrap_or_else(|| panic!("BEGIN response carries a commit URL: {body}"));
    commit_url
        .rsplit('/')
        .next()
        .expect("commit URL has the shape /db/{db}/tx/{id}")
        .to_owned()
}

/// Runs a statement INSIDE the open transaction `id`, leaving it open.
async fn in_tx(app: &Router, token: &str, id: &str, cypher: &str) -> (StatusCode, Json) {
    one(
        app,
        post(format!("/db/{DB}/tx/{id}"), token, statements(cypher)),
    )
    .await
}

async fn rollback(app: &Router, token: &str, id: &str) {
    let app2 = app.clone();
    let req = Request::builder()
        .method("DELETE")
        .uri(format!("/db/{DB}/tx/{id}"))
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap();
    let _ = app2.oneshot(req).await;
}

/// The `name` column of the first data row. The REST surface emits **strict Jolt**, so a string value
/// arrives wrapped as `{"U": "..."}` rather than as a bare JSON string.
fn first_row_name(body: &Json) -> Option<String> {
    // `data` is an array of rows; each row is directly an array of Jolt-encoded cells (there is no
    // Neo4j-style `"row"` wrapper on this surface).
    let cell = &body["results"][0]["data"][0][0];
    cell.as_str()
        .or_else(|| cell["U"].as_str())
        .map(str::to_owned)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_vector_index_built_while_a_rest_transaction_holds_an_uncommitted_embedding_780() {
    let temp = TempStore::new();
    let (app, token) = boot(&temp).await;

    // 1. Seed. `x` sits exactly on the query direction; `y` is the runner-up at cosine 0.9.
    let (status, body) = auto_commit(
        &app,
        &token,
        "CREATE (:Doc {name: 'x', embedding: [1.0, 0.0, 0.0]}), \
                (:Doc {name: 'y', embedding: [0.9, 0.4358899, 0.0]})",
    )
    .await;
    assert_eq!(status, StatusCode::OK, "seed must succeed: {body}");

    // 2. Open an explicit REST transaction — a detached, URL-named server-side handle.
    let tx = begin(&app, &token).await;

    // 3. Write inside it and LEAVE IT OPEN. No commit, no second connection, no race.
    let (status, body) = in_tx(
        &app,
        &token,
        &tx,
        "MATCH (n:Doc {name: 'x'}) SET n.embedding = [0.0, 0.0, 1.0]",
    )
    .await;
    assert_eq!(status, StatusCode::OK, "in-transaction write: {body}");

    // 4. THE PRODUCTION BUILD ROUTE, as a separate later auto-commit request while `tx` is still open.
    let (status, body) = auto_commit(
        &app,
        &token,
        "CREATE VECTOR INDEX doc_vec FOR (d:Doc) ON (d.embedding) \
         OPTIONS { indexConfig: { `vector.dimensions`: 3, `vector.similarity_function`: 'cosine' } }",
    )
    .await;
    assert_eq!(status, StatusCode::OK, "CREATE VECTOR INDEX: {body}");

    // Non-vacuity: the index really was created and really is ONLINE. If it were not, the query below
    // would ERROR rather than mis-rank, and a green test would be the `rmp` #733 gate firing, not this.
    let (status, body) = auto_commit(
        &app,
        &token,
        "SHOW VECTOR INDEXES YIELD name, state RETURN name + ':' + state AS name",
    )
    .await;
    assert_eq!(status, StatusCode::OK, "SHOW VECTOR INDEXES: {body}");
    assert_eq!(
        first_row_name(&body).as_deref(),
        Some("doc_vec:ONLINE"),
        "vacuous unless the index exists and is ONLINE: {body}",
    );

    // 5. A FRESH auto-commit reader asks for the single nearest neighbour of x's committed direction.
    let (status, body) = auto_commit(
        &app,
        &token,
        "CALL db.index.vector.queryNodes('doc_vec', 1, [1.0, 0.0, 0.0]) YIELD node \
         RETURN node.name AS name",
    )
    .await;
    assert_eq!(status, StatusCode::OK, "k-NN query: {body}");
    assert_eq!(
        first_row_name(&body).as_deref(),
        Some("x"),
        "rmp #780 OVER THE WIRE: the nearest neighbour must be the COMMITTED x. Returning y means the \
         build baked the uncommitted [0,0,1] held by the still-open REST transaction, and a fresh \
         auto-commit reader was ranked by an embedding no committed transaction ever wrote: {body}",
    );

    rollback(&app, &token, &tx).await;
}
