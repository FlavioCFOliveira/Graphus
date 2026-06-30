//! Hermetic cargo mirror of the `examples/knowledge-graph-rest` discovery workload (`rmp #284`).
//!
//! This is the **default-run, python-free, socket-free** counterpart of the example's stdlib
//! `data/discovery.py`: it generates the SAME deterministic, seeded knowledge graph
//! (`graphus-kg-gen`, fast profile), boots the REAL REST stack **in process** (the production
//! `graphus_rest` axum [`Router`] over a real [`LocalEngine`] via the server's
//! [`RestEngineAdapter`]), and drives it with [`tower::ServiceExt::oneshot`] — **no TLS, no socket,
//! no python, no network**. It then:
//!
//! - loads the graph over the REST auto-commit endpoint (`POST /db/{db}/tx/commit`),
//! - runs the five canonical discovery queries and asserts every answer against the generator's
//!   analytically-known `reference` subgraph (the same assertions `discovery.py` makes),
//! - streams a large result as **NDJSON** (`Accept: application/x-ndjson`) and asserts the framing,
//! - negotiates **CBOR vs JSON** (`Accept: application/cbor`) and asserts both decode to the *same
//!   logical result* — the content-negotiation proof.
//!
//! Where the shell example proves the wire path (HTTPS + Bearer-JWT over a real socket, driven by a
//! stdlib python client), this test proves the **REST router semantics + serialization** (the
//! reference answers, the NDJSON streaming framing, and the JSON/CBOR encodings) hermetically, in the
//! default `cargo test` run. The HTTPS/TLS/JWT-over-socket E2E stays in
//! `examples/knowledge-graph-rest/run.sh`, gated on `openssl`/`python3`.
//!
//! Auth is still LIVE: the request carries a real Bearer JWT minted from the live `SecurityCatalog`,
//! so the router's authentication path runs exactly as in production (an unauthenticated request is
//! also asserted to be rejected `401`).

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use axum::Router;
use axum::body::Body;
use http::{Request, StatusCode, header};
use http_body_util::BodyExt;
use serde_json::Value as Json;
use tower::ServiceExt;

use graphus_core::capability::Clock;
use graphus_kg_gen::{Profile, generate};
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

// The JWT secret must be >= 32 bytes (the catalog rejects a weak HS256 key at load).
const JWT_SECRET: &str = "kg-rest-hermetic-mirror-jwt-secret-32b!!";
const ADMIN_USER: &str = "neo4j";
const DB: &str = "graphus";
// A fixed clock instant (seconds since epoch, in nanos) — deterministic token minting + validation.
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
        let mut path = std::env::temp_dir();
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system clock after epoch")
            .as_nanos();
        path.push(format!(
            "graphus-kg-rest-mirror-{nanos}-{}",
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

/// A UDS-only config (no network listener is started — the test drives the router directly) over a
/// fresh store dir, with a real (>= 32-byte) JWT secret so live Bearer auth runs.
fn config(temp: &TempStore) -> ServerConfig {
    ServerConfig {
        store_path: temp.path.join("store"),
        default_database: DB.to_owned(),
        buffer_pool_pages: 1024,
        bolt_tcp_addr: None,
        advertised_bolt_address: None,
        rest_addr: None,
        uds_path: None,
        tls: TlsConfig::default(),
        admission: AdmissionConfig {
            max_concurrent_queries: 64,
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
            admin_password: "kg-rest-admin-pw8".to_owned(),
            admin_uid: None,
            users: Vec::new(),
        },
        encryption: graphus_server::config::EncryptionConfig::default(),
        audit: AuditConfig::default(),
        allow_insecure_network: false,
        metrics_scrape_token: None,
    }
}

/// Builds the REAL REST router (the production `graphus_rest` axum `Router`) over a real
/// `LocalEngine` behind the server's `RestEngineAdapter` — the same wiring `build_rest_router` does,
/// minus the observability/admin routes (the transactional API is what this mirror exercises). Also
/// returns a valid Bearer token for the admin user, minted from the live catalog at the fixed clock.
async fn boot_router(temp: &TempStore) -> (Router, String) {
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

    // Mint a Bearer JWT for the bootstrap admin against the fixed clock second.
    let token = security
        .with_auth(|a| a.issue_token(ADMIN_USER, FIXED_SECS, 3600))
        .expect("issue admin token");

    // Keep the catalog alive for the test's lifetime by leaking the Arc into the router's state via
    // the adapter (the adapter already holds it); `catalog` and `security` are also held by the
    // adapter's `AdminContext`, so dropping our local Arcs here is fine.
    drop(catalog);
    drop(security);
    drop(metrics);
    (app, token)
}

/// Sends one request through the router on a blocking task (the `RestEngineAdapter`'s row-pull +
/// begin/run/commit are synchronous blocking submits — production drives the router on a
/// `spawn_blocking` thread for exactly this reason, so the mirror does the same to avoid parking a
/// runtime worker on an engine call). Returns `(status, body_bytes, content_type)`.
async fn send(
    app: &Router,
    method: &str,
    path: &str,
    accept: &str,
    token: Option<&str>,
    body: Option<Vec<u8>>,
) -> (StatusCode, Vec<u8>, String) {
    let mut builder = Request::builder()
        .method(method)
        .uri(path)
        .header(header::ACCEPT, accept);
    if body.is_some() {
        builder = builder.header(header::CONTENT_TYPE, "application/json");
    }
    if let Some(t) = token {
        builder = builder.header(header::AUTHORIZATION, format!("Bearer {t}"));
    }
    let req = builder
        .body(body.map_or_else(Body::empty, Body::from))
        .expect("build request");

    let app = app.clone();
    let resp = app.oneshot(req).await.expect("router responds");
    let status = resp.status();
    let ctype = resp
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_owned();
    let bytes = resp
        .into_body()
        .collect()
        .await
        .expect("collect body")
        .to_bytes()
        .to_vec();
    (status, bytes, ctype)
}

/// Runs a batch of statements as one auto-commit transaction (`POST /db/{db}/tx/commit`).
async fn auto_commit(app: &Router, token: &str, statements: Json) -> (StatusCode, Vec<u8>) {
    let body = serde_json::to_vec(&serde_json::json!({ "statements": statements }))
        .expect("serialize statements");
    let (st, bytes, _) = send(
        app,
        "POST",
        &format!("/db/{DB}/tx/commit"),
        "application/json",
        Some(token),
        Some(body),
    )
    .await;
    (st, bytes)
}

/// Runs a single read query and returns the Jolt-decoded rows of the first result.
async fn query_rows(app: &Router, token: &str, statement: &str, params: Json) -> Vec<Vec<Json>> {
    let stmt = if params.is_null() {
        serde_json::json!({ "statement": statement })
    } else {
        serde_json::json!({ "statement": statement, "parameters": params })
    };
    let (st, body) = auto_commit(app, token, serde_json::json!([stmt])).await;
    assert_eq!(st, StatusCode::OK, "query failed: {statement}");
    let resp: Json = serde_json::from_slice(&body).expect("parse RunResponse");
    let results = resp
        .get("results")
        .and_then(Json::as_array)
        .filter(|r| !r.is_empty())
        .unwrap_or_else(|| panic!("no results in response: {resp}"));
    let data = results[0]
        .get("data")
        .and_then(Json::as_array)
        .expect("result data array");
    data.iter()
        .map(|row| {
            row.as_array()
                .expect("row is an array")
                .iter()
                .map(unjolt)
                .collect()
        })
        .collect()
}

/// Decodes a strict-Jolt sigil cell (`{"Z":"1"}` int, `{"U":"x"}` string, `{"R":"1.5"}` float,
/// `{"?":"true"}` bool) into a plain JSON scalar — the same decoding `discovery.py::unjolt` does.
fn unjolt(v: &Json) -> Json {
    if let Some(obj) = v.as_object() {
        if obj.len() == 1 {
            let (k, val) = obj.iter().next().expect("single-entry map");
            if let Some(s) = val.as_str() {
                match k.as_str() {
                    "Z" => return Json::from(s.parse::<i64>().expect("Jolt int")),
                    "R" => return Json::from(s.parse::<f64>().expect("Jolt float")),
                    "U" => return Json::from(s),
                    "?" => return Json::from(s == "true"),
                    _ => {}
                }
            }
        }
    }
    v.clone()
}

/// Splits the generator's `graph.cypher` into individual statements (comments/blank stripped).
fn parse_statements(cypher: &str) -> Vec<String> {
    let mut statements = Vec::new();
    let mut buf = String::new();
    for line in cypher.lines() {
        if line.starts_with("//") || line.trim().is_empty() {
            continue;
        }
        buf.push_str(line);
        if buf.trim_end().ends_with(';') {
            let trimmed = buf.trim_end();
            statements.push(trimmed[..trimmed.len() - 1].to_owned());
            buf.clear();
        }
    }
    statements
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn fast_profile_rest_discovery_matches_reference_with_ndjson_and_cbor() {
    let temp = TempStore::new();
    let (app, token) = boot_router(&temp).await;

    // ---- 0) Auth is enforced: no Bearer => 401 (live auth path) -------------------------------
    let (st, _, _) = send(
        &app,
        "POST",
        &format!("/db/{DB}/tx/commit"),
        "application/json",
        None,
        Some(
            serde_json::to_vec(&serde_json::json!({"statements":[{"statement":"RETURN 1"}]}))
                .unwrap(),
        ),
    )
    .await;
    assert_eq!(
        st,
        StatusCode::UNAUTHORIZED,
        "no Bearer must be rejected 401"
    );

    // ---- 1) Generate the deterministic fast-profile KG + reference subgraph -------------------
    let cfg = Profile::Fast.config();
    let dataset = generate(cfg, Profile::Fast.name());
    let reference = dataset.reference.clone();
    let cypher = dataset.to_cypher();
    let statements = parse_statements(&cypher);

    // ---- 2) Load the graph over REST: schema DDL standalone, then data in batches -------------
    // The schema DDL (CONSTRAINT/INDEX) must run as standalone auto-commit statements (admin DDL is
    // rejected inside an explicit txn — the same rule the python loader follows).
    let (ddl, data): (Vec<&String>, Vec<&String>) = statements.iter().partition(|s| {
        let u = s.trim_start().to_uppercase();
        u.starts_with("CREATE CONSTRAINT") || u.starts_with("CREATE INDEX")
    });
    for stmt in &ddl {
        let (st, body) =
            auto_commit(&app, &token, serde_json::json!([{ "statement": stmt }])).await;
        assert_eq!(
            st,
            StatusCode::OK,
            "DDL failed: {stmt}\n{}",
            String::from_utf8_lossy(&body)
        );
    }
    for chunk in data.chunks(200) {
        let stmts: Vec<Json> = chunk
            .iter()
            .map(|s| serde_json::json!({ "statement": s }))
            .collect();
        let (st, body) = auto_commit(&app, &token, Json::from(stmts)).await;
        assert_eq!(
            st,
            StatusCode::OK,
            "batch load failed: {}",
            String::from_utf8_lossy(&body)
        );
    }

    // ---- 3) Discovery queries vs the analytically-known reference -----------------------------
    // (1) Entity lookup — a concept by its unique id.
    let rows = query_rows(
        &app,
        &token,
        "MATCH (c:Concept {id:$id}) RETURN c.name AS name",
        serde_json::json!({ "id": reference.lookup_concept_id }),
    )
    .await;
    assert_eq!(
        rows[0][0],
        Json::from(reference.lookup_concept_name.clone()),
        "(1) lookup"
    );

    // (2) Multi-hop semantic traversal — concepts reachable from an author via authored documents.
    let rows = query_rows(
        &app,
        &token,
        "MATCH (a:Author {id:$id})-[:AUTHORED]->(:Document)-[:MENTIONS]->(c:Concept) \
         RETURN DISTINCT c.id AS cid ORDER BY cid",
        serde_json::json!({ "id": reference.traversal_author_id }),
    )
    .await;
    let reachable: Vec<Json> = rows.iter().map(|r| r[0].clone()).collect();
    let expected: Vec<Json> = reference
        .traversal_reachable_concept_ids
        .iter()
        .map(|s| Json::from(s.clone()))
        .collect();
    assert_eq!(reachable, expected, "(2) traversal");

    // (3) Recommendation — documents co-mentioning concepts with the seed, ranked by shared count.
    let rows = query_rows(
        &app,
        &token,
        "MATCH (seed:Document {id:$id})-[:MENTIONS]->(c:Concept)<-[:MENTIONS]-(other:Document) \
         WHERE other.id <> $id \
         RETURN other.id AS doc, count(DISTINCT c) AS shared ORDER BY shared DESC, doc ASC",
        serde_json::json!({ "id": reference.recommend_seed_document_id }),
    )
    .await;
    let recommend: Vec<(String, i64)> = rows
        .iter()
        .map(|r| {
            (
                r[0].as_str().expect("doc id").to_owned(),
                r[1].as_i64().expect("shared count"),
            )
        })
        .collect();
    let expected: Vec<(String, i64)> = reference.recommend_results.clone();
    assert_eq!(recommend, expected, "(3) recommend");

    // (4a) Aggregation — the author's document count.
    let rows = query_rows(
        &app,
        &token,
        "MATCH (a:Author {id:$id})-[:AUTHORED]->(d:Document) RETURN count(d) AS c",
        serde_json::json!({ "id": reference.agg_author_id }),
    )
    .await;
    assert_eq!(
        rows[0][0],
        Json::from(reference.agg_author_document_count),
        "(4a) author document count"
    );

    // (4b) Aggregation — the most-mentioned concept across the reference documents.
    let rows = query_rows(
        &app,
        &token,
        "MATCH (d:Document)-[m:MENTIONS]->(c:Concept) \
         WHERE d.id IN ['ref-d-0','ref-d-1','ref-d-2'] \
         RETURN c.id AS cid, sum(m.count) AS total ORDER BY total DESC, cid ASC LIMIT 1",
        Json::Null,
    )
    .await;
    assert_eq!(
        rows[0][0],
        Json::from(reference.agg_top_concept_id.clone()),
        "(4b) top concept id"
    );
    assert_eq!(
        rows[0][1],
        Json::from(reference.agg_top_concept_total_mentions),
        "(4b) top concept total"
    );

    // (5) Concept path — the shortest :RELATED_TO chain length between two concepts.
    let rows = query_rows(
        &app,
        &token,
        "MATCH p = shortestPath((a:Concept {id:$f})-[:RELATED_TO*]->(b:Concept {id:$t})) \
         RETURN length(p) AS len",
        serde_json::json!({ "f": reference.path_from_concept_id, "t": reference.path_to_concept_id }),
    )
    .await;
    assert_eq!(
        rows[0][0],
        Json::from(reference.path_length),
        "(5) concept path length"
    );

    // ---- 4) NDJSON streaming — one JSON object per line, with the (fields, rows…, summary) frame -
    let ndjson_body = serde_json::json!({
        "statements": [{ "statement": "MATCH (d:Document) RETURN d.id AS id, d.year AS year" }]
    });
    let (st, bytes, ctype) = send(
        &app,
        "POST",
        &format!("/db/{DB}/tx/commit"),
        "application/x-ndjson",
        Some(&token),
        Some(serde_json::to_vec(&ndjson_body).unwrap()),
    )
    .await;
    assert_eq!(st, StatusCode::OK, "ndjson status");
    assert_eq!(ctype, "application/x-ndjson", "ndjson content-type");
    let text = String::from_utf8(bytes).expect("ndjson is utf-8");
    let (mut n_fields, mut n_rows, mut n_summary) = (0u32, 0u32, 0u32);
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let obj: Json = serde_json::from_str(line).expect("each NDJSON line is a JSON object");
        if obj.get("fields").is_some() {
            n_fields += 1;
        } else if obj.get("row").is_some() {
            n_rows += 1;
        } else if obj.get("summary").is_some() {
            n_summary += 1;
        }
    }
    assert_eq!(n_fields, 1, "exactly one NDJSON `fields` line");
    assert_eq!(n_summary, 1, "exactly one NDJSON `summary` line");
    assert!(n_rows > 0, "NDJSON streamed at least one `row` line");

    // ---- 5) Content negotiation — JSON vs CBOR decode to the SAME logical result ---------------
    let neg_body = serde_json::json!({
        "statements": [{ "statement": "MATCH (d:Document) RETURN d.id AS id, d.year AS year" }]
    });
    let neg_bytes = serde_json::to_vec(&neg_body).unwrap();
    let (jst, jbody, jctype) = send(
        &app,
        "POST",
        &format!("/db/{DB}/tx/commit"),
        "application/json",
        Some(&token),
        Some(neg_bytes.clone()),
    )
    .await;
    let (cst, cbody, cctype) = send(
        &app,
        "POST",
        &format!("/db/{DB}/tx/commit"),
        "application/cbor",
        Some(&token),
        Some(neg_bytes),
    )
    .await;
    assert_eq!(jst, StatusCode::OK, "json status");
    assert_eq!(cst, StatusCode::OK, "cbor status");
    assert_eq!(jctype, "application/json", "json content-type");
    assert_eq!(cctype, "application/cbor", "cbor content-type");

    let json_doc: Json = serde_json::from_slice(&jbody).expect("parse JSON body");
    let cbor_doc: Json = ciborium::from_reader(cbody.as_slice()).expect("parse CBOR body");
    assert_eq!(
        cbor_doc, json_doc,
        "CBOR must decode to the SAME logical result as JSON"
    );

    // The deterministic payload-size relationship the example reports on: CBOR is more compact than
    // JSON for this result (a sanity check on the negotiation, not an exact byte assertion — the
    // exact bytes are gated by the example's committed baseline).
    assert!(
        cbody.len() < jbody.len(),
        "CBOR payload ({} B) should be smaller than JSON ({} B)",
        cbody.len(),
        jbody.len()
    );
}

/// Runs one statement auto-commit and returns its `results[0].summary` object (`{ "type", "stats" }`).
async fn statement_summary(app: &Router, token: &str, statement: &str) -> Json {
    let (st, body) = auto_commit(app, token, serde_json::json!([{ "statement": statement }])).await;
    assert_eq!(st, StatusCode::OK, "statement failed: {statement}");
    let resp: Json = serde_json::from_slice(&body).expect("parse RunResponse");
    resp.get("results")
        .and_then(Json::as_array)
        .and_then(|r| r.first())
        .and_then(|r0| r0.get("summary"))
        .cloned()
        .unwrap_or_else(|| panic!("no results[0].summary for {statement}: {resp}"))
}

/// `rmp` #513: every admin/DDL statement carries a populated result summary in the REST response —
/// `results[i].summary` reports the query `type` (`s` for a schema/system change, `r` for a `SHOW *`
/// read) and the schema/system side-effect counters as plain JSON scalars (the Neo4j HTTP-API shape:
/// `"indexes-added": 1`, `"contains-updates": true`). Before #513 the admin summary was always empty
/// (`type` null, `stats {}`) even though the change persisted.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn admin_and_ddl_result_summary_over_rest() {
    let temp = TempStore::new();
    let (app, token) = boot_router(&temp).await;

    // ---- Index DDL → type `s`, indexes-added / indexes-removed (+ contains-updates) ----
    let s = statement_summary(&app, &token, "CREATE INDEX FOR (n:Person) ON (n.name)").await;
    assert_eq!(s["type"], Json::from("s"), "CREATE INDEX is a schema write");
    assert_eq!(s["stats"]["indexes-added"], Json::from(1));
    assert_eq!(s["stats"]["contains-updates"], Json::from(true));

    let s = statement_summary(&app, &token, "DROP INDEX FOR (n:Person) ON (n.name)").await;
    assert_eq!(s["type"], Json::from("s"));
    assert_eq!(s["stats"]["indexes-removed"], Json::from(1));

    // ---- Constraint DDL → type `s`, constraints-added / constraints-removed ----
    let s = statement_summary(
        &app,
        &token,
        "CREATE CONSTRAINT uniq_email FOR (n:Person) REQUIRE n.email IS UNIQUE",
    )
    .await;
    assert_eq!(s["type"], Json::from("s"));
    assert_eq!(s["stats"]["constraints-added"], Json::from(1));
    assert!(
        s["stats"].get("indexes-added").is_none(),
        "a uniqueness constraint's backing index is NOT separately counted (Neo4j parity, rmp #513)"
    );

    let s = statement_summary(&app, &token, "DROP CONSTRAINT uniq_email").await;
    assert_eq!(s["type"], Json::from("s"));
    assert_eq!(s["stats"]["constraints-removed"], Json::from(1));

    // ---- System commands → type `s`, system-updates >= 1 (+ contains-system-updates) ----
    let s = statement_summary(&app, &token, "CREATE DATABASE sales").await;
    assert_eq!(
        s["type"],
        Json::from("s"),
        "CREATE DATABASE is a system write"
    );
    assert!(
        matches!(s["stats"]["system-updates"].as_i64(), Some(n) if n >= 1),
        "system-updates >= 1: {s}"
    );
    assert_eq!(s["stats"]["contains-system-updates"], Json::from(true));

    let s = statement_summary(&app, &token, "CREATE USER dave SET PASSWORD 'dave-pw88'").await;
    assert_eq!(s["type"], Json::from("s"));
    assert!(matches!(s["stats"]["system-updates"].as_i64(), Some(n) if n >= 1));

    // ---- Reads (`SHOW *`) → type `r`, empty stats object ----
    for show in ["SHOW INDEXES", "SHOW CONSTRAINTS", "SHOW DATABASES"] {
        let s = statement_summary(&app, &token, show).await;
        assert_eq!(s["type"], Json::from("r"), "{show} is a read");
        assert_eq!(
            s["stats"],
            serde_json::json!({}),
            "{show} reports an empty stats object"
        );
    }
}
