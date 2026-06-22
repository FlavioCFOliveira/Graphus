//! Hermetic cargo mirror of the `examples/security-multitenant` demonstration (`rmp #292`).
//!
//! This is the **default-run, python-free, Node-free, socket-free** counterpart of the example's
//! live `run.sh`. It proves — entirely in process, in the ordinary `cargo test` run — the two halves
//! of the security demonstration:
//!
//! ## 1. The RBAC allow/deny matrix over the REAL REST router
//!
//! It generates the SAME deterministic, seeded multi-tenant scenario the shell demo uses
//! (`graphus-security-gen`, fast profile: tenants/roles/users/grants + the per-`(user, tenant,
//! access_mode)` allow/deny/unauthenticated matrix), boots the REAL REST stack **in process** (the
//! production `graphus_rest` axum [`Router`] over a real `LocalEngine` via the server's
//! [`RestEngineAdapter`]), and drives it with [`tower::ServiceExt::oneshot`] — **no TLS, no socket,
//! no python, no Node, no network**. It then, exactly as `data/matrix.py` does over the wire:
//!
//! - **provisions** the tenants/roles/users/grants as the bootstrap admin (replays
//!   `provision_cypher` over `POST /db/graphus/tx/commit`),
//! - **seeds** each tenant's canary `:Secret` inside that tenant's database,
//! - drives **every** matrix cell: mints that user's own live Bearer JWT from the catalog, issues the
//!   cell's READ (`MATCH (s:Secret) RETURN s.name`, `access_mode=READ`) or WRITE
//!   (`CREATE (:RbacProbe)`) probe, and asserts the expected HTTP status — `allow ⇒ 200`,
//!   `deny ⇒ 403` (with the `Neo.ClientError.Security.Forbidden` code in the RFC-9457 body),
//!   `unauthenticated ⇒ 401`.
//!
//! The auth path is LIVE: tokens are minted from the live `SecurityCatalog`, so the router's
//! authentication + authorization runs exactly as in production. This is the in-process proof of the
//! `#287` security fix (graph-scoped RBAC over REST), held in the default test run as a regression
//! gate.
//!
//! ## 2. Encryption at rest: ciphertext-on-disk + offline key rotation + encrypted backup roundtrip
//!
//! It drives the REAL encryption-at-rest stack in process — the same one `security_verify` exercises
//! for the example, but here through `graphus-server`'s OWN direct dependencies (`graphus-crypto`
//! `EncryptedFileDevice`/`EncryptedFileLogSink`, `graphus-storage` `RecordStore` + `backup`, the
//! server's `key_rotation::rotate_master_key`), so NO dependency cycle is formed (the
//! `graphus-security-gen` `dst-repro` feature — which depends on `graphus-server` — is deliberately
//! NOT used). It asserts: a known sensitive token is **ciphertext on disk** (absent from the raw
//! encrypted store, present in a cleartext twin); an offline master-key **rotation** keeps the data
//! intact with the **old key failing closed** (a `Security` error via the KCV); and an **encrypted
//! backup roundtrips losslessly** (no plaintext in the sealed artifact, exact restore, wrong key
//! fails closed).
//!
//! Where `run.sh` proves the wire path (HTTPS + Bearer-JWT + Bolt-over-TLS + the official driver),
//! this test proves the router authorization semantics and the crypto invariants hermetically, in
//! the default `cargo test` run.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use axum::Router;
use axum::body::Body;
use http::{Request, StatusCode, header};
use http_body_util::BodyExt;
use serde_json::Value as Json;
use tower::ServiceExt;

use graphus_core::TxnId;
use graphus_core::capability::Clock;
use graphus_core::error::GraphusError;

use graphus_security_gen::{Manifest, Outcome, Profile, generate};

use graphus_server::AuditConfig;
use graphus_server::admin::AdminContext;
use graphus_server::audit::AuditLog;
use graphus_server::config::{
    AdmissionConfig, AuthBootstrap, ServerConfig, TimingConfig, TlsConfig,
};
use graphus_server::dbcatalog::{DatabaseCatalog, STORE_FILE_NAME, WAL_FILE_NAME};
use graphus_server::engine::RestEngineAdapter;
use graphus_server::key_rotation::rotate_master_key;
use graphus_server::metrics::Metrics;
use graphus_server::security::{LiveAuth, SecurityCatalog};

use graphus_auth::AuthProvider;
use graphus_rest::registry::TxRegistry;
use graphus_rest::router::{AppState, DEFAULT_TX_TTL_NANOS, router};

use graphus_crypto::{
    EncryptedFileDevice, EncryptedFileLogSink, KEY_LEN, Keyring, open_backup, random_salt,
    seal_backup,
};
use graphus_io::{BlockDevice, FileBlockDevice, PAGE_SIZE, Page};
use graphus_storage::backup::{backup_store, restore, verify_backup};
use graphus_storage::recovery::recover_device;
use graphus_storage::{Namespace, RecordStore};
use graphus_wal::{FileLogSink, MemLogSink, WalManager};

// The JWT secret must be >= 32 bytes (the catalog rejects a weak HS256 key at load).
const JWT_SECRET: &str = "sec-mt-hermetic-mirror-jwt-secret-32by!!";
const ADMIN_USER: &str = "neo4j";
const ADMIN_DB: &str = "graphus";
// A fixed clock instant (seconds since epoch, in nanos) — deterministic token minting + validation.
const FIXED_SECS: u64 = 1_700_000_000;
const FIXED_NANOS: u64 = FIXED_SECS * 1_000_000_000;

/// The known sensitive plaintext probe (matches the generator's canary `sensitive_token` for
/// tenant_a and the `security_verify` `SENSITIVE` constant).
const SENSITIVE: &str = "TENANT_A_SECRET_TOKEN";
/// Two fixed master keys for the rotation proof (deterministic — never random).
const MASTER_A: [u8; KEY_LEN] = [0xA1; KEY_LEN];
const MASTER_B: [u8; KEY_LEN] = [0xB2; KEY_LEN];

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
    fn new(tag: &str) -> Self {
        let mut path = std::env::temp_dir();
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system clock after epoch")
            .as_nanos();
        path.push(format!(
            "graphus-sec-mt-{tag}-{nanos}-{}",
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

// ====================================================================================================
// Part 1 — the RBAC allow/deny matrix through the REAL REST router.
// ====================================================================================================

/// A config with the bootstrap admin + a real (>= 32-byte) JWT secret so live Bearer auth runs. No
/// network listener is started — the test drives the router directly.
fn config(temp: &TempStore) -> ServerConfig {
    ServerConfig {
        store_path: temp.path.join("store"),
        default_database: ADMIN_DB.to_owned(),
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
            admin_password: "sec-mt-admin-pw8".to_owned(),
            admin_uid: None,
            users: Vec::new(),
        },
        encryption: graphus_server::config::EncryptionConfig::default(),
        audit: AuditConfig::default(),
        allow_insecure_network: false,
        metrics_scrape_token: None,
    }
}

/// Builds the REAL REST router over a real `LocalEngine` behind the server's `RestEngineAdapter`
/// (the same wiring `build_rest_router` does for the transactional API), and keeps the live
/// `SecurityCatalog` so the test can mint per-user Bearer tokens after provisioning.
async fn boot_router(temp: &TempStore) -> (Router, Arc<SecurityCatalog>) {
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

    drop(catalog);
    drop(metrics);
    (app, security)
}

/// Mints a live Bearer JWT for `user` from the catalog at the fixed clock second (requires the user
/// to exist — the bootstrap admin always does, the provisioned users after `CREATE USER`).
fn mint(security: &SecurityCatalog, user: &str) -> String {
    security
        .with_auth(|a| a.issue_token(user, FIXED_SECS, 3600))
        .unwrap_or_else(|e| panic!("issue token for {user}: {e}"))
}

/// Sends one request through the router (`oneshot`); returns `(status, body_text)`.
async fn send(
    app: &Router,
    db: &str,
    token: Option<&str>,
    statements: Json,
    access_mode: Option<&str>,
) -> (StatusCode, String) {
    let mut payload = serde_json::json!({ "statements": statements });
    if let Some(mode) = access_mode {
        payload["access_mode"] = Json::from(mode);
    }
    let body = serde_json::to_vec(&payload).expect("serialize request body");

    let mut builder = Request::builder()
        .method("POST")
        .uri(format!("/db/{db}/tx/commit"))
        .header(header::ACCEPT, "application/json")
        .header(header::CONTENT_TYPE, "application/json");
    if let Some(t) = token {
        builder = builder.header(header::AUTHORIZATION, format!("Bearer {t}"));
    }
    let req = builder.body(Body::from(body)).expect("build request");

    let resp = app.clone().oneshot(req).await.expect("router responds");
    let status = resp.status();
    let bytes = resp
        .into_body()
        .collect()
        .await
        .expect("collect body")
        .to_bytes()
        .to_vec();
    (status, String::from_utf8_lossy(&bytes).into_owned())
}

/// Runs one admin auto-commit statement over `/db/graphus/`, asserting 200.
async fn admin_ok(app: &Router, token: &str, statement: &str) {
    let (st, body) = send(
        app,
        ADMIN_DB,
        Some(token),
        serde_json::json!([{ "statement": statement }]),
        None,
    )
    .await;
    assert_eq!(st, StatusCode::OK, "admin DDL failed: {statement}\n{body}");
}

/// Splits a `.cypher` text into `;`-terminated statements (comments/blank lines stripped), the same
/// rule `matrix.py::parse_statements` follows.
fn parse_statements(cypher: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut buf = String::new();
    for line in cypher.lines() {
        if line.starts_with("//") || line.trim().is_empty() {
            continue;
        }
        buf.push_str(line);
        if buf.trim_end().ends_with(';') {
            let trimmed = buf.trim_end();
            out.push(trimmed[..trimmed.len() - 1].to_owned());
            buf.clear();
        }
    }
    out
}

/// The READ / WRITE probes the matrix issues per cell (identical to `matrix.py`).
const READ_PROBE: &str = "MATCH (s:Secret) RETURN s.name AS name";
const WRITE_PROBE: &str = "CREATE (:RbacProbe {ts: 1})";
/// The error code a denied operation must carry in its RFC-9457 body.
const FORBIDDEN_CODE: &str = "Neo.ClientError.Security.Forbidden";

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn fast_profile_rbac_matrix_over_rest_router_holds_every_cell() {
    let temp = TempStore::new("rbac");
    let (app, security) = boot_router(&temp).await;

    // ---- Generate the SAME deterministic fast-profile scenario the shell demo uses --------------
    let dataset = generate(Profile::Fast.config(), Profile::Fast.name());
    let manifest: &Manifest = &dataset.manifest;

    // ---- Provision tenants/roles/users/grants as the bootstrap admin (over /db/graphus/) --------
    let admin_token = mint(&security, ADMIN_USER);
    for stmt in parse_statements(&dataset.provision_cypher()) {
        admin_ok(&app, &admin_token, &stmt).await;
    }

    // ---- Seed each tenant's canary :Secret inside its own database (as the admin) ---------------
    // The matrix's READ probe reads `(:Secret)`, so each tenant needs its canary present; this is the
    // minimal seed the matrix asserts against (the full PII volume is exercised by the shell demo).
    for tenant in &manifest.tenants {
        let secret_stmt = format!("CREATE (:Secret {{name: '{}'}})", tenant.canary_secret);
        let (st, body) = send(
            &app,
            &tenant.database,
            Some(&admin_token),
            serde_json::json!([{ "statement": secret_stmt }]),
            Some("WRITE"),
        )
        .await;
        assert_eq!(
            st,
            StatusCode::OK,
            "seed {} failed: {body}",
            tenant.database
        );
    }

    // ---- Drive EVERY matrix cell and assert the expected outcome --------------------------------
    let mut allow = 0u32;
    let mut deny = 0u32;
    let mut unauth = 0u32;
    for cell in &manifest.matrix {
        let token = cell.user.as_deref().map(|u| mint(&security, u));
        let is_read = cell.access_mode == "READ";
        let (probe, mode) = if is_read {
            (READ_PROBE, "READ")
        } else {
            (WRITE_PROBE, "WRITE")
        };
        let (st, body) = send(
            &app,
            &cell.tenant,
            token.as_deref(),
            serde_json::json!([{ "statement": probe }]),
            Some(mode),
        )
        .await;

        let label = format!(
            "{:>6} {:<5} {:<9} [{:?}] — {}",
            cell.user.as_deref().unwrap_or("<anon>"),
            cell.access_mode,
            cell.tenant,
            cell.outcome,
            cell.why
        );
        match cell.outcome {
            Outcome::Allow => {
                assert_eq!(
                    st,
                    StatusCode::OK,
                    "ALLOW cell must be 200: {label}\n{body}"
                );
                allow += 1;
            }
            Outcome::Deny => {
                assert_eq!(
                    st,
                    StatusCode::FORBIDDEN,
                    "DENY cell must be 403: {label}\n{body}"
                );
                assert!(
                    body.contains(FORBIDDEN_CODE),
                    "DENY cell must carry {FORBIDDEN_CODE}: {label}\n{body}"
                );
                deny += 1;
            }
            Outcome::Unauthenticated => {
                assert_eq!(
                    st,
                    StatusCode::UNAUTHORIZED,
                    "UNAUTH cell must be 401: {label}\n{body}"
                );
                unauth += 1;
            }
        }
    }

    // The matrix is the one from the manifest: assert we actually exercised allow/deny/unauth cells
    // (so a future generator change that empties a class is caught), and the totals match the
    // committed example's evidence (7 allow, 7 deny, 1 unauth, 15 cells).
    assert_eq!(allow, 7, "allow cells");
    assert_eq!(deny, 7, "deny cells");
    assert_eq!(unauth, 1, "unauthenticated cells");
    assert_eq!(
        allow + deny + unauth,
        manifest.matrix.len() as u32,
        "every matrix cell exercised"
    );

    // ---- The #287 regression assertion, made explicit: a graph-scoped grant ALLOWS its own tenant
    // while DENYING a sibling tenant — the exact bug `#287` fixed (graph-scoped RBAC over REST was
    // false-denying every per-tenant grant). alice (reader_a: READ ON GRAPH tenant_a):
    let alice = mint(&security, "alice");
    let (allow_st, _) = send(
        &app,
        "tenant_a",
        Some(&alice),
        serde_json::json!([{ "statement": READ_PROBE }]),
        Some("READ"),
    )
    .await;
    assert_eq!(
        allow_st,
        StatusCode::OK,
        "#287: a GRAPH-scoped grant must ALLOW reads of its own tenant"
    );
    let (deny_st, deny_body) = send(
        &app,
        "tenant_b",
        Some(&alice),
        serde_json::json!([{ "statement": READ_PROBE }]),
        Some("READ"),
    )
    .await;
    assert_eq!(
        deny_st,
        StatusCode::FORBIDDEN,
        "#287: a GRAPH-scoped grant must DENY reads of a sibling tenant"
    );
    assert!(deny_body.contains(FORBIDDEN_CODE));
}

// ====================================================================================================
// Part 2 — encryption at rest: ciphertext-on-disk + offline key rotation + encrypted backup.
//
// Drives `graphus-server`'s OWN direct deps (graphus-crypto + graphus-storage + key_rotation), the
// SAME stack `security_verify` proves for the example, but WITHOUT the `graphus-security-gen`
// `dst-repro` feature (which depends on `graphus-server` and would form a cycle).
// ====================================================================================================

type EncFileStore = RecordStore<EncryptedFileDevice, EncryptedFileLogSink>;
type MemStore = RecordStore<graphus_io::MemBlockDevice, MemLogSink>;

/// Writes the shared "secret graph": two nodes, one `LINKS` rel, the sensitive token interned as a
/// label on node `a` (so its plaintext bytes land on a device page).
fn write_secret_graph<D: BlockDevice, S: graphus_wal::LogSink>(
    store: &mut RecordStore<D, S>,
) -> (u64, u64, u64, u32) {
    let txn = TxnId(1);
    store.begin(txn);
    let secret_label = store
        .intern_token(Namespace::Label, SENSITIVE)
        .expect("intern label");
    let (a, _) = store.create_node(txn).expect("create node a");
    store.add_label(txn, a, secret_label).expect("add label");
    let (b, _) = store.create_node(txn).expect("create node b");
    let rt = store
        .intern_token(Namespace::RelType, "LINKS")
        .expect("intern reltype");
    let (r, _) = store.create_rel(txn, rt, a, b).expect("create rel");
    store.commit(txn).expect("commit");
    (a, b, r, rt)
}

/// Substring search over raw bytes.
fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    needle.len() <= haystack.len() && haystack.windows(needle.len()).any(|w| w == needle)
}

/// Opens the encrypted store under `master` (recover the WAL onto the device, then open), or returns
/// an error (a wrong key fails closed via the KCV).
fn open_enc_store(
    store_path: &Path,
    wal_path: &Path,
    master: &[u8; KEY_LEN],
) -> graphus_core::error::Result<EncFileStore> {
    let header = EncryptedFileDevice::read_file_header(store_path)?;
    let kr = Keyring::from_master_key(*master, &header.salt);
    let mut device = EncryptedFileDevice::open_file(store_path, &kr)?;
    let wal_backing = FileLogSink::open(wal_path).map_err(wal_err)?;
    let recovery_sink = EncryptedFileLogSink::open(wal_backing, &kr)?;
    let mut wal = WalManager::open(recovery_sink).map_err(wal_err)?;
    recover_device(&mut wal, &mut device)?;
    let wal_backing2 = FileLogSink::open(wal_path).map_err(wal_err)?;
    let serving_sink = EncryptedFileLogSink::open(wal_backing2, &kr)?;
    let wal = WalManager::open(serving_sink).map_err(wal_err)?;
    RecordStore::open(device, wal, 64)
}

/// Snapshots every decrypted page of the encrypted store under `master`.
fn decrypted_pages(
    store_path: &Path,
    master: &[u8; KEY_LEN],
) -> graphus_core::error::Result<Vec<Page>> {
    let header = EncryptedFileDevice::read_file_header(store_path)?;
    let kr = Keyring::from_master_key(*master, &header.salt);
    let device = EncryptedFileDevice::open_file(store_path, &kr)?;
    let count = device.page_count();
    let mut out = Vec::with_capacity(count as usize);
    for p in 0..count {
        let mut buf: Page = [0u8; PAGE_SIZE];
        device.read_page(graphus_core::PageId(p), &mut buf)?;
        out.push(buf);
    }
    Ok(out)
}

/// Order-independent fingerprint of a store's live nodes + rels.
fn node_rel_summary<D: BlockDevice>(store: &mut RecordStore<D, MemLogSink>) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let mut id = 1u64;
    while let Ok(rec) = store.node(id) {
        if rec.mvcc.in_use() {
            out.push(format!("N:{}", rec.element_id.0));
        }
        id += 1;
    }
    let mut id = 1u64;
    while let Ok(rec) = store.rel(id) {
        if rec.mvcc.in_use() {
            out.push(format!(
                "R:{}:{}:{}:{}",
                rec.element_id.0, rec.type_id, rec.start_node, rec.end_node
            ));
        }
        id += 1;
    }
    out.sort();
    out
}

fn wal_err(e: impl std::fmt::Display) -> GraphusError {
    GraphusError::Storage(format!("wal: {e}"))
}

#[test]
fn encryption_at_rest_ciphertext_rotation_backup_roundtrip() {
    let temp = TempStore::new("crypto");
    let enc_dir = temp.path.join("enc");
    let clear_dir = temp.path.join("clear");
    std::fs::create_dir_all(&enc_dir).expect("mk enc dir");
    std::fs::create_dir_all(&clear_dir).expect("mk clear dir");

    let enc_store = enc_dir.join(STORE_FILE_NAME);
    let enc_wal = enc_dir.join(WAL_FILE_NAME);
    let clear_store = clear_dir.join(STORE_FILE_NAME);
    let clear_wal = clear_dir.join(WAL_FILE_NAME);

    // ---- Proof 1: ciphertext on disk (encrypted absent / cleartext present) ---------------------
    let (a, b, r, rt) = {
        let salt = random_salt();
        let kr = Keyring::from_master_key(MASTER_A, &salt);
        let device = EncryptedFileDevice::create_file(&enc_store, &kr, salt).expect("create enc");
        let wal_backing = FileLogSink::open(&enc_wal).expect("open enc wal");
        let wal = WalManager::create(
            EncryptedFileLogSink::create(wal_backing, &kr).expect("enc wal sink"),
        )
        .expect("wal mgr");
        let mut store: EncFileStore = RecordStore::create(device, wal, 64, 1).expect("enc store");
        let handles = write_secret_graph(&mut store);
        store.flush().expect("flush enc");
        handles
    };
    {
        let device = FileBlockDevice::open(&clear_store).expect("open clear dev");
        let wal_backing = FileLogSink::open(&clear_wal).expect("open clear wal");
        let wal = WalManager::create(wal_backing).expect("clear wal mgr");
        let mut store: RecordStore<FileBlockDevice, FileLogSink> =
            RecordStore::create(device, wal, 64, 1).expect("clear store");
        write_secret_graph(&mut store);
        store.flush().expect("flush clear");
    }

    let enc_bytes = std::fs::read(&enc_store).expect("read enc store");
    let clear_bytes = std::fs::read(&clear_store).expect("read clear store");
    assert!(
        contains(&clear_bytes, SENSITIVE.as_bytes()),
        "ciphertext proof not meaningful: token absent from the CLEARTEXT store"
    );
    assert!(
        !contains(&enc_bytes, SENSITIVE.as_bytes()),
        "PLAINTEXT LEAK: the sensitive token is present in the raw ENCRYPTED store"
    );

    // ---- Proof 2: offline key rotation (data intact across; old key fails closed) ---------------
    let before = decrypted_pages(&enc_store, &MASTER_A).expect("pages before rotation");
    rotate_master_key(&enc_dir, &enc_store, &enc_wal, &MASTER_A, &MASTER_B).expect("rotate");

    // The NEW key opens it and the secret graph is intact.
    {
        let store = open_enc_store(&enc_store, &enc_wal, &MASTER_B).expect("open under new key");
        assert!(
            store.node(a).expect("node a").mvcc.in_use()
                && store.node(b).expect("node b").mvcc.in_use(),
            "a node is not live after rotation"
        );
        assert_eq!(
            store.incident_rels(a).expect("incidence a"),
            vec![r],
            "incidence changed after rotation"
        );
        assert_eq!(
            store.token_id(Namespace::RelType, "LINKS"),
            Some(rt),
            "rel-type token changed after rotation"
        );
        assert!(
            store.token_id(Namespace::Label, SENSITIVE).is_some(),
            "the sensitive label token did not survive rotation"
        );
    }
    // Decrypted page images are byte-for-byte identical across the rotation.
    let after = decrypted_pages(&enc_store, &MASTER_B).expect("pages after rotation");
    assert_eq!(before, after, "rotation changed the decrypted page images");
    // The OLD key now fails closed (a Security error via the KCV).
    match open_enc_store(&enc_store, &enc_wal, &MASTER_A) {
        Ok(_) => panic!("SECURITY BUG: the OLD key still opens the store after rotation"),
        Err(GraphusError::Security(_)) => {}
        Err(other) => panic!("old key must fail via the KCV (Security), got: {other}"),
    }
    // The sensitive token is still absent from the re-keyed store bytes.
    let enc_after = std::fs::read(&enc_store).expect("read re-keyed store");
    assert!(
        !contains(&enc_after, SENSITIVE.as_bytes()),
        "PLAINTEXT LEAK: the sensitive token appeared in the re-keyed store"
    );

    // ---- Proof 3: encrypted backup roundtrip (no plaintext sealed; lossless restore) ------------
    let mut src: MemStore = {
        let device = graphus_io::MemBlockDevice::new(0);
        let wal = WalManager::create(MemLogSink::new()).expect("mem wal");
        let mut store: MemStore = RecordStore::create(device, wal, 64, 1).expect("mem store");
        write_secret_graph(&mut store);
        store
    };
    let src_snapshot = node_rel_summary(&mut src);

    let artifact = backup_store(&mut src).expect("backup");
    assert!(
        contains(&artifact, SENSITIVE.as_bytes()),
        "the PLAINTEXT backup artifact must carry the secret (that is WHY it must be sealed)"
    );
    let sealed = seal_backup(&artifact, &MASTER_A).expect("seal");
    assert!(
        !contains(&sealed, SENSITIVE.as_bytes()),
        "PLAINTEXT LEAK: the sealed backup contains the sensitive token"
    );
    let prefix = &artifact[..artifact.len().min(64)];
    assert!(
        !contains(&sealed, prefix),
        "PLAINTEXT LEAK: the sealed backup contains a verbatim prefix of the plaintext artifact"
    );

    let opened = open_backup(&sealed, &MASTER_A).expect("open sealed");
    assert_eq!(
        opened, artifact,
        "open_backup did not recover the exact artifact"
    );
    verify_backup(&opened).expect("verify backup");
    let mut restored: MemStore = restore(
        &opened,
        WalManager::create(MemLogSink::new()).expect("restore wal"),
        64,
    )
    .expect("restore");
    assert_eq!(
        src_snapshot,
        node_rel_summary(&mut restored),
        "restored graph differs from the original (backup is NOT lossless)"
    );
    // A wrong key must fail closed.
    match open_backup(&sealed, &MASTER_B) {
        Ok(_) => panic!("SECURITY BUG: a wrong master key opened the sealed backup"),
        Err(GraphusError::Security(_)) => {}
        Err(other) => panic!("wrong key on sealed backup must fail Security, got: {other}"),
    }
}
