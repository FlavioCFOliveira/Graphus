//! End-to-end tests for the network bulk-import streaming upload endpoint
//! (`POST /admin/db/{db}/bulk-import`, `specification/08-network-bulk-import.md`, `rmp` #518),
//! driven through a REAL booted [`graphus_server::Server`] over a raw HTTP/1.1 client (the same
//! no-framework socket style `db_admin_surface.rs`/`server_integration.rs` already use).
//!
//! This is the **scaffolding** milestone (RBAC, streaming ingestion, quota, disk-space preflight,
//! session timeout, format detection, target-database validation) — it does not yet drive a real
//! `BulkImporter`/`TxnCoordinator` import, so these tests assert the admission/rejection surface,
//! not data actually landing in the graph.
//!
//! Covered: an authenticated `Admin` upload of a valid, small CSV payload succeeds (`202`); no
//! `Authorization` header is `401`; an authenticated but non-admin principal is `403`; an unknown
//! `Content-Type` is `415`; an unknown target database is `404`; and an upload streamed past a
//! (deliberately tiny, test-only) byte quota is rejected (`413`) **before** the client finishes
//! sending it — proving the server never buffers the whole oversized body (`08` §8) — using a
//! synthetic, chunked-transfer-encoded payload generated from a small reused buffer, never a real
//! file on disk.

use std::path::PathBuf;
use std::time::Duration;

use graphus_server::config::{
    AdmissionConfig, AuthBootstrap, BulkImportConfig, ServerConfig, TimingConfig, TlsConfig,
    UserBootstrap,
};
use graphus_server::{Server, ServerHandle};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

const JWT_SECRET: &str = "bulk-import-itest-jwt-secret-32-bytes!!";
const DB: &str = "graphus";
const ADMIN_USER: &str = "alice";
const NON_ADMIN_USER: &str = "bob";

/// A unique temp directory for one test's store (auto-removed on drop).
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
            "graphus-bulkimport-{tag}-{nanos}-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&path).expect("create temp dir");
        Self { path }
    }

    fn store_dir(&self) -> PathBuf {
        self.path.join("store")
    }
}

impl Drop for TempStore {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

/// REST-only (no UDS needed for these tests), non-TLS loopback (`allow_insecure_network`), the
/// `alice` admin and a non-admin `bob` (read+write only — the RBAC-boundary test).
fn base_config(temp: &TempStore, bulk_import: BulkImportConfig) -> ServerConfig {
    ServerConfig {
        store_path: temp.store_dir(),
        default_database: DB.to_owned(),
        buffer_pool_pages: 256,
        bolt_tcp_addr: None,
        advertised_bolt_address: None,
        rest_addr: Some("127.0.0.1:0".to_owned()),
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
            admin_password: "admin-pw8".to_owned(),
            admin_uid: None,
            users: vec![UserBootstrap {
                name: NON_ADMIN_USER.to_owned(),
                password: "user2-pw8".to_owned(),
            }],
        },
        encryption: graphus_server::config::EncryptionConfig::default(),
        audit: graphus_server::AuditConfig::default(),
        bulk_import,
        allow_insecure_network: true,
        metrics_scrape_token: None,
    }
}

/// Boots a server from `config` and returns its handle once ready.
async fn boot(config: ServerConfig) -> ServerHandle {
    Server::new(config)
        .start()
        .await
        .expect("server should boot")
}

/// Mints a Bearer token for `user`, signed with the shared [`JWT_SECRET`] (out-of-band token
/// issuance — the token's validity comes from the signature + expiry only; whether `user` actually
/// holds the `Admin` privilege is checked separately against the server's LIVE security catalog,
/// exactly as `db_admin_surface.rs`'s identical helper documents).
fn mint_token(user: &str) -> String {
    use graphus_auth::Authenticator;
    let mut auth = Authenticator::new(JWT_SECRET.as_bytes()).expect("JWT_SECRET is >= 32 bytes");
    auth.catalog_mut().create_user(user).expect("create user");
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock after epoch")
        .as_secs();
    auth.issue_token(user, now, 3_600).expect("issue token")
}

// ----------------------------------------------------------------------------------------------
// A tiny raw HTTP/1.1 client (no TLS, loopback only), as in `db_admin_surface.rs`.
// ----------------------------------------------------------------------------------------------

/// One small (`Content-Length`-framed) `POST /admin/db/{db}/bulk-import` request.
async fn small_upload(
    addr: std::net::SocketAddr,
    bearer: Option<&str>,
    db: &str,
    content_type: Option<&str>,
    body: &[u8],
) -> (u16, String) {
    let mut stream = TcpStream::connect(addr).await.expect("connect REST");
    let mut req = format!(
        "POST /admin/db/{db}/bulk-import HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nAccept: application/json\r\n"
    );
    if let Some(token) = bearer {
        req.push_str(&format!("Authorization: Bearer {token}\r\n"));
    }
    if let Some(ct) = content_type {
        req.push_str(&format!("Content-Type: {ct}\r\n"));
    }
    req.push_str(&format!("Content-Length: {}\r\n\r\n", body.len()));

    stream
        .write_all(req.as_bytes())
        .await
        .expect("write headers");
    stream.write_all(body).await.expect("write body");
    stream.flush().await.expect("flush");

    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).await.expect("read resp");
    parse_response(&raw)
}

/// Streams a chunked-transfer-encoded body well past any reasonable test quota, generated from a
/// single small, **reused** buffer (never a real file on disk, never a giant in-memory `Vec`), and
/// reads
/// the response **concurrently** with writing (`tokio::join!`) — so a server that aborts and closes
/// the connection mid-stream (the expected quota-exceeded behaviour) does not deadlock the test
/// waiting to finish a write the server will never read. Returns `(status, body, bytes_actually_sent)`.
async fn oversized_streamed_upload(
    addr: std::net::SocketAddr,
    bearer: &str,
    db: &str,
) -> (u16, String, u64) {
    let stream = TcpStream::connect(addr).await.expect("connect REST");
    let (mut rd, mut wr) = tokio::io::split(stream);

    let header = format!(
        "POST /admin/db/{db}/bulk-import HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nAccept: application/json\r\nAuthorization: Bearer {bearer}\r\nContent-Type: text/csv\r\nTransfer-Encoding: chunked\r\n\r\n"
    );

    // Willing to stream up to this many bytes before giving up — comfortably past any reasonable
    // test quota, but far short of anything that would stress the test host.
    const WRITE_CAP_BYTES: u64 = 64 * 1024 * 1024;
    const CHUNK_BYTES: usize = 64 * 1024;

    let writer = async move {
        if wr.write_all(header.as_bytes()).await.is_err() {
            return 0u64;
        }
        let chunk = vec![b'x'; CHUNK_BYTES]; // one small buffer, reused for every chunk
        let mut sent: u64 = 0;
        while sent < WRITE_CAP_BYTES {
            let framing = format!("{CHUNK_BYTES:X}\r\n");
            if wr.write_all(framing.as_bytes()).await.is_err()
                || wr.write_all(&chunk).await.is_err()
                || wr.write_all(b"\r\n").await.is_err()
            {
                break;
            }
            sent += chunk.len() as u64;
        }
        let _ = wr.write_all(b"0\r\n\r\n").await;
        let _ = wr.shutdown().await;
        sent
    };
    let reader = async move {
        let mut buf = Vec::new();
        let _ = rd.read_to_end(&mut buf).await;
        buf
    };

    let (sent, raw) = tokio::time::timeout(Duration::from_secs(30), async {
        tokio::join!(writer, reader)
    })
    .await
    .expect("upload did not complete within the test deadline");

    let (status, body) = parse_response(&raw);
    (status, body, sent)
}

/// Parses a raw HTTP/1.1 response into `(status, body)`.
fn parse_response(raw: &[u8]) -> (u16, String) {
    let text = String::from_utf8_lossy(raw).into_owned();
    let status = text
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let body = text
        .split_once("\r\n\r\n")
        .map(|(_, b)| b.to_owned())
        .unwrap_or_default();
    (status, body)
}

// ----------------------------------------------------------------------------------------------
// Tests
// ----------------------------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn admin_with_valid_csv_upload_is_accepted() {
    let temp = TempStore::new("happy");
    let server = boot(base_config(&temp, BulkImportConfig::default())).await;
    let rest = server.rest_addr.expect("REST enabled");
    let token = mint_token(ADMIN_USER);

    let (status, body) =
        small_upload(rest, Some(&token), DB, Some("text/csv"), b":ID\n1\n2\n").await;

    assert_eq!(status, 202, "body: {body}");
    assert!(body.contains("\"accepted_bytes\":8"), "body: {body}");
    assert!(body.contains("\"format\":\"csv\""), "body: {body}");

    server.shutdown().await.expect("clean shutdown");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn missing_authorization_header_is_401() {
    let temp = TempStore::new("noauth");
    let server = boot(base_config(&temp, BulkImportConfig::default())).await;
    let rest = server.rest_addr.expect("REST enabled");

    let (status, body) = small_upload(rest, None, DB, Some("text/csv"), b":ID\n1\n").await;

    assert_eq!(status, 401, "body: {body}");

    server.shutdown().await.expect("clean shutdown");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn authenticated_non_admin_is_403() {
    let temp = TempStore::new("nonadmin");
    let server = boot(base_config(&temp, BulkImportConfig::default())).await;
    let rest = server.rest_addr.expect("REST enabled");
    let token = mint_token(NON_ADMIN_USER);

    let (status, body) = small_upload(rest, Some(&token), DB, Some("text/csv"), b":ID\n1\n").await;

    assert_eq!(status, 403, "body: {body}");

    server.shutdown().await.expect("clean shutdown");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn unknown_content_type_is_415_with_a_clear_message() {
    let temp = TempStore::new("badformat");
    let server = boot(base_config(&temp, BulkImportConfig::default())).await;
    let rest = server.rest_addr.expect("REST enabled");
    let token = mint_token(ADMIN_USER);

    let (status, body) =
        small_upload(rest, Some(&token), DB, Some("application/json"), b"{}").await;

    assert_eq!(status, 415, "body: {body}");
    assert!(body.contains("application/json"), "body: {body}");
    assert!(body.contains("text/csv"), "body: {body}");

    server.shutdown().await.expect("clean shutdown");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn unknown_database_is_404_with_a_clear_message() {
    let temp = TempStore::new("nodb");
    let server = boot(base_config(&temp, BulkImportConfig::default())).await;
    let rest = server.rest_addr.expect("REST enabled");
    let token = mint_token(ADMIN_USER);

    let (status, body) = small_upload(
        rest,
        Some(&token),
        "does-not-exist",
        Some("text/csv"),
        b":ID\n1\n",
    )
    .await;

    assert_eq!(status, 404, "body: {body}");
    assert!(body.contains("does-not-exist"), "body: {body}");

    server.shutdown().await.expect("clean shutdown");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn upload_past_the_quota_is_rejected_without_buffering_the_whole_body() {
    let temp = TempStore::new("quota");
    // A deliberately tiny quota: the server must reject well before the client has streamed
    // anywhere near `oversized_streamed_upload`'s write cap.
    let bulk_import = BulkImportConfig {
        max_bytes_per_session: 64 * 1024,
        min_free_disk_bytes: 0, // isolate the quota behaviour from the disk-space guard
        ..BulkImportConfig::default()
    };
    let server = boot(base_config(&temp, bulk_import)).await;
    let rest = server.rest_addr.expect("REST enabled");
    let token = mint_token(ADMIN_USER);

    let (status, body, sent) = oversized_streamed_upload(rest, &token, DB).await;

    assert_eq!(status, 413, "body: {body}");
    assert!(body.contains("quota"), "body: {body}");
    // The server must have aborted the connection well before the client exhausted its write
    // budget — proof the rejection happened mid-stream, not after buffering the whole upload.
    assert!(
        sent < 32 * 1024 * 1024,
        "client sent {sent} bytes before the server aborted; expected an early, mid-stream abort"
    );

    server.shutdown().await.expect("clean shutdown");
}
