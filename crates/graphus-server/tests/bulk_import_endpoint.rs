//! End-to-end tests for the network bulk-import streaming upload endpoint, **Mode A**
//! (`POST /admin/db/{db}/bulk-import`, `specification/08-network-bulk-import.md`, `rmp` #518/#519),
//! driven through a REAL booted [`graphus_server::Server`] over a raw HTTP/1.1 client (the same
//! no-framework socket style `db_admin_surface.rs`/`server_integration.rs` already use).
//!
//! Covers both the scaffolding-era admission/rejection surface (RBAC, format detection, byte quota,
//! now exercised through the real `?phase=nodes`/`?phase=relationships`/`?end=true` wire protocol) and
//! the real Mode A ingestion added in `rmp` #519: a full happy-path session (nodes file → relationships
//! file → end → the data is actually there and queryable, the checkpoint sentinel is gone), the
//! `Loading`-state exclusivity (a concurrent query against a loading database is rejected while an
//! unrelated database keeps serving normally), the empty-database precondition (`409` on a non-empty
//! target), and a byte-for-byte stats parity check against the offline `graphus_bulk::BulkImporter` on
//! the same dataset.

use std::path::PathBuf;
use std::time::Duration;

use graphus_bulk::{BulkImporter, DEFAULT_BATCH_SIZE, csv_to_gcol};
use graphus_io::MemBlockDevice;
use graphus_server::config::{
    AdmissionConfig, AuthBootstrap, BulkImportConfig, ServerConfig, TimingConfig, TlsConfig,
    UserBootstrap,
};
use graphus_server::{Server, ServerHandle};
use graphus_storage::RecordStore;
use graphus_wal::{MemLogSink, WalManager};
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
        bolt_server_agent: None,
        bolt_max_protocol_minor: None,
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

async fn http_request(
    addr: std::net::SocketAddr,
    method: &str,
    path: &str,
    bearer: Option<&str>,
    body_json: Option<&str>,
) -> (u16, String) {
    let mut stream = TcpStream::connect(addr).await.expect("connect REST");
    let body = body_json.unwrap_or("");
    let mut req = format!(
        "{method} {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nAccept: application/json\r\n"
    );
    if let Some(token) = bearer {
        req.push_str(&format!("Authorization: Bearer {token}\r\n"));
    }
    if body_json.is_some() {
        req.push_str("Content-Type: application/json\r\n");
    }
    req.push_str(&format!("Content-Length: {}\r\n\r\n", body.len()));
    req.push_str(body);

    stream.write_all(req.as_bytes()).await.expect("write req");
    stream.flush().await.expect("flush req");

    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).await.expect("read resp");
    parse_response(&raw)
}

/// `POST /db/{db}/tx/commit` with one statement; returns `(status, body)`.
async fn rest_statement(
    addr: std::net::SocketAddr,
    token: &str,
    db: &str,
    statement: &str,
) -> (u16, String) {
    let body = format!(r#"{{"statements":[{{"statement":"{statement}"}}]}}"#);
    http_request(
        addr,
        "POST",
        &format!("/db/{db}/tx/commit"),
        Some(token),
        Some(&body),
    )
    .await
}

/// Extracts the integer from the first Jolt `{"Z":"<n>"}` cell in `body` — sufficient for these
/// tests' single-scalar-result queries (`RETURN count(...)`).
fn extract_jolt_int(body: &str) -> Option<i64> {
    let idx = body.find("\"Z\":\"")?;
    let rest = &body[idx + 5..];
    let end = rest.find('"')?;
    rest[..end].parse().ok()
}

/// Extracts a top-level JSON integer field's value by key from the bulk-import endpoint's own plain
/// (non-Jolt) `{"nodes":N,"relationships":M,"properties":P}` response body.
fn extract_json_number(body: &str, key: &str) -> Option<u64> {
    let needle = format!("\"{key}\":");
    let start = body.find(&needle)? + needle.len();
    let rest = &body[start..];
    let end = rest
        .find(|c: char| !c.is_ascii_digit())
        .unwrap_or(rest.len());
    rest[..end].parse().ok()
}

/// Extracts a top-level JSON **string** field's value by key (e.g. Mode B's `"session":"<uuid>"`).
fn extract_json_string(body: &str, key: &str) -> Option<String> {
    let needle = format!("\"{key}\":\"");
    let start = body.find(&needle)? + needle.len();
    let rest = &body[start..];
    let end = rest.find('"')?;
    Some(rest[..end].to_owned())
}

/// One `POST /admin/db/{db}/bulk-import?{query}` call with a `Content-Length`-framed body.
async fn bulk_call(
    addr: std::net::SocketAddr,
    bearer: Option<&str>,
    db: &str,
    query: &str,
    content_type: Option<&str>,
    body: &[u8],
) -> (u16, String) {
    let mut stream = TcpStream::connect(addr).await.expect("connect REST");
    let path = if query.is_empty() {
        format!("/admin/db/{db}/bulk-import")
    } else {
        format!("/admin/db/{db}/bulk-import?{query}")
    };
    let mut req = format!(
        "POST {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nAccept: application/json\r\n"
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
        "POST /admin/db/{db}/bulk-import?phase=nodes HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nAccept: application/json\r\nAuthorization: Bearer {bearer}\r\nContent-Type: text/csv\r\nTransfer-Encoding: chunked\r\n\r\n"
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

/// A `phase=nodes` upload whose chunked body is deliberately left **unterminated** after
/// `first_chunk`, so the connection (and the server-side `Loading` claim it already made before
/// touching any body byte — see `bulk_import.rs`'s module docs) stays open until [`Self::finish`] is
/// called. Used to give a test a reliable window in which the target database is guaranteed
/// `Loading`.
struct PausedUpload {
    stream: TcpStream,
}

async fn start_paused_upload(
    addr: std::net::SocketAddr,
    bearer: &str,
    db: &str,
    first_chunk: &[u8],
) -> PausedUpload {
    let mut stream = TcpStream::connect(addr).await.expect("connect REST");
    let header = format!(
        "POST /admin/db/{db}/bulk-import?phase=nodes HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nAccept: application/json\r\nAuthorization: Bearer {bearer}\r\nContent-Type: text/csv\r\nTransfer-Encoding: chunked\r\n\r\n"
    );
    stream
        .write_all(header.as_bytes())
        .await
        .expect("write header");
    let framing = format!("{:X}\r\n", first_chunk.len());
    stream
        .write_all(framing.as_bytes())
        .await
        .expect("write chunk framing");
    stream
        .write_all(first_chunk)
        .await
        .expect("write chunk data");
    stream
        .write_all(b"\r\n")
        .await
        .expect("write chunk terminator");
    stream.flush().await.expect("flush");
    PausedUpload { stream }
}

impl PausedUpload {
    /// Sends the terminating zero-length chunk and reads the (now-complete) response.
    async fn finish(mut self) -> (u16, String) {
        self.stream
            .write_all(b"0\r\n\r\n")
            .await
            .expect("write terminating chunk");
        self.stream.flush().await.expect("flush");
        let mut raw = Vec::new();
        self.stream.read_to_end(&mut raw).await.expect("read resp");
        parse_response(&raw)
    }
}

/// Retries `attempt` (a closure returning a fresh future each call, e.g. a `rest_statement` call)
/// until it observes the expected `status`, or gives up after `tries` attempts — absorbing the
/// inherent client/server scheduling race between two independent raw-socket connections. Returns
/// the last `(status, body)` observed either way.
async fn poll_until_status<F, Fut>(mut attempt: F, expected: u16, tries: u32) -> (u16, String)
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = (u16, String)>,
{
    let mut last = (0u16, String::new());
    for _ in 0..tries {
        last = attempt().await;
        if last.0 == expected {
            return last;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    last
}

// ----------------------------------------------------------------------------------------------
// Tests: scaffolding-era admission/rejection surface, now exercised through the real wire protocol.
// ----------------------------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn missing_query_parameter_is_400() {
    let temp = TempStore::new("noquery");
    let server = boot(base_config(&temp, BulkImportConfig::default())).await;
    let rest = server.rest_addr.expect("REST enabled");
    let token = mint_token(ADMIN_USER);

    let (status, body) = bulk_call(rest, Some(&token), DB, "", Some("text/csv"), b":ID\n1\n").await;

    assert_eq!(status, 400, "body: {body}");
    assert!(body.contains("phase=nodes"), "body: {body}");

    server.shutdown().await.expect("clean shutdown");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn missing_authorization_header_is_401() {
    let temp = TempStore::new("noauth");
    let server = boot(base_config(&temp, BulkImportConfig::default())).await;
    let rest = server.rest_addr.expect("REST enabled");

    let (status, body) =
        bulk_call(rest, None, DB, "phase=nodes", Some("text/csv"), b":ID\n1\n").await;

    assert_eq!(status, 401, "body: {body}");

    server.shutdown().await.expect("clean shutdown");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn authenticated_non_admin_is_403() {
    let temp = TempStore::new("nonadmin");
    let server = boot(base_config(&temp, BulkImportConfig::default())).await;
    let rest = server.rest_addr.expect("REST enabled");
    let token = mint_token(NON_ADMIN_USER);

    let (status, body) = bulk_call(
        rest,
        Some(&token),
        DB,
        "phase=nodes",
        Some("text/csv"),
        b":ID\n1\n",
    )
    .await;

    assert_eq!(status, 403, "body: {body}");

    server.shutdown().await.expect("clean shutdown");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn unknown_content_type_is_415_with_a_clear_message() {
    let temp = TempStore::new("badformat");
    let server = boot(base_config(&temp, BulkImportConfig::default())).await;
    let rest = server.rest_addr.expect("REST enabled");
    let token = mint_token(ADMIN_USER);

    let (status, body) = bulk_call(
        rest,
        Some(&token),
        DB,
        "phase=nodes",
        Some("application/json"),
        b"{}",
    )
    .await;

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

    let (status, body) = bulk_call(
        rest,
        Some(&token),
        "does-not-exist",
        "phase=nodes",
        Some("text/csv"),
        b":ID\n1\n",
    )
    .await;

    assert_eq!(status, 404, "body: {body}");
    assert!(body.contains("does-not-exist"), "body: {body}");

    server.shutdown().await.expect("clean shutdown");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn default_database_cannot_be_bulk_imported_into() {
    let temp = TempStore::new("defaultdb");
    let server = boot(base_config(&temp, BulkImportConfig::default())).await;
    let rest = server.rest_addr.expect("REST enabled");
    let token = mint_token(ADMIN_USER);

    let (status, body) = bulk_call(
        rest,
        Some(&token),
        DB,
        "phase=nodes",
        Some("text/csv"),
        b"id:ID\n1\n",
    )
    .await;

    assert_eq!(status, 400, "body: {body}");
    assert!(body.contains("default"), "body: {body}");

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

    let (status, body) = rest_statement(rest, &token, DB, "CREATE DATABASE quotadb").await;
    assert_eq!(status, 200, "create database: {body}");

    let (status, body, sent) = oversized_streamed_upload(rest, &token, "quotadb").await;

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

// ----------------------------------------------------------------------------------------------
// Tests: real Mode A ingestion (`rmp` #519).
// ----------------------------------------------------------------------------------------------

/// A small, deterministic node file: 3 people, 2 typed properties each (6 properties).
const NODES_CSV: &str =
    "id:ID,:LABEL,name:string,age:int\n1,Person,Ada,30\n2,Person,Bob,25\n3,Person,Cy,40\n";
/// A small, deterministic relationship file joining the nodes above: 2 `KNOWS` edges, 1 typed
/// property each (2 properties).
const RELS_CSV: &str = ":START_ID,:END_ID,:TYPE,since:int\n1,2,KNOWS,2010\n2,3,KNOWS,2015\n";

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn network_mode_a_happy_path_end_to_end() {
    let temp = TempStore::new("happy");
    let server = boot(base_config(&temp, BulkImportConfig::default())).await;
    let rest = server.rest_addr.expect("REST enabled");
    let token = mint_token(ADMIN_USER);

    let (status, body) = rest_statement(rest, &token, DB, "CREATE DATABASE happydb").await;
    assert_eq!(status, 200, "create database: {body}");

    let (status, body) = bulk_call(
        rest,
        Some(&token),
        "happydb",
        "phase=nodes",
        Some("text/csv"),
        NODES_CSV.as_bytes(),
    )
    .await;
    assert_eq!(status, 200, "nodes phase: {body}");
    assert_eq!(extract_json_number(&body, "nodes"), Some(3), "body: {body}");
    assert_eq!(
        extract_json_number(&body, "relationships"),
        Some(0),
        "body: {body}"
    );

    let (status, body) = bulk_call(
        rest,
        Some(&token),
        "happydb",
        "phase=relationships",
        Some("text/csv"),
        RELS_CSV.as_bytes(),
    )
    .await;
    assert_eq!(status, 200, "relationships phase: {body}");
    assert_eq!(extract_json_number(&body, "nodes"), Some(3), "body: {body}");
    assert_eq!(
        extract_json_number(&body, "relationships"),
        Some(2),
        "body: {body}"
    );
    assert_eq!(
        extract_json_number(&body, "properties"),
        Some(8),
        "body: {body}"
    );

    let (status, body) = bulk_call(rest, Some(&token), "happydb", "end=true", None, b"").await;
    assert_eq!(status, 200, "end: {body}");
    assert_eq!(extract_json_number(&body, "nodes"), Some(3), "body: {body}");
    assert_eq!(
        extract_json_number(&body, "relationships"),
        Some(2),
        "body: {body}"
    );

    // `end_loading` leaves the database `Offline`, never straight back to `Online` (`08` §5.2) — the
    // operator must explicitly bring it back.
    let (status, body) = rest_statement(rest, &token, DB, "START DATABASE happydb").await;
    assert_eq!(status, 200, "start database: {body}");

    // The data is actually there and queryable...
    let (status, body) = rest_statement(rest, &token, "happydb", "MATCH (n) RETURN count(n)").await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(
        extract_jolt_int(&body),
        Some(3),
        "exactly the imported node count — the checkpoint sentinel must be gone: {body}"
    );
    let (status, body) =
        rest_statement(rest, &token, "happydb", "MATCH ()-[r]->() RETURN count(r)").await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(extract_jolt_int(&body), Some(2), "{body}");

    // ...and the checkpoint sentinel label itself is entirely gone (not just outnumbered).
    let (status, body) = rest_statement(
        rest,
        &token,
        "happydb",
        "MATCH (n:__graphus_bulk_import_session__) RETURN count(n)",
    )
    .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(extract_jolt_int(&body), Some(0), "{body}");

    server.shutdown().await.expect("clean shutdown");
}

/// `rmp` #598 (Finding E-5): a Mode A load abandoned with a plain **`STOP DATABASE`** (bypassing the
/// network `?end=true`, whose `End` batch is what normally deletes the sentinel) must not leak its
/// internal `__graphus_bulk_import_session__` checkpoint sentinel into the database once it is brought
/// back Online. Before the fix, `STOP DATABASE` on a `Loading` database closed the store with the
/// sentinel still present, and the next `START DATABASE` (`Offline -> Online`) exposed that internal
/// bookkeeping node to ordinary Cypher. `STOP` now sweeps it at the source (the same `End` batch the
/// endpoint runs), so a subsequent `START` opens a clean store.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn network_mode_a_stop_without_end_then_start_does_not_leak_sentinel() {
    let temp = TempStore::new("stop-no-end");
    let server = boot(base_config(&temp, BulkImportConfig::default())).await;
    let rest = server.rest_addr.expect("REST enabled");
    let token = mint_token(ADMIN_USER);

    let (status, body) = rest_statement(rest, &token, DB, "CREATE DATABASE leakdb").await;
    assert_eq!(status, 200, "create database: {body}");

    // A Mode A nodes batch creates the durable checkpoint sentinel — but we deliberately do NOT call
    // `?end=true`, leaving the database in the `Loading` state with the sentinel present.
    let (status, body) = bulk_call(
        rest,
        Some(&token),
        "leakdb",
        "phase=nodes",
        Some("text/csv"),
        NODES_CSV.as_bytes(),
    )
    .await;
    assert_eq!(status, 200, "nodes phase: {body}");
    assert_eq!(extract_json_number(&body, "nodes"), Some(3), "body: {body}");

    // Abandon the load with a plain STOP (`Loading -> Offline`), bypassing `?end=true`.
    let (status, body) = rest_statement(rest, &token, DB, "STOP DATABASE leakdb").await;
    assert_eq!(status, 200, "stop database: {body}");

    // Bring it back Online for ordinary serving.
    let (status, body) = rest_statement(rest, &token, DB, "START DATABASE leakdb").await;
    assert_eq!(status, 200, "start database: {body}");

    // The imported data survived the stop/start...
    let (status, body) = rest_statement(rest, &token, "leakdb", "MATCH (n) RETURN count(n)").await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(
        extract_jolt_int(&body),
        Some(3),
        "the imported nodes survive the stop/start: {body}"
    );

    // ...and the checkpoint sentinel was swept — it is NOT queryable after coming back Online.
    let (status, body) = rest_statement(
        rest,
        &token,
        "leakdb",
        "MATCH (n:__graphus_bulk_import_session__) RETURN count(n)",
    )
    .await;
    assert_eq!(status, 200, "{body}");
    assert_eq!(
        extract_jolt_int(&body),
        Some(0),
        "a plain STOP of a Loading database must sweep the checkpoint sentinel, never leak it into \
         the Online graph: {body}"
    );

    server.shutdown().await.expect("clean shutdown");
}

/// `rmp` #595 (Finding E-3): a `.gcol` upload is bounded by the configured decode budget. A valid
/// blob whose decoded working set fits the budget ingests normally (`200`); one that would exceed it
/// — the buffered-whole-then-transcoded `.gcol` path is where an oversized-or-adversarial upload could
/// previously drive an unbounded ~2×+ allocation and OOM-kill the server — is rejected with a clean
/// `400` **instead of crashing the process**, and the server keeps serving afterwards. This proves the
/// budget is actually plumbed end-to-end and that the rejection is graceful (availability preserved).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn network_mode_a_gcol_upload_is_bounded_by_the_decode_budget() {
    let temp = TempStore::new("gcol-budget");
    // A deliberately tiny decode budget so a modest, entirely VALID `.gcol` overshoots it in the test
    // without needing a real multi-gigabyte payload.
    let server = boot(base_config(
        &temp,
        BulkImportConfig {
            max_gcol_decoded_bytes: 4096,
            ..BulkImportConfig::default()
        },
    ))
    .await;
    let rest = server.rest_addr.expect("REST enabled");
    let token = mint_token(ADMIN_USER);

    let (status, body) = rest_statement(rest, &token, DB, "CREATE DATABASE gcoldb").await;
    assert_eq!(status, 200, "create database: {body}");

    // A small, valid nodes `.gcol` (decoded ~80 bytes, well under the 4 KiB budget) ingests fine.
    let small_gcol = csv_to_gcol(NODES_CSV.as_bytes(), b',').expect("encode small .gcol");
    let (status, body) = bulk_call(
        rest,
        Some(&token),
        "gcoldb",
        "phase=nodes",
        Some("application/vnd.graphus.gcol"),
        &small_gcol,
    )
    .await;
    assert_eq!(status, 200, "small valid .gcol must ingest: {body}");
    assert_eq!(extract_json_number(&body, "nodes"), Some(3), "body: {body}");

    // A larger — but still perfectly valid — nodes `.gcol` whose decoded size exceeds the 4 KiB budget
    // must be refused with a client-facing `400`, NOT buffered/transcoded into an OOM. (600 rows well
    // exceeds the budget's row ceiling of 4096/size_of::<Vec<u8>> ≈ 170.)
    let mut big_csv = String::from("id:ID,:LABEL,name:string,age:int\n");
    for i in 0..600 {
        big_csv.push_str(&format!("{i},Person,Name{i},{}\n", 20 + (i % 50)));
    }
    let big_gcol = csv_to_gcol(big_csv.as_bytes(), b',').expect("encode big .gcol");
    // The COMPRESSED upload is itself small — proof the guard is on the decoded size, not the upload.
    assert!(
        big_gcol.len() < 64 * 1024,
        "compressed .gcol should be small: {} bytes",
        big_gcol.len()
    );
    let (status, body) = bulk_call(
        rest,
        Some(&token),
        "gcoldb",
        "phase=nodes",
        Some("application/vnd.graphus.gcol"),
        &big_gcol,
    )
    .await;
    assert_eq!(
        status, 400,
        "an over-budget .gcol must be a clean 400, not an OOM/crash: {body}"
    );
    assert!(
        body.contains(".gcol") || body.contains("budget") || body.contains("row count"),
        "the rejection must explain the .gcol size limit: {body}"
    );

    // The server survived the over-budget rejection and keeps serving — the availability guarantee the
    // fix exists to protect. (The database is still `Loading` from the accepted small upload; an
    // unrelated database on the same server answers normally.)
    let (status, body) = rest_statement(rest, &token, DB, "RETURN 1 AS ok").await;
    assert_eq!(
        status, 200,
        "server must still serve after the rejection: {body}"
    );

    server.shutdown().await.expect("clean shutdown");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn loading_database_rejects_queries_while_an_unrelated_database_keeps_serving() {
    let temp = TempStore::new("concurrent");
    let server = boot(base_config(&temp, BulkImportConfig::default())).await;
    let rest = server.rest_addr.expect("REST enabled");
    let token = mint_token(ADMIN_USER);

    let (status, body) = rest_statement(rest, &token, DB, "CREATE DATABASE loadingdb").await;
    assert_eq!(status, 200, "create loadingdb: {body}");
    let (status, body) = rest_statement(rest, &token, DB, "CREATE DATABASE otherdb").await;
    assert_eq!(status, 200, "create otherdb: {body}");
    let (status, body) = rest_statement(rest, &token, "otherdb", "CREATE (:Seed {v: 1})").await;
    assert_eq!(status, 200, "seed otherdb: {body}");

    // Start (but do not finish) a `phase=nodes` upload against `loadingdb`. By the time the header
    // is on the wire, the server has already run the empty-database precondition check and flipped
    // `loadingdb` to `Loading` — BEFORE it ever reads a body byte (`bulk_import.rs` module docs) — so
    // a query against it while this upload is paused is guaranteed to observe the `Loading` state.
    let paused = start_paused_upload(rest, &token, "loadingdb", NODES_CSV.as_bytes()).await;

    // The loading database rejects an ordinary query with a clear "not online" class of error —
    // never a panic, a hang, or a silently-empty result. Poll briefly to absorb the inherent
    // raw-socket scheduling race between the two independent connections.
    let (status, body) = poll_until_status(
        || rest_statement(rest, &token, "loadingdb", "MATCH (n) RETURN count(n)"),
        400,
        50,
    )
    .await;
    assert_eq!(
        status, 400,
        "a Loading database must reject ordinary queries: {body}"
    );
    assert!(
        body.contains("not currently online"),
        "expected a clear not-online error: {body}"
    );

    // The unrelated database is fully unaffected throughout.
    let (status, body) = rest_statement(rest, &token, "otherdb", "MATCH (n) RETURN count(n)").await;
    assert_eq!(status, 200, "otherdb must keep serving: {body}");
    assert_eq!(extract_jolt_int(&body), Some(1), "body: {body}");

    // Finish the paused upload cleanly and end the session (good citizenship — not the assertion).
    let (status, body) = paused.finish().await;
    assert_eq!(status, 200, "finish paused upload: {body}");
    let (status, body) = bulk_call(rest, Some(&token), "loadingdb", "end=true", None, b"").await;
    assert_eq!(status, 200, "end loadingdb: {body}");

    // The unrelated database is STILL fully unaffected after the loading session ends.
    let (status, body) = rest_statement(rest, &token, "otherdb", "MATCH (n) RETURN count(n)").await;
    assert_eq!(status, 200, "otherdb must keep serving: {body}");
    assert_eq!(extract_jolt_int(&body), Some(1), "body: {body}");

    server.shutdown().await.expect("clean shutdown");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn non_empty_database_is_rejected_with_409() {
    let temp = TempStore::new("nonempty");
    let server = boot(base_config(&temp, BulkImportConfig::default())).await;
    let rest = server.rest_addr.expect("REST enabled");
    let token = mint_token(ADMIN_USER);

    let (status, body) = rest_statement(rest, &token, DB, "CREATE DATABASE fulldb").await;
    assert_eq!(status, 200, "create database: {body}");
    let (status, body) = rest_statement(rest, &token, "fulldb", "CREATE (n) RETURN n").await;
    assert_eq!(status, 200, "seed one node: {body}");

    let (status, body) = bulk_call(
        rest,
        Some(&token),
        "fulldb",
        "phase=nodes",
        Some("text/csv"),
        NODES_CSV.as_bytes(),
    )
    .await;

    assert_eq!(status, 409, "body: {body}");
    assert!(
        body.contains("empty database"),
        "message must explain Mode A requires an empty database: {body}"
    );
    assert!(
        body.contains("Mode B") || body.contains("#520"),
        "message should point at Mode B for a live database: {body}"
    );

    // The database is untouched: no session was ever begun (it stays `Online`, still resolvable
    // through the ordinary handle, still holding exactly the one seeded node).
    let (status, body) = rest_statement(rest, &token, "fulldb", "MATCH (n) RETURN count(n)").await;
    assert_eq!(status, 200, "fulldb must still be online: {body}");
    assert_eq!(extract_jolt_int(&body), Some(1), "body: {body}");

    server.shutdown().await.expect("clean shutdown");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn network_mode_a_matches_the_offline_importer_stats() {
    // (a) Offline import of the SAME dataset via `graphus_bulk::BulkImporter`.
    let device = MemBlockDevice::new(0);
    let wal = WalManager::create(MemLogSink::new()).expect("create wal");
    let store = RecordStore::create(device, wal, 64, 1).expect("create store");
    let mut importer = BulkImporter::new(store, DEFAULT_BATCH_SIZE, b',');
    importer
        .import_nodes(NODES_CSV.as_bytes())
        .expect("offline import_nodes");
    importer
        .import_relationships(RELS_CSV.as_bytes())
        .expect("offline import_relationships");
    let (_store, offline_stats) = importer.finish();

    // (b) The SAME dataset via the network Mode A endpoint.
    let temp = TempStore::new("parity");
    let server = boot(base_config(&temp, BulkImportConfig::default())).await;
    let rest = server.rest_addr.expect("REST enabled");
    let token = mint_token(ADMIN_USER);

    let (status, body) = rest_statement(rest, &token, DB, "CREATE DATABASE paritydb").await;
    assert_eq!(status, 200, "create database: {body}");
    let (status, body) = bulk_call(
        rest,
        Some(&token),
        "paritydb",
        "phase=nodes",
        Some("text/csv"),
        NODES_CSV.as_bytes(),
    )
    .await;
    assert_eq!(status, 200, "nodes phase: {body}");
    let (status, body) = bulk_call(
        rest,
        Some(&token),
        "paritydb",
        "phase=relationships",
        Some("text/csv"),
        RELS_CSV.as_bytes(),
    )
    .await;
    assert_eq!(status, 200, "relationships phase: {body}");
    let (status, end_body) = bulk_call(rest, Some(&token), "paritydb", "end=true", None, b"").await;
    assert_eq!(status, 200, "end: {end_body}");

    // (c) Byte-for-byte (well, field-for-field) parity between the two.
    assert_eq!(
        extract_json_number(&end_body, "nodes"),
        Some(offline_stats.nodes),
        "node count parity: network={end_body} offline={offline_stats:?}"
    );
    assert_eq!(
        extract_json_number(&end_body, "relationships"),
        Some(offline_stats.relationships),
        "relationship count parity: network={end_body} offline={offline_stats:?}"
    );
    assert_eq!(
        extract_json_number(&end_body, "properties"),
        Some(offline_stats.properties),
        "property count parity: network={end_body} offline={offline_stats:?}"
    );

    server.shutdown().await.expect("clean shutdown");
}

// ------------------------------------------------------------------------------------------------
// Mode B (`08` §5.3, `rmp` #520): an already-live database, concurrent, no exclusivity.
// ------------------------------------------------------------------------------------------------

/// Full Mode B session lifecycle: open against an already-**non-empty**, `Online` database (proving
/// Mode B has no empty-database precondition, unlike Mode A), nodes then relationships in the SAME
/// session (continued via `?session=<uuid>`), `end`, and the data is durably queryable — all while an
/// ordinary Cypher write against the SAME database succeeds mid-session (the core "still live" proof
/// at the REST layer, `08` §5.3's defining property).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn network_mode_b_session_lifecycle_happy_path_stays_live() {
    let temp = TempStore::new("modeb-happy");
    let server = boot(base_config(&temp, BulkImportConfig::default())).await;
    let rest = server.rest_addr.expect("REST enabled");
    let token = mint_token(ADMIN_USER);

    let (status, body) = rest_statement(rest, &token, DB, "CREATE DATABASE livedb").await;
    assert_eq!(status, 200, "create database: {body}");
    // Seed a pre-existing node BEFORE the Mode B session opens — proves Mode B has no empty-database
    // precondition (`08` §5.3: "Mode B does not require the database to be empty").
    let (status, body) = rest_statement(rest, &token, "livedb", "CREATE (:Seed {x:1})").await;
    assert_eq!(status, 200, "seed pre-existing data: {body}");

    // Open a NEW Mode B session (mode=live, no session param): a fresh id is minted.
    let (status, body) = bulk_call(
        rest,
        Some(&token),
        "livedb",
        "phase=nodes&mode=live",
        Some("text/csv"),
        NODES_CSV.as_bytes(),
    )
    .await;
    assert_eq!(status, 200, "mode=live nodes phase (open): {body}");
    assert_eq!(extract_json_number(&body, "nodes"), Some(3), "body: {body}");
    let session = extract_json_string(&body, "session").expect("a session id is returned");

    // Concurrent ordinary traffic against the SAME database succeeds WHILE the Mode B session is
    // conceptually "open" (between calls) — the defining "still live" property of Mode B.
    let (status, body) = rest_statement(rest, &token, "livedb", "MATCH (n) RETURN count(n)").await;
    assert_eq!(status, 200, "ordinary concurrent read: {body}");
    assert_eq!(
        extract_jolt_int(&body),
        Some(4),
        "ordinary read sees the seed node + the 3 just-imported nodes: {body}"
    );
    let (status, body) = rest_statement(rest, &token, "livedb", "CREATE (:Other {y:2})").await;
    assert_eq!(status, 200, "ordinary concurrent write: {body}");

    // Continue the SAME session for the relationship file, naming it explicitly.
    let (status, body) = bulk_call(
        rest,
        Some(&token),
        "livedb",
        &format!("phase=relationships&mode=live&session={session}"),
        Some("text/csv"),
        RELS_CSV.as_bytes(),
    )
    .await;
    assert_eq!(
        status, 200,
        "mode=live relationships phase (continue): {body}"
    );
    assert_eq!(extract_json_number(&body, "nodes"), Some(3), "body: {body}");
    assert_eq!(
        extract_json_number(&body, "relationships"),
        Some(2),
        "body: {body}"
    );
    assert_eq!(
        extract_json_string(&body, "session").as_deref(),
        Some(session.as_str()),
        "the SAME session id is echoed back on continuation: {body}"
    );

    // End the session.
    let (status, body) = bulk_call(
        rest,
        Some(&token),
        "livedb",
        &format!("end=true&mode=live&session={session}"),
        None,
        b"",
    )
    .await;
    assert_eq!(status, 200, "mode=live end: {body}");
    assert_eq!(extract_json_number(&body, "nodes"), Some(3), "body: {body}");
    assert_eq!(
        extract_json_number(&body, "relationships"),
        Some(2),
        "body: {body}"
    );

    // The database was NEVER taken offline (unlike Mode A) — still Online, still queryable, holding
    // exactly: 1 seed + 3 imported + 1 ordinary-concurrent-write = 5 nodes, 2 imported relationships.
    let (status, body) = rest_statement(rest, &token, "livedb", "MATCH (n) RETURN count(n)").await;
    assert_eq!(status, 200, "post-end read: {body}");
    assert_eq!(extract_jolt_int(&body), Some(5), "body: {body}");
    let (status, body) = rest_statement(
        rest,
        &token,
        "livedb",
        "MATCH ()-[r:KNOWS]->() RETURN count(r)",
    )
    .await;
    assert_eq!(status, 200, "post-end rel read: {body}");
    assert_eq!(extract_jolt_int(&body), Some(2), "body: {body}");

    // Ending again is an idempotent no-op (mirrors Mode A's `End` contract).
    let (status, body) = bulk_call(
        rest,
        Some(&token),
        "livedb",
        &format!("end=true&mode=live&session={session}"),
        None,
        b"",
    )
    .await;
    assert_eq!(status, 200, "second end is a no-op: {body}");
    assert_eq!(extract_json_number(&body, "nodes"), Some(0), "body: {body}");

    server.shutdown().await.expect("clean shutdown");
}

/// RBAC: a Mode B call is denied to an authenticated but non-admin principal, exactly like Mode A.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn network_mode_b_authenticated_non_admin_is_403() {
    let temp = TempStore::new("modeb-rbac");
    let server = boot(base_config(&temp, BulkImportConfig::default())).await;
    let rest = server.rest_addr.expect("REST enabled");
    let admin = mint_token(ADMIN_USER);
    let non_admin = mint_token(NON_ADMIN_USER);

    let (status, body) = rest_statement(rest, &admin, DB, "CREATE DATABASE rbacdb").await;
    assert_eq!(status, 200, "create database: {body}");

    let (status, body) = bulk_call(
        rest,
        Some(&non_admin),
        "rbacdb",
        "phase=nodes&mode=live",
        Some("text/csv"),
        NODES_CSV.as_bytes(),
    )
    .await;
    assert_eq!(status, 403, "body: {body}");

    server.shutdown().await.expect("clean shutdown");
}

/// An unknown/never-opened Mode B session id is a clean `409`, and the target database is
/// completely untouched.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn network_mode_b_unknown_session_is_409() {
    let temp = TempStore::new("modeb-unknown-session");
    let server = boot(base_config(&temp, BulkImportConfig::default())).await;
    let rest = server.rest_addr.expect("REST enabled");
    let token = mint_token(ADMIN_USER);

    let (status, body) = rest_statement(rest, &token, DB, "CREATE DATABASE unkdb").await;
    assert_eq!(status, 200, "create database: {body}");

    let bogus = uuid::Uuid::new_v4();
    let (status, body) = bulk_call(
        rest,
        Some(&token),
        "unkdb",
        &format!("phase=nodes&mode=live&session={bogus}"),
        Some("text/csv"),
        NODES_CSV.as_bytes(),
    )
    .await;
    assert_eq!(status, 409, "body: {body}");
    assert!(
        body.contains(&bogus.to_string()),
        "message should name the unknown session: {body}"
    );

    let (status, body) = rest_statement(rest, &token, "unkdb", "MATCH (n) RETURN count(n)").await;
    assert_eq!(
        status, 200,
        "unkdb must still be online and untouched: {body}"
    );
    assert_eq!(extract_jolt_int(&body), Some(0), "body: {body}");

    server.shutdown().await.expect("clean shutdown");
}

/// The server-wide Mode B concurrent-session cap (`08` §8) is enforced: opening one more session past
/// the configured cap is a clean `503`, and the already-open sessions are unaffected.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn network_mode_b_concurrent_session_cap_is_503() {
    let temp = TempStore::new("modeb-cap");
    let server = boot(base_config(
        &temp,
        BulkImportConfig {
            mode_b_max_concurrent_sessions: 1,
            ..BulkImportConfig::default()
        },
    ))
    .await;
    let rest = server.rest_addr.expect("REST enabled");
    let token = mint_token(ADMIN_USER);

    let (status, body) = rest_statement(rest, &token, DB, "CREATE DATABASE capdb").await;
    assert_eq!(status, 200, "create database: {body}");

    // The first session opens fine (cap == 1).
    let (status, body) = bulk_call(
        rest,
        Some(&token),
        "capdb",
        "phase=nodes&mode=live",
        Some("text/csv"),
        NODES_CSV.as_bytes(),
    )
    .await;
    assert_eq!(status, 200, "first session opens under the cap: {body}");
    let first_session = extract_json_string(&body, "session").expect("session id");

    // A second, DISTINCT session (no `session=` param — a genuinely new session) is refused: the cap
    // is already saturated by the still-open first session.
    let (status, body) = bulk_call(
        rest,
        Some(&token),
        "capdb",
        "phase=nodes&mode=live",
        Some("text/csv"),
        NODES_CSV.as_bytes(),
    )
    .await;
    assert_eq!(status, 503, "body: {body}");

    // The first session is unaffected: it can still be continued and ended normally.
    let (status, body) = bulk_call(
        rest,
        Some(&token),
        "capdb",
        &format!("end=true&mode=live&session={first_session}"),
        None,
        b"",
    )
    .await;
    assert_eq!(
        status, 200,
        "first session still usable after the cap rejection: {body}"
    );
    assert_eq!(extract_json_number(&body, "nodes"), Some(3), "body: {body}");

    server.shutdown().await.expect("clean shutdown");
}

/// Mode B requires the target database to be `Online`; a non-existent database is `404` (unchanged,
/// checked before mode/session parsing even runs), and an `Offline` database is `409`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn network_mode_b_non_online_database_is_rejected() {
    let temp = TempStore::new("modeb-offline");
    let server = boot(base_config(&temp, BulkImportConfig::default())).await;
    let rest = server.rest_addr.expect("REST enabled");
    let token = mint_token(ADMIN_USER);

    let (status, body) = rest_statement(rest, &token, DB, "CREATE DATABASE offdb").await;
    assert_eq!(status, 200, "create database: {body}");
    let (status, body) = rest_statement(rest, &token, DB, "STOP DATABASE offdb").await;
    assert_eq!(status, 200, "stop database: {body}");

    let (status, body) = bulk_call(
        rest,
        Some(&token),
        "offdb",
        "phase=nodes&mode=live",
        Some("text/csv"),
        NODES_CSV.as_bytes(),
    )
    .await;
    assert_eq!(status, 409, "body: {body}");
    assert!(
        body.contains("not online"),
        "message should explain the database is not online: {body}"
    );

    server.shutdown().await.expect("clean shutdown");
}

/// A Mode B session opened against database `A` cannot be continued via a request path naming
/// database `B` — cross-database continuation is refused (`D-multi-db` containment), and the session
/// remains usable against its own database afterward.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn network_mode_b_session_is_bound_to_its_own_database() {
    let temp = TempStore::new("modeb-crossdb");
    let server = boot(base_config(&temp, BulkImportConfig::default())).await;
    let rest = server.rest_addr.expect("REST enabled");
    let token = mint_token(ADMIN_USER);

    let (status, body) = rest_statement(rest, &token, DB, "CREATE DATABASE dba").await;
    assert_eq!(status, 200, "create dba: {body}");
    let (status, body) = rest_statement(rest, &token, DB, "CREATE DATABASE dbb").await;
    assert_eq!(status, 200, "create dbb: {body}");

    let (status, body) = bulk_call(
        rest,
        Some(&token),
        "dba",
        "phase=nodes&mode=live",
        Some("text/csv"),
        NODES_CSV.as_bytes(),
    )
    .await;
    assert_eq!(status, 200, "open against dba: {body}");
    let session = extract_json_string(&body, "session").expect("session id");

    // Continuing against `dbb` (wrong database) is refused.
    let (status, body) = bulk_call(
        rest,
        Some(&token),
        "dbb",
        &format!("phase=relationships&mode=live&session={session}"),
        Some("text/csv"),
        RELS_CSV.as_bytes(),
    )
    .await;
    assert_eq!(
        status, 409,
        "cross-database continuation must be refused: {body}"
    );

    // The session is unaffected and still usable against its OWN database.
    let (status, body) = bulk_call(
        rest,
        Some(&token),
        "dba",
        &format!("end=true&mode=live&session={session}"),
        None,
        b"",
    )
    .await;
    assert_eq!(
        status, 200,
        "session still usable against its own db: {body}"
    );
    assert_eq!(extract_json_number(&body, "nodes"), Some(3), "body: {body}");

    server.shutdown().await.expect("clean shutdown");
}
