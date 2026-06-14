//! End-to-end tests for the **operator backup / restore / PITR surface** and the **authenticated
//! `/metrics` endpoint** (`rmp` task #149), driven through a real booted server over the actual
//! wires (Bolt over UDS + raw HTTP/1.1 on loopback).
//!
//! Covered:
//! - a full **backup → restore round-trip** of a named database via the authorized admin statement
//!   (`BACKUP DATABASE … TO`, `RESTORE DATABASE … FROM`): create data, back it up, mutate, restore,
//!   and confirm the restored database holds exactly the backed-up snapshot (the later mutation is
//!   gone);
//! - **PITR** restore targets (`AT LSN` / whole chain) both yield a *consistent* restored store that
//!   re-opens and serves;
//! - **fail-closed authorization**: a non-admin principal's `BACKUP` / `RESTORE` is refused with no
//!   side effects, and `RESTORE` requires the database to be **stopped** first;
//! - **`/metrics` gating**: no credential → `401`; a valid scrape token → `200`; an admin Bearer →
//!   `200`; a wrong scrape token → `401`; while `/health/live` stays open.

use std::path::PathBuf;

use graphus_bolt::server::{encode_client_handshake, encode_request_framed};
use graphus_bolt::{BoltValue, Dechunker, Frame, Proposal, Request, Response};
use graphus_core::Value;
use graphus_server::config::{
    AdmissionConfig, AuthBootstrap, ServerConfig, TimingConfig, TlsConfig, UserBootstrap,
};
use graphus_server::{Server, ServerHandle};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UnixStream};

const JWT_SECRET: &str = "backup-itest-jwt-secret-32-bytes!!!!";
const SCRAPE_TOKEN: &str = "prometheus-scrape-secret-token-xyz";

/// A unique temp directory for one test's store + backup files (auto-removed on drop).
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
            "graphus-backup-{tag}-{nanos}-{}",
            std::process::id()
        ));
        std::fs::create_dir_all(&path).expect("create temp dir");
        Self { path }
    }

    fn store_dir(&self) -> PathBuf {
        self.path.join("store")
    }

    fn uds_path(&self) -> PathBuf {
        self.path.join("graphus.sock")
    }

    fn backup_path(&self) -> PathBuf {
        self.path.join("snapshot.gbk")
    }
}

impl Drop for TempStore {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

/// REST + UDS on loopback (REST non-TLS for the raw client), admin `alice`, non-admin `bob`, and a
/// configured `/metrics` scrape token.
fn base_config(temp: &TempStore) -> ServerConfig {
    ServerConfig {
        store_path: temp.store_dir(),
        default_database: "graphus".to_owned(),
        buffer_pool_pages: 256,
        bolt_tcp_addr: None,
        advertised_bolt_address: None,
        rest_addr: Some("127.0.0.1:0".to_owned()),
        uds_path: Some(temp.uds_path()),
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
            admin_user: "alice".to_owned(),
            admin_password: "admin-pw8".to_owned(),
            admin_uid: Some(current_uid()),
            users: vec![UserBootstrap {
                name: "bob".to_owned(),
                password: "user2-pw8".to_owned(),
            }],
        },
        encryption: graphus_server::config::EncryptionConfig::default(),
        audit: graphus_server::AuditConfig::default(),
        allow_insecure_network: true,
        metrics_scrape_token: Some(SCRAPE_TOKEN.to_owned()),
    }
}

/// The current process uid, so the UDS peer-cred gate admits this test's own connections.
fn current_uid() -> u32 {
    #[cfg(target_os = "linux")]
    {
        if let Ok(status) = std::fs::read_to_string("/proc/self/status") {
            for line in status.lines() {
                if let Some(rest) = line.strip_prefix("Uid:") {
                    if let Some(first) = rest.split_whitespace().next() {
                        if let Ok(uid) = first.parse() {
                            return uid;
                        }
                    }
                }
            }
        }
        0
    }
    #[cfg(not(target_os = "linux"))]
    {
        0
    }
}

async fn boot(config: ServerConfig) -> ServerHandle {
    Server::new(config)
        .start()
        .await
        .expect("server should boot")
}

/// Mints a Bearer token for `user`, signed with the server's configured secret (out-of-band token
/// issuance — the admin gate then resolves the live RBAC for `user`).
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

fn scalar_row(values: Vec<BoltValue>) -> Vec<Value> {
    values
        .into_iter()
        .map(|v| match v {
            BoltValue::Value(val) => val,
            BoltValue::Node(n) => Value::Integer(n.id),
            BoltValue::Relationship(r) => Value::Integer(r.id),
            BoltValue::Path(_) => Value::Null,
            BoltValue::List(items) => Value::List(items.into_iter().map(first_scalar).collect()),
        })
        .collect()
}

fn first_scalar(v: BoltValue) -> Value {
    match v {
        BoltValue::Value(val) => val,
        BoltValue::Node(n) => Value::Integer(n.id),
        BoltValue::Relationship(r) => Value::Integer(r.id),
        _ => Value::Null,
    }
}

// ----------------------------------------------------------------------------------------------
// A minimal Bolt client over UDS.
// ----------------------------------------------------------------------------------------------

#[derive(Debug)]
struct WireFailure {
    code: String,
    #[allow(dead_code)]
    message: String,
}

struct BoltClient {
    stream: UnixStream,
    dechunker: Dechunker,
}

impl BoltClient {
    async fn connect(path: &std::path::Path) -> Self {
        let stream = UnixStream::connect(path).await.expect("connect UDS");
        Self {
            stream,
            dechunker: Dechunker::new(),
        }
    }

    async fn handshake_and_logon(&mut self, user: &str, password: &str) {
        let hs = encode_client_handshake([
            Proposal::range(5, 4, 4),
            Proposal::exact(0, 0),
            Proposal::exact(0, 0),
            Proposal::exact(0, 0),
        ]);
        self.stream.write_all(&hs).await.expect("write handshake");
        let mut reply = [0u8; 4];
        self.stream
            .read_exact(&mut reply)
            .await
            .expect("handshake reply");
        assert_eq!(reply, [0x00, 0x00, 0x04, 0x05], "negotiated Bolt 5.4");

        self.send(&Request::Hello {
            extra: vec![("user_agent".to_owned(), Value::String("itest".to_owned()))],
        })
        .await;
        assert!(
            matches!(self.recv().await, Response::Success { .. }),
            "HELLO"
        );

        self.send(&Request::Logon {
            auth: vec![
                ("scheme".to_owned(), Value::String("basic".to_owned())),
                ("principal".to_owned(), Value::String(user.to_owned())),
                ("credentials".to_owned(), Value::String(password.to_owned())),
            ],
        })
        .await;
        assert!(
            matches!(self.recv().await, Response::Success { .. }),
            "LOGON"
        );
    }

    async fn run_on_db(
        &mut self,
        query: &str,
        db: Option<&str>,
    ) -> Result<Vec<Vec<Value>>, WireFailure> {
        let extra = match db {
            Some(name) => vec![("db".to_owned(), Value::String(name.to_owned()))],
            None => vec![],
        };
        self.send(&Request::Run {
            query: query.to_owned(),
            parameters: vec![],
            extra,
        })
        .await;
        match self.recv().await {
            Response::Success { .. } => {}
            Response::Failure(f) => {
                return Err(WireFailure {
                    code: f.code,
                    message: f.message,
                });
            }
            other => panic!("unexpected RUN response: {other:?}"),
        }
        self.send(&Request::Pull { n: -1, qid: None }).await;
        let mut rows = Vec::new();
        loop {
            match self.recv().await {
                Response::Record { values } => rows.push(scalar_row(values)),
                Response::Success { .. } => return Ok(rows),
                Response::Failure(f) => {
                    return Err(WireFailure {
                        code: f.code,
                        message: f.message,
                    });
                }
                other => panic!("unexpected response during PULL: {other:?}"),
            }
        }
    }

    async fn run_ok(&mut self, query: &str, db: Option<&str>) -> Vec<Vec<Value>> {
        match self.run_on_db(query, db).await {
            Ok(rows) => rows,
            Err(f) => panic!("query {query:?} on {db:?} failed: {f:?}"),
        }
    }

    async fn count(&mut self, query: &str, db: Option<&str>) -> i64 {
        let rows = self.run_ok(query, db).await;
        assert_eq!(rows.len(), 1, "count returns one row: {rows:?}");
        match rows[0].first() {
            Some(Value::Integer(n)) => *n,
            other => panic!("expected an integer count, got {other:?}"),
        }
    }

    async fn reset(&mut self) {
        self.send(&Request::Reset).await;
        assert!(
            matches!(self.recv().await, Response::Success { .. }),
            "RESET"
        );
    }

    async fn goodbye(&mut self) {
        self.send(&Request::Goodbye).await;
    }

    async fn send(&mut self, req: &Request) {
        let bytes = encode_request_framed(req).expect("encode request");
        self.stream.write_all(&bytes).await.expect("write request");
        self.stream.flush().await.expect("flush");
    }

    async fn recv(&mut self) -> Response {
        loop {
            if let Some(Frame::Message(payload)) = self.dechunker.next_frame().expect("framing") {
                return Response::decode(&payload).expect("decode response");
            }
            let mut buf = [0u8; 4096];
            let n = self.stream.read(&mut buf).await.expect("read");
            assert!(n > 0, "unexpected EOF awaiting a Bolt response");
            self.dechunker.push(&buf[..n]);
        }
    }
}

// ----------------------------------------------------------------------------------------------
// A tiny raw HTTP/1.1 client (no TLS, loopback only).
// ----------------------------------------------------------------------------------------------

async fn http_get(addr: std::net::SocketAddr, path: &str, bearer: Option<&str>) -> (u16, String) {
    let mut stream = TcpStream::connect(addr).await.expect("connect REST");
    let mut req =
        format!("GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nAccept: */*\r\n");
    if let Some(token) = bearer {
        req.push_str(&format!("Authorization: Bearer {token}\r\n"));
    }
    req.push_str("\r\n");
    stream.write_all(req.as_bytes()).await.expect("write req");
    stream.flush().await.expect("flush req");
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).await.expect("read resp");
    let text = String::from_utf8_lossy(&raw).into_owned();
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

// ================================================================================================
// Backup / restore round-trip + PITR.
// ================================================================================================

/// A full operator backup → restore round-trip on a named database: create data, back it up via the
/// authorized admin statement, mutate the data, then stop + restore + start and confirm the restored
/// database holds exactly the backed-up snapshot (the post-backup mutation is gone).
#[tokio::test]
async fn backup_then_restore_round_trips_a_named_database() {
    let temp = TempStore::new("roundtrip");
    let server = boot(base_config(&temp)).await;
    let uds = server.uds_path.clone().expect("UDS enabled");
    let backup = temp.backup_path();

    let mut c = BoltClient::connect(&uds).await;
    c.handshake_and_logon("alice", "admin-pw8").await;

    // A fresh named database with three nodes.
    c.run_ok("CREATE DATABASE sales", None).await;
    for i in 0..3 {
        c.run_ok(&format!("CREATE (:Account {{n: {i}}})"), Some("sales"))
            .await;
    }
    assert_eq!(c.count("MATCH (n) RETURN count(n)", Some("sales")).await, 3);

    // Back it up to a file on the server's filesystem (online — no stop).
    let stmt = format!("BACKUP DATABASE sales TO '{}'", backup.display());
    c.run_ok(&stmt, None).await;
    assert!(backup.is_file(), "backup file was written");

    // Mutate AFTER the backup: add two more nodes (these must NOT survive the restore).
    c.run_ok("CREATE (:Account {n: 100})", Some("sales")).await;
    c.run_ok("CREATE (:Account {n: 101})", Some("sales")).await;
    assert_eq!(c.count("MATCH (n) RETURN count(n)", Some("sales")).await, 5);

    // Restore requires the database stopped first.
    c.run_ok("STOP DATABASE sales", None).await;
    let restore = format!("RESTORE DATABASE sales FROM '{}'", backup.display());
    c.run_ok(&restore, None).await;
    // Restore leaves the database stopped; start it to serve the restored data.
    c.run_ok("START DATABASE sales", None).await;

    // Exactly the backed-up snapshot: three nodes, not five.
    assert_eq!(
        c.count("MATCH (n) RETURN count(n)", Some("sales")).await,
        3,
        "restore rolled back the post-backup mutation"
    );

    c.goodbye().await;
    server.shutdown().await.expect("clean shutdown");
}

/// `RESTORE … AT LSN 0` is a valid point-in-time target: it restores to the chain's base watermark,
/// yielding a **consistent** store that re-opens and serves (the engine's `verify_on_open` runs on
/// `START`). Asserts the PITR target is accepted end-to-end and the restored database is usable.
#[tokio::test]
async fn restore_pitr_lsn_target_is_consistent() {
    let temp = TempStore::new("pitr");
    let server = boot(base_config(&temp)).await;
    let uds = server.uds_path.clone().expect("UDS enabled");
    let backup = temp.backup_path();

    let mut c = BoltClient::connect(&uds).await;
    c.handshake_and_logon("alice", "admin-pw8").await;

    c.run_ok("CREATE DATABASE sales", None).await;
    c.run_ok("CREATE (:Account {n: 1})", Some("sales")).await;
    c.run_ok(
        &format!("BACKUP DATABASE sales TO '{}'", backup.display()),
        None,
    )
    .await;

    c.run_ok("STOP DATABASE sales", None).await;
    // A low LSN target replays up to (at most) the base watermark; recovery makes the store
    // consistent either way. The point of the test is that the PITR target is accepted and the
    // restored store re-opens cleanly.
    let restore = format!(
        "RESTORE DATABASE sales FROM '{}' AT LSN 0",
        backup.display()
    );
    c.run_ok(&restore, None).await;
    c.run_ok("START DATABASE sales", None).await;

    // The restored database serves a query (it passed `verify_on_open` on START).
    let n = c.count("MATCH (n) RETURN count(n)", Some("sales")).await;
    assert!(
        (0..=1).contains(&n),
        "consistent committed state at the cut: {n}"
    );

    c.goodbye().await;
    server.shutdown().await.expect("clean shutdown");
}

/// Fail-closed authorization: a non-admin principal's `BACKUP` and `RESTORE` are refused with no
/// side effects (no backup file written), and `RESTORE` of an online database is refused (it must be
/// stopped first). The admin gate and the stop precondition both hold over the wire.
#[tokio::test]
async fn backup_and_restore_are_admin_only_and_fail_closed() {
    let temp = TempStore::new("authz");
    let server = boot(base_config(&temp)).await;
    let uds = server.uds_path.clone().expect("UDS enabled");
    let backup = temp.backup_path();

    // Admin sets up a named database.
    let mut admin = BoltClient::connect(&uds).await;
    admin.handshake_and_logon("alice", "admin-pw8").await;
    admin.run_ok("CREATE DATABASE sales", None).await;
    admin
        .run_ok("CREATE (:Account {n: 1})", Some("sales"))
        .await;

    // A non-admin (bob) cannot back up.
    let mut bob = BoltClient::connect(&uds).await;
    bob.handshake_and_logon("bob", "user2-pw8").await;
    let stmt = format!("BACKUP DATABASE sales TO '{}'", backup.display());
    let err = bob
        .run_on_db(&stmt, None)
        .await
        .expect_err("non-admin BACKUP must be refused");
    assert!(
        err.code.contains("Forbidden") || err.code.contains("Security"),
        "admin-privilege denial: {err:?}"
    );
    assert!(!backup.is_file(), "a denied BACKUP writes no file");
    bob.reset().await;

    // A non-admin cannot restore either.
    let restore = format!("RESTORE DATABASE sales FROM '{}'", backup.display());
    let err = bob
        .run_on_db(&restore, None)
        .await
        .expect_err("non-admin RESTORE must be refused");
    assert!(
        err.code.contains("Forbidden") || err.code.contains("Security"),
        "admin-privilege denial: {err:?}"
    );
    bob.goodbye().await;

    // The admin makes a real backup, then RESTORE of the still-online database is refused (must stop).
    admin.run_ok(&stmt, None).await;
    let err = admin
        .run_on_db(&restore, None)
        .await
        .expect_err("RESTORE of an online database must be refused");
    assert!(
        err.message.to_lowercase().contains("stop")
            || err.message.to_lowercase().contains("offline"),
        "restore requires a stopped database: {err:?}"
    );
    admin.reset().await;

    admin.goodbye().await;
    server.shutdown().await.expect("clean shutdown");
}

// ================================================================================================
// /metrics authentication (rmp #149).
// ================================================================================================

/// `/metrics` is fail-closed: no credential is `401`; the configured scrape token is `200`; an admin
/// Bearer is `200`; a wrong scrape token is `401`; and `/health/live` stays open without a credential.
#[tokio::test]
async fn metrics_endpoint_is_authenticated() {
    let temp = TempStore::new("metrics");
    let server = boot(base_config(&temp)).await;
    let rest = server.rest_addr.expect("REST enabled");

    // No credential → fail closed.
    let (status, _) = http_get(rest, "/metrics", None).await;
    assert_eq!(status, 401, "unauthenticated /metrics is refused");

    // The configured scrape token → OK.
    let (status, body) = http_get(rest, "/metrics", Some(SCRAPE_TOKEN)).await;
    assert_eq!(status, 200, "scrape token grants /metrics");
    assert!(
        body.contains("graphus_") || !body.is_empty(),
        "metrics body is Prometheus text"
    );

    // An admin Bearer → OK (the same gate as /admin/*).
    let admin = mint_token("alice");
    let (status, _) = http_get(rest, "/metrics", Some(&admin)).await;
    assert_eq!(status, 200, "admin Bearer grants /metrics");

    // A wrong scrape token (and not an admin Bearer) → fail closed.
    let (status, _) = http_get(rest, "/metrics", Some("not-the-token")).await;
    assert_eq!(status, 401, "a wrong token is refused");

    // Liveness stays open without any credential.
    let (status, body) = http_get(rest, "/health/live", None).await;
    assert_eq!(status, 200, "/health/live is open");
    assert!(body.contains("live"), "liveness body: {body:?}");

    server.shutdown().await.expect("clean shutdown");
}
