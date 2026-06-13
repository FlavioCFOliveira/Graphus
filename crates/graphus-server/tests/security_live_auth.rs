//! End-to-end regression tests for **live authentication** (rmp #94): the connectivity seams'
//! authentication path now consults the *live* security catalog rather than a startup snapshot, so a
//! runtime security mutation affects who can authenticate **immediately**, with no reboot.
//!
//! Before #94 the Bolt/REST authentication path held a frozen `Arc<Authenticator>` taken at startup
//! (`server.rs`: `security.snapshot_authenticator()`), so:
//!
//! - a user `CREATE`d at runtime could not LOGON (Bolt) or present a Bearer token (REST) until the
//!   next reboot;
//! - a runtime credential change did not take effect for authentication until reboot;
//! - a runtime `DROP USER` did not invalidate authentication until reboot.
//!
//! These are exactly the gaps `security_enforcement.rs` documented as deferred. The server now backs
//! the seams with a `LiveAuth` provider over the read-locked `SecurityCatalog`, so each of the three
//! properties below holds against a **single, never-restarted** in-process server:
//!
//! 1. A user created at runtime (`CREATE USER … SET PASSWORD '…'`, by an admin over the live server)
//!    can immediately LOGON over **Bolt** AND authenticate via **REST** Bearer.
//! 2. A runtime credential change takes effect: after it, the old credential is rejected and the new
//!    one accepted for a fresh authentication (exercised via the admin surface's drop-then-recreate,
//!    the only runtime credential-mutation path the wire grammar exposes — same live mechanism).
//! 3. A runtime `DROP USER` causes a subsequent authentication for that principal to be refused
//!    immediately, over both Bolt (LOGON) and REST (Bearer).
//!
//! The admin (`alice`) and the bootstrap user `bob` themselves authenticate throughout; the
//! unrestricted/admin path is unchanged, so the TCK ratchet is unaffected.

use std::path::PathBuf;

use graphus_bolt::server::{encode_client_handshake, encode_request_framed};
use graphus_bolt::{Dechunker, Frame, Proposal, Request, Response};
use graphus_core::Value;
use graphus_server::config::{
    AdmissionConfig, AuthBootstrap, ServerConfig, TimingConfig, TlsConfig, UserBootstrap,
};
use graphus_server::{Server, ServerHandle};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UnixStream};

/// The JWT secret shared between the test config and the client-side token minting (the server
/// validates a Bearer token against the same secret; a token whose subject is not a *current*
/// catalog user is rejected even when its signature checks out).
const JWT_SECRET: &str = "secliveauth-itest-jwt-secret-32bytes!";

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
            "graphus-secliveauth-{tag}-{nanos}-{}",
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
}

impl Drop for TempStore {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

/// UDS + REST (non-TLS for the raw test client) on loopback, the `alice`/`pw` admin (bound to this
/// process uid for peer-cred), and a non-admin `bob`/`pw2` bootstrap user. Runtime-created users
/// (e.g. `dave`) are added by the tests themselves over the live admin surface.
fn base_config(temp: &TempStore) -> ServerConfig {
    ServerConfig {
        store_path: temp.store_dir(),
        default_database: "graphus".to_owned(),
        buffer_pool_pages: 256,
        bolt_tcp_addr: None,
        advertised_bolt_address: None,
        // REST on an ephemeral port; no TLS so the test's raw HTTP client can connect.
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
            admin_password: "pw".to_owned(),
            admin_uid: Some(current_uid()),
            users: vec![UserBootstrap {
                name: "bob".to_owned(),
                password: "pw2".to_owned(),
            }],
        },
        encryption: graphus_server::config::EncryptionConfig::default(),
        audit: graphus_server::AuditConfig::default(),
        // The REST test client speaks plaintext HTTP on loopback; opt into the non-TLS network path
        // (production keeps this off — `ServerConfig::validate`).
        allow_insecure_network: true,
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

// ----------------------------------------------------------------------------------------------
// A minimal Bolt client over UDS (mirrors security_enforcement.rs), exposing whether LOGON succeeds.
// ----------------------------------------------------------------------------------------------

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

    /// Performs the handshake + HELLO, then attempts LOGON with `user`/`password`. Returns `Ok(())`
    /// on a `SUCCESS` (authenticated) and `Err(code)` on a `FAILURE` (the Bolt error code, e.g.
    /// `Neo.ClientError.Security.Unauthorized`).
    async fn handshake_and_try_logon(&mut self, user: &str, password: &str) -> Result<(), String> {
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
        match self.recv().await {
            Response::Success { .. } => Ok(()),
            Response::Failure(f) => Err(f.code),
            other => panic!("unexpected LOGON response: {other:?}"),
        }
    }

    /// A full handshake + LOGON that must succeed (panics otherwise).
    async fn handshake_and_logon(&mut self, user: &str, password: &str) {
        self.handshake_and_try_logon(user, password)
            .await
            .unwrap_or_else(|code| panic!("LOGON {user:?} should succeed, got {code}"));
    }

    /// `RUN` + `PULL -1`, asserting success (used by the admin to drive `CREATE/DROP USER`).
    async fn run_ok(&mut self, query: &str) {
        self.send(&Request::Run {
            query: query.to_owned(),
            parameters: vec![],
            extra: vec![],
        })
        .await;
        match self.recv().await {
            Response::Success { .. } => {}
            other => panic!("RUN {query:?} expected SUCCESS, got {other:?}"),
        }
        self.send(&Request::Pull { n: -1, qid: None }).await;
        loop {
            match self.recv().await {
                Response::Record { .. } => {}
                Response::Success { .. } => break,
                other => panic!("PULL for {query:?} unexpected: {other:?}"),
            }
        }
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
// A tiny raw HTTP/1.1 client over a plain TcpStream + client-side Bearer minting.
// ----------------------------------------------------------------------------------------------

/// Sends one HTTP/1.1 request and returns the status code. `bearer` adds an `Authorization` header.
async fn http_status(
    addr: std::net::SocketAddr,
    method: &str,
    path: &str,
    bearer: Option<&str>,
    body_json: Option<&str>,
) -> u16 {
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
    stream.flush().await.unwrap();

    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).await.expect("read resp");
    let text = String::from_utf8_lossy(&raw).into_owned();
    text.split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(0)
}

/// Performs a single REST auto-commit read for `user`, authenticating with a Bearer token minted
/// client-side for that subject. Returns the HTTP status: `200` when the token validated (the
/// subject is a current catalog user with READ), `401` when authentication failed (e.g. the subject
/// is not a current user). The query is a trivial read so a successful auth returns `200`.
async fn rest_auth_status(addr: std::net::SocketAddr, user: &str) -> u16 {
    let token = mint_token(user);
    http_status(
        addr,
        "POST",
        "/db/graphus/tx/commit",
        Some(&token),
        Some(r#"{"statements":[{"statement":"RETURN 1"}],"access_mode":"READ"}"#),
    )
    .await
}

/// Mints a Bearer token for `user` (subject = `user`) valid for an hour, signed with the server's
/// configured JWT secret. The token is *structurally* valid regardless of whether the user exists;
/// the server's live `authenticate_bearer` then decides acceptance by checking the subject against
/// the **current** catalog — which is exactly the live property under test.
fn mint_token(user: &str) -> String {
    use graphus_auth::JwtAuthenticator;
    let jwt = JwtAuthenticator::new(JWT_SECRET.as_bytes());
    jwt.issue_token(user, now_unix_secs(), 3_600)
        .expect("mint token")
}

/// Current unix seconds (the server's `SystemClock` uses the same wall clock for JWT validation).
fn now_unix_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock after epoch")
        .as_secs()
}

// ================================================================================================
// Tests
// ================================================================================================

/// Property 1 + 3 over BOTH transports: a user created at runtime can immediately LOGON (Bolt) and
/// authenticate via Bearer (REST), without restarting the server; a subsequent runtime `DROP USER`
/// refuses both immediately.
#[tokio::test]
async fn runtime_created_user_authenticates_then_drop_refuses_live() {
    let temp = TempStore::new("create-drop");
    let server = boot(base_config(&temp)).await;
    let uds = server.uds_path.clone().expect("UDS enabled");
    let rest = server.rest_addr.expect("REST enabled");

    // Before creation: `dave` cannot LOGON (Bolt) and his Bearer token is refused (REST). This is the
    // baseline the snapshot world ALSO satisfied — the difference is what happens after a runtime
    // CREATE without a reboot, asserted next.
    let mut dave_pre = BoltClient::connect(&uds).await;
    let code = dave_pre
        .handshake_and_try_logon("dave", "davepw")
        .await
        .expect_err("unknown user cannot LOGON");
    assert!(
        code.contains("Security.Unauthorized") || code.contains("Unauthorized"),
        "unknown-user LOGON fails as Unauthorized: {code}"
    );
    dave_pre.goodbye().await;
    assert_eq!(
        rest_auth_status(rest, "dave").await,
        401,
        "unknown user's Bearer token is refused before creation"
    );

    // Admin creates `dave` at runtime over the live server (Bolt admin surface).
    let mut admin = BoltClient::connect(&uds).await;
    admin.handshake_and_logon("alice", "pw").await;
    admin.run_ok("CREATE USER dave SET PASSWORD 'davepw'").await;
    // `dave` needs READ for the REST auto-commit read used by `rest_auth_status`; grant it the
    // bootstrap `readwrite` role (server-wide read+write) so the Bearer success is observable as 200.
    admin.run_ok("GRANT ROLE readwrite TO dave").await;
    admin.goodbye().await;

    // PROPERTY 1 (Bolt): `dave` can now LOGON immediately — previously impossible until reboot.
    let mut dave_bolt = BoltClient::connect(&uds).await;
    dave_bolt
        .handshake_and_try_logon("dave", "davepw")
        .await
        .expect("runtime-created user LOGS ON over Bolt without a reboot");
    dave_bolt.goodbye().await;

    // PROPERTY 1 (REST): `dave`'s Bearer token now validates against the live catalog -> 200.
    assert_eq!(
        rest_auth_status(rest, "dave").await,
        200,
        "runtime-created user authenticates via REST Bearer without a reboot"
    );

    // PROPERTY 3: admin drops `dave` at runtime; both transports refuse him immediately.
    let mut admin2 = BoltClient::connect(&uds).await;
    admin2.handshake_and_logon("alice", "pw").await;
    admin2.run_ok("DROP USER dave").await;
    admin2.goodbye().await;

    let mut dave_after = BoltClient::connect(&uds).await;
    let code = dave_after
        .handshake_and_try_logon("dave", "davepw")
        .await
        .expect_err("dropped user cannot LOGON");
    assert!(
        code.contains("Security.Unauthorized") || code.contains("Unauthorized"),
        "dropped-user LOGON fails as Unauthorized: {code}"
    );
    dave_after.goodbye().await;
    assert_eq!(
        rest_auth_status(rest, "dave").await,
        401,
        "dropped user's Bearer token is refused immediately (no reboot)"
    );

    // The admin and the unmodified bootstrap user still authenticate throughout.
    let mut alice = BoltClient::connect(&uds).await;
    alice.handshake_and_logon("alice", "pw").await;
    alice.goodbye().await;
    let mut bob = BoltClient::connect(&uds).await;
    bob.handshake_and_logon("bob", "pw2").await;
    bob.goodbye().await;

    server.shutdown().await.expect("clean shutdown");
}

/// Property 2 over Bolt: a runtime credential change takes effect for a fresh authentication — the
/// old password is rejected and the new one accepted — without a reboot. The only runtime
/// credential-mutation path the wire admin grammar exposes is drop-then-recreate-with-a-new-password
/// (there is no `ALTER USER SET PASSWORD`), which exercises the same live mechanism: both the
/// refusal of the old credential and the acceptance of the new one resolve against the live catalog.
#[tokio::test]
async fn runtime_password_change_takes_effect_live() {
    let temp = TempStore::new("password-change");
    let server = boot(base_config(&temp)).await;
    let uds = server.uds_path.clone().expect("UDS enabled");

    // Admin creates `erin` with an initial password.
    let mut admin = BoltClient::connect(&uds).await;
    admin.handshake_and_logon("alice", "pw").await;
    admin
        .run_ok("CREATE USER erin SET PASSWORD 'old-secret'")
        .await;
    admin.goodbye().await;

    // `erin` authenticates with the initial password.
    let mut erin1 = BoltClient::connect(&uds).await;
    erin1
        .handshake_and_try_logon("erin", "old-secret")
        .await
        .expect("initial password authenticates");
    erin1.goodbye().await;

    // Admin changes the credential at runtime (drop + recreate with a new password).
    let mut admin2 = BoltClient::connect(&uds).await;
    admin2.handshake_and_logon("alice", "pw").await;
    admin2.run_ok("DROP USER erin").await;
    admin2
        .run_ok("CREATE USER erin SET PASSWORD 'new-secret'")
        .await;
    admin2.goodbye().await;

    // The OLD password is now rejected on a fresh authentication (no reboot).
    let mut erin_old = BoltClient::connect(&uds).await;
    let code = erin_old
        .handshake_and_try_logon("erin", "old-secret")
        .await
        .expect_err("old password is rejected after the runtime change");
    assert!(
        code.contains("Security.Unauthorized") || code.contains("Unauthorized"),
        "old-password LOGON fails as Unauthorized: {code}"
    );
    erin_old.goodbye().await;

    // The NEW password is accepted on a fresh authentication (no reboot).
    let mut erin_new = BoltClient::connect(&uds).await;
    erin_new
        .handshake_and_try_logon("erin", "new-secret")
        .await
        .expect("new password authenticates after the runtime change");
    erin_new.goodbye().await;

    server.shutdown().await.expect("clean shutdown");
}
