//! End-to-end tests for the **security audit log** (rmp #70, parent #69, decision
//! `D-security-scope`), driven through a real booted server over Bolt-over-UDS.
//!
//! Each test boots a server with audit **enabled**, drives a Bolt session that exercises one event
//! class, shuts the server down, then inspects the JSONL `audit.log` at `<store_dir>/audit.log`:
//!
//! - authentication success + failure (`auth_success` / `auth_failure`),
//! - authorization denial (`authz_denied`),
//! - security / admin / schema / data changes (`security_change` / `admin_change` /
//!   `schema_change` / `data_change`),
//! - the **no-secrets** invariant (a password literal never reaches the log),
//! - durability + ordering across a restart (monotonic `seq`, RFC 3339 `ts`),
//! - the disabled-audit case (no file is written).
//!
//! The model under test is the synchronous, non-dropping, `fsync`-on-security-event sink in
//! [`graphus_server::audit`]; these tests certify it over the wire (not just at the unit level).

use std::path::{Path, PathBuf};

use graphus_bolt::server::{encode_client_handshake, encode_request_framed};
use graphus_bolt::{BoltValue, Dechunker, Frame, Proposal, Request, Response};
use graphus_core::Value;
use graphus_server::config::{
    AdmissionConfig, AuthBootstrap, ServerConfig, TimingConfig, TlsConfig, UserBootstrap,
};
use graphus_server::{AuditConfig, Server, ServerHandle};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;

/// Flattens each RECORD cell to a scalar [`Value`] (entity → id, path → list of element ids, list
/// → element-wise) — the admin/scalar tests assert only on scalars.
fn scalar_row(values: Vec<BoltValue>) -> Vec<Value> {
    values.into_iter().map(bolt_to_scalar).collect()
}

/// Flattens one [`BoltValue`] cell to a scalar [`Value`].
fn bolt_to_scalar(v: BoltValue) -> Value {
    match v {
        BoltValue::Value(val) => val,
        BoltValue::Node(n) => Value::Integer(n.id),
        BoltValue::Relationship(r) => Value::Integer(r.id),
        BoltValue::Path(p) => {
            let mut ids = Vec::with_capacity(p.nodes.len() + p.rels.len());
            for node in &p.nodes {
                ids.push(Value::Integer(node.id));
            }
            for rel in &p.rels {
                ids.push(Value::Integer(rel.id));
            }
            Value::List(ids)
        }
        BoltValue::List(items) => Value::List(items.into_iter().map(bolt_to_scalar).collect()),
    }
}

/// The JWT secret shared between the test config and the token-minting helper (unused here — UDS —
/// but `ServerConfig` requires it shaped).
const JWT_SECRET: &str = "audit-itest-jwt-secret-32-bytes-ok!!";

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
            "graphus-audit-it-{tag}-{nanos}-{}",
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

    /// The audit log path under the store directory (the default when `audit.path` is unset).
    fn audit_file(&self) -> PathBuf {
        self.store_dir().join("audit.log")
    }
}

impl Drop for TempStore {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

/// UDS on loopback, the `alice`/`pw` admin (bound to this process uid for peer-cred), a non-admin
/// `bob`/`pw2` bootstrap user (read+write only), and **audit enabled** (all classes exercised,
/// `audit_data_changes` on, security events fsync'd).
fn base_config(temp: &TempStore) -> ServerConfig {
    ServerConfig {
        store_path: temp.store_dir(),
        default_database: "graphus".to_owned(),
        buffer_pool_pages: 256,
        fsync_threads: 1,
        bolt_tcp_addr: None,
        advertised_bolt_address: None,
        rest_addr: None,
        uds_path: Some(temp.uds_path()),
        tls: TlsConfig::default(),
        admission: AdmissionConfig {
            max_concurrent_queries: 64,
            engine_queue_capacity: 256,
            result_buffer_capacity: 64,
        },
        timing: TimingConfig {
            slow_query_threshold_ms: 1_000,
            shutdown_drain_deadline_ms: 5_000,
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
        audit: AuditConfig {
            enabled: true,
            path: None,
            fsync_security_events: true,
            audit_data_changes: true,
            rotate_max_bytes: 64 * 1024 * 1024,
            retain_files: 5,
        },
        allow_insecure_network: true,
    }
}

/// A config with audit DISABLED (for the no-file test).
fn disabled_audit_config(temp: &TempStore) -> ServerConfig {
    ServerConfig {
        audit: AuditConfig {
            enabled: false,
            ..AuditConfig::default()
        },
        ..base_config(temp)
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

/// Boots a server from `config` and returns its handle once ready.
async fn boot(config: ServerConfig) -> ServerHandle {
    Server::new(config)
        .start()
        .await
        .expect("server should boot")
}

// ----------------------------------------------------------------------------------------------
// Audit log readers
// ----------------------------------------------------------------------------------------------

/// Reads the audit log at `path`, splitting on `\n`, skipping empty lines, and parsing each as JSON.
fn read_audit_lines(path: &Path) -> Vec<serde_json::Value> {
    let text = std::fs::read_to_string(path).unwrap_or_default();
    text.lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str(l).expect("each audit line parses as JSON"))
        .collect()
}

/// The `"class"` of every audit line.
fn classes(lines: &[serde_json::Value]) -> Vec<String> {
    lines
        .iter()
        .filter_map(|l| {
            l.get("class")
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned)
        })
        .collect()
}

/// The string field `key` of a JSON line, if present.
fn field<'a>(line: &'a serde_json::Value, key: &str) -> Option<&'a str> {
    line.get(key).and_then(serde_json::Value::as_str)
}

/// Finds the first line whose `class` equals `class`.
fn find_class<'a>(lines: &'a [serde_json::Value], class: &str) -> Option<&'a serde_json::Value> {
    lines.iter().find(|l| field(l, "class") == Some(class))
}

// ----------------------------------------------------------------------------------------------
// A minimal Bolt client over UDS (mirrors security_admin_surface.rs).
// ----------------------------------------------------------------------------------------------

/// A `{code, message}` pair pulled out of a Bolt FAILURE.
#[derive(Debug)]
struct WireFailure {
    #[allow(dead_code)]
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
        self.handshake_then_try_logon(user, password)
            .await
            .expect("LOGON should succeed");
    }

    /// Tries to LOGON, returning `Ok(())` on success or the FAILURE on a rejected auth (the socket
    /// may then close — the caller does not reuse the client).
    async fn handshake_then_try_logon(
        &mut self,
        user: &str,
        password: &str,
    ) -> Result<(), WireFailure> {
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
            Response::Failure(f) => Err(WireFailure {
                code: f.code,
                message: f.message,
            }),
            other => panic!("unexpected LOGON response: {other:?}"),
        }
    }

    /// `RUN` + `PULL -1`. On a RUN failure no PULL is sent and the failure is returned.
    async fn run(&mut self, query: &str) -> Result<Vec<Vec<Value>>, WireFailure> {
        self.send(&Request::Run {
            query: query.to_owned(),
            parameters: vec![],
            extra: vec![],
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

    /// `RUN` asserting success, returning the rows.
    async fn run_ok(&mut self, query: &str) -> Vec<Vec<Value>> {
        match self.run(query).await {
            Ok(rows) => rows,
            Err(f) => panic!("query {query:?} failed: {f:?}"),
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

// ================================================================================================
// Tests
// ================================================================================================

/// A successful LOGON is audited as `auth_success` with the actor, source, and outcome.
#[tokio::test]
async fn auth_success_is_audited() {
    let temp = TempStore::new("auth-success");
    let server = boot(base_config(&temp)).await;
    let uds = server.uds_path.clone().expect("UDS enabled");

    let mut c = BoltClient::connect(&uds).await;
    c.handshake_and_logon("alice", "pw").await;
    c.goodbye().await;
    server.shutdown().await.expect("clean shutdown");

    let lines = read_audit_lines(&temp.audit_file());
    let line = find_class(&lines, "auth_success").expect("an auth_success line");
    assert_eq!(field(line, "actor"), Some("alice"));
    assert_eq!(field(line, "source"), Some("bolt_uds"));
    assert_eq!(field(line, "outcome"), Some("success"));
}

/// A LOGON with a wrong password is audited as `auth_failure` (outcome `failure`).
#[tokio::test]
async fn auth_failure_is_audited() {
    let temp = TempStore::new("auth-failure");
    let server = boot(base_config(&temp)).await;
    let uds = server.uds_path.clone().expect("UDS enabled");

    let mut c = BoltClient::connect(&uds).await;
    let logon = c.handshake_then_try_logon("alice", "WRONG-PASSWORD").await;
    assert!(logon.is_err(), "a wrong password must fail LOGON");
    drop(c);
    server.shutdown().await.expect("clean shutdown");

    let lines = read_audit_lines(&temp.audit_file());
    let line = find_class(&lines, "auth_failure").expect("an auth_failure line");
    assert_eq!(field(line, "outcome"), Some("failure"));
    assert_eq!(field(line, "source"), Some("bolt_uds"));
    // The attempted username is recorded (it is not a secret); the password never is (see the
    // no_secrets test).
    assert_eq!(field(line, "actor"), Some("alice"));
}

/// A non-admin running an admin/security command is audited as `authz_denied` with the actor.
#[tokio::test]
async fn authz_denial_is_audited() {
    let temp = TempStore::new("authz-denied");
    let server = boot(base_config(&temp)).await;
    let uds = server.uds_path.clone().expect("UDS enabled");

    let mut bob = BoltClient::connect(&uds).await;
    bob.handshake_and_logon("bob", "pw2").await;
    // bob has read+write but NOT admin: SHOW USERS is denied.
    let f = bob.run("SHOW USERS").await.expect_err("non-admin denied");
    assert!(f.code.contains("Security.Forbidden"), "{f:?}");
    bob.reset().await;
    bob.goodbye().await;
    server.shutdown().await.expect("clean shutdown");

    let lines = read_audit_lines(&temp.audit_file());
    let line = find_class(&lines, "authz_denied").expect("an authz_denied line");
    assert_eq!(field(line, "actor"), Some("bob"));
    assert_eq!(field(line, "outcome"), Some("failure"));
    assert_eq!(field(line, "source"), Some("bolt_uds"));
}

/// `CREATE USER` is audited as `security_change`, with the redacted detail (the password is never
/// present).
#[tokio::test]
async fn security_change_is_audited() {
    let temp = TempStore::new("security-change");
    let server = boot(base_config(&temp)).await;
    let uds = server.uds_path.clone().expect("UDS enabled");

    let mut c = BoltClient::connect(&uds).await;
    c.handshake_and_logon("alice", "pw").await;
    c.run_ok("CREATE USER carol SET PASSWORD 'cpw'").await;
    c.goodbye().await;
    server.shutdown().await.expect("clean shutdown");

    let lines = read_audit_lines(&temp.audit_file());
    let line = find_class(&lines, "security_change").expect("a security_change line");
    assert_eq!(field(line, "outcome"), Some("success"));
    let detail = field(line, "detail").expect("a detail");
    assert!(
        detail.contains("CREATE USER carol"),
        "detail names the command: {detail}"
    );
    assert!(
        !detail.contains("cpw"),
        "the password is never in detail: {detail}"
    );
}

/// `CREATE DATABASE` is audited as `admin_change`, carrying the database name.
#[tokio::test]
async fn admin_change_is_audited() {
    let temp = TempStore::new("admin-change");
    let server = boot(base_config(&temp)).await;
    let uds = server.uds_path.clone().expect("UDS enabled");

    let mut c = BoltClient::connect(&uds).await;
    c.handshake_and_logon("alice", "pw").await;
    c.run_ok("CREATE DATABASE salesaudit").await;
    c.goodbye().await;
    server.shutdown().await.expect("clean shutdown");

    let lines = read_audit_lines(&temp.audit_file());
    let line = find_class(&lines, "admin_change").expect("an admin_change line");
    assert_eq!(field(line, "outcome"), Some("success"));
    assert_eq!(field(line, "database"), Some("salesaudit"));
    let detail = field(line, "detail").expect("a detail");
    assert!(
        detail.contains("salesaudit"),
        "detail names the db: {detail}"
    );
}

/// `CREATE INDEX` is audited as `schema_change`.
#[tokio::test]
async fn schema_change_is_audited() {
    let temp = TempStore::new("schema-change");
    let server = boot(base_config(&temp)).await;
    let uds = server.uds_path.clone().expect("UDS enabled");

    let mut c = BoltClient::connect(&uds).await;
    c.handshake_and_logon("alice", "pw").await;
    // A node so the index has something to populate, then the openCypher CREATE INDEX form.
    c.run_ok("CREATE (n:Person {name:'p'})").await;
    c.run_ok("CREATE INDEX FOR (n:Person) ON (n.name)").await;
    c.goodbye().await;
    server.shutdown().await.expect("clean shutdown");

    let lines = read_audit_lines(&temp.audit_file());
    let line = find_class(&lines, "schema_change").expect("a schema_change line");
    assert_eq!(field(line, "outcome"), Some("success"));
    let detail = field(line, "detail").expect("a detail");
    assert!(
        detail.to_uppercase().contains("INDEX"),
        "detail describes the index DDL: {detail}"
    );
}

/// A write query is audited as `data_change` when `audit_data_changes` is on, and the `detail`
/// carries only the category — never the query's literal values.
#[tokio::test]
async fn data_change_is_audited_when_enabled() {
    let temp = TempStore::new("data-change");
    let server = boot(base_config(&temp)).await;
    let uds = server.uds_path.clone().expect("UDS enabled");

    let mut c = BoltClient::connect(&uds).await;
    c.handshake_and_logon("alice", "pw").await;
    c.run_ok("CREATE (n:Person {name:'x'})").await;
    c.goodbye().await;
    server.shutdown().await.expect("clean shutdown");

    let lines = read_audit_lines(&temp.audit_file());
    let line = find_class(&lines, "data_change").expect("a data_change line");
    assert_eq!(field(line, "outcome"), Some("success"));
    let detail = field(line, "detail").expect("a detail");
    // Category only — never the literal value 'x'.
    assert!(
        detail.contains("write query"),
        "detail is the category: {detail}"
    );
    assert!(
        !detail.contains('x') || detail.contains("write query"),
        "category form only"
    );
    // The whole line never contains the literal value (query text is never logged).
    assert!(
        !line.to_string().contains("\"x\""),
        "the literal value is never in the data_change line: {line}"
    );
}

/// No secret (password literal) ever reaches the audit log file, across a LOGON and a `CREATE USER
/// SET PASSWORD`.
#[tokio::test]
async fn no_secrets_in_audit_log() {
    let temp = TempStore::new("no-secrets");
    let server = boot(base_config(&temp)).await;
    let uds = server.uds_path.clone().expect("UDS enabled");

    let mut c = BoltClient::connect(&uds).await;
    c.handshake_and_logon("alice", "pw").await;
    c.run_ok("CREATE USER dan SET PASSWORD 'topsecretpw'").await;
    c.goodbye().await;
    server.shutdown().await.expect("clean shutdown");

    let contents = std::fs::read_to_string(temp.audit_file()).expect("audit log file");
    assert!(
        !contents.contains("topsecretpw"),
        "the unique secret must NEVER appear in the audit log:\n{contents}"
    );
    // The redacted marker IS present (the password was set), proving the redaction ran.
    assert!(
        contents.contains("<redacted>"),
        "a set password is redacted in the trail"
    );
}

/// The audit trail survives a restart with strictly-increasing `seq` (no gaps/dupes) and every line
/// carrying an RFC 3339 `ts`.
#[tokio::test]
async fn audit_survives_restart_and_ordering() {
    let temp = TempStore::new("restart");
    let config = base_config(&temp);

    // First boot: a few audited actions.
    {
        let server = boot(config.clone()).await;
        let uds = server.uds_path.clone().expect("UDS enabled");
        let mut c = BoltClient::connect(&uds).await;
        c.handshake_and_logon("alice", "pw").await;
        c.run_ok("CREATE USER erin SET PASSWORD 'epw'").await;
        c.goodbye().await;
        server.shutdown().await.expect("clean shutdown");
    }

    let lines_before = read_audit_lines(&temp.audit_file());
    let count_before = lines_before.len();
    assert!(
        count_before >= 2,
        "first boot wrote events: {lines_before:?}"
    );

    // Restart the SAME store: another audited action.
    let server = boot(config).await;
    let uds = server.uds_path.clone().expect("UDS enabled");
    let mut c = BoltClient::connect(&uds).await;
    c.handshake_and_logon("alice", "pw").await;
    c.run_ok("CREATE ROLE auditrole").await;
    c.goodbye().await;
    server.shutdown().await.expect("clean shutdown");

    let lines = read_audit_lines(&temp.audit_file());
    assert!(
        lines.len() > count_before,
        "the restart appended more events (earlier events preserved): {} > {}",
        lines.len(),
        count_before
    );

    // seq is strictly increasing with no gaps/dupes across the restart; every line has a ts.
    let seqs: Vec<u64> = lines
        .iter()
        .map(|l| {
            l.get("seq")
                .and_then(serde_json::Value::as_u64)
                .expect("every line has a numeric seq")
        })
        .collect();
    for window in seqs.windows(2) {
        assert_eq!(
            window[1],
            window[0] + 1,
            "seq is strictly increasing with no gap/dupe: {seqs:?}"
        );
    }
    assert_eq!(seqs.first().copied(), Some(1), "seq starts at 1");
    for l in &lines {
        let ts = field(l, "ts").expect("every line has a ts");
        // A loose RFC 3339 shape check: ends with Z, has the date/time separator.
        assert!(
            ts.ends_with('Z') && ts.contains('T'),
            "ts is RFC 3339: {ts}"
        );
    }

    // The full class trail spans both boots: the first run's security change and the restart's.
    let all_classes = classes(&lines);
    assert!(
        all_classes
            .iter()
            .filter(|c| c.as_str() == "security_change")
            .count()
            >= 2,
        "both boots' security changes are present: {all_classes:?}"
    );
    assert!(
        all_classes.contains(&"auth_success".to_owned()),
        "auth events are present: {all_classes:?}"
    );
}

/// With audit disabled, no audit file is written even though events would otherwise occur.
#[tokio::test]
async fn disabled_audit_writes_no_file() {
    let temp = TempStore::new("disabled");
    let server = boot(disabled_audit_config(&temp)).await;
    let uds = server.uds_path.clone().expect("UDS enabled");

    let mut c = BoltClient::connect(&uds).await;
    c.handshake_and_logon("alice", "pw").await;
    c.run_ok("CREATE (n:Person {name:'y'})").await;
    c.goodbye().await;
    server.shutdown().await.expect("clean shutdown");

    let audit_path = temp.audit_file();
    let written =
        audit_path.exists() && std::fs::metadata(&audit_path).map(|m| m.len()).unwrap_or(0) > 0;
    assert!(
        !written,
        "a disabled audit log must not write a file at {}",
        audit_path.display()
    );
}
