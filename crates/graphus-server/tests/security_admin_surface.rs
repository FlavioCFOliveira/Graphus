//! End-to-end tests for the **security administration surface** (rmp #92, parent #68; decision
//! `D-auth-scheme`), driven through a real booted server over Bolt-over-UDS:
//!
//! - `CREATE/DROP USER`, `CREATE/DROP ROLE`, `GRANT/REVOKE ROLE`, `GRANT/REVOKE <action> ON
//!   <scope>`, `SHOW USERS/ROLES/PRIVILEGES` — the full grammar over the wire.
//! - The privilege boundary: a non-admin principal is denied every security statement with **no
//!   side effects** (the `Security.Forbidden` classification).
//! - The not-transactional rule: security statements are rejected inside an explicit transaction.
//! - The lock-out safeguard: the bootstrap admin can never be stripped of administration.
//! - Durability: users/roles/grants created over the wire survive a full server restart (the
//!   `security.toml` file is authoritative), and plaintext passwords are never written to it.
//!
//! Enforcement of fine-grained `Traverse`/`Read`/`Write` filtering at query time is **rmp #93** and
//! is intentionally *not* exercised here.

use std::path::PathBuf;

use graphus_bolt::server::{encode_client_handshake, encode_request_framed};
use graphus_bolt::{BoltValue, Dechunker, Frame, Proposal, Request, Response};
use graphus_core::Value;
use graphus_server::config::{
    AdmissionConfig, AuthBootstrap, ServerConfig, TimingConfig, TlsConfig, UserBootstrap,
};
use graphus_server::{Server, ServerHandle};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;

/// Flattens each RECORD cell to a scalar [`Value`] for the property-only assertion path, the way
/// the old server `project_value` did: a graph entity (which a bound-variable `CREATE`/`MATCH`
/// streams back even with no `RETURN`) collapses to its id, a path to the list of its element ids,
/// and a structural list element-wise. These admin/scalar tests assert only on scalars; the entity
/// ids are inert here.
fn scalar_row(values: Vec<BoltValue>) -> Vec<Value> {
    values.into_iter().map(bolt_to_scalar).collect()
}

/// Flattens one [`BoltValue`] cell to a scalar [`Value`] (entity → id, path → list of element ids,
/// list → element-wise).
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

/// The JWT secret shared between the test config and the token-minting helper.
const JWT_SECRET: &str = "secadmin-itest-jwt-secret-32-bytes!!";

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
            "graphus-secadmin-{tag}-{nanos}-{}",
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

    /// The durable security file path under the store directory.
    fn security_file(&self) -> PathBuf {
        self.store_dir().join("security.toml")
    }
}

impl Drop for TempStore {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

/// UDS on loopback, the `alice`/`pw` admin (bound to this process uid for peer-cred), and a
/// non-admin `bob`/`pw2` bootstrap user (read+write only).
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

/// Boots a server from `config` and returns its handle once ready.
async fn boot(config: ServerConfig) -> ServerHandle {
    Server::new(config)
        .start()
        .await
        .expect("server should boot")
}

// ----------------------------------------------------------------------------------------------
// A minimal Bolt client over UDS (mirrors db_admin_surface.rs).
// ----------------------------------------------------------------------------------------------

/// A `{code, message}` pair pulled out of a Bolt FAILURE.
#[derive(Debug)]
struct WireFailure {
    code: String,
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

    /// Tries to LOGON, returning `Ok(())` on success or the failure (used to assert a dropped user
    /// can no longer authenticate after a restart).
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

    /// `RUN` + `PULL -1`. On a RUN failure no PULL is sent (the session is fail-state) and the
    /// failure is returned; the caller recovers with [`reset`].
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

    async fn begin(&mut self) {
        self.send(&Request::Begin { extra: vec![] }).await;
        assert!(
            matches!(self.recv().await, Response::Success { .. }),
            "BEGIN"
        );
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

/// Extracts the string in column `col` of every row (used to scan `SHOW USERS`/`ROLES`/`PRIVILEGES`).
fn column(rows: &[Vec<Value>], col: usize) -> Vec<String> {
    rows.iter()
        .map(|r| match r.get(col) {
            Some(Value::String(s)) => s.clone(),
            other => panic!("expected a string in column {col}, got {other:?}"),
        })
        .collect()
}

// ================================================================================================
// Tests
// ================================================================================================

/// The full security grammar over the wire: create a user + role, grant fine-grained privileges,
/// list everything, and confirm each statement reports a clean result.
#[tokio::test]
async fn security_commands_full_lifecycle_over_the_wire() {
    let temp = TempStore::new("lifecycle");
    let server = boot(base_config(&temp)).await;
    let uds = server.uds_path.clone().expect("UDS enabled");

    let mut c = BoltClient::connect(&uds).await;
    c.handshake_and_logon("alice", "pw").await;

    // CREATE USER / ROLE.
    assert!(
        c.run_ok("CREATE USER carol SET PASSWORD 'cpw'")
            .await
            .is_empty()
    );
    assert!(c.run_ok("CREATE ROLE analyst").await.is_empty());

    // GRANT fine-grained privileges to the role, across the scope tree.
    c.run_ok("GRANT TRAVERSE ON GRAPH graphus TO analyst").await;
    c.run_ok("GRANT READ ON LABEL graphus.Person TO analyst")
        .await;
    c.run_ok("REVOKE READ ON PROPERTY graphus.Person.ssn FROM analyst")
        .await; // idempotent revoke of a not-granted privilege
    // GRANT ROLE to the user.
    c.run_ok("GRANT ROLE analyst TO carol").await;

    // SHOW USERS: alice, bob, carol all present; carol carries the analyst role.
    let users = c.run_ok("SHOW USERS").await;
    let names = column(&users, 0);
    assert!(names.contains(&"alice".to_owned()), "{names:?}");
    assert!(names.contains(&"bob".to_owned()), "{names:?}");
    assert!(names.contains(&"carol".to_owned()), "{names:?}");
    let carol_row = users
        .iter()
        .find(|r| matches!(r.first(), Some(Value::String(s)) if s == "carol"))
        .expect("carol row");
    assert!(
        matches!(&carol_row[1], Value::String(s) if s.contains("analyst")),
        "carol's roles: {carol_row:?}"
    );

    // SHOW ROLES: admin (bootstrap), analyst (and readwrite for bob).
    let roles = column(&c.run_ok("SHOW ROLES").await, 0);
    assert!(roles.contains(&"admin".to_owned()), "{roles:?}");
    assert!(roles.contains(&"analyst".to_owned()), "{roles:?}");

    // SHOW PRIVILEGES: the analyst's grants are listed with action + scope.
    let privs = c.run_ok("SHOW PRIVILEGES").await;
    let analyst_privs: Vec<(String, String)> = privs
        .iter()
        .filter(|r| matches!(r.first(), Some(Value::String(s)) if s == "analyst"))
        .map(|r| match (&r[1], &r[2]) {
            (Value::String(a), Value::String(s)) => (a.clone(), s.clone()),
            other => panic!("priv row shape: {other:?}"),
        })
        .collect();
    assert!(
        analyst_privs.contains(&("traverse".to_owned(), "GRAPH graphus".to_owned())),
        "{analyst_privs:?}"
    );
    assert!(
        analyst_privs.contains(&("read".to_owned(), "LABEL graphus.Person".to_owned())),
        "{analyst_privs:?}"
    );

    // DROP the user + role.
    c.run_ok("DROP USER carol").await;
    c.run_ok("DROP ROLE analyst").await;
    let names = column(&c.run_ok("SHOW USERS").await, 0);
    assert!(
        !names.contains(&"carol".to_owned()),
        "carol dropped: {names:?}"
    );

    c.goodbye().await;
    server.shutdown().await.expect("clean shutdown");
}

/// `IF NOT EXISTS` / `IF EXISTS` turn the duplicate/missing cases into no-op successes; without
/// them the duplicate/missing cases are clear client errors and the session recovers via RESET.
#[tokio::test]
async fn if_exists_variants_and_clear_errors() {
    let temp = TempStore::new("if-variants");
    let server = boot(base_config(&temp)).await;
    let uds = server.uds_path.clone().expect("UDS enabled");

    let mut c = BoltClient::connect(&uds).await;
    c.handshake_and_logon("alice", "pw").await;

    c.run_ok("CREATE USER dave SET PASSWORD 'd'").await;
    // Duplicate without IF NOT EXISTS: a client error.
    let f = c
        .run("CREATE USER dave SET PASSWORD 'd'")
        .await
        .expect_err("duplicate user fails");
    assert!(f.message.contains("already exists"), "{f:?}");
    assert!(f.code.contains("ClientError"), "{f:?}");
    c.reset().await;
    // IF NOT EXISTS: the duplicate is a no-op success.
    c.run_ok("CREATE USER dave SET PASSWORD 'd' IF NOT EXISTS")
        .await;

    // DROP of a missing user fails; IF EXISTS no-ops.
    let f = c
        .run("DROP USER ghost")
        .await
        .expect_err("drop of a missing user fails");
    assert!(f.message.contains("not found"), "{f:?}");
    c.reset().await;
    c.run_ok("DROP USER ghost IF EXISTS").await;

    // Roles: the same IF variants.
    c.run_ok("CREATE ROLE r1").await;
    c.run_ok("CREATE ROLE r1 IF NOT EXISTS").await;
    c.run_ok("DROP ROLE missing IF EXISTS").await;

    c.goodbye().await;
    server.shutdown().await.expect("clean shutdown");
}

/// The privilege boundary: a non-admin principal is denied every security statement with the
/// `Security.Forbidden` classification and **no side effects**.
#[tokio::test]
async fn non_admin_is_denied_security_commands_with_no_side_effects() {
    let temp = TempStore::new("privilege");
    let server = boot(base_config(&temp)).await;
    let uds = server.uds_path.clone().expect("UDS enabled");

    // bob (read+write, no admin) is denied every security statement.
    let mut bob = BoltClient::connect(&uds).await;
    bob.handshake_and_logon("bob", "pw2").await;
    for stmt in [
        "CREATE USER mallory SET PASSWORD 'x'",
        "CREATE ROLE evil",
        "GRANT ADMIN ON DATABASE TO readwrite",
        "GRANT ROLE readwrite TO bob",
        "SHOW USERS",
        "SHOW ROLES",
        "SHOW PRIVILEGES",
        "DROP USER alice",
    ] {
        let f = bob.run(stmt).await.expect_err("non-admin denied");
        assert!(f.code.contains("Security.Forbidden"), "{stmt}: {f:?}");
        assert!(f.message.contains("permission denied"), "{stmt}: {f:?}");
        bob.reset().await;
    }
    bob.goodbye().await;

    // No side effects: alice sees no `mallory`, no `evil`, and bob did not self-escalate.
    let mut alice = BoltClient::connect(&uds).await;
    alice.handshake_and_logon("alice", "pw").await;
    let names = column(&alice.run_ok("SHOW USERS").await, 0);
    assert!(
        !names.contains(&"mallory".to_owned()),
        "no trace of mallory: {names:?}"
    );
    let roles = column(&alice.run_ok("SHOW ROLES").await, 0);
    assert!(
        !roles.contains(&"evil".to_owned()),
        "no trace of evil: {roles:?}"
    );
    // bob still cannot run SHOW USERS (he gained no admin).
    alice.goodbye().await;
    let mut bob2 = BoltClient::connect(&uds).await;
    bob2.handshake_and_logon("bob", "pw2").await;
    assert!(bob2.run("SHOW USERS").await.is_err(), "bob still not admin");
    bob2.reset().await;
    bob2.goodbye().await;

    server.shutdown().await.expect("clean shutdown");
}

/// Security statements are not transactional: inside an explicit transaction they are rejected and
/// have **no side effects**.
#[tokio::test]
async fn security_commands_rejected_inside_explicit_transaction() {
    let temp = TempStore::new("not-transactional");
    let server = boot(base_config(&temp)).await;
    let uds = server.uds_path.clone().expect("UDS enabled");

    let mut c = BoltClient::connect(&uds).await;
    c.handshake_and_logon("alice", "pw").await;

    c.begin().await;
    let f = c
        .run("CREATE USER nope SET PASSWORD 'x'")
        .await
        .expect_err("security command inside an explicit transaction");
    assert!(f.message.contains("explicit transaction"), "{f:?}");
    c.reset().await;

    let names = column(&c.run_ok("SHOW USERS").await, 0);
    assert!(
        !names.contains(&"nope".to_owned()),
        "no side effects: {names:?}"
    );

    c.goodbye().await;
    server.shutdown().await.expect("clean shutdown");
}

/// The lock-out safeguard: the bootstrap admin can never be stripped of administration over the
/// wire (drop user / revoke its role / revoke the underlying global Admin / drop the admin role).
#[tokio::test]
async fn bootstrap_admin_cannot_be_locked_out_over_the_wire() {
    let temp = TempStore::new("lockout");
    let server = boot(base_config(&temp)).await;
    let uds = server.uds_path.clone().expect("UDS enabled");

    let mut c = BoltClient::connect(&uds).await;
    c.handshake_and_logon("alice", "pw").await;

    for stmt in [
        "DROP USER alice",
        "REVOKE ROLE admin FROM alice",
        "REVOKE ADMIN ON DATABASE FROM admin",
        "DROP ROLE admin",
    ] {
        let f = c.run(stmt).await.expect_err("lock-out refused");
        assert!(
            f.message.contains("lock-out") || f.message.contains("administrative access"),
            "{stmt}: {f:?}"
        );
        assert!(f.code.contains("ClientError"), "{stmt}: {f:?}");
        c.reset().await;
    }

    // alice is still an admin: she can still run admin commands.
    c.run_ok("SHOW USERS").await;
    c.goodbye().await;
    server.shutdown().await.expect("clean shutdown");
}

/// Durability: a user + role + grant created over the wire survive a full server restart (the
/// `security.toml` file is authoritative); the persisted file never contains a plaintext password;
/// a dropped user can no longer authenticate after the restart.
#[tokio::test]
async fn security_model_survives_restart_and_never_persists_plaintext() {
    let temp = TempStore::new("restart");
    let config = base_config(&temp);

    {
        let server = boot(config.clone()).await;
        let uds = server.uds_path.clone().expect("UDS enabled");
        let mut c = BoltClient::connect(&uds).await;
        c.handshake_and_logon("alice", "pw").await;
        c.run_ok("CREATE USER erin SET PASSWORD 'sup3r-s3cret'")
            .await;
        c.run_ok("CREATE ROLE auditor").await;
        c.run_ok("GRANT READ ON GRAPH graphus TO auditor").await;
        c.run_ok("GRANT ROLE auditor TO erin").await;
        // Drop bob so we can assert he cannot authenticate after the restart.
        c.run_ok("DROP USER bob").await;
        c.goodbye().await;
        server.shutdown().await.expect("clean shutdown");
    }

    // The persisted file exists, names erin + auditor, carries the argon2 hash, NOT the plaintext.
    let text = std::fs::read_to_string(temp.security_file()).expect("security file");
    assert!(text.contains("erin") && text.contains("auditor"), "{text}");
    assert!(text.contains("$argon2id$"), "the argon2 hash is persisted");
    assert!(
        !text.contains("sup3r-s3cret"),
        "plaintext must NEVER be persisted"
    );

    // Restart: the file is authoritative.
    let server = boot(config).await;
    let uds = server.uds_path.clone().expect("UDS enabled");

    // erin (created last run) can authenticate and her role + grant survived.
    let mut erin = BoltClient::connect(&uds).await;
    erin.handshake_and_logon("erin", "sup3r-s3cret").await;
    erin.goodbye().await;

    // alice (admin) sees erin + auditor in the reloaded model.
    let mut alice = BoltClient::connect(&uds).await;
    alice.handshake_and_logon("alice", "pw").await;
    let names = column(&alice.run_ok("SHOW USERS").await, 0);
    assert!(
        names.contains(&"erin".to_owned()),
        "erin recovered: {names:?}"
    );
    assert!(
        !names.contains(&"bob".to_owned()),
        "bob's drop is durable: {names:?}"
    );
    let roles = column(&alice.run_ok("SHOW ROLES").await, 0);
    assert!(
        roles.contains(&"auditor".to_owned()),
        "auditor recovered: {roles:?}"
    );
    alice.goodbye().await;

    // bob (dropped) can no longer authenticate after the restart (his removal is durable).
    let mut bob = BoltClient::connect(&uds).await;
    let logon = bob.handshake_then_try_logon("bob", "pw2").await;
    assert!(
        logon.is_err(),
        "a dropped user must not authenticate after restart"
    );

    server.shutdown().await.expect("clean shutdown");
}

/// A malformed-but-claimed security statement is a clear syntax error (never sent to Cypher), while
/// Cypher that merely resembles a security statement runs normally.
#[tokio::test]
async fn security_grammar_is_strict_on_the_wire() {
    let temp = TempStore::new("grammar");
    let server = boot(base_config(&temp)).await;
    let uds = server.uds_path.clone().expect("UDS enabled");

    let mut c = BoltClient::connect(&uds).await;
    c.handshake_and_logon("alice", "pw").await;

    // Claimed but malformed → a syntax-class FAILURE.
    for bad in [
        "CREATE USER",
        "GRANT READ ON BOGUS TO reader",
        "GRANT ROLE reader FROM alice",
        "CREATE USER eve SET PASSWORD secret", // password must be quoted
    ] {
        let f = c.run(bad).await.expect_err("malformed security statement");
        assert!(f.code.contains("SyntaxError"), "{bad}: {f:?}");
        c.reset().await;
    }

    // Real Cypher that mentions the words runs as Cypher (a node labelled User).
    c.run_ok("CREATE (n:User {name: 'not-a-user'})").await;
    let rows = c.run_ok("MATCH (n:User) RETURN count(n)").await;
    assert_eq!(rows.len(), 1);
    assert!(
        matches!(rows[0].first(), Some(Value::Integer(1))),
        "{rows:?}"
    );

    c.goodbye().await;
    server.shutdown().await.expect("clean shutdown");
}
