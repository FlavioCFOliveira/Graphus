//! End-to-end tests for **session database selection + the administrative command surface**
//! (rmp #84, parent #67; decision `D-multi-db`), driven through a real booted server over the
//! actual wires:
//!
//! - **Bolt over UDS**: the `db` field of `BEGIN`/`RUN` extras routes a session to a named
//!   database; admin statements (`CREATE/DROP/START/STOP/SHOW DATABASE`) execute over the wire.
//! - **REST**: the `{db}` path segment routes; the same admin statements run through the
//!   statement API.
//!
//! Covered: cross-database isolation through real sessions (both wires), default-database
//! semantics for sessions that never name one, clear failures for unknown/offline databases with
//! the session staying usable (Bolt `RESET` recovery), the no-mid-transaction-switch rule, the
//! full admin lifecycle (`CREATE → SHOW → STOP → DROP`, the `IF [NOT] EXISTS` variants,
//! drop-while-online rejected, created databases surviving a restart), the privilege boundary (a
//! non-admin principal is denied with **no side effects**), and the admin-statements-are-not-
//! transactional rule.

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
const JWT_SECRET: &str = "dbadmin-itest-jwt-secret-32-bytes!!!";

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
            "graphus-dbadmin-{tag}-{nanos}-{}",
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

/// REST + UDS on loopback (REST non-TLS for the raw test client), the `alice`/`pw` admin and a
/// non-admin `bob`/`pw2` bootstrap user (read+write only — the rmp-#84 privilege boundary).
fn base_config(temp: &TempStore) -> ServerConfig {
    ServerConfig {
        store_path: temp.store_dir(),
        default_database: "graphus".to_owned(),
        buffer_pool_pages: 256,
        fsync_threads: 1,
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
            admin_password: "pw".to_owned(),
            admin_uid: Some(current_uid()),
            users: vec![UserBootstrap {
                name: "bob".to_owned(),
                password: "pw2".to_owned(),
            }],
        },
        encryption: graphus_server::config::EncryptionConfig::default(),
        audit: graphus_server::AuditConfig::default(),
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

/// Mints a Bearer token for `user`, signed with the server's configured secret (out-of-band token
/// issuance, exactly like `server_integration.rs`).
fn mint_token(user: &str) -> String {
    use graphus_auth::Authenticator;
    let mut auth = Authenticator::new(JWT_SECRET.as_bytes());
    auth.catalog_mut().create_user(user).expect("create user");
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock after epoch")
        .as_secs();
    auth.issue_token(user, now, 3_600).expect("issue token")
}

// ----------------------------------------------------------------------------------------------
// A minimal Bolt client over UDS with `db`-aware RUN/BEGIN and RESET recovery.
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

    /// Performs the handshake, then HELLO + LOGON(basic), asserting both succeed.
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

    /// `RUN` + `PULL -1` with the given extra map. On a RUN failure no PULL is sent (the session
    /// is in the fail-state) and the failure is returned; the caller recovers with [`reset`].
    async fn run_with_extra(
        &mut self,
        query: &str,
        extra: Vec<(String, Value)>,
    ) -> Result<Vec<Vec<Value>>, WireFailure> {
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

    /// `RUN` against a named database (the Bolt 5.x `db` extra field), or the default when `None`.
    async fn run_on_db(
        &mut self,
        query: &str,
        db: Option<&str>,
    ) -> Result<Vec<Vec<Value>>, WireFailure> {
        let extra = match db {
            Some(name) => vec![("db".to_owned(), Value::String(name.to_owned()))],
            None => vec![],
        };
        self.run_with_extra(query, extra).await
    }

    /// `RUN` asserting success, returning the rows.
    async fn run_ok(&mut self, query: &str, db: Option<&str>) -> Vec<Vec<Value>> {
        match self.run_on_db(query, db).await {
            Ok(rows) => rows,
            Err(f) => panic!("query {query:?} on {db:?} failed: {f:?}"),
        }
    }

    /// Runs a single-row, single-column integer query (e.g. a `count(...)`).
    async fn count(&mut self, query: &str, db: Option<&str>) -> i64 {
        let rows = self.run_ok(query, db).await;
        assert_eq!(rows.len(), 1, "count query returns exactly one row");
        match rows[0].first() {
            Some(Value::Integer(n)) => *n,
            other => panic!("expected an integer count, got {other:?}"),
        }
    }

    /// `BEGIN` with an optional `db`, returning the failure (if any).
    async fn begin(&mut self, db: Option<&str>) -> Result<(), WireFailure> {
        let extra = match db {
            Some(name) => vec![("db".to_owned(), Value::String(name.to_owned()))],
            None => vec![],
        };
        self.send(&Request::Begin { extra }).await;
        match self.recv().await {
            Response::Success { .. } => Ok(()),
            Response::Failure(f) => Err(WireFailure {
                code: f.code,
                message: f.message,
            }),
            other => panic!("unexpected BEGIN response: {other:?}"),
        }
    }

    /// `COMMIT`, asserting success.
    async fn commit(&mut self) {
        self.send(&Request::Commit).await;
        assert!(
            matches!(self.recv().await, Response::Success { .. }),
            "COMMIT"
        );
    }

    /// `RESET`, asserting the session returns to READY (the Bolt failure-recovery rule).
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

/// One `SHOW DATABASES` row, decoded from the wire shape (`name`, `state`, `default`, `error`).
#[derive(Debug)]
struct DbRow {
    name: String,
    state: String,
    is_default: bool,
    error: Option<String>,
}

/// Runs `SHOW DATABASES` on `client` and decodes the rows.
async fn show_databases(client: &mut BoltClient) -> Vec<DbRow> {
    let rows = client.run_ok("SHOW DATABASES", None).await;
    rows.into_iter()
        .map(|row| {
            assert_eq!(row.len(), 4, "name, state, default, error: {row:?}");
            let mut it = row.into_iter();
            let name = match it.next() {
                Some(Value::String(s)) => s,
                other => panic!("name must be a string: {other:?}"),
            };
            let state = match it.next() {
                Some(Value::String(s)) => s,
                other => panic!("state must be a string: {other:?}"),
            };
            let is_default = match it.next() {
                Some(Value::Boolean(b)) => b,
                other => panic!("default must be a boolean: {other:?}"),
            };
            let error = match it.next() {
                Some(Value::Null) => None,
                Some(Value::String(s)) => Some(s),
                other => panic!("error must be string/null: {other:?}"),
            };
            DbRow {
                name,
                state,
                is_default,
                error,
            }
        })
        .collect()
}

// ----------------------------------------------------------------------------------------------
// A tiny raw HTTP/1.1 client (no TLS, loopback only), as in `server_integration.rs`.
// ----------------------------------------------------------------------------------------------

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

/// Extracts a top-level JSON string field's value by key from a flat-ish JSON body (test-grade).
fn extract_json_string(body: &str, key: &str) -> Option<String> {
    let needle = format!("\"{key}\":\"");
    let start = body.find(&needle)? + needle.len();
    let rest = &body[start..];
    let end = rest.find('"')?;
    Some(rest[..end].to_owned())
}

/// One `SHOW INDEXES` row, decoded from the wire shape (`label`, `property`, `state`).
#[derive(Debug)]
struct IndexRow {
    label: String,
    property: String,
    state: String,
}

/// Runs `SHOW INDEXES` on `client` (against the default database) and decodes the rows.
async fn show_indexes(client: &mut BoltClient) -> Vec<IndexRow> {
    let rows = client.run_ok("SHOW INDEXES", None).await;
    rows.into_iter()
        .map(|row| {
            assert_eq!(row.len(), 3, "label, property, state: {row:?}");
            let mut it = row.into_iter();
            let mut next_string = |what: &str| match it.next() {
                Some(Value::String(s)) => s,
                other => panic!("{what} must be a string: {other:?}"),
            };
            IndexRow {
                label: next_string("label"),
                property: next_string("property"),
                state: next_string("state"),
            }
        })
        .collect()
}

// ================================================================================================
// Bolt: online index builds (rmp #91) over the wire.
// ================================================================================================

/// `CREATE INDEX` is non-blocking: it returns immediately, concurrent queries keep working while the
/// index builds, the index reaches `online` in `SHOW INDEXES`, an index-accelerated query then
/// returns the correct rows, and `DROP INDEX` removes it.
#[tokio::test]
async fn bolt_create_index_is_non_blocking_and_reaches_online() {
    let temp = TempStore::new("bolt-online-index");
    let server = boot(base_config(&temp)).await;
    let uds = server.uds_path.clone().expect("UDS enabled");

    let mut c = BoltClient::connect(&uds).await;
    c.handshake_and_logon("alice", "pw").await;

    // Seed a populated graph (so the build has work to do).
    for age in 20..30 {
        c.run_ok(&format!("CREATE (:Person {{age: {age}}})"), None)
            .await;
    }
    c.run_ok("CREATE (:Person {age: 25})", None).await; // duplicate value 25

    // CREATE INDEX returns promptly with no rows (the build runs in the background).
    let rows = c
        .run_ok("CREATE INDEX FOR (n:Person) ON (n.age)", None)
        .await;
    assert!(rows.is_empty(), "CREATE INDEX returns no rows");

    // Concurrent queries keep working while the index builds — writes are not blocked.
    c.run_ok("CREATE (:Person {age: 99})", None).await;
    assert_eq!(
        c.count("MATCH (n:Person) RETURN count(n)", None).await,
        12,
        "reads/writes work while the index builds"
    );

    // The index reaches `online` (it is `populating` or `online` throughout; never absent). Poll
    // SHOW INDEXES — the build is driven between engine commands, so each query advances it.
    let mut state = String::new();
    for _ in 0..200 {
        let idx = show_indexes(&mut c).await;
        let row = idx
            .iter()
            .find(|r| r.label == "Person" && r.property == "age")
            .expect("the index is listed throughout the build");
        state = row.state.clone();
        assert!(
            state == "online" || state == "populating",
            "unexpected index state {state:?}"
        );
        if state == "online" {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
    }
    assert_eq!(state, "online", "the index must reach online");

    // The online index answers an equality query correctly (two Persons aged 25).
    assert_eq!(
        c.count("MATCH (n:Person) WHERE n.age = 25 RETURN count(n)", None)
            .await,
        2
    );

    // DROP INDEX removes it.
    let rows = c.run_ok("DROP INDEX FOR (n:Person) ON (n.age)", None).await;
    assert!(rows.is_empty(), "DROP INDEX returns no rows");
    let idx = show_indexes(&mut c).await;
    assert!(
        !idx.iter()
            .any(|r| r.label == "Person" && r.property == "age"),
        "the dropped index is gone: {idx:?}"
    );

    c.goodbye().await;
    server.shutdown().await.expect("clean shutdown");
}

/// Index DDL is on the admin surface: a non-admin principal is denied, and the index commands are
/// rejected inside an explicit transaction (they are not transactional) — with no side effects.
#[tokio::test]
async fn index_ddl_privilege_and_transaction_rules() {
    let temp = TempStore::new("index-ddl-rules");
    let server = boot(base_config(&temp)).await;
    let uds = server.uds_path.clone().expect("UDS enabled");

    // A non-admin (bob) is denied CREATE INDEX and SHOW INDEXES — the Security classification.
    let mut bob = BoltClient::connect(&uds).await;
    bob.handshake_and_logon("bob", "pw2").await;
    let f = bob
        .run_on_db("CREATE INDEX FOR (n:Person) ON (n.age)", None)
        .await
        .expect_err("non-admin denied CREATE INDEX");
    assert!(f.code.contains("Security.Forbidden"), "{f:?}");
    assert!(f.message.contains("permission denied"), "{f:?}");
    bob.reset().await;
    let f = bob
        .run_on_db("SHOW INDEXES", None)
        .await
        .expect_err("non-admin denied SHOW INDEXES");
    assert!(f.code.contains("Security.Forbidden"), "{f:?}");
    bob.reset().await;
    bob.goodbye().await;

    // Admin (alice): index DDL inside an explicit transaction is rejected, with no side effect.
    let mut c = BoltClient::connect(&uds).await;
    c.handshake_and_logon("alice", "pw").await;
    c.begin(None).await.expect("BEGIN");
    let f = c
        .run_on_db("CREATE INDEX FOR (n:Person) ON (n.age)", None)
        .await
        .expect_err("index DDL inside an explicit transaction");
    assert!(f.message.contains("explicit transaction"), "{f:?}");
    c.reset().await;
    // No side effect: the index was not created.
    let idx = show_indexes(&mut c).await;
    assert!(
        !idx.iter()
            .any(|r| r.label == "Person" && r.property == "age"),
        "rejected index DDL must create nothing: {idx:?}"
    );

    // A malformed-but-claimed index statement is a syntax error (never sent to Cypher).
    let f = c
        .run_on_db("CREATE INDEX FOR (n:Person)", None)
        .await
        .expect_err("malformed index statement");
    assert!(f.code.contains("SyntaxError"), "{f:?}");
    c.reset().await;

    // Real Cypher that merely resembles index DDL runs normally (a node labelled Index).
    c.run_ok("CREATE (n:Index {name: 'not-an-index'})", None)
        .await;
    assert_eq!(
        c.count("MATCH (n:Index) RETURN count(n)", None).await,
        1,
        "the Cypher statement executed as Cypher"
    );

    c.goodbye().await;
    server.shutdown().await.expect("clean shutdown");
}

// ================================================================================================
// Bolt: admin lifecycle + session isolation.
// ================================================================================================

/// Create a database over Bolt admin, write into it through a real session naming it, and prove
/// **full isolation** in both directions against the default database. Sessions that never name a
/// database land in the default (the unchanged single-db experience).
#[tokio::test]
async fn bolt_sessions_target_databases_with_full_isolation() {
    let temp = TempStore::new("bolt-isolation");
    let server = boot(base_config(&temp)).await;
    let uds = server.uds_path.clone().expect("UDS enabled");

    let mut admin = BoltClient::connect(&uds).await;
    admin.handshake_and_logon("alice", "pw").await;

    // CREATE DATABASE over the wire: empty result.
    let rows = admin.run_ok("CREATE DATABASE sales", None).await;
    assert!(rows.is_empty(), "CREATE DATABASE returns no rows");

    // SHOW DATABASES: the default (flagged) + sales, both online, no errors.
    let dbs = show_databases(&mut admin).await;
    assert_eq!(dbs.len(), 2, "{dbs:?}");
    let default = dbs
        .iter()
        .find(|d| d.name == "graphus")
        .expect("default row");
    assert!(default.is_default && default.state == "online" && default.error.is_none());
    let sales = dbs.iter().find(|d| d.name == "sales").expect("sales row");
    assert!(!sales.is_default && sales.state == "online" && sales.error.is_none());

    // SHOW DATABASE <name>: exactly that row; an unknown name yields zero rows.
    let one = admin.run_ok("SHOW DATABASE sales", None).await;
    assert_eq!(one.len(), 1);
    let none = admin.run_ok("SHOW DATABASE ghost", None).await;
    assert!(none.is_empty(), "unknown database: zero rows");
    admin.goodbye().await;

    // A separate session writes into `sales` (RUN extra db) and into the default (no db field).
    let mut session = BoltClient::connect(&uds).await;
    session.handshake_and_logon("alice", "pw").await;
    session
        .run_ok("CREATE (:SalesOnly {v: 1})", Some("sales"))
        .await;
    session.run_ok("CREATE (:DefaultOnly {v: 2})", None).await;

    // Isolation, both directions — through real Bolt sessions.
    assert_eq!(
        session
            .count("MATCH (n:SalesOnly) RETURN count(n)", Some("sales"))
            .await,
        1
    );
    assert_eq!(
        session
            .count("MATCH (n:DefaultOnly) RETURN count(n)", Some("sales"))
            .await,
        0
    );
    assert_eq!(
        session
            .count("MATCH (n:DefaultOnly) RETURN count(n)", None)
            .await,
        1
    );
    assert_eq!(
        session
            .count("MATCH (n:SalesOnly) RETURN count(n)", None)
            .await,
        0
    );

    // An explicit transaction pinned to `sales` via BEGIN's db field.
    session.begin(Some("sales")).await.expect("BEGIN db=sales");
    session.run_ok("CREATE (:SalesOnly {v: 3})", None).await; // no db: stays pinned
    session.commit().await;
    assert_eq!(
        session
            .count("MATCH (n:SalesOnly) RETURN count(n)", Some("sales"))
            .await,
        2
    );

    // An empty db string is the default database (Bolt drivers send "" for the home db).
    assert_eq!(
        session
            .count("MATCH (n:DefaultOnly) RETURN count(n)", Some(""))
            .await,
        1
    );

    session.goodbye().await;
    server.shutdown().await.expect("clean shutdown");
}

/// The full lifecycle over the wire: duplicate CREATE fails (then IF NOT EXISTS no-ops), DROP of
/// an online database fails clearly, STOP takes it offline, DROP removes it, and the IF EXISTS
/// variant turns the missing case into a no-op.
#[tokio::test]
async fn bolt_admin_lifecycle_create_show_stop_drop_and_if_variants() {
    let temp = TempStore::new("bolt-lifecycle");
    let server = boot(base_config(&temp)).await;
    let uds = server.uds_path.clone().expect("UDS enabled");

    let mut c = BoltClient::connect(&uds).await;
    c.handshake_and_logon("alice", "pw").await;

    c.run_ok("CREATE DATABASE scratch", None).await;

    // Duplicate CREATE: a clear client error; the session recovers with RESET.
    let f = c
        .run_on_db("CREATE DATABASE scratch", None)
        .await
        .expect_err("duplicate create fails");
    assert!(f.message.contains("already exists"), "{f:?}");
    assert!(f.code.contains("ClientError"), "{f:?}");
    c.reset().await;

    // IF NOT EXISTS: the duplicate becomes a no-op success.
    c.run_ok("CREATE DATABASE scratch IF NOT EXISTS", None)
        .await;
    // The implicit default also "exists": IF NOT EXISTS no-ops rather than erroring.
    c.run_ok("CREATE DATABASE graphus IF NOT EXISTS", None)
        .await;

    // DROP of an online database is rejected (stop first) — catalog rule, surfaced verbatim.
    let f = c
        .run_on_db("DROP DATABASE scratch", None)
        .await
        .expect_err("drop of an online database fails");
    assert!(f.message.contains("stopped"), "{f:?}");
    c.reset().await;

    // STOP → offline (visible in SHOW DATABASES), sessions can no longer target it.
    c.run_ok("STOP DATABASE scratch", None).await;
    let dbs = show_databases(&mut c).await;
    let scratch = dbs.iter().find(|d| d.name == "scratch").expect("listed");
    assert_eq!(scratch.state, "offline");
    let f = c
        .run_on_db("RETURN 1", Some("scratch"))
        .await
        .expect_err("offline database refuses sessions");
    assert!(f.message.contains("not currently online"), "{f:?}");
    c.reset().await;

    // START brings it back online.
    c.run_ok("START DATABASE scratch", None).await;
    assert_eq!(c.count("RETURN 1", Some("scratch")).await, 1);

    // STOP again, then DROP removes it (and its directory).
    c.run_ok("STOP DATABASE scratch", None).await;
    c.run_ok("DROP DATABASE scratch", None).await;
    let dbs = show_databases(&mut c).await;
    assert_eq!(dbs.len(), 1, "only the default remains: {dbs:?}");
    assert!(
        !temp.store_dir().join("databases").join("scratch").exists(),
        "drop removes the database directory"
    );

    // DROP of a missing database fails; IF EXISTS makes it a no-op.
    let f = c
        .run_on_db("DROP DATABASE scratch", None)
        .await
        .expect_err("drop of a missing database fails");
    assert!(f.message.contains("does not exist"), "{f:?}");
    c.reset().await;
    c.run_ok("DROP DATABASE scratch IF EXISTS", None).await;

    c.goodbye().await;
    server.shutdown().await.expect("clean shutdown");
}

/// A database created over the wire (and its data) survives a full server restart: the durable
/// catalog brings it back online at boot.
#[tokio::test]
async fn created_database_survives_a_restart() {
    let temp = TempStore::new("bolt-restart");
    let config = base_config(&temp);

    {
        let server = boot(config.clone()).await;
        let uds = server.uds_path.clone().expect("UDS enabled");
        let mut c = BoltClient::connect(&uds).await;
        c.handshake_and_logon("alice", "pw").await;
        c.run_ok("CREATE DATABASE keep", None).await;
        c.run_ok("CREATE (:Kept {v: 7})", Some("keep")).await;
        c.goodbye().await;
        server.shutdown().await.expect("clean shutdown");
    }

    let server = boot(config).await;
    let uds = server.uds_path.clone().expect("UDS enabled");
    let mut c = BoltClient::connect(&uds).await;
    c.handshake_and_logon("alice", "pw").await;
    let dbs = show_databases(&mut c).await;
    let keep = dbs.iter().find(|d| d.name == "keep").expect("keep is back");
    assert_eq!(keep.state, "online", "online again after the restart");
    assert_eq!(
        c.count("MATCH (n:Kept) RETURN count(n)", Some("keep"))
            .await,
        1,
        "the data recovered with it"
    );
    c.goodbye().await;
    server.shutdown().await.expect("clean shutdown");
}

/// An unknown database is a clear FAILURE with **no side effects**, on auto-commit RUN and on
/// BEGIN; the connection stays usable after RESET (the Bolt fail-then-ignore-until-RESET rule).
#[tokio::test]
async fn bolt_unknown_database_fails_clearly_and_session_recovers() {
    let temp = TempStore::new("bolt-unknown");
    let server = boot(base_config(&temp)).await;
    let uds = server.uds_path.clone().expect("UDS enabled");

    let mut c = BoltClient::connect(&uds).await;
    c.handshake_and_logon("alice", "pw").await;

    // Auto-commit RUN against a missing database.
    let f = c
        .run_on_db("CREATE (:Lost)", Some("missing"))
        .await
        .expect_err("unknown database fails the RUN");
    assert!(f.message.contains("does not exist"), "{f:?}");
    assert!(f.code.contains("ClientError"), "{f:?}");
    c.reset().await;

    // BEGIN against a missing database.
    let f = c
        .begin(Some("missing"))
        .await
        .expect_err("unknown db BEGIN");
    assert!(f.message.contains("does not exist"), "{f:?}");
    c.reset().await;

    // An invalid name is rejected by the name rule, with the rule in the message.
    let f = c
        .run_on_db("RETURN 1", Some("no/slash"))
        .await
        .expect_err("invalid database name");
    assert!(f.message.contains("invalid database name"), "{f:?}");
    c.reset().await;

    // No side effects anywhere, and the session still works against the default.
    assert_eq!(c.count("MATCH (n) RETURN count(n)", None).await, 0);
    c.goodbye().await;
    server.shutdown().await.expect("clean shutdown");
}

/// A RUN naming a *different* database inside an explicit transaction is an error: the
/// transaction is pinned at BEGIN (naming the same database again is fine).
#[tokio::test]
async fn bolt_run_cannot_switch_database_inside_an_explicit_transaction() {
    let temp = TempStore::new("bolt-pin");
    let server = boot(base_config(&temp)).await;
    let uds = server.uds_path.clone().expect("UDS enabled");

    let mut c = BoltClient::connect(&uds).await;
    c.handshake_and_logon("alice", "pw").await;
    c.run_ok("CREATE DATABASE other", None).await;

    c.begin(None).await.expect("BEGIN on the default");
    // Re-naming the pinned database is allowed (case-insensitively)...
    c.run_ok("RETURN 1", Some("GRAPHUS")).await;
    // ...but a different database is not.
    let f = c
        .run_on_db("RETURN 1", Some("other"))
        .await
        .expect_err("mid-transaction switch is rejected");
    assert!(f.message.contains("cannot switch database"), "{f:?}");
    c.reset().await; // RESET rolls the transaction back; the session is usable again.
    assert_eq!(c.count("RETURN 1", Some("other")).await, 1);

    c.goodbye().await;
    server.shutdown().await.expect("clean shutdown");
}

/// Admin statements are not transactional: inside an explicit transaction they are rejected and
/// have **no side effects**.
#[tokio::test]
async fn bolt_admin_commands_are_rejected_inside_an_explicit_transaction() {
    let temp = TempStore::new("bolt-admin-tx");
    let server = boot(base_config(&temp)).await;
    let uds = server.uds_path.clone().expect("UDS enabled");

    let mut c = BoltClient::connect(&uds).await;
    c.handshake_and_logon("alice", "pw").await;

    c.begin(None).await.expect("BEGIN");
    let f = c
        .run_on_db("CREATE DATABASE nope", None)
        .await
        .expect_err("admin command inside an explicit transaction");
    assert!(f.message.contains("explicit transaction"), "{f:?}");
    c.reset().await;

    // No side effect: the database was not created.
    let dbs = show_databases(&mut c).await;
    assert!(
        !dbs.iter().any(|d| d.name == "nope"),
        "rejected admin command must not create anything: {dbs:?}"
    );
    c.goodbye().await;
    server.shutdown().await.expect("clean shutdown");
}

/// The privilege boundary: a non-admin principal (read+write `bob`) can run queries but every
/// admin statement is permission-denied — with no side effects — on both wires.
#[tokio::test]
async fn non_admin_principal_is_denied_admin_commands_with_no_side_effects() {
    let temp = TempStore::new("privilege");
    let server = boot(base_config(&temp)).await;
    let uds = server.uds_path.clone().expect("UDS enabled");
    let rest = server.rest_addr.expect("REST enabled");

    // Bolt: bob authenticates fine and can query...
    let mut bob = BoltClient::connect(&uds).await;
    bob.handshake_and_logon("bob", "pw2").await;
    assert_eq!(bob.count("RETURN 1", None).await, 1);
    // ...but CREATE DATABASE is forbidden (the Security classification, not a generic error).
    let f = bob
        .run_on_db("CREATE DATABASE forbidden", None)
        .await
        .expect_err("non-admin denied");
    assert!(f.code.contains("Security.Forbidden"), "{f:?}");
    assert!(f.message.contains("permission denied"), "{f:?}");
    bob.reset().await;
    // SHOW DATABASES is part of the admin surface too.
    let f = bob
        .run_on_db("SHOW DATABASES", None)
        .await
        .expect_err("SHOW DATABASES requires admin");
    assert!(f.code.contains("Security.Forbidden"), "{f:?}");
    bob.reset().await;
    bob.goodbye().await;

    // REST: bob's token runs statements but the admin statement is 403.
    let bob_token = mint_token("bob");
    let (status, _body) = rest_statement(rest, &bob_token, "graphus", "RETURN 1").await;
    assert_eq!(status, 200, "bob can query over REST");
    let (status, body) =
        rest_statement(rest, &bob_token, "graphus", "CREATE DATABASE forbidden").await;
    assert_eq!(
        status, 403,
        "non-admin admin statement is forbidden: {body}"
    );
    assert!(body.contains("Security.Forbidden"), "{body}");

    // No side effects: the admin sees no `forbidden` database.
    let mut alice = BoltClient::connect(&uds).await;
    alice.handshake_and_logon("alice", "pw").await;
    let dbs = show_databases(&mut alice).await;
    assert!(
        !dbs.iter().any(|d| d.name == "forbidden"),
        "denied commands must leave no trace: {dbs:?}"
    );
    alice.goodbye().await;
    server.shutdown().await.expect("clean shutdown");
}

// ================================================================================================
// REST: `{db}` routing + the admin surface through the statement API.
// ================================================================================================

/// The REST `{db}` path segment routes a request to the named database, with full isolation
/// against the default; the admin statements work through the statement API; an unknown database
/// is a clear error with no side effects; admin statements are rejected in an explicit
/// transaction.
#[tokio::test]
async fn rest_db_routing_admin_surface_and_isolation() {
    let temp = TempStore::new("rest-routing");
    let server = boot(base_config(&temp)).await;
    let rest = server.rest_addr.expect("REST enabled");
    let token = mint_token("alice");

    // Create a database through the REST statement API.
    let (status, body) = rest_statement(rest, &token, "graphus", "CREATE DATABASE webdb").await;
    assert_eq!(status, 200, "create over REST: {body}");

    // SHOW DATABASES over REST lists it (rows ride the normal result envelope).
    let (status, body) = rest_statement(rest, &token, "graphus", "SHOW DATABASES").await;
    assert_eq!(status, 200, "show over REST: {body}");
    assert!(body.contains("webdb") && body.contains("graphus"), "{body}");

    // Write into webdb through `{db}` routing; write into the default through its own name.
    let (status, body) = rest_statement(rest, &token, "webdb", "CREATE (:WebOnly {v: 1})").await;
    assert_eq!(status, 200, "write into webdb: {body}");
    let (status, body) =
        rest_statement(rest, &token, "graphus", "CREATE (:DefaultOnly {v: 2})").await;
    assert_eq!(status, 200, "write into the default: {body}");

    // Isolation, both directions.
    let (_, body) =
        rest_statement(rest, &token, "webdb", "MATCH (n:WebOnly) RETURN count(n)").await;
    assert!(body.contains('1'), "webdb sees its node: {body}");
    let (_, body) = rest_statement(
        rest,
        &token,
        "webdb",
        "MATCH (n:DefaultOnly) RETURN count(n)",
    )
    .await;
    assert!(
        body.contains('0'),
        "webdb does not see the default's node: {body}"
    );
    let (_, body) =
        rest_statement(rest, &token, "graphus", "MATCH (n:WebOnly) RETURN count(n)").await;
    assert!(
        body.contains('0'),
        "the default does not see webdb's node: {body}"
    );

    // The default name is matched case-insensitively (the catalog's name rule).
    let (status, _) = rest_statement(rest, &token, "GRAPHUS", "RETURN 1").await;
    assert_eq!(status, 200, "the default name is case-insensitive");

    // Unknown database: a clear client error (400 Request.Invalid), no side effects, and the
    // server keeps serving.
    let (status, body) = rest_statement(rest, &token, "ghost", "CREATE (:Lost)").await;
    assert_eq!(status, 400, "unknown database is a client error: {body}");
    assert!(body.contains("does not exist"), "{body}");
    let (status, _) = rest_statement(rest, &token, "graphus", "RETURN 1").await;
    assert_eq!(status, 200, "the server keeps serving after the error");

    // Admin statements are rejected inside an explicit REST transaction.
    let (status, body) = http_request(
        rest,
        "POST",
        "/db/graphus/tx",
        Some(&token),
        Some(r#"{"statements":[],"access_mode":"WRITE"}"#),
    )
    .await;
    assert_eq!(status, 201, "begin: {body}");
    let tx_id = extract_json_string(&body, "id").expect("tx id");
    let (status, body) = http_request(
        rest,
        "POST",
        &format!("/db/graphus/tx/{tx_id}"),
        Some(&token),
        Some(r#"{"statements":[{"statement":"CREATE DATABASE nope"}]}"#),
    )
    .await;
    assert_eq!(status, 400, "admin in an explicit tx is rejected: {body}");
    assert!(body.contains("explicit transaction"), "{body}");
    let (status, body) = rest_statement(rest, &token, "graphus", "SHOW DATABASES").await;
    assert_eq!(status, 200);
    assert!(!body.contains("nope"), "no side effects: {body}");

    server.shutdown().await.expect("clean shutdown");
}

/// A malformed-but-claimed admin statement is a clear syntax error (it is never sent to Cypher),
/// while Cypher statements that merely resemble admin ones run normally.
#[tokio::test]
async fn admin_grammar_is_strict_on_the_wire() {
    let temp = TempStore::new("grammar");
    let server = boot(base_config(&temp)).await;
    let uds = server.uds_path.clone().expect("UDS enabled");

    let mut c = BoltClient::connect(&uds).await;
    c.handshake_and_logon("alice", "pw").await;

    // Claimed (CREATE DATABASE …) but malformed → a syntax-class FAILURE.
    let f = c
        .run_on_db("CREATE DATABASE one two", None)
        .await
        .expect_err("malformed admin statement");
    assert!(f.code.contains("SyntaxError"), "{f:?}");
    c.reset().await;

    // Looks adjacent but is real Cypher: a node labelled Database is NOT swallowed.
    c.run_ok("CREATE (n:Database {name: 'not-a-db'})", None)
        .await;
    assert_eq!(
        c.count("MATCH (n:Database) RETURN count(n)", None).await,
        1,
        "the Cypher statement executed as Cypher"
    );

    c.goodbye().await;
    server.shutdown().await.expect("clean shutdown");
}
