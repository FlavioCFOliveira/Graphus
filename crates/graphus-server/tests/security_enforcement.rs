//! End-to-end tests for **fine-grained RBAC enforcement at query time** (rmp #93, completing the
//! access-control epic #68; the model + durable catalog + admin surface are #92), driven through a
//! real booted server over Bolt-over-UDS.
//!
//! These prove the *enforcement* half that `security_admin_surface.rs` deliberately did not exercise:
//!
//! - an **admin** principal sees and writes everything (the unrestricted pass-through);
//! - a **restricted** principal cannot traverse a denied label, read a denied property (it reads as
//!   absent/NULL while the node stays visible), traverse a denied relationship type, or write a
//!   denied label/type/property (rejected as `Neo.ClientError.Security.Forbidden`);
//! - a **grant** an admin applies takes effect on the restricted principal's **next** statement, and
//!   a **revoke** likewise — because enforcement resolves against the *live* security catalog per
//!   statement (the property #92 deferred to #93).
//!
//! ## Why enforcement is tested via an existing user whose grants change
//!
//! These tests use the bootstrap user `bob` and change *his* grants at runtime, which exercises both
//! fine-grained enforcement and the grant/revoke-takes-effect-next-statement guarantee end-to-end.
//! (The complementary property — that a user *created* at runtime can immediately LOGON / present a
//! Bearer token, and a runtime password change / `DROP USER` takes effect for authentication without
//! a reboot — is now live as of rmp #94 and is proved by `security_live_auth.rs`.) The
//! unrestricted/admin path here is unchanged, so the TCK ratchet is unaffected.

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
/// and a structural list element-wise. These tests assert only on scalars; the entity ids are
/// inert here.
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
const JWT_SECRET: &str = "secenforce-itest-jwt-secret-32-bytes!";

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
            "graphus-secenforce-{tag}-{nanos}-{}",
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

    /// The durable security file path under the store directory (for the DENY-durability test).
    fn security_file(&self) -> PathBuf {
        self.store_dir().join("security.toml")
    }
}

impl Drop for TempStore {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

/// UDS on loopback, the `alice`/`pw` admin (bound to this process uid for peer-cred), and a non-admin
/// `bob`/`pw2` bootstrap user. `bob` starts with the server-wide `readwrite` role; the enforcement
/// tests narrow him at runtime.
fn base_config(temp: &TempStore) -> ServerConfig {
    ServerConfig {
        store_path: temp.store_dir(),
        default_database: "graphus".to_owned(),
        buffer_pool_pages: 256,
        bolt_tcp_addr: None,
        advertised_bolt_address: None,
        bolt_server_agent: None,
        rest_addr: None,
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
        bulk_import: graphus_server::config::BulkImportConfig::default(),
        metrics_scrape_token: None,
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
        // macOS/BSD: std exposes no `getuid()`; read the real uid via `id -u` so it matches the uid the
        // server's UDS peer-cred gate reports (via `getpeereid`). Returning 0 mismatched the runner's uid.
        std::process::Command::new("id")
            .arg("-u")
            .output()
            .ok()
            .and_then(|o| String::from_utf8(o.stdout).ok())
            .and_then(|s| s.trim().parse::<u32>().ok())
            .unwrap_or(0)
    }
}

async fn boot(config: ServerConfig) -> ServerHandle {
    Server::new(config)
        .start()
        .await
        .expect("server should boot")
}

// ----------------------------------------------------------------------------------------------
// A minimal Bolt client over UDS (mirrors security_admin_surface.rs).
// ----------------------------------------------------------------------------------------------

#[derive(Debug)]
struct WireFailure {
    code: String,
    #[allow(dead_code)] // kept for diagnostics in assertion messages
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

    /// `RUN` + `PULL -1`. On a RUN failure no PULL is sent (the session is fail-state) and the failure
    /// is returned; the caller recovers with [`reset`](Self::reset).
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

/// Collects the integer in column `col` of every row (entities project to their id as an integer;
/// scalar properties project as their value).
fn ints(rows: &[Vec<Value>], col: usize) -> Vec<i64> {
    rows.iter()
        .map(|r| match r.get(col) {
            Some(Value::Integer(i)) => *i,
            other => panic!("expected an integer in column {col}, got {other:?}"),
        })
        .collect()
}

/// Collects the optional string in column `col` of every row (a hidden property reads as NULL).
fn opt_strings(rows: &[Vec<Value>], col: usize) -> Vec<Option<String>> {
    rows.iter()
        .map(|r| match r.get(col) {
            Some(Value::String(s)) => Some(s.clone()),
            Some(Value::Null) => None,
            other => panic!("expected a string or null in column {col}, got {other:?}"),
        })
        .collect()
}

// ================================================================================================
// Tests
// ================================================================================================

/// The end-to-end enforcement story over the wire: admin sees everything; a restricted user is
/// filtered (denied label invisible, denied property hidden, denied rel-type not traversed, denied
/// write rejected); a grant and then a revoke each take effect on the restricted user's next
/// statement.
#[tokio::test]
async fn fine_grained_enforcement_admin_restricted_and_live_grant_revoke() {
    let temp = TempStore::new("enforce");
    let server = boot(base_config(&temp)).await;
    let uds = server.uds_path.clone().expect("UDS enabled");

    // ---- 1) Admin seeds data and sees everything (unrestricted pass-through). -------------------
    let mut alice = BoltClient::connect(&uds).await;
    alice.handshake_and_logon("alice", "admin-pw8").await;

    alice
        .run_ok("CREATE (:Person {name: 'Ada', secret: 'hush'})")
        .await;
    alice
        .run_ok("CREATE (:Person {name: 'Bob', secret: 'shush'})")
        .await;
    alice.run_ok("CREATE (:Secret {code: 42})").await;
    // A KNOWS relationship Ada->Bob, plus a HIDDEN relationship Ada->the Secret node.
    alice
        .run_ok(
            "MATCH (a:Person {name: 'Ada'}), (b:Person {name: 'Bob'}) \
             CREATE (a)-[:KNOWS {since: 2010}]->(b)",
        )
        .await;
    alice
        .run_ok("MATCH (a:Person {name: 'Ada'}), (s:Secret) CREATE (a)-[:HIDDEN]->(s)")
        .await;

    // Admin sees all three nodes and both labels.
    let all_people = alice.run_ok("MATCH (n:Person) RETURN n.name").await;
    assert_eq!(opt_strings(&all_people, 0).len(), 2, "admin sees 2 Person");
    let all_secret = alice.run_ok("MATCH (n:Secret) RETURN n.code").await;
    assert_eq!(ints(&all_secret, 0), vec![42], "admin sees the Secret node");
    alice.goodbye().await;

    // ---- 2) Narrow bob to Traverse+Read on :Person.name only (revoke his broad readwrite). ------
    let mut admin = BoltClient::connect(&uds).await;
    admin.handshake_and_logon("alice", "admin-pw8").await;
    admin.run_ok("REVOKE ROLE readwrite FROM bob").await;
    admin.run_ok("CREATE ROLE person_reader").await;
    admin
        .run_ok("GRANT TRAVERSE ON LABEL graphus.Person TO person_reader")
        .await;
    admin
        .run_ok("GRANT READ ON PROPERTY graphus.Person.name TO person_reader")
        .await;
    admin.run_ok("GRANT ROLE person_reader TO bob").await;
    admin.goodbye().await;

    // bob now connects and is filtered.
    let mut bob = BoltClient::connect(&uds).await;
    bob.handshake_and_logon("bob", "user2-pw8").await;

    // Person nodes are visible; `name` reads; `secret` is hidden (reads as NULL, node still visible).
    let people = bob.run_ok("MATCH (n:Person) RETURN n.name, n.secret").await;
    let names = opt_strings(&people, 0);
    assert_eq!(names.len(), 2, "bob sees both Person nodes: {names:?}");
    assert!(
        names.contains(&Some("Ada".to_owned())) && names.contains(&Some("Bob".to_owned())),
        "bob reads names: {names:?}"
    );
    let secrets = opt_strings(&people, 1);
    assert!(
        secrets.iter().all(Option::is_none),
        "secret is hidden (NULL) for bob: {secrets:?}"
    );

    // The :Secret label is invisible — its node is filtered out entirely.
    let bob_secret = bob.run_ok("MATCH (n:Secret) RETURN n.code").await;
    assert!(
        bob_secret.is_empty(),
        "bob cannot traverse :Secret: {bob_secret:?}"
    );

    // The KNOWS relationship is type-denied -> not traversed (bob has no rel-type grant).
    let knows = bob
        .run_ok("MATCH (:Person {name: 'Ada'})-[:KNOWS]->(m) RETURN m.name")
        .await;
    assert!(knows.is_empty(), "bob cannot traverse :KNOWS: {knows:?}");

    // A write to a denied label is rejected as Security.Forbidden, with no side effect.
    let denied = bob
        .run("CREATE (:Secret {code: 99})")
        .await
        .expect_err("write to denied label rejected");
    assert!(
        denied.code.contains("Security.Forbidden"),
        "denied write classifies as Forbidden: {denied:?}"
    );
    bob.reset().await;

    // A write to a denied property on a label bob cannot write is likewise rejected.
    let denied_prop = bob
        .run("MATCH (n:Person {name: 'Ada'}) SET n.name = 'Eve'")
        .await
        .expect_err("write to a non-writable label rejected");
    assert!(
        denied_prop.code.contains("Security.Forbidden"),
        "denied property write classifies as Forbidden: {denied_prop:?}"
    );
    bob.reset().await;

    // ---- 3) A live GRANT takes effect on bob's NEXT statement. ----------------------------------
    // Admin grants bob Read on :Person.secret; bob's next query reads it without reconnecting.
    let mut admin2 = BoltClient::connect(&uds).await;
    admin2.handshake_and_logon("alice", "admin-pw8").await;
    admin2
        .run_ok("GRANT READ ON PROPERTY graphus.Person.secret TO person_reader")
        .await;
    admin2.goodbye().await;

    let people2 = bob.run_ok("MATCH (n:Person) RETURN n.name, n.secret").await;
    let secrets2 = opt_strings(&people2, 1);
    assert!(
        secrets2.contains(&Some("hush".to_owned())) && secrets2.contains(&Some("shush".to_owned())),
        "after the live grant, bob reads the secret on his NEXT statement: {secrets2:?}"
    );

    // ---- 4) A live REVOKE takes effect on bob's NEXT statement. ----------------------------------
    let mut admin3 = BoltClient::connect(&uds).await;
    admin3.handshake_and_logon("alice", "admin-pw8").await;
    admin3
        .run_ok("REVOKE READ ON PROPERTY graphus.Person.secret FROM person_reader")
        .await;
    admin3.goodbye().await;

    let people3 = bob.run_ok("MATCH (n:Person) RETURN n.name, n.secret").await;
    let secrets3 = opt_strings(&people3, 1);
    assert!(
        secrets3.iter().all(Option::is_none),
        "after the live revoke, the secret is hidden again on bob's NEXT statement: {secrets3:?}"
    );
    // ...but name is still readable (the revoke was scoped to `secret`).
    assert_eq!(
        opt_strings(&people3, 0).len(),
        2,
        "name still readable after the secret revoke"
    );

    bob.goodbye().await;
    server.shutdown().await.expect("clean shutdown");
}

/// A regression guard for the unrestricted/admin pass-through: an admin's reads and writes behave
/// exactly as a server without RBAC — every node, label, property and relationship is visible, and no
/// write is rejected. (The restricted path is covered above; this pins that enforcement never leaks
/// into the admin path, which is what keeps the TCK ratchet from regressing.)
#[tokio::test]
async fn admin_path_is_unrestricted() {
    let temp = TempStore::new("admin-unrestricted");
    let server = boot(base_config(&temp)).await;
    let uds = server.uds_path.clone().expect("UDS enabled");

    let mut alice = BoltClient::connect(&uds).await;
    alice.handshake_and_logon("alice", "admin-pw8").await;

    alice
        .run_ok("CREATE (:A {p: 1})-[:R {w: 2}]->(:B {q: 3})")
        .await;
    // Every label, property and relationship is visible to the admin.
    let a = alice.run_ok("MATCH (n:A) RETURN n.p").await;
    assert_eq!(ints(&a, 0), vec![1]);
    let b = alice.run_ok("MATCH (n:B) RETURN n.q").await;
    assert_eq!(ints(&b, 0), vec![3]);
    let r = alice.run_ok("MATCH (:A)-[rel:R]->(:B) RETURN rel.w").await;
    assert_eq!(
        ints(&r, 0),
        vec![2],
        "admin traverses :R and reads its prop"
    );

    // Writes are never rejected for an admin.
    alice.run_ok("MATCH (n:A) SET n.p = 10").await;
    let a2 = alice.run_ok("MATCH (n:A) RETURN n.p").await;
    assert_eq!(ints(&a2, 0), vec![10]);

    alice.goodbye().await;
    server.shutdown().await.expect("clean shutdown");
}

/// **DENY enforcement at query time** (rmp #645): an explicit `DENY` takes precedence over a broad
/// `GRANT` and is enforced element-by-element exactly like a missing grant would be — but critically
/// it *carves holes out of* a grant the principal already holds, and the grant is **never erased**
/// (a `REVOKE DENY` restores access on the next statement). This proves the four-site DENY threading
/// end-to-end through the real engine: `EffectivePrivileges` snapshots the deny union and the
/// `AuthorizedGraph` predicates apply it with precedence.
#[tokio::test]
async fn deny_precedence_is_enforced_at_query_time() {
    let temp = TempStore::new("deny-enforce");
    let server = boot(base_config(&temp)).await;
    let uds = server.uds_path.clone().expect("UDS enabled");

    // ---- 1) Admin seeds data. ------------------------------------------------------------------
    let mut alice = BoltClient::connect(&uds).await;
    alice.handshake_and_logon("alice", "admin-pw8").await;
    alice
        .run_ok("CREATE (:Person {name: 'Ada', secret: 'hush'})")
        .await;
    alice
        .run_ok("CREATE (:Person {name: 'Bob', secret: 'shush'})")
        .await;
    alice.run_ok("CREATE (:Secret {code: 42})").await;
    alice.goodbye().await;

    // ---- 2) Give bob a BROAD grant (Write on the whole graph), then DENY specific things. -------
    // Write on the graph implies Read+Traverse everywhere, so absent any deny bob would see and
    // write everything; each DENY below must carve a precise hole out of that broad grant.
    let mut admin = BoltClient::connect(&uds).await;
    admin.handshake_and_logon("alice", "admin-pw8").await;
    admin.run_ok("REVOKE ROLE readwrite FROM bob").await;
    admin.run_ok("CREATE ROLE broad").await;
    admin.run_ok("GRANT WRITE ON GRAPH graphus TO broad").await;
    admin.run_ok("GRANT ROLE broad TO bob").await;
    // DENY TRAVERSE on :Secret (node invisible), DENY READ on :Person.secret (property NULL, node
    // still visible — the graded reversal), DENY WRITE on :Secret (creation refused).
    admin
        .run_ok("DENY TRAVERSE ON LABEL graphus.Secret TO broad")
        .await;
    admin
        .run_ok("DENY READ ON PROPERTY graphus.Person.secret TO broad")
        .await;
    admin
        .run_ok("DENY WRITE ON LABEL graphus.Secret TO broad")
        .await;
    // SHOW PRIVILEGES reports the denies with access = DENIED.
    let privs = admin.run_ok("SHOW PRIVILEGES").await;
    let broad_denied: Vec<(String, String)> = privs
        .iter()
        .filter(|r| {
            matches!(r.first(), Some(Value::String(s)) if s == "broad")
                && matches!(&r[1], Value::String(a) if a == "DENIED")
        })
        .map(|r| match (&r[2], &r[3]) {
            (Value::String(a), Value::String(s)) => (a.clone(), s.clone()),
            other => panic!("priv row shape: {other:?}"),
        })
        .collect();
    assert!(
        broad_denied.contains(&("traverse".to_owned(), "LABEL graphus.Secret".to_owned())),
        "DENIED traverse Secret listed: {broad_denied:?}"
    );
    assert!(
        broad_denied.contains(&(
            "read".to_owned(),
            "PROPERTY graphus.Person.secret".to_owned()
        )),
        "DENIED read Person.secret listed: {broad_denied:?}"
    );
    admin.goodbye().await;

    // ---- 3) bob is filtered by the denies despite the graph-wide grant. ------------------------
    let mut bob = BoltClient::connect(&uds).await;
    bob.handshake_and_logon("bob", "user2-pw8").await;

    // Person nodes visible + name readable (grant), but `secret` denied → NULL (node still visible:
    // DENY READ leaves TRAVERSE intact).
    let people = bob.run_ok("MATCH (n:Person) RETURN n.name, n.secret").await;
    assert_eq!(opt_strings(&people, 0).len(), 2, "bob sees both Person");
    assert!(
        opt_strings(&people, 0).contains(&Some("Ada".to_owned())),
        "bob reads name despite the deny on secret: {people:?}"
    );
    assert!(
        opt_strings(&people, 1).iter().all(Option::is_none),
        "DENY READ hides secret (NULL) but not the node: {:?}",
        opt_strings(&people, 1)
    );
    // :Secret label denied-traverse → node invisible even though the graph grant covers it.
    let secret = bob.run_ok("MATCH (n:Secret) RETURN n.code").await;
    assert!(
        secret.is_empty(),
        "DENY TRAVERSE hides :Secret despite the graph-wide grant: {secret:?}"
    );
    // Writing :Person is allowed (grant, no deny) but writing :Secret is refused (deny precedence).
    bob.run_ok("CREATE (:Person {name: 'Cy'})").await;
    let denied_write = bob
        .run("CREATE (:Secret {code: 99})")
        .await
        .expect_err("DENY WRITE on :Secret refuses the create");
    assert!(
        denied_write.code.contains("Security.Forbidden"),
        "denied write classifies as Forbidden: {denied_write:?}"
    );
    bob.reset().await;

    // ---- 4) REVOKE DENY restores access on bob's NEXT statement (the grant was never erased). ---
    let mut admin2 = BoltClient::connect(&uds).await;
    admin2.handshake_and_logon("alice", "admin-pw8").await;
    admin2
        .run_ok("REVOKE DENY READ ON PROPERTY graphus.Person.secret FROM broad")
        .await;
    admin2
        .run_ok("REVOKE DENY TRAVERSE ON LABEL graphus.Secret FROM broad")
        .await;
    admin2.goodbye().await;

    // bob's next statement: the underlying graph-wide grant is intact, so secret + :Secret return.
    let people2 = bob.run_ok("MATCH (n:Person) RETURN n.secret").await;
    let secrets2 = opt_strings(&people2, 0);
    assert!(
        secrets2.contains(&Some("hush".to_owned())),
        "REVOKE DENY restores the secret read on the NEXT statement (grant never erased): {secrets2:?}"
    );
    let secret2 = bob.run_ok("MATCH (n:Secret) RETURN n.code").await;
    assert_eq!(
        ints(&secret2, 0),
        vec![42],
        "REVOKE DENY makes :Secret visible again"
    );

    bob.goodbye().await;
    server.shutdown().await.expect("clean shutdown");
}

/// **DENY-across-labels precedence on multi-label nodes** (CWE-863 regression, fix-forward of rmp
/// #645). A node carrying two labels `(:Report:Classified)` where a broad `GRANT` reaches both labels
/// but an explicit `DENY` targets one of them: Neo4j semantics are `(∃l: granted(l)) ∧ (∄l: denied(l))`
/// — a `DENY` on **any** label of the node blocks it, even when another label grants access. The
/// pre-fix executor unioned the per-label verdicts with a bare `OR` (`∃l: granted(l) ∧ ¬denied(l)`),
/// so the node/property/write leaked through the *other*, non-denied label. This proves the fix
/// end-to-end over the wire for traverse, property-read, and write (SET + CREATE), and confirms the
/// deny is surgical — a sibling plain `(:Report)` node and non-denied properties/writes are untouched.
#[tokio::test]
async fn deny_precedence_across_labels_on_multilabel_nodes() {
    let temp = TempStore::new("deny-multilabel");
    let server = boot(base_config(&temp)).await;
    let uds = server.uds_path.clone().expect("UDS enabled");

    // ---- 1) Admin seeds a plain :Report and a multi-label :Report:Classified. ------------------
    let mut alice = BoltClient::connect(&uds).await;
    alice.handshake_and_logon("alice", "admin-pw8").await;
    alice
        .run_ok("CREATE (:Report {title: 'Public memo', contents: 'nothing secret'})")
        .await;
    alice
        .run_ok("CREATE (:Report:Classified {title: 'Q3 numbers', contents: 'TOP SECRET'})")
        .await;
    alice.goodbye().await;

    // ---- 2) bob: READ on the whole graph, but DENY TRAVERSE on :Classified. --------------------
    let mut admin = BoltClient::connect(&uds).await;
    admin.handshake_and_logon("alice", "admin-pw8").await;
    admin.run_ok("REVOKE ROLE readwrite FROM bob").await;
    admin.run_ok("CREATE ROLE analyst").await;
    admin.run_ok("GRANT READ ON GRAPH graphus TO analyst").await;
    admin
        .run_ok("DENY TRAVERSE ON LABEL graphus.Classified TO analyst")
        .await;
    admin.run_ok("GRANT ROLE analyst TO bob").await;

    let mut bob = BoltClient::connect(&uds).await;
    bob.handshake_and_logon("bob", "user2-pw8").await;

    // Phase A: a `:Report` match returns ONLY the plain node — the (:Report:Classified) node is
    // hidden by the DENY on its :Classified label, even though the graph-wide grant reaches :Report.
    // (This is the exploit: pre-fix, the classified node leaked through its :Report label.)
    let reports = bob.run_ok("MATCH (n:Report) RETURN n.title").await;
    let titles = opt_strings(&reports, 0);
    assert_eq!(
        titles,
        vec![Some("Public memo".to_owned())],
        "only the non-classified :Report is visible; the DENY on :Classified hides the other: {titles:?}"
    );
    // A `:Classified` match returns nothing (the node is hidden via its denied label).
    let classified = bob.run_ok("MATCH (n:Classified) RETURN n.title").await;
    assert!(
        classified.is_empty(),
        "the classified node is hidden through its denied label: {classified:?}"
    );

    // ---- 3) Reconfigure: revoke the traverse deny, DENY READ on :Classified.contents. ----------
    admin
        .run_ok("REVOKE DENY TRAVERSE ON LABEL graphus.Classified FROM analyst")
        .await;
    admin
        .run_ok("DENY READ ON PROPERTY graphus.Classified.contents TO analyst")
        .await;

    // Phase B: both :Report nodes are now visible (DENY READ leaves traverse intact), but the
    // classified node's `contents` reads as NULL while the plain node's `contents` is readable — the
    // property deny is applied per-node via its :Classified label, never leaking the secret.
    let reports2 = bob
        .run_ok("MATCH (n:Report) RETURN n.title, n.contents")
        .await;
    assert_eq!(
        opt_strings(&reports2, 0).len(),
        2,
        "both :Report nodes are visible after the traverse deny is revoked"
    );
    let contents = opt_strings(&reports2, 1);
    assert!(
        contents.contains(&Some("nothing secret".to_owned())),
        "the plain :Report's contents is readable: {contents:?}"
    );
    assert!(
        contents.contains(&None),
        "the classified node's contents is hidden (NULL): {contents:?}"
    );
    assert!(
        !contents.contains(&Some("TOP SECRET".to_owned())),
        "the classified secret must NEVER leak via the :Report label: {contents:?}"
    );
    // Directly via :Classified: node visible, title reads, contents hidden.
    let cls = bob
        .run_ok("MATCH (n:Classified) RETURN n.title, n.contents")
        .await;
    assert_eq!(
        opt_strings(&cls, 0),
        vec![Some("Q3 numbers".to_owned())],
        "classified node visible, title reads"
    );
    assert_eq!(
        opt_strings(&cls, 1),
        vec![None],
        "classified contents hidden via DENY READ on :Classified.contents"
    );

    // ---- 4) Reconfigure: WRITE on the graph, DENY WRITE on :Classified.contents. ---------------
    admin
        .run_ok("REVOKE DENY READ ON PROPERTY graphus.Classified.contents FROM analyst")
        .await;
    admin
        .run_ok("GRANT WRITE ON GRAPH graphus TO analyst")
        .await;
    admin
        .run_ok("DENY WRITE ON PROPERTY graphus.Classified.contents TO analyst")
        .await;

    // Phase C: a SET of the denied property on the multi-label node is rejected (Forbidden), even
    // though the graph-wide WRITE grant reaches contents via :Report.
    let denied_set = bob
        .run("MATCH (n:Classified) SET n.contents = 'leaked'")
        .await
        .expect_err("DENY WRITE on :Classified.contents rejects the SET");
    assert!(
        denied_set.code.contains("Security.Forbidden"),
        "denied SET classifies as Forbidden: {denied_set:?}"
    );
    bob.reset().await;
    // A CREATE of a new (:Report:Classified {contents}) is likewise rejected — the create's property
    // check must union DENY-wins across the created labels (the write leaks via :Report pre-fix).
    let denied_create = bob
        .run("CREATE (:Report:Classified {contents: 'x'})")
        .await
        .expect_err("DENY WRITE on :Classified.contents rejects the CREATE");
    assert!(
        denied_create.code.contains("Security.Forbidden"),
        "denied CREATE classifies as Forbidden: {denied_create:?}"
    );
    bob.reset().await;
    // A non-denied write still succeeds (SET title), proving the deny is surgical, not blanket.
    bob.run_ok("MATCH (n:Classified) SET n.title = 'edited'")
        .await;

    // ---- 5) Admin verifies the denied writes had NO side effect. -------------------------------
    let final_state = admin
        .run_ok("MATCH (n:Classified) RETURN n.contents, n.title")
        .await;
    assert_eq!(
        opt_strings(&final_state, 0),
        vec![Some("TOP SECRET".to_owned())],
        "the denied SET/CREATE left contents unchanged"
    );
    assert_eq!(
        opt_strings(&final_state, 1),
        vec![Some("edited".to_owned())],
        "the non-denied title write applied"
    );
    // The denied CREATE created no node (still exactly one :Classified node).
    let count = admin.run_ok("MATCH (n:Classified) RETURN count(n)").await;
    assert_eq!(
        ints(&count, 0),
        vec![1],
        "the denied CREATE produced no node"
    );

    admin.goodbye().await;
    bob.goodbye().await;
    server.shutdown().await.expect("clean shutdown");
}

/// A restart durability check for DENY (rmp #645): a `DENY` recorded over the wire survives a full
/// server restart (persisted in `security.toml` alongside grants) and is still enforced afterwards,
/// and the deny record is durable but never as a plaintext leak.
#[tokio::test]
async fn deny_survives_restart_and_is_still_enforced() {
    let temp = TempStore::new("deny-restart");
    let config = base_config(&temp);

    {
        let server = boot(config.clone()).await;
        let uds = server.uds_path.clone().expect("UDS enabled");
        let mut alice = BoltClient::connect(&uds).await;
        alice.handshake_and_logon("alice", "admin-pw8").await;
        alice.run_ok("CREATE (:Person {name: 'Ada'})").await;
        alice.run_ok("CREATE (:Secret {code: 7})").await;
        alice.run_ok("REVOKE ROLE readwrite FROM bob").await;
        alice.run_ok("CREATE ROLE reader2").await;
        alice.run_ok("GRANT READ ON GRAPH graphus TO reader2").await;
        alice
            .run_ok("DENY TRAVERSE ON LABEL graphus.Secret TO reader2")
            .await;
        alice.run_ok("GRANT ROLE reader2 TO bob").await;
        alice.goodbye().await;
        server.shutdown().await.expect("clean shutdown");
    }

    // The persisted file records the deny (deny = true) alongside the grant.
    let text = std::fs::read_to_string(temp.security_file()).expect("security file");
    assert!(
        text.contains("deny = true"),
        "the deny is persisted: {text}"
    );

    // Restart: the deny is authoritative and still enforced.
    let server = boot(config).await;
    let uds = server.uds_path.clone().expect("UDS enabled");
    let mut bob = BoltClient::connect(&uds).await;
    bob.handshake_and_logon("bob", "user2-pw8").await;
    // Person is readable (grant survived); :Secret is invisible (deny survived).
    let people = bob.run_ok("MATCH (n:Person) RETURN n.name").await;
    assert_eq!(opt_strings(&people, 0).len(), 1, "grant survived restart");
    let secret = bob.run_ok("MATCH (n:Secret) RETURN n.code").await;
    assert!(
        secret.is_empty(),
        "the DENY on :Secret survived the restart and is still enforced: {secret:?}"
    );
    bob.goodbye().await;
    server.shutdown().await.expect("clean shutdown");
}

/// `rmp` #822 (regression, whole-query end-to-end): a fused index seek / precise equality scan on a
/// property a restricted principal is **denied** read on must return EXACTLY the rows the generic
/// `node_property`-masking `WHERE` `Filter` returns — the denied property reads as `null`, so a
/// positive predicate (`=`, `>`) drops the row (never leaking *who* has value `v`, which `RETURN
/// p.salary` would only ever show as `null`), while `IS NULL` keeps it. Proven with the RANGE index
/// present (`NodeIndexSeek`) AND after `DROP INDEX` (the precise `scan_filter_eq` scan) — the two
/// gapped node paths this task closes. The relationship twins already declined for the same reason.
///
/// Pre-fix, the seek/precise-scan re-checked the RAW store value and so bypassed the property masking,
/// returning the denied node (an authorization bypass + information disclosure, CWE-863).
#[tokio::test]
async fn deny_read_property_is_enforced_on_index_seek_and_precise_scan_822() {
    let temp = TempStore::new("enforce822");
    let server = boot(base_config(&temp)).await;
    let uds = server.uds_path.clone().expect("UDS enabled");

    // ---- Admin seeds two Person nodes and a RANGE index on (:Person).salary. --------------------
    let mut alice = BoltClient::connect(&uds).await;
    alice.handshake_and_logon("alice", "admin-pw8").await;
    alice
        .run_ok("CREATE (:Person {name: 'Ada', salary: 100000})")
        .await;
    alice
        .run_ok("CREATE (:Person {name: 'Bob', salary: 40000})")
        .await;
    alice
        .run_ok("CREATE INDEX FOR (n:Person) ON (n.salary)")
        .await;
    // Admin (unrestricted) keeps the accelerated seek — the fast path is unchanged.
    let admin_hi = alice
        .run_ok("MATCH (p:Person) WHERE p.salary = 100000 RETURN p.name")
        .await;
    assert_eq!(
        opt_strings(&admin_hi, 0),
        vec![Some("Ada".to_owned())],
        "admin seeks the high earner via the index"
    );
    alice.goodbye().await;

    // ---- Narrow bob: TRAVERSE :Person + READ :Person.name, but DENY READ :Person.salary. --------
    let mut admin = BoltClient::connect(&uds).await;
    admin.handshake_and_logon("alice", "admin-pw8").await;
    admin.run_ok("REVOKE ROLE readwrite FROM bob").await;
    admin.run_ok("CREATE ROLE salary_blind").await;
    admin
        .run_ok("GRANT TRAVERSE ON LABEL graphus.Person TO salary_blind")
        .await;
    admin
        .run_ok("GRANT READ ON PROPERTY graphus.Person.name TO salary_blind")
        .await;
    // A broad read grant that WOULD reach salary...
    admin
        .run_ok("GRANT READ ON PROPERTY graphus.Person.salary TO salary_blind")
        .await;
    // ...carved by an explicit DENY (the leak vector: the seek re-checks the RAW value).
    admin
        .run_ok("DENY READ ON PROPERTY graphus.Person.salary TO salary_blind")
        .await;
    admin.run_ok("GRANT ROLE salary_blind TO bob").await;
    admin.goodbye().await;

    let mut bob = BoltClient::connect(&uds).await;
    bob.handshake_and_logon("bob", "user2-pw8").await;

    // 1) Equality on the DENIED property returns NO rows — the row would have disclosed the earner.
    let hi = bob
        .run_ok("MATCH (p:Person) WHERE p.salary = 100000 RETURN p.name")
        .await;
    assert!(
        hi.is_empty(),
        "bob must not learn who earns 100000 via the index seek: {hi:?}"
    );

    // 2) Even RETURNING the denied property yields no row (never a row whose salary is null-by-deny).
    let hi2 = bob
        .run_ok("MATCH (p:Person) WHERE p.salary = 100000 RETURN p.name, p.salary")
        .await;
    assert!(
        hi2.is_empty(),
        "no row may survive a positive predicate on a denied property: {hi2:?}"
    );

    // 3) A range predicate on the denied property is likewise dropped (index_seek_range).
    let rich = bob
        .run_ok("MATCH (p:Person) WHERE p.salary > 50000 RETURN p.name")
        .await;
    assert!(
        rich.is_empty(),
        "a range seek must not leak the denied property: {rich:?}"
    );

    // 4) MASKING PARITY: `IS NULL` INCLUDES both (salary reads as null under DENY READ) — served by a
    //    scan + `node_property` masking, never a fused seek, so the fix must not touch it.
    let blind = bob
        .run_ok("MATCH (p:Person) WHERE p.salary IS NULL RETURN p.name")
        .await;
    let mut blind_names = opt_strings(&blind, 0);
    blind_names.sort();
    assert_eq!(
        blind_names,
        vec![Some("Ada".to_owned()), Some("Bob".to_owned())],
        "IS NULL keeps both nodes (the denied salary reads as null): {blind_names:?}"
    );

    // 5) CONTROL: a predicate on a READABLE property (name) still resolves through the same paths.
    let ada = bob
        .run_ok("MATCH (p:Person) WHERE p.name = 'Ada' RETURN p.name")
        .await;
    assert_eq!(
        opt_strings(&ada, 0),
        vec![Some("Ada".to_owned())],
        "a readable property is unaffected: {ada:?}"
    );
    bob.reset().await;

    // ---- Drop the index: the SAME query now falls to the precise equality scan (scan_filter_eq). --
    let mut admin2 = BoltClient::connect(&uds).await;
    admin2.handshake_and_logon("alice", "admin-pw8").await;
    admin2
        .run_ok("DROP INDEX FOR (n:Person) ON (n.salary)")
        .await;
    admin2.goodbye().await;

    let hi3 = bob
        .run_ok("MATCH (p:Person) WHERE p.salary = 100000 RETURN p.name")
        .await;
    assert!(
        hi3.is_empty(),
        "the no-index precise equality scan (scan_filter_eq) must also honour the DENY: {hi3:?}"
    );
    bob.goodbye().await;
    server.shutdown().await.expect("clean shutdown");
}

/// `rmp` #826 (regression, whole-query end-to-end): the named-index PROCEDURE surface must honour a
/// `DENY READ` on the property an index covers. A full-text match returns a node BECAUSE a covered TEXT
/// property matched the search, so a restricted principal denied read on that covered property must NOT
/// learn which nodes match (while `RETURN n.<covered>` shows null) — the procedure never re-reads the
/// covered property, so the `AuthorizedGraph` decorator must filter on read access to every covered
/// property. Proven over `db.index.fulltext.queryNodes`.
///
/// It ALSO pins the VECTOR determination as a positive control: `db.index.vector.queryNodes` does NOT
/// leak (unchanged by this fix), because its mandatory `rmp` #780 re-score reads the covered embedding
/// through the masking `node_property` and drops a candidate whose embedding is unreadable.
#[tokio::test]
async fn deny_read_property_is_enforced_on_named_index_procedures_826() {
    let temp = TempStore::new("enforce826");
    let server = boot(base_config(&temp)).await;
    let uds = server.uds_path.clone().expect("UDS enabled");

    // ---- Admin seeds Docs with a text `body` + an `embedding`, and a full-text + vector index. ----
    let mut alice = BoltClient::connect(&uds).await;
    alice.handshake_and_logon("alice", "admin-pw8").await;
    alice
        .run_ok("CREATE (:Doc {name: 'Alpha', body: 'graph databases are fast', embedding: [1.0, 0.0, 0.0]})")
        .await;
    alice
        .run_ok("CREATE (:Doc {name: 'Beta', body: 'entirely unrelated prose', embedding: [0.0, 1.0, 0.0]})")
        .await;
    alice
        .run_ok("CREATE FULLTEXT INDEX doc_ft FOR (d:Doc) ON EACH [d.body]")
        .await;
    alice
        .run_ok(
            "CREATE VECTOR INDEX doc_vec FOR (d:Doc) ON (d.embedding) \
             OPTIONS { indexConfig: { `vector.dimensions`: 3, `vector.similarity_function`: 'cosine' } }",
        )
        .await;
    // Admin sanity (also drives the incremental full-text build to Online): both indexes find Alpha.
    let a_ft = alice
        .run_ok("CALL db.index.fulltext.queryNodes('doc_ft', 'graph') YIELD node RETURN node.name")
        .await;
    assert_eq!(
        opt_strings(&a_ft, 0),
        vec![Some("Alpha".to_owned())],
        "admin full-text finds the matching doc"
    );
    let a_vec = alice
        .run_ok("CALL db.index.vector.queryNodes('doc_vec', 1, [1.0, 0.0, 0.0]) YIELD node RETURN node.name")
        .await;
    assert_eq!(
        opt_strings(&a_vec, 0),
        vec![Some("Alpha".to_owned())],
        "admin vector k-NN finds the nearest doc"
    );
    alice.goodbye().await;

    // ---- Narrow bob: TRAVERSE :Doc + READ :Doc.name, but DENY READ the covered `body` + `embedding`.
    let mut admin = BoltClient::connect(&uds).await;
    admin.handshake_and_logon("alice", "admin-pw8").await;
    admin.run_ok("REVOKE ROLE readwrite FROM bob").await;
    admin.run_ok("CREATE ROLE doc_reader").await;
    admin
        .run_ok("GRANT TRAVERSE ON LABEL graphus.Doc TO doc_reader")
        .await;
    admin
        .run_ok("GRANT READ ON PROPERTY graphus.Doc.name TO doc_reader")
        .await;
    // Broad read grants that WOULD reach the covered properties...
    admin
        .run_ok("GRANT READ ON PROPERTY graphus.Doc.body TO doc_reader")
        .await;
    admin
        .run_ok("GRANT READ ON PROPERTY graphus.Doc.embedding TO doc_reader")
        .await;
    // ...carved by explicit DENYs (DENY-across precedence; the leak vector for the covered properties).
    admin
        .run_ok("DENY READ ON PROPERTY graphus.Doc.body TO doc_reader")
        .await;
    admin
        .run_ok("DENY READ ON PROPERTY graphus.Doc.embedding TO doc_reader")
        .await;
    admin.run_ok("GRANT ROLE doc_reader TO bob").await;
    admin.goodbye().await;

    let mut bob = BoltClient::connect(&uds).await;
    bob.handshake_and_logon("bob", "user2-pw8").await;

    // 1) FULLTEXT (the fix): the covered `body` is DENY READ, so the match must NOT come back — bob must
    //    not learn Alpha's body contains 'graph' while `RETURN d.body` would show null.
    let ft = bob
        .run_ok("CALL db.index.fulltext.queryNodes('doc_ft', 'graph') YIELD node RETURN node.name")
        .await;
    assert!(
        ft.is_empty(),
        "a full-text match on a DENY-READ covered property must not leak the node: {ft:?}"
    );

    // 2) VECTOR (positive control, unchanged): the covered `embedding` is DENY READ; the #780 re-score
    //    reads it through the masking node_property → null → the candidate is dropped. So vector already
    //    does not leak.
    let vec_hit = bob
        .run_ok("CALL db.index.vector.queryNodes('doc_vec', 1, [1.0, 0.0, 0.0]) YIELD node RETURN node.name")
        .await;
    assert!(
        vec_hit.is_empty(),
        "vector k-NN must not leak a node whose covered embedding is DENY READ: {vec_hit:?}"
    );

    // 3) The node stays visible to a bare scan (DENY READ hides the property value, not the node).
    let all = bob.run_ok("MATCH (d:Doc) RETURN d.name").await;
    let mut names = opt_strings(&all, 0);
    names.sort();
    assert_eq!(
        names,
        vec![Some("Alpha".to_owned()), Some("Beta".to_owned())],
        "DENY READ leaves the Doc nodes visible to a bare scan: {names:?}"
    );
    bob.reset().await;

    // ---- CONTROL: once `body` is readable again, bob's full-text query returns the match. ----
    let mut admin2 = BoltClient::connect(&uds).await;
    admin2.handshake_and_logon("alice", "admin-pw8").await;
    admin2
        .run_ok("REVOKE DENY READ ON PROPERTY graphus.Doc.body FROM doc_reader")
        .await;
    admin2.goodbye().await;

    let ft2 = bob
        .run_ok("CALL db.index.fulltext.queryNodes('doc_ft', 'graph') YIELD node RETURN node.name")
        .await;
    assert_eq!(
        opt_strings(&ft2, 0),
        vec![Some("Alpha".to_owned())],
        "with the covered property readable again, the full-text match returns on bob's next statement"
    );
    bob.goodbye().await;
    server.shutdown().await.expect("clean shutdown");
}
