//! MVP end-to-end acceptance test: a social network over a Unix domain socket, proving Graphus is
//! usable as a Minimum Viable Product.
//!
//! Unlike the in-process integration tests, this one spawns the **real** `graphus-server` binary as
//! a separate OS process (via `CARGO_BIN_EXE_graphus-server`) and drives it through the **real**
//! synchronous Bolt/UDS client from `graphus-cli` — the very same code path the `graphus-cli` binary
//! uses. That is what lets it prove the property an in-process test cannot: that committed data and
//! the server itself **survive a process restart**, including a hard crash.
//!
//! The scenario mirrors `examples/social-network-uds/run.sh` (the human-facing demonstration):
//!
//!   1. Boot the server; accept a UDS connection (peer-cred + password auth).
//!   2. Insert a social graph (Person nodes; FRIEND/FOLLOWS/POSTED relationships with properties).
//!   3. Search and traverse it (friends, friend-of-friend recommendations, aggregation, filters).
//!   4. GRACEFUL restart (SIGTERM → clean shutdown → reboot): the data is unchanged.
//!   5. Manipulate the data (SET / MERGE / DELETE / DETACH DELETE).
//!   6. CRASH + recovery (SIGKILL → reboot → WAL replay): every committed mutation is intact.
//!
//! The test is Unix-only (it relies on UDS and POSIX signals); on other targets it compiles to a
//! no-op so `cargo test` stays green everywhere.

#![cfg(unix)]

use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::time::{Duration, Instant};

use graphus_cli::client::BoltClient;
use graphus_core::Value;

const ADMIN_USER: &str = "alice";
const ADMIN_PW: &str = "social-demo-pw-1";

/// A private temp directory for one test run (store + config + socket), removed on drop.
struct Workspace {
    root: PathBuf,
}

impl Workspace {
    fn new() -> Self {
        let mut root = std::env::temp_dir();
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        root.push(format!("graphus-mvp-itest-{nanos}-{}", std::process::id()));
        std::fs::create_dir_all(&root).unwrap();
        Self { root }
    }

    fn config_path(&self) -> PathBuf {
        self.root.join("graphus.toml")
    }
    fn socket_path(&self) -> PathBuf {
        self.root.join("graphus.sock")
    }
    fn log_path(&self) -> PathBuf {
        self.root.join("server.log")
    }

    /// Writes a UDS-only server config bound to this process's uid (so the `SO_PEERCRED` gate admits
    /// our own connections). No network listener ⇒ no TLS material needed; the JWT secret is present
    /// only because the security catalog mandates a >=32-byte secret even when it is unused.
    fn write_config(&self) {
        let toml = format!(
            "store_path = {data:?}\n\
             buffer_pool_pages = 2048\n\
             uds_path = {sock:?}\n\
             rest_addr = \"\"\n\
             jwt_secret = \"graphus-mvp-social-demo-uds-only-secret-32+\"\n\
             \n[auth]\n\
             admin_user = \"{user}\"\n\
             admin_password = \"{pw}\"\n\
             admin_uid = {uid}\n",
            data = self.root.join("data"),
            sock = self.socket_path(),
            user = ADMIN_USER,
            pw = ADMIN_PW,
            uid = current_uid(),
        );
        std::fs::write(self.config_path(), toml).unwrap();
    }
}

impl Drop for Workspace {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

/// This process's uid, so the UDS peer-cred gate admits the test's own connections (same approach as
/// the other integration tests: read `/proc/self/status` on Linux, fall back to 0 elsewhere).
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

/// A handle to the spawned server process; owns the readiness wait and the two stop modes.
struct ServerProcess {
    child: Child,
}

impl ServerProcess {
    /// Spawns `graphus-server <config>`, appending its stdout+stderr to the workspace log, and waits
    /// until the UDS is bound (readiness) — failing fast if the process dies during startup.
    fn start(ws: &Workspace) -> Self {
        let exe = env!("CARGO_BIN_EXE_graphus-server");
        let log = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(ws.log_path())
            .unwrap();
        let log_err = log.try_clone().unwrap();
        let child = Command::new(exe)
            .arg(ws.config_path())
            .stdout(log)
            .stderr(log_err)
            .spawn()
            .expect("spawn graphus-server");

        let mut proc = Self { child };
        proc.wait_until_ready(&ws.socket_path(), &ws.log_path());
        proc
    }

    fn wait_until_ready(&mut self, socket: &Path, log: &Path) {
        let deadline = Instant::now() + Duration::from_secs(20);
        while Instant::now() < deadline {
            if socket.exists() {
                return;
            }
            if let Ok(Some(status)) = self.child.try_wait() {
                panic!(
                    "graphus-server exited during startup with {status}; log:\n{}",
                    std::fs::read_to_string(log).unwrap_or_default()
                );
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        panic!(
            "graphus-server did not bind UDS {} within timeout; log:\n{}",
            socket.display(),
            std::fs::read_to_string(log).unwrap_or_default()
        );
    }

    /// Graceful shutdown: SIGTERM, then wait for a clean exit.
    fn stop_graceful(mut self) {
        send_signal(self.child.id(), libc_sigterm());
        let _ = self.child.wait();
    }

    /// Crash: SIGKILL (no flush, no clean shutdown), then reap. Recovery must rely solely on the
    /// durable WAL + store.
    fn crash(mut self, socket: &Path) {
        let _ = self.child.kill(); // SIGKILL
        let _ = self.child.wait();
        // The kernel does not unlink the bound socket path on SIGKILL; remove the stale file so the
        // next boot can re-bind it.
        let _ = std::fs::remove_file(socket);
    }
}

/// SIGTERM's signal number (15 on every Unix Graphus targets). Avoids pulling in the `libc` crate
/// for a single constant.
fn libc_sigterm() -> i32 {
    15
}

/// Sends a signal to `pid` via the `kill(1)` utility — portable across Unix without a new crate
/// dependency, and sufficient for SIGTERM in a test harness.
fn send_signal(pid: u32, signal: i32) {
    let _ = Command::new("kill")
        .arg(format!("-{signal}"))
        .arg(pid.to_string())
        .status();
}

/// A thin query helper over the real Bolt/UDS client: connect, login, run one statement, close.
///
/// A fresh connection per statement keeps the test simple and additionally exercises the
/// connect/login/teardown path many times — exactly the per-invocation lifecycle `graphus-cli -c`
/// has.
fn query(socket: &Path, cypher: &str) -> Vec<Vec<Value>> {
    let mut client = BoltClient::connect_uds(socket).expect("connect over UDS");
    client.login(ADMIN_USER, ADMIN_PW).expect("login");
    let result = client
        .run(cypher)
        .unwrap_or_else(|e| panic!("query failed: {cypher}\n{e}"));
    let _ = client.goodbye();
    result.records
}

/// Runs a statement expected to return exactly one row with one integer column, and returns it.
fn scalar_int(socket: &Path, cypher: &str) -> i64 {
    let rows = query(socket, cypher);
    assert_eq!(rows.len(), 1, "expected one row from: {cypher}");
    match &rows[0][0] {
        Value::Integer(n) => *n,
        other => panic!("expected an integer from `{cypher}`, got {other:?}"),
    }
}

/// Runs a statement expected to return exactly one row with one string column, and returns it.
fn scalar_str(socket: &Path, cypher: &str) -> String {
    let rows = query(socket, cypher);
    assert_eq!(rows.len(), 1, "expected one row from: {cypher}");
    match &rows[0][0] {
        Value::String(s) => s.clone(),
        other => panic!("expected a string from `{cypher}`, got {other:?}"),
    }
}

#[test]
fn mvp_social_network_over_uds_survives_restart_and_crash() {
    let ws = Workspace::new();
    ws.write_config();
    let socket = ws.socket_path();

    // ---- Phase 1: boot + accept a UDS connection -------------------------------------------------
    let mut server = ServerProcess::start(&ws);
    assert_eq!(
        scalar_int(&socket, "RETURN 1 AS one"),
        1,
        "server answers over UDS"
    );
    assert_eq!(
        scalar_int(&socket, "MATCH (n) RETURN count(n) AS c"),
        0,
        "graph starts empty"
    );

    // ---- Phase 2: insert the social graph --------------------------------------------------------
    query(
        &socket,
        "CREATE (alice:Person {name:'Alice', age:30, city:'Lisbon'}),
                (bob:Person   {name:'Bob',   age:34, city:'Porto'}),
                (carol:Person {name:'Carol', age:28, city:'Lisbon'}),
                (dave:Person  {name:'Dave',  age:41, city:'Braga'}),
                (eve:Person   {name:'Eve',   age:25, city:'Lisbon'}),
                (frank:Person {name:'Frank', age:37, city:'Porto'}),
                (alice)-[:FRIEND {since:2015}]->(bob),
                (alice)-[:FRIEND {since:2018}]->(carol),
                (bob)-[:FRIEND {since:2016}]->(dave),
                (carol)-[:FRIEND {since:2020}]->(eve),
                (dave)-[:FRIEND {since:2019}]->(frank),
                (alice)-[:FOLLOWS]->(frank),
                (bob)-[:FOLLOWS]->(frank),
                (carol)-[:FOLLOWS]->(frank),
                (eve)-[:FOLLOWS]->(alice),
                (alice)-[:POSTED]->(:Post {text:'Hello graph world', likes:12}),
                (bob)-[:POSTED]->(:Post {text:'Bolt over UDS is fast', likes:7})
         RETURN count(*) AS created",
    );
    assert_eq!(
        scalar_int(&socket, "MATCH (p:Person) RETURN count(p) AS c"),
        6
    );
    assert_eq!(
        scalar_int(&socket, "MATCH ()-[r:FRIEND]->() RETURN count(r) AS c"),
        5
    );
    assert_eq!(
        scalar_int(&socket, "MATCH ()-[r:FOLLOWS]->() RETURN count(r) AS c"),
        4
    );
    assert_eq!(scalar_int(&socket, "MATCH (:Post) RETURN count(*) AS c"), 2);

    // ---- Phase 3: search + traverse --------------------------------------------------------------
    assert_eq!(
        scalar_int(
            &socket,
            "MATCH (:Person {name:'Alice'})-[:FRIEND]-(f) RETURN count(DISTINCT f) AS c",
        ),
        2,
        "Alice has two direct friends",
    );
    // Friend-of-friend recommendations: Alice—Bob—Dave and Alice—Carol—Eve ⇒ {Dave, Eve}.
    assert_eq!(
        scalar_int(
            &socket,
            "MATCH (me:Person {name:'Alice'})-[:FRIEND]-(:Person)-[:FRIEND]-(fof:Person)
             WHERE fof <> me AND NOT (me)-[:FRIEND]-(fof)
             RETURN count(DISTINCT fof) AS c",
        ),
        2,
        "Alice gets two friend-of-friend recommendations",
    );
    assert_eq!(
        scalar_str(
            &socket,
            "MATCH (p:Person)<-[:FOLLOWS]-(f)
             WITH p, count(f) AS followers
             RETURN p.name AS person ORDER BY followers DESC, person ASC LIMIT 1",
        ),
        "Frank",
        "Frank is the most-followed person",
    );
    assert_eq!(
        scalar_int(
            &socket,
            "MATCH (p:Person {city:'Lisbon'}) RETURN count(p) AS c"
        ),
        3,
        "three people live in Lisbon",
    );

    let nodes_before = scalar_int(&socket, "MATCH (n) RETURN count(n) AS c");
    let rels_before = scalar_int(&socket, "MATCH ()-[r]->() RETURN count(r) AS c");
    assert_eq!(nodes_before, 8);
    assert_eq!(rels_before, 11);

    // ---- Phase 4: graceful restart ---------------------------------------------------------------
    server.stop_graceful();
    assert!(!socket.exists(), "clean shutdown unlinks the UDS");
    server = ServerProcess::start(&ws);
    assert_eq!(
        scalar_int(&socket, "MATCH (n) RETURN count(n) AS c"),
        nodes_before,
        "node count survives a graceful restart",
    );
    assert_eq!(
        scalar_int(&socket, "MATCH ()-[r]->() RETURN count(r) AS c"),
        rels_before,
        "relationship count survives a graceful restart",
    );
    assert_eq!(
        scalar_str(
            &socket,
            "MATCH (p:Person {name:'Alice'}) RETURN p.city AS city"
        ),
        "Lisbon",
        "a node property survives the restart",
    );
    assert_eq!(
        scalar_int(
            &socket,
            "MATCH (:Person {name:'Alice'})-[r:FRIEND]-(:Person {name:'Bob'}) RETURN r.since AS s",
        ),
        2015,
        "a relationship property survives the restart",
    );

    // ---- Phase 5: manipulate ---------------------------------------------------------------------
    query(
        &socket,
        "MATCH (p:Person {name:'Alice'}) SET p.city = 'Madrid'",
    );
    assert_eq!(
        scalar_str(
            &socket,
            "MATCH (p:Person {name:'Alice'}) RETURN p.city AS city"
        ),
        "Madrid",
    );
    query(
        &socket,
        "MATCH (a:Person {name:'Alice'}), (e:Person {name:'Eve'})
         MERGE (a)-[:FRIEND {since:2026}]->(e)",
    );
    assert_eq!(
        scalar_int(&socket, "MATCH ()-[r:FRIEND]->() RETURN count(r) AS c"),
        6
    );
    query(
        &socket,
        "MATCH (:Person {name:'Alice'})-[r:FRIEND]-(:Person {name:'Bob'}) DELETE r",
    );
    assert_eq!(
        scalar_int(&socket, "MATCH ()-[r:FRIEND]->() RETURN count(r) AS c"),
        5
    );
    query(
        &socket,
        "MATCH (b:Person {name:'Bob'})-[:POSTED]->(post:Post) DETACH DELETE post",
    );
    assert_eq!(scalar_int(&socket, "MATCH (:Post) RETURN count(*) AS c"), 1);

    let nodes_after = scalar_int(&socket, "MATCH (n) RETURN count(n) AS c");
    let rels_after = scalar_int(&socket, "MATCH ()-[r]->() RETURN count(r) AS c");
    assert_eq!(nodes_after, 7);
    assert_eq!(rels_after, 10);

    // ---- Phase 6: crash + recovery ---------------------------------------------------------------
    server.crash(&socket);
    server = ServerProcess::start(&ws);
    assert_eq!(
        scalar_int(&socket, "MATCH (n) RETURN count(n) AS c"),
        nodes_after,
        "node count survives a crash (WAL recovery)",
    );
    assert_eq!(
        scalar_int(&socket, "MATCH ()-[r]->() RETURN count(r) AS c"),
        rels_after,
        "relationship count survives a crash (WAL recovery)",
    );
    assert_eq!(
        scalar_str(
            &socket,
            "MATCH (p:Person {name:'Alice'}) RETURN p.city AS city"
        ),
        "Madrid",
        "the SET survives the crash",
    );
    assert_eq!(
        scalar_int(
            &socket,
            "MATCH (:Person {name:'Alice'})-[:FRIEND]-(:Person {name:'Eve'}) RETURN count(*) AS c",
        ),
        1,
        "the MERGE survives the crash",
    );
    assert_eq!(
        scalar_int(
            &socket,
            "MATCH (:Person {name:'Alice'})-[:FRIEND]-(:Person {name:'Bob'}) RETURN count(*) AS c",
        ),
        0,
        "the DELETE survives the crash",
    );
    assert_eq!(
        scalar_int(&socket, "MATCH (:Post) RETURN count(*) AS c"),
        1,
        "the post deletion survives the crash",
    );

    // Clean teardown.
    server.stop_graceful();
}
