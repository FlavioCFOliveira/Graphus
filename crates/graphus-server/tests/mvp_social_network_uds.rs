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
//! A second test (`rmp` #697) pins the properties the first one cannot: the crash is taken
//! MID-FLIGHT (an acked commit, then a large un-acked write the SIGKILL interrupts), and the WAL
//! replay itself is ASSERTED — the server's `wal recovery complete` log line must show that recovery
//! scanned the log and re-applied changes, so a silently-skipped recovery fails the build instead of
//! passing on pages that happened to reach the device before the crash.
//!
//! The test is Unix-only (it relies on UDS and POSIX signals); on other targets it compiles to a
//! no-op so `cargo test` stays green everywhere.

#![cfg(unix)]

use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use graphus_cli::client::BoltClient;
use graphus_core::Value;
use graphus_examples_harness::resource::cpu_section;
use graphus_examples_harness::{
    DatasetScale, EvidenceCollector, EvidenceReport, RunMetadata, Target, cumulative_cpu_times,
    current_rss_bytes,
};

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
    /// The default database's record-store device file (under `store_path`).
    fn store_file(&self) -> PathBuf {
        self.root.join("data").join("graphus.store")
    }
    /// The default database's WAL file (under `store_path`).
    fn wal_file(&self) -> PathBuf {
        self.root.join("data").join("graphus.wal")
    }
    /// Where this run's evidence report is emitted (inside the temp workspace, removed on drop).
    fn evidence_dir(&self) -> PathBuf {
        self.root.join("evidence")
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

    /// The OS process id of the running server (for evidence metering of the real process).
    fn pid(&self) -> u32 {
        self.child.id()
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

    // ---- Phase 7: collect standardized performance evidence (rmp #249) ---------------------------
    // The recovered server is still alive, so we can meter the REAL server process (CPU + RSS) and
    // the on-disk store/WAL footprint that survived the crash, then emit the standardized
    // report.json + report.md — the same evidence the `examples/social-network-uds` shell demo
    // produces, exercised here through the Rust harness. This is purely ADDITIVE: it asserts the
    // evidence is produced with POPULATED (not specific) fields, so it cannot make the test flaky.
    let target = Target::Pid(server.pid());
    let cpu = cumulative_cpu_times(target)
        .map(|t| cpu_section(t, Duration::from_secs(1)))
        .unwrap_or_default();
    let final_rss = current_rss_bytes(target).unwrap_or(0);

    let metadata = RunMetadata::new(
        "social-network-uds",
        "Cargo mirror of the social-network-uds example: insert, traverse, mutate, survive a \
         graceful restart + a hard crash, then collect evidence.",
    )
    .with_dataset(DatasetScale::new(nodes_after as u64, rels_after as u64))
    .workload_param("connection", "uds-bolt")
    .workload_param("driver", "graphus-cli BoltClient");

    let mut collector = EvidenceCollector::new(metadata);
    collector.start();
    *collector.cpu_mut() = cpu;
    collector.memory_mut().final_rss_bytes = final_rss;
    collector.memory_mut().peak_rss_bytes = final_rss;
    collector
        .record_storage(ws.store_file(), ws.wal_file(), None)
        .expect("measure store + WAL footprint");
    collector.note("Evidence collected by the cargo integration test (mvp_social_network_uds).");
    let report = collector.finish();

    let (json_path, md_path) = report
        .write_to(ws.evidence_dir())
        .expect("write evidence report");
    assert!(json_path.exists(), "report.json must be produced");
    assert!(md_path.exists(), "report.md must be produced");

    // The emitted report is well-formed and carries the run's identity + real measurements. We
    // assert POPULATED, not specific, values: the store device is non-empty after the workload, and
    // the RSS read for a live process is positive on the supported platforms.
    let loaded = EvidenceReport::load(&json_path).expect("reload report.json");
    assert_eq!(loaded.metadata.scenario, "social-network-uds");
    assert_eq!(loaded.metadata.dataset.nodes, nodes_after as u64);
    assert_eq!(loaded.metadata.dataset.relationships, rels_after as u64);
    assert!(
        loaded.storage.store_bytes > 0,
        "the on-disk store must have a non-zero footprint after the workload, got {}",
        loaded.storage.store_bytes
    );
    assert!(
        loaded.memory.final_rss_bytes > 0,
        "a live server process must report a positive RSS, got {}",
        loaded.memory.final_rss_bytes
    );

    // Clean teardown.
    server.stop_graceful();
}

// ==================================================================================================
// `rmp` #697 — regression: the crash must be MID-FLIGHT, and recovery must be PROVEN to have run.
// ==================================================================================================
//
// The audit of `examples/social-network-uds` found two holes that a passing test did not catch:
//
//   1. The SIGKILL was delivered to an IDLE server. Everything was already flushed and acknowledged,
//      so the "crash" tested nothing a graceful stop does not: there was no committed-or-nothing
//      boundary in flight. The crash must land while the engine is EXECUTING an un-acked write.
//   2. Recovery could have been a COMPLETE NO-OP and every assertion would still have passed — the
//      surviving counts can be satisfied by pages that happened to reach the device before the crash.
//      (Verified empirically: with `recover_device_with_dwb` stubbed out, the old assertions still
//      passed while committed data was silently LOST.) So recovery must itself be asserted: the
//      server now logs a `wal recovery complete` line carrying the ARIES `RecoveryReport` counters,
//      and this test fails unless the replay actually SCANNED the log and RE-APPLIED changes.
//
// This test therefore pins the exact crash partition an ACID engine owes its clients:
//   * the LAST ACKNOWLEDGED commit SURVIVES (durability), and
//   * the LARGE UN-ACKED write in flight at the moment of the kill leaves NO TRACE (atomicity),
//   * and the WAL replay that makes the first of those true is OBSERVED, not assumed.

/// Rows in the un-acked write. Big enough that the (debug-profile) server cannot possibly finish it
/// inside the crash window, so the SIGKILL is guaranteed to land mid-transaction.
const INFLIGHT_ROWS: usize = 50_000;

/// Removes the SGR escape sequences the server's `tracing` subscriber emits even when its output is
/// redirected to a file — without this, the log's field names are `\e[3mkey\e[0m\e[2m=\e[0m`, not
/// `key=`, and no counter can be read out of them.
fn strip_ansi(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c != '\u{1b}' {
            out.push(c);
            continue;
        }
        // CSI: ESC '[' … final byte in @-~ (the `m` of an SGR sequence, in practice).
        if chars.next() != Some('[') {
            continue;
        }
        for c in chars.by_ref() {
            if ('@'..='~').contains(&c) {
                break;
            }
        }
    }
    out
}

#[test]
fn mid_flight_crash_keeps_the_acked_commit_discards_the_unacked_and_proves_the_wal_replayed() {
    let ws = Workspace::new();
    ws.write_config();
    let socket = ws.socket_path();

    let mut server = ServerProcess::start(&ws);

    // A committed baseline, so the WAL holds real work for recovery to replay.
    query(
        &socket,
        "UNWIND range(1, 500) AS i
         CREATE (:Person {uid: i, name: 'user' + toString(i), city: 'Lisbon'})",
    );
    assert_eq!(
        scalar_int(&socket, "MATCH (p:Person) RETURN count(p) AS c"),
        500
    );

    // ---- (1) The LAST ACKNOWLEDGED COMMIT --------------------------------------------------------
    // `run` returns only after the server acked the commit, which it sends only after the WAL is
    // fsynced. This node MUST survive the crash.
    query(&socket, "CREATE (:CrashMarker {tag: 'acked', at: 4242})");
    assert_eq!(
        scalar_int(&socket, "MATCH (m:CrashMarker) RETURN count(m) AS c"),
        1,
        "the pre-crash commit was acknowledged",
    );

    // ---- (2) The IN-FLIGHT, UN-ACKED WRITE --------------------------------------------------------
    // One large single-statement transaction on its own connection. The client blocks awaiting the
    // commit ack; we kill the server while it is still blocked, so the transaction is a loser.
    let inflight_socket = socket.clone();
    let inflight_done = Arc::new(AtomicBool::new(false));
    let done_flag = Arc::clone(&inflight_done);
    let inflight = std::thread::spawn(move || {
        let result = (|| -> Result<(), String> {
            let mut client =
                BoltClient::connect_uds(&inflight_socket).map_err(|e| format!("connect: {e}"))?;
            client
                .login(ADMIN_USER, ADMIN_PW)
                .map_err(|e| format!("login: {e}"))?;
            client
                .run(&format!(
                    "UNWIND range(1, {INFLIGHT_ROWS}) AS i
                     CREATE (:InFlight {{i: i, pad: 'this-write-must-never-survive-the-crash'}})"
                ))
                .map_err(|e| format!("run: {e}"))?;
            Ok(())
        })();
        done_flag.store(true, Ordering::SeqCst);
        result
    });

    // Give the engine time to be deep inside the write, then confirm it is STILL un-acked.
    std::thread::sleep(Duration::from_millis(1_500));
    assert!(
        !inflight_done.load(Ordering::SeqCst),
        "the in-flight write must still be UN-ACKED when the crash lands — otherwise this is not a \
         mid-flight crash at all (raise INFLIGHT_ROWS)",
    );

    // Where the post-crash boot's log will begin (so an earlier boot's line cannot satisfy the
    // recovery assertion below).
    let log_offset = std::fs::read_to_string(ws.log_path())
        .unwrap_or_default()
        .len();

    server.crash(&socket);

    // The killed server never acked: the client's `run` fails (broken connection).
    let inflight_result = inflight.join().expect("in-flight thread must not panic");
    assert!(
        inflight_result.is_err(),
        "the in-flight client must never receive a commit ack; it returned {inflight_result:?}",
    );

    // ---- (3) Reboot: ARIES recovery must ACTUALLY REPLAY ------------------------------------------
    server = ServerProcess::start(&ws);

    let log = std::fs::read_to_string(ws.log_path()).expect("read server log");
    let boot_log = strip_ansi(&log[log_offset.min(log.len())..]);
    let recovery_line = boot_log
        .lines()
        .find(|l| l.contains("wal recovery complete"))
        .unwrap_or_else(|| {
            panic!("the post-crash boot must log a completed WAL recovery; log:\n{boot_log}")
        })
        .to_string();

    let counter = |key: &str| -> u64 {
        // The tracing fmt layer renders the report's fields as `key=value`.
        let at = recovery_line
            .find(&format!("{key}="))
            .unwrap_or_else(|| panic!("recovery line has no `{key}`: {recovery_line}"));
        recovery_line[at + key.len() + 1..]
            .chars()
            .take_while(|c| c.is_ascii_digit())
            .collect::<String>()
            .parse()
            .unwrap_or_else(|_| panic!("`{key}` is not a number in: {recovery_line}"))
    };

    assert!(
        counter("records_scanned") > 0,
        "recovery must SCAN the durable WAL — a no-op replay is a durability hole: {recovery_line}",
    );
    assert!(
        counter("redo_applied") > 0,
        "recovery must RE-APPLY logged changes (the acked commit's page was never flushed before the \
         SIGKILL) — if this is 0 the replay did nothing and the surviving counts are a coincidence: \
         {recovery_line}",
    );

    // ---- (4) The crash partition: acked survives, un-acked vanishes -------------------------------
    assert_eq!(
        scalar_int(
            &socket,
            "MATCH (m:CrashMarker {tag: 'acked'}) RETURN count(m) AS c"
        ),
        1,
        "the ACKED pre-crash commit must survive the crash (durability)",
    );
    assert_eq!(
        scalar_int(&socket, "MATCH (m:CrashMarker) RETURN m.at AS at"),
        4242,
        "…with its exact property intact",
    );
    assert_eq!(
        scalar_int(&socket, "MATCH (n:InFlight) RETURN count(n) AS c"),
        0,
        "the UN-ACKED in-flight write must leave NO TRACE (atomicity: committed-or-nothing)",
    );
    assert_eq!(
        scalar_int(&socket, "MATCH (p:Person) RETURN count(p) AS c"),
        500,
        "every committed person survives the crash",
    );

    server.stop_graceful();
}
