//! Real OFFICIAL Neo4j-driver interoperability test (rmp #226).
//!
//! This closes the "self-referential" gap in the 100%-Bolt/PackStream-compliance pillar: every
//! other Bolt test in this repo drives Graphus's *own* codec, which cannot prove the wire is
//! byte-compatible with the reference ecosystem. This test boots a real Graphus server in-process,
//! exposes Bolt-over-TCP+TLS, then drives it with the **official `neo4j-driver` npm package** (the
//! same driver the Neo4j Java/JS ecosystem ships). If the driver connects, authenticates,
//! round-trips values and runs an explicit transaction, the Bolt handshake + PackStream encoding is
//! empirically interoperable with the reference implementation.
//!
//! ## Why it is feature-gated (NOT skipped)
//!
//! The project rule forbids `#[ignore]`/skip tests. Instead this whole file is compiled only under
//! the opt-in `neo4j-interop` cargo feature (default OFF), so `cargo test` stays hermetic (no
//! Node/npm/registry access). It is a separate, explicit test target that CI runs deliberately:
//!
//! ```text
//! cargo test -p graphus-server --features neo4j-interop --test neo4j_driver_interop -- --nocapture
//! ```
//!
//! Requirements when run: `node` (v18+) and `npm` on PATH for the JavaScript ecosystem, `python3`
//! (with the `venv` module) for the Python ecosystem, `go` (1.23+) for the Go ecosystem, and
//! network/cache access so each ecosystem can provision its official driver. Every provisioning
//! step is a HARD failure when its toolchain is missing — never a skip.
//!
//! Each ecosystem is provisioned **hermetically inside the test's own temp directory**: a Node
//! project with its `node_modules`, a Python virtual environment with the `neo4j` package, and a Go
//! module built against the pinned `neo4j-go-driver`. Nothing is installed system-wide.
#![cfg(feature = "neo4j-interop")]

use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::Command;
use std::sync::OnceLock;

use tokio::sync::Mutex;

use graphus_server::config::{
    AdmissionConfig, AuthBootstrap, ServerConfig, TimingConfig, TlsConfig,
};
use graphus_server::{Server, ServerHandle};

/// The admin identity the official driver authenticates with (Bolt `LOGON`, scheme `basic`).
const USER: &str = "neo4j";
const PASSWORD: &str = "graphus-interop-pw";

/// A unique temp directory for the server store + the Node project (auto-removed on drop).
struct TempDir {
    path: PathBuf,
}

impl TempDir {
    fn new() -> Self {
        let mut path = std::env::temp_dir();
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        // A process-wide atomic counter guarantees a distinct directory even when two tests construct a
        // `TempDir` in the SAME nanosecond under parallel execution (`cargo test`'s default multi-thread
        // runner). Without it, two tests could collide on the same `{nanos}-{pid}` path and one's `Drop`
        // would delete the other's freshly generated `cert.pem` / `security.toml`, spuriously failing the
        // victim at "server should boot". Discovered while extending this harness for rmp #813.
        static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let seq = SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        path.push(format!(
            "graphus-neo4j-interop-{nanos}-{}-{seq}",
            std::process::id()
        ));
        std::fs::create_dir_all(&path).unwrap();
        Self { path }
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

/// Builds a Bolt-TCP+TLS server config bound to an ephemeral loopback port, with `USER`/`PASSWORD`
/// as the admin (so the driver can both authenticate and run write queries — CREATE needs write,
/// which the admin holds). `bolt_server_agent` selects the `HELLO` `SUCCESS` `server` string the
/// listener announces (`None` = the honest `Graphus/<ver>` default; `Some("neo4j-compat")` = the
/// vetted `Neo4j/5.13.0` legacy-driver compat mode — rmp #614). `bolt_max_protocol_minor` caps the
/// highest Bolt 5.x minor the listener advertises (`None` = the full 5.0–5.4 window; `Some(0)` pins
/// an unmodified driver to exactly Bolt 5.0 — rmp #906).
fn config_for(
    dir: &TempDir,
    cert_path: PathBuf,
    key_path: PathBuf,
    bolt_server_agent: Option<String>,
    bolt_max_protocol_minor: Option<u8>,
) -> ServerConfig {
    ServerConfig {
        store_path: dir.path.join("store"),
        default_database: "graphus".to_owned(),
        buffer_pool_pages: 256,
        // Ephemeral port; the OS picks it and we read it back from the handle.
        bolt_tcp_addr: Some("127.0.0.1:0".to_owned()),
        advertised_bolt_address: None,
        bolt_server_agent,
        bolt_max_protocol_minor,
        // No REST/UDS: this test only needs the TLS Bolt-TCP path the driver speaks.
        rest_addr: None,
        uds_path: None,
        tls: TlsConfig {
            cert_path: Some(cert_path),
            key_path: Some(key_path),
        },
        admission: AdmissionConfig {
            max_concurrent_queries: 64,
            engine_queue_capacity: 256,
            result_buffer_capacity: 64,
            ..AdmissionConfig::default()
        },
        timing: TimingConfig {
            slow_query_threshold_ms: 1_000,
            shutdown_drain_deadline_ms: 5_000,
            // The TLS handshake + driver setup can take a moment on a cold runner.
            handshake_timeout_ms: 10_000,
            ..TimingConfig::default()
        },
        jwt_secret: "neo4j-interop-test-jwt-secret-32by!".to_owned(),
        auth: AuthBootstrap {
            admin_user: USER.to_owned(),
            admin_password: PASSWORD.to_owned(),
            admin_uid: None,
            users: Vec::new(),
        },
        encryption: graphus_server::config::EncryptionConfig::default(),
        audit: graphus_server::AuditConfig::default(),
        allow_insecure_network: false,
        bulk_import: graphus_server::config::BulkImportConfig::default(),
        metrics_scrape_token: None,
    }
}

/// Boots the server and returns its handle once ready.
async fn boot(config: ServerConfig) -> ServerHandle {
    Server::new(config)
        .start()
        .await
        .expect("server should boot")
}

/// The Node.js driver script: connects with the OFFICIAL `neo4j-driver` over `bolt+ssc://` (which
/// trusts a self-signed cert), verifies connectivity, round-trips a scalar and a node property, and
/// runs an explicit write transaction. Prints `GRAPHUS_INTEROP_OK` and exits 0 only on full success;
/// any mismatch exits 1 with a clear message. Connection params arrive via argv.
const DRIVER_SCRIPT: &str = r#"
'use strict';
const neo4j = require('neo4j-driver');

const [, , port, user, password] = process.argv;
const uri = `bolt+ssc://127.0.0.1:${port}`;

function fail(msg) {
  console.error('INTEROP FAILURE: ' + msg);
  process.exit(1);
}

(async () => {
  const driver = neo4j.driver(uri, neo4j.auth.basic(user, password));
  try {
    // 1. Handshake + auth + connectivity (drives HELLO/LOGON and a probe round-trip).
    await driver.verifyConnectivity();

    // 2. Scalar round-trip: RETURN 1 AS n  ->  n === 1.
    {
      const session = driver.session();
      try {
        const res = await session.run('RETURN 1 AS n');
        const n = res.records[0].get('n');
        const val = neo4j.isInt(n) ? n.toNumber() : n;
        if (val !== 1) fail(`RETURN 1 gave ${val}, expected 1`);
      } finally {
        await session.close();
      }
    }

    // 3. Node + property round-trip inside an EXPLICIT write transaction (executeWrite), then read
    //    it back in a separate session and assert the property survived the wire both ways.
    const marker = 'graphus-' + Date.now();
    {
      const session = driver.session();
      try {
        const created = await session.executeWrite(async (tx) => {
          const r = await tx.run(
            'CREATE (p:Person {name: $name, age: $age}) RETURN p.name AS name, p.age AS age',
            { name: marker, age: 41 }
          );
          return r.records[0];
        });
        const name = created.get('name');
        const age = neo4j.isInt(created.get('age')) ? created.get('age').toNumber() : created.get('age');
        if (name !== marker) fail(`CREATE returned name=${name}, expected ${marker}`);
        if (age !== 41) fail(`CREATE returned age=${age}, expected 41`);
      } finally {
        await session.close();
      }
    }

    // 4. MATCH it back (read) — proves the write was durable and the node encodes back over the wire.
    {
      const session = driver.session();
      try {
        const res = await session.run(
          'MATCH (p:Person {name: $name}) RETURN p.name AS name, p.age AS age',
          { name: marker }
        );
        if (res.records.length !== 1) fail(`MATCH found ${res.records.length} nodes, expected 1`);
        const rec = res.records[0];
        const age = neo4j.isInt(rec.get('age')) ? rec.get('age').toNumber() : rec.get('age');
        if (rec.get('name') !== marker) fail(`MATCH name=${rec.get('name')}, expected ${marker}`);
        if (age !== 41) fail(`MATCH age=${age}, expected 41`);
      } finally {
        await session.close();
      }
    }

    // 5. Explicit beginTransaction + commit path (a second transaction-management API surface).
    {
      const session = driver.session();
      try {
        const tx = session.beginTransaction();
        const res = await tx.run('RETURN $x + $y AS sum', { x: 20, y: 22 });
        const sum = neo4j.isInt(res.records[0].get('sum'))
          ? res.records[0].get('sum').toNumber()
          : res.records[0].get('sum');
        if (sum !== 42) fail(`explicit tx sum=${sum}, expected 42`);
        await tx.commit();
      } finally {
        await session.close();
      }
    }

    // 6. rmp #813: a READ transaction advances the session bookmark too, exactly like a real Neo4j
    //    server (which emits a `bookmark` in the SUCCESS of a read transaction's COMMIT / terminal
    //    auto-commit PULL). Before #813 Graphus emitted none for reads and lastBookmarks() stayed empty
    //    after a read. Assert: (a) an auto-commit read advances lastBookmarks(); (b) two reads with no
    //    write between them yield the SAME bookmark (the durable-write high-water is not a per-read
    //    phantom tick); (c) chaining a further read on the read bookmark (executeRead) still resolves —
    //    read-your-writes / causal chaining do not regress.
    {
      const session = driver.session();
      try {
        // (a) A pure auto-commit read must advance the session's last bookmarks.
        await session.run('MATCH (p:Person) RETURN count(p) AS c');
        const afterRead1 = session.lastBookmarks();
        if (!afterRead1 || afterRead1.length === 0) {
          fail('a read did not advance lastBookmarks() (rmp #813 regression)');
        }
        // (b) A second read with no write between must not move the bookmark backwards, and (single
        //     instance) yields the same durable-write high-water token.
        await session.run('MATCH (p:Person) RETURN count(p) AS c');
        const afterRead2 = session.lastBookmarks();
        if (JSON.stringify(afterRead1) !== JSON.stringify(afterRead2)) {
          fail(`two reads with no write between yielded different bookmarks: ` +
            `${JSON.stringify(afterRead1)} vs ${JSON.stringify(afterRead2)} (rmp #813)`);
        }
      } finally {
        await session.close();
      }
    }

    // 7. rmp #813 read-your-writes + causal chaining: a write's bookmark chained into a NEW read
    //    session must observe the write (executeRead over the chained bookmarks), and the read session's
    //    lastBookmarks() must be non-empty afterwards.
    {
      const writeSession = driver.session();
      let writeBookmarks;
      try {
        await writeSession.executeWrite((tx) =>
          tx.run('CREATE (:Marker813 {tag: $tag})', { tag: marker })
        );
        writeBookmarks = writeSession.lastBookmarks();
        if (!writeBookmarks || writeBookmarks.length === 0) {
          fail('a write did not advance lastBookmarks() (baseline for chaining)');
        }
      } finally {
        await writeSession.close();
      }
      const readSession = driver.session({ bookmarks: writeBookmarks });
      try {
        const chained = await readSession.executeRead((tx) =>
          tx.run('MATCH (m:Marker813 {tag: $tag}) RETURN count(m) AS c', { tag: marker })
        );
        const c = neo4j.isInt(chained.records[0].get('c'))
          ? chained.records[0].get('c').toNumber()
          : chained.records[0].get('c');
        if (c !== 1) fail(`read chained on a write bookmark saw count ${c}, expected 1 (read-your-writes)`);
        const readBookmarks = readSession.lastBookmarks();
        if (!readBookmarks || readBookmarks.length === 0) {
          fail('a read chained on a write bookmark did not itself advance lastBookmarks() (rmp #813)');
        }
      } finally {
        await readSession.close();
      }
    }

    console.log('GRAPHUS_INTEROP_OK');
    process.exit(0);
  } catch (err) {
    fail((err && err.stack) ? err.stack : String(err));
  } finally {
    await driver.close();
  }
})();
"#;

/// A full-CRUD Node.js script driving Graphus with the OFFICIAL `neo4j-driver` over `bolt+ssc://` at
/// a realistic data volume: it **C**reates 100 `:Person` nodes and 200 `:KNOWS` relationships,
/// **R**eads them back (counts, ordered neighbour traversal, aggregation), **U**pdates node *and*
/// relationship properties, then **D**eletes a relationship class and a subset of nodes
/// (`DETACH DELETE`, asserting the cascade). Every step asserts exact, deterministic counts/values;
/// it prints `GRAPHUS_CRUD_OK` and exits 0 only on full success, else exits 1 with a clear message.
/// Connection params (port, user, password) arrive via argv.
const CRUD_SCRIPT: &str = r#"
'use strict';
const neo4j = require('neo4j-driver');

const [, , port, user, password] = process.argv;
const uri = `bolt+ssc://127.0.0.1:${port}`;

const N = 100;       // nodes
const E = 2 * N;     // 200 edges: each node points at its +1 and +2 neighbours (modulo N)

function fail(msg) {
  console.error('CRUD FAILURE: ' + msg);
  process.exit(1);
}
const toNum = (v) => (neo4j.isInt(v) ? v.toNumber() : v);
// Plain JS numbers cross the wire as PackStream Float; range()/% require integers, so integer
// parameters MUST be wrapped with neo4j.int() (exactly as against a real Neo4j server).
const int = (n) => neo4j.int(n);

// Run a write query inside a managed write transaction.
async function writeQ(driver, query, params) {
  const s = driver.session();
  try { return await s.executeWrite((tx) => tx.run(query, params || {})); }
  finally { await s.close(); }
}
// Run a read query and return one named scalar from the first record.
async function scalar(driver, query, key, params) {
  const s = driver.session();
  try {
    const r = await s.run(query, params || {});
    return toNum(r.records[0].get(key));
  } finally { await s.close(); }
}

(async () => {
  const driver = neo4j.driver(uri, neo4j.auth.basic(user, password));
  try {
    // 0. Connect: HELLO/LOGON handshake + a connectivity probe round-trip.
    await driver.verifyConnectivity();

    // 1. CREATE — 100 :Person nodes in one explicit write transaction (UNWIND range is inclusive).
    await writeQ(driver,
      'UNWIND range(0, $max) AS i ' +
      'CREATE (p:Person {id: i, name: "person-" + toString(i), score: i})',
      { max: int(N - 1) });
    {
      const c = await scalar(driver, 'MATCH (p:Person) RETURN count(p) AS c', 'c');
      if (c !== N) fail(`after CREATE nodes, count=${c}, expected ${N}`);
    }

    // 2. CREATE — 200 :KNOWS edges: i -> (i+1)%N (weight 1) and i -> (i+2)%N (weight 2).
    await writeQ(driver,
      'UNWIND range(0, $max) AS i ' +
      'MATCH (a:Person {id: i}) ' +
      'MATCH (b:Person {id: (i + 1) % $n}) ' +
      'MATCH (c:Person {id: (i + 2) % $n}) ' +
      'CREATE (a)-[:KNOWS {weight: 1}]->(b) ' +
      'CREATE (a)-[:KNOWS {weight: 2}]->(c)',
      { max: int(N - 1), n: int(N) });
    {
      const c = await scalar(driver, 'MATCH ()-[r:KNOWS]->() RETURN count(r) AS c', 'c');
      if (c !== E) fail(`after CREATE edges, count=${c}, expected ${E}`);
    }

    // 3. READ — ordered neighbour traversal of node 0 must be exactly [1, 2].
    {
      const s = driver.session();
      try {
        const r = await s.run('MATCH (a:Person {id: 0})-[:KNOWS]->(b) RETURN b.id AS id ORDER BY b.id');
        const ids = r.records.map((rec) => toNum(rec.get('id')));
        if (JSON.stringify(ids) !== JSON.stringify([1, 2]))
          fail(`neighbours of 0 = ${JSON.stringify(ids)}, expected [1,2]`);
      } finally { await s.close(); }
    }
    // 3b. READ — aggregation: 200 edges, weight sum = 100*1 + 100*2 = 300.
    {
      const c = await scalar(driver, 'MATCH ()-[r:KNOWS]->() RETURN count(r) AS c', 'c');
      const sum = await scalar(driver, 'MATCH ()-[r:KNOWS]->() RETURN sum(r.weight) AS s', 's');
      if (c !== E) fail(`edge count=${c}, expected ${E}`);
      if (sum !== N * 1 + N * 2) fail(`weight sum=${sum}, expected ${N * 3}`);
    }

    // 4. UPDATE — bump every node's score by 1000; verify a sampled node.
    await writeQ(driver, 'MATCH (p:Person) SET p.score = p.score + 1000');
    {
      const s = await scalar(driver, 'MATCH (p:Person {id: 7}) RETURN p.score AS score', 'score');
      if (s !== 1007) fail(`updated score(id=7)=${s}, expected 1007`);
    }
    // 4b. UPDATE — rewrite the weight-2 relationship class to weight 20; verify count + new sum.
    await writeQ(driver, 'MATCH ()-[r:KNOWS {weight: 2}]->() SET r.weight = 20');
    {
      const cnt = await scalar(driver, 'MATCH ()-[r:KNOWS {weight: 20}]->() RETURN count(r) AS c', 'c');
      const sum = await scalar(driver, 'MATCH ()-[r:KNOWS]->() RETURN sum(r.weight) AS s', 's');
      if (cnt !== N) fail(`weight=20 edges=${cnt}, expected ${N}`);
      if (sum !== N * 1 + N * 20) fail(`weight sum after update=${sum}, expected ${N * 21}`);
    }

    // 5. DELETE — drop the weight-20 relationship class; 100 weight-1 edges must remain.
    await writeQ(driver, 'MATCH ()-[r:KNOWS {weight: 20}]->() DELETE r');
    {
      const c = await scalar(driver, 'MATCH ()-[r:KNOWS]->() RETURN count(r) AS c', 'c');
      if (c !== N) fail(`after DELETE edges, count=${c}, expected ${N}`);
    }
    // 5b. DELETE — DETACH DELETE nodes id>=90 (10 nodes). The cascade removes every weight-1 edge
    //     touching them; the survivors are exactly the edges with BOTH endpoints id<90 (i in 0..88).
    await writeQ(driver, 'MATCH (p:Person) WHERE p.id >= 90 DETACH DELETE p');
    {
      const nodes = await scalar(driver, 'MATCH (p:Person) RETURN count(p) AS c', 'c');
      if (nodes !== 90) fail(`after DETACH DELETE, nodes=${nodes}, expected 90`);
      const edges = await scalar(driver, 'MATCH ()-[r:KNOWS]->() RETURN count(r) AS c', 'c');
      if (edges !== 89) fail(`after DETACH DELETE, edges=${edges}, expected 89`);
      // Integrity: every surviving edge still has both endpoints present (no orphaned relationship).
      const anchored = await scalar(driver,
        'MATCH (a:Person)-[r:KNOWS]->(b:Person) RETURN count(r) AS c', 'c');
      if (anchored !== 89) fail(`node-anchored edge count=${anchored}, expected 89 (orphaned edges!)`);
    }

    console.log('GRAPHUS_CRUD_OK');
    process.exit(0);
  } catch (err) {
    fail((err && err.stack) ? err.stack : String(err));
  } finally {
    await driver.close();
  }
})();
"#;

/// A Node.js script that reads back the `server` agent string Graphus announced in `HELLO` `SUCCESS`
/// and asserts it equals the expected value passed as argv (rmp #614 — the Neo4j-compat `server`
/// agent). It verifies BOTH driver-side surfaces the official driver exposes for that field, which
/// must agree byte-for-byte with each other and with the expected string:
///
/// - `driver.getServerInfo({ database }).agent` — reads the HELLO `server` field without a query;
/// - `result.summary.server.agent` — the same field surfaced on a query's `ResultSummary`.
///
/// It prints `GRAPHUS_AGENT_OK:<agent>` and exits 0 only when both surfaces equal the expected
/// string; otherwise it exits non-zero with a clear message. Connection params and the expected
/// agent arrive via argv.
const AGENT_PROBE_SCRIPT: &str = r#"
'use strict';
const neo4j = require('neo4j-driver');

const [, , port, user, password, expectedAgent] = process.argv;
const uri = `bolt+ssc://127.0.0.1:${port}`;

function fail(msg) {
  console.error('AGENT PROBE FAILURE: ' + msg);
  process.exit(1);
}

(async () => {
  const driver = neo4j.driver(uri, neo4j.auth.basic(user, password));
  try {
    // Surface A — getServerInfo(): drives HELLO/LOGON and hands back ServerInfo without a query.
    const info = await driver.getServerInfo({ database: 'graphus' });
    if (info.agent !== expectedAgent)
      fail(`getServerInfo().agent = ${JSON.stringify(info.agent)}, expected ${JSON.stringify(expectedAgent)}`);

    // Surface B — result.summary.server.agent: the same HELLO `server` field on a query summary.
    const session = driver.session();
    try {
      const res = await session.run('RETURN 1 AS n');
      const agent = res.summary.server.agent;
      if (agent !== expectedAgent)
        fail(`result.summary.server.agent = ${JSON.stringify(agent)}, expected ${JSON.stringify(expectedAgent)}`);
    } finally {
      await session.close();
    }

    console.log('GRAPHUS_AGENT_OK:' + expectedAgent);
    process.exit(0);
  } catch (err) {
    fail((err && err.stack) ? err.stack : String(err));
  } finally {
    await driver.close();
  }
})();
"#;

/// A Node.js script that drives Graphus with the OFFICIAL `neo4j-driver` and asserts the
/// verbatim leaf code for a request that names a **database which does not exist** (rmp #814). It
/// opens a session pinned to a non-existent database, runs a query, and asserts the thrown
/// `Neo4jError`:
///
/// - `err.code === 'Neo.ClientError.Database.DatabaseNotFound'` (the exact title an app switches on,
///   e.g. auto-create-on-not-found) — NOT the coarse `Neo.ClientError.Request.Invalid`;
/// - the classification segment is `ClientError`, and the driver's own `retryable` flag / static
///   `isRetryable` is **false** — proving the driver treats it as a NON-retryable client error, so
///   remapping the fine-grained title did not move retryability;
/// - the connection stays usable afterwards (a query against the real default database still works).
///
/// Prints `GRAPHUS_DBNOTFOUND_OK` and exits 0 only on full success; any mismatch exits 1.
const DATABASE_NOT_FOUND_SCRIPT: &str = r#"
'use strict';
const neo4j = require('neo4j-driver');

const [, , port, user, password] = process.argv;
const uri = `bolt+ssc://127.0.0.1:${port}`;

function fail(msg) {
  console.error('DBNOTFOUND FAILURE: ' + msg);
  process.exit(1);
}

// Resolve the driver's own view of retryability robustly across driver minors: the preferred
// `err.retryable` boolean (falls back to the static isRetryable/isRetriable helpers).
function driverRetryable(err) {
  if (typeof err.retryable === 'boolean') return err.retryable;
  if (typeof err.retriable === 'boolean') return err.retriable;
  const E = neo4j.Neo4jError;
  if (E && typeof E.isRetryable === 'function') return E.isRetryable(err);
  if (E && typeof E.isRetriable === 'function') return E.isRetriable(err);
  return null; // unknown to this driver version
}

(async () => {
  const driver = neo4j.driver(uri, neo4j.auth.basic(user, password));
  try {
    await driver.verifyConnectivity();

    // A query pinned to a database that does not exist must FAIL with the verbatim leaf code.
    let caught = null;
    {
      const session = driver.session({ database: 'ghost' });
      try {
        await session.run('RETURN 1 AS n');
        fail('a query against a non-existent database unexpectedly succeeded');
      } catch (err) {
        caught = err;
      } finally {
        await session.close();
      }
    }
    if (!caught) fail('no error was thrown for a non-existent database');

    // (a) Exact verbatim leaf code — the title an application switches on.
    if (caught.code !== 'Neo.ClientError.Database.DatabaseNotFound') {
      fail(`code = ${JSON.stringify(caught.code)}, expected Neo.ClientError.Database.DatabaseNotFound`);
    }
    // (b) Classification segment is ClientError (inherently non-retryable per the driver's class rules).
    const classification = String(caught.code).split('.')[1];
    if (classification !== 'ClientError') {
      fail(`classification = ${classification}, expected ClientError (retryability must not move)`);
    }
    // (c) The driver's own retryability view must not be true (non-retryable), whenever it exposes one.
    const retryable = driverRetryable(caught);
    if (retryable === true) {
      fail('driver reports the DatabaseNotFound error as retryable — classification moved to transient');
    }

    // (d) The connection stays usable: a query against the real default database still round-trips.
    {
      const session = driver.session();
      try {
        const res = await session.run('RETURN 1 AS n');
        const n = neo4j.isInt(res.records[0].get('n')) ? res.records[0].get('n').toNumber() : res.records[0].get('n');
        if (n !== 1) fail(`post-error RETURN 1 gave ${n}, expected 1`);
      } finally {
        await session.close();
      }
    }

    console.log('GRAPHUS_DBNOTFOUND_OK:retryable=' + JSON.stringify(retryable));
    process.exit(0);
  } catch (err) {
    fail((err && err.stack) ? err.stack : String(err));
  } finally {
    await driver.close();
  }
})();
"#;

/// A Node.js script that proves the OFFICIAL driver interoperates over **exactly Bolt 5.0** (rmp
/// #906). The server is booted with `bolt_max_protocol_minor = 0`, so the *unmodified* driver — which
/// would otherwise choose the highest minor on offer — negotiates 5.0 and switches to its own Bolt 5.0
/// protocol implementation, where the authentication token rides in `HELLO` and there is no `LOGON`.
///
/// It asserts:
/// - the negotiated protocol version the driver reports is **5.0** (both on `getServerInfo()` and on a
///   query's `ResultSummary`), so the test cannot silently pass on 5.4;
/// - authentication succeeded (`verifyConnectivity()` completed) — at 5.0 that means the credentials
///   in the `HELLO` were read and accepted;
/// - a query round-trips end to end, including a write inside a managed transaction and reading it
///   back, so the whole 5.0 session (RUN/PULL/BEGIN/COMMIT) works, not just the handshake.
///
/// Prints `GRAPHUS_BOLT50_OK` and exits 0 only on full success; any mismatch exits 1.
const BOLT_50_SCRIPT: &str = r#"
'use strict';
const neo4j = require('neo4j-driver');

const [, , port, user, password] = process.argv;
const uri = `bolt+ssc://127.0.0.1:${port}`;

function fail(msg) {
  console.error('BOLT50 FAILURE: ' + msg);
  process.exit(1);
}
const toNum = (v) => (neo4j.isInt(v) ? v.toNumber() : v);

// Normalises the negotiated Bolt version the driver reports into "<major>.<minor>". Driver 6.x
// reports an object `{ major, minor }`; the 5.x line reported a float (5.4, or 5 for 5.0). Accept
// both shapes so the assertion pins the VERSION, not the driver's internal representation, and
// refuse anything else loudly rather than passing on an unreadable value.
function protocolVersionString(protocolVersion) {
  if (protocolVersion && typeof protocolVersion === 'object' &&
      typeof protocolVersion.major === 'number' && typeof protocolVersion.minor === 'number') {
    return `${protocolVersion.major}.${protocolVersion.minor}`;
  }
  if (typeof protocolVersion === 'number') {
    // 5.0 arrives as the number 5; every other minor keeps its fractional part.
    return Number.isInteger(protocolVersion)
      ? `${protocolVersion}.0`
      : String(protocolVersion);
  }
  return null;
}

function assertProtocol50(protocolVersion, where) {
  const seen = protocolVersionString(protocolVersion);
  if (seen === null) {
    fail(`${where}: could not read the negotiated protocolVersion ` +
      `(got ${JSON.stringify(protocolVersion)}); cannot prove Bolt 5.0 was negotiated`);
  }
  if (seen !== '5.0') {
    fail(`${where}: negotiated Bolt ${seen}, expected exactly 5.0 ` +
      `(the server was booted with bolt_max_protocol_minor = 0)`);
  }
}

(async () => {
  const driver = neo4j.driver(uri, neo4j.auth.basic(user, password));
  try {
    // 1. Handshake + authentication. At Bolt 5.0 the credentials travel INSIDE the HELLO (there is
    //    no LOGON message at that version), so reaching this point at all proves the server read and
    //    accepted a HELLO-carried auth token.
    await driver.verifyConnectivity();
    const info = await driver.getServerInfo({ database: 'graphus' });
    assertProtocol50(info.protocolVersion, 'getServerInfo()');

    // 2. A query round-trips, and its summary agrees the connection is on 5.0.
    {
      const session = driver.session();
      try {
        const res = await session.run('RETURN 1 AS n');
        assertProtocol50(res.summary.server.protocolVersion, 'result.summary.server');
        const n = toNum(res.records[0].get('n'));
        if (n !== 1) fail(`RETURN 1 gave ${n}, expected 1`);
      } finally {
        await session.close();
      }
    }

    // 3. A managed write transaction + read-back: the whole 5.0 session surface (BEGIN/RUN/PULL/
    //    COMMIT), not just the handshake.
    const marker = 'bolt50-' + Date.now();
    {
      const session = driver.session();
      try {
        await session.executeWrite((tx) =>
          tx.run('CREATE (p:Bolt50 {tag: $tag, n: $n})', { tag: marker, n: neo4j.int(7) })
        );
      } finally {
        await session.close();
      }
    }
    {
      const session = driver.session();
      try {
        const res = await session.run(
          'MATCH (p:Bolt50 {tag: $tag}) RETURN p.tag AS tag, p.n AS n', { tag: marker });
        if (res.records.length !== 1) fail(`MATCH found ${res.records.length} nodes, expected 1`);
        if (res.records[0].get('tag') !== marker) fail(`tag=${res.records[0].get('tag')}`);
        const n = toNum(res.records[0].get('n'));
        if (n !== 7) fail(`n=${n}, expected 7`);
        assertProtocol50(res.summary.server.protocolVersion, 'post-write result.summary.server');
      } finally {
        await session.close();
      }
    }

    console.log('GRAPHUS_BOLT50_OK');
    process.exit(0);
  } catch (err) {
    fail((err && err.stack) ? err.stack : String(err));
  } finally {
    await driver.close();
  }
})();
"#;

/// A Node.js script that reproduces rmp #907 with the OFFICIAL `neo4j-driver`: ONE explicit
/// transaction whose FIRST result is larger than the session's `fetchSize`, followed by a SECOND
/// statement issued while that first stream is still open.
///
/// Before the fix, a `RUN` received in Bolt state `TX_STREAMING` was rejected, so the second
/// statement got a `FAILURE` and the whole transaction died. That contradicts the **Bolt 4.0+**
/// server-state specification (this is a 4.0 addition — at Bolt 3 there is no `qid` and a single
/// stream must indeed be drained first; Graphus advertises only 5.0–5.4, so the premise holds
/// structurally here):
///
/// - Table 6 lists `RUN` among the requests valid in `TX_STREAMING`, answering
///   `SUCCESS {"qid": id::Integer}` — so rejecting a `RUN` *because of the state* is non-conformant;
/// - Tables 7 and 8 give the new state as "`TX_READY` **or `TX_STREAMING` if there are other streams
///   open**", which presupposes several concurrently open streams — including the case exercised
///   here, where statement 2 finishes (`has_more: false`) while stream 1 is still suspended;
/// - Table 8 keeps the connection in `TX_STREAMING` when a `PULL` is answered with
///   `SUCCESS {"has_more": true}`;
/// - the message specification's Explicit-Transaction example defines the semantics of addressing
///   those streams individually by `qid` ("two streams are open", `PULL {"qid": 123}`, …).
///
/// ## How the second stream is *genuinely* left open (and proven to be)
///
/// The JavaScript `Result` is lazy and `Promise`-like: `await tx.run(...)` would drain the entire
/// stream and silently degenerate the test into the single-stream case. Instead the script takes the
/// `Result`'s **async iterator** and pulls exactly ONE record, which drives `RUN` + a single
/// `PULL {n: fetchSize}`. The server answers a batch of at most `n` records (`n` is a maximum, not a
/// promise) plus `SUCCESS {has_more: true}`, and stays in `TX_STREAMING`; the driver's own flow
/// control then stops on its own (its high watermark is `0.7 * fetchSize`, so with a full batch
/// buffered and nothing consumed it will not auto-pull again until the buffer drains below
/// `0.3 * fetchSize`). The iterator is never `return`ed — there is no `break` out of a `for await`,
/// which would make the driver send `DISCARD` and close the stream — so stream 1 is still open when
/// statement 2 is issued.
///
/// Because Bolt requests are processed strictly in order, the server dequeues the second `RUN` only
/// after it has finished answering the first `PULL`; this script therefore proves the second `RUN`
/// was *sent* while the client still held an unfinished stream. (The Go program is stricter still:
/// its driver blocks until `SUCCESS {has_more: true}` has actually been received before sending the
/// second `RUN` — see [`GO_MULTI_STREAM_SCRIPT`].)
///
/// That reasoning is not merely asserted in a comment: the script installs a `logging` hook that
/// captures the driver's own outgoing Bolt messages and, at the end, **fails** unless the wire shows
/// the interleaving — at most 2 `PULL`s before the second `RUN` (draining 2500 rows at `n = 1000`
/// needs at least 3); every one of those carrying the fetch size, so a drain-everything
/// `PULL {n: -1}` cannot masquerade as a partial read; at least 2 `PULL`s after it, one for
/// statement 2 and the rest resuming stream 1; at least one of those resume `PULL`s addressed to an
/// explicit `qid`, which is only ever emitted for a stream that is *not* the current one and is thus
/// direct evidence that two streams were open at once; and no `DISCARD` at all. A deliberately
/// mutated variant that drains stream 1 before statement 2 passes every value assertion and is still
/// rejected by that gate.
///
/// Prints `GRAPHUS_MULTISTREAM_OK` and exits 0 only on full success; any mismatch exits 1.
const MULTI_STREAM_SCRIPT: &str = r#"
'use strict';
const neo4j = require('neo4j-driver');

const [, , port, user, password] = process.argv;
const uri = `bolt+ssc://127.0.0.1:${port}`;

const TOTAL = 2500;   // rows in the FIRST result: strictly more than one fetch batch
const FETCH = 1000;   // the driver default; named explicitly so the arithmetic below is checkable

function fail(msg) {
  console.error('MULTISTREAM FAILURE: ' + msg);
  process.exit(1);
}
const toNum = (v) => (neo4j.isInt(v) ? v.toNumber() : v);

// Capture the driver's OWN outgoing Bolt messages. This is what makes the test non-vacuous: it
// proves from the wire that the second RUN was issued while the first stream was still open,
// instead of silently degenerating into the single-stream case if the driver ever decided to
// buffer the first result.
const clientMessages = [];
const logging = {
  level: 'debug',
  logger: (_level, message) => {
    const m = /(?:^|\s)C: (RUN|PULL|DISCARD)\b(.*)$/.exec(message);
    if (m !== null) clientMessages.push(m[1] + m[2]);
  },
};

(async () => {
  const driver = neo4j.driver(uri, neo4j.auth.basic(user, password), { logging });
  try {
    await driver.verifyConnectivity();

    // 1. Seed the rows in a SEPARATE managed write transaction, so the transaction under test does
    //    nothing but run the two statements. Integers must be wrapped with neo4j.int(): a plain JS
    //    number crosses the wire as a PackStream Float, which range() rejects.
    {
      const session = driver.session();
      try {
        await session.executeWrite((tx) =>
          tx.run('UNWIND range(1, $n) AS i CREATE (:Big {i: i})', { n: neo4j.int(TOTAL) })
        );
      } finally {
        await session.close();
      }
    }

    // 2. ONE explicit transaction, TWO statements, the first larger than fetchSize.
    const session = driver.session({ fetchSize: FETCH });
    try {
      const tx = session.beginTransaction();
      const mark = clientMessages.length; // ignore everything the seeding transaction wrote

      // Statement 1 — lazily started, then advanced by exactly one record (see the doc comment).
      const r1 = tx.run('MATCH (n:Big) RETURN n.i AS i ORDER BY i');
      const it = r1[Symbol.asyncIterator]();
      const firstStep = await it.next();
      if (firstStep.done === true) fail('the first statement returned no records at all');
      const firstValue = toNum(firstStep.value.get('i'));
      if (firstValue !== 1) fail(`first record of stream 1 was i=${firstValue}, expected 1`);

      // Statement 2 — the RUN that used to be rejected because the connection was in TX_STREAMING.
      const r2 = await tx.run('RETURN 1 AS one');
      if (r2.records.length !== 1)
        fail(`second statement returned ${r2.records.length} records, expected 1`);
      const one = toNum(r2.records[0].get('one'));
      if (one !== 1) fail(`second statement returned one=${one}, expected 1`);

      // Finish stream 1 and assert the RECORDS (not just the count) arrive complete and in order.
      const got = [firstValue];
      for (;;) {
        const step = await it.next();
        if (step.done === true) break;
        got.push(toNum(step.value.get('i')));
      }
      if (got.length !== TOTAL) fail(`stream 1 yielded ${got.length} records, expected ${TOTAL}`);
      for (let i = 0; i < TOTAL; i++) {
        if (got[i] !== i + 1) fail(`stream 1 record ${i} was i=${got[i]}, expected ${i + 1}`);
      }

      await tx.commit();

      // 3. Non-vacuity gate on the captured wire traffic.
      const msgs = clientMessages.slice(mark);
      const run1 = msgs.findIndex((m) => m.startsWith('RUN') && m.includes('MATCH (n:Big)'));
      const run2 = msgs.findIndex((m) => m.startsWith('RUN') && m.includes('RETURN 1 AS one'));
      if (run1 === -1) fail(`no RUN for the first statement was logged: ${JSON.stringify(msgs)}`);
      if (run2 === -1) fail(`no RUN for the second statement was logged: ${JSON.stringify(msgs)}`);
      if (run2 < run1) fail('the second statement was sent before the first');
      const pullsBefore = msgs.slice(0, run2).filter((m) => m.startsWith('PULL'));
      const pullsAfter = msgs.slice(run2 + 1).filter((m) => m.startsWith('PULL'));
      const discards = msgs.filter((m) => m.startsWith('DISCARD')).length;
      // Draining 2500 rows at n=1000 needs at least 3 PULLs, so <= 2 PULLs before the second RUN
      // proves stream 1 was demonstrably UNFINISHED when statement 2 was issued.
      if (pullsBefore.length > 2) {
        fail(`stream 1 had already been drained before the second RUN (${pullsBefore.length} ` +
          `PULLs); the test would be vacuous: ${JSON.stringify(msgs)}`);
      }
      // ...but only because each of those PULLs was BOUNDED by the fetch size. A drain-everything
      // PULL {n: -1} would finish stream 1 in a single message and make the count meaningless.
      const unbounded = pullsBefore.find((m) => !m.includes(String(FETCH)));
      if (unbounded !== undefined) {
        fail(`a PULL before the second RUN was not bounded by the fetch size ${FETCH}, so the ` +
          `PULL count proves nothing: ${JSON.stringify(unbounded)}`);
      }
      // One PULL serves statement 2's own result; the rest resume the still-open stream 1.
      if (pullsAfter.length < 2) {
        fail(`only ${pullsAfter.length} PULLs followed the second RUN; stream 1 was not resumed ` +
          `after it: ${JSON.stringify(msgs)}`);
      }
      // A PULL carrying an explicit qid addresses a stream that is NOT the connection's current one
      // — direct evidence that two streams of this transaction were open at the same time.
      if (!pullsAfter.some((m) => m.includes('qid'))) {
        fail(`no PULL after the second RUN addressed an explicit qid, so stream 1 was never ` +
          `resumed as a second, independently addressable stream: ${JSON.stringify(msgs)}`);
      }
      if (discards !== 0) {
        fail(`the driver discarded a stream instead of keeping it open: ${JSON.stringify(msgs)}`);
      }
      console.log(`GRAPHUS_MULTISTREAM_WIRE pulls_before=${pullsBefore.length} ` +
        `pulls_after=${pullsAfter.length}`);
    } finally {
      await session.close();
    }

    console.log('GRAPHUS_MULTISTREAM_OK');
    process.exit(0);
  } catch (err) {
    fail((err && err.stack) ? err.stack : String(err));
  } finally {
    await driver.close();
  }
})();
"#;

/// The Python counterpart of [`MULTI_STREAM_SCRIPT`] (rmp #907), driving the OFFICIAL `neo4j` PyPI
/// package. It is the verbatim reproduction from the bug report: `next(iter(r1))` forces exactly the
/// first `PULL` (so the server answers `has_more: true` and stays in `TX_STREAMING`), then a second
/// `tx.run(...)` is issued on the same transaction.
///
/// The Python driver does not buffer the previous result on Bolt 4+/5: it only does so when the
/// connection reports `supports_multiple_results is False` (the Bolt 3 fallback, which has no
/// `qid`) — the driver's own source says as much. On Bolt 5 it therefore sends the second `RUN` with
/// stream 1 still open, which is exactly what the wire gate at the end of the script re-verifies
/// from the driver's own `neo4j.io` debug log, with the same arithmetic and the same bounded-`PULL`
/// and explicit-`qid` checks as the JavaScript script.
///
/// The driver is also the one that would send a `DISCARD` if a result were left unconsumed at commit
/// time; both results here are exhausted first, so the gate's `DISCARD == 0` assertion is a genuine
/// statement about stream lifetime rather than an accident of when the transaction ends.
///
/// Prints `GRAPHUS_PY_MULTISTREAM_OK` and exits 0 only on full success; any mismatch exits non-zero.
const PYTHON_MULTI_STREAM_SCRIPT: &str = r#"
"""Drives Graphus with the OFFICIAL `neo4j` Python driver and reproduces rmp #907: one explicit
transaction whose FIRST result is larger than the session fetch size, followed by a SECOND statement
issued while that first stream is still open (Bolt state TX_STREAMING).
"""

import logging
import sys

import neo4j

PORT, USER, PASSWORD = sys.argv[1], sys.argv[2], sys.argv[3]
URI = f"bolt+ssc://127.0.0.1:{PORT}"

TOTAL = 2500  # rows in the FIRST result: strictly more than one fetch batch
FETCH = 1000  # the driver default; named explicitly so the arithmetic below is checkable


def fail(msg):
    print(f"PY MULTISTREAM FAILURE: {msg}", file=sys.stderr)
    sys.exit(1)


# Capture the driver's OWN outgoing Bolt messages. This is what makes the test non-vacuous: it
# proves from the wire that the second RUN was issued while the first stream was still open, instead
# of silently degenerating into the single-stream case if the driver ever decided to buffer the
# first result.
CLIENT_MESSAGES = []


class _CaptureClientMessages(logging.Handler):
    def emit(self, record):
        text = record.getMessage()
        marker = text.find("C: ")
        if marker == -1:
            return
        body = text[marker + 3 :]
        if body.startswith(("RUN", "PULL", "DISCARD")):
            CLIENT_MESSAGES.append(body)


_io_log = logging.getLogger("neo4j.io")
_io_log.setLevel(logging.DEBUG)
_io_log.addHandler(_CaptureClientMessages())
_io_log.propagate = False


def main():
    with neo4j.GraphDatabase.driver(URI, auth=(USER, PASSWORD)) as driver:
        driver.verify_connectivity()

        # 1. Seed the rows in a SEPARATE managed write transaction, so the transaction under test
        #    does nothing but run the two statements.
        with driver.session() as session:
            session.execute_write(
                lambda tx: tx.run(
                    "UNWIND range(1, $n) AS i CREATE (:Big {i: i})", n=TOTAL
                ).consume()
            )

        # 2. ONE explicit transaction, TWO statements, the first larger than fetch_size.
        with driver.session(fetch_size=FETCH) as session:
            mark = len(CLIENT_MESSAGES)  # ignore everything the seeding transaction wrote
            with session.begin_transaction() as tx:
                # `Result` is lazy. Taking exactly ONE record drives RUN + a single PULL(fetch_size):
                # the server answers a full batch + SUCCESS {has_more: true} and stays in
                # TX_STREAMING. The driver does not pull again until the buffer is consumed, so
                # stream 1 stays open across statement 2. Iterating the same `Result` again later
                # resumes it (every `iter()` walks the same underlying stream state).
                r1 = tx.run("MATCH (n:Big) RETURN n.i AS i ORDER BY i")
                first = next(iter(r1))
                if first["i"] != 1:
                    fail(f"first record of stream 1 was i={first['i']}, expected 1")

                # Statement 2 — the RUN that used to be rejected in TX_STREAMING.
                r2 = tx.run("RETURN 1 AS one")
                single = r2.single()
                if single is None:
                    fail("the second statement returned no record")
                if single["one"] != 1:
                    fail(f"second statement returned one={single['one']}, expected 1")

                # Finish stream 1 and assert the RECORDS (not just the count) arrive in order.
                got = [first["i"]] + [record["i"] for record in r1]
                expected = list(range(1, TOTAL + 1))
                if len(got) != TOTAL:
                    fail(f"stream 1 yielded {len(got)} records, expected {TOTAL}")
                if got != expected:
                    bad = next(i for i, (a, b) in enumerate(zip(got, expected)) if a != b)
                    fail(
                        f"stream 1 record {bad} was i={got[bad]}, expected {expected[bad]}"
                    )

                tx.commit()

            # 3. Non-vacuity gate on the captured wire traffic.
            msgs = CLIENT_MESSAGES[mark:]
            run1 = next(
                (i for i, m in enumerate(msgs) if m.startswith("RUN") and "MATCH (n:Big)" in m),
                -1,
            )
            run2 = next(
                (i for i, m in enumerate(msgs) if m.startswith("RUN") and "RETURN 1 AS one" in m),
                -1,
            )
            if run1 == -1:
                fail(f"no RUN for the first statement was logged: {msgs}")
            if run2 == -1:
                fail(f"no RUN for the second statement was logged: {msgs}")
            if run2 < run1:
                fail("the second statement was sent before the first")
            pulls_before = [m for m in msgs[:run2] if m.startswith("PULL")]
            pulls_after = [m for m in msgs[run2 + 1 :] if m.startswith("PULL")]
            discards = sum(1 for m in msgs if m.startswith("DISCARD"))
            # Draining 2500 rows at n=1000 needs at least 3 PULLs, so <= 2 PULLs before the second
            # RUN proves stream 1 was demonstrably UNFINISHED when statement 2 was issued.
            if len(pulls_before) > 2:
                fail(
                    f"stream 1 had already been drained before the second RUN "
                    f"({len(pulls_before)} PULLs); the test would be vacuous: {msgs}"
                )
            # ...but only because each of those PULLs was BOUNDED by the fetch size. A
            # drain-everything PULL {n: -1} would finish stream 1 in a single message and make the
            # count meaningless.
            unbounded = [m for m in pulls_before if str(FETCH) not in m]
            if unbounded:
                fail(
                    f"a PULL before the second RUN was not bounded by the fetch size {FETCH}, "
                    f"so the PULL count proves nothing: {unbounded}"
                )
            # One PULL serves statement 2's own result; the rest resume the still-open stream 1.
            if len(pulls_after) < 2:
                fail(
                    f"only {len(pulls_after)} PULLs followed the second RUN; stream 1 was not "
                    f"resumed after it: {msgs}"
                )
            # A PULL carrying an explicit qid addresses a stream that is NOT the connection's
            # current one — direct evidence that two streams were open at the same time.
            if not any("qid" in m for m in pulls_after):
                fail(
                    f"no PULL after the second RUN addressed an explicit qid, so stream 1 was "
                    f"never resumed as a second, independently addressable stream: {msgs}"
                )
            if discards != 0:
                fail(f"the driver discarded a stream instead of keeping it open: {msgs}")
            print(
                f"GRAPHUS_PY_MULTISTREAM_WIRE pulls_before={len(pulls_before)} "
                f"pulls_after={len(pulls_after)}"
            )

    print("GRAPHUS_PY_MULTISTREAM_OK")


if __name__ == "__main__":
    main()
"#;

/// The Go counterpart of [`MULTI_STREAM_SCRIPT`] (rmp #907), driving the OFFICIAL
/// `neo4j-go-driver/v5`.
///
/// The Go driver keeps several streams open per transaction rather than buffering: when a `RUN`
/// arrives while the connection is in its `bolt5StreamingTx` state, `bolt5.run` calls `pauseStream`
/// (drain the batch already in flight, then stop) — **not** `bufferStream`, which is what it does
/// for an *auto-commit* stream that has no transaction to key a `qid` against. The paused stream is
/// still counted as open, so the connection stays in `bolt5StreamingTx`, and resuming it later emits
/// `PULL {n, qid}` addressed to the non-current stream. The wire gate at the end of the program
/// re-verifies exactly that from the driver's own `BoltLogger`.
///
/// This makes the Go program the strictest of the three witnesses: `pauseStream` receives every
/// outstanding response before the second `RUN` is queued, so unlike the JavaScript and Python
/// scripts the Go driver has demonstrably *observed* `SUCCESS {has_more: true}` — i.e. knows the
/// server is in `TX_STREAMING` — at the moment it sends the second `RUN`. A server that cannot hold
/// several streams per transaction therefore fails this program twice over: once on the second
/// `RUN`, and once on the `qid`-addressed `PULL` that resumes the first result.
///
/// Prints `GRAPHUS_GO_MULTISTREAM_OK` and exits 0 only on full success; any mismatch exits non-zero.
// NOTE: unlike the JavaScript/Python scripts above, this literal deliberately starts on the SAME
// line as the opening quote. A leading blank line would make the generated `main.go` fail `gofmt`,
// and the Go ecosystem treats an unformatted source file as a defect.
const GO_MULTI_STREAM_SCRIPT: &str = r#"// Drives Graphus with the OFFICIAL neo4j-go-driver and reproduces rmp #907: one explicit
// transaction whose FIRST result is larger than the session fetch size, followed by a SECOND
// statement issued while that first stream is still open (Bolt state TX_STREAMING).
package main

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync"

	"github.com/neo4j/neo4j-go-driver/v5/neo4j"
)

const (
	total = 2500 // rows in the FIRST result: strictly more than one fetch batch
	fetch = 1000 // the driver default; named explicitly so the arithmetic below is checkable
)

func fail(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "GO MULTISTREAM FAILURE: "+format+"\n", args...)
	os.Exit(1)
}

// captureLogger records the driver's OWN outgoing Bolt messages. This is what makes the test
// non-vacuous: it proves from the wire that the second RUN was issued while the first stream was
// still open, instead of silently degenerating into the single-stream case if the driver ever
// decided to buffer the first result.
type captureLogger struct {
	mu       sync.Mutex
	messages []string
}

func (c *captureLogger) LogClientMessage(_ string, msg string, args ...any) {
	line := fmt.Sprintf(msg, args...)
	if !strings.HasPrefix(line, "RUN") && !strings.HasPrefix(line, "PULL") &&
		!strings.HasPrefix(line, "DISCARD") {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.messages = append(c.messages, line)
}

func (c *captureLogger) LogServerMessage(_ string, _ string, _ ...any) {}

func (c *captureLogger) snapshot() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]string(nil), c.messages...)
}

func indexOfRun(messages []string, needle string) int {
	for i, m := range messages {
		if strings.HasPrefix(m, "RUN") && strings.Contains(m, needle) {
			return i
		}
	}
	return -1
}

func withPrefix(messages []string, prefix string) []string {
	var out []string
	for _, m := range messages {
		if strings.HasPrefix(m, prefix) {
			out = append(out, m)
		}
	}
	return out
}

func main() {
	if len(os.Args) < 4 {
		fail("usage: interop <port> <user> <password>")
	}
	port, user, password := os.Args[1], os.Args[2], os.Args[3]
	uri := fmt.Sprintf("bolt+ssc://127.0.0.1:%s", port)
	ctx := context.Background()

	driver, err := neo4j.NewDriverWithContext(uri, neo4j.BasicAuth(user, password, ""))
	if err != nil {
		fail("could not create the driver: %v", err)
	}
	defer func() { _ = driver.Close(ctx) }()

	if err := driver.VerifyConnectivity(ctx); err != nil {
		fail("could not connect: %v", err)
	}

	// 1. Seed the rows in a SEPARATE managed write transaction, so the transaction under test does
	//    nothing but run the two statements.
	seed := driver.NewSession(ctx, neo4j.SessionConfig{})
	_, err = seed.ExecuteWrite(ctx, func(tx neo4j.ManagedTransaction) (any, error) {
		result, err := tx.Run(ctx,
			"UNWIND range(1, $n) AS i CREATE (:Big {i: i})", map[string]any{"n": total})
		if err != nil {
			return nil, err
		}
		return result.Consume(ctx)
	})
	if closeErr := seed.Close(ctx); closeErr != nil {
		fail("could not close the seeding session: %v", closeErr)
	}
	if err != nil {
		fail("could not seed %d nodes: %v", total, err)
	}

	// 2. ONE explicit transaction, TWO statements, the first larger than FetchSize. The BoltLogger
	//    is attached to THIS session only, so the capture holds exactly this transaction's traffic.
	capture := &captureLogger{}
	session := driver.NewSession(ctx, neo4j.SessionConfig{FetchSize: fetch, BoltLogger: capture})
	defer func() { _ = session.Close(ctx) }()

	tx, err := session.BeginTransaction(ctx)
	if err != nil {
		fail("could not begin the transaction: %v", err)
	}

	// Statement 1. Taking exactly ONE record drives RUN + a single PULL(FetchSize): the server
	// answers a full batch + SUCCESS {has_more: true} and stays in TX_STREAMING. The driver then
	// PAUSES this stream (it does not buffer it) and addresses it again later with PULL {n, qid}.
	r1, err := tx.Run(ctx, "MATCH (n:Big) RETURN n.i AS i ORDER BY i", nil)
	if err != nil {
		fail("the first statement failed: %v", err)
	}
	if !r1.Next(ctx) {
		fail("the first statement returned no records at all (err: %v)", r1.Err())
	}
	firstValue, ok := r1.Record().Get("i")
	if !ok {
		fail("the first record of stream 1 has no column i")
	}
	first, ok := firstValue.(int64)
	if !ok {
		fail("column i came back as %T, expected an integer", firstValue)
	}
	if first != 1 {
		fail("first record of stream 1 was i=%d, expected 1", first)
	}

	// Statement 2 — the RUN that used to be rejected because the connection was in TX_STREAMING.
	r2, err := tx.Run(ctx, "RETURN 1 AS one", nil)
	if err != nil {
		fail("the second statement failed while the first stream was open: %v", err)
	}
	record, err := r2.Single(ctx)
	if err != nil {
		fail("the second statement did not return exactly one record: %v", err)
	}
	oneValue, ok := record.Get("one")
	if !ok {
		fail("the second statement's record has no column one")
	}
	if one, ok := oneValue.(int64); !ok || one != 1 {
		fail("second statement returned one=%v, expected 1", oneValue)
	}

	// Finish stream 1 and assert the RECORDS (not just the count) arrive complete and in order.
	got := []int64{first}
	for r1.Next(ctx) {
		value, ok := r1.Record().Get("i")
		if !ok {
			fail("a record of stream 1 has no column i")
		}
		n, ok := value.(int64)
		if !ok {
			fail("column i came back as %T, expected an integer", value)
		}
		got = append(got, n)
	}
	if err := r1.Err(); err != nil {
		fail("stream 1 failed while being drained: %v", err)
	}
	if len(got) != total {
		fail("stream 1 yielded %d records, expected %d", len(got), total)
	}
	for i, n := range got {
		if n != int64(i+1) {
			fail("stream 1 record %d was i=%d, expected %d", i, n, i+1)
		}
	}

	if err := tx.Commit(ctx); err != nil {
		fail("could not commit: %v", err)
	}

	// 3. Non-vacuity gate on the captured wire traffic.
	messages := capture.snapshot()
	run1 := indexOfRun(messages, "MATCH (n:Big)")
	run2 := indexOfRun(messages, "RETURN 1 AS one")
	if run1 == -1 {
		fail("no RUN for the first statement was logged: %v", messages)
	}
	if run2 == -1 {
		fail("no RUN for the second statement was logged: %v", messages)
	}
	if run2 < run1 {
		fail("the second statement was sent before the first: %v", messages)
	}
	pullsBefore := withPrefix(messages[:run2], "PULL")
	pullsAfter := withPrefix(messages[run2+1:], "PULL")
	discards := len(withPrefix(messages, "DISCARD"))
	// Draining 2500 rows at n=1000 needs at least 3 PULLs, so <= 2 PULLs before the second RUN
	// proves stream 1 was demonstrably UNFINISHED when statement 2 was issued.
	if len(pullsBefore) > 2 {
		fail("stream 1 had already been drained before the second RUN (%d PULLs); "+
			"the test would be vacuous: %v", len(pullsBefore), messages)
	}
	// ...but only because each of those PULLs was BOUNDED by the fetch size. A drain-everything
	// PULL {n: -1} would finish stream 1 in a single message and make the count meaningless.
	for _, m := range pullsBefore {
		if !strings.Contains(m, fmt.Sprint(fetch)) {
			fail("a PULL before the second RUN was not bounded by the fetch size %d, so the "+
				"PULL count proves nothing: %q", fetch, m)
		}
	}
	// One PULL serves statement 2's own result; the rest resume the still-open stream 1.
	if len(pullsAfter) < 2 {
		fail("only %d PULLs followed the second RUN; stream 1 was not resumed after it: %v",
			len(pullsAfter), messages)
	}
	// A PULL carrying an explicit qid addresses a stream that is NOT the connection's current one
	// — direct evidence that two streams of this transaction were open at the same time.
	qidAddressed := false
	for _, m := range pullsAfter {
		if strings.Contains(m, "qid") {
			qidAddressed = true
		}
	}
	if !qidAddressed {
		fail("no PULL after the second RUN addressed an explicit qid, so stream 1 was never "+
			"resumed as a second, independently addressable stream: %v", messages)
	}
	if discards != 0 {
		fail("the driver discarded a stream instead of keeping it open: %v", messages)
	}
	fmt.Printf("GRAPHUS_GO_MULTISTREAM_WIRE pulls_before=%d pulls_after=%d\n",
		len(pullsBefore), len(pullsAfter))

	fmt.Println("GRAPHUS_GO_MULTISTREAM_OK")
}
"#;

/// `package.json` pinning the official driver (v6.x — current major) for a reproducible install.
const PACKAGE_JSON: &str = r#"{
  "name": "graphus-neo4j-interop",
  "version": "1.0.0",
  "private": true,
  "description": "Drives Graphus over Bolt+TLS with the official Neo4j driver (rmp #226).",
  "dependencies": {
    "neo4j-driver": "^6.1.0"
  }
}
"#;

/// The official Neo4j Python driver, pinned to the current major for a reproducible `pip install`
/// (same policy as [`PACKAGE_JSON`] pins the JavaScript driver).
const PYTHON_DRIVER_REQUIREMENT: &str = "neo4j>=6.1,<7";

/// `go.mod` for the throw-away interop module. The driver version is pinned to the exact one the
/// repository's own Go client examples depend on (`examples/clients-go/go.mod`), so the interop test
/// and the shipped examples are proven against the same driver build, and the shared module cache is
/// reused rather than fetching a second copy.
const GO_MOD: &str = r#"module graphusinterop

go 1.23

require github.com/neo4j/neo4j-go-driver/v5 v5.28.4
"#;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn official_neo4j_driver_interoperates_over_bolt_tls() {
    let dir = TempDir::new();

    // Self-signed cert/key for the TLS listener (CN/SAN = localhost; `bolt+ssc://` trusts it).
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
    let cert_path = dir.path.join("cert.pem");
    let key_path = dir.path.join("key.pem");
    std::fs::write(&cert_path, cert.cert.pem()).unwrap();
    std::fs::write(&key_path, cert.signing_key.serialize_pem()).unwrap();

    // Boot the real server and read back the OS-assigned ephemeral Bolt-TCP port.
    let config = config_for(&dir, cert_path, key_path, None, None);
    let server = boot(config).await;
    let bolt: SocketAddr = server.bolt_tcp_addr.expect("Bolt-TCP listener enabled");

    // Install the official driver and run the round-trip script against the live server (the shared
    // helper serialises the `npm install` phase so concurrent interop tests don't race the npm cache).
    let (stdout, stderr, ok) =
        install_and_run_driver(dir.path.join("node"), DRIVER_SCRIPT, bolt.port()).await;

    // Surface the full driver output on failure so a real Bolt-compliance regression is debuggable.
    assert!(
        ok,
        "the official Neo4j driver did NOT round-trip against Graphus.\n\
         --- node stdout ---\n{stdout}\n--- node stderr ---\n{stderr}",
    );
    assert!(
        stdout.contains("GRAPHUS_INTEROP_OK"),
        "driver exited 0 but the success marker was missing.\n\
         --- node stdout ---\n{stdout}\n--- node stderr ---\n{stderr}",
    );

    server.shutdown().await.expect("clean shutdown");
}

/// Serialises the `npm install` phase across the concurrent real-driver interop tests. Cargo runs
/// `#[test]` functions in parallel by default, and several `npm install` invocations racing on the
/// shared global npm cache (`~/.npm/_cacache`) can intermittently fail one another — a known npm
/// concurrency hazard, first observed here once the suite grew to four installs. Holding this lock
/// only around the install (never the server boot or the `node` round-trip) removes that race while
/// keeping the actual driver exchanges parallel and the download cache warm.
fn npm_install_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

/// Materialises a Node project (`package.json` + the given script as `interop.js`) in `project`,
/// installs the official driver, runs the script with the given positional `argv` (the arguments
/// after the script path), and returns `(stdout, stderr, success)`. Shared by every interop test so
/// the npm/node plumbing lives in one place.
async fn install_and_run_driver_argv(
    project: PathBuf,
    script: &str,
    argv: Vec<String>,
) -> (String, String, bool) {
    std::fs::create_dir_all(&project).unwrap();
    std::fs::write(project.join("package.json"), PACKAGE_JSON).unwrap();
    std::fs::write(project.join("interop.js"), script).unwrap();

    let install = {
        // Serialise ONLY the install so concurrent tests do not race the shared npm cache.
        let _serialise = npm_install_lock().lock().await;
        let project = project.clone();
        tokio::task::spawn_blocking(move || {
            Command::new("npm")
                .arg("install")
                .arg("--no-audit")
                .arg("--no-fund")
                .arg("--loglevel=error")
                .current_dir(&project)
                .output()
        })
        .await
        .expect("npm install task")
        .expect("spawn npm install (is `npm` on PATH?)")
    };
    assert!(
        install.status.success(),
        "npm install failed:\n--- stdout ---\n{}\n--- stderr ---\n{}",
        String::from_utf8_lossy(&install.stdout),
        String::from_utf8_lossy(&install.stderr),
    );

    let run = {
        let project = project.clone();
        tokio::task::spawn_blocking(move || {
            Command::new("node")
                .arg("interop.js")
                .args(&argv)
                .current_dir(&project)
                .output()
        })
        .await
        .expect("node task")
        .expect("spawn node (is `node` on PATH?)")
    };

    (
        String::from_utf8_lossy(&run.stdout).into_owned(),
        String::from_utf8_lossy(&run.stderr).into_owned(),
        run.status.success(),
    )
}

/// Convenience wrapper for scripts that take the standard `(port, user, password)` argv.
async fn install_and_run_driver(
    project: PathBuf,
    script: &str,
    port: u16,
) -> (String, String, bool) {
    install_and_run_driver_argv(
        project,
        script,
        vec![port.to_string(), USER.to_owned(), PASSWORD.to_owned()],
    )
    .await
}

/// Serialises the Python provisioning phase (virtual-environment creation + `pip install`) across
/// the concurrent interop tests, for exactly the reason [`npm_install_lock`] exists: `pip` shares a
/// global HTTP/wheel cache (`~/.cache/pip`) that concurrent installs can trip over. The lock is held
/// ONLY around the provisioning, never around the server boot or the driver exchange, so the actual
/// Bolt traffic still runs in parallel and the download cache stays warm.
fn pip_install_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

/// Materialises a Python project (the given script as `interop.py`) in `project`, provisions a
/// **virtual environment inside that directory** with the official `neo4j` package, runs the script
/// with the given positional `argv`, and returns `(stdout, stderr, success)`.
///
/// The venv keeps the whole thing hermetic: nothing is installed into the system interpreter, and
/// the environment dies with the test's `TempDir`. A missing `python3` (or a `python3` without the
/// `venv` module) is a HARD failure, never a skip — the same policy `scripts/verify.sh` applies to
/// `node`/`npm`. This mirrors [`install_and_run_driver_argv`] for the Python ecosystem.
async fn install_and_run_python_driver(
    project: PathBuf,
    script: &str,
    argv: Vec<String>,
) -> (String, String, bool) {
    std::fs::create_dir_all(&project).unwrap();
    std::fs::write(project.join("interop.py"), script).unwrap();
    let venv = project.join("venv");

    {
        // Serialise ONLY the provisioning so concurrent tests do not race the shared pip cache.
        let _serialise = pip_install_lock().lock().await;

        let create = {
            let venv = venv.clone();
            let project = project.clone();
            tokio::task::spawn_blocking(move || {
                Command::new("python3")
                    .arg("-m")
                    .arg("venv")
                    .arg(&venv)
                    .current_dir(&project)
                    .output()
            })
            .await
            .expect("python venv task")
            .expect("spawn python3 (is `python3` on PATH?)")
        };
        assert!(
            create.status.success(),
            "python3 -m venv failed (is the `venv` module available?):\n\
             --- stdout ---\n{}\n--- stderr ---\n{}",
            String::from_utf8_lossy(&create.stdout),
            String::from_utf8_lossy(&create.stderr),
        );

        let install = {
            let pip = venv.join("bin").join("pip");
            let project = project.clone();
            tokio::task::spawn_blocking(move || {
                Command::new(&pip)
                    .arg("install")
                    .arg("--disable-pip-version-check")
                    .arg(PYTHON_DRIVER_REQUIREMENT)
                    .current_dir(&project)
                    .output()
            })
            .await
            .expect("pip install task")
            .expect("spawn the venv pip (venv creation should have provided it)")
        };
        assert!(
            install.status.success(),
            "pip install {PYTHON_DRIVER_REQUIREMENT} failed:\n\
             --- stdout ---\n{}\n--- stderr ---\n{}",
            String::from_utf8_lossy(&install.stdout),
            String::from_utf8_lossy(&install.stderr),
        );
    }

    let run = {
        let python = venv.join("bin").join("python");
        tokio::task::spawn_blocking(move || {
            Command::new(&python)
                .arg("interop.py")
                .args(&argv)
                .current_dir(&project)
                .output()
        })
        .await
        .expect("python task")
        .expect("spawn the venv python")
    };

    (
        String::from_utf8_lossy(&run.stdout).into_owned(),
        String::from_utf8_lossy(&run.stderr).into_owned(),
        run.status.success(),
    )
}

/// Serialises the Go provisioning phase (`go mod tidy` + `go build`) across the concurrent interop
/// tests, for exactly the reason [`npm_install_lock`] exists: the module cache (`GOMODCACHE`) and
/// the build cache (`GOCACHE`) are shared, process-global resources. As with npm and pip, the lock
/// covers only the provisioning, never the server boot or the driver exchange.
fn go_build_lock() -> &'static Mutex<()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    LOCK.get_or_init(|| Mutex::new(()))
}

/// Materialises a Go module ([`GO_MOD`] plus the given program as `main.go`) in `project`, resolves
/// and builds it against the pinned official driver, runs the resulting binary with the given
/// positional `argv`, and returns `(stdout, stderr, success)`.
///
/// A missing `go` toolchain is a HARD failure, never a skip. This mirrors
/// [`install_and_run_driver_argv`] for the Go ecosystem.
async fn install_and_run_go_driver(
    project: PathBuf,
    script: &str,
    argv: Vec<String>,
) -> (String, String, bool) {
    std::fs::create_dir_all(&project).unwrap();
    std::fs::write(project.join("go.mod"), GO_MOD).unwrap();
    std::fs::write(project.join("main.go"), script).unwrap();
    let binary = project.join("interop");

    {
        // Serialise ONLY the provisioning so concurrent tests do not race the shared Go caches.
        let _serialise = go_build_lock().lock().await;

        let tidy = {
            let project = project.clone();
            tokio::task::spawn_blocking(move || {
                Command::new("go")
                    .arg("mod")
                    .arg("tidy")
                    .current_dir(&project)
                    .output()
            })
            .await
            .expect("go mod tidy task")
            .expect("spawn go (is `go` on PATH?)")
        };
        assert!(
            tidy.status.success(),
            "go mod tidy failed:\n--- stdout ---\n{}\n--- stderr ---\n{}",
            String::from_utf8_lossy(&tidy.stdout),
            String::from_utf8_lossy(&tidy.stderr),
        );

        let build = {
            let project = project.clone();
            let binary = binary.clone();
            tokio::task::spawn_blocking(move || {
                Command::new("go")
                    .arg("build")
                    .arg("-o")
                    .arg(&binary)
                    .arg(".")
                    .current_dir(&project)
                    .output()
            })
            .await
            .expect("go build task")
            .expect("spawn go build")
        };
        assert!(
            build.status.success(),
            "go build failed:\n--- stdout ---\n{}\n--- stderr ---\n{}",
            String::from_utf8_lossy(&build.stdout),
            String::from_utf8_lossy(&build.stderr),
        );
    }

    let run = tokio::task::spawn_blocking(move || {
        Command::new(&binary)
            .args(&argv)
            .current_dir(&project)
            .output()
    })
    .await
    .expect("go program task")
    .expect("spawn the built Go interop binary");

    (
        String::from_utf8_lossy(&run.stdout).into_owned(),
        String::from_utf8_lossy(&run.stderr).into_owned(),
        run.status.success(),
    )
}

/// Boots a real Graphus server (Bolt-TCP+TLS) for one of the rmp #907 multi-statement-transaction
/// tests and hands back the handle plus its ephemeral Bolt port. Every ecosystem drives the exact
/// same server configuration, so a difference between them is a driver difference, never a
/// configuration difference. The `TempDir` is returned because it owns the store and the TLS
/// material for the lifetime of the test.
async fn boot_multi_stream_server() -> (TempDir, ServerHandle, u16) {
    let dir = TempDir::new();

    // Self-signed cert/key for the TLS listener (`bolt+ssc://` trusts it).
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
    let cert_path = dir.path.join("cert.pem");
    let key_path = dir.path.join("key.pem");
    std::fs::write(&cert_path, cert.cert.pem()).unwrap();
    std::fs::write(&key_path, cert.signing_key.serialize_pem()).unwrap();

    let config = config_for(&dir, cert_path, key_path, None, None);
    let server = boot(config).await;
    let bolt: SocketAddr = server.bolt_tcp_addr.expect("Bolt-TCP listener enabled");
    let port = bolt.port();
    (dir, server, port)
}

/// Full CRUD lifecycle over the OFFICIAL Neo4j driver at a realistic volume (≥100 nodes, ≥200 edges).
///
/// Boots a real Graphus server (Bolt-TCP+TLS), then drives it with the official `neo4j-driver` to
/// create 100 nodes + 200 relationships, read them back (counts, ordered traversal, aggregation),
/// update node *and* relationship properties, and delete a relationship class plus a subset of nodes
/// (`DETACH DELETE`). The driver script asserts exact deterministic counts at every step; this test
/// fails loudly with the full driver output if any operation does not round-trip as expected.
///
/// Like [`official_neo4j_driver_interoperates_over_bolt_tls`], this is a **real-ecosystem wire
/// interop** test, which is why it lives behind the `neo4j-interop` feature and not in the DST
/// simulator: DST is in-process and deterministic and cannot drive the external official driver over
/// a TLS socket — exercising that exact wire path is the entire point (the rmp #226 precedent).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn official_neo4j_driver_full_crud_nodes_and_edges() {
    let dir = TempDir::new();

    // Self-signed cert/key for the TLS listener (`bolt+ssc://` trusts it).
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
    let cert_path = dir.path.join("cert.pem");
    let key_path = dir.path.join("key.pem");
    std::fs::write(&cert_path, cert.cert.pem()).unwrap();
    std::fs::write(&key_path, cert.signing_key.serialize_pem()).unwrap();

    // Boot the real server and read back the OS-assigned ephemeral Bolt-TCP port.
    let config = config_for(&dir, cert_path, key_path, None, None);
    let server = boot(config).await;
    let bolt: SocketAddr = server.bolt_tcp_addr.expect("Bolt-TCP listener enabled");

    // Run the CRUD script against the live server.
    let (stdout, stderr, ok) =
        install_and_run_driver(dir.path.join("node-crud"), CRUD_SCRIPT, bolt.port()).await;

    assert!(
        ok,
        "the official Neo4j driver CRUD lifecycle did NOT complete against Graphus.\n\
         --- node stdout ---\n{stdout}\n--- node stderr ---\n{stderr}",
    );
    assert!(
        stdout.contains("GRAPHUS_CRUD_OK"),
        "driver exited 0 but the CRUD success marker was missing.\n\
         --- node stdout ---\n{stdout}\n--- node stderr ---\n{stderr}",
    );

    server.shutdown().await.expect("clean shutdown");
}

/// The verbatim `Neo.ClientError.Database.DatabaseNotFound` leaf code, proven end-to-end against the
/// OFFICIAL Neo4j driver (rmp #814).
///
/// The #800 Bolt audit found Graphus reported a missing database as the coarse
/// `Neo.ClientError.Request.Invalid`, where Neo4j uses the fine-grained
/// `Neo.ClientError.Database.DatabaseNotFound`. Only the reference driver can prove the fix reaches
/// the wire as the ecosystem reads it: this boots a real Graphus server (Bolt-TCP+TLS), targets a
/// non-existent database with the official driver, and asserts the driver observes the exact leaf
/// code AND still treats it as a NON-retryable `ClientError` (retryability did not move) — then that
/// the connection keeps serving. Like the other real-ecosystem interop tests it lives behind the
/// `neo4j-interop` feature (not the DST simulator), because exercising the external driver over the
/// TLS socket is the entire point.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn official_neo4j_driver_reports_database_not_found_leaf_code() {
    let dir = TempDir::new();

    // Self-signed cert/key for the TLS listener (`bolt+ssc://` trusts it).
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
    let cert_path = dir.path.join("cert.pem");
    let key_path = dir.path.join("key.pem");
    std::fs::write(&cert_path, cert.cert.pem()).unwrap();
    std::fs::write(&key_path, cert.signing_key.serialize_pem()).unwrap();

    // Boot the real server and read back the OS-assigned ephemeral Bolt-TCP port.
    let config = config_for(&dir, cert_path, key_path, None, None);
    let server = boot(config).await;
    let bolt: SocketAddr = server.bolt_tcp_addr.expect("Bolt-TCP listener enabled");

    // Drive the DatabaseNotFound probe against the live server.
    let (stdout, stderr, ok) = install_and_run_driver(
        dir.path.join("node-dbnotfound"),
        DATABASE_NOT_FOUND_SCRIPT,
        bolt.port(),
    )
    .await;

    assert!(
        ok,
        "the official Neo4j driver did NOT observe Neo.ClientError.Database.DatabaseNotFound.\n\
         --- node stdout ---\n{stdout}\n--- node stderr ---\n{stderr}",
    );
    assert!(
        stdout.contains("GRAPHUS_DBNOTFOUND_OK"),
        "driver exited 0 but the DatabaseNotFound success marker was missing.\n\
         --- node stdout ---\n{stdout}\n--- node stderr ---\n{stderr}",
    );

    server.shutdown().await.expect("clean shutdown");
}

/// Bolt **5.0** end to end against the OFFICIAL Neo4j driver (rmp #906).
///
/// Graphus advertises 5.0 in both handshake forms, so a client that negotiates it must be served — but
/// only the 5.1+ `LOGON` authentication flow existed, which made every negotiated-5.0 connection dead
/// on arrival (the `HELLO` credentials were never read, and the first `RUN` was answered with a
/// FAILURE and a closed connection). This test boots the server with `bolt_max_protocol_minor: Some(0)`
/// so the **unmodified** official driver negotiates exactly 5.0, then asserts the driver reports 5.0,
/// authenticates from its `HELLO`, and completes queries and a write transaction.
///
/// It is the real-ecosystem counterpart of the in-process 5.0 state-machine tests in `graphus-bolt`:
/// only the reference driver can prove Graphus serves the 5.0 flow as the ecosystem actually speaks it,
/// which is why — like the other interop tests here — it lives behind the `neo4j-interop` feature and
/// not in the DST simulator (DST is in-process and cannot drive the external driver over a TLS socket).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn official_neo4j_driver_negotiates_bolt_50_and_runs_a_query() {
    let dir = TempDir::new();

    // Self-signed cert/key for the TLS listener (`bolt+ssc://` trusts it).
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
    let cert_path = dir.path.join("cert.pem");
    let key_path = dir.path.join("key.pem");
    std::fs::write(&cert_path, cert.cert.pem()).unwrap();
    std::fs::write(&key_path, cert.signing_key.serialize_pem()).unwrap();

    // Cap the advertised Bolt window at 5.0 so the stock driver negotiates exactly that minor.
    let config = config_for(&dir, cert_path, key_path, None, Some(0));
    let server = boot(config).await;
    let bolt: SocketAddr = server.bolt_tcp_addr.expect("Bolt-TCP listener enabled");

    let (stdout, stderr, ok) =
        install_and_run_driver(dir.path.join("node-bolt50"), BOLT_50_SCRIPT, bolt.port()).await;

    assert!(
        ok,
        "the official Neo4j driver did NOT complete a Bolt 5.0 session against Graphus.\n\
         --- node stdout ---\n{stdout}\n--- node stderr ---\n{stderr}",
    );
    assert!(
        stdout.contains("GRAPHUS_BOLT50_OK"),
        "driver exited 0 but the Bolt 5.0 success marker was missing.\n\
         --- node stdout ---\n{stdout}\n--- node stderr ---\n{stderr}",
    );

    server.shutdown().await.expect("clean shutdown");
}

/// Boots a real Graphus server (Bolt-TCP+TLS) with the given `bolt_server_agent`, then uses the
/// OFFICIAL Neo4j driver to read the `HELLO` `SUCCESS` `server` agent back over the real wire and
/// assert it equals `expected_agent`. This is the real-ecosystem proof that the `bolt_server_agent`
/// startup option actually controls what a genuine Neo4j driver observes (rmp #614) — the unit tests
/// prove the value reaches Graphus's own encoder, but only the reference driver can prove it is what
/// the ecosystem reads back. `project_subdir` isolates each test's Node project inside the tempdir.
async fn assert_official_driver_sees_agent(
    bolt_server_agent: Option<String>,
    expected_agent: &str,
    project_subdir: &str,
) {
    let dir = TempDir::new();

    // Self-signed cert/key for the TLS listener (`bolt+ssc://` trusts it).
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
    let cert_path = dir.path.join("cert.pem");
    let key_path = dir.path.join("key.pem");
    std::fs::write(&cert_path, cert.cert.pem()).unwrap();
    std::fs::write(&key_path, cert.signing_key.serialize_pem()).unwrap();

    // Boot with the requested agent and read back the OS-assigned ephemeral Bolt-TCP port.
    let config = config_for(&dir, cert_path, key_path, bolt_server_agent, None);
    let server = boot(config).await;
    let bolt: SocketAddr = server.bolt_tcp_addr.expect("Bolt-TCP listener enabled");

    // Drive the agent probe: expected agent is argv[4], read back via both driver-side surfaces.
    let (stdout, stderr, ok) = install_and_run_driver_argv(
        dir.path.join(project_subdir),
        AGENT_PROBE_SCRIPT,
        vec![
            bolt.port().to_string(),
            USER.to_owned(),
            PASSWORD.to_owned(),
            expected_agent.to_owned(),
        ],
    )
    .await;

    assert!(
        ok,
        "the official Neo4j driver did NOT read back the server agent {expected_agent:?}.\n\
         --- node stdout ---\n{stdout}\n--- node stderr ---\n{stderr}",
    );
    assert!(
        stdout.contains(&format!("GRAPHUS_AGENT_OK:{expected_agent}")),
        "driver exited 0 but the agent success marker for {expected_agent:?} was missing.\n\
         --- node stdout ---\n{stdout}\n--- node stderr ---\n{stderr}",
    );

    server.shutdown().await.expect("clean shutdown");
}

/// The opt-in Neo4j-compat mode, proven end-to-end against the OFFICIAL driver (rmp #614).
///
/// Booting with the `neo4j-compat` shortcut must make a genuine Neo4j driver observe the vetted
/// `Neo4j/5.13.0` product string over the real Bolt+TLS wire — the entire purpose of the mode (so a
/// strict/legacy driver that parses and case-sensitively checks the `server` product accepts it).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn official_driver_reads_neo4j_compat_server_agent() {
    assert_official_driver_sees_agent(
        Some("neo4j-compat".to_owned()),
        graphus_bolt::server::NEO4J_COMPAT_SERVER_AGENT,
        "node-agent-compat",
    )
    .await;
    // Guard the exact wire literal the strict/legacy driver regex expects (`Neo4j/<major>.<minor>…`).
    assert_eq!(
        graphus_bolt::server::NEO4J_COMPAT_SERVER_AGENT,
        "Neo4j/5.13.0"
    );
}

/// Control for [`official_driver_reads_neo4j_compat_server_agent`]: with no override (`None`), the
/// honest `Graphus/<ver>` default must reach the wire verbatim. This proves it is the *option* the
/// driver observes — not a hard-wired constant — so the compat result above is a real behavioural
/// switch and the default remains truthful about the product for every modern driver (rmp #614).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn official_driver_reads_default_graphus_server_agent() {
    assert_official_driver_sees_agent(
        None,
        graphus_bolt::server::DEFAULT_SERVER_AGENT,
        "node-agent-default",
    )
    .await;
}

/// Several open result streams in ONE explicit transaction, proven with the OFFICIAL JavaScript
/// driver (rmp #907).
///
/// Graphus rejected a `RUN` received in Bolt state `TX_STREAMING`, so an explicit transaction whose
/// FIRST result was larger than the driver's `fetchSize` (1000 by default) could not run a SECOND
/// statement: the driver got a `FAILURE` and the transaction died. That is a direct violation of the
/// Bolt server-state tables, which list `RUN` among the valid requests in `TX_STREAMING` and require
/// the server to keep every stream of the transaction addressable by its `qid`.
///
/// This boots a real Graphus server (Bolt-TCP+TLS), seeds 2500 nodes in a separate write, then in
/// ONE explicit transaction leaves a 2500-row result open after a single batch and runs a second
/// statement on top of it. It asserts the second statement's value, then that the first stream still
/// delivers all 2500 records **in order** (the records, not merely the count), and finally that the
/// captured wire traffic really carried the interleaving — see [`MULTI_STREAM_SCRIPT`] for how the
/// stream is kept open and how the non-vacuity gate is computed.
///
/// Like every other test here it is a real-ecosystem wire test, which is why it lives behind the
/// `neo4j-interop` feature and not in the DST simulator: DST is in-process and cannot drive the
/// external official driver over a TLS socket, and driving that exact wire path is the entire point.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn official_neo4j_driver_multi_statement_transaction_with_large_first_result() {
    let (dir, server, port) = boot_multi_stream_server().await;

    let (stdout, stderr, ok) =
        install_and_run_driver(dir.path.join("node-multistream"), MULTI_STREAM_SCRIPT, port).await;

    assert!(
        ok,
        "the official Neo4j JavaScript driver could NOT run a second statement in a transaction \
         whose first result was still streaming (rmp #907).\n\
         --- node stdout ---\n{stdout}\n--- node stderr ---\n{stderr}",
    );
    assert!(
        stdout.contains("GRAPHUS_MULTISTREAM_OK"),
        "driver exited 0 but the multi-stream success marker was missing.\n\
         --- node stdout ---\n{stdout}\n--- node stderr ---\n{stderr}",
    );

    server.shutdown().await.expect("clean shutdown");
}

/// The same rmp #907 reproduction driven by the OFFICIAL **Python** driver.
///
/// A second, independent driver ecosystem is not redundancy: each official driver decides for
/// itself whether to keep several streams open or to buffer the previous result, so only by driving
/// more than one can Graphus claim the fix matches what the ecosystem actually speaks. The Python
/// driver buffers the previous result **only** on Bolt 3 (no `qid` exists there); on Bolt 5 it sends
/// the second `RUN` with the first stream still open, which is exactly the reproduction from the bug
/// report.
///
/// The `neo4j` package is provisioned into a virtual environment inside the test's own temp
/// directory, so the run is hermetic and leaves nothing behind. A missing `python3` is a hard
/// failure, never a skip.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn official_python_driver_multi_statement_transaction_with_large_first_result() {
    let (dir, server, port) = boot_multi_stream_server().await;

    let (stdout, stderr, ok) = install_and_run_python_driver(
        dir.path.join("python-multistream"),
        PYTHON_MULTI_STREAM_SCRIPT,
        vec![port.to_string(), USER.to_owned(), PASSWORD.to_owned()],
    )
    .await;

    assert!(
        ok,
        "the official Neo4j Python driver could NOT run a second statement in a transaction whose \
         first result was still streaming (rmp #907).\n\
         --- python stdout ---\n{stdout}\n--- python stderr ---\n{stderr}",
    );
    assert!(
        stdout.contains("GRAPHUS_PY_MULTISTREAM_OK"),
        "the Python driver exited 0 but the multi-stream success marker was missing.\n\
         --- python stdout ---\n{stdout}\n--- python stderr ---\n{stderr}",
    );

    server.shutdown().await.expect("clean shutdown");
}

/// The same rmp #907 reproduction driven by the OFFICIAL **Go** driver.
///
/// The Go driver is the strictest witness of the three: on receiving a `RUN` while a transaction
/// stream is open it *pauses* that stream rather than buffering it, and later resumes it with an
/// explicit `PULL {n, qid}` addressed to a non-current stream. A server that cannot hold several
/// streams per transaction therefore fails this test twice over — once on the second `RUN`, and
/// once on the `qid`-addressed `PULL` that resumes the first result.
///
/// The module is created and built inside the test's own temp directory against the very driver
/// version the repository's Go client examples pin (`examples/clients-go/go.mod`). A missing `go`
/// toolchain is a hard failure, never a skip.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn official_go_driver_multi_statement_transaction_with_large_first_result() {
    let (dir, server, port) = boot_multi_stream_server().await;

    let (stdout, stderr, ok) = install_and_run_go_driver(
        dir.path.join("go-multistream"),
        GO_MULTI_STREAM_SCRIPT,
        vec![port.to_string(), USER.to_owned(), PASSWORD.to_owned()],
    )
    .await;

    assert!(
        ok,
        "the official Neo4j Go driver could NOT run a second statement in a transaction whose \
         first result was still streaming (rmp #907).\n\
         --- go stdout ---\n{stdout}\n--- go stderr ---\n{stderr}",
    );
    assert!(
        stdout.contains("GRAPHUS_GO_MULTISTREAM_OK"),
        "the Go driver exited 0 but the multi-stream success marker was missing.\n\
         --- go stdout ---\n{stdout}\n--- go stderr ---\n{stderr}",
    );

    server.shutdown().await.expect("clean shutdown");
}
