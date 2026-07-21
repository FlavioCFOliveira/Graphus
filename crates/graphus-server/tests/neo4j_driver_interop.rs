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
//! Requirements when run: `node` (v18+) and `npm` on PATH, and network/cache access for
//! `npm install neo4j-driver`.
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
/// vetted `Neo4j/5.13.0` legacy-driver compat mode — rmp #614).
fn config_for(
    dir: &TempDir,
    cert_path: PathBuf,
    key_path: PathBuf,
    bolt_server_agent: Option<String>,
) -> ServerConfig {
    ServerConfig {
        store_path: dir.path.join("store"),
        default_database: "graphus".to_owned(),
        buffer_pool_pages: 256,
        // Ephemeral port; the OS picks it and we read it back from the handle.
        bolt_tcp_addr: Some("127.0.0.1:0".to_owned()),
        advertised_bolt_address: None,
        bolt_server_agent,
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
    let config = config_for(&dir, cert_path, key_path, None);
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
    let config = config_for(&dir, cert_path, key_path, None);
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
    let config = config_for(&dir, cert_path, key_path, None);
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
    let config = config_for(&dir, cert_path, key_path, bolt_server_agent);
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
