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
        path.push(format!(
            "graphus-neo4j-interop-{nanos}-{}",
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
/// which the admin holds).
fn config_for(dir: &TempDir, cert_path: PathBuf, key_path: PathBuf) -> ServerConfig {
    ServerConfig {
        store_path: dir.path.join("store"),
        default_database: "graphus".to_owned(),
        buffer_pool_pages: 256,
        // Ephemeral port; the OS picks it and we read it back from the handle.
        bolt_tcp_addr: Some("127.0.0.1:0".to_owned()),
        advertised_bolt_address: None,
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
    let config = config_for(&dir, cert_path, key_path);
    let server = boot(config).await;
    let bolt: SocketAddr = server.bolt_tcp_addr.expect("Bolt-TCP listener enabled");
    let port = bolt.port();

    // Materialise the Node project in the tempdir.
    let project = dir.path.join("node");
    std::fs::create_dir_all(&project).unwrap();
    std::fs::write(project.join("package.json"), PACKAGE_JSON).unwrap();
    std::fs::write(project.join("interop.js"), DRIVER_SCRIPT).unwrap();

    // Install the official driver. `npm install` (not `ci`) so it works with or without a lockfile,
    // honouring any local cache. Run on a blocking thread so we don't stall the Tokio runtime.
    let install = {
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

    // Run the driver script against the live server.
    let run = {
        let project = project.clone();
        let port = port.to_string();
        tokio::task::spawn_blocking(move || {
            Command::new("node")
                .arg("interop.js")
                .arg(&port)
                .arg(USER)
                .arg(PASSWORD)
                .current_dir(&project)
                .output()
        })
        .await
        .expect("node task")
        .expect("spawn node (is `node` on PATH?)")
    };

    let stdout = String::from_utf8_lossy(&run.stdout);
    let stderr = String::from_utf8_lossy(&run.stderr);

    // Surface the full driver output on failure so a real Bolt-compliance regression is debuggable.
    assert!(
        run.status.success(),
        "the official Neo4j driver did NOT round-trip against Graphus (exit {:?}).\n\
         --- node stdout ---\n{stdout}\n--- node stderr ---\n{stderr}",
        run.status.code(),
    );
    assert!(
        stdout.contains("GRAPHUS_INTEROP_OK"),
        "driver exited 0 but the success marker was missing.\n\
         --- node stdout ---\n{stdout}\n--- node stderr ---\n{stderr}",
    );

    server.shutdown().await.expect("clean shutdown");
}

/// Materialises a Node project (`package.json` + the given script as `interop.js`) in `project`,
/// installs the official driver, runs the script against `port`, and returns `(stdout, stderr,
/// success)`. Shared by both interop tests so the npm/node plumbing lives in one place.
async fn install_and_run_driver(
    project: PathBuf,
    script: &str,
    port: u16,
) -> (String, String, bool) {
    std::fs::create_dir_all(&project).unwrap();
    std::fs::write(project.join("package.json"), PACKAGE_JSON).unwrap();
    std::fs::write(project.join("interop.js"), script).unwrap();

    let install = {
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
        let port = port.to_string();
        tokio::task::spawn_blocking(move || {
            Command::new("node")
                .arg("interop.js")
                .arg(&port)
                .arg(USER)
                .arg(PASSWORD)
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
    let config = config_for(&dir, cert_path, key_path);
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
