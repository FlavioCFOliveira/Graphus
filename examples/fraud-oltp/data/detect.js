'use strict';
//
// detect.js — the fraud-detection workload, driven over Bolt-over-TCP+TLS with the OFFICIAL
// `neo4j-driver` npm package (the exact wire path the Neo4j driver ecosystem uses).
//
// It:
//   1. connects with `bolt+ssc://` (trusts the server's self-signed cert),
//   2. loads the schema DDL + the generated graph (from graph.cypher),
//   3. runs three detection queries — transaction RINGS/CYCLES, MULE fan-in/fan-out accounts, and a
//      VELOCITY (structuring) heuristic — using only Cypher features verified to be supported by the
//      Graphus engine (explicit multi-hop cycle patterns + amount-filtered fan-in/fan-out
//      aggregation),
//   4. asserts the union of detected fraud accounts is EXACTLY the injected ground-truth set
//      (ground_truth.json) — no false negatives on the seeded set; false positives must be zero on
//      this dataset (the amount-floor discriminator separates planted fraud from benign noise).
//
// On full success it prints `GRAPHUS_FRAUD_OK` and exits 0; on any mismatch it prints a clear
// diagnosis and exits 1.
//
// Usage:
//   node detect.js <port> <user> <password> <graph.cypher> <ground_truth.json>

const fs = require('fs');
const neo4j = require('neo4j-driver');

const [, , port, user, password, cypherPath, gtPath] = process.argv;
if (!port || !user || !password || !cypherPath || !gtPath) {
  console.error('usage: node detect.js <port> <user> <password> <graph.cypher> <ground_truth.json>');
  process.exit(2);
}

const uri = `bolt+ssc://127.0.0.1:${port}`;
const toNum = (v) => (neo4j.isInt(v) ? v.toNumber() : v);

// ---- Evidence: per-operation latency sample + nearest-rank percentiles (ms) --------------------
// We time every load statement (a write op) and every detection query, accumulate the latencies,
// and emit them as a machine-readable `GRAPHUS_STATS {json}` line the run.sh harness parses and
// feeds into the standardized evidence report (rmp #253). Instrumentation is read-only timing — it
// never changes a query or an assertion.
const latenciesMs = [];
const hrMs = () => Number(process.hrtime.bigint() / 1000n) / 1000; // sub-ms resolution
async function timed(fn) {
  const t0 = hrMs();
  const out = await fn();
  latenciesMs.push(hrMs() - t0);
  return out;
}
function percentileMs(p) {
  if (latenciesMs.length === 0) return 0;
  const sorted = [...latenciesMs].sort((a, b) => a - b);
  const rank = Math.round(p * (sorted.length - 1));
  return sorted[Math.min(rank, sorted.length - 1)];
}

function fail(msg) {
  console.error('FRAUD DETECTION FAILURE: ' + msg);
  process.exit(1);
}

// Set equality on number arrays (order-independent).
function sameSet(a, b) {
  if (a.length !== b.length) return false;
  const sa = new Set(a);
  for (const x of b) if (!sa.has(x)) return false;
  return true;
}

// Split a .cypher script into individual statements on `;` at end-of-line. Comment lines (`//`)
// are dropped. The schema DDL (CREATE CONSTRAINT / CREATE INDEX) MUST run as auto-commit
// statements — Graphus rejects admin DDL inside an explicit transaction — so we run every statement
// in its own auto-commit `session.run`.
function statements(script) {
  return script
    .split('\n')
    .filter((line) => !line.trimStart().startsWith('//'))
    .join('\n')
    .split(';')
    .map((s) => s.trim())
    .filter((s) => s.length > 0);
}

// Run a read query and collect one integer column into a JS number array.
async function collectIds(driver, query, key) {
  const s = driver.session();
  try {
    const r = await timed(() => s.run(query));
    return r.records.map((rec) => toNum(rec.get(key)));
  } finally {
    await s.close();
  }
}

// Run a query and return its raw records (used for the SHOW INDEXES / SHOW CONSTRAINTS evidence).
async function runRecords(driver, query) {
  const s = driver.session();
  try {
    return (await s.run(query)).records;
  } finally {
    await s.close();
  }
}

// Assert that a write is REJECTED by the schema. The driver observes the rejection as a thrown error;
// if the write is accepted, that is an integrity failure and we fail loudly.
async function expectRejected(driver, desc, stmt) {
  const s = driver.session();
  let rejected = false;
  let message = '';
  try {
    await s.run(stmt);
  } catch (e) {
    rejected = true;
    message = e.code ? `${e.code}` : e.message;
  } finally {
    await s.close();
  }
  if (!rejected) {
    fail(`negative test "${desc}": the write was ACCEPTED but the schema must REJECT it`);
  }
  console.log(`  negative test OK: ${desc} rejected (${message})`);
}

// ---- Detection queries (verified against the real Graphus engine) -------------------------------
//
// RINGS: an explicit 3-hop closed cycle a->b->c->a where every TRANSFER is above the fraud amount
// floor (>= 9000). The amount floor is the discriminator: benign background transfers are < 900, so
// a benign 3-cycle (which can occur by chance) never qualifies. Distinct-node guards exclude
// degenerate self/2-cycles. The result is DISTINCT a.id — every account that participates in a
// fraudulent ring.
const RING_QUERY = `
MATCH (a:Account)-[r1:TRANSFER]->(b:Account)-[r2:TRANSFER]->(c:Account)-[r3:TRANSFER]->(a)
WHERE r1.amount >= 9000 AND r2.amount >= 9000 AND r3.amount >= 9000
  AND a.id <> b.id AND b.id <> c.id AND a.id <> c.id
RETURN DISTINCT a.id AS id ORDER BY id`;

// MULES: an account with large fan-IN (>= 6 distinct sources sending >= 2000) AND large fan-OUT
// (>= 6 distinct destinations receiving >= 2000). The >= 2000 floor again excludes benign noise
// (< 900). Two-stage WITH aggregation: fan-in first, then fan-out on the survivors.
const MULE_QUERY = `
MATCH (m:Account)<-[ri:TRANSFER]-(src:Account) WHERE ri.amount >= 2000
WITH m, count(DISTINCT src) AS fanin
WHERE fanin >= 6
MATCH (m)-[ro:TRANSFER]->(dst:Account) WHERE ro.amount >= 2000
WITH m, fanin, count(DISTINCT dst) AS fanout
WHERE fanout >= 6
RETURN m.id AS id ORDER BY id`;

// VELOCITY (structuring): an account that emits a burst of >= 6 large (>= 2000) outgoing transfers.
// A corroborating signal for mule/structuring behaviour (ordered by total volume). On this dataset
// it independently re-identifies the mule accounts.
const VELOCITY_QUERY = `
MATCH (s:Account)-[t:TRANSFER]->(:Account) WHERE t.amount >= 2000
WITH s, count(t) AS bursts, sum(t.amount) AS volume
WHERE bursts >= 6
RETURN s.id AS id ORDER BY volume DESC, id`;

(async () => {
  const script = fs.readFileSync(cypherPath, 'utf8');
  const gt = JSON.parse(fs.readFileSync(gtPath, 'utf8'));

  const gtRings = gt.rings.flatMap((r) => r.accounts);
  const gtMules = gt.mules.map((m) => m.mule);
  const gtFraud = gt.fraud_accounts;

  const driver = neo4j.driver(uri, neo4j.auth.basic(user, password));
  try {
    await driver.verifyConnectivity();

    // ---- Load the schema + graph. Each statement is its own auto-commit run (mandatory for DDL).
    const stmts = statements(script);
    let loaded = 0;
    for (const stmt of stmts) {
      const s = driver.session();
      try {
        await timed(() => s.run(stmt));
        loaded += 1;
      } catch (e) {
        fail(`load statement #${loaded + 1} failed: ${stmt.slice(0, 120)}\n  ${e.message}`);
      } finally {
        await s.close();
      }
    }
    console.log(`loaded ${loaded} statements (schema + graph)`);

    // ---- Sanity: node/edge counts must match the dataset.
    const acctCount = toNum(
      (await (async () => {
        const s = driver.session();
        try {
          return (await s.run('MATCH (a:Account) RETURN count(a) AS c')).records[0].get('c');
        } finally {
          await s.close();
        }
      })())
    );
    console.log(`accounts loaded: ${acctCount}`);

    // ---- Run detection.
    const ringIds = await collectIds(driver, RING_QUERY, 'id');
    const muleIds = await collectIds(driver, MULE_QUERY, 'id');
    const velocityIds = await collectIds(driver, VELOCITY_QUERY, 'id');

    console.log(`rings detected:    ${JSON.stringify(ringIds)}`);
    console.log(`mules detected:    ${JSON.stringify(muleIds)}`);
    console.log(`velocity detected: ${JSON.stringify(velocityIds)}`);

    // ---- Assert EXACT match against ground truth.
    if (!sameSet(ringIds, gtRings)) {
      fail(`ring accounts mismatch.\n  detected: ${JSON.stringify(ringIds.sort((x, y) => x - y))}\n  expected: ${JSON.stringify([...gtRings].sort((x, y) => x - y))}`);
    }
    if (!sameSet(muleIds, gtMules)) {
      fail(`mule accounts mismatch.\n  detected: ${JSON.stringify(muleIds.sort((x, y) => x - y))}\n  expected: ${JSON.stringify([...gtMules].sort((x, y) => x - y))}`);
    }
    // Velocity must independently flag exactly the mules on this dataset.
    if (!sameSet(velocityIds, gtMules)) {
      fail(`velocity accounts mismatch.\n  detected: ${JSON.stringify(velocityIds.sort((x, y) => x - y))}\n  expected: ${JSON.stringify([...gtMules].sort((x, y) => x - y))}`);
    }

    // ---- The UNION of all detections must equal the full ground-truth fraud set.
    const union = [...new Set([...ringIds, ...muleIds])].sort((x, y) => x - y);
    const expectedAll = [...gtFraud].sort((x, y) => x - y);
    if (!sameSet(union, expectedAll)) {
      fail(`fraud-account union mismatch.\n  detected: ${JSON.stringify(union)}\n  expected: ${JSON.stringify(expectedAll)}`);
    }

    console.log(
      `detection matched ground truth EXACTLY: ${gtRings.length} ring-accounts, ${gtMules.length} mules, ${expectedAll.length} fraud accounts total (0 false positives, 0 false negatives)`
    );

    // ---- TEXT-index investigator query -----------------------------------------------------------
    // An analyst "find every holder whose name contains …" look-up, accelerated by the TEXT index on
    // Customer.name. Customer ids are 0..acctCount-1 (one holder per account), so the expected match
    // set is derivable deterministically without the dataset file.
    const nameSubstr = 'customer-1';
    const expectedHolders = [];
    for (let id = 0; id < acctCount; id++) {
      if (`customer-${id}`.includes(nameSubstr)) expectedHolders.push(id);
    }
    const foundHolders = await collectIds(
      driver,
      `MATCH (c:Customer) WHERE c.name CONTAINS '${nameSubstr}' RETURN c.id AS id`,
      'id'
    );
    if (!sameSet(foundHolders, expectedHolders)) {
      fail(
        `name CONTAINS '${nameSubstr}' mismatch.\n  detected(${foundHolders.length}): ${JSON.stringify(foundHolders.sort((x, y) => x - y))}\n  expected(${expectedHolders.length}): ${JSON.stringify(expectedHolders)}`
      );
    }
    console.log(`name CONTAINS '${nameSubstr}': ${foundHolders.length} holders (matches expected — TEXT index path)`);

    // ---- Negative integrity tests: the schema must REJECT bad writes -----------------------------
    // A duplicate Account.id (NODE KEY) and a null-amount TRANSFER (relationship existence) must both
    // be rejected; the driver observes each rejection as a thrown error.
    console.log('negative integrity tests (the schema must reject these):');
    await expectRejected(
      driver,
      'duplicate Account.id (NODE KEY)',
      "CREATE (:Account {id: 0, holder: 0, balance: 1, risk_score: 1, opened_ts: 1, country: 'PT'})"
    );
    await expectRejected(
      driver,
      'null-amount TRANSFER (relationship existence)',
      "MATCH (a:Account {id: 0}), (b:Account {id: 1}) CREATE (a)-[:TRANSFER {ts: 1, device: 1, ip: '10.0.0.1'}]->(b)"
    );

    // ---- Schema evidence: capture SHOW INDEXES + SHOW CONSTRAINTS --------------------------------
    // Emitted between machine-readable markers so run.sh can persist the listing into the evidence
    // dir, plus a `GRAPHUS_SCHEMA {json}` counts line the harness harvests.
    const idxRecords = await runRecords(driver, 'SHOW INDEXES');
    const consRecords = await runRecords(driver, 'SHOW CONSTRAINTS');
    const cell = (rec, key) => {
      if (!rec.keys.includes(key)) return null;
      const v = rec.get(key);
      return Array.isArray(v) ? v.map(toNum) : toNum(v);
    };
    console.log('GRAPHUS_SCHEMA_BEGIN');
    console.log('INDEXES:');
    for (const rec of idxRecords) {
      console.log(
        `  ${JSON.stringify({ name: cell(rec, 'name'), type: cell(rec, 'type'), entityType: cell(rec, 'entityType'), labelsOrTypes: cell(rec, 'labelsOrTypes'), properties: cell(rec, 'properties'), state: cell(rec, 'state') })}`
      );
    }
    console.log('CONSTRAINTS:');
    for (const rec of consRecords) {
      console.log(
        `  ${JSON.stringify({ name: cell(rec, 'name'), type: cell(rec, 'type'), entityType: cell(rec, 'entityType'), properties: cell(rec, 'properties'), propertyType: cell(rec, 'propertyType') })}`
      );
    }
    console.log('GRAPHUS_SCHEMA_END');

    // Assert the new index & constraint kinds are actually declared (fail loudly if not).
    const idxByName = new Map(idxRecords.map((r) => [r.get('name'), r]));
    const consByName = new Map(consRecords.map((r) => [r.get('name'), r]));
    const requireIndex = (name, type) => {
      const r = idxByName.get(name);
      if (!r) fail(`SHOW INDEXES is missing the '${name}' index`);
      if (r.get('type') !== type) fail(`index '${name}' should be ${type}, got ${r.get('type')}`);
    };
    const requireConstraint = (name, type) => {
      const r = consByName.get(name);
      if (!r) fail(`SHOW CONSTRAINTS is missing the '${name}' constraint`);
      if (r.get('type') !== type) fail(`constraint '${name}' should be ${type}, got ${r.get('type')}`);
    };
    requireIndex('transfer_amount_range', 'RANGE');
    requireIndex('customer_name_text', 'TEXT');
    requireConstraint('account_id_key', 'NODE_KEY');
    requireConstraint('transfer_amount_exists', 'RELATIONSHIP_PROPERTY_EXISTENCE');
    requireConstraint('transfer_amount_integer', 'RELATIONSHIP_PROPERTY_TYPE');
    console.log(
      `GRAPHUS_SCHEMA ${JSON.stringify({ indexes: idxRecords.length, constraints: consRecords.length })}`
    );
    // Machine-readable evidence for the run.sh harness: operation count + latency percentiles (ms).
    const stats = {
      load_statements: loaded,
      accounts_loaded: acctCount,
      operations: latenciesMs.length,
      p50_ms: percentileMs(0.5),
      p99_ms: percentileMs(0.99),
      p999_ms: percentileMs(0.999),
    };
    console.log('GRAPHUS_STATS ' + JSON.stringify(stats));
    console.log('GRAPHUS_FRAUD_OK');
    process.exit(0);
  } catch (err) {
    fail(err && err.stack ? err.stack : String(err));
  } finally {
    await driver.close();
  }
})();
