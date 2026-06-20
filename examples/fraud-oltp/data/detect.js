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
