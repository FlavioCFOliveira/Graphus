'use strict';
//
// detect.js — the fraud-detection + OLTP workload, driven over Bolt (TCP+TLS or the target's Bolt
// endpoint) with the OFFICIAL `neo4j-driver` npm package (the exact wire path the Neo4j driver
// ecosystem uses).
//
// It runs against EITHER a locally self-booted server (default DB) OR an already-running instance —
// local or remote — into a dedicated, isolated database the run.sh harness carved out
// (session `{database}` routing). It:
//   1. connects to <uri> (`bolt+ssc://…`, trusting a self-signed cert),
//   2. (idempotency) clears any prior Account/Customer footprint so a REUSED database starts clean,
//   3. loads the schema DDL BEST-EFFORT (a target may be an older Graphus that rejects the newer
//      relationship-constraint / named-index / TEXT-index forms — those are recorded as
//      "unsupported by target" and skipped; the essential node constraints are created everywhere),
//      timing every TRANSFER insert against the cumulative edge count to surface the scan-based
//      RELATIONSHIP KEY O(E) cost (rmp #683),
//   4. runs the fraud detection — transaction RINGS/CYCLES, MULE fan-in/fan-out, VELOCITY (structuring)
//      — and asserts the union equals the injected ground truth EXACTLY (0 FP, 0 FN),
//   5. runs a SHARED-DEVICE / SHARED-IP collusion detection (the generated device/ip fields) and
//      asserts it re-identifies EXACTLY the planted collusion clusters,
//   6. runs a blended point-lookup OLTP mix — account-by-id (a NODE KEY point read) and a
//      recent-transfers statement-of-account read,
//   7. runs the constraint negative tests GATED on which constraints the target actually created.
//
// On full success it prints `GRAPHUS_FRAUD_OK` and exits 0; on any mismatch it exits 1.
//
// Usage:
//   node detect.js <uri> <database> <user> <password> <graph.cypher> <ground_truth.json>
//     <database> may be empty ("") to use the connection's default database (local self-boot).

const fs = require('fs');
const neo4j = require('neo4j-driver');

const [, , uri, database, user, password, cypherPath, gtPath] = process.argv;
if (!uri || user === undefined || !password || !cypherPath || !gtPath) {
  console.error('usage: node detect.js <uri> <database> <user> <password> <graph.cypher> <ground_truth.json>');
  process.exit(2);
}
// `database` is optional: an empty string means "the connection default DB" (local self-boot).
const sessionOpts = (extra) => Object.assign(database ? { database } : {}, extra || {});
const toNum = (v) => (neo4j.isInt(v) ? v.toNumber() : v);

// ---- Evidence: per-operation latency sample + nearest-rank percentiles (ms) --------------------
const latenciesMs = [];
const hrMs = () => Number(process.hrtime.bigint() / 1000n) / 1000; // sub-ms resolution
async function timed(fn) {
  const t0 = hrMs();
  const out = await fn();
  latenciesMs.push(hrMs() - t0);
  return out;
}
function percentileMs(samples, p) {
  if (samples.length === 0) return 0;
  const sorted = [...samples].sort((a, b) => a - b);
  const rank = Math.round(p * (sorted.length - 1));
  return Number(sorted[Math.min(rank, sorted.length - 1)].toFixed(4));
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

// Split a .cypher script into individual statements on `;` at end-of-line, dropping `//` comment
// lines. Every statement runs as its own auto-commit `session.run` (schema DDL MUST be auto-commit).
function statements(script) {
  return script
    .split('\n')
    .filter((line) => !line.trimStart().startsWith('//'))
    .join('\n')
    .split(';')
    .map((s) => s.trim())
    .filter((s) => s.length > 0);
}

// Is a statement schema DDL (a CREATE CONSTRAINT / CREATE [<kind>] INDEX)? If so, extract its name.
const SCHEMA_DDL = /^CREATE\s+(?:CONSTRAINT|(?:RANGE|TEXT|POINT|FULLTEXT|VECTOR|LOOKUP)?\s*INDEX)\s+([A-Za-z_][A-Za-z0-9_]*)\b/i;
function schemaName(stmt) {
  const m = stmt.match(SCHEMA_DDL);
  return m ? m[1] : null;
}
// A DDL rejection meaning "the object already exists" (idempotent re-create on a reused DB) — treat
// as present rather than a failure.
function isAlreadyExists(e) {
  const s = `${e.code || ''} ${e.message || ''}`.toLowerCase();
  return s.includes('already exists') || s.includes('equivalent') || s.includes('constraint already');
}
// A DDL rejection meaning "this target's version does not support this DDL form" (an older Graphus).
function isUnsupportedDdl(e) {
  return `${e.code || ''}`.includes('SyntaxError');
}

// Run a read query and collect one integer column into a JS number array.
async function collectIds(driver, query, key, params) {
  const s = driver.session(sessionOpts());
  try {
    const r = await timed(() => s.run(query, params || {}));
    return r.records.map((rec) => toNum(rec.get(key)));
  } finally {
    await s.close();
  }
}

// Run a query and return its raw records.
async function runRecords(driver, query, params) {
  const s = driver.session(sessionOpts());
  try {
    return (await s.run(query, params || {})).records;
  } finally {
    await s.close();
  }
}

// Assert that a write is REJECTED by the schema (the driver observes a thrown error).
async function expectRejected(driver, desc, stmt) {
  const s = driver.session(sessionOpts());
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
const RING_QUERY = `
MATCH (a:Account)-[r1:TRANSFER]->(b:Account)-[r2:TRANSFER]->(c:Account)-[r3:TRANSFER]->(a)
WHERE r1.amount >= 9000 AND r2.amount >= 9000 AND r3.amount >= 9000
  AND a.id <> b.id AND b.id <> c.id AND a.id <> c.id
RETURN DISTINCT a.id AS id ORDER BY id`;

const MULE_QUERY = `
MATCH (m:Account)<-[ri:TRANSFER]-(src:Account) WHERE ri.amount >= 2000
WITH m, count(DISTINCT src) AS fanin
WHERE fanin >= 6
MATCH (m)-[ro:TRANSFER]->(dst:Account) WHERE ro.amount >= 2000
WITH m, fanin, count(DISTINCT dst) AS fanout
WHERE fanout >= 6
RETURN m.id AS id ORDER BY id`;

const VELOCITY_QUERY = `
MATCH (s:Account)-[t:TRANSFER]->(:Account) WHERE t.amount >= 2000
WITH s, count(t) AS bursts, sum(t.amount) AS volume
WHERE bursts >= 6
RETURN s.id AS id ORDER BY volume DESC, id`;

// SHARED-DEVICE collusion: any device fingerprint used by >= 2 transfers is a planted cluster (every
// benign transfer carries a UNIQUE device, so it never groups). Returns device + edge count.
const COLLUSION_DEVICE_QUERY = `
MATCH ()-[t:TRANSFER]->()
WITH t.device AS device, count(*) AS edges
WHERE edges >= 2
RETURN device, edges ORDER BY device`;

(async () => {
  const script = fs.readFileSync(cypherPath, 'utf8');
  const gt = JSON.parse(fs.readFileSync(gtPath, 'utf8'));

  const gtRings = gt.rings.flatMap((r) => r.accounts);
  const gtMules = gt.mules.map((m) => m.mule);
  const gtFraud = gt.fraud_accounts;
  const gtCollusion = gt.collusion || [];

  const driver = neo4j.driver(uri, neo4j.auth.basic(user, password));
  const createdSchema = new Set(); // names of constraints/indexes actually present on the target
  const unsupportedSchema = []; // DDL the target's version rejected (older Graphus)
  const txInsertCurve = []; // {e: cumulativeTransferCount, ms} per TRANSFER insert (rmp #683)

  try {
    await driver.verifyConnectivity();
    console.log(`connected to ${uri}${database ? ` database='${database}'` : ' (default database)'}`);

    // ---- Idempotency: clear any prior fraud-oltp footprint so a REUSED database starts clean.
    for (const label of ['Account', 'Customer']) {
      const s = driver.session(sessionOpts());
      try {
        await s.run(`MATCH (n:${label}) DETACH DELETE n`);
      } catch (_) {
        /* empty/isolated DB — nothing to clear */
      } finally {
        await s.close();
      }
    }

    // ---- Load the schema + graph. Schema DDL is BEST-EFFORT (older targets reject the newer forms);
    // data statements are mandatory. Every statement is its own auto-commit run.
    const stmts = statements(script);
    let loaded = 0;
    let edgeCount = 0;
    for (const stmt of stmts) {
      const ddlName = schemaName(stmt);
      const s = driver.session(sessionOpts());
      try {
        if (ddlName) {
          // Schema DDL: tolerate "already exists" (reused DB) and "unsupported" (older target).
          try {
            await timed(() => s.run(stmt));
            createdSchema.add(ddlName);
          } catch (e) {
            if (isAlreadyExists(e)) {
              createdSchema.add(ddlName);
            } else if (isUnsupportedDdl(e)) {
              unsupportedSchema.push(ddlName);
              console.log(`  schema: '${ddlName}' unsupported by target (${e.code}) — skipped`);
            } else {
              throw e;
            }
          }
        } else {
          // Data statement (mandatory). Time TRANSFER inserts against the cumulative edge count.
          const isTransfer = /\[:TRANSFER\s*\{/.test(stmt);
          const t0 = hrMs();
          await s.run(stmt);
          const dt = hrMs() - t0;
          latenciesMs.push(dt);
          if (isTransfer) {
            edgeCount += 1;
            txInsertCurve.push({ e: edgeCount, ms: dt });
          }
        }
        loaded += 1;
      } catch (e) {
        fail(`load statement #${loaded + 1} failed: ${stmt.slice(0, 120)}\n  ${e.message}`);
      } finally {
        await s.close();
      }
    }
    console.log(
      `loaded ${loaded} statements; schema created=[${[...createdSchema].join(', ') || 'none'}]` +
        (unsupportedSchema.length ? ` unsupported=[${unsupportedSchema.join(', ')}]` : '')
    );

    // ---- Sanity: node count.
    const acctCount = toNum(
      (await runRecords(driver, 'MATCH (a:Account) RETURN count(a) AS c'))[0].get('c')
    );
    console.log(`accounts loaded: ${acctCount}`);
    if (acctCount === 0) fail('no Account nodes were loaded — the data load did not reach the target');

    // ---- Fraud detection.
    const ringIds = await collectIds(driver, RING_QUERY, 'id');
    const muleIds = await collectIds(driver, MULE_QUERY, 'id');
    const velocityIds = await collectIds(driver, VELOCITY_QUERY, 'id');
    console.log(`rings detected:    ${JSON.stringify(ringIds)}`);
    console.log(`mules detected:    ${JSON.stringify(muleIds)}`);
    console.log(`velocity detected: ${JSON.stringify(velocityIds)}`);

    if (!sameSet(ringIds, gtRings)) {
      fail(`ring accounts mismatch.\n  detected: ${JSON.stringify(ringIds.sort((x, y) => x - y))}\n  expected: ${JSON.stringify([...gtRings].sort((x, y) => x - y))}`);
    }
    if (!sameSet(muleIds, gtMules)) {
      fail(`mule accounts mismatch.\n  detected: ${JSON.stringify(muleIds.sort((x, y) => x - y))}\n  expected: ${JSON.stringify([...gtMules].sort((x, y) => x - y))}`);
    }
    if (!sameSet(velocityIds, gtMules)) {
      fail(`velocity accounts mismatch.\n  detected: ${JSON.stringify(velocityIds.sort((x, y) => x - y))}\n  expected: ${JSON.stringify([...gtMules].sort((x, y) => x - y))}`);
    }
    const union = [...new Set([...ringIds, ...muleIds])].sort((x, y) => x - y);
    const expectedAll = [...gtFraud].sort((x, y) => x - y);
    if (!sameSet(union, expectedAll)) {
      fail(`fraud-account union mismatch.\n  detected: ${JSON.stringify(union)}\n  expected: ${JSON.stringify(expectedAll)}`);
    }
    console.log(
      `detection matched ground truth EXACTLY: ${gtRings.length} ring-accounts, ${gtMules.length} mules, ${expectedAll.length} fraud accounts (0 FP, 0 FN)`
    );

    // ---- SHARED-DEVICE / SHARED-IP collusion detection (the generated device/ip fields) ---------
    // Every benign transfer carries a unique device, every fraud cluster shares one device+IP; so a
    // group-by-device count>=2 re-identifies EXACTLY the planted collusion clusters.
    const collusionRows = await runRecords(driver, COLLUSION_DEVICE_QUERY);
    const detectedCollusion = collusionRows
      .map((r) => ({ device: toNum(r.get('device')), edges: toNum(r.get('edges')) }))
      .sort((a, b) => a.device - b.device);
    const expectedCollusion = [...gtCollusion]
      .map((c) => ({ device: c.device, edges: c.edge_count }))
      .sort((a, b) => a.device - b.device);
    console.log(`shared-device clusters detected: ${JSON.stringify(detectedCollusion)}`);
    if (JSON.stringify(detectedCollusion) !== JSON.stringify(expectedCollusion)) {
      fail(
        `collusion mismatch.\n  detected: ${JSON.stringify(detectedCollusion)}\n  expected: ${JSON.stringify(expectedCollusion)}`
      );
    }
    // Corroborate by shared IP: the fraud clusters use the disjoint 172.16/172.17 space.
    const fraudIps = toNum(
      (await runRecords(driver, "MATCH ()-[t:TRANSFER]->() WHERE t.ip STARTS WITH '172.' RETURN count(DISTINCT t.ip) AS n"))[0].get('n')
    );
    if (fraudIps !== expectedCollusion.length) {
      fail(`shared-IP collusion mismatch: ${fraudIps} distinct 172.x IPs, expected ${expectedCollusion.length}`);
    }
    console.log(
      `collusion matched ground truth EXACTLY: ${expectedCollusion.length} shared-device clusters, ${fraudIps} shared-IP clusters`
    );

    // ---- Blended point-lookup OLTP mix ----------------------------------------------------------
    // account-by-id: a NODE KEY point read (the bread-and-butter OLTP lookup). Probe a fraud account,
    // a benign account, and a definitely-absent id.
    const oltpLat = [];
    const pointLookup = async (id) => {
      const s = driver.session(sessionOpts({ defaultAccessMode: neo4j.session.READ }));
      try {
        const t0 = hrMs();
        const r = await s.run('MATCH (a:Account {id: $id}) RETURN a.id AS id, a.balance AS bal, a.risk_score AS risk', { id: neo4j.int(id) });
        oltpLat.push(hrMs() - t0);
        latenciesMs.push(oltpLat[oltpLat.length - 1]);
        return r.records.length;
      } finally {
        await s.close();
      }
    };
    const probeIds = [gtFraud[0], 0, acctCount + 100000];
    const hits = [];
    for (const id of probeIds) hits.push(await pointLookup(id));
    if (hits[0] !== 1 || hits[1] !== 1 || hits[2] !== 0) {
      fail(`point-lookup account-by-id wrong cardinality: existing ids must return 1, absent id 0 — got ${JSON.stringify(hits)}`);
    }
    // recent-transfers: a mule's statement-of-account (its most recent outgoing transfers by ts).
    const mule = gtMules[0];
    const recent = await runRecords(
      driver,
      'MATCH (a:Account {id: $id})-[t:TRANSFER]->(b:Account) RETURN t.tx_id AS tx, t.amount AS amt, t.ts AS ts, b.id AS dst ORDER BY t.ts DESC LIMIT 10',
      { id: neo4j.int(mule) }
    );
    if (recent.length === 0) {
      fail(`recent-transfers for mule ${mule} returned no rows (the mule must have outgoing transfers)`);
    }
    console.log(
      `OLTP point-lookups OK: account-by-id ${probeIds.length} probes (${hits.join('/')} rows), recent-transfers(mule ${mule}) = ${recent.length} rows`
    );

    // ---- TEXT-index investigator query (substring by name) — works with or without the TEXT index.
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
        `name CONTAINS '${nameSubstr}' mismatch.\n  detected(${foundHolders.length})\n  expected(${expectedHolders.length})`
      );
    }
    console.log(
      `name CONTAINS '${nameSubstr}': ${foundHolders.length} holders` +
        (createdSchema.has('customer_name_text') ? ' (TEXT index path)' : ' (scan path — TEXT index unsupported by target)')
    );

    // ---- Negative integrity tests — GATED on which constraints the target actually created. ------
    console.log('negative integrity tests (only for constraints the target created):');
    if (createdSchema.has('account_id_key')) {
      await expectRejected(
        driver,
        'duplicate Account.id (NODE KEY)',
        "CREATE (:Account {id: 0, holder: 0, balance: 1, risk_score: 1, opened_ts: 1, country: 'PT'})"
      );
    }
    if (createdSchema.has('transfer_amount_exists')) {
      await expectRejected(
        driver,
        'null-amount TRANSFER (relationship existence)',
        "MATCH (a:Account {id: 0}), (b:Account {id: 1}) CREATE (a)-[:TRANSFER {tx_id: 'TX-NEG-EXISTS', ts: 1, device: 1, ip: '10.0.0.1'}]->(b)"
      );
    }
    if (createdSchema.has('transfer_tx_id_key')) {
      const anyTx = (await runRecords(driver, 'MATCH ()-[t:TRANSFER]->() RETURN t.tx_id AS tx LIMIT 1'))[0].get('tx');
      await expectRejected(
        driver,
        `duplicate TRANSFER.tx_id (RELATIONSHIP KEY, id='${anyTx}')`,
        `MATCH (a:Account {id: 0}), (b:Account {id: 1}) CREATE (a)-[:TRANSFER {tx_id: '${anyTx}', amount: 5000, ts: 1, device: 1, ip: '10.0.0.1'}]->(b)`
      );
      await expectRejected(
        driver,
        'missing TRANSFER.tx_id (RELATIONSHIP KEY, present half)',
        "MATCH (a:Account {id: 0}), (b:Account {id: 1}) CREATE (a)-[:TRANSFER {amount: 5000, ts: 1, device: 1, ip: '10.0.0.1'}]->(b)"
      );
    }
    const skippedNegatives = ['transfer_amount_exists', 'transfer_tx_id_key'].filter((n) => !createdSchema.has(n));
    if (skippedNegatives.length) {
      console.log(`  (skipped negatives whose constraint the target does not support: ${skippedNegatives.join(', ')})`);
    }

    // ---- Schema evidence: capture SHOW INDEXES + SHOW CONSTRAINTS (columns vary by version). ------
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
      console.log(`  ${JSON.stringify({ name: cell(rec, 'name'), type: cell(rec, 'type'), entityType: cell(rec, 'entityType'), labelsOrTypes: cell(rec, 'labelsOrTypes'), label: cell(rec, 'label'), properties: cell(rec, 'properties'), property: cell(rec, 'property'), state: cell(rec, 'state') })}`);
    }
    console.log('CONSTRAINTS:');
    for (const rec of consRecords) {
      console.log(`  ${JSON.stringify({ name: cell(rec, 'name'), type: cell(rec, 'type'), entityType: cell(rec, 'entityType'), properties: cell(rec, 'properties'), propertyType: cell(rec, 'propertyType') })}`);
    }
    console.log('GRAPHUS_SCHEMA_END');

    // Strict kind assertions GATED on what the target created (full set locally; a subset on an older
    // target). We only assert a kind when its object was actually created, so the example adapts.
    const idxByName = new Map(idxRecords.filter((r) => r.keys.includes('name')).map((r) => [r.get('name'), r]));
    const consByName = new Map(consRecords.filter((r) => r.keys.includes('name')).map((r) => [r.get('name'), r]));
    const requireIfCreated = (map, name, kindKey, kind) => {
      if (!createdSchema.has(name)) return;
      const r = map.get(name);
      if (!r) return; // older SHOW without a name column — cannot cross-check, don't fail
      if (r.keys.includes(kindKey) && r.get(kindKey) !== kind) {
        fail(`${name} should be ${kind}, got ${r.get(kindKey)}`);
      }
    };
    requireIfCreated(idxByName, 'transfer_amount_range', 'type', 'RANGE');
    requireIfCreated(idxByName, 'customer_name_text', 'type', 'TEXT');
    requireIfCreated(consByName, 'account_id_key', 'type', 'NODE_KEY');
    requireIfCreated(consByName, 'transfer_amount_exists', 'type', 'RELATIONSHIP_PROPERTY_EXISTENCE');
    requireIfCreated(consByName, 'transfer_amount_integer', 'type', 'RELATIONSHIP_PROPERTY_TYPE');
    requireIfCreated(consByName, 'transfer_tx_id_key', 'type', 'RELATIONSHIP_KEY');
    // The NODE KEY works on every supported target — assert it is present regardless.
    if (!createdSchema.has('account_id_key')) {
      fail('the Account.id NODE KEY must be creatable on any supported target');
    }
    console.log(`GRAPHUS_SCHEMA ${JSON.stringify({ indexes: idxRecords.length, constraints: consRecords.length, created: createdSchema.size, unsupported: unsupportedSchema.length })}`);

    // Per-TRANSFER insert latency vs cumulative edge count, bucketed into ~10 windows (rmp #683). On a
    // target that enforces the RELATIONSHIP KEY the scan-based uniqueness check makes later inserts
    // dearer; on a target that lacks it the curve is flat — the report shows the contrast honestly.
    const curve = [];
    if (txInsertCurve.length > 0) {
      const nb = Math.min(10, txInsertCurve.length);
      const per = Math.ceil(txInsertCurve.length / nb);
      for (let i = 0; i < txInsertCurve.length; i += per) {
        const win = txInsertCurve.slice(i, i + per);
        curve.push({
          upto_edges: win[win.length - 1].e,
          n: win.length,
          p50_ms: percentileMs(win.map((w) => w.ms), 0.5),
          p99_ms: percentileMs(win.map((w) => w.ms), 0.99),
        });
      }
    }
    console.log('GRAPHUS_TXCURVE ' + JSON.stringify({ rel_key_enforced: createdSchema.has('transfer_tx_id_key'), buckets: curve }));

    // Machine-readable evidence for the run.sh harness: operation count + latency percentiles (ms).
    //
    // `workload_secs` is the window the `operations` were ACTUALLY issued in — the summed wall-time of
    // the measured operations themselves. This driver is serial (one op at a time on one session), so
    // that sum IS the wall-clock spent executing them, and `operations / workload_secs` is therefore a
    // real achieved rate. Without it, run.sh had to divide the detection ops by the WHOLE workload
    // window (load + detect + the concurrency phase), which silently understated ops/sec by mixing two
    // different windows (rmp #699).
    const workloadSecs = latenciesMs.reduce((a, b) => a + b, 0) / 1000;
    const stats = {
      load_statements: loaded,
      accounts_loaded: acctCount,
      schema_created: createdSchema.size,
      schema_unsupported: unsupportedSchema.length,
      operations: latenciesMs.length,
      workload_secs: workloadSecs,
      point_lookup_p50_ms: percentileMs(oltpLat, 0.5),
      point_lookup_p99_ms: percentileMs(oltpLat, 0.99),
      p50_ms: percentileMs(latenciesMs, 0.5),
      p99_ms: percentileMs(latenciesMs, 0.99),
      p999_ms: percentileMs(latenciesMs, 0.999),
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
