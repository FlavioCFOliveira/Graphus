'use strict';
//
// concurrency.js — the EXTREME-CONCURRENCY SSI driver, over Bolt with the OFFICIAL `neo4j-driver`.
//
// It contends on the REAL mule :Account supernodes of the loaded fraud graph (the highest-degree
// nodes — the fan-in/fan-out hubs), NOT synthetic :Hot nodes. Many overlapping transactions from a
// configurable number of concurrent clients all read-modify-write the mule-account balances and
// ingest a fresh deposit edge, provoking Serializable-Snapshot-Isolation (SSI) conflicts:
//   - WRITER clients: in ONE explicit transaction, read a mule's balance, SET it += delta, and CREATE
//     a `CONC-`tagged incoming TRANSFER {amount: delta} (a "structured deposit"). The balance SET and
//     the edge are written atomically, so the edge sum is an ambiguity-proof oracle for no-lost-update.
//   - READER clients: mule statement-of-account aggregation reads, concurrently with the writers.
//
// It captures commit/abort outcomes and the WRITE-commit latency p99, and verifies the SSI safety
// invariant: for each mule, final_balance == initial_balance + sum(amount over its CONC- deposit
// edges) — a lost update would break this equality.
//
// The abort rate is a FIRST-CLASS signal: contending this hard on so few supernodes is EXPECTED to
// abort heavily (the finding, not a defect), so we assert it lands inside a tight, documented band —
// high enough to prove SSI genuinely fired, low enough to prove writers still made progress.
//
// On success it prints the tallies + `GRAPHUS_CONCURRENCY_OK`, exiting 0; on a lost update, a
// livelock, or contention that never fired it exits 1.
//
// Usage:
//   node concurrency.js <uri> <database> <user> <password> <ground_truth.json> [clients] [ops] [mules]

const fs = require('fs');
const neo4j = require('neo4j-driver');

const [, , uri, database, user, password, gtPath, clientsArg, opsArg, mulesArg] = process.argv;
if (!uri || user === undefined || !password || !gtPath) {
  console.error('usage: node concurrency.js <uri> <database> <user> <password> <ground_truth.json> [clients] [ops] [mules]');
  process.exit(2);
}
const CLIENTS = parseInt(clientsArg || '12', 10);
const OPS = parseInt(opsArg || '30', 10);

// The abort-rate band: a FIRST-CLASS, two-sided, documented sanity gate (replacing the old
// never-firing +/-0.50 baseline band). Deliberately over-contending a couple of :Account supernodes
// under SSI is EXPECTED to abort the large majority of writers — that is the finding, not a defect.
// Measured on pi516 (2 mule supernodes): 5 writers -> ~0.77, 6 -> ~0.87, 9 -> ~0.95; a target that
// also enforces the scan-based RELATIONSHIP KEY (enlarging every writer's read set) aborts even more.
//   FLOOR: SSI must GENUINELY fire — an abort rate this low would mean contention never materialised
//          (a misconfiguration or an SSI regression that could mask lost updates). We always see
//          >= 0.77, so 0.40 leaves generous headroom while still catching a real anomaly.
//   CEIL : writers must still make PROGRESS — above this is a near-total livelock (< 0.5% commit). We
//          always see ~5% commits, so 0.995 catches only a genuine write-liveness collapse.
// Both bounds are overridable via FRAUD_ABORT_FLOOR / FRAUD_ABORT_CEIL for a differently-sized target.
const ABORT_FLOOR = parseFloat(process.env.FRAUD_ABORT_FLOOR || '0.40');
const ABORT_CEIL = parseFloat(process.env.FRAUD_ABORT_CEIL || '0.995');

const sessionOpts = (extra) => Object.assign(database ? { database } : {}, extra || {});
const int = (n) => neo4j.int(n);
const toNum = (v) => (neo4j.isInt(v) ? v.toNumber() : v);

function fail(msg) {
  console.error('CONCURRENCY FAILURE: ' + msg);
  process.exit(1);
}
function percentileMs(samples, p) {
  if (samples.length === 0) return 0;
  const sorted = [...samples].sort((a, b) => a - b);
  const rank = Math.round(p * (sorted.length - 1));
  return Number(sorted[Math.min(rank, sorted.length - 1)].toFixed(4));
}
const hrMs = () => Number(process.hrtime.bigint() / 1000n) / 1000;

// Deterministic-ish per-client PRNG (the wire schedule is still non-deterministic; for the
// byte-deterministic repro use the in-process `dst_contention` binary).
function lcg(seed) {
  let s = seed >>> 0;
  return () => {
    s = (Math.imul(s, 1664525) + 1013904223) >>> 0;
    return s;
  };
}

(async () => {
  const gt = JSON.parse(fs.readFileSync(gtPath, 'utf8'));
  let mules = gt.mules.map((m) => m.mule);
  if (mulesArg) mules = mules.slice(0, Math.max(1, parseInt(mulesArg, 10)));
  if (mules.length === 0) fail('ground truth has no mule accounts to contend on');

  const driver = neo4j.driver(uri, neo4j.auth.basic(user, password), {
    maxConnectionPoolSize: CLIENTS + 4,
  });
  try {
    await driver.verifyConnectivity();
    console.log(`connected to ${uri}${database ? ` database='${database}'` : ' (default database)'}`);

    // ---- Snapshot the mules' INITIAL balances (the graph is already loaded by detect.js).
    const initial = new Map();
    for (const m of mules) {
      const s = driver.session(sessionOpts({ defaultAccessMode: neo4j.session.READ }));
      try {
        const r = await s.run('MATCH (a:Account {id: $id}) RETURN a.balance AS b', { id: int(m) });
        if (r.records.length === 0) fail(`mule account ${m} not found — was the graph loaded?`);
        initial.set(m, toNum(r.records[0].get('b')));
      } finally {
        await s.close();
      }
    }
    console.log(`contending on ${mules.length} REAL mule supernode(s): ${JSON.stringify(mules)}`);

    let commits = 0;
    let aborts = 0;
    let readOps = 0;
    const writeCommitMs = [];

    // WRITER: OPS explicit transactions, each a read-modify-write on a chosen mule balance PLUS a
    // `CONC-`tagged deposit edge into it (atomic in the same tx). A single explicit tx per op so an
    // SSI abort is observed, not hidden by driver retry.
    async function writer(clientId) {
      const rnd = lcg(0x9e3779b9 ^ (clientId * 2654435761));
      for (let op = 0; op < OPS; op++) {
        const mule = mules[rnd() % mules.length];
        const delta = 1 + (rnd() % 100);
        const s = driver.session(sessionOpts());
        const tx = s.beginTransaction();
        const t0 = hrMs();
        try {
          const r = await tx.run('MATCH (m:Account {id: $id}) RETURN m.balance AS b', { id: int(mule) });
          const cur = toNum(r.records[0].get('b'));
          await tx.run('MATCH (m:Account {id: $id}) SET m.balance = $v', { id: int(mule), v: int(cur + delta) });
          // The atomic deposit edge (unique tx_id — satisfies a RELATIONSHIP KEY where one exists; the
          // CONC- prefix keeps it out of the loaded fraud set and makes it the no-lost-update oracle).
          await tx.run(
            'MATCH (src:Account {id: 0}), (m:Account {id: $id}) ' +
              'CREATE (src)-[:TRANSFER {tx_id: $tx, amount: $amt, ts: 0, device: -1, ip: $ip, conc: true}]->(m)',
            { id: int(mule), amt: int(delta), tx: `CONC-${clientId}-${op}`, ip: '172.31.0.1' }
          );
          await tx.commit();
          commits += 1;
          writeCommitMs.push(hrMs() - t0);
        } catch (e) {
          // SSI serialization conflict / transient → abort (the EXPECTED, bounded outcome). We do NOT
          // accumulate a client-side "committed delta" (a failed commit is ambiguous over the wire);
          // the no-lost-update oracle is verified from the graph below.
          aborts += 1;
          try {
            await tx.rollback();
          } catch (_) {
            /* already rolled back by the server */
          }
        } finally {
          await s.close();
        }
      }
    }

    // READER: mule statement-of-account aggregation, concurrent with the writers.
    async function reader() {
      for (let op = 0; op < OPS; op++) {
        const s = driver.session(sessionOpts({ defaultAccessMode: neo4j.session.READ }));
        try {
          await s.run(
            'MATCH (m:Account)<-[t:TRANSFER]-(:Account) WHERE m.id IN $mules ' +
              'RETURN m.id AS id, count(t) AS c, sum(t.amount) AS v ORDER BY v DESC',
            { mules: mules.map(int) }
          );
          readOps += 1;
        } catch (_) {
          /* a read aborting under SSI is fine; count loosely */
        } finally {
          await s.close();
        }
      }
    }

    const writers = Math.max(1, Math.ceil(CLIENTS * 0.75));
    const readers = Math.max(1, CLIENTS - writers);
    const tasks = [];
    for (let i = 0; i < writers; i++) tasks.push(writer(i));
    for (let i = 0; i < readers; i++) tasks.push(reader());
    await Promise.all(tasks);

    // ---- Verify NO-LOST-UPDATE from the graph itself (ambiguity-proof). For each mule the balance
    // SET and the deposit edge are atomic, so final_balance MUST equal initial_balance + sum(amount)
    // over its CONC- deposit edges. A lost update (a SET without its edge, or vice-versa) breaks it.
    const mismatches = [];
    for (const m of mules) {
      const s = driver.session(sessionOpts({ defaultAccessMode: neo4j.session.READ }));
      try {
        const r = await s.run(
          'MATCH (m:Account {id: $id}) ' +
            'OPTIONAL MATCH ()-[t:TRANSFER]->(m) WHERE t.tx_id STARTS WITH "CONC-" ' +
            'RETURN m.balance AS b, sum(t.amount) AS depositsum',
          { id: int(m) }
        );
        const bal = toNum(r.records[0].get('b'));
        const depositsum = toNum(r.records[0].get('depositsum')) || 0;
        const expected = initial.get(m) + depositsum;
        if (bal !== expected) {
          mismatches.push(`mule ${m}: balance=${bal} but initial(${initial.get(m)})+deposits(${depositsum})=${expected} (atomicity broken)`);
        }
      } finally {
        await s.close();
      }
    }

    const total = commits + aborts;
    const abortRate = total > 0 ? aborts / total : 0;
    console.log(`clients=${CLIENTS} (writers=${writers}, readers=${readers}) ops/client=${OPS} mule_supernodes=${mules.length}`);
    console.log(
      `write commits=${commits} write aborts=${aborts} abort_rate=${abortRate.toFixed(3)} ` +
        `write_p50_ms=${percentileMs(writeCommitMs, 0.5)} write_p99_ms=${percentileMs(writeCommitMs, 0.99)} read_ops=${readOps}`
    );

    if (mismatches.length > 0) {
      fail('LOST UPDATE detected:\n  ' + mismatches.join('\n  '));
    }
    console.log('SSI invariant held: every committed deposit is reflected in the mule balances (no lost update).');

    // ---- Abort rate as a FIRST-CLASS signal: assert the tight, documented band.
    if (abortRate < ABORT_FLOOR) {
      fail(
        `abort_rate ${abortRate.toFixed(3)} < floor ${ABORT_FLOOR}: contention did NOT provoke SSI at this ` +
          `scale (raise clients/ops or lower the mule count) — an inconclusive concurrency run, not a pass.`
      );
    }
    if (abortRate > ABORT_CEIL) {
      fail(
        `abort_rate ${abortRate.toFixed(3)} > ceil ${ABORT_CEIL}: writers made almost no progress ` +
          `(near-total livelock) — a regression in write liveness under contention.`
      );
    }
    console.log(`abort_rate ${abortRate.toFixed(3)} within documented band [${ABORT_FLOOR}, ${ABORT_CEIL}] — SSI fired AND writers progressed.`);

    const stats = {
      clients: CLIENTS,
      writers,
      readers,
      ops_per_client: OPS,
      mule_supernodes: mules.length,
      commits,
      aborts,
      abort_rate: Number(abortRate.toFixed(6)),
      write_p50_ms: percentileMs(writeCommitMs, 0.5),
      write_p99_ms: percentileMs(writeCommitMs, 0.99),
      read_ops: readOps,
      abort_floor: ABORT_FLOOR,
      abort_ceil: ABORT_CEIL,
    };
    console.log('GRAPHUS_STATS ' + JSON.stringify(stats));
    console.log('GRAPHUS_CONCURRENCY_OK');
    process.exit(0);
  } catch (err) {
    fail(err && err.stack ? err.stack : String(err));
  } finally {
    await driver.close();
  }
})();
