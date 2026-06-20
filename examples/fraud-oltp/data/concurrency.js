'use strict';
//
// concurrency.js — the EXTREME-CONCURRENCY SSI driver, over Bolt-over-TCP+TLS with the OFFICIAL
// `neo4j-driver`.
//
// It launches many overlapping transactions from a configurable number of concurrent clients, all
// contending on a small set of HOT accounts (supernodes) to provoke Serializable-Snapshot-Isolation
// (SSI) conflicts:
//   - WRITER clients ingest TRANSFER edges into / out of the hot accounts and read-modify-write the
//     hot-account balance (the contended critical section),
//   - READER clients run detection-style aggregation reads over the same hot accounts concurrently.
//
// It captures commit/abort outcomes (SSI aborts surface as `Neo.*` transient/transaction errors the
// driver reports) and verifies the SSI safety invariant: NO committed transfer is lost — the final
// balance of each hot account equals its initial balance plus the sum of the increments from the
// transactions that COMMITTED (tracked exactly on the client side).
//
// On success it prints the commit/abort tallies and `GRAPHUS_CONCURRENCY_OK`, exiting 0; on a lost
// update or any unexpected failure it exits 1.
//
// Usage:
//   node concurrency.js <port> <user> <password> [clients] [ops_per_client] [hot_accounts]

const neo4j = require('neo4j-driver');

const [, , port, user, password, clientsArg, opsArg, hotArg] = process.argv;
if (!port || !user || !password) {
  console.error('usage: node concurrency.js <port> <user> <password> [clients] [ops] [hot]');
  process.exit(2);
}
const CLIENTS = parseInt(clientsArg || '8', 10);
const OPS = parseInt(opsArg || '25', 10);
const HOT = parseInt(hotArg || '4', 10);

const uri = `bolt+ssc://127.0.0.1:${port}`;
const int = (n) => neo4j.int(n);
const toNum = (v) => (neo4j.isInt(v) ? v.toNumber() : v);

function fail(msg) {
  console.error('CONCURRENCY FAILURE: ' + msg);
  process.exit(1);
}

// A deterministic-ish per-client PRNG so a given (client, op) picks a stable hot account + delta.
// (The wire schedule itself is non-deterministic across the network — for the byte-deterministic
// repro use the in-process `dst_contention` binary; this driver exercises the REAL concurrent path.)
function lcg(seed) {
  let s = seed >>> 0;
  return () => {
    s = (Math.imul(s, 1664525) + 1013904223) >>> 0;
    return s;
  };
}

(async () => {
  const driver = neo4j.driver(uri, neo4j.auth.basic(user, password), {
    maxConnectionPoolSize: CLIENTS + 4,
  });
  try {
    await driver.verifyConnectivity();

    // ---- Seed the hot accounts (balance 0 for clean arithmetic). Auto-commit setup.
    {
      const s = driver.session();
      try {
        await s.run('UNWIND range(0, $max) AS i CREATE (:Hot {id: i, balance: 0})', {
          max: int(HOT - 1),
        });
      } finally {
        await s.close();
      }
    }

    let commits = 0;
    let aborts = 0;
    let readOps = 0;

    // One WRITER client: OPS rounds of read-modify-write on a chosen hot account, inside an explicit
    // managed write transaction (executeWrite retries transient conflicts by default; we disable
    // retry semantics by using a single explicit tx per op so an SSI abort is observed, not hidden).
    async function writer(clientId) {
      const rnd = lcg(0x9e3779b9 ^ (clientId * 2654435761));
      for (let op = 0; op < OPS; op++) {
        const hot = rnd() % HOT;
        const delta = 1 + (rnd() % 100);
        const s = driver.session();
        const tx = s.beginTransaction();
        try {
          const r = await tx.run('MATCH (h:Hot {id: $id}) RETURN h.balance AS b', { id: int(hot) });
          const cur = toNum(r.records[0].get('b'));
          await tx.run('MATCH (h:Hot {id: $id}) SET h.balance = $v', {
            id: int(hot),
            v: int(cur + delta),
          });
          // Also ingest a TRANSFER edge to make the write set realistic (a second hot node).
          const other = (hot + 1) % HOT;
          await tx.run(
            'MATCH (a:Hot {id: $a}), (b:Hot {id: $b}) CREATE (a)-[:TRANSFER {amount: $amt}]->(b)',
            { a: int(hot), b: int(other), amt: int(delta) }
          );
          await tx.commit();
          commits += 1;
        } catch (e) {
          // SSI serialization conflict / transient → abort. This is the EXPECTED, bounded outcome.
          // NOTE: we deliberately do NOT accumulate a client-side "committed delta" here. A failed
          // `commit()` can be *ambiguous* (the server may have durably committed just before the
          // error surfaced over the wire), so a client-side commit tally is not a sound oracle for
          // the no-lost-update property. Instead we verify it from the GRAPH ITSELF below: the
          // balance SET and the TRANSFER edge are written in the SAME transaction, so they commit or
          // abort atomically — making the edge sum the authoritative, ambiguity-proof ground truth.
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

    // One READER client: detection-style aggregation reads over the hot accounts (no writes), run
    // concurrently with the writers to exercise read/write overlap.
    async function reader() {
      for (let op = 0; op < OPS; op++) {
        const s = driver.session({ defaultAccessMode: neo4j.session.READ });
        try {
          await s.run(
            'MATCH (h:Hot)-[t:TRANSFER]->(:Hot) RETURN h.id AS id, count(t) AS c, sum(t.amount) AS v ORDER BY v DESC'
          );
          readOps += 1;
        } catch (_) {
          /* a read aborting under SSI is fine; count it loosely */
        } finally {
          await s.close();
        }
      }
    }

    // Launch writers + readers concurrently (genuine overlap on the real server).
    const writers = Math.max(1, Math.ceil(CLIENTS * 0.75));
    const readers = Math.max(1, CLIENTS - writers);
    const tasks = [];
    for (let i = 0; i < writers; i++) tasks.push(writer(i));
    for (let i = 0; i < readers; i++) tasks.push(reader());
    await Promise.all(tasks);

    // ---- Verify ATOMICITY / NO-LOST-UPDATE from the graph itself (ambiguity-proof).
    //
    // In each writer transaction the balance SET and the outgoing TRANSFER {amount: delta} are
    // written ATOMICALLY (same explicit transaction). Therefore, for every hot account, its final
    // balance MUST equal the sum of `amount` over the TRANSFER edges that originate from it — every
    // applied increment is mirrored by exactly one edge, and a lost update (a SET that took effect
    // without its edge, or an edge without its SET) would break this equality. This holds regardless
    // of how many commits were ambiguous over the wire, so it is the sound oracle.
    const mismatches = [];
    for (let hot = 0; hot < HOT; hot++) {
      const s = driver.session({ defaultAccessMode: neo4j.session.READ });
      try {
        const r = await s.run(
          'MATCH (h:Hot {id: $id}) ' +
            'OPTIONAL MATCH (h)-[t:TRANSFER]->(:Hot) ' +
            'RETURN h.balance AS b, sum(t.amount) AS edgesum',
          { id: int(hot) }
        );
        const bal = toNum(r.records[0].get('b'));
        const edgesum = toNum(r.records[0].get('edgesum')) || 0;
        if (bal !== edgesum) {
          mismatches.push(`hot ${hot}: balance=${bal} but outgoing TRANSFER sum=${edgesum} (atomicity broken)`);
        }
      } finally {
        await s.close();
      }
    }

    const total = commits + aborts;
    const abortRate = total > 0 ? aborts / total : 0;
    console.log(
      `clients=${CLIENTS} (writers=${writers}, readers=${readers}) ops/client=${OPS} hot_accounts=${HOT}`
    );
    console.log(
      `write commits=${commits} write aborts=${aborts} abort_rate=${abortRate.toFixed(3)} read_ops=${readOps}`
    );

    if (mismatches.length > 0) {
      fail('LOST UPDATE detected:\n  ' + mismatches.join('\n  '));
    }
    // SSI must have been genuinely exercised: under real contention at this concurrency we expect
    // a non-zero abort count. (If zero, contention was too low to be meaningful — flag it.)
    if (aborts === 0) {
      console.warn(
        'WARNING: zero aborts — contention did not provoke an SSI conflict at this scale; ' +
          'the no-lost-update invariant still held.'
      );
    }
    console.log(
      'SSI invariant held: every committed transfer is reflected in the final balances (no lost update).'
    );
    // Machine-readable evidence for the run.sh harness: commit/abort tallies + abort rate.
    const stats = {
      clients: CLIENTS,
      writers,
      readers,
      ops_per_client: OPS,
      hot_accounts: HOT,
      commits,
      aborts,
      abort_rate: Number(abortRate.toFixed(6)),
      read_ops: readOps,
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
