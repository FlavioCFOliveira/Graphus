'use strict';
//
// concurrency.js — the fraud-oltp OLTP contention driver, over Bolt with the OFFICIAL `neo4j-driver`.
//
// It contends on the REAL mule :Account supernodes of the loaded fraud graph (the highest-degree
// nodes — the fan-in/fan-out hubs), NOT synthetic :Hot nodes. Many overlapping transactions from a
// configurable number of concurrent clients all read-modify-write those mule balances, provoking
// Serializable-Snapshot-Isolation (SSI) conflicts.
//
// ================================================================================================
// THE UNIT OF WORK IS A DOUBLE-ENTRY LEDGER TRANSFER
// ================================================================================================
// One business transaction = move `amount` from the writer's own funded settlement account to a
// mule, as a genuine double-entry move, atomically in ONE transaction:
//
//     read src.balance, read mule.balance          (the read-modify-write that SSI must serialize)
//     check sufficient funds                        (the business rule)
//     SET src.balance  -= amount                    (the debit)
//     SET mule.balance += amount                    (the credit — the contended write)
//     CREATE (src)-[:TRANSFER {tx_id: 'CONC-<client>-<op>', amount, …}]->(mule)   (the journal entry)
//
// Because every committed transfer debits exactly what it credits, the LEDGER MUST RECONCILE: the
// sum of all balances is CONSERVED, no transfer is lost, and none is applied twice. `tx_id` is keyed
// to the BUSINESS unit (client+op), NOT to the attempt, so a retried transfer that the engine
// wrongly committed twice would show up as a duplicate journal entry — and the graph is checked for
// exactly that afterwards. (The old driver credited the mule out of thin air and never debited a
// source, so it could not detect money being created.)
//
// ================================================================================================
// TWO MODES — the DEFAULT is the PRODUCTION-SHAPED, RETRYING CLIENT
// ================================================================================================
// FRAUD_RETRY=1 (DEFAULT) — a real OLTP application. Every transfer is a MANAGED transaction driven
//   through the official driver's `session.executeWrite()`, so a serialization failure is retried,
//   with the driver's own bounded exponential backoff, until it COMMITS or its retry budget
//   (`maxTransactionRetryTime`) is exhausted. This is what every official Neo4j driver does, and the
//   application-visible outcome of contention is therefore "SLOWER", not "LOST".
//
//   This is also the ONLY configuration that exercises the driver's RETRY CLASSIFIER — the exact
//   thing `rmp #612` broke: Graphus dressed its SSI abort in a `…Transaction.Terminated` poison
//   title, which the official driver explicitly EXCLUDES from retry, silently turning managed-
//   transaction retry into a hard failure over Bolt. A no-retry example cannot see that. This one
//   asserts it (see the #612 REGRESSION DETECTOR below), so a regression FAILS the run.
//
// FRAUD_RETRY=0 — the pure-contention isolation: one explicit, single-shot transaction per transfer,
//   no retry, so the RAW engine abort rate is observed directly. A legitimate experiment, and how
//   this example used to run — but NOT what a production client does, so it is no longer the default.
//
// ================================================================================================
// TWO LAYERS OF TRUTH — never conflated
// ================================================================================================
//   ENGINE layer      — attempts, aborts, and the engine ABORT RATE (aborts / attempts). This is the
//                       real contention evidence and it is kept: SSI genuinely fires, hard.
//   APPLICATION layer — business transfers committed, retries per commit, RETRY-INCLUSIVE latency
//                       (p50/p99/p999 — under contention the TAIL is the whole story), and any work
//                       that exhausted its retry budget.
// A high engine abort rate with a 100% application commit rate is a HEALTHY system under contention.
// Reporting only the first reads as failure; reporting only the second hides the contention.
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

// ---- Mode ---------------------------------------------------------------------------------------
// DEFAULT = the production-shaped retrying client. FRAUD_RETRY=0 restores the pure-contention run.
const RETRY = (process.env.FRAUD_RETRY || '1') !== '0';

// The application's declared retry budget, handed to the driver as `maxTransactionRetryTime`. The
// driver retries a RETRYABLE failure with its own exponential backoff + jitter until this elapses,
// then gives up and throws — which is exactly "the work exhausted its retry budget", and we report
// it as such rather than pretending it committed.
const RETRY_BUDGET_MS = parseInt(process.env.FRAUD_RETRY_BUDGET_MS || '30000', 10);

// Each writer funds its OWN settlement account, so the writers do not contend with one another on
// the DEBIT leg — the contention is deliberately concentrated on the shared mule supernodes (the
// CREDIT leg), which is the phenomenon under study. Sized so the funds check can never bite:
// OPS transfers of at most MAX_AMOUNT each.
const MAX_AMOUNT = 100;
const FUNDING = OPS * MAX_AMOUNT * 10;

// ---- The ENGINE abort-rate band (a FIRST-CLASS, two-sided, documented signal) --------------------
// Deliberately over-contending a couple of :Account supernodes under SSI is EXPECTED to abort a large
// share of transaction ATTEMPTS — that is the finding, not a defect. The band is asserted on the
// ENGINE layer (aborts / attempts) in BOTH modes; the APPLICATION layer is asserted separately and far
// more strictly (in retry mode, EVERY transfer must commit).
//
//   FLOOR: SSI must GENUINELY fire. Below this, contention never materialised (a misconfiguration, or
//          an SSI regression that could be masking lost updates) — an inconclusive run, not a pass.
//   CEIL : the engine must still make PROGRESS. Above this, writers are in near-total livelock.
//
// The two modes sit at GENUINELY DIFFERENT points, and the difference is itself the headline finding.
// Measured on this host (9 writers, 2 mule supernodes, 30 transfers each — the identical workload and
// the identical transaction shape, the ONLY difference being whether the client retries):
//
//     NO-RETRY : engine abort rate ~0.91  ->  only  25/270 transfers commit (91% of the work is LOST)
//     RETRY    : engine abort rate ~0.05  ->      270/270 transfers commit (nothing is lost)
//
// A retrying client does not merely SURVIVE contention, it largely DISSOLVES it: backing off after an
// abort spreads the writers out in time, so the per-attempt conflict rate collapses by ~18x. The cost
// is paid in LATENCY (p99 ~1.2s, p999 ~3.4s, against a ~4ms median), never in lost work — which is
// precisely why the raw abort rate of a no-retry client is a misleading measure of a real system.
// Both bounds are overridable via FRAUD_ABORT_FLOOR / FRAUD_ABORT_CEIL for a differently-sized target.
const DEFAULT_FLOOR = RETRY ? '0.01' : '0.40'; // retry: 5x headroom under the measured ~0.05
const DEFAULT_CEIL = RETRY ? '0.60' : '0.995'; // retry: 12x headroom over it — a livelock guard
const ABORT_FLOOR = parseFloat(process.env.FRAUD_ABORT_FLOOR || DEFAULT_FLOOR);
const ABORT_CEIL = parseFloat(process.env.FRAUD_ABORT_CEIL || DEFAULT_CEIL);

const sessionOpts = (extra) => Object.assign(database ? { database } : {}, extra || {});
const int = (n) => neo4j.int(n);
const toNum = (v) => (neo4j.isInt(v) ? v.toNumber() : v);

function fail(msg) {
  console.error('CONCURRENCY FAILURE: ' + msg);
  process.exit(1);
}
function percentileMs(samples, p) {
  if (samples.length === 0) return null; // no sample => NOT MEASURED (never a fabricated 0)
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

// ---- Error classification -----------------------------------------------------------------------
// Is this error an ENGINE serialization / SSI abort — WHATEVER classification the server dressed it
// in? Deliberately broad on the code family: it must still recognise the abort when a regression
// mislabels it (that is the whole point of the #612 detector below).
function isSerializationAbort(e) {
  const code = String((e && e.code) || '');
  const msg = String((e && e.message) || '');
  if (/Transaction\.(Outdated|Terminated|LockClientStopped|ConstraintsChanged)/.test(code)) return true;
  if (/^Neo\.TransientError\./.test(code)) return true;
  return /serializ|conflict|outdated|concurrent (update|modification)/i.test(msg);
}
(async () => {
  const gt = JSON.parse(fs.readFileSync(gtPath, 'utf8'));
  let mules = gt.mules.map((m) => m.mule);
  if (mulesArg) mules = mules.slice(0, Math.max(1, parseInt(mulesArg, 10)));
  if (mules.length === 0) fail('ground truth has no mule accounts to contend on');
  const fraudAccounts = new Set(gt.fraud_accounts || []);

  const writers = Math.max(1, Math.ceil(CLIENTS * 0.75));
  const readers = Math.max(1, CLIENTS - writers);

  const driver = neo4j.driver(uri, neo4j.auth.basic(user, password), {
    maxConnectionPoolSize: CLIENTS + 4,
    // The application's DECLARED retry budget. The driver retries a failure its classifier deems
    // retryable, with exponential backoff + jitter, until this elapses.
    maxTransactionRetryTime: RETRY_BUDGET_MS,
  });

  // ---- Counters -----------------------------------------------------------------------------------
  // ENGINE layer (transaction attempts the engine actually saw).
  let attempts = 0; // every invocation of the write work function = one engine transaction attempt
  let engineAborts = 0; // attempts the engine aborted (serialization conflicts and other failures)
  // APPLICATION layer (units of BUSINESS work).
  let committed = 0; // business transfers that eventually COMMITTED
  let exhausted = 0; // business transfers that exhausted the declared retry budget
  let insufficientFunds = 0; // business transfers rejected by the business rule (must stay 0)
  let retriesOnCommitted = 0; // total retries spent by the transfers that DID commit
  let maxRetries = 0; // the worst single transfer's retry count
  let readOps = 0;
  let readRetries = 0;
  // The #612 REGRESSION DETECTOR: serialization aborts the DRIVER refused to retry.
  const nonRetryable = []; // {code, message}
  // Failures that are NOT serialization conflicts at all (constraint violation, broken connection, …).
  // Kept apart so contention is never blamed for a defect that has nothing to do with contention.
  const hardErrors = []; // {code, message}
  const latencyMs = []; // RETRY-INCLUSIVE per-business-transfer latency (what the application feels)
  const abortCodes = new Map(); // code -> count (evidence of what the engine actually returns)

  const noteAbort = (e) => {
    const code = String((e && e.code) || '(no code)');
    abortCodes.set(code, (abortCodes.get(code) || 0) + 1);
  };

  try {
    await driver.verifyConnectivity();
    console.log(`connected to ${uri}${database ? ` database='${database}'` : ' (default database)'}`);
    console.log(
      `mode: ${RETRY ? 'PRODUCTION (managed transactions, driver retry + backoff)' : 'NO-RETRY (pure contention isolation)'}` +
        (RETRY ? `, retry budget ${RETRY_BUDGET_MS} ms/transfer` : '')
    );

    // ---- Choose the writers' settlement (source) accounts: real benign accounts, never a fraud one,
    // one per writer, so the DEBIT legs never contend with each other.
    const benign = [];
    {
      const s = driver.session(sessionOpts({ defaultAccessMode: neo4j.session.READ }));
      try {
        const r = await s.run('MATCH (a:Account) RETURN a.id AS id ORDER BY a.id');
        for (const rec of r.records) {
          const id = toNum(rec.get('id'));
          if (!fraudAccounts.has(id) && !mules.includes(id)) benign.push(id);
        }
      } finally {
        await s.close();
      }
    }
    if (benign.length < writers) {
      fail(`need ${writers} benign settlement accounts, the graph has only ${benign.length}`);
    }
    const sources = benign.slice(0, writers);

    // ---- Fund each settlement account (a plain deposit, so the funds check can never bite). This is
    // SETUP: the ledger snapshot below is taken AFTER it, so conservation is asserted across the
    // contention phase alone.
    for (const src of sources) {
      const s = driver.session(sessionOpts());
      try {
        await s.run('MATCH (a:Account {id: $id}) SET a.balance = a.balance + $f', {
          id: int(src),
          f: int(FUNDING),
        });
      } finally {
        await s.close();
      }
    }

    // ---- Snapshot the ledger BEFORE the contention phase: the total of every balance (the
    // conservation oracle) plus each contended account's opening balance.
    const ledgerTotal = async () => {
      const s = driver.session(sessionOpts({ defaultAccessMode: neo4j.session.READ }));
      try {
        const r = await s.run('MATCH (a:Account) RETURN sum(a.balance) AS t');
        return toNum(r.records[0].get('t'));
      } finally {
        await s.close();
      }
    };
    const balanceOf = async (id) => {
      const s = driver.session(sessionOpts({ defaultAccessMode: neo4j.session.READ }));
      try {
        const r = await s.run('MATCH (a:Account {id: $id}) RETURN a.balance AS b', { id: int(id) });
        if (r.records.length === 0) fail(`account ${id} not found — was the graph loaded?`);
        return toNum(r.records[0].get('b'));
      } finally {
        await s.close();
      }
    };

    // ==============================================================================================
    // THE #612 RETRY-CLASSIFICATION PROBE — a DETERMINISTIC regression detector.
    //
    // Force ONE genuine SSI serialization abort (two overlapping read-modify-writes on the same mule:
    // T1 reads, T2 reads+writes+commits, T1 then writes and commits -> T1 MUST abort), then ask the
    // OFFICIAL driver's OWN public retry classifier — `neo4j.Neo4jError.isRetriable()`, the very
    // function `executeWrite` consults — whether it would retry it.
    //
    // Why this probe exists at all: `executeWrite` ABSORBS the aborts it retries, so a run driven only
    // through managed transactions never gets to see the abort's error code. This probe surfaces the
    // real code AND puts the driver's classifier under direct assertion, so the #612 detector does not
    // depend on how many retries a given scheduling happened to produce.
    //
    // rmp #612: Graphus dressed its SSI abort in a `…Transaction.Terminated` title, which every
    // official driver EXCLUDES from retry — silently turning execute_write into a hard failure.
    // ==============================================================================================
    let probeCode = null;
    let probeRetriable = null;
    {
      const muleId = mules[0];
      for (let round = 0; round < 5 && probeCode === null; round++) {
        const s1 = driver.session(sessionOpts());
        const s2 = driver.session(sessionOpts());
        const t1 = s1.beginTransaction();
        const t2 = s2.beginTransaction();
        try {
          const r1 = await t1.run('MATCH (a:Account {id: $id}) RETURN a.balance AS b', { id: int(muleId) });
          const b1 = toNum(r1.records[0].get('b'));
          // T2 reads the same balance, writes it, and commits FIRST.
          const r2 = await t2.run('MATCH (a:Account {id: $id}) RETURN a.balance AS b', { id: int(muleId) });
          const b2 = toNum(r2.records[0].get('b'));
          await t2.run('MATCH (a:Account {id: $id}) SET a.balance = $v', { id: int(muleId), v: int(b2 + 1) });
          await t2.commit();
          // T1 now writes the node T2 just changed, on a stale snapshot -> SSI must refuse to serialize.
          await t1.run('MATCH (a:Account {id: $id}) SET a.balance = $v', { id: int(muleId), v: int(b1 + 1) });
          await t1.commit();
          // No abort: T1 was allowed through. Retry the probe (a benign scheduling miss) — but if SSI
          // NEVER refuses this, that is a serious isolation finding, asserted after the loop.
          try {
            await t2.rollback();
          } catch (_) {
            /* already committed */
          }
        } catch (e) {
          probeCode = String((e && e.code) || '(no code)');
          // The OFFICIAL driver's own retry classifier — not a heuristic of ours. (Kept OUT of the
          // workload's `abort_codes` tally: the probe is setup, not workload.)
          probeRetriable = neo4j.Neo4jError.isRetriable(e);
          try {
            await t1.rollback();
          } catch (_) {
            /* already rolled back by the server */
          }
        } finally {
          await s1.close();
          await s2.close();
        }
      }
    }
    if (probeCode === null) {
      fail(
        `the SSI probe could NOT provoke a serialization abort in 5 rounds: two overlapping ` +
          `read-modify-writes on the SAME account both committed. Serializable Snapshot Isolation is ` +
          `not refusing a write-write conflict on a stale snapshot — a LOST UPDATE is possible.`
      );
    }
    console.log(`SSI probe: forced a real serialization abort -> code='${probeCode}', official driver isRetriable=${probeRetriable}`);
    if (probeRetriable !== true) {
      fail(
        `rmp #612 REGRESSION — Graphus's SSI serialization abort is classified NON-RETRYABLE by the ` +
          `OFFICIAL neo4j-driver.\n  code: '${probeCode}'  ->  neo4j.Neo4jError.isRetriable() = ${probeRetriable}\n` +
          `  A serialization failure MUST carry a retryable TransientError code (Graphus emits ` +
          `'Neo.TransientError.Transaction.Outdated'). A poison title such as ` +
          `'Neo.TransientError.Transaction.Terminated' or 'Neo.ClientError.Transaction.Terminated' is ` +
          `EXPLICITLY excluded from retry by every official driver, which silently breaks managed-` +
          `transaction retry (execute_write / executeWrite) for EVERY driver application: contention ` +
          `stops meaning "slower" and starts meaning "LOST". That is exactly the defect #612 fixed.`
      );
    }

    // The probe committed T2 (+1 to a mule). Snapshot the ledger AFTER it, so conservation is asserted
    // across the contention phase alone.
    const totalBefore = await ledgerTotal();
    const initial = new Map();
    for (const id of [...mules, ...sources]) initial.set(id, await balanceOf(id));

    console.log(
      `contending on ${mules.length} REAL mule supernode(s): ${JSON.stringify(mules)}; ` +
        `settlement accounts: ${JSON.stringify(sources)} (funded +${FUNDING} each)`
    );
    console.log(`ledger opening total: ${totalBefore}`);

    // ---- The unit of business work: ONE double-entry transfer. Runs inside whatever transaction the
    // caller gives it, and is re-invoked from scratch on each retry (so `tx_id` stays keyed to the
    // BUSINESS unit, never to the attempt).
    //
    // NOTE: attempts are counted by the CALLER, in a per-unit local, never by differencing a shared
    // global across an `await` — 9 writers interleave on one event loop, so a global differenced
    // around `executeWrite` counts every OTHER client's attempts too (it reported a 4.35 abort "rate"
    // and 253 retries on a single transfer before this was fixed).
    async function transfer(tx, srcId, muleId, amount, txId) {
      const sr = await tx.run('MATCH (a:Account {id: $id}) RETURN a.balance AS b', { id: int(srcId) });
      const sb = toNum(sr.records[0].get('b'));
      const mr = await tx.run('MATCH (a:Account {id: $id}) RETURN a.balance AS b', { id: int(muleId) });
      const mb = toNum(mr.records[0].get('b'));
      if (sb < amount) {
        const e = new Error(`insufficient funds: account ${srcId} has ${sb}, needs ${amount}`);
        e.insufficientFunds = true;
        throw e;
      }
      await tx.run('MATCH (a:Account {id: $id}) SET a.balance = $v', { id: int(srcId), v: int(sb - amount) });
      await tx.run('MATCH (a:Account {id: $id}) SET a.balance = $v', { id: int(muleId), v: int(mb + amount) });
      await tx.run(
        'MATCH (s:Account {id: $src}), (m:Account {id: $mule}) ' +
          'CREATE (s)-[:TRANSFER {tx_id: $tx, amount: $amt, ts: 0, device: -1, ip: $ip, conc: true}]->(m)',
        { src: int(srcId), mule: int(muleId), amt: int(amount), tx: txId, ip: '172.31.0.1' }
      );
    }

    // ---- WRITER — the PRODUCTION path: a MANAGED transaction per transfer. `executeWrite` re-invokes
    // our work function on every retry, so counting invocations gives the engine ATTEMPT count and the
    // application RETRY count for free, straight from the official driver's own retry machinery.
    async function writerManaged(clientId) {
      const rnd = lcg(0x9e3779b9 ^ (clientId * 2654435761));
      const srcId = sources[clientId];
      for (let op = 0; op < OPS; op++) {
        const muleId = mules[rnd() % mules.length];
        const amount = 1 + (rnd() % MAX_AMOUNT);
        const txId = `CONC-${clientId}-${op}`;
        // PER-UNIT attempt counter, closed over by the work function the driver re-invokes on each
        // retry. This is the ONLY sound way to count attempts under concurrency (see `transfer`).
        let used = 0;
        const t0 = hrMs();
        const s = driver.session(sessionOpts());
        try {
          await s.executeWrite((tx) => {
            used += 1;
            return transfer(tx, srcId, muleId, amount, txId);
          });
          attempts += used;
          committed += 1;
          engineAborts += used - 1; // every attempt but the last one aborted
          retriesOnCommitted += used - 1;
          maxRetries = Math.max(maxRetries, used - 1);
          latencyMs.push(hrMs() - t0); // RETRY-INCLUSIVE: what the application actually waited
        } catch (e) {
          used = Math.max(1, used);
          attempts += used;
          maxRetries = Math.max(maxRetries, used - 1);
          noteAbort(e);
          if (e && e.insufficientFunds) {
            // A CLIENT-side business rejection, not an engine abort: the driver rolled the transaction
            // back because OUR work function threw. Only any PRIOR attempts were real engine aborts.
            // (Asserted to be 0 below — the settlement accounts are funded so it cannot fire.)
            insufficientFunds += 1;
            engineAborts += used - 1;
          } else if (isSerializationAbort(e) && used === 1) {
            engineAborts += used;
            // ---- THE #612 REGRESSION DETECTOR ----------------------------------------------------
            // A serialization abort that `executeWrite` did NOT retry even once: the official driver's
            // retry classifier judged it NON-RETRYABLE. That is precisely #612 — an SSI abort dressed
            // in a poison title (`…Transaction.Terminated`) that drivers exclude from retry — and it
            // silently breaks managed-transaction retry for every Neo4j-driver application.
            nonRetryable.push({ code: String((e && e.code) || '(no code)'), message: String((e && e.message) || '') });
          } else {
            engineAborts += used;
            if (isSerializationAbort(e)) {
              // Retried (used > 1), but the declared budget ran out before it could commit.
              exhausted += 1;
            } else {
              // NOT a serialization failure at all — a hard error (a constraint violation, a broken
              // connection, a bad query). Tracked SEPARATELY so it is never misreported as "the retry
              // budget was exhausted", which would blame contention for a defect that is not contention.
              hardErrors.push({ code: String((e && e.code) || '(no code)'), message: String((e && e.message) || '') });
            }
          }
        } finally {
          await s.close();
        }
      }
    }

    // ---- WRITER — the NO-RETRY isolation: one explicit, single-shot transaction per transfer, so the
    // RAW engine abort is observed rather than absorbed by the driver.
    async function writerNoRetry(clientId) {
      const rnd = lcg(0x9e3779b9 ^ (clientId * 2654435761));
      const srcId = sources[clientId];
      for (let op = 0; op < OPS; op++) {
        const muleId = mules[rnd() % mules.length];
        const amount = 1 + (rnd() % MAX_AMOUNT);
        const txId = `CONC-${clientId}-${op}`;
        const t0 = hrMs();
        const s = driver.session(sessionOpts());
        const tx = s.beginTransaction();
        try {
          attempts += 1; // exactly one engine attempt per business transfer: no retry, by design
          await transfer(tx, srcId, muleId, amount, txId);
          await tx.commit();
          committed += 1;
          latencyMs.push(hrMs() - t0);
        } catch (e) {
          noteAbort(e);
          if (e && e.insufficientFunds) {
            insufficientFunds += 1; // a client-side business rejection, not an engine abort
          } else {
            engineAborts += 1;
            if (!isSerializationAbort(e)) {
              hardErrors.push({ code: String((e && e.code) || '(no code)'), message: String((e && e.message) || '') });
            }
          }
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

    // ---- READER — a mule statement-of-account aggregation, concurrent with the writers. Managed too
    // in production mode, so a read that loses a serialization race is retried like a real client's.
    async function reader() {
      for (let op = 0; op < OPS; op++) {
        const s = driver.session(sessionOpts({ defaultAccessMode: neo4j.session.READ }));
        const query =
          'MATCH (m:Account)<-[t:TRANSFER]-(:Account) WHERE m.id IN $mules ' +
          'RETURN m.id AS id, count(t) AS c, sum(t.amount) AS v ORDER BY v DESC';
        const params = { mules: mules.map(int) };
        try {
          if (RETRY) {
            let tries = 0;
            await s.executeRead((tx) => {
              tries += 1;
              return tx.run(query, params);
            });
            readRetries += tries - 1;
          } else {
            await s.run(query, params);
          }
          readOps += 1;
        } catch (_) {
          /* a read that exhausts its budget under extreme contention is counted as a non-op */
        } finally {
          await s.close();
        }
      }
    }

    // ---- Run the contention phase ------------------------------------------------------------------
    const phaseStart = hrMs();
    const tasks = [];
    const writerFn = RETRY ? writerManaged : writerNoRetry;
    for (let i = 0; i < writers; i++) tasks.push(writerFn(i));
    for (let i = 0; i < readers; i++) tasks.push(reader());
    await Promise.all(tasks);
    const phaseMs = hrMs() - phaseStart;

    const businessTxns = writers * OPS;
    const engineAbortRate = attempts > 0 ? engineAborts / attempts : 0;
    const commitRate = businessTxns > 0 ? committed / businessTxns : 0;
    const retriesPerCommit = committed > 0 ? retriesOnCommitted / committed : 0;

    console.log(
      `clients=${CLIENTS} (writers=${writers}, readers=${readers}) ops/client=${OPS} mule_supernodes=${mules.length}`
    );
    console.log(
      `ENGINE      attempts=${attempts} aborts=${engineAborts} abort_rate=${engineAbortRate.toFixed(3)} ` +
        `codes=${JSON.stringify(Object.fromEntries(abortCodes))}`
    );
    console.log(
      `APPLICATION business_transfers=${businessTxns} committed=${committed} ` +
        `commit_rate=${commitRate.toFixed(3)} retry_budget_exhausted=${exhausted} ` +
        `retries_per_commit=${retriesPerCommit.toFixed(2)} max_retries=${maxRetries}`
    );
    console.log(
      `LATENCY     retry-inclusive per business transfer: p50=${percentileMs(latencyMs, 0.5)}ms ` +
        `p99=${percentileMs(latencyMs, 0.99)}ms p999=${percentileMs(latencyMs, 0.999)}ms ` +
        `(phase wall ${phaseMs.toFixed(0)}ms, read_ops=${readOps}, read_retries=${readRetries})`
    );

    // ==============================================================================================
    // ASSERTION 1 — the #612 REGRESSION DETECTOR (production mode only: it is the driver's classifier
    // that is under test, and only a managed transaction consults it).
    // ==============================================================================================
    if (RETRY && nonRetryable.length > 0) {
      const seen = [...new Set(nonRetryable.map((n) => n.code))];
      fail(
        `rmp #612 REGRESSION — ${nonRetryable.length} serialization abort(s) were classified ` +
          `NON-RETRYABLE by the OFFICIAL neo4j-driver: executeWrite() gave up after a SINGLE attempt ` +
          `instead of retrying.\n  codes seen: ${JSON.stringify(seen)}\n` +
          `  An SSI abort MUST carry a retryable TransientError code (Graphus emits ` +
          `'Neo.TransientError.Transaction.Outdated'). A poison title such as ` +
          `'Neo.TransientError.Transaction.Terminated' / 'Neo.ClientError.Transaction.Terminated' is ` +
          `explicitly EXCLUDED from retry by every official driver, which silently breaks managed-` +
          `transaction retry (execute_write) for EVERY Neo4j-driver application. That is exactly the ` +
          `defect #612 fixed; this assertion exists so it can never come back unnoticed.`
      );
    }

    // ==============================================================================================
    // ASSERTION 2 — the retry path was actually EXERCISED. Without this the run proves nothing about
    // #612: a workload that never aborted would pass assertion 1 vacuously.
    // ==============================================================================================
    if (RETRY && retriesOnCommitted === 0) {
      fail(
        `the driver's RETRY PATH NEVER FIRED (0 retries across ${committed} committed transfers, ` +
          `${engineAborts} engine aborts): either contention did not materialise at this scale — an ` +
          `inconclusive run, not a pass — or the aborts never reached the driver's retry classifier. ` +
          `This example must exercise retry, because that is the path #612 broke.`
      );
    }

    // ==============================================================================================
    // ASSERTION 3 — LEDGER RECONCILIATION. What a real fraud/ledger system actually cares about.
    // ==============================================================================================
    const totalAfter = await ledgerTotal();
    if (totalAfter !== totalBefore) {
      fail(
        `LEDGER DOES NOT RECONCILE — the sum of all balances changed across the contention phase: ` +
          `${totalBefore} -> ${totalAfter} (delta ${totalAfter - totalBefore}). Every committed transfer ` +
          `debits exactly what it credits, so the total MUST be conserved. Money was created or destroyed: ` +
          `a partially-applied transaction (an atomicity break).`
      );
    }
    console.log(`LEDGER      conserved: total balance ${totalBefore} -> ${totalAfter} (delta 0)`);

    // Per-account reconciliation: each mule's credit and each source's debit must equal the sum of its
    // COMMITTED journal entries. A lost update (a SET without its edge, or vice-versa) breaks this.
    const mismatches = [];
    for (const id of mules) {
      const s = driver.session(sessionOpts({ defaultAccessMode: neo4j.session.READ }));
      try {
        const r = await s.run(
          'MATCH (a:Account {id: $id}) ' +
            'OPTIONAL MATCH ()-[t:TRANSFER]->(a) WHERE t.tx_id STARTS WITH "CONC-" ' +
            'RETURN a.balance AS b, sum(t.amount) AS credited',
          { id: int(id) }
        );
        const bal = toNum(r.records[0].get('b'));
        const credited = toNum(r.records[0].get('credited')) || 0;
        const expected = initial.get(id) + credited;
        if (bal !== expected) {
          mismatches.push(
            `mule ${id}: balance=${bal} but opening(${initial.get(id)}) + credits(${credited}) = ${expected}`
          );
        }
      } finally {
        await s.close();
      }
    }
    for (const id of sources) {
      const s = driver.session(sessionOpts({ defaultAccessMode: neo4j.session.READ }));
      try {
        const r = await s.run(
          'MATCH (a:Account {id: $id}) ' +
            'OPTIONAL MATCH (a)-[t:TRANSFER]->() WHERE t.tx_id STARTS WITH "CONC-" ' +
            'RETURN a.balance AS b, sum(t.amount) AS debited',
          { id: int(id) }
        );
        const bal = toNum(r.records[0].get('b'));
        const debited = toNum(r.records[0].get('debited')) || 0;
        const expected = initial.get(id) - debited;
        if (bal !== expected) {
          mismatches.push(
            `settlement ${id}: balance=${bal} but opening(${initial.get(id)}) - debits(${debited}) = ${expected}`
          );
        }
      } finally {
        await s.close();
      }
    }
    if (mismatches.length > 0) {
      fail('LOST OR DOUBLE-APPLIED UPDATE detected:\n  ' + mismatches.join('\n  '));
    }
    console.log('LEDGER      every mule credit and settlement debit matches its committed journal entries.');

    // EXACTLY-ONCE: the journal must hold exactly one entry per COMMITTED business transfer — no
    // phantom entry, and (critically, under retry) no DUPLICATE. `tx_id` is keyed to the business unit,
    // so a transfer the engine committed twice would leave two entries carrying the same tx_id.
    {
      const s = driver.session(sessionOpts({ defaultAccessMode: neo4j.session.READ }));
      try {
        const r = await s.run(
          'MATCH ()-[t:TRANSFER]->() WHERE t.tx_id STARTS WITH "CONC-" ' +
            'RETURN count(t) AS entries, count(DISTINCT t.tx_id) AS distinct_ids'
        );
        const entries = toNum(r.records[0].get('entries'));
        const distinctIds = toNum(r.records[0].get('distinct_ids'));
        if (entries !== committed) {
          fail(
            `JOURNAL MISMATCH — ${entries} committed TRANSFER journal entries but ${committed} business ` +
              `transfers reported a commit. ${entries > committed ? 'A transfer was applied MORE THAN ONCE ' +
              '(a retry double-committed, or an aborted attempt left its edge behind)' : 'A committed transfer ' +
              'LOST its journal entry'}.`
          );
        }
        if (distinctIds !== entries) {
          fail(
            `DOUBLE-APPLIED TRANSFER — ${entries} journal entries carry only ${distinctIds} distinct tx_ids: ` +
              `the same business transfer was committed twice (and the RELATIONSHIP KEY on tx_id failed to ` +
              `reject the duplicate).`
          );
        }
        console.log(
          `LEDGER      exactly-once: ${entries} journal entries, ${distinctIds} distinct tx_ids, ` +
            `${committed} committed transfers — all equal.`
        );
      } finally {
        await s.close();
      }
    }

    // ==============================================================================================
    // ASSERTION 4 — the APPLICATION makes PROGRESS under extreme contention.
    // ==============================================================================================
    if (insufficientFunds > 0) {
      fail(
        `${insufficientFunds} transfer(s) hit the insufficient-funds business rule — the settlement ` +
          `accounts were under-funded, so this run did not measure what it claims to.`
      );
    }
    // A failure that is NOT a serialization conflict is not a contention finding — it is a defect, and
    // it must be reported as one rather than absorbed into an abort tally.
    if (hardErrors.length > 0) {
      const seen = [...new Set(hardErrors.map((h) => h.code))];
      fail(
        `${hardErrors.length} transfer(s) failed with a NON-serialization error — this is not ` +
          `contention, it is a defect.\n  codes: ${JSON.stringify(seen)}\n` +
          `  first: ${hardErrors[0].message.slice(0, 300)}`
      );
    }
    if (RETRY) {
      // The whole point: under a retrying client, EVERY unit of business work eventually commits. The
      // application-visible outcome of contention is "slower", NOT "lost".
      if (committed !== businessTxns) {
        fail(
          `${exhausted} of ${businessTxns} business transfer(s) EXHAUSTED the ${RETRY_BUDGET_MS}ms retry ` +
            `budget without committing (commit rate ${commitRate.toFixed(3)}). A production OLTP client ` +
            `retries a serialization failure until it commits; work that never commits under a bounded, ` +
            `honest retry budget is a WRITE-LIVENESS defect, not an acceptable outcome.`
        );
      }
      console.log(
        `PROGRESS    100% of ${businessTxns} business transfers COMMITTED (0 lost, 0 budget-exhausted): ` +
          `contention made the application SLOWER, not lossy.`
      );
    } else if (committed === 0) {
      fail('no transfer committed at all — total write livelock, not a contention experiment.');
    }

    // ==============================================================================================
    // ASSERTION 5 — the ENGINE abort rate lands inside its documented band (the contention evidence).
    // ==============================================================================================
    if (engineAbortRate < ABORT_FLOOR) {
      fail(
        `engine abort_rate ${engineAbortRate.toFixed(3)} < floor ${ABORT_FLOOR}: contention did NOT provoke ` +
          `SSI at this scale (raise clients/ops or lower the mule count) — an inconclusive concurrency run, ` +
          `not a pass.`
      );
    }
    if (engineAbortRate > ABORT_CEIL) {
      fail(
        `engine abort_rate ${engineAbortRate.toFixed(3)} > ceil ${ABORT_CEIL}: the engine aborted almost every ` +
          `attempt (near-total livelock) — a regression in write liveness under contention.`
      );
    }
    console.log(
      `abort_rate ${engineAbortRate.toFixed(3)} within documented band [${ABORT_FLOOR}, ${ABORT_CEIL}] — ` +
        `SSI fired AND the engine progressed.`
    );

    // ---- Machine-readable evidence for run.sh. Two layers, never conflated. -------------------------
    const stats = {
      mode: RETRY ? 'managed-retry' : 'no-retry',
      clients: CLIENTS,
      writers,
      readers,
      ops_per_client: OPS,
      mule_supernodes: mules.length,
      // ENGINE layer — the contention evidence.
      engine_attempts: attempts,
      engine_aborts: engineAborts,
      engine_abort_rate: Number(engineAbortRate.toFixed(6)),
      // APPLICATION layer — the outcome a real OLTP client sees.
      business_txns: businessTxns,
      committed,
      commit_rate: Number(commitRate.toFixed(6)),
      retry_budget_exhausted: exhausted,
      hard_errors: hardErrors.length,
      retries_per_commit: Number(retriesPerCommit.toFixed(4)),
      max_retries: maxRetries,
      retry_budget_ms: RETRY_BUDGET_MS,
      // Retry-INCLUSIVE latency: what the application actually waited for its business work.
      p50_ms: percentileMs(latencyMs, 0.5),
      p99_ms: percentileMs(latencyMs, 0.99),
      p999_ms: percentileMs(latencyMs, 0.999),
      phase_secs: Number((phaseMs / 1000).toFixed(6)),
      committed_per_sec: Number((committed / (phaseMs / 1000)).toFixed(4)),
      read_ops: readOps,
      read_retries: readRetries,
      abort_floor: ABORT_FLOOR,
      abort_ceil: ABORT_CEIL,
      // What the engine ACTUALLY returns for a serialization abort, and whether the OFFICIAL driver's
      // own classifier retries it (the rmp #612 evidence). `abort_codes` is the workload's own tally —
      // EMPTY in managed-retry mode is correct and expected: executeWrite absorbs the aborts it retries,
      // so the probe is where the code becomes visible.
      probe_abort_code: probeCode,
      probe_driver_retriable: probeRetriable,
      abort_codes: Object.fromEntries(abortCodes),
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
