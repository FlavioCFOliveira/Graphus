'use strict';
//
// matrix.js — the multi-tenant RBAC allow/deny matrix over Bolt-over-TCP+TLS, driven by the OFFICIAL
// `neo4j-driver` npm package (the exact wire path the Neo4j driver ecosystem uses).
//
// It drives the SAME matrix the REST client drives, from the SAME generator manifest.json, but over
// Bolt — proving the authorization decisions agree across both wire protocols:
//   - each user authenticates with their OWN basic-auth credentials (user/password from the
//     manifest; the bootstrap admin uses the password passed on argv),
//   - the tenant is selected per session via `session({database: <tenant>})`,
//   - a READ cell runs a read probe in a READ session; a WRITE cell runs a write probe in a WRITE
//     session.
//
// HOW BOLT ENFORCES (verified, and honestly distinct from REST):
//   - WRITE deny — a denied write THROWS `Neo.ClientError.Security.Forbidden` (the write path
//     rejects the ungranted mutation up front), exactly like REST's 403.
//   - READ deny / cross-tenant read — Graphus's engine enforces reads via the FINE-GRAINED, value
//     -level RBAC filter (`AuthorizedGraph` + `EffectivePrivileges`): an ungranted label is filtered
//     out of the scan, so a cross-tenant read SUCCEEDS but returns **ZERO rows** — NO DATA LEAKS.
//     (REST additionally has a coarse up-front gate that turns this into a 403; Bolt relies on the
//     filter, which returns empty instead of erroring. Either way the sensitive data is never
//     returned across the tenant boundary.) So this client asserts a `deny` READ cell returns
//     **zero rows**, and an `allow` READ cell returns **≥1 row** (the canary `:Secret`) — proving
//     the filter denies the wrong tenant while serving the right one.
//   - unauthenticated — connecting with no credentials must fail to authenticate.
//
// Provisioning + tenant seeding is done by the REST client BEFORE this runs (admin DDL is
// database-agnostic), so this script only exercises the authorization matrix.
//
// On full success it prints `GRAPHUS_BOLT_RBAC_OK` and exits 0; on any mismatch it prints the
// offending cell and exits 1.
//
// Usage:
//   node matrix.js <port> <manifest.json> <admin_user> <admin_password>

const fs = require('fs');
const neo4j = require('neo4j-driver');

const [, , port, manifestPath, adminUser, adminPassword] = process.argv;
if (!port || !manifestPath || !adminUser || !adminPassword) {
  console.error('usage: node matrix.js <port> <manifest.json> <admin_user> <admin_password>');
  process.exit(2);
}

const uri = `bolt+ssc://127.0.0.1:${port}`;
const FORBIDDEN = 'Neo.ClientError.Security.Forbidden';
const READ_PROBE = 'MATCH (s:Secret) RETURN s.name AS name';
const WRITE_PROBE = 'CREATE (:RbacProbe {ts: 1})';

let FAILURES = 0;
function check(name, ok, detail) {
  if (ok) {
    console.log(`  OK  ${name}`);
  } else {
    FAILURES += 1;
    console.log(`  BAD ${name}${detail ? ' :: ' + detail : ''}`);
  }
}

// Resolve a user's password from the manifest (the admin's comes from argv).
function passwordFor(manifest, user) {
  if (user === adminUser) return adminPassword;
  const u = manifest.users.find((x) => x.name === user);
  return u ? u.password : null;
}

// Run one matrix cell over Bolt. Returns {ok, code, err, rows} where `ok` is whether the op
// SUCCEEDED and `rows` is the row count returned by a READ (so a filtered-to-empty cross-tenant read
// is distinguishable from an allowed read that returns the canary).
async function runCell(manifest, cell) {
  const user = cell.user; // null for the unauthenticated probe
  const db = cell.tenant;
  const mode = cell.access_mode;

  // Unauthenticated probe: connect with no/bad credentials — authentication must fail.
  if (user === null) {
    const driver = neo4j.driver(uri, neo4j.auth.basic('', ''));
    try {
      await driver.verifyConnectivity();
      return { ok: true, code: null, err: null, rows: 0 }; // unexpected: connected without creds
    } catch (e) {
      return { ok: false, code: e.code || null, err: e.message, rows: 0 };
    } finally {
      await driver.close();
    }
  }

  const password = passwordFor(manifest, user);
  const driver = neo4j.driver(uri, neo4j.auth.basic(user, password));
  const accessMode = mode === 'READ' ? neo4j.session.READ : neo4j.session.WRITE;
  const session = driver.session({ database: db, defaultAccessMode: accessMode });
  try {
    if (mode === 'READ') {
      const res = await session.run(READ_PROBE);
      return { ok: true, code: null, err: null, rows: res.records.length };
    }
    await session.run(WRITE_PROBE);
    return { ok: true, code: null, err: null, rows: 0 };
  } catch (e) {
    return { ok: false, code: e.code || null, err: e.message, rows: 0 };
  } finally {
    await session.close();
    await driver.close();
  }
}

(async () => {
  const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
  const rows = [];

  for (const cell of manifest.matrix) {
    const { ok, code, err, rows: nrows } = await runCell(manifest, cell);
    const label =
      `${(cell.user || '<anon>').padStart(6)} ${cell.access_mode.padEnd(5)} ` +
      `${cell.tenant.padEnd(9)} [${cell.outcome}]`;

    let got;
    if (cell.outcome === 'allow') {
      if (cell.access_mode === 'READ') {
        // An allowed read must succeed AND return the canary (≥1 row) — the right tenant is served.
        check(label, ok === true && nrows >= 1, `ok=${ok} rows=${nrows} err=${err}`);
      } else {
        check(label, ok === true, err || 'expected success');
      }
      got = ok ? `allow(${nrows}r)` : 'deny';
    } else if (cell.outcome === 'deny') {
      if (cell.access_mode === 'WRITE') {
        // A denied write must THROW the Forbidden authorization code.
        check(label, ok === false && code === FORBIDDEN, `code=${code} err=${err}`);
        got = ok ? 'allow' : 'deny';
      } else {
        // A denied/cross-tenant read is enforced by the value-level RBAC filter: it SUCCEEDS but
        // returns ZERO rows — no data crosses the tenant boundary (the canary is filtered out).
        check(label, ok === true && nrows === 0, `ok=${ok} rows=${nrows} (must be 0 — no leak)`);
        got = ok ? `empty(${nrows}r)` : 'error';
      }
    } else {
      // unauthenticated: must have failed to authenticate (any auth error is acceptable).
      check(label, ok === false, err || 'expected auth failure');
      got = ok ? 'allow' : 'deny';
    }
    rows.push([cell.user || '<anon>', cell.tenant, cell.access_mode, cell.outcome,
               got, code || '-', cell.why]);
  }

  // Pretty matrix table.
  console.log('');
  console.log(`  ${'USER'.padEnd(7)}${'TENANT'.padEnd(11)}${'MODE'.padEnd(6)}` +
              `${'EXPECT'.padEnd(8)}${'GOT'.padEnd(7)}${'CODE'.padEnd(42)}WHY`);
  console.log(`  ${'-'.repeat(7)}${'-'.repeat(11)}${'-'.repeat(6)}${'-'.repeat(8)}` +
              `${'-'.repeat(7)}${'-'.repeat(42)}${'-'.repeat(30)}`);
  for (const [user, tenant, mode, outcome, got, code, why] of rows) {
    console.log(`  ${user.padEnd(7)}${tenant.padEnd(11)}${mode.padEnd(6)}` +
                `${outcome.padEnd(8)}${got.padEnd(7)}${code.padEnd(42)}${why}`);
  }

  if (FAILURES === 0) {
    console.log('GRAPHUS_BOLT_RBAC_OK');
    process.exit(0);
  } else {
    console.error(`GRAPHUS_BOLT_RBAC_FAILED — ${FAILURES} cell(s) did not hold`);
    process.exit(1);
  }
})().catch((err) => {
  console.error('matrix.js fatal: ' + (err && err.stack ? err.stack : String(err)));
  process.exit(1);
});
