'use strict';
//
// matrix.js — the multi-tenant RBAC allow/deny matrix over Bolt-over-TCP+TLS, driven by the OFFICIAL
// `neo4j-driver` npm package (the exact wire path the Neo4j driver ecosystem uses). It targets a
// live server — LOCAL or REMOTE — via a full Bolt URI (e.g. `bolt+ssc://host:7687`).
//
// It drives the SAME matrix + DENY checks + cross-tenant negatives the REST client drives, from the
// SAME generator manifest.json, but over Bolt — proving the authorization decisions agree across both
// wire protocols. Provisioning + tenant/DENY seeding is done by the REST client BEFORE this runs
// (admin DDL is database-agnostic), so this script only exercises the authorization surface.
//
// HOW BOLT ENFORCES (verified, and honestly distinct from REST):
//   - WRITE deny — a denied write THROWS `Neo.ClientError.Security.Forbidden` (the write path rejects
//     the ungranted mutation up front), exactly like REST's 403.
//   - READ deny / cross-tenant read — Graphus's engine enforces reads via the FINE-GRAINED, value
//     -level RBAC filter (`AuthorizedGraph` + `EffectivePrivileges`): an ungranted label is filtered
//     out of the scan, so a cross-tenant read SUCCEEDS but returns **ZERO rows** — NO DATA LEAKS.
//   - DENY property — a `DENY READ ON PROPERTY` reads the property back as NULL for the denied user.
//   - DENY label (#645) — a `DENY TRAVERSE ON LABEL` filters the node out of EVERY scan, even one
//     keyed on the node's OTHER label; the node is invisible to the denied user, visible to the admin.
//   - unauthenticated — connecting with no credentials must fail to authenticate.
//
// On full success it prints `GRAPHUS_BOLT_RBAC_OK` and exits 0; on any mismatch it prints the
// offending cell and exits 1.
//
// Usage:
//   node matrix.js <bolt_uri> <manifest.json> <admin_user> <admin_password> <deny_supported:0|1>

const fs = require('fs');
const neo4j = require('neo4j-driver');

const [, , uri, manifestPath, adminUser, adminPassword, denyFlag] = process.argv;
if (!uri || !manifestPath || !adminUser || !adminPassword) {
  console.error('usage: node matrix.js <bolt_uri> <manifest.json> <admin_user> <admin_password> [deny_supported:0|1]');
  process.exit(2);
}
const DENY_SUPPORTED = denyFlag === '1';
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

const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
const MANIFEST_ADMIN = manifest.admin_user;

// Resolve a principal's Bolt basic-auth credentials. The manifest's canonical admin placeholder maps
// to the actual admin creds passed on argv; every other user uses its manifest password.
function credsFor(user) {
  if (user === MANIFEST_ADMIN) return { user: adminUser, password: adminPassword };
  const u = manifest.users.find((x) => x.name === user);
  return u ? { user: u.name, password: u.password } : null;
}

// Open a driver for a principal (short-lived; closed by the caller).
function driverFor(user) {
  const c = credsFor(user);
  if (!c) throw new Error(`no credentials for user ${user}`);
  return neo4j.driver(uri, neo4j.auth.basic(c.user, c.password));
}

function intVal(v) {
  if (v === null || v === undefined) return null;
  return typeof v.toNumber === 'function' ? v.toNumber() : Number(v);
}

// Run a single read query as `user` in `db`; returns {ok, code, err, records}.
async function readAs(user, db, query) {
  const driver = driverFor(user);
  const session = driver.session({ database: db, defaultAccessMode: neo4j.session.READ });
  try {
    const res = await session.run(query);
    return { ok: true, code: null, err: null, records: res.records };
  } catch (e) {
    return { ok: false, code: e.code || null, err: e.message, records: [] };
  } finally {
    await session.close();
    await driver.close();
  }
}

// --- One matrix cell (allow/deny/unauth over READ/WRITE) ------------------------------------------
async function runCell(cell) {
  const user = cell.user; // null for the unauthenticated probe
  const db = cell.tenant;
  const mode = cell.access_mode;

  if (user === null) {
    const driver = neo4j.driver(uri, neo4j.auth.basic('', ''));
    try {
      await driver.verifyConnectivity();
      return { ok: true, code: null, err: null, rows: 0 };
    } catch (e) {
      return { ok: false, code: e.code || null, err: e.message, rows: 0 };
    } finally {
      await driver.close();
    }
  }

  const driver = driverFor(user);
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
  const tableRows = [];

  // ---- The allow/deny/unauthenticated matrix ---------------------------------------------------
  for (const cell of manifest.matrix) {
    const { ok, code, err, rows: nrows } = await runCell(cell);
    const label =
      `${(cell.user || '<anon>').padStart(7)} ${cell.access_mode.padEnd(5)} ` +
      `${cell.tenant.padEnd(24)} [${cell.outcome}]`;

    let got;
    if (cell.outcome === 'allow') {
      if (cell.access_mode === 'READ') {
        check(label, ok === true && nrows >= 1, `ok=${ok} rows=${nrows} err=${err}`);
      } else {
        check(label, ok === true, err || 'expected success');
      }
      got = ok ? `allow(${nrows}r)` : 'deny';
    } else if (cell.outcome === 'deny') {
      if (cell.access_mode === 'WRITE') {
        check(label, ok === false && code === FORBIDDEN, `code=${code} err=${err}`);
        got = ok ? 'allow' : 'deny';
      } else {
        // Denied/cross-tenant read → value-level filter → SUCCEEDS with ZERO rows (no leak).
        check(label, ok === true && nrows === 0, `ok=${ok} rows=${nrows} (must be 0 — no leak)`);
        got = ok ? `empty(${nrows}r)` : 'error';
      }
    } else {
      check(label, ok === false, err || 'expected auth failure');
      got = ok ? 'allow' : 'deny';
    }
    tableRows.push([cell.user || '<anon>', cell.tenant, cell.access_mode, cell.outcome,
                    got, code || '-', cell.why]);
  }

  // ---- Broadened cross-tenant negatives (alice -> tenant_b) ------------------------------------
  const reader = (manifest.users.find((u) => u.role === manifest.roles[0].name) || {}).name;
  const otherTenant = manifest.tenants[1].database; // tenant_b
  const probes = manifest.cross_tenant_probes || [];
  let xtAsserted = 0;
  let xtEmpty = 0;
  if (reader && probes.length) {
    console.log('  -- cross-tenant negatives (value-level filter => zero rows / count 0)');
    for (const p of probes) {
      const r = await readAs(reader, otherTenant, p.query);
      const label = `XTENANT ${reader.padStart(7)} -> ${otherTenant.padEnd(24)} [${p.kind}] — ${p.why}`;
      if (p.kind === 'count') {
        const n = r.ok && r.records.length ? intVal(r.records[0].get('v')) : null;
        const good = r.ok && n === 0;
        if (good) xtEmpty += 1;
        check(label, good, `ok=${r.ok} count=${n} err=${r.err}`);
      } else {
        const good = r.ok && r.records.length === 0;
        if (good) xtEmpty += 1;
        check(label, good, `ok=${r.ok} rows=${r.records.length} err=${r.err}`);
      }
      xtAsserted += 1;
    }
  }

  // ---- Fine-grained DENY checks (only if the target's grammar supports DENY) --------------------
  let denyAsserted = 0;
  if (DENY_SUPPORTED && (manifest.deny_checks || []).length) {
    console.log('  -- fine-grained DENY (property NULL + label-invisible; #645 precedence guard)');
    for (const c of manifest.deny_checks) {
      const asUser = await readAs(c.user, c.tenant, c.query);
      const asAdmin = await readAs(MANIFEST_ADMIN, c.tenant, c.query);
      const label = `DENY ${c.kind.padEnd(14)} ${c.user.padStart(7)} ${c.tenant.padEnd(24)} — ${c.why}`;
      if (c.kind === 'property_null') {
        const uAllNull =
          asUser.ok && asUser.records.length > 0 &&
          asUser.records.every((r) => r.get('v') === null);
        const aHasVal =
          asAdmin.ok && asAdmin.records.some((r) => r.get('v') !== null);
        check(label, uAllNull && aHasVal,
              `user ok=${asUser.ok} rows=${asUser.records.length} | admin ok=${asAdmin.ok} rows=${asAdmin.records.length}`);
      } else {
        // node_invisible: denied user sees zero rows, admin sees at least one.
        const uHidden = asUser.ok && asUser.records.length === 0;
        const aVisible = asAdmin.ok && asAdmin.records.length >= 1;
        check(label, uHidden && aVisible,
              `user ok=${asUser.ok} rows=${asUser.records.length} | admin ok=${asAdmin.ok} rows=${asAdmin.records.length}`);
      }
      denyAsserted += 1;
    }
  } else if ((manifest.deny_checks || []).length) {
    console.log('  ·   DENY not supported by target — cross-protocol DENY checks skipped (version gap)');
  }

  // ---- Table -----------------------------------------------------------------------------------
  console.log('');
  console.log(`  ${'USER'.padEnd(9)}${'TENANT'.padEnd(26)}${'MODE'.padEnd(6)}` +
              `${'EXPECT'.padEnd(8)}${'GOT'.padEnd(11)}${'CODE'.padEnd(42)}WHY`);
  for (const [user, tenant, mode, outcome, got, code, why] of tableRows) {
    console.log(`  ${user.padEnd(9)}${tenant.padEnd(26)}${mode.padEnd(6)}` +
                `${outcome.padEnd(8)}${got.padEnd(11)}${code.padEnd(42)}${why}`);
  }

  if (FAILURES === 0) {
    console.log(`GRAPHUS_BOLT_STATS {"cross_tenant_probes":${xtAsserted},"cross_tenant_empty":${xtEmpty},"deny_checks":${denyAsserted}}`);
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
