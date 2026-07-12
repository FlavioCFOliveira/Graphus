'use strict';
//
// analyze.js — the Graph-Data-Science analytics workload, driven over Bolt (+TLS) with the OFFICIAL
// `neo4j-driver` npm package (the exact wire path the Neo4j driver ecosystem uses).
//
// It runs UNCHANGED against a self-booted local server OR an already-running instance (local or
// remote, e.g. a staging or production host): the caller passes a full Bolt URI and — for the attach path — the name of the
// run-scoped, isolated database the harness carved out. Every session is bound to that database.
//
// What it exercises (rmp #690):
//   1. connects (bolt:// or bolt+ssc:// for a self-signed target) and pins every session to --database,
//   2. TEARS DOWN first (DETACH DELETE :Author/:Ref + drop leftover GDS projections) so a second
//      consecutive run against the SAME database is clean — the workload is idempotent and safe-on-shared,
//   3. loads the schema DDL + the generated influence network from graph.cypher. The schema DDL is
//      IDEMPOTENT (`IF NOT EXISTS`) and applied VERSION-TOLERANTLY: a statement an older server cannot
//      parse (named/relationship indexes, `IF NOT EXISTS`) is skipped with a note, so the SAME script
//      loads on a current build and on an older instance alike,
//   4. asserts the analytically-known reference-subgraph ground truth (reference.json) via gds.*.stream,
//   5. runs a WEIGHTED-vs-UNWEIGHTED comparison — the headline of a real GDS workload: weighted vs
//      unweighted PageRank rankings, and weighted vs unweighted Dijkstra distances (relationshipWeight-
//      Property='weight'), asserting the two genuinely differ and reporting the top rankings,
//   6. streams the FULL (nodeId, score) result set of weighted PageRank (no count(*) collapse),
//   7. exercises the WRITE / MUTATE / STATS execution modes when the server registers them (feature-
//      detected): gds.pageRank.write{writeProperty:'pagerank'} then a MATCH…WHERE pagerank>x ORDER BY
//      readback asserting nodePropertiesWritten==authorCount; gds.pageRank.stats asserting a summary
//      field; gds.pageRank.mutate then gds.graph.nodeProperty.stream readback,
//   8. tears down again (drops projections + DETACH DELETE) and reports machine-readable stats.
//
// On full success it prints `GRAPHUS_GDS_OK` and exits 0; on any assertion mismatch it prints a clear
// diagnosis and exits 1. Skips (older-server capability gaps) are printed but never fail the run.
//
// IMPORTANT — verified procedure-surface facts (empirically confirmed against the real engine):
//   * gds.* procedures use STRICT ARITY: `gds.graph.project` needs 4 args (name, nodeFilter,
//     relFilter, config) and every `gds.*.stream` needs 2 (name, config). A trailing `{}` / null is
//     mandatory, never omitted.
//   * `relationshipWeightProperty` is a PROJECTION-time config: a graph projected with it is weighted,
//     and PageRank / Dijkstra / closeness then use the weights. betweenness is Brandes over UNWEIGHTED
//     BFS in this engine (it ignores weights — see crates/graphus-gds/src/algo/centrality.rs), so we
//     deliberately do NOT claim a weighted betweenness.
//   * The streamed `nodeId` is the engine's INTERNAL node id, not the `id` property; we read the
//     id<->property mapping with `MATCH (a:Author) RETURN id(a), a.id` and translate.
//   * The .write/.stats/.mutate execution modes and gds.graph.nodeProperty.stream are a newer surface
//     (rmp #643); an older instance may not register them, so we feature-detect and skip cleanly.
//
//   9. PER-ALGORITHM SERVER CPU (rmp #717) — the battery that answers "does GDS actually use the
//      cores?". See the block comment above `cpuBattery` below.
//
// Usage:
//   node analyze.js --uri <bolt-uri> --user <u> --password <p> [--database <db>] \
//                   --graph <graph.cypher> --reference <reference.json> [--skip-load] \
//                   [--server-pid <pid> --proc-watch <path> --algo-cpu-out <file>]

const fs = require('fs');
const { execFileSync } = require('child_process');
const os = require('os');
const neo4j = require('neo4j-driver');

// ---- CLI ---------------------------------------------------------------------------------------
function parseArgs(argv) {
  const out = {
    uri: '', user: '', password: '', database: '', graph: '', reference: '',
    skipLoad: false, serverPid: '', procWatch: '', algoCpuOut: '', cpuTargetSecs: 1.0,
  };
  for (let i = 0; i < argv.length; i += 1) {
    const a = argv[i];
    const next = () => argv[(i += 1)];
    switch (a) {
      case '--uri': out.uri = next(); break;
      case '--user': out.user = next(); break;
      case '--password': out.password = next(); break;
      case '--database': out.database = next(); break;
      case '--graph': out.graph = next(); break;
      case '--reference': out.reference = next(); break;
      // The graph is already in the database (the LOCAL run bulk-imports it over the network
      // bulk-import Mode A endpoint, which is ~35x faster than replaying graph.cypher edge by edge).
      case '--skip-load': out.skipLoad = true; break;
      // The per-algorithm SERVER CPU battery. All three must be present, and the pid must be a server
      // on THIS host: they are what makes the CPU figure the server's rather than this driver's.
      case '--server-pid': out.serverPid = next(); break;
      case '--proc-watch': out.procWatch = next(); break;
      case '--algo-cpu-out': out.algoCpuOut = next(); break;
      case '--cpu-target-secs': out.cpuTargetSecs = Number(next()); break;
      default:
        console.error(`analyze.js: unknown argument '${a}'`);
        process.exit(2);
    }
  }
  return out;
}

const args = parseArgs(process.argv.slice(2));
if (!args.uri || !args.user || !args.password || !args.graph || !args.reference) {
  console.error(
    'usage: node analyze.js --uri <bolt-uri> --user <u> --password <p> [--database <db>] ' +
      '--graph <graph.cypher> --reference <reference.json> [--skip-load] ' +
      '[--server-pid <pid> --proc-watch <path> --algo-cpu-out <file>]'
  );
  process.exit(2);
}
// The battery is all-or-nothing: a half-configured battery would silently produce no evidence.
const BATTERY = Boolean(args.serverPid && args.procWatch && args.algoCpuOut);
if (!BATTERY && (args.serverPid || args.procWatch || args.algoCpuOut)) {
  console.error(
    'analyze.js: --server-pid, --proc-watch and --algo-cpu-out must be given together (the ' +
      'per-algorithm CPU battery needs a co-located server pid, the sampler, and somewhere to write)'
  );
  process.exit(2);
}

const toNum = (v) => (neo4j.isInt(v) ? v.toNumber() : v);

// PageRank float comparison tolerance (the engine returns IEEE-754 doubles; assertions on equality
// use this epsilon, never bit-exact).
const PR_EPSILON = 1e-9;
// The magnitude a weighted score must differ from its unweighted counterpart to count as "changed".
const WEIGHT_DELTA = 1e-6;

// ---- Evidence: per-operation latency sample + nearest-rank percentiles (ms) --------------------
const latenciesMs = [];
const hrMs = () => Number(process.hrtime.bigint() / 1000n) / 1000;
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
  console.error('GDS ANALYTICS FAILURE: ' + msg);
  process.exit(1);
}

// ---- The per-algorithm SERVER-CPU battery (rmp #717) --------------------------------------------
//
// The question this example exists to answer is "**does GDS actually use the cores?**", and until now
// nothing here could answer it. The run-level `cpu.mean_core_utilisation` is an average over the whole
// run — a 60 ms algorithm call that saturates fourteen cores vanishes into an 8-second load phase that
// used one — which is precisely how the project came to carry the unmeasured folklore that "GDS uses
// 2 of 9 cores".
//
// So we measure each algorithm SEPARATELY, and we measure the SERVER, not this driver:
//
//   before = proc_watch --pid <server> --snapshot     # the pid's CUMULATIVE cpu counters
//   t0 = now;  <call the algorithm R times over Bolt>;  t1 = now
//   after  = proc_watch --pid <server> --snapshot
//   cores  = (after.cpu - before.cpu) / (t1 - t0)
//
// Three properties make the number trustworthy:
//
//   * `utime`/`stime` are cumulative COUNTERS, so the bracket yields the exact CPU the server burned
//     between the two reads — no sampling, nothing missed.
//   * The server is otherwise idle across the bracket (this driver is serial), so all of that CPU is
//     this algorithm's.
//   * R is chosen ADAPTIVELY so the window is ≥ CPU_TARGET_SECS: the OS accounts CPU in 10 ms ticks,
//     so a single 2.6 ms `gds.wcc.stream` call measures a CPU delta of *zero ticks* and would publish
//     `0.0 cores` — a fabricated zero for an algorithm that did work. Repeating it until the window is
//     ~1 s puts the quantisation error under 1%.
//
// An algorithm whose CPU delta is STILL under five ticks reports NO cpu figure at all (absent, with a
// reason) rather than a zero: measure it or omit it (`examples/README.md`, evidence-honesty rule 1).
const CPU_MIN_MEASURABLE_SECS = 0.05; // five 10 ms clock ticks — must match PhaseTiming::with_cpu
const CPU_MIN_REPEATS = 3;
const CPU_MAX_REPEATS = 400;

// One cumulative CPU + RSS reading of the SERVER process, via the shared `proc_watch` seam.
function serverSnapshot() {
  const out = execFileSync(args.procWatch, ['--pid', args.serverPid, '--snapshot'], {
    encoding: 'utf8',
  });
  return JSON.parse(out);
}

const secs = () => Number(process.hrtime.bigint()) / 1e9;

// Order-independent set equality on number arrays.
function sameSet(a, b) {
  if (a.length !== b.length) return false;
  const sa = new Set(a);
  for (const x of b) if (!sa.has(x)) return false;
  return true;
}

// An error the CURRENT server cannot honour because it is an OLDER build (unknown procedure, or a
// newer DDL surface it cannot parse). Such statements are skipped, never fatal — the same script must
// run on a current build and on an older instance alike.
function isCapabilityGap(e) {
  const m = (e && (e.message || String(e))) || '';
  const code = (e && e.code) || '';
  return (
    m.includes('no procedure registered') ||
    m.includes('there is no procedure') ||
    code === 'Neo.ClientError.Statement.SyntaxError' ||
    m.includes('compile-time error') ||
    /unexpected `/.test(m)
  );
}

// A benign "the object already exists" schema outcome — treated as idempotent success on a server that
// does not support `IF NOT EXISTS` (so a second consecutive run against a shared DB still passes).
function isAlreadyExists(e) {
  const m = (e && (e.message || String(e))) || '';
  return /already exists|equivalent (constraint|index)|already declared/i.test(m);
}

// Split a .cypher script into individual statements on `;`; drop `//` comment lines.
function statements(script) {
  return script
    .split('\n')
    .filter((line) => !line.trimStart().startsWith('//'))
    .join('\n')
    .split(';')
    .map((s) => s.trim())
    .filter((s) => s.length > 0);
}

// Schema DDL: any `CREATE CONSTRAINT …` or any `CREATE … INDEX …` (mirrors the server tests' filter).
function isSchemaDdl(stmt) {
  return (
    stmt.startsWith('CREATE CONSTRAINT') ||
    (stmt.startsWith('CREATE') && stmt.includes(' INDEX '))
  );
}

(async () => {
  const script = fs.readFileSync(args.graph, 'utf8');
  const ref = JSON.parse(fs.readFileSync(args.reference, 'utf8'));

  const driver = neo4j.driver(args.uri, neo4j.auth.basic(args.user, args.password));
  const sess = () => (args.database ? driver.session({ database: args.database }) : driver.session());

  // Run a read/proc query, returning the raw records.
  async function runQuery(query, params) {
    const s = sess();
    try {
      const r = await timed(() => s.run(query, params || {}));
      return r.records;
    } finally {
      await s.close();
    }
  }

  // Run a statement that may not be supported by an older server. Returns {ok, records, err}.
  async function runOptional(query, params) {
    const s = sess();
    try {
      const r = await timed(() => s.run(query, params || {}));
      return { ok: true, records: r.records };
    } catch (e) {
      return { ok: false, err: e };
    } finally {
      await s.close();
    }
  }

  // Like `runOptional`, but the call is NOT added to the workload's latency sample.
  //
  // The CPU battery repeats one algorithm hundreds of times — including a 1-second weighted closeness
  // — purely to open a CPU-measurement window. Folding those calls into the workload's percentiles
  // would report the INSTRUMENT's latency as the workload's: the first cut of this battery pushed the
  // run's p999 to 1 066 ms, which is the weighted-closeness *probe*, not anything a user of this
  // workload would ever wait for. The battery's own per-call cost is reported separately (and
  // honestly) as `ms_per_call` in algo_cpu.json.
  async function runRaw(query, params) {
    const s = sess();
    try {
      const r = await s.run(query, params || {});
      return { ok: true, records: r.records };
    } catch (e) {
      return { ok: false, err: e };
    } finally {
      await s.close();
    }
  }

  // Drop a GDS projection if it exists (never fatal).
  async function dropGraph(name) {
    await runOptional(`CALL gds.graph.drop('${name}') YIELD graphName RETURN graphName`);
  }

  // Drop every registered GDS projection (idempotent teardown of the in-memory catalog).
  async function dropAllProjections() {
    const r = await runOptional('CALL gds.graph.list() YIELD graphName RETURN graphName');
    if (!r.ok) return; // older server without gds.graph.list — nothing we can enumerate
    for (const rec of r.records) {
      await dropGraph(rec.get('graphName'));
    }
  }

  // DETACH DELETE the example's own nodes (clean slate). Safe on an empty database.
  async function deleteExampleData() {
    for (const label of ['Author', 'Ref']) {
      await runOptional(`MATCH (n:${label}) DETACH DELETE n`);
    }
  }

  try {
    await driver.verifyConnectivity();
    console.log(`connected: ${args.uri}  database=${args.database || '(home)'}`);

    // =============================================================================================
    // 0. TEARDOWN-FIRST — idempotent, safe-on-shared. A second consecutive run starts from a clean
    //    slate whether the target is a fresh isolated DB or an operator-owned shared DB.
    //
    //    Skipped under --skip-load: the caller has just bulk-imported the graph into a database it
    //    created for this run, so a DETACH DELETE here would delete exactly the graph we came to
    //    analyse.
    // =============================================================================================
    if (!args.skipLoad) {
      await dropAllProjections();
      await deleteExampleData();
    }

    // =============================================================================================
    // 1. LOAD — schema (idempotent + version-tolerant) then data (batched write transactions).
    //
    //    The SCHEMA is applied in both modes (it is idempotent and it is what the constraint-
    //    enforcement demo below keys on). The DATA statements are replayed only when the graph was
    //    not already loaded: under --skip-load the LOCAL run has ingested it through the network
    //    bulk-import endpoint (Mode A) instead — measured on a 16-core host at the default
    //    `moderate` profile, that path ingests 2 406 nodes + 23 962 relationships in **0.20 s**,
    //    where replaying the same graph as one `MATCH … MATCH … CREATE` per edge takes **~8 s**
    //    (~35x). The Cypher path stays exactly as it was for the ATTACH run, whose target may expose
    //    no bulk-import endpoint (or no admin rights on it).
    // =============================================================================================
    const stmts = statements(script);
    const schema = stmts.filter(isSchemaDdl);
    const data = args.skipLoad ? [] : stmts.filter((s) => !isSchemaDdl(s));

    // Schema DDL runs auto-commit (admin DDL is rejected inside an explicit txn). Each application is
    // version-tolerant. On a current build every form (named + relationship indexes, `IF NOT EXISTS`)
    // applies directly and is idempotent. On an OLDER instance that cannot parse `IF NOT EXISTS`, we
    // retry the plain form (recovering, e.g., the named CONSTRAINTs an older build still supports);
    // a form the old build cannot parse at all (named/relationship indexes) is skipped with a note.
    // An "already exists" outcome (a re-run against a shared DB with no `IF NOT EXISTS`) is benign.
    const createdConstraints = new Set();
    const noteApplied = (stmt) => {
      const m = stmt.match(/^CREATE CONSTRAINT (\w+)/);
      if (m) createdConstraints.add(m[1]);
    };
    // Apply one schema statement. Returns 'applied' | 'skipped' (never throws for a capability gap).
    async function applySchema(stmt) {
      let r = await runOptional(stmt);
      if (r.ok || isAlreadyExists(r.err)) { noteApplied(stmt); return 'applied'; }
      if (!isCapabilityGap(r.err)) fail(`schema statement failed: ${stmt.slice(0, 120)}\n  ${r.err.message}`);
      // Older server: if the clause is `IF NOT EXISTS`, retry the plain form.
      if (/ IF NOT EXISTS /.test(stmt)) {
        const plain = stmt.replace(' IF NOT EXISTS ', ' ');
        r = await runOptional(plain);
        if (r.ok || isAlreadyExists(r.err)) { noteApplied(plain); return 'applied'; }
        if (!isCapabilityGap(r.err)) fail(`schema statement failed: ${plain.slice(0, 120)}\n  ${r.err.message}`);
      }
      console.log(`  · schema skipped (server capability gap): ${stmt.slice(0, 68)}…`);
      return 'skipped';
    }
    // The schema DDL is bracketed against the SERVER's own counters, because building an index is
    // where this server spends memory it never gives back: a RANGE index over the default profile's
    // 23 962 :CITES relationships costs ~160 MB of RESIDENT server memory, and it scales linearly with
    // the indexed element count (~7.8 KB per indexed element — see `rmp` #724, which this example's
    // own evidence is what surfaced). An example that declares a realistic schema and never looks at
    // what it cost would hide exactly the fragility it exists to expose.
    let schemaApplied = 0;
    let schemaSkipped = 0;
    let schemaDdl = null;
    const ddlBefore = BATTERY ? serverSnapshot() : null;
    const ddlT0 = secs();
    for (const stmt of schema) {
      if ((await applySchema(stmt)) === 'applied') schemaApplied += 1;
      else schemaSkipped += 1;
    }
    const ddlWall = secs() - ddlT0;
    if (BATTERY) {
      const ddlAfter = serverSnapshot();
      schemaDdl = {
        statements_applied: schemaApplied,
        statements_skipped: schemaSkipped,
        wall_secs: Number(ddlWall.toFixed(4)),
        cpu_secs: Number(
          (ddlAfter.user_secs - ddlBefore.user_secs + (ddlAfter.system_secs - ddlBefore.system_secs))
            .toFixed(4)
        ),
        server_rss_before_bytes: ddlBefore.rss_bytes,
        server_rss_after_bytes: ddlAfter.rss_bytes,
        server_rss_delta_bytes: ddlAfter.rss_bytes - ddlBefore.rss_bytes,
      };
    }
    console.log(`schema: ${schemaApplied} applied, ${schemaSkipped} skipped (older-server DDL gaps)`);
    if (schemaDdl) {
      console.log(
        `  schema DDL cost the SERVER ${(schemaDdl.server_rss_delta_bytes / 1048576).toFixed(1)} MB of ` +
          `RESIDENT memory (${(schemaDdl.server_rss_before_bytes / 1048576).toFixed(1)} -> ` +
          `${(schemaDdl.server_rss_after_bytes / 1048576).toFixed(1)} MB) and ${schemaDdl.cpu_secs.toFixed(2)} s of CPU`
      );
    }

    // Data CREATEs load in batched write transactions (far fewer round-trips than one-at-a-time —
    // important over a network link). Each batch is one commit.
    const BATCH = 250;
    let loaded = 0;
    for (let i = 0; i < data.length; i += BATCH) {
      const chunk = data.slice(i, i + BATCH);
      const s = sess();
      try {
        await timed(() =>
          s.executeWrite(async (tx) => {
            for (const stmt of chunk) await tx.run(stmt);
          })
        );
        loaded += chunk.length;
      } catch (e) {
        fail(`data load failed near statement #${loaded + 1}: ${e.message}`);
      } finally {
        await s.close();
      }
    }
    if (args.skipLoad) {
      console.log('data load SKIPPED (--skip-load): the graph was bulk-imported over the network ' +
        'bulk-import endpoint before this driver started');
    } else {
      console.log(`loaded ${loaded} data statements (influence network + reference subgraph)`);
    }

    const authorCount = toNum(
      (await runQuery('MATCH (a:Author) RETURN count(a) AS c'))[0].get('c')
    );
    console.log(`authors loaded: ${authorCount}`);
    if (authorCount === 0) fail('no authors were loaded — the data load did not reach this database');

    // Internal nodeId <-> author id property mapping (the .stream surface returns internal ids).
    const authNidToPid = new Map();
    for (const rec of await runQuery('MATCH (a:Author) RETURN id(a) AS nid, a.id AS pid')) {
      authNidToPid.set(toNum(rec.get('nid')), toNum(rec.get('pid')));
    }
    const authPid = (nid) => {
      const p = authNidToPid.get(nid);
      if (p === undefined) fail(`internal nodeId ${nid} has no :Author mapping`);
      return p;
    };

    // =============================================================================================
    // 1b. CONSTRAINT ENFORCEMENT (feature-gated on the constraint having actually been created).
    // =============================================================================================
    if (createdConstraints.has('author_field_name_string')) {
      const s = sess();
      let rejected = false;
      let rejMsg = '';
      try {
        await s.run(
          "CREATE (:Author {id: 9999999, name: 'bad', field: 0, field_name: 123, h_index: 5})"
        );
      } catch (e) {
        rejected = true;
        rejMsg = (e.message || String(e)).split('\n')[0].slice(0, 120);
      } finally {
        await s.close();
      }
      if (!rejected) fail('constraint enforcement broken: a non-string field_name was ACCEPTED');
      const after = toNum((await runQuery('MATCH (a:Author) RETURN count(a) AS c'))[0].get('c'));
      if (after !== authorCount) fail(`rejected write leaked: author count ${after} != ${authorCount}`);
      console.log(`  ✓ property-type constraint rejected a non-string field_name: ${rejMsg}`);
    } else {
      console.log('  · constraint-enforcement demo skipped (no property-type constraint on this server)');
    }

    // =============================================================================================
    // 2. THE REFERENCE SUBGRAPH — analytically-known ground truth (gds.*.stream).
    // =============================================================================================
    console.log('\n-- reference subgraph (analytically-known ground truth) --');
    const refNidToPid = new Map();
    const refPidToNid = new Map();
    for (const rec of await runQuery('MATCH (r:Ref) RETURN id(r) AS nid, r.id AS pid')) {
      const nid = toNum(rec.get('nid'));
      const pid = toNum(rec.get('pid'));
      refNidToPid.set(nid, pid);
      refPidToNid.set(pid, nid);
    }
    const refPid = (nid) => {
      const p = refNidToPid.get(nid);
      if (p === undefined) fail(`internal nodeId ${nid} has no :Ref mapping`);
      return p;
    };

    await runQuery(
      "CALL gds.graph.project('ref','Ref','LINKS',{}) YIELD nodeCount, relationshipCount RETURN nodeCount, relationshipCount"
    );

    // (a) WCC: one component = the reference ids.
    const wccByComp = new Map();
    for (const rec of await runQuery(
      "CALL gds.wcc.stream('ref',{}) YIELD nodeId, componentId RETURN nodeId, componentId"
    )) {
      const pid = refPid(toNum(rec.get('nodeId')));
      const comp = toNum(rec.get('componentId'));
      if (!wccByComp.has(comp)) wccByComp.set(comp, []);
      wccByComp.get(comp).push(pid);
    }
    if (wccByComp.size !== 1) fail(`reference WCC expected 1 component, got ${wccByComp.size}`);
    const wccMembers = [...wccByComp.values()][0].sort((x, y) => x - y);
    if (!sameSet(wccMembers, ref.component)) {
      fail(`reference WCC partition mismatch: got ${JSON.stringify(wccMembers)} exp ${JSON.stringify(ref.component)}`);
    }
    console.log(`  WCC: 1 component = ${JSON.stringify(wccMembers)} (matches ground truth)`);

    // (b) Degree sequence.
    const gotDeg = (
      await runQuery("CALL gds.degree.stream('ref',{}) YIELD nodeId, score RETURN nodeId, score")
    )
      .map((r) => [refPid(toNum(r.get('nodeId'))), Math.round(toNum(r.get('score')))])
      .sort((a, b) => a[0] - b[0]);
    const expDeg = [...ref.degrees].sort((a, b) => a[0] - b[0]);
    if (JSON.stringify(gotDeg) !== JSON.stringify(expDeg)) {
      fail(`reference degree mismatch: got ${JSON.stringify(gotDeg)} exp ${JSON.stringify(expDeg)}`);
    }
    console.log(`  degree: ${JSON.stringify(gotDeg)} (matches ground truth)`);

    // (c) Betweenness: the two bridge endpoints are strictly highest.
    const btw = (
      await runQuery(
        "CALL gds.betweenness.stream('ref',{}) YIELD nodeId, score RETURN nodeId, score"
      )
    )
      .map((r) => ({ id: refPid(toNum(r.get('nodeId'))), s: toNum(r.get('score')) }))
      .sort((a, b) => b.s - a.s);
    const topBtw = btw.slice(0, 2).map((x) => x.id).sort((x, y) => x - y);
    const restMax = Math.max(...btw.slice(2).map((x) => x.s));
    if (!sameSet(topBtw, ref.top_betweenness_nodes)) {
      fail(`reference top-betweenness mismatch: got ${JSON.stringify(topBtw)} exp ${JSON.stringify(ref.top_betweenness_nodes)}`);
    }
    if (!(btw[1].s > restMax)) fail(`betweenness not strictly separated: 2nd=${btw[1].s} restMax=${restMax}`);
    console.log(`  betweenness: top-2 = ${JSON.stringify(topBtw)} (bridge endpoints, highest at ${btw[0].s.toFixed(1)})`);

    // (d) triangleCount: two planted 3-cliques => every node in exactly one triangle.
    const tri = (
      await runQuery(
        "CALL gds.triangleCount.stream('ref',{}) YIELD nodeId, triangleCount RETURN nodeId, triangleCount"
      )
    ).map((r) => toNum(r.get('triangleCount')));
    if (tri.length !== 6 || !tri.every((t) => t === 1)) {
      fail(`reference triangleCount expected six nodes each in one triangle, got ${JSON.stringify(tri)}`);
    }
    console.log('  triangleCount: all 6 nodes in exactly 1 triangle (two planted 3-cliques)');
    await dropGraph('ref');

    // (e) Dijkstra hop distances from b0 over the undirected projection.
    await runQuery("CALL gds.graph.project('refp','Ref','LINKS',{}) YIELD nodeCount RETURN nodeCount");
    const src0 = refPidToNid.get(ref.shortest_paths_from_first[0][0]);
    const gotSp = (
      await runQuery(
        'CALL gds.dijkstra.stream($g,{sourceNode:$s}) YIELD nodeId, distance RETURN nodeId, distance',
        { g: 'refp', s: neo4j.int(src0) }
      )
    )
      .map((r) => [refPid(toNum(r.get('nodeId'))), Math.round(toNum(r.get('distance')))])
      .sort((a, b) => a[0] - b[0]);
    const expSp = [...ref.shortest_paths_from_first].sort((a, b) => a[0] - b[0]);
    if (JSON.stringify(gotSp) !== JSON.stringify(expSp)) {
      fail(`reference shortest-path mismatch: got ${JSON.stringify(gotSp)} exp ${JSON.stringify(expSp)}`);
    }
    console.log(`  dijkstra from ${ref.shortest_paths_from_first[0][0]}: ${JSON.stringify(gotSp.map((x) => x[1]))} hops (matches ground truth)`);
    await dropGraph('refp');

    // =============================================================================================
    // 3. WEIGHTED vs UNWEIGHTED — the headline of a real GDS workload (rmp #690).
    //    relationshipWeightProperty='weight' is a PROJECTION-time knob; PageRank and Dijkstra then use
    //    the weights. We assert weighted and unweighted genuinely differ and report both top rankings.
    // =============================================================================================
    console.log('\n-- weighted vs unweighted analytics (relationshipWeightProperty=weight) --');
    await runQuery(
      "CALL gds.graph.project('infl_u','Author',null,{orientation:'NATURAL'}) YIELD nodeCount, relationshipCount RETURN nodeCount, relationshipCount"
    );
    await runQuery(
      "CALL gds.graph.project('infl_w','Author',null,{orientation:'NATURAL',relationshipWeightProperty:'weight'}) YIELD nodeCount, relationshipCount RETURN nodeCount, relationshipCount"
    );

    // (a) PageRank — full (nodeId, score) result sets (no count(*) collapse), mapped to author ids.
    const prMap = async (g) => {
      const m = new Map();
      for (const r of await runQuery(
        `CALL gds.pageRank.stream('${g}',{}) YIELD nodeId, score RETURN nodeId, score`
      )) {
        m.set(authPid(toNum(r.get('nodeId'))), toNum(r.get('score')));
      }
      return m;
    };
    const prU = await prMap('infl_u');
    const prW = await prMap('infl_w');
    if (prU.size !== authorCount || prW.size !== authorCount) {
      fail(`pageRank streamed ${prU.size}/${prW.size} rows, expected ${authorCount} authors each`);
    }
    // The two score vectors must genuinely differ (weights ∈ [1,10] make this all but certain).
    let maxDelta = 0;
    let changed = 0;
    for (const [id, u] of prU) {
      const d = Math.abs((prW.get(id) ?? 0) - u);
      if (d > WEIGHT_DELTA) changed += 1;
      if (d > maxDelta) maxDelta = d;
    }
    if (!(maxDelta > WEIGHT_DELTA)) {
      fail(`weighted and unweighted PageRank are indistinguishable (maxΔ=${maxDelta}) — weighting had no effect`);
    }
    const topK = (m, k) =>
      [...m.entries()].sort((a, b) => b[1] - a[1] || a[0] - b[0]).slice(0, k).map(([id]) => id);
    const topU = topK(prU, 5);
    const topW = topK(prW, 5);
    const shared = topU.filter((id) => topW.includes(id)).length;
    console.log(`  pageRank streamed ${prU.size} (nodeId,score) rows per projection`);
    console.log(`  weighted changed ${changed}/${authorCount} authors' scores (maxΔ=${maxDelta.toExponential(3)})`);
    console.log(`  top-5 unweighted authors: ${JSON.stringify(topU)}`);
    console.log(`  top-5 weighted   authors: ${JSON.stringify(topW)}  (shared with unweighted: ${shared}/5)`);

    // (b) Dijkstra — weighted vs unweighted distances from author 0. Weighted uses cumulative edge
    //     weight as cost; unweighted counts hops. The distance vectors must differ.
    const src = neo4j.int(
      toNum((await runQuery('MATCH (a:Author {id:0}) RETURN id(a) AS nid'))[0].get('nid'))
    );
    const dijk = async (g) => {
      const m = new Map();
      for (const r of await runQuery(
        'CALL gds.dijkstra.stream($g,{sourceNode:$s}) YIELD nodeId, distance RETURN nodeId, distance',
        { g, s: src }
      )) {
        m.set(authPid(toNum(r.get('nodeId'))), toNum(r.get('distance')));
      }
      return m;
    };
    const dU = await dijk('infl_u');
    const dW = await dijk('infl_w');
    let dijkstraDiffers = false;
    for (const [id, u] of dU) {
      if (Math.abs((dW.get(id) ?? Infinity) - u) > WEIGHT_DELTA) {
        dijkstraDiffers = true;
        break;
      }
    }
    if (!dijkstraDiffers) fail('weighted and unweighted Dijkstra produced identical distances');
    console.log(`  dijkstra from author 0: weighted reached ${dW.size} nodes, unweighted ${dU.size}; distance vectors differ (weights applied)`);

    // =============================================================================================
    // 4. WRITE / MUTATE / STATS execution modes (feature-detected — a newer surface, rmp #643).
    //    Re-uses the weighted projection 'infl_w'. Probe with .stats (read-only); if the modes are
    //    absent (older server) skip the whole section cleanly.
    // =============================================================================================
    console.log('\n-- write / mutate / stats execution modes --');
    let modesSupported = false;
    let nodesWritten = 0;
    const statsProbe = await runOptional(
      "CALL gds.pageRank.stats('infl_w',{}) YIELD ranIterations, didConverge, centralityDistribution RETURN ranIterations, didConverge, centralityDistribution"
    );
    if (!statsProbe.ok && isCapabilityGap(statsProbe.err)) {
      console.log('  · SKIPPED — this server does not register gds.*.{write,stats,mutate}');
      console.log('    (the execution modes are a newer surface: rmp #643 / a current build). The');
      console.log('    weighted analytics above already ran against this instance.');
    } else if (!statsProbe.ok) {
      fail(`gds.pageRank.stats failed unexpectedly: ${statsProbe.err.message}`);
    } else {
      modesSupported = true;

      // ---- .stats — assert a summary field is present and sane.
      const st = statsProbe.records[0];
      const ranIters = toNum(st.get('ranIterations'));
      const didConverge = st.get('didConverge');
      if (!(ranIters >= 1)) fail(`.stats ranIterations should be >= 1, got ${ranIters}`);
      if (typeof didConverge !== 'boolean') fail(`.stats didConverge should be a boolean, got ${didConverge}`);
      console.log(`  stats: ranIterations=${ranIters} didConverge=${didConverge} (summary asserted)`);

      // ---- .write — write pagerank back to the database; assert nodePropertiesWritten==authorCount.
      const wr = (
        await runQuery(
          "CALL gds.pageRank.write('infl_w',{writeProperty:'pagerank'}) YIELD nodePropertiesWritten, ranIterations, didConverge RETURN nodePropertiesWritten, ranIterations, didConverge"
        )
      )[0];
      nodesWritten = toNum(wr.get('nodePropertiesWritten'));
      if (nodesWritten !== authorCount) {
        fail(`.write nodePropertiesWritten=${nodesWritten}, expected authorCount=${authorCount}`);
      }
      // Readback: MATCH … WHERE pagerank > x ORDER BY pagerank — the property is queryable and every
      // author received it (x=0: PageRank scores are strictly positive).
      const nonNull = toNum(
        (await runQuery('MATCH (a:Author) WHERE a.pagerank IS NOT NULL RETURN count(a) AS c'))[0].get('c')
      );
      const positive = toNum(
        (await runQuery('MATCH (a:Author) WHERE a.pagerank > 0 RETURN count(a) AS c'))[0].get('c')
      );
      if (nonNull !== authorCount || positive !== authorCount) {
        fail(`.write readback: ${nonNull} non-null / ${positive} positive, expected ${authorCount} each`);
      }
      const topWritten = await runQuery(
        'MATCH (a:Author) WHERE a.pagerank > 0 RETURN a.id AS id, a.field AS field, a.pagerank AS pr ORDER BY pr DESC LIMIT 5'
      );
      const topList = topWritten.map((r) => ({
        id: toNum(r.get('id')),
        field: toNum(r.get('field')),
        pr: toNum(r.get('pr')),
      }));
      console.log(`  write: nodePropertiesWritten=${nodesWritten} == authorCount; ${nonNull} readable, all > 0`);
      console.log(`  write readback top-5 (MATCH…WHERE pagerank>0 ORDER BY pagerank DESC LIMIT 5):`);
      for (const t of topList) console.log(`    author id=${t.id} field=${t.field} pagerank=${t.pr.toFixed(6)}`);

      // ---- .mutate — write into the in-memory projection, then read it back via nodeProperty.stream.
      const mu = (
        await runQuery(
          "CALL gds.pageRank.mutate('infl_w',{mutateProperty:'pr_mut'}) YIELD nodePropertiesWritten RETURN nodePropertiesWritten"
        )
      )[0];
      const mutated = toNum(mu.get('nodePropertiesWritten'));
      const streamed = await runQuery(
        "CALL gds.graph.nodeProperty.stream('infl_w','pr_mut') YIELD nodeId, propertyValue RETURN nodeId, propertyValue"
      );
      if (streamed.length !== mutated) {
        fail(`.mutate/readback mismatch: mutated ${mutated}, nodeProperty.stream returned ${streamed.length}`);
      }
      if (mutated !== authorCount) fail(`.mutate nodePropertiesWritten=${mutated}, expected ${authorCount}`);
      // The mutated projection property equals the score we just wrote to the DB (same computation).
      const writtenByPid = new Map();
      for (const r of await runQuery('MATCH (a:Author) RETURN a.id AS id, a.pagerank AS pr')) {
        writtenByPid.set(toNum(r.get('id')), toNum(r.get('pr')));
      }
      let mutateMismatch = 0;
      for (const r of streamed) {
        const pid = authPid(toNum(r.get('nodeId')));
        const v = toNum(r.get('propertyValue'));
        if (Math.abs(v - (writtenByPid.get(pid) ?? NaN)) > PR_EPSILON) mutateMismatch += 1;
      }
      if (mutateMismatch !== 0) {
        fail(`.mutate values diverge from .write for ${mutateMismatch} authors (same computation expected)`);
      }
      console.log(`  mutate: nodePropertiesWritten=${mutated}; gds.graph.nodeProperty.stream read back ${streamed.length} values, all == the written pagerank`);
    }

    // =============================================================================================
    // 4b. PER-ALGORITHM SERVER CPU — "does GDS use the cores?", answered per algorithm (rmp #717).
    //     Runs only when the caller handed us a co-located server pid + the proc_watch sampler (a
    //     LOCAL run). Against a REMOTE target there is no /proc to read, so the vector is simply
    //     ABSENT from the evidence — never zero-filled.
    // =============================================================================================
    let batteryCalls = 0;
    let algoCpu = null;
    if (BATTERY) {
      console.log('\n-- per-algorithm SERVER core utilisation (proc_watch brackets the server pid) --');
      // Every algorithm the engine registers, over BOTH projections where weighting changes the work:
      // `weighted` closeness runs Dijkstra per source where the unweighted one runs BFS, and that
      // difference is one of the largest cost signals in the whole surface.
      const suite = [
        ['gds.pageRank.stream',         'infl_u', "CALL gds.pageRank.stream('infl_u',{}) YIELD nodeId, score RETURN count(*) AS c"],
        ['gds.pageRank.stream (weighted)', 'infl_w', "CALL gds.pageRank.stream('infl_w',{}) YIELD nodeId, score RETURN count(*) AS c"],
        ['gds.betweenness.stream',      'infl_u', "CALL gds.betweenness.stream('infl_u',{}) YIELD nodeId, score RETURN count(*) AS c"],
        ['gds.closeness.stream',        'infl_u', "CALL gds.closeness.stream('infl_u',{}) YIELD nodeId, score RETURN count(*) AS c"],
        ['gds.closeness.stream (weighted)', 'infl_w', "CALL gds.closeness.stream('infl_w',{}) YIELD nodeId, score RETURN count(*) AS c"],
        ['gds.triangleCount.stream',    'infl_u', "CALL gds.triangleCount.stream('infl_u',{}) YIELD nodeId, triangleCount RETURN count(*) AS c"],
        ['gds.labelPropagation.stream', 'infl_u', "CALL gds.labelPropagation.stream('infl_u',{}) YIELD nodeId, communityId RETURN count(*) AS c"],
        ['gds.wcc.stream',              'infl_u', "CALL gds.wcc.stream('infl_u',{}) YIELD nodeId, componentId RETURN count(*) AS c"],
        ['gds.scc.stream',              'infl_u', "CALL gds.scc.stream('infl_u',{}) YIELD nodeId, componentId RETURN count(*) AS c"],
        ['gds.degree.stream',           'infl_u', "CALL gds.degree.stream('infl_u',{}) YIELD nodeId, score RETURN count(*) AS c"],
        ['gds.dijkstra.stream',         'infl_u', 'CALL gds.dijkstra.stream($g,{sourceNode:$s}) YIELD nodeId, distance RETURN count(*) AS c'],
        ['gds.bellmanFord.stream',      'infl_u', 'CALL gds.bellmanFord.stream($g,{sourceNode:$s}) YIELD nodeId, distance RETURN count(*) AS c'],
      ];

      const measured = [];
      for (const [name, graph, query] of suite) {
        const params = { g: graph, s: src };
        // Warm-up call: proves the server registers the procedure (an older one may not), and sizes
        // the repeat count. It is OUTSIDE the bracket, so it inflates neither numerator nor
        // denominator.
        const warm0 = secs();
        const probe = await runRaw(query, params);
        const warmSecs = secs() - warm0;
        batteryCalls += 1;
        if (!probe.ok) {
          if (isCapabilityGap(probe.err)) {
            console.log(`  · ${name}: SKIPPED — this server does not register the procedure`);
            measured.push({ algorithm: name, projection: graph, skipped: 'procedure not registered' });
            continue;
          }
          fail(`${name} failed unexpectedly: ${probe.err.message}`);
        }

        // Repeat until the bracket is ≥ the CPU target, so the 10 ms tick is noise (not the signal).
        const reps = Math.min(
          CPU_MAX_REPEATS,
          Math.max(CPU_MIN_REPEATS, Math.ceil(args.cpuTargetSecs / Math.max(warmSecs, 1e-4)))
        );
        const before = serverSnapshot();
        const t0 = secs();
        for (let i = 0; i < reps; i += 1) await runRaw(query, params);
        const wall = secs() - t0;
        const after = serverSnapshot();
        batteryCalls += reps;

        const cpu =
          after.user_secs - before.user_secs + (after.system_secs - before.system_secs);
        const entry = {
          algorithm: name,
          projection: graph,
          calls: reps,
          wall_secs: Number(wall.toFixed(4)),
          ms_per_call: Number(((wall * 1000) / reps).toFixed(3)),
          // The SERVER's resident memory across the bracket. Hundreds of repeats of one algorithm is
          // exactly the shape that exposes a per-call allocation the server never gives back, so the
          // RSS the phase *left behind* is worth recording next to the CPU it burned. (`proc_watch
          // --snapshot` already reads RSS; this costs nothing extra.)
          server_rss_before_bytes: before.rss_bytes,
          server_rss_after_bytes: after.rss_bytes,
          server_rss_delta_bytes: after.rss_bytes - before.rss_bytes,
        };
        const rssMb = (entry.server_rss_delta_bytes / (1024 * 1024)).toFixed(1);
        if (cpu >= CPU_MIN_MEASURABLE_SECS && wall > 0) {
          entry.cpu_secs = Number(cpu.toFixed(4));
          entry.mean_core_utilisation = Number((cpu / wall).toFixed(3));
          console.log(
            `  ${name.padEnd(34)} ${String(reps).padStart(3)} calls  ` +
              `${entry.ms_per_call.toFixed(2).padStart(8)} ms/call  ` +
              `server CPU ${entry.cpu_secs.toFixed(2).padStart(6)} s  ` +
              `=> ${entry.mean_core_utilisation.toFixed(2).padStart(5)} cores busy  ` +
              `(server RSS ${rssMb >= 0 ? '+' : ''}${rssMb} MB)`
          );
        } else {
          // Under five clock ticks of CPU across the whole bracket: the OS cannot resolve it, so the
          // figure is NOT MEASURED. Reporting the 0.0 would tell a reader the server burned no CPU.
          entry.cpu_not_measured =
            `server CPU across ${reps} calls (${cpu.toFixed(3)} s) is below the ` +
            `${CPU_MIN_MEASURABLE_SECS} s the OS clock tick can resolve`;
          console.log(
            `  ${name.padEnd(34)} ${String(reps).padStart(3)} calls  ` +
              `${entry.ms_per_call.toFixed(2).padStart(8)} ms/call  ` +
              `server CPU NOT MEASURABLE (< ${CPU_MIN_MEASURABLE_SECS}s over the bracket)`
          );
        }
        measured.push(entry);
      }

      // The battery's own memory story: the server's RSS when the battery opened, and after ~2 900
      // algorithm calls. A server that gives its per-call memory back ends where it started.
      const rssRows = measured.filter((m) => m.server_rss_before_bytes !== undefined);
      const rssStart = rssRows.length ? rssRows[0].server_rss_before_bytes : null;
      const rssEnd = rssRows.length ? rssRows[rssRows.length - 1].server_rss_after_bytes : null;
      algoCpu = {
        server_pid: Number(args.serverPid),
        host_cores: os.cpus().length,
        cpu_target_secs: args.cpuTargetSecs,
        min_measurable_cpu_secs: CPU_MIN_MEASURABLE_SECS,
        authors: authorCount,
        // What declaring the schema cost the server (rmp #724 — an index is ~7.8 KB of RSS per
        // indexed element, and it is never released).
        schema_ddl: schemaDdl,
        battery_calls: batteryCalls,
        server_rss_at_battery_start_bytes: rssStart,
        server_rss_at_battery_end_bytes: rssEnd,
        server_rss_growth_bytes: rssStart !== null && rssEnd !== null ? rssEnd - rssStart : null,
        algorithms: measured,
      };
      if (rssStart !== null && rssEnd !== null) {
        const mb = (b) => (b / (1024 * 1024)).toFixed(1);
        console.log(
          `  server RSS across the battery: ${mb(rssStart)} MB -> ${mb(rssEnd)} MB ` +
            `(${rssEnd - rssStart >= 0 ? '+' : ''}${mb(rssEnd - rssStart)} MB over ${batteryCalls} calls)`
        );
      }
      fs.writeFileSync(args.algoCpuOut, JSON.stringify(algoCpu, null, 2));
      const busiest = measured
        .filter((m) => m.mean_core_utilisation !== undefined)
        .sort((a, b) => b.mean_core_utilisation - a.mean_core_utilisation)[0];
      if (!busiest) {
        fail('the CPU battery measured no algorithm at all — the server pid was unreadable, or every '
          + 'bracket fell below the clock tick (raise --cpu-target-secs)');
      }
      console.log(
        `  => busiest: ${busiest.algorithm} at ${busiest.mean_core_utilisation} cores of ` +
          `${os.cpus().length} logical (${batteryCalls} battery calls; wrote ${args.algoCpuOut})`
      );
    } else {
      console.log('\n-- per-algorithm SERVER core utilisation: NOT MEASURED --');
      console.log('   (no co-located server pid: an attach run reaches the target over the wire only,');
      console.log('    so /proc is not readable and the vector is ABSENT from the evidence — never 0)');
    }

    await dropGraph('infl_u');
    await dropGraph('infl_w');

    // =============================================================================================
    // 5. TEARDOWN-LAST — drop projections + DETACH DELETE (constraints/indexes persist harmlessly).
    // =============================================================================================
    await dropAllProjections();
    await deleteExampleData();
    const remaining = await runOptional('CALL gds.graph.list() YIELD graphName RETURN count(*) AS c');
    if (remaining.ok) {
      const c = toNum(remaining.records[0].get('c'));
      if (c !== 0) fail(`expected 0 projections after teardown, ${c} remain`);
      console.log('\n  all GDS projections released; example data deleted (idempotent teardown)');
    }

    // ---- Machine-readable evidence for run.sh.
    const totalSecs =
      latenciesMs.reduce((a, b) => a + b, 0) / 1000; // client-side busy time (approx wall for a serial driver)
    const stats = {
      schema_applied: schemaApplied,
      schema_skipped: schemaSkipped,
      load_statements: loaded,
      bulk_imported: args.skipLoad,
      authors_loaded: authorCount,
      modes_supported: modesSupported,
      nodes_written: nodesWritten,
      // The battery's calls are counted SEPARATELY and are deliberately NOT in the latency sample:
      // they are a CPU instrument (hundreds of repeats of one algorithm, including a 1-second
      // weighted closeness), and folding them into the workload's percentiles would report the
      // instrument's latency as the workload's.
      battery_calls: batteryCalls,
      operations: latenciesMs.length,
      workload_secs: Number(totalSecs.toFixed(3)),
      p50_ms: percentileMs(0.5),
      p99_ms: percentileMs(0.99),
      p999_ms: percentileMs(0.999),
    };
    console.log('\nGRAPHUS_STATS ' + JSON.stringify(stats));
    console.log('GRAPHUS_GDS_OK');
    process.exit(0);
  } catch (err) {
    fail(err && err.stack ? err.stack : String(err));
  } finally {
    await driver.close();
  }
})();
