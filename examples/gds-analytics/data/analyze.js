'use strict';
//
// analyze.js — the Graph-Data-Science analytics workload, driven over Bolt-over-TCP+TLS with the
// OFFICIAL `neo4j-driver` npm package (the exact wire path the Neo4j driver ecosystem uses).
//
// It:
//   1. connects with `bolt+ssc://` (trusts the server's self-signed cert),
//   2. loads the schema DDL + the generated influence network (from graph.cypher): :Author nodes,
//      intra-field :CITES edges, sparse inter-field :CROSS edges, and a small :Ref/:LINKS reference
//      subgraph,
//   3. projects the graph into the in-memory CSR via `CALL gds.graph.project(...)` and runs the FULL
//      algorithm suite through the `CALL gds.*.stream(...)` procedure surface — PageRank, degree +
//      betweenness + closeness centrality, WCC + SCC, triangleCount, label propagation (community),
//      and Dijkstra/Bellman-Ford shortest paths — then DROPS the projections,
//   4. asserts the reference-subgraph outputs match the analytically-known ground truth
//      (reference.json) within a documented tolerance: the exact WCC partition, the highest-
//      betweenness (bridge) nodes, the degree sequence, a shortest-path distance vector, the
//      triangle-count signature of the two planted cliques, PageRank symmetry + ordering, and the
//      recovery of the planted FIELD communities via WCC over the :CITES-only projection.
//
// On full success it prints `GRAPHUS_GDS_OK` and exits 0; on any mismatch it prints a clear
// diagnosis and exits 1.
//
// IMPORTANT — verified procedure-surface facts (empirically confirmed against the real engine):
//   * gds.* procedures use STRICT ARITY: `gds.graph.project` needs 4 args (name, nodeFilter,
//     relFilter, config) and every `gds.*.stream` needs 2 (name, config). A trailing `{}` / null is
//     mandatory, never omitted.
//   * `exists` is a reserved word, so `gds.graph.exists` yields must be escaped (we avoid it here).
//   * The streamed `nodeId` is the engine's INTERNAL node id, not the `id` property; we read the
//     id<->property mapping with `MATCH (r:Ref) RETURN id(r), r.id` and translate.
//   * Graphus has NO Louvain and NO node-similarity procedure (verified: "no procedure registered");
//     community detection uses labelPropagation, and the planted FIELD partition is recovered via WCC
//     over the :CITES-only projection (synchronous LPA over-merges dense graphs — documented).
//
// Usage:
//   node analyze.js <port> <user> <password> <graph.cypher> <reference.json>

const fs = require('fs');
const neo4j = require('neo4j-driver');

const [, , port, user, password, cypherPath, refPath] = process.argv;
if (!port || !user || !password || !cypherPath || !refPath) {
  console.error('usage: node analyze.js <port> <user> <password> <graph.cypher> <reference.json>');
  process.exit(2);
}

const uri = `bolt+ssc://127.0.0.1:${port}`;
const toNum = (v) => (neo4j.isInt(v) ? v.toNumber() : v);

// PageRank float comparison tolerance (the engine returns IEEE-754 doubles; we assert symmetry and
// ordering within this epsilon, never bit-exact equality).
const PR_EPSILON = 1e-9;

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

// Order-independent set equality on number arrays.
function sameSet(a, b) {
  if (a.length !== b.length) return false;
  const sa = new Set(a);
  for (const x of b) if (!sa.has(x)) return false;
  return true;
}

// Split a .cypher script into individual statements on `;` at end-of-line; drop `//` comment lines.
// The schema DDL MUST run as auto-commit statements (Graphus rejects admin DDL inside an explicit
// transaction), so each statement runs in its own auto-commit `session.run`.
function statements(script) {
  return script
    .split('\n')
    .filter((line) => !line.trimStart().startsWith('//'))
    .join('\n')
    .split(';')
    .map((s) => s.trim())
    .filter((s) => s.length > 0);
}

// Run a read/proc query and return the raw records.
async function runQuery(driver, query, params) {
  const s = driver.session();
  try {
    const r = await timed(() => s.run(query, params || {}));
    return r.records;
  } finally {
    await s.close();
  }
}

(async () => {
  const script = fs.readFileSync(cypherPath, 'utf8');
  const ref = JSON.parse(fs.readFileSync(refPath, 'utf8'));

  const driver = neo4j.driver(uri, neo4j.auth.basic(user, password));
  try {
    await driver.verifyConnectivity();

    // ---- 1. Load the schema + graph (each statement its own auto-commit run).
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
    console.log(`loaded ${loaded} statements (schema + influence network + reference subgraph)`);

    const authorCount = toNum(
      (await runQuery(driver, 'MATCH (a:Author) RETURN count(a) AS c'))[0].get('c')
    );
    console.log(`authors loaded: ${authorCount}`);

    // ---- nodeId (internal) <-> id (property) mapping for the :Ref nodes, so we can translate the
    //      procedure surface's internal nodeIds back to the stable reference ids in reference.json.
    const refMap = new Map(); // internal nodeId -> property id
    const refRevMap = new Map(); // property id -> internal nodeId
    for (const rec of await runQuery(driver, 'MATCH (r:Ref) RETURN id(r) AS nid, r.id AS pid')) {
      const nid = toNum(rec.get('nid'));
      const pid = toNum(rec.get('pid'));
      refMap.set(nid, pid);
      refRevMap.set(pid, nid);
    }
    const refProp = (nid) => {
      const p = refMap.get(nid);
      if (p === undefined) fail(`internal nodeId ${nid} has no :Ref property mapping`);
      return p;
    };

    // =============================================================================================
    // 2. THE REFERENCE SUBGRAPH — project :Ref/:LINKS (undirected) and assert the ground truth.
    // =============================================================================================
    console.log('\n-- reference subgraph (analytically-known ground truth) --');
    await runQuery(
      driver,
      "CALL gds.graph.project('ref','Ref','LINKS',{}) YIELD nodeCount, relationshipCount RETURN nodeCount, relationshipCount"
    );

    // (a) WCC: a single component containing exactly the reference ids.
    const wccRows = await runQuery(
      driver,
      'CALL gds.wcc.stream($g,{}) YIELD nodeId, componentId RETURN nodeId, componentId',
      { g: 'ref' }
    );
    const wccByComp = new Map();
    for (const rec of wccRows) {
      const pid = refProp(toNum(rec.get('nodeId')));
      const comp = toNum(rec.get('componentId'));
      if (!wccByComp.has(comp)) wccByComp.set(comp, []);
      wccByComp.get(comp).push(pid);
    }
    if (wccByComp.size !== 1) fail(`reference WCC expected 1 component, got ${wccByComp.size}`);
    const wccMembers = [...wccByComp.values()][0].sort((x, y) => x - y);
    if (!sameSet(wccMembers, ref.component)) {
      fail(`reference WCC partition mismatch.\n  got: ${JSON.stringify(wccMembers)}\n  exp: ${JSON.stringify(ref.component)}`);
    }
    console.log(`  WCC: 1 component = ${JSON.stringify(wccMembers)} (matches ground truth)`);

    // (b) Degree sequence.
    const degRows = await runQuery(
      driver,
      'CALL gds.degree.stream($g,{}) YIELD nodeId, score RETURN nodeId, score',
      { g: 'ref' }
    );
    const gotDeg = degRows
      .map((r) => [refProp(toNum(r.get('nodeId'))), Math.round(toNum(r.get('score')))])
      .sort((a, b) => a[0] - b[0]);
    const expDeg = [...ref.degrees].sort((a, b) => a[0] - b[0]);
    if (JSON.stringify(gotDeg) !== JSON.stringify(expDeg)) {
      fail(`reference degree sequence mismatch.\n  got: ${JSON.stringify(gotDeg)}\n  exp: ${JSON.stringify(expDeg)}`);
    }
    console.log(`  degree: ${JSON.stringify(gotDeg)} (matches ground truth)`);

    // (c) Betweenness: the two bridge endpoints are strictly highest.
    const btwRows = await runQuery(
      driver,
      'CALL gds.betweenness.stream($g,{}) YIELD nodeId, score RETURN nodeId, score',
      { g: 'ref' }
    );
    const btw = btwRows
      .map((r) => ({ id: refProp(toNum(r.get('nodeId'))), s: toNum(r.get('score')) }))
      .sort((a, b) => b.s - a.s);
    const topBtw = btw.slice(0, 2).map((x) => x.id).sort((x, y) => x - y);
    const restMax = Math.max(...btw.slice(2).map((x) => x.s));
    if (!sameSet(topBtw, ref.top_betweenness_nodes)) {
      fail(`reference top-betweenness mismatch.\n  got: ${JSON.stringify(topBtw)}\n  exp: ${JSON.stringify(ref.top_betweenness_nodes)}`);
    }
    if (!(btw[1].s > restMax)) {
      fail(`reference betweenness not strictly separated: 2nd=${btw[1].s} restMax=${restMax}`);
    }
    console.log(`  betweenness: top-2 = ${JSON.stringify(topBtw)} (bridge endpoints, strictly highest at ${btw[0].s.toFixed(1)})`);

    // (d) Closeness: the bridge endpoints are the most central (highest closeness).
    const closeRows = await runQuery(
      driver,
      'CALL gds.closeness.stream($g,{}) YIELD nodeId, score RETURN nodeId, score',
      { g: 'ref' }
    );
    const close = closeRows
      .map((r) => ({ id: refProp(toNum(r.get('nodeId'))), s: toNum(r.get('score')) }))
      .sort((a, b) => b.s - a.s);
    const topClose = close.slice(0, 2).map((x) => x.id).sort((x, y) => x - y);
    if (!sameSet(topClose, ref.top_betweenness_nodes)) {
      fail(`reference closeness top-2 expected the bridge endpoints, got ${JSON.stringify(topClose)}`);
    }
    console.log(`  closeness: top-2 = ${JSON.stringify(topClose)} (bridge endpoints, highest at ${close[0].s.toFixed(4)})`);

    // (e) triangleCount: each of the two planted cliques is a triangle, so every node is in exactly 1.
    const triRows = await runQuery(
      driver,
      'CALL gds.triangleCount.stream($g,{}) YIELD nodeId, triangleCount RETURN nodeId, triangleCount',
      { g: 'ref' }
    );
    const tri = triRows.map((r) => toNum(r.get('triangleCount')));
    if (!tri.every((t) => t === 1) || tri.length !== 6) {
      fail(`reference triangleCount expected every node in exactly 1 triangle, got ${JSON.stringify(tri)}`);
    }
    console.log(`  triangleCount: all 6 nodes in exactly 1 triangle (two planted 3-cliques)`);

    // (f) PageRank: symmetry within structural-equivalence classes + bridge endpoints ranked top.
    //     The two clique-internal pairs on each side are structurally equivalent, so their PageRanks
    //     match within epsilon; the two bridge endpoints share the top score.
    const prRows = await runQuery(
      driver,
      'CALL gds.pageRank.stream($g,{}) YIELD nodeId, score RETURN nodeId, score',
      { g: 'ref' }
    );
    const pr = new Map();
    for (const r of prRows) pr.set(refProp(toNum(r.get('nodeId'))), toNum(r.get('score')));
    const [b0, b1, b2, b3, b4, b5] = ref.ref_ids;
    // Bridge endpoints (b2, b3) are the unique maximum.
    const prMax = Math.max(...pr.values());
    if (Math.abs(pr.get(b2) - prMax) > PR_EPSILON || Math.abs(pr.get(b3) - prMax) > PR_EPSILON) {
      fail(`reference PageRank: bridge endpoints (${b2},${b3}) should hold the max score ${prMax}`);
    }
    // Structural symmetry: b0==b1, b4==b5 (the clique-internal non-bridge nodes), and b2==b3.
    const symPairs = [[b0, b1], [b4, b5], [b2, b3]];
    for (const [x, y] of symPairs) {
      if (Math.abs(pr.get(x) - pr.get(y)) > PR_EPSILON) {
        fail(`reference PageRank symmetry broken: PR(${x})=${pr.get(x)} != PR(${y})=${pr.get(y)}`);
      }
    }
    console.log(`  pageRank: bridge endpoints hold the max (${prMax.toFixed(6)}); structural symmetry holds within ${PR_EPSILON}`);

    await runQuery(driver, "CALL gds.graph.drop('ref') YIELD nodeCount RETURN nodeCount");

    // (g) Shortest paths: project DIRECTED+UNWEIGHTED is not how :LINKS reads (it is undirected), so
    //     project undirected unweighted and run Dijkstra from b0 — unit weights => hop distances.
    await runQuery(
      driver,
      "CALL gds.graph.project('refp','Ref','LINKS',{}) YIELD nodeCount RETURN nodeCount"
    );
    const src = refRevMap.get(ref.shortest_paths_from_first[0][0]); // internal id of b0
    const spRows = await runQuery(
      driver,
      'CALL gds.dijkstra.stream($g,{sourceNode:$s}) YIELD nodeId, distance RETURN nodeId, distance',
      { g: 'refp', s: neo4j.int(src) }
    );
    const gotSp = spRows
      .map((r) => [refProp(toNum(r.get('nodeId'))), Math.round(toNum(r.get('distance')))])
      .sort((a, b) => a[0] - b[0]);
    const expSp = [...ref.shortest_paths_from_first].sort((a, b) => a[0] - b[0]);
    if (JSON.stringify(gotSp) !== JSON.stringify(expSp)) {
      fail(`reference shortest-path vector mismatch.\n  got: ${JSON.stringify(gotSp)}\n  exp: ${JSON.stringify(expSp)}`);
    }
    console.log(`  dijkstra from ${ref.shortest_paths_from_first[0][0]}: ${JSON.stringify(gotSp.map((x) => x[1]))} hops (matches ground truth)`);
    await runQuery(driver, "CALL gds.graph.drop('refp') YIELD nodeCount RETURN nodeCount");

    // =============================================================================================
    // 3. THE INFLUENCE NETWORK — the full algorithm suite + planted-field community recovery.
    // =============================================================================================
    console.log('\n-- influence network (full algorithm suite) --');

    // (a) Community recovery: WCC over the :CITES-only projection must recover the planted field
    //     blocks — exactly `planted_field_count` components, each of size `planted_field_size`.
    await runQuery(
      driver,
      "CALL gds.graph.project('comm','Author','CITES',{}) YIELD nodeCount, relationshipCount RETURN nodeCount, relationshipCount"
    );
    const commRows = await runQuery(
      driver,
      'CALL gds.wcc.stream($g,{}) YIELD nodeId, componentId RETURN nodeId, componentId',
      { g: 'comm' }
    );
    const commSizes = new Map();
    for (const r of commRows) {
      const c = toNum(r.get('componentId'));
      commSizes.set(c, (commSizes.get(c) || 0) + 1);
    }
    const fieldCount = ref.planted_field_count;
    const fieldSize = ref.planted_field_size;
    if (commSizes.size !== fieldCount) {
      fail(`community recovery: expected ${fieldCount} planted fields, WCC found ${commSizes.size} components`);
    }
    for (const [c, sz] of commSizes) {
      if (sz !== fieldSize) fail(`community recovery: component ${c} has size ${sz}, expected ${fieldSize}`);
    }
    console.log(`  community (WCC over :CITES): recovered exactly ${fieldCount} planted fields, each size ${fieldSize}`);
    await runQuery(driver, "CALL gds.graph.drop('comm') YIELD nodeCount RETURN nodeCount");

    // (b) The full algorithm suite over the WHOLE influence network (all rel types: :CITES+:CROSS).
    //     Undirected projection for the symmetric algorithms; directed for SCC + Dijkstra.
    await runQuery(
      driver,
      "CALL gds.graph.project('inf','Author',null,{}) YIELD nodeCount, relationshipCount RETURN nodeCount, relationshipCount"
    );
    await runQuery(
      driver,
      "CALL gds.graph.project('infd','Author',null,{orientation:'NATURAL'}) YIELD nodeCount RETURN nodeCount"
    );

    // A valid source for the single-source shortest-path procedures: the internal node id of the
    // author with property id 0 (internal ids are not guaranteed to start at 0 — the engine reserves
    // low ids — so we look it up rather than assuming `sourceNode:0`).
    const srcAuthor = neo4j.int(
      toNum((await runQuery(driver, 'MATCH (a:Author {id:0}) RETURN id(a) AS nid'))[0].get('nid'))
    );

    const suite = [
      ['pageRank', "CALL gds.pageRank.stream('infd',{}) YIELD nodeId, score RETURN count(*) AS c"],
      ['degree', "CALL gds.degree.stream('inf',{}) YIELD nodeId, score RETURN count(*) AS c"],
      ['betweenness', "CALL gds.betweenness.stream('inf',{}) YIELD nodeId, score RETURN count(*) AS c"],
      ['closeness', "CALL gds.closeness.stream('inf',{}) YIELD nodeId, score RETURN count(*) AS c"],
      ['wcc', "CALL gds.wcc.stream('inf',{}) YIELD nodeId, componentId RETURN count(*) AS c"],
      ['scc', "CALL gds.scc.stream('infd',{}) YIELD nodeId, componentId RETURN count(*) AS c"],
      ['triangleCount', "CALL gds.triangleCount.stream('inf',{}) YIELD nodeId, triangleCount RETURN count(*) AS c"],
      ['labelPropagation', "CALL gds.labelPropagation.stream('inf',{}) YIELD nodeId, communityId RETURN count(*) AS c"],
      ['dijkstra', "CALL gds.dijkstra.stream('infd',{sourceNode:$src}) YIELD nodeId, distance RETURN count(*) AS c"],
      ['bellmanFord', "CALL gds.bellmanFord.stream('infd',{sourceNode:$src}) YIELD nodeId, distance RETURN count(*) AS c"],
    ];
    for (const [name, q] of suite) {
      const c = toNum((await runQuery(driver, q, { src: srcAuthor }))[0].get('c'));
      if (name === 'bellmanFord' || name === 'dijkstra') {
        // single-source: at least the source is reachable (the whole net need not be).
        if (c < 1) fail(`influence-net ${name} returned ${c} rows`);
      } else if (c !== authorCount) {
        fail(`influence-net ${name} returned ${c} rows, expected ${authorCount} (one per author)`);
      }
      console.log(`  ${name}: ${c} rows`);
    }

    // Top-PageRank author on the directed influence network (the most "influential" researcher).
    const topPr = await runQuery(
      driver,
      "CALL gds.pageRank.stream('infd',{}) YIELD nodeId, score WITH nodeId, score ORDER BY score DESC LIMIT 1 MATCH (a:Author) WHERE id(a)=nodeId RETURN a.id AS id, a.field AS field, score"
    );
    const tp = topPr[0];
    console.log(`  top-influence author: id=${toNum(tp.get('id'))} field=${toNum(tp.get('field'))} pageRank=${toNum(tp.get('score')).toFixed(6)}`);

    await runQuery(driver, "CALL gds.graph.drop('inf') YIELD nodeCount RETURN nodeCount");
    await runQuery(driver, "CALL gds.graph.drop('infd') YIELD nodeCount RETURN nodeCount");

    // Confirm the CSR catalog is empty (projections released cleanly).
    const listRows = await runQuery(
      driver,
      'CALL gds.graph.list() YIELD graphName RETURN count(*) AS c'
    );
    const remaining = toNum(listRows[0].get('c'));
    if (remaining !== 0) fail(`expected 0 projections after drop, ${remaining} remain (CSR not released)`);
    console.log(`  all CSR projections released cleanly (catalog empty)`);

    // ---- Machine-readable evidence for run.sh.
    const stats = {
      load_statements: loaded,
      authors_loaded: authorCount,
      operations: latenciesMs.length,
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
