//! Hermetic cargo mirror of the `examples/gds-analytics` algorithm workload (`rmp #262`).
//!
//! This is the **default-run, npm-free** counterpart of the example's official-driver `analyze.js`:
//! it generates the SAME deterministic, seeded influence/citation network + reference subgraph
//! (`graphus-gds-gen`, fast profile), loads it into the REAL Graphus engine **in process** via
//! `LocalEngine` (no Bolt, no Node, no network), projects the CSR via `CALL gds.graph.project`, runs
//! the SAME `gds.*.stream` procedures through the engine's `Run` path, and asserts the
//! analytically-known reference-subgraph outputs **exactly** — the WCC partition, the degree
//! sequence, the strictly-highest-betweenness bridge endpoints, the closeness ordering, the
//! triangle-count signature, the PageRank symmetry/ordering, a shortest-path distance vector, and the
//! recovery of the planted FIELD communities via WCC over the `:CITES`-only projection.
//!
//! Where the shell example proves the wire path (the official `neo4j-driver` over Bolt/TLS), this
//! test proves the *engine semantics* the workload relies on, hermetically, in the default
//! `cargo test` run. The official-driver E2E (the Node path) stays in `examples/gds-analytics/run.sh`,
//! opt-in via `RUN_DRIVER`.
//!
//! The procedure calls are kept faithful to `data/analyze.js` (the same projections, the same
//! `gds.*.stream` surface, the same reference assertions) so the two paths assert the same ground
//! truth through different front doors. The `gds.*` procedures are registered into every engine by
//! default at boot (`exec::install_extensions` → `register_gds`), so `LocalEngine` drives them with
//! no extra wiring.

use std::collections::BTreeMap;

use std::sync::Arc;

use graphus_core::Value;
use graphus_cypher::MaterializedValue;
use graphus_gds_gen::{Profile, generate};
use graphus_io::MemBlockDevice;
use graphus_server::engine::LocalEngine;
use graphus_server::engine::command::AccessMode;
use graphus_sim::SharedClock;
use graphus_wal::MemLogSink;

type Eng = LocalEngine<MemBlockDevice, MemLogSink>;

/// PageRank float comparison tolerance — the engine returns IEEE-754 doubles, so we assert symmetry
/// and ordering within this epsilon, never bit-exact equality (mirrors `analyze.js`'s `PR_EPSILON`).
const PR_EPSILON: f64 = 1e-9;

/// Builds an in-memory engine with a fixed clock — the deterministic, hermetic substrate. The `gds.*`
/// procedures are registered by `LocalEngine::new` → `install_extensions`, so no extra setup is
/// needed.
fn engine() -> Eng {
    LocalEngine::in_memory(Arc::new(SharedClock::new(0)), 4096).expect("in-memory engine")
}

/// Loads every data statement inside a SINGLE write transaction, then commits once.
///
/// Batching the whole load into one transaction (rather than auto-committing each `CREATE`) keeps the
/// hermetic test fast: the planted graph is loaded atomically and the projection reads see the same
/// committed snapshot the official-driver path produces. Correctness is unaffected — the projections
/// + algorithms run after the commit, against the durable graph.
fn load_all(eng: &mut Eng, stmts: &[String]) {
    let ticket = eng.begin(AccessMode::Write).expect("begin load txn");
    for stmt in stmts {
        let mut reply = eng
            .run(ticket, stmt, Vec::new(), false, None)
            .unwrap_or_else(|e| panic!("load statement failed: {stmt}\n  {e}"));
        while let Ok(Some(_)) = reply.rows.next() {}
    }
    eng.commit(ticket).expect("commit load txn");
}

/// Runs one auto-commit statement (each `gds.*` call is its own statement, exactly as the official
/// driver runs them in separate sessions) and returns its rows.
fn run(eng: &mut Eng, query: &str) -> Vec<Vec<MaterializedValue>> {
    let ticket = eng
        .begin_auto_commit(AccessMode::Write)
        .expect("begin auto-commit");
    let mut reply = eng
        .run(ticket, query, Vec::new(), false, None)
        .unwrap_or_else(|e| panic!("query failed: {query}\n  {e}"));
    let mut rows = Vec::new();
    while let Ok(Some(row)) = reply.rows.next() {
        rows.push(row);
    }
    rows
}

/// The scalar of a single cell as a plain [`Value`] (panics on a structural materialization).
fn val(cell: &MaterializedValue) -> Value {
    match cell {
        MaterializedValue::Value(v) => v.clone(),
        other => panic!("expected a scalar value, got {other:?}"),
    }
}

/// Reads an integer cell, accepting either an `Integer` or a `Float` that is integral (degree /
/// distance scores stream as floats but carry whole-number values for these structural graphs).
fn as_int(cell: &MaterializedValue) -> i64 {
    match val(cell) {
        Value::Integer(n) => n,
        Value::Float(f) => f.round() as i64,
        other => panic!("expected an integer-valued cell, got {other:?}"),
    }
}

/// Reads a float cell.
fn as_float(cell: &MaterializedValue) -> f64 {
    match val(cell) {
        Value::Float(f) => f,
        Value::Integer(n) => n as f64,
        other => panic!("expected a float cell, got {other:?}"),
    }
}

/// A `;`-terminated statement iterator over the generated Cypher script, dropping `//` comment lines
/// and the schema DDL (`CREATE CONSTRAINT` / `CREATE INDEX`) — the in-process load path runs data
/// `CREATE`s only; the DDL is a load optimisation the official-driver path applies over Bolt, not a
/// correctness precondition for projection/algorithms. (Mirrors `fraud_oltp_detection.rs`.)
fn data_statements(script: &str) -> Vec<String> {
    script
        .lines()
        .filter(|l| !l.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n")
        .split(';')
        .map(|s| s.trim().to_owned())
        .filter(|s| {
            !s.is_empty() && !s.starts_with("CREATE CONSTRAINT") && !s.starts_with("CREATE INDEX")
        })
        .collect()
}

/// Maps each `:Ref` node's stable `id` property to its INTERNAL node id (via `id(r)`), so a test can
/// translate the procedure surface's internal `nodeId`s back to the reference ids in the generated
/// `Reference` (internal ids are not guaranteed to equal the property ids — mirrors `analyze.js`'s
/// `refMap`).
fn ref_prop_to_internal(eng: &mut Eng) -> BTreeMap<i64, i64> {
    let rows = run(eng, "MATCH (r:Ref) RETURN r.id AS pid, id(r) AS nid");
    let mut map = BTreeMap::new();
    for r in rows {
        map.insert(as_int(&r[0]), as_int(&r[1]));
    }
    map
}

/// The inverse mapping: internal node id → stable `:Ref` property id.
fn internal_to_ref_prop(eng: &mut Eng) -> BTreeMap<i64, i64> {
    ref_prop_to_internal(eng)
        .into_iter()
        .map(|(pid, nid)| (nid, pid))
        .collect()
}

#[test]
fn fast_profile_gds_matches_reference_ground_truth_exactly() {
    // 1. Generate the deterministic fast-profile graph + reference subgraph (the same artifacts the
    //    shell example's `gds_gen` binary writes — here used in-process).
    let dataset = generate(Profile::Fast.config(), Profile::Fast.name());
    let reference = &dataset.reference;

    // 2. Load the data into the real engine in process.
    let mut eng = engine();
    let cypher = dataset.to_cypher();
    let stmts = data_statements(&cypher);
    assert!(
        stmts.len() > 100,
        "expected a non-trivial load script, got {} statements",
        stmts.len()
    );
    load_all(&mut eng, &stmts);

    // Sanity: the author count matches the generated dataset.
    let author_count = {
        let rows = run(&mut eng, "MATCH (a:Author) RETURN count(a) AS c");
        as_int(&rows[0][0])
    };
    assert_eq!(
        author_count as u64,
        dataset.config.author_count(),
        "loaded author count must equal the generated dataset"
    );

    // The internal<->property id maps for the :Ref nodes.
    let to_prop = internal_to_ref_prop(&mut eng);
    let to_internal = ref_prop_to_internal(&mut eng);
    let prop = |nid: i64| -> i64 {
        *to_prop
            .get(&nid)
            .unwrap_or_else(|| panic!("internal nodeId {nid} has no :Ref property mapping"))
    };

    // =============================================================================================
    // THE REFERENCE SUBGRAPH — project :Ref/:LINKS (undirected) and assert the ground truth.
    // =============================================================================================
    run(
        &mut eng,
        "CALL gds.graph.project('ref','Ref','LINKS',{}) YIELD nodeCount, relationshipCount \
         RETURN nodeCount, relationshipCount",
    );

    // (a) WCC: a single component containing exactly the reference ids.
    {
        let rows = run(
            &mut eng,
            "CALL gds.wcc.stream('ref',{}) YIELD nodeId, componentId RETURN nodeId, componentId",
        );
        let mut by_comp: BTreeMap<i64, Vec<i64>> = BTreeMap::new();
        for r in &rows {
            by_comp
                .entry(as_int(&r[1]))
                .or_default()
                .push(prop(as_int(&r[0])));
        }
        assert_eq!(by_comp.len(), 1, "reference WCC must be a single component");
        let mut members: Vec<i64> = by_comp.into_values().next().unwrap();
        members.sort_unstable();
        let mut expected = reference.component.clone();
        expected.sort_unstable();
        assert_eq!(
            members, expected,
            "reference WCC partition must match ground truth"
        );
    }

    // (b) Degree sequence: bridge endpoints degree 3, the rest degree 2.
    {
        let rows = run(
            &mut eng,
            "CALL gds.degree.stream('ref',{}) YIELD nodeId, score RETURN nodeId, score",
        );
        let mut got: Vec<(i64, i64)> = rows
            .iter()
            .map(|r| (prop(as_int(&r[0])), as_int(&r[1])))
            .collect();
        got.sort_unstable();
        let mut expected = reference.degrees.clone();
        expected.sort_unstable();
        assert_eq!(
            got, expected,
            "reference degree sequence must match ground truth"
        );
    }

    // (c) Betweenness: the two bridge endpoints are STRICTLY highest.
    {
        let rows = run(
            &mut eng,
            "CALL gds.betweenness.stream('ref',{}) YIELD nodeId, score RETURN nodeId, score",
        );
        let mut scored: Vec<(i64, f64)> = rows
            .iter()
            .map(|r| (prop(as_int(&r[0])), as_float(&r[1])))
            .collect();
        scored.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap());
        let mut top2: Vec<i64> = scored[..2].iter().map(|x| x.0).collect();
        top2.sort_unstable();
        let mut expected = reference.top_betweenness_nodes.clone();
        expected.sort_unstable();
        assert_eq!(
            top2, expected,
            "the bridge endpoints must be the top-betweenness nodes"
        );
        let rest_max = scored[2..].iter().map(|x| x.1).fold(f64::MIN, f64::max);
        assert!(
            scored[1].1 > rest_max,
            "betweenness must be strictly separated: 2nd={} restMax={rest_max}",
            scored[1].1
        );
    }

    // (d) Closeness: the bridge endpoints are the most central (highest closeness).
    {
        let rows = run(
            &mut eng,
            "CALL gds.closeness.stream('ref',{}) YIELD nodeId, score RETURN nodeId, score",
        );
        let mut scored: Vec<(i64, f64)> = rows
            .iter()
            .map(|r| (prop(as_int(&r[0])), as_float(&r[1])))
            .collect();
        scored.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap());
        let mut top2: Vec<i64> = scored[..2].iter().map(|x| x.0).collect();
        top2.sort_unstable();
        let mut expected = reference.top_betweenness_nodes.clone();
        expected.sort_unstable();
        assert_eq!(
            top2, expected,
            "closeness top-2 must be the bridge endpoints"
        );
    }

    // (e) triangleCount: each of the two planted 3-cliques is a triangle, so every node is in 1.
    {
        let rows = run(
            &mut eng,
            "CALL gds.triangleCount.stream('ref',{}) YIELD nodeId, triangleCount \
             RETURN nodeId, triangleCount",
        );
        assert_eq!(rows.len(), 6, "the reference subgraph has six :Ref nodes");
        for r in &rows {
            assert_eq!(
                as_int(&r[1]),
                1,
                "every reference node is in exactly one triangle"
            );
        }
    }

    // (f) PageRank: bridge endpoints hold the max; structural symmetry within equivalence classes.
    {
        let rows = run(
            &mut eng,
            "CALL gds.pageRank.stream('ref',{}) YIELD nodeId, score RETURN nodeId, score",
        );
        let pr: BTreeMap<i64, f64> = rows
            .iter()
            .map(|r| (prop(as_int(&r[0])), as_float(&r[1])))
            .collect();
        let ids = &reference.ref_ids; // [b0, b1, b2, b3, b4, b5]
        let pr_max = pr.values().cloned().fold(f64::MIN, f64::max);
        // Bridge endpoints (b2, b3) are the unique maximum.
        assert!(
            (pr[&ids[2]] - pr_max).abs() <= PR_EPSILON
                && (pr[&ids[3]] - pr_max).abs() <= PR_EPSILON,
            "bridge endpoints must hold the max PageRank ({pr_max})"
        );
        // Structural symmetry: b0==b1, b4==b5, b2==b3 (within epsilon).
        for (x, y) in [(ids[0], ids[1]), (ids[4], ids[5]), (ids[2], ids[3])] {
            assert!(
                (pr[&x] - pr[&y]).abs() <= PR_EPSILON,
                "PageRank symmetry broken: PR({x})={} != PR({y})={}",
                pr[&x],
                pr[&y]
            );
        }
    }

    run(
        &mut eng,
        "CALL gds.graph.drop('ref') YIELD nodeCount RETURN nodeCount",
    );

    // (g) Shortest paths: project undirected unweighted, Dijkstra from b0 — unit weights ⇒ hops.
    {
        run(
            &mut eng,
            "CALL gds.graph.project('refp','Ref','LINKS',{}) YIELD nodeCount RETURN nodeCount",
        );
        let b0_prop = reference.shortest_paths_from_first[0].0;
        let src = to_internal[&b0_prop];
        let query = format!(
            "CALL gds.dijkstra.stream('refp',{{sourceNode:{src}}}) YIELD nodeId, distance \
             RETURN nodeId, distance"
        );
        let rows = run(&mut eng, &query);
        let mut got: Vec<(i64, i64)> = rows
            .iter()
            .map(|r| (prop(as_int(&r[0])), as_int(&r[1])))
            .collect();
        got.sort_unstable();
        let mut expected = reference.shortest_paths_from_first.clone();
        expected.sort_unstable();
        assert_eq!(
            got, expected,
            "reference shortest-path vector must match ground truth"
        );
        run(
            &mut eng,
            "CALL gds.graph.drop('refp') YIELD nodeCount RETURN nodeCount",
        );
    }

    // =============================================================================================
    // THE INFLUENCE NETWORK — planted-field community recovery + the full algorithm suite.
    // =============================================================================================

    // (a) Community recovery: WCC over the :CITES-only projection recovers exactly
    //     `planted_field_count` components, each of size `planted_field_size`.
    {
        run(
            &mut eng,
            "CALL gds.graph.project('comm','Author','CITES',{}) YIELD nodeCount RETURN nodeCount",
        );
        let rows = run(
            &mut eng,
            "CALL gds.wcc.stream('comm',{}) YIELD nodeId, componentId RETURN nodeId, componentId",
        );
        let mut sizes: BTreeMap<i64, i64> = BTreeMap::new();
        for r in &rows {
            *sizes.entry(as_int(&r[1])).or_default() += 1;
        }
        assert_eq!(
            sizes.len() as i64,
            reference.planted_field_count,
            "WCC over :CITES must recover exactly the planted field count"
        );
        for (&c, &sz) in &sizes {
            assert_eq!(
                sz, reference.planted_field_size,
                "planted field component {c} must have the planted field size"
            );
        }
        run(
            &mut eng,
            "CALL gds.graph.drop('comm') YIELD nodeCount RETURN nodeCount",
        );
    }

    // (b) The full algorithm suite over the WHOLE influence network (all rel types: :CITES+:CROSS).
    //     Undirected projection ('inf') for the symmetric algorithms; directed ('infd') for SCC +
    //     the single-source shortest paths. Each yields one row per author (single-source: >= 1).
    {
        run(
            &mut eng,
            "CALL gds.graph.project('inf','Author',null,{}) YIELD nodeCount RETURN nodeCount",
        );
        run(
            &mut eng,
            "CALL gds.graph.project('infd','Author',null,{orientation:'NATURAL'}) \
             YIELD nodeCount RETURN nodeCount",
        );

        // Internal id of the author with property id 0 — the single-source seed.
        let src_author = {
            let rows = run(&mut eng, "MATCH (a:Author {id:0}) RETURN id(a) AS nid");
            as_int(&rows[0][0])
        };

        let per_author: &[(&str, String)] = &[
            (
                "pageRank",
                "CALL gds.pageRank.stream('infd',{}) YIELD nodeId, score RETURN count(*) AS c"
                    .to_owned(),
            ),
            (
                "degree",
                "CALL gds.degree.stream('inf',{}) YIELD nodeId, score RETURN count(*) AS c"
                    .to_owned(),
            ),
            (
                "betweenness",
                "CALL gds.betweenness.stream('inf',{}) YIELD nodeId, score RETURN count(*) AS c"
                    .to_owned(),
            ),
            (
                "closeness",
                "CALL gds.closeness.stream('inf',{}) YIELD nodeId, score RETURN count(*) AS c"
                    .to_owned(),
            ),
            (
                "wcc",
                "CALL gds.wcc.stream('inf',{}) YIELD nodeId, componentId RETURN count(*) AS c"
                    .to_owned(),
            ),
            (
                "scc",
                "CALL gds.scc.stream('infd',{}) YIELD nodeId, componentId RETURN count(*) AS c"
                    .to_owned(),
            ),
            (
                "triangleCount",
                "CALL gds.triangleCount.stream('inf',{}) YIELD nodeId, triangleCount \
                 RETURN count(*) AS c"
                    .to_owned(),
            ),
            (
                "labelPropagation",
                "CALL gds.labelPropagation.stream('inf',{}) YIELD nodeId, communityId \
                 RETURN count(*) AS c"
                    .to_owned(),
            ),
        ];
        for (name, q) in per_author {
            let rows = run(&mut eng, q);
            assert_eq!(
                as_int(&rows[0][0]),
                author_count,
                "influence-net {name} must return one row per author"
            );
        }

        // Single-source shortest paths: at least the source is reachable.
        for (name, q) in [
            (
                "dijkstra",
                format!(
                    "CALL gds.dijkstra.stream('infd',{{sourceNode:{src_author}}}) \
                     YIELD nodeId, distance RETURN count(*) AS c"
                ),
            ),
            (
                "bellmanFord",
                format!(
                    "CALL gds.bellmanFord.stream('infd',{{sourceNode:{src_author}}}) \
                     YIELD nodeId, distance RETURN count(*) AS c"
                ),
            ),
        ] {
            let rows = run(&mut eng, &q);
            assert!(
                as_int(&rows[0][0]) >= 1,
                "single-source {name} must reach at least the source"
            );
        }

        run(
            &mut eng,
            "CALL gds.graph.drop('inf') YIELD nodeCount RETURN nodeCount",
        );
        run(
            &mut eng,
            "CALL gds.graph.drop('infd') YIELD nodeCount RETURN nodeCount",
        );
    }

    // The projection catalog must be empty after the drops (CSR released cleanly).
    {
        let rows = run(
            &mut eng,
            "CALL gds.graph.list() YIELD graphName RETURN count(*) AS c",
        );
        assert_eq!(
            as_int(&rows[0][0]),
            0,
            "all CSR projections must be released after drop"
        );
    }
}
