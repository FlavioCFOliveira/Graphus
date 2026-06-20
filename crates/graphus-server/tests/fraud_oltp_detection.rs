//! Hermetic cargo mirror of the `examples/fraud-oltp` detection workload (`rmp #255`).
//!
//! This is the **default-run, npm-free** counterpart of the example's official-driver `detect.js`:
//! it generates the SAME deterministic, seeded fraud graph (`graphus-fraud-gen`, fast profile),
//! loads it into the REAL Graphus engine **in process** via `LocalEngine` (no Bolt, no Node, no
//! network), runs the SAME three detection queries, and asserts the findings equal the planted
//! `GroundTruth` set **exactly** — zero false negatives, zero false positives on the seeded set.
//!
//! Where the shell example proves the wire path (the official `neo4j-driver` over Bolt/TLS), this
//! test proves the *engine semantics* the detection relies on, hermetically, in the default
//! `cargo test` run. The official-driver E2E (the Node path) stays in `examples/fraud-oltp/run.sh`,
//! opt-in via `RUN_DRIVER`.
//!
//! The detection queries are kept byte-identical to `data/detect.js` so the two paths assert the
//! same thing through different front doors.

use std::sync::Arc;

use graphus_core::Value;
use graphus_cypher::MaterializedValue;
use graphus_fraud_gen::{Profile, generate};
use graphus_io::MemBlockDevice;
use graphus_server::engine::LocalEngine;
use graphus_server::engine::command::AccessMode;
use graphus_sim::SharedClock;
use graphus_wal::MemLogSink;

type Eng = LocalEngine<MemBlockDevice, MemLogSink>;

// ---- Detection queries — byte-identical to `examples/fraud-oltp/data/detect.js` ----------------

/// RINGS: an explicit 3-hop closed cycle `a->b->c->a` where every TRANSFER is above the fraud amount
/// floor (>= 9000), with distinct-node guards. Returns DISTINCT participating account ids.
const RING_QUERY: &str = "\
MATCH (a:Account)-[r1:TRANSFER]->(b:Account)-[r2:TRANSFER]->(c:Account)-[r3:TRANSFER]->(a)
WHERE r1.amount >= 9000 AND r2.amount >= 9000 AND r3.amount >= 9000
  AND a.id <> b.id AND b.id <> c.id AND a.id <> c.id
RETURN DISTINCT a.id AS id ORDER BY id";

/// MULES: large fan-IN (>= 6 distinct sources sending >= 2000) AND large fan-OUT (>= 6 distinct
/// destinations receiving >= 2000), via two-stage WITH aggregation.
const MULE_QUERY: &str = "\
MATCH (m:Account)<-[ri:TRANSFER]-(src:Account) WHERE ri.amount >= 2000
WITH m, count(DISTINCT src) AS fanin
WHERE fanin >= 6
MATCH (m)-[ro:TRANSFER]->(dst:Account) WHERE ro.amount >= 2000
WITH m, fanin, count(DISTINCT dst) AS fanout
WHERE fanout >= 6
RETURN m.id AS id ORDER BY id";

/// VELOCITY (structuring): an account emitting a burst of >= 6 large (>= 2000) outgoing transfers.
const VELOCITY_QUERY: &str = "\
MATCH (s:Account)-[t:TRANSFER]->(:Account) WHERE t.amount >= 2000
WITH s, count(t) AS bursts, sum(t.amount) AS volume
WHERE bursts >= 6
RETURN s.id AS id ORDER BY volume DESC, id";

/// Builds an in-memory engine with a fixed clock — the deterministic, hermetic substrate.
fn engine() -> Eng {
    LocalEngine::in_memory(Arc::new(SharedClock::new(0)), 1024).expect("in-memory engine")
}

/// Loads every data statement inside a SINGLE write transaction, then commits once.
///
/// Batching the whole load into one transaction (rather than auto-committing each `CREATE`) keeps the
/// hermetic test fast — the planted graph is loaded atomically and the detection reads see the same
/// committed snapshot the official-driver path produces. Correctness is unaffected: the detection
/// queries run after the commit, against the durable graph.
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

/// Runs a read query and collects its single integer `id` column into a sorted, de-duplicated set.
fn collect_ids(eng: &mut Eng, query: &str) -> Vec<i64> {
    let ticket = eng.begin(AccessMode::Read).expect("begin read txn");
    let mut reply = eng
        .run(ticket, query, Vec::new(), false, None)
        .expect("detection query runs");
    let mut ids = Vec::new();
    while let Ok(Some(row)) = reply.rows.next() {
        if let Some(MaterializedValue::Value(Value::Integer(n))) = row.first() {
            ids.push(*n);
        }
    }
    eng.commit(ticket).expect("commit read txn");
    ids.sort_unstable();
    ids.dedup();
    ids
}

/// A `;`-terminated statement iterator over the generated Cypher script, dropping `//` comment lines
/// and the schema DDL (`CREATE CONSTRAINT` / `CREATE INDEX`) — the engine's `run` path loads data
/// CREATEs only; the DDL is a performance optimisation the official-driver path applies over Bolt,
/// not a correctness precondition for detection.
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

#[test]
fn fast_profile_detection_matches_ground_truth_exactly() {
    // 1. Generate the deterministic fast-profile graph + ground truth (the same artifacts the shell
    //    example's `gen` binary writes — here used in-process).
    let cfg = Profile::Fast.config();
    let dataset = generate(cfg, Profile::Fast.name());
    let gt = &dataset.ground_truth;

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

    // Sanity: the account count matches the generated dataset.
    let account_count = {
        let ticket = eng.begin(AccessMode::Read).expect("begin count txn");
        let mut reply = eng
            .run(
                ticket,
                "MATCH (a:Account) RETURN count(a) AS c",
                Vec::new(),
                false,
                None,
            )
            .expect("count query");
        let mut c = 0;
        while let Ok(Some(row)) = reply.rows.next() {
            if let Some(MaterializedValue::Value(Value::Integer(n))) = row.first() {
                c = *n;
            }
        }
        eng.commit(ticket).expect("commit count txn");
        c
    };
    assert_eq!(
        account_count as usize,
        dataset.accounts.len(),
        "loaded account count must equal the generated dataset"
    );

    // 3. Run detection.
    let ring_ids = collect_ids(&mut eng, RING_QUERY);
    let mule_ids = collect_ids(&mut eng, MULE_QUERY);
    let velocity_ids = collect_ids(&mut eng, VELOCITY_QUERY);

    // 4. Assert EXACT match against ground truth (the same assertions as `detect.js`).
    let mut gt_rings: Vec<i64> = gt.rings.iter().flat_map(|r| r.accounts.clone()).collect();
    gt_rings.sort_unstable();
    gt_rings.dedup();
    assert_eq!(
        ring_ids, gt_rings,
        "ring accounts must match ground truth exactly (no FP/FN)"
    );

    let mut gt_mules: Vec<i64> = gt.mules.iter().map(|m| m.mule).collect();
    gt_mules.sort_unstable();
    gt_mules.dedup();
    assert_eq!(
        mule_ids, gt_mules,
        "mule accounts must match ground truth exactly (no FP/FN)"
    );
    assert_eq!(
        velocity_ids, gt_mules,
        "velocity must independently re-identify exactly the mules"
    );

    // 5. The UNION of ring + mule detections must equal the full ground-truth fraud set.
    let mut union: Vec<i64> = ring_ids.iter().chain(mule_ids.iter()).copied().collect();
    union.sort_unstable();
    union.dedup();
    assert_eq!(
        union, gt.fraud_accounts,
        "the union of detections must equal the planted fraud-account set"
    );
}
