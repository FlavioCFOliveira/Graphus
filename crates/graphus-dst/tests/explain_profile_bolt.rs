//! **Deterministic** `EXPLAIN` / `PROFILE` over the simulated Bolt wire (`rmp` task #752).
//!
//! The real-server test (`graphus-server/tests/explain_profile_wire.rs`) proves the feature over a real
//! socket; this one proves the same properties **deterministically**, through the DST simulator's Bolt
//! wire (`graphus_dst::wire` — the real [`BoltSession`] state machine, the real PackStream codec, the real
//! engine, over the simulated network), so any failure is exactly reproducible from its seed.
//!
//! It also covers the seam the real-wire test cannot: the deterministic engine runs every statement
//! **inline** (it has no reader pool), so the index seek is really served by the store — and the measured
//! `dbHits` show it, a handful against a whole-store scan. That is the number the reader-pool path does
//! *not* achieve today (see the finding pinned in the real-wire test).

use std::cell::RefCell;
use std::rc::Rc;
use std::sync::Arc;

use graphus_bolt::{Request, Response};
use graphus_core::Value;
use graphus_core::capability::Clock;
use graphus_dst::wire::{SharedEngine, login_prologue, run_scripted_bolt_session, sim_auth};
use graphus_server::engine::{IndexCommand, LocalEngine};
use graphus_sim::SharedClock;

fn clock() -> Arc<dyn Clock + Send + Sync> {
    Arc::new(SharedClock::new(0))
}

fn engine() -> SharedEngine {
    Rc::new(RefCell::new(
        LocalEngine::in_memory(clock(), 256).expect("engine"),
    ))
}

/// Runs `stmts` in one Bolt session over the simulated network, returning every decoded response.
fn session(eng: SharedEngine, seed: u64, stmts: &[&str]) -> Vec<Response> {
    let auth = sim_auth();
    let mut reqs = login_prologue();
    for q in stmts {
        reqs.push(Request::Run {
            query: (*q).to_owned(),
            parameters: vec![],
            extra: vec![],
        });
        reqs.push(Request::Pull { n: -1, qid: None });
    }
    reqs.push(Request::Goodbye);
    run_scripted_bolt_session(eng, seed, &auth, &reqs).expect("session runs")
}

/// The `plan` / `profile` map of the **last** `SUCCESS` that carries one, with the key it came under.
fn last_plan(responses: &[Response]) -> Option<(String, Value)> {
    responses.iter().rev().find_map(|r| match r {
        Response::Success { metadata } => ["profile", "plan"].iter().find_map(|key| {
            metadata
                .iter()
                .find(|(k, _)| k == key)
                .map(|(_, v)| ((*key).to_owned(), v.clone()))
        }),
        _ => None,
    })
}

fn map_get<'v>(v: &'v Value, key: &str) -> Option<&'v Value> {
    match v {
        Value::Map(entries) => entries.iter().find(|(k, _)| k == key).map(|(_, v)| v),
        _ => None,
    }
}

fn operators(node: &Value) -> Vec<String> {
    let mut out = Vec::new();
    if let Some(Value::String(t)) = map_get(node, "operatorType") {
        out.push(t.clone());
    }
    if let Some(Value::List(children)) = map_get(node, "children") {
        for c in children {
            out.extend(operators(c));
        }
    }
    out
}

fn total_db_hits(node: &Value) -> i64 {
    let mine = match map_get(node, "dbHits") {
        Some(Value::Integer(n)) => *n,
        _ => 0,
    };
    let kids: i64 = match map_get(node, "children") {
        Some(Value::List(children)) => children.iter().map(total_db_hits).sum(),
        _ => 0,
    };
    mine + kids
}

/// The first plan node of `operatorType == kind` in a rendered plan tree, searched depth-first.
fn find_operator<'v>(node: &'v Value, kind: &str) -> Option<&'v Value> {
    if let Some(Value::String(t)) = map_get(node, "operatorType")
        && t == kind
    {
        return Some(node);
    }
    match map_get(node, "children") {
        Some(Value::List(children)) => children.iter().find_map(|c| find_operator(c, kind)),
        _ => None,
    }
}

/// The integer `args` entry `key` of a plan node, or [`None`] when the key is absent — which, for the
/// `rmp` #991 candidate counters on the store-backed seam this simulator runs, means a **measured
/// zero** (they are emitted only when non-zero, the same rule the result-summary `stats` map follows).
/// A seam that does not implement the tally at all emits none of them anywhere, and there absence
/// would instead mean "not measured"; the deterministic engine is store-backed, so that case cannot
/// arise here.
fn plan_arg(node: &Value, key: &str) -> Option<i64> {
    match map_get(node, "args").and_then(|args| map_get(args, key)) {
        Some(Value::Integer(n)) => Some(*n),
        _ => None,
    }
}

fn records(responses: &[Response]) -> usize {
    responses
        .iter()
        .filter(|r| matches!(r, Response::Record { .. }))
        .count()
}

/// Declares the node-property index the planner should use. The simulator's Bolt seam carries no index-DDL
/// surface (the DDL is parsed above the protocol, in the server's seam), so it is submitted straight to the
/// deterministic engine — the same `IndexCommand` the real Bolt seam builds after parsing `CREATE INDEX`.
fn declare_email_index(eng: &SharedEngine) {
    eng.borrow_mut()
        .index_ddl(IndexCommand::CreateNodePropertyIndex {
            name: Some("person_email".to_owned()),
            label: "Person".to_owned(),
            properties: vec!["email".to_owned()],
            if_not_exists: false,
        })
        .expect("the index is declared");
}

/// `PROFILE` over the deterministic Bolt wire: the plan comes back under `profile`, with the measured
/// per-operator counters — and, on the inline engine, the index seek really is served by the store.
#[test]
fn profile_over_the_simulated_wire_reports_a_measured_index_seek() {
    let seed = 0x5157_2026;
    let eng = engine();
    let seeded = session(
        Rc::clone(&eng),
        seed,
        &["UNWIND range(0, 199) AS i CREATE (:Person {email: 'u' + toString(i) + '@x.io'})"],
    );
    assert!(
        seeded.iter().all(|r| !matches!(r, Response::Failure(_))),
        "the seed statement succeeds"
    );
    declare_email_index(&eng);

    let with_index = session(
        Rc::clone(&eng),
        seed,
        &["PROFILE MATCH (p:Person {email: 'u7@x.io'}) RETURN p.email AS email"],
    );
    let (key, seek) = last_plan(&with_index).expect("a PROFILE reports a plan");
    assert_eq!(key, "profile", "a PROFILE is delivered under `profile`");
    let seek_ops = operators(&seek);
    assert!(
        seek_ops.iter().any(|o| o == "NodeIndexSeek"),
        "the declared index is used: {seek_ops:?}"
    );
    assert_eq!(
        map_get(&seek, "rows"),
        Some(&Value::Integer(1)),
        "the root emitted the one matching row"
    );
    let seek_hits = total_db_hits(&seek);

    // Now the regression: the index is dropped and the identical query is re-run.
    eng.borrow_mut()
        .index_ddl(IndexCommand::DropNodePropertyIndex {
            index: graphus_server::engine::NodePropertyIndexRef::Named("person_email".to_owned()),
            if_exists: false,
        })
        .expect("the index is dropped");
    let regressed = session(
        eng,
        seed,
        &["PROFILE MATCH (p:Person {email: 'u7@x.io'}) RETURN p.email AS email"],
    );
    let (_, scan) = last_plan(&regressed).expect("a plan");
    let scan_ops = operators(&scan);
    let scan_hits = total_db_hits(&scan);

    assert!(
        !scan_ops.iter().any(|o| o == "NodeIndexSeek"),
        "with no index there is no seek: {scan_ops:?}"
    );
    assert!(
        scan_ops.iter().any(|o| o == "NodeLabelScanEq"),
        "…it scans instead: {scan_ops:?}"
    );
    // The deterministic engine runs the statement inline, so the seek is REALLY served by the store:
    // its measured storage work is a small fraction of the scan's.
    assert!(
        scan_hits >= 200,
        "the scan read the whole 200-node store: {scan_hits}"
    );
    assert!(
        seek_hits * 4 < scan_hits,
        "the index seek reads a fraction of what the scan reads: seek={seek_hits} scan={scan_hits}"
    );
}

/// `EXPLAIN` over the deterministic wire: a plan under `plan`, zero records, and **no side effect**.
#[test]
fn explain_over_the_simulated_wire_plans_without_executing() {
    let eng = engine();
    let responses = session(
        Rc::clone(&eng),
        0x1234_5678,
        &["EXPLAIN CREATE (:Ghost {name: 'nobody'})"],
    );
    assert_eq!(records(&responses), 0, "EXPLAIN returns no records");
    let (key, plan) = last_plan(&responses).expect("EXPLAIN reports a plan");
    assert_eq!(
        key, "plan",
        "an EXPLAIN is delivered under `plan`, not `profile`"
    );
    assert!(operators(&plan).iter().any(|o| o == "Create"));
    assert!(
        map_get(&plan, "dbHits").is_none(),
        "nothing ran, so no runtime counter is reported"
    );

    // The node was not created — proven by reading the graph back over the same wire.
    let after = session(eng, 0x1234_5678, &["MATCH (g:Ghost) RETURN count(g) AS n"]);
    let counted = after.iter().find_map(|r| match r {
        Response::Record { values } => values.first().cloned(),
        _ => None,
    });
    assert_eq!(
        counted,
        Some(graphus_bolt::BoltValue::Value(Value::Integer(0))),
        "EXPLAIN CREATE created nothing, got {counted:?}"
    );

    // …and an ordinary statement carries no plan at all.
    let plain = session(engine(), 1, &["RETURN 1 AS explain"]);
    assert!(
        last_plan(&plain).is_none(),
        "no prefix ⇒ no plan key; `explain` is still an ordinary alias"
    );
}

// =================================================================================================
// The candidate + re-verification counters over the wire (`rmp` task #991)
// =================================================================================================

/// The **measured cost of the candidate model reaches the client**, deterministically, over the real
/// Bolt wire: an index seek reports the candidates it examined and the SIREAD markers it emitted, as
/// `args` entries of its own plan node.
///
/// The unit suite (`graphus-cypher/tests/candidate_instrumentation.rs`) pins the numbers against the
/// engine; this pins that they survive the whole path — recorder → `PlanDescription` → PackStream map
/// → decoded client value — with a seed that makes any failure exactly reproducible.
///
/// # Why this is not vacuous
///
/// Before `rmp` #991 no plan node carried any of these keys, so every `expect` below panics against the
/// pre-change engine. The load-bearing assertion is the **contrast**: the range seek's whole-store
/// blanket marker pass must dwarf the equality seek's precise footprint, over the same 200-node store.
#[test]
fn profile_over_the_simulated_wire_reports_the_candidate_counters_991() {
    let seed = 0x0991_2026;
    let eng = engine();
    let seeded = session(
        Rc::clone(&eng),
        seed,
        &[
            "UNWIND range(0, 199) AS i CREATE (:Person {email: 'u' + toString(i) + '@x.io', age: i})",
        ],
    );
    assert!(
        seeded.iter().all(|r| !matches!(r, Response::Failure(_))),
        "the seed statement succeeds"
    );
    declare_email_index(&eng);

    let responses = session(
        Rc::clone(&eng),
        seed,
        &["PROFILE MATCH (p:Person {email: 'u7@x.io'}) RETURN p.email AS email"],
    );
    let (key, plan) = last_plan(&responses).expect("a PROFILE reports a plan");
    assert_eq!(key, "profile");
    let seek = find_operator(&plan, "NodeIndexSeek").expect("the declared index is used");

    let examined = plan_arg(seek, "CandidatesExamined")
        .expect("the seek reports the candidates it examined (rmp #991)");
    let markers = plan_arg(seek, "ReadMarkers")
        .expect("the seek reports the SIREAD markers it emitted (rmp #991)");
    assert!(examined >= 1, "the seek examined its candidate: {examined}");
    assert!(markers >= 1, "…and marked what it read: {markers}");
    assert!(
        markers < 200,
        "an EQUALITY seek must not mark every live node (rmp #316 removed that blanket): {markers}"
    );

    // The contrast: a RANGE seek over the same store carries the blanket `mark_all_live_nodes`
    // footprint — one marker per live node — however few rows it returns.
    let ranged = session(
        eng,
        seed,
        &["PROFILE MATCH (p:Person) WHERE p.age >= 198 RETURN p.age AS age"],
    );
    let (_, range_plan) = last_plan(&ranged).expect("a PROFILE reports a plan");
    let scan = find_operator(&range_plan, "NodeLabelScan")
        .or_else(|| find_operator(&range_plan, "TokenLookupScan"))
        .or_else(|| find_operator(&range_plan, "NodeIndexRangeSeek"))
        .expect("the range predicate is served by some node access path");
    let range_markers =
        plan_arg(scan, "ReadMarkers").expect("the range access path reports its markers");
    assert!(
        range_markers >= 200,
        "the range path marks every live node in the store: {range_markers}"
    );
    assert!(
        range_markers > 10 * markers,
        "the blanket footprint ({range_markers}) must be measurably heavier than the precise \
         equality one ({markers}) — the whole point of counting markers"
    );
}

/// An `EXPLAIN` executes nothing, so it measures nothing: no candidate counter appears anywhere in the
/// plan it delivers. The wire-side twin of the "omitted counters stay omitted" unit test.
#[test]
fn explain_over_the_simulated_wire_reports_no_candidate_counters_991() {
    let eng = engine();
    declare_email_index(&eng);
    let responses = session(
        eng,
        0x0991_2027,
        &["EXPLAIN MATCH (p:Person {email: 'u7@x.io'}) RETURN p.email AS email"],
    );
    let (key, plan) = last_plan(&responses).expect("EXPLAIN reports a plan");
    assert_eq!(key, "plan");

    fn assert_clean(node: &Value) {
        for measured in [
            "CandidatesExamined",
            "CandidatesRejectedByVisibility",
            "CandidatesRejectedByFilter",
            "ReadMarkers",
            "PredicateMarkers",
        ] {
            assert!(
                plan_arg(node, measured).is_none(),
                "an EXPLAIN runs nothing, so it reports no {measured}"
            );
        }
        // …and the counters Graphus does not measure at all are still absent (decision
        // `D-query-prefixes`), exactly as they were before this task added new ones.
        for unmeasured in [
            "pageCacheHits",
            "pageCacheMisses",
            "pageCacheHitRatio",
            "time",
        ] {
            assert!(
                plan_arg(node, unmeasured).is_none(),
                "{unmeasured} is never reported"
            );
        }
        if let Some(Value::List(children)) = map_get(node, "children") {
            for c in children {
                assert_clean(c);
            }
        }
    }
    assert_clean(&plan);
}
