//! **The official driver's `UNWIND … MATCH … CREATE` idiom, deterministically, with parameters**
//! (`rmp` task #960).
//!
//! # What this reproduces
//!
//! Every Neo4j driver writes relationships in bulk the same way: drive rows with `UNWIND`, look each
//! endpoint up by key with `MATCH`, then `CREATE` the edge — and it sends the values as **parameters**,
//! because parameters are the only thing a driver can send. `rmp` #865 made the cost-based planner
//! rewrite the endpoint lookup into a [`ValueHashJoin`], moving the equality onto the operator as a
//! join-key expression; the parameter binder's join arm matched `{ left, right, .. }` and never walked
//! those keys. The `$param` was then unbound, `eval` resolved it to `Null`, `Null` matched nothing, and
//! the read prefix produced **no driving rows** — so the `CREATE` ran zero times and the relationships
//! were silently never written. No error, no warning, an empty result.
//!
//! This is the deterministic twin of
//! `graphus-server/tests/neo4j_driver_interop.rs::official_neo4j_driver_full_crud_nodes_and_edges`,
//! which failed at exactly this step (`after CREATE edges, count=0, expected 200`). That suite needs
//! `node`, `npm` and the network; this one needs none of them and is reproducible from its seed, so the
//! regression is guarded on every `cargo test` run rather than only when the interop feature is enabled.
//!
//! # Why it runs over the simulated Bolt wire
//!
//! The defect is only reachable through the **production** query path: the cost-based planner needs
//! live statistics to choose a `ValueHashJoin` at all, and the parameters must arrive the way a driver
//! sends them. `graphus_dst::wire` drives the real [`BoltSession`] state machine and the real
//! PackStream codec against the real engine over the simulated network, so `RUN` carries a real
//! parameter map into the real binder — the same seam the official driver reaches, minus the
//! nondeterminism.
//!
//! # Why it cannot pass vacuously
//!
//! Three controls, because "200 edges exist" is easy to produce by accident:
//!
//! 1. **The operator must be on the path.** `ValueHashJoin` is chosen only with statistics and no
//!    usable index; if a planner change stopped choosing it, this scenario would be exercising the
//!    always-correct `NestedLoopJoin` + `Filter` plan and would prove nothing. So the scenario
//!    `EXPLAIN`s the read prefix and asserts the operator is really there.
//! 2. **The driving rows must be counted, not inferred.** The read prefix is run on its own and its
//!    row count asserted, so a failure says *the MATCH found nothing* rather than *the CREATE misfired*.
//! 3. **A literal control arm.** The identical statement with `100` written out instead of `$n` runs
//!    on a separate engine and must produce the same 200 edges — proving the corpus and the idiom can
//!    produce them, so the parameterised arm's number means something.

use std::cell::RefCell;
use std::rc::Rc;
use std::sync::Arc;

use graphus_bolt::{BoltValue, Request, Response};
use graphus_core::Value;
use graphus_core::capability::Clock;
use graphus_dst::wire::{SharedEngine, login_prologue, run_scripted_bolt_session, sim_auth};
use graphus_server::engine::LocalEngine;
use graphus_sim::SharedClock;

/// The seed every run in this file uses. Fixed, so a failure reproduces exactly.
const SEED: u64 = 0x0960_2026;
/// `:Person` nodes seeded, and the modulus the edge query wraps on.
const N: i64 = 100;
/// Relationships the idiom must create: two per person.
const E: i64 = 2 * N;
/// Buffer-pool frames — enough for the corpus, small enough to stay quick.
const POOL_PAGES: usize = 512;

fn engine() -> SharedEngine {
    let clock: Arc<dyn Clock + Send + Sync> = Arc::new(SharedClock::new(0));
    Rc::new(RefCell::new(
        LocalEngine::in_memory(clock, POOL_PAGES).expect("engine"),
    ))
}

/// Runs `(query, parameters)` pairs in one Bolt session over the simulated network.
fn session(eng: SharedEngine, stmts: &[(&str, Vec<(String, Value)>)]) -> Vec<Response> {
    let auth = sim_auth();
    let mut reqs = login_prologue();
    for (q, params) in stmts {
        reqs.push(Request::Run {
            query: (*q).to_owned(),
            parameters: params.clone(),
            extra: vec![],
        });
        reqs.push(Request::Pull { n: -1, qid: None });
    }
    reqs.push(Request::Goodbye);
    run_scripted_bolt_session(eng, SEED, &auth, &reqs).expect("the session runs")
}

/// Asserts no statement in the session failed, quoting the failure if one did.
fn assert_no_failure(responses: &[Response], what: &str) {
    let failure = responses.iter().find_map(|r| match r {
        Response::Failure(meta) => Some(format!("{meta:?}")),
        _ => None,
    });
    assert!(failure.is_none(), "{what} failed: {}", failure.unwrap());
}

/// The first integer any `RECORD` in `responses` carries — the scalar of a one-column
/// `RETURN count(...)`.
fn scalar(responses: &[Response], what: &str) -> i64 {
    responses
        .iter()
        .find_map(|r| match r {
            Response::Record { values } => match values.first() {
                Some(BoltValue::Value(Value::Integer(n))) => Some(*n),
                _ => None,
            },
            _ => None,
        })
        .unwrap_or_else(|| panic!("{what}: no integer record in {responses:?}"))
}

/// How many `RECORD`s the session emitted.
fn records(responses: &[Response]) -> usize {
    responses
        .iter()
        .filter(|r| matches!(r, Response::Record { .. }))
        .count()
}

/// The `operatorType`s of the plan the last plan-carrying `SUCCESS` reports.
fn plan_operators(responses: &[Response]) -> Vec<String> {
    fn map_get<'v>(v: &'v Value, key: &str) -> Option<&'v Value> {
        match v {
            Value::Map(entries) => entries.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }
    fn walk(node: &Value, out: &mut Vec<String>) {
        if let Some(Value::String(t)) = map_get(node, "operatorType") {
            out.push(t.clone());
        }
        if let Some(Value::List(children)) = map_get(node, "children") {
            for c in children {
                walk(c, out);
            }
        }
    }
    let plan = responses
        .iter()
        .rev()
        .find_map(|r| match r {
            Response::Success { metadata } => ["profile", "plan"].iter().find_map(|key| {
                metadata
                    .iter()
                    .find(|(k, _)| k == key)
                    .map(|(_, v)| v.clone())
            }),
            _ => None,
        })
        .expect("EXPLAIN reports a plan");
    let mut out = Vec::new();
    walk(&plan, &mut out);
    out
}

fn int(name: &str, v: i64) -> (String, Value) {
    (name.to_owned(), Value::Integer(v))
}

/// Seeds `N` `:Person` nodes over the wire, exactly as the interop test's step 1 does.
fn seed(eng: &SharedEngine) {
    let r = session(
        Rc::clone(eng),
        &[(
            "UNWIND range(0, $max) AS i \
             CREATE (p:Person {id: i, name: 'person-' + toString(i), score: i})",
            vec![int("max", N - 1)],
        )],
    );
    assert_no_failure(&r, "the seed");
    let counted = session(
        Rc::clone(eng),
        &[("MATCH (p:Person) RETURN count(p) AS c", vec![])],
    );
    assert_eq!(
        scalar(&counted, "seeded nodes"),
        N,
        "the fixture must seed {N} nodes before anything else is measured"
    );
}

/// The read prefix of the driver's edge-creation idiom, parameterised.
const READ_PREFIX_PARAM: &str = "UNWIND range(0, $max) AS i \
     MATCH (a:Person {id: i}) \
     MATCH (b:Person {id: (i + 1) % $n}) \
     MATCH (c:Person {id: (i + 2) % $n}) \
     RETURN count(*) AS c";

/// The full idiom, parameterised — the statement the official driver sends.
const CREATE_EDGES_PARAM: &str = "UNWIND range(0, $max) AS i \
     MATCH (a:Person {id: i}) \
     MATCH (b:Person {id: (i + 1) % $n}) \
     MATCH (c:Person {id: (i + 2) % $n}) \
     CREATE (a)-[:KNOWS {weight: 1}]->(b) \
     CREATE (a)-[:KNOWS {weight: 2}]->(c)";

/// The same idiom with the modulus written as a literal — the control arm.
const CREATE_EDGES_LITERAL: &str = "UNWIND range(0, 99) AS i \
     MATCH (a:Person {id: i}) \
     MATCH (b:Person {id: (i + 1) % 100}) \
     MATCH (c:Person {id: (i + 2) % 100}) \
     CREATE (a)-[:KNOWS {weight: 1}]->(b) \
     CREATE (a)-[:KNOWS {weight: 2}]->(c)";

fn edge_params() -> Vec<(String, Value)> {
    vec![int("max", N - 1), int("n", N)]
}

/// The scenario: the driver's bulk-edge idiom, sent with parameters over Bolt, must write every edge.
#[test]
fn the_driver_edge_idiom_writes_every_edge_when_the_key_is_parameterised() {
    let eng = engine();
    seed(&eng);

    // CONTROL 1: the operator this regression is about is really on the path. Without this the whole
    // scenario could be exercising the nested-loop plan, which was never broken.
    let explained = session(
        Rc::clone(&eng),
        &[(&format!("EXPLAIN {READ_PREFIX_PARAM}"), edge_params())],
    );
    assert_no_failure(&explained, "EXPLAIN of the read prefix");
    let ops = plan_operators(&explained);
    assert!(
        ops.iter().any(|o| o == "ValueHashJoin"),
        "the fixture no longer plans a ValueHashJoin, so this scenario would prove nothing: {ops:?}"
    );

    // CONTROL 2: the read prefix on its own yields one driving row per person. Pre-fix this was 0, and
    // that — not the CREATE — is the defect.
    let prefix = session(Rc::clone(&eng), &[(READ_PREFIX_PARAM, edge_params())]);
    assert_no_failure(&prefix, "the parameterised read prefix");
    assert_eq!(
        scalar(&prefix, "driving rows"),
        N,
        "the parameterised MATCH prefix must find one row per person; 0 is `rmp` #960"
    );

    // The idiom itself.
    let created = session(Rc::clone(&eng), &[(CREATE_EDGES_PARAM, edge_params())]);
    assert_no_failure(&created, "the parameterised edge CREATE");
    let counted = session(
        Rc::clone(&eng),
        &[("MATCH ()-[r:KNOWS]->() RETURN count(r) AS c", vec![])],
    );
    assert_eq!(
        scalar(&counted, "edges"),
        E,
        "after the parameterised CREATE there must be {E} relationships"
    );

    // The edges are the RIGHT ones, not merely the right number: person 0 knows 1 and 2.
    let neighbours = session(
        eng,
        &[(
            "MATCH (a:Person {id: 0})-[:KNOWS]->(b) RETURN b.id AS id ORDER BY b.id",
            vec![],
        )],
    );
    assert_no_failure(&neighbours, "the neighbour read-back");
    assert_eq!(
        records(&neighbours),
        2,
        "person 0 must know exactly two people"
    );
}

/// CONTROL 3: the literal spelling of the same idiom, on its own engine, produces the same edges.
///
/// This is what makes the number in the test above meaningful: it proves the corpus, the idiom and the
/// wire can produce {E} edges, so the parameterised arm returning fewer is the binder's fault and not
/// the fixture's.
#[test]
fn the_literal_spelling_of_the_same_idiom_writes_the_same_edges() {
    let eng = engine();
    seed(&eng);
    let created = session(Rc::clone(&eng), &[(CREATE_EDGES_LITERAL, vec![])]);
    assert_no_failure(&created, "the literal edge CREATE");
    let counted = session(
        eng,
        &[("MATCH ()-[r:KNOWS]->() RETURN count(r) AS c", vec![])],
    );
    assert_eq!(
        scalar(&counted, "edges"),
        E,
        "the literal spelling must write {E} relationships"
    );
}

/// Determinism: the same seed twice yields the same graph, which is what makes this a DST scenario
/// rather than an ad-hoc test.
///
/// The oracle is the whole materialised edge set, not just its cardinality: two runs that wrote the
/// same NUMBER of different edges would be a real determinism failure, and a count cannot see it.
#[test]
fn the_scenario_is_deterministic_across_runs() {
    /// The `(a.id, b.id)` pairs of every `:KNOWS` edge, sorted — the run's full observable outcome.
    ///
    /// Sorted **here**, not with an `ORDER BY`: after `RETURN a.id AS a`, the name `a` denotes the
    /// projected integer, so an `ORDER BY a.id` would evaluate `.id` on an integer and sort by null.
    /// Doing it in Rust keeps this oracle about the edges written, not about projection scoping.
    fn edge_set(eng: SharedEngine) -> Vec<(i64, i64)> {
        let r = session(
            eng,
            &[(
                "MATCH (a:Person)-[:KNOWS]->(b:Person) RETURN a.id AS a, b.id AS b",
                vec![],
            )],
        );
        assert_no_failure(&r, "the edge read-back");
        let mut pairs: Vec<(i64, i64)> = r
            .iter()
            .filter_map(|resp| match resp {
                Response::Record { values } => match (values.first(), values.get(1)) {
                    (
                        Some(BoltValue::Value(Value::Integer(a))),
                        Some(BoltValue::Value(Value::Integer(b))),
                    ) => Some((*a, *b)),
                    _ => None,
                },
                _ => None,
            })
            .collect();
        pairs.sort_unstable();
        pairs
    }

    let runs: Vec<Vec<(i64, i64)>> = (0..2)
        .map(|_| {
            let eng = engine();
            seed(&eng);
            assert_no_failure(
                &session(Rc::clone(&eng), &[(CREATE_EDGES_PARAM, edge_params())]),
                "the parameterised edge CREATE",
            );
            edge_set(eng)
        })
        .collect();

    let expected: Vec<(i64, i64)> = {
        let mut e: Vec<(i64, i64)> = (0..N)
            .flat_map(|i| [(i, (i + 1) % N), (i, (i + 2) % N)])
            .collect();
        e.sort_unstable();
        e
    };
    assert_eq!(
        runs[0].len() as i64,
        E,
        "run 1 must write every one of the {E} edges"
    );
    assert_eq!(runs[0], expected, "run 1 wrote exactly the intended edges");
    assert_eq!(runs[0], runs[1], "the same seed gives the same graph");
}
