//! Regression: QPP / variable-length traversal resource-exhaustion DoS (`rmp` #656).
//!
//! Two inviolable-availability defects a single crafted query could use to abort the whole server
//! (every tenant the engine thread hosts):
//!
//! 1. **Unbounded DFS recursion → stack overflow (SIGABRT).** The QPP walk
//!    (`executor::quantified_path_into_pending`) and the variable-length expand
//!    (`executor::var_expand_into_pending`) recursed ~O(path length) deep. A long chain overflowed the
//!    finite worker-thread stack — an *uncatchable* process abort. Fixed by rewriting both walks as an
//!    **iterative** depth-first traversal over an explicit heap-allocated stack, so an arbitrarily long
//!    walk uses O(1) native stack and can never overflow.
//! 2. **Combinatorial trail-path blowup → memory exhaustion.** A `+` / `*` walk over a dense
//!    (near-complete) digraph enumerates a super-polynomial number of trail paths, each materialised as
//!    a full `Row` into an uncapped `pending` queue. Fixed by charging each emitted row against a
//!    per-query materialisation budget (`PendingBudget`) tied to the shared per-value byte ceiling
//!    (`value_size::max_value_bytes`, `rmp` #489 / #491 / `SEC-191`; the breadth analogue of the
//!    `rmp` #550 decode budget), so the expansion is rejected with a clean, typed `ResourceLimit`
//!    instead of OOMing.
//!
//! These tests were the audit PoCs that reproduced the abort / blowup on the pre-fix HEAD; they are now
//! **passing regression tests** (no `#[ignore]`). They run as ordinary `cargo test`:
//! - `poc_a_stack_overflow_long_chain` and `deep_into_walk_completes_without_overflow` run on the
//!   default (2 MiB) test-thread stack — a *stricter* environment than the production runtime's 8 MiB
//!   threads (`rmp` #602). On the reverted (recursive) code they abort the whole binary; on the fixed
//!   code they return a `Result`.
//! - `poc_b_combinatorial_dense_graph` bounds the pending queue with a lowered budget so it rejects
//!   cleanly and memory-light; on the reverted code it exhausts memory.
use std::sync::Mutex;

use graphus_core::Value;
use graphus_cypher::binding::{Parameters, bind_parameters};
use graphus_cypher::catalog::IndexCatalog;
use graphus_cypher::executor::execute;
use graphus_cypher::graph_access::{MemGraph, NodeId};
use graphus_cypher::lexer::tokenize;
use graphus_cypher::lower::lower;
use graphus_cypher::parser::parse_tokens;
use graphus_cypher::physical::plan_physical;
use graphus_cypher::runtime::Row;
use graphus_cypher::semantics::analyze;
use graphus_cypher::value_size::BudgetOverride;

/// Serialises the process-global materialisation-budget override across this binary's tests (each may
/// lower the cap, so they must not run concurrently and observe each other's override).
static CAP_LOCK: Mutex<()> = Mutex::new(());

fn i(n: i64) -> Value {
    Value::Integer(n)
}

/// Drives the full compile → execute → drain pipeline for `src` over `graph`, returning the produced
/// `Row`s or `Err(message)` for whichever stage failed. Never panics on a *query outcome*, so a clean
/// rejection surfaces as `Err`, not an abort — the whole point of the regression (a bounded rejection
/// must be a recoverable error, never a crash).
fn run_outcome(src: &str, graph: &mut MemGraph) -> Result<Vec<Row>, String> {
    let toks = tokenize(src).map_err(|e| format!("lex: {e:?}"))?;
    let ast = parse_tokens(&toks, src).map_err(|e| format!("parse: {e:?}"))?;
    let validated = analyze(&ast).map_err(|e| format!("semantic: {e:?}"))?;
    let plan = plan_physical(&lower(&validated), &IndexCatalog::empty());
    let bound = bind_parameters(&plan, &Parameters::new()).map_err(|e| format!("bind: {e:?}"))?;
    let mut cursor = execute(&plan, &bound, graph).map_err(|e| format!("exec: {e}"))?;
    cursor.collect_all().map_err(|e| format!("{e}"))
}

/// True iff `outcome` is the typed materialisation-budget rejection (a `ResourceLimit`), as opposed to
/// a success or any other error class. Loose on wording, strict on shape: an error that mentions the
/// budget and is not a cancellation.
fn is_budget_rejection(outcome: &Result<Vec<Row>, String>) -> bool {
    match outcome {
        Ok(_) => false,
        Err(msg) => {
            let m = msg.to_lowercase();
            (m.contains("budget") || m.contains("limit") || m.contains("exceed"))
                && !m.contains("cancel")
        }
    }
}

/// Extracts the single `count(*)`/`count(x)` scalar from a one-row result.
fn count_of(rows: &[Row], col: &str) -> i64 {
    assert_eq!(
        rows.len(),
        1,
        "expected exactly one aggregate row, got {rows:?}"
    );
    match rows[0].value(col) {
        Value::Integer(n) => n,
        other => panic!("expected an integer count in `{col}`, got {other:?}"),
    }
}

/// Builds a directed chain `0 -[:R]-> 1 -[:R]-> ... -[:R]-> n` of `n` relationships and returns the
/// node ids (index == node's `id` property).
fn build_chain(g: &mut MemGraph, n: usize) -> Vec<NodeId> {
    let nodes: Vec<NodeId> = (0..=n)
        .map(|k| g.add_node(["N"], [("id", i(k as i64))]))
        .collect();
    for k in 0..n {
        g.add_rel("R", nodes[k], nodes[k + 1], [("w", i(0))]);
    }
    nodes
}

/// PoC A (stack overflow → SIGABRT on the reverted, recursive code). A directed chain of 50 000
/// relationships makes the QPP `+` trail walk descend ~O(N) deep. On the fixed, iterative code it runs
/// on the heap (never touching the native stack budget), so it does not abort: the expand-all `+` over
/// a chain enumerates one match per reachable endpoint (an O(N²) materialisation), which the per-query
/// budget rejects cleanly. The assertion demands the *shape* of the acceptance criterion — the process
/// survives and returns a `Result` — not a specific outcome.
#[test]
fn poc_a_stack_overflow_long_chain() {
    let _lock = CAP_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    // A modest ceiling keeps this test's transient memory light while the walk still descends far past
    // the depth at which the recursion aborted; the reverted code ignores the budget and overflows
    // regardless. The default 256 MiB ceiling would reject the same query, only heavier.
    let _budget = BudgetOverride::new(16 * 1024 * 1024);

    let n: usize = 50_000;
    let mut g = MemGraph::new();
    build_chain(&mut g, n);

    let outcome = run_outcome(
        "MATCH (a {id:0})((x)-[:R]->(y))+(b) RETURN count(b) AS c",
        &mut g,
    );
    // The inviolable property: a single query must never abort the server. Reaching this assertion at
    // all proves the walk did not overflow the stack; the outcome must be either a completed result or a
    // clean, typed budget rejection — never a crash and never some unrelated error.
    assert!(
        outcome.is_ok() || is_budget_rejection(&outcome),
        "the long-chain `+` QPP must NOT abort — it must complete or return a clean budget error. Got: {outcome:?}"
    );
}

/// PoC B (combinatorial blowup → memory exhaustion on the reverted code). A complete directed graph
/// `K_m` makes the `+` trail walk enumerate a super-polynomial number of simple (trail) paths, each a
/// full `Row` pushed into the uncapped `pending` queue. With the per-query budget lowered, the fixed
/// code rejects each such walk cleanly and memory-light the instant the materialisation would cross the
/// ceiling — a bounded, typed error rather than an unbounded blowup.
#[test]
fn poc_b_combinatorial_dense_graph() {
    let _lock = CAP_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    // A small ceiling: even `K_8` enumerates far more than this in trail-path rows, so the walk is
    // rejected almost immediately — the test never allocates the blowup the reverted code did.
    let _budget = BudgetOverride::new(512 * 1024);

    for m in [8usize, 9, 10, 11] {
        let mut g = MemGraph::new();
        let nodes: Vec<NodeId> = (0..m)
            .map(|k| g.add_node(["T"], [("id", i(k as i64))]))
            .collect();
        // Complete directed graph (every ordered pair, no self-loop): m*(m-1) edges.
        for a in 0..m {
            for b in 0..m {
                if a != b {
                    g.add_rel("E", nodes[a], nodes[b], [("w", i(0))]);
                }
            }
        }
        let outcome = run_outcome(
            "MATCH (a {id:0})((x)-[:E]->(y))+(b) RETURN count(*) AS c",
            &mut g,
        );
        assert!(
            is_budget_rejection(&outcome),
            "the dense-graph `+` QPP must be bounded by a clean budget rejection, not an unbounded blowup (K_{m}). Got: {outcome:?}"
        );
    }
}

/// Positive proof of the *depth* fix by **completion** (not merely by budget rejection), for BOTH the
/// variable-length expand (`var_expand_into_pending`) and the quantified-path walk
/// (`quantified_path_into_pending`) — the two distinct code paths #656 rewrote. Two deep walks over a
/// chain each descend to a depth that overflowed the former recursion, yet enumerate exactly ONE match,
/// so they finish well within the default budget — proving the iterative rewrite handles arbitrary
/// depth *and* preserves the exact trail semantics (the single path is returned, unchanged).
///
/// The walk runs on a thread with a **deliberately small stack** so the former recursion overflows at a
/// shallow depth — a chain of a few thousand edges suffices, which keeps the reference harness's
/// `MemGraph::expand` (an O(E) scan per hop) fast. On the reverted, recursive code this thread overflows
/// its stack and aborts the whole binary (an uncatchable failure the test harness reports as a crash);
/// on the fixed, iterative code it completes because the walk's depth lives on the heap, not the native
/// stack. Both endpoints are bound (`expand-into`) for the variable-length case; the quantified-path
/// case uses an exact `{n}` quantifier so only the single full-length walk is emitted.
#[test]
fn deep_walks_do_not_overflow_the_stack() {
    // Held across the spawned thread's lifetime: the thread runs at the default (production) budget, so
    // it must not observe another test's lowered override.
    let _lock = CAP_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let handle = std::thread::Builder::new()
        .name("deep-walk".into())
        // ~1 MiB: ample for the shallow query-compile / iterative-walk work of the fixed code, but far
        // too little for the former recursion to descend `n` frames deep.
        .stack_size(1024 * 1024)
        .spawn(|| {
            let n: usize = 6_000;
            let mut g = MemGraph::new();
            build_chain(&mut g, n);

            // (1) Variable-length expand-into: exactly one trail reaches the far endpoint of a chain.
            let vlen = run_outcome(
                &format!(
                    "MATCH (a {{id:0}}), (b {{id:{n}}}) MATCH (a)-[:R*]->(b) RETURN count(*) AS c"
                ),
                &mut g,
            )
            .expect("a deep variable-length expand-into must complete without overflow");
            assert_eq!(
                count_of(&vlen, "c"),
                1,
                "exactly one variable-length trail connects the ends of a chain"
            );

            // (2) Quantified path with an exact quantifier: only the single n-iteration walk over the
            // chain.
            let qpp = run_outcome(
                &format!("MATCH (a {{id:0}})((x)-[:R]->(y)){{{n}}}(b) RETURN count(*) AS c"),
                &mut g,
            )
            .expect("a deep exact-quantifier QPP must complete without overflow");
            assert_eq!(
                count_of(&qpp, "c"),
                1,
                "exactly one {n}-iteration QPP walk traverses the whole chain"
            );
        })
        .expect("spawn the small-stack deep-walk thread");
    handle.join().expect(
        "the deep walk must complete without overflowing the stack (would abort on reverted code)",
    );
}

/// Positive control for the *combinatorial* fix: a dense graph small enough to fit the (default) budget
/// must still complete and enumerate every trail path — the budget bounds memory, it must never
/// silently truncate results. Cross-checks that the `+` QPP and the equivalent `*1..` variable-length
/// expand enumerate the **same** number of endpoint rows (both are relationship-unique trail walks), so
/// the iterative rewrite and the budget did not alter *which* paths are returned.
#[test]
fn dense_graph_completes_and_enumeration_is_unchanged() {
    let _lock = CAP_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    // Small complete digraph K_4 (12 edges): the full trail enumeration is non-trivial yet comfortably
    // within the 256 MiB default, so it must complete rather than reject.
    let m = 4usize;
    let mut g = MemGraph::new();
    let nodes: Vec<NodeId> = (0..m)
        .map(|k| g.add_node(["T"], [("id", i(k as i64))]))
        .collect();
    for a in 0..m {
        for b in 0..m {
            if a != b {
                g.add_rel("E", nodes[a], nodes[b], [("w", i(0))]);
            }
        }
    }

    let qpp = run_outcome(
        "MATCH (a {id:0})((x)-[:E]->(y))+(b) RETURN count(*) AS c",
        &mut g,
    )
    .expect("a K_4 `+` QPP fits the default budget and must complete");
    let qpp_count = count_of(&qpp, "c");
    assert!(
        qpp_count > 0,
        "the dense-graph enumeration must be non-empty (not silently truncated), got {qpp_count}"
    );

    let vlen = run_outcome(
        "MATCH (a {id:0})-[:E*1..]->(b) RETURN count(*) AS c",
        &mut g,
    )
    .expect("the equivalent variable-length trail expand must complete");
    assert_eq!(
        count_of(&vlen, "c"),
        qpp_count,
        "the `+` QPP and `*1..` variable-length expand must enumerate the same trail paths"
    );
}
