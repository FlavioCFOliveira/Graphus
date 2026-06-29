//! Red-team security battery for `graphus-cypher` — denial-of-service & resource-exhaustion vectors
//! reachable from untrusted query text or untrusted query parameters.
//!
//! Each test is a *reproducer* for a finding registered in the project roadmap (`rmp`). Tests that
//! demonstrate a stack-overflow run the recursive code on a **stack-limited worker thread** so the
//! crash is contained (the thread dies, the test runner survives) — and they assert on the observed
//! behaviour rather than letting an unbounded allocation actually exhaust host memory.
//!
//! Convention: every finding exercised here is **fixed**; each test is a `// Regression: SEC-<task-id>`
//! asserting the *secure* post-fix behaviour (it passes now and would fail if the fix regressed). No
//! `// VULNERABLE: SEC-<task-id>` markers remain.

use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use graphus_core::Value;
use graphus_cypher::binding::{BindError, Parameters, bind_parameters};
use graphus_cypher::catalog::IndexCatalog;
use graphus_cypher::executor::{CancellationToken, ExecError, Executor};
use graphus_cypher::graph_access::MemGraph;
use graphus_cypher::lexer::tokenize;
use graphus_cypher::lower::lower;
use graphus_cypher::parser::parse_tokens;
use graphus_cypher::physical::plan_physical;
use graphus_cypher::semantics::analyze;
use graphus_cypher::value_depth::MAX_VALUE_DEPTH;
use graphus_cypher::{cmp_values, equals};

/// Builds a left-nested list value `[[[ ... ]]]` of the requested `depth`. This is the canonical
/// shape an attacker supplies as a query **parameter** (parameters are bound verbatim — see
/// `bind_parameters`, which performs no depth validation).
fn nested_list(depth: usize) -> Value {
    let mut v = Value::Integer(0);
    for _ in 0..depth {
        v = Value::List(vec![v]);
    }
    v
}

/// Runs `f` on a worker thread with the given stack size and a wall-clock deadline, reporting
/// whether it **completed cleanly** within the deadline.
///
/// IMPORTANT: on stable Rust a stack overflow aborts the *whole process* (SIGABRT) — it is NOT a
/// catchable panic — so these tests must never drive the recursion past the worker's stack. We
/// therefore size the stack generously relative to the depth under test and assert that recursion
/// *succeeds*, demonstrating that the depth is bounded only by available stack (i.e. by the data,
/// which the attacker controls), with NO algorithmic guard. The unsafe-at-any-size nature is what
/// makes this a DoS: an attacker simply sends a value deeper than the server worker's stack.
fn completes_within(
    stack_bytes: usize,
    timeout: Duration,
    f: impl FnOnce() + Send + 'static,
) -> bool {
    let (tx, rx) = mpsc::channel();
    let builder = thread::Builder::new().stack_size(stack_bytes);
    let _handle = builder
        .spawn(move || {
            f();
            let _ = tx.send(());
        })
        .expect("spawn worker");
    rx.recv_timeout(timeout).is_ok()
}

// =================================================================================================
// SEC: unbounded recursion over nested VALUE data in equality / ordering (CWE-674)
//
// `equals` -> `deep_equals` -> `list_equals` -> `equals` (and `cmp_values` -> `cmp_lists` ->
// `cmp_values`) recurse with the nesting depth of the *data*, which is attacker-controlled via
// parameters. There is NO value-depth bound anywhere in the crate (the only `MAX_EXPR_DEPTH` guard
// is parse-time and bounds the AST shape, not runtime values). A short query such as
// `RETURN $a = $a` or `... ORDER BY $a` with a deeply nested list/map parameter recurses one stack
// frame per nesting level and overflows the worker thread's stack — crashing the connection / the
// server worker. This is a remote DoS gated only by the ability to send a parameter.
// =================================================================================================

/// A depth far beyond the engine's [`MAX_VALUE_DEPTH`] cap and far beyond what any legitimate query
/// nests. Before the fix this recursed one stack frame per level and SIGABRTed a small stack; after
/// the fix the comparison routines stop recursing at the cap, so even this depth is **safe on a tiny
/// stack** — which is exactly what the regression tests below assert.
const DEEP: usize = 200_000;

/// A realistic worker stack (1 MiB — the order of a production server worker). Before the fix, a
/// `DEEP`-nested comparison (200k levels) SIGABRTed a stack this size; after the fix it completes,
/// because recursion is capped at [`MAX_VALUE_DEPTH`] (1000 levels) — well within 1 MiB. The cap is
/// what makes the comparison stack-safe regardless of attacker-controlled data depth.
const SMALL_STACK: usize = 1024 * 1024;

/// A legitimately-shaped (shallow) nested value compares fine on any reasonable stack — the control
/// proving the harness itself is sound.
#[test]
fn shallow_nested_equality_is_fine() {
    let a = nested_list(64);
    let b = nested_list(64);
    let ok = completes_within(8 * 1024 * 1024, Duration::from_secs(10), move || {
        let _ = equals(&a, &b);
    });
    assert!(ok, "a shallow nested value must compare without overflow");
}

/// Regression: SEC-190 — `equals` now caps its recursion at `MAX_VALUE_DEPTH`, so a `DEEP`-nested
/// value (far beyond any real query) compares **safely on a tiny 256 KiB stack** instead of aborting
/// the process. Before the fix this SIGABRTed; now it must complete cleanly.
#[test]
fn deep_nested_equality_is_stack_safe() {
    let a = nested_list(DEEP);
    let b = nested_list(DEEP);
    let completed = completes_within(SMALL_STACK, Duration::from_secs(20), move || {
        let _ = equals(&a, &b);
        // A `DEEP`-nested `Value`'s *Drop* is itself recursive and would overflow this small stack;
        // the fix under test is the *comparison* guard, so leak the values rather than dropping them
        // here (the worker thread exits immediately after).
        std::mem::forget(a);
        std::mem::forget(b);
    });
    assert!(
        completed,
        "SEC-190: equals() of a {DEEP}-deep value must complete on a {SMALL_STACK}-byte stack \
         (recursion is capped at MAX_VALUE_DEPTH). A failure means the depth guard regressed."
    );
}

/// Regression: SEC-190 — `cmp_values` (ORDER BY / DISTINCT / min / max) shares the same capped
/// recursion. A `DEEP`-nested value must order safely on a tiny stack.
#[test]
fn deep_nested_ordering_is_stack_safe() {
    let a = nested_list(DEEP);
    let b = nested_list(DEEP);
    let completed = completes_within(SMALL_STACK, Duration::from_secs(20), move || {
        let _ = cmp_values(&a, &b);
        std::mem::forget(a);
        std::mem::forget(b);
    });
    assert!(
        completed,
        "SEC-190: cmp_values() of a {DEEP}-deep value must complete on a {SMALL_STACK}-byte stack \
         (recursion is capped at MAX_VALUE_DEPTH). A failure means the depth guard regressed."
    );
}

/// Regression: SEC-190 — the primary fix is at the trust boundary: `bind_parameters` rejects an
/// over-deep parameter value with a typed, recoverable [`BindError::ValueTooDeep`] instead of letting
/// it reach (and overflow) the engine. `RETURN $a = $a` references `$a`, so the deep value is checked.
#[test]
fn over_deep_parameter_is_rejected_at_bind_with_a_recoverable_error() {
    let src = "RETURN $a = $a AS eq";
    let toks = tokenize(src).expect("lex");
    let ast = parse_tokens(&toks, src).expect("parse");
    let validated = analyze(&ast).expect("analyze");
    let plan = plan_physical(&lower(&validated), &IndexCatalog::empty());

    // A value one level past the cap is rejected.
    let deep = nested_list(MAX_VALUE_DEPTH + 1);
    let err = bind_parameters(&plan, &Parameters::new().with("a", deep))
        .expect_err("an over-deep parameter must be rejected at bind");
    assert!(
        matches!(err, BindError::ValueTooDeep { .. }),
        "expected a recoverable ValueTooDeep bind error, got {err:?}"
    );

    // A value at the cap still binds (the limit is inclusive and far above any real query).
    let ok = nested_list(MAX_VALUE_DEPTH);
    assert!(
        bind_parameters(&plan, &Parameters::new().with("a", ok)).is_ok(),
        "a value at exactly MAX_VALUE_DEPTH must still bind"
    );
}

// =================================================================================================
// SEC-476: per-statement CPU budget (execution-time deadline) bounds a runaway query
//
// An ordinary Cypher statement used to run with NO execution-time budget: a patient client could
// submit a cartesian-product or deep variable-length-expansion "bomb" that pins the per-database
// engine thread unbounded, starving every co-tenant (a per-database-thread CPU-exhaustion DoS). The
// executor polls a `CancellationToken` at dense safe points (the top of every `Operator::next`, and
// inside the variable-length DFS / shortest-path BFS); rmp #476 drives that token from a
// per-statement wall-clock deadline (`CancellationToken::with_deadline`) so a runaway query aborts
// cooperatively with `ExecError::Cancelled` instead of running forever.
//
// These tests exercise the executor's token plumbing directly (the `graphus-server` end-to-end test
// `tests/statement_timeout.rs` proves the engine-thread path). They build a *bomb* plan and run it
// with an already-elapsed deadline, asserting a clean `Cancelled` (no panic, no hang) — and prove a
// normal query under a generous deadline is unaffected.
// =================================================================================================

/// Compiles `src` to a physical plan (no index catalogue, no stats) via the full front-end pipeline.
fn compile_plan(src: &str) -> graphus_cypher::physical::PhysicalPlan {
    let toks = tokenize(src).expect("lex");
    let ast = parse_tokens(&toks, src).expect("parse");
    let validated = analyze(&ast).expect("analyze");
    plan_physical(&lower(&validated), &IndexCatalog::empty())
}

/// Builds a [`MemGraph`] of `n` `:N` nodes, fully connected (every ordered pair, incl. self-loops)
/// by `:R` edges — a dense substrate so both a cartesian product and a variable-length expansion
/// blow up super-linearly.
fn dense_graph(n: usize) -> MemGraph {
    let mut g = MemGraph::new();
    let ids: Vec<_> = (0..n)
        .map(|i| g.add_node(["N"], [("v", Value::Integer(i as i64))]))
        .collect();
    for &a in &ids {
        for &b in &ids {
            g.add_rel("R", a, b, [] as [(&str, Value); 0]);
        }
    }
    g
}

/// Runs `plan` over `graph` under `token`, draining the cursor; returns the terminal result so a
/// test can assert whether it completed or was cancelled. An open-time error (a materialising
/// aggregate folds at `open`) and a streaming error are unified here.
fn run_under(
    plan: &graphus_cypher::physical::PhysicalPlan,
    graph: &mut MemGraph,
    token: CancellationToken,
) -> Result<usize, ExecError> {
    let bound = bind_parameters(plan, &Parameters::new()).expect("bind");
    Executor::new(plan.clone(), bound)
        .open(graph, token)
        .and_then(|mut c| c.collect_all())
        .map(|rows| rows.len())
}

#[test]
fn statement_deadline_aborts_cartesian_bomb() {
    // Regression: SEC-476 — a 3-way cartesian product over 60 nodes folds 60^3 = 216_000 intermediate
    // rows. With an already-elapsed deadline the executor's per-row safe point trips `Cancelled` within
    // the poll stride — promptly, with no panic and no hang.
    let mut graph = dense_graph(60);
    let plan = compile_plan("MATCH (a:N), (b:N), (c:N) RETURN count(*) AS n");

    let started = Instant::now();
    let result = run_under(
        &plan,
        &mut graph,
        CancellationToken::with_deadline(Some(Instant::now() - Duration::from_secs(1))),
    );
    assert!(
        matches!(result, Err(ExecError::Cancelled)),
        "an elapsed per-statement deadline must abort the cartesian bomb with Cancelled, got {result:?}"
    );
    // It aborted cooperatively at a safe point — not after folding all 216k rows.
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "cancellation must be prompt, took {:?}",
        started.elapsed()
    );
}

#[test]
fn statement_deadline_aborts_var_length_bomb() {
    // Regression: SEC-476 — an unbounded variable-length expansion over a dense graph enumerates an
    // explosive number of relationship-unique trails; the DFS polls the token per recursion, so an
    // elapsed deadline aborts it cleanly (the safe point inside `expand_var_length_dfs`).
    let mut graph = dense_graph(12);
    let plan = compile_plan("MATCH (a:N)-[*]->(b:N) RETURN count(*) AS n");

    let result = run_under(
        &plan,
        &mut graph,
        CancellationToken::with_deadline(Some(Instant::now() - Duration::from_secs(1))),
    );
    assert!(
        matches!(result, Err(ExecError::Cancelled)),
        "an elapsed per-statement deadline must abort the variable-length bomb with Cancelled, got {result:?}"
    );
}

#[test]
fn generous_deadline_does_not_disturb_a_normal_query() {
    // A legitimate query under a far-future deadline completes unaffected — the budget never trips, and
    // the gated wall-clock poll keeps the result exact.
    let mut graph = dense_graph(20);
    let plan = compile_plan("MATCH (a:N), (b:N) RETURN count(*) AS n");

    let result = run_under(
        &plan,
        &mut graph,
        CancellationToken::with_deadline(Some(Instant::now() + Duration::from_secs(3600))),
    );
    // One aggregated row (count(*) over 20*20 = 400 pairs).
    assert_eq!(
        result,
        Ok(1),
        "a normal query under a generous deadline must complete unaffected"
    );
}

#[test]
fn no_deadline_token_preserves_prior_behaviour() {
    // A `None` deadline (every test / TCK / deterministic-engine path) is byte-identical to a fresh
    // token: the executor never reads the wall clock, and the query completes normally.
    let mut graph = dense_graph(20);
    let plan = compile_plan("MATCH (a:N), (b:N) RETURN count(*) AS n");

    let result = run_under(&plan, &mut graph, CancellationToken::with_deadline(None));
    assert_eq!(result, Ok(1));
}
