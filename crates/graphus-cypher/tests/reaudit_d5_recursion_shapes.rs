//! Sprint-42 re-audit (`rmp` task #485), domain **D5 — query-engine hostility**: NEW adversarial
//! recursion / catastrophic-pattern shapes not already covered by `tests/hostile_queries.rs`
//! (arithmetic/boolean/postfix/parens/list/NOT/FOREACH chains, `(a+)+$` ReDoS, giant range) or
//! `tests/security_dos.rs` (nested-LIST value comparison / bind-depth, cartesian / var-length deadline).
//!
//! The inviolable property is the same one #473 established: every adversarial query degrades
//! GRACEFULLY (a bounded, typed error) and NEVER overflows the stack — a Rust stack overflow ABORTS the
//! whole process (the guard-page handler calls `abort()`, uncatchable by `catch_unwind`), which would
//! brick every database the single-threaded engine hosts. Stack overflow cannot be observed in-process
//! (it kills the runner), so the deep-nesting probes run the victim pipeline in a CHILD PROCESS
//! (a re-exec of this binary, gated on an env var) on a thread sized like the server engine thread, and
//! assert the child exits cleanly rather than dying by signal.
//!
//! NEW shapes proven graceful here:
//!   * deeply nested **map literals** `{a:{a:{…}}}` — the value side re-enters `parse_expr`, so the
//!     shared `MAX_EXPR_DEPTH` recursion guard applies (parser.rs:1595); confirms maps share the guard
//!     proven for nested LISTS.
//!   * deeply nested **CASE** `CASE WHEN true THEN (CASE …) ELSE … END` — the THEN/ELSE branches
//!     re-enter `parse_expr`, so the same guard applies.
//!   * a deeply nested **map PARAMETER** (the trust boundary) — `bind_parameters` rejects it with the
//!     recoverable `BindError::ValueTooDeep` (binding.rs:352), confirming `value_depth` counts map
//!     nesting (security_dos.rs only exercises nested LISTS).
//!   * a NEW **catastrophic regex** shape `(a*)*$` — confirms the linear-time (RE2-style) `regex` engine
//!     does not backtrack-explode on a different pattern than hostile_queries' `(a+)+$`.

use std::process::Command;
use std::time::Duration;

use graphus_core::Value;
use graphus_cypher::binding::{BindError, Parameters, bind_parameters};
use graphus_cypher::catalog::IndexCatalog;
use graphus_cypher::executor::execute;
use graphus_cypher::graph_access::MemGraph;
use graphus_cypher::lexer::tokenize;
use graphus_cypher::lower::lower;
use graphus_cypher::parser::parse_tokens;
use graphus_cypher::physical::plan_physical;
use graphus_cypher::semantics::analyze;
use graphus_cypher::value_depth::MAX_VALUE_DEPTH;

// ----------------------------------------------------------------------------------------------- //
// Query generators (NEW shapes)
// ----------------------------------------------------------------------------------------------- //

/// `RETURN {a:{a:{a: … 1 … }}}` — map literals nested `n` deep. Each map *value* re-enters
/// `parse_expr`, so the shared recursion guard should reject deep nesting as a clean parse error.
fn nested_map(n: usize) -> String {
    let mut s = String::with_capacity(8 + 3 * n + 1 + n);
    s.push_str("RETURN ");
    for _ in 0..n {
        s.push_str("{a:");
    }
    s.push('1');
    for _ in 0..n {
        s.push('}');
    }
    s
}

/// `RETURN CASE WHEN true THEN CASE WHEN true THEN … 1 … ELSE 0 END ELSE 0 END` — CASE expressions
/// nested `n` deep through the THEN branch (each branch re-enters `parse_expr`).
fn nested_case(n: usize) -> String {
    let mut s = String::with_capacity(8 + 20 * n + 1 + 11 * n);
    s.push_str("RETURN ");
    for _ in 0..n {
        s.push_str("CASE WHEN true THEN ");
    }
    s.push('1');
    for _ in 0..n {
        s.push_str(" ELSE 0 END");
    }
    s
}

/// Drives the FULL compile→execute pipeline for `src` over an empty graph, returning a short outcome
/// category. Never `unwrap`/`expect`s on the query result (each fallible stage is matched), so a
/// *graceful* outcome is one of these strings; a stack overflow instead aborts the process before any
/// string is returned.
fn run_pipeline(src: &str) -> &'static str {
    let Ok(toks) = tokenize(src) else {
        return "lex_err";
    };
    let Ok(ast) = parse_tokens(&toks, src) else {
        return "parse_err";
    };
    let Ok(validated) = analyze(&ast) else {
        return "semantic_err";
    };
    let plan = plan_physical(&lower(&validated), &IndexCatalog::empty());
    let Ok(bound) = bind_parameters(&plan, &Parameters::new()) else {
        return "bind_err";
    };
    let mut graph = MemGraph::new();
    let mut cursor = match execute(&plan, &bound, &mut graph) {
        Ok(c) => c,
        Err(_) => return "exec_err",
    };
    match cursor.collect_all() {
        Ok(_) => "ok",
        Err(_) => "row_err",
    }
}

// ----------------------------------------------------------------------------------------------- //
// Subprocess victim + driver harness (mirrors tests/hostile_queries.rs; distinct env var so the two
// binaries' re-exec children never collide).
// ----------------------------------------------------------------------------------------------- //

const VICTIM_ENV: &str = "GRAPHUS_REAUDIT_D5_VICTIM";

/// The server engine thread's stack size (`graphus_server::engine::QUERY_ENGINE_STACK_SIZE`, #473).
const ENGINE_STACK: usize = 64 * 1024 * 1024;

/// CHILD-process entry point. When re-exec'd with `GRAPHUS_REAUDIT_D5_VICTIM` set, runs the requested
/// deep query on an engine-sized thread, prints a single `OUTCOME=<category>` line, and exits 0. A
/// stack overflow kills the process by signal *before* it prints — which is exactly what the driver
/// detects.
#[test]
fn recursion_victim() {
    let Ok(_) = std::env::var(VICTIM_ENV) else {
        return; // a normal (non-re-exec) test run: nothing to do.
    };
    let kind = std::env::var("D5_KIND").expect("D5_KIND");
    let n: usize = std::env::var("D5_N")
        .expect("D5_N")
        .parse()
        .expect("D5_N usize");
    let src = match kind.as_str() {
        "map" => nested_map(n),
        "case" => nested_case(n),
        other => panic!("unknown D5_KIND {other}"),
    };
    let handle = std::thread::Builder::new()
        .stack_size(ENGINE_STACK)
        .spawn(move || run_pipeline(&src))
        .expect("spawn victim worker");
    let outcome = handle.join().unwrap_or("panic");
    println!("OUTCOME={outcome}");
    std::process::exit(0);
}

#[derive(Debug, PartialEq, Eq)]
enum Probe {
    Clean(String),
    Signal(i32),
    NonZero(i32),
}

/// Re-execs this test binary as a child running `recursion_victim` with the given parameters and
/// classifies how it terminated.
fn probe(kind: &str, n: usize) -> Probe {
    let exe = std::env::current_exe().expect("current_exe");
    let output = Command::new(exe)
        .args(["recursion_victim", "--exact", "--nocapture"])
        .env(VICTIM_ENV, "1")
        .env("D5_KIND", kind)
        .env("D5_N", n.to_string())
        .output()
        .expect("spawn child probe");

    if let Some(code) = output.status.code() {
        if code == 0 {
            let stdout = String::from_utf8_lossy(&output.stdout);
            let cat = stdout
                .lines()
                .find_map(|l| l.strip_prefix("OUTCOME="))
                .unwrap_or("<none>")
                .to_owned();
            Probe::Clean(cat)
        } else {
            Probe::NonZero(code)
        }
    } else {
        #[cfg(unix)]
        {
            use std::os::unix::process::ExitStatusExt;
            Probe::Signal(output.status.signal().unwrap_or(-1))
        }
        #[cfg(not(unix))]
        {
            Probe::NonZero(-1)
        }
    }
}

/// Asserts a probe terminated CLEANLY (a typed error or a result) — never by signal (a stack overflow
/// aborts via SIGSEGV/SIGABRT, which would mean the adversarial query crashed the engine process).
fn assert_graceful(kind: &str, n: usize) -> String {
    match probe(kind, n) {
        Probe::Clean(cat) => cat,
        other => panic!("hostile recursion kind={kind} n={n} crashed the engine: {other:?}"),
    }
}

// ----------------------------------------------------------------------------------------------- //
// Deep-nesting parse vectors (subprocess, engine stack): must reject as a clean parse error.
// ----------------------------------------------------------------------------------------------- //

#[test]
fn deeply_nested_map_literal_is_graceful_on_engine_stack() {
    // 100k-deep nested map: the shared MAX_EXPR_DEPTH guard (1000) must reject it as a clean parse
    // error long before the parser — or the recursive semantic/lower/eval passes over the AST — can
    // overflow even the 64 MiB engine stack. NEVER a signal.
    assert_eq!(
        assert_graceful("map", 100_000),
        "parse_err",
        "a deeply nested map literal must be a clean compile error, not a crash"
    );
}

#[test]
fn deeply_nested_case_is_graceful_on_engine_stack() {
    assert_eq!(
        assert_graceful("case", 100_000),
        "parse_err",
        "a deeply nested CASE must be a clean compile error, not a crash"
    );
}

#[test]
fn moderately_nested_map_still_evaluates() {
    // A legal, shallow nested map (well under MAX_EXPR_DEPTH) must still compile & run — the guard must
    // not reject honest queries.
    assert_eq!(
        assert_graceful("map", 100),
        "ok",
        "a moderately nested map literal must evaluate to a result"
    );
}

// ----------------------------------------------------------------------------------------------- //
// Deep-nesting VALUE (parameter) vector — the trust boundary. In-process: bind's depth check is an
// iterative walk (value_depth), so it cannot itself overflow; it must reject with a recoverable error.
// ----------------------------------------------------------------------------------------------- //

/// A `Value::Map` nested `depth` levels deep — the canonical over-deep MAP parameter an attacker sends
/// (bound verbatim). `security_dos.rs` only exercises nested LISTS; this confirms maps are guarded too.
fn nested_map_value(depth: usize) -> Value {
    let mut v = Value::Integer(0);
    for _ in 0..depth {
        v = Value::Map(vec![("a".to_owned(), v)]);
    }
    v
}

#[test]
fn deeply_nested_map_parameter_is_rejected_at_bind() {
    let src = "RETURN $a = $a AS eq";
    let toks = tokenize(src).expect("lex");
    let ast = parse_tokens(&toks, src).expect("parse");
    let validated = analyze(&ast).expect("analyze");
    let plan = plan_physical(&lower(&validated), &IndexCatalog::empty());

    // One level past the cap is rejected at the trust boundary with a recoverable, typed error — never
    // reaching (and overflowing) the engine's recursive comparison.
    let deep = nested_map_value(MAX_VALUE_DEPTH + 1);
    let err = bind_parameters(&plan, &Parameters::new().with("a", deep))
        .expect_err("an over-deep MAP parameter must be rejected at bind");
    assert!(
        matches!(err, BindError::ValueTooDeep { .. }),
        "expected a recoverable ValueTooDeep bind error for a nested map, got {err:?}"
    );

    // A map at exactly the cap still binds (the limit is inclusive and far above any real query).
    let ok = nested_map_value(MAX_VALUE_DEPTH);
    assert!(
        bind_parameters(&plan, &Parameters::new().with("a", ok)).is_ok(),
        "a nested map at exactly MAX_VALUE_DEPTH must still bind"
    );
}

// ----------------------------------------------------------------------------------------------- //
// NEW catastrophic regex: confirm the linear-time (RE2-style) engine does not backtrack-explode.
// ----------------------------------------------------------------------------------------------- //

/// Runs `f` on a worker thread, returning its result or `None` if it did not finish within `timeout`
/// (a hang). Turns "did not terminate" into a test failure rather than a frozen run.
fn with_watchdog<T: Send + 'static>(
    timeout: Duration,
    f: impl FnOnce() -> T + Send + 'static,
) -> Option<T> {
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(f());
    });
    rx.recv_timeout(timeout).ok()
}

#[test]
fn new_catastrophic_regex_pattern_is_linear_time_not_a_hang() {
    // `(a*)*$` against a long all-`a` string with a trailing mismatch is a DIFFERENT classic ReDoS shape
    // than hostile_queries' `(a+)+$`: nested unbounded quantifiers over the same character. A
    // backtracking engine explores exponentially many partitions; the linear-time `regex` engine the
    // Cypher `=~` uses returns at once with a clean boolean result.
    let subject = format!("{}b", "a".repeat(60));
    let src = format!("RETURN '{subject}' =~ '(a*)*$'");
    let outcome = with_watchdog(Duration::from_secs(20), move || run_pipeline(&src))
        .expect("regex `=~` must terminate quickly (linear-time engine), not hang");
    // A clean, terminating outcome — the match simply fails. (Any clean category is acceptable; a hang
    // is the only failure.)
    assert!(
        matches!(outcome, "ok" | "row_err" | "exec_err"),
        "a catastrophic regex must terminate with a clean outcome, got {outcome}"
    );
}
