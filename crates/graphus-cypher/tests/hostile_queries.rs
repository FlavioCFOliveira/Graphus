//! Adversarial / hostile-query probes for the Cypher engine (`rmp` task #473).
//!
//! The engine runs ONE `!Send` thread per database; a single query that panics, stack-overflows, or
//! hangs would take down that engine thread for ALL of its connections — and a Rust stack overflow
//! ABORTS THE WHOLE PROCESS (the runtime's guard-page handler calls `abort()`, which `catch_unwind`
//! cannot intercept), bricking every database the server hosts. The inviolable property exercised
//! here is therefore: every adversarial query degrades GRACEFULLY (bounded, returns an error) and
//! NEVER overflows the stack / aborts.
//!
//! Stack overflow cannot be observed in-process (it kills the test runner), so the deep-recursion
//! probes run the victim pipeline in a CHILD PROCESS (a re-exec of this very test binary, gated on an
//! env var) on a thread whose stack size mirrors the server's engine thread, and assert the child
//! exits cleanly (a typed error) rather than dying by signal (SIGSEGV/SIGABRT = a stack overflow).

use std::process::Command;

use graphus_cypher::binding::{Parameters, bind_parameters};
use graphus_cypher::catalog::IndexCatalog;
use graphus_cypher::executor::execute;
use graphus_cypher::graph_access::MemGraph;
use graphus_cypher::lexer::tokenize;
use graphus_cypher::lower::lower;
use graphus_cypher::parser::parse_tokens;
use graphus_cypher::physical::plan_physical;
use graphus_cypher::semantics::analyze;

// ----------------------------------------------------------------------------------------------- //
// Query generators
// ----------------------------------------------------------------------------------------------- //

/// `RETURN 1+1+...+1` with `n` ones (a left-associative operator chain). The parser folds these in a
/// LOOP (left-deep tree), so the recursion-counter depth guard never fires — yet the resulting AST is
/// `n` deep, so every recursive AST pass (semantics, lowering, evaluation) recurses `n` frames.
fn chain(n: usize) -> String {
    let mut s = String::with_capacity(7 + 2 * n);
    s.push_str("RETURN ");
    for i in 0..n {
        if i > 0 {
            s.push('+');
        }
        s.push('1');
    }
    s
}

/// `RETURN ((((...1...))))` nested `n` deep (a directly-recursive parse). Guarded by the parser's
/// `MAX_EXPR_DEPTH` recursion counter.
fn parens(n: usize) -> String {
    let mut s = String::with_capacity(7 + 2 * n + 1);
    s.push_str("RETURN ");
    for _ in 0..n {
        s.push('(');
    }
    s.push('1');
    for _ in 0..n {
        s.push(')');
    }
    s
}

/// `RETURN [[[...1...]]]` — nested list literals `n` deep. List elements re-enter `parse_expr`, so the
/// parser guard should apply; the AST is `n` deep for the post-parse passes.
fn lists(n: usize) -> String {
    let mut s = String::with_capacity(7 + 2 * n + 1);
    s.push_str("RETURN ");
    for _ in 0..n {
        s.push('[');
    }
    s.push('1');
    for _ in 0..n {
        s.push(']');
    }
    s
}

/// `RETURN NOT NOT ... NOT true` — stacked unary `NOT` (`parse_not` recurses directly).
fn nots(n: usize) -> String {
    let mut s = String::with_capacity(7 + 4 * n + 4);
    s.push_str("RETURN ");
    for _ in 0..n {
        s.push_str("NOT ");
    }
    s.push_str("true");
    s
}

/// `RETURN true AND true AND ... AND true` — boolean left-fold loop (escapes the recursion guard).
fn ands(n: usize) -> String {
    let mut s = String::with_capacity(7 + 9 * n);
    s.push_str("RETURN true");
    for _ in 0..n {
        s.push_str(" AND true");
    }
    s
}

/// `RETURN $p.a.a.a...a` — postfix property left-fold loop (`parse_postfix_expr`, escapes the guard;
/// also the shape SET/REMOVE targets take).
fn postfix(n: usize) -> String {
    let mut s = String::with_capacity(9 + 2 * n);
    s.push_str("RETURN $p");
    for _ in 0..n {
        s.push_str(".a");
    }
    s
}

/// `FOREACH (x IN [1] | FOREACH (x IN [1] | ... CREATE (n) ...))` — nested FOREACH clauses. The
/// `parse_foreach` recursion has NO depth guard (clause-level, not expression-level).
fn foreach(n: usize) -> String {
    let mut s = String::with_capacity(20 * n + 16);
    for _ in 0..n {
        s.push_str("FOREACH (x IN [1] | ");
    }
    s.push_str("CREATE (n)");
    for _ in 0..n {
        s.push(')');
    }
    s
}

/// Drives the FULL production compile→execute pipeline for `src` over an empty graph, returning a
/// short outcome category. Never `unwrap`/`expect`s on the query result (each fallible stage is
/// matched), so a *graceful* outcome is one of these strings; a stack overflow instead aborts the
/// process before any string is returned.
fn run_pipeline(src: &str) -> &'static str {
    let toks = match tokenize(src) {
        Ok(t) => t,
        Err(_) => return "lex_err",
    };
    let ast = match parse_tokens(&toks, src) {
        Ok(a) => a,
        Err(_) => return "parse_err",
    };
    let validated = match analyze(&ast) {
        Ok(v) => v,
        Err(_) => return "semantic_err",
    };
    let plan = plan_physical(&lower(&validated), &IndexCatalog::empty());
    let bound = match bind_parameters(&plan, &Parameters::new()) {
        Ok(b) => b,
        Err(_) => return "bind_err",
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
// Subprocess victim + driver harness
// ----------------------------------------------------------------------------------------------- //

const VICTIM_ENV: &str = "GRAPHUS_HOSTILE_VICTIM";

/// The CHILD-process entry point. When this test binary is re-exec'd with `GRAPHUS_HOSTILE_VICTIM`
/// set, this runs the requested deep query on a thread sized like the server engine thread, prints a
/// single `OUTCOME=<category>` line, and exits 0. If the pipeline overflows the stack, the process is
/// killed by a signal *before* it can print/exit — which is exactly what the driver detects.
#[test]
fn hostile_victim() {
    let Ok(_) = std::env::var(VICTIM_ENV) else {
        // Not the re-exec'd child: this is a normal test run, nothing to do.
        return;
    };
    let kind = std::env::var("HOSTILE_KIND").expect("HOSTILE_KIND");
    let n: usize = std::env::var("HOSTILE_N")
        .expect("HOSTILE_N")
        .parse()
        .expect("HOSTILE_N usize");
    let stack: usize = std::env::var("HOSTILE_STACK")
        .expect("HOSTILE_STACK")
        .parse()
        .expect("HOSTILE_STACK usize");
    let src = match kind.as_str() {
        "chain" => chain(n),
        "parens" => parens(n),
        "lists" => lists(n),
        "nots" => nots(n),
        "ands" => ands(n),
        "postfix" => postfix(n),
        "foreach" => foreach(n),
        other => panic!("unknown HOSTILE_KIND {other}"),
    };
    // `HOSTILE_STACK=0` ⇒ inherit the platform default thread stack (what the server engine thread
    // actually gets today: it is spawned via `thread::Builder::new()` with NO `.stack_size()`).
    let mut builder = std::thread::Builder::new();
    if stack != 0 {
        builder = builder.stack_size(stack);
    }
    let handle = builder
        .spawn(move || run_pipeline(&src))
        .expect("spawn victim worker");
    // A panic (unwind) in the worker is recoverable: join returns Err and we still exit 0 with a
    // marker. A stack overflow is NOT — it aborts the whole process here.
    let outcome = handle.join().unwrap_or("panic");
    println!("OUTCOME={outcome}");
    std::process::exit(0);
}

/// Outcome of one child probe run.
#[derive(Debug, PartialEq, Eq)]
enum Probe {
    /// Child exited cleanly; carries the `OUTCOME=` category it reported.
    Clean(String),
    /// Child died by signal `n` (a stack overflow aborts via SIGABRT=6 / SIGSEGV=11) — a CRITICAL
    /// finding: an adversarial query crashed the process.
    Signal(i32),
    /// Child exited non-zero without a signal (unexpected).
    NonZero(i32),
}

/// Re-execs this test binary as a child running `hostile_victim` with the given parameters, and
/// classifies how it terminated.
fn probe(kind: &str, n: usize, stack: usize) -> Probe {
    let exe = std::env::current_exe().expect("current_exe");
    let output = Command::new(exe)
        .args(["hostile_victim", "--exact", "--nocapture"])
        .env(VICTIM_ENV, "1")
        .env("HOSTILE_KIND", kind)
        .env("HOSTILE_N", n.to_string())
        .env("HOSTILE_STACK", stack.to_string())
        // Keep the child quiet on its own re-exec recursion guard.
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

/// The server engine thread's stack size (`graphus_server::engine::QUERY_ENGINE_STACK_SIZE`,
/// `rmp` task #473). The recursion-vector probes mirror it so the test reflects the real production
/// stack the query runs on.
const ENGINE_STACK: usize = 64 * 1024 * 1024;

/// A deliberately SMALL stack (256 KiB). The fold-loop vectors (operator/postfix chains) are rejected
/// at *compile time* by the semantic depth guard — an iterative check that never recurses — so they
/// degrade gracefully **regardless of stack size**; running them on a tiny stack proves the guard,
/// not the stack, is what saves us.
const TINY_STACK: usize = 256 * 1024;

/// Measurement-only (run with `--ignored --nocapture`): prints how each adversarial query class
/// terminates across a ladder of depths and stack sizes, so thresholds are MEASURED, not guessed.
#[test]
#[ignore = "measurement harness; run explicitly with --ignored --nocapture"]
fn measure_overflow_thresholds() {
    let stacks = [
        (0usize, "default"),
        (2 * 1024 * 1024, "2MiB"),
        (8 * 1024 * 1024, "8MiB"),
        (64 * 1024 * 1024, "64MiB"),
    ];
    let depths = [500usize, 1_000, 2_000, 5_000, 20_000, 100_000, 1_000_000];
    for kind in [
        "chain", "parens", "lists", "nots", "ands", "postfix", "foreach",
    ] {
        for (stack, sname) in stacks {
            for &n in &depths {
                let r = probe(kind, n, stack);
                println!("MEASURE kind={kind:<7} stack={sname:<7} n={n:<8} -> {r:?}");
            }
        }
    }
}

/// Asserts a probe terminated CLEANLY (a typed error or a result) — never by signal (a stack overflow
/// aborts via SIGSEGV/SIGABRT, which would mean an adversarial query crashed the process).
fn assert_graceful(kind: &str, n: usize, stack: usize) -> String {
    match probe(kind, n, stack) {
        Probe::Clean(cat) => cat,
        other => {
            panic!("hostile query kind={kind} n={n} stack={stack} crashed the engine: {other:?}")
        }
    }
}

// ----------------------------------------------------------------------------------------------- //
// Probe class 1a: fold-loop vectors (operator / postfix chains).
//
// These build LEFT-DEEP ASTs via parser loops, so they slip past the parser's recursion-depth guard.
// The per-expression fold budget (`rmp` #473) rejects them DURING construction — before a deep tree is
// ever built — so they are graceful in time AND memory on ANY stack, even a tiny one. We assert that
// on a 256 KiB stack (far smaller than production) they still degrade to a clean PARSE error.
// ----------------------------------------------------------------------------------------------- //

#[test]
fn arithmetic_chain_is_rejected_not_crashed_on_tiny_stack() {
    // `1+1+...+1`. Pre-fix this aborted the process at n=500 on the real engine stack. The parser
    // builds it iteratively and the structural-depth guard rejects it as a clean PARSE error before
    // any deep recursion — so it is graceful even on a tiny stack.
    assert_eq!(
        assert_graceful("chain", 100_000, TINY_STACK),
        "parse_err",
        "a deep operator chain must be a clean compile error"
    );
    // And a much larger one, still on the tiny stack.
    assert_graceful("chain", 1_000_000, TINY_STACK);
}

#[test]
fn boolean_chain_is_rejected_not_crashed_on_tiny_stack() {
    // `true AND true AND ... AND true`.
    assert_eq!(assert_graceful("ands", 200_000, TINY_STACK), "parse_err");
}

#[test]
fn postfix_chain_is_rejected_not_crashed_on_tiny_stack() {
    // `$p.a.a.a...a` — also the shape SET/REMOVE targets take.
    assert_eq!(assert_graceful("postfix", 200_000, TINY_STACK), "parse_err");
}

// ----------------------------------------------------------------------------------------------- //
// Probe class 1b: recursive-parse vectors (parens / lists / NOT).
//
// These ARE counted by the parser's recursion-depth guard, but the guard only saves us if the parser
// reaches it before overflowing — which requires the large engine stack (`rmp` #473). On the real
// engine stack they degrade to a clean parse error.
// ----------------------------------------------------------------------------------------------- //

#[test]
fn deep_parens_is_graceful_on_engine_stack() {
    assert_eq!(
        assert_graceful("parens", 100_000, ENGINE_STACK),
        "parse_err"
    );
}

#[test]
fn deep_nested_lists_is_graceful_on_engine_stack() {
    assert_eq!(assert_graceful("lists", 100_000, ENGINE_STACK), "parse_err");
}

#[test]
fn deep_stacked_not_is_graceful_on_engine_stack() {
    assert_eq!(assert_graceful("nots", 100_000, ENGINE_STACK), "parse_err");
}

// ----------------------------------------------------------------------------------------------- //
// Probe class 1c: clause recursion (nested FOREACH).
//
// `parse_foreach` recurses with no depth guard pre-fix — an unbounded clause-level vector. The added
// `enter_recursion` guard (`rmp` #473) makes it a clean parse error; the large engine stack lets the
// parser reach the guard.
// ----------------------------------------------------------------------------------------------- //

#[test]
fn deep_nested_foreach_is_graceful_on_engine_stack() {
    assert_eq!(
        assert_graceful("foreach", 50_000, ENGINE_STACK),
        "parse_err"
    );
}

// A legal, moderately deep expression (well under the limit) must still compile & run — the guard
// must not reject normal queries.
#[test]
fn moderately_deep_legal_chain_still_runs() {
    // 800-term chain: under MAX_EXPR_DEPTH (1000), so it must evaluate to a result, not be rejected.
    assert_eq!(assert_graceful("chain", 800, ENGINE_STACK), "ok");
}

// ----------------------------------------------------------------------------------------------- //
// Probe class 2: regex DoS (`=~`). The engine uses the `regex` crate (RE2-style finite automaton) with
// its linear-time matching guarantee, so a classic catastrophic-backtracking pattern cannot blow up.
// We run a pattern/input pair that would hang a backtracking engine for ages and assert it completes
// well within a watchdog window (it returns in milliseconds).
// ----------------------------------------------------------------------------------------------- //

/// Runs `f` on a worker thread and returns its result, or `None` if it did not finish within
/// `timeout` (a hang). Used to turn "did not terminate" into a test failure instead of a frozen run.
fn with_watchdog<T: Send + 'static>(
    timeout: std::time::Duration,
    f: impl FnOnce() -> T + Send + 'static,
) -> Option<T> {
    let (tx, rx) = std::sync::mpsc::channel();
    // The worker is detached; if it hangs it leaks (the test process exits anyway), but it can never
    // make the test pass spuriously.
    std::thread::spawn(move || {
        let _ = tx.send(f());
    });
    rx.recv_timeout(timeout).ok()
}

#[test]
fn regex_catastrophic_pattern_is_linear_time_not_a_hang() {
    // `(a+)+$` against a long all-`a` string with a trailing mismatch is the textbook ReDoS input: a
    // backtracking engine explores exponentially many splits. The linear-time engine returns at once.
    let subject = "a".repeat(50);
    let src = format!("RETURN '{subject}b' =~ '(a+)+$'");
    let outcome = with_watchdog(std::time::Duration::from_secs(20), move || {
        run_pipeline(&src)
    })
    .expect("regex `=~` must terminate quickly (linear-time engine), not hang");
    // A clean boolean result ("ok") — the match simply fails — never a hang.
    assert_eq!(outcome, "ok");
}

// ----------------------------------------------------------------------------------------------- //
// Probe class 3/4: cardinality / expansion / materialisation bombs. `range(...)` that would
// materialise a huge list is capped at a fixed memory budget (`MAX_RANGE_BYTES`, 256 MiB) and rejected
// as a typed runtime error rather than allocated — so a giant `range`/`UNWIND range` is bounded, not an
// OOM. (Streaming operators additionally poll a `CancellationToken` between rows, so an unbounded
// expansion is time-bounded by the caller's cancel/timeout — exercised by the executor suite.)
// ----------------------------------------------------------------------------------------------- //

#[test]
fn giant_range_is_rejected_not_oom() {
    // ~10^12 integers would be terabytes; the memory cap rejects it as a clean error, fast.
    let outcome = with_watchdog(std::time::Duration::from_secs(20), || {
        run_pipeline("RETURN range(0, 1000000000000)")
    })
    .expect("a giant range() must be rejected promptly, not hang or OOM");
    assert!(
        matches!(outcome, "row_err" | "exec_err"),
        "giant range() must be a clean runtime error, got {outcome}"
    );
}

#[test]
fn giant_unwind_range_is_rejected_not_oom() {
    // `UNWIND range(0, huge)` materialises the range first, so it hits the same memory cap.
    let outcome = with_watchdog(std::time::Duration::from_secs(20), || {
        run_pipeline("UNWIND range(0, 1000000000000) AS x RETURN x")
    })
    .expect("a giant UNWIND range() must be rejected promptly, not hang or OOM");
    assert!(
        matches!(outcome, "row_err" | "exec_err"),
        "giant UNWIND range() must be a clean runtime error, got {outcome}"
    );
}
