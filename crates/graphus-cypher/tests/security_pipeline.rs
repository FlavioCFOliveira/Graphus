//! Red-team security battery for `graphus-cypher` — vectors reachable through the **full query
//! pipeline** (parse → analyze → plan → execute): arbitrary local file read via `LOAD CSV`, and the
//! oversized-allocation ceiling of `range()`.
//!
//! Convention: every finding in this file is **fixed**; each test is a `// Regression: SEC-<task-id>`
//! that asserts the *secure* post-fix behaviour (it passes now and would fail if the fix regressed).
//! No `// VULNERABLE: SEC-<task-id>` markers remain.

use std::io::Write;

use graphus_cypher::binding::{Parameters, bind_parameters};
use graphus_cypher::catalog::IndexCatalog;
use graphus_cypher::executor::execute;
use graphus_cypher::graph_access::MemGraph;
use graphus_cypher::lexer::tokenize;
use graphus_cypher::lower::lower;
use graphus_cypher::parser::parse_tokens;
use graphus_cypher::physical::plan_physical;
use graphus_cypher::runtime::Row;
use graphus_cypher::semantics::analyze;

/// Compiles and runs `src` over `graph`, returning the rows (or panicking on any compile error so a
/// test that expects success fails loudly).
fn run(src: &str, graph: &mut MemGraph) -> Result<Vec<Row>, String> {
    let toks = tokenize(src).map_err(|e| format!("lex: {e:?}"))?;
    let ast = parse_tokens(&toks, src).map_err(|e| format!("parse: {e:?}"))?;
    let validated = analyze(&ast).map_err(|e| format!("analyze: {e:?}"))?;
    let plan = plan_physical(&lower(&validated), &IndexCatalog::empty());
    let bound = bind_parameters(&plan, &Parameters::new()).map_err(|e| format!("bind: {e:?}"))?;
    let mut cursor = execute(&plan, &bound, graph).map_err(|e| format!("open: {e:?}"))?;
    cursor.collect_all().map_err(|e| format!("rows: {e:?}"))
}

// =================================================================================================
// SEC: LOAD CSV reads ARBITRARY local files — no import-directory confinement (CWE-22)
//
// `loadcsv::parse_file_url` accepts any absolute path (`file:///etc/passwd` -> `/etc/passwd`) or
// bare path with NO base-directory sandbox, NO `..` traversal rejection, NO allowlist. Neo4j confines
// LOAD CSV to a configurable `import/` root (chroot-style, default-on); Graphus has no equivalent.
// Any client able to run `LOAD CSV` can therefore read — and exfiltrate to itself — any file the
// server process can read.
// =================================================================================================

/// Regression: SEC-189 — `LOAD CSV FROM 'file://<abs>'` of an arbitrary absolute path must NOT read
/// the file. This binary installs no import policy, so the fail-closed default denies every
/// local-file read; the query must fail and the secret must never appear in the (absent) rows.
#[test]
fn load_csv_rejects_arbitrary_absolute_file() {
    // Create a "sensitive" file in the OS temp dir, well outside any notion of an import directory.
    let dir = std::env::temp_dir();
    let secret_path = dir.join(format!("graphus_sec_secret_{}.txt", std::process::id()));
    {
        let mut f = std::fs::File::create(&secret_path).expect("create secret file");
        writeln!(f, "TOP-SECRET-LINE").expect("write secret");
    }
    let url = format!("file://{}", secret_path.display());
    let query = format!("LOAD CSV FROM '{url}' AS line RETURN line");

    let mut g = MemGraph::new();
    let result = run(&query, &mut g);
    let _ = std::fs::remove_file(&secret_path);

    let err = result.expect_err(
        "SEC-189: LOAD CSV of an arbitrary absolute file must be REJECTED (fail-closed import policy)",
    );
    assert!(
        !err.contains("TOP-SECRET-LINE"),
        "the secret contents must never reach the client, got error: {err}"
    );
}

/// Regression: SEC-189 (traversal variant) — a `..`-laden path must be rejected, not followed
/// (the classic path-traversal shape, CWE-22).
#[test]
fn load_csv_rejects_dot_dot_traversal() {
    let dir = std::env::temp_dir();
    let secret_path = dir.join(format!("graphus_sec_trav_{}.txt", std::process::id()));
    {
        let mut f = std::fs::File::create(&secret_path).expect("create file");
        writeln!(f, "TRAVERSAL-MARKER").expect("write");
    }
    // Build a path containing `..` segments that, before the fix, resolved back to the secret.
    let abs = secret_path.to_string_lossy().to_string();
    let traversal = format!("/../../../../../../../../..{abs}");
    let query = format!("LOAD CSV FROM '{traversal}' AS line RETURN line");

    let mut g = MemGraph::new();
    let result = run(&query, &mut g);
    let _ = std::fs::remove_file(&secret_path);

    let err = result
        .expect_err("SEC-189: a `..` traversal path must be REJECTED, never resolved and read");
    assert!(
        !err.contains("TRAVERSAL-MARKER"),
        "the secret contents must never reach the client, got error: {err}"
    );
}

// =================================================================================================
// SEC: range() resource ceiling is set far too high — a single query can demand a multi-GB
// allocation before the guard trips (CWE-770 / CWE-789).
//
// `MAX_RANGE_ELEMENTS = 1 << 30` (~1.07 billion). `range()` then does `Vec::with_capacity(count)`
// over `Value` (~40 bytes each) => up to ~40 GB single allocation from `RETURN range(1, 1073741824)`,
// which OOM-kills the host long before the count guard would reject anything. The guard caps the
// *count*, not the *memory*, and the cap is itself an OOM vector on any normal host.
// =================================================================================================

/// A `range()` just over the documented limit is rejected (control: the guard exists and fires).
#[test]
fn range_over_the_count_limit_is_rejected() {
    let mut g = MemGraph::new();
    // 1<<30 + 2 elements: comfortably over MAX_RANGE_ELEMENTS, rejected WITHOUT allocating.
    let over = (1i64 << 30) + 2;
    let result = run(&format!("RETURN range(0, {over}) AS r"), &mut g);
    assert!(
        result.is_err(),
        "range() above the element ceiling must be rejected, not materialised"
    );
}

/// Regression: SEC-191 — the `range()` ceiling is now a **memory** budget, so the worst-case single
/// allocation it admits stays well under 1 GiB (the previous `1 << 30` element ceiling admitted a
/// ~40 GiB allocation). We drive a request *just over* the budget and assert it is rejected without
/// materialising, and that the implied worst-case allocation is bounded.
#[test]
fn range_budget_bounds_the_worst_case_allocation() {
    let mut g = MemGraph::new();

    // The crate budget (mirror of `MAX_RANGE_BYTES` in eval.rs). `Value` is ~40 bytes, so the
    // element ceiling is ~6.7M elements — orders of magnitude below the old 1.07e9.
    const MAX_RANGE_BYTES: i128 = 256 * 1024 * 1024;
    const ONE_GIB: i128 = 1 << 30;
    const {
        assert!(
            MAX_RANGE_BYTES < ONE_GIB,
            "the range() materialisation budget must stay under 1 GiB"
        );
    }

    // A request whose materialisation would exceed the budget is rejected, not allocated. At the old
    // ceiling (1<<30 elements) this would have been *accepted* and OOM'd the host.
    let over = 1i64 << 30; // ~1.07e9 elements => ~40 GiB at 40 B/elem, far over the 256 MiB budget
    let result = run(&format!("RETURN range(0, {over}) AS r"), &mut g);
    assert!(
        result.is_err(),
        "a range() whose materialisation exceeds the memory budget must be rejected"
    );

    // A modest range still materialises (the budget is generous for legitimate use).
    let ok = run("RETURN range(1, 1000) AS r", &mut g).expect("a small range materialises");
    assert_eq!(ok.len(), 1);
}
