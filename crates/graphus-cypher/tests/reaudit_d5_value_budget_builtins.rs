//! Sprint-42 re-audit (`rmp` task #485 / #489), domain **D5 — query-engine hostility**: regression
//! locks for the per-value materialised-size budget (`SEC-191` / `rmp` #481, `crate::value_size`,
//! `MAX_VALUE_BYTES = 256 MiB`) across the **list-/string-producing builtins** that previously bypassed
//! it (CWE-770 / CWE-789, an unbounded single-value memory DoS).
//!
//! The #481 budget is enforced by the *streaming* / *concatenating* value builders — `collect`
//! (executor), list / pattern comprehension ([`eval::accumulate_list_bytes`]), `+` string/list concat,
//! `replace` ([`eval::replace_result_len_bound`]) and `range`. The re-audit found it was **NOT** enforced
//! by several *one-shot `.collect()`* builtins: `split` (empty + dense delimiter), `keys` (of a wide map
//! parameter or a property-heavy entity), the list literal `[ … ]`, and `toUpper`/`toLower` (Unicode case
//! expansion). Each could turn a single bounded input (a 64 MiB Bolt string/map parameter, or a large RUN
//! query text) into a multi-GB materialised value and OOM the whole per-database engine thread (all
//! tenants), which #476's 2-minute wall-clock timeout loses the race to. The fix (commit closing #489)
//! adds the same `replace_fn`-style guard to each builder: an `O(1)` element-count / output-byte bound
//! that rejects with a typed `ResourceLimit` **before** the `.collect()` allocates.
//!
//! These tests **measure the boundary cheaply** with a lowered budget ([`BudgetOverride`]) — kilobytes,
//! not the 256 MiB default — so a handful of elements already exceeds it. The override is process-global,
//! so each test holds [`CAP_LOCK`] for its whole body and the RAII guard restores the default on drop.
//!
//! * **Section 1 — REGRESSION LOCKS**: each asserts the builtin rejects an over-budget result with a
//!   typed `ResourceLimit` (the post-fix behaviour), exactly as `replace` / the comprehensions / `range`
//!   already do. These FAILED on the pre-fix HEAD and lock the fix.
//! * **Section 2 — ASYMMETRY / CONFIRM-CLOSED**: proves the budget mechanism is live at the lowered
//!   ceiling for the builders that already enforced it, so Section 1 was a true per-builtin gap.

use std::sync::Mutex;

use graphus_core::Value;
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
use graphus_cypher::value_size::{BudgetOverride, MAX_VALUE_BYTES, max_value_bytes};

/// Serialises the process-global budget override across this binary's tests (each lowers the cap, so
/// they must not run concurrently and observe each other's override).
static CAP_LOCK: Mutex<()> = Mutex::new(());

/// Drives the full compile → execute → drain pipeline for `src` (with optional parameters) over an
/// empty in-memory graph, returning the produced `Row`s or `Err(message)` for whichever stage failed.
/// Never panics on a query outcome, so a clean rejection surfaces as `Err`, not an abort.
fn run_rows(src: &str, params: &Parameters) -> Result<Vec<Row>, String> {
    let toks = tokenize(src).map_err(|e| format!("lex: {e:?}"))?;
    let ast = parse_tokens(&toks, src).map_err(|e| format!("parse: {e:?}"))?;
    let validated = analyze(&ast).map_err(|e| format!("semantic: {e:?}"))?;
    let plan = plan_physical(&lower(&validated), &IndexCatalog::empty());
    let bound = bind_parameters(&plan, params).map_err(|e| format!("bind: {e:?}"))?;
    let mut graph = MemGraph::new();
    let mut cursor = execute(&plan, &bound, &mut graph).map_err(|e| format!("exec: {e}"))?;
    let rows = cursor.collect_all().map_err(|e| format!("{e}"))?;
    Ok(rows)
}

/// True iff `outcome` is the typed value-budget rejection (a `ResourceLimit`), as opposed to a success
/// or any other error class. Loose on wording (the fix author picks the phrasing) but strict on shape:
/// an error that mentions the budget and is not a cancellation.
fn is_value_budget_rejection(outcome: &Result<Vec<Row>, String>) -> bool {
    match outcome {
        Ok(_) => false,
        Err(msg) => {
            let m = msg.to_lowercase();
            (m.contains("limit") || m.contains("budget") || m.contains("exceed"))
                && !m.contains("cancel")
        }
    }
}

// =================================================================================================== //
// Section 1 — REGRESSION LOCKS (failed on the pre-fix HEAD; pass once each builder bounds its result).
// =================================================================================================== //

#[test]
fn split_empty_delim_rejects_over_budget() {
    let _lock = CAP_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let _b = BudgetOverride::new(4096);
    // A 2000-char string (2000 B, UNDER the 4 KiB budget) split char-wise would build ~2000 `Value`
    // slots (~80 KB) — the budget must reject it before allocating, exactly as the comprehension does.
    let s = "a".repeat(2000);
    let params = Parameters::new().with("s", Value::String(s));
    let outcome = run_rows("RETURN split($s, '') AS parts", &params);
    assert!(
        is_value_budget_rejection(&outcome),
        "an over-budget split('','') must reject with a typed ResourceLimit BEFORE allocating. Got: {outcome:?}"
    );
}

#[test]
fn split_dense_delimiter_rejects_over_budget() {
    let _lock = CAP_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let _b = BudgetOverride::new(4096);
    // The non-empty-delimiter amplifier: split("aaaa…a","a") → ~|s|+1 empty parts, each a full Value slot.
    let s = "a".repeat(2000);
    let params = Parameters::new().with("s", Value::String(s));
    let outcome = run_rows("RETURN split($s, 'a') AS parts", &params);
    assert!(
        is_value_budget_rejection(&outcome),
        "an over-budget split with a dense non-empty delimiter must reject with a typed ResourceLimit. Got: {outcome:?}"
    );
}

#[test]
fn split_sparse_delimiter_still_accepted() {
    // The exact-count guard must NOT false-reject a split whose delimiter is sparse/absent (few parts),
    // even when the input string is large — only the part COUNT is bounded, not the input size.
    let _lock = CAP_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let _b = BudgetOverride::new(4096);
    // A 3000-byte string with NO occurrence of the delimiter → exactly 1 part (well under any budget),
    // even though a loose |s|/|delim| upper bound would have wrongly rejected it.
    let s = "a".repeat(3000);
    let params = Parameters::new().with("s", Value::String(s));
    let outcome = run_rows("RETURN split($s, 'Z') AS parts", &params);
    assert!(
        outcome.is_ok(),
        "split on an absent delimiter yields one part and must NOT be falsely rejected. Got: {outcome:?}"
    );
}

#[test]
fn keys_of_map_parameter_rejects_over_budget() {
    let _lock = CAP_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let _b = BudgetOverride::new(4096);
    // A flat (depth-1, so it binds) map parameter with many entries. keys($m) collects one Value::String
    // per key — bound the key list before collecting.
    let entries: Vec<(String, Value)> = (0..2000)
        .map(|i| (format!("k{i}"), Value::Integer(i)))
        .collect();
    let params = Parameters::new().with("m", Value::Map(entries));
    let outcome = run_rows("RETURN keys($m) AS ks", &params);
    assert!(
        is_value_budget_rejection(&outcome),
        "keys() of a wide map must reject an over-budget key list with a typed ResourceLimit. Got: {outcome:?}"
    );
}

#[test]
fn list_literal_rejects_over_budget() {
    let _lock = CAP_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let _b = BudgetOverride::new(4096);
    let src = format!("RETURN [{}] AS xs", vec!["1"; 2000].join(","));
    let outcome = run_rows(&src, &Parameters::new());
    assert!(
        is_value_budget_rejection(&outcome),
        "a flat list literal over the budget must reject with a typed ResourceLimit. Got: {outcome:?}"
    );
}

#[test]
fn toupper_expansion_rejects_over_budget() {
    let _lock = CAP_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    // U+0390 (2 B) uppercases to three code points (6 B) — a 3× byte expansion (Unicode SpecialCasing).
    let up_bytes = "\u{0390}".to_uppercase().to_string().len();
    let count = 600usize;
    let input_bytes = count * "\u{0390}".len();
    let output_bytes = count * up_bytes;
    let budget = (input_bytes + output_bytes) / 2; // input accepted, output over budget
    let _b = BudgetOverride::new(budget);
    let params = Parameters::new().with("s", Value::String("\u{0390}".repeat(count)));
    let outcome = run_rows("RETURN toUpper($s) AS u", &params);
    assert!(
        is_value_budget_rejection(&outcome),
        "toUpper whose result exceeds the budget must reject with a typed ResourceLimit (the output byte \
         length is bounded before the String is built). Got: {outcome:?}"
    );
}

#[test]
fn tolower_non_expanding_still_accepted() {
    // toLower of an ASCII string does not expand; it must not be falsely rejected at a budget above the
    // (unchanged) output size — the guard bounds the actual output, not a worst-case factor.
    let _lock = CAP_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let _b = BudgetOverride::new(4096);
    let params = Parameters::new().with("s", Value::String("ABC".to_owned()));
    let outcome = run_rows("RETURN toLower($s) AS l", &params);
    assert!(
        outcome.is_ok(),
        "a tiny non-expanding toLower must not be falsely rejected. Got: {outcome:?}"
    );
}

// =================================================================================================== //
// Section 2 — ASYMMETRY / CONFIRM-CLOSED (each passes): the budget mechanism is live at the lowered
// ceiling for every builder that consults it, so Section 1 was a true per-builtin enforcement gap.
// =================================================================================================== //

#[test]
fn comprehension_rejects_a_large_element_count() {
    let _lock = CAP_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let _b = BudgetOverride::new(4096);
    // `accumulate_list_bytes` consults the live budget per element and rejects after a few hundred.
    // (range itself caps on its own fixed MAX_RANGE_BYTES, not the override; the comprehension is the
    // override-aware contrast.)
    let outcome = run_rows("RETURN [x IN range(1, 2000) | x] AS r", &Parameters::new());
    assert!(
        is_value_budget_rejection(&outcome),
        "the comprehension must reject a 2000-element build at the 4 KiB budget; got {outcome:?}"
    );
}

#[test]
fn comprehension_wrapping_split_rejects() {
    let _lock = CAP_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let _b = BudgetOverride::new(4096);
    // Post-fix, `split` itself rejects; even wrapped in a comprehension the outcome is a clean budget
    // rejection (whichever stage trips first), never an over-budget materialisation.
    let s = "a".repeat(2000);
    let params = Parameters::new().with("s", Value::String(s));
    let outcome = run_rows("RETURN [c IN split($s, '') | c] AS r", &params);
    assert!(
        is_value_budget_rejection(&outcome),
        "split's output over the budget must reject (split's guard or accumulate_list_bytes); got {outcome:?}"
    );
}

#[test]
fn collect_and_concat_and_replace_still_reject_at_the_lowered_budget() {
    let _lock = CAP_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let _b = BudgetOverride::new(4096);

    // collect over a 10000-element stream (executor budget).
    let collect_big = run_rows(
        "UNWIND range(1, 100) AS x UNWIND range(1, 100) AS y RETURN collect(x) AS c",
        &Parameters::new(),
    );
    assert!(
        is_value_budget_rejection(&collect_big),
        "collect of 10000 elements must reject at the 4 KiB budget; got {collect_big:?}"
    );

    // `+` string concat (each operand 3000 B → 6000 B > 4096).
    let big = "a".repeat(3000);
    let cat_params = Parameters::new().with("s", Value::String(big));
    let concat = run_rows("RETURN $s + $s AS r", &cat_params);
    assert!(
        is_value_budget_rejection(&concat),
        "string `+` concat over the budget must reject; got {concat:?}"
    );

    // `replace` expansion (100 'a' → 100×80 'z' ≈ 8000 B > 4096).
    let rep_params = Parameters::new()
        .with("s", Value::String("a".repeat(100)))
        .with("rep", Value::String("z".repeat(80)));
    let replace = run_rows("RETURN replace($s, 'a', $rep) AS r", &rep_params);
    assert!(
        is_value_budget_rejection(&replace),
        "expanding replace over the budget must reject (the O(1) bound); got {replace:?}"
    );
}

#[test]
fn default_budget_is_unchanged_256_mib() {
    let _lock = CAP_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    // No override held here: production / TCK run at the 256 MiB default, which no legitimate query
    // approaches — so the builtin guards never fire for honest workloads.
    assert_eq!(MAX_VALUE_BYTES, 256 * 1024 * 1024);
    assert_eq!(max_value_bytes(), MAX_VALUE_BYTES);
}
