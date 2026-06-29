//! ADVERSARIAL VERIFICATION PROBE (sprint-42 #485 completeness critic).
//!
//! D5 (commit ae090dc) made the list *literal* `[ … ]` byte-aware via `accumulate_list_bytes`, and
//! guarded `split`/`keys`/`toUpper`/`LOAD CSV`. But the `+` **list concatenation** guard
//! (`check_concat_list_len`, pre-existing #481) is **count-only**: it rejects on element COUNT
//! (`max_list_elements`), never on the bytes the elements own. A concatenation of FEW but LARGE
//! elements therefore stays under the element-count ceiling while its byte footprint grows without
//! bound — bypassing the per-value byte budget the #481/D5 cluster is supposed to enforce.
//!
//! This probe MEASURES the boundary at a lowered budget (`BudgetOverride`): a handful of
//! kilobyte-sized string elements concatenated with `+` exceeds the BYTE budget but stays far under
//! the element COUNT ceiling. If the engine ACCEPTS it, the per-value byte budget is bypassed on the
//! concat path (the finding). The control (`split`, byte-aware after D5) is shown rejecting the same
//! byte volume to prove the budget mechanism is otherwise live at this ceiling.
//!
//! NOTE: this is a TEST-ONLY probe added by the verification pass; it changes no `src/`.

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
use graphus_cypher::value_size::BudgetOverride;

static CAP_LOCK: Mutex<()> = Mutex::new(());

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

/// THE PROBE. A 4 KiB byte budget. Each `[$s]` is a 1-element list holding a ~1 KiB string. Five of
/// them concatenated with `+` materialise a single 5-element list whose byte footprint (~5 KiB +
/// slots) EXCEEDS the 4 KiB budget — yet the element COUNT (5) is far below the count ceiling
/// (`4096 / size_of::<Value>()` ≈ 85). If `check_concat_list_len` were byte-aware (like the list
/// literal after D5) this would reject; on a count-only guard it is ACCEPTED.
#[test]
fn list_concat_of_large_elements_vs_byte_budget() {
    let _lock = CAP_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let _b = BudgetOverride::new(4096);

    // Each element is a 1000-byte string; 5 of them (in a 5-element list) own ~5000 bytes of heap +
    // 5 Value slots — comfortably over the 4096-byte budget, but only 5 elements.
    let s = "a".repeat(1000);
    let params = Parameters::new().with("s", Value::String(s));
    let src = "RETURN [$s] + [$s] + [$s] + [$s] + [$s] AS big";
    let outcome = run_rows(src, &params);

    eprintln!(
        "[#485 verify] list-concat of 5x~1KB elements at a 4KB budget -> {}",
        match &outcome {
            Ok(rows) => format!("ACCEPTED ({} row(s)) = BUDGET BYPASSED", rows.len()),
            Err(e) => format!("rejected: {e}"),
        }
    );

    // Document the observed behaviour. If this list is ACCEPTED, the per-value BYTE budget is bypassed
    // on the list-concat path (a count-only guard). The assertion below records the EXPECTED-SECURE
    // outcome (rejection); it FAILS if the budget is bypassed, which is the proof of the gap.
    assert!(
        is_value_budget_rejection(&outcome),
        "FINDING: a `+` list concatenation producing a 5-element list of ~1 KB strings (~5 KB total) \
         was NOT rejected at a 4 KB per-value byte budget — the concat guard `check_concat_list_len` \
         is COUNT-ONLY (5 elements << ~85 ceiling) and byte-blind. Scaled to production (256 MiB \
         budget, a 64 MiB string param referenced N times), `RETURN [$s]+[$s]+…` materialises an \
         N x 64 MiB single list value that bypasses the per-value budget = authenticated memory DoS \
         (CWE-770/789). Outcome was: {outcome:?}"
    );
}

/// THIRD VECTOR: the **map literal** `{ … }` (eval.rs ExprKind::Map) has NO byte guard at all — D5
/// made the *list* literal byte-aware (`accumulate_list_bytes`) but left the *map* literal unguarded.
/// A map literal with many distinct keys each bound to a large value materialises a single map value
/// whose bytes exceed the budget; the key count is bounded only by the 64 MiB query text.
#[test]
fn map_literal_of_large_values_vs_byte_budget() {
    let _lock = CAP_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let _b = BudgetOverride::new(4096);
    let s = "a".repeat(1000);
    let params = Parameters::new().with("s", Value::String(s));
    // 8 distinct keys, each bound to a ~1 KB string -> ~8 KB map value > 4 KB budget, built unguarded.
    let pairs: Vec<String> = (0..8).map(|i| format!("k{i}: $s")).collect();
    let src = format!("RETURN {{{}}} AS big", pairs.join(", "));
    let outcome = run_rows(&src, &params);
    eprintln!(
        "[#485 verify] map literal of 8x~1KB values at a 4KB budget -> {}",
        match &outcome {
            Ok(rows) => format!("ACCEPTED ({} row(s)) = BUDGET BYPASSED", rows.len()),
            Err(e) => format!("rejected: {e}"),
        }
    );
    assert!(
        is_value_budget_rejection(&outcome),
        "FINDING (3rd vector): a map literal {{k0:$s, … k7:$s}} (~8 KB) was NOT rejected at a 4 KB \
         byte budget — eval.rs `ExprKind::Map` builds the map with no per-value budget guard (the list \
         literal got one in D5; the map literal did not). Outcome was: {outcome:?}"
    );
}

/// CONTROL: the SAME byte volume through `split` (made byte/count-aware by D5) IS rejected — proving
/// the budget mechanism is live at this ceiling and the concat result above is a genuine per-operator
/// gap, not an inert budget.
#[test]
fn split_control_rejects_same_byte_volume() {
    let _lock = CAP_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let _b = BudgetOverride::new(4096);
    let s = "a".repeat(5000); // split('') -> 5000 single-char elements, far over the count ceiling
    let params = Parameters::new().with("s", Value::String(s));
    let outcome = run_rows("RETURN split($s, '') AS parts", &params);
    assert!(
        is_value_budget_rejection(&outcome),
        "control: split of 5000 chars must reject at the 4 KB budget (post-D5 it is guarded). Got: {outcome:?}"
    );
}

/// SCALING VECTOR: the bypass is not a marginal 5 KB-vs-4 KB fluke — it scales linearly with the
/// number of `+` operands while the element count stays trivially under the ceiling. Budget 100 KB
/// (count ceiling = 100_000 / size_of::<Value>() ≈ 2500). A 50-operand concat of 4 KB strings is a
/// 50-element / ~200 KB single list value — 2x the BYTE budget, 50 elements (50 << 2500). Accepted =
/// the byte budget is bypassed proportionally to the (query-text-bounded) operand count.
#[test]
fn list_concat_byte_bypass_scales_with_operands() {
    let _lock = CAP_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let _b = BudgetOverride::new(100_000);
    let s = "a".repeat(4000);
    let params = Parameters::new().with("s", Value::String(s));
    // 50 occurrences of `[$s]` joined by `+`.
    let src = format!("RETURN {} AS big", vec!["[$s]"; 50].join(" + "));
    let outcome = run_rows(&src, &params);
    eprintln!(
        "[#485 verify] 50-operand `+` concat of 4 KB strings at a 100 KB budget -> {}",
        match &outcome {
            Ok(rows) => format!("ACCEPTED ({} row(s)) = BUDGET BYPASSED", rows.len()),
            Err(e) => format!("rejected: {e}"),
        }
    );
    assert!(
        is_value_budget_rejection(&outcome),
        "FINDING (scaling): a 50-operand `+` list concatenation (~200 KB of string content) was NOT \
         rejected at a 100 KB byte budget — the count-only guard scales the bypass linearly with the \
         operand count (bounded only by the 64 MiB query-text cap). Outcome was: {outcome:?}"
    );
}
