//! Regression battery for the per-value **materialised-size budget** (`rmp` task #481 — `SEC-191`
//! follow-up, CWE-770 / CWE-789).
//!
//! Unlike `range()` (already memory-capped at `MAX_VALUE_BYTES` and rejected as a typed error rather
//! than allocated), a single materialised value used to have NO per-value memory budget: `collect(...)`
//! over a huge stream, a runaway `+` / `replace` string, a list concatenation, or a comprehension could
//! each grow ONE value until it exhausts the per-database engine thread's heap — a memory-exhaustion DoS
//! the per-statement timeout (`rmp` #476) only partially mitigates (a multi-second allocation can OOM
//! first). The fix bounds every such builder against the shared budget and rejects with a clean, typed
//! `ResourceLimit` runtime error (the same class `range()` raises), never the over-budget allocation.
//!
//! These tests **measure the boundary**: each installs a small budget override (so the cap is hit with
//! kilobytes, not the 256 MiB default — fast, low-memory, deterministic) and asserts a value that crosses
//! the cap is rejected with the typed error, while a value just under it completes normally. The override
//! is process-global, so every test here holds [`CAP_LOCK`] for its whole body (serialising the budget),
//! and uses an RAII guard that restores the default even on panic. The default (production / TCK) budget
//! is the 256 MiB constant — asserted unchanged in [`default_budget_is_256_mib`].

use std::sync::Mutex;

use graphus_core::Value;
use graphus_cypher::binding::{Parameters, bind_parameters};
use graphus_cypher::catalog::IndexCatalog;
use graphus_cypher::coordinator::TxnCoordinator;
use graphus_cypher::executor::execute;
use graphus_cypher::graph_access::MemGraph;
use graphus_cypher::lexer::tokenize;
use graphus_cypher::lower::lower;
use graphus_cypher::parser::parse_tokens;
use graphus_cypher::physical::plan_physical;
use graphus_cypher::runtime::RowValue;
use graphus_cypher::semantics::analyze;
use graphus_cypher::value_size::{
    BudgetOverride, MAX_VALUE_BYTES, estimate_rowvalue_bytes, max_list_elements, max_value_bytes,
};
use graphus_io::MemBlockDevice;
use graphus_storage::{Namespace, RecordStore};
use graphus_wal::{MemLogSink, WalManager};

/// Serialises the process-global budget override across this binary's tests (each lowers the cap, so they
/// must not run concurrently and observe each other's override).
static CAP_LOCK: Mutex<()> = Mutex::new(());

/// Drives the full compile → execute → drain pipeline for `src` (with optional parameters) over an empty
/// in-memory graph, returning `Ok(row_count)` or `Err(message)` for whichever stage failed. Never panics
/// on a query outcome (every fallible stage is matched), so a clean rejection surfaces as `Err`, not an
/// abort.
fn run(src: &str, params: &Parameters) -> Result<usize, String> {
    let toks = tokenize(src).map_err(|e| format!("lex: {e:?}"))?;
    let ast = parse_tokens(&toks, src).map_err(|e| format!("parse: {e:?}"))?;
    let validated = analyze(&ast).map_err(|e| format!("semantic: {e:?}"))?;
    let plan = plan_physical(&lower(&validated), &IndexCatalog::empty());
    let bound = bind_parameters(&plan, params).map_err(|e| format!("bind: {e:?}"))?;
    let mut graph = MemGraph::new();
    let mut cursor = execute(&plan, &bound, &mut graph).map_err(|e| format!("exec: {e}"))?;
    let rows = cursor.collect_all().map_err(|e| format!("{e}"))?;
    Ok(rows.len())
}

/// `run` with no parameters.
fn run_q(src: &str) -> Result<usize, String> {
    run(src, &Parameters::new())
}

/// The estimated byte cost of one `collect`ed integer element — the unit the boundary tests size the
/// budget against, read from the production estimator so the measurement tracks `size_of::<Value>()`
/// rather than hard-coding it.
fn bytes_per_collected_int() -> usize {
    estimate_rowvalue_bytes(&RowValue::Value(Value::Integer(0)))
}

// --------------------------------------------------------------------------------------------------- //
// Default budget (the production / TCK ceiling)
// --------------------------------------------------------------------------------------------------- //

#[test]
fn default_budget_is_256_mib() {
    let _lock = CAP_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    // No override installed: the live budget is the 256 MiB default constant — the value the TCK and
    // production run at, and which no legitimate query approaches.
    assert_eq!(MAX_VALUE_BYTES, 256 * 1024 * 1024);
    assert_eq!(max_value_bytes(), MAX_VALUE_BYTES);
}

// --------------------------------------------------------------------------------------------------- //
// collect() — the dominant vector
// --------------------------------------------------------------------------------------------------- //

#[test]
fn collect_is_capped_at_the_budget_boundary() {
    let _lock = CAP_LOCK.lock().unwrap_or_else(|e| e.into_inner());

    let per = bytes_per_collected_int();
    // A budget that holds exactly `K` collected integers, so the boundary is exact: K is accepted, K+1 is
    // rejected. (`range(1, n)` materialises `n` elements; `range` itself uses the untouched 256 MiB ceiling
    // so it never trips here — only the `collect` does.)
    let k = 1000usize;
    let _budget = BudgetOverride::new(per * k);

    // Exactly at the budget: accepted (total == cap, which is not "> cap").
    assert_eq!(
        run_q(&format!("UNWIND range(1, {k}) AS x RETURN collect(x) AS c")),
        Ok(1),
        "a collect whose size equals the budget must complete"
    );

    // One element over the budget: a clean typed ResourceLimit, NOT an allocation/panic/hang.
    let over = run_q(&format!(
        "UNWIND range(1, {}) AS x RETURN collect(x) AS c",
        k + 1
    ))
    .expect_err("a collect one element over the budget must be rejected");
    assert!(
        over.contains("collected list exceeds") && over.contains("value limit"),
        "expected a typed collected-list ResourceLimit, got: {over}"
    );
}

#[test]
fn collect_over_huge_stream_is_rejected_fast() {
    let _lock = CAP_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    // A 64 KiB budget vs a stream that would collect 5 million integers (~hundreds of MiB unbounded). The
    // fix must reject it after a few hundred elements — proven by it returning an Err essentially
    // instantly rather than allocating its way to OOM.
    let _budget = BudgetOverride::new(64 * 1024);
    let start = std::time::Instant::now();
    let err = run_q("UNWIND range(1, 5000000) AS x RETURN collect(x) AS c")
        .expect_err("a huge collect must be rejected, not materialised");
    assert!(err.contains("collected list exceeds"), "got: {err}");
    assert!(
        start.elapsed() < std::time::Duration::from_secs(5),
        "rejection must be fast (it allocated unboundedly): took {:?}",
        start.elapsed()
    );
}

#[test]
fn normal_collect_is_unaffected() {
    let _lock = CAP_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    // At the real 256 MiB default, an ordinary aggregation is untouched.
    assert_eq!(
        run_q("UNWIND range(1, 10000) AS x RETURN collect(x) AS c"),
        Ok(1),
        "a normal-sized collect must complete unaffected"
    );
}

// --------------------------------------------------------------------------------------------------- //
// String builders — `+` concatenation and `replace`
// --------------------------------------------------------------------------------------------------- //

#[test]
fn string_concat_is_capped() {
    let _lock = CAP_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let _budget = BudgetOverride::new(1024);

    // `$s + $s` with |s| = 600 ⇒ 1200 bytes > 1024: rejected before the result string is allocated.
    let s = "a".repeat(600);
    let params = Parameters::new().with("s", Value::String(s.clone()));
    let err = run("RETURN $s + $s AS r", &params)
        .expect_err("a string concatenation over the budget must be rejected");
    assert!(
        err.contains("string concatenation") && err.contains("bytes"),
        "expected a typed string-concat ResourceLimit, got: {err}"
    );

    // A concat that stays under the budget (600 + 1 byte) completes — and the same `+` path also covers
    // string + number coercion.
    assert_eq!(
        run("RETURN $s + 1 AS r", &params),
        Ok(1),
        "a concat under the budget must complete (incl. number coercion)"
    );
}

#[test]
fn replace_expansion_is_capped() {
    let _lock = CAP_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let _budget = BudgetOverride::new(1024);

    // `replace("a"*100, "a", <50 chars>)` expands to ~5000 bytes > 1024: rejected on the O(1) length bound
    // BEFORE `String::replace` allocates the expanded result.
    let params = Parameters::new()
        .with("s", Value::String("a".repeat(100)))
        .with("rep", Value::String("z".repeat(50)));
    let err = run("RETURN replace($s, 'a', $rep) AS r", &params)
        .expect_err("an expanding replace over the budget must be rejected");
    assert!(
        err.contains("replace()") && err.contains("bytes"),
        "expected a typed replace ResourceLimit, got: {err}"
    );

    // A non-expanding replace (replacement no longer than the search) can never grow past the source, so it
    // is accepted regardless of the (small) budget.
    assert_eq!(
        run("RETURN replace($s, 'a', 'b') AS r", &params),
        Ok(1),
        "a non-expanding replace must complete"
    );
}

// --------------------------------------------------------------------------------------------------- //
// List builders — `+` concatenation and comprehensions
// --------------------------------------------------------------------------------------------------- //

#[test]
fn list_concat_is_capped_at_the_element_ceiling() {
    let _lock = CAP_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    // Pick a budget whose element ceiling is a small, exact number so the boundary is measurable.
    let _budget = BudgetOverride::new(1024);
    let limit = max_list_elements();
    assert!(
        limit >= 2,
        "the test needs a ceiling of at least 2 elements"
    );

    // `limit` + `limit` elements = `2*limit` > `limit`: rejected before the result Vec is grown.
    let half = limit; // each operand has `limit` elements; the concatenation is `2*limit`.
    let err = run_q(&format!("RETURN range(1, {half}) + range(1, {half}) AS r"))
        .expect_err("a list concatenation over the element ceiling must be rejected");
    assert!(
        err.contains("list concatenation") && err.contains("elements"),
        "expected a typed list-concat ResourceLimit, got: {err}"
    );

    // A concatenation that stays at/under the ceiling completes.
    let lo = limit / 2;
    assert_eq!(
        run_q(&format!("RETURN range(1, {lo}) + range(1, {lo}) AS r")),
        Ok(1),
        "a list concatenation under the ceiling must complete"
    );
}

#[test]
fn list_comprehension_is_capped() {
    let _lock = CAP_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let _budget = BudgetOverride::new(64 * 1024);
    // A comprehension projecting 5 million elements would be hundreds of MiB unbounded; it must reject
    // after a few hundred, fast.
    let start = std::time::Instant::now();
    let err = run_q("RETURN [x IN range(1, 5000000) | x] AS r")
        .expect_err("a huge list comprehension must be rejected, not materialised");
    assert!(
        err.contains("list comprehension") && err.contains("value limit"),
        "expected a typed comprehension ResourceLimit, got: {err}"
    );
    assert!(
        start.elapsed() < std::time::Duration::from_secs(5),
        "rejection must be fast: took {:?}",
        start.elapsed()
    );

    // A small comprehension under the budget completes.
    assert_eq!(
        run_q("RETURN [x IN range(1, 100) | x * 2] AS r"),
        Ok(1),
        "a normal-sized comprehension must complete"
    );
}

// --------------------------------------------------------------------------------------------------- //
// Compose with #476 cancellation — a capped value is a distinct, immediate error (not a timeout)
// --------------------------------------------------------------------------------------------------- //

#[test]
fn cap_error_is_distinct_from_cancellation() {
    let _lock = CAP_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let _budget = BudgetOverride::new(64 * 1024);
    // The rejection is a ResourceLimit ("...exceeds...value limit"), NOT a "cancelled" / timeout error: the
    // value cap fires immediately on crossing the budget, it does not wait for the statement deadline.
    let err = run_q("UNWIND range(1, 5000000) AS x RETURN collect(x) AS c")
        .expect_err("must be rejected");
    assert!(
        err.contains("exceeds") && err.contains("value limit"),
        "got: {err}"
    );
    assert!(
        !err.to_lowercase().contains("cancel"),
        "a value-budget rejection must not masquerade as a cancellation: {err}"
    );
}

// --------------------------------------------------------------------------------------------------- //
// Parallel grouped collect (#360 morsel tier) — the cap composes with intra-query parallelism
// --------------------------------------------------------------------------------------------------- //

/// Bulk-seeds `n` committed `:Person` nodes that all share ONE `country` (so `GROUP BY country` produces a
/// single group whose `collect(n.age)` accumulates every node), with a durable `nodes_with_label` of `n`
/// so the `rmp` #360 grouped-morsel tier engages above `MORSEL_MIN_ROWS = 50_000`. Mirrors
/// `tests/morsel_group_aggregate.rs::coord_with_grouped_people`.
fn coord_with_one_big_group(n: i64) -> TxnCoordinator<MemBlockDevice, MemLogSink> {
    let device = MemBlockDevice::new(0);
    let wal = WalManager::create(MemLogSink::new()).expect("create wal");
    let mut s = RecordStore::create(device, wal, 64, 1).expect("create store");
    let txn = graphus_core::TxnId(1);
    s.begin(txn);
    let l_person = s.intern_token(Namespace::Label, "Person").unwrap();
    let k_country = s.intern_token(Namespace::PropKey, "country").unwrap();
    let k_age = s.intern_token(Namespace::PropKey, "age").unwrap();
    for i in 0..n {
        let (id, _) = s.create_node(txn).unwrap();
        s.add_label(txn, id, l_person).unwrap();
        s.set_node_property_value(txn, id, k_country, &Value::String("PT".to_owned()))
            .unwrap();
        s.set_node_property_value(txn, id, k_age, &Value::Integer(i % 100))
            .unwrap();
    }
    s.commit(txn).unwrap();
    TxnCoordinator::new(s)
}

/// Runs `src` over the coordinator in a fresh serializable read txn, returning `Ok(rows)` or `Err(message)`
/// — never panicking on a query outcome, so a clean rejection surfaces as `Err`.
fn run_coord(
    coord: &mut TxnCoordinator<MemBlockDevice, MemLogSink>,
    src: &str,
) -> Result<usize, String> {
    let toks = tokenize(src).map_err(|e| format!("lex: {e:?}"))?;
    let ast = parse_tokens(&toks, src).map_err(|e| format!("parse: {e:?}"))?;
    let validated = analyze(&ast).map_err(|e| format!("semantic: {e:?}"))?;
    let plan = plan_physical(&lower(&validated), &IndexCatalog::empty());
    let bound = bind_parameters(&plan, &Parameters::new()).map_err(|e| format!("bind: {e:?}"))?;

    let txn = coord.begin_serializable();
    let outcome = {
        let mut graph = coord.statement(txn).expect("statement");
        let mut cursor = match execute(&plan, &bound, &mut graph) {
            Ok(c) => c,
            Err(e) => {
                let _ = coord.commit(txn);
                return Err(format!("exec: {e}"));
            }
        };
        match cursor.collect_all() {
            Ok(rows) => Ok(rows.len()),
            Err(e) => Err(format!("{e}")),
        }
    };
    let _ = coord.commit(txn);
    outcome
}

#[test]
fn parallel_grouped_collect_is_capped_and_falls_back_cleanly() {
    let _lock = CAP_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    // 60k > MORSEL_MIN_ROWS (50k) ⇒ the grouped-morsel collect tier engages; one country ⇒ one group whose
    // collect accumulates all 60k ages.
    let mut coord = coord_with_one_big_group(60_000);
    let q = "MATCH (n:Person) RETURN n.country AS c, collect(n.age) AS ages";

    // A budget that one big group's collect must exceed (60k * per-int >> 256 KiB). With the morsel knob ON,
    // the parallel tier folds/merges over budget, so it DECLINES (per-morsel fold and/or the merge-site
    // detector trips) and falls back to serial, which re-raises the identical typed ResourceLimit — no
    // panic, no wrong/oversized result, no hang.
    let _budget = BudgetOverride::new(256 * 1024);
    graphus_cypher::morsel::set_morsel_threads(8);
    let parallel = run_coord(&mut coord, q);
    graphus_cypher::morsel::set_morsel_threads(1);
    let serial = run_coord(&mut coord, q);

    let perr = parallel.expect_err("the parallel grouped collect over budget must be rejected");
    let serr = serial.expect_err("the serial grouped collect over budget must be rejected");
    assert!(
        perr.contains("collected list exceeds"),
        "parallel path must surface the typed collect ResourceLimit, got: {perr}"
    );
    assert!(
        serr.contains("collected list exceeds"),
        "serial path must surface the typed collect ResourceLimit, got: {serr}"
    );
}

#[test]
fn parallel_grouped_collect_under_budget_is_unaffected() {
    let _lock = CAP_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    // Same large scan, but at the real 256 MiB default the per-group collect (60k small ints ≈ a few MiB) is
    // far under budget: the parallel tier completes normally and produces the one group.
    let mut coord = coord_with_one_big_group(60_000);
    let q = "MATCH (n:Person) RETURN n.country AS c, collect(n.age) AS ages";
    graphus_cypher::morsel::set_morsel_threads(8);
    let rows = run_coord(&mut coord, q);
    graphus_cypher::morsel::set_morsel_threads(1);
    assert_eq!(
        rows,
        Ok(1),
        "a normal grouped collect must complete (one group)"
    );
}
