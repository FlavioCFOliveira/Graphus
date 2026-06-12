//! The **offline correctness harness** — the headline deliverable of the offline-scoped LDBC task.
//!
//! # What this is, and why it is the offline substitute for official validation
//!
//! The official LDBC SNB validates an engine by comparing its answers, query by query, against an
//! *audited* result set computed from the official Datagen dataset with official validation
//! parameters. Offline, neither the dataset nor those parameters are available. We substitute a
//! **self-consistent verification against known ground truth**:
//!
//!   1. The synthetic graph is generated **deterministically** ([`crate::ldbc::generator`]), and the
//!      generator captures the entire structure in a pure-Rust [`SnbModel`] — the *same* model it
//!      emits the loader's Cypher from, so the engine's graph and the model are identical by
//!      construction.
//!   2. Each [`Operation`] has an `expected` function that computes its answer **directly from the
//!      model in Rust**, never by running Cypher.
//!   3. This harness runs each operation's Cypher through the **real engine pipeline** (the exact
//!      `tokenize → … → execute → commit` path the benchmark and the TCK runner use) and asserts the
//!      engine's rows equal the model-derived `expected` rows.
//!
//! Because the engine and the oracle reach the same answer by two fully independent routes (a graph
//! traversal in the storage/executor stack vs. a closed-form computation over the model), agreement
//! is strong evidence the engine answered the query correctly. This is *not* a claim of official LDBC
//! conformance (see `LDBC.md`); it is a rigorous, repeatable, deterministic correctness gate against
//! the synthetic dataset's known ground truth.
//!
//! # The comparison contract
//!
//! Each operation's `expected` closure returns its rows in the operation's exact `ORDER BY` order
//! with a unique tiebreaker (or projects only the ordering key, so any tied rows are byte-identical),
//! making the expected order **total**. The harness therefore compares **positionally** — the
//! strongest single assertion: it catches a wrong value, a missing row, an extra row, a wrong
//! multiplicity, *and* a wrong `ORDER BY`, all at once.
//!
//! When the positional check fails, the harness diagnoses *why* before erroring: it re-compares the
//! two row sets as **sorted multisets**. If the multisets differ, the engine returned wrong rows (a
//! genuine content/correctness bug); if they match but positions differed, the engine returned the
//! right rows in the wrong order (an `ORDER BY` bug). Both are reported distinctly, and neither is
//! ever silently tolerated.
//!
//! Floats (e.g. `avg(age)`) are compared with a small relative+absolute tolerance; all other values
//! use exact [`Value`] equality.

use graphus_core::Value;
use graphus_cypher::binding::Parameters;
use graphus_cypher::runtime::Row;
use graphus_txn::IsolationLevel;

use crate::ldbc::driver::{Coord, RunError, fresh_coord, run_statement, run_write};
use crate::ldbc::generator::{self, ScaleFactor, SnbModel};
use crate::ldbc::operations::{self, ExpectedResult, ExpectedRow, Operation};

/// A normalised, comparable cell value: a column name paired with the engine/expected [`Value`].
/// Comparison and ordering treat floats with tolerance (see [`cells_equal`] / [`cell_cmp`]).
type NormCell = (String, Value);
/// A normalised row: its cells in *sorted column order* (so cell order never affects equality).
type NormRow = Vec<NormCell>;

/// The outcome of checking one operation against ground truth.
#[derive(Debug)]
pub struct CheckOutcome {
    /// The operation id, e.g. `"IC-fof"`.
    pub id: &'static str,
    /// The official query it translates.
    pub inspired_by: &'static str,
    /// `Ok(invocations_checked)` if every checked invocation matched ground truth, else `Err(reason)`
    /// describing the first mismatch (with the offending invocation, expected, and actual rows).
    pub result: Result<u64, String>,
}

/// How many distinct invocations of each operation the correctness harness verifies. Each invocation
/// anchors on a different id (via the operation's `pick`-based parameterisation), so this spreads the
/// check across the id space. Kept modest so the `cargo test` stays fast at the micro scale.
pub const CHECK_INVOCATIONS: u64 = 16;

/// Generates the deterministic graph at `scale`, builds the standard property indexes, then verifies
/// **every** operation in the catalog against ground truth. Returns one [`CheckOutcome`] per
/// operation. The returned model is the ground-truth oracle (handy for a caller that wants to assert
/// further invariants).
///
/// # Errors
/// Returns a [`RunError`] only if graph generation or index creation fails (a harness bug). A
/// per-operation correctness *mismatch* is reported inside its [`CheckOutcome::result`], not as an
/// `Err` here — the caller (the test) decides how to assert on the outcomes.
pub fn verify_all(scale: ScaleFactor) -> Result<(SnbModel, Vec<CheckOutcome>), RunError> {
    let mut coord = fresh_coord();
    let (model, _stats) = generator::generate(&mut coord, scale)?;

    // Build the standard SNB-style id indexes (mirrors the perf harness) so the verification runs
    // over the same plans the benchmark measures — index seeks for `{id: x}` lookups.
    for (label, property) in [("Person", "id"), ("Forum", "id"), ("Post", "id")] {
        coord
            .create_node_property_index(label, property)
            .map_err(|e| RunError::Execute(format!("create index {label}.{property}: {e}")))?;
    }

    let mut outcomes = Vec::new();
    for op in operations::catalog() {
        outcomes.push(check_operation(&mut coord, &op, &model));
    }
    Ok((model, outcomes))
}

/// Verifies one operation across [`CHECK_INVOCATIONS`] invocations against ground truth.
fn check_operation(coord: &mut Coord, op: &Operation, model: &SnbModel) -> CheckOutcome {
    for i in 0..CHECK_INVOCATIONS {
        if let Err(reason) = check_invocation(coord, op, model, i) {
            return CheckOutcome {
                id: op.id,
                inspired_by: op.inspired_by,
                result: Err(reason),
            };
        }
    }
    CheckOutcome {
        id: op.id,
        inspired_by: op.inspired_by,
        result: Ok(CHECK_INVOCATIONS),
    }
}

/// Verifies a single invocation `i`. For a read op: run its Cypher, compare to `expected`. For a
/// write op: run the write (committing), then run its `verify` read and compare *that* to `expected`
/// (which, for a write, encodes the effect the read must observe).
fn check_invocation(
    coord: &mut Coord,
    op: &Operation,
    model: &SnbModel,
    i: u64,
) -> Result<(), String> {
    let expected = (op.expected)(i, model);

    let actual_rows = if op.is_write {
        // Apply the write at SERIALIZABLE (the OLTP write level), committing it, then observe its
        // effect with the verification read at SNAPSHOT.
        let write_src = (op.build)(i, model);
        run_write(coord, &write_src).map_err(|e| {
            format!(
                "[{}] invocation {i}: write failed: {e}\n  query: {write_src}",
                op.id
            )
        })?;
        let verify_src = (op.verify).ok_or_else(|| {
            format!(
                "[{}] is a write op but carries no `verify` read query",
                op.id
            )
        })?(i, model);
        run_read(coord, &verify_src).map_err(|e| {
            format!(
                "[{}] invocation {i}: verification read failed: {e}\n  query: {verify_src}",
                op.id
            )
        })?
    } else {
        let src = (op.build)(i, model);
        run_read(coord, &src).map_err(|e| {
            format!(
                "[{}] invocation {i}: read failed: {e}\n  query: {src}",
                op.id
            )
        })?
    };

    compare(op.id, i, &expected, &actual_rows)
}

/// Runs a read statement at SNAPSHOT isolation and returns its rows.
fn run_read(coord: &mut Coord, src: &str) -> Result<Vec<Row>, RunError> {
    run_statement(coord, src, &Parameters::new(), IsolationLevel::Snapshot).map(|r| r.rows)
}

/// Compares the engine's `actual` rows to the `expected` ground truth: content (as a sorted multiset)
/// and order (monotonic under the expected sequence's own ordering). Returns `Ok(())` on a match, or
/// a detailed mismatch report.
fn compare(id: &str, i: u64, expected: &ExpectedResult, actual: &[Row]) -> Result<(), String> {
    let exp_rows: Vec<NormRow> = expected.iter().map(normalise_expected).collect();
    let act_rows: Vec<NormRow> = actual.iter().map(normalise_actual).collect();

    if exp_rows.len() != act_rows.len() {
        return Err(mismatch(id, i, "row count", &exp_rows, &act_rows));
    }

    // -- primary check: positional equality (the strongest assertion — catches a wrong value, a -----
    //    missing/extra row, AND a wrong ORDER BY in one shot). The `expected` sequence is produced in
    //    the operation's exact `ORDER BY` order with a unique tiebreaker, so a correct engine matches
    //    it position for position.
    let positional_ok = exp_rows
        .iter()
        .zip(act_rows.iter())
        .all(|(e, a)| rows_equal(e, a));
    if positional_ok {
        return Ok(());
    }

    // -- diagnose the failure: is it CONTENT (wrong rows) or only ORDER (right rows, tie-order) ? ---
    //    Content is the correctness signal; an order-only difference is tolerated *only* where the
    //    operation's `ORDER BY` left rows tied (equal sort key), which can legitimately differ from
    //    our ground-truth tie-order. We detect a pure-order difference by comparing as multisets.
    let mut exp_sorted = exp_rows.clone();
    let mut act_sorted = act_rows.clone();
    exp_sorted.sort_by(rows_cmp);
    act_sorted.sort_by(rows_cmp);
    let content_matches = exp_sorted
        .iter()
        .zip(act_sorted.iter())
        .all(|(e, a)| rows_equal(e, a));

    if !content_matches {
        // A genuine content mismatch — the engine returned wrong rows/values. This is the case that
        // must never be silently tolerated (a real correctness bug, not a tie-order quirk).
        return Err(mismatch(id, i, "row content", &exp_rows, &act_rows));
    }

    // Content matches as a multiset but the positional check above failed: the engine returned the
    // right rows in the wrong order. Every operation's Cypher ends its `ORDER BY` in a unique
    // tiebreaker (or projects only the ordering key, so tied rows are byte-identical and unobservable
    // out of order) — so the expected order is total and a positional difference on observable cells
    // is a real ORDER BY bug, not a tolerable tie.
    Err(format!(
        "[{id}] invocation {i}: engine returned the correct rows but in the wrong ORDER BY order\n  \
         expected (ordered): {:?}\n  actual: {:?}",
        debug_rows(&exp_rows),
        debug_rows(&act_rows),
    ))
}

/// Normalises an expected row to a [`NormRow`]: clone the cells, sort by column name.
fn normalise_expected(row: &ExpectedRow) -> NormRow {
    let mut cells: NormRow = row
        .iter()
        .map(|(name, value)| ((*name).to_owned(), value.clone()))
        .collect();
    cells.sort_by(|a, b| a.0.cmp(&b.0));
    cells
}

/// Normalises an engine [`Row`] to a [`NormRow`]: read each named column as a property [`Value`],
/// sort by column name. (Every benchmark projection returns property-typed columns — ids, names,
/// counts, lists — never raw entity references, so `Row::value` is the right accessor.)
fn normalise_actual(row: &Row) -> NormRow {
    let mut cells: NormRow = row
        .columns()
        .iter()
        .map(|c| (c.clone(), row.value(c)))
        .collect();
    cells.sort_by(|a, b| a.0.cmp(&b.0));
    cells
}

/// Whether two normalised rows are equal (same columns, each cell equal under [`cells_equal`]).
fn rows_equal(a: &NormRow, b: &NormRow) -> bool {
    a.len() == b.len()
        && a.iter()
            .zip(b.iter())
            .all(|((an, av), (bn, bv))| an == bn && cells_equal(av, bv))
}

/// A total-ish ordering over normalised rows for the multiset sort (column names then cell values).
fn rows_cmp(a: &NormRow, b: &NormRow) -> std::cmp::Ordering {
    use std::cmp::Ordering;
    for ((an, av), (bn, bv)) in a.iter().zip(b.iter()) {
        match an.cmp(bn).then_with(|| cell_cmp(av, bv)) {
            Ordering::Equal => {}
            other => return other,
        }
    }
    a.len().cmp(&b.len())
}

/// Cell equality with float tolerance; everything else is exact [`Value`] equality.
fn cells_equal(a: &Value, b: &Value) -> bool {
    match (a, b) {
        (Value::Float(x), Value::Float(y)) => floats_close(*x, *y),
        // An integer and a float can both be a legitimate aggregate result on some engines; compare
        // numerically with tolerance to be robust (e.g. `avg` of integers may surface as a float).
        (Value::Integer(x), Value::Float(y)) | (Value::Float(y), Value::Integer(x)) => {
            floats_close(*x as f64, *y)
        }
        (Value::List(xs), Value::List(ys)) => {
            xs.len() == ys.len() && xs.iter().zip(ys).all(|(x, y)| cells_equal(x, y))
        }
        _ => a == b,
    }
}

/// A deterministic ordering over [`Value`]s for the multiset sort. Only needs to be *consistent*, not
/// semantically meaningful; floats that are `close` compare equal so tolerance does not split a tie.
fn cell_cmp(a: &Value, b: &Value) -> std::cmp::Ordering {
    use std::cmp::Ordering;
    match (a, b) {
        (Value::Integer(x), Value::Integer(y)) => x.cmp(y),
        (Value::Float(x), Value::Float(y)) => {
            if floats_close(*x, *y) {
                Ordering::Equal
            } else {
                x.partial_cmp(y).unwrap_or(Ordering::Equal)
            }
        }
        (Value::Integer(x), Value::Float(y)) | (Value::Float(y), Value::Integer(x)) => {
            let xf = *x as f64;
            if floats_close(xf, *y) {
                Ordering::Equal
            } else {
                xf.partial_cmp(y).unwrap_or(Ordering::Equal)
            }
        }
        (Value::String(x), Value::String(y)) => x.cmp(y),
        (Value::Boolean(x), Value::Boolean(y)) => x.cmp(y),
        (Value::List(xs), Value::List(ys)) => {
            for (x, y) in xs.iter().zip(ys) {
                match cell_cmp(x, y) {
                    Ordering::Equal => {}
                    other => return other,
                }
            }
            xs.len().cmp(&ys.len())
        }
        // Different variants: order by a stable discriminant rank so the sort is total.
        _ => variant_rank(a).cmp(&variant_rank(b)),
    }
}

/// A stable rank per [`Value`] variant, so the multiset sort is total across mixed types.
fn variant_rank(v: &Value) -> u8 {
    match v {
        Value::Null => 0,
        Value::Boolean(_) => 1,
        Value::Integer(_) => 2,
        Value::Float(_) => 3,
        Value::String(_) => 4,
        Value::List(_) => 5,
        _ => 6,
    }
}

/// Relative+absolute float closeness, robust around zero (used for `avg`-style aggregates).
fn floats_close(x: f64, y: f64) -> bool {
    let diff = (x - y).abs();
    diff <= 1e-9 || diff <= 1e-9 * x.abs().max(y.abs())
}

/// Builds a detailed mismatch message (truncated row dumps so a large result does not flood output).
fn mismatch(id: &str, i: u64, what: &str, expected: &[NormRow], actual: &[NormRow]) -> String {
    format!(
        "[{id}] invocation {i}: {what} mismatch vs ground truth\n  \
         expected ({} rows): {:?}\n  actual   ({} rows): {:?}",
        expected.len(),
        debug_rows(expected),
        actual.len(),
        debug_rows(actual),
    )
}

/// Renders at most the first 12 rows for an error message (avoids dumping a 60-row aggregate).
fn debug_rows(rows: &[NormRow]) -> Vec<&NormRow> {
    rows.iter().take(12).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// **The offline correctness gate.** Generate the deterministic micro-scale graph, then assert
    /// **every** catalog operation's engine answer equals the ground-truth answer computed from the
    /// model — covering all the IS/IC/BI read shapes *and* the write op (verified by read-back).
    ///
    /// This is the offline substitute for the official LDBC audited validation: a self-consistent
    /// check against the synthetic dataset's known ground truth (see the module docs and `LDBC.md`).
    #[test]
    fn every_operation_matches_ground_truth_at_micro_scale() {
        let (model, outcomes) =
            verify_all(ScaleFactor::micro()).expect("generation + verification harness runs");

        // The graph is non-trivial (so the checks are meaningful, not vacuously passing on emptiness).
        assert!(model.persons() >= 20, "a well-populated person set");
        assert!(model.post_count() > 0, "posts exist");
        assert!(model.comment_count() > 0, "comments exist");

        // Every operation must have matched ground truth on every checked invocation.
        let mut failures: Vec<String> = Vec::new();
        for o in &outcomes {
            match &o.result {
                Ok(n) => assert_eq!(
                    *n, CHECK_INVOCATIONS,
                    "{} should have checked every invocation",
                    o.id
                ),
                Err(reason) => failures.push(reason.clone()),
            }
        }
        assert!(
            failures.is_empty(),
            "{} operation(s) disagreed with ground truth:\n\n{}",
            failures.len(),
            failures.join("\n\n")
        );

        // Sanity: the catalog is the broad set we intend to ship (a guard against an accidental
        // truncation of `catalog()`), and at least one of each family (IS/IC/BI/write) is present.
        let ids: Vec<&str> = outcomes.iter().map(|o| o.id).collect();
        assert!(
            ids.len() >= 20,
            "the broadened catalog has ≥ 20 operations, got {}",
            ids.len()
        );
        assert!(
            ids.iter().any(|id| id.starts_with("IS")),
            "an IS short read"
        );
        assert!(
            ids.iter().any(|id| id.starts_with("IC")),
            "an IC complex read"
        );
        assert!(ids.iter().any(|id| id.starts_with("BI")), "a BI aggregate");
        assert!(ids.iter().any(|id| id.starts_with("IU")), "a write op");
    }

    /// A focused guard that the **write** op's effect is genuinely observed: after the insert, the
    /// verification read returns exactly the (post, author) the write targeted. (The broad test above
    /// already covers this; this isolates it so a write-path regression names itself.)
    #[test]
    fn write_op_effect_is_observed() {
        let scale = ScaleFactor::micro();
        let mut coord = fresh_coord();
        let (model, _stats) = generator::generate(&mut coord, scale).expect("generate");

        let op = operations::catalog()
            .into_iter()
            .find(|o| o.is_write)
            .expect("a write operation exists");

        // Run + verify a few invocations directly.
        for i in 0..4 {
            check_invocation(&mut coord, &op, &model, i)
                .unwrap_or_else(|e| panic!("write op invocation {i} failed verification: {e}"));
        }
    }
}
