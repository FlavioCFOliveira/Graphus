//! `INTEGER` vs `FLOAT` at and above 2^53: the evaluator's numeric relations must implement the
//! openCypher **unlimited-precision** rule, and **declaring an index must not change the answer**
//! (`rmp` task #894).
//!
//! openCypher CIP2016-06-14, §Numbers, under *Comparability and equality*, verbatim:
//!
//! > "Numbers of different types (excluding `NaN` values and the Infinities) are compared to each
//! > other and tested for equality **as if both numbers would have been coerced to unlimited
//! > precision big decimals** (currently outside the Cypher type system) before comparing them with
//! > each other numerically in their natural order."
//!
//! Under unlimited precision `9007199254740993` (2^53+1) and `9007199254740992.0` (2^53) are
//! *different* numbers, so `=` is `FALSE`, `<` is `FALSE` and `>` is `TRUE`. Coercing the integer
//! through `f64` — which is what the evaluator used to do — drops it onto the float's 53-bit
//! mantissa and reports them equal, which the specification forbids.
//!
//! # What this file pins
//!
//! Two kinds of assertion:
//!
//! * **The relation itself** — scalar `RETURN a <op> b` probes, plus `DISTINCT` (grouping
//!   equivalence) and `ORDER BY` (orderability), so all three of Cypher's value relations are shown
//!   to agree on the same pairs.
//! * **Index ≡ scan** — [`assert_index_and_scan_agree`] runs the **same query over the same data
//!   twice**: once compiled against [`IndexCatalog::empty`] (the scan + residual-`Filter` path) and
//!   once against the coordinator's real catalog (asserted to plan a `NodeIndexSeek` /
//!   `NodeIndexRangeSeek`), then requires the two result **bags** to be equal *and* to equal the
//!   specification's answer. An index is a performance artefact and must never be a semantic one.
//!
//! The seam-level companion — the index-range candidate-**superset** contract for an exclusive upper
//! bound, which no query shape currently reaches — lives in `index_set`'s
//! `two_sided_range_upper_bound_keeps_the_candidate_superset_above_2_53`.
//!
//! The harness mirrors `tests/index_wiring.rs`.

use graphus_core::Value;
use graphus_cypher::binding::{Parameters, bind_parameters};
use graphus_cypher::catalog::IndexCatalog;
use graphus_cypher::coordinator::TxnCoordinator;
use graphus_cypher::executor::execute;
use graphus_cypher::lexer::tokenize;
use graphus_cypher::lower::lower;
use graphus_cypher::parser::parse_tokens;
use graphus_cypher::physical::{PhysicalOp, PhysicalPlan, plan_physical};
use graphus_cypher::runtime::Row;
use graphus_cypher::semantics::analyze;
use graphus_io::MemBlockDevice;
use graphus_storage::RecordStore;
use graphus_wal::{MemLogSink, WalManager};

type Coord = TxnCoordinator<MemBlockDevice, MemLogSink>;

// =================================================================================================
// Harness
// =================================================================================================

fn fresh_coord() -> Coord {
    let device = MemBlockDevice::new(0);
    let wal = WalManager::create(MemLogSink::new()).expect("create wal");
    TxnCoordinator::new(RecordStore::create(device, wal, 64, 1).expect("create store"))
}

fn compile(src: &str, catalog: &IndexCatalog) -> PhysicalPlan {
    let toks = tokenize(src).expect("lex");
    let ast = parse_tokens(&toks, src).expect("parse");
    let validated = analyze(&ast).expect("analyze");
    plan_physical(&lower(&validated), catalog)
}

fn run_plan(coord: &Coord, txn: graphus_core::TxnId, plan: &PhysicalPlan) -> Vec<Row> {
    let bound = bind_parameters(plan, &Parameters::new()).expect("bind");
    let mut graph = coord.statement(txn).expect("statement");
    let rows = {
        let mut cursor = execute(plan, &bound, &mut graph).expect("open cursor");
        cursor.collect_all().expect("collect")
    };
    assert!(
        !graph.has_error(),
        "statement captured an error: {:?}",
        graph.take_error()
    );
    rows
}

fn run_write(coord: &mut Coord, src: &str) {
    let plan = compile(src, &IndexCatalog::empty());
    let txn = coord.begin_serializable();
    let _rows = run_plan(coord, txn, &plan);
    coord.commit(txn).expect("write commits");
}

/// Runs `src` and returns column `col` as strings **sorted** (bag comparison).
fn read_sorted_tags(coord: &mut Coord, catalog: &IndexCatalog, src: &str) -> Vec<String> {
    let mut v = read_tags_in_order(coord, catalog, src);
    v.sort();
    v
}

/// Runs `src` and returns column `tag` as strings **in result order** (for `ORDER BY`).
fn read_tags_in_order(coord: &mut Coord, catalog: &IndexCatalog, src: &str) -> Vec<String> {
    let plan = compile(src, catalog);
    let txn = coord.begin_serializable();
    let rows = run_plan(coord, txn, &plan);
    coord.commit(txn).expect("read commits");
    rows.iter()
        .filter_map(|r| match r.value("tag") {
            Value::String(s) => Some(s),
            _ => None,
        })
        .collect()
}

/// Runs a single-row scalar query and returns the one value of column `x`.
fn read_scalar(coord: &mut Coord, src: &str) -> Value {
    let plan = compile(src, &IndexCatalog::empty());
    let txn = coord.begin_serializable();
    let rows = run_plan(coord, txn, &plan);
    coord.commit(txn).expect("read commits");
    assert_eq!(rows.len(), 1, "expected exactly one row from {src}");
    rows[0].value("x")
}

fn plan_contains(plan: &PhysicalPlan, pred: &dyn Fn(&PhysicalOp) -> bool) -> bool {
    fn walk(op: &PhysicalOp, pred: &dyn Fn(&PhysicalOp) -> bool) -> bool {
        if pred(op) {
            return true;
        }
        children(op).iter().any(|c| walk(c, pred))
    }
    fn children(op: &PhysicalOp) -> Vec<&PhysicalOp> {
        match op {
            PhysicalOp::ExpandAll { input, .. }
            | PhysicalOp::ExpandInto { input, .. }
            | PhysicalOp::Filter { input, .. }
            | PhysicalOp::Projection { input, .. }
            | PhysicalOp::Aggregation { input, .. }
            | PhysicalOp::Sort { input, .. }
            | PhysicalOp::TopN { input, .. }
            | PhysicalOp::Skip { input, .. }
            | PhysicalOp::Limit { input, .. }
            | PhysicalOp::Unwind { input, .. }
            | PhysicalOp::Optional { input, .. }
            | PhysicalOp::Eager { input, .. } => vec![input],
            PhysicalOp::NestedLoopJoin { left, right }
            | PhysicalOp::HashJoin { left, right, .. }
            | PhysicalOp::Union { left, right, .. } => vec![left, right],
            _ => Vec::new(),
        }
    }
    walk(&plan.root, pred)
}

fn uses_index(plan: &PhysicalPlan) -> bool {
    plan_contains(plan, &|op| {
        matches!(
            op,
            PhysicalOp::NodeIndexSeek { .. }
                | PhysicalOp::NodeIndexRangeSeek { .. }
                | PhysicalOp::NodeIndexScan { .. }
        )
    })
}

/// The three-node fixture from the `rmp` #894 reproduction, straddling 2^53.
///
/// * `float-2^53`  → `Float(9007199254740992.0)` (2^53, exactly representable)
/// * `int-2^53`    → `Integer(9007199254740992)` (the *same* number as a Cypher `INTEGER`)
/// * `int-2^53+1`  → `Integer(9007199254740993)` (2^53+1, **not** representable as `f64`; it rounds
///   to 2^53, which is precisely why an `f64` coercion loses it)
fn seed(coord: &mut Coord) {
    run_write(
        coord,
        "CREATE (:T {tag: 'float-2^53', v: 9007199254740992.0})",
    );
    run_write(coord, "CREATE (:T {tag: 'int-2^53', v: 9007199254740992})");
    run_write(
        coord,
        "CREATE (:T {tag: 'int-2^53+1', v: 9007199254740993})",
    );
}

/// Seeds, then builds a `RANGE` index on `:T(v)` and returns the index-aware catalog.
fn seed_and_index(coord: &mut Coord) -> IndexCatalog {
    seed(coord);
    coord
        .create_node_property_index("T", "v")
        .expect("create index");
    coord.catalog()
}

/// The load-bearing assertion of `rmp` #894: `src` must return `expect` **whether or not** an index
/// is declared, and the indexed plan must genuinely use the index (otherwise the test would compare
/// the scan path against itself and prove nothing).
fn assert_index_and_scan_agree(src: &str, expect: &[&str]) {
    let mut coord = fresh_coord();
    let cat = seed_and_index(&mut coord);
    let empty = IndexCatalog::empty();

    let indexed_plan = compile(src, &cat);
    assert!(
        uses_index(&indexed_plan),
        "NON-VACUITY: the indexed plan for `{src}` must use an index operator, else this test \
         compares the scan path with itself:\n{indexed_plan}"
    );
    let scan_plan = compile(src, &empty);
    assert!(
        !uses_index(&scan_plan),
        "NON-VACUITY: the empty-catalog plan for `{src}` must NOT use an index:\n{scan_plan}"
    );

    let scanned = read_sorted_tags(&mut coord, &empty, src);
    let sought = read_sorted_tags(&mut coord, &cat, src);
    let want: Vec<String> = expect.iter().map(|s| (*s).to_owned()).collect();

    assert_eq!(
        scanned, want,
        "scan + Filter result for `{src}` must be the openCypher answer"
    );
    assert_eq!(
        sought, want,
        "index-seek result for `{src}` must be the openCypher answer"
    );
    assert_eq!(
        scanned, sought,
        "DECLARING AN INDEX CHANGED THE ANSWER for `{src}`"
    );
}

// =================================================================================================
// (1) The headline: `=` across INTEGER/FLOAT above 2^53
// =================================================================================================

/// `RETURN 9007199254740993 = 9007199254740992.0` must be **FALSE** (CIP §Numbers: unlimited
/// precision). Before `rmp` #894 the evaluator coerced the integer through `f64` and returned
/// `true`.
#[test]
fn mixed_equality_above_2_53_is_false() {
    let mut coord = fresh_coord();
    assert_eq!(
        read_scalar(
            &mut coord,
            "RETURN 9007199254740993 = 9007199254740992.0 AS x"
        ),
        Value::Boolean(false),
        "2^53+1 = 2^53.0 must be FALSE under unlimited precision"
    );
    // Symmetric, and the `<>` negation.
    assert_eq!(
        read_scalar(
            &mut coord,
            "RETURN 9007199254740992.0 = 9007199254740993 AS x"
        ),
        Value::Boolean(false)
    );
    assert_eq!(
        read_scalar(
            &mut coord,
            "RETURN 9007199254740993 <> 9007199254740992.0 AS x"
        ),
        Value::Boolean(true)
    );
    // The number that *is* 2^53 still compares equal across the two types.
    assert_eq!(
        read_scalar(
            &mut coord,
            "RETURN 9007199254740992 = 9007199254740992.0 AS x"
        ),
        Value::Boolean(true),
        "2^53 IS exactly representable, so INTEGER 2^53 = FLOAT 2^53.0"
    );
    // Negative side, same construction.
    assert_eq!(
        read_scalar(
            &mut coord,
            "RETURN -9007199254740993 = -9007199254740992.0 AS x"
        ),
        Value::Boolean(false)
    );
    assert_eq!(
        read_scalar(
            &mut coord,
            "RETURN -9007199254740992 = -9007199254740992.0 AS x"
        ),
        Value::Boolean(true)
    );
}

/// **Regression, TCK `Comparison1 [9]`**: the ordinary small-magnitude cross-type equality
/// `1 = 1.0` is `true` and must stay `true` — the fix must not "correct" the exact-`f64` domain.
#[test]
fn small_magnitude_cross_type_equality_is_unaffected() {
    let mut coord = fresh_coord();
    for (q, want) in [
        ("RETURN 1 = 1.0 AS x", true),
        ("RETURN 1.0 = 1 AS x", true),
        ("RETURN 0 = -0.0 AS x", true),
        ("RETURN -0.0 = 0 AS x", true),
        ("RETURN 2 = 2.0 AS x", true),
        ("RETURN 1 = 1.5 AS x", false),
        ("RETURN 3 = 2.0 AS x", false),
    ] {
        assert_eq!(
            read_scalar(&mut coord, q),
            Value::Boolean(want),
            "`{q}` must be {want}"
        );
    }
}

/// The reproduction from the `rmp` #894 report, verbatim: a row disappeared when you
/// `CREATE INDEX`. Without the index the scan's `=` (an `f64` coercion) matched `float-2^53` too;
/// with the index the seek's exact key did not. Both sides must now return exactly `int-2^53+1`.
#[test]
fn equality_seek_and_scan_agree_above_2_53() {
    assert_index_and_scan_agree(
        "MATCH (t:T) WHERE t.v = 9007199254740993 RETURN t.tag AS tag",
        &["int-2^53+1"],
    );
}

/// The float side of the same predicate: `= 9007199254740992.0` matches the two values that really
/// *are* 2^53 (the `FLOAT` and the `INTEGER`), and never the distinct 2^53+1.
#[test]
fn equality_seek_and_scan_agree_on_the_float_side() {
    assert_index_and_scan_agree(
        "MATCH (t:T) WHERE t.v = 9007199254740992.0 RETURN t.tag AS tag",
        &["float-2^53", "int-2^53"],
    );
}

// =================================================================================================
// (2) Ranges — the same divergence in the `<` / `<=` / `>` / `>=` direction
// =================================================================================================

/// `< 2^53+1`: the two values that are 2^53 satisfy it, `2^53+1` itself does not.
///
/// This is the **candidate-superset** direction. The index's order-preserving key folds an `i64`
/// onto the `f64` magnitude line, so `Integer(2^53+1)`, `Integer(2^53)` and `Float(2^53)` all share
/// one magnitude; an exclusive upper bound cut at that magnitude drops rows the scan keeps.
#[test]
fn range_lt_seek_and_scan_agree_above_2_53() {
    assert_index_and_scan_agree(
        "MATCH (t:T) WHERE t.v < 9007199254740993 RETURN t.tag AS tag",
        &["float-2^53", "int-2^53"],
    );
}

/// `<= 2^53.0`: only the values that really are 2^53 — `2^53+1` is strictly greater.
#[test]
fn range_lte_seek_and_scan_agree_above_2_53() {
    assert_index_and_scan_agree(
        "MATCH (t:T) WHERE t.v <= 9007199254740992.0 RETURN t.tag AS tag",
        &["float-2^53", "int-2^53"],
    );
}

/// `> 2^53.0`: only `2^53+1`, which an `f64` coercion would have reported as *equal* (and therefore
/// not greater).
#[test]
fn range_gt_seek_and_scan_agree_above_2_53() {
    assert_index_and_scan_agree(
        "MATCH (t:T) WHERE t.v > 9007199254740992.0 RETURN t.tag AS tag",
        &["int-2^53+1"],
    );
}

/// `>= 2^53+1`: only `2^53+1`.
#[test]
fn range_gte_seek_and_scan_agree_above_2_53() {
    assert_index_and_scan_agree(
        "MATCH (t:T) WHERE t.v >= 9007199254740993 RETURN t.tag AS tag",
        &["int-2^53+1"],
    );
}

/// A **two-sided** range, where the second bound is applied as a residual `Filter` above the seek.
///
/// What this proves is the *answer*: `Float(2^53.0)` now satisfies `< 9007199254740993`, because the
/// two are different numbers — before `rmp` #894 the residual `Filter` compared them through `f64`,
/// called them equal, and dropped the row. It does **not** exercise the seam's exclusive-upper-key
/// widening: the physical planner emits one bound per `NodeIndexRangeSeek`
/// (`NodeIndexRangeSeek(t:T v > …)` + `Filter(t.v < …)`), so the seek's `upper` is always `None`
/// here. That widening is pinned directly at the seam, in `index_set`'s
/// `two_sided_range_upper_bound_keeps_the_candidate_superset_above_2_53`.
#[test]
fn two_sided_range_keeps_a_float_below_a_large_integer_bound() {
    let mut coord = fresh_coord();
    let cat = seed_and_index(&mut coord);
    let empty = IndexCatalog::empty();
    let src = "MATCH (t:T) WHERE t.v > 9007199254740000 AND t.v < 9007199254740993 \
               RETURN t.tag AS tag";

    let indexed_plan = compile(src, &cat);
    assert!(
        uses_index(&indexed_plan),
        "NON-VACUITY: the indexed plan must use an index:\n{indexed_plan}"
    );

    let want = vec!["float-2^53".to_owned(), "int-2^53".to_owned()];
    assert_eq!(read_sorted_tags(&mut coord, &empty, src), want);
    assert_eq!(
        read_sorted_tags(&mut coord, &cat, src),
        want,
        "DECLARING AN INDEX CHANGED THE ANSWER for a two-sided range"
    );
}

/// A non-regression guard, not evidence: ordinary small-magnitude bounds are entirely unaffected by
/// `rmp` #894 (this test passes before and after), and it is here to catch a fix that over-reached
/// into the exact-`f64` domain.
#[test]
fn ordinary_magnitude_ranges_are_unaffected() {
    let mut coord = fresh_coord();
    for v in 1..=20 {
        run_write(&mut coord, &format!("CREATE (:W {{tag: 'n{v}', v: {v}}})"));
    }
    coord
        .create_node_property_index("W", "v")
        .expect("create index");
    let cat = coord.catalog();
    let empty = IndexCatalog::empty();
    let src = "MATCH (w:W) WHERE w.v >= 5 AND w.v < 9 RETURN w.tag AS tag";

    assert!(
        uses_index(&compile(src, &cat)),
        "NON-VACUITY: the indexed plan must use an index"
    );
    let want = vec![
        "n5".to_owned(),
        "n6".to_owned(),
        "n7".to_owned(),
        "n8".to_owned(),
    ];
    assert_eq!(read_sorted_tags(&mut coord, &empty, src), want);
    assert_eq!(read_sorted_tags(&mut coord, &cat, src), want);
}

// =================================================================================================
// (3) equivalence (DISTINCT / grouping) and ordering (ORDER BY) agree with equality
// =================================================================================================

/// `DISTINCT` groups by Cypher **equivalence**, which must agree with `=` on these pairs: the
/// `FLOAT` 2^53 and the `INTEGER` 2^53 are one group; `2^53+1` is its own.
#[test]
fn distinct_separates_2_53_from_2_53_plus_1() {
    let mut coord = fresh_coord();
    seed(&mut coord);
    let plan = compile(
        "MATCH (t:T) RETURN DISTINCT t.v AS x",
        &IndexCatalog::empty(),
    );
    let txn = coord.begin_serializable();
    let rows = run_plan(&coord, txn, &plan);
    coord.commit(txn).expect("read commits");
    assert_eq!(
        rows.len(),
        2,
        "2^53 (as FLOAT and as INTEGER) is one group and 2^53+1 is another; got {:?}",
        rows.iter().map(|r| r.value("x")).collect::<Vec<_>>()
    );
}

/// `ORDER BY` uses Cypher **orderability**, which must place `2^53+1` strictly *after* both
/// spellings of 2^53. The two spellings of 2^53 are numerically equal, so the `INTEGER`-before-
/// `FLOAT` tie-break decides between them.
#[test]
fn order_by_places_2_53_plus_1_last() {
    let mut coord = fresh_coord();
    seed(&mut coord);
    assert_eq!(
        read_tags_in_order(
            &mut coord,
            &IndexCatalog::empty(),
            "MATCH (t:T) RETURN t.tag AS tag ORDER BY t.v, t.tag"
        ),
        vec![
            "int-2^53".to_owned(),
            "float-2^53".to_owned(),
            "int-2^53+1".to_owned()
        ],
        "2^53+1 is the largest of the three"
    );
}

/// The three relations must not contradict one another for the same pair: if `a = b` is `false`
/// then exactly one of `a < b` / `a > b` is `true`, and `DISTINCT` must keep them apart.
#[test]
fn equality_ordering_and_equivalence_agree_across_magnitudes() {
    let mut coord = fresh_coord();
    // (left, right, eq, lt, gt) at and around 2^53, both signs, both spellings.
    let cases: &[(&str, &str, bool, bool, bool)] = &[
        // 2^53+1 vs 2^53.0 — the reported pair.
        ("9007199254740993", "9007199254740992.0", false, false, true),
        // 2^53 vs 2^53.0 — exactly representable, genuinely equal.
        ("9007199254740992", "9007199254740992.0", true, false, false),
        // 2^53-1 vs 2^53.0.
        ("9007199254740991", "9007199254740992.0", false, true, false),
        // The whole-number float just above 2^53 is 2^53+2; 2^53+1 sits strictly between.
        ("9007199254740993", "9007199254740994.0", false, true, false),
        // Negatives mirror exactly.
        (
            "-9007199254740993",
            "-9007199254740992.0",
            false,
            true,
            false,
        ),
        (
            "-9007199254740993",
            "-9007199254740994.0",
            false,
            false,
            true,
        ),
        // i64::MAX against the f64 it rounds to (2^63), which is *larger* than any i64.
        (
            "9223372036854775807",
            "9223372036854775808.0",
            false,
            true,
            false,
        ),
        // i64::MIN is exactly -2^63 and the float -2^63 is the same number.
        (
            "-9223372036854775808",
            "-9223372036854775808.0",
            true,
            false,
            false,
        ),
        // Small magnitudes are unchanged.
        ("1", "1.0", true, false, false),
        ("1", "1.5", false, true, false),
    ];
    for &(l, r, eq, lt, gt) in cases {
        assert_eq!(
            read_scalar(&mut coord, &format!("RETURN {l} = {r} AS x")),
            Value::Boolean(eq),
            "`{l} = {r}`"
        );
        assert_eq!(
            read_scalar(&mut coord, &format!("RETURN {l} < {r} AS x")),
            Value::Boolean(lt),
            "`{l} < {r}`"
        );
        assert_eq!(
            read_scalar(&mut coord, &format!("RETURN {l} > {r} AS x")),
            Value::Boolean(gt),
            "`{l} > {r}`"
        );
        // `<=` / `>=` are the union of the strict relation with equality — a coherence check that
        // catches a fix applied to `=` but not to the ordering path (or vice versa).
        assert_eq!(
            read_scalar(&mut coord, &format!("RETURN {l} <= {r} AS x")),
            Value::Boolean(lt || eq),
            "`{l} <= {r}`"
        );
        assert_eq!(
            read_scalar(&mut coord, &format!("RETURN {l} >= {r} AS x")),
            Value::Boolean(gt || eq),
            "`{l} >= {r}`"
        );
        // Exactly one of the three relations holds (totality + antisymmetry of the numeric order).
        assert_eq!(
            u8::from(eq) + u8::from(lt) + u8::from(gt),
            1,
            "the fixture for `{l}` vs `{r}` must state exactly one of =, <, >"
        );
    }
}

/// `NaN` and the Infinities are excluded by the CIP sentence itself, and their behaviour must not
/// change: `NaN` is never equal to anything (not even itself), and every comparison against it is
/// `false`; `±Infinity` compares as the extremes.
#[test]
fn nan_and_infinities_are_unchanged() {
    let mut coord = fresh_coord();
    for (q, want) in [
        // NaN under `=` is always false (CIP §Equality), including against a large integer.
        ("RETURN 0.0/0.0 = 0.0/0.0 AS x", false),
        ("RETURN 9007199254740993 = 0.0/0.0 AS x", false),
        ("RETURN 9007199254740993 <> 0.0/0.0 AS x", true),
        // NaN vs a number under the inequality operators is FALSE (TCK `Comparison2 [5]`).
        ("RETURN 9007199254740993 < 0.0/0.0 AS x", false),
        ("RETURN 9007199254740993 > 0.0/0.0 AS x", false),
        // The Infinities are the extremes of the numeric line, for a large integer too.
        ("RETURN 9223372036854775807 < 1.0/0.0 AS x", true),
        ("RETURN 9223372036854775807 > -1.0/0.0 AS x", true),
        ("RETURN 9223372036854775807 = 1.0/0.0 AS x", false),
        ("RETURN -9223372036854775808 > -1.0/0.0 AS x", true),
    ] {
        assert_eq!(
            read_scalar(&mut coord, q),
            Value::Boolean(want),
            "`{q}` must be {want}"
        );
    }
}
