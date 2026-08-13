//! End-to-end index-wiring tests for the Cypher engine over the real store (`rmp` task #48, EPIC
//! #16): label scans and node-property predicates are answered from the coordinator's derived
//! [`IndexSet`] and must return **exactly** the scan-and-filter result.
//!
//! The overriding correctness property every test here asserts is *equivalence*: a query planned
//! against [`TxnCoordinator::catalog`] (the index-aware path — proven to actually use a
//! `NodeIndexSeek` / `NodeIndexRangeSeek` / `TokenLookupScan`) returns the same rows, **as a set**,
//! as the same query planned against [`IndexCatalog::empty`] (the scan + residual-filter path). This
//! holds under MVCC deletes (stale index entries must be dropped by the re-check) and across a
//! crash + recovery (a fresh coordinator rebuilds a store-consistent index).
//!
//! The harness mirrors `tests/ssi.rs` / `tests/crash_concurrency.rs` (a `TxnCoordinator` over an
//! in-memory store) and `tests/physical_planner.rs` (structural assertions on the [`PhysicalOp`]
//! tree).

use graphus_core::Value;
use graphus_cypher::binding::{Parameters, bind_parameters};
use graphus_cypher::catalog::IndexCatalog;
use graphus_cypher::coordinator::TxnCoordinator;
use graphus_cypher::executor::execute;
use graphus_cypher::graph_access::{GraphAccess, KeyValues};
use graphus_cypher::lexer::tokenize;
use graphus_cypher::lower::lower;
use graphus_cypher::parser::parse_tokens;
use graphus_cypher::physical::{PhysicalOp, PhysicalPlan, plan_physical};
use graphus_cypher::runtime::Row;
use graphus_cypher::semantics::analyze;
use graphus_io::MemBlockDevice;
use graphus_storage::RecordStore;
use graphus_storage::recovery::recover_device;
use graphus_wal::{LogSink, MemLogSink, WalManager};

type Store = RecordStore<MemBlockDevice, MemLogSink>;
type Coord = TxnCoordinator<MemBlockDevice, MemLogSink>;

// =================================================================================================
// Harness
// =================================================================================================

fn fresh_store() -> Store {
    let device = MemBlockDevice::new(0);
    let wal = WalManager::create(MemLogSink::new()).expect("create wal");
    RecordStore::create(device, wal, 64, 1).expect("create store")
}

fn fresh_coord() -> Coord {
    TxnCoordinator::new(fresh_store())
}

/// Compiles `src` to a physical plan against `catalog`.
fn compile(src: &str, catalog: &IndexCatalog) -> PhysicalPlan {
    let toks = tokenize(src).expect("lex");
    let ast = parse_tokens(&toks, src).expect("parse");
    let validated = analyze(&ast).expect("analyze");
    plan_physical(&lower(&validated), catalog)
}

/// Runs one statement of `txn` over the coordinator with a pre-built plan, returning its rows. The
/// per-statement seam is dropped before returning, so the transaction stays open without borrowing
/// the store. Panics if the statement captured a deferred / storage error.
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

/// Runs `src` (compiled against `catalog`) in a fresh committed read transaction, returning the
/// integer values of result column `col`, sorted (so result-sets can be compared as sets).
fn read_sorted_ints(coord: &mut Coord, catalog: &IndexCatalog, src: &str, col: &str) -> Vec<i64> {
    let plan = compile(src, catalog);
    let txn = coord.begin_serializable();
    let rows = run_plan(coord, txn, &plan);
    coord.commit(txn).expect("read commits");
    let mut vs: Vec<i64> = rows
        .iter()
        .filter_map(|r| match r.value(col) {
            Value::Integer(k) => Some(k),
            _ => None,
        })
        .collect();
    vs.sort_unstable();
    vs
}

/// Runs `src` in its own committed write transaction (a setup / mutation helper).
fn run_write(coord: &mut Coord, src: &str) {
    let plan = compile(src, &IndexCatalog::empty());
    let txn = coord.begin_serializable();
    let _rows = run_plan(coord, txn, &plan);
    coord.commit(txn).expect("write commits");
}

/// Walks the physical tree, returning whether any operator satisfies `pred` (pre-order).
fn plan_contains(plan: &PhysicalPlan, pred: &dyn Fn(&PhysicalOp) -> bool) -> bool {
    fn walk(op: &PhysicalOp, pred: &dyn Fn(&PhysicalOp) -> bool) -> bool {
        if pred(op) {
            return true;
        }
        children(op).iter().any(|c| walk(c, pred))
    }
    walk(&plan.root, pred)
}

/// The child operators of `op` (for the generic walker) — the subset relevant to these read plans.
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
        | PhysicalOp::Eager { input, .. }
        | PhysicalOp::Create { input, .. }
        | PhysicalOp::Merge { input, .. }
        | PhysicalOp::SetClause { input, .. }
        | PhysicalOp::Delete { input, .. }
        | PhysicalOp::Remove { input, .. } => vec![input],
        PhysicalOp::NestedLoopJoin { left, right }
        | PhysicalOp::HashJoin { left, right, .. }
        | PhysicalOp::Union { left, right, .. } => vec![left, right],
        PhysicalOp::ProcedureCall { input, .. } => input.iter().map(Box::as_ref).collect(),
        _ => Vec::new(),
    }
}

fn has_index_seek(plan: &PhysicalPlan) -> bool {
    plan_contains(plan, &|op| matches!(op, PhysicalOp::NodeIndexSeek { .. }))
}

fn has_index_range_seek(plan: &PhysicalPlan) -> bool {
    plan_contains(plan, &|op| {
        matches!(op, PhysicalOp::NodeIndexRangeSeek { .. })
    })
}

fn has_token_lookup(plan: &PhysicalPlan) -> bool {
    plan_contains(plan, &|op| matches!(op, PhysicalOp::TokenLookupScan { .. }))
}

fn has_index_scan(plan: &PhysicalPlan) -> bool {
    plan_contains(plan, &|op| matches!(op, PhysicalOp::NodeIndexScan { .. }))
}

fn has_sort(plan: &PhysicalPlan) -> bool {
    plan_contains(plan, &|op| matches!(op, PhysicalOp::Sort { .. }))
}

/// Runs `src` in a fresh committed read transaction, returning the integer values of result column
/// `col` **in result order** (unlike [`read_sorted_ints`], which sorts). Used to assert `ORDER BY`
/// output order across the Sort-elided and Sort-kept plans.
fn read_ints_in_order(coord: &mut Coord, catalog: &IndexCatalog, src: &str, col: &str) -> Vec<i64> {
    let plan = compile(src, catalog);
    let txn = coord.begin_serializable();
    let rows = run_plan(coord, txn, &plan);
    coord.commit(txn).expect("read commits");
    rows.iter()
        .filter_map(|r| match r.value(col) {
            Value::Integer(k) => Some(k),
            _ => None,
        })
        .collect()
}

/// Seeds a representative graph: many `(:Person {age: N})` with consistent integer ages, a few
/// `:Person` with no `age`, and a few non-`Person` nodes (which must never leak into a `:Person`
/// result whether scanned or sought).
fn seed_people(coord: &mut Coord) {
    // Ages 20..=40 inclusive — a dense integer column with duplicates at 30 (two people).
    for age in 20..=40 {
        run_write(coord, &format!("CREATE (:Person {{age: {age}}})"));
    }
    run_write(coord, "CREATE (:Person {age: 30})"); // a second person aged 30 (duplicate value)
    run_write(coord, "CREATE (:Person {name: 'no-age-1'})"); // Person without `age`
    run_write(coord, "CREATE (:Person {name: 'no-age-2'})"); // Person without `age`
    run_write(coord, "CREATE (:Company {age: 30})"); // non-Person carrying `age` 30 (must not match)
    run_write(coord, "CREATE (:Company {founded: 1999})"); // unrelated non-Person
}

// =================================================================================================
// SSI: an indexed equality seek must not over-abort disjoint-key writers (rmp #316)
// =================================================================================================

/// Two SERIALIZABLE transactions that each seek a DIFFERENT indexed key and write only that node
/// are genuinely independent and MUST both commit. Before `rmp` #316, `index_seek_eq` SIREAD-marked
/// **every live node** (mirroring the scan fallback), so each writer manufactured an rw-edge with
/// the other's unrelated write — reciprocal edges made both transactions pivots and one aborted with
/// a spurious serialization failure (the measured fraud-oltp abort storm). With the precise
/// per-candidate SIREAD + `Equality` predicate marker, no false rw-edge forms, while a real
/// conflict (same key, or an insert/update *into* the sought predicate) is still caught — proven by
/// the unchanged write-skew / serializability batteries.
#[test]
fn disjoint_indexed_equality_writers_both_commit_no_false_abort() {
    let mut coord = fresh_coord();
    run_write(
        &mut coord,
        "CREATE (:Account {id: 1, bal: 100}), (:Account {id: 2, bal: 100})",
    );
    coord
        .create_node_property_index("Account", "id")
        .expect("create index");
    let cat = coord.catalog();

    let p1 = compile("MATCH (a:Account {id: 1}) SET a.bal = 1", &cat);
    let p2 = compile("MATCH (a:Account {id: 2}) SET a.bal = 2", &cat);
    // Guard: both writes must take the index path (else this would test the scan path instead).
    assert!(
        has_index_seek(&p1) && has_index_seek(&p2),
        "both write plans must use a NodeIndexSeek:\n{p1}\n{p2}"
    );

    let t1 = coord.begin_serializable();
    let t2 = coord.begin_serializable();
    // Each transaction touches only its own distinct, indexed node — no real dependency between them.
    run_plan(&coord, t1, &p1);
    run_plan(&coord, t2, &p2);
    // Both independent transactions commit. Pre-#316, one aborted here with a false serialization
    // failure because of the blanket all-nodes SIREAD.
    coord.commit(t1).expect("t1 (account 1) commits");
    coord
        .commit(t2)
        .expect("t2 (account 2) commits — disjoint indexed key, no false abort");

    // Both writes took effect (serializable, and neither was lost to a spurious abort).
    assert_eq!(
        read_sorted_ints(
            &mut coord,
            &cat,
            "MATCH (a:Account) RETURN a.bal AS bal",
            "bal"
        ),
        vec![1, 2],
        "both disjoint writes committed and are visible"
    );
}

// =================================================================================================
// Equivalence: index path == scan+filter path, with the index actually used
// =================================================================================================

#[test]
fn equality_seek_equals_scan_filter_and_uses_node_index_seek() {
    let mut coord = fresh_coord();
    seed_people(&mut coord);
    coord
        .create_node_property_index("Person", "age")
        .expect("create index");

    let src = "MATCH (n:Person) WHERE n.age = 30 RETURN n.age AS a";
    let indexed = coord.catalog();

    // The index-aware plan must actually contain a NodeIndexSeek (otherwise we would only be
    // re-testing the scan path against itself).
    let plan = compile(src, &indexed);
    assert!(
        has_index_seek(&plan),
        "the index-aware plan must use a NodeIndexSeek:\n{plan}"
    );

    let via_index = read_sorted_ints(&mut coord, &indexed, src, "a");
    let via_scan = read_sorted_ints(&mut coord, &IndexCatalog::empty(), src, "a");

    // Two Persons are aged exactly 30 (and the Company aged 30 must NOT appear).
    assert_eq!(via_index, vec![30, 30], "index result");
    assert_eq!(
        via_index, via_scan,
        "index seek must equal scan+filter (eq)"
    );
}

#[test]
fn range_seek_equals_scan_filter_and_uses_node_index_range_seek() {
    let mut coord = fresh_coord();
    seed_people(&mut coord);
    coord
        .create_node_property_index("Person", "age")
        .expect("create index");

    let src = "MATCH (n:Person) WHERE n.age > 30 RETURN n.age AS a";
    let indexed = coord.catalog();

    let plan = compile(src, &indexed);
    assert!(
        has_index_range_seek(&plan),
        "the index-aware plan must use a NodeIndexRangeSeek:\n{plan}"
    );

    let via_index = read_sorted_ints(&mut coord, &indexed, src, "a");
    let via_scan = read_sorted_ints(&mut coord, &IndexCatalog::empty(), src, "a");

    // Strictly > 30: ages 31..=40 (the two 30s are excluded).
    assert_eq!(via_index, (31..=40).collect::<Vec<_>>(), "index result");
    assert_eq!(
        via_index, via_scan,
        "index range seek must equal scan+filter (range)"
    );
}

// =================================================================================================
// rmp #665: existence (IS NOT NULL) index scan + ORDER BY served by the index, over the real store
// =================================================================================================

/// **REGRESSION (`rmp` task #879, found while certifying it).** A property column that holds a value
/// the index key codec cannot encode — a `List` — makes the derived tree a **strict subset** of the
/// nodes carrying the property, and the whole-index existence scan then silently loses those rows.
///
/// Measured against the code before the fix, on three `:T` nodes with `v` set to `1`, `[1, 2, 3]` and
/// `'abc'`: `MATCH (n:T) WHERE n.v IS NOT NULL` returned **3** rows through the label scan and **2**
/// through `NodeIndexScan`. **Declaring an index changed the answer**, and the lost row was committed
/// data — the `rmp` #680 / #738 / #894 defect class.
///
/// The mechanism: `IndexSet::insert_node_property` did `let _ = np.index.insert(...)`, discarding the
/// `KeyEncodeError::Unindexable` a `List` raises. Skipping a `Null` there is correct (a null property
/// is *absent* for index purposes); skipping a present value is not. The fix records the refusal and
/// declines the **unbounded** range seek — and only that one, since a bounded seek can never match a
/// `List` and so has no row to lose.
#[test]
fn a_list_valued_property_does_not_disappear_from_the_existence_scan_879() {
    let mut coord = fresh_coord();
    run_write(&mut coord, "CREATE (:T {v: 1})");
    run_write(&mut coord, "CREATE (:T {v: [1, 2, 3]})");
    run_write(&mut coord, "CREATE (:T {v: 'abc'})");
    coord
        .create_node_property_index("T", "v")
        .expect("create index");

    let src = "MATCH (n:T) WHERE n.v IS NOT NULL RETURN n.v AS a";
    let indexed = coord.catalog();
    // Non-vacuity: the planner really does choose the index access path for this shape, so the run
    // below exercises the code the bug lived in (the seam declines at RUN time, not at plan time).
    assert!(
        has_index_scan(&compile(src, &indexed)),
        "the index-aware plan must still choose NodeIndexScan for this shape"
    );

    let via_index = read_rows(&mut coord, &indexed, src);
    let via_scan = read_rows(&mut coord, &IndexCatalog::empty(), src);
    assert_eq!(
        via_index.len(),
        3,
        "all three committed rows must survive (was 2 before the fix)"
    );
    assert_eq!(
        sorted_debug(&via_index),
        sorted_debug(&via_scan),
        "declaring an index must not change the answer"
    );

    // The BOUNDED seeks are unaffected and must keep using the index: a `List` matches no cross-type
    // comparison, so there is no row for them to lose and no reason to give up the access path.
    for bounded in [
        "MATCH (n:T) WHERE n.v > 0 RETURN n.v AS a",
        "MATCH (n:T) WHERE n.v = 1 RETURN n.v AS a",
    ] {
        assert_eq!(
            sorted_debug(&read_rows(&mut coord, &indexed, bounded)),
            sorted_debug(&read_rows(&mut coord, &IndexCatalog::empty(), bounded)),
            "{bounded}: the bounded path must still agree with the scan"
        );
    }
}

/// Runs `src` and returns its rows (a small helper for the `rmp` #879 regression above).
fn read_rows(coord: &mut Coord, catalog: &IndexCatalog, src: &str) -> Vec<Row> {
    let plan = compile(src, catalog);
    let bound = bind_parameters(&plan, &Parameters::new()).expect("bind");
    let txn = coord.begin_serializable();
    let rows = {
        let mut graph = coord.statement(txn).expect("statement");
        let mut cursor = execute(&plan, &bound, &mut graph).expect("open cursor");
        cursor.collect_all().expect("collect")
    };
    coord.commit(txn).expect("read commits");
    rows
}

/// A deterministic, order-independent rendering of a row bag for comparison.
fn sorted_debug(rows: &[Row]) -> Vec<String> {
    let mut out: Vec<String> = rows.iter().map(|r| format!("{:?}", r.values())).collect();
    out.sort();
    out
}

#[test]
fn existence_scan_equals_scan_filter_and_uses_node_index_scan() {
    // `rmp` task #665 (A): `IS NOT NULL` over an indexed property is served by a `NodeIndexScan` (a
    // full index scan) and must return exactly the scan+filter result — including under a delete that
    // leaves a stale index entry the re-check must drop.
    let mut coord = fresh_coord();
    seed_people(&mut coord);
    coord
        .create_node_property_index("Person", "age")
        .expect("create index");

    let src = "MATCH (n:Person) WHERE n.age IS NOT NULL RETURN n.age AS a";
    let indexed = coord.catalog();

    let plan = compile(src, &indexed);
    assert!(
        has_index_scan(&plan),
        "the index-aware plan must use a NodeIndexScan:\n{plan}"
    );

    let via_index = read_sorted_ints(&mut coord, &indexed, src, "a");
    let via_scan = read_sorted_ints(&mut coord, &IndexCatalog::empty(), src, "a");
    assert_eq!(
        via_index, via_scan,
        "existence index scan must equal scan+filter"
    );
    // Every Person carrying an age (20..=40 plus the duplicate 30); the two no-age Persons and the
    // Company aged 30 must not appear.
    let mut expected: Vec<i64> = (20..=40).collect();
    expected.push(30);
    expected.sort_unstable();
    assert_eq!(via_index, expected, "exactly the age-bearing Persons");

    // Delete an age-40 Person: its index entry lingers (stale) until GC, but the candidate re-check
    // drops the now-invisible node — both paths still agree, and 40 is gone.
    run_write(&mut coord, "MATCH (n:Person) WHERE n.age = 40 DELETE n");
    let via_index2 = read_sorted_ints(&mut coord, &indexed, src, "a");
    let via_scan2 = read_sorted_ints(&mut coord, &IndexCatalog::empty(), src, "a");
    assert_eq!(
        via_index2, via_scan2,
        "still equal after the delete leaves a stale index entry"
    );
    assert!(
        !via_index2.contains(&40),
        "the deleted node must not leak through the stale index entry:\n{via_index2:?}"
    );
}

#[test]
fn order_by_indexed_key_elides_sort_and_matches_sorted_scan_over_real_store() {
    // `rmp` task #665 (B): an `ORDER BY` on the range-seek key is served by the index order, so the
    // planner elides the `Sort`. The elided plan must produce the SAME ordered rows as the Sort-kept
    // (unindexed) plan — including duplicate values and a value updated mid-life (which leaves a stale
    // index entry under the OLD value; the ordered scan must re-read the CURRENT value).
    let mut coord = fresh_coord();
    for (age, tag) in [(30, "a"), (10, "b"), (20, "c"), (10, "d"), (30, "e")] {
        run_write(
            &mut coord,
            &format!("CREATE (:P {{age: {age}, tag: '{tag}'}})"),
        );
    }
    coord
        .create_node_property_index("P", "age")
        .expect("create index");
    let indexed = coord.catalog();

    let src = "MATCH (n:P) WHERE n.age > 0 RETURN n.age AS a ORDER BY n.age";

    // The index-aware plan uses an ordered range seek and DROPS the Sort; the unindexed plan keeps it.
    let plan = compile(src, &indexed);
    assert!(
        has_index_range_seek(&plan),
        "the index-aware plan must use a NodeIndexRangeSeek:\n{plan}"
    );
    assert!(
        !has_sort(&plan),
        "the Sort over the ordered range seek must be elided:\n{plan}"
    );
    assert!(
        has_sort(&compile(src, &IndexCatalog::empty())),
        "the unindexed plan must keep its Sort"
    );

    let via_index = read_ints_in_order(&mut coord, &indexed, src, "a");
    let via_scan = read_ints_in_order(&mut coord, &IndexCatalog::empty(), src, "a");
    assert_eq!(
        via_index, via_scan,
        "eliding the Sort must yield the identical ordered rows"
    );
    assert_eq!(
        via_index,
        vec![10, 10, 20, 30, 30],
        "ascending by age, duplicates preserved"
    );

    // Update one age-30 node to age 5 (now the smallest). The old value 30's index entry lingers as a
    // stale entry until GC; the ordered index scan must re-read the live value (5) and order by it.
    run_write(&mut coord, "MATCH (n:P) WHERE n.tag = 'a' SET n.age = 5");
    let via_index2 = read_ints_in_order(&mut coord, &indexed, src, "a");
    let via_scan2 = read_ints_in_order(&mut coord, &IndexCatalog::empty(), src, "a");
    assert_eq!(
        via_index2, via_scan2,
        "the elided order must track the update like the Sort (no stale value leaks)"
    );
    assert_eq!(
        via_index2,
        vec![5, 10, 10, 20, 30],
        "the updated node sorts first by its NEW value, exactly once"
    );
}

#[test]
fn range_seek_inclusive_and_open_lower_equal_scan_filter() {
    // Exercise both an inclusive bound and a `<` (open-below) bound, the cases `IndexSet` widens to
    // a superset internally — the re-check must still land on exactly the scan result.
    let mut coord = fresh_coord();
    seed_people(&mut coord);
    coord
        .create_node_property_index("Person", "age")
        .expect("create index");

    for src in [
        "MATCH (n:Person) WHERE n.age >= 30 RETURN n.age AS a", // inclusive lower (widened internally)
        "MATCH (n:Person) WHERE n.age <= 22 RETURN n.age AS a", // inclusive upper (widened internally)
        "MATCH (n:Person) WHERE n.age < 23 RETURN n.age AS a", // open below (whole-column superset)
    ] {
        let indexed = coord.catalog();
        let plan = compile(src, &indexed);
        assert!(
            has_index_range_seek(&plan),
            "`{src}` must use a NodeIndexRangeSeek:\n{plan}"
        );
        let via_index = read_sorted_ints(&mut coord, &indexed, src, "a");
        let via_scan = read_sorted_ints(&mut coord, &IndexCatalog::empty(), src, "a");
        assert_eq!(via_index, via_scan, "`{src}`: index must equal scan+filter");
    }
}

// =================================================================================================
// STARTS WITH: the string-prefix seek == scan+filter, with the index actually used (rmp #658)
// =================================================================================================

fn has_starts_with_seek(plan: &PhysicalPlan) -> bool {
    plan_contains(plan, &|op| {
        matches!(op, PhysicalOp::NodeIndexStartsWithSeek { .. })
    })
}

/// Seeds a `(:Word {id, name})` corpus with ASCII, Unicode, empty-string, missing, mixed-type
/// (numeric `name`) and other-label rows — the full matrix the string-prefix seek must serve
/// identically to a scan + `STARTS WITH` filter. Each node carries a unique integer `id` so result
/// sets compare as sorted id lists.
fn seed_words(coord: &mut Coord) {
    for (id, name) in [
        (1, "alpha"),
        (2, "alpine"),
        (3, "beta"),
        (4, "az"),
        (5, "a"),
        (6, "café"),  // U+00E9
        (7, "cafe"),  // ASCII 'e'
        (8, "cafés"), // 'café' is a prefix of this
        (9, "CAFÉ"),  // uppercase — different code points, must not match 'caf'
        (10, "naïve"),
        (11, ""), // empty-string name: matches STARTS WITH '' only
    ] {
        run_write(
            coord,
            &format!("CREATE (:Word {{id: {id}, name: '{name}'}})"),
        );
    }
    // A mixed-type row: `name` is a NUMBER. Every `STARTS WITH` must evaluate to null for it, so it
    // must never appear — the retained residual filter is what rejects it (the index band excludes it
    // for a bounded range, but the empty-prefix open-upper range admits it as a candidate).
    run_write(coord, "CREATE (:Word {id: 12, name: 42})");
    // A row with no `name` at all (null) — never matches any string predicate.
    run_write(coord, "CREATE (:Word {id: 13})");
    // A different label carrying a would-be-matching name — must not leak into `:Word` results.
    run_write(coord, "CREATE (:Other {id: 14, name: 'alpha'})");
}

#[test]
fn starts_with_seek_equals_scan_filter_and_uses_prefix_seek() {
    let mut coord = fresh_coord();
    seed_words(&mut coord);
    coord
        .create_node_property_index("Word", "name")
        .expect("create index");
    let indexed = coord.catalog();

    // (query, expected matching ids) — covers ASCII prefixes, a single-char prefix, Unicode prefixes
    // (multi-byte last scalar), an exact-length and a prefix-of relationship, the empty prefix
    // (matches every STRING name but not the numeric/null/other-label rows), a no-match prefix, and a
    // prefix longer than any value.
    let cases: &[(&str, &[i64])] = &[
        ("'al'", &[1, 2]),
        ("'a'", &[1, 2, 4, 5]),
        ("'caf'", &[6, 7, 8]),   // not CAFÉ (id 9): 'C' != 'c'
        ("'café'", &[6, 8]),     // café itself + cafés; NOT cafe (id 7): 'e' != 'é'
        ("'na\u{00EF}'", &[10]), // 'naï' — multi-byte prefix
        ("''", &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11]), // every string name; NOT 42/null/Other
        ("'z'", &[]),
        ("'alphabet'", &[]), // prefix longer than 'alpha'
    ];

    for (lit, expected) in cases {
        let src = format!("MATCH (n:Word) WHERE n.name STARTS WITH {lit} RETURN n.id AS a");
        let plan = compile(&src, &indexed);
        assert!(
            has_starts_with_seek(&plan),
            "`{src}` must use a NodeIndexStartsWithSeek:\n{plan}"
        );
        let via_index = read_sorted_ints(&mut coord, &indexed, &src, "a");
        let via_scan = read_sorted_ints(&mut coord, &IndexCatalog::empty(), &src, "a");
        assert_eq!(
            via_index, via_scan,
            "`{src}`: prefix seek must equal scan+filter"
        );
        assert_eq!(
            via_index,
            expected.to_vec(),
            "`{src}`: unexpected match set"
        );
    }
}

#[test]
fn starts_with_seek_matches_scan_under_param_prefix() {
    // The prefix arrives as a `$param` (the shape literal auto-parameterisation produces). The
    // executor computes the bounds from the run-time value, so the param form is served by the same
    // prefix seek as a literal — and equals the scan path.
    let mut coord = fresh_coord();
    seed_words(&mut coord);
    coord
        .create_node_property_index("Word", "name")
        .expect("create index");
    let indexed = coord.catalog();

    let src = "MATCH (n:Word) WHERE n.name STARTS WITH $p RETURN n.id AS a";
    let plan = compile(src, &indexed);
    assert!(
        has_starts_with_seek(&plan),
        "the param-prefix plan must still use a NodeIndexStartsWithSeek:\n{plan}"
    );

    // Bind $p = 'caf' and run both paths, comparing result sets.
    let run = |coord: &mut Coord, catalog: &IndexCatalog| -> Vec<i64> {
        let plan = compile(src, catalog);
        let params = Parameters::new().with("p", Value::String("caf".to_owned()));
        let bound = bind_parameters(&plan, &params).expect("bind");
        let txn = coord.begin_serializable();
        let rows = {
            let mut graph = coord.statement(txn).expect("statement");
            let mut cursor = execute(&plan, &bound, &mut graph).expect("open");
            let rows = cursor.collect_all().expect("collect");
            assert!(!graph.has_error(), "error: {:?}", graph.take_error());
            rows
        };
        coord.commit(txn).expect("commit");
        let mut vs: Vec<i64> = rows
            .iter()
            .filter_map(|r| match r.value("a") {
                Value::Integer(k) => Some(k),
                _ => None,
            })
            .collect();
        vs.sort_unstable();
        vs
    };
    let via_index = run(&mut coord, &indexed);
    let via_scan = run(&mut coord, &IndexCatalog::empty());
    assert_eq!(via_index, via_scan, "param prefix: index must equal scan");
    assert_eq!(
        via_index,
        vec![6, 7, 8],
        "param 'caf' matches café/cafe/cafés"
    );
}

#[test]
fn bare_label_scan_equals_scan_path_and_uses_token_lookup() {
    let mut coord = fresh_coord();
    seed_people(&mut coord);
    coord
        .create_node_property_index("Person", "age")
        .expect("create index");

    // A bare `MATCH (n:Person)` — no property predicate. The catalog must yield a TokenLookupScan
    // (the always-present label index is exposed for every indexed label).
    let src = "MATCH (n:Person) RETURN n.age AS a";
    let indexed = coord.catalog();
    let plan = compile(src, &indexed);
    assert!(
        has_token_lookup(&plan),
        "the index-aware plan must use a TokenLookupScan:\n{plan}"
    );

    let via_index = read_sorted_ints(&mut coord, &indexed, src, "a");
    let via_scan = read_sorted_ints(&mut coord, &IndexCatalog::empty(), src, "a");
    // Every Person's age (the two no-age Persons project null, filtered out by `read_sorted_ints`);
    // the two non-Person nodes never appear.
    let mut expected: Vec<i64> = (20..=40).collect();
    expected.push(30); // the duplicate 30
    expected.sort_unstable();
    assert_eq!(via_index, expected, "index label-scan result");
    assert_eq!(
        via_index, via_scan,
        "token-lookup label scan must equal full label scan"
    );
}

#[test]
fn equality_seek_on_string_property_equals_scan_filter() {
    // A String-valued property exercises the `strings.store` overflow value class through the index
    // value-match path (the index keys by encoded value); the result must still equal the scan path.
    let mut coord = fresh_coord();
    run_write(&mut coord, "CREATE (:Tag {name: 'red', n: 1})");
    run_write(&mut coord, "CREATE (:Tag {name: 'green', n: 2})");
    run_write(&mut coord, "CREATE (:Tag {name: 'red', n: 3})");
    run_write(&mut coord, "CREATE (:Other {name: 'red', n: 9})");
    coord
        .create_node_property_index("Tag", "name")
        .expect("create index");

    let src = "MATCH (n:Tag) WHERE n.name = 'red' RETURN n.n AS a";
    let indexed = coord.catalog();
    let plan = compile(src, &indexed);
    assert!(has_index_seek(&plan), "must use a NodeIndexSeek:\n{plan}");

    let via_index = read_sorted_ints(&mut coord, &indexed, src, "a");
    let via_scan = read_sorted_ints(&mut coord, &IndexCatalog::empty(), src, "a");
    assert_eq!(
        via_index,
        vec![1, 3],
        "two `red` Tags, the `red` Other excluded"
    );
    assert_eq!(via_index, via_scan, "string eq seek must equal scan+filter");
}

// =================================================================================================
// MVCC: dead (deleted) versions must be excluded even though stale index entries linger
// =================================================================================================

#[test]
fn deleted_versions_excluded_from_seek_equal_scan() {
    let mut coord = fresh_coord();
    seed_people(&mut coord);
    coord
        .create_node_property_index("Person", "age")
        .expect("create index");

    // MVCC-delete every Person aged > 35 in a committed transaction. Their index entries remain
    // (the index is never removed from); a later seek must NOT return them — the re-check drops the
    // now-invisible (tombstoned) candidates.
    run_write(&mut coord, "MATCH (n:Person) WHERE n.age > 35 DELETE n");

    // Equality on a surviving value, and on a deleted value (36): both must match the scan path.
    for src in [
        "MATCH (n:Person) WHERE n.age = 30 RETURN n.age AS a", // survivors (two 30s)
        "MATCH (n:Person) WHERE n.age = 36 RETURN n.age AS a", // deleted: must be empty
    ] {
        let indexed = coord.catalog();
        assert!(
            has_index_seek(&compile(src, &indexed)),
            "`{src}` must still use a NodeIndexSeek"
        );
        let via_index = read_sorted_ints(&mut coord, &indexed, src, "a");
        let via_scan = read_sorted_ints(&mut coord, &IndexCatalog::empty(), src, "a");
        assert_eq!(
            via_index, via_scan,
            "`{src}`: seek must exclude deleted versions (equal to scan+filter)"
        );
    }

    // A range over the deleted region (> 30): only the survivors 31..=35 remain.
    let src = "MATCH (n:Person) WHERE n.age > 30 RETURN n.age AS a";
    let indexed = coord.catalog();
    let via_index = read_sorted_ints(&mut coord, &indexed, src, "a");
    let via_scan = read_sorted_ints(&mut coord, &IndexCatalog::empty(), src, "a");
    assert_eq!(
        via_index,
        (31..=35).collect::<Vec<_>>(),
        "only survivors above 30 remain after deleting > 35"
    );
    assert_eq!(via_index, via_scan, "range seek excludes deleted versions");

    // The bare label scan must likewise drop the deleted Persons.
    let src = "MATCH (n:Person) RETURN n.age AS a";
    let indexed = coord.catalog();
    let via_index = read_sorted_ints(&mut coord, &indexed, src, "a");
    let via_scan = read_sorted_ints(&mut coord, &IndexCatalog::empty(), src, "a");
    assert_eq!(
        via_index, via_scan,
        "label scan over the index excludes deleted versions"
    );
}

#[test]
fn overwritten_value_seek_equals_scan() {
    // Overwriting a property leaves a stale index entry at the OLD value (no removal). A seek on the
    // old value must return nothing (the node's current value differs); a seek on the new value must
    // return the node. Both must equal the scan path.
    let mut coord = fresh_coord();
    seed_people(&mut coord);
    coord
        .create_node_property_index("Person", "age")
        .expect("create index");

    // Move the (unique) Person aged 40 to a fresh, previously-unused value 999.
    run_write(
        &mut coord,
        "MATCH (n:Person) WHERE n.age = 40 SET n.age = 999",
    );

    for src in [
        "MATCH (n:Person) WHERE n.age = 40 RETURN n.age AS a", // old value: now stale -> empty
        "MATCH (n:Person) WHERE n.age = 999 RETURN n.age AS a", // new value: the moved node
    ] {
        let indexed = coord.catalog();
        let via_index = read_sorted_ints(&mut coord, &indexed, src, "a");
        let via_scan = read_sorted_ints(&mut coord, &IndexCatalog::empty(), src, "a");
        assert_eq!(
            via_index, via_scan,
            "`{src}`: overwritten-value seek must equal scan+filter"
        );
    }
}

// =================================================================================================
// Crash / recovery: a fresh coordinator rebuilds a store-consistent index
// =================================================================================================

/// Recovers a no-force crash: replay the durable WAL prefix onto a fresh device and reopen
/// (mirrors `tests/crash_concurrency.rs::recover_no_force`).
fn recover_no_force(store: &Store) -> Store {
    let log = store.with_wal(|w| w.sink().durable_bytes().to_vec());
    let mut sink = MemLogSink::new();
    sink.append(&log);
    sink.sync().expect("sync log prefix");
    let mut device = MemBlockDevice::new(0);
    let mut wal = WalManager::open(sink.clone()).expect("open wal");
    recover_device(&mut wal, &mut device).expect("recover");
    let wal = WalManager::open(sink).expect("reopen wal");
    RecordStore::open(device, wal, 64).expect("open store")
}

#[test]
fn index_survives_crash_recovery_without_re_registration() {
    // `rmp` task #90: the durable index catalog makes index *registration* survive a crash. Declare
    // the index, drive committed inserts, crash, recover the store, build a NEW coordinator — and do
    // NOT re-create the index. The fresh coordinator must recover the declared index from the durable
    // catalog, repopulate it from the recovered rows, and answer seeks identically to the scan path.
    let mut coord = fresh_coord();
    // Declare the index FIRST (it is now durable), then seed the rows it must index.
    coord
        .create_node_property_index("Person", "age")
        .expect("create index");
    seed_people(&mut coord);

    // Crash: reclaim the store with no open transaction, then recover from the durable WAL alone.
    let store = coord.into_store();
    let recovered = recover_no_force(&store);

    // Build a fresh coordinator over the recovered store. Crucially, we do NOT re-register the index:
    // `TxnCoordinator::new` -> `rebuild_index` recovers the durable catalog entry and repopulates it.
    let mut coord2 = TxnCoordinator::new(recovered);

    // The recovered index must be Online and planner-visible: the index-aware catalog must actually
    // route a seek (otherwise we would only be comparing the scan path against itself, and the
    // crash-survival claim would be vacuous).
    let indexed = coord2.catalog();
    let seek_plan = compile(
        "MATCH (n:Person) WHERE n.age = 30 RETURN n.age AS a",
        &indexed,
    );
    assert!(
        has_index_seek(&seek_plan),
        "the recovered index must be Online and drive a NodeIndexSeek (no re-registration):\n{seek_plan}"
    );
    let range_plan = compile(
        "MATCH (n:Person) WHERE n.age > 30 RETURN n.age AS a",
        &indexed,
    );
    assert!(
        has_index_range_seek(&range_plan),
        "the recovered index must drive a NodeIndexRangeSeek:\n{range_plan}"
    );

    for src in [
        "MATCH (n:Person) WHERE n.age = 30 RETURN n.age AS a",
        "MATCH (n:Person) WHERE n.age > 30 RETURN n.age AS a",
        "MATCH (n:Person) RETURN n.age AS a",
    ] {
        let indexed = coord2.catalog();
        let via_index = read_sorted_ints(&mut coord2, &indexed, src, "a");
        let via_scan = read_sorted_ints(&mut coord2, &IndexCatalog::empty(), src, "a");
        assert_eq!(
            via_index, via_scan,
            "`{src}`: post-recovery index must equal scan+filter over the recovered graph"
        );
    }

    // Sanity: the recovered graph is non-empty (the committed seed survived), so the equivalence
    // above is not vacuously over empty result-sets.
    let indexed = coord2.catalog();
    let any = read_sorted_ints(
        &mut coord2,
        &indexed,
        "MATCH (n:Person) WHERE n.age = 30 RETURN n.age AS a",
        "a",
    );
    assert_eq!(any, vec![30, 30], "the committed seed survived recovery");
}

// =================================================================================================
// Planner state gating (`rmp` task #90): only an Online index serves seeks; a Populating one falls
// back to a label-scan + filter, but still returns the same rows. (`rmp` task #91 reaches the
// genuine Populating state via a partially-advanced non-blocking build — a fabricated-then-reopened
// Populating index is now completed on reopen by the crash-recovery promotion path, so the live
// in-progress build is the faithful way to observe the Populating planner gating.)
// =================================================================================================

#[test]
fn populating_index_is_not_used_by_planner_while_online_is() {
    // Seed a graph, then start a NON-BLOCKING build and advance it only partway so the index is a
    // genuine in-progress `Populating` (`rmp` task #91): a build over a multi-node snapshot left
    // un-promoted. The planner must NOT route a seek to it.
    let mut coord = fresh_coord();
    seed_people(&mut coord);
    coord
        .begin_online_node_property_index("Person", "age")
        .expect("begin online build");
    // Advance a single tiny chunk: the snapshot has many nodes, so the build stays Populating.
    coord.advance_index_builds(2);
    assert!(
        coord.has_pending_index_builds(),
        "the build must still be in progress (partial advance keeps it Populating)"
    );

    // The catalog must withhold the Populating index: an equality / range predicate on `Person.age`
    // must fall back to a label-scan (TokenLookupScan) + Filter, NOT a NodeIndexSeek.
    let indexed = coord.catalog();
    for (src, kind) in [
        ("MATCH (n:Person) WHERE n.age = 30 RETURN n.age AS a", "eq"),
        (
            "MATCH (n:Person) WHERE n.age > 30 RETURN n.age AS a",
            "range",
        ),
    ] {
        let plan = compile(src, &indexed);
        assert!(
            !has_index_seek(&plan) && !has_index_range_seek(&plan),
            "`{src}` ({kind}): a Populating index must NOT drive an index seek:\n{plan}"
        );
        // The Populating *property* index is withheld. The exact fallback shape depends on the
        // predicate kind:
        //   - equality (`rmp` task #325): the precise full-scan `NodeLabelScanEq` access path (no
        //     property index, no token-lookup — it scans every node but SIREAD-marks only the matches);
        //   - range: the always-present label token-lookup scan + a residual `Filter`.
        // Either way, no NodeIndexSeek/NodeIndexRangeSeek is routed (the property index is invisible).
        let rendered = plan.to_string();
        if kind == "eq" {
            assert!(
                rendered.contains("NodeLabelScanEq"),
                "`{src}` ({kind}): a Populating index's equality fallback must use the precise NodeLabelScanEq:\n{plan}"
            );
        } else {
            assert!(
                has_token_lookup(&plan),
                "`{src}` ({kind}): must fall back to a TokenLookupScan + Filter:\n{plan}"
            );
        }
        // And the fallback returns exactly the scan+filter rows.
        let via_catalog = read_sorted_ints(&mut coord, &indexed, src, "a");
        let via_scan = read_sorted_ints(&mut coord, &IndexCatalog::empty(), src, "a");
        assert_eq!(
            via_catalog, via_scan,
            "`{src}` ({kind}): Populating fallback must equal scan+filter"
        );
    }

    // Now drive the same non-blocking build to completion: at the final chunk it flips the catalog
    // entry to Online. The planner must now route a seek, proving the gating is state-driven
    // (Online -> seek; Populating -> scan).
    while coord.has_pending_index_builds() {
        coord.advance_index_builds(4);
    }
    let indexed = coord.catalog();
    let seek_plan = compile(
        "MATCH (n:Person) WHERE n.age = 30 RETURN n.age AS a",
        &indexed,
    );
    assert!(
        has_index_seek(&seek_plan),
        "after promotion to Online the planner must use a NodeIndexSeek:\n{seek_plan}"
    );
    let range_plan = compile(
        "MATCH (n:Person) WHERE n.age > 30 RETURN n.age AS a",
        &indexed,
    );
    assert!(
        has_index_range_seek(&range_plan),
        "after promotion to Online the planner must use a NodeIndexRangeSeek:\n{range_plan}"
    );
    // Equivalence still holds on the Online path.
    let via_index = read_sorted_ints(
        &mut coord,
        &indexed,
        "MATCH (n:Person) WHERE n.age = 30 RETURN n.age AS a",
        "a",
    );
    let via_scan = read_sorted_ints(
        &mut coord,
        &IndexCatalog::empty(),
        "MATCH (n:Person) WHERE n.age = 30 RETURN n.age AS a",
        "a",
    );
    assert_eq!(via_index, via_scan, "Online seek must equal scan+filter");
}

// =================================================================================================
// Two-anchor edge create: BOTH disconnected anchors index-seek, with result parity (`rmp` #303/#312)
// =================================================================================================

/// Counts `NodeIndexSeek` operators anywhere in the physical tree.
fn count_index_seeks(plan: &PhysicalPlan) -> usize {
    fn walk(op: &PhysicalOp) -> usize {
        usize::from(matches!(op, PhysicalOp::NodeIndexSeek { .. }))
            + children(op).iter().map(|c| walk(c)).sum::<usize>()
    }
    walk(&plan.root)
}

/// Seeds `:User {id: 1..=5}` (unique ids) plus a couple of non-`User` decoys that carry an `id` but
/// must never be reachable through a `:User` anchor.
fn seed_users(coord: &mut Coord) {
    for id in 1..=5 {
        run_write(coord, &format!("CREATE (:User {{id: {id}}})"));
    }
    run_write(coord, "CREATE (:Company {id: 2})"); // non-User carrying id 2 (must not match a :User anchor)
    run_write(coord, "CREATE (:Company {id: 4})");
}

#[test]
fn two_anchor_create_inline_both_seek_and_matches_scan_path() {
    let mut coord = fresh_coord();
    seed_users(&mut coord);
    coord
        .create_node_property_index("User", "id")
        .expect("create index");
    let indexed = coord.catalog();

    // The endpoint-resolving MATCH of a two-anchor edge create — the exact shape that previously
    // scanned the second anchor. Both anchors must now index-seek.
    let src = "MATCH (a:User {id: 2}), (b:User {id: 4}) RETURN a.id * 100 + b.id AS a";
    let plan = compile(src, &indexed);
    assert_eq!(
        count_index_seeks(&plan),
        2,
        "both disconnected anchors must index-seek:\n{plan}"
    );

    // Result parity: the seek path returns exactly the scan+filter path's rows.
    let via_index = read_sorted_ints(&mut coord, &indexed, src, "a");
    let via_scan = read_sorted_ints(&mut coord, &IndexCatalog::empty(), src, "a");
    assert_eq!(via_index, vec![204], "the single (2,4) pair"); // 2*100 + 4
    assert_eq!(
        via_index, via_scan,
        "two-anchor seek path must equal the scan+filter path (inline form)"
    );
}

#[test]
fn two_anchor_create_trailing_where_both_seek_and_matches_scan_path() {
    let mut coord = fresh_coord();
    seed_users(&mut coord);
    coord
        .create_node_property_index("User", "id")
        .expect("create index");
    let indexed = coord.catalog();

    // The trailing-`WHERE` twin: a single top `Filter` over the whole pattern before the fix, so
    // NEITHER anchor sought. Each single-variable equality is now pushed onto its anchor's scan.
    let src = "MATCH (a:User), (b:User) WHERE a.id = 2 AND b.id = 4 RETURN a.id * 100 + b.id AS a";
    let plan = compile(src, &indexed);
    assert_eq!(
        count_index_seeks(&plan),
        2,
        "both anchors must index-seek in the WHERE form:\n{plan}"
    );

    let via_index = read_sorted_ints(&mut coord, &indexed, src, "a");
    let via_scan = read_sorted_ints(&mut coord, &IndexCatalog::empty(), src, "a");
    assert_eq!(via_index, vec![204]);
    assert_eq!(
        via_index, via_scan,
        "two-anchor seek path must equal the scan+filter path (WHERE form)"
    );
}

#[test]
fn two_variable_join_predicate_still_correct_and_not_pushed() {
    // A genuine two-variable predicate must stay a join condition (no anchor seek), and still produce
    // the correct pairs — identical whether the catalog carries the index or not.
    let mut coord = fresh_coord();
    seed_users(&mut coord);
    coord
        .create_node_property_index("User", "id")
        .expect("create index");
    let indexed = coord.catalog();

    // Ordered distinct pairs from the same 5-user set; `a.id = b.id - 1` spans both variables.
    let src = "MATCH (a:User), (b:User) WHERE a.id = b.id - 1 RETURN a.id * 100 + b.id AS a";
    let plan = compile(src, &indexed);
    assert_eq!(
        count_index_seeks(&plan),
        0,
        "a two-variable predicate must not drive any anchor seek:\n{plan}"
    );

    let via_index = read_sorted_ints(&mut coord, &indexed, src, "a");
    let via_scan = read_sorted_ints(&mut coord, &IndexCatalog::empty(), src, "a");
    // (1,2),(2,3),(3,4),(4,5) -> 102,203,304,405
    assert_eq!(via_index, vec![102, 203, 304, 405]);
    assert_eq!(
        via_index, via_scan,
        "join predicate result must be catalog-independent"
    );
}

#[test]
fn two_anchor_create_edge_executes_over_the_seek_path() {
    // End-to-end: run the actual `CREATE (a)-[:FRIEND]->(b)` over the index (seek) path, then verify
    // the edge landed between exactly the right endpoints.
    let mut coord = fresh_coord();
    seed_users(&mut coord);
    coord
        .create_node_property_index("User", "id")
        .expect("create index");
    let indexed = coord.catalog();

    let create_src = "MATCH (a:User {id: 2}), (b:User {id: 4}) CREATE (a)-[:FRIEND]->(b)";
    let create_plan = compile(create_src, &indexed);
    assert_eq!(
        count_index_seeks(&create_plan),
        2,
        "the create's endpoint resolution must use two index seeks:\n{create_plan}"
    );

    // Execute the create over the seek path in its own committed write transaction.
    let txn = coord.begin_serializable();
    let _ = run_plan(&coord, txn, &create_plan);
    coord.commit(txn).expect("edge create commits");

    // The FRIEND edge exists from user 2 to user 4 (and to no one else).
    let targets = read_sorted_ints(
        &mut coord,
        &indexed,
        "MATCH (a:User {id: 2})-[:FRIEND]->(b:User) RETURN b.id AS a",
        "a",
    );
    assert_eq!(targets, vec![4], "the edge points 2 -> 4");
    // No stray reverse edge.
    let reverse = read_sorted_ints(
        &mut coord,
        &indexed,
        "MATCH (a:User {id: 4})-[:FRIEND]->(b:User) RETURN b.id AS a",
        "a",
    );
    assert!(reverse.is_empty(), "no reverse 4 -> 2 edge was created");
}

// =================================================================================================
// An index is a PERFORMANCE artefact, never a SEMANTIC one (`rmp` task #680 regression)
// =================================================================================================

/// A range predicate whose bound is a **different value class** from the property (an `INTEGER` `age`
/// against a `STRING` bound) must return the SAME rows with and without the index — namely **none**,
/// because Cypher comparability (CIP §Comparability, the semantics of `<`/`<=`/`>`/`>=`) makes a
/// cross-class comparison `NULL`, and a `WHERE` clause drops a `NULL` row.
///
/// # The bug this pins (`rmp` task #680, found while adding the relationship range seek)
///
/// `NodeIndexRangeSeek`'s per-candidate re-check (and its `scan_filter_range` fallback) used
/// [`cmp_values`](graphus_cypher::cmp_values) — the total **orderability** behind `ORDER BY` / `min` /
/// `max` / the index key codec, under which value classes are *ranked* (`STRING < NUMBER < null`).
/// Under that order `30 >= 'abc'` is TRUE (a number out-ranks a string), so the seek returned **every**
/// node while the scan + `Filter` plan for the identical query returned **none**:
///
/// ```text
/// MATCH (n:P) WHERE n.age >= 'abc' RETURN n.age    -- with a (P, age) index: [30, 10]   WRONG
///                                                  -- without:               []          correct
/// ```
///
/// Declaring an index silently changed a query's result — a correctness defect, not a performance one.
/// Both paths now re-check through `eval::satisfies_range`, the single source of truth for the
/// comparison operators.
#[test]
fn a_cross_type_range_bound_returns_the_same_rows_with_and_without_the_index() {
    let mut coord = fresh_coord();
    run_write(&mut coord, "CREATE (:P {age: 30}), (:P {age: 10})");
    coord
        .create_node_property_index("P", "age")
        .expect("create the (P, age) range index");
    let indexed = coord.catalog();

    let src = "MATCH (n:P) WHERE n.age >= 'abc' RETURN n.age AS a";
    let plan = compile(src, &indexed);
    // Non-vacuity: the indexed plan really is the seek path under test (without this assertion the
    // test would pass on an engine that never seeks).
    assert!(
        has_index_range_seek(&plan),
        "the indexed plan must really use the NodeIndexRangeSeek:\n{plan}"
    );

    let via_index = read_sorted_ints(&mut coord, &indexed, src, "a");
    let via_scan = read_sorted_ints(&mut coord, &IndexCatalog::empty(), src, "a");
    assert!(
        via_scan.is_empty(),
        "an INTEGER property vs a STRING bound is incomparable: the predicate is NULL, so no row \
         survives the WHERE — got {via_scan:?}"
    );
    assert_eq!(
        via_index, via_scan,
        "the index seek MUST agree with the scan + filter: declaring an index may never change a \
         query's result"
    );

    // The symmetric orientation (`'abc' <= n.age`, which the planner mirrors into `n.age >= 'abc'`).
    let mirrored = "MATCH (n:P) WHERE 'abc' <= n.age RETURN n.age AS a";
    assert!(
        has_index_range_seek(&compile(mirrored, &indexed)),
        "the mirrored orientation also seeks"
    );
    assert_eq!(
        read_sorted_ints(&mut coord, &indexed, mirrored, "a"),
        read_sorted_ints(&mut coord, &IndexCatalog::empty(), mirrored, "a"),
        "the mirrored bound must agree too"
    );
}

/// A `NaN`-valued property must be excluded by a range predicate on **both** paths: openCypher pins
/// every inequality against a `NaN` operand to `FALSE` (TCK `Comparison2 [5]`), whereas the total
/// orderability [`cmp_values`](graphus_cypher::cmp_values) ranks `NaN` as the **largest number** — so
/// the old `cmp_values`-based re-check let `NaN >= 5` through the seek while the scan + `Filter` plan
/// (correctly) dropped it (`rmp` task #680).
#[test]
fn a_nan_property_is_excluded_by_a_range_predicate_on_both_paths() {
    let mut coord = fresh_coord();
    run_write(
        &mut coord,
        "CREATE (:Q {v: 0.0/0.0}), (:Q {v: 100.0}), (:Q {v: 1.0})",
    );
    coord
        .create_node_property_index("Q", "v")
        .expect("create the (Q, v) range index");
    let indexed = coord.catalog();

    let src = "MATCH (n:Q) WHERE n.v >= 5 RETURN toInteger(n.v) AS a";
    let plan = compile(src, &indexed);
    assert!(
        has_index_range_seek(&plan),
        "the indexed plan must really use the NodeIndexRangeSeek:\n{plan}"
    );

    let via_index = read_sorted_ints(&mut coord, &indexed, src, "a");
    let via_scan = read_sorted_ints(&mut coord, &IndexCatalog::empty(), src, "a");
    assert_eq!(
        via_scan,
        vec![100],
        "only 100.0 satisfies `>= 5` — `NaN >= 5` is FALSE and `1.0 >= 5` is false"
    );
    assert_eq!(
        via_index, via_scan,
        "the seek must not admit the NaN row the scan + filter rejects"
    );
}

/// REGRESSION (`rmp` #680 storage audit): a **Float lower bound over Integer-valued data** (and the
/// signed-zero variants) must return the same rows with and without the index. The order-preserving
/// index key sorts `Integer(2020)` below `Float(2020.0)` (numtag tie-break), so a `>= 2020.0` seek
/// anchored at the bound's own key used to SKIP the Cypher-equal `Integer(2020)` — a silent false
/// negative where declaring an index dropped a committed row. `PropertyIndex::seek_range` now anchors at
/// the byte-minimum of the Cypher-equal class, restoring the true-superset contract.
#[test]
fn a_float_lower_bound_over_integer_data_returns_the_same_rows_with_and_without_the_index() {
    let mut coord = fresh_coord();
    run_write(
        &mut coord,
        "CREATE (:P {age: 2019}), (:P {age: 2020}), (:P {age: 2021})",
    );
    coord
        .create_node_property_index("P", "age")
        .expect("create the (P, age) range index");
    let indexed = coord.catalog();

    for src in [
        "MATCH (n:P) WHERE n.age >= 2020.0 RETURN n.age AS a", // the dropped-row case
        "MATCH (n:P) WHERE n.age > 2019.0 RETURN n.age AS a",
        "MATCH (n:P) WHERE n.age <= 2020.0 RETURN n.age AS a",
        "MATCH (n:P) WHERE 2020.0 <= n.age RETURN n.age AS a", // mirrored orientation
    ] {
        let plan = compile(src, &indexed);
        assert!(
            has_index_range_seek(&plan),
            "non-vacuity: {src} must really seek:\n{plan}"
        );
        let via_index = read_sorted_ints(&mut coord, &indexed, src, "a");
        let via_scan = read_sorted_ints(&mut coord, &IndexCatalog::empty(), src, "a");
        assert_eq!(
            via_index, via_scan,
            "the Float-bound range seek must agree with the scan + filter for: {src}"
        );
    }
    // The specific dropped row is present: `>= 2020.0` includes 2020.
    assert_eq!(
        read_sorted_ints(
            &mut coord,
            &indexed,
            "MATCH (n:P) WHERE n.age >= 2020.0 RETURN n.age AS a",
            "a",
        ),
        vec![2020, 2021],
        "the Integer(2020) row must not be dropped by a Float(2020.0) lower bound"
    );
}

/// REGRESSION (`rmp` #680 storage audit): `Integer(0)`, `Float(0.0)` and `Float(-0.0)` are all
/// Cypher-equal to zero but encode to distinct keys (`-0.0` sorts below `+0.0`, and the numtag splits
/// int from float). A `>= 0` / `>= 0.0` / `>= -0.0` seek must admit **all three** regardless of the
/// bound's spelling — the signed-zero half of the widening the fix restored.
#[test]
fn a_zero_lower_bound_admits_every_signed_zero_representation_on_both_paths() {
    let mut coord = fresh_coord();
    // Store the three zeros (tagged so we can identify them) plus a positive control.
    run_write(&mut coord, "CREATE (:Z {tag: 1, v: 0})");
    run_write(&mut coord, "CREATE (:Z {tag: 2, v: 0.0})");
    run_write(&mut coord, "CREATE (:Z {tag: 3, v: -0.0})");
    run_write(&mut coord, "CREATE (:Z {tag: 4, v: 5})");
    coord
        .create_node_property_index("Z", "v")
        .expect("create the (Z, v) range index");
    let indexed = coord.catalog();

    for src in [
        "MATCH (n:Z) WHERE n.v >= 0 RETURN n.tag AS a",
        "MATCH (n:Z) WHERE n.v >= 0.0 RETURN n.tag AS a",
        "MATCH (n:Z) WHERE n.v >= -0.0 RETURN n.tag AS a",
    ] {
        let plan = compile(src, &indexed);
        assert!(
            has_index_range_seek(&plan),
            "non-vacuity: {src} must really seek:\n{plan}"
        );
        let via_index = read_sorted_ints(&mut coord, &indexed, src, "a");
        let via_scan = read_sorted_ints(&mut coord, &IndexCatalog::empty(), src, "a");
        assert_eq!(
            via_index,
            vec![1, 2, 3, 4],
            "every zero representation (and the positive control) is >= zero: {src}"
        );
        assert_eq!(via_index, via_scan, "seek must agree with scan for: {src}");
    }
}

/// REGRESSION (found while certifying `rmp` #680): a **`List`-typed bound** on an indexed property is
/// the one value class that is COMPARABLE under Cypher (`compare_values` on two lists is `Some`) yet
/// UNINDEXABLE under the key codec (`encode_value` errors `Unindexable("List")`). A range predicate
/// whose bound is a list must therefore return the SAME rows with and without the index. Before the
/// fix the seam's `seek_..._property_range` collapsed the bound's encode error to `Some(empty)` (via
/// `unwrap_or_default`) rather than `None`, so the executor used the empty candidate set and never took
/// the scan fallback: `n.data >= [1,2,3]` returned 0 rows through the index but 1 row through the scan
/// — an index silently changing a query's result, the exact defect class #680 exists to eliminate. The
/// fix makes the seam decline (`None`) whenever a bound is not index-encodable, forcing the exact scan.
#[test]
fn a_list_range_bound_returns_the_same_rows_with_and_without_the_index() {
    let mut coord = fresh_coord();
    // A node whose list property is Cypher-`>=` the list bound, plus a control that is not.
    run_write(&mut coord, "CREATE (:T {tag: 1, data: [1, 2, 3, 4]})");
    run_write(&mut coord, "CREATE (:T {tag: 2, data: [1, 2]})");
    coord
        .create_node_property_index("T", "data")
        .expect("create the (T, data) range index");
    let indexed = coord.catalog();

    for src in [
        "MATCH (n:T) WHERE n.data >= [1, 2, 3] RETURN n.tag AS a",
        "MATCH (n:T) WHERE n.data < [1, 2, 3] RETURN n.tag AS a",
        "MATCH (n:T) WHERE [1, 2, 3] <= n.data RETURN n.tag AS a", // mirrored orientation
    ] {
        // Non-vacuity: the indexed plan really lowers to the range seek under test (so it is genuinely
        // exercising the seam decline + scan fallback, not a plan that never seeks).
        let plan = compile(src, &indexed);
        assert!(
            has_index_range_seek(&plan),
            "non-vacuity: {src} must really lower to a NodeIndexRangeSeek:\n{plan}"
        );
        let via_index = read_sorted_ints(&mut coord, &indexed, src, "a");
        let via_scan = read_sorted_ints(&mut coord, &IndexCatalog::empty(), src, "a");
        assert_eq!(
            via_index, via_scan,
            "a List-typed range bound must return the same rows with and without the index: {src}"
        );
    }
    // The specific row a list bound must NOT drop: `[1,2,3,4] >= [1,2,3]` is `True`.
    assert_eq!(
        read_sorted_ints(
            &mut coord,
            &indexed,
            "MATCH (n:T) WHERE n.data >= [1, 2, 3] RETURN n.tag AS a",
            "a",
        ),
        vec![1],
        "the `[1,2,3,4]` node (tag 1) satisfies `>= [1,2,3]` and must survive the index path"
    );
}

/// REGRESSION (found while certifying `rmp` #680): the equality twin of
/// [`a_list_range_bound_returns_the_same_rows_with_and_without_the_index`]. A `= [list]` equality
/// predicate on an indexed property shares the identical root cause — `seek_node_property_eq` collapsed
/// the bound's encode error to `Some(empty)`, so `n.data = [1,2,3]` returned 0 rows via the index but 1
/// via the scan. The seam now declines (`None`) on a non-encodable bound, forcing the exact scan.
#[test]
fn a_list_equality_bound_returns_the_same_rows_with_and_without_the_index() {
    let mut coord = fresh_coord();
    run_write(&mut coord, "CREATE (:T {tag: 1, data: [1, 2, 3]})");
    run_write(&mut coord, "CREATE (:T {tag: 2, data: [9]})");
    coord
        .create_node_property_index("T", "data")
        .expect("create the (T, data) index");
    let indexed = coord.catalog();

    let src = "MATCH (n:T) WHERE n.data = [1, 2, 3] RETURN n.tag AS a";
    let plan = compile(src, &indexed);
    assert!(
        has_index_seek(&plan),
        "non-vacuity: the indexed plan must really lower to a NodeIndexSeek:\n{plan}"
    );
    let via_index = read_sorted_ints(&mut coord, &indexed, src, "a");
    let via_scan = read_sorted_ints(&mut coord, &IndexCatalog::empty(), src, "a");
    assert_eq!(
        via_scan,
        vec![1],
        "the `[1,2,3]` node (tag 1) equals the list bound"
    );
    assert_eq!(
        via_index, via_scan,
        "a List-typed equality bound must return the same rows with and without the index"
    );
}

/// **The rebuild gate: a captured off-thread seek must never serve a reader older than the last index
/// rebuild** (`rmp` task #755, Slice S2 — containment of `rmp` #765).
///
/// # The hazard this pins
///
/// The captured-candidate design (Slice S2) rests on `node_props` being append-only, so that the *stale*
/// index entry a reader with an older snapshot still depends on survives to be captured. That holds for
/// the per-entry surface (`insert_node_property` is the only per-entry mutation; there is no
/// `remove_node_property`) — but **not for the tree**: `TxnCoordinator::rebuild_index` calls
/// `IndexSet::clear()`, which wipes every node-property tree, and refills **newest-wins**. The stale
/// entries are annihilated, while the indexes stay `Online` and `heal()` clears `degraded` — so the
/// `Online` and not-degraded gates both pass over a tree that is a genuine SUBSET for an older snapshot.
///
/// Any index/constraint DDL triggers it, including one on a **completely unrelated** label/property, and
/// so does the degraded-rebuild retry — no user DDL required.
///
/// # What this test asserts
///
/// With a reader's snapshot fixed BEFORE a value change, and a rebuild driven AFTER it, the capture the
/// reader would be handed must be **empty** (a decline → the executor's exact `scan_filter_eq`, which is
/// snapshot-correct). If the gate were removed, the capture would instead HIT with an empty candidate
/// list — `Some(vec![])`, the precise "reads as no rows" hazard of `rmp` #680/#738 — and the reader would
/// silently drop a committed row it can still see (measured: 1 row → 0 rows).
///
/// # One invariant, two seams (`rmp` #765, closed)
///
/// This gate began as *containment* for the then-open `rmp` #765, which lived on the INLINE seek. #765 is
/// now closed by applying the same reader-vs-rebuild gate there too, and the assertion at the foot of
/// this test — which pinned the row loss at `0` while the defect was open — now pins the row's SURVIVAL
/// at `1`. The two gates are not redundant: they guard different sources (this one the **capture** handed
/// to the off-thread reader, the inline one the **live tree**), and removing either re-opens #765 on that
/// seam. Both express one invariant: a reader older than the last rebuild is never served from
/// `node_props`.
#[test]
fn rebuild_gate_declines_the_capture_for_an_older_snapshot() {
    let mut coord = fresh_coord();
    run_write(&mut coord, "CREATE (:Person {email: 'a@x.io'})");
    coord
        .create_node_property_index("Person", "email")
        .expect("create index");

    // The reader begins HERE: its snapshot sees `email = 'a@x.io'`.
    let reader = coord.begin_serializable();

    // A writer moves the node OFF the sought value and commits. The index keeps the stale
    // ('a@x.io' -> n) entry (append-only per entry), so the reader is still correctly served.
    run_write(
        &mut coord,
        "MATCH (n:Person) WHERE n.email = 'a@x.io' SET n.email = 'zz@x.io'",
    );

    let plan = compile(
        "MATCH (n:Person) WHERE n.email = 'a@x.io' RETURN n.email AS a",
        &coord.catalog(),
    );
    let bound = bind_parameters(&plan, &Parameters::new()).expect("bind");
    let seek = Value::String("a@x.io".to_owned());
    let (l_person, k_email) = {
        // The tokens exactly as the reader resolves them: through the dispatch-captured dictionary.
        let tokens = coord.read_task_inputs(reader).expect("read inputs").tokens;
        (
            tokens
                .token_id(graphus_storage::Namespace::Label, "Person")
                .expect("Person token"),
            tokens
                .token_id(graphus_storage::Namespace::PropKey, "email")
                .expect("email token"),
        )
    };

    // BEFORE any rebuild the memo is a superset and the reader is served the row.
    assert_eq!(
        run_plan(&coord, reader, &plan).len(),
        1,
        "before the rebuild the reader must see the row under its own snapshot"
    );
    let pre = coord.index_candidates_for(reader, &plan, &bound);
    assert_eq!(
        pre.get(l_person, k_email, &seek).as_deref(),
        Some(&[1u64][..]),
        "before the rebuild the capture must SERVE this seek, holding the stale entry. If this is \
         None the test is vacuous — it would then prove nothing about the gate below."
    );

    // An index on a COMPLETELY UNRELATED property rebuilds EVERY node-property tree: clear() + a
    // newest-wins refill destroys the stale ('a@x.io' -> n) entry. State stays Online, degraded heals.
    coord
        .create_node_property_index("Person", "unrelated")
        .expect("create unrelated index");

    // THE GATE: the reader's snapshot predates the rebuild, so the capture must DECLINE — empty, so the
    // reader's `index_seek_eq` misses and falls back to the exact, snapshot-correct scan.
    let post = coord.index_candidates_for(reader, &plan, &bound);
    assert!(
        post.get(l_person, k_email, &seek).is_none(),
        "GATE 3 (rmp #755): a rebuild destroyed the stale entries this reader depends on, so the \
         capture MUST decline (→ exact scan). Serving it would hand the reader `Some(vec![])` and \
         silently drop a committed row it can still see. Without the gate this returns Some([])."
    );
    assert!(
        post.is_empty(),
        "the whole capture must be empty for a pre-rebuild reader"
    );

    // A reader that begins AFTER the rebuild is at-or-after the stamped high-water: still served, so the
    // gate contains the hazard without disabling the acceleration for the normal case.
    let fresh_reader = coord.begin_serializable();
    let fresh = coord.index_candidates_for(fresh_reader, &plan, &bound);
    assert!(
        fresh.get(l_person, k_email, &seek).is_some(),
        "a post-rebuild reader must still be SERVED — the gate must not disable the fast path wholesale"
    );

    // AND THE ROWS COME BACK. The declined capture is the whole point: the off-thread reader's
    // `index_seek_eq` misses, returns `None`, and the executor falls back to the exact `scan_filter_eq`,
    // which is snapshot-correct. This is what "strictly <= pre-#755" means — the pre-#755 reader declined
    // every seek and scanned, and here we reproduce exactly that, for exactly this reader.
    {
        let inputs = coord.read_task_inputs(reader).expect("read inputs");
        let ro: graphus_cypher::ReadOnlyGraph<MemBlockDevice, MemLogSink> =
            graphus_cypher::ReadOnlyGraph::new(
                inputs.view,
                inputs.tokens,
                inputs.snapshot,
                reader,
                graphus_txn::SsiReadBuffer::new(reader),
            )
            .with_index_candidates(post);
        assert!(
            ro.index_seek_eq("Person", "email", &seek, KeyValues::Discard)
                .is_none(),
            "the reader must DECLINE the seek (never Some(vec![])), so the executor scans"
        );
        assert_eq!(
            ro.scan_filter_eq("Person", "email", &seek).matched.len(),
            1,
            "and the exact scan the decline falls back to RESTORES the row the rebuild's wipe hid"
        );
        assert!(!ro.has_error());
    }

    // THE HAZARD, NOW CLOSED (`rmp` #765 — this assertion was `0` while the defect was open). The inline
    // seek now applies the SAME reader-vs-rebuild gate (`RecordStoreGraph::index_seek_eq` declines when
    // `snapshot.ts < rebuilt_trees_trustworthy_from`), so it too falls back to the exact scan and the
    // committed row survives. Inline and off-thread now agree — via the same decline, at two seams.
    assert_eq!(
        run_plan(&coord, reader, &plan).len(),
        1,
        "rmp #765: the inline seek must DECLINE for a reader older than the rebuild and fall back to \
         the exact scan, so the committed row visible at this reader's snapshot survives. A `0` here \
         is the row loss #765 fixed."
    );
}

/// `rmp` #768: the **RANGE** capture rides the SAME node-property rebuild watermark as the equality
/// capture (`rebuilt_trees_trustworthy_from`) — exercised here, not presumed from the equality test.
/// A reader whose snapshot predates an unrelated `CREATE INDEX` (which `clear`s + newest-wins-refills
/// every node-property tree, destroying the stale entries it depends on) must have its range capture
/// **decline** (→ exact `scan_filter_range`, snapshot-correct), never serve a subset. The composite
/// capture shares the identical guard (`capture_node_property_composite`, same first two lines).
#[test]
fn rebuild_gate_declines_the_range_capture_for_an_older_snapshot() {
    let mut coord = fresh_coord();
    run_write(&mut coord, "CREATE (:Person {age: 10})");
    coord
        .create_node_property_index("Person", "age")
        .expect("create the (Person, age) range index");

    // The reader begins HERE: its snapshot sees `age = 10`, which satisfies `age >= 5`.
    let reader = coord.begin_serializable();

    // A writer moves the node OUT of the range (10 -> 1) and commits; the index keeps the stale
    // (10 -> n) entry (append-only per entry), so the reader is still correctly served under its snapshot.
    run_write(
        &mut coord,
        "MATCH (n:Person) WHERE n.age = 10 SET n.age = 1",
    );

    let plan = compile(
        "MATCH (n:Person) WHERE n.age >= 5 RETURN n.age AS a",
        &coord.catalog(),
    );
    let bound = bind_parameters(&plan, &Parameters::new()).expect("bind");
    let (l_person, k_age) = {
        let tokens = coord.read_task_inputs(reader).expect("read inputs").tokens;
        (
            tokens
                .token_id(graphus_storage::Namespace::Label, "Person")
                .expect("Person token"),
            tokens
                .token_id(graphus_storage::Namespace::PropKey, "age")
                .expect("age token"),
        )
    };
    let lower = Some((&Value::Integer(5), true));

    // BEFORE any rebuild the memo is a superset and the reader is served the row (else the gate assertion
    // below is vacuous).
    assert_eq!(
        run_plan(&coord, reader, &plan).len(),
        1,
        "before the rebuild the reader must see the row under its own snapshot"
    );
    let pre = coord.index_candidates_for(reader, &plan, &bound);
    assert!(
        pre.get_range(l_person, k_age, lower, None).is_some(),
        "before the rebuild the RANGE capture must SERVE this seek (holding the stale entry) — if None \
         the test is vacuous"
    );

    // An index on a COMPLETELY UNRELATED property rebuilds EVERY node-property tree, destroying the stale
    // (10 -> n) entry. State stays Online, degraded heals — exactly the `rmp` #765 hazard.
    coord
        .create_node_property_index("Person", "unrelated")
        .expect("create unrelated index");

    // THE GATE: the reader predates the rebuild, so the range capture must DECLINE (empty), so the
    // reader's `index_seek_range` misses and the executor falls back to the exact, snapshot-correct scan.
    let post = coord.index_candidates_for(reader, &plan, &bound);
    assert!(
        post.get_range(l_person, k_age, lower, None).is_none(),
        "GATE (rmp #765/#768): a rebuild destroyed the stale entries this reader depends on, so the \
         RANGE capture MUST decline. Serving it would hand the reader a subset and drop a committed row."
    );

    // A reader that begins AFTER the rebuild is at-or-after the watermark: still served (the gate must
    // not disable the fast path wholesale).
    let fresh_reader = coord.begin_serializable();
    let fresh = coord.index_candidates_for(fresh_reader, &plan, &bound);
    assert!(
        fresh.get_range(l_person, k_age, lower, None).is_some(),
        "a post-rebuild reader must still be SERVED the range seek"
    );

    // AND THE ROW SURVIVES: the inline seek applies the SAME watermark gate (`rmp` #765, closed), so it
    // too declines to the exact scan and the committed row visible at this reader's snapshot survives.
    assert_eq!(
        run_plan(&coord, reader, &plan).len(),
        1,
        "rmp #765: the row visible at this reader's snapshot must survive the unrelated rebuild"
    );
}

/// **THE `rmp` #765 REGRESSION: an unrelated `CREATE INDEX` must not make a concurrent older-snapshot
/// reader lose a committed row on the INLINE path.**
///
/// # The defect
///
/// `TxnCoordinator::rebuild_index` calls `IndexSet::clear()`, which swaps every node-property tree for
/// an empty one while **keeping each index's state** (an `Online` index stays `Online` over an empty
/// tree), then refills **newest-wins** — destroying every STALE entry. A reader whose snapshot predates
/// the rebuild still legitimately resolves the node under its OLD value (node properties are
/// MVCC-versioned per value, `rmp` #50: newest-VISIBLE-wins), so it needs exactly those destroyed
/// entries. Both gates that guard a seek (`IndexState::Online` and `!degraded`) therefore pass over a
/// tree that is a genuine SUBSET, and the per-candidate re-check can only REMOVE candidates — never
/// resurrect a missing one. Result: 1 row → 0 rows, from a `CREATE INDEX` on an unrelated property.
///
/// # What this asserts
///
/// The reader's answer must be INVARIANT across the unrelated rebuild, and the inline path must agree
/// with the off-thread reader (which reaches the same answer by declining to `scan_filter_eq`).
/// Pre-fix this fails with `after = 0`.
#[test]
fn an_unrelated_rebuild_must_not_lose_a_committed_row_for_an_older_snapshot() {
    let mut coord = fresh_coord();
    run_write(&mut coord, "CREATE (:Person {email: 'a@x.io'})");
    coord
        .create_node_property_index("Person", "email")
        .expect("create the (Person, email) index");

    // The reader begins HERE: its snapshot sees `email = 'a@x.io'`.
    let reader = coord.begin_serializable();

    // A writer moves the node OFF the sought value and commits, leaving a STALE index entry behind.
    // The reader's snapshot still resolves the node under the OLD value.
    run_write(
        &mut coord,
        "MATCH (n:Person) WHERE n.email = 'a@x.io' SET n.email = 'zz@x.io'",
    );

    let plan = compile(
        "MATCH (n:Person) WHERE n.email = 'a@x.io' RETURN n.email AS a",
        &coord.catalog(),
    );
    // NON-VACUITY: this must really lower to a seek. Were it a scan, the test could never observe the
    // defect (the scan is snapshot-correct) and would prove nothing.
    assert!(
        has_index_seek(&plan),
        "non-vacuity: the reader's plan must lower to a NodeIndexSeek, else this test cannot \
         observe the rebuild hazard at all:\n{plan}"
    );

    let before = run_plan(&coord, reader, &plan).len();
    assert_eq!(
        before, 1,
        "baseline: before any rebuild the reader must see the row under its own snapshot (the \
         stale index entry is still there). If this is 0 the test is vacuous."
    );

    // An index on a COMPLETELY UNRELATED property rebuilds EVERY node-property tree: clear() + a
    // newest-wins refill destroys the stale ('a@x.io' -> n) entry, while the index stays Online and
    // heal() clears `degraded`.
    coord
        .create_node_property_index("Person", "unrelated")
        .expect("create the unrelated (Person, unrelated) index");

    let after = run_plan(&coord, reader, &plan).len();
    assert_eq!(
        before, after,
        "rmp #765 ROW LOSS: an unrelated CREATE INDEX rebuilt (wiped + newest-wins refilled) the \
         node-property trees and destroyed the stale entry this reader's snapshot depends on, so \
         the inline seek returned a SUBSET and silently dropped a COMMITTED row (before={before}, \
         after={after}). The seek must DECLINE for a reader older than the rebuild and fall back \
         to the exact scan."
    );
}

/// `rmp` #765, the **relationship-property** tree: `rel_props` is stale-retaining
/// (`insert_rel_property` is its only per-entry mutator) over MVCC-versioned relationship property
/// values (they share `tombstone_props_for_key` + the prepend-and-filter chain with node properties),
/// so a rebuild's newest-wins refill destroys the entry an older snapshot depends on, exactly as for
/// `node_props`. Pre-fix this loses the row.
#[test]
fn an_unrelated_rebuild_must_not_lose_a_committed_rel_row_for_an_older_snapshot() {
    let mut coord = fresh_coord();
    run_write(
        &mut coord,
        "CREATE (:P {i: 1})-[:KNOWS {since: 1990}]->(:P {i: 2})",
    );
    coord
        .create_rel_property_index_named(None, "KNOWS", "since", false)
        .expect("create the (KNOWS, since) index");

    let reader = coord.begin_serializable();

    run_write(
        &mut coord,
        "MATCH ()-[r:KNOWS]->() WHERE r.since = 1990 SET r.since = 2020",
    );

    let src = "MATCH ()-[r:KNOWS]->() WHERE r.since = 1990 RETURN r.since AS a";
    let plan = compile(src, &coord.catalog());
    assert!(
        plan.to_string().contains("RelIndexSeek"),
        "non-vacuity: the reader's plan must lower to a RelIndexSeek, else this test cannot observe \
         the rebuild hazard:\n{plan}"
    );

    let before = run_plan(&coord, reader, &plan).len();
    assert_eq!(
        before, 1,
        "baseline: before the rebuild the reader sees the relationship under its own snapshot"
    );

    coord
        .create_node_property_index("P", "unrelated")
        .expect("create an unrelated index (rebuilds every tree)");

    let after = run_plan(&coord, reader, &plan).len();
    assert_eq!(
        before, after,
        "rmp #765 ROW LOSS (rel_props): an unrelated CREATE INDEX wiped + newest-wins refilled the \
         relationship-property tree, destroying the stale entry this reader's snapshot depends on \
         (before={before}, after={after})."
    );
}

/// `rmp` #765, the **node composite** tree. Strictly worse than the single-property case: overwriting
/// ANY ONE covered property destroys the entry for the whole old TUPLE, so a reader seeking
/// `(a_old, b_old)` misses even though only `b` changed.
#[test]
fn an_unrelated_rebuild_must_not_lose_a_committed_composite_row_for_an_older_snapshot() {
    let mut coord = fresh_coord();
    run_write(&mut coord, "CREATE (:Person {a: 1, b: 2})");
    coord
        .begin_online_node_composite_index_named(
            None,
            "Person",
            &["a".to_owned(), "b".to_owned()],
            false,
        )
        .expect("create the (Person, [a, b]) composite index");

    let reader = coord.begin_serializable();

    // Change ONE covered property: the whole (1, 2) tuple entry becomes stale.
    run_write(&mut coord, "MATCH (n:Person) WHERE n.a = 1 SET n.b = 99");

    let src = "MATCH (n:Person) WHERE n.a = 1 AND n.b = 2 RETURN n.a AS a";
    let plan = compile(src, &coord.catalog());
    assert!(
        plan.to_string().contains("NodeCompositeIndexSeek"),
        "non-vacuity: the reader's plan must lower to a NodeCompositeIndexSeek:\n{plan}"
    );

    let before = run_plan(&coord, reader, &plan).len();
    assert_eq!(
        before, 1,
        "baseline: before the rebuild the reader sees the (1, 2) tuple at its own snapshot"
    );

    coord
        .create_node_property_index("Person", "unrelated")
        .expect("create an unrelated index (rebuilds every tree)");

    let after = run_plan(&coord, reader, &plan).len();
    assert_eq!(
        before, after,
        "rmp #765 ROW LOSS (composite): an unrelated CREATE INDEX destroyed the stale tuple entry \
         this reader's snapshot depends on (before={before}, after={after})."
    );
}

/// `rmp` #765, the **relationship composite** tree — the rel twin of the composite case above.
#[test]
fn an_unrelated_rebuild_must_not_lose_a_committed_rel_composite_row_for_an_older_snapshot() {
    let mut coord = fresh_coord();
    run_write(
        &mut coord,
        "CREATE (:P {i: 1})-[:RATED {x: 1, y: 2}]->(:P {i: 2})",
    );
    coord
        .begin_online_rel_composite_index_named(
            None,
            "RATED",
            &["x".to_owned(), "y".to_owned()],
            false,
        )
        .expect("create the (RATED, [x, y]) composite index");

    let reader = coord.begin_serializable();

    run_write(
        &mut coord,
        "MATCH ()-[r:RATED]->() WHERE r.x = 1 SET r.y = 99",
    );

    let src = "MATCH ()-[r:RATED]->() WHERE r.x = 1 AND r.y = 2 RETURN r.x AS a";
    let plan = compile(src, &coord.catalog());
    assert!(
        plan.to_string().contains("RelCompositeIndexSeek"),
        "non-vacuity: the reader's plan must lower to a RelCompositeIndexSeek:\n{plan}"
    );

    let before = run_plan(&coord, reader, &plan).len();
    assert_eq!(
        before, 1,
        "baseline: before the rebuild the reader sees the (1, 2) rel tuple at its own snapshot"
    );

    coord
        .create_node_property_index("P", "unrelated")
        .expect("create an unrelated index (rebuilds every tree)");

    let after = run_plan(&coord, reader, &plan).len();
    assert_eq!(
        before, after,
        "rmp #765 ROW LOSS (rel_composite): an unrelated CREATE INDEX destroyed the stale rel tuple \
         entry this reader's snapshot depends on (before={before}, after={after})."
    );
}

/// `rmp` #765, the **node range** seek (`index_seek_range`). A range seek has no residual that could
/// resurrect a missing row, so the destroyed stale entry is lost outright.
#[test]
fn an_unrelated_rebuild_must_not_lose_a_committed_range_row_for_an_older_snapshot() {
    let mut coord = fresh_coord();
    run_write(&mut coord, "CREATE (:Person {age: 30})");
    coord
        .create_node_property_index("Person", "age")
        .expect("create the (Person, age) index");

    let reader = coord.begin_serializable();

    // Move the node BELOW the range's lower bound. The direction matters: `seek_node_property_range`
    // widens an INCLUSIVE upper bound to unbounded-above, so a value moved UP would still be a candidate
    // and the re-check would restore the row — the test would then pass at HEAD and prove nothing
    // (verified: it did). Moving it DOWN puts it outside the widened range, so the rebuilt tree really
    // cannot yield it and the seek must decline.
    run_write(
        &mut coord,
        "MATCH (n:Person) WHERE n.age = 30 SET n.age = 5",
    );

    let src = "MATCH (n:Person) WHERE n.age > 25 AND n.age < 40 RETURN n.age AS a";
    let plan = compile(src, &coord.catalog());
    assert!(
        has_index_range_seek(&plan),
        "non-vacuity: the reader's plan must lower to a NodeIndexRangeSeek:\n{plan}"
    );

    let before = run_plan(&coord, reader, &plan).len();
    assert_eq!(
        before, 1,
        "baseline: before the rebuild the reader sees age=30 at its own snapshot"
    );

    coord
        .create_node_property_index("Person", "unrelated")
        .expect("create an unrelated index (rebuilds every tree)");

    let after = run_plan(&coord, reader, &plan).len();
    assert_eq!(
        before, after,
        "rmp #765 ROW LOSS (node range): an unrelated CREATE INDEX destroyed the stale entry this \
         reader's snapshot depends on (before={before}, after={after})."
    );
}

/// `rmp` #765, the **relationship range** seek (`rel_index_seek_range`).
#[test]
fn an_unrelated_rebuild_must_not_lose_a_committed_rel_range_row_for_an_older_snapshot() {
    let mut coord = fresh_coord();
    run_write(
        &mut coord,
        "CREATE (:P {i: 1})-[:KNOWS {since: 1990}]->(:P {i: 2})",
    );
    coord
        .create_rel_property_index_named(None, "KNOWS", "since", false)
        .expect("create the (KNOWS, since) index");

    let reader = coord.begin_serializable();

    // BELOW the lower bound — see the node-range twin above for why the direction is load-bearing.
    run_write(
        &mut coord,
        "MATCH ()-[r:KNOWS]->() WHERE r.since = 1990 SET r.since = 1900",
    );

    let src = "MATCH ()-[r:KNOWS]->() WHERE r.since > 1980 AND r.since < 2000 RETURN r.since AS a";
    let plan = compile(src, &coord.catalog());
    assert!(
        plan.to_string().contains("RelIndexRangeSeek"),
        "non-vacuity: the reader's plan must lower to a RelIndexRangeSeek:\n{plan}"
    );

    let before = run_plan(&coord, reader, &plan).len();
    assert_eq!(
        before, 1,
        "baseline: before the rebuild the reader sees since=1990 at its own snapshot"
    );

    coord
        .create_node_property_index("P", "unrelated")
        .expect("create an unrelated index (rebuilds every tree)");

    let after = run_plan(&coord, reader, &plan).len();
    assert_eq!(
        before, after,
        "rmp #765 ROW LOSS (rel range): an unrelated CREATE INDEX destroyed the stale entry this \
         reader's snapshot depends on (before={before}, after={after})."
    );
}

/// `rmp` #765 on the **WRITE path**: an unrelated rebuild must not change a NODE KEY constraint's
/// verdict for a writer whose snapshot predates it.
///
/// # Why this seam is the dangerous one
///
/// `composite_seek_eq` is reached from `node_key_tuple_conflict`, the duplicate-detector behind NODE
/// KEY / composite uniqueness. If a rebuild leaves that seek a SUBSET, the detector finds no holder and
/// the duplicate is **admitted** — committed corrupt data, not a slow query. The gate makes the seek
/// decline for a pre-rebuild writer, which routes it to the exact label scan (`unwrap_or_else`).
///
/// # What is asserted (and what is deliberately NOT)
///
/// PARITY, not an absolute verdict: the same scenario is run twice — once with an unrelated
/// `CREATE INDEX` interposed, once without — and the two verdicts must AGREE. This pins the invariant
/// "a rebuild changes no answer" without this test having to decide what uniqueness-under-snapshot
/// *should* rule, which is a semantics question in its own right. Pre-fix the two disagree.
#[test]
fn an_unrelated_rebuild_must_not_change_a_node_key_verdict_for_an_older_writer() {
    // `run` performs the scenario, optionally interposing an unrelated rebuild, and reports whether the
    // duplicate CREATE was REJECTED.
    let run = |with_rebuild: bool| -> bool {
        let mut coord = fresh_coord();
        run_write(
            &mut coord,
            "CREATE (:Person {first: 'Ada', last: 'Lovelace'})",
        );
        coord
            .create_constraint_general(
                "person_key",
                "Person",
                &["first", "last"],
                graphus_cypher::ConstraintKind::NodeKey,
                None,
            )
            .expect("create node key over conforming data");

        // The writer begins HERE: its snapshot sees the holder as ('Ada', 'Lovelace').
        let writer = coord.begin_serializable();

        // A committed change moves the holder OFF that tuple, leaving the ('Ada','Lovelace') entry
        // stale — still the tuple the writer's snapshot sees.
        run_write(
            &mut coord,
            "MATCH (n:Person) WHERE n.first = 'Ada' SET n.last = 'Byron'",
        );

        if with_rebuild {
            coord
                .create_node_property_index("Person", "unrelated")
                .expect("create an unrelated index (rebuilds every tree)");
        }

        // The writer now tries to CREATE the very tuple its snapshot still sees held.
        let plan = compile(
            "CREATE (:Person {first: 'Ada', last: 'Lovelace'})",
            &IndexCatalog::empty(),
        );
        let bound = bind_parameters(&plan, &Parameters::new()).expect("bind");
        let captured = {
            let mut graph = coord.statement(writer).expect("statement");
            let mut cursor = execute(&plan, &bound, &mut graph).expect("open cursor");
            let _ = cursor.collect_all().expect("collect");
            drop(cursor);
            graph.take_error()
        };
        let _ = coord.rollback(writer);
        captured.is_some()
    };

    let without_rebuild = run(false);
    let with_rebuild = run(true);

    assert_eq!(
        without_rebuild, with_rebuild,
        "rmp #765 (write path): an unrelated CREATE INDEX changed the NODE KEY verdict for a writer \
         whose snapshot predates it (rejected without rebuild = {without_rebuild}, with rebuild = \
         {with_rebuild}). The rebuild wiped the composite tree and refilled it newest-wins, so the \
         duplicate detector's seek became a SUBSET and stopped seeing the holder — admitting a \
         duplicate. The seek must decline for a pre-rebuild writer and fall back to the exact scan."
    );
}
