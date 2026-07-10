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
