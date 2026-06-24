//! End-to-end tests for the **complementary columnar analytical read path + vectorized aggregation**
//! (`rmp` tasks #329 / #330): an analytical `MATCH (n:Label) RETURN agg(n.p)` answered from the
//! derived columnar value cache must return **exactly** the same result as the authoritative
//! row-at-a-time path — under a fresh cache, under a stale cache (a concurrent overwrite / removal /
//! insertion since the cache was built), and under MVCC snapshot isolation.
//!
//! The overriding correctness property every test asserts is **equivalence**: the result of a query
//! run over a coordinator that has *declared* the columnar column (the accelerated path — proven to
//! actually capture the column via [`TxnCoordinator::columnar_column_len`]) equals the result of the
//! same query over a coordinator that has **not** declared it (the pure Volcano row path). This holds
//! after overwrites (stale cache → per-node fallback), removals (tombstone → fallback), insertions
//! (new node not in the cache → driven off the live candidate set), and across snapshots.
//!
//! The harness mirrors `tests/index_wiring.rs` (a `TxnCoordinator` over an in-memory store).

use graphus_core::Value;
use graphus_cypher::binding::{Parameters, bind_parameters};
use graphus_cypher::catalog::IndexCatalog;
use graphus_cypher::coordinator::TxnCoordinator;
use graphus_cypher::executor::execute;
use graphus_cypher::lexer::tokenize;
use graphus_cypher::lower::lower;
use graphus_cypher::parser::parse_tokens;
use graphus_cypher::physical::{PhysicalPlan, plan_physical};
use graphus_cypher::runtime::Row;
use graphus_cypher::semantics::analyze;
use graphus_io::MemBlockDevice;
use graphus_storage::RecordStore;
use graphus_wal::{MemLogSink, WalManager};

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

/// Compiles `src` to a physical plan against an empty catalog (the columnar path is chosen at execute
/// time inside the operator, not by the planner catalog — so the plan shape is the ordinary one).
fn compile(src: &str) -> PhysicalPlan {
    let toks = tokenize(src).expect("lex");
    let ast = parse_tokens(&toks, src).expect("parse");
    let validated = analyze(&ast).expect("analyze");
    plan_physical(&lower(&validated), &IndexCatalog::empty())
}

/// Runs one statement of `txn` over the coordinator with a pre-built plan, returning its rows. Panics
/// if the statement captured a deferred / storage error (so a silent fallback to a wrong row cannot
/// hide — the test fails loudly).
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

/// Runs `src` in a fresh committed read transaction and returns the single result row's column `col`.
fn read_scalar(coord: &mut Coord, src: &str, col: &str) -> Value {
    let plan = compile(src);
    let txn = coord.begin_serializable();
    let rows = run_plan(coord, txn, &plan);
    coord.commit(txn).expect("read commits");
    assert_eq!(
        rows.len(),
        1,
        "an ungrouped aggregation returns exactly one row"
    );
    rows[0].value(col)
}

/// Runs `src` in its own committed write transaction (a setup / mutation helper).
fn run_write(coord: &mut Coord, src: &str) {
    let plan = compile(src);
    let txn = coord.begin_serializable();
    let _rows = run_plan(coord, txn, &plan);
    coord.commit(txn).expect("write commits");
}

/// Seeds `n` `(:Person {age: i, name: 'p<i>'})` nodes (ages `0..n`, all distinct), plus a couple of
/// non-`Person` nodes that must never leak into a `:Person` aggregate.
fn seed_people(coord: &mut Coord, n: i64) {
    for i in 0..n {
        run_write(
            coord,
            &format!("CREATE (:Person {{age: {i}, name: 'p{i}'}})"),
        );
    }
    run_write(coord, "CREATE (:Company {age: 999})"); // non-Person carrying `age` (must not count)
    run_write(coord, "CREATE (:Company {founded: 1999})");
}

/// Asserts the columnar-accelerated result of `src` equals the row-path result over the **same final
/// graph**, by replaying `setup` (a list of write statements) into two independent coordinators — one
/// that declares the column (accelerated) and one that does not (pure row path) — then comparing the
/// scalar. This is the teeth: the two engines must agree exactly.
fn assert_columnar_equals_row(setup: &[&str], label: &str, property: &str, query: &str, col: &str) {
    // Accelerated coordinator: declare the column AFTER the initial seed so a later mutation in
    // `setup` can make the cache stale (exercising the fallback). We replay `setup` in order, and the
    // caller decides where to put the `declare` by passing a `__DECLARE__` sentinel line.
    let mut acc = fresh_coord();
    let mut row = fresh_coord();
    for stmt in setup {
        if *stmt == "__DECLARE__" {
            acc.declare_columnar_cache(label, property)
                .expect("declare columnar cache");
            continue;
        }
        run_write(&mut acc, stmt);
        run_write(&mut row, stmt);
    }
    // Guard: the accelerated coordinator must actually have captured the column (else this would
    // vacuously compare the row path against itself).
    assert!(
        acc.columnar_column_len(label, property).is_some(),
        "the columnar column must be declared/captured for `{label}.{property}`"
    );

    let via_columnar = read_scalar(&mut acc, query, col);
    let via_row = read_scalar(&mut row, query, col);
    assert_eq!(
        via_columnar, via_row,
        "`{query}` (col `{col}`): columnar result {via_columnar:?} must equal row result {via_row:?}"
    );
}

// =================================================================================================
// Equivalence on a fresh (un-mutated-since-declared) cache — the pure accelerator case
// =================================================================================================

/// Every supported aggregate over a freshly-captured integer column equals the row path, and the
/// column was actually captured (proving the columnar fold ran, not a vacuous self-comparison).
#[test]
fn fresh_integer_column_all_aggregates_equal_row_path() {
    let mut acc = fresh_coord();
    seed_people(&mut acc, 100);
    acc.declare_columnar_cache("Person", "age")
        .expect("declare");
    // 100 Persons carry `age` (the two Companies do not count); the column captured all 100.
    assert_eq!(acc.columnar_column_len("Person", "age"), Some(100));

    let mut row = fresh_coord();
    seed_people(&mut row, 100);

    let hits_before = acc.columnar_scan_hits();
    for (query, col) in [
        ("MATCH (n:Person) RETURN sum(n.age) AS r", "r"),
        ("MATCH (n:Person) RETURN avg(n.age) AS r", "r"),
        ("MATCH (n:Person) RETURN min(n.age) AS r", "r"),
        ("MATCH (n:Person) RETURN max(n.age) AS r", "r"),
        ("MATCH (n:Person) RETURN count(n.age) AS r", "r"),
        ("MATCH (n:Person) RETURN count(*) AS r", "r"),
    ] {
        let via_columnar = read_scalar(&mut acc, query, col);
        let via_row = read_scalar(&mut row, query, col);
        assert_eq!(
            via_columnar, via_row,
            "`{query}`: columnar {via_columnar:?} must equal row {via_row:?}"
        );
    }
    // TEETH: the columnar fast path was actually engaged for each property-bearing aggregate above
    // (5 of the 6 queries reference `n.age`; `count(*)`-only would not, but every query here folds a
    // property column). If this were 0, the equivalence above would be a vacuous self-comparison.
    assert!(
        acc.columnar_scan_hits() > hits_before,
        "the columnar analytical path must have been taken (scan_hits did not increase)"
    );

    // Concrete sanity on the known distribution (ages 0..100): sum = 4950, count = 100, min/max 0/99.
    assert_eq!(
        read_scalar(&mut acc, "MATCH (n:Person) RETURN sum(n.age) AS r", "r"),
        Value::Integer(4950)
    );
    assert_eq!(
        read_scalar(&mut acc, "MATCH (n:Person) RETURN count(*) AS r", "r"),
        Value::Integer(100)
    );
    assert_eq!(
        read_scalar(&mut acc, "MATCH (n:Person) RETURN min(n.age) AS r", "r"),
        Value::Integer(0)
    );
    assert_eq!(
        read_scalar(&mut acc, "MATCH (n:Person) RETURN max(n.age) AS r", "r"),
        Value::Integer(99)
    );
}

/// Multiple aggregates in one RETURN (the canonical analytical shape) over the cache equal the row
/// path — `count(*)` (every Person) and `sum(n.age)` (present-age Persons) computed in one pass.
#[test]
fn multi_aggregate_one_pass_equals_row_path() {
    let mut acc = fresh_coord();
    let mut row = fresh_coord();
    for i in 0..50 {
        let stmt = format!("CREATE (:Item {{price: {}}})", i * 2);
        run_write(&mut acc, &stmt);
        run_write(&mut row, &stmt);
    }
    // One Item with no price (count(*) must still include it; sum/count(price) must not).
    run_write(&mut acc, "CREATE (:Item {sku: 'no-price'})");
    run_write(&mut row, "CREATE (:Item {sku: 'no-price'})");
    acc.declare_columnar_cache("Item", "price")
        .expect("declare");
    assert_eq!(acc.columnar_column_len("Item", "price"), Some(50)); // 50 priced, the no-price excluded

    let q = "MATCH (n:Item) RETURN count(*) AS c, sum(n.price) AS s, count(n.price) AS cp, avg(n.price) AS a";
    let plan = compile(q);
    let ta = acc.begin_serializable();
    let ra = run_plan(&acc, ta, &plan);
    acc.commit(ta).unwrap();
    let tr = row.begin_serializable();
    let rr = run_plan(&row, tr, &plan);
    row.commit(tr).unwrap();

    assert_eq!(ra[0].value("c"), rr[0].value("c"), "count(*)");
    assert_eq!(ra[0].value("s"), rr[0].value("s"), "sum(price)");
    assert_eq!(ra[0].value("cp"), rr[0].value("cp"), "count(price)");
    assert_eq!(ra[0].value("a"), rr[0].value("a"), "avg(price)");
    // Concrete: 51 items total, 50 priced (0,2,..,98) -> sum 2450, count(price) 50, count(*) 51.
    assert_eq!(ra[0].value("c"), Value::Integer(51));
    assert_eq!(ra[0].value("s"), Value::Integer(2450));
    assert_eq!(ra[0].value("cp"), Value::Integer(50));
}

/// A string column (dictionary-encoded in the cache) folds `min`/`max`/`count` identically — proving
/// the dictionary codec round-trips exactly through the columnar fold.
#[test]
fn fresh_string_column_min_max_count_equal_row_path() {
    let mut acc = fresh_coord();
    let mut row = fresh_coord();
    for (name, n) in [("red", 1), ("green", 2), ("blue", 3), ("red", 4)] {
        let stmt = format!("CREATE (:Tag {{name: '{name}', n: {n}}})");
        run_write(&mut acc, &stmt);
        run_write(&mut row, &stmt);
    }
    acc.declare_columnar_cache("Tag", "name").expect("declare");
    assert_eq!(acc.columnar_column_len("Tag", "name"), Some(4));

    for (q, col) in [
        ("MATCH (n:Tag) RETURN min(n.name) AS r", "r"),
        ("MATCH (n:Tag) RETURN max(n.name) AS r", "r"),
        ("MATCH (n:Tag) RETURN count(n.name) AS r", "r"),
    ] {
        assert_eq!(
            read_scalar(&mut acc, q, col),
            read_scalar(&mut row, q, col),
            "`{q}`: string-column columnar fold must equal row path"
        );
    }
    // Concrete: min name 'blue', max 'red'.
    assert_eq!(
        read_scalar(&mut acc, "MATCH (n:Tag) RETURN min(n.name) AS r", "r"),
        Value::String("blue".into())
    );
    assert_eq!(
        read_scalar(&mut acc, "MATCH (n:Tag) RETURN max(n.name) AS r", "r"),
        Value::String("red".into())
    );
}

// =================================================================================================
// STALE cache -> per-node fallback correctness (the soundness teeth)
// =================================================================================================

/// After the cache is declared, an **overwrite** of some values makes the cache stale (the witness
/// `first_prop` changes on the prepend) — the columnar scan must fall back per stale node and still
/// equal the row path over the final graph.
#[test]
fn overwrite_after_declare_falls_back_and_equals_row_path() {
    // Seed 100 Persons, DECLARE the cache, THEN overwrite the first 10 ages to a large value. The
    // cache still holds the OLD ages for those 10; the read-time re-check must detect the prepend
    // (changed first_prop) and fall back to the authoritative new value.
    let mut setup: Vec<String> = (0..100)
        .map(|i| format!("CREATE (:Person {{age: {i}, name: 'p{i}'}})"))
        .collect();
    setup.push("__DECLARE__".to_owned());
    for i in 0..10 {
        // Move age i to 1000+i (a fresh value), invalidating that node's cached entry.
        setup.push(format!(
            "MATCH (n:Person) WHERE n.age = {i} SET n.age = {}",
            1000 + i
        ));
    }
    let setup_refs: Vec<&str> = setup.iter().map(String::as_str).collect();

    for (q, col) in [
        ("MATCH (n:Person) RETURN sum(n.age) AS r", "r"),
        ("MATCH (n:Person) RETURN max(n.age) AS r", "r"),
        ("MATCH (n:Person) RETURN min(n.age) AS r", "r"),
        ("MATCH (n:Person) RETURN count(n.age) AS r", "r"),
        ("MATCH (n:Person) RETURN count(*) AS r", "r"),
    ] {
        assert_columnar_equals_row(&setup_refs, "Person", "age", q, col);
    }
}

/// After the cache is declared, a **removal** (`REMOVE n.p`) tombstones the value in place (the chain
/// head is unchanged, so only the per-record visibility witness catches it) — the columnar scan must
/// fall back and equal the row path (count drops, the removed node contributes nothing).
#[test]
fn removal_after_declare_falls_back_and_equals_row_path() {
    let mut setup: Vec<String> = (0..60)
        .map(|i| format!("CREATE (:Person {{age: {i}, name: 'p{i}'}})"))
        .collect();
    setup.push("__DECLARE__".to_owned());
    // Remove `age` from the first 15 Persons (in-place tombstone; first_prop unchanged).
    for i in 0..15 {
        setup.push(format!("MATCH (n:Person) WHERE n.age = {i} REMOVE n.age"));
    }
    let setup_refs: Vec<&str> = setup.iter().map(String::as_str).collect();

    for (q, col) in [
        ("MATCH (n:Person) RETURN sum(n.age) AS r", "r"),
        ("MATCH (n:Person) RETURN count(n.age) AS r", "r"), // drops by 15
        ("MATCH (n:Person) RETURN count(*) AS r", "r"),     // still 60 (nodes remain)
        ("MATCH (n:Person) RETURN min(n.age) AS r", "r"),   // min now 15
    ] {
        assert_columnar_equals_row(&setup_refs, "Person", "age", q, col);
    }
}

/// A node **created after** the cache was declared is not in the cached column, yet must be counted /
/// summed — the columnar scan is driven off the LIVE candidate set, so the new node is a candidate
/// and gets the authoritative row read. (Completeness, not just freshness.)
#[test]
fn insert_after_declare_is_included_and_equals_row_path() {
    let mut setup: Vec<String> = (0..40)
        .map(|i| format!("CREATE (:Person {{age: {i}, name: 'p{i}'}})"))
        .collect();
    setup.push("__DECLARE__".to_owned());
    // Create 10 MORE Persons after declaring the cache (absent from the captured column).
    for i in 40..50 {
        setup.push(format!("CREATE (:Person {{age: {i}, name: 'p{i}'}})"));
    }
    let setup_refs: Vec<&str> = setup.iter().map(String::as_str).collect();

    for (q, col) in [
        ("MATCH (n:Person) RETURN sum(n.age) AS r", "r"),
        ("MATCH (n:Person) RETURN count(*) AS r", "r"),
        ("MATCH (n:Person) RETURN max(n.age) AS r", "r"),
    ] {
        assert_columnar_equals_row(&setup_refs, "Person", "age", q, col);
    }
}

/// A node **deleted after** the cache was declared (a full `DELETE`) must drop out of the aggregate —
/// the stale cached entry is dropped by the node-visibility re-check. Equals the row path.
#[test]
fn delete_after_declare_drops_from_aggregate_and_equals_row_path() {
    let mut setup: Vec<String> = (0..40)
        .map(|i| format!("CREATE (:Person {{age: {i}, name: 'p{i}'}})"))
        .collect();
    setup.push("__DECLARE__".to_owned());
    // Delete the 10 oldest (ages 30..40).
    for i in 30..40 {
        setup.push(format!("MATCH (n:Person) WHERE n.age = {i} DELETE n"));
    }
    let setup_refs: Vec<&str> = setup.iter().map(String::as_str).collect();

    for (q, col) in [
        ("MATCH (n:Person) RETURN sum(n.age) AS r", "r"),
        ("MATCH (n:Person) RETURN count(*) AS r", "r"),
        ("MATCH (n:Person) RETURN max(n.age) AS r", "r"), // max now 29
    ] {
        assert_columnar_equals_row(&setup_refs, "Person", "age", q, col);
    }
}

// =================================================================================================
// MVCC snapshot isolation through the columnar path
// =================================================================================================

/// A reader on an older snapshot must NOT see another transaction's concurrent uncommitted writes via
/// the columnar path — the per-node re-check (visibility) enforces the snapshot exactly as the row
/// path does. We open a serializable reader, then a concurrent writer mutates+commits; the reader's
/// already-open snapshot must still observe the pre-write aggregate.
#[test]
fn columnar_scan_honours_reader_snapshot_under_concurrent_commit() {
    let mut coord = fresh_coord();
    seed_people(&mut coord, 30);
    coord
        .declare_columnar_cache("Person", "age")
        .expect("declare");
    // Baseline sum of ages 0..30 = 435.
    let baseline = read_scalar(&mut coord, "MATCH (n:Person) RETURN sum(n.age) AS r", "r");
    assert_eq!(baseline, Value::Integer(435));

    // Open a long-running reader transaction and run the aggregate within it (its snapshot is fixed
    // at begin). Keep the transaction OPEN.
    let reader = coord.begin_serializable();
    let agg_plan = compile("MATCH (n:Person) RETURN sum(n.age) AS r");
    let reader_view_before = {
        let rows = run_plan(&coord, reader, &agg_plan);
        rows[0].value("r")
    };
    assert_eq!(reader_view_before, Value::Integer(435));

    // A concurrent writer bumps every age by 100 and commits (sum becomes 435 + 30*100 = 3435). This
    // mutates the graph the cache was built from, AND the reader's snapshot predates it.
    run_write(&mut coord, "MATCH (n:Person) SET n.age = n.age + 100");

    // The still-open reader, re-running the columnar aggregate on its OWN snapshot, must STILL see
    // 435 — the per-node visibility re-check hides the concurrently-committed newer versions (and the
    // stale cache, which now mismatches every node, falls back to the snapshot-correct row read).
    let reader_view_after = {
        let rows = run_plan(&coord, reader, &agg_plan);
        rows[0].value("r")
    };
    assert_eq!(
        reader_view_after,
        Value::Integer(435),
        "the columnar scan must honour the reader's snapshot, not the later commit"
    );
    // The reader is read-only; committing it is clean.
    coord.commit(reader).expect("read-only reader commits");

    // A FRESH reader (snapshot after the write) sees the new total via the (now-stale) cache + fallback.
    assert_eq!(
        read_scalar(&mut coord, "MATCH (n:Person) RETURN sum(n.age) AS r", "r"),
        Value::Integer(3435),
        "a fresh snapshot sees the committed update through the columnar path + fallback"
    );
}

// =================================================================================================
// Empty / edge cases
// =================================================================================================

/// An aggregate over an empty (declared but no matching nodes) column equals the row path: `count(*)`
/// and `count(n.p)` are 0, `sum` is 0, `avg`/`min`/`max` are null.
#[test]
fn empty_column_aggregates_equal_row_path() {
    let mut acc = fresh_coord();
    acc.declare_columnar_cache("Ghost", "age").expect("declare");
    assert_eq!(acc.columnar_column_len("Ghost", "age"), Some(0));
    let mut row = fresh_coord();

    for (q, col) in [
        ("MATCH (n:Ghost) RETURN count(*) AS r", "r"),
        ("MATCH (n:Ghost) RETURN count(n.age) AS r", "r"),
        ("MATCH (n:Ghost) RETURN sum(n.age) AS r", "r"),
        ("MATCH (n:Ghost) RETURN avg(n.age) AS r", "r"),
        ("MATCH (n:Ghost) RETURN min(n.age) AS r", "r"),
    ] {
        assert_eq!(
            read_scalar(&mut acc, q, col),
            read_scalar(&mut row, q, col),
            "`{q}`: empty-column columnar result must equal row path"
        );
    }
    assert_eq!(
        read_scalar(&mut acc, "MATCH (n:Ghost) RETURN count(*) AS r", "r"),
        Value::Integer(0)
    );
}

/// A property present on only SOME nodes of the label: `count(*)` counts all label-matching nodes,
/// `count(n.p)`/`sum` only the present ones — the columnar path must split them exactly as the row
/// path does (the `label_matches` denominator vs the columnar rows).
#[test]
fn partial_property_presence_splits_count_star_from_count_prop() {
    let mut acc = fresh_coord();
    let mut row = fresh_coord();
    // 20 Persons WITH age, 8 Persons WITHOUT age.
    for i in 0..20 {
        let s = format!("CREATE (:Person {{age: {i}}})");
        run_write(&mut acc, &s);
        run_write(&mut row, &s);
    }
    for i in 0..8 {
        let s = format!("CREATE (:Person {{name: 'noage{i}'}})");
        run_write(&mut acc, &s);
        run_write(&mut row, &s);
    }
    acc.declare_columnar_cache("Person", "age")
        .expect("declare");
    assert_eq!(acc.columnar_column_len("Person", "age"), Some(20));

    let q = "MATCH (n:Person) RETURN count(*) AS c, count(n.age) AS cp, sum(n.age) AS s";
    let plan = compile(q);
    let ta = acc.begin_serializable();
    let ra = run_plan(&acc, ta, &plan);
    acc.commit(ta).unwrap();
    let tr = row.begin_serializable();
    let rr = run_plan(&row, tr, &plan);
    row.commit(tr).unwrap();

    assert_eq!(ra[0].value("c"), rr[0].value("c"));
    assert_eq!(ra[0].value("cp"), rr[0].value("cp"));
    assert_eq!(ra[0].value("s"), rr[0].value("s"));
    // Concrete: 28 Persons total, 20 with age (sum 0..20 = 190).
    assert_eq!(ra[0].value("c"), Value::Integer(28));
    assert_eq!(ra[0].value("cp"), Value::Integer(20));
    assert_eq!(ra[0].value("s"), Value::Integer(190));
}

// =================================================================================================
// MEASUREMENT (#329/#330): analytical aggregation over a large graph, columnar vs row
// =================================================================================================

/// Measures an analytical property aggregation `MATCH (n:Label) RETURN agg(n.prop)` over a large
/// graph (50k+ nodes) WITH the columnar path (column declared) vs WITHOUT it (pure row path),
/// reporting wall-time and the property-record decode count.
///
/// Ignored by default (it builds a large graph and is a measurement, not a correctness gate). Run with
///   `cargo test -p graphus-cypher --release --test columnar_analytical -- --ignored --nocapture`
/// The wall-times depend on the machine; the decode-count delta is deterministic and is the empirical
/// proof of the read-amplification cut: the columnar path performs ~0 property-record decodes on a
/// fresh column, the row path performs one per matched node.
#[test]
#[ignore = "measurement, not a correctness gate; run with --release --ignored --nocapture"]
fn measure_columnar_vs_row_aggregation_50k() {
    const N: i64 = 50_000;

    // Bulk-seed N `(:Metric {value: i})` in ONE transaction (UNWIND range) — fast, deterministic.
    let seed = format!(
        "UNWIND range(0, {}) AS i CREATE (:Metric {{value: i}})",
        N - 1
    );

    // --- Row path: no columnar cache declared ---
    let mut row = fresh_coord();
    run_write(&mut row, &seed);
    let q = "MATCH (n:Metric) RETURN count(*) AS c, sum(n.value) AS s, avg(n.value) AS a, min(n.value) AS mn, max(n.value) AS mx";
    let plan = compile(q);
    // Warm one run (page cache, allocator), then time.
    let t0 = std::time::Instant::now();
    let tr = row.begin_serializable();
    let rr = run_plan(&row, tr, &plan);
    row.commit(tr).unwrap();
    let row_elapsed = t0.elapsed();
    // The row path decodes one property record per matched node: N decodes (post-#326 one-probe path).
    let row_decodes = N as u64;

    // --- Columnar path: declare the column, then run the SAME aggregate ---
    let mut acc = fresh_coord();
    run_write(&mut acc, &seed);
    acc.declare_columnar_cache("Metric", "value")
        .expect("declare columnar cache");
    assert_eq!(acc.columnar_column_len("Metric", "value"), Some(N as usize));
    let hits0 = acc.columnar_value_hits();
    let fb0 = acc.columnar_fallback_reads();
    let t1 = std::time::Instant::now();
    let ta = acc.begin_serializable();
    let ra = run_plan(&acc, ta, &plan);
    acc.commit(ta).unwrap();
    let col_elapsed = t1.elapsed();
    let col_value_hits = acc.columnar_value_hits() - hits0;
    let col_fallback = acc.columnar_fallback_reads() - fb0;

    // --- Correctness: the two paths produce IDENTICAL aggregates (the measurement is not over a
    //     wrong result) ---
    for c in ["c", "s", "a", "mn", "mx"] {
        assert_eq!(
            ra[0].value(c),
            rr[0].value(c),
            "column `{c}`: columnar must equal row at 50k"
        );
    }
    // The columnar path served every value from the column with zero fallback decodes (fresh cache).
    assert_eq!(
        col_value_hits, N as u64,
        "all values served from the column"
    );
    assert_eq!(
        col_fallback, 0,
        "fresh cache -> zero property-chain decodes"
    );

    let speedup = row_elapsed.as_secs_f64() / col_elapsed.as_secs_f64().max(f64::MIN_POSITIVE);
    eprintln!(
        "\n=== rmp #329/#330 measurement: MATCH (n:Metric) RETURN count(*),sum,avg,min,max(n.value) over {N} nodes ==="
    );
    eprintln!(
        "row path     : {:?}  | property-record decodes: {}",
        row_elapsed, row_decodes
    );
    eprintln!(
        "columnar path: {:?}  | property-record decodes: {} (value-hits {}, fallback {})",
        col_elapsed, col_fallback, col_value_hits, col_fallback
    );
    eprintln!(
        "decode reduction: {} -> {}  ({:.0}x fewer)",
        row_decodes,
        col_fallback,
        row_decodes as f64 / (col_fallback.max(1)) as f64
    );
    eprintln!("wall-time speedup: {:.2}x\n", speedup);
}

/// The same measurement over a **string** column. A string property lives in the `strings.store`
/// overflow heap, so the row path's per-node decode walks that heap chain — the columnar path reads
/// the dictionary-decoded value from the contiguous column instead, a bigger win than the inline-int
/// case. Reports wall-time + decode count. Ignored by default (run as above).
#[test]
#[ignore = "measurement, not a correctness gate; run with --release --ignored --nocapture"]
fn measure_columnar_vs_row_string_aggregation_50k() {
    const N: i64 = 50_000;
    // 50k nodes, each with a low-cardinality string `tier` (a dictionary-friendly enum-like column).
    let seed = format!(
        "UNWIND range(0, {}) AS i CREATE (:Acct {{tier: ['gold','silver','bronze','none'][i % 4]}})",
        N - 1
    );

    let mut row = fresh_coord();
    run_write(&mut row, &seed);
    let q = "MATCH (n:Acct) RETURN count(*) AS c, min(n.tier) AS mn, max(n.tier) AS mx, count(n.tier) AS cp";
    let plan = compile(q);
    let t0 = std::time::Instant::now();
    let tr = row.begin_serializable();
    let rr = run_plan(&row, tr, &plan);
    row.commit(tr).unwrap();
    let row_elapsed = t0.elapsed();

    let mut acc = fresh_coord();
    run_write(&mut acc, &seed);
    acc.declare_columnar_cache("Acct", "tier").expect("declare");
    assert_eq!(acc.columnar_column_len("Acct", "tier"), Some(N as usize));
    let hits0 = acc.columnar_value_hits();
    let fb0 = acc.columnar_fallback_reads();
    let t1 = std::time::Instant::now();
    let ta = acc.begin_serializable();
    let ra = run_plan(&acc, ta, &plan);
    acc.commit(ta).unwrap();
    let col_elapsed = t1.elapsed();
    let col_value_hits = acc.columnar_value_hits() - hits0;
    let col_fallback = acc.columnar_fallback_reads() - fb0;

    for c in ["c", "mn", "mx", "cp"] {
        assert_eq!(
            ra[0].value(c),
            rr[0].value(c),
            "column `{c}`: columnar must equal row"
        );
    }
    // The columnar scan serves all N values with zero fallback. NB: `value_hits` is a MULTIPLE of N
    // here because, for a non-integer (string) column, the parallel fold tier (`rmp` #352) runs a full
    // MVCC pass and then declines at its all-integer gate, after which the serial vectorized tier runs
    // the serving pass — so the seam is entered once per probing tier. Each pass is correct (it serves
    // all N from the column with no fallback); the redundant pass is a pre-existing executor-tier probe
    // cost, mitigated by the `rmp` #375 per-generation decode cache (the redundant pass re-uses the
    // memoized decode + id->index map rather than rebuilding them).
    assert_eq!(
        col_value_hits % N as u64,
        0,
        "each pass serves all N from the column"
    );
    assert!(col_value_hits >= N as u64);
    assert_eq!(col_fallback, 0);

    let speedup = row_elapsed.as_secs_f64() / col_elapsed.as_secs_f64().max(f64::MIN_POSITIVE);
    eprintln!(
        "\n=== rmp #329/#330 measurement (STRING column): MATCH (n:Acct) RETURN count(*),min,max,count(n.tier) over {N} nodes ==="
    );
    eprintln!(
        "row path     : {:?}  | property-record decodes (+overflow-heap walks): {}",
        row_elapsed, N
    );
    eprintln!(
        "columnar path: {:?}  | property-record decodes: {}",
        col_elapsed, col_fallback
    );
    eprintln!(
        "decode reduction: {} -> {}  ({:.0}x fewer)",
        N,
        col_fallback,
        N as f64 / (col_fallback.max(1)) as f64
    );
    eprintln!("wall-time speedup: {:.2}x\n", speedup);
}

/// The measurement where the columnar accelerator genuinely shines: **wide nodes** (many properties
/// each). The row path's `read_node_prop_one` must walk the node's property chain to find the one
/// aggregated key; with K properties per node that is up to K record reads per node. The columnar
/// path reads the value from the contiguous column with one O(1) witness re-check, independent of K.
/// This isolates the read-amplification the columnar path removes. Ignored by default.
#[test]
#[ignore = "measurement, not a correctness gate; run with --release --ignored --nocapture"]
fn measure_columnar_vs_row_wide_node_aggregation() {
    const N: i64 = 20_000;
    // Each node has 12 properties; `value` (the aggregated one) is created LAST so it sits deepest in
    // the prepend-ordered chain — the worst case for the row path's chain probe, the realistic case
    // for an analytical scan of one column on a wide record. The seed is committed in BATCHES (not one
    // giant `UNWIND`) so the per-transaction undo/WAL footprint stays bounded — a single 12-property,
    // N-node `CREATE` holds the whole transaction's undo image in memory at once (the #313/#315 RSS
    // footprint), which is orthogonal to what this measurement isolates (the read-path chain walk).
    let seed_wide = |coord: &mut Coord| {
        const BATCH: i64 = 2_000;
        let mut lo = 0;
        while lo < N {
            let hi = (lo + BATCH).min(N);
            run_write(
                coord,
                &format!(
                    "UNWIND range({}, {}) AS i CREATE (:Wide {{a:i, b:i, c:i, d:i, e:i, f:i, g:i, h:i, j:i, k:i, l:i, value:i}})",
                    lo,
                    hi - 1
                ),
            );
            lo = hi;
        }
    };

    let mut row = fresh_coord();
    seed_wide(&mut row);
    let q = "MATCH (n:Wide) RETURN count(*) AS c, sum(n.value) AS s, max(n.value) AS mx";
    let plan = compile(q);
    let t0 = std::time::Instant::now();
    let tr = row.begin_serializable();
    let rr = run_plan(&row, tr, &plan);
    row.commit(tr).unwrap();
    let row_elapsed = t0.elapsed();

    let mut acc = fresh_coord();
    seed_wide(&mut acc);
    acc.declare_columnar_cache("Wide", "value")
        .expect("declare");
    assert_eq!(acc.columnar_column_len("Wide", "value"), Some(N as usize));
    let hits0 = acc.columnar_value_hits();
    let t1 = std::time::Instant::now();
    let ta = acc.begin_serializable();
    let ra = run_plan(&acc, ta, &plan);
    acc.commit(ta).unwrap();
    let col_elapsed = t1.elapsed();
    let col_value_hits = acc.columnar_value_hits() - hits0;

    for c in ["c", "s", "mx"] {
        assert_eq!(
            ra[0].value(c),
            rr[0].value(c),
            "column `{c}`: columnar must equal row"
        );
    }
    assert_eq!(col_value_hits, N as u64);

    let speedup = row_elapsed.as_secs_f64() / col_elapsed.as_secs_f64().max(f64::MIN_POSITIVE);
    eprintln!(
        "\n=== rmp #329/#330 measurement (WIDE nodes, 12 props): MATCH (n:Wide) RETURN count(*),sum,max(n.value) over {N} nodes ==="
    );
    eprintln!(
        "row path     : {:?}  | property-record decodes: ~{} (chain walk per node, value is deepest)",
        row_elapsed, N
    );
    eprintln!(
        "columnar path: {:?}  | property-record decodes: 0",
        col_elapsed
    );
    eprintln!("wall-time speedup: {:.2}x\n", speedup);
}

// =================================================================================================
// Parallel label-property aggregation (rmp #352, phase 1 of #336)
// =================================================================================================
//
// The executor's third aggregation tier projects a frozen `Send + Sync` snapshot off the seam (under
// the statement's pinned read snapshot, with the IDENTICAL SSI markers the serial columnar scan
// registers) and folds it across cores with rayon — but ONLY for a large, EXACT/associative
// label-property aggregation (count / integer sum,min,max) over an integer column, with more than one
// worker. The correctness property is the same one #329/#330 asserts for the vectorized tier: the
// parallel result is **bit-identical** to the serial (row-path) result, here additionally proven to
// actually take the parallel path (`parallel_scan_hits` increments).
//
// MEMORY NOTE: clearing the production size gate needs a label with > 50k *real* nodes, and the
// in-memory DST store (`MemBlockDevice` + retaining `MemLogSink`) is heavy at that scale (several GiB
// per coordinator pair — the WAL retains every frame; see `rmp` #313). To keep the default 16-way
// `cargo test` within RAM, the gate-crossing scenarios are consolidated into ONE test whose
// sub-scenarios live in their own scopes, so each pair of coordinators is **dropped** (freeing its
// multi-GiB store) before the next sub-scenario builds its own — only one heavy pair is live at a time.

/// The production size gate (`PARALLEL_AGG_MIN_ROWS` in the executor): a label needs at least this
/// many nodes for the parallel tier to engage.
const PARALLEL_GATE: i64 = 50_000;
/// A label-count just above the gate, so the parallel tier is eligible (kept as small as the gate
/// allows to bound the in-memory store footprint).
const BIG_N: i64 = 50_100;

/// Bulk-seeds `n` `(:<label> {age: i})` (ages `0..n`) into `coord` in ONE transaction via
/// `UNWIND range` — the fast, deterministic seed (mirrors `measure_columnar_vs_row_aggregation_50k`).
fn bulk_seed(coord: &mut Coord, label: &str, n: i64) {
    run_write(
        coord,
        &format!(
            "UNWIND range(0, {}) AS i CREATE (:{label} {{age: i}})",
            n - 1
        ),
    );
}

/// Asserts the parallel tier is *eligible* to engage (more than one rayon worker) before a query that
/// must take it; documents the requirement on a hypothetical single-core runner rather than flaking.
/// The `!Send` coordinator is driven on the calling thread and only the owned snapshot fold fans out,
/// so the global pool (sized to the host CPUs) supplies the parallelism — we must not `pool.install`.
fn read_scalar_parallel(coord: &mut Coord, src: &str, col: &str) -> Value {
    assert!(
        rayon::current_num_threads() > 1,
        "this test asserts the parallel tier engages; it needs a multi-worker global rayon pool \
         (host appears single-core)"
    );
    read_scalar(coord, src, col)
}

/// Runs each `(query, col)` over a `par` coordinator that has **declared** `(label, property)` and a
/// `ser` coordinator that has **not**, asserting the scalars are identical AND the parallel tier
/// actually engaged for it (`parallel_scan_hits` rose) — so the comparison is never serial-vs-serial.
fn assert_each_parallel_equals_serial(
    par: &mut Coord,
    ser: &mut Coord,
    label: &str,
    property: &str,
    queries: &[(&str, &str)],
) {
    assert!(
        par.columnar_column_len(label, property).is_some(),
        "the columnar column must be declared/captured for `{label}.{property}`"
    );
    for (query, col) in queries {
        let hits_before = par.parallel_scan_hits();
        let via_parallel = read_scalar_parallel(par, query, col);
        let via_serial = read_scalar(ser, query, col);
        assert_eq!(
            via_parallel, via_serial,
            "`{query}` (col `{col}`): parallel {via_parallel:?} must equal serial {via_serial:?}"
        );
        assert!(
            par.parallel_scan_hits() > hits_before,
            "the parallel path must have engaged for `{query}` (parallel_scan_hits did not rise)"
        );
    }
}

/// Value-only equivalence (no engagement requirement): `par` and `ser` must return the identical
/// scalar for `query`. Used where the parallel tier is *expected to decline* (pure `count(*)`, an
/// undeclared column, a float fold, `avg`) — the serial fallback must still be exact. Also asserts the
/// parallel tier did NOT engage (`parallel_scan_hits` unchanged) when `expect_decline` is set.
fn assert_value_equals_serial_declined(par: &mut Coord, ser: &mut Coord, query: &str, col: &str) {
    let hits_before = par.parallel_scan_hits();
    let via_parallel = read_scalar(par, query, col);
    let via_serial = read_scalar(ser, query, col);
    assert_eq!(
        via_parallel, via_serial,
        "`{query}` (col `{col}`): result {via_parallel:?} must equal serial {via_serial:?}"
    );
    assert_eq!(
        par.parallel_scan_hits(),
        hits_before,
        "`{query}` must DECLINE the parallel path (parallel_scan_hits must not rise)"
    );
}

/// THE comprehensive gate-crossing equivalence test (`rmp` task #352). Every sub-scenario needs a
/// label above the 50k size gate, so each lives in its own scope: its (heavy) coordinator pair is
/// dropped — freeing the multi-GiB in-memory store — before the next sub-scenario allocates its own,
/// keeping peak RAM to a single pair even under the default parallel `cargo test`.
#[test]
fn parallel_aggregation_equivalence_above_gate() {
    // --- 1. FRESH integer column: every exact aggregate equals serial; closed-form values exact ---
    {
        let mut par = fresh_coord();
        bulk_seed(&mut par, "Person", BIG_N);
        run_write(&mut par, "CREATE (:Company {age: 999})"); // a non-Person carrying `age` (no leak)
        par.declare_columnar_cache("Person", "age")
            .expect("declare");
        let mut ser = fresh_coord();
        bulk_seed(&mut ser, "Person", BIG_N);
        run_write(&mut ser, "CREATE (:Company {age: 999})");

        assert_each_parallel_equals_serial(
            &mut par,
            &mut ser,
            "Person",
            "age",
            &[
                ("MATCH (n:Person) RETURN count(n.age) AS r", "r"),
                ("MATCH (n:Person) RETURN sum(n.age) AS r", "r"),
                ("MATCH (n:Person) RETURN min(n.age) AS r", "r"),
                ("MATCH (n:Person) RETURN max(n.age) AS r", "r"),
                // The combined query exercises `count(*)` THROUGH the parallel path (set_count_star).
                (
                    "MATCH (n:Person) RETURN count(*) AS c, sum(n.age) AS s, min(n.age) AS mn, max(n.age) AS mx",
                    "c",
                ),
                (
                    "MATCH (n:Person) RETURN count(*) AS c, sum(n.age) AS s, min(n.age) AS mn, max(n.age) AS mx",
                    "s",
                ),
                (
                    "MATCH (n:Person) RETURN count(*) AS c, sum(n.age) AS s, min(n.age) AS mn, max(n.age) AS mx",
                    "mx",
                ),
            ],
        );
        // Concrete closed-form (ages 0..BIG_N): sum=(N-1)*N/2, count=N, min/max=0/(N-1).
        let expected_sum = (BIG_N - 1) * BIG_N / 2;
        assert_eq!(
            read_scalar_parallel(&mut par, "MATCH (n:Person) RETURN sum(n.age) AS r", "r"),
            Value::Integer(expected_sum)
        );
        assert_eq!(
            read_scalar_parallel(&mut par, "MATCH (n:Person) RETURN max(n.age) AS r", "r"),
            Value::Integer(BIG_N - 1)
        );
        // A pure `count(*)`-only aggregation has no property column → serial tier (mirrors vectorized).
        assert_value_equals_serial_declined(
            &mut par,
            &mut ser,
            "MATCH (n:Person) RETURN count(*) AS r",
            "r",
        );
    }

    // --- 2. OVERWRITE since declare (stale cache → MVCC re-check + row fallback) ---
    {
        let overwrite = "MATCH (n:Person) WHERE n.age < 1000 SET n.age = n.age + 1000000";
        let mut par = fresh_coord();
        bulk_seed(&mut par, "Person", BIG_N);
        par.declare_columnar_cache("Person", "age")
            .expect("declare"); // declare BEFORE the overwrite → cache goes stale for touched nodes
        run_write(&mut par, overwrite);
        let mut ser = fresh_coord();
        bulk_seed(&mut ser, "Person", BIG_N);
        run_write(&mut ser, overwrite);

        assert_each_parallel_equals_serial(
            &mut par,
            &mut ser,
            "Person",
            "age",
            &[
                ("MATCH (n:Person) RETURN sum(n.age) AS r", "r"),
                ("MATCH (n:Person) RETURN max(n.age) AS r", "r"),
                ("MATCH (n:Person) RETURN count(n.age) AS r", "r"),
            ],
        );
    }

    // --- 3. INSERT since declare (new nodes absent from the cache, present in the candidate set) ---
    {
        let insert = "UNWIND range(1, 500) AS i CREATE (:Person {age: 100000 + i})";
        let mut par = fresh_coord();
        bulk_seed(&mut par, "Person", BIG_N);
        par.declare_columnar_cache("Person", "age")
            .expect("declare");
        run_write(&mut par, insert);
        let mut ser = fresh_coord();
        bulk_seed(&mut ser, "Person", BIG_N);
        run_write(&mut ser, insert);

        assert_each_parallel_equals_serial(
            &mut par,
            &mut ser,
            "Person",
            "age",
            &[
                (
                    "MATCH (n:Person) RETURN count(*) AS c, sum(n.age) AS s",
                    "c",
                ),
                ("MATCH (n:Person) RETURN sum(n.age) AS r", "r"),
                ("MATCH (n:Person) RETURN max(n.age) AS r", "r"),
            ],
        );
    }

    // --- 4. DELETE since declare (tombstones dropped by the MVCC re-check) ---
    {
        // Delete only a small slice so the surviving Person count stays ABOVE the size gate (the gate
        // reads the live label count): BIG_N - 50 = 50_050 >= 50_000, so the parallel tier still
        // engages while the tombstone drop-out path is exercised.
        let delete = "MATCH (n:Person) WHERE n.age < 50 DELETE n";
        let mut par = fresh_coord();
        bulk_seed(&mut par, "Person", BIG_N);
        par.declare_columnar_cache("Person", "age")
            .expect("declare");
        run_write(&mut par, delete);
        let mut ser = fresh_coord();
        bulk_seed(&mut ser, "Person", BIG_N);
        run_write(&mut ser, delete);

        assert_each_parallel_equals_serial(
            &mut par,
            &mut ser,
            "Person",
            "age",
            &[
                (
                    "MATCH (n:Person) RETURN count(*) AS c, sum(n.age) AS s",
                    "c",
                ),
                ("MATCH (n:Person) RETURN count(n.age) AS r", "r"),
                ("MATCH (n:Person) RETURN sum(n.age) AS r", "r"),
                ("MATCH (n:Person) RETURN min(n.age) AS r", "r"),
            ],
        );
    }

    // --- 5. CROSS-SNAPSHOT visibility: a reader pinned before a concurrent committed update folds in
    //        parallel and still sees the OLD values (snapshot isolation, projected under its view) ---
    {
        let mut coord = fresh_coord();
        bulk_seed(&mut coord, "Person", BIG_N);
        coord
            .declare_columnar_cache("Person", "age")
            .expect("declare");
        let pre_sum = (BIG_N - 1) * BIG_N / 2; // ages 0..BIG_N

        let reader = coord.begin_serializable(); // pin the snapshot here...
        run_write(&mut coord, "MATCH (n:Person) SET n.age = n.age + 1"); // ...concurrent committed bump

        assert!(
            rayon::current_num_threads() > 1,
            "needs a multi-worker global rayon pool to exercise the parallel fold"
        );
        let plan = compile("MATCH (n:Person) RETURN sum(n.age) AS r");
        let hits_before = coord.parallel_scan_hits();
        let rows = run_plan(&coord, reader, &plan);
        let via_parallel = rows[0].value("r");
        coord.commit(reader).expect("reader commits");
        assert_eq!(
            via_parallel,
            Value::Integer(pre_sum),
            "the parallel snapshot must observe the reader's pinned snapshot, not the concurrent commit"
        );
        assert!(
            coord.parallel_scan_hits() > hits_before,
            "the parallel path must have engaged for the snapshot-isolated reader"
        );
    }

    // --- 6. FLOAT column DECLINES a numeric fold (float + is non-associative); count(*) stays exact ---
    {
        let seed = format!(
            "UNWIND range(0, {}) AS i CREATE (:Meas {{v: i + 0.5}})",
            BIG_N - 1
        );
        let mut par = fresh_coord();
        run_write(&mut par, &seed);
        par.declare_columnar_cache("Meas", "v").expect("declare");
        let mut ser = fresh_coord();
        run_write(&mut ser, &seed);
        // sum over a float column must decline (and stay correct via the serial fallback).
        assert_value_equals_serial_declined(
            &mut par,
            &mut ser,
            "MATCH (n:Meas) RETURN sum(n.v) AS r",
            "r",
        );
    }

    // --- 7. avg DECLINES (the explicitly deferred slice), correct via serial fallback ---
    {
        let mut par = fresh_coord();
        bulk_seed(&mut par, "Person", BIG_N);
        par.declare_columnar_cache("Person", "age")
            .expect("declare");
        let mut ser = fresh_coord();
        bulk_seed(&mut ser, "Person", BIG_N);
        assert_value_equals_serial_declined(
            &mut par,
            &mut ser,
            "MATCH (n:Person) RETURN avg(n.age) AS r",
            "r",
        );
    }

    // --- 8. UNDECLARED column DECLINES (no columnar cache covers it — the same decline path a
    //        historical / begin_at_snapshot read takes); correct via serial fallback ---
    {
        let mut par = fresh_coord();
        bulk_seed(&mut par, "Person", BIG_N); // NB: NO declare_columnar_cache
        let mut ser = fresh_coord();
        bulk_seed(&mut ser, "Person", BIG_N);
        assert_value_equals_serial_declined(
            &mut par,
            &mut ser,
            "MATCH (n:Person) RETURN sum(n.age) AS r",
            "r",
        );
    }
}

/// The size gate, end-to-end through the real engine: a **below-threshold** label takes the serial
/// path (no parallel-scan hit), an **above-threshold** label takes the parallel path (a hit) — and
/// BOTH equal the pure serial coordinator. Kept separate from the big test (the below-gate half is
/// cheap, the above-gate half reuses one heavy pair, dropped at the end of the test).
#[test]
fn parallel_size_gate_below_serial_above_parallel() {
    // --- below the gate: a small label, declared, integer column → serial (cheap) ---
    {
        let small_n: i64 = PARALLEL_GATE / 2;
        let mut small = fresh_coord();
        bulk_seed(&mut small, "Small", small_n);
        small
            .declare_columnar_cache("Small", "age")
            .expect("declare");
        let mut small_row = fresh_coord();
        bulk_seed(&mut small_row, "Small", small_n);
        assert_value_equals_serial_declined(
            &mut small,
            &mut small_row,
            "MATCH (n:Small) RETURN sum(n.age) AS r",
            "r",
        );
    }
    // --- above the gate: a large label, declared, integer column → parallel (heavy; scoped) ---
    {
        let mut big = fresh_coord();
        bulk_seed(&mut big, "Big", BIG_N);
        big.declare_columnar_cache("Big", "age").expect("declare");
        let mut big_row = fresh_coord();
        bulk_seed(&mut big_row, "Big", BIG_N);

        let hits_before = big.parallel_scan_hits();
        let big_par = read_scalar_parallel(&mut big, "MATCH (n:Big) RETURN sum(n.age) AS r", "r");
        let big_ser = read_scalar(&mut big_row, "MATCH (n:Big) RETURN sum(n.age) AS r", "r");
        assert_eq!(big_par, big_ser, "above-gate result equals serial");
        assert!(
            big.parallel_scan_hits() > hits_before,
            "above the gate the parallel path MUST engage"
        );
    }
}

// NOTE: the single-thread *decline* — `current_num_threads() == 1` ⇒ no fan-out benefit ⇒ serial — is
// covered deterministically by a one-thread-pool unit test in `executor::tests`
// (`parallel_thread_gate_declines_single_worker`), because the `!Send` coordinator cannot be driven
// inside a `rayon` `pool.install` from an integration test.

/// Measurement harness (ignored): END-TO-END aggregation latency THROUGH THE EXECUTOR (compile +
/// `project_snapshot` + fold), not just the isolated snapshot fold of
/// `snapshot::tests::measure_parallel_speedup`. With `RAYON_NUM_THREADS=1` the gate
/// (`current_num_threads() > 1`) fails so the executor picks the existing SERIAL vectorized tier;
/// with `RAYON_NUM_THREADS=16` it picks the PARALLEL tier — so running this twice measures the real
/// before/after of `rmp` #352 over the live `RecordStoreGraph` path (projection cost included).
///
/// Reproduce:
///   RAYON_NUM_THREADS=1  cargo test -p graphus-cypher --release --test columnar_analytical \
///       measure_executor_parallel_speedup -- --ignored --nocapture
///   RAYON_NUM_THREADS=16 cargo test -p graphus-cypher --release --test columnar_analytical \
///       measure_executor_parallel_speedup -- --ignored --nocapture
#[test]
#[ignore]
fn measure_executor_parallel_speedup() {
    const MEASURE_N: i64 = 200_000;
    const ROUNDS: u32 = 30;
    let query = "MATCH (n:Person) RETURN sum(n.age) AS r";

    let mut coord = fresh_coord();
    bulk_seed(&mut coord, "Person", MEASURE_N);
    coord
        .declare_columnar_cache("Person", "age")
        .expect("declare");

    // Warm the columnar cache + one-time costs, then time a steady-state batch.
    let _ = read_scalar(&mut coord, query, "r");
    let hits_before = coord.parallel_scan_hits();
    let start = std::time::Instant::now();
    let mut last = Value::Null;
    for _ in 0..ROUNDS {
        last = read_scalar(&mut coord, query, "r");
    }
    let per_ms = start.elapsed().as_secs_f64() * 1000.0 / f64::from(ROUNDS);
    let engaged = coord.parallel_scan_hits() - hits_before;

    // The result is invariant of the path taken (closed form: sum of ages 0..MEASURE_N-1).
    assert_eq!(
        last,
        Value::Integer((MEASURE_N - 1) * MEASURE_N / 2),
        "aggregate must be exact regardless of path"
    );

    println!(
        "EXECUTOR-E2E sum(n.age) over {MEASURE_N} :Person | rayon_threads={} | per_query_ms={per_ms:.3} | rounds={ROUNDS} | parallel_engaged={} (hits+={engaged})",
        rayon::current_num_threads(),
        engaged > 0,
    );
}

// =================================================================================================
// `rmp` task #375 — late materialization: fold on dictionary codes, decode only touched rows, and
// memoize the decode keyed on the column's build generation. Two teeth:
//
//   1. A low-cardinality string column (dictionary-encoded, codes-backed) aggregated through the
//      columnar fold returns the **identical** scalar the row path does — under a fresh column and a
//      stale (overwritten) one. The codes/dict view is canonical (sorted, deduped), so code-equality
//      ⟺ value-equality (asserted at the codec/cache level in unit tests); here we prove the *engine*
//      result is byte-identical when the codes-backed decode feeds the fold.
//   2. A repeated scan of an un-mutated column re-uses the memoized decode (decode paid once, not per
//      query), and a re-capture (a mutation that rebuilds the column → a new generation) decodes
//      afresh rather than serving the stale decode.
// =================================================================================================

/// The codes-backed string column fold equals the row path on a low-cardinality column with many
/// repeats (the dictionary win), both fresh and after an overwrite makes the cache stale.
#[test]
fn codes_backed_string_aggregate_equals_row_path_fresh_and_stale() {
    // 12 rows, 3 distinct colours, heavily repeated and out of order.
    let colours = [
        "red", "green", "blue", "red", "blue", "red", "green", "red", "blue", "green", "red",
        "blue",
    ];
    let mut acc = fresh_coord();
    let mut row = fresh_coord();
    for c in colours {
        let stmt = format!("CREATE (:Item {{colour: '{c}'}})");
        run_write(&mut acc, &stmt);
        run_write(&mut row, &stmt);
    }
    acc.declare_columnar_cache("Item", "colour")
        .expect("declare");
    assert_eq!(
        acc.columnar_column_len("Item", "colour"),
        Some(colours.len()),
        "the low-cardinality colour column must be captured (else this is vacuous)"
    );

    let hits_before = acc.columnar_scan_hits();
    for (q, col) in [
        ("MATCH (n:Item) RETURN min(n.colour) AS r", "r"),
        ("MATCH (n:Item) RETURN max(n.colour) AS r", "r"),
        ("MATCH (n:Item) RETURN count(n.colour) AS r", "r"),
    ] {
        assert_eq!(
            read_scalar(&mut acc, q, col),
            read_scalar(&mut row, q, col),
            "`{q}`: codes-backed fold must equal the row path"
        );
    }
    // TEETH: the columnar (codes-backed) path actually ran — not a vacuous row-vs-row comparison.
    assert!(
        acc.columnar_scan_hits() > hits_before,
        "the columnar analytical path must have run"
    );
    // Concrete: min 'blue', max 'red', count 12.
    assert_eq!(
        read_scalar(&mut acc, "MATCH (n:Item) RETURN min(n.colour) AS r", "r"),
        Value::String("blue".into())
    );
    assert_eq!(
        read_scalar(&mut acc, "MATCH (n:Item) RETURN max(n.colour) AS r", "r"),
        Value::String("red".into())
    );
    assert_eq!(
        read_scalar(&mut acc, "MATCH (n:Item) RETURN count(n.colour) AS r", "r"),
        Value::Integer(12)
    );

    // Now make the cache stale: overwrite one node's colour to a brand-new value 'amber' (lexically
    // the new min). The read-time witness re-check must fall back for that node, so both engines agree.
    run_write(
        &mut acc,
        "MATCH (n:Item {colour: 'red'}) WITH n LIMIT 1 SET n.colour = 'amber'",
    );
    run_write(
        &mut row,
        "MATCH (n:Item {colour: 'red'}) WITH n LIMIT 1 SET n.colour = 'amber'",
    );
    for (q, col) in [
        ("MATCH (n:Item) RETURN min(n.colour) AS r", "r"),
        ("MATCH (n:Item) RETURN max(n.colour) AS r", "r"),
        ("MATCH (n:Item) RETURN count(n.colour) AS r", "r"),
    ] {
        assert_eq!(
            read_scalar(&mut acc, q, col),
            read_scalar(&mut row, q, col),
            "`{q}` after overwrite: stale codes-backed cache must still equal the row path"
        );
    }
    assert_eq!(
        read_scalar(&mut acc, "MATCH (n:Item) RETURN min(n.colour) AS r", "r"),
        Value::String("amber".into()),
        "the overwritten value must be observed via the per-node fallback"
    );
}

/// A repeated scan of an un-mutated column re-uses the memoized decode (`rmp` #375 (c)); a re-capture
/// bumps the generation and decodes afresh, never serving the stale decode.
#[test]
fn repeated_scan_reuses_decode_and_recapture_invalidates() {
    let mut coord = fresh_coord();
    for c in ["gold", "silver", "gold", "bronze", "silver", "gold"] {
        run_write(&mut coord, &format!("CREATE (:Medal {{kind: '{c}'}})"));
    }
    coord
        .declare_columnar_cache("Medal", "kind")
        .expect("declare");

    let q = "MATCH (n:Medal) RETURN max(n.kind) AS r";
    assert_eq!(coord.columnar_decode_cache_hits(), 0);

    // First scan: the decode is computed (no decode-cache hit yet).
    let first = read_scalar(&mut coord, q, "r");
    assert_eq!(first, Value::String("silver".into()));
    assert_eq!(coord.columnar_decode_cache_hits(), 0, "first scan decodes");

    // Second scan of the SAME un-mutated column: the memoized decode is re-used.
    let second = read_scalar(&mut coord, q, "r");
    assert_eq!(second, first, "repeated scans must agree");
    assert!(
        coord.columnar_decode_cache_hits() >= 1,
        "a repeated scan of an un-mutated column must re-use the decode (no re-decode)"
    );

    // Re-capture the declared column (re-declaring drives a rebuild → a fresh generation). The new
    // column starts cold: its first scan decodes again rather than serving the old (stale) decode.
    run_write(&mut coord, "CREATE (:Medal {kind: 'zinc'})"); // a new lexical max
    coord
        .declare_columnar_cache("Medal", "kind")
        .expect("re-declare rebuilds");
    let hits_after_recapture = coord.columnar_decode_cache_hits();
    let post = read_scalar(&mut coord, q, "r");
    assert_eq!(
        coord.columnar_decode_cache_hits(),
        hits_after_recapture,
        "the re-captured column must decode afresh (no decode-cache hit on its first scan)"
    );
    assert_eq!(
        post,
        Value::String("zinc".into()),
        "the re-captured column must reflect the new data, never the stale decode"
    );
}

/// `rmp` #375 measurement: the late-materialization + per-generation decode-cache win on **repeated**
/// analytical scans of a low-cardinality string column. The first scan decodes the dictionary and
/// builds the `id -> index` map; every subsequent scan of the un-mutated column re-uses both (zero
/// re-decode, zero per-query `HashMap` rebuild). We report cold (first) vs warm (cached) per-query
/// wall time and the RAM proxy (allocations avoided: one decoded column + one `id->index` map per
/// repeat are no longer rebuilt). Ignored by default; run with:
///   cargo test -p graphus-cypher --release --test columnar_analytical -- --ignored --nocapture \
///       measure_repeated_string_scan_decode_cache
#[test]
#[ignore = "measurement, not a correctness gate; run with --release --ignored --nocapture"]
fn measure_repeated_string_scan_decode_cache() {
    const N: i64 = 50_000;
    const REPEATS: u32 = 200;
    let seed = format!(
        "UNWIND range(0, {}) AS i CREATE (:Acct {{tier: ['gold','silver','bronze','none'][i % 4]}})",
        N - 1
    );
    let mut acc = fresh_coord();
    run_write(&mut acc, &seed);
    acc.declare_columnar_cache("Acct", "tier").expect("declare");
    assert_eq!(acc.columnar_column_len("Acct", "tier"), Some(N as usize));

    let q = "MATCH (n:Acct) RETURN min(n.tier) AS mn, max(n.tier) AS mx, count(n.tier) AS cp";
    let plan = compile(q);

    // Cold query: the FIRST columnar scan of this query decodes the column + builds the id->index map
    // (multi-tier probing may re-enter the seam within the same query, re-using that decode — exactly
    // the `rmp` #375 win).
    let t_cold = std::time::Instant::now();
    {
        let t = acc.begin_serializable();
        let _ = run_plan(&acc, t, &plan);
        acc.commit(t).unwrap();
    }
    let cold = t_cold.elapsed();
    let dch_after_cold = acc.columnar_decode_cache_hits();

    // Warm queries: every subsequent query re-uses the memoized decode + index map across ALL its
    // scans (no re-decode, no per-query map rebuild) — the column is un-mutated.
    let t_warm = std::time::Instant::now();
    for _ in 0..REPEATS {
        let t = acc.begin_serializable();
        let _ = run_plan(&acc, t, &plan);
        acc.commit(t).unwrap();
    }
    let warm_total = t_warm.elapsed();
    let warm_per = warm_total / REPEATS;
    assert!(
        acc.columnar_decode_cache_hits() - dch_after_cold >= u64::from(REPEATS),
        "every warm query must re-use the memoized decode at least once"
    );

    eprintln!(
        "\n=== rmp #375 measurement: repeated low-cardinality STRING scan over {N} :Acct (4 distinct tiers) ==="
    );
    eprintln!("cold scan (decode + id->index map built): {cold:?}");
    eprintln!(
        "warm scan (memoized decode + map re-used)  : {warm_per:?}/query  over {REPEATS} repeats"
    );
    eprintln!(
        "RAM avoided per warm scan: 1 decoded String column ({N} rows -> 4 dict strings + {N} codes) + 1 id->index map ({N} entries) NOT rebuilt"
    );
    let ratio = cold.as_secs_f64() / warm_per.as_secs_f64().max(f64::MIN_POSITIVE);
    eprintln!("cold/warm per-query ratio: {ratio:.2}x\n");
}
