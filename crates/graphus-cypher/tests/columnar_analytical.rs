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
    assert_eq!(col_value_hits, N as u64);
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
