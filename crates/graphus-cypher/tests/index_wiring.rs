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
fn index_rebuilt_after_crash_recovery_equals_scan() {
    // Drive committed inserts through one coordinator, crash, recover the store, build a NEW
    // coordinator over the recovered store, register the same index, and assert seeks/scans match
    // the scan path over the recovered graph (the rebuild makes the index consistent by
    // construction).
    let mut coord = fresh_coord();
    seed_people(&mut coord);

    // Crash: reclaim the store with no open transaction, then recover from the durable WAL alone.
    let store = coord.into_store();
    let recovered = recover_no_force(&store);

    let mut coord2 = TxnCoordinator::new(recovered);
    // Register the index AFTER recovery: `create_node_property_index` rebuilds it from the recovered
    // rows, and `new` already rebuilt the always-present label index.
    coord2
        .create_node_property_index("Person", "age")
        .expect("create index post-recovery");

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
