//! Text (trigram) node index end-to-end (`rmp` task #662): DDL (`CREATE TEXT INDEX FOR (n:L) ON
//! (n.p)`), the durable catalog + synchronous online build, per-write maintenance, the planner's
//! `CONTAINS` / `ENDS WITH` / `STARTS WITH` seek, execution parity against the scan+filter fallback,
//! and crash recovery.
//!
//! The harness mirrors `tests/composite_index.rs`: a `TxnCoordinator` over an in-memory store with a
//! `run_write` commit probe and the `recover_no_force` deterministic reopen. The **execution parity**
//! tests are the black-box witness that the text index seek returns exactly the scan+filter set —
//! `read_ids(..)` runs the SAME read query twice, once compiled against the coordinator's catalog (the
//! `NodeTextIndexSeek` path) and once against the empty catalog (the scan+filter path), and asserts
//! the id sets are identical.

use graphus_core::{Timestamp, Value};
use graphus_cypher::binding::{Parameters, bind_parameters};
use graphus_cypher::catalog::IndexCatalog;
use graphus_cypher::coordinator::TxnCoordinator;
use graphus_cypher::executor::execute;
use graphus_cypher::lexer::tokenize;
use graphus_cypher::lower::lower;
use graphus_cypher::parser::parse_tokens;
use graphus_cypher::physical::{PhysicalPlan, plan_physical};
use graphus_cypher::plan_description::{PlanDescription, PlanNode};
use graphus_cypher::runtime::Row;
use graphus_cypher::semantics::analyze;
use graphus_cypher::{CONSTRAINT_VIOLATION_PREFIX, ConstraintKind};
use graphus_io::MemBlockDevice;
use graphus_storage::recovery::recover_device;
use graphus_storage::{ConstraintTypeDescriptor, IndexState, RecordStore};
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

fn compile_with(src: &str, catalog: &IndexCatalog) -> PhysicalPlan {
    let toks = tokenize(src).expect("lex");
    let ast = parse_tokens(&toks, src).expect("parse");
    let validated = analyze(&ast).expect("analyze");
    plan_physical(&lower(&validated), catalog)
}

/// Runs a write statement and **commits** it, asserting it succeeded with no captured error.
fn run_write(coord: &mut Coord, src: &str) {
    let plan = compile_with(src, &IndexCatalog::empty());
    let txn = coord.begin_serializable();
    let bound = bind_parameters(&plan, &Parameters::new()).expect("bind");
    let captured = {
        let mut graph = coord.statement(txn).expect("statement");
        let _rows: Vec<Row> = {
            let mut cursor = execute(&plan, &bound, &mut graph).expect("open cursor");
            cursor.collect_all().expect("collect")
        };
        graph.take_error()
    };
    assert!(
        captured.is_none(),
        "write {src:?} must succeed: {captured:?}"
    );
    coord.commit(txn).expect("write commits");
}

/// Runs a write statement cleanly (no captured error) and then **rolls it back** — the abort path the
/// `rmp` #756 regression exercises (the durable store is undone; the in-memory ft/spatial/text index is
/// NOT). Asserts the statement ran without error before the rollback so the test isolates the abort's
/// effect on the freshness marker rather than a mid-statement failure.
fn run_write_then_rollback(coord: &mut Coord, src: &str) {
    let plan = compile_with(src, &IndexCatalog::empty());
    let txn = coord.begin_serializable();
    let bound = bind_parameters(&plan, &Parameters::new()).expect("bind");
    let captured = {
        let mut graph = coord.statement(txn).expect("statement");
        let _rows: Vec<Row> = {
            let mut cursor = execute(&plan, &bound, &mut graph).expect("open cursor");
            cursor.collect_all().expect("collect")
        };
        graph.take_error()
    };
    assert!(
        captured.is_none(),
        "write {src:?} must run cleanly before the deliberate rollback: {captured:?}"
    );
    coord.rollback(txn).expect("rollback");
}

/// Runs a read `src` (which must `RETURN n.id AS id`) compiled against `catalog`, returning the sorted
/// `id`s. Passing the coordinator's catalog exercises the text seek; the empty catalog exercises the
/// scan+filter fallback — the two must agree.
fn read_ids(coord: &mut Coord, src: &str, catalog: &IndexCatalog) -> Vec<i64> {
    let plan = compile_with(src, catalog);
    let txn = coord.begin_serializable();
    let bound = bind_parameters(&plan, &Parameters::new()).expect("bind");
    let rows = {
        let mut graph = coord.statement(txn).expect("statement");
        let mut cursor = execute(&plan, &bound, &mut graph).expect("open cursor");
        cursor.collect_all().expect("collect")
    };
    coord.commit(txn).expect("read commits");
    let mut ids: Vec<i64> = rows
        .iter()
        .map(|r| match r.value("id") {
            Value::Integer(i) => i,
            other => panic!("expected an integer id, got {other:?}"),
        })
        .collect();
    ids.sort_unstable();
    ids
}

/// Asserts the text-seek plan (compiled against `coord.catalog()`) and the scan+filter plan (compiled
/// against the empty catalog) return the **identical** id set for `src`, and returns it.
fn assert_seek_matches_scan(coord: &mut Coord, src: &str) -> Vec<i64> {
    let catalog = coord.catalog();
    // Sanity: the catalog plan actually uses the text seek (else the parity check is vacuous).
    let plan = compile_with(src, &catalog);
    assert!(
        plan.to_string().contains("NodeTextIndexSeek"),
        "expected a text seek for {src:?}, got:\n{plan}"
    );
    let seek_ids = read_ids(coord, src, &catalog);
    let scan_ids = read_ids(coord, src, &IndexCatalog::empty());
    assert_eq!(
        seek_ids, scan_ids,
        "text seek rows must equal scan+filter rows for {src:?}"
    );
    seek_ids
}

/// Deterministically reopens `store` from its durable WAL prefix (the recovery probe).
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

/// Seeds `Person` nodes with `(id, name)` exercising case, substrings, a unicode value, a mixed-type
/// `name` (an integer), and a node missing `name` entirely.
fn seed_people(coord: &mut Coord) {
    run_write(coord, "CREATE (:Person {id: 1, name: 'Robert'})");
    run_write(coord, "CREATE (:Person {id: 2, name: 'roberta'})");
    run_write(coord, "CREATE (:Person {id: 3, name: 'Bobby'})");
    run_write(coord, "CREATE (:Person {id: 4, name: 'Álvaro'})"); // unicode scalar values
    run_write(coord, "CREATE (:Person {id: 5, name: 42})"); // mixed-type property (not a string)
    run_write(coord, "CREATE (:Person {id: 6, age: 30})"); // no name at all
}

// =================================================================================================
// Tests
// =================================================================================================

#[test]
fn text_index_is_durable_listed_idempotent_and_survives_reopen() {
    let mut coord = fresh_coord();
    seed_people(&mut coord);

    // Declare a text index over the existing data (synchronous, always Online).
    let created = coord
        .create_text_index("tx_person_name", "Person", "name", false)
        .expect("create text index");
    assert!(created, "a fresh create mutates");

    // SHOW-source surface: (name, label, property, Online).
    assert_eq!(
        coord.list_text_indexes(),
        vec![(
            "tx_person_name".to_owned(),
            "Person".to_owned(),
            "name".to_owned(),
            IndexState::Online,
        )],
        "the text index is Online and covers (Person, name)"
    );

    // IF NOT EXISTS equivalence: a re-declare of the same (label, property) errors without the flag...
    let err = coord
        .create_text_index("other_name", "Person", "name", false)
        .expect_err("an equivalent text index without IF NOT EXISTS errors");
    assert!(err.to_string().contains("equivalent index"), "{err:?}");
    // ...and is an idempotent no-op with it (a different name over the same schema).
    assert!(
        !coord
            .create_text_index("other_name", "Person", "name", true)
            .expect("IF NOT EXISTS is a clean no-op"),
        "IF NOT EXISTS on an equivalent text index does not mutate"
    );

    // A name collision with a DIFFERENT catalog errors without IF NOT EXISTS. Declare a range index of
    // a distinct name is fine (different kind, different schema), but reusing THIS text name for a
    // different-target text index is caught as a duplicate-name.
    coord
        .begin_online_node_property_index_named(Some("range_email"), "Person", "email", false)
        .expect("a range index of a distinct name coexists");
    let err = coord
        .create_text_index("range_email", "Person", "bio", false)
        .expect_err("a cross-catalog name collision errors");
    assert!(err.to_string().contains("named"), "{err:?}");

    // Crash + reopen: the durable catalog reload re-registers and repopulates the text index.
    let store = coord.into_store();
    assert_eq!(
        store.text_indexes().len(),
        1,
        "the text registration survives the reopen (durable catalog)"
    );
    let reopened = recover_no_force(&store);
    let mut coord2 = TxnCoordinator::new(reopened);
    assert_eq!(
        coord2.list_text_indexes(),
        vec![(
            "tx_person_name".to_owned(),
            "Person".to_owned(),
            "name".to_owned(),
            IndexState::Online,
        )],
        "the text index is fully recovered Online after reopen"
    );

    // The recovered index still serves the seek and agrees with the scan — and a post-recovery write is
    // maintained by the rebuilt index (id 7 "Roberto" matches CONTAINS 'obe' too).
    let before = assert_seek_matches_scan(
        &mut coord2,
        "MATCH (n:Person) WHERE n.name CONTAINS 'obe' RETURN n.id AS id",
    );
    assert_eq!(
        before,
        vec![1, 2],
        "Robert + roberta match 'obe' after reopen"
    );
    run_write(&mut coord2, "CREATE (:Person {id: 7, name: 'Roberto'})");
    let after = assert_seek_matches_scan(
        &mut coord2,
        "MATCH (n:Person) WHERE n.name CONTAINS 'obe' RETURN n.id AS id",
    );
    assert_eq!(
        after,
        vec![1, 2, 7],
        "the post-recovery write is maintained by the rebuilt text index"
    );
}

#[test]
fn text_seek_equals_scan_across_predicates_unicode_and_edge_cases() {
    let mut coord = fresh_coord();
    seed_people(&mut coord);
    coord
        .create_text_index("tx_person_name", "Person", "name", false)
        .expect("create text index");

    // CONTAINS.
    assert_eq!(
        assert_seek_matches_scan(
            &mut coord,
            "MATCH (n:Person) WHERE n.name CONTAINS 'obe' RETURN n.id AS id"
        ),
        vec![1, 2],
    );
    assert_eq!(
        assert_seek_matches_scan(
            &mut coord,
            "MATCH (n:Person) WHERE n.name CONTAINS 'bb' RETURN n.id AS id"
        ),
        vec![3],
    );
    // ENDS WITH — anchored at the tail, so 'ert' matches Robert but not roberta.
    assert_eq!(
        assert_seek_matches_scan(
            &mut coord,
            "MATCH (n:Person) WHERE n.name ENDS WITH 'ert' RETURN n.id AS id"
        ),
        vec![1],
    );
    assert_eq!(
        assert_seek_matches_scan(
            &mut coord,
            "MATCH (n:Person) WHERE n.name ENDS WITH 'ta' RETURN n.id AS id"
        ),
        vec![2],
    );
    // STARTS WITH — case-sensitive (raw match).
    assert_eq!(
        assert_seek_matches_scan(
            &mut coord,
            "MATCH (n:Person) WHERE n.name STARTS WITH 'Rob' RETURN n.id AS id"
        ),
        vec![1],
    );
    assert_eq!(
        assert_seek_matches_scan(
            &mut coord,
            "MATCH (n:Person) WHERE n.name STARTS WITH 'rob' RETURN n.id AS id"
        ),
        vec![2],
    );
    // Unicode: 'lvar' is a raw substring of "Álvaro".
    assert_eq!(
        assert_seek_matches_scan(
            &mut coord,
            "MATCH (n:Person) WHERE n.name CONTAINS 'lvar' RETURN n.id AS id"
        ),
        vec![4],
    );
    // No match — the seek narrows to nothing, agreeing with the scan.
    assert_eq!(
        assert_seek_matches_scan(
            &mut coord,
            "MATCH (n:Person) WHERE n.name CONTAINS 'zzz' RETURN n.id AS id"
        ),
        Vec::<i64>::new(),
    );
}

#[test]
fn short_needle_and_empty_needle_fall_back_but_still_match_the_scan() {
    // A needle too short to form a trigram makes the seam decline (scan fallback); the residual predicate
    // still yields exactly the scan result. The seek path is chosen by the planner (the plan routes
    // through `NodeTextIndexSeek`), but at run time the seam falls back to the label scan — transparent
    // to the caller. We can't assert `assert_seek_matches_scan` (it requires the plan to route through
    // the seek — which it does), so verify the parity directly.
    let mut coord = fresh_coord();
    seed_people(&mut coord);
    coord
        .create_text_index("tx_person_name", "Person", "name", false)
        .expect("create text index");

    for q in [
        "MATCH (n:Person) WHERE n.name CONTAINS 'o' RETURN n.id AS id", // 1-char (< 3)
        "MATCH (n:Person) WHERE n.name CONTAINS 'ob' RETURN n.id AS id", // 2-char (< 3)
        "MATCH (n:Person) WHERE n.name CONTAINS '' RETURN n.id AS id",  // empty needle
        "MATCH (n:Person) WHERE n.name STARTS WITH 'R' RETURN n.id AS id", // 1-char prefix (< 2)
        "MATCH (n:Person) WHERE n.name ENDS WITH 'o' RETURN n.id AS id", // 1-char suffix (< 2)
    ] {
        // The plan routes through the text seek (the catalog covers (Person, name))...
        let catalog = coord.catalog();
        assert!(
            compile_with(q, &catalog)
                .to_string()
                .contains("NodeTextIndexSeek"),
            "the plan should route through the text seek for {q:?}"
        );
        // ...and the seek result (with the run-time scan fallback for the short needle) equals the pure
        // scan result.
        let seek = read_ids(&mut coord, q, &catalog);
        let scan = read_ids(&mut coord, q, &IndexCatalog::empty());
        assert_eq!(
            seek, scan,
            "short/empty-needle seek must match the scan for {q:?}"
        );
    }
}

#[test]
fn drop_text_index_removes_it_and_ddl_is_idempotent() {
    let mut coord = fresh_coord();
    seed_people(&mut coord);
    coord
        .create_text_index("tx_person_name", "Person", "name", false)
        .expect("create text index");
    assert_eq!(coord.list_text_indexes().len(), 1);

    // DROP removes it (durable + in-memory); the catalog no longer surfaces a text seek.
    assert!(
        coord
            .drop_text_index("tx_person_name", false)
            .expect("drop"),
        "dropping an existing index mutates"
    );
    assert!(coord.list_text_indexes().is_empty());
    let plan = compile_with(
        "MATCH (n:Person) WHERE n.name CONTAINS 'obe' RETURN n.id AS id",
        &coord.catalog(),
    );
    assert!(
        !plan.to_string().contains("NodeTextIndexSeek"),
        "after DROP, the planner no longer routes through the text seek:\n{plan}"
    );

    // A second DROP of the now-missing index errors without IF EXISTS and is a no-op with it.
    assert!(
        coord.drop_text_index("tx_person_name", false).is_err(),
        "dropping a missing index without IF EXISTS errors"
    );
    assert!(
        !coord
            .drop_text_index("tx_person_name", true)
            .expect("IF EXISTS is a clean no-op"),
        "dropping a missing index with IF EXISTS does not mutate"
    );
}

// =================================================================================================
// `rmp` #756 — the rollback freshness-marker poison must be CONDITIONAL on a real remove/replace.
//
// End-to-end proof (through the REAL coordinator write + abort seams) of BOTH directions:
//   (a) an aborted INSERT of a NEW indexed node leaves the seek SELECTIVE — the marker is NOT poisoned,
//       so every inline reader keeps the fast index path (the `rmp` #467/#755 regression this fixes);
//   (b) an aborted SET that REPLACES an indexed value, and an aborted DELETE of an indexed node, leave
//       NO false negative — the committed node is still returned by the seek.
// =================================================================================================

const CONTAINS_OBE: &str = "MATCH (n:Person) WHERE n.name CONTAINS 'obe' RETURN n.id AS id";

#[test]
fn rmp756_aborted_insert_of_new_indexed_node_does_not_poison_marker() {
    let mut coord = fresh_coord();
    seed_people(&mut coord);
    coord
        .create_text_index("tx_person_name", "Person", "name", false)
        .expect("create text index");
    // Baseline: no mutator in flight and not poisoned, so the marker is a real commit ts (not u64::MAX).
    assert_ne!(
        coord.effective_ft_spatial_marker(),
        Timestamp(u64::MAX),
        "baseline: the freshness marker is not poisoned"
    );

    // An aborted CREATE of a BRAND-NEW Person (a pure insert into the trigram index), rolled back.
    run_write_then_rollback(&mut coord, "CREATE (:Person {id: 99, name: 'Zelda'})");

    // THE FIX: a rolled-back pure INSERT must NOT poison — it left only a re-check-filterable false
    // positive, never a false negative (`rmp` #756). Under the OLD unconditional poison this was u64::MAX.
    assert_ne!(
        coord.effective_ft_spatial_marker(),
        Timestamp(u64::MAX),
        "a rolled-back pure INSERT must NOT poison the freshness marker (rmp #756)"
    );

    // So the inline reader keeps the fast seek AND stays correct: the plan uses NodeTextIndexSeek and its
    // rows equal the scan+filter rows; the aborted 'Zelda' phantom is filtered by the per-candidate
    // re-check, so it never appears.
    let rows = assert_seek_matches_scan(&mut coord, CONTAINS_OBE);
    assert_eq!(
        rows,
        vec![1, 2],
        "Robert + roberta; the aborted node leaves no committed trace"
    );
    let cat = coord.catalog();
    assert!(
        read_ids(
            &mut coord,
            "MATCH (n:Person) WHERE n.name CONTAINS 'eld' RETURN n.id AS id",
            &cat,
        )
        .is_empty(),
        "the aborted 'Zelda' is not a committed match"
    );
}

#[test]
fn rmp756_aborted_set_replace_fails_closed_no_false_negative() {
    let mut coord = fresh_coord();
    seed_people(&mut coord);
    coord
        .create_text_index("tx_person_name", "Person", "name", false)
        .expect("create text index");
    // Baseline: 'Robert' (id 1) + 'roberta' (id 2) match CONTAINS 'obe'.
    let cat = coord.catalog();
    assert_eq!(read_ids(&mut coord, CONTAINS_OBE, &cat), vec![1, 2]);

    // An aborted SET that REPLACES id 1's indexed name 'Robert' -> 'Xavier'. The wholesale last-wins
    // re-index drops id 1's 'Robert' trigrams and inserts 'Xavier' ones; the abort undoes the STORE
    // (id 1 is 'Robert' again) but NOT the in-memory trigram index (it now holds id 1 under 'Xavier').
    run_write_then_rollback(&mut coord, "MATCH (n:Person {id: 1}) SET n.name = 'Xavier'");

    // FAIL CLOSED: because the rollback dropped a still-committed posting, the marker MUST poison so the
    // inline reader declines to the always-correct scan. Under the OLD (and equally the naive by-branch)
    // classification this could be missed and the fast seek for 'obe' would silently lose id 1.
    assert_eq!(
        coord.effective_ft_spatial_marker(),
        Timestamp(u64::MAX),
        "a rolled-back REPLACE dropped a committed posting: the marker MUST poison (rmp #756)"
    );

    // THE SAFETY PROOF: the committed id 1 ('Robert') is STILL returned by CONTAINS 'obe'. `assert_seek_
    // matches_scan` proves the seek-path rows equal the authoritative scan+filter rows — so no committed
    // node is ever missing. If poison had failed to fire, the fast seek would return [2] (id 1 is under
    // 'Xavier' in the in-memory index) and this parity assertion would fail.
    let rows = assert_seek_matches_scan(&mut coord, CONTAINS_OBE);
    assert_eq!(
        rows,
        vec![1, 2],
        "the committed 'Robert' is never missing after a rolled-back replace (no false negative)"
    );
}

#[test]
fn rmp756_aborted_delete_of_indexed_node_no_false_negative() {
    let mut coord = fresh_coord();
    seed_people(&mut coord);
    coord
        .create_text_index("tx_person_name", "Person", "name", false)
        .expect("create text index");

    // An aborted DELETE of id 1 ('Robert'), rolled back. `delete_node` de-indexes ONLY the bitmaps; the
    // trigram posting for id 1 survives (the ft/spatial/text/vector indexes rely on the visibility
    // re-check, not removal), and the abort reverts the store tombstone. No posting was dropped, so this
    // needs no poison — yet the committed node must still be found.
    run_write_then_rollback(&mut coord, "MATCH (n:Person {id: 1}) DELETE n");

    // THE SAFETY PROOF: id 1 is still returned by CONTAINS 'obe' (seek rows == scan rows). A committed
    // node is never missing after a rolled-back delete.
    let rows = assert_seek_matches_scan(&mut coord, CONTAINS_OBE);
    assert_eq!(
        rows,
        vec![1, 2],
        "the committed 'Robert' survives an aborted DELETE — never missing (no false negative)"
    );
}

// =================================================================================================
// `rmp` #756 — a CONSTRAINT-REJECTED insert keeps the seek SELECTIVE (the measured dbHits proof).
//
// The tests above drive the abort a *client* asks for (an explicit `coord.rollback`). This one drives
// the abort the *engine* decides on its own: a write rejected by a declared constraint. That is the
// path which produced the bug in the wild — the `product-recommendations` loader issues constraint-
// negative `CREATE`s against `:Product`, a label carrying a `name` TEXT index, so each rejected write
// poisoned the whole database at LOAD time, before a single read had ever run. Every later
// `Product.name` seek then silently read the entire store.
//
// The property pinned here is the one a user actually feels, and it is MEASURED, not inferred: after
// the rejected write a `PROFILE`d seek's **dbHits** must still be a small fraction of the store. The
// operator name alone cannot witness it — a poisoned marker still *plans* `NodeTextIndexSeek` and only
// then declines to a full scan at run time (`rmp` #755), so the plan reads identical while the work
// explodes by two orders of magnitude. Only dbHits separates the two, which is why the store must be
// seeded large enough for "a fraction of it" to mean something (the 6-node `seed_people` cannot).
// =================================================================================================

/// The `:Product` population of the dbHits proof. Large enough that a full scan (which reads every
/// record) is unambiguously distinguishable from a selective seek (which reads a handful) — the whole
/// point of the acceptance criterion, and unprovable on a store of six nodes.
const PRODUCTS: i64 = 200;

/// A `CONTAINS` needle matching exactly ONE seeded product. Three characters, so it forms a real
/// trigram and the seam narrows rather than declining to the scan fallback (see
/// `short_needle_and_empty_needle_fall_back_but_still_match_the_scan`); and unique across `Widget 0` ..
/// `Widget 199`, so a selective seek reads ~1 record where a scan reads 200.
const CONTAINS_137: &str = "MATCH (n:Product) WHERE n.name CONTAINS '137' RETURN n.id AS id";
const PROFILE_CONTAINS_137: &str =
    "PROFILE MATCH (n:Product) WHERE n.name CONTAINS '137' RETURN n.id AS id";

/// Seeds [`PRODUCTS`] `:Product` nodes, mirroring the `product-recommendations` loader's shape: one
/// label carrying BOTH a TEXT index (on `name`) and constraints (unique `sku`, typed `price`).
fn seed_products(coord: &mut Coord) {
    run_write(
        coord,
        &format!(
            "UNWIND range(0, {last}) AS i CREATE (:Product {{id: i, sku: 'sku-' + toString(i), \
             name: 'Widget ' + toString(i), price: i}})",
            last = PRODUCTS - 1
        ),
    );
}

/// Declares the schema over the seeded products: the TEXT index whose selectivity is under test, plus
/// the two constraints that will reject a write. Both constraints are validated against — and satisfied
/// by — the existing data, so only the deliberate violations below ever trip them.
fn declare_product_schema(coord: &mut Coord) {
    coord
        .create_text_index("tx_product_name", "Product", "name", false)
        .expect("create text index");
    coord
        .create_constraint("uniq_product_sku", "Product", "sku", ConstraintKind::Unique)
        .expect("create uniqueness constraint over conforming data");
    coord
        .create_constraint_general(
            "product_price_int",
            "Product",
            &["price"],
            ConstraintKind::PropertyType,
            Some(ConstraintTypeDescriptor::Integer),
        )
        .expect("create property-type constraint over conforming data");
}

/// Runs a write that a declared constraint must REJECT, letting the **engine** drive the abort: the
/// violation is captured on the statement seam (the captured-error channel), which is what makes the
/// transaction retire through the same rollback seam an explicit `coord.rollback` reaches — with no
/// client involvement at all.
///
/// Asserts the write really was rejected, and rejected *by a constraint*: a write that quietly
/// succeeded, or one that failed for an unrelated reason, never exercises the path under test and would
/// make the caller's assertions vacuous.
fn run_write_rejected_by_constraint(coord: &mut Coord, src: &str) {
    let plan = compile_with(src, &IndexCatalog::empty());
    let txn = coord.begin_serializable();
    let bound = bind_parameters(&plan, &Parameters::new()).expect("bind");
    let captured = {
        let mut graph = coord.statement(txn).expect("statement");
        let _rows: Vec<Row> = {
            let mut cursor = execute(&plan, &bound, &mut graph).expect("open cursor");
            cursor.collect_all().expect("collect")
        };
        graph.take_error()
    };
    let err = captured
        .unwrap_or_else(|| panic!("write {src:?} must be REJECTED — it is the path under test"));
    assert!(
        err.to_string().contains(CONSTRAINT_VIOLATION_PREFIX),
        "write {src:?} must be rejected by a CONSTRAINT, not by anything else: {err}"
    );
    coord.rollback(txn).expect("rollback after captured error");
}

/// Compiles `src` (which MUST carry the `PROFILE` prefix) against `catalog` exactly as the server's
/// compile pipeline does, executes it over the real coordinator, and returns `(row count, the MEASURED
/// plan description)` — every operator's `dbHits` is what it really read, never an estimate.
fn profile_query(coord: &mut Coord, src: &str, catalog: &IndexCatalog) -> (usize, PlanDescription) {
    let toks = tokenize(src).expect("lex");
    let ast = parse_tokens(&toks, src).expect("parse");
    let validated = analyze(&ast).expect("analyze");
    let plan = plan_physical(&lower(&validated), catalog).with_prefix(ast.prefix());
    let bound = bind_parameters(&plan, &Parameters::new()).expect("bind");
    let txn = coord.begin_serializable();
    let (rows, description) = {
        let mut graph = coord.statement(txn).expect("statement");
        let mut cursor = execute(&plan, &bound, &mut graph).expect("open cursor");
        let rows = cursor.collect_all().expect("collect").len();
        let description = PlanDescription::profile(
            cursor
                .profile()
                .expect("a PROFILEd statement has a recorder"),
        );
        (rows, description)
    };
    coord.commit(txn).expect("read commits");
    (rows, description)
}

/// Sums the measured `dbHits` of every operator of a profiled plan.
fn total_db_hits(p: &PlanDescription) -> u64 {
    fn walk(n: &PlanNode) -> u64 {
        n.db_hits.unwrap_or(0) + n.children.iter().map(walk).sum::<u64>()
    }
    walk(p.root())
}

#[test]
fn rmp756_constraint_rejected_insert_keeps_the_text_seek_selective() {
    let mut coord = fresh_coord();
    seed_products(&mut coord);
    declare_product_schema(&mut coord);

    // The calibration contrast, measured on the same store: the SAME query planned with no index is the
    // fused scan+filter, which reports the records it EXAMINED — all 200. This is the number the bug
    // regressed the seek to, and it is what "a small fraction of the store" is a fraction OF.
    let (scan_rows, scan) = profile_query(&mut coord, PROFILE_CONTAINS_137, &IndexCatalog::empty());
    let scan_hits = total_db_hits(&scan);
    assert_eq!(scan_rows, 1, "exactly one product is named 'Widget 137'");
    assert!(
        scan_hits >= PRODUCTS as u64,
        "the scan reads the whole store ({scan_hits} records over {PRODUCTS} products)"
    );

    // The healthy baseline, BEFORE any rejected write: this is what a selective seek costs.
    let catalog = coord.catalog();
    let (seek_rows, seek) = profile_query(&mut coord, PROFILE_CONTAINS_137, &catalog);
    let baseline_hits = total_db_hits(&seek);
    assert_eq!(seek_rows, 1, "the seek finds the same single product");
    assert!(seek.contains_operator("NodeTextIndexSeek"), "{seek:?}");
    assert!(
        baseline_hits * 4 < scan_hits,
        "baseline: the text seek reads a fraction of the store (seek={baseline_hits} scan={scan_hits})"
    );

    // THE REJECTED WRITES — the reco loader's two constraint-negative CREATEs. Each one only INSERTS a
    // brand-new node into the TEXT-covered label (`name` is applied, and therefore indexed, before the
    // deferred constraint check runs on the fully-built node), and is then rejected: once for a
    // duplicate `sku` (uniqueness), once for a `price` of the wrong type. Both retire through the
    // freshness-marker rollback seam having dropped NO pre-existing posting.
    run_write_rejected_by_constraint(
        &mut coord,
        "CREATE (:Product {id: 900, sku: 'sku-7', name: 'Counterfeit Widget', price: 1})",
    );
    run_write_rejected_by_constraint(
        &mut coord,
        "CREATE (:Product {id: 901, sku: 'sku-901', name: 'Prototype Widget', price: 'free'})",
    );

    // THE FIX (`rmp` #756): a constraint-rejected pure INSERT must NOT poison the DB-wide freshness
    // marker. It left only a re-check-filterable false positive in the trigram index, never a false
    // negative. Under the OLD unconditional poison this pinned at u64::MAX from LOAD time onward — for
    // every TEXT/FULLTEXT/spatial index in the database, until a reopen.
    assert_ne!(
        coord.effective_ft_spatial_marker(),
        Timestamp(u64::MAX),
        "a constraint-rejected pure INSERT must NOT poison the freshness marker (rmp #756)"
    );

    // THE ACCEPTANCE CRITERION, measured after the rejected writes: the seek is STILL selective. Not
    // "the marker looks healthy" — the reader demonstrably still reads a small fraction of the store,
    // and costs exactly what it cost before the rejected writes ever happened. A poisoned marker reports
    // this very same operator and then reads all 200 records, so `contains_operator` alone would pass
    // while the user's query got 100x slower; `after_hits` is what actually pins the property.
    let catalog = coord.catalog();
    let (after_rows, after) = profile_query(&mut coord, PROFILE_CONTAINS_137, &catalog);
    let after_hits = total_db_hits(&after);
    assert_eq!(after_rows, 1, "the seek still finds the single product");
    assert!(after.contains_operator("NodeTextIndexSeek"), "{after:?}");
    assert!(
        after_hits * 4 < scan_hits,
        "after a constraint-rejected insert the seek MUST still read a fraction of the store, not scan \
         it: seek={after_hits} scan={scan_hits} over {PRODUCTS} products (rmp #756)"
    );
    assert_eq!(
        after_hits, baseline_hits,
        "the rejected writes cost every later reader exactly nothing"
    );

    // And correctness is intact: the seek rows still equal the authoritative scan+filter rows, so the
    // aborted 'Counterfeit Widget' / 'Prototype Widget' phantoms left in the trigram index are filtered
    // by the per-candidate re-check and never surface as committed rows.
    assert_eq!(
        assert_seek_matches_scan(&mut coord, CONTAINS_137),
        vec![137],
        "only the committed 'Widget 137' matches; the rejected inserts leave no committed trace"
    );
    let catalog = coord.catalog();
    assert!(
        read_ids(
            &mut coord,
            "MATCH (n:Product) WHERE n.name CONTAINS 'feit' RETURN n.id AS id",
            &catalog,
        )
        .is_empty(),
        "the rejected 'Counterfeit Widget' is not a committed match"
    );
}
