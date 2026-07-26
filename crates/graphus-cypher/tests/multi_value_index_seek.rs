//! Multi-value index seek end-to-end (`rmp` task #868): `WHERE n.p IN [a, b, c]` and
//! `WHERE n.p = a OR n.p = b` served by a **union of per-value index descents**
//! ([`NodeIndexMultiSeek`] / [`RelIndexMultiSeek`]) instead of the full label/token scan + residual
//! filter both spellings fell through to before.
//!
//! The harness mirrors `tests/composite_index.rs`: a `TxnCoordinator` over an in-memory store with a
//! `run_write` commit probe. The **execution parity** tests are the black-box witness that the seek
//! returns exactly the scan+filter bag — `read_ids(..)` runs the SAME read query twice, once compiled
//! against the coordinator's catalog (the multi-seek path) and once against the empty catalog (the
//! scan+filter path) — and asserts the id *bags* (sorted, duplicates retained) are identical. A bag
//! comparison, not a set comparison, is what makes the duplicate-alternative test meaningful.
//!
//! Coverage map (every acceptance criterion and every named decline of `rmp` #868):
//!
//! * planning — the `IN` and `OR` spellings both become a multi-seek; the single-value forms and every
//!   pre-existing indexed plan are untouched;
//! * semantics — result parity with the scan, duplicate alternatives do not duplicate rows, cross-type
//!   Cypher-equal alternatives (`1` / `1.0`) collapse to one descent yet still match, `IN []` yields
//!   zero rows, a `null` alternative declines the whole union to the exact scan;
//! * three-valued logic — `NOT (n.p IN [...])`, an `IN` under a larger `OR`, and an `IN` inside a
//!   projection all stay residual filters;
//! * ordering — a multi-seek never claims the `rmp` #665 provided-order `Sort` elision;
//! * cost — a large `IN` list reverts to the scan under `plan_physical_with_stats`;
//! * relationships — the same for `RelIndexMultiSeek`.

use graphus_core::Value;
use graphus_cypher::binding::{Parameters, bind_parameters};
use graphus_cypher::catalog::IndexCatalog;
use graphus_cypher::coordinator::TxnCoordinator;
use graphus_cypher::executor::execute;
use graphus_cypher::lexer::tokenize;
use graphus_cypher::lower::lower;
use graphus_cypher::parser::parse_tokens;
use graphus_cypher::physical::{PhysicalPlan, plan_physical, plan_physical_with_stats};
use graphus_cypher::runtime::Row;
use graphus_cypher::semantics::analyze;
use graphus_cypher::statistics::Statistics;
use graphus_cypher::{CONSTRAINT_VIOLATION_PREFIX, ConstraintKind};
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

fn compile_with(src: &str, catalog: &IndexCatalog) -> PhysicalPlan {
    let toks = tokenize(src).expect("lex");
    let ast = parse_tokens(&toks, src).expect("parse");
    let validated = analyze(&ast).expect("analyze");
    plan_physical(&lower(&validated), catalog)
}

/// Compiles `src` with **statistics**, so the cost-based access-path rewrite (seek vs scan) runs.
fn compile_with_stats(src: &str, catalog: &IndexCatalog, stats: &dyn Statistics) -> PhysicalPlan {
    let toks = tokenize(src).expect("lex");
    let ast = parse_tokens(&toks, src).expect("parse");
    let validated = analyze(&ast).expect("analyze");
    plan_physical_with_stats(&lower(&validated), catalog, Some(stats))
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

/// Runs a read `src` (which must `RETURN … AS id`) compiled against `catalog`, returning the `id`s as a
/// **sorted bag** (duplicates retained, so a row duplicated by a buggy union is visible).
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

/// Asserts the indexed plan uses `operator` and returns the **identical row bag** as the scan+filter
/// plan (compiled against the empty catalog), then returns that bag.
///
/// The `operator` assertion is what keeps the parity check **non-vacuous**: without it, a rewrite that
/// silently never fired would pass every parity assertion trivially.
fn assert_seek_matches_scan(coord: &mut Coord, src: &str, operator: &str) -> Vec<i64> {
    let catalog = coord.catalog();
    let plan = compile_with(src, &catalog);
    assert!(
        plan.to_string().contains(operator),
        "expected a {operator} for {src:?}, got:\n{plan}"
    );
    let seek_ids = read_ids(coord, src, &catalog);
    let scan_ids = read_ids(coord, src, &IndexCatalog::empty());
    assert_eq!(
        seek_ids, scan_ids,
        "{operator} rows must equal scan+filter rows for {src:?}"
    );
    seek_ids
}

/// Seeds seven `USER` nodes whose `uidn` exercises duplicates, a cross-type float, an absent property
/// and a non-matching value. `id` is the stable identity the assertions compare.
fn seed_users(coord: &mut Coord) {
    run_write(coord, "CREATE (:USER {id: 1, uidn: 1})");
    run_write(coord, "CREATE (:USER {id: 2, uidn: 2})");
    run_write(coord, "CREATE (:USER {id: 3, uidn: 3})");
    run_write(coord, "CREATE (:USER {id: 4, uidn: 4})");
    run_write(coord, "CREATE (:USER {id: 5, uidn: 2})"); // a duplicate value
    run_write(coord, "CREATE (:USER {id: 6, uidn: 3.0})"); // Cypher-equal to the integer 3
    run_write(coord, "CREATE (:USER {id: 7})"); // no `uidn` at all: never a match
}

/// Declares the `ONLINE` RANGE index on `(USER, uidn)` the whole suite plans against.
fn index_users(coord: &mut Coord) {
    coord
        .create_node_property_index("USER", "uidn")
        .expect("create the USER.uidn index");
}

fn seeded_indexed_coord() -> Coord {
    let mut coord = fresh_coord();
    seed_users(&mut coord);
    index_users(&mut coord);
    coord
}

// =================================================================================================
// Planning: both spellings become a multi-value seek
// =================================================================================================

#[test]
fn in_list_plans_a_multi_value_seek_instead_of_a_scan() {
    let coord = seeded_indexed_coord();
    let plan = compile_with(
        "MATCH (u:USER) WHERE u.uidn IN [1, 2, 3] RETURN u.id AS id",
        &coord.catalog(),
    );
    let rendered = plan.to_string();
    assert!(
        rendered.contains("NodeIndexMultiSeek(u:USER uidn IN [1, 2, 3]"),
        "the IN list must lower to a multi-value seek, got:\n{rendered}"
    );
    // The predicate is CONSUMED: no residual `Filter` re-applies it.
    assert!(
        !rendered.contains("Filter"),
        "the consumed IN predicate must not be re-attached as a residual filter:\n{rendered}"
    );
    // And the pre-#868 access path is gone.
    assert!(
        !rendered.contains("TokenLookupScan") && !rendered.contains("NodeByLabelScan"),
        "the full label scan must be gone:\n{rendered}"
    );
}

#[test]
fn or_of_equalities_plans_a_multi_value_seek_instead_of_a_scan() {
    let coord = seeded_indexed_coord();
    let plan = compile_with(
        "MATCH (u:USER) WHERE u.uidn = 1 OR u.uidn = 2 RETURN u.id AS id",
        &coord.catalog(),
    );
    let rendered = plan.to_string();
    assert!(
        rendered.contains("NodeIndexMultiSeek(u:USER uidn IN ["),
        "the OR of equalities must lower to a multi-value seek, got:\n{rendered}"
    );
    assert!(
        !rendered.contains("TokenLookupScan") && !rendered.contains("NodeByLabelScan"),
        "the full label scan must be gone:\n{rendered}"
    );
}

#[test]
fn a_three_branch_or_and_a_mixed_or_in_chain_both_collect_every_alternative() {
    let coord = seeded_indexed_coord();
    for src in [
        "MATCH (u:USER) WHERE u.uidn = 1 OR u.uidn = 2 OR u.uidn = 3 RETURN u.id AS id",
        // `OR` is associative and `IN` is its fold, so a mixed chain flattens to the same alternatives.
        "MATCH (u:USER) WHERE u.uidn = 1 OR u.uidn IN [2, 3] RETURN u.id AS id",
    ] {
        let plan = compile_with(src, &coord.catalog());
        let rendered = plan.to_string();
        assert!(
            rendered.contains("NodeIndexMultiSeek"),
            "{src:?} must lower to a multi-value seek, got:\n{rendered}"
        );
        // All three alternatives reached the operator, in source order, inside the brackets.
        assert!(
            rendered.contains("uidn IN [1, 2, 3]"),
            "every alternative must reach the operator, got:\n{rendered}"
        );
    }
}

#[test]
fn the_single_value_forms_are_untouched_by_868() {
    let coord = seeded_indexed_coord();
    // A plain equality still plans the single-value seek (which alone carries the `ordered` flag).
    let eq = compile_with(
        "MATCH (u:USER) WHERE u.uidn = 1 RETURN u.id AS id",
        &coord.catalog(),
    )
    .to_string();
    assert!(eq.contains("NodeIndexSeek(u:USER uidn = 1"), "{eq}");
    assert!(!eq.contains("MultiSeek"), "{eq}");

    // A single-element IN list is exactly one equality, so it takes the *same* single-value seek —
    // `x IN [e]` and `x = e` have identical three-valued semantics.
    let one = compile_with(
        "MATCH (u:USER) WHERE u.uidn IN [1] RETURN u.id AS id",
        &coord.catalog(),
    )
    .to_string();
    assert!(
        one.contains("NodeIndexMultiSeek(u:USER uidn IN [1]"),
        "a one-element IN list stays on the multi-seek path (one descent), got:\n{one}"
    );

    // A bare equality is never routed through the multi-value analysis, even where the single-value
    // seek would decline: only the `IN` and `OR` spellings are entry points, so the single-value seek
    // — the only one that can carry the `rmp` #665 provided-order elision and the `rmp` #708 correlated
    // per-row key — always wins a plain equality.
    let correlated = compile_with(
        "UNWIND [1, 2] AS t MATCH (u:USER) WHERE u.uidn = t RETURN u.id AS id",
        &coord.catalog(),
    )
    .to_string();
    assert!(
        correlated.contains("NodeIndexSeek(u:USER uidn = t") && !correlated.contains("MultiSeek"),
        "a correlated equality keeps the per-row single-value seek, got:\n{correlated}"
    );

    // A range predicate is unchanged.
    let range = compile_with(
        "MATCH (u:USER) WHERE u.uidn > 1 RETURN u.id AS id",
        &coord.catalog(),
    )
    .to_string();
    assert!(range.contains("NodeIndexRangeSeek"), "{range}");
}

#[test]
fn a_single_equality_conjunct_still_wins_over_an_in_list() {
    // `rmp` #868 runs its pass AFTER the single-predicate loop precisely so every plan that already
    // used an index is byte-identical to before. Here both `uidn` and `grp` are indexed; the equality
    // must still be the consumed conjunct and the `IN` must stay a residual filter.
    let mut coord = fresh_coord();
    run_write(&mut coord, "CREATE (:USER {id: 1, uidn: 1, grp: 9})");
    index_users(&mut coord);
    coord
        .create_node_property_index("USER", "grp")
        .expect("create the USER.grp index");

    let rendered = compile_with(
        "MATCH (u:USER) WHERE u.uidn IN [1, 2] AND u.grp = 9 RETURN u.id AS id",
        &coord.catalog(),
    )
    .to_string();
    assert!(
        rendered.contains("NodeIndexSeek(u:USER grp = 9"),
        "the single equality must still be consumed into the seek, got:\n{rendered}"
    );
    assert!(
        !rendered.contains("MultiSeek"),
        "the IN list must stay a residual filter here, got:\n{rendered}"
    );
}

// =================================================================================================
// Semantics: parity with the scan, duplicates, cross-type, empty list
// =================================================================================================

#[test]
fn in_list_returns_exactly_the_scan_rows() {
    let mut coord = seeded_indexed_coord();
    let ids = assert_seek_matches_scan(
        &mut coord,
        "MATCH (u:USER) WHERE u.uidn IN [1, 2, 3] RETURN u.id AS id",
        "NodeIndexMultiSeek",
    );
    // id 5 also carries uidn 2; id 6 carries the float 3.0, Cypher-equal to the integer 3.
    assert_eq!(ids, vec![1, 2, 3, 5, 6]);
}

#[test]
fn or_of_equalities_returns_exactly_the_scan_rows() {
    let mut coord = seeded_indexed_coord();
    let ids = assert_seek_matches_scan(
        &mut coord,
        "MATCH (u:USER) WHERE u.uidn = 1 OR u.uidn = 2 RETURN u.id AS id",
        "NodeIndexMultiSeek",
    );
    assert_eq!(ids, vec![1, 2, 5]);
}

#[test]
fn a_repeated_alternative_does_not_duplicate_result_rows() {
    // The acceptance criterion: `IN [1, 1, 2]` must return each matching node ONCE. The bag comparison
    // inside `assert_seek_matches_scan` is what makes this meaningful — a union that seeked `1` twice
    // and concatenated would return id 1 twice while the scan returns it once.
    //
    // The guard this pins is the operator's final `sorted_deduped`, NOT the value-level collapse:
    // removing the collapse costs a redundant descent but cannot duplicate a row, while removing the
    // id dedup fails this test. (Mutation-verified both ways; the collapse is pinned as the
    // descent-count guard it actually is, in `tests/multi_value_seek_hardening.rs`.)
    let mut coord = seeded_indexed_coord();
    let ids = assert_seek_matches_scan(
        &mut coord,
        "MATCH (u:USER) WHERE u.uidn IN [1, 1, 2, 2, 2] RETURN u.id AS id",
        "NodeIndexMultiSeek",
    );
    assert_eq!(ids, vec![1, 2, 5], "each matching node exactly once");

    // The same through the OR spelling.
    let ids = assert_seek_matches_scan(
        &mut coord,
        "MATCH (u:USER) WHERE u.uidn = 1 OR u.uidn = 1 RETURN u.id AS id",
        "NodeIndexMultiSeek",
    );
    assert_eq!(ids, vec![1]);
}

#[test]
fn cypher_equal_alternatives_of_different_types_collapse_without_losing_rows() {
    // `3` and `3.0` are Cypher-equal, so they collapse to ONE descent (`equivalence::equivalent`). The
    // collapse is only sound because `NodePropertyIndex::seek_eq` probes the whole Cypher-equal class
    // (`rmp` #466) — the order-preserving index key is NOT Cypher-equality-canonical, so a naive
    // collapse would lose the node stored under the sibling encoding. Node id 3 holds the integer 3 and
    // node id 6 holds the float 3.0: BOTH must come back, from either spelling of the alternative.
    let mut coord = seeded_indexed_coord();
    for src in [
        "MATCH (u:USER) WHERE u.uidn IN [3, 3.0] RETURN u.id AS id",
        "MATCH (u:USER) WHERE u.uidn IN [3] RETURN u.id AS id",
        "MATCH (u:USER) WHERE u.uidn IN [3.0] RETURN u.id AS id",
    ] {
        let ids = assert_seek_matches_scan(&mut coord, src, "NodeIndexMultiSeek");
        assert_eq!(ids, vec![3, 6], "{src}");
    }
}

/// A UNIQUE constraint rejects a **cross-type** duplicate at the `i64`/`f64` boundary, through its
/// index-backed check (`rmp` task #868, scope check).
///
/// `rmp` #738 names the worst consequence of a narrow index seek: *"a UNIQUE constraint check passing
/// over rows it never examined"*. Constraint validation is index-accelerated —
/// `RecordStoreGraph::unique_conflict` asks `index_seek_eq` for the holders of the new value — so #868
/// had to establish that it still rejects a duplicate the seek could conceivably miss. This pins that
/// it does.
///
/// **What this test does NOT prove.** It is deliberately reported as insensitive to the probe-class fix
/// in `graphus-index::numeric_equal_sibling`: restoring the old narrow probe class by mutation leaves
/// it passing, because `9007199254740992` and `9007199254740993` happen to share one *order-preserving*
/// index key (that key folds an `i64` onto its `f64` magnitude), so the candidate reaches the re-check
/// either way. The probe-class fix is pinned by
/// [`large_integer_float_alternatives_neither_lose_nor_duplicate_rows`] instead, where the missed value
/// is a `Float` whose key carries a different numtag. No claim is made here that the constraint was
/// ever broken — only that it is not broken now.
#[test]
fn a_unique_constraint_rejects_a_cross_type_duplicate_the_index_used_to_miss() {
    let mut coord = fresh_coord();
    // A UNIQUE constraint registers and populates a backing node-property index, so the duplicate check
    // takes the SEEK path — the one that was narrow.
    coord
        .create_constraint("uniq_uidn", "USER", "uidn", ConstraintKind::Unique)
        .expect("declare the uniqueness constraint");

    run_write(&mut coord, "CREATE (:USER {id: 1, uidn: 9007199254740993})");

    // `9007199254740992.0 = 9007199254740993` is TRUE under Cypher's mixed INTEGER/FLOAT comparison, so
    // this is a duplicate and must be rejected.
    let plan = compile_with(
        "CREATE (:USER {id: 2, uidn: 9007199254740992.0})",
        &IndexCatalog::empty(),
    );
    let txn = coord.begin_serializable();
    let bound = bind_parameters(&plan, &Parameters::new()).expect("bind");
    let captured = {
        let mut graph = coord.statement(txn).expect("statement");
        let mut cursor = execute(&plan, &bound, &mut graph).expect("open cursor");
        let _ = cursor.collect_all();
        graph.take_error()
    };
    coord
        .rollback(txn)
        .expect("the rejected write rolls back cleanly");
    let err = captured.expect("the duplicate must be rejected, not admitted");
    assert!(
        err.to_string().contains(CONSTRAINT_VIOLATION_PREFIX),
        "expected a constraint violation, got: {err}"
    );

    // A genuinely distinct value is still accepted, so the check has not become blanket-restrictive.
    run_write(&mut coord, "CREATE (:USER {id: 3, uidn: 1})");
    // The check really is index-backed: the constraint's backing index is planner-visible, so
    // `unique_conflict` takes its `index_seek_eq` arm rather than the no-index label scan.
    let backed = compile_with(
        "MATCH (u:USER) WHERE u.uidn = 1 RETURN u.id AS id",
        &coord.catalog(),
    )
    .to_string();
    assert!(
        backed.contains("NodeIndexSeek"),
        "the constraint must register a planner-visible backing index, got:\n{backed}"
    );
}

/// **Regression, `rmp` #868: the alternative collapse must key on VALUE IDENTITY, never on the index
/// key** — `duration({days: 1})` and `duration({hours: 24})`.
///
/// `encode_single` is the **order-preserving** index key, and for a `Duration` it is
/// `duration_order_nanos`, an approximate projection the codec documents as deliberately coarser than
/// equality ("equality remains strictly component-wise"). `1 day` and `24 hours` therefore encode to
/// **byte-identical keys** while being Cypher-**unequal** (`=` compares durations component-wise). An
/// implementation that collapsed alternatives by that key issued one descent instead of two and lost
/// every row only the dropped alternative matched — measured as a multi-seek returning `[1]` where the
/// scan returned `[1, 2]`. That is exactly the `rmp` #738 defect class, inside the operator the #868
/// doc claims makes it "unexpressible".
///
/// The same hazard exists for two large integers that share one `f64` magnitude, pinned below.
#[test]
fn order_equal_but_unequal_durations_are_not_collapsed() {
    let mut coord = fresh_coord();
    run_write(
        &mut coord,
        "CREATE (:USER {id: 1, uidn: duration({days: 1})})",
    );
    run_write(
        &mut coord,
        "CREATE (:USER {id: 2, uidn: duration({hours: 24})})",
    );
    run_write(
        &mut coord,
        "CREATE (:USER {id: 3, uidn: duration({days: 2})})",
    );
    index_users(&mut coord);

    // Both orders, so an order-dependent collapse cannot hide behind "the first one won".
    for src in [
        "MATCH (u:USER) WHERE u.uidn IN [duration({days: 1}), duration({hours: 24})] \
         RETURN u.id AS id",
        "MATCH (u:USER) WHERE u.uidn IN [duration({hours: 24}), duration({days: 1})] \
         RETURN u.id AS id",
        "MATCH (u:USER) WHERE u.uidn = duration({days: 1}) OR u.uidn = duration({hours: 24}) \
         RETURN u.id AS id",
    ] {
        let ids = assert_seek_matches_scan(&mut coord, src, "NodeIndexMultiSeek");
        assert_eq!(
            ids,
            vec![1, 2],
            "both order-equal but component-unequal durations must match, for {src:?}"
        );
    }

    // And each alone still matches only its own node — the collapse is not merely disabled, the two
    // alternatives really are distinguished.
    for (src, want) in [
        (
            "MATCH (u:USER) WHERE u.uidn IN [duration({days: 1})] RETURN u.id AS id",
            vec![1],
        ),
        (
            "MATCH (u:USER) WHERE u.uidn IN [duration({hours: 24})] RETURN u.id AS id",
            vec![2],
        ),
    ] {
        assert_eq!(
            assert_seek_matches_scan(&mut coord, src, "NodeIndexMultiSeek"),
            want,
            "{src}"
        );
    }
}

/// **Regression, `rmp` #868: the same hazard on the `i64` side.**
///
/// The order-preserving key folds an `i64` onto its `f64` magnitude, so `9007199254740992` and
/// `9007199254740993` (2^53 and 2^53 + 1) share one key while selecting different rows. They must not
/// collapse into a single descent.
///
/// This test compares the multi-value seek against **`k` separate single-value seeks**, not against the
/// scan. That is the invariant #868 owns: a union of `k` descents must return exactly what those `k`
/// descents return. Whether an indexed `=` agrees with a *scanned* `=` at magnitudes at or above 2^53 is
/// a **separate, open** question — the index's cross-type probe class (`graphus-index`
/// `numeric_equal_sibling`) follows `encode_equality_canonical`, which keeps a large integer distinct
/// from its rounded `f64` exactly as Neo4j's `NumberValues.numbersEqual` does, while
/// `graphus_cypher::equality` compares the pair as `f64`. Reconciling those two is a specification
/// decision outside this task; see the `rmp` #868 report.
#[test]
fn large_integer_alternatives_are_not_collapsed_into_one_descent() {
    let mut coord = fresh_coord();
    run_write(&mut coord, "CREATE (:USER {id: 1, uidn: 9007199254740993})");
    run_write(&mut coord, "CREATE (:USER {id: 2, uidn: 9007199254740992})");
    index_users(&mut coord);
    let catalog = coord.catalog();

    // The union of the two alternatives must equal the union of the two single-value seeks.
    let single_a = read_ids(
        &mut coord,
        "MATCH (u:USER) WHERE u.uidn = 9007199254740993 RETURN u.id AS id",
        &catalog,
    );
    let single_b = read_ids(
        &mut coord,
        "MATCH (u:USER) WHERE u.uidn = 9007199254740992 RETURN u.id AS id",
        &catalog,
    );
    let mut union: Vec<i64> = single_a.iter().chain(single_b.iter()).copied().collect();
    union.sort_unstable();
    union.dedup();
    assert_eq!(union, vec![1, 2], "the two seeks reach different nodes");

    for src in [
        "MATCH (u:USER) WHERE u.uidn IN [9007199254740993, 9007199254740992] RETURN u.id AS id",
        "MATCH (u:USER) WHERE u.uidn IN [9007199254740992, 9007199254740993] RETURN u.id AS id",
    ] {
        let plan = compile_with(src, &catalog);
        assert!(plan.to_string().contains("NodeIndexMultiSeek"), "{plan}");
        assert_eq!(
            read_ids(&mut coord, src, &catalog),
            union,
            "the union must equal the union of the individual seeks, for {src:?}"
        );
    }
}

#[test]
fn an_empty_in_list_returns_zero_rows_without_declining_to_a_scan() {
    // openCypher: `x IN []` is FALSE for every `x`, including `null` (the OR-fold of no terms is its
    // identity). So the correct plan answers zero rows, and it does so without touching the store.
    let mut coord = seeded_indexed_coord();
    let catalog = coord.catalog();
    let rendered = compile_with(
        "MATCH (u:USER) WHERE u.uidn IN [] RETURN u.id AS id",
        &catalog,
    )
    .to_string();
    assert!(
        rendered.contains("NodeIndexMultiSeek(u:USER uidn IN [] via"),
        "an empty IN list is a legal zero-descent seek, got:\n{rendered}"
    );
    let ids = assert_seek_matches_scan(
        &mut coord,
        "MATCH (u:USER) WHERE u.uidn IN [] RETURN u.id AS id",
        "NodeIndexMultiSeek",
    );
    assert!(ids.is_empty(), "IN [] matches nothing, got {ids:?}");
}

#[test]
fn a_null_alternative_declines_the_whole_union_to_the_exact_scan() {
    // TRAP 1 / `rmp` #738: `null` is not index-encodable, so `seek_node_property_eq` DECLINES for it.
    // The union must then take the exact scan for EVERY value rather than silently dropping `null`
    // from the list and proceeding — and the answer must still be the three-valued-correct one
    // (`3 IN [1, null]` is `null`, which a `WHERE` drops exactly like `false`, so the positive match
    // set is unchanged).
    let mut coord = seeded_indexed_coord();
    let ids = assert_seek_matches_scan(
        &mut coord,
        "MATCH (u:USER) WHERE u.uidn IN [1, null, 2] RETURN u.id AS id",
        "NodeIndexMultiSeek",
    );
    assert_eq!(
        ids,
        vec![1, 2, 5],
        "the non-null alternatives still match, and nothing else does"
    );

    // A list of only nulls matches nothing at all.
    let ids = assert_seek_matches_scan(
        &mut coord,
        "MATCH (u:USER) WHERE u.uidn IN [null] RETURN u.id AS id",
        "NodeIndexMultiSeek",
    );
    assert!(ids.is_empty(), "IN [null] is never TRUE, got {ids:?}");
}

#[test]
fn a_non_matching_and_a_mixed_type_alternative_are_served_correctly() {
    let mut coord = seeded_indexed_coord();
    // A value no node carries, and a value of a different type entirely.
    let ids = assert_seek_matches_scan(
        &mut coord,
        "MATCH (u:USER) WHERE u.uidn IN [99, 'two', 4] RETURN u.id AS id",
        "NodeIndexMultiSeek",
    );
    assert_eq!(ids, vec![4]);
}

/// **The whole-union decline, proven non-vacuously.** A `List` value is not index-encodable
/// (`rmp` #680), so its descent declines — and the seeded graph contains a node that **actually holds
/// that list**, so the declining alternative has real rows to lose.
///
/// This is what makes the test bite: with a `null` alternative the union could silently drop the
/// declining value and still answer correctly (`null` matches nothing), so a `null`-only test proves
/// nothing about the decline contract. Here, dropping the declining value from the union loses node 3
/// — exactly the `rmp` #738 defect class.
#[test]
fn a_matching_list_alternative_declines_the_whole_union_to_the_exact_scan() {
    let mut coord = fresh_coord();
    run_write(&mut coord, "CREATE (:USER {id: 1, uidn: 1})");
    run_write(&mut coord, "CREATE (:USER {id: 2, uidn: 2})");
    // A list-valued property: the index cannot key it, but the scan matches it exactly.
    run_write(&mut coord, "CREATE (:USER {id: 3, uidn: [7, 8]})");
    index_users(&mut coord);

    let ids = assert_seek_matches_scan(
        &mut coord,
        "MATCH (u:USER) WHERE u.uidn IN [1, [7, 8]] RETURN u.id AS id",
        "NodeIndexMultiSeek",
    );
    assert_eq!(
        ids,
        vec![1, 3],
        "the row only the DECLINING alternative matches must not be lost"
    );

    // Same through the OR spelling, and with the declining alternative first.
    let ids = assert_seek_matches_scan(
        &mut coord,
        "MATCH (u:USER) WHERE u.uidn = [7, 8] OR u.uidn = 1 RETURN u.id AS id",
        "NodeIndexMultiSeek",
    );
    assert_eq!(ids, vec![1, 3]);

    // And a list that matches ONLY through the declining alternative.
    let ids = assert_seek_matches_scan(
        &mut coord,
        "MATCH (u:USER) WHERE u.uidn IN [[7, 8]] RETURN u.id AS id",
        "NodeIndexMultiSeek",
    );
    assert_eq!(ids, vec![3]);
}

#[test]
fn parameters_bind_as_alternatives() {
    // Every alternative is walked by `binding::walk_physical`, or a `$param` alternative would never
    // bind. Exercised end-to-end through the executor.
    let mut coord = seeded_indexed_coord();
    let catalog = coord.catalog();
    let src = "MATCH (u:USER) WHERE u.uidn IN [$a, $b] RETURN u.id AS id";
    let plan = compile_with(src, &catalog);
    assert!(
        plan.to_string().contains("NodeIndexMultiSeek"),
        "{}",
        plan.to_string()
    );
    let mut params = Parameters::new();
    params.insert("a".to_owned(), Value::Integer(1));
    params.insert("b".to_owned(), Value::Integer(4));
    let bound = bind_parameters(&plan, &params).expect("bind");
    let txn = coord.begin_serializable();
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
    assert_eq!(ids, vec![1, 4]);
}

// =================================================================================================
// Three-valued logic: the positions where the rewrite would be ILLEGAL must decline
// =================================================================================================

#[test]
fn a_negated_in_list_is_never_rewritten() {
    // `NOT (n.p IN [1, null])` is `NOT null` = `null`, not `true`. Consuming the inner `IN` into a
    // positive match set and negating it would invert `null` into a match. The analysis matches only
    // the two top-level spellings, so `NOT` can never reach it.
    let coord = seeded_indexed_coord();
    let rendered = compile_with(
        "MATCH (u:USER) WHERE NOT (u.uidn IN [1, 2]) RETURN u.id AS id",
        &coord.catalog(),
    )
    .to_string();
    assert!(
        !rendered.contains("MultiSeek"),
        "a negated IN must stay a residual filter, got:\n{rendered}"
    );
    assert!(rendered.contains("Filter"), "{rendered}");
}

#[test]
fn an_in_list_disjoined_with_a_different_property_is_never_rewritten() {
    // `u.uidn IN [1] OR u.other = 2` is a union of two DIFFERENT access paths, and its three-valued
    // result is observable inside the larger `OR`. Out of scope, stays a filter.
    let coord = seeded_indexed_coord();
    let rendered = compile_with(
        "MATCH (u:USER) WHERE u.uidn IN [1, 2] OR u.other = 7 RETURN u.id AS id",
        &coord.catalog(),
    )
    .to_string();
    assert!(
        !rendered.contains("MultiSeek"),
        "a disjunction over different properties must decline, got:\n{rendered}"
    );
}

#[test]
fn an_or_mixing_an_equality_with_a_range_is_never_rewritten() {
    let coord = seeded_indexed_coord();
    let rendered = compile_with(
        "MATCH (u:USER) WHERE u.uidn = 1 OR u.uidn > 3 RETURN u.id AS id",
        &coord.catalog(),
    )
    .to_string();
    assert!(
        !rendered.contains("MultiSeek"),
        "an equality/range mix must decline, got:\n{rendered}"
    );
}

#[test]
fn an_or_across_two_different_variables_is_never_rewritten() {
    let mut coord = seeded_indexed_coord();
    run_write(&mut coord, "CREATE (:USER {id: 8, uidn: 8})");
    let rendered = compile_with(
        "MATCH (u:USER), (v:USER) WHERE u.uidn = 1 OR v.uidn = 2 RETURN u.id AS id",
        &coord.catalog(),
    )
    .to_string();
    assert!(
        !rendered.contains("MultiSeek"),
        "a disjunction across variables must decline, got:\n{rendered}"
    );
}

#[test]
fn an_in_list_in_a_projection_is_never_rewritten() {
    // In a projection the three-valued result is the VALUE returned, not a row filter, so the
    // positive-match-set rewrite is not available at all. It is not a `Filter` conjunct, so it never
    // reaches the analysis.
    let coord = seeded_indexed_coord();
    let rendered = compile_with(
        "MATCH (u:USER) RETURN u.uidn IN [1, 2] AS hit, u.id AS id",
        &coord.catalog(),
    )
    .to_string();
    assert!(
        !rendered.contains("MultiSeek"),
        "an IN in a projection must not drive a seek, got:\n{rendered}"
    );
}

#[test]
fn a_non_list_in_right_side_declines() {
    // `IN $ids` / `IN keys(m)`: the alternatives are not enumerable at plan time, so `k` is unknown and
    // the cost comparison the operator is costed by cannot be made. A named deferral of `rmp` #868.
    let coord = seeded_indexed_coord();
    for src in [
        "MATCH (u:USER) WHERE u.uidn IN $ids RETURN u.id AS id",
        "MATCH (u:USER) WHERE u.uidn IN range(1, 3) RETURN u.id AS id",
    ] {
        let rendered = compile_with(src, &coord.catalog()).to_string();
        assert!(
            !rendered.contains("MultiSeek"),
            "{src:?} must decline (k unknown at plan time), got:\n{rendered}"
        );
    }
}

#[test]
fn an_alternative_referencing_a_variable_declines() {
    // A multi-value seek is never correlated: the executor evaluates its alternatives against the EMPTY
    // row, so an alternative that reads a variable would silently evaluate to `null`.
    let coord = seeded_indexed_coord();
    for src in [
        "MATCH (u:USER) WHERE u.uidn IN [1, u.other] RETURN u.id AS id",
        "UNWIND [1, 2] AS t MATCH (u:USER) WHERE u.uidn IN [t, 3] RETURN u.id AS id",
    ] {
        let rendered = compile_with(src, &coord.catalog()).to_string();
        assert!(
            !rendered.contains("MultiSeek"),
            "{src:?} must decline (a value referencing a variable), got:\n{rendered}"
        );
    }
}

#[test]
fn without_an_index_the_in_list_stays_a_scan() {
    // The decline that matters most: no index on `(USER, uidn)` means no seek, and the answer is the
    // same scan+filter answer as before this task.
    let mut coord = fresh_coord();
    seed_users(&mut coord);
    let rendered = compile_with(
        "MATCH (u:USER) WHERE u.uidn IN [1, 2] RETURN u.id AS id",
        &coord.catalog(),
    )
    .to_string();
    assert!(!rendered.contains("MultiSeek"), "{rendered}");
    let catalog = coord.catalog();
    let ids = read_ids(
        &mut coord,
        "MATCH (u:USER) WHERE u.uidn IN [1, 2] RETURN u.id AS id",
        &catalog,
    );
    assert_eq!(ids, vec![1, 2, 5]);
}

// =================================================================================================
// Ordering: a multi-value seek must NEVER claim the provided-order Sort elision (`rmp` #665)
// =================================================================================================

#[test]
fn a_multi_value_seek_never_elides_an_order_by() {
    // `k` concatenated descents are not globally ordered by the property, so the `Sort` must survive.
    // (Contrast the single-value seek immediately below, which legitimately takes the elision.)
    let coord = seeded_indexed_coord();
    let rendered = compile_with(
        "MATCH (u:USER) WHERE u.uidn IN [3, 1, 2] RETURN u.id AS id ORDER BY u.uidn",
        &coord.catalog(),
    )
    .to_string();
    assert!(rendered.contains("NodeIndexMultiSeek"), "{rendered}");
    assert!(
        rendered.contains("Sort"),
        "the Sort above a multi-value seek must NOT be elided, got:\n{rendered}"
    );
    assert!(
        !rendered.contains("ordered asc"),
        "a multi-value seek must never be marked order-providing, got:\n{rendered}"
    );
}

#[test]
fn the_single_value_seek_still_elides_its_order_by() {
    // The control: the elision machinery is alive, so the assertion above is about the multi-seek being
    // excluded — not about the elision having been disabled everywhere.
    let coord = seeded_indexed_coord();
    let rendered = compile_with(
        "MATCH (u:USER) WHERE u.uidn > 1 RETURN u.id AS id ORDER BY u.uidn",
        &coord.catalog(),
    )
    .to_string();
    assert!(
        rendered.contains("ordered asc") && !rendered.contains("Sort"),
        "the single-value range seek still provides order, got:\n{rendered}"
    );
}

#[test]
fn an_order_by_over_a_multi_value_seek_still_returns_sorted_rows() {
    // The behavioural half of the guard: whatever the plan shape, the rows come out sorted. This is the
    // assertion that would fail if the multi-seek were wrongly granted the elision.
    let mut coord = seeded_indexed_coord();
    let catalog = coord.catalog();
    let plan = compile_with(
        "MATCH (u:USER) WHERE u.uidn IN [4, 1, 2] RETURN u.uidn AS id ORDER BY u.uidn",
        &catalog,
    );
    let bound = bind_parameters(&plan, &Parameters::new()).expect("bind");
    let txn = coord.begin_serializable();
    let rows = {
        let mut graph = coord.statement(txn).expect("statement");
        let mut cursor = execute(&plan, &bound, &mut graph).expect("open cursor");
        cursor.collect_all().expect("collect")
    };
    coord.commit(txn).expect("read commits");
    let seq: Vec<i64> = rows
        .iter()
        .map(|r| match r.value("id") {
            Value::Integer(i) => i,
            other => panic!("expected an integer, got {other:?}"),
        })
        .collect();
    assert_eq!(
        seq,
        vec![1, 2, 2, 4],
        "rows must be ascending by uidn (ids 1, 2, 5, 4)"
    );
}

// =================================================================================================
// Cost: a large IN list reverts to the scan
// =================================================================================================

/// Statistics describing a label of `n` nodes, with no histogram — the shape a freshly-loaded store
/// has before `ANALYZE`.
struct LabelOf(u64);

impl Statistics for LabelOf {
    fn total_nodes(&self) -> u64 {
        self.0
    }
    fn nodes_with_label(&self, _label: &str) -> Option<u64> {
        Some(self.0)
    }
    fn total_relationships(&self) -> u64 {
        0
    }
    fn relationships_with_type(&self, _rel_type: &str) -> Option<u64> {
        Some(0)
    }
}

/// The seek-vs-scan comparison is **live in both directions** for a multi-value seek: it reverts to the
/// scan when the label is small enough that `k` seek setups outweigh `k` comparisons over a handful of
/// rows, and keeps the seek otherwise.
///
/// # What the crossover actually is, measured
///
/// The comparison costs the seek at `k` setups plus the matched rows, and the scan at one pass over the
/// label plus `rows × k` predicate comparisons (`cost::filter_width` — an `IN` list of `k` elements is
/// `k` comparisons per row, not one). The scan therefore wins only while the label has a *handful* of
/// rows; past that the `rows × k` term dominates. That is not a modelling artefact — on a 50 000-node
/// label with `k = 20 000` the reverted scan was measured at **39.1 s against the seek's 51 ms**
/// (`rmp` #868). Before `filter_width` existed the model priced the `IN` list's `k` comparisons at
/// zero and chose that 39-second plan.
#[test]
fn the_seek_vs_scan_comparison_reverts_on_a_tiny_label_and_keeps_the_seek_otherwise() {
    let coord = seeded_indexed_coord();
    let catalog = coord.catalog();
    let src_small = "MATCH (u:USER) WHERE u.uidn IN [1, 2, 3] RETURN u.id AS id";
    let big_list = (1..=200)
        .map(|i| i.to_string())
        .collect::<Vec<_>>()
        .join(", ");
    let src_big = format!("MATCH (u:USER) WHERE u.uidn IN [{big_list}] RETURN u.id AS id");

    // A three-node label: `k = 8` setups lose to eight comparisons over three rows, so revert.
    let reverted = compile_with_stats(
        "MATCH (u:USER) WHERE u.uidn IN [1, 2, 3, 4, 5, 6, 7, 8] RETURN u.id AS id",
        &catalog,
        &LabelOf(3),
    )
    .to_string();
    assert!(
        !reverted.contains("MultiSeek"),
        "a tiny label must revert to the scan, got:\n{reverted}"
    );
    assert!(
        (reverted.contains("TokenLookupScan") || reverted.contains("NodeByLabelScan"))
            && reverted.contains("Filter"),
        "the reverted plan must be a scan re-applying the IN predicate, got:\n{reverted}"
    );

    // The same tiny label keeps the seek for a *short* list — the comparison is not simply "always
    // revert".
    let kept_small_k = compile_with_stats(src_small, &catalog, &LabelOf(3)).to_string();
    assert!(
        kept_small_k.contains("NodeIndexMultiSeek"),
        "a 3-element list over the same tiny label keeps the seek, got:\n{kept_small_k}"
    );

    // And a realistically-sized label keeps the seek at BOTH list sizes — the regime the 39-second
    // measurement covers. A revert here would be the pessimisation `filter_width` exists to prevent.
    for (src, k) in [(src_small, 3usize), (src_big.as_str(), 200)] {
        let kept = compile_with_stats(src, &catalog, &LabelOf(200_000)).to_string();
        assert!(
            kept.contains("NodeIndexMultiSeek"),
            "a 200k-node label must keep the seek at k = {k}, got:\n{kept}"
        );
    }
}

#[test]
fn the_reverted_scan_returns_the_same_rows_as_the_seek() {
    // The revert is only admissible if it is bag-preserving. Run both realisations and compare.
    let mut coord = seeded_indexed_coord();
    let catalog = coord.catalog();
    let src = "MATCH (u:USER) WHERE u.uidn IN [1, 2, 3, 4, 5, 6, 7, 8] RETURN u.id AS id";

    let seek_plan = compile_with(src, &catalog);
    assert!(
        seek_plan.to_string().contains("NodeIndexMultiSeek"),
        "{seek_plan}"
    );
    let reverted = compile_with_stats(src, &catalog, &LabelOf(3));
    assert!(
        !reverted.to_string().contains("MultiSeek"),
        "expected a revert, got:\n{reverted}"
    );

    let run = |coord: &mut Coord, plan: &PhysicalPlan| -> Vec<i64> {
        let bound = bind_parameters(plan, &Parameters::new()).expect("bind");
        let txn = coord.begin_serializable();
        let rows = {
            let mut graph = coord.statement(txn).expect("statement");
            let mut cursor = execute(plan, &bound, &mut graph).expect("open cursor");
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
    };
    let want = vec![1, 2, 3, 4, 5, 6];
    assert_eq!(run(&mut coord, &seek_plan), want);
    assert_eq!(
        run(&mut coord, &reverted),
        want,
        "the reverted scan must answer exactly what the seek answers"
    );
}

// =================================================================================================
// Relationships: the same operator over a relationship-property index
// =================================================================================================

/// Seeds a small `:KNOWS` graph with a `since` property and declares its index.
fn seeded_indexed_rel_coord() -> Coord {
    let mut coord = fresh_coord();
    run_write(
        &mut coord,
        "CREATE (:P {id: 1})-[:KNOWS {since: 2020, rid: 1}]->(:P {id: 2})",
    );
    run_write(
        &mut coord,
        "CREATE (:P {id: 3})-[:KNOWS {since: 2021, rid: 2}]->(:P {id: 4})",
    );
    run_write(
        &mut coord,
        "CREATE (:P {id: 5})-[:KNOWS {since: 2022, rid: 3}]->(:P {id: 6})",
    );
    run_write(
        &mut coord,
        "CREATE (:P {id: 7})-[:KNOWS {since: 2020, rid: 4}]->(:P {id: 8})",
    );
    coord
        .create_rel_property_index_named(Some("ix_since"), "KNOWS", "since", false)
        .expect("create the KNOWS.since index");
    coord
}

#[test]
fn a_relationship_in_list_plans_and_answers_a_multi_value_seek() {
    let mut coord = seeded_indexed_rel_coord();
    let src = "MATCH ()-[r:KNOWS]->() WHERE r.since IN [2020, 2022] RETURN r.rid AS id";
    let rendered = compile_with(src, &coord.catalog()).to_string();
    assert!(
        rendered.contains("RelIndexMultiSeek"),
        "the relationship IN list must lower to a multi-value seek, got:\n{rendered}"
    );
    let ids = assert_seek_matches_scan(&mut coord, src, "RelIndexMultiSeek");
    assert_eq!(ids, vec![1, 3, 4]);
}

#[test]
fn a_relationship_or_of_equalities_plans_and_answers_a_multi_value_seek() {
    let mut coord = seeded_indexed_rel_coord();
    let ids = assert_seek_matches_scan(
        &mut coord,
        "MATCH ()-[r:KNOWS]->() WHERE r.since = 2021 OR r.since = 2022 RETURN r.rid AS id",
        "RelIndexMultiSeek",
    );
    assert_eq!(ids, vec![2, 3]);
}

#[test]
fn an_undirected_relationship_multi_seek_matches_the_scan_bag_exactly() {
    // An undirected pattern surfaces each relationship in BOTH orientations; the seek must reproduce
    // that doubling exactly, which the bag comparison against the scan path witnesses.
    let mut coord = seeded_indexed_rel_coord();
    let ids = assert_seek_matches_scan(
        &mut coord,
        "MATCH ()-[r:KNOWS]-() WHERE r.since IN [2020] RETURN r.rid AS id",
        "RelIndexMultiSeek",
    );
    assert_eq!(ids, vec![1, 1, 4, 4], "each match once per orientation");
}

#[test]
fn a_relationship_repeated_alternative_does_not_duplicate_rows() {
    let mut coord = seeded_indexed_rel_coord();
    let ids = assert_seek_matches_scan(
        &mut coord,
        "MATCH ()-[r:KNOWS]->() WHERE r.since IN [2020, 2020, 2020.0] RETURN r.rid AS id",
        "RelIndexMultiSeek",
    );
    assert_eq!(ids, vec![1, 4]);
}

#[test]
fn a_relationship_null_alternative_declines_the_whole_union_to_the_scan() {
    let mut coord = seeded_indexed_rel_coord();
    let ids = assert_seek_matches_scan(
        &mut coord,
        "MATCH ()-[r:KNOWS]->() WHERE r.since IN [2021, null] RETURN r.rid AS id",
        "RelIndexMultiSeek",
    );
    assert_eq!(ids, vec![2]);
}

#[test]
fn a_relationship_single_equality_still_wins_over_an_in_list() {
    let coord = seeded_indexed_rel_coord();
    let rendered = compile_with(
        "MATCH ()-[r:KNOWS]->() WHERE r.since = 2020 AND r.rid IN [1, 2] RETURN r.rid AS id",
        &coord.catalog(),
    )
    .to_string();
    assert!(
        rendered.contains("RelIndexSeek(") && !rendered.contains("MultiSeek"),
        "the single equality must still be consumed, got:\n{rendered}"
    );
}
