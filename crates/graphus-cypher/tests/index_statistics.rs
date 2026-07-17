//! End-to-end tests for **index selectivity statistics** (`rmp` task #572): the `ANALYZE` surface
//! (`db.resampleIndex` / `db.resampleOutdatedIndexes`) and the seeding of a histogram at
//! `CREATE INDEX`, driven through the **production** coordinator path.
//!
//! # What this file exists to prevent
//!
//! Before `rmp` task #572 the whole equi-depth histogram machinery existed but **had no production
//! caller**: `recompute_property_histogram` was reachable only from tests, so every declared index ran
//! the planner on the flat `DEFAULT_PREDICATE_SELECTIVITY` (0.3) constant for every range and join
//! estimate, however skewed the data. `db.resampleIndex` / `db.resampleOutdatedIndexes` were
//! registered as VOID no-ops whose justification was a comment claiming histograms are "rebuilt from
//! the store on open" — which nothing did.
//!
//! # Non-vacuity
//!
//! Every test here must be able to **fail**. A test that asserts "the estimate is good" would pass
//! just as happily against the constant fallback if the fallback happened to be close, and a test that
//! asserts "a histogram exists" proves nothing about whether it is *right*. So each test below pins
//! the **exact** value the seeded distribution implies AND contrasts it against the fallback the same
//! query would get without statistics — the two are held apart by an explicit assertion, so a
//! regression that silently reverts to the constant fails loudly.
//!
//! The seeded distribution is deliberately **skewed**, because a uniform one cannot distinguish a real
//! histogram from the constant: 90 `:Person` at `age = 1`, plus 10 spread over `10..=91`. A
//! `WHERE n.age > 50` matches exactly **5** of the 100 — where the 0.3 constant claims **30**, a 6x
//! over-estimate. That gap is what every assertion here is built on.

use graphus_core::capability::Rng;
use graphus_core::{TxnId, Value};
use graphus_cypher::binding::{Parameters, bind_parameters};
use graphus_cypher::catalog::IndexCatalog;
use graphus_cypher::coordinator::TxnCoordinator;
use graphus_cypher::executor::execute;
use graphus_cypher::lexer::tokenize;
use graphus_cypher::lower::lower;
use graphus_cypher::parser::parse_tokens;
use graphus_cypher::physical::{PhysicalPlan, plan_physical, plan_physical_with_stats};
use graphus_cypher::runtime::{Row, RowValue};
use graphus_cypher::semantics::analyze;
use graphus_cypher::statistics::Statistics;
use graphus_io::MemBlockDevice;
use graphus_sim::SimRng;
use graphus_storage::RecordStore;
use graphus_storage::recovery::recover_device;
use graphus_wal::{LogSink, MemLogSink, WalManager};

type Store = RecordStore<MemBlockDevice, MemLogSink>;
type Coord = TxnCoordinator<MemBlockDevice, MemLogSink>;

/// The plan estimate a `WHERE n.age > 50` gets with **no** statistics: 100 `:Person` * 0.3.
const FALLBACK_ROWS: f64 = 30.0;
/// The number of seeded `:Person` whose `age > 50` — what a *real* histogram must estimate.
const TRUE_ROWS_OVER_50: f64 = 5.0;
/// The worst absolute error an equi-depth histogram is held to at these populations, in rows —
/// measured, not assumed (`rmp` #572: 2.0 was the maximum observed over the DST seeds; the constant
/// fallback is off by up to 37 on the same queries).
const HISTOGRAM_TOLERANCE_ROWS: f64 = 2.0;

// =================================================================================================
// Harness (the coordinator-driven statement pattern of `coordinator_statistics.rs`)
// =================================================================================================

/// Deterministically reopens `store` from its **durable WAL prefix** — the recovery probe shared by
/// the index test suites (`text_index.rs`). This is a real crash-recovery reopen, not a graceful
/// close: a statistic that is staged but not durably logged does not survive it.
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

fn fresh_coord() -> Coord {
    let device = MemBlockDevice::new(0);
    let wal = WalManager::create(MemLogSink::new()).expect("create wal");
    let store: Store = RecordStore::create(device, wal, 64, 1).expect("create store");
    TxnCoordinator::new(store)
}

fn compile(src: &str) -> PhysicalPlan {
    let toks = tokenize(src).expect("lex");
    let ast = parse_tokens(&toks, src).expect("parse");
    let validated = analyze(&ast).expect("analyze");
    plan_physical(&lower(&validated), &IndexCatalog::empty())
}

fn lower_query(src: &str) -> graphus_cypher::logical::LogicalOp {
    let toks = tokenize(src).expect("lex");
    let ast = parse_tokens(&toks, src).expect("parse");
    let validated = analyze(&ast).expect("analyze");
    lower(&validated)
}

/// Runs one statement in `txn`; the per-statement seam is dropped before returning.
fn run_stmt(coord: &Coord, txn: TxnId, src: &str) -> Vec<Row> {
    let plan = compile(src);
    let bound = bind_parameters(&plan, &Parameters::new()).expect("bind");
    let mut graph = coord.statement(txn).expect("statement");
    let rows = {
        let mut cursor = execute(&plan, &bound, &mut graph).expect("open cursor");
        cursor.collect_all().expect("collect")
    };
    assert!(
        !graph.has_error(),
        "unexpected captured error: {:?}",
        graph.take_error()
    );
    rows
}

fn exec_commit(coord: &mut Coord, src: &str) {
    let txn = coord.begin_serializable();
    let _ = run_stmt(coord, txn, src);
    coord.commit(txn).expect("commit");
}

/// Runs `src` in its own transaction and returns the executor's error, if any — without asserting the
/// seam stayed clean (used for the procedures that are *expected* to fail).
fn exec_commit_result(coord: &mut Coord, src: &str) -> Result<(), String> {
    let txn = coord.begin_serializable();
    let plan = compile(src);
    let bound = bind_parameters(&plan, &Parameters::new()).expect("bind");
    let outcome = {
        let mut graph = coord.statement(txn).expect("statement");
        execute(&plan, &bound, &mut graph)
            .and_then(|mut c| c.collect_all())
            .map(|_| ())
            .map_err(|e| format!("{e}"))
    };
    match outcome {
        Ok(()) => {
            coord.commit(txn).expect("commit");
            Ok(())
        }
        Err(e) => {
            let _ = coord.rollback(txn);
            Err(e)
        }
    }
}

/// The **skewed** distribution the whole file is calibrated on: 100 `:Person`, 90 of them at
/// `age = 1`, the other 10 spread over `10, 19, 28, …, 91`. Exactly 5 have `age > 50`
/// (`55, 64, 73, 82, 91`) and there are exactly 11 distinct ages.
fn seed_skewed(coord: &mut Coord) {
    for _ in 0..90 {
        exec_commit(coord, "CREATE (:Person {age: 1})");
    }
    for k in 0..10 {
        exec_commit(coord, &format!("CREATE (:Person {{age: {}}})", 10 + k * 9));
    }
}

/// The **production** `CREATE INDEX` path: graphus-server drives
/// `begin_online_node_composite_index_named` (arity 1 delegating to the non-blocking
/// `begin_online_node_property_index_named`), then the engine drains the background build via
/// `advance_index_builds`. `create_node_property_index` is a *test-only* API with no production
/// caller — testing statistics through it would prove nothing about a real `CREATE INDEX`.
fn create_index_like_the_server(coord: &mut Coord, label: &str, property: &str) -> String {
    let created = coord
        .begin_online_node_composite_index_named(None, label, &[property.to_owned()], false)
        .expect("create index");
    assert!(created, "the index must actually be created");
    let mut guard = 0;
    while coord.advance_index_builds(64) {
        guard += 1;
        assert!(guard < 100_000, "the background build did not converge");
    }
    // Non-vacuity: an index that never came ONLINE would make every statistics assertion below
    // meaningless (and a `Populating` index is withheld from the planner entirely).
    let listed = coord.list_node_property_indexes();
    let entry = listed
        .iter()
        .find(|(_, l, p, _)| l == label && p == property)
        .expect("the index is declared");
    assert_eq!(
        format!("{:?}", entry.3),
        "Online",
        "the index must be ONLINE before its statistics are judged"
    );
    entry.0.clone()
}

/// Asserts `actual` is within one row of `expected`.
///
/// An equi-depth histogram **interpolates within a bucket**, so its range estimate is exact only when
/// the bound lands on a bucket boundary; elsewhere it carries sub-bucket error. One row is that
/// resolution at these seeded sizes (the observed error is 0.5 of a row — 0.9%). Asserting exact
/// equality here would be asserting a property the estimator does not claim; asserting nothing would
/// be vacuous. Every caller pairs this with an explicit "and it is NOT the stale/fallback value"
/// assertion, which is what actually proves the resample ran.
#[track_caller]
fn assert_near(actual: Option<f64>, expected: f64, what: &str) {
    let got = actual.unwrap_or_else(|| panic!("{what}: expected a histogram estimate, got None"));
    assert!(
        (got - expected).abs() <= 1.0,
        "{what}: expected ~{expected} (+/-1 row of equi-depth interpolation), got {got}"
    );
}

/// Asserts a histogram estimate is both **near** the ground truth and **decisively better** than the
/// constant fallback the planner would otherwise use.
///
/// Two bounds, each measured rather than assumed (see the `rmp` #572 measurement run):
///
/// * **Absolute** — within [`HISTOGRAM_TOLERANCE_ROWS`] of the truth. An equi-depth histogram
///   interpolates *within* a bucket and cannot split a run of duplicate values, so a bound landing
///   inside a bucket carries sub-bucket error; 2 rows was the worst observed across these seeds at
///   these populations (most are 0-1). This is the estimator's honest resolution, not a defect.
/// * **Relative** — at most a third of the error the `DEFAULT_PREDICATE_SELECTIVITY` constant makes on
///   the same query. This is the bound that carries the meaning: it is what fails if the statistic
///   silently reverts to the fallback, and it holds with wide margin (the constant is off by up to 37
///   rows where the histogram is off by 2).
#[track_caller]
fn assert_beats_the_constant(estimate: f64, truth: f64, label_rows: f64, seed: u64, when: &str) {
    let hist_err = (estimate - truth).abs();
    let fallback = label_rows * 0.3;
    let fallback_err = (fallback - truth).abs();
    assert!(
        hist_err <= HISTOGRAM_TOLERANCE_ROWS,
        "seed {seed} ({when}): estimate {estimate} is {hist_err} rows from the truth {truth} —          beyond the {HISTOGRAM_TOLERANCE_ROWS}-row equi-depth resolution"
    );
    assert!(
        hist_err * 3.0 < fallback_err,
        "seed {seed} ({when}): the histogram must decisively beat the constant — histogram err          {hist_err} vs constant ({fallback}) err {fallback_err}. A regression to the fallback fails here."
    );
}

/// Drains the engine's pending index work — exactly what graphus-server's `drive_index_build` does
/// after every command, and what the DST `LocalEngine::drain_index_builds` spins on. A queued
/// `db.resampleIndex` is reported by `has_pending_index_builds`, so this executes it.
fn drain_engine_work(coord: &mut Coord) {
    let mut guard = 0;
    while coord.advance_index_builds(64) {
        guard += 1;
        assert!(guard < 100_000, "the engine drain did not converge");
    }
}

/// `CALL db.resampleIndex(name)` as an auto-commit statement, then let the engine run it — the exact
/// production sequence (execute → commit → `drive_index_build`).
fn resample_and_drain(coord: &mut Coord, name: &str) {
    exec_commit(coord, &format!("CALL db.resampleIndex('{name}')"));
    drain_engine_work(coord);
}

/// The planner's row estimate for `WHERE n.age > 50` under `coord`'s current statistics.
fn estimated_rows_over_50(coord: &Coord) -> f64 {
    let stats = coord.statistics();
    let logical = lower_query("MATCH (n:Person) WHERE n.age > 50 RETURN n");
    plan_physical_with_stats(&logical, &IndexCatalog::empty(), Some(&stats)).estimated_rows()
}

// =================================================================================================
// 1. CREATE INDEX seeds a real histogram (`rmp` task #572, half 2)
// =================================================================================================

#[test]
fn create_index_seeds_a_real_histogram_so_the_planner_leaves_the_constant_fallback() {
    let mut coord = fresh_coord();
    seed_skewed(&mut coord);

    // BEFORE: no index, no histogram — the planner is on the flat constant. This is the control that
    // makes the assertion below non-vacuous: if the estimate were 5.0 here too, the test could not
    // tell a real histogram from a lucky fallback.
    assert!(
        (estimated_rows_over_50(&coord) - FALLBACK_ROWS).abs() < 1e-6,
        "control: with no statistics the planner must be on the 100*0.3 constant"
    );

    create_index_like_the_server(&mut coord, "Person", "age");

    // AFTER: the index was born with statistics — no `db.resampleIndex` was called.
    let stats = coord.statistics();
    assert_eq!(
        stats.estimate_nodes_label_property_eq("Person", "age", &Value::Integer(1)),
        Some(90.0),
        "the histogram must place the 90 nodes at the skew spike exactly"
    );
    assert_eq!(
        stats.estimate_nodes_label_property_range(
            "Person",
            "age",
            Some(&Value::Integer(50)),
            false,
            None,
            true
        ),
        Some(TRUE_ROWS_OVER_50),
        "the histogram must estimate `age > 50` exactly (5 of 100), not the 30-row constant"
    );
    assert_eq!(
        stats.distinct_label_property_values("Person", "age"),
        Some(11),
        "11 distinct ages were seeded"
    );

    // And the planner consumes it end-to-end: the range plan is estimated at the truth, not 30.
    let estimate = estimated_rows_over_50(&coord);
    assert!(
        (estimate - TRUE_ROWS_OVER_50).abs() < 1e-6,
        "the range plan must be estimated from the real distribution, got {estimate}"
    );
    assert!(
        (estimate - FALLBACK_ROWS).abs() > 1e-6,
        "REGRESSION: the estimate fell back to the {FALLBACK_ROWS}-row constant"
    );
}

#[test]
fn a_seeded_histogram_survives_a_reopen() {
    // The seeding runs in its own committed transaction, so it must be durable — a histogram that
    // vanished on restart would silently return the planner to the constant fallback.
    let device = MemBlockDevice::new(0);
    let wal = WalManager::create(MemLogSink::new()).expect("create wal");
    let store: Store = RecordStore::create(device, wal, 64, 1).expect("create store");
    let mut coord = TxnCoordinator::new(store);
    seed_skewed(&mut coord);
    create_index_like_the_server(&mut coord, "Person", "age");

    let reopened = recover_no_force(&coord.into_store());
    let coord = TxnCoordinator::new(reopened);

    assert_eq!(
        coord.statistics().estimate_nodes_label_property_range(
            "Person",
            "age",
            Some(&Value::Integer(50)),
            false,
            None,
            true
        ),
        Some(TRUE_ROWS_OVER_50),
        "the seeded histogram must survive the reopen"
    );
}

// =================================================================================================
// 2. db.resampleIndex refreshes a STALE histogram (`rmp` task #572, half 1)
// =================================================================================================

#[test]
fn db_resample_index_refreshes_a_stale_histogram() {
    let mut coord = fresh_coord();
    seed_skewed(&mut coord);
    let index_name = create_index_like_the_server(&mut coord, "Person", "age");

    // Make the histogram genuinely stale: 50 more people, all `age = 99`, so `age > 50` now matches
    // 55, not 5. An equi-depth histogram cannot track this incrementally — that is exactly why an
    // explicit resample exists.
    for _ in 0..50 {
        exec_commit(&mut coord, "CREATE (:Person {age: 99})");
    }

    // NON-VACUITY: the histogram must actually be stale now. If the estimate already tracked the new
    // data, the resample below would be unobservable and this test would pass without proving
    // anything.
    let stale = coord
        .statistics()
        .estimate_nodes_label_property_range(
            "Person",
            "age",
            Some(&Value::Integer(50)),
            false,
            None,
            true,
        )
        .expect("a histogram exists");
    assert!(
        (stale - TRUE_ROWS_OVER_50).abs() < 1e-6,
        "the pre-resample histogram must still be the stale (5-row) image, got {stale}"
    );

    // THE RESAMPLE.
    resample_and_drain(&mut coord, &index_name);

    let refreshed = coord
        .statistics()
        .estimate_nodes_label_property_range(
            "Person",
            "age",
            Some(&Value::Integer(50)),
            false,
            None,
            true,
        )
        .expect("a histogram exists");
    // The new truth is 55 (the 5 original + 50 at age 99).
    assert_near(Some(refreshed), 55.0, "the resampled `age > 50` estimate");
    // NON-VACUITY: it must have actually MOVED off the stale image. This is the assertion that fails
    // if `db.resampleIndex` silently goes back to being a no-op.
    assert!(
        (refreshed - stale).abs() > 1.0,
        "REGRESSION: the resample did not change the estimate (still {stale})"
    );
    assert_eq!(
        coord
            .statistics()
            .distinct_label_property_values("Person", "age"),
        Some(12),
        "the 12th distinct age (99) must now be tracked"
    );
}

#[test]
fn db_resample_outdated_indexes_refreshes_every_declared_index() {
    let mut coord = fresh_coord();
    seed_skewed(&mut coord);
    // A second indexed property, so the nullary form has more than one target to prove it walks.
    exec_commit(&mut coord, "MATCH (n:Person) SET n.score = 7");
    create_index_like_the_server(&mut coord, "Person", "age");
    create_index_like_the_server(&mut coord, "Person", "score");

    // Drift BOTH properties.
    for _ in 0..50 {
        exec_commit(&mut coord, "CREATE (:Person {age: 99, score: 42})");
    }

    // Non-vacuity: both histograms are stale before the call.
    let stats = coord.statistics();
    assert_eq!(
        stats.estimate_nodes_label_property_eq("Person", "score", &Value::Integer(42)),
        Some(0.0),
        "control: the stale score histogram has never seen the value 42"
    );
    assert_eq!(
        stats.estimate_nodes_label_property_range(
            "Person",
            "age",
            Some(&Value::Integer(50)),
            false,
            None,
            true
        ),
        Some(TRUE_ROWS_OVER_50),
        "control: the age histogram is stale"
    );
    drop(stats);

    exec_commit(&mut coord, "CALL db.resampleOutdatedIndexes()");
    drain_engine_work(&mut coord);

    let stats = coord.statistics();
    assert_eq!(
        stats.estimate_nodes_label_property_eq("Person", "score", &Value::Integer(42)),
        Some(50.0),
        "every declared index is resampled: score now sees the 50 nodes at 42"
    );
    assert_near(
        stats.estimate_nodes_label_property_range(
            "Person",
            "age",
            Some(&Value::Integer(50)),
            false,
            None,
            true,
        ),
        55.0,
        "every declared index is resampled: age now sees the 50 nodes at 99",
    );
}

// =================================================================================================
// 3. Name resolution: the error / no-op boundary
// =================================================================================================

#[test]
fn db_resample_index_rejects_an_unknown_index_name() {
    let mut coord = fresh_coord();
    seed_skewed(&mut coord);
    create_index_like_the_server(&mut coord, "Person", "age");

    let err = exec_commit_result(&mut coord, "CALL db.resampleIndex('no_such_index')")
        .expect_err("an unknown index name must be rejected, not silently ignored");
    assert!(
        err.contains("no_such_index"),
        "the error must name the index the caller asked for, got: {err}"
    );
}

#[test]
fn db_resample_index_accepts_a_real_index_name_that_keeps_no_histogram() {
    // An index of another KIND (here full-text) exists but has no equi-depth histogram to refresh.
    // That is a no-op SUCCESS, not an error: the index the caller named genuinely exists. Only a name
    // that is in no catalog at all is an error.
    let mut coord = fresh_coord();
    seed_skewed(&mut coord);
    coord
        .create_fulltext_index(
            "ft_person",
            &["Person".to_owned()],
            &["name".to_owned()],
            graphus_index::fulltext::Analyzer::Standard,
            false,
        )
        .expect("create fulltext index");
    while coord.advance_index_builds(64) {}

    exec_commit_result(&mut coord, "CALL db.resampleIndex('ft_person')")
        .expect("resampling an existing index of another kind is a no-op success");
}

#[test]
fn db_resample_index_resolves_the_name_show_indexes_displays() {
    // The resampler must accept exactly the name a user can SEE. A name that `SHOW INDEXES` lists but
    // `db.resampleIndex` rejects would be an unusable surface.
    let mut coord = fresh_coord();
    seed_skewed(&mut coord);
    let created = create_index_like_the_server(&mut coord, "Person", "age");
    let listed = coord.list_node_property_indexes();
    let shown = listed
        .iter()
        .find(|(_, l, p, _)| l == "Person" && p == "age")
        .map(|(n, _, _, _)| n.clone())
        .expect("listed");
    assert_eq!(created, shown, "the created name is the displayed name");
    exec_commit_result(&mut coord, &format!("CALL db.resampleIndex('{shown}')"))
        .expect("the displayed name must resample");
}

#[test]
fn db_resample_index_honours_an_explicit_index_name() {
    let mut coord = fresh_coord();
    seed_skewed(&mut coord);
    let created = coord
        .begin_online_node_composite_index_named(
            Some("my_age_ix"),
            "Person",
            &["age".to_owned()],
            false,
        )
        .expect("create named index");
    assert!(created);
    while coord.advance_index_builds(64) {}

    for _ in 0..50 {
        exec_commit(&mut coord, "CREATE (:Person {age: 99})");
    }
    resample_and_drain(&mut coord, "my_age_ix");

    assert_near(
        coord.statistics().estimate_nodes_label_property_range(
            "Person",
            "age",
            Some(&Value::Integer(50)),
            false,
            None,
            true,
        ),
        55.0,
        "the explicitly-named index must resample by that name",
    );
}

// =================================================================================================
// 4. Determinism: the resample NEVER rides the caller's transaction
// =================================================================================================

/// Runs a resample in one of the two shapes a user can write, and returns the resulting estimate.
/// `bystander` opens an unrelated transaction first — the concurrency that used to decide, all by
/// itself, whether a rolled-back resample survived.
fn resample_shape(explicit_txn_then_rollback: bool, bystander: bool) -> Option<f64> {
    let mut coord = fresh_coord();
    seed_skewed(&mut coord);
    let name = create_index_like_the_server(&mut coord, "Person", "age");
    for _ in 0..50 {
        exec_commit(&mut coord, "CREATE (:Person {age: 99})");
    }

    let idle = bystander.then(|| {
        let t = coord.begin_serializable();
        let _ = run_stmt(&coord, t, "MATCH (n:Person) RETURN n LIMIT 1");
        t
    });

    if explicit_txn_then_rollback {
        // BEGIN … CALL db.resampleIndex(…) … ROLLBACK
        let t = coord.begin_serializable();
        let _ = run_stmt(&coord, t, &format!("CALL db.resampleIndex('{name}')"));
        coord.rollback(t).expect("the caller rolls back");
        drain_engine_work(&mut coord);
    } else {
        // The auto-commit shape.
        resample_and_drain(&mut coord, &name);
    }

    if let Some(t) = idle {
        coord.commit(t).expect("bystander commits");
    }
    // Force the catalog out and back through a real crash-recovery reopen, so this reports what is
    // DURABLE, not merely what is in memory.
    let reopened = recover_no_force(&coord.into_store());
    let coord = TxnCoordinator::new(reopened);
    coord.statistics().estimate_nodes_label_property_range(
        "Person",
        "age",
        Some(&Value::Integer(50)),
        false,
        None,
        true,
    )
}

#[test]
fn a_resample_is_deterministic_across_every_caller_shape() {
    // THE POINT OF `rmp` #572's design decision. A resample is deliberately NOT part of the caller's
    // transaction — Neo4j schedules a background job that ignores it, so a ROLLBACK not undoing a
    // resample is the conformant behaviour, not a compromise.
    //
    // What was indefensible before was never "rollback does not undo it". It was that rollback undid it
    // *or not* depending on whether some unrelated transaction happened to be open at the time:
    // `RecordStore::rollback` restores the catalog's schema half wholesale when the active set is
    // non-empty, resurrecting the very change it was undoing (the pre-existing `rmp` #734 gap, which
    // this design sidesteps rather than closes). The measured result then was:
    //
    //     auto-commit                     -> 55.5  (applied)
    //     BEGIN…ROLLBACK, no bystander    ->  5.0  (discarded)
    //     BEGIN…ROLLBACK, with bystander  -> 55.5  (RESURRECTED — same source, different answer)
    //
    // Now all four shapes must agree, because the resample never rides the caller's transaction at all.
    let shapes = [
        ("auto-commit, no bystander", resample_shape(false, false)),
        ("auto-commit, with bystander", resample_shape(false, true)),
        ("BEGIN…ROLLBACK, no bystander", resample_shape(true, false)),
        ("BEGIN…ROLLBACK, with bystander", resample_shape(true, true)),
    ];

    // NON-VACUITY: the resample must actually have DONE something in every shape — 55 is the post-drift
    // truth, 5.0 the stale image it started from. A design that simply never resampled would return 5.0
    // everywhere and satisfy "all shapes agree" while defeating the entire task.
    for (what, got) in &shapes {
        assert_near(
            *got,
            55.0,
            &format!("{what}: the resample must have been applied"),
        );
    }
    // And they must agree EXACTLY — not merely "all near 55". Concurrency must not perturb the result
    // by so much as a bucket.
    let first = shapes[0].1;
    for (what, got) in &shapes {
        assert_eq!(
            *got, first,
            "DETERMINISM: {what} gave {got:?} but `{}` gave {first:?} — the outcome must not depend \
             on the caller's transaction shape or on unrelated concurrency",
            shapes[0].0
        );
    }
}

#[test]
fn a_committed_resample_survives_a_reopen() {
    let device = MemBlockDevice::new(0);
    let wal = WalManager::create(MemLogSink::new()).expect("create wal");
    let store: Store = RecordStore::create(device, wal, 64, 1).expect("create store");
    let mut coord = TxnCoordinator::new(store);
    seed_skewed(&mut coord);
    let index_name = create_index_like_the_server(&mut coord, "Person", "age");
    for _ in 0..50 {
        exec_commit(&mut coord, "CREATE (:Person {age: 99})");
    }
    resample_and_drain(&mut coord, &index_name);

    let reopened = recover_no_force(&coord.into_store());
    let coord = TxnCoordinator::new(reopened);

    assert_near(
        coord.statistics().estimate_nodes_label_property_range(
            "Person",
            "age",
            Some(&Value::Integer(50)),
            false,
            None,
            true,
        ),
        55.0,
        "the resampled histogram must be durable",
    );
}

// =================================================================================================
// 5. DST: deterministic simulation of the statistics path (CLAUDE.md — drive concurrent /
//    reproducible scenarios through the deterministic simulator)
// =================================================================================================

/// Runs one statement, tolerating a statement-level failure (an SSI abort), reporting whether it
/// succeeded — the `elle.rs` concurrent-statement shape.
fn try_stmt(coord: &Coord, txn: TxnId, src: &str) -> bool {
    let plan = compile(src);
    let bound = bind_parameters(&plan, &Parameters::new()).expect("bind");
    let mut graph = coord.statement(txn).expect("statement");
    let ok = execute(&plan, &bound, &mut graph)
        .and_then(|mut c| c.collect_all())
        .is_ok();
    ok && !graph.has_error()
}

/// The exact number of `:Person` with `age > 50`, from a real query — the **ground truth** oracle the
/// histogram is judged against (never derived from the histogram itself).
fn true_count_over_50(coord: &mut Coord) -> f64 {
    let txn = coord.begin_serializable();
    let rows = run_stmt(
        coord,
        txn,
        "MATCH (n:Person) WHERE n.age > 50 RETURN count(n) AS c",
    );
    coord.commit(txn).expect("commit count");
    match rows.first().and_then(|r| r.get("c")) {
        Some(RowValue::Value(Value::Integer(c))) => *c as f64,
        other => panic!("expected an integer count, got {other:?}"),
    }
}

#[test]
fn dst_a_resampled_histogram_tracks_ground_truth_over_randomized_histories() {
    // DETERMINISTIC SIMULATION (`graphus_sim::SimRng`, fixed seeds — reproducible on any host): over
    // many randomized-but-replayable write histories, a resampled histogram's estimate must track the
    // graph's ACTUAL contents, verified against an independent `count(n)` query rather than against
    // the histogram's own machinery.
    //
    // This is the property that matters: `db.resampleIndex` is only worth calling if the statistic it
    // publishes describes the data as it really is, for arbitrary distributions — not just the one
    // hand-picked distribution the other tests pin.
    let mut checked = 0usize;
    let mut saw_a_stale_gap = 0usize;

    for seed in 1..=8u64 {
        let mut coord = fresh_coord();
        let mut rng = SimRng::new(seed);

        // A deterministic, seed-dependent initial distribution.
        for _ in 0..60 {
            let age = rng.next_u64() % 100;
            exec_commit(&mut coord, &format!("CREATE (:Person {{age: {age}}})"));
        }
        let index_name = create_index_like_the_server(&mut coord, "Person", "age");

        // The seeded histogram must already track the truth at birth.
        let truth_at_birth = true_count_over_50(&mut coord);
        let est_at_birth = coord
            .statistics()
            .estimate_nodes_label_property_range(
                "Person",
                "age",
                Some(&Value::Integer(50)),
                false,
                None,
                true,
            )
            .expect("the index was born with a histogram");
        assert_beats_the_constant(
            est_at_birth,
            truth_at_birth,
            60.0,
            seed,
            "seeded at CREATE INDEX",
        );

        // Drift the graph deterministically.
        for _ in 0..40 {
            let age = 50 + rng.next_u64() % 50; // skewed high, so `age > 50` genuinely moves
            exec_commit(&mut coord, &format!("CREATE (:Person {{age: {age}}})"));
        }

        let truth_after_drift = true_count_over_50(&mut coord);
        let stale = coord
            .statistics()
            .estimate_nodes_label_property_range(
                "Person",
                "age",
                Some(&Value::Integer(50)),
                false,
                None,
                true,
            )
            .expect("a histogram exists");
        // NON-VACUITY: the drift must actually have made the histogram stale. If `stale` already
        // equalled the new truth, the resample below would be unobservable for this seed.
        if (stale - truth_after_drift).abs() > 1.0 {
            saw_a_stale_gap += 1;
        }

        resample_and_drain(&mut coord, &index_name);

        let est_after = coord
            .statistics()
            .estimate_nodes_label_property_range(
                "Person",
                "age",
                Some(&Value::Integer(50)),
                false,
                None,
                true,
            )
            .expect("a histogram exists");
        assert_beats_the_constant(
            est_after,
            truth_after_drift,
            100.0,
            seed,
            "after db.resampleIndex",
        );
        checked += 1;
    }

    assert_eq!(checked, 8, "every seed must have been checked");
    assert!(
        saw_a_stale_gap >= 6,
        "NON-VACUITY: the drift must leave the histogram measurably stale in most seeds (only \
         {saw_a_stale_gap}/8 did) — otherwise the resample assertions prove nothing"
    );
}

#[test]
fn dst_index_creation_under_concurrent_writes_loses_no_committed_write() {
    // `rmp` task #572 makes CREATE INDEX open its OWN transaction (to seed the histogram) at the
    // build-completion tick — i.e. an extra transaction now runs *inside* the DDL, interleaved with
    // whatever concurrent writers are live. ACID is inviolable, so the property under deterministic
    // simulation is: every write that COMMITS while an index is being created and seeded is still
    // there afterwards, and the seeded histogram is consistent with the final graph.
    let mut total_committed = 0usize;
    let mut seeds_with_concurrency = 0usize;

    for seed in 1..=10u64 {
        let mut coord = fresh_coord();
        let mut rng = SimRng::new(seed);
        for _ in 0..30 {
            let age = rng.next_u64() % 100;
            exec_commit(&mut coord, &format!("CREATE (:Person {{age: {age}}})"));
        }

        // Declare the index but DO NOT drain: the background build is now in flight.
        let created = coord
            .begin_online_node_composite_index_named(None, "Person", &["age".to_owned()], false)
            .expect("create index");
        assert!(created);

        // Interleave concurrent writers with the build ticks, deterministically.
        let mut committed_here = 0usize;
        let mut ticks = 0usize;
        loop {
            let t = coord.begin_serializable();
            let age = rng.next_u64() % 100;
            let ok = try_stmt(&coord, t, &format!("CREATE (:Person {{age: {age}}})"));
            if ok && coord.commit(t).is_ok() {
                committed_here += 1;
            } else {
                let _ = coord.rollback(t);
            }
            if !coord.advance_index_builds(4) {
                break;
            }
            ticks += 1;
            assert!(ticks < 100_000, "the build did not converge");
        }
        if ticks > 0 {
            seeds_with_concurrency += 1;
        }
        total_committed += committed_here;

        // ACID: every committed node is still visible. The ground truth is the store's own count.
        let txn = coord.begin_serializable();
        let rows = run_stmt(&coord, txn, "MATCH (n:Person) RETURN count(n) AS c");
        coord.commit(txn).expect("commit count");
        let surviving = match rows.first().and_then(|r| r.get("c")) {
            Some(RowValue::Value(Value::Integer(c))) => *c as usize,
            other => panic!("expected a count, got {other:?}"),
        };
        assert_eq!(
            surviving,
            30 + committed_here,
            "seed {seed}: a committed write was lost across index creation + histogram seeding"
        );

        // And the statistic published during that concurrency is consistent with the final graph.
        let truth = true_count_over_50(&mut coord);
        if let Some(est) = coord.statistics().estimate_nodes_label_property_range(
            "Person",
            "age",
            Some(&Value::Integer(50)),
            false,
            None,
            true,
        ) {
            // The histogram is a point-in-time image taken at the build-completion tick, so writes
            // that committed AFTER it legitimately are not reflected. It must never exceed the total
            // population, and must never be negative — a histogram describing a graph that never
            // existed would break both.
            assert!(
                (0.0..=(surviving as f64)).contains(&est),
                "seed {seed}: the seeded estimate {est} is outside the graph's actual population \
                 (truth now {truth}, total {surviving})"
            );
        }
    }

    assert!(
        total_committed > 0,
        "NON-VACUITY: no write ever committed during index creation — the test proves nothing"
    );
    assert!(
        seeds_with_concurrency >= 8,
        "NON-VACUITY: writes must genuinely interleave with build ticks (only \
         {seeds_with_concurrency}/10 seeds did)"
    );
}

// =================================================================================================
// 6. Seeding must not abort a concurrent writer (regression, storage audit of `rmp` #572)
// =================================================================================================

#[test]
fn creating_an_index_does_not_abort_a_concurrent_writer() {
    // REGRESSION (storage audit of `rmp` #572). Seeding the histogram opens a transaction that SCANS
    // the whole label. Left at SERIALIZABLE, that scan merges SIREAD markers for every live node of
    // the label into the shared tracker, handing an in-flight writer of that label an **in-conflict**
    // it would not otherwise have. A writer that already holds an out-conflict then forms a complete
    // SSI dangerous structure and is ABORTED at its own commit — so `CREATE INDEX` would kill a
    // concurrent user transaction that was going to commit, purely to compute an estimate. `rmp` #545
    // rejected exactly that trade for ordinary reads.
    //
    // THE SHAPE MATTERS. A lone `CREATE (:Person …)` writer can never be a pivot: SSI aborts on a
    // dangerous structure (`in` AND `out` rw-edges), and a pure write has no out-edge. An earlier
    // draft of this test did exactly that and passed with the fix REVERTED — green and worthless. The
    // pivot needs all three:
    //   * `other`  — writes :Person and commits  => gives `writer` its OUT-conflict (writer read
    //                :Person, `other` then wrote it),
    //   * `writer` — READS :Person and writes it => the candidate pivot,
    //   * the seed — reads :Person while `writer` is in flight => gives `writer` its IN-conflict.
    // Only the seed's marker is new; remove it and the structure is incomplete.
    fn run_scenario(
        create_index: bool,
    ) -> Result<graphus_core::Timestamp, graphus_core::GraphusError> {
        let mut coord = fresh_coord();
        seed_skewed(&mut coord);

        // `writer` READS the label (this is what gives it an out-edge later) and writes it.
        let writer = coord.begin_serializable();
        assert!(
            try_stmt(&coord, writer, "MATCH (n:Person) WHERE n.age > 50 RETURN n"),
            "writer read"
        );
        assert!(
            try_stmt(&coord, writer, "CREATE (:Person {age: 7})"),
            "writer write"
        );

        // `other` writes the label writer read, and commits => writer --rw--> other (OUT-conflict).
        let other = coord.begin_serializable();
        assert!(
            try_stmt(&coord, other, "CREATE (:Person {age: 77})"),
            "other write"
        );
        coord.commit(other).expect("other commits");

        // The variable under test: the index creation, whose seeding scan reads :Person while
        // `writer` is still in flight => seed --rw--> writer (IN-conflict, completing the structure).
        if create_index {
            create_index_like_the_server(&mut coord, "Person", "age");
        }

        coord.commit(writer)
    }

    // CONTROL: the identical interleaving WITHOUT the index creation. This is what makes the probe
    // non-vacuous — it proves the shape produces a committing writer when the seed's marker is absent.
    let control = run_scenario(false);
    assert!(
        control.is_ok(),
        "CONTROL: without a concurrent CREATE INDEX this writer commits — if it did not, the probe \
         below would prove nothing. Got {control:?}"
    );

    // PROBE: the same interleaving, with the index creation.
    let probed = run_scenario(true);
    assert!(
        probed.is_ok(),
        "REGRESSION: creating an index aborted a concurrent writer that commits without it — the \
         histogram seeding scan must carry no SSI footprint (demote it to snapshot isolation). \
         Got {probed:?}"
    );

    // NON-VACUITY: the seeding must still have run (a fix that simply stopped seeding would pass the
    // assertion above while defeating the whole task).
    let mut coord = fresh_coord();
    seed_skewed(&mut coord);
    create_index_like_the_server(&mut coord, "Person", "age");
    assert!(
        coord
            .statistics()
            .estimate_nodes_label_property_eq("Person", "age", &Value::Integer(1))
            .is_some(),
        "NON-VACUITY: the index must still be seeded with a histogram"
    );
}
