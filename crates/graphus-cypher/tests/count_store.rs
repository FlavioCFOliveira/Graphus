//! The **count-store access path** (`rmp` task #866): an ungrouped `count(*)` / `count(v)` over a bare
//! label or relationship-type scan answered from the durable live-record counters instead of reading
//! every record.
//!
//! # What these tests are actually for
//!
//! The speed is not the deliverable — the counters were already there and reading one is trivially
//! fast. The deliverable is the **equivalence predicate** that decides when reading one is *allowed*,
//! because the counters are not an MVCC snapshot read:
//!
//! * they move **eagerly at write time**, so an uncommitted writer's rows are already in them;
//! * they describe the committed image **now**, not as of a reader's snapshot;
//! * reading one registers **no** SIREAD markers, a narrower read footprint than the scan it replaces.
//!
//! So the seam answers only when all three conjuncts hold — **E1** no transaction holds a pending
//! count delta, **E2** nothing has committed since this snapshot, **E3** the reader is
//! Snapshot-isolated — and declines to the scan otherwise. Each conjunct below has a test that fails
//! if *that* conjunct is deleted, which is what makes these tests evidence about the guard rather than
//! about arithmetic. The decline tests likewise pin the plan-time shape rules one at a time.
//!
//! Every assertion compares against the **scan** answer, which is the reference path and is always
//! correct: a count-store answer is only ever admissible when it equals it.

use graphus_core::{TxnId, Value};
use graphus_cypher::binding::{Parameters, bind_parameters};
use graphus_cypher::catalog::IndexCatalog;
use graphus_cypher::coordinator::TxnCoordinator;
use graphus_cypher::executor::execute;
use graphus_cypher::lexer::tokenize;
use graphus_cypher::lower::lower;
use graphus_cypher::parser::parse_tokens;
use graphus_cypher::physical::{PhysicalPlan, plan_physical};
use graphus_cypher::runtime::{Row, RowValue};
use graphus_cypher::semantics::analyze;
use graphus_io::MemBlockDevice;
use graphus_storage::RecordStore;
use graphus_wal::{MemLogSink, WalManager};

type Store = RecordStore<MemBlockDevice, MemLogSink>;
type Coord = TxnCoordinator<MemBlockDevice, MemLogSink>;

// =================================================================================================
// Harness (the coordinator-driven statement pattern of `coordinator_statistics.rs`)
// =================================================================================================

fn fresh_coord() -> Coord {
    let device = MemBlockDevice::new(0);
    let wal = WalManager::create(MemLogSink::new()).expect("create wal");
    let store: Store = RecordStore::create(device, wal, 64, 1).expect("create store");
    TxnCoordinator::new(store)
}

fn compile(src: &str) -> PhysicalPlan {
    compile_with(src, &IndexCatalog::empty())
}

fn compile_with(src: &str, catalog: &IndexCatalog) -> PhysicalPlan {
    let toks = tokenize(src).expect("lex");
    let ast = parse_tokens(&toks, src).expect("parse");
    let validated = analyze(&ast).expect("analyze");
    plan_physical(&lower(&validated), catalog)
}

/// Runs one statement of `txn`; the per-statement seam is dropped before returning.
fn run_stmt(coord: &Coord, txn: TxnId, src: &str) -> Vec<Row> {
    let plan = compile(src);
    let bound = bind_parameters(&plan, &Parameters::new()).expect("bind");
    let mut graph = coord.statement(txn).expect("statement");
    let rows = {
        let mut cursor = execute(&plan, &bound, &mut graph).expect("open cursor");
        cursor.collect_all().expect("collect rows")
    };
    assert!(
        !graph.has_error(),
        "unexpected captured error: {:?}",
        graph.take_error()
    );
    rows
}

/// Runs `src` in its own committed serializable transaction (the write auto-commit shape).
fn exec_commit(coord: &mut Coord, src: &str) {
    let txn = coord.begin_serializable();
    let _ = run_stmt(coord, txn, src);
    coord.commit(txn).expect("commit");
}

/// The single integer a `RETURN count(...) AS c` statement produced.
fn only_count(rows: &[Row]) -> i64 {
    assert_eq!(rows.len(), 1, "an ungrouped count returns exactly one row");
    match rows[0].get("c") {
        Some(RowValue::Value(Value::Integer(i))) => *i,
        other => panic!("expected an Integer count, got {other:?}"),
    }
}

/// An **auto-commit read**: the exact shape `rmp` #545 demotes to Snapshot Isolation before running,
/// which is the only shape the count store may serve. This is what the server does at
/// `engine/exec.rs` for a structurally read-only auto-commit statement.
fn read_autocommit(coord: &mut Coord, src: &str) -> i64 {
    let txn = coord.begin_serializable();
    coord.demote_read_to_snapshot(txn);
    let rows = run_stmt(coord, txn, src);
    coord.commit(txn).expect("commit read");
    only_count(&rows)
}

/// The reference answer: the same query with the count-store rewrite unavailable, obtained by running
/// it inside an explicit **Serializable** transaction (which the E3 conjunct always declines). Any
/// count-store answer must equal this.
fn read_by_scan(coord: &mut Coord, src: &str) -> i64 {
    let txn = coord.begin_serializable();
    let rows = run_stmt(coord, txn, src);
    coord.commit(txn).expect("commit scan read");
    only_count(&rows)
}

/// Seeds `people` `:Person` nodes and `likes` `(:Person)-[:LIKES]->(:Person)` edges, each in its own
/// committed transaction, so the counters describe a fully committed image with nothing open.
fn seed(coord: &mut Coord, people: usize, likes: usize) {
    for i in 0..people {
        exec_commit(coord, &format!("CREATE (:Person {{n: {i}}})"));
    }
    for i in 0..likes {
        exec_commit(
            coord,
            &format!(
                "MATCH (a:Person {{n: {i}}}), (b:Person {{n: {}}}) CREATE (a)-[:LIKES]->(b)",
                i + 1
            ),
        );
    }
}

/// Whether a compiled plan chose the count-store access path.
fn plans_count_store(src: &str) -> bool {
    let rendered = compile(src).root.to_string();
    rendered.contains("NodeCountFromCountStore")
        || rendered.contains("RelationshipCountFromCountStore")
}

// =================================================================================================
// 1. The two target queries: the count store answers, and answers what the scan would have
// =================================================================================================

#[test]
fn node_count_over_a_bare_label_scan_matches_the_scan() {
    let mut coord = fresh_coord();
    seed(&mut coord, 12, 0);
    let src = "MATCH (u:Person) RETURN count(u) AS c";
    assert!(
        plans_count_store(src),
        "the shape must plan the count store"
    );
    assert_eq!(read_autocommit(&mut coord, src), 12);
    assert_eq!(read_by_scan(&mut coord, src), 12);
}

#[test]
fn relationship_count_over_a_bare_type_scan_matches_the_scan() {
    let mut coord = fresh_coord();
    seed(&mut coord, 12, 7);
    let src = "MATCH ()-[r:LIKES]->() RETURN count(r) AS c";
    assert!(
        plans_count_store(src),
        "the shape must plan the count store"
    );
    assert_eq!(read_autocommit(&mut coord, src), 7);
    assert_eq!(read_by_scan(&mut coord, src), 7);
}

#[test]
fn count_star_and_count_variable_agree_because_a_scan_never_binds_null() {
    let mut coord = fresh_coord();
    seed(&mut coord, 9, 0);
    assert!(plans_count_store("MATCH (u:Person) RETURN count(*) AS c"));
    assert_eq!(
        read_autocommit(&mut coord, "MATCH (u:Person) RETURN count(*) AS c"),
        9
    );
    assert_eq!(
        read_autocommit(&mut coord, "MATCH (u:Person) RETURN count(u) AS c"),
        9
    );
}

#[test]
fn untyped_and_unlabelled_counts_use_the_grand_totals() {
    let mut coord = fresh_coord();
    seed(&mut coord, 6, 4);
    // `MATCH (n) RETURN count(n)` — the grand total, which is tracked exactly (`rmp` #82) and is not
    // the sum of the per-label counts.
    assert!(plans_count_store("MATCH (n) RETURN count(n) AS c"));
    assert_eq!(
        read_autocommit(&mut coord, "MATCH (n) RETURN count(n) AS c"),
        6
    );
    assert_eq!(
        read_by_scan(&mut coord, "MATCH (n) RETURN count(n) AS c"),
        6
    );

    assert!(plans_count_store("MATCH ()-[r]->() RETURN count(r) AS c"));
    assert_eq!(
        read_autocommit(&mut coord, "MATCH ()-[r]->() RETURN count(r) AS c"),
        4
    );
    assert_eq!(
        read_by_scan(&mut coord, "MATCH ()-[r]->() RETURN count(r) AS c"),
        4
    );
}

#[test]
fn a_label_no_node_carries_is_an_exact_zero_not_a_decline() {
    let mut coord = fresh_coord();
    seed(&mut coord, 5, 0);
    // A never-interned label has no live node, so the counter's `0` is exact — and must be reported as
    // a row, not swallowed. (`Some(0)` versus `None` is the standing contract of this whole seam
    // family; conflating them would report an empty result set instead of a zero count.)
    let src = "MATCH (u:NoSuchLabel) RETURN count(u) AS c";
    assert_eq!(read_autocommit(&mut coord, src), 0);
    assert_eq!(read_by_scan(&mut coord, src), 0);
}

#[test]
fn the_column_name_is_the_verbatim_projection_alias() {
    let mut coord = fresh_coord();
    seed(&mut coord, 3, 0);
    // Unaliased, the column is the verbatim source text — the count store must carry the alias through
    // rather than re-derive it, or the result bag differs from the scan's by its column name alone.
    let txn = coord.begin_serializable();
    coord.demote_read_to_snapshot(txn);
    let rows = run_stmt(&coord, txn, "MATCH (u:Person) RETURN count(u)");
    coord.commit(txn).expect("commit");
    assert_eq!(rows.len(), 1);
    assert!(
        matches!(
            rows[0].get("count(u)"),
            Some(RowValue::Value(Value::Integer(3)))
        ),
        "expected column `count(u)` = 3, got {:?}",
        rows[0]
    );
}

// =================================================================================================
// 2. THE ACCEPTANCE: the guard
// =================================================================================================
//
// Every test in this section is **non-vacuous against a naive unconditional rewrite** — remove all
// three conjuncts and 7 of them fail. Which conjunct kills which differs, and the distinction is worth
// stating precisely rather than claiming more than is true:
//
//   * the foreign-writer pair (`an_uncommitted_foreign_*`) fails under **E1 alone** — they are genuine
//     SI auto-commit reads at the head, so E1 is the only conjunct standing between them and a dirty
//     read;
//   * the stale-snapshot pair fails under **E2 alone**;
//   * the phantom write-skew fails under **E3 alone**;
//   * the two own-writes tests fail only when **E3 is also removed**, because the transactions they
//     model are Serializable and E3 declines them first. They are still real guard tests — a naive
//     rewrite returns 9 and 6 where 6 and 3 are correct — but E3 shadows E1 for them.
//
// That property did not come for free. Two earlier drafts of the own-writes tests were vacuous: the
// eager counter coincidentally equals a LONE writer's own view, so a same-transaction
// create-then-count or delete-then-count agreed with an unguarded shortcut by arithmetic. Both now run
// a CONCURRENT open writer, which no single shared tally can satisfy — the transaction must see its
// own writes and none of the other's. A test that passes when the thing it tests is deleted is
// evidence of nothing.

/// **E1, the CREATE direction.** A transaction that creates and then counts in the SAME transaction
/// must see its own writes.
///
/// Stated on its own this is the acceptance criterion but NOT a guard test: with no other writer open
/// the counter equals this transaction's own view, so it passes against an unguarded shortcut too.
/// [`own_writes_are_visible_while_a_concurrent_writers_are_not`] is the non-vacuous form; this one is
/// kept as the plain statement of the required behaviour.
#[test]
fn a_transaction_counting_after_its_own_create_sees_its_own_writes() {
    let mut coord = fresh_coord();
    seed(&mut coord, 4, 0);
    let txn = coord.begin_serializable();
    let _ = run_stmt(&coord, txn, "CREATE (:Person {n: 100})");
    let _ = run_stmt(&coord, txn, "CREATE (:Person {n: 101})");
    let rows = run_stmt(&coord, txn, "MATCH (u:Person) RETURN count(u) AS c");
    assert_eq!(
        only_count(&rows),
        6,
        "read-your-own-writes: 4 committed + 2 created in this transaction"
    );
    coord.commit(txn).expect("commit");
    assert_eq!(
        read_by_scan(&mut coord, "MATCH (u:Person) RETURN count(u) AS c"),
        6
    );
}

/// **E1, the DELETE direction.** A transaction that deletes and then counts must see the deletion —
/// and must not see a concurrent writer's uncommitted creates.
///
/// The concurrent writer is what makes this test about the guard. Without it the transaction is the
/// only open writer, so the shared tally happens to equal its own view and an unguarded shortcut
/// returns the right number by coincidence; the test then passes against a naive unconditional
/// rewrite and proves only arithmetic. With three foreign uncommitted creates in the tally, the live
/// counter says 6 while the only correct answer is 3.
#[test]
fn a_transaction_counting_after_its_own_delete_sees_the_deletion() {
    let mut coord = fresh_coord();
    seed(&mut coord, 5, 0);

    let other = coord.begin_serializable();
    let _ = run_stmt(&coord, other, "CREATE (:Person {n: 300})");
    let _ = run_stmt(&coord, other, "CREATE (:Person {n: 301})");
    let _ = run_stmt(&coord, other, "CREATE (:Person {n: 302})");

    let txn = coord.begin_serializable();
    let _ = run_stmt(&coord, txn, "MATCH (u:Person {n: 0}) DELETE u");
    let _ = run_stmt(&coord, txn, "MATCH (u:Person {n: 1}) DELETE u");
    let rows = run_stmt(&coord, txn, "MATCH (u:Person) RETURN count(u) AS c");
    assert_eq!(
        only_count(&rows),
        3,
        "5 committed - my own 2 deletes; the shared counter says 6 because it also holds the other \
         transaction's 3 uncommitted creates"
    );

    coord.rollback(other).expect("rollback other");
    coord.commit(txn).expect("commit");
    assert_eq!(
        read_by_scan(&mut coord, "MATCH (u:Person) RETURN count(u) AS c"),
        3
    );
}

/// **E1, read-your-own-writes *and* isolation together.** The two tests above are satisfied by the
/// counter's arithmetic alone when the counting transaction is the only open writer — its own rows are
/// in the tally, so an unguarded read would coincidentally agree. That coincidence is exactly what a
/// guard test must not rely on, so this one runs a *concurrent* writer alongside: the transaction must
/// see its own two creates and none of the foreign one's. No single tally can be both, which is why the
/// only correct answer is to decline and scan.
#[test]
fn own_writes_are_visible_while_a_concurrent_writers_are_not() {
    let mut coord = fresh_coord();
    seed(&mut coord, 4, 0);

    let other = coord.begin_serializable();
    let _ = run_stmt(&coord, other, "CREATE (:Person {n: 200})");
    let _ = run_stmt(&coord, other, "CREATE (:Person {n: 201})");
    let _ = run_stmt(&coord, other, "CREATE (:Person {n: 202})");

    let mine = coord.begin_serializable();
    let _ = run_stmt(&coord, mine, "CREATE (:Person {n: 100})");
    let _ = run_stmt(&coord, mine, "CREATE (:Person {n: 101})");
    let rows = run_stmt(&coord, mine, "MATCH (u:Person) RETURN count(u) AS c");
    assert_eq!(
        only_count(&rows),
        6,
        "4 committed + my own 2; the shared counter says 9 because it also holds the other \
         transaction's 3 uncommitted creates"
    );

    coord.rollback(other).expect("rollback other");
    coord.commit(mine).expect("commit mine");
    assert_eq!(
        read_by_scan(&mut coord, "MATCH (u:Person) RETURN count(u) AS c"),
        6
    );
}

/// **E1, isolated.** A *foreign* in-flight writer's uncommitted rows are already in the counters (they
/// move eagerly), while no snapshot may see them. This is the only conjunct that catches it: nothing
/// has committed, so E2 holds; the reader is a genuine SI auto-commit read, so E3 holds. Without E1 the
/// count store would return a **dirty read**.
#[test]
fn an_uncommitted_foreign_writer_is_not_counted() {
    let mut coord = fresh_coord();
    seed(&mut coord, 4, 0);

    let writer = coord.begin_serializable();
    let _ = run_stmt(&coord, writer, "CREATE (:Person {n: 100})");
    let _ = run_stmt(&coord, writer, "CREATE (:Person {n: 101})");
    // The writer is still open. A concurrent auto-commit read must see only the committed image.
    assert_eq!(
        read_autocommit(&mut coord, "MATCH (u:Person) RETURN count(u) AS c"),
        4,
        "an in-flight writer's uncommitted creates must not be counted (dirty read)"
    );
    coord.rollback(writer).expect("rollback writer");
    assert_eq!(
        read_autocommit(&mut coord, "MATCH (u:Person) RETURN count(u) AS c"),
        4
    );
}

/// **E1, isolated, deletion direction.** Symmetric to the above: an in-flight writer's uncommitted
/// *deletes* have already been subtracted from the counters, so a concurrent reader must not observe
/// them either.
#[test]
fn an_uncommitted_foreign_delete_is_still_counted() {
    let mut coord = fresh_coord();
    seed(&mut coord, 6, 0);

    let writer = coord.begin_serializable();
    let _ = run_stmt(&coord, writer, "MATCH (u:Person {n: 0}) DELETE u");
    assert_eq!(
        read_autocommit(&mut coord, "MATCH (u:Person) RETURN count(u) AS c"),
        6,
        "an in-flight writer's uncommitted delete must not be visible to a concurrent reader"
    );
    coord.rollback(writer).expect("rollback writer");
    assert_eq!(
        read_autocommit(&mut coord, "MATCH (u:Person) RETURN count(u) AS c"),
        6
    );
}

/// **E2.** A reader holding an older snapshot must see its snapshot's count, not the moved one. The
/// counters describe the committed image *now*; this reader may only see the image as of its own
/// begin timestamp.
#[test]
fn a_reader_on_an_older_snapshot_sees_its_snapshot_count() {
    let mut coord = fresh_coord();
    seed(&mut coord, 3, 0);

    // Take the snapshot first...
    let reader = coord.begin_serializable();
    coord.demote_read_to_snapshot(reader);

    // ...then move the world underneath it, with fully committed transactions.
    exec_commit(&mut coord, "CREATE (:Person {n: 50})");
    exec_commit(&mut coord, "CREATE (:Person {n: 51})");

    let rows = run_stmt(&coord, reader, "MATCH (u:Person) RETURN count(u) AS c");
    assert_eq!(
        only_count(&rows),
        3,
        "the reader's snapshot predates both commits; the counter now says 5"
    );
    coord.commit(reader).expect("commit reader");

    // A fresh reader sees the moved count — proving the 3 above was snapshot isolation, not staleness.
    assert_eq!(
        read_autocommit(&mut coord, "MATCH (u:Person) RETURN count(u) AS c"),
        5
    );
}

/// **E2, relationships.** The same, over the relationship counters.
#[test]
fn a_reader_on_an_older_snapshot_sees_its_snapshot_relationship_count() {
    let mut coord = fresh_coord();
    seed(&mut coord, 8, 3);

    let reader = coord.begin_serializable();
    coord.demote_read_to_snapshot(reader);
    exec_commit(
        &mut coord,
        "MATCH (a:Person {n: 5}), (b:Person {n: 6}) CREATE (a)-[:LIKES]->(b)",
    );

    let rows = run_stmt(
        &coord,
        reader,
        "MATCH ()-[r:LIKES]->() RETURN count(r) AS c",
    );
    assert_eq!(only_count(&rows), 3);
    coord.commit(reader).expect("commit reader");
    assert_eq!(
        read_autocommit(&mut coord, "MATCH ()-[r:LIKES]->() RETURN count(r) AS c"),
        4
    );
}

/// **E3 — the read footprint, not the number.** A Serializable read declines, because answering from
/// a counter registers **no** SIREAD markers: a strictly narrower read footprint than the scan, which
/// drops the rw-edges SSI needs. Correctness of the number is not enough.
///
/// The probe is the classic **phantom write-skew**: two Serializable transactions each count the
/// `:Person` set and, finding it empty, each insert one. Serially, whichever ran second would have
/// seen the other's row, so at most one may commit. SSI catches it only through the *predicate* SIREAD
/// the counting scan registers (`rmp` #171) — with the count answered from a counter, neither
/// transaction reads anything, no rw-edge forms, and **both commit**, materialising the anomaly.
///
/// This is deliberately not an assertion about markers (which no public API exposes) but about the
/// observable outcome, which is what the ACID contract is actually stated in.
#[test]
fn a_serializable_count_keeps_the_read_footprint_that_catches_a_phantom() {
    let coord = fresh_coord();

    let t1 = coord.begin_serializable();
    let t2 = coord.begin_serializable();

    // Each transaction counts the set it is about to write into, and sees it empty.
    assert_eq!(
        only_count(&run_stmt(
            &coord,
            t1,
            "MATCH (u:Person) RETURN count(u) AS c"
        )),
        0
    );
    assert_eq!(
        only_count(&run_stmt(
            &coord,
            t2,
            "MATCH (u:Person) RETURN count(u) AS c"
        )),
        0
    );

    // Each then inserts into the very set the other counted — a phantom in both directions.
    let _ = run_stmt(&coord, t1, "CREATE (:Person {n: 1})");
    let _ = run_stmt(&coord, t2, "CREATE (:Person {n: 2})");

    let first = coord.commit(t1);
    let second = coord.commit(t2);
    assert!(
        first.is_err() || second.is_err(),
        "both transactions committed: the counting read left no SIREAD footprint, so SSI could not \
         see the phantom write-skew (t1={first:?}, t2={second:?})"
    );
}

// =================================================================================================
// 3. Counter integrity under interleaving, at the coordinator (production) path
// =================================================================================================
//
// The counters drifted **permanently** in both directions before this task: a rollback reverted the
// shared tally to the durable catalogue wholesale, which both baked in the aborting transaction's
// increments (when a concurrent commit had checkpointed them) and wiped a concurrent transaction's
// still-uncommitted ones. Nothing ever re-derived them, so no guard could have saved a count-store
// answer — the numbers below were 2/1 and 0/1 before the fix. The storage-level regressions live in
// `graphus-storage/tests/count_txn_undo_866.rs`; these pin the same defect where #866 consumes it.

#[test]
fn a_rollback_after_a_concurrent_commit_leaves_the_count_exact() {
    let mut coord = fresh_coord();
    let t1 = coord.begin_serializable();
    let _ = run_stmt(&coord, t1, "CREATE (:Person {n: 1})");
    let t2 = coord.begin_serializable();
    let _ = run_stmt(&coord, t2, "CREATE (:Person {n: 2})");
    coord.commit(t2).expect("commit t2");
    coord.rollback(t1).expect("rollback t1");

    let src = "MATCH (u:Person) RETURN count(u) AS c";
    assert_eq!(read_by_scan(&mut coord, src), 1, "only t2's node survives");
    assert_eq!(read_autocommit(&mut coord, src), 1);
}

#[test]
fn a_rollback_does_not_wipe_a_concurrent_transactions_count() {
    let mut coord = fresh_coord();
    let t1 = coord.begin_serializable();
    let _ = run_stmt(&coord, t1, "CREATE (:Person {n: 1})");
    let t2 = coord.begin_serializable();
    let _ = run_stmt(&coord, t2, "CREATE (:Person {n: 2})");
    coord.rollback(t1).expect("rollback t1");
    coord.commit(t2).expect("commit t2");

    let src = "MATCH (u:Person) RETURN count(u) AS c";
    assert_eq!(read_by_scan(&mut coord, src), 1);
    assert_eq!(read_autocommit(&mut coord, src), 1);
}

#[test]
fn relationship_counters_survive_interleaved_rollback() {
    let mut coord = fresh_coord();
    seed(&mut coord, 6, 2);

    let t1 = coord.begin_serializable();
    let _ = run_stmt(
        &coord,
        t1,
        "MATCH (a:Person {n: 3}), (b:Person {n: 4}) CREATE (a)-[:LIKES]->(b)",
    );
    let t2 = coord.begin_serializable();
    let _ = run_stmt(
        &coord,
        t2,
        "MATCH (a:Person {n: 4}), (b:Person {n: 5}) CREATE (a)-[:LIKES]->(b)",
    );
    coord.commit(t2).expect("commit t2");
    coord.rollback(t1).expect("rollback t1");

    let src = "MATCH ()-[r:LIKES]->() RETURN count(r) AS c";
    assert_eq!(read_by_scan(&mut coord, src), 3);
    assert_eq!(read_autocommit(&mut coord, src), 3);
}

// =================================================================================================
// 4. Plan-time declines: every shape rule, pinned one at a time
// =================================================================================================

/// `count(DISTINCT v)` de-duplicates by value; no counter can. (A scan binds each node once, so over
/// *this* input the answer happens to coincide — but the rule must not depend on that, and the plan
/// must not claim a path whose contract it cannot meet.)
#[test]
fn count_distinct_declines() {
    assert!(!plans_count_store(
        "MATCH (u:Person) RETURN count(DISTINCT u) AS c"
    ));
}

/// A multi-label pattern lowers to a `Filter` over a single-label scan; the counters are per single
/// label and know nothing about the conjunction.
#[test]
fn multi_label_pattern_declines() {
    assert!(!plans_count_store(
        "MATCH (u:Person:Admin) RETURN count(u) AS c"
    ));
}

#[test]
fn a_where_clause_declines() {
    assert!(!plans_count_store(
        "MATCH (u:Person) WHERE u.n > 3 RETURN count(u) AS c"
    ));
}

#[test]
fn an_inline_property_map_declines() {
    assert!(!plans_count_store(
        "MATCH (u:Person {n: 3}) RETURN count(u) AS c"
    ));
}

#[test]
fn an_inline_label_expression_declines() {
    // `-[:A&B]->` lowers to an `AllRelationshipsScan` with EMPTY types plus a `HasLabels` post-filter.
    // Matching the leaf alone would silently count *every* relationship; requiring the scan to be the
    // aggregation's direct child is what excludes it.
    assert!(!plans_count_store(
        "MATCH ()-[r:LIKES&FOLLOWS]->() RETURN count(r) AS c"
    ));
}

#[test]
fn optional_match_declines() {
    assert!(!plans_count_store(
        "OPTIONAL MATCH (u:Person) RETURN count(u) AS c"
    ));
}

/// TRAP: an **undirected** pattern binds each non-self relationship twice and each self-loop once, so
/// its row count is `2 * rels - self_loops` — and the self-loop total is not tracked. `rmp` #867 had
/// just fixed the executor's version of exactly this halving.
#[test]
fn an_undirected_relationship_pattern_declines() {
    assert!(!plans_count_store(
        "MATCH ()-[r:LIKES]-() RETURN count(r) AS c"
    ));
    assert!(!plans_count_store("MATCH ()-[r]-() RETURN count(r) AS c"));
}

/// ...and the reason it must: the undirected answer is genuinely different from the counter.
#[test]
fn an_undirected_count_is_not_the_relationship_count() {
    let mut coord = fresh_coord();
    seed(&mut coord, 6, 3);
    let directed = read_by_scan(&mut coord, "MATCH ()-[r:LIKES]->() RETURN count(r) AS c");
    let undirected = read_by_scan(&mut coord, "MATCH ()-[r:LIKES]-() RETURN count(r) AS c");
    assert_eq!(directed, 3);
    assert_eq!(
        undirected, 6,
        "each non-self relationship binds once per orientation — the raw counter would answer half"
    );
    // And the auto-commit path agrees with the scan, because it declined.
    assert_eq!(
        read_autocommit(&mut coord, "MATCH ()-[r:LIKES]-() RETURN count(r) AS c"),
        6
    );
}

/// A self-loop binds **once** even undirected, which is why `2 * count` is not a usable correction.
#[test]
fn a_self_loop_binds_once_undirected_so_doubling_would_be_wrong() {
    let mut coord = fresh_coord();
    seed(&mut coord, 4, 0);
    exec_commit(
        &mut coord,
        "MATCH (a:Person {n: 0}) CREATE (a)-[:LIKES]->(a)",
    );
    exec_commit(
        &mut coord,
        "MATCH (a:Person {n: 1}), (b:Person {n: 2}) CREATE (a)-[:LIKES]->(b)",
    );
    assert_eq!(
        read_by_scan(&mut coord, "MATCH ()-[r:LIKES]->() RETURN count(r) AS c"),
        2
    );
    assert_eq!(
        read_by_scan(&mut coord, "MATCH ()-[r:LIKES]-() RETURN count(r) AS c"),
        3,
        "1 self-loop (once) + 1 ordinary (twice); `2 * 2` would be 4"
    );
}

#[test]
fn more_than_one_aggregate_declines() {
    assert!(!plans_count_store(
        "MATCH (u:Person) RETURN count(u) AS c, count(*) AS d"
    ));
}

#[test]
fn a_grouped_count_declines() {
    assert!(!plans_count_store(
        "MATCH (u:Person) RETURN u.n AS k, count(u) AS c"
    ));
}

#[test]
fn an_expression_containing_a_count_declines() {
    assert!(!plans_count_store(
        "MATCH (u:Person) RETURN count(u) + 1 AS c"
    ));
}

#[test]
fn a_non_count_aggregate_declines() {
    assert!(!plans_count_store("MATCH (u:Person) RETURN sum(u.n) AS c"));
    assert!(!plans_count_store(
        "MATCH (u:Person) RETURN collect(u) AS c"
    ));
}

#[test]
fn a_count_over_a_multi_part_pattern_declines() {
    assert!(!plans_count_store(
        "MATCH (a:Person)-[:LIKES]->(b:Person) RETURN count(a) AS c"
    ));
    assert!(!plans_count_store(
        "MATCH (a:Person), (b:Person) RETURN count(a) AS c"
    ));
}

#[test]
fn a_count_of_a_property_declines() {
    assert!(!plans_count_store(
        "MATCH (u:Person) RETURN count(u.n) AS c"
    ));
}

// =================================================================================================
// 5. Shapes that look risky and are legal — operators ABOVE the aggregation compose unchanged
// =================================================================================================

#[test]
fn a_limit_above_the_count_still_yields_the_right_answer() {
    let mut coord = fresh_coord();
    seed(&mut coord, 11, 0);
    // `LIMIT`/`SKIP`/`ORDER BY` sit ABOVE the aggregation, not between it and the scan, so they neither
    // block the rewrite nor change the count. They must still be applied to the one row it produces.
    assert!(plans_count_store(
        "MATCH (u:Person) RETURN count(u) AS c LIMIT 1"
    ));
    assert_eq!(
        read_autocommit(&mut coord, "MATCH (u:Person) RETURN count(u) AS c LIMIT 1"),
        11
    );

    let txn = coord.begin_serializable();
    coord.demote_read_to_snapshot(txn);
    let rows = run_stmt(&coord, txn, "MATCH (u:Person) RETURN count(u) AS c SKIP 1");
    coord.commit(txn).expect("commit");
    assert!(rows.is_empty(), "SKIP 1 over a single row yields none");
}

#[test]
fn a_count_inside_a_call_subquery_matches_the_scan() {
    let mut coord = fresh_coord();
    seed(&mut coord, 5, 0);
    let src = "CALL { MATCH (u:Person) RETURN count(u) AS c } RETURN c";
    let txn = coord.begin_serializable();
    coord.demote_read_to_snapshot(txn);
    let rows = run_stmt(&coord, txn, src);
    coord.commit(txn).expect("commit");
    assert_eq!(rows.len(), 1);
    assert!(matches!(
        rows[0].get("c"),
        Some(RowValue::Value(Value::Integer(5)))
    ));
}

#[test]
fn an_empty_graph_counts_zero_on_both_paths() {
    let mut coord = fresh_coord();
    let src = "MATCH (u:Person) RETURN count(u) AS c";
    assert_eq!(read_by_scan(&mut coord, src), 0);
    assert_eq!(read_autocommit(&mut coord, src), 0);
    let rsrc = "MATCH ()-[r:LIKES]->() RETURN count(r) AS c";
    assert_eq!(read_by_scan(&mut coord, rsrc), 0);
    assert_eq!(read_autocommit(&mut coord, rsrc), 0);
}

// =================================================================================================
// 6. The token-lookup spelling of a label scan
// =================================================================================================

/// `MATCH (u:Person)` lowers to a `NodeByLabelScan` or a `TokenLookupScan` depending on whether the
/// catalogue offers a label index. Both bind exactly the same node set (the executor serves them with
/// the same function), so the recognizer must match both — otherwise the optimisation would silently
/// depend on whether a label index happens to exist.
#[test]
fn a_token_lookup_scan_is_recognised_like_a_label_scan() {
    let catalog = IndexCatalog::builder().with_token_lookup("Person").build();
    let rendered = compile_with("MATCH (u:Person) RETURN count(u) AS c", &catalog)
        .root
        .to_string();
    assert!(
        rendered.contains("TokenLookupScan"),
        "expected the token-lookup spelling: {rendered}"
    );
    assert!(
        rendered.contains("NodeCountFromCountStore"),
        "the count store must recognise it too: {rendered}"
    );
}

#[test]
fn a_token_lookup_plan_answers_the_same_number() {
    let mut coord = fresh_coord();
    seed(&mut coord, 13, 0);
    let catalog = IndexCatalog::builder().with_token_lookup("Person").build();
    let plan = compile_with("MATCH (u:Person) RETURN count(u) AS c", &catalog);
    let bound = bind_parameters(&plan, &Parameters::new()).expect("bind");
    let txn = coord.begin_serializable();
    coord.demote_read_to_snapshot(txn);
    let rows = {
        let mut graph = coord.statement(txn).expect("statement");
        let mut cursor = execute(&plan, &bound, &mut graph).expect("cursor");
        cursor.collect_all().expect("collect")
    };
    coord.commit(txn).expect("commit");
    assert_eq!(only_count(&rows), 13);
}

// =================================================================================================
// 7. The OFF-THREAD reader path — the route an auto-commit read actually takes
// =================================================================================================
//
// A structurally read-only auto-commit statement is dispatched to the reader pool (`rmp` #543), and a
// reader thread holds no live store: it can neither read the counters nor evaluate their equivalence
// predicate. So the engine thread freezes the verdict AND the values together at dispatch
// (`TxnCoordinator::count_store_for`) and the reader answers from that memo. These tests drive the
// real `ReadOnlyGraph` with a real dispatch capture, because the acceptance criterion is about this
// path — proving it inline only would leave the production route untested.

/// Builds the off-thread reader seam for `txn` exactly as `engine/read_pool.rs` does, with the
/// count-store memo captured for `plan` at dispatch.
fn offthread_graph(
    coord: &Coord,
    txn: TxnId,
    plan: &PhysicalPlan,
) -> graphus_cypher::ReadOnlyGraph<MemBlockDevice, MemLogSink> {
    let inputs = coord.read_task_inputs(txn).expect("read inputs");
    let counts = coord.count_store_for(txn, plan);
    graphus_cypher::ReadOnlyGraph::new(
        inputs.view,
        inputs.tokens,
        inputs.snapshot,
        inputs.registry,
        txn,
        graphus_txn::SsiReadBuffer::new(txn),
    )
    .with_count_store(counts)
}

/// Runs `plan` on the off-thread reader seam, returning the single count it produced.
fn run_offthread(coord: &Coord, txn: TxnId, plan: &PhysicalPlan) -> i64 {
    let bound = bind_parameters(plan, &Parameters::new()).expect("bind");
    let mut graph = offthread_graph(coord, txn, plan);
    let rows = {
        let mut cursor = execute(plan, &bound, &mut graph).expect("open cursor");
        cursor.collect_all().expect("collect")
    };
    assert!(!graph.has_error(), "reader captured an error");
    only_count(&rows)
}

#[test]
fn the_off_thread_reader_answers_a_node_count_from_the_memo() {
    let mut coord = fresh_coord();
    seed(&mut coord, 17, 0);
    let plan = compile("MATCH (u:Person) RETURN count(u) AS c");

    let reader = coord.begin_serializable();
    coord.demote_read_to_snapshot(reader);
    // The memo must actually be populated, or this test would pass vacuously by declining.
    assert_eq!(
        coord.count_store_for(reader, &plan).nodes(Some("Person")),
        Some(17),
        "the dispatch capture must SERVE this count; a None here would make the assertion below \
         prove nothing about the memo"
    );
    assert_eq!(run_offthread(&coord, reader, &plan), 17);
    coord.commit(reader).expect("commit reader");
}

#[test]
fn the_off_thread_reader_answers_a_relationship_count_from_the_memo() {
    let mut coord = fresh_coord();
    seed(&mut coord, 10, 6);
    let plan = compile("MATCH ()-[r:LIKES]->() RETURN count(r) AS c");

    let reader = coord.begin_serializable();
    coord.demote_read_to_snapshot(reader);
    assert_eq!(
        coord
            .count_store_for(reader, &plan)
            .rels(&["LIKES".to_owned()]),
        Some(6),
        "the dispatch capture must SERVE this count"
    );
    assert_eq!(run_offthread(&coord, reader, &plan), 6);
    coord.commit(reader).expect("commit reader");
}

/// The predicate is evaluated at **capture** time, on the engine thread. When it fails, the memo is
/// left empty and the reader falls back to the scan — which is correct, just unaccelerated.
#[test]
fn the_dispatch_capture_declines_when_a_writer_is_in_flight() {
    let mut coord = fresh_coord();
    seed(&mut coord, 5, 0);
    let plan = compile("MATCH (u:Person) RETURN count(u) AS c");

    let writer = coord.begin_serializable();
    let _ = run_stmt(&coord, writer, "CREATE (:Person {n: 900})");

    let reader = coord.begin_serializable();
    coord.demote_read_to_snapshot(reader);
    assert_eq!(
        coord.count_store_for(reader, &plan).nodes(Some("Person")),
        None,
        "E1: an in-flight writer's uncommitted rows are in the counter, so the capture must decline"
    );
    // ...and the reader still answers correctly, from the scan.
    assert_eq!(run_offthread(&coord, reader, &plan), 5);
    coord.commit(reader).expect("commit reader");
    coord.rollback(writer).expect("rollback writer");
}

#[test]
fn the_dispatch_capture_declines_for_a_stale_snapshot() {
    let mut coord = fresh_coord();
    seed(&mut coord, 5, 0);
    let plan = compile("MATCH (u:Person) RETURN count(u) AS c");

    let reader = coord.begin_serializable();
    coord.demote_read_to_snapshot(reader);
    exec_commit(&mut coord, "CREATE (:Person {n: 900})");

    assert_eq!(
        coord.count_store_for(reader, &plan).nodes(Some("Person")),
        None,
        "E2: something committed after this snapshot, so the capture must decline"
    );
    assert_eq!(
        run_offthread(&coord, reader, &plan),
        5,
        "the reader sees its own snapshot, not the moved counter"
    );
    coord.commit(reader).expect("commit reader");
}

/// **F1 regression.** `IsolationLevel::Snapshot` and "in the SSI tracker's `snapshot_txns` set" are
/// NOT the same set, and only the second one licenses answering with no SIREAD markers.
///
/// `demote_read_to_snapshot` sets both, so a demoted auto-commit read satisfies either test. But
/// `begin(IsolationLevel::Snapshot)` sets only the per-transaction isolation — such a reader's markers
/// ARE merged by `SsiTracker::merge_read_buffer`, and handing it a count with none would drop an
/// rw-edge and let a Serializable pivot commit that SSI would have aborted. The dispatch capture
/// therefore gates on `is_snapshot`, exactly as the inline seam does. Gating on `isolation.runs_ssi()`
/// instead makes this test return `Some(5)`.
#[test]
fn the_dispatch_capture_declines_for_a_snapshot_isolated_but_undemoted_reader() {
    let mut coord = fresh_coord();
    seed(&mut coord, 5, 0);
    let plan = compile("MATCH (u:Person) RETURN count(u) AS c");

    // Begun at Snapshot isolation, but never demoted — so NOT in `snapshot_txns`, so its markers are
    // merged and it must keep the scan's read footprint.
    let reader = coord.begin(graphus_txn::IsolationLevel::Snapshot);
    assert_eq!(
        coord.count_store_for(reader, &plan).nodes(Some("Person")),
        None,
        "E3 must key on SSI-tracker membership, not on the declared isolation level"
    );
    assert_eq!(run_offthread(&coord, reader, &plan), 5);
    coord.commit(reader).expect("commit reader");
}

/// The inline seam has always keyed on `is_snapshot`; this pins that the two paths agree.
#[test]
fn the_inline_seam_also_declines_for_a_snapshot_isolated_but_undemoted_reader() {
    let mut coord = fresh_coord();
    seed(&mut coord, 5, 0);
    let reader = coord.begin(graphus_txn::IsolationLevel::Snapshot);
    let rows = run_stmt(&coord, reader, "MATCH (u:Person) RETURN count(u) AS c");
    assert_eq!(only_count(&rows), 5);
    coord.commit(reader).expect("commit reader");
}

#[test]
fn the_dispatch_capture_declines_for_a_serializable_reader() {
    let mut coord = fresh_coord();
    seed(&mut coord, 5, 0);
    let plan = compile("MATCH (u:Person) RETURN count(u) AS c");

    // No `demote_read_to_snapshot`: a Serializable reader keeps the scan's SIREAD footprint.
    let reader = coord.begin_serializable();
    assert_eq!(
        coord.count_store_for(reader, &plan).nodes(Some("Person")),
        None,
        "E3: a Serializable reader must not lose its read footprint to a counter read"
    );
    assert_eq!(run_offthread(&coord, reader, &plan), 5);
    coord.commit(reader).expect("commit reader");
}

/// A miss must DECLINE, never read as zero. The scalar face of the `rmp` #680/#738 rule: an
/// uncaptured count reported as `Some(0)` would announce an empty graph.
#[test]
fn an_uncaptured_count_declines_rather_than_reporting_zero() {
    let mut coord = fresh_coord();
    seed(&mut coord, 9, 0);
    let plan = compile("MATCH (u:Person) RETURN count(u) AS c");

    let reader = coord.begin_serializable();
    coord.demote_read_to_snapshot(reader);
    let inputs = coord.read_task_inputs(reader).expect("read inputs");
    // Deliberately do NOT attach a capture — the unfilled default, which every non-dispatch reader
    // (e.g. the morsel readers) carries.
    let mut graph = graphus_cypher::ReadOnlyGraph::new(
        inputs.view,
        inputs.tokens,
        inputs.snapshot,
        inputs.registry,
        reader,
        graphus_txn::SsiReadBuffer::new(reader),
    );
    let bound = bind_parameters(&plan, &Parameters::new()).expect("bind");
    let rows = {
        let mut cursor = execute(&plan, &bound, &mut graph).expect("open cursor");
        cursor.collect_all().expect("collect")
    };
    assert_eq!(
        only_count(&rows),
        9,
        "an empty capture must fall back to the exact scan, not report 0"
    );
    coord.commit(reader).expect("commit reader");
}
