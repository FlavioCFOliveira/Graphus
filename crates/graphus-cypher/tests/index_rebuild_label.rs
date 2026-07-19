//! An index rebuild must never lose a COMMITTED label an uncommitted writer had removed (`rmp` #771).
//!
//! `IndexSet::clear` used to empty the always-present label tree, and `rebuild_index` then refilled it
//! from each node's CURRENT inline bitmap. Labels are mutated IN PLACE with **no version chain**, so
//! that bitmap includes every UNCOMMITTED change and the committed label set exists nowhere the refill
//! can read it — it survives only in the WAL undo image. A rebuild run while a writer held an
//! uncommitted `REMOVE n:Person` therefore wrote a **subset**: the entry was destroyed and not
//! re-inserted. When that writer ROLLED BACK, WAL undo correctly restored the record's label bit, but
//! nothing restored the index entry — and `MATCH (n:Person)` returned ZERO rows, permanently, for a
//! label the node demonstrably still carried.
//!
//! The fix makes the refill purely ADDITIVE: `clear` no longer empties the label tree. That is the only
//! image it may hold, by the false-negative asymmetry — the re-check (in
//! `read_source::filter_label_candidates`) can REMOVE a candidate but never RESURRECT one, so a
//! retained stale entry is a false POSITIVE the re-check drops, while a destroyed entry is a
//! committed row lost for good.
//!
//! Since `rmp` #767 that re-check resolves label membership against the READER'S SNAPSHOT rather than
//! the current bitmap, so it no longer independently rejects a stale entry — additive retention is now
//! the only thing standing between this tree and `rmp` #765. See `tests/label_tree_765_reaudit_767.rs`,
//! which re-runs #765's per-tree audit for the label tree under the new re-check.
//!
//! Every test compares the label-index-routed `MATCH (n:Person)` against an ALL-NODES scan reading
//! `labels(n)` — the ground truth, which never consults the label index — so a test can only pass by
//! the two agreeing. The opposite direction (a COMMITTED `REMOVE`, where the label must genuinely
//! disappear) is pinned too: retaining entries must not resurrect a label that is really gone.

use graphus_core::Value;
use graphus_cypher::ConstraintKind;
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

type Coord = TxnCoordinator<MemBlockDevice, MemLogSink>;

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
    let mut cursor = execute(plan, &bound, &mut graph).expect("open cursor");
    cursor.collect_all().expect("collect")
}

fn run_write(coord: &mut Coord, src: &str) {
    let plan = compile(src, &IndexCatalog::empty());
    let txn = coord.begin_serializable();
    let _ = run_plan(coord, txn, &plan);
    coord.commit(txn).expect("write commits");
}

/// Opens a writer that removes `:Person` from every such node, and leaves it UNCOMMITTED.
fn open_writer_removing_label(coord: &mut Coord) -> graphus_core::TxnId {
    let writer = coord.begin_serializable();
    let _ = run_plan(
        coord,
        writer,
        &compile("MATCH (n:Person) REMOVE n:Person", &IndexCatalog::empty()),
    );
    writer
}

/// The label-index-routed count of `:Person`, and the ALL-NODES-scan ground truth for the same thing.
///
/// The ground truth walks every node and reads `labels(n)`, which reads the node record's inline bitmap
/// directly and never consults the label index — so the two agreeing is a real check, not a tautology.
fn labelled_vs_truth(coord: &Coord, txn: graphus_core::TxnId) -> (usize, usize) {
    let routed = run_plan(
        coord,
        txn,
        &compile("MATCH (n:Person) RETURN n", &IndexCatalog::empty()),
    )
    .len();
    let truth = run_plan(
        coord,
        txn,
        &compile("MATCH (n) RETURN labels(n) AS l", &IndexCatalog::empty()),
    )
    .iter()
    .filter(|row| {
        row.values().iter().any(|v| match v {
            // `labels(n)` is a pure-property list, so it collapses to `RowValue::Value(Value::List)`.
            RowValue::Value(Value::List(items)) => items.contains(&Value::String("Person".into())),
            _ => false,
        })
    })
    .count();
    (routed, truth)
}

/// An UNRELATED `CREATE CONSTRAINT` on the PRODUCTION route, while a writer holds an uncommitted
/// `REMOVE n:Person`.
///
/// THE PRODUCTION ROUTE (`rmp` #771 acceptance criterion 1). A server `CREATE CONSTRAINT` runs
/// `handle_constraint_ddl` (graphus-server/src/engine/mod.rs:3100) → `create_constraint_ddl` →
/// `create_constraint_general` → `rebuild_index` → `IndexSet::clear`. It is the synchronous full
/// rebuild, NOT the incremental build, that destroys the tree — the task expected the incremental
/// `advance_index_builds` to be the carrier, and it is not (it never calls `clear`; see
/// `the_incremental_build_is_additive_and_cannot_lose_the_label`). The constraint is on an unrelated
/// label: nothing about `:Person` is being declared, and the writer is still open.
#[test]
fn an_unrelated_constraint_ddl_does_not_lose_a_label_a_rolled_back_writer_removed() {
    let mut coord = fresh_coord();
    run_write(&mut coord, "CREATE (:Person {email: 'a@x.io'})");

    let writer = open_writer_removing_label(&mut coord);

    coord
        .create_constraint_ddl(
            "widget_sku",
            "Widget",
            &["sku"],
            ConstraintKind::Unique,
            None,
            false,
            false,
        )
        .expect("unrelated constraint DDL");

    // WAL undo restores the record's label bit: the node carries `:Person` again, as the ground truth
    // below independently confirms.
    coord.rollback(writer).expect("rollback");

    let reader = coord.begin_serializable();
    let (routed, truth) = labelled_vs_truth(&coord, reader);
    assert_eq!(
        truth, 1,
        "ground truth broken: the rolled-back REMOVE must leave the node carrying :Person",
    );
    assert_eq!(
        routed, truth,
        "the rebuild destroyed the label entry while the REMOVE was uncommitted and the rollback \
         could not restore it: MATCH (n:Person) returned {routed}, the ground-truth scan {truth}",
    );
}

/// The opposite direction, which the fix must not break: when that writer COMMITS, the label is
/// genuinely gone and must NOT be resurrected by the entry the rebuild now retains.
///
/// This is the counterpart hazard to the one above, and the reason a superset is only safe where the
/// consumer re-checks: `filter_label_candidates` re-checks `node_has_label` against the CURRENT bitmap,
/// so the retained entry is a false positive it drops. Without that re-check, retaining entries would
/// produce WRONG ANSWERS rather than harmless candidates (the trap that nearly shipped in `rmp` #766,
/// where the full-text consumer re-checks no term).
#[test]
fn an_unrelated_constraint_ddl_does_not_resurrect_a_label_a_committed_writer_removed() {
    let mut coord = fresh_coord();
    run_write(&mut coord, "CREATE (:Person {email: 'a@x.io'})");

    let writer = open_writer_removing_label(&mut coord);

    coord
        .create_constraint_ddl(
            "widget_sku",
            "Widget",
            &["sku"],
            ConstraintKind::Unique,
            None,
            false,
            false,
        )
        .expect("unrelated constraint DDL");

    coord.commit(writer).expect("the REMOVE commits");

    let reader = coord.begin_serializable();
    let (routed, truth) = labelled_vs_truth(&coord, reader);
    assert_eq!(
        truth, 0,
        "ground truth broken: the committed REMOVE must leave the node without :Person",
    );
    assert_eq!(
        routed, truth,
        "the retained label entry resurrected a label that was genuinely removed: \
         MATCH (n:Person) returned {routed}, the ground-truth scan {truth}",
    );
}

/// A node created by the SAME rolled-back writer must NOT survive the rollback — the label entry the
/// write path inserted eagerly at CREATE time is RETAINED by the #771 fix (nothing removes it, and
/// `clear` no longer wipes the tree), so it is a live candidate the query must reject. It is rejected
/// by BOTH query-path guards independently: `filter_label_candidates` drops it on the visibility check
/// (the rolled-back record is no longer visible) AND, as a backstop, on the label re-check
/// (`node_has_label` reads `false` for the freed slot). Both had to be disabled together to drive this
/// red (measured: with both off, `MATCH (n:Person)` returned 2, the scan 1 — the ghost resurrected);
/// disabling either alone leaves the other to catch it. This is precisely the safety the #771 fix
/// leans on: retaining entries is sound only because the consumer re-validates every candidate.
#[test]
fn a_rolled_back_create_is_not_resurrected_by_a_retained_label_entry() {
    let mut coord = fresh_coord();
    run_write(&mut coord, "CREATE (:Person {email: 'a@x.io'})");

    let writer = coord.begin_serializable();
    let _ = run_plan(
        &coord,
        writer,
        &compile(
            "CREATE (:Person {email: 'ghost@x.io'})",
            &IndexCatalog::empty(),
        ),
    );

    coord
        .create_constraint_ddl(
            "widget_sku",
            "Widget",
            &["sku"],
            ConstraintKind::Unique,
            None,
            false,
            false,
        )
        .expect("unrelated constraint DDL");

    coord.rollback(writer).expect("rollback");

    let reader = coord.begin_serializable();
    let (routed, truth) = labelled_vs_truth(&coord, reader);
    assert_eq!(
        truth, 1,
        "ground truth broken: only the committed :Person node may survive the rollback",
    );
    assert_eq!(
        routed, truth,
        "a rolled-back CREATE was resurrected: MATCH (n:Person) returned {routed}, scan {truth}",
    );
}

/// The INCREMENTAL build (`advance_index_builds`) is ADDITIVE for labels and therefore cannot lose one
/// — it never calls `IndexSet::clear`, so there is no entry for it to destroy.
///
/// This pins the premise the `rmp` #771 task got wrong: it named `advance_index_builds` as the
/// production carrier of the defect, on the reasoning that the refill helpers are shared between both
/// drivers. They are (`index_one_node` serves both), but the loss needs `clear` to destroy the entry
/// first, and only the synchronous `rebuild_index` does that. Measured, not assumed: this test PASSED
/// on pristine `HEAD`, before any fix. It stays as the guard that the incremental path remains additive
/// if it ever grows a reset.
#[test]
fn the_incremental_build_is_additive_and_cannot_lose_the_label() {
    let mut coord = fresh_coord();
    run_write(&mut coord, "CREATE (:Person {email: 'a@x.io'})");

    let writer = open_writer_removing_label(&mut coord);

    // The production incremental route: declare an index on an unrelated label and let the engine drain
    // the build exactly as it does between commands.
    coord
        .begin_online_node_property_index("Widget", "sku")
        .expect("declare online index");
    while coord.advance_index_builds(usize::MAX) {}

    // NON-VACUITY: the build must actually have run and published an index, or this exercises nothing.
    assert!(
        !coord.catalog().indexes().is_empty(),
        "vacuous: the incremental build published no index, so no refill ran",
    );

    coord.rollback(writer).expect("rollback");

    let reader = coord.begin_serializable();
    let (routed, truth) = labelled_vs_truth(&coord, reader);
    assert_eq!(truth, 1, "ground truth broken: the node carries :Person");
    assert_eq!(
        routed, truth,
        "the incremental build lost the label: MATCH (n:Person) returned {routed}, scan {truth}",
    );
}
