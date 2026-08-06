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
//!
//! # The PROPERTY tree half (`rmp` #904)
//!
//! Exempting the label tree from `clear` closed the loss on that ONE tree, and left the same live
//! label word gating the trees `clear` **does** wipe. `rebuild_index`'s per-node helpers all decide
//! *which indexes a node belongs to* from `RecordStore::node_labels` — the raw in-place word — so an
//! uncommitted `REMOVE n:Person` made the refill skip the node for every `(Person, *)` node-property,
//! composite, text, spatial, full-text and vector index. Those trees WERE emptied by `clear`, so the
//! entry was destroyed and not re-inserted; the rollback restored the label bit and nothing restored
//! the entry. `MATCH (n:Person) WHERE n.email = ...` then returned zero rows permanently, and — worse
//! — `unique_conflict` received `Some([])`, i.e. "no duplicate", so a live `IS UNIQUE` constraint
//! ADMITTED a second node with the same value.
//!
//! The fix gates the refill on the **union** of the live word and every bitmap `LabelHistory` retains
//! for the node, so the membership decision is a superset in BOTH directions: it never loses a
//! committed label an uncommitted writer removed, and never loses an uncommitted one either. Every
//! consumer of these trees re-checks label membership against the reader's snapshot, so the extra
//! candidates are false positives the re-check drops.

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

/// Runs a write statement, returning the captured runtime error (rolled back) or `Ok(())` (committed).
///
/// This is the constraint-enforcement probe, mirroring `tests/constraint_coordinator.rs`: a constraint
/// violation is captured on the STATEMENT SEAM rather than raised as an `ExecError`, so a violating
/// write rolls the transaction back and surfaces the error here — exactly what the server's
/// `stream_rows` sends to the wire.
fn try_write(coord: &mut Coord, src: &str) -> Result<(), graphus_core::GraphusError> {
    let plan = compile(src, &IndexCatalog::empty());
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
    match captured {
        Some(e) => {
            coord.rollback(txn).expect("rollback after captured error");
            Err(e)
        }
        None => {
            coord.commit(txn).expect("write commits");
            Ok(())
        }
    }
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

/// An UNRELATED index DDL on the PRODUCTION route, while a writer holds an uncommitted
/// `REMOVE n:Person`.
///
/// THE PRODUCTION ROUTE (`rmp` #771 acceptance criterion 1). A server
/// `CREATE POINT INDEX FOR ()-[r:WIDGET]-() ON (r.at)` runs `handle_index_ddl`
/// (graphus-server/src/engine/mod.rs) → `create_point_rel_index` → `rebuild_index` →
/// `IndexSet::clear`. It is the synchronous full rebuild, NOT the incremental build, that destroys
/// the tree — the task expected the incremental `advance_index_builds` to be the carrier, and it is
/// not (it never calls `clear`; see `the_incremental_build_is_additive_and_cannot_lose_the_label`).
/// The index is on an unrelated relationship type: nothing about `:Person` is being declared, and the
/// writer is still open.
///
/// The vehicle used to be `CREATE CONSTRAINT`, which reaches the same `rebuild_index`. It no longer
/// can: since `rmp` task #902 a constraint DDL is fail-closed while any transaction holds uncommitted
/// writes, because a constraint *decides* on the data it reads and must never decide on a value that
/// may be rolled back. An index DDL is the right vehicle anyway — index **population** is precisely
/// the path that is allowed to read raw physical state, since the seek re-checks every candidate.
/// That opposite polarity is the whole subject of this file.
#[test]
fn an_unrelated_index_ddl_does_not_lose_a_label_a_rolled_back_writer_removed() {
    let mut coord = fresh_coord();
    run_write(&mut coord, "CREATE (:Person {email: 'a@x.io'})");

    let writer = open_writer_removing_label(&mut coord);

    coord
        .create_point_rel_index("widget_at", "WIDGET", "at", false)
        .expect("unrelated index DDL");

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
fn an_unrelated_index_ddl_does_not_resurrect_a_label_a_committed_writer_removed() {
    let mut coord = fresh_coord();
    run_write(&mut coord, "CREATE (:Person {email: 'a@x.io'})");

    let writer = open_writer_removing_label(&mut coord);

    coord
        .create_point_rel_index("widget_at", "WIDGET", "at", false)
        .expect("unrelated index DDL");

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
///
/// # Why the entry is still RETAINED after `rmp` #992
///
/// #992 gave every index entry an owner, so a rollback now removes the entries its transaction
/// created — which would have inverted this test's premise and left it passing while testing
/// nothing. It does not, and the reason is the unrelated index DDL in the middle: that DDL drives
/// `rebuild_index` -> `IndexSet::clear`, which drops every open transaction's undo log, because a log
/// taken before a wipe names keys the refill re-creates from COMMITTED versions and replaying it
/// could only destroy committed state. So the rollback here removes nothing and the ghost entry is
/// retained, exactly as this test needs. That mechanism is pinned directly by
/// `coordinator::index_entry_rollback_wiring_992::an_index_ddl_between_the_write_and_the_rollback_retains_the_entry`;
/// if it ever changes, this test's premise must be re-established rather than assumed.
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
        .create_point_rel_index("widget_at", "WIDGET", "at", false)
        .expect("unrelated index DDL");

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

// ---------------------------------------------------------------------------------------------
// The PROPERTY tree half (`rmp` task #904).
//
// Everything above pins the `labels` tree, which `clear` exempts. These pin the trees `clear` DOES
// wipe, whose refill is gated by the same raw live label word — so the #771 defect survived on them
// untouched. `MATCH (n:Person) WHERE n.email = ...` is compared against the SAME query at the SAME
// snapshot with an empty catalog (a forced full scan): the ground truth, which never consults the
// property tree.
// ---------------------------------------------------------------------------------------------

/// `(index-routed count, forced-full-scan count)` for `query`, both read under `txn`.
///
/// The scan arm compiles against an EMPTY catalog, so it cannot reach any index — the two agreeing is
/// a real check, not a tautology.
fn seek_vs_scan(coord: &Coord, txn: graphus_core::TxnId, query: &str) -> (usize, usize) {
    let seek = run_plan(coord, txn, &compile(query, &coord.catalog())).len();
    let scan = run_plan(coord, txn, &compile(query, &IndexCatalog::empty())).len();
    (seek, scan)
}

const FIND_BY_EMAIL: &str = "MATCH (n:Person) WHERE n.email = 'a@x.io' RETURN n";

/// Asserts the planner really routes `FIND_BY_EMAIL` through the property index under `coord`'s live
/// catalog. Without this the `seek == scan` assertions below would pass on a plan that never touches
/// an index — the classic vacuous index test.
fn assert_routes_to_a_seek(coord: &Coord) {
    let plan = compile(FIND_BY_EMAIL, &coord.catalog()).to_string();
    assert!(
        plan.contains("NodeIndexSeek"),
        "vacuous: the query did not plan an index seek, so it exercises no property tree:\n{plan}",
    );
}

/// The `rmp` #904 defect, on the node-property tree: an unrelated index DDL run while a writer holds
/// an uncommitted `REMOVE n:Person` must not destroy the node's `(Person, email)` entry.
///
/// `clear` wipes this tree and the refill decides membership from the LIVE label word, which at that
/// instant says the node is not a `:Person`. The entry is destroyed and never re-inserted; the
/// rollback restores the label bit and nothing restores the entry.
#[test]
fn an_unrelated_index_ddl_does_not_lose_a_property_entry_a_rolled_back_writer_unlabelled() {
    let mut coord = fresh_coord();
    run_write(&mut coord, "CREATE (:Person {email: 'a@x.io'})");
    coord
        .create_node_property_index("Person", "email")
        .expect("declare the property index");
    assert_routes_to_a_seek(&coord);

    let writer = open_writer_removing_label(&mut coord);

    coord
        .create_point_rel_index("widget_at", "WIDGET", "at", false)
        .expect("unrelated index DDL");

    coord.rollback(writer).expect("rollback");

    let reader = coord.begin_serializable();
    let (seek, scan) = seek_vs_scan(&coord, reader, FIND_BY_EMAIL);
    assert_eq!(
        scan, 1,
        "ground truth broken: the rolled-back REMOVE must leave the node carrying :Person",
    );
    assert_eq!(
        seek, scan,
        "the rebuild dropped the node from the (Person, email) tree because the LIVE label word \
         showed an uncommitted REMOVE: the seek returned {seek}, the ground-truth scan {scan}",
    );
}

/// The same loss reached through the **composite** tree — the other stale-retaining tree `clear`
/// wipes, and the one that backs `NODE KEY`. Its duplicate check (`node_key_tuple_conflict`) reads the
/// composite tree exactly as `unique_conflict` reads the property tree, so an emptied composite admits
/// a committed duplicate under a declared NODE KEY.
#[test]
fn a_rebuild_during_an_uncommitted_label_removal_cannot_admit_a_node_key_duplicate() {
    let mut coord = fresh_coord();
    run_write(
        &mut coord,
        "CREATE (:Person {email: 'a@x.io', city: 'lisbon'})",
    );
    coord
        .create_constraint_general(
            "person_key",
            "Person",
            &["email", "city"],
            ConstraintKind::NodeKey,
            None,
        )
        .expect("declare the node-key constraint");

    const DUPLICATE: &str = "CREATE (:Person {email: 'a@x.io', city: 'lisbon'})";

    // NON-VACUITY, control arm: with no rebuild in the way the NODE KEY refuses the duplicate.
    assert!(
        try_write(&mut coord, DUPLICATE).is_err(),
        "vacuous: the NODE KEY does not refuse a duplicate even without a rebuild",
    );

    let writer = open_writer_removing_label(&mut coord);

    coord
        .create_point_rel_index("widget_at", "WIDGET", "at", false)
        .expect("unrelated index DDL");

    coord.rollback(writer).expect("rollback");

    assert!(
        try_write(&mut coord, DUPLICATE).is_err(),
        "the rebuild emptied the backing composite tree and a live NODE KEY constraint admitted a \
         second node with the same (email, city) tuple",
    );
}

/// The second half of the `rmp` #904 defect, and the serious one: the emptied tree does not merely
/// lose rows, it makes a live `IS UNIQUE` constraint ADMIT A DUPLICATE.
///
/// `unique_conflict` consults the backing property index and treats `Some([])` as "no duplicate". With
/// the node dropped from that tree the answer is an empty set, so a second `:Person {email:'a@x.io'}`
/// is accepted — a committed duplicate under a declared uniqueness constraint, which no later query
/// can repair.
#[test]
fn a_rebuild_during_an_uncommitted_label_removal_cannot_admit_a_unique_duplicate() {
    let mut coord = fresh_coord();
    run_write(&mut coord, "CREATE (:Person {email: 'a@x.io'})");
    coord
        .create_constraint("person_email", "Person", "email", ConstraintKind::Unique)
        .expect("declare the uniqueness constraint");

    const DUPLICATE: &str = "CREATE (:Person {email: 'a@x.io'})";

    // NON-VACUITY, control arm: with no rebuild in the way the constraint refuses the duplicate. If
    // this ever stops holding, the assertion at the end of the test proves nothing.
    assert!(
        try_write(&mut coord, DUPLICATE).is_err(),
        "vacuous: the uniqueness constraint does not refuse a duplicate even without a rebuild",
    );

    let writer = open_writer_removing_label(&mut coord);

    coord
        .create_point_rel_index("widget_at", "WIDGET", "at", false)
        .expect("unrelated index DDL");

    coord.rollback(writer).expect("rollback");

    assert!(
        try_write(&mut coord, DUPLICATE).is_err(),
        "the rebuild emptied the backing index, `unique_conflict` read Some([]) as `no duplicate`, \
         and a live IS UNIQUE constraint admitted a second node with the same value",
    );
}

/// The opposite direction, which the fix must not break: a label a COMMITTED writer removed must not
/// be resurrected through the property tree either. The refill's superset is only safe because every
/// consumer re-checks label membership at the reader's snapshot.
#[test]
fn an_unrelated_index_ddl_does_not_resurrect_a_property_entry_a_committed_writer_unlabelled() {
    let mut coord = fresh_coord();
    run_write(&mut coord, "CREATE (:Person {email: 'a@x.io'})");
    coord
        .create_node_property_index("Person", "email")
        .expect("declare the property index");
    assert_routes_to_a_seek(&coord);

    let writer = open_writer_removing_label(&mut coord);

    coord
        .create_point_rel_index("widget_at", "WIDGET", "at", false)
        .expect("unrelated index DDL");

    coord.commit(writer).expect("the REMOVE commits");

    let reader = coord.begin_serializable();
    let (seek, scan) = seek_vs_scan(&coord, reader, FIND_BY_EMAIL);
    assert_eq!(
        scan, 0,
        "ground truth broken: the committed REMOVE must leave the node without :Person",
    );
    assert_eq!(
        seek, scan,
        "the widened refill resurrected a row whose label was genuinely removed: \
         seek {seek}, scan {scan}",
    );
}

/// **The "index changes the answer" gate.** Creating an index must never alter a result BAG — not the
/// row count, not the values, not the multiplicities — and that must hold across the whole `rmp` #904
/// interleaving, at every point in it.
///
/// This project has paid for that class three times, so the check is a full multiset comparison rather
/// than a count: the same query is compiled twice, once against the coordinator's live catalog (which
/// routes it through whichever index applies) and once against an empty catalog (which forces the exact
/// scan), and both are run at the SAME snapshot. It sweeps the queries that touch each affected tree —
/// the node-property seek, a range seek, a composite seek and a plain label scan — at four points:
/// before the writer opens, while its `REMOVE` is uncommitted, after the rebuild, and after the
/// rollback.
#[test]
fn creating_an_index_never_changes_the_result_bag_across_the_interleaving() {
    /// Every query's index-routed and forced-scan answers, as sorted bags of rendered rows.
    fn bags_agree(coord: &Coord, txn: graphus_core::TxnId, query: &str) -> Result<(), String> {
        let render = |plan: &PhysicalPlan| -> Vec<String> {
            let mut rows: Vec<String> = run_plan(coord, txn, plan)
                .iter()
                .map(|row| format!("{:?}", row.values()))
                .collect();
            rows.sort();
            rows
        };
        let routed = render(&compile(query, &coord.catalog()));
        let scanned = render(&compile(query, &IndexCatalog::empty()));
        if routed == scanned {
            Ok(())
        } else {
            Err(format!(
                "`{query}`: the index changed the answer.\n  routed: {routed:?}\n  scanned: {scanned:?}"
            ))
        }
    }

    const QUERIES: &[&str] = &[
        "MATCH (n:Person) WHERE n.email = 'a@x.io' RETURN n.email AS e, n.city AS c",
        "MATCH (n:Person) WHERE n.city > 'a' RETURN n.email AS e",
        "MATCH (n:Person) WHERE n.email = 'a@x.io' AND n.city = 'lisbon' RETURN n.email AS e",
        "MATCH (n:Person) RETURN n.email AS e",
        "MATCH (n) RETURN labels(n) AS l, n.email AS e",
    ];

    /// Runs the whole sweep at one point in the interleaving, in a read transaction of its own that is
    /// rolled back afterwards so the observation perturbs nothing.
    fn checkpoint(coord: &mut Coord, at: &str, failures: &mut Vec<String>) {
        let txn = coord.begin_serializable();
        for q in QUERIES {
            if let Err(e) = bags_agree(coord, txn, q) {
                failures.push(format!("at `{at}`: {e}"));
            }
        }
        coord.rollback(txn).expect("the probe rolls back");
    }

    let mut failures: Vec<String> = Vec::new();

    let mut coord = fresh_coord();
    run_write(
        &mut coord,
        "CREATE (:Person {email: 'a@x.io', city: 'lisbon'})",
    );
    run_write(
        &mut coord,
        "CREATE (:Person {email: 'b@x.io', city: 'porto'})",
    );
    run_write(&mut coord, "CREATE (:Widget {sku: 'w1'})");
    coord
        .create_node_property_index("Person", "email")
        .expect("declare the property index");
    coord
        .create_constraint_general(
            "person_key",
            "Person",
            &["email", "city"],
            ConstraintKind::NodeKey,
            None,
        )
        .expect("declare the node-key constraint");

    // NON-VACUITY: at least one of these queries must actually reach an index, or the whole sweep is a
    // comparison of a scan with itself.
    assert!(
        QUERIES.iter().any(|q| compile(q, &coord.catalog())
            .to_string()
            .contains("IndexSeek")),
        "vacuous: no query in the sweep plans an index seek",
    );

    checkpoint(&mut coord, "before the writer opens", &mut failures);

    let writer = open_writer_removing_label(&mut coord);
    checkpoint(&mut coord, "while the REMOVE is uncommitted", &mut failures);

    coord
        .create_point_rel_index("widget_at", "WIDGET", "at", false)
        .expect("unrelated index DDL");
    checkpoint(
        &mut coord,
        "after the rebuild, writer still open",
        &mut failures,
    );

    coord.rollback(writer).expect("rollback");
    checkpoint(&mut coord, "after the rollback", &mut failures);

    assert!(
        failures.is_empty(),
        "the index changed the answer at {} point(s):\n{}",
        failures.len(),
        failures.join("\n"),
    );
}
