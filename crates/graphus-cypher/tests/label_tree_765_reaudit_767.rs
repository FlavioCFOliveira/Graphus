//! `rmp` #765's per-tree audit, RE-RUN for the `labels` tree after `rmp` #767 made the label re-check
//! snapshot-isolated. Acceptance criterion (4) of #767.
//!
//! # Why this had to be re-derived rather than carried over
//!
//! #765 is committed-row loss caused by a rebuild: `IndexSet::clear` wipes a tree, `rebuild_index`
//! refills it newest-wins from CURRENT state, and an entry an OLDER snapshot was still entitled to is
//! destroyed. The per-candidate re-check can only REMOVE candidates, never resurrect one, so a
//! destroyed entry is a row lost for good. Four trees needed the
//! `rebuilt_trees_trustworthy_from` watermark for exactly this reason (`node_props`, `rel_props`,
//! `composite`, `rel_composite`).
//!
//! The `labels` tree was ruled safe. #767's task text records the reason believed at the time: that
//! the re-check read the CURRENT bitmap, so a dropped stale entry "would have been rejected anyway".
//! **That reason is now gone** — after #767 the re-check resolves label membership AS OF THE READER'S
//! SNAPSHOT, so an older reader can legitimately need a candidate whose label the current bitmap no
//! longer shows. If that were the whole of the argument, this tree would now be exposed.
//!
//! # The verdict, re-derived: still SAFE, for a different and stronger reason
//!
//! The labels tree is **purely additive and is never emptied**, so a rebuild destroys nothing:
//!
//! * its ONLY mutation is `insert` (`IndexSet::insert_label`) — there is no removal path;
//! * `IndexSet::clear` deliberately does **not** reset it (`rmp` #771), so a rebuild's refill can only
//!   ADD to it;
//! * `IndexSet::fail_closed` sets `labels_usable = false` rather than wiping it, and an unusable label
//!   index degrades to a full scan.
//!
//! So over an `IndexSet`'s whole life, once `(label, node)` is inserted it stays. Every node that
//! carries a label at ANY point either carried it at store open (the initial build inserted it) or
//! acquired it later (the write path inserted it). The candidate set is therefore a **monotone
//! superset** of what any snapshot can need, and a snapshot-correct re-check narrows it to exactly the
//! right answer. #765 cannot bite a tree that never loses an entry.
//!
//! # This invariant is load-bearing, so it is PINNED here, not just asserted in prose
//!
//! The safety now rests entirely on "the labels tree never loses an entry". That is a tempting thing
//! to break: `IndexSet::clear`'s own documentation notes the cost of retention is that "nothing prunes
//! a label entry whose node was since deleted or relabelled". Anyone adding that prune — or
//! re-enabling the wipe — reintroduces #765 on this tree, and now it would be a REAL row loss rather
//! than a harmless false positive, because the re-check no longer independently rejects the stale
//! entry.
//!
//! [`an_unrelated_rebuild_does_not_lose_a_label_an_older_reader_still_sees`] is the trap: it compares
//! the label-INDEX-routed answer against an all-nodes-scan ground truth, at a snapshot that predates a
//! COMMITTED label removal, across a full rebuild. It fails the moment the tree stops being additive.

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

type Coord = TxnCoordinator<MemBlockDevice, MemLogSink>;

fn fresh_coord() -> Coord {
    let device = MemBlockDevice::new(0);
    let wal = WalManager::create(MemLogSink::new()).expect("create wal");
    TxnCoordinator::new(RecordStore::create(device, wal, 64, 1).expect("create store"))
}

fn compile(src: &str) -> PhysicalPlan {
    let toks = tokenize(src).expect("lex");
    let ast = parse_tokens(&toks, src).expect("parse");
    let validated = analyze(&ast).expect("analyze");
    plan_physical(&lower(&validated), &IndexCatalog::empty())
}

fn run_plan(coord: &Coord, txn: TxnId, plan: &PhysicalPlan) -> Vec<Row> {
    let bound = bind_parameters(plan, &Parameters::new()).expect("bind");
    let mut graph = coord.statement(txn).expect("statement");
    let mut cursor = execute(plan, &bound, &mut graph).expect("open cursor");
    cursor.collect_all().expect("collect")
}

fn run_write(coord: &mut Coord, src: &str) {
    let plan = compile(src);
    let txn = coord.begin_serializable();
    let _ = run_plan(coord, txn, &plan);
    coord.commit(txn).expect("write commits");
}

/// `(label-index-routed count, all-nodes-scan ground truth)` for `:Person`, both read under `txn`.
///
/// The ground truth walks every node and reads `labels(n)`; it never consults the label index. The two
/// agreeing is therefore a real check rather than a tautology — and any divergence is precisely the
/// index losing (or inventing) a row relative to the snapshot-correct scan.
fn routed_vs_truth(coord: &Coord, txn: TxnId) -> (usize, usize) {
    let routed = run_plan(coord, txn, &compile("MATCH (n:Person) RETURN n")).len();
    let truth = run_plan(coord, txn, &compile("MATCH (n) RETURN labels(n) AS l"))
        .iter()
        .filter(|row| {
            row.values().iter().any(|v| match v {
                RowValue::Value(Value::List(items)) => {
                    items.contains(&Value::String("Person".into()))
                }
                _ => false,
            })
        })
        .count();
    (routed, truth)
}

/// Runs an UNRELATED index DDL, the production route to a full `IndexSet::clear` + `rebuild_index`
/// (`rmp` #771): `handle_index_ddl` -> `create_point_rel_index` -> `rebuild_index` ->
/// `IndexSet::clear`. Nothing about `:Person` is being declared.
///
/// The vehicle was `CREATE CONSTRAINT` until `rmp` task #902 made a constraint DDL fail-closed while
/// any transaction holds uncommitted writes — which is the state the trap below deliberately sets up.
/// An index DDL is the right vehicle in any case: index **population** is exactly the path that may
/// read raw physical state, because every candidate is re-checked at seek time, which is the property
/// this file audits.
fn unrelated_rebuild(coord: &mut Coord) {
    coord
        .create_point_rel_index("widget_at", "WIDGET", "at", false)
        .expect("unrelated index DDL succeeds");
}

/// **THE #765 RE-AUDIT TRAP for the `labels` tree (`rmp` #767 AC 4).**
///
/// A reader opened before a COMMITTED `REMOVE n:Person` must still match the node — and must get the
/// SAME answer through the label index as through a plain scan — even after an unrelated full rebuild
/// has refilled the index from bitmaps that no longer show the label.
///
/// This is the assertion that would fail if the labels tree ever stopped being additive.
#[test]
fn an_unrelated_rebuild_does_not_lose_a_label_an_older_reader_still_sees() {
    let mut coord = fresh_coord();
    run_write(&mut coord, "CREATE (:Person {email: 'a@x.io'})");

    // A reader whose snapshot is taken BEFORE the removal commits.
    let reader = coord.begin_serializable();
    assert_eq!(
        routed_vs_truth(&coord, reader),
        (1, 1),
        "precondition: the reader must see the :Person node before anything else happens"
    );

    // The label is removed and COMMITTED — after the reader's snapshot.
    run_write(&mut coord, "MATCH (n:Person) REMOVE n:Person");

    // An unrelated rebuild refills the index from CURRENT bitmaps, which no longer show `:Person`.
    unrelated_rebuild(&mut coord);

    // The reader is entitled to the node at its snapshot, and both routes must agree.
    let (routed, truth) = routed_vs_truth(&coord, reader);
    assert_eq!(
        truth, 1,
        "rmp #767: the scan ground truth must still show :Person at the older reader's snapshot"
    );
    assert_eq!(
        routed, truth,
        "rmp #765 ROW LOSS (labels tree): the label-index-routed answer ({routed}) diverged from the \
         snapshot-correct scan ({truth}) after an unrelated rebuild. The labels tree's #765 safety \
         rests ENTIRELY on it being purely additive (only `insert_label`, never emptied by `clear` — \
         `rmp` #771); a prune or a re-enabled wipe reintroduces #765 here, and since `rmp` #767 the \
         re-check no longer independently rejects the stale entry, so it is a REAL lost row"
    );
}

/// The opposite direction, so the retention above cannot pass by simply never dropping anything: a
/// reader whose snapshot is AFTER the committed removal must NOT match the node, on either route.
/// Retained stale entries must remain false positives that the re-check drops.
#[test]
fn a_retained_stale_entry_is_still_rejected_for_a_current_reader() {
    let mut coord = fresh_coord();
    run_write(&mut coord, "CREATE (:Person {email: 'a@x.io'})");
    run_write(&mut coord, "MATCH (n:Person) REMOVE n:Person");
    unrelated_rebuild(&mut coord);

    let current = coord.begin_serializable();
    let (routed, truth) = routed_vs_truth(&coord, current);
    assert_eq!(
        (routed, truth),
        (0, 0),
        "a reader after the committed removal must not match the node on either route — the retained \
         stale label entry must still be rejected by the re-check"
    );
}

/// The #771 direction must not regress: a rebuild run while a writer holds an UNCOMMITTED
/// `REMOVE n:Person` must not destroy the committed entry, and after that writer rolls back the label
/// must still be found through the index.
#[test]
fn an_uncommitted_removal_plus_rebuild_still_cannot_lose_the_committed_label() {
    let mut coord = fresh_coord();
    run_write(&mut coord, "CREATE (:Person {email: 'a@x.io'})");

    // A writer removes the label and stays OPEN.
    let writer = coord.begin_serializable();
    let _ = run_plan(&coord, writer, &compile("MATCH (n:Person) REMOVE n:Person"));

    // The rebuild refills from bitmaps that include the writer's UNCOMMITTED removal.
    unrelated_rebuild(&mut coord);

    // The writer rolls back: the record's bit comes back, and so must the index answer.
    coord.rollback(writer).expect("writer rolls back");

    let after = coord.begin_serializable();
    let (routed, truth) = routed_vs_truth(&coord, after);
    assert_eq!(
        (routed, truth),
        (1, 1),
        "rmp #771 regression: a rebuild during an uncommitted REMOVE destroyed the committed label \
         entry, so it never came back when the writer rolled back"
    );
}
