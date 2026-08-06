//! DST scenario for the **derived-index reclamation** the version GC drives (`rmp` #992, AC2).
//!
//! `record_graph::reindex_node` re-indexes an entity's whole current state on every write and only
//! ever inserts, so before this task the derived indexes grew with the number of versions of a
//! rewritten key and nothing ever took the dead entries back. The GC now reports what it destroyed
//! ([`graphus_storage::DeadIndexKey`]) and the derived-index layer removes what no live version
//! warrants (`graphus_cypher::IndexSet::collect_dead_keys`).
//!
//! Two properties are worth a deterministic scenario rather than a unit test, because both are about
//! an **interleaving** between a maintenance pass and a reader:
//!
//! 1. **Plateau.** A steady churn of `write; maintenance tick` must leave the index footprint flat,
//!    not linear in the number of ticks. This is the shape a leak shows up in — the same one
//!    `graphus-iot-gen`'s `churn_plateau` uses for the undo store — and it is the acceptance
//!    criterion's claim stated over time instead of over a single pass.
//! 2. **Teeth.** A version an **open reader** can still resolve must keep its index entry, and must
//!    lose it the moment that reader retires. The watermark is what separates the two, so the
//!    scenario runs the *same* churn under both conditions and compares.
//!
//! Every step here is fixed — the same operations in the same order over the DST in-memory device and
//! log — so it is exactly the single-threaded interleaving the simulator models, and it reproduces
//! identically on every run.

use graphus_core::TxnId;
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

type Coord = TxnCoordinator<MemBlockDevice, MemLogSink>;

/// How many `write; maintenance tick` rounds the churn runs. Large enough that a per-version leak is
/// unmistakable against a plateau, small enough to stay a fast deterministic test.
const ROUNDS: usize = 40;

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

fn run_plan(coord: &Coord, txn: TxnId, plan: &PhysicalPlan) -> Vec<Row> {
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

fn write(coord: &mut Coord, src: &str) {
    let plan = compile(src, &IndexCatalog::empty());
    let txn = coord.begin_serializable();
    let _ = run_plan(coord, txn, &plan);
    coord.commit(txn).expect("write commits");
}

fn read_rows(coord: &mut Coord, catalog: &IndexCatalog, src: &str) -> Vec<Row> {
    let plan = compile(src, catalog);
    let txn = coord.begin_serializable();
    let rows = run_plan(coord, txn, &plan);
    coord.commit(txn).expect("read commits");
    rows
}

/// The corpus every scenario starts from: one indexed `(:Sensor).reading` over a single node.
fn seeded() -> Coord {
    let mut coord = fresh_coord();
    write(&mut coord, "CREATE (:Sensor {id: 1, reading: 0})");
    coord
        .create_node_property_index("Sensor", "reading")
        .expect("create index");
    coord
}

/// The corpus's steady-state index footprint: one `(:Sensor, n)` label entry plus one
/// `(:Sensor).reading` entry for the value in place. Everything above this is a version that died and
/// was not collected.
const FLAT: usize = 2;

/// **Plateau.** `ROUNDS` rounds of "rewrite the indexed property, then run one maintenance tick" must
/// leave the indexes holding exactly [`FLAT`] entries — the label entry plus the value in place —
/// rather than one more per round.
///
/// The pre-#992 behaviour is the arithmetic alternative and is stated in the failure message: with no
/// collection the count at round `r` is `r + FLAT`, so a regression that disables the mechanism does
/// not merely fail, it fails with a number that says which mechanism broke.
#[test]
fn a_rewrite_churn_leaves_the_index_footprint_flat() {
    let mut coord = seeded();
    assert_eq!(
        coord.derived_index_entries(),
        FLAT,
        "precondition: the seeded corpus holds one label entry and one property entry"
    );

    let mut peak = 0usize;
    for round in 1..=ROUNDS {
        write(
            &mut coord,
            &format!("MATCH (n:Sensor) SET n.reading = {round} RETURN n"),
        );
        coord.gc().expect("maintenance tick");
        let held = coord.derived_index_entries();
        peak = peak.max(held);
        assert_eq!(
            held,
            FLAT,
            "round {round}: the indexes must hold exactly the label entry and the value in place. \
             Holding {held} means the collection is not keeping up with the churn; holding {} would \
             mean it never ran at all.",
            round + FLAT
        );
    }
    assert_eq!(
        peak, FLAT,
        "the footprint must be flat across the whole churn"
    );

    // The index is still a correct candidate source afterwards, which is the half a leak test cannot
    // see: an index that removed too much also has a flat footprint.
    let indexed = coord.catalog();
    let found = read_rows(
        &mut coord,
        &indexed,
        &format!("MATCH (n:Sensor) WHERE n.reading = {ROUNDS} RETURN n.id AS a"),
    );
    assert_eq!(
        found.len(),
        1,
        "after the churn the live value must still be findable THROUGH the index"
    );
}

/// **Teeth.** The same churn with a reader open throughout: every version that reader can still
/// resolve keeps its index entry, so the footprint grows — and the moment the reader retires, one
/// pass takes it back to [`FLAT`].
///
/// This is the property that makes the collection safe rather than merely tidy. The GC watermark is
/// the oldest open snapshot, so "dead" always means "dead for everyone"; if a future change derived
/// the watermark from anything else, the first assertion below would start failing while the plateau
/// test above still passed.
#[test]
fn an_open_reader_pins_its_versions_entries_until_it_retires() {
    let mut coord = seeded();

    // A reader that begins before the churn and stays open across every tick.
    let reader = coord.begin_serializable();

    for round in 1..=ROUNDS {
        write(
            &mut coord,
            &format!("MATCH (n:Sensor) SET n.reading = {round} RETURN n"),
        );
        coord.gc().expect("maintenance tick");
    }

    assert_eq!(
        coord.derived_index_entries(),
        ROUNDS + FLAT,
        "a version the open reader can still resolve lost its index entry: the collection ran past \
         the GC watermark"
    );

    coord.rollback(reader).expect("the reader retires");
    coord
        .gc()
        .expect("maintenance tick after the reader retires");
    assert_eq!(
        coord.derived_index_entries(),
        FLAT,
        "once no reader can resolve them, the churn's dead entries must be collected in one pass"
    );
}

/// **A deleted node's entries survive exactly as long as the node does.** Deleting only tombstones,
/// so an older snapshot still sees the node and its entries must stay; physical reclamation is what
/// makes them collectable, and that is gated on the same watermark.
#[test]
fn a_deleted_nodes_entries_go_with_its_reclamation_and_not_before() {
    let mut coord = seeded();
    assert_eq!(
        coord.derived_index_entries(),
        FLAT,
        "precondition: the node is indexed"
    );

    let reader = coord.begin_serializable();
    write(&mut coord, "MATCH (n:Sensor) DELETE n");
    coord
        .gc()
        .expect("maintenance tick while the reader is open");
    assert_eq!(
        coord.derived_index_entries(),
        FLAT,
        "the entries of a node an open reader still sees were collected"
    );

    coord.rollback(reader).expect("the reader retires");
    coord
        .gc()
        .expect("maintenance tick after the reader retires");
    assert_eq!(
        coord.derived_index_entries(),
        0,
        "the reclaimed node's label and property entries survived its record"
    );
}
