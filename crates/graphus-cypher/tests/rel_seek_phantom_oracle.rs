//! The **non-weakening oracle** for the relationship equality-seek SSI footprint (`rmp` #683).
//!
//! # What this file protects
//!
//! `rel_index_seek_eq` used to SIREAD-mark **every live relationship** on every seek
//! (`mark_all_live_rels()` — an O(live rels) "blanket"). #683 removed that blanket and replaced it with
//! the precise `PredicateRead::RelEquality` marker. Removing markers is the **only** kind of change that
//! can introduce an SSI **false negative** (a missed anomaly — a critical ACID defect, as opposed to a
//! false positive, which merely costs throughput). So "the new footprint is not weaker than the blanket"
//! may not be *argued in prose*; it must be **checked**. This file is that check.
//!
//! Each cell below was **measured against the pre-#683 code** (the blanket implementation) and is pinned
//! here as an assertion. A cell may go `false` -> `true` (strictly stronger). A cell going `true` ->
//! `false` is a false negative and a critical regression — that is what these tests exist to catch.
//!
//! # The four cells, and why each one exists
//!
//! Two orthogonal axes: WHAT the concurrent writer does, and WHEN it does it.
//!
//! | shape        | interleaving | pre-#683 (blanket) | post-#683 (`RelEquality`) |
//! |--------------|--------------|--------------------|---------------------------|
//! | `CreateNew`  | writer-first | true               | true                      |
//! | `CreateNew`  | reader-first | **false**          | **true** (hole closed)    |
//! | `ModifyInto` | writer-first | true               | true                      |
//! | `ModifyInto` | reader-first | true               | true                      |
//!
//! * **writer-first** — T2 writes before T1's seek. Both arms abort, but NOT because of the blanket:
//!   the real mechanism is the **shared ephemeral index**. `reindex_rel` inserts under `EPHEMERAL_TXN`
//!   regardless of commit, so T2's uncommitted relationship surfaces as a *candidate* of T1's seek, and
//!   the candidate re-check's `rel_data` SIREAD-marks it **before** the visibility filter drops it.
//!   These two cells therefore say nothing about the blanket; they are here to keep the other two
//!   honest (a change that broke them could not pass unnoticed).
//!
//! * **`ModifyInto`/reader-first** — the ONLY cell the blanket was ever load-bearing for. T1 seeks
//!   'X' and matches nothing; T2 then SETs an existing, already-committed relationship from 'Y' INTO
//!   'X'. Nothing links them physically: the relationship is not a candidate (the index had no 'X'
//!   entry at seek time) and T1 never examined it. The blanket caught it only by marking every live
//!   relationship. Post-#683 the edge forms precisely, via T2's `set_rel_property` post-image
//!   `RelEquality{T, p, 'X'}` announcement matching T1's marker. **This cell is the whole reason the
//!   writer half had to land before the reader half.**
//!
//! * **`CreateNew`/reader-first** — a phantom hole that existed at HEAD **before** #683: the executor's
//!   `RelIndexSeek` path (`index_seek_rel_eq`, `rmp` #659) registered no predicate marker at all, and
//!   the blanket cannot mark a relationship that does not exist yet. T1 reads "no `:TRANSFER` with
//!   tx_id='X'", T2 then creates exactly one, and no rw-edge formed. #683 closes it for free, because
//!   the marker now lives inside `rel_index_seek_eq` where both of its callers get it.
//!
//! # Why every scenario needs THREE transactions
//!
//! A single rw-edge is **not** a dangerous structure — SSI aborts on a *pivot*: a transaction with both
//! an inbound and an outbound rw-edge (`T0 --rw--> T1 --rw--> T2`). A two-transaction test of these
//! shapes would only abort if BOTH directions of the edge happened to form, which would silently mask a
//! half-broken fix (one direction working, the other not) and would prove nothing about the direction
//! under test.
//!
//! So each probe builds the pivot explicitly around T1, the reader:
//!   * **edge 1** `T0 --rw--> T1` is manufactured from a plain physical-key SIREAD (T0 reads
//!     `anchor.v`; T1 writes it) — an independent, always-present mechanism, deliberately NOT the one
//!     under test;
//!   * **edge 2** `T1 --rw--> T2` is the edge under test.
//!
//! T1 is then the pivot and aborts **iff edge 2 formed**. A failure to abort isolates the missing edge
//! to the marker under test, with no other explanation available.

use graphus_core::{GraphusError, TxnId, Value};
use graphus_cypher::binding::{Parameters, bind_parameters};
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

fn fresh_coord() -> Coord {
    let device = MemBlockDevice::new(0);
    let wal = WalManager::create(MemLogSink::new()).expect("create wal");
    let store: Store = RecordStore::create(device, wal, 64, 1).expect("create store");
    TxnCoordinator::new(store)
}

/// Compiles against the coordinator's REAL catalog.
///
/// NON-VACUITY: an `IndexCatalog::empty()` here would withhold the index from the planner, silently
/// plan a typed scan + residual filter, and make every assertion in this file measure the **scan**
/// path instead of the seek — a dead sonde that passes for the wrong reason. (This is not
/// hypothetical: the first draft of this probe did exactly that.)
fn compile(coord: &Coord, src: &str) -> PhysicalPlan {
    let toks = tokenize(src).expect("lex");
    let ast = parse_tokens(&toks, src).expect("parse");
    let validated = analyze(&ast).expect("analyze");
    plan_physical(&lower(&validated), &coord.catalog())
}

fn run_stmt(coord: &Coord, txn: TxnId, src: &str) -> (Vec<Row>, Option<GraphusError>) {
    let plan = compile(coord, src);
    let bound = bind_parameters(&plan, &Parameters::new()).expect("bind");
    let mut graph = coord.statement(txn).expect("statement");
    let rows = {
        let mut cursor = execute(&plan, &bound, &mut graph).expect("open cursor");
        cursor.collect_all().expect("collect")
    };
    let err = graph.take_error();
    (rows, err)
}

fn run_write_committed(coord: &mut Coord, src: &str) {
    let t = coord.begin_serializable();
    let (_r, err) = run_stmt(coord, t, src);
    assert!(err.is_none(), "seed/write {src:?} error: {err:?}");
    coord.commit(t).expect("write commits");
}

/// NON-VACUITY CONTROL: the reading query must actually be planned as a `RelIndexSeek`.
fn assert_plans_rel_index_seek(coord: &Coord, src: &str) {
    let rendered = compile(coord, src).root.to_string();
    assert!(
        rendered.contains("RelIndexSeek"),
        "NON-VACUITY CONTROL FAILED: {src:?} did not plan a RelIndexSeek, so this probe would be \
         measuring the scan fallback rather than the seek under test. plan:\n{rendered}"
    );
}

/// What the concurrent writer T2 does — the two distinct phantom shapes.
#[derive(Clone, Copy, Debug)]
enum Shape {
    /// T2 CREATEs a brand-new relationship holding the sought value (an **absence** phantom).
    CreateNew,
    /// T2 SETs an EXISTING, already-committed relationship's property INTO the sought value (a
    /// **modify-into-value** phantom) — the one cell the removed blanket was load-bearing for.
    ModifyInto,
}

const SEEK_QUERY: &str = "MATCH ()-[r:TRANSFER]->() WHERE r.tx_id = 'X' RETURN count(r) AS c";

/// The 3-txn pivot probe. Returns whether T1 (the reader, and the pivot) aborted — i.e. whether the
/// rw-edge under test formed. See the module docs for the construction.
fn probe(writer_first: bool, shape: Shape) -> bool {
    let mut coord = fresh_coord();
    // A standalone relationship-property index, NOT a constraint: this isolates the QUERY path
    // (`index_seek_rel_eq` -> `rel_index_seek_eq`) from the write-path uniqueness check
    // (`rel_unique_conflict`), which would otherwise contribute its own predicate read and confound
    // the measurement.
    coord
        .create_rel_property_index_named(Some("ix_tx"), "TRANSFER", "tx_id", false)
        .expect("create rel property index");
    // Endpoints are seeded and COMMITTED, so T2's write touches ONLY the relationship. If T2 also
    // inserted nodes, its `AllNodes`/`Label` predicate-write footprint could form a confounding edge
    // with T1's node reads and the probe would abort for the wrong reason.
    run_write_committed(&mut coord, "CREATE (:Anchor {v: 0})");
    run_write_committed(&mut coord, "CREATE (:Src), (:Dst)");
    // A live, committed TRANSFER holding 'Y': the `ModifyInto` subject, and a live relationship for the
    // (removed) blanket to have had something to mark.
    run_write_committed(
        &mut coord,
        "MATCH (s:Src), (d:Dst) CREATE (s)-[:TRANSFER {tx_id: 'Y'}]->(d)",
    );

    assert_plans_rel_index_seek(&coord, SEEK_QUERY);
    let write_src = match shape {
        Shape::CreateNew => "MATCH (s:Src), (d:Dst) CREATE (s)-[:TRANSFER {tx_id: 'X'}]->(d)",
        Shape::ModifyInto => "MATCH ()-[r:TRANSFER]->() WHERE r.tx_id = 'Y' SET r.tx_id = 'X'",
    };

    let t0 = coord.begin_serializable();
    let t1 = coord.begin_serializable();
    let t2 = coord.begin_serializable();

    // Edge 1 (NOT under test): T0 reads `anchor.v`; T1 writes it below => T0 --rw--> T1.
    let (_r, e) = run_stmt(&coord, t0, "MATCH (a:Anchor) RETURN a.v AS v");
    assert!(e.is_none(), "t0 read: {e:?}");

    if writer_first {
        let (_r, e) = run_stmt(&coord, t2, write_src);
        assert!(e.is_none(), "t2 write: {e:?}");
    }

    // T1 closes edge 1 by writing the anchor, then runs the seek that must see nothing.
    let (_r, e) = run_stmt(&coord, t1, "MATCH (a:Anchor) SET a.v = 1");
    assert!(e.is_none(), "t1 write: {e:?}");
    let (rows, e) = run_stmt(&coord, t1, SEEK_QUERY);
    assert!(e.is_none(), "t1 seek: {e:?}");
    assert_eq!(
        rows[0].value("c"),
        Value::Integer(0),
        "T1 must see NO matching relationship (T2's write is uncommitted and invisible to T1's \
         snapshot) — seeing one would mean there is no phantom left to catch and the probe is \
         vacuous ({shape:?}, writer_first={writer_first})"
    );

    if !writer_first {
        let (_r, e) = run_stmt(&coord, t2, write_src);
        assert!(e.is_none(), "t2 write: {e:?}");
    }

    // T1 is the pivot (inbound from T0, outbound to T2) => it aborts IFF edge 2 formed.
    let c1 = coord.commit(t1);
    let aborted = c1.is_err();
    if aborted {
        assert!(
            matches!(c1, Err(GraphusError::Transaction(_))),
            "an SSI abort must surface as a RETRIABLE transaction error, not some other failure: \
             {c1:?}"
        );
    }
    let _ = coord.commit(t2);
    let _ = coord.commit(t0);
    aborted
}

// =================================================================================================
// The four pinned cells.
// =================================================================================================

#[test]
fn create_new_writer_first_forms_edge() {
    // Pre-#683 (blanket): true. Post-#683: true. The mechanism is the shared ephemeral index candidate
    // re-check, NOT the blanket and NOT the predicate marker — this cell holds either way, and exists
    // so that a change which broke it could not pass unnoticed.
    assert!(
        probe(true, Shape::CreateNew),
        "CreateNew/writer-first: the rw-edge into the concurrent creator did not form"
    );
}

#[test]
fn create_new_reader_first_forms_edge_hole_closed_by_683() {
    // Pre-#683 (blanket): FALSE — a genuine phantom hole on the executor's RelIndexSeek path (#659),
    // which registered no predicate marker, and a blanket cannot mark a relationship that does not
    // exist yet. Post-#683: TRUE, closed by the `RelEquality` marker now living inside
    // `rel_index_seek_eq`, matching `create_rel`'s post-image announcement.
    //
    // REGRESSION GUARD: this assertion FAILS on the pre-#683 code. It is the executable proof that
    // #683 closed a pre-existing serializability hole rather than merely relocating markers.
    assert!(
        probe(false, Shape::CreateNew),
        "CreateNew/reader-first: T1 read the ABSENCE of :TRANSFER {{tx_id:'X'}}, T2 then created one, \
         and no rw-edge formed — the absence phantom is not caught"
    );
}

#[test]
fn modify_into_writer_first_forms_edge() {
    // Pre-#683 (blanket): true. Post-#683: true.
    assert!(
        probe(true, Shape::ModifyInto),
        "ModifyInto/writer-first: the rw-edge into the concurrent modifier did not form"
    );
}

#[test]
fn modify_into_reader_first_forms_edge_the_cell_the_blanket_bought() {
    // THE LOAD-BEARING CELL. Pre-#683 this was the ONLY one of the four the `mark_all_live_rels()`
    // blanket actually bought; every other cell held without it. Post-#683 the edge forms precisely,
    // via `set_rel_property`'s post-image `RelEquality{TRANSFER, tx_id, 'X'}` announcement matching the
    // marker `rel_index_seek_eq` registered.
    //
    // If this test fails, the blanket's removal HAS introduced a false negative and #683 is unsound.
    // Do not "fix" it by reintroducing `mark_all_live_rels()` — that would restore the O(live rels)
    // footprint the task exists to remove. Fix the writer-side announcement instead.
    assert!(
        probe(false, Shape::ModifyInto),
        "ModifyInto/reader-first: T1 read the ABSENCE of :TRANSFER {{tx_id:'X'}}, T2 then modified an \
         existing relationship INTO 'X', and no rw-edge formed — this is the exact phantom the removed \
         blanket used to catch, so its replacement marker is not working"
    );
}
