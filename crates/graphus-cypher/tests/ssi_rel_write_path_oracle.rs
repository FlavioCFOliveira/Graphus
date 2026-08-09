//! The **per-write-path** SSI oracle for relationship predicate markers (`rmp` #683 AC3/AC4/AC5/AC6).
//!
//! # What this file checks
//!
//! `rel_index_seek_eq` no longer SIREAD-marks every live relationship. That blanket was what made the
//! relationship seek-then-check safe by brute force; the replacement is a precise `RelEquality` marker
//! pair — a **reader** side (the seek) and a **writer** side that EVERY relationship write path must
//! announce. If any single write path forgets to announce, the marker silently stops matching for that
//! path and SSI misses the anomaly: a **false negative**, the critical failure class.
//!
//! So the guarantee cannot be "the seek registers a marker" — it must be checked **once per write
//! path**. The `GraphAccess` relationship write surface is closed (there is no relationship-type
//! mutation path, so a relationship's type component only changes on create/delete), which makes the
//! following seven paths exhaustive:
//!
//! | # | path                     | Cypher            | image the marker rides on |
//! |---|--------------------------|-------------------|---------------------------|
//! | 1 | `create_rel`             | `CREATE`          | post                      |
//! | 2 | `set_rel_property`       | `SET r.p = v`     | pre + post                |
//! | 3 | `set_rel_property` null  | `SET r.p = null`  | pre                       |
//! | 4 | `remove_rel_property`    | `REMOVE r.p`      | pre  (**H1** fixed here)  |
//! | 5 | `replace_rel_properties` | `SET r = {...}`   | pre  (**H2** fixed here)  |
//! | 6 | `merge_rel_properties`   | `SET r += {...}`  | post (via #2)             |
//! | 7 | `delete_rel`             | `DELETE r`        | pre                       |
//!
//! # Why three transactions, always
//!
//! A single rw-edge is not a dangerous structure — SSI aborts on a **pivot** (a transaction with both
//! an inbound and an outbound rw-edge). A two-transaction test would abort only if BOTH directions
//! happened to form, masking a half-broken fix. Each probe therefore manufactures
//! `T0 --rw--> T1 --rw--> T2` where edge 1 is an independent physical-key SIREAD (T0 reads `anchor.v`,
//! T1 writes it) and **edge 2 is the one under test**. T1 is the pivot and aborts iff edge 2 formed.
//!
//! # What each probe isolates (honesty about redundancy)
//!
//! * **Post-image paths (1, 2, 6)** — the reader seeks a value that matches NOTHING at its snapshot
//!   (`expect_seen = 0`), so no physical marker can exist and the predicate marker is the *only*
//!   possible mechanism. **Fully isolated**: these cells have teeth on the marker itself.
//!
//! * **Pre-image paths (3, 4, 5, 7)** — READ THIS BEFORE TRUSTING THESE CELLS. They use
//!   `expect_seen = 1`: the reader SEES the relationship, so its candidate re-check SIREAD-marks it
//!   physically and the writer's `note_write` closes the edge on its own. **They therefore pass with
//!   or without the pre-image marker** — they are shape/`note_write` checks, NOT isolations of the
//!   pre-image announcement. Do not read a green run here as evidence that the pre-image marker is
//!   load-bearing; it is not, and it is not meant to be (see below).
//!
//!   What they DO have teeth on is `note_write`: cells 4 and 5 (the empty-map variant) FAIL on the
//!   pre-#683 code, because `remove_rel_property` and `replace_rel_properties` did not record the
//!   physical write at all. That is the H1/H2 regression proof, and it is real.
//!
//!   The pre-image marker itself is **deliberate redundancy** (defence-in-depth). Duplicate
//!   protection rides entirely on the POST-image — a duplicate needs two relationships *holding* a
//!   value, while the pre-image announces the value being *left* — so dropping the pre-image could
//!   never admit a duplicate, only a read-then-unmatch write-skew. It is kept because the redundancy
//!   rests on the invariant "every write path calls `note_write`", and that invariant was violated in
//!   two of seven paths until this very cycle. Its cost is gated away wherever it is inert
//!   (`IndexSet::rel_equality_declared`), so the defence is free.

use graphus_core::{GraphusError, TxnId, Value};
use graphus_cypher::ConstraintKind;
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

/// A graph with a standalone `TRANSFER.tx_id` relationship index, an `:Anchor` node, committed
/// endpoints, and one committed `:TRANSFER {tx_id:'Y', leg: 7}` relationship (`b`).
///
/// The index is standalone, NOT a constraint: the write-path uniqueness check would contribute its own
/// predicate read and confound the measurement of the QUERY reader's marker.
fn seeded_coord() -> Coord {
    let mut coord = fresh_coord();
    coord
        .create_rel_property_index_named(Some("ix_tx"), "TRANSFER", "tx_id", false)
        .expect("create rel property index");
    run_write_committed(&mut coord, "CREATE (:Anchor {v: 0})");
    run_write_committed(&mut coord, "CREATE (:Src), (:Dst)");
    run_write_committed(
        &mut coord,
        "MATCH (s:Src), (d:Dst) CREATE (s)-[:TRANSFER {tx_id: 'Y', leg: 7}]->(d)",
    );
    coord
}

fn assert_plans_rel_index_seek(coord: &Coord, src: &str) {
    let rendered = compile(coord, src).root.to_string();
    assert!(
        rendered.contains("RelIndexSeek"),
        "NON-VACUITY CONTROL FAILED: {src:?} did not plan a RelIndexSeek, so this probe would be \
         measuring the scan fallback rather than the seek under test. plan:\n{rendered}"
    );
}

/// Runs the 3-txn pivot probe for one write path.
///
/// * `seek_value` — the value T1's index seek reads.
/// * `expect_seen` — how many relationships T1's seek must match at its snapshot (a NON-VACUITY
///   assertion: it pins that the probe is exercising the shape it claims to).
/// * `write_src` — the concurrent write under test, run AFTER T1's seek (reader-first — the
///   interleaving in which no physical accident can close the edge for a post-image path).
///
/// Returns whether T1 (the pivot) aborted, i.e. whether the edge under test formed.
fn probe(seek_value: &str, expect_seen: i64, write_src: &str) -> bool {
    let coord = seeded_coord();
    let seek_query =
        format!("MATCH ()-[r:TRANSFER]->() WHERE r.tx_id = '{seek_value}' RETURN count(r) AS c");
    assert_plans_rel_index_seek(&coord, &seek_query);

    let t0 = coord.begin_serializable();
    let t1 = coord.begin_serializable();
    let t2 = coord.begin_serializable();

    // Edge 1 (NOT under test): T0 reads `anchor.v`, T1 writes it => T0 --rw--> T1.
    let (_r, e) = run_stmt(&coord, t0, "MATCH (a:Anchor) RETURN a.v AS v");
    assert!(e.is_none(), "t0 read: {e:?}");
    let (_r, e) = run_stmt(&coord, t1, "MATCH (a:Anchor) SET a.v = 1");
    assert!(e.is_none(), "t1 anchor write: {e:?}");

    // T1's seek — the reader whose marker is under test.
    let (rows, e) = run_stmt(&coord, t1, &seek_query);
    assert!(e.is_none(), "t1 seek: {e:?}");
    assert_eq!(
        rows[0].value("c"),
        Value::Integer(expect_seen),
        "probe shape check: T1's seek for '{seek_value}' matched an unexpected number of \
         relationships"
    );

    // T2 performs the write path under test, AFTER T1's seek (reader-first).
    let (_r, e) = run_stmt(&coord, t2, write_src);
    assert!(e.is_none(), "t2 write {write_src:?}: {e:?}");

    let c1 = coord.commit(t1);
    let aborted = c1.is_err();
    if aborted {
        assert!(
            matches!(c1, Err(GraphusError::Transaction(_))),
            "an SSI abort must be a RETRIABLE transaction error: {c1:?}"
        );
    }
    let _ = coord.commit(t2);
    let _ = coord.commit(t0);
    aborted
}

// =================================================================================================
// AC3 — the seven write paths. Each must close the rw-edge into a concurrent predicate reader.
// =================================================================================================

#[test]
fn path1_create_rel_announces_post_image() {
    // T1 reads the ABSENCE of tx_id='X'; T2 CREATEs one. Post-image, fully isolated: no physical
    // marker can exist for a relationship that did not exist when T1 seeked.
    assert!(
        probe(
            "X",
            0,
            "MATCH (s:Src), (d:Dst) CREATE (s)-[:TRANSFER {tx_id: 'X'}]->(d)"
        ),
        "create_rel did not announce its post-image RelEquality marker"
    );
}

#[test]
fn path2_set_rel_property_announces_post_image() {
    // T1 reads the ABSENCE of tx_id='X'; T2 SETs an existing relationship INTO 'X'. Post-image, fully
    // isolated — and this is the exact cell the removed `mark_all_live_rels()` blanket used to cover.
    assert!(
        probe(
            "X",
            0,
            "MATCH ()-[r:TRANSFER]->() WHERE r.tx_id = 'Y' SET r.tx_id = 'X'"
        ),
        "set_rel_property did not announce its post-image RelEquality marker — this is the phantom \
         the blanket used to catch"
    );
}

#[test]
fn path3_set_rel_property_null_announces_pre_image() {
    // T1 SEES tx_id='Y'; T2 clears it with `SET r.tx_id = null`, un-matching it from the predicate.
    assert!(
        probe(
            "Y",
            1,
            "MATCH ()-[r:TRANSFER]->() WHERE r.tx_id = 'Y' SET r.tx_id = null"
        ),
        "set_rel_property(null) left a reader of the vacated (T, p, 'Y') predicate with no rw-edge"
    );
}

#[test]
fn path4_remove_rel_property_announces_pre_image_h1() {
    // H1 REGRESSION GUARD. Before this cycle `remove_rel_property` never called
    // `note_write(rel_ssi_key(..))` — the node twin always has — so `REMOVE r.p` un-matched a
    // relationship from `(T, p, v)` leaving ZERO SSI evidence: a read-then-unmatch write-skew that no
    // reader could detect. This assertion FAILS on the pre-#683 code.
    assert!(
        probe(
            "Y",
            1,
            "MATCH ()-[r:TRANSFER]->() WHERE r.tx_id = 'Y' REMOVE r.tx_id"
        ),
        "H1: REMOVE r.tx_id left a reader of (T, tx_id, 'Y') with no rw-edge — the un-match is \
         invisible to SSI"
    );
}

#[test]
fn path5_replace_rel_properties_announces_pre_image() {
    // `SET r = {leg: 1}` clears tx_id='Y'. NOTE this variant does NOT isolate H2: the map's `leg`
    // entry runs through `set_rel_property`, whose own `note_write` closes the edge even on the
    // pre-#683 code (measured: this passes at HEAD). It is kept as a shape check; the H2 isolation is
    // `path5_replace_rel_properties_with_empty_map_announces_pre_image_h2` below.
    assert!(
        probe(
            "Y",
            1,
            "MATCH ()-[r:TRANSFER]->() WHERE r.tx_id = 'Y' SET r = {leg: 1}"
        ),
        "SET r = {{leg: 1}} cleared tx_id='Y' and left a reader of that predicate with no rw-edge"
    );
}

#[test]
fn path5_replace_rel_properties_with_empty_map_announces_pre_image_h2() {
    // H2 REGRESSION GUARD — the ISOLATING case.
    //
    // Before this cycle `replace_rel_properties` had NEITHER a `note_write` NOR a pre-image
    // announcement; it relied entirely on the per-key `set_rel_property` calls in its re-set loop to
    // record anything at all. With an EMPTY map that loop never runs, so `SET r = {}` cleared the
    // relationship's ENTIRE property set with ZERO SSI evidence — invisible to every concurrent
    // reader.
    //
    // The non-empty variant above cannot see this (its `leg` entry supplies the missing `note_write`
    // by accident), which is exactly why the isolating case is needed. This assertion FAILS on the
    // pre-#683 code.
    assert!(
        probe(
            "Y",
            1,
            "MATCH ()-[r:TRANSFER]->() WHERE r.tx_id = 'Y' SET r = {}"
        ),
        "H2: SET r = {{}} cleared tx_id='Y' with no set_rel_property to record it, and left a reader \
         of that predicate with no rw-edge — the wholesale clear is invisible to SSI"
    );
}

#[test]
fn path6_merge_rel_properties_announces_post_image() {
    // `SET r += map` delegates to `set_rel_property`, so it inherits path 2's markers. Pinned so a
    // future refactor that stops delegating cannot silently drop the announcement.
    assert!(
        probe(
            "X",
            0,
            "MATCH ()-[r:TRANSFER]->() WHERE r.tx_id = 'Y' SET r += {tx_id: 'X'}"
        ),
        "merge_rel_properties did not announce its post-image RelEquality marker"
    );
}

#[test]
fn path7_delete_rel_announces_full_pre_image() {
    // A delete makes the edge stop satisfying every equality predicate it held, so it must announce the
    // FULL pre-image (the coarse pair PLUS one RelEquality per property), before the store mutation
    // while the property chain is still readable.
    assert!(
        probe(
            "Y",
            1,
            "MATCH ()-[r:TRANSFER]->() WHERE r.tx_id = 'Y' DELETE r"
        ),
        "delete_rel left a reader of the deleted edge's (T, tx_id, 'Y') predicate with no rw-edge"
    );
}

// =================================================================================================
// AC4 — the duplicate shape. The anomaly a naive fix admits.
// =================================================================================================

/// `T1 CREATE {tx_id:'X'}` vs `T2 SET b.tx_id = 'X'` under a relationship-uniqueness constraint.
///
/// Neither writer can see the other under MVCC, so each passes its own write-time check: T1 excludes
/// its own new edge and sees only `b@'Y'`; T2 excludes `b` as self and cannot see T1's edge. **Both
/// would commit 'X' — a duplicate.**
///
/// This cannot be rescued by index-candidate overlap: if T1's seek runs before T2's `reindex_rel`
/// inserts `b -> 'X'`, `b` is not a candidate and T1 marks nothing. Only the post-image
/// `RelEquality{TRANSFER, tx_id, 'X'}` announced by **both** sides closes the edges.
///
/// The assertion is the ACID property itself: no duplicate may survive.
#[test]
fn duplicate_shape_create_vs_set_never_commits_a_duplicate() {
    let mut coord = fresh_coord();
    run_write_committed(&mut coord, "CREATE (:Src), (:Dst)");
    run_write_committed(
        &mut coord,
        "MATCH (s:Src), (d:Dst) CREATE (s)-[:TRANSFER {tx_id: 'Y'}]->(d)",
    );
    coord
        .create_constraint_general(
            "uniq_tx",
            "TRANSFER",
            &["tx_id"],
            ConstraintKind::RelUnique,
            None,
        )
        .expect("create rel uniqueness constraint");

    let t1 = coord.begin_serializable();
    let t2 = coord.begin_serializable();

    let (_r, e1) = run_stmt(
        &coord,
        t1,
        "MATCH (s:Src), (d:Dst) CREATE (s)-[:TRANSFER {tx_id: 'X'}]->(d)",
    );
    assert!(
        e1.is_none(),
        "t1 passes its own write-time check (it sees only b@'Y'): {e1:?}"
    );
    let (_r, e2) = run_stmt(
        &coord,
        t2,
        "MATCH ()-[r:TRANSFER]->() WHERE r.tx_id = 'Y' SET r.tx_id = 'X'",
    );
    assert!(
        e2.is_none(),
        "t2 passes its own write-time check (T1's edge is invisible to it): {e2:?}"
    );

    let c1 = coord.commit(t1);
    let c2 = coord.commit(t2);
    assert_eq!(
        [&c1, &c2].iter().filter(|r| r.is_ok()).count(),
        1,
        "exactly one of the two 'X' writers may commit (c1={c1:?}, c2={c2:?})"
    );

    // The ACID assertion: whatever committed, no duplicate 'X' exists.
    let t = coord.begin_serializable();
    let (rows, _e) = run_stmt(
        &coord,
        t,
        "MATCH ()-[r:TRANSFER]->() WHERE r.tx_id = 'X' RETURN count(r) AS c",
    );
    coord.commit(t).expect("count commits");
    assert_eq!(
        rows[0].value("c"),
        Value::Integer(1),
        "A COMMITTED DUPLICATE relationship-uniqueness value survived — this is a critical ACID \
         defect, not a performance regression"
    );
}

// =================================================================================================
// AC5 — the Cypher-equality-canonical twin.
// =================================================================================================

/// A reader of `{tx_id: 1}` and a writer of `{tx_id: 1.0}` must close the rw-edge.
///
/// `1` and `1.0` are **Cypher-equal**, so they are the same predicate. The order-preserving index
/// encoding (`encode_single`) tags `Integer(1)` and `Float(1.0)` apart, so encoding the marker with it
/// would make the reader and the writer register DIFFERENT markers — the edge would never close and no
/// same-type test could ever catch it (`rmp` #171 blocker C1). Both sides must use
/// `encode_equality_canonical`.
#[test]
fn cross_type_numeric_reader_int_writer_float_closes_the_edge() {
    let mut coord = fresh_coord();
    coord
        .create_rel_property_index_named(Some("ix_tx"), "TRANSFER", "tx_id", false)
        .expect("create rel property index");
    run_write_committed(&mut coord, "CREATE (:Anchor {v: 0})");
    run_write_committed(&mut coord, "CREATE (:Src), (:Dst)");
    run_write_committed(
        &mut coord,
        "MATCH (s:Src), (d:Dst) CREATE (s)-[:TRANSFER {tx_id: 99}]->(d)",
    );

    const SEEK: &str = "MATCH ()-[r:TRANSFER]->() WHERE r.tx_id = 1 RETURN count(r) AS c";
    assert_plans_rel_index_seek(&coord, SEEK);

    let t0 = coord.begin_serializable();
    let t1 = coord.begin_serializable();
    let t2 = coord.begin_serializable();

    let (_r, e) = run_stmt(&coord, t0, "MATCH (a:Anchor) RETURN a.v AS v");
    assert!(e.is_none(), "t0: {e:?}");
    let (_r, e) = run_stmt(&coord, t1, "MATCH (a:Anchor) SET a.v = 1");
    assert!(e.is_none(), "t1 anchor: {e:?}");

    // T1 reads the INTEGER predicate `tx_id = 1` and sees nothing.
    let (rows, e) = run_stmt(&coord, t1, SEEK);
    assert!(e.is_none(), "t1 seek: {e:?}");
    assert_eq!(rows[0].value("c"), Value::Integer(0), "T1 must see nothing");

    // T2 writes the FLOAT 1.0 — Cypher-equal to 1, so it satisfies T1's predicate.
    let (_r, e) = run_stmt(
        &coord,
        t2,
        "MATCH (s:Src), (d:Dst) CREATE (s)-[:TRANSFER {tx_id: 1.0}]->(d)",
    );
    assert!(e.is_none(), "t2 create 1.0: {e:?}");

    let c1 = coord.commit(t1);
    assert!(
        c1.is_err(),
        "a reader of {{tx_id: 1}} and a writer of {{tx_id: 1.0}} registered different markers, so \
         the cross-type numeric phantom rw-edge never closed (`rmp` #171 blocker C1). The marker is \
         almost certainly being encoded with the order-preserving index key instead of \
         encode_equality_canonical. c1={c1:?}"
    );
    let _ = coord.commit(t2);
    let _ = coord.commit(t0);
}

/// The writer/reader roles swapped: a reader of `{tx_id: 1.0}` and a writer of `{tx_id: 1}`.
#[test]
fn cross_type_numeric_reader_float_writer_int_closes_the_edge() {
    let mut coord = fresh_coord();
    coord
        .create_rel_property_index_named(Some("ix_tx"), "TRANSFER", "tx_id", false)
        .expect("create rel property index");
    run_write_committed(&mut coord, "CREATE (:Anchor {v: 0})");
    run_write_committed(&mut coord, "CREATE (:Src), (:Dst)");
    run_write_committed(
        &mut coord,
        "MATCH (s:Src), (d:Dst) CREATE (s)-[:TRANSFER {tx_id: 99}]->(d)",
    );

    const SEEK: &str = "MATCH ()-[r:TRANSFER]->() WHERE r.tx_id = 1.0 RETURN count(r) AS c";
    assert_plans_rel_index_seek(&coord, SEEK);

    let t0 = coord.begin_serializable();
    let t1 = coord.begin_serializable();
    let t2 = coord.begin_serializable();

    let (_r, e) = run_stmt(&coord, t0, "MATCH (a:Anchor) RETURN a.v AS v");
    assert!(e.is_none(), "t0: {e:?}");
    let (_r, e) = run_stmt(&coord, t1, "MATCH (a:Anchor) SET a.v = 1");
    assert!(e.is_none(), "t1 anchor: {e:?}");
    let (rows, e) = run_stmt(&coord, t1, SEEK);
    assert!(e.is_none(), "t1 seek: {e:?}");
    assert_eq!(rows[0].value("c"), Value::Integer(0), "T1 must see nothing");

    let (_r, e) = run_stmt(
        &coord,
        t2,
        "MATCH (s:Src), (d:Dst) CREATE (s)-[:TRANSFER {tx_id: 1}]->(d)",
    );
    assert!(e.is_none(), "t2 create 1: {e:?}");

    let c1 = coord.commit(t1);
    assert!(
        c1.is_err(),
        "a reader of {{tx_id: 1.0}} and a writer of {{tx_id: 1}} did not close the rw-edge: {c1:?}"
    );
    let _ = coord.commit(t2);
    let _ = coord.commit(t0);
}

/// The index seek's cross-type probe (`rmp` #466) and the marker's canonical encoding
/// (`rmp` #171 blocker C1) must agree on what "Cypher-equal" means.
///
/// Two independent mechanisms have to line up for a numeric predicate to be correct end-to-end:
///   * `PropertyIndex::seek_eq` probes the Cypher-equal cross-type **sibling** (`numeric_equal_probes`)
///     and unions the matches, so seeking `1` finds a relationship stored as `1.0` (#466); and
///   * the SSI marker encodes with `encode_equality_canonical`, so a reader of `1` and a writer of
///     `1.0` register byte-identical markers (#171 C1).
///
/// If those two disagreed — e.g. if the seek probed cross-type but the marker did not — a numeric
/// predicate would silently read rows it could not be woken for.
///
/// `expect_seen = 1` is the assertion that pins the #466 probe: the seeded relationship holds `1.0`
/// and the reader seeks `1`, so it MUST be found. (A previous draft of this cell asserted
/// `expect_seen = 0` on the theory that the seek is byte-exact and misses the sibling. That theory is
/// false — `seek_eq` at `kinds.rs` probes the sibling — and asserting 0 would have pinned BROKEN
/// behaviour as if it were desired. Verified against the implementation, not assumed.)
///
/// NON-VACUITY: the writer creates a **different, brand-new** relationship, so the edge under test
/// cannot come from the physical marker on the seeded one — only from the predicate marker.
#[test]
fn cross_type_seek_probe_and_marker_encoding_agree() {
    let mut coord = fresh_coord();
    coord
        .create_rel_property_index_named(Some("ix_tx"), "TRANSFER", "tx_id", false)
        .expect("create rel property index");
    run_write_committed(&mut coord, "CREATE (:Anchor {v: 0})");
    run_write_committed(&mut coord, "CREATE (:Src), (:Dst)");
    // The seed holds the FLOAT 1.0.
    run_write_committed(
        &mut coord,
        "MATCH (s:Src), (d:Dst) CREATE (s)-[:TRANSFER {tx_id: 1.0}]->(d)",
    );

    // The reader seeks the INTEGER 1.
    const SEEK: &str = "MATCH ()-[r:TRANSFER]->() WHERE r.tx_id = 1 RETURN count(r) AS c";
    assert_plans_rel_index_seek(&coord, SEEK);

    let t0 = coord.begin_serializable();
    let t1 = coord.begin_serializable();
    let t2 = coord.begin_serializable();

    let (_r, e) = run_stmt(&coord, t0, "MATCH (a:Anchor) RETURN a.v AS v");
    assert!(e.is_none(), "t0: {e:?}");
    let (_r, e) = run_stmt(&coord, t1, "MATCH (a:Anchor) SET a.v = 1");
    assert!(e.is_none(), "t1 anchor: {e:?}");

    let (rows, e) = run_stmt(&coord, t1, SEEK);
    assert!(e.is_none(), "t1 seek: {e:?}");
    assert_eq!(
        rows[0].value("c"),
        Value::Integer(1),
        "#466 CROSS-TYPE PROBE: seeking the integer 1 must find the relationship stored as the float \
         1.0 — they are Cypher-equal, so this is one predicate, not two"
    );

    // A DIFFERENT, brand-new relationship also satisfying the predicate (as the integer 1 this time).
    let (_r, e) = run_stmt(
        &coord,
        t2,
        "MATCH (s:Src), (d:Dst) CREATE (s)-[:TRANSFER {tx_id: 1}]->(d)",
    );
    assert!(e.is_none(), "t2 create: {e:?}");

    let c1 = coord.commit(t1);
    assert!(
        c1.is_err(),
        "#171-C1 MARKER ENCODING: the reader of `tx_id = 1` gained no rw-edge into a concurrent \
         creator of a Cypher-equal relationship. The seek and the marker disagree on numeric \
         equality. c1={c1:?}"
    );
    let _ = coord.commit(t2);
    let _ = coord.commit(t0);
}
