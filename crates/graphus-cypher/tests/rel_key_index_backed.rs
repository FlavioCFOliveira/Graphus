//! A RELATIONSHIP KEY / composite relationship-uniqueness insert takes an index **point lookup**, not
//! `scan_rel_ids()` (`rmp` #683 AC1/AC2).
//!
//! # The defect this pins
//!
//! `enforce_constraints_for_rel` dispatches `RelKey` on **kind, not arity**, so an arity-1 REL KEY on
//! `TRANSFER.tx_id` routed to `rel_key_tuple_conflict` -> `scan_rel_ids()` — re-reading and
//! SIREAD-marking **every live relationship in the graph** (type-filtered only afterwards) — and never
//! reached the index-backed `rel_index_seek_eq` (`rmp` #646). Measured before the fix: ~2 SSI markers
//! per live relationship per keyed write, linear across three decades (2,008 markers at 1e3 live rels;
//! 200,008 at 1e5), and a real-server p50 of 12ms -> 44ms -> 474ms from 1e3 to 1e5 live rels against a
//! flat 5ms with no constraint.
//!
//! # How this is measured without a probe build
//!
//! The SSI read-set size is the mechanical witness: the scan marks O(live rels), the point lookup marks
//! O(candidates). We do not need to count markers directly — we can observe the *consequence* that
//! matters, which is the abort rate among concurrent writers of DISTINCT values. With the scan every
//! pair of concurrent writers conflicts (each marks the other's relationship); with the point lookup
//! plus the precise `RelEquality` marker, writers of distinct values share no marker at all.
//!
//! `bounded_footprint_abort_rate_is_independent_of_live_rel_count` is the load-bearing assertion: it
//! scales the live-relationship count by 10x and requires the outcome not to change. On the pre-#683
//! code the same shape aborts.

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

/// Seeds `n` committed `:TRANSFER` relationships with distinct `tx_id`s, between committed endpoints.
fn seed_transfers(coord: &mut Coord, n: usize) {
    run_write_committed(coord, "CREATE (:Src), (:Dst)");
    for i in 0..n {
        run_write_committed(
            coord,
            &format!("MATCH (s:Src), (d:Dst) CREATE (s)-[:TRANSFER {{tx_id: 'seed{i}'}}]->(d)"),
        );
    }
}

/// As [`seed_transfers`], but every seeded relationship also carries a `leg` — required before a
/// composite `(tx_id, leg)` REL KEY can be declared, since a REL KEY's **existence** half rejects any
/// existing relationship missing a covered property (correctly: the DDL refuses non-conforming data).
fn seed_transfers_with_leg(coord: &mut Coord, n: usize) {
    run_write_committed(coord, "CREATE (:Src), (:Dst)");
    for i in 0..n {
        run_write_committed(
            coord,
            &format!(
                "MATCH (s:Src), (d:Dst) CREATE (s)-[:TRANSFER {{tx_id: 'seed{i}', leg: {i}}}]->(d)"
            ),
        );
    }
}

fn create_rel_key(coord: &mut Coord, name: &str, properties: &[&str]) {
    coord
        .create_constraint_general(name, "TRANSFER", properties, ConstraintKind::RelKey, None)
        .expect("create REL KEY over conforming data");
}

// =================================================================================================
// AC1 — the point lookup is taken, with a NON-VACUITY CONTROL.
// =================================================================================================

/// THREE concurrent writers of DISTINCT `tx_id`s under an arity-1 REL KEY must NOT conflict.
///
/// Before #683 the enforcement scan re-read every live relationship — including the other writers'
/// uncommitted, INVISIBLE ones, because `rel_data` SIREAD-marks BEFORE the visibility filter — closing
/// rw-edges between transactions that share nothing semantically. Measured on the pre-#683 code with
/// this exact shape: 1 of 3 aborted.
///
/// THREE writers, not two, and the distinction is load-bearing. The pre-#683 physical marking is
/// **asymmetric**: only the *later* scanner marks the *earlier* writer's relationship, so two writers
/// produce exactly ONE rw-edge — which is not a dangerous structure, so nothing aborts and a
/// two-writer version of this test would pass on the pre-#683 code **for the wrong reason** (see
/// `control_...`, which proves that same asymmetry let a genuine DUPLICATE commit). A third writer
/// creates the in+out pair a pivot needs, so the pre-#683 code aborts here and this assertion has
/// teeth.
#[test]
fn concurrent_rel_key_writers_of_distinct_values_do_not_conflict() {
    let mut coord = fresh_coord();
    seed_transfers(&mut coord, 20);
    create_rel_key(&mut coord, "tx_key", &["tx_id"]);

    let txns: Vec<_> = (0..3).map(|_| coord.begin_serializable()).collect();
    for (i, &t) in txns.iter().enumerate() {
        let (_r, e) = run_stmt(
            &coord,
            t,
            &format!(
                "MATCH (s:Src), (d:Dst) CREATE (s)-[:TRANSFER {{tx_id: 'distinct_{i}'}}]->(d)"
            ),
        );
        assert!(e.is_none(), "t{i} write-time check: {e:?}");
    }
    let results: Vec<_> = txns.into_iter().map(|t| coord.commit(t)).collect();
    let committed = results.iter().filter(|r| r.is_ok()).count();
    assert_eq!(
        committed, 3,
        "three concurrent REL KEY writers of DISTINCT values share no predicate marker and must ALL \
         commit; an abort here means the O(live rels) scan footprint is back: {results:?}"
    );
}

/// NON-VACUITY CONTROL for the test above: the identical shape with the SAME value MUST still be
/// caught. Without this, `do_not_conflict` could pass simply because enforcement stopped working.
///
/// # This cell also pins a CRITICAL pre-existing bug that #683 fixes (measured, not argued)
///
/// On the pre-#683 code this assertion FAILS, and not marginally: both transactions commit
/// (`c1=Ok`, `c2=Ok`, no statement-time error) and the graph ends with **two** relationships holding
/// `tx_id='SAME'` under a **declared RELATIONSHIP KEY** — a committed violation of a declared
/// invariant, i.e. corrupt data.
///
/// Why it was broken: an arity-1 `RelKey` dispatched to `rel_key_tuple_conflict` -> `scan_rel_ids()`,
/// a path that registers **no predicate marker at all**. Its only SSI evidence was the *physical*
/// scan marking, which is **asymmetric** — only the later scanner marks the earlier writer's
/// relationship — so exactly ONE rw-edge forms, one rw-edge is not a dangerous structure, no pivot is
/// detected, and both writers commit the duplicate. (`RelUnique` escaped this only because it
/// registered the coarse `RelType(T)` predicate read, which IS symmetric: both writers register it and
/// both `create_rel`s announce it, so mutual edges form and one aborts.)
///
/// #683's per-component `RelEquality` marker is symmetric in the same way, which is what restores the
/// guarantee.
#[test]
fn control_concurrent_rel_key_writers_of_the_same_value_still_abort_exactly_one() {
    let mut coord = fresh_coord();
    seed_transfers(&mut coord, 20);
    create_rel_key(&mut coord, "tx_key", &["tx_id"]);

    let t1 = coord.begin_serializable();
    let t2 = coord.begin_serializable();

    let (_r, e1) = run_stmt(
        &coord,
        t1,
        "MATCH (s:Src), (d:Dst) CREATE (s)-[:TRANSFER {tx_id: 'SAME'}]->(d)",
    );
    assert!(
        e1.is_none(),
        "t1 passes its own check (t2 invisible): {e1:?}"
    );
    let (_r, e2) = run_stmt(
        &coord,
        t2,
        "MATCH (s:Src), (d:Dst) CREATE (s)-[:TRANSFER {tx_id: 'SAME'}]->(d)",
    );
    assert!(
        e2.is_none(),
        "t2 passes its own check (t1 invisible): {e2:?}"
    );

    let c1 = coord.commit(t1);
    let c2 = coord.commit(t2);
    let committed = [&c1, &c2].iter().filter(|r| r.is_ok()).count();
    assert_eq!(
        committed, 1,
        "NON-VACUITY CONTROL FAILED: exactly one concurrent identical-key CREATE may commit — a \
         committed duplicate REL KEY is a critical constraint violation (c1={c1:?}, c2={c2:?})"
    );

    // And the surviving graph holds exactly one 'SAME'.
    let t = coord.begin_serializable();
    let (rows, _e) = run_stmt(
        &coord,
        t,
        "MATCH ()-[r:TRANSFER]->() WHERE r.tx_id = 'SAME' RETURN count(r) AS c",
    );
    coord.commit(t).expect("count commits");
    assert_eq!(
        rows[0].value("c"),
        Value::Integer(1),
        "no duplicate REL KEY may survive"
    );
}

// =================================================================================================
// AC2 — the footprint is bounded: independent of the live-relationship count.
// =================================================================================================

/// The SSI footprint of a keyed-relationship write is O(props), not O(live rels).
///
/// Mechanical witness: scale the live-relationship count 10x and require the concurrency outcome to be
/// unchanged. With the pre-#683 scan footprint every live relationship is another shared SIREAD marker
/// between the writers, so they conflict at BOTH sizes; with the bounded footprint, at neither.
///
/// THREE writers, for the same reason as above: with two, the pre-#683 asymmetric physical marking
/// forms only one rw-edge and nothing aborts, so the test would pass on the broken code.
#[test]
fn bounded_footprint_abort_rate_is_independent_of_live_rel_count() {
    for live in [20_usize, 200] {
        let mut coord = fresh_coord();
        seed_transfers(&mut coord, live);
        create_rel_key(&mut coord, "tx_key", &["tx_id"]);

        let txns: Vec<_> = (0..3).map(|_| coord.begin_serializable()).collect();
        for (i, &t) in txns.iter().enumerate() {
            let (_r, e) = run_stmt(
                &coord,
                t,
                &format!("MATCH (s:Src), (d:Dst) CREATE (s)-[:TRANSFER {{tx_id: 'v{i}'}}]->(d)"),
            );
            assert!(e.is_none(), "t{i} (live={live}): {e:?}");
        }
        let results: Vec<_> = txns.into_iter().map(|t| coord.commit(t)).collect();
        let committed = results.iter().filter(|r| r.is_ok()).count();
        assert_eq!(
            committed, 3,
            "with {live} live relationships, three distinct-value writers conflicted => the \
             footprint still scales with the live-relationship count: {results:?}"
        );
    }
}

// =================================================================================================
// Composite (arity > 1) REL KEY — the same guarantees over the composite index.
// =================================================================================================

/// Composite REL KEY writers whose tuples share **no** component must not conflict.
///
/// This is the case the per-component marker design actually buys: two `(tx_id, leg)` tuples with
/// nothing in common register disjoint marker sets, so no rw-edge forms.
#[test]
fn composite_rel_key_fully_distinct_tuples_do_not_conflict() {
    let mut coord = fresh_coord();
    seed_transfers_with_leg(&mut coord, 20);
    create_rel_key(&mut coord, "tx_key2", &["tx_id", "leg"]);

    let t1 = coord.begin_serializable();
    let t2 = coord.begin_serializable();
    let (_r, e1) = run_stmt(
        &coord,
        t1,
        "MATCH (s:Src), (d:Dst) CREATE (s)-[:TRANSFER {tx_id: 'A', leg: 1}]->(d)",
    );
    assert!(e1.is_none(), "t1: {e1:?}");
    let (_r, e2) = run_stmt(
        &coord,
        t2,
        "MATCH (s:Src), (d:Dst) CREATE (s)-[:TRANSFER {tx_id: 'B', leg: 2}]->(d)",
    );
    assert!(e2.is_none(), "t2: {e2:?}");
    let (c1, c2) = (coord.commit(t1), coord.commit(t2));
    assert!(
        c1.is_ok() && c2.is_ok(),
        "composite REL KEY writers of tuples sharing NO component register disjoint markers and must \
         BOTH commit (c1={c1:?}, c2={c2:?})"
    );
}

/// DOCUMENTED FALSE POSITIVE: composite writers whose tuples share **one** component DO conflict, and
/// exactly one aborts even though neither is a duplicate.
///
/// This is a deliberate, known cost of **per-component** markers, pinned here so it is a decision on
/// record rather than a surprise. The alternative — a single tuple-shaped marker — would be precise
/// here but would make the writer's footprint **schema-derived**: the writer would have to enumerate
/// the declared constraint rules to know which tuples to announce, opening a DDL/DML race in which a
/// rule the enumeration missed is a **FALSE NEGATIVE** (a committed duplicate). Per-component markers
/// are schema-independent and a sound superset.
///
/// The trade is therefore: extra aborts (throughput) in exchange for never missing a duplicate
/// (correctness). Per the project's correct -> safe -> fast ordering, that is the right way round. It
/// is also bounded — the spurious edge needs a *shared component value* between concurrent writers,
/// not merely a shared type, which is what the pre-#683 `RelType(T)` marker required (every pair of
/// concurrent `:T` writers conflicted).
#[test]
fn composite_rel_key_tuples_sharing_one_component_conflict_documented_false_positive() {
    let mut coord = fresh_coord();
    seed_transfers_with_leg(&mut coord, 20);
    create_rel_key(&mut coord, "tx_key2", &["tx_id", "leg"]);

    let t1 = coord.begin_serializable();
    let t2 = coord.begin_serializable();
    let (_r, e1) = run_stmt(
        &coord,
        t1,
        "MATCH (s:Src), (d:Dst) CREATE (s)-[:TRANSFER {tx_id: 'T', leg: 1}]->(d)",
    );
    assert!(e1.is_none(), "t1: {e1:?}");
    let (_r, e2) = run_stmt(
        &coord,
        t2,
        "MATCH (s:Src), (d:Dst) CREATE (s)-[:TRANSFER {tx_id: 'T', leg: 2}]->(d)",
    );
    assert!(e2.is_none(), "t2: {e2:?}");
    let (c1, c2) = (coord.commit(t1), coord.commit(t2));
    assert_eq!(
        [&c1, &c2].iter().filter(|r| r.is_ok()).count(),
        1,
        "sharing the `tx_id='T'` component marker forms a mutual rw-edge, so exactly one aborts. \
         This is a FALSE POSITIVE (neither tuple duplicates the other) and is the accepted cost of \
         schema-independent per-component markers — see the test doc. If this ever reports 2, the \
         per-component markers stopped being registered and the composite path has lost its \
         duplicate protection (c1={c1:?}, c2={c2:?})"
    );
}

#[test]
fn composite_rel_key_identical_tuples_abort_exactly_one() {
    let mut coord = fresh_coord();
    seed_transfers_with_leg(&mut coord, 20);
    create_rel_key(&mut coord, "tx_key2", &["tx_id", "leg"]);

    // NON-VACUITY CONTROL: identical tuples still abort exactly one.
    let t3 = coord.begin_serializable();
    let t4 = coord.begin_serializable();
    let (_r, e3) = run_stmt(
        &coord,
        t3,
        "MATCH (s:Src), (d:Dst) CREATE (s)-[:TRANSFER {tx_id: 'U', leg: 9}]->(d)",
    );
    assert!(e3.is_none(), "t3: {e3:?}");
    let (_r, e4) = run_stmt(
        &coord,
        t4,
        "MATCH (s:Src), (d:Dst) CREATE (s)-[:TRANSFER {tx_id: 'U', leg: 9}]->(d)",
    );
    assert!(e4.is_none(), "t4: {e4:?}");
    let (c3, c4) = (coord.commit(t3), coord.commit(t4));
    assert_eq!(
        [&c3, &c4].iter().filter(|r| r.is_ok()).count(),
        1,
        "NON-VACUITY CONTROL FAILED: exactly one identical composite REL KEY tuple may commit \
         (c3={c3:?}, c4={c4:?})"
    );
}
