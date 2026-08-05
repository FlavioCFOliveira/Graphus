//! **Statement-level isolation** (`04 §5.1.4`, `rmp` task #972): a statement reads the graph as it
//! stood when the statement started, and writes into the graph as it stands now.
//!
//! # The mechanism under test
//!
//! Every undo delta carries the `command_id` of the statement that produced it. A read carries a
//! [`View`]: under `New` it sees everything its own transaction has written, under `Old` it sees
//! everything *except* what the **current** statement wrote. The executor installs `Old` around the
//! reads whose openCypher semantics owe it (scans, every index seek, expansions, `WHERE`, `UNWIND`)
//! and leaves `New` everywhere else (`CREATE`/`SET`/`DELETE`/`REMOVE`/`FOREACH`, the `MERGE` match,
//! `RETURN`/`WITH`, aggregation, `ORDER BY`/`SKIP`/`LIMIT`).
//!
//! # Why the eagerness barriers do not make these tests vacuous
//!
//! The planner also inserts `Eager` barriers at several of these clause boundaries, and `Eager`
//! independently fixes some of the same symptoms. The two mechanisms are deliberately kept side by
//! side (`rmp` #972 section E), so a green result here is **not** by itself proof that the command
//! isolation is doing the work — the shadowing-the-primary-control trap.
//!
//! Each test below was therefore run against a **deliberately broken** engine, one mechanism at a
//! time, and the measured outcome is recorded here. The three mutations:
//!
//! * **A — every scan and seek forced back to `New`** (`leaf_read_view` returns `New`).
//!   Only [`the_decision_table_is_what_the_plan_executes`] fails. That is the honest result: the
//!   `Eager` barriers do mask the Halloween *counts*, which is precisely why this file's proof of the
//!   leaf polarity is the recorded-view test and not a row count.
//! * **B — the `WITH` never advances the command.**
//!   [`a_with_after_a_write_opens_the_next_statement`] fails with **6** instead of 10,
//!   [`a_with_filter_after_a_set_reads_the_new_values`] with `[3, 5]` instead of `[2, 4, 6]`, and
//!   [`an_index_seek_and_a_scan_agree_after_a_write_in_the_same_statement`] with 1 row instead of 2.
//!   No barrier can produce these numbers: they are visibility, not row production.
//! * **C — the view is never restored after a scoped switch.**
//!   Five tests fail, including [`a_return_after_a_write_still_sees_the_write`] and
//!   [`the_right_hand_side_of_a_set_composes_across_repeated_matches`] (`11` instead of `14`).
//! * **D — a named path reconstructed under `Old`** (the reading this task tried first, and the one
//!   the TCK rejected). [`a_path_bound_over_a_same_statement_creation_is_oriented_correctly`] fails
//!   with the path ending at node `1` instead of node `2`, and the recorded-view test names the
//!   operator.
//!
//! So the tests split into **evidence** (the recorded-view test, and everything that moved under B
//! or C) and **guards** (the Halloween counts, which hold under either mechanism and exist to stop a
//! future change from removing *both*). Each is what it is; none is presented as more.
//!
//! # Sources
//!
//! The polarity table is Memgraph's (`src/query/plan/operator.cpp`, `rule_based_planner.cpp`); the
//! row counts are openCypher TCK scenarios, cited per test.

use std::cell::RefCell;
use std::collections::BTreeMap;

use graphus_core::Value;
use graphus_cypher::binding::{Parameters, bind_parameters};
use graphus_cypher::catalog::IndexCatalog;
use graphus_cypher::coordinator::TxnCoordinator;
use graphus_cypher::executor::execute;
use graphus_cypher::graph_access::{
    CompositeSeekHits, ExpandDirection, GraphAccess, Incident, IndexSeekHits, KeyValues, MemGraph,
    NodeId, RelData, RelId, ScanFilter,
};
use graphus_cypher::lexer::tokenize;
use graphus_cypher::lower::lower;
use graphus_cypher::parser::parse_tokens;
use graphus_cypher::physical::{PhysicalOp, PhysicalPlan, plan_physical};
use graphus_cypher::runtime::{Row, RowValue};
use graphus_cypher::semantics::analyze;
use graphus_cypher::{QueryCounters, View};
use graphus_io::MemBlockDevice;
use graphus_storage::RecordStore;
use graphus_wal::{MemLogSink, WalManager};

type Coord = TxnCoordinator<MemBlockDevice, MemLogSink>;

// =================================================================================================
// Harness — the production coordinator path
// =================================================================================================

fn fresh_coord() -> Coord {
    let device = MemBlockDevice::new(0);
    let wal = WalManager::create(MemLogSink::new()).expect("wal");
    TxnCoordinator::new(RecordStore::create(device, wal, 64, 1).expect("store"))
}

fn compile(src: &str, catalog: &IndexCatalog) -> PhysicalPlan {
    let toks = tokenize(src).expect("lex");
    let ast = parse_tokens(&toks, src).expect("parse");
    let validated = analyze(&ast).expect("analyze");
    plan_physical(&lower(&validated), catalog).with_prefix(ast.prefix())
}

/// One statement in its own committed transaction: the rows it produced and the side-effect counters
/// it accumulated. Panics if the seam captured a storage error (a swallowed fault would make every
/// count below meaningless).
fn run(coord: &mut Coord, src: &str, catalog: &IndexCatalog) -> (Vec<Row>, QueryCounters) {
    let plan = compile(src, catalog);
    let bound = bind_parameters(&plan, &Parameters::new()).expect("bind");
    let txn = coord.begin_serializable();
    let out = {
        let mut graph = coord.statement(txn).expect("statement");
        let rows = {
            let mut cursor = execute(&plan, &bound, &mut graph).expect("open");
            cursor.collect_all().expect("collect")
        };
        let counters = graph.write_counters();
        assert!(
            graph.take_error().is_none(),
            "`{src}` captured a storage error"
        );
        (rows, counters)
    };
    coord.commit(txn).expect("commit");
    out
}

/// Runs `src` and returns only its side-effect counters.
fn counters(coord: &mut Coord, src: &str) -> QueryCounters {
    run(coord, src, &IndexCatalog::empty()).1
}

/// Runs `src` purely for its effect (seeding), discarding the counters.
fn seed(coord: &mut Coord, src: &str) {
    let _ = counters(coord, src);
}

/// Runs `src` and returns only its rows.
fn rows(coord: &mut Coord, src: &str, catalog: &IndexCatalog) -> Vec<Row> {
    run(coord, src, catalog).0
}

/// The rows as an order-independent multiset of `column -> Value` maps, so two plans (index vs scan)
/// can be compared without depending on emission order.
fn bag(rows: &[Row]) -> Vec<BTreeMap<String, Value>> {
    let mut out: Vec<BTreeMap<String, Value>> = rows
        .iter()
        .map(|r| {
            r.columns()
                .iter()
                .cloned()
                .zip(r.values().iter().map(|v| match v {
                    RowValue::Value(v) => v.clone(),
                    other => panic!("expected a property-value column, got {other:?}"),
                }))
                .collect()
        })
        .collect();
    out.sort_by(|a, b| format!("{a:?}").cmp(&format!("{b:?}")));
    out
}

/// Whether the plan reaches the graph through a genuine **property-index** access path (the
/// non-vacuity witness for the "an index must not change the answer" tests).
///
/// `NodeLabelScanEq` is deliberately NOT in this list: it is a label scan with a fused equality
/// residual and the planner emits it against an EMPTY catalog too, so counting it would make the
/// "no index here" half of every comparison fail — and, worse, would let a future version that
/// silently stopped seeking still read as a pass.
fn uses_index(plan: &PhysicalPlan) -> bool {
    fn walk(op: &PhysicalOp) -> bool {
        let here = matches!(
            op,
            PhysicalOp::NodeIndexSeek { .. }
                | PhysicalOp::NodeIndexMultiSeek { .. }
                | PhysicalOp::NodeIndexRangeSeek { .. }
                | PhysicalOp::NodeIndexScan { .. }
                | PhysicalOp::NodeCompositeIndexSeek { .. }
                | PhysicalOp::NodeIndexStartsWithSeek { .. }
                | PhysicalOp::NodeTextIndexSeek { .. }
        );
        here || op.children().iter().any(|c| walk(c))
    }
    walk(&plan.root)
}

/// The `num` column of every row, sorted.
fn sorted_ints(rows: &[Row], col: &str) -> Vec<i64> {
    let mut out: Vec<i64> = rows
        .iter()
        .map(|r| match r.get(col) {
            Some(RowValue::Value(Value::Integer(n))) => *n,
            other => panic!("column `{col}` is not an integer: {other:?}"),
        })
        .collect();
    out.sort_unstable();
    out
}

// =================================================================================================
// 1. The Halloween problem — a scan must not see the rows the same statement creates
// =================================================================================================

/// `MATCH (n:N) CREATE (:N)` over `k` nodes creates **exactly `k`** nodes and terminates.
///
/// This is the canonical Halloween anomaly: without statement isolation the scan re-reads the nodes
/// its own `CREATE` is adding, and the query either creates `2^k`-ish nodes or never finishes.
#[test]
fn a_scan_does_not_see_the_nodes_its_own_statement_creates() {
    for k in [1_u64, 2, 5, 17] {
        let mut coord = fresh_coord();
        for _ in 0..k {
            seed(&mut coord, "CREATE (:N)");
        }
        let c = counters(&mut coord, "MATCH (n:N) CREATE (:N)");
        assert_eq!(
            c.nodes_created, k,
            "a scan over {k} nodes must drive exactly {k} creations, not {}",
            c.nodes_created
        );
        // And the graph really holds 2k nodes afterwards — the counter and the store agree.
        let after = rows(
            &mut coord,
            "MATCH (n:N) RETURN count(n) AS c",
            &IndexCatalog::empty(),
        );
        assert_eq!(
            after[0].get("c"),
            Some(&RowValue::Value(Value::Integer(2 * k as i64))),
            "the store must hold exactly 2 * {k} nodes"
        );
    }
}

/// The same anomaly through a **relationship** scan: `MATCH ()-[r:T]->() CREATE ()-[:T]->()` over
/// `k` edges creates exactly `k` edges.
#[test]
fn a_relationship_scan_does_not_see_the_edges_its_own_statement_creates() {
    let mut coord = fresh_coord();
    for _ in 0..4 {
        seed(&mut coord, "CREATE (:A)-[:T]->(:B)");
    }
    let c = counters(&mut coord, "MATCH ()-[r:T]->() CREATE (:A)-[:T]->(:B)");
    assert_eq!(
        c.relationships_created, 4,
        "the relationship scan re-read the edges it was creating"
    );
}

// =================================================================================================
// 2. The Halloween problem under an index — and the index must not change the answer
// =================================================================================================

/// `MATCH (n:N) WHERE n.v = 1 SET n.v = n.v + 1` increments each matching node **exactly once**,
/// and returns the identical bag with and without an index on `:N(v)`.
///
/// # Why the bag comparison is the load-bearing half
///
/// The seek half of an index access path yields a *candidate* superset that must be re-verified per
/// candidate under the reader's own view. If the re-verification ran under `New` while the scan
/// fallback ran under `Old`, `CREATE INDEX` would change the answer — the `index-changes-the-answer`
/// defect class (`rmp` #738, #894). Comparing the two bags is the only way to catch it, because each
/// plan on its own looks perfectly consistent.
#[test]
fn an_update_matching_its_own_new_value_applies_once_with_and_without_an_index() {
    const SRC: &str = "MATCH (n:N) WHERE n.v = 1 SET n.v = n.v + 1";
    const READBACK: &str = "MATCH (n:N) RETURN n.v AS v";

    // --- scan path ---------------------------------------------------------------------------
    let mut scan_coord = fresh_coord();
    for _ in 0..6 {
        seed(&mut scan_coord, "CREATE (:N {v: 1})");
    }
    let empty = IndexCatalog::empty();
    assert!(
        !uses_index(&compile(SRC, &empty)),
        "NON-VACUITY: the empty-catalog plan must not use an index"
    );
    let scan_counters = counters(&mut scan_coord, SRC);
    let scan_bag = bag(&rows(&mut scan_coord, READBACK, &empty));

    // --- index path --------------------------------------------------------------------------
    let mut idx_coord = fresh_coord();
    for _ in 0..6 {
        seed(&mut idx_coord, "CREATE (:N {v: 1})");
    }
    idx_coord
        .create_node_property_index("N", "v")
        .expect("create index");
    let cat = idx_coord.catalog();
    assert!(
        uses_index(&compile(SRC, &cat)),
        "NON-VACUITY: the indexed plan must reach the graph through an index operator, else this \
         test compares the scan path against itself:\n{}",
        compile(SRC, &cat)
    );
    let idx_counters = {
        let plan = compile(SRC, &cat);
        let bound = bind_parameters(&plan, &Parameters::new()).expect("bind");
        let txn = idx_coord.begin_serializable();
        let c = {
            let mut graph = idx_coord.statement(txn).expect("statement");
            {
                let mut cursor = execute(&plan, &bound, &mut graph).expect("open");
                cursor.collect_all().expect("collect");
            }
            let c = graph.write_counters();
            assert!(
                graph.take_error().is_none(),
                "indexed run captured an error"
            );
            c
        };
        idx_coord.commit(txn).expect("commit");
        c
    };
    let idx_bag = bag(&rows(&mut idx_coord, READBACK, &cat));

    // --- the assertions ------------------------------------------------------------------------
    assert_eq!(
        scan_counters.properties_set, 6,
        "each of the 6 nodes must be updated exactly once on the scan path"
    );
    assert_eq!(
        idx_counters.properties_set, 6,
        "each of the 6 nodes must be updated exactly once on the index path"
    );
    assert_eq!(
        scan_bag,
        vec![BTreeMap::from([("v".to_owned(), Value::Integer(2))]); 6],
        "every node must end at 2, not at 3+ (a re-matched increment)"
    );
    assert_eq!(
        idx_bag, scan_bag,
        "CREATE INDEX changed the answer: the index path and the scan path disagree"
    );
}

/// The read side of the same property: an indexed seek and the scan fallback must return the
/// identical bag **within a statement that has already written**, which is where the two views can
/// actually diverge.
#[test]
fn an_index_seek_and_a_scan_agree_after_a_write_in_the_same_statement() {
    // `CREATE ... WITH * MATCH ...`: the `WITH` advances the command, so the second match DOES see
    // the created node under either view — but the two paths must agree about that, and about the
    // node the second `MATCH`'s own clause could otherwise re-read.
    const SRC: &str = "CREATE (:N {v: 7}) WITH * MATCH (m:N) WHERE m.v = 7 RETURN m.v AS v";

    let mut scan_coord = fresh_coord();
    seed(&mut scan_coord, "CREATE (:N {v: 7})");
    let empty = IndexCatalog::empty();
    let scan_bag = bag(&rows(&mut scan_coord, SRC, &empty));

    let mut idx_coord = fresh_coord();
    seed(&mut idx_coord, "CREATE (:N {v: 7})");
    idx_coord
        .create_node_property_index("N", "v")
        .expect("create index");
    let cat = idx_coord.catalog();
    assert!(
        uses_index(&compile(SRC, &cat)),
        "NON-VACUITY: the indexed plan must use an index operator"
    );
    let idx_bag = bag(&rows(&mut idx_coord, SRC, &cat));

    assert_eq!(
        idx_bag, scan_bag,
        "CREATE INDEX changed the answer of a write-then-read statement"
    );
    assert_eq!(
        scan_bag.len(),
        2,
        "both the seeded and the created node match"
    );
}

// =================================================================================================
// 3. A `WITH` after a write opens the next statement
// =================================================================================================

/// `MATCH () CREATE () WITH * MATCH () CREATE ()` over 2 nodes creates **10** nodes.
///
/// openCypher TCK `clauses/create/Create3.feature` \[3\] ("Create a pattern with multiple hops"
/// family — the nested-create counting scenario). The arithmetic:
///
/// * the first `MATCH ()` sees 2 nodes and creates 2 → the graph holds 4, of which the first
///   statement's own creations are invisible to *it*;
/// * the `WITH` **advances the command**, so the second `MATCH ()` starts a new statement and sees
///   all 4;
/// * 2 driving rows × 4 matches = 8 more creations. Total **10**.
///
/// NON-VACUITY: without the advance the second `MATCH` would still be at the first statement's
/// command and would see only the original 2 nodes, giving 2 + (2 × 2) = **6**. The eagerness barrier
/// alone cannot produce 10 — it decouples row production, not visibility — so this number is
/// evidence for the `WITH` rule specifically.
#[test]
fn a_with_after_a_write_opens_the_next_statement() {
    let mut coord = fresh_coord();
    seed(&mut coord, "CREATE ()");
    seed(&mut coord, "CREATE ()");

    let c = counters(&mut coord, "MATCH () CREATE () WITH * MATCH () CREATE ()");
    assert_eq!(
        c.nodes_created, 10,
        "expected 2 + (2 x 4) = 10; 6 means the WITH did not advance the command, and anything \
         above 10 means a MATCH saw its own CREATE"
    );
}

/// A `WITH` that follows **no** write does not open a statement — there is nothing to close, and a
/// gratuitous advance would be observable as a `RETURN` that cannot see its own writes.
#[test]
fn a_with_before_any_write_does_not_advance() {
    let mut coord = fresh_coord();
    seed(&mut coord, "CREATE (:N)");
    seed(&mut coord, "CREATE (:N)");
    // The `WITH` here precedes every write in the statement.
    let c = counters(&mut coord, "MATCH (n:N) WITH n CREATE (:N)");
    assert_eq!(
        c.nodes_created, 2,
        "the read-only WITH must not change what the scan below it saw"
    );
}

/// A `RETURN` never advances (`GenReturn` fixes the flag to `false`): the projection must still see
/// what the statement wrote.
#[test]
fn a_return_after_a_write_still_sees_the_write() {
    let mut coord = fresh_coord();
    let r = rows(
        &mut coord,
        "CREATE (n:N {num: 3}) RETURN n.num AS num",
        &IndexCatalog::empty(),
    );
    assert_eq!(
        sorted_ints(&r, "num"),
        vec![3],
        "RETURN must read the property its own statement just set"
    );
}

// =================================================================================================
// 4. `New` is preserved where openCypher requires it
// =================================================================================================

/// `MERGE`'s match sub-plan is the one match planned under `New`
/// (Memgraph `rule_based_planner.hpp`): `CREATE (:X) CREATE (:X) MERGE (:X)` creates 2 nodes, not 3
/// — the `MERGE` matches what the same statement just created.
#[test]
fn merge_matches_what_its_own_statement_created() {
    let mut coord = fresh_coord();
    let c = counters(&mut coord, "CREATE (:X) CREATE (:X) MERGE (:X)");
    assert_eq!(
        c.nodes_created, 2,
        "MERGE must match a node created by its own statement; 3 means its match ran under Old"
    );
}

/// `DELETE` runs under `New` — *"this way it is also possible to delete newly added nodes and
/// edges"* (Memgraph `operator.cpp`). A property read of a node the same statement deleted raises
/// `DeletedEntityAccess`, which proves the `DELETE` reached the node the `MATCH` bound.
#[test]
fn deleting_and_then_reading_raises_deleted_entity_access() {
    let mut coord = fresh_coord();
    seed(&mut coord, "CREATE (:N {num: 1})");

    let plan = compile("MATCH (n) DELETE n RETURN n.num", &IndexCatalog::empty());
    let bound = bind_parameters(&plan, &Parameters::new()).expect("bind");
    let txn = coord.begin_serializable();
    let err = {
        let mut graph = coord.statement(txn).expect("statement");
        let mut cursor = execute(&plan, &bound, &mut graph).expect("open");
        cursor.collect_all().expect_err("must fail")
    };
    coord.rollback(txn).expect("rollback");
    assert!(
        format!("{err:?}").contains("DeletedEntityAccess"),
        "expected DeletedEntityAccess, got {err:?}"
    );
}

/// `CREATE (n) DELETE n` deletes the node its own statement created — the `New` polarity of the
/// delete target, stated as a count rather than as an error.
#[test]
fn delete_removes_a_node_its_own_statement_created() {
    let mut coord = fresh_coord();
    let c = counters(&mut coord, "CREATE (n:Z) DELETE n");
    assert_eq!(c.nodes_created, 1);
    assert_eq!(
        c.nodes_deleted, 1,
        "DELETE must see the node CREATE just made"
    );
    let after = rows(
        &mut coord,
        "MATCH (n:Z) RETURN count(n) AS c",
        &IndexCatalog::empty(),
    );
    assert_eq!(after[0].get("c"), Some(&RowValue::Value(Value::Integer(0))));
}

/// `SET` needs the latest changes (*"Set, just like Create needs to see the latest changes"*), and
/// the `WITH` **after** it filters on the value it wrote.
///
/// `MATCH (n:N) SET n.num = n.num + 1 WITH n WHERE n.num % 2 = 0 RETURN n.num` over `num = 1..5`
/// yields `2, 4, 6` and sets 5 properties.
#[test]
fn a_with_filter_after_a_set_reads_the_new_values() {
    let mut coord = fresh_coord();
    for n in 1..=5 {
        seed(&mut coord, &format!("CREATE (:N {{num: {n}}})"));
    }
    let plan = compile(
        "MATCH (n:N) SET n.num = n.num + 1 WITH n WHERE n.num % 2 = 0 RETURN n.num AS num",
        &IndexCatalog::empty(),
    );
    let bound = bind_parameters(&plan, &Parameters::new()).expect("bind");
    let txn = coord.begin_serializable();
    let (r, c) = {
        let mut graph = coord.statement(txn).expect("statement");
        let r = {
            let mut cursor = execute(&plan, &bound, &mut graph).expect("open");
            cursor.collect_all().expect("collect")
        };
        let c = graph.write_counters();
        assert!(graph.take_error().is_none());
        (r, c)
    };
    coord.commit(txn).expect("commit");

    assert_eq!(
        sorted_ints(&r, "num"),
        vec![2, 4, 6],
        "the WITH's WHERE must filter on the values the SET wrote"
    );
    assert_eq!(
        c.properties_set, 5,
        "every one of the 5 nodes must be updated exactly once"
    );
}

// =================================================================================================
// 5. The gap the TCK does not cover: the right-hand side of a `SET` is `New`
// =================================================================================================

/// `MATCH (n)--() SET n.num = n.num + 1` with `n` matched `k` times composes to `n.num + k`.
///
/// The left-hand target and the right-hand expression are **both** `New`. If the right-hand side
/// read under `Old` it would re-read the pre-statement value on every driving row and the node would
/// end at `num + 1` however many rows matched — a silently wrong aggregate-by-repetition. No TCK
/// scenario pins this, which is exactly why it is pinned here.
#[test]
fn the_right_hand_side_of_a_set_composes_across_repeated_matches() {
    for k in [1_i64, 2, 4] {
        let mut coord = fresh_coord();
        seed(&mut coord, "CREATE (:C {num: 10})");
        // `k` distinct neighbours, so `MATCH (n:C)--() ` binds `n` exactly `k` times.
        for _ in 0..k {
            seed(&mut coord, "MATCH (c:C) CREATE (c)-[:E]->(:Other)");
        }
        let c = counters(&mut coord, "MATCH (n:C)--() SET n.num = n.num + 1");
        assert_eq!(
            c.properties_set, k as u64,
            "the SET must run once per matched row"
        );
        let r = rows(
            &mut coord,
            "MATCH (n:C) RETURN n.num AS num",
            &IndexCatalog::empty(),
        );
        assert_eq!(
            sorted_ints(&r, "num"),
            vec![10 + k],
            "with {k} matching rows the increments must COMPOSE to 10 + {k}; 11 means the \
             right-hand side read the pre-statement value each time"
        );
    }
}

// =================================================================================================
// 6. The decision table, asserted directly
// =================================================================================================

/// A [`GraphAccess`] decorator that owns a real [`View`] and records the view in force at every read
/// it serves.
///
/// This is what makes the polarity table **observable**: no barrier, no plan shape and no row count
/// can make these assertions pass by accident, because they read the view the executor installed,
/// not a consequence of it.
struct ViewRecorder {
    inner: MemGraph,
    view: View,
    log: RefCell<Vec<(&'static str, View)>>,
}

impl ViewRecorder {
    fn new(inner: MemGraph) -> Self {
        Self {
            inner,
            view: View::New,
            log: RefCell::new(Vec::new()),
        }
    }

    fn note(&self, what: &'static str) {
        self.log.borrow_mut().push((what, self.view));
    }

    /// Every distinct view recorded for `what`, in first-seen order. Empty when the access never
    /// happened — which every assertion below treats as a failure, so a plan that stopped taking the
    /// access under test can never read as a pass.
    fn views_of(&self, what: &str) -> Vec<View> {
        let mut out: Vec<View> = Vec::new();
        for (name, view) in self.log.borrow().iter() {
            if *name == what && !out.contains(view) {
                out.push(*view);
            }
        }
        out
    }
}

impl GraphAccess for ViewRecorder {
    // ---- the accesses whose polarity is under test ----------------------------------------------
    fn scan_nodes(&self) -> Vec<NodeId> {
        self.note("scan_nodes");
        self.inner.scan_nodes()
    }
    fn scan_nodes_by_label(&self, label: &str) -> Vec<NodeId> {
        self.note("scan_nodes_by_label");
        self.inner.scan_nodes_by_label(label)
    }
    fn expand(&self, node: NodeId, direction: ExpandDirection, types: &[String]) -> Vec<Incident> {
        self.note("expand");
        self.inner.expand(node, direction, types)
    }
    fn index_seek_eq(
        &self,
        label: &str,
        property: &str,
        value: &Value,
        carry: KeyValues,
    ) -> Option<IndexSeekHits> {
        self.note("index_seek_eq");
        self.inner.index_seek_eq(label, property, value, carry)
    }
    fn scan_filter_eq(&self, label: &str, property: &str, value: &Value) -> ScanFilter {
        self.note("scan_filter_eq");
        self.inner.scan_filter_eq(label, property, value)
    }
    fn index_seek_composite_eq(
        &self,
        label: &str,
        properties: &[String],
        values: &[Value],
        carry: KeyValues,
    ) -> Option<CompositeSeekHits> {
        self.note("index_seek_composite_eq");
        self.inner
            .index_seek_composite_eq(label, properties, values, carry)
    }
    fn node_property(&self, node: NodeId, key: &str) -> Option<Value> {
        self.note("node_property");
        self.inner.node_property(node, key)
    }
    fn node_labels(&self, node: NodeId) -> Option<Vec<String>> {
        self.note("node_labels");
        self.inner.node_labels(node)
    }
    fn node_exists(&self, node: NodeId) -> bool {
        self.note("node_exists");
        self.inner.node_exists(node)
    }
    fn rel_exists(&self, rel: RelId) -> bool {
        self.note("rel_exists");
        self.inner.rel_exists(rel)
    }
    fn rel_data(&self, rel: RelId) -> Option<RelData> {
        self.note("rel_data");
        self.inner.rel_data(rel)
    }
    fn rel_property(&self, rel: RelId, key: &str) -> Option<Value> {
        self.note("rel_property");
        self.inner.rel_property(rel, key)
    }
    fn node_properties(&self, node: NodeId) -> Option<Vec<(String, Value)>> {
        self.note("node_properties");
        self.inner.node_properties(node)
    }
    fn rel_properties(&self, rel: RelId) -> Option<Vec<(String, Value)>> {
        self.note("rel_properties");
        self.inner.rel_properties(rel)
    }
    fn incident_rels(&self, node: NodeId) -> Vec<RelId> {
        self.note("incident_rels");
        self.inner.incident_rels(node)
    }

    // ---- writes: recorded too, so the table's `New` half is asserted, not assumed ---------------
    fn create_node(&mut self, labels: &[String], properties: &[(String, Value)]) -> NodeId {
        self.log.borrow_mut().push(("create_node", self.view));
        self.inner.create_node(labels, properties)
    }
    fn create_rel(
        &mut self,
        rel_type: &str,
        start: NodeId,
        end: NodeId,
        properties: &[(String, Value)],
    ) -> RelId {
        self.log.borrow_mut().push(("create_rel", self.view));
        self.inner.create_rel(rel_type, start, end, properties)
    }
    fn set_node_property(&mut self, node: NodeId, key: &str, value: Value) {
        self.log.borrow_mut().push(("set_node_property", self.view));
        self.inner.set_node_property(node, key, value);
    }
    fn set_rel_property(&mut self, rel: RelId, key: &str, value: Value) {
        self.inner.set_rel_property(rel, key, value);
    }
    fn add_labels(&mut self, node: NodeId, labels: &[String]) {
        self.log.borrow_mut().push(("add_labels", self.view));
        self.inner.add_labels(node, labels);
    }
    fn remove_labels(&mut self, node: NodeId, labels: &[String]) {
        self.inner.remove_labels(node, labels);
    }
    fn remove_node_property(&mut self, node: NodeId, key: &str) {
        self.log
            .borrow_mut()
            .push(("remove_node_property", self.view));
        self.inner.remove_node_property(node, key);
    }
    fn remove_rel_property(&mut self, rel: RelId, key: &str) {
        self.inner.remove_rel_property(rel, key);
    }
    fn replace_node_properties(&mut self, node: NodeId, properties: &[(String, Value)]) {
        self.inner.replace_node_properties(node, properties);
    }
    fn merge_node_properties(&mut self, node: NodeId, properties: &[(String, Value)]) {
        self.inner.merge_node_properties(node, properties);
    }
    fn replace_rel_properties(&mut self, rel: RelId, properties: &[(String, Value)]) {
        self.inner.replace_rel_properties(rel, properties);
    }
    fn merge_rel_properties(&mut self, rel: RelId, properties: &[(String, Value)]) {
        self.inner.merge_rel_properties(rel, properties);
    }
    fn delete_rel(&mut self, rel: RelId) {
        self.log.borrow_mut().push(("delete_rel", self.view));
        self.inner.delete_rel(rel);
    }
    fn delete_node(&mut self, node: NodeId) {
        self.log.borrow_mut().push(("delete_node", self.view));
        self.inner.delete_node(node);
    }

    fn statistics(&self) -> Option<&dyn graphus_cypher::statistics::Statistics> {
        self.inner.statistics()
    }
    fn write_counters(&self) -> QueryCounters {
        self.inner.write_counters()
    }

    // ---- the view seam itself --------------------------------------------------------------------
    fn read_view(&self) -> View {
        self.view
    }
    fn set_read_view(&mut self, view: View) -> View {
        std::mem::replace(&mut self.view, view)
    }
}

/// Runs `src` over a [`ViewRecorder`] and returns the recorder for inspection.
fn record(src: &str, seed: impl FnOnce(&mut MemGraph)) -> ViewRecorder {
    let mut mem = MemGraph::new();
    seed(&mut mem);
    let mut g = ViewRecorder::new(mem);
    let plan = compile(src, &IndexCatalog::empty());
    let bound = bind_parameters(&plan, &Parameters::new()).expect("bind");
    execute(&plan, &bound, &mut g)
        .expect("open")
        .collect_all()
        .expect("collect");
    g
}

/// Asserts that every recorded access named `what` happened under exactly `want`, and that it
/// happened **at all**.
#[track_caller]
fn assert_view(g: &ViewRecorder, what: &str, want: View, why: &str) {
    let seen = g.views_of(what);
    assert!(
        !seen.is_empty(),
        "NON-VACUITY: `{what}` was never called, so its polarity was not asserted ({why})"
    );
    assert_eq!(
        seen,
        vec![want],
        "`{what}` must run under {want:?} ({why}), but ran under {seen:?}"
    );
}

/// The decision table, asserted operator by operator against the plan that actually executes.
///
/// Each row cites the Memgraph justification it transcribes.
#[test]
fn the_decision_table_is_what_the_plan_executes() {
    // --- scans: OLD ------------------------------------------------------------------------------
    let g = record("MATCH (n) RETURN n", |m| {
        m.add_node(["N"], [("v", Value::Integer(1))]);
    });
    assert_view(&g, "scan_nodes", View::Old, "an all-nodes scan");

    let g = record("MATCH (n:N) RETURN n", |m| {
        m.add_node(["N"], [("v", Value::Integer(1))]);
    });
    assert_view(&g, "scan_nodes_by_label", View::Old, "a label scan");

    // --- index seek: OLD, and the scan-and-filter fallback with it -------------------------------
    let g = record("MATCH (n:N {v: 1}) RETURN n", |m| {
        m.add_node(["N"], [("v", Value::Integer(1))]);
    });
    let seek = g.views_of("index_seek_eq");
    let filter = g.views_of("scan_filter_eq");
    assert!(
        !seek.is_empty() || !filter.is_empty(),
        "NON-VACUITY: neither the seek nor its scan fallback was taken"
    );
    for (what, seen) in [("index_seek_eq", seek), ("scan_filter_eq", filter)] {
        if !seen.is_empty() {
            assert_eq!(
                seen,
                vec![View::Old],
                "`{what}` must run under Old — a seek that disagreed with its scan fallback is \
                 exactly how CREATE INDEX comes to change the answer"
            );
        }
    }

    // --- expansion: OLD --------------------------------------------------------------------------
    let g = record("MATCH (a:A)-[r:T]->(b) RETURN b", |m| {
        let a = m.add_node(["A"], [] as [(&str, Value); 0]);
        let b = m.add_node(["B"], [] as [(&str, Value); 0]);
        m.add_rel("T", a, b, [] as [(&str, Value); 0]);
    });
    assert_view(&g, "expand", View::Old, "an expansion");

    // --- WHERE (Filter): OLD ---------------------------------------------------------------------
    // *"newly set values should not affect filtering of old nodes and edges"* (operator.cpp:4555).
    let g = record("MATCH (n) WHERE n.v > 0 RETURN n", |m| {
        m.add_node(["N"], [("v", Value::Integer(1))]);
    });
    assert_view(
        &g,
        "node_property",
        View::Old,
        "the property read of a MATCH's WHERE",
    );

    // --- UNWIND's list expression: OLD -----------------------------------------------------------
    let g = record("MATCH (n) UNWIND [n.v] AS x RETURN x", |m| {
        m.add_node(["N"], [("v", Value::Integer(1))]);
    });
    assert_view(
        &g,
        "node_property",
        View::Old,
        "the list expression of an UNWIND",
    );

    // --- RETURN (Produce): NEW -------------------------------------------------------------------
    // *"Produce should always yield the latest results"* (operator.cpp:4669).
    let g = record("MATCH (n) RETURN n.v AS v", |m| {
        m.add_node(["N"], [("v", Value::Integer(1))]);
    });
    assert_view(
        &g,
        "node_property",
        View::New,
        "the property read of a RETURN projection",
    );

    // --- aggregation: NEW ------------------------------------------------------------------------
    let g = record("MATCH (n) RETURN sum(n.v) AS s", |m| {
        m.add_node(["N"], [("v", Value::Integer(1))]);
    });
    assert_view(&g, "node_property", View::New, "an aggregate's argument");

    // --- ORDER BY: NEW ---------------------------------------------------------------------------
    let g = record("MATCH (n) RETURN n ORDER BY n.v", |m| {
        m.add_node(["N"], [("v", Value::Integer(1))]);
        m.add_node(["N"], [("v", Value::Integer(2))]);
    });
    assert_view(&g, "node_property", View::New, "an ORDER BY sort key");

    // --- CREATE: NEW -----------------------------------------------------------------------------
    let g = record("MATCH (n:N) CREATE (:M)", |m| {
        m.add_node(["N"], [] as [(&str, Value); 0]);
    });
    assert_view(&g, "create_node", View::New, "a CREATE");
    assert_view(&g, "scan_nodes_by_label", View::Old, "the scan driving it");

    // --- SET, target AND right-hand side: NEW ----------------------------------------------------
    // *"Set, just like Create needs to see the latest changes"* (operator.cpp:4909).
    let g = record("MATCH (n:N) SET n.v = n.v + 1", |m| {
        m.add_node(["N"], [("v", Value::Integer(1))]);
    });
    assert_view(&g, "set_node_property", View::New, "a SET's target");
    assert_view(
        &g,
        "node_property",
        View::New,
        "a SET's right-hand expression",
    );

    // --- REMOVE: NEW -----------------------------------------------------------------------------
    let g = record("MATCH (n:N) REMOVE n.v", |m| {
        m.add_node(["N"], [("v", Value::Integer(1))]);
    });
    assert_view(&g, "remove_node_property", View::New, "a REMOVE");

    // --- DELETE: NEW -----------------------------------------------------------------------------
    // *"this way it is also possible to delete newly added nodes and edges"* (operator.cpp:4716).
    let g = record("MATCH (n:N) DELETE n", |m| {
        m.add_node(["N"], [] as [(&str, Value); 0]);
    });
    assert_view(&g, "delete_node", View::New, "a DELETE");

    // --- FOREACH: NEW ----------------------------------------------------------------------------
    let g = record("MATCH (n:N) FOREACH (i IN [1] | SET n.v = i)", |m| {
        m.add_node(["N"], [] as [(&str, Value); 0]);
    });
    assert_view(&g, "set_node_property", View::New, "a FOREACH's body");

    // --- MERGE's match: NEW ----------------------------------------------------------------------
    let g = record("MERGE (:X)", |m| {
        m.add_node(["X"], [] as [(&str, Value); 0]);
    });
    assert_view(&g, "scan_nodes_by_label", View::New, "a MERGE's match");

    // --- a named path's reconstruction: NEW -------------------------------------------------------
    // It materialises a value from ids the row already holds — the `Produce` job, not a match. Pinned
    // by `clauses/merge/Merge5.feature` [10], which binds a path over a relationship its own statement
    // created; see the operator's comment for the measured TCK regression the `Old` reading caused.
    let g = record("MATCH p = (a:A)-[r:T]->(b) RETURN p", |m| {
        let a = m.add_node(["A"], [] as [(&str, Value); 0]);
        let b = m.add_node(["B"], [] as [(&str, Value); 0]);
        m.add_rel("T", a, b, [] as [(&str, Value); 0]);
    });
    assert_view(&g, "rel_data", View::New, "a named path's reconstruction");
}

/// A named path bound over entities the **same statement created** comes back correctly oriented.
///
/// This is `clauses/merge/Merge5.feature` \[10\] reproduced as a unit test, so the regression it
/// caught during `rmp` #972 names itself here rather than only in the TCK aggregate.
#[test]
fn a_path_bound_over_a_same_statement_creation_is_oriented_correctly() {
    let mut coord = fresh_coord();
    let r = rows(
        &mut coord,
        "MERGE (a {num: 1}) MERGE (b {num: 2}) MERGE p = (a)-[:R]->(b)          RETURN length(p) AS len, nodes(p)[0].num AS first, nodes(p)[1].num AS last",
        &IndexCatalog::empty(),
    );
    assert_eq!(r.len(), 1, "exactly one path row");
    assert_eq!(sorted_ints(&r, "len"), vec![1]);
    assert_eq!(
        sorted_ints(&r, "first"),
        vec![1],
        "the path must start at the node MERGE bound as `a`"
    );
    assert_eq!(
        sorted_ints(&r, "last"),
        vec![2],
        "the path must end at `b`; a stale view orients the hop at its own start node"
    );
}

/// The view is **restored** after every scoped switch, so an operator can never leave the seam
/// re-polarised for the ones that follow it.
#[test]
fn the_view_is_restored_after_every_operator() {
    let g = record("MATCH (n:N) WHERE n.v > 0 SET n.v = n.v + 1", |m| {
        m.add_node(["N"], [("v", Value::Integer(1))]);
    });
    assert_eq!(
        g.read_view(),
        View::New,
        "the seam must be handed back on the default polarity"
    );
    // And the `SET` really ran under New even though a `Filter` under Old preceded it.
    assert_view(&g, "set_node_property", View::New, "a SET below a Filter");
}

/// The **morsel (parallel scan) path** carries the seam's current view into the bundle it hands the
/// worker threads.
///
/// A parallel scan resolves visibility on a different thread, through a `StoreReadView` rather than
/// the live store, and a reader that resolves through a different mechanism than the inline path is
/// the `rmp` #755/#768/#769/#770 defect family. The polarity travels on the pinned `Snapshot`, so
/// this asserts exactly that: switch the seam, and the bundle carries the switch.
///
/// This is a **plumbing guard**, deliberately labelled as such. No query can make the two views
/// disagree on this path — every morsel tier's shape gate requires a bare scan with no write between
/// it and its consumer — so there is no row count that could witness it instead.
#[test]
fn the_morsel_bundle_carries_the_seams_view() {
    let mut coord = fresh_coord();
    for i in 0..4 {
        seed(&mut coord, &format!("CREATE (:N {{v: {i}}})"));
    }

    let txn = coord.begin_serializable();
    {
        let mut graph = coord.statement(txn).expect("statement");
        assert_eq!(graph.read_view(), View::New, "the seam starts on New");

        let scan = graph
            .morsel_label_scan("N")
            .expect("NON-VACUITY: the coordinated seam must serve a morsel label scan");
        assert_eq!(
            scan.snapshot.view,
            View::New,
            "the bundle must carry the seam's current view"
        );

        assert_eq!(graph.set_read_view(View::Old), View::New);
        let scan = graph
            .morsel_label_scan("N")
            .expect("NON-VACUITY: the coordinated seam must serve a morsel label scan");
        assert_eq!(
            scan.snapshot.view,
            View::Old,
            "the Old view did not reach the parallel scan bundle"
        );

        let frontier = graph
            .frontier_morsel_source()
            .expect("NON-VACUITY: the coordinated seam must serve a frontier morsel source");
        assert_eq!(
            frontier.snapshot.view,
            View::Old,
            "the Old view did not reach the frontier morsel source"
        );
        graph.set_read_view(View::New);
    }
    coord.rollback(txn).expect("rollback");
}

/// A statement's `command_id` comes from the **store**, so successive statements of one explicit
/// transaction — each on its own seam instance — keep advancing rather than restarting.
///
/// This is what makes an explicit multi-statement transaction behave like the auto-commit case, and
/// it is the reason the counter lives on `RecordStore` and not on the coordinator.
#[test]
fn successive_statements_of_one_transaction_keep_advancing_the_command() {
    let mut coord = fresh_coord();
    seed(&mut coord, "CREATE (:N)");
    seed(&mut coord, "CREATE (:N)");

    let txn = coord.begin_serializable();
    let mut commands = Vec::new();
    for src in [
        "MATCH (n:N) CREATE (:N)",
        "MATCH (n:N) CREATE (:N)",
        "MATCH (n:N) CREATE (:N)",
    ] {
        let plan = compile(src, &IndexCatalog::empty());
        let bound = bind_parameters(&plan, &Parameters::new()).expect("bind");
        let mut graph = coord.statement(txn).expect("statement");
        {
            let mut cursor = execute(&plan, &bound, &mut graph).expect("open");
            cursor.collect_all().expect("collect");
        }
        assert!(graph.take_error().is_none());
        commands.push(graph.current_command());
    }
    coord.rollback(txn).expect("rollback");

    assert!(
        commands.windows(2).all(|w| w[1] > w[0]),
        "each statement must open a NEW command; got {commands:?}"
    );
}

/// The three seam methods have working defaults, so an implementation with no MVCC is never asked to
/// pretend it switched. `MemGraph` is the reference seam and takes exactly that path.
#[test]
fn a_seam_without_mvcc_keeps_the_new_view() {
    let mut m = MemGraph::new();
    assert_eq!(m.read_view(), View::New);
    assert_eq!(m.set_read_view(View::Old), View::New);
    assert_eq!(
        m.read_view(),
        View::New,
        "a seam that cannot distinguish the views must keep answering New rather than lie"
    );
    m.begin_command(); // a no-op, and must not panic
}
