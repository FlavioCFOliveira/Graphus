//! Hardening regressions for the multi-value index seek (`rmp` task #868), each pinning a defect a
//! security audit of the first implementation found and this one fixes.
//!
//! These are deliberately separate from `tests/multi_value_index_seek.rs` (which pins the *feature*):
//! they need a **counting / instrumented** [`GraphAccess`] decorator or a tripped
//! [`CancellationToken`], neither of which the coordinator-backed harness exposes.
//!
//! 1. **The whole-union decline must cost ONE scan, not `k`.** The seam declines whenever any single
//!    alternative is not index-encodable (a `null`, a list) — and, for relationships, on **every**
//!    query a restricted RBAC principal issues, since `AuthorizedGraph::index_seek_rel_eq` declines
//!    outright for them. Falling back per value would re-scan the whole label `k` times: a `k`-fold
//!    amplification over the `scan + IN filter` plan the operator replaced, freely triggerable from the
//!    query text. Measured at 6.6x (nodes) / 24.8x (relationships) before the fix.
//! 2. **The operator build must poll the cancellation token.** The whole `k`-descent union is computed
//!    eagerly in `build_operator`, *before* the first `Cursor::next` — so without an explicit poll a
//!    long `IN` list burns CPU with no safe point and the statement deadline (`rmp` #476) cannot fire.

use graphus_core::Value;
use graphus_cypher::binding::{Parameters, bind_parameters};
use graphus_cypher::catalog::IndexCatalog;
use graphus_cypher::executor::{CancellationToken, ExecError, Executor, execute};
use graphus_cypher::graph_access::{
    ExpandDirection, GraphAccess, Incident, IndexSeekHits, KeyValues, MemGraph, NodeId, RelData,
    RelId, ScanFilter,
};
use graphus_cypher::lexer::tokenize;
use graphus_cypher::lower::lower;
use graphus_cypher::parser::parse_tokens;
use graphus_cypher::physical::{PhysicalPlan, plan_physical};
use graphus_cypher::semantics::analyze;
use std::cell::Cell;

// =================================================================================================
// Harness
// =================================================================================================

fn compile(src: &str, catalog: &IndexCatalog) -> PhysicalPlan {
    let toks = tokenize(src).expect("lex");
    let ast = parse_tokens(&toks, src).expect("parse");
    let validated = analyze(&ast).expect("analyze");
    plan_physical(&lower(&validated), catalog)
}

/// A catalog declaring the `(USER, uidn)` and `(KNOWS, since)` indexes, so the planner emits the
/// multi-value seeks. The backing [`MemGraph`] deliberately implements **neither** seek seam (it
/// inherits the `None` default), which is precisely the whole-union decline this file measures.
fn indexed_catalog() -> IndexCatalog {
    IndexCatalog::builder()
        .with_label_property("USER", "uidn")
        .with_rel_property("KNOWS", "since")
        .build()
}

fn corpus() -> MemGraph {
    let mut g = MemGraph::new();
    let users: Vec<NodeId> = (0..40)
        .map(|i| g.add_node(["USER"], [("uidn", Value::Integer(i))]))
        .collect();
    for w in users.windows(2) {
        g.add_rel("KNOWS", w[0], w[1], [("since", Value::Integer(2020))]);
    }
    g
}

/// A [`GraphAccess`] decorator that counts how many times the executor starts a **full enumeration**.
///
/// It forwards everything verbatim, so the rows are the inner graph's rows exactly; it only observes.
/// `MemGraph` implements neither index seek, so a multi-value seek over it always takes the decline
/// path — making these counters the direct measurement of "how many passes did the fallback cost?".
struct CountingGraph<'a> {
    inner: &'a mut MemGraph,
    label_scans: Cell<usize>,
    all_node_scans: Cell<usize>,
    /// When set, [`GraphAccess::index_seek_eq`] is **served** (and counted) instead of declining, so a
    /// test can measure how many index descents the union actually issues.
    serve_eq_seeks: bool,
    eq_seeks: Cell<usize>,
    /// Trips this token once `eq_seeks` reaches the bound — a client disconnect / `RESET` / timeout
    /// arriving *while the descents are running*, which is the only window the per-descent poll
    /// defends (the alternative-evaluation loop has already finished by then).
    cancel_after_seeks: Option<(usize, CancellationToken)>,
}

impl<'a> CountingGraph<'a> {
    fn new(inner: &'a mut MemGraph) -> Self {
        Self {
            inner,
            label_scans: Cell::new(0),
            all_node_scans: Cell::new(0),
            serve_eq_seeks: false,
            eq_seeks: Cell::new(0),
            cancel_after_seeks: None,
        }
    }

    fn serving_seeks(inner: &'a mut MemGraph) -> Self {
        Self {
            serve_eq_seeks: true,
            ..Self::new(inner)
        }
    }

    fn cancelling_after(inner: &'a mut MemGraph, seeks: usize, token: CancellationToken) -> Self {
        Self {
            serve_eq_seeks: true,
            cancel_after_seeks: Some((seeks, token)),
            ..Self::new(inner)
        }
    }
}

impl GraphAccess for CountingGraph<'_> {
    // ---- the three enumerations this test measures ------------------------------------------
    fn scan_nodes(&self) -> Vec<NodeId> {
        self.all_node_scans.set(self.all_node_scans.get() + 1);
        self.inner.scan_nodes()
    }
    fn scan_nodes_by_label(&self, label: &str) -> Vec<NodeId> {
        self.label_scans.set(self.label_scans.get() + 1);
        self.inner.scan_nodes_by_label(label)
    }
    fn scan_filter_eq(&self, label: &str, property: &str, value: &Value) -> ScanFilter {
        // Counted as a label pass too: it is likewise a full enumeration of the label.
        self.label_scans.set(self.label_scans.get() + 1);
        self.inner.scan_filter_eq(label, property, value)
    }

    /// A hand-rolled equality seek over the inner graph, counted. Returning `Some` is what puts the
    /// operator on its **served** path, so `eq_seeks` measures the descents the union issues. The
    /// matches are computed with the same Cypher equality the real seam re-checks with, so the rows are
    /// the correct ones and only the count is under test.
    fn index_seek_eq(
        &self,
        label: &str,
        property: &str,
        value: &Value,
        _carry: KeyValues,
    ) -> Option<IndexSeekHits> {
        if !self.serve_eq_seeks {
            return None; // inherit the default decline, like `MemGraph` itself
        }
        self.eq_seeks.set(self.eq_seeks.get() + 1);
        if let Some((bound, token)) = &self.cancel_after_seeks
            && self.eq_seeks.get() >= *bound
        {
            token.cancel();
        }
        Some(IndexSeekHits::ids(
            self.inner
                .scan_nodes_by_label(label)
                .into_iter()
                .filter(|&id| {
                    self.inner
                        .node_property(id, property)
                        .is_some_and(|v| graphus_cypher::equality::equals(&v, value).is_true())
                })
                .collect(),
        ))
    }

    // ---- verbatim forwarding: the rows are the inner graph's rows exactly ---------------------
    fn expand(&self, node: NodeId, direction: ExpandDirection, types: &[String]) -> Vec<Incident> {
        self.inner.expand(node, direction, types)
    }
    fn node_exists(&self, node: NodeId) -> bool {
        self.inner.node_exists(node)
    }
    fn rel_exists(&self, rel: RelId) -> bool {
        self.inner.rel_exists(rel)
    }
    fn node_labels(&self, node: NodeId) -> Option<Vec<String>> {
        self.inner.node_labels(node)
    }
    fn rel_data(&self, rel: RelId) -> Option<RelData> {
        self.inner.rel_data(rel)
    }
    fn node_property(&self, node: NodeId, key: &str) -> Option<Value> {
        self.inner.node_property(node, key)
    }
    fn rel_property(&self, rel: RelId, key: &str) -> Option<Value> {
        self.inner.rel_property(rel, key)
    }
    fn node_properties(&self, node: NodeId) -> Option<Vec<(String, Value)>> {
        self.inner.node_properties(node)
    }
    fn rel_properties(&self, rel: RelId) -> Option<Vec<(String, Value)>> {
        self.inner.rel_properties(rel)
    }
    fn incident_rels(&self, node: NodeId) -> Vec<RelId> {
        self.inner.incident_rels(node)
    }
    fn create_node(&mut self, labels: &[String], properties: &[(String, Value)]) -> NodeId {
        self.inner.create_node(labels, properties)
    }
    fn create_rel(
        &mut self,
        rel_type: &str,
        start: NodeId,
        end: NodeId,
        properties: &[(String, Value)],
    ) -> RelId {
        self.inner.create_rel(rel_type, start, end, properties)
    }
    fn set_node_property(&mut self, node: NodeId, key: &str, value: Value) {
        self.inner.set_node_property(node, key, value);
    }
    fn set_rel_property(&mut self, rel: RelId, key: &str, value: Value) {
        self.inner.set_rel_property(rel, key, value);
    }
    fn add_labels(&mut self, node: NodeId, labels: &[String]) {
        self.inner.add_labels(node, labels);
    }
    fn remove_labels(&mut self, node: NodeId, labels: &[String]) {
        self.inner.remove_labels(node, labels);
    }
    fn remove_node_property(&mut self, node: NodeId, key: &str) {
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
        self.inner.delete_rel(rel);
    }
    fn delete_node(&mut self, node: NodeId) {
        self.inner.delete_node(node);
    }
}

fn run_counted(src: &str, g: &mut MemGraph, catalog: &IndexCatalog) -> (usize, usize, usize) {
    let plan = compile(src, catalog);
    let bound = bind_parameters(&plan, &Parameters::new()).expect("bind");
    let mut counting = CountingGraph::new(g);
    let rows = {
        let mut cursor = execute(&plan, &bound, &mut counting).expect("open");
        cursor.collect_all().expect("run").len()
    };
    (
        rows,
        counting.label_scans.get(),
        counting.all_node_scans.get(),
    )
}

// =================================================================================================
// 1. The whole-union decline costs ONE pass, not k
// =================================================================================================

#[test]
fn a_declining_node_multi_seek_scans_the_label_exactly_once() {
    let mut g = corpus();
    let catalog = indexed_catalog();
    let src = "MATCH (u:USER) WHERE u.uidn IN [1, 2, 3, 4, 5, 6, 7, 8] RETURN u.uidn AS x";
    let plan = compile(src, &catalog);
    assert!(
        plan.to_string().contains("NodeIndexMultiSeek"),
        "the measurement is vacuous unless the multi-value seek is actually planned:\n{plan}"
    );

    let (rows, label_scans, _) = run_counted(src, &mut g, &catalog);
    assert_eq!(rows, 8, "all eight alternatives match one user each");
    assert_eq!(
        label_scans, 1,
        "the whole-union decline must cost ONE label pass, not one per alternative"
    );

    // The count must not grow with `k`: this is the amplification the fix removes.
    let big: Vec<String> = (0..40).map(|i| i.to_string()).collect();
    let src_big = format!(
        "MATCH (u:USER) WHERE u.uidn IN [{}] RETURN u.uidn AS x",
        big.join(", ")
    );
    let (rows_big, label_scans_big, _) = run_counted(&src_big, &mut g, &catalog);
    assert_eq!(rows_big, 40);
    assert_eq!(
        label_scans_big, 1,
        "a 40-element list must still cost ONE label pass"
    );
}

#[test]
fn a_declining_relationship_multi_seek_enumerates_the_store_exactly_once() {
    let mut g = corpus();
    let catalog = indexed_catalog();
    let src =
        "MATCH ()-[r:KNOWS]->() WHERE r.since IN [2020, 2021, 2022, 2023] RETURN r.since AS x";
    let plan = compile(src, &catalog);
    assert!(
        plan.to_string().contains("RelIndexMultiSeek"),
        "the measurement is vacuous unless the multi-value seek is actually planned:\n{plan}"
    );

    let (rows, _, all_node_scans) = run_counted(src, &mut g, &catalog);
    assert_eq!(rows, 39, "every KNOWS has since = 2020");
    assert_eq!(
        all_node_scans, 1,
        "the relationship decline must walk the store ONCE, not once per alternative — this path is \
         taken on EVERY relationship multi-seek a restricted RBAC principal issues"
    );
}

#[test]
fn the_declining_fallback_answers_exactly_what_the_scan_plan_answers() {
    // The single-pass fallback is only admissible if it is bag-identical to the plan it replaces.
    // Compare against the same query planned with NO index at all (a plain scan + `IN` filter).
    let mut g = corpus();
    for src in [
        "MATCH (u:USER) WHERE u.uidn IN [1, 2, 3] RETURN u.uidn AS x",
        // A `null` alternative forces the decline even when the index IS declared.
        "MATCH (u:USER) WHERE u.uidn IN [1, null, 2] RETURN u.uidn AS x",
        "MATCH (u:USER) WHERE u.uidn IN [] RETURN u.uidn AS x",
        "MATCH (u:USER) WHERE u.uidn = 5 OR u.uidn = 6 RETURN u.uidn AS x",
        "MATCH ()-[r:KNOWS]->() WHERE r.since IN [2020, 2021] RETURN r.since AS x",
        "MATCH ()-[r:KNOWS]-() WHERE r.since IN [2020] RETURN r.since AS x",
    ] {
        let (seek_rows, _, _) = run_counted(src, &mut g, &indexed_catalog());
        let (scan_rows, _, _) = run_counted(src, &mut g, &IndexCatalog::empty());
        assert_eq!(
            seek_rows, scan_rows,
            "the declining multi-value seek must answer exactly the scan plan for {src:?}"
        );
    }
}

// =================================================================================================
// 2. The operator build polls the cancellation token
// =================================================================================================

/// A [`CancellationToken`] whose wall-clock deadline is already in the past — the shape `rmp` #476
/// installs for a statement timeout. Unlike an explicitly *flagged* token (which `Executor::open`
/// rejects before building anything, so it proves nothing about the operator body), a past deadline is
/// only observed where the code actually **polls**: `check_cancelled` reads the clock on a strided
/// cadence, so the loop under test has to run enough iterations to reach a poll point.
fn expired_token() -> CancellationToken {
    let past = std::time::Instant::now()
        .checked_sub(std::time::Duration::from_secs(60))
        .expect("a monotonic instant 60s in the past");
    CancellationToken::with_deadline(Some(past))
}

/// A list long enough to cross the deadline-poll stride several times over.
fn long_list(start: i64) -> String {
    (start..start + 8192)
        .map(|i| i.to_string())
        .collect::<Vec<_>>()
        .join(", ")
}

#[test]
fn a_long_node_in_list_is_interrupted_by_an_expired_statement_deadline() {
    // `build_operator` runs before the first `Cursor::next`, so the whole `k`-element evaluation and the
    // `k`-descent union happen at OPEN time. Without an explicit poll there, a long `IN` list is
    // uninterruptible: the statement deadline of `rmp` #476 could not fire however long the list, and
    // the work moved out from under the deadline is exactly what the pre-#868 `Filter` did per row —
    // where it WAS polled.
    let mut g = corpus();
    let catalog = indexed_catalog();
    let src = format!(
        "MATCH (u:USER) WHERE u.uidn IN [{}] RETURN u.uidn AS x",
        long_list(0)
    );
    let plan = compile(&src, &catalog);
    assert!(plan.to_string().contains("NodeIndexMultiSeek"), "{plan}");
    let bound = bind_parameters(&plan, &Parameters::new()).expect("bind");

    let err = Executor::new(plan, bound)
        .open(&mut g, expired_token())
        .err()
        .expect("an expired deadline must interrupt the union build");
    assert!(
        matches!(err, ExecError::Cancelled),
        "expected ExecError::Cancelled, got {err:?}"
    );
}

#[test]
fn a_long_relationship_in_list_is_interrupted_by_an_expired_statement_deadline() {
    let mut g = corpus();
    let catalog = indexed_catalog();
    let src = format!(
        "MATCH ()-[r:KNOWS]->() WHERE r.since IN [{}] RETURN r.since AS x",
        long_list(3000)
    );
    let plan = compile(&src, &catalog);
    assert!(plan.to_string().contains("RelIndexMultiSeek"), "{plan}");
    let bound = bind_parameters(&plan, &Parameters::new()).expect("bind");

    let err = Executor::new(plan, bound)
        .open(&mut g, expired_token())
        .err()
        .expect("an expired deadline must interrupt the union build");
    assert!(
        matches!(err, ExecError::Cancelled),
        "expected ExecError::Cancelled, got {err:?}"
    );
}

/// The control: an *unexpired* deadline must not interrupt anything, so the assertions above are about
/// the poll firing rather than about the operator being broken.
#[test]
fn an_unexpired_deadline_lets_the_union_complete() {
    let mut g = corpus();
    let catalog = indexed_catalog();
    let src = format!(
        "MATCH (u:USER) WHERE u.uidn IN [{}] RETURN u.uidn AS x",
        long_list(0)
    );
    let plan = compile(&src, &catalog);
    let bound = bind_parameters(&plan, &Parameters::new()).expect("bind");
    let future = std::time::Instant::now() + std::time::Duration::from_secs(600);
    let mut cursor = Executor::new(plan, bound)
        .open(&mut g, CancellationToken::with_deadline(Some(future)))
        .expect("an unexpired deadline must not interrupt the build");
    assert_eq!(
        cursor.collect_all().expect("run").len(),
        40,
        "every seeded user's uidn is in the list"
    );
}

// =================================================================================================
// 3. The value collapse issues one descent per DISTINCT alternative
// =================================================================================================

/// Runs `src` on the **served** seek path and returns `(rows, index descents issued)`.
fn run_seek_counted(src: &str, g: &mut MemGraph, catalog: &IndexCatalog) -> (usize, usize) {
    let plan = compile(src, catalog);
    assert!(
        plan.to_string().contains("NodeIndexMultiSeek"),
        "the measurement is vacuous unless the multi-value seek is actually planned:\n{plan}"
    );
    let bound = bind_parameters(&plan, &Parameters::new()).expect("bind");
    let mut counting = CountingGraph::serving_seeks(g);
    let rows = {
        let mut cursor = execute(&plan, &bound, &mut counting).expect("open");
        cursor.collect_all().expect("run").len()
    };
    (rows, counting.eq_seeks.get())
}

/// The value-level collapse is a **cost** guard, not a correctness one: the operator's final id
/// sort+dedup is what stops a repeated alternative duplicating a row (pinned in
/// `tests/multi_value_index_seek.rs`). What the collapse guarantees is that `k` repetitions of one
/// value cost **one** descent, not `k` — which is invisible in the result and therefore has to be
/// measured directly, or the guard would be untested.
///
/// It is deliberately keyed on **value identity**, not Cypher equality: `1` and `1.0` are Cypher-equal
/// but are NOT collapsed, because at magnitudes at or above 2^53 the Cypher-equal classes of two
/// mutually-equal values differ and collapsing loses rows (`rmp` #868; the correctness half is pinned by
/// `large_integer_float_alternatives_neither_lose_nor_duplicate_rows`).
#[test]
fn repeated_alternatives_cost_one_descent_each_and_cross_type_ones_do_not_collapse() {
    let mut g = corpus();
    let catalog = indexed_catalog();

    // Four alternatives, three distinct values (`1` twice) → three descents.
    let (rows, descents) = run_seek_counted(
        "MATCH (u:USER) WHERE u.uidn IN [1, 1, 1.0, 2] RETURN u.uidn AS x",
        &mut g,
        &catalog,
    );
    assert_eq!(rows, 2, "users 1 and 2 match, each exactly once");
    assert_eq!(
        descents, 3,
        "the repeated `1` collapses to one descent; `1.0` is a different VALUE and keeps its own"
    );

    // Twenty repetitions of one value still cost one descent.
    let twenty = std::iter::repeat_n("7", 20).collect::<Vec<_>>().join(", ");
    let (rows, descents) = run_seek_counted(
        &format!("MATCH (u:USER) WHERE u.uidn IN [{twenty}] RETURN u.uidn AS x"),
        &mut g,
        &catalog,
    );
    assert_eq!(rows, 1);
    assert_eq!(descents, 1, "20 repetitions of one value = 1 descent");

    // `-0.0` and `+0.0` are Cypher-EQUAL but are deliberately NOT collapsed: they encode to distinct
    // SSI equality markers, so merging them would register one marker where two are needed and let a
    // concurrent `CREATE {p: -0.0}` escape a reader of `= 0.0`. Two descents is the correct answer.
    let (_, descents) = run_seek_counted(
        "MATCH (u:USER) WHERE u.uidn IN [0.0, -0.0] RETURN u.uidn AS x",
        &mut g,
        &catalog,
    );
    assert_eq!(
        descents, 2,
        "signed zeros keep one descent each, so each registers its own SSI equality marker"
    );

    // Two durations that share an order-preserving index key but are Cypher-UNEQUAL must likewise keep
    // one descent each — collapsing them lost rows (`rmp` #868; pinned for result correctness in
    // `tests/multi_value_index_seek.rs::order_equal_but_unequal_durations_are_not_collapsed`).
    let (_, descents) = run_seek_counted(
        "MATCH (u:USER) WHERE u.uidn IN [duration({days: 1}), duration({hours: 24})] \
         RETURN u.uidn AS x",
        &mut g,
        &catalog,
    );
    assert_eq!(descents, 2, "order-equal durations are two distinct values");

    // An empty list issues no descent at all.
    let (rows, descents) = run_seek_counted(
        "MATCH (u:USER) WHERE u.uidn IN [] RETURN u.uidn AS x",
        &mut g,
        &catalog,
    );
    assert_eq!((rows, descents), (0, 0), "IN [] touches nothing");
}

/// The per-**descent** poll, proven separately from the per-alternative one.
///
/// With an already-expired deadline the alternative-evaluation loop always reaches a poll point first,
/// so that test cannot distinguish the two polls. This one trips the token from inside the seam, after
/// the evaluation loop has finished and three descents have run — the real shape of a client
/// disconnect, a `RESET`, or a deadline elapsing *during* the I/O. Only the descent-loop poll can
/// observe it, and `is_flagged` is checked unstrided so the observation is deterministic.
#[test]
fn a_cancellation_arriving_during_the_descents_stops_the_union() {
    let mut g = corpus();
    let catalog = indexed_catalog();
    let plan = compile(
        "MATCH (u:USER) WHERE u.uidn IN [1, 2, 3, 4, 5, 6, 7, 8] RETURN u.uidn AS x",
        &catalog,
    );
    assert!(plan.to_string().contains("NodeIndexMultiSeek"), "{plan}");
    let bound = bind_parameters(&plan, &Parameters::new()).expect("bind");

    let token = CancellationToken::new();
    let mut graph = CountingGraph::cancelling_after(&mut g, 3, token.clone());
    let err = Executor::new(plan, bound)
        .open(&mut graph, token)
        .err()
        .expect("a cancellation arriving mid-union must stop it");
    assert!(
        matches!(err, ExecError::Cancelled),
        "expected ExecError::Cancelled, got {err:?}"
    );
    assert!(
        graph.eq_seeks.get() < 8,
        "the union must stop early, not run all eight descents (ran {})",
        graph.eq_seeks.get()
    );
}

// =================================================================================================
// 4. Off-thread reader parity: every alternative is captured for the candidate memo
// =================================================================================================

/// The off-thread reader holds no `IndexSet`; it answers a seek from a **memo** captured on the engine
/// thread from `PhysicalPlan::static_node_index_eq_seeks` / `static_rel_index_eq_seeks`. A multi-value
/// seek needs one captured key per alternative — a miss on any single one declines the WHOLE union, so
/// an uncaptured alternative silently degrades every off-thread multi-seek to a scan. That is the
/// off-thread/inline parity gap `rmp` #768/#769 catalogued for the other seek kinds, and it is
/// invisible in query results (a decline is a decline, never a wrong answer), so it has to be asserted
/// on the capture itself.
#[test]
fn every_alternative_is_captured_for_the_off_thread_reader_memo() {
    let catalog = indexed_catalog();

    let node_plan = compile(
        "MATCH (u:USER) WHERE u.uidn IN [1, 2, 3] RETURN u.uidn AS x",
        &catalog,
    );
    assert!(node_plan.to_string().contains("NodeIndexMultiSeek"));
    let bound = bind_parameters(&node_plan, &Parameters::new()).expect("bind");
    let captured = node_plan.static_node_index_eq_seeks(&bound);
    assert_eq!(
        captured,
        vec![
            ("USER".to_owned(), "uidn".to_owned(), Value::Integer(1)),
            ("USER".to_owned(), "uidn".to_owned(), Value::Integer(2)),
            ("USER".to_owned(), "uidn".to_owned(), Value::Integer(3)),
        ],
        "one captured key per alternative, in source order"
    );

    let rel_plan = compile(
        "MATCH ()-[r:KNOWS]->() WHERE r.since IN [2020, 2021] RETURN r.since AS x",
        &catalog,
    );
    assert!(rel_plan.to_string().contains("RelIndexMultiSeek"));
    let rel_bound = bind_parameters(&rel_plan, &Parameters::new()).expect("bind");
    assert_eq!(
        rel_plan.static_rel_index_eq_seeks(&rel_bound),
        vec![
            ("KNOWS".to_owned(), "since".to_owned(), Value::Integer(2020)),
            ("KNOWS".to_owned(), "since".to_owned(), Value::Integer(2021)),
        ],
        "the relationship twin must capture its alternatives too"
    );

    // The OR spelling captures its alternatives as well (they arrive as auto-parameters, which
    // `static_seek_value` resolves through the bound parameter set).
    let or_plan = compile(
        "MATCH (u:USER) WHERE u.uidn = 7 OR u.uidn = 8 RETURN u.uidn AS x",
        &catalog,
    );
    let or_bound = bind_parameters(&or_plan, &Parameters::new()).expect("bind");
    assert_eq!(
        or_plan.static_node_index_eq_seeks(&or_bound).len(),
        2,
        "the OR spelling captures one key per branch"
    );
}
