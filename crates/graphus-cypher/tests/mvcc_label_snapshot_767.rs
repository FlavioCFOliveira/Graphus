//! MVCC snapshot isolation of **label membership** (`rmp` task #767).
//!
//! ## What this pins
//!
//! `04-technical-design.md` §5.3 gives every read a consistent point-in-time snapshot: a reader sees
//! exactly the versions committed at or before its begin timestamp. `mvcc_visibility.rs` already
//! pins that for node *existence* (clauses 1 and 2) and for *properties*.
//!
//! Label membership is the third component of a node's observable state, and it is read through the
//! same seam. This file pins it to the same rule: a committed `REMOVE n:Person` must NOT become
//! visible to a reader whose snapshot predates that commit, exactly as a committed `SET n.v = 2`
//! does not.
//!
//! ## Why a pure scan
//!
//! Every query here compiles against [`IndexCatalog::empty`], so there is no index to seek and the
//! label predicate is evaluated by scanning and re-checking each node. That is deliberate: it makes
//! this a statement about **store-level MVCC semantics**, not about index staleness. An index-backed
//! variant of the same defect would be a different bug in a different layer.
//!
//! ## The control is load-bearing
//!
//! [`property_change_is_snapshot_isolated_control`] applies a property change and a label change in
//! the SAME transaction, at the SAME commit timestamp, and reads both back at the SAME older
//! snapshot. Without that control a failure here could be blamed on the harness picking the wrong
//! timestamp; with it, the two reads differ while everything else is held constant, so the only
//! variable left is label-vs-property.

use graphus_core::{Timestamp, TxnId, Value};
use graphus_cypher::binding::{Parameters, bind_parameters};
use graphus_cypher::catalog::IndexCatalog;
use graphus_cypher::executor::execute;
use graphus_cypher::lexer::tokenize;
use graphus_cypher::lower::lower;
use graphus_cypher::parser::parse_tokens;
use graphus_cypher::physical::plan_physical;
use graphus_cypher::record_graph::RecordStoreGraph;
use graphus_cypher::runtime::Row;
use graphus_cypher::semantics::analyze;
use graphus_io::MemBlockDevice;
use graphus_storage::RecordStore;
use graphus_wal::{MemLogSink, WalManager};

type Store = RecordStore<MemBlockDevice, MemLogSink>;

fn fresh_store() -> Store {
    let device = MemBlockDevice::new(0);
    let wal = WalManager::create(MemLogSink::new()).expect("create wal");
    RecordStore::create(device, wal, 64, 1).expect("create store")
}

fn compile(src: &str) -> graphus_cypher::physical::PhysicalPlan {
    let toks = tokenize(src).expect("lex");
    let ast = parse_tokens(&toks, src).expect("parse");
    let validated = analyze(&ast).expect("analyze");
    // `IndexCatalog::empty()`: no index exists, so every label predicate below is a pure scan +
    // per-candidate re-check. See the module docs.
    plan_physical(&lower(&validated), &IndexCatalog::empty())
}

/// Runs a write query under `txn` and commits it (advancing the store's commit timestamp).
fn run_commit(src: &str, store: Store, txn: u64) -> Store {
    let plan = compile(src);
    let bound = bind_parameters(&plan, &Parameters::new()).expect("bind");
    let mut graph = RecordStoreGraph::begin(store, TxnId(txn));
    {
        let mut cursor = execute(&plan, &bound, &mut graph).expect("open cursor");
        cursor.collect_all().expect("collect");
    }
    assert!(
        !graph.has_error(),
        "captured error: {:?}",
        graph.take_error()
    );
    graph.commit().expect("commit")
}

/// Runs a read-only query at an explicit MVCC snapshot timestamp `ts` and returns its rows.
fn read_at(src: &str, store: Store, txn: u64, ts: u64) -> (Vec<Row>, Store) {
    let plan = compile(src);
    let bound = bind_parameters(&plan, &Parameters::new()).expect("bind");
    let mut graph = RecordStoreGraph::begin_at_snapshot(store, TxnId(txn), Timestamp(ts));
    let rows = {
        let mut cursor = execute(&plan, &bound, &mut graph).expect("open cursor");
        cursor.collect_all().expect("collect")
    };
    assert!(
        !graph.has_error(),
        "captured error: {:?}",
        graph.take_error()
    );
    (rows, graph.into_store())
}

fn ints(rows: &[Row], col: &str) -> Vec<i64> {
    let mut vs: Vec<i64> = rows
        .iter()
        .filter_map(|r| match r.value(col) {
            Value::Integer(k) => Some(k),
            _ => None,
        })
        .collect();
    vs.sort_unstable();
    vs
}

/// The label names a row's `labels(n)` column carries, ascending.
fn label_names(rows: &[Row], col: &str) -> Vec<Vec<String>> {
    rows.iter()
        .map(|r| match r.value(col) {
            Value::List(items) => {
                let mut names: Vec<String> = items
                    .iter()
                    .filter_map(|v| match v {
                        Value::String(s) => Some(s.clone()),
                        _ => None,
                    })
                    .collect();
                names.sort();
                names
            }
            other => panic!("labels() must evaluate to a list, got {other:?}"),
        })
        .collect()
}

/// **THE REPRODUCTION (`rmp` #767).** A committed `REMOVE n:Person` must not be visible to a reader
/// whose snapshot predates the commit.
///
/// While the defect was open this assertion failed with an EMPTY result: the scan re-read the node's
/// CURRENT label bitmap (the label word is mutated in place, with no version chain), so the older
/// reader's `MATCH (n:Person)` matched nothing even though at its snapshot the node carried the
/// label. That is a non-repeatable read: within one transaction the same `MATCH` can return a node
/// and then stop returning it.
#[test]
fn older_snapshot_does_not_see_a_later_committed_label_removal() {
    // txn 1 commits a :Person node at commit timestamp 1.
    let store = run_commit("CREATE (:Person {v: 1})", fresh_store(), 1);
    // txn 2 removes the label and commits at timestamp 2.
    let store = run_commit("MATCH (n:Person) REMOVE n:Person", store, 2);

    // A reader whose snapshot is at ts 1 began BEFORE the removal committed (its xmax-equivalent
    // committed at 2 > 1), so the label must still be there — the same rule
    // `older_snapshot_still_sees_a_concurrently_deleted_node` pins for node existence.
    let (rows, store) = read_at("MATCH (n:Person) RETURN n.v AS v", store, 3, 1);
    assert_eq!(
        ints(&rows, "v"),
        vec![1],
        "rmp #767 NON-REPEATABLE READ: a reader whose snapshot predates the committed \
         `REMOVE n:Person` must still match the node, but the label predicate read the CURRENT \
         label bitmap instead of the version visible at the snapshot"
    );

    // A reader at or after the removal (ts = 2) correctly does not match it.
    let (rows, _store) = read_at("MATCH (n:Person) RETURN n.v AS v", store, 4, 2);
    assert!(
        rows.is_empty(),
        "a snapshot at/after the label removal must not match the node, got {rows:?}"
    );
}

/// The same defect seen through the `labels()` accessor rather than the match predicate, so the
/// reproduction does not depend on how the label filter happens to be planned.
#[test]
fn older_snapshot_reads_the_label_set_as_of_its_snapshot() {
    let store = run_commit("CREATE (:Person {v: 1})", fresh_store(), 1);
    let store = run_commit("MATCH (n:Person) REMOVE n:Person", store, 2);

    // Label-agnostic scan: no label predicate at all, so nothing here can be attributed to the
    // planner's handling of `:Person`.
    let (rows, store) = read_at("MATCH (n) RETURN labels(n) AS ls", store, 3, 1);
    assert_eq!(
        label_names(&rows, "ls"),
        vec![vec!["Person".to_owned()]],
        "rmp #767: `labels(n)` at a snapshot older than the committed REMOVE must report the label \
         set as of that snapshot"
    );

    let (rows, _store) = read_at("MATCH (n) RETURN labels(n) AS ls", store, 4, 2);
    assert_eq!(
        label_names(&rows, "ls"),
        vec![Vec::<String>::new()],
        "at/after the removal the label set is empty"
    );
}

/// **THE CONTROL.** One transaction, one commit timestamp, changes a property AND a label; one
/// reader at one older snapshot reads both back. Everything except label-vs-property is held
/// constant, so a divergence between the two columns isolates the defect to label membership.
///
/// While #767 was open this test failed on the `ls` column ALONE — `v` read back as the old value
/// `1` (properties are MVCC-versioned, `rmp` #50 newest-VISIBLE-wins) while `ls` read back empty.
/// That asymmetry, under identical conditions, is what established the defect was store-level label
/// semantics and not a snapshot-plumbing mistake in this harness.
#[test]
fn property_change_is_snapshot_isolated_control() {
    let store = run_commit("CREATE (:Person {v: 1})", fresh_store(), 1);
    // ONE transaction, ONE commit timestamp, changing both kinds of state.
    let store = run_commit("MATCH (n:Person) SET n.v = 2 REMOVE n:Person", store, 2);

    let (rows, store) = read_at("MATCH (n) RETURN n.v AS v, labels(n) AS ls", store, 3, 1);
    assert_eq!(
        ints(&rows, "v"),
        vec![1],
        "control: the property change committed at ts 2 must be invisible at snapshot ts 1"
    );
    assert_eq!(
        label_names(&rows, "ls"),
        vec![vec!["Person".to_owned()]],
        "rmp #767: the label change committed at ts 2 must be invisible at snapshot ts 1, exactly \
         as the property change on the SAME node in the SAME transaction already is"
    );

    // And at/after the commit both changes are visible together.
    let (rows, _store) = read_at("MATCH (n) RETURN n.v AS v, labels(n) AS ls", store, 4, 2);
    assert_eq!(
        ints(&rows, "v"),
        vec![2],
        "at ts 2 the new property is visible"
    );
    assert_eq!(
        label_names(&rows, "ls"),
        vec![Vec::<String>::new()],
        "at ts 2 the label removal is visible"
    );
}

/// The mirror case: a committed label ADDITION must not become visible to an older reader either.
/// Pinned separately because the two directions go through different store calls (`add_label` vs
/// `remove_label`) and a fix that versions only one of them would still be a non-repeatable read.
#[test]
fn older_snapshot_does_not_see_a_later_committed_label_addition() {
    let store = run_commit("CREATE (:Person {v: 1})", fresh_store(), 1);
    let store = run_commit("MATCH (n:Person) SET n:Admin", store, 2);

    let (rows, store) = read_at("MATCH (n:Admin) RETURN n.v AS v", store, 3, 1);
    assert!(
        rows.is_empty(),
        "rmp #767: a reader whose snapshot predates the committed `SET n:Admin` must not match the \
         node as :Admin, got {rows:?}"
    );

    let (rows, _store) = read_at("MATCH (n:Admin) RETURN n.v AS v", store, 4, 2);
    assert_eq!(
        ints(&rows, "v"),
        vec![1],
        "a snapshot at/after the label addition matches it"
    );
}

// =================================================================================================
// The CONCURRENT dimension: an UNCOMMITTED label change must not be visible to anyone else
// =================================================================================================
//
// The tests above use `begin_at_snapshot` to model an older reader over a single-threaded store. That
// pins the non-repeatable read but cannot reach the second, strictly worse anomaly: a reader seeing a
// writer's label change BEFORE it commits. That needs two genuinely concurrent transactions, which is
// what `TxnCoordinator` provides (several `RecordStoreGraph` seams over one `Rc`-shared store).
//
// A dirty read is below READ COMMITTED. `docs/transactions.md` documents Snapshot Isolation as the
// WEAKEST tier Graphus offers (a standalone autocommit read), so this broke the guarantee for every
// tier, not only the serializable one.

mod concurrent {
    use super::*;
    use graphus_cypher::coordinator::TxnCoordinator;
    use graphus_cypher::physical::PhysicalPlan;

    type Coord = TxnCoordinator<MemBlockDevice, MemLogSink>;

    fn fresh_coord() -> Coord {
        let device = MemBlockDevice::new(0);
        let wal = WalManager::create(MemLogSink::new()).expect("create wal");
        TxnCoordinator::new(RecordStore::create(device, wal, 64, 1).expect("create store"))
    }

    /// Runs `plan` under `txn`. The error surfaces via `graph.take_error()`, NOT the row iterator.
    fn run_stmt(coord: &Coord, txn: TxnId, plan: &PhysicalPlan) -> (Vec<Row>, Option<String>) {
        let bound = bind_parameters(plan, &Parameters::new()).expect("bind");
        let mut graph = coord.statement(txn).expect("statement");
        let rows = {
            let mut cursor = execute(plan, &bound, &mut graph).expect("open cursor");
            cursor.collect_all().expect("collect")
        };
        let err = graph
            .has_error()
            .then(|| format!("{:?}", graph.take_error()));
        (rows, err)
    }

    fn seed_person(coord: &mut Coord) {
        let t0 = coord.begin_serializable();
        let (_r, err) = run_stmt(coord, t0, &compile("CREATE (:Person {v: 1})"));
        assert!(err.is_none(), "seed errored: {err:?}");
        coord.commit(t0).expect("seed commits");
    }

    /// **THE DIRTY READ (`rmp` #767).** A concurrent reader must not observe an UNCOMMITTED
    /// `REMOVE n:Person`.
    ///
    /// While the defect was open this returned `List([])` — the reader saw a label removal that had
    /// not committed and, had the writer rolled back, never existed at all.
    #[test]
    fn a_concurrent_reader_does_not_see_an_uncommitted_label_removal() {
        let mut coord = fresh_coord();
        seed_person(&mut coord);

        // W1 removes the label and does NOT commit.
        let w1 = coord.begin_serializable();
        let (_r, err) = run_stmt(&coord, w1, &compile("MATCH (n:Person) REMOVE n:Person"));
        assert!(err.is_none(), "W1 REMOVE errored: {err:?}");

        // A concurrent reader must still see the COMMITTED state.
        let r = coord.begin_serializable();
        let (rows, err) = run_stmt(&coord, r, &compile("MATCH (n) RETURN labels(n) AS l"));
        assert!(err.is_none(), "reader errored: {err:?}");
        assert_eq!(
            rows[0].value("l"),
            Value::List(vec![Value::String("Person".to_owned())]),
            "rmp #767 DIRTY READ: a concurrent reader observed W1's UNCOMMITTED label removal"
        );

        // And the label predicate agrees with the accessor.
        let (rows, err) = run_stmt(&coord, r, &compile("MATCH (n:Person) RETURN n.v AS v"));
        assert!(err.is_none(), "reader errored: {err:?}");
        assert_eq!(
            ints(&rows, "v"),
            vec![1],
            "rmp #767 DIRTY READ: `MATCH (n:Person)` matched against W1's UNCOMMITTED removal"
        );

        coord.rollback(w1).expect("W1 rolls back");
    }

    /// The mirror: an uncommitted label ADDITION must not be visible to a concurrent reader either.
    #[test]
    fn a_concurrent_reader_does_not_see_an_uncommitted_label_addition() {
        let mut coord = fresh_coord();
        seed_person(&mut coord);

        let w1 = coord.begin_serializable();
        let (_r, err) = run_stmt(&coord, w1, &compile("MATCH (n:Person) SET n:Admin"));
        assert!(err.is_none(), "W1 SET label errored: {err:?}");

        let r = coord.begin_serializable();
        let (rows, err) = run_stmt(&coord, r, &compile("MATCH (n:Admin) RETURN n.v AS v"));
        assert!(err.is_none(), "reader errored: {err:?}");
        assert!(
            rows.is_empty(),
            "rmp #767 DIRTY READ: a concurrent reader matched W1's UNCOMMITTED `SET n:Admin`, got \
             {rows:?}"
        );

        coord.rollback(w1).expect("W1 rolls back");
    }

    /// A writer must still see its OWN uncommitted label change (own-writes visibility, `04 §5.3`).
    /// Pinned because the obvious way to close the dirty read — ignoring the live word whenever a
    /// history exists — must not also hide the change from its author.
    #[test]
    fn a_writer_sees_its_own_uncommitted_label_change() {
        let mut coord = fresh_coord();
        seed_person(&mut coord);

        let w1 = coord.begin_serializable();
        let (_r, err) = run_stmt(&coord, w1, &compile("MATCH (n:Person) SET n:Admin"));
        assert!(err.is_none(), "W1 SET label errored: {err:?}");

        // Its own read, in the same transaction, must reflect it.
        let (rows, err) = run_stmt(&coord, w1, &compile("MATCH (n:Admin) RETURN n.v AS v"));
        assert!(err.is_none(), "W1 self-read errored: {err:?}");
        assert_eq!(
            ints(&rows, "v"),
            vec![1],
            "a transaction must see its own uncommitted label addition"
        );
        let (rows, err) = run_stmt(&coord, w1, &compile("MATCH (n) RETURN labels(n) AS l"));
        assert!(err.is_none(), "W1 self-read errored: {err:?}");
        assert_eq!(
            rows[0].value("l"),
            Value::List(vec![
                Value::String("Admin".to_owned()),
                Value::String("Person".to_owned())
            ]),
            "a transaction's own uncommitted label addition must show in its own `labels(n)`"
        );

        coord.rollback(w1).expect("W1 rolls back");
    }

    /// After a rolled-back label change, every reader sees the committed set again — the history entry
    /// must not strand the node on a stale value.
    #[test]
    fn a_rolled_back_label_change_leaves_the_committed_set_intact() {
        let mut coord = fresh_coord();
        seed_person(&mut coord);

        let w1 = coord.begin_serializable();
        let (_r, err) = run_stmt(&coord, w1, &compile("MATCH (n:Person) REMOVE n:Person"));
        assert!(err.is_none(), "W1 REMOVE errored: {err:?}");
        coord.rollback(w1).expect("W1 rolls back");

        let r = coord.begin_serializable();
        let (rows, err) = run_stmt(&coord, r, &compile("MATCH (n:Person) RETURN n.v AS v"));
        assert!(err.is_none(), "reader errored: {err:?}");
        assert_eq!(
            ints(&rows, "v"),
            vec![1],
            "after the rollback the committed label must be matchable again"
        );
    }
}

// =================================================================================================
// The OFF-THREAD reader seam
// =================================================================================================
//
// Everything above drives the INLINE seam (`RecordStoreGraph`). Auto-commit reads are dispatched to
// the off-thread reader pool (`rmp` #336), which reads through a different pair of types —
// `StoreReadView` + `ReadOnlyGraph` — so label snapshot isolation has to be proven there too or the
// anomaly simply moves to the path most production reads actually take.
//
// The two seams resolve labels differently in one respect worth pinning: an off-thread reader carries
// a CLONED `CommitRegistry` (captured at dispatch) but shares the label history LIVE by `Arc`. That
// combination is deliberate. Sharing the history live is what lets a reader undo a label change
// committed AFTER it was dispatched — a captured history would have no entry for it and the reader
// would fall through to the live word, which is the very defect #767 closed. The cloned registry then
// correctly reports that post-dispatch writer as not-visible.

mod off_thread {
    use super::*;
    use graphus_cypher::graph_access::GraphAccess;
    use graphus_cypher::read_only_graph::ReadOnlyGraph;
    use graphus_txn::{Snapshot, SsiReadBuffer};

    /// Builds an off-thread `ReadOnlyGraph` over `store` at snapshot `ts` — the same package the
    /// reader pool captures on the engine thread.
    fn reader_at(store: &Store, txn: u64, ts: u64) -> ReadOnlyGraph<MemBlockDevice, MemLogSink> {
        let snapshot = Snapshot::new(TxnId(txn), Timestamp(ts));
        ReadOnlyGraph::new(
            store.read_view(),
            store.token_snapshot(),
            snapshot,
            store.commit_registry().clone(),
            TxnId(txn),
            SsiReadBuffer::new(TxnId(txn)),
        )
    }

    /// The reproduction through the OFF-THREAD seam: a committed `REMOVE n:Person` must not be
    /// visible to an off-thread reader whose snapshot predates it.
    #[test]
    fn off_thread_reader_sees_labels_as_of_its_snapshot() {
        let store = run_commit("CREATE (:Person {v: 1})", fresh_store(), 1);
        let store = run_commit("MATCH (n:Person) REMOVE n:Person", store, 2);

        // Older snapshot: the label is still there, on both the accessor and the label scan.
        let ro = reader_at(&store, 3, 1);
        let scanned = ro.scan_nodes_by_label("Person");
        assert_eq!(
            scanned.len(),
            1,
            "rmp #767 (off-thread): a reader whose snapshot predates the committed REMOVE must \
             still match the node, got {scanned:?}"
        );
        assert_eq!(
            ro.node_labels(scanned[0]),
            Some(vec!["Person".to_owned()]),
            "rmp #767 (off-thread): `labels(n)` must report the set as of the reader's snapshot"
        );

        // At/after the removal the off-thread reader correctly sees it gone.
        let ro = reader_at(&store, 4, 2);
        assert!(
            ro.scan_nodes_by_label("Person").is_empty(),
            "an off-thread reader at/after the removal must not match the node"
        );
    }

    /// The off-thread seam must agree with the inline seam at the SAME snapshot. A divergence here
    /// would mean the two read paths disagree about what the database contains.
    #[test]
    fn off_thread_and_inline_agree_on_labels_at_the_same_snapshot() {
        let store = run_commit("CREATE (:Person {v: 1})", fresh_store(), 1);
        let mut store = run_commit("MATCH (n:Person) REMOVE n:Person", store, 2);

        // ABSOLUTE expected values, not just cross-seam agreement. An equivalence assertion ALONE is
        // vacuous against this defect: both seams read labels the same wrong way, so they agree
        // perfectly while both being wrong (verified — this test SURVIVES a mutation that reverts the
        // fix). Pinning the known-correct answer at each snapshot is what gives it teeth; the
        // agreement assertion then adds that neither seam drifts from the other.
        for (ts, expected) in [(1u64, 1usize), (2u64, 0usize)] {
            let off = reader_at(&store, 10 + ts, ts)
                .scan_nodes_by_label("Person")
                .len();
            let (rows, returned) = read_at("MATCH (n:Person) RETURN n.v AS v", store, 20, ts);
            store = returned;
            assert_eq!(
                off, expected,
                "rmp #767: the OFF-THREAD seam must return {expected} row(s) for :Person at ts {ts} \
                 (ts 1 predates the committed REMOVE, ts 2 is at it)"
            );
            assert_eq!(
                rows.len(),
                expected,
                "rmp #767: the INLINE seam must return {expected} row(s) for :Person at ts {ts}"
            );
            assert_eq!(
                off,
                rows.len(),
                "rmp #767: the off-thread and inline seams disagree about :Person at ts {ts}"
            );
        }
    }
}

// =================================================================================================
// GC INTERACTION — the two defects an adversarial audit of the first #767 fix found
// =================================================================================================
//
// The first cut of #767 retained each label version under the writer's RAW `VersionStamp::in_flight`
// stamp and resolved it through the `CommitRegistry`, exactly as an MVCC record header is resolved.
// For a record header that is safe, because the GC freeze sweep rewrites the header to
// `Committed(ts)` BEFORE the pass forgets the writer from the registry. The label history is not a
// record header: the freeze sweep never walks it, so its stamp stayed in-flight forever while
// `pending_gc_prune` forgot the writer — after which `CommitRegistry::outcome` maps the unknown id to
// `Aborted`, the version reads as never-committed, and every reader falls back to `base`.
//
// Both defects below are therefore GC-cadence-dependent and, being purely in-memory, HEAL ON RESTART
// while the on-disk word was correct the whole time — the worst possible diagnostic profile. They are
// pinned here through the real `RecordStore::gc` path rather than by poking `LabelHistory` directly,
// so they stay honest about reachability.

mod gc_interaction {
    use super::*;
    use graphus_core::Timestamp as Ts;

    /// Runs a real GC pass at `watermark`, as the engine's maintenance tick does.
    fn gc_at(store: &mut Store, txn: u64, watermark: Ts) {
        store.begin(TxnId(txn));
        store.gc(TxnId(txn), watermark).expect("gc");
        store.commit(TxnId(txn)).expect("gc commit");
    }

    /// **DEFECT 1: a lagging GC pass permanently resurrected a committed `REMOVE n:Person`.**
    ///
    /// The pass forgets the label writer from the `CommitRegistry` (its record headers are frozen), but
    /// nothing had settled the retained label version's stamp — so from then on the committed removal
    /// resolved as aborted and EVERY new reader saw the label come back.
    ///
    /// Closed by settling the stamp to `Committed(ts)` in `commit_prepare`, which takes the registry
    /// out of the committed path entirely.
    #[test]
    fn a_lagging_gc_pass_does_not_resurrect_a_committed_label_removal() {
        let mut store = run_commit("CREATE (:Person {v: 1})", fresh_store(), 1);
        let wm = store.snapshot_ts();
        gc_at(&mut store, 2, wm);

        // A long-running reader opens here: its snapshot is what pins the GC watermark below.
        let reader_ts = store.snapshot_ts();

        store = run_commit("MATCH (n:Person) REMOVE n:Person", store, 3);

        // Preconditions (non-vacuity): the removal is visible now, and the old snapshot still is not.
        let now = store.snapshot_ts().0;
        let (rows, s) = read_at("MATCH (n:Person) RETURN n.v AS v", store, 90, now);
        store = s;
        assert!(
            rows.is_empty(),
            "precondition: the REMOVE is visible at a fresh snapshot"
        );
        let (rows, s) = read_at("MATCH (n:Person) RETURN n.v AS v", store, 91, reader_ts.0);
        store = s;
        assert_eq!(
            ints(&rows, "v"),
            vec![1],
            "precondition: the older snapshot must still see :Person (this is #767 working)"
        );

        // THE TRAP: a GC pass whose watermark lags, because that long reader is still open.
        gc_at(&mut store, 4, reader_ts);

        // The reader departs. A brand-new snapshot must NOT see :Person again.
        let now = store.snapshot_ts().0;
        let (rows, _s) = read_at("MATCH (n:Person) RETURN n.v AS v", store, 92, now);
        assert!(
            rows.is_empty(),
            "rmp #767: a committed `REMOVE n:Person` was RESURRECTED by a lagging GC pass — the \
             retained label version's in-flight stamp was never settled, so once the pass forgot the \
             writer from the CommitRegistry the committed change read as aborted and every reader \
             fell back to the pre-change bitmap. Got {rows:?}"
        );
    }

    /// **DEFECT 2: a reclaimed physical id handed the NEW node the DEAD node's labels.**
    ///
    /// `LabelHistory` is keyed by bare physical id, and ids are reused after reclamation (`04 §2.7`).
    /// An entry outliving its node is inherited by whatever new node takes the slot — and because
    /// `resolve` ignores the live word whenever an entry exists, while the new node records no version
    /// of its own (its creator is its own in-flight writer, which `track_label_history` skips), the
    /// stale value is never overridden.
    ///
    /// Closed by purging the node's history in `reclaim_node`, before its id reaches the free list.
    /// Note the GC-time `prune` is NOT sufficient on its own: a version whose writer the registry has
    /// forgotten is unprunable, so it would strand there forever.
    #[test]
    fn a_reclaimed_and_reused_node_id_does_not_inherit_the_dead_nodes_labels() {
        let mut store = run_commit("CREATE (:Person {v: 1})", fresh_store(), 1);
        let wm = store.snapshot_ts();
        gc_at(&mut store, 2, wm);

        let reader_ts = store.snapshot_ts();
        store = run_commit("MATCH (n:Person) REMOVE n:Person", store, 3);
        // The lagging pass that strands the entry (defect 1's mechanism).
        gc_at(&mut store, 4, reader_ts);

        // The node is deleted and its slot reclaimed at a full watermark.
        store = run_commit("MATCH (n) DELETE n", store, 5);
        let wm = store.snapshot_ts();
        gc_at(&mut store, 6, wm);

        // A brand-new, completely unrelated node reuses the freed physical id.
        store = run_commit("CREATE (:Company {v: 2})", store, 7);

        let now = store.snapshot_ts().0;
        let (company, s) = read_at("MATCH (n:Company) RETURN n.v AS v", store, 90, now);
        store = s;
        let (person, _s) = read_at("MATCH (n:Person) RETURN n.v AS v", store, 91, now);
        assert_eq!(
            ints(&company, "v"),
            vec![2],
            "rmp #767: the new :Company node is INVISIBLE TO ITS OWN LABEL — it resolved its labels \
             through the reclaimed id's stranded history"
        );
        assert!(
            person.is_empty(),
            "rmp #767: the new node INHERITED :Person from the dead node that previously held its \
             physical id, got {person:?}"
        );
    }

    /// The label versions must not leak: once no reader can need them, a GC pass at a full watermark
    /// reclaims every one. `rmp` #968 moved them from the in-process history onto the node's undo
    /// chain, so what this now pins is that the chain sweep reaches label deltas exactly as it reaches
    /// property ones — a delta the sweep skipped would grow `undo.store` without bound.
    #[test]
    fn a_full_watermark_gc_pass_drains_the_label_history() {
        let mut store = run_commit("CREATE (:Person {v: 1})", fresh_store(), 1);
        store = run_commit("MATCH (n:Person) SET n:Admin", store, 2);
        assert!(
            store.live_label_delta_census().expect("census").0 > 0,
            "precondition: the relabel of an already-committed node must retain a version"
        );

        let wm = store.snapshot_ts();
        gc_at(&mut store, 3, wm);
        assert_eq!(
            store.live_label_delta_census().expect("census").0,
            0,
            "rmp #767/#968: a GC pass at a full watermark must reclaim every label delta — one the \
             chain sweep skips leaks for the life of the store and grows `undo.store` without bound"
        );
    }
}
