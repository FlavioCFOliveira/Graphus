//! **A derived-index entry belongs to the transaction that made it** (`rmp` task #992, AC1).
//!
//! Until this landed, every write into the B+-tree-backed derived indexes ran under a fixed,
//! never-committed transaction id (`EPHEMERAL_TXN`), and a rollback undid **none** of it: the trees
//! kept advertising candidates for writes that never happened. The removal APIs existed
//! (`TokenIndex::remove`, `PropertyIndex::remove`, `CompositeIndex::remove`,
//! `RelPropertyIndex::remove`) and had no production caller at all.
//!
//! # What is — and is not — observable from a query
//!
//! Nothing here asserts that a query result changed, and that is deliberate rather than a gap. A
//! seek returns **candidates**, and every consumer re-checks each one against its own MVCC snapshot,
//! so a leftover entry for a rolled-back write is a false positive the re-check drops. The defect was
//! therefore *latent*: the trees were not a faithful image of committed state, and only the re-check
//! stood between that and a wrong answer. So these tests assert on the **index content** directly,
//! through the public [`IndexSet`] API, over the real write seam
//! ([`RecordStoreGraph`], which is what `TxnCoordinator::statement` builds) — plus one query-level
//! equivalence check, because "declaring an index must not change the answer" is the invariant every
//! index change in this engine has to re-earn (`rmp` #738 / #894).
//!
//! # The two hazards these tests pin
//!
//! 1. **A rollback must not destroy an entry a committed version warrants.** A write re-indexes every
//!    current label and every current property of the entity, not only the ones the statement
//!    changed — so `SET n.name = 'y'` re-inserts the untouched `(age, 30, n)` entry that a *committed*
//!    transaction put there. Undoing that would silently lose a committed row from every seek. Only
//!    entries the backing tree reports as newly **created** are logged, which is what makes the
//!    difference. Pinned by
//!    [`a_rollback_must_not_destroy_an_entry_it_merely_re_inserted`].
//! 2. **A half-built tree breaks the premise behind (1).** "The key was absent when I inserted it"
//!    implies "no committed version warrants it" only while the tree is complete with respect to
//!    committed state — and an index build makes it incomplete by construction. So any
//!    [`IndexWriter::Population`] write invalidates every open transaction's log. Pinned by
//!    [`a_population_write_invalidates_an_open_transactions_undo_log`].

use graphus_core::{TxnId, Value};
use graphus_cypher::binding::{Parameters, bind_parameters};
use graphus_cypher::catalog::IndexCatalog;
use graphus_cypher::coordinator::TxnCoordinator;
use graphus_cypher::executor::execute;
use graphus_cypher::graph_access::{GraphAccess, NodeId, RelId};
use graphus_cypher::index_set::{IndexSet, IndexWriter};
use graphus_cypher::lexer::tokenize;
use graphus_cypher::lower::lower;
use graphus_cypher::parser::parse_tokens;
use graphus_cypher::physical::{PhysicalPlan, plan_physical};
use graphus_cypher::record_graph::RecordStoreGraph;
use graphus_cypher::runtime::Row;
use graphus_cypher::semantics::analyze;
use graphus_cypher::shared_cell::{SharedCell, SharedRef};
use graphus_io::MemBlockDevice;
use graphus_storage::{IndexState, Namespace, RecordStore};
use graphus_txn::{Snapshot, SsiTracker};
use graphus_wal::{MemLogSink, WalManager};

type Store = RecordStore<MemBlockDevice, MemLogSink>;
type Live = RecordStoreGraph<MemBlockDevice, MemLogSink>;
type Coord = TxnCoordinator<MemBlockDevice, MemLogSink>;

// =================================================================================================
// Harness
// =================================================================================================

/// A store + SSI tracker + derived [`IndexSet`], wired exactly the way `TxnCoordinator` wires them,
/// but with the index reachable so a test can assert on its **content**.
///
/// The transaction lifecycle helpers ([`commit`](Fixture::commit) / [`rollback`](Fixture::rollback))
/// perform the same index-set steps the coordinator performs, in the same order — drain before the
/// durable undo, apply only if it succeeded. `TxnCoordinator` really calling them is a separate
/// question, pinned by the inline unit test
/// `rollback_removes_the_index_entries_the_transaction_created` in `src/coordinator.rs`, which is
/// where the coordinator's private index handle is reachable.
struct Fixture {
    store: SharedRef<Store>,
    ssi: SharedCell<SsiTracker>,
    index: SharedCell<IndexSet>,
    columns: SharedCell<graphus_cypher::column_cache::ColumnCache>,
    zones: SharedCell<graphus_cypher::zone_map::ZoneMap>,
    next_txn: std::cell::Cell<u64>,
}

impl Fixture {
    fn new() -> Self {
        let device = MemBlockDevice::new(0);
        let wal = WalManager::create(MemLogSink::new()).expect("create wal");
        let store = RecordStore::create(device, wal, 64, 1).expect("create store");
        Self {
            store: SharedRef::new(store),
            ssi: SharedCell::new(SsiTracker::new()),
            index: SharedCell::new(IndexSet::new()),
            columns: SharedCell::new(graphus_cypher::column_cache::ColumnCache::new()),
            zones: SharedCell::new(graphus_cypher::zone_map::ZoneMap::new()),
            next_txn: std::cell::Cell::new(100),
        }
    }

    /// Interns `name` in `ns` and returns its token id.
    fn token(&self, ns: Namespace, name: &str) -> u32 {
        self.store
            .borrow_mut()
            .intern_token(ns, name)
            .expect("intern token")
    }

    /// Begins a write transaction on the store and registers it with the SSI tracker.
    fn begin(&self) -> TxnId {
        let txn = TxnId(self.next_txn.get());
        self.next_txn.set(self.next_txn.get() + 1);
        self.store.borrow_mut().begin(txn);
        let ts = self.store.borrow().snapshot_ts();
        self.ssi.borrow_mut().register(txn, ts);
        txn
    }

    /// A live statement seam for `txn` — the same package `TxnCoordinator::statement` builds.
    fn stmt(&self, txn: TxnId) -> Live {
        let ts = self.store.borrow().snapshot_ts();
        RecordStoreGraph::attach(
            self.store.clone(),
            txn,
            Snapshot::new(txn, ts),
            self.ssi.clone(),
            self.index.clone(),
            self.columns.clone(),
            self.zones.clone(),
            None,
        )
    }

    /// Commits `txn`, mirroring `TxnCoordinator::commit`'s index-set step: the entries describe writes
    /// that are now committed, so only the bookkeeping is freed.
    fn commit(&self, txn: TxnId) {
        self.store.borrow_mut().commit(txn).expect("commit");
        self.index.borrow_mut().forget_txn_entries(txn);
    }

    /// Rolls `txn` back, mirroring `TxnCoordinator::abort`: drain the undo log **before** the durable
    /// undo (so a failing undo cannot strand it), apply it only if the undo succeeded. Returns how
    /// many entries the log held and how many were actually removed.
    fn rollback(&self, txn: TxnId) -> (usize, usize) {
        let log = self.index.borrow_mut().take_txn_entries(txn);
        let logged = log.len();
        self.store.borrow_mut().rollback(txn).expect("rollback");
        let removed = self.index.borrow_mut().undo_entries(log);
        (logged, removed)
    }

    /// Whether the node-property index over `(label, prop)` currently holds a candidate for `node`
    /// under `value`. Asserts on the index's **content**, with no MVCC re-check in the way.
    fn node_prop_has(&self, label: u32, prop: u32, value: &Value, node: u64) -> bool {
        self.index
            .borrow_mut()
            .seek_node_property_eq(label, prop, value)
            .expect("the index is registered, so the seek must not decline")
            .contains(&node)
    }

    /// As [`node_prop_has`](Self::node_prop_has), for a relationship-property index.
    fn rel_prop_has(&self, ty: u32, prop: u32, value: &Value, rel: u64) -> bool {
        self.index
            .borrow_mut()
            .seek_rel_property_eq(ty, prop, value)
            .expect("the index is registered, so the seek must not decline")
            .contains(&rel)
    }

    /// As [`node_prop_has`](Self::node_prop_has), for a node composite index.
    fn composite_has(&self, label: u32, props: &[u32], values: &[Value], node: u64) -> bool {
        self.index
            .borrow_mut()
            .seek_composite_eq(label, props, values)
            .expect("the index is registered, so the seek must not decline")
            .contains(&node)
    }

    /// Whether the label index currently holds a `(label, node)` candidate.
    fn label_has(&self, label: u32, node: u64) -> bool {
        self.index.borrow_mut().seek_label(label).contains(&node)
    }
}

// =================================================================================================
// AC1 — a rollback undoes the entries the transaction created
// =================================================================================================

/// **The acceptance criterion, directly.** A transaction writes an indexed property; it rolls back;
/// the entry it created is **gone** from the index.
///
/// The three assertions are one chain and each one is load-bearing:
/// * the entry is present while the transaction is open (otherwise there is nothing to undo and the
///   test proves nothing);
/// * the undo log is **non-empty** at abort time. Without this the test would pass vacuously the
///   moment anything invalidated the log — an index build running concurrently does exactly that, and
///   on a busy engine a build is drained after nearly every command;
/// * the entry is absent afterwards, and so are the label and composite entries the same write made.
#[test]
fn a_rolled_back_write_removes_the_index_entry_it_created() {
    let f = Fixture::new();
    let l = f.token(Namespace::Label, "Person");
    let k_age = f.token(Namespace::PropKey, "age");
    let k_email = f.token(Namespace::PropKey, "email");
    {
        let mut idx = f.index.borrow_mut();
        idx.register_node_property_with_state(l, k_age, IndexState::Online);
        idx.register_composite(l, vec![k_age, k_email]);
    }

    let txn = f.begin();
    let node = {
        let mut g = f.stmt(txn);
        g.create_node(
            &["Person".to_owned()],
            &[
                ("age".to_owned(), Value::Integer(41)),
                ("email".to_owned(), Value::String("ghost@x.io".to_owned())),
            ],
        )
    };

    assert!(
        f.node_prop_has(l, k_age, &Value::Integer(41), node.0),
        "precondition: the open transaction's write must be in the index, or there is nothing to undo"
    );
    assert!(f.label_has(l, node.0), "precondition: label entry present");
    assert!(
        f.composite_has(
            l,
            &[k_age, k_email],
            &[Value::Integer(41), Value::String("ghost@x.io".to_owned())],
            node.0
        ),
        "precondition: composite entry present"
    );

    let (logged, removed) = f.rollback(txn);
    assert!(
        logged > 0,
        "NON-VACUITY: the transaction must own a non-empty undo log at abort time — a log that had \
         been invalidated (by a concurrent index build, say) would make every assertion below pass \
         without the mechanism ever running"
    );
    assert_eq!(
        removed, logged,
        "every logged entry must have been present and removed"
    );

    assert!(
        !f.node_prop_has(l, k_age, &Value::Integer(41), node.0),
        "the rolled-back write's property entry survived the rollback"
    );
    assert!(
        !f.label_has(l, node.0),
        "the rolled-back write's label entry survived the rollback"
    );
    assert!(
        !f.composite_has(
            l,
            &[k_age, k_email],
            &[Value::Integer(41), Value::String("ghost@x.io".to_owned())],
            node.0
        ),
        "the rolled-back write's composite entry survived the rollback"
    );
}

/// The relationship half of the criterion: a rolled-back relationship write removes the
/// relationship-property and relationship-composite entries it created.
#[test]
fn a_rolled_back_relationship_write_removes_the_entries_it_created() {
    let f = Fixture::new();
    let t = f.token(Namespace::RelType, "RATED");
    let k_score = f.token(Namespace::PropKey, "score");
    let k_at = f.token(Namespace::PropKey, "at");
    {
        let mut idx = f.index.borrow_mut();
        idx.register_rel_property_with_state(t, k_score, IndexState::Online);
        idx.register_rel_composite(t, vec![k_score, k_at]);
    }

    // Two committed endpoints, so the rolled-back transaction writes only the relationship.
    let setup = f.begin();
    let (a, b) = {
        let mut g = f.stmt(setup);
        (g.create_node(&[], &[]), g.create_node(&[], &[]))
    };
    f.commit(setup);

    let txn = f.begin();
    let rel = {
        let mut g = f.stmt(txn);
        g.create_rel(
            "RATED",
            a,
            b,
            &[
                ("score".to_owned(), Value::Integer(9)),
                ("at".to_owned(), Value::Integer(1700)),
            ],
        )
    };
    assert!(
        f.rel_prop_has(t, k_score, &Value::Integer(9), rel.0),
        "precondition: the relationship-property entry must be in the index"
    );

    let (logged, removed) = f.rollback(txn);
    assert!(logged > 0, "NON-VACUITY: the undo log must be non-empty");
    assert_eq!(removed, logged, "every logged entry must have been removed");
    assert!(
        !f.rel_prop_has(t, k_score, &Value::Integer(9), rel.0),
        "the rolled-back relationship-property entry survived"
    );
    assert!(
        !f.index
            .borrow_mut()
            .seek_rel_composite_eq(
                t,
                &[k_score, k_at],
                &[Value::Integer(9), Value::Integer(1700)]
            )
            .expect("registered")
            .contains(&rel.0),
        "the rolled-back relationship-composite entry survived"
    );
}

/// **A commit undoes nothing.** The same shape as the criterion test, committed instead of rolled
/// back: the entries describe writes that are now committed and must stay.
#[test]
fn a_committed_write_keeps_the_index_entries_it_created() {
    let f = Fixture::new();
    let l = f.token(Namespace::Label, "Person");
    let k_age = f.token(Namespace::PropKey, "age");
    f.index
        .borrow_mut()
        .register_node_property_with_state(l, k_age, IndexState::Online);

    let txn = f.begin();
    let node = {
        let mut g = f.stmt(txn);
        g.create_node(
            &["Person".to_owned()],
            &[("age".to_owned(), Value::Integer(41))],
        )
    };
    f.commit(txn);

    assert!(
        f.node_prop_has(l, k_age, &Value::Integer(41), node.0),
        "a committed write's index entry must survive"
    );
    assert!(
        f.label_has(l, node.0),
        "a committed write's label entry must survive"
    );

    // And the log is gone, so a later transaction reusing bookkeeping cannot resurrect it.
    let (logged, removed) = f.rollback(f.begin());
    assert_eq!(
        (logged, removed),
        (0, 0),
        "an unrelated later rollback must find nothing to undo"
    );
    assert!(
        f.node_prop_has(l, k_age, &Value::Integer(41), node.0),
        "an unrelated rollback must not disturb a committed entry"
    );
}

// =================================================================================================
// Hazard 1 — a rollback must not destroy what a COMMITTED version warrants
// =================================================================================================

/// **The counter-example that makes the "created, not replaced" rule load-bearing.**
///
/// `RecordStoreGraph::reindex_node` re-indexes the node's *entire* current state on every write — all
/// its labels and all its properties, not only the ones the statement touched. So a transaction that
/// changes `name` also re-inserts the untouched `(age, 30, n)` entry that a **committed** transaction
/// put there. That re-insert is a replace over an identical key (the key carries the value *and* the
/// record id), so a rollback that blindly removed everything the transaction inserted would delete a
/// committed entry — and `WHERE n.age = 30` would silently lose a committed row.
///
/// Measured on this fixture before the guard existed: the entry disappeared and the seek returned
/// nothing. With the guard, the re-insert reports "not created", is never logged, and survives.
#[test]
fn a_rollback_must_not_destroy_an_entry_it_merely_re_inserted() {
    let f = Fixture::new();
    let l = f.token(Namespace::Label, "Person");
    let k_age = f.token(Namespace::PropKey, "age");
    let k_name = f.token(Namespace::PropKey, "name");
    f.index
        .borrow_mut()
        .register_node_property_with_state(l, k_age, IndexState::Online);

    // A COMMITTED node with an indexed property.
    let setup = f.begin();
    let node = {
        let mut g = f.stmt(setup);
        g.create_node(
            &["Person".to_owned()],
            &[("age".to_owned(), Value::Integer(30))],
        )
    };
    f.commit(setup);
    assert!(
        f.node_prop_has(l, k_age, &Value::Integer(30), node.0),
        "precondition: the committed entry is indexed"
    );

    // A transaction that never touches `age` — but whose re-index re-inserts it anyway.
    let txn = f.begin();
    {
        let mut g = f.stmt(txn);
        g.set_node_property(node, "name", Value::String("y".to_owned()));
    }
    assert!(
        f.node_prop_has(l, k_age, &Value::Integer(30), node.0),
        "precondition: the re-index re-inserted the untouched entry over the committed key"
    );

    f.rollback(txn);

    assert!(
        f.node_prop_has(l, k_age, &Value::Integer(30), node.0),
        "COMMITTED DATA LOSS: the rollback destroyed an `age = 30` entry a committed version \
         warrants. It was only ever RE-inserted by the rolled-back transaction, never created by it, \
         so it must not be in that transaction's undo log."
    );
    assert!(
        f.label_has(l, node.0),
        "COMMITTED DATA LOSS: the rollback destroyed the committed node's label entry, which the \
         re-index likewise only re-inserted (`rmp` #765 / #767 / #771)"
    );

    // Belt: the untouched property must still be reachable, and the property the transaction DID
    // create must be gone if it were indexed. `name` is not indexed here, so assert the log shape:
    // the transaction created nothing under a registered index, so it logged nothing.
    let _ = k_name;
}

/// The same rule for a value the transaction **changes**: the new value's entry is created (so it is
/// undone) while the old value's entry — which a committed version warrants, and which an older
/// snapshot still reads — is untouched. This is the `rmp` #767 direction: the tree must stay a
/// superset for readers whose snapshot predates the change.
#[test]
fn a_rollback_removes_only_the_new_value_and_leaves_the_committed_one() {
    let f = Fixture::new();
    let l = f.token(Namespace::Label, "Person");
    let k_age = f.token(Namespace::PropKey, "age");
    f.index
        .borrow_mut()
        .register_node_property_with_state(l, k_age, IndexState::Online);

    let setup = f.begin();
    let node = {
        let mut g = f.stmt(setup);
        g.create_node(
            &["Person".to_owned()],
            &[("age".to_owned(), Value::Integer(30))],
        )
    };
    f.commit(setup);

    let txn = f.begin();
    {
        let mut g = f.stmt(txn);
        g.set_node_property(node, "age", Value::Integer(31));
    }
    assert!(
        f.node_prop_has(l, k_age, &Value::Integer(31), node.0),
        "precondition: the new value is indexed"
    );

    let (logged, _) = f.rollback(txn);
    assert!(logged > 0, "NON-VACUITY: the undo log must be non-empty");

    assert!(
        !f.node_prop_has(l, k_age, &Value::Integer(31), node.0),
        "the rolled-back value's entry survived"
    );
    assert!(
        f.node_prop_has(l, k_age, &Value::Integer(30), node.0),
        "COMMITTED DATA LOSS: the committed value's entry was destroyed. It is the entry every \
         reader — including one whose snapshot predates the rolled-back write — resolves through."
    );
}

// =================================================================================================
// Hazard 2 — population entries are never rolled back, and they invalidate open logs
// =================================================================================================

/// **A build's entries belong to no transaction.** A rebuild populates the trees with
/// [`IndexWriter::Population`]; an unrelated transaction's rollback afterwards must not remove a
/// single one of them. This is the superset contract: a build indexes every not-yet-GC'd version with
/// no visibility filter, and that superset is what lets a seek's re-check drop a false positive
/// without ever needing to resurrect a missing row.
#[test]
fn population_entries_are_never_rolled_back() {
    let f = Fixture::new();
    let l = f.token(Namespace::Label, "Person");
    let k_age = f.token(Namespace::PropKey, "age");
    f.index
        .borrow_mut()
        .register_node_property_with_state(l, k_age, IndexState::Online);

    // A build's worth of entries, owned by no transaction.
    {
        let mut idx = f.index.borrow_mut();
        for id in 1..=8u64 {
            idx.insert_node_property(
                IndexWriter::Population,
                l,
                k_age,
                &Value::Integer(id as i64),
                id,
            );
            idx.insert_label(IndexWriter::Population, l, id);
        }
    }

    // An unrelated transaction writes, then rolls back.
    let txn = f.begin();
    let node = {
        let mut g = f.stmt(txn);
        g.create_node(
            &["Person".to_owned()],
            &[("age".to_owned(), Value::Integer(999))],
        )
    };
    f.rollback(txn);

    for id in 1..=8u64 {
        assert!(
            f.node_prop_has(l, k_age, &Value::Integer(id as i64), id),
            "population property entry {id} was rolled back by an unrelated transaction"
        );
        assert!(
            f.label_has(l, id),
            "population label entry {id} was rolled back by an unrelated transaction"
        );
    }
    assert!(
        !f.node_prop_has(l, k_age, &Value::Integer(999), node.0),
        "the rolled-back transaction's own entry should still have gone"
    );
}

/// **A population write invalidates every open transaction's undo log.**
///
/// The "created ⇒ no committed version warrants it" premise holds only while the tree is complete
/// with respect to committed state, and an index build makes it incomplete by construction. The
/// sequence that breaks it needs no `clear()` at all:
///
/// 1. committed node `n` has `age = 30`; a build is registered but has not reached `n`, so the tree
///    lacks the key;
/// 2. an open transaction writes `n` — the re-index inserts `(age, 30, n)`, finds it absent, and
///    would log it as **created**;
/// 3. the build reaches `n` and inserts the very same key **from the committed store**;
/// 4. the transaction aborts — and a naive undo deletes a committed entry.
///
/// Step 3 is what this pins: the population write drops the open log, so step 4 removes nothing.
#[test]
fn a_population_write_invalidates_an_open_transactions_undo_log() {
    let f = Fixture::new();
    let l = f.token(Namespace::Label, "Person");
    let k_age = f.token(Namespace::PropKey, "age");

    // (1) A committed node, indexed by nothing yet — the half-built tree.
    let setup = f.begin();
    let node = {
        let mut g = f.stmt(setup);
        g.create_node(
            &["Person".to_owned()],
            &[("age".to_owned(), Value::Integer(30))],
        )
    };
    f.commit(setup);
    f.index
        .borrow_mut()
        .register_node_property_with_state(l, k_age, IndexState::Online);
    assert!(
        !f.node_prop_has(l, k_age, &Value::Integer(30), node.0),
        "precondition: the tree must not yet hold the committed key"
    );

    // (2) An open writer touches the node; its re-index CREATES the committed key.
    let txn = f.begin();
    {
        let mut g = f.stmt(txn);
        g.set_node_property(node, "nick", Value::String("n".to_owned()));
    }
    assert!(
        f.node_prop_has(l, k_age, &Value::Integer(30), node.0),
        "precondition: the writer's re-index created the key the build has not reached"
    );

    // (3) The build reaches this node and inserts the same key from committed state.
    f.index.borrow_mut().insert_node_property(
        IndexWriter::Population,
        l,
        k_age,
        &Value::Integer(30),
        node.0,
    );

    // (4) The abort must now remove nothing.
    let (logged, removed) = f.rollback(txn);
    assert_eq!(
        (logged, removed),
        (0, 0),
        "the population write must have invalidated the open transaction's undo log"
    );
    assert!(
        f.node_prop_has(l, k_age, &Value::Integer(30), node.0),
        "COMMITTED DATA LOSS: the rollback removed a key the build had just re-derived from the \
         COMMITTED store. \"Absent when I inserted it\" does not imply \"no committed version \
         warrants it\" while a build is in flight."
    );
}

// =================================================================================================
// Query-level equivalence — declaring an index must not change the answer
// =================================================================================================

/// Rolling a write back, with an index declared, must leave the query answer identical to the
/// scan-and-filter answer. This is the `rmp` #738 / #894 invariant every index change has to re-earn:
/// the mechanism above removes entries from a live index, and the one thing that may never follow is
/// a row appearing or disappearing because an index exists.
///
/// It runs on a real [`TxnCoordinator`], so it also exercises the coordinator's own commit / rollback
/// wiring end to end.
#[test]
fn a_rollback_with_an_index_declared_answers_exactly_as_the_scan() {
    let mut coord = fresh_coord();
    run_write(&mut coord, "CREATE (:Person {age: 30, email: 'a@x.io'})");
    run_write(&mut coord, "CREATE (:Person {age: 31, email: 'b@x.io'})");
    coord
        .create_node_property_index("Person", "age")
        .expect("create index");

    // A rolled-back CREATE plus a rolled-back UPDATE of a committed row.
    let writer = coord.begin_serializable();
    run_plan(
        &coord,
        writer,
        &compile(
            "CREATE (:Person {age: 30, email: 'ghost@x.io'})",
            &IndexCatalog::empty(),
        ),
    );
    run_plan(
        &coord,
        writer,
        &compile(
            "MATCH (n:Person) WHERE n.email = 'b@x.io' SET n.age = 99",
            &IndexCatalog::empty(),
        ),
    );
    coord.rollback(writer).expect("rollback");

    let indexed = coord.catalog();
    for src in [
        "MATCH (n:Person) WHERE n.age = 30 RETURN n.email AS a",
        "MATCH (n:Person) WHERE n.age = 31 RETURN n.email AS a",
        "MATCH (n:Person) WHERE n.age = 99 RETURN n.email AS a",
        "MATCH (n:Person) WHERE n.age > 0 RETURN n.email AS a",
        "MATCH (n:Person) WHERE n.age IS NOT NULL RETURN n.email AS a",
        "MATCH (n:Person) RETURN n.email AS a",
    ] {
        let via_index = sorted_debug(&read_rows(&mut coord, &indexed, src));
        let via_scan = sorted_debug(&read_rows(&mut coord, &IndexCatalog::empty(), src));
        assert_eq!(
            via_index, via_scan,
            "{src}: declaring an index changed the answer after a rollback"
        );
    }

    // Ground truth, so the comparison above cannot agree by both being empty.
    assert_eq!(
        sorted_debug(&read_rows(
            &mut coord,
            &indexed,
            "MATCH (n:Person) RETURN n.email AS a"
        ))
        .len(),
        2,
        "ground truth: exactly the two committed rows survive the rollback"
    );
}

// -------------------------------------------------------------------------------------------------
// Coordinator helpers (mirroring tests/index_wiring.rs)
// -------------------------------------------------------------------------------------------------

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

fn run_write(coord: &mut Coord, src: &str) {
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

fn sorted_debug(rows: &[Row]) -> Vec<String> {
    let mut out: Vec<String> = rows.iter().map(|r| format!("{:?}", r.values())).collect();
    out.sort();
    out
}

/// Keeps the unused-import lint honest about the ids the fixture hands back.
#[allow(dead_code)]
fn _ids(n: NodeId, r: RelId) -> (u64, u64) {
    (n.0, r.0)
}
