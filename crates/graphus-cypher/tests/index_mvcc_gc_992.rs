//! **The version GC collects the derived-index entries dead versions leave behind** (`rmp` task #992,
//! AC2).
//!
//! Slice 1 gave an index entry an owner, so a rollback could take back what a transaction created.
//! This is the other end of the same problem. `record_graph::reindex_node` re-indexes an entity's
//! **whole current state** on every write and only ever inserts, so `SET n.age = 31` over `age = 30`
//! leaves `(age, 30, n)` in the tree for ever — and the index grew with the number of versions of a
//! rewritten key, which is precisely what `04 §6.3` promises it does not.
//!
//! # What is under test here, and what is under test elsewhere
//!
//! The **measurement** the acceptance criterion asks for — index entries against the number of
//! versions — is in `src/coordinator.rs`'s `index_gc_collection_992` module, because it must run on a
//! real [`TxnCoordinator`] whose index handle is private.
//!
//! This file pins the two things that module cannot:
//!
//! 1. the **public seam** `IndexSet::collect_dead_keys` — its contract, key by key, including every
//!    case in which it must refuse to remove. A seam whose only test is an end-to-end one is a seam
//!    whose contract can be silently narrowed by a change three layers away (`rmp` #894);
//! 2. **query-level equivalence** — declaring an index must not change the answer, after the
//!    collection has run. That is the invariant every index change in this engine has to re-earn
//!    (`rmp` #680 / #738 / #894), and it is the only assertion here that a user could observe.
//!
//! # Why the seam tests build their own dead keys
//!
//! `IndexSet::collect_dead_keys` takes a `&[DeadIndexKey]` and a witness map, both of which are
//! ordinary public values. Handing it a hand-built key is not a mock of the storage layer: it is the
//! only way to state, in a test, "*this* key with *this* evidence must produce *this* decision" —
//! including the decisions that a store cannot be persuaded to emit on demand, such as a witness that
//! could not be read at all. That the store really emits these keys, and that the coordinator really
//! drives this method, is exactly what the coordinator module proves.

use std::collections::HashMap;

use graphus_core::{TxnId, Value};
use graphus_cypher::binding::{Parameters, bind_parameters};
use graphus_cypher::catalog::IndexCatalog;
use graphus_cypher::coordinator::TxnCoordinator;
use graphus_cypher::executor::execute;
use graphus_cypher::index_set::{DeadKeyEvidence, IndexSet, IndexWriter};
use graphus_cypher::lexer::tokenize;
use graphus_cypher::lower::lower;
use graphus_cypher::parser::parse_tokens;
use graphus_cypher::physical::{PhysicalPlan, plan_physical};
use graphus_cypher::runtime::Row;
use graphus_cypher::semantics::analyze;
use graphus_io::MemBlockDevice;
use graphus_storage::{DeadIndexKey, IndexState, RecordStore, StoreKind};
use graphus_wal::{MemLogSink, WalManager};

type Coord = TxnCoordinator<MemBlockDevice, MemLogSink>;

/// The GC pass's own transaction id, under which the removals run.
const GC_TXN: TxnId = TxnId(9_000);

const LABEL: u32 = 1;
const PROP: u32 = 7;
const NODE: u64 = 42;

// =================================================================================================
// Seam helpers
// =================================================================================================

/// An [`IndexSet`] with one node-property index over `(LABEL, PROP)` holding `values` for [`NODE`],
/// as a committed writer would have left them.
fn index_holding(values: &[Value]) -> IndexSet {
    let mut index = IndexSet::new();
    index.register_node_property_with_state(LABEL, PROP, IndexState::Online);
    for value in values {
        index.insert_node_property(IndexWriter::Txn(TxnId(1)), LABEL, PROP, value, NODE);
        index.insert_label(IndexWriter::Txn(TxnId(1)), LABEL, NODE);
    }
    index
}

/// A witness saying [`NODE`] is live, carries `labels`, and holds `values` for [`PROP`].
fn witness(values: &[Value], labels: &[u32]) -> HashMap<(StoreKind, u64), DeadKeyEvidence> {
    let mut map = HashMap::new();
    map.insert(
        (StoreKind::Node, NODE),
        DeadKeyEvidence {
            property_versions: values.iter().map(|v| (PROP, v.clone())).collect(),
            labels: labels.to_vec(),
            in_use: true,
        },
    );
    map
}

fn dead_property(value: Value) -> DeadIndexKey {
    DeadIndexKey::Property {
        kind: StoreKind::Node,
        entity: NODE,
        key: PROP,
        value,
    }
}

fn offers(index: &mut IndexSet, value: &Value) -> bool {
    index
        .seek_node_property_eq(LABEL, PROP, value)
        .expect("the index is registered, so the seek must not decline")
        .contains(&NODE)
}

// =================================================================================================
// The seam contract: when a key may be honoured, and when it must not be
// =================================================================================================

/// The plain case: a value no surviving version holds is removed.
#[test]
fn a_key_no_live_version_warrants_is_removed() {
    let mut index = index_holding(&[Value::Integer(30), Value::Integer(31)]);
    let keys = [dead_property(Value::Integer(30))];
    let out = index.collect_dead_keys(GC_TXN, &keys, &witness(&[Value::Integer(31)], &[LABEL]));

    assert_eq!(out.entries_removed, 1, "the dead entry was not removed");
    assert_eq!(out.keys_retained, 0, "nothing should have been retained");
    assert!(!offers(&mut index, &Value::Integer(30)));
    assert!(
        offers(&mut index, &Value::Integer(31)),
        "the live value's entry must be untouched"
    );
}

/// **The `a → b → a` case.** A dead version held `30`; so does the live one. The key is honest — that
/// version really is gone — and honouring it would delete the live row's only entry, which no seek
/// could ever resurrect. This is the single case the whole re-check exists for.
#[test]
fn a_key_the_live_version_still_warrants_is_retained() {
    let mut index = index_holding(&[Value::Integer(30), Value::Integer(31)]);
    let keys = [dead_property(Value::Integer(30))];
    let out = index.collect_dead_keys(GC_TXN, &keys, &witness(&[Value::Integer(30)], &[LABEL]));

    assert_eq!(out.entries_removed, 0);
    assert_eq!(
        out.keys_retained, 1,
        "NON-VACUITY: the key must have been considered and refused, not skipped"
    );
    assert!(
        offers(&mut index, &Value::Integer(30)),
        "COMMITTED ROW LOST: a value the live version still holds was collected"
    );
}

/// **An entity with no witness keeps everything.** A store read that faulted proves nothing, and
/// "cannot prove it dead" must never be treated as "proved dead" — only one of those two mistakes
/// loses a row.
#[test]
fn a_key_with_no_witness_is_retained() {
    let mut index = index_holding(&[Value::Integer(30)]);
    let keys = [dead_property(Value::Integer(30))];
    let out = index.collect_dead_keys(GC_TXN, &keys, &HashMap::new());

    assert_eq!(out.entries_removed, 0);
    assert_eq!(out.keys_retained, 1);
    assert!(
        offers(&mut index, &Value::Integer(30)),
        "an entry was removed on no evidence at all"
    );
}

/// **The comparison happens in the index-key domain, not in Cypher's.**
///
/// `Integer(30)` and `Float(30.0)` are Cypher-equal but occupy **different** index keys, because the
/// order-preserving encoding appends a numeric-type tie-break (`rmp` #466). So a live `Float(30.0)`
/// does *not* warrant the `Integer(30)` entry — and a removal decided by Cypher equality would leave
/// the dead `Integer(30)` entry behind for ever, which is the growth this task removes.
///
/// It must also delete the **integer** entry specifically, because `PropertyIndex::remove` is
/// byte-exact on the encoded key. That cannot be observed through a seek: `seek_node_property_eq`
/// deliberately probes the whole Cypher-equal numeric class and unions the matches (`rmp` #466), so it
/// answers the same for either survivor. The entry census plus a second, float-keyed collection is
/// what makes the assertion decisive — measured, after the first version of this test passed on
/// `entries_removed` alone while asserting a seek that could not fail.
#[test]
fn cypher_equal_but_differently_keyed_values_do_not_warrant_each_other() {
    let mut index = index_holding(&[Value::Integer(30), Value::Float(30.0)]);
    assert_eq!(
        index.node_property_entry_count(LABEL, PROP),
        Some(2),
        "precondition: the two Cypher-equal values occupy two DISTINCT entries"
    );

    let keys = [dead_property(Value::Integer(30))];
    let out = index.collect_dead_keys(GC_TXN, &keys, &witness(&[Value::Float(30.0)], &[LABEL]));

    assert_eq!(
        (out.entries_removed, out.keys_retained),
        (1, 0),
        "a live `Float(30.0)` must not warrant the `Integer(30)` entry — they are different keys"
    );
    assert_eq!(index.node_property_entry_count(LABEL, PROP), Some(1));

    // Which one survived? Ask for the float's own key back: if it is still there, the byte-exact
    // removal took the integer entry and only the integer entry.
    let float_key = [dead_property(Value::Float(30.0))];
    let out = index.collect_dead_keys(GC_TXN, &float_key, &witness(&[], &[LABEL]));
    assert_eq!(
        out.entries_removed, 1,
        "the surviving entry was not the live float's — an integer-keyed removal deleted it"
    );
    assert_eq!(index.node_property_entry_count(LABEL, PROP), Some(0));
}

/// **The other direction of the same rule, and the dangerous one.** The index key is *coarsening* for
/// a `Duration`: it is the approximate length `duration_order_nanos`, so `duration({days: 1})` and
/// `duration({seconds: 86400})` are different values that occupy **one** key (`rmp` #894's lossy-key
/// class, verified against `keycodec::encode_single` rather than assumed).
///
/// A removal decided by value inequality would therefore delete the live `duration({seconds: 86400})`
/// row's entry while honouring a dead key for `duration({days: 1})` — the entry is shared, so deleting
/// "the dead one" deletes the live one. Only a comparison in the key domain sees that.
///
/// This is the test that gives `same_index_key` its teeth: it is the *only* one that fails when the
/// comparison is weakened to `Value` equality, because for every numeric pair the two agree.
#[test]
fn two_values_sharing_one_index_key_warrant_each_other() {
    let one_day = Value::Duration(graphus_core::Duration {
        months: 0,
        days: 1,
        seconds: 0,
        nanos: 0,
    });
    let same_span = Value::Duration(graphus_core::Duration {
        months: 0,
        days: 0,
        seconds: 86_400,
        nanos: 0,
    });
    assert_ne!(
        one_day, same_span,
        "precondition: the two durations are DIFFERENT values"
    );

    let mut index = index_holding(std::slice::from_ref(&one_day));
    assert_eq!(
        index.node_property_entry_count(LABEL, PROP),
        Some(1),
        "precondition: and they share ONE index entry"
    );

    // The version holding `one_day` died; the live version holds `same_span`, which occupies the very
    // entry the dead key names.
    let keys = [dead_property(one_day.clone())];
    let out = index.collect_dead_keys(
        GC_TXN,
        &keys,
        &witness(std::slice::from_ref(&same_span), &[LABEL]),
    );

    assert_eq!(
        out.keys_retained, 1,
        "the shared entry must be RETAINED: a live value occupies it"
    );
    assert_eq!(
        index.node_property_entry_count(LABEL, PROP),
        Some(1),
        "COMMITTED ROW LOST: removing the dead duration's key deleted the live duration's entry — \
         they are the same key, so the comparison must be made in the key domain"
    );
    assert!(
        offers(&mut index, &same_span),
        "the live duration is no longer a candidate for its own value"
    );
}

/// A value that has no index key at all (`Null` is *absent* for indexing) never produced an entry, so
/// it is not a decision: nothing is removed and nothing is counted as retained.
#[test]
fn an_unindexable_dead_value_is_not_a_decision() {
    let mut index = index_holding(&[Value::Integer(30)]);
    let keys = [dead_property(Value::Null)];
    let out = index.collect_dead_keys(GC_TXN, &keys, &witness(&[Value::Integer(30)], &[LABEL]));

    assert_eq!(
        (out.entries_removed, out.keys_retained, out.entities_purged),
        (0, 0, 0)
    );
    assert!(offers(&mut index, &Value::Integer(30)));
}

/// A lost label takes the `(label, node)` entry **and** the property entries filed under that label,
/// while the values themselves stay live.
#[test]
fn a_lost_label_takes_the_entries_filed_under_it() {
    let mut index = index_holding(&[Value::Integer(30)]);
    assert!(index.seek_label(LABEL).contains(&NODE), "precondition");

    let keys = [DeadIndexKey::Label {
        node: NODE,
        label: LABEL,
    }];
    // The node is alive and still holds `30`; it simply no longer carries `LABEL`.
    let out = index.collect_dead_keys(GC_TXN, &keys, &witness(&[Value::Integer(30)], &[]));

    assert_eq!(
        out.entries_removed, 2,
        "both the label entry and the property entry filed under it must go"
    );
    assert!(!index.seek_label(LABEL).contains(&NODE));
    assert!(!offers(&mut index, &Value::Integer(30)));
}

/// A label the node still carries is not collected — the mirror of the property re-check.
#[test]
fn a_label_the_node_still_carries_is_retained() {
    let mut index = index_holding(&[Value::Integer(30)]);
    let keys = [DeadIndexKey::Label {
        node: NODE,
        label: LABEL,
    }];
    let out = index.collect_dead_keys(GC_TXN, &keys, &witness(&[Value::Integer(30)], &[LABEL]));

    assert_eq!(out.entries_removed, 0);
    assert_eq!(out.keys_retained, 1);
    assert!(index.seek_label(LABEL).contains(&NODE));
    assert!(offers(&mut index, &Value::Integer(30)));
}

/// **A still-in-use slot is never purged.** The id may have been handed to a *different* entity
/// between the pass and the re-check, and purging then would delete the new entity's postings.
#[test]
fn an_entity_key_for_a_still_in_use_slot_is_retained() {
    let mut index = index_holding(&[Value::Integer(30)]);
    index.register_bitmap(LABEL, PROP);
    index.insert_bitmap_value(LABEL, PROP, &Value::Integer(30), NODE);
    let keys = [DeadIndexKey::Entity {
        kind: StoreKind::Node,
        entity: NODE,
    }];
    let out = index.collect_dead_keys(GC_TXN, &keys, &witness(&[Value::Integer(30)], &[LABEL]));

    assert_eq!(out.entities_purged, 0);
    assert_eq!(out.keys_retained, 1);
    assert_eq!(
        index.seek_bitmap_eq(LABEL, PROP, &Value::Integer(30)),
        Some(vec![NODE]),
        "a live entity's bitmap posting was purged"
    );
}

/// A reclaimed slot's entity-keyed postings are purged — the bitmap here standing for the whole
/// family (full-text, spatial, text, vector), which share one code path and one witness.
#[test]
fn an_entity_key_for_a_reclaimed_slot_purges_the_entity_keyed_postings() {
    let mut index = index_holding(&[Value::Integer(30)]);
    index.register_bitmap(LABEL, PROP);
    index.insert_bitmap_value(LABEL, PROP, &Value::Integer(30), NODE);
    assert_eq!(
        index.seek_bitmap_eq(LABEL, PROP, &Value::Integer(30)),
        Some(vec![NODE]),
        "precondition: the posting exists"
    );

    let mut evidence = witness(&[], &[]);
    evidence
        .get_mut(&(StoreKind::Node, NODE))
        .expect("built above")
        .in_use = false;
    let keys = [DeadIndexKey::Entity {
        kind: StoreKind::Node,
        entity: NODE,
    }];
    let out = index.collect_dead_keys(GC_TXN, &keys, &evidence);

    assert_eq!(out.entities_purged, 1);
    assert_eq!(
        index.seek_bitmap_eq(LABEL, PROP, &Value::Integer(30)),
        Some(Vec::new()),
        "the reclaimed entity's bitmap posting survived its record"
    );
}

/// **A reclaimed slot's record body must not be believed.** A store frees a slot by clearing its
/// flag, not by erasing its body, so a reclaimed node's label word still reads as its last live label
/// set. Consulting it would retain the entries of every node the GC has just reclaimed — which is
/// exactly what the first cut of this code did.
#[test]
fn a_reclaimed_slots_stale_label_word_does_not_protect_its_entries() {
    let mut index = index_holding(&[Value::Integer(30)]);
    // The witness a freed slot really produces: `in_use == false`, but with the stale body still
    // reporting the label and the value.
    let mut evidence = witness(&[Value::Integer(30)], &[LABEL]);
    evidence
        .get_mut(&(StoreKind::Node, NODE))
        .expect("built above")
        .in_use = false;

    let keys = [
        DeadIndexKey::Label {
            node: NODE,
            label: LABEL,
        },
        dead_property(Value::Integer(30)),
    ];
    let out = index.collect_dead_keys(GC_TXN, &keys, &evidence);

    assert_eq!(
        out.keys_retained, 0,
        "the stale body of a freed slot was treated as a live warrant"
    );
    assert!(!index.seek_label(LABEL).contains(&NODE));
    assert!(!offers(&mut index, &Value::Integer(30)));
}

/// The relationship dimension of the property re-check, so the `StoreKind::Rel` arm is not carried by
/// inspection alone.
#[test]
fn a_relationship_property_key_is_decided_the_same_way() {
    const TYPE: u32 = 3;
    const REL: u64 = 11;
    let mut index = IndexSet::new();
    index.register_rel_property_with_state(TYPE, PROP, IndexState::Online);
    for v in [Value::Integer(1), Value::Integer(2)] {
        index.insert_rel_property(IndexWriter::Txn(TxnId(1)), TYPE, PROP, &v, REL);
    }

    let mut evidence = HashMap::new();
    evidence.insert(
        (StoreKind::Rel, REL),
        DeadKeyEvidence {
            property_versions: vec![(PROP, Value::Integer(2))],
            labels: Vec::new(),
            in_use: true,
        },
    );
    let keys = [
        DeadIndexKey::Property {
            kind: StoreKind::Rel,
            entity: REL,
            key: PROP,
            value: Value::Integer(1),
        },
        DeadIndexKey::Property {
            kind: StoreKind::Rel,
            entity: REL,
            key: PROP,
            value: Value::Integer(2),
        },
    ];
    let out = index.collect_dead_keys(GC_TXN, &keys, &evidence);

    assert_eq!((out.entries_removed, out.keys_retained), (1, 1));
    assert!(
        !index
            .seek_rel_property_eq(TYPE, PROP, &Value::Integer(1))
            .expect("registered")
            .contains(&REL)
    );
    assert!(
        index
            .seek_rel_property_eq(TYPE, PROP, &Value::Integer(2))
            .expect("registered")
            .contains(&REL),
        "the live relationship value's entry was collected"
    );
}

// =================================================================================================
// Query-level equivalence — collecting must not change the answer
// =================================================================================================

/// **Declaring an index must not change the answer, after the collection has run.**
///
/// The mechanism removes entries from a live index, and the one consequence that may never follow is
/// a row appearing or disappearing because an index exists. The comparison is a bag comparison of the
/// same query planned with and without the catalog, over a corpus that has been rewritten, deleted
/// from, and had a label removed — i.e. over every key shape the pass can emit — with a ground-truth
/// count so the two arms cannot agree by both being empty (`rmp` #680 / #738 / #894).
///
/// # The vacuity trap this test has to dodge
///
/// A bag comparison of "with index" against "without index" proves nothing if the *with-index* plan
/// is also a scan — and at three nodes a cost-based planner has every reason to choose one. This
/// repo's own record of that trap is explicit, so the test asserts the **plan shape** first: the
/// indexed arm must actually contain a `NodeIndexSeek`. Without that assertion the whole comparison
/// could pass while comparing two identical label scans.
#[test]
fn collecting_dead_entries_answers_exactly_as_the_scan() {
    let mut coord = fresh_coord();
    run_write(
        &mut coord,
        "CREATE (:Person:Staff {age: 30, email: 'a@x.io'})",
    );
    run_write(&mut coord, "CREATE (:Person {age: 31, email: 'b@x.io'})");
    run_write(&mut coord, "CREATE (:Person {age: 32, email: 'c@x.io'})");
    coord
        .create_node_property_index("Person", "age")
        .expect("create index");

    // Every shape of dead key: a rewritten value, a value rewritten back to itself, a removed label,
    // and a deleted (and then reclaimed) node.
    run_write(
        &mut coord,
        "MATCH (n:Person) WHERE n.email = 'b@x.io' SET n.age = 41",
    );
    run_write(
        &mut coord,
        "MATCH (n:Person) WHERE n.email = 'b@x.io' SET n.age = 31",
    );
    run_write(&mut coord, "MATCH (n:Staff) REMOVE n:Staff");
    run_write(
        &mut coord,
        "MATCH (n:Person) WHERE n.email = 'c@x.io' DELETE n",
    );

    let report = coord.gc().expect("gc pass");
    assert!(
        report.dead_index_keys > 0,
        "NON-VACUITY: the pass must have collected something, or this compares two untouched indexes"
    );

    let indexed = coord.catalog();
    // NON-VACUITY: the indexed arm must genuinely seek, or every comparison below is scan-vs-scan.
    let seeking = "MATCH (n:Person) WHERE n.age = 31 RETURN n.email AS a";
    assert!(
        has_op(&compile(seeking, &indexed), "NodeIndexSeek"),
        "the catalog did not produce an index seek, so the comparison below would be scan-vs-scan \
         and could not detect an index changing the answer"
    );
    assert!(
        !has_op(&compile(seeking, &IndexCatalog::empty()), "NodeIndexSeek"),
        "the CONTROL arm must not seek, or the two arms are the same plan"
    );

    for src in [
        "MATCH (n:Person) WHERE n.age = 30 RETURN n.email AS a",
        "MATCH (n:Person) WHERE n.age = 31 RETURN n.email AS a",
        "MATCH (n:Person) WHERE n.age = 41 RETURN n.email AS a",
        "MATCH (n:Person) WHERE n.age > 0 RETURN n.email AS a",
        "MATCH (n:Person) WHERE n.age IS NOT NULL RETURN n.email AS a",
        "MATCH (n:Person) RETURN n.email AS a",
        "MATCH (n:Staff) RETURN n.email AS a",
    ] {
        let via_index = sorted_debug(&read_rows(&mut coord, &indexed, src));
        let via_scan = sorted_debug(&read_rows(&mut coord, &IndexCatalog::empty(), src));
        assert_eq!(
            via_index, via_scan,
            "{src}: declaring an index changed the answer after the GC collection"
        );
    }

    assert_eq!(
        sorted_debug(&read_rows(
            &mut coord,
            &indexed,
            "MATCH (n:Person) RETURN n.email AS a"
        ))
        .len(),
        2,
        "ground truth: the two surviving rows, so the comparison above is not vacuous"
    );
    assert_eq!(
        sorted_debug(&read_rows(
            &mut coord,
            &indexed,
            "MATCH (n:Person) WHERE n.age = 31 RETURN n.email AS a"
        ))
        .len(),
        1,
        "ground truth: the value rewritten AWAY and BACK is still found through the index"
    );
}

// -------------------------------------------------------------------------------------------------
// Coordinator helpers (mirroring tests/index_mvcc_rollback_992.rs)
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

/// Whether `plan` contains a physical operator called `name` (the shape assertion every index test in
/// this repo uses, e.g. `tests/chain_anchor.rs`).
fn has_op(plan: &PhysicalPlan, name: &str) -> bool {
    format!("{:?}", plan.root).contains(&format!("{name} {{"))
}

fn sorted_debug(rows: &[Row]) -> Vec<String> {
    let mut out: Vec<String> = rows.iter().map(|r| format!("{:?}", r.values())).collect();
    out.sort();
    out
}
