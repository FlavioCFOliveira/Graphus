//! **An abort changes nothing a concurrent snapshot can see** (`rmp` #970, acceptance criterion 1).
//!
//! This is the mechanical form of "an abort must not write state that belongs to another
//! transaction". Stating it as *bytes* would be both too strong and too weak: too strong because the
//! logical rollback legitimately rewrites a committed neighbour's incidence-chain pointers — the very
//! words the aborting transaction had changed on its way in, bridged back against the current state —
//! and too weak because a byte comparison says nothing about whether the result is the *right*
//! structure.
//!
//! So the property is stated where it is observable and where every defect in the family
//! (`rmp` #220 / #172 / #239 / #301 / #578 / #772) showed itself: **the image a third, uninvolved
//! snapshot reads must be identical immediately before and immediately after the abort.** Every one
//! of those defects was a case of one transaction's undo damaging another's committed state, and each
//! of them changes that image.
//!
//! # Non-vacuity
//!
//! Each scenario asserts, before the abort, that the committed image it is about to preserve is
//! **non-empty and structurally interesting** — a hub with several committed edges, a node carrying
//! committed properties and labels — and that the aborting transaction genuinely wrote (its own
//! effects are present in the raw, superset view, and gone afterwards). A test that preserved an
//! empty image, or that compared two reads of a transaction which never wrote, would fail those
//! guards first.

use graphus_core::{TxnId, Value, VersionStamp};
use graphus_io::MemBlockDevice;
use graphus_storage::{Namespace, RecordStore, check::check_store};
use graphus_txn::{Snapshot, is_visible};
use graphus_wal::{MemLogSink, WalManager};

type Store = RecordStore<MemBlockDevice, MemLogSink>;

const POOL: usize = 64;

fn fresh() -> Store {
    let device = MemBlockDevice::new(0);
    let wal = WalManager::create(MemLogSink::new()).expect("create wal");
    RecordStore::create(device, wal, POOL, 1).expect("create store")
}

/// Everything an uninvolved snapshot can see, rendered as a stable, comparable text image: for every
/// visible node its labels, its visible property values and its visible incident relationships; for
/// every visible relationship its endpoints and type.
///
/// Keyed by [`ElementId`](graphus_core::ElementId) — the stable public identity — rather than by
/// physical id, so a slot the abort reclaims and a later writer reuses cannot make two different
/// entities compare equal.
fn committed_image(s: &Store, observer: TxnId) -> Vec<String> {
    let snapshot = Snapshot {
        owner: observer,
        ts: s.snapshot_ts(),
    };
    let registry = s.commit_registry();
    let visible = |mvcc: graphus_storage::MvccHeader| {
        mvcc.in_use() && is_visible(snapshot, mvcc.created_ts, mvcc.expired_ts, registry)
    };

    let mut out = Vec::new();
    for id in s.scan_node_ids().expect("scan nodes") {
        let n = s.node(id).expect("read node");
        if !visible(n.mvcc) {
            continue;
        }
        let labels = s
            .label_bitmap_at(id, n.labels, n.mvcc.undo_ptr, snapshot)
            .expect("labels at snapshot");
        let mut props: Vec<String> = s
            .decision_scan_node_properties(id, snapshot)
            .expect("decided props")
            .visible_versions()
            .iter()
            .map(|c| format!("{}={}:{:#x}", c.key, c.type_tag, c.value_inline))
            .collect();
        props.sort_unstable();
        let mut edges: Vec<String> = s
            .incident_rels(id)
            .expect("incident")
            .into_iter()
            .filter(|&r| visible(s.rel(r).expect("read rel").mvcc))
            .map(|r| format!("{:x}", s.rel(r).expect("read rel").element_id.0))
            .collect();
        edges.sort_unstable();
        out.push(format!(
            "node {:x} labels={labels:#x} props=[{}] edges=[{}]",
            n.element_id.0,
            props.join(","),
            edges.join(",")
        ));
    }
    for id in s.scan_rel_ids().expect("scan rels") {
        let r = s.rel(id).expect("read rel");
        if !visible(r.mvcc) {
            continue;
        }
        let eid = |n: u64| format!("{:x}", s.node(n).expect("read node").element_id.0);
        out.push(format!(
            "rel {:x} type={} {} -> {}",
            r.element_id.0,
            r.type_id,
            eid(r.start_node),
            eid(r.end_node)
        ));
    }
    out.sort();
    out
}

/// The raw (superset) count of in-use relationship slots — used only as a non-vacuity witness that
/// the aborting transaction really did write.
fn in_use_rels(s: &Store) -> usize {
    s.scan_rel_ids()
        .expect("scan rels")
        .into_iter()
        .filter(|&r| s.rel(r).expect("read rel").mvcc.in_use())
        .count()
}

/// **Scenario 1 — a supernode's fan-out.** Three writers prepend an edge each onto one hub; the
/// middle one aborts. This is the exact shape of `rmp` #220: the aborting writer's undo used to
/// restore a `first_rel` word a concurrently-committed writer owned, collapsing the fan-out.
#[test]
fn aborting_a_prepend_leaves_a_shared_hubs_committed_fan_out_untouched() {
    let mut s = fresh();
    let seed = TxnId(1);
    s.begin(seed);
    let rt = s.intern_token(Namespace::RelType, "R").expect("intern");
    let (hub, _) = s.create_node(seed).expect("hub");
    let leaves: Vec<u64> = (0..4)
        .map(|_| s.create_node(seed).expect("leaf").0)
        .collect();
    s.commit(seed).expect("commit seed");

    // Two committed prepends around one aborting prepend, opened in an order that leaves the aborting
    // writer in the MIDDLE of the chain by the time it rolls back.
    let (c1, a, c2) = (TxnId(2), TxnId(3), TxnId(4));
    s.begin(c1);
    s.begin(a);
    s.begin(c2);
    s.create_rel(c1, rt, hub, leaves[0]).expect("c1 edge");
    s.create_rel(a, rt, hub, leaves[1]).expect("a edge");
    s.create_rel(c2, rt, hub, leaves[2]).expect("c2 edge");
    s.commit(c1).expect("commit c1");
    s.commit(c2).expect("commit c2");

    let observer = TxnId(9);
    let before = committed_image(&s, observer);
    assert!(
        before
            .iter()
            .any(|l| l.contains("edges=[") && l.matches(',').count() >= 1),
        "non-vacuity: the hub must carry SEVERAL committed edges before the abort, or there is \
         nothing for the abort to damage: {before:?}"
    );
    let rels_before = in_use_rels(&s);
    assert_eq!(
        rels_before, 3,
        "non-vacuity: the aborting writer's edge is physically present before the rollback"
    );

    s.rollback(a).expect("rollback");

    assert_eq!(
        committed_image(&s, observer),
        before,
        "rmp #970/#220: the abort of a middle prepend must leave the hub's committed fan-out exactly \
         as it found it"
    );
    assert_eq!(
        in_use_rels(&s),
        2,
        "non-vacuity: the aborting writer's own edge is gone"
    );
    let report = check_store(&mut s, &[]).expect("check");
    assert!(
        report.is_consistent(),
        "store consistent after the abort: {:?}",
        report.violations
    );
}

/// **Scenario 2 — properties and labels on nodes a committed writer also owns.** The aborting writer
/// touches its own node while a committed writer's node carries properties and labels; `rmp` #772 was
/// a label rollback destroying a committed property on the same record, and `rmp` #172 was the
/// property-chain twin.
#[test]
fn aborting_property_and_label_writes_leaves_committed_values_untouched() {
    let mut s = fresh();
    let seed = TxnId(1);
    s.begin(seed);
    let k1 = s.intern_token(Namespace::PropKey, "a").expect("intern");
    let k2 = s.intern_token(Namespace::PropKey, "b").expect("intern");
    let l1 = s.intern_token(Namespace::Label, "L1").expect("intern");
    let l2 = s.intern_token(Namespace::Label, "L2").expect("intern");
    let (shared, _) = s.create_node(seed).expect("shared");
    let (other, _) = s.create_node(seed).expect("other");
    s.set_node_property_value(seed, shared, k1, &Value::Integer(1))
        .expect("seed prop");
    s.set_node_labels(seed, shared, &[l1]).expect("seed label");
    s.commit(seed).expect("commit seed");

    // A committed writer changes the shared node; the aborting writer works on the other node with
    // exactly the same kinds of write, then rolls back.
    let c = TxnId(2);
    s.begin(c);
    s.set_node_property_value(c, shared, k1, &Value::Integer(42))
        .expect("c prop");
    s.set_node_property_value(c, shared, k2, &Value::String("committed".into()))
        .expect("c prop 2");
    s.set_node_labels(c, shared, &[l1, l2]).expect("c labels");
    s.commit(c).expect("commit c");

    let a = TxnId(3);
    s.begin(a);
    s.set_node_property_value(a, other, k1, &Value::String("x".repeat(4096)))
        .expect("a prop");
    s.set_node_labels(a, other, &[l2]).expect("a labels");
    let (a_node, _) = s.create_node(a).expect("a node");
    s.set_node_property_value(a, a_node, k2, &Value::Integer(7))
        .expect("a prop on its own node");

    let observer = TxnId(9);
    let before = committed_image(&s, observer);
    assert!(
        before
            .iter()
            .any(|l| l.contains("props=[") && l.contains(',')),
        "non-vacuity: a committed node must carry SEVERAL committed properties: {before:?}"
    );
    assert!(
        s.node(a_node).expect("read").mvcc.in_use()
            && VersionStamp::from_raw(s.node(a_node).expect("read").mvcc.created_ts)
                == VersionStamp::InFlight(a),
        "non-vacuity: the aborting writer's own node is physically present and uncommitted"
    );

    s.rollback(a).expect("rollback");

    assert_eq!(
        committed_image(&s, observer),
        before,
        "rmp #970/#772/#172: aborting a property + label writer must leave every committed value and \
         label exactly as it found them"
    );
    assert!(
        !s.node(a_node).expect("read").mvcc.in_use(),
        "non-vacuity: the aborting writer's own node is retired"
    );
    let report = check_store(&mut s, &[]).expect("check");
    assert!(
        report.is_consistent(),
        "store consistent after the abort: {:?}",
        report.violations
    );
}

/// **Scenario 3 — an abort interleaved with a deletion and a slot reuse.** The aborting writer pops a
/// slot a GC pass freed (`rmp` #578 / #581) and a committed writer works around it; the committed
/// image must be untouched and the store must stay allocation-consistent.
#[test]
fn aborting_a_reused_slot_leaves_the_committed_image_and_the_allocator_sound() {
    let mut s = fresh();
    let seed = TxnId(1);
    s.begin(seed);
    let rt = s.intern_token(Namespace::RelType, "R").expect("intern");
    let (hub, _) = s.create_node(seed).expect("hub");
    let (leaf, _) = s.create_node(seed).expect("leaf");
    let (victim, _) = s.create_rel(seed, rt, hub, leaf).expect("victim");
    let (keeper, _) = s.create_rel(seed, rt, hub, leaf).expect("keeper");
    s.commit(seed).expect("commit seed");

    let del = TxnId(2);
    s.begin(del);
    s.delete_rel(del, victim).expect("delete victim");
    s.commit(del).expect("commit delete");
    let gc = TxnId(3);
    s.begin(gc);
    s.gc(gc, s.snapshot_ts()).expect("gc");
    s.commit(gc).expect("commit gc");

    let a = TxnId(4);
    s.begin(a);
    let (reused, _) = s.create_rel(a, rt, hub, leaf).expect("a edge");
    assert_eq!(
        reused, victim,
        "non-vacuity: the aborting writer must pop the slot GC freed, or the scenario is not the one \
         #578 is about"
    );

    let observer = TxnId(9);
    let before = committed_image(&s, observer);
    assert!(
        before.iter().any(|l| l.starts_with("rel ")),
        "non-vacuity: a committed relationship must survive the churn: {before:?}"
    );

    s.rollback(a).expect("rollback");

    assert_eq!(
        committed_image(&s, observer),
        before,
        "rmp #970/#578: aborting a writer that reused a freed slot must leave the committed image \
         untouched"
    );
    assert!(
        s.rel(keeper).expect("read keeper").mvcc.in_use(),
        "the committed relationship keeps its slot"
    );
    let report = check_store(&mut s, &[]).expect("check");
    assert!(
        report.is_consistent(),
        "store consistent after the abort: {:?}",
        report.violations
    );
}
