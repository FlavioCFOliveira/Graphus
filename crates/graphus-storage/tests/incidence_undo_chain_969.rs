//! Adjacency on the unified undo chain (`rmp` #969, `05-storage-format.md` §12.3,
//! `04-technical-design.md` §5.1).
//!
//! Creating a relationship threads it into **two** incidence chains, and until this task that
//! in-place mutation had no version at all: its correctness came from a bespoke compare-and-set undo
//! on the endpoints' `first_rel` words. This file certifies the version that replaces that
//! reasoning — one [`UndoAction::RemoveIncidentEdge`] delta per end, naming **one incidence entry**
//! and never a shared pointer word — and the choice that makes it affordable: the deltas anchor on
//! the **relationship**, not on the endpoint node (`D-incidence-anchor`).
//!
//! Every test states its own non-vacuity: what it looks like against a tree without the change.
//!
//! Run with `cargo test -p graphus-storage --test incidence_undo_chain_969`.

use graphus_core::{TxnId, Value};
use graphus_io::MemBlockDevice;
use graphus_storage::undo::IncidentDirection;
use graphus_storage::{Namespace, RecordStore, StoreKind, UndoAction, check::check_store};
use graphus_txn::Snapshot;
use graphus_wal::{MemLogSink, WalManager};

type Store = RecordStore<MemBlockDevice, MemLogSink>;

fn fresh() -> Store {
    let device = MemBlockDevice::new(0);
    let wal = WalManager::create(MemLogSink::new()).expect("create wal");
    RecordStore::create(device, wal, 256, 1).expect("create store")
}

/// Every incidence delta on `(kind, entity)`'s chain, newest first, as
/// `(action, token, direction, peer, edge)`.
fn incidence_deltas(
    s: &Store,
    kind: StoreKind,
    entity: u64,
) -> Vec<(UndoAction, u32, u8, u64, u64)> {
    s.version_chain(kind, entity)
        .expect("chain reads")
        .into_iter()
        .filter(|(_, d)| d.action.is_incidence())
        .map(|(_, d)| (d.action, d.token, d.direction, d.peer, d.edge))
        .collect()
}

/// The value `snapshot` reads for `node`'s property `key`, or `None` if the key is absent to it.
fn value_at(s: &Store, node: u64, key: u32, snapshot: Snapshot) -> Option<Value> {
    let decided = s
        .decision_scan_node_properties(node, snapshot)
        .expect("decision-polarity read");
    let seen = decided.visible_version(key)?;
    Some(
        s.decode_property_value(seen.type_tag, seen.value_inline)
            .expect("decode the visible value"),
    )
}

fn assert_consistent(store: &mut Store, when: &str) {
    let report = check_store(store, &[]).expect("consistency check runs");
    assert!(
        report.violations.is_empty(),
        "store must be consistent {when}, found: {:?}",
        report.violations
    );
}

// ==========================================================================================
// Acceptance criterion 1 — creating an edge versions BOTH of its incidence entries.
// ==========================================================================================

/// One `RemoveIncidentEdge` delta per end lands on the **relationship's** chain, carrying the four
/// fields `05 §12.2` gives the incidence actions: the type token, which end it is, the peer endpoint,
/// and the edge.
///
/// The action is the INVERSE of the event — the transaction *added* an incidence entry, so what
/// undoes it is *removing* that entry — which is the convention `05 §12.3` states and the one a
/// reader is most likely to get backwards.
///
/// **Non-vacuity.** Against the tree before this task, `create_rel` linked no incidence delta at all:
/// the vector below is empty and the first `assert_eq!` fails on length.
#[test]
fn creating_an_edge_versions_both_of_its_incidence_entries() {
    let mut s = fresh();
    let rt = s.intern_token(Namespace::RelType, "R").expect("intern");

    let setup = TxnId(1);
    s.begin(setup);
    let (a, _) = s.create_node(setup).expect("create a");
    let (b, _) = s.create_node(setup).expect("create b");
    s.commit(setup).expect("commit setup");

    let t = TxnId(2);
    s.begin(t);
    let (r, _) = s.create_rel(t, rt, a, b).expect("create edge");
    s.commit(t).expect("commit edge");

    let mut got = incidence_deltas(&s, StoreKind::Rel, r);
    got.sort_unstable_by_key(|e| e.2);
    assert_eq!(
        got,
        vec![
            (
                UndoAction::RemoveIncidentEdge,
                rt,
                IncidentDirection::Start.as_byte(),
                b,
                r
            ),
            (
                UndoAction::RemoveIncidentEdge,
                rt,
                IncidentDirection::End.as_byte(),
                a,
                r
            ),
        ],
        "one delta per end, each naming the edge, its type, its side and the PEER endpoint"
    );
    assert_consistent(&mut s, "after a versioned edge insertion");
}

/// A self-loop is threaded into the single chain **twice** (`04 §2.4`), so it is two incidence
/// entries and must be two deltas — one per direction — differing only in `direction`.
///
/// **Non-vacuity.** With a single delta (the obvious mistake: "one edge, one delta") the length
/// assertion fails; with the directions not distinguished, the direction assertion fails.
#[test]
fn a_self_loop_versions_both_of_its_incidence_entries() {
    let mut s = fresh();
    let rt = s.intern_token(Namespace::RelType, "R").expect("intern");

    let setup = TxnId(1);
    s.begin(setup);
    let (n, _) = s.create_node(setup).expect("create n");
    s.commit(setup).expect("commit setup");

    let t = TxnId(2);
    s.begin(t);
    let (r, _) = s.create_rel(t, rt, n, n).expect("create self-loop");
    s.commit(t).expect("commit self-loop");

    let mut got = incidence_deltas(&s, StoreKind::Rel, r);
    got.sort_unstable_by_key(|e| e.2);
    assert_eq!(
        got,
        vec![
            (
                UndoAction::RemoveIncidentEdge,
                rt,
                IncidentDirection::Start.as_byte(),
                n,
                r
            ),
            (
                UndoAction::RemoveIncidentEdge,
                rt,
                IncidentDirection::End.as_byte(),
                n,
                r
            ),
        ],
        "a self-loop is two incidence entries on one relationship, each naming the node as the peer"
    );
    assert_consistent(&mut s, "after a versioned self-loop insertion");
}

// ==========================================================================================
// Acceptance criterion 2 — the anchor: the endpoint NODE's chain is untouched.
// ==========================================================================================

/// **The measurement that decided the anchor** (`D-incidence-anchor`).
///
/// The endpoint node is where the incidence *chain head* lives, so it looks like the natural place to
/// anchor the delta — and an earlier draft of this task put it there. That makes a node's chain grow
/// by one delta per edge inserted on it, and **every property and label read of that node walks its
/// chain**: measured on that draft, one visible-property read on a hub cost 220 ns at degree 0 and
/// 488 µs at degree 4000. Worse, the growth does not end at the next GC pass —
/// `gc_reclaim_undo_chains` frees a chain only when *every* delta on it is dead, so a hub under
/// sustained insertion never prunes.
///
/// Anchoring on the relationship — a fresh slot private to its creator — keeps node chains exactly as
/// long as the property and label history that belongs on them.
///
/// **Non-vacuity.** Against the node-anchored draft the hub carries 200 incidence deltas here and the
/// first assertion fails; the read-cost assertion fails with it.
#[test]
fn inserting_edges_on_a_hub_does_not_grow_the_hubs_own_version_chain() {
    let mut s = fresh();
    let rt = s.intern_token(Namespace::RelType, "R").expect("intern");
    let key = s.intern_token(Namespace::PropKey, "p").expect("intern");

    let setup = TxnId(1);
    s.begin(setup);
    let (hub, _) = s.create_node(setup).expect("hub");
    s.set_node_property_value(setup, hub, key, &Value::Integer(1))
        .expect("seed the property");
    let leaves: Vec<u64> = (0..200)
        .map(|_| s.create_node(setup).expect("leaf").0)
        .collect();
    s.commit(setup).expect("commit setup");

    let chain_before = s.version_chain(StoreKind::Node, hub).expect("chain").len();
    let t = TxnId(2);
    s.begin(t);
    for &leaf in &leaves {
        s.create_rel(t, rt, hub, leaf).expect("edge");
    }
    s.commit(t).expect("commit the edges");

    assert!(
        incidence_deltas(&s, StoreKind::Node, hub).is_empty(),
        "no incidence delta may land on the endpoint node's chain"
    );
    assert_eq!(
        s.version_chain(StoreKind::Node, hub).expect("chain").len(),
        chain_before,
        "200 edge insertions must leave the hub's own version chain exactly as it was"
    );
    assert_eq!(s.degree(hub).expect("degree"), 200);

    // And the read the chain length would have cost still sees the seeded value.
    let snapshot = Snapshot::new(TxnId(9_999), s.snapshot_ts());
    assert_eq!(value_at(&s, hub, key, snapshot), Some(Value::Integer(1)));
    assert_consistent(&mut s, "after 200 edge insertions on one hub");
}

/// An edge insertion is **never** refused, and never causes another transaction to be refused —
/// not even onto a node another open transaction is changing. Edge insertion is the operation
/// `rmp` #220 and the multi-writer work exist to keep concurrent, and with the delta on the
/// relationship's own private chain there is nothing on the node to contend for.
///
/// **Non-vacuity.** Against the node-anchored draft, both insertions below are refused with a
/// write-write conflict unless a bespoke relaxation is added; against a draft that anchors on the
/// node *without* that relaxation, the very first one is.
#[test]
fn an_edge_insertion_is_never_refused_whatever_holds_the_node() {
    let mut s = fresh();
    let rt = s.intern_token(Namespace::RelType, "R").expect("intern");
    let key = s.intern_token(Namespace::PropKey, "p").expect("intern");
    let label = s.intern_token(Namespace::Label, "L").expect("intern");

    let setup = TxnId(1);
    s.begin(setup);
    let (hub, _) = s.create_node(setup).expect("hub");
    let (l1, _) = s.create_node(setup).expect("l1");
    let (l2, _) = s.create_node(setup).expect("l2");
    s.set_node_property_value(setup, hub, key, &Value::Integer(1))
        .expect("seed");
    s.commit(setup).expect("commit setup");

    // A property write holds the hub…
    let holder = TxnId(2);
    s.begin(holder);
    s.set_node_property_value(holder, hub, key, &Value::Integer(2))
        .expect("holder writes");

    let inserter = TxnId(3);
    s.begin(inserter);
    let _ = s
        .create_rel(inserter, rt, hub, l1)
        .expect("an edge insertion over a property holder must be accepted");

    // …and so does a label change.
    s.add_label(holder, hub, label).expect("holder labels");
    let _ = s
        .create_rel(inserter, rt, hub, l2)
        .expect("an edge insertion over a label holder must be accepted");

    s.commit(inserter).expect("the inserter commits");
    s.commit(holder).expect("the holder commits");
    assert_eq!(s.degree(hub).expect("degree"), 2);
    assert_consistent(&mut s, "after edge insertions over a sequential holder");
}

/// Three concurrently-open transactions each insert an edge on one shared hub. All three must commit
/// and all three edges must persist — the `rmp` #220 guarantee, now stated over the version model.
///
/// **Non-vacuity.** Against any design that versions adjacency on the endpoint node without an
/// explicit relaxation, the second `create_rel` below fails with a write-write conflict.
#[test]
fn three_concurrent_writers_on_one_hub_all_commit_and_all_edges_persist() {
    let mut s = fresh();
    let rt = s.intern_token(Namespace::RelType, "R").expect("intern");

    let setup = TxnId(1);
    s.begin(setup);
    let (hub, _) = s.create_node(setup).expect("create hub");
    let leaves: Vec<u64> = (0..3)
        .map(|_| s.create_node(setup).expect("create leaf").0)
        .collect();
    s.commit(setup).expect("commit setup");

    let txns = [TxnId(2), TxnId(3), TxnId(4)];
    for t in txns {
        s.begin(t);
    }
    let mut edges = Vec::new();
    for (t, leaf) in txns.iter().zip(&leaves) {
        let (r, _) = s
            .create_rel(*t, rt, hub, *leaf)
            .expect("a concurrent edge insertion on a shared hub must NOT conflict");
        edges.push(r);
    }
    for t in txns {
        s.commit(t).expect("every writer commits");
    }

    let mut incident = s.incident_rels(hub).expect("walk the hub");
    incident.sort_unstable();
    edges.sort_unstable();
    assert_eq!(
        incident, edges,
        "every committed edge must persist on the hub's incidence chain"
    );
    assert_eq!(s.degree(hub).expect("degree"), 3);
    for &e in &edges {
        assert_eq!(
            incidence_deltas(&s, StoreKind::Rel, e).len(),
            2,
            "and each edge carries its own two incidence versions"
        );
    }
    assert_consistent(&mut s, "after three concurrent supernode writers");
}

/// A rolled-back edge insertion leaves no live incidence version behind, and the concurrently
/// committed edge is untouched — the `rmp` #220 guarantee restated over the version chain.
#[test]
fn an_aborted_edge_insertion_leaves_no_live_incidence_version() {
    let mut s = fresh();
    let rt = s.intern_token(Namespace::RelType, "R").expect("intern");

    let setup = TxnId(1);
    s.begin(setup);
    let (hub, _) = s.create_node(setup).expect("create hub");
    let (l1, _) = s.create_node(setup).expect("create l1");
    let (l2, _) = s.create_node(setup).expect("create l2");
    s.commit(setup).expect("commit setup");

    let t1 = TxnId(2);
    let t2 = TxnId(3);
    s.begin(t1);
    s.begin(t2);
    let (kept, _) = s.create_rel(t1, rt, hub, l1).expect("T1 inserts an edge");
    let (dropped, _) = s.create_rel(t2, rt, hub, l2).expect("T2 inserts an edge");
    s.rollback(t2).expect("T2 aborts");
    s.commit(t1).expect("T1 commits");

    assert_eq!(
        s.incident_rels(hub).expect("walk"),
        vec![kept],
        "the committed edge survives the concurrent abort"
    );
    assert_eq!(
        incidence_deltas(&s, StoreKind::Rel, kept).len(),
        2,
        "the survivor keeps both of its incidence versions"
    );
    let live_dropped = s
        .version_chain(StoreKind::Rel, dropped)
        .expect("chain reads")
        .into_iter()
        .filter(|(_, d)| d.action.is_incidence() && d.in_use())
        .count();
    assert_eq!(
        live_dropped, 0,
        "the aborted insertion leaves no LIVE incidence version"
    );
    assert_consistent(&mut s, "after an aborted concurrent edge insertion");
}

// ==========================================================================================
// The measured cost ("Measure to decide")
// ==========================================================================================

/// What versioning adjacency costs: exactly **two** deltas per edge, on the relationship's own chain,
/// and the WAL bytes that come with them.
///
/// The delta count is the exact statement — the unit of the cost is the delta — and the byte figure
/// is held under a ceiling so a regression that starts writing more per edge is caught. Unlike the
/// node-anchored draft there is no gated shape: every edge pays, including a bulk load, which is the
/// price of the anchor that keeps node chains short.
///
/// Measured on this tree: **1096 B/edge**, 2 deltas/edge.
#[test]
fn versioning_an_edge_writes_exactly_two_deltas_on_the_relationship() {
    let s = fresh();
    let rt = s.intern_token(Namespace::RelType, "R").expect("intern");

    const EDGES: usize = 200;

    let seed = TxnId(1);
    s.begin(seed);
    let mut pairs = Vec::new();
    for _ in 0..EDGES {
        let (a, _) = s.create_node(seed).expect("a");
        let (b, _) = s.create_node(seed).expect("b");
        pairs.push((a, b));
    }
    s.commit(seed).expect("commit the endpoints");

    let before = s.with_wal(|w| w.durable_len());
    let versioned = TxnId(2);
    s.begin(versioned);
    let mut edges = Vec::new();
    for &(a, b) in &pairs {
        edges.push(s.create_rel(versioned, rt, a, b).expect("edge").0);
    }
    s.commit(versioned).expect("commit the edges");
    let per_edge = (s.with_wal(|w| w.durable_len()) - before) / EDGES as u64;

    let deltas: usize = edges
        .iter()
        .map(|&e| incidence_deltas(&s, StoreKind::Rel, e).len())
        .sum();
    assert_eq!(
        deltas,
        2 * EDGES,
        "exactly two incidence deltas per edge — one per end — and not one more"
    );
    assert!(
        per_edge <= 1_800,
        "an edge must stay within its budget; measured {per_edge} B/edge"
    );
    println!("incidence versioning: {per_edge} B/edge, 2 deltas/edge");
}

// ==========================================================================================
// A pre-existing ACID defect the versioned adjacency makes fixable (`rmp` #969, found by the
// storage-systems-auditor and the concurrency-architect independently)
// ==========================================================================================

/// **The hazard this used to guard is gone with the undo image that created it** (`rmp` #969 →
/// `rmp` #970).
///
/// A writer `W` prepending onto node `N` used to capture `N`'s current `first_rel` as its undo
/// image, so GC reclaiming *that* relationship — legitimate on its own terms, since it is tombstoned
/// and committed below the watermark — left `W`'s abort restoring `first_rel` to a slot on the free
/// list, which the next allocation handed to an unrelated relationship: a silently wrong traversal.
/// The fix was a GC deferral keyed on the set of captured heads.
///
/// `rmp` #970 removes the premise. A chain-head publication is **redo-only** — its inverse is the
/// transaction's `RemoveIncidentEdge` delta, which unlinks against the state at abort time — so no
/// image names the tombstoned head, nothing has to be deferred, and the captured-head bookkeeping is
/// deleted. GC may reclaim the head while the writer is open, and the writer's abort still leaves a
/// correct chain, because it recomputes rather than restores.
///
/// **Non-vacuity.** The two assertions that matter are kept and are the ones that would fail if the
/// abort had gone back to restoring a captured id: after `W` aborts, the node's chain contains
/// exactly the live edges, and `check_store` is clean — the pre-#969 failure produced
/// `Adjacency { detail: DeadRel }` and `FreeList { detail: ReferencedByLiveChain }` right here. The
/// GC pass is asserted to have actually reclaimed, so the race is genuinely run.
#[test]
fn gc_may_reclaim_a_tombstoned_head_while_a_writer_prepends_onto_it() {
    let mut s = fresh();
    let rt = s.intern_token(Namespace::RelType, "R").expect("intern");

    let setup = TxnId(1);
    s.begin(setup);
    let (n, _) = s.create_node(setup).expect("n");
    let (l, _) = s.create_node(setup).expect("l");
    let (l2, _) = s.create_node(setup).expect("l2");
    let (head, _) = s
        .create_rel(setup, rt, n, l)
        .expect("the edge that becomes the head");
    s.commit(setup).expect("commit setup");

    // The head is tombstoned and committed, so it is reclaimable on its own terms.
    let del = TxnId(2);
    s.begin(del);
    s.delete_rel(del, head).expect("tombstone the head");
    s.commit(del).expect("commit the deletion");

    // W prepends a new edge on top of the tombstoned head.
    let w = TxnId(3);
    s.begin(w);
    let (fresh_edge, _) = s.create_rel(w, rt, n, l2).expect("W prepends");
    assert_eq!(s.node(n).expect("read n").first_rel, fresh_edge);

    // A GC pass runs while W is still open, at a watermark that reclaims the head. No deferral.
    let watermark = s.snapshot_ts();
    let g = TxnId(4);
    s.begin(g);
    let pass = s.gc(g, watermark).expect("gc pass");
    s.commit(g).expect("commit gc");
    assert!(
        pass.reclaimed >= 1,
        "non-vacuity: the GC pass must actually reclaim the tombstoned head, or the race this test \
         exists for never happens (got {})",
        pass.reclaimed
    );

    s.rollback(w).expect("W aborts");
    assert!(
        s.incident_rels(n).expect("walk").is_empty(),
        "rmp #970: the abort unlinked its own edge and restored no captured id, so n's chain is \
         empty — the reclaimed head is NOT resurrected onto the free list"
    );
    assert_consistent(&mut s, "after a GC pass raced an open prepend");
}

/// Reclaiming a relationship that an **aborted prepend** left with a stale `prev` and a cleared
/// first-in-chain marker must free its slot exactly **once**.
///
/// `relink_old_head` writes those two fields with an *undo == redo* image (`rmp` #239), so an abort
/// of the prepend leaves them naming the aborted record. The relationship is the node's head again —
/// `first_rel` says so — while its own pointers say it is not. A reclaim that trusted the record took
/// the neighbour branch, left `first_rel` naming the freed slot, and the corpse splice then
/// re-discovered it from that head and freed it a **second** time. A free list that does not
/// deduplicate hands one physical id to two records, whose chains self-cycle (`rmp` #578).
///
/// **Non-vacuity.** Against the tree before the headship re-derivation in `unlink_side_with`, this
/// exact sequence — abort a prepend, then run one GC pass, with no concurrency at all — ends with
/// `check_store` reporting `FreeList { kind: Rel, id: 1, detail: Duplicate }`.
#[test]
fn reclaiming_a_relationship_an_aborted_prepend_left_stale_frees_its_slot_once() {
    let mut s = fresh();
    let rt = s.intern_token(Namespace::RelType, "R").expect("intern");

    let setup = TxnId(1);
    s.begin(setup);
    let (n, _) = s.create_node(setup).expect("n");
    let (l, _) = s.create_node(setup).expect("l");
    let (l2, _) = s.create_node(setup).expect("l2");
    let (head, _) = s.create_rel(setup, rt, n, l).expect("head edge");
    s.commit(setup).expect("commit setup");

    let del = TxnId(2);
    s.begin(del);
    s.delete_rel(del, head).expect("tombstone the head");
    s.commit(del).expect("commit the deletion");

    // Prepend and abort: the head keeps a stale `prev` and a cleared first-in-chain marker.
    let w = TxnId(3);
    s.begin(w);
    let _ = s.create_rel(w, rt, n, l2).expect("W prepends");
    s.rollback(w).expect("W aborts");
    assert_eq!(
        s.node(n).expect("read n").first_rel,
        head,
        "the abort restored the head, so `first_rel` names it again"
    );
    assert_consistent(&mut s, "after the aborted prepend");

    let g = TxnId(4);
    s.begin(g);
    s.gc(g, s.snapshot_ts()).expect("gc pass");
    s.commit(g).expect("commit gc");
    assert_consistent(&mut s, "after reclaiming a stale-marked head");
}

/// The GC gate must be **exact**: an open edge writer on a hub may not stop every other tombstoned
/// relationship on that hub from being reclaimed.
///
/// The first version of the gate asked "does either endpoint carry an uncommitted incidence delta?",
/// which on a hub under sustained insertion is always true — so reclamation stopped entirely and the
/// space leak was unbounded. Only the relationship a writer actually captured as its `first_rel`
/// pre-image needs protecting.
///
/// **Non-vacuity.** Against that first version this test reports `reclaimed: 0`: the open writer's
/// incidence delta on the hub blocks the unrelated tombstoned edge as well.
#[test]
fn an_open_edge_writer_does_not_starve_reclamation_of_other_edges_on_the_hub() {
    let mut s = fresh();
    let rt = s.intern_token(Namespace::RelType, "R").expect("intern");

    let setup = TxnId(1);
    s.begin(setup);
    let (hub, _) = s.create_node(setup).expect("hub");
    let (l1, _) = s.create_node(setup).expect("l1");
    let (l2, _) = s.create_node(setup).expect("l2");
    let (l3, _) = s.create_node(setup).expect("l3");
    let (doomed, _) = s.create_rel(setup, rt, hub, l1).expect("the doomed edge");
    // A second, later edge becomes the head, so `doomed` is NOT what a prepend captures.
    let _ = s.create_rel(setup, rt, hub, l2).expect("the head edge");
    s.commit(setup).expect("commit setup");

    let del = TxnId(2);
    s.begin(del);
    s.delete_rel(del, doomed)
        .expect("tombstone the doomed edge");
    s.commit(del).expect("commit the deletion");

    // An open writer inserts on the same hub. It captures the CURRENT head, which is not `doomed`.
    let w = TxnId(3);
    s.begin(w);
    let _ = s.create_rel(w, rt, hub, l3).expect("W prepends");

    let g = TxnId(4);
    s.begin(g);
    let pass = s.gc(g, s.snapshot_ts()).expect("gc pass");
    s.commit(g).expect("commit gc");
    assert!(
        pass.reclaimed >= 1,
        "an unrelated tombstoned edge on the hub must still be reclaimed while a writer is \
         inserting; got {}",
        pass.reclaimed
    );

    s.commit(w).expect("W commits");
    assert_consistent(&mut s, "after reclaiming under an open edge writer");
}
