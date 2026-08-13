//! **`rmp` #1069 phase 3, acceptance criterion 4 — the STRUCTURAL half of the measurement.**
//!
//! A record header's unsettled MVCC stamp stopped naming a `TxnId` translatable by an in-memory
//! table and started naming a slot in `commit.store`. Resolving one is therefore a **durable read**
//! where it used to be a hash lookup, and the honest question is not "did the benchmark move?" — a
//! wall-clock number is a property of this host — but **how many commit-slot reads does one entity
//! visibility decision perform, and does that number depend on anything it should not?**
//!
//! Two numbers matter and they are different, which is why both are pinned here:
//!
//! * with the header **settled** (a GC pass has frozen it to `Committed(ts)`), resolution is a bit
//!   test on the word and costs **zero** slot reads. This is the steady state of any store whose GC
//!   has run, and it is what makes the change free on the hot path;
//! * with the header **unsettled** (committed, not yet frozen), the durable slot must be read. The
//!   bound is what matters: it must be **one read per decision**, not one per header word, because
//!   the naive shape asks the door twice per word — once for the own-write override and once for the
//!   outcome — which would be four reads per record. `CommitOracle::resolve_for` exists to collapse
//!   that pair into one resolution, and this file is the proof that it does.
//!
//! Neither number can be satisfied by a faster machine, which is the whole reason the proof is a
//! count. See `graphus_storage::read_probe` for the general argument.
//!
//! # Running
//!
//! ```text
//! cargo test -p graphus-storage --features read-probe --test entity_visibility_record_count_1069
//! ```
#![cfg(feature = "read-probe")]

use graphus_core::{HeaderStamp, TxnId, Value};
use graphus_io::MemBlockDevice;
use graphus_storage::{Namespace, RecordStore, StoreKind, read_probe};
use graphus_txn::Snapshot;
use graphus_wal::{MemLogSink, WalManager};

type Store = RecordStore<MemBlockDevice, MemLogSink>;

fn fresh() -> Store {
    let device = MemBlockDevice::new(0);
    let wal = WalManager::create(MemLogSink::new()).expect("create wal");
    RecordStore::create(device, wal, 256, 1).expect("create store")
}

/// One committed node carrying one property, and a spectator snapshot that sees it.
fn committed_node() -> (Store, u64, u32, Snapshot) {
    let store = fresh();
    let key = store
        .intern_token(Namespace::PropKey, "v")
        .expect("intern propkey");
    let t = TxnId(1);
    store.begin(t);
    let (node, _eid) = store.create_node(t).expect("create node");
    store
        .set_node_property_value(t, node, key, &Value::Integer(7))
        .expect("set property");
    store.commit(t).expect("commit");
    let snap = Snapshot::new(TxnId(90), store.snapshot_ts());
    (store, node, key, snap)
}

/// Whether `node`'s `created_ts` still names a commit slot (i.e. has not been settled).
fn unsettled(store: &Store, node: u64) -> bool {
    HeaderStamp::from_raw(store.node(node).expect("read node").mvcc.created_ts)
        .slot_id()
        .is_some()
}

/// The record reads one **entity visibility decision** costs.
///
/// `entity_visible_at` is the seam every scan and every seek filters rows through, so it is the unit
/// the cost of the change is measured in. The verdict is asserted, so a count can never come from a
/// read that did not happen.
fn reads_for_one_visibility_decision(
    store: &Store,
    node: u64,
    snap: Snapshot,
) -> read_probe::RecordReads {
    let mvcc = store.node(node).expect("read node").mvcc;
    let (visible, counts) = read_probe::counting(|| {
        store
            .entity_visible_at(StoreKind::Node, node, mvcc, snap)
            .expect("existence at snapshot")
    });
    assert!(visible, "the committed node must be visible");
    counts
}

/// **The settled case costs no commit-slot read at all.**
///
/// Once GC has frozen a header, its stamp carries the commit timestamp directly and the oracle
/// answers from the word. That is the state every store reaches, and it is why the phase adds nothing
/// to the steady-state read path: the indirection exists only while a version is young.
#[test]
fn a_settled_header_resolves_with_zero_commit_slot_reads() {
    let (store, node, _key, _snap) = committed_node();
    // Settle every stamp, exactly as a maintenance GC pass does.
    let watermark = store.snapshot_ts();
    let gc = TxnId(50);
    store.begin(gc);
    store.gc(gc, watermark).expect("gc");
    store.commit(gc).expect("commit gc");
    assert!(
        !unsettled(&store, node),
        "the premise: GC must actually have settled the header, or this measures the other case",
    );

    let snap = Snapshot::new(TxnId(91), store.snapshot_ts());
    let reads = reads_for_one_visibility_decision(&store, node, snap);
    assert_eq!(
        reads.commit, 0,
        "a settled stamp is resolved from the word itself — no commit.store read (got {reads:?})",
    );
}

/// **The unsettled case costs exactly ONE commit-slot read per decision — not one per header word.**
///
/// `is_visible_via` asks two questions of `xmin` (does it name my own write? what became of its
/// transaction?) and, when the creator is visible, the same two of `xmax`. Against the in-memory
/// table that was four hash lookups and free. Against `commit.store` the naive shape is four durable
/// reads per record, and this asserts it is not.
///
/// The bound is **one**, and the reason it is one rather than two is that only `xmin` names a slot on
/// a live version: `xmax` is the `0` sentinel, which resolves with no read under either convention.
/// A version that is both created and expired by unsettled writers would cost two — one per *word*,
/// still never two per word.
#[test]
fn an_unsettled_header_costs_one_commit_slot_read_per_decision() {
    let (store, node, _key, snap) = committed_node();
    assert!(
        unsettled(&store, node),
        "the premise: no GC has run, so the header must still name its writer's commit slot",
    );

    let reads = reads_for_one_visibility_decision(&store, node, snap);
    assert_eq!(
        reads.commit, 1,
        "ONE resolution per unsettled word, not one per question asked of it — \
         `CommitOracle::resolve_for` collapses the own-write test and the outcome into a single slot \
         read (got {reads:?})",
    );
}

/// **The count does not grow with the number of decisions taken over the same version.**
///
/// A per-decision cost of one is only meaningful if it stays one. This reads the same node's
/// visibility ten times and asserts ten reads — linear in decisions, and in nothing else. It is the
/// control that would catch a resolution that had quietly become a chain walk.
#[test]
fn the_cost_is_linear_in_decisions_and_nothing_else() {
    let (store, node, _key, snap) = committed_node();
    let mvcc = store.node(node).expect("read node").mvcc;
    let (n, counts) = read_probe::counting(|| {
        let mut seen = 0usize;
        for _ in 0..10 {
            if store
                .entity_visible_at(StoreKind::Node, node, mvcc, snap)
                .expect("existence at snapshot")
            {
                seen += 1;
            }
        }
        seen
    });
    assert_eq!(n, 10);
    assert_eq!(
        counts.commit, 10,
        "ten decisions, ten slot reads: the resolution is O(1) per decision (got {counts:?})",
    );
}
