//! Per-transaction undo for the **live-record count** half of `Statistics` (`rmp` #866).
//!
//! # The defect these tests pin
//!
//! The six durable counters — `total_nodes`, `total_relationships`, `nodes_per_label`,
//! `rels_per_type`, and the `rmp` #856 directional projections `rels_per_start_label_type` /
//! `rels_per_type_end_label` — are mutated **eagerly at write time**, but `rollback` used to restore
//! them by reloading the *durable* catalog wholesale. Under statement-granularity interleaving of two
//! transactions (which the single engine thread allows: commands are serialised, transactions are
//! not) that wholesale revert is wrong in **both** directions, and the error is **permanent** — it
//! survives the next checkpoint and every reopen after it:
//!
//! * **P3 (over-count).** `T1 CREATE (:Person)` [open] → `T2 CREATE (:Person)` COMMIT → `T1 ROLLBACK`.
//!   T2's commit checkpoints the *live* counter, which already carries T1's uncommitted `+1`; T1's
//!   rollback then reloads that checkpoint as though it were committed. Counter `2`, true live `1`.
//! * **P4 (under-count).** `T1 CREATE (:Person)` [open] → `T2 CREATE (:Person)` [open] → `T1 ROLLBACK`
//!   → `T2 COMMIT`. T1's rollback reverts the counter to the durable image, wiping T2's still-pending
//!   `+1`; T2's commit then checkpoints the wiped value. Counter `0`, true live `1`.
//!
//! Every other monotonic/shared catalog field in `rollback` already had exactly this treatment — the
//! `rmp` #220/#172 high-water floor, the #578 free-list `pre_free` minus own pushes, the #534/#734
//! schema `pre_statistics` + per-transaction undo. The counts half had none. `rmp` #866 (answer
//! `count()` from these counters instead of scanning) turns the drift from a planner-estimate error
//! into a **wrong query answer**, i.e. an ACID/TCK breach, which is why it is closed here first.
//!
//! # Oracle
//!
//! Every assertion compares the counters against an **independent re-scan** built in this file from
//! public record reads only — it shares no code with the maintenance path under test. "Live" means
//! what it means to the counters: the slot is in use **and** the record carries no MVCC tombstone
//! (`xmax == 0`). After a rollback the aborting transaction's records have been undone to
//! `!in_use`, so the re-scan is the exact post-condition oracle.

use std::collections::BTreeMap;

use graphus_core::TxnId;
use graphus_io::{MemBlockDevice, Page};
use graphus_storage::recovery::recover_device;
use graphus_storage::{Namespace, RecordStore};
use graphus_wal::{LogSink, MemLogSink, WalManager};

type Store = RecordStore<MemBlockDevice, MemLogSink>;

/// The scalar counters an independent live re-scan computes.
#[derive(Debug, PartialEq, Eq)]
struct Scalars {
    nodes: u64,
    relationships: u64,
    per_label: BTreeMap<u32, u64>,
    per_type: BTreeMap<u32, u64>,
}

/// Both directional maps: `(by_start_label_type, by_type_end_label)` (`rmp` #856).
type Directional = (BTreeMap<(u32, u32), u64>, BTreeMap<(u32, u32), u64>);

fn fresh(cap: usize) -> Store {
    let device = MemBlockDevice::new(0);
    let wal = WalManager::create(MemLogSink::new()).expect("create wal");
    RecordStore::create(device, wal, cap, 1).expect("create store")
}

/// Independent re-scan oracle for the four scalar counters, from public reads only.
fn rescan_scalars(s: &mut Store) -> Scalars {
    let mut out = Scalars {
        nodes: 0,
        relationships: 0,
        per_label: BTreeMap::new(),
        per_type: BTreeMap::new(),
    };
    for id in s.scan_node_ids().expect("scan nodes") {
        let rec = s.node(id).expect("read node");
        if rec.mvcc.expired_ts != 0 {
            continue;
        }
        out.nodes += 1;
        for token in s.node_labels(id).expect("node labels") {
            *out.per_label.entry(token).or_insert(0) += 1;
        }
    }
    for id in s.scan_rel_ids().expect("scan rels") {
        let rel = s.rel(id).expect("read rel");
        if rel.mvcc.expired_ts != 0 {
            continue;
        }
        out.relationships += 1;
        *out.per_type.entry(rel.type_id).or_insert(0) += 1;
    }
    out
}

/// Independent re-scan oracle for the two directional projections (`rmp` #856), from public reads
/// only. A self-loop's single node is both endpoints, so it contributes to both maps — the oracle
/// gets that by asking the same node twice rather than by special-casing it.
fn rescan_directional(s: &mut Store) -> Directional {
    let mut by_start: BTreeMap<(u32, u32), u64> = BTreeMap::new();
    let mut by_end: BTreeMap<(u32, u32), u64> = BTreeMap::new();
    for id in s.scan_rel_ids().expect("scan rels") {
        let rel = s.rel(id).expect("read rel");
        if rel.mvcc.expired_ts != 0 {
            continue;
        }
        for label in s.node_labels(rel.start_node).expect("start labels") {
            *by_start.entry((label, rel.type_id)).or_insert(0) += 1;
        }
        for label in s.node_labels(rel.end_node).expect("end labels") {
            *by_end.entry((rel.type_id, label)).or_insert(0) += 1;
        }
    }
    (by_start, by_end)
}

/// Asserts every one of the six counters equals the independent re-scan. `when` names the point in
/// the interleaving, so a failure reports which step of the scenario drifted.
fn assert_all_counters_match_rescan(s: &mut Store, when: &str) {
    let want = rescan_scalars(s);
    let (want_start, want_end) = rescan_directional(s);
    let stats = s.statistics();
    assert_eq!(
        stats.total_nodes(),
        want.nodes,
        "{when}: total_nodes must equal a live re-scan"
    );
    assert_eq!(
        stats.total_relationships(),
        want.relationships,
        "{when}: total_relationships must equal a live re-scan"
    );
    assert_eq!(
        stats.nodes_per_label, want.per_label,
        "{when}: nodes_per_label must equal a live re-scan"
    );
    assert_eq!(
        stats.rels_per_type, want.per_type,
        "{when}: rels_per_type must equal a live re-scan"
    );
    assert_eq!(
        stats.rels_per_start_label_type, want_start,
        "{when}: rels_per_start_label_type must equal a live re-scan (`rmp` #856)"
    );
    assert_eq!(
        stats.rels_per_type_end_label, want_end,
        "{when}: rels_per_type_end_label must equal a live re-scan (`rmp` #856)"
    );
}

/// The durable WAL bytes of a store (its group-committed log prefix).
fn durable_log(store: &Store) -> Vec<u8> {
    store.with_wal(|w| w.sink().durable_bytes().to_vec())
}

/// Recovers a *no-force* crash: committed work lives only in the durable WAL; the data device was
/// never flushed. Replays the WAL onto a fresh empty device, then opens the store. This is the
/// crash-shaped reopen — losers are undone, so the recovered counters must equal the recovered
/// records.
fn recover_no_force(store: &Store) -> Store {
    let log = durable_log(store);
    let mut sink = MemLogSink::new();
    sink.append(&log);
    sink.sync().expect("sync log prefix");

    let mut device = MemBlockDevice::new(0);
    let mut wal = WalManager::open(sink.clone()).expect("open wal");
    recover_device(&mut wal, &mut device).expect("recover");

    let wal = WalManager::open(sink).expect("reopen wal");
    RecordStore::open(device, wal, 64).expect("open store")
}

/// Splits a flushed store into its device + a freshly-opened WAL over the same durable log, so the
/// store can be reopened. The pages were flushed home, so this is a clean reopen.
fn into_parts(mut s: Store) -> (MemBlockDevice, WalManager<MemLogSink>) {
    s.flush().unwrap();
    let pages = s.mapped_pages();
    let max = pages.iter().map(|p| p.0).max().unwrap_or(0);
    let mut device = MemBlockDevice::new(max + 1);
    {
        let mut staged: Vec<(u64, Box<Page>)> = Vec::new();
        for p in &pages {
            staged.push((p.0, s.read_device_page(*p).expect("read device page")));
        }
        use graphus_io::BlockDevice;
        for (idx, bytes) in staged {
            device
                .write_page(graphus_core::PageId(idx), &bytes)
                .expect("stage page");
        }
        device.sync_all().expect("persist disk image");
    }
    let sink = s.with_wal(|w| w.sink().clone());
    let wal = WalManager::open(sink).expect("reopen wal");
    (device, wal)
}

/// A committed baseline: one `:Person` node, so no later equality can hold vacuously against an
/// empty catalog. Returns the `Person` label token.
fn committed_baseline(s: &mut Store) -> u32 {
    let t0 = TxnId(1);
    s.begin(t0);
    let person = s.intern_token(Namespace::Label, "Person").unwrap();
    let (a, _) = s.create_node(t0).unwrap();
    s.add_label(t0, a, person).unwrap();
    s.commit(t0).unwrap();
    person
}

// ---------------------------------------------------------------------------------------------
// P3 — a concurrent COMMIT bakes the open transaction's counts; its later ROLLBACK reads them back
// ---------------------------------------------------------------------------------------------

#[test]
fn p3_a_concurrent_commit_then_own_rollback_must_not_overcount() {
    let mut s = fresh(64);
    let person = committed_baseline(&mut s);
    assert_eq!(s.node_count_for_label(person), 1, "baseline");

    // T1 creates a labelled node and stays OPEN.
    let t1 = TxnId(2);
    s.begin(t1);
    let (n1, _) = s.create_node(t1).unwrap();
    s.add_label(t1, n1, person).unwrap();

    // T2 creates a labelled node and COMMITS — its `checkpoint_meta` persists the catalog, which must
    // carry T2's `+1` and NOT T1's still-uncommitted one.
    let t2 = TxnId(3);
    s.begin(t2);
    let (n2, _) = s.create_node(t2).unwrap();
    s.add_label(t2, n2, person).unwrap();
    s.commit(t2).unwrap();

    // T1 aborts. Its own `+1` must go; T2's committed `+1` must stay.
    s.rollback(t1).unwrap();

    assert_eq!(
        s.node_count_for_label(person),
        2,
        "P3: the baseline node + T2's committed node, and nothing of aborted T1"
    );
    assert_eq!(s.total_node_count(), 2, "P3: total_nodes");
    assert_all_counters_match_rescan(&mut s, "P3 after T1 rollback");
}

#[test]
fn p3_directional_projections_must_not_overcount() {
    let mut s = fresh(64);
    let t0 = TxnId(1);
    s.begin(t0);
    let person = s.intern_token(Namespace::Label, "Person").unwrap();
    let knows = s.intern_token(Namespace::RelType, "KNOWS").unwrap();
    let (a, _) = s.create_node(t0).unwrap();
    let (b, _) = s.create_node(t0).unwrap();
    s.add_label(t0, a, person).unwrap();
    s.add_label(t0, b, person).unwrap();
    s.create_rel(t0, knows, a, b).unwrap();
    s.commit(t0).unwrap();

    // T1 adds a second KNOWS edge between the same labelled endpoints and stays OPEN.
    let t1 = TxnId(2);
    s.begin(t1);
    s.create_rel(t1, knows, b, a).unwrap();

    // T2 adds a third and COMMITS.
    let t2 = TxnId(3);
    s.begin(t2);
    s.create_rel(t2, knows, a, b).unwrap();
    s.commit(t2).unwrap();

    s.rollback(t1).unwrap();

    assert_eq!(
        s.rel_count_for_start_label_type(person, knows),
        2,
        "P3/#856: baseline edge + T2's committed edge only"
    );
    assert_eq!(
        s.rel_count_for_type_end_label(knows, person),
        2,
        "P3/#856: baseline edge + T2's committed edge only"
    );
    assert_all_counters_match_rescan(&mut s, "P3 directional after T1 rollback");
}

// ---------------------------------------------------------------------------------------------
// P4 — a ROLLBACK wipes a concurrent open transaction's counts, and its COMMIT then persists the loss
// ---------------------------------------------------------------------------------------------

#[test]
fn p4_a_rollback_must_not_wipe_a_concurrent_transactions_counts() {
    let mut s = fresh(64);
    let person = committed_baseline(&mut s);

    // Both transactions create a labelled node and stay OPEN.
    let t1 = TxnId(2);
    s.begin(t1);
    let (n1, _) = s.create_node(t1).unwrap();
    s.add_label(t1, n1, person).unwrap();

    let t2 = TxnId(3);
    s.begin(t2);
    let (n2, _) = s.create_node(t2).unwrap();
    s.add_label(t2, n2, person).unwrap();

    // T1 aborts FIRST — it must withdraw only its own contribution.
    s.rollback(t1).unwrap();
    assert_eq!(
        s.node_count_for_label(person),
        2,
        "P4: after T1's rollback the live counter must still carry T2's pending node"
    );

    // T2 commits: its `+1` must survive into the checkpointed catalog.
    s.commit(t2).unwrap();

    assert_eq!(
        s.node_count_for_label(person),
        2,
        "P4: the baseline node + T2's committed node"
    );
    assert_eq!(s.total_node_count(), 2, "P4: total_nodes");
    assert_all_counters_match_rescan(&mut s, "P4 after T2 commit");
}

#[test]
fn p4_directional_projections_must_not_undercount() {
    let mut s = fresh(64);
    let t0 = TxnId(1);
    s.begin(t0);
    let person = s.intern_token(Namespace::Label, "Person").unwrap();
    let knows = s.intern_token(Namespace::RelType, "KNOWS").unwrap();
    let (a, _) = s.create_node(t0).unwrap();
    let (b, _) = s.create_node(t0).unwrap();
    s.add_label(t0, a, person).unwrap();
    s.add_label(t0, b, person).unwrap();
    s.create_rel(t0, knows, a, b).unwrap();
    s.commit(t0).unwrap();

    let t1 = TxnId(2);
    s.begin(t1);
    s.create_rel(t1, knows, b, a).unwrap();

    let t2 = TxnId(3);
    s.begin(t2);
    s.create_rel(t2, knows, a, b).unwrap();

    s.rollback(t1).unwrap();
    s.commit(t2).unwrap();

    assert_eq!(
        s.rel_count_for_start_label_type(person, knows),
        2,
        "P4/#856: baseline edge + T2's committed edge"
    );
    assert_eq!(
        s.rel_count_for_type_end_label(knows, person),
        2,
        "P4/#856: baseline edge + T2's committed edge"
    );
    assert_all_counters_match_rescan(&mut s, "P4 directional after T2 commit");
}

// ---------------------------------------------------------------------------------------------
// The DELETE direction of both scenarios (the `dec_*` mutators are the exact inverse hazard)
// ---------------------------------------------------------------------------------------------

#[test]
fn p3_a_rolled_back_delete_must_not_undercount() {
    let mut s = fresh(64);
    let t0 = TxnId(1);
    s.begin(t0);
    let person = s.intern_token(Namespace::Label, "Person").unwrap();
    let (a, _) = s.create_node(t0).unwrap();
    let (b, _) = s.create_node(t0).unwrap();
    s.add_label(t0, a, person).unwrap();
    s.add_label(t0, b, person).unwrap();
    s.commit(t0).unwrap();
    assert_eq!(s.node_count_for_label(person), 2, "baseline");

    // T1 deletes `a` (`-1`) and stays open; T2 creates a third labelled node and commits, baking
    // T1's uncommitted `-1` into the checkpoint; T1 then aborts and reads it back.
    let t1 = TxnId(2);
    s.begin(t1);
    s.delete_node(t1, a).unwrap();

    let t2 = TxnId(3);
    s.begin(t2);
    let (c, _) = s.create_node(t2).unwrap();
    s.add_label(t2, c, person).unwrap();
    s.commit(t2).unwrap();

    s.rollback(t1).unwrap();

    assert_eq!(
        s.node_count_for_label(person),
        3,
        "P3/delete: a and b are still live (T1 aborted) plus T2's committed c"
    );
    assert_all_counters_match_rescan(&mut s, "P3 delete after T1 rollback");
}

#[test]
fn p4_a_concurrent_open_delete_must_survive_an_unrelated_rollback() {
    let mut s = fresh(64);
    let t0 = TxnId(1);
    s.begin(t0);
    let person = s.intern_token(Namespace::Label, "Person").unwrap();
    let (a, _) = s.create_node(t0).unwrap();
    let (b, _) = s.create_node(t0).unwrap();
    s.add_label(t0, a, person).unwrap();
    s.add_label(t0, b, person).unwrap();
    s.commit(t0).unwrap();

    // T1 creates (open); T2 deletes `a` (open); T1 aborts; T2 commits.
    let t1 = TxnId(2);
    s.begin(t1);
    let (n1, _) = s.create_node(t1).unwrap();
    s.add_label(t1, n1, person).unwrap();

    let t2 = TxnId(3);
    s.begin(t2);
    s.delete_node(t2, a).unwrap();

    s.rollback(t1).unwrap();
    s.commit(t2).unwrap();

    assert_eq!(
        s.node_count_for_label(person),
        1,
        "P4/delete: only b survives — T2's committed delete must not be resurrected by T1's rollback"
    );
    assert_all_counters_match_rescan(&mut s, "P4 delete after T2 commit");
}

// ---------------------------------------------------------------------------------------------
// The existing single-writer behaviour must not regress
// ---------------------------------------------------------------------------------------------

#[test]
fn a_lone_rollback_still_discards_its_own_counts() {
    let mut s = fresh(64);
    let t0 = TxnId(1);
    s.begin(t0);
    let person = s.intern_token(Namespace::Label, "Person").unwrap();
    let knows = s.intern_token(Namespace::RelType, "KNOWS").unwrap();
    let (a, _) = s.create_node(t0).unwrap();
    let (b, _) = s.create_node(t0).unwrap();
    s.add_label(t0, a, person).unwrap();
    s.add_label(t0, b, person).unwrap();
    let (r, _) = s.create_rel(t0, knows, a, b).unwrap();
    s.commit(t0).unwrap();
    let baseline = (
        s.total_node_count(),
        s.total_relationship_count(),
        s.node_count_for_label(person),
        s.rel_count_for_type(knows),
        s.rel_count_for_start_label_type(person, knows),
        s.rel_count_for_type_end_label(knows, person),
    );
    assert_eq!(baseline, (2, 1, 2, 1, 1, 1), "baseline");

    // A lone aborting transaction that moves every counter in both directions.
    let t1 = TxnId(2);
    s.begin(t1);
    let (c, _) = s.create_node(t1).unwrap();
    s.add_label(t1, c, person).unwrap();
    s.create_rel(t1, knows, a, c).unwrap();
    s.delete_rel(t1, r).unwrap();
    s.remove_label(t1, b, person).unwrap();
    s.delete_node(t1, b).unwrap();
    s.rollback(t1).unwrap();

    assert_eq!(
        (
            s.total_node_count(),
            s.total_relationship_count(),
            s.node_count_for_label(person),
            s.rel_count_for_type(knows),
            s.rel_count_for_start_label_type(person, knows),
            s.rel_count_for_type_end_label(knows, person),
        ),
        baseline,
        "a lone rollback must leave every counter at its committed value"
    );
    assert_all_counters_match_rescan(&mut s, "lone rollback");
}

#[test]
fn a_concurrent_open_transactions_counts_survive_an_unrelated_rollback() {
    let mut s = fresh(64);
    let person = committed_baseline(&mut s);

    // T2 is the innocent bystander: it writes and stays open across T1's whole lifecycle.
    let t2 = TxnId(3);
    s.begin(t2);
    let (n2, _) = s.create_node(t2).unwrap();
    s.add_label(t2, n2, person).unwrap();

    let t1 = TxnId(2);
    s.begin(t1);
    let (n1, _) = s.create_node(t1).unwrap();
    s.add_label(t1, n1, person).unwrap();
    s.rollback(t1).unwrap();

    // The LIVE counters are "committed image + every in-flight delta", so T2's pending node is still
    // counted here — the shared/eager semantics are deliberately unchanged.
    assert_eq!(
        s.node_count_for_label(person),
        2,
        "the live counter must still carry open T2's pending node after T1's unrelated rollback"
    );
    assert_eq!(s.total_node_count(), 2);
    assert_all_counters_match_rescan(&mut s, "bystander T2 still open");
}

// ---------------------------------------------------------------------------------------------
// Checkpoint / reopen: what the durable catalog must (and must not) carry
// ---------------------------------------------------------------------------------------------

#[test]
fn a_committed_writes_counts_survive_the_checkpoint_and_reopen() {
    // The sharp edge of stripping open transactions at checkpoint time: the COMMITTING transaction
    // must NOT be stripped from its own checkpoint. `commit_prepare` removes `txn` from the active
    // set BEFORE it calls `checkpoint_meta`, so the strip sees only the OTHER open transactions —
    // this test is the guard that keeps that ordering true.
    let mut s = fresh(64);
    let t0 = TxnId(1);
    s.begin(t0);
    let person = s.intern_token(Namespace::Label, "Person").unwrap();
    let knows = s.intern_token(Namespace::RelType, "KNOWS").unwrap();
    let (a, _) = s.create_node(t0).unwrap();
    let (b, _) = s.create_node(t0).unwrap();
    s.add_label(t0, a, person).unwrap();
    s.add_label(t0, b, person).unwrap();
    s.create_rel(t0, knows, a, b).unwrap();
    s.commit(t0).unwrap();

    let (device, wal) = into_parts(s);
    let mut reopened = RecordStore::open(device, wal, 64).expect("reopen");
    assert_eq!(reopened.total_node_count(), 2, "reopened total_nodes");
    assert_eq!(reopened.total_relationship_count(), 1);
    assert_eq!(reopened.node_count_for_label(person), 2);
    assert_eq!(reopened.rel_count_for_type(knows), 1);
    assert_eq!(reopened.rel_count_for_start_label_type(person, knows), 1);
    assert_eq!(reopened.rel_count_for_type_end_label(knows, person), 1);
    assert_all_counters_match_rescan(&mut reopened, "clean reopen");
}

#[test]
fn an_open_transactions_counts_are_not_baked_into_a_concurrent_commits_checkpoint() {
    // The crash-shaped case. T1 writes and stays open; T2 commits, which checkpoints the catalog.
    // A crash here loses T1 (ARIES undoes it), so the recovered catalog must not carry T1's counts —
    // the atomicity breach `rmp` #734 closed for the schema half, closed here for the counts half.
    let mut s = fresh(64);
    let person = committed_baseline(&mut s);

    let t1 = TxnId(2);
    s.begin(t1);
    let (n1, _) = s.create_node(t1).unwrap();
    s.add_label(t1, n1, person).unwrap();

    let t2 = TxnId(3);
    s.begin(t2);
    let (n2, _) = s.create_node(t2).unwrap();
    s.add_label(t2, n2, person).unwrap();
    s.commit(t2).unwrap();

    // Harden T1's tail so the crash log carries its records and recovery actually undoes them
    // (otherwise the loser's pages would simply be absent and the test would be vacuous).
    s.with_wal(graphus_wal::WalManager::flush);

    let mut rec = recover_no_force(&s);
    assert_eq!(
        rec.node_count_for_label(person),
        2,
        "recovered catalog must carry the baseline + T2's committed node, and nothing of open T1"
    );
    assert_eq!(rec.total_node_count(), 2);
    assert_all_counters_match_rescan(&mut rec, "recovered after crash with T1 open");
}

// ---------------------------------------------------------------------------------------------
// The predicate `rmp` #866's `count()` shortcut consumes
// ---------------------------------------------------------------------------------------------

#[test]
fn counts_match_committed_image_tracks_open_writers() {
    let mut s = fresh(64);
    assert!(
        s.counts_match_committed_image(),
        "a fresh store has no open writer"
    );

    let person = committed_baseline(&mut s);
    assert!(
        s.counts_match_committed_image(),
        "after a commit the live counters ARE the committed image"
    );

    // An open transaction that has not touched a counter does not disqualify the shortcut.
    let reader = TxnId(10);
    s.begin(reader);
    assert!(
        s.counts_match_committed_image(),
        "an open transaction that has moved no counter holds no delta"
    );

    // A counter-moving writer does.
    let writer = TxnId(11);
    s.begin(writer);
    let (n, _) = s.create_node(writer).unwrap();
    assert!(
        !s.counts_match_committed_image(),
        "an open writer's uncommitted node is folded into the live counter — the shortcut must \
         DECLINE and the caller must scan"
    );
    s.add_label(writer, n, person).unwrap();
    assert!(!s.counts_match_committed_image());

    // Committing publishes the delta into the committed image, so the predicate is true again.
    s.commit(writer).unwrap();
    assert!(
        s.counts_match_committed_image(),
        "a committed delta is part of the committed image"
    );
    assert_eq!(s.node_count_for_label(person), 2);

    // ...and so does aborting: a withdrawn delta leaves nothing pending either.
    let aborter = TxnId(12);
    s.begin(aborter);
    s.create_node(aborter).unwrap();
    assert!(!s.counts_match_committed_image());
    s.rollback(aborter).unwrap();
    assert!(
        s.counts_match_committed_image(),
        "an aborted transaction's delta is withdrawn, so nothing is pending"
    );

    s.rollback(reader).unwrap();
    assert!(s.counts_match_committed_image());
    assert_all_counters_match_rescan(&mut s, "after the predicate walk");
}

#[test]
fn a_delta_that_nets_to_zero_leaves_nothing_pending() {
    // The pruning contract behind `counts_match_committed_image`: a transaction that creates and then
    // deletes the same node has moved no counter on net, so it holds no delta — a later checkpoint has
    // nothing to strip and a later rollback has nothing to withdraw.
    let mut s = fresh(64);
    let person = committed_baseline(&mut s);

    let t1 = TxnId(2);
    s.begin(t1);
    let (n, _) = s.create_node(t1).unwrap();
    s.add_label(t1, n, person).unwrap();
    assert!(!s.counts_match_committed_image());
    s.delete_node(t1, n).unwrap();
    assert!(
        s.counts_match_committed_image(),
        "create + delete of the same node nets to zero, so no delta remains pending"
    );
    assert_eq!(s.node_count_for_label(person), 1);
    s.commit(t1).unwrap();
    assert_eq!(s.node_count_for_label(person), 1);
    assert_all_counters_match_rescan(&mut s, "after a net-zero transaction");
}

// ---------------------------------------------------------------------------------------------
// Deterministic interleaving stress: many transactions overlapping, resolving out of order
// ---------------------------------------------------------------------------------------------

#[test]
fn interleaved_writers_resolving_out_of_order_keep_every_counter_exact() {
    // P3/P4 are the two minimal shapes. This drives a deterministic pseudo-random schedule of
    // OVERLAPPING transactions that commit and abort **out of order** — the arrival order a per-entry
    // undo log would be sensitive to, and which a commutative delta must be immune to. Every counter
    // is checked against the independent re-scan at every resolution point, so a drift is caught at
    // the step that caused it rather than at the end.
    //
    // Deterministic by construction (a fixed xorshift, no clock, no thread scheduling), so a failure
    // reproduces byte-for-byte.
    let mut s = fresh(256);
    let t0 = TxnId(1);
    s.begin(t0);
    let labels: Vec<u32> = ["Person", "Admin", "Bot"]
        .iter()
        .map(|n| s.intern_token(Namespace::Label, n).unwrap())
        .collect();
    let types: Vec<u32> = ["KNOWS", "OWNS"]
        .iter()
        .map(|n| s.intern_token(Namespace::RelType, n).unwrap())
        .collect();
    // A committed corpus to write against, so nothing below holds vacuously against an empty graph.
    let mut live_nodes: Vec<u64> = Vec::new();
    for i in 0..8u64 {
        let (n, _) = s.create_node(t0).unwrap();
        s.add_label(t0, n, labels[(i % 3) as usize]).unwrap();
        live_nodes.push(n);
    }
    for i in 0..6usize {
        s.create_rel(
            t0,
            types[i % 2],
            live_nodes[i],
            live_nodes[(i + 1) % live_nodes.len()],
        )
        .unwrap();
    }
    s.commit(t0).unwrap();
    assert_all_counters_match_rescan(&mut s, "stress baseline");
    assert!(
        s.total_relationship_count() > 0 && s.node_count_for_label(labels[0]) > 0,
        "the baseline must be non-empty, else every comparison below holds vacuously"
    );

    // xorshift64*, seeded — a fixed schedule, not a random one.
    let mut rng: u64 = 0x2545_F491_4F6C_DD1D;
    let mut next = || {
        rng ^= rng << 13;
        rng ^= rng >> 7;
        rng ^= rng << 17;
        rng
    };

    // Up to three transactions open at once, each holding the nodes it created so it can delete them.
    let mut open: Vec<(TxnId, Vec<u64>)> = Vec::new();
    let mut next_txn = 2u64;

    for step in 0..120u64 {
        let roll = next() % 100;
        if open.len() < 3 && roll < 45 {
            // Open a new transaction and give it a write.
            let txn = TxnId(next_txn);
            next_txn += 1;
            s.begin(txn);
            let (n, _) = s.create_node(txn).unwrap();
            s.add_label(txn, n, labels[(next() % 3) as usize]).unwrap();
            if !live_nodes.is_empty() {
                let anchor = live_nodes[(next() as usize) % live_nodes.len()];
                s.create_rel(txn, types[(next() % 2) as usize], n, anchor)
                    .unwrap();
            }
            open.push((txn, vec![n]));
        } else if !open.is_empty() && roll < 70 {
            // Add another write to a transaction that is already open (interleaving, not batching).
            let which = (next() as usize) % open.len();
            let (txn, owned) = &mut open[which];
            let txn = *txn;
            let (n, _) = s.create_node(txn).unwrap();
            s.add_label(txn, n, labels[(next() % 3) as usize]).unwrap();
            // Re-label an owned node: exercises `apply_directional_label_change`, which re-keys the
            // directional counters of every edge incident to that node.
            if let Some(&first) = owned.first() {
                s.add_label(txn, first, labels[(next() % 3) as usize])
                    .unwrap();
            }
            owned.push(n);
        } else if !open.is_empty() {
            // Resolve one — NOT necessarily the newest, so aborts and commits arrive out of order.
            let which = (next() as usize) % open.len();
            let (txn, owned) = open.remove(which);
            if next() % 2 == 0 {
                s.rollback(txn).unwrap();
            } else {
                s.commit(txn).unwrap();
                live_nodes.extend(owned);
            }
        }
        assert_all_counters_match_rescan(&mut s, &format!("stress step {step}"));
    }

    // Drain whatever is still open, again out of order, and check after each.
    while let Some((txn, owned)) = open.pop() {
        if next() % 2 == 0 {
            s.rollback(txn).unwrap();
        } else {
            s.commit(txn).unwrap();
            live_nodes.extend(owned);
        }
        assert_all_counters_match_rescan(&mut s, "stress drain");
    }
    assert!(
        s.counts_match_committed_image(),
        "with everything resolved the live counters ARE the committed image"
    );

    // Finally: the durable catalog must agree too — the counters that survive a reopen are the ones
    // `rmp` #866's `count()` would answer from.
    let want_nodes = s.total_node_count();
    let want_rels = s.total_relationship_count();
    let want_per_label = s.statistics().nodes_per_label.clone();
    let want_start = s.statistics().rels_per_start_label_type.clone();
    let want_end = s.statistics().rels_per_type_end_label.clone();
    let (device, wal) = into_parts(s);
    let mut reopened = RecordStore::open(device, wal, 64).expect("reopen");
    assert_eq!(
        reopened.total_node_count(),
        want_nodes,
        "reopened total_nodes"
    );
    assert_eq!(reopened.total_relationship_count(), want_rels);
    assert_eq!(reopened.statistics().nodes_per_label, want_per_label);
    assert_eq!(
        reopened.statistics().rels_per_start_label_type,
        want_start,
        "reopened (startLabel, type) projection"
    );
    assert_eq!(reopened.statistics().rels_per_type_end_label, want_end);
    assert_all_counters_match_rescan(&mut reopened, "stress after reopen");
}
