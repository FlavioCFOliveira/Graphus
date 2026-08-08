//! Deterministic reproduction of the **Halloween problem** and of the statement-level isolation
//! that removes it (`rmp` #972, `04 §5.1.4`).
//!
//! # The defect this models
//!
//! A statement that reads and writes the same pattern can observe the rows it is itself producing.
//! The classic form is a scan that feeds a `CREATE`: every created row lands in the set the scan is
//! still walking, so the scan never reaches the end — `MATCH (n:L) CREATE (:L)` does not terminate.
//! The sibling form is an update that feeds an index seek: the updated row re-qualifies and is
//! incremented again.
//!
//! Both are the same bug — *the statement is not isolated from itself* — and the MVCC answer is one
//! comparison: an undo delta records the `command_id` of the statement that wrote it, and a read
//! taken on the `OLD` view undoes every delta of the current statement. Memgraph states the rule in
//! two lines (`/data/refsrc/memgraph/src/storage/v2/mvcc.hpp:72-94`); PostgreSQL states it as
//! `cmin < curcid` (`heapam_visibility.c:965`).
//!
//! # Why the DST, and why at the store rather than through Cypher
//!
//! The scenario needs a *statement-interleaved* transaction — a write, then a read at two different
//! polarities of the same statement, then the next statement — observed at explicit points. Driven
//! at the [`RecordStore`] layer it is fully deterministic: the interleaving is expressed as ordering
//! and not as threads, so a failure reproduces byte-for-byte on every machine and every run.
//!
//! It also has to be asserted **here** rather than only end-to-end, because the query planner holds
//! a *second*, independent Halloween defence — the openCypher `Eager` barrier
//! (`crates/graphus-cypher/src/physical.rs`). Two mechanisms that mask each other is precisely how
//! `rmp` #967's retired-mechanism defect happened, so each is proven on its own.
//!
//! # The invariants asserted
//!
//! 1. **Termination and cardinality.** A scan-feeds-create loop driven on the `OLD` view walks
//!    exactly the nodes that existed when the statement began, so `k` seed nodes produce `k`
//!    creations and the loop stops.
//! 2. **The defect is real.** The same loop on the `NEW` view sees its own creations — asserted
//!    positively, so the scenario cannot pass by the mechanism being inert.
//! 3. **The ladder.** Statement `i` of one transaction reads exactly the state statement `i-1` left,
//!    never its own.
//! 4. **Crash.** An in-flight statement's work does not survive a crash, and the recovered store
//!    reads the committed baseline with an empty undo area — the counter is transaction-local state
//!    and no recovered reader can ask about a statement that no longer exists.

use graphus_core::{PageId, TxnId, Value};
use graphus_io::{BlockDevice, MemBlockDevice};
use graphus_storage::{RecordStore, StoreKind};
use graphus_txn::{Snapshot, View};
use graphus_wal::{LogSink, MemLogSink, WalManager};

/// The store type the reproducer drives.
type Store = RecordStore<MemBlockDevice, MemLogSink>;

/// A small buffer-pool capacity, so eviction and the WAL rule are exercised during the run.
const POOL_CAPACITY: usize = 16;
/// The label every node in the scenario carries.
const LABEL_BIT: u32 = 0;
/// The property the update scenario increments.
const KEY: u32 = 1;
/// How many nodes the seed commits.
const SEED_NODES: usize = 4;

fn fresh_store() -> Store {
    let device = MemBlockDevice::new(0);
    let wal = WalManager::create(MemLogSink::new()).expect("create wal");
    RecordStore::create(device, wal, POOL_CAPACITY, 1).expect("create store")
}

/// The snapshot `txn` reads with at its current statement, on `view`.
fn snap(store: &Store, txn: TxnId, view: View) -> Snapshot {
    Snapshot::at_command(txn, store.snapshot_ts(), store.command_of(txn), view)
}

/// The labelled nodes `snapshot` sees — the store-level equivalent of `MATCH (n:L)`.
///
/// Both gates a label scan owes are applied, in the order the engine applies them: the entity must
/// exist to the snapshot, and it must carry the label *as of* that snapshot.
fn scan_labelled(store: &Store, snapshot: Snapshot) -> Vec<u64> {
    let registry = store.commit_registry_snapshot();
    let mut out = Vec::new();
    for id in store.scan_node_ids().expect("scan node ids") {
        let rec = store.node(id).expect("read node");
        if !store
            .entity_visible_at(StoreKind::Node, id, rec.mvcc, snapshot, &registry)
            .expect("existence at snapshot")
        {
            continue;
        }
        let bitmap = store
            .label_bitmap_at(id, rec.labels, rec.mvcc.undo_ptr, snapshot)
            .expect("labels at snapshot");
        if bitmap & (1u64 << LABEL_BIT) != 0 {
            out.push(id);
        }
    }
    out
}

/// The value `snapshot` reads for `node`'s [`KEY`].
fn value_at(store: &Store, node: u64, snapshot: Snapshot) -> Option<i64> {
    let decided = store
        .decision_scan_node_properties(node, snapshot)
        .expect("decision-polarity property read");
    let seen = decided.visible_version(KEY)?;
    match store
        .decode_property_value(seen.type_tag, seen.value_inline)
        .expect("decode")
    {
        Value::Integer(i) => Some(i),
        other => panic!("the scenario only ever writes integers, found {other:?}"),
    }
}

/// Commits [`SEED_NODES`] labelled nodes carrying `KEY = 1`, and returns their ids.
fn seed(store: &mut Store, txn: TxnId) -> Vec<u64> {
    store.begin(txn);
    let mut ids = Vec::with_capacity(SEED_NODES);
    for _ in 0..SEED_NODES {
        let (n, _) = store.create_node(txn).expect("create seed node");
        store.add_label(txn, n, LABEL_BIT).expect("seed label");
        store
            .set_node_property_value(txn, n, KEY, &Value::Integer(1))
            .expect("seed property");
        ids.push(n);
    }
    store.commit(txn).expect("seed commits");
    ids
}

// =================================================================================================
// Scenario 1 — scan feeds create
// =================================================================================================

/// What one run of the scan-feeds-create scenario observed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HalloweenReport {
    /// How many nodes the seed committed.
    pub seeded: usize,
    /// How many rows the `OLD`-view scan produced. Must equal [`seeded`](Self::seeded).
    pub old_view_rows: usize,
    /// How many nodes the statement created — one per scanned row.
    pub created: usize,
    /// Re-running the `OLD`-view scan *after* the creations. Must still equal
    /// [`seeded`](Self::seeded): the statement's own creations are invisible to it.
    pub old_view_rows_after: usize,
    /// The same scan on the `NEW` view, after the creations. Must be `seeded + created`: this is the
    /// positive proof that the creations really are there and that `OLD` is doing work.
    pub new_view_rows_after: usize,
    /// The `OLD`-view scan taken by the transaction's **next** statement. Must be
    /// `seeded + created`: an earlier statement's writes are part of what the next one starts from.
    pub next_statement_rows: usize,
}

impl HalloweenReport {
    /// The `rmp` #972 invariant: the statement is isolated from itself, its writes really happened,
    /// and the next statement sees them.
    #[must_use]
    pub fn statement_isolated(&self) -> bool {
        self.old_view_rows == self.seeded
            && self.created == self.seeded
            && self.old_view_rows_after == self.seeded
            && self.new_view_rows_after == self.seeded + self.created
            && self.next_statement_rows == self.seeded + self.created
    }
}

/// Drives the scan-feeds-create scenario and returns `(store, report)`.
fn drive_halloween() -> (Store, HalloweenReport) {
    let mut store = fresh_store();
    let seeded = seed(&mut store, TxnId(1)).len();

    let t = TxnId(2);
    store.begin(t);
    store.begin_command(t); // statement 1 opens

    // The scan the statement drives. Taken ONCE, on the OLD view, exactly as a `MATCH (n:L)` feeding
    // a `CREATE` does: the row set is settled by the state the statement began in.
    let rows = scan_labelled(&store, snap(&store, t, View::Old));
    let old_view_rows = rows.len();

    // One creation per scanned row — the write that, without statement isolation, feeds the scan.
    let mut created = 0usize;
    for _ in &rows {
        let (n, _) = store.create_node(t).expect("create node");
        store.add_label(t, n, LABEL_BIT).expect("label it");
        created += 1;
        // The invariant that makes the loop terminate, asserted at EVERY step rather than only at
        // the end: a scan re-taken mid-loop must still be the original row set.
        assert_eq!(
            scan_labelled(&store, snap(&store, t, View::Old)).len(),
            old_view_rows,
            "the statement's own creations must never enter the set it is walking"
        );
    }

    let old_view_rows_after = scan_labelled(&store, snap(&store, t, View::Old)).len();
    let new_view_rows_after = scan_labelled(&store, snap(&store, t, View::New)).len();

    store.begin_command(t); // statement 2 opens
    let next_statement_rows = scan_labelled(&store, snap(&store, t, View::Old)).len();

    store
        .commit(t)
        .expect("the statement's transaction commits");
    (
        store,
        HalloweenReport {
            seeded,
            old_view_rows,
            created,
            old_view_rows_after,
            new_view_rows_after,
            next_statement_rows,
        },
    )
}

/// Runs the scan-feeds-create reproduction and reports what each polarity observed.
#[must_use]
pub fn run_halloween_scan() -> HalloweenReport {
    drive_halloween().1
}

// =================================================================================================
// Scenario 2 — update feeds seek (the increment form)
// =================================================================================================

/// What one run of the update form observed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IncrementReport {
    /// The values the nodes hold when the statement ends. Every one must be `2`.
    pub values_after: Vec<i64>,
    /// How many nodes re-qualify for the **new** key the statement's own write moved them to, as
    /// re-checked against the statement's `OLD` view. Must be `0` — this is the number that, if it
    /// were not zero, would make an index scan raise the same row over and over.
    pub re_qualified_under_new_key: usize,
    /// The same re-check on the `NEW` view. Must be the full seed count: positive proof that the
    /// writes landed and that the rows really did move to the new key.
    pub moved_under_new_view: usize,
}

/// Runs the update form of the defect — the shape the Halloween problem is named after.
///
/// `MATCH (n) WHERE n.v = 1 SET n.v = n.v + 1` over an index on `v` is dangerous because the update
/// **moves the row's index entry** to the new key. A scan that later reaches that entry finds a
/// candidate, and if the candidate re-check is done against the live value the row qualifies again
/// and is incremented again — indefinitely, for a predicate that keeps admitting the new value.
///
/// The MVCC answer is that the re-check runs on the statement's `OLD` view, where the row's value is
/// still the one it had when the statement began — which does **not** match the key the moved entry
/// is filed under. The candidate is rejected, and it is rejected by construction rather than by the
/// scan happening not to revisit it.
///
/// That rejection is what this models: after the increments, re-checking every node against the new
/// key must yield nothing on `OLD` and everything on `NEW`.
#[must_use]
pub fn run_halloween_increment() -> IncrementReport {
    let mut store = fresh_store();
    let ids = seed(&mut store, TxnId(1));

    let t = TxnId(2);
    store.begin(t);
    store.begin_command(t);

    // The statement's qualifying set, decided once against the state it began in.
    let matched: Vec<u64> = ids
        .iter()
        .copied()
        .filter(|&id| value_at(&store, id, snap(&store, t, View::Old)) == Some(1))
        .collect();
    assert_eq!(matched.len(), ids.len(), "precondition: every seed matches");

    for &id in &matched {
        let now = value_at(&store, id, snap(&store, t, View::New)).expect("current value");
        store
            .set_node_property_value(t, id, KEY, &Value::Integer(now + 1))
            .expect("increment");
    }

    // The candidate re-check an index seek would perform on every entry the statement itself moved.
    let re_qualified_under_new_key = ids
        .iter()
        .filter(|&&id| value_at(&store, id, snap(&store, t, View::Old)) == Some(2))
        .count();
    let moved_under_new_view = ids
        .iter()
        .filter(|&&id| value_at(&store, id, snap(&store, t, View::New)) == Some(2))
        .count();

    let values_after = ids
        .iter()
        .map(|&id| value_at(&store, id, snap(&store, t, View::New)).expect("value"))
        .collect();
    store.commit(t).expect("commit");
    IncrementReport {
        values_after,
        re_qualified_under_new_key,
        moved_under_new_view,
    }
}

// =================================================================================================
// Scenario 3 — the statement ladder
// =================================================================================================

/// Runs a ladder of statements in one transaction, each incrementing every node once, and returns
/// what each statement's `OLD` view read on entry.
///
/// Statement `i` must read `i` — the state statement `i-1` left — never `i+1`. A single off-by-one
/// in the comparison shows up here as the whole ladder shifting.
#[must_use]
pub fn run_statement_ladder(statements: usize) -> Vec<i64> {
    let mut store = fresh_store();
    let ids = seed(&mut store, TxnId(1));
    let probe = ids[0];

    let t = TxnId(2);
    store.begin(t);
    let mut seen_on_entry = Vec::with_capacity(statements);
    for _ in 0..statements {
        store.begin_command(t);
        seen_on_entry.push(value_at(&store, probe, snap(&store, t, View::Old)).expect("value"));
        for &id in &ids {
            let now = value_at(&store, id, snap(&store, t, View::New)).expect("value");
            store
                .set_node_property_value(t, id, KEY, &Value::Integer(now + 1))
                .expect("increment");
        }
    }
    store.commit(t).expect("commit");
    seen_on_entry
}

// =================================================================================================
// Scenario 4 — crash with a statement in flight
// =================================================================================================

/// Crashes with statement 1 of a transaction mid-flight, recovers, and returns
/// `(labelled_nodes_after_recovery, live_deltas_after_recovery, live_deltas_before_the_loser)`.
///
/// Two things must hold. The committed baseline is [`SEED_NODES`] labelled nodes, so the loser's
/// creations must be gone. And the undo area must be back to **exactly** the committed baseline's own
/// delta count — not zero, because the committed seed's deltas are live version state until GC, and
/// asserting zero would be asserting the wrong thing. The `command_id` is transaction-local state: a
/// transaction that did not commit must leave nothing behind for a recovered reader to resolve a
/// statement against.
#[must_use]
pub fn run_crash_mid_statement(steal: bool) -> (usize, usize, usize) {
    let mut store = fresh_store();
    let _ = seed(&mut store, TxnId(1));
    let baseline_deltas = store
        .live_undo_delta_count()
        .expect("census the committed baseline");

    let t = TxnId(2);
    store.begin(t);
    store.begin_command(t);
    for _ in 0..SEED_NODES {
        let (n, _) = store.create_node(t).expect("create node");
        store.add_label(t, n, LABEL_BIT).expect("label it");
    }
    assert!(
        store.live_undo_delta_count().expect("census") > baseline_deltas,
        "precondition: the loser must actually have written version state to lose"
    );
    store.with_wal(WalManager::flush);

    let store = if steal {
        crash_steal(store)
    } else {
        crash_no_force(store)
    };
    let reader = Snapshot::new(TxnId(u64::MAX), store.snapshot_ts());
    let rows = scan_labelled(&store, reader).len();
    let deltas = store
        .live_undo_delta_count()
        .expect("census the undo area after recovery");
    (rows, deltas, baseline_deltas)
}

/// No-force crash: rebuild onto a fresh empty device from the durable WAL prefix, then reopen.
fn crash_no_force(store: Store) -> Store {
    let log = store.with_wal(|w| w.sink().durable_bytes().to_vec());
    let mut sink = MemLogSink::new();
    sink.append(&log);
    sink.sync().expect("sync log prefix");
    let mut device = MemBlockDevice::new(0);
    let mut wal = WalManager::open(sink.clone()).expect("open wal");
    graphus_storage::recovery::recover_device(&mut wal, &mut device).expect("recover");
    let wal = WalManager::open(sink).expect("reopen wal");
    RecordStore::open(device, wal, POOL_CAPACITY).expect("open store")
}

/// Steal crash: flush dirty pages home, snapshot that on-disk image, then recover.
fn crash_steal(mut store: Store) -> Store {
    store.flush().expect("flush (steal)");
    let pages = store.mapped_pages();
    let max = pages.iter().map(|p| p.0).max().unwrap_or(0);
    let mut device = MemBlockDevice::new(max + 1);
    for p in &pages {
        let bytes = store.read_device_page(*p).expect("read device page");
        device.write_page(PageId(p.0), &bytes).expect("stage page");
    }
    device.sync_all().expect("persist disk image");

    let log = store.with_wal(|w| w.sink().durable_bytes().to_vec());
    let mut sink = MemLogSink::new();
    sink.append(&log);
    sink.sync().expect("sync log prefix");
    let mut wal = WalManager::open(sink.clone()).expect("open wal");
    graphus_storage::recovery::recover_device(&mut wal, &mut device).expect("recover");
    let wal = WalManager::open(sink).expect("reopen wal");
    RecordStore::open(device, wal, POOL_CAPACITY).expect("open store")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// **The Halloween problem, and its absence.**
    #[test]
    fn a_statement_is_isolated_from_its_own_creations() {
        let report = run_halloween_scan();
        assert_eq!(report.seeded, SEED_NODES);
        assert_eq!(
            report.old_view_rows, SEED_NODES,
            "the scan sees exactly the state the statement began in"
        );
        assert_eq!(
            report.created, SEED_NODES,
            "one creation per scanned row, and the loop terminates"
        );
        assert_eq!(
            report.old_view_rows_after, SEED_NODES,
            "re-scanning after the writes still yields the original set"
        );
        assert_eq!(
            report.new_view_rows_after,
            2 * SEED_NODES,
            "positive control: the creations DID happen, so OLD is doing real work rather than the \
             writes silently not landing"
        );
        assert_eq!(
            report.next_statement_rows,
            2 * SEED_NODES,
            "the next statement starts from everything the previous one left"
        );
        assert!(report.statement_isolated());
    }

    /// The update form: a row the statement moved to a new key does not re-qualify under it.
    #[test]
    fn a_statement_does_not_re_qualify_the_rows_it_has_already_moved() {
        let report = run_halloween_increment();
        assert_eq!(
            report.values_after,
            vec![2; SEED_NODES],
            "each row is incremented exactly once"
        );
        assert_eq!(
            report.re_qualified_under_new_key, 0,
            "the candidate re-check must reject every index entry the statement itself moved — a \
             non-zero count here is the runaway update"
        );
        assert_eq!(
            report.moved_under_new_view, SEED_NODES,
            "positive control: the rows DID move, so the rejection above is the OLD view doing \
             work rather than the writes silently not landing"
        );
    }

    /// Statement `i` reads what statement `i-1` left — the whole ladder, not just its ends.
    #[test]
    fn each_statement_reads_exactly_what_the_previous_one_left() {
        assert_eq!(run_statement_ladder(5), vec![1, 2, 3, 4, 5]);
    }

    /// A crash with a statement in flight leaves exactly the committed baseline — the rows and the
    /// version state — under both the no-force and the steal crash models.
    #[test]
    fn a_crash_mid_statement_leaves_the_committed_baseline() {
        for steal in [false, true] {
            let (rows, deltas, baseline) = run_crash_mid_statement(steal);
            assert_eq!(
                rows, SEED_NODES,
                "steal={steal}: the loser statement's creations must not survive"
            );
            assert_eq!(
                deltas, baseline,
                "steal={steal}: no delta of the transaction that never committed may outlive it, \
                 and no delta of the one that did may be lost"
            );
        }
    }

    /// Determinism is the property the whole DST rests on: same input, same observation, always.
    #[test]
    fn reproduction_is_deterministic() {
        assert_eq!(run_halloween_scan(), run_halloween_scan());
        assert_eq!(run_halloween_increment(), run_halloween_increment());
        assert_eq!(run_statement_ladder(4), run_statement_ladder(4));
        assert_eq!(
            run_crash_mid_statement(false),
            run_crash_mid_statement(false)
        );
    }
}
