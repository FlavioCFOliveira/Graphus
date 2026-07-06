//! **`rmp` #590 (sprint-52 E-2) regression gate** — a large Mode A network bulk-import interrupted by a
//! crash / SIGKILL / power-loss / `STOP DATABASE` **before** `?end=true` must NOT leave the whole
//! retained WAL un-reclaimed for the next `START DATABASE` to materialise into its ARIES recovery heap
//! (the confirmed reopen-OOM). The fix runs a **freeze-only** maintenance pass on a tight adaptive
//! cadence *during* the load: the incremental freeze sweep (`rmp` #522) drains `unfrozen_commit_lsn` and
//! so lowers the WAL reclaim floor — bounding the retained WAL to ≈ the cadence at ANY mid-abort point —
//! WITHOUT paying the `O(store)` property sweep the Mode A checkpoint sentinel would otherwise gate ON
//! every batch (`sweep_property_chains`), which on a tight cadence would reintroduce the `O(N²)`
//! maintenance cost `rmp` #556/#565 had widened the loading cadence to avoid.
//!
//! This is the deterministic, single-threaded crash/recovery model (the same shape the other
//! `graphus-dst` crash tests use). It drives a `RecordStore` directly with the exact Mode A ingest
//! pattern (per-batch node creates + a per-batch **checkpoint-sentinel property update**, committed per
//! batch — see `graphus_server::engine::bulk_load`), interleaves freeze-only maintenance passes at a
//! fixed batch cadence, then crashes **before** any `End`/final reclaim and reopens.
//!
//! It asserts, empirically:
//!   1. **(b) bounded retained WAL** — with freeze-only passes, the retained window
//!      (`durable_len − reclaimed_floor`) at the crash point is bounded by the cadence and **independent
//!      of the total load size** (a 2× larger load leaves the same window), whereas the same load with NO
//!      maintenance retains ≈ the whole load's WAL. The retained window is exactly what a reopen reads
//!      (`rmp` #525 bounds the recovery read to `reclaimed_floor()`), so a bounded window is a bounded
//!      reopen allocation.
//!   2. **(a) no committed data loss** — after the mid-abort reopen, every node a committed (acked) batch
//!      created is still present, and the durable checkpoint sentinel still records the acked counts.

use graphus_io::{BlockDevice, MemBlockDevice};
use graphus_storage::recovery::recover_device;
use graphus_storage::{Namespace, RecordStore};
use graphus_wal::{LogSink, MemLogSink, WalManager};

use graphus_core::{PageId, TxnId, Value};

type Store = RecordStore<MemBlockDevice, MemLogSink>;

const POOL_CAPACITY: usize = 64;
const SENTINEL_LABEL: &str = "__mode_a_sentinel__";

/// A fresh store with the store's own auto-checkpoint cadence **disabled**, so the ONLY thing that can
/// advance the WAL reclaim floor is a freeze-only maintenance pass this test drives explicitly — exactly
/// isolating the `rmp` #590 mechanism under test.
fn fresh() -> Store {
    let device = MemBlockDevice::new(0);
    let wal = WalManager::create(MemLogSink::new()).expect("create wal");
    let mut store = RecordStore::create(device, wal, POOL_CAPACITY, 1).expect("create store");
    store.set_checkpoint_interval_bytes(0);
    store
}

/// The retained durable WAL window = `durable_len − reclaimed_floor`. This is precisely the number of
/// bytes a reopen reads into its recovery heap (`rmp` #525 clamps the recovery read to
/// `reclaimed_floor()`), so it is the direct proxy for reopen memory.
fn retained_window(store: &Store) -> u64 {
    store.with_wal(|w| w.sink().durable_len() - w.sink().reclaimed_floor())
}

/// The interned property-key tokens a Mode A load writes (the data-node property + the two sentinel
/// counters), bundled so [`ingest_batch`] stays within a sane argument count.
struct LoadKeys {
    prop: u32,
    sentinel_nodes: u32,
    sentinel_batch: u32,
}

/// One Mode A batch: create `nodes_per_batch` data nodes (each with one property) and update the durable
/// checkpoint sentinel node's cumulative counters, all under a single transaction committed at the end —
/// the exact abort/commit granularity of `bulk_load::LoadingSession::ingest_nodes` +
/// `bulk_load::checkpoint_sentinel`. Returns the physical id of this batch's first data node (a
/// representative committed record for the reopen check).
fn ingest_batch(
    store: &mut Store,
    txn: TxnId,
    nodes_per_batch: u64,
    running_total: &mut u64,
    sentinel: &mut Option<u64>,
    keys: &LoadKeys,
    batch_seq: u64,
) -> u64 {
    store.begin(txn);
    let mut first_node = 0u64;
    for i in 0..nodes_per_batch {
        let (id, _) = store.create_node(txn).expect("create node");
        if i == 0 {
            first_node = id;
        }
        store
            .set_node_property_value(txn, id, keys.prop, &Value::Integer(id as i64))
            .expect("set node prop");
        *running_total += 1;
    }
    // Create/update the checkpoint sentinel (updates tombstone the prior property version — the reason
    // the property sweep gates ON every batch, which is exactly why the mid-load pass must be freeze-only).
    let sid = match *sentinel {
        Some(id) => id,
        None => {
            let (id, _) = store.create_node(txn).expect("create sentinel");
            let label = store
                .intern_token(Namespace::Label, SENTINEL_LABEL)
                .expect("intern label");
            store
                .set_node_labels(txn, id, &[label])
                .expect("label sentinel");
            *sentinel = Some(id);
            id
        }
    };
    store
        .set_node_property_value(
            txn,
            sid,
            keys.sentinel_batch,
            &Value::Integer(batch_seq as i64),
        )
        .expect("sentinel batch_seq");
    store
        .set_node_property_value(
            txn,
            sid,
            keys.sentinel_nodes,
            &Value::Integer(*running_total as i64),
        )
        .expect("sentinel nodes");
    store.commit(txn).expect("commit batch");
    first_node
}

/// One **freeze-only** maintenance pass + sharp store checkpoint — the storage half of the engine's
/// mid-load maintenance (`TxnCoordinator::checkpoint_reader_safe_freeze_only`): the incremental freeze
/// sweep drains `unfrozen_commit_lsn`, then `checkpoint()` flushes dirty pages home and physically
/// reclaims the WAL prefix below the now-lowered floor.
fn freeze_only_maintenance(store: &mut Store, txn: TxnId) {
    let watermark = store.snapshot_ts();
    store.begin(txn);
    let report = store
        .gc_freeze_only(txn, watermark)
        .expect("freeze-only gc pass");
    store.commit(txn).expect("commit freeze-only gc");
    // A freeze-only pass must freeze (so the floor can advance) but must reclaim NOTHING (the O(store)
    // reclamation sweeps — including the property sweep — are skipped): this is what keeps it O(Δ).
    assert_eq!(
        report.reclaimed, 0,
        "a freeze-only pass must not run the reclamation sweeps (it reclaims nothing)"
    );
    assert!(
        report.frozen > 0,
        "a freeze-only pass must still freeze committed stamps, so the WAL floor can advance"
    );
    store
        .checkpoint()
        .expect("sharp checkpoint reclaims the WAL prefix");
}

/// Reopens `store` after a mid-abort crash, **preserving the reclaimed floor** — the production
/// `FileLogSink` reopen recovers the floor because the below-floor segments are physically deleted, so we
/// model that by cloning the sink (its `head`/`base`/`tail` carry the floor + retained window) rather than
/// the `durable_bytes()` flatten the other DST crash helpers use (that zero-fills the reclaimed gap and
/// resets the floor to 0 — which would make the reopen allocate the whole lifetime buffer, the exact OOM
/// this fix prevents). Steal model: the flushed pages are on the device; the retained WAL redoes onto them.
fn reopen_preserving_floor(store: &mut Store) -> Store {
    // Steal capture: flush current dirty pages home, snapshot the device image.
    store.flush().expect("flush (steal capture)");
    let pages = store.mapped_pages();
    let max = pages.iter().map(|p| p.0).max().unwrap_or(0);
    let mut device = MemBlockDevice::new(max + 1);
    for p in &pages {
        let bytes = store.read_device_page(*p).expect("read device page");
        device.write_page(PageId(p.0), &bytes).expect("stage page");
    }
    device.sync_all().expect("persist disk image");

    // Clone the sink so the reclaimed floor + retained window survive (models the FileLogSink reopen),
    // then drop any un-synced tail (power loss).
    let mut sink = store.with_wal(|w| w.sink().clone());
    sink.crash();

    let mut wal = WalManager::open(sink.clone()).expect("open wal");
    recover_device(&mut wal, &mut device).expect("recover");
    let wal = WalManager::open(sink).expect("reopen wal");
    RecordStore::open(device, wal, POOL_CAPACITY).expect("open store")
}

/// Drives a Mode A load of `total_batches` batches. When `freeze_every` is `Some(k)`, a freeze-only
/// maintenance pass runs after every `k` committed batches (the `rmp` #590 mid-load cadence); when
/// `None`, no maintenance runs at all (the pre-fix behaviour, the control). Crashes **before** any `End`
/// and reopens. Returns `(retained_window_at_crash, representative_node_ids, sentinel_id)`.
fn run_load(total_batches: u64, freeze_every: Option<u64>) -> (u64, Vec<u64>, u64, Store) {
    const NODES_PER_BATCH: u64 = 100;
    let mut store = fresh();
    let keys = LoadKeys {
        prop: store.intern_token(Namespace::PropKey, "v").unwrap(),
        sentinel_nodes: store.intern_token(Namespace::PropKey, "nodes").unwrap(),
        sentinel_batch: store.intern_token(Namespace::PropKey, "batch_seq").unwrap(),
    };

    let mut next_txn = 0u64;
    let mut running_total = 0u64;
    let mut sentinel: Option<u64> = None;
    let mut reps: Vec<u64> = Vec::new();

    for b in 1..=total_batches {
        next_txn += 1;
        let first = ingest_batch(
            &mut store,
            TxnId(next_txn),
            NODES_PER_BATCH,
            &mut running_total,
            &mut sentinel,
            &keys,
            b,
        );
        reps.push(first);
        if let Some(k) = freeze_every {
            if b % k == 0 {
                next_txn += 1;
                freeze_only_maintenance(&mut store, TxnId(next_txn));
            }
        }
    }

    let window = retained_window(&store);
    let sentinel_id = sentinel.expect("at least one batch created the sentinel");
    let recovered = reopen_preserving_floor(&mut store);
    (window, reps, sentinel_id, recovered)
}

/// (b) The retained WAL a mid-abort load leaves is bounded by the maintenance cadence and **independent of
/// the total load size** — the property that makes the reopen O(window), not O(total). A 2× larger load
/// under the same freeze-only cadence leaves the SAME retained window, while the pre-fix (no-maintenance)
/// control retains ≈ the whole load's WAL and grows with it.
#[test]
fn freeze_only_bounds_the_retained_wal_independent_of_load_size() {
    const FREEZE_EVERY: u64 = 15;

    // Two freeze-only loads of very different total size; both crash 5 batches after the last pass.
    let (win_small, _, _, _) = run_load(50, Some(FREEZE_EVERY));
    let (win_large, _, _, _) = run_load(200, Some(FREEZE_EVERY));

    // The retained window is bounded by the cadence, so the 4× larger load's window is ≈ the small one's
    // (both hold only the WAL written since their last freeze-only pass), NOT 4× larger.
    assert!(
        win_large <= win_small * 2,
        "freeze-only retained WAL must be bounded by the cadence, independent of total load size \
         (small={win_small}, large={win_large})"
    );

    // The pre-fix control (no maintenance) retains the WHOLE load's WAL — it grows with the total, and is
    // dramatically larger than the freeze-only window. This is the reopen-OOM the fix prevents.
    let (win_control_small, _, _, _) = run_load(50, None);
    let (win_control_large, _, _, _) = run_load(200, None);
    assert!(
        win_control_large > win_control_small * 3,
        "the no-maintenance control retains WAL proportional to the total load (small={win_control_small}, \
         large={win_control_large})"
    );
    assert!(
        win_large * 4 < win_control_large,
        "the freeze-only window ({win_large}) must be far below the no-maintenance window \
         ({win_control_large}) for the same-size load — the O(window)-vs-O(total) fix"
    );
}

/// (a) A mid-abort reopen loses no committed data: every representative node of every acked batch is
/// still present after recovery, and the durable checkpoint sentinel still records the acked node count.
#[test]
fn mid_abort_reopen_recovers_every_committed_batch() {
    const TOTAL_BATCHES: u64 = 80;
    const FREEZE_EVERY: u64 = 15;
    const NODES_PER_BATCH: u64 = 100;

    let (_window, reps, sentinel_id, recovered) = run_load(TOTAL_BATCHES, Some(FREEZE_EVERY));

    // Every acked batch's representative node survived the mid-abort reopen.
    assert_eq!(reps.len() as u64, TOTAL_BATCHES);
    for (b, &id) in reps.iter().enumerate() {
        assert!(
            recovered
                .node(id)
                .expect("read recovered node")
                .mvcc
                .in_use(),
            "batch {}'s committed node {id} was lost across the mid-abort reopen (committed data loss)",
            b + 1
        );
    }

    // The durable checkpoint sentinel survived and still records the acked cumulative node count — its
    // last committed `nodes` property must equal every data node created (TOTAL_BATCHES × NODES_PER_BATCH).
    let expected_nodes = (TOTAL_BATCHES * NODES_PER_BATCH) as i64;
    let s_nodes = recovered
        .token_id(Namespace::PropKey, "nodes")
        .expect("nodes prop key recovered");
    let mut sentinel_nodes: Option<i64> = None;
    for (_pid, prop) in recovered
        .node_properties(sentinel_id)
        .expect("walk sentinel property chain")
    {
        if prop.key == s_nodes && prop.mvcc.in_use() && prop.mvcc.expired_ts == 0 {
            let v = recovered
                .decode_property_value(prop.type_tag, prop.value_inline)
                .expect("decode sentinel nodes value");
            if let Value::Integer(n) = v {
                sentinel_nodes = Some(n);
            }
        }
    }
    assert_eq!(
        sentinel_nodes,
        Some(expected_nodes),
        "the recovered checkpoint sentinel must record the acked node count ({expected_nodes})"
    );
}
