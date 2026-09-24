//! **What an in-memory commit table could save on the header read path** (`rmp` #1071, acceptance
//! criterion 3).
//!
//! `rmp` #1071 decides whether the in-memory Active/Recent Transaction Table survives as a cache of
//! `commit.store` or goes altogether, and requires the decision to rest on two numbers measured on
//! one host: resolving a record header WITH such a table and WITHOUT it. A header is resolved in one
//! of two ways since `rmp` #1069:
//!
//! * a **settled** word (`Committed(ts)`) resolves from the word alone — no table, no slot;
//! * an **unsettled** word names a `commit.store` slot, which is read (a pool-resident page, 32
//!   bytes) and yields the outcome.
//!
//! A cache can therefore save at most the difference between resolving an unsettled word through its
//! slot and resolving it through an in-memory map; on a settled word it has nothing to save. This
//! file measures, per record, over the same 200 000 node headers:
//!
//! * **(i) slot** — headers unsettled (no GC pass since the commits), resolved by the store's own
//!   oracle, which reads the slot;
//! * **(ii) settled** — the same headers after one GC pass has settled them;
//! * **(iii) table** — the same records' header pages read, and their pre-`rmp` #1069 `TxnId` words
//!   resolved through an in-memory `CommitRegistry` (`graphus_txn::RegistryOracle`): the best a cache
//!   keyed by writer could do, with no invalidation cost counted.
//!
//! each inline (`RecordStore`) and through the off-thread `StoreReadView`, with the buffer pool larger
//! and smaller than the working set, and with the writes spread over 1 000 transactions (few slots,
//! all hot) and over 200 000 (one slot per node — the adversarial case for the slot read).
//!
//! Run with `cargo test --release -p graphus-storage --test commit_resolution_cost_1071 -- --ignored
//! --nocapture`. With `--features read-probe` it also proves the arms are what they claim to be: (i)
//! reads one slot per record, (ii) and (iii) read none.

use std::time::Instant;

use graphus_core::{TxnId, VersionStamp};
use graphus_io::MemBlockDevice;
use graphus_storage::{RecordStore, StoreKind};
use graphus_txn::{CommitRegistry, RegistryOracle, Snapshot, is_visible_via};
use graphus_wal::{MemLogSink, WalManager};

type Store = RecordStore<MemBlockDevice, MemLogSink>;

const NODES: u64 = 200_000;
const REPS: usize = 7;

/// Builds a store of `NODES` nodes written by `NODES / per_txn` transactions, and returns it with
/// the pre-`rmp` #1069 `TxnId` form of every node's `created_ts` and the table that resolves it.
fn build(pool: usize, per_txn: u64) -> (Store, Vec<u64>, Vec<u64>, CommitRegistry) {
    let wal = WalManager::create(MemLogSink::new()).expect("wal");
    let store = RecordStore::create(MemBlockDevice::new(0), wal, pool, 1).expect("store");
    let mut ids = Vec::with_capacity(NODES as usize);
    let mut t = 10u64;
    while (ids.len() as u64) < NODES {
        store.begin(TxnId(t));
        for _ in 0..per_txn {
            ids.push(store.create_node(TxnId(t)).expect("create").0);
        }
        store.commit(TxnId(t)).expect("commit");
        t += 1;
    }
    let mut legacy = Vec::with_capacity(ids.len());
    let mut registry = CommitRegistry::new();
    for &id in &ids {
        let word = store
            .read_mvcc_for_test(StoreKind::Node, id)
            .expect("header")
            .created_ts;
        let slot_id = graphus_core::HeaderStamp::from_raw(word)
            .slot_id()
            .expect("unsettled before any GC pass");
        let slot = store
            .commit_slot(slot_id)
            .expect("slot")
            .expect("written slot");
        let ts = match VersionStamp::from_raw(slot.commit_ts) {
            VersionStamp::Committed(ts) => ts,
            other => panic!("the writer committed, its slot says {other:?}"),
        };
        registry.record_commit(TxnId(slot.txn_id), ts);
        legacy.push(VersionStamp::in_flight(TxnId(slot.txn_id)));
    }
    (store, ids, legacy, registry)
}

fn per_record(ns: u128) -> f64 {
    ns as f64 / NODES as f64
}

/// Times `REPS` runs of `f` and returns `(min, median, max)` nanoseconds per record.
fn time(mut f: impl FnMut() -> usize) -> (f64, f64, f64) {
    let mut v: Vec<f64> = (0..REPS)
        .map(|_| {
            let t0 = Instant::now();
            let visible = f();
            let ns = t0.elapsed().as_nanos();
            assert_eq!(visible as u64, NODES, "every committed node is visible");
            per_record(ns)
        })
        .collect();
    v.sort_by(|a, b| a.partial_cmp(b).expect("finite"));
    (v[0], v[REPS / 2], v[REPS - 1])
}

fn inline_arm(store: &Store, ids: &[u64], reader: Snapshot) -> usize {
    ids.iter()
        .filter(|&&id| {
            let m = store
                .read_mvcc_for_test(StoreKind::Node, id)
                .expect("header");
            is_visible_via(store, reader, m.created_ts, m.expired_ts).expect("resolve")
        })
        .count()
}

fn view_arm(store: &Store, ids: &[u64], reader: Snapshot) -> usize {
    let view = store.read_view();
    ids.iter()
        .filter(|&&id| {
            let m = view.read_mvcc(StoreKind::Node, id).expect("header");
            is_visible_via(&view, reader, m.created_ts, m.expired_ts).expect("resolve")
        })
        .count()
}

fn table_arm(
    store: &Store,
    ids: &[u64],
    legacy: &[u64],
    registry: &CommitRegistry,
    reader: Snapshot,
) -> usize {
    let oracle = RegistryOracle(registry);
    ids.iter()
        .zip(legacy)
        .filter(|&(&id, &word)| {
            // The header page is read exactly as the other arms read it, so the arms differ only in
            // how the word is resolved.
            let m = store
                .read_mvcc_for_test(StoreKind::Node, id)
                .expect("header");
            std::hint::black_box(m);
            is_visible_via(&oracle, reader, word, 0).expect("resolve")
        })
        .count()
}

#[cfg(feature = "read-probe")]
fn slot_reads(f: impl FnOnce() -> usize) -> u64 {
    graphus_storage::read_probe::counting(f).1.commit
}

#[test]
#[ignore = "measurement; run explicitly in release with --ignored --nocapture"]
fn commit_resolution_cost_with_and_without_a_table_1071() {
    for (label, pool) in [
        ("pool >= working set (16384 frames)", 16_384usize),
        ("pool <  working set (256 frames)", 256),
    ] {
        for per_txn in [200u64, 1] {
            let (store, ids, legacy, registry) = build(pool, per_txn);
            let reader = Snapshot::new(TxnId(9_999_999), store.snapshot_ts());
            let slot_inline = time(|| inline_arm(&store, &ids, reader));
            let slot_view = time(|| view_arm(&store, &ids, reader));
            #[cfg(feature = "read-probe")]
            let unsettled_reads = slot_reads(|| inline_arm(&store, &ids, reader));

            // One pass settles every header.
            let g = TxnId(5_000_000);
            store.begin(g);
            store.gc(g, store.snapshot_ts()).expect("gc");
            store.commit(g).expect("commit gc");
            let reader = Snapshot::new(TxnId(9_999_999), store.snapshot_ts());
            let settled_inline = time(|| inline_arm(&store, &ids, reader));
            let settled_view = time(|| view_arm(&store, &ids, reader));
            let table = time(|| table_arm(&store, &ids, &legacy, &registry, reader));
            #[cfg(feature = "read-probe")]
            {
                let settled_reads = slot_reads(|| inline_arm(&store, &ids, reader));
                let table_reads =
                    slot_reads(|| table_arm(&store, &ids, &legacy, &registry, reader));
                eprintln!(
                    "  read-probe slot reads: (i) {unsettled_reads}  (ii) {settled_reads}  \
                     (iii) {table_reads}"
                );
                assert_eq!(unsettled_reads, NODES, "(i) must read one slot per record");
                assert_eq!(settled_reads, 0, "(ii) must read no slot");
                assert_eq!(table_reads, 0, "(iii) must read no slot");
            }
            let show = |(a, b, c): (f64, f64, f64)| format!("{a:6.1} / {b:6.1} / {c:6.1}");
            eprintln!(
                "rmp #1071 header resolution, ns/record (min / median / max of {REPS}), {label}, \
                 {} writers:\n  (i)   slot, inline   : {}\n  (i)   slot, view     : {}\n  \
                 (ii)  settled, inline: {}\n  (ii)  settled, view  : {}\n  (iii) table, inline  : {}",
                NODES / per_txn,
                show(slot_inline),
                show(slot_view),
                show(settled_inline),
                show(settled_view),
                show(table),
            );
        }
    }
}
