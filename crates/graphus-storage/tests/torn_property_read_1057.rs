//! **A concurrent reader never observes one leg of a transfer without the other** (`rmp` #1057).
//!
//! # The defect this pins, at the layer that owns it
//!
//! A property read reconstructs one entity's visible version from two things that live in
//! **different records, on different pages, under different latches**: the *current* value of each
//! key (its `props.store` cells) and the *older* values (its undo chain, reached through the
//! `undo_ptr` word of the entity's own record, `rmp` #967). Nothing made the two an atom, and the
//! write path publishes them in this order — `RecordStore::link_delta` writes the delta carrying the
//! old value and publishes it as the entity's new chain head, and only *then* is the cell rewritten
//! in place (`set_entity_property_encoded`).
//!
//! `read_view` sampled them the other way round: the chain head first, the cells afterwards. A reader
//! whose head sample fell **before** the publication and whose cell read fell **after** the rewrite
//! therefore held a new value with no delta above its head to undo it, and kept it — whoever wrote
//! it, committed or not.
//!
//! It was measured through the engine (`graphus-server`'s
//! `concurrent_reader_serializability::concurrent_readers_see_consistent_snapshot`, which failed 10
//! processes in 80 under an 8-process load), but it is **not** an engine defect: this suite
//! reproduces it against a bare [`RecordStore`], which is where it lives and where it is fixed.
//!
//! # Why the workload is a conserved system, and what the snapshot rule excludes
//!
//! Each transfer is ONE transaction moving [`AMOUNT`] between two accounts, so
//! `sum(balance)` is `TOTAL` at every committed point — no interleaving of committed transfers makes
//! it anything else, and a sum that differs by exactly `AMOUNT` is exactly "one leg observed without
//! the other".
//!
//! The readers snapshot at a timestamp the writer publishes only **after** `commit` returns, so no
//! transaction can be at a timestamp `<= snapshot.ts` while its commit slot is still unpublished.
//! That is deliberate: it excludes, *by construction*, the hypothesis that the tear comes from
//! `read_view::decide_properties` resolving each delta against a **live** read of `commit.store`
//! whose slot can flip mid-scan. A tear observed here is not that one.
//!
//! # Non-vacuity
//!
//! Two mechanical checks, because a conserved sum is trivially conserved by a reader that never runs
//! concurrently with a writer: the writer must complete every transfer, and the readers must observe
//! **more than one** distinct state of the system (so they really did read a moving store).
//!
//! By ablation, which is the claim that matters. With the fix withdrawn — the pre-#1057 shape, chain
//! head sampled before the cells with no validation — this test fails **5 runs out of 5**, between
//! 0.03 s and 0.13 s into a run that takes ~1.7 s when it passes, alternating between `off by 10`
//! and `off by -10` (the credited leg observed without the debited one, and the reverse):
//!
//! ```text
//! reader 6 at snapshot ts  24 observed sum 2010 != 2000 — off by  10 (1 transfer leg(s))
//! reader 1 at snapshot ts 338 observed sum 1990 != 2000 — off by -10 (1 transfer leg(s))
//! reader 5 at snapshot ts  70 observed sum 2010 != 2000 — off by  10 (1 transfer leg(s))
//! reader 2 at snapshot ts 850 observed sum 1990 != 2000 — off by -10 (1 transfer leg(s))
//! reader 1 at snapshot ts 331 observed sum 2010 != 2000 — off by  10 (1 transfer leg(s))
//! ```
//!
//! With the fix in place it completes clean, repeatedly. The deterministic twin of this suite is
//! `graphus-dst`'s `det_scheduler_torn_property_read_1057`, which reproduces the same tear from a
//! seed.

use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use graphus_core::{Timestamp, TxnId, Value};
use graphus_io::MemBlockDevice;
use graphus_storage::{Namespace, RecordStore, StoreKind};
use graphus_txn::Snapshot;
use graphus_wal::{MemLogSink, WalManager};

/// Accounts in the conserved system.
const ACCOUNTS: usize = 2;
/// What each account starts with.
const START: i64 = 1_000;
/// The invariant every snapshot read must observe.
const TOTAL: i64 = ACCOUNTS as i64 * START;
/// What one transfer moves, and therefore the size of one torn leg.
const AMOUNT: i64 = 10;
/// Transfers the writer performs. The ablated build tears within the first ~1 % of them (measured:
/// 5 runs of 5, between 0.03 s and 0.12 s of a ~1.8 s run), so this is a >10x margin.
const TRANSFERS: usize = 10_000;
/// Concurrent snapshot readers. Oversubscribing the writer's core count is what makes the window —
/// a reader descheduled between its chain-head sample and its cell read — reliably reachable.
const READERS: usize = 8;

#[test]
fn concurrent_readers_never_see_half_a_transfer() {
    let device = MemBlockDevice::new(0);
    let wal = WalManager::create(MemLogSink::new()).expect("create wal");
    let store = Arc::new(RecordStore::create(device, wal, 4096, 1).expect("create store"));
    let key = store
        .intern_token(Namespace::PropKey, "balance")
        .expect("intern property key");

    let seed_txn = TxnId(1);
    store.begin(seed_txn);
    let mut nodes = Vec::with_capacity(ACCOUNTS);
    for _ in 0..ACCOUNTS {
        let (node, _) = store.create_node(seed_txn).expect("create account");
        store
            .set_node_property_value(seed_txn, node, key, &Value::Integer(START))
            .expect("seed balance");
        nodes.push(node);
    }
    store.commit(seed_txn).expect("commit the seed");

    // The commit timestamp the writer has PUBLISHED — stored only after `commit` returns. See the
    // module note: this is what excludes the commit-slot hypothesis from this reproduction.
    let head = Arc::new(AtomicU64::new(store.snapshot_ts().0));
    let stop = Arc::new(AtomicBool::new(false));
    let report: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));
    // Non-vacuity: how many DISTINCT states of the system the readers observed.
    let states: Arc<Mutex<std::collections::BTreeSet<Vec<i64>>>> =
        Arc::new(Mutex::new(std::collections::BTreeSet::new()));
    let reads = Arc::new(AtomicUsize::new(0));

    let mut readers = Vec::with_capacity(READERS);
    for r in 0..READERS {
        let store = Arc::clone(&store);
        let head = Arc::clone(&head);
        let stop = Arc::clone(&stop);
        let report = Arc::clone(&report);
        let states = Arc::clone(&states);
        let reads = Arc::clone(&reads);
        let nodes = nodes.clone();
        readers.push(std::thread::spawn(move || {
            let view = store.read_view();
            while !stop.load(Ordering::Acquire) {
                let ts = head.load(Ordering::Acquire);
                let snapshot = Snapshot::new(TxnId(u64::MAX), Timestamp(ts));
                let mut observed = Vec::with_capacity(ACCOUNTS);
                // The undo-chain head before and after each account's read, kept only to make a
                // failure diagnosable: a head that moved across the read is the window itself.
                let mut heads = Vec::with_capacity(ACCOUNTS);
                for &node in &nodes {
                    let before = view
                        .read_mvcc(StoreKind::Node, node)
                        .expect("mvcc header")
                        .undo_ptr;
                    let decided = view
                        .decision_scan_node_properties(node, snapshot)
                        .expect("a snapshot read of a live account must not fail");
                    let after = view
                        .read_mvcc(StoreKind::Node, node)
                        .expect("mvcc header")
                        .undo_ptr;
                    observed.push(
                        decided
                            .visible_versions()
                            .iter()
                            .find(|c| c.key == key)
                            .map_or(0, |c| c.value_inline as i64),
                    );
                    heads.push((before, after));
                }
                reads.fetch_add(1, Ordering::Relaxed);
                let sum: i64 = observed.iter().sum();
                states.lock().expect("states lock").insert(observed.clone());
                if sum != TOTAL {
                    let mut lines = vec![format!(
                        "reader {r} at snapshot ts {ts} observed sum {sum} != {TOTAL} — off by {} \
                         ({} transfer leg(s))",
                        sum - TOTAL,
                        (sum - TOTAL).abs() / AMOUNT
                    )];
                    for (i, &node) in nodes.iter().enumerate() {
                        // Re-read the SAME account at the SAME snapshot. A different answer proves
                        // the first one was not a function of the snapshot, which is what a torn
                        // read is.
                        let again = view
                            .decision_scan_node_properties(node, snapshot)
                            .expect("re-read")
                            .visible_versions()
                            .iter()
                            .find(|c| c.key == key)
                            .map_or(0, |c| c.value_inline as i64);
                        let (before, after) = heads[i];
                        lines.push(format!(
                            "  account {node}: decided {}, re-read at the same snapshot {again}, \
                             undo_ptr {before} -> {after}{}",
                            observed[i],
                            if before == after {
                                ""
                            } else {
                                "   <== the chain head moved DURING this account's read"
                            }
                        ));
                    }
                    report.lock().expect("report lock").extend(lines);
                    stop.store(true, Ordering::Release);
                    return;
                }
            }
        }));
    }

    let writer = {
        let store = Arc::clone(&store);
        let head = Arc::clone(&head);
        let stop = Arc::clone(&stop);
        let nodes = nodes.clone();
        std::thread::spawn(move || {
            let mut balance = [START; ACCOUNTS];
            let mut done = 0usize;
            while done < TRANSFERS && !stop.load(Ordering::Acquire) {
                let from = done % ACCOUNTS;
                let to = (done + 1) % ACCOUNTS;
                let txn = TxnId(100 + done as u64);
                store.begin(txn);
                balance[from] -= AMOUNT;
                balance[to] += AMOUNT;
                // Two legs, one transaction: they commit together or not at all.
                store
                    .set_node_property_value(txn, nodes[from], key, &Value::Integer(balance[from]))
                    .expect("debit leg");
                store
                    .set_node_property_value(txn, nodes[to], key, &Value::Integer(balance[to]))
                    .expect("credit leg");
                store.commit(txn).expect("commit the transfer");
                head.store(store.snapshot_ts().0, Ordering::Release);
                done += 1;
            }
            stop.store(true, Ordering::Release);
            done
        })
    };

    let transfers = writer.join().expect("writer joined");
    for reader in readers {
        reader.join().expect("reader joined");
    }

    let report = report.lock().expect("report lock").clone();
    assert!(
        report.is_empty(),
        "a concurrent snapshot read observed one leg of a transfer without the other — the property \
         cells and the undo-chain head they were reconstructed against came from two different \
         instants (`rmp` #1057):\n{}",
        report.join("\n")
    );

    // ---- non-vacuity ----
    assert_eq!(
        transfers, TRANSFERS,
        "the writer stopped early, so the readers did not race a full transfer stream"
    );
    let reads = reads.load(Ordering::Relaxed);
    assert!(
        reads > TRANSFERS,
        "only {reads} snapshot reads ran against {TRANSFERS} transfers — too few to have raced them"
    );
    let distinct = states.lock().expect("states lock").len();
    assert!(
        distinct > 1,
        "every snapshot read observed the SAME state of the system, so no read was concurrent with \
         a transfer and the conserved total was conserved trivially"
    );
}
