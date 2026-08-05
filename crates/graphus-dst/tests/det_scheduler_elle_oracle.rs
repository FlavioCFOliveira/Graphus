//! **The isolation oracle keeps ruling on histories produced under the deterministic scheduler**
//! (`rmp` #973, acceptance criterion 5).
//!
//! Introducing a scheduler that reorders real threads is exactly the kind of change that can quietly
//! decouple the correctness oracles from the runs they are supposed to judge. This suite pins both
//! halves of that:
//!
//! 1. [`a_scheduled_two_thread_history_is_serializable`] — a **genuinely two-threaded** run, whose
//!    interleaving the scheduler chose from a seed, is recorded as a [`graphus_elle::History`] and
//!    ruled on by the real [`graphus_elle::check`]. This is the new capability: before this task no
//!    DST history could contain two threads at all.
//! 2. [`the_vopr_safety_oracle_still_runs_under_an_installed_scheduler`] — the **existing** VOPR
//!    safety oracle (which records a recovered Elle history through the real engine and checks the
//!    four-property safety bundle) still runs, still rules clean, and still replays identically with
//!    a scheduler installed over it.
//!
//! # The object model
//!
//! The same list-append model [`graphus_dst::isolation`] uses, expressed at the storage layer: the
//! object is one node, an **append** of `v` is a committed transaction adding a property whose inline
//! value is `v`, and a **read** is a snapshot read
//! (`StoreReadView::decision_scan_node_properties` — the production off-thread reader path) that
//! observes the appended values in ascending order. Values increase monotonically, so ascending value
//! order *is* append order, which is what makes the history self-recoverable for Elle.
//!
//! A read that observes a **non-prefix** of the append sequence — value 5 present while 3 is missing —
//! is precisely what a severed or torn chain walk produces, and precisely what the checker rejects.
//!
//! # Running it
//!
//! ```text
//! cargo test -p graphus-dst --features det-sched --test det_scheduler_elle_oracle
//! ```

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use graphus_core::TxnId;
use graphus_core::sched::YieldSite;
use graphus_dst::detsched::{DetSchedConfig, run_scheduled};
use graphus_dst::vopr::{VoprConfig, run_safety};
use graphus_elle::{Op, Transaction, check};
use graphus_io::MemBlockDevice;
use graphus_storage::{Namespace, RecordStore};
use graphus_txn::Snapshot;
use graphus_wal::{MemLogSink, WalManager};

/// Appends the writer performs. Each is its own committed transaction.
const APPENDS: u64 = 24;

/// The Elle key the whole run operates on (one object, two threads).
const KEY: &str = "x";

/// Drives one appending writer and one snapshot reader under a scheduler seeded with `seed`,
/// recording every transaction into an Elle history. Returns the history and the number of context
/// switches the scheduler actually performed (the run's non-vacuity number).
fn scheduled_history(seed: u64) -> (Vec<Transaction>, u64) {
    let cfg = DetSchedConfig::exhaustive(seed);
    let (history, sched_history) = run_scheduled(cfg, || {
        let device = MemBlockDevice::new(0);
        let wal = WalManager::create(MemLogSink::new()).expect("create wal");
        let mut store = RecordStore::create(device, wal, 64, 1).expect("create store");

        // One property key per append, so each append is a distinct list element rather than an
        // overwrite of the previous one.
        let keys: Vec<u32> = (0..APPENDS)
            .map(|i| {
                store
                    .intern_token(Namespace::PropKey, &format!("v{i}"))
                    .expect("intern property key")
            })
            .collect();

        let t0 = TxnId(1);
        store.begin(t0);
        let (node, _) = store.create_node(t0).expect("create node");
        store.commit(t0).expect("commit node");

        let view = store.read_view();
        let stop = Arc::new(AtomicBool::new(false));
        // The head commit timestamp the writer has published. The reader takes its snapshot at
        // whatever it observes here, which models "a reader that begins now".
        let head = Arc::new(AtomicU64::new(store.snapshot_ts().0));
        let reads: Arc<std::sync::Mutex<Vec<Vec<i64>>>> =
            Arc::new(std::sync::Mutex::new(Vec::new()));

        let reader = {
            let stop = Arc::clone(&stop);
            let head = Arc::clone(&head);
            let reads = Arc::clone(&reads);
            graphus_core::sched::spawn("reader", move || {
                while !stop.load(Ordering::Relaxed) {
                    let snapshot = Snapshot::new(
                        TxnId(u64::MAX),
                        graphus_core::Timestamp(head.load(Ordering::Acquire)),
                    );
                    let decided = view
                        .decision_scan_node_properties(node, snapshot)
                        .expect("a snapshot read of a live owner must not fail");
                    let mut observed: Vec<i64> = decided
                        .visible_versions()
                        .iter()
                        .map(|c| c.value_inline as i64)
                        .collect();
                    observed.sort_unstable();
                    reads.lock().expect("reads lock").push(observed);
                }
            })
        };

        let mut writes: Vec<Transaction> = Vec::new();
        for (txn, (i, key)) in (10u64..).zip(keys.iter().enumerate()) {
            let val = i as i64 + 1;
            store.begin(TxnId(txn));
            store
                .add_node_property(TxnId(txn), node, *key, 1, val as u64)
                .expect("append");
            store.commit(TxnId(txn)).expect("commit append");
            // Publish the new head only AFTER the commit, so a reader can never take a snapshot at a
            // timestamp whose write is not yet committed.
            head.store(store.snapshot_ts().0, Ordering::Release);
            writes.push(Transaction::committed(
                txn,
                vec![Op::Append {
                    key: KEY.to_owned(),
                    val,
                }],
            ));
        }

        stop.store(true, Ordering::Relaxed);
        reader.join().expect("reader joined");

        // The reader's transactions come after the writers' in the recorded order; Elle recovers the
        // real order from the observed lists, so the observation order carries no meaning.
        let mut history = writes;
        // Read transaction ids live in a disjoint, far-away range so a read can never collide with a
        // writer's id in the checker's dependency graph.
        for (read_txn, observed) in
            (1_000_000u64..).zip(reads.lock().expect("reads lock").drain(..))
        {
            history.push(Transaction::committed(
                read_txn,
                vec![Op::Read {
                    key: KEY.to_owned(),
                    observed,
                }],
            ));
        }
        history
    });
    (history, sched_history.switches)
}

/// **Acceptance criterion 5, the new half** — a two-thread history the scheduler produced is still
/// ruled on by the real Elle checker, and it is serializable.
#[test]
fn a_scheduled_two_thread_history_is_serializable() {
    for seed in [5u64, 0x811, 0x973, 20_260_805] {
        let (history, switches) = scheduled_history(seed);

        // Non-vacuity, in three parts: the run really interleaved, the reader really read, and the
        // checker really had appends AND reads to relate. A clean verdict over a history with no
        // reads proves nothing at all.
        assert!(
            switches >= 100,
            "seed {seed:#x}: only {switches} context switches — the run barely interleaved"
        );
        let appends = history
            .iter()
            .filter(|t| matches!(t.ops.first(), Some(Op::Append { .. })))
            .count();
        let reads = history
            .iter()
            .filter(|t| matches!(t.ops.first(), Some(Op::Read { .. })))
            .count();
        assert_eq!(appends, APPENDS as usize, "seed {seed:#x}: appends missing");
        assert!(reads > 0, "seed {seed:#x}: the reader observed nothing");

        // At least one read must have caught the list mid-growth. A history whose every read saw
        // either nothing or the finished list would be serializable without ever having exercised
        // the concurrency.
        let partial = history.iter().any(|t| match t.ops.first() {
            Some(Op::Read { observed, .. }) => {
                !observed.is_empty() && observed.len() < APPENDS as usize
            }
            _ => false,
        });
        assert!(
            partial,
            "seed {seed:#x}: every read saw an empty or a complete list, so no read overlapped a \
             write and the verdict is vacuous"
        );

        let verdict = check(&history);
        assert!(
            verdict.serializable,
            "seed {seed:#x}: the isolation oracle rejected a scheduled history: {:?}",
            verdict.anomaly
        );
    }
}

/// **Acceptance criterion 5, the regression half** — the existing VOPR safety oracle still runs, and
/// still replays identically, with a deterministic scheduler installed over it.
///
/// The VOPR drives the engine inline on one thread, so the scheduler has nothing to interleave here;
/// that is stated plainly rather than dressed up. What this test proves is the property that matters
/// for this task: installing a scheduler does not disturb the existing oracle, its history, or its
/// determinism — a regression that would otherwise be found only when `rmp` #975 first tried to use
/// them together.
#[test]
fn the_vopr_safety_oracle_still_runs_under_an_installed_scheduler() {
    let vopr_cfg = VoprConfig::safety(0x239_0973);
    let (first, history) =
        run_scheduled(DetSchedConfig::exhaustive(0x973), || run_safety(vopr_cfg));
    let (second, _) = run_scheduled(DetSchedConfig::exhaustive(0x973), || run_safety(vopr_cfg));

    assert!(
        first.safe,
        "the safety oracle reported violations under a scheduler: {:?}",
        first.violations
    );
    assert!(
        first.checked_txns > 0,
        "the Elle checker ruled on zero transactions — the oracle ran vacuously"
    );
    assert_eq!(
        first.run, second.run,
        "the VOPR report stopped being deterministic with a scheduler installed"
    );

    // The scheduler was genuinely armed over the run: the engine's own yield points appear in the
    // history. Without this the test would pass just as happily if the seam had compiled to nothing.
    assert!(
        history.count_site(YieldSite::FrameReadFetched) > 0,
        "no record-read yield point was reached: the seam was not armed over the VOPR run"
    );
    assert!(
        history.count_site(YieldSite::CommitRegistryRecord) > 0,
        "no commit-publication yield point was reached"
    );
}
