//! **`rmp` #1052 — the catalog's live-record counters under scheduled concurrent committers.**
//!
//! # What is being pinned
//!
//! [`Statistics`]'s six live-record counters move **eagerly at write time**, so the live value is
//! `committed image + every in-flight transaction's delta`. That makes the counters and the
//! per-transaction [`CountDelta`]s a single piece of state held in two places — the catalog, behind
//! the rank-10 catalog latch, and the sharded active-transaction table — and every operation that
//! relates them is a difference of the two. `rmp` #1052 was those two being sampled at two different
//! instants, which makes the difference a state of nothing.
//!
//! Since `rmp` #866 a `count()` is answered from these numbers, and nothing recomputes them from a
//! scan at `open`, so a drift is a wrong query answer that survives every restart.
//!
//! # What this suite asserts, and why by seed
//!
//! The invariant is exact and needs no tolerance: after `W` writers have each committed `R`
//! transactions that create one labelled node, `total_nodes` is the seeded count plus `W * R`, and
//! each label's counter is its own writer's share. A single unit either way is a defect.
//!
//! Real threads reach that state too — `graphus-storage`'s `catalog_counts_multi_writer_1052` does it
//! by repetition, and it is the test that fails on a wrong VALUE in a release build. What it cannot
//! do is come back. Under [`run_scheduled`] the interleaving is a function of the seed, so a failure
//! here names a schedule that can be replayed, which is what
//! [`the_same_seed_replays_the_run_identically`] exists to guarantee.
//!
//! # Running it
//!
//! ```text
//! cargo test --profile gate -p graphus-dst --features det-sched --test det_scheduler_catalog_counts_1052
//! ```

use std::sync::Arc;

use graphus_core::TxnId;
use graphus_dst::detsched::{DetSchedConfig, run_scheduled};
use graphus_io::MemBlockDevice;
use graphus_storage::{Namespace, RecordStore};
use graphus_wal::{MemLogSink, WalManager};

/// Seeds swept. The scheduler switches at every yield point, so it enters the commit/write overlap by
/// construction rather than by repetition; the sweep only has to vary *where*.
const SEEDS: u64 = 24;

/// Scheduled writer threads. Three, not two: with two writers the loser of every race is the same
/// thread, and the window this targets is a third transaction's delta being folded out of a second's
/// checkpoint image while a first is still moving it.
const WRITERS: usize = 3;

/// Transactions each writer commits. Small on purpose — see [`SEEDS`].
const ROUNDS: u64 = 3;

/// The counters as one scheduled run left them, beside what they must be.
#[derive(Debug, PartialEq, Eq)]
struct Run {
    /// `[total_nodes, L0, L1, …]` as the live catalog held them once every writer had finished.
    got: Vec<u64>,
    /// The same vector, computed from what the writers acknowledged.
    want: Vec<u64>,
}

/// Runs [`WRITERS`] scheduled committers against one store under the schedule `seed` names.
fn scenario(seed: u64) -> Run {
    let cfg = DetSchedConfig::exhaustive(seed);
    let (run, _history) = run_scheduled(cfg, || {
        let device = MemBlockDevice::new(0);
        let wal = WalManager::create(MemLogSink::new()).expect("create wal");
        let store = Arc::new(RecordStore::create(device, wal, 64, 1).expect("create store"));

        // Interning takes the catalogue's write latch, which the scheduler does not mediate. Done on
        // the root thread, so the run's contention is only where the scenario means it to be.
        let labels: Vec<u32> = (0..WRITERS)
            .map(|w| {
                store
                    .intern_token(Namespace::Label, &format!("L{w}"))
                    .expect("intern a label token")
            })
            .collect();

        // One committed node per label, so every counter starts non-zero and a counter wrongly driven
        // to zero has somewhere to fall from.
        let setup = TxnId(1);
        store.begin(setup);
        for &label in &labels {
            let (node, _) = store.create_node(setup).expect("create the seed node");
            store.add_label(setup, node, label).expect("label the seed");
        }
        store.commit(setup).expect("commit the seed");

        // THE RELOADER, and it is what gives this scenario its teeth.
        //
        // A transaction that begins and rolls back having linked no delta owns no commit slot, so it
        // takes the PHYSICAL rollback path — the only path that calls `reload_catalog`. That method
        // used to revert the whole `Statistics`, counters included, to the durable image, and the
        // caller reinstalled a `counts_image()` captured before the entire physical undo. Everything
        // between those two points is a window in which a CONCURRENT writer's increment is captured by
        // nobody and reverted by the reload, and unlike the other two mechanisms of `rmp` #1052 that
        // window is hundreds of steps wide and dense with yield sites — so the scheduler enters it by
        // construction, and this scenario reproduces the loss BY SEED rather than by repetition.
        //
        // It contributes nothing to any counter: it never writes and never commits.
        let reloader = {
            let store = Arc::clone(&store);
            graphus_core::sched::spawn("reloader", move || {
                for r in 0..ROUNDS {
                    let txn = TxnId(900_000 + r + 1);
                    store.begin(txn);
                    store.rollback(txn).expect("roll back an empty transaction");
                }
                0
            })
        };
        let threads: Vec<_> = (0..WRITERS)
            .map(|w| {
                let store = Arc::clone(&store);
                let label = labels[w];
                graphus_core::sched::spawn("writer", move || {
                    let mut committed = 0u64;
                    for r in 0..ROUNDS {
                        // Every writer's node is its own, so no round can be refused by the
                        // write-write conflict check and the expected counts are exact.
                        let txn = TxnId((w as u64 + 1) * 1_000 + r + 1);
                        store.begin(txn);
                        let (node, _) = store.create_node(txn).expect("create a node");
                        store.add_label(txn, node, label).expect("label the node");
                        store.commit(txn).expect("a disjoint write always commits");
                        committed += 1;
                    }
                    committed
                })
            })
            .collect();
        let per_writer: Vec<u64> = threads
            .into_iter()
            .map(|t| t.join().expect("a writer thread joins"))
            .collect();
        reloader.join().expect("the reloader thread joins");

        let live = store.statistics();
        let mut got = vec![live.total_nodes()];
        got.extend(labels.iter().map(|&l| live.node_count_for_label(l)));
        // One node per label was seeded; every committed round added exactly one more.
        let mut want = vec![per_writer.iter().sum::<u64>() + WRITERS as u64];
        want.extend(per_writer.iter().map(|c| c + 1));
        Run { got, want }
    });
    run
}

/// **Concurrent commits leave every counter exactly right, on every schedule.**
///
/// The vector is compared whole, so the message names which counter moved: slot 0 is `total_nodes`
/// and slot `w + 1` is writer `w`'s label. Both directions are defects and both are reported — a
/// counter BELOW its expectation means a delta was withdrawn from an image that did not contain it,
/// and one ABOVE means a delta was applied and never withdrawn.
#[test]
fn concurrent_commits_leave_the_catalog_counters_exact() {
    for seed in 0..SEEDS {
        let run = scenario(seed);
        assert_eq!(
            run.got, run.want,
            "seed {seed}: the live-record counters drifted under {WRITERS} scheduled committers. \
             Slot 0 is total_nodes and slot w+1 is writer w's label. The counters and the pending \
             deltas are one state read from two places; sampling them at two instants makes their \
             difference a state of nothing (`rmp` #1052), and `rmp` #866 answers count() from the \
             result"
        );
    }
}

/// **The same seed replays the same outcome**, so a failure above is reproducible rather than
/// anecdotal — the property every scheduled suite in this crate rests on.
#[test]
fn the_same_seed_replays_the_run_identically() {
    for seed in 0..8 {
        assert_eq!(
            scenario(seed),
            scenario(seed),
            "seed {seed} produced two different outcomes; the run is not deterministic"
        );
    }
}
