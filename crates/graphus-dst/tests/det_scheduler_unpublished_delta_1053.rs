//! **`rmp` #1053 — the delta a refused publication leaves behind, reproduced from a seed.**
//!
//! # The window
//!
//! `RecordStore::link_delta` writes a delta in three steps whose order `04 §5.1.2` fixes and which
//! cannot be reordered: the delta is written **in full and live**, with its `commit_info` naming the
//! transaction's commit slot; then it is published as the entity's chain head; then it is registered
//! in the transaction's `undo_links`. The middle step is fallible — under two writers on one chain
//! the compare-and-set is refused, the head is re-read, and the re-read head may belong to a
//! **still-open** transaction, which is the write-write conflict `D-property-write-conflict`
//! mandates.
//!
//! Everything downstream reads one side or the other of that failure:
//!
//! * `publish_commit_slot` counts `undo_links`, so an unregistered delta is **not counted**;
//! * `detach_own_deltas` frees `undo_links`, so an unregistered delta is **not freed** by the abort;
//! * `free_own_commit_slot` hands the slot id back to the allocator on the strength of "every delta
//!   naming it is gone";
//! * the consistency checker's census counts every **live** delta naming a slot.
//!
//! So before `rmp` #1053 the refused delta outlived its transaction: live, on no chain, and still
//! naming a commit slot the allocator had already re-issued. Two faces of one leak follow, and which
//! one is seen depends only on whether that slot id was taken again before the store was checked:
//!
//! * `UndoSlot { FreedButReferenced }` — the leaked delta names a slot on the free list;
//! * `UndoSlot { DeltaCountMismatch { recorded: n, actual: n + 1 } }` — the slot has been re-issued
//!   to another transaction, which committed and published *its* count, and the census finds one
//!   delta too many on the slot of an entirely innocent committed transaction.
//!
//! The second is what `graphus-server`'s `multi_writer_certification_1034` gate 1 reported at
//! `engine_workers = 8`, durable and reproduced through WAL recovery. It needs two writers, because
//! the only thing that refuses a publication is another transaction on the same chain.
//!
//! # Why this file, when a real-thread gate already fails
//!
//! Because the gate fails by repetition and cannot come back. Under [`run_scheduled`] the
//! interleaving is a function of the seed, so the window here is entered deliberately rather than
//! hoped for, and [`the_same_seed_replays_the_run_identically`] pins that it replays.
//!
//! # Non-vacuity
//!
//! Two writers on one chain need not race: if the scheduler runs one to completion first, the second
//! is refused by `link_delta`'s **entry** guard, before it has allocated or written anything — a
//! clean refusal that leaks nothing and proves nothing about this window. The two are told apart on
//! the store itself rather than from the error text, which is identical: a refusal from the
//! *publication* leaves a second delta whose `next` names the head both writers read, and an entry-
//! guard refusal cannot produce one. The sweep asserts that at least one seed produced that second
//! delta before it asserts anything about what became of it.
//!
//! # Running it
//!
//! An installed scheduler is process-global, so the run must be filtered to this target (see the
//! note in `graphus_core::sched`):
//!
//! ```text
//! cargo test --profile gate -p graphus-dst --features det-sched --test det_scheduler_unpublished_delta_1053
//! ```

use std::sync::Arc;

use graphus_core::TxnId;
use graphus_dst::detsched::{DetSchedConfig, run_scheduled};
use graphus_io::MemBlockDevice;
use graphus_storage::{Namespace, RecordStore, StoreKind};
use graphus_wal::{MemLogSink, WalManager};

/// Seeds swept. The scheduler switches at every yield point, so it enters the read/publish overlap by
/// construction rather than by repetition; the sweep only has to vary *where*. Wider than the other
/// scheduled suites because the target window is genuinely narrow — see [`WRITERS`].
const SEEDS: u64 = 96;

/// Contending writers. Three, not two, and that is not a margin: the window is the span between one
/// writer's entry guard and its compare-and-set — an id allocation and one record write — and a
/// *second* writer's publication has to land inside it. With two threads the loser is far more often
/// turned away by the entry guard, which allocates nothing; a third writer multiplies the chances
/// that some publication falls in some other writer's narrow span. The sweep's own non-vacuity
/// assertion is what proves this claim rather than assuming it.
const WRITERS: usize = 3;

/// The `type_tag` the scenario's property carries. Non-zero, so every value is a real one rather than
/// an emptied cell.
const TYPE_TAG: u8 = 1;

/// The exclusive upper bound of the delta ids the scan below inspects. The scenario writes a couple
/// of dozen deltas at most, so this covers the whole allocated id space with room to spare; a slot
/// that was never written decodes as no delta at all and is skipped.
const DELTA_SCAN_LIMIT: u64 = 256;

/// What one scheduled run of the two contending writers produced.
#[derive(Debug, PartialEq, Eq)]
struct Run {
    /// The writers' outcomes, in thread order: `Ok(())`, or the error text.
    outcomes: Vec<Result<(), String>>,
    /// How many delta slots name, as their `next`, the chain head both writers read. Two means both
    /// writers got as far as **writing** a delta against that head, which is the window — one means
    /// the loser was turned away by the entry guard and never wrote anything.
    deltas_against_the_shared_head: usize,
    /// How many of those are still **live**. The refused one must not be: it is on no chain, so a
    /// live one is a delta that has outlived its transaction.
    live_deltas_against_the_shared_head: usize,
    /// The violations the read-only consistency pass found afterwards. Empty is the assertion; the
    /// field carries them so a failure names them.
    violations: Vec<String>,
}

/// Runs two transactions writing the **same** property of the **same** node, on two scheduled
/// threads, under the schedule `seed` names.
fn scenario(seed: u64) -> Run {
    // Switch at EVERY yield point: the window spans the few steps between one writer reading the
    // chain head and the other publishing onto it, which the amortised default steps over.
    let cfg = DetSchedConfig::exhaustive(seed);
    let (run, _history) = run_scheduled(cfg, || {
        let device = MemBlockDevice::new(0);
        let wal = WalManager::create(MemLogSink::new()).expect("create wal");
        let store = Arc::new(RecordStore::create(device, wal, 64, 1).expect("create store"));

        // Interning takes the catalogue's write latch, which the scheduler does not mediate. Done on
        // the root thread, so the run's contention is only where the scenario means it to be.
        let key = store
            .intern_token(Namespace::PropKey, "p")
            .expect("intern a property key");

        // The node, and one COMMITTED overwrite of its property. The overwrite is what makes the
        // chain head a delta of a *finished* transaction, so both writers below pass `link_delta`'s
        // entry guard and the race is decided at the publication rather than before it.
        let setup = TxnId(1);
        store.begin(setup);
        let (node, _) = store.create_node(setup).expect("create the node");
        store
            .add_node_property(setup, node, key, TYPE_TAG, 7)
            .expect("seed the property");
        store.commit(setup).expect("commit setup");

        let overwrite = TxnId(2);
        store.begin(overwrite);
        store
            .add_node_property(overwrite, node, key, TYPE_TAG, 8)
            .expect("overwrite the property so the chain head is a committed delta");
        store.commit(overwrite).expect("commit the overwrite");

        // The head both writers below will read, and the value their deltas' `next` must name for
        // this run to have entered the window at all.
        let shared_head = store
            .undo_chain_for_test(StoreKind::Node, node)
            .expect("walk the node's chain")
            .first()
            .map(|&(id, _)| id)
            .expect("the committed overwrite left a chain head");

        // THE RACE, in the shape the `rmp` #1034 certification workload has: every writer contends
        // for the SAME property and then does private work before committing.
        //
        // The private write is what makes the window reachable, and it is the one thing an earlier
        // draft of this file got wrong. A refused compare-and-set only leaks a delta if the head it
        // re-reads belongs to a **still-open** transaction; a winner that commits immediately after
        // publishing is resolved by then, the loser's retry simply succeeds, and nothing is left
        // behind. The certification workload's transactions run a second statement after the
        // contended one (`CREATE (:Rec …)` after `SET c.n = c.n + 1`), so the winner stays open for
        // hundreds of steps — which is exactly the state this reproduces.
        //
        // Each thread ends its own transaction, and only its own (`rmp` #1051).
        let writers: Vec<_> = (0..WRITERS)
            .map(|i| {
                let store = Arc::clone(&store);
                graphus_core::sched::spawn("writer", move || {
                    let txn = TxnId(10 + i as u64);
                    store.begin(txn);
                    let contended =
                        store.add_node_property(txn, node, key, TYPE_TAG, 100 + i as u64);
                    let outcome = contended.map(|_| ()).and_then(|()| {
                        // The private half: its own node, so it can never be refused, and it keeps
                        // this transaction OPEN across the span in which the others publish.
                        let (own, _) = store.create_node(txn)?;
                        store.add_node_property(txn, own, key, TYPE_TAG, 200 + i as u64)?;
                        Ok(())
                    });
                    match outcome {
                        Ok(()) => store.commit(txn).map(|_| ()).map_err(|e| e.to_string()),
                        Err(e) => {
                            let refusal = e.to_string();
                            store
                                .rollback(txn)
                                .expect("the refused writer rolls itself back");
                            Err(refusal)
                        }
                    }
                })
            })
            .collect();
        let outcomes: Vec<Result<(), String>> = writers
            .into_iter()
            .map(|t| t.join().expect("writer joins"))
            .collect();

        // The census this file rests on: every delta slot that names `shared_head` as its `next`, and
        // how many of them are still live. It is taken from the raw store rather than from a chain
        // walk **on purpose** — a leaked delta is on no chain, so a walk is exactly the instrument
        // that cannot see it.
        let mut deltas_against_the_shared_head = 0usize;
        let mut live_deltas_against_the_shared_head = 0usize;
        for id in 1..DELTA_SCAN_LIMIT {
            let Ok(Some(delta)) = store.read_delta_for_test(id) else {
                continue;
            };
            if delta.next == shared_head {
                deltas_against_the_shared_head += 1;
                if delta.in_use() {
                    live_deltas_against_the_shared_head += 1;
                }
            }
        }

        let violations = graphus_storage::check::check_store(&store, &[])
            .expect("the read-only consistency pass runs")
            .violations
            .iter()
            .map(|v| format!("{v:?}"))
            .collect();
        Run {
            outcomes,
            deltas_against_the_shared_head,
            live_deltas_against_the_shared_head,
            violations,
        }
    });
    run
}

/// **A refused publication leaves nothing behind, on every schedule.**
///
/// Three assertions, and the first is what licenses the other two:
///
/// 1. **The window is entered.** At least one seed must leave *two* deltas naming the shared head —
///    the winner's, published, and the loser's, written and then refused. Without this the sweep
///    could pass on schedules that only ever took the entry guard, which allocates nothing and
///    therefore asserts nothing about this window. The probe works identically before and after the
///    fix (the refused delta survives either way; what changes is whether it is *live*), so it
///    cannot be satisfied by the fix it is meant to license.
/// 2. **The refused delta is not live.** At most one delta naming the shared head may be in use: the
///    published one. A second live one is a delta that outlived its transaction — on no chain, and
///    still holding a commit slot the allocator is free to re-issue.
/// 3. **The store is intact.** The read-only consistency pass — which walks the free lists, the
///    chains and the undo area's census — finds nothing. This is where the leak surfaces as
///    `FreedButReferenced` or `DeltaCountMismatch` if assertion 2 is ever weakened away.
#[test]
fn a_refused_publication_leaves_no_live_delta_behind() {
    let runs: Vec<Run> = (0..SEEDS).map(scenario).collect();

    let entered: Vec<u64> = (0..SEEDS)
        .filter(|&s| runs[s as usize].deltas_against_the_shared_head >= 2)
        .collect();
    assert!(
        !entered.is_empty(),
        "NON-VACUITY: no seed in 0..{SEEDS} got two writers to WRITE a delta against the same chain \
         head, so every refusal came from `link_delta`'s entry guard and nothing below asserts \
         anything about a refused publication. Outcomes: {:?}",
        runs.iter().map(|r| &r.outcomes).collect::<Vec<_>>()
    );
    println!(
        "rmp #1053: the publication window was entered on {} of {SEEDS} seeds {entered:?}",
        entered.len()
    );

    for (seed, run) in runs.iter().enumerate() {
        assert!(
            run.live_deltas_against_the_shared_head <= 1,
            "seed {seed}: {} live deltas name the same chain head, so a refused publication left \
             its delta LIVE on no chain (`rmp` #1053). It is uncounted by `publish_commit_slot`, \
             unfreed by `detach_own_deltas`, and it outlives the commit slot it names. Outcomes: \
             {:?}",
            run.live_deltas_against_the_shared_head,
            run.outcomes
        );
        assert!(
            run.violations.is_empty(),
            "seed {seed}: the store is inconsistent after two writers contended for one chain. \
             Outcomes: {:?}. Violations: {:?}",
            run.outcomes,
            run.violations
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
