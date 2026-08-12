//! **`rmp` #1067 — the applied-transaction set is bounded, under load, with losers in it.**
//!
//! # What could grow, and why it would be silent
//!
//! Since #1067 a commit's cardinality change reaches disk as its own WAL record, and the catalogue
//! image carries the **set of transactions the persisted counters already account for**
//! ([`AppliedTxSet`]). That set is a gap-free frontier plus an explicit list of the ids above it —
//! the shape `rmp` #1066 adopted because a watermark is unsound here (a transaction with a higher id
//! can be applied while a lower one is still in flight).
//!
//! A transaction that never applies — a **loser**, which rolls back and logs no delta at all —
//! stalls that frontier immediately below itself, and every applied id above it has to be carried
//! explicitly. Under sustained load with rollbacks in the mix, that list grows by one entry per
//! commit and there is no natural end to it. It is written into every catalogue image, so the growth
//! is not a memory leak that a restart clears: it is a durable structure that gets bigger for ever,
//! and nothing in any result the store returns would ever look wrong.
//!
//! #1066 named the bound and left it to this task: an id whose delta record is **no longer in the
//! retained log** can never be presented to a replay again, so it can leave the set. The reclaim
//! that removes those records is the checkpoint's, and this file is the proof that the two are
//! actually wired to each other.
//!
//! # What this measures, and why measuring correctness would not be enough
//!
//! The counters coming out right is [`the counters stay exact`](counters_stay_exact) below and it is
//! necessary — but a build that never dropped a single id from the set would satisfy it perfectly
//! while growing without end. So the assertion is on the **size of the set, sampled throughout the
//! load**: it must not keep pace with the number of commits.
//!
//! # Why the WAL reclaim needs a freeze pass to move at all
//!
//! The reclaim floor is clamped by `unfrozen_commit_lsn` — the oldest committed transaction whose
//! record versions a GC pass has not yet frozen — because an unfrozen in-flight stamp is resolved
//! through its commit record. So a store that checkpoints but never runs GC retains its whole log by
//! design, and the applied set legitimately grows with it. `RecordStore::gc_freeze_only` (`rmp` #590)
//! exists precisely to drain that map, and the maintenance cycle below is the shape a server runs.
//!
//! ```text
//! cargo test -p graphus-storage --test applied_counts_stabilises_1067 -- --nocapture
//! ```

use graphus_core::TxnId;
use graphus_io::MemBlockDevice;
use graphus_storage::{Namespace, RecordStore};
use graphus_wal::{LogSink, MemLogSink, WalManager};

type Store = RecordStore<MemBlockDevice, MemLogSink>;

/// Transactions the load runs. Large enough that an unbounded set is unmistakable: at one stray per
/// commit the set would end the run naming hundreds of ids.
const ROUNDS: u64 = 600;

/// Every `MAINTENANCE`th round runs the cycle a server's maintenance loop runs — a freeze pass to
/// lower the WAL reclaim floor, then a checkpoint to fold, persist and reclaim.
const MAINTENANCE: u64 = 25;

/// Buffer-pool frames, comfortably above this workload's working set.
const POOL_PAGES: usize = 256;

/// One sample of the set's size, taken after a maintenance cycle.
#[derive(Debug, Clone, Copy)]
struct Sample {
    round: u64,
    /// Ids named ABOVE the gap-free frontier: the part that grows when a loser stalls it, and the
    /// part the durable image pays eight bytes each for.
    strays: usize,
    frontier: u64,
    /// The WAL's reclaimed floor after this cycle. The witness that the mechanism which BOUNDS the
    /// set actually ran: ids leave the set because their records were physically dropped, so a floor
    /// that never moved would make "the set is empty" a statement about a set nothing ever fed.
    reclaimed_floor: u64,
}

/// Runs the load and returns `(samples, live nodes, durable nodes)`.
///
/// Every third round rolls back, so the id space is riddled with transactions that log no delta and
/// can never enter the set. That is what makes the frontier stall and the strays accumulate — the
/// exact condition this file exists to bound.
fn run() -> (Vec<Sample>, u64, u64) {
    let device = MemBlockDevice::new(0);
    let wal = WalManager::create(MemLogSink::new()).expect("create wal");
    let store: Store = RecordStore::create(device, wal, POOL_PAGES, 1).expect("create store");
    // The automatic cadence is 64 MiB, which this workload never reaches; the maintenance cycle
    // below drives the checkpoints explicitly so their number is a property of the test.
    store.set_checkpoint_interval_bytes(0);
    let label = store
        .intern_token(Namespace::Label, "L")
        .expect("intern the label");

    let mut samples = Vec::new();
    let mut committed = 0u64;
    for r in 1..=ROUNDS {
        let txn = TxnId(r);
        store.begin(txn);
        let (node, _) = store.create_node(txn).expect("create a node");
        store.add_label(txn, node, label).expect("label it");
        if r % 3 == 0 {
            // A LOSER. It logs no count delta, so its id can never enter the applied set and the
            // gap-free frontier can never advance past it.
            store.rollback(txn).expect("roll back");
        } else {
            store.commit(txn).expect("commit");
            committed += 1;
        }
        if r % MAINTENANCE == 0 {
            // The server's maintenance cycle: freeze (which lowers the WAL reclaim floor by draining
            // `unfrozen_commit_lsn`), then checkpoint (which folds the deltas below the floor into the
            // durable base, persists the pair, reclaims the prefix and prunes the set).
            let watermark = store.snapshot_ts();
            let gc_txn = TxnId(1_000_000 + r);
            store.begin(gc_txn);
            store
                .gc_freeze_only(gc_txn, watermark)
                .expect("freeze pass");
            // The pass only SCHEDULES the registry prune; committing it is what applies it and drops
            // the frozen writers out of `unfrozen_commit_lsn`, which is what lets the reclaim floor
            // move at all. Without this commit the log is retained by design and nothing here is
            // measuring the bound.
            store.commit(gc_txn).expect("commit the freeze pass");
            store.checkpoint().expect("checkpoint");
            let applied = store.applied_counts();
            samples.push(Sample {
                round: r,
                strays: applied.stray().count(),
                frontier: applied.frontier(),
                reclaimed_floor: store.with_wal(|w| w.sink().reclaimed_floor()),
            });
        }
    }

    let live = store.statistics().total_nodes();
    (samples, live, committed)
}

/// **The set does not keep pace with the load.**
///
/// The bound asserted is deliberately generous — the point is the SHAPE, not a tuned constant. An
/// unbounded set grows by one id per commit, so by the end of [`ROUNDS`] rounds it would name
/// hundreds; a bounded one holds only what the retained log still has records for, which is one
/// maintenance interval's worth.
///
/// The comparison is against the LAST sample rather than the maximum, and against the number of
/// commits since the previous maintenance cycle rather than a constant, so the test says what it
/// means: after a fold-and-reclaim, what remains is the recent window and not the history.
#[test]
fn the_applied_set_stays_bounded_under_sustained_load_with_losers() {
    let (samples, _, committed) = run();
    assert!(
        samples.len() >= 8,
        "NON-VACUITY: only {} maintenance cycle(s) ran, which is too few for 'the set stopped \
         growing' to mean anything",
        samples.len()
    );
    println!(
        "applied-set size after each maintenance cycle ({committed} commits in the run):\n{}",
        samples
            .iter()
            .map(|s| format!(
                "  round {:>4}: frontier {:>4}, {} stray id(s), WAL reclaimed floor {}",
                s.round, s.frontier, s.strays, s.reclaimed_floor
            ))
            .collect::<Vec<_>>()
            .join("\n")
    );

    // What one maintenance interval can legitimately leave behind: the commits since the previous
    // cycle, plus the ones whose records that cycle's reclaim happened not to reach. Twice the
    // interval is the honest ceiling for "the recent window"; a set that grows with the RUN blows
    // through it long before the end.
    let ceiling = (MAINTENANCE * 2) as usize;
    let last = samples.last().expect("at least one sample");
    assert!(
        last.strays <= ceiling,
        "the applied-transaction set names {} ids above its frontier after {} rounds, which is more \
         than the {ceiling} one maintenance interval can account for. It is persisted inside every \
         catalogue image, so a set that grows with the life of the store makes every checkpoint \
         write more bytes than the last, for ever. The bound is that an id whose delta record the \
         WAL has reclaimed can never be replayed again and must leave the set \
         (`AppliedTxSet::from_retained_ids`, driven by `RecordStore::checkpoint`)",
        last.strays,
        last.round
    );
    // And it is not merely bounded at the end: it never RAN AWAY in the middle either.
    let peak = samples.iter().map(|s| s.strays).max().expect("samples");
    assert!(
        peak <= ceiling,
        "the applied-transaction set peaked at {peak} stray ids during the run, above the \
         {ceiling} one maintenance interval accounts for, so it grows and is merely trimmed at the \
         end: {samples:?}"
    );
}

/// **NON-VACUITY: the mechanism that bounds the set really ran.**
///
/// The set comes out EMPTY at every sample, which is the strongest form of the bound and also the
/// easiest thing in the world to achieve by accident — a build where nothing is ever folded, or
/// where deltas are not logged at all, produces exactly the same measurement. So what is asserted
/// here is the CAUSE: the WAL's reclaimed floor advances across the run.
///
/// The chain is: a checkpoint folds every delta below the floor into the durable base, persists the
/// pair, reclaims the prefix, and then drops from the set every id whose record that reclaim
/// physically removed. A floor that moved is a reclaim that happened; a reclaim that happened over a
/// run of 400 commits is deltas that were folded and dropped. If the floor never moved and the set
/// were still empty, nothing would have been folded and the emptiness would mean nothing.
///
/// # Why this sink empties the set completely, and a production one need not
///
/// [`MemLogSink`] frees exact byte ranges, so everything below the floor really is gone and every
/// folded id can leave. A segmented `FileLogSink` drops whole SEGMENTS, so it commonly retains
/// records below the floor it was given — and those ids must stay in the set, which is exactly why
/// the set is pruned against `reclaimed_floor()` (what the sink actually freed) and never against
/// the floor the checkpoint asked for. The bound there is one segment's worth of records, and the
/// unit tests beside [`AppliedTxSet`] are where the loser-stall growth and the rebuild that bounds
/// it are exercised directly.
#[test]
fn the_reclaim_that_bounds_the_set_really_runs() {
    let (samples, _, committed) = run();
    assert!(
        committed > 100,
        "NON-VACUITY: only {committed} commits ran, which is not a sustained load"
    );
    let first = samples.first().expect("at least one sample");
    let last = samples.last().expect("at least one sample");
    assert!(
        last.reclaimed_floor > first.reclaimed_floor,
        "NON-VACUITY: the WAL reclaimed floor stood still at {} across {} rounds, so no delta \
         record was ever physically dropped. The applied set being empty then says nothing about \
         the bound — it says nothing was ever folded into the base in the first place: {samples:?}",
        first.reclaimed_floor,
        last.round
    );
}

/// **And the counters are exact throughout.** A bound that was achieved by dropping ids the log
/// still holds records for would double-count on the next recovery; a bound achieved by never
/// folding would lose them. Both show up here as a wrong number.
#[test]
fn counters_stay_exact() {
    let (_, live, committed) = run();
    assert_eq!(
        live, committed,
        "the live counter is not the number of commits the run acknowledged, so the fold, the \
         pruning or the rollback withdrawal moved a counter that was not theirs to move"
    );
}
