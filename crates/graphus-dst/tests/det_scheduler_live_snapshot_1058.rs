//! **A live snapshot placed inside a commit's publication window, from a seed** (`rmp` #1058).
//!
//! # The window, and why a seed is the only honest way to sit in it
//!
//! `RecordStore::commit_prepare` issues its commit timestamp `C` at the top and makes `C` readable
//! only later, in two places: the durable `commit.store` slot ([`YieldSite::CommitPublishSlot`]) and
//! then the in-memory commit registry ([`YieldSite::CommitRegistryRecord`]). Between the issue and
//! the slot write there is a whole `checkpoint_meta`; nothing at `C` is visible for any of it.
//!
//! A reader resolves each undo delta it walks against a **live** read of that delta's commit slot
//! (`graphus_storage::read_view::decide_properties`), once per entity. Two entities written by one
//! transaction are therefore two slot reads at two different instants. Let a reader hold a snapshot
//! timestamp `>= C` while `C` is still publishing, and let the slot write fall between those two
//! reads, and the reader keeps the new value of the entity it read second and the old value of the
//! entity it read first — **one leg of a transfer without the other**.
//!
//! What decides whether that is reachable is what [`RecordStore::snapshot_ts`] hands out. The
//! allocation clock (`commit_ts_hw`, the pre-#1056 shape) reaches `C` the instant `C` is issued and
//! walks the reader straight in. The commit-visibility horizon (`commit_visible_hw`, shipped by `rmp`
//! #1056) is the contiguous **published** prefix, so while `C` is pending the reader is held at
//! `C - 1` or below — and there both slot reads decide the same way whichever side of the publication
//! they land on, because an unpublished delta is undone and a `Committed(C)` delta with
//! `C > snapshot.ts` is undone too. The tear is not repaired; it is made unreachable.
//!
//! Reaching that interleaving needs the snapshot instant itself to be a scheduling seam, which is
//! what [`YieldSite::SnapshotBegin`] is: `RecordStore::begin` offers the token immediately before it
//! reads the horizon. Every reader round here takes its snapshot through `begin`, exactly as every
//! reader in the engine does, so the scheduler can park a reader in the window rather than hoping the
//! step count happens to land there.
//!
//! # The scenario
//!
//! [`WRITERS`] writers, each owning the disjoint account pair `(w, w + WRITERS)` and moving
//! [`AMOUNT`] between them one transaction at a time, plus one reader looping over all [`ACCOUNTS`]
//! accounts at a snapshot it takes itself. `sum(balance)` is [`TOTAL`] at every committed point, so a
//! sum off by exactly `AMOUNT` is exactly one observed leg of one transfer.
//!
//! Two writers rather than one, because a second committer is what makes the horizon's *contiguity*
//! rule load-bearing: with `A` pending at `C` and `B` already published at `C + 1`, the published
//! prefix must stay at `C - 1` rather than jump to `C + 1`. One writer can never produce that state.
//!
//! The pair is `(w, w + WRITERS)` and not `(2w, 2w + 1)` because the reader scans in index order, so
//! this puts the other writer's accounts between a writer's two legs and gives the scheduler more
//! places to interpose the publication.
//!
//! Disjoint accounts do **not** make the writers refusal-free. A writer's own previous commit at `C`
//! is a chain head it cannot see whenever the *other* writer's pending commit is holding the
//! published prefix below `C`, and `ensure_chain_head_unheld`'s second arm refuses it with a
//! retriable serialization failure — the horizon being conservative in freshness, which is what makes
//! it safe. The workload does what any client must do and retries.
//!
//! # Non-vacuity
//!
//! Asserted on every run, not claimed:
//!
//! * the scheduler really handed the token over and all [`WRITERS`] + 1 logical threads really ran,
//!   and the writers **acknowledged** every transfer — counted after `commit` returned, never read
//!   back off the loop bound ([`the_threads_really_interleave`]);
//! * all three seams of this scenario were really reached — [`YieldSite::SnapshotBegin`],
//!   [`YieldSite::CommitPublishSlot`], [`YieldSite::CommitRegistryRecord`];
//! * the reader really read a moving store **on some single seed**, not merely across the pooled
//!   sweep ([`the_reader_really_reads_a_moving_store`]);
//! * and the window the defect needs really occurred, **fully attributed**
//!   ([`the_snapshot_really_lands_inside_a_publication_window`]). A round qualifies only when a
//!   committed transfer's timestamp `C` was provably already issued when the round snapshotted
//!   (`allocated >= C`, sound because the allocation clock is monotone and is sampled *before* the
//!   snapshot), the horizon the round actually got had not reached it (`begin_ts < C`), and that
//!   commit's `CommitPublishSlot` step lies inside the round's own **scan** — bounded at the
//!   reader's last record read, so the rollback and any idle time afterwards are excluded. Measured:
//!   **9 attributed windows across 6 of the 16 seeds**, listed by the test itself.
//!
//! One of them is worth reading, because it is the contiguity rule doing its job:
//! `seed 0x4 round 4: snapshot at 3 while the commit at 5 was issued and still publishing`. The
//! horizon is held at 3, not 4, because the commit at 4 is pending too.
//!
//! # Ablation (measured 2026-08-12)
//!
//! `snapshot_ts()` reverted to the pre-#1056 shape — `Timestamp(self.commit_ts_hw.load(Acquire))` —
//! and nothing else changed. [`no_live_snapshot_observes_half_a_commit`] FAILS on **9 of the 16
//! seeds**, 13 torn rounds, and two consecutive ablation runs produced the byte-identical list:
//!
//! ```text
//! seed 0x2 round  3: begin_ts 3, sum 4010 != 4000 (off by  10, 1 leg) — [1000,  990, 1010, 1010]
//! seed 0x3 round  7: begin_ts 6, sum 4010 != 4000 (off by  10, 1 leg) — [1000, 1000, 1010, 1000]
//! seed 0x4 round  2: begin_ts 2, sum 4010 != 4000 (off by  10, 1 leg) — [1000, 1000, 1010, 1000]
//! seed 0x5 round  3: begin_ts 3, sum 4010 != 4000 (off by  10, 1 leg) — [1000,  990, 1010, 1010]
//! seed 0x5 round  8: begin_ts 7, sum 4010 != 4000 (off by  10, 1 leg) — [1000,  990, 1010, 1010]
//! seed 0x7 round  2: begin_ts 2, sum 4010 != 4000 (off by  10, 1 leg) — [1000, 1000, 1000, 1010]
//! seed 0x7 round  8: begin_ts 7, sum 4010 != 4000 (off by  10, 1 leg) — [1000,  990, 1010, 1010]
//! seed 0x9 round  4: begin_ts 5, sum 3990 != 4000 (off by -10, 1 leg) — [ 990, 1000, 1000, 1000]
//! seed 0x9 round 10: begin_ts 8, sum 3990 != 4000 (off by -10, 1 leg) — [ 990,  990, 1010, 1000]
//! seed 0xa round  8: begin_ts 7, sum 4010 != 4000 (off by  10, 1 leg) — [1000,  990, 1010, 1010]
//! seed 0xd round 10: begin_ts 8, sum 3990 != 4000 (off by -10, 1 leg) — [ 990,  990, 1000, 1010]
//! seed 0xe round  3: begin_ts 3, sum 4020 != 4000 (off by  20, 2 legs) — [1000, 1000, 1010, 1010]
//! seed 0xe round  5: begin_ts 4, sum 3990 != 4000 (off by -10, 1 leg) — [ 990,  990, 1000, 1010]
//! ```
//!
//! Read seed `0x4` round 2: the reader's snapshot is `begin_ts 2`, and the balances are
//! `[1000, 1000, 1010, 1000]`. Writer 1's pair (accounts 1 and 3) reads `1000 + 1000` — untouched.
//! Writer 0's pair (accounts 0 and 2) reads `1000 + 1010`: the credited leg of a transfer kept and
//! the debited leg undone, at a timestamp the allocation clock had already advanced to while the
//! commit at that timestamp was still publishing itself.
//!
//! Every off-by is an exact multiple of [`AMOUNT`], which is what makes the failure one or two
//! observed legs and nothing else. With the shipped `snapshot_ts()` all sixteen seeds are clean.
//!
//! [`the_snapshot_really_lands_inside_a_publication_window`] also fails under the ablation, reporting
//! **0** attributed windows where the shipped build reports 9. That is the defect stated from the
//! other side rather than a weakness of the witness: the witness is defined against a horizon
//! *distinct from* the allocation clock, and the ablation makes them one value — the reader is then
//! never held behind a pending commit, it is unconditionally inside every one of them. The other
//! three non-vacuity tests pass in both builds.
//!
//! # Scope
//!
//! **Node properties only**, like its real-threads twin: the balances are read through
//! `decision_scan_node_properties`. Relationship properties and labels reach the same
//! `scan_polarity::delta_verdict` through different entry points (the relationship property path and
//! `label_bitmap_at`) and are **not** covered here.
//!
//! The real-threads twin of this suite is `graphus-storage`'s `live_snapshot_horizon_1058`, which
//! measures the same window under genuine parallelism.
//!
//! # Running it
//!
//! ```text
//! cargo test -p graphus-dst --features det-sched --test det_scheduler_live_snapshot_1058
//! ```

use std::collections::BTreeSet;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};

use graphus_core::sched::YieldSite;
use graphus_core::{GraphusError, TxnId, Value};
use graphus_dst::detsched::{DetSchedConfig, SchedHistory, run_scheduled};
use graphus_io::MemBlockDevice;
use graphus_storage::{Namespace, RecordStore};
use graphus_txn::Snapshot;
use graphus_wal::{MemLogSink, WalManager};

/// Concurrent writer threads. Two, because the horizon's contiguity rule needs a second committer to
/// be load-bearing at all (see the module note).
const WRITERS: usize = 2;
/// Accounts in the conserved system — two per writer.
const ACCOUNTS: usize = 2 * WRITERS;
/// What each account starts with.
const START: i64 = 1_000;
/// The invariant every snapshot read must observe.
const TOTAL: i64 = ACCOUNTS as i64 * START;
/// What one transfer moves, and therefore the exact size of one torn leg.
const AMOUNT: i64 = 10;
/// Transfers each writer performs. Each is one transaction with two legs.
const TRANSFERS: usize = 4;
/// Read rounds the reader performs, unless the writers finish first.
const ROUNDS: usize = 24;
/// Base of the reader's transaction-id range, kept far away from the writers' so a `SnapshotBegin`
/// step can be attributed to the reader by the resource id the history recorded with it.
const READER_TXN_BASE: u64 = 10_000;
/// The seeds this suite pins. A fixed list, not a sample: a seed that reproduces a defect is
/// evidence only if it is still run tomorrow.
const SEEDS: [u64; 16] = [
    0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf,
];

/// Ceiling on a writer's refused attempts for one transfer, so a regression that freezes the horizon
/// fails this scenario instead of spinning inside the scheduler.
const MAX_ATTEMPTS: u64 = 1_000;

/// The two accounts writer `w` owns.
const fn legs(w: usize) -> (usize, usize) {
    (w, w + WRITERS)
}

/// Whether a writer's pair of balances is one a **committed** state can hold. Each writer alternates
/// the direction of its transfer, so its pair is only ever untouched or one transfer along.
fn legal_pair(debit: i64, credit: i64) -> bool {
    (debit == START && credit == START) || (debit == START - AMOUNT && credit == START + AMOUNT)
}

/// One reader round: the snapshot it took and what it saw through it.
#[derive(Debug, Clone)]
struct Round {
    /// Which round of the reader's loop it was.
    round: usize,
    /// The begin timestamp `RecordStore::begin` handed back — the reader's live snapshot.
    begin_ts: u64,
    /// The **allocation clock** sampled immediately BEFORE the snapshot was taken. Because that clock
    /// is monotone, this is a lower bound on its value at the snapshot instant, which is what lets
    /// [`the_snapshot_really_lands_inside_a_publication_window`] prove that a given commit's timestamp
    /// had already been issued when this round snapshotted.
    allocated: u64,
    /// Every account's balance at that snapshot, in scan order.
    balances: Vec<i64>,
}

impl Round {
    fn sum(&self) -> i64 {
        self.balances.iter().sum()
    }

    /// Why this round observed a state no serial schedule could produce, or [`None`] if it did not.
    ///
    /// Two independent oracles: the conserved total, and each writer's pair being a state that writer
    /// actually passed through. The second is strictly stronger — a scan that tears two writers'
    /// pairs in opposite directions conserves the total exactly and is still an isolation violation.
    fn illegal(&self) -> Option<String> {
        let sum = self.sum();
        if sum != TOTAL {
            return Some(format!(
                "sum {sum} != {TOTAL} (off by {}, i.e. {} transfer leg(s))",
                sum - TOTAL,
                (sum - TOTAL).abs() / AMOUNT
            ));
        }
        for w in 0..WRITERS {
            let (a, b) = legs(w);
            if !legal_pair(self.balances[a], self.balances[b]) {
                return Some(format!(
                    "the total is conserved but writer {w}'s pair reads ({}, {}), which is neither \
                     ({START}, {START}) nor ({}, {})",
                    self.balances[a],
                    self.balances[b],
                    START - AMOUNT,
                    START + AMOUNT
                ));
            }
        }
        None
    }
}

/// What one scheduled run produced.
struct Run {
    rounds: Vec<Round>,
    /// `(transaction id, commit timestamp)` for every acknowledged transfer, so a `CommitPublishSlot`
    /// step in the history — which carries the transaction id as its resource — can be resolved to
    /// the timestamp that commit was publishing.
    commits: Vec<(u64, u64)>,
    /// Transfers the writers **acknowledged**, counted on the line after `commit` returned.
    transfers: usize,
    /// Attempts the write-write check refused and the writer retried.
    retries: usize,
    history: SchedHistory,
}

/// Runs [`WRITERS`] writers and one live-snapshot reader over the conserved system, under a scheduler
/// seeded with `seed`.
fn scenario(seed: u64) -> Run {
    // Switch at EVERY yield point: the window this scenario targets is the handful of steps between
    // a committer issuing its timestamp and publishing its commit, which the amortised default would
    // step straight over.
    let cfg = DetSchedConfig::exhaustive(seed);
    let ((rounds, commits, transfers, retries), history) = run_scheduled(cfg, || {
        let device = MemBlockDevice::new(0);
        let wal = WalManager::create(MemLogSink::new()).expect("create wal");
        let store = Arc::new(RecordStore::create(device, wal, 4096, 1).expect("create store"));
        // Interned up front, on the root thread: the catalogue's write lock is not scheduler-mediated,
        // so keeping it out of the concurrent phase keeps the contention where the scenario means it.
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

        let stop = Arc::new(AtomicBool::new(false));

        let reader = {
            let store = Arc::clone(&store);
            let stop = Arc::clone(&stop);
            let nodes = nodes.clone();
            graphus_core::sched::spawn("reader", move || {
                let clock = store.commit_clock();
                let mut out = Vec::with_capacity(ROUNDS);
                for round in 0..ROUNDS {
                    if stop.load(Ordering::Acquire) {
                        break;
                    }
                    let txn = TxnId(READER_TXN_BASE + round as u64);
                    // Sampled BEFORE the snapshot: the allocation clock is monotone, so this is a
                    // lower bound on its value at the snapshot instant that follows.
                    let allocated = clock.load(Ordering::Acquire);
                    // THE SEAM. `begin` yields at `SnapshotBegin` and then reads the horizon, so the
                    // scheduler decides — from the seed — whether this snapshot is taken inside
                    // another thread's commit-publication window.
                    let begin_ts = store.begin(txn);
                    let snapshot = Snapshot::new(txn, begin_ts);
                    let balances: Vec<i64> = nodes
                        .iter()
                        .map(|&node| {
                            store
                                .decision_scan_node_properties(node, snapshot)
                                .expect("a snapshot read of a live account must not fail")
                                .visible_versions()
                                .iter()
                                .find(|c| c.key == key)
                                .map_or(0, |c| c.value_inline as i64)
                        })
                        .collect();
                    store.rollback(txn).expect("close the read transaction");
                    out.push(Round {
                        round,
                        begin_ts: begin_ts.0,
                        allocated,
                        balances,
                    });
                }
                out
            })
        };

        let refused: Arc<Mutex<usize>> = Arc::new(Mutex::new(0));
        // `(transaction id, commit timestamp)` per acknowledged transfer, so the history's
        // `CommitPublishSlot` steps can be resolved to the timestamp being published.
        let commits: Arc<Mutex<Vec<(u64, u64)>>> = Arc::new(Mutex::new(Vec::new()));
        let writers: Vec<_> = (0..WRITERS)
            .map(|w| {
                let store = Arc::clone(&store);
                let nodes = nodes.clone();
                let refused = Arc::clone(&refused);
                let commits = Arc::clone(&commits);
                graphus_core::sched::spawn(&format!("writer-{w}"), move || {
                    let (a, b) = legs(w);
                    let mut balance = [START; 2];
                    let mut attempt = 0u64;
                    // COUNTED on the line after `commit` returns, never assumed from the loop bound.
                    let mut committed = 0usize;
                    for t in 0..TRANSFERS {
                        // The new balances are computed ONCE, outside the retry loop: a refused
                        // attempt wrote nothing, so it must not move the writer's own model.
                        let (from, to) = if t % 2 == 0 { (0, 1) } else { (1, 0) };
                        let mut next = balance;
                        next[from] -= AMOUNT;
                        next[to] += AMOUNT;
                        let mut refusals_here = 0u64;
                        loop {
                            assert!(
                                refusals_here < MAX_ATTEMPTS,
                                "writer {w} transfer {t}: refused {MAX_ATTEMPTS} times in a row, so \
                                 the horizon stopped advancing and this writer can never see its \
                                 own last commit"
                            );
                            // Disjoint id ranges, so no two threads can pick the same transaction
                            // id, and a fresh id per attempt, because a rolled-back id is spent.
                            let txn = TxnId(1_000_000 * (w as u64 + 1) + attempt);
                            attempt += 1;
                            store.begin(txn);
                            // Two legs, ONE transaction: they commit together or not at all.
                            let written = store
                                .set_node_property_value(
                                    txn,
                                    nodes[a],
                                    key,
                                    &Value::Integer(next[0]),
                                )
                                .and_then(|_| {
                                    store.set_node_property_value(
                                        txn,
                                        nodes[b],
                                        key,
                                        &Value::Integer(next[1]),
                                    )
                                });
                            match written {
                                Ok(_) => {
                                    let commit_ts =
                                        store.commit(txn).expect("an admitted transfer commits");
                                    committed += 1;
                                    commits
                                        .lock()
                                        .expect("commit log")
                                        .push((txn.0, commit_ts.0));
                                    break;
                                }
                                // Retriable, and expected: see the module note on refusals.
                                Err(GraphusError::Transaction(_)) => {
                                    store.rollback(txn).expect("roll back a refused transfer");
                                    *refused.lock().expect("refusal counter") += 1;
                                    refusals_here += 1;
                                }
                                Err(e) => {
                                    panic!("writer {w} transfer {t}: unexpected store error: {e}")
                                }
                            }
                        }
                        balance = next;
                    }
                    committed
                })
            })
            .collect();

        let transfers: usize = writers
            .into_iter()
            .map(|h| h.join().expect("a writer thread joins"))
            .sum();
        stop.store(true, Ordering::Release);
        let rounds = reader.join().expect("the reader thread joins");
        let retries = *refused.lock().expect("refusal counter");
        let commits = commits.lock().expect("commit log").clone();
        (rounds, commits, transfers, retries)
    });
    Run {
        rounds,
        commits,
        transfers,
        retries,
        history,
    }
}

/// The transaction id a `ResourceId::txn(id)` names, or [`None`] for any other resource class.
///
/// The encoding is fixed by `graphus_core::sched::ResourceId`: class `5` in the top byte, the value
/// in the low 56 bits.
fn txn_of(resource: u64) -> Option<u64> {
    const CLASS_TXN: u64 = 5;
    const VALUE_MASK: u64 = (1u64 << 56) - 1;
    (resource >> 56 == CLASS_TXN).then_some(resource & VALUE_MASK)
}

/// The reader round a `SnapshotBegin` resource names, or [`None`] if the resource is not one of the
/// reader's transactions.
fn reader_round_of(resource: u64) -> Option<usize> {
    let id = txn_of(resource)?;
    // An explicit range test, not `then_some`: that argument is evaluated eagerly, and the
    // subtraction underflows for every writer's transaction id (which sit below the base).
    if id < READER_TXN_BASE || id >= READER_TXN_BASE + ROUNDS as u64 {
        return None;
    }
    Some((id - READER_TXN_BASE) as usize)
}

/// Every reader round whose snapshot **provably** fell inside a commit's publication window, with the
/// commit that window belonged to.
///
/// This is a full attribution, not a proxy. A round qualifies when there is a committed transfer `W`
/// with commit timestamp `C` such that all three hold:
///
/// 1. `round.allocated >= C` — the allocation clock had already reached `C` *before* the round took
///    its snapshot, so `C` had been **issued**. Sound because that clock is monotone and the sample
///    is taken before the snapshot;
/// 2. `round.begin_ts < C` — the horizon the snapshot actually got had **not** reached `C`, so `C`
///    was issued and not yet published at that instant. Together with (1) that *is* the window;
/// 3. `W`'s [`YieldSite::CommitPublishSlot`] step lies inside the round's **scan** — between the
///    round's own `SnapshotBegin` and the last record read the reader performed before its next
///    snapshot. So the publication landed in the middle of the very scan taken at that snapshot,
///    which is the interleaving that tears the read when the horizon lies.
///
/// The scan is bounded at the reader's last [`YieldSite::FrameReadFetched`] step rather than at its
/// next snapshot, so the rollback and any idle time after the scan are excluded: a publication
/// landing there is not inside the scan and must not count.
fn rounds_inside_a_publication_window(run: &Run) -> Vec<(usize, u64, u64)> {
    let steps = run.history.decode();
    let commit_ts_of: std::collections::HashMap<u64, u64> = run.commits.iter().copied().collect();
    // (step index of the round's snapshot, the round number, the reader's logical thread id).
    let snapshots: Vec<(usize, usize, u32)> = steps
        .iter()
        .enumerate()
        .filter_map(|(i, (_, thread, site, _, resource))| {
            (*site == YieldSite::SnapshotBegin.code())
                .then(|| reader_round_of(*resource).map(|r| (i, r, *thread)))
                .flatten()
        })
        .collect();

    let mut out = Vec::new();
    for (k, &(start, round_no, reader_thread)) in snapshots.iter().enumerate() {
        let Some(round) = run.rounds.iter().find(|r| r.round == round_no) else {
            continue;
        };
        let limit = snapshots.get(k + 1).map_or(steps.len(), |&(i, _, _)| i);
        // The round's SCAN ends at the reader's last record read before its next snapshot.
        let Some(scan_end) = (start + 1..limit).rev().find(|&i| {
            steps[i].1 == reader_thread && steps[i].2 == YieldSite::FrameReadFetched.code()
        }) else {
            continue;
        };
        for step in &steps[start + 1..scan_end] {
            if step.2 != YieldSite::CommitPublishSlot.code() {
                continue;
            }
            let Some(commit_ts) = txn_of(step.4).and_then(|t| commit_ts_of.get(&t)) else {
                continue;
            };
            if round.allocated >= *commit_ts && round.begin_ts < *commit_ts {
                out.push((round_no, round.begin_ts, *commit_ts));
            }
        }
    }
    out
}

/// **The property.** A snapshot the reader took **itself**, live, never observes one leg of a
/// transfer without the other.
///
/// This is the complement of `graphus-storage`'s `torn_property_read_1057` suite, which deliberately
/// snapshotted at a timestamp published only after `commit` returned and so excluded this window by
/// construction. Here the reader samples the horizon while the committers are running, which is the
/// only way to sit inside it.
#[test]
fn no_live_snapshot_observes_half_a_commit() {
    let mut torn = Vec::new();
    for seed in SEEDS {
        let run = scenario(seed);
        assert!(
            !run.rounds.is_empty(),
            "seed {seed:#x}: the reader observed nothing, so the property was never tested"
        );
        for round in &run.rounds {
            if let Some(why) = round.illegal() {
                torn.push(format!(
                    "seed {seed:#x} round {}: begin_ts {}, {why} — {:?}",
                    round.round, round.begin_ts, round.balances,
                ));
            }
        }
    }
    assert!(
        torn.is_empty(),
        "a scheduled live snapshot observed a state no serial schedule could produce — the snapshot \
         timestamp named a commit that had not finished publishing itself (`rmp` #1058):\n{}",
        torn.join("\n")
    );
}

/// **Non-vacuity.** The scheduler really interleaved the threads, every writer completed its
/// transfers, and all three seams this scenario is written around were really reached.
#[test]
fn the_threads_really_interleave() {
    for seed in SEEDS {
        let run = scenario(seed);
        assert!(
            run.history.switches > 0,
            "seed {seed:#x}: the scheduler never handed the token over, so the run was serial"
        );
        // `> WRITERS` is `>= WRITERS + 1`: every writer AND the reader appear in the history.
        assert!(
            run.history.threads > WRITERS,
            "seed {seed:#x}: only {} logical thread(s) ran, so the {WRITERS} writers and the reader \
             were not all interleaved",
            run.history.threads
        );
        // Thread COUNT alone would be satisfied by a reader that started and immediately stopped.
        // This is the reader actually doing the work the property is asserted over.
        assert!(
            !run.rounds.is_empty(),
            "seed {seed:#x}: the reader thread ran but completed no round, so nothing was read \
             against the writers"
        );
        assert_eq!(
            run.transfers,
            WRITERS * TRANSFERS,
            "seed {seed:#x}: the writers acknowledged {} transfers, not {}",
            run.transfers,
            WRITERS * TRANSFERS
        );
        assert_eq!(
            run.commits.len(),
            WRITERS * TRANSFERS,
            "seed {seed:#x}: {} commit timestamps were recorded for {} acknowledged transfers",
            run.commits.len(),
            run.transfers
        );
        for site in [
            YieldSite::SnapshotBegin,
            YieldSite::CommitPublishSlot,
            YieldSite::CommitRegistryRecord,
        ] {
            assert!(
                run.history.count_site(site) > 0,
                "seed {seed:#x}: {site:?} was never reached, so the window this scenario places a \
                 snapshot in was never entered"
            );
        }
    }
}

/// **Non-vacuity, and the window by name.** Some seed produced a reader round whose snapshot
/// provably fell inside a commit's publication window, with that commit publishing in the middle of
/// the round's own scan.
///
/// Fully attributed rather than inferred — see [`rounds_inside_a_publication_window`] for the three
/// conditions and why each is sound. Without this, the property above would be satisfied by sixteen
/// runs in which every read happened to fall outside every publication: a by-seed reproduction that
/// reproduces nothing, which is exactly how the first draft of `rmp` #1056's suite came back clean on
/// all its seeds with the fix withdrawn.
#[test]
fn the_snapshot_really_lands_inside_a_publication_window() {
    let mut witnesses = Vec::new();
    for seed in SEEDS {
        for (round, begin_ts, commit_ts) in rounds_inside_a_publication_window(&scenario(seed)) {
            witnesses.push(format!(
                "seed {seed:#x} round {round}: snapshot at {begin_ts} while the commit at \
                 {commit_ts} was issued and still publishing, and it published inside that round's \
                 own scan"
            ));
        }
    }
    // Printed so the strength of the witness is a measured number rather than a claim.
    println!(
        "{} attributed window(s) across {} seeds:\n{}",
        witnesses.len(),
        SEEDS.len(),
        witnesses.join("\n")
    );
    assert!(
        !witnesses.is_empty(),
        "no seed took a reader snapshot while a commit timestamp sat issued-but-unpublished above \
         its horizon AND had that commit publish inside the same scan, so the window `rmp` #1058 is \
         about was never sampled and these seeds prove nothing about it"
    );
}

/// **Non-vacuity of the workload's own premise.** The reader observed more than one state of the
/// system **on some single seed**, so on that seed it really did read a moving store.
///
/// Per seed, not pooled: sixteen seeds each observing one settled state of its own would satisfy a
/// pooled check while not one of them had read anything concurrent.
#[test]
fn the_reader_really_reads_a_moving_store() {
    let mut best = (SEEDS[0], 0usize);
    for seed in SEEDS {
        let states: BTreeSet<Vec<i64>> = scenario(seed)
            .rounds
            .into_iter()
            .map(|r| r.balances)
            .collect();
        if states.len() > best.1 {
            best = (seed, states.len());
        }
    }
    assert!(
        best.1 > 1,
        "no seed observed more than one state of the system (the best was seed {:#x} with {}), so \
         no read was concurrent with a transfer and the conserved total was conserved trivially",
        best.0,
        best.1
    );
}

/// **Determinism.** The same seed replays the same interleaving and the same observations, which is
/// what makes a reproduction from a seed a reproduction at all.
#[test]
fn the_same_seed_replays_the_same_interleaving() {
    for seed in [SEEDS[0], SEEDS[7], SEEDS[15]] {
        let first = scenario(seed);
        let second = scenario(seed);
        assert_eq!(
            first.history.hash, second.history.hash,
            "seed {seed:#x}: the same seed produced two different interleavings"
        );
        assert_eq!(
            first.retries, second.retries,
            "seed {seed:#x}: the same seed refused a different number of attempts"
        );
        let a: Vec<(u64, Vec<i64>)> = first
            .rounds
            .iter()
            .map(|r| (r.begin_ts, r.balances.clone()))
            .collect();
        let b: Vec<(u64, Vec<i64>)> = second
            .rounds
            .iter()
            .map(|r| (r.begin_ts, r.balances.clone()))
            .collect();
        assert_eq!(
            a, b,
            "seed {seed:#x}: the same seed produced two different sequences of observations"
        );
    }
}
