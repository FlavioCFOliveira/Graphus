//! **A snapshot taken live never lands inside a commit that is still publishing itself**
//! (`rmp` #1058).
//!
//! # The mechanism this pins, and how it differs from `rmp` #1057's
//!
//! A commit becomes visible in **two** places, in this order: the durable `commit.store` slot
//! (`RecordStore::publish_commit_slot`) and then the in-memory `CommitRegistry` entry. The commit
//! *timestamp* is issued long before either, at the top of `RecordStore::commit_prepare`. So there is
//! a real interval — one `checkpoint_meta`, one slot write, one WAL append wide — during which a
//! timestamp `C` has been allocated and nothing at `C` is readable yet.
//!
//! A reader resolves each undo delta it walks against a **live** read of that delta's commit slot
//! (`read_view::decide_properties` -> `read_commit_slot`), once per entity. Two entities written by
//! one transaction are therefore two separate slot reads at two separate instants. If the reader's
//! snapshot timestamp is `>= C` while `C` is still publishing, and the slot publication falls
//! *between* those two reads, the reader keeps the new value of the entity it read second and the old
//! value of the entity it read first: **one leg of a transfer without the other**.
//!
//! Everything above is a property of the reader. What decides whether it is reachable is what
//! `RecordStore::snapshot_ts()` hands out:
//!
//! * the **allocation clock** (`commit_ts_hw`, the pre-#1056 shape) reaches `C` the moment `C` is
//!   issued, so the reader is invited straight into the window;
//! * the **commit-visibility horizon** (`commit_visible_hw`, shipped by `rmp` #1056) is the
//!   contiguous *published* prefix, so while `C` is pending the reader is held at `C - 1` or below.
//!   At `C - 1` both slot reads decide the same way whichever side of the publication they fall on —
//!   unpublished resolves as not-yet-committed, published resolves as `Committed(C)` with `C >
//!   snapshot.ts` — and both undo the delta. The tear is not repaired; it is made **unreachable**.
//!
//! This is the deliberate complement of `rmp` #1057's suite. That one had its readers snapshot at a
//! timestamp the writer published only **after** `commit` returned, which excluded this mechanism *by
//! construction* so that the tear it measured could not be confused with this one. This one does the
//! opposite: every reader derives its own snapshot, concurrently with the committers, which is the
//! only way to sample the interval between a commit timestamp being issued and that commit being
//! published.
//!
//! It derives it through the **production door** — [`RecordStore::begin`], which is where every
//! reader in the engine gets its timestamp and which reads the horizon itself. Calling
//! [`RecordStore::snapshot_ts`] beside a fabricated snapshot would leave `begin` unpinned, so a
//! change to how it derives a timestamp would slip past this probe. It also means the snapshot's
//! owner is this reader's own registered transaction rather than a borrowed identity: a snapshot
//! owned by `TxnId(u64::MAX)` is owned by `SYSTEM_TXN`, and `scan_polarity::delta_verdict` gives
//! `InFlight(w) if w == snapshot.owner` the reader's-own-write treatment, which is a coincidence this
//! probe should not be resting on. The cost is one `begin` + one `rollback` per round, measured at
//! ~44 % of the read throughput of the fabricated-snapshot shape (33 000 rounds against 58 000); the
//! window is still sampled on ~89 % of them, so the door is affordable and is taken.
//!
//! # Scope
//!
//! **Node properties only.** Both probes read balances through
//! `decision_scan_node_properties`. Relationship properties and labels reach the same
//! `scan_polarity::delta_verdict` through different entry points (the relationship property path and
//! `label_bitmap_at`), and those entry points are **not** covered here.
//!
//! # The workload
//!
//! [`ACCOUNTS`] accounts of [`START`] each and [`WRITERS`] concurrent writer threads. Writer `w` owns
//! the disjoint pair `(w, w + WRITERS)` and moves [`AMOUNT`] between them, one transaction per
//! transfer, alternating direction. Disjoint pairs, so no two writers ever contend for one entity;
//! one transaction per transfer, so `sum(balance)` is [`TOTAL`] at every committed point and a sum
//! off by exactly `AMOUNT` is exactly one observed leg of one transfer.
//!
//! Disjoint accounts do **not** make the writers refusal-free, and the workload retries because of
//! it. A writer's own previous commit at `C` is a chain head it cannot see whenever another writer's
//! pending commit is holding the published prefix below `C`, and `ensure_chain_head_unheld`'s second
//! arm refuses it with a retriable serialization failure. That is the horizon being conservative in
//! freshness — the very thing that makes it safe — and the correct answer to it is the one every
//! client gives: roll back and try again.
//!
//! The pair is `(w, w + WRITERS)` and not `(2w, 2w + 1)` on purpose: the reader scans the accounts in
//! index order, so putting a writer's two legs [`WRITERS`] apart puts `WRITERS - 1` other account
//! reads between the two slot reads that have to straddle the publication. It widens the window the
//! probe is trying to sample; it does not create it.
//!
//! # The oracle
//!
//! Two independent checks per scan, in [`illegal_state`]. The conserved total names the leg count and
//! is the shape #1058 was reported in; the per-pair check is strictly stronger, because a scan that
//! tears two writers' pairs in opposite directions conserves the total exactly and is still an
//! isolation violation. That is not hypothetical: of the 480 tears transcribed by the ablation below,
//! **25 conserved the sum** and were caught only by the pair check.
//!
//! # Non-vacuity
//!
//! Five checks, all asserted mechanically on the run that just happened, because a conserved sum is
//! trivially conserved by a reader that never overlaps a writer:
//!
//! 1. the writers **acknowledged** `WRITERS * TRANSFERS` transfers — counted on the line after
//!    `commit` returns, never read back off the loop bound;
//! 2. the readers observed **more than one** distinct state of the system, so they really read a
//!    moving store;
//! 3. they performed more reads than there were transfers;
//! 4. **the window itself**: at least one snapshot was taken while a commit timestamp above its own
//!    horizon had already been issued. Sampled directly — `commit_clock()` (the allocation clock)
//!    read *before* the snapshot, compared against the horizon `begin` then returned. Because the
//!    allocation clock is monotone, `allocated > begin_ts` proves a timestamp was issued-and-
//!    unpublished at the snapshot instant. This replaces the horizon-moved-during-the-scan proxy,
//!    which is neither necessary (the ablation transcript contains tears whose horizon did not move
//!    across the scan) nor sufficient. That counter is still computed, and reported, and asserted on
//!    by nothing;
//! 5. the same window from the write side: at least one attempt was **refused**. A refusal is
//!    `ensure_chain_head_unheld` telling a writer its own last commit sits above the horizon, which
//!    can only happen while another writer's commit is pending — so zero refusals would mean the
//!    committers never overlapped at all.
//!
//! # Ablation (measured 2026-08-12; one 16-core machine, debug profile, otherwise idle)
//!
//! `snapshot_ts()` reverted to the pre-#1056 shape — `Timestamp(self.commit_ts_hw.load(Acquire))` —
//! and nothing else changed. Five consecutive runs, **all five FAILED**, each in ~0.81 s:
//!
//! ```text
//! run 1: 6583 torn of 29857 live snapshot reads, 206 distinct states
//! run 2: 6717 torn of 29652 live snapshot reads, 201 distinct states
//! run 3: 6808 torn of 29562 live snapshot reads, 202 distinct states
//! run 4: 6757 torn of 29982 live snapshot reads, 199 distinct states
//! run 5: 6792 torn of 29457 live snapshot reads, 203 distinct states
//! ```
//!
//! Roughly one read in four and a half. Of the 480 transcribed tears, 455 broke the conserved total —
//! 220 by `+10`, 195 by `-10`, 20 by `+20`, 20 by `-20`, all exact multiples of `AMOUNT`, i.e. whole
//! transfer legs observed without their counterparts — and the remaining **25 conserved the total
//! exactly** and were caught only by the per-pair oracle. A representative entry, verbatim:
//!
//! ```text
//! reader 0 at snapshot 29 (allocation clock 29, horizon 29 after the scan): sum 8020 != 8000
//!   — off by 20 (2 transfer leg(s))
//!   balances [1000, 1000, 1000, 990, 1010, 1010, 1000, 1010],
//!   re-read at the SAME snapshot [990, 990, 1000, 1000, 1010, 1010, 1000, 1000]
//! ```
//!
//! A different answer at the *same* snapshot timestamp is what proves the first was never a function
//! of the snapshot. Note also `horizon 29 after the scan`, unchanged across it: the straddle proxy
//! would not have flagged this one, which is why it is no longer asserted on.
//!
//! Two of this suite's own non-vacuity witnesses also stop firing under the ablation — `0` snapshots
//! inside a window and `0` refusals, in every run. That is not a weakness of the witnesses; it is the
//! defect stated from the other side. Both are defined against a horizon that is *distinct from* the
//! allocation clock, and the ablation makes them the same value: the reader is then never held behind
//! a pending commit, it is unconditionally inside every one of them, and a writer is never told its
//! own last commit is out of reach. The ablated run therefore fails on the oracle first and on those
//! two controls as well.
//!
//! With the shipped `snapshot_ts()` the same workload completes clean. On this machine at this load:
//! 8000 transfers, 33 057 live snapshot reads, 29 322 of them taken inside a publication window,
//! 1713 refusals, **0 torn**, 0.91 s. These figures are one machine at one load and are recorded as
//! evidence of shape, not as a threshold — an independent re-measurement of the earlier
//! fabricated-snapshot shape of this probe on the same box returned 63 503 and 66 495 reads where
//! this session measured 57 500 to 58 700, so read counts and refusal counts move with load and a
//! deviation is not by itself a regression.
//!
//! The deterministic twin of this suite is `graphus-dst`'s `det_scheduler_live_snapshot_1058`, which
//! places a reader's snapshot inside that window from a seed.

use std::collections::BTreeSet;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use graphus_core::{TxnId, Value};
use graphus_io::MemBlockDevice;
use graphus_storage::{Namespace, RecordStore, StoreReadView};
use graphus_txn::Snapshot;
use graphus_wal::{MemLogSink, WalManager};

/// Concurrent writer threads, each committing into its own disjoint pair of accounts. More than one
/// is the point: with `W` committers there are up to `W` timestamps issued and unpublished at once,
/// which is the state `rmp` #1058 is about.
const WRITERS: usize = 4;
/// Accounts in the conserved system — two per writer.
const ACCOUNTS: usize = 2 * WRITERS;
/// What each account starts with.
const START: i64 = 1_000;
/// The invariant every snapshot read must observe.
const TOTAL: i64 = ACCOUNTS as i64 * START;
/// What one transfer moves, and therefore the size of one torn leg.
const AMOUNT: i64 = 10;
/// Transfers each writer performs.
const TRANSFERS: usize = 2_000;
/// Concurrent snapshot readers. Oversubscribing the box (`WRITERS + READERS` = 16 threads here) is
/// what keeps a reader parked mid-scan long enough for a publication to land inside it.
const READERS: usize = 12;
/// How many torn reads are described in full. The count is unbounded; only the transcript is capped,
/// so a badly broken build reports its shape without producing an unreadable failure.
const REPORT_CAP: usize = 8;
/// Base of each reader's transaction-id range. Reader `r` uses `READER_TXN_BASE * (r + 1) + round`,
/// which cannot collide with a writer's `1_000_000 * (w + 1) + attempt`.
const READER_TXN_BASE: u64 = 1_000_000_000;
/// Ceiling on a writer's refused attempts for one transfer. A refusal is retriable and the horizon
/// advances as the other writers publish, so a writer that cannot get through in this many attempts
/// is not contending — it is stuck, and the run must say so rather than spin. `D-published-snapshot-
/// horizon` names the adjacent failure mode directly: a commit timestamp issued and never released
/// freezes the horizon for the life of the process, and under that regression every writer here would
/// refuse forever. Unbounded, this probe would hang CI instead of failing it.
const MAX_ATTEMPTS: u64 = 10_000;

/// The two accounts writer `w` owns: its debit leg and its credit leg, deliberately [`WRITERS`] apart
/// in the reader's scan order (see the module note).
const fn legs(w: usize) -> (usize, usize) {
    (w, w + WRITERS)
}

/// Whether a writer's pair of balances is one a **committed** state can hold.
///
/// Each writer alternates the direction of its transfer, so its pair is only ever untouched or one
/// transfer along. Anything else is a state no serial schedule produced, whatever the total says.
fn legal_pair(debit: i64, credit: i64) -> bool {
    (debit == START && credit == START) || (debit == START - AMOUNT && credit == START + AMOUNT)
}

/// Why `observed` is not a state any serial schedule could have produced, or [`None`] if it is one.
///
/// Two independent oracles, because the conserved total is weaker than what the workload permits: a
/// scan that tears two writers' pairs in opposite directions conserves the sum exactly and is still
/// an isolation violation. The per-pair check catches it; the sum check names the leg count, which is
/// the shape `rmp` #1058 was reported in.
fn illegal_state(observed: &[i64]) -> Option<String> {
    let sum: i64 = observed.iter().sum();
    if sum != TOTAL {
        return Some(format!(
            "sum {sum} != {TOTAL} — off by {} ({} transfer leg(s))",
            sum - TOTAL,
            (sum - TOTAL).abs() / AMOUNT
        ));
    }
    for w in 0..WRITERS {
        let (a, b) = legs(w);
        if !legal_pair(observed[a], observed[b]) {
            return Some(format!(
                "the total is conserved but writer {w}'s pair reads ({}, {}), which is neither \
                 ({START}, {START}) nor ({}, {})",
                observed[a],
                observed[b],
                START - AMOUNT,
                START + AMOUNT
            ));
        }
    }
    None
}

/// What one reader thread recorded.
#[derive(Default)]
struct ReaderOutcome {
    /// Complete scans of all [`ACCOUNTS`] accounts.
    reads: usize,
    /// Snapshots taken while a commit timestamp was **issued but unpublished** — the window itself,
    /// sampled directly. See the module note on how the two clocks make this sound.
    windows: usize,
    /// Scans during which the horizon moved. Reported, never asserted on: it is neither necessary
    /// (a tear can occur with the horizon unchanged across the scan) nor sufficient, and in an
    /// ablated build `snapshot_ts()` is a different clock so the counter means a different thing.
    straddles: usize,
    /// The distinct states of the system this reader observed.
    states: BTreeSet<Vec<i64>>,
    /// Every scan that observed a state no serial schedule could produce.
    tears: usize,
    /// The first few of them, in full.
    transcript: Vec<String>,
}

/// Account `node`'s balance as of `snapshot`, or `0` when the key is not visible.
fn balance_at(
    view: &StoreReadView<MemBlockDevice, MemLogSink>,
    node: u64,
    key: u32,
    snapshot: Snapshot,
) -> i64 {
    view.decision_scan_node_properties(node, snapshot)
        .expect("a snapshot read of a live account must not fail")
        .visible_versions()
        .iter()
        .find(|c| c.key == key)
        .map_or(0, |c| c.value_inline as i64)
}

#[test]
fn a_live_snapshot_never_observes_half_a_commit() {
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

    let stop = Arc::new(AtomicBool::new(false));

    let readers: Vec<_> = (0..READERS)
        .map(|r| {
            let store = Arc::clone(&store);
            let stop = Arc::clone(&stop);
            let nodes = nodes.clone();
            std::thread::spawn(move || {
                let view = store.read_view();
                // The ALLOCATION clock, read-only and public. Paired with the horizon below it is the
                // direct witness of the window (see the module note).
                let clock = store.commit_clock();
                let mut out = ReaderOutcome::default();
                let mut round = 0u64;
                while !stop.load(Ordering::Acquire) {
                    let txn = TxnId(READER_TXN_BASE * (r as u64 + 1) + round);
                    round += 1;
                    // Sampled BEFORE the snapshot, which is what makes the witness sound rather than
                    // merely suggestive: the allocation clock is monotone, so `allocated` is a LOWER
                    // bound on its value at the snapshot instant that follows.
                    let allocated = clock.load(Ordering::Acquire);
                    // THE POINT OF THIS SUITE, through the production door: `begin` yields the
                    // snapshot instant and derives the timestamp itself, exactly as every reader in
                    // the engine does. Nothing hands this reader a timestamp known to be safe, and
                    // the snapshot's owner is this reader's own registered transaction rather than a
                    // borrowed identity.
                    let begin_ts = store.begin(txn);
                    let snapshot = Snapshot::new(txn, begin_ts);
                    let observed: Vec<i64> = nodes
                        .iter()
                        .map(|&node| balance_at(&view, node, key, snapshot))
                        .collect();
                    let after = store.snapshot_ts();
                    store
                        .rollback(txn)
                        .expect("closing a read-only transaction cannot fail");

                    out.reads += 1;
                    // `allocated > begin_ts` says a commit timestamp above this snapshot's horizon
                    // had already been ISSUED when the snapshot was taken — i.e. the snapshot was
                    // taken inside some commit's publication window. That is the window `rmp` #1058
                    // is about, named directly instead of inferred from movement.
                    if allocated > begin_ts.0 {
                        out.windows += 1;
                    }
                    if after != begin_ts {
                        out.straddles += 1;
                    }
                    if let Some(why) = illegal_state(&observed) {
                        out.tears += 1;
                        if out.transcript.len() < REPORT_CAP {
                            // Re-read at the SAME snapshot. A different answer proves the first one
                            // was not a function of the snapshot, which is what a torn read is.
                            let again: Vec<i64> = nodes
                                .iter()
                                .map(|&node| balance_at(&view, node, key, snapshot))
                                .collect();
                            out.transcript.push(format!(
                                "reader {r} at snapshot {} (allocation clock {allocated}, horizon \
                                 {} after the scan): {why}\n  balances {observed:?}, re-read at the \
                                 SAME snapshot {again:?}",
                                begin_ts.0,
                                after.0,
                            ));
                        }
                    }
                    out.states.insert(observed);
                }
                out
            })
        })
        .collect();

    let writers: Vec<_> = (0..WRITERS)
        .map(|w| {
            let store = Arc::clone(&store);
            let nodes = nodes.clone();
            std::thread::spawn(move || {
                let (a, b) = legs(w);
                let mut balance = [START; 2];
                let mut attempt = 0u64;
                let mut retries = 0usize;
                // COUNTED, not assumed. The loop bound below is a constant, so returning it would
                // make the caller's `assert_eq!` on the total true in every run that reaches it —
                // an assertion that can only ever agree with itself. This counter is incremented on
                // the line after `commit` returns `Ok`, so it counts acknowledged transfers.
                let mut committed = 0usize;
                for t in 0..TRANSFERS {
                    // Alternating, so the two balances stay near `START` instead of drifting. The
                    // new balances are computed ONCE, outside the retry loop: a refused attempt
                    // wrote nothing, so it must not move the writer's own model of the accounts.
                    let (from, to) = if t % 2 == 0 { (0, 1) } else { (1, 0) };
                    let mut next = balance;
                    next[from] -= AMOUNT;
                    next[to] += AMOUNT;
                    let mut refusals_here = 0u64;
                    let mut last_refusal: Option<String> = None;
                    loop {
                        assert!(
                            refusals_here < MAX_ATTEMPTS,
                            "writer {w} transfer {t}: refused {MAX_ATTEMPTS} times in a row, so the \
                             horizon is not advancing and this writer can never see its own last \
                             commit. Under `D-published-snapshot-horizon` that is a leaked pending \
                             commit timestamp — the failure mode the decision names — and this \
                             probe fails on it rather than spinning forever. Last refusal: {}",
                            last_refusal.as_deref().unwrap_or("<none recorded>")
                        );
                        // Disjoint id ranges, so no two writers can pick the same transaction id,
                        // and a fresh id per attempt, because a rolled-back id is spent.
                        let txn = TxnId(1_000_000 * (w as u64 + 1) + attempt);
                        attempt += 1;
                        let begin_ts = store.begin(txn);
                        // Two legs, ONE transaction: they commit together or not at all.
                        let written = store
                            .set_node_property_value(txn, nodes[a], key, &Value::Integer(next[0]))
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
                                store.commit(txn).expect("an admitted transfer commits");
                                committed += 1;
                                break;
                            }
                            // RETRIABLE, and expected under `WRITERS > 1`. The accounts are
                            // disjoint, so this is never two writers contending for one entity: it
                            // is `ensure_chain_head_unheld`'s second arm refusing this writer's own
                            // previous commit, whose timestamp is above the horizon because ANOTHER
                            // writer's commit is still pending and holds the published prefix down.
                            // Conservative in the freshness of a snapshot, never in its consistency
                            // — and a serialization failure is the contract's own answer to it, so
                            // the workload does what any client must do and retries.
                            Err(graphus_core::GraphusError::Transaction(why)) => {
                                store.rollback(txn).expect("roll back a refused transfer");
                                retries += 1;
                                refusals_here += 1;
                                last_refusal =
                                    Some(format!("began at {}: {why}", begin_ts.0));
                                // Yield rather than spin: the horizon only advances when another
                                // writer gets to finish publishing.
                                std::thread::yield_now();
                            }
                            Err(e) => {
                                panic!("writer {w} transfer {t}: unexpected store error: {e}")
                            }
                        }
                    }
                    balance = next;
                }
                (committed, retries)
            })
        })
        .collect();

    let mut transfers = 0usize;
    let mut retries = 0usize;
    for writer in writers {
        let (done, refused) = writer.join().expect("a writer thread joins");
        transfers += done;
        retries += refused;
    }
    stop.store(true, Ordering::Release);

    let mut reads = 0usize;
    let mut windows = 0usize;
    let mut straddles = 0usize;
    let mut tears = 0usize;
    let mut states = BTreeSet::new();
    let mut transcript = Vec::new();
    for reader in readers {
        let out = reader.join().expect("a reader thread joins");
        reads += out.reads;
        windows += out.windows;
        straddles += out.straddles;
        tears += out.tears;
        states.extend(out.states);
        transcript.extend(out.transcript);
    }

    // The shape of the run, printed so an ablation is recorded from what happened rather than from
    // what it was expected to do. Visible on failure, and with `--nocapture` on success.
    println!(
        "{transfers} transfers ({retries} refused and retried), {reads} live snapshot reads, \
         {windows} taken inside a publication window, {straddles} straddling a horizon move, \
         {} distinct states observed, {tears} torn",
        states.len()
    );

    assert_eq!(
        tears,
        0,
        "{tears} of {reads} live snapshot reads observed a state no serial schedule could produce — \
         the snapshot timestamp named a commit that had not finished publishing itself (`rmp` \
         #1058):\n{}",
        transcript.join("\n")
    );

    // ---- non-vacuity ----
    assert_eq!(
        transfers,
        WRITERS * TRANSFERS,
        "the writers acknowledged {transfers} transfers, not {} — the readers did not race the full \
         stream",
        WRITERS * TRANSFERS
    );
    assert!(
        reads > WRITERS * TRANSFERS,
        "only {reads} snapshot reads ran against {} transfers — too few to have raced them",
        WRITERS * TRANSFERS
    );
    assert!(
        states.len() > 1,
        "every snapshot read observed the SAME state of the system, so no read was concurrent with \
         a transfer and the conserved total was conserved trivially"
    );
    // THE WINDOW ITSELF. Not "the horizon moved at some point during the scan", which is neither
    // necessary nor sufficient, but "a commit timestamp above this snapshot's horizon had already
    // been issued when the snapshot was taken".
    assert!(
        windows > 0,
        "not one of {reads} snapshots was taken while a commit timestamp sat issued-but-unpublished \
         above its own horizon, so the window `rmp` #1058 is about was never sampled and this run \
         proves nothing about it"
    );
    // And the write side of the same window: a refusal is `ensure_chain_head_unheld` telling a
    // writer that its own last commit is above the horizon, which can only happen while another
    // writer's commit is pending. Zero refusals means the committers never overlapped.
    assert!(
        retries > 0,
        "not one attempt was refused across {transfers} transfers, so no writer ever held a pending \
         commit while another was beginning and the committers never actually overlapped"
    );
}
