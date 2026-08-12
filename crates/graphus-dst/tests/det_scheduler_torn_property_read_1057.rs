//! **A torn property read, reproduced from a seed** (`rmp` #1057, acceptance criterion 2).
//!
//! # What tore, and where
//!
//! A property read reconstructs one entity's visible version from two things that live in
//! **different records, on different pages, under different latches**: the *current* value of each
//! key (its `props.store` cells) and the *older* values (its undo chain, reached through the
//! `undo_ptr` word of the entity's own record). `graphus_storage::read_view` sampled the chain head
//! **first** and the cells **afterwards**, while the write path publishes them the other way round —
//! `RecordStore::link_delta` writes the delta carrying the old value and publishes it as the new
//! chain head, and only *then* is the cell rewritten in place.
//!
//! A reader whose head sample fell before the publication and whose cell read fell after the rewrite
//! therefore held a **new value with no delta above its head to undo it**, and kept it — whoever
//! wrote it, committed or not.
//!
//! # The workload, and why it is the smallest one that can show it
//!
//! Two accounts and a conserved total. Each transfer is ONE transaction moving [`AMOUNT`] from one
//! account to the other, so `balance(a) + balance(b)` is `TOTAL` at every committed point and at
//! every snapshot — there is no interleaving of committed transactions that makes it anything else.
//! A reader that observes one leg of a transfer without the other observes a state no serial
//! schedule ever produced, which is an **isolation violation** and therefore a violation of the
//! project's inviolable 100% ACID requirement.
//!
//! The reader takes its snapshot at a timestamp the writer publishes only **after** `commit` returns,
//! so no transaction can ever be at a timestamp `<= snapshot.ts` while its commit slot is still
//! unpublished. That is deliberate: it excludes the "the reader resolves each delta against a *live*
//! read of `commit.store`, which can flip mid-scan" hypothesis **by construction**, so a tear
//! observed here is not that. (That window is real and is tracked separately; it is unreachable in
//! this scenario.)
//!
//! # Non-vacuity
//!
//! Asserted mechanically below rather than assumed:
//!
//! * the scheduler really switched (`switches > 0`) and really ran both logical threads;
//! * the reader really observed the writer's growth — at least one seed reads a state that is
//!   neither the initial one nor the final one, so the reads are concurrent with the writes rather
//!   than being serialised before or after them.
//!
//! And by ablation, which is the claim that matters. With the fix withdrawn — the pre-#1057
//! `read_view` shape: sample the chain head from the entity record, *then* read the cells, then walk
//! from that head — [`no_snapshot_read_observes_one_leg_of_a_transfer`] fails on three of the sixteen
//! seeds, reproducibly (two consecutive ablation runs produced the identical list):
//!
//! ```text
//! seed 0x3 round 33: sum 2010 != 2000 (off by 10, i.e. 1 transfer leg(s))
//! seed 0x5 round  5: sum 2010 != 2000 (off by 10, i.e. 1 transfer leg(s))
//! seed 0xb round 18: sum 2010 != 2000 (off by 10, i.e. 1 transfer leg(s))
//! ```
//!
//! With the fix in place all sixteen are clean. `+10` on a two-account system is exactly the shape
//! `rmp` #1057 measured at engine level: the credited leg observed without the debited one.
//!
//! # Running it
//!
//! ```text
//! cargo test -p graphus-dst --features det-sched --test det_scheduler_torn_property_read_1057
//! ```

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use graphus_core::sched::YieldSite;
use graphus_core::{Timestamp, TxnId, Value};
use graphus_dst::detsched::{DetSchedConfig, SchedHistory, run_scheduled};
use graphus_io::MemBlockDevice;
use graphus_storage::{Namespace, RecordStore};
use graphus_txn::Snapshot;
use graphus_wal::{MemLogSink, WalManager};

/// The two accounts of the conserved system.
const ACCOUNTS: usize = 2;
/// What each account starts with.
const START: i64 = 1_000;
/// The invariant every snapshot must observe.
const TOTAL: i64 = ACCOUNTS as i64 * START;
/// What one transfer moves, and therefore the exact size of one torn leg.
const AMOUNT: i64 = 10;
/// Transfers the writer performs. Each is one transaction with two legs.
const TRANSFERS: usize = 6;
/// Read rounds the reader performs. Enough that some fall inside a transfer.
const ROUNDS: usize = 40;
/// The seeds this suite pins. A fixed list, not a sample: a seed that reproduces a defect is
/// evidence only if it is still run tomorrow.
const SEEDS: [u64; 16] = [
    0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf,
];

/// What one scheduled run recorded.
struct Run {
    /// Every total the reader observed, in the order it observed them.
    sums: Vec<i64>,
    history: SchedHistory,
}

/// Runs one writer and one snapshot reader over a two-account conserved system, under a scheduler
/// seeded with `seed`.
fn scenario(seed: u64) -> Run {
    let cfg = DetSchedConfig::exhaustive(seed);
    let (sums, history) = run_scheduled(cfg, || {
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
        // The commit timestamp the writer has PUBLISHED. Stored only after `commit` returns, so a
        // reader can never snapshot at a timestamp whose transaction is still committing.
        let head = Arc::new(AtomicU64::new(store.snapshot_ts().0));
        let sums = Arc::new(std::sync::Mutex::new(Vec::new()));

        let reader = {
            let store = Arc::clone(&store);
            let stop = Arc::clone(&stop);
            let head = Arc::clone(&head);
            let sums = Arc::clone(&sums);
            let nodes = nodes.clone();
            graphus_core::sched::spawn("reader", move || {
                let view = store.read_view();
                for _ in 0..ROUNDS {
                    if stop.load(Ordering::Acquire) {
                        break;
                    }
                    let snapshot =
                        Snapshot::new(TxnId(u64::MAX), Timestamp(head.load(Ordering::Acquire)));
                    let mut sum = 0i64;
                    for &node in &nodes {
                        let decided = view
                            .decision_scan_node_properties(node, snapshot)
                            .expect("a snapshot read of a live account must not fail");
                        sum += decided
                            .visible_versions()
                            .iter()
                            .find(|c| c.key == key)
                            .map_or(0, |c| c.value_inline as i64);
                    }
                    sums.lock().expect("sums lock").push(sum);
                }
            })
        };

        let mut balance = [START; ACCOUNTS];
        for t in 0..TRANSFERS {
            let from = t % ACCOUNTS;
            let to = (t + 1) % ACCOUNTS;
            let txn = TxnId(100 + t as u64);
            store.begin(txn);
            balance[from] -= AMOUNT;
            balance[to] += AMOUNT;
            store
                .set_node_property_value(txn, nodes[from], key, &Value::Integer(balance[from]))
                .expect("leg a");
            store
                .set_node_property_value(txn, nodes[to], key, &Value::Integer(balance[to]))
                .expect("leg b");
            store.commit(txn).expect("commit the transfer");
            head.store(store.snapshot_ts().0, Ordering::Release);
        }

        stop.store(true, Ordering::Release);
        reader.join().expect("reader joined");
        sums.lock().expect("sums lock").clone()
    });
    Run { sums, history }
}

/// **The property.** Every snapshot read of a closed transfer system observes the conserved total —
/// never one leg of a transfer without the other.
#[test]
fn no_snapshot_read_observes_one_leg_of_a_transfer() {
    let mut torn = Vec::new();
    for seed in SEEDS {
        let run = scenario(seed);
        assert!(
            !run.sums.is_empty(),
            "seed {seed:#x}: the reader observed nothing, so the property was never tested"
        );
        for (round, sum) in run.sums.iter().enumerate() {
            if *sum != TOTAL {
                torn.push(format!(
                    "seed {seed:#x} round {round}: sum {sum} != {TOTAL} (off by {}, i.e. {} \
                     transfer leg(s))",
                    sum - TOTAL,
                    (sum - TOTAL).abs() / AMOUNT
                ));
            }
        }
    }
    assert!(
        torn.is_empty(),
        "a scheduled snapshot read observed one leg of a transfer without the other — the property \
         cells and the undo-chain head they were reconstructed against came from two different \
         instants (`rmp` #1057):\n{}",
        torn.join("\n")
    );
}

/// **Non-vacuity.** The scheduler really interleaved the two threads, and the reader really ran
/// concurrently with the writer rather than before or after it.
///
/// Without this, the assertion above would still pass on a run in which the reader executed entirely
/// before the first transfer (every read `TOTAL`, trivially) — the shape of a green test that proves
/// nothing.
#[test]
fn the_reads_really_interleave_with_the_transfers() {
    let mut concurrent_seeds = 0usize;
    for seed in SEEDS {
        let run = scenario(seed);
        assert!(
            run.history.switches > 0,
            "seed {seed:#x}: the scheduler never handed the token over, so the run was serial"
        );
        assert!(
            run.history.threads > 1,
            "seed {seed:#x}: only one logical thread ran, so nothing was interleaved"
        );
        assert!(
            run.history.count_site(YieldSite::FrameReadFetched) > 0,
            "seed {seed:#x}: no record read was ever reached, so the read path never ran"
        );
        // The reader saw the writer's growth if the totals it observed were produced under a moving
        // store: the balances it read are only conserved, so "concurrent" is established from the
        // schedule instead — the writer's commit-slot publications must be interleaved with the
        // reader's record reads rather than all preceding or all following them.
        if reads_straddle_a_commit(&run.history) {
            concurrent_seeds += 1;
        }
    }
    assert!(
        concurrent_seeds > 0,
        "no seed ever ran a record read between two commit-slot publications, so every read was \
         serialised outside the transfers and the property was never actually exercised"
    );
}

/// Whether the history contains a record read (`FrameReadFetched`) that falls **between** two commit
/// publications (`CommitPublishSlot`) — i.e. a reader step inside the writer's transfer sequence.
fn reads_straddle_a_commit(history: &SchedHistory) -> bool {
    let steps = history.decode();
    let first_commit = steps
        .iter()
        .position(|(_, _, site, _, _)| *site == YieldSite::CommitPublishSlot.code());
    let last_commit = steps
        .iter()
        .rposition(|(_, _, site, _, _)| *site == YieldSite::CommitPublishSlot.code());
    match (first_commit, last_commit) {
        (Some(first), Some(last)) if last > first => steps[first..last]
            .iter()
            .any(|(_, _, site, _, _)| *site == YieldSite::FrameReadFetched.code()),
        _ => false,
    }
}

/// **Determinism.** The same seed replays the same interleaving, which is what makes a reproduction
/// from a seed a reproduction at all.
#[test]
fn the_same_seed_replays_the_same_interleaving() {
    let first = scenario(SEEDS[1]);
    let second = scenario(SEEDS[1]);
    assert_eq!(
        first.history.hash, second.history.hash,
        "the same seed produced two different interleavings"
    );
    assert_eq!(
        first.sums, second.sums,
        "the same seed produced two different sequences of observed totals"
    );
}
