//! **N concurrent writers against one database, reproduced deterministically from a seed**
//! (`rmp` #1034, acceptance criterion 4).
//!
//! # The gap this closes
//!
//! `rmp` #973 built the deterministic writer scheduler, and the two engine-level suites that came
//! with it — `det_scheduler_gc_reader_811` and `det_scheduler_elle_oracle` — each drive **one writer
//! and one reader**. The only N-thread scheduled run in the tree was `detsched`'s own `AtomicU32`
//! counter self-test, which is not a database. So the shape #1034 has to certify — *several writers
//! contending on one store* — had never been scheduled at all, and the write-path yield points
//! `rmp` #973 installed said so in their own doc comments: `WriteReadMvcc`, `WriteConflictCheck`,
//! `WriteChainHeadUnheld` and `WriteLinkDelta` were annotated "installed but not yet exercised …
//! whose whole point only exists once `rmp` #975 gives it a second writer to race". This suite is
//! that second writer, and the third, and the fourth.
//!
//! # The workload, and why it contends for real
//!
//! [`WRITERS`] threads share one [`RecordStore`] (`Send + Sync` since `rmp` #337 Slice 2; every write
//! entry point takes `&self` since the `rmp` #971 retirement of the lock table). Each thread runs
//! [`ROUNDS`] rounds, and each round is an **observation** followed by a **write transaction**:
//!
//! 1. **the observation** — a read-only snapshot read of the hot node, taken before the write
//!    transaction begins. It is what the isolation oracle rules on; see below for why it is its own
//!    transaction and not the read half of a read-modify-write.
//! 2. **the disjoint half of the write** — a property on the writer's own private node, which no
//!    other thread ever touches. Without it the scenario would be a pure conflict storm, and it is
//!    also what gives the atomicity check its teeth: this write lands *before* the contended one, so
//!    a transaction that is then refused has something to leave behind if the rollback is not
//!    complete.
//! 3. **the contended half of the write** — a property on the single **hot node** that every writer
//!    targets. Two open transactions writing one node collide on that node's undo-chain head, which
//!    is exactly where `D-write-conflict-detection` puts the check (`specification/
//!    02-decision-register.md`): `ensure_no_conflicting_writer` reads the header, finds the head held
//!    by another open transaction, and returns a **retriable** `GraphusError::Transaction`
//!    immediately. No waiting, no lock table, no deadlock detector — the loser aborts.
//!
//! So committed *and* aborted transactions both appear in every history, and the aborts are produced
//! by the engine's own concurrency control rather than injected.
//!
//! # Which oracle rules on a multi-writer history, and why both
//!
//! The two oracles the project already owns answer different halves of criterion 4, and neither
//! covers the other, so this suite runs both over the same runs:
//!
//! - [`graphus_dst::verify`], the DST invariant checker, compares the **whole final store** against a
//!   reference [`Model`] built from acknowledged commits only. Because the comparison is *equality*,
//!   one pass proves both directions of the criterion: a committed property that is missing is a lost
//!   write, and an aborted transaction's property that is present is residue — both surface as the
//!   same `PropMismatch`. It also re-verifies every mapped page's CRC32C, so a page torn by two
//!   racing writers cannot hide behind a clean logical result. What it cannot see is *ordering*: it
//!   rules on the end state, not on what the transactions observed on the way there.
//! - [`graphus_elle::check`] rules on exactly that, over the observations.
//!
//! ## Why the observation is its own read-only transaction (a premise that fell)
//!
//! The first draft of this suite recorded each round as one Elle transaction shaped
//! `[Read …, Append …]` — the read half and the write half of a read-modify-write. The checker
//! rejected it, and it was right to: at seed `0x2`, transactions `2005` and `4005` produced the cycle
//! `2005 → 4005 → 3004 → 2005` (`2005` read a value `4005` had not yet written, `4005` missed a value
//! `2005` went on to see, and both committed).
//!
//! That is **not** a defect. It is textbook Snapshot Isolation read-write skew, and Snapshot
//! Isolation is precisely what this layer provides: `RecordStore`'s only concurrency control is
//! `D-write-conflict-detection`, the Memgraph `PrepareForWrite` model — first-committer-wins on the
//! *entity header*, which refuses two concurrently **open** writers of one entity and says nothing
//! about a reader whose snapshot predates a commit it later races. Serializability comes from SSI
//! (`crates/graphus-txn/src/ssi.rs`, the SIREAD predicate tracking of `rmp` #171) one layer **above**
//! the record store. Asserting serializability over read-modify-write transactions here would have
//! been asserting a guarantee this layer does not make — a green test today, and a false alarm the
//! first time a legitimate SI interleaving appeared.
//!
//! Recording the observation as its own read-only transaction states only what this layer *does*
//! guarantee, and states it with teeth. Under SI every snapshot is a **prefix of the commit order**,
//! so any two observations are comparable and each can be placed in the total order of the appends.
//! An observation that saw a *non-prefix* — a later commit while an earlier one is missing, a gap
//! inside one writer's list, an uncommitted writer's value, or two observations that cannot both be
//! true — has no such placement, and the checker reports it as a cycle. That is the anomaly class
//! this scheduler exists to hunt: the reader's snapshot is taken while other writers are inside
//! `commit_prepare`, between publishing the durable commit slot and recording the commit in the
//! registry.
//!
//! ## The Elle object model
//!
//! The list-append model the project already uses, mapped so it stays sound under N writers: **one
//! key per writer**, not one key per store node. Within a key the append order is that writer's own
//! program order, so ascending value order *is* append order and the history is self-recoverable.
//! Had every writer appended to a single shared key, recovering the order by sorting would have
//! asserted a total order across threads that no thread ever established — the oracle would have been
//! reading its own assumption back. Values encode their writer ([`encode_value`]), so one snapshot
//! read of the hot node partitions into per-writer lists with no side table; and because it is one
//! read, the multi-key observation is atomic, which is what makes a cross-key inconsistency
//! detectable at all.
//!
//! # What each test asserts
//!
//! | Test | Assertion |
//! |---|---|
//! | [`same_seed_replays_the_multi_writer_run_byte_identically`] | 1 — one seed, two runs, identical history bytes; divergence is reported with its step index |
//! | [`different_seeds_explore_different_multi_writer_interleavings`] | 2 — 8 seeds, 8 distinct histories, every one a genuine [`WRITERS`]-writer run |
//! | [`a_writer_really_steps_inside_another_writers_commit`] | 3 — the multi-writer window is reached: a second writer's step lands *strictly inside* another writer's commit sequence |
//! | [`no_committed_write_is_lost_and_no_abort_leaves_residue`] | 4 — both oracles rule clean on every seed of the sweep |
//! | [`the_write_path_yield_points_are_reached_by_more_than_one_writer`] | the seam is armed on the paths this task exists to schedule, and armed for more than one writer |
//!
//! # Running it
//!
//! ```text
//! cargo test -p graphus-dst --features det-sched --test det_scheduler_multi_writer_1034
//! ```

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use graphus_core::sched::YieldSite;
use graphus_core::{GraphusError, TxnId};
use graphus_dst::detsched::{DetSchedConfig, SchedHistory, run_scheduled};
use graphus_dst::model::PropTriple;
use graphus_dst::{CheckResult, Model, verify};
use graphus_elle::{Op, Transaction, check};
use graphus_io::MemBlockDevice;
use graphus_storage::{Namespace, RecordStore};
use graphus_txn::Snapshot;
use graphus_wal::{MemLogSink, WalManager};

/// Concurrent writer threads. Four clears the "N ≥ 3" bar with a margin, and three-way contention on
/// one header is a materially different shape from two-way: with two writers the loser of a race is
/// always the same transaction, with four the conflict graph has structure.
const WRITERS: usize = 4;

/// Rounds each writer runs. Kept small on purpose — a scheduled run enters the contended window by
/// construction rather than by repetition, so the count only has to be large enough for the seeds to
/// differ in *where* they enter it.
const ROUNDS: u64 = 6;

/// The `type_tag` every property in this scenario carries. Non-zero, so the checker compares it
/// rather than skipping it as an emptied cell.
const TYPE_TAG: u8 = 1;

/// Spacing between writers in the value space. A value therefore names its writer (`value / STRIDE -
/// 1`) and orders that writer's appends by its low digits, which is what lets one read of the hot
/// node be partitioned into per-writer Elle lists with no side table.
const WRITER_STRIDE: u64 = 1_000_000;

/// Offset that keeps an observation's Elle id disjoint from — and far away from — every write
/// transaction's id, so a read can never collide with an append in the checker's dependency graph.
const OBSERVATION_ID_BASE: u64 = 1_000_000;

/// The unique value writer `w` appends in `round`.
fn encode_value(w: usize, round: u64) -> u64 {
    (w as u64 + 1) * WRITER_STRIDE + round + 1
}

/// The writer a value belongs to. Panics on a value this scenario could not have produced, so a
/// decode surprise fails loudly instead of silently mis-partitioning the Elle history.
fn writer_of(value: u64) -> usize {
    let w = (value / WRITER_STRIDE)
        .checked_sub(1)
        .expect("every property in this scenario carries an encoded writer");
    let w = usize::try_from(w).expect("a writer index fits a usize");
    assert!(
        w < WRITERS,
        "value {value} decodes to writer {w}, which is out of range"
    );
    w
}

/// The Elle key holding writer `w`'s append list.
fn elle_key(w: usize) -> String {
    format!("w{w}")
}

/// One round as the writer that ran it observed it: a read-only observation, then a write
/// transaction the engine either acknowledged or refused.
#[derive(Debug, Clone)]
struct Round {
    /// The write transaction's id, unique across all writers.
    id: u64,
    /// Which writer ran it.
    writer: usize,
    /// Whether the engine acknowledged the commit. `false` means the write-write conflict check
    /// refused it and the writer rolled back.
    committed: bool,
    /// The value the write transaction appended (to both its private node and the hot node).
    value: u64,
    /// The property-key token used on the hot node.
    hot_key: u32,
    /// The writer's private node.
    private_node: u64,
    /// The property-key token used on the private node.
    private_key: u32,
    /// What the read-only observation saw on the hot node, partitioned by writer and in append
    /// order. Index `w` is writer `w`'s Elle list.
    observed: Vec<Vec<i64>>,
}

/// What one scheduled run of the scenario produced.
#[derive(Debug)]
struct Run {
    history: SchedHistory,
    rounds: Vec<Round>,
    /// The DST invariant checker's verdict on the final store.
    check: CheckResult,
}

impl Run {
    fn commits(&self) -> usize {
        self.rounds.iter().filter(|r| r.committed).count()
    }

    fn aborts(&self) -> usize {
        self.rounds.iter().filter(|r| !r.committed).count()
    }
}

/// Partitions one snapshot read of the hot node into one ascending Elle list per writer.
fn partition_by_writer(values: impl Iterator<Item = u64>) -> Vec<Vec<i64>> {
    let mut lists = vec![Vec::new(); WRITERS];
    for v in values {
        lists[writer_of(v)].push(v as i64);
    }
    for list in &mut lists {
        // Ascending value order IS append order within one writer's key: that writer's transactions
        // are sequential and its values increase with the round.
        list.sort_unstable();
    }
    lists
}

/// Runs [`WRITERS`] contending writer threads over one store under a scheduler seeded with `seed`.
fn scenario(seed: u64) -> Run {
    // Switch at EVERY yield point. The windows this scenario targets — one writer's commit sequence,
    // and the gap between the conflict check and the chain-head republication — are a handful of
    // steps wide, so the amortised default would step over them.
    let cfg = DetSchedConfig::exhaustive(seed);
    let ((rounds, check), history) = run_scheduled(cfg, || {
        let device = MemBlockDevice::new(0);
        let wal = WalManager::create(MemLogSink::new()).expect("create wal");
        // 64 frames, as the sibling scheduled suites use: small enough that eviction is live and the
        // victim-selection path is genuinely exercised rather than idling behind an oversized pool.
        let store = Arc::new(RecordStore::create(device, wal, 64, 1).expect("create store"));

        // Every token is interned up front, on the root thread. Interning takes the catalogue's write
        // lock, which the scheduler does not mediate; keeping it out of the concurrent phase keeps the
        // run's contention where the scenario means it to be.
        let intern = |prefix: &str| -> Vec<Vec<u32>> {
            (0..WRITERS)
                .map(|w| {
                    (0..ROUNDS)
                        .map(|r| {
                            store
                                .intern_token(Namespace::PropKey, &format!("{prefix}_{w}_{r}"))
                                .expect("intern a property key")
                        })
                        .collect()
                })
                .collect()
        };
        let hot_keys = intern("hot");
        let private_keys = intern("own");

        // The shared object every writer collides on, plus one uncontended node per writer.
        let setup = TxnId(1);
        store.begin(setup);
        let (hot, _) = store.create_node(setup).expect("create the hot node");
        let private: Vec<u64> = (0..WRITERS)
            .map(|_| store.create_node(setup).expect("create a private node").0)
            .collect();
        store.commit(setup).expect("commit setup");

        let handles: Vec<_> = (0..WRITERS)
            .map(|w| {
                let store = Arc::clone(&store);
                let hot_keys = hot_keys[w].clone();
                let private_keys = private_keys[w].clone();
                let private_node = private[w];
                graphus_core::sched::spawn(&format!("writer-{w}"), move || {
                    let mut rounds = Vec::with_capacity(ROUNDS as usize);
                    for round in 0..ROUNDS {
                        // Disjoint id ranges, so no two writers can pick the same transaction id.
                        let id = 1_000 * (w as u64 + 1) + round;
                        let txn = TxnId(id);
                        let value = encode_value(w, round);

                        // ---- the observation: a read-only transaction of its own ----
                        //
                        // Taken BEFORE the write transaction begins and under a reader id no write is
                        // ever attributed to, so it is a genuine snapshot read and not the read half
                        // of a read-modify-write. See the module doc for why that distinction is what
                        // makes the isolation verdict mean something at this layer.
                        let snapshot = Snapshot::new(TxnId(u64::MAX), store.snapshot_ts());
                        let decided = store
                            .decision_scan_node_properties(hot, snapshot)
                            .expect("a snapshot read of the live hot node must not fail");
                        let observed = partition_by_writer(
                            decided.visible_versions().iter().map(|c| c.value_inline),
                        );

                        // ---- the write transaction ----
                        store.begin(txn);

                        // 1. The disjoint half. Nobody else writes this node, so it cannot conflict —
                        //    and it is already in progress when the contended write below decides the
                        //    transaction's fate, which is what an abort has to undo.
                        store
                            .add_node_property(
                                txn,
                                private_node,
                                private_keys[round as usize],
                                TYPE_TAG,
                                value,
                            )
                            .expect("INVARIANT: a writer's private node has no other writer");

                        // 2. The contended half.
                        let committed = match store.add_node_property(
                            txn,
                            hot,
                            hot_keys[round as usize],
                            TYPE_TAG,
                            value,
                        ) {
                            Ok(_) => {
                                store
                                    .commit(txn)
                                    .expect("commit an uncontended transaction");
                                true
                            }
                            // The engine's own concurrency control refused us: another open
                            // transaction holds the hot node's chain head. Retriable, immediate, and
                            // the whole point of the scenario.
                            Err(GraphusError::Transaction(_)) => {
                                store
                                    .rollback(txn)
                                    .expect("roll a refused transaction back");
                                false
                            }
                            Err(other) => {
                                panic!("unexpected storage error on the contended write: {other:?}")
                            }
                        };

                        rounds.push(Round {
                            id,
                            writer: w,
                            committed,
                            value,
                            hot_key: hot_keys[round as usize],
                            private_node,
                            private_key: private_keys[round as usize],
                            observed,
                        });
                    }
                    rounds
                })
            })
            .collect();

        let mut rounds: Vec<Round> = Vec::new();
        for h in handles {
            rounds.extend(h.join().expect("writer thread joined"));
        }
        // A stable order for the reference model and the Elle history: the scheduler decides the
        // interleaving, not the bookkeeping.
        rounds.sort_unstable_by_key(|r| r.id);

        // The reference model holds ONLY acknowledged commits. Order is irrelevant here because every
        // committed write uses a property key no other transaction touches, so the model is the union
        // of the acknowledged effects however they interleaved.
        let mut model = Model::new();
        model.add_node(hot);
        for &n in &private {
            model.add_node(n);
        }
        for r in rounds.iter().filter(|r| r.committed) {
            model.add_node_prop(
                hot,
                PropTriple {
                    key: r.hot_key,
                    type_tag: TYPE_TAG,
                    value_inline: r.value,
                },
            );
            model.add_node_prop(
                r.private_node,
                PropTriple {
                    key: r.private_key,
                    type_tag: TYPE_TAG,
                    value_inline: r.value,
                },
            );
        }

        // "Present and readable AFTERWARDS": a sharp checkpoint flushes every dirty page home and
        // syncs the device, so the checker's page-checksum pass reads what the concurrent writers
        // actually left on disk rather than what the buffer pool still happens to hold.
        store.checkpoint().expect("checkpoint the store");

        let check = verify(&store, &model);
        (rounds, check)
    });
    Run {
        history,
        rounds,
        check,
    }
}

/// The Elle history for a run: each round's read-only observation of every writer's list, and each
/// round's append carrying the engine's committed / aborted verdict.
fn elle_history(run: &Run) -> Vec<Transaction> {
    let mut history = Vec::with_capacity(run.rounds.len() * 2);
    for r in &run.rounds {
        // The observation. A read-only snapshot always "commits"; there is nothing for it to abort.
        history.push(Transaction::committed(
            OBSERVATION_ID_BASE + r.id,
            (0..WRITERS)
                .map(|w| Op::Read {
                    key: elle_key(w),
                    observed: r.observed[w].clone(),
                })
                .collect(),
        ));
        // The append.
        let ops = vec![Op::Append {
            key: elle_key(r.writer),
            val: r.value as i64,
        }];
        history.push(if r.committed {
            Transaction::committed(r.id, ops)
        } else {
            Transaction::aborted(r.id, ops)
        });
    }
    history
}

/// The logical threads that are writers, taken from the history rather than assumed: only a spawned
/// child records [`YieldSite::ThreadStart`], so the root — which does the setup and the verification
/// — is excluded by construction.
fn writer_threads(history: &SchedHistory) -> BTreeSet<u32> {
    history
        .decode()
        .into_iter()
        .filter(|(_, _, site, _, _)| *site == YieldSite::ThreadStart.code())
        .map(|(_, thread, _, _, _)| thread)
        .collect()
}

/// Whether `site` is one of the three steps `RecordStore::commit_prepare` takes, and which one — in
/// the order it takes them.
fn commit_step(site: u16) -> Option<u8> {
    match site {
        s if s == YieldSite::CommitPublishSlot.code() => Some(0),
        s if s == YieldSite::CommitRegistryRecord.code() => Some(1),
        s if s == YieldSite::CommitSettle.code() => Some(2),
        _ => None,
    }
}

/// Finds a step by one writer that landed **strictly inside** another writer's commit sequence, and
/// describes it.
///
/// This is the teeth of the whole suite. "Zero lost writes" is trivially true of a run in which the
/// writers happened to take their turns one after another, so the oracles' clean verdicts are worth
/// nothing without proof that the transactions really overlapped at the one place where overlapping
/// is hardest: between publishing a durable commit slot and recording that commit in the registry —
/// the instant a commit becomes visible.
///
/// "Strictly inside" is taken literally: the bracket must be two *consecutive* steps of one commit
/// (`CommitPublishSlot` → `CommitRegistryRecord`, or `CommitRegistryRecord` → `CommitSettle`), never
/// the gap between one transaction's last commit step and the next transaction's first, which would
/// merely say the writer paused between transactions.
fn writer_inside_another_writers_commit(history: &SchedHistory) -> Option<String> {
    let steps = history.decode();
    let writers = writer_threads(history);
    // Per writer thread: the index and the ordinal of its most recent commit-path step.
    let mut last: BTreeMap<u32, (usize, u8)> = BTreeMap::new();

    for (i, (_, thread, site, _, _)) in steps.iter().enumerate() {
        if !writers.contains(thread) {
            continue;
        }
        let Some(ordinal) = commit_step(*site) else {
            continue;
        };
        if let Some(&(prev_i, prev_ordinal)) = last.get(thread)
            && prev_ordinal + 1 == ordinal
            && let Some(k) =
                (prev_i + 1..i).find(|&k| steps[k].1 != *thread && writers.contains(&steps[k].1))
        {
            return Some(format!(
                "writer thread {} ran step {} (site {}) inside writer thread {}'s commit, between \
                 its steps {} and {} (commit ordinals {} → {})",
                steps[k].1, k, steps[k].2, thread, prev_i, i, prev_ordinal, ordinal
            ));
        }
        last.insert(*thread, (i, ordinal));
    }
    None
}

/// Every assertion below rests on the run having been a genuine multi-writer run. Checked once, in
/// one place, so no individual test can pass on a degenerate history.
fn assert_multi_writer(seed: u64, run: &Run) {
    assert_eq!(
        run.history.threads,
        WRITERS + 1,
        "seed {seed:#x}: the history holds {} thread(s); it must hold the root plus all {WRITERS} \
         writers",
        run.history.threads
    );
    assert_eq!(
        writer_threads(&run.history).len(),
        WRITERS,
        "seed {seed:#x}: not every writer thread reached its body"
    );
    assert!(
        run.history.switches >= 100,
        "seed {seed:#x}: only {} context switches — the run barely interleaved",
        run.history.switches
    );
    assert_eq!(
        run.rounds.len(),
        WRITERS * ROUNDS as usize,
        "seed {seed:#x}: a writer did not run every round"
    );
    // Both outcomes must be present, or half the criterion is untested.
    assert!(
        run.commits() > 0,
        "seed {seed:#x}: every transaction was refused — nothing committed, so 'no committed write \
         is lost' is vacuous"
    );
    assert!(
        run.aborts() > 0,
        "seed {seed:#x}: nothing was ever refused, so the write-write conflict check never fired \
         and 'an abort leaves no residue' is vacuous"
    );
    // The conflict check must have been reached on the write path, not merely inferred from the
    // aborts.
    assert!(
        run.history.count_site(YieldSite::WriteConflictCheck) > 0,
        "seed {seed:#x}: the write-write conflict check was never reached"
    );
}

/// **Assertion 1** — the same seed replays the whole multi-writer run byte for byte.
///
/// Compared on the raw fixed-width history records rather than on the digest, so a divergence is
/// located, not merely detected.
#[test]
fn same_seed_replays_the_multi_writer_run_byte_identically() {
    const SEED: u64 = 0x1034_0973;

    let first = scenario(SEED);
    let second = scenario(SEED);

    assert_eq!(
        first.history.bytes.len(),
        second.history.bytes.len(),
        "the same seed produced histories of different length ({} vs {} steps)",
        first.history.steps,
        second.history.steps
    );
    if first.history.bytes != second.history.bytes {
        let a = first.history.decode();
        let b = second.history.decode();
        let at = a
            .iter()
            .zip(&b)
            .position(|(x, y)| x != y)
            .expect("lengths are equal, so a difference must have an index");
        panic!(
            "the same seed diverged at step {at}: {:?} vs {:?}",
            a[at], b[at]
        );
    }
    assert_eq!(first.history.hash, second.history.hash);

    // The engine's outcome replays too, not just the schedule: the same transactions committed, the
    // same ones were refused, and every observation saw the same thing.
    let outcomes = |r: &Run| -> Vec<(u64, bool, Vec<Vec<i64>>)> {
        r.rounds
            .iter()
            .map(|x| (x.id, x.committed, x.observed.clone()))
            .collect()
    };
    assert_eq!(
        outcomes(&first),
        outcomes(&second),
        "the schedule replayed but the engine's own outcome did not"
    );

    assert_multi_writer(SEED, &first);
}

/// **Assertion 2** — different seeds explore different interleavings, and every one of them is a
/// genuine [`WRITERS`]-writer run.
///
/// A **fixed** set of constant seeds, asserted for full distinctness: there is no sampling, so there
/// is nothing to be flaky about.
#[test]
fn different_seeds_explore_different_multi_writer_interleavings() {
    const SEEDS: [u64; 8] = [1, 7, 42, 1234, 0xDEAD, 0xBEEF, 0x1034, 0x975];

    let runs: Vec<Run> = SEEDS.iter().map(|s| scenario(*s)).collect();
    let mut hashes: Vec<u64> = runs.iter().map(|r| r.history.hash).collect();
    hashes.sort_unstable();
    hashes.dedup();
    assert_eq!(
        hashes.len(),
        SEEDS.len(),
        "different seeds collapsed onto the same interleaving — the scheduler is not exploring"
    );

    for (seed, run) in SEEDS.iter().zip(&runs) {
        assert_multi_writer(*seed, run);
    }
}

/// **Assertion 3** — the multi-writer window is actually reached.
///
/// Not "the threads existed" and not "the history hashes differ", but: a second writer's step landed
/// *strictly inside* another writer's commit sequence. See
/// [`writer_inside_another_writers_commit`] for why that bracket and no other.
#[test]
fn a_writer_really_steps_inside_another_writers_commit() {
    const SEEDS: [u64; 6] = [3, 11, 0x1034, 0x975, 20_260_811, 0xC0FFEE];

    for seed in SEEDS {
        let run = scenario(seed);
        assert_multi_writer(seed, &run);

        // All three commit steps must be present, or the bracket could not exist to be found.
        for site in [
            YieldSite::CommitPublishSlot,
            YieldSite::CommitRegistryRecord,
            YieldSite::CommitSettle,
        ] {
            assert!(
                run.history.count_site(site) > 0,
                "seed {seed:#x}: {site:?} was never reached, so no commit sequence ran"
            );
        }

        assert!(
            writer_inside_another_writers_commit(&run.history).is_some(),
            "seed {seed:#x}: no writer's step ever landed inside another writer's commit sequence. \
             The writers took turns instead of overlapping, so every clean verdict in this suite \
             would be vacuous. ({} steps, {} switches, {} commits, {} aborts)",
            run.history.steps,
            run.history.switches,
            run.commits(),
            run.aborts()
        );
    }
}

/// **Assertion 4** — the outcome is correct on every seed.
///
/// Both oracles, over the same runs: the DST invariant checker on the final store (no committed write
/// lost, no aborted write left behind, every page still checksum-clean) and the Elle isolation
/// checker on the recorded observations (every snapshot is a prefix of the commit order).
#[test]
fn no_committed_write_is_lost_and_no_abort_leaves_residue() {
    const SEEDS: [u64; 8] = [2, 13, 0x1034, 0x975, 0x811, 20_260_811, 0xC0FFEE, 0xFEED];

    for seed in SEEDS {
        let run = scenario(seed);
        assert_multi_writer(seed, &run);

        // --- Durability + atomicity + integrity, over the whole store. ---
        if let Err(failure) = &run.check {
            panic!(
                "seed {seed:#x}: the DST invariant checker rejected the final store after {} \
                 committed and {} refused transactions across {WRITERS} writers: {failure}. Replay \
                 this exact interleaving with seed {seed:#x}.",
                run.commits(),
                run.aborts()
            );
        }

        // --- Isolation, over the recorded observations. ---
        let history = elle_history(&run);

        // The verdict must have something to rule on. An observation that saw nothing, and one that
        // saw the finished list, both cost the checker no constraint at all: the teeth are the
        // observations that caught the lists mid-growth.
        let total_appends = run.commits();
        let partial = run.rounds.iter().any(|r| {
            let seen: usize = r.observed.iter().map(Vec::len).sum();
            seen > 0 && seen < total_appends
        });
        assert!(
            partial,
            "seed {seed:#x}: no observation ever caught the hot node mid-growth, so the isolation \
             verdict is vacuous"
        );
        // And at least one observation must have crossed a writer boundary — seen another writer's
        // append — or the history holds no cross-writer dependency and is really N independent
        // single-writer ones.
        let cross_writer = run.rounds.iter().any(|r| {
            (0..WRITERS)
                .filter(|&w| w != r.writer)
                .any(|w| !r.observed[w].is_empty())
        });
        assert!(
            cross_writer,
            "seed {seed:#x}: every observation only ever saw its own writer's appends, so the \
             history holds no cross-writer dependency for the checker to rule on"
        );

        let verdict = check(&history);
        assert!(
            verdict.serializable,
            "seed {seed:#x}: the isolation oracle rejected a scheduled multi-writer history — some \
             observation saw a non-prefix of the commit order: {:?}",
            verdict.anomaly
        );
    }
}

/// The write-path yield points `rmp` #973 installed and left unexercised must all be reached now, and
/// reached by more than one writer.
///
/// Without this, every assertion above could hold in a run where the seam compiled to nothing on
/// exactly the paths this task exists to schedule.
#[test]
fn the_write_path_yield_points_are_reached_by_more_than_one_writer() {
    let run = scenario(0x1034);
    let writers = writer_threads(&run.history);
    let steps = run.history.decode();

    for site in [
        YieldSite::WriteReadMvcc,
        YieldSite::WriteConflictCheck,
        YieldSite::WriteChainHeadUnheld,
        YieldSite::WriteLinkDelta,
        YieldSite::UndoChainHeadPublish,
        YieldSite::CommitPublishSlot,
        YieldSite::CommitRegistryRecord,
        YieldSite::CommitSettle,
    ] {
        let reached: BTreeSet<u32> = steps
            .iter()
            .filter(|(_, thread, s, _, _)| *s == site.code() && writers.contains(thread))
            .map(|(_, thread, _, _, _)| *thread)
            .collect();
        assert!(
            reached.len() > 1,
            "{site:?} was reached by {} writer thread(s). A write-path yield point that only ever \
             sees one writer proves nothing about writer-versus-writer scheduling — which is the \
             whole subject of this suite.",
            reached.len()
        );
    }
}
