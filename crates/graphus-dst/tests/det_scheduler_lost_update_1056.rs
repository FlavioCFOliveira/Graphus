//! **A lost update, reproduced from a seed** (`rmp` #1056, acceptance criterion 2).
//!
//! # What was lost, and how
//!
//! Two writers, one counter, `n = n + 1` each, both acknowledged, one increment applied. That is the
//! cardinal ACID violation, and at `engine_workers = 8` the multi-writer certification gate
//! (`graphus-server`'s `multi_writer_certification_1034`) hit it on 4 runs in 20 — "the shared
//! counters total 114 after 115 acknowledged concurrent increments" — and never at
//! `engine_workers = 1`.
//!
//! Two things had to be true at once, and this file pins both.
//!
//! ## 1. A begin timestamp that named a commit nobody could see
//!
//! `RecordStore::commit_prepare` issues its commit timestamp at the top and publishes the commit
//! afterwards — first the durable `commit.store` slot, then the in-memory `CommitRegistry` entry.
//! `snapshot_ts()` read the *issuing* clock. So a second writer beginning inside that window took a
//! begin timestamp `B` equal to a commit timestamp `C` whose transaction neither oracle would yet
//! admit was committed, read the pre-`C` value of the counter, and computed its increment from it.
//!
//! Every reader in the engine treats `commit_ts <= snapshot.ts` as "visible"
//! (`graphus_txn::visibility::is_visible_via`, `scan_polarity::delta_verdict`), and
//! `SsiTracker::are_concurrent` treats it as "committed before it began" and forms no
//! rw-antidependency edge. All three were reading a timestamp that did not mean what they took it to
//! mean. `RecordStore`'s `CommitSequencer` is what makes it mean that now: the horizon
//! `snapshot_ts()` returns never crosses a commit that has not finished publishing itself.
//!
//! ## 2. A write-write check that only refused an *open* holder
//!
//! `ensure_chain_head_unheld` refused a chain head held by a transaction that was still open, and
//! nothing else — so a head committed at `commit_ts > begin_ts`, which is by definition a version
//! the writer cannot see, was written straight over. The ratified `D-write-conflict-detection`
//! requires the writer to abort unless the head belongs to a transaction that "is neither itself nor
//! committed before its own start timestamp"; that second arm is now implemented.
//!
//! # Why the property is stated as *snapshot honesty*, not just as the counter
//!
//! [`no_transaction_reads_behind_its_own_begin_timestamp`] asserts the contract the whole engine is
//! built on:
//!
//! > if `A` committed at `C` and `B` began at `B.begin_ts >= C`, then `B` observed `A`'s write.
//!
//! That is checkable from what the test itself recorded — every transaction's begin timestamp, the
//! value it observed, and the commit timestamp the store handed back — and it names the offending
//! `(commit_ts, begin_ts)` pair in the failure message, which is the pair `rmp` #1056 measured. The
//! counter oracle ([`no_acknowledged_increment_is_lost`]) is the consequence, and is kept as its own
//! test because it is the shape a user sees.
//!
//! # The layer, deliberately
//!
//! This drives `RecordStore` directly, with **no SSI above it**. At engine level the pre-fix losses
//! were partly masked by the SSI backstop — instrumentation of the #1034 gate found the
//! `commit_ts > begin_ts` shape reaching the write path 100-130 times per run yet **never once**
//! surviving to commit, because the rw-edge formed and the pivot rule aborted it, while the
//! `commit_ts == begin_ts` shape formed no edge at all and survived ~30 times per run. Here there is
//! no backstop to mask anything: `D-write-conflict-detection` is the store's only concurrency
//! control, so this file certifies it on its own terms.
//!
//! # Non-vacuity
//!
//! Asserted on every invocation, not by an experiment somebody once ran:
//!
//! * the scheduler really switched, and both logical writers really ran
//!   ([`the_writers_really_interleave`]);
//! * the equality case is really exercised — some seed of the sweep produces a committed `A` and a
//!   `B` with `A.commit_ts == B.begin_ts` ([`the_equality_case_is_really_reached`]). That
//!   pair is the one #1056 measured; with the fix in place it is legal (`B` did see `A`), and the
//!   point of asserting it is that the run keeps *reaching* it;
//! * the contention is real — the write-write check refuses somebody
//!   ([`the_writers_really_contend`]);
//! * the counter oracle has teeth — the same reconciliation must reject a counter one short of the
//!   one actually read, and the run must have committed something at all
//!   ([`no_acknowledged_increment_is_lost`]'s controls);
//! * the honesty oracle had pairs to rule on — some `(committed A, B)` with `B.begin_ts >=
//!   A.commit_ts` existed ([`no_transaction_reads_behind_its_own_begin_timestamp`]'s control);
//! * something was really refused, so the residue check ruled on a non-empty set
//!   ([`a_refused_transaction_leaves_no_witness`]).
//!
//! # Proof by mutation
//!
//! Each half of the fix withdrawn independently, everything else untouched, `SEEDS` unchanged
//! (measured 2026-08-12):
//!
//! | Withdrawn | [`no_transaction_reads_behind_its_own_begin_timestamp`] | [`no_acknowledged_increment_is_lost`] |
//! |---|---|---|
//! | the `CommitSequencer` — `snapshot_ts()` reads the issuing clock again | **FAILS**, 19 seeds; **every** violation reported `commit_ts == begin_ts` | **FAILS**, 19 of 32 seeds |
//! | the committed-before-my-start arm of `ensure_chain_head_unheld` | passes | **FAILS**, all 32 seeds, 2-5 increments lost each |
//! | nothing (the shipped code) | passes | passes |
//!
//! The middle row is why both halves are needed and neither is sufficient. With the sequencer in
//! place a begin timestamp never names an unpublished commit, so snapshot honesty holds — and a
//! writer can still overwrite a head committed *after* it began, which only the arm refuses. The top
//! row is why the arm could not simply have been added on its own: with a dishonest horizon the arm
//! is asked `head_ts > begin_ts` about a `begin_ts` that already equals `head_ts`, and answers no.
//!
//! # The seam this needed
//!
//! Reaching the window required a yield point at the snapshot itself
//! ([`YieldSite::SnapshotBegin`]). Without it `RecordStore::begin` runs straight through from
//! wherever its thread was last parked, and whether a transaction lands inside another's commit is
//! decided by how many steps happen to separate the two: the first version of this file, before the
//! site existed, came back **clean on all 32 seeds with the sequencer withdrawn** — a by-seed
//! reproduction that reproduced nothing.
//!
//! # Running it
//!
//! ```text
//! cargo test -p graphus-dst --features det-sched --test det_scheduler_lost_update_1056
//! ```

use std::sync::Arc;
use std::sync::Mutex;

use graphus_core::sched::YieldSite;
use graphus_core::{GraphusError, TxnId, Value};
use graphus_dst::detsched::{DetSchedConfig, SchedHistory, run_scheduled};
use graphus_io::MemBlockDevice;
use graphus_storage::{Namespace, RecordStore};
use graphus_txn::Snapshot;
use graphus_wal::{MemLogSink, WalManager};

/// Contending writer threads. Two is the exact arity of the defect — a lost update needs a pair, and
/// a pair is what the failure message has to be able to name.
const WRITERS: usize = 2;

/// Read-modify-write rounds each writer runs. Enough that the seeds differ in *where* they enter the
/// commit-publication window rather than in whether they enter it.
const ROUNDS: u64 = 12;

/// What the counter starts at.
const START: i64 = 0;

/// The seeds this suite pins. A fixed list, not a sample: a seed that reproduces a defect is
/// evidence only if it is still run tomorrow.
const SEEDS: [u64; 32] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
];

/// One read-modify-write round, as the store answered it.
#[derive(Debug, Clone)]
struct Round {
    /// Which writer ran it.
    writer: usize,
    /// Which of that writer's rounds it was — the second half of a witness's identity.
    round: u64,
    /// The begin timestamp the store handed back — this transaction's **start timestamp** in the
    /// sense `D-write-conflict-detection` uses the term.
    begin_ts: u64,
    /// The counter value this transaction observed at that timestamp.
    observed: i64,
    /// The value it wrote (`observed + 1`), meaningful only when [`commit_ts`](Self::commit_ts) is
    /// `Some`.
    written: i64,
    /// The commit timestamp the store assigned, or [`None`] when the write-write check refused the
    /// transaction and it rolled back.
    commit_ts: Option<u64>,
    /// Which `(writer, round)` **witnesses** this transaction observed at its begin timestamp — the
    /// uncontended half of the scenario. A witness is a property key nobody else ever writes, so
    /// whether it is visible is purely a question of visibility and can never be destroyed by another
    /// transaction's write. That is what makes
    /// [`no_transaction_reads_behind_its_own_begin_timestamp`] independent of
    /// [`no_acknowledged_increment_is_lost`]: a lost update cannot make a witness disappear.
    seen: Vec<(usize, u64)>,
}

/// What one scheduled run produced.
struct Run {
    rounds: Vec<Round>,
    /// The counter's value once every writer had finished, read at the store's own horizon.
    final_value: i64,
    /// Every witness present once every writer had finished — the durable trace of who committed.
    final_witnesses: Vec<(usize, u64)>,
    history: SchedHistory,
}

impl Run {
    fn commits(&self) -> usize {
        self.rounds.iter().filter(|r| r.commit_ts.is_some()).count()
    }

    fn aborts(&self) -> usize {
        self.rounds.iter().filter(|r| r.commit_ts.is_none()).count()
    }
}

/// What one snapshot observed of the counter node: the counter's value, and which `(writer, round)`
/// **witnesses** were visible.
///
/// Both come from ONE `decision_scan_node_properties` — one chain walk over one entity at one
/// snapshot — which is what makes the two oracles built on them independent rather than merely
/// separate. Read in two calls they would be two instants, and a witness could be missing for the
/// banal reason that the writer published between them.
///
/// The witness keys live on the **counter node** for exactly that reason. Nobody ever overwrites a
/// witness (its key names its writer and its round), so its visibility is a pure visibility fact; the
/// counter key is the only contended one.
fn read_state(
    store: &RecordStore<MemBlockDevice, MemLogSink>,
    counter: u64,
    key: u32,
    witness_keys: &[Vec<u32>],
    snap: Snapshot,
) -> (i64, Vec<(usize, u64)>) {
    let decided = store
        .decision_scan_node_properties(counter, snap)
        .expect("a snapshot read of the live counter must not fail");
    let mut value = START;
    let mut seen = Vec::new();
    for cand in decided.visible_versions() {
        if cand.key == key {
            value = cand.value_inline as i64;
            continue;
        }
        for (w, keys) in witness_keys.iter().enumerate() {
            if let Some(round) = keys.iter().position(|&k| k == cand.key) {
                seen.push((w, round as u64));
            }
        }
    }
    seen.sort_unstable();
    (value, seen)
}

/// Runs [`WRITERS`] writers, each incrementing one shared counter [`ROUNDS`] times, under a
/// scheduler seeded with `seed`.
fn scenario(seed: u64) -> Run {
    // Switch at EVERY yield point: the window this scenario targets is the handful of steps between
    // a committer issuing its timestamp and publishing its commit, which the amortised default would
    // step straight over.
    let cfg = DetSchedConfig::exhaustive(seed);
    let ((rounds, final_value), history) = run_scheduled(cfg, || {
        let device = MemBlockDevice::new(0);
        let wal = WalManager::create(MemLogSink::new()).expect("create wal");
        let store = Arc::new(RecordStore::create(device, wal, 64, 1).expect("create store"));
        // Interned up front, on the root thread: the catalogue's write lock is not scheduler-mediated,
        // so keeping it out of the concurrent phase keeps the contention where the scenario means it.
        let key = store
            .intern_token(Namespace::PropKey, "n")
            .expect("intern the counter's property key");
        // One witness key per (writer, round), all on the counter node. Distinct keys, so no witness
        // is ever overwritten; same entity, so one chain walk decides the counter and every witness
        // together.
        let witness_keys: Vec<Vec<u32>> = (0..WRITERS)
            .map(|w| {
                (0..ROUNDS)
                    .map(|r| {
                        store
                            .intern_token(Namespace::PropKey, &format!("w{w}_r{r}"))
                            .expect("intern a witness key")
                    })
                    .collect()
            })
            .collect();

        let setup = TxnId(1);
        store.begin(setup);
        let (counter, _) = store.create_node(setup).expect("create the counter node");
        store
            .set_node_property_value(setup, counter, key, &Value::Integer(START))
            .expect("seed the counter");
        store.commit(setup).expect("commit setup");

        let log: Arc<Mutex<Vec<Round>>> = Arc::new(Mutex::new(Vec::new()));
        let handles: Vec<_> = (0..WRITERS)
            .map(|w| {
                let store = Arc::clone(&store);
                let log = Arc::clone(&log);
                let witness_keys = witness_keys.clone();
                graphus_core::sched::spawn(&format!("writer-{w}"), move || {
                    for round in 0..ROUNDS {
                        // Disjoint id ranges, so no two writers can pick the same transaction id.
                        let txn = TxnId(1_000 * (w as u64 + 1) + round);
                        // ONE begin timestamp, taken by the store as it registers the transaction —
                        // the same value `ensure_chain_head_unheld` will measure a committed chain
                        // head against, and the value this scenario's oracle is written in terms of.
                        let begin_ts = store.begin(txn);
                        let snapshot = Snapshot::new(txn, begin_ts);
                        let (observed, seen) =
                            read_state(&store, counter, key, &witness_keys, snapshot);
                        let written = observed + 1;
                        // The witness FIRST, so it is already written when the counter write below
                        // decides the transaction's fate — which is what an abort has to undo, and what
                        // makes a surviving witness a residue rather than a commit.
                        let witness = store
                            .set_node_property_value(
                                txn,
                                counter,
                                witness_keys[w][round as usize],
                                &Value::Integer(1),
                            )
                            .map_err(|e| match e {
                                // The write-write check may refuse the transaction HERE rather than on
                                // the counter write below: both touch the same entity, and the check is
                                // entity-granular. Carry the refusal forward so the round is recorded
                                // as the abort it is.
                                GraphusError::Transaction(_) => e,
                                other => panic!(
                                    "writer {w} round {round}: unexpected store error: {other}"
                                ),
                            });
                        let commit_ts = match witness.and_then(|_| {
                            store.set_node_property_value(
                                txn,
                                counter,
                                key,
                                &Value::Integer(written),
                            )
                        }) {
                            Ok(_prop_id) => {
                                Some(store.commit(txn).expect("an admitted transaction commits"))
                            }
                            // `D-write-conflict-detection` refused us — retriable, immediate, and
                            // exactly what this scenario exists to see happen at the right moments.
                            Err(GraphusError::Transaction(_)) => {
                                store.rollback(txn).expect("roll back a refused writer");
                                None
                            }
                            Err(e) => {
                                panic!("writer {w} round {round}: unexpected store error: {e}")
                            }
                        };
                        log.lock().expect("round log").push(Round {
                            writer: w,
                            round,
                            begin_ts: begin_ts.0,
                            observed,
                            written,
                            commit_ts: commit_ts.map(|ts: graphus_core::Timestamp| ts.0),
                            seen,
                        });
                    }
                })
            })
            .collect();
        for h in handles {
            h.join().expect("a writer thread joins");
        }

        let horizon = store.snapshot_ts();
        let final_snapshot = Snapshot::new(TxnId(u64::MAX), horizon);
        let (final_value, final_witnesses) =
            read_state(&store, counter, key, &witness_keys, final_snapshot);
        let rounds = log.lock().expect("round log").clone();
        (rounds, (final_value, final_witnesses))
    });
    Run {
        rounds,
        final_value: final_value.0,
        final_witnesses: final_value.1,
        history,
    }
}

/// Every `(committed A, B)` pair in which `A.commit_ts <= B.begin_ts` and `B` nevertheless did not
/// observe `A`'s **witness**, plus how many pairs were examined.
///
/// The witness, not the counter: a witness property is written by one transaction and overwritten by
/// nobody, so its absence from a snapshot that claims to include its writer is a pure visibility
/// failure. Reading the counter instead would conflate two different defects — a lost update also
/// makes an earlier write unobservable, by destroying it rather than by hiding it.
fn snapshot_lies(rounds: &[Round]) -> (Vec<String>, usize) {
    let mut out = Vec::new();
    let mut examined = 0usize;
    for (ai, a) in rounds.iter().enumerate() {
        let Some(committed_at) = a.commit_ts else {
            continue;
        };
        let witness = (a.writer, a.round);
        for (bi, b) in rounds.iter().enumerate() {
            if ai == bi || committed_at > b.begin_ts {
                continue;
            }
            examined += 1;
            if b.seen.contains(&witness) {
                continue;
            }
            out.push(format!(
                "writer {} began at {} without observing writer {}'s round {}, which had committed \
                 at {} ({})",
                b.writer,
                b.begin_ts,
                a.writer,
                a.round,
                committed_at,
                if committed_at == b.begin_ts {
                    "commit_ts == begin_ts, the pair `rmp` #1056 measured"
                } else {
                    "commit_ts < begin_ts"
                },
            ));
        }
    }
    (out, examined)
}

/// **The property.** A transaction whose begin timestamp is at or after another transaction's commit
/// timestamp observes that transaction's writes.
///
/// This is the contract every visibility decision in the engine is written against
/// (`ts <= snapshot.ts` is visible) and the one `SsiTracker::are_concurrent` relies on to decide that
/// a rw-antidependency edge is unnecessary. Break it and the two mechanisms that should have caught a
/// lost update both correctly conclude there is nothing to catch.
#[test]
fn no_transaction_reads_behind_its_own_begin_timestamp() {
    let mut lies = Vec::new();
    let mut examined = 0usize;
    for seed in SEEDS {
        let run = scenario(seed);
        let (seed_lies, seed_examined) = snapshot_lies(&run.rounds);
        examined += seed_examined;
        for lie in seed_lies {
            lies.push(format!("seed {seed:#x}: {lie}"));
        }
    }
    // CONTROL: the check must have had pairs to rule on. A run in which no transaction ever began
    // at or after another's commit would satisfy the assertion below by having nothing to test.
    assert!(
        examined > 0,
        "CONTROL FAILED: not one (committed A, B with B.begin_ts >= A.commit_ts) pair existed \
         across {} seeds, so snapshot honesty was never actually tested",
        SEEDS.len()
    );
    assert!(
        lies.is_empty(),
        "a begin timestamp named a commit its own transaction could not see — the commit-visibility \
         horizon crossed a commit that had not finished publishing itself (`rmp` #1056):\n{}",
        lies.join("\n")
    );
}

/// Whether a counter reading of `value` is what `commits` acknowledged increments should have left.
/// The single function both the assertion and its control go through, so both branches of the
/// comparison are exercised on every run.
fn counter_reconciles(value: i64, commits: usize) -> bool {
    value == START + commits as i64
}

/// **The consequence.** Every acknowledged increment is in the counter.
///
/// The shape a user sees, and the oracle the `rmp` #1034 certification gate fails on. It is stated
/// separately from [`no_transaction_reads_behind_its_own_begin_timestamp`] because the two are broken
/// by different halves of the fix: withdrawing the write-write check's committed-before-my-start arm
/// leaves snapshot honesty intact and loses increments anyway.
#[test]
fn no_acknowledged_increment_is_lost() {
    let mut losses = Vec::new();
    for seed in SEEDS {
        let run = scenario(seed);
        let commits = run.commits();
        if !counter_reconciles(run.final_value, commits) {
            let acked: Vec<String> = run
                .rounds
                .iter()
                .filter_map(|r| {
                    r.commit_ts.map(|ts| {
                        format!(
                            "w{} r{} began {} observed {} wrote {} committed {ts}",
                            r.writer, r.round, r.begin_ts, r.observed, r.written
                        )
                    })
                })
                .collect();
            losses.push(format!(
                "seed {seed:#x}: the counter reads {} after {commits} acknowledged increments \
                 ({} lost)\n    {}",
                run.final_value,
                START + commits as i64 - run.final_value,
                acked.join("\n    ")
            ));
        }
        // CONTROL, on the very run the assertion above ruled on, and evaluable whether that run was
        // clean or not: the comparison must reject the counter one short of what it actually read.
        // Without it a scenario in which nothing ever committed would satisfy the oracle vacuously.
        assert!(
            !counter_reconciles(run.final_value - 1, commits),
            "CONTROL FAILED: seed {seed:#x} accepts a counter one short of the {} it read, so \
             this oracle cannot detect a lost update",
            run.final_value
        );
        assert!(
            commits > 0,
            "CONTROL FAILED: seed {seed:#x} committed nothing, so the oracle ruled on an empty run"
        );
    }
    assert!(
        losses.is_empty(),
        "two writers read the same counter value and both committed — a LOST UPDATE (`rmp` \
         #1056):\n{}",
        losses.join("\n")
    );
}

/// **Non-vacuity.** The scheduler really handed the token over, both writers really ran, and the
/// write path was really reached — so the property above was tested against an interleaving rather
/// than against two serial runs.
#[test]
fn the_writers_really_interleave() {
    for seed in SEEDS {
        let run = scenario(seed);
        assert!(
            run.history.switches > 0,
            "seed {seed:#x}: the scheduler never handed the token over, so the run was serial"
        );
        assert!(
            run.history.threads > WRITERS,
            "seed {seed:#x}: only {} logical thread(s) ran, so nothing was interleaved",
            run.history.threads
        );
        assert!(
            run.history.count_site(YieldSite::WriteChainHeadUnheld) > 0,
            "seed {seed:#x}: the write-write check was never reached, so the arm this task \
             implements was never exercised"
        );
        assert_eq!(
            run.rounds.len(),
            WRITERS * ROUNDS as usize,
            "seed {seed:#x}: not every writer completed its rounds"
        );
    }
}

/// **Non-vacuity.** The write-write check refuses somebody: without a refusal the writers never
/// actually contended and the whole scenario would be two independent serial runs wearing a
/// scheduler.
#[test]
fn the_writers_really_contend() {
    let total_aborts: usize = SEEDS.iter().map(|&s| scenario(s).aborts()).sum();
    assert!(
        total_aborts > 0,
        "not one transaction was refused across {} seeds: the writers never contended on the \
         counter, so `D-write-conflict-detection` was never exercised",
        SEEDS.len()
    );
}

/// **Non-vacuity, and the pair by name.** Some seed produces a committed `A` and a committed `B`
/// with `A.commit_ts == B.begin_ts` exactly — the pair every measured lost update of `rmp` #1056
/// had.
///
/// With the fix in place that pair is legal: the horizon only reaches `A.commit_ts` once `A` has
/// finished publishing, so `B` genuinely saw `A` — which
/// [`no_transaction_reads_behind_its_own_begin_timestamp`] independently checks. What this asserts is
/// that the sweep keeps *reaching* the equality, so that check is not being satisfied by never
/// meeting the case.
#[test]
fn the_equality_case_is_really_reached() {
    let mut seeds_with_the_pair = Vec::new();
    for seed in SEEDS {
        let run = scenario(seed);
        let reached = run
            .rounds
            .iter()
            .filter_map(|a| a.commit_ts.map(|ts| (a.writer, ts)))
            .any(|(writer, committed_at)| {
                run.rounds
                    .iter()
                    .any(|b| b.writer != writer && b.begin_ts == committed_at)
            });
        if reached {
            seeds_with_the_pair.push(seed);
        }
    }
    assert!(
        !seeds_with_the_pair.is_empty(),
        "no seed produced a transaction whose begin timestamp equalled another's commit timestamp, \
         so the `commit_ts == begin_ts` case `rmp` #1056 measured was never reached and the \
         snapshot-honesty check never had to rule on it"
    );
}

/// **Determinism.** One seed, two runs, the same recorded history and the same observations — the
/// property that makes a failure above reproducible rather than anecdotal.
#[test]
fn the_same_seed_replays_identically() {
    for seed in [SEEDS[0], SEEDS[15], SEEDS[31]] {
        let a = scenario(seed);
        let b = scenario(seed);
        assert_eq!(
            a.history.steps, b.history.steps,
            "seed {seed:#x}: two runs recorded different scheduling histories"
        );
        assert_eq!(
            a.final_value, b.final_value,
            "seed {seed:#x}: two runs of one seed left the counter at different values"
        );
        let ts_a: Vec<(u64, i64, Option<u64>)> = a
            .rounds
            .iter()
            .map(|r| (r.begin_ts, r.observed, r.commit_ts))
            .collect();
        let ts_b: Vec<(u64, i64, Option<u64>)> = b
            .rounds
            .iter()
            .map(|r| (r.begin_ts, r.observed, r.commit_ts))
            .collect();
        assert_eq!(
            ts_a, ts_b,
            "seed {seed:#x}: two runs of one seed produced different timestamps"
        );
    }
}

/// **No residue.** A transaction the write-write check refused leaves nothing behind.
///
/// Its witness is written **before** the contended counter write that refuses it, so a refusal has
/// real work to undo. A witness that survived a refusal would be a dirty write — the failure the
/// `rmp` #1034 gate calls "a transaction that was refused and left a trace anyway" — and it would
/// also silently break [`no_transaction_reads_behind_its_own_begin_timestamp`]'s premise that a
/// visible witness names a committed transaction.
#[test]
fn a_refused_transaction_leaves_no_witness() {
    let mut residue = Vec::new();
    let mut refusals = 0usize;
    for seed in SEEDS {
        let run = scenario(seed);
        refusals += run.aborts();
        for r in run.rounds.iter().filter(|r| r.commit_ts.is_none()) {
            if run.final_witnesses.contains(&(r.writer, r.round)) {
                residue.push(format!(
                    "seed {seed:#x}: writer {} round {} was REFUSED and its witness is still in \
                     the store",
                    r.writer, r.round
                ));
            }
        }
        // And the converse, on the same run: every acknowledged transaction's witness IS there. A
        // check that only looked for residue would pass on a store that had lost everything.
        for r in run.rounds.iter().filter(|r| r.commit_ts.is_some()) {
            assert!(
                run.final_witnesses.contains(&(r.writer, r.round)),
                "seed {seed:#x}: writer {} round {} was ACKNOWLEDGED and its witness is missing \
                 from the store — a lost commit",
                r.writer,
                r.round
            );
        }
    }
    assert!(
        refusals > 0,
        "CONTROL FAILED: nothing was refused across {} seeds, so this test ruled on an empty set",
        SEEDS.len()
    );
    assert!(
        residue.is_empty(),
        "a refused transaction left a durable trace (`rmp` #1056):\n{}",
        residue.join("\n")
    );
}
