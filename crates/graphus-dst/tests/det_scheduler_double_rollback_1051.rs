//! **`rmp` #1051 — two threads inside one transaction's rollback, reproduced from a seed.**
//!
//! # The window
//!
//! A logical rollback (`RecordStore::rollback_logical`, `rmp` #970) reads the transaction's delta
//! list, applies each delta against the current state, detaches the deltas from the chains they are
//! on and frees them together with the transaction's commit slot. Every step of that assumes one
//! thing about the world: **this transaction is being undone by exactly one thread**. It is not
//! re-entrant and it is not idempotent — the first pass detaches and frees, and a second pass over
//! the same delta list finds a chain those deltas have already left.
//!
//! The store states that assumption as a fail-closed tripwire rather than trusting it. A rollback
//! that reaches a delta it did not detach refuses:
//!
//! ```text
//! rollback of transaction N: delta D on Node X is not on the head prefix of its chain,
//! so detaching it would splice a live chain (`05 §12.2`)
//! ```
//!
//! and by the `rmp` #955 contract the refusal leaves the transaction **open** — its active-set entry
//! is released only once every fallible step has succeeded — so the caller must take the database to
//! its degraded state rather than serve over a half-undone transaction.
//!
//! # Why this scenario exists
//!
//! Because that tripwire fired in production shape, and until `rmp` #1051 nothing in the tree could
//! reproduce it. At `engine_workers = 8` the SSI commit path aborted a **foreign** transaction — the
//! Case-B pivot, running on another worker — from the committing worker's thread, while that
//! transaction's own worker was aborting it too. Two threads, one `rollback_logical`, and the
//! measured consequence was 476 of 480 requests answered "engine degraded". The cause is fixed one
//! layer up (`graphus_txn::SsiTracker::doom` and
//! `graphus_cypher::TxnCoordinator::break_dangerous_structure`): a victim is now **condemned** and
//! aborts itself, on its own worker, and no thread ever undoes a transaction that is not its own.
//!
//! This file is the other half — the store's own last line of defence, exercised deliberately. It
//! drives the forbidden state on purpose and asserts the store refuses it rather than splicing a live
//! chain and freeing a slot that is still threaded (`rmp` #578 in reverse). It is what keeps the
//! tripwire from decaying into a comment: delete the tripwire and this file fails.
//!
//! # Non-vacuity
//!
//! Two threads calling `rollback` need not collide: if the scheduler runs one to completion first,
//! the second finds no commit slot and takes the physical path, which is a clean no-op. That outcome
//! proves nothing, so the sweep **asserts the window is genuinely entered** — at least one seed must
//! reach the head-prefix refusal — before it asserts anything about what the refusal leaves behind.
//!
//! # Running it
//!
//! ```text
//! cargo test -p graphus-dst --features det-sched --test det_scheduler_double_rollback_1051
//! ```

use std::sync::Arc;

use graphus_core::TxnId;
use graphus_dst::detsched::{DetSchedConfig, run_scheduled};
use graphus_io::MemBlockDevice;
use graphus_storage::{Namespace, RecordStore};
use graphus_wal::{MemLogSink, WalManager};

/// Seeds swept. Small: the window is a handful of steps wide and an exhaustive-switch scheduler
/// enters it by construction rather than by repetition, so the sweep only has to vary *where*.
const SEEDS: u64 = 24;

/// The `type_tag` the scenario's one property carries. Non-zero, so it is a real value rather than
/// an emptied cell.
const TYPE_TAG: u8 = 1;

/// What one scheduled run of the forbidden state produced.
#[derive(Debug)]
struct Run {
    /// The two rollbacks' outcomes, in thread order: `Ok(())`, or the error text.
    outcomes: [Result<(), String>; 2],
    /// The violations the read-only consistency pass found on the store afterwards. Empty is the
    /// assertion; the field carries them so a failure names them.
    violations: Vec<String>,
}

impl Run {
    /// Whether either thread hit the head-prefix tripwire — i.e. the two rollbacks really did
    /// overlap inside one delta list, and the *detach* phase was the one that caught it.
    fn hit_the_tripwire(&self) -> bool {
        self.outcomes.iter().any(|o| {
            o.as_ref()
                .err()
                .is_some_and(|e| e.contains("is not on the head prefix of its chain"))
        })
    }
}

/// Runs one transaction and two concurrent rollbacks of it, under a scheduler seeded with `seed`.
fn scenario(seed: u64) -> Run {
    // Switch at EVERY yield point: the overlap this targets spans the few steps between one
    // rollback's chain walk and the other's detach-and-free, which the amortised default steps over.
    let cfg = DetSchedConfig::exhaustive(seed);
    let (run, _history) = run_scheduled(cfg, || {
        let device = MemBlockDevice::new(0);
        let wal = WalManager::create(MemLogSink::new()).expect("create wal");
        let store = Arc::new(RecordStore::create(device, wal, 64, 1).expect("create store"));

        // Interning takes the catalogue's write lock, which the scheduler does not mediate. Done on
        // the root thread, so the run's contention is only where the scenario means it to be.
        let key = store
            .intern_token(Namespace::PropKey, "p")
            .expect("intern a property key");

        let setup = TxnId(1);
        store.begin(setup);
        let (node, _) = store.create_node(setup).expect("create the node");
        store
            .add_node_property(setup, node, key, TYPE_TAG, 7)
            .expect("seed a property so the node is a realistic record");
        store.commit(setup).expect("commit setup");

        // The victim: one open transaction holding one linked delta on `node`. One delta is enough —
        // the tripwire is about whether a delta is where its owner left it, not about how many.
        //
        // A DELETION, deliberately, and this is the one non-obvious choice in the file. A logical
        // rollback runs in two phases — APPLY the transaction's own deltas, then DETACH them — and
        // both are fail-closed against a second thread. The head-prefix tripwire lives in the
        // *detach* phase, so a second rollback only reaches it if it survives the apply phase, and a
        // property write does not survive it: `undo_own_property` restores a cell from the delta's
        // recorded old value and refuses the moment the first thread has already put it back
        // ("property chain of Node N does not contain cell C"). A deletion's undo is
        // `undo_own_deletion` — it clears the tombstone stamp, which is an absolute write and
        // therefore idempotent — so both threads get through the apply phase and the detach phase is
        // reached by both. Same forbidden state, aimed at the assertion this file is about.
        let victim = TxnId(2);
        store.begin(victim);
        store
            .delete_node(victim, node)
            .expect("the victim's delete has no competing writer");

        // THE FORBIDDEN STATE, on purpose. This is the shape the SSI Case-B abort produced before
        // `rmp` #1051: the transaction's own worker and a stranger, both undoing it.
        let owner = {
            let store = Arc::clone(&store);
            graphus_core::sched::spawn("owner", move || store.rollback(victim))
        };
        let stranger = {
            let store = Arc::clone(&store);
            graphus_core::sched::spawn("stranger", move || store.rollback(victim))
        };
        let outcomes = [
            owner.join().expect("the owner thread joins"),
            stranger.join().expect("the stranger thread joins"),
        ]
        .map(|r| r.map_err(|e| e.to_string()));

        let violations = graphus_storage::check::check_store(&store, &[])
            .expect("the read-only consistency pass runs")
            .violations
            .iter()
            .map(|v| format!("{v:?}"))
            .collect();
        Run {
            outcomes,
            violations,
        }
    });
    run
}

/// **The tripwire has teeth, and refusing bounds the damage.**
///
/// Two assertions over the sweep, and the first is what licenses the second:
///
/// 1. **The window is entered, and the detach phase is what catches it.** At least one seed must
///    reach the *head-prefix* refusal by name. Without this the test would pass on a sweep in which
///    the scheduler serialised every pair (the second rollback then finds no commit slot and takes
///    the physical no-op path) — an assertion about a state that never occurred. It also pins the
///    phase: the apply phase has fail-closed guards of its own, and a sweep that only ever tripped
///    *those* would leave this file certifying somebody else's tripwire.
/// 2. **The store is intact afterwards, on every seed.** The read-only consistency pass — which
///    walks the free lists, the property chains, the incidence chains and the undo area — finds
///    nothing. That is the tripwire's actual claim, checked rather than asserted in prose: rather
///    than free a slot that is still threaded and splice a live chain (`rmp` #578 in reverse), the
///    second rollback returned an error and touched nothing.
///
/// Deliberately NOT asserted: that the transaction is still open afterwards. It is not, and it
/// should not be — the *other* thread's rollback completed and released the bookkeeping, which is
/// correct. The `rmp` #955 "a failed undo leaves the transaction open" contract is a statement about
/// one invocation, and this scenario runs two.
#[test]
fn a_concurrent_second_rollback_of_one_transaction_is_refused_fail_closed() {
    let runs: Vec<Run> = (0..SEEDS).map(scenario).collect();

    let entered: Vec<u64> = (0..SEEDS)
        .filter(|&s| runs[s as usize].hit_the_tripwire())
        .collect();
    assert!(
        !entered.is_empty(),
        "NON-VACUITY: no seed in 0..{SEEDS} reached the head-prefix refusal, so nothing below \
         asserts anything about that tripwire. Outcomes: {:?}",
        runs.iter().map(|r| &r.outcomes).collect::<Vec<_>>()
    );
    println!(
        "rmp #1051: the head-prefix tripwire fired on {} of {SEEDS} seeds {entered:?}",
        entered.len()
    );

    for (seed, run) in runs.iter().enumerate() {
        assert!(
            run.violations.is_empty(),
            "seed {seed}: the store is inconsistent after two concurrent rollbacks of one \
             transaction — the refusal did not bound the damage. Outcomes: {:?}. Violations: {:?}",
            run.outcomes,
            run.violations
        );
    }
}

// =================================================================================================
// The cause, reproduced from a seed: two workers committing, one SSI victim between them.
// =================================================================================================

/// What one scheduled run of the two concurrent commits produced.
#[derive(Debug, PartialEq, Eq)]
struct CommitRun {
    /// `Ok(())`, a retriable `Transaction` refusal, or a `Storage` FAULT — which is the thing under
    /// test, because a storage fault here means a rollback ran that should never have run.
    outcomes: [Result<(), String>; 2],
    faults: Vec<String>,
}

/// Builds `Tin --rw--> Tpivot --rw--> Tout` over a real [`TxnCoordinator`], then commits `Tout` and
/// `Tpivot` on **two scheduled threads at once**, seeded with `seed`.
///
/// That pair is the exact production shape `rmp` #1051 was found in: `Tout`'s commit resolves the
/// dangerous structure by naming `Tpivot`, while `Tpivot`'s own commit resolves it by naming itself.
/// Before the fix both threads then ran `Tpivot`'s undo, and the store faulted; now only `Tpivot`'s
/// own thread does, because `Tout` merely condemns it.
fn commit_scenario(seed: u64) -> CommitRun {
    use graphus_cypher::coordinator::TxnCoordinator;
    use graphus_cypher::graph_access::{GraphAccess, NodeId};

    let cfg = DetSchedConfig::exhaustive(seed);
    let (run, _history) = run_scheduled(cfg, || {
        let device = MemBlockDevice::new(0);
        let wal = WalManager::create(MemLogSink::new()).expect("create wal");
        let store = RecordStore::create(device, wal, 64, 1).expect("create store");
        let coord = Arc::new(TxnCoordinator::new(store));

        // Two committed nodes, read and written by physical id: every SIREAD marker below is a
        // single-record one, so the structure is built out of exactly the four markers it names. A
        // label scan would read every node and smear the footprints together.
        let seed_txn = coord.begin_serializable();
        let (p, q) = {
            let mut seam = coord.statement(seed_txn).expect("seed statement");
            let p = seam.create_node(&[], &[("v".to_owned(), graphus_core::Value::Integer(0))]);
            let q = seam.create_node(&[], &[("v".to_owned(), graphus_core::Value::Integer(0))]);
            assert!(seam.take_error().is_none(), "the seed captured an error");
            (p, q)
        };
        coord.commit(seed_txn).expect("seed commits");

        let t_in = coord.begin_serializable();
        let t_pivot = coord.begin_serializable();
        let t_out = coord.begin_serializable();
        let write = |txn, node: NodeId| {
            let mut seam = coord.statement(txn).expect("statement");
            seam.set_node_property(node, "v", graphus_core::Value::Integer(1));
            assert!(seam.take_error().is_none(), "a write captured an error");
        };
        let read = |txn, node: NodeId| {
            let seam = coord.statement(txn).expect("statement");
            let _ = seam.node_property(node, "v");
            assert!(seam.take_error().is_none(), "a read captured an error");
        };
        write(t_out, q);
        read(t_pivot, q); // Tpivot --rw--> Tout
        write(t_pivot, p);
        read(t_in, p); // Tin --rw--> Tpivot

        // The two commits, at the same time, on two threads.
        let out = {
            let coord = Arc::clone(&coord);
            graphus_core::sched::spawn("commit-out", move || coord.commit(t_out).map(|_| ()))
        };
        let pivot = {
            let coord = Arc::clone(&coord);
            graphus_core::sched::spawn("commit-pivot", move || coord.commit(t_pivot).map(|_| ()))
        };
        let raw = [
            out.join().expect("the t_out thread joins"),
            pivot.join().expect("the t_pivot thread joins"),
        ];
        let faults = raw
            .iter()
            .filter_map(|r| match r {
                Err(graphus_core::GraphusError::Storage(m)) => Some(m.clone()),
                _ => None,
            })
            .collect();
        CommitRun {
            outcomes: raw.map(|r| r.map_err(|e| e.to_string())),
            faults,
        }
    });
    run
}

/// **Two concurrent commits resolving one dangerous structure never fault the store.**
///
/// This is the seeded reproduction of the cause, and it is the test that changes verdict with the
/// fix. Before it, `TxnCoordinator::commit` answered its Case-B victim by running that transaction's
/// undo from the committing thread, so on the seeds where the victim was committing at the same
/// instant two threads entered one `rollback_logical` and the store returned a
/// [`GraphusError::Storage`](graphus_core::GraphusError::Storage) — a hard fault, which the engine
/// answers by degrading the whole database.
///
/// The assertion is on the error VARIANT, deliberately. A commit refusing with a **retriable**
/// `Transaction` error is the correct, expected outcome of a dangerous structure and happens on
/// every seed; a `Storage` error is never a legitimate answer to contention. Asserting "no aborts"
/// would assert the opposite of what SSI is for.
///
/// Non-vacuity is built in and asserted: at least one of the two commits must be refused on every
/// seed, so a run in which the structure failed to form cannot pass quietly.
#[test]
fn two_workers_resolving_one_dangerous_structure_never_fault_the_store() {
    for seed in 0..SEEDS {
        let run = commit_scenario(seed);
        assert!(
            run.faults.is_empty(),
            "seed {seed}: resolving one SSI dangerous structure produced a STORAGE fault, which \
             means a rollback ran that should never have run — a transaction is undone by its own \
             worker and by no other (`rmp` #1051). Outcomes: {:?}",
            run.outcomes
        );
        assert!(
            run.outcomes.iter().any(Result::is_err),
            "seed {seed}: NON-VACUITY — neither commit was refused, so the dangerous structure this \
             scenario is built on did not form and nothing above was tested. Outcomes: {:?}",
            run.outcomes
        );
    }
}

/// **The same seed replays the same outcome**, so a failure here is reproducible rather than
/// anecdotal — the property every scheduled suite in this crate rests on.
#[test]
fn the_same_seed_replays_the_commit_race_identically() {
    for seed in 0..8 {
        assert_eq!(
            commit_scenario(seed),
            commit_scenario(seed),
            "seed {seed} produced two different outcomes; the run is not deterministic"
        );
    }
}

/// **The same seed replays the same outcome**, so a failure here is reproducible rather than
/// anecdotal — the property every scheduled suite in this crate rests on.
#[test]
fn the_same_seed_replays_the_double_rollback_identically() {
    for seed in 0..8 {
        let first = scenario(seed);
        let second = scenario(seed);
        assert_eq!(
            first.outcomes, second.outcomes,
            "seed {seed} produced two different outcomes; the run is not deterministic"
        );
        assert_eq!(
            first.violations, second.violations,
            "seed {seed} produced two different post-states; the run is not deterministic"
        );
    }
}
