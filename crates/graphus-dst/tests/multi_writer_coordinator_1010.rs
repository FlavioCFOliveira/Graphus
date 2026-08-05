//! **Two writer threads over one `TxnCoordinator`** — the scenario `rmp` #1010 (layer 2 of #975) had
//! to make *expressible*.
//!
//! Before layer 2 this file could not compile. The coordinator's six shared fields were
//! `Rc<RefCell<…>>`, so `TxnCoordinator` was `!Send`, so no `Arc`, no `Mutex` and no `thread::spawn`
//! could put it in front of two writers. The project's only multi-threaded shape was one writer plus N
//! readers, and that was a consequence of the type, not a design choice.
//!
//! The scenario body lives in [`graphus_dst::multi_writer_coordinator`]; this file states what must
//! hold. See that module for what the scenario does and — just as importantly — what it does not claim
//! (it is not a throughput result: the writers still serialise).
//!
//! Real OS threads, so the interleaving is the scheduler's. Every assertion below is therefore
//! scheduler-independent: totals, liveness, and a hand-off sequenced by explicit signalling.
//!
//! Run with `cargo test -p graphus-dst --test multi_writer_coordinator_1010`.

use graphus_dst::multi_writer_coordinator::{run_contended_handoff, run_two_writer_threads};

/// Two writer threads, sharing one coordinator, both commit — and everything they committed is there.
///
/// The three claims, in the order they would break:
///
/// * **Liveness.** The run terminates and neither thread panicked (`join` inside the scenario would
///   have propagated it). Under a bare `Arc<Mutex<…>>` a re-entrant acquisition on the write path
///   would hang here forever instead; under `SharedCell` it would abort. Both are visible as a failure
///   of this test rather than as a green run.
/// * **Non-vacuity.** Two *distinct* OS threads ran writer bodies, and each of them committed
///   everything it attempted. Without the distinct-thread check, a run in which one thread did all the
///   work would satisfy every total below.
/// * **Safety.** Every committed node is visible afterwards, and each is attributed to the thread that
///   wrote it — so the two writers did not overwrite or lose one another's rows.
#[test]
fn two_writer_threads_share_one_coordinator_and_both_commit() {
    const THREADS: usize = 2;
    const PER_THREAD: usize = 64;

    let report = run_two_writer_threads(THREADS, PER_THREAD);

    assert_eq!(
        report.distinct_writer_threads, THREADS,
        "both writer bodies must have run on their own OS thread, else the totals below say nothing \
         about concurrency: {report:?}"
    );
    assert_eq!(
        report.committed_per_thread,
        vec![PER_THREAD; THREADS],
        "every writer must commit every transaction it attempted — a serializable refusal is legal in \
         general, but these writers touch disjoint fresh nodes and conflict with nothing: {report:?}"
    );
    assert_eq!(
        report.refused_per_thread,
        vec![0; THREADS],
        "no transaction should have been refused: {report:?}"
    );
    assert_eq!(
        report.committed_total(),
        THREADS * PER_THREAD,
        "the commit tally must account for every attempt: {report:?}"
    );
    assert_eq!(
        report.visible_after,
        THREADS * PER_THREAD,
        "every committed node must be visible to a later reader — a lost row here is committed-data \
         loss, not a scheduling artefact: {report:?}"
    );
    assert_eq!(
        report.visible_per_author,
        vec![PER_THREAD; THREADS],
        "each writer's rows must survive attributed to it, so neither thread clobbered the other's: \
         {report:?}"
    );
}

/// A writer that finds the coordinator held by **another thread** must block and then proceed — never
/// panic, never barge in.
///
/// This is the control that keeps the `SharedCell` tripwire honest. That tripwire panics on a
/// *re-entrant* acquisition, which is the whole reason the `Rc<RefCell<…>>` → `Arc<Mutex<…>>` swap is
/// safe to make: re-entrancy stays a loud failure instead of becoming a silent hang. But a tripwire
/// that fired on *any* contended acquisition would be indistinguishable from that one in a
/// single-threaded suite, and would make every multi-writer scenario — starting with the one above —
/// abort spuriously. This test is what separates the two.
///
/// The hand-off is sequenced by signalling, not timing: thread A holds the coordinator and only
/// releases after B has announced that it is asking for it, so the contention is a fact of the run.
#[test]
fn a_contended_writer_blocks_and_then_proceeds() {
    let report = run_contended_handoff();

    assert!(
        !report.second_panicked,
        "the contended writer must not panic: a panic here means the re-entrancy tripwire cannot \
         tell ordinary cross-thread contention from a genuine self-re-entrancy — {report:?}"
    );
    assert!(
        report.second_acquired_after_release,
        "the contended writer must acquire only AFTER the holder released, i.e. it genuinely blocked: \
         {report:?}"
    );
    assert!(
        report.second_write_visible,
        "the contended writer must not merely survive the contention, its transaction must commit and \
         be readable: {report:?}"
    );
}
