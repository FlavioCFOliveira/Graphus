//! **`N` writer threads allocate physical ids at once, and no id is ever handed out twice**
//! (`rmp` #1012, layer 4 of #975 — acceptance criteria 3 and 4).
//!
//! # What is under test, and why it is a *thread* test
//!
//! Layer 4 put each store's four pieces of allocation state — the high-water mark, the free list, the
//! `rmp` #588 shadow-hold overlay and the reuse barrier that stamps it — behind **one latch per
//! store**, and turned the read-then-write withdrawal of an unused id into a compare-exchange. Both
//! changes exist for a world with more than one writer, and neither can be falsified by a
//! single-threaded test: with one writer every interleaving that matters is unreachable, so the
//! defects they close are invisible and the code that closes them is indistinguishable from code that
//! does not.
//!
//! So the properties are asserted against real threads, hammering the real API:
//!
//! 1. **No id is issued twice.** A repeated physical id is two live records in one slot, whose
//!    property / incidence chains then self-cycle (`rmp` #578's `"malformed (cycle?)"`) — a
//!    corruption, not a performance bug.
//! 2. **No id is lost.** Every seeded free id ends up either allocated exactly once or still listed:
//!    the space guarantee `rmp` #581 exists to keep.
//! 3. **The free list stays well-formed.** Each id at most once, always — the `rmp` #578 invariant
//!    that makes `FreeList::remove_id`'s "remove exactly this transaction's push" sound.
//! 4. **A shadow-held slot is never handed out** while the reader that predates its free may still be
//!    walking through it (`rmp` #588: an ACID Isolation violation if it is).
//! 5. **The six stores are six independent latches**, not one — the point of per-store granularity.
//!
//! # Why these tests are not vacuous
//!
//! Each one fails when the correction it defends is reverted; the reverts and their output are
//! recorded in the task's report. Concretely: reverting `allocate` to peek-then-pop across two holds
//! breaks (1) and (3); reverting `unbump_fresh` to an unconditional `restore` breaks (1) in
//! `withdrawals_under_contention_never_reissue_a_live_id`; dropping the overlay consultation from
//! `pop_reusable` breaks (4); reverting `unbump_run` to an unconditional `restore_to` breaks
//! `claimed_runs_under_contention_never_overlap` — and **only** that one, since the single-id tests
//! never touch the run API; putting one global mutex inside `StoreAllocator::lock` breaks (5) — but
//! **only** in `a_writer_progresses_while_another_stores_latch_is_held`, and that split is the whole
//! reason it exists as a separate test. See its documentation: granularity is a *liveness* property,
//! and no amount of inspecting the ids a run produced can see it.

use std::collections::{BTreeSet, HashMap};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Barrier};
use std::time::Duration;

use graphus_storage::{Allocation, FreeList, StoreAllocator};

/// Physical threads to run. Eight is the acceptance criterion's floor and enough to interleave on any
/// machine the project targets, from a Raspberry Pi 5 upwards.
const THREADS: usize = 8;

/// Spawns `THREADS` threads that all start together, and collects what each returned.
fn race<T, F>(work: F) -> Vec<T>
where
    T: Send + 'static,
    F: Fn(usize) -> T + Send + Sync + 'static,
{
    let gate = Arc::new(Barrier::new(THREADS));
    let work = Arc::new(work);
    let handles: Vec<_> = (0..THREADS)
        .map(|t| {
            let gate = Arc::clone(&gate);
            let work = Arc::clone(&work);
            std::thread::spawn(move || {
                // Start together, so the threads actually contend rather than running end to end.
                gate.wait();
                work(t)
            })
        })
        .collect();
    handles
        .into_iter()
        .map(|h| h.join().expect("allocator thread panicked"))
        .collect()
}

/// Asserts that `ids` holds no value twice, naming the offender when it does.
fn assert_no_duplicates(ids: &[u64], what: &str) {
    let mut seen = BTreeSet::new();
    for &id in ids {
        assert!(
            seen.insert(id),
            "{what}: physical id {id} was handed out twice. Two live records would share one \
             physical slot and their property / incidence chains would self-cycle (`rmp` #578)."
        );
    }
}

/// **Property 1 + 3.** `THREADS` threads allocate from one store, drawing from a large pre-seeded
/// free list and then growing past it. Every id must be distinct, and the free list must be empty and
/// well-formed at the end.
///
/// The seeded free list is what makes this test able to fail: it forces most allocations down the
/// *reuse* path, which is where the read-and-act decision lives. A test that only ever grew the mark
/// would exercise a single atomic and prove nothing about the latch.
#[test]
fn n_threads_never_receive_the_same_physical_id() {
    const SEEDED: u64 = 4_000;
    const PER_THREAD: usize = 1_000;

    let mut free = FreeList::new();
    for id in 1..=SEEDED {
        free.push(id);
    }
    // The mark starts past the seeded ids, so a grown id can never collide with a seeded one by
    // accident — a collision here is a real double-issue, not an artefact of the fixture.
    let alloc = Arc::new(StoreAllocator::restore(SEEDED + 1, free));

    let a = Arc::clone(&alloc);
    let per_thread = race(move |_| {
        (0..PER_THREAD)
            .map(|_| a.allocate().expect("id space is not exhausted"))
            .collect::<Vec<Allocation>>()
    });

    let ids: Vec<u64> = per_thread
        .iter()
        .flat_map(|v| v.iter().map(|a| a.id()))
        .collect();
    assert_eq!(ids.len(), THREADS * PER_THREAD);
    assert_no_duplicates(&ids, "concurrent allocation from one store");

    // Every seeded id was reused exactly once, and the reuse really happened (the fixture is not
    // silently allocating everything fresh, which would make the assertion above vacuous).
    let reused: Vec<u64> = per_thread
        .iter()
        .flat_map(|v| v.iter())
        .filter_map(|a| match a {
            Allocation::Reused(id) => Some(*id),
            Allocation::Fresh(_) => None,
            // Unreachable through the unbounded `allocate`, which never declines: only
            // `allocate_within` can return `Grow` (`rmp` #1014).
            Allocation::Grow { next } => unreachable!("`allocate` never declines; got Grow {next}"),
        })
        .collect();
    assert_eq!(
        reused.len() as u64,
        SEEDED,
        "every seeded free id must be reused exactly once — no id lost, none issued twice"
    );
    assert_eq!(
        reused.iter().copied().collect::<BTreeSet<_>>().len() as u64,
        SEEDED
    );

    // `rmp` #578: the free list is drained and well-formed.
    assert!(
        alloc.free_is_empty(),
        "every seeded id was taken, so nothing may remain listed"
    );
    // `rmp` #452 / #479: the mark accounts for exactly the ids grown beyond the seed.
    let grown = (THREADS * PER_THREAD) as u64 - SEEDED;
    assert_eq!(
        alloc.high_water(),
        SEEDED + 1 + grown,
        "the mark must account for every fresh id handed out, and for no others"
    );
}

/// **Property 2 + 3 under mixed traffic.** Half the threads allocate, half free, over the same store.
/// Nothing may be issued twice, and the free list must never end up holding an id twice — the
/// invariant `rmp` #578's `remove_id` ("a well-formed free list holds each id at most once") rests on.
#[test]
fn concurrent_allocate_and_free_keep_the_free_list_well_formed() {
    const ROUNDS: usize = 2_000;
    const SEEDED: u64 = 2_000;

    let mut free = FreeList::new();
    for id in 1..=SEEDED {
        free.push(id);
    }
    let alloc = Arc::new(StoreAllocator::restore(SEEDED + 1, free));

    let a = Arc::clone(&alloc);
    let per_thread = race(move |t| {
        let mut mine: Vec<u64> = Vec::new();
        for _ in 0..ROUNDS {
            if t % 2 == 0 {
                // Allocator: take an id and keep it. Nobody else may ever receive it.
                mine.push(a.allocate().expect("id space is not exhausted").id());
            } else {
                // Freer: hand back an id from a per-thread private range that no allocator can be
                // holding, so a push is never a double-free of a live slot. What is under test is the
                // list's structural integrity under concurrent push and pop, not the reclaim policy.
                let id = 1_000_000 + (t as u64) * (ROUNDS as u64) + mine.len() as u64;
                a.lock().push_free(id);
                mine.push(id);
            }
        }
        (t, mine)
    });

    let allocated: Vec<u64> = per_thread
        .iter()
        .filter(|(t, _)| t % 2 == 0)
        .flat_map(|(_, v)| v.iter().copied())
        .collect();
    assert_no_duplicates(&allocated, "concurrent allocation alongside frees");

    // The list may legitimately hold anything the allocators did not take — but never a duplicate,
    // and never an id an allocator is holding.
    let listed = alloc.free_ids();
    assert_no_duplicates(&listed, "the free list after concurrent pushes and pops");
    let held: BTreeSet<u64> = allocated.iter().copied().collect();
    for id in &listed {
        assert!(
            !held.contains(id),
            "id {id} is listed as free while a writer is still holding it (`rmp` #581)"
        );
    }
}

/// **Property 4.** While a GC pass's barrier is armed, a slot it frees must not be handed to a writer
/// until every transaction that predates the free has retired (`rmp` #588). One thread frees under an
/// armed barrier; the others allocate as fast as they can. No allocation may return a held id.
///
/// The freed ids come from a range strictly below the starting mark, so an id in that range appearing
/// in an allocation result can only have come off the free list — the assertion cannot be satisfied
/// by accident.
#[test]
fn a_freed_slot_is_never_handed_out_while_it_is_shadow_held() {
    const RECLAIMED: u64 = 3_000;
    const BARRIER_TICKET: u64 = 500;

    let alloc = Arc::new(StoreAllocator::restore(RECLAIMED + 1, FreeList::new()));
    alloc.lock().set_reuse_barrier(Some(BARRIER_TICKET));

    let a = Arc::clone(&alloc);
    let per_thread = race(move |t| {
        if t == 0 {
            // The GC pass: reclaim slots one at a time, each stamped with the armed barrier.
            for id in 1..=RECLAIMED {
                a.free_shadow_held(id);
            }
            Vec::new()
        } else {
            (0..RECLAIMED as usize)
                .map(|_| a.allocate().expect("id space is not exhausted").id())
                .collect::<Vec<u64>>()
        }
    });

    for id in per_thread.iter().flat_map(|v| v.iter().copied()) {
        assert!(
            id > RECLAIMED,
            "allocation returned id {id}, which the concurrent GC pass had shadow-held. A writer \
             would overwrite a slot an off-thread reader is still threading through, so the reader \
             reads a FOREIGN record and diverts — the ACID Isolation violation `rmp` #588 closes."
        );
    }

    // The holds really were in force (this is what keeps the assertion above from being vacuous:
    // without them, or without the frees having landed, `id > RECLAIMED` would hold trivially).
    assert_eq!(
        alloc.held_len() as u64,
        RECLAIMED,
        "every reclaimed slot must be shadow-held while the barrier is armed"
    );
    assert_eq!(alloc.free_len() as u64, RECLAIMED);

    // And once the readers retire, the space comes back — a hold, never a leak.
    alloc.lock().release_held(BARRIER_TICKET);
    assert_eq!(alloc.held_len(), 0);
    let reused = alloc.allocate().expect("space");
    assert!(
        matches!(reused, Allocation::Reused(id) if id <= RECLAIMED),
        "after release the reclaimed slots must be reusable again, got {reused:?}"
    );
}

/// **Property 5, the half that inspecting a finished run can see.** Six stores keep six *separate*
/// pieces of state: threads spread across the six `StoreKind`s each get a distinct id **within** their
/// store, and an id handed out by the node store says nothing about the relationship store's mark. One
/// `StoreAllocator` shared behind six handles fails here, on the per-store mark.
///
/// It does **not** prove the latches are six. Separate *state* and separate *latches* are different
/// claims, and this test only reaches the first: one global mutex serialising all six allocators
/// produces exactly these ids, these marks and these absences of duplicates, so every assertion below
/// passes either way. The second claim is a liveness property and needs
/// [`a_writer_progresses_while_another_stores_latch_is_held`], which is the test that fails when the
/// latch is made global.
#[test]
fn the_six_store_allocators_keep_six_separate_marks() {
    const STORES: usize = 6;
    const PER_THREAD: usize = 500;

    let allocs: Arc<Vec<StoreAllocator>> =
        Arc::new((0..STORES).map(|_| StoreAllocator::new()).collect());

    let a = Arc::clone(&allocs);
    let per_thread = race(move |t| {
        let mut out: Vec<(usize, u64)> = Vec::new();
        for i in 0..PER_THREAD {
            // Every thread touches every store, round-robin from a different offset, so each store is
            // genuinely contended by all eight threads.
            let s = (t + i) % STORES;
            // Through `StoreAllocator::allocate`, the API production calls — not `lock().allocate()`.
            // The distinction is load-bearing: the latch-scope this takes and releases per call is
            // what a peek-then-take split would break, and going through the guard by hand would hide
            // that.
            out.push((s, a[s].allocate().expect("space").id()));
        }
        out
    });

    let mut by_store: HashMap<usize, Vec<u64>> = HashMap::new();
    for (s, id) in per_thread.into_iter().flatten() {
        by_store.entry(s).or_default().push(id);
    }
    assert_eq!(
        by_store.len(),
        STORES,
        "every store must have been exercised"
    );
    for (s, ids) in &by_store {
        assert_no_duplicates(ids, &format!("concurrent allocation from store {s}"));
        // Each store's mark accounts for exactly its own allocations and nobody else's — proof the
        // six counters are six, not one shared behind six handles.
        assert_eq!(
            allocs[*s].high_water(),
            ids.len() as u64 + 1,
            "store {s}'s high-water mark must count only its own ids"
        );
    }
    assert_eq!(
        by_store.values().map(Vec::len).sum::<usize>(),
        THREADS * PER_THREAD
    );
}

/// **Property 5, the half no finished run can show.** Granularity is a **liveness** property. Six
/// independent latches and one global latch behind six façades produce the same ids, the same marks
/// and the same absence of duplicates — every assertion in
/// [`the_six_store_allocators_keep_six_separate_marks`] passes under both. What separates them is
/// whether a writer in one store can make progress *while* another store's latch is held, and that is
/// only observable from inside the holding window.
///
/// So the window is opened deliberately: one thread takes store 0's latch and keeps it; another
/// allocates from store 1 and publishes its progress; the holder samples that counter **before**
/// releasing. Six latches — the sampled count is the whole run. One latch — the prober is parked on
/// the mutex and the count is zero. This is the test that fails when `lock` is made global, and the
/// only one that can.
///
/// # Why a deadline, and why it is not a timing assumption
///
/// Under a global latch the prober never progresses, so a holder that simply waited for the target
/// would wait forever: the failure mode of the assertion would be a hang, and a hanging test reports
/// nothing. The deadline turns that hang into a named failure. It does not weaken the passing
/// direction — the holder is woken the *instant* the prober finishes, which with per-store latches is
/// microseconds — it only bounds how long the failing direction may take. The latch is released before
/// the join either way, so the prober always finishes and the failure is reported rather than
/// deadlocked.
///
/// The holder **blocks** on a channel rather than spinning on the counter. Spinning was measured to be
/// wrong here, not merely wasteful: `cargo test` runs this file's cases concurrently, and a holder
/// busy-waiting against the other tests' sixteen threads starves the one thread whose progress is
/// under test — turning a scheduling artefact into a 10-second near-miss. Blocking hands the core to
/// the prober, which is precisely the thread that must run for the test to mean anything.
#[test]
fn a_writer_progresses_while_another_stores_latch_is_held() {
    /// Enough allocations that "the prober ran" is unmistakable, few enough to finish instantly when
    /// the latches really are independent.
    const PROBE_ALLOCS: u64 = 1_000;
    /// Only ever spent in the FAILING direction. Generous, because a loaded CI machine that is merely
    /// slow must not be reported as a serialised allocator.
    const DEADLINE: Duration = Duration::from_secs(10);

    let allocs = Arc::new([StoreAllocator::new(), StoreAllocator::new()]);
    let progress = Arc::new(AtomicU64::new(0));
    // Two parties: the prober may not start until store 0's latch is genuinely held, or it could
    // finish the whole run before the window ever opens and the test would pass vacuously.
    let window_open = Arc::new(Barrier::new(2));
    let (finished_tx, finished_rx) = std::sync::mpsc::channel::<()>();

    let prober = {
        let allocs = Arc::clone(&allocs);
        let progress = Arc::clone(&progress);
        let window_open = Arc::clone(&window_open);
        std::thread::spawn(move || {
            window_open.wait();
            for _ in 0..PROBE_ALLOCS {
                allocs[1].allocate().expect("space");
                progress.fetch_add(1, Ordering::Release);
            }
            // Ignore a send error: it only means the holder already gave up on the deadline, which is
            // the failing direction and is reported by the assertion, not by a panic in this thread.
            let _ = finished_tx.send(());
        })
    };

    let guard = allocs[0].lock();
    window_open.wait();
    let _ = finished_rx.recv_timeout(DEADLINE);
    // Sampled while store 0's latch is STILL held — that is the whole measurement.
    let observed_while_held = progress.load(Ordering::Acquire);
    // Released BEFORE the join, so the failing direction terminates and reports instead of hanging.
    drop(guard);
    prober.join().expect("prober thread panicked");

    assert_eq!(
        observed_while_held, PROBE_ALLOCS,
        "a writer allocating from store 1 completed only {observed_while_held} of {PROBE_ALLOCS} \
         allocations while store 0's latch was held. The six allocators are sharing one latch, so \
         every writer in the database serialises behind whichever store any other writer happens to \
         be touching — the single-writer bottleneck `rmp` #975 exists to remove, reintroduced one \
         layer down."
    );
}

/// **Runs, under contention.** [`AllocGuard::claim_run`] is the one public allocation API whose
/// caller-supplied closure runs **with the latch held** — the undo-delta slabs of `rmp` #1011 are its
/// caller — and it is therefore the sharpest test of "read the mark and advance it indivisibly": the
/// run's extent is computed *from* the mark it is about to move. Everything else in this file
/// allocates one id at a time, where a split hold shows up as a duplicate; a split hold here shows up
/// as two threads owning **overlapping ranges**, which no single-id test can see.
///
/// Same keeper/withdrawer shape as the single-id withdrawal below, for the same reason: without runs
/// that stay outstanding, a lowered mark has nothing to undercut and the test proves nothing.
///
/// # The interleaving is CONSTRUCTED for one round, then left free for the rest
///
/// The evidence that the threads interleaved is a *declined* withdrawal: a withdrawer found the mark no
/// longer at the end of its own run, which can only mean another thread claimed in between. Leaving
/// that to the scheduler is leaving the test's validity to the host — under the concurrent suite
/// (`rmp` #1044) eight threads ran end to end rather than together, not one withdrawal was declined,
/// and the non-vacuity assertion fired on a machine where nothing was wrong.
///
/// Raising the round count would not fix that; it would only make the same coin-flip cheaper to win.
/// So round zero is *built* to interleave, with two rendezvous, and it is cross-thread by construction
/// rather than by luck:
///
/// 1. every withdrawer claims its run — rendezvous — so all withdrawn runs exist first;
/// 2. every keeper claims its run — rendezvous — so every keeper's run sits ABOVE every withdrawer's;
/// 3. every withdrawer then withdraws, and each one is declined, because a run it does not own is on
///    top of the mark. Four declines, caused by other threads' claims, on any machine at any load.
///
/// The remaining rounds run exactly as before, unsynchronised, so the full interleaving space — a claim
/// racing a withdrawal, two withdrawals racing each other — is still exercised, and the overlap
/// property below is asserted over every round of every thread.
#[test]
fn claimed_runs_under_contention_never_overlap() {
    const ROUNDS: usize = 1_500;
    const RUN_LEN: u64 = 7;

    let alloc = Arc::new(StoreAllocator::new());
    // Used twice, by all eight threads, to stage round zero (see the doc comment above).
    let staged = Arc::new(Barrier::new(THREADS));

    let a = Arc::clone(&alloc);
    let per_thread = race(move |t| {
        let keeper = t % 2 == 0;
        let mut outstanding: Vec<(u64, u64)> = Vec::new();
        let mut declined = 0usize;

        // ROUND ZERO, staged: withdrawers claim, then keepers claim on top of them, then the
        // withdrawals are attempted and every one of them must be declined.
        let staged_run = if keeper {
            staged.wait();
            let run = a
                .lock()
                .claim_run(|first| Ok(first + RUN_LEN))
                .expect("space");
            staged.wait();
            outstanding.push(run);
            None
        } else {
            let run = a
                .lock()
                .claim_run(|first| Ok(first + RUN_LEN))
                .expect("space");
            staged.wait();
            staged.wait();
            Some(run)
        };
        if let Some((first, end)) = staged_run {
            assert!(
                !a.lock().unbump_run(first, end),
                "run [{first}, {end}) was withdrawn even though a keeper's run was claimed on top of \
                 it: `unbump_run` moved a mark that was no longer its own to move, which is exactly \
                 how two threads end up owning overlapping ids"
            );
            declined += 1;
            outstanding.push((first, end));
        }

        for _ in 1..ROUNDS {
            let (first, end) = a
                .lock()
                .claim_run(|first| Ok(first + RUN_LEN))
                .expect("space");
            if keeper {
                outstanding.push((first, end));
            } else if a.lock().unbump_run(first, end) {
                // Withdrawn: the mark was still ours to move, so the range is genuinely back in play.
            } else {
                declined += 1;
                outstanding.push((first, end));
            }
        }
        (outstanding, declined)
    });

    let mut outstanding: Vec<(u64, u64)> = per_thread
        .iter()
        .flat_map(|(runs, _)| runs.iter().copied())
        .collect();
    outstanding.sort_unstable();
    // THE property. Two threads holding overlapping runs means the same physical ids back two undo
    // slabs at once, and one transaction's deltas overwrite another's.
    for pair in outstanding.windows(2) {
        let ((first_a, end_a), (first_b, _)) = (pair[0], pair[1]);
        assert!(
            end_a <= first_b,
            "runs [{first_a}, {end_a}) and [{first_b}, …) overlap: two threads were handed the same \
             physical ids, so two undo slabs share storage and one transaction's deltas land on top \
             of another's"
        );
    }
    let highest_end = outstanding.last().expect("non-empty").1;
    assert!(
        alloc.high_water() >= highest_end,
        "the high-water mark ({}) sits below the end of an outstanding run ({highest_end}): the next \
         claim would overlap it",
        alloc.high_water()
    );

    // NON-VACUITY. It is asserted inside the threads, on the staged round, and deliberately not here:
    // this is where it used to live as `declined > 0` over the free-running rounds, and that is a
    // property of the host's scheduler, not of the allocator — it fired on a loaded machine with
    // nothing wrong (`rmp` #1044). The staged round proves the same thing about the same code path
    // (`unbump_run` declining a mark another thread moved) on every machine at every load, and it
    // still fails under the mutation this file's module docs name: an unconditional `restore_to`
    // withdraws the run and the staged assertion trips at once.
    //
    // The free rounds' declines are reported rather than required, because that is exactly the status
    // they have: evidence of how much genuine interleaving this particular run happened to get.
    let staged = THREADS / 2; // one guaranteed decline per withdrawer, from the staged round
    let declined: usize = per_thread.iter().map(|(_, d)| d).sum();
    println!(
        "claimed_runs_under_contention_never_overlap: {} declined withdrawals in the free rounds \
         (plus {staged} staged)",
        declined - staged
    );
}

/// **The `rmp` #1012 withdrawal, under contention.** Half the threads are *keepers*: they allocate an
/// id and hold it forever, exactly as a successful `create_node` does. The other half are *withdrawers*:
/// they allocate an id and immediately hand it back, the shape `alloc_id` takes when mapping the new
/// id's page fails (ENOSPC).
///
/// The invariant is one sentence: **a withdrawal must never drop the mark below an id somebody else is
/// still holding.** An unconditional lowering — the `alloc = PhysicalAllocator::restore(id)` this
/// replaced — violates it directly: a withdrawer that lost the race to a keeper drags the mark back
/// past the keeper's id, and the next allocation issues that id a **second** time. Two live records
/// then share one physical slot, and their property / incidence chains self-cycle.
///
/// The keepers' ids are what makes that observable. A test where every thread withdrew would see the
/// mark bounce harmlessly, because no id would be outstanding for the lowering to undercut.
///
/// Round zero is staged exactly as in [`claimed_runs_under_contention_never_overlap`], and for the same
/// reason: a declined withdrawal is this test's evidence that the threads interleaved, and leaving that
/// evidence to the scheduler makes the test's validity a property of the host. Withdrawers allocate,
/// rendezvous, keepers allocate on top of them, rendezvous, and every withdrawal is then declined
/// because a live id it does not own sits above the mark. The remaining rounds are unsynchronised, so
/// the full race is still run.
#[test]
fn withdrawals_under_contention_never_reissue_a_live_id() {
    const ROUNDS: usize = 4_000;

    let alloc = Arc::new(StoreAllocator::new());
    // Used twice, by all eight threads, to stage round zero (see the doc comment above).
    let staged = Arc::new(Barrier::new(THREADS));

    let a = Arc::clone(&alloc);
    let per_thread = race(move |t| {
        let keeper = t % 2 == 0;
        // For a keeper: every id it was handed, all of them outstanding. For a withdrawer: only the
        // ids whose withdrawal was DECLINED, which are outstanding for the same reason.
        let mut outstanding: Vec<u64> = Vec::new();
        let mut declined = 0usize;

        // ROUND ZERO, staged: withdrawers allocate, then keepers allocate on top of them, then every
        // withdrawal is attempted and every one of them must be declined.
        let staged_id = if keeper {
            staged.wait();
            let id = a.allocate().expect("space").id();
            staged.wait();
            outstanding.push(id);
            None
        } else {
            let id = a.allocate().expect("space").id();
            staged.wait();
            staged.wait();
            Some(id)
        };
        if let Some(id) = staged_id {
            assert!(
                !a.lock().unbump_fresh(id),
                "id {id} was withdrawn even though a keeper's id was allocated on top of it: the \
                 withdrawal lowered a mark that was no longer its own to move, which re-issues a live \
                 id and puts two records in one physical slot"
            );
            declined += 1;
            outstanding.push(id);
        }

        for _ in 1..ROUNDS {
            let id = a.allocate().expect("space").id();
            if keeper {
                outstanding.push(id);
            } else if a.lock().unbump_fresh(id) {
                // Withdrawn: the mark was still ours to move, so the id is genuinely back in play and
                // another thread may legitimately receive it.
            } else {
                declined += 1;
                outstanding.push(id);
            }
        }
        (outstanding, declined)
    });

    let outstanding: Vec<u64> = per_thread
        .iter()
        .flat_map(|(ids, _)| ids.iter().copied())
        .collect();
    // THE property. Every id here is one a thread still holds; a repeat means a withdrawal lowered
    // the mark underneath a live id and the allocator issued it again.
    assert_no_duplicates(
        &outstanding,
        "ids still held by a thread, with concurrent withdrawals in flight",
    );
    // ...and the mark still covers all of them.
    let highest = outstanding.iter().copied().max().expect("non-empty");
    assert!(
        alloc.high_water() > highest,
        "the high-water mark ({}) sits below an outstanding id ({highest}): the next allocation \
         would re-issue it, so two live records would share one physical slot",
        alloc.high_water()
    );

    // NON-VACUITY. Asserted inside the threads, on the staged round, and deliberately not here — the
    // reasoning is identical to `claimed_runs_under_contention_never_overlap`'s, and so was the
    // failure: `declined > 0` over the free-running rounds is a property of the host's scheduler, and
    // it fired under the concurrent suite with nothing wrong (`rmp` #1044). The staged round proves
    // the same thing about the same code path on every machine, and still trips under the mutation
    // this file's module docs name (an unconditional `restore`).
    let staged = THREADS / 2; // one guaranteed decline per withdrawer, from the staged round
    let declined: usize = per_thread.iter().map(|(_, d)| d).sum();
    println!(
        "withdrawals_under_contention_never_reissue_a_live_id: {} declined withdrawals in the free \
         rounds (plus {staged} staged)",
        declined - staged
    );
}
