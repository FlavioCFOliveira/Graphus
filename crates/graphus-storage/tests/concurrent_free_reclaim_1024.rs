//! **Two reclaimers racing for the same slot list it exactly once** (`rmp` #1024).
//!
//! # The defect, and why it is a thread test
//!
//! Reclaiming a dead slot is one decision — "is it already listed? if not, list it" — and three call
//! sites in `RecordStore` took it under one hold and acted under another: `gc_reclaim_orphan_slots`
//! (a narrow gap), `reclaim_aborted_pops` (page fetches in the gap) and the property-chain sweep (a
//! **WAL write** in the gap). Two reclaimers both observe the id absent, both push it, and the free
//! list holds one id twice. The next two allocations hand the same physical slot to two writers: two
//! live records in one slot, whose property / incidence chains then self-cycle — the `rmp` #578
//! duplicate-free-list-entry shape, and the invariant `FreeList::remove_id` states in its own
//! contract ("a well-formed free list holds each id at most once").
//!
//! Before the per-store latch of `rmp` #1012 the pairing was free: every caller held
//! `&mut RecordStore`, so test and push were atomic whether or not the author thought about it.
//! Turning that borrow into a latch acquisition removed the guarantee without changing a line of the
//! logic. That is why this is asserted against real threads: with one writer the interleaving is
//! unreachable, so the defect is invisible and the code that closes it is indistinguishable from code
//! that does not.
//!
//! # Why these tests are not vacuous
//!
//! Reverting `push_free_shadow_held_if_absent` to a test outside the hold and a push inside it makes
//! both tests below fail with duplicate entries. Each also carries its own vacuity control: a race
//! that never actually raced would leave every round with a single caller and prove nothing, so the
//! contention itself is asserted.

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Barrier};

use graphus_storage::StoreAllocator;

/// Physical threads. Eight is the project's floor for a contention test and enough to interleave on
/// any target from a Raspberry Pi 5 upwards.
const THREADS: usize = 8;

/// **The property.** `THREADS` reclaimers converge on the same id, round after round. Exactly one may
/// list it; the rest must be told it is already listed.
#[test]
fn threads_racing_to_free_one_slot_list_it_exactly_once() {
    const ROUNDS: u64 = 2_000;

    let alloc = Arc::new(StoreAllocator::new());
    // All threads free the id named here, then move to the next one together.
    let gate = Arc::new(Barrier::new(THREADS));
    // How many callers won the right to list, summed over every round. Must be exactly ROUNDS.
    let listed = Arc::new(AtomicU64::new(0));

    let handles: Vec<_> = (0..THREADS)
        .map(|_| {
            let alloc = Arc::clone(&alloc);
            let gate = Arc::clone(&gate);
            let listed = Arc::clone(&listed);
            std::thread::spawn(move || {
                for id in 1..=ROUNDS {
                    // Start each round together, so the callers genuinely collide on `id` rather than
                    // running one after another.
                    gate.wait();
                    if alloc.free_shadow_held_if_absent(id) {
                        listed.fetch_add(1, Ordering::Relaxed);
                    }
                }
            })
        })
        .collect();
    for h in handles {
        h.join().expect("reclaimer thread panicked");
    }

    // THE property, stated on the list itself: no id appears twice.
    let free = alloc.free_ids();
    let mut seen: BTreeMap<u64, usize> = BTreeMap::new();
    for id in &free {
        *seen.entry(*id).or_default() += 1;
    }
    if let Some((&id, &n)) = seen.iter().find(|&(_, &n)| n > 1) {
        panic!(
            "physical id {id} is on the free list {n} times. Two reclaimers each proved the slot \
             dead and each listed it, so the next two allocations hand one physical slot to two \
             writers — two live records sharing it, and their property / incidence chains \
             self-cycling (`rmp` #1024, the #578 duplicate-free-list-entry shape)"
        );
    }
    // And the same fact from the callers' side: exactly one winner per round.
    assert_eq!(
        listed.load(Ordering::Relaxed),
        ROUNDS,
        "every round must have exactly one caller that listed the id, and {THREADS} that were \
         declined"
    );
    assert_eq!(free.len() as u64, ROUNDS, "every id must be listed once");
}

/// **The same property with pops in the mix**, which is what a live store does: reclaimers race each
/// other *and* an allocator that keeps taking ids back off the list. A stale membership mirror shows
/// up here and not above — an id popped and then wrongly still considered "listed" would leak, and one
/// popped and then wrongly considered "absent" while a copy remained would duplicate.
#[test]
fn reclaimers_and_an_allocator_racing_keep_the_free_list_well_formed() {
    const ROUNDS: u64 = 1_500;

    let alloc = Arc::new(StoreAllocator::new());
    let gate = Arc::new(Barrier::new(THREADS));
    // Ids the allocator thread took back out; each must be a genuine, singly-listed id.
    let popped = Arc::new(AtomicU64::new(0));

    let handles: Vec<_> = (0..THREADS)
        .map(|t| {
            let alloc = Arc::clone(&alloc);
            let gate = Arc::clone(&gate);
            let popped = Arc::clone(&popped);
            std::thread::spawn(move || {
                let mut mine: Vec<u64> = Vec::new();
                for id in 1..=ROUNDS {
                    gate.wait();
                    if t == 0 {
                        // The allocator: drains whatever is listed rather than freeing.
                        if let Some(got) = alloc.lock().pop_reusable() {
                            popped.fetch_add(1, Ordering::Relaxed);
                            mine.push(got);
                        }
                    } else if alloc.free_shadow_held_if_absent(id) {
                        mine.push(id);
                    }
                }
                mine
            })
        })
        .collect();
    let taken: Vec<Vec<u64>> = handles
        .into_iter()
        .map(|h| h.join().expect("thread panicked"))
        .collect();

    let free = alloc.free_ids();
    let mut seen: BTreeMap<u64, usize> = BTreeMap::new();
    for id in &free {
        *seen.entry(*id).or_default() += 1;
    }
    if let Some((&id, &n)) = seen.iter().find(|&(_, &n)| n > 1) {
        panic!(
            "physical id {id} is on the free list {n} times, with an allocator popping \
             concurrently (`rmp` #1024)"
        );
    }
    // Nothing was invented: every listed id is one some reclaimer actually freed.
    for id in &free {
        assert!(
            *id >= 1 && *id <= ROUNDS,
            "id {id} is on the free list but no reclaimer ever freed it"
        );
    }
    // Vacuity control, checked LAST so a real duplicate above is reported as the duplicate it is.
    // If the allocator never popped anything, the two paths never interleaved and this test reduces
    // to the one above.
    assert!(
        popped.load(Ordering::Relaxed) > 0,
        "the allocator never popped a single id, so it never raced the reclaimers and this test \
         proved nothing beyond the previous one. Raise ROUNDS or THREADS."
    );
    let _ = taken;
}
