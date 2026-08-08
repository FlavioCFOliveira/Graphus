//! **Arming the `rmp` #588 reuse barrier is one act, not six** (`rmp` #1025).
//!
//! # The defect
//!
//! Layer 4 (`rmp` #1012) gave every store its own copy of the reuse barrier, to buy the read-and-act
//! atomicity that matters: `free_push` reads the barrier and stamps the shadow-hold overlay in the
//! same hold. That much was right. What it also created was an **arming** race, because six copies
//! are armed one latch at a time:
//!
//! 1. a GC pass arms the barrier; stores 0 and 1 take it, stores 2..5 have not yet;
//! 2. a writer frees a relationship slot — store 5's barrier is still `None`, so the slot is **not**
//!    stamped and is immediately reusable;
//! 3. another writer allocates, receives that very slot, and overwrites the record body;
//! 4. an off-thread reader that predates the free, mid-walk through the slot, reads a stranger's
//!    record.
//!
//! That is the ACID Isolation violation `rmp` #588 exists to close, re-opened by the replication that
//! was meant to make the stamp atomic. With a single writer the window was a few mutex acquisitions
//! wide and unreachable; it becomes real the moment writers run in parallel (`rmp` #1013).
//!
//! # What is asserted, and why it is the right property
//!
//! Not "the six values are equal" — sampling six reads of one atom can legitimately straddle an arming
//! and disagree, so that assertion would be wrong even with the fix. The property that actually
//! matters is **implication**: if any store can be *seen* to have the barrier armed, then a free
//! landing on any *other* store from that moment on must be stamped. One shared atom makes "store 0
//! sees it armed" and "store 5 sees it armed" the same fact, so the implication holds by construction.
//! Six replicas have no such point, and the test below catches exactly that.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use graphus_storage::{SharedReuseBarrier, StoreAllocator};

/// The number of stores a `RecordStore` has.
const STORES: usize = 6;
/// The engine ticket the GC pass arms with. Arbitrary and non-zero — but see the encoding note in
/// `SharedReuseBarrier`: zero is a legal ticket too, which is why the sentinel is not zero.
const TICKET: u64 = 4_242;

/// Builds six allocators sharing one barrier, exactly as `RecordStore` does.
fn six_sharing_one_barrier() -> Vec<StoreAllocator> {
    let barrier = Arc::<SharedReuseBarrier>::default();
    (0..STORES)
        .map(|_| StoreAllocator::with_shared_barrier(Arc::clone(&barrier)))
        .collect()
}

/// **The property.** A freer watching the FIRST store waits until it can see the barrier armed, and
/// the instant it does, frees a slot in the LAST store. That free must be stamped.
///
/// With one shared atom the wait and the free observe the same value, so the stamp is guaranteed.
/// With six replicas armed in a loop from store 0 upwards, the freer is released by store 0's arming
/// and reaches store 5 before the arming does — the slot goes unstamped and is immediately reusable.
///
/// Non-vacuous twice over: the arming is verified to have been observed at all (otherwise the freer
/// never ran inside the window), and reverting `set` to a per-store loop makes it fail.
#[test]
fn a_free_after_the_barrier_is_visible_anywhere_is_stamped() {
    const ROUNDS: usize = 500;

    let mut observed_armed = 0usize;
    for round in 0..ROUNDS {
        let allocs = Arc::new(six_sharing_one_barrier());
        let go = Arc::new(AtomicBool::new(false));

        let freer = {
            let allocs = Arc::clone(&allocs);
            let go = Arc::clone(&go);
            std::thread::spawn(move || {
                // Wait until the barrier is visible THROUGH THE FIRST STORE...
                while !go.load(Ordering::Acquire) {
                    std::hint::spin_loop();
                }
                let saw_armed_on_first = allocs[0].armed_barrier().is_some();
                // ...then free in the LAST store, immediately.
                let id = (round as u64) + 1;
                allocs[STORES - 1].free_shadow_held(id);
                let stamped = allocs[STORES - 1].lock().is_shadow_held(id);
                (saw_armed_on_first, stamped)
            })
        };

        let armer = {
            let allocs = Arc::clone(&allocs);
            let go = Arc::clone(&go);
            std::thread::spawn(move || {
                // Release the freer and arm as close together as possible, so the free lands inside
                // the arming rather than comfortably after it.
                go.store(true, Ordering::Release);
                // Armed the way `RecordStore::set_reuse_barrier` used to: once per store, in order.
                // With one shared atom that is the same store repeated six times and stays atomic;
                // with a per-store replica it is the staggered window this test exists to catch.
                for a in allocs.iter() {
                    a.arm_reuse_barrier(Some(TICKET));
                }
            })
        };

        armer.join().expect("armer panicked");
        let (saw_armed_on_first, stamped) = freer.join().expect("freer panicked");

        if saw_armed_on_first {
            observed_armed += 1;
            assert!(
                stamped,
                "round {round}: the barrier was already visible through store 0, yet a free landing \
                 on store {} was NOT shadow-held. Its slot is immediately reusable, so a writer takes \
                 it and an off-thread reader that predates the free reads a stranger's record — the \
                 ACID Isolation violation `rmp` #588 closes (`rmp` #1025)",
                STORES - 1
            );
        }
    }

    // Vacuity control: if the freer never once saw the barrier armed, it never ran inside the window
    // and the assertion above never fired on anything.
    assert!(
        observed_armed > 0,
        "in {ROUNDS} rounds the freer never observed the barrier armed, so it never ran inside the \
         arming window and this test proved nothing. Raise ROUNDS."
    );
}

/// **Disarming is one act too.** The bracket clears the barrier before releasing the holds, so a
/// non-GC free that follows must NOT be stamped — a slot held for a reader that no longer exists is a
/// space leak that nothing lifts. Same shape, opposite direction.
#[test]
fn a_free_after_the_barrier_is_cleared_anywhere_is_not_stamped() {
    const ROUNDS: usize = 500;

    let mut observed_clear = 0usize;
    for round in 0..ROUNDS {
        let allocs = Arc::new(six_sharing_one_barrier());
        for a in allocs.iter() {
            a.arm_reuse_barrier(Some(TICKET));
        }
        let go = Arc::new(AtomicBool::new(false));

        let freer = {
            let allocs = Arc::clone(&allocs);
            let go = Arc::clone(&go);
            std::thread::spawn(move || {
                while !go.load(Ordering::Acquire) {
                    std::hint::spin_loop();
                }
                let saw_clear_on_first = allocs[0].armed_barrier().is_none();
                let id = (round as u64) + 1;
                allocs[STORES - 1].free_shadow_held(id);
                let stamped = allocs[STORES - 1].lock().is_shadow_held(id);
                (saw_clear_on_first, stamped)
            })
        };

        let disarmer = {
            let allocs = Arc::clone(&allocs);
            let go = Arc::clone(&go);
            std::thread::spawn(move || {
                go.store(true, Ordering::Release);
                // Cleared store by store, as the bracket used to — see the arming twin above.
                for a in allocs.iter() {
                    a.arm_reuse_barrier(None);
                }
            })
        };

        disarmer.join().expect("disarmer panicked");
        let (saw_clear_on_first, stamped) = freer.join().expect("freer panicked");

        if saw_clear_on_first {
            observed_clear += 1;
            assert!(
                !stamped,
                "round {round}: the barrier was already cleared as seen through store 0, yet a free \
                 on store {} was still shadow-held. The hold is for readers that predate a GC pass; \
                 stamping outside one leaks the slot until the next release (`rmp` #1025)",
                STORES - 1
            );
        }
    }

    assert!(
        observed_clear > 0,
        "in {ROUNDS} rounds the freer never observed the barrier cleared, so it never ran inside the \
         disarming window. Raise ROUNDS."
    );
}
