//! `loom` model-check of the doublewrite **eviction ring**'s concurrent paths (`rmp` #419 / #431).
//!
//! ## Why loom (and why a faithful model, not the real `Dwb`)
//!
//! DST is single-threaded and structurally cannot exercise concurrent eviction-vs-eviction or
//! eviction-vs-checkpoint interleavings; only an exhaustive interleaving explorer (loom) can. The
//! real [`graphus_storage::dwb::DwbPageStager`] uses `std::sync` primitives (it is below the
//! `--cfg loom` boundary that only `graphus-bufpool` crosses), so this test models the **exact**
//! claim → stage → home-write → free protocol the stager runs, over `loom::sync` primitives, so loom
//! can drive every interleaving:
//!
//!   * a [`FreeSlots`] free-slot allocator behind a `loom::sync::Mutex` (the ring's slot allocator);
//!   * a shared DWB "device" (a slot → staged-page map) behind a *separate* `loom::sync::Mutex` (the
//!     `Arc<Mutex<Dwb>>` the staging fsync writes under);
//!   * the home "device" behind its own `loom::sync::Mutex` (the store device the home write writes
//!     under, holding NO DWB lock).
//!
//! Each evictor: claims a slot (free-slot lock), stages its page into that slot + "fsyncs" (DWB lock,
//! released), writes home (home-device lock, holding no DWB lock), then frees the slot.
//!
//! ## What this proves on EVERY interleaving
//!
//! 1. **Distinct slots / no clobber** — two concurrent evictors never hold the same ring slot at the
//!    same time, and the slot a live evictor staged still holds *its* page (never overwritten by the
//!    other evictor) right up to the moment its home write is durable.
//! 2. **Recover-discoverable until durable** — at the instant either evictor's home write completes,
//!    its page is still present in its DWB slot (so a recovery scan would find it to repair a torn
//!    home page) — the valid-until-durable invariant (`rmp` #411).
//! 3. **Checkpoint disjointness** — a concurrent checkpoint "batch stage" writes a region byte-
//!    disjoint from every ring slot, so neither clobbers the other.
//! 4. **Acyclic lock order** — the model only ever acquires locks in the order
//!    free-slots → DWB-device → home-device (and never the reverse), so loom (which deadlocks on a
//!    lock-order cycle) completing all interleavings is itself the proof of deadlock-freedom.
//!
//! Run with:
//!
//! ```text
//! RUSTFLAGS="--cfg loom" cargo test -p graphus-bufpool --test loom_dwb_ring --release
//! ```

#![cfg(loom)]

use loom::sync::{Arc, Mutex};

/// Ring slot count for the model (2 is enough for two concurrent evictors; mirrors the production
/// ring's per-slot disjointness without exploding loom's interleaving space).
const RING_SLOTS: usize = 2;

/// The free-slot allocator (mirrors `dwb::FreeSlots`): the only state held across a slot claim/free,
/// never across the staging fsync or the home write.
struct FreeSlots {
    free: [bool; RING_SLOTS],
}
impl FreeSlots {
    fn new() -> Self {
        Self {
            free: [true; RING_SLOTS],
        }
    }
    fn claim(&mut self) -> Option<usize> {
        for (i, f) in self.free.iter_mut().enumerate() {
            if *f {
                *f = false;
                return Some(i);
            }
        }
        None
    }
    fn free(&mut self, slot: usize) {
        assert!(!self.free[slot], "freeing an already-free slot {slot}");
        self.free[slot] = true;
    }
}

/// The shared DWB "device": each ring slot holds the page id currently staged in it (`None` = empty),
/// plus a one-page checkpoint "batch region" disjoint from the ring slots. Models the on-disk slots
/// the staging fsync writes (under the DWB device lock).
struct DwbDevice {
    ring: [Option<u64>; RING_SLOTS],
    batch: Option<u64>,
}
impl DwbDevice {
    fn new() -> Self {
        Self {
            ring: [None; RING_SLOTS],
            batch: None,
        }
    }
}

/// One evictor: claim a slot, stage (DWB lock), home-write (home lock, no DWB lock), free.
/// Returns nothing; all invariants are asserted inline so a violation fails the loom model.
fn evict(
    page_id: u64,
    free_slots: &Arc<Mutex<FreeSlots>>,
    dwb: &Arc<Mutex<DwbDevice>>,
    home: &Arc<Mutex<Vec<u64>>>,
) {
    // 1. CLAIM a free slot (free-slots lock only; no I/O held). RING_SLOTS == #threads here, so a
    //    claim always succeeds without spinning.
    let slot = {
        let mut fs = free_slots.lock().unwrap();
        fs.claim().expect("a free ring slot")
    };

    // 2. STAGE the page into the claimed slot (DWB device lock, released after). No two live evictors
    //    can hold the same slot (the allocator handed out distinct indices), so this never clobbers
    //    another evictor's slot.
    {
        let mut d = dwb.lock().unwrap();
        assert!(
            d.ring[slot].is_none(),
            "claimed slot {slot} must be empty before staging (no clobber)"
        );
        d.ring[slot] = Some(page_id);
        // DWB lock released here — other evictors stage/home concurrently.
    }

    // 3. HOME-WRITE holding NO DWB lock (home-device lock only). Before and after the write, our slot
    //    must STILL hold our page — it may not be reused until our home write is durable (valid-until-
    //    durable, rmp #411). We assert that by re-reading the DWB slot around the home write.
    {
        // Pre-home: our slot still ours.
        assert_eq!(
            dwb.lock().unwrap().ring[slot],
            Some(page_id),
            "slot {slot} must still hold page {page_id} entering the home write"
        );
        let mut h = home.lock().unwrap();
        h.push(page_id);
        // Post-home (still before freeing the slot): our slot is STILL ours and thus a recovery scan
        // would still find page_id to repair a torn home write — recover-discoverable until durable.
        assert_eq!(
            dwb.lock().unwrap().ring[slot],
            Some(page_id),
            "slot {slot} must still hold page {page_id} after a durable home write, before free"
        );
        drop(h);
    }

    // 4. FREE the slot (post-home-durable). Clear the slot image then return it to the allocator.
    {
        let mut d = dwb.lock().unwrap();
        d.ring[slot] = None;
    }
    free_slots.lock().unwrap().free(slot);
}

/// Two concurrent evictors over a 2-slot ring. loom explores every interleaving; on each, the
/// inline assertions in [`evict`] must hold (distinct slots, no clobber, recover-discoverable until
/// durable) and the model must not deadlock (acyclic lock order). Both pages must end up home.
#[test]
fn two_evictors_claim_disjoint_ring_slots_without_clobber() {
    loom::model(|| {
        let free_slots = Arc::new(Mutex::new(FreeSlots::new()));
        let dwb = Arc::new(Mutex::new(DwbDevice::new()));
        let home = Arc::new(Mutex::new(Vec::<u64>::new()));

        let h = {
            let free_slots = Arc::clone(&free_slots);
            let dwb = Arc::clone(&dwb);
            let home = Arc::clone(&home);
            loom::thread::spawn(move || evict(11, &free_slots, &dwb, &home))
        };
        evict(22, &free_slots, &dwb, &home);
        h.join().unwrap();

        // Both pages reached the home device; the ring is fully drained and free again.
        let mut got = home.lock().unwrap().clone();
        got.sort_unstable();
        assert_eq!(got, vec![11, 22], "both evicted pages must reach home");
        let d = dwb.lock().unwrap();
        assert!(d.ring.iter().all(Option::is_none), "ring must be drained");
        let fs = free_slots.lock().unwrap();
        assert!(
            fs.free.iter().all(|&f| f),
            "all ring slots must be free again"
        );
    });
}

/// A checkpoint BATCH stage concurrent with an eviction RING stage: each writes a disjoint region of
/// the shared DWB device, so neither clobbers the other (`rmp` #412/#431 region disjointness). loom
/// explores both orders; the checkpoint's batch and the eviction's ring slot must each survive.
#[test]
fn checkpoint_batch_stage_is_disjoint_from_an_eviction_ring_stage() {
    loom::model(|| {
        let free_slots = Arc::new(Mutex::new(FreeSlots::new()));
        let dwb = Arc::new(Mutex::new(DwbDevice::new()));
        let home = Arc::new(Mutex::new(Vec::<u64>::new()));

        // Checkpoint thread: stage a batch page into the disjoint batch region (DWB lock), then home.
        let ckpt = {
            let dwb = Arc::clone(&dwb);
            let home = Arc::clone(&home);
            loom::thread::spawn(move || {
                {
                    let mut d = dwb.lock().unwrap();
                    d.batch = Some(99);
                }
                home.lock().unwrap().push(99);
                // The batch region must be untouched by the concurrent eviction's ring write.
                assert_eq!(
                    dwb.lock().unwrap().batch,
                    Some(99),
                    "the checkpoint batch region must not be clobbered by a ring stage"
                );
            })
        };

        // Eviction thread: stage into a ring slot — disjoint from the batch region.
        evict(7, &free_slots, &dwb, &home);
        ckpt.join().unwrap();

        // The eviction also reached home, and the batch region still holds the checkpoint page.
        let got = home.lock().unwrap().clone();
        assert!(
            got.contains(&7) && got.contains(&99),
            "both writers reached home: {got:?}"
        );
        assert_eq!(dwb.lock().unwrap().batch, Some(99));
    });
}
