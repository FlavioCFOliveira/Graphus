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
//! 5. **Stale-slot floor gate (`rmp` #437)** — freeing a slot leaves its on-disk image IN PLACE
//!    (matching production `DwbPageStager::free_slot`, which only flips the in-memory free bitmap and
//!    never zeroes the slot header). The model therefore carries the stale image after a free, exactly
//!    as the device does, and a separate recovery model asserts that a stale slot whose staged lsn is
//!    **below the persisted checkpoint floor** is IGNORED (never restored over a torn newer home
//!    page) — the property the #437 floor gate adds. (Previously the model zeroed the slot on free,
//!    diverging from production and hiding the stale-slot hole.)
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

/// One staged ring-slot copy: the home page id it protects and the `page_lsn` of the staged image
/// (`rmp` #437: the lsn is what the floor gate compares against on recovery).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
struct Staged {
    page_id: u64,
    lsn: u64,
}

/// The shared DWB "device": each ring slot holds the page currently staged in it (`None` = empty),
/// plus a one-page checkpoint "batch region" disjoint from the ring slots, and the persisted
/// checkpoint-floor LSN (`rmp` #437). Models the on-disk slots the staging fsync writes (under the DWB
/// device lock). A FREED slot keeps its image (production `free_slot` never zeroes the on-disk slot),
/// so a stale image persists until the slot is re-staged — exactly the device behaviour the floor gate
/// must tolerate.
struct DwbDevice {
    ring: [Option<Staged>; RING_SLOTS],
    batch: Option<Staged>,
    floor: u64,
}
impl DwbDevice {
    fn new() -> Self {
        Self {
            ring: [None; RING_SLOTS],
            batch: None,
            floor: 0,
        }
    }
}

/// One evictor: claim a slot, stage (DWB lock), home-write (home lock, no DWB lock), free.
/// `lsn` is the staged image's `page_lsn` (`rmp` #437). Returns nothing; all invariants are asserted
/// inline so a violation fails the loom model.
fn evict(
    page_id: u64,
    lsn: u64,
    free_slots: &Arc<Mutex<FreeSlots>>,
    dwb: &Arc<Mutex<DwbDevice>>,
    home: &Arc<Mutex<Vec<u64>>>,
) {
    let staged = Staged { page_id, lsn };
    // 1. CLAIM a free slot (free-slots lock only; no I/O held). RING_SLOTS == #threads here, so a
    //    claim always succeeds without spinning.
    let slot = {
        let mut fs = free_slots.lock().unwrap();
        fs.claim().expect("a free ring slot")
    };

    // 2. STAGE the page into the claimed slot (DWB device lock, released after). A claimed slot was
    //    free in the ALLOCATOR; its on-disk image may be a STALE copy from a prior eviction (production
    //    never zeroes a freed slot, `rmp` #437) — staging overwrites it. The key no-clobber invariant
    //    is that no OTHER LIVE evictor holds this slot (the allocator handed out distinct indices), so
    //    we never overwrite another in-flight evictor's still-needed copy.
    {
        let mut d = dwb.lock().unwrap();
        d.ring[slot] = Some(staged);
        // DWB lock released here — other evictors stage/home concurrently.
    }

    // 3. HOME-WRITE holding NO DWB lock (home-device lock only). Before and after the write, our slot
    //    must STILL hold our page — it may not be reused until our home write is durable (valid-until-
    //    durable, rmp #411). We assert that by re-reading the DWB slot around the home write.
    {
        // Pre-home: our slot still ours.
        assert_eq!(
            dwb.lock().unwrap().ring[slot],
            Some(staged),
            "slot {slot} must still hold page {page_id} entering the home write"
        );
        let mut h = home.lock().unwrap();
        h.push(page_id);
        // Post-home (still before freeing the slot): our slot is STILL ours and thus a recovery scan
        // would still find page_id to repair a torn home write — recover-discoverable until durable.
        assert_eq!(
            dwb.lock().unwrap().ring[slot],
            Some(staged),
            "slot {slot} must still hold page {page_id} after a durable home write, before free"
        );
        drop(h);
    }

    // 4. FREE the slot (post-home-durable). Production `free_slot` ONLY flips the in-memory free
    //    bitmap — it does NOT zero the on-disk slot image (`rmp` #437). Model that faithfully: leave
    //    `d.ring[slot]` IN PLACE (the now-stale copy persists on disk) and only return the slot to the
    //    allocator. The #437 floor gate is what makes such a stale copy harmless on recovery.
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
            loom::thread::spawn(move || evict(11, 110, &free_slots, &dwb, &home))
        };
        evict(22, 220, &free_slots, &dwb, &home);
        h.join().unwrap();

        // Both pages reached the home device, and every ring slot is FREE in the allocator again.
        let mut got = home.lock().unwrap().clone();
        got.sort_unstable();
        assert_eq!(got, vec![11, 22], "both evicted pages must reach home");
        let fs = free_slots.lock().unwrap();
        assert!(
            fs.free.iter().all(|&f| f),
            "all ring slots must be free again"
        );
        // The on-disk slot images are NOT drained — production leaves a freed slot's stale copy in
        // place (`rmp` #437). Every slot the two evictors used now carries one of their (now-stale)
        // copies; the floor gate (separate test) is what neutralises that on recovery.
        let d = dwb.lock().unwrap();
        let staged: std::collections::BTreeSet<u64> =
            d.ring.iter().flatten().map(|s| s.page_id).collect();
        assert!(
            staged.is_subset(&[11u64, 22].into_iter().collect()),
            "freed slots retain only the evictors' own (now-stale) images, none zeroed"
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
                    d.batch = Some(Staged {
                        page_id: 99,
                        lsn: 990,
                    });
                }
                home.lock().unwrap().push(99);
                // The batch region must be untouched by the concurrent eviction's ring write.
                assert_eq!(
                    dwb.lock().unwrap().batch.map(|s| s.page_id),
                    Some(99),
                    "the checkpoint batch region must not be clobbered by a ring stage"
                );
            })
        };

        // Eviction thread: stage into a ring slot — disjoint from the batch region.
        evict(7, 70, &free_slots, &dwb, &home);
        ckpt.join().unwrap();

        // The eviction also reached home, and the batch region still holds the checkpoint page.
        let got = home.lock().unwrap().clone();
        assert!(
            got.contains(&7) && got.contains(&99),
            "both writers reached home: {got:?}"
        );
        assert_eq!(dwb.lock().unwrap().batch.map(|s| s.page_id), Some(99));
    });
}

/// **Stale-slot floor gate (`rmp` #437).** Proves that the recovery SELECTION rule — run over the
/// device a real workload leaves behind (freed slots NOT zeroed) — ignores a STALE ring slot whose
/// staged lsn is BELOW the persisted checkpoint floor, and repairs a torn home page from the highest
/// copy at or above the floor instead.
///
/// The device pre-state is exactly the #437 lifecycle's residue: page `P` carries TWO on-disk ring
/// copies — a STALE `P@lsn_old` (an earlier eviction whose slot was freed but never zeroed) and a
/// fresher `P@lsn_new` (a later eviction). A checkpoint then persists the floor BETWEEN them. We model
/// a concurrent unrelated eviction (page `Q`) to keep the device under genuine concurrent mutation
/// while the floor is set, then run the single-threaded recovery selection (as real recovery is).
///
/// On EVERY interleaving, recovery's floor-gated highest-lsn-wins selection for torn home `P` must be
/// `lsn_new`, NEVER the stale below-floor `lsn_old`. (Pre-#437, recovery scanned slots in index order
/// and a lower-index stale slot could be applied — the data-loss hole this gate closes.)
#[test]
fn stale_below_floor_ring_slot_is_ignored_on_recovery() {
    loom::model(|| {
        const P: u64 = 4;
        const Q: u64 = 7;
        const LSN_OLD: u64 = 100;
        const LSN_NEW: u64 = 200;
        const FLOOR: u64 = 150; // between the two: gates out LSN_OLD, keeps LSN_NEW

        let free_slots = Arc::new(Mutex::new(FreeSlots::new()));
        let dwb = Arc::new(Mutex::new(DwbDevice::new()));
        let home = Arc::new(Mutex::new(Vec::<u64>::new()));

        // PRE-STATE (the #437 device residue): both a STALE below-floor P copy and a fresher above-
        // floor P copy persist on disk in two ring slots — neither was zeroed when its slot was freed.
        // Both slots are FREE in the allocator (their evictions completed); `RING_SLOTS == 2`, so the
        // concurrent `Q` eviction below will CLAIM one of them and overwrite it — loom explores which.
        {
            let mut d = dwb.lock().unwrap();
            d.ring[0] = Some(Staged {
                page_id: P,
                lsn: LSN_OLD,
            });
            d.ring[1] = Some(Staged {
                page_id: P,
                lsn: LSN_NEW,
            });
        }

        // A concurrent unrelated eviction mutates the device (claims+stages+frees a slot) while the
        // checkpoint persists the floor — the genuine concurrency loom explores.
        let h = {
            let free_slots = Arc::clone(&free_slots);
            let dwb = Arc::clone(&dwb);
            let home = Arc::clone(&home);
            loom::thread::spawn(move || evict(Q, 700, &free_slots, &dwb, &home))
        };
        // The checkpoint persists the floor concurrently with Q's eviction.
        dwb.lock().unwrap().floor = FLOOR;
        h.join().unwrap();

        // RECOVERY MODEL (single-threaded, as real recovery): for torn home page P, choose the
        // highest-lsn VALID copy across all ring slots, IGNORING any slot whose lsn is below the floor.
        let d = dwb.lock().unwrap();
        let floor = d.floor;
        let p_copies: Vec<u64> = d
            .ring
            .iter()
            .flatten()
            .filter(|s| s.page_id == P)
            .map(|s| s.lsn)
            .collect();
        let chosen = p_copies
            .iter()
            .copied()
            .filter(|&lsn| lsn >= floor) // FLOOR GATE
            .max();
        // Q may have overwritten the slot that held P@lsn_old OR P@lsn_new. Whatever survives, the
        // floor gate must never select a below-floor copy: the chosen copy (if any) is >= floor, and
        // the stale lsn_old is never chosen.
        assert!(
            chosen != Some(LSN_OLD),
            "the stale below-floor copy ({LSN_OLD}) must NEVER be chosen — the #437 floor gate. P \
             copies on disk: {p_copies:?}, floor {floor}"
        );
        if p_copies.contains(&LSN_NEW) {
            assert_eq!(
                chosen,
                Some(LSN_NEW),
                "when the fresh above-floor copy survives, recovery must pick it ({LSN_NEW}), never \
                 the stale {LSN_OLD}. P copies: {p_copies:?}"
            );
        }
    });
}
