//! Regression gate for `rmp` #437 — the **persisted checkpoint-floor LSN** that closes the
//! doublewrite **stale-eviction-ring-slot committed-data-loss** hole.
//!
//! ## The bug (`rmp` #437, F-STG-1)
//!
//! Eviction-ring slots are freed only in memory ([`DwbPageStager`]'s `free_slot`); the on-disk slot
//! header is never zeroed, so a **stale** ring slot — an old eviction copy of a page that was later
//! re-written and flushed home — lingers on disk indefinitely. On recovery, when the page's *newer*
//! home write tears, the old recovery code (which restored a torn home from *any* checksum-valid DWB
//! copy, with its lsn guard a no-op for a torn home) restored the STALE older image over the torn
//! newer one — silently reverting a committed change once the WAL records that would have rolled it
//! forward had been reclaimed by a checkpoint. That is a Durability + Atomicity (ACID) violation and a
//! deviation from `05 §3` ("restored from its INTACT doublewrite copy" assumes intact AND current).
//!
//! ## The fix (`rmp` #437, option (b))
//!
//! Each checkpoint persists a **floor LSN** (its WAL reclaim floor) durably in the DWB batch region
//! header, *before* the WAL prefix below it is reclaimed. On recovery, a ring slot whose staged
//! `page_lsn` is **below** the floor is provably superseded (its home was flushed durably by that
//! checkpoint) and is **ignored** — never a repair candidate. Recovery also chooses the **highest-lsn**
//! valid copy across all regions, so a stale older copy can never beat a fresher one. If a torn home
//! page has no valid copy at or above the floor, recovery surfaces an **unrepairable fault** rather
//! than silently restoring the stale pre-floor copy.
//!
//! These gates prove:
//!   1. a stale below-floor ring slot is IGNORED — recovery does NOT revert the page to the old image;
//!   2. with a fresher copy present (batch region), recovery picks it (highest-lsn-wins);
//!   3. the floor is persisted durably and survives `clear()` (the per-checkpoint batch invalidation).

use graphus_bufpool::page;
use graphus_core::{Lsn, PageId};
use graphus_io::{BlockDevice, MemBlockDevice, PAGE_SIZE, Page};
use graphus_storage::dwb::Dwb;

fn make_page(id: u64, lsn: u64, fill: u8) -> Page {
    let mut p = [fill; PAGE_SIZE];
    page::set_page_id(&mut p, id);
    page::set_page_lsn(&mut p, Lsn(lsn));
    page::write_checksum(&mut p);
    p
}

fn torn(of: &Page) -> Page {
    let mut t = *of;
    t[100..].iter_mut().for_each(|b| *b = 0); // zero the body so the CRC32C fails => torn
    assert!(
        !page::verify_checksum(&t),
        "the torn image must fail its checksum"
    );
    t
}

/// THE #437 GATE: a STALE below-floor ring slot must NOT win over a fresher above-floor copy of the
/// same torn home page (highest-lsn-wins + floor gate together).
///
/// Mirrors the production lifecycle where a hot page is evicted twice via the ring:
///   1. evict P@lsn100 into ring slot 5, home write completes → on-disk slot 5 is now STALE;
///   2. P is re-written to lsn200 and evicted into ring slot 9 (still on disk, an in-flight eviction
///      whose home write is the one that tears);
///   3. a checkpoint persists the floor at lsn150 (between the two) and reclaims the (100,150] WAL;
///   4. the crash tears P's lsn200 home write;
///   5. recovery: slot 5's lsn100 is BELOW the floor (150) → ignored; slot 9's lsn200 is ABOVE the
///      floor and is the highest-lsn valid copy → P is repaired to lsn200, NOT reverted to lsn100.
///
/// Pre-#437, recovery scanned the batch region then every ring slot in index order and restored from
/// whichever torn-home copy it found — so a stale lower-index slot could overwrite a fresher one. Now
/// the floor gates out the stale copy and highest-lsn-wins picks lsn200.
#[test]
fn stale_below_floor_ring_slot_does_not_beat_a_fresher_above_floor_copy() {
    const P: u64 = 4;
    let mut dwb = Dwb::new(MemBlockDevice::new(0)).expect("dwb");

    // 1. STALE older copy of P in ring slot 5 (lsn100, below the coming floor).
    let old = make_page(P, 100, 0xA1);
    dwb.stage_eviction_slot(5, PageId(P), &old)
        .expect("stage stale slot 5");
    // 2. FRESHER copy of P in ring slot 9 (lsn200, above the coming floor) — the in-flight eviction.
    let new = make_page(P, 200, 0xB2);
    dwb.stage_eviction_slot(9, PageId(P), &new)
        .expect("stage fresh slot 9");
    // 3. Checkpoint persists the floor at lsn150 (gates out slot 5, keeps slot 9).
    dwb.set_floor(Lsn(150)).expect("persist floor 150");

    // 4. The crash tears P's lsn200 home write.
    let mut home = MemBlockDevice::new(8);
    home.write_page(PageId(P), &torn(&new)).unwrap();
    home.sync_data().unwrap();

    // 5. Recovery: floor=150 gates out the stale slot-5 lsn100; slot-9 lsn200 (highest valid) repairs.
    let repaired = dwb.recover_home(&mut home).expect("recover");
    assert_eq!(
        repaired, 1,
        "P must be repaired from the highest-lsn (lsn200) copy"
    );

    let mut got: Page = [0u8; PAGE_SIZE];
    home.read_page(PageId(P), &mut got).unwrap();
    assert!(page::verify_checksum(&got), "repaired home must be intact");
    assert_eq!(
        page::page_lsn(&got),
        Lsn(200),
        "CRITICAL #437: recovery must restore the CURRENT lsn200 image, NOT revert to the stale \
         below-floor ring-slot lsn100 (which a lower index would have applied pre-#437)"
    );
    assert_eq!(
        &got[..],
        &new[..],
        "home must equal the fresh lsn200 image byte-for-byte"
    );
}

/// The floor gate must SURFACE an unrepairable fault (never silently revert) when a torn home page's
/// ONLY doublewrite copy is a stale below-floor ring slot — the correct image is unavailable.
///
/// Models the worst case: P@lsn100 in stale slot 5, P later re-written to lsn200 whose DWB slot was
/// reused (so no lsn200 copy survives in the DWB), checkpoint floor at 150, P's lsn200 home torn. The
/// stale lsn100 is gated out and there is no copy ≥ floor → recovery returns an error rather than
/// silently restoring lsn100.
#[test]
fn torn_home_with_only_a_stale_below_floor_copy_surfaces_a_fault() {
    const P: u64 = 4;
    let mut dwb = Dwb::new(MemBlockDevice::new(0)).expect("dwb");

    // Only a STALE below-floor ring slot for P (no batch/ring copy of the newer lsn200).
    let old = make_page(P, 100, 0xA1);
    dwb.stage_eviction_slot(5, PageId(P), &old)
        .expect("stage stale slot 5");
    dwb.set_floor(Lsn(150)).expect("persist floor 150");

    let mut home = MemBlockDevice::new(8);
    let new = make_page(P, 200, 0xB2);
    home.write_page(PageId(P), &torn(&new)).unwrap();
    home.sync_data().unwrap();

    let r = dwb.recover_home(&mut home);
    assert!(
        r.is_err(),
        "a torn home whose only DWB copy is a stale below-floor ring slot must surface an \
         unrepairable fault, never silently revert to the stale image (rmp #437)"
    );
    // The home page must NOT have been reverted to the stale lsn100 image.
    let mut got: Page = [0u8; PAGE_SIZE];
    home.read_page(PageId(P), &mut got).unwrap();
    assert_ne!(
        page::page_lsn(&got),
        Lsn(100),
        "the stale below-floor image must NOT have been written home"
    );
}

/// A ring slot AT OR ABOVE the floor is still a legitimate repair (the floor gate must not over-reject
/// an in-flight eviction's own torn write — the original #431 case).
#[test]
fn ring_slot_at_or_above_floor_still_repairs() {
    const P: u64 = 3;
    let mut dwb = Dwb::new(MemBlockDevice::new(0)).expect("dwb");
    // Floor at 100; the eviction copy is at lsn150 (>= floor) — the in-flight eviction whose own home
    // write tears. It MUST repair.
    dwb.set_floor(Lsn(100)).expect("floor 100");
    let img = make_page(P, 150, 0xC3);
    dwb.stage_eviction_slot(2, PageId(P), &img)
        .expect("stage slot 2");

    let mut home = MemBlockDevice::new(8);
    home.write_page(PageId(P), &torn(&img)).unwrap();
    home.sync_data().unwrap();

    let repaired = dwb.recover_home(&mut home).expect("recover");
    assert_eq!(
        repaired, 1,
        "an at-or-above-floor ring slot must still repair its torn home"
    );
    let mut got: Page = [0u8; PAGE_SIZE];
    home.read_page(PageId(P), &mut got).unwrap();
    assert_eq!(
        page::page_lsn(&got),
        Lsn(150),
        "repaired from the lsn150 ring copy"
    );
}

/// The persisted floor must SURVIVE `clear()` (the per-checkpoint batch invalidation): clearing the
/// batch must not drop the floor to 0 (which would re-open the stale-slot hole on the next open).
#[test]
fn floor_survives_clear_and_reopen() {
    let dwb_dev = MemBlockDevice::new(0);
    let mut dwb = Dwb::new(dwb_dev).expect("dwb");
    dwb.set_floor(Lsn(4242)).expect("set floor");
    assert_eq!(dwb.floor(), Lsn(4242));
    // clear() empties the batch but must keep the floor.
    dwb.clear().expect("clear");
    assert_eq!(
        dwb.floor(),
        Lsn(4242),
        "clear() must preserve the persisted floor"
    );
    // The floor must be DURABLE: a fresh Dwb over the same device reads it back.
    let dev = dwb.into_device();
    let reopened = Dwb::new(dev).expect("reopen");
    assert_eq!(
        reopened.floor(),
        Lsn(4242),
        "the floor must persist durably across reopen (it gates ring recovery)"
    );
}

/// The floor is MONOTONIC: a smaller `set_floor` is a no-op (a checkpoint never moves the recovery
/// floor backwards, which would widen the window of honoured stale slots).
#[test]
fn floor_is_monotonic() {
    let mut dwb = Dwb::new(MemBlockDevice::new(0)).expect("dwb");
    dwb.set_floor(Lsn(500)).expect("floor 500");
    dwb.set_floor(Lsn(300)).expect("smaller floor is a no-op");
    assert_eq!(dwb.floor(), Lsn(500), "the floor must never move backwards");
    dwb.set_floor(Lsn(900)).expect("floor 900");
    assert_eq!(dwb.floor(), Lsn(900), "a larger floor advances");
}
