//! Regression gate for `rmp` #412 — the checkpoint-vs-eviction doublewrite region-clobber hole.
//!
//! ## The bug (`rmp` #412, the third in the DWB-region class after `rmp` #407 / `rmp` #411)
//!
//! Before the fix the doublewrite area held a **single** region used by BOTH writers:
//!
//! * the **checkpoint** path — [`graphus_storage::dwb::Dwb::stage_batch`] via
//!   [`graphus_bufpool::ConcurrentBufferPool::flush_pages`] Phase 3a / `RecordStore::flush_protected`
//!   — stages a batch of dirty home pages, `sync_data`s the DWB, **releases the DWB lock**, and only
//!   THEN writes the batch to its home locations (Phase 3b);
//! * the per-**eviction** path — [`graphus_storage::dwb::DwbPageStager::stage_and_sync`] — stages one
//!   stolen dirty page (the production reader pool, `rmp` #336, is NOT quiesced during a checkpoint).
//!
//! A concurrent eviction landing in the checkpoint's 3a→3b gap called `stage_batch` and **overwrote
//! the single region**. If a checkpoint home write then tore at a power loss,
//! [`graphus_storage::dwb::Dwb::recover_home`] read the single region, found only the **evictor's**
//! page, and the checkpoint's torn home page was **UNRECOVERABLE** — ARIES redo then read a garbage
//! `page_lsn` from the torn page and skipped its repair: latent corruption, the exact failure the
//! doublewrite buffer exists to prevent. Reproduced as `recover_home == 0` for the checkpoint page.
//!
//! ## The fix (`rmp` #412): two disjoint regions
//!
//! The DWB device now carries TWO disjoint regions — a BATCH region (checkpoint path) and a
//! single-page EVICTION region (per-eviction path) — that never overlap on disk. `stage_batch` writes
//! ONLY the batch region; `stage_and_sync`/`stage_eviction` writes ONLY the eviction region; and
//! `recover_home` scans BOTH region headers and repairs every torn home page found in either. A
//! concurrent checkpoint and eviction now touch disjoint bytes and cannot clobber each other, so the
//! checkpoint's batch copy survives an interleaved eviction and a torn checkpoint home page is
//! repairable.
//!
//! This gate drives the **real** [`Dwb`] and [`DwbPageStager`] over a shared in-memory device,
//! reproducing the exact 3a→3b interleaving: stage a checkpoint batch, then (in the gap) run a
//! concurrent eviction stage, then tear a checkpoint home page and assert it is repaired. Before the
//! fix the eviction's stage overwrote the single region and the checkpoint page's `repaired == 0`;
//! after the fix the disjoint eviction region leaves the checkpoint batch intact and it is repaired.

use std::sync::{Arc, Mutex};

use graphus_bufpool::{PageStager, page};
use graphus_core::PageId;
use graphus_core::error::Result;
use graphus_io::{BlockDevice, MemBlockDevice, PAGE_SIZE, Page};
use graphus_storage::dwb::{Dwb, DwbPageStager};

/// Builds a valid, checksummed page that self-identifies as `id` with `page_lsn` and a body fill.
fn make_page(id: u64, lsn: u64, fill: u8) -> Page {
    let mut p = [fill; PAGE_SIZE];
    page::set_page_id(&mut p, id);
    page::set_page_lsn(&mut p, graphus_core::Lsn(lsn));
    page::write_checksum(&mut p);
    p
}

/// The checkpoint batch covers two home pages; a concurrent eviction stages a third page **in the
/// gap between the checkpoint's DWB sync and its home writes** (the checkpoint releases the DWB lock
/// before writing home, so an eviction can interleave there). One of the checkpoint's home pages then
/// tears (a power loss mid home write). After recovery that checkpoint page MUST be repaired — its
/// doublewrite copy must not have been overwritten by the interleaved eviction.
///
/// Fails before the `rmp` #412 fix (`repaired == 0` for the checkpoint page: the eviction's
/// `stage_batch` overwrote the single shared region between the checkpoint's stage and the crash, so
/// the checkpoint copy is gone). Passes after (the eviction stages into the disjoint eviction region,
/// leaving the checkpoint batch region intact, so the torn checkpoint page is repaired).
#[test]
fn checkpoint_batch_page_survives_interleaved_eviction_and_is_repaired() {
    const CKPT_A: u64 = 3; // checkpoint batch page that will tear
    const CKPT_B: u64 = 4; // checkpoint batch page (intact)
    const EVICT_C: u64 = 9; // the page a concurrent eviction stages in the gap

    let dwb_dev = MemBlockDevice::new(0);
    let dwb = Arc::new(Mutex::new(Dwb::new(dwb_dev).expect("dwb")));
    let stager: Arc<dyn PageStager> = Arc::new(DwbPageStager::new(Arc::clone(&dwb)));

    // The home device. Page CKPT_A's home write will tear (CRC fails) — the power loss.
    let mut home = MemBlockDevice::new(16);
    home.arm_torn_write(PageId(CKPT_A), 16);

    let ckpt_a = make_page(CKPT_A, 100, 0xA1);
    let ckpt_b = make_page(CKPT_B, 101, 0xB2);
    let evict_c = make_page(EVICT_C, 200, 0xC3);

    // --- Phase 3a (checkpoint): stage the whole batch into the DWB and sync, then RELEASE the DWB
    // lock (the real `flush_pages`/`stage_batch_and_sync` releases the lock before its home writes).
    let ckpt_batch: [(PageId, &[u8]); 2] =
        [(PageId(CKPT_A), &ckpt_a[..]), (PageId(CKPT_B), &ckpt_b[..])];
    stager
        .stage_batch_and_sync(&ckpt_batch)
        .expect("checkpoint stage_batch_and_sync");
    // (lock released — exactly the 3a→3b gap)

    // --- In the gap: a concurrent EVICTION stages a stolen dirty page and writes it home. Before the
    // fix this `stage_batch` (now `stage_eviction`) reused the single region; after the fix it writes
    // the disjoint eviction region. Its home write (and durable sync) runs inside the stager callback.
    {
        let mut home_write = || -> Result<()> {
            home.write_page(PageId(EVICT_C), &evict_c)?;
            home.sync_data()
        };
        stager
            .stage_and_sync(PageId(EVICT_C), &evict_c[..], &mut home_write)
            .expect("eviction stage+home");
    }

    // --- Phase 3b (checkpoint): now write the checkpoint batch home. CKPT_A's write tears (power
    // loss); CKPT_B lands intact. Then the crash.
    home.write_page(PageId(CKPT_A), &ckpt_a)
        .expect("write A (torn)");
    home.write_page(PageId(CKPT_B), &ckpt_b).expect("write B");
    home.sync_data().expect("sync home");

    // Precondition: CKPT_A is torn on its home device.
    let mut a_disk: Page = [0u8; PAGE_SIZE];
    home.read_page(PageId(CKPT_A), &mut a_disk).expect("read A");
    assert!(
        !page::verify_checksum(&a_disk),
        "precondition: checkpoint page A's home write must be torn on disk"
    );

    // --- Recovery (run before redo): `recover_home` scans BOTH regions and must repair the torn
    // checkpoint page A from the checkpoint batch region (which the interleaved eviction left intact).
    drop(stager); // release the stager's clone of the shared DWB so we can reclaim it
    let mut dwb = Arc::try_unwrap(dwb)
        .unwrap_or_else(|_| panic!("dwb still shared"))
        .into_inner()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let repaired = dwb.recover_home(&mut home).expect("recover_home");

    // THE GATE: the torn checkpoint page must be repaired. Before the fix the eviction overwrote the
    // single region in the 3a→3b gap, so the checkpoint copy was gone and `recover_home` could not
    // restore A (`repaired == 0` for A) — latent, unrecoverable corruption.
    assert!(
        repaired >= 1,
        "torn checkpoint home page A must be repaired from the DWB batch region — the interleaved \
         eviction must not have clobbered it (rmp #412). repaired={repaired}"
    );
    let mut a_fixed: Page = [0u8; PAGE_SIZE];
    home.read_page(PageId(CKPT_A), &mut a_fixed)
        .expect("reread A");
    assert!(
        page::verify_checksum(&a_fixed),
        "checkpoint page A must be intact after doublewrite repair"
    );
    assert_eq!(
        &a_fixed[..],
        &ckpt_a[..],
        "repaired A must equal its staged checkpoint DWB copy"
    );
}
