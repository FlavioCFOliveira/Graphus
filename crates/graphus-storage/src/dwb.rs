//! Doublewrite buffer (DWB) — torn-write protection for home data pages
//! (`specification/05-storage-format.md` §3, `04-technical-design.md` §4.5).
//!
//! A logical page (8 KiB) spans several device sectors; a power loss mid-write can leave a **torn
//! page** — some sectors new, some old — whose CRC32C checksum (`graphus_bufpool::page`) fails and
//! which ARIES redo *cannot* repair on its own: redo gates each change on the page's own `page_lsn`
//! (`recovery.rs`: `record.lsn > page.page_lsn`), but a torn page's header — and therefore its
//! `page_lsn` — is itself garbage. A torn home page that happens to decode to a `page_lsn` greater
//! than or equal to a logged change's LSN has that redo **skipped**, and the corrupt page is served:
//! latent corruption under power loss for any page larger than a device sector. This is the last
//! durability hole in the crash-recovery component, recorded by the DST harness as the deferred
//! `TornDataPage` fault.
//!
//! ## Decision: doublewrite buffer (over full-page-writes)
//!
//! `05 §3` ratifies the **doublewrite buffer** (InnoDB-style) over full-page-writes: it keeps the
//! WAL lean (no per-checkpoint full-page images inflating commit I/O), is a bounded constant-size
//! overhead, and composes cleanly with per-page checksums — the checksum is the torn-page
//! *detector*, the DWB is the *repair*. This module implements exactly that decision.
//!
//! ## Protocol (write side, [`Dwb::stage_batch`])
//!
//! Before a batch of dirty home pages is written to its **home** locations:
//!
//! 1. write each page image into a DWB **data slot**, then write the DWB **header slot** recording
//!    how many data slots the batch occupies and the home `PageId` of each;
//! 2. **`sync_data` the DWB device** — the whole batch is now durable in the DWB;
//! 3. only then may the caller write the pages to their home locations and sync the home device.
//!
//! This is the standard InnoDB ordering: the DWB copy is durable *before* the home write begins, so
//! at every crash point one intact copy of each in-flight page exists — either the (now durable) DWB
//! copy, or the old home page (the home write had not started), or the new home page (the home write
//! completed). A torn home page is the only failure the DWB must repair, and the DWB copy is then
//! guaranteed intact.
//!
//! ## Protocol (recovery side, [`Dwb::recover_home`])
//!
//! Run **before** ARIES redo. For each occupied, checksum-valid DWB data slot, read its home page;
//! if the home page **fails its checksum** (torn), restore it verbatim from the DWB copy and write it
//! home. Then sync the home device. After this pass every home page either is intact as last written
//! or has been replaced by the last fully-written image the DWB captured, so redo reads a trustworthy
//! `page_lsn` from every page and its `record.lsn > page_lsn` gate is sound again.
//!
//! A DWB whose header slot does not decode (a crash *during* the DWB write itself, before the batch
//! was made durable) describes **no** committed batch: there is nothing to repair, because the home
//! write for that batch had not yet begun (the home write only starts after the DWB sync returns).
//! Recovery treats that as an empty DWB — the safe, committed-or-nothing outcome.
//!
//! ## Two disjoint regions (`rmp` #412): batch region + eviction region
//!
//! The doublewrite area is shared by two independent writers: the **checkpoint** path
//! ([`Dwb::stage_batch`] for the dirty-page checkpoint/flush, via
//! [`DwbPageStager::stage_batch_and_sync`]) and the per-eviction **steal** path
//! ([`DwbPageStager::stage_and_sync`]). When both shared a single on-disk region, a concurrent
//! eviction could overwrite the region between a checkpoint's DWB sync and its home write (the
//! checkpoint releases the DWB lock before its home writes), destroying the checkpoint's only intact
//! copy of an in-flight page — a torn checkpoint home page then became unrepairable (`rmp` #412,
//! reopening the `rmp` #411 / `rmp` #407 hole across the two paths).
//!
//! The fix is structural: the device carries **two disjoint regions**, each with its own header and
//! data slots, that never overlap on disk:
//!
//! * the **BATCH region** (pages `0 ..= DWB_MAX_BATCH`) — used **only** by the checkpoint path; one
//!   header slot plus up to [`DWB_MAX_BATCH`] data slots;
//! * the **EVICTION region** (pages `DWB_MAX_BATCH+1 ..= DWB_MAX_BATCH+2`) — used **only** by the
//!   per-eviction path; one header slot plus one data slot (the eviction path stages exactly one page
//!   at a time and is serialised by the DWB lock held across its stage+home-write, `rmp` #411).
//!
//! A concurrent checkpoint and eviction now touch **disjoint bytes** and cannot clobber each other.
//! [`Dwb::recover_home`] scans **both** region headers and repairs every torn home page found in
//! either, so a torn page from either writer is recovered. The batch region's layout is byte-for-byte
//! identical to the pre-#412 single region (header at page 0, data at pages `1..`), so the only
//! on-disk change is the appended eviction region; the format version in the header magic is bumped
//! (v1 → v2) so a device written by the prior single-region layout is not silently misread.

use graphus_bufpool::page;
use graphus_core::PageId;
use graphus_core::error::{GraphusError, Result};
use graphus_io::{BlockDevice, PAGE_SIZE, Page, PageReadOutcome};

/// Magic identifying a valid DWB header slot (`"GDWB"` + version `2`, little-endian).
///
/// Version `2` marks the two-region layout (`rmp` #412): a batch region followed by a disjoint
/// eviction region. A device written by the pre-#412 single-region layout carries version `1`, whose
/// magic differs, so its headers fail [`Dwb::decode_header`]'s magic check and decode as "no batch" —
/// it is never silently misread as a v2 device.
const DWB_MAGIC: u64 = 0x0000_0002_4257_4447; // 'G''D''W''B' = 0x47 0x44 0x57 0x42, version 2
// The DWB header slot is a standard page: its first 24 bytes are the page header
// (`graphus_bufpool::page`), of which bytes `0..4` are the CRC32C checksum that `write_checksum`
// stamps. The DWB-specific fields therefore live *after* the 24-byte page header so they do not
// collide with the checksum/`page_lsn`/`page_id` header fields.
const HDR_OFF_MAGIC: usize = page::HEADER_SIZE; // u64
const HDR_OFF_COUNT: usize = HDR_OFF_MAGIC + 8; // u64 (number of data slots in the batch)
const HDR_OFF_HOMES: usize = HDR_OFF_COUNT + 8; // u64[count] home page ids

/// Maximum number of home pages one DWB **batch** (checkpoint) region may protect.
///
/// The batch's home page ids are stored as a `u64[count]` array inside the **single** header page,
/// starting at [`HDR_OFF_HOMES`]; the cap is therefore the number of `u64`s that fit in the header
/// page after its fixed prefix: `(PAGE_SIZE - HDR_OFF_HOMES) / 8`. Deriving it from the page layout
/// (rather than a hand-picked literal) keeps [`Dwb::encode_header`]/[`Dwb::decode_header`] and the
/// DWB device size mutually consistent and makes an over-cap header physically impossible to encode.
/// It also bounds the DWB device size and guards the header decode against an
/// attacker-/corruption-supplied length driving an unbounded read loop.
///
/// (`rmp` #385: the previous literal `4096` overflowed the header page — `HDR_OFF_HOMES + 4096*8`
/// far exceeds `PAGE_SIZE` — so a maximal batch panicked in `encode_header`; the derived value is
/// the largest batch the header can actually describe.)
pub const DWB_MAX_BATCH: usize = (PAGE_SIZE - HDR_OFF_HOMES) / 8;

/// The fixed slot layout of one DWB region: a header slot followed by `capacity` contiguous data
/// slots, none of which overlap any other region (`rmp` #412).
///
/// Both regions share the same on-disk encoding (header magic, count, `u64[count]` home ids in the
/// header; the same image-then-header write order in [`Dwb::stage_into`]); they differ only in their
/// base device pages and capacities, so [`Dwb::stage_into`]/[`Dwb::recover_region`] are fully shared.
#[derive(Clone, Copy)]
struct Region {
    /// Device page of this region's header slot.
    header_slot: u64,
    /// Device page of this region's first data slot (the header is immediately before it).
    first_data_slot: u64,
    /// Maximum number of home pages this region may protect (its data-slot count).
    capacity: usize,
}

/// The BATCH region (checkpoint path): header at page 0, data slots at pages `1 ..= DWB_MAX_BATCH`.
/// Byte-for-byte the pre-#412 single-region layout, so the checkpoint flow is unchanged.
const BATCH_REGION: Region = Region {
    header_slot: 0,
    first_data_slot: 1,
    capacity: DWB_MAX_BATCH,
};

/// The EVICTION region (per-eviction path): header + one data slot, placed immediately after the
/// batch region's last data slot so the two regions are disjoint (`rmp` #412). The eviction path
/// stages exactly one page at a time and serialises stage+home-write under the DWB lock (`rmp` #411),
/// so a single data slot suffices.
const EVICT_REGION: Region = Region {
    header_slot: 1 + DWB_MAX_BATCH as u64,
    first_data_slot: 2 + DWB_MAX_BATCH as u64,
    capacity: 1,
};

/// The number of DWB device pages the two-region layout needs (`rmp` #412): the batch region (one
/// header + [`DWB_MAX_BATCH`] data slots) plus the eviction region (one header + one data slot).
#[must_use]
pub const fn dwb_device_pages() -> u64 {
    // batch: 1 + DWB_MAX_BATCH ; eviction: 1 + 1
    (1 + DWB_MAX_BATCH as u64) + 2
}

/// The doublewrite buffer over a dedicated [`BlockDevice`] (the `doublewrite.dwb` area, `05 §2.1`).
///
/// Holds no page images itself; it is a thin, stateless protocol over its device, so it can be
/// reconstructed on open and driven during both normal flush and recovery.
pub struct Dwb<D: BlockDevice> {
    device: D,
}

impl<D: BlockDevice> Dwb<D> {
    /// Wraps an already-sized DWB `device`, growing it to [`dwb_device_pages`] pages (the two-region
    /// layout, `rmp` #412) if it is shorter.
    ///
    /// # Errors
    /// Returns a storage error if the device cannot be grown to hold both regions.
    pub fn new(mut device: D) -> Result<Self> {
        let need = dwb_device_pages();
        if device.page_count() < need {
            let grow = need - device.page_count();
            device.extend(grow)?;
        }
        Ok(Self { device })
    }

    /// Borrows the DWB device.
    pub fn device(&self) -> &D {
        &self.device
    }

    /// Encodes a header slot for a batch of `homes` page ids.
    ///
    /// The caller ([`stage_into`](Self::stage_into)) has already rejected a batch larger than the
    /// region's capacity; this debug assertion restates the invariant the page layout relies on —
    /// `HDR_OFF_HOMES + homes.len()*8` must fit one header page — so an over-cap batch can never
    /// silently index out of the header page (`rmp` #385). Both regions cap at most at
    /// [`DWB_MAX_BATCH`] (the eviction region at 1), so this single bound covers both.
    fn encode_header(homes: &[PageId]) -> Page {
        debug_assert!(
            homes.len() <= DWB_MAX_BATCH,
            "DWB header batch of {} exceeds the {DWB_MAX_BATCH}-page header capacity",
            homes.len()
        );
        let mut hdr = [0u8; PAGE_SIZE];
        hdr[HDR_OFF_MAGIC..HDR_OFF_MAGIC + 8].copy_from_slice(&DWB_MAGIC.to_le_bytes());
        hdr[HDR_OFF_COUNT..HDR_OFF_COUNT + 8].copy_from_slice(&(homes.len() as u64).to_le_bytes());
        let mut off = HDR_OFF_HOMES;
        for h in homes {
            hdr[off..off + 8].copy_from_slice(&h.0.to_le_bytes());
            off += 8;
        }
        // Cover the header with the standard page checksum so a torn header decodes as "no batch".
        page::write_checksum(&mut hdr);
        hdr
    }

    /// Decodes a header slot, returning the batch's home page ids, or `None` if the slot does not
    /// describe a durable batch (a fresh/zeroed DWB, or a header torn mid-write — both mean "no
    /// committed batch to repair").
    fn decode_header(hdr: &Page) -> Option<Vec<PageId>> {
        // A torn or never-written header fails the checksum: no batch.
        if !page::verify_checksum(hdr) {
            return None;
        }
        let magic = u64::from_le_bytes(
            hdr[HDR_OFF_MAGIC..HDR_OFF_MAGIC + 8]
                .try_into()
                .expect("8-byte slice"),
        );
        if magic != DWB_MAGIC {
            return None;
        }
        let count = u64::from_le_bytes(
            hdr[HDR_OFF_COUNT..HDR_OFF_COUNT + 8]
                .try_into()
                .expect("8-byte slice"),
        );
        // Bound the count: a checksum-valid header cannot exceed the batch cap, and `HDR_OFF_HOMES +
        // count*8` must fit the header page. Both guard against a corrupt-but-checksum-coincident
        // header driving an over-long read (defence in depth; the checksum already makes this
        // astronomically unlikely).
        let count = count as usize;
        if count > DWB_MAX_BATCH || HDR_OFF_HOMES + count * 8 > PAGE_SIZE {
            return None;
        }
        let mut homes = Vec::with_capacity(count);
        let mut off = HDR_OFF_HOMES;
        for _ in 0..count {
            let id = u64::from_le_bytes(hdr[off..off + 8].try_into().expect("8-byte slice"));
            homes.push(PageId(id));
            off += 8;
        }
        Some(homes)
    }

    /// Stages a batch into a specific `region` and makes it durable (steps 1–2 of the write
    /// protocol), without touching any other region (`rmp` #412). Shared by both
    /// [`stage_batch`](Self::stage_batch) (the checkpoint path → [`BATCH_REGION`]) and the per-eviction
    /// path (→ [`EVICT_REGION`]).
    fn stage_into(&mut self, region: &Region, batch: &[(PageId, &Page)]) -> Result<()> {
        if batch.is_empty() {
            return Ok(());
        }
        if batch.len() > region.capacity {
            return Err(GraphusError::Storage(format!(
                "doublewrite batch of {} pages exceeds the {}-page region capacity",
                batch.len(),
                region.capacity
            )));
        }
        // 1. Write each image into one of this region's data slots.
        for (i, (_, image)) in batch.iter().enumerate() {
            let slot = PageId(region.first_data_slot + i as u64);
            self.device.write_page(slot, image)?;
        }
        // Write the header *after* the data slots, so a crash between the two leaves a header that
        // either is absent (no batch) or fully describes data slots that are all present.
        let homes: Vec<PageId> = batch.iter().map(|(p, _)| *p).collect();
        let hdr = Self::encode_header(&homes);
        self.device.write_page(PageId(region.header_slot), &hdr)?;
        // 2. Make the whole batch durable before the home write may begin.
        self.device.sync_data()?;
        Ok(())
    }

    /// Stages a batch of dirty home pages into the **checkpoint** ([`BATCH_REGION`]) region and makes
    /// the DWB durable (steps 1–2 of the write protocol). After this returns the caller may write the
    /// pages to their home locations. Used by the checkpoint/flush path only; the per-eviction path
    /// uses the disjoint eviction region instead (`rmp` #412).
    ///
    /// Each `(PageId, &Page)` is the home id and the *exact image* about to be written home; the
    /// images must already carry a valid checksum (they are page-cache images, checksummed before
    /// write-back).
    ///
    /// # Errors
    /// Returns a storage error if the batch exceeds [`DWB_MAX_BATCH`], or if a DWB write or sync
    /// fails. A DWB write/sync error is **never** swallowed: the caller must not proceed to the home
    /// write without a durable DWB copy, so the error propagates and aborts the flush.
    pub fn stage_batch(&mut self, batch: &[(PageId, &Page)]) -> Result<()> {
        self.stage_into(&BATCH_REGION, batch)
    }

    /// Stages a single evicted home page into the **eviction** ([`EVICT_REGION`]) region and makes it
    /// durable — disjoint from the checkpoint batch region, so a concurrent checkpoint can never
    /// clobber it and vice versa (`rmp` #412). Used only by [`DwbPageStager::stage_and_sync`].
    ///
    /// # Errors
    /// Returns a storage error if the DWB write or sync fails (never swallowed: the home write must
    /// not proceed without a durable copy).
    pub fn stage_eviction(&mut self, page_id: PageId, image: &Page) -> Result<()> {
        self.stage_into(&EVICT_REGION, &[(page_id, image)])
    }

    /// Invalidates the **checkpoint** region's batch by clearing its header slot and syncing, so a
    /// later recovery finds no batch to repair there once the home pages are known durable.
    /// Best-effort hygiene: leaving a stale-but-checksum-valid batch is still *safe* (recovery only
    /// restores a home page that fails its own checksum, i.e. is genuinely torn), so a clear failure
    /// is non-fatal and is reported. (The eviction region is self-managing: each eviction overwrites
    /// it under the DWB lock held across the home write, `rmp` #411, so it never needs a separate
    /// clear.)
    ///
    /// # Errors
    /// Returns a storage error if the header clear write or sync fails.
    pub fn clear(&mut self) -> Result<()> {
        let zero = [0u8; PAGE_SIZE];
        self.device
            .write_page(PageId(BATCH_REGION.header_slot), &zero)?;
        self.device.sync_data()
    }

    /// The home `PageId`s the **current** durable checkpoint-region batch protects (an empty `Vec`
    /// when its header describes no batch). Reads and decodes the batch region's header slot.
    ///
    /// # Errors
    /// Returns a storage error if the header slot cannot be read.
    pub fn staged_home_ids(&self) -> Result<Vec<PageId>> {
        self.region_home_ids(&BATCH_REGION)
    }

    /// The home `PageId`s the **current** durable eviction-region copy protects (an empty `Vec` when
    /// its header describes no page). Used by tests/diagnostics to discover which home page the
    /// eviction-path stager (`rmp` #407/#411) covers, so a torn-page repair can be exercised
    /// deterministically.
    ///
    /// # Errors
    /// Returns a storage error if the header slot cannot be read.
    pub fn evicted_home_ids(&self) -> Result<Vec<PageId>> {
        self.region_home_ids(&EVICT_REGION)
    }

    fn region_home_ids(&self, region: &Region) -> Result<Vec<PageId>> {
        let mut hdr: Page = [0u8; PAGE_SIZE];
        self.device
            .read_page(PageId(region.header_slot), &mut hdr)?;
        Ok(Self::decode_header(&hdr).unwrap_or_default())
    }

    /// Recovery pass: restores every torn home page from its intact DWB copy, run **before** ARIES
    /// redo. Returns the number of home pages repaired.
    ///
    /// For each home page the last committed DWB batch protected, reads the home page; if it fails
    /// its checksum it is torn, so it is overwritten with the DWB copy (which must itself be
    /// checksum-valid — a DWB slot that is *also* torn is reported as an unrepairable corruption
    /// rather than silently restoring garbage). Pages whose home image is intact are left untouched:
    /// they are either the old or the new image, both of which ARIES redo reconciles correctly.
    ///
    /// `home` is the data device whose pages are being repaired.
    ///
    /// # Errors
    /// Returns a storage error if a home/DWB read or a home write/sync fails, or if a DWB copy needed
    /// to repair a torn home page is itself corrupt (an unrepairable double fault — surfaced, never
    /// hidden, per the integrity-is-inviolable rule, `04 §4.6`).
    pub fn recover_home<H: BlockDevice>(&mut self, home: &mut H) -> Result<usize> {
        // Scan BOTH regions (`rmp` #412): a torn home page may be protected by the checkpoint batch
        // region OR the per-eviction region, and the two are written by independent paths. Repairing
        // both is safe and order-independent — `recover_region` only restores a home page that fails
        // its own checksum, and the lsn/page_id guards reject a stale or misdirected copy, so a page
        // that a region does not actually protect (or whose home is already intact) is left untouched.
        let batch_repaired = self.recover_region(&BATCH_REGION, home)?;
        let evict_repaired = self.recover_region(&EVICT_REGION, home)?;
        Ok(batch_repaired + evict_repaired)
    }

    /// Repairs every torn home page protected by a single `region`'s durable batch. Returns the number
    /// of home pages repaired in that region. A separate trailing `sync_data` is issued per region
    /// that repaired anything; recovery is idempotent, so a crash between the two region passes simply
    /// reruns from the top on the next open.
    fn recover_region<H: BlockDevice>(&mut self, region: &Region, home: &mut H) -> Result<usize> {
        let mut hdr: Page = [0u8; PAGE_SIZE];
        self.device
            .read_page(PageId(region.header_slot), &mut hdr)?;
        let Some(homes) = Self::decode_header(&hdr) else {
            return Ok(0); // no durable batch in this region: nothing to repair
        };

        let mut repaired = 0usize;
        for (i, home_id) in homes.iter().enumerate() {
            // A page the DWB protected may be beyond the home device's current extent only if the
            // home write for it never happened; redo will (re)create it, so skip — there is no torn
            // home image to repair.
            if home_id.0 >= home.page_count() {
                continue;
            }
            // Read + classify the home page (`rmp` #408). On the **plaintext** device a torn page
            // reads back as bytes whose CRC32C fails `verify_checksum` (the read itself succeeds). On
            // the **encrypted** device (`graphus_crypto`) the torn slot fails its AES-GCM tag, which
            // `read_page_classified` reports as `PageReadOutcome::Torn` — distinct from a **transient**
            // I/O error, which it propagates as `Err`.
            //
            // ROOT-CAUSE FIX (`rmp` #408): the previous code mapped *any* home-read `Err` to "torn",
            // so a fine-but-momentarily-unreadable home page (a transient device error) with a stale
            // surviving DWB batch present would be CLOBBERED by the older DWB image — a durability
            // violation (an older image written over a newer home page). We now:
            //   - repair ONLY on a genuine tear: `PageReadOutcome::Torn`, or a successful read whose
            //     CRC32C fails (the plaintext tear);
            //   - PROPAGATE a transient `Err` (never silently revert) — recovery fails loudly so the
            //     operator/retry sees it, rather than corrupting a good page from a stale copy.
            let mut home_buf: Page = [0u8; PAGE_SIZE];
            // `home_trusted_lsn` is `Some(lsn)` only when the home page read back **and** its own
            // CRC32C verifies — i.e. its header (and `page_lsn`) is trustworthy. A torn page's header
            // is garbage, so its lsn is never trusted (`None`). Used by the lsn guard below.
            let (home_torn, home_trusted_lsn) =
                match home.read_page_classified(*home_id, &mut home_buf)? {
                    // Read succeeded: intact iff its own CRC32C verifies (plaintext-tear detection).
                    PageReadOutcome::Read => {
                        if page::verify_checksum(&home_buf) {
                            (false, Some(page::page_lsn(&home_buf)))
                        } else {
                            (true, None) // readable but CRC-failed ⇒ torn; lsn untrusted
                        }
                    }
                    // Genuine AEAD-tag failure on the encrypted device: the page is torn.
                    PageReadOutcome::Torn => (true, None),
                };
            if !home_torn {
                continue; // home image intact (old or new) — redo reconciles it
            }
            // Home page is torn. Restore from this region's DWB copy.
            let slot = PageId(region.first_data_slot + i as u64);
            let mut dwb_buf: Page = [0u8; PAGE_SIZE];
            // A DWB-slot read that errors (an AEAD failure on an encrypted DWB device, i.e. the copy
            // is itself torn) is the unrepairable double fault — surface it, never hide it.
            let dwb_readable = match self.device.read_page(slot, &mut dwb_buf) {
                Ok(()) => page::verify_checksum(&dwb_buf),
                Err(_) => false,
            };
            if !dwb_readable {
                return Err(GraphusError::Storage(format!(
                    "doublewrite recovery: home page {} is torn and its doublewrite copy in slot {} \
                     is also corrupt — unrepairable double fault",
                    home_id.0, slot.0
                )));
            }
            // Defence in depth: the DWB copy's self-referential page_id header must name this home
            // page (`05 §6`: page_id detects misdirected/torn writes), or we would restore the wrong
            // page over a torn one.
            if page::page_id(&dwb_buf) != home_id.0 {
                return Err(GraphusError::Storage(format!(
                    "doublewrite recovery: slot {} carries page_id {} but the header maps it to home \
                     page {} — misdirected doublewrite copy, refusing to restore",
                    slot.0,
                    page::page_id(&dwb_buf),
                    home_id.0
                )));
            }
            // Defence in depth — the lsn guard (`rmp` #408): never write an OLDER image over a NEWER
            // home page. We only reach here when the home page is torn, so normally its lsn is
            // untrusted (`home_trusted_lsn == None`) and the guard is a no-op — the root-cause fix
            // (classifying transient `Err` vs genuine tear above) is what actually closes the reported
            // clobber. But if a future caller ever reaches this restore with a home page whose header
            // *does* verify (a trusted lsn), refuse to apply a strictly-staler DWB copy: a DWB image
            // older than the live home page is a stale surviving batch, and restoring it would revert a
            // committed change. (A DWB image of equal-or-greater lsn is the legitimate repair image.)
            if let Some(home_lsn) = home_trusted_lsn {
                let dwb_lsn = page::page_lsn(&dwb_buf);
                if dwb_lsn < home_lsn {
                    return Err(GraphusError::Storage(format!(
                        "doublewrite recovery: refusing to restore home page {} from slot {}: the \
                         doublewrite copy's page_lsn {} is OLDER than the (intact) home page's \
                         page_lsn {} — a stale doublewrite batch must never overwrite a newer home \
                         page",
                        home_id.0, slot.0, dwb_lsn.0, home_lsn.0
                    )));
                }
            }
            home.write_page(*home_id, &dwb_buf)?;
            repaired += 1;
        }
        if repaired > 0 {
            home.sync_data()?;
        }
        Ok(repaired)
    }
}

/// A [`graphus_bufpool::PageStager`] over a **shared persistent doublewrite buffer** (`rmp` #407).
///
/// This is what wires the buffer pool's *eviction/steal* home-write path into the doublewrite
/// protocol: when the pool must steal a dirty data page and write it home, it first calls
/// [`stage_and_sync`](graphus_bufpool::PageStager::stage_and_sync) on this stager, which stages that
/// one page image into the **same** persistent DWB the checkpoint path uses and fsyncs it — so the
/// image is durable before the home write begins, and a torn eviction write is repairable on the
/// next open ([`recover_device_with_dwb`](crate::recovery::recover_device_with_dwb)).
///
/// The DWB lives behind an `Arc<Mutex<Dwb<D>>>` shared with the owning [`RecordStore`]: the `Mutex`
/// serialises concurrent evictions' staging against each other and against a checkpoint's
/// `flush_protected`, so there is exactly one writer of the DWB device at a time and one DWB owner
/// overall. A single-page batch ([`Dwb::stage_batch`] with one entry) is exactly what
/// [`Dwb::recover_home`] already scans and repairs (it iterates every occupied slot of the recorded
/// batch, whether the batch holds one page or many), so an evicted torn page is covered identically
/// to a checkpoint torn page.
///
/// PERFORMANCE: each eviction that steals a dirty page now pays one extra DWB `write_page` + one
/// `sync_data` (an fsync) before its home write. Under steal-heavy pressure (a working set larger
/// than the pool) this is a real per-eviction fsync cost; correctness (no unprotected home write)
/// takes precedence. A perf follow-up may coalesce staging across a burst of evictions, but must not
/// weaken the stage-before-home ordering. (`rmp` #407.)
pub struct DwbPageStager<D: BlockDevice> {
    dwb: std::sync::Arc<std::sync::Mutex<Dwb<D>>>,
}

impl<D: BlockDevice> DwbPageStager<D> {
    /// Wraps the shared persistent DWB so the pool can stage evicted pages into it.
    #[must_use]
    pub fn new(dwb: std::sync::Arc<std::sync::Mutex<Dwb<D>>>) -> Self {
        Self { dwb }
    }
}

impl<D: BlockDevice + Send> graphus_bufpool::PageStager for DwbPageStager<D> {
    fn stage_and_sync(
        &self,
        page_id: PageId,
        image: &[u8],
        home_write: &mut dyn FnMut() -> Result<()>,
    ) -> Result<()> {
        // The image is exactly one page; `stage_batch` of a single `(page_id, &Page)` writes it to a
        // DWB data slot, records the header, and `sync_data`s — durable before the home write begins.
        let page: &Page = image.try_into().map_err(|_| {
            GraphusError::Storage(format!(
                "doublewrite stage: image for page {} is {} bytes, expected {PAGE_SIZE}",
                page_id.0,
                image.len()
            ))
        })?;
        // DISJOINT-REGION + SLOT-REUSE-AFTER-DURABLE INVARIANT (`rmp` #412, `rmp` #411). The eviction
        // path stages into the DWB's **eviction region** (`stage_eviction`), which is disjoint on disk
        // from the checkpoint **batch region** (`stage_batch`). So a concurrent checkpoint can never
        // clobber this evicted copy and vice versa (`rmp` #412) — that closes the checkpoint-vs-eviction
        // hole at the layout level.
        //
        // Among evictors themselves, the eviction region has a single data slot, so we still hold the
        // DWB lock across BOTH the staging fsync AND the home write: this page's copy stays the
        // region's occupant — and discoverable by `recover_home` — until the home write is DURABLY
        // complete (`home_write` writes the page home and `sync_data`s the home device). Only then does
        // the lock release, freeing the eviction region for the next evictor. Without this, two
        // concurrent evictors race on the single eviction slot: T1 stages A, T2 OVERWRITES it with B,
        // then T1's home write of A tears on a crash and A is UNRECOVERABLE (`rmp` #411). Serialising
        // staging+home-write here closes that hole.
        //
        // DEADLOCK-FREEDOM: `write_back` (the sole caller) holds the victim frame's write latch, then
        // calls here, which takes the DWB lock, and `home_write` then takes the device write guard.
        // Order is uniformly frame-latch → DWB → device. The checkpoint path (`flush_pages`) stages
        // under held frame latches via `stage_batch_and_sync` (DWB lock) then takes the device only
        // AFTER releasing the DWB lock — so no path ever holds the device while acquiring the DWB lock.
        // The global order has no cycle: no ABBA between a checkpoint and a concurrent eviction.
        let mut dwb = self
            .dwb
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        // 1. Stage the copy into the disjoint eviction region and make it durable in the DWB.
        dwb.stage_eviction(page_id, page)?;
        // 2. Write the page home and make THAT durable — still holding the DWB lock, so the region is
        //    not reusable until this page is durable home.
        home_write()
        // 3. Lock released here: the region's occupant (`page_id`) is now durable on the home device,
        //    so the next evictor may safely reuse it.
    }

    fn stage_batch_and_sync(&self, batch: &[(PageId, &[u8])]) -> Result<()> {
        // Reborrow each `&[u8]` image as a `&Page` (each is exactly one page; the pool stamped the
        // checksum before calling). The whole batch is staged as ONE durable DWB batch (a single
        // `sync_data` inside `stage_batch`), so every page is protected before any home write.
        let mut pages: Vec<(PageId, &Page)> = Vec::with_capacity(batch.len());
        for (page_id, image) in batch {
            let page: &Page = (*image).try_into().map_err(|_| {
                GraphusError::Storage(format!(
                    "doublewrite stage: image for page {} is {} bytes, expected {PAGE_SIZE}",
                    page_id.0,
                    image.len()
                ))
            })?;
            pages.push((*page_id, page));
        }
        let mut dwb = self
            .dwb
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        dwb.stage_batch(&pages)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use graphus_io::MemBlockDevice;

    /// Builds a valid, checksummed page that self-identifies as `id` with `page_lsn` and a body
    /// byte pattern `fill`.
    fn make_page(id: u64, lsn: u64, fill: u8) -> Page {
        let mut p = [fill; PAGE_SIZE];
        page::set_page_id(&mut p, id);
        page::set_page_lsn(&mut p, graphus_core::Lsn(lsn));
        page::write_checksum(&mut p);
        p
    }

    fn fresh_dwb() -> Dwb<MemBlockDevice> {
        Dwb::new(MemBlockDevice::new(0)).expect("dwb")
    }

    #[test]
    fn fresh_dwb_has_no_batch_to_recover() {
        let mut dwb = fresh_dwb();
        let mut home = MemBlockDevice::new(4);
        assert_eq!(dwb.recover_home(&mut home).expect("recover"), 0);
    }

    #[test]
    fn repairs_a_torn_home_page_from_the_dwb_copy() {
        let mut dwb = fresh_dwb();
        let good = make_page(2, 50, 0xAB);

        // Stage + sync the DWB copy (the protocol's durable-before-home step).
        dwb.stage_batch(&[(PageId(2), &good)]).expect("stage");

        // Home device: page 2 is TORN — first 100 bytes of the new image, rest stale zeros.
        let mut home = MemBlockDevice::new(4);
        let mut torn = good;
        torn[100..].iter_mut().for_each(|b| *b = 0);
        // Re-stamp nothing: the torn image keeps the new checksum field but a stale body, so its
        // checksum no longer verifies — exactly a torn write.
        home.write_page(PageId(2), &torn).expect("write torn");
        home.sync_data().expect("sync home");
        assert!(
            !page::verify_checksum(&torn),
            "the torn image must fail its checksum (precondition)"
        );

        let repaired = dwb.recover_home(&mut home).expect("recover");
        assert_eq!(repaired, 1);

        let mut got: Page = [0u8; PAGE_SIZE];
        home.read_page(PageId(2), &mut got).expect("read repaired");
        assert!(
            page::verify_checksum(&got),
            "home page must be intact after repair"
        );
        assert_eq!(&got[..], &good[..], "home page must equal the DWB copy");
    }

    #[test]
    fn leaves_an_intact_home_page_untouched() {
        let mut dwb = fresh_dwb();
        let old = make_page(2, 50, 0xAB);
        let new = make_page(2, 60, 0xCD);
        dwb.stage_batch(&[(PageId(2), &new)]).expect("stage");

        // Home holds the OLD (intact) image — the home write had not happened yet at the crash.
        let mut home = MemBlockDevice::new(4);
        home.write_page(PageId(2), &old).expect("write old");
        home.sync_data().expect("sync");

        assert_eq!(dwb.recover_home(&mut home).expect("recover"), 0);
        let mut got: Page = [0u8; PAGE_SIZE];
        home.read_page(PageId(2), &mut got).expect("read");
        assert_eq!(
            &got[..],
            &old[..],
            "intact home page must be left for redo to reconcile"
        );
    }

    #[test]
    fn a_torn_header_describes_no_batch() {
        let mut dwb = fresh_dwb();
        let good = make_page(1, 10, 0x11);
        dwb.stage_batch(&[(PageId(1), &good)]).expect("stage");
        // Corrupt the batch region's header slot (a crash mid-DWB-write): its checksum no longer
        // verifies.
        let mut hdr: Page = [0u8; PAGE_SIZE];
        dwb.device
            .read_page(PageId(BATCH_REGION.header_slot), &mut hdr)
            .unwrap();
        hdr[8] ^= 0xFF; // flip the count field; checksum now fails
        dwb.device
            .write_page(PageId(BATCH_REGION.header_slot), &hdr)
            .unwrap();
        dwb.device.sync_data().unwrap();

        // Even with a torn home page, a header that does not decode means "no committed batch".
        let mut home = MemBlockDevice::new(4);
        let mut torn = good;
        torn[100..].iter_mut().for_each(|b| *b = 0);
        home.write_page(PageId(1), &torn).unwrap();
        home.sync_data().unwrap();
        assert_eq!(dwb.recover_home(&mut home).expect("recover"), 0);
    }

    #[test]
    fn double_fault_is_surfaced_not_hidden() {
        let mut dwb = fresh_dwb();
        let good = make_page(3, 7, 0x22);
        dwb.stage_batch(&[(PageId(3), &good)]).expect("stage");
        // Corrupt the batch region's data slot too (a double fault): both home and copy are torn.
        let mut slot: Page = [0u8; PAGE_SIZE];
        dwb.device
            .read_page(PageId(BATCH_REGION.first_data_slot), &mut slot)
            .unwrap();
        slot[200] ^= 0xFF; // body byte; slot checksum now fails
        dwb.device
            .write_page(PageId(BATCH_REGION.first_data_slot), &slot)
            .unwrap();
        dwb.device.sync_data().unwrap();

        let mut home = MemBlockDevice::new(4);
        let mut torn = good;
        torn[100..].iter_mut().for_each(|b| *b = 0);
        home.write_page(PageId(3), &torn).unwrap();
        home.sync_data().unwrap();
        assert!(
            dwb.recover_home(&mut home).is_err(),
            "double fault must surface as an error"
        );
    }

    #[test]
    fn clear_invalidates_the_batch() {
        let mut dwb = fresh_dwb();
        let good = make_page(1, 10, 0x11);
        dwb.stage_batch(&[(PageId(1), &good)]).expect("stage");
        dwb.clear().expect("clear");
        let mut home = MemBlockDevice::new(4);
        // Even a torn home page is not touched after clear (no batch recorded).
        let mut torn = good;
        torn[100..].iter_mut().for_each(|b| *b = 0);
        home.write_page(PageId(1), &torn).unwrap();
        home.sync_data().unwrap();
        assert_eq!(dwb.recover_home(&mut home).expect("recover"), 0);
    }

    #[test]
    fn batch_over_the_cap_is_rejected() {
        let mut dwb = fresh_dwb();
        let p = make_page(1, 1, 0);
        let big: Vec<(PageId, &Page)> = (0..=DWB_MAX_BATCH)
            .map(|i| (PageId(i as u64), &p))
            .collect();
        assert!(dwb.stage_batch(&big).is_err());
    }
}
