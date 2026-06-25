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
//! ## Disjoint regions: one batch region + an eviction ring (`rmp` #412, `rmp` #431)
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
//! The device therefore carries **disjoint regions** that never overlap on disk:
//!
//! * the **BATCH region** (pages `0 ..= DWB_MAX_BATCH`) — used **only** by the checkpoint path; one
//!   header slot plus up to [`DWB_MAX_BATCH`] data slots;
//! * the **EVICTION RING** (the pages after the batch region) — used **only** by the per-eviction
//!   path; [`DWB_EVICT_RING_SLOTS`] independent single-page regions, each its own (header, data)
//!   pair. (`rmp` #431.)
//!
//! ### Why a ring, not a single eviction slot (`rmp` #431)
//!
//! The pre-#431 layout had a **single** eviction slot, and [`DwbPageStager::stage_and_sync`] held the
//! one process-wide `Arc<Mutex<Dwb>>` across BOTH the staging fsync AND the home write+fsync (that
//! serialisation is what `rmp` #411 used to guarantee the single slot's occupant stayed
//! recover-discoverable until its home write was durable). Under combined read+write load every dirty
//! eviction across `~2 * min(N_cpu, 16)` threads then serialised through that one slot and its two
//! serial fsyncs — a **convoy**: correctness was intact, throughput collapsed.
//!
//! The eviction ring removes the convoy. Each evictor **claims a free ring slot** from a lightweight
//! free-slot allocator (the only step under a short lock), stages its page into that slot and fsyncs
//! the DWB, writes the page home and fsyncs the home device — **without** holding any global lock
//! across the home write — then **frees its slot**. With `N` slots, up to `N` evictions are in flight
//! concurrently, each owning a disjoint slot. The reuse-after-durable invariant (`rmp` #411) is now
//! enforced by the **free-slot allocator**, not by holding a lock across the home write: a slot is
//! returned to the free list (and thus reusable) **only after** its occupant's home write is durably
//! complete.
//!
//! ### The invariants the ring still upholds (why #411/#412 existed)
//!
//! 1. **Valid-until-durable** — a claimed slot's page image stays in place and
//!    [`recover_home`](Dwb::recover_home)-discoverable until that page's home write is durable: the
//!    slot is not freed (nor its header cleared) before the home write returns.
//! 2. **Reuse-after-durable** — a slot is handed to another evictor only after its prior occupant's
//!    home write is durably complete (the allocator frees it only post-home-sync).
//! 3. **No clobber** — the `N` ring slots are byte-disjoint from each other and from the batch
//!    region, and the free-slot allocator hands each in-flight evictor a *distinct* slot, so no two
//!    evictors (nor an evictor and the checkpoint) ever write the same bytes.
//! 4. **Recovery scans everything** — [`recover_home`](Dwb::recover_home) scans the batch region AND
//!    every ring slot, repairing every torn home page found in any of them.
//! 5. **Deadlock-free** — lock order is uniformly frame-latch → DWB(claim/stage/free) → store-device;
//!    the DWB device lock is never held while taking the store device, and the home write takes the
//!    store device while holding NO DWB lock at all.
//!
//! [`Dwb::recover_home`] scans the batch region header and every ring-slot header and repairs every
//! torn home page found, so a torn page from either writer is recovered. The format version in the
//! header magic is bumped (v2 → v3, `rmp` #434) so a device written by the prior single-eviction-slot
//! (v2) or single-region (v1) layout is detected and recreated rather than silently misread.

use graphus_bufpool::page;
use graphus_core::PageId;
use graphus_core::error::{GraphusError, Result};
use graphus_io::{BlockDevice, PAGE_SIZE, Page, PageReadOutcome};

/// Magic identifying a valid DWB header slot (`"GDWB"` + version `3`, little-endian).
///
/// Version `3` marks the eviction-**ring** layout (`rmp` #431): a batch region followed by
/// [`DWB_EVICT_RING_SLOTS`] disjoint single-page eviction regions. A device written by the
/// pre-#431 two-region layout carries version `2`, and the original single-region layout version `1`;
/// both differ in this magic, so their headers fail [`Dwb::decode_header`]'s magic check and decode as
/// "no batch" — an old-format device is never silently misread as v3 (`rmp` #434). [`Dwb::new`]
/// additionally **grows** a too-small old device to the v3 page count, so an in-place upgrade after a
/// clean shutdown (every slot home-durable, so nothing to repair) reopens safely.
const DWB_MAGIC: u64 = 0x0000_0003_4257_4447; // 'G''D''W''B' = 0x47 0x44 0x57 0x42, version 3
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

/// The number of independent single-page eviction slots in the eviction **ring** (`rmp` #431).
///
/// Chosen as a small fixed constant sized to the **maximum concurrent evictor bound**: the server's
/// reader pool (`rmp` #336) and writer concurrency are each capped near `min(N_cpu, 16)`, so at most
/// `~2 * 16 = 32` threads can be evicting a dirty page at once. `32` ring slots therefore let every
/// possible concurrent evictor own a distinct slot with no contention on the slot allocator, while
/// costing only `32 * 2 = 64` extra DWB pages (`512 KiB`) of fixed on-disk overhead — negligible. A
/// constant (rather than a runtime-sized ring) keeps the on-disk layout fixed and the header-decode
/// bounds static. If the evictor count ever exceeds this, the allocator degrades **gracefully** to
/// the pre-#431 behaviour (an evictor with no free slot waits, capped at `N`-way parallelism — never
/// incorrect, only as fast as `N` slots allow).
pub const DWB_EVICT_RING_SLOTS: usize = 32;

/// The fixed slot layout of one DWB region: a header slot followed by `capacity` contiguous data
/// slots, none of which overlap any other region (`rmp` #412 / `rmp` #431).
///
/// Both the batch region and every eviction-ring slot share the same on-disk encoding (header magic,
/// count, `u64[count]` home ids in the header; the same image-then-header write order in
/// [`Dwb::stage_into`]); they differ only in their base device pages and capacities, so
/// [`Dwb::stage_into`]/[`Dwb::recover_region`] are fully shared.
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

/// Device page of the first eviction-ring slot's header. The ring is placed immediately after the
/// batch region's last data slot so it is disjoint from the batch region (`rmp` #412). Each ring slot
/// occupies two consecutive pages: `[header, data]`.
const EVICT_RING_BASE: u64 = 1 + DWB_MAX_BATCH as u64;

/// The [`Region`] descriptor for eviction-ring slot `slot` (`0 ..= DWB_EVICT_RING_SLOTS-1`). Each slot
/// is a one-page-capacity region of two consecutive device pages: a header page then a data page,
/// disjoint from every other slot and from the batch region (`rmp` #431).
const fn evict_ring_region(slot: usize) -> Region {
    let base = EVICT_RING_BASE + (slot as u64) * 2;
    Region {
        header_slot: base,
        first_data_slot: base + 1,
        capacity: 1,
    }
}

/// The number of DWB device pages the layout needs (`rmp` #412 / `rmp` #431): the batch region (one
/// header + [`DWB_MAX_BATCH`] data slots) plus the eviction ring ([`DWB_EVICT_RING_SLOTS`] slots, each
/// one header + one data page).
#[must_use]
pub const fn dwb_device_pages() -> u64 {
    // batch: 1 + DWB_MAX_BATCH ; ring: DWB_EVICT_RING_SLOTS * (1 header + 1 data)
    (1 + DWB_MAX_BATCH as u64) + (DWB_EVICT_RING_SLOTS as u64) * 2
}

/// The doublewrite buffer over a dedicated [`BlockDevice`] (the `doublewrite.dwb` area, `05 §2.1`).
///
/// Holds no page images itself; it is a thin, stateless protocol over its device, so it can be
/// reconstructed on open and driven during both normal flush and recovery.
pub struct Dwb<D: BlockDevice> {
    device: D,
}

impl<D: BlockDevice> Dwb<D> {
    /// Wraps an already-sized DWB `device`, growing it to [`dwb_device_pages`] pages (the current
    /// ring layout, `rmp` #431) if it is shorter.
    ///
    /// An older-format device (v1 single-region or v2 single-eviction-slot, `rmp` #434) is **shorter**
    /// than the v3 ring layout, so it is grown here: the new ring slots are zero pages, which
    /// [`decode_header`](Self::decode_header) reads as "no batch", so they are never misread.
    /// [`recover_home`](Self::recover_home) only ever *reads* old slots; on a clean shutdown every page
    /// is home-durable so there is nothing to repair, and the v3 magic on the next stage marks the
    /// device as v3 going forward. The header magic also differs (v3 vs v2/v1), so even an old device
    /// that is *not* grown (already large enough) decodes its stale batch header as "no batch" rather
    /// than misreading a v2/v1 layout.
    ///
    /// # Errors
    /// Returns a storage error if the device cannot be grown to hold the ring layout.
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
    /// silently index out of the header page (`rmp` #385). Both region kinds cap at most at
    /// [`DWB_MAX_BATCH`] (each ring slot at 1), so this single bound covers them all.
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
    /// describe a durable batch (a fresh/zeroed DWB, an old-format (v1/v2) header, or a header torn
    /// mid-write — all mean "no committed batch to repair").
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
        // A wrong magic includes an old-format device (v1/v2): treat it as "no batch" (`rmp` #434),
        // so an old device's stale header is never misread as a current-format batch.
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
    /// protocol), without touching any other region (`rmp` #412 / `rmp` #431). Shared by both
    /// [`stage_batch`](Self::stage_batch) (the checkpoint path → [`BATCH_REGION`]) and the per-eviction
    /// path (→ an [`evict_ring_region`] slot).
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
    /// uses the disjoint eviction ring instead (`rmp` #412 / `rmp` #431).
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

    /// Stages a single evicted home page into eviction-ring **slot** `slot` and makes it durable —
    /// disjoint from the checkpoint batch region and from every other ring slot, so a concurrent
    /// checkpoint or another evictor can never clobber it and vice versa (`rmp` #412 / `rmp` #431).
    /// Used only by [`DwbPageStager::stage_and_sync`], which owns `slot` (claimed from the free-slot
    /// allocator) for the duration of the stage+home-write.
    ///
    /// # Errors
    /// Returns a storage error if `slot` is out of range, or if the DWB write or sync fails (never
    /// swallowed: the home write must not proceed without a durable copy).
    pub fn stage_eviction_slot(
        &mut self,
        slot: usize,
        page_id: PageId,
        image: &Page,
    ) -> Result<()> {
        if slot >= DWB_EVICT_RING_SLOTS {
            return Err(GraphusError::Storage(format!(
                "doublewrite eviction ring slot {slot} out of range (0..{DWB_EVICT_RING_SLOTS})"
            )));
        }
        let region = evict_ring_region(slot);
        self.stage_into(&region, &[(page_id, image)])
    }

    /// Invalidates the **checkpoint** region's batch by clearing its header slot and syncing, so a
    /// later recovery finds no batch to repair there once the home pages are known durable.
    /// Best-effort hygiene: leaving a stale-but-checksum-valid batch is still *safe* (recovery only
    /// restores a home page that fails its own checksum, i.e. is genuinely torn), so a clear failure
    /// is non-fatal and is reported.
    ///
    /// # Errors
    /// Returns a storage error if the header clear write or sync fails.
    pub fn clear(&mut self) -> Result<()> {
        let zero = [0u8; PAGE_SIZE];
        self.device
            .write_page(PageId(BATCH_REGION.header_slot), &zero)?;
        self.device.sync_data()
    }

    /// Zeroes **every** DWB header (the batch region and all ring slots) and syncs, so no stale
    /// doublewrite copy from a prior generation survives. Used by the restore path (`rmp` #417): a
    /// restore lays down a fresh device + WAL, and any leftover doublewrite batch from the prior
    /// generation must not be able to clobber a (genuinely or coincidentally) torn page of the freshly
    /// restored device on the next open. Mirrors the WAL reset.
    ///
    /// # Errors
    /// Returns a storage error if a header clear write or the sync fails.
    pub fn reset(&mut self) -> Result<()> {
        let zero = [0u8; PAGE_SIZE];
        self.device
            .write_page(PageId(BATCH_REGION.header_slot), &zero)?;
        for slot in 0..DWB_EVICT_RING_SLOTS {
            let region = evict_ring_region(slot);
            self.device.write_page(PageId(region.header_slot), &zero)?;
        }
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

    /// The home `PageId`s the **eviction ring** currently protects across all its slots (an empty
    /// `Vec` when no slot is occupied). Used by tests/diagnostics to discover which home pages the
    /// eviction-path stager (`rmp` #407/#411/#431) covers, so a torn-page repair can be exercised
    /// deterministically.
    ///
    /// # Errors
    /// Returns a storage error if a header slot cannot be read.
    pub fn evicted_home_ids(&self) -> Result<Vec<PageId>> {
        let mut ids = Vec::new();
        for slot in 0..DWB_EVICT_RING_SLOTS {
            let region = evict_ring_region(slot);
            ids.extend(self.region_home_ids(&region)?);
        }
        Ok(ids)
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
        // Scan the batch region AND every eviction-ring slot (`rmp` #412 / `rmp` #431): a torn home
        // page may be protected by the checkpoint batch region OR by any in-flight eviction-ring slot,
        // and the two are written by independent paths. Repairing all is safe and order-independent —
        // `recover_region` only restores a home page that fails its own checksum, and the lsn/page_id
        // guards reject a stale or misdirected copy, so a page that a region does not actually protect
        // (or whose home is already intact) is left untouched.
        let mut repaired = self.recover_region(&BATCH_REGION, home)?;
        for slot in 0..DWB_EVICT_RING_SLOTS {
            let region = evict_ring_region(slot);
            repaired += self.recover_region(&region, home)?;
        }
        Ok(repaired)
    }

    /// Repairs every torn home page protected by a single `region`'s durable batch. Returns the number
    /// of home pages repaired in that region. A separate trailing `sync_data` is issued per region
    /// that repaired anything; recovery is idempotent, so a crash between the region passes simply
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

/// A lightweight free-slot allocator over the eviction ring's [`DWB_EVICT_RING_SLOTS`] slots
/// (`rmp` #431).
///
/// This is the only state held under a lock across the *claim* and *free* of a ring slot — and the
/// lock is **never** held across the staging fsync or the home write, so it does not serialise the
/// expensive I/O. It enforces the reuse-after-durable invariant (`rmp` #411): a slot is returned to
/// the free set (and thus claimable by another evictor) **only after** its occupant's home write is
/// durably complete (the caller frees it only post-home-sync). A free bitmap of `usize` words is
/// ample for the small constant ring.
struct FreeSlots {
    /// `free[i] == true` iff ring slot `i` is available to claim.
    free: Vec<bool>,
}

impl FreeSlots {
    fn new() -> Self {
        Self {
            free: vec![true; DWB_EVICT_RING_SLOTS],
        }
    }

    /// Claims a free ring slot, returning its index, or `None` if every slot is currently in flight.
    fn claim(&mut self) -> Option<usize> {
        let slot = self.free.iter().position(|&f| f)?;
        self.free[slot] = false;
        Some(slot)
    }

    /// Returns a previously-claimed `slot` to the free set. Called only after the slot's occupant's
    /// home write is durably complete (reuse-after-durable).
    fn free(&mut self, slot: usize) {
        debug_assert!(slot < DWB_EVICT_RING_SLOTS);
        debug_assert!(
            !self.free[slot],
            "freeing eviction ring slot {slot} that is already free"
        );
        self.free[slot] = true;
    }
}

/// An escalating exponential-backoff helper for the eviction-ring claim loop (`rmp` #436).
///
/// This is a local mirror of `graphus_bufpool`'s crate-private `Backoff` (introduced for the buffer
/// pool's `fetch`/victim-sweep contention at `rmp` #359): a few cheap `spin_loop` hints first, then
/// escalating `yield_now` calls, capped so a single backoff never blocks for long. Using the **same**
/// strategy and constants keeps the storm-handling behaviour consistent across the two contended
/// allocators; it is mirrored rather than imported because the bufpool type is `pub(crate)` and to add
/// no new dependency.
///
/// Used by [`DwbPageStager::claim_slot`] to drain the waiter herd in *time* (so in-flight evictors
/// finish and free their ring slots) instead of a bare `yield_now` busy-spin that burns a core and
/// prolongs the victim frame's write-latch hold under storm.
struct Backoff {
    step: u32,
}

impl Backoff {
    /// A fresh backoff at the lowest (cheapest) escalation step.
    #[inline]
    fn new() -> Self {
        Self { step: 0 }
    }

    /// Backs off once, escalating the patience: a short `spin_loop` burst for the first few steps
    /// (cheap, no syscall, lets a peer holding a latch on the same core finish), then `yield_now`
    /// (deschedule so a peer on another core can run), capped so a single backoff never blocks for
    /// long. Each call advances the step until a ceiling. Mirrors `graphus_bufpool::Backoff::spin`.
    #[inline]
    fn spin(&mut self) {
        // Spin steps 0..=5 (1, 2, 4, …, 32 pauses), then yield for higher steps. The yield steps
        // escalate by issuing several yields, spreading heavily-contended threads further apart in
        // time so the evictor herd drains. Capped at step 10 so the patience is bounded.
        const SPIN_CEIL: u32 = 6;
        const STEP_CEIL: u32 = 10;
        if self.step < SPIN_CEIL {
            for _ in 0..(1u32 << self.step) {
                std::hint::spin_loop();
            }
        } else {
            for _ in 0..(self.step - SPIN_CEIL + 1) {
                std::thread::yield_now();
            }
        }
        if self.step < STEP_CEIL {
            self.step += 1;
        }
    }
}

/// A [`graphus_bufpool::PageStager`] over a **shared persistent doublewrite buffer** (`rmp` #407,
/// `rmp` #431).
///
/// This is what wires the buffer pool's *eviction/steal* home-write path into the doublewrite
/// protocol: when the pool must steal a dirty data page and write it home, it first calls
/// [`stage_and_sync`](graphus_bufpool::PageStager::stage_and_sync) on this stager, which claims a free
/// eviction-ring slot, stages that one page image into the **same** persistent DWB the checkpoint path
/// uses and fsyncs it — so the image is durable before the home write begins, and a torn eviction
/// write is repairable on the next open
/// ([`recover_device_with_dwb`](crate::recovery::recover_device_with_dwb)).
///
/// ## Concurrency (`rmp` #431): an N-slot ring instead of one serialising slot
///
/// The DWB device lives behind an `Arc<Mutex<Dwb<D>>>` (the device's `write_page`/`sync_data` are
/// `&mut`, so the device itself is accessed under that mutex). The pre-#431 design held that one mutex
/// across BOTH the staging fsync AND the home write+fsync, serialising **every** eviction through one
/// slot and two serial fsyncs — a convoy under load.
///
/// Now each evictor:
/// 1. **claims** a free ring slot from the [`FreeSlots`] allocator (a brief lock, no I/O held);
/// 2. **stages** its page into that slot and fsyncs the DWB (holds the DWB device mutex only for this
///    write+fsync, then releases it);
/// 3. runs `home_write` to write the page home and fsync the home device — holding **no** DWB lock,
///    so up to [`DWB_EVICT_RING_SLOTS`] evictors run their home writes concurrently;
/// 4. **frees** its slot (a brief lock), making it reusable — and, crucially, only *after* the home
///    write is durable (step 3 returned), so the reuse-after-durable invariant (`rmp` #411) holds.
///
/// Each in-flight evictor owns a **distinct** slot (the allocator hands out distinct indices), so the
/// slots are byte-disjoint and no evictor can clobber another's copy or the checkpoint batch region
/// (the ring is disjoint from the batch region, `rmp` #412). [`Dwb::recover_home`] scans the batch
/// region and **every** ring slot, so an in-flight evicted page is always recover-discoverable until
/// its home write is durable. If every slot is momentarily in flight, the claim backs off and retries
/// (capping concurrency at `N`-way — never incorrect, only as fast as the ring allows).
///
/// DEADLOCK-FREEDOM: `write_back` (the sole caller) holds the victim frame's write latch, then calls
/// here, which takes the free-slot lock (briefly) and the DWB device lock (briefly, for the stage),
/// and `home_write` then takes the store-device write guard while holding **no** DWB lock. Lock order
/// is uniformly frame-latch → DWB(claim/stage/free) → store-device, with no path holding the store
/// device while acquiring a DWB lock — no ABBA cycle between a checkpoint and a concurrent eviction.
pub struct DwbPageStager<D: BlockDevice> {
    dwb: std::sync::Arc<std::sync::Mutex<Dwb<D>>>,
    /// The eviction-ring free-slot allocator (`rmp` #431). A `Mutex` distinct from the DWB device
    /// mutex so claiming/freeing a slot never blocks behind another evictor's staging fsync or home
    /// write — that is what removes the convoy.
    free_slots: std::sync::Arc<std::sync::Mutex<FreeSlots>>,
}

impl<D: BlockDevice> DwbPageStager<D> {
    /// Wraps the shared persistent DWB so the pool can stage evicted pages into it, initialising the
    /// eviction-ring free-slot allocator (all [`DWB_EVICT_RING_SLOTS`] slots free).
    #[must_use]
    pub fn new(dwb: std::sync::Arc<std::sync::Mutex<Dwb<D>>>) -> Self {
        Self {
            dwb,
            free_slots: std::sync::Arc::new(std::sync::Mutex::new(FreeSlots::new())),
        }
    }

    /// Claims a free eviction-ring slot, **blocking** until one is free, and returns its index. The
    /// free-slot lock is held only for the claim attempt itself, never across I/O.
    ///
    /// CONTRACT (`rmp` #407/#431): this MUST always return a slot — it never returns without one and
    /// never falls back to an unprotected home write (that would reopen the torn-write hole #407). It
    /// is **not** a livelock: progress is guaranteed because a slot WILL free as the device-guard
    /// holders complete their home writes and call [`Self::free_slot`].
    ///
    /// CONTENTION (`rmp` #436): when `> DWB_EVICT_RING_SLOTS` dirty evictions are in flight at once,
    /// the ring is momentarily exhausted and the caller is still holding the victim frame's write
    /// latch. A bare `yield_now()` busy-spin here burns a core and prolongs that latch hold under
    /// storm — the same positive-feedback class the buffer pool hit at `rmp` #359. We instead drain
    /// the herd with the *same escalating backoff strategy* used there (`graphus_bufpool`'s
    /// `Backoff`): a few `spin_loop` hints, escalating to repeated `yield_now`, spreading the waiters
    /// in **time** so the in-flight evictors finish and free their slots, instead of re-contending the
    /// free-slot lock in lockstep. Mirrored locally (no new dependency, and the bufpool primitive is
    /// crate-private) but identical in behaviour and constants.
    fn claim_slot(&self) -> usize {
        let mut backoff = Backoff::new();
        loop {
            {
                let mut slots = self
                    .free_slots
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                if let Some(slot) = slots.claim() {
                    return slot;
                }
            }
            // Every slot is in flight (>= N concurrent evictors). Back off (escalating spin → yield)
            // and retry — correctness is preserved (we simply cap at N-way parallelism, never an
            // unprotected home write); this is the graceful-degradation path. Progress is guaranteed:
            // a device-guard holder will complete its home write and free its slot.
            backoff.spin();
        }
    }

    /// Returns a previously-claimed `slot` to the free set (post-home-durable).
    fn free_slot(&self, slot: usize) {
        let mut slots = self
            .free_slots
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        slots.free(slot);
    }
}

impl<D: BlockDevice + Send> graphus_bufpool::PageStager for DwbPageStager<D> {
    fn stage_and_sync(
        &self,
        page_id: PageId,
        image: &[u8],
        home_write: &mut dyn FnMut() -> Result<()>,
    ) -> Result<()> {
        let page: &Page = image.try_into().map_err(|_| {
            GraphusError::Storage(format!(
                "doublewrite stage: image for page {} is {} bytes, expected {PAGE_SIZE}",
                page_id.0,
                image.len()
            ))
        })?;
        // RING-SLOT PROTOCOL (`rmp` #431, upholding `rmp` #412 / #411). The eviction path stages into
        // ONE eviction-ring slot, disjoint on disk from the checkpoint **batch region**
        // (`stage_batch`) and from every other ring slot. So a concurrent checkpoint or another
        // evictor can never clobber this copy and vice versa — that closes the checkpoint-vs-eviction
        // and evictor-vs-evictor holes at the layout level.
        //
        // 1. CLAIM a free ring slot (brief free-slot lock; no I/O held). This evictor now owns `slot`
        //    exclusively until it frees it in step 4.
        let slot = self.claim_slot();
        // Helper that guarantees the slot is freed on EVERY exit path (Ok or Err) AFTER its home write
        // is known durable — except we must NOT free before the home write is durable. So we free
        // explicitly only on the success path and on a staging error (no home write happened); on a
        // home-write error the slot stays claimed by-value here and is freed in the closing block.
        //
        // 2. STAGE the copy into the claimed slot and make it durable in the DWB. We hold the DWB
        //    device mutex only for this write+fsync, then release it — so other evictors stage/home
        //    concurrently. If staging fails, no home write happened and nothing is in flight for this
        //    slot, so free it and propagate.
        let stage_result = {
            let mut dwb = self
                .dwb
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            dwb.stage_eviction_slot(slot, page_id, page)
            // DWB device mutex released here.
        };
        if let Err(e) = stage_result {
            self.free_slot(slot);
            return Err(e);
        }
        // 3. WRITE the page home and make THAT durable — holding NO DWB lock, so up to
        //    DWB_EVICT_RING_SLOTS evictors run their home writes concurrently. The slot's copy stays in
        //    place and `recover_home`-discoverable for the whole of this call (we have not freed it),
        //    so a torn home write here is repairable from `slot` on the next open. The home write is
        //    durable when this returns (the callback writes the page home and `sync_data`s the home
        //    device).
        let home_result = home_write();
        // 4. FREE the slot — now that the home write is durably complete (or failed; either way the
        //    slot is no longer needed and its copy is safe to reuse). Freeing AFTER the home write
        //    returns is what enforces reuse-after-durable (`rmp` #411): the next evictor cannot claim
        //    this slot until this page's home write is durable, so it can never overwrite a copy whose
        //    home write is still pending.
        //
        //    On a home-write *error* freeing the slot is also correct: the page's home write did not
        //    complete, but `recover_home` will still repair the (durable) DWB copy of `slot` on the
        //    next open IF that home page is torn — and a later stage into the reused slot only happens
        //    after a *successful* home write of its own page, which would have re-torn-protected the
        //    same home location. The error is propagated so the pool surfaces it (the frame's dirty
        //    flag is left set by the caller on error). For maximal safety we keep the freed copy until
        //    the next stage overwrites it; recovery is idempotent.
        self.free_slot(slot);
        home_result
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

    #[test]
    fn ring_slots_are_disjoint_and_after_the_batch_region() {
        // Every ring slot's header+data pages must be distinct from each other and beyond the batch
        // region's last data page — the byte-disjointness invariant (`rmp` #431 #3).
        let mut seen = std::collections::HashSet::new();
        let batch_last = BATCH_REGION.first_data_slot + BATCH_REGION.capacity as u64 - 1;
        for slot in 0..DWB_EVICT_RING_SLOTS {
            let r = evict_ring_region(slot);
            assert!(
                r.header_slot > batch_last,
                "ring slot {slot} overlaps batch"
            );
            assert!(seen.insert(r.header_slot), "ring slot {slot} header reused");
            assert!(
                seen.insert(r.first_data_slot),
                "ring slot {slot} data reused"
            );
        }
        // The device must be large enough to hold the highest ring slot.
        let last = evict_ring_region(DWB_EVICT_RING_SLOTS - 1).first_data_slot;
        assert!(dwb_device_pages() > last, "device too small for ring");
    }

    #[test]
    fn repairs_a_torn_page_from_a_specific_ring_slot() {
        // Stage three pages into three distinct ring slots; tear the EARLIEST-staged page's home;
        // recovery must repair it from its ring slot even though later slots are occupied too.
        let mut dwb = fresh_dwb();
        let a = make_page(2, 10, 0xA1);
        let b = make_page(3, 11, 0xB2);
        let c = make_page(4, 12, 0xC3);
        dwb.stage_eviction_slot(0, PageId(2), &a).expect("slot 0");
        dwb.stage_eviction_slot(1, PageId(3), &b).expect("slot 1");
        dwb.stage_eviction_slot(2, PageId(4), &c).expect("slot 2");

        let mut home = MemBlockDevice::new(8);
        // Page 2 (slot 0, earliest) tears; pages 3 and 4 land intact.
        let mut torn = a;
        torn[100..].iter_mut().for_each(|x| *x = 0);
        home.write_page(PageId(2), &torn).unwrap();
        home.write_page(PageId(3), &b).unwrap();
        home.write_page(PageId(4), &c).unwrap();
        home.sync_data().unwrap();

        let repaired = dwb.recover_home(&mut home).expect("recover");
        assert_eq!(repaired, 1, "only the torn page 2 should be repaired");
        let mut got: Page = [0u8; PAGE_SIZE];
        home.read_page(PageId(2), &mut got).unwrap();
        assert_eq!(
            &got[..],
            &a[..],
            "page 2 repaired from its ring slot 0 copy"
        );
    }

    #[test]
    fn reset_clears_batch_and_all_ring_slots() {
        // After `reset` (the restore path, `rmp` #417) no region — batch or ring — may protect any
        // page, so even a torn home page is left untouched.
        let mut dwb = fresh_dwb();
        let bp = make_page(1, 10, 0x11);
        let ep = make_page(2, 20, 0x22);
        dwb.stage_batch(&[(PageId(1), &bp)]).expect("batch");
        dwb.stage_eviction_slot(5, PageId(2), &ep).expect("ring");

        dwb.reset().expect("reset");
        assert!(dwb.staged_home_ids().expect("batch ids").is_empty());
        assert!(dwb.evicted_home_ids().expect("ring ids").is_empty());

        let mut home = MemBlockDevice::new(4);
        let mut torn = bp;
        torn[100..].iter_mut().for_each(|x| *x = 0);
        home.write_page(PageId(1), &torn).unwrap();
        home.sync_data().unwrap();
        assert_eq!(
            dwb.recover_home(&mut home).expect("recover"),
            0,
            "reset must leave no batch in any region"
        );
    }

    #[test]
    fn stage_eviction_slot_out_of_range_is_rejected() {
        let mut dwb = fresh_dwb();
        let p = make_page(1, 1, 0);
        assert!(
            dwb.stage_eviction_slot(DWB_EVICT_RING_SLOTS, PageId(1), &p)
                .is_err()
        );
    }

    #[test]
    fn upgrade_from_old_dwb_is_handled_safely() {
        // `rmp` #434: an older-format DWB device must be detected and handled, never silently misread.
        //
        // Case A — a TOO-SMALL old device (pre-#431 v2 two-region layout, `1 + DWB_MAX_BATCH + 2`
        // pages) is shorter than the v3 ring layout. `Dwb::new` must GROW it (no OOB read) and its
        // headers must decode as "no batch".
        let old_pages = (1 + DWB_MAX_BATCH as u64) + 2; // the v2 layout size
        let dev = MemBlockDevice::new(old_pages);
        let mut dwb = Dwb::new(dev).expect("grow old device");
        assert!(
            dwb.device.page_count() >= dwb_device_pages(),
            "an undersized old device must be grown to the v3 ring size"
        );
        let mut home = MemBlockDevice::new(4);
        assert_eq!(
            dwb.recover_home(&mut home).expect("recover"),
            0,
            "a grown old-format device must decode as no batch"
        );

        // Case B — a device that is ALREADY large enough but carries a stale v2-magic batch header
        // (a clean-shutdown old device that was over-sized). Its v2 magic differs from v3, so
        // `decode_header` rejects it as "no batch" — it is never misread as a current-format batch,
        // and a torn home page is therefore NOT restored from a stale v2 copy.
        const V2_MAGIC: u64 = 0x0000_0002_4257_4447;
        let mut big = MemBlockDevice::new(dwb_device_pages());
        let mut hdr = [0u8; PAGE_SIZE];
        hdr[HDR_OFF_MAGIC..HDR_OFF_MAGIC + 8].copy_from_slice(&V2_MAGIC.to_le_bytes());
        hdr[HDR_OFF_COUNT..HDR_OFF_COUNT + 8].copy_from_slice(&1u64.to_le_bytes());
        hdr[HDR_OFF_HOMES..HDR_OFF_HOMES + 8].copy_from_slice(&2u64.to_le_bytes());
        page::write_checksum(&mut hdr); // a checksum-VALID but v2-magic header
        big.write_page(PageId(BATCH_REGION.header_slot), &hdr)
            .unwrap();
        big.sync_data().unwrap();
        let mut dwb = Dwb::new(big).expect("open large old device");
        assert!(
            dwb.staged_home_ids().expect("ids").is_empty(),
            "a v2-magic header must decode as no batch under v3 (rmp #434)"
        );
        let mut home = MemBlockDevice::new(4);
        let good = make_page(2, 50, 0xAB);
        let mut torn = good;
        torn[100..].iter_mut().for_each(|b| *b = 0);
        home.write_page(PageId(2), &torn).unwrap();
        home.sync_data().unwrap();
        assert_eq!(
            dwb.recover_home(&mut home).expect("recover"),
            0,
            "a stale v2 batch must NOT be applied over a torn v3 home page"
        );
    }

    #[test]
    fn free_slots_allocator_hands_out_distinct_slots() {
        let mut fs = FreeSlots::new();
        let mut claimed = std::collections::HashSet::new();
        for _ in 0..DWB_EVICT_RING_SLOTS {
            let s = fs.claim().expect("slot available");
            assert!(claimed.insert(s), "allocator handed out slot {s} twice");
        }
        assert!(fs.claim().is_none(), "ring exhausted: no more free slots");
        // Free one and re-claim it.
        let some = *claimed.iter().next().unwrap();
        fs.free(some);
        assert_eq!(fs.claim(), Some(some), "freed slot is reclaimable");
    }
}
