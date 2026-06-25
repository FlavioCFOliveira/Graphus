//! In-memory block device modelling the page-cache / durability boundary, with crash,
//! torn-write and a full seed-driven disk-corruption fault model for Deterministic Simulation
//! Testing (decision `D-dst-investment`).
//!
//! The corruption faults are armed explicitly through a [`FaultPlan`] and are a pure function of the
//! plan's seed: there is no wall clock and no OS entropy on any path, so the same plan reproduces an
//! identical corruption bit-for-bit (`specification/04-technical-design.md` §11.1). Every fault is
//! designed to be *detectable* — corrupt data is never silently served as valid: bit-rot and
//! misdirected reads surface through the page checksum the caller verifies, a latent sector error
//! surfaces as a hard read failure, ENOSPC surfaces as an `extend` failure, and a write-reordering
//! sync leaves a crash-losable subset of writes that recovery must reconcile.

use std::collections::HashMap;

use graphus_core::PageId;
use graphus_core::error::{GraphusError, Result};

use crate::block::{BlockDevice, PAGE_SIZE, Page};

/// The physical sector size a torn write is modelled at. A real power loss tears a write at the
/// device's atomic write unit: some sectors carry the *new* bytes, some retain the *old* (pre-write)
/// bytes, never a byte-granular split mid-sector. `4096` models a modern Advanced Format (4Kn) drive
/// — the realistic default for contemporary storage. At [`PAGE_SIZE`] = 8192 this yields two sectors
/// per page, enough to produce the header/body split a coarse check could miss (an OLD header sector
/// over a NEW body sector, or the reverse). It must divide [`PAGE_SIZE`] (asserted in tests).
pub const TORN_SECTOR_SIZE: usize = 4096;

/// Computes the sector-granular torn image of writing `new` bytes over the current `old` page,
/// seeded by `seed` — the single source of truth for the sector-tear pattern, shared by the device's
/// injected fault ([`MemBlockDevice::arm_torn_write_sectors`]) and any caller that needs to *predict*
/// the same image deterministically (e.g. the DST harness selecting a page whose tear provably
/// corrupts it).
///
/// The page is partitioned into [`TORN_SECTOR_SIZE`] sectors; each sector independently — by a
/// deterministic, seeded coin flip — takes the `new` bytes or keeps the `old` ones. The choice is
/// forced non-trivial (at least one OLD sector and one NEW sector), so the result differs from both
/// `old` and `new`: a genuine partial write a checksum must catch, never a vacuous all-old/all-new
/// copy. The same `(old, new, seed)` always yields the identical image — determinism is load-bearing
/// for DST. A degenerate single-sector page is split in half (old header / new body) so even then it
/// is a real old/new mix rather than all-or-nothing.
#[must_use]
pub fn sector_torn_image(old: &Page, new: &Page, seed: u64) -> Page {
    // Sector count over the page. `TORN_SECTOR_SIZE` divides `PAGE_SIZE` (8192 = 2 * 4096); the
    // ceiling division keeps this correct even if that ever changes (a short trailing sector is
    // still treated as one whole unit, as a device would on its last sector).
    let sectors = PAGE_SIZE.div_ceil(TORN_SECTOR_SIZE);
    if sectors <= 1 {
        // A single sector cannot be a sector-wise mix; tear it in half so the page is still a
        // genuine old/new split (header half old, body half new) rather than all-or-nothing.
        let mut torn = *old;
        let half = PAGE_SIZE / 2;
        torn[half..].copy_from_slice(&new[half..]);
        return torn;
    }
    // Seed the per-page stream so the same seed reproduces the identical pattern.
    let mut rng = SplitMix64::new(seed ^ 0x7A6B_5C4D_3E2F_1A0B);
    // Draw a fresh take/keep mask until it is non-trivial (some old, some new). With >= 2 sectors a
    // non-uniform draw is reached almost immediately; the loop only guards the rare all-same draw.
    let mut takes_new = vec![false; sectors];
    loop {
        for t in takes_new.iter_mut() {
            *t = rng.below(2) == 1;
        }
        let any_new = takes_new.iter().any(|&t| t);
        let any_old = takes_new.iter().any(|&t| !t);
        if any_new && any_old {
            break;
        }
    }
    let mut torn = *old;
    for (s, &take_new) in takes_new.iter().enumerate() {
        if take_new {
            let start = s * TORN_SECTOR_SIZE;
            let end = (start + TORN_SECTOR_SIZE).min(PAGE_SIZE);
            torn[start..end].copy_from_slice(&new[start..end]);
        }
    }
    torn
}

/// A tiny, allocation-free [SplitMix64] PRNG, seeded explicitly. Used to derive every stochastic
/// choice in a [`FaultPlan`] (which bytes to flip, which subset of pending writes a reordering sync
/// drops) so a plan is reproducible from its seed alone, without pulling an external RNG crate.
///
/// [SplitMix64]: https://prng.di.unimi.it/splitmix64.c
#[derive(Debug, Clone)]
struct SplitMix64 {
    state: u64,
}

impl SplitMix64 {
    fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// A uniform draw in `0..n` (`0` when `n == 0`). The modulo bias is negligible for the small `n`
    /// this device uses and, crucially, is identical for a given seed — all determinism requires.
    fn below(&mut self, n: u64) -> u64 {
        if n == 0 { 0 } else { self.next_u64() % n }
    }
}

/// A seed-driven schedule of disk-corruption faults for a [`MemBlockDevice`], armed explicitly via
/// [`MemBlockDevice::arm_fault_plan`].
///
/// Each fault is opt-in (a `None`/empty field is inert) and every armed fault is a pure function of
/// the plan's seed: the same plan injects identical corruption every run. The model covers
/// the disk faults the DST/VOPR simulator needs (`04 §11.5`):
///
/// * **bit-rot** — flip seeded bytes when a target page is *read*, so its checksum must catch it;
/// * **misdirected I/O** — read or write returns/persists the wrong page id;
/// * **latent sector error** — a page is marked unreadable so a later read hard-fails;
/// * **ENOSPC** — [`extend`](BlockDevice::extend) past a seeded capacity fails;
/// * **write reordering** — a sync does *not* atomically drain the cache, so a crash can lose an
///   arbitrary seeded subset of the pre-sync writes (resolves the former `DeferredFault::WriteReordering`
///   in `graphus-dst`, now a real injected fault).
#[derive(Debug, Clone, Default)]
pub struct FaultPlan {
    /// The seed every stochastic choice derives from.
    seed: u64,
    /// Pages to corrupt on read with bit-rot, and how many bytes to flip in each.
    bit_rot: HashMap<u64, usize>,
    /// Misdirected reads: reading `from` returns the contents of page `to` instead.
    misdirected_read: HashMap<u64, u64>,
    /// Misdirected writes: writing `from` persists to page `to` instead.
    misdirected_write: HashMap<u64, u64>,
    /// Pages that are unreadable (latent sector error): a read of one hard-fails.
    latent_sector_error: Vec<u64>,
    /// Maximum page count [`extend`](BlockDevice::extend) may grow to before failing with ENOSPC.
    capacity_pages: Option<u64>,
    /// When set, a sync persists only this fraction (`0..=100`) of the pending cache, leaving the
    /// rest crash-losable (write reordering: the sync did not atomically drain the cache).
    reorder_sync_persist_percent: Option<u64>,
}

impl FaultPlan {
    /// Creates an empty plan seeded by `seed`. With no fault armed the plan is inert and the device
    /// behaves exactly as an un-faulted one.
    #[must_use]
    pub fn new(seed: u64) -> Self {
        Self {
            seed,
            ..Self::default()
        }
    }

    /// Arms bit-rot on `page`: the next read of it flips `flips` seeded bytes, so its checksum must
    /// catch the corruption. `flips` is clamped to the page size.
    #[must_use]
    pub fn with_bit_rot(mut self, page: PageId, flips: usize) -> Self {
        self.bit_rot.insert(page.0, flips.min(PAGE_SIZE));
        self
    }

    /// Arms a misdirected read: reading `from` returns the bytes of page `to` instead (a checksum
    /// over the page header's own id must catch the substitution).
    #[must_use]
    pub fn with_misdirected_read(mut self, from: PageId, to: PageId) -> Self {
        self.misdirected_read.insert(from.0, to.0);
        self
    }

    /// Arms a misdirected write: writing `from` persists to page `to` instead, so `from` keeps its
    /// old contents and `to` is silently overwritten.
    #[must_use]
    pub fn with_misdirected_write(mut self, from: PageId, to: PageId) -> Self {
        self.misdirected_write.insert(from.0, to.0);
        self
    }

    /// Arms a latent sector error on `page`: any later read of it hard-fails with an I/O error
    /// (modelling an unreadable sector that develops after the data was written).
    #[must_use]
    pub fn with_latent_sector_error(mut self, page: PageId) -> Self {
        self.latent_sector_error.push(page.0);
        self
    }

    /// Arms ENOSPC: [`extend`](BlockDevice::extend) fails once growth would exceed `capacity_pages`
    /// total pages, modelling a full disk.
    #[must_use]
    pub fn with_capacity(mut self, capacity_pages: u64) -> Self {
        self.capacity_pages = Some(capacity_pages);
        self
    }

    /// Arms write reordering: a sync persists only `persist_percent` (`0..=100`, seeded which pages)
    /// of the pending cache and leaves the rest cached, so a subsequent [`MemBlockDevice::crash`]
    /// loses that pre-sync subset. Models a sync that does not atomically drain the cache.
    #[must_use]
    pub fn with_write_reordering(mut self, persist_percent: u64) -> Self {
        self.reorder_sync_persist_percent = Some(persist_percent.min(100));
        self
    }
}

/// An in-memory [`BlockDevice`] whose writes land in a cache and only become durable on a sync;
/// [`MemBlockDevice::crash`] discards un-synced writes, modelling power loss.
///
/// One-shot faults can be armed to exercise recovery: an I/O error on the next write; a coarse torn
/// write that stores only a prefix of a page ([`arm_torn_write`](MemBlockDevice::arm_torn_write)); or
/// a faithful sector-granular torn write that mixes whole sectors of old and new bytes
/// ([`arm_torn_write_sectors`](MemBlockDevice::arm_torn_write_sectors)), modelling a real power loss.
/// A richer seed-driven [`FaultPlan`] arms the full disk-corruption model (bit-rot, misdirected I/O,
/// latent sector errors, ENOSPC, write reordering).
#[derive(Debug, Default)]
pub struct MemBlockDevice {
    /// Pages that have been synced and would survive a crash.
    persisted: Vec<Page>,
    /// Written-but-not-yet-synced pages (the modelled page cache).
    cache: HashMap<u64, Page>,
    /// When set, the next `write_page` fails (then clears).
    armed_io_error: bool,
    /// When set, the next write to this page stores only `prefix` bytes (then clears).
    armed_torn: Option<(u64, usize)>,
    /// When set, the next write to this page is torn at sector granularity, seeded by the `u64`:
    /// each [`TORN_SECTOR_SIZE`] sector independently keeps the OLD (pre-write) bytes or takes the
    /// NEW bytes (then clears). Models a real power loss far more faithfully than `armed_torn`.
    armed_torn_sectors: Option<(u64, u64)>,
    /// The seed-driven disk-corruption schedule, if armed.
    plan: Option<FaultPlan>,
}

impl MemBlockDevice {
    /// Creates a device of `pages` zero-filled, durable pages.
    #[must_use]
    pub fn new(pages: u64) -> Self {
        Self {
            persisted: vec![[0u8; PAGE_SIZE]; pages as usize],
            ..Self::default()
        }
    }

    /// Arms a one-shot I/O error on the next `write_page`.
    pub fn arm_io_error(&mut self) {
        self.armed_io_error = true;
    }

    /// Arms a one-shot torn write: the next write to `page` stores only its first `prefix`
    /// bytes, leaving the rest of the page as it was (a corruption a checksum must catch).
    ///
    /// This is the coarse byte-prefix model. For a faithful power-loss image use
    /// [`arm_torn_write_sectors`](Self::arm_torn_write_sectors), which mixes whole sectors of old and
    /// new bytes rather than a single new/old boundary.
    pub fn arm_torn_write(&mut self, page: PageId, prefix: usize) {
        self.armed_torn = Some((page.0, prefix.min(PAGE_SIZE)));
    }

    /// Arms a one-shot **sector-granular** torn write on `page`, seeded by `seed`.
    ///
    /// On the next write to `page`, the page is partitioned into [`TORN_SECTOR_SIZE`] sectors and
    /// each sector independently — by a deterministic, seeded coin flip — either takes the NEW bytes
    /// being written or retains the OLD (pre-write) bytes already on the device. This is what a real
    /// power loss produces: the device's atomic write unit is the sector, so a torn page is a
    /// sector-wise *mix* of old and new content, never a byte-prefix of new over a zeroed tail.
    ///
    /// The seeded choice is forced to be non-trivial: at least one sector keeps OLD bytes and at
    /// least one takes NEW bytes, so the torn image genuinely differs from both the pre- and
    /// post-write page (a vacuous "all old" or "all new" tear would not exercise recovery). The same
    /// `seed` reproduces the identical sector pattern — determinism is load-bearing for DST. The fault
    /// reads the device's current (pre-write) bytes for `page` at write time, so the retained sectors
    /// are exactly the old durable/cached content.
    pub fn arm_torn_write_sectors(&mut self, page: PageId, seed: u64) {
        self.armed_torn_sectors = Some((page.0, seed));
    }

    /// Arms a seed-driven [`FaultPlan`] of disk-corruption faults. Replaces any previously armed
    /// plan; the one-shot `arm_io_error`/`arm_torn_write` seams remain independent.
    pub fn arm_fault_plan(&mut self, plan: FaultPlan) {
        self.plan = Some(plan);
    }

    /// Models power loss: discards all un-synced (cached) writes.
    pub fn crash(&mut self) {
        self.cache.clear();
    }

    /// The number of un-synced cached writes.
    #[must_use]
    pub fn dirty_pages(&self) -> usize {
        self.cache.len()
    }

    fn current(&self, idx: u64) -> &Page {
        self.cache
            .get(&idx)
            .unwrap_or(&self.persisted[idx as usize])
    }

    /// Applies seed-driven bit-rot to `idx`'s freshly-read bytes, if armed. The flips are derived
    /// from `(seed, idx)` so they are identical every run and per page, and each flip is forced to
    /// change a byte (XOR with a non-zero mask), so the corruption is never a no-op a checksum
    /// could miss.
    fn apply_bit_rot(&self, idx: u64, buf: &mut Page) {
        let Some(plan) = &self.plan else { return };
        let Some(&flips) = plan.bit_rot.get(&idx) else {
            return;
        };
        // Seed the per-page stream from the plan seed mixed with the page id, so different pages rot
        // differently yet each is deterministic.
        let mut rng = SplitMix64::new(plan.seed ^ idx.wrapping_mul(0x100_0000_01B3));
        for _ in 0..flips {
            let pos = rng.below(PAGE_SIZE as u64) as usize;
            // A non-zero mask guarantees the byte actually changes (a 0 mask would be a vacuous flip).
            let mask = (rng.below(255) as u8).wrapping_add(1);
            buf[pos] ^= mask;
        }
    }

    /// Builds the sector-granular torn image for a write of `new` bytes over the current `old` page,
    /// seeded by `seed`. The page is split into [`TORN_SECTOR_SIZE`] sectors; each sector
    /// deterministically (seeded) takes `new` or keeps `old`. The choice is forced non-trivial: at
    /// least one sector keeps OLD and at least one takes NEW, so the result differs from both `old`
    /// and `new` (a real partial write, not a vacuous all-old/all-new copy).
    fn build_sector_torn(old: &Page, new: &Page, seed: u64) -> Page {
        sector_torn_image(old, new, seed)
    }

    /// The page id a write to `idx` actually lands on (misdirected-write redirection, if armed).
    fn write_target(&self, idx: u64) -> u64 {
        self.plan
            .as_ref()
            .and_then(|p| p.misdirected_write.get(&idx).copied())
            .unwrap_or(idx)
    }
}

impl BlockDevice for MemBlockDevice {
    fn read_page(&self, page: PageId, buf: &mut Page) -> Result<()> {
        if page.0 >= self.persisted.len() as u64 {
            return Err(GraphusError::Storage(format!(
                "read out of range: page {}",
                page.0
            )));
        }
        // Latent sector error: an unreadable sector hard-fails the read rather than serving bytes.
        if let Some(plan) = &self.plan
            && plan.latent_sector_error.contains(&page.0)
        {
            return Err(GraphusError::Storage(format!(
                "latent sector error: page {} unreadable",
                page.0
            )));
        }
        // Misdirected read: return the contents of a *different* page (its header carries the wrong
        // id, so the caller's page checksum/id check must catch the substitution).
        let source = self
            .plan
            .as_ref()
            .and_then(|p| p.misdirected_read.get(&page.0).copied())
            .filter(|&to| to < self.persisted.len() as u64)
            .unwrap_or(page.0);
        buf.copy_from_slice(self.current(source));
        // Bit-rot: flip seeded bytes after the read so the page no longer matches its checksum.
        self.apply_bit_rot(page.0, buf);
        Ok(())
    }

    fn write_page(&mut self, page: PageId, buf: &Page) -> Result<()> {
        let idx = page.0;
        if idx >= self.persisted.len() as u64 {
            return Err(GraphusError::Storage(format!(
                "write out of range: page {idx}"
            )));
        }
        if self.armed_io_error {
            self.armed_io_error = false;
            return Err(GraphusError::Storage("injected I/O error".to_owned()));
        }
        // Misdirected write: the bytes land on a *different*, in-range page; `idx` keeps its old
        // contents and the target page is silently overwritten.
        let target = self.write_target(idx);
        if target >= self.persisted.len() as u64 {
            return Err(GraphusError::Storage(format!(
                "misdirected write out of range: page {target}"
            )));
        }
        let mut page_buf = *buf;
        if let Some((tp, prefix)) = self.armed_torn.take() {
            if tp == idx {
                let mut torn = *self.current(target);
                torn[..prefix].copy_from_slice(&buf[..prefix]);
                page_buf = torn;
            } else {
                self.armed_torn = Some((tp, prefix)); // not this page; keep it armed
            }
        }
        // Sector-granular torn write: a faithful power-loss image where whole sectors keep the OLD
        // (pre-write) bytes or take the NEW ones. Reads the current bytes for the *target* page (the
        // device's pre-write content, cache or persisted) so retained sectors carry the real old data.
        if let Some((tp, seed)) = self.armed_torn_sectors.take() {
            if tp == idx {
                let old = *self.current(target);
                page_buf = Self::build_sector_torn(&old, &page_buf, seed);
            } else {
                self.armed_torn_sectors = Some((tp, seed)); // not this page; keep it armed
            }
        }
        self.cache.insert(target, page_buf);
        Ok(())
    }

    fn sync_data(&mut self) -> Result<()> {
        // Write reordering: when armed, the sync does NOT atomically drain the cache. It persists
        // only a seeded subset of pending pages and leaves the rest cached, so a subsequent crash
        // loses that pre-sync subset (modelling a non-atomic, reordered flush).
        if let Some(percent) = self
            .plan
            .as_ref()
            .and_then(|p| p.reorder_sync_persist_percent)
        {
            // A stable, seed-driven order over the pending page ids, so the persisted subset is the
            // same for a given plan regardless of the cache's hash iteration order.
            let mut pending: Vec<u64> = self.cache.keys().copied().collect();
            pending.sort_unstable();
            let seed = self.plan.as_ref().map_or(0, |p| p.seed);
            let mut rng = SplitMix64::new(seed ^ 0x5DEE_CE66_D5A1_3CA1);
            for idx in pending {
                if rng.below(100) < percent {
                    if let Some(page) = self.cache.remove(&idx) {
                        self.persisted[idx as usize] = page;
                    }
                }
                // Otherwise the page stays in the cache: not yet durable, lost on the next crash.
            }
            return Ok(());
        }
        for (idx, page) in self.cache.drain() {
            self.persisted[idx as usize] = page;
        }
        Ok(())
    }

    fn sync_all(&mut self) -> Result<()> {
        self.sync_data()
    }

    fn page_count(&self) -> u64 {
        self.persisted.len() as u64
    }

    fn extend(&mut self, additional: u64) -> Result<()> {
        let new_len = self
            .persisted
            .len()
            .checked_add(additional as usize)
            .ok_or_else(|| GraphusError::Storage("page count overflow".to_owned()))?;
        // ENOSPC: a seeded capacity caps how large the device may grow, modelling a full disk.
        if let Some(plan) = &self.plan
            && let Some(cap) = plan.capacity_pages
            && new_len as u64 > cap
        {
            return Err(GraphusError::Storage(format!(
                "ENOSPC: cannot grow to {new_len} pages (capacity {cap})"
            )));
        }
        self.persisted.resize(new_len, [0u8; PAGE_SIZE]);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn page_of(byte: u8) -> Page {
        [byte; PAGE_SIZE]
    }

    fn read(dev: &MemBlockDevice, page: u64) -> Page {
        let mut buf = [0u8; PAGE_SIZE];
        dev.read_page(PageId(page), &mut buf).unwrap();
        buf
    }

    #[test]
    fn cached_write_is_visible_then_crash_loses_it() {
        let mut dev = MemBlockDevice::new(2);
        dev.write_page(PageId(0), &page_of(0xAB)).unwrap();
        let mut buf = [0u8; PAGE_SIZE];
        dev.read_page(PageId(0), &mut buf).unwrap();
        assert_eq!(buf[0], 0xAB); // visible before sync
        dev.crash();
        assert_eq!(dev.dirty_pages(), 0);
        dev.read_page(PageId(0), &mut buf).unwrap();
        assert_eq!(buf[0], 0x00); // un-synced write was lost
    }

    #[test]
    fn synced_write_survives_crash() {
        let mut dev = MemBlockDevice::new(1);
        dev.write_page(PageId(0), &page_of(0x7E)).unwrap();
        dev.sync_all().unwrap();
        dev.crash();
        let mut buf = [0u8; PAGE_SIZE];
        dev.read_page(PageId(0), &mut buf).unwrap();
        assert_eq!(buf[0], 0x7E);
    }

    #[test]
    fn injected_io_error_fires_once() {
        let mut dev = MemBlockDevice::new(1);
        dev.arm_io_error();
        assert!(dev.write_page(PageId(0), &page_of(1)).is_err());
        assert!(dev.write_page(PageId(0), &page_of(1)).is_ok());
    }

    #[test]
    fn torn_write_leaves_a_detectable_partial_page() {
        let mut dev = MemBlockDevice::new(1);
        dev.sync_all().unwrap(); // page 0 is zero and durable
        dev.arm_torn_write(PageId(0), 100);
        dev.write_page(PageId(0), &page_of(0xFF)).unwrap();
        let mut buf = [0u8; PAGE_SIZE];
        dev.read_page(PageId(0), &mut buf).unwrap();
        assert!(buf[..100].iter().all(|&b| b == 0xFF));
        assert!(buf[100..].iter().all(|&b| b == 0x00)); // tail kept old bytes => torn
    }

    /// A simple whole-page CRC32 (IEEE polynomial), used only by the test below to prove a torn
    /// page is *detectable* by a whole-page checksum without pulling the `graphus-bufpool` page codec
    /// (which depends on this crate — a dependency cycle Cargo forbids). The realistic
    /// header+`verify_checksum` integration gate lives in `graphus-dst`'s `torn_data_page` test,
    /// which legitimately depends on `graphus-bufpool`.
    fn page_crc32(page: &Page) -> u32 {
        let mut crc: u32 = 0xFFFF_FFFF;
        for &byte in page.iter() {
            crc ^= u32::from(byte);
            for _ in 0..8 {
                let mask = (crc & 1).wrapping_neg();
                crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
            }
        }
        !crc
    }

    /// A sector-granular torn write produces a sector-wise *mix* of old and new bytes (not a byte
    /// prefix of new over old), the mix is deterministic per seed, and a whole-page checksum still
    /// flags it as torn. This is the regression gate for rmp #433: the realistic power-loss image
    /// where an OLD header sector can sit over a NEW body sector (or the reverse), a state a coarse
    /// prefix tear could never produce.
    #[test]
    fn sector_torn_write_mixes_old_and_new_sectors_deterministically() {
        assert_eq!(
            PAGE_SIZE % TORN_SECTOR_SIZE,
            0,
            "the sector size must divide the page size for a clean sector model"
        );
        let sectors = PAGE_SIZE / TORN_SECTOR_SIZE;
        assert!(sectors >= 2, "need >= 2 sectors to model an old/new split");

        // OLD durable page (e.g. a valid header in sector 0); NEW page with different bytes
        // everywhere (the write that is torn mid-flight by the power loss).
        let old = page_of(0xA0);
        let new = page_of(0x0B);

        let run = |seed: u64| {
            let mut dev = MemBlockDevice::new(1);
            dev.write_page(PageId(0), &old).unwrap();
            dev.sync_all().unwrap(); // old page durable
            dev.arm_torn_write_sectors(PageId(0), seed);
            dev.write_page(PageId(0), &new).unwrap(); // torn at sector granularity
            read(&dev, 0)
        };

        // Find a seed that produces the canonical rmp #433 shape: an OLD header sector (sector 0)
        // sitting over a NEW body sector (sector 1) — a "valid old header + new body" image the old
        // byte-prefix model (which always kept the NEW bytes at the front) could NEVER produce. This
        // is the realistic partial-sector state the fix exists to exercise.
        let seed = (0..1024u64)
            .find(|&s| {
                let t = run(s);
                t[..TORN_SECTOR_SIZE] == old[..TORN_SECTOR_SIZE]
                    && t[TORN_SECTOR_SIZE..2 * TORN_SECTOR_SIZE]
                        == new[TORN_SECTOR_SIZE..2 * TORN_SECTOR_SIZE]
            })
            .expect("a seed yielding an OLD-header / NEW-body sector tear must exist");

        let torn_a = run(seed);
        let torn_b = run(seed);

        // The canonical shape holds: sector 0 is OLD, sector 1 is NEW — impossible under a prefix
        // tear, where the leading bytes are always the NEW ones.
        assert_eq!(
            torn_a[..TORN_SECTOR_SIZE],
            old[..TORN_SECTOR_SIZE],
            "header sector must retain the OLD bytes (a prefix tear could never do this)"
        );
        assert_eq!(
            torn_a[TORN_SECTOR_SIZE..2 * TORN_SECTOR_SIZE],
            new[TORN_SECTOR_SIZE..2 * TORN_SECTOR_SIZE],
            "body sector must carry the NEW bytes"
        );

        // (b) Determinism: same seed reproduces the identical torn pattern, byte for byte.
        assert_eq!(
            torn_a, torn_b,
            "same seed must reproduce the identical sector-torn pattern"
        );

        // (a) Sector-wise mix, NOT a byte-prefix: classify each sector as fully-old or fully-new and
        // require at least one of each. A prefix tear cannot make an *earlier* sector new while a
        // *later* one is old; here the seeded choice is independent per sector.
        let mut old_sectors = 0usize;
        let mut new_sectors = 0usize;
        for s in 0..sectors {
            let start = s * TORN_SECTOR_SIZE;
            let end = start + TORN_SECTOR_SIZE;
            let seg = &torn_a[start..end];
            if seg == &old[start..end] {
                old_sectors += 1;
            } else if seg == &new[start..end] {
                new_sectors += 1;
            } else {
                panic!("sector {s} is neither fully old nor fully new — not sector-granular");
            }
        }
        assert!(
            old_sectors >= 1 && new_sectors >= 1,
            "a sector-torn page must mix old and new sectors (saw {old_sectors} old, {new_sectors} new)"
        );

        // The torn image differs from BOTH the clean old and the clean new pages (a real partial
        // write, not a vacuous all-old or all-new copy).
        assert_ne!(torn_a, old, "torn page must differ from the old image");
        assert_ne!(torn_a, new, "torn page must differ from the new image");

        // (c) A whole-page checksum still flags the torn page as corrupt: its CRC differs from both
        // the old and the new clean pages, so any whole-page checksum check rejects it.
        let torn_crc = page_crc32(&torn_a);
        assert_ne!(
            torn_crc,
            page_crc32(&old),
            "torn page must not pass as the old page"
        );
        assert_ne!(
            torn_crc,
            page_crc32(&new),
            "torn page must not pass as the new page"
        );
    }

    /// A different seed tears a different set of sectors (the pattern tracks the seed), proving the
    /// sector choice is genuinely seed-driven and not fixed.
    #[test]
    fn sector_torn_pattern_varies_with_seed() {
        let old = page_of(0x11);
        let new = page_of(0x22);
        let run = |seed: u64| {
            let mut dev = MemBlockDevice::new(1);
            dev.write_page(PageId(0), &old).unwrap();
            dev.sync_all().unwrap();
            dev.arm_torn_write_sectors(PageId(0), seed);
            dev.write_page(PageId(0), &new).unwrap();
            read(&dev, 0)
        };
        // Scan a small seed range for two seeds that disagree. With independent per-sector coin flips
        // over >= 2 sectors, distinct patterns are abundant, so this finds a difference quickly.
        let base = run(1);
        let differs = (2..=64u64).any(|s| run(s) != base);
        assert!(differs, "the sector-torn pattern must vary with the seed");
    }

    #[test]
    fn out_of_range_access_errors() {
        let mut dev = MemBlockDevice::new(1);
        let mut buf = [0u8; PAGE_SIZE];
        assert!(dev.read_page(PageId(1), &mut buf).is_err());
        assert!(dev.write_page(PageId(1), &page_of(1)).is_err());
    }

    // --- FaultPlan: seed-driven disk-corruption model -----------------------------------------

    /// Bit-rot is deterministic (same seed => identical corruption) and detectable (the read bytes
    /// no longer equal what was durably written, so a checksum over them must fail).
    #[test]
    fn bit_rot_is_deterministic_and_corrupts_the_page() {
        let build = || {
            let mut dev = MemBlockDevice::new(1);
            dev.write_page(PageId(0), &page_of(0xAA)).unwrap();
            dev.sync_all().unwrap();
            dev.arm_fault_plan(FaultPlan::new(0x1234).with_bit_rot(PageId(0), 8));
            dev
        };
        let a = read(&build(), 0);
        let b = read(&build(), 0);
        assert_eq!(a, b, "same seed must produce identical bit-rot");
        let clean = page_of(0xAA);
        assert_ne!(a, clean, "bit-rot must actually corrupt the served bytes");
        let differing = a.iter().zip(clean.iter()).filter(|(x, y)| x != y).count();
        assert!(
            (1..=8).contains(&differing),
            "expected up to 8 flipped bytes, saw {differing}"
        );
    }

    /// A different seed rots a different set of bytes (the corruption tracks the seed).
    #[test]
    fn bit_rot_varies_with_seed() {
        let build = |seed: u64| {
            let mut dev = MemBlockDevice::new(1);
            dev.write_page(PageId(0), &page_of(0x55)).unwrap();
            dev.sync_all().unwrap();
            dev.arm_fault_plan(FaultPlan::new(seed).with_bit_rot(PageId(0), 16));
            dev
        };
        assert_ne!(read(&build(1), 0), read(&build(2), 0));
    }

    /// A misdirected read serves another page's bytes; the substitution is visible (and a header
    /// id/checksum check would reject it).
    #[test]
    fn misdirected_read_serves_the_wrong_page() {
        let mut dev = MemBlockDevice::new(2);
        dev.write_page(PageId(0), &page_of(0x11)).unwrap();
        dev.write_page(PageId(1), &page_of(0x22)).unwrap();
        dev.sync_all().unwrap();
        dev.arm_fault_plan(FaultPlan::new(7).with_misdirected_read(PageId(0), PageId(1)));
        assert_eq!(read(&dev, 0)[0], 0x22, "read of page 0 returned page 1");
        assert_eq!(read(&dev, 1)[0], 0x22); // page 1 itself is unaffected
    }

    /// A misdirected write persists to the wrong page: the intended page keeps its old contents and
    /// the redirected page is silently overwritten.
    #[test]
    fn misdirected_write_persists_to_the_wrong_page() {
        let mut dev = MemBlockDevice::new(2);
        dev.arm_fault_plan(FaultPlan::new(9).with_misdirected_write(PageId(0), PageId(1)));
        dev.write_page(PageId(0), &page_of(0xCD)).unwrap();
        dev.sync_all().unwrap();
        assert_eq!(read(&dev, 0)[0], 0x00, "intended page 0 stayed untouched");
        assert_eq!(read(&dev, 1)[0], 0xCD, "write landed on page 1");
    }

    /// A latent sector error makes a page unreadable: the read hard-fails instead of serving bytes.
    #[test]
    fn latent_sector_error_fails_the_read() {
        let mut dev = MemBlockDevice::new(2);
        dev.write_page(PageId(0), &page_of(1)).unwrap();
        dev.write_page(PageId(1), &page_of(2)).unwrap();
        dev.sync_all().unwrap();
        dev.arm_fault_plan(FaultPlan::new(3).with_latent_sector_error(PageId(0)));
        let mut buf = [0u8; PAGE_SIZE];
        assert!(
            dev.read_page(PageId(0), &mut buf).is_err(),
            "unreadable sector must surface as an error"
        );
        assert!(dev.read_page(PageId(1), &mut buf).is_ok()); // other pages still read
    }

    /// ENOSPC: extending past the seeded capacity fails deterministically, and growth up to the cap
    /// still succeeds.
    #[test]
    fn enospc_fails_extend_past_capacity() {
        let mut dev = MemBlockDevice::new(2);
        dev.arm_fault_plan(FaultPlan::new(0).with_capacity(4));
        assert!(dev.extend(2).is_ok(), "growth to the cap is allowed");
        assert_eq!(dev.page_count(), 4);
        assert!(dev.extend(1).is_err(), "growth past the cap is ENOSPC");
        assert!(dev.extend(1).is_err(), "ENOSPC is sticky, not one-shot");
        assert_eq!(dev.page_count(), 4, "a failed extend grew nothing");
    }

    /// Write reordering: a sync persists only a seeded subset of the pending cache, so a crash loses
    /// the rest. The lost subset is deterministic (identical across runs) and non-trivial (some
    /// writes survive, some are lost), proving the sync did not atomically drain the cache.
    #[test]
    fn write_reordering_loses_a_seeded_subset_on_crash() {
        const N: u64 = 32;
        let run = || {
            let mut dev = MemBlockDevice::new(N);
            dev.arm_fault_plan(FaultPlan::new(0xABCD).with_write_reordering(50));
            for p in 0..N {
                dev.write_page(PageId(p), &page_of(0xEE)).unwrap();
            }
            dev.sync_all().unwrap(); // non-atomic: persists ~half, leaves the rest cached
            dev.crash(); // drops the un-persisted pre-sync writes
            (0..N).map(|p| read(&dev, p)[0] == 0xEE).collect::<Vec<_>>()
        };
        let first = run();
        let second = run();
        assert_eq!(first, second, "the lost subset must be identical per seed");
        let survived = first.iter().filter(|&&s| s).count();
        assert!(
            survived > 0 && survived < N as usize,
            "reordering must lose *some* but not *all* writes; survived {survived}/{N}"
        );
    }

    /// An empty (default) plan is inert: arming it changes nothing.
    #[test]
    fn empty_plan_is_inert() {
        let mut dev = MemBlockDevice::new(1);
        dev.write_page(PageId(0), &page_of(0x9A)).unwrap();
        dev.sync_all().unwrap();
        dev.arm_fault_plan(FaultPlan::new(42));
        assert_eq!(read(&dev, 0)[0], 0x9A);
        assert!(dev.extend(10).is_ok());
    }
}
