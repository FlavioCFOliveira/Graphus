//! Adaptive buffer-pool sizing for the offline bulk importer / dumper (`rmp` #718).
//!
//! # Why the pool must scale with the data
//!
//! The importer builds the store through a [`RecordStore`](graphus_storage::RecordStore), whose
//! in-RAM buffer pool holds a fixed number of [`graphus_io::PAGE_SIZE`] (8 KiB) page frames. The
//! **relationship phase** is the hot path and it is **random-access over the whole store**:
//! [`RecordStore::create_rel`](graphus_storage::RecordStore::create_rel) prepends the new edge into
//! the incident-relationship chain of **both** endpoint nodes (scattered across the node store) and
//! relinks the previous chain head (scattered across the relationship store). Once the store grows
//! past the pool, almost every edge insert evicts and re-reads a page, so the page-miss rate
//! approaches 100 % and the import cost goes **superlinear** — a hard-coded 256-page (2 MiB) pool
//! made the loader **quadratic** at scale (`rmp` #718: on the reference host, 4.0x the data cost
//! 16.8x the time, i.e. `O(N^2.0)`). The fix is to size the pool to the store the load will build,
//! so the random-access working set stays resident.
//!
//! # Why not simply a bigger constant, or the full RAM budget
//!
//! Every frame **eagerly allocates and zeroes** its 8 KiB page at pool construction
//! (`FrameMeta::empty` in `graphus-bufpool`), so an over-sized pool taxes **every** import — even a
//! tiny one — with `capacity × 8 KiB` of pointless allocation + zeroing (and resident memory). The
//! `rmp` #718 probe confirmed this: forcing a fixed 256 MiB pool cut a large import 2.4x **but made
//! the small import measurably slower**. Sizing must therefore be **proportional to the data**,
//! bounded, never a fixed large value.
//!
//! # The policy
//!
//! 1. **Estimate the store's page count from the loader's own input size.** The offline loader
//!    knows its whole input up front, and a fixed-record property-graph store measures ~6x its CSV
//!    input (`rmp` #718, examples/bulk-etl: default 6.15x, large 5.93x). We provision
//!    [`STORE_BYTES_PER_CSV_BYTE`] = 8x so the **whole** store fits with headroom even for schemas
//!    whose input is more compact than this generator's. The columnar `.gcol` input is denser than
//!    CSV, so [`STORE_BYTES_PER_GCOL_BYTE`] scales that up (best-effort; see [`InputFormatHint`]).
//! 2. **Clamp to a RAM ceiling** derived exactly as the server's hardware auto-tuner does (`rmp`
//!    #617): at most [`RAM_FRACTION_NUM`]/[`RAM_FRACTION_DEN`] (= 1/8) of the host's **available**
//!    (else total) RAM, itself capped at [`HARD_CEIL_PAGES`] (= 2 GiB). So a huge ETL on a small box
//!    degrades gracefully to the RAM it actually has instead of over-committing.
//! 3. **Floor at [`POOL_FLOOR_PAGES`]** (= the historical 256 pages / 2 MiB), so a tiny import keeps
//!    exactly the small, cheap pool it always had (no regression) and the pool is never below a
//!    workable minimum.
//!
//! This module is pure and deterministic: it takes a [`MemoryInfo`] by value (never probes), so the
//! whole policy is unit-testable with synthetic hardware — the binary probes once via
//! [`graphus_sysres::memory`] and passes the snapshot in.

use graphus_io::PAGE_SIZE;
use graphus_sysres::MemoryInfo;

/// [`graphus_io::PAGE_SIZE`] as a `u64`, for the byte↔page arithmetic below.
const PAGE_BYTES: u64 = PAGE_SIZE as u64;

/// Estimated durable **store bytes per byte of CSV input**. A fixed-record property-graph store
/// measures ~6x its CSV input (`rmp` #718: examples/bulk-etl default 6.15x, large 5.93x); we
/// provision 8x so the whole store fits with headroom for schemas whose CSV is more compact.
pub const STORE_BYTES_PER_CSV_BYTE: u64 = 8;

/// Estimated durable **store bytes per byte of `.gcol` (columnar) input**. The `.gcol` format is a
/// compressed transcoding of the CSV (dictionary / frame-of-reference / bit-packed), so a `.gcol`
/// byte expands to more store than a CSV byte. Calibrated as ~3x denser than CSV; best-effort, and
/// bounded by the RAM ceiling like every other estimate. Operators loading dense `.gcol` at extreme
/// scale can always pin the pool explicitly (see the binary's `--buffer-pool-pages`).
pub const STORE_BYTES_PER_GCOL_BYTE: u64 = 24;

/// The auto-sizing **floor**, in pages: the historical fixed pool (256 pages = 2 MiB at 8 KiB/page).
/// A tiny import is sized to exactly this, so it keeps the small, cheap pool it always had — no
/// regression — and the pool is never below a workable minimum.
pub const POOL_FLOOR_PAGES: usize = 256;

/// Numerator of the RAM fraction the ceiling uses — mirrors the server's `rmp` #617 auto-tuner
/// (`AUTO_BUFFER_POOL_RAM_NUM`/`_DEN` = 1/8) so the two sizing paths share one policy.
pub const RAM_FRACTION_NUM: u64 = 1;
/// Denominator of [`RAM_FRACTION_NUM`] — see it.
pub const RAM_FRACTION_DEN: u64 = 8;

/// Hard ceiling on the pool, in pages: 262 144 pages = **2 GiB** at 8 KiB/page. Mirrors the server's
/// `rmp` #617 `AUTO_BUFFER_POOL_CEIL_PAGES`, so an unbounded RAM figure can never size an unbounded
/// pool.
pub const HARD_CEIL_PAGES: usize = 262_144;

/// The input file format, so the estimate can account for CSV vs. the denser columnar `.gcol`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InputFormatHint {
    /// Row-oriented CSV — [`STORE_BYTES_PER_CSV_BYTE`].
    Csv,
    /// Compressed columnar `.gcol` — [`STORE_BYTES_PER_GCOL_BYTE`].
    Gcol,
}

impl InputFormatHint {
    /// The store-bytes-per-input-byte factor for this format.
    #[must_use]
    fn store_per_input_byte(self) -> u64 {
        match self {
            Self::Csv => STORE_BYTES_PER_CSV_BYTE,
            Self::Gcol => STORE_BYTES_PER_GCOL_BYTE,
        }
    }
}

/// The RAM-derived **ceiling** on the pool, in pages: 1/8 of the host's available (else total) RAM,
/// clamped to `[`[`POOL_FLOOR_PAGES`]`,`[`HARD_CEIL_PAGES`]`]`. When RAM is unknown (the probe
/// failed) it returns [`HARD_CEIL_PAGES`], trusting the self-limiting input estimate up to 2 GiB.
#[must_use]
pub fn ram_ceiling_pages(mem: MemoryInfo) -> usize {
    match mem.available_bytes.or(mem.total_bytes) {
        Some(ram) => {
            // budget = ram × NUM / DEN, then pages = budget / PAGE — all in u64 (no overflow), then
            // clamped. `/ DEN` before `× NUM` keeps the product small; NUM is 1 so it is exact here.
            let budget = ram / RAM_FRACTION_DEN * RAM_FRACTION_NUM;
            let pages = budget / PAGE_BYTES;
            pages.clamp(POOL_FLOOR_PAGES as u64, HARD_CEIL_PAGES as u64) as usize
        }
        None => HARD_CEIL_PAGES,
    }
}

/// Clamps a desired page count to `[`[`POOL_FLOOR_PAGES`]`,`[`ram_ceiling_pages`]`]`. The ceiling is
/// always `>=` the floor, so the clamp bounds are valid.
#[must_use]
fn clamp_pages(wanted_pages: u64, mem: MemoryInfo) -> usize {
    let ceiling = ram_ceiling_pages(mem) as u64;
    wanted_pages.clamp(POOL_FLOOR_PAGES as u64, ceiling) as usize
}

/// Auto-sizes the buffer pool for an **import**, from the loader's total input byte size (the sum of
/// the node + relationship file sizes) and the input format.
///
/// Returns a page count in `[`[`POOL_FLOOR_PAGES`]`,`[`ram_ceiling_pages`]`]`, sized to hold the
/// store the import will build. `input_bytes == 0` (no measurable input) falls to the floor.
#[must_use]
pub fn auto_pool_pages_for_input(
    input_bytes: u64,
    format: InputFormatHint,
    mem: MemoryInfo,
) -> usize {
    let est_store_bytes = input_bytes.saturating_mul(format.store_per_input_byte());
    let wanted = est_store_bytes.div_ceil(PAGE_BYTES);
    clamp_pages(wanted, mem)
}

/// Extra pages beyond the store's own page count when **opening** an existing store, covering the
/// meta / free-list / doublewrite working set touched during WAL recovery + the dump scan.
const STORE_OPEN_HEADROOM_PAGES: u64 = 256;

/// Auto-sizes the buffer pool for **opening** an existing store (the dumper), from the durable
/// `graph.store` byte size — which is known exactly, so no per-format estimate is needed. A small
/// headroom ([`STORE_OPEN_HEADROOM_PAGES`]) covers recovery/scan working pages.
#[must_use]
pub fn auto_pool_pages_for_store(store_bytes: u64, mem: MemoryInfo) -> usize {
    let wanted = store_bytes
        .div_ceil(PAGE_BYTES)
        .saturating_add(STORE_OPEN_HEADROOM_PAGES);
    clamp_pages(wanted, mem)
}

#[cfg(test)]
mod tests {
    use super::*;

    const GIB: u64 = 1 << 30;
    const MIB: u64 = 1 << 20;

    fn mem(total: Option<u64>, avail: Option<u64>) -> MemoryInfo {
        MemoryInfo {
            total_bytes: total,
            available_bytes: avail,
        }
    }

    #[test]
    fn page_bytes_is_8_kib() {
        assert_eq!(
            PAGE_BYTES, 8192,
            "the whole calibration assumes 8 KiB pages"
        );
    }

    #[test]
    fn tiny_import_stays_at_the_floor_no_regression() {
        // A ~134 KiB CSV (the `fast` profile) → ~1 MiB store estimate → well under the floor, so the
        // pool is the historical 256 pages: a tiny import keeps its small, cheap pool.
        let pages = auto_pool_pages_for_input(
            134 * 1024,
            InputFormatHint::Csv,
            mem(Some(16 * GIB), Some(8 * GIB)),
        );
        assert_eq!(pages, POOL_FLOOR_PAGES);
    }

    #[test]
    fn zero_input_falls_to_the_floor() {
        assert_eq!(
            auto_pool_pages_for_input(0, InputFormatHint::Csv, mem(Some(16 * GIB), Some(8 * GIB))),
            POOL_FLOOR_PAGES
        );
    }

    #[test]
    fn default_profile_holds_the_whole_store() {
        // examples/bulk-etl `default`: ~5.0 MB total CSV → 8x = ~40 MB store estimate → ~4884 pages.
        // The measured store was 3760 pages, so the estimate comfortably HOLDS it (no thrashing) on
        // a machine with plenty of RAM.
        let input = 5_009_799u64;
        let pages = auto_pool_pages_for_input(
            input,
            InputFormatHint::Csv,
            mem(Some(64 * GIB), Some(32 * GIB)),
        );
        let expected = (input * STORE_BYTES_PER_CSV_BYTE).div_ceil(PAGE_BYTES) as usize;
        assert_eq!(pages, expected);
        assert!(
            pages >= 3760,
            "must hold the measured 3760-page default store, got {pages}"
        );
    }

    #[test]
    fn large_profile_holds_the_whole_store() {
        // examples/bulk-etl `large`: ~20.8 MB total CSV → 8x → ~20291 pages. Measured store = 15033
        // pages, so the pool holds it entirely — the random-access relationship phase never thrashes.
        let input = 20_777_546u64;
        let pages = auto_pool_pages_for_input(
            input,
            InputFormatHint::Csv,
            mem(Some(64 * GIB), Some(32 * GIB)),
        );
        assert!(
            pages >= 15033,
            "must hold the measured 15033-page large store, got {pages}"
        );
    }

    #[test]
    fn ram_ceiling_bounds_a_huge_import_on_a_small_box() {
        // A 1 GB CSV → 8x = 8 GB store estimate, but a 2 GiB-RAM box allows only 1/8 × 2 GiB = 256
        // MiB = 32768 pages. The pool is capped at the RAM ceiling, not the (much larger) estimate.
        let one_gb_csv = 1_000_000_000u64;
        let pages = auto_pool_pages_for_input(
            one_gb_csv,
            InputFormatHint::Csv,
            mem(Some(2 * GIB), Some(2 * GIB)),
        );
        let ceiling = ram_ceiling_pages(mem(Some(2 * GIB), Some(2 * GIB)));
        assert_eq!(pages, ceiling);
        assert_eq!(ceiling, (2 * GIB / 8 / PAGE_BYTES) as usize);
    }

    #[test]
    fn hard_ceiling_caps_even_a_huge_ram_box() {
        // 1 TiB available RAM → 1/8 = 128 GiB budget, but the pool is capped at the 2 GiB hard ceiling.
        let ceiling = ram_ceiling_pages(mem(Some(1024 * GIB), Some(1024 * GIB)));
        assert_eq!(ceiling, HARD_CEIL_PAGES);
    }

    #[test]
    fn available_ram_is_preferred_over_total() {
        // 32 GiB total but only 4 GiB available → the ceiling uses the 4 GiB available figure.
        let ceiling = ram_ceiling_pages(mem(Some(32 * GIB), Some(4 * GIB)));
        assert_eq!(ceiling, (4 * GIB / 8 / PAGE_BYTES) as usize);
    }

    #[test]
    fn unknown_ram_trusts_the_input_estimate_up_to_the_hard_ceiling() {
        // Probe failed (both None): the ceiling is the hard 2 GiB cap, and a modest input is sized
        // from the estimate (not forced to the ceiling).
        assert_eq!(ram_ceiling_pages(mem(None, None)), HARD_CEIL_PAGES);
        let input = 20_777_546u64; // the large profile
        let pages = auto_pool_pages_for_input(input, InputFormatHint::Csv, mem(None, None));
        let expected = (input * STORE_BYTES_PER_CSV_BYTE).div_ceil(PAGE_BYTES) as usize;
        assert_eq!(pages, expected);
    }

    #[test]
    fn gcol_input_provisions_more_than_csv_for_the_same_bytes() {
        let bytes = 5 * MIB;
        let rich_ram = mem(Some(64 * GIB), Some(64 * GIB));
        let csv = auto_pool_pages_for_input(bytes, InputFormatHint::Csv, rich_ram);
        let gcol = auto_pool_pages_for_input(bytes, InputFormatHint::Gcol, rich_ram);
        assert!(
            gcol > csv,
            "denser gcol must provision more pages: csv={csv} gcol={gcol}"
        );
    }

    #[test]
    fn open_sizes_from_the_exact_store_bytes_plus_headroom() {
        // A 117 MiB store (the large profile) → its page count + headroom, well under a big RAM box.
        let store_bytes = 123_150_336u64; // measured large store
        let pages = auto_pool_pages_for_store(store_bytes, mem(Some(64 * GIB), Some(32 * GIB)));
        let expected =
            store_bytes.div_ceil(PAGE_BYTES) as usize + STORE_OPEN_HEADROOM_PAGES as usize;
        assert_eq!(pages, expected);
    }

    #[test]
    fn open_of_a_tiny_store_stays_at_the_floor() {
        // A 1-page store + 256 headroom = 257 → clamped to the floor is a no-op (257 > 256); a
        // truly empty/near-empty store still lands at or just above the floor.
        let pages = auto_pool_pages_for_store(PAGE_BYTES, mem(Some(16 * GIB), Some(8 * GIB)));
        assert_eq!(pages, 1 + STORE_OPEN_HEADROOM_PAGES as usize);
        assert!(pages >= POOL_FLOOR_PAGES);
    }

    #[test]
    fn ceiling_is_never_below_the_floor_even_on_a_micro_box() {
        // 64 MiB RAM → 1/8 = 8 MiB = 1024 pages, still >= floor; the clamp bounds are always valid.
        let ceiling = ram_ceiling_pages(mem(Some(64 * MIB), Some(64 * MIB)));
        assert!(ceiling >= POOL_FLOOR_PAGES);
        // And a tiny RAM box that computes below the floor still yields a valid (>= floor) ceiling.
        let ceiling = ram_ceiling_pages(mem(Some(8 * MIB), Some(8 * MIB)));
        assert_eq!(ceiling, POOL_FLOOR_PAGES);
    }
}
