//! The block-device abstraction: page-granular, synchronous I/O for the storage core.

use graphus_core::PageId;
use graphus_core::constants::LOGICAL_PAGE_SIZE;
use graphus_core::error::Result;

/// The size in bytes of one storage page (equal to
/// [`graphus_core::constants::LOGICAL_PAGE_SIZE`]).
pub const PAGE_SIZE: usize = LOGICAL_PAGE_SIZE;

/// Exactly one page worth of bytes.
pub type Page = [u8; PAGE_SIZE];

/// The classified outcome of a [`BlockDevice::read_page_classified`] read, distinguishing a page
/// that read back intact from one that is **genuinely torn/corrupt** (`rmp` #408).
///
/// On the plaintext device a torn page reads back as bytes whose CRC32C fails — the bytes *are*
/// returned, the caller detects the tear via the checksum. On the **encrypted** device a torn slot
/// fails its AES-GCM authentication tag, so `read_page` returns an *error* — but that same error path
/// is also taken by a **transient** I/O failure (a momentary device read error). Collapsing the two
/// (the historical behaviour of doublewrite recovery, which mapped *any* home-read error to "torn")
/// let a fine-but-momentarily-unreadable home page be clobbered by a stale doublewrite copy. This
/// enum is the structured signal that lets the caller repair **only** a genuine tear and propagate a
/// transient error instead of silently reverting a good page.
#[derive(Debug)]
pub enum PageReadOutcome {
    /// The page read back and (on the encrypted device) authenticated successfully. Its bytes are in
    /// the caller's buffer. The caller still verifies the CRC32C to detect a plaintext tear.
    Read,
    /// The page is **genuinely torn/corrupt**: on the encrypted device its AES-GCM tag failed to
    /// authenticate (a torn/partial write, a relocated page, tamper, or a wrong key). This is the
    /// only condition under which doublewrite recovery may restore the page from its copy.
    Torn,
}

/// A synchronous, page-addressable block device.
///
/// This is the single I/O surface the buffer pool and write-ahead log build on. Two
/// implementations exist: [`crate::FileBlockDevice`] (production, over a real file) and
/// [`crate::MemBlockDevice`] (in-memory, modelling the durability boundary with crash,
/// torn-write and I/O-error injection for Deterministic Simulation Testing).
///
/// Writes need not be durable until [`BlockDevice::sync_data`] or [`BlockDevice::sync_all`]
/// returns.
pub trait BlockDevice {
    /// Reads page `page` into `buf`. Errors if `page` is out of range.
    fn read_page(&self, page: PageId, buf: &mut Page) -> Result<()>;

    /// Reads page `page` into `buf`, **classifying** a read failure as a *genuine tear/corruption*
    /// ([`PageReadOutcome::Torn`]) versus a *transient I/O error* (propagated as `Err`) — the signal
    /// doublewrite recovery needs to repair only a genuinely torn page and never clobber a
    /// fine-but-momentarily-unreadable one with a stale doublewrite copy (`rmp` #408).
    ///
    /// The **default** implementation (plaintext devices) maps `read_page` onto
    /// [`PageReadOutcome::Read`]: a plaintext device returns torn bytes *successfully* (the caller
    /// detects the tear via the CRC32C), and a `read_page` `Err` on a plaintext device is a genuine
    /// I/O failure, so it propagates — exactly the desired classification with no per-device code.
    ///
    /// The **encrypted** device ([`graphus_crypto`]) overrides this: an AES-GCM tag failure means the
    /// slot is genuinely torn/corrupt → [`PageReadOutcome::Torn`]; a transient backing-store read
    /// error → `Err` (propagated, never treated as torn).
    ///
    /// # Errors
    /// Returns `Err` for an out-of-range page or a **transient** I/O failure. A genuine tear is
    /// reported as `Ok(PageReadOutcome::Torn)`, not an error.
    fn read_page_classified(&self, page: PageId, buf: &mut Page) -> Result<PageReadOutcome> {
        self.read_page(page, buf)?;
        Ok(PageReadOutcome::Read)
    }

    /// Writes `buf` to page `page`. The write may be buffered until a subsequent sync.
    fn write_page(&mut self, page: PageId, buf: &Page) -> Result<()>;

    /// Writes a run of `pages` to consecutive page ids starting at `base`: `pages[i]` lands on
    /// page `base + i`. The pages are assumed to be at *contiguous* (adjacent) offsets; the caller
    /// (the buffer pool's checkpoint/flush) groups its dirty frames into contiguous runs and emits
    /// each run through this method so a device that supports it can collapse the run into a single
    /// vectored/sequential write — far fewer syscalls than one `write_page` per page (`rmp` #374).
    ///
    /// The default implementation simply loops [`write_page`](Self::write_page), so every device
    /// keeps working unchanged (and, crucially, the in-memory DST device keeps its per-page
    /// fault-injection semantics — torn writes, misdirected writes, armed I/O errors all still fire
    /// per page). A device overrides this only to coalesce the syscalls; the bytes written, the
    /// offsets, and the per-page durability contract are identical to the per-page path.
    ///
    /// # Errors
    /// Propagates the first device-write failure. On error, an unspecified prefix of the run may
    /// have reached the device's buffers (exactly as with a sequence of `write_page` calls); the
    /// caller's WAL + recovery make a partial write-back recoverable.
    fn write_pages(&mut self, base: PageId, pages: &[&Page]) -> Result<()> {
        for (i, page) in pages.iter().enumerate() {
            let id = PageId(base.0.checked_add(i as u64).ok_or_else(|| {
                graphus_core::error::GraphusError::Storage(
                    "page id overflow in write_pages run".to_owned(),
                )
            })?);
            self.write_page(id, page)?;
        }
        Ok(())
    }

    /// Flushes file data (and the minimum metadata needed to read it back) durably.
    fn sync_data(&mut self) -> Result<()>;

    /// Flushes file data and all metadata durably.
    fn sync_all(&mut self) -> Result<()>;

    /// The number of pages the device currently holds.
    fn page_count(&self) -> u64;

    /// Grows the device by `additional` zero-filled pages.
    fn extend(&mut self, additional: u64) -> Result<()>;
}
