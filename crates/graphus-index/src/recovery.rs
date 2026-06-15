//! WAL ordering rule, intra-page patch encoding, and ARIES crash recovery for index pages
//! (`04-technical-design.md` §6.4, §4.3, §4.8).
//!
//! Index pages are ordinary logical pages, so this module mirrors the storage core exactly:
//!
//! - [`SharedWal`] is the single-threaded shared handle to the [`WalManager`] that both the
//!   B+-tree (for logging mutations) and the buffer pool's WAL rule (for the write-home ordering
//!   guarantee, `04 §4.3`) drive over the *same* manager. The same ownership discipline as
//!   `graphus-storage::wal_rule` applies: the logging borrow is always dropped before any pool
//!   write path runs, so the two borrows never overlap.
//! - [`encode_patch`] / [`apply_patch`] are the intra-page `(u16 offset, bytes)` redo/undo patch
//!   format (identical to `graphus-storage::paging`), so the WAL records an index page change as a
//!   physiological redo / physical undo patch.
//! - [`IndexTarget`] is the [`ApplyTarget`] that replays those patches onto the raw device during
//!   recovery, and [`recover_index_device`] drives `graphus_wal::recover`. After it returns, the
//!   index pages are at the last durable committed-or-nothing state and [`crate::BTree::open`]
//!   re-reads the root from the recovered meta page — there is **no separate index rebuild on
//!   crash** (`04 §6.4`).

use std::cell::RefCell;
use std::rc::Rc;

use graphus_bufpool::WalRule;
use graphus_bufpool::page;
use graphus_core::error::{GraphusError, Result};
use graphus_core::{Lsn, PageId};
use graphus_io::{BlockDevice, PAGE_SIZE, Page};
use graphus_wal::{ApplyTarget, LogSink, RecoveryReport, WalManager, recover};

/// A single-threaded shared handle to the [`WalManager`], cloned by both the B+-tree and the
/// buffer pool's WAL rule so they drive one log (mirrors `graphus-storage::wal_rule::SharedWal`).
pub struct SharedWal<S: LogSink> {
    inner: Rc<RefCell<WalManager<S>>>,
}

impl<S: LogSink> std::fmt::Debug for SharedWal<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SharedWal")
            .field("strong_count", &Rc::strong_count(&self.inner))
            .finish()
    }
}

impl<S: LogSink> Clone for SharedWal<S> {
    fn clone(&self) -> Self {
        Self {
            inner: Rc::clone(&self.inner),
        }
    }
}

impl<S: LogSink> SharedWal<S> {
    /// Wraps `wal` in a shared, single-threaded handle.
    #[must_use]
    pub fn new(wal: WalManager<S>) -> Self {
        Self {
            inner: Rc::new(RefCell::new(wal)),
        }
    }

    /// Borrows the manager for a closure. The borrow lives only for `f`; callers must not invoke
    /// buffer-pool write paths from within `f` (which would re-borrow through the WAL rule).
    pub fn with<R>(&self, f: impl FnOnce(&mut WalManager<S>) -> R) -> R {
        f(&mut self.inner.borrow_mut())
    }

    /// Consumes the handle and returns the inner manager.
    ///
    /// # Errors
    /// Returns the handle back (as `Err`) if other clones still exist.
    pub fn into_inner(self) -> std::result::Result<WalManager<S>, Self> {
        Rc::try_unwrap(self.inner)
            .map_or_else(|inner| Err(Self { inner }), |cell| Ok(cell.into_inner()))
    }
}

impl<S: LogSink> WalRule for SharedWal<S> {
    /// Hardens the log through `up_to` before the pool writes an index page home (`04 §4.3`).
    ///
    /// # Panics
    /// Panics (controlled abort) if the durability `fdatasync` fails (`04 §4.9`).
    fn ensure_durable(&mut self, up_to: Lsn) -> Result<()> {
        self.inner.borrow_mut().ensure_durable(up_to);
        Ok(())
    }
}

/// Encodes an intra-page patch: a 2-byte little-endian `offset` followed by `bytes` (identical to
/// `graphus-storage::paging::encode_patch`, reused so index and record WAL records share a format).
///
/// # Panics
/// Panics if `offset + bytes.len()` would run past [`PAGE_SIZE`], or if `offset` does not fit a
/// `u16` (the on-wire patch encodes the offset as a `u16`). Both are internal invariants — offsets
/// are always produced inside `CELL_LIMIT` — so a panic here signals a caller bug, never adversarial
/// input. The checked arithmetic and explicit narrowing harden against a future regression that
/// would otherwise truncate the offset silently (SEC-208, CWE-190).
#[must_use]
pub fn encode_patch(offset: usize, bytes: &[u8]) -> Vec<u8> {
    let end = offset
        .checked_add(bytes.len())
        .expect("INVARIANT: patch offset + length does not overflow usize");
    assert!(end <= PAGE_SIZE, "patch runs past the page");
    let off16 = u16::try_from(offset).expect("INVARIANT: patch offset fits a u16 (page-bounded)");
    let mut out = Vec::with_capacity(2 + bytes.len());
    out.extend_from_slice(&off16.to_le_bytes());
    out.extend_from_slice(bytes);
    out
}

/// Applies a patch produced by [`encode_patch`] to `page`.
///
/// # Errors
/// Returns a storage error if the patch is malformed or would write past the page.
pub fn apply_patch(page: &mut [u8], patch: &[u8]) -> Result<()> {
    if patch.len() < 2 {
        return Err(GraphusError::Storage("patch too short".to_owned()));
    }
    let offset = u16::from_le_bytes(patch[0..2].try_into().expect("2-byte slice")) as usize;
    let bytes = &patch[2..];
    let end = offset
        .checked_add(bytes.len())
        .ok_or_else(|| GraphusError::Storage("patch offset overflow".to_owned()))?;
    if end > page.len() {
        return Err(GraphusError::Storage("patch runs past the page".to_owned()));
    }
    page[offset..end].copy_from_slice(bytes);
    Ok(())
}

/// An [`ApplyTarget`] that applies WAL redo/undo intra-page patches directly to a [`BlockDevice`]
/// during index recovery (mirrors `graphus-storage::recovery::DeviceTarget`).
pub struct IndexTarget<'a, D: BlockDevice> {
    device: &'a mut D,
}

impl<'a, D: BlockDevice> IndexTarget<'a, D> {
    /// Wraps a device as an index recovery apply target.
    pub fn new(device: &'a mut D) -> Self {
        Self { device }
    }

    fn ensure(&mut self, page: PageId) -> Result<()> {
        if page.0 >= self.device.page_count() {
            let additional = page.0 - self.device.page_count() + 1;
            self.device.extend(additional)?;
        }
        Ok(())
    }

    /// Hardens every applied page durably.
    ///
    /// # Errors
    /// Returns a storage error if the device sync fails.
    pub fn sync(&mut self) -> Result<()> {
        self.device.sync_all()
    }
}

impl<D: BlockDevice> ApplyTarget for IndexTarget<'_, D> {
    fn page_lsn(&self, page: PageId) -> Lsn {
        if page.0 >= self.device.page_count() {
            return Lsn(0);
        }
        let mut buf: Page = [0u8; PAGE_SIZE];
        if self.device.read_page(page, &mut buf).is_err() {
            return Lsn(0);
        }
        page::page_lsn(&buf)
    }

    fn apply(&mut self, page: PageId, lsn: Lsn, image: &[u8]) -> Result<()> {
        self.ensure(page)?;
        let mut buf: Page = [0u8; PAGE_SIZE];
        self.device.read_page(page, &mut buf)?;
        apply_patch(&mut buf, image)?;
        page::set_page_lsn(&mut buf, lsn);
        page::set_page_id(&mut buf, page.0);
        page::write_checksum(&mut buf);
        self.device.write_page(page, &buf)
    }
}

/// Runs three-phase ARIES recovery of `wal` onto the index `device`, leaving its pages at the last
/// durable committed-or-nothing state. Hardens the device before returning.
///
/// # Errors
/// Propagates a WAL read, apply, or device sync failure.
///
/// # Panics
/// Panics if hardening the CLRs written during undo fails (`04 §4.9`).
pub fn recover_index_device<S: LogSink, D: BlockDevice>(
    wal: &mut WalManager<S>,
    device: &mut D,
) -> Result<RecoveryReport> {
    let mut target = IndexTarget::new(device);
    let report = recover(wal, &mut target)?;
    target.sync()?;
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use graphus_core::{PageId, TxnId};
    use graphus_io::MemBlockDevice;
    use graphus_wal::MemLogSink;

    #[test]
    fn patch_round_trips() {
        let mut page = [0u8; PAGE_SIZE];
        let patch = encode_patch(100, &[1, 2, 3, 4]);
        apply_patch(&mut page, &patch).unwrap();
        assert_eq!(&page[100..104], &[1, 2, 3, 4]);
    }

    #[test]
    fn patch_rejects_out_of_range_and_short_input() {
        let mut page = [0u8; PAGE_SIZE];
        assert!(apply_patch(&mut page, &[0]).is_err());
        let mut bad = ((PAGE_SIZE - 2) as u16).to_le_bytes().to_vec();
        bad.extend_from_slice(&[9, 9, 9, 9]);
        assert!(apply_patch(&mut page, &bad).is_err());
    }

    #[test]
    fn shared_wal_rule_hardens_through_page_lsn() {
        let wal = WalManager::create(MemLogSink::new()).unwrap();
        let mut shared = SharedWal::new(wal);
        let u = shared.with(|w| {
            w.begin(TxnId(1));
            w.log_update(TxnId(1), PageId(0), b"r".to_vec(), b"u".to_vec())
        });
        assert!(shared.with(|w| w.durable_len()) <= u.0);
        shared.ensure_durable(u).unwrap();
        assert!(shared.with(|w| w.durable_len()) > u.0);
    }

    #[test]
    fn index_target_applies_and_stamps_lsn() {
        let mut dev = MemBlockDevice::new(1);
        {
            let mut t = IndexTarget::new(&mut dev);
            t.apply(PageId(0), Lsn(7), &encode_patch(50, &[5, 6]))
                .unwrap();
            t.sync().unwrap();
        }
        let mut buf = [0u8; PAGE_SIZE];
        dev.read_page(PageId(0), &mut buf).unwrap();
        assert_eq!(&buf[50..52], &[5, 6]);
        assert_eq!(page::page_lsn(&buf), Lsn(7));
        assert!(page::verify_checksum(&buf));
    }

    #[test]
    fn recover_on_empty_log_is_a_noop() {
        let wal = WalManager::create(MemLogSink::new()).unwrap();
        let sink = wal.sink().clone();
        let mut wal2 = WalManager::open(sink).unwrap();
        let mut dev = MemBlockDevice::new(1);
        let report = recover_index_device(&mut wal2, &mut dev).unwrap();
        assert_eq!(report.redo_applied, 0);
        assert_eq!(report.losers, 0);
    }
}
