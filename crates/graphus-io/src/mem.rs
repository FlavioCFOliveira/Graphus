//! In-memory block device modelling the page-cache / durability boundary, with crash,
//! torn-write and I/O-error injection for Deterministic Simulation Testing (decision
//! `D-dst-investment`).

use std::collections::HashMap;

use graphus_core::PageId;
use graphus_core::error::{GraphusError, Result};

use crate::block::{BlockDevice, PAGE_SIZE, Page};

/// An in-memory [`BlockDevice`] whose writes land in a cache and only become durable on a
/// sync; [`MemBlockDevice::crash`] discards un-synced writes, modelling power loss.
///
/// One-shot faults can be armed to exercise recovery: an I/O error on the next write, or a
/// torn write that stores only a prefix of a page.
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
    pub fn arm_torn_write(&mut self, page: PageId, prefix: usize) {
        self.armed_torn = Some((page.0, prefix.min(PAGE_SIZE)));
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
}

impl BlockDevice for MemBlockDevice {
    fn read_page(&self, page: PageId, buf: &mut Page) -> Result<()> {
        if page.0 >= self.persisted.len() as u64 {
            return Err(GraphusError::Storage(format!(
                "read out of range: page {}",
                page.0
            )));
        }
        buf.copy_from_slice(self.current(page.0));
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
        let mut page_buf = *buf;
        if let Some((tp, prefix)) = self.armed_torn.take() {
            if tp == idx {
                let mut torn = *self.current(idx);
                torn[..prefix].copy_from_slice(&buf[..prefix]);
                page_buf = torn;
            } else {
                self.armed_torn = Some((tp, prefix)); // not this page; keep it armed
            }
        }
        self.cache.insert(idx, page_buf);
        Ok(())
    }

    fn sync_data(&mut self) -> Result<()> {
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

    #[test]
    fn out_of_range_access_errors() {
        let mut dev = MemBlockDevice::new(1);
        let mut buf = [0u8; PAGE_SIZE];
        assert!(dev.read_page(PageId(1), &mut buf).is_err());
        assert!(dev.write_page(PageId(1), &page_of(1)).is_err());
    }
}
