//! A single-threaded buffer pool over a [`BlockDevice`], with CLOCK eviction, pinning,
//! checksummed dirty-page write-back, and the write-ahead-log ordering rule.
//!
//! A concurrent, latched version (validated with loom) is a separate Phase 1 task; this is
//! the correct single-threaded core the storage and WAL layers build on.

use std::collections::HashMap;

use graphus_core::error::{GraphusError, Result};
use graphus_core::{Lsn, PageId};
use graphus_io::{BlockDevice, PAGE_SIZE, Page};

use crate::page;

/// The write-ahead-log ordering rule: before a dirty page stamped with `up_to` is written to
/// the device, the log up to `up_to` must be durable. The real WAL implements this; [`NoWal`]
/// is the standalone default that treats everything as already durable.
pub trait WalRule {
    /// Ensures the log is durable up to (and including) `up_to`.
    fn ensure_durable(&mut self, up_to: Lsn) -> Result<()>;
}

/// A [`WalRule`] for standalone use (no WAL): every LSN is considered already durable.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoWal;

impl WalRule for NoWal {
    fn ensure_durable(&mut self, _up_to: Lsn) -> Result<()> {
        Ok(())
    }
}

/// A handle to a pinned frame, valid until it is unpinned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrameId(usize);

struct Frame {
    page_id: Option<PageId>,
    data: Box<Page>,
    pin_count: u32,
    dirty: bool,
    ref_bit: bool,
}

impl Frame {
    fn empty() -> Self {
        Self {
            page_id: None,
            data: Box::new([0u8; PAGE_SIZE]),
            pin_count: 0,
            dirty: false,
            ref_bit: false,
        }
    }
}

/// A fixed-capacity buffer pool.
pub struct BufferPool<D: BlockDevice, W: WalRule = NoWal> {
    device: D,
    wal: W,
    frames: Vec<Frame>,
    table: HashMap<PageId, usize>,
    clock: usize,
}

impl<D: BlockDevice> BufferPool<D, NoWal> {
    /// Creates a pool of `capacity` frames over `device`, with no WAL coupling.
    pub fn new(device: D, capacity: usize) -> Self {
        Self::with_wal(device, NoWal, capacity)
    }
}

impl<D: BlockDevice, W: WalRule> BufferPool<D, W> {
    /// Creates a pool of `capacity` frames with an explicit [`WalRule`].
    ///
    /// # Panics
    /// Panics if `capacity` is zero.
    pub fn with_wal(device: D, wal: W, capacity: usize) -> Self {
        assert!(capacity > 0, "buffer pool capacity must be > 0");
        let frames = (0..capacity).map(|_| Frame::empty()).collect();
        Self {
            device,
            wal,
            frames,
            table: HashMap::new(),
            clock: 0,
        }
    }

    /// Borrows the cached page held by a pinned frame.
    #[must_use]
    pub fn page(&self, f: FrameId) -> &Page {
        &self.frames[f.0].data
    }

    /// Mutably borrows the page held by a pinned frame and marks it dirty.
    pub fn page_mut(&mut self, f: FrameId) -> &mut Page {
        self.frames[f.0].dirty = true;
        &mut self.frames[f.0].data
    }

    /// Decrements the pin count of a frame.
    pub fn unpin(&mut self, f: FrameId) {
        debug_assert!(self.frames[f.0].pin_count > 0);
        self.frames[f.0].pin_count = self.frames[f.0].pin_count.saturating_sub(1);
    }

    /// Fetches `page_id`, loading it from the device on a miss (verifying its checksum), and
    /// pins it.
    pub fn fetch(&mut self, page_id: PageId) -> Result<FrameId> {
        if let Some(&idx) = self.table.get(&page_id) {
            self.frames[idx].pin_count += 1;
            self.frames[idx].ref_bit = true;
            return Ok(FrameId(idx));
        }
        let idx = self.evict_victim()?;
        let mut buf: Box<Page> = Box::new([0u8; PAGE_SIZE]);
        self.device.read_page(page_id, &mut buf)?;
        if !page::verify_checksum(&buf) {
            return Err(GraphusError::Storage(format!(
                "page {} failed checksum verification",
                page_id.0
            )));
        }
        self.install(idx, page_id, buf, false);
        Ok(FrameId(idx))
    }

    /// Allocates a fresh zero page at the end of the device, pins it, and returns its handle
    /// and id.
    pub fn new_page(&mut self) -> Result<(FrameId, PageId)> {
        let idx = self.evict_victim()?;
        let page_id = PageId(self.device.page_count());
        self.device.extend(1)?;
        let mut buf: Box<Page> = Box::new([0u8; PAGE_SIZE]);
        page::set_page_id(&mut buf, page_id.0);
        page::write_checksum(&mut buf);
        self.install(idx, page_id, buf, true);
        Ok((FrameId(idx), page_id))
    }

    /// Writes a frame back to the device if it is dirty.
    pub fn flush(&mut self, f: FrameId) -> Result<()> {
        self.write_back(f.0)
    }

    /// Writes every dirty frame back and syncs the device.
    pub fn flush_all(&mut self) -> Result<()> {
        let dirty: Vec<usize> = self
            .frames
            .iter()
            .enumerate()
            .filter(|(_, fr)| fr.dirty)
            .map(|(i, _)| i)
            .collect();
        for idx in dirty {
            self.write_back(idx)?;
        }
        self.device.sync_all()
    }

    fn install(&mut self, idx: usize, page_id: PageId, data: Box<Page>, dirty: bool) {
        let fr = &mut self.frames[idx];
        fr.data = data;
        fr.page_id = Some(page_id);
        fr.dirty = dirty;
        fr.pin_count = 1;
        fr.ref_bit = true;
        self.table.insert(page_id, idx);
    }

    fn write_back(&mut self, idx: usize) -> Result<()> {
        if !self.frames[idx].dirty {
            return Ok(());
        }
        let page_id = self.frames[idx]
            .page_id
            .expect("a dirty frame must hold a page");
        page::write_checksum(&mut self.frames[idx].data);
        let lsn = page::page_lsn(&self.frames[idx].data);
        self.wal.ensure_durable(lsn)?; // WAL rule: log before data
        self.device.write_page(page_id, &self.frames[idx].data)?;
        self.frames[idx].dirty = false;
        Ok(())
    }

    fn evict_victim(&mut self) -> Result<usize> {
        if let Some(idx) = self.frames.iter().position(|fr| fr.page_id.is_none()) {
            return Ok(idx);
        }
        let n = self.frames.len();
        for _ in 0..(2 * n) {
            let idx = self.clock;
            self.clock = (self.clock + 1) % n;
            if self.frames[idx].pin_count > 0 {
                continue;
            }
            if self.frames[idx].ref_bit {
                self.frames[idx].ref_bit = false;
                continue;
            }
            self.write_back(idx)?;
            if let Some(pid) = self.frames[idx].page_id.take() {
                self.table.remove(&pid);
            }
            return Ok(idx);
        }
        Err(GraphusError::Storage(
            "buffer pool is full of pinned pages".to_owned(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use graphus_io::MemBlockDevice;

    fn pool(cap: usize) -> BufferPool<MemBlockDevice> {
        BufferPool::new(MemBlockDevice::new(0), cap)
    }

    #[test]
    fn new_page_is_cached_and_readable() {
        let mut p = pool(4);
        let (f, id) = p.new_page().unwrap();
        p.page_mut(f)[100] = 0xAA;
        p.unpin(f);
        let g = p.fetch(id).unwrap();
        assert_eq!(p.page(g)[100], 0xAA);
    }

    #[test]
    fn eviction_writes_dirty_then_reload_verifies_checksum() {
        let mut p = pool(1);
        let (fa, a) = p.new_page().unwrap();
        p.page_mut(fa)[100] = 0xAA;
        p.unpin(fa);
        let (fb, _b) = p.new_page().unwrap(); // evicts a, writing it back
        p.unpin(fb);
        let g = p.fetch(a).unwrap(); // miss -> reload, checksum verified
        assert_eq!(p.page(g)[100], 0xAA);
    }

    #[test]
    fn a_fully_pinned_pool_cannot_evict() {
        let mut p = pool(1);
        let (_fa, _a) = p.new_page().unwrap(); // pinned
        assert!(p.new_page().is_err());
    }

    #[test]
    fn wal_rule_is_enforced_before_write_back() {
        struct FailWal;
        impl WalRule for FailWal {
            fn ensure_durable(&mut self, _up_to: Lsn) -> Result<()> {
                Err(GraphusError::Storage("wal not durable".to_owned()))
            }
        }
        let mut p = BufferPool::with_wal(MemBlockDevice::new(0), FailWal, 2);
        let (f, _id) = p.new_page().unwrap();
        p.page_mut(f)[0] = 1;
        assert!(p.flush(f).is_err()); // the WAL rule refuses, so the write-back fails
    }
}
