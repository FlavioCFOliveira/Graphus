//! Production block device backed by a regular file using Unix positioned I/O.

use std::fs::{File, OpenOptions};
use std::os::unix::fs::FileExt;
use std::path::Path;

use graphus_core::PageId;
use graphus_core::error::{GraphusError, Result};

use crate::block::{BlockDevice, PAGE_SIZE, Page};

fn io_err(context: &str, e: &std::io::Error) -> GraphusError {
    GraphusError::Storage(format!("{context}: {e}"))
}

/// A [`BlockDevice`] backed by a regular file, using positioned reads and writes so that
/// concurrent readers need no shared cursor.
#[derive(Debug)]
pub struct FileBlockDevice {
    file: File,
    page_count: u64,
}

impl FileBlockDevice {
    /// Opens the block-device file at `path`, creating it if it does not exist. The file is
    /// never truncated. Errors if the existing length is not a whole number of pages.
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(path)
            .map_err(|e| io_err("open", &e))?;
        let len = file.metadata().map_err(|e| io_err("metadata", &e))?.len();
        if len % PAGE_SIZE as u64 != 0 {
            return Err(GraphusError::Storage(format!(
                "file length {len} is not a multiple of the page size {PAGE_SIZE}"
            )));
        }
        Ok(Self {
            file,
            page_count: len / PAGE_SIZE as u64,
        })
    }

    fn offset(page: PageId) -> u64 {
        page.0 * PAGE_SIZE as u64
    }
}

impl BlockDevice for FileBlockDevice {
    fn read_page(&self, page: PageId, buf: &mut Page) -> Result<()> {
        if page.0 >= self.page_count {
            return Err(GraphusError::Storage(format!(
                "read out of range: page {} of {}",
                page.0, self.page_count
            )));
        }
        self.file
            .read_exact_at(buf, Self::offset(page))
            .map_err(|e| io_err("read", &e))
    }

    fn write_page(&mut self, page: PageId, buf: &Page) -> Result<()> {
        if page.0 >= self.page_count {
            return Err(GraphusError::Storage(format!(
                "write out of range: page {} of {}",
                page.0, self.page_count
            )));
        }
        self.file
            .write_all_at(buf, Self::offset(page))
            .map_err(|e| io_err("write", &e))
    }

    fn sync_data(&mut self) -> Result<()> {
        self.file.sync_data().map_err(|e| io_err("sync_data", &e))
    }

    fn sync_all(&mut self) -> Result<()> {
        self.file.sync_all().map_err(|e| io_err("sync_all", &e))
    }

    fn page_count(&self) -> u64 {
        self.page_count
    }

    fn extend(&mut self, additional: u64) -> Result<()> {
        let new_count = self
            .page_count
            .checked_add(additional)
            .ok_or_else(|| GraphusError::Storage("page count overflow".to_owned()))?;
        self.file
            .set_len(new_count * PAGE_SIZE as u64)
            .map_err(|e| io_err("set_len", &e))?;
        self.page_count = new_count;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static COUNTER: AtomicU64 = AtomicU64::new(0);

    fn temp_path() -> std::path::PathBuf {
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!("graphus-io-{}-{n}.blk", std::process::id()))
    }

    #[test]
    fn write_read_roundtrip_and_durability() {
        let path = temp_path();
        {
            let mut dev = FileBlockDevice::open(&path).unwrap();
            dev.extend(2).unwrap();
            assert_eq!(dev.page_count(), 2);
            let mut page = [0u8; PAGE_SIZE];
            page[..5].copy_from_slice(b"hello");
            dev.write_page(PageId(1), &page).unwrap();
            dev.sync_all().unwrap();
        }
        // Reopen: the data must have survived.
        let dev = FileBlockDevice::open(&path).unwrap();
        assert_eq!(dev.page_count(), 2);
        let mut buf = [0u8; PAGE_SIZE];
        dev.read_page(PageId(1), &mut buf).unwrap();
        assert_eq!(&buf[..5], &b"hello"[..]);
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn out_of_range_read_errors() {
        let path = temp_path();
        let dev = FileBlockDevice::open(&path).unwrap();
        let mut buf = [0u8; PAGE_SIZE];
        assert!(dev.read_page(PageId(0), &mut buf).is_err());
        std::fs::remove_file(&path).ok();
    }
}
