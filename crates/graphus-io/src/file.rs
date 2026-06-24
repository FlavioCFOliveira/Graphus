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

/// Upper bound on the number of pages a single file-backed device may address.
///
/// This is a defence-in-depth cap, independent of (and far below) the `u64 * PAGE_SIZE`
/// overflow boundary: any page count / page id at or above this limit is rejected outright,
/// so a tampered WAL/store header cannot drive the device into an absurd `set_len` or an
/// out-of-position seek even before the multiplication is range-checked. At `PAGE_SIZE`
/// bytes per page this still allows a multi-exabyte logical device — orders of magnitude
/// beyond any real filesystem — while leaving headroom so `page_count * PAGE_SIZE` never
/// approaches `u64::MAX`.
const MAX_PAGE_COUNT: u64 = u64::MAX / (PAGE_SIZE as u64) / 2;

/// A [`BlockDevice`] backed by a regular file, using positioned reads and writes so that
/// concurrent readers need no shared cursor.
#[derive(Debug)]
pub struct FileBlockDevice {
    file: File,
    page_count: u64,
    /// Reused staging buffer for the coalesced [`write_pages`](BlockDevice::write_pages) run (one
    /// concatenated `pwrite` per contiguous run). Held on the device so a checkpoint that flushes
    /// many runs does not re-allocate per run. Empty when idle.
    coalesce_buf: Vec<u8>,
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
        let page_count = len / PAGE_SIZE as u64;
        if page_count > MAX_PAGE_COUNT {
            return Err(GraphusError::Storage(format!(
                "file length {len} addresses {page_count} pages, exceeding the maximum of \
                 {MAX_PAGE_COUNT}"
            )));
        }
        Ok(Self {
            file,
            page_count,
            coalesce_buf: Vec::new(),
        })
    }

    /// The byte offset of `page` within the file, computed with a checked multiplication so an
    /// attacker-controlled `page_id` (e.g. decoded from a tampered, unkeyed-CRC WAL frame) can
    /// never wrap `u64` into an out-of-position, in-bounds-looking offset (CWE-190 → CWE-787/125).
    fn offset(page: PageId) -> Result<u64> {
        if page.0 >= MAX_PAGE_COUNT {
            return Err(GraphusError::Storage(format!(
                "page id {} exceeds the maximum addressable page {MAX_PAGE_COUNT}",
                page.0
            )));
        }
        page.0.checked_mul(PAGE_SIZE as u64).ok_or_else(|| {
            GraphusError::Storage(format!(
                "page id {} times page size {PAGE_SIZE} overflows the byte offset",
                page.0
            ))
        })
    }

    /// Portable, `unsafe`-free coalesced write: concatenate the contiguous run into a reused staging
    /// buffer (`self.coalesce_buf`, no per-call allocation) and emit it with one `write_all_at`
    /// (a single `pwrite(2)`). The on-disk image is byte-identical to writing each page in turn at
    /// its own contiguous offset. The caller has already validated the whole span fits in range.
    ///
    /// This is the fallback path on every build except Linux-with-`pwritev`; it copies the run
    /// bytes once into the staging buffer (the price of staying off `unsafe`).
    #[cfg_attr(all(target_os = "linux", feature = "pwritev"), allow(dead_code))]
    fn write_run_concat(&mut self, offset: u64, pages: &[&Page]) -> Result<()> {
        let need = pages.len() * PAGE_SIZE;
        self.coalesce_buf.clear();
        self.coalesce_buf.reserve(need);
        for page in pages {
            self.coalesce_buf.extend_from_slice(*page);
        }
        self.file
            .write_all_at(&self.coalesce_buf, offset)
            .map_err(|e| io_err("write", &e))
    }

    /// Copy-free coalesced write (Linux + `pwritev` feature, `rmp` #374): emit the contiguous run
    /// with one scatter/gather `pwritev(2)` whose `iovec` array points directly at the caller's page
    /// buffers — no staging buffer, no copy. Drives `pwritev` to completion across short writes
    /// (partial writes, and the kernel's per-call `IOV_MAX` iovec cap) and verifies the total byte
    /// count equals the run length, so a truncated run can never be silently accepted. The on-disk
    /// image is byte-identical to writing each page in turn at its own contiguous offset.
    ///
    /// The caller (`write_pages`) has already validated that `pages.len() >= 2`, that the whole span
    /// `base ..= base + len - 1` is in range, and computed `offset = base * PAGE_SIZE`.
    #[cfg(all(target_os = "linux", feature = "pwritev"))]
    #[allow(unsafe_code)]
    fn write_run_pwritev(&mut self, offset: u64, pages: &[&Page]) -> Result<()> {
        use std::os::unix::io::AsRawFd;

        let fd = self.file.as_raw_fd();
        // One `iovec` per page, each borrowing that page's bytes for the duration of the syscall.
        // `iov_base` is a `*mut c_void` by the C ABI, but `pwritev` (unlike `preadv`) only *reads*
        // through these pointers; the buffers are never mutated by the call.
        let iovs: Vec<libc::iovec> = pages
            .iter()
            .map(|p| libc::iovec {
                iov_base: p.as_ptr() as *mut libc::c_void,
                iov_len: PAGE_SIZE,
            })
            .collect();

        let total = (pages.len() * PAGE_SIZE) as u64;
        let mut written: u64 = 0;
        // `iovcnt` is capped per call at `IOV_MAX` (commonly 1024); a longer run simply takes more
        // `pwritev` calls, each advancing the file offset — still far fewer syscalls than one per
        // page, and the byte image is identical.
        let iov_max = Self::iov_max();
        while written < total {
            // The first not-yet-written page and the byte offset within it.
            let first_page = (written as usize) / PAGE_SIZE;
            let page_off = (written as usize) % PAGE_SIZE;
            let remaining_pages = pages.len() - first_page;
            let this_cnt = remaining_pages.min(iov_max);

            // Build the iovec window for this call. The first iovec is trimmed to the unwritten tail
            // of `first_page` (only ever non-zero after a partial write, which is rare); the rest are
            // whole pages. We rebuild the small window each iteration so the pointer/length math is
            // trivially correct and cannot drift.
            let mut window: Vec<libc::iovec> = Vec::with_capacity(this_cnt);
            window.push(libc::iovec {
                iov_base: unsafe { iovs[first_page].iov_base.add(page_off) },
                iov_len: PAGE_SIZE - page_off,
            });
            window.extend_from_slice(&iovs[first_page + 1..first_page + this_cnt]);

            // SAFETY:
            // * `fd` is a valid, open file descriptor: it is borrowed from `self.file` (a live
            //   `File` that outlives this call); the file is opened read+write in `open`.
            // * `window.as_ptr()` points to `window.len()` (= `this_cnt`, `1..=IOV_MAX`) properly
            //   initialised, contiguous `libc::iovec` values; `iovcnt` passed matches that length.
            // * Each `iov_base`/`iov_len` describes a sub-slice of a page buffer that is borrowed
            //   from `pages: &[&Page]` for the whole duration of this synchronous call. Those page
            //   frames are pinned + write-latched by the buffer pool's `flush_all` while it calls
            //   `write_pages`, so no other thread mutates or frees them here, and `&self`-borrowing
            //   `Vec`s keep them alive. `pwritev` only *reads* through these pointers (it writes to
            //   the file), so there is no aliasing/mutation of the borrowed buffers.
            // * `iov_len` for each entry is `<= PAGE_SIZE`, and the trimmed first entry stays within
            //   its page, so no read runs past a buffer end. The summed length per call is
            //   `<= total`, and the file region `offset + written ..` was bounds-checked by the
            //   caller to fit the device, so the kernel writes only in-range bytes.
            // * The `*const` offset `iovs[first_page].iov_base.add(page_off)` stays within the same
            //   page allocation (`page_off < PAGE_SIZE`), so the pointer arithmetic is in-bounds.
            // The return value is checked below; a negative result is an error (no bytes consumed).
            let rc = unsafe {
                libc::pwritev(
                    fd,
                    window.as_ptr(),
                    this_cnt as libc::c_int,
                    (offset + written) as libc::off_t,
                )
            };
            if rc < 0 {
                return Err(io_err("write", &std::io::Error::last_os_error()));
            }
            if rc == 0 {
                // No progress and no error: treat as a write failure rather than spinning forever.
                return Err(GraphusError::Storage(
                    "pwritev wrote 0 bytes (device full or closed)".to_owned(),
                ));
            }
            written += rc as u64;
        }
        // Defence in depth: the loop only exits when `written == total`, but assert the invariant so
        // a future change that mishandles short writes can never silently truncate a coalesced run.
        if written != total {
            return Err(GraphusError::Storage(format!(
                "pwritev wrote {written} of {total} bytes for a coalesced run"
            )));
        }
        Ok(())
    }

    /// The kernel's per-call `iovec` cap (`IOV_MAX`/`UIO_MAXIOV`, `_SC_IOV_MAX`). Falls back to the
    /// POSIX minimum (16) if the sysconf query is unavailable, so a run is always split safely.
    #[cfg(all(target_os = "linux", feature = "pwritev"))]
    #[allow(unsafe_code)]
    fn iov_max() -> usize {
        // SAFETY: `sysconf` takes a single integer name and returns a `long`; it touches no memory we
        // own and has no preconditions. A `-1` (query unsupported) is handled below.
        let v = unsafe { libc::sysconf(libc::_SC_IOV_MAX) };
        if v >= 1 { v as usize } else { 16 }
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
            .read_exact_at(buf, Self::offset(page)?)
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
            .write_all_at(buf, Self::offset(page)?)
            .map_err(|e| io_err("write", &e))
    }

    fn write_pages(&mut self, base: PageId, pages: &[&Page]) -> Result<()> {
        if pages.is_empty() {
            return Ok(());
        }
        // The run occupies pages `base ..= base + len - 1`. Validate the whole span up front so a
        // single concatenated `write_all_at` can never spill past `page_count` (a partial write of
        // a coalesced run that then errored would otherwise leave a gap behind a valid prefix). The
        // checked arithmetic mirrors `offset`: an attacker-controlled `base` (decoded from a
        // tampered, unkeyed-CRC WAL frame) can never wrap `u64` into an in-bounds-looking offset.
        let len = pages.len() as u64;
        let last = base.0.checked_add(len - 1).ok_or_else(|| {
            GraphusError::Storage(format!(
                "write_pages run from page {} of {len} pages overflows the page id space",
                base.0
            ))
        })?;
        if last >= self.page_count {
            return Err(GraphusError::Storage(format!(
                "write_pages out of range: pages {}..={} of {}",
                base.0, last, self.page_count
            )));
        }
        let offset = Self::offset(base)?;
        if pages.len() == 1 {
            // Single page: no staging / no vector — identical to `write_page`.
            return self
                .file
                .write_all_at(pages[0], offset)
                .map_err(|e| io_err("write", &e));
        }
        // Two coalescing strategies, both producing a byte-identical on-disk image to writing each
        // page in turn at its own contiguous offset:
        //
        //  * The `pwritev` feature (Linux only) takes the copy-free scatter/gather fast path: one
        //    `pwritev(2)` that borrows the page buffers directly — no staging copy (`rmp` #374).
        //  * Every other build takes the portable, `unsafe`-free fallback: one concatenated
        //    `write_all_at` (a single `pwrite(2)`) over a reused staging buffer.
        #[cfg(all(target_os = "linux", feature = "pwritev"))]
        {
            self.write_run_pwritev(offset, pages)
        }
        #[cfg(not(all(target_os = "linux", feature = "pwritev")))]
        {
            self.write_run_concat(offset, pages)
        }
    }

    fn sync_data(&mut self) -> Result<()> {
        // `full_sync_data` issues a true stable-storage barrier on every platform: `F_FULLFSYNC` on
        // macOS (a bare `fdatasync` there does NOT flush the drive's volatile write cache), an
        // ordinary `fdatasync` elsewhere. See `crate::fullsync`.
        crate::full_sync_data(&self.file).map_err(|e| io_err("sync_data", &e))
    }

    fn sync_all(&mut self) -> Result<()> {
        crate::full_sync_all(&self.file).map_err(|e| io_err("sync_all", &e))
    }

    fn page_count(&self) -> u64 {
        self.page_count
    }

    fn extend(&mut self, additional: u64) -> Result<()> {
        let new_count = self
            .page_count
            .checked_add(additional)
            .ok_or_else(|| GraphusError::Storage("page count overflow".to_owned()))?;
        // Defence-in-depth cap first: a tampered WAL/store header could decode an absurd page
        // count; reject it before computing a byte length at all.
        if new_count > MAX_PAGE_COUNT {
            return Err(GraphusError::Storage(format!(
                "extend to {new_count} pages exceeds the maximum of {MAX_PAGE_COUNT}"
            )));
        }
        // Checked multiplication: `new_count * PAGE_SIZE` must never wrap `u64` into a tiny byte
        // length (which `set_len` would use to TRUNCATE the file while `page_count` is bumped huge —
        // desynchronising metadata from the real file length → out-of-position writes → silent
        // corruption in release, overflow panic in debug). CWE-190 → CWE-787.
        let new_len = new_count.checked_mul(PAGE_SIZE as u64).ok_or_else(|| {
            GraphusError::Storage(format!(
                "new page count {new_count} times page size {PAGE_SIZE} overflows the byte length"
            ))
        })?;
        self.file
            .set_len(new_len)
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

    fn page_of(byte: u8) -> Page {
        [byte; PAGE_SIZE]
    }

    /// `rmp` #374: a coalesced `write_pages` over a contiguous run must produce a byte-identical
    /// on-disk image to writing each page individually with `write_page`. We write the same data to
    /// two devices — one with the per-page loop, one with the batched run — and assert the whole
    /// file bytes match.
    #[test]
    fn write_pages_byte_identical_to_per_page_loop() {
        let per_page_path = temp_path();
        let batched_path = temp_path();

        let p3 = page_of(0x33);
        let p4 = page_of(0x44);
        let p5 = page_of(0x55);
        let pages: [&Page; 3] = [&p3, &p4, &p5];

        // Per-page reference image: write pages 3,4,5 one at a time.
        {
            let mut dev = FileBlockDevice::open(&per_page_path).unwrap();
            dev.extend(8).unwrap();
            dev.write_page(PageId(3), &p3).unwrap();
            dev.write_page(PageId(4), &p4).unwrap();
            dev.write_page(PageId(5), &p5).unwrap();
            dev.sync_all().unwrap();
        }
        // Coalesced image: same pages via a single contiguous-run write_pages.
        {
            let mut dev = FileBlockDevice::open(&batched_path).unwrap();
            dev.extend(8).unwrap();
            dev.write_pages(PageId(3), &pages).unwrap();
            dev.sync_all().unwrap();
        }

        let a = std::fs::read(&per_page_path).unwrap();
        let b = std::fs::read(&batched_path).unwrap();
        assert_eq!(a, b, "coalesced run image differs from per-page image");

        std::fs::remove_file(&per_page_path).ok();
        std::fs::remove_file(&batched_path).ok();
    }

    /// A run LONGER than the kernel's per-call `IOV_MAX` (commonly 1024) forces `pwritev` to make
    /// multiple syscalls — exercising the short-write / IOV_MAX-splitting loop in `write_run_pwritev`.
    /// The resulting image must still be byte-identical to the per-page path. This is the regression
    /// guard for the multi-call vectored path; on non-`pwritev` builds it validates the concatenated
    /// fallback over a large run.
    #[test]
    fn write_pages_large_run_exceeds_iov_max_byte_identical() {
        let per_page_path = temp_path();
        let batched_path = temp_path();

        // > 1024 pages so a single pwritev cannot consume the whole run in one call on Linux.
        const N: usize = 1500;
        let mut pages: Vec<Page> = Vec::with_capacity(N);
        for i in 0..N {
            // A page-distinct fill so a misordered/short-write bug would corrupt the image.
            pages.push(page_of((i % 251) as u8));
        }
        let refs: Vec<&Page> = pages.iter().collect();

        {
            let mut dev = FileBlockDevice::open(&per_page_path).unwrap();
            dev.extend(N as u64).unwrap();
            for (i, p) in pages.iter().enumerate() {
                dev.write_page(PageId(i as u64), p).unwrap();
            }
            dev.sync_all().unwrap();
        }
        {
            let mut dev = FileBlockDevice::open(&batched_path).unwrap();
            dev.extend(N as u64).unwrap();
            dev.write_pages(PageId(0), &refs).unwrap(); // one contiguous run, > IOV_MAX
            dev.sync_all().unwrap();
        }

        let a = std::fs::read(&per_page_path).unwrap();
        let b = std::fs::read(&batched_path).unwrap();
        assert_eq!(
            a, b,
            "large coalesced run (> IOV_MAX) differs from per-page image"
        );

        std::fs::remove_file(&per_page_path).ok();
        std::fs::remove_file(&batched_path).ok();
    }

    /// A gap in page ids must break a run: the buffer pool never asks `write_pages` to span a gap,
    /// but we prove the two halves (run 3..=4 then run 6..=6, with page 5 left untouched) produce
    /// the identical image to the per-page path — i.e. a gap is genuinely a run boundary.
    #[test]
    fn write_pages_gap_breaks_run_byte_identical() {
        let per_page_path = temp_path();
        let batched_path = temp_path();

        let p3 = page_of(0xA3);
        let p4 = page_of(0xA4);
        let p6 = page_of(0xA6);

        {
            let mut dev = FileBlockDevice::open(&per_page_path).unwrap();
            dev.extend(8).unwrap();
            dev.write_page(PageId(3), &p3).unwrap();
            dev.write_page(PageId(4), &p4).unwrap();
            dev.write_page(PageId(6), &p6).unwrap(); // page 5 left as the zero-fill from extend
            dev.sync_all().unwrap();
        }
        {
            let mut dev = FileBlockDevice::open(&batched_path).unwrap();
            dev.extend(8).unwrap();
            let run_a: [&Page; 2] = [&p3, &p4];
            dev.write_pages(PageId(3), &run_a).unwrap(); // contiguous run 3..=4
            let run_b: [&Page; 1] = [&p6];
            dev.write_pages(PageId(6), &run_b).unwrap(); // separate run after the gap at page 5
            dev.sync_all().unwrap();
        }

        let a = std::fs::read(&per_page_path).unwrap();
        let b = std::fs::read(&batched_path).unwrap();
        assert_eq!(a, b, "gap-split runs differ from per-page image");

        std::fs::remove_file(&per_page_path).ok();
        std::fs::remove_file(&batched_path).ok();
    }

    #[test]
    fn write_pages_out_of_range_errors() {
        let path = temp_path();
        let mut dev = FileBlockDevice::open(&path).unwrap();
        dev.extend(2).unwrap();
        let p = page_of(1);
        // Run [1,2] would touch page 2, which is out of range (only pages 0,1 exist).
        let run: [&Page; 2] = [&p, &p];
        assert!(dev.write_pages(PageId(1), &run).is_err());
        // The valid prefix must not have been written by the failing call (whole-span validated up
        // front), so page 1 stays zero.
        let mut buf = [0u8; PAGE_SIZE];
        dev.read_page(PageId(1), &mut buf).unwrap();
        assert_eq!(buf, [0u8; PAGE_SIZE]);
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
