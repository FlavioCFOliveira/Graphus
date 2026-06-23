//! Regression for **concurrent reads under eviction** in [`ConcurrentBufferPool`] (`rmp` task #339 —
//! the first true concurrent reader, the morsel-driven parallel label scan, surfaced this).
//!
//! `rmp` #337 made the concurrent pool the production pool and proved its latch protocol under `loom`
//! (`loom_bufpool.rs` / `loom_freeze_vs_reader.rs`), but those models have **2 frames and ≤2 threads** —
//! they exercise the load/evict/latch protocol but not a many-thread CLOCK eviction storm. `rmp` #339's
//! morsel tier is the first code that reads the same store from many threads at once, and over a pool too
//! small to hold the working set it intermittently returned **wrong** aggregate values (some pages'
//! contents were read as another page's), i.e. a reader saw a frame whose bytes did not belong to the
//! page it asked for — a correctness (ACID read-integrity) bug.
//!
//! This test reproduces it deterministically-enough to fail reliably on a racy pool: a device of `PAGES`
//! distinct pages, each stamped with `page_id` at a fixed offset, behind a pool **far smaller** than
//! `PAGES` (forcing constant eviction), read concurrently by `READERS` threads that each fetch every page
//! many times and assert the bytes match the page id requested. A single mismatch fails the test.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use graphus_bufpool::ConcurrentBufferPool;
use graphus_bufpool::page;
use graphus_core::PageId;
use graphus_core::error::Result;
use graphus_io::{BlockDevice, PAGE_SIZE, Page};
/// The fixed offset at which each page carries its own id (a witness the reader verifies).
const TAG_OFF: usize = 64;

/// Reads the 8-byte little-endian word at `off`.
fn read_word(p: &Page, off: usize) -> u64 {
    u64::from_le_bytes(p[off..off + 8].try_into().expect("8-byte word"))
}

/// Writes the 8-byte little-endian word at `off`.
fn write_word(p: &mut Page, off: usize, v: u64) {
    p[off..off + 8].copy_from_slice(&v.to_le_bytes());
}

/// A `Send + Sync` in-memory device of `n` checksummed pages, each stamped with its own id at
/// [`TAG_OFF`]. Read-only at the device level (the test never writes), so no interior mutability is
/// needed for the reads under test.
struct TaggedDevice {
    pages: Vec<Page>,
}

impl TaggedDevice {
    fn new(n: u64) -> Self {
        let mut pages = Vec::with_capacity(n as usize);
        for i in 0..n {
            let mut p: Page = [0u8; PAGE_SIZE];
            page::set_page_id(&mut p, i);
            // Stamp the page id at TAG_OFF as the witness, plus a second copy near the end so a torn /
            // wrong-frame read is caught wherever it lands.
            write_word(&mut p, TAG_OFF, i);
            write_word(&mut p, PAGE_SIZE - 16, i);
            page::write_checksum(&mut p);
            pages.push(p);
        }
        Self { pages }
    }
}

impl BlockDevice for TaggedDevice {
    fn read_page(&self, page: PageId, buf: &mut Page) -> Result<()> {
        buf.copy_from_slice(&self.pages[page.0 as usize]);
        Ok(())
    }
    fn write_page(&mut self, page: PageId, buf: &Page) -> Result<()> {
        self.pages[page.0 as usize] = *buf;
        Ok(())
    }
    fn sync_data(&mut self) -> Result<()> {
        Ok(())
    }
    fn sync_all(&mut self) -> Result<()> {
        Ok(())
    }
    fn page_count(&self) -> u64 {
        self.pages.len() as u64
    }
    fn extend(&mut self, _additional: u64) -> Result<()> {
        // The test never grows the device.
        Ok(())
    }
}

/// Many concurrent readers over a pool too small for the working set must each read **exactly** the page
/// they asked for — never another page's bytes — even under constant CLOCK eviction. A racy pool (a
/// reader pinning/reading a frame an evictor is concurrently reloading) fails this with a tag mismatch.
#[test]
fn concurrent_reads_under_eviction_never_cross_pages() {
    const PAGES: u64 = 512;
    // A pool far smaller than the working set, so every fetch likely evicts — the eviction storm the
    // morsel scan triggers over a small buffer pool.
    const POOL_FRAMES: usize = 16;
    const READERS: usize = 16;
    const ROUNDS: usize = 40;

    let dev = TaggedDevice::new(PAGES);
    let pool = ConcurrentBufferPool::new(dev, POOL_FRAMES).shared();

    // A shared flag the first mismatch trips, so every thread stops promptly and the failure is reported
    // once with the offending (requested, observed) pair.
    let bad = Arc::new(AtomicBool::new(false));
    let mismatch: Arc<std::sync::Mutex<Option<(u64, u64, u64)>>> =
        Arc::new(std::sync::Mutex::new(None));

    std::thread::scope(|scope| {
        for r in 0..READERS {
            let pool = Arc::clone(&pool);
            let bad = Arc::clone(&bad);
            let mismatch = Arc::clone(&mismatch);
            scope.spawn(move || {
                // Each reader sweeps the pages in a different rotation so the access pattern (and thus the
                // eviction interleaving) differs per thread, maximising the chance of catching a race.
                for round in 0..ROUNDS {
                    if bad.load(Ordering::Relaxed) {
                        return;
                    }
                    let start = (r * 37 + round * 13) as u64 % PAGES;
                    for off in 0..PAGES {
                        let id = (start + off) % PAGES;
                        let res = pool.with_page_fetched(PageId(id), |p| {
                            (read_word(p, TAG_OFF), read_word(p, PAGE_SIZE - 16))
                        });
                        let (tag1, tag2) =
                            res.expect("fetch must succeed (no I/O error in this device)");
                        if tag1 != id || tag2 != id {
                            // A frame's bytes did not belong to the page requested: the wrong-frame /
                            // torn read the morsel scan surfaced. Record and stop everyone.
                            if !bad.swap(true, Ordering::Relaxed) {
                                *mismatch.lock().unwrap() = Some((id, tag1, tag2));
                            }
                            return;
                        }
                    }
                }
            });
        }
    });

    if let Some((requested, got1, got2)) = *mismatch.lock().unwrap() {
        panic!(
            "concurrent read under eviction returned the WRONG page's bytes: requested page {requested}, \
             frame held tags ({got1}, {got2}) — the concurrent buffer pool let a reader observe a frame \
             an evictor was reloading (a read-integrity / ACID bug)"
        );
    }
}
