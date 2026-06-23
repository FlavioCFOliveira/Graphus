//! `loom` model-check of the **many-evictor-vs-reader eviction storm** on
//! [`graphus_bufpool::ConcurrentBufferPool`] (`rmp` #339 — the first true concurrent reader, the
//! morsel-driven parallel label scan, surfaced a read-integrity bug here).
//!
//! ## What this proves
//!
//! The existing models in `loom_bufpool.rs` / `loom_freeze_vs_reader.rs` use **2 frames and ≤2
//! threads**: they exercise the load/evict/latch protocol but never put a reader's *pin* in
//! contention with **two** independent evictors reloading the very frame the reader pinned. That is
//! the interleaving `rmp` #339's `concurrent_eviction.rs` runtime test reproduced (~33–60% of runs):
//! a reader asked for page `A` and observed another page's complete bytes.
//!
//! This model reproduces it at a small frame/thread count that still exhibits it: **two frames over
//! three distinct pages** (so every cross-page fetch must evict a resident one, but a victim is
//! generally available, unlike a 1-frame pool where a transient "all frames pinned" capacity error
//! dominates the search), shared by a reader that reads page `A` through
//! [`ConcurrentBufferPool::with_page_fetched`] and two evictor threads that read pages `B` and `C`
//! (each forcing an eviction). loom explores all interleavings, including the one where the reader's
//! pin on `A`'s frame is placed on the fast path *before* it takes its read latch, an evictor wins
//! the frame, and an absolute (`store(1)`) cold-path publish discards the reader's pin — letting a
//! second evictor reload the frame while a holder is still about to read it.
//!
//! On **every** interleaving the reader must observe **exactly** page `A`'s stamped byte — never
//! `B`'s or `C`'s. A failure here is the wrong-page read (an ACID read-integrity violation).
//!
//! Run with:
//!
//! ```text
//! RUSTFLAGS="--cfg loom" LOOM_MAX_PREEMPTIONS=3 \
//!   cargo test -p graphus-bufpool --test loom_eviction_storm --release
//! ```

#![cfg(loom)]

use graphus_bufpool::ConcurrentBufferPool;
use graphus_bufpool::page;
use graphus_core::PageId;
use graphus_core::error::{GraphusError, Result};
use graphus_io::{BlockDevice, PAGE_SIZE, Page};

use loom::sync::Arc;

/// The fixed offset at which each page carries a witness of its own id (mirrors
/// `concurrent_eviction.rs`'s `TAG_OFF`, kept well past the page header).
const TAG_OFF: usize = 64;

/// Reads the 8-byte little-endian witness word.
fn tag(p: &Page) -> u64 {
    u64::from_le_bytes(p[TAG_OFF..TAG_OFF + 8].try_into().expect("8-byte word"))
}

/// A tiny `Send`, read-only in-memory device of `n` checksummed pages, each stamped with its own id
/// at [`TAG_OFF`] (and a second copy near the tail, exactly as the runtime repro), so a wrong-frame
/// read is caught. The device is read-only at the byte level (the model never writes), so no
/// interior mutability is needed.
struct TaggedDevice {
    pages: Vec<Page>,
}

impl TaggedDevice {
    fn new(n: u64) -> Self {
        let mut pages = Vec::with_capacity(n as usize);
        for i in 0..n {
            let mut p: Page = [0u8; PAGE_SIZE];
            page::set_page_id(&mut p, i);
            p[TAG_OFF..TAG_OFF + 8].copy_from_slice(&i.to_le_bytes());
            p[PAGE_SIZE - 16..PAGE_SIZE - 8].copy_from_slice(&i.to_le_bytes());
            page::write_checksum(&mut p);
            pages.push(p);
        }
        Self { pages }
    }
}

impl BlockDevice for TaggedDevice {
    fn read_page(&self, page: PageId, buf: &mut Page) -> Result<()> {
        let idx = page.0 as usize;
        if idx >= self.pages.len() {
            return Err(GraphusError::Storage(format!("read oob {}", page.0)));
        }
        buf.copy_from_slice(&self.pages[idx]);
        Ok(())
    }
    fn write_page(&mut self, page: PageId, buf: &Page) -> Result<()> {
        let idx = page.0 as usize;
        if idx >= self.pages.len() {
            return Err(GraphusError::Storage(format!("write oob {}", page.0)));
        }
        self.pages[idx] = *buf;
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
        Ok(())
    }
}

/// Two frames, three threads: a reader of page `A` plus two evictors reading pages `B` and `C`.
///
/// Two frames over three distinct pages still forces constant eviction, but (unlike a single frame)
/// leaves the reader's fetch of `A` a victim to use even while one evictor holds the other frame —
/// so a transient "pool full of pinned pages" is not the dominant outcome and the wrong-page
/// interleaving is reachable. The reader uses [`ConcurrentBufferPool::with_page_fetched`], whose hit
/// fast path pins the frame **before** taking the read latch; loom explores the interleaving where
/// that pin is placed, an evictor wins and reloads the frame, and (if the publish discards the
/// reader's pin) a second evictor reloads it again while the reader is still about to read it. The
/// core assertion: whenever the reader's fetch *succeeds*, it observes **only** page `A`'s witness —
/// never `B`'s or `C`'s. (A transient capacity error — every frame momentarily pinned by the other
/// two threads — is a legitimate, non-corrupting outcome and is tolerated; it is **not** the bug.)
#[test]
fn loom_reader_pin_never_lost_under_two_evictors() {
    // 3 threads + the eviction storm is a large state space; cap preemptions so the search
    // terminates in reasonable time while still covering the lost-pin window (which needs only a
    // couple of preemption points: one between the reader's pin and its read latch, one inside the
    // evictor's publish).
    loom::model(|| {
        const A: u64 = 0;
        const B: u64 = 1;
        const C: u64 = 2;

        let dev = TaggedDevice::new(3);
        // Two frames over three pages: constant eviction, but a victim is generally available.
        let pool = ConcurrentBufferPool::new(dev, 2).shared();

        // Pre-resident `A` so the reader takes the HIT fast path of `with_page_fetched` (the path
        // that pins before latching), maximising the lost-pin window the bug lives in.
        {
            let f = pool.fetch(PageId(A)).expect("seed fetch A");
            pool.unpin(f);
        }

        let pr = Arc::clone(&pool);
        let reader = loom::thread::spawn(move || {
            // The reader asks for A. Whenever its fetch SUCCEEDS it must read A's witness — never
            // B/C. A transient capacity error (both frames pinned by the evictors) is legitimate.
            if let Ok(got) = pr.with_page_fetched(PageId(A), tag) {
                assert_eq!(
                    got, A,
                    "READER READ THE WRONG PAGE: asked for {A}, observed page {got}'s bytes — the \
                     concurrent buffer pool let an evictor reload the frame the reader had pinned \
                     (a read-integrity / ACID bug)"
                );
            }
        });

        let pb = Arc::clone(&pool);
        let evictor_b = loom::thread::spawn(move || {
            // Reads a DIFFERENT page, forcing eviction of whatever resides (often A's frame).
            if let Ok(got) = pb.with_page_fetched(PageId(B), tag) {
                assert_eq!(got, B, "evictor B read the wrong page: {got}");
            }
        });

        let pc = Arc::clone(&pool);
        let evictor_c = loom::thread::spawn(move || {
            if let Ok(got) = pc.with_page_fetched(PageId(C), tag) {
                assert_eq!(got, C, "evictor C read the wrong page: {got}");
            }
        });

        reader.join().unwrap();
        evictor_b.join().unwrap();
        evictor_c.join().unwrap();

        // No pin leaked by any path on any interleaving: every frame is evictable again.
        for slot in 0..pool.capacity() {
            let f = pool.fetch(PageId(slot as u64)).unwrap();
            pool.unpin(f);
        }
    });
}
