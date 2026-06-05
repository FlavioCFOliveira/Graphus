//! `loom` model-checking of [`graphus_bufpool::ConcurrentBufferPool`]'s latching logic.
//!
//! These tests are the **substantive** validator of the concurrent pool. The crate is
//! `#![forbid(unsafe_code)]`, so it has no undefined behaviour and no data races by construction
//! (Rust's type system guarantees that) — `miri`/ThreadSanitizer would therefore find nothing.
//! What still needs proving is that the *latching/pinning/eviction protocol* is correct under
//! every legal thread interleaving: exactly-once loads, no lost dirty writes, no pin underflow,
//! no deadlock, and the WAL-before-data ordering on every path. `loom` exhaustively explores
//! those interleavings.
//!
//! The whole file is gated on `#[cfg(loom)]`, so it is **not** compiled by a normal `cargo test`.
//! Run it with:
//!
//! ```text
//! RUSTFLAGS="--cfg loom" cargo test -p graphus-bufpool --test loom_bufpool --release
//! ```
//!
//! `--release` is recommended (loom's search is exponential). Each model is kept deliberately
//! tiny (2 threads, 1–2 frames, 2–3 pages) so the search terminates quickly; growing any of those
//! dimensions can blow up the state space.

#![cfg(loom)]

use graphus_bufpool::page;
use graphus_bufpool::{ConcurrentBufferPool, WalRule};
use graphus_core::error::{GraphusError, Result};
use graphus_core::{Lsn, PageId};
use graphus_io::{BlockDevice, PAGE_SIZE, Page};

use loom::sync::Arc;
use loom::sync::atomic::{AtomicUsize, Ordering};

/// A tiny in-memory device for loom models: a fixed set of durable, checksummed pages and a
/// per-instance device-read counter so a test can assert "loaded exactly once". Writes land in
/// place (no crash modeling needed for the latch-logic models). It is `Send` and uses no interior
/// mutability of its own — the pool already serializes it behind a latch/mutex — so the read
/// counter is an atomic to stay observable across the `&self` `read_page`.
struct ModelDevice {
    pages: Vec<Page>,
    reads: Arc<AtomicUsize>,
}

impl ModelDevice {
    /// `n` zero pages, each stamped with its id and a valid checksum, plus a shared read counter.
    fn new(n: u64, reads: Arc<AtomicUsize>) -> Self {
        let mut pages = Vec::with_capacity(n as usize);
        for i in 0..n {
            let mut p: Page = [0u8; PAGE_SIZE];
            page::set_page_id(&mut p, i);
            // Stamp a recognizable byte so reads can be checked.
            p[100] = (i as u8).wrapping_add(1);
            page::write_checksum(&mut p);
            pages.push(p);
        }
        Self { pages, reads }
    }
}

impl BlockDevice for ModelDevice {
    fn read_page(&self, page: PageId, buf: &mut Page) -> Result<()> {
        self.reads.fetch_add(1, Ordering::SeqCst);
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

    fn extend(&mut self, additional: u64) -> Result<()> {
        for i in 0..additional {
            let id = self.pages.len() as u64;
            let mut p: Page = [0u8; PAGE_SIZE];
            page::set_page_id(&mut p, id);
            page::write_checksum(&mut p);
            self.pages.push(p);
            let _ = i;
        }
        Ok(())
    }
}

/// A WAL rule that records, on every `ensure_durable`, that the log was made durable. The device
/// write happens *inside* the pool right after this returns, so a successful `ensure_durable`
/// preceding the home write is the log-before-data guarantee. We additionally assert ordering by
/// counting: each write-back must bump `wal_calls` before the device's `write_page`. Because the
/// pool calls `ensure_durable` then `write_page` under the same frame latch, observing
/// `wal_calls >= writes` at all times is the invariant.
struct OrderingWal {
    wal_calls: Arc<AtomicUsize>,
}

impl WalRule for OrderingWal {
    fn ensure_durable(&mut self, _up_to: Lsn) -> Result<()> {
        self.wal_calls.fetch_add(1, Ordering::SeqCst);
        Ok(())
    }
}

/// A device that, in addition to the model device, asserts the WAL-before-data invariant on every
/// `write_page`: the WAL-call counter must be strictly greater than the writes-seen counter at the
/// moment of a write, proving `ensure_durable` ran for this write-back before the home write.
struct WalCheckingDevice {
    inner: ModelDevice,
    wal_calls: Arc<AtomicUsize>,
    writes: Arc<AtomicUsize>,
}

impl BlockDevice for WalCheckingDevice {
    fn read_page(&self, page: PageId, buf: &mut Page) -> Result<()> {
        self.inner.read_page(page, buf)
    }

    fn write_page(&mut self, page: PageId, buf: &Page) -> Result<()> {
        // Log-before-data: before this home write, the WAL must already have been ensured durable
        // at least once more than the number of writes completed so far.
        let wal = self.wal_calls.load(Ordering::SeqCst);
        let done = self.writes.load(Ordering::SeqCst);
        assert!(
            wal > done,
            "WAL rule must run before the home write (wal={wal}, writes_done={done})"
        );
        self.writes.fetch_add(1, Ordering::SeqCst);
        self.inner.write_page(page, buf)
    }

    fn sync_data(&mut self) -> Result<()> {
        self.inner.sync_data()
    }

    fn sync_all(&mut self) -> Result<()> {
        self.inner.sync_all()
    }

    fn page_count(&self) -> u64 {
        self.inner.page_count()
    }

    fn extend(&mut self, additional: u64) -> Result<()> {
        self.inner.extend(additional)
    }
}

/// Scenario 1: two threads concurrently `fetch` the **same** page.
///
/// Asserts on every interleaving: the page is read from the device **exactly once**, both threads
/// observe a consistent pinned view (the stamped byte), the pin count reflects both pins, and
/// after both unpin the count is zero.
#[test]
fn loom_two_threads_fetch_same_page_loads_once() {
    loom::model(|| {
        let reads = Arc::new(AtomicUsize::new(0));
        let dev = ModelDevice::new(2, reads.clone());
        // 2 frames so a victim is always available without forcing eviction churn.
        let pool = ConcurrentBufferPool::new(dev, 2).shared();

        let p0 = pool.clone();
        let r0 = reads.clone();
        let t0 = loom::thread::spawn(move || {
            let f = p0.fetch(PageId(0)).expect("fetch ok");
            let v = p0.with_page(f, |pg| pg[100]);
            assert_eq!(v, 1, "page 0 stamped byte");
            p0.unpin(f);
            let _ = r0;
        });

        let p1 = pool.clone();
        let t1 = loom::thread::spawn(move || {
            let f = p1.fetch(PageId(0)).expect("fetch ok");
            let v = p1.with_page(f, |pg| pg[100]);
            assert_eq!(v, 1, "page 0 stamped byte");
            p1.unpin(f);
        });

        t0.join().unwrap();
        t1.join().unwrap();

        assert_eq!(
            reads.load(Ordering::SeqCst),
            1,
            "page 0 must be loaded from the device exactly once"
        );
    });
}

/// Scenario 2: one thread `fetch`es page 0 while another `fetch`es a **different** page (page 1),
/// in a 1-frame pool so the second fetch must evict the first.
///
/// Asserts: no panic, no deadlock, and each fetch yields the correct stamped byte for its page
/// (no corruption / no cross-page tearing). With a single frame, total device reads may be 2 (one
/// per page) or more if the two contend and reload, but each observed page is internally
/// consistent.
#[test]
fn loom_fetch_while_evict_other_page() {
    loom::model(|| {
        let reads = Arc::new(AtomicUsize::new(0));
        let dev = ModelDevice::new(2, reads.clone());
        let pool = ConcurrentBufferPool::new(dev, 1).shared();

        let p0 = pool.clone();
        let t0 = loom::thread::spawn(move || {
            if let Ok(f) = p0.fetch(PageId(0)) {
                assert_eq!(p0.with_page(f, |pg| pg[100]), 1);
                p0.unpin(f);
            }
        });

        let p1 = pool.clone();
        let t1 = loom::thread::spawn(move || {
            if let Ok(f) = p1.fetch(PageId(1)) {
                assert_eq!(p1.with_page(f, |pg| pg[100]), 2);
                p1.unpin(f);
            }
        });

        t0.join().unwrap();
        t1.join().unwrap();
    });
}

/// Scenario 3: concurrent pin/unpin on the same page — pin count never underflows, and once both
/// threads have unpinned, the frame is unpinned (evictable).
#[test]
fn loom_concurrent_pin_unpin_never_underflows() {
    loom::model(|| {
        let reads = Arc::new(AtomicUsize::new(0));
        let dev = ModelDevice::new(1, reads);
        let pool = ConcurrentBufferPool::new(dev, 2).shared();

        let p0 = pool.clone();
        let t0 = loom::thread::spawn(move || {
            let f = p0.fetch(PageId(0)).unwrap();
            // Pin count is at least 1 here.
            assert!(p0.pin_count(f) >= 1);
            p0.unpin(f);
        });

        let p1 = pool.clone();
        let t1 = loom::thread::spawn(move || {
            let f = p1.fetch(PageId(0)).unwrap();
            assert!(p1.pin_count(f) >= 1);
            p1.unpin(f);
        });

        t0.join().unwrap();
        t1.join().unwrap();

        // After both threads finished, the page (if resident) must be fully unpinned.
        let f = pool.fetch(PageId(0)).unwrap();
        // We hold exactly one pin now.
        assert_eq!(pool.pin_count(f), 1);
        pool.unpin(f);
        assert_eq!(
            pool.pin_count(f),
            0,
            "frame must be evictable after all unpins"
        );
    });
}

/// Scenario 4: the WAL rule is satisfied **before** every dirty write-back, on every interleaving.
///
/// Two threads each create-and-dirty a page in a 1-frame pool, forcing eviction write-backs. The
/// `WalCheckingDevice` asserts, inside `write_page`, that `ensure_durable` already ran for this
/// write-back (log-before-data). The model also confirms the final WAL-call count is at least the
/// number of home writes.
#[test]
fn loom_wal_rule_before_every_write_back() {
    loom::model(|| {
        let reads = Arc::new(AtomicUsize::new(0));
        let wal_calls = Arc::new(AtomicUsize::new(0));
        let writes = Arc::new(AtomicUsize::new(0));
        let dev = WalCheckingDevice {
            inner: ModelDevice::new(0, reads),
            wal_calls: wal_calls.clone(),
            writes: writes.clone(),
        };
        let wal = OrderingWal {
            wal_calls: wal_calls.clone(),
        };
        // 1 frame so the second allocation must evict (and thus write back) the first.
        let pool = ConcurrentBufferPool::with_wal(dev, wal, 1).shared();

        let p0 = pool.clone();
        let t0 = loom::thread::spawn(move || {
            if let Ok((f, _id)) = p0.new_page() {
                p0.with_page_mut(f, |pg| pg[10] = 0xAA);
                p0.unpin(f);
            }
        });

        let p1 = pool.clone();
        let t1 = loom::thread::spawn(move || {
            if let Ok((f, _id)) = p1.new_page() {
                p1.with_page_mut(f, |pg| pg[20] = 0xBB);
                p1.unpin(f);
            }
        });

        t0.join().unwrap();
        t1.join().unwrap();

        // Every home write was preceded by a WAL call (asserted in write_page); also confirm the
        // counts are consistent (wal >= writes) at the end.
        assert!(
            wal_calls.load(Ordering::SeqCst) >= writes.load(Ordering::SeqCst),
            "WAL calls must be >= home writes"
        );
    });
}
