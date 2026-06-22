//! `loom` model-check of the **GC lazy-freeze vs. concurrent reader** race on
//! [`graphus_bufpool::ConcurrentBufferPool`] (`rmp` #337, Slice 1).
//!
//! ## What this proves
//!
//! Graphus's GC "lazy-freeze" rewrites a record's two MVCC header words — `xmin` (created-ts) and
//! `xmax` (expired-ts) — *in place*, as **two separate, non-atomic, WAL-logged 8-byte writes**
//! (`graphus-storage::store::freeze_store_headers` → `patch_header_word`). It is a value-preserving
//! representation change: visibility resolves a record identically before and after the freeze. The
//! only hazard, once reads run **off-thread** concurrently with the freeze (the later #336/#339
//! slices), is a **torn read of a single 8-byte word** — a reader observing 4 old bytes and 4 new
//! bytes of the *same* word, which is neither the old nor the new value and would corrupt visibility.
//!
//! Slice 1's precondition is that **every** page read goes through
//! [`ConcurrentBufferPool::with_page`] (a per-frame **read latch**) and every write through
//! [`with_page_mut`](ConcurrentBufferPool::with_page_mut) (a per-frame **write latch**). This model
//! exhaustively explores the interleavings of one freezing writer and one reader on a shared frame
//! and asserts the latch excludes a torn single-word read.
//!
//! The two writes being non-atomic *with respect to each other* is acceptable and modelled: a reader
//! may observe the pair as (old `xmin`, old `xmax`), (new `xmin`, old `xmax`) or (new `xmin`, new
//! `xmax`) — every prefix of the freeze is a legal, visibility-equivalent state — but **never** a
//! half-written single word.
//!
//! The encoding is a self-contained stand-in for `graphus_txn::VersionStamp` (the task forbids a
//! dependency on `graphus-txn`): a "stamp" is just a recognizable 8-byte little-endian value, and a
//! torn word is any 8-byte read that is neither the old nor the new stamp.
//!
//! Run with:
//!
//! ```text
//! RUSTFLAGS="--cfg loom" cargo test -p graphus-bufpool --test loom_freeze_vs_reader --release
//! ```

#![cfg(loom)]

use graphus_bufpool::page;
use graphus_bufpool::{ConcurrentBufferPool, WalRule};
use graphus_core::error::Result;
use graphus_core::{Lsn, PageId};
use graphus_io::{BlockDevice, PAGE_SIZE, Page};

use loom::sync::Arc;

/// Byte offsets of the two MVCC header words inside the record, mirroring
/// `graphus_storage::record` (`MVCC_OFF_CREATED_TS = 1`, `MVCC_OFF_EXPIRED_TS = 9`). The exact
/// values are not load-bearing for the model; what matters is two **disjoint** 8-byte words past the
/// page header so neither overlaps the `page_lsn`/checksum machinery.
const REC_OFF: usize = page::HEADER_SIZE; // record starts right after the page header
const XMIN_OFF: usize = REC_OFF + 1; // MVCC_OFF_CREATED_TS
const XMAX_OFF: usize = REC_OFF + 9; // MVCC_OFF_EXPIRED_TS

/// The "in-flight" stamps the record carries before the freeze (a writer's `TxnId`-keyed form).
const XMIN_OLD: u64 = 0xAAAA_AAAA_AAAA_AAAA;
const XMAX_OLD: u64 = 0xBBBB_BBBB_BBBB_BBBB;
/// The "committed(ts)" stamps the freeze rewrites them to.
const XMIN_NEW: u64 = 0x1111_1111_1111_1111;
const XMAX_NEW: u64 = 0x2222_2222_2222_2222;

/// Reads the 8-byte little-endian word at `off`.
fn read_word(p: &Page, off: usize) -> u64 {
    u64::from_le_bytes(p[off..off + 8].try_into().expect("8-byte word"))
}

/// Writes the 8-byte little-endian word at `off`.
fn write_word(p: &mut Page, off: usize, v: u64) {
    p[off..off + 8].copy_from_slice(&v.to_le_bytes());
}

/// A tiny `Send` in-memory device of `n` checksummed pages (no read counter needed here).
struct ModelDevice {
    pages: Vec<Page>,
}

impl ModelDevice {
    fn new(n: u64) -> Self {
        let mut pages = Vec::with_capacity(n as usize);
        for i in 0..n {
            let mut p: Page = [0u8; PAGE_SIZE];
            page::set_page_id(&mut p, i);
            page::write_checksum(&mut p);
            pages.push(p);
        }
        Self { pages }
    }
}

impl BlockDevice for ModelDevice {
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
    fn extend(&mut self, additional: u64) -> Result<()> {
        for _ in 0..additional {
            let id = self.pages.len() as u64;
            let mut p: Page = [0u8; PAGE_SIZE];
            page::set_page_id(&mut p, id);
            page::write_checksum(&mut p);
            self.pages.push(p);
        }
        Ok(())
    }
}

/// A no-op WAL rule that nonetheless reports `tracks_lsn() == true`, so the freeze writes must stamp
/// `page_lsn` via `with_page_mut_lsn` (exactly as `patch_header_word` → `write_region` does in the
/// store). `ensure_durable` is a no-op: this model checks the *latch* protocol, not durability (that
/// is `loom_bufpool.rs`'s scenario 4).
struct TrackingNoopWal;

impl WalRule for TrackingNoopWal {
    fn ensure_durable(&mut self, _up_to: Lsn) -> Result<()> {
        Ok(())
    }
}

/// The freeze-vs-reader model.
///
/// One frame, two threads:
/// * the **writer** takes the write latch once and performs the two sequential 8-byte header-word
///   writes (xmin then xmax), each as a `with_page_mut_lsn` — mirroring the store's two
///   `patch_header_word` calls in `freeze_store_headers`;
/// * the **reader** repeatedly read-latches and reads BOTH words, asserting on every observation that
///   each single word is *whole* (either fully-old or fully-new), and that the pair is one of the
///   three legal freeze prefixes.
#[test]
fn loom_freeze_two_words_vs_reader_no_torn_word() {
    loom::model(|| {
        let mut dev = ModelDevice::new(1);
        // Seed the record's two header words with their pre-freeze (in-flight) stamps, on a
        // checksummed page, so a fetch loads a valid page whose words are XMIN_OLD / XMAX_OLD.
        {
            let p = &mut dev.pages[0];
            write_word(p, XMIN_OFF, XMIN_OLD);
            write_word(p, XMAX_OFF, XMAX_OLD);
            page::write_checksum(p);
        }
        // 2 frames so the reader's fetch never has to evict the writer's pinned frame (keeps the
        // model about the latch, not eviction — eviction is covered by loom_bufpool.rs).
        let pool = ConcurrentBufferPool::with_wal(dev, TrackingNoopWal, 2).shared();

        // Writer: pin the record's page, then freeze the two words under the write latch.
        let pw = Arc::clone(&pool);
        let writer = loom::thread::spawn(move || {
            let f = pw.fetch(PageId(0)).expect("writer fetch");
            // Two separate non-atomic WAL-logged 8-byte writes, each write-latched and lsn-stamped —
            // exactly `freeze_store_headers`'s two `patch_header_word` calls.
            pw.with_page_mut_lsn(f, Lsn(0x10), |p| write_word(p, XMIN_OFF, XMIN_NEW));
            pw.with_page_mut_lsn(f, Lsn(0x11), |p| write_word(p, XMAX_OFF, XMAX_NEW));
            pw.unpin(f);
        });

        // Reader: read both words under the read latch and assert no torn single word, and that the
        // observed pair is a legal freeze prefix.
        let pr = Arc::clone(&pool);
        let reader = loom::thread::spawn(move || {
            let f = pr.fetch(PageId(0)).expect("reader fetch");
            let (xmin, xmax) =
                pr.with_page(f, |p| (read_word(p, XMIN_OFF), read_word(p, XMAX_OFF)));
            pr.unpin(f);

            // 1) No torn SINGLE word: each word is whole (fully-old or fully-new), never a mix.
            assert!(
                xmin == XMIN_OLD || xmin == XMIN_NEW,
                "torn xmin word observed: {xmin:#018x} (neither old {XMIN_OLD:#018x} nor new \
                 {XMIN_NEW:#018x}) — the read latch failed to exclude the freeze write"
            );
            assert!(
                xmax == XMAX_OLD || xmax == XMAX_NEW,
                "torn xmax word observed: {xmax:#018x} (neither old {XMAX_OLD:#018x} nor new \
                 {XMAX_NEW:#018x}) — the read latch failed to exclude the freeze write"
            );

            // 2) The PAIR is a legal freeze prefix. The writes are ordered xmin-then-xmax, so a
            //    reader may see (old,old), (new,old) or (new,new) — but NOT (old,new): observing the
            //    new xmax while xmin is still old would mean the second write became visible before
            //    the first, which the single write-latched, ordered freeze cannot produce.
            let pair_ok = (xmin == XMIN_OLD && xmax == XMAX_OLD)
                || (xmin == XMIN_NEW && xmax == XMAX_OLD)
                || (xmin == XMIN_NEW && xmax == XMAX_NEW);
            assert!(
                pair_ok,
                "illegal freeze prefix observed: xmin={xmin:#018x}, xmax={xmax:#018x} \
                 (xmax cannot be new while xmin is still old)"
            );
        });

        writer.join().unwrap();
        reader.join().unwrap();

        // Final state: after both threads, the frozen pair is fully committed.
        let f = pool.fetch(PageId(0)).unwrap();
        let (xmin, xmax) = pool.with_page(f, |p| (read_word(p, XMIN_OFF), read_word(p, XMAX_OFF)));
        pool.unpin(f);
        assert_eq!(xmin, XMIN_NEW, "xmin is frozen after the writer completes");
        assert_eq!(xmax, XMAX_NEW, "xmax is frozen after the writer completes");
    });
}
