//! **`rmp` #1085 — a checkpoint hardens the catalogue image the checkpoint itself writes.**
//!
//! # The property
//!
//! [`RecordStore::checkpoint`] flushes every dirty page home before it marks the clean point in the
//! log. The promise is not only about the pages other people wrote — the checkpoint writes one of its
//! own.
//!
//! Since `rmp` #1067 the durable counters are a base plus every logged delta the base does not name,
//! and a checkpoint FOLDS the deltas it is about to reclaim into that base. `rmp` #1083 added the
//! pending-DDL settle to the same image. Both write the catalogue through `checkpoint_meta`, and both
//! necessarily run **after** the flush at the top of `checkpoint` — the fold needs the reclaim floor,
//! the floor needs the `CHECKPOINT-END` record, and that record's empty Dirty Page Table is only
//! truthful because a flush preceded it. So the checkpoint acquired a page write positioned after its
//! own flush, and returned with the metadata page dirty.
//!
//! # Why a dirty page is a checksum failure and not a harmless cache state
//!
//! A page's CRC32C is stamped at **write-back** (`graphus_bufpool::page::write_checksum`, called only
//! from the pool's home-write paths) and never by the store's write path. A dirty resident frame
//! therefore holds bytes its stored checksum does not cover, and every reader served from the pool
//! sees that pair. `rmp` #426 already stated the consequence — "a resident dirty page is served from
//! cache without a disk read, carrying a stale checksum until write-back" — and built
//! `check::assert_cold_open` on it. What #1067 broke was the *other* half of that contract: the path
//! that guaranteed a checkpoint leaves the pool cold.
//!
//! It was measured through the DST integrity oracle, which reads every mapped page back through
//! [`RecordStore::read_device_page`] and recomputes its checksum
//! (`crates/graphus-dst/tests/det_scheduler_multi_writer_1034.rs`, every seed, deterministically —
//! `integrity: device page 0 failed its checksum`). This file is the same defect with no scheduler,
//! no threads and no seeds, so a regression fails here first and in one second.
//!
//! # Why the oracle asserts the DURABLE bytes and not just the checksum
//!
//! Checking only `verify_checksum(read_device_page(p))` would be a **proxy**, and a weak one:
//! `read_device_page` serves a resident frame from the pool, so that assertion also passes if someone
//! "repairs" #1085 by stamping `page::write_checksum` onto the dirty frame in place — a page that is
//! self-consistent in memory and still not on disk, which is the repair the fix's own comment rejects.
//!
//! So these tests run over a device whose **durable** bytes are separately readable
//! ([`SharedMemDevice`], the pattern of `dwb_floor_end_to_end_437.rs`) and assert both halves: the
//! page verifies its checksum **and** the durable image equals the one the pool serves. The
//! hand-stamped repair fails the second half; only actually flushing the page passes both.
//!
//! # Non-vacuity
//!
//! The oracle is worthless unless the checkpoint under test actually wrote a catalogue image after
//! its flush, so each test asserts that it did, using the only counter that can see it
//! ([`RecordStore::meta_chunk_writes`]). `checkpoint` writes no metadata chunk anywhere except in the
//! fold, so an increment across the call IS the post-flush write.
//!
//! ```text
//! cargo test -p graphus-storage --test checkpoint_leaves_no_dirty_page_1085
//! ```

use std::sync::{Arc, Mutex};

use graphus_core::{PageId, TxnId};
use graphus_io::{BlockDevice, PAGE_SIZE, Page};
use graphus_storage::RecordStore;
use graphus_storage::dwb::Dwb;
use graphus_wal::{MemLogSink, WalManager};

/// A block device whose **durable** bytes can be read independently of the store, so a test can tell
/// "the page is home" from "the page looks fine in the buffer pool". Writes land in a cache; only a
/// sync promotes them to `durable`. (Same shape as `dwb_floor_end_to_end_437.rs`.)
#[derive(Clone)]
struct SharedMemDevice {
    durable: Arc<Mutex<Vec<Page>>>,
    cache: Arc<Mutex<std::collections::HashMap<u64, Page>>>,
}

impl SharedMemDevice {
    fn new(pages: u64) -> Self {
        Self {
            durable: Arc::new(Mutex::new(vec![[0u8; PAGE_SIZE]; pages as usize])),
            cache: Arc::new(Mutex::new(std::collections::HashMap::new())),
        }
    }

    /// The page's bytes **as they are on stable storage**, or `None` if the device never got it.
    fn durable_page(&self, page: PageId) -> Option<Page> {
        let durable = self.durable.lock().expect("durable lock");
        durable.get(page.0 as usize).copied()
    }
}

impl BlockDevice for SharedMemDevice {
    fn read_page(&self, page: PageId, buf: &mut Page) -> graphus_core::error::Result<()> {
        if let Some(p) = self.cache.lock().expect("cache lock").get(&page.0) {
            *buf = *p;
            return Ok(());
        }
        let durable = self.durable.lock().expect("durable lock");
        let p = durable.get(page.0 as usize).ok_or_else(|| {
            graphus_core::error::GraphusError::Storage(format!(
                "read out of range: page {}",
                page.0
            ))
        })?;
        *buf = *p;
        Ok(())
    }

    fn write_page(&mut self, page: PageId, buf: &Page) -> graphus_core::error::Result<()> {
        self.cache.lock().expect("cache lock").insert(page.0, *buf);
        Ok(())
    }

    fn sync_data(&mut self) -> graphus_core::error::Result<()> {
        let cache = std::mem::take(&mut *self.cache.lock().expect("cache lock"));
        let mut durable = self.durable.lock().expect("durable lock");
        for (id, p) in cache {
            if id as usize >= durable.len() {
                durable.resize(id as usize + 1, [0u8; PAGE_SIZE]);
            }
            durable[id as usize] = p;
        }
        Ok(())
    }

    fn sync_all(&mut self) -> graphus_core::error::Result<()> {
        self.sync_data()
    }

    fn page_count(&self) -> u64 {
        self.durable.lock().expect("durable lock").len() as u64
    }

    fn extend(&mut self, additional: u64) -> graphus_core::error::Result<()> {
        let mut durable = self.durable.lock().expect("durable lock");
        let new_len = durable.len() + additional as usize;
        durable.resize(new_len, [0u8; PAGE_SIZE]);
        Ok(())
    }
}

type Store = RecordStore<SharedMemDevice, MemLogSink>;

/// Frames enough for this workload's whole image, so nothing is evicted: an eviction would write a
/// page home (and stamp its checksum) behind the test's back, which is precisely the accident that
/// would let a regression pass.
const POOL_PAGES: usize = 64;

fn fresh_store() -> (Store, SharedMemDevice) {
    let device = SharedMemDevice::new(0);
    let wal = WalManager::create(MemLogSink::new()).expect("create wal");
    let store = RecordStore::create(device.clone(), wal, POOL_PAGES, 1).expect("create store");
    // The redo-bounding auto-checkpoint fires from `commit`, and one that ran between the setup and
    // the explicit `checkpoint` below would have already folded the deltas — leaving the checkpoint
    // under test with nothing owed and the non-vacuity assertion unmet. Disabled so the run is
    // deterministic and the fold happens where the test can see it.
    store.set_checkpoint_interval_bytes(0);
    (store, device)
}

/// Moves the cardinality, so the checkpoint's fold has something to fold and therefore writes an
/// image. Without this the whole oracle is vacuous.
fn commit_some_nodes(store: &Store, txn: u64) {
    let txn = TxnId(txn);
    store.begin(txn);
    for _ in 0..8 {
        store.create_node(txn).expect("create a node");
    }
    store.commit(txn).expect("commit the setup");
}

/// The oracle: after a checkpoint, every mapped page must be **home** — its durable bytes present,
/// equal to what the pool serves, and covered by its own stored checksum.
fn assert_every_mapped_page_is_home(store: &Store, device: &SharedMemDevice, context: &str) {
    for page in store.mapped_pages() {
        let served = store
            .read_device_page(page)
            .unwrap_or_else(|e| panic!("{context}: read page {}: {e}", page.0));

        assert!(
            graphus_bufpool::page::verify_checksum(&served),
            "{context}: page {} holds bytes its stored checksum does not cover after `checkpoint` \
             returned. A checkpoint must harden the catalogue image its own counter fold writes, not \
             leave it dirty in the pool with a checksum stamped by the earlier flush (`rmp` #1085).",
            page.0
        );

        let durable = device.durable_page(page).unwrap_or_else(|| {
            panic!(
                "{context}: page {} is mapped but absent from the device's durable image — the \
                 checkpoint returned without ever writing it home (`rmp` #1085)",
                page.0
            )
        });
        assert!(
            durable == *served,
            "{context}: page {}'s DURABLE bytes differ from the image the pool serves. The page was \
             never written home, so the checkpoint's own catalogue write survives only in the log. \
             This is the half a checksum-only oracle cannot see, and the half that distinguishes \
             flushing the page from stamping its checksum in place (`rmp` #1085).",
            page.0
        );
    }
}

/// The bare store: `flush` takes the `pool.flush_all` path.
#[test]
fn no_dirty_page_survives_a_checkpoint() {
    let (store, device) = fresh_store();
    commit_some_nodes(&store, 1);

    let written_before = store.meta_chunk_writes().0;
    store.checkpoint().expect("checkpoint the store");
    let written_after = store.meta_chunk_writes().0;

    assert!(
        written_after > written_before,
        "the checkpoint wrote no catalogue chunk at all ({written_before} -> {written_after}), so \
         the oracle below proves nothing about `rmp` #1085: the defect is a page written after the \
         flush, and this run produced no such write. Fix the workload (the fold needs a pending \
         cardinality delta) before trusting a green verdict here."
    );

    assert_every_mapped_page_is_home(&store, &device, "bare store");
}

/// The **production** shape: with a doublewrite buffer attached, `flush` takes
/// `flush_protected_with_attached_dwb` — a different code path, chunked by `DWB_MAX_BATCH` and
/// routed through the stager. Every production store attaches one, so the bare-store test above
/// would leave the shipping path uncovered.
#[test]
fn no_dirty_page_survives_a_checkpoint_with_a_doublewrite_buffer() {
    let (store, device) = fresh_store();
    let dwb_dev = SharedMemDevice::new(0);
    store.attach_dwb(Dwb::new(dwb_dev).expect("attach a doublewrite buffer"));

    commit_some_nodes(&store, 1);

    let written_before = store.meta_chunk_writes().0;
    store.checkpoint().expect("checkpoint the store");
    let written_after = store.meta_chunk_writes().0;

    assert!(
        written_after > written_before,
        "the checkpoint wrote no catalogue chunk ({written_before} -> {written_after}); see the \
         sibling test for why that makes the oracle vacuous"
    );

    assert_every_mapped_page_is_home(&store, &device, "doublewrite-protected store");
}

/// The same property when the checkpoint has **nothing** to fold: a second checkpoint, back to back.
///
/// Since `rmp` #1085 the hardening flush is taken only when the fold actually wrote, so this is the
/// case that exercises the *skipped* branch. It must still leave the store clean — and it does, for a
/// reason worth stating: if the fold wrote nothing, nothing dirtied a page after the checkpoint's own
/// flush, so there is nothing left to harden.
#[test]
fn a_checkpoint_with_nothing_to_fold_also_leaves_the_store_clean() {
    let (store, device) = fresh_store();
    commit_some_nodes(&store, 1);

    store.checkpoint().expect("first checkpoint");
    let written_before = store.meta_chunk_writes().0;
    store.checkpoint().expect("second checkpoint");
    assert_eq!(
        store.meta_chunk_writes().0,
        written_before,
        "the second checkpoint wrote a catalogue chunk, so it was NOT the nothing-to-fold case this \
         test exists to cover"
    );

    assert_every_mapped_page_is_home(&store, &device, "back-to-back checkpoint");
}
