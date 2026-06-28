//! End-to-end (deterministic, DST-style) regression for `rmp` #437: the **real** `RecordStore` +
//! attached `Dwb` checkpoint path must persist the checkpoint-floor LSN durably in the DWB and
//! reclaim the WAL below it, and the production recovery path (`recover_device_with_dwb`) must use
//! that persisted floor to IGNORE a stale below-floor eviction-ring slot — so a stale slot can never
//! revert a committed change once its WAL has been reclaimed.
//!
//! This drives the genuine wiring (no internal shims): `RecordStore::create` + `attach_dwb` (installs
//! the eviction-ring stager and the checkpoint DWB), real commits + GC + `checkpoint()` (flushes
//! homes, **persists the DWB floor**, **reclaims** the WAL below it), then the production
//! `recover_device_with_dwb` over a snapshot with the #437 device residue injected.
//!
//! Both the store device AND the DWB device are a shared in-memory `BlockDevice` so the test can
//! snapshot the **store's own attached DWB** after the real checkpoint (proving the floor was
//! persisted by production code, not a test shim). Deterministic per the DST mandate (`04 §11`,
//! CLAUDE.md): no wall-clock, no entropy — the hazard reproduces reliably.

use std::sync::{Arc, Mutex};

use graphus_bufpool::page;
use graphus_core::{Lsn, PageId, TxnId};
use graphus_io::{BlockDevice, PAGE_SIZE, Page};
use graphus_storage::RecordStore;
use graphus_storage::dwb::Dwb;
use graphus_storage::recovery::recover_device_with_dwb;
use graphus_wal::{LogSink, MemLogSink, WalManager};

/// An in-memory device whose durable bytes live behind a shared `Arc<Mutex<..>>`, so a device can be
/// both driven by the store AND snapshotted for an independent recovery. (Mirrors
/// `dwb_eviction_ring_431.rs`'s `SharedMemDevice`.)
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
    /// A fresh, independent device holding a crash-consistent copy of this device's DURABLE bytes
    /// (un-synced cache writes are dropped — a power-loss snapshot).
    fn crash_snapshot(&self) -> Self {
        Self {
            durable: Arc::new(Mutex::new(self.durable.lock().unwrap().clone())),
            cache: Arc::new(Mutex::new(std::collections::HashMap::new())),
        }
    }
}
impl BlockDevice for SharedMemDevice {
    fn read_page(&self, page: PageId, buf: &mut Page) -> graphus_core::error::Result<()> {
        if let Some(p) = self.cache.lock().unwrap().get(&page.0) {
            *buf = *p;
            return Ok(());
        }
        let durable = self.durable.lock().unwrap();
        if page.0 as usize >= durable.len() {
            return Err(graphus_core::error::GraphusError::Storage(format!(
                "read out of range: page {}",
                page.0
            )));
        }
        *buf = durable[page.0 as usize];
        Ok(())
    }
    fn write_page(&mut self, page: PageId, buf: &Page) -> graphus_core::error::Result<()> {
        self.cache.lock().unwrap().insert(page.0, *buf);
        Ok(())
    }
    fn sync_data(&mut self) -> graphus_core::error::Result<()> {
        let cache = std::mem::take(&mut *self.cache.lock().unwrap());
        let mut durable = self.durable.lock().unwrap();
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
        self.durable.lock().unwrap().len() as u64
    }
    fn extend(&mut self, additional: u64) -> graphus_core::error::Result<()> {
        let mut durable = self.durable.lock().unwrap();
        let new_len = durable.len() + additional as usize;
        durable.resize(new_len, [0u8; PAGE_SIZE]);
        Ok(())
    }
}

type Store = RecordStore<SharedMemDevice, MemLogSink>;

/// THE #437 END-TO-END GATE.
///
/// 1. A real store with an attached DWB commits nodes, GC-freezes them, and takes a real
///    `checkpoint()` — which flushes homes, **persists the DWB floor**, and reclaims the WAL below it.
/// 2. We snapshot the store's OWN attached DWB device and assert the persisted floor advanced past 0
///    (the new #437 wiring — proven on the real device the store wrote, not a shim).
/// 3. We snapshot the store device + WAL, inject the #437 residue (a STALE below-floor ring slot for a
///    real home page `P`, plus a torn NEWER home image of `P`), and run `recover_device_with_dwb`.
/// 4. Recovery must IGNORE the stale below-floor slot. The correct image of `P` is unavailable (its
///    newer image is not in the DWB and its WAL is reclaimed), so recovery must SURFACE an
///    unrepairable fault rather than silently revert `P` to the stale image. We assert the error and
///    that `P`'s home was NOT reverted to the stale content.
#[test]
fn checkpoint_persists_floor_and_recovery_ignores_a_stale_below_floor_ring_slot() {
    // 1. Build a store over a SHARED device with an attached DWB over a SECOND shared device.
    let store_dev = SharedMemDevice::new(0);
    let dwb_dev = SharedMemDevice::new(0);
    let wal = WalManager::create(MemLogSink::new()).expect("create wal");
    let mut s: Store = RecordStore::create(store_dev, wal, 64, 1).expect("create store");
    s.attach_dwb(Dwb::new(dwb_dev.clone()).expect("dwb"));
    s.set_checkpoint_interval_bytes(0); // manual, deterministic

    // Commit a handful of nodes.
    for i in 1..=4u64 {
        let txn = TxnId(i);
        s.begin(txn);
        s.create_node(txn).unwrap();
        s.commit(txn).unwrap();
    }
    // GC-freeze so commit records stop flooring reclamation, then a real checkpoint reclaims the WAL
    // prefix AND persists the DWB floor.
    {
        let watermark = s.snapshot_ts();
        s.begin(TxnId(50));
        s.gc(TxnId(50), watermark).unwrap();
        s.commit(TxnId(50)).unwrap();
    }
    s.checkpoint()
        .expect("checkpoint persists floor + reclaims WAL");

    // 2a. The checkpoint reclaimed part of the committed WAL prefix (so below-floor redo is gone).
    use graphus_wal::HEADER_LEN;
    let log = s.with_wal(|w| w.sink().durable_bytes().to_vec());
    assert!(log.len() as u64 > HEADER_LEN, "the WAL still has records");
    assert!(
        log[HEADER_LEN as usize..].iter().take(64).any(|&x| x == 0),
        "the checkpoint must reclaim (zero) part of the committed WAL prefix"
    );

    // 2b. THE #437 WIRING: the store's OWN attached DWB now carries a persisted floor > 0. Snapshot the
    //     DWB device the store wrote and read the floor back through a fresh `Dwb`.
    let persisted_floor = Dwb::new(dwb_dev.crash_snapshot())
        .expect("reopen dwb snapshot")
        .floor();
    assert!(
        persisted_floor.0 > 0,
        "rmp #437: the real checkpoint must persist a non-zero DWB floor (got {persisted_floor:?})"
    );

    // 3. Snapshot the store device + WAL for recovery, and inject the #437 residue.
    // Flush the store so its committed dirty pages are durable on the shared device, then snapshot.
    s.flush().expect("flush store");
    let dev_snapshot = store_dev_snapshot(&mut s);

    // Pick a real, committed, intact, non-metadata home page P to be the victim.
    let victim = {
        let mut found = None;
        for pid in 1..dev_snapshot.page_count() {
            let mut buf: Page = [0u8; PAGE_SIZE];
            if dev_snapshot.read_page(PageId(pid), &mut buf).is_ok()
                && page::verify_checksum(&buf)
                && page::page_id(&buf) == pid
            {
                found = Some(pid);
                break;
            }
        }
        found.expect("a committed intact home page")
    };

    // Build the recovery DWB on a FRESH device carrying the SAME persisted floor (snapshotted from the
    // store's own DWB), and inject the STALE below-floor ring slot for the victim page.
    let rec_dwb_dev = dwb_dev.crash_snapshot();
    let stale_lsn = persisted_floor.0.saturating_sub(1); // strictly below the floor ⇒ gated out
    {
        let mut rdwb = Dwb::new(rec_dwb_dev.clone()).expect("recovery dwb");
        // The floor is already persisted on the snapshot (it came from the store's DWB). Confirm.
        assert_eq!(
            rdwb.floor(),
            persisted_floor,
            "the recovery DWB must carry the store's persisted floor"
        );
        let mut stale_img: Page = [0u8; PAGE_SIZE];
        page::set_page_id(&mut stale_img, victim);
        page::set_page_lsn(&mut stale_img, Lsn(stale_lsn));
        stale_img[200] = 0x5A; // distinct stale content
        page::write_checksum(&mut stale_img);
        rdwb.stage_eviction_slot(3, PageId(victim), &stale_img)
            .expect("inject stale ring slot 3");
    }

    // TEAR the victim's (newer) home write on the recovery device — a power loss mid-write.
    let mut rec_dev = dev_snapshot;
    {
        let mut buf: Page = [0u8; PAGE_SIZE];
        rec_dev.read_page(PageId(victim), &mut buf).unwrap();
        buf[1000] ^= 0xFF; // corrupt body ⇒ CRC fails ⇒ torn
        assert!(
            !page::verify_checksum(&buf),
            "the victim home must be torn now"
        );
        rec_dev.write_page(PageId(victim), &buf).unwrap();
        rec_dev.sync_all().unwrap();
    }

    // 4. Run the PRODUCTION recovery. Stale slot 3 is BELOW the floor ⇒ gated out ⇒ NOT restored over
    //    the torn newer home. The correct image is unavailable (only the gated stale copy, WAL
    //    reclaimed), so recovery must SURFACE an unrepairable fault, never silently revert.
    let mut sink = MemLogSink::new();
    sink.append(&log);
    sink.sync().expect("sync log");
    let mut wal = WalManager::open(sink).expect("open wal");
    let mut rec_dwb = Dwb::new(rec_dwb_dev).expect("reopen recovery dwb");

    let result = recover_device_with_dwb(&mut wal, &mut rec_dev, &mut rec_dwb);
    assert!(
        result.is_err(),
        "recovery must SURFACE a fault: the only DWB copy of the torn page is a stale below-floor \
         ring slot (gated out), so the correct image is unavailable — it must NOT silently revert to \
         the stale image (rmp #437). Got: {result:?}"
    );

    // The victim's home must NOT have been reverted to the STALE content (byte 200 == 0x5A).
    let mut after: Page = [0u8; PAGE_SIZE];
    rec_dev.read_page(PageId(victim), &mut after).unwrap();
    assert_ne!(
        after[200], 0x5A,
        "CRITICAL #437: the stale below-floor ring-slot image must NOT have been written over the \
         torn home page"
    );
}

/// Snapshots a store's mapped device pages into a fresh shared device (a crash-consistent disk image).
fn store_dev_snapshot(s: &mut Store) -> SharedMemDevice {
    let pages = s.mapped_pages();
    let maxp = pages.iter().map(|p| p.0).max().unwrap_or(0);
    let mut dev = SharedMemDevice::new(maxp + 1);
    for p in &pages {
        let bytes = s.read_device_page(*p).expect("read device page");
        dev.write_page(PageId(p.0), &bytes).expect("stage page");
    }
    dev.sync_all().expect("persist snapshot");
    dev
}
