//! `rmp` #532 commit pipelining — the **Defect-B end-to-end gate**: an eviction that fires DURING a
//! pipelined harden's overlap must never write a data page home over an un-synced WAL record.
//!
//! This drives the *real* [`ConcurrentBufferPool`] eviction path over a WAL rule
//! ([`SharedWal`]) sharing the **same** [`WalManager`] the store logs through — the exact
//! production wiring (`graphus-storage`). It reproduces the pipeline-overlap window
//! (`durable_len < written_len`, a batch written-but-un-synced with its `fdatasync` still deferred),
//! then forces the buffer pool to evict a dirty, WAL-stamped page. The buffer pool's WAL-before-data
//! rule ([`ConcurrentBufferPool::write_back`] → `ensure_durable`) MUST harden the written range before
//! the home write, so the page is never written over an un-synced WAL record.
//!
//! On the defective (no-op-when-pending-empty) `sync`, `ensure_durable` returned `Ok` without
//! `fdatasync`ing (the records were already in the file, so the *pending tail* was empty), leaving the
//! home page durable while its redo record was not — the silent atomicity hole. This test FAILS there.
//!
//! Real filesystem I/O (`FileLogSink`), so it is `miri`-ignored like the other on-disk WAL tests; the
//! window and the assertion are fully deterministic (a single-threaded, manually-triggered eviction).

use graphus_bufpool::ConcurrentBufferPool;
use graphus_core::TxnId;
use graphus_io::MemBlockDevice;
use graphus_storage::SharedWal;
use graphus_wal::{FileLogSink, WalManager};

struct TempWalDir {
    path: std::path::PathBuf,
}
impl TempWalDir {
    fn new(tag: &str) -> Self {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock after epoch")
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "graphus-pipeline-wbd-{tag}-{nanos}-{}",
            std::process::id()
        ));
        Self { path }
    }
}
impl Drop for TempWalDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

#[cfg_attr(
    miri,
    ignore = "real filesystem I/O is outside miri's isolation/UB scope"
)]
#[test]
fn eviction_during_pipeline_overlap_hardens_wal_before_writing_the_page_home() {
    let dir = TempWalDir::new("evict");
    let wal = WalManager::create(FileLogSink::open(&dir.path).unwrap()).unwrap();
    let shared = SharedWal::new(wal);

    // A capacity-1 buffer pool over a scratch device, wired to the SAME WAL via `SharedWal` — the
    // pool's WAL rule and the log below are clones over one `Arc<Mutex<WalManager>>`, exactly as the
    // record store wires them. Capacity 1 makes the next allocation deterministically evict the first.
    let pool = ConcurrentBufferPool::with_wal(MemBlockDevice::new(0), shared.clone(), 1);

    // Allocate page P, log a WAL update for it (its record's LSN is `page_lsn`), stamp `page_lsn`,
    // dirty it, and unpin so it becomes an eviction candidate.
    let (frame, page_id) = pool.new_page().unwrap();
    let page_lsn = shared.with(|w| {
        w.begin(TxnId(1));
        w.log_update(
            TxnId(1),
            page_id,
            b"redo-image".to_vec(),
            b"undo-image".to_vec(),
        )
    });
    pool.with_page_mut_lsn(frame, page_lsn, |p| p[100] = 0xAB);
    pool.unpin(frame);

    // PREPARE half of a pipelined harden: `page_lsn`'s record is WRITTEN to the log file but its
    // `fdatasync` is DEFERRED to `job` (still un-run) — the pipeline-overlap window.
    let job = shared.with(|w| w.begin_harden().unwrap());
    assert!(
        shared.with(|w| w.durable_len()) <= page_lsn.0,
        "precondition: the page's WAL record is written-but-not-durable during the overlap"
    );

    // Force an eviction of the dirty page P: a second allocation needs a victim, and P (capacity 1,
    // unpinned, dirty, WAL-stamped) is it. `new_page` → `evict_held` → `write_back(P)` →
    // `ensure_durable(page_lsn)` — the buffer pool's WAL-before-data rule, mid-overlap.
    let (frame2, _) = pool.new_page().unwrap();
    pool.unpin(frame2);

    // THE GATE: the eviction must have hardened the WAL through the evicted page's LSN BEFORE writing
    // it home — otherwise a crash before the deferred `fdatasync` leaves the home page over an
    // un-synced (hence un-undoable) WAL record. FAILS on the no-op-sync (Defect-B) version.
    assert!(
        shared.with(|w| w.durable_len()) > page_lsn.0,
        "WAL-before-data (rmp #532): an eviction during the pipeline overlap MUST harden the WAL \
         through the evicted page's page_lsn before writing it home"
    );

    // The (now redundant) offloaded harden then runs and completes; `complete_harden` is monotonic.
    let target = job.target_len();
    job.run().unwrap();
    shared.with(|w| w.complete_harden(target));
    assert!(shared.with(|w| w.durable_len()) > page_lsn.0);
}
