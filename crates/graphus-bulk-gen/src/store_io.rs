//! Opening a `--db <dir>` store on disk, for the round-trip and footprint drivers.
//!
//! This mirrors the `graphus-bulk` CLI's own `open_store` logic so the drivers can re-open a store
//! the **real `graphus-bulk` binary** just wrote (via a subprocess `import`) and inspect its logical
//! contents — recover the WAL onto the device, then [`RecordStore::open`] it. It is read-only
//! inspection: the drivers never mutate the store through this handle.
//!
//! A `<dir>` holds `graph.store` (the block device file) and `graph.wal` (the segmented WAL
//! directory), exactly the layout `graphus-bulk import` produces.

use std::path::Path;

use graphus_core::GraphusError;
use graphus_io::FileBlockDevice;
use graphus_storage::RecordStore;
use graphus_storage::recovery::recover_device;
use graphus_wal::{FileLogSink, WalManager};

/// Buffer-pool frames for the inspection session (read-mostly; a modest pool is plenty).
const POOL_PAGES: usize = 256;

/// An on-disk store opened for read-only inspection.
pub type FileStore = RecordStore<FileBlockDevice, FileLogSink>;

/// Opens an existing store in `db` (recovering its WAL onto the device first), matching the
/// `graphus-bulk` CLI's open path.
///
/// # Errors
///
/// Returns a [`GraphusError`] if `db` holds no store, or if opening the device / WAL / recovery
/// fails.
pub fn open_store(db: &Path) -> Result<FileStore, GraphusError> {
    let device_file = db.join("graph.store");
    let wal_file = db.join("graph.wal");
    if !device_file.metadata().map(|m| m.len() > 0).unwrap_or(false) {
        return Err(GraphusError::Storage(format!(
            "no store found in {}",
            db.display()
        )));
    }
    let mut device = FileBlockDevice::open(&device_file)?;
    let mut wal = WalManager::open(
        FileLogSink::open(&wal_file)
            .map_err(|e| GraphusError::Storage(format!("opening WAL: {e}")))?,
    )
    .map_err(|e| GraphusError::Storage(format!("opening WAL manager: {e}")))?;
    recover_device(&mut wal, &mut device)?;
    let wal = WalManager::open(
        FileLogSink::open(&wal_file)
            .map_err(|e| GraphusError::Storage(format!("reopening WAL: {e}")))?,
    )
    .map_err(|e| GraphusError::Storage(format!("reopening WAL manager: {e}")))?;
    RecordStore::open(device, wal, POOL_PAGES)
}
