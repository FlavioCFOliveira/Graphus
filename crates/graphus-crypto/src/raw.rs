//! The raw positioned-**slot** backing under [`crate::EncryptedBlockDevice`].
//!
//! [`RawSlots`] is the minimal seam the encrypted device needs: positioned reads/writes of one
//! [`SLOT_SIZE`]-byte slot, sync, slot count, and extend. It is the encrypted analogue of
//! [`graphus_io::BlockDevice`] one layer down — slots, not pages — so the encryption logic in
//! [`crate::device`] is testable over an in-memory backing with the same crash/torn/io-error
//! injection the storage tests already use for `MemBlockDevice`.
//!
//! Two impls: [`FileRawSlots`] (production, positioned I/O over a real file at stride `SLOT_SIZE`,
//! mirroring `graphus_io::FileBlockDevice`'s `FileExt` usage) and [`MemRawSlots`] (in-memory,
//! mirroring `graphus_io::MemBlockDevice`'s injection model for Deterministic Simulation Testing).

use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::os::unix::fs::FileExt;
use std::path::Path;

use graphus_core::error::{GraphusError, Result};

use crate::slot::{SLOT_SIZE, Slot};

/// A positioned, slot-addressable raw backing for the encrypted device.
///
/// Each slot is exactly [`SLOT_SIZE`] bytes. Writes need not be durable until [`RawSlots::sync_data`]
/// or [`RawSlots::sync_all`] returns — the same durability contract as [`graphus_io::BlockDevice`].
pub trait RawSlots {
    /// Reads slot `index` into `buf`. Errors if `index` is out of range.
    fn read_slot(&self, index: u64, buf: &mut Slot) -> Result<()>;

    /// Writes `buf` to slot `index`. The write may be buffered until a subsequent sync.
    fn write_slot(&mut self, index: u64, buf: &Slot) -> Result<()>;

    /// Flushes slot data (and the minimum metadata needed to read it back) durably.
    fn sync_data(&mut self) -> Result<()>;

    /// Flushes slot data and all metadata durably.
    fn sync_all(&mut self) -> Result<()>;

    /// The number of slots the backing currently holds (including the header slot).
    fn slot_count(&self) -> u64;

    /// Grows the backing by `additional` zero-filled slots.
    fn extend(&mut self, additional: u64) -> Result<()>;
}

fn io_err(context: &str, e: &std::io::Error) -> GraphusError {
    GraphusError::Storage(format!("{context}: {e}"))
}

/// A [`RawSlots`] backed by a regular file, using positioned reads and writes at stride
/// [`SLOT_SIZE`] so concurrent readers need no shared cursor (mirrors
/// [`graphus_io::FileBlockDevice`]).
#[derive(Debug)]
pub struct FileRawSlots {
    file: File,
    slot_count: u64,
}

impl FileRawSlots {
    /// Opens the encrypted-device file at `path`, creating it if absent. Never truncates. Errors if
    /// the existing length is not a whole number of slots.
    ///
    /// # Errors
    /// [`GraphusError::Storage`] on an open/metadata failure or a length that is not a multiple of
    /// [`SLOT_SIZE`].
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(path)
            .map_err(|e| io_err("open", &e))?;
        let len = file.metadata().map_err(|e| io_err("metadata", &e))?.len();
        if len % SLOT_SIZE as u64 != 0 {
            return Err(GraphusError::Storage(format!(
                "encrypted file length {len} is not a multiple of the slot size {SLOT_SIZE}"
            )));
        }
        Ok(Self {
            file,
            slot_count: len / SLOT_SIZE as u64,
        })
    }

    fn offset(index: u64) -> u64 {
        index * SLOT_SIZE as u64
    }
}

impl RawSlots for FileRawSlots {
    fn read_slot(&self, index: u64, buf: &mut Slot) -> Result<()> {
        if index >= self.slot_count {
            return Err(GraphusError::Storage(format!(
                "raw read out of range: slot {index} of {}",
                self.slot_count
            )));
        }
        self.file
            .read_exact_at(buf, Self::offset(index))
            .map_err(|e| io_err("raw read", &e))
    }

    fn write_slot(&mut self, index: u64, buf: &Slot) -> Result<()> {
        if index >= self.slot_count {
            return Err(GraphusError::Storage(format!(
                "raw write out of range: slot {index} of {}",
                self.slot_count
            )));
        }
        self.file
            .write_all_at(buf, Self::offset(index))
            .map_err(|e| io_err("raw write", &e))
    }

    fn sync_data(&mut self) -> Result<()> {
        self.file.sync_data().map_err(|e| io_err("sync_data", &e))
    }

    fn sync_all(&mut self) -> Result<()> {
        self.file.sync_all().map_err(|e| io_err("sync_all", &e))
    }

    fn slot_count(&self) -> u64 {
        self.slot_count
    }

    fn extend(&mut self, additional: u64) -> Result<()> {
        let new_count = self
            .slot_count
            .checked_add(additional)
            .ok_or_else(|| GraphusError::Storage("slot count overflow".to_owned()))?;
        self.file
            .set_len(new_count * SLOT_SIZE as u64)
            .map_err(|e| io_err("set_len", &e))?;
        self.slot_count = new_count;
        Ok(())
    }
}

/// An in-memory [`RawSlots`] modelling the page-cache / durability boundary, with crash, torn-write
/// and I/O-error injection for Deterministic Simulation Testing — mirroring
/// [`graphus_io::MemBlockDevice`] one layer down (slots instead of pages).
#[derive(Debug, Default)]
pub struct MemRawSlots {
    /// Slots that have been synced and would survive a crash.
    persisted: Vec<Slot>,
    /// Written-but-not-yet-synced slots (the modelled page cache).
    cache: HashMap<u64, Slot>,
    /// When set, the next `write_slot` fails (then clears).
    armed_io_error: bool,
    /// When set, the next write to this slot stores only `prefix` bytes (then clears).
    armed_torn: Option<(u64, usize)>,
}

impl MemRawSlots {
    /// Creates a backing of `slots` zero-filled, durable slots.
    #[must_use]
    pub fn new(slots: u64) -> Self {
        Self {
            persisted: vec![[0u8; SLOT_SIZE]; slots as usize],
            ..Self::default()
        }
    }

    /// Arms a one-shot I/O error on the next `write_slot`.
    pub fn arm_io_error(&mut self) {
        self.armed_io_error = true;
    }

    /// Arms a one-shot torn write: the next write to `index` stores only its first `prefix` bytes,
    /// leaving the rest as it was (the corruption AEAD must catch).
    pub fn arm_torn_write(&mut self, index: u64, prefix: usize) {
        self.armed_torn = Some((index, prefix.min(SLOT_SIZE)));
    }

    /// Models power loss: discards all un-synced (cached) writes.
    pub fn crash(&mut self) {
        self.cache.clear();
    }

    /// The number of un-synced cached writes.
    #[must_use]
    pub fn dirty_slots(&self) -> usize {
        self.cache.len()
    }

    fn current(&self, idx: u64) -> &Slot {
        self.cache
            .get(&idx)
            .unwrap_or(&self.persisted[idx as usize])
    }

    // -- test-only inspection/corruption helpers (used by `crate::device` tests) ------------------

    /// Returns the current (cache-or-persisted) raw bytes of slot `index`, or `None` if out of
    /// range. Used to assert ciphertext secrecy.
    #[cfg(test)]
    #[must_use]
    pub fn raw_slot(&self, index: u64) -> Option<Slot> {
        if index >= self.persisted.len() as u64 {
            return None;
        }
        Some(*self.current(index))
    }

    /// Flips one byte of slot `index` at `offset` (in the cache, creating the entry from the
    /// persisted copy if needed). Used to test tamper detection.
    #[cfg(test)]
    pub fn flip_byte(&mut self, index: u64, offset: usize) {
        let mut s = *self.current(index);
        s[offset] ^= 0xFF;
        self.cache.insert(index, s);
    }

    /// Swaps the contents of slots `a` and `b`. Used to test page-relocation detection.
    #[cfg(test)]
    pub fn swap_slots(&mut self, a: u64, b: u64) {
        let sa = *self.current(a);
        let sb = *self.current(b);
        self.cache.insert(a, sb);
        self.cache.insert(b, sa);
    }
}

impl RawSlots for MemRawSlots {
    fn read_slot(&self, index: u64, buf: &mut Slot) -> Result<()> {
        if index >= self.persisted.len() as u64 {
            return Err(GraphusError::Storage(format!(
                "raw read out of range: slot {index}"
            )));
        }
        buf.copy_from_slice(self.current(index));
        Ok(())
    }

    fn write_slot(&mut self, index: u64, buf: &Slot) -> Result<()> {
        if index >= self.persisted.len() as u64 {
            return Err(GraphusError::Storage(format!(
                "raw write out of range: slot {index}"
            )));
        }
        if self.armed_io_error {
            self.armed_io_error = false;
            return Err(GraphusError::Storage("injected I/O error".to_owned()));
        }
        let mut s = *buf;
        if let Some((ti, prefix)) = self.armed_torn.take() {
            if ti == index {
                let mut torn = *self.current(index);
                torn[..prefix].copy_from_slice(&buf[..prefix]);
                s = torn;
            } else {
                self.armed_torn = Some((ti, prefix)); // not this slot; keep it armed
            }
        }
        self.cache.insert(index, s);
        Ok(())
    }

    fn sync_data(&mut self) -> Result<()> {
        for (idx, s) in self.cache.drain() {
            self.persisted[idx as usize] = s;
        }
        Ok(())
    }

    fn sync_all(&mut self) -> Result<()> {
        self.sync_data()
    }

    fn slot_count(&self) -> u64 {
        self.persisted.len() as u64
    }

    fn extend(&mut self, additional: u64) -> Result<()> {
        let new_len = self
            .persisted
            .len()
            .checked_add(additional as usize)
            .ok_or_else(|| GraphusError::Storage("slot count overflow".to_owned()))?;
        self.persisted.resize(new_len, [0u8; SLOT_SIZE]);
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
        std::env::temp_dir().join(format!("graphus-crypto-raw-{}-{n}.enc", std::process::id()))
    }

    #[test]
    fn file_roundtrip_and_durability() {
        let path = temp_path();
        {
            let mut raw = FileRawSlots::open(&path).expect("open");
            raw.extend(2).expect("extend");
            assert_eq!(raw.slot_count(), 2);
            let mut s = [0u8; SLOT_SIZE];
            s[..5].copy_from_slice(b"hello");
            raw.write_slot(1, &s).expect("write");
            raw.sync_all().expect("sync");
        }
        let raw = FileRawSlots::open(&path).expect("reopen");
        assert_eq!(raw.slot_count(), 2);
        let mut buf = [0u8; SLOT_SIZE];
        raw.read_slot(1, &mut buf).expect("read");
        assert_eq!(&buf[..5], b"hello");
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn file_rejects_non_slot_multiple_length() {
        let path = temp_path();
        std::fs::write(&path, b"not a whole slot").expect("write stub");
        assert!(FileRawSlots::open(&path).is_err());
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn mem_cached_write_lost_on_crash() {
        let mut raw = MemRawSlots::new(1);
        let mut s = [0u8; SLOT_SIZE];
        s[0] = 0xAB;
        raw.write_slot(0, &s).expect("write");
        raw.crash();
        assert_eq!(raw.dirty_slots(), 0);
        let mut buf = [0u8; SLOT_SIZE];
        raw.read_slot(0, &mut buf).expect("read");
        assert_eq!(buf[0], 0x00);
    }

    #[test]
    fn mem_synced_write_survives_crash() {
        let mut raw = MemRawSlots::new(1);
        let mut s = [0u8; SLOT_SIZE];
        s[0] = 0x7E;
        raw.write_slot(0, &s).expect("write");
        raw.sync_all().expect("sync");
        raw.crash();
        let mut buf = [0u8; SLOT_SIZE];
        raw.read_slot(0, &mut buf).expect("read");
        assert_eq!(buf[0], 0x7E);
    }

    #[test]
    fn mem_injected_io_error_fires_once() {
        let mut raw = MemRawSlots::new(1);
        raw.arm_io_error();
        assert!(raw.write_slot(0, &[1u8; SLOT_SIZE]).is_err());
        assert!(raw.write_slot(0, &[1u8; SLOT_SIZE]).is_ok());
    }
}
