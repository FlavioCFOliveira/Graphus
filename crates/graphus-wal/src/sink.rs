//! The append-only byte log the WAL writes to, and its two implementations.
//!
//! The WAL is a byte stream, not a page array, so it has its own sink abstraction (parallel to
//! [`graphus_io::BlockDevice`]). [`FileLogSink`] is the production sink: it batches appends and
//! issues **one `write` + one `fdatasync`** per [`LogSink::sync`] (group commit, `§4.2`).
//! [`MemLogSink`] is the Deterministic-Simulation-Testing sink: appended-but-un-synced bytes
//! live in a side buffer and are discarded by [`MemLogSink::crash`], modelling power loss of the
//! un-`fdatasync`'d tail (decision `D-dst-investment`).
//!
//! Durability rule: bytes are durable only once [`LogSink::sync`] returns `Ok`. A sink reports
//! its `durable_len` (survives a crash) and `buffered_len` (durable + pending); the WAL uses
//! `buffered_len` to allocate the next LSN (`= byte offset`, `§4.1`) and `durable_len` to know
//! how far group commit has hardened.

use graphus_core::error::Result;

/// An append-only byte log with an explicit durability boundary.
pub trait LogSink {
    /// Appends `bytes` to the write buffer. They become durable only on a successful
    /// [`sync`](LogSink::sync).
    fn append(&mut self, bytes: &[u8]);

    /// Hardens every appended byte durably (the `fdatasync` of group commit). A returned error
    /// is treated as unrecoverable by [`crate::WalManager`] (PANIC on fsync failure, `§4.9`).
    fn sync(&mut self) -> Result<()>;

    /// The number of bytes that are durable (would survive a crash now).
    fn durable_len(&self) -> u64;

    /// The number of bytes appended so far (durable + not-yet-synced).
    fn buffered_len(&self) -> u64;

    /// Reads durable bytes `[from, durable_len)` into `into` (which is cleared first).
    fn read_durable(&self, from: u64, into: &mut Vec<u8>) -> Result<()>;
}

/// In-memory [`LogSink`] for Deterministic Simulation Testing. Un-synced appends live in
/// `pending` and are dropped by [`crash`](MemLogSink::crash); a one-shot sync error can be
/// armed to exercise the PANIC-on-fsync-failure path (`§4.9`).
#[derive(Debug, Default, Clone)]
pub struct MemLogSink {
    durable: Vec<u8>,
    pending: Vec<u8>,
    armed_sync_error: bool,
}

impl MemLogSink {
    /// An empty sink.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Models power loss: discards all appended-but-un-synced bytes.
    pub fn crash(&mut self) {
        self.pending.clear();
    }

    /// Arms a one-shot error on the next [`sync`](LogSink::sync).
    pub fn arm_sync_error(&mut self) {
        self.armed_sync_error = true;
    }

    /// A read-only view of the durable bytes (test helper).
    #[must_use]
    pub fn durable_bytes(&self) -> &[u8] {
        &self.durable
    }
}

impl LogSink for MemLogSink {
    fn append(&mut self, bytes: &[u8]) {
        self.pending.extend_from_slice(bytes);
    }

    fn sync(&mut self) -> Result<()> {
        if self.armed_sync_error {
            self.armed_sync_error = false;
            return Err(graphus_core::GraphusError::Storage(
                "injected fdatasync failure".to_owned(),
            ));
        }
        self.durable.append(&mut self.pending);
        Ok(())
    }

    fn durable_len(&self) -> u64 {
        self.durable.len() as u64
    }

    fn buffered_len(&self) -> u64 {
        (self.durable.len() + self.pending.len()) as u64
    }

    fn read_durable(&self, from: u64, into: &mut Vec<u8>) -> Result<()> {
        into.clear();
        let from = from as usize;
        if from <= self.durable.len() {
            into.extend_from_slice(&self.durable[from..]);
        }
        Ok(())
    }
}

/// Production [`LogSink`] over a regular file. Appends accumulate in a buffer that one
/// [`sync`](LogSink::sync) flushes with a single positioned write followed by a single
/// `fdatasync` — the group-commit path of `§4.2`.
#[derive(Debug)]
pub struct FileLogSink {
    file: std::fs::File,
    durable_len: u64,
    pending: Vec<u8>,
}

impl FileLogSink {
    /// Opens (creating if absent) the WAL segment at `path`. The file is never truncated; its
    /// current length is taken as already durable so recovery can scan it.
    pub fn open<P: AsRef<std::path::Path>>(path: P) -> Result<Self> {
        use graphus_core::GraphusError;
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(path)
            .map_err(|e| GraphusError::Storage(format!("open wal: {e}")))?;
        let durable_len = file
            .metadata()
            .map_err(|e| GraphusError::Storage(format!("wal metadata: {e}")))?
            .len();
        Ok(Self {
            file,
            durable_len,
            pending: Vec::new(),
        })
    }
}

impl LogSink for FileLogSink {
    fn append(&mut self, bytes: &[u8]) {
        self.pending.extend_from_slice(bytes);
    }

    fn sync(&mut self) -> Result<()> {
        use graphus_core::GraphusError;
        use std::os::unix::fs::FileExt;
        if self.pending.is_empty() {
            return Ok(());
        }
        self.file
            .write_all_at(&self.pending, self.durable_len)
            .map_err(|e| GraphusError::Storage(format!("wal write: {e}")))?;
        self.file
            .sync_data()
            .map_err(|e| GraphusError::Storage(format!("wal fdatasync: {e}")))?;
        self.durable_len += self.pending.len() as u64;
        self.pending.clear();
        Ok(())
    }

    fn durable_len(&self) -> u64 {
        self.durable_len
    }

    fn buffered_len(&self) -> u64 {
        self.durable_len + self.pending.len() as u64
    }

    fn read_durable(&self, from: u64, into: &mut Vec<u8>) -> Result<()> {
        use graphus_core::GraphusError;
        use std::os::unix::fs::FileExt;
        into.clear();
        if from >= self.durable_len {
            return Ok(());
        }
        let len = (self.durable_len - from) as usize;
        into.resize(len, 0);
        self.file
            .read_exact_at(into, from)
            .map_err(|e| GraphusError::Storage(format!("wal read: {e}")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn append_is_not_durable_until_sync() {
        let mut s = MemLogSink::new();
        s.append(b"hello");
        assert_eq!(s.buffered_len(), 5);
        assert_eq!(s.durable_len(), 0);
        s.sync().unwrap();
        assert_eq!(s.durable_len(), 5);
    }

    #[test]
    fn crash_discards_unsynced_tail_but_keeps_synced_prefix() {
        let mut s = MemLogSink::new();
        s.append(b"durable");
        s.sync().unwrap();
        s.append(b"-lost");
        s.crash();
        assert_eq!(s.durable_len(), 7);
        let mut buf = Vec::new();
        s.read_durable(0, &mut buf).unwrap();
        assert_eq!(buf, b"durable");
    }

    #[test]
    fn armed_sync_error_fires_once() {
        let mut s = MemLogSink::new();
        s.append(b"x");
        s.arm_sync_error();
        assert!(s.sync().is_err());
        assert_eq!(s.durable_len(), 0); // not hardened
        assert!(s.sync().is_ok());
        assert_eq!(s.durable_len(), 1);
    }

    #[test]
    fn read_durable_from_offset() {
        let mut s = MemLogSink::new();
        s.append(b"0123456789");
        s.sync().unwrap();
        let mut buf = Vec::new();
        s.read_durable(4, &mut buf).unwrap();
        assert_eq!(buf, b"456789");
    }

    #[test]
    fn file_sink_round_trips_and_survives_reopen() {
        let path =
            std::env::temp_dir().join(format!("graphus-wal-sink-{}.wal", std::process::id()));
        let _ = std::fs::remove_file(&path);
        {
            let mut s = FileLogSink::open(&path).unwrap();
            s.append(b"committed");
            s.sync().unwrap();
            s.append(b"never-synced"); // dropped on "crash" (no sync, just drop the sink)
            assert_eq!(s.durable_len(), 9);
        }
        let s = FileLogSink::open(&path).unwrap();
        assert_eq!(s.durable_len(), 9); // only the synced prefix is on disk
        let mut buf = Vec::new();
        s.read_durable(0, &mut buf).unwrap();
        assert_eq!(buf, b"committed");
        std::fs::remove_file(&path).ok();
    }
}
