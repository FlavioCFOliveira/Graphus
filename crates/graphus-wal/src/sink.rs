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
//!
//! ## The production sink is a **segmented directory** (`rmp` #116)
//!
//! [`FileLogSink`] backs the byte stream with a *directory* of files rather than one monolithic
//! file, so that [`reclaim`](LogSink::reclaim) can free disk physically by **deleting whole
//! segment files** below the recovery floor (the user-chosen segmentation strategy, over
//! hole-punching). The layout under the sink's directory path:
//!
//! ```text
//!   <wal-dir>/
//!   ├── anchor                       the first sync's bytes — the log header at [0, anchor_len)
//!   ├── seg.00000000000000000008     contiguous record bytes [base, base+len)
//!   ├── seg.00000000000000065544     …rolled to a new segment at SEGMENT_TARGET_BYTES
//!   └── …
//! ```
//!
//! - **Anchor.** The bytes hardened by the **first** [`sync`](LogSink::sync) on a fresh sink are the
//!   log header (both `WalManager::create` and the encrypted sink write+sync their header as their
//!   very first operation, before any record/frame). They live in `anchor`, which is **never
//!   deleted**, so offset `0` — the header recovery validates — always survives reclamation.
//! - **Segments.** Every later byte lives in a `seg.<base>` file, where `base` is the segment's
//!   physical start offset (`>= anchor_len`), zero-padded so lexicographic order is numeric order.
//!   A sync's bytes are never split across segments; the active segment rolls to a fresh one once it
//!   reaches `SEGMENT_TARGET_BYTES`.
//! - **Reclaim** deletes the maximal **prefix** of segments whose whole range lies below the floor
//!   (never the anchor, never the active segment). Byte offsets / LSNs are unchanged: the freed
//!   prefix reads back as **zeros** ([`read_durable`](LogSink::read_durable) zero-fills the gap
//!   between the anchor and the first surviving segment), and recovery skips that leading zero run to
//!   the first surviving record — exactly the contract [`MemLogSink::reclaim`] models for DST. Only a
//!   contiguous front prefix is ever freed, which recovery's interior-corruption check relies on.

use std::collections::BTreeMap;
use std::fs::File;
use std::path::{Path, PathBuf};

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

    /// Physically reclaims the storage backing the durable byte range `[from, up_to)` — bytes that
    /// recovery no longer needs (below the checkpoint / oldest-active-transaction floor, `rmp` #114).
    ///
    /// The logical length and every byte offset are **unchanged** (LSN == byte offset is preserved):
    /// only physical storage is freed, and the reclaimed range subsequently reads back as **zeros**.
    /// Recovery tolerates this by skipping a leading zero prefix to the first intact record (a real
    /// record never begins with a zero byte). The **default is a no-op**: a sink that does not
    /// implement physical reclamation keeps the bytes — always correct, just not disk-bounded. The
    /// in-memory [`MemLogSink`] implements it by zeroing the range (modelling a deleted segment) for
    /// Deterministic Simulation Testing, and the production [`FileLogSink`] implements it by **deleting
    /// the prefix of segment files** below the floor (`rmp` #116); the encrypted sink translates the
    /// logical range to whole frames and forwards it, and the encryption key-rotation swap handles the
    /// segmented WAL as a directory fileset.
    ///
    /// # Errors
    /// Returns a storage error if the underlying reclaim operation fails.
    fn reclaim(&mut self, _from: u64, _up_to: u64) -> Result<()> {
        Ok(())
    }
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

    fn reclaim(&mut self, from: u64, up_to: u64) -> Result<()> {
        // Models physical reclamation (a deleted segment / punched hole): the range reads back as
        // zeros — the bytes are freed — while the logical length and all offsets are preserved. Lets
        // recovery's skip-leading-zeros path and the storage reclaim floor be exercised under DST.
        let from = (from as usize).min(self.durable.len());
        let up_to = (up_to as usize).min(self.durable.len());
        if from < up_to {
            self.durable[from..up_to].fill(0);
        }
        Ok(())
    }
}

/// The filename holding the log header (`[0, anchor_len)`), never deleted by reclamation.
const ANCHOR_NAME: &str = "anchor";
/// The filename prefix of a record segment; the suffix is its zero-padded physical base offset.
const SEGMENT_PREFIX: &str = "seg.";
/// Width of the zero-padded base-offset suffix in a segment filename (`u64::MAX` is 20 digits), so
/// lexicographic directory order equals numeric byte-offset order.
const SEGMENT_BASE_WIDTH: usize = 20;
/// Default size at which the active segment rolls to a fresh one. 64 MiB bounds per-file size while
/// keeping the segment count (hence directory entries and the reclaim granularity) small for a large
/// log. Reclamation frees disk in whole-segment units, so this also sets the reclaim granularity.
pub const DEFAULT_SEGMENT_TARGET_BYTES: u64 = 64 * 1024 * 1024;

/// One present record segment: its physical byte range `[base, base + len)` and the open file.
#[derive(Debug)]
struct Segment {
    base: u64,
    len: u64,
    file: File,
}

/// Production [`LogSink`] over a **segmented directory** (see the module docs). Appends accumulate in
/// a buffer that one [`sync`](LogSink::sync) flushes to the active segment with a single positioned
/// write followed by a single `fdatasync` — the group-commit path of `§4.2`. [`reclaim`](LogSink::reclaim)
/// deletes the prefix of segments below the recovery floor to bound WAL disk (`rmp` #116).
#[derive(Debug)]
pub struct FileLogSink {
    /// The WAL directory holding `anchor` + `seg.<base>` files.
    dir: PathBuf,
    /// Length of the header in `anchor` (`0` until the first sync writes it).
    anchor_len: u64,
    /// Present segments, keyed by base offset (ascending). A reclaimed prefix is absent; the gap it
    /// leaves reads back as zeros.
    segments: BTreeMap<u64, Segment>,
    /// Total logical length = end of the last segment (or `anchor_len` if none). Byte offset == LSN,
    /// so this is unchanged by reclamation (the freed prefix becomes a zero gap, not a shift).
    durable_len: u64,
    /// Bytes appended since the last sync (durable only once `sync` returns `Ok`).
    pending: Vec<u8>,
    /// The active segment rolls to a fresh one once it reaches this size.
    segment_target: u64,
}

impl FileLogSink {
    /// Opens (creating if absent) the WAL directory at `path`, with the default segment size. An
    /// existing directory is scanned — its `anchor` length and `seg.<base>` files become the durable
    /// state — so recovery can read the assembled byte stream. Nothing is ever truncated.
    ///
    /// # Errors
    /// [`GraphusError::Storage`](graphus_core::GraphusError::Storage) on a filesystem failure or a
    /// malformed segment layout (non-contiguous segments, which a correct sink never writes).
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self> {
        Self::open_with_segment_target(path, DEFAULT_SEGMENT_TARGET_BYTES)
    }

    /// Like [`open`](Self::open) but with an explicit segment roll size (used by tests to force many
    /// small segments). `segment_target` is clamped to at least 1 so a degenerate `0` cannot wedge
    /// rolling.
    ///
    /// # Errors
    /// As [`open`](Self::open).
    pub fn open_with_segment_target<P: AsRef<Path>>(path: P, segment_target: u64) -> Result<Self> {
        use graphus_core::GraphusError;
        let dir = path.as_ref().to_path_buf();
        std::fs::create_dir_all(&dir)
            .map_err(|e| GraphusError::Storage(format!("open wal dir {}: {e}", dir.display())))?;

        // Read the anchor's length (the header), if present.
        let anchor_path = dir.join(ANCHOR_NAME);
        let anchor_len = match std::fs::metadata(&anchor_path) {
            Ok(m) => m.len(),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => 0,
            Err(e) => {
                return Err(GraphusError::Storage(format!("wal anchor metadata: {e}")));
            }
        };

        // Enumerate segment files, sorted by base offset.
        let mut bases: Vec<(u64, PathBuf)> = Vec::new();
        for entry in std::fs::read_dir(&dir)
            .map_err(|e| GraphusError::Storage(format!("read wal dir {}: {e}", dir.display())))?
        {
            let entry =
                entry.map_err(|e| GraphusError::Storage(format!("read wal dir entry: {e}")))?;
            let name = entry.file_name();
            let Some(name) = name.to_str() else { continue };
            if let Some(suffix) = name.strip_prefix(SEGMENT_PREFIX) {
                let base: u64 = suffix.parse().map_err(|_| {
                    GraphusError::Storage(format!("malformed WAL segment filename {name}"))
                })?;
                bases.push((base, entry.path()));
            }
        }
        bases.sort_by_key(|(b, _)| *b);

        // Open each segment and validate contiguity. The first present segment may start above
        // `anchor_len` (a reclaimed prefix), but from there segments are gap-free: `base == prev_end`.
        let mut segments: BTreeMap<u64, Segment> = BTreeMap::new();
        let mut expected_end: Option<u64> = None;
        for (base, seg_path) in bases {
            let file = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(&seg_path)
                .map_err(|e| GraphusError::Storage(format!("open wal segment: {e}")))?;
            let len = file
                .metadata()
                .map_err(|e| GraphusError::Storage(format!("wal segment metadata: {e}")))?
                .len();
            if let Some(end) = expected_end {
                if base != end {
                    return Err(GraphusError::Storage(format!(
                        "non-contiguous WAL segments: segment at {base} does not abut the previous \
                         segment end {end}"
                    )));
                }
            } else if base < anchor_len {
                return Err(GraphusError::Storage(format!(
                    "WAL segment base {base} overlaps the anchor header [0, {anchor_len})"
                )));
            }
            expected_end = Some(base + len);
            segments.insert(base, Segment { base, len, file });
        }

        let durable_len = expected_end.unwrap_or(anchor_len);
        Ok(Self {
            dir,
            anchor_len,
            segments,
            durable_len,
            pending: Vec::new(),
            segment_target: segment_target.max(1),
        })
    }

    /// The path of the segment file whose physical base is `base`.
    fn segment_path(&self, base: u64) -> PathBuf {
        self.dir
            .join(format!("{SEGMENT_PREFIX}{base:0SEGMENT_BASE_WIDTH$}"))
    }

    /// `fdatasync`s the WAL directory, hardening a created/deleted file's *name* (POSIX requires a
    /// directory fsync to make a new/removed directory entry durable, independent of file contents).
    fn sync_dir(&self) -> Result<()> {
        use graphus_core::GraphusError;
        let f = File::open(&self.dir).map_err(|e| {
            GraphusError::Storage(format!("open wal dir to fsync {}: {e}", self.dir.display()))
        })?;
        f.sync_data()
            .map_err(|e| GraphusError::Storage(format!("fsync wal dir: {e}")))
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

        // The very first sync on a fresh sink hardens the header into the anchor file.
        if self.anchor_len == 0 && self.segments.is_empty() && self.durable_len == 0 {
            let anchor_path = self.dir.join(ANCHOR_NAME);
            let f = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .truncate(false)
                .open(&anchor_path)
                .map_err(|e| GraphusError::Storage(format!("create wal anchor: {e}")))?;
            f.write_all_at(&self.pending, 0)
                .map_err(|e| GraphusError::Storage(format!("wal anchor write: {e}")))?;
            // True stable-storage barrier (`F_FULLFSYNC` on macOS, `fdatasync` elsewhere): a bare
            // `fdatasync` on APFS/HFS+ does not flush the drive's volatile write cache, so an
            // acknowledged commit could be lost on power failure. See `crate::fullsync`.
            crate::fullsync::full_sync_data(&f, "wal anchor fdatasync")?;
            self.sync_dir()?; // harden the anchor's directory entry
            self.anchor_len = self.pending.len() as u64;
            self.durable_len = self.anchor_len;
            self.pending.clear();
            return Ok(());
        }

        // Append the whole pending batch to the active segment, creating the first/next segment if
        // there is none or the active one has reached the roll size. A sync's bytes never split
        // across segments (the new segment starts at the current durable end).
        let need_new_segment = match self.segments.values().next_back() {
            None => true,
            Some(active) => active.len >= self.segment_target,
        };
        let created_segment = need_new_segment;
        if need_new_segment {
            let base = self.durable_len;
            let path = self.segment_path(base);
            let file = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .truncate(false)
                .open(&path)
                .map_err(|e| GraphusError::Storage(format!("create wal segment: {e}")))?;
            self.segments.insert(base, Segment { base, len: 0, file });
        }

        let active = self
            .segments
            .values_mut()
            .next_back()
            .expect("INVARIANT: a segment exists after the create-if-needed step above");
        let write_at = active.len; // file-relative offset (file holds bytes from its base)
        active
            .file
            .write_all_at(&self.pending, write_at)
            .map_err(|e| GraphusError::Storage(format!("wal segment write: {e}")))?;
        // True stable-storage barrier (`F_FULLFSYNC` on macOS, `fdatasync` elsewhere) — see the
        // anchor path above and `crate::fullsync`.
        crate::fullsync::full_sync_data(&active.file, "wal segment fdatasync")?;
        let n = self.pending.len() as u64;
        active.len += n;
        self.durable_len += n;
        if created_segment {
            self.sync_dir()?; // harden the new segment's directory entry after its data is durable
        }
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
        // Build `[from, durable_len)` zero-filled (the reclaimed gap stays zero), then overwrite the
        // anchor portion and each surviving segment's portion with their real bytes.
        let total = (self.durable_len - from) as usize;
        into.resize(total, 0);

        if from < self.anchor_len {
            let anchor_path = self.dir.join(ANCHOR_NAME);
            let end = self.anchor_len.min(self.durable_len);
            let len = (end - from) as usize;
            let f = File::open(&anchor_path)
                .map_err(|e| GraphusError::Storage(format!("open wal anchor to read: {e}")))?;
            f.read_exact_at(&mut into[..len], from)
                .map_err(|e| GraphusError::Storage(format!("wal anchor read: {e}")))?;
        }

        for seg in self.segments.values() {
            let seg_end = seg.base + seg.len;
            if seg_end <= from || seg.len == 0 {
                continue;
            }
            let read_from = seg.base.max(from);
            let out_off = (read_from - from) as usize;
            let file_off = read_from - seg.base;
            let len = (seg_end - read_from) as usize;
            seg.file
                .read_exact_at(&mut into[out_off..out_off + len], file_off)
                .map_err(|e| GraphusError::Storage(format!("wal segment read: {e}")))?;
        }
        Ok(())
    }

    fn reclaim(&mut self, from: u64, up_to: u64) -> Result<()> {
        // Delete the maximal **prefix** of segments whose whole range lies below `up_to` — never the
        // anchor (offsets `< from`, the header), never the active (last) segment (it takes appends).
        // The freed prefix then reads back as zeros, exactly the `MemLogSink::reclaim` contract.
        debug_assert!(from >= self.anchor_len || self.anchor_len == 0);
        let last_base = self.segments.values().next_back().map(|s| s.base);
        let mut to_delete: Vec<u64> = Vec::new();
        for seg in self.segments.values() {
            let seg_end = seg.base + seg.len;
            // Stop at the first segment not fully below the floor (a prefix only), and never the
            // active segment. `from` guards the anchor (segments always start at `>= anchor_len`).
            if seg_end <= up_to && seg.base >= from && Some(seg.base) != last_base {
                to_delete.push(seg.base);
            } else {
                break;
            }
        }
        if to_delete.is_empty() {
            return Ok(());
        }
        for base in &to_delete {
            let path = self.segment_path(*base);
            self.segments.remove(base);
            std::fs::remove_file(&path).map_err(|e| {
                graphus_core::GraphusError::Storage(format!("reclaim wal segment {base}: {e}"))
            })?;
        }
        // Harden the unlinks: the freed directory entries must be durable so a crash cannot resurrect
        // a deleted segment (which would reappear as non-zero bytes mid-stream and break recovery's
        // leading-zero-prefix assumption).
        self.sync_dir()?;
        Ok(())
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

    // miri has filesystem isolation enabled by default, so the real `open`/`remove_dir_all`
    // syscalls here abort under it. These tests exercise the *production* `FileLogSink` (real disk
    // durability + segmentation), which is out of miri's UB-checking scope anyway — the WAL *logic*
    // is validated over the in-memory `MemLogSink` in the other tests, which DO run under miri. (See
    // `VERIFICATION.md` → miri gate.)

    /// A unique temp WAL directory for one test, removed on drop.
    struct TempWal {
        path: std::path::PathBuf,
    }
    impl TempWal {
        fn new(tag: &str) -> Self {
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock after epoch")
                .as_nanos();
            let path = std::env::temp_dir().join(format!(
                "graphus-wal-sink-{tag}-{nanos}-{}",
                std::process::id()
            ));
            Self { path }
        }
    }
    impl Drop for TempWal {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }

    #[cfg_attr(
        miri,
        ignore = "real filesystem I/O is outside miri's isolation/UB scope"
    )]
    #[test]
    fn file_sink_round_trips_and_survives_reopen() {
        let dir = TempWal::new("roundtrip");
        {
            let mut s = FileLogSink::open(&dir.path).unwrap();
            s.append(b"committed");
            s.sync().unwrap();
            s.append(b"never-synced"); // dropped on "crash" (no sync, just drop the sink)
            assert_eq!(s.durable_len(), 9);
        }
        let s = FileLogSink::open(&dir.path).unwrap();
        assert_eq!(s.durable_len(), 9); // only the synced prefix is on disk
        let mut buf = Vec::new();
        s.read_durable(0, &mut buf).unwrap();
        assert_eq!(buf, b"committed");
    }

    #[cfg_attr(
        miri,
        ignore = "real filesystem I/O is outside miri's isolation/UB scope"
    )]
    #[test]
    fn file_sink_segments_and_assembles_across_a_reopen() {
        let dir = TempWal::new("segments");
        // Tiny segment target (4 bytes) forces a roll on nearly every sync.
        {
            let mut s = FileLogSink::open_with_segment_target(&dir.path, 4).unwrap();
            s.append(b"HEAD"); // first sync -> anchor (4 bytes)
            s.sync().unwrap();
            for chunk in [&b"aaaa"[..], b"bbbb", b"cccc", b"dddd"] {
                s.append(chunk);
                s.sync().unwrap();
            }
            assert_eq!(s.durable_len(), 4 + 16);
            // Multiple segment files were created (the active rolls past the 4-byte target).
            let segs = std::fs::read_dir(&dir.path)
                .unwrap()
                .filter_map(std::result::Result::ok)
                .filter(|e| e.file_name().to_str().unwrap().starts_with("seg."))
                .count();
            assert!(segs >= 4, "expected multiple segments, found {segs}");
        }
        // Reopen: the assembled byte stream is byte-identical.
        let s = FileLogSink::open_with_segment_target(&dir.path, 4).unwrap();
        assert_eq!(s.durable_len(), 20);
        let mut buf = Vec::new();
        s.read_durable(0, &mut buf).unwrap();
        assert_eq!(buf, b"HEADaaaabbbbccccdddd");
    }

    #[cfg_attr(
        miri,
        ignore = "real filesystem I/O is outside miri's isolation/UB scope"
    )]
    #[test]
    fn reclaim_deletes_a_prefix_and_the_gap_reads_as_zeros() {
        let dir = TempWal::new("reclaim");
        let mut s = FileLogSink::open_with_segment_target(&dir.path, 4).unwrap();
        s.append(b"HEAD"); // anchor [0,4)
        s.sync().unwrap();
        // Segments at bases 4, 8, 12, 16 (each rolls after reaching 4 bytes).
        for chunk in [&b"aaaa"[..], b"bbbb", b"cccc", b"dddd"] {
            s.append(chunk);
            s.sync().unwrap();
        }
        assert_eq!(s.durable_len(), 20);

        // Reclaim below offset 12: segments fully below 12 (bases 4 and 8) are deleted; the anchor
        // and the active segment are kept. `from` is the header end (the anchor length, 4 here).
        // Offsets are unchanged.
        s.reclaim(4, 12).unwrap();
        assert_eq!(s.durable_len(), 20, "reclaim never shifts offsets");

        // The freed prefix [4, 12) reads back as zeros; the rest is intact.
        let mut buf = Vec::new();
        s.read_durable(0, &mut buf).unwrap();
        assert_eq!(&buf[0..4], b"HEAD");
        assert_eq!(&buf[4..12], &[0u8; 8], "reclaimed segments read as zeros");
        assert_eq!(&buf[12..20], b"ccccdddd");

        // The deleted segment files are physically gone.
        assert!(!dir.path.join(format!("seg.{:020}", 4u64)).exists());
        assert!(!dir.path.join(format!("seg.{:020}", 8u64)).exists());

        // The zero gap and offsets survive a reopen, too.
        let s2 = FileLogSink::open_with_segment_target(&dir.path, 4).unwrap();
        assert_eq!(s2.durable_len(), 20);
        let mut buf2 = Vec::new();
        s2.read_durable(0, &mut buf2).unwrap();
        assert_eq!(buf2, buf);
    }

    #[cfg_attr(
        miri,
        ignore = "real filesystem I/O is outside miri's isolation/UB scope"
    )]
    #[test]
    fn reclaim_keeps_the_active_segment_even_if_below_floor() {
        let dir = TempWal::new("reclaim-active");
        let mut s = FileLogSink::open_with_segment_target(&dir.path, 4).unwrap();
        s.append(b"HEAD");
        s.sync().unwrap();
        s.append(b"aaaa");
        s.sync().unwrap(); // single segment at base 4, len 4
        // Floor above the whole log: the lone (active) segment must still be kept (`from` = anchor
        // length 4).
        s.reclaim(4, 1000).unwrap();
        let mut buf = Vec::new();
        s.read_durable(0, &mut buf).unwrap();
        assert_eq!(buf, b"HEADaaaa");
    }
}
