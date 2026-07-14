//! **`rmp` #745 — the WAL's durable byte offset is an EXACT, reclamation-proof measure of WAL volume.**
//!
//! `graphus_wal_bytes_written_total` (see `graphus_server::metrics::Metrics::publish_wal_bytes_for`)
//! is built on one property of [`LogSink`]: its `durable_len` is the log's **absolute lifetime byte
//! offset** — a monotone counter of every byte ever hardened, which segment reclamation does not move.
//! This file is the ground-truth proof of that property, and of the failure it replaces.
//!
//! ## What it replaces, and why that thing is broken
//!
//! Before this metric existed, the only way an outside observer (e.g. `examples/iot-timeseries`) could
//! estimate WAL volume was to **poll the WAL directory** and sum the largest size it ever saw for each
//! segment path. That reconstruction is structurally unsound: a segment can be created, filled, sealed
//! **and reclaimed** entirely between two polls, so it is never observed at *any* size, let alone its
//! final one — and its bytes vanish from the estimate. The error is **one-sided** (it can only
//! under-count) and **host-speed dependent** (a faster host reclaims more between polls and under-counts
//! *more*), which makes the resulting write-amplification figure a floor, not a measurement.
//!
//! [`missed_whole_segment_between_polls`] reproduces exactly that, deterministically and with no
//! threads: it polls, writes a segment's worth of records, seals it, reclaims it, polls again — and
//! shows the poll-based reconstruction is short by the whole segment while `durable_len` is not.
//!
//! ## Ground truth
//!
//! The tests never compare `durable_len` against another engine-derived number (that would be
//! circular). They compare it against the byte count the **test itself appended**, which it knows
//! exactly.

use std::path::Path;

use graphus_wal::sink::{FileLogSink, LogSink};

/// A stand-in for the 8-byte WAL header `WalManager::create` hardens as its very first sync — the bytes
/// that land in the never-reclaimed `anchor` file. Any first sync would do; the sink's only requirement
/// is that the anchor exists before segments start.
const HEADER: &[u8] = b"GRAPHUS\x01";

/// Segments roll at this size, so a handful of records seals one. The production default is 64 MiB
/// (clamped store-proportionally, `rmp` #706); a small target makes seal + reclaim cheap to drive here
/// WITHOUT changing any code path — `segment_target` only decides *when* the sink rolls.
const SEGMENT_TARGET: u64 = 4096;

/// One log record's worth of bytes. Content is irrelevant — this test measures VOLUME.
fn record(seq: u8, len: usize) -> Vec<u8> {
    vec![seq; len]
}

/// A scratch directory removed on drop.
struct TempDir(std::path::PathBuf);
impl TempDir {
    fn new(tag: &str) -> Self {
        let p = std::env::temp_dir().join(format!(
            "graphus_wal750_{tag}_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ));
        std::fs::create_dir_all(&p).expect("create scratch dir");
        Self(p)
    }
    fn path(&self) -> &Path {
        &self.0
    }
}
impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// The bytes **physically present** in the WAL directory right now (anchor + every surviving segment).
/// This is what an external observer can see at one instant — and, crucially, it FALLS when a reclaim
/// deletes segment files, even though no byte was ever un-written.
fn bytes_on_disk(dir: &Path) -> u64 {
    std::fs::read_dir(dir)
        .expect("read wal dir")
        .filter_map(|e| e.ok())
        .filter_map(|e| e.metadata().ok())
        .filter(|m| m.is_file())
        .map(|m| m.len())
        .sum()
}

/// One poll of the directory by an external observer, folded into `seen`: the largest size ever
/// observed for each segment path. This is precisely the reconstruction `examples/iot-timeseries` used
/// (max-per-path, summed) — and precisely what this metric replaces.
fn poll(dir: &Path, seen: &mut std::collections::BTreeMap<String, u64>) {
    for e in std::fs::read_dir(dir).expect("read wal dir").flatten() {
        let Ok(m) = e.metadata() else { continue };
        if !m.is_file() {
            continue;
        }
        let name = e.file_name().to_string_lossy().into_owned();
        let slot = seen.entry(name).or_insert(0);
        *slot = (*slot).max(m.len());
    }
}

/// Opens a sink with a small segment target and hardens the header into the anchor, exactly as
/// `WalManager::create` does. Returns the sink and the header's byte length (the fold baseline).
fn create_sink(dir: &Path) -> (FileLogSink, u64) {
    let mut sink = FileLogSink::open_with_segment_target(dir, SEGMENT_TARGET).expect("open sink");
    sink.append(HEADER);
    sink.sync().expect("sync header");
    let base = sink.durable_len();
    assert_eq!(
        base,
        HEADER.len() as u64,
        "the first sync hardens the header into the anchor at offset 0"
    );
    (sink, base)
}

/// **The load-bearing property.** `durable_len` counts EVERY byte hardened — exactly, with no drift —
/// across a segment SEAL/roll and across a RECLAMATION that physically deletes segment files.
///
/// Ground truth is the test's own running total of the bytes it appended. Reclamation is where the
/// poll-based reconstruction dies, so it is asserted here explicitly: the bytes physically on disk
/// COLLAPSE (files are unlinked) while `durable_len` does not so much as pause.
#[test]
fn durable_len_equals_bytes_appended_across_seal_and_reclaim() {
    let dir = TempDir::new("exact");
    let (mut sink, base) = create_sink(dir.path());

    // Append well past the segment target so the sink seals segments and rolls — several times.
    let mut appended: u64 = 0;
    for i in 0..40u8 {
        let rec = record(i, 512);
        sink.append(&rec);
        sink.sync().expect("sync record");
        appended += rec.len() as u64;

        // EXACT at every step: the offset is the header plus every byte this test has appended.
        assert_eq!(
            sink.durable_len(),
            base + appended,
            "durable_len must equal header + cumulative appended bytes (record {i})"
        );
    }

    // We must actually have crossed a seal, or the test proves nothing about rolling.
    let seg_count = std::fs::read_dir(dir.path())
        .expect("read dir")
        .flatten()
        .count();
    assert!(
        seg_count > 2,
        "TEETH: the workload must have sealed and rolled several segments (anchor + >1 segment), \
         found {seg_count} files — raise the record count or lower SEGMENT_TARGET"
    );

    let offset_before_reclaim = sink.durable_len();
    let on_disk_before = bytes_on_disk(dir.path());

    // RECLAIM everything below the current offset. The sink deletes the maximal prefix of segments
    // fully below the floor — never the anchor, never the active segment.
    sink.reclaim(HEADER.len() as u64, offset_before_reclaim)
        .expect("reclaim");

    let on_disk_after = bytes_on_disk(dir.path());
    assert!(
        on_disk_after < on_disk_before,
        "TEETH: the reclaim must have physically deleted segment files ({on_disk_before} -> \
         {on_disk_after} bytes on disk); without that this test does not exercise reclamation"
    );

    // THE POINT. Reclamation freed disk but moved nothing: the offset still equals every byte ever
    // appended. A metric built on this cannot lose a reclaimed segment.
    assert_eq!(
        sink.durable_len(),
        base + appended,
        "reclamation must NOT move the durable byte offset — it deletes segment files, it does not \
         un-write bytes (the freed prefix reads back as zeros and the offset keeps climbing)"
    );
    assert_eq!(sink.durable_len(), offset_before_reclaim);

    // And the offset is now provably LARGER than everything on disk — which is the precise reason an
    // on-disk reconstruction cannot recover it after the fact.
    assert!(
        sink.durable_len() > on_disk_after,
        "after reclamation the lifetime offset ({}) necessarily exceeds the bytes still on disk ({})",
        sink.durable_len(),
        on_disk_after
    );

    // Writes after a reclaim keep counting from the same offset — no rebase, no gap, no double count.
    let rec = record(0xAA, 300);
    sink.append(&rec);
    sink.sync().expect("sync post-reclaim");
    appended += rec.len() as u64;
    assert_eq!(
        sink.durable_len(),
        base + appended,
        "appends after a reclamation continue the same monotone offset"
    );
}

/// The offset survives a **reopen**, including one whose log has already been reclaimed — so a
/// `STOP`/`START DATABASE` cycle does not rewind it. (The metric re-baselines per engine incarnation
/// and so does not *depend* on this; proving it anyway pins the sink invariant the whole design rests
/// on, and would catch a future change that made `FileLogSink::open` recover the wrong offset.)
#[test]
fn durable_len_survives_reopen_after_reclamation() {
    let dir = TempDir::new("reopen");
    let (mut sink, base) = create_sink(dir.path());

    let mut appended: u64 = 0;
    for i in 0..40u8 {
        let rec = record(i, 512);
        sink.append(&rec);
        sink.sync().expect("sync");
        appended += rec.len() as u64;
    }
    let before_close = sink.durable_len();
    assert_eq!(before_close, base + appended);

    sink.reclaim(HEADER.len() as u64, before_close)
        .expect("reclaim");
    assert_eq!(sink.durable_len(), before_close, "reclaim does not rewind");
    drop(sink);

    // Reopen: `FileLogSink::open` recovers the offset from the surviving segments' absolute bases
    // (`base + len` of the last one), NOT from a count of the bytes still present.
    let reopened =
        FileLogSink::open_with_segment_target(dir.path(), SEGMENT_TARGET).expect("reopen sink");
    assert_eq!(
        reopened.durable_len(),
        before_close,
        "reopening a RECLAIMED log must recover the absolute lifetime byte offset, not collapse to \
         the bytes still on disk — the segment file's name IS its absolute base offset"
    );
    assert!(
        reopened.durable_len() > bytes_on_disk(dir.path()),
        "TEETH: the reopened offset must exceed the surviving bytes, i.e. a reclaim really did \
         happen before the close"
    );
}

/// **The bug this metric exists to kill**, reproduced deterministically.
///
/// An external observer polls the WAL directory and sums the largest size it ever saw per segment path.
/// Between two polls a segment is created, filled, sealed AND reclaimed — so the observer never sees it
/// at all. Its bytes are simply absent from the reconstruction, permanently. `durable_len` counts them.
///
/// No threads, no timing: the "poll" is an explicit call, so the miss is forced, not raced.
#[test]
fn missed_whole_segment_between_polls() {
    let dir = TempDir::new("missed");
    let (mut sink, base) = create_sink(dir.path());

    // ---- POLL #1: the observer's "before" sample. Only the anchor exists. ----
    let mut seen: std::collections::BTreeMap<String, u64> = std::collections::BTreeMap::new();
    poll(dir.path(), &mut seen);
    let reconstruction_before: u64 = seen.values().sum();
    let offset_before = sink.durable_len();

    // ---- The window the observer never sees inside. ----
    // Write enough to fill and SEAL a segment, then roll onto the next one.
    let mut appended: u64 = 0;
    for i in 0..40u8 {
        let rec = record(i, 512);
        sink.append(&rec);
        sink.sync().expect("sync");
        appended += rec.len() as u64;
    }
    // ...and reclaim the sealed segments, deleting the files before the observer can look again.
    sink.reclaim(HEADER.len() as u64, sink.durable_len())
        .expect("reclaim");

    // ---- POLL #2: the observer's "after" sample. The reclaimed segments are GONE. ----
    poll(dir.path(), &mut seen);
    let reconstruction_after: u64 = seen.values().sum();
    let offset_after = sink.durable_len();

    // The engine's answer: EXACT (ground truth is what the test appended).
    let truth = appended;
    assert_eq!(
        offset_after - offset_before,
        truth,
        "the durable byte offset delta must equal the bytes the window actually wrote"
    );

    // The observer's answer: SHORT — by an entire reclaimed segment it never once observed.
    let reconstructed = reconstruction_after - reconstruction_before;
    assert!(
        reconstructed < truth,
        "THE BUG (this assertion IS the finding): a poll-based reconstruction must UNDER-count when a \
         segment is created, sealed and reclaimed between two polls. It reported {reconstructed} \
         bytes; the window really wrote {truth}. If this ever fails, the reconstruction stopped being \
         broken and this test's premise must be re-derived."
    );

    // The under-count is not a rounding error — it is a whole segment's worth of bytes.
    let missed = truth - reconstructed;
    assert!(
        missed >= SEGMENT_TARGET,
        "the miss must be at least one whole segment ({SEGMENT_TARGET} bytes), was {missed}"
    );
    assert_eq!(
        offset_after,
        base + appended,
        "meanwhile the offset counted every byte, reclaimed or not"
    );
}
