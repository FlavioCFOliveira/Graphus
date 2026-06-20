//! Storage metering + throughput/latency collectors for example runs (`rmp #247`).
//!
//! This module fills the [`StorageSection`](crate::StorageSection) and
//! [`ThroughputSection`](crate::ThroughputSection) seams that the `rmp #245` scaffold stubbed (with
//! the CPU/memory seams filled by `rmp #246`). It provides three cooperating pieces:
//!
//! - [`StorageMeter`] — measures the **real on-disk footprint** of a store directory (and,
//!   separately, the WAL) by recursively summing file sizes via `std::fs`, reports the equivalent
//!   **page counts** (bytes / [`PAGE_SIZE`]), and computes the two classic storage-engine ratios —
//!   **write amplification** and **space amplification** — from caller-supplied logical figures.
//! - [`LatencyCollector`] — an exact, sorted-sample latency recorder: it stores one nanosecond
//!   duration per operation and yields nearest-rank **p50 / p99 / p999** percentiles. For examples,
//!   an exact sorted sample is preferable to an approximate histogram (no `hdrhistogram` dependency)
//!   and is trivially deterministic.
//! - [`ThroughputCounter`] — counts operations over a measured wall-clock window and derives
//!   ops/sec. The window may be measured live (`start`/`stop`) or **injected** for deterministic
//!   tests via [`ThroughputCounter::ops_per_sec_over`].
//!
//! These are wired into the report through [`EvidenceCollector::record_storage`] and
//! [`EvidenceCollector::record_throughput`].
//!
//! [`EvidenceCollector::record_storage`]: crate::EvidenceCollector::record_storage
//! [`EvidenceCollector::record_throughput`]: crate::EvidenceCollector::record_throughput

use std::io;
use std::path::Path;
use std::time::{Duration, Instant};

use crate::{StorageSection, ThroughputSection};

/// On-disk page size, in bytes.
///
/// This mirrors `graphus_io::PAGE_SIZE` (itself `graphus_core::constants::LOGICAL_PAGE_SIZE`), the
/// canonical source of truth for Graphus's fixed page size. It is duplicated here as a plain `const`
/// rather than via a dependency on `graphus-io`, deliberately: this is a dev-only leaf crate whose
/// `Cargo.toml` mandates a lean dependency surface, and `graphus-io` pulls in Tokio — far too heavy
/// to acquire a single, stable constant. The value is power-of-two and has been fixed at 8192 since
/// the storage engine's inception. If `LOGICAL_PAGE_SIZE` ever changes, update this constant too.
pub const PAGE_SIZE: u64 = 8192;

// ---------------------------------------------------------------------------------------------
// Storage metering
// ---------------------------------------------------------------------------------------------

/// A measured on-disk footprint: total bytes and the equivalent whole-page count.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DiskFootprint {
    /// Total on-disk size, in bytes (sum of every regular file's length, recursively).
    pub bytes: u64,
    /// Equivalent page count, rounded **up** (`ceil(bytes / PAGE_SIZE)`): a partially-filled final
    /// page still occupies a whole page on a page-oriented store.
    pub pages: u64,
}

impl DiskFootprint {
    /// Builds a footprint from a raw byte total, deriving the (ceil-rounded) page count.
    #[must_use]
    pub fn from_bytes(bytes: u64) -> Self {
        // ceil(bytes / PAGE_SIZE) without overflow: (bytes + PAGE_SIZE - 1) / PAGE_SIZE is safe
        // because PAGE_SIZE is tiny relative to u64::MAX.
        let pages = bytes.div_ceil(PAGE_SIZE);
        Self { bytes, pages }
    }
}

/// Measures the on-disk footprint of a store directory and its WAL, and derives the standard
/// storage-engine amplification ratios.
///
/// The meter is a thin, side-effect-free wrapper over `std::fs` directory walking; it never opens
/// the store for writing and is safe to call against a *live* example store between phases (it reads
/// file sizes only). Pointing at the store and WAL **paths** lets an example separate the data-store
/// footprint from the log footprint precisely, rather than guessing by filename pattern.
///
/// # Examples
///
/// ```
/// use graphus_examples_harness::metrics::StorageMeter;
///
/// # fn main() -> std::io::Result<()> {
/// let dir = std::env::temp_dir().join("storage-meter-doctest");
/// std::fs::create_dir_all(&dir)?;
/// std::fs::write(dir.join("data.gph"), vec![0u8; 16_384])?;
///
/// let store = StorageMeter::measure_path(&dir)?;
/// assert_eq!(store.bytes, 16_384);
/// assert_eq!(store.pages, 2); // 16_384 / 8192
///
/// // write amplification = physical bytes written / logical bytes written
/// assert_eq!(StorageMeter::write_amplification(16_384, 8_192), 2.0);
/// // space amplification = on-disk bytes / logical graph size
/// assert_eq!(StorageMeter::space_amplification(16_384, 4_096), 4.0);
/// # std::fs::remove_dir_all(&dir).ok();
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone, Default)]
pub struct StorageMeter;

impl StorageMeter {
    /// Recursively sums the size of every regular file under `path`, returning the
    /// [`DiskFootprint`].
    ///
    /// If `path` is a single regular file, its length is returned directly. Symlinks are **not**
    /// followed (their own small entry size is what `symlink_metadata` reports), preventing both
    /// double-counting and cycles. A non-existent `path` is reported as a zero footprint — an
    /// example may legitimately ask for a WAL that has not been created yet.
    ///
    /// # Errors
    ///
    /// Propagates any I/O error encountered while reading directory entries or file metadata (other
    /// than a top-level "not found", which is treated as an empty footprint).
    pub fn measure_path(path: impl AsRef<Path>) -> io::Result<DiskFootprint> {
        let path = path.as_ref();
        match dir_size_bytes(path) {
            Ok(bytes) => Ok(DiskFootprint::from_bytes(bytes)),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(DiskFootprint::default()),
            Err(e) => Err(e),
        }
    }

    /// Measures the store directory and WAL path together, returning `(store, wal)` footprints.
    ///
    /// Pass the example's known store directory and WAL path (file or directory — Graphus's WAL is a
    /// directory of segment files). Either may be missing; a missing path yields a zero footprint.
    ///
    /// # Errors
    ///
    /// Propagates any I/O error from walking either path (a top-level missing path is not an error).
    pub fn measure(
        store_path: impl AsRef<Path>,
        wal_path: impl AsRef<Path>,
    ) -> io::Result<(DiskFootprint, DiskFootprint)> {
        let store = Self::measure_path(store_path)?;
        let wal = Self::measure_path(wal_path)?;
        Ok((store, wal))
    }

    /// **Write amplification** = physical bytes written to disk / logical bytes written.
    ///
    /// A ratio of `1.0` is ideal (every logical byte hit disk exactly once); `> 1.0` quantifies the
    /// extra I/O a durability scheme (WAL + double-write + page padding + …) incurs. Returns `0.0`
    /// when `logical_bytes_written == 0` (no work to amplify) to avoid a division by zero.
    #[must_use]
    pub fn write_amplification(physical_bytes_written: u64, logical_bytes_written: u64) -> f64 {
        if logical_bytes_written == 0 {
            return 0.0;
        }
        physical_bytes_written as f64 / logical_bytes_written as f64
    }

    /// **Space amplification** = total on-disk bytes / logical graph size.
    ///
    /// A ratio of `1.0` means the on-disk representation is exactly the logical data size; `> 1.0`
    /// captures fixed-record padding, free-list slack, index overhead, and retained WAL. Returns
    /// `0.0` when `logical_graph_bytes == 0` to avoid a division by zero.
    #[must_use]
    pub fn space_amplification(on_disk_bytes: u64, logical_graph_bytes: u64) -> f64 {
        if logical_graph_bytes == 0 {
            return 0.0;
        }
        on_disk_bytes as f64 / logical_graph_bytes as f64
    }
}

/// Recursively sums the byte size of every regular file at (or under) `path`.
///
/// Uses an explicit stack rather than recursion so a deep store tree cannot overflow the call stack.
fn dir_size_bytes(path: &Path) -> io::Result<u64> {
    let meta = std::fs::symlink_metadata(path)?;
    if meta.is_file() {
        return Ok(meta.len());
    }
    if !meta.is_dir() {
        // Symlink or special file at the top level: count nothing (it holds no store data).
        return Ok(0);
    }

    let mut total: u64 = 0;
    let mut stack: Vec<std::path::PathBuf> = vec![path.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir)? {
            let entry = entry?;
            // symlink_metadata: do not follow symlinks (avoid cycles / double-counting).
            let m = entry.metadata()?;
            if m.is_dir() {
                stack.push(entry.path());
            } else if m.is_file() {
                total = total.saturating_add(m.len());
            }
            // Symlinks and special files contribute no store bytes.
        }
    }
    Ok(total)
}

// ---------------------------------------------------------------------------------------------
// Latency collector
// ---------------------------------------------------------------------------------------------

/// An exact, sorted-sample per-operation latency recorder.
///
/// Records one nanosecond duration per operation and yields nearest-rank **p50 / p99 / p999**
/// percentiles over the full sample. Holding the raw sample (a `Vec<u128>`) makes the percentiles
/// *exact* and *deterministic* — the right trade-off for example evidence, where samples are modest
/// and reproducibility matters more than the constant-memory footprint of an approximate histogram.
///
/// # Examples
///
/// ```
/// use std::time::Duration;
/// use graphus_examples_harness::metrics::LatencyCollector;
///
/// let mut lat = LatencyCollector::new();
/// for ms in 1..=100 {
///     lat.record(Duration::from_millis(ms));
/// }
/// let (p50, p99, p999) = lat.percentiles();
/// assert_eq!(lat.count(), 100);
/// // nearest-rank p50: round(0.5 * 99) = 50 (0-based index) -> 51ms.
/// assert_eq!(p50, Duration::from_millis(51));
/// // nearest-rank p99: round(0.99 * 99) = 98 -> 99ms.
/// assert_eq!(p99, Duration::from_millis(99));
/// let _ = p999;
/// ```
#[derive(Debug, Clone, Default)]
pub struct LatencyCollector {
    /// Per-operation latencies, in nanoseconds. Sorted lazily inside [`percentiles`](Self::percentiles).
    nanos: Vec<u128>,
}

impl LatencyCollector {
    /// Creates an empty collector.
    #[must_use]
    pub fn new() -> Self {
        Self { nanos: Vec::new() }
    }

    /// Creates a collector pre-sized for `capacity` samples (avoids reallocation in hot loops).
    #[must_use]
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            nanos: Vec::with_capacity(capacity),
        }
    }

    /// Records a single operation's latency.
    pub fn record(&mut self, latency: Duration) {
        self.nanos.push(latency.as_nanos());
    }

    /// The number of recorded samples.
    #[must_use]
    pub fn count(&self) -> usize {
        self.nanos.len()
    }

    /// Returns `true` if no samples have been recorded.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.nanos.is_empty()
    }

    /// Computes the nearest-rank **p50 / p99 / p999** latencies over the recorded sample.
    ///
    /// Sorts a working copy of the sample (so the collector stays usable afterwards) and applies the
    /// nearest-rank rule. An empty collector yields three zero durations.
    #[must_use]
    pub fn percentiles(&self) -> (Duration, Duration, Duration) {
        if self.nanos.is_empty() {
            return (Duration::ZERO, Duration::ZERO, Duration::ZERO);
        }
        let mut sorted = self.nanos.clone();
        sorted.sort_unstable();
        let p50 = nanos_to_duration(percentile(&sorted, 0.50));
        let p99 = nanos_to_duration(percentile(&sorted, 0.99));
        let p999 = nanos_to_duration(percentile(&sorted, 0.999));
        (p50, p99, p999)
    }
}

/// The percentile `p` (`0.0..=1.0`) of an already-sorted nanosecond slice (nearest-rank).
///
/// This mirrors `graphus_bench::ldbc::percentile` byte-for-byte (same nearest-rank formula:
/// `rank = round(p * (n - 1))`). It is re-implemented here rather than depended upon because
/// `graphus-bench` is a heavy crate (it pulls in `graphus-cypher` and the rest of the query stack),
/// and acquiring a six-line helper does not justify dragging that whole graph into this lean,
/// dev-only harness — nor risking the dependency weight. The algorithms are kept deliberately
/// identical so example latency figures are comparable with `graphus-bench`'s LDBC report.
#[must_use]
fn percentile(sorted_nanos: &[u128], p: f64) -> u128 {
    if sorted_nanos.is_empty() {
        return 0;
    }
    let rank = (p * (sorted_nanos.len() - 1) as f64).round() as usize;
    sorted_nanos[rank.min(sorted_nanos.len() - 1)]
}

/// Converts a nanosecond count into a [`Duration`], saturating at [`u64::MAX`] nanoseconds (~584
/// years — unreachable for any real per-operation latency).
fn nanos_to_duration(nanos: u128) -> Duration {
    Duration::from_nanos(nanos.min(u128::from(u64::MAX)) as u64)
}

// ---------------------------------------------------------------------------------------------
// Throughput counter
// ---------------------------------------------------------------------------------------------

/// Counts operations over a measured wall-clock window and derives ops/sec.
///
/// Typical use brackets the workload: [`start`](Self::start), call [`op`](Self::op) (or
/// [`add`](Self::add)) per operation, [`stop`](Self::stop), then read [`ops_per_sec`](Self::ops_per_sec).
/// For deterministic tests the window can be **injected** with
/// [`ops_per_sec_over`](Self::ops_per_sec_over), bypassing the wall clock entirely.
///
/// # Examples
///
/// ```
/// use std::time::Duration;
/// use graphus_examples_harness::metrics::ThroughputCounter;
///
/// let mut tp = ThroughputCounter::new();
/// for _ in 0..1_000 {
///     tp.op();
/// }
/// // Deterministic: 1000 ops over an injected 2-second window => 500 ops/sec.
/// assert_eq!(tp.count(), 1_000);
/// assert_eq!(tp.ops_per_sec_over(Duration::from_secs(2)), 500.0);
/// ```
#[derive(Debug, Clone)]
pub struct ThroughputCounter {
    operations: u64,
    started: Option<Instant>,
    elapsed: Option<Duration>,
}

impl Default for ThroughputCounter {
    fn default() -> Self {
        Self::new()
    }
}

impl ThroughputCounter {
    /// Creates a counter with zero operations and no measured window.
    #[must_use]
    pub fn new() -> Self {
        Self {
            operations: 0,
            started: None,
            elapsed: None,
        }
    }

    /// Marks the start of the measurement window (records the wall-clock origin).
    ///
    /// Calling it again restarts the window; the operation count is **not** reset (call
    /// [`new`](Self::new) for a fresh counter).
    pub fn start(&mut self) {
        self.started = Some(Instant::now());
        self.elapsed = None;
    }

    /// Records one operation.
    pub fn op(&mut self) {
        self.operations += 1;
    }

    /// Records `n` operations at once (e.g. a batch).
    pub fn add(&mut self, n: u64) {
        self.operations += n;
    }

    /// Closes the measurement window, freezing the elapsed wall-clock time.
    ///
    /// Has no effect if [`start`](Self::start) was never called.
    pub fn stop(&mut self) {
        if let Some(t0) = self.started {
            self.elapsed = Some(t0.elapsed());
        }
    }

    /// The total number of recorded operations.
    #[must_use]
    pub fn count(&self) -> u64 {
        self.operations
    }

    /// The measured window duration: the frozen value after [`stop`](Self::stop), else the live
    /// elapsed since [`start`](Self::start), else `Duration::ZERO`.
    #[must_use]
    pub fn elapsed(&self) -> Duration {
        self.elapsed
            .or_else(|| self.started.map(|t0| t0.elapsed()))
            .unwrap_or(Duration::ZERO)
    }

    /// Throughput in operations per second over the measured window.
    ///
    /// Returns `0.0` if the window is zero-length (avoids a division by zero / `inf`).
    #[must_use]
    pub fn ops_per_sec(&self) -> f64 {
        self.ops_per_sec_over(self.elapsed())
    }

    /// Throughput in operations per second over an **injected** `window` — the deterministic path.
    ///
    /// Returns `0.0` for a zero-length window.
    #[must_use]
    pub fn ops_per_sec_over(&self, window: Duration) -> f64 {
        let secs = window.as_secs_f64();
        if secs <= 0.0 {
            return 0.0;
        }
        self.operations as f64 / secs
    }
}

// ---------------------------------------------------------------------------------------------
// Section assembly
// ---------------------------------------------------------------------------------------------

impl StorageSection {
    /// Builds a [`StorageSection`] from measured store/WAL footprints and a `bytes_fsynced` figure.
    ///
    /// `bytes_fsynced` is what the example honestly observed to have been forced to durable media. If
    /// the example cannot instrument fsync directly, the WAL byte count is the most faithful proxy
    /// (every committed WAL byte is fsynced before acknowledgement) — see
    /// [`EvidenceCollector::record_storage`](crate::EvidenceCollector::record_storage), which defaults
    /// it to exactly that.
    #[must_use]
    pub fn from_footprints(store: DiskFootprint, wal: DiskFootprint, bytes_fsynced: u64) -> Self {
        Self {
            store_bytes: store.bytes,
            wal_bytes: wal.bytes,
            bytes_fsynced,
        }
    }
}

impl ThroughputSection {
    /// Builds a [`ThroughputSection`] from a throughput counter and a latency collector.
    ///
    /// Percentiles are emitted in **milliseconds** to match the section's field units.
    #[must_use]
    pub fn from_collectors(throughput: &ThroughputCounter, latency: &LatencyCollector) -> Self {
        let (p50, p99, p999) = latency.percentiles();
        Self {
            operations: throughput.count(),
            ops_per_sec: throughput.ops_per_sec(),
            p50_latency_ms: duration_to_millis(p50),
            p99_latency_ms: duration_to_millis(p99),
            p999_latency_ms: duration_to_millis(p999),
        }
    }

    /// Like [`from_collectors`](Self::from_collectors) but with an **injected** throughput window,
    /// for deterministic tests/scenarios.
    #[must_use]
    pub fn from_collectors_over(
        throughput: &ThroughputCounter,
        latency: &LatencyCollector,
        window: Duration,
    ) -> Self {
        let (p50, p99, p999) = latency.percentiles();
        Self {
            operations: throughput.count(),
            ops_per_sec: throughput.ops_per_sec_over(window),
            p50_latency_ms: duration_to_millis(p50),
            p99_latency_ms: duration_to_millis(p99),
            p999_latency_ms: duration_to_millis(p999),
        }
    }
}

/// Converts a [`Duration`] to fractional milliseconds.
fn duration_to_millis(d: Duration) -> f64 {
    d.as_secs_f64() * 1_000.0
}

#[cfg(test)]
mod tests {
    use super::*;

    // -- Storage metering -------------------------------------------------------------------

    #[test]
    fn storage_meter_reports_real_directory_size_and_pages() {
        let dir =
            std::env::temp_dir().join(format!("graphus-metrics-store-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let sub = dir.join("nested");
        std::fs::create_dir_all(&sub).unwrap();

        // Known-size files: 8192 + 4096 + 100 = 12_388 bytes across two directory levels.
        std::fs::write(dir.join("a.gph"), vec![0u8; 8_192]).unwrap();
        std::fs::write(dir.join("b.gph"), vec![0u8; 4_096]).unwrap();
        std::fs::write(sub.join("c.gph"), vec![0u8; 100]).unwrap();

        let fp = StorageMeter::measure_path(&dir).unwrap();
        assert_eq!(fp.bytes, 12_388, "measured bytes must equal the exact sum");
        // ceil(12_388 / 8_192) = 2.
        assert_eq!(fp.pages, 2);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn storage_meter_missing_path_is_zero() {
        let missing = std::env::temp_dir().join("graphus-metrics-does-not-exist-xyz");
        let _ = std::fs::remove_dir_all(&missing);
        let fp = StorageMeter::measure_path(&missing).unwrap();
        assert_eq!(fp, DiskFootprint::default());
    }

    #[test]
    fn storage_meter_single_file() {
        let dir = std::env::temp_dir().join(format!("graphus-metrics-file-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let f = dir.join("solo.wal");
        std::fs::write(&f, vec![0u8; 8_193]).unwrap();

        let fp = StorageMeter::measure_path(&f).unwrap();
        assert_eq!(fp.bytes, 8_193);
        assert_eq!(fp.pages, 2); // ceil(8_193 / 8_192)

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn amplification_ratios_are_correct() {
        // write amp: 24 KiB physical for 8 KiB logical => 3.0
        assert_eq!(StorageMeter::write_amplification(24_576, 8_192), 3.0);
        // space amp: 16 KiB on disk for 4 KiB logical => 4.0
        assert_eq!(StorageMeter::space_amplification(16_384, 4_096), 4.0);
        // zero logical => 0.0 (no division by zero)
        assert_eq!(StorageMeter::write_amplification(100, 0), 0.0);
        assert_eq!(StorageMeter::space_amplification(100, 0), 0.0);
    }

    #[test]
    fn footprint_page_rounding_is_ceil() {
        assert_eq!(DiskFootprint::from_bytes(0).pages, 0);
        assert_eq!(DiskFootprint::from_bytes(1).pages, 1);
        assert_eq!(DiskFootprint::from_bytes(8_192).pages, 1);
        assert_eq!(DiskFootprint::from_bytes(8_193).pages, 2);
        assert_eq!(DiskFootprint::from_bytes(16_384).pages, 2);
    }

    // -- Latency collector ------------------------------------------------------------------

    #[test]
    fn latency_percentiles_on_known_sample() {
        // Record 1..=1000 nanoseconds. With nearest-rank rank = round(p * (n-1)):
        //   p50  -> round(0.50 * 999) = round(499.5) = 500 -> value index 500 -> 501ns
        //   p99  -> round(0.99 * 999) = round(989.01) = 989 -> value index 989 -> 990ns
        //   p999 -> round(0.999 * 999) = round(998.001) = 998 -> value index 998 -> 999ns
        let mut lat = LatencyCollector::new();
        for n in 1..=1_000u64 {
            lat.record(Duration::from_nanos(n));
        }
        assert_eq!(lat.count(), 1_000);
        let (p50, p99, p999) = lat.percentiles();
        assert_eq!(p50, Duration::from_nanos(501));
        assert_eq!(p99, Duration::from_nanos(990));
        assert_eq!(p999, Duration::from_nanos(999));
    }

    #[test]
    fn latency_empty_yields_zero() {
        let lat = LatencyCollector::new();
        assert!(lat.is_empty());
        assert_eq!(
            lat.percentiles(),
            (Duration::ZERO, Duration::ZERO, Duration::ZERO)
        );
    }

    #[test]
    fn latency_percentiles_do_not_consume_sample() {
        let mut lat = LatencyCollector::with_capacity(3);
        lat.record(Duration::from_nanos(10));
        lat.record(Duration::from_nanos(30));
        lat.record(Duration::from_nanos(20));
        let _ = lat.percentiles();
        // Still usable: a second call must reproduce the same result (sample not drained/sorted away).
        let (p50, _, _) = lat.percentiles();
        assert_eq!(lat.count(), 3);
        // nearest-rank p50 over [10,20,30] sorted: rank = round(0.5 * 2) = 1 -> 20ns
        assert_eq!(p50, Duration::from_nanos(20));
    }

    // -- Throughput counter -----------------------------------------------------------------

    #[test]
    fn throughput_matches_known_count_over_injected_window() {
        let mut tp = ThroughputCounter::new();
        tp.add(2_000);
        tp.op();
        tp.op();
        assert_eq!(tp.count(), 2_002);
        // Deterministic: 2002 ops over a 4-second injected window => 500.5 ops/sec.
        assert_eq!(tp.ops_per_sec_over(Duration::from_secs(4)), 500.5);
        // Zero-length window => 0.0, never inf/NaN.
        assert_eq!(tp.ops_per_sec_over(Duration::ZERO), 0.0);
    }

    #[test]
    fn throughput_live_window_is_within_tolerance() {
        let mut tp = ThroughputCounter::new();
        tp.start();
        for _ in 0..1_000 {
            tp.op();
        }
        std::thread::sleep(Duration::from_millis(20));
        tp.stop();
        let rate = tp.ops_per_sec();
        // 1000 ops over ~>=20ms => well under 50_000 ops/sec, and strictly positive.
        assert!(rate > 0.0, "rate must be positive, got {rate}");
        assert!(
            rate <= 1_000.0 / 0.018,
            "rate must respect the measured floor of the sleep, got {rate}"
        );
    }

    // -- Section assembly -------------------------------------------------------------------

    #[test]
    fn throughput_section_carries_p999_in_millis() {
        let mut lat = LatencyCollector::new();
        for ms in 1..=100u64 {
            lat.record(Duration::from_millis(ms));
        }
        let mut tp = ThroughputCounter::new();
        tp.add(100);

        let section = ThroughputSection::from_collectors_over(&tp, &lat, Duration::from_secs(1));
        assert_eq!(section.operations, 100);
        assert_eq!(section.ops_per_sec, 100.0);
        // p50 over 1..=100 ms: rank = round(0.5*99) = 50 (0-based) -> 51ms.
        assert!((section.p50_latency_ms - 51.0).abs() < 1e-9);
        // p999 over 1..=100 ms: rank = round(0.999*99) = round(98.901) = 99 -> 100ms.
        assert!((section.p999_latency_ms - 100.0).abs() < 1e-9);
    }

    #[test]
    fn storage_section_from_footprints() {
        let store = DiskFootprint::from_bytes(20_000);
        let wal = DiskFootprint::from_bytes(5_000);
        let section = StorageSection::from_footprints(store, wal, wal.bytes);
        assert_eq!(section.store_bytes, 20_000);
        assert_eq!(section.wal_bytes, 5_000);
        assert_eq!(section.bytes_fsynced, 5_000);
    }
}
