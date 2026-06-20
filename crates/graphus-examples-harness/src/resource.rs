//! CPU and memory metering for example runs (`rmp #246`).
//!
//! This module fills the [`crate::CpuSection`] and [`crate::MemorySection`]
//! seams that the `rmp #245` scaffold stubbed. It provides two cooperating pieces:
//!
//! - [`CpuMeter`] — brackets a workload and reports the **user** and **system** CPU seconds consumed
//!   during it, plus a derived `mean_core_utilisation` (`cpu_secs / wall_secs`). It can measure
//!   either the *current* (client/driver) process via `getrusage(RUSAGE_SELF, ..)` or a *monitored
//!   separate server process* by PID via `/proc/<pid>/stat` (Linux) / `ps` (macOS).
//! - [`RssSampler`] — captures a peak RSS, a final RSS, and an RSS **time series**
//!   (`Vec<(elapsed, rss_bytes)>`) for either the current process (peak via `getrusage`'s
//!   `ru_maxrss`, current via `/proc/self/statm`) or a monitored server PID. Its sampling **cadence
//!   is injectable**: callers may either drive it manually with [`RssSampler::sample_now`] (the
//!   deterministic / DST-friendly path) or let it self-pace against a wall clock — there is *no*
//!   hard-wired background timer thread.
//!
//! ## Platform notes
//!
//! - **`ru_maxrss` unit differs by OS.** On **Linux** it is **kilobytes**; on **macOS/BSD** it is
//!   **bytes**. [`peak_rss_self_bytes`] normalises both to bytes (see
//!   <https://man7.org/linux/man-pages/man2/getrusage.2.html> and the Darwin `getrusage(2)` man page).
//! - **Monitored-PID CPU** on Linux comes from fields 14 (`utime`) and 15 (`stime`) of
//!   `/proc/<pid>/stat`, expressed in clock ticks; we divide by `sysconf(_SC_CLK_TCK)` to get
//!   seconds. On macOS there is no `/proc`, so we shell out to `ps -o utime=,stime= -p <pid>`
//!   (documented fallback) and parse the `[[dd-]hh:]mm:ss[.frac]` columns.
//! - **Monitored-PID RSS** on Linux is the resident field of `/proc/<pid>/statm` (in pages)
//!   multiplied by `sysconf(_SC_PAGESIZE)`. On macOS we read `ps -o rss= -p <pid>` (KiB).
//!
//! All FFI is confined to small, single-syscall helpers, each with a `// SAFETY:` rationale. Reading
//! `/proc` and running `ps` are ordinary safe I/O.

#![allow(unsafe_code)]

use std::time::{Duration, Instant};

use crate::{CpuSection, MemorySection};

/// Identifies which process a meter observes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Target {
    /// The current (client / driver / test) process — measured via `getrusage(RUSAGE_SELF, ..)`.
    SelfProcess,
    /// A separate, monitored server process identified by its OS PID — measured via `/proc` (Linux)
    /// or `ps` (macOS).
    Pid(u32),
}

/// A snapshot of consumed CPU time, split into user-mode and kernel-mode seconds.
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub struct CpuTimes {
    /// User-mode CPU seconds.
    pub user_secs: f64,
    /// Kernel-mode CPU seconds.
    pub system_secs: f64,
}

impl CpuTimes {
    /// Total CPU seconds (user + system).
    #[must_use]
    pub fn total_secs(self) -> f64 {
        self.user_secs + self.system_secs
    }

    /// Difference `self - earlier`, clamped to be non-negative per component (CPU counters are
    /// monotonic, but a PID-reparse race or integer rounding could otherwise yield a tiny negative).
    #[must_use]
    fn saturating_sub(self, earlier: CpuTimes) -> CpuTimes {
        CpuTimes {
            user_secs: (self.user_secs - earlier.user_secs).max(0.0),
            system_secs: (self.system_secs - earlier.system_secs).max(0.0),
        }
    }
}

/// Brackets a workload and reports the CPU it consumed.
///
/// Construct with [`CpuMeter::start`] (which snapshots the baseline immediately), run the workload,
/// then call [`CpuMeter::measure`] (repeatable) or [`CpuMeter::stop`] (consuming) to read the CPU
/// consumed *since `start`*. Wall-clock elapsed is tracked alongside so `mean_core_utilisation` can
/// be derived.
#[derive(Debug, Clone)]
pub struct CpuMeter {
    target: Target,
    baseline: CpuTimes,
    started_at: Instant,
}

impl CpuMeter {
    /// Starts metering `target`, snapshotting its current CPU counters as the baseline.
    ///
    /// On any platform where the counters cannot be read (e.g. the PID has already exited, or an
    /// unsupported OS), the baseline is taken as zero; subsequent measurements then report the
    /// absolute counter value, which is still meaningful.
    #[must_use]
    pub fn start(target: Target) -> Self {
        Self {
            target,
            baseline: read_cpu_times(target).unwrap_or_default(),
            started_at: Instant::now(),
        }
    }

    /// CPU consumed since [`start`](Self::start), as `(times, wall_elapsed)`.
    ///
    /// Repeatable: calling it twice yields monotonically non-decreasing totals (the underlying OS
    /// counters never decrease).
    #[must_use]
    pub fn measure(&self) -> (CpuTimes, Duration) {
        let now = read_cpu_times(self.target).unwrap_or(self.baseline);
        (now.saturating_sub(self.baseline), self.started_at.elapsed())
    }

    /// Consuming variant of [`measure`](Self::measure).
    #[must_use]
    pub fn stop(self) -> (CpuTimes, Duration) {
        self.measure()
    }

    /// Convenience: builds a [`CpuSection`] from a measurement, deriving `mean_core_utilisation` as
    /// `total_cpu_secs / wall_secs` (`0.0` if no wall time elapsed).
    #[must_use]
    pub fn to_section(&self) -> CpuSection {
        let (times, wall) = self.measure();
        cpu_section(times, wall)
    }
}

/// Reads the **cumulative** CPU time consumed by `target` since it started, or `None` if it cannot
/// be read on this platform / for this PID.
///
/// Unlike [`CpuMeter`], which reports CPU consumed *within a bracketed window*, this is the raw
/// absolute counter. It is the right primitive when the monitored process is **dedicated to the
/// workload for its whole lifetime** (e.g. an example's purpose-booted server): its since-boot CPU
/// *is* the workload's CPU, so a single absolute read — paired with the process's wall-clock uptime —
/// yields the run's CPU evidence without bracketing.
#[must_use]
pub fn cumulative_cpu_times(target: Target) -> Option<CpuTimes> {
    read_cpu_times(target)
}

/// Reads the current resident-set size of `target` in bytes, or `None` if unavailable.
///
/// A single instantaneous read (no bracketing), suitable for sampling a monitored server PID's RSS
/// at a chosen instant (e.g. at the end of a workload phase).
#[must_use]
pub fn current_rss_bytes(target: Target) -> Option<u64> {
    read_rss_bytes(target)
}

/// Builds a [`CpuSection`] from CPU times and the wall-clock window they were consumed over.
#[must_use]
pub fn cpu_section(times: CpuTimes, wall: Duration) -> CpuSection {
    let wall_secs = wall.as_secs_f64();
    let mean = if wall_secs > 0.0 {
        times.total_secs() / wall_secs
    } else {
        0.0
    };
    CpuSection {
        user_secs: times.user_secs,
        system_secs: times.system_secs,
        mean_core_utilisation: mean,
    }
}

/// A single observation in an RSS time series: wall-clock offset from the sampler's start, and the
/// resident set size in bytes at that instant.
#[derive(Debug, Clone, Copy, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct RssSample {
    /// Seconds elapsed since [`RssSampler::start`].
    pub elapsed_secs: f64,
    /// Resident set size in bytes at the sample instant.
    pub rss_bytes: u64,
}

/// Samples resident-set size over time, tracking a peak, a final value, and a full time series.
///
/// ## Injectable cadence (DST-friendly)
///
/// The sampler does **not** spawn a background timer. Instead:
///
/// - **Manual / deterministic:** call [`sample_now`](Self::sample_now) at chosen points (e.g. driven
///   by a DST clock). The time series has exactly one point per call.
/// - **Self-paced:** call [`sample_if_due`](Self::sample_if_due) in a loop; it records a sample only
///   when at least `min_interval` of wall time has elapsed since the previous one, so the caller
///   controls the loop while the sampler enforces a minimum cadence.
///
/// Either way, sampling is an explicit caller action, which keeps deterministic scenarios fully in
/// control of *when* memory is observed.
#[derive(Debug, Clone)]
pub struct RssSampler {
    target: Target,
    started_at: Instant,
    min_interval: Duration,
    last_sample_at: Option<Instant>,
    peak_bytes: u64,
    samples: Vec<RssSample>,
}

impl RssSampler {
    /// Creates a sampler for `target` with a `min_interval` used only by the self-paced
    /// [`sample_if_due`](Self::sample_if_due) path. Pass [`Duration::ZERO`] if you only ever drive it
    /// manually via [`sample_now`](Self::sample_now).
    #[must_use]
    pub fn start(target: Target, min_interval: Duration) -> Self {
        Self {
            target,
            started_at: Instant::now(),
            min_interval,
            last_sample_at: None,
            peak_bytes: 0,
            samples: Vec::new(),
        }
    }

    /// Takes a sample **now**, unconditionally, appending it to the time series and updating the peak.
    ///
    /// This is the deterministic path: the caller decides exactly when each point is recorded. Returns
    /// the just-recorded RSS in bytes (`0` if it could not be read for the target).
    pub fn sample_now(&mut self) -> u64 {
        let rss = read_rss_bytes(self.target).unwrap_or(0);
        let elapsed_secs = self.started_at.elapsed().as_secs_f64();
        self.peak_bytes = self.peak_bytes.max(rss);
        self.last_sample_at = Some(Instant::now());
        self.samples.push(RssSample {
            elapsed_secs,
            rss_bytes: rss,
        });
        rss
    }

    /// Self-paced sample: records a point only if at least `min_interval` has elapsed since the last
    /// one (always records the first). Returns `Some(rss)` if a sample was taken, else `None`.
    pub fn sample_if_due(&mut self) -> Option<u64> {
        let due = match self.last_sample_at {
            None => true,
            Some(prev) => prev.elapsed() >= self.min_interval,
        };
        due.then(|| self.sample_now())
    }

    /// The peak RSS in bytes observed across all samples so far.
    #[must_use]
    pub fn peak_bytes(&self) -> u64 {
        self.peak_bytes
    }

    /// The most recently sampled RSS in bytes, or `0` if no sample has been taken.
    #[must_use]
    pub fn final_bytes(&self) -> u64 {
        self.samples.last().map_or(0, |s| s.rss_bytes)
    }

    /// The full RSS time series, in sampling order.
    #[must_use]
    pub fn samples(&self) -> &[RssSample] {
        &self.samples
    }

    /// Builds a [`MemorySection`] from the observations.
    ///
    /// For a [`Target::SelfProcess`] sampler the OS-reported peak (`getrusage`'s `ru_maxrss`) is
    /// authoritative and is folded in, so the peak reflects the high-water mark even between samples.
    #[must_use]
    pub fn to_section(&self) -> MemorySection {
        let mut peak = self.peak_bytes;
        if self.target == Target::SelfProcess {
            peak = peak.max(peak_rss_self_bytes().unwrap_or(0));
        }
        MemorySection {
            peak_rss_bytes: peak,
            final_rss_bytes: self.final_bytes(),
        }
    }
}

/// Brackets a workload and meters **both** CPU and RSS for a single [`Target`].
///
/// A thin convenience that pairs a [`CpuMeter`] with an [`RssSampler`] sharing the same start origin,
/// so an example can bracket its workload once and produce both a [`CpuSection`] and a
/// [`MemorySection`] for the evidence report. RSS sampling stays explicit (call
/// [`sample`](Self::sample) at chosen points); on [`finish`](Self::finish) a final sample is taken.
#[derive(Debug, Clone)]
pub struct ResourceMeter {
    cpu: CpuMeter,
    rss: RssSampler,
}

impl ResourceMeter {
    /// Starts metering `target`. `rss_min_interval` governs only the self-paced
    /// [`sample_if_due`](RssSampler::sample_if_due) path; pass [`Duration::ZERO`] for purely manual
    /// sampling. An initial RSS sample is taken immediately so the time series has a baseline point.
    #[must_use]
    pub fn start(target: Target, rss_min_interval: Duration) -> Self {
        let cpu = CpuMeter::start(target);
        let mut rss = RssSampler::start(target, rss_min_interval);
        rss.sample_now();
        Self { cpu, rss }
    }

    /// Takes an explicit RSS sample now (the deterministic path). Returns the sampled bytes.
    pub fn sample(&mut self) -> u64 {
        self.rss.sample_now()
    }

    /// Self-paced RSS sample; see [`RssSampler::sample_if_due`].
    pub fn sample_if_due(&mut self) -> Option<u64> {
        self.rss.sample_if_due()
    }

    /// Read-only access to the underlying RSS sampler (e.g. for the time series).
    #[must_use]
    pub fn rss(&self) -> &RssSampler {
        &self.rss
    }

    /// Takes a final RSS sample and returns the finished `(CpuSection, MemorySection)` pair.
    #[must_use]
    pub fn finish(mut self) -> (CpuSection, MemorySection) {
        self.rss.sample_now();
        let (times, wall) = self.cpu.measure();
        (cpu_section(times, wall), self.rss.to_section())
    }
}

// ---------------------------------------------------------------------------------------------
// Platform backends
// ---------------------------------------------------------------------------------------------

/// Reads consumed CPU times for `target`, or `None` if unavailable on this platform / for this PID.
fn read_cpu_times(target: Target) -> Option<CpuTimes> {
    match target {
        Target::SelfProcess => cpu_times_self(),
        Target::Pid(pid) => cpu_times_pid(pid),
    }
}

/// Reads current RSS (bytes) for `target`, or `None` if unavailable.
fn read_rss_bytes(target: Target) -> Option<u64> {
    match target {
        Target::SelfProcess => rss_self_bytes(),
        Target::Pid(pid) => rss_pid_bytes(pid),
    }
}

#[cfg(unix)]
fn cpu_times_self() -> Option<CpuTimes> {
    // SAFETY: `getrusage` writes a fully-initialised `rusage` into the provided out-pointer, which
    // points to local, properly-aligned, sufficiently-sized storage that outlives the call. We pass
    // the standard `RUSAGE_SELF` request and check the return code before reading the struct.
    let usage = unsafe {
        let mut usage = std::mem::MaybeUninit::<libc::rusage>::zeroed();
        if libc::getrusage(libc::RUSAGE_SELF, usage.as_mut_ptr()) != 0 {
            return None;
        }
        usage.assume_init()
    };
    Some(CpuTimes {
        user_secs: timeval_secs(usage.ru_utime),
        system_secs: timeval_secs(usage.ru_stime),
    })
}

#[cfg(not(unix))]
fn cpu_times_self() -> Option<CpuTimes> {
    None
}

/// Converts a `libc::timeval` to fractional seconds.
#[cfg(unix)]
fn timeval_secs(tv: libc::timeval) -> f64 {
    tv.tv_sec as f64 + (tv.tv_usec as f64) / 1_000_000.0
}

/// Peak RSS of the **current** process in bytes via `getrusage`'s `ru_maxrss`.
///
/// `ru_maxrss` is reported in **kilobytes on Linux** but in **bytes on macOS/BSD**; this normalises
/// both to bytes.
#[cfg(unix)]
#[must_use]
pub fn peak_rss_self_bytes() -> Option<u64> {
    // SAFETY: identical contract to `cpu_times_self` — `getrusage` initialises the out `rusage` and
    // we check its return value before reading.
    let usage = unsafe {
        let mut usage = std::mem::MaybeUninit::<libc::rusage>::zeroed();
        if libc::getrusage(libc::RUSAGE_SELF, usage.as_mut_ptr()) != 0 {
            return None;
        }
        usage.assume_init()
    };
    let maxrss = usage.ru_maxrss;
    if maxrss < 0 {
        return None;
    }
    let maxrss = maxrss as u64;
    #[cfg(target_os = "macos")]
    {
        Some(maxrss) // already bytes on Darwin
    }
    #[cfg(not(target_os = "macos"))]
    {
        Some(maxrss.saturating_mul(1024)) // kilobytes -> bytes on Linux
    }
}

#[cfg(not(unix))]
#[must_use]
pub fn peak_rss_self_bytes() -> Option<u64> {
    None
}

// ---- Linux backends (real /proc) -----------------------------------------------------------------

#[cfg(target_os = "linux")]
fn cpu_times_pid(pid: u32) -> Option<CpuTimes> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    // The comm field (field 2) is parenthesised and may contain spaces/parentheses; split off
    // everything up to and including the *last* ')' so the remaining fields are space-clean.
    let after_comm = &stat[stat.rfind(')')? + 1..];
    let fields: Vec<&str> = after_comm.split_whitespace().collect();
    // After the ')' the next token is field 3 (state). utime is field 14, stime is field 15, so
    // relative to `fields[0] == field 3` they sit at indices 11 and 12.
    let utime_ticks: u64 = fields.get(11)?.parse().ok()?;
    let stime_ticks: u64 = fields.get(12)?.parse().ok()?;
    let hz = clk_tck();
    Some(CpuTimes {
        user_secs: utime_ticks as f64 / hz,
        system_secs: stime_ticks as f64 / hz,
    })
}

#[cfg(target_os = "linux")]
fn rss_self_bytes() -> Option<u64> {
    rss_pid_bytes(std::process::id())
}

#[cfg(target_os = "linux")]
fn rss_pid_bytes(pid: u32) -> Option<u64> {
    // /proc/<pid>/statm: "size resident shared ..." in pages. We want the resident field (#2).
    let statm = std::fs::read_to_string(format!("/proc/{pid}/statm")).ok()?;
    let resident_pages: u64 = statm.split_whitespace().nth(1)?.parse().ok()?;
    Some(resident_pages.saturating_mul(page_size()))
}

/// `sysconf(_SC_CLK_TCK)` — clock ticks per second (Linux CPU-time accounting unit).
#[cfg(target_os = "linux")]
fn clk_tck() -> f64 {
    // SAFETY: `sysconf` takes an integer name and returns a `long`; no memory is shared. A negative
    // return (`-1`) means the value is indeterminate, in which case we fall back to the near-universal
    // default of 100 Hz.
    let hz = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
    if hz > 0 { hz as f64 } else { 100.0 }
}

/// `sysconf(_SC_PAGESIZE)` — bytes per memory page.
#[cfg(target_os = "linux")]
fn page_size() -> u64 {
    // SAFETY: as `clk_tck` — `sysconf` shares no memory; fall back to 4 KiB on an indeterminate value.
    let sz = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    if sz > 0 { sz as u64 } else { 4096 }
}

// ---- macOS backends (documented `ps` fallback) ---------------------------------------------------

#[cfg(target_os = "macos")]
fn cpu_times_pid(pid: u32) -> Option<CpuTimes> {
    // Documented fallback: `ps -o utime=,stime= -p <pid>` yields two `[[dd-]hh:]mm:ss[.frac]` columns
    // (cumulative user and system CPU). macOS has no `/proc`. The fields are headerless (`=`).
    let out = std::process::Command::new("ps")
        .args(["-o", "utime=", "-o", "stime=", "-p", &pid.to_string()])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&out.stdout);
    let mut cols = text.split_whitespace();
    let user = parse_ps_cpu(cols.next()?)?;
    let system = parse_ps_cpu(cols.next()?)?;
    Some(CpuTimes {
        user_secs: user,
        system_secs: system,
    })
}

/// Parses a `ps` CPU-time column of the form `[[dd-]hh:]mm:ss[.frac]` into seconds.
#[cfg(target_os = "macos")]
fn parse_ps_cpu(col: &str) -> Option<f64> {
    // Split optional leading "dd-".
    let (days, rest) = match col.split_once('-') {
        Some((d, r)) => (d.parse::<f64>().ok()?, r),
        None => (0.0, col),
    };
    // rest is "hh:mm:ss(.frac)" or "mm:ss(.frac)".
    let parts: Vec<&str> = rest.split(':').collect();
    let secs = match parts.as_slice() {
        [m, s] => m.parse::<f64>().ok()? * 60.0 + s.parse::<f64>().ok()?,
        [h, m, s] => {
            h.parse::<f64>().ok()? * 3600.0
                + m.parse::<f64>().ok()? * 60.0
                + s.parse::<f64>().ok()?
        }
        _ => return None,
    };
    Some(days * 86_400.0 + secs)
}

#[cfg(target_os = "macos")]
fn rss_self_bytes() -> Option<u64> {
    rss_pid_bytes(std::process::id())
}

#[cfg(target_os = "macos")]
fn rss_pid_bytes(pid: u32) -> Option<u64> {
    // `ps -o rss= -p <pid>` reports resident set size in KiB (headerless via `=`).
    let out = std::process::Command::new("ps")
        .args(["-o", "rss=", "-p", &pid.to_string()])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let kib: u64 = String::from_utf8_lossy(&out.stdout).trim().parse().ok()?;
    Some(kib.saturating_mul(1024))
}

// ---- Other Unix / non-Unix fallbacks -------------------------------------------------------------

#[cfg(all(unix, not(any(target_os = "linux", target_os = "macos"))))]
fn cpu_times_pid(_pid: u32) -> Option<CpuTimes> {
    None
}

#[cfg(all(unix, not(any(target_os = "linux", target_os = "macos"))))]
fn rss_self_bytes() -> Option<u64> {
    peak_rss_self_bytes() // best effort: no portable "current RSS" without OS-specific calls
}

#[cfg(all(unix, not(any(target_os = "linux", target_os = "macos"))))]
fn rss_pid_bytes(_pid: u32) -> Option<u64> {
    None
}

#[cfg(not(unix))]
fn cpu_times_pid(_pid: u32) -> Option<CpuTimes> {
    None
}

#[cfg(not(unix))]
fn rss_self_bytes() -> Option<u64> {
    None
}

#[cfg(not(unix))]
fn rss_pid_bytes(_pid: u32) -> Option<u64> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A KNOWN BUSY LOOP that the optimiser cannot elide, returning an accumulated value the caller
    /// black-boxes. `iters` controls how much user-mode CPU is burned.
    fn burn_cpu(iters: u64) -> u64 {
        let mut acc = 0u64;
        for i in 0..iters {
            acc = acc
                .wrapping_add(i)
                .wrapping_mul(2_654_435_761)
                .rotate_left(13);
        }
        acc
    }

    #[test]
    fn cpu_is_nontrivial_and_monotonic() {
        let meter = CpuMeter::start(Target::SelfProcess);

        // First window of work.
        std::hint::black_box(burn_cpu(20_000_000));
        let (first, _wall1) = meter.measure();

        // Some user CPU must have registered for a tight multi-ms loop.
        assert!(
            first.user_secs > 0.0,
            "expected non-trivial user CPU, got {first:?}"
        );

        // More work, then a second measurement that must be >= the first (monotonic counters).
        std::hint::black_box(burn_cpu(40_000_000));
        let (second, _wall2) = meter.measure();
        assert!(
            second.user_secs >= first.user_secs,
            "user CPU must be monotonic: first={first:?} second={second:?}"
        );
        assert!(second.total_secs() >= first.total_secs());

        // Derived utilisation is finite and non-negative.
        let section = cpu_section(second, _wall2);
        assert!(section.mean_core_utilisation >= 0.0);
        assert!(section.mean_core_utilisation.is_finite());
    }

    #[test]
    fn peak_rss_tracks_a_controlled_allocation() {
        let mut sampler = RssSampler::start(Target::SelfProcess, Duration::ZERO);
        let before = sampler.sample_now();

        // Allocate and TOUCH ~64 MiB so the pages are actually resident (not just reserved).
        const N: usize = 64 * 1024 * 1024;
        let mut big = vec![0u8; N];
        for chunk in big.chunks_mut(4096) {
            chunk[0] = 1; // fault in one byte per page
        }
        std::hint::black_box(&big);

        let after = sampler.sample_now();

        // Generous tolerance: expect at least half the allocation to show as a resident-set rise.
        // (`Target::SelfProcess` peak also folds in `ru_maxrss`, so check the sampler peak too.)
        let rose = after.saturating_sub(before);
        let peak = sampler.peak_bytes().max(after);
        assert!(
            rose >= (N as u64) / 2 || peak.saturating_sub(before) >= (N as u64) / 2,
            "expected RSS to rise by ~order of {N} bytes: before={before} after={after} peak={peak}"
        );

        drop(big);
        let section = sampler.to_section();
        assert!(section.peak_rss_bytes >= after);
        assert_eq!(section.final_rss_bytes, after);
    }

    #[test]
    fn reads_metrics_for_a_separate_child_pid() {
        // Spawn a tiny child that lives long enough to be observed. `sleep` exists on Linux + macOS.
        let mut child = std::process::Command::new("sleep")
            .arg("30")
            .spawn()
            .expect("spawn child sleeper");
        let pid = child.id();

        // RSS must be readable for the child PID on this platform.
        let rss = read_rss_bytes(Target::Pid(pid));
        assert!(
            rss.is_some_and(|b| b > 0),
            "expected to read child RSS for pid {pid}, got {rss:?}"
        );

        // CPU times must be readable (a sleeping process legitimately reports ~0 CPU; the point is
        // that the read SUCCEEDS for a separate PID on this platform).
        let cpu = read_cpu_times(Target::Pid(pid));
        assert!(
            cpu.is_some(),
            "expected to read child CPU times for pid {pid}, got {cpu:?}"
        );

        let _ = child.kill();
        let _ = child.wait();
    }

    #[test]
    fn sampling_cadence_is_injectable_via_manual_ticks() {
        // The manual-tick path: N explicit samples must yield exactly N time-series points, with no
        // reliance on a wall-clock timer thread.
        let mut sampler = RssSampler::start(Target::SelfProcess, Duration::ZERO);
        const N: usize = 5;
        for _ in 0..N {
            sampler.sample_now();
        }
        assert_eq!(
            sampler.samples().len(),
            N,
            "manual ticks must be 1:1 points"
        );

        // elapsed_secs is non-decreasing across the series.
        let series = sampler.samples();
        for w in series.windows(2) {
            assert!(w[1].elapsed_secs >= w[0].elapsed_secs);
        }

        // The self-paced path with a huge min_interval records only the first (the rest are not due).
        let mut paced = RssSampler::start(Target::SelfProcess, Duration::from_secs(3600));
        assert!(
            paced.sample_if_due().is_some(),
            "first sample is always due"
        );
        assert!(paced.sample_if_due().is_none(), "second is not yet due");
        assert_eq!(paced.samples().len(), 1);
    }
}
