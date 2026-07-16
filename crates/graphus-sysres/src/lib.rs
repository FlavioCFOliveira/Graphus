//! `graphus-sysres` — best-effort probes of the host's hardware resources.
//!
//! Graphus is engineered to extract the fullest possible throughput from the machine it runs on
//! (see `specification/01-needs-survey.md`, FR-AR-6 hardware adaptivity). To
//! do that, the server must *size itself* to the real hardware — the number of worker threads, the
//! buffer-pool budget, checkpoint cadence, and so on — rather than to fixed compile-time constants.
//! This crate is the small, separately-auditable leaf that answers three questions about the host:
//!
//! 1. How many logical CPUs are available? ([`logical_cpus`])
//! 2. How much RAM does the machine have, and roughly how much is free? ([`memory`] → [`MemoryInfo`])
//! 3. How big is the filesystem backing a given path, how much is free, and is it likely rotational?
//!    ([`storage`] → [`StorageInfo`])
//!
//! ## Design contract
//!
//! Every probe is **best-effort and total**: it never panics, never blocks on I/O beyond a single
//! quick syscall or a small `/proc` / `/sys` read, and degrades gracefully to `None` on any failure
//! or unsupported platform. Callers treat every field as a *hint*; a `None` simply means "fall back
//! to a conservative default". This makes the tuning logic that consumes these values trivially
//! testable: [`MemoryInfo`] and [`StorageInfo`] are plain public structs with public fields, so a
//! unit test in the consuming crate can construct synthetic values directly — there is no global
//! state and no hidden constructor.
//!
//! ## Platforms
//!
//! - **Linux / Raspberry Pi OS** — memory via `sysinfo(2)` (rustix) cross-checked against
//!   `/proc/meminfo` (whose `MemAvailable` is a better free-memory estimate than `freeram`), and a
//!   rotational hint via `/sys/block/<dev>/queue/rotational`.
//! - **macOS** — total RAM via `sysctlbyname("hw.memsize")`; the free-memory and rotational hints
//!   are reported as `None` (the mach `host_statistics` path is deliberately not implemented — it
//!   would add `unsafe` and complexity for a value the tuner only treats as a hint).
//! - **Any other target** — memory and rotational hints are `None`; filesystem capacity still works
//!   wherever POSIX `statvfs(3)` is available.
//!
//! ## Safety
//!
//! The non-macOS build is `#![forbid(unsafe_code)]` and compiles no `unsafe` at all. macOS needs a
//! single scoped `unsafe` block — the `sysctlbyname` FFI call — so on that target the crate lint is
//! relaxed to `deny(unsafe_code)` and exactly one private function carries a localized
//! `#[allow(unsafe_code)]` with a `// SAFETY:` justification. `unsafe_op_in_unsafe_fn` is denied
//! crate-wide so the FFI call must sit in an explicit `unsafe { … }` block, not leak out of an
//! `unsafe fn`.

// See the `## Safety` section above. Non-macOS forbids `unsafe` outright; macOS denies it (so a
// stray `unsafe` anywhere else still fails the build) while letting the one documented sysctl block
// compile behind a localized `#[allow]`.
#![cfg_attr(not(target_os = "macos"), forbid(unsafe_code))]
#![cfg_attr(target_os = "macos", deny(unsafe_code))]
#![deny(unsafe_op_in_unsafe_fn)]

use std::path::Path;

/// Total and available system memory, in bytes.
///
/// Both fields are best-effort: a field is `None` when the value could not be determined on the
/// current platform (see the crate-level docs). When both are `Some`, `available_bytes` is never
/// larger than `total_bytes`.
///
/// The struct is a plain public record with public fields so tuning logic can be unit-tested with
/// synthetic values:
///
/// ```
/// use graphus_sysres::MemoryInfo;
/// let synthetic = MemoryInfo { total_bytes: Some(16 << 30), available_bytes: Some(8 << 30) };
/// assert_eq!(synthetic.total_bytes, Some(16 << 30));
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct MemoryInfo {
    /// Total physical RAM in bytes, or `None` if it could not be determined.
    pub total_bytes: Option<u64>,
    /// An estimate of the RAM available for new allocations without swapping, in bytes, or `None`
    /// if it could not be determined. On Linux this prefers `/proc/meminfo`'s `MemAvailable`, which
    /// accounts for reclaimable page cache and is a better estimate than raw free memory.
    pub available_bytes: Option<u64>,
}

/// Capacity of the filesystem backing a path, plus a rotational-media hint.
///
/// All fields are best-effort (`None` on error or where unsupported). When both `total_bytes` and
/// `available_bytes` are `Some`, `available_bytes` is never larger than `total_bytes`.
///
/// Like [`MemoryInfo`], this is a plain public record for direct construction in tests:
///
/// ```
/// use graphus_sysres::StorageInfo;
/// let synthetic = StorageInfo {
///     total_bytes: Some(500 << 30),
///     available_bytes: Some(120 << 30),
///     rotational: Some(false),
/// };
/// assert_eq!(synthetic.rotational, Some(false));
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct StorageInfo {
    /// Total size of the filesystem in bytes, or `None` if it could not be determined.
    pub total_bytes: Option<u64>,
    /// Space available to an unprivileged process in bytes (from `statvfs`'s `f_bavail`), or `None`
    /// if it could not be determined.
    pub available_bytes: Option<u64>,
    /// Rotational-media hint: `Some(true)` for a spinning disk (HDD), `Some(false)` for a
    /// non-rotational device (SSD/NVMe), or `None` when it could not be determined. Linux-only and
    /// best-effort — treat it purely as a hint, never as load-bearing.
    pub rotational: Option<bool>,
}

/// Returns the number of logical CPUs available to this process.
///
/// Backed by [`std::thread::available_parallelism`], which honours cgroup/affinity limits where the
/// platform exposes them. Falls back to `1` if the count cannot be determined, so the result is
/// always at least `1` and safe to use as a divisor or thread count.
#[must_use]
pub fn logical_cpus() -> usize {
    std::thread::available_parallelism()
        .map(std::num::NonZeroUsize::get)
        .unwrap_or(1)
}

/// Probes total and available system memory. Never panics; see [`MemoryInfo`].
#[must_use]
pub fn memory() -> MemoryInfo {
    #[cfg(target_os = "linux")]
    {
        memory_linux()
    }
    #[cfg(target_os = "macos")]
    {
        memory_macos()
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        MemoryInfo {
            total_bytes: None,
            available_bytes: None,
        }
    }
}

/// Probes the filesystem backing `path` for capacity and a rotational-media hint. Never panics; see
/// [`StorageInfo`].
///
/// `path` need not be a directory — any existing path on the target filesystem works (the server
/// typically passes its data directory).
#[must_use]
pub fn storage(path: &Path) -> StorageInfo {
    let (total_bytes, available_bytes) = match rustix::fs::statvfs(path) {
        Ok(st) => {
            // Block counts (`f_blocks`, `f_bavail`) are expressed in units of the fundamental
            // fragment size `f_frsize`; fall back to the block size `f_bsize` if a filesystem
            // leaves `f_frsize` unset (0). If neither is known, report unknown rather than a
            // misleading zero (`checked_mul(0)` would otherwise yield `Some(0)`).
            let unit = if st.f_frsize != 0 {
                st.f_frsize
            } else {
                st.f_bsize
            };
            if unit == 0 {
                (None, None)
            } else {
                (st.f_blocks.checked_mul(unit), st.f_bavail.checked_mul(unit))
            }
        }
        Err(_) => (None, None),
    };

    StorageInfo {
        total_bytes,
        available_bytes,
        rotational: rotational_hint(path),
    }
}

// ---------------------------------------------------------------------------------------------
// Linux memory
// ---------------------------------------------------------------------------------------------

#[cfg(target_os = "linux")]
fn memory_linux() -> MemoryInfo {
    // `sysinfo(2)` is infallible in rustix (it returns the struct directly). `mem_unit` is the size
    // in bytes of the units in which `totalram`/`freeram` are expressed; older kernels report 0 to
    // mean "1 byte", so treat 0 as 1. Widen to u64 before multiplying (`c_ulong` is 32-bit on a
    // 32-bit Raspberry Pi OS) and saturate rather than overflow.
    let info = rustix::system::sysinfo();
    let unit = if info.mem_unit == 0 {
        1u64
    } else {
        u64::from(info.mem_unit)
    };
    let total_from_sysinfo = (info.totalram as u64).saturating_mul(unit);
    let free_from_sysinfo = (info.freeram as u64).saturating_mul(unit);

    // `/proc/meminfo` is cheap to read and its `MemAvailable` is a materially better "free" estimate
    // than `freeram` (it includes reclaimable page cache). Prefer it for `available_bytes`.
    let (meminfo_total, meminfo_available) = std::fs::read_to_string("/proc/meminfo")
        .ok()
        .map(|contents| parse_meminfo(&contents))
        .unwrap_or((None, None));

    let total_bytes = match total_from_sysinfo {
        0 => meminfo_total,
        n => Some(n),
    };
    let available_bytes = meminfo_available.or(match free_from_sysinfo {
        0 => None,
        n => Some(n),
    });

    // `total` (sysinfo) and `available` (MemAvailable) come from two separate reads, so in the
    // extreme they could skew by a few KiB. Enforce the documented `available <= total` invariant by
    // clamping, so a consumer (and the startup log) never sees a nonsensical available > total.
    let available_bytes = match (available_bytes, total_bytes) {
        (Some(a), Some(t)) => Some(a.min(t)),
        (a, _) => a,
    };

    MemoryInfo {
        total_bytes,
        available_bytes,
    }
}

/// Parses the relevant fields out of `/proc/meminfo` contents, returning
/// `(MemTotal, MemAvailable)` in **bytes**.
///
/// Factored out as a pure function over `&str` so it is deterministic and platform-independent to
/// unit-test. The kernel reports these fields in kibibytes (`kB`); the parser scales to bytes and
/// tolerates a missing or unexpected unit by assuming the raw value is already in bytes.
#[cfg(target_os = "linux")]
fn parse_meminfo(contents: &str) -> (Option<u64>, Option<u64>) {
    let mut total = None;
    let mut available = None;
    for line in contents.lines() {
        if let Some(rest) = line.strip_prefix("MemTotal:") {
            total = parse_meminfo_value(rest);
        } else if let Some(rest) = line.strip_prefix("MemAvailable:") {
            available = parse_meminfo_value(rest);
        }
        if total.is_some() && available.is_some() {
            break;
        }
    }
    (total, available)
}

/// Parses one `/proc/meminfo` value line body (everything after the `Key:` prefix) into bytes.
#[cfg(target_os = "linux")]
fn parse_meminfo_value(rest: &str) -> Option<u64> {
    let mut fields = rest.split_whitespace();
    let number: u64 = fields.next()?.parse().ok()?;
    match fields.next() {
        Some(unit) if unit.eq_ignore_ascii_case("kb") => Some(number.saturating_mul(1024)),
        Some(unit) if unit.eq_ignore_ascii_case("mb") => Some(number.saturating_mul(1024 * 1024)),
        _ => Some(number),
    }
}

// ---------------------------------------------------------------------------------------------
// macOS memory (the crate's only `unsafe`)
// ---------------------------------------------------------------------------------------------

#[cfg(target_os = "macos")]
fn memory_macos() -> MemoryInfo {
    // `available_bytes` is intentionally `None`: a faithful "available" figure needs mach
    // `host_statistics64` (vm page stats), which would add `unsafe` and a mach dependency for a
    // value the tuner only treats as a hint. Total RAM via `hw.memsize` is enough to size budgets.
    MemoryInfo {
        total_bytes: macos_hw_memsize(),
        available_bytes: None,
    }
}

/// Reads total physical RAM (bytes) from the `hw.memsize` sysctl OID on macOS.
///
/// Returns `None` on any failure (non-zero return code, unexpected result size, or a zero value).
#[cfg(target_os = "macos")]
#[allow(unsafe_code)]
fn macos_hw_memsize() -> Option<u64> {
    // `hw.memsize` is documented to return a 64-bit integer (physical memory in bytes).
    let name = c"hw.memsize";
    let mut value: u64 = 0;
    let mut len: libc::size_t = core::mem::size_of::<u64>();

    // SAFETY: `sysctlbyname` reads the OID named by `name` and, on success, writes at most `*oldlenp`
    // bytes to `oldp`. All pointer arguments are valid for the duration of this single call and are
    // not retained by the callee:
    //   * `name` is a `&'static CStr` (NUL-terminated, valid for reads for the whole program).
    //   * `oldp` points at `value`, a live, properly aligned `u64` on this stack frame; `oldlenp`
    //     points at `len`, initialised to `size_of::<u64>()`, so the kernel cannot write past the
    //     8-byte destination.
    //   * `newp` is null and `newlen` is 0 — a read-only query, so no input buffer is dereferenced.
    // After the call we additionally require the reported length to equal 8 bytes before trusting
    // `value`, so a short/partial write is rejected rather than read as garbage.
    let rc = unsafe {
        libc::sysctlbyname(
            name.as_ptr(),
            core::ptr::from_mut(&mut value).cast::<core::ffi::c_void>(),
            &mut len,
            core::ptr::null_mut(),
            0,
        )
    };

    if rc == 0 && len == core::mem::size_of::<u64>() && value > 0 {
        Some(value)
    } else {
        None
    }
}

// ---------------------------------------------------------------------------------------------
// Rotational-media hint
// ---------------------------------------------------------------------------------------------

/// Best-effort rotational hint for the device backing `path`. Linux-only; `None` everywhere else.
///
/// Resolves the backing device via the filesystem's `st_dev` (major:minor) and reads
/// `/sys/dev/block/<major>:<minor>/queue/rotational`. For a partition the `queue` directory lives on
/// the parent whole-disk node, so a `../queue/rotational` fallback is attempted. Any difficulty
/// (path off a block device, missing sysfs entry, unexpected contents) yields `None`.
#[cfg(target_os = "linux")]
fn rotational_hint(path: &Path) -> Option<bool> {
    use std::os::linux::fs::MetadataExt;

    let dev = std::fs::metadata(path).ok()?.st_dev();
    // glibc dev_t decomposition (`gnu_dev_major`/`gnu_dev_minor`): the low bits carry the common
    // small major/minor, the high bits extend them. Pure bit math — no `unsafe`.
    let major = ((dev >> 8) & 0x0fff) | ((dev >> 32) & !0x0fffu64);
    let minor = (dev & 0xff) | ((dev >> 12) & !0xffu64);

    let base = format!("/sys/dev/block/{major}:{minor}");
    // Whole disk first, then the partition -> parent-disk fallback.
    for candidate in [
        format!("{base}/queue/rotational"),
        format!("{base}/../queue/rotational"),
    ] {
        if let Some(is_rotational) = read_rotational_flag(&candidate) {
            return Some(is_rotational);
        }
    }
    None
}

/// Reads a `queue/rotational` sysfs file: `"1"` -> `Some(true)`, `"0"` -> `Some(false)`, else `None`.
#[cfg(target_os = "linux")]
fn read_rotational_flag(sysfs_path: &str) -> Option<bool> {
    match std::fs::read_to_string(sysfs_path).ok()?.trim() {
        "1" => Some(true),
        "0" => Some(false),
        _ => None,
    }
}

/// Rotational hints are only implemented for Linux; every other target reports `None`.
#[cfg(not(target_os = "linux"))]
fn rotational_hint(_path: &Path) -> Option<bool> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn logical_cpus_is_at_least_one() {
        assert!(
            logical_cpus() >= 1,
            "logical_cpus must never report fewer than one CPU"
        );
    }

    #[test]
    fn memory_probe_is_total_and_self_consistent() {
        let info = memory();
        // Whenever both are known, availability cannot exceed the total.
        if let (Some(total), Some(available)) = (info.total_bytes, info.available_bytes) {
            assert!(
                available <= total,
                "available ({available}) must not exceed total ({total})"
            );
        }
        // On Linux (the CI/dev platform) total RAM must be discoverable and positive. Asserting this
        // only under cfg keeps the test green on any platform.
        #[cfg(target_os = "linux")]
        {
            let total = info
                .total_bytes
                .expect("Linux must report total memory via sysinfo");
            assert!(total > 0, "Linux total memory must be positive");
        }
    }

    #[test]
    fn storage_probe_of_temp_dir_is_self_consistent() {
        let info = storage(&std::env::temp_dir());
        if let (Some(total), Some(available)) = (info.total_bytes, info.available_bytes) {
            assert!(
                available <= total,
                "available ({available}) must not exceed total ({total})"
            );
        }
    }

    #[test]
    fn storage_probe_of_missing_path_degrades_to_none() {
        // A path that cannot exist must not panic; it simply yields unknowns.
        let info = storage(Path::new("/graphus-sysres/definitely/does/not/exist"));
        assert_eq!(info.total_bytes, None);
        assert_eq!(info.available_bytes, None);
        assert_eq!(info.rotational, None);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn parse_meminfo_extracts_total_and_available_in_bytes() {
        let sample = "\
MemTotal:       16333764 kB
MemFree:         1234567 kB
MemAvailable:    9876543 kB
Buffers:          123456 kB
Cached:          2345678 kB
SwapTotal:       2097148 kB
";
        let (total, available) = parse_meminfo(sample);
        assert_eq!(total, Some(16_333_764 * 1024));
        assert_eq!(available, Some(9_876_543 * 1024));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn parse_meminfo_missing_available_yields_none() {
        let sample = "MemTotal:        8000000 kB\nMemFree:          100000 kB\n";
        let (total, available) = parse_meminfo(sample);
        assert_eq!(total, Some(8_000_000 * 1024));
        assert_eq!(available, None);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn parse_meminfo_tolerates_missing_unit_as_bytes() {
        // Defensive: if a value ever lacks the `kB` suffix, treat it as raw bytes rather than mis-scale.
        let sample = "MemTotal: 4096\nMemAvailable: 2048\n";
        assert_eq!(parse_meminfo(sample), (Some(4096), Some(2048)));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn parse_meminfo_ignores_garbage_and_empty() {
        assert_eq!(parse_meminfo(""), (None, None));
        assert_eq!(parse_meminfo("MemTotal:   not_a_number kB\n"), (None, None));
    }

    #[test]
    fn structs_are_directly_constructible_as_a_test_seam() {
        // The deterministic test seam: server tuning logic builds these with synthetic values, with
        // no global state or hidden constructor.
        let mem = MemoryInfo {
            total_bytes: Some(1 << 30),
            available_bytes: Some(1 << 29),
        };
        assert_eq!(mem.total_bytes, Some(1 << 30));
        assert_eq!(mem.available_bytes, Some(1 << 29));

        let store = StorageInfo {
            total_bytes: Some(100),
            available_bytes: Some(40),
            rotational: Some(true),
        };
        assert_eq!(store.total_bytes, Some(100));
        assert_eq!(store.rotational, Some(true));
    }
}
