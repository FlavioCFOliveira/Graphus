//! Host / environment detection for the evidence report (`rmp #248`).
//!
//! Captures the cheap, portable facts that make a piece of evidence reproducible — *which machine,
//! which OS/arch, how many cores, which toolchain, and when*. These are **report metadata**, not
//! simulation inputs, so a wall-clock timestamp and platform queries are appropriate here (every
//! measured metric value comes from the injected meters in [`crate::resource`] / [`crate::metrics`],
//! not from this module).
//!
//! Detection is deliberately dependency-light and fail-soft:
//!
//! - **os / arch** — compile-time constants `std::env::consts::{OS, ARCH}` (zero cost, always present).
//! - **cpu cores** — [`std::thread::available_parallelism`] (the schedulable parallelism the process
//!   sees), falling back to `1`.
//! - **hostname** — `gethostname(2)` via `libc` on Unix (already a dependency); `"unknown"` elsewhere
//!   or on failure.
//! - **rustc version** — the compiler version baked in at build time via the `RUSTC_VERSION` env var
//!   exported by `build.rs` (`rustc -V`); `"unknown"` if unavailable.
//! - **timestamp** — `SystemTime::now()` Unix seconds.

use serde::{Deserialize, Serialize};

/// Host / environment facts captured once per run for the evidence report.
///
/// Every field has a stable snake_case wire name. All fields are best-effort: an undetectable value
/// degrades to a sensible default (`"unknown"` / `0`) rather than failing the run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostInfo {
    /// Operating system, e.g. `"linux"` / `"macos"` (from `std::env::consts::OS`).
    pub os: String,
    /// CPU architecture, e.g. `"x86_64"` / `"aarch64"` (from `std::env::consts::ARCH`).
    pub arch: String,
    /// Number of schedulable CPU cores the process sees (`available_parallelism`), at least `1`.
    pub cpu_cores: u32,
    /// Machine hostname, or `"unknown"` if it could not be read.
    pub hostname: String,
    /// `rustc` version the harness was built with, or `"unknown"`.
    pub rustc_version: String,
    /// Capture time as a Unix timestamp in whole seconds.
    pub timestamp_unix_secs: u64,
}

impl Default for HostInfo {
    /// An all-`"unknown"` / zero host — used when deserializing an older report that predates the
    /// `host` section, so the field is never missing.
    fn default() -> Self {
        Self {
            os: "unknown".to_string(),
            arch: "unknown".to_string(),
            cpu_cores: 0,
            hostname: "unknown".to_string(),
            rustc_version: "unknown".to_string(),
            timestamp_unix_secs: 0,
        }
    }
}

impl HostInfo {
    /// Detects the current host / environment. Cheap and portable; never fails (undetectable values
    /// degrade to defaults).
    #[must_use]
    pub fn detect() -> Self {
        Self {
            os: std::env::consts::OS.to_string(),
            arch: std::env::consts::ARCH.to_string(),
            cpu_cores: std::thread::available_parallelism()
                .map(|n| n.get() as u32)
                .unwrap_or(1),
            hostname: hostname().unwrap_or_else(|| "unknown".to_string()),
            rustc_version: option_env!("RUSTC_VERSION")
                .unwrap_or("unknown")
                .to_string(),
            timestamp_unix_secs: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
        }
    }
}

/// Reads the machine hostname via `gethostname(2)` on Unix; `None` on failure / non-Unix.
#[cfg(unix)]
fn hostname() -> Option<String> {
    // POSIX guarantees a host name no longer than `HOST_NAME_MAX`; 256 covers it with room to spare,
    // plus one byte for a guaranteed NUL terminator.
    const CAP: usize = 256;
    let mut buf = vec![0u8; CAP];
    // SAFETY: `gethostname` writes at most `len` bytes into `buf` (a valid, `len`-byte allocation we
    // own) and NUL-terminates when there is room. We pass `CAP - 1` so a terminator always fits, then
    // treat the buffer as a C string. The cast to `*mut c_char` is sound: `u8` and `c_char` share the
    // same size/alignment, and `gethostname` only writes ASCII/host-charset bytes.
    let rc = unsafe { libc::gethostname(buf.as_mut_ptr() as *mut libc::c_char, CAP - 1) };
    if rc != 0 {
        return None;
    }
    // Find the NUL terminator and decode the bytes up to it as UTF-8 (lossy: a hostname is ASCII in
    // practice, but never panic on an odd byte).
    let end = buf.iter().position(|&b| b == 0).unwrap_or(CAP);
    let name = String::from_utf8_lossy(&buf[..end]).into_owned();
    if name.is_empty() { None } else { Some(name) }
}

#[cfg(not(unix))]
fn hostname() -> Option<String> {
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detect_populates_every_field() {
        let h = HostInfo::detect();
        // os / arch are compile-time constants, always non-empty and matching the build target.
        assert_eq!(h.os, std::env::consts::OS);
        assert_eq!(h.arch, std::env::consts::ARCH);
        // At least one core is always reported.
        assert!(
            h.cpu_cores >= 1,
            "cpu_cores must be >= 1, got {}",
            h.cpu_cores
        );
        // Hostname is read on Unix (the supported platforms); never empty (defaults to "unknown").
        assert!(!h.hostname.is_empty());
        // A timestamp after the epoch was captured.
        assert!(h.timestamp_unix_secs > 0);
    }

    #[test]
    fn default_is_all_unknown_for_legacy_reports() {
        let h = HostInfo::default();
        assert_eq!(h.os, "unknown");
        assert_eq!(h.cpu_cores, 0);
        assert_eq!(h.timestamp_unix_secs, 0);
    }

    #[cfg(unix)]
    #[test]
    fn hostname_is_readable_on_unix() {
        // On the Tier-1 Unix targets the hostname must be readable and non-empty.
        let name = hostname();
        assert!(
            name.as_deref().is_some_and(|n| !n.is_empty()),
            "expected a readable hostname on Unix, got {name:?}"
        );
    }
}
