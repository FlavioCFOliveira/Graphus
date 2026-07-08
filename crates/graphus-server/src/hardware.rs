//! Startup hardware probe (`04 §9.5`, decision `D-hw-autotune`).
//!
//! [`HardwareResources`] is a **snapshot** of the host's resources — logical CPU count, physical
//! RAM, and the store filesystem's capacity/free space + an SSD-vs-rotational hint — taken **once**
//! at server startup by [`HardwareResources::detect`]. It exists so the server can derive sane
//! defaults for its resource-sizing parameters (the buffer pool, the reader/morsel pools) from the
//! real hardware instead of shipping one fixed value that is simultaneously too small for a big
//! server and too large for a Raspberry Pi.
//!
//! The actual OS probing (and the small, isolated `unsafe` it needs on macOS) lives in the
//! [`graphus_sysres`] leaf crate, so this crate stays `#![forbid(unsafe_code)]`. Every probe is
//! **best-effort**: a value that cannot be determined comes back as `None` and the caller falls
//! back to a built-in floor — detection never panics and never fails the server start.
//!
//! The snapshot is pure data. The **policy** that turns it into concrete parameter values —
//! including the override rule that any value set in the TOML file or a `GRAPHUS_*` env var wins
//! over the hardware-derived default — lives in
//! [`ServerConfig::apply_hardware_defaults`](crate::config::ServerConfig::apply_hardware_defaults),
//! which takes a `&HardwareResources` and is therefore pure and unit-testable with synthetic
//! hardware.

use std::path::{Path, PathBuf};

pub use graphus_sysres::{MemoryInfo, StorageInfo};

/// A one-shot snapshot of the host hardware relevant to server auto-tuning (`04 §9.5`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HardwareResources {
    /// Logical CPUs available to this process (`std::thread::available_parallelism`, floored at 1).
    pub logical_cpus: usize,
    /// Physical memory: total and (where the OS exposes it) available. Either may be `None`.
    pub memory: MemoryInfo,
    /// The store filesystem's capacity/free space + rotational hint. Any field may be `None`.
    pub storage: StorageInfo,
}

impl HardwareResources {
    /// Probes the host once. Best-effort: never panics, and any undeterminable figure is `None`.
    ///
    /// Storage is stat'd on `store_path` — or, when that path does not exist yet (a fresh
    /// deployment whose data directory is created *after* config is resolved), on its nearest
    /// existing ancestor — so the reading reflects the filesystem the store will actually live on.
    #[must_use]
    pub fn detect(store_path: &Path) -> Self {
        let storage_path = nearest_existing_ancestor(store_path);
        Self {
            logical_cpus: graphus_sysres::logical_cpus(),
            memory: graphus_sysres::memory(),
            storage: graphus_sysres::storage(storage_path.as_deref().unwrap_or(store_path)),
        }
    }

    /// A snapshot with everything unknown — the graceful-degradation baseline used when hardware
    /// cannot be probed. Auto-sizing then falls back to the built-in floors. Handy in tests.
    #[must_use]
    pub fn unknown() -> Self {
        Self {
            logical_cpus: 1,
            memory: MemoryInfo {
                total_bytes: None,
                available_bytes: None,
            },
            storage: StorageInfo {
                total_bytes: None,
                available_bytes: None,
                rotational: None,
            },
        }
    }

    /// The RAM figure the buffer-pool auto-sizer bases its budget on: **available** memory when the
    /// OS reports it (the honest "how much can we actually use right now" number), else **total**
    /// memory, else `None` (⇒ the caller uses its floor). See
    /// [`ServerConfig::apply_hardware_defaults`](crate::config::ServerConfig::apply_hardware_defaults).
    #[must_use]
    pub fn sizing_memory_bytes(&self) -> Option<u64> {
        self.memory.available_bytes.or(self.memory.total_bytes)
    }
}

/// Walks up `path` to the first component that exists on disk, so a not-yet-created store directory
/// still yields a stat'able filesystem for the capacity probe. Returns `None` if nothing on the
/// chain exists (extraordinarily unlikely — the root always exists — in which case the caller stats
/// the original path and lets the probe degrade to `None`).
fn nearest_existing_ancestor(path: &Path) -> Option<PathBuf> {
    path.ancestors()
        .find(|p| !p.as_os_str().is_empty() && p.exists())
        .map(Path::to_path_buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_is_the_floor_baseline() {
        let hw = HardwareResources::unknown();
        assert_eq!(hw.logical_cpus, 1);
        assert_eq!(hw.sizing_memory_bytes(), None);
    }

    #[test]
    fn sizing_memory_prefers_available_then_total() {
        let mut hw = HardwareResources::unknown();
        hw.memory.total_bytes = Some(8 * 1024 * 1024 * 1024);
        assert_eq!(hw.sizing_memory_bytes(), Some(8 * 1024 * 1024 * 1024));
        hw.memory.available_bytes = Some(3 * 1024 * 1024 * 1024);
        assert_eq!(
            hw.sizing_memory_bytes(),
            Some(3 * 1024 * 1024 * 1024),
            "available memory wins over total when both are known"
        );
    }

    #[test]
    fn detect_never_panics_and_finds_a_filesystem_for_a_missing_path() {
        // A deep, non-existent path under a real temp dir: detection must still return a snapshot,
        // and the storage probe should resolve against an existing ancestor.
        let missing = std::env::temp_dir().join("graphus-nonexistent-xyz/deeper/store");
        let hw = HardwareResources::detect(&missing);
        assert!(hw.logical_cpus >= 1);
        // On a normal Linux/macOS host the temp filesystem yields a capacity; we only assert the
        // call is total (no panic) and internally consistent — the figures themselves are host-
        // dependent, so we do not hard-assert them here.
        if let (Some(total), Some(avail)) = (hw.storage.total_bytes, hw.storage.available_bytes) {
            assert!(avail <= total, "free space cannot exceed capacity");
        }
    }
}
