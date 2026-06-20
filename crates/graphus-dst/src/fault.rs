//! The fault schedule: which fault a scenario injects, and an honest catalogue of what is and is
//! not exercised against the *current* engine (`specification/04-technical-design.md` §11.5).
//!
//! The project forbids guessing and forbids claiming coverage that does not exist
//! (`CLAUDE.md`: "Measure to decide", "Never guess"; the task brief: "be honest about scope").
//! This module therefore splits faults into two enums:
//!
//! * [`FaultKind`] — faults the harness **actually injects through the full `RecordStore` engine
//!   and verifies** through recovery, because the engine genuinely supports them via its public API
//!   today (verified against the engine's own DST devices and crash-recovery tests, not assumed).
//! * [`DeferredFault`] — faults the spec calls for but whose machinery (or a public injection seam)
//!   is **not yet available**; the harness records why each is deferred so the gap is visible in the
//!   run report instead of being silently skipped.
//!
//! ## What is exercised through the full engine (verified)
//!
//! * **Crash (power loss)** — the central DST fault. Modelled exactly as the engine's own
//!   `graphus-storage` crash-recovery tests do (`tests/crash_recovery.rs`): keep only the durable
//!   WAL prefix that committed transactions' group-commit `fdatasync` hardened
//!   ([`graphus_wal::MemLogSink::durable_bytes`]), optionally keep a partially-flushed disk image
//!   (the *steal* variant uses [`graphus_storage::RecordStore::mapped_pages`] +
//!   `read_device_page`), then run three-phase ARIES recovery
//!   ([`graphus_storage::recovery::recover_device`]) and reopen. The crash point is seeded, so a
//!   crash can land with work in flight.
//! * **Torn WAL tail** — a crash mid-record. Modelled by truncating the durable WAL prefix at a
//!   seeded byte strictly *after* the last committed record (so no acknowledged commit is lost);
//!   ARIES analysis stops cleanly at the last intact record ([`graphus_wal::recover`] treats a
//!   decode failure as the end of the durable log), which is the committed-or-nothing guarantee.
//! * **Write reordering** — a sync that does *not* atomically drain the page cache. Modelled with
//!   [`graphus_io::FaultPlan::with_write_reordering`]: the steal flush's sync persists only a seeded
//!   subset of dirty pages home, so the crash drops the rest. Recovery (ARIES redo from the durable
//!   WAL) must reconstruct every committed page the reordered sync failed to persist, which is the
//!   committed-or-nothing guarantee under a non-atomic flush. Verified through the full `RecordStore`
//!   engine; this is why it is a [`FaultKind`], not a [`DeferredFault`].
//!
//! ## What is exercised at the layer the public API permits
//!
//! * **Write I/O error** ([`graphus_io::MemBlockDevice::arm_io_error`]) — see
//!   [`DeferredFault::WriteIoErrorFullEngine`] for *why the full-engine path is deferred*. The
//!   error contract ("surface, never corrupt") **is** verified at the buffer-pool write path, the
//!   layer where the public API lets the harness own and arm the device; see
//!   `tests/write_io_error.rs`. That test is real coverage of the fault at the component where it
//!   can be honestly injected, not a stand-in for full-engine coverage.
//!
//! ## What is deferred (machinery or seam not yet available) — see [`DeferredFault`]
//!
//! * **Write I/O error, full `RecordStore` write path** — `RecordStore` exposes no public seam to
//!   reach its device after construction, and the task forbids modifying other crates, so the error
//!   cannot be armed mid-workload on the live store. Deferred until `graphus-storage` exposes a
//!   device-fault hook; covered at the buffer-pool layer in the meantime (above).
//! * **Torn DATA page (DWB-repaired)** — now exercised through the full engine, *not* deferred. The
//!   [`graphus_io::MemBlockDevice::arm_torn_write`] device tears a home page mid-write; recovery
//!   repairs it from the **doublewrite buffer** (`05 §3`, `04 §4.5`,
//!   [`graphus_storage::recovery::recover_device_with_dwb`]) **before** ARIES redo reads its
//!   `page_lsn`, and the consistency checker then passes. Verified by `tests/torn_data_page.rs`.
//! * **fsync EIO (the controlled PANIC path, `04 §4.9`)** — a failed `fdatasync` aborts the process
//!   by design (fsyncgate). The engine already proves this with a `#[should_panic]` unit test
//!   (`graphus-wal` `manager::tests::fsync_failure_panics`). Exercising it here would mean catching
//!   the abort via `std::panic::catch_unwind` and treating it as a crash; that adds no new coverage
//!   over the crash fault (post-abort recovery *is* the crash path) and couples the harness to panic
//!   unwinding, so it is deliberately out of scope and cross-referenced.

/// A fault the harness actually injects into a scenario through the full engine and verifies through
/// recovery.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FaultKind {
    /// Power loss: drop the device's and the WAL sink's un-synced tail at a seeded point, keep only
    /// what committed work hardened, then reopen + recover. The *no-force* variant recovers onto a
    /// fresh empty device (committed work lives only in the WAL); the *steal* variant first writes
    /// dirty pages home and snapshots that disk image so undo must roll back uncommitted pages.
    Crash {
        /// Whether uncommitted dirty pages were stolen (flushed home) before the crash.
        steal: bool,
    },
    /// A crash whose durable WAL prefix is truncated mid-record (a torn tail); recovery must stop at
    /// the last intact record.
    TornWalTail,
    /// A power loss that tears a **home data page** mid-write (some sectors new, some old). Recovery
    /// must repair it from the doublewrite buffer (`05 §3`, `04 §4.5`) before ARIES redo reads its
    /// `page_lsn`, so the checksum-detected tear is repaired rather than served.
    TornDataPage,
    /// A power loss whose steal flush synced through a **reordering device**: the sync persisted only
    /// a seeded subset of dirty pages home, so the crash dropped the rest. ARIES redo from the
    /// durable WAL must reconstruct every committed page the non-atomic sync failed to persist
    /// ([`graphus_io::FaultPlan::with_write_reordering`]).
    WriteReordering,
}

impl FaultKind {
    /// A short, stable label for the run summary.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            FaultKind::Crash { steal: false } => "crash(no-force)",
            FaultKind::Crash { steal: true } => "crash(steal)",
            FaultKind::TornWalTail => "torn-wal-tail",
            FaultKind::TornDataPage => "torn-data-page",
            FaultKind::WriteReordering => "write-reordering",
        }
    }

    /// Every fault label the harness can emit, for initialising per-kind tallies in the report.
    #[must_use]
    pub fn all_labels() -> [&'static str; 5] {
        [
            FaultKind::Crash { steal: false }.label(),
            FaultKind::Crash { steal: true }.label(),
            FaultKind::TornWalTail.label(),
            FaultKind::TornDataPage.label(),
            FaultKind::WriteReordering.label(),
        ]
    }
}

/// A fault the spec (`04 §11.5`) calls for but that the current engine cannot honestly exercise
/// *through the full `RecordStore`*, recorded so the gap is explicit in the run report rather than
/// silently skipped.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DeferredFault {
    /// Write I/O error against the full `RecordStore` write path — no public device seam; covered at
    /// the buffer-pool layer instead (`tests/write_io_error.rs`).
    WriteIoErrorFullEngine,
    /// `fdatasync` EIO — the controlled-PANIC path (`04 §4.9`); covered by a WAL unit test, out of
    /// scope here to avoid coupling to panic unwinding (adds no coverage over the crash path).
    FsyncEio,
}

impl DeferredFault {
    /// A short label.
    #[must_use]
    pub fn label(self) -> &'static str {
        match self {
            DeferredFault::WriteIoErrorFullEngine => "write-io-error(full-engine)",
            DeferredFault::FsyncEio => "fsync-eio",
        }
    }

    /// The reason this fault is deferred, for the run report.
    #[must_use]
    pub fn reason(self) -> &'static str {
        match self {
            DeferredFault::WriteIoErrorFullEngine => {
                "RecordStore exposes no public device seam to arm an I/O error mid-workload, and the \
                 task forbids modifying other crates; the surface-not-corrupt contract is verified \
                 at the buffer-pool write path instead (tests/write_io_error.rs)"
            }
            DeferredFault::FsyncEio => {
                "controlled-PANIC path (04 §4.9); covered by graphus-wal \
                 manager::tests::fsync_failure_panics; out of scope here (no new coverage over crash)"
            }
        }
    }

    /// Every deferred fault, for listing in the report.
    #[must_use]
    pub fn all() -> [DeferredFault; 2] {
        [
            DeferredFault::WriteIoErrorFullEngine,
            DeferredFault::FsyncEio,
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fault_labels_are_distinct_and_cover_all_kinds() {
        let labels = FaultKind::all_labels();
        let unique: std::collections::BTreeSet<&str> = labels.iter().copied().collect();
        assert_eq!(unique.len(), labels.len(), "labels must be distinct");
        assert!(labels.contains(&FaultKind::Crash { steal: false }.label()));
        assert!(labels.contains(&FaultKind::Crash { steal: true }.label()));
        assert!(labels.contains(&FaultKind::TornWalTail.label()));
        assert!(labels.contains(&FaultKind::TornDataPage.label()));
        assert!(labels.contains(&FaultKind::WriteReordering.label()));
    }

    #[test]
    fn deferred_faults_carry_a_reason() {
        for f in DeferredFault::all() {
            assert!(!f.label().is_empty());
            assert!(f.reason().len() > 20, "a deferred fault must state why");
        }
    }
}
