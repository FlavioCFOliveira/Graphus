//! I/O backend selection: the epoll/kqueue (Tokio) baseline and the optional io_uring fast path.
//!
//! Decision `D-io-backend` (`04 §3.6`, §9.1): the baseline is Tokio over epoll (Linux) / kqueue
//! (macOS), which runs everywhere in the Tier-1 matrix. On capable Linux an **io_uring** fast path
//! may engage, but it must **always fall back cleanly** to the baseline when io_uring is
//! unavailable — an old kernel, a kernel with io_uring disabled (e.g. by seccomp or
//! `io_uring_disabled` sysctl), a container that blocks the syscalls, or any non-Linux target.
//!
//! ## What is fully implemented vs gated
//! - **Capability probe** ([`probe_io_uring`]) and **backend selection** ([`select_backend`],
//!   [`select_backend_with`]) are implemented and tested on every target. Selection is a *pure*
//!   function of the probe result, so the fallback guarantee is verified independent of whether the
//!   `io-uring` feature (and a capable kernel) are present.
//! - The **real `io_uring_setup(2)` probe** lives behind the `io-uring` Cargo feature (Linux only),
//!   in the `uring` module; without the feature the probe is a truthful `false` (the submission path
//!   is compiled out, so io_uring genuinely cannot be used).
//! - The **submission path** itself is stubbed pending the `io-uring` crate — see the `uring` module
//!   and its `TODO(io_uring submission)`. The Tokio baseline carries correctness; io_uring is a
//!   perf path only. Selecting [`IoBackend::Uring`] today is therefore a *capability assertion*
//!   that the engine will honour once the submission path lands; until then the engine treats both
//!   variants identically at the byte level (the baseline does the work).

/// The active I/O backend chosen at startup.
///
/// `Tokio` is the epoll/kqueue baseline (always available). `Uring` is the Linux io_uring fast path
/// (only ever chosen when the runtime probe confirms the kernel supports it *and* the `io-uring`
/// feature is compiled in).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IoBackend {
    /// Epoll/kqueue via Tokio — the portable baseline (`04 §9.1`).
    Tokio,
    /// Linux io_uring fast path (`04 §3.6`). Only selected when [`probe_io_uring`] returns `true`.
    Uring,
}

impl IoBackend {
    /// Whether this backend is the io_uring fast path.
    #[must_use]
    pub fn is_uring(self) -> bool {
        matches!(self, IoBackend::Uring)
    }

    /// A short, stable name for logging/metrics.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            IoBackend::Tokio => "tokio-epoll-kqueue",
            IoBackend::Uring => "io-uring",
        }
    }
}

/// Runtime capability check: is io_uring usable on this host *right now*?
///
/// Returns `true` only when the `io-uring` feature is compiled in, the target is Linux, and a
/// minimal `io_uring_setup(2)` actually succeeds (the only honest test — a kernel-version string is
/// not enough, because io_uring can be present-but-disabled). In every other case it returns
/// `false`, which drives a clean fallback to the Tokio baseline.
///
/// This never panics and never blocks; it is safe to call once at startup.
#[must_use]
pub fn probe_io_uring() -> bool {
    #[cfg(all(target_os = "linux", feature = "io-uring"))]
    {
        crate::uring::probe()
    }
    #[cfg(not(all(target_os = "linux", feature = "io-uring")))]
    {
        // No feature, or not Linux: io_uring submission is compiled out, so it is genuinely
        // unavailable. Reporting `false` is the truth, not a stub.
        false
    }
}

/// Selects the I/O backend at startup using the real [`probe_io_uring`] capability check.
///
/// Equivalent to `select_backend_with(probe_io_uring)`. This is what the engine (`graphus-server`,
/// rmp #20) calls once during construction.
#[must_use]
pub fn select_backend() -> IoBackend {
    select_backend_with(probe_io_uring)
}

/// Selects the I/O backend from an injectable probe, so the fallback logic is unit-testable without
/// depending on the host kernel.
///
/// The rule is intentionally trivial and total: **io_uring only when the probe says yes; otherwise
/// the Tokio baseline.** There is no configuration that can select io_uring when the probe reports
/// it unavailable — the fallback is guaranteed by construction, which is exactly the property the
/// acceptance criterion ("falls back cleanly") requires.
#[must_use]
pub fn select_backend_with<P: FnOnce() -> bool>(probe: P) -> IoBackend {
    if probe() {
        IoBackend::Uring
    } else {
        IoBackend::Tokio
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selection_prefers_uring_when_probe_succeeds() {
        assert_eq!(select_backend_with(|| true), IoBackend::Uring);
    }

    #[test]
    fn selection_falls_back_to_tokio_when_probe_fails() {
        // The core fallback guarantee: probe says "no" → always the baseline.
        assert_eq!(select_backend_with(|| false), IoBackend::Tokio);
    }

    #[test]
    fn real_probe_and_selection_yield_a_usable_backend() {
        // On any host this must return *a* backend; on this (Linux) host without the `io-uring`
        // feature it is the Tokio baseline. The point is that `select_backend` never panics and
        // always produces a working choice.
        let backend = select_backend();
        // The chosen backend is consistent with the probe.
        if probe_io_uring() {
            assert_eq!(backend, IoBackend::Uring);
        } else {
            assert_eq!(backend, IoBackend::Tokio);
        }
        // Without the `io-uring` feature, the probe is always false and the baseline is chosen.
        #[cfg(not(feature = "io-uring"))]
        {
            assert!(!probe_io_uring());
            assert_eq!(backend, IoBackend::Tokio);
            assert_eq!(backend.name(), "tokio-epoll-kqueue");
        }
    }

    #[test]
    fn backend_accessors() {
        assert!(IoBackend::Uring.is_uring());
        assert!(!IoBackend::Tokio.is_uring());
        assert_eq!(IoBackend::Tokio.name(), "tokio-epoll-kqueue");
        assert_eq!(IoBackend::Uring.name(), "io-uring");
    }
}
