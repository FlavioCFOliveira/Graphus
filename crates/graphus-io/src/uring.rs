//! Linux io_uring fast-path module (feature `io-uring`, Linux only).
//!
//! This module is compiled **only** under `#[cfg(all(target_os = "linux", feature = "io-uring"))]`
//! (see `lib.rs`). It contains the one piece of `unsafe` in the crate: a raw `io_uring_setup(2)`
//! capability probe. The default (no-feature) build stays `#![forbid(unsafe_code)]`; this module
//! carries a narrowly scoped `#![allow(unsafe_code)]` instead, and every `unsafe` block is
//! justified with a `// SAFETY:` comment.
//!
//! ## Status
//! - [`probe`] is a **real** capability check: it asks the kernel to create a 1-entry ring and
//!   immediately tears it down. Success means io_uring is genuinely usable on this host *now*
//!   (kernel new enough, syscall not blocked by seccomp, not disabled by the
//!   `kernel.io_uring_disabled` sysctl). This is what makes [`crate::backend::probe_io_uring`]
//!   honest rather than a version-string guess.
//! - The **submission path is stubbed** ([`submit_fsync`]) pending adoption of the `io-uring`
//!   crate's safe-ish submission/completion API. The Tokio baseline carries correctness; io_uring
//!   is a perf path only (`04 §3.6`/§9.1).
//!
//! We deliberately depend on `libc` (for the raw syscall number and `close`) rather than the
//! `io-uring` crate for the *probe*, so the capability check has a tiny dependency footprint and
//! works even where the higher-level crate's ring abstraction is not warranted.

// This module is the sole `unsafe` site; the default build keeps `forbid(unsafe_code)` (lib.rs).
#![allow(unsafe_code)]

use std::io;

/// The kernel `struct io_uring_params` ABI (`include/uapi/linux/io_uring.h`).
///
/// `io_uring_setup(2)` writes into this on success, so it **must** match the kernel layout exactly
/// in size and field order — otherwise the kernel would write past our buffer. It is stable kernel
/// uapi. We zero it before the call and only read it back conceptually (the probe ignores the
/// contents; it cares only about the returned fd).
#[repr(C)]
#[derive(Default)]
struct IoUringParams {
    sq_entries: u32,
    cq_entries: u32,
    flags: u32,
    sq_thread_cpu: u32,
    sq_thread_idle: u32,
    features: u32,
    wq_fd: u32,
    resv: [u32; 3],
    sq_off: IoSqringOffsets,
    cq_off: IoCqringOffsets,
}

/// Submission-queue ring offsets (part of `io_uring_params`); contents unused by the probe.
#[repr(C)]
#[derive(Default)]
struct IoSqringOffsets {
    head: u32,
    tail: u32,
    ring_mask: u32,
    ring_entries: u32,
    flags: u32,
    dropped: u32,
    array: u32,
    resv1: u32,
    user_addr: u64,
}

/// Completion-queue ring offsets (part of `io_uring_params`); contents unused by the probe.
#[repr(C)]
#[derive(Default)]
struct IoCqringOffsets {
    head: u32,
    tail: u32,
    ring_mask: u32,
    ring_entries: u32,
    overflow: u32,
    cqes: u32,
    flags: u32,
    resv1: u32,
    user_addr: u64,
}

/// Real io_uring capability probe via `io_uring_setup(2)`.
///
/// Returns `true` iff the kernel successfully creates a minimal ring (which we then close). Any
/// failure — `ENOSYS` (too old / syscall absent), `EPERM` (disabled / seccomp), or anything else —
/// yields `false`, driving the clean fallback to the Tokio baseline.
///
/// Never panics; never blocks.
#[must_use]
pub(crate) fn probe() -> bool {
    let mut params = IoUringParams::default();
    // SAFETY: `io_uring_setup(entries, params)` reads `entries` by value and reads/writes exactly a
    // `struct io_uring_params` through the pointer. `params` is a live, properly aligned, zeroed
    // value of our `#[repr(C)]` mirror of that exact struct, so the kernel writes only within its
    // bounds. We pass a valid mutable pointer to it. The call has no other preconditions.
    let ret = unsafe {
        libc::syscall(
            libc::SYS_io_uring_setup,
            1u32 as libc::c_long,
            std::ptr::addr_of_mut!(params) as libc::c_long,
        )
    };
    if ret < 0 {
        // Setup failed (ENOSYS/EPERM/…): io_uring is not usable here.
        return false;
    }
    // `ret` is a fresh ring file descriptor we own and must not leak.
    let fd = ret as libc::c_int;
    // SAFETY: `fd` is a valid open file descriptor just returned by `io_uring_setup`; closing it
    // exactly once is the correct way to release the ring. We never use `fd` again.
    unsafe {
        libc::close(fd);
    }
    true
}

/// Stubbed io_uring submission for an `fsync`/`fdatasync` (the perf fast path).
///
/// TODO(io_uring submission): wire an `IORING_OP_FSYNC` SQE (with `IORING_FSYNC_DATASYNC` for the
/// fdatasync variant) through the `io-uring` crate's `Submitter`/`SubmissionQueue`, submit, and
/// await the CQE on a Tokio-friendly completion notifier. Until then this returns
/// [`io::ErrorKind::Unsupported`] so any *accidental* caller falls back to the
/// [`crate::fsync::FsyncPool`] baseline rather than silently skipping a durability sync. Correctness
/// lives entirely in the baseline; this is an optional throughput optimization (`04 §3.6`).
// `allow` (not `expect`): the library does not call this yet — only the unit test does — so it is
// dead in a non-test build but used under `cargo test`. `expect(dead_code)` would be unfulfilled in
// the test build; `allow` is correct for both.
#[allow(dead_code)]
pub(crate) fn submit_fsync(_fd: libc::c_int, _datasync: bool) -> io::Result<()> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "io_uring submission path not yet implemented; use the fsync pool baseline",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn probe_does_not_panic_and_returns_a_bool() {
        // On a capable Linux host (kernel 5.1+ with io_uring enabled) this is `true`; on a locked
        // down or old kernel it is `false`. The test asserts only that the probe runs cleanly and
        // yields a definite answer — the selection logic in `backend` consumes it and is tested for
        // both outcomes. We surface the value with `--nocapture` so the bench/test report can note
        // whether io_uring actually engaged on the measuring host.
        let available: bool = probe();
        println!("io_uring probe on this host: available = {available}");
    }

    #[test]
    fn when_kernel_is_capable_selection_engages_uring() {
        // End-to-end on *this* host with the feature on: if the real probe says io_uring is
        // available, the backend selector must choose `Uring`; if not, it must fall back to the
        // Tokio baseline. Either way the selector and probe agree (no path where a capable kernel is
        // ignored or an incapable one is forced).
        use crate::backend::{IoBackend, select_backend};
        let chosen = select_backend();
        if probe() {
            assert_eq!(
                chosen,
                IoBackend::Uring,
                "capable kernel must engage io_uring"
            );
        } else {
            assert_eq!(chosen, IoBackend::Tokio, "incapable kernel must fall back");
        }
    }

    #[test]
    fn submission_stub_reports_unsupported() {
        let err = submit_fsync(-1, false).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::Unsupported);
    }
}
