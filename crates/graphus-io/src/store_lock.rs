//! Exclusive advisory store-open lock (`rmp` #563).
//!
//! [`StoreOpenLock`] is an `flock(2)`-based advisory **exclusive** lock on a `store.lock` file in a
//! store's directory. It is acquired the instant a store is opened (the initial server open **and**
//! every `START DATABASE`) and held for the whole lifetime of the engine that owns the store,
//! released only when the store is fully closed (the lock's file handle is dropped, after the final
//! flush). It exists to make a *second* open of the same store **fail fast** instead of tearing the
//! on-disk image with two concurrent writers.
//!
//! ## The bug it closes (`rmp` #555/#563)
//!
//! `STOP DATABASE` bounds the engine drain with a deadline (`rmp` #450). On elapse it **force-detaches**
//! the engine: it drops the thread `JoinHandle` *without joining*, so the OS thread keeps running —
//! and if that thread was mid-`store.flush()`, it keeps **writing the store files**. When the process
//! stays alive (the STOP→START path, not whole-process shutdown), a following `START DATABASE` reopens
//! the **same** files while the zombie is still writing them → two concurrent writers → a logically
//! inconsistent multi-page on-disk image → durable corruption (the observed
//! `PropertyChain{Node …, DeadProp}`). This lock makes that reopen fail loudly rather than race.
//!
//! ## Why `flock(2)` and not POSIX `fcntl` record locks
//!
//! The corruption window is **intra-process**: the zombie engine thread and the `START` engine live in
//! the *same* process. An advisory lock must therefore conflict between two *open file descriptions*
//! held by one process. `flock(2)` locks are associated with the open file description, so two
//! independent `open(2)`s of the same file — even in one process — conflict. From the Linux `flock(2)`
//! man page: *"If a process uses open(2) (or similar) to obtain more than one file descriptor for the
//! same file, these file descriptors are treated independently by flock(). An attempt to lock the file
//! using one of these file descriptors may be denied by a lock that the calling process has placed via
//! another file descriptor."* POSIX `fcntl(F_SETLK)` record locks are per `(process, inode)` and would
//! **not** conflict within one process — useless here. Linux `F_OFD_SETLK` would work but is
//! Linux-only; `flock(2)` is available on Linux, macOS and Raspberry Pi OS — all of Graphus's target
//! platforms (`04 §1`).
//!
//! We call `flock(2)` through [`rustix::fs::flock`] — a safe, `unsafe`-free wrapper — so this crate
//! stays `#![forbid(unsafe_code)]` **and** within the workspace MSRV (`std::fs::File::try_lock` would
//! do the same but is only stable since Rust 1.89, above the declared `rust-version = 1.85`). (On the
//! few platforms where `flock` is emulated via `fcntl` — Solaris/illumos — the same-process guarantee
//! would not hold; those are not Graphus targets, and the
//! [`double_open_same_process_conflicts`](self) regression test would fail loudly on such a platform.)

use std::fs::{File, OpenOptions};
use std::path::{Path, PathBuf};

use rustix::fs::{FlockOperation, flock};

use graphus_core::error::{GraphusError, Result};

/// The fixed lock-file name inside a store directory.
pub const STORE_LOCK_FILE: &str = "store.lock";

/// A held exclusive advisory open-lock on a store directory's `store.lock`.
///
/// Dropping it (when the store closes) releases the underlying `flock`. The value is otherwise inert
/// — it carries no API surface beyond its RAII lifetime; holding it alive is the entire contract.
#[derive(Debug)]
pub struct StoreOpenLock {
    /// Holds the `flock` for the guard's lifetime: the lock is released when this handle is closed
    /// (dropped). Never read — its open file description *is* the lock.
    _file: File,
    /// The lock-file path (diagnostics / tests only).
    path: PathBuf,
}

impl StoreOpenLock {
    /// Acquires the exclusive advisory open-lock for the store in `dir`, creating `dir/store.lock`
    /// if absent (never truncating it). **Non-blocking**: if another live open file description
    /// already holds it — another engine, possibly a force-detached zombie still flushing the store
    /// — this returns an error immediately rather than blocking or, far worse, opening the store for
    /// a second concurrent writer.
    ///
    /// # Errors
    /// * [`GraphusError::Storage`] with a clear, retriable message if the lock is already held.
    /// * [`GraphusError::Storage`] if the lock file cannot be created / opened / locked.
    pub fn acquire(dir: &Path) -> Result<Self> {
        let path = dir.join(STORE_LOCK_FILE);
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(&path)
            .map_err(|e| {
                GraphusError::Storage(format!("opening store lock file {}: {e}", path.display()))
            })?;
        // Non-blocking exclusive `flock`: EWOULDBLOCK/EAGAIN means another open file description (an
        // engine, possibly a force-detached zombie still writing) already holds it.
        match flock(&file, FlockOperation::NonBlockingLockExclusive) {
            Ok(()) => Ok(Self { _file: file, path }),
            Err(e) if e == rustix::io::Errno::WOULDBLOCK || e == rustix::io::Errno::AGAIN => {
                Err(GraphusError::Storage(format!(
                    "store directory {} is already open by another engine (a previous engine may \
                     still be shutting down / flushing); refusing to open it a second time to avoid \
                     two concurrent writers corrupting the store — retry shortly",
                    dir.display()
                )))
            }
            Err(e) => Err(GraphusError::Storage(format!(
                "acquiring the exclusive store-open lock on {}: {e}",
                path.display()
            ))),
        }
    }

    /// The lock-file path this guard holds (diagnostics / tests).
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    static COUNTER: AtomicU64 = AtomicU64::new(0);

    fn temp_dir() -> PathBuf {
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let dir =
            std::env::temp_dir().join(format!("graphus-storelock-{}-{n}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// The core guarantee: a second acquire, **in the same process** (the STOP→START zombie window),
    /// fails while the first is still held. This is also the platform check that the standard library
    /// backs `try_lock` with `flock` (per open-file-description), not `fcntl` (per process) — under
    /// `fcntl` emulation the second acquire would spuriously succeed and this assertion would fail.
    #[test]
    fn double_open_same_process_conflicts() {
        let dir = temp_dir();
        let first = StoreOpenLock::acquire(&dir).expect("first acquire succeeds");
        let second = StoreOpenLock::acquire(&dir);
        assert!(
            second.is_err(),
            "a second open of the same store directory must fail while the first lock is held"
        );
        drop(first);
        std::fs::remove_dir_all(&dir).ok();
    }

    /// Releasing the lock (dropping the guard — what happens when the store finally closes after its
    /// last flush) lets the next open succeed. This is the clean STOP→START path: the previous engine
    /// fully exited, so the lock is free.
    #[test]
    fn reacquire_after_release_succeeds() {
        let dir = temp_dir();
        let first = StoreOpenLock::acquire(&dir).expect("first acquire succeeds");
        drop(first);
        let second = StoreOpenLock::acquire(&dir).expect("acquire after release succeeds");
        drop(second);
        std::fs::remove_dir_all(&dir).ok();
    }

    /// Two *different* store directories never conflict — one tenant's engine must not block another's.
    #[test]
    fn distinct_directories_do_not_conflict() {
        let dir_a = temp_dir();
        let dir_b = temp_dir();
        let a = StoreOpenLock::acquire(&dir_a).expect("dir A acquire succeeds");
        let b = StoreOpenLock::acquire(&dir_b).expect("dir B acquire succeeds while A is held");
        drop(a);
        drop(b);
        std::fs::remove_dir_all(&dir_a).ok();
        std::fs::remove_dir_all(&dir_b).ok();
    }
}
