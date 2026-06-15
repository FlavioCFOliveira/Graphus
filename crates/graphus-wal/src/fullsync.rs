//! Platform-correct durability barrier for the WAL on-disk segments.
//!
//! On macOS (APFS/HFS+), a plain `fsync(2)`/`fdatasync(2)` flushes the kernel page cache to the
//! drive but does **not** flush the drive's own volatile write cache, so a power loss after a
//! "successful" sync can still lose the just-committed WAL bytes — a direct ACID-durability
//! violation on the commit path. Apple's documented remedy is `fcntl(fd, F_FULLFSYNC)` (macOS
//! `fsync(2)` man page; Apple Technical Q&A QA1067); SQLite (`os_unix.c`) and PostgreSQL (`fd.c`)
//! both do this on Darwin.
//!
//! `graphus-wal` is a deliberately lean leaf crate (only `graphus-core` + `crc32c`), so rather than
//! depend on `graphus-io` (which would pull in Tokio), it carries this minimal, self-contained
//! barrier. The non-macOS path compiles no `unsafe` and no `libc`; the macOS path is this crate's
//! only `unsafe`, with a `// SAFETY:` justification.

use std::fs::File;

use graphus_core::error::{GraphusError, Result};

/// `fdatasync`s `file` with a true stable-storage barrier on every platform (`F_FULLFSYNC` on
/// macOS, `fdatasync` elsewhere). `context` labels the error.
///
/// # Errors
/// Returns a [`GraphusError::Storage`] wrapping the underlying I/O error. The WAL commit path treats
/// any such error as unrecoverable (fsyncgate; the caller panics).
pub(crate) fn full_sync_data(file: &File, context: &str) -> Result<()> {
    let res = {
        #[cfg(target_os = "macos")]
        {
            full_fsync_or_fallback(file, || file.sync_data())
        }
        #[cfg(not(target_os = "macos"))]
        {
            file.sync_data()
        }
    };
    res.map_err(|e| GraphusError::Storage(format!("{context}: {e}")))
}

/// Issues `fcntl(fd, F_FULLFSYNC)` on macOS, falling back to a plain `sync_data` only when the
/// platform reports the command is unsupported for this fd. Any other error is propagated unchanged
/// (a genuine I/O failure must not be masked by a weaker barrier).
#[cfg(target_os = "macos")]
#[allow(unsafe_code)]
fn full_fsync_or_fallback<F>(file: &File, fallback: F) -> std::io::Result<()>
where
    F: FnOnce() -> std::io::Result<()>,
{
    use std::os::unix::io::AsRawFd;

    let fd = file.as_raw_fd();
    // SAFETY: `fd` is a valid, open descriptor borrowed from `file: &File`, which outlives this
    // call. `F_FULLFSYNC` takes no pointer/length argument, so there is no buffer/memory-safety
    // obligation; `fcntl` only acts on the descriptor. The return value is checked below.
    let rc = unsafe { libc::fcntl(fd, libc::F_FULLFSYNC) };
    if rc == -1 {
        let err = std::io::Error::last_os_error();
        match err.raw_os_error() {
            Some(code) if code == libc::ENOTSUP || code == libc::ENOTTY || code == libc::EINVAL => {
                fallback()
            }
            _ => Err(err),
        }
    } else {
        Ok(())
    }
}
