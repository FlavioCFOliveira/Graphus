//! Platform-correct durability barriers.
//!
//! On most platforms `fsync(2)`/`fdatasync(2)` are the strongest durability barriers an application
//! can issue, and the kernel guarantees the data has reached stable storage when they return. On
//! **macOS (and the APFS/HFS+ filesystems)** this is *not* true: `fsync(2)` only flushes the data
//! from the kernel page cache to the drive, but does **not** ask the drive to flush its own volatile
//! write cache. A power loss after a "successful" `fsync` can therefore still lose the just-committed
//! bytes. Apple documents the remedy as `fcntl(fd, F_FULLFSYNC)`, which additionally asks the drive
//! to flush its track cache to the media (see the macOS `fsync(2)` man page and Apple Technical
//! Q&A QA1067). SQLite (`os_unix.c`, `full_fsync`) and PostgreSQL (`fd.c`, `pg_fsync`) take exactly
//! this approach on Darwin.
//!
//! These helpers therefore route to `F_FULLFSYNC` on macOS and to the ordinary
//! `sync_data`/`sync_all` everywhere else. On macOS, if `F_FULLFSYNC` is not supported by the
//! underlying device/filesystem (the kernel returns `ENOTSUP`/`ENOTTY`/`EINVAL` — e.g. some network
//! or virtualized filesystems), they fall back to `sync_data`/`sync_all`, which is the strongest
//! barrier those backends offer.
//!
//! The non-macOS path compiles no `unsafe` and pulls in no `libc`; the macOS path is the crate's
//! only `unsafe` outside the optional io_uring feature, with a `// SAFETY:` justification.

use std::fs::File;
use std::io;

/// Flushes file data and the minimum metadata needed to read it back, with a true
/// stable-storage barrier on every supported platform (`F_FULLFSYNC` on macOS, `fdatasync`
/// elsewhere).
///
/// # Errors
/// Returns the underlying `std::io::Error`. Per the fsyncgate semantics, a WAL/data-path caller must
/// treat any such error as unrecoverable.
pub fn full_sync_data(file: &File) -> io::Result<()> {
    #[cfg(target_os = "macos")]
    {
        full_fsync_or_fallback(file, || file.sync_data())
    }
    #[cfg(not(target_os = "macos"))]
    {
        file.sync_data()
    }
}

/// Flushes file data and all metadata, with a true stable-storage barrier on every supported
/// platform (`F_FULLFSYNC` on macOS, `fsync` elsewhere).
///
/// # Errors
/// As [`full_sync_data`].
pub fn full_sync_all(file: &File) -> io::Result<()> {
    #[cfg(target_os = "macos")]
    {
        full_fsync_or_fallback(file, || file.sync_all())
    }
    #[cfg(not(target_os = "macos"))]
    {
        file.sync_all()
    }
}

/// Issues `fcntl(fd, F_FULLFSYNC)` on macOS, falling back to `fallback` (an ordinary
/// `sync_data`/`sync_all`) only when the platform reports the command is unsupported for this fd.
///
/// Any other error from `F_FULLFSYNC` is propagated unchanged: a genuine I/O failure must *not* be
/// masked by silently downgrading to a weaker barrier (that would reintroduce the durability hole).
#[cfg(target_os = "macos")]
#[allow(unsafe_code)]
fn full_fsync_or_fallback<F>(file: &File, fallback: F) -> io::Result<()>
where
    F: FnOnce() -> io::Result<()>,
{
    use std::os::unix::io::AsRawFd;

    let fd = file.as_raw_fd();
    // SAFETY: `fd` is a valid, open file descriptor for the lifetime of this call because it is
    // borrowed from `file: &File` (the `File` outlives the syscall). `F_FULLFSYNC` takes no
    // pointer/length argument, so there is no buffer aliasing or memory-safety obligation; `fcntl`
    // only reads the descriptor. The return value is checked below.
    let rc = unsafe { libc::fcntl(fd, libc::F_FULLFSYNC) };
    if rc == -1 {
        let err = io::Error::last_os_error();
        // The device/filesystem does not implement F_FULLFSYNC for this fd. Fall back to the
        // ordinary barrier, which is the strongest such a backend offers. ENOTTY/EINVAL are the
        // observed codes from filesystems that reject the ioctl-style command; ENOTSUP is the
        // documented "operation not supported" code.
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
