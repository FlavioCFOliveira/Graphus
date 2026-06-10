//! Async Unix-domain-socket listener and connection (the default `graphus-cli` transport).
//!
//! UDS is the highest-efficiency local transport (`04` connections section): in-kernel, no TLS,
//! authenticated by `SO_PEERCRED` ([`PeerCred`]) plus filesystem permissions (`04 §8.4`). Like the
//! TCP side this is the epoll/kqueue baseline driven by the Tokio runtime.

use std::io;
use std::path::{Path, PathBuf};

use tokio::net::{UnixListener, UnixStream};

use super::peer::PeerCred;

/// An async Unix-domain-socket acceptor bound to a filesystem path.
///
/// The bound socket path is unlinked when the acceptor is dropped, so a clean shutdown
/// (`04 §9.4`) leaves no stale socket file behind. If a stale socket from a previous crashed run
/// already occupies the path, [`UdsAcceptor::bind`] removes it first (a leftover socket inode is
/// never a live listener — `bind(2)` would otherwise fail with `EADDRINUSE`).
#[derive(Debug)]
pub struct UdsAcceptor {
    listener: UnixListener,
    path: PathBuf,
}

impl UdsAcceptor {
    /// Binds a Unix-domain-socket listener at `path`.
    ///
    /// Any pre-existing socket file at `path` is removed first (see the type docs). The caller is
    /// responsible for choosing a path inside a directory with appropriate permissions, which —
    /// together with `SO_PEERCRED` — is the UDS authorization story (`04 §8.4`).
    ///
    /// # Errors
    /// Returns the `std::io::Error` from removing a stale socket (other than "not found") or from
    /// `bind(2)`/`listen(2)`.
    pub fn bind<P: AsRef<Path>>(path: P) -> io::Result<Self> {
        let path = path.as_ref().to_path_buf();
        // Remove a stale socket inode left by a previous run. We only ignore `NotFound`; any other
        // error (e.g. permission, or a non-socket file we must not clobber) is surfaced.
        match std::fs::remove_file(&path) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
        // `UnixListener::bind` is non-blocking (it does not await) and is valid to call outside a
        // runtime; it registers the socket with the current reactor on first poll.
        let listener = UnixListener::bind(&path)?;
        Ok(Self { listener, path })
    }

    /// The filesystem path this listener is bound to.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Accepts the next inbound connection and captures its peer credentials.
    ///
    /// On Linux the returned [`UdsConn`] carries `SO_PEERCRED` (uid/gid/pid); on other platforms
    /// the credentials are `None` (see [`PeerCred`]). This call is cancellation-safe.
    ///
    /// # Errors
    /// Returns the `std::io::Error` from `accept(2)` or from reading peer credentials.
    pub async fn accept(&self) -> io::Result<UdsConn> {
        let (stream, _addr) = self.listener.accept().await?;
        // Capture credentials eagerly at accept time: the kernel attests the *connecting* peer, and
        // doing it once here means the server never re-reads it per request.
        let peer_cred = PeerCred::from_unix_stream(&stream)?;
        Ok(UdsConn { stream, peer_cred })
    }
}

impl Drop for UdsAcceptor {
    fn drop(&mut self) {
        // Best-effort unlink so a graceful shutdown leaves no stale socket. Errors are ignored: by
        // the time we drop, the fd is closed regardless, and a leftover inode is handled by the
        // next `bind`'s stale-socket removal above.
        let _ = std::fs::remove_file(&self.path);
    }
}

/// An accepted Unix-domain-socket connection: an `AsyncRead + AsyncWrite` byte stream plus the
/// peer's OS-attested credentials.
#[derive(Debug)]
pub struct UdsConn {
    stream: UnixStream,
    peer_cred: Option<PeerCred>,
}

impl UdsConn {
    /// The peer's `SO_PEERCRED` credentials, if the platform supplies them (`Some` on Linux).
    #[must_use]
    pub fn peer_cred(&self) -> Option<PeerCred> {
        self.peer_cred
    }

    /// Consumes the wrapper and returns the underlying Tokio [`UnixStream`].
    #[must_use]
    pub fn into_inner(self) -> UnixStream {
        self.stream
    }
}

impl tokio::io::AsyncRead for UdsConn {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::pin::Pin::new(&mut self.stream).poll_read(cx, buf)
    }
}

impl tokio::io::AsyncWrite for UdsConn {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<io::Result<usize>> {
        std::pin::Pin::new(&mut self.stream).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::pin::Pin::new(&mut self.stream).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::pin::Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}
