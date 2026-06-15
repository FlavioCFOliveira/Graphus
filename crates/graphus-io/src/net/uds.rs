//! Async Unix-domain-socket listener and connection (the default `graphus-cli` transport).
//!
//! UDS is the highest-efficiency local transport (`04` connections section): in-kernel, no TLS,
//! authenticated by `SO_PEERCRED` ([`PeerCred`]) plus filesystem permissions (`04 §8.4`). The
//! filesystem-permission half is enforced by [`UdsAcceptor::bind`], which restricts the socket to
//! owner-only (`0o600`) immediately after bind, before any connection is accepted (SEC-176). Like the
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
    /// Binds a Unix-domain-socket listener at `path`, restricting the socket to owner-only access
    /// (mode `0o600`) before it becomes connectable.
    ///
    /// Any pre-existing socket file at `path` is removed first (see the type docs). The caller is
    /// responsible for choosing a path inside a directory with appropriate permissions, which —
    /// together with the socket mode applied here and `SO_PEERCRED` — is the UDS authorization story
    /// (`04 §8.4`).
    ///
    /// # Security (SEC-176, CWE-276 / CWE-732)
    /// `UnixListener::bind` creates the socket inode under the process `umask`, which on a typical
    /// host leaves it world-connectable (`0o775`). That contradicts the documented "filesystem
    /// permissions" half of the UDS authorization story and lets any local process reach the Bolt
    /// parser pre-auth (a local DoS / attack-surface concern). To close this, the socket is `chmod`ed
    /// to `0o600` **immediately after** `bind`, before this function returns and therefore before the
    /// caller ever issues an [`accept`](Self::accept) — so no connection is served while the socket is
    /// at the looser umask mode.
    ///
    /// The mode is applied **in place** (not via a temp-path + atomic rename) because a UDS path is
    /// length-bounded (`SUN_LEN`, ~108 bytes on Linux): a longer staging sibling could overflow it.
    /// The residual window between `bind` and `chmod` is a few instructions wide and the socket is
    /// not yet polled for connections; defence-in-depth `SO_PEERCRED` still gates every accepted peer.
    ///
    /// On non-Unix targets (where this listener is not used in practice) the mode step is a no-op.
    ///
    /// # Errors
    /// Returns the `std::io::Error` from removing a stale socket (other than "not found"), from
    /// `bind(2)`/`listen(2)`, or from restricting the socket mode.
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

        // Restrict to owner-only (SEC-176) immediately, before any `accept`. If the chmod fails we
        // must not leave a world-connectable socket behind: drop the listener and unlink it.
        #[cfg(unix)]
        if let Err(e) = Self::restrict_mode(&path) {
            drop(listener);
            let _ = std::fs::remove_file(&path);
            return Err(e);
        }

        Ok(Self { listener, path })
    }

    /// Restricts a freshly-bound socket inode to owner-only access (`0o600`) — SEC-176.
    #[cfg(unix)]
    fn restrict_mode(path: &Path) -> io::Result<()> {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
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

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt as _;

    /// A unique temp socket path that is unlinked on drop.
    struct TempSock(PathBuf);

    impl TempSock {
        fn new(tag: &str) -> Self {
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let mut p = std::env::temp_dir();
            p.push(format!("graphus-uds-{tag}-{nanos}-{}.sock", std::process::id()));
            Self(p)
        }
    }

    impl Drop for TempSock {
        fn drop(&mut self) {
            let _ = std::fs::remove_file(&self.0);
        }
    }

    /// Regression: SEC-176 (CWE-276/732) — the bound socket must be owner-only; no group/world bit
    /// may be set, regardless of the process umask.
    #[tokio::test]
    async fn bind_restricts_socket_to_owner_only() {
        let sock = TempSock::new("perms");
        let acceptor = UdsAcceptor::bind(&sock.0).expect("bind succeeds");

        let mode = std::fs::metadata(&sock.0)
            .expect("the published socket exists")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(
            mode & 0o077,
            0,
            "the UDS socket must be owner-only (mode {mode:#o}); SEC-176 regressed"
        );
        drop(acceptor);
    }

    /// Restricting the mode must leave a *working* listener: the owner can still connect at the path
    /// (the restriction is on filesystem permissions, not reachability by the owner).
    #[tokio::test]
    async fn bound_socket_is_connectable() {
        let sock = TempSock::new("connect");
        let acceptor = UdsAcceptor::bind(&sock.0).expect("bind succeeds");

        let accept = tokio::spawn(async move { acceptor.accept().await.map(|_| ()) });
        let _client = UnixStream::connect(&sock.0).await.expect("client connects");
        accept
            .await
            .expect("accept task joins")
            .expect("server accepts the connection");
    }

    /// A pre-existing stale inode at the path must be cleared and rebound cleanly — the bind path is
    /// idempotent across crashed runs, and the rebound socket stays owner-only.
    #[tokio::test]
    async fn bind_replaces_a_stale_inode() {
        let sock = TempSock::new("stale");
        let first = UdsAcceptor::bind(&sock.0).expect("first bind");
        drop(first);
        // Simulate a crash that left an inode behind (recreate it as a plain file).
        std::fs::write(&sock.0, b"").expect("leave a stale file");
        let _second = UdsAcceptor::bind(&sock.0).expect("rebind over stale inode");
        let mode = std::fs::metadata(&sock.0).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode & 0o077, 0, "rebound socket stays owner-only");
    }
}
