//! Unix-domain-socket peer credentials (`SO_PEERCRED`).
//!
//! When a client connects over a Unix domain socket, the kernel can report the connecting
//! process's effective `uid`, `gid` and `pid` (`SO_PEERCRED`, `getsockopt(2)`). Graphus uses
//! this for local peer authentication (`04 §8.4`): UDS has no TLS — it is a kernel-protected
//! local channel — so identity is established from the OS-attested peer credentials plus the
//! socket's filesystem permissions.
//!
//! This crate deliberately does **not** depend on `graphus-auth`: `graphus-io` is a low-level
//! substrate and must not pull a connectivity-layer crate (`04 §1.2` dependency rule). It
//! therefore surfaces its own plain [`PeerCred`] value and lets the listener wiring (rmp #20)
//! map it onto the auth model.

/// OS-attested credentials of the process on the other end of a Unix domain socket.
///
/// Obtained from `SO_PEERCRED` at accept time (see [`crate::net::UdsConn::peer_cred`]). Only
/// meaningful for UDS connections; TCP connections never carry it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerCred {
    /// Effective user id of the peer process.
    pub uid: u32,
    /// Effective group id of the peer process.
    pub gid: u32,
    /// Process id of the peer, when the platform reports it (`None` if unavailable).
    pub pid: Option<i32>,
}

impl PeerCred {
    /// Extracts the peer credentials from an accepted Tokio [`tokio::net::UnixStream`].
    ///
    /// Returns `Ok(Some(cred))` on platforms that support `SO_PEERCRED` (Linux), `Ok(None)` on
    /// platforms where peer credentials are not available through this mechanism, and `Err` only
    /// if the underlying `getsockopt` fails on a platform that does support it.
    ///
    /// # Errors
    /// Propagates the `std::io::Error` from `UnixStream::peer_cred` on supported platforms.
    #[cfg(target_os = "linux")]
    pub(crate) fn from_unix_stream(
        stream: &tokio::net::UnixStream,
    ) -> std::io::Result<Option<Self>> {
        // `peer_cred()` wraps `getsockopt(SO_PEERCRED)`; it is a pure socket-metadata read, not a
        // blocking I/O syscall, so calling it on a runtime worker does not violate the §9.1 rule.
        let creds = stream.peer_cred()?;
        Ok(Some(Self {
            uid: creds.uid(),
            gid: creds.gid(),
            // `UCred::pid()` returns `Option<i32>` (the kernel may not have recorded a pid).
            pid: creds.pid(),
        }))
    }

    /// Non-Linux fallback: peer credentials are not surfaced.
    ///
    /// macOS exposes `LOCAL_PEERCRED`/`getpeereid` with different semantics (no pid, and a
    /// different `getsockopt` level); Graphus treats UDS peer-cred auth as a Linux capability for
    /// now and returns `None` elsewhere so the build stays portable. The listener (rmp #20) is
    /// expected to fall back to filesystem socket permissions where this is `None`.
    #[cfg(not(target_os = "linux"))]
    pub(crate) fn from_unix_stream(
        _stream: &tokio::net::UnixStream,
    ) -> std::io::Result<Option<Self>> {
        Ok(None)
    }
}
