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
    /// Uses Tokio's cross-platform [`tokio::net::UnixStream::peer_cred`], which wraps
    /// `getsockopt(SO_PEERCRED)` on Linux and `getpeereid` / `LOCAL_PEERCRED` on macOS/BSD. It is
    /// therefore available on **every** Graphus Tier-1 target (x86_64/aarch64 Linux and aarch64
    /// macOS), so UDS peer-credential authentication (`04 §8.4`) works on Apple Silicon as well as
    /// Linux — previously it was gated to Linux only and the listener fail-closed-refused every UDS
    /// connection on macOS ("peer credentials unavailable on this platform"). `uid`/`gid` are always
    /// reported; `pid` only where the platform records it (`None` on macOS/BSD, whose `getpeereid`
    /// carries no pid — Graphus authenticates on the **uid**, so the missing pid is immaterial).
    ///
    /// Returns `Ok(Some(cred))` on success and `Err` only if the underlying `getsockopt` fails.
    ///
    /// # Errors
    /// Propagates the `std::io::Error` from [`tokio::net::UnixStream::peer_cred`].
    pub(crate) fn from_unix_stream(
        stream: &tokio::net::UnixStream,
    ) -> std::io::Result<Option<Self>> {
        // `peer_cred()` is a pure socket-metadata read (`getsockopt`), not a blocking I/O syscall, so
        // calling it on a runtime worker does not violate the §9.1 rule. Tokio implements it for every
        // Graphus Tier-1 platform.
        let creds = stream.peer_cred()?;
        Ok(Some(Self {
            uid: creds.uid(),
            gid: creds.gid(),
            // `UCred::pid()` returns `Option<i32>` — `None` on macOS/BSD (getpeereid carries no pid).
            pid: creds.pid(),
        }))
    }
}
