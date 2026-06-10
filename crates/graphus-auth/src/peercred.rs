//! UDS peer-credential authentication (`SO_PEERCRED`; `04 §8.4`, `D-auth-scheme`).
//!
//! The Unix-domain-socket path has **no TLS** — it is a kernel-protected local channel — and
//! authenticates by the peer's OS credentials plus filesystem socket permissions. The kernel
//! reports the connected peer's `(uid, gid, pid)` via `getsockopt(SO_PEERCRED)` (Linux) /
//! `LOCAL_PEERCRED` / `getpeereid` (macOS/BSD). Graphus maps that **uid** to an RBAC
//! [`User`](crate::User), so a local process authenticates as whichever user the operator bound its
//! uid to — no password is exchanged.
//!
//! ## Seam for the server (rmp #18/#20)
//!
//! Reading the socket option is the **listener's** job, not this crate's, so the syscall is modeled
//! behind the [`PeerCredSource`] trait returning a plain [`PeerCred`]. This crate provides:
//!
//! - the [`PeerCred`] value type;
//! - the [`PeerCredSource`] trait (the server's real `UnixStream`-backed implementation calls
//!   `getsockopt`; tests use a mock);
//! - [`PeerCredMap`], the operator-configured `uid → username` mapping;
//! - [`PeerCredMap::authenticate`], which reads a source's credentials and resolves them to a
//!   known username, deny-by-default for any unmapped uid.
//!
//! No socket is ever opened here.

use std::collections::HashMap;
use std::io;

use crate::error::{AuthError, Result};

/// The OS credentials of a connected UDS peer, as reported by the kernel.
///
/// Mirrors Linux's `struct ucred`. `gid`/`pid` are carried for completeness and for any future
/// group-based policy or audit logging; authentication keys on `uid`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerCred {
    /// The peer process's effective user id.
    pub uid: u32,
    /// The peer process's effective group id.
    pub gid: u32,
    /// The peer process's id (informational / audit).
    pub pid: i32,
}

/// A source of peer credentials for a single UDS connection.
///
/// The production implementation (in `graphus-server`) wraps a `UnixStream` and calls
/// `getsockopt(SO_PEERCRED)`; it is intentionally **not** implemented in this crate so that
/// `graphus-auth` opens no sockets and stays unit-testable. Tests implement it trivially.
pub trait PeerCredSource {
    /// Reads the connected peer's OS credentials.
    ///
    /// # Errors
    /// Returns the underlying I/O error if the credentials cannot be read (e.g. the socket is not
    /// a connected UDS, or the platform call fails).
    fn peer_cred(&self) -> io::Result<PeerCred>;
}

/// An operator-configured mapping from OS uid to RBAC username for the UDS interface.
///
/// Deny-by-default: a uid with no entry resolves to no user and cannot authenticate. The map holds
/// only usernames (strings); the resolved name is then looked up in the [`Catalog`](crate::Catalog)
/// by the caller (or via [`crate::auth::Authenticator`]) to obtain the actual
/// [`User`](crate::User) and its privileges, so this type stays free of any catalog borrow.
#[derive(Debug, Clone, Default)]
pub struct PeerCredMap {
    uid_to_user: HashMap<u32, String>,
}

impl PeerCredMap {
    /// Creates an empty mapping (authenticates nobody until uids are bound).
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Binds `uid` to `username` (overwriting any previous binding for that uid).
    pub fn map_uid(&mut self, uid: u32, username: impl Into<String>) {
        self.uid_to_user.insert(uid, username.into());
    }

    /// Removes any binding for `uid`.
    pub fn unmap_uid(&mut self, uid: u32) {
        self.uid_to_user.remove(&uid);
    }

    /// Returns the username bound to `cred.uid`, or `None` if the uid is unmapped.
    #[must_use]
    pub fn map_peer_to_user(&self, cred: &PeerCred) -> Option<&str> {
        self.uid_to_user.get(&cred.uid).map(String::as_str)
    }

    /// Reads `source`'s peer credentials and resolves them to a mapped username.
    ///
    /// This is the UDS authentication entry point: a connection is authenticated as the username
    /// its peer uid is bound to.
    ///
    /// # Errors
    /// - The source's I/O error (wrapped as [`AuthError::Unauthenticated`]) if credentials cannot
    ///   be read — an unreadable peer cannot be trusted.
    /// - [`AuthError::Unauthenticated`] if the uid maps to no user (deny-by-default), deliberately
    ///   indistinguishable from a missing credential so an unmapped local user learns nothing.
    pub fn authenticate(&self, source: &impl PeerCredSource) -> Result<String> {
        let cred = source.peer_cred().map_err(|_| AuthError::Unauthenticated)?;
        self.map_peer_to_user(&cred)
            .map(ToOwned::to_owned)
            .ok_or(AuthError::Unauthenticated)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A mock peer-credential source returning a fixed result (no socket involved).
    struct MockSource(io::Result<PeerCred>);

    impl PeerCredSource for MockSource {
        fn peer_cred(&self) -> io::Result<PeerCred> {
            // Clone the stored result (PeerCred is Copy; io::Error is not, so reconstruct it).
            match &self.0 {
                Ok(c) => Ok(*c),
                Err(e) => Err(io::Error::new(e.kind(), "mock peercred failure")),
            }
        }
    }

    fn cred(uid: u32) -> PeerCred {
        PeerCred {
            uid,
            gid: uid,
            pid: 4242,
        }
    }

    #[test]
    fn maps_known_uid_to_user() {
        let mut map = PeerCredMap::new();
        map.map_uid(1000, "alice");
        let src = MockSource(Ok(cred(1000)));
        assert_eq!(map.authenticate(&src).unwrap(), "alice");
    }

    #[test]
    fn unmapped_uid_is_unauthenticated() {
        let mut map = PeerCredMap::new();
        map.map_uid(1000, "alice");
        let src = MockSource(Ok(cred(2000)));
        assert_eq!(map.authenticate(&src), Err(AuthError::Unauthenticated));
    }

    #[test]
    fn unreadable_credentials_are_unauthenticated() {
        let map = PeerCredMap::new();
        let src = MockSource(Err(io::Error::from(io::ErrorKind::PermissionDenied)));
        assert_eq!(map.authenticate(&src), Err(AuthError::Unauthenticated));
    }

    #[test]
    fn unmap_revokes_access() {
        let mut map = PeerCredMap::new();
        map.map_uid(1000, "alice");
        map.unmap_uid(1000);
        let src = MockSource(Ok(cred(1000)));
        assert_eq!(map.authenticate(&src), Err(AuthError::Unauthenticated));
    }

    #[test]
    fn map_peer_to_user_is_pure_lookup() {
        let mut map = PeerCredMap::new();
        map.map_uid(0, "root");
        assert_eq!(map.map_peer_to_user(&cred(0)), Some("root"));
        assert_eq!(map.map_peer_to_user(&cred(1)), None);
    }
}
