//! The authentication facade the three listeners resolve to (`04 §8.3`, `§8.4`).
//!
//! [`Authenticator`] owns the [`Catalog`] (RBAC) and the per-interface authentication mechanisms,
//! and exposes the single set of operations each listener calls so that an identity has the **same
//! authorization regardless of entry point**:
//!
//! - **Bolt native (`LOGON`)** → [`Authenticator::authenticate_password`] (verifies a per-user
//!   Argon2 hash, constant-time).
//! - **REST Bearer** → [`Authenticator::authenticate_bearer`] (verifies an HS256 JWT and maps its
//!   subject back to a catalog user).
//! - **UDS `SO_PEERCRED`** → [`Authenticator::authenticate_peer`] (resolves a peer uid to a user).
//! - **Authorization** (all three) → [`Authenticator::authorize`], delegating to [`Catalog`].
//!
//! It also adds the per-user password operations (`set_password` / `verify_password`) on top of the
//! [`crate::password`] primitives, since those bind a hash to a [`User`](crate::User).
//!
//! Every authentication method returns the **username** of the resolved principal (deny-by-default
//! on any failure); the caller then attaches that identity to its session and gates each operation
//! through [`Authenticator::authorize`]. The JWT clock value (`now_unix_secs`) and the peer
//! credential source are passed in by the listener, keeping this type free of I/O and wall time.

use crate::error::{AuthError, Result};
use crate::limits::{RateLimiter, RequestLimits};
use crate::peercred::{PeerCredMap, PeerCredSource};
use crate::rbac::{Catalog, Privilege};
use crate::token::{Claims, JwtAuthenticator};
use crate::{password, tls};

use graphus_core::capability::Clock;
use rustls::ServerConfig;

/// The authentication operations the connectivity seams (`graphus-bolt`, `graphus-rest`) resolve
/// through their stored auth handle — the **live-vs-snapshot seam**.
///
/// `graphus-bolt` and `graphus-rest` are deliberately transport-agnostic and must not depend on
/// `graphus-server`, so they cannot hold a `SecurityCatalog` directly. Instead they hold a
/// `&dyn AuthProvider` (Bolt) / `Arc<dyn AuthProvider>` (REST) and call only the three methods
/// below. [`Authenticator`] implements this trait by delegating to its inherent methods, which lets
/// a *snapshot* satisfy the seam; `graphus-server` supplies a **live** implementation that resolves
/// every call through its read-locked `SecurityCatalog`, so a runtime `CREATE USER` /
/// password change / `DROP USER` takes effect for authentication immediately (no reboot).
///
/// Every method is non-generic, so the trait is fully object-safe (`dyn`-compatible) **by design**:
/// the seams store it behind a trait object. The generic UDS peer path
/// ([`Authenticator::authenticate_peer`], generic over [`PeerCredSource`]) is *not* on this trait;
/// that path is handled inside `graphus-server` directly, which can read the live catalog without a
/// trait object.
pub trait AuthProvider: Send + Sync {
    /// Bolt native (`LOGON`): authenticates `user` by password, returning the username on success.
    ///
    /// # Errors
    /// - [`AuthError::Unauthenticated`] on a wrong/missing password or unknown user.
    /// - [`AuthError::PasswordHash`] only if the stored hash is corrupt (operational fault).
    fn authenticate_password(&self, user: &str, plaintext: &str) -> Result<String>;

    /// REST Bearer: verifies a JWT (signature + expiry against `now_unix_secs`) and maps its subject
    /// back to a current catalog user, returning the validated [`Claims`].
    ///
    /// # Errors
    /// - [`AuthError::BadToken`] / [`AuthError::TokenExpired`] on an invalid/expired token.
    /// - [`AuthError::Unauthenticated`] if the subject names no current catalog user.
    fn authenticate_bearer(&self, token: &str, now_unix_secs: u64) -> Result<Claims>;

    /// Coarse authorization (the REST `READ`/`WRITE` access-mode gate): `Ok(())` if `user` holds
    /// `wanted`, else [`AuthError::Unauthorized`].
    ///
    /// # Errors
    /// [`AuthError::Unauthorized`] if `user` lacks `wanted`.
    fn require(&self, user: &str, wanted: &Privilege) -> Result<()>;
}

/// The shared authentication + authorization service for all listeners.
///
/// Construct it with a JWT signing secret, then populate the [`Catalog`] (users/roles/privileges)
/// and the [`PeerCredMap`] (uid bindings) through the delegating methods. `Clone` is cheap-ish (the
/// catalog and uid map are cloned); in the server it lives behind an `Arc`/lock owned by the
/// connection-accept loop.
#[derive(Debug, Clone)]
pub struct Authenticator {
    catalog: Catalog,
    jwt: JwtAuthenticator,
    peers: PeerCredMap,
}

impl Authenticator {
    /// Creates an authenticator with an empty catalog and uid map, using `jwt_secret` for HS256
    /// Bearer tokens.
    #[must_use]
    pub fn new(jwt_secret: &[u8]) -> Self {
        Self {
            catalog: Catalog::new(),
            jwt: JwtAuthenticator::new(jwt_secret),
            peers: PeerCredMap::new(),
        }
    }

    /// Shared access to the RBAC catalog (for user/role/privilege CRUD via its inherent methods).
    #[must_use]
    pub fn catalog(&self) -> &Catalog {
        &self.catalog
    }

    /// Mutable access to the RBAC catalog (create/drop users & roles, grant/revoke).
    pub fn catalog_mut(&mut self) -> &mut Catalog {
        &mut self.catalog
    }

    /// Mutable access to the UDS uid→user mapping.
    pub fn peers_mut(&mut self) -> &mut PeerCredMap {
        &mut self.peers
    }

    // ---- Per-user password operations --------------------------------------------------------

    /// Sets (or replaces) `user`'s password, storing only its Argon2 hash.
    ///
    /// # Errors
    /// - [`AuthError::NotFound`] if the user does not exist.
    /// - [`AuthError::PasswordHash`] if hashing fails.
    pub fn set_password(&mut self, user: &str, plaintext: &str) -> Result<()> {
        let hash = password::hash_password(plaintext)?;
        let u = self
            .catalog
            .user_mut(user)
            .ok_or_else(|| AuthError::NotFound {
                what: format!("user {user}"),
            })?;
        u.password_hash = Some(hash);
        Ok(())
    }

    /// Clears `user`'s password (after this, password auth for the user always fails until reset).
    ///
    /// # Errors
    /// [`AuthError::NotFound`] if the user does not exist.
    pub fn clear_password(&mut self, user: &str) -> Result<()> {
        let u = self
            .catalog
            .user_mut(user)
            .ok_or_else(|| AuthError::NotFound {
                what: format!("user {user}"),
            })?;
        u.password_hash = None;
        Ok(())
    }

    /// Verifies `plaintext` against `user`'s stored hash in constant time.
    ///
    /// Returns `Ok(true)` on a correct password, `Ok(false)` for an unknown user, a user with no
    /// password configured, or a wrong password — the negative cases are deliberately
    /// indistinguishable to the caller to avoid user-enumeration. Errors only on a corrupt stored
    /// hash.
    ///
    /// # Errors
    /// [`AuthError::PasswordHash`] if the stored hash cannot be parsed.
    pub fn verify_password(&self, user: &str, plaintext: &str) -> Result<bool> {
        match self
            .catalog
            .user(user)
            .and_then(|u| u.password_hash.as_deref())
        {
            Some(hash) => password::verify_password(plaintext, hash),
            None => Ok(false),
        }
    }

    // ---- Per-interface authentication --------------------------------------------------------

    /// Bolt native (`LOGON`): authenticates `user` by password, returning the username on success.
    ///
    /// # Errors
    /// - [`AuthError::Unauthenticated`] on a wrong/missing password or unknown user.
    /// - [`AuthError::PasswordHash`] only if the stored hash is corrupt (operational fault).
    pub fn authenticate_password(&self, user: &str, plaintext: &str) -> Result<String> {
        if self.verify_password(user, plaintext)? {
            Ok(user.to_owned())
        } else {
            Err(AuthError::Unauthenticated)
        }
    }

    /// REST Bearer: verifies a JWT (signature + expiry against `now_unix_secs`) and maps its subject
    /// back to a catalog user, returning the validated [`Claims`].
    ///
    /// Resolving the subject to a *known* user closes the gap between "the token is validly signed"
    /// and "the principal still exists": a token for a since-dropped user is rejected even though
    /// its signature checks out.
    ///
    /// # Errors
    /// - [`AuthError::BadToken`] / [`AuthError::TokenExpired`] per [`JwtAuthenticator::verify_bearer`].
    /// - [`AuthError::Unauthenticated`] if the subject names no current catalog user.
    pub fn authenticate_bearer(&self, token: &str, now_unix_secs: u64) -> Result<Claims> {
        let claims = self.jwt.verify_bearer(token, now_unix_secs)?;
        if self.catalog.has_user(&claims.sub) {
            Ok(claims)
        } else {
            Err(AuthError::Unauthenticated)
        }
    }

    /// Issues a Bearer token for `user`, valid for `ttl_secs` from `now_unix_secs`.
    ///
    /// # Errors
    /// - [`AuthError::NotFound`] if the user does not exist (only known users get tokens).
    /// - [`AuthError::BadToken`] if encoding fails.
    pub fn issue_token(&self, user: &str, now_unix_secs: u64, ttl_secs: u64) -> Result<String> {
        if !self.catalog.has_user(user) {
            return Err(AuthError::NotFound {
                what: format!("user {user}"),
            });
        }
        self.jwt.issue_token(user, now_unix_secs, ttl_secs)
    }

    /// UDS `SO_PEERCRED`: resolves a connection's peer credentials to a catalog user.
    ///
    /// Reads `source`'s peer uid, maps it to a username, and confirms that username is a current
    /// catalog user, returning it on success.
    ///
    /// # Errors
    /// [`AuthError::Unauthenticated`] if the credentials are unreadable, the uid is unmapped, or the
    /// mapped username is not a current catalog user.
    pub fn authenticate_peer(&self, source: &impl PeerCredSource) -> Result<String> {
        let user = self.peers.authenticate(source)?;
        if self.catalog.has_user(&user) {
            Ok(user)
        } else {
            Err(AuthError::Unauthenticated)
        }
    }

    // ---- Authorization -----------------------------------------------------------------------

    /// Returns `true` iff `user` is authorized for `wanted` (deny-by-default; see
    /// [`Catalog::authorize`]). The same call backs all three interfaces.
    #[must_use]
    pub fn authorize(&self, user: &str, wanted: &Privilege) -> bool {
        self.catalog.authorize(user, wanted)
    }

    /// [`authorize`](Self::authorize) as a `Result`: `Ok(())` if permitted, else
    /// [`AuthError::Unauthorized`]. Convenient for `?`-driven request handlers.
    ///
    /// # Errors
    /// [`AuthError::Unauthorized`] if `user` lacks `wanted`.
    pub fn require(&self, user: &str, wanted: &Privilege) -> Result<()> {
        if self.authorize(user, wanted) {
            Ok(())
        } else {
            Err(AuthError::Unauthorized)
        }
    }

    // ---- TLS + limits convenience ------------------------------------------------------------

    /// Builds the TLS 1.3-only [`ServerConfig`] for the network listeners from PEM material. See
    /// [`tls::tls_server_config`].
    ///
    /// # Errors
    /// [`AuthError::TlsConfig`] if the material is invalid.
    pub fn tls_server_config(&self, cert_pem: &str, key_pem: &str) -> Result<ServerConfig> {
        tls::tls_server_config(cert_pem, key_pem)
    }

    /// Creates a per-connection [`RateLimiter`] from the given parameters and clock. The server owns
    /// one limiter per connection (or per client key); this is a thin constructor delegating to
    /// [`RateLimiter::new`].
    ///
    /// # Errors
    /// [`AuthError::InvalidLimits`] if `capacity` or `refill_per_sec` is zero.
    pub fn rate_limiter(
        &self,
        capacity: u32,
        refill_per_sec: u32,
        clock: &dyn Clock,
    ) -> Result<RateLimiter> {
        RateLimiter::new(capacity, refill_per_sec, clock)
    }

    /// Validates and returns a [`RequestLimits`] config. Delegates to [`RequestLimits::new`].
    ///
    /// # Errors
    /// [`AuthError::InvalidLimits`] if either field is zero.
    pub fn request_limits(
        &self,
        max_body_bytes: u64,
        request_timeout: std::time::Duration,
    ) -> Result<RequestLimits> {
        RequestLimits::new(max_body_bytes, request_timeout)
    }
}

/// A point-in-time [`Authenticator`] (a clone/snapshot) satisfies the seam by delegating each method
/// to its inherent implementation. `graphus-server` supplies a *live* [`AuthProvider`] that resolves
/// the same three calls through its read-locked `SecurityCatalog`; both are interchangeable behind
/// the trait object the seams hold.
impl AuthProvider for Authenticator {
    fn authenticate_password(&self, user: &str, plaintext: &str) -> Result<String> {
        Authenticator::authenticate_password(self, user, plaintext)
    }

    fn authenticate_bearer(&self, token: &str, now_unix_secs: u64) -> Result<Claims> {
        Authenticator::authenticate_bearer(self, token, now_unix_secs)
    }

    fn require(&self, user: &str, wanted: &Privilege) -> Result<()> {
        Authenticator::require(self, user, wanted)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::peercred::PeerCred;
    use std::io;

    struct FixedPeer(PeerCred);
    impl PeerCredSource for FixedPeer {
        fn peer_cred(&self) -> io::Result<PeerCred> {
            Ok(self.0)
        }
    }

    /// An authenticator with one `alice` user (password `pw`, role `reader` → DB Read), uid 1000
    /// mapped to `alice`.
    fn fixture() -> Authenticator {
        let mut a = Authenticator::new(b"shared-jwt-secret-at-least-32-bytes!!");
        a.catalog_mut().create_user("alice").unwrap();
        a.catalog_mut().create_role("reader").unwrap();
        a.catalog_mut()
            .grant_privilege("reader", Privilege::read_database())
            .unwrap();
        a.catalog_mut().grant_role("alice", "reader").unwrap();
        a.set_password("alice", "pw").unwrap();
        a.peers_mut().map_uid(1000, "alice");
        a
    }

    #[test]
    fn password_auth_round_trips() {
        let a = fixture();
        assert_eq!(a.authenticate_password("alice", "pw").unwrap(), "alice");
        assert_eq!(
            a.authenticate_password("alice", "wrong"),
            Err(AuthError::Unauthenticated)
        );
        assert_eq!(
            a.authenticate_password("ghost", "pw"),
            Err(AuthError::Unauthenticated)
        );
    }

    #[test]
    fn set_password_requires_existing_user() {
        let mut a = fixture();
        assert!(matches!(
            a.set_password("ghost", "pw"),
            Err(AuthError::NotFound { .. })
        ));
    }

    #[test]
    fn cleared_password_cannot_authenticate() {
        let mut a = fixture();
        a.clear_password("alice").unwrap();
        assert_eq!(
            a.authenticate_password("alice", "pw"),
            Err(AuthError::Unauthenticated)
        );
    }

    #[test]
    fn bearer_auth_maps_subject_to_user() {
        let a = fixture();
        let token = a.issue_token("alice", 1000, 3600).unwrap();
        let claims = a.authenticate_bearer(&token, 1100).unwrap();
        assert_eq!(claims.sub, "alice");
    }

    #[test]
    fn bearer_for_dropped_user_is_rejected() {
        let mut a = fixture();
        let token = a.issue_token("alice", 1000, 3600).unwrap();
        a.catalog_mut().drop_user("alice").unwrap();
        // Signature still valid, but the principal no longer exists.
        assert_eq!(
            a.authenticate_bearer(&token, 1100),
            Err(AuthError::Unauthenticated)
        );
    }

    #[test]
    fn issue_token_requires_existing_user() {
        let a = fixture();
        assert!(matches!(
            a.issue_token("ghost", 1000, 3600),
            Err(AuthError::NotFound { .. })
        ));
    }

    #[test]
    fn peer_auth_resolves_uid_to_user() {
        let a = fixture();
        let src = FixedPeer(PeerCred {
            uid: 1000,
            gid: 1000,
            pid: 1,
        });
        assert_eq!(a.authenticate_peer(&src).unwrap(), "alice");
        // An unmapped uid is denied.
        let other = FixedPeer(PeerCred {
            uid: 4242,
            gid: 0,
            pid: 1,
        });
        assert_eq!(a.authenticate_peer(&other), Err(AuthError::Unauthenticated));
    }

    #[test]
    fn peer_mapped_to_dropped_user_is_rejected() {
        let mut a = fixture();
        a.catalog_mut().drop_user("alice").unwrap();
        let src = FixedPeer(PeerCred {
            uid: 1000,
            gid: 1000,
            pid: 1,
        });
        assert_eq!(a.authenticate_peer(&src), Err(AuthError::Unauthenticated));
    }

    #[test]
    fn authorization_is_shared_across_interfaces() {
        let a = fixture();
        // Whatever interface authenticated alice, she has DB Read but not DB Write.
        assert!(a.authorize("alice", &Privilege::read_database()));
        assert!(!a.authorize("alice", &Privilege::write_database()));
        assert!(a.require("alice", &Privilege::read_database()).is_ok());
        assert_eq!(
            a.require("alice", &Privilege::write_database()),
            Err(AuthError::Unauthorized)
        );
    }
}
