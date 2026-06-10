//! `graphus-auth` — the shared authentication, authorization, and TLS layer for Graphus
//! (`specification/04-technical-design.md` §8.4; decisions `D-auth-scheme`, `D-security-scope`).
//!
//! All three listeners (UDS, Bolt-over-TCP, REST) authenticate by their own scheme but resolve to
//! **one shared RBAC model**, so an identity has the **same authorization regardless of entry
//! point** (`04 §8.3`/`§8.4`). This crate is the in-process, fully testable core of that layer; the
//! actual network handshake (TLS stream, `getsockopt(SO_PEERCRED)`) is wired by the
//! server/listeners (rmp #18/#19/#20) at the seams this crate exposes — **no socket is opened
//! here**.
//!
//! ## What this crate provides
//!
//! - **RBAC** ([`rbac`]): [`User`], [`Role`], [`Privilege`] ([`Action`] × [`Resource`]) and a
//!   [`Catalog`] with user/role CRUD, grant/revoke, and a deny-by-default
//!   [`authorize`](Catalog::authorize) that unions the user's roles' privileges; `Admin` implies
//!   all actions over the same (or, for the database, every) resource (`04 §8.4`).
//! - **Password credentials** ([`password`]) for Bolt native `LOGON`: Argon2id hashing with
//!   constant-time verification; plaintext is never stored.
//! - **JWT / Bearer** ([`token`]) for REST (RFC 6750 / RFC 7519): HS256 issue + verify with a
//!   subject and expiry, expiry checked against an **injected clock** for deterministic tests.
//! - **UDS peer credentials** ([`peercred`]): the [`PeerCred`] value, the [`PeerCredSource`] seam
//!   (the server's real `SO_PEERCRED` implementation), and a uid→user [`PeerCredMap`].
//! - **Rate limiting + request limits** ([`limits`]): a token-bucket [`RateLimiter`] driven by
//!   [`graphus_core::capability::Clock`] (never wall time) and a validated [`RequestLimits`].
//! - **TLS** ([`tls`]): [`tls_server_config`] builds a **TLS 1.3-only** [`rustls::ServerConfig`]
//!   from PEM material (the handshake stays the server's job).
//! - **The [`Authenticator`] facade** ([`auth`]): the single object each listener holds, tying the
//!   catalog and the per-interface mechanisms together (`authenticate_password` /
//!   `authenticate_bearer` / `authenticate_peer` / `authorize`).
//!
//! ## Seams left for the server (deliberately out of scope here)
//!
//! - [`PeerCredSource`] — the real `getsockopt(SO_PEERCRED)` over a `UnixStream` lives in
//!   `graphus-server`; this crate ships only the trait + a [`PeerCredMap`] and is tested with mocks.
//! - The TLS **handshake / accept loop** — [`tls_server_config`] returns a ready config; performing
//!   the handshake and binding sockets is the listener's job.
//! - The wall-clock → `now_unix_secs` derivation for JWTs and the per-connection clock for the
//!   rate limiter are passed in by the server from its production
//!   [`Clock`](graphus_core::capability::Clock).
//!
//! ## Errors
//!
//! Everything fallible returns the crate's own rich [`AuthError`]; it converts into
//! [`GraphusError::Protocol`](graphus_core::GraphusError) at the connectivity boundary.
//!
//! ## Quick start
//!
//! ```
//! use graphus_auth::{Authenticator, Privilege};
//!
//! // One shared service per server; populate users, roles, and grants.
//! let mut auth = Authenticator::new(b"a-32-byte-or-longer-jwt-signing-secret");
//! auth.catalog_mut().create_user("alice").unwrap();
//! auth.catalog_mut().create_role("reader").unwrap();
//! auth.catalog_mut()
//!     .grant_privilege("reader", Privilege::read_database())
//!     .unwrap();
//! auth.catalog_mut().grant_role("alice", "reader").unwrap();
//! auth.set_password("alice", "correct horse battery staple").unwrap();
//!
//! // Bolt native LOGON: authenticate by password, then authorize each action.
//! let who = auth
//!     .authenticate_password("alice", "correct horse battery staple")
//!     .unwrap();
//! assert_eq!(who, "alice");
//! assert!(auth.authorize(&who, &Privilege::read_database()));
//! assert!(!auth.authorize(&who, &Privilege::write_database()));
//!
//! // REST Bearer: issue a token (now=1000s, ttl=1h) and verify it later (now=1100s).
//! let token = auth.issue_token("alice", 1000, 3600).unwrap();
//! assert_eq!(auth.authenticate_bearer(&token, 1100).unwrap().sub, "alice");
//! ```
#![forbid(unsafe_code)]

pub mod auth;
pub mod error;
pub mod limits;
pub mod password;
pub mod peercred;
pub mod rbac;
pub mod tls;
pub mod token;

pub use auth::Authenticator;
pub use error::{AuthError, Result};
pub use limits::{RateLimiter, RequestLimits};
pub use peercred::{PeerCred, PeerCredMap, PeerCredSource};
pub use rbac::{Action, Catalog, Privilege, Resource, Role, User};
pub use tls::{into_shared, tls_server_config};
pub use token::{Claims, JwtAuthenticator};
