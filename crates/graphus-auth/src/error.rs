//! The authentication/authorization error taxonomy (`04 §8.4`).
//!
//! [`AuthError`] is this crate's own rich error type. Auth failures ultimately surface to a client
//! at the connectivity boundary, so [`AuthError`] converts into [`GraphusError::Protocol`] (the only
//! `graphus-core` variant that models a connectivity/protocol failure; see
//! `graphus_core::error`). The conversion is intentionally lossy — it collapses to a single
//! protocol-error string — because the connectivity layer maps an auth failure to a uniform
//! `FAILURE`/`401` shape and must not leak *which* internal check failed to an unauthenticated
//! peer. Callers that need to branch on the cause keep the [`AuthError`] before converting.
//!
//! Like the rest of the workspace, the `Display`/`Error` impls are hand-rolled rather than derived
//! via `thiserror`, to match `graphus_core::error::GraphusError`.

use graphus_core::GraphusError;

/// The crate-local result alias.
pub type Result<T> = std::result::Result<T, AuthError>;

/// An authentication or authorization failure.
///
/// Variants distinguish *authentication* (who are you — credentials bad/missing/expired) from
/// *authorization* ([`AuthError::Unauthorized`] — you are known but lack the privilege) and from
/// *configuration* faults ([`AuthError::TlsConfig`]) so the caller can react appropriately (retry
/// login vs. give up vs. fail startup).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum AuthError {
    /// The credentials presented could not be authenticated (wrong password, unknown user, or a
    /// peer that maps to no user). Deliberately does **not** say which, to avoid user-enumeration.
    Unauthenticated,
    /// The identity is authenticated but lacks the requested [`Privilege`](crate::Privilege).
    Unauthorized,
    /// A bearer token was malformed, had a bad signature, used an unexpected algorithm, or was
    /// otherwise unverifiable. `detail` is a short, non-sensitive reason for logs.
    BadToken {
        /// A short, safe-to-log description of why the token was rejected.
        detail: String,
    },
    /// A bearer token was well-formed and correctly signed but has expired (`exp` in the past).
    /// Separated from [`AuthError::BadToken`] so the client knows to re-authenticate rather than
    /// treat the token as forged.
    TokenExpired,
    /// A referenced user, role, or privilege already exists (CRUD conflict).
    AlreadyExists {
        /// The catalog entity kind and name, for the operator's log.
        what: String,
    },
    /// A referenced user, role, or privilege does not exist (CRUD lookup miss).
    NotFound {
        /// The catalog entity kind and name, for the operator's log.
        what: String,
    },
    /// Building the TLS server configuration failed (bad/empty PEM, key/cert mismatch, rustls
    /// rejection). This is a configuration/startup fault, not a per-request authentication failure.
    TlsConfig {
        /// A short description of the configuration problem.
        detail: String,
    },
    /// A request-limit or rate-limit configuration value was invalid (e.g. a zero capacity).
    InvalidLimits {
        /// A short description of the invalid configuration.
        detail: String,
    },
    /// Hashing or verifying a password failed for a reason other than a wrong password (e.g. a
    /// stored hash that could not be parsed). A *wrong* password is `Ok(false)`, not this error.
    PasswordHash {
        /// A short, non-sensitive description of the failure.
        detail: String,
    },
    /// The JWT signing secret supplied at construction was too short to be cryptographically sound
    /// for HS256 (shorter than [`MIN_JWT_SECRET_LEN`](crate::token::MIN_JWT_SECRET_LEN) bytes). This
    /// is a configuration/startup fault: a weak secret makes Bearer tokens forgeable, so the
    /// authenticator refuses to build rather than operate insecurely.
    WeakSecret {
        /// A short, non-sensitive description of why the secret was rejected.
        detail: String,
    },
    /// A password supplied to `set_password`/`hash_password` did not meet the minimum strength
    /// policy (it was empty or shorter than the required minimum length). This is a configuration
    /// or input fault, not a failed login.
    WeakPassword {
        /// A short, non-sensitive description of why the password was rejected.
        detail: String,
    },
}

impl std::fmt::Display for AuthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unauthenticated => write!(f, "authentication failed"),
            Self::Unauthorized => write!(f, "not authorized for the requested action"),
            Self::BadToken { detail } => write!(f, "invalid bearer token: {detail}"),
            Self::TokenExpired => write!(f, "bearer token expired"),
            Self::AlreadyExists { what } => write!(f, "already exists: {what}"),
            Self::NotFound { what } => write!(f, "not found: {what}"),
            Self::TlsConfig { detail } => write!(f, "tls configuration error: {detail}"),
            Self::InvalidLimits { detail } => write!(f, "invalid limit configuration: {detail}"),
            Self::PasswordHash { detail } => write!(f, "password hashing error: {detail}"),
            Self::WeakSecret { detail } => write!(f, "weak jwt signing secret: {detail}"),
            Self::WeakPassword { detail } => write!(f, "weak password: {detail}"),
        }
    }
}

impl std::error::Error for AuthError {}

impl From<AuthError> for GraphusError {
    /// Maps an [`AuthError`] onto [`GraphusError::Protocol`].
    ///
    /// Auth failures are surfaced to clients at the connectivity layer, whose only matching
    /// `graphus-core` category is `Protocol`. The mapping is one-way and lossy by design.
    fn from(err: AuthError) -> Self {
        GraphusError::Protocol(err.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn display_is_stable_and_non_enumerating() {
        // The generic "authentication failed" must not reveal whether the user exists.
        assert_eq!(
            AuthError::Unauthenticated.to_string(),
            "authentication failed"
        );
        assert_eq!(
            AuthError::Unauthorized.to_string(),
            "not authorized for the requested action"
        );
        assert_eq!(AuthError::TokenExpired.to_string(), "bearer token expired");
    }

    #[test]
    fn converts_into_core_protocol_error() {
        let core: GraphusError = AuthError::Unauthorized.into();
        match core {
            GraphusError::Protocol(msg) => {
                assert!(msg.contains("not authorized"), "unexpected message: {msg}");
            }
            other => panic!("expected Protocol, got {other:?}"),
        }
    }

    #[test]
    fn detail_variants_render_their_detail() {
        assert_eq!(
            AuthError::BadToken {
                detail: "bad signature".to_owned()
            }
            .to_string(),
            "invalid bearer token: bad signature"
        );
        assert_eq!(
            AuthError::TlsConfig {
                detail: "empty certificate chain".to_owned()
            }
            .to_string(),
            "tls configuration error: empty certificate chain"
        );
    }
}
