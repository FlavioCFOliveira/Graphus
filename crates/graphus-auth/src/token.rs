//! JWT / Bearer authentication for the REST interface (RFC 6750 Bearer, RFC 7519 JWT; `04 §8.4`).
//!
//! REST clients present a `Bearer` token; Graphus issues and verifies **HS256** JWTs carrying the
//! username as the `sub` (subject) claim and an `exp` (expiry) claim. The HMAC secret is held only
//! server-side, so a valid signature proves the token was minted by this server.
//!
//! ## Deterministic time
//!
//! Expiry is **inviolably tied to an injected clock**, never wall time, so tests are reproducible
//! (project rule: use the injected clock). [`JwtAuthenticator::issue_token`] stamps `exp = now +
//! ttl` from a caller-supplied `now_unix_secs`, and [`JwtAuthenticator::verify_bearer`] checks
//! `exp` against a caller-supplied `now_unix_secs`. The `jsonwebtoken` library's *own*
//! `SystemTime`-based `exp` check is therefore **disabled** ([`Validation::validate_exp`] = `false`)
//! and replaced by our deterministic comparison; the library still validates the **signature** and
//! the **algorithm** (pinned to HS256, so an `alg:none` or RS256 substitution is rejected).
//!
//! `now_unix_secs` is seconds since the Unix epoch; the server derives it once per request from the
//! production [`Clock`](graphus_core::capability::Clock) wall source. Keeping it a plain parameter
//! (rather than borrowing a `Clock` here) keeps this module trivially testable and free of any I/O.

use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, encode};
use serde::{Deserialize, Serialize};

use crate::error::{AuthError, Result};

/// The registered claims Graphus puts in a Bearer JWT.
///
/// Only the standard `sub`/`exp`/`iat` claims are used; the subject maps back to an RBAC
/// [`User`](crate::User) by name.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Claims {
    /// Subject — the authenticated username (maps to a `Catalog` user).
    pub sub: String,
    /// Expiry, as seconds since the Unix epoch (RFC 7519 `exp`).
    pub exp: u64,
    /// Issued-at, as seconds since the Unix epoch (RFC 7519 `iat`).
    pub iat: u64,
}

/// Issues and verifies HS256 Bearer JWTs against a single shared HMAC secret.
///
/// Construct one per server from a high-entropy secret (≥ 32 bytes recommended). The same instance
/// both signs (`issue_token`) and verifies (`verify_bearer`), since HS256 is symmetric.
#[derive(Clone)]
pub struct JwtAuthenticator {
    encoding: EncodingKey,
    decoding: DecodingKey,
    validation: Validation,
}

impl std::fmt::Debug for JwtAuthenticator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never print key material.
        f.debug_struct("JwtAuthenticator")
            .field("algorithm", &"HS256")
            .finish_non_exhaustive()
    }
}

impl JwtAuthenticator {
    /// Creates an authenticator from a raw HMAC `secret`.
    ///
    /// The `validation` is fixed to HS256 with the library's *internal* expiry check disabled (we
    /// enforce `exp` deterministically against an injected clock instead); the subject claim is
    /// still required to be present.
    #[must_use]
    pub fn new(secret: &[u8]) -> Self {
        let mut validation = Validation::new(Algorithm::HS256);
        // We validate `exp` ourselves against the injected clock (see module docs), so turn off the
        // library's wall-clock check. Require `sub` so a token without a subject is rejected.
        validation.validate_exp = false;
        validation.required_spec_claims =
            std::collections::HashSet::from(["sub".to_owned(), "exp".to_owned()]);
        Self {
            encoding: EncodingKey::from_secret(secret),
            decoding: DecodingKey::from_secret(secret),
            validation,
        }
    }

    /// Issues a signed HS256 token for `subject`, expiring `ttl_secs` after `now_unix_secs`.
    ///
    /// # Errors
    /// [`AuthError::BadToken`] if encoding fails (should not happen for well-formed claims).
    pub fn issue_token(&self, subject: &str, now_unix_secs: u64, ttl_secs: u64) -> Result<String> {
        let claims = Claims {
            sub: subject.to_owned(),
            iat: now_unix_secs,
            exp: now_unix_secs.saturating_add(ttl_secs),
        };
        encode(&Header::new(Algorithm::HS256), &claims, &self.encoding).map_err(|e| {
            AuthError::BadToken {
                detail: format!("encode failed: {e}"),
            }
        })
    }

    /// Verifies a Bearer `token`'s signature and algorithm, then checks it has not expired as of
    /// `now_unix_secs`, returning the validated [`Claims`].
    ///
    /// A tampered or wrongly-signed token, or one using an unexpected algorithm, yields
    /// [`AuthError::BadToken`]; a structurally valid, correctly-signed token whose `exp` is at or
    /// before `now_unix_secs` yields [`AuthError::TokenExpired`].
    ///
    /// # Errors
    /// - [`AuthError::BadToken`] — bad signature, malformed token, or unexpected algorithm.
    /// - [`AuthError::TokenExpired`] — signature valid but `exp <= now_unix_secs`.
    pub fn verify_bearer(&self, token: &str, now_unix_secs: u64) -> Result<Claims> {
        let data = decode::<Claims>(token, &self.decoding, &self.validation).map_err(|e| {
            AuthError::BadToken {
                detail: e.to_string(),
            }
        })?;
        if data.claims.exp <= now_unix_secs {
            return Err(AuthError::TokenExpired);
        }
        Ok(data.claims)
    }

    /// Convenience: verify a token and return only the subject (username) for RBAC lookup.
    ///
    /// # Errors
    /// As [`JwtAuthenticator::verify_bearer`].
    pub fn subject_of(&self, token: &str, now_unix_secs: u64) -> Result<String> {
        self.verify_bearer(token, now_unix_secs).map(|c| c.sub)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &[u8] = b"a-test-secret-at-least-32-bytes-long!!";
    const NOW: u64 = 1_700_000_000;

    #[test]
    fn round_trips_subject_and_expiry() {
        let auth = JwtAuthenticator::new(SECRET);
        let token = auth.issue_token("alice", NOW, 3600).unwrap();
        let claims = auth.verify_bearer(&token, NOW + 10).unwrap();
        assert_eq!(claims.sub, "alice");
        assert_eq!(claims.exp, NOW + 3600);
        assert_eq!(auth.subject_of(&token, NOW + 10).unwrap(), "alice");
    }

    #[test]
    fn expired_token_is_rejected() {
        let auth = JwtAuthenticator::new(SECRET);
        let token = auth.issue_token("alice", NOW, 60).unwrap();
        // Exactly at expiry counts as expired (exp <= now).
        assert_eq!(
            auth.verify_bearer(&token, NOW + 60),
            Err(AuthError::TokenExpired)
        );
        // And well past expiry.
        assert_eq!(
            auth.verify_bearer(&token, NOW + 1000),
            Err(AuthError::TokenExpired)
        );
    }

    #[test]
    fn tampered_token_is_rejected() {
        let auth = JwtAuthenticator::new(SECRET);
        let mut token = auth.issue_token("alice", NOW, 3600).unwrap();
        // Flip a character in the signature segment.
        let last = token.pop().unwrap();
        token.push(if last == 'a' { 'b' } else { 'a' });
        assert!(matches!(
            auth.verify_bearer(&token, NOW + 10),
            Err(AuthError::BadToken { .. })
        ));
    }

    #[test]
    fn token_signed_with_another_secret_is_rejected() {
        let issuer = JwtAuthenticator::new(SECRET);
        let verifier = JwtAuthenticator::new(b"a-completely-different-secret-key-32b!");
        let token = issuer.issue_token("alice", NOW, 3600).unwrap();
        assert!(matches!(
            verifier.verify_bearer(&token, NOW + 10),
            Err(AuthError::BadToken { .. })
        ));
    }

    #[test]
    fn garbage_token_is_rejected() {
        let auth = JwtAuthenticator::new(SECRET);
        assert!(matches!(
            auth.verify_bearer("not.a.jwt", NOW),
            Err(AuthError::BadToken { .. })
        ));
    }

    #[test]
    fn debug_does_not_leak_secret() {
        let auth = JwtAuthenticator::new(SECRET);
        let dbg = format!("{auth:?}");
        assert!(!dbg.contains("secret"));
        assert!(dbg.contains("HS256"));
    }
}
