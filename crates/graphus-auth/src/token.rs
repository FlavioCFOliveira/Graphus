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
//!
//! ## Token binding and revocation (SEC-180, CWE-613)
//!
//! Every token also carries `iss` (issuer) and `aud` (audience) claims, **both validated** on verify
//! against this authenticator's configured identity, so a token minted for one Graphus deployment is
//! **not transferable** to another even if the two share (or leak) the HS256 secret. A random `jti`
//! (unique token id) and a per-user credential epoch `ver` (token version) are carried so a token can
//! be invalidated *before* `exp`: the [`Authenticator`](crate::Authenticator) facade rejects a token
//! whose `ver` is older than the user's current credential epoch (a password change bumps the epoch,
//! invalidating outstanding tokens) and supports an explicit `jti` denylist for targeted revocation.
//! This module owns the `iss`/`aud` binding; the credential-epoch and denylist checks live in the
//! facade, which holds the catalog state. The default issuer/audience are fixed constants; a
//! deployment that needs cross-deployment isolation under a shared secret sets distinct ones via
//! [`JwtAuthenticator::with_identity`].

use std::collections::HashSet;

use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation, decode, encode};
use serde::{Deserialize, Serialize};

use crate::error::{AuthError, Result};

/// The default JWT **issuer** (`iss`) when an authenticator is built without an explicit identity.
pub const DEFAULT_ISSUER: &str = "graphus";

/// The default JWT **audience** (`aud`) when an authenticator is built without an explicit identity.
pub const DEFAULT_AUDIENCE: &str = "graphus";

/// The registered claims Graphus puts in a Bearer JWT.
///
/// The subject maps back to an RBAC [`User`](crate::User) by name; `iss`/`aud` bind the token to a
/// deployment; `jti` uniquely identifies the token (revocation); `ver` is the user's credential
/// epoch at issue time (a password change bumps the user's epoch, invalidating older tokens).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Claims {
    /// Subject — the authenticated username (maps to a `Catalog` user).
    pub sub: String,
    /// Expiry, as seconds since the Unix epoch (RFC 7519 `exp`).
    pub exp: u64,
    /// Issued-at, as seconds since the Unix epoch (RFC 7519 `iat`).
    pub iat: u64,
    /// Issuer (RFC 7519 `iss`) — this server's id; validated on verify.
    pub iss: String,
    /// Audience (RFC 7519 `aud`) — the intended service; validated on verify.
    pub aud: String,
    /// JWT id (RFC 7519 `jti`) — a random, unique token id for revocation/denylisting.
    pub jti: String,
    /// Credential epoch (token version) — the user's epoch at issue time (SEC-180). A token whose
    /// `ver` is older than the user's current epoch is rejected by the facade (forced logout on a
    /// password change). `0` for a token minted before any password change.
    #[serde(default)]
    pub ver: u64,
}

/// Issues and verifies HS256 Bearer JWTs against a single shared HMAC secret, bound to a deployment
/// identity (`iss`/`aud`).
///
/// Construct one per server from a high-entropy secret (≥ 32 bytes recommended). The same instance
/// both signs (`issue_token`) and verifies (`verify_bearer`), since HS256 is symmetric.
#[derive(Clone)]
pub struct JwtAuthenticator {
    encoding: EncodingKey,
    decoding: DecodingKey,
    validation: Validation,
    /// This deployment's issuer id, stamped into `iss` on issue and validated on verify (SEC-180).
    issuer: String,
    /// This deployment's audience, stamped into `aud` on issue and validated on verify (SEC-180).
    audience: String,
}

impl std::fmt::Debug for JwtAuthenticator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never print key material.
        f.debug_struct("JwtAuthenticator")
            .field("algorithm", &"HS256")
            .field("issuer", &self.issuer)
            .field("audience", &self.audience)
            .finish_non_exhaustive()
    }
}

/// The minimum HMAC secret length, in bytes, accepted by [`JwtAuthenticator::new`].
///
/// HS256 keys shorter than the 256-bit (32-byte) output of SHA-256 reduce the effective security of
/// the MAC and make brute-forcing the signing key tractable — a forged-token risk. RFC 2104 §3 and
/// RFC 7518 §3.2 both require an HMAC key at least as long as the hash output, so we reject anything
/// shorter than 32 bytes at construction (fail-closed startup) rather than mint forgeable tokens.
pub const MIN_JWT_SECRET_LEN: usize = 32;

impl JwtAuthenticator {
    /// Creates an authenticator from a raw HMAC `secret`, with the default issuer/audience
    /// ([`DEFAULT_ISSUER`] / [`DEFAULT_AUDIENCE`]).
    ///
    /// The `validation` is fixed to HS256 with the library's *internal* expiry check disabled (we
    /// enforce `exp` deterministically against an injected clock instead); the `sub`/`exp`/`iss`/`aud`
    /// claims are all required to be present, and `iss`/`aud` are validated against the configured
    /// identity.
    ///
    /// # Errors
    /// [`AuthError::WeakSecret`] if `secret` is shorter than [`MIN_JWT_SECRET_LEN`] bytes — a short
    /// HS256 key would make signatures brute-forceable and tokens forgeable, so it is rejected here
    /// at startup instead of producing an insecure authenticator.
    pub fn new(secret: &[u8]) -> Result<Self> {
        Self::with_identity(secret, DEFAULT_ISSUER, DEFAULT_AUDIENCE)
    }

    /// Creates an authenticator with an explicit `issuer` (`iss`) and `audience` (`aud`) identity
    /// (SEC-180), so tokens are bound to this deployment and rejected elsewhere even under a shared
    /// secret. Both are validated on every verify.
    ///
    /// # Errors
    /// [`AuthError::WeakSecret`] if `secret` is shorter than [`MIN_JWT_SECRET_LEN`] bytes.
    pub fn with_identity(secret: &[u8], issuer: &str, audience: &str) -> Result<Self> {
        if secret.len() < MIN_JWT_SECRET_LEN {
            return Err(AuthError::WeakSecret {
                detail: format!(
                    "JWT signing secret is {} bytes; HS256 requires at least {MIN_JWT_SECRET_LEN}",
                    secret.len()
                ),
            });
        }
        let mut validation = Validation::new(Algorithm::HS256);
        // We validate `exp` ourselves against the injected clock (see module docs), so turn off the
        // library's wall-clock check. Require `sub`/`exp`/`iss`/`aud` so a token missing any binding
        // claim is rejected; bind `iss`/`aud` so a wrong/foreign value is rejected too.
        validation.validate_exp = false;
        validation.required_spec_claims = HashSet::from([
            "sub".to_owned(),
            "exp".to_owned(),
            "iss".to_owned(),
            "aud".to_owned(),
        ]);
        validation.set_issuer(&[issuer]);
        validation.set_audience(&[audience]);
        Ok(Self {
            encoding: EncodingKey::from_secret(secret),
            decoding: DecodingKey::from_secret(secret),
            validation,
            issuer: issuer.to_owned(),
            audience: audience.to_owned(),
        })
    }

    /// This authenticator's configured issuer (`iss`).
    #[must_use]
    pub fn issuer(&self) -> &str {
        &self.issuer
    }

    /// This authenticator's configured audience (`aud`).
    #[must_use]
    pub fn audience(&self) -> &str {
        &self.audience
    }

    /// Issues a signed HS256 token for `subject` at credential epoch `ver`, expiring `ttl_secs` after
    /// `now_unix_secs`. The token carries this deployment's `iss`/`aud` and a fresh random `jti`.
    ///
    /// # Errors
    /// [`AuthError::BadToken`] if encoding fails (should not happen for well-formed claims).
    pub fn issue_token(
        &self,
        subject: &str,
        now_unix_secs: u64,
        ttl_secs: u64,
        ver: u64,
    ) -> Result<String> {
        let claims = Claims {
            sub: subject.to_owned(),
            iat: now_unix_secs,
            exp: now_unix_secs.saturating_add(ttl_secs),
            iss: self.issuer.clone(),
            aud: self.audience.clone(),
            jti: random_jti(),
            ver,
        };
        encode(&Header::new(Algorithm::HS256), &claims, &self.encoding).map_err(|e| {
            AuthError::BadToken {
                detail: format!("encode failed: {e}"),
            }
        })
    }

    /// Verifies a Bearer `token`'s signature, algorithm, issuer, and audience, then checks it has not
    /// expired as of `now_unix_secs`, returning the validated [`Claims`].
    ///
    /// A tampered or wrongly-signed token, one using an unexpected algorithm, or one whose `iss`/`aud`
    /// does not match this deployment, yields [`AuthError::BadToken`]; a structurally valid,
    /// correctly-signed token whose `exp` is at or before `now_unix_secs` yields
    /// [`AuthError::TokenExpired`]. The credential-epoch (`ver`) and `jti`-denylist checks are applied
    /// one layer up in [`Authenticator`](crate::Authenticator), which holds the catalog state.
    ///
    /// # Errors
    /// - [`AuthError::BadToken`] — bad signature, malformed token, unexpected algorithm, or wrong
    ///   `iss`/`aud`.
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

/// Generates a fresh, unguessable JWT id (`jti`): 128 bits from the OS CSPRNG, lower-hex encoded.
/// Used for revocation/denylisting (SEC-180). On the vanishingly unlikely event the OS RNG fails,
/// falls back to a high-resolution timestamp so a token is still issued with a unique-enough id
/// (uniqueness, not secrecy, is what `jti` needs for the denylist).
fn random_jti() -> String {
    let mut bytes = [0u8; 16];
    if getrandom::getrandom(&mut bytes).is_err() {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0u128, |d| d.as_nanos());
        bytes.copy_from_slice(&nanos.to_le_bytes());
    }
    let mut s = String::with_capacity(32);
    for b in bytes {
        s.push(char::from_digit(u32::from(b >> 4), 16).unwrap_or('0'));
        s.push(char::from_digit(u32::from(b & 0x0F), 16).unwrap_or('0'));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &[u8] = b"a-test-secret-at-least-32-bytes-long!!";
    const NOW: u64 = 1_700_000_000;

    /// Constructs from the fixture secret, asserting it is accepted.
    fn authenticator() -> JwtAuthenticator {
        JwtAuthenticator::new(SECRET).expect("fixture secret is >= 32 bytes")
    }

    #[test]
    fn round_trips_subject_and_expiry() {
        let auth = authenticator();
        let token = auth.issue_token("alice", NOW, 3600, 0).unwrap();
        let claims = auth.verify_bearer(&token, NOW + 10).unwrap();
        assert_eq!(claims.sub, "alice");
        assert_eq!(claims.exp, NOW + 3600);
        assert_eq!(claims.iss, DEFAULT_ISSUER);
        assert_eq!(claims.aud, DEFAULT_AUDIENCE);
        assert!(!claims.jti.is_empty(), "a jti must be stamped");
        assert_eq!(auth.subject_of(&token, NOW + 10).unwrap(), "alice");
    }

    #[test]
    fn two_tokens_get_distinct_jtis() {
        let auth = authenticator();
        let a = auth.verify_bearer(&auth.issue_token("u", NOW, 60, 0).unwrap(), NOW + 1).unwrap();
        let b = auth.verify_bearer(&auth.issue_token("u", NOW, 60, 0).unwrap(), NOW + 1).unwrap();
        assert_ne!(a.jti, b.jti, "each issued token gets a fresh random jti");
    }

    #[test]
    fn expired_token_is_rejected() {
        let auth = authenticator();
        let token = auth.issue_token("alice", NOW, 60, 0).unwrap();
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
        let auth = authenticator();
        let mut token = auth.issue_token("alice", NOW, 3600, 0).unwrap();
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
        let issuer = authenticator();
        let verifier = JwtAuthenticator::new(b"a-completely-different-secret-key-32b!")
            .expect("alternate secret is >= 32 bytes");
        let token = issuer.issue_token("alice", NOW, 3600, 0).unwrap();
        assert!(matches!(
            verifier.verify_bearer(&token, NOW + 10),
            Err(AuthError::BadToken { .. })
        ));
    }

    #[test]
    fn token_for_another_audience_is_rejected() {
        // SEC-180: a token minted for deployment A's audience must be rejected by deployment B even
        // under the SAME secret — the iss/aud binding makes tokens non-transferable.
        let a = JwtAuthenticator::with_identity(SECRET, "graphus", "deployment-a")
            .expect("secret ok");
        let b = JwtAuthenticator::with_identity(SECRET, "graphus", "deployment-b")
            .expect("secret ok");
        let token = a.issue_token("alice", NOW, 3600, 0).unwrap();
        assert!(
            matches!(b.verify_bearer(&token, NOW + 10), Err(AuthError::BadToken { .. })),
            "a token bound to audience A must be rejected by audience B"
        );
        // And A accepts its own token.
        assert!(a.verify_bearer(&token, NOW + 10).is_ok());
    }

    #[test]
    fn token_for_another_issuer_is_rejected() {
        let a = JwtAuthenticator::with_identity(SECRET, "issuer-a", "graphus")
            .expect("secret ok");
        let b = JwtAuthenticator::with_identity(SECRET, "issuer-b", "graphus")
            .expect("secret ok");
        let token = a.issue_token("alice", NOW, 3600, 0).unwrap();
        assert!(matches!(
            b.verify_bearer(&token, NOW + 10),
            Err(AuthError::BadToken { .. })
        ));
    }

    #[test]
    fn garbage_token_is_rejected() {
        let auth = authenticator();
        assert!(matches!(
            auth.verify_bearer("not.a.jwt", NOW),
            Err(AuthError::BadToken { .. })
        ));
    }

    #[test]
    fn debug_does_not_leak_secret() {
        let auth = authenticator();
        let dbg = format!("{auth:?}");
        assert!(!dbg.contains("secret"));
        assert!(dbg.contains("HS256"));
    }

    #[test]
    fn short_secret_is_rejected_as_weak() {
        // A 31-byte secret is one byte below the HS256 minimum and must be refused, so a
        // mis-configured server fails closed at startup rather than minting forgeable tokens.
        let short = vec![b'x'; MIN_JWT_SECRET_LEN - 1];
        assert!(matches!(
            JwtAuthenticator::new(&short),
            Err(AuthError::WeakSecret { .. })
        ));
        // An empty secret is the degenerate worst case.
        assert!(matches!(
            JwtAuthenticator::new(b""),
            Err(AuthError::WeakSecret { .. })
        ));
    }

    #[test]
    fn secret_at_minimum_length_is_accepted() {
        // Exactly 32 bytes is the boundary and must be accepted.
        let exact = vec![b'k'; MIN_JWT_SECRET_LEN];
        assert!(JwtAuthenticator::new(&exact).is_ok());
    }

    /// Regression: SEC-178 (CWE-208). Graphus must only ever construct the **HS256** (symmetric HMAC)
    /// JWT algorithm — never an RSA (`RS*`/`PS*`) or ECDSA (`ES*`) algorithm — so the vulnerable `rsa`
    /// crate (RUSTSEC-2023-0071, the Marvin timing oracle) that `jsonwebtoken` transitively compiles
    /// in is **never reached** on any Graphus signing or verification path. This test pins both the
    /// signing header and the verification validation to HS256, so a future change that introduces an
    /// asymmetric algorithm — and thus a live RSA private-key operation — fails the build's tests.
    #[test]
    fn only_hs256_is_ever_constructed() {
        let auth = authenticator();
        // The encoding header used on issue is HS256.
        let token = auth.issue_token("alice", NOW, 60, 0).unwrap();
        let header = jsonwebtoken::decode_header(&token).expect("a valid JWT header");
        assert_eq!(
            header.alg,
            Algorithm::HS256,
            "issued tokens must be signed with HS256 only (no RSA/ECDSA path)"
        );
        // The verification validation accepts exactly HS256.
        assert_eq!(
            auth.validation.algorithms,
            vec![Algorithm::HS256],
            "verification must accept HS256 only, so an RS*/PS*/ES* token is rejected"
        );
    }
}
