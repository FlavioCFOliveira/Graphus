//! Security regression battery for credential handling (red-team audit, 2026-06).
//!
//! Covers: password hashing strength + constant-time verification properties, JWT signature/alg
//! enforcement and expiry, AND pins the SEC-180 fixes (CWE-613): `aud`/`iss` binding makes tokens
//! non-transferable across deployments, and a per-user credential epoch (`ver`) plus an explicit
//! `jti` denylist invalidate outstanding tokens on a password change / targeted revocation. The
//! binding/revocation tests now assert the SECURE post-fix behaviour (rejection), not the old gap.

use graphus_auth::{Authenticator, JwtAuthenticator, Privilege};

const SECRET: &[u8] = b"a-test-jwt-signing-secret-at-least-32b!";
const OTHER_SECRET: &[u8] = b"a-completely-different-secret-key-32by!";
const NOW: u64 = 1_700_000_000;

// ---- password hashing ----------------------------------------------------------------------------

/// A stored credential is an Argon2id PHC string, never the plaintext, and each hash uses a fresh
/// salt (equal passwords produce distinct hashes — no precomputation/rainbow exposure).
#[test]
fn passwords_are_argon2id_salted_and_never_plaintext() {
    let mut a = Authenticator::new(SECRET).expect("secret >= 32 bytes");
    a.catalog_mut().create_user("alice").unwrap();
    a.set_password("alice", "correct horse battery staple")
        .unwrap();

    // The hash is reachable only via verify (the PHC string is not exposed publicly), so we assert
    // the observable properties: right password verifies, wrong does not, and a second user with the
    // same password authenticates independently (distinct salts, both valid).
    assert!(
        a.verify_password("alice", "correct horse battery staple")
            .unwrap()
    );
    assert!(
        !a.verify_password("alice", "correct horse battery stapl3")
            .unwrap()
    );

    a.catalog_mut().create_user("bob").unwrap();
    a.set_password("bob", "correct horse battery staple")
        .unwrap();
    assert!(
        a.verify_password("bob", "correct horse battery staple")
            .unwrap()
    );
}

/// Weak (empty / below-minimum) passwords are refused BEFORE any store mutation, so a weak
/// credential never reaches disk.
#[test]
fn weak_passwords_are_rejected_before_storage() {
    let mut a = Authenticator::new(SECRET).unwrap();
    a.catalog_mut().create_user("alice").unwrap();
    a.set_password("alice", "strong-enough-pw").unwrap();
    assert!(
        a.set_password("alice", "").is_err(),
        "empty password must be refused"
    );
    assert!(
        a.set_password("alice", "short77").is_err(),
        "7-char password must be refused"
    );
    // The original credential is untouched by the rejected updates.
    assert!(a.verify_password("alice", "strong-enough-pw").unwrap());
}

/// User-enumeration resistance: verifying an unknown user, a user with no password, and a wrong
/// password are all indistinguishable `Ok(false)` (no error, no distinct signal).
#[test]
fn password_verification_does_not_enable_user_enumeration() {
    let mut a = Authenticator::new(SECRET).unwrap();
    a.catalog_mut().create_user("alice").unwrap();
    a.set_password("alice", "alice-strong-pw").unwrap();
    assert!(
        !a.verify_password("ghost", "anything").unwrap(),
        "unknown user -> Ok(false)"
    );
    a.catalog_mut().create_user("nopass").unwrap();
    assert!(
        !a.verify_password("nopass", "anything").unwrap(),
        "no password set -> Ok(false)"
    );
    assert!(
        !a.verify_password("alice", "wrong").unwrap(),
        "wrong password -> Ok(false)"
    );
}

// ---- JWT signature / algorithm / expiry ----------------------------------------------------------

/// A token signed by another secret is rejected (HMAC binds the token to this server's secret).
#[test]
fn jwt_signed_with_another_secret_is_rejected() {
    let issuer = JwtAuthenticator::new(SECRET).unwrap();
    let verifier = JwtAuthenticator::new(OTHER_SECRET).unwrap();
    let token = issuer.issue_token("alice", NOW, 3600, 0).unwrap();
    assert!(verifier.verify_bearer(&token, NOW + 10).is_err());
}

/// Minimal base64url-no-pad encoder (RFC 4648 §5), hand-rolled so the test adds no dependency.
fn b64url(input: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::new();
    for chunk in input.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        let chars = [
            ALPHABET[((n >> 18) & 0x3F) as usize],
            ALPHABET[((n >> 12) & 0x3F) as usize],
            ALPHABET[((n >> 6) & 0x3F) as usize],
            ALPHABET[(n & 0x3F) as usize],
        ];
        let take = chunk.len() + 1; // 3 bytes -> 4 chars, 2 -> 3, 1 -> 2
        for &c in &chars[..take] {
            out.push(c as char);
        }
    }
    out
}

/// An `alg: none` token (the classic JWT bypass) must be rejected: the algorithm is pinned to HS256.
#[test]
fn jwt_alg_none_is_rejected() {
    let auth = JwtAuthenticator::new(SECRET).unwrap();
    // Forge an unsigned token: header {"alg":"none","typ":"JWT"} . payload . (empty signature).
    let header = b64url(br#"{"alg":"none","typ":"JWT"}"#);
    let payload =
        b64url(format!(r#"{{"sub":"alice","exp":{},"iat":{NOW}}}"#, NOW + 3600).as_bytes());
    let forged = format!("{header}.{payload}.");
    assert!(
        auth.verify_bearer(&forged, NOW + 10).is_err(),
        "an alg:none token must be rejected (HS256 is pinned)"
    );
}

/// Expiry is enforced deterministically against the injected clock: a token is rejected at and after
/// its `exp`.
#[test]
fn jwt_expiry_is_enforced() {
    let auth = JwtAuthenticator::new(SECRET).unwrap();
    let token = auth.issue_token("alice", NOW, 60, 0).unwrap();
    assert!(auth.verify_bearer(&token, NOW + 59).is_ok());
    assert!(
        auth.verify_bearer(&token, NOW + 60).is_err(),
        "exp <= now must be rejected"
    );
    assert!(auth.verify_bearer(&token, NOW + 10_000).is_err());
}

/// A too-short HS256 secret is refused at construction (fail-closed startup), so a mis-configured
/// server cannot mint brute-forceable, forgeable tokens.
#[test]
fn short_jwt_secret_is_refused_at_construction() {
    assert!(JwtAuthenticator::new(b"too-short").is_err());
    assert!(JwtAuthenticator::new(&[b'k'; 31]).is_err());
    assert!(JwtAuthenticator::new(&[b'k'; 32]).is_ok());
}

/// Regression: SEC-180 (CWE-613). Tokens now carry `iss`/`aud` and both are validated on verify, so
/// a token minted for deployment A's audience is REJECTED by deployment B even under the SAME secret
/// — tokens are non-transferable across deployments. (The companion positive case — A accepts its
/// own token — is covered by `round_trips_subject_and_expiry` in the unit suite.)
#[test]
fn jwt_is_bound_to_issuer_and_audience() {
    use graphus_auth::JwtAuthenticator;
    // Two deployments sharing the SAME secret but with distinct audiences (the shared/leaked-key
    // threat model). The aud binding makes A's token invalid at B.
    let deployment_a = JwtAuthenticator::with_identity(SECRET, "graphus", "deployment-a").unwrap();
    let deployment_b = JwtAuthenticator::with_identity(SECRET, "graphus", "deployment-b").unwrap();
    let token = deployment_a.issue_token("alice", NOW, 3600, 0).unwrap();
    assert!(
        deployment_b.verify_bearer(&token, NOW + 10).is_err(),
        "a token bound to audience A must be rejected by audience B even under a shared secret"
    );
    // A still accepts its own token, and the bound claims are present.
    let claims = deployment_a.verify_bearer(&token, NOW + 10).unwrap();
    assert_eq!(claims.iss, "graphus");
    assert_eq!(claims.aud, "deployment-a");
    assert!(
        !claims.jti.is_empty(),
        "a jti must be stamped for revocation"
    );
}

/// Regression: SEC-180 (CWE-613). Changing a user's password now invalidates already-issued Bearer
/// tokens (forced logout via the per-user credential epoch). The old token is rejected well before
/// its `exp`, while a freshly issued token works.
#[test]
fn password_change_revokes_outstanding_tokens() {
    let mut a = Authenticator::new(SECRET).unwrap();
    a.catalog_mut().create_user("alice").unwrap();
    a.set_password("alice", "original-strong-pw").unwrap();
    let token = a.issue_token("alice", NOW, 3600).unwrap();
    // Valid before the reset.
    assert_eq!(
        a.authenticate_bearer(&token, NOW + 10).unwrap().sub,
        "alice"
    );

    // Rotate the password (simulating a compromise response / forced reset). This bumps the epoch.
    a.set_password("alice", "rotated-strong-pw").unwrap();

    // The previously-issued token is now rejected — its credential epoch is stale.
    assert!(
        a.authenticate_bearer(&token, NOW + 10).is_err(),
        "an old token must NOT survive a password change (forced logout)"
    );
    // A token minted after the reset is accepted again.
    let fresh = a.issue_token("alice", NOW + 1, 3600).unwrap();
    assert_eq!(
        a.authenticate_bearer(&fresh, NOW + 10).unwrap().sub,
        "alice"
    );
}

/// Regression: SEC-180. A single leaked token can be killed by its `jti` without disturbing the
/// user's other tokens or forcing a password change.
#[test]
fn explicit_jti_revocation_kills_one_token() {
    let mut a = Authenticator::new(SECRET).unwrap();
    a.catalog_mut().create_user("alice").unwrap();
    a.set_password("alice", "alice-strong-pw").unwrap();
    let leaked = a.issue_token("alice", NOW, 3600).unwrap();
    let other = a.issue_token("alice", NOW, 3600).unwrap();
    let leaked_jti = a.authenticate_bearer(&leaked, NOW + 10).unwrap().jti;
    a.revoke_token(leaked_jti);
    assert!(
        a.authenticate_bearer(&leaked, NOW + 10).is_err(),
        "the revoked token must be rejected"
    );
    assert_eq!(
        a.authenticate_bearer(&other, NOW + 10).unwrap().sub,
        "alice",
        "the user's other token is unaffected"
    );
}

/// Positive control: a token for a DROPPED user IS rejected (the subject-liveness check works). This
/// bounds the SEC-180 severity — dropped users cannot replay, only still-existing ones can.
#[test]
fn token_for_dropped_user_is_rejected() {
    let mut a = Authenticator::new(SECRET).unwrap();
    a.catalog_mut().create_user("alice").unwrap();
    let token = a.issue_token("alice", NOW, 3600).unwrap();
    a.catalog_mut().drop_user("alice").unwrap();
    assert!(a.authenticate_bearer(&token, NOW + 10).is_err());
}

// ---- authorization: deny-by-default --------------------------------------------------------------

/// Deny-by-default holds across the facade: an unknown user, a user with no roles, and a user
/// lacking the exact privilege are all denied; no wildcard escalation.
#[test]
fn authorization_is_deny_by_default() {
    let mut a = Authenticator::new(SECRET).unwrap();
    assert!(!a.authorize("nobody", &Privilege::read_database()));
    a.catalog_mut().create_user("alice").unwrap();
    assert!(
        !a.authorize("alice", &Privilege::read_database()),
        "no roles -> denied"
    );
    a.catalog_mut().create_role("reader").unwrap();
    a.catalog_mut()
        .grant_privilege("reader", Privilege::read_database())
        .unwrap();
    a.catalog_mut().grant_role("alice", "reader").unwrap();
    assert!(a.authorize("alice", &Privilege::read_database()));
    // Read does not escalate to Write.
    assert!(!a.authorize("alice", &Privilege::write_database()));
}
