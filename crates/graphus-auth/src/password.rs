//! Password hashing for Bolt native `LOGON` auth (`04 §8.4`).
//!
//! Bolt TCP carries credentials over TLS and authenticates with the native scheme; the password is
//! never stored in plaintext. Graphus hashes with **Argon2id** ([`Argon2::default`], the modern
//! memory-hard default; OWASP-recommended) and stores the resulting **PHC-format string** (which
//! embeds the algorithm, parameters, and a per-password random salt) on the [`User`](crate::User).
//! Verification is **constant-time** — `argon2`'s [`PasswordVerifier::verify_password`] compares the
//! derived hash without early-out, so it does not leak how many bytes matched.
//!
//! This module owns only the cryptographic primitives ([`hash_password`] / [`verify_password`]);
//! the [`Catalog`](crate::Catalog) ties a hash to a user and exposes `set_password` /
//! `verify_user_password` on top of these (see [`crate::auth`]).

use argon2::password_hash::rand_core::OsRng;
use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::{Argon2, password_hash::Error as PhcError};

use crate::error::{AuthError, Result};

/// The minimum accepted password length, in characters (Unicode scalar values).
///
/// Empty or trivially short passwords defeat the purpose of hashing — they are brute-forceable
/// regardless of the KDF. OWASP recommends a minimum of 8 characters as a baseline; [`hash_password`]
/// (and therefore `Authenticator::set_password`) rejects anything shorter so a weak credential never
/// reaches the store.
pub const MIN_PASSWORD_LEN: usize = 8;

/// Hashes `plaintext` with Argon2id and a fresh random salt, returning the PHC-format string to
/// store (e.g. on [`User::password_hash`](crate::User::password_hash)).
///
/// The salt is drawn from the OS CSPRNG ([`OsRng`]); each call therefore produces a *different*
/// string for the same password, which is correct (the salt defeats precomputation and makes equal
/// passwords indistinguishable on disk).
///
/// # Errors
/// - [`AuthError::WeakPassword`] if `plaintext` is shorter than [`MIN_PASSWORD_LEN`] characters
///   (including the empty string).
/// - [`AuthError::PasswordHash`] if the underlying Argon2 hashing fails (e.g. a parameter/memory
///   configuration error). It does **not** fail on ordinary inputs.
pub fn hash_password(plaintext: &str) -> Result<String> {
    // Count Unicode scalar values, not bytes, so the policy is about visible length rather than
    // UTF-8 encoding width.
    let len = plaintext.chars().count();
    if len < MIN_PASSWORD_LEN {
        return Err(AuthError::WeakPassword {
            detail: format!("password must be at least {MIN_PASSWORD_LEN} characters"),
        });
    }
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    argon2
        .hash_password(plaintext.as_bytes(), &salt)
        .map(|hash| hash.to_string())
        .map_err(|e| AuthError::PasswordHash {
            detail: e.to_string(),
        })
}

/// Verifies `plaintext` against a stored PHC `hash` in constant time.
///
/// Returns `Ok(true)` on a match, `Ok(false)` on a *wrong password* (the expected negative case),
/// and an error only when the stored `hash` itself cannot be parsed or another cryptographic
/// failure occurs — a malformed stored hash is an operational fault, not a failed login attempt.
///
/// # Errors
/// [`AuthError::PasswordHash`] if `hash` is not a valid PHC string or verification fails for a
/// reason other than a password mismatch.
pub fn verify_password(plaintext: &str, hash: &str) -> Result<bool> {
    let parsed = PasswordHash::new(hash).map_err(|e| AuthError::PasswordHash {
        detail: format!("stored hash unparsable: {e}"),
    })?;
    match Argon2::default().verify_password(plaintext.as_bytes(), &parsed) {
        Ok(()) => Ok(true),
        // A wrong password is the expected negative — surface it as `false`, not an error.
        Err(PhcError::Password) => Ok(false),
        Err(e) => Err(AuthError::PasswordHash {
            detail: e.to_string(),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_a_known_password() {
        let hash = hash_password("correct horse battery staple").unwrap();
        assert!(verify_password("correct horse battery staple", &hash).unwrap());
    }

    #[test]
    fn rejects_a_wrong_password() {
        let hash = hash_password("s3cr3t-strong").unwrap();
        assert!(!verify_password("not-the-password", &hash).unwrap());
    }

    #[test]
    fn never_stores_plaintext() {
        // The PHC string must be an argon2id descriptor, not the plaintext.
        let hash = hash_password("plaintextvalue").unwrap();
        assert!(hash.starts_with("$argon2id$"), "unexpected PHC: {hash}");
        assert!(!hash.contains("plaintextvalue"));
    }

    #[test]
    fn same_password_hashes_differently_each_time() {
        // Distinct random salts ⇒ distinct PHC strings, yet both verify.
        let a = hash_password("same-strong-pw").unwrap();
        let b = hash_password("same-strong-pw").unwrap();
        assert_ne!(a, b);
        assert!(verify_password("same-strong-pw", &a).unwrap());
        assert!(verify_password("same-strong-pw", &b).unwrap());
    }

    #[test]
    fn empty_or_short_password_is_rejected() {
        // Empty and below-minimum passwords are refused before any hashing happens.
        assert!(matches!(
            hash_password(""),
            Err(AuthError::WeakPassword { .. })
        ));
        // 7 characters: one below the 8-character minimum.
        assert!(matches!(
            hash_password("short77"),
            Err(AuthError::WeakPassword { .. })
        ));
    }

    #[test]
    fn password_at_minimum_length_is_accepted() {
        // Exactly 8 characters is the boundary and must hash successfully.
        let pw = "8charsok";
        assert_eq!(pw.chars().count(), MIN_PASSWORD_LEN);
        let hash = hash_password(pw).unwrap();
        assert!(verify_password(pw, &hash).unwrap());
    }

    #[test]
    fn malformed_stored_hash_is_an_error_not_a_false() {
        let err = verify_password("whatever", "not-a-phc-string").unwrap_err();
        assert!(matches!(err, AuthError::PasswordHash { .. }));
    }
}
