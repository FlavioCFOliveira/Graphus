//! **RFC 9457 Problem Details** (`application/problem+json`) — the single error shape for every
//! REST failure (`04-technical-design.md` §8.2; `06-bolt-and-error-shapes.md` §3.3).
//!
//! `06 §3.3` fixes that a Cypher/engine error over REST is rendered as an RFC 9457 problem object,
//! the **REST sibling** of the Bolt `FAILURE` (`graphus_bolt::error::failure_from_error`): both are
//! derived from the same engine [`GraphusError`] and its TCK `(phase, type, detail)` classification,
//! so the two interfaces report one error model (`04 §8.3`). This module is the REST renderer.
//!
//! An RFC 9457 object carries (RFC 9457 §3.1):
//!
//! - **`type`** — a URI reference identifying the problem *kind* (here a stable `urn:graphus:error:*`
//!   URN, so the type is dereference-free and versionable without a docs host).
//! - **`title`** — a short, human-readable summary of the kind (stable per `type`).
//! - **`status`** — the HTTP status code, duplicated in the body per RFC 9457.
//! - **`detail`** — a human-readable explanation specific to *this* occurrence (the engine message).
//!
//! Graphus adds one extension member:
//!
//! - **`code`** — the engine's classified error code (the same best-effort `Neo.*`-shaped string the
//!   Bolt `FAILURE` carries — `06 §2.4`, `06 §3.2`), so a client can branch on a stable code rather
//!   than parse `detail`. RFC 9457 §3.2 explicitly allows such extension members.
//!
//! The **phase** (`06 §2.1`) is observable rather than a named field: a compile-time error fails the
//! request before any NDJSON row is emitted; a runtime error may surface after rows have begun
//! streaming (`06 §3.3`).
//!
//! ## Classification mirrors the Bolt mapping (`06 §2`–§3)
//!
//! The status + code derivation from a [`GraphusError`] variant is deliberately the same split
//! `graphus_bolt::error::failure_from_error` uses, so an identical engine error yields a consistent
//! client signal on both wires:
//!
//! | `GraphusError` | HTTP status | `code` | rationale |
//! | --- | --- | --- | --- |
//! | [`GraphusError::Compile`] | 400 | `Neo.ClientError.Statement.SyntaxError` | client query invalid (compile-time, `06 §2.1`) |
//! | [`GraphusError::Runtime`] | 400 | `Neo.ClientError.Statement.ArgumentError` | client-caused runtime fault (`06 §2.3`) |
//! | [`GraphusError::Transaction`] | 409 | `Neo.TransientError.Transaction.Outdated` | retriable serialization/abort (`04 §5.4`; `Terminated` is a driver poison title) |
//! | [`GraphusError::Storage`] | 500 | `Neo.DatabaseError.General.UnknownError` | server-side fault |
//! | [`GraphusError::Protocol`] | 400 | `Neo.ClientError.Request.Invalid` | malformed request/protocol misuse |
//! | [`GraphusError::Security`] | 403 | `Neo.ClientError.Security.Forbidden` | the principal lacks the required privilege (`04 §8.4`) |
//!
//! A 409 (Conflict) for a transaction error is the HTTP-idiomatic "retriable conflict" signal,
//! matching the Bolt `TransientError` classification drivers act on.
//!
//! ## Retryability does not come from the variant alone (`rmp` task #988)
//!
//! The table above is the **fallback**. [`GraphusError::Transaction`] used to be the carrier for both
//! a genuine serialization abort (retriable) and a pile of permanent misuse errors — writing in a
//! READ transaction, naming a transaction that does not exist, an illegal message for the current
//! transaction state — so every one of those was announced as a retriable 409/`TransientError`. Those
//! conditions now travel on a carrier variant of the correct class, carrying a verbatim Neo4j leaf
//! code (see [`graphus_core::status`]), and are answered here with the status that code deserves:
//!
//! | condition | `code` | HTTP |
//! | --- | --- | --- |
//! | write statement in a READ transaction | `Neo.ClientError.Statement.AccessMode` | 400 |
//! | unknown / spent transaction handle | `Neo.ClientError.Transaction.TransactionNotFound` | 404 |
//! | illegal request for the transaction state | `Neo.ClientError.Request.Invalid` | 400 |
//! | engine unavailable (shutting down) | `Neo.TransientError.General.DatabaseUnavailable` | 503 |
//!
//! A genuine serialization abort is unchanged: 409 with
//! `Neo.TransientError.Transaction.Outdated`, retriable.

use graphus_auth::AuthError;
use graphus_core::{
    GraphusError, SCHEMA_RULE_ERROR_PREFIX, SCHEMA_RULE_ERROR_SEP, WIRE_STATUS_CODE_PREFIX,
    WIRE_STATUS_CODE_SEP,
};
use http::StatusCode;
use serde::Serialize;

use crate::value::ValueCodecError;

/// The RFC 9457 media type for a problem-details response.
pub const PROBLEM_JSON: &str = "application/problem+json";

/// The stable, generic `detail` returned to clients for any **server-fault** (5xx) problem (rmp #187,
/// CWE-209). The verbose internal cause is logged server-side only; the client learns nothing about
/// the server's internals (filesystem paths, offsets, storage internals).
const GENERIC_SERVER_FAULT_DETAIL: &str = "an internal error occurred";

/// An RFC 9457 Problem Details object (`06 §3.3`).
///
/// Serialised with the canonical member names. `type`/`title`/`status` are always present; `detail`
/// and the `code` extension are present whenever known (the engine always supplies both here).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Problem {
    /// A URI reference for the problem *kind* (a stable `urn:graphus:error:*` URN).
    #[serde(rename = "type")]
    pub type_uri: String,
    /// A short, human-readable summary of the problem kind (stable per `type`).
    pub title: String,
    /// The HTTP status code (duplicated in the body per RFC 9457 §3.1).
    pub status: u16,
    /// A human-readable explanation specific to this occurrence (the engine message).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
    /// The engine's classified error code (`Neo.*`-shaped; `06 §2.4`) — an RFC 9457 extension member.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,
}

impl Problem {
    /// Builds a problem from its parts.
    #[must_use]
    pub fn new(status: StatusCode, kind: &str, title: &str, detail: impl Into<String>) -> Self {
        Self {
            type_uri: format!("urn:graphus:error:{kind}"),
            title: title.to_owned(),
            status: status.as_u16(),
            detail: Some(detail.into()),
            code: None,
        }
    }

    /// Attaches the classified `code` extension member (builder style).
    #[must_use]
    pub fn with_code(mut self, code: &str) -> Self {
        self.code = Some(code.to_owned());
        self
    }

    /// The [`StatusCode`] this problem should be sent with.
    ///
    /// Reconstructed from the stored `u16`; falls back to 500 if it were ever out of range (it is
    /// always set from a valid [`StatusCode`] by the constructors, so the fallback is unreachable in
    /// practice — but we never `unwrap` on a value that round-trips through the wire).
    #[must_use]
    pub fn status_code(&self) -> StatusCode {
        StatusCode::from_u16(self.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR)
    }

    /// Renders a Cypher/engine [`GraphusError`] into an RFC 9457 problem (`06 §3.3`).
    ///
    /// The status and `code` follow the same classification as the Bolt `FAILURE`
    /// (`graphus_bolt::error::failure_from_error`); the `detail` is the engine message with its
    /// `GraphusError::Display` layer prefix stripped (the classification already conveys the layer),
    /// matching the Bolt renderer.
    #[must_use]
    pub fn from_graphus_error(error: &GraphusError) -> Self {
        // A verbatim wire status code (`rmp` task #814): ANY `GraphusError` variant whose
        // (layer-stripped) message carries the `WIRE_STATUS_CODE_PREFIX` sentinel + `<leaf code>
        // \u{1f}<human>` surfaces that Neo4j leaf code VERBATIM — the REST sibling of
        // `graphus_bolt::failure_from_error`'s verbatim handling. The HTTP status is derived from the
        // leaf code's own classification segment so it agrees with the code (a `Neo.ClientError.*`
        // leaf → 400, exactly as the `Neo.ClientError.Request.Invalid` it replaces for the headline
        // `Neo.ClientError.Database.DatabaseNotFound`), i.e. the classification is unchanged and only
        // the fine-grained title becomes exact. A server-fault (`Neo.DatabaseError.*`) leaf uses the
        // generic detail (rmp #187, CWE-209); a client-fault leaf keeps the (server-authored) human
        // message, which helps the client fix its request.
        {
            let stripped = strip_layer_prefix(&error.to_string());
            if let Some(rest) = stripped.strip_prefix(WIRE_STATUS_CODE_PREFIX)
                && let Some((leaf, human)) = rest.split_once(WIRE_STATUS_CODE_SEP)
            {
                let (status, kind, title) = problem_shape_for_leaf_code(leaf);
                let detail = if status.is_server_error() {
                    eprintln!("graphus-rest: internal fault (wire status {leaf}): {error}");
                    GENERIC_SERVER_FAULT_DETAIL.to_owned()
                } else {
                    human.to_owned()
                };
                return Problem::new(status, kind, title, detail).with_code(leaf);
            }
        }

        // A schema-rule declaration error (`rmp` task #624) is a `GraphusError::Runtime` carrying the
        // `SCHEMA_RULE_ERROR_PREFIX` sentinel + `<Neo4j leaf code>\u{1f}<message>`. Surface it as a
        // client-fault **400** with the precise `Neo.ClientError.Schema.*` code and the stripped human
        // message — the REST sibling of `graphus_bolt::failure_from_error`'s schema classification.
        if let GraphusError::Runtime(_) = error {
            let stripped = strip_layer_prefix(&error.to_string());
            if let Some(rest) = stripped.strip_prefix(SCHEMA_RULE_ERROR_PREFIX)
                && let Some((leaf, human)) = rest.split_once(SCHEMA_RULE_ERROR_SEP)
            {
                return Problem::new(
                    StatusCode::BAD_REQUEST,
                    "schema",
                    "schema rule error",
                    human.to_owned(),
                )
                .with_code(leaf);
            }
        }

        // `server_fault` marks the 5xx (server-side) classes whose raw `detail` must NOT reach the
        // untrusted client (rmp #187, CWE-209): an internal/storage fault would otherwise disclose
        // file paths, offsets, and low-level causes. For those, the wire `detail` is a stable generic
        // string and the verbose cause is logged server-side only. Client-fault 4xx detail is kept —
        // it is the client's own request that is at fault and the detail helps them fix it.
        let (status, kind, title, code, server_fault) = match error {
            GraphusError::Compile(_) => (
                StatusCode::BAD_REQUEST,
                "compile",
                "Cypher compile-time error",
                CODE_COMPILE_SYNTAX,
                false,
            ),
            GraphusError::Runtime(_) => (
                StatusCode::BAD_REQUEST,
                "runtime",
                "Cypher runtime error",
                CODE_RUNTIME_ARGUMENT,
                false,
            ),
            GraphusError::Transaction(_) => (
                StatusCode::CONFLICT,
                "transaction",
                "transaction error",
                CODE_TXN_CONFLICT_RETRYABLE,
                false,
            ),
            GraphusError::Storage(_) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "storage",
                "storage error",
                CODE_DB_UNKNOWN,
                true,
            ),
            GraphusError::Protocol(_) => (
                StatusCode::BAD_REQUEST,
                "protocol",
                "protocol error",
                CODE_REQUEST_INVALID,
                false,
            ),
            GraphusError::Security(_) => (
                StatusCode::FORBIDDEN,
                "forbidden",
                "not authorized",
                CODE_FORBIDDEN,
                false,
            ),
            // `#[non_exhaustive]`: an unclassified future variant defaults to a server fault.
            _ => (
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal",
                "internal error",
                CODE_DB_UNKNOWN,
                true,
            ),
        };

        if server_fault {
            // Log the verbose internal cause server-side, never on the wire (rmp #187, CWE-209).
            eprintln!("graphus-rest: internal {kind} fault: {error}");
            return Problem::new(status, kind, title, GENERIC_SERVER_FAULT_DETAIL).with_code(code);
        }
        Problem::new(status, kind, title, strip_layer_prefix(&error.to_string())).with_code(code)
    }

    /// Renders an authentication/authorization [`AuthError`] into an RFC 9457 problem.
    ///
    /// Authentication failures (unknown principal, bad/expired token) are **401 Unauthorized**;
    /// authorization failures (known principal lacking the privilege) are **403 Forbidden**
    /// (`04 §8.4`). The `detail` is the [`AuthError`] `Display`, which is deliberately
    /// non-enumerating for the authentication cases (it never reveals whether a user exists).
    #[must_use]
    pub fn from_auth_error(error: &AuthError) -> Self {
        match error {
            AuthError::Unauthorized => Problem::new(
                StatusCode::FORBIDDEN,
                "forbidden",
                "not authorized",
                error.to_string(),
            )
            .with_code(CODE_FORBIDDEN),
            // Every other auth failure is an authentication failure → 401.
            _ => Problem::new(
                StatusCode::UNAUTHORIZED,
                "unauthorized",
                "authentication failed",
                error.to_string(),
            )
            .with_code(CODE_UNAUTHORIZED),
        }
    }

    /// A **400 Bad Request** for a malformed request body / bad value encoding
    /// ([`ValueCodecError`]) — a client-side fault at the decode boundary.
    #[must_use]
    pub fn from_codec_error(error: &ValueCodecError) -> Self {
        Problem::new(
            StatusCode::BAD_REQUEST,
            "bad-request",
            "malformed request body",
            error.to_string(),
        )
        .with_code(CODE_REQUEST_INVALID)
    }

    /// A **400 Bad Request** with a bespoke message (e.g. an invalid `access_mode` value — `06 §4`).
    #[must_use]
    pub fn bad_request(detail: impl Into<String>) -> Self {
        Problem::new(
            StatusCode::BAD_REQUEST,
            "bad-request",
            "bad request",
            detail,
        )
        .with_code(CODE_REQUEST_INVALID)
    }

    /// A **429 Too Many Requests** when the open-transaction cap is reached (rmp #448, CWE-770): one
    /// authenticated principal cannot accumulate unbounded open explicit transactions (each pins the MVCC
    /// GC watermark and grows memory on a shared engine — a slow-motion OOM affecting co-tenants). It is
    /// a **retriable** load-shed: the client should back off and retry once an in-flight transaction
    /// commits/expires and frees a slot, so it carries a *transient* (not client-fault) Neo error code,
    /// matching how a "server busy" admission reject is surfaced.
    #[must_use]
    pub fn too_many_transactions(detail: impl Into<String>) -> Self {
        Problem::new(
            StatusCode::TOO_MANY_REQUESTS,
            "too-many-transactions",
            "too many open transactions",
            detail,
        )
        .with_code(CODE_TXN_CONFLICT_RETRYABLE)
    }

    /// A **401 Unauthorized** for a failed `POST /auth/login` (rmp #499): a wrong password **or** an
    /// unknown user, deliberately **indistinguishable**.
    ///
    /// The `detail` is a fixed, generic `"invalid username or password"` for *both* causes, so the
    /// login endpoint is never a user-existence oracle (CWE-204): an attacker learns nothing about
    /// whether a given username exists. It reuses the same `unauthorized` kind/title/code as a failed
    /// Bearer validation, so a client sees one consistent authentication-failure shape.
    #[must_use]
    pub fn invalid_credentials() -> Self {
        Problem::new(
            StatusCode::UNAUTHORIZED,
            "unauthorized",
            "authentication failed",
            "invalid username or password",
        )
        .with_code(CODE_UNAUTHORIZED)
    }

    /// A **429 Too Many Requests** when the per-account login throttle (rmp #458) rejects an attempt
    /// **before** the expensive Argon2 verification: the account has exhausted its failed-login budget
    /// within the window.
    ///
    /// It is a **retriable** load-shed (the bucket refills over time), so it carries the
    /// authentication-rate-limit code rather than a permanent client-fault code — the client should
    /// back off and retry once the throttle window refills, exactly as for
    /// [`too_many_transactions`](Self::too_many_transactions). A *successful* login is never throttled
    /// (a correct credential does not debit the bucket), so a legitimate client is unaffected by its
    /// own attempt rate.
    #[must_use]
    pub fn too_many_login_attempts(detail: impl Into<String>) -> Self {
        Problem::new(
            StatusCode::TOO_MANY_REQUESTS,
            "too-many-login-attempts",
            "too many login attempts",
            detail,
        )
        .with_code(CODE_AUTH_RATE_LIMIT)
    }

    /// A **503 Service Unavailable** when the global concurrent-password-verification bound (rmp #824)
    /// is saturated: the server is momentarily at its Argon2 verification capacity, so the login is shed
    /// **before** the memory-hard KDF runs rather than piling unbounded concurrent hashing onto the
    /// shared blocking pool — the pre-authentication availability collapse a *username-rotation* flood
    /// would otherwise force, which the per-account throttle cannot bound.
    ///
    /// It is a **retriable** load-shed (capacity frees as in-flight verifications finish), so it carries
    /// a *transient* Neo error code; the client should back off briefly and retry. The shed reads only
    /// the global in-flight count — never the submitted username — so it is byte-identical for a valid
    /// vs an invalid user and is never a user-existence oracle (preserving the rmp #812 constant-work
    /// property).
    #[must_use]
    pub fn service_unavailable(detail: impl Into<String>) -> Self {
        Problem::new(
            StatusCode::SERVICE_UNAVAILABLE,
            "service-unavailable",
            "server busy verifying credentials",
            detail,
        )
        .with_code(CODE_SERVER_BUSY)
    }

    /// A **404 Not Found** for an unknown transaction id (`04 §8.2`).
    #[must_use]
    pub fn unknown_transaction(id: &str) -> Self {
        Problem::new(
            StatusCode::NOT_FOUND,
            "unknown-transaction",
            "unknown transaction",
            format!("no open transaction with id `{id}` (it may have expired or been rolled back)"),
        )
        .with_code(CODE_TXN_NOT_FOUND)
    }

    /// A **406 Not Acceptable** when the `Accept` header asks for a representation Graphus cannot
    /// produce (content negotiation — `04 §8.2`).
    #[must_use]
    pub fn not_acceptable(detail: impl Into<String>) -> Self {
        Problem::new(
            StatusCode::NOT_ACCEPTABLE,
            "not-acceptable",
            "not acceptable",
            detail,
        )
        .with_code(CODE_REQUEST_INVALID)
    }

    /// A **415 Unsupported Media Type** when the request `Content-Type` is one Graphus cannot decode.
    #[must_use]
    pub fn unsupported_media_type(detail: impl Into<String>) -> Self {
        Problem::new(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            "unsupported-media-type",
            "unsupported media type",
            detail,
        )
        .with_code(CODE_REQUEST_INVALID)
    }
}

// Best-effort engine codes (shared classification with the Bolt `FAILURE`; `06 §2.4` deferral).
const CODE_COMPILE_SYNTAX: &str = "Neo.ClientError.Statement.SyntaxError";
const CODE_RUNTIME_ARGUMENT: &str = "Neo.ClientError.Statement.ArgumentError";
/// The retriable serialization-conflict code (kept byte-identical to `graphus_bolt`'s
/// `CODE_TXN_CONFLICT_RETRYABLE` for cross-wire parity). The title MUST NOT be `Terminated` /
/// `LockClientStopped`: those are Neo4j-driver **poison titles** that the driver `ERROR_REWRITE_MAP`
/// downgrades from TransientError to a non-retriable ClientError, breaking managed-transaction retry.
/// `Outdated` = optimistic-concurrency abort, retriable, not rewritten. (rmp #612.)
const CODE_TXN_CONFLICT_RETRYABLE: &str = "Neo.TransientError.Transaction.Outdated";
const CODE_TXN_NOT_FOUND: &str = "Neo.ClientError.Transaction.TransactionNotFound";
const CODE_DB_UNKNOWN: &str = "Neo.DatabaseError.General.UnknownError";
const CODE_REQUEST_INVALID: &str = "Neo.ClientError.Request.Invalid";
const CODE_UNAUTHORIZED: &str = "Neo.ClientError.Security.Unauthorized";
const CODE_FORBIDDEN: &str = "Neo.ClientError.Security.Forbidden";
/// The auth-rate-limit code for a throttled login (rmp #458/#499): the same best-effort `Neo.*`-shaped
/// rendering the rest of the surface uses (`06 §2.4`), matching Neo4j's authentication-rate-limit class.
const CODE_AUTH_RATE_LIMIT: &str = "Neo.ClientError.Security.AuthenticationRateLimit";
/// The "server busy at authentication" transient code for a login shed by the global
/// concurrent-verification bound (rmp #824), byte-identical to `graphus_bolt`'s `CODE_SERVER_BUSY`
/// (`Neo.TransientError.General.DatabaseUnavailable`) for cross-wire parity: a **retryable**
/// `TransientError` telling the client to back off and retry, not a credential failure.
const CODE_SERVER_BUSY: &str = "Neo.TransientError.General.DatabaseUnavailable";

/// Derives the RFC 9457 HTTP status from a verbatim Neo4j leaf status code's classification segment
/// Derives the RFC 9457 problem shape — HTTP status, `type` suffix (`kind`) and human `title` — from
/// a verbatim Neo4j leaf status code's classification segment (`rmp` task #814), so a
/// `WIRE_STATUS_CODE_PREFIX`-tagged error's status/kind agree with the code it carries. The
/// classification is the second dotted segment (`Neo.<Classification>.<Category>.<Title>`):
///
/// - `TransientError` → **409 Conflict** (retriable — the same status the retriable
///   `Neo.TransientError.Transaction.*` class maps to);
/// - `DatabaseError` → **500 Internal Server Error** (server fault);
/// - anything else (`ClientError`, or a malformed code) → **400 Bad Request** (client fault) — the
///   conservative default that matches the `Neo.ClientError.Request.Invalid` these codes refine.
///
/// Two leaf codes are answered more precisely than their classification alone would give (`rmp` task
/// #988), because HTTP has a *better* status for them than the class default and REST clients branch
/// on the status long before they read the body:
///
/// - `Neo.ClientError.Transaction.TransactionNotFound` → **404 Not Found**, not the ClientError
///   default of 400. The named resource is a transaction that does not exist, which is what 404
///   means; it is also what the reference server answers (`TransactionNotFoundException` passes
///   `Response.Status.NOT_FOUND`) and what [`Problem::unknown_transaction`] — the twin the router
///   raises when it fails to resolve the id itself — has always answered. Routing both to the same
///   status *and* the same `type` URN means one condition has one REST shape however it is detected.
/// - `Neo.TransientError.General.DatabaseUnavailable` → **503 Service Unavailable**, not the
///   TransientError default of 409. 409 means "conflict with the target resource's current state"
///   (RFC 9110 §15.5.10) — a serialization abort — whereas this code means the server cannot serve
///   the request at all right now, which is precisely 503 (RFC 9110 §15.6.4). It is also the status
///   [`Problem::service_unavailable`] already answers for the same leaf code, so the two agree.
fn problem_shape_for_leaf_code(code: &str) -> (StatusCode, &'static str, &'static str) {
    match code {
        CODE_TXN_NOT_FOUND => {
            return (
                StatusCode::NOT_FOUND,
                "unknown-transaction",
                "unknown transaction",
            );
        }
        CODE_SERVER_BUSY => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                "service-unavailable",
                "service unavailable",
            );
        }
        _ => {}
    }
    match code.split('.').nth(1) {
        Some("TransientError") => (StatusCode::CONFLICT, "transient", "transient error"),
        Some("DatabaseError") => (
            StatusCode::INTERNAL_SERVER_ERROR,
            "database",
            "database error",
        ),
        _ => (StatusCode::BAD_REQUEST, "client-error", "client error"),
    }
}

/// Removes the `GraphusError::Display` layer prefix (`"<layer> error: "`) so the problem `detail`
/// is the bare human description — mirrors `graphus_bolt::error`'s `strip_layer_prefix`.
fn strip_layer_prefix(s: &str) -> String {
    for prefix in [
        "storage error: ",
        "transaction error: ",
        "compile error: ",
        "runtime error: ",
        "protocol error: ",
        "security error: ",
    ] {
        if let Some(rest) = s.strip_prefix(prefix) {
            return rest.to_owned();
        }
    }
    s.to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compile_error_is_400_with_syntax_code_and_stripped_detail() {
        let p = Problem::from_graphus_error(&GraphusError::Compile(
            "Variable `n` not defined".to_owned(),
        ));
        assert_eq!(p.status, 400);
        assert_eq!(p.code.as_deref(), Some(CODE_COMPILE_SYNTAX));
        // The `compile error: ` layer prefix is stripped.
        assert_eq!(p.detail.as_deref(), Some("Variable `n` not defined"));
        assert_eq!(p.type_uri, "urn:graphus:error:compile");
    }

    #[test]
    fn transaction_error_is_409_transient() {
        let p = Problem::from_graphus_error(&GraphusError::Transaction(
            "serialization failure".to_owned(),
        ));
        assert_eq!(p.status, 409);
        let code = p.code.as_deref().unwrap();
        assert!(code.contains("TransientError"));
        // Regression guard (rmp #612): keep the title off the Neo4j-driver poison list, so managed
        // retry works on the Bolt wire that shares this classification.
        assert!(!code.ends_with(".Terminated"), "poison title: {code}");
        assert!(
            !code.ends_with(".LockClientStopped"),
            "poison title: {code}"
        );
    }

    #[test]
    fn storage_error_is_500() {
        let p = Problem::from_graphus_error(&GraphusError::Storage("disk".to_owned()));
        assert_eq!(p.status, 500);
    }

    #[test]
    fn server_fault_detail_is_redacted() {
        // rmp #187 (CWE-209): a 500 must carry a generic detail, never the raw internal cause.
        let p = Problem::from_graphus_error(&GraphusError::Storage(
            "page fault at /var/lib/graphus/data/store.0001 offset 0xDEADBEEF".to_owned(),
        ));
        assert_eq!(p.status, 500);
        assert_eq!(p.detail.as_deref(), Some(GENERIC_SERVER_FAULT_DETAIL));
        let detail = p.detail.unwrap();
        assert!(!detail.contains("/var/lib/graphus"));
        assert!(!detail.contains("0xDEADBEEF"));
    }

    #[test]
    fn wire_status_code_sentinel_emits_verbatim_leaf_with_classification_derived_status() {
        // The verbatim-leaf-code mechanism (`rmp` task #814), REST sibling of the Bolt renderer: a
        // `Neo.ClientError.Database.DatabaseNotFound` carried on a `GraphusError::Protocol` (the
        // session-targeting unknown-database case) surfaces the leaf VERBATIM at a 400 (its
        // ClientError classification — the SAME status the coarse Request.Invalid it refines used),
        // with the sentinel + code stripped from the detail.
        let msg = graphus_core::wire_status_code_message(
            "Neo.ClientError.Database.DatabaseNotFound",
            "database \"ghost\" does not exist",
        );
        let p = Problem::from_graphus_error(&GraphusError::Protocol(msg));
        assert_eq!(p.status, 400);
        assert_eq!(
            p.code.as_deref(),
            Some("Neo.ClientError.Database.DatabaseNotFound")
        );
        assert_eq!(
            p.detail.as_deref(),
            Some("database \"ghost\" does not exist")
        );
    }

    #[test]
    fn wire_status_code_status_tracks_classification_segment() {
        // The derived status agrees with the leaf code's own classification: ClientError → 400,
        // TransientError → 409 (retriable), DatabaseError → 500 (server fault, generic detail).
        assert_eq!(
            problem_shape_for_leaf_code("Neo.ClientError.Database.DatabaseNotFound").0,
            StatusCode::BAD_REQUEST
        );
        // A TransientError leaf with no more precise HTTP answer keeps the class default of 409.
        // (`Neo.TransientError.General.DatabaseUnavailable` is deliberately NOT the probe here — it
        // is one of the two codes `rmp` #988 refines; see the test below.)
        assert_eq!(
            problem_shape_for_leaf_code("Neo.TransientError.Transaction.DeadlockDetected").0,
            StatusCode::CONFLICT
        );
        assert_eq!(
            problem_shape_for_leaf_code("Neo.DatabaseError.Database.Unknown").0,
            StatusCode::INTERNAL_SERVER_ERROR
        );
        // A server-fault leaf redacts its detail (rmp #187) even when carried by the sentinel.
        let msg = graphus_core::wire_status_code_message(
            "Neo.DatabaseError.Database.Unknown",
            "internal path /var/lib/graphus/store leaked",
        );
        let p = Problem::from_graphus_error(&GraphusError::Storage(msg));
        assert_eq!(p.status, 500);
        assert_eq!(p.detail.as_deref(), Some(GENERIC_SERVER_FAULT_DETAIL));
    }

    #[test]
    fn the_two_refined_leaf_codes_get_a_better_status_than_their_class_default() {
        // `rmp` #988. Both of these would land on their classification default (400 / 409) if the
        // shape were derived from the classification segment alone, and both have a strictly better
        // HTTP answer that REST clients branch on before they read the body.

        // An unknown/spent transaction handle is a missing resource: 404, not 400.
        let (status, kind, title) =
            problem_shape_for_leaf_code("Neo.ClientError.Transaction.TransactionNotFound");
        assert_eq!(status, StatusCode::NOT_FOUND);
        // ... and it lands on the SAME `type` URN + title as `Problem::unknown_transaction`, the twin
        // the router raises when it fails to resolve the id itself: one condition, one REST shape,
        // however it is detected.
        let router_twin = Problem::unknown_transaction("7");
        assert_eq!(format!("urn:graphus:error:{kind}"), router_twin.type_uri);
        assert_eq!(title, router_twin.title);
        assert_eq!(status.as_u16(), router_twin.status);

        // An unavailable engine cannot serve the request at all: 503, not 409 ("conflict with the
        // target resource's current state", RFC 9110 §15.5.10, which this is not).
        let (status, kind, title) =
            problem_shape_for_leaf_code("Neo.TransientError.General.DatabaseUnavailable");
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        // Same agreement with `Problem::service_unavailable`, which already answers 503 for this leaf.
        let busy_twin = Problem::service_unavailable("busy");
        assert_eq!(format!("urn:graphus:error:{kind}"), busy_twin.type_uri);
        assert_eq!(status.as_u16(), busy_twin.status);
        assert_eq!(title, "service unavailable");

        // End to end, through the constructor a seam actually calls.
        let p = Problem::from_graphus_error(&graphus_core::status::database_unavailable(
            "engine unavailable (server shutting down)",
        ));
        assert_eq!(p.status, 503);
        assert_eq!(
            p.code.as_deref(),
            Some("Neo.TransientError.General.DatabaseUnavailable")
        );
        // Still a retriable TransientError — this fix moves the STATUS, never the retryability.
        assert!(p.code.as_deref().unwrap().contains("TransientError"));

        let p = Problem::from_graphus_error(&graphus_core::status::transaction_not_found(
            "transaction handle 7",
        ));
        assert_eq!(p.status, 404);
        assert_eq!(
            p.code.as_deref(),
            Some("Neo.ClientError.Transaction.TransactionNotFound")
        );
        // Non-retryable: a ClientError, NOT the transient class it used to be announced as.
        assert!(!p.code.as_deref().unwrap().contains("TransientError"));
    }

    #[test]
    fn untagged_protocol_still_maps_to_400_request_invalid() {
        // Non-regression guard (`rmp` task #814): a plain `GraphusError::Protocol` WITHOUT the
        // sentinel stays the coarse 400 `Neo.ClientError.Request.Invalid`.
        let p = Problem::from_graphus_error(&GraphusError::Protocol("bad frame".to_owned()));
        assert_eq!(p.status, 400);
        assert_eq!(p.code.as_deref(), Some(CODE_REQUEST_INVALID));
    }

    #[test]
    fn security_error_is_403_forbidden_with_stripped_detail() {
        let p = Problem::from_graphus_error(&GraphusError::Security(
            "permission denied: admin required".to_owned(),
        ));
        assert_eq!(p.status, 403);
        assert_eq!(p.code.as_deref(), Some(CODE_FORBIDDEN));
        assert_eq!(
            p.detail.as_deref(),
            Some("permission denied: admin required")
        );
    }

    #[test]
    fn auth_unauthorized_is_403_others_401() {
        assert_eq!(
            Problem::from_auth_error(&AuthError::Unauthorized).status,
            403
        );
        assert_eq!(
            Problem::from_auth_error(&AuthError::Unauthenticated).status,
            401
        );
        assert_eq!(
            Problem::from_auth_error(&AuthError::TokenExpired).status,
            401
        );
    }

    #[test]
    fn problem_serializes_with_rfc9457_member_names() {
        let p = Problem::bad_request("bad access_mode");
        let json = serde_json::to_value(&p).unwrap();
        assert_eq!(json["type"], "urn:graphus:error:bad-request");
        assert_eq!(json["status"], 400);
        assert_eq!(json["detail"], "bad access_mode");
        assert!(json["title"].is_string());
        assert!(json["code"].is_string());
    }

    #[test]
    fn status_code_round_trips() {
        let p = Problem::unknown_transaction("tx-7");
        assert_eq!(p.status_code(), StatusCode::NOT_FOUND);
    }

    #[test]
    fn invalid_credentials_is_uniform_401_with_no_oracle() {
        // rmp #499 (CWE-204): the wrong-password and unknown-user 401s must be byte-identical, so the
        // login endpoint never reveals whether a username exists.
        let p = Problem::invalid_credentials();
        assert_eq!(p.status, 401);
        assert_eq!(p.detail.as_deref(), Some("invalid username or password"));
        assert_eq!(p.code.as_deref(), Some(CODE_UNAUTHORIZED));
        // Calling it again yields the same object (the fixed, cause-independent shape).
        assert_eq!(Problem::invalid_credentials(), p);
    }

    #[test]
    fn too_many_login_attempts_is_retriable_429() {
        let p = Problem::too_many_login_attempts("account login throttled");
        assert_eq!(p.status, 429);
        assert_eq!(p.code.as_deref(), Some(CODE_AUTH_RATE_LIMIT));
        assert_eq!(p.type_uri, "urn:graphus:error:too-many-login-attempts");
    }
}
