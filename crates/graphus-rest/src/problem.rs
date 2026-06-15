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
//! | [`GraphusError::Transaction`] | 409 | `Neo.TransientError.Transaction.Terminated` | retriable serialization/abort (`04 §5.4`) |
//! | [`GraphusError::Storage`] | 500 | `Neo.DatabaseError.General.UnknownError` | server-side fault |
//! | [`GraphusError::Protocol`] | 400 | `Neo.ClientError.Request.Invalid` | malformed request/protocol misuse |
//! | [`GraphusError::Security`] | 403 | `Neo.ClientError.Security.Forbidden` | the principal lacks the required privilege (`04 §8.4`) |
//!
//! A 409 (Conflict) for a transaction error is the HTTP-idiomatic "retriable conflict" signal,
//! matching the Bolt `TransientError` classification drivers act on.

use graphus_auth::AuthError;
use graphus_core::GraphusError;
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
                CODE_TXN_TERMINATED,
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
const CODE_TXN_TERMINATED: &str = "Neo.TransientError.Transaction.Terminated";
const CODE_TXN_NOT_FOUND: &str = "Neo.ClientError.Transaction.TransactionNotFound";
const CODE_DB_UNKNOWN: &str = "Neo.DatabaseError.General.UnknownError";
const CODE_REQUEST_INVALID: &str = "Neo.ClientError.Request.Invalid";
const CODE_UNAUTHORIZED: &str = "Neo.ClientError.Security.Unauthorized";
const CODE_FORBIDDEN: &str = "Neo.ClientError.Security.Forbidden";

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
        assert!(p.code.as_deref().unwrap().contains("TransientError"));
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
}
