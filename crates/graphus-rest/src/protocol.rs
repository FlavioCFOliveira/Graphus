//! The REST transactional API's **request and response body shapes** (`04-technical-design.md`
//! §8.2; `06-bolt-and-error-shapes.md` §4 for `access_mode`).
//!
//! These are the JSON/CBOR-facing structs the router (de)serialises. They are kept free of any
//! engine type: a request carries statements + raw-JSON parameters (decoded to [`graphus_core::Value`]
//! by [`crate::value`] at the boundary), and a response carries the transaction metadata and result
//! envelopes. The actual `Value` ↔ bytes work lives in [`crate::value`]; this module only frames the
//! *envelope* around it.
//!
//! ## `access_mode` (`06 §4`)
//!
//! A transaction declares its access mode through an **`access_mode`** member with values
//! **`"READ"`** / **`"WRITE"`**, defaulting to **`"WRITE"`** when absent (`06 §4`). An invalid value
//! is a client error (the router returns `400` problem+json and does not open the transaction).
//! [`parse_access_mode`] is the single, case-sensitive validator.

use serde::{Deserialize, Serialize};
use serde_json::Value as Json;

use crate::engine::AccessMode;

/// One Cypher statement to execute, with optional parameters (`04 §8.2`).
///
/// `parameters` is held as raw JSON (Jolt sparse or strict) and decoded to
/// [`graphus_core::Value`] by [`crate::value::jolt_to_value`] when the router binds it, so this
/// struct stays codec-agnostic. (For a CBOR request the router decodes the whole body to JSON-shaped
/// values first; the envelope is identical.)
#[derive(Debug, Clone, Deserialize)]
pub struct Statement {
    /// The Cypher query text.
    pub statement: String,
    /// The query parameters as a JSON object (`{name: value}`), or absent for none.
    #[serde(default)]
    pub parameters: Option<Json>,
}

/// A request body carrying a batch of statements to run (`POST …/tx`, `…/tx/{id}`, `…/tx/{id}/commit`).
///
/// The `access_mode` member is only meaningful on the open/auto-commit entry points; it is parsed
/// from the body by the router via [`parse_access_mode`] (kept as raw here so an *invalid* value can
/// be rejected with a tailored `400` rather than a generic deserialization error).
#[derive(Debug, Clone, Default, Deserialize)]
pub struct RunRequest {
    /// The statements to execute, in order. May be empty (e.g. an empty commit that just finalises
    /// an open transaction).
    #[serde(default)]
    pub statements: Vec<Statement>,
    /// The raw `access_mode` member, validated by [`parse_access_mode`] (`06 §4`).
    #[serde(default)]
    pub access_mode: Option<Json>,
}

/// Validates the `access_mode` request member (`06 §4`).
///
/// - **Absent** → `Ok(AccessMode::Write)` (the default).
/// - `"READ"` → `Ok(AccessMode::Read)`; `"WRITE"` → `Ok(AccessMode::Write)` (case-sensitive).
/// - Anything else (a non-string, or any other string) → `Err(the offending rendering)`, which the
///   router turns into a `400` problem+json (`06 §4`: an invalid value is a client error and the
///   transaction is not opened).
///
/// # Errors
/// The offending value's compact JSON rendering, for the problem `detail`.
pub fn parse_access_mode(raw: &Option<Json>) -> Result<AccessMode, String> {
    match raw {
        None | Some(Json::Null) => Ok(AccessMode::Write),
        Some(Json::String(s)) if s == "READ" => Ok(AccessMode::Read),
        Some(Json::String(s)) if s == "WRITE" => Ok(AccessMode::Write),
        Some(other) => Err(other.to_string()),
    }
}

/// The response to opening an explicit transaction (`POST /db/{db}/tx`) (`04 §8.2`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BeginResponse {
    /// The public transaction id (URL-safe), to address the tx in later requests.
    pub id: String,
    /// The relative URL of the open transaction (`/db/{db}/tx/{id}`).
    pub commit: String,
    /// The absolute expiry, as **nanoseconds on the injected clock's timeline** (not wall-clock),
    /// after which the transaction is auto-rolled-back unless touched (`04 §8.2`).
    ///
    /// It is the engine's deterministic clock value (`graphus_core::capability::Clock::now_nanos`),
    /// echoed so a client (or a test) can reason about expiry without a wall reference.
    pub expires_at_nanos: u64,
    /// The effective access mode of the transaction (`"READ"` / `"WRITE"`), after defaulting.
    pub access_mode: String,
}

/// One statement's result envelope inside a [`RunResponse`] (`04 §8.2`).
///
/// The `data` rows are typed-value-encoded by the router ([`crate::value`]); here they are held as
/// the already-encoded JSON so the envelope serialises uniformly for the buffered (non-streaming)
/// path. The streaming (NDJSON) path bypasses this struct and writes rows one line at a time
/// ([`crate::router`](mod@crate::router)).
#[derive(Debug, Clone, Serialize)]
pub struct StatementResult {
    /// The result column names, in order.
    pub fields: Vec<String>,
    /// The rows: each a list of typed-encoded values, in `fields` order.
    pub data: Vec<Json>,
    /// The result summary (`type` + `stats`), as a typed-encoded object.
    pub summary: Json,
}

/// The buffered response to running statements in a transaction (`04 §8.2`).
///
/// Used for the non-streaming path; carries one [`StatementResult`] per statement plus the
/// transaction metadata (the same envelope is returned by `…/tx/{id}` and the committing endpoints,
/// with `id`/`expires_at_nanos` omitted once the tx is closed).
#[derive(Debug, Clone, Serialize)]
pub struct RunResponse {
    /// The per-statement results, in request order.
    pub results: Vec<StatementResult>,
    /// The open transaction's id, while it remains open (absent after commit/rollback).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    /// The refreshed expiry (nanoseconds on the injected clock), while the tx remains open.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at_nanos: Option<u64>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn access_mode_absent_defaults_to_write() {
        assert_eq!(parse_access_mode(&None), Ok(AccessMode::Write));
        assert_eq!(parse_access_mode(&Some(Json::Null)), Ok(AccessMode::Write));
    }

    #[test]
    fn access_mode_read_and_write_parse() {
        assert_eq!(
            parse_access_mode(&Some(Json::String("READ".to_owned()))),
            Ok(AccessMode::Read)
        );
        assert_eq!(
            parse_access_mode(&Some(Json::String("WRITE".to_owned()))),
            Ok(AccessMode::Write)
        );
    }

    #[test]
    fn access_mode_is_case_sensitive_and_rejects_garbage() {
        // `06 §4`: case-sensitive; anything else is a client error.
        assert!(parse_access_mode(&Some(Json::String("read".to_owned()))).is_err());
        assert!(parse_access_mode(&Some(Json::String("ReadWrite".to_owned()))).is_err());
        assert!(parse_access_mode(&Some(serde_json::json!(7))).is_err());
        assert!(parse_access_mode(&Some(serde_json::json!(true))).is_err());
    }

    #[test]
    fn run_request_deserializes_statements_and_params() {
        let body = serde_json::json!({
            "statements": [
                { "statement": "RETURN $x", "parameters": { "x": 1 } },
                { "statement": "MATCH (n) RETURN n" }
            ],
            "access_mode": "READ"
        });
        let req: RunRequest = serde_json::from_value(body).unwrap();
        assert_eq!(req.statements.len(), 2);
        assert_eq!(req.statements[0].statement, "RETURN $x");
        assert!(req.statements[0].parameters.is_some());
        assert!(req.statements[1].parameters.is_none());
        assert_eq!(parse_access_mode(&req.access_mode), Ok(AccessMode::Read));
    }

    #[test]
    fn run_request_defaults_to_empty() {
        let req: RunRequest = serde_json::from_value(serde_json::json!({})).unwrap();
        assert!(req.statements.is_empty());
        assert_eq!(parse_access_mode(&req.access_mode), Ok(AccessMode::Write));
    }
}
