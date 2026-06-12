//! The crate's error type, and the mapping from a Graphus engine error onto a Bolt `FAILURE`
//! (`06-bolt-and-error-shapes.md` §2–§3).
//!
//! Two distinct things live here:
//!
//! - [`BoltError`] — a *protocol/codec* error (a malformed frame, a bad handshake, a state-machine
//!   violation, a transport read/write failure). These are faults in the Bolt conversation itself,
//!   not Cypher errors. At the connectivity boundary a `BoltError` converts into
//!   [`graphus_core::GraphusError::Protocol`].
//! - [`Failure`] and [`failure_from_error`] — the rendering of a Cypher/engine
//!   [`graphus_core::GraphusError`] into the `{code, message}` pair a Bolt `FAILURE` carries
//!   (`06 §3.2`).
//!
//! ## Status-code mapping is a documented best-effort (deferral)
//!
//! `06 §2.4` **defers** the verbatim Neo4j two-letter Bolt status codes (e.g.
//! `Neo.ClientError.Statement.SyntaxError`): they are a Neo4j surface, not part of the openCypher
//! TCK triple, and pinning them verbatim needs the certified driver artifacts. Until then, `06 §3.2`
//! says a `FAILURE` carries "the engine's own classified rendering of the triple". [`failure_from_error`]
//! therefore produces a **`Neo.<Classification>.*`-shaped best-effort code** derived from the
//! [`GraphusError`] variant (the phase/type the engine already knows), and renders the human message
//! verbatim. Every code this module emits is marked here as best-effort so the eventual verbatim
//! mapping (`06 §2.4` flag) has a single place to replace.

use std::fmt;

use graphus_core::{CONSTRAINT_VIOLATION_PREFIX, GraphusError};

/// The crate-wide result alias for protocol/codec operations.
pub type BoltResult<T> = std::result::Result<T, BoltError>;

/// A Bolt protocol or codec error — a fault in the Bolt conversation, distinct from a Cypher error.
///
/// A Cypher/engine error is *not* a `BoltError`: it is delivered to the client as a Bolt `FAILURE`
/// (see [`Failure`]) and is a normal part of a healthy session. A `BoltError`, by contrast, means
/// the wire conversation itself is broken (bad bytes, illegal message for the current state, a
/// transport failure) and typically tears the connection down.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum BoltError {
    /// A value/message could not be encoded (e.g. a structure with more than 15 fields).
    Encode(String),
    /// A byte stream could not be decoded (truncated, bad marker, bad UTF-8, unknown tag).
    Decode(String),
    /// The handshake was malformed or proposed no acceptable version.
    Handshake(String),
    /// A message arrived that is illegal for the connection's current state (`04 §8.1`).
    Protocol(String),
    /// The underlying transport failed to read or write bytes.
    Transport(String),
}

impl fmt::Display for BoltError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Encode(m) => write!(f, "bolt encode error: {m}"),
            Self::Decode(m) => write!(f, "bolt decode error: {m}"),
            Self::Handshake(m) => write!(f, "bolt handshake error: {m}"),
            Self::Protocol(m) => write!(f, "bolt protocol error: {m}"),
            Self::Transport(m) => write!(f, "bolt transport error: {m}"),
        }
    }
}

impl std::error::Error for BoltError {}

impl From<BoltError> for GraphusError {
    /// A protocol/codec fault surfaces at the connectivity boundary as
    /// [`GraphusError::Protocol`] (`04 §8`, the connectivity layer's error class).
    fn from(e: BoltError) -> Self {
        GraphusError::Protocol(e.to_string())
    }
}

/// The `{code, message}` pair a Bolt `FAILURE` message carries (`06 §3.2`).
///
/// `code` is a structured status string; `message` is the human-readable description (which, for a
/// compile-time error, preserves the offending byte position carried by `graphus-cypher`'s `Span`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Failure {
    /// The structured status code (best-effort `Neo.*`-shaped string; see the module docs and
    /// `06 §2.4`).
    pub code: String,
    /// The human-readable error message.
    pub message: String,
}

impl Failure {
    /// Constructs a failure from a code and message.
    #[must_use]
    pub fn new(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
        }
    }
}

/// Maps a [`GraphusError`] onto the Bolt `FAILURE` `{code, message}` pair (`06 §3.2`).
///
/// The `code` is a **documented best-effort** `Neo.<Classification>.*` string derived from the
/// error variant (the verbatim Neo4j status code is deferred per `06 §2.4`); the `message` is the
/// error's `Display`, verbatim. The classification follows the TCK phase/type split (`06 §2`):
///
/// | `GraphusError` | best-effort `code` | rationale |
/// | --- | --- | --- |
/// | [`GraphusError::Compile`] | `Neo.ClientError.Statement.SyntaxError` | client's query is invalid (compile-time, `06 §2.1`) |
/// | [`GraphusError::Runtime`] | `Neo.ClientError.Statement.ArgumentError` | client-caused runtime fault (type/arith/entity, `06 §2.3`) |
/// | [`GraphusError::Transaction`] | `Neo.TransientError.Transaction.Terminated` | retriable serialization/abort (`04 §5.4` safe-retry) |
/// | [`GraphusError::Storage`] | `Neo.DatabaseError.General.UnknownError` | server-side fault, not the client's |
/// | [`GraphusError::Protocol`] | `Neo.ClientError.Request.Invalid` | malformed request/protocol misuse |
/// | [`GraphusError::Security`] | `Neo.ClientError.Security.Forbidden` | the principal lacks the required privilege (`04 §8.4`) |
///
/// The `Neo.ClientError` / `Neo.TransientError` / `Neo.DatabaseError` top-level *classification*
/// (client-caused vs retriable vs server fault) is the part drivers act on (retry vs fail), and is
/// faithfully derived from the variant; only the fine-grained third/fourth segments are the
/// best-effort placeholders the `06 §2.4` flag will pin verbatim.
#[must_use]
pub fn failure_from_error(error: &GraphusError) -> Failure {
    // The human message renders verbatim, but strip the `GraphusError` layer prefix
    // ("compile error: ", …) the engine's `Display` adds — the classification already conveys the
    // layer, and Neo4j `FAILURE` messages do not carry that prefix.
    let message = strip_layer_prefix(&error.to_string());

    // A constraint violation (`rmp` task #99) is a `GraphusError::Runtime` whose message carries the
    // internal sentinel `graphus_cypher::CONSTRAINT_VIOLATION_PREFIX`. Detect it and emit the precise
    // openCypher/Neo4j schema class — `Neo.ClientError.Schema.ConstraintValidationFailed` — instead of
    // the generic runtime class, stripping the sentinel from the message the wire carries. This is the
    // TCK-faithful class the driver ecosystem asserts for a unique/existence-constraint breach.
    if let GraphusError::Runtime(_) = error
        && let Some(stripped) = message.strip_prefix(CONSTRAINT_VIOLATION_PREFIX)
    {
        return Failure::new(CODE_CONSTRAINT_VALIDATION, stripped.to_owned());
    }

    let code = match error {
        GraphusError::Compile(_) => CODE_COMPILE_SYNTAX,
        GraphusError::Runtime(_) => CODE_RUNTIME_ARGUMENT,
        GraphusError::Transaction(_) => CODE_TXN_TERMINATED,
        GraphusError::Storage(_) => CODE_DB_UNKNOWN,
        GraphusError::Protocol(_) => CODE_REQUEST_INVALID,
        GraphusError::Security(_) => CODE_FORBIDDEN,
        // `GraphusError` is `#[non_exhaustive]`: a new variant defaults to a server-fault code
        // until it is explicitly classified, which is the safe (non-retriable, owner-visible) choice.
        _ => CODE_DB_UNKNOWN,
    };
    Failure::new(code, message)
}

// Best-effort status codes (`06 §2.4` deferral; replace verbatim when the certified mapping lands).
const CODE_COMPILE_SYNTAX: &str = "Neo.ClientError.Statement.SyntaxError";
const CODE_RUNTIME_ARGUMENT: &str = "Neo.ClientError.Statement.ArgumentError";
const CODE_TXN_TERMINATED: &str = "Neo.TransientError.Transaction.Terminated";
const CODE_DB_UNKNOWN: &str = "Neo.DatabaseError.General.UnknownError";
const CODE_REQUEST_INVALID: &str = "Neo.ClientError.Request.Invalid";
/// The constraint-validation class (`rmp` task #99): a unique/existence-constraint breach. This is
/// the verbatim openCypher/Neo4j class the driver ecosystem asserts for such a failure, so it is
/// emitted as-is (not a best-effort placeholder) — detected via the
/// [`CONSTRAINT_VIOLATION_PREFIX`] sentinel on a [`GraphusError::Runtime`] message.
const CODE_CONSTRAINT_VALIDATION: &str = "Neo.ClientError.Schema.ConstraintValidationFailed";

/// Best-effort code for a failed authentication (`04 §8.4`). Authentication failures are not a
/// `GraphusError` variant (they are an `AuthError` resolved before any engine call), so the server
/// builds this `Failure` directly; the code is the documented best-effort placeholder.
pub const CODE_UNAUTHORIZED: &str = "Neo.ClientError.Security.Unauthorized";

/// Best-effort code for an authorization failure: the authenticated principal lacks the privilege
/// the operation requires ([`GraphusError::Security`], `04 §8.4`).
const CODE_FORBIDDEN: &str = "Neo.ClientError.Security.Forbidden";

/// Removes the `GraphusError::Display` layer prefix (`"<layer> error: "`) so the `FAILURE` message
/// is the bare human description.
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
    fn bolt_error_converts_to_protocol_graphus_error() {
        let e: GraphusError = BoltError::Decode("bad".to_owned()).into();
        assert!(matches!(e, GraphusError::Protocol(_)));
        assert!(e.to_string().contains("bolt decode error: bad"));
    }

    #[test]
    fn compile_error_maps_to_client_syntax_code_without_prefix() {
        let f = failure_from_error(&GraphusError::Compile(
            "Variable `n` not defined".to_owned(),
        ));
        assert_eq!(f.code, CODE_COMPILE_SYNTAX);
        assert_eq!(f.message, "Variable `n` not defined");
    }

    #[test]
    fn runtime_error_maps_to_client_argument_code() {
        let f = failure_from_error(&GraphusError::Runtime("/ by zero".to_owned()));
        assert_eq!(f.code, CODE_RUNTIME_ARGUMENT);
        assert_eq!(f.message, "/ by zero");
    }

    #[test]
    fn transaction_error_is_transient_so_drivers_retry() {
        let f = failure_from_error(&GraphusError::Transaction(
            "serialization failure".to_owned(),
        ));
        assert_eq!(f.code, CODE_TXN_TERMINATED);
        assert!(f.code.contains("TransientError"));
    }

    #[test]
    fn security_error_maps_to_forbidden_without_prefix() {
        let f = failure_from_error(&GraphusError::Security("permission denied".to_owned()));
        assert_eq!(f.code, CODE_FORBIDDEN);
        assert_eq!(f.message, "permission denied");
    }

    #[test]
    fn constraint_violation_maps_to_schema_class_and_strips_the_sentinel() {
        // A constraint violation is a Runtime error whose message carries the sentinel prefix; the
        // renderer must emit the schema class and strip BOTH the layer prefix and the sentinel.
        let msg = format!(
            "{CONSTRAINT_VIOLATION_PREFIX}Node(:Person) already exists with property `email`"
        );
        let f = failure_from_error(&GraphusError::Runtime(msg));
        assert_eq!(f.code, "Neo.ClientError.Schema.ConstraintValidationFailed");
        assert_eq!(
            f.message,
            "Node(:Person) already exists with property `email`"
        );
        // A plain runtime error (no sentinel) still maps to the generic argument class.
        let plain = failure_from_error(&GraphusError::Runtime("/ by zero".to_owned()));
        assert_eq!(plain.code, CODE_RUNTIME_ARGUMENT);
    }

    #[test]
    fn storage_and_protocol_classify_as_db_and_request() {
        assert_eq!(
            failure_from_error(&GraphusError::Storage("disk".to_owned())).code,
            CODE_DB_UNKNOWN
        );
        assert_eq!(
            failure_from_error(&GraphusError::Protocol("bad frame".to_owned())).code,
            CODE_REQUEST_INVALID
        );
    }
}
