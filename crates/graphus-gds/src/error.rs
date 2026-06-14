//! The crate-local error type, [`GdsError`].
//!
//! `graphus-gds` deliberately keeps **zero runtime dependencies** so it can be unit-tested in
//! isolation from the rest of the workspace. For that reason it does **not** reach for `thiserror`
//! and does **not** depend on `graphus-core`'s `GraphusError`. Instead it hand-writes
//! [`Display`](core::fmt::Display) and [`std::error::Error`], matching the style of
//! `graphus-core`'s hand-written `GraphusError`.
//!
//! When the engine is later wired to the real store, the integration layer is expected to map
//! [`GdsError`] into `graphus_core::GraphusError` (typically the `Runtime(String)` variant) at the
//! crate boundary.

use core::fmt;

/// Errors produced by the GDS projection and algorithms.
///
/// Every variant is reachable only from *misuse* or *precondition violation* — never from valid
/// graph data. The algorithms in this crate are panic-free on every degenerate graph shape (empty,
/// isolated nodes, self-loops, parallel edges, disconnected components); they signal genuine
/// precondition failures (such as a negative weight handed to Dijkstra) through this type instead.
#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub enum GdsError {
    /// A named graph was requested from the catalog but is not present.
    GraphNotFound(String),

    /// An attempt was made to project a graph under a name that is already in use.
    GraphAlreadyExists(String),

    /// An external node id referenced by an edge was never declared as a node.
    UnknownNode(u64),

    /// An algorithm precondition was violated (for example, a negative edge weight passed to an
    /// algorithm that requires non-negative weights, or an out-of-range configuration value).
    InvalidArgument(String),

    /// A negative-weight cycle was detected by an algorithm whose result is only defined for graphs
    /// without one (Bellman-Ford).
    NegativeCycle,

    /// The operation was cancelled cooperatively via the caller-supplied cancellation check.
    Cancelled,

    /// An internal invariant would have overflowed a fixed-width integer. Surfaced rather than
    /// silently wrapping, so callers can treat pathologically large graphs as a clean error.
    Overflow(&'static str),
}

impl fmt::Display for GdsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            GdsError::GraphNotFound(name) => write!(f, "graph not found: {name}"),
            GdsError::GraphAlreadyExists(name) => write!(f, "graph already exists: {name}"),
            GdsError::UnknownNode(id) => write!(f, "edge references unknown node id: {id}"),
            GdsError::InvalidArgument(msg) => write!(f, "invalid argument: {msg}"),
            GdsError::NegativeCycle => write!(f, "graph contains a negative-weight cycle"),
            GdsError::Cancelled => write!(f, "operation cancelled"),
            GdsError::Overflow(what) => write!(f, "arithmetic overflow: {what}"),
        }
    }
}

impl std::error::Error for GdsError {}

/// The crate's standard `Result` alias.
pub type Result<T> = core::result::Result<T, GdsError>;
