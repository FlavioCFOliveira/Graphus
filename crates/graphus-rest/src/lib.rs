//! `graphus-rest` — the **transactional HTTP API** for Graphus: an axum/hyper `Router` plus the
//! transaction state machine, the typed-value codecs, and the RFC 9457 error model, all driven
//! fully in-process (`04-technical-design.md` §8.2; `06-bolt-and-error-shapes.md` §4).
//!
//! This crate is the REST sibling of `graphus-bolt`: it turns HTTP requests into the same
//! [`graphus_core::Value`]-shaped query execution behind a clean seam, and turns the engine's
//! results and errors back into bytes. It owns **no sockets and no TLS**: binding a listener and
//! terminating TLS is the server's job (rmp #20). Everything here is exercised over an in-process
//! `tower::ServiceExt::oneshot`, so the API is certified independently of the I/O layer — exactly as
//! `graphus-bolt` certifies its Bolt state machine over in-memory transports (`04 §8.2`, §8.3).
//!
//! # Module map
//!
//! - [`engine`] — the [`engine::RestEngine`] **query-execution seam** the engine (rmp #20, via
//!   `graphus-cypher`'s coordinator) implements, returning a pull-based [`engine::ResultStream`] of
//!   [`graphus_core::Value`] rows (`04 §8.3`, §7.7). The HTTP analogue of `graphus_bolt::executor`.
//! - [`value`] — the **one place** `Value` becomes bytes for REST: **Jolt-style typed JSON** (with
//!   **int53** 64-bit integers string-encoded) and **CBOR** (RFC 8949, native 64-bit ints)
//!   (`04 §8.2`, `D-serialization`).
//! - [`problem`] — **RFC 9457 problem+json** ([`problem::Problem`]) and the mapping of a
//!   [`graphus_core::GraphusError`] / [`graphus_auth::AuthError`] onto it (`06 §3.3`), mirroring the
//!   Bolt `FAILURE` classification.
//! - [`negotiate`] — `Accept` / `Content-Type` content negotiation across JSON / CBOR / NDJSON
//!   (`04 §8.2`).
//! - [`protocol`] — the request/response **body shapes** and the `access_mode` validator (`06 §4`).
//! - [`registry`] — the [`registry::TxRegistry`]: open transactions keyed by id, **inactivity
//!   auto-rollback** over the injected [`graphus_core::capability::Clock`] (deterministic, no
//!   wall-clock), and **`Idempotency-Key`** replay (`04 §8.2`).
//! - [`openapi`] — the static **OpenAPI 3.1** document served at `GET /openapi.json` (`04 §8.2`).
//! - [`router`](mod@router) — the axum [`Router`](axum::Router), [`router::AppState`], and the
//!   handlers, with CORS + compression layers wired (`04 §8.2`).
//!
//! # The seam the server (rmp #20) wires
//!
//! ```no_run
//! use std::sync::Arc;
//! use graphus_auth::AuthProvider;
//! use graphus_core::capability::Clock;
//! use graphus_rest::engine::RestEngine;
//! use graphus_rest::registry::TxRegistry;
//! use graphus_rest::router::{AppState, DEFAULT_TX_TTL_NANOS, router};
//!
//! // The listener owns the real `RestEngine` (graphus-cypher's coordinator), the shared
//! // authentication seam (`AuthProvider` — the server backs it with a LIVE security-catalog view,
//! // rmp #94), and the production `Clock`, builds the router, and serves it over TLS:
//! fn build<E: RestEngine + 'static>(
//!     engine: Arc<E>,
//!     auth: Arc<dyn AuthProvider>,
//!     clock: Arc<dyn Clock + Send + Sync>,
//! ) -> axum::Router {
//!     let registry = Arc::new(TxRegistry::new(DEFAULT_TX_TTL_NANOS));
//!     router(AppState::new(engine, auth, registry, clock))
//! }
//! ```
//!
//! # Pins and documented deferrals
//!
//! - **`access_mode`** values are `"READ"` / `"WRITE"`, default `"WRITE"`, case-sensitive; an invalid
//!   value is a `400` problem+json and the tx is not opened (`06 §4`).
//! - **Error codes** in the problem `code` member are the same **best-effort** `Neo.*`-shaped
//!   rendering the Bolt `FAILURE` carries (the verbatim Neo4j mapping is deferred per `06 §2.4`).
//! - **`Value::Node` / `Relationship` / `Path` / `Point`** are **deferred in `graphus_core::Value`**
//!   (`04 §7.2`). The Jolt structural sigils (`$N`/`$R`/`$P`) and the point sigil (`@`) are therefore
//!   not emitted yet; the codec gains them when the variants land, without changing the seam — see
//!   [`value`].
//! - **NDJSON streaming** frames each row as its own line from the pull-based seam; in this
//!   in-process build the body is assembled eagerly (the engine cursor is synchronous), which a
//!   future async cursor turns into true incremental flushing with no API change.
#![forbid(unsafe_code)]

pub mod engine;
pub mod negotiate;
pub mod openapi;
pub mod problem;
pub mod protocol;
pub mod registry;
pub mod restvalue;
pub mod router;
pub mod value;

// A coherent top-level re-export of the surface the server (rmp #20) and tests use most, per the
// Rust API Guidelines (a flat, discoverable crate root).
pub use engine::{AccessMode, RestEngine, ResultStream, Row, RunSummary, TxHandle};
pub use negotiate::{Decode, Wire};
pub use problem::{PROBLEM_JSON, Problem};
pub use protocol::{
    BeginResponse, RunRequest, RunResponse, Statement, StatementResult, parse_access_mode,
};
pub use registry::{CachedResponse, TxRegistry};
pub use restvalue::{
    GraphProjection, RestNode, RestPath, RestRelationship, RestValue, restvalue_to_jolt,
};
pub use router::{AppState, DEFAULT_TX_TTL_NANOS, router};
pub use value::{ValueCodecError, cbor_to_value, jolt_to_value, value_to_cbor, value_to_jolt};
