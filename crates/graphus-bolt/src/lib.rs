//! `graphus-bolt` — the **transport-agnostic Bolt 5.4 protocol core** for Graphus: the bytes ↔
//! Bolt-messages ↔ query-execution machinery, with the socket I/O left to the server
//! (`04-technical-design.md` §8.1; `06-bolt-and-error-shapes.md` §1 pins **Bolt 5.4**).
//!
//! This crate turns a byte stream into a driven Bolt session and back, fully in-process. It owns
//! **no sockets, no TLS, and no async runtime**: the UDS / TCP-TLS accept-read-write loop is the
//! server's job (rmp #20). Everything here is exercised over in-memory byte buffers, so the protocol
//! is certified independently of the I/O layer (`04 §8.1`: "the same Bolt state machine and codec
//! run over a `UnixStream` and a `TcpStream`; only the transport and auth differ").
//!
//! # Module map
//!
//! - [`packstream`] — the **PackStream v1** codec: [`graphus_core::Value`] ↔ bytes, big-endian,
//!   smallest-marker-that-fits, plus the [`packstream::Structure`] primitive and the structure tag
//!   bytes for the graph/temporal types (`04 §8.1`).
//! - [`framing`] — **chunked message framing**: a message is one-or-more `len`-prefixed chunks
//!   terminated by `00 00`; a bare `00 00` is a NOOP keep-alive (`04 §8.1`).
//! - [`handshake`] — the **legacy 4-slot handshake** *and* the **Manifest-v1 handshake** (rmp #95):
//!   magic preamble + four range-encoded version proposals, negotiating down to any 5.0–5.4 minor
//!   (`06 §1`); a manifest-aware client (`00 00 01 FF`) gets the modern two-round exchange instead.
//! - [`message`] — the Bolt 5.4 **request/response set**, each a PackStream structure with the
//!   correct opcode and field layout (`04 §8.1`, `06 §3`).
//! - [`error`] — [`error::BoltError`] (protocol/codec faults) and the
//!   [`error::failure_from_error`] mapping of an engine error onto a Bolt `FAILURE` (`06 §2`–§3).
//! - [`transport`] — the [`transport::Transport`] byte-pipe seam (impl'd over a socket by the
//!   server, over memory in tests).
//! - [`executor`] — the [`executor::BoltExecutor`] query-execution seam the engine implements
//!   (rmp #20, via `graphus-cypher`'s coordinator), returning a pull-based
//!   [`executor::RecordStream`] (`04 §8.3`, §7.7).
//! - [`server`] — the [`server::BoltSession`] **state machine** that ties the above together and
//!   enforces the Bolt server-state transitions and the fail-then-ignore-until-RESET rule
//!   (`04 §8.1`).
//!
//! # The two seams the server (rmp #20) wires
//!
//! ```no_run
//! use graphus_auth::Authenticator;
//! use graphus_bolt::executor::BoltExecutor;
//! use graphus_bolt::server::BoltSession;
//! use graphus_bolt::transport::Transport;
//!
//! // The listener owns a real `Transport` (a UDS/TCP-TLS byte pipe) and a real `BoltExecutor`
//! // (graphus-cypher's coordinator), plus the shared `Authenticator`, and drives one session:
//! fn serve_connection(transport: impl Transport, executor: impl BoltExecutor, auth: &Authenticator) {
//!     let mut session = BoltSession::new(transport, executor, auth);
//!     let _ = session.run(); // handshake → message loop until GOODBYE/EOF
//! }
//! ```
//!
//! # Pins and documented deferrals
//!
//! - **Bolt 5.4** is the negotiated maximum (`06 §1`). Both the **legacy 4-slot** handshake and the
//!   **Manifest-v1** handshake (`06 §1.2`; rmp #95) are implemented, and both negotiate the same
//!   5.0–5.4 window — so a modern routing driver and an older driver connect identically.
//! - **`FAILURE` status codes** are a documented **best-effort** `Neo.*`-shaped rendering of the
//!   engine's classified error (the verbatim Neo4j two-letter mapping is deferred per `06 §2.4`);
//!   see [`error::failure_from_error`].
//! - **`Value::Node` / `Relationship` / `Path` / `Point`** are **deferred in `graphus_core::Value`**
//!   (`04 §7.2`). The PackStream structure *encoders* exist ([`packstream::tag`]); a wire graph
//!   structure cannot yet be *decoded* into a `Value` and is reported rather than guessed. See
//!   [`executor`] for how the executor exposes entity ids/properties through today's `Value` model.
#![forbid(unsafe_code)]

pub mod error;
pub mod executor;
pub mod framing;
pub mod handshake;
pub mod message;
pub mod packstream;
pub mod server;
pub mod transport;

// A coherent top-level re-export of the surface the server (rmp #20) and tests use most, per the
// Rust API Guidelines (a flat, discoverable crate root).
pub use error::{BoltError, BoltResult, Failure, failure_from_error};
pub use executor::{AccessMode, BoltExecutor, QuerySummary, Record, RecordStream, TxControl};
pub use framing::{Dechunker, Frame, chunk_message};
pub use handshake::{
    MANIFEST_V1_REQUEST, ManifestChoice, Proposal, Version, detect_manifest_request,
    encode_manifest_choice, encode_server_manifest, graphus_manifest, negotiate,
    parse_manifest_choice,
};
pub use message::{Request, Response};
pub use packstream::{
    BoltNode, BoltPath, BoltRelationship, BoltValue, Packer, Structure, Unpacker, pack_bolt_value,
    pack_node, pack_path, pack_point_2d, pack_point_3d, pack_relationship, pack_value,
    unpack_bolt_value, unpack_value,
};
pub use server::{BoltSession, SessionConfig, State};
pub use transport::{MemoryTransport, Transport};
