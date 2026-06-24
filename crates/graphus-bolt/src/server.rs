//! The Bolt **server state machine** — the protocol's behavioural core (`04-technical-design.md`
//! §8.1; `06-bolt-and-error-shapes.md` §3).
//!
//! [`BoltSession`] drives one connection end-to-end over a [`Transport`] (the byte pipe) and a
//! [`BoltExecutor`] (the query seam), authenticating through an [`AuthProvider`] seam. It owns no
//! sockets and no runtime: the listener (rmp #20) constructs the three pieces and calls
//! [`BoltSession::run`].
//!
//! ## Authentication is live, not a snapshot (rmp #94)
//!
//! The session holds the auth seam as a `&dyn AuthProvider` (not a concrete `Authenticator`), so
//! the listener decides what backs it. `graphus-server` supplies a *live* implementation that
//! resolves each `LOGON` through its read-locked security catalog, so a user created/changed/dropped
//! at runtime authenticates (or is refused) immediately, without a reboot. `graphus-bolt` itself
//! stays transport-agnostic — it depends only on the [`AuthProvider`] trait in `graphus-auth`.
//!
//! ## States (`04 §8.1`)
//!
//! ```text
//! CONNECTED --(HELLO)--> AUTHENTICATION --(LOGON ok)--> READY
//!    READY  --(RUN)--> STREAMING --(stream drained)--> READY
//!    READY  --(BEGIN)--> TX_READY --(RUN)--> TX_STREAMING --(drained)--> TX_READY
//!  TX_READY --(COMMIT/ROLLBACK)--> READY
//!    <any>  --(error)--> FAILED --(RESET)--> READY
//!    <any>  --(GOODBYE / fatal)--> DEFUNCT
//! ```
//!
//! ## The fail-then-ignore-until-RESET rule (`04 §8.1`, `06 §3.2`)
//!
//! After any `FAILURE`, the connection enters [`State::Failed`] and **every** subsequent request is
//! answered `IGNORED` until the client sends `RESET`, which clears the failure and returns to
//! [`State::Ready`]. This is modelled as an explicit guard at the top of the dispatch.
//!
//! ## Streaming honours the fetch size (`04 §7.7`, `06 §3.1`)
//!
//! A `RUN` produces a [`RecordStream`]; the server replies `SUCCESS`
//! with the `fields` metadata and then waits for `PULL`/`DISCARD`. `PULL {n}` emits up to `n`
//! `RECORD`s (`n == -1` = all) followed by a trailing `SUCCESS`; if `n` was bounded and rows remain,
//! the trailing `SUCCESS` carries `has_more = true` and the connection stays in `STREAMING`
//! (`06 §3.1`). `DISCARD` drops the remaining rows and emits only the trailing `SUCCESS`.

use graphus_auth::AuthProvider;
use graphus_core::Value;

use crate::error::{BoltError, BoltResult, CODE_UNAUTHORIZED, Failure, failure_from_error};
use crate::executor::{AccessMode, BoltExecutor, Record, RecordStream, TxControl};
use crate::framing::{Dechunker, Frame, chunk_message_into};
use crate::handshake::{
    MAGIC, Version, detect_manifest_request, graphus_manifest, negotiate, parse_client_handshake,
    parse_manifest_choice, server_reply,
};
use crate::message::{ALL, Request, Response};
use crate::packstream::Packer;
use crate::transport::Transport;

/// The server-side connection state (`04 §8.1`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    /// Handshake done; awaiting `HELLO`.
    Connected,
    /// `HELLO` accepted; awaiting `LOGON`.
    Authentication,
    /// Authenticated and idle; awaiting `RUN`/`BEGIN`/`LOGOFF`/`GOODBYE`.
    Ready,
    /// A `RUN` result is open (auto-commit); awaiting `PULL`/`DISCARD`.
    Streaming,
    /// Inside an explicit transaction; awaiting `RUN`/`COMMIT`/`ROLLBACK`.
    TxReady,
    /// A `RUN` result is open inside an explicit transaction; awaiting `PULL`/`DISCARD`.
    TxStreaming,
    /// A `FAILURE` occurred; ignore requests until `RESET` (`04 §8.1`).
    Failed,
    /// The connection is finished (after `GOODBYE` or a fatal error); no more messages.
    Defunct,
}

impl State {
    /// Whether the connection is mid-result (auto-commit or in-tx streaming).
    fn is_streaming(self) -> bool {
        matches!(self, State::Streaming | State::TxStreaming)
    }

    /// The READY-class state to return to after a result is consumed (back into a tx if we were in
    /// one).
    fn ready_after_stream(self) -> State {
        match self {
            State::TxStreaming => State::TxReady,
            _ => State::Ready,
        }
    }
}

/// The default `server` agent string reported in `HELLO` `SUCCESS` (`04 §8.1`). The listener can
/// override it with a build-stamped one via [`SessionConfig`].
pub const DEFAULT_SERVER_AGENT: &str = concat!("Graphus/", env!("CARGO_PKG_VERSION"));

/// Per-connection metadata the listener supplies to a [`BoltSession`] (rmp #95).
///
/// The protocol core is transport-agnostic, but two pieces of `HELLO`/`ROUTE` metadata are inherently
/// the *listener's* to know: the **`connection_id`** the listener mints per accepted connection (so a
/// driver and the server logs can correlate one connection — Graphus hardcoded `bolt-1` before this),
/// and the **advertised Bolt address** a routing (`neo4j://`) driver should reconnect to (the
/// server's externally-reachable `host:port`, which the protocol layer cannot discover on its own).
/// Both have sensible defaults so existing call sites keep working.
#[derive(Debug, Clone)]
pub struct SessionConfig {
    /// The unique id reported in `HELLO` `SUCCESS` as `connection_id`. Minted per connection by the
    /// listener; defaults to `"bolt-1"` for call sites that do not mint one.
    pub connection_id: String,
    /// The `server` agent string reported in `HELLO` `SUCCESS`. Defaults to [`DEFAULT_SERVER_AGENT`].
    pub server_agent: String,
    /// The Bolt address (`host:port`) a routing driver should connect to, returned in the `ROUTE`
    /// routing table for all three roles. `None` advertises the literal the client used (a driver
    /// connected to a single node keeps using that address), which keeps a single-instance routing
    /// driver working without any configuration.
    pub advertised_bolt_address: Option<String>,
    /// The routing table's time-to-live in seconds (`ROUTE` `rt.ttl`). Drivers re-fetch the table
    /// after this; a single instance's table never really changes, so a comfortable default avoids
    /// needless re-routing round-trips.
    pub routing_ttl_secs: i64,
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            connection_id: "bolt-1".to_owned(),
            server_agent: DEFAULT_SERVER_AGENT.to_owned(),
            advertised_bolt_address: None,
            routing_ttl_secs: DEFAULT_ROUTING_TTL_SECS,
        }
    }
}

/// The default `ROUTE` routing-table TTL in seconds (300 = 5 minutes, Neo4j's driver default).
pub const DEFAULT_ROUTING_TTL_SECS: i64 = 300;

/// A Bolt connection session: the state machine plus its in-flight result stream.
///
/// Generic over the [`Transport`] (byte pipe) and the [`BoltExecutor`] (query seam) so it is
/// equally a UDS, a TCP-TLS, or an in-memory test connection (`04 §8.1`/§8.4). One session handles
/// one connection for its whole lifetime.
pub struct BoltSession<'a, T: Transport, E: BoltExecutor> {
    transport: T,
    executor: E,
    auth: &'a dyn AuthProvider,
    /// Per-connection metadata (connection id, server agent, advertised routing address — rmp #95).
    config: SessionConfig,
    state: State,
    /// The negotiated protocol version (set after the handshake).
    version: Option<Version>,
    /// The authenticated principal (set after `LOGON`).
    principal: Option<String>,
    /// The in-flight result, while `STREAMING` / `TX_STREAMING`.
    open_stream: Option<OpenResult<E::Stream>>,
    /// Reassembles request messages from the inbound byte stream.
    dechunker: Dechunker,
    /// A scratch read buffer.
    read_buf: Vec<u8>,
    /// PERF (C4/C5): retained encode buffer (PackStream payload), reused across responses.
    packer: Packer,
    /// PERF (C4/C5): retained framing buffer (chunked wire bytes), reused across responses.
    framed: Vec<u8>,
}

/// An open `RUN` result plus a **one-record lookahead** buffer.
///
/// The lookahead makes the `has_more` flag of a bounded `PULL n` *accurate* (`06 §3.1`): after
/// emitting `n` records the server peeks one more — if a record is there, `has_more = true` is true
/// because a record genuinely remains (it is buffered for the next `PULL`); if the peek is `None`,
/// the stream drained exactly on the batch boundary and the trailing summary `SUCCESS` is emitted.
/// Without the lookahead the server could only guess `has_more` from "did we hit the limit", which
/// the Bolt spec's wording ("more records *to stream*") does not mean and which costs a spurious
/// extra round-trip.
struct OpenResult<S> {
    stream: S,
    /// A record peeked-but-not-yet-emitted (the lookahead), if any.
    peeked: Option<Record>,
}

impl<S: RecordStream> OpenResult<S> {
    fn new(stream: S) -> Self {
        Self {
            stream,
            peeked: None,
        }
    }

    /// Returns the next record (the buffered lookahead first, then the stream), or `Ok(None)` when
    /// exhausted.
    fn next_record(&mut self) -> Result<Option<Record>, graphus_core::GraphusError> {
        if let Some(r) = self.peeked.take() {
            return Ok(Some(r));
        }
        self.stream.next_record()
    }

    /// Whether at least one more record remains, consuming nothing observable (it fills the
    /// lookahead buffer). Used to compute an accurate `has_more`.
    fn has_more(&mut self) -> Result<bool, graphus_core::GraphusError> {
        if self.peeked.is_some() {
            return Ok(true);
        }
        self.peeked = self.stream.next_record()?;
        Ok(self.peeked.is_some())
    }
}

/// What the dispatcher decided to do after handling one request.
enum Flow {
    /// Keep serving requests.
    Continue,
    /// The connection is finished (GOODBYE or a fatal transport/handshake error); stop the loop.
    Stop,
}

impl<'a, T: Transport, E: BoltExecutor> BoltSession<'a, T, E> {
    /// Builds a session over `transport`, running queries through `executor`, authenticating with
    /// `auth` (the [`AuthProvider`] seam), with the default [`SessionConfig`]. The session starts in
    /// [`State::Connected`] (pre-handshake).
    pub fn new(transport: T, executor: E, auth: &'a dyn AuthProvider) -> Self {
        Self::with_config(transport, executor, auth, SessionConfig::default())
    }

    /// Builds a session with explicit per-connection [`SessionConfig`] (the listener mints the
    /// `connection_id` and supplies the advertised routing address — rmp #95).
    pub fn with_config(
        transport: T,
        executor: E,
        auth: &'a dyn AuthProvider,
        config: SessionConfig,
    ) -> Self {
        Self {
            transport,
            executor,
            auth,
            config,
            state: State::Connected,
            version: None,
            principal: None,
            open_stream: None,
            dechunker: Dechunker::new(),
            read_buf: vec![0u8; 8 * 1024],
            packer: Packer::new(),
            framed: Vec::new(),
        }
    }

    /// The current connection state (for tests/observability).
    #[must_use]
    pub fn state(&self) -> State {
        self.state
    }

    /// The negotiated protocol version, if the handshake has completed.
    #[must_use]
    pub fn version(&self) -> Option<Version> {
        self.version
    }

    /// The authenticated principal, if `LOGON` has succeeded.
    #[must_use]
    pub fn principal(&self) -> Option<&str> {
        self.principal.as_deref()
    }

    /// Test-only borrow of the executor (used by the state-machine tests to assert side effects
    /// like a RESET-triggered rollback via the mock's call log).
    #[cfg(test)]
    pub(crate) fn executor(&self) -> &E {
        &self.executor
    }

    /// Runs the whole connection: the handshake, then the message loop until `GOODBYE`, EOF, or a
    /// fatal error.
    ///
    /// # Errors
    /// [`BoltError`] for a fatal transport or handshake failure (a Cypher/auth failure is delivered
    /// as a `FAILURE` message and is **not** an error here — it is part of a healthy session).
    pub fn run(&mut self) -> BoltResult<()> {
        self.do_handshake()?;
        loop {
            let Some(payload) = self.read_message()? else {
                // EOF before GOODBYE: the peer dropped the connection. `read_message` already
                // flushed any pending response before it observed EOF, so nothing is left buffered.
                self.state = State::Defunct;
                return Ok(());
            };
            let request = match Request::decode(&payload) {
                Ok(r) => r,
                Err(e) => {
                    // A malformed message is a protocol fault: FAILURE then fail-state.
                    self.send_failure(Failure::new(
                        "Neo.ClientError.Request.Invalid",
                        e.to_string(),
                    ))?;
                    self.state = State::Failed;
                    continue;
                }
            };
            match self.dispatch(request)? {
                Flow::Continue => {}
                Flow::Stop => {
                    // Terminal return (GOODBYE / fatal): no further read will flush. GOODBYE itself
                    // writes no response, but flush defensively so any buffered bytes a Stop path
                    // might have written reach the client before the listener closes the socket
                    // (rmp #317). Harmless (no-op) when the buffer is already empty.
                    self.transport.flush()?;
                    return Ok(());
                }
            }
        }
    }

    // ---- Handshake -------------------------------------------------------------------------------

    /// Reads the 20-byte client handshake and negotiates a version, over either the **legacy** 4-slot
    /// reply or the **Manifest-v1** exchange (rmp #95).
    ///
    /// The first transmission is always magic + 4 proposals (20 bytes). If one slot is the
    /// Manifest-v1 marker (`00 00 01 FF`), the server replies with its manifest and reads the
    /// client's chosen version + capabilities (a second round); otherwise it replies with the single
    /// negotiated version exactly as before. Both forms converge on the same version window.
    ///
    /// # Errors
    /// [`BoltError::Handshake`] if the magic/length is wrong, no version is acceptable, or (manifest)
    /// the client picks a version Graphus does not support (the listener closes the connection on a
    /// handshake error).
    fn do_handshake(&mut self) -> BoltResult<()> {
        const HANDSHAKE_LEN: usize = MAGIC.len() + 4 * 4;
        let bytes = self.read_exact_bytes(HANDSHAKE_LEN)?;
        let proposals = parse_client_handshake(&bytes)?;

        if detect_manifest_request(&proposals) {
            return self.do_manifest_handshake();
        }

        let chosen = negotiate(&proposals);
        self.transport.write_all(&server_reply(chosen))?;
        match chosen {
            Some(v) => {
                self.version = Some(v);
                self.state = State::Connected;
                Ok(())
            }
            None => {
                // Replied with 00 00 00 00; the connection is rejected. This is a terminal
                // write-WITHOUT-a-following-read: `run` returns this `Err` and the listener closes
                // the socket, so the rejection bytes must be flushed explicitly or a buffering
                // transport would drop them on close, leaving the client waiting (rmp #317).
                self.transport.flush()?;
                self.state = State::Defunct;
                Err(BoltError::Handshake(
                    "no mutually-supported Bolt version".to_owned(),
                ))
            }
        }
    }

    /// Runs the Manifest-v1 second round: send Graphus's manifest, read the client's chosen version +
    /// capabilities, and accept it if it is in Graphus's supported window (`06 §1.2`; rmp #95).
    ///
    /// # Errors
    /// [`BoltError::Handshake`] if the client's choice is unreadable or names an unsupported version.
    fn do_manifest_handshake(&mut self) -> BoltResult<()> {
        self.transport.write_all(&graphus_manifest())?;
        let choice_bytes = self.read_manifest_choice()?;
        let choice = parse_manifest_choice(&choice_bytes)?;
        if choice.version.is_supported() {
            self.version = Some(choice.version);
            self.state = State::Connected;
            Ok(())
        } else {
            self.state = State::Defunct;
            Err(BoltError::Handshake(format!(
                "client chose unsupported Bolt version {}.{} in the manifest handshake",
                choice.version.major, choice.version.minor
            )))
        }
    }

    /// Reads the client's post-manifest response off the transport: 4 version bytes then a
    /// continuation-terminated capabilities varint. The varint is read byte-by-byte (its length is
    /// not known in advance), stopping at the first byte without the high continuation bit.
    ///
    /// # Errors
    /// [`BoltError::Transport`] on EOF mid-response; [`BoltError::Handshake`] if the varint runs past
    /// a sane bound (a malformed, never-terminating continuation).
    fn read_manifest_choice(&mut self) -> BoltResult<Vec<u8>> {
        // The 4-byte chosen version.
        let mut out = self.read_exact_bytes(4)?;
        // The capabilities varint: at most 10 bytes encode a u64; refuse a longer run as malformed.
        const MAX_VARINT_BYTES: usize = 10;
        for _ in 0..MAX_VARINT_BYTES {
            let byte = self.read_exact_bytes(1)?[0];
            out.push(byte);
            if byte & 0x80 == 0 {
                return Ok(out);
            }
        }
        self.state = State::Defunct;
        Err(BoltError::Handshake(
            "manifest capabilities varint never terminates".to_owned(),
        ))
    }

    // ---- Dispatch --------------------------------------------------------------------------------

    /// Handles one decoded request per the current state, writing the response(s).
    fn dispatch(&mut self, request: Request) -> BoltResult<Flow> {
        // GOODBYE is honoured in every state: the client is leaving.
        if matches!(request, Request::Goodbye) {
            self.state = State::Defunct;
            return Ok(Flow::Stop);
        }

        // Fail-then-ignore-until-RESET: in FAILED, only RESET is processed; all else is IGNORED.
        if self.state == State::Failed {
            if matches!(request, Request::Reset) {
                self.handle_reset()?;
            } else {
                self.send(&Response::Ignored)?;
            }
            return Ok(Flow::Continue);
        }

        match self.state {
            State::Connected => self.dispatch_connected(request),
            State::Authentication => self.dispatch_authentication(request),
            State::Ready | State::TxReady => self.dispatch_ready(request),
            State::Streaming | State::TxStreaming => self.dispatch_streaming(request),
            // FAILED handled above; DEFUNCT never dispatches (loop stops first).
            State::Failed | State::Defunct => {
                self.send(&Response::Ignored)?;
                Ok(Flow::Continue)
            }
        }
    }

    /// `CONNECTED`: only `HELLO` is valid.
    fn dispatch_connected(&mut self, request: Request) -> BoltResult<Flow> {
        match request {
            Request::Hello { extra } => {
                // `user_agent` is a REQUIRED field of the HELLO extra map across all Bolt 5.x
                // versions (`04 §8.1`); a HELLO that omits it (or carries a non-string / empty
                // value) is malformed and is rejected with FAILURE rather than silently accepted —
                // this also closes a trivial DoS where a client drives the handshake with truncated
                // metadata. The connection enters FAILED and the listener closes it.
                let user_agent_ok = map_str(&extra, "user_agent").is_some_and(|s| !s.is_empty());
                if !user_agent_ok {
                    self.send_failure(Failure::new(
                        "Neo.ClientError.Request.Invalid",
                        "HELLO is missing the required `user_agent` field",
                    ))?;
                    self.state = State::Failed;
                    return Ok(Flow::Continue);
                }
                // HELLO no longer carries credentials in 5.1+ (LOGON does). Acknowledge with server
                // metadata and move to AUTHENTICATION. The `server` agent and the per-connection
                // `connection_id` come from the listener's `SessionConfig` (rmp #95); `hints` is the
                // optional driver-tuning map (empty here — Graphus advertises no hints yet, but the
                // key's presence is what some drivers probe).
                let meta = vec![
                    (
                        "server".to_owned(),
                        Value::String(self.config.server_agent.clone()),
                    ),
                    (
                        "connection_id".to_owned(),
                        Value::String(self.config.connection_id.clone()),
                    ),
                    ("hints".to_owned(), Value::Map(vec![])),
                ];
                self.send(&Response::Success { metadata: meta })?;
                self.state = State::Authentication;
                Ok(Flow::Continue)
            }
            other => self.unexpected(&other),
        }
    }

    /// `AUTHENTICATION`: only `LOGON` is valid.
    fn dispatch_authentication(&mut self, request: Request) -> BoltResult<Flow> {
        match request {
            Request::Logon { auth } => {
                // Capture the attempted principal BEFORE authenticating, so a failure can be
                // audited with the attempted username (the username is not a secret; the
                // credentials in `auth` ARE — they are never passed to the audit hook — rmp #70).
                let attempted = map_str(&auth, "principal").map(str::to_owned);
                match self.authenticate(&auth) {
                    Ok(user) => {
                        // Announce the identity to the executor so it can authorize
                        // identity-gated work (e.g. administrative statements — rmp #84) and record
                        // an `auth_success` audit event (rmp #70).
                        self.executor.on_auth_success(&user);
                        self.executor.set_principal(Some(&user));
                        self.principal = Some(user);
                        self.send(&Response::Success { metadata: vec![] })?;
                        self.state = State::Ready;
                    }
                    Err(failure) => {
                        // Record the failed attempt for audit (rmp #70) before the FAILURE goes out.
                        self.executor
                            .on_auth_failure(attempted.as_deref(), "authentication failed");
                        // A failed auth is delivered as FAILURE; the connection enters FAILED and
                        // the listener closes it (`04 §8.4`: failed auth → FAILURE + close). We stay
                        // in the fail-state so a stray follow-up is IGNORED until the socket drops.
                        self.send_failure(failure)?;
                        self.state = State::Failed;
                    }
                }
                Ok(Flow::Continue)
            }
            other => self.unexpected(&other),
        }
    }

    /// `READY` / `TX_READY`: `RUN`, `BEGIN`/`COMMIT`/`ROLLBACK`, `LOGOFF`, `RESET`.
    fn dispatch_ready(&mut self, request: Request) -> BoltResult<Flow> {
        match (self.state, request) {
            // RUN: auto-commit (READY) or in-transaction (TX_READY). Both carry the target
            // database from the extra's `db` field (Bolt 5.x; absent/empty = default).
            (
                State::Ready,
                Request::Run {
                    query,
                    parameters,
                    extra,
                },
            ) => {
                let mode = access_mode_from_extra(&extra);
                let db = db_from_extra(&extra);
                self.handle_run(
                    &query,
                    parameters,
                    TxControl::AutoCommit { mode, db },
                    State::Streaming,
                )
            }
            (
                State::TxReady,
                Request::Run {
                    query,
                    parameters,
                    extra,
                },
            ) => {
                // The transaction is pinned to the database named at BEGIN; the executor rejects a
                // different non-empty `db` here (cannot switch databases mid-transaction).
                let db = db_from_extra(&extra);
                self.handle_run(
                    &query,
                    parameters,
                    TxControl::InExplicit { db },
                    State::TxStreaming,
                )
            }
            (State::Ready, Request::Begin { extra }) => {
                let mode = access_mode_from_extra(&extra);
                let db = db_from_extra(&extra);
                match self.executor.begin(mode, db.as_deref()) {
                    Ok(()) => {
                        self.send(&Response::Success { metadata: vec![] })?;
                        self.state = State::TxReady;
                    }
                    Err(e) => self.fail_with(&e)?,
                }
                Ok(Flow::Continue)
            }
            (State::TxReady, Request::Commit) => {
                match self.executor.commit() {
                    Ok(summary) => {
                        self.send(&Response::Success {
                            metadata: summary_metadata(&summary, false),
                        })?;
                        self.state = State::Ready;
                    }
                    Err(e) => self.fail_with(&e)?,
                }
                Ok(Flow::Continue)
            }
            (State::TxReady, Request::Rollback) => {
                match self.executor.rollback() {
                    Ok(()) => {
                        self.send(&Response::Success { metadata: vec![] })?;
                        self.state = State::Ready;
                    }
                    Err(e) => self.fail_with(&e)?,
                }
                Ok(Flow::Continue)
            }
            (State::Ready, Request::Route { extra, .. }) => {
                // A routing (`neo4j://`) driver asks for the cluster routing table. Graphus is a
                // single instance, so every role resolves to this one server (rmp #95). ROUTE is a
                // READY-state request: it does not open a result, so the state is unchanged.
                let db = db_from_extra(&extra);
                self.handle_route(db.as_deref())?;
                Ok(Flow::Continue)
            }
            (State::Ready, Request::Telemetry { .. }) => {
                // TELEMETRY (Bolt 5.4+) is advisory: it reports which driver API the client used. The
                // spec state machine accepts it ONLY in READY — `READY + TELEMETRY -> SUCCESS{} ->
                // READY` (no state change). It is rejected as a wrong-state request in every other
                // state (it falls through to `unexpected` below), per the Bolt server-state spec. The
                // `telemetry.enabled` HELLO hint is opt-out only and never makes TELEMETRY legal
                // outside READY; in READY the server must SUCCESS it even if the hint was sent.
                // (Supersedes the earlier rmp #95 "accept in any state" leniency in favour of the
                // inviolable 100%-Bolt-compliance mandate.)
                self.send(&Response::Success { metadata: vec![] })?;
                Ok(Flow::Continue)
            }
            (_, Request::Logoff) => {
                // Drop the identity; back to AUTHENTICATION (5.1+ re-auth without a new connection).
                self.executor.set_principal(None);
                self.principal = None;
                self.send(&Response::Success { metadata: vec![] })?;
                self.state = State::Authentication;
                Ok(Flow::Continue)
            }
            (_, Request::Reset) => {
                self.handle_reset()?;
                Ok(Flow::Continue)
            }
            (_, other) => self.unexpected(&other),
        }
    }

    /// `STREAMING` / `TX_STREAMING`: `PULL`, `DISCARD`, `RESET`.
    fn dispatch_streaming(&mut self, request: Request) -> BoltResult<Flow> {
        match request {
            Request::Pull { n, qid: _ } => self.handle_pull(n, true),
            Request::Discard { n, qid: _ } => self.handle_pull(n, false),
            Request::Reset => {
                self.handle_reset()?;
                Ok(Flow::Continue)
            }
            other => self.unexpected(&other),
        }
    }

    // ---- RUN / PULL streaming --------------------------------------------------------------------

    /// Runs a query and, on success, replies `SUCCESS{fields}` and enters `streaming_state`.
    fn handle_run(
        &mut self,
        query: &str,
        parameters: Vec<(String, Value)>,
        tx: TxControl,
        streaming_state: State,
    ) -> BoltResult<Flow> {
        match self.executor.run(query, parameters, tx) {
            Ok(stream) => {
                let fields: Vec<Value> = stream
                    .fields()
                    .iter()
                    .map(|f| Value::String(f.clone()))
                    .collect();
                self.send(&Response::Success {
                    metadata: vec![("fields".to_owned(), Value::List(fields))],
                })?;
                self.open_stream = Some(OpenResult::new(stream));
                self.state = streaming_state;
                Ok(Flow::Continue)
            }
            Err(e) => {
                // A compile-time error arrives here, before any RECORD (`06 §3.2`).
                self.fail_with(&e)?;
                Ok(Flow::Continue)
            }
        }
    }

    /// Emits up to `n` records (`n == -1` = all) when `emit` is true (PULL) or silently drops them
    /// when false (DISCARD), then the trailing `SUCCESS`. Honours the fetch size (`04 §7.7`) and
    /// reports an **accurate** `has_more` via the result's one-record lookahead (`06 §3.1`).
    fn handle_pull(&mut self, n: i64, emit: bool) -> BoltResult<Flow> {
        // Validate the `n` domain (`04 §7.7`/`06 §3.1`): the only legal values are `-1` (fetch/throw
        // away all remaining) or a strictly positive integer. The spec is silent on `n == 0` and
        // `n < -1`; the Neo4j reference server rejects them with FAILURE
        // (`Neo.ClientError.Request.Invalid`) → FAILED, so we mirror that for driver-ecosystem
        // compatibility rather than silently treating an out-of-range `n` as a no-op or "all".
        if n != ALL && n < 1 {
            self.fail_protocol("PULL/DISCARD n must be -1 (all) or a positive integer")?;
            return Ok(Flow::Continue);
        }
        let Some(mut result) = self.open_stream.take() else {
            // Should not happen (only reachable in a streaming state), but be defensive.
            self.fail_protocol("PULL/DISCARD with no open result")?;
            return Ok(Flow::Continue);
        };

        let unlimited = n == ALL;
        let mut produced: i64 = 0;
        let drained = loop {
            if !unlimited && produced >= n {
                break false; // hit the fetch-size limit; whether rows remain is checked below
            }
            match result.next_record() {
                Ok(Some(record)) => {
                    if emit {
                        self.send(&Response::Record { values: record })?;
                    }
                    produced += 1;
                }
                Ok(None) => break true, // stream genuinely drained
                Err(e) => {
                    // A runtime error mid-stream (`06 §3.2`): FAILURE, drop the stream, fail-state.
                    self.fail_with(&e)?;
                    return Ok(Flow::Continue);
                }
            }
        };

        // If we stopped on the fetch limit, peek one record to learn whether more *actually* remain
        // (the lookahead is buffered for the next PULL, so nothing is lost).
        let has_more = if drained {
            false
        } else {
            match result.has_more() {
                Ok(more) => more,
                Err(e) => {
                    self.fail_with(&e)?;
                    return Ok(Flow::Continue);
                }
            }
        };

        if has_more {
            // Bounded PULL with rows genuinely remaining: has_more = true, keep streaming.
            self.send(&Response::Success {
                metadata: vec![("has_more".to_owned(), Value::Boolean(true))],
            })?;
            self.open_stream = Some(result);
            debug_assert!(self.state.is_streaming());
        } else {
            // Exhausted (either the stream drained, or the limit landed exactly on the last record):
            // trailing SUCCESS with the summary; back to (TX_)READY.
            let summary = result.stream.summary();
            self.send(&Response::Success {
                metadata: summary_metadata(&summary, false),
            })?;
            self.state = self.state.ready_after_stream();
        }
        Ok(Flow::Continue)
    }

    // ---- ROUTE -----------------------------------------------------------------------------------

    /// Answers `ROUTE` with a **single-instance** routing table (rmp #95): every role (READ / WRITE /
    /// ROUTE) points at this server's advertised Bolt address, with a TTL. A `neo4j://` (routing)
    /// driver resolves the one node from it and proceeds.
    ///
    /// `db` is the database the table is for (from the `ROUTE` extra's `db`); it is echoed into the
    /// table as `db` (or null for the home database). The advertised address comes from
    /// [`SessionConfig::advertised_bolt_address`]; when unset it falls back to the routing context's
    /// `address` hint (the literal a single-node driver already uses), then to `localhost:7687` so a
    /// table is always well-formed.
    fn handle_route(&mut self, db: Option<&str>) -> BoltResult<()> {
        let address = self.advertised_address();
        let server_entry = |role: &str| {
            Value::Map(vec![
                (
                    "addresses".to_owned(),
                    Value::List(vec![Value::String(address.clone())]),
                ),
                ("role".to_owned(), Value::String(role.to_owned())),
            ])
        };
        // All three roles resolve to this single instance (single-instance topology, `04 §8.4`).
        let servers = Value::List(vec![
            server_entry("READ"),
            server_entry("WRITE"),
            server_entry("ROUTE"),
        ]);
        let db_value = db.map_or(Value::Null, |d| Value::String(d.to_owned()));
        let rt = Value::Map(vec![
            (
                "ttl".to_owned(),
                Value::Integer(self.config.routing_ttl_secs),
            ),
            ("db".to_owned(), db_value),
            ("servers".to_owned(), servers),
        ]);
        self.send(&Response::Success {
            metadata: vec![("rt".to_owned(), rt)],
        })
    }

    /// The Bolt address advertised in the `ROUTE` routing table: the configured
    /// [`SessionConfig::advertised_bolt_address`], else a documented `localhost:7687` fallback
    /// (Bolt's default port) so the table is always usable on a single node.
    fn advertised_address(&self) -> String {
        self.config
            .advertised_bolt_address
            .clone()
            .unwrap_or_else(|| "localhost:7687".to_owned())
    }

    // ---- RESET / failure -------------------------------------------------------------------------

    /// Handles `RESET`: clears any failure and open stream, rolls back an open transaction, and
    /// returns to `READY` (`04 §8.1`).
    fn handle_reset(&mut self) -> BoltResult<()> {
        // If a transaction was open, RESET rolls it back (best-effort; ignore its error — we are
        // forcing the connection back to a clean READY regardless).
        if matches!(self.state, State::TxReady | State::TxStreaming) {
            let _ = self.executor.rollback();
        }
        self.open_stream = None;
        self.send(&Response::Success { metadata: vec![] })?;
        self.state = State::Ready;
        Ok(())
    }

    /// Sends a `FAILURE` for a `GraphusError` and enters [`State::Failed`], dropping any open
    /// stream (the fail-then-ignore rule then applies until `RESET`).
    fn fail_with(&mut self, error: &graphus_core::GraphusError) -> BoltResult<()> {
        self.open_stream = None;
        self.send_failure(failure_from_error(error))?;
        self.state = State::Failed;
        Ok(())
    }

    /// Sends a protocol `FAILURE` and enters [`State::Failed`].
    fn fail_protocol(&mut self, message: &str) -> BoltResult<()> {
        self.open_stream = None;
        self.send_failure(Failure::new("Neo.ClientError.Request.Invalid", message))?;
        self.state = State::Failed;
        Ok(())
    }

    /// An unexpected request for the current state: `FAILURE` + fail-state (`04 §8.1` rejects an
    /// out-of-order message).
    fn unexpected(&mut self, request: &Request) -> BoltResult<Flow> {
        let msg = format!(
            "request {} is not valid in state {:?}",
            request_name(request),
            self.state
        );
        self.fail_protocol(&msg)?;
        Ok(Flow::Continue)
    }

    // ---- Auth ------------------------------------------------------------------------------------

    /// Resolves `LOGON` credentials through [`AuthProvider::authenticate_password`] (Bolt native
    /// auth, `04 §8.4`). Returns the principal username, or a `FAILURE` to send on rejection.
    fn authenticate(&self, auth: &[(String, Value)]) -> Result<String, Failure> {
        let scheme = map_str(auth, "scheme").unwrap_or("");
        // v1 supports the `basic` scheme (principal + credentials); `none` and others are rejected
        // with a clear FAILURE rather than silently accepted.
        if scheme != "basic" {
            return Err(Failure::new(
                CODE_UNAUTHORIZED,
                format!("unsupported auth scheme {scheme:?}; only \"basic\" is supported"),
            ));
        }
        let principal = map_str(auth, "principal").unwrap_or("");
        let credentials = map_str(auth, "credentials").unwrap_or("");
        match self.auth.authenticate_password(principal, credentials) {
            Ok(user) => Ok(user),
            Err(_) => Err(Failure::new(CODE_UNAUTHORIZED, "authentication failed")),
        }
    }

    // ---- Transport plumbing ----------------------------------------------------------------------

    /// Reads the next complete message payload from the transport, or `None` at EOF.
    fn read_message(&mut self) -> BoltResult<Option<Vec<u8>>> {
        loop {
            // Drain any complete frame already buffered. A NOOP keep-alive is skipped (it carries no
            // message), so we keep pulling.
            match self.dechunker.next_frame()? {
                Some(Frame::Message(payload)) => return Ok(Some(payload)),
                Some(Frame::Noop) => continue,
                None => {}
            }
            // Need more bytes from the transport.
            let n = self.transport.read(&mut self.read_buf)?;
            if n == 0 {
                return Ok(None); // EOF
            }
            // PERF (C1): push the read slice directly; `push` already copies into the inbox,
            // so the intermediate `to_vec()` was a redundant per-read heap allocation.
            self.dechunker.push(&self.read_buf[..n]);
        }
    }

    /// Reads exactly `n` bytes (used for the fixed-size handshake), looping over short reads.
    fn read_exact_bytes(&mut self, n: usize) -> BoltResult<Vec<u8>> {
        let mut out = Vec::with_capacity(n);
        while out.len() < n {
            let want = n - out.len();
            let end = want.min(self.read_buf.len());
            let got = self.transport.read(&mut self.read_buf[..end])?;
            if got == 0 {
                return Err(BoltError::Transport(format!(
                    "EOF after {} of {n} handshake bytes",
                    out.len()
                )));
            }
            out.extend_from_slice(&self.read_buf[..got]);
        }
        Ok(out)
    }

    /// Encodes a response, frames it into chunks, and writes it.
    fn send(&mut self, response: &Response) -> BoltResult<()> {
        // PERF (C4/C5): encode into the retained packer and frame into the retained buffer, both
        // cleared (capacity preserved) between messages, so the steady-state send path allocates
        // nothing. Wire bytes are byte-identical to the prior fresh-Vec path.
        self.packer.reset();
        response.encode_into(&mut self.packer)?;
        self.framed.clear();
        chunk_message_into(&mut self.framed, self.packer.as_bytes());
        self.transport.write_all(&self.framed)
    }

    /// Convenience: send a `FAILURE`.
    fn send_failure(&mut self, failure: Failure) -> BoltResult<()> {
        self.send(&Response::Failure(failure))
    }
}

// ---- free helpers --------------------------------------------------------------------------------

/// Reads the `mode` field from a `RUN`/`BEGIN` extra map (`"r"` = read, anything else / absent =
/// write, matching Bolt's default and `06 §4`).
fn access_mode_from_extra(extra: &[(String, Value)]) -> AccessMode {
    match map_str(extra, "mode") {
        Some("r") => AccessMode::Read,
        _ => AccessMode::Write,
    }
}

/// Reads the `db` field from a `RUN`/`BEGIN` extra map (Bolt 5.x database targeting). An absent or
/// **empty** value means "the default database" and is normalised to `None` (drivers send `""` or
/// omit the field for the home database).
fn db_from_extra(extra: &[(String, Value)]) -> Option<String> {
    map_str(extra, "db")
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
}

/// Borrows a string value from a map by key.
fn map_str<'m>(map: &'m [(String, Value)], key: &str) -> Option<&'m str> {
    map.iter().find_map(|(k, v)| match v {
        Value::String(s) if k == key => Some(s.as_str()),
        _ => None,
    })
}

/// Builds the trailing-`SUCCESS` metadata from a [`QuerySummary`](crate::executor::QuerySummary),
/// optionally flagging `has_more` (`06 §3.1`).
fn summary_metadata(
    summary: &crate::executor::QuerySummary,
    has_more: bool,
) -> Vec<(String, Value)> {
    let mut meta = Vec::new();
    if has_more {
        meta.push(("has_more".to_owned(), Value::Boolean(true)));
    }
    if let Some(t) = &summary.query_type {
        meta.push(("type".to_owned(), Value::String(t.clone())));
    }
    if !summary.stats.is_empty() {
        meta.push(("stats".to_owned(), Value::Map(summary.stats.clone())));
    }
    meta
}

/// A short name for a request, for protocol-error messages.
fn request_name(r: &Request) -> &'static str {
    match r {
        Request::Hello { .. } => "HELLO",
        Request::Logon { .. } => "LOGON",
        Request::Logoff => "LOGOFF",
        Request::Run { .. } => "RUN",
        Request::Discard { .. } => "DISCARD",
        Request::Pull { .. } => "PULL",
        Request::Begin { .. } => "BEGIN",
        Request::Commit => "COMMIT",
        Request::Rollback => "ROLLBACK",
        Request::Reset => "RESET",
        Request::Goodbye => "GOODBYE",
        Request::Route { .. } => "ROUTE",
        Request::Telemetry { .. } => "TELEMETRY",
        Request::Unsupported { .. } => "UNSUPPORTED",
    }
}

/// Encodes a client handshake (magic + four proposals) for tests and any client-side use.
#[must_use]
pub fn encode_client_handshake(proposals: [crate::handshake::Proposal; 4]) -> Vec<u8> {
    let mut v = Vec::with_capacity(20);
    v.extend_from_slice(&MAGIC);
    for p in proposals {
        v.extend_from_slice(&p.to_wire());
    }
    v
}

/// Frames a request into chunked wire bytes for tests and any client-side use.
///
/// # Errors
/// [`BoltError::Encode`] if the request cannot be encoded (never for the standard messages).
pub fn encode_request_framed(request: &Request) -> BoltResult<Vec<u8>> {
    let payload = request.encode()?;
    Ok(crate::framing::chunk_message(&payload))
}

// These end-to-end session tests construct an `Authenticator` and call `set_password`, which runs a
// deliberately CPU-expensive password KDF (`graphus-auth`); under the miri interpreter a KDF takes
// many minutes, so the module is excluded from the miri run. This hides no UB: the session loop is
// pure safe Rust, and the UB-relevant wire codec it drives (framing, message, handshake, packstream)
// is covered by those modules' own unit tests, which DO run green under miri. (See `VERIFICATION.md`
// → miri gate.)
#[cfg(all(test, not(miri)))]
mod tests;
