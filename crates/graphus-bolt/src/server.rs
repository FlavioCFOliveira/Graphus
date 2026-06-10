//! The Bolt **server state machine** — the protocol's behavioural core (`04-technical-design.md`
//! §8.1; `06-bolt-and-error-shapes.md` §3).
//!
//! [`BoltSession`] drives one connection end-to-end over a [`Transport`] (the byte pipe) and a
//! [`BoltExecutor`] (the query seam), authenticating through a shared [`Authenticator`]. It owns no
//! sockets and no runtime: the listener (rmp #20) constructs the three pieces and calls
//! [`BoltSession::run`].
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

use graphus_auth::Authenticator;
use graphus_core::Value;

use crate::error::{BoltError, BoltResult, CODE_UNAUTHORIZED, Failure, failure_from_error};
use crate::executor::{AccessMode, BoltExecutor, Record, RecordStream, TxControl};
use crate::framing::{Dechunker, Frame, chunk_message_into};
use crate::handshake::{MAGIC, Version, negotiate, parse_client_handshake, server_reply};
use crate::message::{ALL, Request, Response};
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

/// A Bolt connection session: the state machine plus its in-flight result stream.
///
/// Generic over the [`Transport`] (byte pipe) and the [`BoltExecutor`] (query seam) so it is
/// equally a UDS, a TCP-TLS, or an in-memory test connection (`04 §8.1`/§8.4). One session handles
/// one connection for its whole lifetime.
pub struct BoltSession<'a, T: Transport, E: BoltExecutor> {
    transport: T,
    executor: E,
    auth: &'a Authenticator,
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
    /// `auth`. The session starts in [`State::Connected`] (pre-handshake).
    pub fn new(transport: T, executor: E, auth: &'a Authenticator) -> Self {
        Self {
            transport,
            executor,
            auth,
            state: State::Connected,
            version: None,
            principal: None,
            open_stream: None,
            dechunker: Dechunker::new(),
            read_buf: vec![0u8; 8 * 1024],
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
                // EOF before GOODBYE: the peer dropped the connection.
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
                Flow::Stop => return Ok(()),
            }
        }
    }

    // ---- Handshake -------------------------------------------------------------------------------

    /// Reads the 20-byte client handshake, negotiates a version, and replies.
    ///
    /// # Errors
    /// [`BoltError::Handshake`] if the magic/length is wrong or no version is acceptable (the
    /// listener closes the connection on a handshake error).
    fn do_handshake(&mut self) -> BoltResult<()> {
        const HANDSHAKE_LEN: usize = MAGIC.len() + 4 * 4;
        let bytes = self.read_exact_bytes(HANDSHAKE_LEN)?;
        let proposals = parse_client_handshake(&bytes)?;
        let chosen = negotiate(&proposals);
        self.transport.write_all(&server_reply(chosen))?;
        match chosen {
            Some(v) => {
                self.version = Some(v);
                self.state = State::Connected;
                Ok(())
            }
            None => {
                // Replied with 00 00 00 00; the connection is rejected.
                self.state = State::Defunct;
                Err(BoltError::Handshake(
                    "no mutually-supported Bolt version".to_owned(),
                ))
            }
        }
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
            Request::Hello { extra: _ } => {
                // HELLO no longer carries credentials in 5.1+ (LOGON does). Acknowledge with server
                // metadata and move to AUTHENTICATION. The `server` agent and `connection_id` are
                // sensible defaults; a listener that mints per-connection ids (rmp #20) can enrich
                // them later without changing the protocol surface.
                let meta = vec![
                    (
                        "server".to_owned(),
                        Value::String("Graphus/0.0.0".to_owned()),
                    ),
                    (
                        "connection_id".to_owned(),
                        Value::String("bolt-1".to_owned()),
                    ),
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
                match self.authenticate(&auth) {
                    Ok(user) => {
                        self.principal = Some(user);
                        self.send(&Response::Success { metadata: vec![] })?;
                        self.state = State::Ready;
                    }
                    Err(failure) => {
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
            // RUN: auto-commit (READY) or in-transaction (TX_READY).
            (
                State::Ready,
                Request::Run {
                    query,
                    parameters,
                    extra,
                },
            ) => {
                let mode = access_mode_from_extra(&extra);
                self.handle_run(
                    &query,
                    parameters,
                    TxControl::AutoCommit { mode },
                    State::Streaming,
                )
            }
            (
                State::TxReady,
                Request::Run {
                    query,
                    parameters,
                    extra: _,
                },
            ) => self.handle_run(
                &query,
                parameters,
                TxControl::InExplicit,
                State::TxStreaming,
            ),
            (State::Ready, Request::Begin { extra }) => {
                let mode = access_mode_from_extra(&extra);
                match self.executor.begin(mode) {
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
            (_, Request::Logoff) => {
                // Drop the identity; back to AUTHENTICATION (5.1+ re-auth without a new connection).
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

    /// Resolves `LOGON` credentials through [`Authenticator::authenticate_password`] (Bolt native
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
            let chunk = self.read_buf[..n].to_vec();
            self.dechunker.push(&chunk);
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
        let payload = response.encode()?;
        let mut framed = Vec::with_capacity(payload.len() + 4);
        chunk_message_into(&mut framed, &payload);
        self.transport.write_all(&framed)
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
