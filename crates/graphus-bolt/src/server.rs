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
//! The **authentication prologue depends on the negotiated version** (rmp #906); everything from
//! `READY` onwards is version-independent.
//!
//! ```text
//! Bolt 5.1+ : CONNECTED --(HELLO ok)--> AUTHENTICATION --(LOGON ok)--> READY
//! Bolt 5.0  : CONNECTED --(HELLO ok, credentials IN the HELLO)-------> READY
//!
//!    READY  --(RUN)--> STREAMING --(stream drained)--> READY
//!    READY  --(BEGIN)--> TX_READY --(RUN)--> TX_STREAMING --(RUN)--> TX_STREAMING
//! TX_STREAMING --(last open stream drained)--> TX_READY
//!  TX_READY --(COMMIT/ROLLBACK)--> READY
//!  post-auth --(error)--> FAILED --(RESET)--> READY
//!  pre-auth  --(HELLO/LOGON fail or out-of-order msg)--> DEFUNCT
//!    <any>  --(GOODBYE / fatal)--> DEFUNCT
//! ```
//!
//! ## Several result streams may be open at once inside a transaction (rmp #907)
//!
//! Inside an explicit transaction a client may start a new statement **while an earlier result is
//! still being streamed**. The Bolt server-state specification says so directly: `TX_STREAMING`
//! lists `RUN to TX_STREAMING or FAILED` (Table 6), and the `PULL`/`DISCARD` tables (7 and 8) give
//! the post-stream state as "`TX_READY` **or `TX_STREAMING` if there are other streams open**"
//! (neo4j.com/docs/bolt/current/bolt/server-state/). Each in-transaction `RUN` is answered with its
//! own `qid`, and `PULL`/`DISCARD` address a specific result by that `qid`. The session therefore
//! keeps an **ordered collection** of open streams, not a single slot, and only returns to
//! `TX_READY` once the last one is consumed or discarded.
//!
//! This is not a theoretical corner of the specification: the official drivers depend on it. The
//! Neo4j Python driver buffers the previous result before the next `tx.run()` **only** when
//! `connection.supports_multiple_results is False` — a branch its own comment labels "Bolt 3
//! Support" — and `_bolt5.py` sets `supports_multiple_results = True`. So on Bolt 5.x the driver
//! deliberately leaves the earlier result open. A server that rejects `RUN` in `TX_STREAMING`
//! breaks any transaction whose first result exceeds the driver's fetch size (1000 by default),
//! because that first result's `PULL` answers `has_more = true` and the connection is still
//! `TX_STREAMING` when the second `tx.run()` arrives.
//!
//! **Auto-commit `STREAMING` stays single-stream**, deliberately: the specification assigns no
//! `qid` to an auto-commit `RUN`, and `STREAMING`'s transition table lists only `PULL` and
//! `DISCARD` — `RUN` is not a valid message there.
//!
//! ## Bolt 5.0 authenticates from `HELLO` (rmp #906)
//!
//! Bolt **5.1** is where authentication moved out of `HELLO` into `LOGON`. The Bolt server-state
//! specification's "Summary of changes" records it exactly: *Version 5.1* — "HELLO message no longer
//! accepts authentication … LOGON message has been added"; *Version 5.0* — "No changes compared to
//! version 4.4" (neo4j.com/docs/bolt/current/bolt/server-state/). So at **5.0** the `HELLO` both
//! negotiates *and* authenticates, there is no `AUTHENTICATION` state, and `LOGON`/`LOGOFF` are not
//! even decodable (see [`crate::message::opcode_available_at`]). The Neo4j reference server encodes
//! the same split: `BoltProtocolV50` drops the `NEGOTIATION` state and starts in `AUTHENTICATION`
//! with `HelloStateTransition.andThen(AuthenticationStateTransition)`, and unregisters the
//! `LOGON`/`LOGOFF` decoders.
//!
//! [`BoltSession::dispatch_connected`] therefore branches on the negotiated version. Both branches
//! validate `user_agent` identically, share the same `HELLO` `SUCCESS` metadata, and route every
//! credential through the one [`BoltSession::authenticate`] chokepoint — so the per-account
//! [`AuthThrottle`] (rmp #823) and the global [`VerifyLimiter`] (rmp #824) apply to the 5.0 path
//! exactly as they do to `LOGON`. Negotiating 5.0 can never be a way around them.
//!
//! ## The fail-then-ignore-until-RESET rule (`04 §8.1`, `06 §3.2`)
//!
//! After any `FAILURE` **in an authenticated state**, the connection enters [`State::Failed`] and
//! **every** subsequent request is answered `IGNORED` until the client sends `RESET`, which clears
//! the failure and returns to [`State::Ready`]. This is modelled as an explicit guard at the top of
//! the dispatch.
//!
//! ## Pre-authentication failures are terminal (`04 §8.1`; rmp #820)
//!
//! A failure **before** authentication completes — a malformed/absent `HELLO`, a failed `LOGON`, a
//! malformed frame, or any out-of-order message in `CONNECTED`/`AUTHENTICATION` — is **not**
//! recoverable. The Bolt server-state spec transitions `NEGOTIATION` and `AUTHENTICATION` to
//! `DEFUNCT` on such a failure (never to `FAILED`), and `RESET` is not a valid message before
//! authentication. Entering the recoverable `FAILED` state here was an authentication bypass: a
//! subsequent `RESET` returned the connection to `READY` with a `None` principal, which the engine
//! seam treats as unrestricted. Every pre-auth failure therefore goes straight to [`State::Defunct`]
//! and closes the connection (see [`BoltSession::fail_terminal`]).
//!
//! ## Streaming honours the fetch size (`04 §7.7`, `06 §3.1`)
//!
//! A `RUN` produces a [`RecordStream`]; the server replies `SUCCESS`
//! with the `fields` metadata and then waits for `PULL`/`DISCARD`. `PULL {n}` emits up to `n`
//! `RECORD`s (`n == -1` = all) followed by a trailing `SUCCESS`; if `n` was bounded and rows remain,
//! the trailing `SUCCESS` carries `has_more = true` and the connection stays in `STREAMING`
//! (`06 §3.1`). `DISCARD` drops the remaining rows and emits only the trailing `SUCCESS`.

use std::sync::Arc;
use std::time::Duration;

use graphus_auth::{AuthProvider, AuthThrottle, VerifyLimiter};
use graphus_core::Value;
use graphus_core::capability::Clock;

use crate::error::{
    BoltError, BoltResult, CODE_FORBIDDEN, CODE_SERVER_BUSY, CODE_UNAUTHORIZED, Failure,
    failure_from_error,
};
use crate::executor::{AccessMode, BoltExecutor, Record, RecordStream, TxControl};
use crate::framing::{Dechunker, Frame, chunk_message_into};
use crate::handshake::{
    MAGIC, Version, detect_manifest_request, graphus_manifest_within, negotiate_within,
    parse_client_handshake, parse_manifest_choice, server_reply, version_supported_within,
};
use crate::message::{ALL, Request, Response};
use crate::packstream::Packer;
use crate::transport::Transport;

/// The server-side connection state (`04 §8.1`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    /// Handshake done; awaiting `HELLO`.
    Connected,
    /// `HELLO` accepted; awaiting `LOGON`. **Bolt 5.1+ only** — at 5.0 authentication rides in the
    /// `HELLO` itself, so a 5.0 connection goes straight from [`Connected`](Self::Connected) to
    /// [`Ready`](Self::Ready) and this state is unreachable (the only other way in, `LOGOFF` from
    /// `READY`, is a 5.1+ message that a 5.0 connection cannot even decode — rmp #906).
    Authentication,
    /// Authenticated and idle; awaiting `RUN`/`BEGIN`/`LOGOFF`/`GOODBYE`.
    Ready,
    /// A `RUN` result is open (auto-commit); awaiting `PULL`/`DISCARD`.
    Streaming,
    /// Inside an explicit transaction; awaiting `RUN`/`COMMIT`/`ROLLBACK`.
    TxReady,
    /// At least one `RUN` result is open inside an explicit transaction; awaiting
    /// `PULL`/`DISCARD`/`RUN` (rmp #907 — a further `RUN` re-enters this state and opens an
    /// additional stream; the connection falls back to [`TxReady`](Self::TxReady) only once the
    /// **last** open stream is consumed or discarded).
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

/// The `server` agent string for the **opt-in Neo4j compatibility mode** (the listener selects it via
/// [`SessionConfig::server_agent`]; not the default). Some strict/legacy Bolt clients — the 1.x-era
/// Neo4j drivers and third-party tooling derived from them — verify the `HELLO` `SUCCESS` `server`
/// string and reject any product that is not the *case-sensitive* literal `Neo4j` (they parse it with
/// an anchored `([^/]+)/(\d+)\.(\d+)…` regex and compare the product with `.equals("Neo4j")`). This
/// value satisfies that check so Graphus interoperates with the widest driver ecosystem.
///
/// **Why `5.13.0` and never higher:** the announced Neo4j version must map to a Neo4j release whose
/// *native* Bolt maximum equals the Bolt version Graphus actually negotiates. Graphus pins Bolt
/// [`handshake::MAX_MINOR`](crate::handshake::MAX_MINOR) = **5.4**, and per the official Bolt
/// compatibility matrix Bolt 5.4 ⇒ Neo4j **5.13–5.22**; `5.13.0` is the floor of that window.
/// Announcing a higher Neo4j version (e.g. `5.26`, which speaks Bolt 5.7/5.8 natively) could make a
/// version-keyed client assume Bolt features Graphus does not serve. If [`handshake::MAX_MINOR`] is
/// ever raised, this constant must move in lock-step to the matching Neo4j floor.
pub const NEO4J_COMPAT_SERVER_AGENT: &str = "Neo4j/5.13.0";

/// Smallest valid `TELEMETRY` `api` value (`0` = managed transaction). The Bolt 5.4+ message spec
/// enumerates the `api` field as `0` (managed transaction), `1` (explicit transaction), `2`
/// (implicit transaction), `3` (driver-level `execute_query()`); any value outside this inclusive
/// range is an invalid api value the server must answer with `FAILURE` → `FAILED`
/// (neo4j.com/docs/bolt/current/bolt/message/).
const VALID_TELEMETRY_API_MIN: i64 = 0;
/// Largest valid `TELEMETRY` `api` value (`3` = driver-level `execute_query()`); see
/// [`VALID_TELEMETRY_API_MIN`].
const VALID_TELEMETRY_API_MAX: i64 = 3;

/// The first Bolt 5.x minor whose `HELLO` **no longer carries** the authentication token — i.e. the
/// minor from which a separate `LOGON` authenticates the connection (Bolt **5.1**; rmp #906).
///
/// Below it (only 5.0 within Graphus's window) the credentials ride in the `HELLO` `extra` map, per
/// the Bolt server-state spec's "Summary of changes" (*Version 5.1*: "HELLO message no longer accepts
/// authentication … LOGON message has been added"; *Version 5.0*: "No changes compared to version
/// 4.4") and the message spec's `HELLO` note ("On versions earlier than 5.1, the authentication token
/// described on the LOGON message should be sent as part of the HELLO message instead").
const LOGON_AUTH_MIN_MINOR: u8 = 1;

/// The `HELLO` `extra` keys that are **not** part of the authentication token when `HELLO` carries
/// credentials (Bolt 5.0 — rmp #906).
///
/// At 5.0 the auth token is *the whole `extra` map minus these reserved fields*, exactly as the Neo4j
/// reference server builds it: `HelloMessageDecoderV41` (the decoder `BoltProtocolV50` registers for
/// `HELLO`) declares this field list, and `AbstractLegacyHelloMessageDecoder.readAuthToken` hands it
/// to `AuthenticationMetadataUtils.extractAuthToken(providedFields, meta)`, which copies every other
/// entry into the token. Keeping the list identical is what makes an unmodified stock driver
/// authenticate: it sends `scheme`/`principal`/`credentials` (and any realm/custom-scheme entries)
/// alongside these, and only these must be filtered out.
///
/// Note what is **absent**: `bolt_agent` is a Bolt **5.3+** field and is *not* in the 5.0 decoder's
/// list, so a 5.0 client that sent it would have it treated as part of the token — the reference
/// behaviour, reproduced here deliberately rather than "improved".
/// The default cap on **concurrently-open result streams within one explicit transaction**
/// (rmp #907).
///
/// The Bolt specification permits a client to keep several results open at once inside a
/// transaction (server-state Tables 6/7/8) and places no limit on how many. The Neo4j reference
/// server keeps them in an unbounded `HashMap` (`TransactionImpl.statementMap`). Graphus does not:
/// on an authenticated connection an unbounded collection is an attacker-controlled allocation —
/// a client could issue `RUN` after `RUN` without ever consuming a result and pin server memory,
/// an engine cursor and an admission permit per stream. The engine bounds the same resource for the
/// same reason (its `max_parked_inline` queue).
///
/// **Where the number comes from.** Every open stream pins one engine *admission permit* for its
/// whole lifetime, and the engine's per-database budget for those is `admission
/// .max_concurrent_queries` (256 by default). A per-transaction cap of a **quarter** of that budget
/// means no single transaction — and therefore no single connection — can monopolise a database's
/// admission capacity with results nobody is reading, while still being an order of magnitude above
/// what any real driver does: a driver opens one stream per `tx.run()` whose result the application
/// has not finished consuming, which in practice is a handful.
///
/// **What a client sees when it is hit.** The offending `RUN` is answered with a `FAILURE`
/// (`Neo.ClientError.Request.Invalid`) and the connection enters `FAILED`, so the transaction is
/// abandoned rather than silently degraded; `RESET` recovers the connection and rolls the
/// transaction back. The classification is deliberately a *client* error: retrying the same
/// statement would hit the same limit, so it must not look retryable to a driver.
pub const DEFAULT_MAX_OPEN_STREAMS_PER_TX: usize = 64;

const HELLO_NON_AUTH_FIELDS: [&str; 5] = [
    "patch_bolt",
    "routing",
    "user_agent",
    "notifications_minimum_severity",
    "notifications_disabled_categories",
];

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
    /// The **highest Bolt 5.x minor** this session will advertise and accept (rmp #906). Defaults to
    /// the compiled [`handshake::MAX_MINOR`](crate::handshake::MAX_MINOR), so the out-of-the-box
    /// behaviour is bit-for-bit what it always was.
    ///
    /// Lowering it pins an unmodified stock driver to an exact older minor — the supported way to
    /// exercise (or work around) a specific protocol version end to end. The cap governs **both**
    /// handshake forms: the legacy 4-slot reply negotiates within `MIN_MINOR..=max_protocol_minor`
    /// and the Manifest-v1 exchange advertises (and accepts) exactly the same window, so the two can
    /// never disagree. Values outside `MIN_MINOR..=MAX_MINOR` are clamped by the handshake layer
    /// ([`clamp_max_minor`](crate::handshake::clamp_max_minor)), so this can only ever *narrow* what
    /// Graphus offers.
    pub max_protocol_minor: u8,
    /// The maximum number of **concurrently-open result streams inside one explicit transaction**
    /// (rmp #907). Defaults to [`DEFAULT_MAX_OPEN_STREAMS_PER_TX`], whose documentation explains
    /// where the number comes from and what a client sees when the cap is reached. A value of `0` is
    /// treated as `1` (a transaction must always be able to open one result).
    pub max_open_streams_per_tx: usize,
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            connection_id: "bolt-1".to_owned(),
            server_agent: DEFAULT_SERVER_AGENT.to_owned(),
            advertised_bolt_address: None,
            routing_ttl_secs: DEFAULT_ROUTING_TTL_SECS,
            max_protocol_minor: crate::handshake::MAX_MINOR,
            max_open_streams_per_tx: DEFAULT_MAX_OPEN_STREAMS_PER_TX,
        }
    }
}

/// The default `ROUTE` routing-table TTL in seconds (300 = 5 minutes, Neo4j's driver default).
pub const DEFAULT_ROUTING_TTL_SECS: i64 = 300;

/// The per-account failed-authentication throttle a listener wires into a [`BoltSession`] so the
/// Bolt native `LOGON` path shares the **same** lockout policy as the REST `POST /auth/login`
/// endpoint (rmp #458/#823): the shared [`AuthThrottle`] plus the [`Clock`] its token buckets read.
///
/// [`BoltSession::authenticate`] consults it **before** the Argon2 verify, keyed by the attempted
/// **principal** — exactly as the REST endpoint keys by the submitted username — so an account whose
/// failure budget is spent is rejected up front without paying the memory-hard KDF, closing the
/// interface-shopping gap where an attacker used Bolt to sidestep the per-account lockout REST
/// enforces (CWE-307). The budget accrues **across reconnects**: a failed pre-auth `LOGON` is terminal
/// (rmp #820), so each connection is one attempt, and the shared throttle remembers the account's
/// spent budget from one connection to the next. A session with no throttle attached (the default)
/// authenticates exactly as before.
#[derive(Clone)]
pub struct LoginThrottle {
    throttle: Arc<AuthThrottle>,
    clock: Arc<dyn Clock + Send + Sync>,
}

impl LoginThrottle {
    /// Wraps the shared [`AuthThrottle`] + [`Clock`] a listener already owns so it can be attached to a
    /// session with [`BoltSession::with_login_throttle`].
    #[must_use]
    pub fn new(throttle: Arc<AuthThrottle>, clock: Arc<dyn Clock + Send + Sync>) -> Self {
        Self { throttle, clock }
    }
}

impl std::fmt::Debug for LoginThrottle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never expose the throttle's internal per-key bucket state or the clock.
        f.debug_struct("LoginThrottle").finish_non_exhaustive()
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
    auth: &'a dyn AuthProvider,
    /// Per-connection metadata (connection id, server agent, advertised routing address — rmp #95).
    config: SessionConfig,
    state: State,
    /// The negotiated protocol version (set after the handshake).
    version: Option<Version>,
    /// The authenticated principal (set after `LOGON`).
    principal: Option<String>,
    /// The in-flight results, while `STREAMING` / `TX_STREAMING`, **in the order they were opened**
    /// (rmp #907).
    ///
    /// Auto-commit `STREAMING` holds at most one entry, with no `qid` — the specification assigns
    /// none and `RUN` is not a valid `STREAMING` message, so a second one can never appear. Inside
    /// an explicit transaction there may be several, each addressed by its own `qid`; an entry is
    /// removed when its result is consumed or discarded, and the connection leaves `TX_STREAMING`
    /// only when the collection empties. It is bounded by
    /// [`SessionConfig::max_open_streams_per_tx`].
    open_streams: Vec<OpenStream<E::Stream>>,
    /// Inside an explicit transaction, the server assigns each `RUN` a query id (`qid`), returned in
    /// the `RUN` `SUCCESS` and addressable by `PULL`/`DISCARD` (`04 §8.1` / Bolt message spec). It
    /// starts at 0 for the first `RUN` after `BEGIN` and increments per statement; it is reset when a
    /// new explicit transaction opens. An auto-commit `RUN` consumes no `qid` (the spec returns none).
    next_qid: i64,
    /// The `qid` of the **most recently opened** statement of the current explicit transaction —
    /// what `qid == -1` ("the last query", also the field's default) addresses.
    ///
    /// It records the last `qid` *assigned*, not the last still open: it is deliberately **not**
    /// cleared when that stream drains. This is the Neo4j reference server's `latestStatementId`
    /// (`TransactionImpl.run` sets it; `StreamingStateTransition` resolves `statementId == -1` to
    /// it and fails when the statement it names is no longer open), so a `-1` that names a finished
    /// result is a protocol error here too rather than a silent re-aim at some other open stream.
    /// `None` outside an explicit transaction — an auto-commit result carries no `qid`, so `-1`
    /// simply addresses the single open stream.
    last_opened_qid: Option<i64>,
    /// Reassembles request messages from the inbound byte stream.
    dechunker: Dechunker,
    /// A scratch read buffer.
    read_buf: Vec<u8>,
    /// PERF (C4/C5): retained encode buffer (PackStream payload), reused across responses.
    packer: Packer,
    /// PERF (C4/C5): retained framing buffer (chunked wire bytes), reused across responses.
    framed: Vec<u8>,
    /// Optional per-account failed-`LOGON` throttle (rmp #458/#823). `None` (the default) leaves the
    /// auth path unchanged; the server attaches the process-wide shared throttle via
    /// [`with_login_throttle`](Self::with_login_throttle) so Bolt enforces the SAME per-account lockout
    /// as REST `/auth/login`.
    login_throttle: Option<LoginThrottle>,
    /// Optional GLOBAL bound on concurrent password verifications (rmp #824). `None` (the default)
    /// leaves the auth path unbounded; the server attaches the process-wide shared limiter via
    /// [`with_verify_limiter`](Self::with_verify_limiter) so a username-rotation flood cannot force
    /// unbounded concurrent Argon2 work on the shared blocking pool.
    verify_limiter: Option<Arc<VerifyLimiter>>,
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

/// One open result stream and the `qid` that addresses it (rmp #907).
struct OpenStream<S> {
    /// The server-assigned statement id returned in the `RUN` `SUCCESS`, for a statement inside an
    /// explicit transaction. `None` for an auto-commit result: the Bolt message spec assigns a `qid`
    /// to an explicit-transaction `RUN` only, and an auto-commit connection can hold just one result.
    qid: Option<i64>,
    /// The result itself, with its one-record `has_more` lookahead.
    result: OpenResult<S>,
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
            open_streams: Vec::new(),
            next_qid: 0,
            last_opened_qid: None,
            dechunker: Dechunker::new(),
            read_buf: vec![0u8; 8 * 1024],
            packer: Packer::new(),
            framed: Vec::new(),
            login_throttle: None,
            verify_limiter: None,
        }
    }

    /// Attaches the shared per-account failed-`LOGON` throttle (rmp #458/#823) so the Bolt auth path
    /// enforces the **same** per-account lockout as REST `/auth/login`. Consulted in
    /// [`authenticate`](Self::authenticate) **before** the Argon2 verify (keyed by the attempted
    /// principal); without it — the default — the auth path is unthrottled, exactly as before.
    #[must_use]
    pub fn with_login_throttle(mut self, throttle: LoginThrottle) -> Self {
        self.login_throttle = Some(throttle);
        self
    }

    /// Attaches the shared **global** concurrent-password-verification bound (rmp #824), consulted in
    /// [`authenticate`](Self::authenticate) **after** the per-account throttle and **before** the
    /// Argon2 verify. When the process is already at its verification capacity, a `LOGON` is shed with a
    /// transient [`CODE_SERVER_BUSY`] `FAILURE` **without** running the KDF, so a username-rotation flood
    /// cannot pile unbounded concurrent Argon2 work onto the shared blocking pool. Without it — the
    /// default — verification is unbounded, exactly as before.
    #[must_use]
    pub fn with_verify_limiter(mut self, limiter: Arc<VerifyLimiter>) -> Self {
        self.verify_limiter = Some(limiter);
        self
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
                // An abrupt disconnect must NOT leak an explicit transaction: roll back any open
                // tx here (best-effort, idempotent) so it stops pinning the GC watermark and its
                // intents stop blocking concurrent writers (rmp #388). RESET/ROLLBACK already
                // cleared it in the clean cases, so `rollback_open_tx` is a no-op then; the
                // executor's `Drop` is the final backstop (covers a panic mid-session).
                self.executor.rollback_open_tx();
                self.state = State::Defunct;
                return Ok(());
            };
            let request = match self.decode_request(&payload) {
                Ok(r) => r,
                Err(e) => {
                    let failure = Failure::new("Neo.ClientError.Request.Invalid", e.to_string());
                    // Before authentication a malformed message is TERMINAL: the Bolt server-state
                    // spec transitions NEGOTIATION / AUTHENTICATION to DEFUNCT on failure, and RESET
                    // is not valid pre-auth — so a recoverable FAILED here would let a later RESET
                    // resurrect an unauthenticated connection to READY (which then runs with a `None`,
                    // i.e. unrestricted, principal at the engine seam — rmp #820). Send the FAILURE,
                    // flush, then close. After authentication a malformed message stays recoverable
                    // (fail-then-ignore-until-RESET).
                    if matches!(self.state, State::Connected | State::Authentication) {
                        self.send_failure(failure)?;
                        self.state = State::Defunct;
                        self.transport.flush()?;
                        return Ok(());
                    }
                    self.send_failure(failure)?;
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

    /// Decodes one request payload **at the negotiated protocol version** (rmp #906), so a message
    /// the version does not define (`LOGON`/`LOGOFF` below 5.1, `TELEMETRY` below 5.4) is rejected as
    /// undecodable instead of being acted on. The caller (`run`) answers the error exactly as it
    /// answers any other malformed message.
    ///
    /// The version is always `Some` here — `do_handshake` runs to completion before the first message
    /// is read — but the `None` arm decodes version-agnostically rather than panicking, so a future
    /// caller that drives the message loop without a handshake still behaves as it did before.
    fn decode_request(&self, payload: &[u8]) -> BoltResult<Request> {
        match self.version {
            Some(version) => Request::decode_at(payload, version),
            None => Request::decode(payload),
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

        // Negotiate within the configured window (rmp #906): `SessionConfig::max_protocol_minor`
        // defaults to the compiled `MAX_MINOR`, so an unconfigured listener negotiates exactly as
        // before; a capped listener offers only up to its cap.
        let chosen = negotiate_within(&proposals, self.config.max_protocol_minor);
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
        // The manifest advertises — and the acceptance check below honours — the SAME capped window
        // the legacy path negotiates (rmp #906), so the two handshake forms can never disagree about
        // which versions Graphus offers.
        let cap = self.config.max_protocol_minor;
        self.transport.write_all(&graphus_manifest_within(cap))?;
        let choice_bytes = self.read_manifest_choice()?;
        let choice = parse_manifest_choice(&choice_bytes)?;
        if version_supported_within(choice.version, cap) {
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
        // GOODBYE is honoured in every state: the client is leaving. Per the Bolt message spec,
        // GOODBYE "interrupts the server current work if there is any"
        // (neo4j.com/docs/bolt/current/bolt/message/) — an open explicit transaction is "current
        // work", so roll it back here (best-effort, idempotent) for symmetry with the EOF arm
        // (`run`): a clean session-ended signal must not leak a tx that pins the GC watermark and
        // blocks concurrent writers. `rollback_open_tx` is a no-op when nothing is open (RESET /
        // ROLLBACK / COMMIT already cleared it). The executor's `Drop` remains the final backstop for
        // the panic path; this explicit call also covers a future executor that implements
        // `rollback_open_tx` without relying on `Drop` (rmp #444).
        if matches!(request, Request::Goodbye) {
            self.executor.rollback_open_tx();
            self.state = State::Defunct;
            return Ok(Flow::Stop);
        }

        // Fail-then-ignore-until-RESET: in FAILED, only RESET is processed; all else is IGNORED.
        if self.state == State::Failed {
            if matches!(request, Request::Reset) {
                // `handle_reset` decides the flow: it recovers an authenticated connection to READY
                // (Continue), but makes an *unauthenticated* one terminal (Stop) — rmp #820.
                return self.handle_reset();
            }
            self.send(&Response::Ignored)?;
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
    ///
    /// What the `HELLO` *does* depends on the negotiated version (rmp #906): at **5.1+** it only
    /// negotiates and hands over to `AUTHENTICATION` for a `LOGON`; at **5.0** it also authenticates,
    /// from the credentials in its own `extra` map, and lands directly in `READY`.
    fn dispatch_connected(&mut self, request: Request) -> BoltResult<Flow> {
        match request {
            Request::Hello { extra } => {
                // `user_agent` is a REQUIRED field of the HELLO extra map across all Bolt 5.x
                // versions (`04 §8.1`); a HELLO that omits it (or carries a non-string / empty
                // value) is malformed and is rejected with FAILURE rather than silently accepted —
                // this also closes a trivial DoS where a client drives the handshake with truncated
                // metadata. Being a pre-authentication failure it is terminal: the connection goes
                // straight to DEFUNCT and closes (rmp #820), never the recoverable FAILED state.
                // Validated identically on BOTH version branches, and BEFORE any credential is
                // looked at, so a malformed HELLO never reaches the authenticator.
                let user_agent_ok = map_str(&extra, "user_agent").is_some_and(|s| !s.is_empty());
                if !user_agent_ok {
                    // A malformed HELLO is a PRE-authentication failure and is therefore TERMINAL:
                    // the Bolt server-state spec transitions NEGOTIATION to DEFUNCT on an
                    // unsuccessful HELLO, and RESET is not valid before authentication — so this must
                    // not enter the RESET-recoverable FAILED state (rmp #820).
                    return self.fail_terminal(Failure::new(
                        "Neo.ClientError.Request.Invalid",
                        "HELLO is missing the required `user_agent` field",
                    ));
                }
                if self.hello_carries_auth() {
                    // Hand `extra` over BY VALUE: the auth token is derived by filtering it in place,
                    // so the decoded map is never duplicated while the (slow) KDF runs. See
                    // `hello_auth_token`.
                    return self.hello_authenticate(extra);
                }
                // Bolt 5.1+: HELLO no longer carries credentials (LOGON does). Acknowledge with the
                // server metadata and move to AUTHENTICATION.
                let metadata = self.hello_success_metadata();
                self.send(&Response::Success { metadata })?;
                self.state = State::Authentication;
                Ok(Flow::Continue)
            }
            other => self.unexpected(&other),
        }
    }

    /// Whether the negotiated version carries the authentication token **inside `HELLO`** — true
    /// only for Bolt 5.0 within Graphus's 5.0–5.4 window (rmp #906; see [`LOGON_AUTH_MIN_MINOR`]).
    ///
    /// An un-negotiated session (`version == None`, unreachable once `do_handshake` has run) keeps
    /// the 5.1+ `LOGON` flow, which is the safer default: it never treats a `HELLO` as an
    /// authentication attempt on a connection whose version is unknown. The `major` is checked for
    /// the same reason its two sibling predicates check it
    /// ([`version_supported_within`](crate::handshake::version_supported_within) and
    /// [`opcode_available_at`](crate::message::opcode_available_at)): the minor number only means
    /// anything within a known major, so all three agree by construction rather than by coincidence.
    fn hello_carries_auth(&self) -> bool {
        self.version.is_some_and(|v| {
            v.major == crate::handshake::SUPPORTED_MAJOR && v.minor < LOGON_AUTH_MIN_MINOR
        })
    }

    /// The `HELLO` `SUCCESS` metadata, identical on both version branches: the `server` agent and the
    /// per-connection `connection_id` from the listener's [`SessionConfig`] (rmp #95), plus `hints` —
    /// the optional driver-tuning map (empty here; Graphus advertises no hints yet, but the key's
    /// presence is what some drivers probe).
    fn hello_success_metadata(&self) -> Vec<(String, Value)> {
        vec![
            (
                "server".to_owned(),
                Value::String(self.config.server_agent.clone()),
            ),
            (
                "connection_id".to_owned(),
                Value::String(self.config.connection_id.clone()),
            ),
            ("hints".to_owned(), Value::Map(vec![])),
        ]
    }

    /// Bolt **5.0**: authenticate from the `HELLO` `extra` map and, on success, go straight to
    /// `READY` (rmp #906).
    ///
    /// The token is `extra` minus [`HELLO_NON_AUTH_FIELDS`] — the reference server's rule, see that
    /// constant — and is resolved through the SAME [`authenticate`](Self::authenticate) chokepoint as
    /// a 5.1+ `LOGON`, so the per-account throttle (rmp #823) and the global verification bound
    /// (rmp #824) are enforced here too. A client can never sidestep either limiter by negotiating
    /// 5.0.
    ///
    /// Success mirrors the `LOGON` success arm exactly (audit hook, executor principal, the shared
    /// `HELLO` `SUCCESS` metadata, and the rmp #469 pre-authentication read-deadline relaxation);
    /// failure is a PRE-authentication failure and is therefore terminal (rmp #820).
    ///
    /// `extra` is taken **by value** so the token is produced by filtering it in place. Cloning it
    /// instead would keep the decoded `HELLO` map and a near-copy of it alive simultaneously across
    /// the memory-hard KDF — the longest window in the pre-authentication phase — raising this path's
    /// peak heap ~1.55× over the `LOGON` path for the same attacker byte budget, and with it the
    /// number of unauthenticated connections needed to exhaust memory (measured on a
    /// `MAX_DECODE_ELEMENTS`-sized `extra`; the `rmp` #550 decode budget is the bound this must not
    /// erode).
    fn hello_authenticate(&mut self, extra: Vec<(String, Value)>) -> BoltResult<Flow> {
        let auth = hello_auth_token(extra);
        // Capture the attempted principal BEFORE authenticating so a failure can be audited with the
        // attempted username (the username is not a secret; the credentials in `auth` ARE — they are
        // never passed to the audit hook — rmp #70).
        let attempted = map_str(&auth, "principal").map(str::to_owned);
        match self.authenticate(&auth) {
            Ok(user) => {
                // Announce the identity to the executor so it can authorize identity-gated work
                // (rmp #84) and record an `auth_success` audit event (rmp #70).
                self.executor.on_auth_success(&user);
                self.executor.set_principal(Some(&user));
                self.principal = Some(user);
                // At 5.0 the HELLO SUCCESS is BOTH the negotiation ack and the authentication ack, so
                // it carries the same `server`/`connection_id`/`hints` metadata as the 5.1+ HELLO
                // (the 5.1+ LOGON's own empty SUCCESS has no counterpart here).
                let metadata = self.hello_success_metadata();
                self.send(&Response::Success { metadata })?;
                self.state = State::Ready;
                // The connection has authenticated: relax the transport's stricter *pre-authentication*
                // read deadline (the slow-loris guard that reaps a connected-but-silent unauthenticated
                // client) to its steady-state idle policy (rmp #469, F-NET-1). Skipping this on the 5.0
                // path would reap legitimate long-lived 5.0 sessions. A no-op on transports without a
                // deadline.
                self.transport.on_authenticated();
                Ok(Flow::Continue)
            }
            Err(failure) => {
                // Record the failed attempt for audit (rmp #70) before the FAILURE goes out.
                self.executor
                    .on_auth_failure(attempted.as_deref(), "authentication failed");
                // A failed 5.0 HELLO is a PRE-authentication failure and is TERMINAL, exactly like a
                // failed 5.1+ LOGON: the Bolt server-state spec transitions to DEFUNCT on an
                // unsuccessful HELLO, and RESET is not valid before authentication — so this must never
                // enter the RESET-recoverable FAILED state (rmp #820).
                self.fail_terminal(failure)
            }
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
                        // The connection has authenticated: relax the transport's stricter
                        // *pre-authentication* read deadline (the slow-loris guard that reaps a
                        // connected-but-silent unauthenticated client) to its steady-state idle policy,
                        // so a legitimate long-lived authenticated session is not reaped (rmp #469,
                        // F-NET-1). A no-op on transports without a deadline.
                        self.transport.on_authenticated();
                        Ok(Flow::Continue)
                    }
                    Err(failure) => {
                        // Record the failed attempt for audit (rmp #70) before the FAILURE goes out.
                        self.executor
                            .on_auth_failure(attempted.as_deref(), "authentication failed");
                        // A failed LOGON is a PRE-authentication failure and is TERMINAL: the Bolt
                        // server-state spec transitions AUTHENTICATION to DEFUNCT on an unsuccessful
                        // LOGON (never a recoverable FAILED), and RESET is not valid before
                        // authentication (`04 §8.4`: failed auth → FAILURE + close). Closing here
                        // prevents a later RESET from resurrecting the unauthenticated connection to
                        // READY with a `None` (unrestricted) principal (rmp #820). The FAILURE keeps
                        // its `Neo.ClientError.Security.Unauthorized` code (set by `authenticate`).
                        self.fail_terminal(failure)
                    }
                }
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
                let extra = match parse_tx_extra(&extra) {
                    Ok(extra) => extra,
                    Err(rejection) => return self.refuse_extra(rejection, "RUN"),
                };
                self.handle_run(
                    &query,
                    parameters,
                    TxControl::AutoCommit {
                        mode: extra.mode,
                        db: extra.db,
                        timeout: extra.timeout,
                    },
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
                let extra = match parse_tx_extra(&extra) {
                    Ok(extra) => extra,
                    Err(rejection) => return self.refuse_extra(rejection, "RUN"),
                };
                self.handle_run(
                    &query,
                    parameters,
                    TxControl::InExplicit { db: extra.db },
                    State::TxStreaming,
                )
            }
            (State::Ready, Request::Begin { extra }) => {
                let extra = match parse_tx_extra(&extra) {
                    Ok(extra) => extra,
                    Err(rejection) => return self.refuse_extra(rejection, "BEGIN"),
                };
                match self
                    .executor
                    .begin(extra.mode, extra.db.as_deref(), extra.timeout)
                {
                    Ok(()) => {
                        // A fresh transaction restarts qid assignment at 0 (`04 §8.1`; qids are
                        // scoped to the transaction — rmp #391), and nothing is open in it yet.
                        self.next_qid = 0;
                        self.last_opened_qid = None;
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
                //
                // `ROUTE` carries `imp_user` too (the reference server routes it through the same
                // impersonation transition as `BEGIN`/`RUN` — `RouteStateTransition` extends
                // `SimpleImpersonationStateTransition`), so it is refused here on the same terms: a
                // routing table resolved for the *connection* principal, handed to a client that
                // asked for another principal's home database, is a silent answer to a question the
                // client did not ask (`rmp` #909).
                let db = match parse_route_extra(&extra) {
                    Ok(db) => db,
                    Err(rejection) => return self.refuse_extra(rejection, "ROUTE"),
                };
                self.handle_route(db.as_deref())?;
                Ok(Flow::Continue)
            }
            (State::Ready, Request::Telemetry { api }) => {
                // TELEMETRY (Bolt 5.4+) is advisory: it reports which driver API the client used. The
                // spec state machine accepts it ONLY in READY — `READY + TELEMETRY -> SUCCESS{} ->
                // READY` (no state change). It is rejected as a wrong-state request in every other
                // state (it falls through to `unexpected` below), per the Bolt server-state spec. The
                // `telemetry.enabled` HELLO hint is opt-out only and never makes TELEMETRY legal
                // outside READY; in READY the server must SUCCESS it even if the hint was sent.
                // (Supersedes the earlier rmp #95 "accept in any state" leniency in favour of the
                // inviolable 100%-Bolt-compliance mandate.)
                //
                // The `api` value is validated against the spec's enumeration — 0 = managed
                // transaction, 1 = explicit transaction, 2 = implicit transaction, 3 = driver-level
                // `execute_query()`. The Bolt message spec mandates that "a TELEMETRY message [that]
                // contains a value that is not a valid api value … responds with a FAILURE message and
                // enters the FAILED state" (neo4j.com/docs/bolt/current/bolt/message/). An out-of-range
                // `api` (the codec already rejects a non-integer) is therefore a protocol error →
                // FAILURE `Neo.ClientError.Request.Invalid` → FAILED, not a silent SUCCESS.
                if !(VALID_TELEMETRY_API_MIN..=VALID_TELEMETRY_API_MAX).contains(&api) {
                    self.fail_protocol(&format!(
                        "TELEMETRY api {api} is invalid (must be 0, 1, 2, or 3)"
                    ))?;
                    return Ok(Flow::Continue);
                }
                self.send(&Response::Success { metadata: vec![] })?;
                Ok(Flow::Continue)
            }
            (State::Ready, Request::Logoff) => {
                // LOGOFF is valid ONLY in READY (`04 §8.1`; Bolt spec: "If LOGOFF is received while
                // the server is not in the READY state, it should trigger a FAILURE"). Drop the
                // identity; back to AUTHENTICATION (5.1+ re-auth without a new connection).
                self.executor.set_principal(None);
                self.principal = None;
                self.send(&Response::Success { metadata: vec![] })?;
                self.state = State::Authentication;
                Ok(Flow::Continue)
            }
            (State::TxReady, Request::Logoff) => {
                // LOGOFF inside an open explicit transaction is an invalid transition (the previous
                // wildcard arm wrongly accepted it, dropping the principal and leaving the tx
                // dangling — rmp #392). Roll the transaction back so it does not leak (mirrors RESET
                // / the EOF arm), then FAILURE → FAILED per the spec; the client recovers with RESET.
                let _ = self.executor.rollback();
                self.fail_protocol("LOGOFF is only valid in the READY state")?;
                Ok(Flow::Continue)
            }
            (_, Request::Reset) => self.handle_reset(),
            (_, other) => self.unexpected(&other),
        }
    }

    /// `STREAMING`: `PULL`, `DISCARD`, `RESET`. `TX_STREAMING`: the same, plus `RUN` (rmp #907).
    ///
    /// The asymmetry is the specification's, not a simplification. `STREAMING`'s transition table
    /// lists only `PULL` and `DISCARD` ("this result must be fully consumed or discarded by a client
    /// before the server can re-enter the READY state and allow any further queries to be
    /// executed"), whereas `TX_STREAMING` additionally lists `RUN to TX_STREAMING or FAILED`
    /// (Table 6) — a second statement inside the same transaction opens an *additional* result
    /// stream and leaves the connection streaming
    /// (neo4j.com/docs/bolt/current/bolt/server-state/).
    ///
    /// `COMMIT` and `ROLLBACK` are deliberately **not** accepted here: neither appears among
    /// `TX_STREAMING`'s transitions — they are listed for `TX_READY` only — and the specification
    /// states that the open results "must be fully consumed or discarded by a client before the
    /// server can transition to the TX_READY state". The official drivers honour this: the Neo4j
    /// Python driver's `_commit` and `_rollback` both call `_consume_results()` first, with the
    /// comment "DISCARD pending records then do a commit". So they fall through to
    /// [`unexpected`](Self::unexpected) → `FAILURE` → `FAILED`, exactly as any other out-of-order
    /// message does.
    fn dispatch_streaming(&mut self, request: Request) -> BoltResult<Flow> {
        match (self.state, request) {
            (_, Request::Pull { n, qid }) => self.handle_pull(n, qid, true),
            (_, Request::Discard { n, qid }) => self.handle_pull(n, qid, false),
            (_, Request::Reset) => self.handle_reset(),
            (
                State::TxStreaming,
                Request::Run {
                    query,
                    parameters,
                    extra,
                },
            ) => {
                // A further statement in the same explicit transaction. The transaction is pinned to
                // the database named at BEGIN; the executor rejects a different non-empty `db` here,
                // exactly as it does for the TX_READY RUN.
                let extra = match parse_tx_extra(&extra) {
                    Ok(extra) => extra,
                    Err(rejection) => return self.refuse_extra(rejection, "RUN"),
                };
                self.handle_run(
                    &query,
                    parameters,
                    TxControl::InExplicit { db: extra.db },
                    State::TxStreaming,
                )
            }
            (_, other) => self.unexpected(&other),
        }
    }

    // ---- RUN / PULL streaming --------------------------------------------------------------------

    /// Runs a query and, on success, replies `SUCCESS{fields}`, opens a result stream and enters
    /// `streaming_state`.
    ///
    /// Inside an explicit transaction the new stream is **added** to the streams already open
    /// (rmp #907) rather than replacing one; the per-transaction cap is enforced first, *before* the
    /// executor is asked to do any work, so a refused `RUN` never starts a statement it then has to
    /// abandon.
    fn handle_run(
        &mut self,
        query: &str,
        parameters: Vec<(String, Value)>,
        tx: TxControl,
        streaming_state: State,
    ) -> BoltResult<Flow> {
        let in_transaction = streaming_state == State::TxStreaming;
        // An auto-commit RUN is only ever dispatched from READY, which is unreachable while a result
        // is open — so the single-stream invariant of `STREAMING` holds by construction.
        debug_assert!(in_transaction || self.open_streams.is_empty());
        if in_transaction && self.open_streams.len() >= self.max_open_streams_per_tx() {
            // The per-transaction open-stream cap (see `DEFAULT_MAX_OPEN_STREAMS_PER_TX`). Refuse
            // BEFORE running anything: a client error, non-retryable, recoverable with RESET.
            let limit = self.max_open_streams_per_tx();
            self.fail_protocol(&format!(
                "too many result streams open in one transaction (limit {limit}); consume or \
                 discard a result before running another statement"
            ))?;
            return Ok(Flow::Continue);
        }
        match self.executor.run(query, parameters, tx) {
            Ok(stream) => {
                let fields: Vec<Value> = stream
                    .fields()
                    .iter()
                    .map(|f| Value::String(f.clone()))
                    .collect();
                let mut metadata = vec![("fields".to_owned(), Value::List(fields))];
                // Inside an explicit transaction the server assigns this statement a `qid` and
                // returns it in the RUN SUCCESS so `PULL`/`DISCARD` can address it (`04 §8.1`; Bolt
                // message spec: "qid::Integer specifies the server assigned statement ID … Explicit
                // Transaction only"). An auto-commit RUN omits `qid` entirely (rmp #391).
                let qid = if in_transaction {
                    let qid = self.next_qid;
                    self.next_qid += 1;
                    // This statement becomes "the last query" that a `qid` of -1 addresses.
                    self.last_opened_qid = Some(qid);
                    metadata.push(("qid".to_owned(), Value::Integer(qid)));
                    Some(qid)
                } else {
                    // An auto-commit result has no qid; `-1` addresses the one open stream.
                    self.last_opened_qid = None;
                    None
                };
                self.send(&Response::Success { metadata })?;
                self.open_streams.push(OpenStream {
                    qid,
                    result: OpenResult::new(stream),
                });
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

    /// The effective per-transaction open-stream cap: [`SessionConfig::max_open_streams_per_tx`],
    /// floored at 1 so a misconfigured `0` cannot make every in-transaction `RUN` impossible.
    fn max_open_streams_per_tx(&self) -> usize {
        self.config.max_open_streams_per_tx.max(1)
    }

    /// Resolves the `qid` of a `PULL`/`DISCARD` to an index into [`open_streams`](Self::open_streams),
    /// or `None` when it names no open stream (rmp #391/#907).
    ///
    /// An absent `qid` and `qid == -1` are the same thing — the Bolt message spec gives the field a
    /// default of `-1`, "the last executed statement". Inside a transaction that is the most recently
    /// *opened* statement ([`last_opened_qid`](Self::last_opened_qid)); if that statement has already
    /// been consumed, `-1` resolves to nothing and the caller reports a protocol failure, exactly as
    /// the reference server does. Outside a transaction no `qid` is ever assigned, so `-1` addresses
    /// the single open auto-commit result.
    fn stream_index_for(&self, qid: Option<i64>) -> Option<usize> {
        let requested = qid.unwrap_or(ALL);
        if requested == ALL {
            return match self.last_opened_qid {
                Some(last) => self.open_streams.iter().position(|s| s.qid == Some(last)),
                None => self.open_streams.iter().position(|s| s.qid.is_none()),
            };
        }
        self.open_streams
            .iter()
            .position(|s| s.qid == Some(requested))
    }

    /// Emits up to `n` records (`n == -1` = all) when `emit` is true (PULL) or silently drops them
    /// when false (DISCARD), then the trailing `SUCCESS`. Honours the fetch size (`04 §7.7`) and
    /// reports an **accurate** `has_more` via the result's one-record lookahead (`06 §3.1`).
    fn handle_pull(&mut self, n: i64, qid: Option<i64>, emit: bool) -> BoltResult<Flow> {
        // Validate the `n` domain (`04 §7.7`/`06 §3.1`): the only legal values are `-1` (fetch/throw
        // away all remaining) or a strictly positive integer. The spec is silent on `n == 0` and
        // `n < -1`; the Neo4j reference server rejects them with FAILURE
        // (`Neo.ClientError.Request.Invalid`) → FAILED, so we mirror that for driver-ecosystem
        // compatibility rather than silently treating an out-of-range `n` as a no-op or "all".
        if n != ALL && n < 1 {
            self.fail_protocol("PULL/DISCARD n must be -1 (all) or a positive integer")?;
            return Ok(Flow::Continue);
        }
        // Route to the addressed stream (rmp #391/#907). `qid == -1` (or absent) means "the last
        // executed statement"; an explicit `qid` names one of the streams open in this transaction.
        // A `qid` that names no open stream is a protocol error → FAILURE
        // `Neo.ClientError.Request.Invalid` → FAILED, per the Bolt message spec's `qid` semantics
        // and the reference server (`StreamingStateTransition` throws when the id resolves to no
        // live statement).
        let Some(index) = self.stream_index_for(qid) else {
            if self.open_streams.is_empty() {
                // Should not happen (only reachable in a streaming state), but be defensive.
                self.fail_protocol("PULL/DISCARD with no open result")?;
            } else {
                self.fail_protocol("PULL/DISCARD qid does not match an open result stream")?;
            }
            return Ok(Flow::Continue);
        };
        // Detached for the duration of the stream loop (the emit path needs `&mut self`), then put
        // back at the SAME position if rows remain, so the opening order — which is what `-1` and the
        // "other streams open" rule are defined against — is preserved.
        let mut entry = self.open_streams.remove(index);

        let unlimited = n == ALL;
        let mut produced: i64 = 0;
        let drained = loop {
            if !unlimited && produced >= n {
                break false; // hit the fetch-size limit; whether rows remain is checked below
            }
            match entry.result.next_record() {
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
            match entry.result.has_more() {
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
            self.open_streams.insert(index, entry);
            debug_assert!(self.state.is_streaming());
        } else {
            // Exhausted (either the stream drained, or the limit landed exactly on the last record):
            // trailing SUCCESS with the summary. This stream is closed — `entry` is dropped here, so
            // its `qid` no longer addresses anything (rmp #391).
            let summary = entry.result.stream.summary();
            self.send(&Response::Success {
                metadata: summary_metadata(&summary, false),
            })?;
            drop(entry);
            // Back to (TX_)READY only when NO stream is left open. The Bolt server-state spec's
            // PULL/DISCARD tables give the post-stream state as "TX_READY **or TX_STREAMING if there
            // are other streams open**" (Tables 7 and 8), so consuming one of several results inside
            // a transaction keeps the connection streaming (rmp #907).
            if self.open_streams.is_empty() {
                self.state = self.state.ready_after_stream();
            }
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
    /// returns to `READY` (`04 §8.1`) — for an **authenticated** connection. Returns [`Flow::Stop`]
    /// (terminal) when the connection has never authenticated (defense in depth for rmp #820).
    fn handle_reset(&mut self) -> BoltResult<Flow> {
        // Defense in depth (rmp #820): RESET must never resurrect an UNAUTHENTICATED connection to
        // READY. A legitimate client only ever RESETs an authenticated session (the principal is
        // `Some`); a `None` principal here means the connection reached a RESET-handling path without
        // a successful LOGON, and READY with a `None` principal runs unrestricted at the engine seam.
        // Make it terminal instead. (The primary fix already turns every pre-auth failure into
        // DEFUNCT outright, so this is a backstop against any residual/future path, not the main
        // guard.) A legitimate flow is never affected — a post-auth RESET always has `principal`
        // `Some` and takes the normal recovery path below.
        if self.principal.is_none() {
            self.executor.rollback_open_tx();
            self.close_all_streams();
            self.next_qid = 0;
            self.send_failure(Failure::new(
                "Neo.ClientError.Request.Invalid",
                "RESET is not valid before authentication",
            ))?;
            self.state = State::Defunct;
            return Ok(Flow::Stop);
        }
        // RESET forces the connection back to a clean READY "as if HELLO/LOGON had just completed"
        // (`04 §8.1`, Bolt RESET spec), so any in-flight transaction MUST be aborted. Roll back
        // whatever transaction the executor actually holds, UNCONDITIONALLY — do NOT gate on the
        // Bolt state enum: a statement failure inside a transaction has already moved the enum to
        // `State::Failed` (via `fail_with`), erasing the `TxReady`/`TxStreaming` marker. Gating on
        // the enum (the old bug, rmp #613) skipped the rollback in exactly that case, leaking the
        // executor's open transaction and poisoning the pooled connection — the next `BEGIN` then
        // failed with "a transaction is already open". `rollback_open_tx` consults the executor's
        // own `current_tx`, is a no-op when nothing is open, and is idempotent and infallible, so it
        // is safe on every RESET (clean `TxReady`/`TxStreaming`, post-failure `Failed`, or plain
        // `Ready`).
        self.executor.rollback_open_tx();
        // RESET discards EVERY open result stream, not just the one being streamed: the connection
        // must come back "as if HELLO/LOGON had just successfully completed", and a freshly
        // authenticated connection has no open results at all (rmp #907 generalises the single-slot
        // clear this used to do).
        self.close_all_streams();
        self.next_qid = 0;
        self.send(&Response::Success { metadata: vec![] })?;
        self.state = State::Ready;
        Ok(Flow::Continue)
    }

    /// Drops **every** open result stream and forgets the `qid` they were addressed by.
    ///
    /// Used on `RESET` and on every failure path. Dropping a stream releases whatever the executor
    /// attached to it (for the engine seam: the admission permit and the result channel), so no
    /// stream is ever orphaned when a transaction is abandoned — with several open at once that
    /// matters more than it did with one (rmp #907).
    fn close_all_streams(&mut self) {
        self.open_streams.clear();
        self.last_opened_qid = None;
    }

    /// Sends a `FAILURE` for a `GraphusError` and enters [`State::Failed`], dropping **all** open
    /// streams (the fail-then-ignore rule then applies until `RESET`).
    fn fail_with(&mut self, error: &graphus_core::GraphusError) -> BoltResult<()> {
        self.close_all_streams();
        self.send_failure(failure_from_error(error))?;
        self.state = State::Failed;
        Ok(())
    }

    /// Sends a protocol `FAILURE` and enters [`State::Failed`], dropping **all** open streams.
    fn fail_protocol(&mut self, message: &str) -> BoltResult<()> {
        self.close_all_streams();
        self.send_failure(Failure::new("Neo.ClientError.Request.Invalid", message))?;
        self.state = State::Failed;
        Ok(())
    }

    /// Refuses a message whose `extra` map asked for something the server will not silently ignore
    /// (`rmp` #909), replying `FAILURE` and entering the RESET-recoverable [`State::Failed`].
    ///
    /// `message` names the refused request (`"BEGIN"`, `"RUN"`, `"ROUTE"`) so the client can tell
    /// *which* of its messages was rejected. This is only ever reached from a post-authentication
    /// dispatch arm, so the recoverable `FAILED` state is correct: the pre-authentication states
    /// terminate instead (`rmp` #820), and this guard is deliberately placed *after* the state match
    /// so an out-of-order message is still reported as an illegal transition rather than as an
    /// impersonation refusal.
    fn refuse_extra(&mut self, rejection: ExtraRejected, message: &str) -> BoltResult<Flow> {
        match rejection {
            ExtraRejected::Impersonation => self.refuse_impersonation(message)?,
            ExtraRejected::MalformedTxTimeout => self.fail_protocol(&format!(
                "{message} `{TX_TIMEOUT_FIELD}` must be an integer number of milliseconds"
            ))?,
        }
        Ok(Flow::Continue)
    }

    /// Refuses a client's request to run as another principal (`rmp` #909).
    ///
    /// Graphus does not implement impersonation. The only two honest answers are to *enforce* it or
    /// to *refuse* it; accepting the field and running as the connection principal anyway is the one
    /// answer that is unsafe, because `imp_user` exists to **drop** privileges. The standard
    /// middle-tier pattern — one pooled connection authenticated as a service principal, each request
    /// impersonating its end user — would then silently execute every tenant's request with the
    /// service principal's full rights, and the application would have no way to notice.
    ///
    /// ## Why this code
    ///
    /// [`CODE_FORBIDDEN`] (`Neo.ClientError.Security.Forbidden`, documented by Neo4j as "An attempt
    /// was made to perform an unauthorized action"). The reference server answers a rejected
    /// impersonation in the authentication/authorization class as well
    /// (`SimpleImpersonationStateTransition` wraps the realm's `AuthenticationException` into
    /// `AuthenticationStateTransitionException`, which carries that exception's security status).
    /// The alternatives were considered and rejected: `Neo.ClientError.Statement.ArgumentError` is
    /// what Neo4j *Community* happens to raise (`BasicSystemGraphRealm.impersonate` throws
    /// `InvalidArgumentException.unsupportedInCommunity`), but it is indistinguishable from "your
    /// query's arguments are wrong"; [`CODE_UNAUTHORIZED`] means "your credentials were not accepted"
    /// and would make a driver invalidate a perfectly good auth token.
    ///
    /// ## Why it does not leak
    ///
    /// The refusal is **unconditional and identical** for every value: the requested principal is
    /// never looked up, never compared against the connection's own principal, and never echoed. A
    /// client learns only that Graphus refuses impersonation — never whether a principal exists
    /// (`rmp` #812's constant-work property). Impersonating *yourself* is refused on the same terms:
    /// the reference server also treats it as an impersonation
    /// (`if (message.impersonatedUser() != null)`, with no self-check), and a rule whose outcome
    /// depended on matching the connection's principal would make the server's behaviour a function
    /// of a name the client supplied — a needless comparison oracle for no benefit.
    fn refuse_impersonation(&mut self, message: &str) -> BoltResult<()> {
        self.close_all_streams();
        self.send_failure(Failure::new(
            CODE_FORBIDDEN,
            format!(
                "{message} requested impersonation via `{IMP_USER_FIELD}`, which this server does \
                 not support; the statement was NOT run as the connection's own principal"
            ),
        ))?;
        self.state = State::Failed;
        Ok(())
    }

    /// Sends a `FAILURE` for a **pre-authentication** fault and makes the connection TERMINAL
    /// ([`State::Defunct`] + [`Flow::Stop`]), so the message loop flushes the failure and closes the
    /// socket instead of returning to a recoverable state.
    ///
    /// The Bolt server-state spec transitions NEGOTIATION and AUTHENTICATION to DEFUNCT on a failed
    /// HELLO / LOGON (never to the RESET-recoverable FAILED state), and RESET is not a valid message
    /// before authentication (neo4j.com/docs/bolt/current/bolt/server-state/). Using FAILED here was
    /// an authentication bypass: a later RESET reset the connection to READY with a `None` principal,
    /// which the engine seam treats as unrestricted (rmp #820). No transaction can be open before
    /// authentication, so there is nothing to roll back.
    fn fail_terminal(&mut self, failure: Failure) -> BoltResult<Flow> {
        self.close_all_streams();
        self.send_failure(failure)?;
        self.state = State::Defunct;
        Ok(Flow::Stop)
    }

    /// An unexpected request for the current state: an out-of-order message (`04 §8.1`). Before
    /// authentication this is TERMINAL (DEFUNCT); after authentication it is the recoverable FAILED
    /// state (fail-then-ignore-until-RESET).
    fn unexpected(&mut self, request: &Request) -> BoltResult<Flow> {
        let msg = format!(
            "request {} is not valid in state {:?}",
            request_name(request),
            self.state
        );
        // A pre-authentication out-of-order message must not enter the RESET-recoverable FAILED state
        // (which a later RESET could turn into an unauthenticated, `None`-principal, unrestricted
        // READY — rmp #820): NEGOTIATION / AUTHENTICATION transition to DEFUNCT on failure and RESET
        // is not valid pre-auth. After authentication an out-of-order message stays recoverable.
        if matches!(self.state, State::Connected | State::Authentication) {
            return self.fail_terminal(Failure::new("Neo.ClientError.Request.Invalid", msg));
        }
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

        // Per-account failed-`LOGON` throttle (rmp #458/#823), keyed by the attempted `principal`
        // EXACTLY as the REST `/auth/login` throttle keys by the submitted username — so both
        // password-authentication interfaces share ONE per-account lockout and an attacker cannot pick
        // Bolt to sidestep the lockout REST enforces (CWE-307). Consulted BEFORE the Argon2 verify: an
        // account whose failure budget is spent is rejected up front WITHOUT paying the memory-hard KDF
        // (this also blunts the per-account Argon2 CPU-exhaustion vector). A denied attempt returns the
        // SAME `Unauthorized` FAILURE as a wrong password, so — like every pre-auth failure — it is
        // terminal (rmp #820) and reveals nothing about why it was refused.
        if let Some(t) = &self.login_throttle
            && !t.throttle.permit_attempt(principal, t.clock.as_ref())
        {
            return Err(Failure::new(
                CODE_UNAUTHORIZED,
                "too many failed authentication attempts for this account; retry later",
            ));
        }

        // GLOBAL concurrent-verification bound (rmp #824), consulted AFTER the per-account throttle and
        // BEFORE the Argon2 verify: if the process is already at its verification capacity, shed this
        // `LOGON` with a transient FAILURE WITHOUT running the memory-hard KDF, so a username-rotation
        // flood cannot pile unbounded concurrent Argon2 work onto the shared blocking pool. The permit is
        // held across the verify (RAII release on drop) so the in-flight count reflects real KDF work.
        // The shed decision reads only the global in-flight counter — never the principal — so it is
        // byte-identical for a valid vs an invalid username and adds no enumeration oracle (rmp #812).
        let _verify_permit = match &self.verify_limiter {
            Some(limiter) => match limiter.try_acquire() {
                Some(permit) => Some(permit),
                None => {
                    return Err(Failure::new(
                        CODE_SERVER_BUSY,
                        "server is busy verifying credentials; retry shortly",
                    ));
                }
            },
            None => None,
        };

        match self.auth.authenticate_password(principal, credentials) {
            Ok(user) => Ok(user),
            Err(_) => {
                // Debit this account's failure bucket (rmp #458/#823): the Nth failure within the
                // window empties it, so `permit_attempt` rejects the next attempt for this principal —
                // across reconnects — before the KDF. A *correct* credential never reaches here, so a
                // successful auth never debits (mirrors the REST endpoint: success is never throttled).
                if let Some(t) = &self.login_throttle {
                    t.throttle.note_failure(principal, t.clock.as_ref());
                }
                Err(Failure::new(CODE_UNAUTHORIZED, "authentication failed"))
            }
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

/// The `extra` field naming the principal a client wants to run as (`04 §8.4`; Bolt `BEGIN`, `RUN`
/// and `ROUTE`). Graphus refuses it — see [`BoltSession::refuse_impersonation`] (`rmp` #909).
const IMP_USER_FIELD: &str = "imp_user";

/// The `extra` field carrying the client's transaction timeout **in milliseconds** (Bolt `BEGIN` and
/// auto-commit `RUN`). See [`tx_timeout_from_extra`] (`rmp` #909).
const TX_TIMEOUT_FIELD: &str = "tx_timeout";

/// The client-controlled fields Graphus reads from a **transaction-initiating** `extra` map — the
/// map carried by `BEGIN` and by `RUN` (`04 §8.1`; Neo4j's `AbstractTransactionInitiatingMessage`).
///
/// It exists so that reading the map is **one operation, validated once** (`rmp` #909). Previously
/// each dispatch arm picked out `mode` and `db` with its own helper, and every other field the client
/// sent — including `imp_user` and `tx_timeout`, both of which change what the client believes the
/// server is doing — was silently discarded. Making [`parse_tx_extra`] the only constructor means a
/// new dispatch arm cannot obtain `db`/`mode` without also submitting to the validation: forgetting a
/// field is a compile-time impossibility rather than a silent security regression.
struct TxExtra {
    /// The `mode` field: `"r"` = read, anything else / absent = write (Bolt's default, `06 §4`).
    mode: AccessMode,
    /// The `db` field (Bolt 5.x database targeting). An absent or **empty** value means "the default
    /// database" and is normalised to `None` (drivers send `""` or omit the field for the home
    /// database), exactly as the reference decoder does
    /// (`TransactionInitiatingMetadataParser.readDatabaseName`: "we permit both empty strings and
    /// null values as a reference to the default … database, so we'll unify it at decoder level").
    db: Option<String>,
    /// The normalised `tx_timeout` (`rmp` #909): `None` when the client imposed no bound of its own.
    timeout: Option<Duration>,
}

/// Why a client's `extra` map was refused before the message it belongs to ran (`rmp` #909).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ExtraRejected {
    /// The map carries `imp_user`: the client asked the server to act as a different principal.
    Impersonation,
    /// The map carries a `tx_timeout` that is not an integer.
    MalformedTxTimeout,
}

/// Reads and validates a transaction-initiating `extra` map (`BEGIN` / `RUN`).
///
/// # Errors
/// [`ExtraRejected`] when the map asks for something the server will not silently ignore.
fn parse_tx_extra(extra: &[(String, Value)]) -> Result<TxExtra, ExtraRejected> {
    if impersonation_requested(extra) {
        return Err(ExtraRejected::Impersonation);
    }
    Ok(TxExtra {
        mode: match map_str(extra, "mode") {
            Some("r") => AccessMode::Read,
            _ => AccessMode::Write,
        },
        db: db_from_extra(extra),
        timeout: tx_timeout_from_extra(extra)?,
    })
}

/// Reads and validates a `ROUTE` `extra` map, yielding the requested `db`.
///
/// `ROUTE`'s `extra` is a *routing-context* map, not a transaction-initiating one: the reference
/// decoder (`RouteMessageDecoder`) reads exactly `db` and `imp_user` from it, and `tx_timeout` is not
/// defined for `ROUTE`. So this validates the impersonation field only — refusing an undefined field
/// the specification does not give `ROUTE` would be over-strict, not more conformant.
///
/// # Errors
/// [`ExtraRejected::Impersonation`] when the map carries `imp_user`.
fn parse_route_extra(extra: &[(String, Value)]) -> Result<Option<String>, ExtraRejected> {
    if impersonation_requested(extra) {
        return Err(ExtraRejected::Impersonation);
    }
    Ok(db_from_extra(extra))
}

/// Whether an `extra` map asks the server to run as another principal (`rmp` #909).
///
/// The test is **presence of a non-null value**, not "a non-empty string", and that is deliberate:
///
/// * It mirrors the reference server, which gates on `message.impersonatedUser() != null`
///   (`CreateTransactionStateTransition`, `CreateAutocommitStatementStateTransition`,
///   `SimpleImpersonationStateTransition`) after a decode that — unlike `db` — does **not** fold the
///   empty string into "absent" (`TransactionInitiatingMetadataParser.readImpersonatedUser`).
/// * It cannot be bypassed by type confusion. Were this a `map_str` lookup, `imp_user` sent as an
///   integer, a list, or a map would read as absent and the request would run as the connection
///   principal — reintroducing the very defect this closes. Any present, non-null value is treated
///   as an impersonation request and refused.
/// * A `Value::Null` is treated as absent, matching the reference decoder's
///   `asNullableStringValue`, which yields `null` for a null value.
///
/// No official driver sends an empty `imp_user`: they guard the field on the impersonated user being
/// set (the JavaScript driver's `buildTxMetadata`/`routeV4x4` emit `imp_user` only
/// `if (impersonatedUser)`), so the strictness costs no interoperability.
fn impersonation_requested(extra: &[(String, Value)]) -> bool {
    extra
        .iter()
        .any(|(key, value)| key == IMP_USER_FIELD && !matches!(value, Value::Null))
}

/// Reads the `db` field from an `extra` map, normalising absent/empty to `None`.
fn db_from_extra(extra: &[(String, Value)]) -> Option<String> {
    map_str(extra, "db")
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
}

/// Reads the client's `tx_timeout` (milliseconds) from an `extra` map (`rmp` #909).
///
/// Semantics, matching the reference server:
///
/// * **Absent or null** → `None`: no client-imposed bound.
/// * **A strictly positive integer** → `Some(duration)`: the client's own ceiling. The server clamps
///   it downward against its configured bounds; it can only shorten them, never extend them.
/// * **Zero or negative** → `None`. Neo4j documents `Duration.ZERO` as "transaction does not have a
///   timeout" (`TransactionTimeout`), and its expiry sweep gates on `timeoutNanos > 0`
///   (`TransactionMonitor.checkExpiredTransaction`), so a non-positive value is simply "no
///   client-imposed timeout" — never an error, and never a way to run unbounded, because the
///   server's own bounds still apply unchanged. (The official drivers reject a negative timeout
///   client-side, so only a hand-rolled client can send one.)
/// * **Any other type** → refused. The reference decoder raises `Illegal value for field
///   "tx_timeout": Expected long`; accepting it silently would be exactly the "the client believes it
///   has a lever it does not have" defect this closes.
///
/// # Errors
/// [`ExtraRejected::MalformedTxTimeout`] when the field is present with a non-integer, non-null value.
fn tx_timeout_from_extra(extra: &[(String, Value)]) -> Result<Option<Duration>, ExtraRejected> {
    let Some((_, value)) = extra.iter().find(|(k, _)| k == TX_TIMEOUT_FIELD) else {
        return Ok(None);
    };
    match value {
        Value::Null => Ok(None),
        // `> 0` makes `unsigned_abs` exactly the value: an i64 millisecond count always fits a u64.
        Value::Integer(ms) if *ms > 0 => Ok(Some(Duration::from_millis(ms.unsigned_abs()))),
        Value::Integer(_) => Ok(None),
        _ => Err(ExtraRejected::MalformedTxTimeout),
    }
}

/// Builds the Bolt **5.0** authentication token from a `HELLO` `extra` map: every entry that is not
/// one of the reserved [`HELLO_NON_AUTH_FIELDS`] (rmp #906).
///
/// The whole-map-minus-reserved-fields rule is the Neo4j reference server's
/// (`AuthenticationMetadataUtils.extractAuthToken`, driven by `HelloMessageDecoderV41`'s field list),
/// and it is what lets an unmodified stock driver authenticate at 5.0: it puts `scheme`, `principal`
/// and `credentials` — plus any realm/custom-scheme entries — straight into the `HELLO` `extra`
/// alongside the protocol fields. The result is fed to [`BoltSession::authenticate`], which is the
/// same function the 5.1+ `LOGON` uses, so the two paths validate the token identically.
///
/// SECURITY: the map is consumed and filtered **in place** (`Vec::retain`) rather than cloned. A
/// clone would keep the decoded `HELLO` map and a near-copy of it alive at the same time across the
/// memory-hard KDF that follows, inflating the peak heap an *unauthenticated* peer can pin per
/// connection and eroding the `rmp` #550 pre-authentication decode budget. Measured at the decode
/// budget's ceiling, the cloning form cost ~1.55× the `LOGON` path's peak for the same attacker byte
/// budget; filtering in place restores parity.
fn hello_auth_token(mut extra: Vec<(String, Value)>) -> Vec<(String, Value)> {
    extra.retain(|(k, _)| !HELLO_NON_AUTH_FIELDS.contains(&k.as_str()));
    extra
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
    // The query plan of an `EXPLAIN` / `PROFILE` statement (`rmp` task #752), under exactly one of the two
    // mutually-exclusive keys Neo4j uses — `plan` (not executed: estimates) or `profile` (executed: measured
    // rows + dbHits). An ordinary statement carries neither key.
    if let Some(plan) = &summary.plan {
        meta.push((plan.metadata_key().to_owned(), plan.description.clone()));
    }
    // The transaction bookmark (`rmp` task #807). The Bolt spec lists `bookmark::String` in the
    // `SUCCESS` response to `COMMIT` and in the terminal (`has_more == false`) `SUCCESS` of an
    // **auto-commit** `PULL` — "the bookmark after committing this transaction". The executor sets it
    // in the [`QuerySummary`](crate::executor::QuerySummary) only when a transaction actually committed
    // a durable write, so it is present here on exactly those two messages (this builder is called for
    // the trailing `COMMIT`/`PULL` `SUCCESS` only — a `has_more:true` page and a `RUN` `SUCCESS` build
    // their metadata elsewhere and never carry it, and a `ROLLBACK` mints no bookmark). The token is
    // opaque and monotonic-per-database; the server serialises it verbatim.
    if let Some(bookmark) = &summary.bookmark {
        meta.push(("bookmark".to_owned(), Value::String(bookmark.clone())));
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
