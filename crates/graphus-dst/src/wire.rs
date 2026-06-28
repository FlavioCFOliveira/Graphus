//! `wire` — virtual clients that speak the **real** wire protocols over the simulated network
//! (rmp #163; `04-technical-design.md` §11). This is the "connect every way" half of the VOPR: the
//! genuine Bolt state machine + PackStream codec run over a [`graphus_sim::SimNet`] byte pipe, against
//! the deterministic [`LocalEngine`]. No OS sockets, fully reproducible.
//!
//! ## Bolt: a scripted client driving a real `BoltSession`
//!
//! `BoltSession::run` is a *blocking* loop (read request → execute → write response). In a
//! single-threaded simulator there is no second thread to react to responses, so a client is
//! **byte-scripted**: it encodes a fixed sequence of requests (handshake + messages) with the crate's
//! own client encoders, the network delivers them, then the real session consumes them end to end and
//! writes its responses back. This is exactly the shape sprint 3's *misbehaved* clients need (a
//! crafted, possibly malformed, byte script), and it still exercises the entire real stack: handshake,
//! framing, PackStream, message dispatch, the `BoltExecutor` seam, and the engine.

use std::cell::RefCell;
use std::rc::Rc;
use std::sync::Arc;

use graphus_auth::{AuthProvider, Authenticator, Privilege};
use graphus_bolt::executor::{
    AccessMode as BoltAccessMode, BoltExecutor, QuerySummary, Record, RecordStream, TxControl,
};
use graphus_bolt::server::{BoltSession, encode_client_handshake, encode_request_framed};
use graphus_bolt::{BoltResult, Dechunker, Frame, Proposal, Request, Response, Transport};
use graphus_core::capability::Clock;
use graphus_core::{GraphusError, Value};
use graphus_io::MemBlockDevice;
use graphus_rest::engine::{
    AccessMode as RestAccessMode, RestEngine, ResultStream, Row, RunSummary as RestRunSummary,
    TxHandle, TxOrigin,
};
use graphus_rest::protocol::{RunRequest, Statement};
use graphus_rest::registry::TxRegistry;
use graphus_rest::router::{AppState, DEFAULT_TX_TTL_NANOS, execute_autocommit};
use graphus_rest::{CachedResponse, Wire};
use graphus_server::engine::bolt_values::materialized_to_bolt;
use graphus_server::engine::command::AccessMode as EngineAccessMode;
use graphus_server::engine::rest_values::materialized_to_rest;
use graphus_server::engine::{LocalEngine, RunReply, TxTicket};
use graphus_sim::{SharedClock, Side, SimNet, TransportFaultPlan};
use graphus_wal::MemLogSink;

/// The simulated engine, shared (single-threaded `Rc<RefCell<…>>`) so successive client sessions hit
/// the same database — exactly as real connections to one server do.
pub type SharedEngine = Rc<RefCell<LocalEngine<MemBlockDevice, MemLogSink>>>;

/// A [`BoltExecutor`] that runs Cypher through the deterministic [`LocalEngine`]. One instance backs
/// one Bolt connection (the session owns it); the engine is shared across connections.
pub struct LocalBoltExecutor {
    engine: SharedEngine,
    /// The currently-open explicit transaction's ticket (`BEGIN` … `COMMIT`/`ROLLBACK`), if any.
    explicit: Option<TxTicket>,
}

impl LocalBoltExecutor {
    /// Builds an executor over the shared engine.
    #[must_use]
    pub fn new(engine: SharedEngine) -> Self {
        Self {
            engine,
            explicit: None,
        }
    }
}

/// The result stream backing one `RUN`: it owns the engine's self-contained [`RunReply`] (rows are
/// already buffered through the unbounded inline egress), so it yields records without holding any
/// borrow on the engine — the next statement can run immediately.
pub struct LocalRecordStream {
    reply: RunReply,
    summary: QuerySummary,
}

impl RecordStream for LocalRecordStream {
    fn fields(&self) -> &[String] {
        &self.reply.fields
    }

    fn next_record(&mut self) -> Result<Option<Record>, GraphusError> {
        match self.reply.rows.next()? {
            // Map each materialized cell onto the Bolt structural value via the SAME mapping the real
            // server seam uses (`graphus_server::engine::bolt_values`), so packing is byte-identical.
            Some(row) => Ok(Some(row.into_iter().map(materialized_to_bolt).collect())),
            None => Ok(None),
        }
    }

    fn summary(&self) -> QuerySummary {
        self.summary.clone()
    }
}

/// Maps the Bolt access mode onto the engine's neutral access mode.
fn map_mode(mode: BoltAccessMode) -> EngineAccessMode {
    match mode {
        BoltAccessMode::Read => EngineAccessMode::Read,
        BoltAccessMode::Write => EngineAccessMode::Write,
    }
}

impl BoltExecutor for LocalBoltExecutor {
    type Stream = LocalRecordStream;

    fn run(
        &mut self,
        query: &str,
        parameters: Vec<(String, Value)>,
        tx: TxControl,
    ) -> Result<Self::Stream, GraphusError> {
        let mut eng = self.engine.borrow_mut();
        let (ticket, auto_commit) = match tx {
            TxControl::AutoCommit { mode, .. } => (eng.begin_auto_commit(map_mode(mode))?, true),
            TxControl::InExplicit { .. } => {
                let ticket = self.explicit.ok_or_else(|| {
                    GraphusError::Transaction(
                        "RUN in explicit mode with no open transaction".into(),
                    )
                })?;
                (ticket, false)
            }
        };
        let reply = eng.run(ticket, query, parameters, auto_commit, None)?;
        Ok(LocalRecordStream {
            reply,
            summary: QuerySummary::default(),
        })
    }

    fn begin(&mut self, mode: BoltAccessMode, _db: Option<&str>) -> Result<(), GraphusError> {
        let ticket = self.engine.borrow_mut().begin(map_mode(mode))?;
        self.explicit = Some(ticket);
        Ok(())
    }

    fn commit(&mut self) -> Result<QuerySummary, GraphusError> {
        let ticket = self
            .explicit
            .take()
            .ok_or_else(|| GraphusError::Transaction("COMMIT with no open transaction".into()))?;
        self.engine.borrow_mut().commit(ticket)?;
        Ok(QuerySummary::default())
    }

    fn rollback(&mut self) -> Result<(), GraphusError> {
        let ticket = self
            .explicit
            .take()
            .ok_or_else(|| GraphusError::Transaction("ROLLBACK with no open transaction".into()))?;
        self.engine.borrow_mut().rollback(ticket)
    }
}

/// A logical instant far past any per-write latency, used to flush the simulated network so the whole
/// scripted exchange is delivered before/after the (blocking) session runs.
const FLUSH: u64 = 1_000_000_000;

/// Drives one **scripted** Bolt session over the simulated network against `engine`, returning the
/// decoded server responses (in order).
///
/// The `requests` are the messages **after** the handshake (typically `HELLO`, `LOGON`, then
/// `RUN`/`PULL`/`BEGIN`/`COMMIT`/…, ending in `GOODBYE`). The handshake proposing Bolt 5.4 is prepended
/// automatically.
///
/// # Errors
/// [`graphus_bolt::BoltError`] if encoding a request, the simulated transport, or the session itself
/// fails.
pub fn run_scripted_bolt_session(
    engine: SharedEngine,
    seed: u64,
    auth: &dyn AuthProvider,
    requests: &[Request],
) -> BoltResult<Vec<Response>> {
    let net = SimNet::with_seed(seed);
    let link = net.connect();

    // Build the client byte script: a Bolt 5.4 handshake, then each framed request.
    let mut input = encode_client_handshake([
        Proposal::range(5, 4, 4),
        Proposal::exact(0, 0),
        Proposal::exact(0, 0),
        Proposal::exact(0, 0),
    ]);
    for r in requests {
        input.extend_from_slice(&encode_request_framed(r)?);
    }

    // The client sends everything; flush so the whole script is readable by the server side.
    net.endpoint(link, Side::Client).write_all(&input)?;
    net.advance_to(FLUSH);

    // Run the REAL session over the server endpoint against the deterministic engine.
    let server_ep = net.endpoint(link, Side::Server);
    let executor = LocalBoltExecutor::new(engine);
    let mut session = BoltSession::new(server_ep, executor, auth);
    session.run()?;

    // Deliver the server's responses to the client and collect every byte it wrote.
    net.advance_to(FLUSH * 2);
    let mut client = net.endpoint(link, Side::Client);
    let mut written = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        let n = client.read(&mut buf)?;
        if n == 0 {
            break;
        }
        written.extend_from_slice(&buf[..n]);
    }

    Ok(decode_responses(&written))
}

/// Drives a Bolt session over the simulated network from a **raw, possibly malformed** client byte
/// stream (rmp #166), capturing both the session's run result and the decoded responses **without
/// panicking or propagating**. This is the entry point for misbehaved-client testing: feed crafted
/// garbage / protocol violations and assert the server handles them gracefully.
///
/// `raw_input` is the entire client stream (handshake bytes + whatever follows). The first 4 bytes of
/// the server's output (the handshake reply) are returned separately so a test can inspect a version
/// rejection.
#[must_use]
pub fn drive_raw_bolt(
    engine: SharedEngine,
    seed: u64,
    auth: &dyn AuthProvider,
    raw_input: &[u8],
) -> RawBoltOutcome {
    let net = SimNet::with_seed(seed);
    let link = net.connect();
    // A write may legitimately fail if the link is already broken; ignore — we want the server's view.
    let _ = net.endpoint(link, Side::Client).write_all(raw_input);
    net.advance_to(FLUSH);

    let server_ep = net.endpoint(link, Side::Server);
    let executor = LocalBoltExecutor::new(engine);
    let mut session = BoltSession::new(server_ep, executor, auth);
    let run_result = session.run();

    net.advance_to(FLUSH * 2);
    let mut client = net.endpoint(link, Side::Client);
    let mut written = Vec::new();
    let mut buf = [0u8; 4096];
    while let Ok(n) = client.read(&mut buf) {
        if n == 0 {
            break;
        }
        written.extend_from_slice(&buf[..n]);
    }

    let handshake_reply = if written.len() >= 4 {
        Some([written[0], written[1], written[2], written[3]])
    } else {
        None
    };
    RawBoltOutcome {
        run_ok: run_result.is_ok(),
        handshake_reply,
        responses: decode_responses(&written),
    }
}

/// The captured result of a raw/misbehaved Bolt session (see [`drive_raw_bolt`]).
#[derive(Debug)]
pub struct RawBoltOutcome {
    /// Whether `BoltSession::run` returned `Ok` (a clean run) vs `Err` (a transport/protocol error).
    /// Either is acceptable for a misbehaved client — what matters is that it did not **panic**.
    pub run_ok: bool,
    /// The 4-byte handshake reply the server wrote, if any (e.g. `[0,0,0,0]` = version rejected).
    pub handshake_reply: Option<[u8; 4]>,
    /// Any Bolt messages the server managed to write before closing.
    pub responses: Vec<Response>,
}

impl RawBoltOutcome {
    /// Whether the server emitted at least one `FAILURE` message.
    #[must_use]
    pub fn has_failure(&self) -> bool {
        self.responses
            .iter()
            .any(|r| matches!(r, Response::Failure { .. }))
    }
}

/// The captured result of a Bolt session driven across a [`TransportFaultPlan`] (see
/// [`run_bolt_session_with_transport_fault`]). The whole point is that, whatever the fault, the
/// session **terminated** (no hang) and **did not panic** — `run_terminated` is always `true` here, by
/// virtue of having returned at all.
#[derive(Debug)]
pub struct FaultedBoltOutcome {
    /// Whether `BoltSession::run` returned `Ok` (clean close / EOF — e.g. a truncate-then-stall) vs
    /// `Err` (a transport error surfaced — e.g. a mid-message reset). Both are acceptable; what matters
    /// is that exactly one of them happened (the loop terminated, no hang) without a panic.
    pub run_ok: bool,
    /// The decoded server responses written before the session ended.
    pub responses: Vec<Response>,
}

/// Drives a **real** `BoltSession` over the simulated network with a seed-driven
/// [`TransportFaultPlan`] armed on the server's read direction (so the fault lands *inside* the
/// client's `RUN`/`PULL`/`COMMIT` byte stream as the session consumes it), returning the session
/// outcome.
///
/// # Liveness (cannot hang CI)
///
/// The fault is armed *before* delivery, then the network is stepped to quiescence with a **bounded**
/// step loop ([`drive_to_quiescence`]) so that, by the time the (blocking) `BoltSession::run` reads,
/// the server endpoint is already in a terminal state: a `DropInMessage` left the link broken (reads
/// error), a `TruncateThenStall` left it half-closed (reads EOF after the prefix), and a
/// `SlowConsumer` has — after enough bounded steps — delivered every byte. In every case the
/// `SimEndpoint` read is non-blocking and `run()` returns; it can never block the test.
pub fn run_bolt_session_with_transport_fault(
    engine: SharedEngine,
    seed: u64,
    auth: &dyn AuthProvider,
    requests: &[Request],
    fault: TransportFaultPlan,
) -> FaultedBoltOutcome {
    let net = SimNet::with_seed(seed);
    let link = net.connect();

    // Arm the fault on the stream the SERVER reads (the client's writes) before any delivery.
    net.arm_transport_fault(link, Side::Server, fault);

    let mut input = encode_client_handshake([
        Proposal::range(5, 4, 4),
        Proposal::exact(0, 0),
        Proposal::exact(0, 0),
        Proposal::exact(0, 0),
    ]);
    for r in requests {
        // Encoding never fails for well-formed requests; a failure would itself be a clean error, not a
        // panic, so surface it as an empty (but terminated) outcome.
        match encode_request_framed(r) {
            Ok(bytes) => input.extend_from_slice(&bytes),
            Err(_) => {
                return FaultedBoltOutcome {
                    run_ok: false,
                    responses: Vec::new(),
                };
            }
        }
    }

    // A write may fail if a fault has already broken the link at offset 0; ignore — we want the
    // server's view, and the delivery step below establishes the terminal state regardless.
    let _ = net.endpoint(link, Side::Client).write_all(&input);
    drive_to_quiescence(&net, link, Side::Server);

    let server_ep = net.endpoint(link, Side::Server);
    let executor = LocalBoltExecutor::new(engine);
    let mut session = BoltSession::new(server_ep, executor, auth);
    let run_result = session.run();

    // Collect whatever the server managed to write back to the client.
    net.advance_to(FLUSH * 4);
    let mut client = net.endpoint(link, Side::Client);
    let mut written = Vec::new();
    let mut buf = [0u8; 4096];
    while let Ok(n) = client.read(&mut buf) {
        if n == 0 {
            break;
        }
        written.extend_from_slice(&buf[..n]);
    }

    FaultedBoltOutcome {
        run_ok: run_result.is_ok(),
        responses: decode_responses(&written),
    }
}

/// Steps the simulated network in **bounded** unit-time increments until the server's read direction
/// reaches a terminal state — EOF / reset, or no further bytes become readable (everything in flight
/// has been delivered, e.g. a slow consumer has fully drained). The step cap guarantees the loop (and
/// hence any test built on it) terminates: it can never hang.
fn drive_to_quiescence(net: &SimNet, link: graphus_sim::LinkId, server: Side) {
    // A generous-but-finite cap: a slow consumer of 1 byte/step over a multi-KiB handshake+script still
    // drains well inside this bound; everything else terminates far sooner.
    const MAX_STEPS: u64 = 1_000_000;
    let probe = net.endpoint(link, server);
    let mut t = net.now();
    let mut stalled = 0u64;
    for _ in 0..MAX_STEPS {
        let before = probe.readable_len();
        t += 1;
        net.advance_to(t);
        if probe.is_eof() || probe.is_broken() {
            return;
        }
        // No new bytes delivered this step: count consecutive stalls. A short run of stalls is normal
        // under a slow consumer (latency gaps); a long run means delivery is complete.
        if probe.readable_len() == before {
            stalled += 1;
            if stalled > 64 {
                return;
            }
        } else {
            stalled = 0;
        }
    }
}

/// Decodes the server's written byte stream into [`Response`]s: skips the 4-byte handshake reply, then
/// dechunks and decodes each message. Returns an empty vec if the stream is too short to contain a
/// handshake reply (e.g. the session failed before responding).
fn decode_responses(written: &[u8]) -> Vec<Response> {
    if written.len() < 4 {
        return Vec::new();
    }
    let mut d = Dechunker::new();
    d.push(&written[4..]);
    let mut out = Vec::new();
    while let Ok(Some(Frame::Message(payload))) = d.next_frame() {
        match Response::decode(&payload) {
            Ok(resp) => out.push(resp),
            Err(_) => break,
        }
    }
    out
}

/// Builds a real [`Authenticator`] with one password user `sim`/`sim-secret` for the LOGON exchange.
/// Authentication is genuine; engine-level authorization is disabled in the simulator's executor
/// (it passes no privileges), so the user's grants do not gate queries — only login succeeds.
#[must_use]
pub fn sim_auth() -> Authenticator {
    let mut a = Authenticator::new(b"graphus-sim-shared-jwt-secret-32bytes!!")
        .expect("fixture secret is >= 32 bytes");
    a.catalog_mut().create_user("sim").expect("create user");
    a.catalog_mut().create_role("simrole").expect("create role");
    a.catalog_mut()
        .grant_privilege("simrole", Privilege::read_database())
        .expect("grant");
    a.catalog_mut()
        .grant_role("sim", "simrole")
        .expect("grant role");
    a.set_password("sim", "sim-secret").expect("set password");
    a
}

/// Runs a generated [`WorkloadOp`](crate::mix::WorkloadOp) stream over a single scripted Bolt session
/// — proving the shared workload generator (rmp #165) drives the Bolt path, not just the direct
/// engine path. Each op becomes a `RUN` + `PULL`; the session is framed by the login prologue and a
/// `GOODBYE`.
///
/// # Errors
/// [`graphus_bolt::BoltError`] as [`run_scripted_bolt_session`].
pub fn run_bolt_workload(
    engine: SharedEngine,
    seed: u64,
    auth: &dyn AuthProvider,
    ops: &[crate::mix::WorkloadOp],
) -> BoltResult<Vec<Response>> {
    let mut reqs = login_prologue();
    for op in ops {
        let (stmt, params) = op.to_cypher();
        reqs.push(Request::Run {
            query: stmt.to_owned(),
            parameters: params,
            extra: vec![],
        });
        reqs.push(Request::Pull { n: -1, qid: None });
    }
    reqs.push(Request::Goodbye);
    run_scripted_bolt_session(engine, seed, auth, &reqs)
}

/// The standard `HELLO` + `LOGON` prologue for the `sim` user (Bolt 5.x basic auth).
#[must_use]
pub fn login_prologue() -> Vec<Request> {
    vec![
        Request::Hello {
            extra: vec![(
                "user_agent".to_owned(),
                Value::String("graphus-vopr".to_owned()),
            )],
        },
        Request::Logon {
            auth: vec![
                ("scheme".to_owned(), Value::String("basic".to_owned())),
                ("principal".to_owned(), Value::String("sim".to_owned())),
                (
                    "credentials".to_owned(),
                    Value::String("sim-secret".to_owned()),
                ),
            ],
        },
    ]
}

/// Drives a real `BoltSession` under a transport fault **taken from the unified
/// [`FaultScheduler`](crate::vopr_fault::FaultScheduler)** (rmp #462, closing F-DST-4) — the bridge that
/// physically applies a *scheduled, trace-folded* transport plan to a real in-flight Bolt byte stream.
///
/// The pre-#462 state: the `FaultScheduler` plans, budgets and folds transport faults into the canonical
/// trace, but its in-process `LocalEngine` driver has no byte stream to reset, so
/// [`take_transport_plan`](crate::vopr_fault::FaultScheduler::take_transport_plan) was a documented seam
/// with nothing to arm it on. This function closes that seam: it builds a **transport-only** fault
/// budget, fires the scheduler over the run horizon so a transport plan comes due, pulls that plan via
/// `take_transport_plan`, and arms it on the SimNet link the Bolt session reads — so the very plan the
/// scheduler folded into the trace is the one physically injected.
///
/// Returns `(outcome, fired)`: the [`FaultedBoltOutcome`] (the recovery oracle: the Bolt state machine
/// must not panic or hang — `run()` always returns — and an un-acked write must leave no trace) and
/// whether the scheduler actually produced a transport plan to inject (so a test can assert the
/// injection was non-vacuous). The whole thing is a pure function of `master_seed`.
#[must_use]
pub fn run_bolt_session_with_scheduled_transport_fault(
    engine: SharedEngine,
    master_seed: u64,
    auth: &dyn AuthProvider,
    requests: &[Request],
) -> (FaultedBoltOutcome, bool) {
    use crate::vopr_fault::{FaultBudget, FaultScheduler};

    // A transport-only budget guarantees the planned fault is a transport fault (the kind that needs the
    // SimNet byte stream). A generous rate over a short horizon makes at least one come due.
    let budget = FaultBudget::none().with_max_faults(8).with_weights(0, 0, 1);
    let mut scheduler = FaultScheduler::plan(master_seed, budget, 64);

    // Drain the whole horizon so every planned transport fault fires; the disk/clock hooks are no-ops
    // (a transport-only budget never arms them), and `fold` is ignored here (the trace is the VOPR
    // loop's concern; this bridge only needs the resulting plan).
    scheduler.drain_due(u64::MAX, |_plan| true, |_plan| {}, |_tok, _t| {});

    // Pull the scheduler's most-recently-planned transport plan. If the budget produced one, arm it on a
    // real Bolt session; otherwise fall back to an inert plan so the session still runs cleanly (the
    // `fired` flag tells the caller which happened).
    match scheduler.take_transport_plan() {
        Some(plan) => (
            run_bolt_session_with_transport_fault(engine, master_seed, auth, requests, plan),
            true,
        ),
        None => (
            run_bolt_session_with_transport_fault(
                engine,
                master_seed,
                auth,
                requests,
                TransportFaultPlan::new(master_seed),
            ),
            false,
        ),
    }
}

// =================================== REST wire client (rmp #164) ================================

/// A [`RestEngine`] over the deterministic [`LocalEngine`] — the REST analogue of
/// [`LocalBoltExecutor`]. It is **not** `Send` (the engine is single-threaded), which is exactly why
/// the REST router relaxed its `Send + Sync` bound onto the router function (rmp #164): the simulator
/// reuses the router's synchronous request core (`graphus_rest::router::execute_autocommit`) without
/// the async axum surface.
pub struct SimRestEngine {
    engine: SharedEngine,
}

impl SimRestEngine {
    /// Builds a REST engine over the shared deterministic engine.
    #[must_use]
    pub fn new(engine: SharedEngine) -> Self {
        Self { engine }
    }
}

/// The REST result stream: owns the engine's self-contained [`RunReply`] and maps cells to
/// [`graphus_rest`]'s `RestValue` via the SAME mapping the real server seam uses.
pub struct SimRestStream {
    reply: RunReply,
    summary: RestRunSummary,
}

impl ResultStream for SimRestStream {
    fn fields(&self) -> &[String] {
        &self.reply.fields
    }

    fn next_row(&mut self) -> Result<Option<Row>, GraphusError> {
        match self.reply.rows.next()? {
            Some(row) => Ok(Some(row.into_iter().map(materialized_to_rest).collect())),
            None => Ok(None),
        }
    }

    fn summary(&self) -> RestRunSummary {
        self.summary.clone()
    }
}

/// Maps the REST access mode onto the engine's neutral access mode.
fn map_rest_mode(mode: RestAccessMode) -> EngineAccessMode {
    match mode {
        RestAccessMode::Read => EngineAccessMode::Read,
        RestAccessMode::Write => EngineAccessMode::Write,
    }
}

impl RestEngine for SimRestEngine {
    type Stream = SimRestStream;

    fn begin(
        &self,
        _db: &str,
        mode: RestAccessMode,
        _origin: TxOrigin<'_>,
    ) -> Result<TxHandle, GraphusError> {
        // An explicit transaction (the auto-commit core does begin → run → commit itself).
        let ticket = self.engine.borrow_mut().begin(map_rest_mode(mode))?;
        Ok(TxHandle(ticket.0))
    }

    fn run(
        &self,
        tx: TxHandle,
        query: &str,
        parameters: Vec<(String, Value)>,
    ) -> Result<Self::Stream, GraphusError> {
        let reply = self
            .engine
            .borrow_mut()
            .run(TxTicket(tx.0), query, parameters, false, None)?;
        Ok(SimRestStream {
            reply,
            summary: RestRunSummary::default(),
        })
    }

    fn commit(&self, tx: TxHandle) -> Result<RestRunSummary, GraphusError> {
        self.engine.borrow_mut().commit(TxTicket(tx.0))?;
        Ok(RestRunSummary::default())
    }

    fn rollback(&self, tx: TxHandle) -> Result<(), GraphusError> {
        self.engine.borrow_mut().rollback(TxTicket(tx.0))
    }
}

/// Drives one **auto-commit REST request** (a statement batch) through the REAL REST request core
/// against `engine`, returning the serialized response (status + content-type + JSON body bytes).
///
/// This is the third connection method in the deterministic harness: it exercises the genuine REST
/// statement binding, transaction lifecycle and result serialization (`execute_autocommit`), without
/// the axum/hyper socket layer. `write` selects the transaction access mode.
#[must_use]
pub fn run_rest_autocommit(
    engine: SharedEngine,
    statements: &[Statement],
    write: bool,
) -> CachedResponse {
    // `AppState::new` stores the engine as `Arc<E>`, so an `Arc` is required even though our engine is
    // intentionally `!Send` (single-threaded determinism); it never crosses a thread.
    #[allow(clippy::arc_with_non_send_sync)]
    let sim_engine = Arc::new(SimRestEngine::new(engine));
    let auth: Arc<dyn AuthProvider> = Arc::new(sim_auth());
    let registry = Arc::new(TxRegistry::new(DEFAULT_TX_TTL_NANOS));
    let clock: Arc<dyn Clock + Send + Sync> = Arc::new(SharedClock::new(0));
    let state = AppState::new(sim_engine, auth, registry, clock);
    let mode = if write {
        RestAccessMode::Write
    } else {
        RestAccessMode::Read
    };
    execute_autocommit(&state, "neo4j", "sim", mode, Wire::Json, statements)
}

/// The captured result of a REST request driven across a [`TransportFaultPlan`] (see
/// [`run_rest_with_transport_fault`]).
///
/// The REST byte transport in the simulator is the [`SimNet`] stream carrying the **JSON request
/// body**; the request "core" is the body parse (`serde_json` into a [`RunRequest`]) followed by
/// [`execute_autocommit`]. A transport fault therefore corrupts/cuts the body *before* it reaches the
/// core, exactly as a real truncated/reset HTTP body would — and the core never sees a half-message.
#[derive(Debug)]
pub struct RestTransportOutcome {
    /// Whether the full request body arrived and parsed into a valid [`RunRequest`]. `false` for a
    /// truncated body (partial JSON) or a reset stream — in which case the engine is **never invoked**.
    pub request_complete: bool,
    /// The REST response, present only when `request_complete` (the core ran). A clean session yields
    /// `Some(200…)`; a faulted/truncated request yields `None` (no core run, no mutation).
    pub response: Option<CachedResponse>,
}

/// Drives a REST auto-commit request across a seed-driven [`TransportFaultPlan`]: the JSON request
/// body is sent over a [`SimNet`] stream with the fault armed, then the (possibly truncated/reset)
/// bytes are read on the server side and only a **complete, well-formed** body is handed to the real
/// request core ([`execute_autocommit`]).
///
/// This is the REST analogue of [`run_bolt_session_with_transport_fault`] and upholds the same
/// guarantees: no panic, no hang (the byte read is non-blocking and the stream is driven to a terminal
/// state with a bounded loop), a clean error / no-op on a faulted request, and **ACID preserved** — a
/// truncated or reset request never reaches the engine, so it leaves no trace.
#[must_use]
pub fn run_rest_with_transport_fault(
    engine: SharedEngine,
    seed: u64,
    statements: &[Statement],
    write: bool,
    fault: TransportFaultPlan,
) -> RestTransportOutcome {
    // Build the JSON request body the client would POST.
    let body = rest_request_body(statements, write);

    let net = SimNet::with_seed(seed);
    let link = net.connect();
    net.arm_transport_fault(link, Side::Server, fault);
    let _ = net.endpoint(link, Side::Client).write_all(body.as_bytes());
    drive_to_quiescence(&net, link, Side::Server);

    // Read the server-side bytes that actually arrived (a non-blocking, bounded drain).
    let mut server = net.endpoint(link, Side::Server);
    let mut received = Vec::new();
    let mut buf = [0u8; 4096];
    let mut reset = false;
    loop {
        match server.read(&mut buf) {
            Ok(0) => break, // EOF (clean close or truncate-then-stall) — stop.
            Ok(n) => received.extend_from_slice(&buf[..n]),
            Err(_) => {
                reset = true; // a mid-message reset surfaced
                break;
            }
        }
    }

    // Only a complete, well-formed body reaches the core. A truncated body fails to parse (partial
    // JSON); a reset stream is incomplete. Either way the engine is never touched.
    if reset {
        return RestTransportOutcome {
            request_complete: false,
            response: None,
        };
    }
    match serde_json::from_slice::<RunRequest>(&received) {
        Ok(req) if received.len() == body.len() => {
            // The whole body arrived and parsed: run the real core.
            let resp = run_rest_autocommit(engine, &req.statements, write);
            RestTransportOutcome {
                request_complete: true,
                response: Some(resp),
            }
        }
        _ => RestTransportOutcome {
            request_complete: false,
            response: None,
        },
    }
}

/// Serializes a REST auto-commit request body (the JSON a client would POST) for a batch of
/// statements and an access mode.
fn rest_request_body(statements: &[Statement], write: bool) -> String {
    let stmts: Vec<serde_json::Value> = statements
        .iter()
        .map(|s| serde_json::json!({ "statement": s.statement }))
        .collect();
    serde_json::json!({
        "statements": stmts,
        "access_mode": if write { "WRITE" } else { "READ" },
    })
    .to_string()
}

/// Builds a single-statement REST batch with no inline parameters (parameters can be embedded as
/// literals in `cypher`).
#[must_use]
pub fn rest_statement(cypher: &str) -> Statement {
    Statement {
        statement: cypher.to_owned(),
        parameters: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn engine() -> SharedEngine {
        let clock = Arc::new(SharedClock::new(0));
        Rc::new(RefCell::new(
            LocalEngine::in_memory(clock, 256).expect("build engine"),
        ))
    }

    /// A full real Bolt session over the simulated network: handshake → HELLO → LOGON → auto-commit
    /// CREATE → MATCH the node back, asserting the engine's data arrives as a proper Bolt RECORD.
    #[test]
    fn bolt_session_over_simnet_round_trips_engine_data() {
        let eng = engine();
        let mut reqs = login_prologue();
        reqs.extend([
            Request::Run {
                query: "CREATE (:Person {name: 'Ada'})".to_owned(),
                parameters: vec![],
                extra: vec![],
            },
            Request::Pull { n: -1, qid: None },
            Request::Run {
                query: "MATCH (p:Person) RETURN p.name AS name".to_owned(),
                parameters: vec![],
                extra: vec![],
            },
            Request::Pull { n: -1, qid: None },
            Request::Goodbye,
        ]);

        let auth = sim_auth();
        let responses = run_scripted_bolt_session(eng, 7, &auth, &reqs).expect("session runs");

        // HELLO+LOGON succeed, both RUNs succeed, and a RECORD carries the created name.
        assert!(
            responses.len() >= 6,
            "expected handshake + run/pull responses, got {responses:?}"
        );
        let has_ada = responses.iter().any(|r| match r {
            Response::Record { values } => values.iter().any(|v| format!("{v:?}").contains("Ada")),
            _ => false,
        });
        assert!(
            has_ada,
            "the MATCH returns the created node over Bolt: {responses:?}"
        );
        // No FAILURE responses in a clean session.
        assert!(
            !responses
                .iter()
                .any(|r| matches!(r, Response::Failure { .. })),
            "clean session has no FAILURE: {responses:?}"
        );
    }

    /// The same script over the same seed yields byte-identical decoded responses (determinism).
    #[test]
    fn bolt_session_is_deterministic() {
        let run = || {
            let eng = engine();
            let mut reqs = login_prologue();
            reqs.extend([
                Request::Run {
                    query: "CREATE (:N {v: 1}) RETURN 1 AS one".to_owned(),
                    parameters: vec![],
                    extra: vec![],
                },
                Request::Pull { n: -1, qid: None },
                Request::Goodbye,
            ]);
            let auth = sim_auth();
            let responses = run_scripted_bolt_session(eng, 42, &auth, &reqs).expect("runs");
            format!("{responses:?}")
        };
        assert_eq!(
            run(),
            run(),
            "same seed + script ⇒ identical Bolt responses"
        );
    }

    /// An explicit transaction that rolls back leaves no data visible to a later auto-commit read.
    #[test]
    fn bolt_explicit_rollback_is_not_visible() {
        let eng = engine();
        let mut reqs = login_prologue();
        reqs.extend([
            Request::Begin { extra: vec![] },
            Request::Run {
                query: "CREATE (:Temp {x: 1})".to_owned(),
                parameters: vec![],
                extra: vec![],
            },
            Request::Pull { n: -1, qid: None },
            Request::Rollback,
            Request::Run {
                query: "MATCH (t:Temp) RETURN t".to_owned(),
                parameters: vec![],
                extra: vec![],
            },
            Request::Pull { n: -1, qid: None },
            Request::Goodbye,
        ]);
        let auth = sim_auth();
        let responses = run_scripted_bolt_session(eng, 1, &auth, &reqs).expect("runs");
        // The post-rollback MATCH yields no RECORD carrying a Temp node.
        let temp_records = responses
            .iter()
            .filter(|r| matches!(r, Response::Record { .. }))
            .count();
        assert_eq!(
            temp_records, 0,
            "rolled-back node is invisible: {responses:?}"
        );
    }

    /// A REST auto-commit request over the real request core: create a node, then read it back, and
    /// confirm the JSON response (status 200) carries the data — the third connection method, fully
    /// deterministic.
    #[test]
    fn rest_autocommit_round_trips_engine_data() {
        let eng = engine();

        let create = run_rest_autocommit(
            eng.clone(),
            &[rest_statement("CREATE (:City {name: 'Lisbon'})")],
            true,
        );
        assert_eq!(create.status, 200, "create succeeds: {create:?}");

        let read = run_rest_autocommit(
            eng.clone(),
            &[rest_statement("MATCH (c:City) RETURN c.name AS name")],
            false,
        );
        assert_eq!(read.status, 200, "read succeeds: {read:?}");
        let body = String::from_utf8_lossy(&read.body);
        assert!(
            body.contains("Lisbon"),
            "REST JSON carries the created node: {body}"
        );
    }

    /// The same REST request replays byte-identically from the same engine state (determinism).
    #[test]
    fn rest_autocommit_is_deterministic() {
        let run = || {
            let eng = engine();
            let resp = run_rest_autocommit(
                eng,
                &[rest_statement("CREATE (:N {v: 1}) RETURN 1 AS one")],
                true,
            );
            (
                resp.status,
                String::from_utf8_lossy(&resp.body).into_owned(),
            )
        };
        assert_eq!(run(), run(), "same script ⇒ identical REST response");
    }

    /// The shared workload generator drives the Bolt path: generate a write-heavy op stream and run
    /// it over a real Bolt session, asserting it completes with no FAILURE (rmp #165).
    #[test]
    fn generated_workload_drives_bolt_path() {
        use crate::mix::{MixProfile, WorkloadGen};

        let mut rng = graphus_sim::SimRng::new(11);
        let mut wgen = WorkloadGen::new(MixProfile::write_heavy());
        let ops: Vec<_> = (0..20).map(|_| wgen.next(&mut rng)).collect();

        let eng = engine();
        let auth = sim_auth();
        let responses = run_bolt_workload(eng, 11, &auth, &ops).expect("session runs");
        assert!(
            !responses
                .iter()
                .any(|r| matches!(r, Response::Failure { .. })),
            "generated workload runs clean over Bolt: {responses:?}"
        );
        assert!(responses.len() > ops.len(), "each op produced responses");
    }

    /// A compile error comes back as an RFC 9457 problem+json with a 4xx status (no panic).
    #[test]
    fn rest_compile_error_is_problem_json() {
        let eng = engine();
        let resp = run_rest_autocommit(eng, &[rest_statement("THIS IS NOT CYPHER")], true);
        assert!(
            (400..500).contains(&resp.status),
            "a bad statement is a client error, got {}",
            resp.status
        );
        assert!(
            resp.content_type.contains("problem+json") || resp.content_type.contains("json"),
            "error is JSON problem: {}",
            resp.content_type
        );
    }

    // ============================ Transport-fault DST tests (rmp #234) ============================
    //
    // Each test drives a real `BoltSession` (or the REST core) over the simulated network with a
    // seed-driven `TransportFaultPlan` armed mid-message, and asserts the four invariants from the
    // acceptance criteria: NO PANIC (the harness returns at all), NO HANG (liveness — the blocking
    // session loop terminates because the faulted stream reaches a terminal reset/EOF), the correct
    // TRANSPORT ERROR or CLEAN CLOSE, and ACID PRESERVED (an un-acked write leaves no trace; an acked
    // write survives — checked against the shared engine after the fault).

    use graphus_sim::TransportFaultPlan;

    /// Counts `Probe` nodes visible to a fresh, clean Bolt read session against `eng` — the ACID
    /// oracle: a write that was never committed must leave zero, a committed write must survive.
    fn count_probe_nodes(eng: SharedEngine) -> usize {
        let mut reqs = login_prologue();
        reqs.extend([
            Request::Run {
                query: "MATCH (n:Probe) RETURN n.id AS id".to_owned(),
                parameters: vec![],
                extra: vec![],
            },
            Request::Pull { n: -1, qid: None },
            Request::Goodbye,
        ]);
        let auth = sim_auth();
        let responses =
            run_scripted_bolt_session(eng, 999, &auth, &reqs).expect("clean read session runs");
        responses
            .iter()
            .filter(|r| matches!(r, Response::Record { .. }))
            .count()
    }

    /// The script a faulted session attempts: log in, then CREATE a `Probe` node in auto-commit. If the
    /// transport fault cuts the stream before the server reads + commits the CREATE, the node must not
    /// exist (ACID: no partial effect from an un-acked op).
    fn create_probe_script() -> Vec<Request> {
        let mut reqs = login_prologue();
        reqs.extend([
            Request::Run {
                query: "CREATE (:Probe {id: 1})".to_owned(),
                parameters: vec![],
                extra: vec![],
            },
            Request::Pull { n: -1, qid: None },
            Request::Goodbye,
        ]);
        reqs
    }

    /// Bolt + **drop in message**: a mid-message reset must surface as a transport error (or a clean
    /// close), never a panic or a hang, and the un-acked CREATE must leave no `Probe` behind.
    #[test]
    fn bolt_drop_in_message_is_clean_and_atomic() {
        let eng = engine();
        // Drop somewhere inside the first 80 delivered bytes — well inside the handshake/HELLO/LOGON/RUN
        // prologue, so the CREATE is never fully received.
        let fault = TransportFaultPlan::new(0xD1).drop_in_message(80);
        let outcome = run_bolt_session_with_transport_fault(
            eng.clone(),
            7,
            &sim_auth(),
            &create_probe_script(),
            fault,
        );
        // No panic (we got here) and the loop terminated (run() returned, populating `outcome`). A reset
        // is typically an Err, but a boundary-aligned drop could read as a clean EOF — both acceptable;
        // the assertion below (an outcome exists at all) captures "no hang, no panic".
        let _ = outcome.run_ok;
        // ACID: the un-acked CREATE left no trace.
        assert_eq!(
            count_probe_nodes(eng),
            0,
            "a CREATE cut off by a mid-message reset must leave no node"
        );
    }

    /// Bolt + **truncate then stall**: a partial write that stops must read as a clean EOF (the session
    /// loop ends, no hang), and the un-acked CREATE must leave no `Probe`.
    #[test]
    fn bolt_truncate_then_stall_ends_in_eof_and_atomic() {
        let eng = engine();
        let fault = TransportFaultPlan::new(0x7C).truncate_then_stall(80);
        let outcome = run_bolt_session_with_transport_fault(
            eng.clone(),
            11,
            &sim_auth(),
            &create_probe_script(),
            fault,
        );
        // A truncate-then-stall is a half-close: the server reads the prefix then EOFs, so run() returns
        // Ok (clean termination) — never a hang.
        assert!(
            outcome.run_ok,
            "a truncated-then-stalled stream reads as a clean EOF, run() returns Ok"
        );
        assert_eq!(
            count_probe_nodes(eng),
            0,
            "a CREATE cut off by truncation must leave no node"
        );
    }

    /// Bolt + **slow consumer**: throttled delivery must NOT corrupt the stream — every byte still
    /// arrives, the full script runs, the CREATE commits, and the node survives (ACID: an acked op
    /// persists). This is the liveness-positive case (the session completes despite backpressure).
    #[test]
    fn bolt_slow_consumer_completes_and_persists() {
        let eng = engine();
        let fault = TransportFaultPlan::new(0x5C).slow_consumer(4);
        let outcome = run_bolt_session_with_transport_fault(
            eng.clone(),
            13,
            &sim_auth(),
            &create_probe_script(),
            fault,
        );
        assert!(
            outcome.run_ok,
            "a slow consumer only throttles; the full session completes: {outcome:?}"
        );
        assert!(
            !outcome
                .responses
                .iter()
                .any(|r| matches!(r, Response::Failure { .. })),
            "no FAILURE under mere backpressure: {outcome:?}"
        );
        // ACID: the CREATE was fully delivered, committed, and survives.
        assert_eq!(
            count_probe_nodes(eng),
            1,
            "a slow consumer still delivers + commits the CREATE: the node survives"
        );
    }

    /// Determinism: the same seed reproduces the same Bolt fault outcome bit-for-bit.
    #[test]
    fn bolt_transport_fault_is_deterministic() {
        let run = || {
            let eng = engine();
            let outcome = run_bolt_session_with_transport_fault(
                eng.clone(),
                21,
                &sim_auth(),
                &create_probe_script(),
                TransportFaultPlan::new(0xABBA).drop_in_message(96),
            );
            (
                outcome.run_ok,
                format!("{:?}", outcome.responses),
                count_probe_nodes(eng),
            )
        };
        assert_eq!(run(), run(), "same seed ⇒ identical faulted Bolt outcome");
    }

    /// **rmp #462 (F-DST-4 closed).** A transport fault **taken from the unified `FaultScheduler`** is
    /// physically injected into a real in-flight Bolt session, and the recovery oracle holds:
    ///
    /// * **No panic** — control reaches the assertions.
    /// * **No hang** — `run()` returned (the bounded `drive_to_quiescence` guarantees termination).
    /// * **No half-applied / torn transaction** — the CREATE is **atomic**: the `:Probe` node count is
    ///   `0` or `1`, never a partial or duplicated state. A cut stream (`drop`/`truncate`) leaves `0`;
    ///   a `slow_consumer` (which only throttles, delivering everything) legitimately commits `1`. The
    ///   precise atomicity invariant: when the session did **not** run cleanly to a successful response,
    ///   the node is absent (a severed transaction never half-commits).
    ///
    /// Swept over several master seeds so the scheduler genuinely produces and arms transport plans (the
    /// `fired` flag proves the injection is non-vacuous on at least one seed), and replayed for
    /// determinism.
    #[test]
    fn scheduled_transport_fault_is_physically_injected_and_recovers() {
        let mut any_fired = false;
        for seed in [1u64, 7, 13, 21, 42, 99, 256, 1024] {
            let eng = engine();
            let (outcome, fired) = run_bolt_session_with_scheduled_transport_fault(
                eng.clone(),
                seed,
                &sim_auth(),
                &create_probe_script(),
            );
            any_fired |= fired;
            let nodes = count_probe_nodes(eng);
            // Atomicity: never a torn/duplicated state.
            assert!(
                nodes <= 1,
                "seed {seed}: the CREATE must be atomic (0 or 1 node), got {nodes}"
            );
            // A session that produced a committed success may persist the node; a session that did not
            // run cleanly (a mid-message reset) must leave NO node — no half-applied transaction.
            let committed_ok = outcome.run_ok
                && outcome
                    .responses
                    .iter()
                    .any(|r| matches!(r, Response::Success { .. }));
            if !committed_ok {
                assert_eq!(
                    nodes, 0,
                    "seed {seed}: a non-clean session must not half-apply the CREATE"
                );
            }
            // Determinism: same master seed ⇒ identical injection + outcome.
            let eng2 = engine();
            let (outcome2, fired2) = run_bolt_session_with_scheduled_transport_fault(
                eng2.clone(),
                seed,
                &sim_auth(),
                &create_probe_script(),
            );
            assert_eq!(
                fired, fired2,
                "seed {seed}: scheduler injection is deterministic"
            );
            assert_eq!(
                format!("{:?}", outcome.responses),
                format!("{:?}", outcome2.responses),
                "seed {seed}: faulted Bolt outcome replays identically"
            );
        }
        assert!(
            any_fired,
            "the scheduler must physically inject a transport fault on at least one master seed \
             (otherwise the F-DST-4 bridge is vacuous)"
        );
    }

    /// REST + **drop in message**: a reset request body must never reach the engine; the response is
    /// absent (no core run) and the CREATE leaves no `Probe` (ACID).
    #[test]
    fn rest_drop_in_message_never_reaches_engine() {
        let eng = engine();
        let fault = TransportFaultPlan::new(0xD2).drop_in_message(20);
        let outcome = run_rest_with_transport_fault(
            eng.clone(),
            7,
            &[rest_statement("CREATE (:Probe {id: 1})")],
            true,
            fault,
        );
        assert!(
            !outcome.request_complete && outcome.response.is_none(),
            "a reset body never reaches the core: {outcome:?}"
        );
        assert_eq!(
            count_probe_nodes(eng),
            0,
            "a reset REST request leaves no node (ACID)"
        );
    }

    /// REST + **truncate then stall**: a partial body fails to parse (incomplete JSON), so the core
    /// never runs and the CREATE leaves no trace.
    #[test]
    fn rest_truncate_then_stall_never_reaches_engine() {
        let eng = engine();
        let fault = TransportFaultPlan::new(0x7D).truncate_then_stall(20);
        let outcome = run_rest_with_transport_fault(
            eng.clone(),
            11,
            &[rest_statement("CREATE (:Probe {id: 1})")],
            true,
            fault,
        );
        assert!(
            !outcome.request_complete && outcome.response.is_none(),
            "a truncated body is incomplete JSON; the core never runs: {outcome:?}"
        );
        assert_eq!(
            count_probe_nodes(eng),
            0,
            "a truncated REST request leaves no node (ACID)"
        );
    }

    /// REST + **slow consumer**: throttled delivery still delivers the whole body, so the core runs, the
    /// CREATE commits (200), and the node survives (ACID: an acked op persists).
    #[test]
    fn rest_slow_consumer_completes_and_persists() {
        let eng = engine();
        let fault = TransportFaultPlan::new(0x5D).slow_consumer(3);
        let outcome = run_rest_with_transport_fault(
            eng.clone(),
            13,
            &[rest_statement("CREATE (:Probe {id: 1})")],
            true,
            fault,
        );
        assert!(
            outcome.request_complete,
            "a slow consumer still delivers the full body: {outcome:?}"
        );
        let resp = outcome.response.expect("the core ran");
        assert_eq!(resp.status, 200, "the CREATE succeeds: {resp:?}");
        assert_eq!(
            count_probe_nodes(eng),
            1,
            "a slow REST consumer still commits the CREATE: the node survives"
        );
    }

    /// Determinism: the same seed reproduces the same REST fault outcome.
    #[test]
    fn rest_transport_fault_is_deterministic() {
        let run = || {
            let eng = engine();
            let outcome = run_rest_with_transport_fault(
                eng.clone(),
                21,
                &[rest_statement("CREATE (:Probe {id: 1})")],
                true,
                TransportFaultPlan::new(0xCAFE).drop_in_message(24),
            );
            (
                outcome.request_complete,
                outcome.response.map(|r| r.status),
                count_probe_nodes(eng),
            )
        };
        assert_eq!(run(), run(), "same seed ⇒ identical faulted REST outcome");
    }
}
