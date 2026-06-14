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
use graphus_core::capability::Clock;
use graphus_bolt::executor::{
    AccessMode as BoltAccessMode, BoltExecutor, QuerySummary, Record, RecordStream, TxControl,
};
use graphus_bolt::server::{BoltSession, encode_client_handshake, encode_request_framed};
use graphus_bolt::{BoltResult, Dechunker, Frame, Proposal, Request, Response, Transport};
use graphus_core::{GraphusError, Value};
use graphus_io::MemBlockDevice;
use graphus_rest::engine::{
    AccessMode as RestAccessMode, RestEngine, ResultStream, Row, RunSummary as RestRunSummary,
    TxHandle, TxOrigin,
};
use graphus_rest::registry::TxRegistry;
use graphus_rest::router::{AppState, DEFAULT_TX_TTL_NANOS, execute_autocommit};
use graphus_rest::protocol::Statement;
use graphus_rest::{CachedResponse, Wire};
use graphus_server::engine::bolt_values::materialized_to_bolt;
use graphus_server::engine::command::AccessMode as EngineAccessMode;
use graphus_server::engine::rest_values::materialized_to_rest;
use graphus_server::engine::{LocalEngine, RunReply, TxTicket};
use graphus_sim::{SharedClock, Side, SimNet};
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
            Some(row) => Ok(Some(row.iter().map(materialized_to_bolt).collect())),
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
                    GraphusError::Transaction("RUN in explicit mode with no open transaction".into())
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
    a.catalog_mut().grant_role("sim", "simrole").expect("grant role");
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
            extra: vec![("user_agent".to_owned(), Value::String("graphus-vopr".to_owned()))],
        },
        Request::Logon {
            auth: vec![
                ("scheme".to_owned(), Value::String("basic".to_owned())),
                ("principal".to_owned(), Value::String("sim".to_owned())),
                ("credentials".to_owned(), Value::String("sim-secret".to_owned())),
            ],
        },
    ]
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
            Some(row) => Ok(Some(row.iter().map(materialized_to_rest).collect())),
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
        assert!(has_ada, "the MATCH returns the created node over Bolt: {responses:?}");
        // No FAILURE responses in a clean session.
        assert!(
            !responses.iter().any(|r| matches!(r, Response::Failure { .. })),
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
        assert_eq!(run(), run(), "same seed + script ⇒ identical Bolt responses");
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
        assert_eq!(temp_records, 0, "rolled-back node is invisible: {responses:?}");
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
        assert!(body.contains("Lisbon"), "REST JSON carries the created node: {body}");
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
            (resp.status, String::from_utf8_lossy(&resp.body).into_owned())
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
            !responses.iter().any(|r| matches!(r, Response::Failure { .. })),
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
}
