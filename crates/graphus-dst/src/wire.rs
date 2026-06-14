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

use graphus_auth::{AuthProvider, Authenticator, Privilege};
use graphus_bolt::executor::{
    AccessMode as BoltAccessMode, BoltExecutor, QuerySummary, Record, RecordStream, TxControl,
};
use graphus_bolt::server::{BoltSession, encode_client_handshake, encode_request_framed};
use graphus_bolt::{BoltResult, Dechunker, Frame, Proposal, Request, Response, Transport};
use graphus_core::{GraphusError, Value};
use graphus_io::MemBlockDevice;
use graphus_server::engine::bolt_values::materialized_to_bolt;
use graphus_server::engine::command::AccessMode as EngineAccessMode;
use graphus_server::engine::{LocalEngine, RunReply, TxTicket};
use graphus_sim::{Side, SimNet};
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    use graphus_sim::SharedClock;

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
}
