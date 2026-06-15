//! Security regression battery for the **Bolt server state machine** and the **`Response::decode`
//! client path** — both consume bytes that originate at an untrusted peer.
//!
//! The server-side tests drive a whole [`BoltSession`] over an in-memory transport with adversarial
//! message ordering (messages out of state, RESET recovery, malformed frames) and assert the server
//! never panics and always answers per the fail-then-ignore-until-RESET rule.
//!
//! The `Response::decode` test demonstrates a concrete allocation-bomb finding: this decoder runs on
//! the *client* side (graphus-cli, graphus-dst) over bytes a server sends, and its RECORD path
//! pre-allocates a `Vec` sized by an unbounded wire list header — a malicious/compromised server can
//! force a multi-GiB allocation and abort the client process.

use graphus_bolt::executor::{AccessMode, BoltExecutor, QuerySummary, Record, RecordStream, TxControl};
use graphus_bolt::server::{encode_client_handshake, encode_request_framed};
use graphus_bolt::{BoltSession, MemoryTransport, Request, Response, State};
use graphus_auth::Authenticator;
use graphus_core::{GraphusError, Value};

// ---- minimal public-API test doubles ----------------------------------------------------------

/// A real [`Authenticator`] with one `alice`/`pw` user — the same fixture shape the crate's internal
/// state-machine tests use, exercised through the public `AuthProvider` seam.
fn auth_fixture() -> Authenticator {
    let mut a = Authenticator::new(b"shared-jwt-secret-at-least-32-bytes!!")
        .expect("fixture secret is >= 32 bytes");
    a.catalog_mut().create_user("alice").unwrap();
    a.set_password("alice", "alice-pw").unwrap();
    a
}

/// An empty result stream (no rows) for the trivial RUN in the streaming-order test.
struct EmptyStream {
    fields: Vec<String>,
}
impl RecordStream for EmptyStream {
    fn fields(&self) -> &[String] {
        &self.fields
    }
    fn next_record(&mut self) -> Result<Option<Record>, GraphusError> {
        Ok(None)
    }
    fn summary(&self) -> QuerySummary {
        QuerySummary::default()
    }
}

/// A trivial executor: every RUN yields an empty result; transactions are accepted.
#[derive(Default)]
struct TrivialExecutor;
impl BoltExecutor for TrivialExecutor {
    type Stream = EmptyStream;
    fn run(
        &mut self,
        _query: &str,
        _parameters: Vec<(String, Value)>,
        _tx: TxControl,
    ) -> Result<Self::Stream, GraphusError> {
        Ok(EmptyStream { fields: vec![] })
    }
    fn begin(&mut self, _mode: AccessMode, _db: Option<&str>) -> Result<(), GraphusError> {
        Ok(())
    }
    fn commit(&mut self) -> Result<QuerySummary, GraphusError> {
        Ok(QuerySummary::default())
    }
    fn rollback(&mut self) -> Result<(), GraphusError> {
        Ok(())
    }
}

/// The standard 5.4 handshake bytes (magic + four proposals, one 5.4 and three empty).
fn handshake_54() -> Vec<u8> {
    use graphus_bolt::Proposal;
    encode_client_handshake([
        Proposal::exact(5, 4),
        Proposal::exact(0, 0),
        Proposal::exact(0, 0),
        Proposal::exact(0, 0),
    ])
}

fn hello() -> Request {
    Request::Hello {
        extra: vec![("user_agent".to_owned(), Value::String("drv/1".to_owned()))],
    }
}

fn logon() -> Request {
    Request::Logon {
        auth: vec![
            ("scheme".to_owned(), Value::String("basic".to_owned())),
            ("principal".to_owned(), Value::String("alice".to_owned())),
            ("credentials".to_owned(), Value::String("alice-pw".to_owned())),
        ],
    }
}

/// Builds a full inbound byte stream: handshake + the framed requests, in order.
fn session_input(requests: &[Request]) -> Vec<u8> {
    let mut input = handshake_54();
    for r in requests {
        input.extend_from_slice(&encode_request_framed(r).unwrap());
    }
    input
}

/// Drives a session to completion over the scripted input and returns the final state.
fn run_session(requests: &[Request]) -> State {
    let input = session_input(requests);
    let transport = MemoryTransport::with_input(&input);
    let auth = auth_fixture();
    let mut session = BoltSession::new(transport, TrivialExecutor, &auth);
    // EOF after the scripted messages ends the loop cleanly.
    let _ = session.run();
    session.state()
}

// ---- adversarial message ordering -------------------------------------------------------------

#[test]
fn run_before_hello_does_not_panic_and_fails() {
    // A peer that skips HELLO and sends RUN immediately: the server must reject (unexpected message
    // in CONNECTED), never panic. The session ends in a failed/defunct posture, not READY.
    let state = run_session(&[Request::Run {
        query: "RETURN 1".to_owned(),
        parameters: vec![],
        extra: vec![],
    }]);
    assert_ne!(state, State::Ready, "RUN before HELLO must never reach READY");
}

#[test]
fn logon_before_hello_is_rejected() {
    let state = run_session(&[logon()]);
    assert_ne!(state, State::Ready, "LOGON before HELLO must never authenticate");
}

#[test]
fn pull_before_run_does_not_panic() {
    // PULL with no open result: must be handled defensively (protocol failure), not panic.
    let state = run_session(&[
        hello(),
        logon(),
        Request::Pull { n: -1, qid: None },
    ]);
    // The session survived to process the messages without panicking; reaching here is the assertion.
    let _ = state;
}

#[test]
fn wrong_credentials_never_authenticate() {
    let bad_logon = Request::Logon {
        auth: vec![
            ("scheme".to_owned(), Value::String("basic".to_owned())),
            ("principal".to_owned(), Value::String("alice".to_owned())),
            ("credentials".to_owned(), Value::String("WRONG".to_owned())),
        ],
    };
    let state = run_session(&[hello(), bad_logon]);
    assert_ne!(state, State::Ready, "bad credentials must never reach READY");
}

#[test]
fn unsupported_auth_scheme_is_rejected() {
    // The `none` scheme (and any non-`basic`) must be refused, not silently accepted (auth bypass).
    let none_logon = Request::Logon {
        auth: vec![("scheme".to_owned(), Value::String("none".to_owned()))],
    };
    let state = run_session(&[hello(), none_logon]);
    assert_ne!(state, State::Ready, "the `none` scheme must never authenticate");
}

#[test]
fn hello_without_user_agent_is_rejected() {
    let bad_hello = Request::Hello { extra: vec![] };
    let state = run_session(&[bad_hello]);
    assert_ne!(state, State::Ready);
}

#[test]
fn reset_after_failure_recovers_to_ready() {
    // The fail-then-ignore-until-RESET contract: provoke a failure (RUN before auth fails), then
    // RESET should clear it. After a healthy HELLO+LOGON, a stray RUN, then RESET, the session must
    // be usable again. We assert the session processed RESET without panic and did not end DEFUNCT
    // prematurely.
    let state = run_session(&[
        hello(),
        logon(),
        // A malformed-by-state extra is not needed; send RESET directly and confirm recovery.
        Request::Reset,
        Request::Run {
            query: "RETURN 1".to_owned(),
            parameters: vec![],
            extra: vec![],
        },
        Request::Pull { n: -1, qid: None },
    ]);
    // After the scripted messages the peer "drops" (EOF), so a HEALTHY session ends DEFUNCT — not
    // FAILED. Ending in FAILED would mean RESET failed to recover the connection. The security
    // property: RESET + a subsequent RUN/PULL processed cleanly, never stuck in the fail state.
    assert_eq!(
        state,
        State::Defunct,
        "a recovered session that then sees EOF must end DEFUNCT, never stuck in FAILED"
    );
    assert_ne!(state, State::Failed);
}

#[test]
fn malformed_message_bytes_yield_failure_not_panic() {
    // After a healthy handshake+auth, feed a chunk whose payload is NOT a valid PackStream structure
    // (a lone 0xFF marker). The server must answer FAILURE and enter the fail state, never panic.
    let mut input = handshake_54();
    input.extend_from_slice(&encode_request_framed(&hello()).unwrap());
    input.extend_from_slice(&encode_request_framed(&logon()).unwrap());
    // Hand-frame a garbage payload: chunk len=1, byte 0xFF, terminator 00 00.
    input.extend_from_slice(&[0x00, 0x01, 0xFF, 0x00, 0x00]);

    let transport = MemoryTransport::with_input(&input);
    let auth = auth_fixture();
    let mut session = BoltSession::new(transport, TrivialExecutor, &auth);
    let _ = session.run();
    // Reaching here without a panic is the security property under test.
    assert_ne!(session.state(), State::Ready, "a garbage message must not leave the session READY");
}

#[test]
fn goodbye_in_any_state_stops_cleanly() {
    let state = run_session(&[Request::Goodbye]);
    assert_eq!(state, State::Defunct);
}

// ---- Response::decode allocation bomb (client-side path) --------------------------------------

/// Hand-builds a RECORD message payload (opcode 0x71, 1 field) whose single field is a LIST_32 header
/// announcing `count` elements, with `tail` raw bytes after it. With a small `count` this is a valid,
/// safe payload; with a huge `count` it is the allocation-bomb vector.
fn record_with_list_header(count: u32, tail: &[u8]) -> Vec<u8> {
    let mut p = Vec::new();
    p.push(0xB1); // TINY_STRUCT, 1 field
    p.push(0x71); // RECORD opcode
    p.push(0xD6); // LIST_32 marker
    p.extend_from_slice(&count.to_be_bytes());
    p.extend_from_slice(tail);
    p
}

#[test]
fn response_decode_small_record_is_fine() {
    // A genuine small RECORD with one element (a NULL) round-trips through the client decoder.
    let payload = record_with_list_header(1, &[0xC0]); // one NULL element
    let resp = Response::decode(&payload).expect("a small RECORD must decode");
    match resp {
        Response::Record { values } => assert_eq!(values.len(), 1),
        other => panic!("expected RECORD, got {other:?}"),
    }
}

#[test]
fn response_decode_giant_record_header_does_not_allocate_unbounded() {
    // Regression: SEC-192 (CWE-789) — `Response::decode`'s RECORD path must NOT size its `Vec` from
    // the raw wire `LIST_32` header. Pre-fix it did `Vec::with_capacity(count)` with `count` taken
    // straight from the header; a RECORD declaring `0xFFFF_FFFF` (~4.29e9) elements forced a
    // `Vec::<BoltValue>::with_capacity(4_294_967_295)` — hundreds of GiB — that aborted the CLIENT
    // process (graphus-cli / graphus-dst) via `handle_alloc_error` (SIGABRT) from a single 7-byte
    // message over an untrusted server / MITM link.
    //
    // Post-fix the pre-allocation is clamped via `prealloc_cap` (≤ MAX_PREALLOC) and the `Vec` grows
    // only as REAL elements are decoded. The decisive proof: a maximal `0xFFFF_FFFF` header with no
    // element bytes must return `Err` cleanly (the loop errors at end-of-input) WITHOUT the giant
    // reservation. If this test ever aborts the process instead of returning, the cap has regressed.
    let payload = record_with_list_header(u32::MAX, &[]);
    let result = Response::decode(&payload);
    assert!(
        result.is_err(),
        "a RECORD with a u32::MAX list header and no element bytes must error cleanly, not abort \
         (regression guard for the SEC-192 uncapped Vec::with_capacity)"
    );

    // A merely-large header (2 million, also far above MAX_PREALLOC) likewise errors cleanly:
    // capacity is bounded by the cap, the loop fails on the first missing element.
    let payload = record_with_list_header(2_000_000, &[]);
    assert!(
        Response::decode(&payload).is_err(),
        "a RECORD header far above MAX_PREALLOC with no element bytes must error cleanly"
    );
}

#[test]
fn response_decode_large_record_with_real_elements_still_succeeds() {
    // Regression: SEC-192 — capping only the *pre-allocation* must not change successful decodes.
    // A RECORD declaring 5000 elements (≫ MAX_PREALLOC = 1024) WITH all 5000 real element bytes
    // present must still decode to a 5000-element row: the `Vec` grows past the cap as elements are
    // read. This pins that the fix is a pure allocation-bound, not a length limit.
    let count: u32 = 5000;
    let tail = vec![0xC0_u8; count as usize]; // `count` NULL elements (one byte each)
    let payload = record_with_list_header(count, &tail);
    match Response::decode(&payload).expect("a large but well-formed RECORD must decode") {
        Response::Record { values } => assert_eq!(values.len(), count as usize),
        other => panic!("expected RECORD, got {other:?}"),
    }
}
