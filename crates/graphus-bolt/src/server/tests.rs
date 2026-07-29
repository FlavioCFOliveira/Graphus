//! End-to-end state-machine tests: drive whole Bolt sessions in-process over a
//! [`MemoryTransport`](crate::transport::MemoryTransport) against a mock executor, asserting the
//! state transitions, streaming/fetch-size, and the fail-then-ignore-until-RESET recovery
//! (`04 §8.1`, `06 §3`).

use super::*;
use crate::executor::QuerySummary;
use crate::executor::mock::{CannedResult, MockExecutor};
use crate::framing::{Dechunker, Frame};
use crate::handshake::Proposal;
use crate::message::Request;
use crate::transport::MemoryTransport;
use graphus_auth::{Authenticator, Privilege};
use graphus_core::{GraphusError, Value};

/// An authenticator with one `alice`/`alice-pw` user (Bolt native auth, `04 §8.4`).
fn auth_fixture() -> Authenticator {
    let mut a = Authenticator::new(b"shared-jwt-secret-at-least-32-bytes!!")
        .expect("fixture secret is >= 32 bytes");
    a.catalog_mut().create_user("alice").unwrap();
    a.catalog_mut().create_role("reader").unwrap();
    a.catalog_mut()
        .grant_privilege("reader", Privilege::read_database())
        .unwrap();
    a.catalog_mut().grant_role("alice", "reader").unwrap();
    a.set_password("alice", "alice-pw").unwrap();
    a
}

/// The standard 5.4-only client handshake bytes.
fn handshake_54() -> Vec<u8> {
    encode_client_handshake([
        Proposal::exact(5, 4),
        Proposal::exact(0, 0),
        Proposal::exact(0, 0),
        Proposal::exact(0, 0),
    ])
}

/// A **Manifest-v1** client opening: magic + 4 slots (one is the manifest marker), then the client's
/// chosen-version + capabilities response the server reads after sending its manifest.
fn manifest_handshake(chosen: Version) -> Vec<u8> {
    use crate::handshake::{MANIFEST_V1_REQUEST, ManifestChoice, encode_manifest_choice};
    let mut out = encode_client_handshake([
        Proposal::from_wire(MANIFEST_V1_REQUEST),
        Proposal::exact(0, 0),
        Proposal::exact(0, 0),
        Proposal::exact(0, 0),
    ]);
    out.extend_from_slice(&encode_manifest_choice(ManifestChoice {
        version: chosen,
        capabilities: 0,
    }));
    out
}

/// A spec-valid `HELLO` carrying the required `user_agent` field (`04 §8.1`). Use this in tests that
/// drive a healthy handshake; the missing-`user_agent` rejection has its own dedicated test.
fn hello() -> Request {
    Request::Hello {
        extra: vec![("user_agent".to_owned(), Value::String("drv/1".to_owned()))],
    }
}

/// A `LOGON` with the `basic` scheme for `alice`/`alice-pw`.
fn logon_alice() -> Request {
    Request::Logon {
        auth: vec![
            ("scheme".to_owned(), Value::String("basic".to_owned())),
            ("principal".to_owned(), Value::String("alice".to_owned())),
            (
                "credentials".to_owned(),
                Value::String("alice-pw".to_owned()),
            ),
        ],
    }
}

/// Decodes the server's framed output into a flat list of [`Response`]s.
fn decode_responses(bytes: &[u8]) -> Vec<Response> {
    let mut d = Dechunker::new();
    d.push(bytes);
    let mut out = Vec::new();
    while let Some(frame) = d.next_frame().expect("framing") {
        match frame {
            Frame::Message(payload) => out.push(Response::decode(&payload).expect("decode resp")),
            Frame::Noop => {}
        }
    }
    out
}

/// Splits the server's output into the 4-byte handshake reply and the framed message stream.
fn split_handshake(bytes: &[u8]) -> ([u8; 4], &[u8]) {
    let mut hs = [0u8; 4];
    hs.copy_from_slice(&bytes[..4]);
    (hs, &bytes[4..])
}

/// Builds an input byte stream: handshake + each request framed.
fn session_input(requests: &[Request]) -> Vec<u8> {
    let mut input = handshake_54();
    for r in requests {
        input.extend_from_slice(&encode_request_framed(r).unwrap());
    }
    input
}

#[test]
fn full_session_handshake_hello_logon_run_pull_begin_commit() {
    // A complete healthy session: handshake → HELLO → LOGON → RUN → PULL (rows) → BEGIN → RUN(in-tx)
    // → PULL → COMMIT → GOODBYE.
    let exec = MockExecutor::new()
        .on_query(
            "RETURN 1 AS x",
            CannedResult::rows(&["x"], vec![vec![Value::Integer(1)]]),
        )
        .on_query(
            "CREATE (n) RETURN n",
            CannedResult::rows(&["n"], vec![vec![Value::Integer(42)]]),
        );

    let input = session_input(&[
        Request::Hello {
            extra: vec![("user_agent".to_owned(), Value::String("drv/1".to_owned()))],
        },
        logon_alice(),
        Request::Run {
            query: "RETURN 1 AS x".to_owned(),
            parameters: vec![],
            extra: vec![],
        },
        Request::Pull { n: ALL, qid: None },
        Request::Begin { extra: vec![] },
        Request::Run {
            query: "CREATE (n) RETURN n".to_owned(),
            parameters: vec![],
            extra: vec![],
        },
        Request::Pull { n: ALL, qid: None },
        Request::Commit,
        Request::Goodbye,
    ]);

    let auth = auth_fixture();
    let mut transport = MemoryTransport::with_input(&input);
    {
        let mut session = BoltSession::new(&mut transport, exec, &auth);
        session.run().expect("session runs");
        assert_eq!(session.state(), State::Defunct); // ended by GOODBYE
        assert_eq!(session.version(), Some(Version::new(5, 4)));
        assert_eq!(session.principal(), Some("alice"));
    }

    let written = transport.written();
    let (hs, stream) = split_handshake(written);
    assert_eq!(hs, [0x00, 0x00, 0x04, 0x05], "negotiated 5.4");

    let responses = decode_responses(stream);
    // HELLO→SUCCESS, LOGON→SUCCESS, RUN→SUCCESS{fields}, RECORD, SUCCESS(summary),
    // BEGIN→SUCCESS, RUN→SUCCESS{fields}, RECORD, SUCCESS(summary), COMMIT→SUCCESS.
    assert_eq!(responses.len(), 10, "responses: {responses:?}");
    assert!(matches!(responses[0], Response::Success { .. })); // HELLO
    assert!(matches!(responses[1], Response::Success { .. })); // LOGON
    // RUN SUCCESS carries the fields metadata.
    match &responses[2] {
        Response::Success { metadata } => {
            assert!(metadata.iter().any(|(k, _)| k == "fields"));
        }
        other => panic!("expected RUN SUCCESS, got {other:?}"),
    }
    assert!(matches!(responses[3], Response::Record { .. }));
    assert!(matches!(responses[4], Response::Success { .. })); // trailing summary
    assert!(matches!(responses[5], Response::Success { .. })); // BEGIN
    assert!(matches!(responses[6], Response::Success { .. })); // RUN in-tx
    assert!(matches!(responses[7], Response::Record { .. }));
    assert!(matches!(responses[8], Response::Success { .. })); // trailing summary
    assert!(matches!(responses[9], Response::Success { .. })); // COMMIT
}

#[test]
fn failure_then_ignore_until_reset_recovery() {
    // RUN a query that raises a compile error → FAILURE → subsequent RUN is IGNORED → RESET → SUCCESS
    // → a fresh RUN succeeds. This is the mandatory fail-then-ignore-until-RESET rule (`04 §8.1`).
    let exec = MockExecutor::new()
        .on_query_error(
            "BAD CYPHER",
            GraphusError::Compile("Invalid input".to_owned()),
        )
        .on_query(
            "RETURN 1",
            CannedResult::rows(&["x"], vec![vec![Value::Integer(1)]]),
        );

    let input = session_input(&[
        hello(),
        logon_alice(),
        Request::Run {
            query: "BAD CYPHER".to_owned(),
            parameters: vec![],
            extra: vec![],
        },
        // Ignored while FAILED:
        Request::Run {
            query: "RETURN 1".to_owned(),
            parameters: vec![],
            extra: vec![],
        },
        Request::Pull { n: ALL, qid: None },
        // Clear:
        Request::Reset,
        // Now works:
        Request::Run {
            query: "RETURN 1".to_owned(),
            parameters: vec![],
            extra: vec![],
        },
        Request::Pull { n: ALL, qid: None },
        Request::Goodbye,
    ]);

    let auth = auth_fixture();
    let mut transport = MemoryTransport::with_input(&input);
    {
        let mut session = BoltSession::new(&mut transport, exec, &auth);
        session.run().unwrap();
    }
    let (_, stream) = split_handshake(transport.written());
    let r = decode_responses(stream);
    // HELLO SUCCESS, LOGON SUCCESS, FAILURE, IGNORED (RUN), IGNORED (PULL), RESET SUCCESS,
    // RUN SUCCESS{fields}, RECORD, trailing SUCCESS.
    assert!(matches!(r[0], Response::Success { .. }));
    assert!(matches!(r[1], Response::Success { .. }));
    match &r[2] {
        Response::Failure(f) => assert_eq!(f.code, "Neo.ClientError.Statement.SyntaxError"),
        other => panic!("expected FAILURE, got {other:?}"),
    }
    assert!(
        matches!(r[3], Response::Ignored),
        "RUN while FAILED → IGNORED"
    );
    assert!(
        matches!(r[4], Response::Ignored),
        "PULL while FAILED → IGNORED"
    );
    assert!(matches!(r[5], Response::Success { .. }), "RESET → SUCCESS");
    assert!(
        matches!(r[6], Response::Success { .. }),
        "RUN → SUCCESS{{fields}}"
    );
    assert!(matches!(r[7], Response::Record { .. }));
    assert!(matches!(r[8], Response::Success { .. }));
    assert_eq!(r.len(), 9);
}

#[test]
fn pull_honours_bounded_fetch_size_with_has_more() {
    // Three rows, PULL n=2 then PULL n=2: first batch has_more=true (1 row remains), second drains.
    let exec = MockExecutor::new().on_query(
        "RETURN r",
        CannedResult::rows(
            &["r"],
            vec![
                vec![Value::Integer(1)],
                vec![Value::Integer(2)],
                vec![Value::Integer(3)],
            ],
        ),
    );

    let input = session_input(&[
        hello(),
        logon_alice(),
        Request::Run {
            query: "RETURN r".to_owned(),
            parameters: vec![],
            extra: vec![],
        },
        Request::Pull { n: 2, qid: None },
        Request::Pull { n: 2, qid: None },
        Request::Goodbye,
    ]);

    let auth = auth_fixture();
    let mut transport = MemoryTransport::with_input(&input);
    {
        let mut session = BoltSession::new(&mut transport, exec, &auth);
        session.run().unwrap();
    }
    let (_, stream) = split_handshake(transport.written());
    let r = decode_responses(stream);
    // HELLO, LOGON, RUN SUCCESS, RECORD, RECORD, SUCCESS{has_more}, RECORD, SUCCESS{summary}.
    assert!(matches!(r[3], Response::Record { .. }));
    assert!(matches!(r[4], Response::Record { .. }));
    match &r[5] {
        Response::Success { metadata } => {
            assert_eq!(
                metadata
                    .iter()
                    .find(|(k, _)| k == "has_more")
                    .map(|(_, v)| v),
                Some(&Value::Boolean(true)),
                "first bounded PULL must report has_more"
            );
        }
        other => panic!("expected SUCCESS has_more, got {other:?}"),
    }
    assert!(
        matches!(r[6], Response::Record { .. }),
        "third row in second PULL"
    );
    match &r[7] {
        Response::Success { metadata } => {
            assert!(
                !metadata.iter().any(|(k, _)| k == "has_more"),
                "final SUCCESS must not say has_more"
            );
        }
        other => panic!("expected trailing SUCCESS, got {other:?}"),
    }
    assert_eq!(r.len(), 8);
}

#[test]
fn bounded_pull_landing_exactly_on_last_record_does_not_say_has_more() {
    // The lookahead boundary case: exactly 2 rows, PULL n=2. The fetch limit lands on the last
    // record, but no record remains, so the trailing SUCCESS must be the summary (no has_more) and
    // there must be no spurious extra PULL round-trip. (`06 §3.1`: has_more means rows *remain*.)
    let exec = MockExecutor::new().on_query(
        "RETURN r",
        CannedResult::rows(
            &["r"],
            vec![vec![Value::Integer(1)], vec![Value::Integer(2)]],
        ),
    );
    let input = session_input(&[
        hello(),
        logon_alice(),
        Request::Run {
            query: "RETURN r".to_owned(),
            parameters: vec![],
            extra: vec![],
        },
        Request::Pull { n: 2, qid: None },
        Request::Goodbye,
    ]);
    let auth = auth_fixture();
    let mut transport = MemoryTransport::with_input(&input);
    {
        let mut session = BoltSession::new(&mut transport, exec, &auth);
        session.run().unwrap();
    }
    let (_, stream) = split_handshake(transport.written());
    let r = decode_responses(stream);
    // HELLO, LOGON, RUN SUCCESS, RECORD, RECORD, trailing SUCCESS (no has_more).
    assert_eq!(r.len(), 6);
    assert!(matches!(r[3], Response::Record { .. }));
    assert!(matches!(r[4], Response::Record { .. }));
    match &r[5] {
        Response::Success { metadata } => assert!(
            !metadata.iter().any(|(k, _)| k == "has_more"),
            "fetch limit on the last record must not falsely report has_more"
        ),
        other => panic!("expected trailing SUCCESS, got {other:?}"),
    }
}

#[test]
fn discard_drops_rows_and_yields_summary_only() {
    let exec = MockExecutor::new().on_query(
        "RETURN r",
        CannedResult::rows(
            &["r"],
            vec![vec![Value::Integer(1)], vec![Value::Integer(2)]],
        ),
    );
    let input = session_input(&[
        hello(),
        logon_alice(),
        Request::Run {
            query: "RETURN r".to_owned(),
            parameters: vec![],
            extra: vec![],
        },
        Request::Discard { n: ALL, qid: None },
        Request::Goodbye,
    ]);
    let auth = auth_fixture();
    let mut transport = MemoryTransport::with_input(&input);
    {
        let mut session = BoltSession::new(&mut transport, exec, &auth);
        session.run().unwrap();
    }
    let (_, stream) = split_handshake(transport.written());
    let r = decode_responses(stream);
    // HELLO, LOGON, RUN SUCCESS, trailing SUCCESS — no RECORD.
    assert_eq!(r.len(), 4);
    assert!(!r.iter().any(|resp| matches!(resp, Response::Record { .. })));
}

#[test]
fn bad_credentials_fail_and_close() {
    // A failed LOGON is a PRE-authentication failure: the Bolt server-state spec transitions
    // AUTHENTICATION to DEFUNCT on an unsuccessful LOGON (never a RESET-recoverable FAILED), and
    // RESET is not valid before authentication. So the FAILURE (`Unauthorized`) is TERMINAL — the
    // connection closes and the following RUN is never processed. Letting it stay recoverable was an
    // authentication bypass (a later RESET reached an unauthenticated READY — rmp #820).
    let exec = MockExecutor::new();
    let input = session_input(&[
        hello(),
        Request::Logon {
            auth: vec![
                ("scheme".to_owned(), Value::String("basic".to_owned())),
                ("principal".to_owned(), Value::String("alice".to_owned())),
                ("credentials".to_owned(), Value::String("WRONG".to_owned())),
            ],
        },
        // The connection is DEFUNCT after the failed LOGON; this RUN is never even read.
        Request::Run {
            query: "RETURN 1".to_owned(),
            parameters: vec![],
            extra: vec![],
        },
        Request::Goodbye,
    ]);
    let auth = auth_fixture();
    let mut transport = MemoryTransport::with_input(&input);
    {
        let mut session = BoltSession::new(&mut transport, exec, &auth);
        session.run().unwrap();
        assert_eq!(session.principal(), None);
        assert_eq!(
            session.state(),
            State::Defunct,
            "a failed LOGON must close the connection, not leave it recoverable (rmp #820)"
        );
    }
    let (_, stream) = split_handshake(transport.written());
    let r = decode_responses(stream);
    assert!(matches!(r[0], Response::Success { .. })); // HELLO
    match &r[1] {
        Response::Failure(f) => assert_eq!(f.code, CODE_UNAUTHORIZED),
        other => panic!("expected auth FAILURE, got {other:?}"),
    }
    // The connection closed after the FAILURE: no further response (the RUN was never processed).
    assert!(
        r.get(2).is_none(),
        "a failed LOGON is terminal; no response may follow the FAILURE: {r:?}"
    );
    assert_eq!(r.len(), 2);
}

#[test]
fn handshake_rejection_closes_connection() {
    // A client offering only an unsupported major → server replies 00 00 00 00 and run() errors.
    let mut input = encode_client_handshake([
        Proposal::exact(6, 0),
        Proposal::exact(0, 0),
        Proposal::exact(0, 0),
        Proposal::exact(0, 0),
    ]);
    input.extend_from_slice(&encode_request_framed(&hello()).unwrap());
    let auth = auth_fixture();
    let mut transport = MemoryTransport::with_input(&input);
    {
        let mut session = BoltSession::new(&mut transport, MockExecutor::new(), &auth);
        let err = session.run().unwrap_err();
        assert!(matches!(err, BoltError::Handshake(_)));
        assert_eq!(session.state(), State::Defunct);
    }
    let (hs, _) = split_handshake(transport.written());
    assert_eq!(hs, [0x00, 0x00, 0x00, 0x00], "rejection bytes");
}

#[test]
fn out_of_order_run_before_logon_fails() {
    // RUN in AUTHENTICATION (before LOGON) is illegal → FAILURE.
    let input = session_input(&[
        hello(),
        Request::Run {
            query: "RETURN 1".to_owned(),
            parameters: vec![],
            extra: vec![],
        },
        Request::Goodbye,
    ]);
    let auth = auth_fixture();
    let mut transport = MemoryTransport::with_input(&input);
    {
        let mut session = BoltSession::new(&mut transport, MockExecutor::new(), &auth);
        session.run().unwrap();
    }
    let (_, stream) = split_handshake(transport.written());
    let r = decode_responses(stream);
    assert!(matches!(r[0], Response::Success { .. })); // HELLO
    match &r[1] {
        Response::Failure(f) => assert_eq!(f.code, "Neo.ClientError.Request.Invalid"),
        other => panic!("expected protocol FAILURE, got {other:?}"),
    }
}

#[test]
fn rollback_in_transaction_returns_to_ready() {
    let exec = MockExecutor::new().with_default(CannedResult::rows(&[], vec![]));
    let input = session_input(&[
        hello(),
        logon_alice(),
        Request::Begin { extra: vec![] },
        Request::Rollback,
        Request::Goodbye,
    ]);
    let auth = auth_fixture();
    let mut transport = MemoryTransport::with_input(&input);
    {
        let mut session = BoltSession::new(&mut transport, exec, &auth);
        session.run().unwrap();
    }
    let (_, stream) = split_handshake(transport.written());
    let r = decode_responses(stream);
    // HELLO, LOGON, BEGIN SUCCESS, ROLLBACK SUCCESS.
    assert_eq!(r.len(), 4);
    assert!(
        r.iter()
            .all(|resp| matches!(resp, Response::Success { .. }))
    );
}

#[test]
fn reset_mid_transaction_rolls_back() {
    // RESET while TX_READY must roll back the open transaction and return to READY.
    let exec = MockExecutor::new();
    let input = session_input(&[
        hello(),
        logon_alice(),
        Request::Begin { extra: vec![] },
        Request::Reset,
        Request::Goodbye,
    ]);
    let auth = auth_fixture();
    let mut transport = MemoryTransport::with_input(&input);
    let mut session = BoltSession::new(&mut transport, exec, &auth);
    session.run().unwrap();
    // The mock executor logged the RESET-triggered rollback of the open transaction. RESET aborts
    // via `rollback_open_tx` (consults the executor's own `current_tx`), not the plain `rollback`.
    assert!(
        session
            .executor()
            .log
            .contains(&"rollback_open_tx".to_owned()),
        "RESET in a transaction must roll back the open transaction"
    );
}

#[test]
fn reset_after_error_inside_explicit_tx_clears_tx_so_next_begin_succeeds() {
    // Regression (rmp #613): a statement FAILURE inside an explicit transaction moves the Bolt state
    // enum to FAILED, which used to make `handle_reset` skip the executor rollback (it gated on
    // TxReady/TxStreaming). The executor's transaction then leaked and the NEXT `BEGIN` on the same
    // (pooled) connection failed with "a transaction is already open", poisoning it. RESET must
    // abort the underlying transaction UNCONDITIONALLY so the connection is reusable. Found against
    // a live v0.0.7 instance with the real neo4j driver.
    let exec = MockExecutor::new()
        .on_query_error("RETURN 1/0", GraphusError::Runtime("/ by zero".to_owned()));
    let input = session_input(&[
        hello(),
        logon_alice(),
        Request::Begin { extra: vec![] },
        Request::Run {
            query: "RETURN 1/0".to_owned(),
            parameters: vec![],
            extra: vec![],
        },
        Request::Reset,
        Request::Begin { extra: vec![] },
        Request::Goodbye,
    ]);
    let auth = auth_fixture();
    let mut transport = MemoryTransport::with_input(&input);
    {
        let mut session = BoltSession::new(&mut transport, exec, &auth);
        session.run().unwrap();
    }
    let (_, stream) = split_handshake(transport.written());
    let r = decode_responses(stream);
    // HELLO, LOGON, BEGIN#1 SUCCESS, RUN FAILURE, RESET SUCCESS, BEGIN#2 SUCCESS.
    assert!(matches!(r[0], Response::Success { .. }), "HELLO");
    assert!(matches!(r[1], Response::Success { .. }), "LOGON");
    assert!(matches!(r[2], Response::Success { .. }), "BEGIN #1");
    match &r[3] {
        Response::Failure(f) => assert_eq!(f.code, "Neo.ClientError.Statement.ArgumentError"),
        other => panic!("expected RUN FAILURE, got {other:?}"),
    }
    assert!(matches!(r[4], Response::Success { .. }), "RESET → SUCCESS");
    // The crux: before the fix this was a FAILURE "a transaction is already open".
    assert!(
        matches!(r[5], Response::Success { .. }),
        "BEGIN #2 after RESET must SUCCEED — a leaked transaction poisons the connection"
    );
    assert_eq!(r.len(), 6);
}

#[test]
fn pre_auth_reset_cannot_bypass_authentication_rmp_820() {
    // rmp #820 (CRITICAL auth bypass): a PRE-authentication failure must be TERMINAL. The Bolt
    // server-state spec transitions NEGOTIATION/AUTHENTICATION to DEFUNCT on failure (never to a
    // RESET-recoverable FAILED), and RESET is not a valid message before authentication
    // (neo4j.com/docs/bolt/current/bolt/server-state/). Before the fix, a junk message in CONNECTED
    // entered the recoverable FAILED state and a following RESET reset the connection to READY with a
    // `None` principal — which the server engine seam treats as UNRESTRICTED — so an unauthenticated
    // client could run arbitrary queries. This drives exactly that exploit (no HELLO, no LOGON) and
    // proves the query never reaches the executor.
    let exec = MockExecutor::new().on_query(
        "RETURN 1",
        CannedResult::rows(&["x"], vec![vec![Value::Integer(1)]]),
    );
    let input = session_input(&[
        Request::Reset, // junk in CONNECTED → must be terminal
        Request::Reset, // the "recovery" RESET the exploit relied on
        Request::Run {
            query: "RETURN 1".to_owned(),
            parameters: vec![],
            extra: vec![],
        },
        Request::Pull { n: ALL, qid: None },
    ]);
    let auth = auth_fixture();
    let mut transport = MemoryTransport::with_input(&input);
    let mut session = BoltSession::new(&mut transport, exec, &auth);
    session.run().expect("session runs to a clean terminal");

    // PRIMARY discriminator: the query NEVER reached the executor. `run(` is the mock's per-RUN log
    // marker; its absence proves the RUN bytes were never dispatched. (RED on the unfixed code, where
    // the second RESET resurrected the connection to READY and the RUN executed unrestricted.)
    assert!(
        !session.executor().log.iter().any(|e| e.starts_with("run(")),
        "an unauthenticated RUN must never execute (auth bypass, rmp #820): {:?}",
        session.executor().log
    );
    // On the wire the client sees only a FAILURE — never a SUCCESS (which would open a stream / signal
    // a resurrected READY) and never a RECORD.
    drop(session);
    let (_, stream) = split_handshake(transport.written());
    let r = decode_responses(stream);
    assert!(
        matches!(r.first(), Some(Response::Failure(_))),
        "pre-auth junk must be answered with FAILURE: {r:?}"
    );
    assert!(
        !r.iter().any(|resp| matches!(resp, Response::Record { .. })),
        "no RECORD may ever be produced for an unauthenticated session: {r:?}"
    );
    assert!(
        !r.iter()
            .any(|resp| matches!(resp, Response::Success { .. })),
        "no SUCCESS may follow pre-auth junk — a SUCCESS means the connection was resurrected: {r:?}"
    );
}

#[test]
fn post_logoff_reset_cannot_reach_ready_unauthenticated_rmp_820() {
    // rmp #820 variant: even a genuinely-authenticated connection must not be able to reach an
    // unrestricted READY. After LOGOFF the connection is back in AUTHENTICATION with a cleared
    // principal; a RESET there must be TERMINAL (not a jump to READY), so the post-LOGOFF path cannot
    // run queries with a `None` (unrestricted) principal. The discriminating property is that the
    // RUN never executes (the EOF at the end of the script drives BOTH the fixed and unfixed builds
    // to DEFUNCT, so the final state alone does not distinguish them).
    let exec = MockExecutor::new().on_query(
        "RETURN 1",
        CannedResult::rows(&["x"], vec![vec![Value::Integer(1)]]),
    );
    let input = session_input(&[
        hello(),
        logon_alice(),
        Request::Logoff, // → AUTHENTICATION, principal cleared
        Request::Reset,  // junk in AUTHENTICATION → must be terminal
        Request::Reset,  // the "recovery" RESET the exploit relied on
        Request::Run {
            query: "RETURN 1".to_owned(),
            parameters: vec![],
            extra: vec![],
        },
        Request::Pull { n: ALL, qid: None },
    ]);
    let auth = auth_fixture();
    let mut transport = MemoryTransport::with_input(&input);
    let mut session = BoltSession::new(&mut transport, exec, &auth);
    session.run().expect("session runs to a clean terminal");
    assert!(
        !session.executor().log.iter().any(|e| e.starts_with("run(")),
        "a RUN after a post-LOGOFF RESET must never execute (auth bypass, rmp #820): {:?}",
        session.executor().log
    );
    drop(session);
    let (_, stream) = split_handshake(transport.written());
    let r = decode_responses(stream);
    assert!(
        !r.iter().any(|resp| matches!(resp, Response::Record { .. })),
        "no RECORD may be produced after a post-LOGOFF RESET: {r:?}"
    );
}

#[test]
fn post_auth_statement_failure_still_recovers_via_reset_rmp_820_guard() {
    // rmp #820 must NOT regress the correct POST-authentication recovery (the rmp #613 semantics): an
    // AUTHENTICATED session that hits a statement FAILURE stays in the recoverable FAILED state, and a
    // RESET returns it to READY so the next statement runs. Only PRE-auth failures are terminal. This
    // guards that the `handle_reset` change (principal-present path) keeps recovering.
    let exec = MockExecutor::new()
        .on_query_error("BAD", GraphusError::Compile("nope".to_owned()))
        .on_query(
            "RETURN 1",
            CannedResult::rows(&["x"], vec![vec![Value::Integer(1)]]),
        );
    let input = session_input(&[
        hello(),
        logon_alice(),
        Request::Run {
            query: "BAD".to_owned(),
            parameters: vec![],
            extra: vec![],
        },
        Request::Reset,
        Request::Run {
            query: "RETURN 1".to_owned(),
            parameters: vec![],
            extra: vec![],
        },
        Request::Pull { n: ALL, qid: None },
        Request::Goodbye,
    ]);
    let auth = auth_fixture();
    let mut transport = MemoryTransport::with_input(&input);
    {
        let mut session = BoltSession::new(&mut transport, exec, &auth);
        session.run().unwrap();
    }
    let (_, stream) = split_handshake(transport.written());
    let r = decode_responses(stream);
    // HELLO, LOGON, FAILURE (BAD), RESET SUCCESS, RUN SUCCESS{fields}, RECORD, trailing SUCCESS.
    assert!(matches!(r[0], Response::Success { .. }), "HELLO");
    assert!(matches!(r[1], Response::Success { .. }), "LOGON");
    assert!(matches!(r[2], Response::Failure(_)), "BAD → FAILURE");
    assert!(
        matches!(r[3], Response::Success { .. }),
        "RESET → SUCCESS (recovered to READY)"
    );
    assert!(
        matches!(r[4], Response::Success { .. }),
        "RUN after RESET → SUCCESS"
    );
    assert!(
        matches!(r[5], Response::Record { .. }),
        "the recovered RUN streams its record"
    );
    assert!(matches!(r[6], Response::Success { .. }), "trailing summary");
    assert_eq!(r.len(), 7);
}

#[test]
fn noop_keepalive_between_messages_is_ignored() {
    // Insert a bare NOOP (00 00) between LOGON and RUN; the session must skip it.
    let mut input = handshake_54();
    input.extend_from_slice(&encode_request_framed(&hello()).unwrap());
    input.extend_from_slice(&encode_request_framed(&logon_alice()).unwrap());
    input.extend_from_slice(&crate::framing::END_MARKER); // NOOP
    input.extend_from_slice(
        &encode_request_framed(&Request::Run {
            query: "RETURN 1".to_owned(),
            parameters: vec![],
            extra: vec![],
        })
        .unwrap(),
    );
    input.extend_from_slice(&encode_request_framed(&Request::Pull { n: ALL, qid: None }).unwrap());
    input.extend_from_slice(&encode_request_framed(&Request::Goodbye).unwrap());

    let exec = MockExecutor::new().on_query(
        "RETURN 1",
        CannedResult::rows(&["x"], vec![vec![Value::Integer(7)]]),
    );
    let auth = auth_fixture();
    let mut transport = MemoryTransport::with_input(&input);
    {
        let mut session = BoltSession::new(&mut transport, exec, &auth);
        session.run().unwrap();
    }
    let (_, stream) = split_handshake(transport.written());
    let r = decode_responses(stream);
    // The NOOP produced no response; the RUN still streamed its record.
    assert!(r.iter().any(|resp| matches!(resp, Response::Record { .. })));
}

#[test]
fn commit_serialization_failure_is_transient_failure() {
    // A retriable commit failure must surface as a TransientError FAILURE (drivers retry).
    let mut exec = MockExecutor::new();
    exec.commit_fails_with = Some(GraphusError::Transaction(
        "serialization failure".to_owned(),
    ));
    let input = session_input(&[
        hello(),
        logon_alice(),
        Request::Begin { extra: vec![] },
        Request::Commit,
        Request::Goodbye,
    ]);
    let auth = auth_fixture();
    let mut transport = MemoryTransport::with_input(&input);
    {
        let mut session = BoltSession::new(&mut transport, exec, &auth);
        session.run().unwrap();
    }
    let (_, stream) = split_handshake(transport.written());
    let r = decode_responses(stream);
    match &r[3] {
        Response::Failure(f) => assert!(f.code.contains("TransientError"), "code: {}", f.code),
        other => panic!("expected transient FAILURE, got {other:?}"),
    }
}

#[test]
fn eof_before_goodbye_ends_cleanly() {
    // The peer drops the socket right after LOGON; the session ends without error, state DEFUNCT.
    let input = session_input(&[hello(), logon_alice()]);
    let auth = auth_fixture();
    let mut transport = MemoryTransport::with_input(&input);
    let mut session = BoltSession::new(&mut transport, MockExecutor::new(), &auth);
    session.run().expect("clean EOF");
    assert_eq!(session.state(), State::Defunct);
}

#[test]
fn hello_without_user_agent_is_rejected_with_failure() {
    // Regression: `user_agent` is REQUIRED in HELLO (`04 §8.1`). A HELLO that omits it must be
    // answered with FAILURE (not SUCCESS). A malformed HELLO is a PRE-authentication failure and is
    // therefore TERMINAL (DEFUNCT) — never a recoverable FAILED, and never AUTHENTICATION (rmp #820).
    // The connection closes, so the following LOGON is never even processed.
    let input = session_input(&[
        Request::Hello { extra: vec![] }, // no `user_agent`
        logon_alice(),
        Request::Goodbye,
    ]);
    let auth = auth_fixture();
    let mut transport = MemoryTransport::with_input(&input);
    {
        let mut session = BoltSession::new(&mut transport, MockExecutor::new(), &auth);
        session.run().expect("session runs");
        assert_ne!(
            session.principal(),
            Some("alice"),
            "a rejected HELLO must not authenticate"
        );
        assert_eq!(
            session.state(),
            State::Defunct,
            "a malformed HELLO is terminal (DEFUNCT), not a recoverable FAILED (rmp #820)"
        );
    }
    let (_, stream) = split_handshake(transport.written());
    let r = decode_responses(stream);
    match &r[0] {
        Response::Failure(f) => {
            assert_eq!(f.code, "Neo.ClientError.Request.Invalid");
            assert!(f.message.contains("user_agent"), "message: {}", f.message);
        }
        other => panic!("expected HELLO FAILURE, got {other:?}"),
    }
    // The connection is terminal after the FAILURE: the LOGON that followed was never processed, so
    // there is no second response at all (before rmp #820 it was IGNORED on a still-open connection).
    assert!(
        r.get(1).is_none(),
        "a malformed HELLO closes the connection; no further response may follow: {r:?}"
    );
}

#[test]
fn hello_with_empty_user_agent_is_rejected() {
    // A present-but-empty `user_agent` is as malformed as an absent one.
    let input = session_input(&[
        Request::Hello {
            extra: vec![("user_agent".to_owned(), Value::String(String::new()))],
        },
        Request::Goodbye,
    ]);
    let auth = auth_fixture();
    let mut transport = MemoryTransport::with_input(&input);
    {
        let mut session = BoltSession::new(&mut transport, MockExecutor::new(), &auth);
        session.run().expect("session runs");
        assert_eq!(
            session.state(),
            State::Defunct,
            "an empty user_agent is a terminal pre-auth failure (rmp #820)"
        );
    }
    let (_, stream) = split_handshake(transport.written());
    let r = decode_responses(stream);
    assert!(
        matches!(&r[0], Response::Failure(f) if f.message.contains("user_agent")),
        "empty user_agent must be rejected: {r:?}"
    );
}

#[test]
fn summary_carries_query_type_and_stats() {
    let summary = QuerySummary {
        plan: None,
        query_type: Some("rw".to_owned()),
        stats: vec![("nodes-created".to_owned(), Value::Integer(1))],
        bookmark: None,
    };
    let exec = MockExecutor::new().on_query(
        "CREATE (n)",
        CannedResult {
            fields: vec![],
            rows: vec![],
            summary,
        },
    );
    let input = session_input(&[
        hello(),
        logon_alice(),
        Request::Run {
            query: "CREATE (n)".to_owned(),
            parameters: vec![],
            extra: vec![("mode".to_owned(), Value::String("w".to_owned()))],
        },
        Request::Pull { n: ALL, qid: None },
        Request::Goodbye,
    ]);
    let auth = auth_fixture();
    let mut transport = MemoryTransport::with_input(&input);
    {
        let mut session = BoltSession::new(&mut transport, exec, &auth);
        session.run().unwrap();
    }
    let (_, stream) = split_handshake(transport.written());
    let r = decode_responses(stream);
    // Trailing SUCCESS (after RUN SUCCESS) carries type and stats.
    let trailing = r.last().unwrap();
    match trailing {
        Response::Success { metadata } => {
            assert_eq!(
                metadata.iter().find(|(k, _)| k == "type").map(|(_, v)| v),
                Some(&Value::String("rw".to_owned()))
            );
            assert!(metadata.iter().any(|(k, _)| k == "stats"));
        }
        other => panic!("expected trailing SUCCESS, got {other:?}"),
    }
}

#[test]
fn bookmark_on_commit_and_autocommit_pull_only_and_monotonic() {
    // rmp #807/#813: the Bolt spec lists `bookmark::String` in the SUCCESS response to COMMIT and in the
    // terminal (`has_more == false`) SUCCESS of an AUTO-COMMIT PULL ("the bookmark after committing
    // this transaction"; auto-commit only). Graphus emits an opaque, monotonic-per-database token
    // there — and ONLY there. Since rmp #813 a READ carries a bookmark too (matching a real Neo4j
    // server), on exactly the same terminal messages. This test pins every positive and negative case:
    //   * auto-commit final PULL (write) -> carries a bookmark (two writes, strictly advancing);
    //   * auto-commit final PULL (READ)  -> carries a bookmark (rmp #813) — on the terminal PULL only;
    //   * explicit COMMIT                -> carries a bookmark;
    //   * RUN SUCCESS (write OR read)    -> NO bookmark (it commits nothing);
    //   * explicit-transaction PULL      -> NO bookmark (the tx has not committed; its COMMIT carries it);
    //   * ROLLBACK                       -> NO bookmark (it committed nothing).
    // Mutation guard: deleting the emission in `summary_metadata` (or the COMMIT arm) fails this test, and
    // leaking it onto a RUN / mid-stream / in-tx PULL fails the negative assertions below.
    let exec = MockExecutor::new()
        // Two auto-commit writes with strictly increasing bookmarks. The engine mints "<db>:<ts>" from
        // the monotonic commit-timestamp oracle; the mock stands in with fixed advancing tokens so the
        // wire plumbing (engine summary -> QuerySummary -> SUCCESS metadata) is exercised end to end.
        .on_query(
            "CREATE (:A)",
            CannedResult::rows(&[], vec![]).with_bookmark("graphus:100"),
        )
        .on_query(
            "CREATE (:B)",
            CannedResult::rows(&[], vec![]).with_bookmark("graphus:101"),
        )
        // An in-transaction read: its PULL summary carries NO bookmark (the tx has not committed).
        .on_query(
            "MATCH (n) RETURN n",
            CannedResult::rows(&["n"], vec![vec![Value::Integer(1)]]),
        )
        // An AUTO-COMMIT read: its terminal PULL summary DOES carry a bookmark (rmp #813) — the DB's
        // durable-write high-water. The mock stands in with a fixed token past the prior writes/commit.
        .on_query(
            "MATCH (x) RETURN x",
            CannedResult::rows(&["x"], vec![vec![Value::Integer(1)]]).with_bookmark("graphus:250"),
        )
        // The explicit COMMIT of the write transaction mints its own bookmark.
        .with_commit_bookmark("graphus:200");

    let input = session_input(&[
        hello(),
        logon_alice(),
        // (A) auto-commit write #1 — RUN SUCCESS then terminal PULL SUCCESS(bookmark 100).
        Request::Run {
            query: "CREATE (:A)".to_owned(),
            parameters: vec![],
            extra: vec![],
        },
        Request::Pull { n: ALL, qid: None },
        // (B) auto-commit write #2 — terminal PULL SUCCESS(bookmark 101), strictly greater.
        Request::Run {
            query: "CREATE (:B)".to_owned(),
            parameters: vec![],
            extra: vec![],
        },
        Request::Pull { n: ALL, qid: None },
        // (C) explicit tx: BEGIN, RUN(read), PULL(no bookmark), COMMIT(bookmark 200).
        Request::Begin { extra: vec![] },
        Request::Run {
            query: "MATCH (n) RETURN n".to_owned(),
            parameters: vec![],
            extra: vec![],
        },
        Request::Pull { n: ALL, qid: None },
        Request::Commit,
        // (D) explicit tx that ROLLBACKs (no bookmark on the ROLLBACK).
        Request::Begin { extra: vec![] },
        Request::Run {
            query: "MATCH (n) RETURN n".to_owned(),
            parameters: vec![],
            extra: vec![],
        },
        Request::Pull { n: ALL, qid: None },
        Request::Rollback,
        // (E) auto-commit READ — RUN SUCCESS (no bookmark) then a RECORD then a terminal PULL SUCCESS
        // that DOES carry a bookmark (rmp #813: a read carries a bookmark on the terminal auto-commit
        // PULL, exactly like a write, and NOT on its RUN).
        Request::Run {
            query: "MATCH (x) RETURN x".to_owned(),
            parameters: vec![],
            extra: vec![],
        },
        Request::Pull { n: ALL, qid: None },
        Request::Goodbye,
    ]);

    let auth = auth_fixture();
    let mut transport = MemoryTransport::with_input(&input);
    {
        let mut session = BoltSession::new(&mut transport, exec, &auth);
        session.run().expect("session runs");
    }
    let (_, stream) = split_handshake(transport.written());
    let r = decode_responses(stream);

    // The `bookmark` string in a SUCCESS response, or `None` (panics if the response is not SUCCESS,
    // so the caller must index a known-SUCCESS response).
    let bookmark_of = |resp: &Response| -> Option<String> {
        match resp {
            Response::Success { metadata } => {
                metadata.iter().find_map(|(k, v)| match (k.as_str(), v) {
                    ("bookmark", Value::String(s)) => Some(s.clone()),
                    _ => None,
                })
            }
            other => panic!("expected SUCCESS, got {other:?}"),
        }
    };

    // Response index map (a CREATE returns 0 rows, a MATCH one RECORD):
    //  [0]HELLO [1]LOGON
    //  [2]RUN(A)SUCCESS [3]PULL SUCCESS(bookmark 100)
    //  [4]RUN(B)SUCCESS [5]PULL SUCCESS(bookmark 101)
    //  [6]BEGIN [7]RUN(read)SUCCESS [8]RECORD [9]PULL SUCCESS(in-tx,none) [10]COMMIT(bookmark 200)
    //  [11]BEGIN [12]RUN(read)SUCCESS [13]RECORD [14]PULL SUCCESS(in-tx,none) [15]ROLLBACK(none)
    //  [16]RUN(read E)SUCCESS [17]RECORD [18]PULL SUCCESS(auto-commit read, bookmark 250)
    assert_eq!(
        bookmark_of(&r[2]),
        None,
        "RUN SUCCESS must not carry a bookmark"
    );
    let bm1 = bookmark_of(&r[3]).expect("auto-commit final PULL carries a bookmark");
    assert_eq!(bm1, "graphus:100");
    let bm2 = bookmark_of(&r[5]).expect("second auto-commit final PULL carries a bookmark");
    assert_eq!(bm2, "graphus:101");
    assert_eq!(
        bookmark_of(&r[7]),
        None,
        "in-tx RUN SUCCESS must not carry a bookmark"
    );
    assert_eq!(
        bookmark_of(&r[9]),
        None,
        "explicit-transaction PULL must not carry a bookmark (its COMMIT does)"
    );
    assert_eq!(
        bookmark_of(&r[10]).as_deref(),
        Some("graphus:200"),
        "COMMIT SUCCESS carries the transaction bookmark"
    );
    assert_eq!(
        bookmark_of(&r[14]),
        None,
        "explicit-transaction PULL must not carry a bookmark"
    );
    assert_eq!(
        bookmark_of(&r[15]),
        None,
        "ROLLBACK must not carry a bookmark"
    );
    // (E) an AUTO-COMMIT READ: its RUN carries NO bookmark, but its terminal PULL DOES (rmp #813).
    assert_eq!(
        bookmark_of(&r[16]),
        None,
        "auto-commit READ RUN SUCCESS must not carry a bookmark"
    );
    let bmr =
        bookmark_of(&r[18]).expect("auto-commit READ terminal PULL carries a bookmark (rmp #813)");
    assert_eq!(bmr, "graphus:250");

    // Strict monotonic advance across the two successive auto-commit writes (the property causal
    // chaining relies on): parse the numeric suffix of each opaque `"<db>:<n>"` token.
    let seq = |bm: &str| -> u64 { bm.rsplit(':').next().unwrap().parse().unwrap() };
    assert!(
        seq(&bm2) > seq(&bm1),
        "bookmark must advance monotonically: {bm1} -> {bm2}"
    );
    // The read's bookmark is monotonic past the prior write bookmarks too (rmp #813): a real read reflects
    // the DB's durable-write high-water, which is >= any write the session has done.
    assert!(
        seq(&bmr) > seq(&bm2),
        "a read's bookmark advances monotonically past prior writes: {bm2} -> {bmr}"
    );
}

#[test]
fn db_field_from_extras_reaches_the_executor() {
    // The `db` field of BEGIN and auto-commit RUN extras flows through to the executor; an
    // empty/absent value is normalised to None (Bolt 5.x database targeting — rmp #84).
    let exec = MockExecutor::new().with_default(CannedResult::rows(&[], vec![]));
    let input = session_input(&[
        hello(),
        logon_alice(),
        // Auto-commit RUN naming a database.
        Request::Run {
            query: "RETURN 1".to_owned(),
            parameters: vec![],
            extra: vec![("db".to_owned(), Value::String("sales".to_owned()))],
        },
        Request::Pull { n: ALL, qid: None },
        // Auto-commit RUN with an EMPTY db → the default database (None).
        Request::Run {
            query: "RETURN 2".to_owned(),
            parameters: vec![],
            extra: vec![("db".to_owned(), Value::String(String::new()))],
        },
        Request::Pull { n: ALL, qid: None },
        // BEGIN naming a database.
        Request::Begin {
            extra: vec![("db".to_owned(), Value::String("sales".to_owned()))],
        },
        Request::Rollback,
        Request::Goodbye,
    ]);
    let auth = auth_fixture();
    let mut transport = MemoryTransport::with_input(&input);
    let mut session = BoltSession::new(&mut transport, exec, &auth);
    session.run().unwrap();

    let log = &session.executor().log;
    assert!(
        log.iter()
            .any(|l| l.contains("RETURN 1") && l.contains("db: Some(\"sales\")")),
        "RUN db reaches the executor: {log:?}"
    );
    assert!(
        log.iter()
            .any(|l| l.contains("RETURN 2") && l.contains("db: None")),
        "empty RUN db is the default database: {log:?}"
    );
    assert!(
        log.contains(&"begin(Write, db=Some(\"sales\"))".to_owned()),
        "BEGIN db reaches the executor: {log:?}"
    );
}

#[test]
fn logon_announces_the_principal_and_logoff_clears_it() {
    // LOGON → set_principal(Some), LOGOFF → set_principal(None) (rmp #84 identity plumbing).
    let exec = MockExecutor::new();
    let input = session_input(&[hello(), logon_alice(), Request::Logoff, Request::Goodbye]);
    let auth = auth_fixture();
    let mut transport = MemoryTransport::with_input(&input);
    let mut session = BoltSession::new(&mut transport, exec, &auth);
    session.run().unwrap();

    let log = &session.executor().log;
    assert!(
        log.contains(&"set_principal(Some(\"alice\"))".to_owned()),
        "LOGON announces the principal: {log:?}"
    );
    assert!(
        log.contains(&"set_principal(None)".to_owned()),
        "LOGOFF clears the principal: {log:?}"
    );
    assert_eq!(session.executor().principal, None, "cleared after LOGOFF");
}

#[test]
fn in_tx_run_emits_qid_autocommit_omits_it() {
    // rmp #391 / Bolt message spec: a RUN inside an explicit transaction MUST return a server-
    // assigned `qid::Integer` in its SUCCESS metadata (starting at 0, incrementing per statement);
    // an auto-commit RUN omits `qid` entirely.
    let exec = MockExecutor::new()
        .on_query(
            "RETURN 1",
            CannedResult::rows(&["x"], vec![vec![Value::Integer(1)]]),
        )
        .on_query(
            "RETURN 2",
            CannedResult::rows(&["y"], vec![vec![Value::Integer(2)]]),
        )
        .on_query(
            "RETURN 3",
            CannedResult::rows(&["z"], vec![vec![Value::Integer(3)]]),
        );

    let input = session_input(&[
        hello(),
        logon_alice(),
        // Auto-commit RUN: no qid.
        Request::Run {
            query: "RETURN 1".to_owned(),
            parameters: vec![],
            extra: vec![],
        },
        Request::Pull { n: ALL, qid: None },
        // Explicit transaction: two RUNs, qids 0 then 1.
        Request::Begin { extra: vec![] },
        Request::Run {
            query: "RETURN 2".to_owned(),
            parameters: vec![],
            extra: vec![],
        },
        Request::Pull { n: ALL, qid: None },
        Request::Run {
            query: "RETURN 3".to_owned(),
            parameters: vec![],
            extra: vec![],
        },
        Request::Pull { n: ALL, qid: None },
        Request::Commit,
        Request::Goodbye,
    ]);

    let auth = auth_fixture();
    let mut transport = MemoryTransport::with_input(&input);
    {
        let mut session = BoltSession::new(&mut transport, exec, &auth);
        session.run().expect("session runs");
    }
    let (_, stream) = split_handshake(transport.written());
    let r = decode_responses(stream);

    let qid_of = |resp: &Response| -> Option<i64> {
        match resp {
            Response::Success { metadata } => {
                metadata.iter().find_map(|(k, v)| match (k.as_str(), v) {
                    ("qid", Value::Integer(n)) => Some(*n),
                    _ => None,
                })
            }
            other => panic!("expected SUCCESS, got {other:?}"),
        }
    };

    // Index map: [0]HELLO [1]LOGON [2]RUN(auto) [3]REC [4]SUMMARY [5]BEGIN
    //            [6]RUN(tx qid0) [7]REC [8]SUMMARY [9]RUN(tx qid1) [10]REC [11]SUMMARY [12]COMMIT
    assert_eq!(qid_of(&r[2]), None, "auto-commit RUN omits qid");
    assert_eq!(qid_of(&r[6]), Some(0), "first in-tx RUN gets qid 0");
    assert_eq!(qid_of(&r[9]), Some(1), "second in-tx RUN gets qid 1");
}

#[test]
fn pull_with_unknown_qid_is_rejected() {
    // rmp #391: PULL addressing a qid that is neither -1 ("last") nor the open stream's id must
    // FAILURE Neo.ClientError.Request.Invalid → FAILED (the result it names is not open).
    let exec = MockExecutor::new().on_query(
        "RETURN 1",
        CannedResult::rows(&["x"], vec![vec![Value::Integer(1)]]),
    );

    let input = session_input(&[
        hello(),
        logon_alice(),
        Request::Begin { extra: vec![] },
        Request::Run {
            query: "RETURN 1".to_owned(),
            parameters: vec![],
            extra: vec![],
        },
        // The open stream is qid 0; PULL qid 99 names nothing.
        Request::Pull {
            n: ALL,
            qid: Some(99),
        },
        Request::Goodbye,
    ]);

    let auth = auth_fixture();
    let mut transport = MemoryTransport::with_input(&input);
    {
        let mut session = BoltSession::new(&mut transport, exec, &auth);
        session.run().unwrap();
        assert_eq!(session.state(), State::Defunct); // GOODBYE after the FAILURE
    }
    let (_, stream) = split_handshake(transport.written());
    let r = decode_responses(stream);
    // [0]HELLO [1]LOGON [2]BEGIN [3]RUN SUCCESS{qid:0} [4]FAILURE (bad qid).
    match &r[4] {
        Response::Failure(f) => assert_eq!(f.code, "Neo.ClientError.Request.Invalid"),
        other => panic!("expected FAILURE for bad qid, got {other:?}"),
    }
}

#[test]
fn pull_accepts_the_open_qid_and_minus_one() {
    // rmp #391: an explicit qid that matches the open stream, and qid -1 ("last"), both address the
    // open stream and stream normally.
    let exec = MockExecutor::new().on_query(
        "RETURN 1",
        CannedResult::rows(&["x"], vec![vec![Value::Integer(1)]]),
    );

    let input = session_input(&[
        hello(),
        logon_alice(),
        Request::Begin { extra: vec![] },
        Request::Run {
            query: "RETURN 1".to_owned(),
            parameters: vec![],
            extra: vec![],
        },
        // Address the open stream by its exact qid (0).
        Request::Pull {
            n: ALL,
            qid: Some(0),
        },
        Request::Commit,
        Request::Goodbye,
    ]);

    let auth = auth_fixture();
    let mut transport = MemoryTransport::with_input(&input);
    {
        let mut session = BoltSession::new(&mut transport, exec, &auth);
        session.run().unwrap();
    }
    let (_, stream) = split_handshake(transport.written());
    let r = decode_responses(stream);
    // [3]RUN SUCCESS{qid:0} [4]RECORD [5]SUMMARY [6]COMMIT — no FAILURE.
    assert!(matches!(r[4], Response::Record { .. }), "qid match streams");
    assert!(
        !r.iter().any(|resp| matches!(resp, Response::Failure(_))),
        "a matching qid must not FAILURE: {r:?}"
    );
}

#[test]
fn logoff_in_tx_ready_is_rejected_and_rolls_back() {
    // rmp #392 / Bolt spec: LOGOFF is valid only in READY. Inside an open explicit transaction it
    // must FAILURE → FAILED, the principal must stay set (not dropped), and the open tx must be
    // rolled back (not left dangling).
    let exec = MockExecutor::new();
    let input = session_input(&[
        hello(),
        logon_alice(),
        Request::Begin { extra: vec![] },
        Request::Logoff,
        Request::Goodbye,
    ]);
    let auth = auth_fixture();
    let mut transport = MemoryTransport::with_input(&input);
    {
        let mut session = BoltSession::new(&mut transport, exec, &auth);
        session.run().unwrap();
        assert_eq!(session.state(), State::Defunct); // GOODBYE after the FAILURE
        // The principal is NOT dropped by an invalid LOGOFF.
        assert_eq!(session.principal(), Some("alice"));
        // The transaction was rolled back, not left open.
        assert!(
            !session.executor().tx_open,
            "tx rolled back on invalid LOGOFF"
        );
        let log = &session.executor().log;
        assert!(
            log.contains(&"rollback".to_owned()),
            "invalid LOGOFF rolls the tx back: {log:?}"
        );
    }
    let (_, stream) = split_handshake(transport.written());
    let r = decode_responses(stream);
    // [0]HELLO [1]LOGON [2]BEGIN [3]FAILURE (invalid LOGOFF).
    match &r[3] {
        Response::Failure(f) => assert_eq!(f.code, "Neo.ClientError.Request.Invalid"),
        other => panic!("expected FAILURE for in-tx LOGOFF, got {other:?}"),
    }
}

#[test]
fn logoff_in_ready_still_succeeds() {
    // rmp #392 regression guard: a READY-state LOGOFF still works (drops principal → AUTHENTICATION).
    let exec = MockExecutor::new();
    let input = session_input(&[hello(), logon_alice(), Request::Logoff, Request::Goodbye]);
    let auth = auth_fixture();
    let mut transport = MemoryTransport::with_input(&input);
    {
        let mut session = BoltSession::new(&mut transport, exec, &auth);
        session.run().unwrap();
        assert_eq!(
            session.principal(),
            None,
            "READY LOGOFF clears the principal"
        );
    }
    let (_, stream) = split_handshake(transport.written());
    let r = decode_responses(stream);
    // [0]HELLO [1]LOGON [2]LOGOFF SUCCESS.
    assert!(
        matches!(r[2], Response::Success { .. }),
        "READY LOGOFF → SUCCESS"
    );
}

// ---- Manifest-v1 handshake, ROUTE, TELEMETRY, per-connection id (rmp #95) ---------------------

#[test]
fn manifest_handshake_negotiates_and_runs_a_full_session() {
    // A manifest-aware client (00 00 01 FF) gets the modern exchange and ends up at 5.4, then drives
    // a normal HELLO/LOGON/RUN/PULL session — proving the manifest path converges on the same engine.
    let exec = MockExecutor::new().on_query(
        "RETURN 1",
        CannedResult::rows(&["x"], vec![vec![Value::Integer(9)]]),
    );
    let mut input = manifest_handshake(Version::new(5, 4));
    for r in [
        hello(),
        logon_alice(),
        Request::Run {
            query: "RETURN 1".to_owned(),
            parameters: vec![],
            extra: vec![],
        },
        Request::Pull { n: ALL, qid: None },
        Request::Goodbye,
    ] {
        input.extend_from_slice(&encode_request_framed(&r).unwrap());
    }

    let auth = auth_fixture();
    let mut transport = MemoryTransport::with_input(&input);
    {
        let mut session = BoltSession::new(&mut transport, exec, &auth);
        session.run().expect("manifest session runs");
        assert_eq!(session.version(), Some(Version::new(5, 4)));
        assert_eq!(session.state(), State::Defunct);
    }

    // The server's first write is the manifest (ack 00 00 01 FF + range + capabilities), NOT a bare
    // 4-byte legacy reply.
    let written = transport.written();
    assert_eq!(
        &written[..4],
        &crate::handshake::MANIFEST_V1_REQUEST,
        "server replies with the manifest acknowledgment"
    );
    // After the manifest, the framed message stream begins. Find it: manifest is 10 bytes here
    // (ack 4 + count 1 + range 4 + caps 1). Decode the responses past it.
    let manifest_len = crate::handshake::graphus_manifest().len();
    let responses = decode_responses(&written[manifest_len..]);
    // HELLO SUCCESS, LOGON SUCCESS, RUN SUCCESS{fields}, RECORD, trailing SUCCESS.
    assert!(matches!(responses[0], Response::Success { .. }));
    assert!(
        responses
            .iter()
            .any(|r| matches!(r, Response::Record { .. }))
    );
}

#[test]
fn both_handshake_forms_reach_the_same_version() {
    // Legacy and manifest handshakes against the same fixture both negotiate 5.4.
    let auth = auth_fixture();
    let legacy_input = session_input(&[hello(), logon_alice()]);
    let mut legacy_transport = MemoryTransport::with_input(&legacy_input);
    let legacy_version = {
        let mut s = BoltSession::new(&mut legacy_transport, MockExecutor::new(), &auth);
        s.run().unwrap();
        s.version()
    };

    let mut manifest_input = manifest_handshake(Version::new(5, 4));
    for r in [hello(), logon_alice()] {
        manifest_input.extend_from_slice(&encode_request_framed(&r).unwrap());
    }
    let mut manifest_transport = MemoryTransport::with_input(&manifest_input);
    let manifest_version = {
        let mut s = BoltSession::new(&mut manifest_transport, MockExecutor::new(), &auth);
        s.run().unwrap();
        s.version()
    };

    assert_eq!(legacy_version, Some(Version::new(5, 4)));
    assert_eq!(manifest_version, legacy_version, "both forms agree on 5.4");
}

#[test]
fn manifest_client_choosing_unsupported_version_is_rejected() {
    // A manifest client that picks 5.9 (outside our window) fails the handshake.
    let input = manifest_handshake(Version::new(5, 9));
    let auth = auth_fixture();
    let mut transport = MemoryTransport::with_input(&input);
    let mut session = BoltSession::new(&mut transport, MockExecutor::new(), &auth);
    let err = session.run().unwrap_err();
    assert!(matches!(err, BoltError::Handshake(_)));
    assert_eq!(session.state(), State::Defunct);
}

#[test]
fn route_returns_a_well_formed_single_instance_routing_table() {
    let exec = MockExecutor::new();
    let mut input = handshake_54();
    for r in [
        hello(),
        logon_alice(),
        Request::Route {
            routing: vec![],
            bookmarks: vec![],
            extra: vec![("db".to_owned(), Value::String("graphus".to_owned()))],
        },
        Request::Goodbye,
    ] {
        input.extend_from_slice(&encode_request_framed(&r).unwrap());
    }

    let auth = auth_fixture();
    let mut transport = MemoryTransport::with_input(&input);
    {
        let mut session = BoltSession::with_config(
            &mut transport,
            exec,
            &auth,
            crate::server::SessionConfig {
                advertised_bolt_address: Some("graphus.example:7687".to_owned()),
                ..Default::default()
            },
        );
        session.run().unwrap();
        // ROUTE does not open a result; the connection stays usable (it ended via GOODBYE).
        assert_eq!(session.state(), State::Defunct);
    }

    let (_, stream) = split_handshake(transport.written());
    let r = decode_responses(stream);
    // HELLO SUCCESS, LOGON SUCCESS, ROUTE SUCCESS{rt}.
    let rt = match &r[2] {
        Response::Success { metadata } => metadata
            .iter()
            .find(|(k, _)| k == "rt")
            .map(|(_, v)| v)
            .expect("ROUTE SUCCESS carries an rt map"),
        other => panic!("expected ROUTE SUCCESS, got {other:?}"),
    };
    let Value::Map(rt) = rt else {
        panic!("rt must be a map, got {rt:?}");
    };
    // ttl present and matches the default.
    assert_eq!(
        rt.iter().find(|(k, _)| k == "ttl").map(|(_, v)| v),
        Some(&Value::Integer(crate::server::DEFAULT_ROUTING_TTL_SECS))
    );
    // db echoes the requested database.
    assert_eq!(
        rt.iter().find(|(k, _)| k == "db").map(|(_, v)| v),
        Some(&Value::String("graphus".to_owned()))
    );
    // servers: exactly READ, WRITE, ROUTE, all pointing at the advertised address.
    let Some((_, Value::List(servers))) = rt.iter().find(|(k, _)| k == "servers") else {
        panic!("rt.servers must be a list: {rt:?}");
    };
    assert_eq!(servers.len(), 3, "three roles on a single instance");
    let mut roles: Vec<String> = Vec::new();
    for entry in servers {
        let Value::Map(m) = entry else {
            panic!("each server entry is a map: {entry:?}");
        };
        let Some((_, Value::String(role))) = m.iter().find(|(k, _)| k == "role") else {
            panic!("server entry has a role: {m:?}");
        };
        roles.push(role.clone());
        let Some((_, Value::List(addrs))) = m.iter().find(|(k, _)| k == "addresses") else {
            panic!("server entry has addresses: {m:?}");
        };
        assert_eq!(
            addrs,
            &vec![Value::String("graphus.example:7687".to_owned())],
            "every role advertises the configured address"
        );
    }
    roles.sort();
    assert_eq!(roles, vec!["READ", "ROUTE", "WRITE"]);
}

#[test]
fn route_db_defaults_to_null_for_the_home_database() {
    // ROUTE with an empty/absent db field yields a null `db` in the table (the home database).
    let mut input = handshake_54();
    for r in [
        hello(),
        logon_alice(),
        Request::Route {
            routing: vec![],
            bookmarks: vec![],
            extra: vec![],
        },
        Request::Goodbye,
    ] {
        input.extend_from_slice(&encode_request_framed(&r).unwrap());
    }
    let auth = auth_fixture();
    let mut transport = MemoryTransport::with_input(&input);
    {
        let mut session = BoltSession::new(&mut transport, MockExecutor::new(), &auth);
        session.run().unwrap();
    }
    let (_, stream) = split_handshake(transport.written());
    let r = decode_responses(stream);
    let Response::Success { metadata } = &r[2] else {
        panic!("expected ROUTE SUCCESS, got {:?}", r[2]);
    };
    let Some((_, Value::Map(rt))) = metadata.iter().find(|(k, _)| k == "rt") else {
        panic!("rt map missing");
    };
    assert_eq!(
        rt.iter().find(|(k, _)| k == "db").map(|(_, v)| v),
        Some(&Value::Null),
        "absent db ⇒ null (home database)"
    );
    // The fallback address is well-formed even without configuration.
    let Some((_, Value::List(servers))) = rt.iter().find(|(k, _)| k == "servers") else {
        panic!("servers missing");
    };
    let Value::Map(first) = &servers[0] else {
        panic!("server entry not a map");
    };
    let Some((_, Value::List(addrs))) = first.iter().find(|(k, _)| k == "addresses") else {
        panic!("addresses missing");
    };
    assert_eq!(addrs, &vec![Value::String("localhost:7687".to_owned())]);
}

#[test]
fn telemetry_with_valid_api_is_acknowledged_with_success() {
    // TELEMETRY in READY carrying a VALID api (2 = implicit transaction) → SUCCESS, the connection
    // stays usable for a following RUN. (An INVALID api is rejected — see
    // `telemetry_with_invalid_api_is_rejected`.)
    let exec = MockExecutor::new().on_query(
        "RETURN 1",
        CannedResult::rows(&["x"], vec![vec![Value::Integer(1)]]),
    );
    let input = session_input(&[
        hello(),
        logon_alice(),
        Request::Telemetry { api: 2 },
        Request::Run {
            query: "RETURN 1".to_owned(),
            parameters: vec![],
            extra: vec![],
        },
        Request::Pull { n: ALL, qid: None },
        Request::Goodbye,
    ]);
    let auth = auth_fixture();
    let mut transport = MemoryTransport::with_input(&input);
    {
        let mut session = BoltSession::new(&mut transport, exec, &auth);
        session.run().unwrap();
        assert_eq!(session.state(), State::Defunct);
    }
    let (_, stream) = split_handshake(transport.written());
    let r = decode_responses(stream);
    // HELLO, LOGON, TELEMETRY SUCCESS, RUN SUCCESS{fields}, RECORD, trailing SUCCESS.
    assert!(
        matches!(r[2], Response::Success { .. }),
        "TELEMETRY → SUCCESS"
    );
    assert!(
        !r.iter().any(|resp| matches!(resp, Response::Failure(_))),
        "TELEMETRY with a valid api must never produce a FAILURE: {r:?}"
    );
    assert!(r.iter().any(|resp| matches!(resp, Response::Record { .. })));
}

#[test]
fn telemetry_in_authentication_is_rejected_as_wrong_state() {
    // TELEMETRY is legal ONLY in READY (Bolt 5.4+ state machine). Sent out of order in
    // AUTHENTICATION (after HELLO, before LOGON) it is a wrong-state request. Since this is BEFORE
    // authentication, the failure is TERMINAL (DEFUNCT), not a RESET-recoverable FAILED: NEGOTIATION
    // / AUTHENTICATION transition to DEFUNCT on failure and RESET is not valid pre-auth (rmp #820).
    // So the FAILURE closes the connection and the following LOGON is never processed.
    let input = session_input(&[
        hello(),
        Request::Telemetry { api: 1 },
        logon_alice(),
        Request::Goodbye,
    ]);
    let auth = auth_fixture();
    let mut transport = MemoryTransport::with_input(&input);
    {
        let mut session = BoltSession::new(&mut transport, MockExecutor::new(), &auth);
        session.run().unwrap();
        assert_eq!(session.state(), State::Defunct);
    }
    let (_, stream) = split_handshake(transport.written());
    let r = decode_responses(stream);
    // HELLO SUCCESS, TELEMETRY FAILURE (wrong state) — then the connection is closed (terminal).
    assert!(matches!(r[0], Response::Success { .. }), "HELLO → SUCCESS");
    match &r[1] {
        Response::Failure(f) => assert_eq!(f.code, "Neo.ClientError.Request.Invalid"),
        other => panic!("expected wrong-state FAILURE, got {other:?}"),
    }
    assert!(
        r.get(2).is_none(),
        "a pre-auth wrong-state FAILURE is terminal; the LOGON must never be processed: {r:?}"
    );
    assert_eq!(r.len(), 2);
}

// ---- rmp #443: absent-`n` PULL/DISCARD + invalid-`api` TELEMETRY rejection ---------------------

#[test]
fn pull_without_n_is_rejected() {
    // rmp #443 / Bolt spec (neo4j.com/docs/bolt/current/bolt/message/): for PULL "n has no default
    // and must be present." A PULL whose extra map omits `n` — the hand-framed payload B1 3F A0
    // (TINY_STRUCT-1, PULL opcode 0x3F, empty MAP A0) — must FAILURE `Neo.ClientError.Request.Invalid`
    // → FAILED and emit NO RECORD, instead of silently streaming the whole result. We inject the raw
    // payload (the typed `Request::Pull` always encodes `n`, so it cannot express this malformed
    // case). After RUN opens a stream, the no-`n` PULL is rejected at decode and the following PULL
    // is IGNORED.
    let exec = MockExecutor::new().on_query(
        "RETURN 1",
        CannedResult::rows(&["x"], vec![vec![Value::Integer(1)]]),
    );

    let mut input = handshake_54();
    input.extend_from_slice(&encode_request_framed(&hello()).unwrap());
    input.extend_from_slice(&encode_request_framed(&logon_alice()).unwrap());
    input.extend_from_slice(
        &encode_request_framed(&Request::Run {
            query: "RETURN 1".to_owned(),
            parameters: vec![],
            extra: vec![],
        })
        .unwrap(),
    );
    // The hand-framed no-`n` PULL: B1 3F A0.
    let pull_no_n = [0xB1u8, crate::message::opcode::PULL, 0xA0];
    input.extend_from_slice(&crate::framing::chunk_message(&pull_no_n));
    input.extend_from_slice(&encode_request_framed(&Request::Goodbye).unwrap());

    let auth = auth_fixture();
    let mut transport = MemoryTransport::with_input(&input);
    {
        let mut session = BoltSession::new(&mut transport, exec, &auth);
        session.run().unwrap();
        assert_eq!(session.state(), State::Defunct); // GOODBYE after the FAILURE
    }
    let (_, stream) = split_handshake(transport.written());
    let r = decode_responses(stream);
    // [0]HELLO [1]LOGON [2]RUN SUCCESS{fields} [3]FAILURE (absent n). NO RECORD must appear.
    match &r[3] {
        Response::Failure(f) => assert_eq!(f.code, "Neo.ClientError.Request.Invalid"),
        other => panic!("expected FAILURE for absent n, got {other:?}"),
    }
    assert!(
        !r.iter().any(|resp| matches!(resp, Response::Record { .. })),
        "an absent-n PULL must stream NO records: {r:?}"
    );
}

#[test]
fn telemetry_with_invalid_api_is_rejected() {
    // rmp #443 / Bolt spec: a TELEMETRY whose `api` is not a valid value (valid api ∈ {0,1,2,3}) must
    // FAILURE `Neo.ClientError.Request.Invalid` → FAILED, after which the next request is IGNORED
    // until RESET. `api: 99` is in range as an integer (so it decodes) but out of the valid
    // enumeration (so dispatch rejects it).
    let exec = MockExecutor::new().on_query(
        "RETURN 1",
        CannedResult::rows(&["x"], vec![vec![Value::Integer(1)]]),
    );
    let input = session_input(&[
        hello(),
        logon_alice(),
        Request::Telemetry { api: 99 },
        // This RUN must be IGNORED (the connection is FAILED until RESET).
        Request::Run {
            query: "RETURN 1".to_owned(),
            parameters: vec![],
            extra: vec![],
        },
        Request::Goodbye,
    ]);
    let auth = auth_fixture();
    let mut transport = MemoryTransport::with_input(&input);
    {
        let mut session = BoltSession::new(&mut transport, exec, &auth);
        session.run().unwrap();
        assert_eq!(session.state(), State::Defunct);
    }
    let (_, stream) = split_handshake(transport.written());
    let r = decode_responses(stream);
    // [0]HELLO [1]LOGON [2]TELEMETRY FAILURE (invalid api) [3]RUN IGNORED.
    match &r[2] {
        Response::Failure(f) => assert_eq!(f.code, "Neo.ClientError.Request.Invalid"),
        other => panic!("expected FAILURE for invalid TELEMETRY api, got {other:?}"),
    }
    assert!(
        matches!(r[3], Response::Ignored),
        "the request after an invalid TELEMETRY must be IGNORED (FAILED until RESET): {r:?}"
    );
}

// ---- rmp #444: GOODBYE-mid-tx rollback + RESET serial-equivalence ------------------------------

#[test]
fn goodbye_mid_tx_rolls_back_open_transaction() {
    // rmp #444 / Bolt spec: GOODBYE "interrupts the server current work if there is any." An open
    // explicit transaction is current work, so GOODBYE received mid-tx must explicitly roll it back
    // (symmetry with the EOF arm), not leave it dangling for a future executor that lacks a `Drop`
    // backstop to leak. We drive HELLO/LOGON/BEGIN/GOODBYE and assert the executor saw the
    // session-ended rollback hook fire.
    let exec = MockExecutor::new();
    let input = session_input(&[
        hello(),
        logon_alice(),
        Request::Begin { extra: vec![] },
        Request::Goodbye,
    ]);
    let auth = auth_fixture();
    let mut transport = MemoryTransport::with_input(&input);
    {
        let mut session = BoltSession::new(&mut transport, exec, &auth);
        session.run().unwrap();
        assert_eq!(session.state(), State::Defunct); // ended by GOODBYE
        // The open tx was rolled back via the session-ended hook, not left open.
        assert!(
            !session.executor().tx_open,
            "GOODBYE mid-tx must roll the open transaction back"
        );
        let log = &session.executor().log;
        assert!(
            log.contains(&"rollback_open_tx".to_owned()),
            "GOODBYE mid-tx must call the session-ended rollback hook: {log:?}"
        );
    }
}

#[test]
fn goodbye_with_no_open_tx_does_not_roll_back() {
    // Regression guard for the GOODBYE rollback (rmp #444): a clean GOODBYE in READY (no open tx)
    // must NOT spuriously invoke a rollback — the hook is a no-op when nothing is open (idempotent,
    // mirrors the EOF arm so a normal close stays cheap and side-effect-free).
    let exec = MockExecutor::new();
    let input = session_input(&[hello(), logon_alice(), Request::Goodbye]);
    let auth = auth_fixture();
    let mut transport = MemoryTransport::with_input(&input);
    {
        let mut session = BoltSession::new(&mut transport, exec, &auth);
        session.run().unwrap();
        assert_eq!(session.state(), State::Defunct);
        let log = &session.executor().log;
        assert!(
            !log.contains(&"rollback_open_tx".to_owned()),
            "a GOODBYE with no open tx must not roll anything back: {log:?}"
        );
    }
}

#[test]
fn reset_after_run_pull_clears_state_serial_equivalence() {
    // rmp #444 (RESET serial-equivalence, documented in specification/06-bolt-and-error-shapes.md):
    // Graphus processes messages serially (it has no async pipeline to interrupt), so a pipelined
    // RUN + PULL + RESET is observably equivalent to the spec's queue-jumping RESET for a lockstep
    // client: by the time RESET is processed the RUN and PULL have already completed, the result is
    // fully drained, and RESET returns the connection to a clean READY. This test PINS that chosen
    // semantics: the RUN succeeds, the PULL streams its record, RESET → SUCCESS, and a fresh RUN
    // afterwards works (the connection is cleanly READY again, no IGNORED, no leaked stream).
    let exec = MockExecutor::new()
        .on_query(
            "RETURN 1",
            CannedResult::rows(&["x"], vec![vec![Value::Integer(1)]]),
        )
        .on_query(
            "RETURN 2",
            CannedResult::rows(&["y"], vec![vec![Value::Integer(2)]]),
        );
    let input = session_input(&[
        hello(),
        logon_alice(),
        Request::Run {
            query: "RETURN 1".to_owned(),
            parameters: vec![],
            extra: vec![],
        },
        Request::Pull { n: ALL, qid: None },
        Request::Reset,
        // The connection must be cleanly READY again: this RUN must SUCCEED, not be IGNORED.
        Request::Run {
            query: "RETURN 2".to_owned(),
            parameters: vec![],
            extra: vec![],
        },
        Request::Pull { n: ALL, qid: None },
        Request::Goodbye,
    ]);
    let auth = auth_fixture();
    let mut transport = MemoryTransport::with_input(&input);
    {
        let mut session = BoltSession::new(&mut transport, exec, &auth);
        session.run().unwrap();
        assert_eq!(session.state(), State::Defunct);
    }
    let (_, stream) = split_handshake(transport.written());
    let r = decode_responses(stream);
    // [0]HELLO [1]LOGON [2]RUN1 SUCCESS{fields} [3]RECORD [4]SUMMARY [5]RESET SUCCESS
    // [6]RUN2 SUCCESS{fields} [7]RECORD [8]SUMMARY.
    assert!(
        matches!(r[5], Response::Success { .. }),
        "RESET → SUCCESS: {r:?}"
    );
    // No request after RESET is IGNORED — the connection is cleanly READY.
    assert!(
        !r.iter().any(|resp| matches!(resp, Response::Ignored)),
        "a serial RUN+PULL+RESET must leave the connection cleanly READY (no IGNORED): {r:?}"
    );
    // The post-RESET RUN streamed its own record (proving a usable READY connection).
    assert!(
        matches!(r[7], Response::Record { .. }),
        "the post-RESET RUN must stream normally: {r:?}"
    );
    assert_eq!(r.len(), 9, "exact response shape: {r:?}");
}

#[test]
fn telemetry_before_hello_is_rejected_as_wrong_state() {
    // TELEMETRY sent in CONNECTED (before HELLO) is a wrong-state request. Since this is BEFORE
    // authentication, the failure is TERMINAL (DEFUNCT), not a RESET-recoverable FAILED: NEGOTIATION
    // transitions to DEFUNCT on failure and RESET is not valid pre-auth (rmp #820). The FAILURE
    // closes the connection, so the following HELLO is never processed.
    let input = session_input(&[Request::Telemetry { api: 3 }, hello(), Request::Goodbye]);
    let auth = auth_fixture();
    let mut transport = MemoryTransport::with_input(&input);
    {
        let mut session = BoltSession::new(&mut transport, MockExecutor::new(), &auth);
        session.run().unwrap();
        assert_eq!(session.state(), State::Defunct);
    }
    let (_, stream) = split_handshake(transport.written());
    let r = decode_responses(stream);
    // TELEMETRY FAILURE (pre-HELLO) — then the connection is closed (terminal).
    match &r[0] {
        Response::Failure(f) => assert_eq!(f.code, "Neo.ClientError.Request.Invalid"),
        other => panic!("expected wrong-state FAILURE, got {other:?}"),
    }
    assert!(
        r.get(1).is_none(),
        "a pre-auth wrong-state FAILURE is terminal; the HELLO must never be processed: {r:?}"
    );
    assert_eq!(r.len(), 1);
}

#[test]
fn pull_and_discard_reject_out_of_range_n() {
    // The only legal `n` values are -1 (all) or a strictly positive integer. `n == 0` and `n < -1`
    // are rejected with FAILURE (`Neo.ClientError.Request.Invalid`) → FAILED, matching the Neo4j
    // reference server, rather than silently fetching nothing or "all".
    for bad_n in [0_i64, -2, -100] {
        for emit in [true, false] {
            let exec = MockExecutor::new().on_query(
                "RETURN 1",
                CannedResult::rows(&["x"], vec![vec![Value::Integer(1)]]),
            );
            let req = if emit {
                Request::Pull {
                    n: bad_n,
                    qid: None,
                }
            } else {
                Request::Discard {
                    n: bad_n,
                    qid: None,
                }
            };
            let input = session_input(&[
                hello(),
                logon_alice(),
                Request::Run {
                    query: "RETURN 1".to_owned(),
                    parameters: vec![],
                    extra: vec![],
                },
                req,
                Request::Goodbye,
            ]);
            let auth = auth_fixture();
            let mut transport = MemoryTransport::with_input(&input);
            {
                let mut session = BoltSession::new(&mut transport, exec, &auth);
                session.run().unwrap();
            }
            let (_, stream) = split_handshake(transport.written());
            let r = decode_responses(stream);
            // HELLO SUCCESS, LOGON SUCCESS, RUN SUCCESS{fields}, PULL/DISCARD FAILURE.
            match &r[3] {
                Response::Failure(f) => assert_eq!(
                    f.code, "Neo.ClientError.Request.Invalid",
                    "n={bad_n} emit={emit} must FAIL as out-of-range"
                ),
                other => panic!("n={bad_n} emit={emit}: expected FAILURE, got {other:?}"),
            }
            // No RECORD was emitted before the rejection.
            assert!(
                !r.iter().any(|resp| matches!(resp, Response::Record { .. })),
                "n={bad_n} emit={emit}: out-of-range PULL/DISCARD must not stream records"
            );
        }
    }
}

#[test]
fn connection_id_is_unique_per_session_and_surfaced_in_hello() {
    // Two sessions configured with distinct connection ids must each report their own in HELLO.
    fn hello_connection_id(conn_id: &str) -> String {
        let input = session_input(&[hello(), Request::Goodbye]);
        let auth = auth_fixture();
        let mut transport = MemoryTransport::with_input(&input);
        {
            let mut session = BoltSession::with_config(
                &mut transport,
                MockExecutor::new(),
                &auth,
                crate::server::SessionConfig {
                    connection_id: conn_id.to_owned(),
                    ..Default::default()
                },
            );
            session.run().unwrap();
        }
        let (_, stream) = split_handshake(transport.written());
        let r = decode_responses(stream);
        match &r[0] {
            Response::Success { metadata } => metadata
                .iter()
                .find(|(k, _)| k == "connection_id")
                .map(|(_, v)| match v {
                    Value::String(s) => s.clone(),
                    other => panic!("connection_id must be a string, got {other:?}"),
                })
                .expect("HELLO SUCCESS carries connection_id"),
            other => panic!("expected HELLO SUCCESS, got {other:?}"),
        }
    }

    let a = hello_connection_id("bolt-7");
    let b = hello_connection_id("bolt-42");
    assert_eq!(a, "bolt-7");
    assert_eq!(b, "bolt-42");
    assert_ne!(a, b, "per-connection ids are distinct");
}

#[test]
fn hello_reports_the_server_agent_and_hints() {
    // HELLO SUCCESS carries a Graphus server agent and a hints map (drivers probe both).
    let input = session_input(&[hello(), Request::Goodbye]);
    let auth = auth_fixture();
    let mut transport = MemoryTransport::with_input(&input);
    {
        let mut session = BoltSession::new(&mut transport, MockExecutor::new(), &auth);
        session.run().unwrap();
    }
    let (_, stream) = split_handshake(transport.written());
    let r = decode_responses(stream);
    let Response::Success { metadata } = &r[0] else {
        panic!("expected HELLO SUCCESS, got {:?}", r[0]);
    };
    match metadata.iter().find(|(k, _)| k == "server").map(|(_, v)| v) {
        Some(Value::String(s)) => assert!(s.starts_with("Graphus/"), "server agent: {s}"),
        other => panic!("server agent missing/!string: {other:?}"),
    }
    assert!(
        metadata
            .iter()
            .any(|(k, v)| k == "hints" && matches!(v, Value::Map(_))),
        "hints map present: {metadata:?}"
    );
}

#[test]
fn hello_honors_overridden_server_agent() {
    // The listener can override the `server` agent (rmp #614, opt-in Neo4j-compat mode): a custom
    // SessionConfig.server_agent is announced in HELLO SUCCESS verbatim, replacing the Graphus default.
    let input = session_input(&[hello(), Request::Goodbye]);
    let auth = auth_fixture();
    let mut transport = MemoryTransport::with_input(&input);
    {
        let mut session = BoltSession::with_config(
            &mut transport,
            MockExecutor::new(),
            &auth,
            crate::server::SessionConfig {
                server_agent: crate::server::NEO4J_COMPAT_SERVER_AGENT.to_owned(),
                ..Default::default()
            },
        );
        session.run().unwrap();
    }
    let (_, stream) = split_handshake(transport.written());
    let r = decode_responses(stream);
    let Response::Success { metadata } = &r[0] else {
        panic!("expected HELLO SUCCESS, got {:?}", r[0]);
    };
    match metadata.iter().find(|(k, _)| k == "server").map(|(_, v)| v) {
        Some(Value::String(s)) => assert_eq!(s, "Neo4j/5.13.0", "overridden server agent: {s}"),
        other => panic!("server agent missing/!string: {other:?}"),
    }
}

#[test]
fn neo4j_compat_agent_matches_negotiated_bolt_window() {
    // The Neo4j-compat agent (rmp #614) must announce a Neo4j version whose *native* Bolt maximum
    // equals the Bolt version Graphus negotiates. Graphus pins MAX_MINOR = 4 (Bolt 5.4); per the
    // official Bolt compatibility matrix Bolt 5.4 ⇒ Neo4j 5.13–5.22, and we announce the 5.13.0 floor.
    // These two constants live in different modules with nothing else coupling them — this test makes
    // a future MAX_MINOR bump fail LOUDLY here, forcing a conscious re-selection of the compat version
    // (a stale higher/lower Neo4j version would misrepresent the capabilities Graphus actually serves).
    assert_eq!(
        crate::handshake::MAX_MINOR,
        4,
        "Bolt max minor changed — re-select NEO4J_COMPAT_SERVER_AGENT against the Bolt↔Neo4j matrix"
    );
    assert_eq!(crate::server::NEO4J_COMPAT_SERVER_AGENT, "Neo4j/5.13.0");
}

// ---- Bolt LOGON per-account throttle (rmp #458/#823) ------------------------------------------

use graphus_auth::AuthProvider;
use graphus_auth::AuthThrottle;
use graphus_core::capability::Clock;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

/// An [`AuthProvider`] that delegates to a real [`Authenticator`] but **counts** every call to
/// `authenticate_password` — i.e. every time the memory-hard Argon2 KDF is invoked (the KDF lives
/// strictly inside that call). The Bolt `LOGON` throttle (rmp #823) must reject a spent-budget account
/// *before* this call, so a flat count across the throttled attempt is a direct, non-vacuous proof
/// that "the KDF did not run" — the same property graphus-auth's own `#[cfg(test)] KDF_VERIFY_COUNT`
/// seam proves, but reachable here (that thread-local is invisible cross-crate).
struct CountingAuth {
    inner: Authenticator,
    kdf_calls: AtomicUsize,
}

impl CountingAuth {
    fn new(inner: Authenticator) -> Self {
        Self {
            inner,
            kdf_calls: AtomicUsize::new(0),
        }
    }
    fn kdf_calls(&self) -> usize {
        self.kdf_calls.load(Ordering::SeqCst)
    }
}

impl AuthProvider for CountingAuth {
    fn authenticate_password(&self, user: &str, plaintext: &str) -> graphus_auth::Result<String> {
        self.kdf_calls.fetch_add(1, Ordering::SeqCst);
        self.inner.authenticate_password(user, plaintext)
    }
    fn authenticate_bearer(
        &self,
        token: &str,
        now_unix_secs: u64,
    ) -> graphus_auth::Result<graphus_auth::Claims> {
        self.inner.authenticate_bearer(token, now_unix_secs)
    }
    fn require(&self, user: &str, wanted: &Privilege) -> graphus_auth::Result<()> {
        self.inner.require(user, wanted)
    }
    fn issue_token(
        &self,
        user: &str,
        now_unix_secs: u64,
        ttl_secs: u64,
    ) -> graphus_auth::Result<String> {
        self.inner.issue_token(user, now_unix_secs, ttl_secs)
    }
}

/// A deterministic, manually-advanced [`Clock`] for the throttle window — no wall time (the project
/// rule: throttle behaviour is a pure function of injected clock readings).
struct TestClock {
    nanos: AtomicU64,
}

impl TestClock {
    fn new() -> Self {
        Self {
            nanos: AtomicU64::new(0),
        }
    }
    fn advance_secs(&self, secs: u64) {
        self.nanos
            .fetch_add(secs.saturating_mul(1_000_000_000), Ordering::SeqCst);
    }
}

impl Clock for TestClock {
    fn now_nanos(&self) -> u64 {
        self.nanos.load(Ordering::SeqCst)
    }
}

/// Drives ONE bad `LOGON` for `principal` on a fresh session sharing `auth` + `throttle`, returning
/// the decoded responses. A failed pre-auth `LOGON` is terminal (rmp #820), so each attempt is a fresh
/// connection — exactly how the throttle accrues across reconnects in production.
fn drive_bad_logon(
    auth: &CountingAuth,
    throttle: &LoginThrottle,
    principal: &str,
) -> Vec<Response> {
    let input = session_input(&[
        hello(),
        Request::Logon {
            auth: vec![
                ("scheme".to_owned(), Value::String("basic".to_owned())),
                ("principal".to_owned(), Value::String(principal.to_owned())),
                (
                    "credentials".to_owned(),
                    Value::String("WRONG-pw".to_owned()),
                ),
            ],
        },
    ]);
    let mut transport = MemoryTransport::with_input(&input);
    {
        let mut session = BoltSession::new(&mut transport, MockExecutor::new(), auth)
            .with_login_throttle(throttle.clone());
        session.run().unwrap();
        assert_eq!(session.principal(), None);
        assert_eq!(
            session.state(),
            State::Defunct,
            "a failed LOGON is terminal (rmp #820) — one attempt per connection"
        );
    }
    let (_, stream) = split_handshake(transport.written());
    decode_responses(stream)
}

#[test]
fn bolt_logon_consults_the_shared_per_account_throttle_before_the_kdf() {
    // rmp #823 (security audit Finding 2): the Bolt `LOGON` path MUST consult the SAME per-account
    // failed-login throttle as REST `/auth/login`, so an attacker cannot pick the Bolt interface to
    // sidestep the per-account lockout (CWE-307). Proven via `CountingAuth` (the KDF lives strictly
    // inside `authenticate_password`), so a flat call-count across the throttled attempt proves the
    // KDF did not run — the assertion that is RED without the `authenticate` throttle check.
    const MAX: u32 = 3; // a small budget keeps the test cheap; the mechanism is identical at 5.
    let auth = CountingAuth::new(auth_fixture());
    let clock = Arc::new(TestClock::new());
    let throttle = LoginThrottle::new(
        Arc::new(AuthThrottle::new(MAX, 1).expect("non-zero limits")),
        clock.clone(),
    );

    // The first MAX bad LOGONs for `alice` each run the KDF and each FAIL; the shared throttle accrues
    // those failures across the reconnects.
    for i in 0..MAX {
        let before = auth.kdf_calls();
        let r = drive_bad_logon(&auth, &throttle, "alice");
        assert!(
            matches!(r[1], Response::Failure(_)),
            "attempt {i}: a wrong password must FAIL"
        );
        assert_eq!(
            auth.kdf_calls(),
            before + 1,
            "attempt {i}: the KDF must run while the account still has failure budget"
        );
    }

    // The (MAX+1)th LOGON for `alice`: the bucket is empty, so the throttle rejects it BEFORE the KDF.
    let before = auth.kdf_calls();
    let r = drive_bad_logon(&auth, &throttle, "alice");
    match &r[1] {
        Response::Failure(f) => assert_eq!(
            f.code, CODE_UNAUTHORIZED,
            "a throttled LOGON returns the SAME Unauthorized as a wrong password (no oracle)"
        ),
        other => panic!("expected an Unauthorized FAILURE, got {other:?}"),
    }
    assert_eq!(
        auth.kdf_calls(),
        before,
        "the throttled LOGON MUST be rejected BEFORE the Argon2 KDF runs (rmp #823)"
    );

    // Key derivation matches REST — PER-ACCOUNT: a DIFFERENT principal is unaffected by alice's spent
    // budget, so its first attempt still runs the KDF (the throttle is not a global gate).
    let before = auth.kdf_calls();
    let _ = drive_bad_logon(&auth, &throttle, "bob");
    assert_eq!(
        auth.kdf_calls(),
        before + 1,
        "a different account is keyed independently, not globally throttled"
    );

    // A CORRECT credential still authenticates once the account's bucket refills (success is never
    // throttled): advance the injected clock past the refill window so alice's bucket recovers.
    clock.advance_secs(u64::from(MAX) + 1);
    let input = session_input(&[hello(), logon_alice()]);
    let mut transport = MemoryTransport::with_input(&input);
    {
        let mut session = BoltSession::new(&mut transport, MockExecutor::new(), &auth)
            .with_login_throttle(throttle.clone());
        session.run().unwrap();
        // The session ends `Defunct` on EOF (no further messages), so the proof of a successful LOGON
        // is the resolved principal (retained past the EOF) plus the `SUCCESS` on the wire below.
        assert_eq!(
            session.principal(),
            Some("alice"),
            "a correct credential still authenticates after the throttle window refills"
        );
    }
    let (_, stream) = split_handshake(transport.written());
    let r = decode_responses(stream);
    assert!(
        matches!(r[0], Response::Success { .. }),
        "HELLO must succeed"
    );
    assert!(
        matches!(r[1], Response::Success { .. }),
        "the LOGON must SUCCEED after the throttle refills (success is never throttled): {r:?}"
    );
}

// ---- Bolt LOGON global concurrent-verification bound (rmp #824) --------------------------------

use graphus_auth::VerifyLimiter;

/// Drives ONE `LOGON` (`principal`/`password`) on a fresh session wired with `verify_limiter` (no
/// per-account throttle — this isolates the GLOBAL verification bound), over the shared counting
/// `auth`, returning the decoded responses.
fn drive_logon_with_limiter(
    auth: &CountingAuth,
    verify_limiter: Arc<VerifyLimiter>,
    principal: &str,
    password: &str,
) -> Vec<Response> {
    let input = session_input(&[
        hello(),
        Request::Logon {
            auth: vec![
                ("scheme".to_owned(), Value::String("basic".to_owned())),
                ("principal".to_owned(), Value::String(principal.to_owned())),
                ("credentials".to_owned(), Value::String(password.to_owned())),
            ],
        },
    ]);
    let mut transport = MemoryTransport::with_input(&input);
    {
        let mut session = BoltSession::new(&mut transport, MockExecutor::new(), auth)
            .with_verify_limiter(verify_limiter);
        session.run().unwrap();
    }
    let (_, stream) = split_handshake(transport.written());
    decode_responses(stream)
}

#[test]
fn bolt_logon_sheds_before_the_kdf_when_the_global_verify_bound_is_saturated() {
    // rmp #824 (security audit Finding 1): when the GLOBAL concurrent-verification bound is saturated, a
    // Bolt `LOGON` is shed with a transient FAILURE BEFORE the Argon2 KDF — and the shed is BYTE-IDENTICAL
    // for a valid vs an invalid username (no enumeration oracle; preserves rmp #812's constant work).
    // Proven via `CountingAuth` (the KDF lives strictly inside `authenticate_password`) and a shared
    // `VerifyLimiter` whose K slots are pre-held to model K verifications already in flight. This is the
    // assertion that is RED without the `authenticate` acquire (the shed would still run the KDF).
    const K: usize = 2;
    let auth = CountingAuth::new(auth_fixture());
    let limiter = Arc::new(VerifyLimiter::new(K));

    // Saturate the bound: hold all K permits (K verifications "in flight").
    let held: Vec<_> = (0..K)
        .map(|_| limiter.try_acquire().expect("within cap"))
        .collect();
    assert_eq!(limiter.in_flight(), K);

    // A LOGON with a VALID username is shed with the transient busy code, WITHOUT running the KDF.
    let before = auth.kdf_calls();
    let valid = drive_logon_with_limiter(&auth, Arc::clone(&limiter), "alice", "alice-pw");
    match &valid[1] {
        Response::Failure(f) => assert_eq!(
            f.code, CODE_SERVER_BUSY,
            "a saturated-bound shed carries the transient busy code"
        ),
        other => panic!("expected a busy FAILURE, got {other:?}"),
    }
    assert_eq!(
        auth.kdf_calls(),
        before,
        "a shed LOGON must NOT run the Argon2 KDF (rmp #824)"
    );

    // A LOGON with an INVALID username is shed IDENTICALLY — the rmp #812 constant-work invariant at the
    // shed: a valid vs an invalid username are byte-indistinguishable (same code + message, no KDF).
    let before = auth.kdf_calls();
    let invalid = drive_logon_with_limiter(&auth, Arc::clone(&limiter), "ghost", "any-password");
    match &invalid[1] {
        Response::Failure(f) => assert_eq!(f.code, CODE_SERVER_BUSY),
        other => panic!("expected a busy FAILURE, got {other:?}"),
    }
    assert_eq!(
        auth.kdf_calls(),
        before,
        "the shed is username-independent — no KDF for an unknown user either (no oracle)"
    );
    assert_eq!(
        valid[1], invalid[1],
        "a valid vs invalid username must shed BYTE-IDENTICALLY (rmp #812 constant work)"
    );

    // Free the slots: a subsequent LOGON is admitted to the KDF again and a correct credential succeeds.
    drop(held);
    assert_eq!(limiter.in_flight(), 0);
    let before = auth.kdf_calls();
    let ok = drive_logon_with_limiter(&auth, Arc::clone(&limiter), "alice", "alice-pw");
    assert!(
        matches!(ok[1], Response::Success { .. }),
        "a correct credential authenticates once verification capacity frees: {ok:?}"
    );
    assert_eq!(
        auth.kdf_calls(),
        before + 1,
        "the admitted LOGON ran exactly one KDF"
    );
}

// ---- Bolt 5.0 HELLO-carried authentication + per-version decodability (rmp #906) ---------------
//
// Bolt 5.1 is where authentication moved out of `HELLO` into `LOGON` (server-state spec, "Summary of
// changes": Version 5.1 — "HELLO message no longer accepts authentication … LOGON message has been
// added"; Version 5.0 — "No changes compared to version 4.4"). Graphus advertises 5.0 in both
// handshake forms, so it MUST serve the 5.0 flow: HELLO authenticates and lands in READY, and
// LOGON/LOGOFF are not even decodable. These tests drive whole sessions at an exact negotiated minor.

/// Client handshake bytes proposing **exactly** `Version::new(5, minor)` (range 0, one slot).
fn handshake_at(minor: u8) -> Vec<u8> {
    encode_client_handshake([
        Proposal::exact(5, minor),
        Proposal::exact(0, 0),
        Proposal::exact(0, 0),
        Proposal::exact(0, 0),
    ])
}

/// An input byte stream that negotiates exactly Bolt 5.`minor`, then frames each request.
fn session_input_at(minor: u8, requests: &[Request]) -> Vec<u8> {
    let mut input = handshake_at(minor);
    for r in requests {
        input.extend_from_slice(&encode_request_framed(r).unwrap());
    }
    input
}

/// A Bolt **5.0** `HELLO`: the required `user_agent` **plus** the authentication token, which at 5.0
/// rides in the `HELLO` `extra` map itself. Also carries the reserved non-auth field `patch_bolt`, to
/// prove it is filtered out of the token rather than fed to the authenticator as a credential.
fn hello_50(principal: &str, credentials: &str) -> Request {
    Request::Hello {
        extra: vec![
            ("user_agent".to_owned(), Value::String("drv/1".to_owned())),
            (
                "patch_bolt".to_owned(),
                Value::List(vec![Value::String("utc".to_owned())]),
            ),
            ("scheme".to_owned(), Value::String("basic".to_owned())),
            ("principal".to_owned(), Value::String(principal.to_owned())),
            (
                "credentials".to_owned(),
                Value::String(credentials.to_owned()),
            ),
        ],
    }
}

#[test]
fn bolt_50_authenticates_from_hello_and_runs_a_query() {
    // ACCEPTANCE 1 (rmp #906): a client negotiating exactly 5.0 authenticates from its HELLO and can
    // RUN. Before the fix, HELLO always routed to AUTHENTICATION and read only `user_agent`, so the
    // credentials were dropped on the floor and the first RUN hit `unexpected` → FAILURE + DEFUNCT:
    // EVERY negotiated-5.0 connection was dead on arrival.
    let exec = MockExecutor::new().on_query(
        "RETURN 1 AS x",
        CannedResult::rows(&["x"], vec![vec![Value::Integer(1)]]),
    );
    let input = session_input_at(
        0,
        &[
            hello_50("alice", "alice-pw"),
            Request::Run {
                query: "RETURN 1 AS x".to_owned(),
                parameters: vec![],
                extra: vec![],
            },
            Request::Pull { n: ALL, qid: None },
            Request::Goodbye,
        ],
    );

    let auth = auth_fixture();
    let mut transport = MemoryTransport::with_input(&input);
    {
        let mut session = BoltSession::new(&mut transport, exec, &auth);
        session.run().expect("session runs");
        assert_eq!(
            session.version(),
            Some(Version::new(5, 0)),
            "negotiated 5.0"
        );
        assert_eq!(
            session.principal(),
            Some("alice"),
            "the HELLO credentials must authenticate the connection at 5.0"
        );
        assert_eq!(session.state(), State::Defunct, "ended by GOODBYE");
    }

    let written = transport.written();
    let (hs, stream) = split_handshake(written);
    assert_eq!(hs, [0x00, 0x00, 0x00, 0x05], "server replied 5.0");

    let r = decode_responses(stream);
    // HELLO→SUCCESS (negotiation AND authentication ack), RUN→SUCCESS{fields}, RECORD, trailing
    // SUCCESS. There is no LOGON SUCCESS at 5.0 — the HELLO SUCCESS is the only handshake reply.
    assert_eq!(r.len(), 4, "responses: {r:?}");
    assert!(
        !r.iter().any(|resp| matches!(resp, Response::Failure(_))),
        "a healthy 5.0 session must produce no FAILURE: {r:?}"
    );
    // The 5.0 HELLO SUCCESS carries the SAME metadata as the 5.1+ one.
    match &r[0] {
        Response::Success { metadata } => {
            let keys: Vec<&str> = metadata.iter().map(|(k, _)| k.as_str()).collect();
            assert!(keys.contains(&"server"), "metadata: {metadata:?}");
            assert!(keys.contains(&"connection_id"), "metadata: {metadata:?}");
            assert!(keys.contains(&"hints"), "metadata: {metadata:?}");
        }
        other => panic!("expected HELLO SUCCESS, got {other:?}"),
    }
    match &r[1] {
        Response::Success { metadata } => {
            assert!(metadata.iter().any(|(k, _)| k == "fields"));
        }
        other => panic!("expected RUN SUCCESS, got {other:?}"),
    }
    assert!(matches!(r[2], Response::Record { .. }));
    assert!(matches!(r[3], Response::Success { .. }));
}

#[test]
fn bolt_50_hello_with_wrong_credentials_fails_terminally() {
    // The 5.0 HELLO is a PRE-authentication message, so a rejected credential is terminal (DEFUNCT),
    // exactly like a rejected 5.1+ LOGON — never the RESET-recoverable FAILED state (rmp #820).
    let input = session_input_at(
        0,
        &[
            hello_50("alice", "WRONG-pw"),
            Request::Run {
                query: "RETURN 1".to_owned(),
                parameters: vec![],
                extra: vec![],
            },
        ],
    );
    let auth = auth_fixture();
    let mut transport = MemoryTransport::with_input(&input);
    {
        let mut session = BoltSession::new(&mut transport, MockExecutor::new(), &auth);
        session.run().unwrap();
        assert_eq!(session.principal(), None);
        assert_eq!(session.state(), State::Defunct);
    }
    let (_, stream) = split_handshake(transport.written());
    let r = decode_responses(stream);
    match &r[0] {
        Response::Failure(f) => assert_eq!(f.code, CODE_UNAUTHORIZED),
        other => panic!("expected an Unauthorized FAILURE, got {other:?}"),
    }
    assert_eq!(
        r.len(),
        1,
        "a failed 5.0 HELLO is terminal; the RUN must never be processed: {r:?}"
    );
}

#[test]
fn bolt_50_hello_without_user_agent_is_still_rejected_before_any_credential() {
    // The `user_agent` requirement is version-independent, and it is checked BEFORE the credentials,
    // so a malformed 5.0 HELLO never reaches the authenticator. `CountingAuth` proves the KDF is
    // untouched.
    let auth = CountingAuth::new(auth_fixture());
    let input = session_input_at(
        0,
        &[Request::Hello {
            extra: vec![
                ("scheme".to_owned(), Value::String("basic".to_owned())),
                ("principal".to_owned(), Value::String("alice".to_owned())),
                (
                    "credentials".to_owned(),
                    Value::String("alice-pw".to_owned()),
                ),
            ],
        }],
    );
    let mut transport = MemoryTransport::with_input(&input);
    {
        let mut session = BoltSession::new(&mut transport, MockExecutor::new(), &auth);
        session.run().unwrap();
        assert_eq!(session.state(), State::Defunct);
        assert_eq!(session.principal(), None);
    }
    assert_eq!(
        auth.kdf_calls(),
        0,
        "a HELLO missing `user_agent` must be refused BEFORE the credentials are looked at"
    );
    let (_, stream) = split_handshake(transport.written());
    match &decode_responses(stream)[0] {
        Response::Failure(f) => assert_eq!(f.code, "Neo.ClientError.Request.Invalid"),
        other => panic!("expected a malformed-HELLO FAILURE, got {other:?}"),
    }
}

#[test]
fn bolt_50_rejects_logon_as_an_undefined_message() {
    // ACCEPTANCE 2 (rmp #906): LOGON does not exist at 5.0 — the Neo4j reference server unregisters
    // its decoder entirely (`BoltProtocolV50.createRequestMessageRegistry`). Graphus must therefore
    // reject it as an UNDECODABLE message for the negotiated version, not act on it.
    //
    // (a) POST-authentication (the realistic case: a 5.0 session is READY straight after HELLO). A
    //     post-auth malformed message is the recoverable FAILED state, and RESET clears it.
    let exec = MockExecutor::new().on_query(
        "RETURN 1",
        CannedResult::rows(&["x"], vec![vec![Value::Integer(1)]]),
    );
    let input = session_input_at(
        0,
        &[
            hello_50("alice", "alice-pw"),
            logon_alice(),
            Request::Reset,
            Request::Run {
                query: "RETURN 1".to_owned(),
                parameters: vec![],
                extra: vec![],
            },
            Request::Pull { n: ALL, qid: None },
            Request::Goodbye,
        ],
    );
    let auth = auth_fixture();
    let mut transport = MemoryTransport::with_input(&input);
    {
        let mut session = BoltSession::new(&mut transport, exec, &auth);
        session.run().unwrap();
        assert_eq!(session.state(), State::Defunct, "ended by GOODBYE");
    }
    let (_, stream) = split_handshake(transport.written());
    let r = decode_responses(stream);
    assert!(
        matches!(r[0], Response::Success { .. }),
        "HELLO authenticates"
    );
    match &r[1] {
        Response::Failure(f) => {
            assert_eq!(f.code, "Neo.ClientError.Request.Invalid");
            assert!(
                f.message.contains("not defined by Bolt 5.0"),
                "the FAILURE must say the message does not exist at this version: {f:?}"
            );
        }
        other => panic!("expected an undecodable-message FAILURE, got {other:?}"),
    }
    assert!(matches!(r[2], Response::Success { .. }), "RESET recovers");
    assert!(matches!(r[3], Response::Success { .. }), "RUN after RESET");
    assert!(matches!(r[4], Response::Record { .. }));

    // (b) PRE-authentication: a LOGON as the very first message is refused the same way, and being
    //     pre-auth it is TERMINAL (rmp #820) — it can never authenticate the connection.
    let input = session_input_at(0, &[logon_alice(), hello_50("alice", "alice-pw")]);
    let mut transport = MemoryTransport::with_input(&input);
    {
        let mut session = BoltSession::new(&mut transport, MockExecutor::new(), &auth);
        session.run().unwrap();
        assert_eq!(session.state(), State::Defunct);
        assert_eq!(session.principal(), None);
    }
    let (_, stream) = split_handshake(transport.written());
    let r = decode_responses(stream);
    match &r[0] {
        Response::Failure(f) => assert_eq!(f.code, "Neo.ClientError.Request.Invalid"),
        other => panic!("expected an undecodable-message FAILURE, got {other:?}"),
    }
    assert_eq!(r.len(), 1, "a pre-auth failure is terminal: {r:?}");
}

#[test]
fn bolt_50_rejects_logoff_as_an_undefined_message() {
    // LOGOFF shares LOGON's 5.1 introduction and the reference's `unregister`, so at 5.0 it too is
    // undecodable. It must NOT drop the principal or move the session to AUTHENTICATION — that state
    // is unreachable at 5.0, where there is no LOGON to get back out of it.
    let exec = MockExecutor::new().on_query(
        "RETURN 1",
        CannedResult::rows(&["x"], vec![vec![Value::Integer(1)]]),
    );
    let input = session_input_at(
        0,
        &[
            hello_50("alice", "alice-pw"),
            Request::Logoff,
            Request::Reset,
            Request::Run {
                query: "RETURN 1".to_owned(),
                parameters: vec![],
                extra: vec![],
            },
            Request::Pull { n: ALL, qid: None },
            Request::Goodbye,
        ],
    );
    let auth = auth_fixture();
    let mut transport = MemoryTransport::with_input(&input);
    {
        let mut session = BoltSession::new(&mut transport, exec, &auth);
        session.run().unwrap();
        assert_eq!(
            session.principal(),
            Some("alice"),
            "an undecodable LOGOFF must NOT drop the authenticated identity"
        );
    }
    let (_, stream) = split_handshake(transport.written());
    let r = decode_responses(stream);
    match &r[1] {
        Response::Failure(f) => {
            assert_eq!(f.code, "Neo.ClientError.Request.Invalid");
            assert!(
                f.message.contains("not defined by Bolt 5.0"),
                "the FAILURE must say the message does not exist at this version: {f:?}"
            );
        }
        other => panic!("expected an undecodable-message FAILURE, got {other:?}"),
    }
    // Post-authentication the refusal is the RECOVERABLE `FAILED` state, not a state change and not
    // a closed connection: RESET clears it and the session keeps serving.
    assert!(matches!(r[2], Response::Success { .. }), "RESET recovers");
    assert!(matches!(r[3], Response::Success { .. }), "RUN after RESET");
    assert!(matches!(r[4], Response::Record { .. }));
}

#[test]
fn bolt_51_still_requires_logon_and_never_authenticates_from_hello() {
    // ACCEPTANCE 3 (rmp #906): 5.1+ behaviour is unchanged. A HELLO — even one that (wrongly) carries
    // credentials — only negotiates: the session goes to AUTHENTICATION with NO principal, and a RUN
    // before the LOGON is a terminal pre-auth failure.
    let input = session_input_at(
        1,
        &[
            hello_50("alice", "alice-pw"), // credentials in HELLO: ignored at 5.1+
            Request::Run {
                query: "RETURN 1".to_owned(),
                parameters: vec![],
                extra: vec![],
            },
        ],
    );
    let auth = auth_fixture();
    let mut transport = MemoryTransport::with_input(&input);
    {
        let mut session = BoltSession::new(&mut transport, MockExecutor::new(), &auth);
        session.run().unwrap();
        assert_eq!(session.version(), Some(Version::new(5, 1)));
        assert_eq!(
            session.principal(),
            None,
            "a 5.1 HELLO must NEVER authenticate, whatever it carries"
        );
        assert_eq!(session.state(), State::Defunct);
    }
    let (_, stream) = split_handshake(transport.written());
    let r = decode_responses(stream);
    assert!(matches!(r[0], Response::Success { .. }), "HELLO → SUCCESS");
    match &r[1] {
        Response::Failure(f) => assert_eq!(f.code, "Neo.ClientError.Request.Invalid"),
        other => panic!("expected a pre-auth wrong-state FAILURE, got {other:?}"),
    }
    assert_eq!(r.len(), 2, "pre-auth failures are terminal: {r:?}");

    // The full 5.1 flow still works end to end: HELLO → LOGON → RUN → PULL.
    let exec = MockExecutor::new().on_query(
        "RETURN 1",
        CannedResult::rows(&["x"], vec![vec![Value::Integer(1)]]),
    );
    let input = session_input_at(
        1,
        &[
            hello(),
            logon_alice(),
            Request::Run {
                query: "RETURN 1".to_owned(),
                parameters: vec![],
                extra: vec![],
            },
            Request::Pull { n: ALL, qid: None },
            Request::Goodbye,
        ],
    );
    let mut transport = MemoryTransport::with_input(&input);
    {
        let mut session = BoltSession::new(&mut transport, exec, &auth);
        session.run().unwrap();
        assert_eq!(session.principal(), Some("alice"));
    }
    let (_, stream) = split_handshake(transport.written());
    let r = decode_responses(stream);
    // HELLO SUCCESS, LOGON SUCCESS, RUN SUCCESS{fields}, RECORD, trailing SUCCESS.
    assert_eq!(r.len(), 5, "responses: {r:?}");
    assert!(!r.iter().any(|resp| matches!(resp, Response::Failure(_))));

    // ...and LOGOFF (a 5.1 message) is still honoured at 5.1, returning to AUTHENTICATION.
    let input = session_input_at(1, &[hello(), logon_alice(), Request::Logoff]);
    let mut transport = MemoryTransport::with_input(&input);
    {
        let mut session = BoltSession::new(&mut transport, MockExecutor::new(), &auth);
        session.run().unwrap();
        assert_eq!(
            session.principal(),
            None,
            "LOGOFF drops the identity at 5.1"
        );
    }
    let (_, stream) = split_handshake(transport.written());
    let r = decode_responses(stream);
    assert!(
        matches!(r[2], Response::Success { .. }),
        "LOGOFF is a valid 5.1 message: {r:?}"
    );
}

#[test]
fn telemetry_is_undecodable_below_5_4_and_accepted_at_5_4() {
    // The reference server registers `TelemetryMessageDecoder` only from `BoltProtocolV54`; v50–v53
    // unregister it. So a TELEMETRY in READY is an undecodable message below 5.4 — and the same
    // message becomes a plain SUCCESS at 5.4. Driven at 5.3 (the highest minor that still lacks it)
    // and at 5.4, over the same authenticated flow, so ONLY the negotiated version differs.
    let auth = auth_fixture();
    for (minor, expect_success) in [(3u8, false), (4u8, true)] {
        let input = session_input_at(
            minor,
            &[hello(), logon_alice(), Request::Telemetry { api: 2 }],
        );
        let mut transport = MemoryTransport::with_input(&input);
        {
            let mut session = BoltSession::new(&mut transport, MockExecutor::new(), &auth);
            session.run().unwrap();
        }
        let (_, stream) = split_handshake(transport.written());
        let r = decode_responses(stream);
        if expect_success {
            assert!(
                matches!(r[2], Response::Success { .. }),
                "TELEMETRY must be accepted at 5.{minor}: {r:?}"
            );
        } else {
            match &r[2] {
                Response::Failure(f) => {
                    assert_eq!(f.code, "Neo.ClientError.Request.Invalid");
                    assert!(
                        f.message.contains("TELEMETRY")
                            && f.message.contains(&format!("Bolt 5.{minor}")),
                        "the FAILURE must name the message and the version: {f:?}"
                    );
                }
                other => panic!("TELEMETRY must be undecodable at 5.{minor}, got {other:?}"),
            }
        }
    }
}

#[test]
fn max_protocol_minor_caps_both_handshake_forms_and_serves_the_capped_version() {
    // The ratified `bolt_max_protocol_minor` option (rmp #906) reaches the session through
    // `SessionConfig`. A capped session must (a) reply with the cap even though the client offered
    // more, on BOTH handshake forms, and (b) then serve that version's flow — here the 5.0
    // HELLO-carried authentication, driven by a client that had asked for 5.0..=5.4.
    let capped = SessionConfig {
        max_protocol_minor: 0,
        ..SessionConfig::default()
    };
    let auth = auth_fixture();
    let requests = [hello_50("alice", "alice-pw"), Request::Goodbye];

    // (a) Legacy 4-slot handshake: the client offers the full 5.0..=5.4 span.
    let mut input = encode_client_handshake([
        Proposal::range(5, 4, 4),
        Proposal::exact(0, 0),
        Proposal::exact(0, 0),
        Proposal::exact(0, 0),
    ]);
    for r in &requests {
        input.extend_from_slice(&encode_request_framed(r).unwrap());
    }
    let mut transport = MemoryTransport::with_input(&input);
    {
        let mut session =
            BoltSession::with_config(&mut transport, MockExecutor::new(), &auth, capped.clone());
        session.run().unwrap();
        assert_eq!(session.version(), Some(Version::new(5, 0)), "capped to 5.0");
        assert_eq!(session.principal(), Some("alice"));
    }
    let (hs, stream) = split_handshake(transport.written());
    assert_eq!(hs, [0x00, 0x00, 0x00, 0x05], "legacy reply is 5.0");
    assert!(matches!(
        decode_responses(stream)[0],
        Response::Success { .. }
    ));

    // (b) Manifest-v1 handshake: the server's manifest must advertise the SAME capped window, and a
    //     client choosing above the cap is refused.
    let mut input = manifest_handshake(Version::new(5, 0));
    for r in &requests {
        input.extend_from_slice(&encode_request_framed(r).unwrap());
    }
    let mut transport = MemoryTransport::with_input(&input);
    {
        let mut session =
            BoltSession::with_config(&mut transport, MockExecutor::new(), &auth, capped.clone());
        session.run().unwrap();
        assert_eq!(session.version(), Some(Version::new(5, 0)));
        assert_eq!(session.principal(), Some("alice"));
    }
    let written = transport.written().to_vec();
    // The manifest reply: ack (4 bytes), count 1, the range, capabilities 0 — the range must be the
    // exact 5.0 single version, matching what the legacy path negotiated.
    assert_eq!(&written[..4], &crate::handshake::MANIFEST_V1_REQUEST);
    assert_eq!(
        &written[5..9],
        &[0x00, 0x00, 0x00, 0x05],
        "advertised 5.0 only"
    );

    // A manifest client that picks 5.4 against a 5.0-capped server is rejected outright.
    let mut transport = MemoryTransport::with_input(&manifest_handshake(Version::new(5, 4)));
    let mut session = BoltSession::with_config(&mut transport, MockExecutor::new(), &auth, capped);
    assert!(
        session.run().is_err(),
        "a capped server must refuse a manifest choice above its cap"
    );

    // The DEFAULT session is unchanged: it still negotiates the compiled maximum.
    let mut input = encode_client_handshake([
        Proposal::range(5, 4, 4),
        Proposal::exact(0, 0),
        Proposal::exact(0, 0),
        Proposal::exact(0, 0),
    ]);
    input.extend_from_slice(&encode_request_framed(&hello()).unwrap());
    let mut transport = MemoryTransport::with_input(&input);
    {
        let mut session = BoltSession::new(&mut transport, MockExecutor::new(), &auth);
        session.run().unwrap();
        assert_eq!(
            session.version(),
            Some(Version::new(5, crate::handshake::MAX_MINOR))
        );
    }
}

/// A [`Transport`] that counts [`Transport::on_authenticated`] calls and otherwise delegates to a
/// [`MemoryTransport`], so a test can prove the rmp #469 pre-authentication read-deadline relaxation
/// fires on a given authentication path (on a real socket transport that call is what stops a
/// legitimate long-lived session from being reaped by the slow-loris guard).
struct AuthSignalTransport {
    inner: MemoryTransport,
    on_authenticated_calls: usize,
}

impl AuthSignalTransport {
    fn with_input(input: &[u8]) -> Self {
        Self {
            inner: MemoryTransport::with_input(input),
            on_authenticated_calls: 0,
        }
    }
}

impl crate::transport::Transport for AuthSignalTransport {
    fn read(&mut self, buf: &mut [u8]) -> BoltResult<usize> {
        self.inner.read(buf)
    }
    fn write_all(&mut self, bytes: &[u8]) -> BoltResult<()> {
        self.inner.write_all(bytes)
    }
    fn flush(&mut self) -> BoltResult<()> {
        self.inner.flush()
    }
    fn on_authenticated(&mut self) {
        self.on_authenticated_calls += 1;
    }
}

#[test]
fn bolt_50_hello_relaxes_the_pre_auth_read_deadline_exactly_once() {
    // rmp #469 (F-NET-1): the transport's stricter PRE-authentication read deadline must be relaxed
    // at the single transition out of the unauthenticated phase. At 5.0 that transition is the HELLO,
    // not a LOGON — skipping the signal there would have the slow-loris guard reap every legitimate
    // long-lived 5.0 session.
    let auth = auth_fixture();
    let mut transport = AuthSignalTransport::with_input(&session_input_at(
        0,
        &[hello_50("alice", "alice-pw"), Request::Goodbye],
    ));
    {
        let mut session = BoltSession::new(&mut transport, MockExecutor::new(), &auth);
        session.run().unwrap();
    }
    assert_eq!(
        transport.on_authenticated_calls, 1,
        "the 5.0 HELLO must signal authentication to the transport exactly once"
    );

    // A REJECTED 5.0 HELLO must NOT relax the deadline (the connection never authenticated).
    let mut transport =
        AuthSignalTransport::with_input(&session_input_at(0, &[hello_50("alice", "WRONG-pw")]));
    {
        let mut session = BoltSession::new(&mut transport, MockExecutor::new(), &auth);
        session.run().unwrap();
    }
    assert_eq!(
        transport.on_authenticated_calls, 0,
        "a failed 5.0 HELLO must never relax the pre-authentication deadline"
    );
}

/// Drives ONE bad Bolt **5.0** `HELLO` authentication for `principal` on a fresh session sharing
/// `auth` + `throttle`, returning the decoded responses. A failed pre-auth HELLO is terminal
/// (rmp #820), so each attempt is a fresh connection — exactly how the throttle accrues across
/// reconnects in production. The 5.0 counterpart of [`drive_bad_logon`].
fn drive_bad_hello_auth_50(
    auth: &CountingAuth,
    throttle: &LoginThrottle,
    principal: &str,
) -> Vec<Response> {
    let input = session_input_at(0, &[hello_50(principal, "WRONG-pw")]);
    let mut transport = MemoryTransport::with_input(&input);
    {
        let mut session = BoltSession::new(&mut transport, MockExecutor::new(), auth)
            .with_login_throttle(throttle.clone());
        session.run().unwrap();
        assert_eq!(session.principal(), None);
        assert_eq!(
            session.state(),
            State::Defunct,
            "a failed 5.0 HELLO authentication is terminal (rmp #820)"
        );
    }
    let (_, stream) = split_handshake(transport.written());
    decode_responses(stream)
}

#[test]
fn bolt_50_hello_auth_consults_the_same_throttle_and_verify_bound_as_logon() {
    // ACCEPTANCE 4 + the SECURITY PRECONDITION of rmp #906: the 5.0 HELLO-carried authentication path
    // MUST traverse BOTH existing limiters — the per-account `AuthThrottle` (rmp #823) and the global
    // `VerifyLimiter` (rmp #824). If it bypassed them, an attacker would sidestep both simply by
    // negotiating 5.0. Proven exactly as the LOGON tests prove it: `CountingAuth` counts the Argon2
    // KDF, which lives strictly inside `authenticate_password`, so a FLAT count across a
    // throttled/shed attempt proves the limiter rejected it before the KDF.
    const MAX: u32 = 3;
    let auth = CountingAuth::new(auth_fixture());
    let clock = Arc::new(TestClock::new());
    let throttle = LoginThrottle::new(
        Arc::new(AuthThrottle::new(MAX, 1).expect("non-zero limits")),
        clock.clone(),
    );

    // Spend `alice`'s failure budget over Bolt 5.0 connections only.
    for i in 0..MAX {
        let before = auth.kdf_calls();
        let r = drive_bad_hello_auth_50(&auth, &throttle, "alice");
        assert!(
            matches!(r[0], Response::Failure(_)),
            "attempt {i}: a wrong password in a 5.0 HELLO must FAIL"
        );
        assert_eq!(
            auth.kdf_calls(),
            before + 1,
            "attempt {i}: the KDF runs while the account still has budget"
        );
    }

    // The (MAX+1)th 5.0 HELLO is rejected BEFORE the KDF by the SAME per-account throttle.
    let before = auth.kdf_calls();
    let r = drive_bad_hello_auth_50(&auth, &throttle, "alice");
    match &r[0] {
        Response::Failure(f) => assert_eq!(
            f.code, CODE_UNAUTHORIZED,
            "a throttled 5.0 HELLO returns the SAME Unauthorized as a wrong password (no oracle)"
        ),
        other => panic!("expected an Unauthorized FAILURE, got {other:?}"),
    }
    assert_eq!(
        auth.kdf_calls(),
        before,
        "the throttled 5.0 HELLO MUST be rejected BEFORE the Argon2 KDF (rmp #823 over 5.0)"
    );

    // The budget is shared with the 5.1+ LOGON path: `alice` is ALSO locked out over LOGON, so an
    // attacker cannot spend the budget on one version and continue on the other.
    let before = auth.kdf_calls();
    let r = drive_bad_logon(&auth, &throttle, "alice");
    match &r[1] {
        Response::Failure(f) => assert_eq!(f.code, CODE_UNAUTHORIZED),
        other => panic!("expected an Unauthorized FAILURE, got {other:?}"),
    }
    assert_eq!(
        auth.kdf_calls(),
        before,
        "the budget spent over 5.0 must lock the account out over the 5.1+ LOGON path too"
    );

    // Still PER-ACCOUNT: a different principal is unaffected and its first attempt runs the KDF.
    let before = auth.kdf_calls();
    let _ = drive_bad_hello_auth_50(&auth, &throttle, "bob");
    assert_eq!(auth.kdf_calls(), before + 1);

    // A CORRECT credential authenticates once the bucket refills (success is never throttled).
    clock.advance_secs(u64::from(MAX) + 1);
    let input = session_input_at(0, &[hello_50("alice", "alice-pw")]);
    let mut transport = MemoryTransport::with_input(&input);
    {
        let mut session = BoltSession::new(&mut transport, MockExecutor::new(), &auth)
            .with_login_throttle(throttle);
        session.run().unwrap();
        assert_eq!(session.principal(), Some("alice"));
    }

    // ...and the GLOBAL concurrent-verification bound (rmp #824) sheds a 5.0 HELLO before the KDF
    // exactly as it sheds a LOGON.
    let limiter = Arc::new(VerifyLimiter::new(1));
    let held = limiter.try_acquire().expect("within cap");
    let before = auth.kdf_calls();
    let input = session_input_at(0, &[hello_50("alice", "alice-pw")]);
    let mut transport = MemoryTransport::with_input(&input);
    {
        let mut session = BoltSession::new(&mut transport, MockExecutor::new(), &auth)
            .with_verify_limiter(Arc::clone(&limiter));
        session.run().unwrap();
        assert_eq!(session.principal(), None);
    }
    let (_, stream) = split_handshake(transport.written());
    match &decode_responses(stream)[0] {
        Response::Failure(f) => assert_eq!(
            f.code, CODE_SERVER_BUSY,
            "a saturated-bound shed carries the transient busy code over 5.0 too"
        ),
        other => panic!("expected a busy FAILURE, got {other:?}"),
    }
    assert_eq!(
        auth.kdf_calls(),
        before,
        "a shed 5.0 HELLO must NOT run the Argon2 KDF (rmp #824 over 5.0)"
    );
    drop(held);
}

#[test]
fn bolt_50_hello_auth_token_excludes_exactly_the_reserved_protocol_fields() {
    // The 5.0 auth token is `extra` MINUS the reserved non-auth fields, mirroring the Neo4j
    // reference (`HelloMessageDecoderV41.FIELDS` → `AuthenticationMetadataUtils.extractAuthToken`).
    // Pin the list: a future edit that drops one would leak a protocol field into the token, and one
    // that adds `bolt_agent` (a 5.3+ field NOT in the reference's 5.0 list) would silently diverge.
    let extra = vec![
        ("user_agent".to_owned(), Value::String("drv/1".to_owned())),
        ("patch_bolt".to_owned(), Value::List(vec![])),
        ("routing".to_owned(), Value::Map(vec![])),
        (
            "notifications_minimum_severity".to_owned(),
            Value::String("WARNING".to_owned()),
        ),
        (
            "notifications_disabled_categories".to_owned(),
            Value::List(vec![]),
        ),
        ("bolt_agent".to_owned(), Value::Map(vec![])),
        ("scheme".to_owned(), Value::String("basic".to_owned())),
        ("principal".to_owned(), Value::String("alice".to_owned())),
        (
            "credentials".to_owned(),
            Value::String("alice-pw".to_owned()),
        ),
        ("realm".to_owned(), Value::String("native".to_owned())),
    ];
    let token = hello_auth_token(extra);
    let token: Vec<&str> = token.iter().map(|(k, _)| k.as_str()).collect();
    assert_eq!(
        token,
        ["bolt_agent", "scheme", "principal", "credentials", "realm"],
        "the token is everything except the five reserved protocol fields, in `extra` order"
    );
    // The reserved list itself, pinned against the reference decoder's field list.
    assert_eq!(
        HELLO_NON_AUTH_FIELDS,
        [
            "patch_bolt",
            "routing",
            "user_agent",
            "notifications_minimum_severity",
            "notifications_disabled_categories",
        ]
    );
}
