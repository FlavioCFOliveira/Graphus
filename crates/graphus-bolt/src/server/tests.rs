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

/// An authenticator with one `alice`/`pw` user (Bolt native auth, `04 §8.4`).
fn auth_fixture() -> Authenticator {
    let mut a = Authenticator::new(b"shared-jwt-secret-at-least-32-bytes!!");
    a.catalog_mut().create_user("alice").unwrap();
    a.catalog_mut().create_role("reader").unwrap();
    a.catalog_mut()
        .grant_privilege("reader", Privilege::read_database())
        .unwrap();
    a.catalog_mut().grant_role("alice", "reader").unwrap();
    a.set_password("alice", "pw").unwrap();
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

/// A `LOGON` with the `basic` scheme for `alice`/`pw`.
fn logon_alice() -> Request {
    Request::Logon {
        auth: vec![
            ("scheme".to_owned(), Value::String("basic".to_owned())),
            ("principal".to_owned(), Value::String("alice".to_owned())),
            ("credentials".to_owned(), Value::String("pw".to_owned())),
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
        Request::Hello { extra: vec![] },
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
        Request::Hello { extra: vec![] },
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
        Request::Hello { extra: vec![] },
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
        Request::Hello { extra: vec![] },
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
fn bad_credentials_fail_and_then_ignore() {
    let exec = MockExecutor::new();
    let input = session_input(&[
        Request::Hello { extra: vec![] },
        Request::Logon {
            auth: vec![
                ("scheme".to_owned(), Value::String("basic".to_owned())),
                ("principal".to_owned(), Value::String("alice".to_owned())),
                ("credentials".to_owned(), Value::String("WRONG".to_owned())),
            ],
        },
        // After a failed auth the connection is FAILED; this RUN is IGNORED.
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
    }
    let (_, stream) = split_handshake(transport.written());
    let r = decode_responses(stream);
    assert!(matches!(r[0], Response::Success { .. })); // HELLO
    match &r[1] {
        Response::Failure(f) => assert_eq!(f.code, CODE_UNAUTHORIZED),
        other => panic!("expected auth FAILURE, got {other:?}"),
    }
    assert!(matches!(r[2], Response::Ignored));
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
    input.extend_from_slice(&encode_request_framed(&Request::Hello { extra: vec![] }).unwrap());
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
        Request::Hello { extra: vec![] },
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
        Request::Hello { extra: vec![] },
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
        Request::Hello { extra: vec![] },
        logon_alice(),
        Request::Begin { extra: vec![] },
        Request::Reset,
        Request::Goodbye,
    ]);
    let auth = auth_fixture();
    let mut transport = MemoryTransport::with_input(&input);
    let mut session = BoltSession::new(&mut transport, exec, &auth);
    session.run().unwrap();
    // The mock executor logged a rollback triggered by RESET.
    assert!(
        session.executor().log.contains(&"rollback".to_owned()),
        "RESET in a transaction must roll back"
    );
}

#[test]
fn noop_keepalive_between_messages_is_ignored() {
    // Insert a bare NOOP (00 00) between LOGON and RUN; the session must skip it.
    let mut input = handshake_54();
    input.extend_from_slice(&encode_request_framed(&Request::Hello { extra: vec![] }).unwrap());
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
        Request::Hello { extra: vec![] },
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
    let input = session_input(&[Request::Hello { extra: vec![] }, logon_alice()]);
    let auth = auth_fixture();
    let mut transport = MemoryTransport::with_input(&input);
    let mut session = BoltSession::new(&mut transport, MockExecutor::new(), &auth);
    session.run().expect("clean EOF");
    assert_eq!(session.state(), State::Defunct);
}

#[test]
fn summary_carries_query_type_and_stats() {
    let summary = QuerySummary {
        query_type: Some("rw".to_owned()),
        stats: vec![("nodes-created".to_owned(), Value::Integer(1))],
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
        Request::Hello { extra: vec![] },
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
