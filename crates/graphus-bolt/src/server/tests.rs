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

#[test]
fn db_field_from_extras_reaches_the_executor() {
    // The `db` field of BEGIN and auto-commit RUN extras flows through to the executor; an
    // empty/absent value is normalised to None (Bolt 5.x database targeting — rmp #84).
    let exec = MockExecutor::new().with_default(CannedResult::rows(&[], vec![]));
    let input = session_input(&[
        Request::Hello { extra: vec![] },
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
    let input = session_input(&[
        Request::Hello { extra: vec![] },
        logon_alice(),
        Request::Logoff,
        Request::Goodbye,
    ]);
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
        Request::Hello { extra: vec![] },
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
    let legacy_input = session_input(&[Request::Hello { extra: vec![] }, logon_alice()]);
    let mut legacy_transport = MemoryTransport::with_input(&legacy_input);
    let legacy_version = {
        let mut s = BoltSession::new(&mut legacy_transport, MockExecutor::new(), &auth);
        s.run().unwrap();
        s.version()
    };

    let mut manifest_input = manifest_handshake(Version::new(5, 4));
    for r in [Request::Hello { extra: vec![] }, logon_alice()] {
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
        Request::Hello { extra: vec![] },
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
        Request::Hello { extra: vec![] },
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
fn telemetry_is_acknowledged_with_success_and_never_fails() {
    // TELEMETRY in READY → SUCCESS, the connection stays usable for a following RUN.
    let exec = MockExecutor::new().on_query(
        "RETURN 1",
        CannedResult::rows(&["x"], vec![vec![Value::Integer(1)]]),
    );
    let input = session_input(&[
        Request::Hello { extra: vec![] },
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
        "TELEMETRY must never produce a FAILURE: {r:?}"
    );
    assert!(r.iter().any(|resp| matches!(resp, Response::Record { .. })));
}

#[test]
fn telemetry_before_logon_is_still_success_not_failure() {
    // Even out of the usual order (sent in AUTHENTICATION), TELEMETRY is acknowledged, never failed.
    let input = session_input(&[
        Request::Hello { extra: vec![] },
        Request::Telemetry { api: 1 },
        logon_alice(),
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
    // HELLO SUCCESS, TELEMETRY SUCCESS, LOGON SUCCESS — no FAILURE, and LOGON still works after.
    assert!(
        matches!(r[1], Response::Success { .. }),
        "TELEMETRY → SUCCESS"
    );
    assert!(
        matches!(r[2], Response::Success { .. }),
        "LOGON still works"
    );
    assert!(!r.iter().any(|resp| matches!(resp, Response::Failure(_))));
}

#[test]
fn connection_id_is_unique_per_session_and_surfaced_in_hello() {
    // Two sessions configured with distinct connection ids must each report their own in HELLO.
    fn hello_connection_id(conn_id: &str) -> String {
        let input = session_input(&[Request::Hello { extra: vec![] }, Request::Goodbye]);
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
    let input = session_input(&[Request::Hello { extra: vec![] }, Request::Goodbye]);
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
