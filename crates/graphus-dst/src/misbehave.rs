//! `misbehave` — badly-behaved Bolt client scenarios for the deterministic harness (rmp #166).
//!
//! A production database must **never panic, hang, or corrupt state** on hostile input (CLAUDE.md:
//! 100% Bolt/PackStream is inviolable). These scenarios feed the *real* `BoltSession` (over the
//! simulated network, against the real engine) crafted malformed / abusive byte streams and the tests
//! assert the server degrades gracefully: a Bolt `FAILURE`, a version rejection, or a clean transport
//! close — but always *without panicking* and always reaching a well-defined end.
//!
//! Each builder returns the raw client byte stream; [`crate::wire::drive_raw_bolt`] runs it.

use graphus_bolt::server::{encode_client_handshake, encode_request_framed};
use graphus_bolt::{Proposal, Request};
use graphus_core::Value;

/// A standard, well-formed Bolt 5.4 handshake (the valid prefix most misbehaviours build on).
#[must_use]
pub fn handshake_v54() -> Vec<u8> {
    encode_client_handshake([
        Proposal::range(5, 4, 4),
        Proposal::exact(0, 0),
        Proposal::exact(0, 0),
        Proposal::exact(0, 0),
    ])
}

/// A handshake proposing only the impossible version 0.0 — the server must reject it (reply
/// `00 00 00 00`) and close, never negotiate.
#[must_use]
pub fn handshake_unsupported_version() -> Vec<u8> {
    encode_client_handshake([
        Proposal::exact(0, 0),
        Proposal::exact(0, 0),
        Proposal::exact(0, 0),
        Proposal::exact(0, 0),
    ])
}

/// A valid handshake followed by raw garbage where a chunked message is expected.
#[must_use]
pub fn garbage_after_handshake() -> Vec<u8> {
    let mut v = handshake_v54();
    v.extend_from_slice(&[0xFF, 0xFE, 0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01]);
    v
}

/// A valid handshake then a chunk header claiming 16 bytes but supplying only 2 (a truncated message
/// the dechunker can never complete before EOF).
#[must_use]
pub fn truncated_chunk() -> Vec<u8> {
    let mut v = handshake_v54();
    v.extend_from_slice(&[0x00, 0x10]); // length prefix = 16
    v.extend_from_slice(b"ab"); // only 2 bytes, no terminator
    v
}

/// A valid handshake then a maximal chunk header (65535) with no payload at all.
#[must_use]
pub fn oversized_chunk_header() -> Vec<u8> {
    let mut v = handshake_v54();
    v.extend_from_slice(&[0xFF, 0xFF]);
    v
}

/// A valid handshake then a `RUN` with **no** preceding `HELLO`/`LOGON` — a protocol-state violation
/// the Bolt state machine must reject.
#[must_use]
pub fn run_before_logon() -> Vec<u8> {
    let mut v = handshake_v54();
    let run = Request::Run {
        query: "RETURN 1".to_owned(),
        parameters: vec![],
        extra: vec![],
    };
    v.extend_from_slice(&encode_request_framed(&run).expect("encode run"));
    v
}

/// A valid handshake + `HELLO` carrying a bogus structure where auth fields are expected, then a
/// `LOGON` with wrong credentials — exercises the auth-failure path.
#[must_use]
pub fn bad_credentials() -> Vec<u8> {
    let mut v = handshake_v54();
    for r in [
        Request::Hello {
            extra: vec![("user_agent".to_owned(), Value::String("bad".to_owned()))],
        },
        Request::Logon {
            auth: vec![
                ("scheme".to_owned(), Value::String("basic".to_owned())),
                ("principal".to_owned(), Value::String("sim".to_owned())),
                ("credentials".to_owned(), Value::String("WRONG".to_owned())),
            ],
        },
    ] {
        v.extend_from_slice(&encode_request_framed(&r).expect("encode"));
    }
    v
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::rc::Rc;
    use std::sync::Arc;

    use graphus_server::engine::LocalEngine;
    use graphus_sim::SharedClock;

    use crate::wire::{SharedEngine, drive_raw_bolt, login_prologue, run_scripted_bolt_session, sim_auth};

    fn engine() -> SharedEngine {
        Rc::new(RefCell::new(
            LocalEngine::in_memory(Arc::new(SharedClock::new(0)), 256).expect("engine"),
        ))
    }

    /// Every malformed/abusive raw stream is handled without panic and reaches a defined end (the
    /// test process aborts on a panic, so reaching the asserts *is* the no-panic proof).
    #[test]
    fn malformed_streams_never_panic() {
        let auth = sim_auth();
        let scenarios: Vec<(&str, Vec<u8>)> = vec![
            ("garbage_after_handshake", garbage_after_handshake()),
            ("truncated_chunk", truncated_chunk()),
            ("oversized_chunk_header", oversized_chunk_header()),
            ("run_before_logon", run_before_logon()),
            ("bad_credentials", bad_credentials()),
            ("empty", Vec::new()),
            ("handshake_only", handshake_v54()),
        ];
        for (name, bytes) in scenarios {
            let outcome = drive_raw_bolt(engine(), 1, &auth, &bytes);
            // The contract: it returned (no panic/hang) with a well-defined outcome. A misbehaved
            // client legitimately yields either a clean run, a transport error, or a FAILURE — all
            // fine; a panic or hang would never reach here.
            let _ = outcome.run_ok;
            assert!(
                outcome.responses.len() < 1000,
                "{name}: bounded response set (no runaway)",
            );
        }
    }

    /// An unsupported handshake version is rejected with the `00 00 00 00` reply and no session.
    #[test]
    fn unsupported_version_is_rejected() {
        let auth = sim_auth();
        let outcome = drive_raw_bolt(engine(), 1, &auth, &handshake_unsupported_version());
        assert_eq!(
            outcome.handshake_reply,
            Some([0, 0, 0, 0]),
            "server rejects the impossible version",
        );
        assert!(outcome.responses.is_empty(), "no messages after a rejected handshake");
    }

    /// `RUN` before authentication is a protocol-state violation: the server must not execute it; it
    /// fails or closes, never panics, and certainly never returns a normal RECORD/SUCCESS for it.
    #[test]
    fn run_before_logon_does_not_execute() {
        let auth = sim_auth();
        let outcome = drive_raw_bolt(engine(), 1, &auth, &run_before_logon());
        // No successful RECORD should be produced for the premature RUN.
        assert!(
            !outcome
                .responses
                .iter()
                .any(|r| matches!(r, graphus_bolt::Response::Record { .. })),
            "a pre-auth RUN must not stream records: {:?}",
            outcome.responses,
        );
    }

    /// Wrong credentials yield a Bolt `FAILURE`, not a panic and not a logged-in session.
    #[test]
    fn bad_credentials_fail_cleanly() {
        let auth = sim_auth();
        let outcome = drive_raw_bolt(engine(), 1, &auth, &bad_credentials());
        assert!(
            outcome.has_failure(),
            "bad credentials must produce a FAILURE: {:?}",
            outcome.responses,
        );
    }

    /// A well-formed session with invalid Cypher returns a `FAILURE` (compile error) and the session
    /// stays usable for protocol purposes (fail-then-ignore), never panicking.
    #[test]
    fn invalid_cypher_is_a_failure_not_a_panic() {
        let auth = sim_auth();
        let mut reqs = login_prologue();
        reqs.extend([
            Request::Run {
                query: "THIS IS NOT CYPHER".to_owned(),
                parameters: vec![],
                extra: vec![],
            },
            Request::Pull { n: -1, qid: None },
            Request::Goodbye,
        ]);
        let responses = run_scripted_bolt_session(engine(), 1, &auth, &reqs).expect("runs");
        assert!(
            responses
                .iter()
                .any(|r| matches!(r, graphus_bolt::Response::Failure { .. })),
            "invalid Cypher yields a FAILURE: {responses:?}",
        );
    }

    /// Determinism: a malformed stream produces the identical outcome on replay.
    #[test]
    fn misbehaviour_is_deterministic() {
        let auth = sim_auth();
        let once = drive_raw_bolt(engine(), 5, &auth, &garbage_after_handshake());
        let twice = drive_raw_bolt(engine(), 5, &auth, &garbage_after_handshake());
        assert_eq!(once.run_ok, twice.run_ok);
        assert_eq!(format!("{:?}", once.responses), format!("{:?}", twice.responses));
    }
}
