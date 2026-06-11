//! Integration test: drive a full Bolt session through the crate's **public** API, with a
//! `BoltExecutor` implemented *outside* the crate — exactly as the server (rmp #20) will wire
//! `graphus-cypher`'s coordinator. This proves the two seams (`Transport`, `BoltExecutor`) are
//! usable from another crate and that a whole session works over the public surface.

use graphus_auth::{Authenticator, Privilege};
use graphus_bolt::executor::{
    AccessMode, BoltExecutor, QuerySummary, Record, RecordStream, TxControl,
};
use graphus_bolt::server::{encode_client_handshake, encode_request_framed};
use graphus_bolt::{
    BoltSession, Dechunker, Frame, MemoryTransport, Proposal, Request, Response, State, Version,
};
use graphus_core::{GraphusError, Value};

/// A minimal external executor: returns a fixed two-row result for any query, tracks tx state.
#[derive(Default)]
struct DemoExecutor {
    tx_open: bool,
}

struct DemoStream {
    fields: Vec<String>,
    rows: std::vec::IntoIter<Record>,
}

impl RecordStream for DemoStream {
    fn fields(&self) -> &[String] {
        &self.fields
    }
    fn next_record(&mut self) -> Result<Option<Record>, GraphusError> {
        Ok(self.rows.next())
    }
    fn summary(&self) -> QuerySummary {
        QuerySummary {
            query_type: Some("r".to_owned()),
            stats: vec![],
        }
    }
}

impl BoltExecutor for DemoExecutor {
    type Stream = DemoStream;

    fn run(
        &mut self,
        _query: &str,
        _parameters: Vec<(String, Value)>,
        _tx: TxControl,
    ) -> Result<Self::Stream, GraphusError> {
        Ok(DemoStream {
            fields: vec!["x".to_owned()],
            rows: vec![vec![Value::Integer(10)], vec![Value::Integer(20)]].into_iter(),
        })
    }

    fn begin(&mut self, _mode: AccessMode, _db: Option<&str>) -> Result<(), GraphusError> {
        self.tx_open = true;
        Ok(())
    }
    fn commit(&mut self) -> Result<QuerySummary, GraphusError> {
        self.tx_open = false;
        Ok(QuerySummary::default())
    }
    fn rollback(&mut self) -> Result<(), GraphusError> {
        self.tx_open = false;
        Ok(())
    }
}

fn auth() -> Authenticator {
    let mut a = Authenticator::new(b"shared-jwt-secret-at-least-32-bytes!!");
    a.catalog_mut().create_user("bob").unwrap();
    a.catalog_mut().create_role("r").unwrap();
    a.catalog_mut()
        .grant_privilege("r", Privilege::read_database())
        .unwrap();
    a.catalog_mut().grant_role("bob", "r").unwrap();
    a.set_password("bob", "secret").unwrap();
    a
}

fn responses(written: &[u8]) -> Vec<Response> {
    // Skip the 4-byte handshake reply, then decode the framed message stream.
    let mut d = Dechunker::new();
    d.push(&written[4..]);
    let mut out = Vec::new();
    while let Some(Frame::Message(p)) = d.next_frame().unwrap() {
        out.push(Response::decode(&p).unwrap());
    }
    out
}

#[test]
fn full_session_over_public_api() {
    let mut input = encode_client_handshake([
        Proposal::range(5, 4, 4), // 5.0..=5.4
        Proposal::exact(0, 0),
        Proposal::exact(0, 0),
        Proposal::exact(0, 0),
    ]);
    for r in [
        Request::Hello {
            extra: vec![("user_agent".to_owned(), Value::String("itest".to_owned()))],
        },
        Request::Logon {
            auth: vec![
                ("scheme".to_owned(), Value::String("basic".to_owned())),
                ("principal".to_owned(), Value::String("bob".to_owned())),
                ("credentials".to_owned(), Value::String("secret".to_owned())),
            ],
        },
        Request::Run {
            query: "MATCH (x) RETURN x".to_owned(),
            parameters: vec![],
            extra: vec![],
        },
        Request::Pull { n: -1, qid: None },
        Request::Goodbye,
    ] {
        input.extend_from_slice(&encode_request_framed(&r).unwrap());
    }

    let a = auth();
    let mut transport = MemoryTransport::with_input(&input);
    {
        let mut session = BoltSession::new(&mut transport, DemoExecutor::default(), &a);
        session.run().expect("session runs to GOODBYE");
        assert_eq!(session.state(), State::Defunct);
        assert_eq!(session.version(), Some(Version::new(5, 4)));
        assert_eq!(session.principal(), Some("bob"));
    }

    // Handshake reply is 5.4.
    assert_eq!(&transport.written()[..4], &[0x00, 0x00, 0x04, 0x05]);

    let r = responses(transport.written());
    // HELLO SUCCESS, LOGON SUCCESS, RUN SUCCESS{fields}, RECORD, RECORD, trailing SUCCESS.
    assert_eq!(r.len(), 6);
    assert!(matches!(r[0], Response::Success { .. }));
    assert!(matches!(r[1], Response::Success { .. }));
    match &r[2] {
        Response::Success { metadata } => assert!(metadata.iter().any(|(k, _)| k == "fields")),
        other => panic!("expected RUN SUCCESS, got {other:?}"),
    }
    assert_eq!(
        r[3],
        Response::Record {
            values: vec![Value::Integer(10)]
        }
    );
    assert_eq!(
        r[4],
        Response::Record {
            values: vec![Value::Integer(20)]
        }
    );
    assert!(matches!(r[5], Response::Success { .. }));
}
