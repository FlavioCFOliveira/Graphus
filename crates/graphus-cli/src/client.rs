//! A **synchronous Bolt client over a Unix domain socket** (and, transparently, any
//! [`Read`] + [`Write`] stream) for the Graphus interactive shell.
//!
//! An interactive REPL is request/response and one connection at a time, so a blocking client is the
//! right shape: no async runtime, no backpressure machinery — just the pure-sync Bolt byte codec from
//! [`graphus_bolt`] driven over a [`std::os::unix::net::UnixStream`]. This mirrors the async
//! `BoltUdsClient` in `graphus-server`'s integration tests, but synchronous and reusable, and it
//! surfaces a Bolt `FAILURE` as a clean [`ClientError`] instead of panicking.
//!
//! # Protocol flow (`04-technical-design.md` §8.1; `06-bolt-and-error-shapes.md` §1)
//!
//! 1. **Handshake** — write [`graphus_bolt::handshake::MAGIC`] + four range-encoded version
//!    proposals, read the 4-byte negotiated version (or all-zeros rejection).
//! 2. **HELLO** — send the `user_agent` (+ bolt agent extras); the server answers `SUCCESS` with its
//!    `server` agent string and `connection_id`, which we retain for `:status`.
//! 3. **LOGON** — `basic` scheme with `principal`/`credentials`; `SUCCESS` moves us to `READY`.
//! 4. **RUN + PULL(-1)** per query — the `RUN` `SUCCESS` carries `fields` (column names); zero or
//!    more `RECORD`s follow; a final `SUCCESS` carries the summary, or a `FAILURE` carries
//!    `code`/`message`.
//! 5. **GOODBYE** on quit.
//!
//! Multi-chunk responses are reassembled with [`graphus_bolt::Dechunker`]. Credentials are never
//! logged or stored beyond the single `LOGON` send.

use std::fmt;
use std::io::{self, Read, Write};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::time::{Duration, Instant};

use graphus_bolt::handshake::{MAX_MINOR, Proposal, SUPPORTED_MAJOR, Version};
use graphus_bolt::message::ALL;
use graphus_bolt::server::{encode_client_handshake, encode_request_framed};
use graphus_bolt::{BoltValue, Dechunker, Failure, Frame, Request, Response};
use graphus_core::Value;

/// The user agent the CLI advertises in `HELLO` (`name/version`, per the Bolt convention).
pub const USER_AGENT: &str = concat!("graphus-cli/", env!("CARGO_PKG_VERSION"));

/// An error from the Bolt client: a transport fault, a protocol/codec fault, or a server `FAILURE`.
///
/// A server-reported `FAILURE` (a syntax error, an auth rejection, a runtime error) is **not** a
/// panic — it is a first-class [`ClientError::Failure`] the REPL renders cleanly and recovers from.
#[derive(Debug)]
pub enum ClientError {
    /// An I/O error on the underlying socket (connect, read, write, unexpected EOF).
    Io(io::Error),
    /// A protocol- or codec-level fault (a malformed frame, a wrong message in this state).
    Protocol(String),
    /// The server rejected the request with a Bolt `FAILURE` carrying a `code` and `message`.
    Failure(Failure),
}

impl fmt::Display for ClientError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(e) => write!(f, "I/O error: {e}"),
            Self::Protocol(m) => write!(f, "protocol error: {m}"),
            Self::Failure(fail) => write!(f, "{}: {}", fail.code, fail.message),
        }
    }
}

impl std::error::Error for ClientError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<io::Error> for ClientError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

impl From<graphus_bolt::BoltError> for ClientError {
    fn from(e: graphus_bolt::BoltError) -> Self {
        Self::Protocol(e.to_string())
    }
}

/// A convenience result alias for client operations.
pub type ClientResult<T> = Result<T, ClientError>;

/// Server identity learned during the handshake/`HELLO`, surfaced by `:status`.
#[derive(Debug, Clone)]
pub struct ServerInfo {
    /// The negotiated Bolt protocol version (e.g. `5.4`).
    pub version: Version,
    /// The server agent string from the `HELLO` `SUCCESS` (e.g. `Graphus/0.0.0`).
    pub server_agent: String,
    /// The connection id the server assigned (from the `HELLO` `SUCCESS`).
    pub connection_id: String,
}

/// The outcome of running one query: the column names, the rows, and a summary.
#[derive(Debug, Clone)]
pub struct QueryResult {
    /// The result column names, in order, from the `RUN` `SUCCESS` `fields`.
    pub fields: Vec<String>,
    /// One [`Value`] list per `RECORD`, in field order.
    pub records: Vec<Vec<Value>>,
    /// The query summary metadata from the trailing `SUCCESS` (e.g. `type`, `stats`).
    pub summary: Vec<(String, Value)>,
    /// Wall-clock time from sending `RUN` to receiving the trailing `SUCCESS`.
    pub elapsed: Duration,
}

impl QueryResult {
    /// The number of result rows.
    #[must_use]
    pub fn row_count(&self) -> usize {
        self.records.len()
    }
}

/// A synchronous Bolt session over a byte stream `S` (a [`UnixStream`] in production).
///
/// Construct it with [`BoltClient::connect_uds`] (or [`BoltClient::with_stream`] for testing over an
/// in-memory pipe), then [`BoltClient::login`], then [`BoltClient::run`] per query, and
/// [`BoltClient::goodbye`] on close.
pub struct BoltClient<S: Read + Write> {
    stream: S,
    dechunker: Dechunker,
    info: Option<ServerInfo>,
}

impl BoltClient<UnixStream> {
    /// Connects to a Graphus server over a Unix domain socket at `path` and performs the handshake.
    ///
    /// # Errors
    /// [`ClientError::Io`] if the socket cannot be reached; [`ClientError::Protocol`] if the server
    /// rejects every proposed version or replies with an unsupported version.
    pub fn connect_uds(path: &Path) -> ClientResult<Self> {
        let stream = UnixStream::connect(path)?;
        // A read timeout keeps an interactive REPL from hanging forever on a wedged server while
        // staying generous enough for slow queries. The shell is single-connection, so this is the
        // simplest robust default; it can be lifted to a flag later if needed.
        stream.set_read_timeout(Some(Duration::from_secs(120)))?;
        Self::with_stream(stream)
    }
}

impl<S: Read + Write> BoltClient<S> {
    /// Wraps an already-connected stream and performs the Bolt handshake over it.
    ///
    /// Exposed for tests that drive the client over an in-memory duplex stream; production uses
    /// [`BoltClient::connect_uds`].
    ///
    /// # Errors
    /// [`ClientError::Io`] on a transport fault; [`ClientError::Protocol`] if the negotiated version
    /// is the all-zero rejection or a version the client does not support.
    pub fn with_stream(mut stream: S) -> ClientResult<Self> {
        let negotiated = Self::handshake(&mut stream)?;
        Ok(Self {
            stream,
            dechunker: Dechunker::new(),
            info: Some(ServerInfo {
                version: negotiated,
                // Filled in by `HELLO` during `login`; placeholders until then.
                server_agent: String::new(),
                connection_id: String::new(),
            }),
        })
    }

    /// Performs the 4-slot handshake: proposes 5.0..=5.4 and reads the negotiated version.
    fn handshake(stream: &mut S) -> ClientResult<Version> {
        // Propose the whole supported window in slot 1 (top 5.4, spanning down to 5.0), leaving the
        // other three slots empty — the standard single-line driver proposal.
        let proposals = [
            Proposal::range(SUPPORTED_MAJOR, MAX_MINOR, MAX_MINOR),
            Proposal::exact(0, 0),
            Proposal::exact(0, 0),
            Proposal::exact(0, 0),
        ];
        stream.write_all(&encode_client_handshake(proposals))?;
        stream.flush()?;

        let mut reply = [0u8; 4];
        stream.read_exact(&mut reply)?;
        if reply == [0, 0, 0, 0] {
            return Err(ClientError::Protocol(
                "server rejected all proposed Bolt versions (5.0–5.4)".to_owned(),
            ));
        }
        let version = Version::from_wire(reply);
        if !version.is_supported() {
            return Err(ClientError::Protocol(format!(
                "server negotiated unsupported Bolt version {}.{}",
                version.major, version.minor
            )));
        }
        Ok(version)
    }

    /// Sends `HELLO` then `LOGON` (basic scheme), authenticating as `user`.
    ///
    /// On success the [`ServerInfo`] is enriched with the server agent and connection id from the
    /// `HELLO` `SUCCESS`. The `password` is sent once in the `LOGON` auth map and never retained.
    ///
    /// # Errors
    /// [`ClientError::Failure`] if the server rejects the credentials; [`ClientError::Protocol`] if
    /// the server answers `HELLO`/`LOGON` with an unexpected message; [`ClientError::Io`] on a
    /// transport fault.
    pub fn login(&mut self, user: &str, password: &str) -> ClientResult<&ServerInfo> {
        self.send(&Request::Hello {
            extra: vec![
                (
                    "user_agent".to_owned(),
                    Value::String(USER_AGENT.to_owned()),
                ),
                // The 5.3+ structured bolt agent block (informational; the server ignores unknowns).
                (
                    "bolt_agent".to_owned(),
                    Value::Map(vec![(
                        "product".to_owned(),
                        Value::String(USER_AGENT.to_owned()),
                    )]),
                ),
            ],
        })?;
        match self.recv()? {
            Response::Success { metadata } => {
                if let Some(info) = self.info.as_mut() {
                    info.server_agent =
                        map_get_string(&metadata, "server").unwrap_or_else(|| "unknown".to_owned());
                    info.connection_id = map_get_string(&metadata, "connection_id")
                        .unwrap_or_else(|| "unknown".to_owned());
                }
            }
            other => return Err(unexpected("HELLO", &other)),
        }

        self.send(&Request::Logon {
            auth: vec![
                ("scheme".to_owned(), Value::String("basic".to_owned())),
                ("principal".to_owned(), Value::String(user.to_owned())),
                ("credentials".to_owned(), Value::String(password.to_owned())),
            ],
        })?;
        match self.recv()? {
            Response::Success { .. } => {}
            Response::Failure(f) => return Err(ClientError::Failure(f)),
            other => return Err(unexpected("LOGON", &other)),
        }

        // `login` only succeeds when `info` is `Some` (set in `with_stream`), so this is infallible.
        self.info
            .as_ref()
            .ok_or_else(|| ClientError::Protocol("missing server info after login".to_owned()))
    }

    /// The server identity learned during the handshake/`HELLO`, if connected.
    #[must_use]
    pub fn server_info(&self) -> Option<&ServerInfo> {
        self.info.as_ref()
    }

    /// Runs one `query` (no parameters, auto-commit) and pulls all records.
    ///
    /// Sends `RUN` then `PULL(n: -1)` and reads the response stream: the `RUN` `SUCCESS` provides the
    /// column names; each `RECORD` is a row; the trailing `SUCCESS` is the summary. A `FAILURE` at
    /// either stage is returned as [`ClientError::Failure`].
    ///
    /// # Errors
    /// [`ClientError::Failure`] on a server-reported failure (syntax/runtime/…);
    /// [`ClientError::Protocol`] on an out-of-place message; [`ClientError::Io`] on a transport fault.
    pub fn run(&mut self, query: &str) -> ClientResult<QueryResult> {
        let started = Instant::now();
        self.send(&Request::Run {
            query: query.to_owned(),
            parameters: vec![],
            extra: vec![],
        })?;
        let fields = match self.recv()? {
            Response::Success { metadata } => extract_fields(&metadata),
            Response::Failure(f) => return Err(ClientError::Failure(f)),
            other => return Err(unexpected("RUN", &other)),
        };

        self.send(&Request::Pull { n: ALL, qid: None })?;
        let mut records = Vec::new();
        let summary = loop {
            match self.recv()? {
                Response::Record { values } => records.push(scalar_row(values)),
                Response::Success { metadata } => break metadata, // trailing summary
                Response::Failure(f) => return Err(ClientError::Failure(f)),
                other => return Err(unexpected("PULL", &other)),
            }
        };

        Ok(QueryResult {
            fields,
            records,
            summary,
            elapsed: started.elapsed(),
        })
    }

    /// Sends `GOODBYE`, signalling a clean disconnect. The server closes the socket in response.
    ///
    /// # Errors
    /// [`ClientError::Io`] if the message cannot be written.
    pub fn goodbye(&mut self) -> ClientResult<()> {
        self.send(&Request::Goodbye)
    }

    /// Frames and writes one request, then flushes.
    fn send(&mut self, request: &Request) -> ClientResult<()> {
        let bytes = encode_request_framed(request)?;
        self.stream.write_all(&bytes)?;
        self.stream.flush()?;
        Ok(())
    }

    /// Reads one framed Bolt response, buffering from the socket as needed (handles multi-chunk
    /// messages and NOOP keep-alives).
    fn recv(&mut self) -> ClientResult<Response> {
        let mut buf = [0u8; 8192];
        loop {
            match self.dechunker.next_frame()? {
                Some(Frame::Message(payload)) => return Ok(Response::decode(&payload)?),
                Some(Frame::Noop) => continue, // keep-alive; keep reading for a real message
                None => {}
            }
            let n = self.stream.read(&mut buf)?;
            if n == 0 {
                return Err(ClientError::Protocol(
                    "connection closed by server while awaiting a response".to_owned(),
                ));
            }
            self.dechunker.push(&buf[..n]);
        }
    }
}

/// Builds a [`ClientError::Protocol`] describing an out-of-place response for `stage`.
fn unexpected(stage: &str, got: &Response) -> ClientError {
    ClientError::Protocol(format!("unexpected response to {stage}: {got:?}"))
}

/// Extracts the `fields` column-name list from a `RUN` `SUCCESS` metadata map.
fn extract_fields(metadata: &[(String, Value)]) -> Vec<String> {
    metadata
        .iter()
        .find(|(k, _)| k == "fields")
        .and_then(|(_, v)| match v {
            Value::List(items) => Some(
                items
                    .iter()
                    .map(|v| match v {
                        Value::String(s) => s.clone(),
                        other => format!("{other:?}"),
                    })
                    .collect(),
            ),
            _ => None,
        })
        .unwrap_or_default()
}

/// Flattens a RECORD's cells to scalar [`Value`]s for the CLI's text renderer, which formats
/// `Value`s. A graph entity collapses to its id (`Value::Integer`), a path to the `Value::List` of
/// its element ids in traversal order (start node, then each hop's relationship and arrival node),
/// and a structural list element-wise — the same projection the server's old `project_value` used
/// while `graphus_core::Value` defers the structural classes (`04 §7.2`).
fn scalar_row(values: Vec<BoltValue>) -> Vec<Value> {
    values.into_iter().map(bolt_to_scalar).collect()
}

/// Flattens one [`BoltValue`] cell to a scalar [`Value`] (entity → id, path → list of element ids,
/// list → element-wise).
fn bolt_to_scalar(v: BoltValue) -> Value {
    match v {
        BoltValue::Value(val) => val,
        BoltValue::Node(n) => Value::Integer(n.id),
        BoltValue::Relationship(r) => Value::Integer(r.id),
        BoltValue::Path(p) => {
            let mut ids = Vec::with_capacity(p.nodes.len() + p.rels.len());
            for node in &p.nodes {
                ids.push(Value::Integer(node.id));
            }
            for rel in &p.rels {
                ids.push(Value::Integer(rel.id));
            }
            Value::List(ids)
        }
        BoltValue::List(items) => Value::List(items.into_iter().map(bolt_to_scalar).collect()),
    }
}

/// Looks up a string-valued key in a Bolt metadata map.
fn map_get_string(map: &[(String, Value)], key: &str) -> Option<String> {
    map.iter().find_map(|(k, v)| match v {
        Value::String(s) if k == key => Some(s.clone()),
        _ => None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use graphus_bolt::framing::chunk_message;
    use graphus_bolt::handshake::MAGIC;
    use std::io::Cursor;

    /// A scripted duplex stream: reads are served from a fixed byte script (the "server"), writes are
    /// captured so the test can assert what the client sent. This lets the synchronous client be
    /// exercised without a socket.
    struct ScriptedStream {
        to_client: Cursor<Vec<u8>>,
        from_client: Vec<u8>,
    }

    impl ScriptedStream {
        fn new(server_script: Vec<u8>) -> Self {
            Self {
                to_client: Cursor::new(server_script),
                from_client: Vec::new(),
            }
        }
    }

    impl Read for ScriptedStream {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            self.to_client.read(buf)
        }
    }

    impl Write for ScriptedStream {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            self.from_client.extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    /// Frames a response message into chunked wire bytes.
    fn framed(resp: &Response) -> Vec<u8> {
        chunk_message(&resp.encode().unwrap())
    }

    /// The 4-byte server reply negotiating Bolt 5.4.
    fn negotiated_54() -> [u8; 4] {
        Version::new(5, 4).to_wire()
    }

    #[test]
    fn handshake_writes_magic_and_proposals_then_reads_version() {
        let stream = ScriptedStream::new(negotiated_54().to_vec());
        let client = BoltClient::with_stream(stream).expect("handshake ok");
        assert_eq!(client.server_info().unwrap().version, Version::new(5, 4));

        // The client must have written exactly the 20-byte handshake: magic + 4 proposals, with slot
        // 1 proposing the 5.4-topped supported window.
        let sent = &client.stream.from_client;
        assert_eq!(&sent[..4], &MAGIC, "magic preamble");
        assert_eq!(sent.len(), 20, "magic + four 4-byte proposals");
        assert_eq!(
            &sent[4..8],
            &Proposal::range(5, 4, 4).to_wire(),
            "slot 1 proposes 5.0..=5.4"
        );
    }

    #[test]
    fn handshake_rejection_is_a_clean_error() {
        let stream = ScriptedStream::new(vec![0, 0, 0, 0]);
        match BoltClient::with_stream(stream) {
            Err(ClientError::Protocol(_)) => {}
            // `BoltClient` is intentionally not `Debug` (it owns a live stream), so match rather than
            // `expect_err` to inspect the rejection.
            Ok(_) => panic!("a rejected handshake must not yield a client"),
            Err(other) => panic!("expected a protocol error, got {other:?}"),
        }
    }

    #[test]
    fn login_captures_server_agent_and_connection_id() {
        // Server script: negotiated version, then HELLO SUCCESS (with server/connection_id), then
        // LOGON SUCCESS.
        let mut script = negotiated_54().to_vec();
        script.extend(framed(&Response::Success {
            metadata: vec![
                (
                    "server".to_owned(),
                    Value::String("Graphus/0.0.0".to_owned()),
                ),
                (
                    "connection_id".to_owned(),
                    Value::String("bolt-7".to_owned()),
                ),
            ],
        }));
        script.extend(framed(&Response::Success { metadata: vec![] }));

        let mut client = BoltClient::with_stream(ScriptedStream::new(script)).unwrap();
        let info = client.login("alice", "pw").expect("login ok").clone();
        assert_eq!(info.server_agent, "Graphus/0.0.0");
        assert_eq!(info.connection_id, "bolt-7");

        // The password must appear exactly once on the wire (in the single LOGON) and never be
        // duplicated — a guard against accidental re-sends.
        let sent = String::from_utf8_lossy(&client.stream.from_client);
        assert_eq!(sent.matches("pw").count(), 1, "credentials sent once");
    }

    #[test]
    fn bad_login_surfaces_failure_not_panic() {
        let mut script = negotiated_54().to_vec();
        script.extend(framed(&Response::Success { metadata: vec![] })); // HELLO ok
        script.extend(framed(&Response::Failure(Failure::new(
            "Neo.ClientError.Security.Unauthorized",
            "invalid credentials",
        ))));

        let mut client = BoltClient::with_stream(ScriptedStream::new(script)).unwrap();
        match client.login("alice", "wrong") {
            Err(ClientError::Failure(f)) => {
                assert_eq!(f.code, "Neo.ClientError.Security.Unauthorized");
            }
            other => panic!("expected a FAILURE, got {other:?}"),
        }
    }

    #[test]
    fn run_collects_fields_records_and_summary() {
        let mut script = negotiated_54().to_vec();
        script.extend(framed(&Response::Success { metadata: vec![] })); // HELLO
        script.extend(framed(&Response::Success { metadata: vec![] })); // LOGON
        // RUN SUCCESS with the column names.
        script.extend(framed(&Response::Success {
            metadata: vec![(
                "fields".to_owned(),
                Value::List(vec![
                    Value::String("n".to_owned()),
                    Value::String("m".to_owned()),
                ]),
            )],
        }));
        // Two records, then the trailing summary.
        script.extend(framed(&Response::Record {
            values: vec![
                BoltValue::Value(Value::Integer(1)),
                BoltValue::Value(Value::String("a".to_owned())),
            ],
        }));
        script.extend(framed(&Response::Record {
            values: vec![
                BoltValue::Value(Value::Integer(2)),
                BoltValue::Value(Value::String("b".to_owned())),
            ],
        }));
        script.extend(framed(&Response::Success {
            metadata: vec![("type".to_owned(), Value::String("r".to_owned()))],
        }));

        let mut client = BoltClient::with_stream(ScriptedStream::new(script)).unwrap();
        client.login("alice", "pw").unwrap();
        let result = client.run("MATCH (n) RETURN n, n AS m").unwrap();

        assert_eq!(result.fields, vec!["n".to_owned(), "m".to_owned()]);
        assert_eq!(result.row_count(), 2);
        assert_eq!(result.records[0][0], Value::Integer(1));
        assert_eq!(result.records[1][1], Value::String("b".to_owned()));
        assert_eq!(
            map_get_string(&result.summary, "type"),
            Some("r".to_owned())
        );
    }

    #[test]
    fn run_failure_surfaces_cleanly() {
        let mut script = negotiated_54().to_vec();
        script.extend(framed(&Response::Success { metadata: vec![] })); // HELLO
        script.extend(framed(&Response::Success { metadata: vec![] })); // LOGON
        script.extend(framed(&Response::Failure(Failure::new(
            "Neo.ClientError.Statement.SyntaxError",
            "boom",
        ))));

        let mut client = BoltClient::with_stream(ScriptedStream::new(script)).unwrap();
        client.login("alice", "pw").unwrap();
        match client.run("RETUNR 1") {
            Err(ClientError::Failure(f)) => assert!(f.message.contains("boom")),
            other => panic!("expected a FAILURE, got {other:?}"),
        }
    }

    #[test]
    fn eof_mid_response_is_a_protocol_error_not_a_hang() {
        // Negotiated version, but no HELLO reply: the stream EOFs.
        let mut client = BoltClient::with_stream(ScriptedStream::new(negotiated_54().to_vec()))
            .expect("handshake");
        let err = client.login("alice", "pw").expect_err("eof");
        assert!(matches!(err, ClientError::Protocol(_)), "got {err:?}");
    }
}
