//! A **synchronous Bolt client over a Unix domain socket** for the `reco_bench` concurrent read
//! driver.
//!
//! This is a purpose-built sibling of `graphus-cli`'s interactive `BoltClient`: a pure-synchronous
//! Bolt session over a [`std::os::unix::net::UnixStream`], reusing the [`graphus_bolt`] symmetric wire
//! codec (handshake, framing, message, packstream) with **no wire format reinvented**. It adds the two
//! things a load driver needs over the interactive shell's client:
//!
//! 1. **Database selection** — every `RUN` carries the target database in its `extra` map's `db`
//!    field (Bolt 5.x), so the driver can hammer a **non-default** database (the recommendation graph
//!    is bulk-imported into `recodb`, which Mode A requires to be non-default).
//! 2. **Parameters** — `RUN` carries a `parameters` map, so the whole load uses a single
//!    plan-cache-friendly parameterised query per family with `$id` varying per operation, rather than
//!    re-planning a fresh literal-inlined text every call.
//!
//! Each worker thread owns one [`BoltClient`] over its own connection; the client is **not** `Sync`
//! and is never shared between threads — the driver's concurrency is one-connection-per-thread, which
//! is exactly the "many concurrent client connections" the example puts under load.
//!
//! # Protocol flow (`04-technical-design.md` §8.1)
//!
//! Handshake → `HELLO` → `LOGON` (basic) → per query `RUN` + `PULL(-1)` → `GOODBYE`. A server
//! `FAILURE` is surfaced as a clean [`ClientError::Failure`], never a panic, so the driver can count
//! it and carry on. Multi-chunk responses are reassembled with [`graphus_bolt::Dechunker`].

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

/// The user agent the driver advertises in `HELLO`.
pub const USER_AGENT: &str = concat!("graphus-reco-bench/", env!("CARGO_PKG_VERSION"));

/// An error from the Bolt client: a transport fault, a protocol/codec fault, or a server `FAILURE`.
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

/// The outcome of running one query: the column names, the rows, and the wall-clock latency.
#[derive(Debug, Clone)]
pub struct QueryResult {
    /// The result column names, in order, from the `RUN` `SUCCESS` `fields`.
    pub fields: Vec<String>,
    /// One flattened scalar row per `RECORD`, in field order.
    pub records: Vec<Vec<Value>>,
    /// Wall-clock time from sending `RUN` to receiving the trailing `SUCCESS`.
    pub elapsed: Duration,
}

impl QueryResult {
    /// The number of result rows.
    #[must_use]
    pub fn row_count(&self) -> usize {
        self.records.len()
    }

    /// The first row's first integer cell, if the result is scalar-shaped (e.g. a `count(...)`).
    #[must_use]
    pub fn first_scalar(&self) -> Option<i64> {
        match self.records.first().and_then(|r| r.first()) {
            Some(Value::Integer(n)) => Some(*n),
            _ => None,
        }
    }
}

/// A synchronous Bolt session over a Unix domain socket.
///
/// Construct with [`BoltClient::connect_uds`], then [`BoltClient::login`], then
/// [`BoltClient::run`] per query, and [`BoltClient::goodbye`] on close.
pub struct BoltClient {
    stream: UnixStream,
    dechunker: Dechunker,
    version: Version,
}

impl BoltClient {
    /// Connects to a Graphus server over a Unix domain socket at `path`, performing the handshake.
    /// A generous read timeout keeps a wedged server from hanging a worker forever.
    ///
    /// # Errors
    /// [`ClientError::Io`] if the socket cannot be reached; [`ClientError::Protocol`] if the server
    /// rejects every proposed version or replies with an unsupported version.
    pub fn connect_uds(path: &Path, read_timeout: Duration) -> ClientResult<Self> {
        let mut stream = UnixStream::connect(path)?;
        stream.set_read_timeout(Some(read_timeout))?;
        let version = Self::handshake(&mut stream)?;
        Ok(Self {
            stream,
            dechunker: Dechunker::new(),
            version,
        })
    }

    /// The negotiated Bolt protocol version.
    #[must_use]
    pub fn version(&self) -> Version {
        self.version
    }

    /// Performs the 4-slot handshake: proposes the whole supported window and reads the negotiated
    /// version.
    fn handshake(stream: &mut UnixStream) -> ClientResult<Version> {
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
                "server rejected all proposed Bolt versions (5.0-5.4)".to_owned(),
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

    /// Sends `HELLO` then `LOGON` (basic scheme), authenticating as `user`. The `password` is sent
    /// once in the `LOGON` auth map and never retained.
    ///
    /// # Errors
    /// [`ClientError::Failure`] if the server rejects the credentials; [`ClientError::Protocol`] on an
    /// unexpected reply; [`ClientError::Io`] on a transport fault.
    pub fn login(&mut self, user: &str, password: &str) -> ClientResult<()> {
        self.send(&Request::Hello {
            extra: vec![(
                "user_agent".to_owned(),
                Value::String(USER_AGENT.to_owned()),
            )],
        })?;
        match self.recv()? {
            Response::Success { .. } => {}
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
            Response::Success { .. } => Ok(()),
            Response::Failure(f) => Err(ClientError::Failure(f)),
            other => Err(unexpected("LOGON", &other)),
        }
    }

    /// Runs one query (auto-commit) against database `db` with `parameters`, pulling all records.
    ///
    /// `db` selects the target database via the `RUN` `extra` map's `db` field (Bolt 5.x); pass the
    /// empty string for the server's default database. `parameters` is the `$name -> Value` map.
    ///
    /// # Errors
    /// [`ClientError::Failure`] on a server-reported failure; [`ClientError::Protocol`] on an
    /// out-of-place message; [`ClientError::Io`] on a transport fault.
    pub fn run(
        &mut self,
        query: &str,
        parameters: Vec<(String, Value)>,
        db: &str,
    ) -> ClientResult<QueryResult> {
        let extra = if db.is_empty() {
            vec![]
        } else {
            vec![("db".to_owned(), Value::String(db.to_owned()))]
        };
        let started = Instant::now();
        self.send(&Request::Run {
            query: query.to_owned(),
            parameters,
            extra,
        })?;
        let fields = match self.recv()? {
            Response::Success { metadata } => extract_fields(&metadata),
            Response::Failure(f) => return Err(ClientError::Failure(f)),
            other => return Err(unexpected("RUN", &other)),
        };

        self.send(&Request::Pull { n: ALL, qid: None })?;
        let mut records = Vec::new();
        loop {
            match self.recv()? {
                Response::Record { values } => records.push(scalar_row(values)),
                Response::Success { .. } => break, // trailing summary
                Response::Failure(f) => return Err(ClientError::Failure(f)),
                other => return Err(unexpected("PULL", &other)),
            }
        }

        Ok(QueryResult {
            fields,
            records,
            elapsed: started.elapsed(),
        })
    }

    /// Sends `GOODBYE`, signalling a clean disconnect.
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

    /// Reads one framed Bolt response, buffering from the socket as needed (multi-chunk + NOOP).
    fn recv(&mut self) -> ClientResult<Response> {
        let mut buf = [0u8; 8192];
        loop {
            match self.dechunker.next_frame()? {
                Some(Frame::Message(payload)) => return Ok(Response::decode(&payload)?),
                Some(Frame::Noop) => continue,
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

/// Flattens a `RECORD`'s cells to scalar [`Value`]s (entity → id, path → list of element ids,
/// list → element-wise) — the same projection `graphus-cli`'s client uses.
fn scalar_row(values: Vec<BoltValue>) -> Vec<Value> {
    values.into_iter().map(bolt_to_scalar).collect()
}

/// Flattens one [`BoltValue`] cell to a scalar [`Value`].
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
