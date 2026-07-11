//! A **synchronous Bolt client** for the `reco_bench` concurrent read driver, over either a **Unix
//! domain socket** (the co-located local server) or **Bolt-over-TCP with TLS** (an already-running,
//! possibly remote instance — e.g. pi516; `rmp` #693).
//!
//! This is a purpose-built sibling of `graphus-cli`'s interactive `BoltClient`: a pure-synchronous
//! Bolt session over a transport-agnostic [`Transport`] (a `UnixStream`, a plaintext `TcpStream`, or a
//! rustls-wrapped `TcpStream`), reusing the [`graphus_bolt`] symmetric wire codec (handshake, framing,
//! message, packstream) with **no wire format reinvented**. The TLS plumbing MIRRORS
//! `graphus-cli`'s `transport.rs` (synchronous rustls 0.23 + the `aws_lc_rs` provider; `bolt+ssc://`
//! accepts a self-signed cert), so no second crypto backend enters the dependency graph. It adds the
//! two things a load driver needs over the interactive shell's client:
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
use std::net::TcpStream;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use graphus_bolt::handshake::{MAX_MINOR, Proposal, SUPPORTED_MAJOR, Version};
use graphus_bolt::message::ALL;
use graphus_bolt::server::{encode_client_handshake, encode_request_framed};
use graphus_bolt::{BoltValue, Dechunker, Failure, Frame, Request, Response};
use graphus_core::Value;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{
    ClientConfig, ClientConnection, DigitallySignedStruct, RootCertStore, SignatureScheme,
    StreamOwned,
};

/// The user agent the driver advertises in `HELLO`.
pub const USER_AGENT: &str = concat!("graphus-reco-bench/", env!("CARGO_PKG_VERSION"));

/// The default Bolt TCP port (the Neo4j convention) used when a `--bolt` URL omits `:port`.
pub const DEFAULT_BOLT_PORT: u16 = 7687;

// ================================================================================================
// Bolt-over-TCP + TLS transport (mirrors `graphus-cli`'s `transport.rs`, `rmp` #688/#693)
// ================================================================================================

/// How TLS is applied to a Bolt-over-TCP connection, decided by the URL scheme.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsMode {
    /// `bolt://` — plaintext TCP, no TLS.
    None,
    /// `bolt+s://` — TLS 1.3 with server-certificate verification against the Mozilla root store.
    Verified,
    /// `bolt+ssc://` — TLS 1.3 that accepts **any** server certificate (self-signed / demo servers,
    /// e.g. pi516).
    SelfSignedOk,
}

/// A parsed Bolt URL: the destination host, port, and the TLS mode implied by its scheme.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoltUrl {
    /// The destination host (a DNS name or an IP literal; an IPv6 literal is stored without brackets).
    pub host: String,
    /// The destination TCP port (defaults to [`DEFAULT_BOLT_PORT`] when the URL omits it).
    pub port: u16,
    /// The TLS mode selected by the URL scheme.
    pub tls: TlsMode,
}

impl BoltUrl {
    /// Parses a `bolt://` / `bolt+s://` / `bolt+ssc://` URL into a [`BoltUrl`].
    ///
    /// The authority is `host[:port]`; an IPv6 literal must be bracketed (`[::1]:7687`). When the port
    /// is omitted it defaults to [`DEFAULT_BOLT_PORT`] (`7687`). Any path/query/fragment tail is
    /// ignored (a Bolt URL carries none).
    ///
    /// # Errors
    /// A human-readable message if the scheme is missing or unsupported, the host is empty, or the
    /// port is not a valid `u16`.
    pub fn parse(url: &str) -> Result<Self, String> {
        let (scheme, rest) = url.split_once("://").ok_or_else(|| {
            format!(
                "invalid Bolt URL {url:?}: expected a scheme, e.g. bolt://host:7687, \
                 bolt+s://host:7687, or bolt+ssc://host:7687"
            )
        })?;
        let tls = match scheme {
            "bolt" => TlsMode::None,
            "bolt+s" => TlsMode::Verified,
            "bolt+ssc" => TlsMode::SelfSignedOk,
            other => {
                return Err(format!(
                    "unsupported Bolt URL scheme {other:?}: use bolt://, bolt+s://, or bolt+ssc://"
                ));
            }
        };
        // Bolt URLs carry no path/query/fragment; be lenient and strip any tail before the authority.
        let authority = rest.split(['/', '?', '#']).next().unwrap_or(rest);
        let (host, port) = parse_authority(authority, url)?;
        Ok(Self { host, port, tls })
    }
}

impl fmt::Display for BoltUrl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let scheme = match self.tls {
            TlsMode::None => "bolt",
            TlsMode::Verified => "bolt+s",
            TlsMode::SelfSignedOk => "bolt+ssc",
        };
        // Re-bracket an IPv6 literal so the rendering round-trips through `parse`.
        if self.host.contains(':') {
            write!(f, "{scheme}://[{}]:{}", self.host, self.port)
        } else {
            write!(f, "{scheme}://{}:{}", self.host, self.port)
        }
    }
}

/// Splits a `host[:port]` authority (with bracketed-IPv6 support) into host + port.
fn parse_authority(authority: &str, url: &str) -> Result<(String, u16), String> {
    if authority.is_empty() {
        return Err(format!("invalid Bolt URL {url:?}: missing host"));
    }
    // Bracketed IPv6: `[addr]` or `[addr]:port`.
    if let Some(rest) = authority.strip_prefix('[') {
        let (addr, after) = rest.split_once(']').ok_or_else(|| {
            format!("invalid Bolt URL {url:?}: unterminated IPv6 literal (missing ']')")
        })?;
        if addr.is_empty() {
            return Err(format!("invalid Bolt URL {url:?}: empty IPv6 host"));
        }
        let port = match after {
            "" => DEFAULT_BOLT_PORT,
            p => {
                let p = p.strip_prefix(':').ok_or_else(|| {
                    format!("invalid Bolt URL {url:?}: expected ':port' after the IPv6 literal")
                })?;
                parse_port(p, url)?
            }
        };
        return Ok((addr.to_owned(), port));
    }
    // `host:port` or a bare `host` (IPv4 or DNS name). `rsplit_once` keeps the last `:` as the port
    // separator; a bare host has none.
    match authority.rsplit_once(':') {
        Some((host, port)) if !host.is_empty() => Ok((host.to_owned(), parse_port(port, url)?)),
        Some(_) => Err(format!("invalid Bolt URL {url:?}: missing host")),
        None => Ok((authority.to_owned(), DEFAULT_BOLT_PORT)),
    }
}

/// Parses the port component, erroring with the offending URL for context.
fn parse_port(port: &str, url: &str) -> Result<u16, String> {
    port.parse::<u16>()
        .map_err(|_| format!("invalid Bolt URL {url:?}: {port:?} is not a valid port (0..=65535)"))
}

/// A byte transport for the Bolt session: a local Unix socket, a plain TCP socket, or a TLS-wrapped
/// TCP socket. All three implement [`Read`] + [`Write`], so [`BoltClient`] drives the identical Bolt
/// codec over any of them. The `Tls` variant is boxed ([`StreamOwned`] embeds a large rustls buffer
/// holder) so the enum — and every `BoltClient` on the stack — stays small.
pub enum Transport {
    /// A Unix domain socket (the default, kernel-protected local transport).
    Uds(UnixStream),
    /// A plaintext TCP socket (`bolt://`).
    Tcp(TcpStream),
    /// A TLS 1.3 session over TCP (`bolt+s://` / `bolt+ssc://`).
    Tls(Box<StreamOwned<ClientConnection, TcpStream>>),
}

impl Transport {
    /// Connects to `url` over TCP, wrapping the socket in a TLS 1.3 session for the `bolt+s`/`bolt+ssc`
    /// schemes. For the TLS schemes the handshake is driven eagerly so a certificate/verification
    /// failure surfaces here (at connect time) rather than as an opaque error during the first read.
    ///
    /// # Errors
    /// [`ClientError::Io`] if the TCP connection or the (eager) TLS handshake fails;
    /// [`ClientError::Protocol`] if the host is not a valid TLS server name or the TLS config cannot
    /// be built.
    pub fn connect_bolt(url: &BoltUrl, read_timeout: Duration) -> ClientResult<Self> {
        let tcp = TcpStream::connect((url.host.as_str(), url.port))?;
        tcp.set_read_timeout(Some(read_timeout))?;
        // A load driver issues many small request/response round-trips; disabling Nagle avoids the
        // 40 ms coalescing delay. Best-effort (a failure here is never fatal to the session).
        let _ = tcp.set_nodelay(true);
        match url.tls {
            TlsMode::None => Ok(Self::Tcp(tcp)),
            TlsMode::Verified => Self::wrap_tls(tcp, &url.host, tls_config_verified()?),
            TlsMode::SelfSignedOk => Self::wrap_tls(tcp, &url.host, tls_config_accept_any()?),
        }
    }

    /// Wraps an established TCP socket in a rustls client session for `host`, completing the TLS
    /// handshake eagerly.
    fn wrap_tls(mut tcp: TcpStream, host: &str, config: Arc<ClientConfig>) -> ClientResult<Self> {
        let server_name = ServerName::try_from(host.to_owned())
            .map_err(|_| ClientError::Protocol(format!("invalid TLS server name {host:?}")))?;
        let mut conn = ClientConnection::new(config, server_name).map_err(tls_err)?;
        // Drive the handshake to completion now: a rejected certificate becomes a clean connect-time
        // error instead of an opaque failure buried in the first Bolt read.
        conn.complete_io(&mut tcp)?;
        Ok(Self::Tls(Box::new(StreamOwned::new(conn, tcp))))
    }
}

impl Read for Transport {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Self::Uds(s) => s.read(buf),
            Self::Tcp(s) => s.read(buf),
            Self::Tls(s) => s.read(buf),
        }
    }
}

impl Write for Transport {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self {
            Self::Uds(s) => s.write(buf),
            Self::Tcp(s) => s.write(buf),
            Self::Tls(s) => s.write(buf),
        }
    }
    fn flush(&mut self) -> io::Result<()> {
        match self {
            Self::Uds(s) => s.flush(),
            Self::Tcp(s) => s.flush(),
            Self::Tls(s) => s.flush(),
        }
    }
}

/// Builds a TLS 1.3-only client config that **verifies** the server certificate against the Mozilla
/// root store (`bolt+s://`).
fn tls_config_verified() -> ClientResult<Arc<ClientConfig>> {
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let config = ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .map_err(tls_err)?
    .with_root_certificates(roots)
    .with_no_client_auth();
    Ok(Arc::new(config))
}

/// Builds a TLS 1.3-only client config that accepts **any** server certificate (`bolt+ssc://`) — the
/// self-signed / demo mode (pi516). It encrypts but does not authenticate the peer.
fn tls_config_accept_any() -> ClientResult<Arc<ClientConfig>> {
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    // Advertise exactly the provider's supported signature schemes so the (accepted) CertificateVerify
    // step negotiates a scheme both sides understand; an empty list would leave the server nothing to
    // sign with.
    let schemes = provider
        .signature_verification_algorithms
        .supported_schemes();
    let config = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(tls_err)?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAnyServerCert { schemes }))
        .with_no_client_auth();
    Ok(Arc::new(config))
}

/// Maps a rustls error into a [`ClientError::Protocol`].
fn tls_err(e: rustls::Error) -> ClientError {
    ClientError::Protocol(format!("TLS error: {e}"))
}

/// A rustls [`ServerCertVerifier`] that accepts **any** server certificate and signature — the
/// `bolt+ssc://` (self-signed / demo) mode. It performs no trust-chain or hostname checks: reachable
/// only when the user explicitly selects `bolt+ssc://` (an opt-out of server authentication; traffic
/// stays encrypted but is not protected against an active man-in-the-middle).
#[derive(Debug)]
struct AcceptAnyServerCert {
    /// The signature schemes the crypto provider supports, advertised to the server verbatim.
    schemes: Vec<SignatureScheme>,
}

impl ServerCertVerifier for AcceptAnyServerCert {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }
    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.schemes.clone()
    }
}

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

/// A synchronous Bolt session over either a Unix domain socket or a (optionally TLS-wrapped) TCP
/// stream.
///
/// Construct with [`BoltClient::connect_uds`] (local) or [`BoltClient::connect_bolt`] (a Bolt URL,
/// possibly TLS), then [`BoltClient::login`], then [`BoltClient::run`] per query, and
/// [`BoltClient::goodbye`] on close.
pub struct BoltClient {
    transport: Transport,
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
        let stream = UnixStream::connect(path)?;
        stream.set_read_timeout(Some(read_timeout))?;
        Self::from_transport(Transport::Uds(stream))
    }

    /// Connects to a Graphus server over Bolt-over-TCP at `url`, wrapping the socket in a rustls TLS
    /// session for the `bolt+s://` / `bolt+ssc://` schemes, then performing the Bolt handshake. A
    /// generous read timeout keeps a wedged/slow server from hanging a worker forever.
    ///
    /// # Errors
    /// [`ClientError::Io`] on a TCP/TLS-handshake failure; [`ClientError::Protocol`] if the host is
    /// not a valid TLS server name, the TLS config cannot be built, or the Bolt version negotiation
    /// fails.
    pub fn connect_bolt(url: &BoltUrl, read_timeout: Duration) -> ClientResult<Self> {
        let transport = Transport::connect_bolt(url, read_timeout)?;
        Self::from_transport(transport)
    }

    /// Completes the Bolt handshake over an already-connected transport.
    fn from_transport(mut transport: Transport) -> ClientResult<Self> {
        let version = Self::handshake(&mut transport)?;
        Ok(Self {
            transport,
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
    /// version. Generic over the transport so it drives an identical byte exchange over UDS or TLS.
    fn handshake<S: Read + Write>(stream: &mut S) -> ClientResult<Version> {
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

    /// Opens an **explicit transaction** on this connection (`BEGIN`), targeting database `db` (empty
    /// ⇒ the server's default database). Bolt 5.x carries the database in the `BEGIN` `extra` map, so
    /// every statement of the transaction runs against it without repeating the selection
    /// (`04-technical-design.md` §8.1; the Bolt state machine moves `READY` → `TX_READY`).
    ///
    /// After `begin`, run statements with [`run_in_txn`](Self::run_in_txn) — **not** [`run`](Self::run),
    /// whose `RUN` would be an auto-commit statement the server rejects while a transaction is open —
    /// and close with [`commit`](Self::commit) or [`rollback`](Self::rollback).
    ///
    /// Leaving the transaction open and dropping the connection (or crashing the server) is exactly the
    /// **in-flight** case a durability example needs: nothing it wrote was ever acknowledged, so no
    /// effect of it may ever be observable (`rmp` #698).
    ///
    /// # Errors
    /// [`ClientError::Failure`] if the server refuses to open the transaction; [`ClientError::Protocol`]
    /// on an out-of-place reply; [`ClientError::Io`] on a transport fault.
    pub fn begin(&mut self, db: &str) -> ClientResult<()> {
        let extra = if db.is_empty() {
            vec![]
        } else {
            vec![("db".to_owned(), Value::String(db.to_owned()))]
        };
        self.send(&Request::Begin { extra })?;
        match self.recv()? {
            Response::Success { .. } => Ok(()),
            Response::Failure(f) => Err(ClientError::Failure(f)),
            other => Err(unexpected("BEGIN", &other)),
        }
    }

    /// Runs one statement **inside the open explicit transaction** (`RUN` + `PULL(-1)`), pulling all
    /// records. The database was fixed by [`begin`](Self::begin), so the `RUN` `extra` map is empty —
    /// re-sending `db` inside a transaction is not the Bolt 5.x contract.
    ///
    /// Its effects are visible only to this transaction until [`commit`](Self::commit) succeeds.
    ///
    /// # Errors
    /// As [`run`](Self::run).
    pub fn run_in_txn(
        &mut self,
        query: &str,
        parameters: Vec<(String, Value)>,
    ) -> ClientResult<QueryResult> {
        let started = Instant::now();
        self.send(&Request::Run {
            query: query.to_owned(),
            parameters,
            extra: vec![],
        })?;
        let fields = match self.recv()? {
            Response::Success { metadata } => extract_fields(&metadata),
            Response::Failure(f) => return Err(ClientError::Failure(f)),
            other => return Err(unexpected("RUN (in txn)", &other)),
        };

        self.send(&Request::Pull { n: ALL, qid: None })?;
        let mut records = Vec::new();
        loop {
            match self.recv()? {
                Response::Record { values } => records.push(scalar_row(values)),
                Response::Success { .. } => break, // trailing summary
                Response::Failure(f) => return Err(ClientError::Failure(f)),
                other => return Err(unexpected("PULL (in txn)", &other)),
            }
        }

        Ok(QueryResult {
            fields,
            records,
            elapsed: started.elapsed(),
        })
    }

    /// Commits the open explicit transaction (`COMMIT`). A `SUCCESS` here is the **acknowledgement**
    /// that makes every statement of the transaction durable — the exact event a durability proof
    /// treats as "this MUST survive a crash".
    ///
    /// # Errors
    /// [`ClientError::Failure`] if the server aborts the commit (e.g. an SSI serialization conflict);
    /// [`ClientError::Protocol`] on an out-of-place reply; [`ClientError::Io`] on a transport fault.
    pub fn commit(&mut self) -> ClientResult<()> {
        self.send(&Request::Commit)?;
        match self.recv()? {
            Response::Success { .. } => Ok(()),
            Response::Failure(f) => Err(ClientError::Failure(f)),
            other => Err(unexpected("COMMIT", &other)),
        }
    }

    /// Rolls back the open explicit transaction (`ROLLBACK`): none of its effects may be observable.
    ///
    /// # Errors
    /// [`ClientError::Failure`] on a server-reported failure; [`ClientError::Protocol`] on an
    /// out-of-place reply; [`ClientError::Io`] on a transport fault.
    pub fn rollback(&mut self) -> ClientResult<()> {
        self.send(&Request::Rollback)?;
        match self.recv()? {
            Response::Success { .. } => Ok(()),
            Response::Failure(f) => Err(ClientError::Failure(f)),
            other => Err(unexpected("ROLLBACK", &other)),
        }
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
        self.transport.write_all(&bytes)?;
        self.transport.flush()?;
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
            let n = self.transport.read(&mut buf)?;
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scheme_maps_to_tls_mode() {
        assert_eq!(BoltUrl::parse("bolt://h:1").unwrap().tls, TlsMode::None);
        assert_eq!(
            BoltUrl::parse("bolt+s://h:1").unwrap().tls,
            TlsMode::Verified
        );
        assert_eq!(
            BoltUrl::parse("bolt+ssc://h:1").unwrap().tls,
            TlsMode::SelfSignedOk
        );
    }

    #[test]
    fn parses_the_pi516_self_signed_target() {
        // The exact acceptance-criteria URL: a self-signed remote box addressed by IPv4 literal.
        let url = BoltUrl::parse("bolt+ssc://100.89.148.30:7687").expect("valid");
        assert_eq!(url.host, "100.89.148.30");
        assert_eq!(url.port, 7687);
        assert_eq!(url.tls, TlsMode::SelfSignedOk);
    }

    #[test]
    fn port_defaults_to_7687_when_omitted() {
        let url = BoltUrl::parse("bolt+ssc://db.internal").expect("valid");
        assert_eq!(url.port, DEFAULT_BOLT_PORT);
    }

    #[test]
    fn parses_bracketed_ipv6() {
        let url = BoltUrl::parse("bolt+s://[2001:db8::1]:7000").expect("valid");
        assert_eq!(url.host, "2001:db8::1");
        assert_eq!(url.port, 7000);
        let url = BoltUrl::parse("bolt://[::1]").expect("valid");
        assert_eq!(url.host, "::1");
        assert_eq!(url.port, DEFAULT_BOLT_PORT);
    }

    #[test]
    fn rejects_missing_and_unsupported_scheme() {
        assert!(BoltUrl::parse("example.com:7687").is_err());
        assert!(BoltUrl::parse("neo4j://example.com:7687").is_err());
    }

    #[test]
    fn rejects_invalid_port_and_empty_host() {
        assert!(BoltUrl::parse("bolt://h:notaport").is_err());
        assert!(BoltUrl::parse("bolt://h:70000").is_err());
        assert!(BoltUrl::parse("bolt://:7687").is_err());
    }

    #[test]
    fn display_round_trips_through_parse() {
        for raw in [
            "bolt://example.com:7687",
            "bolt+s://db.internal:7000",
            "bolt+ssc://100.89.148.30:7687",
            "bolt+s://[2001:db8::1]:7000",
        ] {
            let url = BoltUrl::parse(raw).expect("valid");
            let reparsed = BoltUrl::parse(&url.to_string()).expect("re-parse");
            assert_eq!(url, reparsed, "{raw}");
        }
    }

    #[test]
    fn tls_configs_build() {
        assert!(tls_config_accept_any().is_ok());
        assert!(tls_config_verified().is_ok());
    }
}
