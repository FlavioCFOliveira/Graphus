//! Transport selection for the CLI: the default **Unix domain socket** and, for reaching a remote
//! instance, **Bolt-over-TCP** with optional **TLS** (rmp #688).
//!
//! The Bolt wire codec is transport-agnostic ([`crate::client::BoltClient`] is generic over any
//! [`Read`] + [`Write`] stream), so this module only owns the *plumbing* that produces such a stream:
//! it parses a Neo4j-style URL, opens the socket, and — for the TLS schemes — wraps it in a
//! synchronous rustls session. The Bolt handshake, `HELLO`/`LOGON`, `RUN`/`PULL`, and `GOODBYE` are
//! then driven identically over whichever [`Transport`] is chosen.
//!
//! # URL schemes (Neo4j driver convention)
//!
//! | Scheme        | Encryption | Server-certificate verification                         |
//! |---------------|------------|---------------------------------------------------------|
//! | `bolt://`     | none       | — (plaintext TCP; use only on a trusted network)        |
//! | `bolt+s://`   | TLS 1.3    | **verified** against the Mozilla root store             |
//! | `bolt+ssc://` | TLS 1.3    | **accept any** certificate (self-signed / demo servers) |
//!
//! Bolt over TLS is simply the identical Bolt byte stream carried inside a TLS tunnel — there is no
//! Bolt-specific TLS negotiation and no ALPN; the 20-byte Bolt handshake is the first application
//! payload once the tunnel is up. The default Bolt port is `7687`.
//!
//! # Security (`bolt+ssc://`)
//!
//! `bolt+ssc://` installs a certificate verifier that accepts **any** server certificate. This keeps
//! the traffic encrypted but does **not** authenticate the server, so the connection is exposed to an
//! active man-in-the-middle. It exists for self-signed / demo deployments (e.g. a staging box or a
//! box) where the operator has explicitly opted out of verification. Prefer `bolt+s://` whenever the
//! server presents a certificate that chains to a public root.

use std::fmt;
use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{
    ClientConfig, ClientConnection, DigitallySignedStruct, RootCertStore, SignatureScheme,
    StreamOwned,
};

use crate::client::{ClientError, ClientResult};

/// The default Bolt TCP port (the Neo4j convention) used when a `--bolt` URL omits `:port`.
const DEFAULT_BOLT_PORT: u16 = 7687;

/// A generous read timeout for the interactive, single-connection REPL — mirrors the UDS path so a
/// wedged server cannot hang the shell forever while still tolerating slow queries.
const READ_TIMEOUT: Duration = Duration::from_secs(120);

/// How TLS is applied to a Bolt-over-TCP connection, decided by the URL scheme.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsMode {
    /// `bolt://` — plaintext TCP, no TLS.
    None,
    /// `bolt+s://` — TLS 1.3 with server-certificate verification against the Mozilla root store.
    Verified,
    /// `bolt+ssc://` — TLS 1.3 that accepts **any** server certificate (self-signed / demo servers).
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
    /// Returns a human-readable message if the scheme is missing or unsupported, the host is empty, or
    /// the port is not a valid `u16`.
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

    // `host:port` or a bare `host` (IPv4 or DNS name). `rsplit_once` keeps the last `:` as the
    // port separator; a bare host has none.
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
/// TCP socket. All three implement [`Read`] + [`Write`], so [`crate::client::BoltClient`] drives the
/// identical Bolt codec over any of them.
///
/// The `Tls` variant is boxed: [`StreamOwned`] embeds a rustls `ClientConnection` (a large buffer
/// holder), so boxing keeps the enum — and every `Transport`-sized value on the stack — small.
pub enum Transport {
    /// A Unix domain socket (the default, kernel-protected local transport).
    Uds(UnixStream),
    /// A plaintext TCP socket (`bolt://`).
    Tcp(TcpStream),
    /// A TLS 1.3 session over TCP (`bolt+s://` / `bolt+ssc://`).
    Tls(Box<StreamOwned<ClientConnection, TcpStream>>),
}

impl Transport {
    /// Connects a Unix domain socket at `path` (the default transport) and applies the read timeout.
    ///
    /// # Errors
    /// [`ClientError::Io`] if the socket cannot be reached or the timeout cannot be set.
    pub fn connect_uds(path: &Path) -> ClientResult<Self> {
        let stream = UnixStream::connect(path)?;
        stream.set_read_timeout(Some(READ_TIMEOUT))?;
        Ok(Self::Uds(stream))
    }

    /// Connects to `url` over TCP, wrapping the socket in a TLS 1.3 session for the `bolt+s`/`bolt+ssc`
    /// schemes. For the TLS schemes the handshake is driven eagerly so a certificate/verification
    /// failure surfaces here (at connect time) rather than as an opaque error during the first read.
    ///
    /// # Errors
    /// [`ClientError::Io`] if the TCP connection or the (eager) TLS handshake fails;
    /// [`ClientError::Protocol`] if the host is not a valid TLS server name or the TLS config cannot
    /// be built.
    pub fn connect_bolt(url: &BoltUrl) -> ClientResult<Self> {
        let tcp = TcpStream::connect((url.host.as_str(), url.port))?;
        tcp.set_read_timeout(Some(READ_TIMEOUT))?;
        // Interactive request/response benefits from disabling Nagle; best-effort (a failure here is
        // never fatal to the session).
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

/// Builds a TLS 1.3-only client config that accepts **any** server certificate (`bolt+ssc://`).
///
/// See the module-level security note: this encrypts but does not authenticate the peer.
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
/// `bolt+ssc://` (self-signed / demo) mode.
///
/// This deliberately performs no trust-chain or hostname checks: it returns the "verified" assertion
/// unconditionally. It is only reachable when the user selects `bolt+ssc://`, an explicit opt-out of
/// server authentication (the traffic stays encrypted, but is not protected against an active
/// man-in-the-middle). See the module-level security note.
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_plain_bolt_with_explicit_port() {
        let url = BoltUrl::parse("bolt://example.com:7687").expect("valid");
        assert_eq!(url.host, "example.com");
        assert_eq!(url.port, 7687);
        assert_eq!(url.tls, TlsMode::None);
    }

    #[test]
    fn scheme_maps_to_the_right_tls_mode() {
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
    fn port_defaults_to_7687_when_omitted() {
        let url = BoltUrl::parse("bolt+ssc://db.internal").expect("valid");
        assert_eq!(url.host, "db.internal");
        assert_eq!(url.port, DEFAULT_BOLT_PORT);
        assert_eq!(url.tls, TlsMode::SelfSignedOk);
    }

    #[test]
    fn parses_a_self_signed_remote_target() {
        // The exact acceptance-criteria URL: a self-signed remote box addressed by IPv4 literal.
        let url = BoltUrl::parse("bolt+ssc://203.0.113.10:7687").expect("valid");
        assert_eq!(url.host, "203.0.113.10");
        assert_eq!(url.port, 7687);
        assert_eq!(url.tls, TlsMode::SelfSignedOk);
    }

    #[test]
    fn parses_bracketed_ipv6_with_and_without_port() {
        let url = BoltUrl::parse("bolt+s://[2001:db8::1]:7000").expect("valid");
        assert_eq!(url.host, "2001:db8::1");
        assert_eq!(url.port, 7000);
        assert_eq!(url.tls, TlsMode::Verified);

        let url = BoltUrl::parse("bolt://[::1]").expect("valid");
        assert_eq!(url.host, "::1");
        assert_eq!(url.port, DEFAULT_BOLT_PORT);
    }

    #[test]
    fn rejects_missing_scheme() {
        assert!(BoltUrl::parse("example.com:7687").is_err());
    }

    #[test]
    fn rejects_unsupported_scheme() {
        // `neo4j://` implies routing, which a single Graphus instance does not model — reject it
        // rather than silently pretend.
        let err = BoltUrl::parse("neo4j://example.com:7687").unwrap_err();
        assert!(err.contains("unsupported"), "{err}");
    }

    #[test]
    fn rejects_invalid_port() {
        assert!(BoltUrl::parse("bolt://example.com:notaport").is_err());
        assert!(BoltUrl::parse("bolt://example.com:70000").is_err());
        assert!(BoltUrl::parse("bolt://example.com:").is_err());
    }

    #[test]
    fn rejects_empty_host() {
        assert!(BoltUrl::parse("bolt://:7687").is_err());
        assert!(BoltUrl::parse("bolt://").is_err());
    }

    #[test]
    fn display_round_trips_through_parse() {
        for raw in [
            "bolt://example.com:7687",
            "bolt+s://db.internal:7000",
            "bolt+ssc://203.0.113.10:7687",
            "bolt+s://[2001:db8::1]:7000",
        ] {
            let url = BoltUrl::parse(raw).expect("valid");
            let rendered = url.to_string();
            let reparsed = BoltUrl::parse(&rendered).expect("re-parse rendered URL");
            assert_eq!(url, reparsed, "{raw} -> {rendered}");
        }
    }

    #[test]
    fn a_trailing_path_is_ignored() {
        let url = BoltUrl::parse("bolt://example.com:7687/ignored?x=1").expect("valid");
        assert_eq!(url.host, "example.com");
        assert_eq!(url.port, 7687);
    }

    #[test]
    fn accept_any_verifier_config_builds() {
        // Exercises the dangerous-verifier config path (provider wiring + scheme advertisement) so a
        // regression in the rustls builder chain is caught without opening a socket.
        assert!(tls_config_accept_any().is_ok());
    }

    #[test]
    fn verified_config_builds_with_mozilla_roots() {
        assert!(tls_config_verified().is_ok());
    }
}
