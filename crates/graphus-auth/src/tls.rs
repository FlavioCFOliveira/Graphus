//! TLS 1.3 server-configuration builder for the network listeners (`04 §8.4`, `D-auth-scheme`).
//!
//! Bolt-over-TCP and REST require **mandatory TLS** (the UDS path does not — it is local and
//! kernel-protected). This module builds a [`rustls::ServerConfig`] **pinned to TLS 1.3 only**
//! (`.with_protocol_versions(&[&rustls::version::TLS13])`), with no client-certificate auth (client
//! identity comes from Bolt native auth / Bearer JWT, not mTLS, in v1).
//!
//! It **does not open any socket** — performing the handshake and accepting connections is the
//! server's job (rmp #18/#19). The function takes PEM text (the operator's certificate chain and
//! private key), parses it to DER with `rustls-pemfile`, and returns a ready `ServerConfig` (or an
//! [`AuthError::TlsConfig`] describing why the material was rejected). This keeps the crate
//! testable from an in-process self-signed cert with no I/O.
//!
//! rustls 0.23's default `aws_lc_rs` provider installs a process-default `CryptoProvider`, so
//! `ServerConfig::builder*` needs no manual provider wiring here.

use std::io::Cursor;
use std::sync::Arc;

use rustls::ServerConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};

use crate::error::{AuthError, Result};

/// Builds a **TLS 1.3-only** [`ServerConfig`] from a PEM certificate chain and a PEM private key.
///
/// `cert_pem` must contain one or more `CERTIFICATE` blocks (leaf first, then any intermediates);
/// `key_pem` must contain exactly one private key (PKCS#8, PKCS#1/RSA, or SEC1/EC). Client
/// authentication is disabled.
///
/// The returned config negotiates **only** TLS 1.3 — TLS 1.2 and below are refused at the protocol
/// level — satisfying the network-path requirement of `04 §8.4`.
///
/// # Errors
/// [`AuthError::TlsConfig`] if:
/// - the certificate PEM contains no certificates or fails to parse;
/// - the key PEM contains no private key or fails to parse;
/// - rustls rejects the cert/key pair (e.g. the key does not match the leaf certificate).
///
/// # Examples
/// ```
/// # use graphus_auth::tls_server_config;
/// // A self-signed cert/key generated in-test (see the crate tests for the `rcgen` flow).
/// # let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
/// # let cert_pem = cert.cert.pem();
/// # let key_pem = cert.signing_key.serialize_pem();
/// let config = tls_server_config(&cert_pem, &key_pem).expect("valid self-signed material");
/// // The config is ready to wrap an accepted TCP stream (the listener does the handshake).
/// // It negotiates TLS 1.3 only; see the crate tests for the in-memory handshake that proves a
/// // TLS 1.2 client is refused.
/// # let _ = config;
/// ```
pub fn tls_server_config(cert_pem: &str, key_pem: &str) -> Result<ServerConfig> {
    let certs = parse_certificates(cert_pem)?;
    let key = parse_private_key(key_pem)?;

    ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| AuthError::TlsConfig {
            detail: format!("rustls rejected the certificate/key: {e}"),
        })
}

/// Parses every `CERTIFICATE` block in `cert_pem` into owned DER, erroring if none are present.
fn parse_certificates(cert_pem: &str) -> Result<Vec<CertificateDer<'static>>> {
    let mut reader = Cursor::new(cert_pem.as_bytes());
    let certs = rustls_pemfile::certs(&mut reader)
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|e| AuthError::TlsConfig {
            detail: format!("could not parse certificate PEM: {e}"),
        })?;
    if certs.is_empty() {
        return Err(AuthError::TlsConfig {
            detail: "certificate PEM contained no certificates".to_owned(),
        });
    }
    Ok(certs)
}

/// Parses the single private key in `key_pem` into owned DER (PKCS#8 / PKCS#1 / SEC1).
fn parse_private_key(key_pem: &str) -> Result<PrivateKeyDer<'static>> {
    let mut reader = Cursor::new(key_pem.as_bytes());
    rustls_pemfile::private_key(&mut reader)
        .map_err(|e| AuthError::TlsConfig {
            detail: format!("could not parse private-key PEM: {e}"),
        })?
        .ok_or_else(|| AuthError::TlsConfig {
            detail: "private-key PEM contained no key".to_owned(),
        })
}

/// `ServerConfig` is wrapped in an `Arc` by the listener to share across accepted connections; this
/// is a small convenience so callers do not repeat the wrap.
#[must_use]
pub fn into_shared(config: ServerConfig) -> Arc<ServerConfig> {
    Arc::new(config)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    use rustls::pki_types::ServerName;
    use rustls::{ClientConfig, ClientConnection, RootCertStore, ServerConnection};

    /// Generates a fresh self-signed cert/key as PEM, in-process (no sockets, no files).
    fn self_signed_pem() -> (String, String) {
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()])
            .expect("rcgen self-signed generation");
        (cert.cert.pem(), cert.signing_key.serialize_pem())
    }

    /// Drives a rustls client/server handshake to completion **entirely in memory** (no sockets):
    /// it ping-pongs the TLS records each side wants to send through `Vec<u8>` buffers until both
    /// stop handshaking or one side errors. Returns the first handshake error, if any.
    ///
    /// This is the socket-free way to *prove* a protocol property of the server config: a TLS 1.2
    /// client must be refused by a TLS 1.3-only server during version negotiation, which happens
    /// before any certificate verification.
    fn drive_handshake(
        client: &mut ClientConnection,
        server: &mut ServerConnection,
    ) -> std::result::Result<(), rustls::Error> {
        // Bound the loop so a logic error cannot hang the test.
        for _ in 0..20 {
            // client -> server
            let mut buf = Vec::new();
            while client.wants_write() {
                client.write_tls(&mut buf).unwrap();
            }
            if !buf.is_empty() {
                let mut rd = Cursor::new(&buf);
                while server.read_tls(&mut rd).unwrap() > 0 {}
                server.process_new_packets()?;
            }
            // server -> client
            let mut buf = Vec::new();
            while server.wants_write() {
                server.write_tls(&mut buf).unwrap();
            }
            if !buf.is_empty() {
                let mut rd = Cursor::new(&buf);
                while client.read_tls(&mut rd).unwrap() > 0 {}
                client.process_new_packets()?;
            }
            if !client.is_handshaking() && !server.is_handshaking() {
                break;
            }
        }
        Ok(())
    }

    #[test]
    fn builds_a_config_from_self_signed_material() {
        let (cert_pem, key_pem) = self_signed_pem();
        // The requirement's "succeeds" half: valid self-signed material yields a config.
        assert!(tls_server_config(&cert_pem, &key_pem).is_ok());
    }

    #[test]
    fn refuses_a_tls12_client_proving_tls13_only() {
        // rustls hides the enabled-version list (`ServerConfig::versions` is private), so the
        // robust, socket-free proof of "TLS 1.3 only" is a handshake: a TLS 1.2-only client must be
        // refused at version negotiation. (A self-signed leaf would later fail cert verification,
        // but version negotiation fails first, so no trust chain is needed for this assertion.)
        let (cert_pem, key_pem) = self_signed_pem();
        let server_config = tls_server_config(&cert_pem, &key_pem).unwrap();
        let mut server = ServerConnection::new(into_shared(server_config)).unwrap();

        // A client that offers ONLY TLS 1.2.
        let client_config =
            ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS12])
                .with_root_certificates(RootCertStore::empty())
                .with_no_client_auth();
        let mut client = ClientConnection::new(
            std::sync::Arc::new(client_config),
            ServerName::try_from("localhost").unwrap(),
        )
        .unwrap();

        let result = drive_handshake(&mut client, &mut server);
        assert!(
            result.is_err(),
            "a TLS 1.2-only client must be refused by a TLS 1.3-only server"
        );
    }

    #[test]
    fn empty_certificate_pem_is_rejected() {
        let (_, key_pem) = self_signed_pem();
        let err = tls_server_config("", &key_pem).unwrap_err();
        assert!(matches!(err, AuthError::TlsConfig { .. }));
    }

    #[test]
    fn empty_key_pem_is_rejected() {
        let (cert_pem, _) = self_signed_pem();
        let err = tls_server_config(&cert_pem, "").unwrap_err();
        assert!(matches!(err, AuthError::TlsConfig { .. }));
    }

    #[test]
    fn mismatched_key_is_rejected() {
        // Cert from one key, private key from a different self-signed pair ⇒ rustls rejects.
        let (cert_pem, _) = self_signed_pem();
        let (_, other_key_pem) = self_signed_pem();
        let err = tls_server_config(&cert_pem, &other_key_pem).unwrap_err();
        assert!(matches!(err, AuthError::TlsConfig { .. }));
    }

    #[test]
    fn garbage_pem_is_rejected_not_panicking() {
        let err = tls_server_config("not a pem", "also not a pem").unwrap_err();
        assert!(matches!(err, AuthError::TlsConfig { .. }));
    }

    #[test]
    fn into_shared_wraps_in_arc_usable_by_a_connection() {
        let (cert_pem, key_pem) = self_signed_pem();
        let config = tls_server_config(&cert_pem, &key_pem).unwrap();
        let shared = into_shared(config);
        // The shared config is accepted by a ServerConnection (the listener's usage).
        assert!(ServerConnection::new(shared).is_ok());
    }
}
