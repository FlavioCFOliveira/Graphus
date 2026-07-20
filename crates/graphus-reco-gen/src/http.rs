//! A minimal, dependency-free HTTP/1.1 **GET** client, used by `reco_bench` to scrape a co-located
//! Graphus server's Prometheus `/metrics` endpoint over the plaintext-loopback REST listener
//! (`rmp #805`).
//!
//! # Why this exists
//!
//! `reco_bench` drives its workload over Bolt (UDS or TCP), which cannot serve `/metrics`. The one
//! stable, reclamation-independent measure of the WAL bytes a run **wrote** —
//! `graphus_wal_bytes_written_total` (`rmp #745`) — lives in the server's Prometheus text exposition,
//! reachable only over HTTP. So the bench performs a single, small GET against the local REST port
//! after its ladder, parses the counter, and reports it as `storage.wal_bytes` (the durable write
//! volume), replacing the bimodal on-disk WAL-directory walk that could not gate a regression.
//!
//! # Scope
//!
//! This is a *client* helper for a **dev-only** benchmark binary against a **loopback, plaintext**
//! endpoint the example itself booted. It is deliberately tiny: blocking, `Connection: close`, no
//! TLS, no redirects, no keep-alive. It is not a general-purpose HTTP client and must not be used as
//! one. The response parsing (header split, status line, chunked de-framing) mirrors the loader's
//! (`reco_load`), kept separate here so the bench does not depend on a binary crate's internals.

use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;

/// Connection timeout for the loopback GET. Generous: the endpoint is a local process the example
/// just booted, but a busy CI host can be slow to accept.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(30);

/// Read/write timeout. The `/metrics` body is a few kilobytes of text; this only guards against a
/// wedged peer.
const IO_TIMEOUT: Duration = Duration::from_secs(120);

/// A parsed HTTP/1.1 response: the status code and the (de-chunked) body bytes.
#[derive(Debug, Clone)]
pub struct HttpResponse {
    /// The HTTP status code (e.g. `200`).
    pub status: u16,
    /// The response body, de-chunked if it arrived `Transfer-Encoding: chunked`.
    pub body: Vec<u8>,
}

impl HttpResponse {
    /// The body as UTF-8 text, or an error if it is not valid UTF-8 (a `/metrics` scrape always is).
    ///
    /// # Errors
    ///
    /// Returns a message when the body is not valid UTF-8.
    pub fn text(&self) -> Result<String, String> {
        String::from_utf8(self.body.clone()).map_err(|e| format!("response body is not UTF-8: {e}"))
    }
}

/// Issues a blocking `GET {path}` to `addr` (`host:port`), sending `Authorization: Bearer {bearer}`
/// when a token is supplied, and returns the parsed response.
///
/// The connection is `Connection: close`, so the whole body is read to EOF. TLS is not supported —
/// this is for the example's own **plaintext loopback** REST listener only.
///
/// # Errors
///
/// Returns a message on any DNS/connect/IO failure or a malformed response.
pub fn http_get(addr: &str, path: &str, bearer: Option<&str>) -> Result<HttpResponse, String> {
    let mut stream = connect(addr)?;

    let mut head = format!(
        "GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\nAccept: text/plain\r\n"
    );
    if let Some(token) = bearer {
        head.push_str(&format!("Authorization: Bearer {token}\r\n"));
    }
    head.push_str("\r\n");

    stream
        .write_all(head.as_bytes())
        .and_then(|()| stream.flush())
        .map_err(|e| format!("writing GET {addr}{path} failed: {e}"))?;

    let mut raw = Vec::new();
    stream
        .read_to_end(&mut raw)
        .map_err(|e| format!("reading response from {addr}{path} failed: {e}"))?;

    parse_response(&raw).map_err(|e| format!("malformed response from {addr}{path}: {e}"))
}

/// Opens a timeout-bounded TCP connection to `host:port` (first resolved address).
fn connect(addr: &str) -> Result<TcpStream, String> {
    let sock = addr
        .to_socket_addrs()
        .map_err(|e| format!("resolving {addr} failed: {e}"))?
        .next()
        .ok_or_else(|| format!("no socket address resolved for {addr}"))?;
    let stream = TcpStream::connect_timeout(&sock, CONNECT_TIMEOUT)
        .map_err(|e| format!("connecting to {addr} failed: {e}"))?;
    stream
        .set_read_timeout(Some(IO_TIMEOUT))
        .and_then(|()| stream.set_write_timeout(Some(IO_TIMEOUT)))
        .map_err(|e| format!("setting socket timeouts for {addr} failed: {e}"))?;
    let _ = stream.set_nodelay(true);
    Ok(stream)
}

/// Splits a raw HTTP/1.1 response into `(status, body)`, de-chunking a `Transfer-Encoding: chunked`
/// body. The body is everything after the header terminator, to EOF (`Connection: close`).
///
/// # Errors
/// When the header terminator or status code cannot be found, or a chunked body is malformed.
fn parse_response(raw: &[u8]) -> Result<HttpResponse, String> {
    let sep = find_sub(raw, b"\r\n\r\n").ok_or("no header terminator (\\r\\n\\r\\n)")?;
    let head = &raw[..sep];
    let body = &raw[sep + 4..];

    let line_end = find_sub(head, b"\r\n").unwrap_or(head.len());
    let status_line =
        std::str::from_utf8(&head[..line_end]).map_err(|_| "status line is not UTF-8")?;
    let status: u16 = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| format!("no status code in status line {status_line:?}"))?;

    let mut chunked = false;
    for line in std::str::from_utf8(&head[line_end..])
        .unwrap_or("")
        .split("\r\n")
    {
        if let Some((k, v)) = line.split_once(':')
            && k.trim().eq_ignore_ascii_case("transfer-encoding")
            && v.to_ascii_lowercase().contains("chunked")
        {
            chunked = true;
        }
    }

    let body = if chunked {
        dechunk(body)?
    } else {
        body.to_vec()
    };
    Ok(HttpResponse { status, body })
}

/// Decodes a complete, in-memory HTTP/1.1 chunked body into its payload bytes, ignoring any trailer.
///
/// # Errors
/// When a chunk-size line is missing/invalid or a chunk is truncated.
fn dechunk(mut data: &[u8]) -> Result<Vec<u8>, String> {
    let mut out = Vec::with_capacity(data.len());
    loop {
        let nl = find_sub(data, b"\r\n").ok_or("chunked body: missing chunk-size CRLF")?;
        let size_line = std::str::from_utf8(&data[..nl])
            .map_err(|_| "chunked body: chunk-size line is not UTF-8")?;
        // A chunk-size line may carry `;ext` extensions after the hex size.
        let hex = size_line.split(';').next().unwrap_or("").trim();
        let size = usize::from_str_radix(hex, 16)
            .map_err(|_| format!("chunked body: invalid chunk size {hex:?}"))?;
        data = &data[nl + 2..];
        if size == 0 {
            break; // last chunk; trailers (if any) are ignored
        }
        if data.len() < size {
            return Err("chunked body: truncated chunk data".to_owned());
        }
        out.extend_from_slice(&data[..size]);
        data = &data[size..];
        // Skip the CRLF that terminates the chunk data.
        if data.starts_with(b"\r\n") {
            data = &data[2..];
        }
    }
    Ok(out)
}

/// The index of the first occurrence of `needle` in `hay`, or `None`.
fn find_sub(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || needle.len() > hay.len() {
        return None;
    }
    hay.windows(needle.len()).position(|w| w == needle)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_a_plain_content_length_response() {
        let raw =
            b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 11\r\n\r\nhello world";
        let r = parse_response(raw).expect("parse");
        assert_eq!(r.status, 200);
        assert_eq!(r.text().unwrap(), "hello world");
    }

    #[test]
    fn de_chunks_a_chunked_body() {
        // "Wiki" + "pedia" across two chunks, then the terminating 0-chunk.
        let raw = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nWiki\r\n5\r\npedia\r\n0\r\n\r\n";
        let r = parse_response(raw).expect("parse");
        assert_eq!(r.status, 200);
        assert_eq!(r.text().unwrap(), "Wikipedia");
    }

    #[test]
    fn surfaces_a_non_200_status() {
        let raw = b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n";
        let r = parse_response(raw).expect("parse");
        assert_eq!(r.status, 403);
        assert!(r.body.is_empty());
    }

    #[test]
    fn a_headerless_blob_is_an_error_not_a_panic() {
        assert!(parse_response(b"garbage without a terminator").is_err());
    }

    #[test]
    fn find_sub_matches_and_misses() {
        assert_eq!(find_sub(b"abcdef", b"cd"), Some(2));
        assert_eq!(find_sub(b"abcdef", b"xy"), None);
        assert_eq!(find_sub(b"abc", b""), None);
    }
}
