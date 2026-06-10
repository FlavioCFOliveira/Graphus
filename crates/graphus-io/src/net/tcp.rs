//! Async TCP listener and connection (`bolt://` over TLS is layered above by `graphus-bolt`).
//!
//! This is the epoll/kqueue baseline transport (`04 §9.1`): Tokio's [`TcpListener`] is driven by
//! the multi-thread work-stealing runtime. TLS is **not** handled here — `graphus-io` exposes the
//! raw byte stream and the connectivity layer wraps it (rustls for `bolt://`, `04 §8.4`). Per the
//! task scope, no per-connection buffering is added here; backpressure is the server's concern.

use std::io;
use std::net::SocketAddr;

use tokio::net::{TcpListener, TcpStream};

/// An async TCP acceptor bound to a local address.
///
/// Construct with [`TcpAcceptor::bind`], then call [`TcpAcceptor::accept`] in a loop to obtain a
/// [`TcpConn`] per client. `TCP_NODELAY` is set on every accepted connection (Nagle off — Bolt and
/// REST are request/response latency-sensitive).
#[derive(Debug)]
pub struct TcpAcceptor {
    listener: TcpListener,
}

impl TcpAcceptor {
    /// Binds a TCP listener to `addr`.
    ///
    /// Passing a port of `0` lets the OS choose a free port; recover it with
    /// [`TcpAcceptor::local_addr`] (this is how the in-process loopback tests avoid port clashes).
    ///
    /// # Errors
    /// Returns the `std::io::Error` from `bind(2)`/`listen(2)` (e.g. address in use, permission).
    pub async fn bind(addr: SocketAddr) -> io::Result<Self> {
        let listener = TcpListener::bind(addr).await?;
        Ok(Self { listener })
    }

    /// The actual local address the listener is bound to (resolves an OS-chosen port).
    ///
    /// # Errors
    /// Propagates `getsockname(2)` failure.
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.listener.local_addr()
    }

    /// Accepts the next inbound connection.
    ///
    /// Sets `TCP_NODELAY` on the accepted socket before returning it. This call is cancellation-safe
    /// (Tokio's `accept` is): dropping the returned future before it resolves does not drop an
    /// already-accepted connection.
    ///
    /// # Errors
    /// Returns the `std::io::Error` from `accept(2)`, or from setting `TCP_NODELAY`.
    pub async fn accept(&self) -> io::Result<TcpConn> {
        let (stream, peer) = self.listener.accept().await?;
        // Latency over throughput on the request path; the server may still coalesce writes itself.
        stream.set_nodelay(true)?;
        Ok(TcpConn { stream, peer })
    }
}

/// An accepted TCP connection: an `AsyncRead + AsyncWrite` byte stream plus its peer address.
///
/// Deref to the inner [`TcpStream`] is intentionally **not** provided; the connection is consumed
/// via the `AsyncRead`/`AsyncWrite` impls (or [`TcpConn::into_inner`] when the caller needs the raw
/// stream, e.g. to hand it to a rustls acceptor).
#[derive(Debug)]
pub struct TcpConn {
    stream: TcpStream,
    peer: SocketAddr,
}

impl TcpConn {
    /// The remote peer's socket address.
    #[must_use]
    pub fn peer_addr(&self) -> SocketAddr {
        self.peer
    }

    /// Consumes the wrapper and returns the underlying Tokio [`TcpStream`].
    ///
    /// Used by the connectivity layer to wrap the stream in TLS (`04 §8.4`).
    #[must_use]
    pub fn into_inner(self) -> TcpStream {
        self.stream
    }
}

// The connection *is* an async byte stream. We delegate to the inner `TcpStream` rather than
// re-export it directly so the public surface is a stable `TcpConn` type the server (#20) codes
// against, independent of whether the bytes come from epoll, kqueue or (later) io_uring.
impl tokio::io::AsyncRead for TcpConn {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::pin::Pin::new(&mut self.stream).poll_read(cx, buf)
    }
}

impl tokio::io::AsyncWrite for TcpConn {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<io::Result<usize>> {
        std::pin::Pin::new(&mut self.stream).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::pin::Pin::new(&mut self.stream).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        std::pin::Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}
