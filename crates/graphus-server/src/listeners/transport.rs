//! The async→blocking bridge for the Bolt transport seam (`04-technical-design.md` §8.1, §9.1).
//!
//! `graphus_bolt::Transport` is a **blocking** byte pipe (`read`/`write_all`); the accepted
//! connection is an **async** `AsyncRead + AsyncWrite` stream (a `UnixStream`, or a TLS-wrapped
//! `TcpStream`). [`AsyncToBlockingTransport`] bridges the two: each Bolt connection runs on a
//! `tokio::task::spawn_blocking` task, and the transport drives the async socket op to completion
//! with the runtime [`Handle::block_on`].
//!
//! ## Why this is sound (no §9.1 violation)
//!
//! `Handle::block_on` panics only when called on a **runtime worker** thread. A `spawn_blocking`
//! thread is part of Tokio's *blocking* pool, not a worker — blocking there is exactly what the pool
//! is for — so `block_on` is legal and parks the blocking thread (never a worker) while the async I/O
//! makes progress on the runtime's reactor. This keeps the hard rule "no blocking on runtime
//! workers" (`04 §9.1`) intact: the protocol state machine and its socket waits live entirely on a
//! blocking task.

use graphus_bolt::error::{BoltError, BoltResult};
use graphus_bolt::transport::Transport;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::runtime::Handle;

use crate::shutdown::ShutdownCoordinator;

/// A blocking [`Transport`] over an async byte stream `S`, driven via the runtime `Handle`.
///
/// `S` is the accepted connection (`UdsConn`, or `tokio_rustls::server::TlsStream<TcpConn>`). The
/// transport also holds the shutdown coordinator so a blocked `read` can be interrupted when the
/// server is draining (`04 §9.4`): a read that loses the race to shutdown returns EOF, ending the
/// session loop cleanly.
pub struct AsyncToBlockingTransport<S> {
    stream: S,
    handle: Handle,
    shutdown: ShutdownCoordinator,
    /// Outbound write buffer (rmp #317). [`Transport::write_all`] appends here without touching the
    /// socket; the bytes are pushed (one `block_on` + one `write_all` + one `flush`) by
    /// [`Transport::flush`] — which the state machine calls before every read and at the terminal
    /// write-without-read paths. This collapses a `PULL` of *N* rows from *N* syscalls/flushes (one
    /// per `RECORD`) to **one** per batch, while leaving the wire bytes byte-for-byte identical.
    write_buf: Vec<u8>,
    /// Optional per-read deadline (`None` = no deadline). Serves as the **idle/read timeout** that
    /// reaps a silent connection (rmp #118): each `read` that receives no bytes within the window
    /// returns EOF, ending the session loop cleanly. It also doubles as a drain bound during graceful
    /// shutdown (`04 §9.4`) — in both cases the effect is the same: a stalled read ends the session.
    read_deadline: Option<std::time::Duration>,
}

impl<S> AsyncToBlockingTransport<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    /// Builds the bridge over `stream`, using `handle` to drive async ops and `shutdown` to interrupt
    /// a blocked read during a graceful drain.
    pub fn new(
        stream: S,
        handle: Handle,
        shutdown: ShutdownCoordinator,
        read_deadline: Option<std::time::Duration>,
    ) -> Self {
        Self {
            stream,
            handle,
            shutdown,
            write_buf: Vec::new(),
            read_deadline,
        }
    }
}

impl<S> Transport for AsyncToBlockingTransport<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    fn read(&mut self, buf: &mut [u8]) -> BoltResult<usize> {
        // Flush any buffered response BEFORE blocking for the next request (rmp #317). Bolt's strict
        // request/response discipline guarantees the server always returns here after writing a
        // response, so this delivers the full buffered response to the client at exactly the moment
        // the server next waits for input — no deadlock, no lost bytes.
        self.flush()?;
        let stream = &mut self.stream;
        let shutdown = &self.shutdown;
        let deadline = self.read_deadline;
        self.handle.block_on(async move {
            // Race the read against the shutdown edge (and an optional drain deadline) so a session
            // idle-blocked on the socket does not stall graceful shutdown (`04 §9.4`).
            let read_fut = stream.read(buf);
            tokio::pin!(read_fut);
            if let Some(d) = deadline {
                tokio::select! {
                    r = &mut read_fut => r.map_err(|e| BoltError::Transport(e.to_string())),
                    () = shutdown.wait() => Ok(0), // treat shutdown as EOF
                    () = tokio::time::sleep(d) => Ok(0), // drain deadline: end the session
                }
            } else {
                tokio::select! {
                    r = &mut read_fut => r.map_err(|e| BoltError::Transport(e.to_string())),
                    () = shutdown.wait() => Ok(0),
                }
            }
        })
    }

    fn write_all(&mut self, bytes: &[u8]) -> BoltResult<()> {
        // Buffer only — no syscall, no `block_on`, no flush per call (rmp #317). A `PULL` that emits
        // one `RECORD` per row used to cost one syscall + one flush (one TLS record under TLS) +
        // one `block_on` *per row*; now the whole batch accumulates here and leaves in a single
        // `flush` (driven before the next read). The bytes appended are exactly the framed PackStream
        // the caller passed, so the wire output is unchanged.
        self.write_buf.extend_from_slice(bytes);
        Ok(())
    }

    fn flush(&mut self) -> BoltResult<()> {
        if self.write_buf.is_empty() {
            return Ok(());
        }
        let stream = &mut self.stream;
        let buf = &self.write_buf;
        let result = self.handle.block_on(async move {
            stream
                .write_all(buf)
                .await
                .map_err(|e| BoltError::Transport(e.to_string()))?;
            // Flush so the client sees the response promptly (Bolt is request/response). For a TLS
            // stream this also drives the record out of the rustls buffer.
            stream
                .flush()
                .await
                .map_err(|e| BoltError::Transport(e.to_string()))
        });
        // Clear regardless of outcome: on error the connection is dead and the session ends, so the
        // buffered bytes must not be re-sent against a future (impossible) read.
        self.write_buf.clear();
        result
    }
}
