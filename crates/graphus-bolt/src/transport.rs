//! The **transport seam** — the byte pipe the Bolt state machine reads from and writes to, with
//! the socket I/O left to the server (`04-technical-design.md` §8.1 "only the transport and auth
//! differ"; rmp #20).
//!
//! This crate is deliberately **transport-agnostic**: the same [`crate::server`] state machine runs
//! over a `UnixStream` (UDS) and a TLS-wrapped `TcpStream` (Bolt-over-TCP), and the only difference
//! is which concrete [`Transport`] the server hands it (`04 §8.1`/§8.4). Modelling the transport as
//! a trait keeps `graphus-bolt` free of `tokio`/sockets/TLS — those belong to the listener (rmp
//! #20) — while remaining **fully testable in-process** over an in-memory byte buffer.
//!
//! [`Transport`] is intentionally a **blocking, synchronous** byte interface. The async runtime,
//! backpressure, and `select!` cancellation live in the server (`04 §9`); a synchronous seam is the
//! simplest contract to drive the protocol logic and to test exhaustively, and the listener adapts
//! its async socket to it (e.g. by running the per-connection loop on a blocking task, or by
//! feeding decoded frames in). The protocol-correctness guarantees this crate certifies do not
//! depend on the concurrency model.

use crate::error::{BoltError, BoltResult};

/// A bidirectional byte pipe for one Bolt connection.
///
/// The state machine reads request bytes with [`Transport::read`] and writes response bytes with
/// [`Transport::write_all`]. Implementations map these onto a real socket (the server) or an
/// in-memory buffer (tests). EOF is signalled by [`Transport::read`] returning `Ok(0)`.
pub trait Transport {
    /// Reads some bytes into `buf`, returning how many were read. `Ok(0)` means the peer closed
    /// the connection (EOF).
    ///
    /// # Errors
    /// [`BoltError::Transport`] if the underlying pipe fails.
    fn read(&mut self, buf: &mut [u8]) -> BoltResult<usize>;

    /// Writes the whole of `bytes`, retrying short writes until done.
    ///
    /// An implementation MAY buffer the bytes rather than push them to the underlying pipe
    /// immediately; in that case [`Transport::flush`] (or the implicit flush a real socket transport
    /// performs before its next [`Transport::read`]) is what guarantees delivery. Buffering changes
    /// only *when* bytes leave, never *what* bytes leave — the wire output is byte-for-byte identical.
    ///
    /// # Errors
    /// [`BoltError::Transport`] if the underlying pipe fails before all bytes are written.
    fn write_all(&mut self, bytes: &[u8]) -> BoltResult<()>;

    /// Pushes any bytes buffered by [`Transport::write_all`] to the underlying pipe.
    ///
    /// The default is a no-op, which is correct for unbuffered transports (e.g. the in-memory test
    /// transport, which appends directly to its sink). A buffering socket transport overrides this to
    /// drain its buffer to the socket.
    ///
    /// The state machine relies on Bolt's strict request/response discipline: the server always
    /// returns to a read after writing a response, so flushing **before each read** delivers the full
    /// buffered response exactly when the server next blocks for a request. The few paths that write
    /// *without* a following read (handshake rejection, the terminal `run` returns) flush explicitly
    /// so the client never waits on bytes stuck in the buffer.
    ///
    /// # Errors
    /// [`BoltError::Transport`] if the underlying pipe fails while draining the buffer.
    fn flush(&mut self) -> BoltResult<()> {
        Ok(())
    }
}

/// A mutable reference to a transport is itself a transport (mirroring `std::io::Read`/`Write` for
/// `&mut T`). This lets a caller retain ownership of the concrete transport — e.g. to inspect what
/// the session wrote after [`crate::server::BoltSession::run`] returns — while still handing the
/// session something that satisfies `T: Transport`.
impl<T: Transport + ?Sized> Transport for &mut T {
    fn read(&mut self, buf: &mut [u8]) -> BoltResult<usize> {
        (**self).read(buf)
    }

    fn write_all(&mut self, bytes: &[u8]) -> BoltResult<()> {
        (**self).write_all(bytes)
    }

    fn flush(&mut self) -> BoltResult<()> {
        (**self).flush()
    }
}

/// An in-memory, single-direction byte queue used to build a test [`Transport`].
///
/// It is a simple FIFO: bytes pushed with [`ByteQueue::feed`] are handed out by
/// [`ByteQueue::take`]. A drained queue reports EOF (`take` returns 0).
#[derive(Debug, Default)]
pub struct ByteQueue {
    buf: std::collections::VecDeque<u8>,
}

impl ByteQueue {
    /// A new empty queue.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Appends bytes the consumer will later read.
    pub fn feed(&mut self, bytes: &[u8]) {
        self.buf.extend(bytes.iter().copied());
    }

    /// Pops up to `buf.len()` bytes into `buf`, returning the count (0 = empty/EOF).
    pub fn take(&mut self, buf: &mut [u8]) -> usize {
        let n = buf.len().min(self.buf.len());
        for slot in buf.iter_mut().take(n) {
            *slot = self
                .buf
                .pop_front()
                .expect("INVARIANT: n <= len checked above");
        }
        n
    }

    /// All bytes currently queued (without consuming them), as a contiguous `Vec`.
    #[must_use]
    pub fn snapshot(&self) -> Vec<u8> {
        self.buf.iter().copied().collect()
    }

    /// Whether the queue is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }
}

/// An in-memory [`Transport`] for tests: a client-supplied **inbound** queue (bytes the server will
/// read) and an **outbound** sink (bytes the server writes), so a whole session can be driven and
/// asserted in-process with no sockets.
///
/// Build it with [`MemoryTransport::with_input`], feed more bytes mid-session with
/// [`MemoryTransport::feed`], and read what the server wrote with [`MemoryTransport::written`].
#[derive(Debug, Default)]
pub struct MemoryTransport {
    inbound: ByteQueue,
    outbound: Vec<u8>,
}

impl MemoryTransport {
    /// A transport whose inbound stream is `input` (what the server will read).
    #[must_use]
    pub fn with_input(input: &[u8]) -> Self {
        let mut inbound = ByteQueue::new();
        inbound.feed(input);
        Self {
            inbound,
            outbound: Vec::new(),
        }
    }

    /// Appends more inbound bytes (e.g. the next client message in a scripted session).
    pub fn feed(&mut self, bytes: &[u8]) {
        self.inbound.feed(bytes);
    }

    /// All bytes the server has written so far.
    #[must_use]
    pub fn written(&self) -> &[u8] {
        &self.outbound
    }

    /// Takes ownership of the written bytes, clearing the outbound buffer.
    pub fn take_written(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.outbound)
    }

    /// Whether all inbound bytes have been consumed.
    #[must_use]
    pub fn input_drained(&self) -> bool {
        self.inbound.is_empty()
    }
}

impl Transport for MemoryTransport {
    fn read(&mut self, buf: &mut [u8]) -> BoltResult<usize> {
        Ok(self.inbound.take(buf))
    }

    fn write_all(&mut self, bytes: &[u8]) -> BoltResult<()> {
        self.outbound.extend_from_slice(bytes);
        Ok(())
    }
}

/// A [`Transport`] wrapper that fails the *n*-th write, for testing transport-error handling.
#[derive(Debug)]
pub struct FailingTransport {
    inner: MemoryTransport,
    fail_after_writes: usize,
    writes: usize,
}

impl FailingTransport {
    /// Wraps `inner`, returning a [`BoltError::Transport`] on the write after `fail_after` writes.
    #[must_use]
    pub fn new(inner: MemoryTransport, fail_after: usize) -> Self {
        Self {
            inner,
            fail_after_writes: fail_after,
            writes: 0,
        }
    }
}

impl Transport for FailingTransport {
    fn read(&mut self, buf: &mut [u8]) -> BoltResult<usize> {
        self.inner.read(buf)
    }

    fn write_all(&mut self, bytes: &[u8]) -> BoltResult<()> {
        if self.writes >= self.fail_after_writes {
            return Err(BoltError::Transport("injected write failure".to_owned()));
        }
        self.writes += 1;
        self.inner.write_all(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn byte_queue_is_fifo_and_reports_eof() {
        let mut q = ByteQueue::new();
        q.feed(&[1, 2, 3]);
        let mut buf = [0u8; 2];
        assert_eq!(q.take(&mut buf), 2);
        assert_eq!(buf, [1, 2]);
        assert_eq!(q.take(&mut buf), 1);
        assert_eq!(buf[0], 3);
        assert_eq!(q.take(&mut buf), 0); // drained = EOF
    }

    #[test]
    fn memory_transport_reads_input_and_collects_writes() {
        let mut t = MemoryTransport::with_input(b"abc");
        let mut buf = [0u8; 4];
        let n = t.read(&mut buf).unwrap();
        assert_eq!(&buf[..n], b"abc");
        assert_eq!(t.read(&mut buf).unwrap(), 0); // EOF

        t.write_all(b"xy").unwrap();
        t.write_all(b"z").unwrap();
        assert_eq!(t.written(), b"xyz");
        assert_eq!(t.take_written(), b"xyz");
        assert_eq!(t.written(), b"");
    }

    #[test]
    fn failing_transport_errors_after_n_writes() {
        let mut t = FailingTransport::new(MemoryTransport::default(), 1);
        assert!(t.write_all(b"ok").is_ok());
        assert!(matches!(t.write_all(b"boom"), Err(BoltError::Transport(_))));
    }
}
