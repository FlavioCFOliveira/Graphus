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
    /// The **currently-active** per-read deadline (`None` = no deadline): each `read` that receives no
    /// bytes within the window returns EOF, ending the session loop cleanly. It also doubles as a drain
    /// bound during graceful shutdown (`04 §9.4`) — in both cases the effect is the same: a stalled read
    /// ends the session.
    ///
    /// It starts at the **pre-authentication** deadline (the slow-loris guard that reaps a
    /// connected-but-silent *unauthenticated* peer which withholds the Bolt handshake / `HELLO` /
    /// `LOGON` — rmp #469, F-NET-1) and is relaxed to [`idle_deadline`](Self::idle_deadline) once the
    /// session authenticates (via [`Transport::on_authenticated`]), so a legitimate long-lived
    /// authenticated session is governed only by the (often disabled) idle policy, not the strict
    /// pre-auth bound.
    read_deadline: Option<std::time::Duration>,
    /// The steady-state **idle** read deadline that takes over once the connection authenticates
    /// (rmp #118; `None` = idle reaping disabled, the default). Held here so
    /// [`Transport::on_authenticated`] can swap it into [`read_deadline`](Self::read_deadline).
    idle_deadline: Option<std::time::Duration>,
    /// The **cumulative** pre-authentication wall-clock deadline (rmp #478, R2): an absolute instant,
    /// captured at construction (≈ accept / post-TLS), past which the *whole* pre-auth phase is reaped —
    /// regardless of how recently a byte arrived. The [`read_deadline`](Self::read_deadline) above is a
    /// *per-read* bound that every received byte resets; on its own a slow dribbler that sends one byte
    /// just under it can extend the unauthenticated phase indefinitely. This absolute bound caps the
    /// accept→READY span so that cannot happen: each pre-auth read is governed by the **earlier** of its
    /// per-read deadline and this instant. It is `None` once idle (no pre-auth guard configured), and is
    /// **cleared** on [`Transport::on_authenticated`] so a legitimate long-lived authenticated session is
    /// never reaped by it.
    pre_auth_absolute_deadline: Option<std::time::Instant>,
}

impl<S> AsyncToBlockingTransport<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    /// Builds the bridge over `stream`, using `handle` to drive async ops and `shutdown` to interrupt
    /// a blocked read during a graceful drain.
    ///
    /// `idle_deadline` is the steady-state idle/read timeout applied **once authenticated** (rmp #118;
    /// `None` disables idle reaping — the default). `pre_auth_deadline` is the stricter slow-loris
    /// guard applied from connection accept until authentication (rmp #469, F-NET-1): it reaps a peer
    /// that completes the transport handshake but then withholds the Bolt handshake / `HELLO` /
    /// `LOGON`, so an unauthenticated client can never pin a connection slot, a blocking thread, and a
    /// socket indefinitely. The active deadline starts at the **stricter** of the two (so a smaller
    /// idle policy is honoured during the pre-auth phase too) and is relaxed to `idle_deadline` when
    /// [`Transport::on_authenticated`] fires.
    pub fn new(
        stream: S,
        handle: Handle,
        shutdown: ShutdownCoordinator,
        idle_deadline: Option<std::time::Duration>,
        pre_auth_deadline: Option<std::time::Duration>,
    ) -> Self {
        // Active deadline for the pre-auth phase: the stricter (smaller) of the pre-auth guard and any
        // idle policy. If no pre-auth guard is configured, fall back to the idle policy alone.
        let read_deadline = match (pre_auth_deadline, idle_deadline) {
            (Some(p), Some(i)) => Some(p.min(i)),
            (Some(p), None) => Some(p),
            (None, i) => i,
        };
        // The cumulative pre-auth bound (rmp #478, R2): an absolute instant `pre_auth_deadline` from now
        // (construction ≈ accept / post-TLS), bounding the *whole* pre-auth phase so a dribbler that
        // keeps the per-read deadline alive cannot extend it indefinitely. `None` when no pre-auth guard
        // is configured (the per-read idle policy, if any, then governs alone).
        let pre_auth_absolute_deadline = pre_auth_deadline.map(|p| std::time::Instant::now() + p);
        Self {
            stream,
            handle,
            shutdown,
            write_buf: Vec::new(),
            read_deadline,
            idle_deadline,
            pre_auth_absolute_deadline,
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
        let absolute = self.pre_auth_absolute_deadline;
        self.handle.block_on(async move {
            // Race the read against the shutdown edge and the effective read deadline so a session
            // idle-blocked on the socket does not stall graceful shutdown (`04 §9.4`).
            //
            // The effective deadline for THIS read is the **earlier** of two bounds (rmp #478, R2):
            //   - the per-read `deadline` (the idle / pre-auth bound that every byte resets), and
            //   - the cumulative `absolute` pre-auth instant (the wall-clock cap on the whole pre-auth
            //     phase, which a dribbler cannot push back by sending a byte).
            // Taking the min means a slow dribbler keeping the per-read bound alive is still reaped once
            // the cumulative pre-auth instant passes, while a normal client (which authenticates, clearing
            // `absolute`) is then governed only by the relaxed idle policy.
            let read_fut = stream.read(buf);
            tokio::pin!(read_fut);
            let effective = effective_deadline(deadline, absolute);
            if let Some(when) = effective {
                tokio::select! {
                    r = &mut read_fut => r.map_err(|e| BoltError::Transport(e.to_string())),
                    () = shutdown.wait() => Ok(0), // treat shutdown as EOF
                    () = tokio::time::sleep_until(when) => Ok(0), // deadline: end the session
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

    fn on_authenticated(&mut self) {
        // The connection authenticated: drop the strict pre-authentication slow-loris deadline and
        // govern subsequent reads by the steady-state idle policy only (often `None` = no deadline),
        // so a legitimate long-lived authenticated session is not reaped (rmp #469, F-NET-1).
        self.read_deadline = self.idle_deadline;
        // Clear the cumulative pre-auth wall-clock bound (rmp #478, R2): once authenticated, only the
        // (relaxed) idle policy governs the session — the accept→READY cap must never reap it.
        self.pre_auth_absolute_deadline = None;
    }
}

/// The effective deadline instant for one pre-auth/idle read (rmp #478, R2): the **earlier** of the
/// per-read relative `deadline` (measured from *now*, so a received byte resets it) and the cumulative
/// pre-auth `absolute` instant (a fixed wall-clock cap on the whole pre-auth phase). `None` when neither
/// bound applies.
///
/// Must be called inside the Tokio runtime context — it reads [`tokio::time::Instant::now`]; the
/// transport's [`Transport::read`] calls it inside [`Handle::block_on`], which provides that context.
fn effective_deadline(
    deadline: Option<std::time::Duration>,
    absolute: Option<std::time::Instant>,
) -> Option<tokio::time::Instant> {
    let per_read = deadline.map(|d| tokio::time::Instant::now() + d);
    let cumulative = absolute.map(tokio::time::Instant::from_std);
    match (per_read, cumulative) {
        (Some(a), Some(b)) => Some(a.min(b)),
        (Some(a), None) => Some(a),
        (None, b) => b,
    }
}

#[cfg(test)]
mod tests {
    //! F-NET-1 (rmp #469) regression battery for the **pre-authentication read deadline** — the
    //! slow-loris / connection-pinning guard. A connected-but-silent *unauthenticated* peer (one that
    //! completes the transport handshake then withholds the Bolt handshake / `HELLO` / `LOGON`) must
    //! be reaped, never able to pin a blocking thread + connection permit + socket indefinitely; and
    //! once a session authenticates, the strict pre-auth deadline must relax to the steady-state idle
    //! policy so a legitimate long-lived authenticated session is not killed.

    use super::*;
    use crate::shutdown::ShutdownCoordinator;
    use std::io;
    use std::pin::Pin;
    use std::task::{Context, Poll};
    use std::time::{Duration, Instant};
    use tokio::io::ReadBuf;

    /// An async stream that **never** yields a read byte (`poll_read` is always `Pending`) — the model
    /// of a connected-but-silent peer. Writes succeed (so the implicit pre-read flush is a no-op-ish
    /// success); flush/shutdown succeed.
    #[derive(Default)]
    struct SilentStream;

    impl AsyncRead for SilentStream {
        fn poll_read(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            // A silent peer: never delivers a byte. We deliberately do not register a waker — the read
            // future is only ever completed by the deadline / shutdown branches of the transport's
            // `select!`, exactly as a real never-sending socket would be timed out.
            Poll::Pending
        }
    }

    impl AsyncWrite for SilentStream {
        fn poll_write(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            Poll::Ready(Ok(buf.len()))
        }
        fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
        fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    fn multi_thread_rt() -> tokio::runtime::Runtime {
        // A multi-thread runtime so the blocking `read` (which parks a thread in `Handle::block_on`)
        // runs on a `spawn_blocking` thread while the time driver fires the deadline on a worker —
        // exactly the production topology (`listeners::bolt::spawn_session`).
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .expect("build multi-thread runtime")
    }

    #[test]
    fn pre_auth_deadline_reaps_a_silent_unauthenticated_connection() {
        // The headline F-NET-1 guarantee: with idle reaping DISABLED (the default) but a 50 ms pre-auth
        // deadline, a silent peer's read is reaped as a clean EOF (`Ok(0)`) near the deadline — it does
        // NOT block forever pinning the blocking thread/permit/socket. Before this fix, with
        // idle_timeout = None, this read had no deadline at all and would hang until shutdown.
        let rt = multi_thread_rt();
        let handle = rt.handle().clone();
        let shutdown = ShutdownCoordinator::new();
        let mut t = AsyncToBlockingTransport::new(
            SilentStream,
            handle,
            shutdown,
            None,                            // idle reaping disabled (the production default)
            Some(Duration::from_millis(50)), // pre-auth slow-loris guard
        );
        let start = Instant::now();
        let n = rt
            .block_on(async move {
                tokio::task::spawn_blocking(move || {
                    let mut buf = [0u8; 16];
                    t.read(&mut buf)
                })
                .await
                .expect("blocking read task joins")
            })
            .expect("a reaped pre-auth read returns Ok(0) (EOF), never an error");
        assert_eq!(n, 0, "a silent pre-auth read is reaped as EOF");
        assert!(
            start.elapsed() < Duration::from_secs(5),
            "the silent connection was reaped near the 50ms deadline, not pinned indefinitely \
             (elapsed {:?})",
            start.elapsed()
        );
    }

    #[test]
    fn authenticated_connection_relaxes_to_the_idle_deadline() {
        // After authentication the strict pre-auth deadline must give way to the (looser) idle policy.
        // Pre-auth = 50 ms, idle = 600 ms: post-`on_authenticated`, a silent read must survive well
        // past 50 ms and only be reaped at ~600 ms — proving the swap (not the strict pre-auth bound)
        // governs an authenticated session. Both reads terminate, so the runtime drops cleanly.
        let rt = multi_thread_rt();
        let handle = rt.handle().clone();
        let shutdown = ShutdownCoordinator::new();
        let mut t = AsyncToBlockingTransport::new(
            SilentStream,
            handle,
            shutdown,
            Some(Duration::from_millis(600)), // idle policy (post-auth)
            Some(Duration::from_millis(50)),  // strict pre-auth guard
        );
        t.on_authenticated(); // relax: the 50ms pre-auth bound gives way to the 600ms idle policy
        let start = Instant::now();
        let n = rt
            .block_on(async move {
                tokio::task::spawn_blocking(move || {
                    let mut buf = [0u8; 16];
                    t.read(&mut buf)
                })
                .await
                .expect("blocking read task joins")
            })
            .expect("the idle-deadline read returns Ok(0) (EOF)");
        assert_eq!(n, 0, "the read is eventually reaped by the idle deadline");
        let elapsed = start.elapsed();
        assert!(
            elapsed > Duration::from_millis(250),
            "an authenticated session must NOT be reaped at the old 50ms pre-auth deadline \
             (elapsed {elapsed:?})"
        );
        assert!(
            elapsed < Duration::from_secs(5),
            "but it IS reaped at the ~600ms idle deadline (elapsed {elapsed:?})"
        );
    }

    #[test]
    fn authenticated_connection_with_idle_disabled_is_not_reaped() {
        // The Neo4j-compatible default: idle reaping disabled. After authentication, a silent idle
        // session must NOT be reaped at all — proving disabling idle reaping never re-opens the
        // unauthenticated slow-loris hole (that is handled strictly pre-auth) while honouring a
        // long-lived authenticated session. We prove "not reaped" by showing the read is STILL pending
        // after a window far past the old 50ms pre-auth deadline, then release it via shutdown so the
        // detached blocking task finishes and the runtime tears down cleanly.
        let rt = multi_thread_rt();
        let handle = rt.handle().clone();
        let shutdown = ShutdownCoordinator::new();
        let releaser = shutdown.clone();
        let mut t = AsyncToBlockingTransport::new(
            SilentStream,
            handle,
            shutdown,
            None,                            // idle reaping disabled (the default)
            Some(Duration::from_millis(50)), // strict pre-auth guard
        );
        t.on_authenticated(); // relax: idle = None ⇒ no read deadline
        let still_pending = rt.block_on(async move {
            let read_task = tokio::task::spawn_blocking(move || {
                let mut buf = [0u8; 16];
                t.read(&mut buf)
            });
            // 300 ms ≫ the 50 ms pre-auth deadline: if the read completes, the relaxation failed.
            let early = tokio::time::timeout(Duration::from_millis(300), read_task).await;
            // Release the parked read so the detached blocking task returns and joins.
            releaser.trigger();
            early.is_err()
        });
        // Drop the runtime without blocking on the (now releasing) detached task.
        rt.shutdown_background();
        assert!(
            still_pending,
            "an authenticated session with idle reaping disabled must NOT be reaped (the read stayed \
             pending well past the old 50ms pre-auth deadline)"
        );
    }

    #[test]
    fn cumulative_pre_auth_deadline_reaps_a_slow_dribbler() {
        // R2 (rmp #478): the pre-auth read deadline is a *per-read* bound — every received byte resets
        // it — so a slow dribbler that sends one byte just under it could otherwise extend the
        // unauthenticated phase forever. The CUMULATIVE pre-auth wall-clock bound caps the whole
        // accept→READY span, so such a dribbler is still reaped. Here a writer dribbles one byte every
        // 25ms (always well within the 150ms per-read bound, so the per-read guard never fires), yet the
        // 150ms cumulative bound reaps the pre-auth phase near 150ms — not indefinitely.
        let rt = multi_thread_rt();
        let handle = rt.handle().clone();
        let shutdown = ShutdownCoordinator::new();
        // An in-memory bidirectional pipe: the transport reads the `server` half; a task dribbles into
        // the `client` half (the model of a slow-loris that keeps the per-read deadline alive).
        let (client, server) = tokio::io::duplex(256);
        rt.spawn(async move {
            let mut client = client;
            loop {
                if client.write_all(b"x").await.is_err() {
                    break; // the transport closed its end (reaped) — stop dribbling.
                }
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        });
        let mut t = AsyncToBlockingTransport::new(
            server,
            handle,
            shutdown,
            None,                             // idle reaping disabled (the production default)
            Some(Duration::from_millis(150)), // 150ms pre-auth bound (per-read AND cumulative)
        );
        let start = Instant::now();
        let reads = rt.block_on(async move {
            tokio::task::spawn_blocking(move || {
                let mut buf = [0u8; 1];
                let mut reads = 0u32;
                loop {
                    match t.read(&mut buf) {
                        Ok(0) => return reads, // reaped (EOF) by the cumulative pre-auth bound
                        Ok(_) => {
                            reads += 1;
                            if reads > 100_000 {
                                return reads; // safety valve — never the expected path
                            }
                        }
                        Err(_) => return reads,
                    }
                }
            })
            .await
            .expect("blocking read task joins")
        });
        let elapsed = start.elapsed();
        // The dribbler delivered SOME bytes (the per-read guard never fired on a 25ms-spaced drip) ...
        assert!(
            (1..100_000).contains(&reads),
            "the dribbler delivered a bounded number of bytes before being reaped (got {reads})"
        );
        // ... and the pre-auth phase was reaped near the 150ms cumulative bound — NOT extended forever
        // by the drip the per-read deadline alone could never stop.
        assert!(
            elapsed >= Duration::from_millis(120),
            "reaped at/after the cumulative pre-auth bound, not before (elapsed {elapsed:?})"
        );
        assert!(
            elapsed < Duration::from_secs(3),
            "reaped near the cumulative bound, never pinned indefinitely by the drip (elapsed {elapsed:?})"
        );
    }
}
