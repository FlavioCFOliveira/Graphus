//! Transport-agnostic async listeners and byte streams for the connectivity layer.
//!
//! This is the network half of `graphus-io`: a thin, Tokio-based listener/stream layer that the
//! Bolt and REST servers (rmp #18/#19 cores, wired by #20) plug into. It is the **epoll/kqueue
//! baseline** the whole runtime targets (`04 §9.1`); the optional io_uring fast path
//! ([`crate::backend`]) is selected at startup and is transparent to this surface.
//!
//! Design constraints (`04 §9.1`, task scope):
//! - Every accepted connection ([`TcpConn`] / [`UdsConn`]) is `AsyncRead + AsyncWrite`, so the
//!   protocol codecs read/write bytes without caring about the transport.
//! - UDS connections expose `SO_PEERCRED` ([`PeerCred`]) for local peer auth (`04 §8.4`); this
//!   crate surfaces its own [`PeerCred`] and does **not** depend on `graphus-auth` (`04 §1.2`).
//! - `TCP_NODELAY` is set; no unbounded per-connection buffering is added here (backpressure and
//!   admission control are the server's concern, `04 §9.3`).

mod peer;
mod tcp;
mod uds;

pub use peer::PeerCred;
pub use tcp::{TcpAcceptor, TcpConn};
pub use uds::{UdsAcceptor, UdsConn};

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, SocketAddr};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// Generates a unique temp path for a UDS socket so parallel tests do not collide.
    fn temp_uds_path() -> std::path::PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        // Keep the path short: Unix socket paths are capped at ~108 bytes (`sun_path`).
        std::env::temp_dir().join(format!("graphus-io-{}-{n}.sock", std::process::id()))
    }

    #[tokio::test]
    async fn tcp_round_trip_echo() {
        // Bind to an OS-chosen loopback port (no fixed port → no clashes across parallel tests).
        let acceptor = TcpAcceptor::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
            .await
            .expect("bind loopback");
        let addr = acceptor.local_addr().expect("local_addr");

        // Server task: accept one connection, echo a single framed message back.
        let server = tokio::spawn(async move {
            let mut conn = acceptor.accept().await.expect("accept");
            assert_eq!(conn.peer_addr().ip(), Ipv4Addr::LOCALHOST);
            let mut buf = [0u8; 5];
            conn.read_exact(&mut buf).await.expect("server read");
            conn.write_all(&buf).await.expect("server echo");
            conn.flush().await.expect("server flush");
        });

        // Client: connect, send, read the echo.
        let mut client = tokio::net::TcpStream::connect(addr).await.expect("connect");
        client.write_all(b"hello").await.expect("client write");
        let mut echoed = [0u8; 5];
        client.read_exact(&mut echoed).await.expect("client read");
        assert_eq!(&echoed, b"hello");

        server.await.expect("server task");
    }

    #[tokio::test]
    async fn uds_round_trip_with_peer_cred() {
        let path = temp_uds_path();
        let acceptor = UdsAcceptor::bind(&path).expect("bind uds");
        assert_eq!(acceptor.path(), path.as_path());

        let server = tokio::spawn(async move {
            let mut conn = acceptor.accept().await.expect("accept");
            // Peer credentials are now available on every Tier-1 platform via Tokio's cross-platform
            // `peer_cred()` (SO_PEERCRED on Linux, getpeereid on macOS/BSD), so they must be present
            // here regardless of OS (the test process is both client and server). `geteuid` via std is
            // not exposed, so we assert against the documented invariant that the connecting peer is
            // this very process: the pid, **where the platform records it**, is our own. macOS/BSD
            // `getpeereid` carries no pid, so `pid` is `None` there and the check is simply skipped.
            let cred = conn
                .peer_cred()
                .expect("peer cred present on every Tier-1 platform (SO_PEERCRED / getpeereid)");
            if let Some(pid) = cred.pid {
                assert_eq!(pid, std::process::id() as i32);
            }
            let mut buf = [0u8; 4];
            conn.read_exact(&mut buf).await.expect("server read");
            conn.write_all(&buf).await.expect("server echo");
            conn.flush().await.expect("server flush");
        });

        let mut client = tokio::net::UnixStream::connect(&path)
            .await
            .expect("connect uds");
        client.write_all(b"ping").await.expect("client write");
        let mut echoed = [0u8; 4];
        client.read_exact(&mut echoed).await.expect("client read");
        assert_eq!(&echoed, b"ping");

        server.await.expect("server task");
    }

    #[tokio::test]
    async fn uds_bind_replaces_stale_socket() {
        let path = temp_uds_path();
        // First bind creates the socket file.
        let first = UdsAcceptor::bind(&path).expect("first bind");
        // A second bind to the *same path* while the first is dropped must succeed (the stale inode
        // is removed). We drop `first` to release the fd but the inode would linger without the
        // bind-time cleanup.
        drop(first);
        let second = UdsAcceptor::bind(&path).expect("second bind over stale path");
        assert!(second.path().exists());
        drop(second);
        // After the last acceptor drops, the socket file is unlinked (graceful-shutdown hygiene).
        assert!(!path.exists(), "socket file should be unlinked on drop");
    }
}
