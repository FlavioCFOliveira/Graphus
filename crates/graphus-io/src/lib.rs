//! `graphus-io` — the I/O substrate for the Graphus storage core and connectivity layer.
//!
//! Two complementary halves live here, matching `specification/04-technical-design.md` §1.2's
//! description of `graphus-io` ("epoll/kqueue + optional io_uring; dedicated fsync threads"):
//!
//! 1. **Synchronous, page-granular block device** ([`BlockDevice`]) — the I/O surface the buffer
//!    pool and write-ahead log build on, with a file-backed production impl ([`FileBlockDevice`])
//!    and an in-memory impl ([`MemBlockDevice`]) that models the durability boundary with crash,
//!    torn-write and I/O-error injection for Deterministic Simulation Testing. This half is
//!    unchanged by the async work.
//!
//! 2. **Async network I/O + durability offload** (this task, rmp #28) — the layer the Bolt/REST
//!    servers (rmp #18/#19, wired by #20) plug into:
//!    - [`net`] — transport-agnostic async listeners ([`net::TcpAcceptor`], [`net::UdsAcceptor`])
//!      yielding `AsyncRead + AsyncWrite` connections, with UDS `SO_PEERCRED` ([`net::PeerCred`]).
//!    - [`fsync`] — a dedicated blocking thread pool ([`fsync::FsyncPool`]) that runs
//!      `fsync`/`fdatasync` off the runtime workers (`04 §9.1`'s hard rule: no blocking syscalls on
//!      runtime workers).
//!    - [`backend`] — runtime io_uring detection ([`backend::probe_io_uring`]) and backend
//!      selection ([`backend::select_backend`]) with a **guaranteed clean fallback** to the
//!      epoll/kqueue Tokio baseline (`D-io-backend`, `04 §3.6`/§9.1).
//!
//! ## Safety
//! The default build is `#![forbid(unsafe_code)]`. The only `unsafe` in the crate is the real
//! `io_uring_setup(2)` capability probe in the `uring` module, which is compiled in **only** under
//! the optional, Linux-gated `io-uring` Cargo feature; in that build the crate lint is relaxed to
//! `deny` and the `uring` module scopes an `allow`, with every `unsafe` block documented by a
//! `// SAFETY:` comment. The portable default never compiles any `unsafe`.
// `forbid(unsafe_code)` is kept for the portable, non-macOS default build. macOS needs one scoped
// `unsafe` block (`fcntl(fd, F_FULLFSYNC)` in `fullsync.rs`) to issue a true stable-storage barrier,
// and the optional `io-uring` feature needs the probe's `unsafe`; both relax the crate lint to
// `deny` (so a stray `unsafe` anywhere else still fails the build) while letting those two
// `// SAFETY:`-documented blocks compile.
#![cfg_attr(
    all(not(feature = "io-uring"), not(target_os = "macos")),
    forbid(unsafe_code)
)]
#![cfg_attr(any(feature = "io-uring", target_os = "macos"), deny(unsafe_code))]

mod block;
mod file;
mod fullsync;
mod mem;
mod replace;

// The async/network half is built on Tokio. Tokio's own `net`/runtime modules are
// `#![cfg(not(loom))]`, so under `--cfg loom` `tokio::net` does not exist and these modules cannot
// compile. They are also irrelevant to loom model-checking, which targets the *synchronous*
// buffer-pool latch logic (`graphus-bufpool`, the only loom-tested crate) over the
// `block`/`mem` device types below. Gating the Tokio-backed half on `not(loom)` therefore lets the
// workspace build under `--cfg loom` without touching any production behaviour: `loom` is a
// test-only cfg never set in a real build.
#[cfg(not(loom))]
pub mod backend;
#[cfg(not(loom))]
pub mod fsync;
#[cfg(not(loom))]
pub mod net;

// The io_uring fast path: real capability probe + stubbed submission. Linux + feature only; the
// portable build does not compile it (and so compiles no `unsafe`). See `backend` for selection.
#[cfg(all(target_os = "linux", feature = "io-uring", not(loom)))]
mod uring;

pub use block::{BlockDevice, PAGE_SIZE, Page};
pub use file::FileBlockDevice;
pub use fullsync::{full_sync_all, full_sync_data};
pub use mem::MemBlockDevice;
pub use replace::atomic_replace_file;

#[cfg(not(loom))]
pub use backend::{IoBackend, probe_io_uring, select_backend};
#[cfg(not(loom))]
pub use fsync::{FsyncPool, SyncTarget};
#[cfg(not(loom))]
pub use net::{PeerCred, TcpAcceptor, TcpConn, UdsAcceptor, UdsConn};
