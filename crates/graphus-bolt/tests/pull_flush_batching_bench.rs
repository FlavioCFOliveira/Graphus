//! Wire-level benchmark + correctness gate for the **flush-before-read** batching (rmp #317).
//!
//! ## What this proves
//!
//! Before #317 the server's async→blocking transport flushed the socket on **every**
//! `Transport::write_all`, so a `PULL` of *N* rows — which emits one `RECORD` per row plus a
//! trailing `SUCCESS` — cost **N+1 socket pushes/flushes** (one syscall + one `flush`, i.e. one
//! TLS record under TLS, per row). After #317 `write_all` only *buffers*; the bytes are pushed in a
//! single `flush`, driven **before the next read**. So a whole `PULL` batch collapses to **one**
//! push/flush regardless of row count: O(rows) → O(1).
//!
//! The two transports below are faithful models of the two regimes. The real production bridge is
//! `graphus_server::listeners::transport::AsyncToBlockingTransport`, which is async and cannot run
//! in this crate's hermetic, socket-free unit-test environment; these in-memory transports reproduce
//! its *write/flush accounting* exactly (buffer in `write_all`, push in `flush`, and — like the real
//! bridge — flush before every `read`).
//!
//! ## Why a `#[ignore]` bench
//!
//! It drives a real, bounded `BoltSession` to completion (no hang) and reports numbers; it is run on
//! demand:
//! `cargo test -p graphus-bolt --test pull_flush_batching_bench -- --ignored --nocapture`
//! The two non-ignored tests in this file are the **correctness gates** (byte-identical wire output,
//! O(1) flushes) and run in the normal suite.

use std::time::Instant;

use graphus_auth::{Authenticator, Privilege};
use graphus_bolt::BoltValue;
use graphus_bolt::error::BoltResult;
use graphus_bolt::executor::{
    AccessMode, BoltExecutor, QuerySummary, Record, RecordStream, TxControl,
};
use graphus_bolt::server::{encode_client_handshake, encode_request_framed};
use graphus_bolt::transport::{ByteQueue, Transport};
use graphus_bolt::{BoltSession, Proposal, Request};
use graphus_core::{GraphusError, Value};

// ---- a wide N-row executor -----------------------------------------------------------------------

struct BigStream {
    fields: Vec<String>,
    next: i64,
    n: i64,
}

impl RecordStream for BigStream {
    fn fields(&self) -> &[String] {
        &self.fields
    }
    fn next_record(&mut self) -> Result<Option<Record>, GraphusError> {
        if self.next >= self.n {
            return Ok(None);
        }
        let v = self.next;
        self.next += 1;
        Ok(Some(vec![BoltValue::Value(Value::Integer(v))]))
    }
    fn summary(&self) -> QuerySummary {
        QuerySummary {
            query_type: Some("r".to_owned()),
            stats: vec![],
        }
    }
}

struct BigExecutor {
    rows: i64,
}

impl BoltExecutor for BigExecutor {
    type Stream = BigStream;
    fn run(
        &mut self,
        _query: &str,
        _parameters: Vec<(String, Value)>,
        _tx: TxControl,
    ) -> Result<Self::Stream, GraphusError> {
        Ok(BigStream {
            fields: vec!["x".to_owned()],
            next: 0,
            n: self.rows,
        })
    }
    fn begin(&mut self, _mode: AccessMode, _db: Option<&str>) -> Result<(), GraphusError> {
        Ok(())
    }
    fn commit(&mut self) -> Result<QuerySummary, GraphusError> {
        Ok(QuerySummary::default())
    }
    fn rollback(&mut self) -> Result<(), GraphusError> {
        Ok(())
    }
}

// ---- the two transport regimes -------------------------------------------------------------------

/// OLD regime: each `write_all` pushes to the socket immediately and flushes (no buffering). Models
/// the pre-#317 bridge where `write_all` did `block_on { write_all + flush }`.
struct UnbufferedCounting {
    inbound: ByteQueue,
    sink: Vec<u8>,
    /// Socket pushes == flushes (each `write_all` flushes in the old regime).
    flushes: usize,
}

impl UnbufferedCounting {
    fn new(input: &[u8]) -> Self {
        let mut inbound = ByteQueue::new();
        inbound.feed(input);
        Self {
            inbound,
            sink: Vec::new(),
            flushes: 0,
        }
    }
}

impl Transport for UnbufferedCounting {
    fn read(&mut self, buf: &mut [u8]) -> BoltResult<usize> {
        Ok(self.inbound.take(buf))
    }
    fn write_all(&mut self, bytes: &[u8]) -> BoltResult<()> {
        self.sink.extend_from_slice(bytes);
        self.flushes += 1; // old regime: a flush per write
        Ok(())
    }
    // flush() is the default no-op: in the old regime the bytes are already out.
}

/// NEW regime (#317): `write_all` only buffers; `flush` pushes the buffer to the socket and is the
/// only thing that counts as a socket push. `read` flushes first (mirrors the real bridge). This is
/// a faithful model of `AsyncToBlockingTransport` after #317.
struct BufferedCounting {
    inbound: ByteQueue,
    sink: Vec<u8>,
    write_buf: Vec<u8>,
    /// Actual non-empty socket pushes (== `block_on { write_all + flush }` invocations).
    flushes: usize,
}

impl BufferedCounting {
    fn new(input: &[u8]) -> Self {
        let mut inbound = ByteQueue::new();
        inbound.feed(input);
        Self {
            inbound,
            sink: Vec::new(),
            write_buf: Vec::new(),
            flushes: 0,
        }
    }
}

impl Transport for BufferedCounting {
    fn read(&mut self, buf: &mut [u8]) -> BoltResult<usize> {
        self.flush()?; // flush-before-read, exactly like the production bridge
        Ok(self.inbound.take(buf))
    }
    fn write_all(&mut self, bytes: &[u8]) -> BoltResult<()> {
        self.write_buf.extend_from_slice(bytes); // buffer only — no push, no flush
        Ok(())
    }
    fn flush(&mut self) -> BoltResult<()> {
        if self.write_buf.is_empty() {
            return Ok(());
        }
        self.sink.extend_from_slice(&self.write_buf);
        self.write_buf.clear();
        self.flushes += 1; // one socket push per non-empty flush
        Ok(())
    }
}

// ---- shared session driver -----------------------------------------------------------------------

fn auth() -> Authenticator {
    let mut a = Authenticator::new(b"shared-jwt-secret-at-least-32-bytes!!")
        .expect("fixture secret is >= 32 bytes");
    a.catalog_mut().create_user("bob").unwrap();
    a.catalog_mut().create_role("r").unwrap();
    a.catalog_mut()
        .grant_privilege("r", Privilege::read_database())
        .unwrap();
    a.catalog_mut().grant_role("bob", "r").unwrap();
    a.set_password("bob", "bob-secret").unwrap();
    a
}

/// The scripted client: handshake, HELLO, LOGON, RUN, PULL all (`n = -1`), GOODBYE.
fn scripted_input() -> Vec<u8> {
    let mut input = encode_client_handshake([
        Proposal::range(5, 4, 4),
        Proposal::exact(0, 0),
        Proposal::exact(0, 0),
        Proposal::exact(0, 0),
    ]);
    for r in [
        Request::Hello {
            extra: vec![("user_agent".to_owned(), Value::String("bench".to_owned()))],
        },
        Request::Logon {
            auth: vec![
                ("scheme".to_owned(), Value::String("basic".to_owned())),
                ("principal".to_owned(), Value::String("bob".to_owned())),
                (
                    "credentials".to_owned(),
                    Value::String("bob-secret".to_owned()),
                ),
            ],
        },
        Request::Run {
            query: "MATCH (x) RETURN x".to_owned(),
            parameters: vec![],
            extra: vec![],
        },
        Request::Pull { n: -1, qid: None },
        Request::Goodbye,
    ] {
        input.extend_from_slice(&encode_request_framed(&r).unwrap());
    }
    input
}

/// Runs the buffered regime, returning (wire bytes, socket-push count).
fn run_buffered(rows: i64) -> (Vec<u8>, usize) {
    let a = auth();
    let input = scripted_input();
    let mut t = BufferedCounting::new(&input);
    {
        let mut session = BoltSession::new(&mut t, BigExecutor { rows }, &a);
        session.run().expect("buffered session runs to GOODBYE");
    }
    (t.sink, t.flushes)
}

/// Runs the unbuffered regime, returning (wire bytes, socket-push count).
fn run_unbuffered(rows: i64) -> (Vec<u8>, usize) {
    let a = auth();
    let input = scripted_input();
    let mut t = UnbufferedCounting::new(&input);
    {
        let mut session = BoltSession::new(&mut t, BigExecutor { rows }, &a);
        session.run().expect("unbuffered session runs to GOODBYE");
    }
    (t.sink, t.flushes)
}

// ---- correctness gates (run in the normal suite) -------------------------------------------------

#[test]
fn buffering_is_byte_identical_to_unbuffered() {
    // The inviolable Bolt/PackStream guarantee: buffering changes WHEN bytes flush, not WHAT bytes
    // flush. Across a representative row count the two regimes must emit byte-for-byte identical wire
    // output (handshake reply + every framed response).
    for rows in [0_i64, 1, 2, 100, 1000] {
        let (buffered, _) = run_buffered(rows);
        let (unbuffered, _) = run_unbuffered(rows);
        assert_eq!(
            buffered, unbuffered,
            "wire bytes diverge at rows={rows}: buffering must be byte-identical"
        );
    }
}

#[test]
fn pull_flush_count_is_o1_not_o_rows() {
    // The whole point of #317: the buffered regime's socket-push count does NOT grow with the row
    // count, whereas the unbuffered regime's does (one push per RECORD). We assert the buffered count
    // is a small constant independent of N, and that the unbuffered count grows ~linearly.
    let (_, f_small) = run_buffered(10);
    let (_, f_big) = run_buffered(10_000);
    assert_eq!(
        f_small, f_big,
        "buffered socket-push count must be constant (O(1)), independent of rows"
    );
    // The constant is the number of read-points that flush a non-empty buffer across the whole
    // session (handshake reply, then one flush per request whose response was buffered, plus the
    // terminal GOODBYE flush). It must be a small single-digit constant, NOT proportional to rows.
    assert!(
        f_big < 16,
        "buffered pushes should be a small constant, got {f_big}"
    );

    // The unbuffered regime pushes once per RECORD: ~N pushes for N rows.
    let (_, u_big) = run_unbuffered(10_000);
    assert!(
        u_big > 10_000,
        "unbuffered regime should push O(rows) times, got {u_big}"
    );
}

// ---- the on-demand benchmark ---------------------------------------------------------------------

#[test]
#[ignore = "wire-level benchmark; run explicitly with --ignored --nocapture"]
fn bench_pull_10k_rows_flush_count_and_walltime() {
    const ROWS: i64 = 10_000;

    let t0 = Instant::now();
    let (buf_bytes, buf_flushes) = run_buffered(ROWS);
    let buf_wall = t0.elapsed();

    let t1 = Instant::now();
    let (unbuf_bytes, unbuf_flushes) = run_unbuffered(ROWS);
    let unbuf_wall = t1.elapsed();

    assert_eq!(buf_bytes, unbuf_bytes, "wire bytes must be byte-identical");

    eprintln!("=== PULL {ROWS} rows: socket-push (syscall+flush) count & wall time ===");
    eprintln!("  BEFORE (#317): unbuffered  flushes = {unbuf_flushes:>6}  wall = {unbuf_wall:?}");
    eprintln!("  AFTER  (#317): buffered    flushes = {buf_flushes:>6}  wall = {buf_wall:?}");
    eprintln!(
        "  reduction: {}x fewer flushes ({} -> {}); wire bytes identical ({} bytes)",
        unbuf_flushes
            .checked_div(buf_flushes)
            .unwrap_or(unbuf_flushes),
        unbuf_flushes,
        buf_flushes,
        buf_bytes.len()
    );
}
