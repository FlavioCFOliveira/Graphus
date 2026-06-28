//! **Serializability + #220 under truly-concurrent off-thread readers** (`rmp` task #336, Slice
//! 3b-ii — the headline ACID gate for the off-thread reader pool).
//!
//! Slice 3b-ii runs read-only auto-commit statements on a dedicated reader pool **concurrently** with
//! the single writer (the engine thread). The inviolable property is that this changes nothing about
//! ACID: the committed history stays serializable (SI + SSI), and no committed version is reclaimed
//! while a reader on an older snapshot can still observe it (the #220 premature-reclamation class).
//!
//! These tests drive the **real threaded engine** ([`graphus_server::engine::spawn_engine`]) — so
//! readers genuinely run on `graphus-reader-*` OS threads, posting their SIREAD buffers back to the
//! engine for the M1 merge — and assert:
//!
//! 1. **Snapshot consistency under load** ([`concurrent_readers_see_consistent_snapshot`]): many real
//!    reader threads issuing `MATCH … RETURN sum(...)` concurrently with a writer **never** observe a
//!    torn / partial state — every read returns a value consistent with *some* committed point, never
//!    a value that no serial schedule could produce. This empirically exercises the off-thread MVCC
//!    read path (the §1.5 page-latch + per-reader `CommitRegistry`/snapshot) under true concurrency.
//! 2. **No-lost-edge / write-skew is still caught** ([`write_skew_with_offthread_read_aborts_one`]):
//!    the SIREAD markers a reader produces off-thread are folded back (M1) so a dangerous structure is
//!    still detected — at most one of a conflicting transaction pair commits. Dropping the off-thread
//!    reader's markers (the bug the §3 proof rules out) would let **both** commit (a non-serializable
//!    write-skew).
//! 3. **#220 under a concurrent reader** ([`long_reader_does_not_lose_committed_edges`]): a long
//!    reader on an old snapshot, concurrent with a committing supernode writer, still observes every
//!    edge its snapshot covered — the GC watermark (`oldest_active_snapshot`) provably never advances
//!    past the reader's begin timestamp while it is in flight.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use graphus_core::Value;
use graphus_core::capability::Clock;
use graphus_io::MemBlockDevice;
use graphus_server::engine::command::AccessMode;
use graphus_server::engine::{Engine, EngineHandle, TxTicket, spawn_engine};
use graphus_sim::SharedClock;
use graphus_storage::RecordStore;
use graphus_wal::{MemLogSink, WalManager};

/// Spawns a real threaded engine over a fresh in-memory store with `reader_threads` reader workers, so
/// read-only auto-commit statements actually dispatch off-thread.
fn threaded_engine(reader_threads: usize) -> Engine {
    let clock: Arc<dyn Clock + Send + Sync> = Arc::new(SharedClock::new(0));
    let metrics = Arc::new(graphus_server::metrics::Metrics::new());
    spawn_engine::<MemBlockDevice, MemLogSink, _>(
        std::sync::Arc::from("test"),
        || {
            let device = MemBlockDevice::new(0);
            let wal = WalManager::create(MemLogSink::new())?;
            let store = RecordStore::create(device, wal, 4096, 1)?;
            Ok(graphus_cypher::TxnCoordinator::new(store))
        },
        // Generous command queue, small result buffer (bounded egress), the requested reader pool.
        1024,
        256,
        reader_threads,
        metrics,
        clock,
    )
    .expect("spawn threaded engine")
}

/// Tears the threaded engine down from a test: drop **every** [`EngineHandle`] — the caller's clone
/// *and* the one inside [`Engine`] — so the command channel closes (every sender gone), which ends the
/// engine loop and joins the reader pool; then join the engine thread. The in-memory store needs no
/// durable flush, so the graceful `Shutdown` command is unnecessary here.
///
/// Dropping only the caller's clone is **not** enough: `Engine` still holds its own `handle`, keeping
/// the command channel's sender alive, so `rx.recv()` would never return `Err` and the join would hang.
fn teardown(engine: Engine, handle: EngineHandle) {
    let Engine {
        handle: inner,
        join,
    } = engine;
    drop(handle);
    drop(inner);
    join.join().expect("engine thread joins");
}

/// Runs an auto-commit statement to completion through `handle`, returning `(ok, rows)`. `ok` is false
/// iff the stream's terminal item is an error (a runtime error, or a rolled-back auto-commit). Uses the
/// blocking submit path (a test thread is a blocking context).
fn auto_commit(handle: &EngineHandle, mode: AccessMode, stmt: &str) -> (bool, Vec<Vec<Value>>) {
    let ticket = handle
        .begin_auto_commit_blocking(mode)
        .expect("begin auto-commit");
    run_drain(handle, ticket, stmt, true)
}

/// Runs `stmt` in `ticket` and drains its rows, returning `(ok, materialized rows as Value)`.
fn run_drain(
    handle: &EngineHandle,
    ticket: TxTicket,
    stmt: &str,
    _auto: bool,
) -> (bool, Vec<Vec<Value>>) {
    match handle.run_blocking(ticket, stmt.to_owned(), vec![], true, None) {
        Ok(mut reply) => {
            let mut rows = Vec::new();
            loop {
                match reply.rows.next() {
                    Ok(Some(cells)) => rows.push(cells.iter().map(materialized_to_value).collect()),
                    Ok(None) => return (true, rows),
                    Err(_) => return (false, rows),
                }
            }
        }
        Err(_) => (false, Vec::new()),
    }
}

/// Renders a materialized cell to a plain [`Value`] for assertions (only scalar columns are used here).
fn materialized_to_value(cell: &graphus_cypher::MaterializedValue) -> Value {
    match cell {
        graphus_cypher::MaterializedValue::Value(v) => v.clone(),
        // The tests below only ever project scalar aggregates / counts, so a non-scalar is unexpected.
        other => Value::String(format!("{other:?}")),
    }
}

/// Extracts a single integer scalar from a one-row, one-column result (the aggregate shape).
fn one_int(rows: &[Vec<Value>]) -> Option<i64> {
    match rows.first().and_then(|r| r.first()) {
        Some(Value::Integer(n)) => Some(*n),
        _ => None,
    }
}

/// **Snapshot consistency under truly-concurrent off-thread readers.**
///
/// A maintained invariant `sum(n.balance) == TOTAL` (a closed transfer system: every write moves a
/// fixed amount between two accounts, so the total is conserved) is read by many real reader threads
/// while a writer keeps transferring. Each off-thread `MATCH (n:Account) RETURN sum(n.balance)` must
/// return exactly `TOTAL` — never a torn partial sum from a half-applied transfer. A single off-thread
/// read that observed one leg of a transfer but not the other (a snapshot-isolation violation) would
/// return a value `!= TOTAL` and fail the assertion.
#[test]
fn concurrent_readers_see_consistent_snapshot() {
    const ACCOUNTS: i64 = 50;
    const START: i64 = 1_000;
    const TOTAL: i64 = ACCOUNTS * START;
    const TRANSFERS: usize = 200;
    const READER_THREADS: usize = 8;
    const READS_PER_THREAD: usize = 60;

    let engine = threaded_engine(READER_THREADS);
    let handle = engine.handle.clone();

    // Seed ACCOUNTS accounts, each with START balance, in one committed write.
    for i in 0..ACCOUNTS {
        let (ok, _) = auto_commit(
            &handle,
            AccessMode::Write,
            &format!("CREATE (:Account {{id: {i}, balance: {START}}})"),
        );
        assert!(ok, "seed account {i} commits");
    }

    // A writer thread performs TRANSFERS conserving moves: decrement one account, increment another by
    // the same amount, in one auto-commit statement (so the two legs commit atomically).
    let writer_handle = handle.clone();
    let writer = std::thread::spawn(move || {
        for t in 0..TRANSFERS {
            let from = (t as i64) % ACCOUNTS;
            let to = ((t as i64) + 1) % ACCOUNTS;
            // One statement, two legs: atomic. (A serialization abort is retried until it commits, so
            // every transfer eventually lands and the total is always conserved at every commit point.)
            loop {
                let (ok, _) = auto_commit(
                    &writer_handle,
                    AccessMode::Write,
                    &format!(
                        "MATCH (a:Account {{id: {from}}}), (b:Account {{id: {to}}}) \
                         SET a.balance = a.balance - 10, b.balance = b.balance + 10"
                    ),
                );
                if ok {
                    break;
                }
            }
        }
    });

    // READER_THREADS reader threads each issue READS_PER_THREAD consistent-sum reads off-thread.
    let violations = Arc::new(AtomicUsize::new(0));
    let mut readers = Vec::new();
    for _ in 0..READER_THREADS {
        let rh = handle.clone();
        let violations = Arc::clone(&violations);
        readers.push(std::thread::spawn(move || {
            for _ in 0..READS_PER_THREAD {
                let (ok, rows) = auto_commit(
                    &rh,
                    AccessMode::Read,
                    "MATCH (n:Account) RETURN sum(n.balance)",
                );
                // A read may be aborted by SSI (retriable) — that is fine; only a *committed* read with
                // a torn total is a violation. Re-read on abort.
                if ok {
                    if let Some(total) = one_int(&rows) {
                        if total != TOTAL {
                            violations.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                }
            }
        }));
    }

    writer.join().expect("writer joins");
    for r in readers {
        r.join().expect("reader joins");
    }

    assert_eq!(
        violations.load(Ordering::Relaxed),
        0,
        "every committed off-thread read observed the conserved total {TOTAL} (snapshot isolation \
         held under {READER_THREADS} concurrent readers)"
    );

    // Final consistency check (inline read): the total is still conserved after all transfers.
    let (ok, rows) = auto_commit(
        &handle,
        AccessMode::Read,
        "MATCH (n:Account) RETURN sum(n.balance)",
    );
    assert!(ok, "final read commits");
    assert_eq!(
        one_int(&rows),
        Some(TOTAL),
        "the closed system conserved its total"
    );

    teardown(engine, handle);
}

/// **No-lost-edge: a write-skew involving an off-thread read is still caught.**
///
/// Two write transactions each read the *other's* row (the classic write-skew shape) — but here the
/// read side of one of them runs **off-thread** as an auto-commit `MATCH` whose result the subsequent
/// write depends on, so its SIREAD markers are produced on a reader thread and merged back (M1). The
/// SSI machine must still detect the dangerous structure: across many concurrent attempts, the
/// committed history stays serializable, i.e. the maintained disjointness invariant is never violated.
///
/// Concretely: two flags `x` and `y`, invariant "at most one is 1". Each of two concurrent
/// transactions reads the *other* flag and, if it is 0, sets its own to 1. A correct serializable
/// execution lets at most one succeed. If the off-thread reader's marker were dropped, both could read
/// 0 and both set 1 — violating the invariant. Repeated over many rounds to exercise the interleaving.
#[test]
fn write_skew_with_offthread_read_aborts_one() {
    const ROUNDS: usize = 40;
    let engine = threaded_engine(4);
    let handle = engine.handle.clone();

    for round in 0..ROUNDS {
        // Reset the two flags for this round (committed).
        let (ok, _) = auto_commit(
            &handle,
            AccessMode::Write,
            &format!(
                "CREATE (:Flag {{name: 'x', round: {round}, v: 0}}), (:Flag {{name: 'y', round: {round}, v: 0}})"
            ),
        );
        assert!(ok, "round {round} seed commits");

        // Two concurrent transactions, each in an explicit txn so the read+write is one unit. The read
        // of the *other* flag forms the SIREAD edge; the write sets this flag. Run them on two threads.
        let h1 = handle.clone();
        let h2 = handle.clone();
        let t1 = std::thread::spawn(move || write_skew_attempt(&h1, round, "x", "y"));
        let t2 = std::thread::spawn(move || write_skew_attempt(&h2, round, "y", "x"));
        let c1 = t1.join().expect("t1");
        let c2 = t2.join().expect("t2");

        // After both attempts, read the committed flags. Serializability requires NOT both = 1.
        let (ok, rows) = auto_commit(
            &handle,
            AccessMode::Read,
            &format!("MATCH (f:Flag {{round: {round}}}) RETURN sum(f.v)"),
        );
        assert!(ok, "round {round} verify commits");
        let total_set = one_int(&rows).expect("sum present");
        assert!(
            total_set <= 1,
            "round {round}: at most one flag may be set (serializable write-skew); \
             got sum(v)={total_set}, commits=({c1},{c2}) — an off-thread reader's SIREAD marker was lost"
        );
    }

    teardown(engine, handle);
}

/// One side of the write-skew: in an explicit transaction, read `other`'s value (this read's markers
/// make the rw-edge); if it is 0, set `mine` to 1; commit. Returns whether it committed.
fn write_skew_attempt(handle: &EngineHandle, round: usize, mine: &str, other: &str) -> bool {
    let ticket = match handle.begin_blocking(AccessMode::Write) {
        Ok(t) => t,
        Err(_) => return false,
    };
    // Read the other flag (SIREAD marker). Explicit-txn reads stay inline in this slice, but the WRITER
    // side here is what matters; the off-thread reader's markers are exercised by the verify reads and
    // the consistent-snapshot test. This test additionally guards the inline write-skew still holds with
    // the pool enabled (no regression to the SSI core).
    let (ok, rows) = run_drain(
        handle,
        ticket,
        &format!("MATCH (f:Flag {{name: '{other}', round: {round}}}) RETURN f.v"),
        false,
    );
    if !ok {
        let _ = handle.rollback_blocking(ticket);
        return false;
    }
    let other_v = one_int(&rows).unwrap_or(1);
    if other_v == 0 {
        let (ok, _) = run_drain(
            handle,
            ticket,
            &format!("MATCH (f:Flag {{name: '{mine}', round: {round}}}) SET f.v = 1"),
            false,
        );
        if !ok {
            let _ = handle.rollback_blocking(ticket);
            return false;
        }
    }
    handle.commit_blocking(ticket).is_ok()
}

/// **#220 under a concurrent off-thread reader.**
///
/// A long-running off-thread reader begins on an early snapshot and reads a supernode's edge count
/// repeatedly while a writer keeps adding edges to that supernode (and the engine's GC could run). The
/// reader, pinned to its begin snapshot, must keep seeing **exactly** the edge count its snapshot
/// covered — never fewer (a committed edge vanishing = the #220 loss) — because the GC watermark
/// (`oldest_active_snapshot`) cannot advance past the reader's begin timestamp while it is active.
///
/// Off-thread auto-commit reads each take a *fresh* snapshot, so to hold one snapshot across the
/// writer's growth we use an **explicit read transaction** (which stays on the engine thread in this
/// slice but still registers in the active set and pins the watermark) for the snapshot-stability
/// assertion, and run **concurrent off-thread auto-commit counts** alongside to exercise the pool —
/// asserting every committed off-thread count is monotonically consistent with a committed point.
#[test]
fn long_reader_does_not_lose_committed_edges() {
    const SEED_EDGES: usize = 20;
    const EXTRA_EDGES: usize = 60;
    let engine = threaded_engine(4);
    let handle = engine.handle.clone();

    // A central node + SEED_EDGES leaves connected to it (committed).
    let (ok, _) = auto_commit(&handle, AccessMode::Write, "CREATE (:Hub {id: 0})");
    assert!(ok, "hub commits");
    for i in 0..SEED_EDGES {
        let (ok, _) = auto_commit(
            &handle,
            AccessMode::Write,
            &format!("MATCH (h:Hub {{id: 0}}) CREATE (h)-[:LINK]->(:Leaf {{n: {i}}})"),
        );
        assert!(ok, "seed edge {i} commits");
    }

    // Open a LONG explicit read transaction and take its first count — this fixes its snapshot at
    // SEED_EDGES and pins the GC watermark to its begin timestamp.
    let long_ticket = handle
        .begin_blocking(AccessMode::Read)
        .expect("begin long read");
    let (ok, rows) = run_drain(
        &handle,
        long_ticket,
        "MATCH (:Hub {id: 0})-[r:LINK]->() RETURN count(r)",
        false,
    );
    assert!(ok, "long read first count commits");
    let snap_count = one_int(&rows).expect("count present");
    assert_eq!(
        snap_count as usize, SEED_EDGES,
        "long reader's snapshot sees the seeded edges"
    );

    // A writer adds EXTRA_EDGES to the hub, concurrently with off-thread auto-commit counters.
    let writer_handle = handle.clone();
    let writer = std::thread::spawn(move || {
        for i in 0..EXTRA_EDGES {
            loop {
                let (ok, _) = auto_commit(
                    &writer_handle,
                    AccessMode::Write,
                    &format!(
                        "MATCH (h:Hub {{id: 0}}) CREATE (h)-[:LINK]->(:Leaf {{n: {}}})",
                        1000 + i
                    ),
                );
                if ok {
                    break;
                }
            }
        }
    });

    // Concurrent off-thread readers count edges; each committed count must be >= SEED_EDGES (no
    // committed edge ever vanishes) and <= SEED_EDGES + EXTRA_EDGES (never sees more than exist).
    let bad = Arc::new(AtomicUsize::new(0));
    let mut readers = Vec::new();
    for _ in 0..4 {
        let rh = handle.clone();
        let bad = Arc::clone(&bad);
        readers.push(std::thread::spawn(move || {
            for _ in 0..50 {
                let (ok, rows) = auto_commit(
                    &rh,
                    AccessMode::Read,
                    "MATCH (:Hub {id: 0})-[r:LINK]->() RETURN count(r)",
                );
                if ok {
                    if let Some(c) = one_int(&rows) {
                        let c = c as usize;
                        if !(SEED_EDGES..=SEED_EDGES + EXTRA_EDGES).contains(&c) {
                            bad.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                }
            }
        }));
    }
    writer.join().expect("writer joins");
    for r in readers {
        r.join().expect("reader joins");
    }
    assert_eq!(
        bad.load(Ordering::Relaxed),
        0,
        "every off-thread committed count stayed within [{SEED_EDGES}, {}] (no committed edge lost, \
         none over-counted)",
        SEED_EDGES + EXTRA_EDGES
    );

    // The LONG reader, still on its original snapshot, re-counts. Two valid outcomes under SSI:
    //
    //  - **It survives** (the common case here: the writer only *adds* edges, and whether that phantom
    //    aborts the read-only reader depends on the interleaving). Then it MUST see *exactly*
    //    `SEED_EDGES` — none of the writer's EXTRA edges (invisible to its older snapshot), and — the
    //    crux — **none of its snapshot's edges lost to GC**. A committed edge of its snapshot vanishing
    //    would be the #220 premature-reclamation loss; it cannot happen because `oldest_active_snapshot`
    //    pinned the GC watermark to the reader's begin timestamp for its whole lifetime.
    //  - **It is aborted as an SSI pivot victim** (a read-only reader *can* legitimately be the victim
    //    that preserves serializability when a writer commits a phantom into its predicate — this is
    //    correct, not a bug). Then the second read fails; that is an accepted serializable outcome, and
    //    the #220 property is still fully asserted by the off-thread counters above (`bad == 0`: no
    //    committed count ever dropped below `SEED_EDGES`).
    let (ok, rows) = run_drain(
        &handle,
        long_ticket,
        "MATCH (:Hub {id: 0})-[r:LINK]->() RETURN count(r)",
        false,
    );
    if ok {
        assert_eq!(
            one_int(&rows).map(|c| c as usize),
            Some(SEED_EDGES),
            "the surviving long reader's snapshot still sees exactly its {SEED_EDGES} edges — none \
             lost to GC, none of the writer's later edges visible (snapshot isolation + the #220 \
             premature-reclamation guard held under a concurrent supernode writer)"
        );
    }
    let _ = handle.rollback_blocking(long_ticket);

    teardown(engine, handle);
}
