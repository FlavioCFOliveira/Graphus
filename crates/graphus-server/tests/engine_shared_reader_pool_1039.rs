//! **`rmp` #1039 — the reader pool and the retirement channel belong to the ENGINE, not to each worker.**
//!
//! `run_engine_loop` used to build both, so an engine running `W` workers held `W` of each.
//! `reader_threads` is auto-sized to `min(cores, 16)`, so at `W = 8` on a sixteen-core host that is
//! **128 reader threads and 8 retirement channels for one database**, each pool sized as though it were
//! the only one. The multi-writer measurement `rmp` #1034 exists to take would have measured
//! oversubscription rather than scale.
//!
//! # What this file proves, and why the oracle is a spawn counter
//!
//! The oracle is a process-wide count of `ReadPool::spawn` calls, reader worker `Builder::spawn` calls
//! and retirement-channel creations, sampled as a DELTA across one engine spawn. Reading
//! `/proc/self/task` was the obvious alternative and is the wrong one: it is Linux-only, so the gate
//! would assert nothing at all on the macOS leg, and a gate that quietly asserts nothing is
//! indistinguishable from one that passes — the failure mode this project has closed repeatedly.
//! The counters are always compiled (no feature gate), for the same reason.
//!
//! A delta rather than an absolute, because the test binary runs its tests in one process and in
//! parallel: another test's engine may spawn between two reads. The delta is taken around this test's
//! own spawn, and the assertion is about the difference.
//!
//! # Non-vacuity, measured
//!
//! With the pool and channel moved back into `run_engine_loop` — the pre-`rmp` #1039 shape — this gate
//! reports `4` pools, `4` retirement channels and `12` reader threads against the `1`, `1` and `3` it
//! requires, and names each. The numbers are `W` and `W * reader_threads` exactly, which is what makes
//! the mutation's signature unmistakable rather than merely red.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use graphus_core::capability::Clock;
use graphus_io::MemBlockDevice;
use graphus_server::engine::command::AccessMode;
use graphus_server::engine::{Engine, EngineHandle, spawn_engine_with_timeout};
use graphus_server::metrics::Metrics;
use graphus_storage::RecordStore;
use graphus_wal::{MemLogSink, WalManager};

struct RealClock;
impl Clock for RealClock {
    fn now_nanos(&self) -> u64 {
        use std::time::{SystemTime, UNIX_EPOCH};
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u64
    }
}

struct TempDir {
    path: PathBuf,
}
impl TempDir {
    fn new(tag: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "graphus_pool1039_{tag}_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ));
        std::fs::create_dir_all(&path).expect("create scratch dir");
        Self { path }
    }
}
impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

/// Builds an engine with `workers` workers and `reader_threads` reader threads over an in-memory store.
///
/// `spawn_engine_with_timeout` directly, because `admission.engine_workers > 1` is still refused by
/// configuration until `rmp` #1034 certifies the multi-worker engine — the same door
/// `tests/engine_shared_sessions_1041.rs` and `tests/engine_latch_scaling_1038.rs` use, and for the
/// same reason: the refusal bounds who can REACH the multi-worker engine, not whether it is developed
/// and tested.
fn engine(_dir: &Path, workers: usize, reader_threads: usize) -> (Engine, Arc<Metrics>) {
    let clock: Arc<dyn Clock + Send + Sync> = Arc::new(RealClock);
    let metrics = Arc::new(Metrics::new());
    let engine = spawn_engine_with_timeout::<MemBlockDevice, MemLogSink, _>(
        Arc::from("pool1039"),
        move || {
            let device = MemBlockDevice::new(0);
            let wal = WalManager::create(MemLogSink::new())?;
            let store = RecordStore::create(device, wal, 4_096, 1)?;
            Ok(graphus_cypher::TxnCoordinator::new(store))
        },
        8192,
        256,
        reader_threads,
        workers,
        Arc::clone(&metrics),
        clock,
        None,
        None,
        None,
        Arc::new(graphus_server::txn_registry::TransactionRegistry::new()),
    )
    .expect("spawn engine");
    (engine, metrics)
}

fn shutdown(engine: Engine) {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("shutdown runtime");
    rt.block_on(engine.handle.shutdown()).expect("shutdown");
    for j in engine.joins {
        j.join().expect("engine worker joins cleanly");
    }
}

/// Serialises the two gates in this file. Gate 1's oracle is a DELTA over process-wide spawn counters,
/// and gate 2 spawns an engine of its own — running them concurrently makes gate 1 count gate 2's pool
/// and fail for a reason that has nothing to do with the property. Only this binary's tests can perturb
/// those counters (every other test binary is a separate process), so serialising here is sufficient.
static COUNTER_GATE: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// **GATE 1 — one pool, one retirement channel, `reader_threads` reader threads, whatever `W` is.**
#[test]
fn a_four_worker_engine_builds_exactly_one_reader_pool_and_one_retirement_channel() {
    const WORKERS: usize = 4;
    const READER_THREADS: usize = 3;
    let _serial = COUNTER_GATE
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);

    let before_pools = graphus_server::engine::read_pool::pools_spawned();
    let before_threads = graphus_server::engine::read_pool::reader_threads_spawned();
    let before_channels = graphus_server::engine::retirement_channels_created();

    let dir = TempDir::new("counts");
    let (engine, _metrics) = engine(&dir.path, WORKERS, READER_THREADS);

    let pools = graphus_server::engine::read_pool::pools_spawned() - before_pools;
    let threads = graphus_server::engine::read_pool::reader_threads_spawned() - before_threads;
    let channels = graphus_server::engine::retirement_channels_created() - before_channels;

    assert_eq!(
        pools, 1,
        "a {WORKERS}-worker engine built {pools} reader pools: the pool is the engine's, and one per \
         worker oversubscribes the host by W (rmp #1039)"
    );
    assert_eq!(
        channels, 1,
        "a {WORKERS}-worker engine created {channels} retirement channels: with more than one, a \
         worker can only drain the readers it dispatched itself (rmp #1039)"
    );
    assert_eq!(
        threads, READER_THREADS as u64,
        "a {WORKERS}-worker engine spawned {threads} reader threads for a pool of {READER_THREADS}: \
         the pool must be sized once, not once per worker (rmp #1039)"
    );

    shutdown(engine);
}

/// **GATE 2 — a read dispatched off-thread still retires, and the engine goes quiet.**
///
/// The structural change is that a reader's retirement is drained by whichever worker reaches the
/// engine's one channel, which need not be the worker that dispatched it. Two things must therefore
/// still hold, and both are observed rather than assumed:
///
/// * every statement is accounted for — `committed + aborted` grows by exactly the number issued, so a
///   retirement that was dropped, or processed twice, shows up as a count that does not add up;
/// * the engine goes QUIET — no transaction is left open once the clients are done. A retirement that
///   never reached a drainer leaves its ticket in the open-transaction table forever, pinning the MVCC
///   GC watermark and leaving the client's egress channel unclosed.
///
/// The clients are spread across sessions deliberately: `BEGIN` round-robins, so their auto-commit
/// reads are dispatched from several workers into the one channel.
///
/// **Non-vacuity.** With `process_retirements` made to skip retirements whose ticket the draining
/// worker does not own — the shape a per-worker channel imposes, and the obvious wrong "fix" for
/// sharing one — the quiescence assertion below fails: the readers dispatched by other workers never
/// retire and the gauge never returns to zero.
#[test]
fn readers_dispatched_from_several_workers_all_retire_on_one_channel() {
    const WORKERS: usize = 4;
    const CLIENTS: usize = 8;
    const READS_EACH: usize = 12;
    let _serial = COUNTER_GATE
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);

    let dir = TempDir::new("retire");
    let (engine, metrics) = engine(&dir.path, WORKERS, 4);
    let handle = engine.handle.clone();

    // Seed something to read, so the reads are not trivially empty.
    let seed = handle.begin_blocking(AccessMode::Write).expect("begin");
    run_in(
        &handle,
        seed,
        "UNWIND range(1, 64) AS x CREATE (:Leaf {seq: x})",
        false,
    )
    .expect("seed");
    handle.commit_blocking(seed).expect("commit seed");

    let before = counter(&metrics, "graphus_transactions_committed_total")
        + counter(&metrics, "graphus_transactions_aborted_total");

    let clients: Vec<_> = (0..CLIENTS)
        .map(|_| {
            let handle = handle.clone();
            std::thread::spawn(move || {
                for _ in 0..READS_EACH {
                    let ticket = handle
                        .begin_auto_commit_blocking(AccessMode::Read)
                        .expect("begin auto-commit read");
                    run_in(&handle, ticket, "MATCH (l:Leaf) RETURN count(l) AS c", true)
                        .expect("an auto-commit read must succeed");
                }
            })
        })
        .collect();
    for c in clients {
        c.join().expect("client thread");
    }

    // ACCOUNTING, waited for rather than sampled. A client returns when its rows are drained, which is
    // BEFORE the reader retires and before any worker drains that retirement — the resolution is the
    // engine's work, not the client's, so reading the counter the instant the clients join measures
    // nothing. Waiting for the expected total is not a weaker assertion than reading it once: a
    // retirement that is dropped never arrives, and the deadline below reports the count it did reach.
    let expected = (CLIENTS * READS_EACH) as u64;
    let deadline = std::time::Instant::now() + Duration::from_secs(20);
    let mut resolved = 0u64;
    while std::time::Instant::now() < deadline {
        resolved = counter(&metrics, "graphus_transactions_committed_total")
            + counter(&metrics, "graphus_transactions_aborted_total")
            - before;
        if resolved >= expected {
            break;
        }
        std::thread::sleep(Duration::from_millis(2));
    }
    assert_eq!(
        resolved, expected,
        "{expected} reads were issued and {resolved} transactions resolved: a retirement was dropped \
         or processed twice on the engine's shared channel (rmp #1039)"
    );

    // QUIESCENCE: nothing is left open. A retirement that never reached a drainer would sit here.
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    let mut open = metrics.active_txns();
    while open != 0 && std::time::Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(2));
        open = metrics.active_txns();
    }
    assert_eq!(
        open, 0,
        "{open} transactions are still open after every client finished: a reader's retirement was \
         never drained, so its ticket pins the GC watermark for the life of the engine (rmp #1039)"
    );

    drop(handle);
    shutdown(engine);
}

/// Runs `query` to completion inside `ticket`, returning its rows or the terminal error.
fn run_in(
    handle: &EngineHandle,
    ticket: graphus_server::engine::TxTicket,
    query: &str,
    // MUST match how the ticket was opened. A ticket from `begin_auto_commit_blocking` run with
    // `auto_commit = false` is never finalised by the engine: it streams its rows and then simply
    // stays open, which reads exactly like a retirement that was never drained. Getting this wrong is
    // how the first draft of this gate accused the engine of leaking 96 transactions.
    auto_commit: bool,
) -> Result<usize, String> {
    let mut reply = handle
        .run_blocking(
            ticket,
            query.to_owned(),
            Vec::new(),
            auto_commit,
            None,
            None,
        )
        .map_err(|e| e.to_string())?;
    let mut rows = 0usize;
    loop {
        match reply.rows.next() {
            Ok(Some(_)) => rows += 1,
            Ok(None) => return Ok(rows),
            Err(e) => return Err(e.to_string()),
        }
    }
}

/// The value of a Prometheus counter, by exact metric name.
fn counter(metrics: &Metrics, name: &str) -> u64 {
    for line in metrics.render_prometheus().lines() {
        if let Some(rest) = line.strip_prefix(name) {
            let rest = rest.trim();
            if let Ok(v) = rest.parse::<u64>() {
                return v;
            }
        }
    }
    panic!("metric {name} not found in the Prometheus rendering");
}
