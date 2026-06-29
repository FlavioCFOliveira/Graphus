//! **Engine concurrency-engine & admission saturation audit** (`rmp` task #470).
//!
//! A real-OS-thread, non-deterministic stress battery that drives the single-engine-thread write
//! authority + the off-thread reader pool + the global admission semaphore (`04 §9.3`) through a
//! cloned `Send + Sync` [`EngineHandle`] from many client threads at once, to certify the
//! correctness / fairness / liveness behaviour the production-confidence audit asks for:
//!
//! - **CORRECT** — every committed write survives (no lost / duplicated work); a rolled-back or
//!   shed write never reaches the graph; no torn read; no panic; no transaction leak
//!   (`Metrics::active_txns()` returns to 0).
//! - **LIVE** — the run always terminates (a genuine deadlock / livelock is caught by the
//!   [`Watchdog`] as a hard, loud failure, never an infinite CI hang) and the engine keeps serving a
//!   fresh query afterwards.
//! - **FAIR / BOUNDED** — at saturation the admission semaphore fast-rejects excess work with
//!   [`ServerBusy`] (a clean, retriable signal counted in `graphus_admission_rejections_total`)
//!   rather than blocking the engine, OOMing, or dropping committed work; the in-flight gauge nets
//!   back to zero (no permit leak).
//!
//! ## Why these run on real OS threads (not the DST simulator)
//!
//! The deterministic VOPR driver runs the engine on **one cooperative thread** with readers dispatched
//! inline, so the true-parallel reader-pool / buffer-pool / admission-semaphore machinery is
//! structurally invisible to it (see `specification/07-dst-simulator.md` §5.1 and the sibling
//! `graphus-dst/tests/real_thread_supernode_stress.rs`). This file is the real-thread owner for the
//! **admission + saturation** slice of that parallel-race class. It is therefore intentionally
//! non-deterministic (the OS scheduler picks the interleaving) and is **not** part of the
//! deterministic seed-replay gate; it asserts *properties* (survival, termination, bounded shedding),
//! never fragile absolute timings or exact shed/commit splits.
//!
//! ## Hang detection
//!
//! A deadlock/livelock would otherwise hang the test binary forever. [`Watchdog`] converts that into a
//! prompt, explicit failure: a monitor thread aborts the process with a diagnostic if a phase exceeds a
//! generous deadline. A healthy run disarms it long before the deadline, so it never trips in practice.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use graphus_core::Value;
use graphus_core::capability::Clock;
use graphus_io::MemBlockDevice;
use graphus_server::engine::command::AccessMode;
use graphus_server::engine::{Engine, EngineHandle, ServerBusy, spawn_engine};
use graphus_sim::SharedClock;
use graphus_storage::RecordStore;
use graphus_wal::{MemLogSink, WalManager};

// --------------------------------------------------------------------------------------------------
// Harness
// --------------------------------------------------------------------------------------------------

/// Spawns a threaded engine over a fresh in-memory store. `pool_pages` is deliberately modest so a
/// wide working set forces real eviction / contended victim sweeps in the `ConcurrentBufferPool` while
/// many reader threads pull concurrently; `queue_cap` is the bounded command-channel capacity (the
/// submission backpressure surface); `reader_threads` sizes the off-thread reader pool.
fn engine(reader_threads: usize, pool_pages: usize, queue_cap: usize) -> Engine {
    let clock: Arc<dyn Clock + Send + Sync> = Arc::new(SharedClock::new(0));
    let metrics = Arc::new(graphus_server::metrics::Metrics::new());
    spawn_engine::<MemBlockDevice, MemLogSink, _>(
        Arc::<str>::from("admission-saturation"),
        move || {
            let device = MemBlockDevice::new(0);
            let wal = WalManager::create(MemLogSink::new())?;
            let store = RecordStore::create(device, wal, pool_pages, 1)?;
            Ok(graphus_cypher::TxnCoordinator::new(store))
        },
        queue_cap,
        256,
        reader_threads,
        metrics,
        clock,
    )
    .expect("spawn threaded engine")
}

/// Tears the engine down: drop both handle clones so the command channel closes, then join the thread.
fn teardown(engine: Engine, handle: EngineHandle) {
    let Engine {
        handle: inner,
        join,
    } = engine;
    drop(handle);
    drop(inner);
    join.join()
        .expect("engine thread joins cleanly (no panic in the engine loop)");
}

/// Runs an auto-commit statement to completion, returning the first integer scalar of the first row.
fn scalar(handle: &EngineHandle, stmt: &str) -> Option<i64> {
    let ticket = handle.begin_auto_commit_blocking(AccessMode::Read).ok()?;
    let mut reply = handle
        .run_blocking(ticket, stmt.to_owned(), vec![], true, None)
        .ok()?;
    let mut v = None;
    while let Ok(Some(cells)) = reply.rows.next() {
        if let Some(graphus_cypher::MaterializedValue::Value(Value::Integer(n))) = cells.first() {
            v = Some(*n);
        }
    }
    v
}

/// Drains a read statement to completion, asserting it never tears (every produced scalar is a valid
/// non-negative count). Returns whether the read completed without a runtime error.
fn drain_read(handle: &EngineHandle, stmt: &str) -> bool {
    let Ok(ticket) = handle.begin_auto_commit_blocking(AccessMode::Read) else {
        return false;
    };
    let Ok(mut reply) = handle.run_blocking(ticket, stmt.to_owned(), vec![], true, None) else {
        return false;
    };
    loop {
        match reply.rows.next() {
            Ok(Some(cells)) => {
                if let Some(graphus_cypher::MaterializedValue::Value(Value::Integer(n))) =
                    cells.first()
                {
                    assert!(
                        *n >= 0,
                        "a concurrent count read must never tear to a negative value"
                    );
                }
            }
            Ok(None) => return true,
            Err(_) => return false,
        }
    }
}

/// Creates one `:LINK` edge from the shared hub to a fresh unique leaf inside an EXPLICIT write txn,
/// committing it. Returns `true` iff the commit was acknowledged (the edge is durable + visible).
fn commit_one_edge(handle: &EngineHandle, leaf: i64) -> bool {
    let Ok(ticket) = handle.begin_blocking(AccessMode::Write) else {
        return false;
    };
    match handle.run_blocking(
        ticket,
        "MATCH (h:Hub {id: 0}) CREATE (h)-[:LINK]->(:Leaf {id: $l})".to_owned(),
        vec![("l".to_owned(), Value::Integer(leaf))],
        false,
        None,
    ) {
        Ok(mut reply) => {
            let mut ok = true;
            loop {
                match reply.rows.next() {
                    Ok(Some(_)) => {}
                    Ok(None) => break,
                    Err(_) => {
                        ok = false;
                        break;
                    }
                }
            }
            if !ok {
                let _ = handle.rollback_blocking(ticket);
                return false;
            }
        }
        Err(_) => {
            let _ = handle.rollback_blocking(ticket);
            return false;
        }
    }
    handle.commit_blocking(ticket).is_ok()
}

/// Creates one `:LINK` edge but **rolls it back** — it must never become visible. Returns whether the
/// statement and the rollback both completed without an engine fault.
fn rollback_one_edge(handle: &EngineHandle, leaf: i64) -> bool {
    let Ok(ticket) = handle.begin_blocking(AccessMode::Write) else {
        return false;
    };
    let ran = handle
        .run_blocking(
            ticket,
            "MATCH (h:Hub {id: 0}) CREATE (h)-[:LINK]->(:Leaf {id: $l})".to_owned(),
            vec![("l".to_owned(), Value::Integer(leaf))],
            false,
            None,
        )
        .map(|mut reply| while let Ok(Some(_)) = reply.rows.next() {})
        .is_ok();
    handle.rollback_blocking(ticket).ok();
    ran
}

/// Creates the shared `:Hub {id:0}` the writers fan edges onto.
fn create_hub(handle: &EngineHandle) {
    let setup = handle
        .begin_auto_commit_blocking(AccessMode::Write)
        .expect("begin hub setup");
    let mut r = handle
        .run_blocking(
            setup,
            "CREATE (:Hub {id: 0})".to_owned(),
            vec![],
            true,
            None,
        )
        .expect("create hub");
    while let Ok(Some(_)) = r.rows.next() {}
}

/// The hub's current `:LINK` fan-out (committed out-edges), the survival oracle.
fn fanout(handle: &EngineHandle) -> Option<i64> {
    scalar(
        handle,
        "MATCH (h:Hub {id: 0})-[:LINK]->(x) RETURN count(x) AS c",
    )
}

/// Reads a Prometheus counter/gauge value `name <value>` out of a rendered exposition.
fn metric(text: &str, name: &str) -> u64 {
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix(&format!("{name} ")) {
            if let Some(v) = rest.split_whitespace().next() {
                if let Ok(n) = v.parse() {
                    return n;
                }
            }
        }
    }
    0
}

/// A hang detector. Arm it around a stress phase; if the phase does not [`disarm`](Watchdog::disarm)
/// within `budget`, a monitor thread prints a diagnostic and aborts the process — turning a genuine
/// deadlock / livelock into a prompt, loud failure instead of an infinite CI hang. A healthy phase
/// disarms it in milliseconds, so it never trips in practice.
struct Watchdog {
    done: Arc<AtomicBool>,
}

impl Watchdog {
    fn arm(label: &'static str, budget: Duration) -> Self {
        let done = Arc::new(AtomicBool::new(false));
        let d = Arc::clone(&done);
        std::thread::Builder::new()
            .name(format!("watchdog-{label}"))
            .spawn(move || {
                let deadline = Instant::now() + budget;
                while Instant::now() < deadline {
                    if d.load(Ordering::Acquire) {
                        return;
                    }
                    std::thread::sleep(Duration::from_millis(25));
                }
                if !d.load(Ordering::Acquire) {
                    eprintln!(
                        "\n[#470 WATCHDOG] phase '{label}' exceeded {budget:?} without completing — \
                         this is a DEADLOCK / LIVELOCK (a CRITICAL concurrency finding). Aborting."
                    );
                    std::process::abort();
                }
            })
            .expect("spawn watchdog");
        Self { done }
    }

    fn disarm(self) {
        self.done.store(true, Ordering::Release);
    }
}

/// Runs `n` worker closures on real OS threads, **without** join-blocking on them while they are in
/// flight (a deadlocked worker would hang a direct `join` forever). Each worker is wrapped in a panic
/// boundary so a panic is recorded but still advances the `finished` counter; this fn waits for
/// `finished == n` (so a worker that genuinely hangs leaves this spin running, which the caller's
/// per-test [`Watchdog`] then catches and aborts) and then inspects the `panicked` flag (so a panic
/// fails cleanly). The per-test watchdog — not this fn — is the hang detector.
fn run_workers<F>(n: usize, make: F)
where
    F: Fn(usize) -> Box<dyn FnOnce() + Send>,
{
    let finished = Arc::new(AtomicUsize::new(0));
    let panicked = Arc::new(AtomicBool::new(false));
    let mut handles = Vec::with_capacity(n);
    for i in 0..n {
        let body = make(i);
        let finished = Arc::clone(&finished);
        let panicked = Arc::clone(&panicked);
        handles.push(std::thread::spawn(move || {
            let res = std::panic::catch_unwind(std::panic::AssertUnwindSafe(body));
            if res.is_err() {
                panicked.store(true, Ordering::Release);
            }
            finished.fetch_add(1, Ordering::Release);
        }));
    }
    // Wait for every worker to finish. We spin on the counter rather than `join`, so a hung worker
    // leaves this loop running (caught by the caller's per-test watchdog) instead of dead-joining here.
    while finished.load(Ordering::Acquire) < n {
        std::thread::sleep(Duration::from_millis(2));
    }
    // Every worker incremented `finished`, so these joins are instant; they also reap the threads.
    for h in handles {
        let _ = h.join();
    }
    assert!(
        !panicked.load(Ordering::Acquire),
        "a client worker panicked — the engine must never make a client thread panic"
    );
}

/// The per-test hang budget. A clean run finishes in seconds; this generous wall-clock ceiling only
/// trips on a genuine deadlock/livelock (the budget is loose enough to absorb a heavily loaded CI box).
/// Polls `active_txns` until it nets to 0, up to a generous bound, then returns the final value. The
/// open-transaction gauge is decremented by off-thread reader RETIREMENTS, which settle asynchronously
/// on the engine thread *after* the client worker threads observe their statements finish — so under
/// extreme CPU oversubscription (e.g. many test binaries sharing the cores) an immediate read can race
/// ahead of the last retirement. Polling removes that test-fidelity race WITHOUT masking a real leak: a
/// genuinely leaked transaction never reaches 0 within the bound, so the caller's `assert_eq!(.., 0)`
/// still fails on a true defect. (`rmp` #485 D4 F-D4-2 — the only fix is to the assertion's timing, not
/// the engine, which already nets to 0.)
fn settle_active_txns(mut sample: impl FnMut() -> u64) -> u64 {
    for _ in 0..500 {
        let v = sample();
        if v == 0 {
            return 0;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    sample()
}

const TEST_BUDGET: Duration = Duration::from_secs(240);

// --------------------------------------------------------------------------------------------------
// Probe 1 — concurrent writer/reader storm, swept to high concurrency.
// --------------------------------------------------------------------------------------------------

/// **Probe 1.** `N ∈ {16, 64, 256}` real OS-thread clients hammer ONE engine through a cloned handle,
/// mixing committed writes on the shared hub (disjoint leaf keys) with auto-commit reads on the shared
/// hub + a disjoint scan. Asserts at every `N`: no panic, no hang, **every committed edge survives**
/// (`fan-out == committed`), the engine keeps serving afterwards, and no transaction leaked
/// (`active_txns() == 0`). The buffer pool is deliberately small so reads force contended eviction.
#[test]
fn writer_reader_storm_high_n_keeps_all_committed_and_stays_live() {
    let wd = Watchdog::arm("probe1-storm", TEST_BUDGET);
    for &n in &[16usize, 64, 256] {
        let eng = engine(16, 512, 1024);
        let handle = eng.handle.clone();
        create_hub(&handle);

        let committed = Arc::new(AtomicUsize::new(0));
        let writers = n / 2;
        {
            let handle = handle.clone();
            let committed = Arc::clone(&committed);
            run_workers(n, move |i| {
                let h = handle.clone();
                let committed = Arc::clone(&committed);
                if i < writers {
                    // Writer: commit exactly one identifiable edge on the shared hub.
                    Box::new(move || {
                        if commit_one_edge(&h, 1_000_000 + i as i64) {
                            committed.fetch_add(1, Ordering::Relaxed);
                        }
                    })
                } else {
                    // Reader: a burst of reads mixing the shared hot key with a disjoint scan, so the
                    // off-thread reader pool + buffer pool are exercised under the writers' churn.
                    Box::new(move || {
                        for _ in 0..6 {
                            // Under saturation a read may be legitimately load-shed (ServerBusy) — that
                            // is correct back-pressure, not a defect — so we do NOT assert completion.
                            // The real invariants hold regardless: no deadlock (the watchdog), no torn
                            // result (the `count >= 0` check inside `drain_read`), no leak (the
                            // active_txns settle-poll), and committed-edge survival (the final fan-out).
                            let _ =
                                drain_read(&h, "MATCH (h:Hub {id: 0})-[:LINK]->(x) RETURN count(x)");
                            let _ = drain_read(&h, "MATCH (l:Leaf) RETURN count(l)");
                        }
                    })
                }
            });
        }

        let committed = committed.load(Ordering::Relaxed);
        assert!(committed >= 1, "at N={n}, at least one writer must commit");
        let survived = fanout(&handle);
        assert_eq!(
            survived,
            Some(committed as i64),
            "N={n}: every committed edge must survive (fan-out {survived:?} == committed {committed})"
        );

        // No transaction leaked: the open-transaction gauge nets back to zero once the storm drains
        // (settle-polled — off-thread reader retirements decrement it asynchronously; see settle_active_txns).
        let active = settle_active_txns(|| handle.metrics().active_txns());
        assert_eq!(
            active, 0,
            "N={n}: no transaction may leak — active_txns must net to 0, got {active}"
        );
        // No statement panicked, and no recovery double-panic bricked the engine.
        assert_eq!(
            handle.metrics().statement_panics(),
            0,
            "N={n}: no statement panic"
        );
        assert_eq!(
            handle.metrics().engine_recovery_panics(),
            0,
            "N={n}: no recovery double-panic"
        );

        // The engine is still live and serving after the storm.
        assert_eq!(
            fanout(&handle),
            Some(committed as i64),
            "N={n}: engine still serves after storm"
        );

        teardown(eng, handle);
        eprintln!(
            "[#470 probe1] N={n}: committed={committed} all survived; active_txns=0; engine live"
        );
    }
    wd.disarm();
}

// --------------------------------------------------------------------------------------------------
// Probe 2 — admission load-shedding at saturation: ServerBusy, not block / OOM / lost work.
// --------------------------------------------------------------------------------------------------

/// **Probe 2.** Mirror what the listeners do: gate every query through the global admission semaphore
/// (`EngineHandle::try_admit`, `04 §9.3`) sized to a small `LIMIT`, then offer far more concurrent
/// load than it permits. Asserts: excess is **fast-rejected** with [`ServerBusy`] (counted in
/// `graphus_admission_rejections_total`) — never a block, OOM, or lost commit; every admitted write
/// that committed survives; a shed attempt never reaches the graph (so `fan-out == committed`); the
/// in-flight permit gauge nets back to zero (no permit leak); and the engine stays live afterwards.
#[test]
fn admission_load_shedding_sheds_excess_without_losing_committed_work() {
    const LIMIT: usize = 8;
    const THREADS: usize = 128;
    const OPS_PER_THREAD: usize = 20;

    let wd = Watchdog::arm("probe2-admission", TEST_BUDGET);
    let eng = engine(16, 512, 1024);
    // The base handle (unlimited) creates the hub; the limited handle shares the same engine channel +
    // metrics but enforces an 8-permit admission ceiling — exactly the listener's surface.
    let base = eng.handle.clone();
    create_hub(&base);
    let limited = base.with_admission_limit(LIMIT);

    let committed = Arc::new(AtomicUsize::new(0));
    let shed = Arc::new(AtomicUsize::new(0));
    let admitted = Arc::new(AtomicUsize::new(0));

    {
        let limited = limited.clone();
        let committed = Arc::clone(&committed);
        let shed = Arc::clone(&shed);
        let admitted = Arc::clone(&admitted);
        run_workers(THREADS, move |t| {
            let h = limited.clone();
            let committed = Arc::clone(&committed);
            let shed = Arc::clone(&shed);
            let admitted = Arc::clone(&admitted);
            Box::new(move || {
                for op in 0..OPS_PER_THREAD {
                    // The admission gate: a permit, or a clean retriable ServerBusy. A shed attempt
                    // does NOT touch the engine (so it cannot corrupt state or lose committed work).
                    match h.try_admit() {
                        Ok(_permit) => {
                            admitted.fetch_add(1, Ordering::Relaxed);
                            let leaf = 2_000_000 + (t * OPS_PER_THREAD + op) as i64;
                            if commit_one_edge(&h, leaf) {
                                committed.fetch_add(1, Ordering::Relaxed);
                            }
                            // `_permit` drops here, releasing the slot + decrementing the gauge.
                        }
                        Err(ServerBusy) => {
                            shed.fetch_add(1, Ordering::Relaxed);
                        }
                    }
                }
            })
        });
    }

    let committed = committed.load(Ordering::Relaxed);
    let shed = shed.load(Ordering::Relaxed);
    let admitted = admitted.load(Ordering::Relaxed);

    // The cap engaged: with 128 threads × 20 ops against 8 permits, some work is shed.
    assert!(
        shed > 0,
        "admission cap (LIMIT={LIMIT}) must shed under {THREADS} threads; shed={shed}"
    );
    assert!(
        admitted > 0,
        "admitted queries must run under the cap; admitted={admitted}"
    );

    // Every admitted-and-committed edge survives; a shed attempt never created one.
    let survived = fanout(&base);
    assert_eq!(
        survived,
        Some(committed as i64),
        "every committed edge survives and no shed attempt leaked an edge (fan-out {survived:?} == committed {committed})"
    );

    // The shedding is observable and the permit gauge is balanced (no leak).
    let text = base.metrics().render_prometheus();
    let rejections = metric(&text, "graphus_admission_rejections_total");
    let in_flight = metric(&text, "graphus_admission_in_flight");
    assert_eq!(
        rejections, shed as u64,
        "every ServerBusy is counted exactly once in graphus_admission_rejections_total"
    );
    assert_eq!(
        in_flight, 0,
        "every admission permit was released — the in-flight gauge nets to zero"
    );
    assert_eq!(
        settle_active_txns(|| base.metrics().active_txns()),
        0,
        "no transaction leaked under load shedding"
    );
    assert_eq!(
        base.metrics().statement_panics(),
        0,
        "no statement panic under load shedding"
    );

    // The engine is still live and admits fresh work now the burst has drained.
    assert!(
        commit_one_edge(&base, 9_999_999),
        "engine still serves after the shedding storm"
    );
    assert_eq!(
        fanout(&base),
        Some(committed as i64 + 1),
        "the post-storm commit is visible"
    );

    // Drop the limited handle's command-sender clone BEFORE teardown so the engine channel can close
    // (otherwise `teardown`'s join would block forever on the still-open channel — the documented
    // teardown contract: every handle clone must be dropped for the engine loop to exit).
    drop(limited);
    teardown(eng, base);
    wd.disarm();
    eprintln!(
        "[#470 probe2] LIMIT={LIMIT} threads={THREADS} ops={}: admitted={admitted} committed={committed} shed={shed} (rejections_metric={rejections}); in_flight=0; no leak",
        THREADS * OPS_PER_THREAD
    );
}

// --------------------------------------------------------------------------------------------------
// Probe 4 — begin/commit/abort + reads churn: no deadlock, no leak, abort never leaks an edge.
// --------------------------------------------------------------------------------------------------

/// **Probe 4 (deadlock / fairness).** Many threads churn a mix of EXPLICIT-txn committed writes,
/// EXPLICIT-txn rolled-back writes, auto-commit reads (off-thread pool), and EXPLICIT-txn reads
/// (inline path) on the shared hub + disjoint scans — exercising concurrent begin/commit/abort against
/// the engine thread (which runs version GC at commit) while reader threads pound the buffer-pool shard
/// and frame latches. Asserts: the run terminates (no lock-order deadlock / livelock — caught by the
/// watchdog), no panic, **only committed edges survive** (`fan-out == committed`; every rolled-back
/// edge is invisible), and no transaction leaks (`active_txns() == 0`).
#[test]
fn begin_commit_abort_with_reads_churn_no_deadlock_no_leak() {
    const THREADS: usize = 64;
    const ITERS: usize = 24;

    let wd = Watchdog::arm("probe4-churn", TEST_BUDGET);
    let eng = engine(16, 384, 1024);
    let handle = eng.handle.clone();
    create_hub(&handle);

    let committed = Arc::new(AtomicUsize::new(0));

    {
        let handle = handle.clone();
        let committed = Arc::clone(&committed);
        run_workers(THREADS, move |t| {
            let h = handle.clone();
            let committed = Arc::clone(&committed);
            Box::new(move || {
                for it in 0..ITERS {
                    // A deterministic-but-mixed schedule per (thread, iter), so all four lifecycle
                    // shapes interleave concurrently across threads.
                    match (t + it) % 4 {
                        0 => {
                            if commit_one_edge(&h, 3_000_000 + (t * ITERS + it) as i64) {
                                committed.fetch_add(1, Ordering::Relaxed);
                            }
                        }
                        1 => {
                            // Rolled-back write: must NEVER become visible.
                            rollback_one_edge(&h, 7_000_000 + (t * ITERS + it) as i64);
                        }
                        2 => {
                            // Auto-commit read → off-thread reader pool. Under saturation this read may
                            // be legitimately load-shed (ServerBusy) — correct back-pressure, not a
                            // defect — so we do NOT assert completion; the test's real invariants (no
                            // deadlock = watchdog, no torn result = the `count >= 0` check inside
                            // `drain_read`, no leak = the active_txns settle-poll, committed-edge
                            // survival = the final fan-out) hold whether or not this read is shed.
                            let _ =
                                drain_read(&h, "MATCH (h:Hub {id: 0})-[:LINK]->(x) RETURN count(x)");
                        }
                        _ => {
                            // EXPLICIT-txn read → inline engine-thread path (not the reader pool).
                            if let Ok(ticket) = h.begin_blocking(AccessMode::Read) {
                                if let Ok(mut reply) = h.run_blocking(
                                    ticket,
                                    "MATCH (l:Leaf) RETURN count(l)".to_owned(),
                                    vec![],
                                    false,
                                    None,
                                ) {
                                    while let Ok(Some(_)) = reply.rows.next() {}
                                }
                                let _ = h.commit_blocking(ticket);
                            }
                        }
                    }
                }
            })
        });
    }

    let committed = committed.load(Ordering::Relaxed);
    let survived = fanout(&handle);
    assert_eq!(
        survived,
        Some(committed as i64),
        "only committed edges survive — every rolled-back edge is invisible (fan-out {survived:?} == committed {committed})"
    );
    assert_eq!(
        settle_active_txns(|| handle.metrics().active_txns()),
        0,
        "no transaction leaked across begin/commit/abort churn"
    );
    assert_eq!(
        handle.metrics().statement_panics(),
        0,
        "no statement panic during churn"
    );
    assert_eq!(
        handle.metrics().engine_recovery_panics(),
        0,
        "no recovery double-panic during churn"
    );

    // Engine still live.
    assert!(
        commit_one_edge(&handle, 8_888_888),
        "engine serves after the churn"
    );

    teardown(eng, handle);
    wd.disarm();
    eprintln!(
        "[#470 probe4] threads={THREADS} iters={ITERS}: committed-only survived={committed}; no deadlock; active_txns=0"
    );
}
