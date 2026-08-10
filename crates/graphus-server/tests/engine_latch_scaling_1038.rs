//! **`rmp` #1038 — the engine's session latches do not serialise its workers.**
//!
//! # What is being proved, and why the obvious test cannot prove it
//!
//! Before #1038 every execution call site in the engine loop handed its latch guards to the callee in
//! argument position:
//!
//! ```ignore
//! run_statement_isolated(coord, &mut open.lock()…, &mut plan_cache.lock()…, ticket, &query, …);
//! ```
//!
//! A Rust temporary lives to the end of the *statement* that created it, so both latches were held for
//! the entire query — compile, execute, materialise, morsel, GDS.
//!
//! # What this gate does and does not catch, stated precisely
//!
//! Measured, not assumed: with a lock held across the whole statement, the engine still occupies 3.95
//! of 4 cores **provided each worker holds its own lock**, and collapses to 1.00 the moment the lock is
//! shared. When this was written the tables were constructed inside `run_engine_loop`, one per worker —
//! the pre-#1038 guards therefore did not contend, and this gate would have passed over them. The
//! defect was **latent, not active**: it becomes a hang, not a slowdown, the moment the tables are
//! shared between workers, which is exactly why `rmp` #1041 was blocked on #1038.
//!
//! `rmp` #1041 has since landed. The three tables live in `EngineSessions`, built once per engine and
//! shared by every worker, so **this measurement is now the direct gate for the sharing hazard** and no
//! longer only a prediction about it — unchanged in a single line, which was the point of writing it
//! this way. Observed after the sharing landed: 0.99 cores at `engine_workers = 1` against 3.93 at
//! `engine_workers = 4`, i.e. exactly the third run below rather than the collapse.
//!
//! The complementary live gate for the latch *discipline* remains the tripwire
//! (`engine_latch_order_1038.rs` — a rank-5 scope alive when a statement starts is a panic). What this
//! test contributes is the end-to-end fact, and the one `rmp` #1034 needs a floor for: **W workers
//! really do execute statements at the same time**, and the restructured critical sections are short
//! enough not to get in the way.
//!
//! # The experiment
//!
//! `W` client threads each run explicit `BEGIN … RUN … COMMIT` transactions. Explicit-transaction
//! statements execute **inline on the engine worker** (only auto-commit reads dispatch to the reader
//! pool — see `exec::handle_run`), which is exactly the path the guards used to span. The statement is
//! a pure `UNWIND` over a generated range: it touches no store page, takes no store latch and drives no
//! I/O, so what it measures is the engine worker's own CPU and nothing else. Sessions reach distinct
//! workers by construction — the handle routes a `BEGIN` round-robin and every later command by
//! `ticket % W` (`rmp` #1035).
//!
//! The same total work is run twice, against `engine_workers = 1` and `engine_workers = W`, and the
//! comparison is **paired**: it asks whether giving the engine more workers makes its threads busier,
//! on this machine, in this run. An absolute threshold would encode the host's core count into the
//! assertion; the ratio does not.
//!
//! # Non-vacuity
//!
//! Holding a **shared** lock across `run_statement_isolated` collapses the `W`-worker occupancy from
//! 3.95 cores to 1.00 and fails the assertion; holding a **per-worker** one leaves it at 3.95. Both
//! were run. The pair is what tells this gate apart from a test that would pass whatever the engine
//! did, and it is where the "latent, not active" conclusion above comes from.
//!
//! A third run answered the question the fix exists for, before the sharing landed. With the three
//! session tables hoisted into process-wide statics — every worker of the engine sharing one of each,
//! which is what `rmp` #1041 then did for real — the restructured code still occupied **3.95 of 4
//! cores**. Sharing plus a critical section that spans a statement is 1.00 core (the shared-lock run
//! above); sharing plus critical sections that span a table operation is 3.95. That difference is the
//! whole of `rmp` #1038, and the prediction held: the real sharing measures 3.93.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use graphus_core::Value;
use graphus_core::capability::Clock;
use graphus_io::FileBlockDevice;
use graphus_server::engine::command::AccessMode;
use graphus_server::engine::{Engine, EngineHandle, spawn_engine_with_timeout};
use graphus_storage::RecordStore;
use graphus_wal::{FileLogSink, WalManager};

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
            "graphus_latch1038_{tag}_{}_{}",
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

fn create_engine(dir: &Path, engine_workers: usize) -> Engine {
    let device_path = dir.join("graph.db");
    let wal_dir = dir.join("wal");
    let clock: Arc<dyn Clock + Send + Sync> = Arc::new(RealClock);
    let metrics = Arc::new(graphus_server::metrics::Metrics::new());
    spawn_engine_with_timeout::<FileBlockDevice, FileLogSink, _>(
        Arc::from("latch1038"),
        move || {
            let device = FileBlockDevice::open(&device_path)?;
            let sink = FileLogSink::open(&wal_dir)?;
            let wal = WalManager::create(sink)?;
            let store = RecordStore::create(device, wal, 4_096, 1)?;
            Ok(graphus_cypher::TxnCoordinator::new(store))
        },
        8192,
        256,
        2,
        engine_workers,
        metrics,
        clock,
        None,
        None,
        None,
        Arc::new(graphus_server::txn_registry::TransactionRegistry::new()),
    )
    .expect("spawn engine")
}

/// Sum of `utime + stime` (clock ticks) over every thread of this process whose `comm` starts with
/// `prefix`. The engine names its workers `graphus-engine-<id>` (`spawn_engine_with_timeout`), so the
/// prefix selects exactly the threads whose CPU this test is about — reader-pool and rayon threads are
/// named differently and are deliberately excluded.
fn thread_ticks(prefix: &str) -> u64 {
    let mut total = 0u64;
    let Ok(entries) = std::fs::read_dir("/proc/self/task") else {
        return 0;
    };
    for entry in entries.flatten() {
        let tid = entry.file_name();
        let tid = tid.to_string_lossy();
        let Ok(comm) = std::fs::read_to_string(format!("/proc/self/task/{tid}/comm")) else {
            continue;
        };
        if !comm.trim_end().starts_with(prefix) {
            continue;
        }
        let Ok(stat) = std::fs::read_to_string(format!("/proc/self/task/{tid}/stat")) else {
            continue;
        };
        // The `comm` field may contain spaces and parentheses, so parse after the last ')'. From there
        // field 3 (state) is index 0, so utime (field 14) is index 11 and stime (field 15) is index 12.
        if let Some(rparen) = stat.rfind(')') {
            let rest: Vec<&str> = stat[rparen + 1..].split_whitespace().collect();
            if rest.len() > 12 {
                total +=
                    rest[11].parse::<u64>().unwrap_or(0) + rest[12].parse::<u64>().unwrap_or(0);
            }
        }
    }
    total
}

/// POSIX `_SC_CLK_TCK`, which is 100 on every Linux target this project builds for. Hard-coded rather
/// than pulled through `libc`, exactly as the `rmp` #1034 harness does — the two numbers have to be
/// comparable, and a difference in this constant would silently rescale one of them.
const CLK_TCK: f64 = 100.0;

/// One statement's worth of pure engine-thread CPU: an `UNWIND` over a generated range with a
/// per-row predicate. No store access, so nothing here can be attributed to page I/O, to a store latch,
/// or to the reader pool — every cycle it costs is spent by the engine worker running the cursor.
fn cpu_statement(rows: i64) -> (String, Vec<(String, Value)>) {
    (
        "UNWIND range(1, $n) AS x WITH x WHERE x % 7 = 3 RETURN count(x) AS c".to_owned(),
        vec![("n".to_owned(), Value::Integer(rows))],
    )
}

/// Runs one explicit `BEGIN … RUN … COMMIT`. Returns `false` if any step failed, so the caller can
/// assert that the measurement actually measured completed work rather than a stream of errors.
fn run_one(handle: &EngineHandle, rows: i64) -> bool {
    let Ok(ticket) = handle.begin_blocking(AccessMode::Read) else {
        return false;
    };
    let (query, params) = cpu_statement(rows);
    let Ok(mut reply) = handle.run_blocking(ticket, query, params, false, None, None) else {
        let _ = handle.rollback_blocking(ticket);
        return false;
    };
    loop {
        match reply.rows.next() {
            Ok(Some(_)) => {}
            Ok(None) => break,
            Err(_) => {
                let _ = handle.rollback_blocking(ticket);
                return false;
            }
        }
    }
    handle.commit_blocking(ticket).is_ok()
}

struct Measurement {
    /// Engine-thread CPU divided by wall-clock: how many cores the engine's own threads were worth.
    cores: f64,
    elapsed: f64,
    completed: usize,
}

/// Drives `clients` concurrent client threads, each running `per_client` explicit transactions against
/// an engine configured with `engine_workers` workers, and reports the engine threads' CPU occupancy.
fn measure(clients: usize, per_client: usize, rows: i64, engine_workers: usize) -> Measurement {
    let dir = TempDir::new(&format!("w{engine_workers}"));
    let engine = create_engine(&dir.path, engine_workers);
    let handle = engine.handle.clone();

    // Warm up: intern the plan in every worker's cache and reach steady state, so the measured window
    // contains execution rather than W first-compiles.
    for _ in 0..(engine_workers * 2).max(4) {
        assert!(run_one(&handle, 64), "warmup transaction");
    }

    let before = thread_ticks("graphus-engine");
    let t0 = std::time::Instant::now();
    let mut threads = Vec::with_capacity(clients);
    for _ in 0..clients {
        let h = handle.clone();
        threads.push(std::thread::spawn(move || {
            let mut ok = 0usize;
            for _ in 0..per_client {
                if run_one(&h, rows) {
                    ok += 1;
                }
            }
            ok
        }));
    }
    let completed: usize = threads
        .into_iter()
        .map(|t| t.join().expect("client thread joins"))
        .sum();
    let elapsed = t0.elapsed().as_secs_f64();
    let ticks = thread_ticks("graphus-engine").saturating_sub(before);

    drop(handle);
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("shutdown runtime");
    rt.block_on(engine.handle.shutdown()).expect("shutdown");
    for j in engine.joins {
        let _ = j.join();
    }

    Measurement {
        cores: (ticks as f64 / CLK_TCK) / elapsed.max(f64::EPSILON),
        elapsed,
        completed,
    }
}

/// The gate. See the module docs for the design and for how non-vacuity was established.
#[test]
fn engine_workers_execute_statements_concurrently() {
    let hw = std::thread::available_parallelism().map_or(1, std::num::NonZeroUsize::get);
    // Four is enough to separate "parallel" from "serialised" with a wide margin while staying cheap;
    // more workers would only add scheduling noise to a property that is qualitative.
    let workers = hw.min(4);
    let per_client = 12usize;
    let rows: i64 = 60_000;

    let serial = measure(workers, per_client, rows, 1);
    let parallel = measure(workers, per_client, rows, workers);

    println!(
        "rmp #1038 | hw={hw} clients={workers} | engine_workers=1: {:.2} cores in {:.3}s ({} txns) \
         | engine_workers={workers}: {:.2} cores in {:.3}s ({} txns)",
        serial.cores,
        serial.elapsed,
        serial.completed,
        parallel.cores,
        parallel.elapsed,
        parallel.completed
    );

    let expected = workers * per_client;
    assert_eq!(
        serial.completed, expected,
        "every transaction must complete on the single-worker engine — a measurement over failed \
         statements measures nothing"
    );
    assert_eq!(
        parallel.completed, expected,
        "every transaction must complete on the {workers}-worker engine"
    );

    if workers < 2 {
        // One hardware thread cannot execute two statements at once, so occupancy cannot separate the
        // two configurations here. The liveness assertions above still hold and are what this run
        // contributes; the concurrency claim is measured wherever the hardware can express it.
        println!("rmp #1038 | single hardware thread: occupancy cannot distinguish the two shapes");
        return;
    }

    // A serialised engine spends all its CPU on one thread at a time, so its occupancy sits at ~1.0
    // core no matter how many workers it was given. The bar is deliberately well below `workers`:
    // the claim is "they overlap", not "they scale linearly", and linear scaling is `rmp` #1034's
    // question, not this gate's.
    let floor = 1.0 + 0.5 * (workers as f64 - 1.0);
    assert!(
        parallel.cores >= floor,
        "engine_workers={workers} occupied only {:.2} cores (floor {floor:.2}). The workers are \
         taking turns — some engine latch is being held across statement execution (rmp #1038).",
        parallel.cores
    );
    assert!(
        parallel.cores >= serial.cores * 1.5,
        "{workers} workers occupied {:.2} cores against {:.2} for a single worker: adding workers did \
         not add concurrency, which is what a latch held across a statement looks like (rmp #1038).",
        parallel.cores,
        serial.cores
    );
}
