//! **Adaptive reader-pool morsel width** (`rmp` task #575-g.1): a heavy morsel-eligible read dispatched
//! to the off-thread reader pool must now engage **intra-query** morsel parallelism in the LIVE server,
//! without reintroducing the `rmp` #377 pool-on-pool over-subscription.
//!
//! ## Background
//!
//! `rmp` #575 parallelized the 3-hop `r3_fof3` recommendation query with an intra-query morsel tier
//! (measured 14320 ms/1 core → 486 ms/8 cores at the cypher/executor level, i.e. on the engine thread).
//! But in the live server `r3_fof3` is a read-only auto-commit statement, so the engine dispatches it
//! **off-thread** to the reader pool — where `rmp` #377 (v1) clamped `Ctx.morsel_threads` to `1` on every
//! reader-pool worker, to stop `K` concurrent large reads each fanning `min(N,16)` morsel tasks onto the
//! shared `min(N,16)`-thread analytics pool. So a lone heavy read still ran on ONE reader thread and the
//! #575 win never reached production.
//!
//! ## The fix under test
//!
//! The engine dispatch site (which knows `readers_inflight`) now chooses an **adaptive** width of
//! `floor(analytics_pool_threads / (readers_inflight + 1))`
//! ([`graphus_cypher::morsel::reader_pool_morsel_width`]) and carries it to the worker's
//! [`ReaderPoolWorkerGuard::enter_with_width`](graphus_cypher::morsel::ReaderPoolWorkerGuard). A lone read
//! gets the whole pool (all cores); `K` concurrent reads get `<= P/K` each (sum `<= P`, no
//! over-subscription); at `K >= P` the width is `1` — reproducing the #377 v1 clamp exactly.
//!
//! ## What is asserted
//!
//! 1. **Correctness + engagement (always runs)**
//!    ([`lone_reader_read_engages_morsel_off_thread_and_matches`]): a lone auto-commit `r3_fof3` read
//!    dispatched off-thread with the adaptive width returns rows **byte-identical** to the same query run
//!    inline (explicit transaction) AND to the `rmp` #377 v1 baseline (morsel knob pinned to `1`), while
//!    the morsel tier is proven to actually **fan out on the reader path** (the process-global
//!    [`morsel_fanout_count`](graphus_cypher::morsel::morsel_fanout_count) increments) — which it did NOT
//!    before this change. The knob=1 baseline read is proven to fan out **zero** times (the #377 v1
//!    serial-per-reader behavior is preserved).
//!
//! 2. **Two-regime measurement (`#[ignore]`, Linux)** ([`measure_reader_pool_morsel_width`]): the lone
//!    read's mean cores + wall-time, and the `K`-concurrent-read throughput + per-query latency, each
//!    reported for the adaptive width vs the clamp-to-1 baseline. Ignored by default (a multi-second CPU
//!    measurement); run with `--ignored --nocapture`.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Instant;

use graphus_core::capability::Clock;
use graphus_core::{TxnId, Value};
use graphus_io::MemBlockDevice;
use graphus_server::engine::command::AccessMode;
use graphus_server::engine::{Engine, EngineHandle, spawn_engine};
use graphus_sim::SharedClock;
use graphus_storage::{Namespace, RecordStore};
use graphus_wal::{MemLogSink, WalManager};

/// The exact `rmp` #575 target — the heaviest reco query: a 3-hop friend chain from ONE seed, join
/// `PURCHASED`, anti-join the seed's own purchases, grouped `count(DISTINCT f3)`, `ORDER BY … LIMIT 10`.
const R3_FOF3: &str = "MATCH (me:User {id: $id})-[:FRIEND]-(:User)-[:FRIEND]-(:User)-[:FRIEND]-(f3:User) \
     WHERE f3.id <> $id \
     MATCH (f3)-[:PURCHASED]->(p:Product) \
     WHERE NOT (me)-[:PURCHASED]->(p) \
     RETURN p.id AS product, count(DISTINCT f3) AS reach \
     ORDER BY reach DESC, product ASC LIMIT 10";

/// Serializes every test in this file: they all mutate the process-global morsel knobs
/// (`set_morsel_threads` / `set_analytics_pool_threads`) and read the process-global `morsel_fanout_count`,
/// so they must not run concurrently (the default Rust test harness runs tests on parallel threads).
static TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Bulk-seeds a committed recommendation-shaped graph directly on the record store (NOT via Cypher — a
/// two-anchor per-edge `CREATE` serializes on one writer and is `O(E·N)`): `n_users` `:User` nodes, a
/// circulant band + scattered long-range `FRIEND` graph (so a single seed's 3-hop friend frontier is
/// large and spans the id range), `n_products` `:Product` nodes, and a deterministic spread of `PURCHASED`
/// edges. Mirrors the `graphus-cypher` `morsel_frontier_fof` seeder so the shapes match. Deterministic.
fn seed_reco(s: &mut RecordStore<MemBlockDevice, MemLogSink>, cfg: SeedCfg) {
    let txn = TxnId(1);
    s.begin(txn);
    let l_user = s.intern_token(Namespace::Label, "User").unwrap();
    let l_product = s.intern_token(Namespace::Label, "Product").unwrap();
    let k_id = s.intern_token(Namespace::PropKey, "id").unwrap();
    let t_friend = s.intern_token(Namespace::RelType, "FRIEND").unwrap();
    let t_purchased = s.intern_token(Namespace::RelType, "PURCHASED").unwrap();

    let mut products = Vec::with_capacity(cfg.products as usize);
    for p in 0..cfg.products {
        let (id, _) = s.create_node(txn).unwrap();
        s.add_label(txn, id, l_product).unwrap();
        s.set_node_property_value(txn, id, k_id, &Value::Integer(p))
            .unwrap();
        products.push(id);
    }
    let mut users = Vec::with_capacity(cfg.users as usize);
    for u in 0..cfg.users {
        let (id, _) = s.create_node(txn).unwrap();
        s.add_label(txn, id, l_user).unwrap();
        s.set_node_property_value(txn, id, k_id, &Value::Integer(u))
            .unwrap();
        users.push(id);
    }
    for u in 0..cfg.users {
        for d in 1..=cfg.friend_deg {
            let v = (u + d).rem_euclid(cfg.users);
            if v != u {
                s.create_rel(txn, t_friend, users[u as usize], users[v as usize])
                    .unwrap();
            }
        }
        let far = (u.wrapping_mul(2_654_435_761) ^ 0x9E37).rem_euclid(cfg.users);
        if far != u {
            s.create_rel(txn, t_friend, users[u as usize], users[far as usize])
                .unwrap();
        }
    }
    for u in 0..cfg.users {
        for k in 0..cfg.purchase_deg {
            let p = (u.wrapping_mul(31).wrapping_add(k.wrapping_mul(97))).rem_euclid(cfg.products);
            s.create_rel(txn, t_purchased, users[u as usize], products[p as usize])
                .unwrap();
        }
    }
    s.commit(txn).unwrap();
}

#[derive(Clone, Copy)]
struct SeedCfg {
    users: i64,
    products: i64,
    friend_deg: i64,
    purchase_deg: i64,
}

/// Spawns a threaded engine with `reader_threads` reader workers over a store bulk-seeded with a reco
/// graph, and a generously-sized buffer pool (working set stays RAM-resident → the measurement is
/// CPU-bound, not eviction-bound). Sets the process-global morsel + analytics knobs to `pool` — exactly
/// what the real server does at startup (`dbcatalog`), which the bare `spawn_engine` test harness omits.
fn engine_seeded(reader_threads: usize, pool: usize, cfg: SeedCfg) -> Engine {
    // Model the production startup: enable the morsel tier and size the shared analytics pool. The
    // analytics pool is built ONCE (lazily) at this width, so set it before the first read engages.
    graphus_cypher::morsel::set_morsel_threads(pool);
    graphus_cypher::morsel::set_analytics_pool_threads(pool);

    let clock: Arc<dyn Clock + Send + Sync> = Arc::new(SharedClock::new(0));
    let metrics = Arc::new(graphus_server::metrics::Metrics::new());
    spawn_engine::<MemBlockDevice, MemLogSink, _>(
        std::sync::Arc::from("test"),
        move || {
            let device = MemBlockDevice::new(0);
            let wal = WalManager::create(MemLogSink::new())?;
            // 262_144 pages of buffer pool: comfortably holds the reco working set in RAM so eviction
            // never dilutes the CPU measurement.
            let mut store = RecordStore::create(device, wal, 262_144, 1)?;
            seed_reco(&mut store, cfg);
            Ok(graphus_cypher::TxnCoordinator::new(store))
        },
        4096,
        256,
        reader_threads,
        metrics,
        clock,
        std::sync::Arc::new(graphus_server::txn_registry::TransactionRegistry::new()),
    )
    .expect("spawn threaded engine")
}

/// Drains every row of an **auto-commit** statement (dispatched off-thread when structurally read-only),
/// returning its materialized rows.
fn run_auto(
    handle: &EngineHandle,
    stmt: &str,
    id: i64,
) -> Vec<Vec<graphus_cypher::MaterializedValue>> {
    let ticket = handle
        .begin_auto_commit_blocking(AccessMode::Read)
        .expect("begin auto-commit");
    let params = vec![("id".to_owned(), Value::Integer(id))];
    let mut rows = Vec::new();
    match handle.run_blocking(ticket, stmt.to_owned(), params, true, None, None) {
        Ok(mut reply) => loop {
            match reply.rows.next() {
                Ok(Some(cells)) => rows.push(cells),
                Ok(None) => break,
                Err(e) => panic!("auto-commit read streamed an error: {e:?}"),
            }
        },
        Err(e) => panic!("auto-commit run failed: {e:?}"),
    }
    rows
}

/// Drains every row of a read inside an **explicit** transaction (never dispatched off-thread — runs
/// inline on the engine thread, where `morsel_threads` is the full configured pool).
fn run_explicit(
    handle: &EngineHandle,
    stmt: &str,
    id: i64,
) -> Vec<Vec<graphus_cypher::MaterializedValue>> {
    let ticket = handle
        .begin_blocking(AccessMode::Read)
        .expect("begin explicit");
    let params = vec![("id".to_owned(), Value::Integer(id))];
    let mut rows = Vec::new();
    match handle.run_blocking(ticket, stmt.to_owned(), params, false, None, None) {
        Ok(mut reply) => loop {
            match reply.rows.next() {
                Ok(Some(cells)) => rows.push(cells),
                Ok(None) => break,
                Err(e) => panic!("explicit read streamed an error: {e:?}"),
            }
        },
        Err(e) => panic!("explicit run failed: {e:?}"),
    }
    handle
        .commit_blocking(ticket)
        .expect("explicit read commits");
    rows
}

fn shutdown(eng: Engine, handle: EngineHandle) {
    let Engine {
        handle: inner,
        join,
    } = eng;
    drop(handle);
    drop(inner);
    join.join().expect("engine joins");
}

/// (1) Correctness + engagement, always runs. A lone auto-commit `r3_fof3` read dispatched off-thread
/// with the adaptive width returns rows byte-identical to the inline (explicit-txn) execution AND to the
/// `rmp` #377 v1 clamp-to-1 baseline, while the morsel tier is proven to actually fan out on the reader
/// path (which it did NOT before `rmp` #575-g.1). The clamp-to-1 baseline read is proven to fan out zero
/// times (the #377 v1 serial-per-reader behavior is preserved).
#[test]
fn lone_reader_read_engages_morsel_off_thread_and_matches() {
    let _lock = TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    // A modest reco graph: the 3-hop frontier from seed 0 is a few thousand distinct `f3`, large enough
    // that the frontier tier genuinely fans out, small enough to run fast in CI.
    let cfg = SeedCfg {
        users: 3_000,
        products: 200,
        friend_deg: 16,
        purchase_deg: 6,
    };
    let pool = 8;
    let eng = engine_seeded(8, pool, cfg);
    let handle = eng.handle.clone();

    // Inline (explicit transaction) — the engine thread runs the full morsel tier; the reference result.
    graphus_cypher::morsel::set_morsel_threads(pool);
    let inline = run_explicit(&handle, R3_FOF3, 0);
    assert!(
        !inline.is_empty(),
        "the reco result must be non-empty (else the equivalence is vacuous)"
    );

    // Adaptive off-thread: a LONE auto-commit read → dispatched to the reader pool → adaptive width =
    // pool / (0 + 1) = pool > 1 → the frontier tier engages ON THE READER PATH. Prove it fanned out.
    graphus_cypher::morsel::set_morsel_threads(pool);
    let fan_before = graphus_cypher::morsel::morsel_fanout_count();
    let off_thread_adaptive = run_auto(&handle, R3_FOF3, 0);
    let fan_after = graphus_cypher::morsel::morsel_fanout_count();
    assert!(
        fan_after > fan_before,
        "rmp #575-g.1: a lone off-thread reader read MUST engage the morsel tier (fan-outs: \
         {fan_before} → {fan_after}); before this fix the #377 v1 clamp kept it at 0"
    );
    assert_eq!(
        off_thread_adaptive, inline,
        "rmp #575-g.1: the adaptive off-thread read must be byte-identical to the inline execution"
    );

    // Clamp-to-1 baseline (the `rmp` #377 v1 behavior): pin the morsel knob to 1 → the reader read runs
    // serial on its reader thread and MUST NOT fan out. Result still identical (width-independence).
    graphus_cypher::morsel::set_morsel_threads(1);
    let fan_before_serial = graphus_cypher::morsel::morsel_fanout_count();
    let off_thread_serial = run_auto(&handle, R3_FOF3, 0);
    let fan_after_serial = graphus_cypher::morsel::morsel_fanout_count();
    assert_eq!(
        fan_after_serial, fan_before_serial,
        "rmp #377: with the morsel knob pinned to 1 a reader read must stay serial (no fan-out)"
    );
    assert_eq!(
        off_thread_serial, inline,
        "the clamp-to-1 off-thread read must also be byte-identical to inline (width-independence)"
    );

    graphus_cypher::morsel::set_morsel_threads(1);
    shutdown(eng, handle);
}

/// This process's total CPU time (user + system) in seconds, from `/proc/self/stat` (Linux). Isolates
/// each measured phase's mean-core utilisation. `_SC_CLK_TCK` is 100 on every mainstream Linux.
#[cfg(target_os = "linux")]
fn proc_cpu_secs() -> f64 {
    let stat = std::fs::read_to_string("/proc/self/stat").unwrap_or_default();
    let after = stat.rsplit_once(')').map(|(_, t)| t).unwrap_or("");
    let fields: Vec<&str> = after.split_whitespace().collect();
    let utime: f64 = fields.get(11).and_then(|s| s.parse().ok()).unwrap_or(0.0);
    let stime: f64 = fields.get(12).and_then(|s| s.parse().ok()).unwrap_or(0.0);
    (utime + stime) / 100.0
}

/// (2) Two-regime measurement (`#[ignore]`, Linux). For BOTH the adaptive width and the `rmp` #377 v1
/// clamp-to-1 baseline (morsel knob pinned to 1), reports:
///   * **lone read** — mean cores `(utime+stime)/wall` + wall-time (proves the lone read now engages many
///     cores through the live reader-pool path, vs ≈ 1 core clamped);
///   * **K concurrent reads** — aggregate throughput (reads/s) + mean per-query latency (proves NO
///     over-subscription / thrash: the adaptive path must not regress vs clamp-to-1 at `K >= P`, and it
///     fills otherwise-idle cores at `K < P`).
///
/// Run (Linux, release):
/// ```text
/// cargo test -p graphus-server --release --test reader_pool_morsel_width \
///     measure_reader_pool_morsel_width -- --ignored --nocapture
/// ```
/// `GRAPHUS_BENCH_USERS` / `_FRIEND_DEG` / `_PRODUCTS` / `_PURCHASE_DEG` / `_ITERS` size the graph/loop.
#[test]
#[ignore = "multi-second CPU measurement; run with --ignored --nocapture under release"]
#[cfg(target_os = "linux")]
fn measure_reader_pool_morsel_width() {
    let _lock = TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    let env_i64 = |k: &str, d: i64| {
        std::env::var(k)
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(d)
    };
    let env_usize = |k: &str, d: usize| {
        std::env::var(k)
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(d)
    };
    let cfg = SeedCfg {
        users: env_i64("GRAPHUS_BENCH_USERS", 30_000),
        products: env_i64("GRAPHUS_BENCH_PRODUCTS", 2_000),
        friend_deg: env_i64("GRAPHUS_BENCH_FRIEND_DEG", 24),
        purchase_deg: env_i64("GRAPHUS_BENCH_PURCHASE_DEG", 4),
    };
    let iters = env_usize("GRAPHUS_BENCH_ITERS", 24);
    let pool = graphus_cypher::morsel::analytics_pool_threads(); // = min(N,16), the live default
    let reader_threads = pool;

    let eng = engine_seeded(reader_threads, pool, cfg);
    let handle = eng.handle.clone();

    println!(
        "\nreader-pool adaptive morsel width (rmp #575-g.1): users={} friend_deg={} products={} \
         purchase_deg={} | analytics pool P={pool}, reader_threads={reader_threads}, iters/thread={iters}",
        cfg.users, cfg.friend_deg, cfg.products, cfg.purchase_deg
    );

    // Warm one read (fault pages into the buffer pool) so no phase pays first-touch cost.
    graphus_cypher::morsel::set_morsel_threads(pool);
    let _warm = run_auto(&handle, R3_FOF3, 0);

    // ---- Regime 1: LONE read (reader pool otherwise idle) ----
    println!("\n[regime 1] lone heavy read (K=1):");
    for (label, knob) in [
        ("clamp-to-1 (rmp #377 v1)", 1usize),
        ("adaptive (rmp #575-g.1)", pool),
    ] {
        graphus_cypher::morsel::set_morsel_threads(knob);
        let _ = run_auto(&handle, R3_FOF3, 0); // settle
        let (cpu0, wall0) = (proc_cpu_secs(), Instant::now());
        let reps = 6usize;
        for _ in 0..reps {
            let _ = run_auto(&handle, R3_FOF3, 0);
        }
        let wall = wall0.elapsed().as_secs_f64();
        let cpu = proc_cpu_secs() - cpu0;
        let cores = cpu / wall.max(f64::MIN_POSITIVE);
        println!(
            "  {label:26}: {reps} reads in {wall:6.3}s ({:6.1} ms/read) | mean cores = {cores:5.2}",
            wall * 1000.0 / reps as f64,
        );
    }

    // ---- Regime 2: K concurrent reads (the #377 no-over-subscription regime) ----
    for k in [pool / 2, pool, pool * 2] {
        if k == 0 {
            continue;
        }
        println!("\n[regime 2] K={k} concurrent heavy reads:");
        for (label, knob) in [
            ("clamp-to-1 (rmp #377 v1)", 1usize),
            ("adaptive (rmp #575-g.1)", pool),
        ] {
            graphus_cypher::morsel::set_morsel_threads(knob);
            let barrier = Arc::new(std::sync::Barrier::new(k + 1));
            let done = Arc::new(AtomicUsize::new(0));
            let mut workers = Vec::new();
            for t in 0..k {
                let h = handle.clone();
                let b = Arc::clone(&barrier);
                let d = Arc::clone(&done);
                // Different seeds so the reads are genuinely independent work.
                let seed = (t as i64 * 37) % cfg.users;
                workers.push(std::thread::spawn(move || {
                    b.wait();
                    for _ in 0..iters {
                        let rows = run_auto(&h, R3_FOF3, seed);
                        assert!(!rows.is_empty(), "each concurrent read yields rows");
                        d.fetch_add(1, Ordering::Relaxed);
                    }
                }));
            }
            barrier.wait();
            let (cpu0, wall0) = (proc_cpu_secs(), Instant::now());
            for w in workers {
                w.join().expect("worker joins");
            }
            let wall = wall0.elapsed().as_secs_f64();
            let cpu = proc_cpu_secs() - cpu0;
            let total = done.load(Ordering::Relaxed);
            let thru = total as f64 / wall.max(f64::MIN_POSITIVE);
            let lat_ms = wall * 1000.0 * k as f64 / total as f64; // mean per-query wall (k in flight)
            let cores = cpu / wall.max(f64::MIN_POSITIVE);
            println!(
                "  {label:26}: {total:4} reads in {wall:6.3}s | throughput = {thru:7.1} reads/s | \
                 mean latency = {lat_ms:7.1} ms | mean cores = {cores:5.2}",
            );
        }
    }

    graphus_cypher::morsel::set_morsel_threads(1);
    shutdown(eng, handle);
    println!();
}

/// Drains an **auto-commit WRITE** and returns whether it committed (used by the write-stall bench).
fn run_write(handle: &EngineHandle, stmt: &str) -> bool {
    let Ok(ticket) = handle.begin_auto_commit_blocking(AccessMode::Write) else {
        return false;
    };
    match handle.run_blocking(ticket, stmt.to_owned(), vec![], true, None, None) {
        Ok(mut reply) => loop {
            match reply.rows.next() {
                Ok(Some(_)) => {}
                Ok(None) => break true,
                Err(_) => break false,
            }
        },
        Err(_) => false,
    }
}

/// (3) The empirical case AGAINST design (b) "inline routing" (`rmp` task #575-g.1, `#[ignore]`): route a
/// heavy morsel-eligible read INLINE on the engine thread (where `morsel_threads` is the full pool,
/// unclamped) and it engages all cores — but it **occupies the single engine thread** for its whole
/// duration, so every concurrent write / commit / dispatch queues behind it. This bench measures small
/// auto-commit **write** latency while ONE client hammers heavy `r3_fof3` reads, comparing:
///   * design (a) — the read runs auto-commit **off-thread** (adaptive width) → writes keep flowing on the
///     engine thread while the read fans on the analytics pool;
///   * design (b) proxy — the read runs in an **explicit transaction**, i.e. INLINE on the engine thread
///     (the faithful stand-in for routing a heavy read inline) → writes stall behind it.
///
/// A design-(b) write-latency blow-up is the disqualifier: it trades the lone-read win for a stalled write
/// path, unacceptable for a mixed read+write server. Design (a) has no such stall (its whole point).
///
/// Run: `cargo test -p graphus-server --release --test reader_pool_morsel_width \
///     measure_inline_routing_write_stall -- --ignored --nocapture`
#[test]
#[ignore = "multi-second latency measurement; run with --ignored --nocapture under release"]
fn measure_inline_routing_write_stall() {
    let _lock = TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    let cfg = SeedCfg {
        users: 30_000,
        products: 2_000,
        friend_deg: 24,
        purchase_deg: 4,
    };
    let pool = graphus_cypher::morsel::analytics_pool_threads();
    let eng = engine_seeded(pool, pool, cfg);
    let handle = eng.handle.clone();
    graphus_cypher::morsel::set_morsel_threads(pool);
    let _warm = run_auto(&handle, R3_FOF3, 0);

    println!(
        "\ninline-routing write-stall (rmp #575-g.1): a concurrent heavy r3_fof3 read + small writes | P={pool}"
    );

    // `inline_read == true` is the design-(b) proxy (heavy read in an explicit txn → inline on the engine
    // thread); `false` is design (a) (heavy read auto-commit → off-thread with adaptive width).
    for (label, inline_read) in [
        ("(a) read off-thread ", false),
        ("(b) read inline (proxy)", true),
    ] {
        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let reads_done = Arc::new(AtomicUsize::new(0));
        let h_read = handle.clone();
        let stop_r = Arc::clone(&stop);
        let reads_c = Arc::clone(&reads_done);
        let reader = std::thread::spawn(move || {
            while !stop_r.load(Ordering::Relaxed) {
                if inline_read {
                    let _ = run_explicit(&h_read, R3_FOF3, 0);
                } else {
                    let _ = run_auto(&h_read, R3_FOF3, 0);
                }
                reads_c.fetch_add(1, Ordering::Relaxed);
            }
        });

        // Give the reader a moment to get a heavy read in flight, then measure write latencies.
        std::thread::sleep(std::time::Duration::from_millis(50));
        let mut lats: Vec<f64> = Vec::new();
        let n_writes = 40usize;
        for _ in 0..n_writes {
            let t0 = Instant::now();
            let ok = run_write(&handle, "CREATE (:Ping {t: 1})");
            let ms = t0.elapsed().as_secs_f64() * 1000.0;
            assert!(ok, "the small write must commit");
            lats.push(ms);
            std::thread::sleep(std::time::Duration::from_millis(5));
        }
        stop.store(true, Ordering::Relaxed);
        reader.join().expect("reader joins");

        lats.sort_by(|a, b| a.partial_cmp(b).unwrap());
        let mean = lats.iter().sum::<f64>() / lats.len() as f64;
        let p50 = lats[lats.len() / 2];
        let p95 = lats[(lats.len() * 95 / 100).min(lats.len() - 1)];
        let max = *lats.last().unwrap();
        println!(
            "  {label}: write latency mean={mean:7.1} ms  p50={p50:7.1} ms  p95={p95:7.1} ms  \
             max={max:7.1} ms  ({} heavy reads ran concurrently)",
            reads_done.load(Ordering::Relaxed),
        );
    }

    graphus_cypher::morsel::set_morsel_threads(1);
    shutdown(eng, handle);
    println!();
}

/// Like [`engine_seeded`] but with an explicit (typically SMALL relative to the working set) buffer-pool
/// page budget, so reads plus the writer's page growth force `ConcurrentBufferPool` eviction/victim sweeps —
/// the read+write contention regime `rmp` #575's wider off-thread fan-out first creates.
fn engine_seeded_pooled(
    reader_threads: usize,
    pool: usize,
    pool_pages: usize,
    cfg: SeedCfg,
) -> Engine {
    graphus_cypher::morsel::set_morsel_threads(pool);
    graphus_cypher::morsel::set_analytics_pool_threads(pool);
    let clock: Arc<dyn Clock + Send + Sync> = Arc::new(SharedClock::new(0));
    let metrics = Arc::new(graphus_server::metrics::Metrics::new());
    spawn_engine::<MemBlockDevice, MemLogSink, _>(
        std::sync::Arc::from("test"),
        move || {
            let device = MemBlockDevice::new(0);
            let wal = WalManager::create(MemLogSink::new())?;
            let mut store = RecordStore::create(device, wal, pool_pages, 1)?;
            seed_reco(&mut store, cfg);
            Ok(graphus_cypher::TxnCoordinator::new(store))
        },
        4096,
        256,
        reader_threads,
        metrics,
        clock,
        std::sync::Arc::new(graphus_server::txn_registry::TransactionRegistry::new()),
    )
    .expect("spawn threaded engine (explicit pool)")
}

/// `rmp` #583 (F1/F1b) + #584 — the first test to drive N concurrent OFF-THREAD fanned-out morsel readers
/// TOGETHER WITH a sustained concurrent writer, under a buffer pool smaller than the (growing) working set.
/// It exercises, together, three paths neither prior test covered at once:
///   * the `ConcurrentBufferPool` eviction / victim-sweep path under real read+write contention (`rmp` #359
///     — a contended sweep must fail CLOSED, never return a wrong/torn result);
///   * the group-commit drain with reads/opens interleaving the write batch (`rmp` #583 F1 — the drain must
///     stay bounded rather than starve the engine's top-of-loop maintenance); and
///   * off-thread reader-retirement release BETWEEN hardened batches during a sustained write storm
///     (`rmp` #583 F1b — a finished reader must not keep pinning the GC watermark for the whole storm).
///
/// Correctness oracle: the concurrent writer only creates DISJOINT `:Filler` nodes — it never touches the
/// `:User` FRIEND/PURCHASED graph the readers query — so every reader's `r3_fof3` over the ORIGINAL anchors
/// is invariant and MUST stay byte-identical to the serial reference computed over the seeded graph, with
/// zero read errors, while thousands of writes commit concurrently.
#[test]
fn concurrent_off_thread_readers_and_writer_under_bufpool_pressure() {
    let _lock = TEST_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    let cfg = SeedCfg {
        users: 2_000,
        products: 200,
        friend_deg: 10,
        purchase_deg: 6,
    };
    let pool = 8;
    // Comfortably above the peak concurrent pin count (so sweeps always find a victim → no spurious
    // fail-closed), but far below what the writer grows the store to — so eviction genuinely happens under
    // concurrent reads.
    let pool_pages = 4096;
    let eng = engine_seeded_pooled(pool, pool, pool_pages, cfg);
    let handle = eng.handle.clone();

    // Serial reference results (inline explicit reads — never dispatched off-thread) for a spread of anchors.
    graphus_cypher::morsel::set_morsel_threads(pool);
    let anchors: Arc<Vec<i64>> = Arc::new(vec![0, 1, 7, 13, 101, 499]);
    let refs: Arc<Vec<Vec<Vec<graphus_cypher::MaterializedValue>>>> = Arc::new(
        anchors
            .iter()
            .map(|&a| run_explicit(&handle, R3_FOF3, a))
            .collect(),
    );
    assert!(
        refs.iter().all(|r| !r.is_empty()),
        "every reference result must be non-empty (else the equivalence is vacuous)"
    );

    // A sustained concurrent writer: auto-commit CREATE of DISJOINT `:Filler` nodes — durable write commits
    // that drive the group-commit pipeline and grow the store past the pool — for the whole read-stress window.
    let stop = Arc::new(AtomicBool::new(false));
    let committed = Arc::new(AtomicUsize::new(0));
    let writer = {
        let h = handle.clone();
        let stop = stop.clone();
        let committed = committed.clone();
        std::thread::spawn(move || {
            let mut k = 0i64;
            while !stop.load(Ordering::Relaxed) {
                if run_write(&h, &format!("CREATE (:Filler {{id: {k}}})")) {
                    committed.fetch_add(1, Ordering::Relaxed);
                }
                k += 1;
            }
        })
    };

    // K concurrent off-thread readers, each hammering r3_fof3 over the anchors for many iterations. Every
    // result must be byte-identical to the serial reference and stream no error (run_auto panics on error).
    let n_readers = pool;
    let iters = 8usize;
    let readers: Vec<_> = (0..n_readers)
        .map(|w| {
            let h = handle.clone();
            let anchors = anchors.clone();
            let refs = refs.clone();
            std::thread::spawn(move || {
                for it in 0..iters {
                    let ai = (w + it) % anchors.len();
                    let got = run_auto(&h, R3_FOF3, anchors[ai]);
                    assert_eq!(
                        got, refs[ai],
                        "reader {w} iter {it} (anchor {}): an off-thread fanned-out read over the untouched \
                         :User graph must be byte-identical to the serial reference — the concurrent writes \
                         are disjoint :Filler nodes, so a mismatch means a torn read / bufpool race / lost SSI marker",
                        anchors[ai]
                    );
                }
            })
        })
        .collect();

    // Join ALL readers (each runs to completion or panics) BEFORE stopping the writer, so no reader thread
    // is left detached; then propagate the first reader panic, if any.
    let results: Vec<std::thread::Result<()>> = readers.into_iter().map(|r| r.join()).collect();
    stop.store(true, Ordering::Relaxed);
    writer.join().expect("writer thread joins");
    for r in results {
        if let Err(e) = r {
            std::panic::resume_unwind(e);
        }
    }

    assert!(
        committed.load(Ordering::Relaxed) > 0,
        "the concurrent writer must have committed durable writes during the read stress (else the test did \
         not actually exercise read+write concurrency)"
    );

    graphus_cypher::morsel::set_morsel_threads(1);
    shutdown(eng, handle);
}
