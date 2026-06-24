//! rmp #363 — the Tokio runtime's blocking-thread budget must be derived from
//! `admission.max_connections`, so that more than 512 concurrent Bolt sessions (each pinned to one
//! `spawn_blocking` task for its whole lifetime) can all be admitted without the runtime starving.
//!
//! Before this fix the binary used `#[tokio::main]`, whose default `max_blocking_threads` is 512.
//! With `max_connections` defaulting to 1024 (and the sample config at 4096), the 513th session's
//! `spawn_blocking` would queue forever — a silent hang under load, and a starvation of the REST /
//! engine-bridge / catalog-persistence work that shares the same pool.
//!
//! These tests are deterministic and fast: they build the runtime exactly as `main.rs` does (the
//! budget derived via `AdmissionConfig::blocking_thread_budget`) and prove that a number of
//! mutually-blocking tasks **well beyond 512** all run concurrently. Each task parks on a
//! `std::sync::Barrier` that only releases once *every* task has occupied a blocking thread — so a
//! pool capped at 512 would deadlock (the 513th task never arrives at the barrier) and the bounded
//! timeout would fire, turning a regression into a fast, clear failure instead of a hung suite.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use graphus_server::ServerConfig;

/// Builds the runtime exactly as `graphus-server`'s `main` does: a multi-thread runtime whose
/// `max_blocking_threads` is derived from the config's `max_connections`. Kept in lock-step with
/// `main::build_runtime` (rmp #363) — if that derivation changes, this must too.
fn build_runtime(config: &ServerConfig) -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .max_blocking_threads(config.admission.blocking_thread_budget())
        .build()
        .expect("INVARIANT: a multi-thread runtime with a positive blocking budget always builds")
}

/// A loaded default config with the connection cap set to `max_connections`. UDS is enabled so the
/// config is valid without TLS/JWT, matching the other listener tests; the field is public, so we set
/// it directly rather than round-tripping through the env overlay.
fn config_with_max_connections(max_connections: usize) -> ServerConfig {
    let mut config = ServerConfig::load(None).expect("default config must load");
    config.uds_path = Some(std::path::PathBuf::from("graphus-test.sock"));
    config.admission.max_connections = max_connections;
    config
}

/// Drives `count` mutually-blocking tasks on `runtime` and asserts they all complete within a bounded
/// timeout. Each task waits on a shared `std::sync::Barrier(count)`, so it occupies its blocking
/// thread until *every* peer has also reached the barrier — genuine simultaneous occupancy of `count`
/// blocking threads. If the pool is smaller than `count`, the barrier can never release and the
/// timeout fires (a regression fails fast instead of hanging).
fn assert_all_blocking_tasks_run_concurrently(runtime: &tokio::runtime::Runtime, count: usize) {
    runtime.block_on(async move {
        let barrier = Arc::new(std::sync::Barrier::new(count));
        let completed = Arc::new(AtomicUsize::new(0));

        let mut handles = Vec::with_capacity(count);
        for _ in 0..count {
            let barrier = Arc::clone(&barrier);
            let completed = Arc::clone(&completed);
            handles.push(tokio::task::spawn_blocking(move || {
                // A blocking park, exactly the shape a long-lived Bolt session has: the thread is
                // held for the session's lifetime. The barrier releases only when all `count` tasks
                // are simultaneously parked here, proving the pool seats them all at once.
                barrier.wait();
                completed.fetch_add(1, Ordering::SeqCst);
            }));
        }

        // 30 s is generous slack for CI; the work itself is sub-millisecond once the barrier releases.
        // A timeout means the blocking pool starved past 512 (the rmp #363 regression).
        let all = join_all(handles);
        tokio::time::timeout(Duration::from_secs(30), all)
            .await
            .unwrap_or_else(|_| {
                panic!(
                    "all {count} blocking tasks must run concurrently: a timeout here means the \
                     blocking pool starved (rmp #363 regression — likely a fallback to Tokio's 512 \
                     default)"
                )
            });

        assert_eq!(
            completed.load(Ordering::SeqCst),
            count,
            "every one of the {count} blocking tasks must have run to completion"
        );
    });
}

/// The headline AC (rmp #363): with `max_connections = 2000`, the built runtime lets **2000**
/// mutually-blocking tasks all run at once — impossible with the old 512-capped default pool.
#[test]
fn runtime_admits_far_more_than_512_concurrent_blocking_tasks() {
    const MAX_CONNECTIONS: usize = 2000;

    let config = config_with_max_connections(MAX_CONNECTIONS);
    // The derived budget must seat every simultaneous session with headroom; this is what makes the
    // run below succeed rather than deadlock.
    let budget = config.admission.blocking_thread_budget();
    assert!(
        budget >= MAX_CONNECTIONS,
        "blocking budget {budget} must seat all {MAX_CONNECTIONS} simultaneous sessions"
    );

    let runtime = build_runtime(&config);
    assert_all_blocking_tasks_run_concurrently(&runtime, MAX_CONNECTIONS);
}

/// A tighter variant just past the 512 boundary (600 tasks): same proof, cheaper — guards
/// specifically the off-by-one cliff at Tokio's historical 512 default.
#[test]
fn runtime_admits_just_past_the_512_boundary() {
    const TASKS: usize = 600;

    let config = config_with_max_connections(TASKS);
    assert!(config.admission.blocking_thread_budget() >= TASKS);

    let runtime = build_runtime(&config);
    assert_all_blocking_tasks_run_concurrently(&runtime, TASKS);
}

/// Awaits a batch of `JoinHandle`s in order, propagating a panic if any task panicked. Kept local to
/// avoid a dev-dependency on `futures` just for `join_all`.
async fn join_all<T>(handles: Vec<tokio::task::JoinHandle<T>>) -> Vec<T> {
    let mut out = Vec::with_capacity(handles.len());
    for h in handles {
        out.push(h.await.expect("a blocking task panicked"));
    }
    out
}
