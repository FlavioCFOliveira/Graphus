//! Loopback throughput micro-benchmarks for the `graphus-io` async layer.
//!
//! This benchmarks the **epoll/kqueue baseline** (`04 §9.1`) — the path that runs on every Tier-1
//! target — over loopback: a TCP round-trip, a UDS round-trip, and a batch of `fdatasync`s through
//! the dedicated [`graphus_io::FsyncPool`]. It is the AC's "benchmarked vs the epoll/kqueue
//! baseline" anchor.
//!
//! ## How to compare io_uring vs epoll/kqueue (measure-to-decide, honest deferral)
//! A full A/B of io_uring vs epoll needs (a) a capable Linux kernel and (b) the io_uring submission
//! path wired (currently a documented stub — see `graphus_io::backend`). The intended comparison,
//! once submission lands, is to add a sibling benchmark group that drives the **same** loopback and
//! fsync workloads through the io_uring backend and compare on identical hardware/toolchain, using
//! Criterion baselines (`--save-baseline epoll` then `--baseline epoll`). Until then this file
//! measures the baseline so there is a recorded reference point; io_uring numbers are to be gathered
//! on capable hardware and compared against this saved baseline. Improvements inside Criterion's
//! noise band are ignored (project rule: measure to decide).
//!
//! Run with: `cargo bench -p graphus-io`. Report alongside hardware (`lscpu`), kernel
//! (`uname -r`), and toolchain (`rustc --version`).

use std::hint::black_box;
use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use criterion::{Criterion, criterion_group, criterion_main};
use graphus_io::FsyncPool;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::runtime::Runtime;

/// A 4 KiB payload — representative of a small Bolt/REST message.
const PAYLOAD: usize = 4096;

fn rt() -> Runtime {
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
        .expect("build runtime")
}

/// One TCP loopback request/response: client sends `PAYLOAD` bytes, server echoes them back.
async fn tcp_round_trip(addr: SocketAddr, buf: &[u8]) {
    let mut client = tokio::net::TcpStream::connect(addr).await.expect("connect");
    client.set_nodelay(true).expect("nodelay");
    client.write_all(buf).await.expect("write");
    let mut echoed = vec![0u8; buf.len()];
    client.read_exact(&mut echoed).await.expect("read");
    black_box(&echoed);
}

fn bench_tcp_loopback(c: &mut Criterion) {
    let rt = rt();
    let payload = vec![0xABu8; PAYLOAD];

    // A persistent echo server accepting connections for the duration of the bench.
    let (addr, _server) = rt.block_on(async {
        let listener = tokio::net::TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");
        let server = tokio::spawn(async move {
            loop {
                let Ok((mut conn, _)) = listener.accept().await else {
                    break;
                };
                conn.set_nodelay(true).ok();
                tokio::spawn(async move {
                    let mut buf = vec![0u8; PAYLOAD];
                    while conn.read_exact(&mut buf).await.is_ok() {
                        if conn.write_all(&buf).await.is_err() {
                            break;
                        }
                    }
                });
            }
        });
        (addr, server)
    });

    let mut group = c.benchmark_group("loopback");
    group.throughput(criterion::Throughput::Bytes(PAYLOAD as u64));
    group.bench_function("tcp_round_trip_4k", |b| {
        b.to_async(&rt)
            .iter(|| tcp_round_trip(black_box(addr), black_box(&payload)));
    });
    group.finish();
}

fn bench_uds_loopback(c: &mut Criterion) {
    let rt = rt();
    let payload = vec![0xCDu8; PAYLOAD];
    let path = std::env::temp_dir().join(format!("graphus-bench-{}.sock", std::process::id()));

    rt.block_on(async {
        let _ = std::fs::remove_file(&path);
        let listener = tokio::net::UnixListener::bind(&path).expect("bind uds");
        // Detached echo server for the duration of the bench; the runtime (and process exit) reaps
        // it. We bind the handle to `_` so the async block yields `()` rather than a `JoinHandle`
        // (clippy::async_yields_async).
        let _server = tokio::spawn(async move {
            loop {
                let Ok((mut conn, _)) = listener.accept().await else {
                    break;
                };
                tokio::spawn(async move {
                    let mut buf = vec![0u8; PAYLOAD];
                    while conn.read_exact(&mut buf).await.is_ok() {
                        if conn.write_all(&buf).await.is_err() {
                            break;
                        }
                    }
                });
            }
        });
    });

    let mut group = c.benchmark_group("loopback");
    group.throughput(criterion::Throughput::Bytes(PAYLOAD as u64));
    let bench_path = path.clone();
    group.bench_function("uds_round_trip_4k", |b| {
        b.to_async(&rt).iter(|| {
            let path = bench_path.clone();
            let payload = &payload;
            async move {
                let mut client = tokio::net::UnixStream::connect(&path)
                    .await
                    .expect("connect");
                client.write_all(payload).await.expect("write");
                let mut echoed = vec![0u8; payload.len()];
                client.read_exact(&mut echoed).await.expect("read");
                black_box(&echoed);
            }
        });
    });
    group.finish();
    let _ = std::fs::remove_file(&path);
}

fn bench_fsync_pool(c: &mut Criterion) {
    let rt = rt();
    let pool = Arc::new(FsyncPool::new(4, 64));

    // A temp file synced through the pool; fdatasync of an unchanged file is cheap but still
    // exercises the offload path (submit → dedicated thread → oneshot completion).
    let path = std::env::temp_dir().join(format!("graphus-bench-fsync-{}.tmp", std::process::id()));
    let file = Arc::new(std::fs::File::create(&path).expect("create"));

    let mut group = c.benchmark_group("fsync_offload");
    group.bench_function("fdatasync_via_pool", |b| {
        b.to_async(&rt).iter(|| {
            let pool = Arc::clone(&pool);
            let file = Arc::clone(&file);
            async move {
                pool.sync_data(file).await.expect("fdatasync");
            }
        });
    });
    group.finish();
    let _ = std::fs::remove_file(&path);
}

criterion_group! {
    name = benches;
    // Keep wall time modest in CI; Criterion still warms up and reports variance honestly.
    config = Criterion::default()
        .warm_up_time(Duration::from_millis(500))
        .measurement_time(Duration::from_secs(2));
    targets = bench_tcp_loopback, bench_uds_loopback, bench_fsync_pool
}
criterion_main!(benches);
