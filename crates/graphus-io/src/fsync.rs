//! Durability-sync offload: a dedicated blocking thread pool for `fsync`/`fdatasync`.
//!
//! **The hard rule (`04 §9.1`):** durability syscalls (`fsync`/`fdatasync`) must never run on a
//! Tokio runtime worker. A stalled disk would otherwise block a work-stealing worker and starve
//! query execution and other sessions. This module funnels every sync to a small pool of
//! **dedicated OS threads** and exposes it as an `async fn` that submits the job and awaits its
//! completion on a `oneshot`.
//!
//! Why a hand-rolled pool rather than `tokio::task::spawn_blocking`? Two reasons grounded in the
//! design:
//! - **Bounded, owned threads.** `spawn_blocking` shares Tokio's general blocking pool (default up
//!   to 512 threads) with every other blocking call in the process. Durability is on the latency-
//!   critical commit path (`04 §4.2` group commit) and we want a *small, dedicated, bounded* set of
//!   sync threads we can size and reason about, isolated from unrelated blocking work.
//! - **Explicit shutdown.** Graceful shutdown (`04 §9.4`) flushes and `fdatasync`s the WAL; owning
//!   the threads lets us drain and join them deterministically.
//!
//! The pool is generic over *what* gets synced via the [`SyncTarget`] trait, so it is unit-testable
//! without a real file (the tests drive both `std::fs::File` and an in-memory counter target).

use std::io;
use std::sync::Arc;
use std::sync::mpsc::{Receiver, SyncSender};
use std::thread::JoinHandle;

use tokio::sync::oneshot;

/// Something whose data/metadata can be made durable with a blocking syscall.
///
/// Implemented for [`std::fs::File`] (and `Arc<File>`, so the same handle can be shared across the
/// async caller and the sync thread without dup'ing the fd). `sync_data` maps to `fdatasync(2)`
/// (data + the minimum metadata to read it back) and `sync_all` to `fsync(2)` (data + all
/// metadata), matching the [`crate::BlockDevice`] vocabulary.
pub trait SyncTarget: Send + 'static {
    /// Flushes file data and the minimum metadata needed to read it back (`fdatasync`).
    ///
    /// # Errors
    /// Returns the underlying `std::io::Error`. Per `04 §4.9` (fsyncgate), the *caller* on the WAL
    /// path must treat any such error as unrecoverable (PANIC), because a failed fsync may have
    /// cleared the kernel's dirty-page error state; this pool only reports the error faithfully.
    fn sync_data(&self) -> io::Result<()>;

    /// Flushes file data and all metadata (`fsync`).
    ///
    /// # Errors
    /// As [`SyncTarget::sync_data`].
    fn sync_all(&self) -> io::Result<()>;
}

impl SyncTarget for std::fs::File {
    fn sync_data(&self) -> io::Result<()> {
        std::fs::File::sync_data(self)
    }
    fn sync_all(&self) -> io::Result<()> {
        std::fs::File::sync_all(self)
    }
}

impl SyncTarget for Arc<std::fs::File> {
    fn sync_data(&self) -> io::Result<()> {
        std::fs::File::sync_data(self)
    }
    fn sync_all(&self) -> io::Result<()> {
        std::fs::File::sync_all(self)
    }
}

/// A unit of work for a sync thread: run the boxed sync, then report the result back.
///
/// Boxing the closure keeps the pool decoupled from the target type (the channel carries one job
/// type regardless of what is being synced).
type Job = Box<dyn FnOnce() + Send + 'static>;

/// A dedicated, bounded pool of OS threads that perform durability syncs off the async runtime.
///
/// Clone-free shared use is via an [`Arc<FsyncPool>`]; the pool is `Send + Sync`. Dropping the pool
/// closes the job queue and joins every worker thread (so a clean shutdown drains in-flight syncs).
#[derive(Debug)]
pub struct FsyncPool {
    /// Bounded sender to the shared job queue. Bounded so a flood of sync requests exerts
    /// backpressure on submitters instead of growing unboundedly (`04 §9.3` — no unbounded queues
    /// on a production path).
    sender: Option<SyncSender<Job>>,
    /// Worker thread handles, joined on drop.
    workers: Vec<JoinHandle<()>>,
    /// Number of worker threads (for observability / tests).
    thread_count: usize,
}

impl FsyncPool {
    /// Creates a pool with `threads` dedicated worker threads and a job queue of capacity
    /// `queue_capacity`.
    ///
    /// `threads` is clamped to at least 1. The queue is bounded: when full, [`FsyncPool::sync_data`]
    /// / [`FsyncPool::sync_all`] park the *calling task* (never a runtime worker thread — see the
    /// submit path) until a slot frees, which is the intended backpressure.
    ///
    /// # Panics
    /// Panics if an OS thread cannot be spawned (an unrecoverable environment failure at startup).
    #[must_use]
    pub fn new(threads: usize, queue_capacity: usize) -> Self {
        let threads = threads.max(1);
        let queue_capacity = queue_capacity.max(1);
        let (sender, receiver) = std::sync::mpsc::sync_channel::<Job>(queue_capacity);
        // The receiver is shared by all workers behind a mutex; each worker pulls the next job. A
        // single mutex on the receiver is fine: the critical section is just a channel `recv`, far
        // cheaper than the syscall the job will run, so it is never the bottleneck.
        let receiver = Arc::new(std::sync::Mutex::new(receiver));
        let mut workers = Vec::with_capacity(threads);
        for i in 0..threads {
            let receiver: Arc<std::sync::Mutex<Receiver<Job>>> = Arc::clone(&receiver);
            let handle = std::thread::Builder::new()
                .name(format!("graphus-fsync-{i}"))
                .spawn(move || worker_loop(&receiver))
                .expect("spawn fsync worker thread");
            workers.push(handle);
        }
        Self {
            sender: Some(sender),
            workers,
            thread_count: threads,
        }
    }

    /// The number of dedicated worker threads in this pool.
    #[must_use]
    pub fn thread_count(&self) -> usize {
        self.thread_count
    }

    /// Submits an `fdatasync` for `target` to a worker thread and awaits its completion.
    ///
    /// The blocking syscall runs on a dedicated pool thread, never on the awaiting runtime worker
    /// (`04 §9.1`). The `target` is moved onto the worker thread; share an fd with
    /// `Arc<std::fs::File>` if the caller must retain it.
    ///
    /// # Errors
    /// Returns the sync's `std::io::Error`, or an [`io::ErrorKind::Other`] if the pool was shut
    /// down before the job could run (the worker dropped the result channel).
    pub async fn sync_data<T: SyncTarget>(&self, target: T) -> io::Result<()> {
        self.submit(move || target.sync_data()).await
    }

    /// Submits an `fsync` for `target` to a worker thread and awaits its completion.
    ///
    /// # Errors
    /// As [`FsyncPool::sync_data`].
    pub async fn sync_all<T: SyncTarget>(&self, target: T) -> io::Result<()> {
        self.submit(move || target.sync_all()).await
    }

    /// Core submit path shared by `sync_data`/`sync_all`.
    ///
    /// Builds a job that runs `op` on a worker thread and sends the result back over a `oneshot`,
    /// then awaits that `oneshot`. The bounded `SyncSender::send` can block when the queue is full;
    /// we therefore must not call it directly on a runtime worker. We don't: the only blocking that
    /// can happen here is the channel being full, and we keep the queue sized for the workload; a
    /// fuller design (offloading the send too) is unnecessary because the queue capacity is the
    /// admission bound. The `oneshot` await is fully async and cancellation-safe.
    async fn submit<F>(&self, op: F) -> io::Result<()>
    where
        F: FnOnce() -> io::Result<()> + Send + 'static,
    {
        let (tx, rx) = oneshot::channel::<io::Result<()>>();
        let job: Job = Box::new(move || {
            // If the receiver was dropped (caller's future cancelled), the result is discarded;
            // the sync still ran to completion, which is correct for durability (we never want to
            // *skip* a sync just because the awaiter went away).
            let _ = tx.send(op());
        });
        let sender = self
            .sender
            .as_ref()
            .expect("sender present until drop")
            .clone();
        // `try_send` first so a non-full queue never blocks; on `Full`, fall back to a blocking send
        // performed inside `spawn_blocking` so the runtime worker is never parked on the channel.
        match sender.try_send(job) {
            Ok(()) => {}
            Err(std::sync::mpsc::TrySendError::Full(job)) => {
                // Park on the bounded queue without blocking a runtime worker: hand the blocking
                // `send` to Tokio's blocking pool. This only happens under sync backpressure.
                tokio::task::spawn_blocking(move || sender.send(job))
                    .await
                    .map_err(|e| io::Error::other(format!("fsync submit join: {e}")))?
                    .map_err(|_| io::Error::other("fsync pool closed"))?;
            }
            Err(std::sync::mpsc::TrySendError::Disconnected(_)) => {
                return Err(io::Error::other("fsync pool closed"));
            }
        }
        rx.await
            .map_err(|_| io::Error::other("fsync pool dropped the job before completion"))?
    }
}

impl Drop for FsyncPool {
    fn drop(&mut self) {
        // Close the queue: workers see `Disconnected` once the queue drains and exit their loops.
        self.sender = None;
        // Join every worker so in-flight syncs finish before the pool (and any file handles still
        // owned by queued jobs) are torn down — graceful-shutdown hygiene (`04 §9.4`).
        for handle in self.workers.drain(..) {
            let _ = handle.join();
        }
    }
}

/// A worker thread body: pull jobs off the shared queue and run them until the queue is closed.
fn worker_loop(receiver: &Arc<std::sync::Mutex<Receiver<Job>>>) {
    loop {
        // Scope the lock so it is released *before* the (potentially slow) job runs — otherwise the
        // pool would serialize to a single concurrent sync. The lock guards only the `recv`.
        let job = {
            let guard = receiver.lock().expect("fsync receiver mutex poisoned");
            guard.recv()
        };
        match job {
            Ok(job) => job(),
            // Queue closed and drained: the pool is shutting down.
            Err(_) => break,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// An in-memory sync target that counts how many times it was synced and how many syncs ran
    /// concurrently (to prove the pool actually parallelizes across its threads).
    struct CountingTarget {
        count: Arc<AtomicUsize>,
        in_flight: Arc<AtomicUsize>,
        max_in_flight: Arc<AtomicUsize>,
    }

    impl SyncTarget for CountingTarget {
        fn sync_data(&self) -> io::Result<()> {
            let now = self.in_flight.fetch_add(1, Ordering::SeqCst) + 1;
            self.max_in_flight.fetch_max(now, Ordering::SeqCst);
            // Hold the "syscall" briefly so concurrent submissions overlap on multiple threads.
            std::thread::sleep(std::time::Duration::from_millis(20));
            self.in_flight.fetch_sub(1, Ordering::SeqCst);
            self.count.fetch_add(1, Ordering::SeqCst);
            Ok(())
        }
        fn sync_all(&self) -> io::Result<()> {
            self.sync_data()
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn many_concurrent_syncs_all_complete() {
        let pool = Arc::new(FsyncPool::new(4, 64));
        assert_eq!(pool.thread_count(), 4);

        let count = Arc::new(AtomicUsize::new(0));
        let in_flight = Arc::new(AtomicUsize::new(0));
        let max_in_flight = Arc::new(AtomicUsize::new(0));

        let mut handles = Vec::new();
        for _ in 0..32 {
            let pool = Arc::clone(&pool);
            let target = CountingTarget {
                count: Arc::clone(&count),
                in_flight: Arc::clone(&in_flight),
                max_in_flight: Arc::clone(&max_in_flight),
            };
            handles.push(tokio::spawn(async move { pool.sync_data(target).await }));
        }
        for h in handles {
            h.await.expect("join").expect("sync ok");
        }

        assert_eq!(count.load(Ordering::SeqCst), 32, "every sync must complete");
        // With 4 threads and 32 overlapping jobs, more than one must have run at once.
        assert!(
            max_in_flight.load(Ordering::SeqCst) > 1,
            "pool should run syncs concurrently across its threads (saw max {})",
            max_in_flight.load(Ordering::SeqCst)
        );
        // And it must never exceed the bounded thread count.
        assert!(
            max_in_flight.load(Ordering::SeqCst) <= 4,
            "concurrency must be bounded by the thread count"
        );
    }

    #[tokio::test]
    async fn syncs_a_real_file() {
        use std::io::Write;
        let dir = std::env::temp_dir();
        let path = dir.join(format!("graphus-fsync-{}.tmp", std::process::id()));
        let mut file = std::fs::File::create(&path).expect("create");
        file.write_all(b"durable bytes").expect("write");
        let file = Arc::new(file);

        let pool = FsyncPool::new(1, 4);
        // fdatasync then fsync the same shared handle off the runtime.
        pool.sync_data(Arc::clone(&file)).await.expect("fdatasync");
        pool.sync_all(Arc::clone(&file)).await.expect("fsync");

        std::fs::remove_file(&path).ok();
    }

    #[tokio::test]
    async fn pool_bounds_its_threads_to_at_least_one() {
        // A request for zero threads is clamped to one (never a zero-thread pool that deadlocks).
        let pool = FsyncPool::new(0, 1);
        assert_eq!(pool.thread_count(), 1);
        let count = Arc::new(AtomicUsize::new(0));
        let target = CountingTarget {
            count: Arc::clone(&count),
            in_flight: Arc::new(AtomicUsize::new(0)),
            max_in_flight: Arc::new(AtomicUsize::new(0)),
        };
        pool.sync_data(target).await.expect("sync ok");
        assert_eq!(count.load(Ordering::SeqCst), 1);
    }
}
