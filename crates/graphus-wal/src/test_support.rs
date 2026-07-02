//! Shared test-only helpers for `graphus-wal` (`rmp` #525).

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use graphus_core::error::Result;

use crate::sink::LogSink;

/// A [`LogSink`] wrapper that records the **largest single physical read** any `read_durable` /
/// `read_bounded` produced (`into.len()`) **and** counts every [`sync`](LogSink::sync)
/// (`fdatasync`) call, forwarding every operation to the wrapped sink otherwise.
///
/// The read counter lets a test prove the recovery reads stay bounded by the RETAINED window and never
/// allocate a buffer sized by the log's whole lifetime (`rmp` #525): reverting the recovery-path
/// `max(reclaimed_floor())` bound makes those reads start at the header floor, spiking the counter to
/// the lifetime length and failing the gating assertion.
///
/// The sync counter is the **strace-free group-commit proof** (`rmp` #528): a batch of `K` committers
/// that PREPARE (`commit_at_no_sync`) and then issue ONE [`flush`](crate::WalManager::flush) must show
/// `sync_count == 1`, not `K` — the exact `fdatasync`-coalescing the group-commit path exists to
/// deliver. A `sync` on an EMPTY pending buffer still increments this counter, but a production
/// [`FileLogSink`](crate::FileLogSink) skips the real syscall in that case, so a read-only batch costs
/// zero real `fdatasync`s (asserted separately at the sink layer).
pub(crate) struct CountingSink<S: LogSink> {
    inner: S,
    max_read: Arc<AtomicU64>,
    sync_count: Arc<AtomicU64>,
}

impl<S: LogSink> CountingSink<S> {
    /// Wraps `inner`, publishing its largest observed read into the shared `max_read` counter and its
    /// `sync` (`fdatasync`) call count into the shared `sync_count` counter.
    pub(crate) fn new(inner: S, max_read: Arc<AtomicU64>, sync_count: Arc<AtomicU64>) -> Self {
        Self {
            inner,
            max_read,
            sync_count,
        }
    }

    fn record(&self, n: usize) {
        self.max_read.fetch_max(n as u64, Ordering::SeqCst);
    }
}

impl<S: LogSink + Clone> Clone for CountingSink<S> {
    fn clone(&self) -> Self {
        // Clones share the SAME counters (an `Arc`), so a `WalManager::open` on a cloned sink still
        // publishes its reads/syncs to the test's observation point.
        Self {
            inner: self.inner.clone(),
            max_read: Arc::clone(&self.max_read),
            sync_count: Arc::clone(&self.sync_count),
        }
    }
}

impl<S: LogSink> LogSink for CountingSink<S> {
    fn append(&mut self, bytes: &[u8]) {
        self.inner.append(bytes);
    }

    fn sync(&mut self) -> Result<()> {
        self.sync_count.fetch_add(1, Ordering::SeqCst);
        self.inner.sync()
    }

    fn durable_len(&self) -> u64 {
        self.inner.durable_len()
    }

    fn buffered_len(&self) -> u64 {
        self.inner.buffered_len()
    }

    fn read_durable(&self, from: u64, into: &mut Vec<u8>) -> Result<()> {
        self.inner.read_durable(from, into)?;
        self.record(into.len());
        Ok(())
    }

    fn read_bounded(&self, from: u64, to: u64, into: &mut Vec<u8>) -> Result<()> {
        self.inner.read_bounded(from, to, into)?;
        self.record(into.len());
        Ok(())
    }

    fn reclaim(&mut self, from: u64, up_to: u64) -> Result<()> {
        self.inner.reclaim(from, up_to)
    }

    fn reclaimed_floor(&self) -> u64 {
        self.inner.reclaimed_floor()
    }
}
