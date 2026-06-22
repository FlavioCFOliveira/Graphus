//! Wiring the WAL ordering rule into the buffer pool (`04-technical-design.md` §4.3, §4.9).
//!
//! The buffer pool owns a [`graphus_bufpool::WalRule`] it consults *before* writing any dirty
//! page home (on eviction or on an explicit flush): the log must be durable through the page's
//! `page_lsn` first. [`SharedWal`] is the shared handle to the [`WalManager`] — the record store
//! logs through it and the pool enforces ordering through it, over the *same* manager, so the
//! invariant holds on **every** write-home path.
//!
//! ## Ownership model (`rmp` #337, Slice 1)
//!
//! The storage core now builds on the concurrent, latched buffer pool
//! ([`graphus_bufpool::ConcurrentBufferPool`]), whose every method takes `&self` and which is
//! shared across threads behind an [`Arc`]. For the pool's WAL rule to live inside that
//! `Send + Sync` pool, the manager handle must itself be `Send + Sync`, so it is held with
//! [`Arc`]`<`[`Mutex`]`<…>>` (previously `Rc<RefCell<…>>`, when the store built on the
//! single-threaded pool). The record store and the pool's WAL rule each hold a [`SharedWal`]
//! clone over the *same* manager.
//!
//! ## Lock ordering — no WAL-lock held across a pool call (`rmp` #337, Slice 1)
//!
//! The concurrent pool serializes its own device and WAL-rule access behind internal `Mutex`es,
//! and its documented lock order is **shard → frame-latch → device/WAL**. The store's own
//! `SharedWal` lock and the pool's internal `Mutex<W>` wrap the **same** [`WalManager`] via this
//! [`Arc`]. To keep the two from forming a wait cycle (and, single-threaded, to avoid a
//! non-reentrant self-deadlock), the discipline is strict and absolute:
//!
//! > **The store MUST NOT hold its own `SharedWal` lock while calling any buffer-pool method that
//! > can trigger a write-back** (eviction / flush), because that write-back re-enters
//! > [`ensure_durable`](WalRule::ensure_durable) and would try to take the WAL lock again.
//!
//! Every write path in [`crate::store`] already *drops* its WAL borrow (the `with` closure ends)
//! before calling `page_mut`/`fetch`/`flush`. The one path where `WalManager::rollback` *itself*
//! holds the manager lock while driving page application — live transaction rollback — is handled
//! in [`crate::store::RecordStore::rollback`] by **recording** the compensating page images during
//! the locked phase and **replaying** them into the pool only *after* the WAL lock is released (so
//! an eviction during replay takes the WAL lock with no holder). See that method for the full
//! rationale; the `rmp` #337 audit proved that without this split a rollback whose working set
//! exceeds the pool capacity deadlocks (it panicked under the old `RefCell` handle).

use std::sync::{Arc, Mutex};

use graphus_bufpool::WalRule;
use graphus_core::Lsn;
use graphus_core::error::Result;
use graphus_wal::{LogSink, WalManager};

/// A shared, `Send + Sync` handle to the [`WalManager`], cloned by both the record store and the
/// buffer pool's WAL rule so they drive one log.
///
/// Held with [`Arc`]`<`[`Mutex`]`<…>>` so it can live inside the `Send + Sync`
/// [`graphus_bufpool::ConcurrentBufferPool`] the storage core now builds on (`rmp` #337, Slice 1).
pub struct SharedWal<S: LogSink> {
    inner: Arc<Mutex<WalManager<S>>>,
}

impl<S: LogSink> std::fmt::Debug for SharedWal<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // `WalManager` is intentionally not `Debug` (it owns an opaque sink); surface just the
        // shared-handle reference count, which is what matters for the ownership model.
        f.debug_struct("SharedWal")
            .field("strong_count", &Arc::strong_count(&self.inner))
            .finish()
    }
}

impl<S: LogSink> Clone for SharedWal<S> {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
        }
    }
}

impl<S: LogSink> SharedWal<S> {
    /// Wraps `wal` in a shared, `Send + Sync` handle.
    #[must_use]
    pub fn new(wal: WalManager<S>) -> Self {
        Self {
            inner: Arc::new(Mutex::new(wal)),
        }
    }

    /// Borrows the manager for a closure. The lock is held only for `f`; callers must not invoke
    /// buffer-pool write paths from within `f` (which would re-lock through the WAL rule and
    /// deadlock — see the module-level lock-ordering note).
    ///
    /// A poisoned lock is recovered rather than re-panicked: the manager's own durability invariant
    /// is upheld by ARIES recovery, and wedging every later WAL access on a single prior panic would
    /// be an availability failure under extreme load (mirrors the buffer pool's `unwrap_lock`).
    pub fn with<R>(&self, f: impl FnOnce(&mut WalManager<S>) -> R) -> R {
        let mut guard = self
            .inner
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        f(&mut guard)
    }

    /// Consumes the handle and returns the inner manager.
    ///
    /// # Errors
    /// Returns the handle back (as `Err`) if other clones still exist.
    pub fn into_inner(self) -> std::result::Result<WalManager<S>, Self> {
        Arc::try_unwrap(self.inner).map_or_else(
            |inner| Err(Self { inner }),
            |cell| {
                Ok(cell
                    .into_inner()
                    .unwrap_or_else(std::sync::PoisonError::into_inner))
            },
        )
    }
}

impl<S: LogSink> WalRule for SharedWal<S> {
    /// Hardens the log through `up_to` before the pool writes a page home
    /// (`WalManager::ensure_durable`, the WAL rule of `04 §4.3`).
    ///
    /// # Panics
    /// Panics (controlled abort) if the durability `fdatasync` fails (`04 §4.9`); that inherent
    /// method never returns an error, so this rule always reports `Ok`.
    fn ensure_durable(&mut self, up_to: Lsn) -> Result<()> {
        self.with(|w| w.ensure_durable(up_to));
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use graphus_core::{PageId, TxnId};
    use graphus_wal::MemLogSink;

    #[test]
    fn rule_hardens_through_the_page_lsn() {
        let wal = WalManager::create(MemLogSink::new()).unwrap();
        let mut shared = SharedWal::new(wal);

        let u = shared.with(|w| {
            w.begin(TxnId(1));
            w.log_update(TxnId(1), PageId(0), b"r".to_vec(), b"u".to_vec())
        });
        // The update is appended but not durable yet.
        assert!(shared.with(|w| w.durable_len()) <= u.0);
        // The pool's rule fires: the log is hardened through the page's lsn.
        shared.ensure_durable(u).unwrap();
        assert!(shared.with(|w| w.durable_len()) > u.0);
    }

    #[test]
    fn into_inner_recovers_the_manager_when_unique() {
        let wal = WalManager::create(MemLogSink::new()).unwrap();
        let shared = SharedWal::new(wal);
        assert!(shared.into_inner().is_ok());
    }

    #[test]
    fn into_inner_fails_while_a_clone_is_outstanding() {
        let wal = WalManager::create(MemLogSink::new()).unwrap();
        let shared = SharedWal::new(wal);
        let _clone = shared.clone();
        assert!(shared.into_inner().is_err());
    }

    /// `rmp` #337, Slice 1: the migrated handle must be `Send + Sync` so it can live inside the
    /// `Send + Sync` concurrent buffer pool. A compile-time assertion (no runtime body needed).
    #[test]
    fn shared_wal_is_send_and_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<SharedWal<MemLogSink>>();
    }
}
