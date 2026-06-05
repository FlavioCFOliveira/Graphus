//! Wiring the WAL ordering rule into the buffer pool (`04-technical-design.md` §4.3, §4.9).
//!
//! The buffer pool owns a [`graphus_bufpool::WalRule`] it consults *before* writing any dirty
//! page home (on eviction or on an explicit flush): the log must be durable through the page's
//! `page_lsn` first. [`SharedWal`] is the shared, single-threaded handle to the [`WalManager`] —
//! the record store logs through it and the pool enforces ordering through it, over the *same*
//! manager, so the invariant holds on **every** write-home path.
//!
//! ## Ownership model
//!
//! This is the single-threaded storage core (`04 §3` — the concurrent latched pool is a separate
//! task), so the manager is shared with [`Rc`]`<`[`RefCell`]`<…>>`. The record store and the
//! pool's WAL rule each hold a [`SharedWal`] clone. The rule's
//! [`ensure_durable`](graphus_bufpool::WalRule::ensure_durable) borrows the manager only for the
//! duration of one `harden`; the store always *drops* its own WAL borrow before calling any pool
//! method that can trigger write-back, so the two borrows never overlap (this discipline is
//! upheld in [`crate::store`] and asserted by its crash-recovery tests).

use std::cell::RefCell;
use std::rc::Rc;

use graphus_bufpool::WalRule;
use graphus_core::Lsn;
use graphus_core::error::Result;
use graphus_wal::{LogSink, WalManager};

/// A single-threaded shared handle to the [`WalManager`], cloned by both the record store and the
/// buffer pool's WAL rule so they drive one log.
pub struct SharedWal<S: LogSink> {
    inner: Rc<RefCell<WalManager<S>>>,
}

impl<S: LogSink> std::fmt::Debug for SharedWal<S> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // `WalManager` is intentionally not `Debug` (it owns an opaque sink); surface just the
        // shared-handle reference count, which is what matters for the ownership model.
        f.debug_struct("SharedWal")
            .field("strong_count", &Rc::strong_count(&self.inner))
            .finish()
    }
}

impl<S: LogSink> Clone for SharedWal<S> {
    fn clone(&self) -> Self {
        Self {
            inner: Rc::clone(&self.inner),
        }
    }
}

impl<S: LogSink> SharedWal<S> {
    /// Wraps `wal` in a shared, single-threaded handle.
    #[must_use]
    pub fn new(wal: WalManager<S>) -> Self {
        Self {
            inner: Rc::new(RefCell::new(wal)),
        }
    }

    /// Borrows the manager for a closure. The borrow lives only for `f`; callers must not invoke
    /// buffer-pool write paths from within `f` (which would re-borrow through the WAL rule).
    pub fn with<R>(&self, f: impl FnOnce(&mut WalManager<S>) -> R) -> R {
        f(&mut self.inner.borrow_mut())
    }

    /// Consumes the handle and returns the inner manager.
    ///
    /// # Errors
    /// Returns the handle back (as `Err`) if other clones still exist.
    pub fn into_inner(self) -> std::result::Result<WalManager<S>, Self> {
        Rc::try_unwrap(self.inner)
            .map_or_else(|inner| Err(Self { inner }), |cell| Ok(cell.into_inner()))
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
        self.inner.borrow_mut().ensure_durable(up_to);
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
}
