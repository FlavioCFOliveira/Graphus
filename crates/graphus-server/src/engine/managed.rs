//! The **one** lifecycle guard both connectivity seams apply to a client-managed transaction
//! (`rmp` task #957) — the single place `TERMINATE TRANSACTIONS` (`rmp` #637) is honoured.
//!
//! # Why this module exists
//!
//! A client-managed transaction is the same three values on every interface: the engine it lives on
//! ([`EngineHandle`]), its ticket there ([`TxTicket`]), and its entry in the server-wide live-transaction
//! registry ([`TxnGuard`], which carries the `TERMINATE TRANSACTIONS` flag). Both seams held those three
//! values and each wrote its **own** copy of the termination rule — and the copies diverged: the Bolt
//! seam refused to commit a terminated transaction while the REST seam had no check on its commit path
//! at all, so an operator who terminated a REST transaction was told it had been stopped and it
//! nevertheless committed. Adding a second hand-written check would only invite a third.
//!
//! So the rule is stated **once**, here, and every seam resumes/commits/rolls back through
//! [`ManagedTx`]. A new interface that holds the three values finds exactly one API for finishing a
//! transaction, and that API cannot commit a terminated one: [`ManagedTx::commit`] requires the
//! registry entry to be presented alongside the ticket.
//!
//! # The rule
//!
//! | Operation | Terminated | Not terminated |
//! | --- | --- | --- |
//! | [`resume`](ManagedTx::resume) (statement boundary, keep-alive, any re-entry) | roll back, [`terminated_error`](crate::txn_registry::terminated_error) | `Ok(())` |
//! | [`commit`](ManagedTx::commit) | roll back, [`terminated_error`](crate::txn_registry::terminated_error) | commit |
//! | [`rollback`](ManagedTx::rollback) | roll back | roll back |
//!
//! **Rollback is deliberately unconditional.** Rolling a terminated transaction back is precisely what
//! the operator asked for, so refusing it would leave the client no way to discard the transaction it
//! has just been told is dead — and would diverge from the Bolt `ROLLBACK`, which has always succeeded.
//! Both seams therefore report success for a rollback of a terminated transaction, on purpose.
//!
//! # What this does *not* change
//!
//! A **client** registry entry carries no cancellation token (see
//! [`TransactionRegistry::register`](crate::txn_registry::TransactionRegistry::register)), so a
//! statement that is already executing still runs to completion; termination is observed at the next
//! resumption point. That is the `rmp` #637 contract on both interfaces and this module preserves it —
//! it makes the interfaces agree, it does not move when they look.

use graphus_core::GraphusError;

use super::{EngineHandle, RunSummary, TxTicket};
use crate::txn_registry::{TxnGuard, terminated_error};

/// One client-managed transaction, as every seam holds it: where it lives, which transaction it is,
/// and its live-registry entry.
///
/// Borrowed rather than owning, because the seams store the three values differently — the Bolt seam
/// owns its [`TxnGuard`] in a per-connection `Option<OpenTx>`, the REST seam keeps an `Arc<TxnGuard>`
/// in a shared table whose entries are cloned out under a mutex — and neither storage shape should
/// have to change to use the shared rule.
pub(super) struct ManagedTx<'a> {
    /// The engine the transaction was opened on (pinned for its lifetime).
    handle: &'a EngineHandle,
    /// The engine's opaque ticket for it.
    ticket: TxTicket,
    /// Its entry in the live-transaction registry — the `TERMINATE TRANSACTIONS` flag lives here.
    txn: &'a TxnGuard,
}

impl<'a> ManagedTx<'a> {
    /// Bundles the three values a seam already holds.
    pub(super) fn new(handle: &'a EngineHandle, ticket: TxTicket, txn: &'a TxnGuard) -> Self {
        Self {
            handle,
            ticket,
            txn,
        }
    }

    /// The guard every **resumption** point applies: a statement boundary, a keep-alive that refreshes
    /// an inactivity lease, or any other re-entry into an already-open transaction.
    ///
    /// When the transaction has been terminated by `TERMINATE TRANSACTIONS`, it is rolled back here —
    /// releasing its GC-watermark pin and its writes — and the non-retryable
    /// [`terminated_error`] is returned so the client learns the transaction is gone rather than
    /// silently continuing in it. The rollback's own outcome is ignored on purpose: a concurrent
    /// resumption on the same handle may have rolled it back already, and the engine answers a
    /// second rollback of a resolved ticket as an idempotent success anyway (`rmp` #955).
    ///
    /// The caller is responsible for discarding **its own** bookkeeping for the transaction (the Bolt
    /// seam's `current_tx`, the REST seam's table entry) on the error path, so the registry entry
    /// deregisters and the admission permit is released.
    ///
    /// # Errors
    /// [`terminated_error`] when the transaction has been terminated.
    pub(super) fn resume(&self) -> Result<(), GraphusError> {
        if self.txn.is_terminated() {
            let _ = self.handle.rollback_blocking(self.ticket);
            return Err(terminated_error());
        }
        Ok(())
    }

    /// Commits the transaction — **unless** it has been terminated, in which case it is rolled back and
    /// [`terminated_error`] is returned instead.
    ///
    /// This is the operation the whole module exists for: a terminated transaction that commits is
    /// worse than a `TERMINATE` that refuses, because the operator has been told the work was stopped
    /// and has no reason to look again.
    ///
    /// # Errors
    /// [`terminated_error`] when the transaction has been terminated, or the engine's own commit error
    /// (a serialization abort, a degraded engine, …) otherwise.
    pub(super) fn commit(&self) -> Result<RunSummary, GraphusError> {
        self.resume()?;
        self.handle.commit_blocking(self.ticket)
    }

    /// Rolls the transaction back, terminated or not — see the module docs for why termination does
    /// **not** make this fail.
    ///
    /// # Errors
    /// The engine's rollback error, if the undo itself failed.
    pub(super) fn rollback(&self) -> Result<(), GraphusError> {
        self.handle.rollback_blocking(self.ticket)
    }
}
