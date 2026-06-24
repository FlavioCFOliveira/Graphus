//! The transaction manager: lifecycle, visibility, SSI validation, write-write conflict handling,
//! deadlock detection, and version GC, tying together every other module (`04 §5`).
//!
//! [`TxnManager`] owns the [`TimestampOracle`], the [`CommitRegistry`], the [`SsiTracker`], the
//! [`LockTable`], and a [`VersionedStore`]. It is single-threaded by construction (consistent with
//! the single-writer storage core of this milestone): callers drive transactions through
//! [`begin`](TxnManager::begin) → reads/writes → [`commit`](TxnManager::commit) /
//! [`rollback`](TxnManager::rollback).
//!
//! ## Lifecycle and durability
//!
//! On [`commit`](TxnManager::commit) the manager, in order: (1) runs SSI validation for SERIALIZABLE
//! transactions and aborts a pivot on a dangerous structure (`04 §5.4`); (2) assigns a commit
//! timestamp from the oracle; (3) **hardens durability** through the [`Durability`] hook — in
//! production this is `graphus_wal::WalManager::commit` (group commit + `fdatasync`, `04 §1.3` step
//! 6 / `§4.2`); and only then (4) stamps the writer's versions with the commit timestamp and
//! publishes the outcome. The hook is the documented seam to the WAL so this crate stays
//! self-contained and testable while the commit ordering matches the real engine.
//!
//! ## What the manager guarantees
//!
//! - **Reads never block writers** (`04 §5.7`, NFR-4): [`read`](TxnManager::read) takes no locks and
//!   never waits — it is a pure visibility check plus a non-blocking SIREAD marker.
//! - **Serializable by default** with **Snapshot Isolation as a documented opt-in**
//!   ([`IsolationLevel`], `D-isolation-level`).
//! - **Write-write is the only blocking**, resolved first-updater-wins with deadlock detection
//!   (`04 §5.7`).

use std::time::{Duration, Instant};

// FxHashMap: the active-transaction table is keyed by internal TxnId (never attacker-controlled)
// and never iterated in an order-observable way, so the faster non-cryptographic hash is safe.
use rustc_hash::FxHashMap as HashMap;

use graphus_core::{GraphusError, Result, Timestamp, TxnId, VersionStamp};

use crate::gc::{GcReport, collect};
use crate::lock::{LockOutcome, LockTable};
use crate::oracle::TimestampOracle;
use crate::snapshot::{CommitRegistry, IsolationLevel, Snapshot};
use crate::ssi::SsiTracker;
use crate::store::{Key, VersionedStore};

/// A durability hook invoked on commit, *before* a transaction's effects are made visible.
///
/// In production this is bound to `graphus_wal::WalManager::commit` so that a commit returns only
/// once its `COMMIT` WAL record is group-committed and `fdatasync`'d (`04 §1.3` step 6, `§4.2`). In
/// tests the default [`NoDurability`] is used. Keeping it a trait keeps `graphus-txn` free of a WAL
/// dependency while pinning the commit ordering to the real engine's.
pub trait Durability {
    /// Hardens the commit of `txn`. Returning `Err` aborts the commit (the transaction is rolled
    /// back and the error surfaced); the real WAL panics rather than returning on fsync failure
    /// (`04 §4.9`), so an `Err` here models a *logical* refusal, not a sync failure.
    ///
    /// # Errors
    /// Returns an error if durability could not be established.
    fn harden_commit(&mut self, txn: TxnId) -> Result<()>;
}

/// The no-op durability hook for **tests only** (storage audit F15). It is gated behind
/// `cfg(test)` / the `test-support` feature so a production (default-features) build cannot wire a
/// transaction manager whose commits are not hardened: production must supply a real [`Durability`]
/// (bound to `graphus_wal::WalManager::commit`) via [`TxnManager::with_durability`]. The WAL-backed
/// durable `VersionedStore` is the explicit ACID-certification dependency this gate makes visible.
#[cfg(any(test, feature = "test-support"))]
#[derive(Debug, Default)]
pub struct NoDurability;

#[cfg(any(test, feature = "test-support"))]
impl Durability for NoDurability {
    fn harden_commit(&mut self, _txn: TxnId) -> Result<()> {
        Ok(())
    }
}

/// The default ceiling on concurrently active transactions (SEC-198). Chosen well above any sane
/// single-node concurrency yet low enough that a runaway client opening transactions in a loop
/// cannot exhaust memory. Override via [`TxnConfig`].
pub const DEFAULT_MAX_ACTIVE_TXNS: usize = 100_000;

/// The default idle-transaction timeout (SEC-198): a transaction that neither commits, rolls back,
/// nor performs an operation within this wall-clock window is eligible for reaping by
/// [`TxnManager::reap_idle`], so a single abandoned transaction cannot pin the GC low-water mark
/// forever (the classic long-running-idle-transaction hazard). Override via [`TxnConfig`].
pub const DEFAULT_IDLE_TIMEOUT: Duration = Duration::from_secs(300);

/// Resource-safety limits for the transaction manager (SEC-198, CWE-400). Both default to safe,
/// generous values ([`DEFAULT_MAX_ACTIVE_TXNS`], [`DEFAULT_IDLE_TIMEOUT`]); a server tunes them to
/// its environment. Keeping them in one struct makes the admission/eviction policy explicit and
/// forward-compatible with the planned multi-threaded promotion.
#[derive(Debug, Clone, Copy)]
pub struct TxnConfig {
    /// Maximum number of simultaneously active (uncommitted, un-rolled-back) transactions. A
    /// [`begin`](TxnManager::begin) above this ceiling is refused with a retriable error.
    pub max_active_txns: usize,
    /// How long a transaction may stay idle (no begin/read/write/delete progress) before
    /// [`reap_idle`](TxnManager::reap_idle) may abort it to free the GC watermark.
    pub idle_timeout: Duration,
}

impl Default for TxnConfig {
    fn default() -> Self {
        Self {
            max_active_txns: DEFAULT_MAX_ACTIVE_TXNS,
            idle_timeout: DEFAULT_IDLE_TIMEOUT,
        }
    }
}

/// Live state of an in-flight transaction, owned by the manager.
#[derive(Debug)]
struct ActiveTxn {
    snapshot: Snapshot,
    isolation: IsolationLevel,
    /// Wall-clock instant of this transaction's most recent operation (begin/read/write/delete).
    /// Drives the idle-timeout reaper (SEC-198); refreshed on every operation.
    last_active: Instant,
}

/// The MVCC + SSI transaction manager (`04 §5`).
///
/// `D` (the [`Durability`] hook) has **no default**: production must name a real durability binding
/// via [`with_durability`](Self::with_durability). The no-op [`NoDurability`] and the convenience
/// [`new`](Self::new) constructor exist only under `cfg(test)` / the `test-support` feature
/// (storage audit F15).
#[derive(Debug)]
pub struct TxnManager<S: VersionedStore, D: Durability> {
    oracle: TimestampOracle,
    registry: CommitRegistry,
    ssi: SsiTracker,
    locks: LockTable,
    store: S,
    durability: D,
    active: HashMap<TxnId, ActiveTxn>,
    next_txn_id: u64,
    config: TxnConfig,
}

#[cfg(any(test, feature = "test-support"))]
impl<S: VersionedStore> TxnManager<S, NoDurability> {
    /// A manager over `store` with **no durability hook** — tests only. Gated behind `cfg(test)` /
    /// the `test-support` feature so production cannot construct a non-durable manager by accident
    /// (storage audit F15); production uses [`with_durability`](Self::with_durability).
    #[must_use]
    pub fn new(store: S) -> Self {
        Self::with_durability(store, NoDurability)
    }
}

impl<S: VersionedStore, D: Durability> TxnManager<S, D> {
    /// A manager over `store` whose commits are hardened through `durability` (production wires this
    /// to the WAL; see [`Durability`]).
    pub fn with_durability(store: S, durability: D) -> Self {
        Self::with_durability_and_config(store, durability, TxnConfig::default())
    }

    /// A manager over `store` with explicit durability and resource-limit [`TxnConfig`] (SEC-198).
    pub fn with_durability_and_config(store: S, durability: D, config: TxnConfig) -> Self {
        Self {
            oracle: TimestampOracle::new(),
            registry: CommitRegistry::new(),
            ssi: SsiTracker::new(),
            locks: LockTable::new(),
            store,
            durability,
            active: HashMap::default(),
            next_txn_id: 0,
            config,
        }
    }

    /// Begins a transaction at `isolation`, returning its [`TxnId`].
    ///
    /// Assigns a fresh `TxnId` and a begin timestamp (its read snapshot) from the oracle, and
    /// registers it with the SSI tracker and the commit registry.
    ///
    /// # Errors
    /// - [`GraphusError::Transaction`] (retriable) if the active-transaction ceiling
    ///   ([`TxnConfig::max_active_txns`]) is reached — admission control against resource exhaustion
    ///   (SEC-198, CWE-400).
    /// - [`GraphusError::Transaction`] if the transaction-id / timestamp space is exhausted
    ///   (SEC-197, CWE-190): `next_txn_id` is incremented with [`u64::checked_add`] and bounded by
    ///   the 63-bit usable range so it can never wrap to the reserved `TxnId(0)` nor collide with the
    ///   in-flight high-bit discriminator.
    pub fn begin(&mut self, isolation: IsolationLevel) -> Result<TxnId> {
        // Admission control: refuse a new transaction above the configured ceiling so a client
        // opening transactions in a loop cannot grow the in-memory tables without bound (SEC-198).
        if self.active.len() >= self.config.max_active_txns {
            return Err(GraphusError::Transaction(format!(
                "transaction admission limit reached ({} active); retry",
                self.config.max_active_txns
            )));
        }
        // SEC-197: a checked, range-bounded id. The usable id space is `1..=MAX_TIMESTAMP` (bit 63 is
        // the in-flight/committed discriminator and `TxnId(0)` is reserved), so cap there and refuse
        // gracefully at exhaustion rather than wrapping into an illegal stamp that panics later.
        let next_id = self
            .next_txn_id
            .checked_add(1)
            .filter(|n| *n <= graphus_core::MAX_TIMESTAMP)
            .ok_or_else(|| {
                GraphusError::Transaction(
                    "transaction-id space exhausted (63-bit); no new transactions can begin"
                        .to_owned(),
                )
            })?;
        // The oracle may itself refuse if the timestamp space is exhausted (SEC-200). Reserve the id
        // only after a begin timestamp is successfully issued so a refusal leaves no gap/poison.
        let begin_ts = self.oracle.begin()?;
        self.next_txn_id = next_id;
        let txn = TxnId(next_id);
        let snapshot = Snapshot {
            owner: txn,
            ts: begin_ts,
        };
        self.registry.register_begin(txn);
        self.ssi.register(txn, begin_ts);
        self.active.insert(
            txn,
            ActiveTxn {
                snapshot,
                isolation,
                last_active: Instant::now(),
            },
        );
        Ok(txn)
    }

    /// Begins a SERIALIZABLE transaction (the default level).
    ///
    /// # Errors
    /// See [`begin`](Self::begin).
    pub fn begin_serializable(&mut self) -> Result<TxnId> {
        self.begin(IsolationLevel::Serializable)
    }

    /// Reads the version of `key` visible to `txn`'s snapshot, registering a non-blocking SIREAD
    /// marker for SSI. **Never blocks and never takes a lock** (`04 §5.7`, NFR-4).
    ///
    /// # Errors
    /// Returns [`GraphusError::Transaction`] if `txn` is not active.
    pub fn read(&mut self, txn: TxnId, key: Key) -> Result<Option<Vec<u8>>> {
        let snapshot = self.active_snapshot(txn)?;
        self.touch(txn); // refresh idle-timeout activity (SEC-198)
        // SIREAD marker first (SSI tracking is independent of whether a version is visible — a read
        // of a key still establishes the rw relationship if a concurrent writer overwrites it).
        self.ssi.record_read(txn, key);
        Ok(self.store.read_visible(key, snapshot, &self.registry))
    }

    /// Writes `payload` as a new version of `key` on behalf of `txn` (insert or update).
    ///
    /// Acquires the write lock first-updater-wins; on a write-write conflict the conflicting holder
    /// is reported. Records the write in the SSI tracker (closing rw-edges with concurrent readers).
    ///
    /// # Errors
    /// - [`GraphusError::Transaction`] if `txn` is not active.
    /// - [`GraphusError::Transaction`] (retriable serialization failure) on a write-write conflict
    ///   with another in-flight transaction.
    pub fn write(&mut self, txn: TxnId, key: Key, payload: Vec<u8>) -> Result<()> {
        self.ensure_active(txn)?;
        self.touch(txn); // refresh idle-timeout activity (SEC-198)
        self.acquire_write(txn, key)?;
        self.ensure_no_concurrent_committed_write(txn, key)?;
        self.store.create_version(key, txn, payload)?;
        self.ssi.record_write(txn, key);
        Ok(())
    }

    /// Deletes (expires) the version of `key` visible to `txn` on behalf of `txn`.
    ///
    /// Same locking and SSI semantics as [`write`](Self::write).
    ///
    /// # Errors
    /// - [`GraphusError::Transaction`] if `txn` is not active or there is no live version to expire.
    /// - A retriable serialization failure on a write-write conflict.
    pub fn delete(&mut self, txn: TxnId, key: Key) -> Result<()> {
        self.ensure_active(txn)?;
        self.touch(txn); // refresh idle-timeout activity (SEC-198)
        self.acquire_write(txn, key)?;
        self.ensure_no_concurrent_committed_write(txn, key)?;
        self.store.expire_version(key, txn)?;
        self.ssi.record_write(txn, key);
        Ok(())
    }

    /// Commits `txn`. Runs SSI validation (SERIALIZABLE only), hardens durability, then publishes.
    ///
    /// On a dangerous structure (`04 §5.4`) the chosen victim is aborted with a retriable
    /// serialization failure; if the victim is `txn` itself, this returns the error after rolling
    /// `txn` back. (When the victim is *another* still-running transaction, that transaction is
    /// poisoned: its next operation or commit will fail — modelled by aborting it now.)
    ///
    /// # Errors
    /// - [`GraphusError::Transaction`] if `txn` is not active.
    /// - [`GraphusError::Transaction`] (retriable) if `txn` is the SSI abort victim.
    /// - Any error returned by the [`Durability`] hook (the commit is rolled back first).
    pub fn commit(&mut self, txn: TxnId) -> Result<Timestamp> {
        let active = self.active.get(&txn).ok_or_else(|| {
            GraphusError::Transaction(format!("commit of inactive txn {}", txn.0))
        })?;
        let isolation = active.isolation;

        // 1) SSI validation (SERIALIZABLE only).
        if isolation.runs_ssi()
            && let Some(victim) = self.ssi.detect_pivot_abort(txn)
        {
            if victim == txn {
                self.abort_internal(txn);
                return Err(GraphusError::Transaction(format!(
                    "serialization failure: transaction {} aborted to preserve serializability \
                     (SSI dangerous structure); retry",
                    txn.0
                )));
            }
            // The pivot is another in-flight transaction: abort it now so the safe member (txn)
            // commits. The aborted transaction's own commit/op will then fail as inactive.
            self.abort_internal(victim);
        }

        // 2) Assign the commit timestamp. A timestamp-space exhaustion is a recoverable refusal
        //    (SEC-200): roll the transaction back rather than panic.
        let commit_ts = match self.oracle.commit() {
            Ok(ts) => ts,
            Err(e) => {
                self.abort_internal(txn);
                return Err(e);
            }
        };

        // 3) Harden durability (production: WAL group commit + fdatasync) BEFORE publishing.
        if let Err(e) = self.durability.harden_commit(txn) {
            self.abort_internal(txn);
            return Err(e);
        }

        // 4) Publish: stamp versions, record outcomes, release locks, free the snapshot.
        self.store.commit_writer(txn, commit_ts);
        self.registry.record_commit(txn, commit_ts);
        self.ssi.record_commit(txn, commit_ts);
        self.locks.release_all(txn);
        let snapshot_ts = self.active.remove(&txn).map(|a| a.snapshot.ts);
        if let Some(ts) = snapshot_ts {
            // A defensive no-op if bookkeeping is inconsistent (SEC-200); never panic on commit.
            let _ = self.oracle.release_begin(ts);
        }
        Ok(commit_ts)
    }

    /// Rolls `txn` back: discards its writes, releases its locks, and frees its snapshot.
    ///
    /// # Errors
    /// Returns [`GraphusError::Transaction`] if `txn` is not active.
    pub fn rollback(&mut self, txn: TxnId) -> Result<()> {
        if !self.active.contains_key(&txn) {
            return Err(GraphusError::Transaction(format!(
                "rollback of inactive txn {}",
                txn.0
            )));
        }
        self.abort_internal(txn);
        Ok(())
    }

    /// Runs one GC pass at the current low-water mark and forgets fully-dead transactions.
    ///
    /// Reclaims versions invisible to every live snapshot (`04 §5.5`) and prunes registry/SSI
    /// entries that no live reader can still resolve (`rmp` task #59), so neither table grows with
    /// the store's lifetime. Long-running readers hold the watermark back automatically. Returns the
    /// [`GcReport`].
    ///
    /// Pruning the commit registry here is safe because the [`VersionedStore`] contract settles
    /// every committed writer's in-flight stamps at `commit_writer`, so no version header a reader
    /// can still consult resolves through a settled entry; the `≤ low_water` gate additionally
    /// matches the SSI retention rule (see [`SsiTracker::prune_committed`]).
    pub fn run_gc(&mut self) -> GcReport {
        let low_water = self.oracle.low_water_mark();
        let mut report = collect(&mut self.store, low_water, &self.registry);
        report.txns_pruned = self.registry.prune_settled(low_water);
        self.ssi.prune_committed(low_water);
        report
    }

    /// The current GC low-water mark (oldest active begin timestamp), for observability/tests.
    #[must_use]
    pub fn low_water_mark(&self) -> Option<Timestamp> {
        self.oracle.low_water_mark()
    }

    /// The number of currently active transactions (observability).
    #[must_use]
    pub fn active_count(&self) -> usize {
        self.active.len()
    }

    /// The number of entries in the commit registry (the Active/Recent Transaction Table). Bounded
    /// by the [`run_gc`](Self::run_gc) prune (`rmp` task #59); observability/tests.
    #[must_use]
    pub fn registry_len(&self) -> usize {
        self.registry.len()
    }

    /// Borrows the underlying store (read-only inspection, tests).
    #[must_use]
    pub fn store(&self) -> &S {
        &self.store
    }

    /// Aborts every transaction idle longer than [`TxnConfig::idle_timeout`], returning how many
    /// were reaped (SEC-198, CWE-400).
    ///
    /// A transaction that opens, reads/writes nothing further, and never commits or rolls back pins
    /// the GC low-water mark indefinitely — the classic long-running-idle-transaction hazard — and
    /// keeps its read/write set, lock, and SSI bookkeeping resident forever. The server calls this
    /// periodically (a background tick); an idle holder is aborted with the same effect as an
    /// explicit rollback, freeing the watermark so [`run_gc`](Self::run_gc) can make progress.
    ///
    /// Idleness is measured from each transaction's last operation; an actively progressing
    /// transaction is never reaped regardless of total lifetime.
    pub fn reap_idle(&mut self) -> usize {
        self.reap_idle_as_of(Instant::now())
    }

    /// [`reap_idle`](Self::reap_idle) relative to an explicit `now` (testable without sleeping).
    fn reap_idle_as_of(&mut self, now: Instant) -> usize {
        let timeout = self.config.idle_timeout;
        let victims: Vec<TxnId> = self
            .active
            .iter()
            .filter(|(_, a)| now.saturating_duration_since(a.last_active) >= timeout)
            .map(|(id, _)| *id)
            .collect();
        for txn in &victims {
            self.abort_internal(*txn);
        }
        victims.len()
    }

    /// The active-transaction / idle-timeout limits in force (observability/tests).
    #[must_use]
    pub fn config(&self) -> TxnConfig {
        self.config
    }

    // ----------------------------- internals -----------------------------

    /// Refreshes a transaction's idle clock (SEC-198). A no-op if `txn` is not active.
    fn touch(&mut self, txn: TxnId) {
        if let Some(a) = self.active.get_mut(&txn) {
            a.last_active = Instant::now();
        }
    }

    fn active_snapshot(&self, txn: TxnId) -> Result<Snapshot> {
        self.active
            .get(&txn)
            .map(|a| a.snapshot)
            .ok_or_else(|| GraphusError::Transaction(format!("read in inactive txn {}", txn.0)))
    }

    fn ensure_active(&self, txn: TxnId) -> Result<()> {
        if self.active.contains_key(&txn) {
            Ok(())
        } else {
            Err(GraphusError::Transaction(format!(
                "write in inactive txn {}",
                txn.0
            )))
        }
    }

    /// Acquires the write lock for `txn` on `key`, applying first-updater-wins with deadlock
    /// detection. On a conflict that is not a deadlock, the *waiter* fails fast with a retriable
    /// serialization error (the single-threaded model has no thread to park; a multi-threaded
    /// promotion would block here and retry on release).
    /// Enforces Snapshot Isolation **first-committer-wins** (`04 §5.3`): a writer may not overwrite a
    /// version it cannot see. After the write lock is held (which already serialises concurrent
    /// *in-flight* writers of `key`), this rejects the case the lock cannot — a transaction that
    /// **committed** a write to `key` *after* this transaction's snapshot. Overwriting it would be a
    /// lost update; under SI the later writer aborts with a retriable conflict. This is the property
    /// the SSI dangerous-structure detector *assumes* SI already provides (it only tracks
    /// rw-antidependencies); without it a ww/rw cycle escapes serializability (`rmp` storage audit F9).
    ///
    /// A head version this transaction itself authored (an in-flight stamp) is not a conflict, nor is
    /// a head committed at or before the snapshot.
    fn ensure_no_concurrent_committed_write(&self, txn: TxnId, key: Key) -> Result<()> {
        let Some(active) = self.active.get(&txn) else {
            return Err(GraphusError::Transaction(format!(
                "write in inactive txn {}",
                txn.0
            )));
        };
        let snapshot_ts = active.snapshot.ts;
        if let Some(xmin) = self.store.head_xmin(key)
            && let VersionStamp::Committed(committed_ts) = VersionStamp::from_raw(xmin)
            && committed_ts > snapshot_ts
        {
            return Err(GraphusError::Transaction(format!(
                "write conflict: key {key} was updated by a concurrent transaction that committed \
                 after this snapshot (first-committer-wins); retry"
            )));
        }
        Ok(())
    }

    fn acquire_write(&mut self, txn: TxnId, key: Key) -> Result<()> {
        match self.locks.acquire(txn, key) {
            LockOutcome::Granted => Ok(()),
            LockOutcome::Wait { holder } => {
                // A wait-for edge `txn -> holder` was just recorded; a *new* cycle can only pass
                // through that edge, so the edge-rooted search (O(cycle length)) suffices and picks
                // the exact same youngest victim the full O(V+E) sweep would (debug-asserted inside).
                if let Some(victim) = self.locks.find_deadlock_victim_for(txn, holder) {
                    if victim == txn {
                        self.abort_internal(txn);
                        return Err(GraphusError::Transaction(format!(
                            "deadlock: transaction {} aborted (youngest on the wait-for cycle); \
                             retry",
                            txn.0
                        )));
                    }
                    // Abort the youngest victim (another transaction), then grant our lock.
                    self.abort_internal(victim);
                    // The key may now be free; re-acquire.
                    return match self.locks.acquire(txn, key) {
                        LockOutcome::Granted => Ok(()),
                        LockOutcome::Wait { holder } => Err(GraphusError::Transaction(format!(
                            "write-write conflict: key {key} held by transaction {}; retry",
                            holder.0
                        ))),
                    };
                }
                // No deadlock, but the key is held: first-updater-wins, the second writer fails
                // fast with a retriable error (NFR — readers stay non-blocking regardless).
                Err(GraphusError::Transaction(format!(
                    "write-write conflict: key {key} held by transaction {}; retry",
                    holder.0
                )))
            }
        }
    }

    /// Aborts `txn`: discards its store writes, records the abort, releases locks, frees the
    /// snapshot, and forgets it from the SSI tracker.
    fn abort_internal(&mut self, txn: TxnId) {
        self.store.abort_writer(txn);
        self.registry.record_abort(txn);
        self.ssi.forget(txn);
        self.locks.release_all(txn);
        if let Some(a) = self.active.remove(&txn) {
            // Defensive no-op on a bookkeeping inconsistency (SEC-200); abort must never panic.
            let _ = self.oracle.release_begin(a.snapshot.ts);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::MemVersionedStore;

    fn mgr() -> TxnManager<MemVersionedStore, NoDurability> {
        TxnManager::new(MemVersionedStore::new())
    }

    #[test]
    fn basic_commit_makes_writes_visible_to_later_txns() {
        let mut m = mgr();
        let t1 = m.begin_serializable().unwrap();
        m.write(t1, 1, b"hello".to_vec()).unwrap();
        m.commit(t1).unwrap();

        let t2 = m.begin_serializable().unwrap();
        assert_eq!(m.read(t2, 1).unwrap(), Some(b"hello".to_vec()));
        m.commit(t2).unwrap();
    }

    #[test]
    fn snapshot_isolation_for_reads_under_concurrent_commit() {
        let mut m = mgr();
        // Seed.
        let t0 = m.begin_serializable().unwrap();
        m.write(t0, 1, b"v1".to_vec()).unwrap();
        m.commit(t0).unwrap();

        // Long reader opens its snapshot.
        let reader = m.begin_serializable().unwrap();
        assert_eq!(m.read(reader, 1).unwrap(), Some(b"v1".to_vec()));

        // A concurrent writer updates and commits.
        let writer = m.begin_serializable().unwrap();
        m.write(writer, 1, b"v2".to_vec()).unwrap();
        m.commit(writer).unwrap();

        // The reader still sees its snapshot (v1), not v2.
        assert_eq!(m.read(reader, 1).unwrap(), Some(b"v1".to_vec()));
        m.commit(reader).unwrap();

        // A fresh transaction sees v2.
        let t3 = m.begin_serializable().unwrap();
        assert_eq!(m.read(t3, 1).unwrap(), Some(b"v2".to_vec()));
        m.commit(t3).unwrap();
    }

    #[test]
    fn write_write_conflict_is_first_updater_wins() {
        let mut m = mgr();
        let t1 = m.begin_serializable().unwrap();
        let t2 = m.begin_serializable().unwrap();
        m.write(t1, 1, b"a".to_vec()).unwrap();
        // Second writer of the same key conflicts (retriable).
        let err = m.write(t2, 1, b"b".to_vec()).unwrap_err();
        assert!(matches!(err, GraphusError::Transaction(_)));
        m.commit(t1).unwrap();
        m.rollback(t2).ok();
    }

    #[test]
    fn rollback_discards_writes() {
        let mut m = mgr();
        let t1 = m.begin_serializable().unwrap();
        m.write(t1, 1, b"x".to_vec()).unwrap();
        m.rollback(t1).unwrap();
        let t2 = m.begin_serializable().unwrap();
        assert_eq!(m.read(t2, 1).unwrap(), None);
    }

    #[test]
    fn inactive_txn_operations_error() {
        let mut m = mgr();
        let t1 = m.begin_serializable().unwrap();
        m.commit(t1).unwrap();
        assert!(m.read(t1, 1).is_err());
        assert!(m.write(t1, 1, b"x".to_vec()).is_err());
        assert!(m.commit(t1).is_err());
        assert!(m.rollback(t1).is_err());
    }

    #[test]
    fn delete_then_invisible() {
        let mut m = mgr();
        let t0 = m.begin_serializable().unwrap();
        m.write(t0, 1, b"v".to_vec()).unwrap();
        m.commit(t0).unwrap();
        let t1 = m.begin_serializable().unwrap();
        m.delete(t1, 1).unwrap();
        m.commit(t1).unwrap();
        let t2 = m.begin_serializable().unwrap();
        assert_eq!(m.read(t2, 1).unwrap(), None);
    }

    #[test]
    fn run_gc_prunes_settled_registry_entries_but_keeps_live_ones() {
        let mut m = mgr();
        // Three committed writers grow the registry.
        for key in 1..=3u64 {
            let t = m.begin_serializable().unwrap();
            m.write(t, key, b"v".to_vec()).unwrap();
            m.commit(t).unwrap();
        }
        assert_eq!(m.registry_len(), 3);

        // A long reader pins the low-water mark at its begin timestamp: a writer that commits
        // *after* the reader began stays in the registry (it is still potentially relevant), while
        // the three writers settled before the reader began are pruned.
        let reader = m.begin_serializable().unwrap();
        let late = m.begin_serializable().unwrap();
        m.write(late, 9, b"late".to_vec()).unwrap();
        m.commit(late).unwrap();
        let report = m.run_gc();
        assert_eq!(report.txns_pruned, 3);
        assert_eq!(
            m.registry_len(),
            2,
            "the reader (in flight) + the late writer"
        );
        // The reader still resolves everything it could see (the settled writers' versions carry
        // committed stamps per the VersionedStore contract).
        assert_eq!(m.read(reader, 1).unwrap(), Some(b"v".to_vec()));
        m.commit(reader).unwrap();

        // With no active transactions, everything settles.
        let report = m.run_gc();
        assert!(report.txns_pruned >= 2);
        assert_eq!(m.registry_len(), 0);
    }

    #[test]
    fn durability_hook_failure_rolls_back_commit() {
        struct AlwaysFail;
        impl Durability for AlwaysFail {
            fn harden_commit(&mut self, _txn: TxnId) -> Result<()> {
                Err(GraphusError::Transaction("durability refused".to_owned()))
            }
        }
        let mut m = TxnManager::with_durability(MemVersionedStore::new(), AlwaysFail);
        let t1 = m.begin_serializable().unwrap();
        m.write(t1, 1, b"x".to_vec()).unwrap();
        assert!(m.commit(t1).is_err());
        // The write was rolled back; a fresh txn sees nothing.
        let t2 = m.begin_serializable().unwrap();
        assert_eq!(m.read(t2, 1).unwrap(), None);
    }
}
