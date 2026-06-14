//! The [`VersionedStore`] trait — the multiversion key→value record interface the manager drives —
//! and [`MemVersionedStore`], an in-memory reference implementation for tests.
//!
//! ## Why an abstraction
//!
//! `04 §5.1`/`05 §5` chose **in-place latest + undo-delta chain** as the version representation, but
//! that representation is itself the open spike (`04 §12 item 2`): the real `graphus_storage` does
//! not yet implement version-chain mechanics. To keep this task (the ACID core) self-contained and
//! fully testable *now*, the manager is written against this small trait, which captures exactly the
//! multiversion operations it needs:
//!
//! - **create a new version** of a key, stamped with the writer's in-flight `TxnId` as `xmin`
//!   ([`create_version`](VersionedStore::create_version));
//! - **expire (set `xmax` on) the current version** of a key ([`expire_version`](VersionedStore::expire_version));
//! - **read the version visible to a snapshot** by walking newest→oldest along the `version_ptr`
//!   chain and applying [`crate::visibility`] ([`read_visible`](VersionedStore::read_visible));
//! - at commit, **stamp the writer's in-flight versions** with the real commit timestamp
//!   ([`commit_writer`](VersionedStore::commit_writer)); at abort, **discard them**
//!   ([`abort_writer`](VersionedStore::abort_writer));
//! - **garbage-collect** versions dead below the low-water mark ([`gc`](VersionedStore::gc)).
//!
//! The header fields use the frozen `05 §7` convention exactly: `xmin = created_ts`,
//! `xmax = expired_ts` (`0` = live), `version_ptr = undo_ptr` (older version). `xmin`/`xmax` carry
//! the committed-vs-in-flight [`VersionStamp`] encoding.
//!
//! ## Deferred follow-up (documented seam)
//!
//! Wiring real `graphus-storage` records to implement [`VersionedStore`] (mapping
//! `graphus_storage::record::MvccHeader` in-place + a WAL-backed undo area onto these operations,
//! and resolving the §12 representation spike) is a follow-up task, intentionally **out of scope**
//! here. The trait is the seam: any store that upholds its contract drops in unchanged.

#[cfg(any(test, feature = "test-support"))]
// FxHashMap: the in-memory reference store is keyed by internal Key (u64) and never iterated in an
// order-observable way, so the faster non-cryptographic hash is safe.
use rustc_hash::FxHashMap as HashMap;

use graphus_core::{Timestamp, TxnId};

use crate::snapshot::{CommitRegistry, Snapshot};
// Used only by the test-only `MemVersionedStore` reference implementation (gated below).
#[cfg(any(test, feature = "test-support"))]
use crate::oracle::VersionStamp;
#[cfg(any(test, feature = "test-support"))]
use crate::visibility::is_visible;

/// An opaque key identifying a versioned record (a node/relationship/property physical id in the
/// real store; an arbitrary `u64` in the in-memory reference store).
pub type Key = u64;

/// One physical version of a record: its frozen MVCC header words plus an opaque payload.
///
/// The payload models the record body the store would hold; the manager treats it opaquely.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Version {
    /// `created_ts` (`xmin`): committed-or-in-flight [`VersionStamp`]
    /// word of the creating transaction.
    pub xmin: u64,
    /// `expired_ts` (`xmax`): `0` while live, else the expiring transaction's stamp word.
    pub xmax: u64,
    /// The record body (opaque to the manager).
    pub payload: Vec<u8>,
}

impl Version {
    /// Whether this version is live (`xmax == 0`).
    #[must_use]
    pub fn is_live(&self) -> bool {
        self.xmax == 0
    }
}

/// The multiversion record interface the transaction manager is written against.
///
/// All methods are `&mut self`: the manager owns its store single-threadedly (consistent with the
/// single-writer storage core of this milestone). Errors are [`graphus_core::Result`] so a real
/// store's I/O failures surface uniformly.
pub trait VersionedStore {
    /// Creates a new version of `key` authored by in-flight `writer`, with `payload`.
    ///
    /// The new version becomes the chain head; any previous head is linked behind it via the
    /// `version_ptr`/undo chain and (if it was live) has its `xmax` set to `writer`'s in-flight
    /// stamp. This is both *insert* (no prior version) and *update* (prior version present).
    ///
    /// # Errors
    /// Propagates a store error.
    fn create_version(
        &mut self,
        key: Key,
        writer: TxnId,
        payload: Vec<u8>,
    ) -> graphus_core::Result<()>;

    /// Expires (tombstones) the current head version of `key` on behalf of in-flight `writer`,
    /// setting its `xmax` to `writer`'s in-flight stamp, without creating a new version. Models a
    /// delete.
    ///
    /// # Errors
    /// Returns an error if `key` has no live head version to expire.
    fn expire_version(&mut self, key: Key, writer: TxnId) -> graphus_core::Result<()>;

    /// Returns the payload of the version of `key` visible to `snapshot` (newest visible along the
    /// chain), or `None` if no version is visible.
    fn read_visible(
        &self,
        key: Key,
        snapshot: Snapshot,
        registry: &CommitRegistry,
    ) -> Option<Vec<u8>>;

    /// Stamps every in-flight version authored by `writer` with the committed `commit_ts` (both
    /// `xmin` it created and `xmax` it set). Called after the WAL `COMMIT` is durable.
    fn commit_writer(&mut self, writer: TxnId, commit_ts: Timestamp);

    /// Discards (or reverts) every change made by aborting `writer`: in-flight versions it created
    /// are removed and any `xmax` it set on older versions is cleared back to live.
    fn abort_writer(&mut self, writer: TxnId);

    /// Reclaims versions that are dead below `low_water`: any version with a committed `xmax ≤
    /// low_water` is invisible to every live and future snapshot and is removed. Returns the number
    /// of physical versions reclaimed.
    ///
    /// `None` (no active transactions) means everything not the live head can be reclaimed.
    fn gc(&mut self, low_water: Option<Timestamp>, registry: &CommitRegistry) -> usize;

    /// Total number of physical versions currently stored (across all chains). Test/metric aid.
    fn version_count(&self) -> usize;

    /// The `xmin` (`created_ts`) stamp word of `key`'s current head (newest) version, or `None` if
    /// the key has no version. Used by the manager to enforce SI **first-committer-wins**: a writer
    /// whose snapshot predates the head's *committed* creator is overwriting a version it cannot see
    /// (a lost update) and must abort. A head still in-flight is handled by the write lock, not here.
    fn head_xmin(&self, key: Key) -> Option<u64>;
}

/// An in-memory [`VersionedStore`] **for tests only** (storage audit F15): each key maps to a
/// `Vec<Version>` ordered **newest-first** (index `0` is the chain head), mirroring the
/// in-place-latest + undo-chain layout. Gated behind `cfg(test)` / the `test-support` feature so a
/// production build cannot run the manager over a non-durable in-memory store — production must
/// supply a durable `VersionedStore` (the WAL-backed implementation is the open ACID-certification
/// dependency).
#[cfg(any(test, feature = "test-support"))]
#[derive(Debug, Default)]
pub struct MemVersionedStore {
    chains: HashMap<Key, Vec<Version>>,
}

#[cfg(any(test, feature = "test-support"))]
impl MemVersionedStore {
    /// An empty store.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Borrows the version chain of `key` (newest-first), for test inspection.
    #[must_use]
    pub fn chain(&self, key: Key) -> Option<&[Version]> {
        self.chains.get(&key).map(Vec::as_slice)
    }
}

#[cfg(any(test, feature = "test-support"))]
impl VersionedStore for MemVersionedStore {
    fn create_version(
        &mut self,
        key: Key,
        writer: TxnId,
        payload: Vec<u8>,
    ) -> graphus_core::Result<()> {
        let stamp = VersionStamp::in_flight(writer);
        let chain = self.chains.entry(key).or_default();
        // The previous head, if live, is superseded by this writer.
        if let Some(head) = chain.first_mut()
            && head.xmax == 0
        {
            head.xmax = stamp;
        }
        chain.insert(
            0,
            Version {
                xmin: stamp,
                xmax: 0,
                payload,
            },
        );
        Ok(())
    }

    fn expire_version(&mut self, key: Key, writer: TxnId) -> graphus_core::Result<()> {
        let stamp = VersionStamp::in_flight(writer);
        let head = self
            .chains
            .get_mut(&key)
            .and_then(|c| c.first_mut())
            .filter(|h| h.xmax == 0)
            .ok_or_else(|| {
                graphus_core::GraphusError::Transaction(format!(
                    "expire of key {key} with no live head version"
                ))
            })?;
        head.xmax = stamp;
        Ok(())
    }

    fn read_visible(
        &self,
        key: Key,
        snapshot: Snapshot,
        registry: &CommitRegistry,
    ) -> Option<Vec<u8>> {
        let chain = self.chains.get(&key)?;
        chain
            .iter()
            .find(|v| is_visible(snapshot, v.xmin, v.xmax, registry))
            .map(|v| v.payload.clone())
    }

    fn commit_writer(&mut self, writer: TxnId, commit_ts: Timestamp) {
        let inflight = VersionStamp::in_flight(writer);
        let committed = VersionStamp::committed(commit_ts);
        for chain in self.chains.values_mut() {
            for v in chain.iter_mut() {
                if v.xmin == inflight {
                    v.xmin = committed;
                }
                if v.xmax == inflight {
                    v.xmax = committed;
                }
            }
        }
    }

    fn abort_writer(&mut self, writer: TxnId) {
        let inflight = VersionStamp::in_flight(writer);
        for chain in self.chains.values_mut() {
            // Drop versions this writer created.
            chain.retain(|v| v.xmin != inflight);
            // Revert any xmax this writer set (its delete/supersede) back to live.
            for v in chain.iter_mut() {
                if v.xmax == inflight {
                    v.xmax = 0;
                }
            }
        }
        self.chains.retain(|_, c| !c.is_empty());
    }

    fn gc(&mut self, low_water: Option<Timestamp>, registry: &CommitRegistry) -> usize {
        let mut reclaimed = 0;
        for chain in self.chains.values_mut() {
            let before = chain.len();
            // A version is dead iff its xmax committed at `≤ low_water` (invisible to every live and
            // future snapshot). With no active transactions, every committed xmax is dead. The live
            // head (xmax == 0) is never reclaimed.
            chain.retain(|v| {
                let Some(xmax_commit) = registry.resolve_commit_ts(v.xmax) else {
                    return true; // live, or expired by an in-flight/aborted writer: keep
                };
                match low_water {
                    Some(mark) => xmax_commit > mark, // keep if still potentially visible
                    None => false,                    // no readers: reclaim every committed-dead
                }
            });
            reclaimed += before - chain.len();
        }
        self.chains.retain(|_, c| !c.is_empty());
        reclaimed
    }

    fn version_count(&self) -> usize {
        self.chains.values().map(Vec::len).sum()
    }

    fn head_xmin(&self, key: Key) -> Option<u64> {
        self.chains
            .get(&key)
            .and_then(|c| c.first())
            .map(|v| v.xmin)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use graphus_core::Timestamp;

    fn snap(owner: u64, ts: u64) -> Snapshot {
        Snapshot {
            owner: TxnId(owner),
            ts: Timestamp(ts),
        }
    }

    #[test]
    fn create_then_read_own_write() {
        let mut s = MemVersionedStore::new();
        let reg = CommitRegistry::new();
        s.create_version(1, TxnId(7), b"v1".to_vec()).unwrap();
        // Own write is visible to its author before commit.
        assert_eq!(s.read_visible(1, snap(7, 100), &reg), Some(b"v1".to_vec()));
        // Invisible to a concurrent reader.
        assert_eq!(s.read_visible(1, snap(8, 100), &reg), None);
    }

    #[test]
    fn commit_then_visible_to_later_snapshot() {
        let mut s = MemVersionedStore::new();
        let mut reg = CommitRegistry::new();
        s.create_version(1, TxnId(7), b"v1".to_vec()).unwrap();
        s.commit_writer(TxnId(7), Timestamp(10));
        reg.record_commit(TxnId(7), Timestamp(10));
        assert_eq!(s.read_visible(1, snap(9, 20), &reg), Some(b"v1".to_vec()));
        // A snapshot before the commit does not see it.
        assert_eq!(s.read_visible(1, snap(9, 5), &reg), None);
    }

    #[test]
    fn update_supersedes_and_old_snapshot_sees_old_version() {
        let mut s = MemVersionedStore::new();
        let mut reg = CommitRegistry::new();
        s.create_version(1, TxnId(1), b"v1".to_vec()).unwrap();
        s.commit_writer(TxnId(1), Timestamp(10));
        reg.record_commit(TxnId(1), Timestamp(10));
        // Update at a later commit.
        s.create_version(1, TxnId(2), b"v2".to_vec()).unwrap();
        s.commit_writer(TxnId(2), Timestamp(20));
        reg.record_commit(TxnId(2), Timestamp(20));
        // Reader at snapshot 15 sees the old version; reader at 25 sees the new one.
        assert_eq!(s.read_visible(1, snap(9, 15), &reg), Some(b"v1".to_vec()));
        assert_eq!(s.read_visible(1, snap(9, 25), &reg), Some(b"v2".to_vec()));
        assert_eq!(s.version_count(), 2);
    }

    #[test]
    fn abort_discards_created_version_and_reverts_xmax() {
        let mut s = MemVersionedStore::new();
        let mut reg = CommitRegistry::new();
        s.create_version(1, TxnId(1), b"v1".to_vec()).unwrap();
        s.commit_writer(TxnId(1), Timestamp(10));
        reg.record_commit(TxnId(1), Timestamp(10));
        // Txn 2 updates then aborts.
        s.create_version(1, TxnId(2), b"v2".to_vec()).unwrap();
        s.abort_writer(TxnId(2));
        reg.record_abort(TxnId(2));
        // Only v1 remains, live again.
        assert_eq!(s.version_count(), 1);
        assert_eq!(s.read_visible(1, snap(9, 50), &reg), Some(b"v1".to_vec()));
    }

    #[test]
    fn expire_then_invisible() {
        let mut s = MemVersionedStore::new();
        let mut reg = CommitRegistry::new();
        s.create_version(1, TxnId(1), b"v1".to_vec()).unwrap();
        s.commit_writer(TxnId(1), Timestamp(10));
        reg.record_commit(TxnId(1), Timestamp(10));
        s.expire_version(1, TxnId(2)).unwrap();
        s.commit_writer(TxnId(2), Timestamp(20));
        reg.record_commit(TxnId(2), Timestamp(20));
        assert_eq!(s.read_visible(1, snap(9, 25), &reg), None); // deleted by snapshot 25
        assert_eq!(s.read_visible(1, snap(9, 15), &reg), Some(b"v1".to_vec())); // alive at 15
    }

    #[test]
    fn expire_with_no_live_head_errors() {
        let mut s = MemVersionedStore::new();
        assert!(s.expire_version(99, TxnId(1)).is_err());
    }

    #[test]
    fn gc_reclaims_dead_below_low_water_and_holds_back_for_readers() {
        let mut s = MemVersionedStore::new();
        let mut reg = CommitRegistry::new();
        // v1 committed at 10, superseded by v2 committed at 20.
        s.create_version(1, TxnId(1), b"v1".to_vec()).unwrap();
        s.commit_writer(TxnId(1), Timestamp(10));
        reg.record_commit(TxnId(1), Timestamp(10));
        s.create_version(1, TxnId(2), b"v2".to_vec()).unwrap();
        s.commit_writer(TxnId(2), Timestamp(20));
        reg.record_commit(TxnId(2), Timestamp(20));
        assert_eq!(s.version_count(), 2);
        // A reader at snapshot 15 still needs v1: low-water 15 holds it (v1.xmax == 20 > 15).
        assert_eq!(s.gc(Some(Timestamp(15)), &reg), 0);
        assert_eq!(s.version_count(), 2);
        // Once the oldest reader is past 20, v1 is dead (xmax 20 ≤ 25).
        assert_eq!(s.gc(Some(Timestamp(25)), &reg), 1);
        assert_eq!(s.version_count(), 1);
    }
}
