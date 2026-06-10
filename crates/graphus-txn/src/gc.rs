//! Version garbage collection (`04 §5.5`).
//!
//! The GC watermark is the timestamp oracle's **low-water mark**: the oldest active begin timestamp
//! ([`TimestampOracle::low_water_mark`](crate::oracle::TimestampOracle::low_water_mark)). Any version
//! whose `xmax` committed `≤` the watermark is invisible to every live and future snapshot, so its
//! storage (the superseded version / undo delta / freed physical id) is reclaimed and the writer's
//! Active-Transaction-Table and SSI entries may be forgotten.
//!
//! GC is intentionally **decoupled** from the hot path: it is a function the manager (or a
//! background vacuum) invokes; long-running readers hold the watermark back simply by remaining
//! active, which is the correct, automatic behaviour (`04 §5.5`) and is surfaced as an observability
//! signal via [`GcReport`].

use graphus_core::Timestamp;

use crate::snapshot::CommitRegistry;
use crate::store::VersionedStore;

/// What one GC pass reclaimed (observability, NFR-10).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GcReport {
    /// The watermark used (the oldest active begin timestamp; `None` = no active transactions).
    pub low_water: Option<Timestamp>,
    /// Number of physical versions reclaimed.
    pub versions_reclaimed: usize,
    /// Number of settled transactions pruned from the manager's commit registry after the pass
    /// (`rmp` task #59; `0` from [`collect`] itself — the manager's
    /// [`run_gc`](crate::manager::TxnManager::run_gc) fills it in, since the registry prune is the
    /// manager-facing half of GC).
    pub txns_pruned: usize,
}

/// Runs one GC pass over `store` at the given `low_water` watermark, resolving writer outcomes via
/// `registry`. Returns a [`GcReport`].
///
/// This is the store-facing half of GC; the manager additionally forgets fully-dead transactions
/// from its registries (see [`crate::manager`]).
#[must_use]
pub fn collect<S: VersionedStore>(
    store: &mut S,
    low_water: Option<Timestamp>,
    registry: &CommitRegistry,
) -> GcReport {
    let versions_reclaimed = store.gc(low_water, registry);
    GcReport {
        low_water,
        versions_reclaimed,
        txns_pruned: 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::MemVersionedStore;
    use graphus_core::TxnId;

    #[test]
    fn collect_reports_reclaimed_count() {
        let mut s = MemVersionedStore::new();
        let mut reg = CommitRegistry::new();
        s.create_version(1, TxnId(1), b"v1".to_vec()).unwrap();
        s.commit_writer(TxnId(1), Timestamp(10));
        reg.record_commit(TxnId(1), Timestamp(10));
        s.create_version(1, TxnId(2), b"v2".to_vec()).unwrap();
        s.commit_writer(TxnId(2), Timestamp(20));
        reg.record_commit(TxnId(2), Timestamp(20));

        // No active readers -> watermark None -> the dead v1 is reclaimed.
        let report = collect(&mut s, None, &reg);
        assert_eq!(report.versions_reclaimed, 1);
        assert_eq!(report.low_water, None);
        assert_eq!(s.version_count(), 1);
    }
}
