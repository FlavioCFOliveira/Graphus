//! **Read polarity** — which of three answers a storage read is required to give, and the types that
//! keep them apart (`rmp` task #905).
//!
//! Every read of the record store returns *physical* state: whatever occupies the slot at that
//! instant, including MVCC tombstones the GC has not reclaimed, versions written by transactions that
//! have not committed, and (for labels, which are mutated in place) a word that a rollback will change
//! back. Nothing about that raw image is wrong. What is wrong — three times over, in `rmp` tasks #902,
//! #904 and #771 — is using one polarity's read where another polarity's answer was required.
//!
//! The three polarities are not two ends of a scale. They are three different obligations:
//!
//! | Polarity | Obligation | Who re-checks | What a wrong answer costs |
//! |---|---|---|---|
//! | **Superset** | the result must CONTAIN every row any snapshot could need | the consumer, against its own snapshot | a missing row is unrecoverable; an extra row is dropped by the re-check |
//! | **Decision** | the result must be EXACTLY what the deciding snapshot sees | nobody | a wrong row is committed into the schema or into a uniqueness verdict |
//! | **Conservative** | the result must never EXCLUDE on state that is not proven | nobody, for the excluded range | an excluded range disappears before any re-check runs |
//!
//! # Superset — index population
//!
//! An index built by a refill has **no reader and therefore no snapshot**. It populates a *candidate*
//! structure, and every consumer re-checks each candidate against its own snapshot. The asymmetry that
//! makes that safe is one-directional: **a re-check can REMOVE a candidate, but it can never RESURRECT
//! one.** So the only image a candidate structure may hold is a superset of every row any snapshot can
//! ask for. Reading raw is not a concession here, it is the requirement:
//! `TxnCoordinator::index_one_node` indexes **every** property version with no visibility filter on
//! purpose (`rmp` task #766), and the label gate is the live-OR-retained union
//! [`RecordStore::node_label_superset`](crate::RecordStore::node_label_superset), not the live word
//! (`rmp` task #904), because the live word is a *subset* while an uncommitted `REMOVE n:L` is open.
//!
//! # Decision — constraint validation
//!
//! A `CREATE CONSTRAINT` walk is the opposite. It does not produce candidates, it produces a verdict
//! that is then written durably into the catalogue, and **nothing downstream re-checks it**. It must
//! therefore see exactly the graph a `MATCH` in the same transaction would see: the same visibility
//! predicate ([`graphus_txn::is_visible`]), resolved against the same [`Snapshot`]. Reading raw there
//! counted a committed `REMOVE n.email` as a present value, so `IS UNIQUE` was refused over a duplicate
//! no query could find and `IS NOT NULL` was accepted over a property that was gone (`rmp` task #902).
//!
//! # Conservative — data-skipping structures
//!
//! A zone map is neither. It **prunes**: the per-row re-check only ever runs on the ids
//! `candidate_ranges_eq` did *not* prune, so a narrowed zone removes a whole id range before any
//! re-check can see it, and nothing rebuilds a zone map afterwards. A pruning structure may therefore
//! only ever narrow on state it can prove, which in practice means its rebuild takes the same superset
//! gates an index refill takes and never the current image: the live-OR-retained label union rather
//! than the live word (`rmp` task #904), and **every** property version rather than the chain head
//! (`rmp` task #958) — both in `TxnCoordinator::rebuild_zone_column`. A rebuild whose scan faults
//! abandons the column rather than summarising the part of the store it could read.
//!
//! The obligation has a second half that is easy to miss, because it is not about the summary at all:
//! the structure must produce **candidates**, and the per-candidate re-check that turns them into rows
//! must run at the reader's snapshot. `rmp` #958 was exactly that miss — the skip query re-checked its
//! candidates against the raw live label word and `mvcc.in_use()` and then returned *rows*, so an
//! uncommitted creation was served to every reader and an uncommitted `REMOVE n:L` hid a committed one,
//! with nothing downstream able to repair either. The re-check therefore lives on the seam that owns
//! the `(Snapshot, CommitRegistry)` pair (`RecordStoreGraph::zone_scan_eq`, sharing the same
//! `index_seek_eq_recheck` body as every node equality seek), never on the coordinator, which has no
//! snapshot to resolve against.
//!
//! # What this module enforces
//!
//! The property-chain axis — the one the `rmp` #902 defect lived on — is separated in the type system:
//!
//! * [`SupersetProperties`] is what a raw chain read returns. It is not a `Vec` and does not
//!   dereference to one; reaching the records means naming the polarity out loud
//!   ([`every_version`](SupersetProperties::every_version), which says in its own name that MVCC
//!   tombstones and uncommitted versions are included).
//! * [`DecidedProperties`] is what a decision path must hold. It has **no public constructor**: the
//!   only way to obtain one is [`SupersetProperties::decide`], which takes a [`Snapshot`] and a
//!   [`CommitRegistry`]. A decision helper that takes `&DecidedProperties` therefore cannot be handed
//!   a raw chain — that is a type error, not a review finding.
//!
//! The label axis is separated by *signature* rather than by type, and was already so before this
//! module existed: the decision-grade read
//! [`RecordStore::label_bitmap_at`](crate::RecordStore::label_bitmap_at) cannot be called without a
//! `(Snapshot, &CommitRegistry)` pair, and the superset-grade read
//! [`RecordStore::node_label_superset`](crate::RecordStore::node_label_superset) says its polarity in
//! its name. What is *not* prevented by the compiler is a population path reaching for the live-word
//! read [`RecordStore::node_labels`](crate::RecordStore::node_labels), which is what `rmp` task #904
//! did; that direction is held by the census test
//! `graphus-cypher/tests/read_polarity_census.rs`, which also carries the reviewer-facing record of
//! every call site that reads raw on purpose.

use graphus_txn::{CommitRegistry, Snapshot, is_visible};

use crate::record::PropRecord;

/// One entity's property chain exactly as it sits in the store: **every slot-occupied version**, head
/// to tail (`rmp` task #905).
///
/// The chain is prepend-ordered, so the first occurrence of a key is its newest version. It carries
/// MVCC tombstones (a removed or overwritten version keeps its slot until [`gc`](crate::RecordStore::gc)
/// reclaims it, and GC has no automatic trigger — `rmp` #305), versions written by transactions that
/// have not committed, and versions written by transactions that aborted and whose rollback has not yet
/// landed.
///
/// This is the **superset** polarity of the module docs. It is the right read for an index refill and
/// the wrong read for a decision; to make a decision, call [`decide`](Self::decide), which requires the
/// snapshot the decision is being made under.
#[derive(Debug, Clone)]
pub struct SupersetProperties {
    /// The raw chain, head to tail (newest-first per key).
    versions: Vec<(u64, PropRecord)>,
}

impl SupersetProperties {
    /// Wraps a chain a store read just walked. Crate-private on purpose: a value of this type is a
    /// claim that these records came off the store, so nothing outside the storage crate may mint one.
    #[must_use]
    pub(crate) fn from_chain(versions: Vec<(u64, PropRecord)>) -> Self {
        Self { versions }
    }

    /// Every `(physical_id, record)` in the chain — **MVCC tombstones and uncommitted versions
    /// included**, head to tail.
    ///
    /// The name is the point. A caller that needs the superset says so here; a caller that needed a
    /// decision has to reach for [`decide`](Self::decide) instead, because this slice answers a
    /// different question from the one a `MATCH` would.
    #[must_use]
    pub fn every_version(&self) -> &[(u64, PropRecord)] {
        &self.versions
    }

    /// [`every_version`](Self::every_version), by value, for a caller that consumes the chain.
    #[must_use]
    pub fn into_every_version(self) -> Vec<(u64, PropRecord)> {
        self.versions
    }

    /// How many versions the chain holds (tombstones included).
    #[must_use]
    pub fn len(&self) -> usize {
        self.versions.len()
    }

    /// Whether the entity has no property record at all.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.versions.is_empty()
    }

    /// Narrows the chain to what `snapshot` sees: **the newest visible version of each key**, and
    /// nothing else (`rmp` task #905).
    ///
    /// This is the superset → decision conversion, and the only way a [`DecidedProperties`] comes into
    /// existence — which is what makes "a decision path must hold a snapshot" a property of the type
    /// system rather than of a comment.
    ///
    /// The rule is the one the read path applies: the chain is prepend-ordered, so the **first** version
    /// of a key that [`is_visible`] accepts is the one that decides, and a key whose every version is
    /// invisible is absent. Exactly one version of a key can be visible to a given snapshot anyway (a
    /// `SET` stamps the new version's `xmin` and the old version's `xmax` with the same transaction), so
    /// the newest-wins fold resolves a single value rather than choosing among several.
    ///
    /// Values are **not** decoded here. A decision path that needs one key must not be made to fail on
    /// an unreadable overflow chain belonging to an unrelated property (`rmp` task #733), so decoding
    /// stays with the caller, one key at a time.
    #[must_use]
    pub fn decide(self, snapshot: Snapshot, registry: &CommitRegistry) -> DecidedProperties {
        let mut visible: Vec<(u64, PropRecord)> = Vec::new();
        for (pid, prop) in self.versions {
            if !is_visible(
                snapshot,
                prop.mvcc.created_ts,
                prop.mvcc.expired_ts,
                registry,
            ) {
                continue;
            }
            // Prepend order: a key already resolved has been resolved to its newest visible version.
            if visible.iter().any(|(_, kept)| kept.key == prop.key) {
                continue;
            }
            visible.push((pid, prop));
        }
        DecidedProperties { snapshot, visible }
    }
}

/// One entity's properties **as of a snapshot**: at most one version per key, and exactly the versions
/// a `MATCH` under that snapshot would resolve (`rmp` task #905).
///
/// This is the **decision** polarity of the module docs — the only image a constraint validation, or
/// any other read whose answer is final and never re-checked, may be built on.
///
/// # It cannot be constructed without a snapshot
///
/// The fields are private and there is no public constructor; the sole way to obtain a value is
/// [`SupersetProperties::decide`], which takes the [`Snapshot`] and the [`CommitRegistry`] the
/// narrowing is performed against. A helper that accepts `&DecidedProperties` therefore cannot be
/// handed the raw chain, and the `rmp` #902 defect — a raw chain resolved first-occurrence-wins into a
/// constraint verdict — does not compile against this API.
#[derive(Debug, Clone)]
pub struct DecidedProperties {
    /// The snapshot the narrowing was performed against, retained so a caller can assert the decision
    /// and the walk agree on it.
    snapshot: Snapshot,
    /// The newest visible version of each key the entity holds, in chain order.
    visible: Vec<(u64, PropRecord)>,
}

impl DecidedProperties {
    /// The version of `prop_key` this snapshot sees, or [`None`] when the entity does not hold that
    /// key in this snapshot — because it never had it, because a visible removal expired it, or
    /// because the only versions of it belong to transactions this snapshot cannot see.
    #[must_use]
    pub fn visible_version(&self, prop_key: u32) -> Option<&PropRecord> {
        self.visible
            .iter()
            .find(|(_pid, prop)| prop.key == prop_key)
            .map(|(_pid, prop)| prop)
    }

    /// Every key the entity holds in this snapshot, as `(physical_id, record)` pairs — one per key.
    #[must_use]
    pub fn visible_versions(&self) -> &[(u64, PropRecord)] {
        &self.visible
    }

    /// The snapshot this view was narrowed against.
    #[must_use]
    pub fn snapshot(&self) -> Snapshot {
        self.snapshot
    }

    /// How many distinct keys the entity holds in this snapshot.
    #[must_use]
    pub fn len(&self) -> usize {
        self.visible.len()
    }

    /// Whether the entity holds no property at all in this snapshot.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.visible.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use graphus_core::{Timestamp, TxnId, VersionStamp};

    use super::*;
    use crate::record::MvccHeader;

    /// A property version of `key` stamped `(xmin, xmax)`, at physical id `pid`.
    fn version(pid: u64, key: u32, xmin: u64, xmax: u64) -> (u64, PropRecord) {
        (
            pid,
            PropRecord {
                mvcc: MvccHeader {
                    flags: crate::record::FLAG_IN_USE,
                    created_ts: xmin,
                    expired_ts: xmax,
                    undo_ptr: 0,
                },
                key,
                type_tag: 0,
                value_inline: u64::from(key),
                next_prop: 0,
            },
        )
    }

    /// A snapshot at `ts` owned by `owner`.
    fn snapshot_at(owner: u64, ts: u64) -> Snapshot {
        Snapshot {
            owner: TxnId(owner),
            ts: Timestamp(ts),
        }
    }

    #[test]
    fn the_superset_hands_back_every_version_tombstones_included() {
        let chain = SupersetProperties::from_chain(vec![
            version(2, 7, Timestamp(20).0, 0),
            version(1, 7, Timestamp(10).0, Timestamp(20).0),
        ]);
        assert_eq!(chain.len(), 2);
        assert!(!chain.is_empty());
        assert_eq!(chain.every_version().len(), 2, "the tombstone is included");
        assert_eq!(chain.into_every_version().len(), 2);
    }

    /// THE `rmp` #902 SHAPE. Prepend order alone answers "the newest version of key 7 is the one at
    /// physical id 2"; only the visibility narrowing answers "and the entity no longer holds key 7 at
    /// all, because that version is a committed removal".
    #[test]
    fn a_committed_removal_leaves_the_key_absent_in_the_decision() {
        let registry = CommitRegistry::default();
        // Key 7 was written at ts 10 and removed at ts 20; the version keeps its slot.
        let chain =
            SupersetProperties::from_chain(vec![version(1, 7, Timestamp(10).0, Timestamp(20).0)]);
        let decided = chain.decide(snapshot_at(9, 30), &registry);
        assert!(
            decided.visible_version(7).is_none(),
            "a committed removal must not be resolvable as a present value",
        );
        assert!(decided.is_empty());
    }

    /// The same chain, read by a snapshot that predates the removal, still resolves the old version —
    /// the narrowing is a snapshot question, not a "newest committed" question.
    #[test]
    fn an_older_snapshot_still_sees_the_version_the_removal_expired() {
        let registry = CommitRegistry::default();
        let chain =
            SupersetProperties::from_chain(vec![version(1, 7, Timestamp(10).0, Timestamp(20).0)]);
        let decided = chain.decide(snapshot_at(9, 15), &registry);
        assert_eq!(decided.visible_version(7).map(|p| p.value_inline), Some(7));
        assert_eq!(decided.len(), 1);
        assert_eq!(decided.snapshot().ts, Timestamp(15));
    }

    /// An in-flight writer's version is invisible to everyone else, so the decision resolves the
    /// committed one underneath it rather than the newest slot in the chain. Its uncommitted removal
    /// of that older version does not hide it either — which is the half the `rmp` #902 raw
    /// `expired_ts != 0` test got wrong.
    #[test]
    fn an_uncommitted_version_does_not_win_the_decision() {
        let mut registry = CommitRegistry::default();
        registry.register_begin(TxnId(5));
        let chain = SupersetProperties::from_chain(vec![
            // Newest slot: written by an in-flight TxnId(5), which also expired the older version.
            version(2, 7, VersionStamp::in_flight(TxnId(5)), 0),
            version(1, 7, Timestamp(10).0, VersionStamp::in_flight(TxnId(5))),
        ]);
        let decided = chain.decide(snapshot_at(9, 30), &registry);
        assert_eq!(
            decided.visible_version(7).map(|p| p.value_inline),
            Some(7),
            "the committed version is the one this snapshot holds",
        );
        assert_eq!(
            decided.visible_versions().len(),
            1,
            "one version per key, never both",
        );
    }

    /// Newest-visible-**wins per key**: two different keys each resolve independently, and the older
    /// version of a key that has a newer visible one never surfaces.
    #[test]
    fn each_key_resolves_to_its_own_newest_visible_version() {
        let registry = CommitRegistry::default();
        let chain = SupersetProperties::from_chain(vec![
            version(3, 7, Timestamp(20).0, 0),
            version(2, 8, Timestamp(10).0, 0),
            version(1, 7, Timestamp(10).0, Timestamp(20).0),
        ]);
        let decided = chain.decide(snapshot_at(9, 30), &registry);
        assert_eq!(decided.len(), 2);
        assert_eq!(decided.visible_version(7).map(|p| p.value_inline), Some(7));
        assert_eq!(decided.visible_version(8).map(|p| p.value_inline), Some(8));
        assert!(decided.visible_version(9).is_none());
    }
}
