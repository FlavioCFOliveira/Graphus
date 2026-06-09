//! `IndexSet` — an in-memory, token-keyed set of derived secondary indexes (`rmp` task #48).
//!
//! This is the **data-structure layer** for index wiring. An [`IndexSet`] holds:
//!
//! - one always-present **label** [`TokenIndex`] (`(label_token, node_id)`), auto-maintained, that
//!   answers `MATCH (n:Label)` candidate scans; and
//! - a map `(label_token, prop_key) -> ` [`PropertyIndex`] of **declared** node-property indexes
//!   that answer equality and range predicates.
//!
//! # Derived / ephemeral by design (`graphus-index` crate-root seam)
//!
//! Every backing tree lives over an **in-memory** device ([`MemBlockDevice`]) and an in-memory log
//! sink ([`MemLogSink`]): the index set is rebuilt from the record store on open and is never
//! recovered after a crash, so there is no durability requirement here. Consequently the internal
//! WAL transaction id is irrelevant — every op uses a fixed [`TxnId`]`(1)`; the buffer pool applies
//! each mutation to its in-memory page immediately, so reads observe writes without a commit.
//!
//! # Candidates, not answers
//!
//! Like the underlying [`graphus_index`] kinds, every `seek_*` here returns **candidate** record
//! ids and never filters by MVCC visibility, by current label membership, or by the *current* value
//! of the property (an entry may be stale): that re-check is the caller's job (the
//! coordinator/`RecordStoreGraph`). Because the caller re-checks the predicate, returning a
//! **superset** of the truly-matching ids is always correct; returning a subset never is. The range
//! seek deliberately exploits this when a bound cannot be expressed exactly against the backing
//! index (see [`IndexSet::seek_node_property_range`]).

use std::collections::HashMap;

use graphus_bufpool::BufferPool;
use graphus_core::{TxnId, Value};
use graphus_index::recovery::SharedWal;
use graphus_index::{BTree, PropertyIndex, TokenIndex};
use graphus_io::MemBlockDevice;
use graphus_wal::{MemLogSink, WalManager};

/// The in-memory block device the derived indexes are built on.
type Dev = MemBlockDevice;
/// The in-memory log sink the derived indexes' ephemeral WAL is built on.
type Sink = MemLogSink;

/// The fixed transaction id used for every backing-tree op. The WAL is ephemeral and never
/// recovered, so the id carries no meaning; the buffer pool applies each mutation in-memory
/// immediately, so reads see writes without a commit.
const EPHEMERAL_TXN: TxnId = TxnId(1);

/// Buffer-pool capacity (in frames) for each backing tree. Generous enough that a derived index of
/// a modestly sized store stays resident; the pool spills to the in-memory device otherwise.
const POOL_FRAMES: usize = 64;

/// Builds a fresh, empty in-memory [`BTree`] with its own throwaway WAL.
///
/// Each call wires a brand-new [`MemBlockDevice`] + [`MemLogSink`] pair, so trees are fully
/// independent — exactly what [`IndexSet::clear`] needs to drop all entries by recreation.
fn fresh_tree() -> BTree<Dev, Sink> {
    // An in-memory sink + manager: `WalManager::create` over `MemLogSink` cannot fail in practice.
    let wal = WalManager::create(MemLogSink::new())
        .expect("INVARIANT: in-memory WAL creation over MemLogSink is infallible");
    let shared = SharedWal::new(wal);
    let pool = BufferPool::with_wal(MemBlockDevice::new(0), shared.clone(), POOL_FRAMES);
    // An in-memory B+-tree: `BTree::create` over a fresh in-memory pool cannot fail in practice.
    BTree::create(pool, shared).expect("INVARIANT: in-memory BTree creation is infallible")
}

/// An in-memory, token-keyed set of derived secondary indexes over the [`graphus_index`] kinds.
///
/// See the [module docs](self) for the durability / candidate-vs-answer contract. The struct is
/// `!Sync` (it holds `&mut`-driven trees); the coordinator owns it single-threaded.
pub struct IndexSet {
    /// The always-present label scan index, keyed `(label_token, node_id)`.
    labels: TokenIndex<Dev, Sink>,
    /// Declared node-property indexes, keyed by `(label_token, prop_key)`. Each value is keyed
    /// internally on `(prop_key, property_value, node_id)` (`prop_key` is the `PropertyIndex`
    /// token), which is sufficient because the map already partitions by `label_token`.
    node_props: HashMap<(u32, u32), PropertyIndex<Dev, Sink>>,
}

impl IndexSet {
    /// An empty index set: a single label [`TokenIndex`] (always present, auto-maintained) and no
    /// property indexes yet.
    #[must_use]
    pub fn new() -> Self {
        Self {
            labels: TokenIndex::new(fresh_tree()),
            node_props: HashMap::new(),
        }
    }

    /// Declares a node-property index on `(label_token, prop_key)`. Idempotent: a no-op if one is
    /// already registered, otherwise creates the backing [`PropertyIndex`].
    pub fn register_node_property(&mut self, label_token: u32, prop_key: u32) {
        self.node_props
            .entry((label_token, prop_key))
            .or_insert_with(|| PropertyIndex::new(fresh_tree()));
    }

    /// Whether a node-property index is registered for `(label_token, prop_key)`.
    #[must_use]
    pub fn has_node_property(&self, label_token: u32, prop_key: u32) -> bool {
        self.node_props.contains_key(&(label_token, prop_key))
    }

    /// Drops all entries from every index, keeping the registered `(label_token, prop_key)` set, for
    /// a full rebuild from the store. Implemented by recreating each backing tree (the simplest
    /// correct reset for an ephemeral in-memory index).
    pub fn clear(&mut self) {
        self.labels = TokenIndex::new(fresh_tree());
        for idx in self.node_props.values_mut() {
            *idx = PropertyIndex::new(fresh_tree());
        }
    }

    /// Records that node `node_id` carries label `label_token` (a candidate for label scans).
    pub fn insert_label(&mut self, label_token: u32, node_id: u64) {
        // in-memory index: a BTree op cannot fail in practice; an insert failure leaves the entry
        // simply absent (the caller re-checks, so a missing candidate degrades to a full scan, never
        // to a wrong answer).
        let _ = self.labels.insert(EPHEMERAL_TXN, label_token, node_id);
    }

    /// Records that node `node_id` has `value` for the `(label_token, prop_key)` index, if such an
    /// index is registered (else a no-op).
    pub fn insert_node_property(
        &mut self,
        label_token: u32,
        prop_key: u32,
        value: &Value,
        node_id: u64,
    ) {
        if let Some(idx) = self.node_props.get_mut(&(label_token, prop_key)) {
            // in-memory index: a BTree op cannot fail in practice. A `Null` value is unindexable
            // (`PropertyIndex::insert` errors) and is correctly skipped — `Null` properties are
            // absent for index purposes, matching Cypher's treatment in equality/range predicates.
            let _ = idx.insert(EPHEMERAL_TXN, prop_key, value, node_id);
        }
    }

    /// Candidate node ids carrying `label_token`, ascending. The caller re-checks visibility and
    /// current label membership.
    pub fn seek_label(&mut self, label_token: u32) -> Vec<u64> {
        // in-memory index: a BTree op cannot fail in practice; a seek error degrades to no
        // candidates (which the caller turns into a full scan), never to a wrong answer.
        self.labels.scan_token(label_token).unwrap_or_default()
    }

    /// Candidate node ids for `(label_token, prop_key) == value`, ascending. `None` if no such index
    /// is registered. The caller re-checks visibility, current label, and the current value.
    pub fn seek_node_property_eq(
        &mut self,
        label_token: u32,
        prop_key: u32,
        value: &Value,
    ) -> Option<Vec<u64>> {
        let idx = self.node_props.get_mut(&(label_token, prop_key))?;
        // in-memory index: a BTree op cannot fail in practice; a seek error degrades to an empty
        // candidate list. Note this is `Some(vec![])`, not `None`: the index *is* registered, it
        // simply has no matching candidate.
        Some(idx.seek_eq(prop_key, value).unwrap_or_default())
    }

    /// Candidate node ids for `(label_token, prop_key)` within a range, ascending. `None` if no such
    /// index is registered; otherwise a **superset** of the in-range candidates (see below).
    ///
    /// Bounds are `(value, inclusive)`; a `None` bound is unbounded on that side. The caller
    /// re-checks the predicate, so a superset is correct and a subset is not.
    ///
    /// # Bound mapping (superset semantics)
    ///
    /// The backing [`PropertyIndex::seek_range`]`(token, lo, hi)` answers a **half-open** range
    /// `[lo, hi)` over one token: the lower value is **inclusive**, `hi = Some(v)` is **exclusive**,
    /// and `hi = None` is unbounded above. It has no unbounded-below and no exclusive-lower form.
    /// We translate the requested `(lower, upper)` to the *tightest range it can express that is
    /// still a superset* of the request:
    ///
    /// - **Lower** `Some((v, true))` (inclusive) maps exactly to `lo = v`.
    /// - **Lower** `Some((v, false))` (exclusive) cannot be expressed (the backing lower is always
    ///   inclusive), so we widen to `lo = v` (inclusive). This adds at most the `== v` candidates,
    ///   which the caller's predicate re-check then drops.
    /// - **Lower** `None` (unbounded below) cannot be expressed (a concrete `lo` is required), so we
    ///   widen to the smallest indexable value for the token. Because the index stores no `Null`
    ///   keys and orders every other value above the integer/temporal floor, scanning from the most
    ///   negative integer would still miss values that sort *below* integers (e.g. strings, by
    ///   openCypher orderability). To remain a correct **superset**, an unbounded-below request
    ///   therefore returns **all** candidates for the token (the whole index column), which is
    ///   always a superset of any `< upper` request. The caller re-checks the predicate.
    /// - **Upper** `Some((v, false))` (exclusive) maps exactly to `hi = Some(v)`.
    /// - **Upper** `Some((v, true))` (inclusive) cannot be expressed (the backing upper is always
    ///   exclusive), so we widen to `hi = None` (unbounded above). This over-includes everything
    ///   `> v`, which the caller's predicate re-check then drops. (A tighter `next-value` upper is
    ///   not generally constructible for arbitrary `Value`s, so the safe superset is used.)
    /// - **Upper** `None` (unbounded above) maps exactly to `hi = None`.
    ///
    /// Net effect: the returned set always contains every node whose current value satisfies the
    /// requested bounds (assuming its index entry is up to date), and may contain extra candidates
    /// that the caller filters out.
    pub fn seek_node_property_range(
        &mut self,
        label_token: u32,
        prop_key: u32,
        lower: Option<(&Value, bool)>,
        upper: Option<(&Value, bool)>,
    ) -> Option<Vec<u64>> {
        let idx = self.node_props.get_mut(&(label_token, prop_key))?;

        // Map the upper bound: exclusive maps exactly; inclusive widens to unbounded-above (a
        // superset); `None` is unbounded-above.
        let hi: Option<&Value> = match upper {
            Some((v, false)) => Some(v), // exclusive: exact
            Some((_, true)) => None,     // inclusive: widen to unbounded above (superset)
            None => None,                // unbounded above
        };

        let candidates = match lower {
            // Inclusive lower maps exactly; exclusive lower widens to inclusive (superset).
            Some((v, _)) => idx.seek_range(prop_key, v, hi),
            // Unbounded below cannot be expressed against the inclusive-lower backing range without
            // risking a subset (values may sort below the integer floor). Return all candidates for
            // the token — always a superset of any `< upper` request.
            None => Self::all_candidates(idx, prop_key),
        };

        // in-memory index: a BTree op cannot fail in practice; a seek error degrades to an empty
        // candidate list (still `Some`, since the index is registered).
        Some(candidates.unwrap_or_default())
    }

    /// The label tokens that currently have at least one entry, ascending and de-duplicated. Used to
    /// build the planner's auto token-lookup catalog.
    #[must_use]
    pub fn indexed_label_tokens(&mut self) -> Vec<u32> {
        // `TokenIndex` has no token-enumeration API, so recover the tokens from the label index by
        // scanning the full keyspace via the underlying tree (`scan_all`, ascending). The tree is
        // the only place that holds the per-token keys.
        let mut tokens: Vec<u32> = self
            .labels
            .tree_mut()
            .scan_all()
            .unwrap_or_default()
            .into_iter()
            // Each label key is `(token: u32 BE, element_id: u64 BE)`; the leading 4 bytes are the
            // label token. Anything shorter is not a label key and is skipped defensively.
            .filter_map(|(k, _)| {
                k.get(0..4)
                    .map(|b| u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
            })
            .collect();
        tokens.sort_unstable();
        tokens.dedup();
        tokens
    }

    /// The registered node-property index keys `(label_token, prop_key)`, ascending and
    /// de-duplicated. Used to build the planner's label-property catalog.
    #[must_use]
    pub fn registered_node_properties(&self) -> Vec<(u32, u32)> {
        let mut keys: Vec<(u32, u32)> = self.node_props.keys().copied().collect();
        keys.sort_unstable();
        keys
    }

    /// All candidate ids for `token` in `idx`, regardless of value. Used as the correct
    /// unbounded-below superset (see [`Self::seek_node_property_range`]). Implemented by scanning the
    /// whole keyspace and keeping the entries whose key carries this token in its leading `u32`.
    fn all_candidates(
        idx: &mut PropertyIndex<Dev, Sink>,
        token: u32,
    ) -> graphus_core::error::Result<Vec<u64>> {
        let prefix = token.to_be_bytes();
        Ok(idx
            .tree_mut()
            .scan_all()?
            .into_iter()
            .filter(|(k, _)| k.get(0..4) == Some(&prefix[..]))
            .filter_map(|(_, v)| v.as_slice().try_into().ok().map(u64::from_le_bytes))
            .collect())
    }
}

impl Default for IndexSet {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use graphus_core::Value;

    fn s(v: &str) -> Value {
        Value::String(v.to_owned())
    }

    #[test]
    fn label_insert_then_seek_returns_inserted_ids_ascending() {
        let mut set = IndexSet::new();
        set.insert_label(7, 100);
        set.insert_label(7, 50);
        set.insert_label(9, 200); // different label token

        assert_eq!(set.seek_label(7), vec![50, 100]);
        assert_eq!(set.seek_label(9), vec![200]);
        assert_eq!(set.seek_label(1), Vec::<u64>::new()); // no entries
    }

    #[test]
    fn register_is_idempotent_and_queryable() {
        let mut set = IndexSet::new();
        assert!(!set.has_node_property(1, 2));
        set.register_node_property(1, 2);
        assert!(set.has_node_property(1, 2));
        // Idempotent: registering again does not panic or wipe state.
        set.insert_node_property(1, 2, &Value::Integer(10), 42);
        set.register_node_property(1, 2);
        assert_eq!(
            set.seek_node_property_eq(1, 2, &Value::Integer(10)),
            Some(vec![42])
        );
    }

    #[test]
    fn node_property_eq_returns_matches_and_none_when_unregistered() {
        let mut set = IndexSet::new();
        set.register_node_property(1, 2);
        set.insert_node_property(1, 2, &Value::Integer(10), 1000);
        set.insert_node_property(1, 2, &Value::Integer(10), 1001); // same value, two ids
        set.insert_node_property(1, 2, &Value::Integer(20), 1002);

        let mut got = set
            .seek_node_property_eq(1, 2, &Value::Integer(10))
            .expect("index is registered");
        got.sort_unstable();
        assert_eq!(got, vec![1000, 1001]);

        // Registered but no such value -> Some(empty), not None.
        assert_eq!(
            set.seek_node_property_eq(1, 2, &Value::Integer(999)),
            Some(Vec::<u64>::new())
        );

        // Unregistered (label_token, prop_key) -> None.
        assert_eq!(set.seek_node_property_eq(1, 3, &Value::Integer(10)), None);
        assert_eq!(set.seek_node_property_eq(9, 2, &Value::Integer(10)), None);
    }

    #[test]
    fn insert_node_property_on_unregistered_is_noop() {
        let mut set = IndexSet::new();
        // No register call: insert is a silent no-op and the pair stays unregistered.
        set.insert_node_property(1, 2, &Value::Integer(10), 42);
        assert!(!set.has_node_property(1, 2));
        assert_eq!(set.seek_node_property_eq(1, 2, &Value::Integer(10)), None);
    }

    #[test]
    fn null_value_is_skipped_silently() {
        let mut set = IndexSet::new();
        set.register_node_property(1, 2);
        // Null is unindexable; the insert is a no-op and does not panic.
        set.insert_node_property(1, 2, &Value::Null, 7);
        assert_eq!(
            set.seek_node_property_eq(1, 2, &Value::Null),
            Some(Vec::<u64>::new())
        );
    }

    #[test]
    fn range_returns_superset_of_in_range_ids() {
        let mut set = IndexSet::new();
        set.register_node_property(1, 2);
        set.insert_node_property(1, 2, &Value::Integer(-5), 100);
        set.insert_node_property(1, 2, &Value::Integer(0), 101);
        set.insert_node_property(1, 2, &Value::Integer(10), 102);
        set.insert_node_property(1, 2, &Value::Integer(10), 103); // two ids share value 10
        set.insert_node_property(1, 2, &Value::Integer(20), 104);

        // Helper: a result must be a superset of `expected` (every expected id present), and may
        // contain extras (caller re-checks). It must NEVER be a subset.
        let assert_superset = |got: Vec<u64>, expected: &[u64]| {
            for id in expected {
                assert!(got.contains(id), "missing in-range id {id}; got {got:?}");
            }
        };

        // [0, 20): inclusive lower, exclusive upper -> exact mapping, ids 101, 102, 103.
        let r = set
            .seek_node_property_range(
                1,
                2,
                Some((&Value::Integer(0), true)),
                Some((&Value::Integer(20), false)),
            )
            .expect("registered");
        assert_superset(r.clone(), &[101, 102, 103]);
        assert!(
            !r.contains(&100),
            "{:?} must exclude the < 0 id (exact lower)",
            r
        );

        // [0, 10] inclusive upper -> widens to unbounded-above superset; must include 101,102,103
        // and may include 104.
        let r = set
            .seek_node_property_range(
                1,
                2,
                Some((&Value::Integer(0), true)),
                Some((&Value::Integer(10), true)),
            )
            .expect("registered");
        assert_superset(r, &[101, 102, 103]);

        // (0, 20) exclusive lower -> widens to inclusive lower; superset still contains 101.
        let r = set
            .seek_node_property_range(
                1,
                2,
                Some((&Value::Integer(0), false)),
                Some((&Value::Integer(20), false)),
            )
            .expect("registered");
        assert_superset(r, &[102, 103]); // strictly-in-range ids guaranteed present

        // Unbounded below, exclusive upper 20 -> all candidates < 20 superset (returns whole column,
        // a valid superset); must include 100, 101, 102, 103.
        let r = set
            .seek_node_property_range(1, 2, None, Some((&Value::Integer(20), false)))
            .expect("registered");
        assert_superset(r, &[100, 101, 102, 103]);

        // Unbounded both ways -> the whole column.
        let mut r = set
            .seek_node_property_range(1, 2, None, None)
            .expect("registered");
        r.sort_unstable();
        assert_superset(r, &[100, 101, 102, 103, 104]);

        // Unregistered pair -> None.
        assert_eq!(
            set.seek_node_property_range(1, 3, Some((&Value::Integer(0), true)), None),
            None
        );
    }

    #[test]
    fn range_over_strings_unbounded_below_is_superset() {
        // Strings sort below numbers in openCypher orderability; the unbounded-below path must still
        // return them (it returns the whole column), proving the superset guarantee for a value
        // class that an integer-floor lower bound would have missed.
        let mut set = IndexSet::new();
        set.register_node_property(1, 2);
        set.insert_node_property(1, 2, &s("alice"), 1);
        set.insert_node_property(1, 2, &s("bob"), 2);

        let r = set
            .seek_node_property_range(1, 2, None, Some((&s("zzz"), false)))
            .expect("registered");
        assert!(
            r.contains(&1) && r.contains(&2),
            "superset must include both strings; got {r:?}"
        );
    }

    #[test]
    fn clear_empties_then_reinsert_works() {
        let mut set = IndexSet::new();
        set.register_node_property(1, 2);
        set.insert_label(7, 100);
        set.insert_node_property(1, 2, &Value::Integer(10), 42);
        assert_eq!(set.seek_label(7), vec![100]);
        assert_eq!(
            set.seek_node_property_eq(1, 2, &Value::Integer(10)),
            Some(vec![42])
        );

        set.clear();
        // Entries gone, but the registered set is preserved.
        assert_eq!(set.seek_label(7), Vec::<u64>::new());
        assert_eq!(
            set.seek_node_property_eq(1, 2, &Value::Integer(10)),
            Some(Vec::<u64>::new())
        );
        assert!(set.has_node_property(1, 2));

        // Re-insert after clear works.
        set.insert_label(7, 200);
        set.insert_node_property(1, 2, &Value::Integer(10), 99);
        assert_eq!(set.seek_label(7), vec![200]);
        assert_eq!(
            set.seek_node_property_eq(1, 2, &Value::Integer(10)),
            Some(vec![99])
        );
    }

    #[test]
    fn indexed_label_tokens_lists_nonempty_tokens_sorted_deduped() {
        let mut set = IndexSet::new();
        assert_eq!(set.indexed_label_tokens(), Vec::<u32>::new());
        set.insert_label(9, 1);
        set.insert_label(7, 2);
        set.insert_label(7, 3); // duplicate token, distinct node
        let tokens = set.indexed_label_tokens();
        assert_eq!(tokens, vec![7, 9]);
    }

    #[test]
    fn registered_node_properties_lists_keys_sorted() {
        let mut set = IndexSet::new();
        assert_eq!(set.registered_node_properties(), Vec::<(u32, u32)>::new());
        set.register_node_property(2, 5);
        set.register_node_property(1, 9);
        set.register_node_property(1, 3);
        assert_eq!(
            set.registered_node_properties(),
            vec![(1, 3), (1, 9), (2, 5)]
        );
    }
}
