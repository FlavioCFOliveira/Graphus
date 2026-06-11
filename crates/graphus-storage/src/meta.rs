//! The metadata page (device page `0`): the durable root of all in-memory store state
//! (`04-technical-design.md` §2.1, §2.6, §2.7).
//!
//! Every store's in-memory state — physical-id high-water marks, free lists, the token
//! dictionaries, the [`ElementId`](graphus_core::ElementId) seed, and each store's
//! store-relative-page → device-page map — is rooted in a single metadata page so the whole
//! catalog can be re-derived on recovery by reloading one page. Mutations to it go through the
//! WAL like any other page (`04 §2.6`: token creation is WAL-logged), so a crash mid-write
//! recovers atomically.
//!
//! The metadata payload is a self-describing, length-prefixed serialization that lives entirely
//! within one page's payload (`05 §6`); the encoder asserts it fits.

use std::collections::BTreeMap;

use graphus_core::error::{GraphusError, Result};

use crate::idalloc::FreeList;
use crate::store::STORE_COUNT;
use crate::tokens::TokenStore;

/// The durable catalog stored in the metadata page.
///
/// Holds, for each of the three record stores, the physical-id high-water mark, the free list,
/// and the store-relative-page → device-`PageId` map; plus the shared token store and the
/// next `ElementId` to allocate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Meta {
    /// Next `ElementId` to allocate (never-reused monotonic counter, `04 §2.2`).
    pub element_id_next: u128,
    /// The largest MVCC commit timestamp issued so far (`04 §5.2`). Persisted so the timestamp
    /// oracle resumes strictly monotonically after reopen/recovery — a reader's snapshot and a new
    /// committer's timestamp must never alias or regress past a durable committed version.
    pub commit_ts_hw: u64,
    /// Per-store state, indexed by [`StoreKind`](crate::store::StoreKind) `as usize` (the node, rel
    /// and prop stores plus the `strings.store` overflow heap, `04 §2.1`).
    pub stores: [StoreMeta; STORE_COUNT],
    /// The token dictionaries (`04 §2.6`).
    pub tokens: TokenStore,
    /// Exact, persisted live-record cardinalities for the planner's cardinality estimator
    /// (`rmp` task #79): per-label node counts and per-relationship-type counts.
    pub statistics: Statistics,
}

/// Exact live-record cardinalities maintained in the durable catalog (`rmp` task #79).
///
/// Holds, for the planner's cardinality estimator, how many currently-**live** nodes carry each
/// [`Label`](crate::tokens::Namespace::Label)-namespace token id, and how many currently-live
/// relationships have each [`RelType`](crate::tokens::Namespace::RelType)-namespace token id, so the
/// planner gets exact cardinalities by an O(1) lookup with no scan.
///
/// # What "live" means here, and why it is crash- and abort-safe
///
/// A record is *live* for counting exactly when it is the latest visible version: its slot is in use
/// **and** it carries no MVCC expiry tombstone (`xmax == 0`) — the
/// [`RecordStore::is_live_version`](crate::RecordStore) predicate. The store therefore adjusts these
/// counts on the **committed transition** that changes a record's live label/type contribution:
/// `create_rel` increments; `delete_node`/`delete_rel` (which stamp the `xmax` tombstone, `04 §5.3`)
/// decrement; `set_node_labels`/`add_label`/`remove_label` adjust the per-label delta on a live node.
/// GC reclamation ([`reclaim_node`](crate::RecordStore)/[`reclaim_rel`](crate::RecordStore)) does
/// **not** touch the counts — the decrement already happened at the tombstone-stamping delete.
///
/// Because the whole catalog (this struct included) is persisted only at commit by
/// [`checkpoint_meta`](crate::RecordStore) and reloaded wholesale on rollback and on
/// [`open`](crate::RecordStore) (post-recovery) from the durable metadata page, these counts follow
/// the **identical** durability lifecycle as the id high-water marks and free lists: an aborted
/// transaction's in-memory increments/decrements are discarded by the catalog reload, and a crash
/// recovers the last committed counts. No path overcounts on abort or double-counts on replay.
///
/// # Determinism and the zero-count invariant
///
/// The maps are [`BTreeMap`]s so the encoding (and [`PartialEq`]) is deterministic. A token id whose
/// count reaches `0` is **removed** from the map rather than left at `0`, so equality against a fresh
/// full re-scan (which only ever inserts positive counts) always holds.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Statistics {
    /// `nodes_per_label[t]` is the number of currently-live nodes carrying the `Label`-namespace
    /// token id `t`. A node with `k` labels contributes `1` to each of its `k` entries; an unlabelled
    /// node contributes to none. Absent key == count `0`.
    pub nodes_per_label: BTreeMap<u32, u64>,
    /// `rels_per_type[t]` is the number of currently-live relationships whose `RelType`-namespace
    /// token id is `t`. Absent key == count `0`.
    pub rels_per_type: BTreeMap<u32, u64>,
}

impl Statistics {
    /// An empty statistics catalog (every count `0`).
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The number of currently-live nodes carrying the label `token_id` (`0` if none).
    #[must_use]
    pub fn node_count_for_label(&self, token_id: u32) -> u64 {
        self.nodes_per_label.get(&token_id).copied().unwrap_or(0)
    }

    /// The number of currently-live relationships of relationship-type `token_id` (`0` if none).
    #[must_use]
    pub fn rel_count_for_type(&self, token_id: u32) -> u64 {
        self.rels_per_type.get(&token_id).copied().unwrap_or(0)
    }

    /// Adds `1` to the live-node count for label `token_id`.
    pub(crate) fn inc_label(&mut self, token_id: u32) {
        *self.nodes_per_label.entry(token_id).or_insert(0) += 1;
    }

    /// Subtracts `1` from the live-node count for label `token_id`, removing the entry when it
    /// reaches `0` so equality against a fresh re-scan holds (the zero-count invariant).
    ///
    /// # Panics
    /// Panics (debug builds) if the count is already `0` or absent: that is an internal invariant
    /// violation — every decrement must correspond to a prior increment of a live node's label.
    pub(crate) fn dec_label(&mut self, token_id: u32) {
        Self::dec(&mut self.nodes_per_label, token_id);
    }

    /// Adds `1` to the live-relationship count for relationship-type `token_id`.
    pub(crate) fn inc_rel_type(&mut self, token_id: u32) {
        *self.rels_per_type.entry(token_id).or_insert(0) += 1;
    }

    /// Subtracts `1` from the live-relationship count for relationship-type `token_id`, removing the
    /// entry when it reaches `0` (the zero-count invariant).
    ///
    /// # Panics
    /// Panics (debug builds) if the count is already `0` or absent (an internal invariant violation).
    pub(crate) fn dec_rel_type(&mut self, token_id: u32) {
        Self::dec(&mut self.rels_per_type, token_id);
    }

    /// Shared decrement-with-removal: `count -= 1`, dropping the entry at `0`. In a release build a
    /// missing/zero entry saturates at `0` (never wraps to a huge count) so a logic slip can never
    /// silently corrupt the catalog into an absurd cardinality; in a debug build it is caught.
    fn dec(map: &mut BTreeMap<u32, u64>, token_id: u32) {
        match map.get_mut(&token_id) {
            Some(c) if *c > 1 => *c -= 1,
            Some(_) => {
                map.remove(&token_id);
            }
            None => {
                debug_assert!(
                    false,
                    "statistics decrement underflow for token id {token_id}"
                );
            }
        }
    }

    /// Serialises the statistics to a self-describing byte image.
    ///
    /// Layout: `n_labels(u32) | [ token_id(u32) | count(u64) ]* | n_types(u32) | [ token_id(u32) |
    /// count(u64) ]*`, each map in ascending-token-id ([`BTreeMap`]) order so the image is
    /// deterministic.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out =
            Vec::with_capacity(8 + self.nodes_per_label.len() * 12 + self.rels_per_type.len() * 12);
        Self::encode_map(&mut out, &self.nodes_per_label);
        Self::encode_map(&mut out, &self.rels_per_type);
        out
    }

    fn encode_map(out: &mut Vec<u8>, map: &BTreeMap<u32, u64>) {
        out.extend_from_slice(&(map.len() as u32).to_le_bytes());
        for (&token_id, &count) in map {
            out.extend_from_slice(&token_id.to_le_bytes());
            out.extend_from_slice(&count.to_le_bytes());
        }
    }

    /// Rebuilds the statistics from an image produced by [`encode`](Self::encode).
    ///
    /// # Errors
    /// Returns a storage error if the image is truncated, a count is `0` (violates the zero-count
    /// invariant — such an image was never produced by [`encode`](Self::encode)), or a token id
    /// appears twice in one map.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut cur = 0usize;
        let nodes_per_label = Self::decode_map(bytes, &mut cur, "nodes_per_label")?;
        let rels_per_type = Self::decode_map(bytes, &mut cur, "rels_per_type")?;
        Ok(Self {
            nodes_per_label,
            rels_per_type,
        })
    }

    fn decode_map(bytes: &[u8], cur: &mut usize, which: &str) -> Result<BTreeMap<u32, u64>> {
        let n = read_u32(bytes, cur)? as usize;
        let mut map = BTreeMap::new();
        for _ in 0..n {
            let token_id = read_u32(bytes, cur)?;
            let count = read_u64(bytes, cur)?;
            if count == 0 {
                return Err(GraphusError::Storage(format!(
                    "statistics {which} holds a zero count for token id {token_id}"
                )));
            }
            if map.insert(token_id, count).is_some() {
                return Err(GraphusError::Storage(format!(
                    "statistics {which} repeats token id {token_id}"
                )));
            }
        }
        Ok(map)
    }
}

/// Durable per-store catalog: id high-water mark, free list, and the device-page map.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct StoreMeta {
    /// Physical-id high-water mark — one past the largest id ever allocated (`04 §2.2`).
    pub high_water: u64,
    /// Stack of freed physical ids available for reuse (`04 §2.7`).
    pub free_list: FreeList,
    /// `device_pages[i]` is the device `PageId` holding this store's store-relative page `i`.
    pub device_pages: Vec<u64>,
}

impl Meta {
    /// A fresh catalog with the given `ElementId` seed, empty stores and tokens.
    #[must_use]
    pub fn new(element_id_seed: u128) -> Self {
        Self {
            element_id_next: element_id_seed,
            commit_ts_hw: 0,
            stores: Default::default(),
            tokens: TokenStore::new(),
            statistics: Statistics::new(),
        }
    }

    /// Serialises the catalog into a flat byte buffer.
    ///
    /// The buffer is persisted by [`RecordStore::checkpoint_meta`](crate::RecordStore) across a
    /// singly-linked **chain** of metadata pages rooted at the metadata page (`rmp` task #51), so
    /// the catalog is no longer bounded by a single page payload — a store can grow to many
    /// thousands of record pages (whose device-page maps dominate this buffer) without overflow.
    ///
    /// # Errors
    /// Currently infallible; returns [`Result`] for symmetry with [`decode`](Self::decode) and to
    /// keep the signature stable if a future encoding step can fail.
    pub fn encode(&self) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        out.extend_from_slice(&self.element_id_next.to_le_bytes());
        out.extend_from_slice(&self.commit_ts_hw.to_le_bytes());
        for s in &self.stores {
            out.extend_from_slice(&s.high_water.to_le_bytes());
            let fl = s.free_list.encode();
            out.extend_from_slice(&(fl.len() as u32).to_le_bytes());
            out.extend_from_slice(&fl);
            out.extend_from_slice(&(s.device_pages.len() as u32).to_le_bytes());
            for &p in &s.device_pages {
                out.extend_from_slice(&p.to_le_bytes());
            }
        }
        let tok = self.tokens.encode();
        out.extend_from_slice(&(tok.len() as u32).to_le_bytes());
        out.extend_from_slice(&tok);
        // Statistics are appended after the tokens (`rmp` task #79). Length-prefixed like the token
        // image so a future field can follow without ambiguity.
        let stats = self.statistics.encode();
        out.extend_from_slice(&(stats.len() as u32).to_le_bytes());
        out.extend_from_slice(&stats);
        Ok(out)
    }

    /// Rebuilds a catalog from a metadata payload produced by [`encode`](Self::encode).
    ///
    /// # Errors
    /// Returns a storage error if the payload is truncated or malformed.
    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let mut cur = 0usize;
        let element_id_next = read_u128(bytes, &mut cur)?;
        let commit_ts_hw = read_u64(bytes, &mut cur)?;
        let mut stores: [StoreMeta; STORE_COUNT] = Default::default();
        for s in &mut stores {
            s.high_water = read_u64(bytes, &mut cur)?;
            let fl_len = read_u32(bytes, &mut cur)? as usize;
            let fl_end = take(bytes, &mut cur, fl_len)?;
            s.free_list = FreeList::decode(&bytes[cur - fl_len..fl_end])?;
            let n_pages = read_u32(bytes, &mut cur)? as usize;
            s.device_pages = Vec::with_capacity(n_pages);
            for _ in 0..n_pages {
                s.device_pages.push(read_u64(bytes, &mut cur)?);
            }
        }
        let tok_len = read_u32(bytes, &mut cur)? as usize;
        let tok_end = take(bytes, &mut cur, tok_len)?;
        let tokens = TokenStore::decode(&bytes[cur - tok_len..tok_end])?;
        // Statistics follow the tokens (`rmp` task #79).
        let stats_len = read_u32(bytes, &mut cur)? as usize;
        let stats_end = take(bytes, &mut cur, stats_len)?;
        let statistics = Statistics::decode(&bytes[cur - stats_len..stats_end])?;
        Ok(Self {
            element_id_next,
            commit_ts_hw,
            stores,
            tokens,
            statistics,
        })
    }
}

fn take(bytes: &[u8], cur: &mut usize, len: usize) -> Result<usize> {
    let end = cur
        .checked_add(len)
        .filter(|&e| e <= bytes.len())
        .ok_or_else(|| GraphusError::Storage("metadata truncated".to_owned()))?;
    *cur = end;
    Ok(end)
}

fn read_u32(b: &[u8], cur: &mut usize) -> Result<u32> {
    let end = take(b, cur, 4)?;
    Ok(u32::from_le_bytes(b[end - 4..end].try_into().expect("4")))
}

fn read_u64(b: &[u8], cur: &mut usize) -> Result<u64> {
    let end = take(b, cur, 8)?;
    Ok(u64::from_le_bytes(b[end - 8..end].try_into().expect("8")))
}

fn read_u128(b: &[u8], cur: &mut usize) -> Result<u128> {
    let end = take(b, cur, 16)?;
    Ok(u128::from_le_bytes(
        b[end - 16..end].try_into().expect("16"),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::paging::PAGE_PAYLOAD;
    use crate::tokens::Namespace;

    #[test]
    fn empty_meta_round_trips() {
        let m = Meta::new(1);
        let back = Meta::decode(&m.encode().unwrap()).unwrap();
        assert_eq!(back, m);
    }

    #[test]
    fn populated_meta_round_trips() {
        let mut m = Meta::new(0x1234_5678_9ABC);
        m.stores[0].high_water = 9;
        m.stores[0].free_list.push(3);
        m.stores[0].free_list.push(7);
        m.stores[0].device_pages = vec![1, 4, 9];
        m.stores[1].high_water = 2;
        m.stores[1].device_pages = vec![2];
        m.stores[2].device_pages = vec![3, 5];
        // The strings.store overflow heap (`rmp` task #43) is the fourth catalog store.
        m.stores[3].high_water = 4;
        m.stores[3].free_list.push(2);
        m.stores[3].device_pages = vec![6, 7];
        m.tokens.intern(Namespace::Label, "Person").unwrap();
        m.tokens.intern(Namespace::RelType, "KNOWS").unwrap();
        // Populate the statistics catalog too (`rmp` task #79) so its round-trip is exercised here.
        m.statistics.inc_label(0); // Person: 2 live nodes
        m.statistics.inc_label(0);
        m.statistics.inc_label(5); // another label token: 1 live node
        m.statistics.inc_rel_type(0); // KNOWS: 3 live rels
        m.statistics.inc_rel_type(0);
        m.statistics.inc_rel_type(0);

        let back = Meta::decode(&m.encode().unwrap()).unwrap();
        assert_eq!(back, m);
        assert_eq!(back.tokens.id(Namespace::Label, "Person"), Some(0));
        assert_eq!(back.statistics.node_count_for_label(0), 2);
        assert_eq!(back.statistics.node_count_for_label(5), 1);
        assert_eq!(back.statistics.rel_count_for_type(0), 3);
    }

    #[test]
    fn statistics_round_trip_and_zero_count_invariant() {
        let mut s = Statistics::new();
        assert_eq!(s.node_count_for_label(7), 0);
        s.inc_label(7);
        s.inc_label(7);
        s.inc_rel_type(3);
        // Decrementing to 0 removes the entry (zero-count invariant): the map must not linger a 0.
        s.dec_rel_type(3);
        assert!(s.rels_per_type.is_empty(), "a 0 count must not linger");
        s.dec_label(7);
        assert_eq!(s.node_count_for_label(7), 1);

        let back = Statistics::decode(&s.encode()).unwrap();
        assert_eq!(back, s);
        assert_eq!(back.node_count_for_label(7), 1);
    }

    #[test]
    fn statistics_decode_rejects_a_zero_count() {
        // A hand-built image with an explicit 0 count must be rejected (encode never produces one).
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&1u32.to_le_bytes()); // 1 label entry
        bytes.extend_from_slice(&4u32.to_le_bytes()); // token id 4
        bytes.extend_from_slice(&0u64.to_le_bytes()); // count 0 (invalid)
        bytes.extend_from_slice(&0u32.to_le_bytes()); // 0 rel-type entries
        assert!(Statistics::decode(&bytes).is_err());
    }

    #[test]
    fn statistics_decode_rejects_truncation() {
        let mut s = Statistics::new();
        s.inc_label(1);
        let mut bytes = s.encode();
        bytes.truncate(bytes.len() - 1);
        assert!(Statistics::decode(&bytes).is_err());
    }

    #[test]
    fn large_device_page_map_round_trips_past_one_page() {
        // A catalog whose device-page maps far exceed one page payload must still round-trip:
        // the single-page cap was the `rmp` task #51 defect (it capped a store at ~1000 pages).
        // 4000 pages/store * 8 B ≈ 128 KiB total — an order of magnitude past one 8 KiB page.
        let mut m = Meta::new(7);
        for (k, s) in m.stores.iter_mut().enumerate() {
            s.high_water = 4000;
            s.device_pages = (0..4000).map(|i| (k as u64 * 4000) + i + 1).collect();
        }
        let bytes = m.encode().unwrap();
        assert!(
            bytes.len() > PAGE_PAYLOAD,
            "test must exceed one page payload to be meaningful: {} <= {PAGE_PAYLOAD}",
            bytes.len()
        );
        let back = Meta::decode(&bytes).unwrap();
        assert_eq!(back, m);
    }

    #[test]
    fn decode_rejects_truncation() {
        let m = Meta::new(1);
        let mut bytes = m.encode().unwrap();
        bytes.truncate(3);
        assert!(Meta::decode(&bytes).is_err());
    }
}
