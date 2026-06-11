//! The four v1 index kinds (`04-technical-design.md` §6.2, `D-v1-index-types`).
//!
//! Each kind is a thin **key-composition** layer over the single WAL-logged [`BTree`]: they differ
//! only in how they build the encoded key and what the payload means. The payload is always an
//! 8-byte little-endian **candidate record id** (a physical id, `04 §2.2`); visibility is resolved
//! by the transaction layer against the record's MVCC header (`04 §6.3`, see the crate root seam).
//!
//! - [`TokenIndex`] — label/reltype scan store: key `(token_id, element_physical_id)`. A
//!   per-token range scan enumerates `MATCH (n:Label)` candidates without a full scan.
//! - [`PropertyIndex`] — range/B-tree property index: key `(token, value)` for equality and range
//!   predicates with Cypher type-aware ordering ([`crate::keycodec`]).
//! - [`CompositeIndex`] — key `(token, v1, …, vk)` in declared order: multi-property equality and
//!   **leading-prefix** range predicates.
//! - [`RelPropertyIndex`] — the property index over relationship records: key `(reltype, value)`.
//!
//! All four return [`u64`] record ids. They never filter by visibility.

use graphus_core::error::Result;
use graphus_core::{TxnId, Value};
use graphus_io::BlockDevice;
use graphus_wal::LogSink;

use crate::btree::BTree;
use crate::histogram::PropertyHistogram;
use crate::keycodec::{self, KeyEncodeError};

/// The default number of equi-depth buckets when a caller passes `0` to [`PropertyIndex::build_histogram`].
///
/// `64` is a common statistics default (e.g. it matches PostgreSQL's `default_statistics_target`):
/// enough buckets to bound the range-estimate error to roughly `total/64` per open end while keeping
/// the persisted histogram small. The exact value is not load-bearing for correctness — only for the
/// tightness of the documented error bound — so it can be tuned later from measured plan quality.
pub const DEFAULT_HISTOGRAM_BUCKETS: usize = 64;

/// Encodes an 8-byte record-id payload.
fn rid_payload(rid: u64) -> [u8; 8] {
    rid.to_le_bytes()
}

/// Decodes an 8-byte record-id payload.
fn rid_decode(bytes: &[u8]) -> Option<u64> {
    bytes.try_into().ok().map(u64::from_le_bytes)
}

/// Encodes the per-token key tail with a `u32` token prefix and an appended record id so multiple
/// ids under the same `(token, value)` are distinct B+-tree keys (the index is multi-entry).
fn token_value_id_key(token: u32, value_tail: &[u8], rid: u64) -> Vec<u8> {
    let mut k = keycodec::with_token_prefix(token, value_tail);
    k.extend_from_slice(&rid.to_be_bytes()); // big-endian so id order = byte order within a value
    k
}

/// The lower bound (inclusive) for all keys under `(token, value)` — i.e. record id `0`.
fn token_value_lo(token: u32, value_tail: &[u8]) -> Vec<u8> {
    token_value_id_key(token, value_tail, 0)
}

/// The exclusive upper bound for all keys under `(token, value)` — the next value's lower bound.
/// Built by appending the all-ones id terminator then incrementing is avoided by using the next
/// token-value boundary: we use an upper key of `(token, value)` with id = `u64::MAX` made
/// exclusive by callers via a half-open range that adds 1 conceptually. Here we return the
/// inclusive-max key and rely on `range`'s `< hi` by appending a trailing `0x00` sentinel.
fn token_value_hi(token: u32, value_tail: &[u8]) -> Vec<u8> {
    // All keys for this (token, value) are < this bound: same prefix with an id strictly greater
    // than any u64, modelled by appending one extra 0xFF byte after the max id.
    let mut k = keycodec::with_token_prefix(token, value_tail);
    k.extend_from_slice(&u64::MAX.to_be_bytes());
    k.push(0xFF);
    k
}

/// A token-lookup (label / reltype scan) index keyed `(token_id, element_physical_id)`.
pub struct TokenIndex<D: BlockDevice, S: LogSink> {
    tree: BTree<D, S>,
}

impl<D: BlockDevice, S: LogSink> TokenIndex<D, S> {
    /// Wraps a [`BTree`] as a token-lookup index.
    #[must_use]
    pub fn new(tree: BTree<D, S>) -> Self {
        Self { tree }
    }

    /// Borrows the underlying tree (for flush / recovery wiring).
    pub fn tree_mut(&mut self) -> &mut BTree<D, S> {
        &mut self.tree
    }

    fn key(token: u32, element_id: u64) -> Vec<u8> {
        let mut k = token.to_be_bytes().to_vec();
        k.extend_from_slice(&element_id.to_be_bytes());
        k
    }

    /// Records that element `element_id` carries `token` (label/reltype), under `txn`.
    ///
    /// # Errors
    /// Propagates a B+-tree/WAL failure.
    pub fn insert(&mut self, txn: TxnId, token: u32, element_id: u64) -> Result<()> {
        let k = Self::key(token, element_id);
        self.tree.insert(txn, &k, &rid_payload(element_id))
    }

    /// Removes the `(token, element_id)` entry under `txn`, returning whether it was present.
    ///
    /// # Errors
    /// Propagates a B+-tree/WAL failure.
    pub fn remove(&mut self, txn: TxnId, token: u32, element_id: u64) -> Result<bool> {
        self.tree.delete(txn, &Self::key(token, element_id))
    }

    /// All element ids carrying `token`, ascending. The seek a `MATCH (n:Label)` scan compiles to.
    ///
    /// # Errors
    /// Propagates a B+-tree fetch failure.
    pub fn scan_token(&mut self, token: u32) -> Result<Vec<u64>> {
        let lo = Self::key(token, 0);
        let hi = Self::key(token, u64::MAX);
        let mut out: Vec<u64> = self
            .tree
            .range(&lo, &hi)?
            .into_iter()
            .filter_map(|(_, v)| rid_decode(&v))
            .collect();
        // Include the upper-bound element if present (range is half-open and u64::MAX is a valid id).
        if let Some(v) = self.tree.lookup(&hi)? {
            if let Some(r) = rid_decode(&v) {
                out.push(r);
            }
        }
        Ok(out)
    }
}

/// A range/B-tree property index keyed `(token, property_value)` → record id (`04 §6.2`).
///
/// Supports equality ([`Self::seek_eq`]) and range ([`Self::seek_range`]) predicates with Cypher
/// type-aware ordering. The range methods expose the covered key range so the txn layer can
/// register an SSI predicate marker (crate-root seam).
pub struct PropertyIndex<D: BlockDevice, S: LogSink> {
    tree: BTree<D, S>,
}

impl<D: BlockDevice, S: LogSink> PropertyIndex<D, S> {
    /// Wraps a [`BTree`] as a property index.
    #[must_use]
    pub fn new(tree: BTree<D, S>) -> Self {
        Self { tree }
    }

    /// Borrows the underlying tree.
    pub fn tree_mut(&mut self) -> &mut BTree<D, S> {
        &mut self.tree
    }

    /// Inserts `(token, value) -> rid` under `txn`. The `value` is encoded order-preservingly.
    ///
    /// # Errors
    /// Returns [`KeyEncodeError`] (wrapped) for an unindexable value (e.g. `Null` — treated as
    /// absent), else propagates a B+-tree/WAL failure.
    pub fn insert(&mut self, txn: TxnId, token: u32, value: &Value, rid: u64) -> Result<()> {
        let tail = encode_or_storage_err(value)?;
        let k = token_value_id_key(token, &tail, rid);
        self.tree.insert(txn, &k, &rid_payload(rid))
    }

    /// Removes `(token, value) -> rid` under `txn`, returning whether it was present.
    ///
    /// # Errors
    /// See [`Self::insert`].
    pub fn remove(&mut self, txn: TxnId, token: u32, value: &Value, rid: u64) -> Result<bool> {
        let tail = encode_or_storage_err(value)?;
        let k = token_value_id_key(token, &tail, rid);
        self.tree.delete(txn, &k)
    }

    /// Equality seek: all record ids with `token`'s property equal to `value`, ascending by id.
    ///
    /// # Errors
    /// See [`Self::insert`].
    pub fn seek_eq(&mut self, token: u32, value: &Value) -> Result<Vec<u64>> {
        let tail = encode_or_storage_err(value)?;
        let lo = token_value_lo(token, &tail);
        let hi = token_value_hi(token, &tail);
        Ok(self
            .tree
            .range(&lo, &hi)?
            .into_iter()
            .filter_map(|(_, v)| rid_decode(&v))
            .collect())
    }

    /// Range seek `[lo_value, hi_value)` (half-open) for `token`, ascending by `(value, id)`.
    /// Pass `None` for `hi_value` for an unbounded-above range (`>= lo_value`).
    ///
    /// Returns the record ids; the covered encoded key range is `[token_value_lo(lo), bound)`,
    /// which the txn layer uses as the SSI predicate marker (crate-root seam).
    ///
    /// # Errors
    /// See [`Self::insert`].
    pub fn seek_range(
        &mut self,
        token: u32,
        lo_value: &Value,
        hi_value: Option<&Value>,
    ) -> Result<Vec<u64>> {
        let lo_tail = encode_or_storage_err(lo_value)?;
        let lo = token_value_lo(token, &lo_tail);
        let entries = match hi_value {
            Some(hv) => {
                let hi_tail = encode_or_storage_err(hv)?;
                let hi = token_value_lo(token, &hi_tail); // exclusive of hi_value
                self.tree.range(&lo, &hi)?
            }
            None => {
                // Unbounded above *within this token*: stop at the next token.
                let next_token_lo = token
                    .checked_add(1)
                    .map_or_else(Vec::new, |t| t.to_be_bytes().to_vec());
                if next_token_lo.is_empty() {
                    self.tree.range_from(&lo)?
                } else {
                    self.tree.range(&lo, &next_token_lo)?
                }
            }
        };
        Ok(entries
            .into_iter()
            .filter_map(|(_, v)| rid_decode(&v))
            .collect())
    }

    /// Builds an equi-depth [`PropertyHistogram`] over all values indexed under `token`, for the
    /// planner's cardinality estimation.
    ///
    /// Scans every entry for `token` in ascending B+-tree key order (mirroring how [`Self::seek_range`]
    /// bounds the token prefix), strips the 4-byte big-endian token prefix and the trailing 8-byte
    /// big-endian record-id suffix from each key to recover the **encoded value** bytes (already in
    /// ascending order, duplicates included), and feeds them to [`PropertyHistogram::from_sorted_encoded`].
    /// A `target_buckets` of `0` uses [`DEFAULT_HISTOGRAM_BUCKETS`].
    ///
    /// # Errors
    /// Propagates a B+-tree/buffer-pool fetch failure. The encoded values come straight from existing
    /// keys, so no value re-encoding (and thus no [`KeyEncodeError`]) can occur here.
    pub fn build_histogram(
        &mut self,
        token: u32,
        target_buckets: usize,
    ) -> Result<PropertyHistogram> {
        let target = if target_buckets == 0 {
            DEFAULT_HISTOGRAM_BUCKETS
        } else {
            target_buckets
        };

        // Bound the scan to exactly this token's key span: `[token, token+1)`. When `token == u32::MAX`
        // there is no next token, so scan from the prefix to the end of the tree.
        let lo = token.to_be_bytes().to_vec();
        let entries = match token.checked_add(1) {
            Some(next) => self.tree.range(&lo, &next.to_be_bytes())?,
            None => self.tree.range_from(&lo)?,
        };

        // Strip the 4-byte token prefix and the 8-byte trailing rid to recover the encoded value.
        // Every key is `token(4 BE) || encoded_value || rid(8 BE)`, so any well-formed key is at
        // least 12 bytes; a shorter key would be a corruption we simply skip (defensive, never
        // expected for keys this index wrote).
        const PREFIX: usize = 4;
        const SUFFIX: usize = 8;
        let values: Vec<Vec<u8>> = entries
            .into_iter()
            .filter_map(|(k, _)| {
                (k.len() >= PREFIX + SUFFIX).then(|| k[PREFIX..k.len() - SUFFIX].to_vec())
            })
            .collect();

        Ok(PropertyHistogram::from_sorted_encoded(&values, target))
    }
}

/// A composite index keyed `(token, v1, …, vk)` in declared order (`04 §6.2`).
pub struct CompositeIndex<D: BlockDevice, S: LogSink> {
    tree: BTree<D, S>,
    arity: usize,
}

impl<D: BlockDevice, S: LogSink> CompositeIndex<D, S> {
    /// Wraps a [`BTree`] as a composite index over `arity` properties.
    ///
    /// # Panics
    /// Panics if `arity` is zero.
    #[must_use]
    pub fn new(tree: BTree<D, S>, arity: usize) -> Self {
        assert!(arity > 0, "composite index needs at least one property");
        Self { tree, arity }
    }

    /// Borrows the underlying tree.
    pub fn tree_mut(&mut self) -> &mut BTree<D, S> {
        &mut self.tree
    }

    /// The composite index arity (number of key properties).
    #[must_use]
    pub fn arity(&self) -> usize {
        self.arity
    }

    fn key(&self, token: u32, values: &[Value], rid: u64) -> Result<Vec<u8>> {
        let tail = composite_tail(values)?;
        Ok(token_value_id_key(token, &tail, rid))
    }

    /// Inserts `(token, values) -> rid` under `txn`.
    ///
    /// # Errors
    /// Returns a storage error if `values.len() != arity`; propagates encoding / B+-tree failures.
    pub fn insert(&mut self, txn: TxnId, token: u32, values: &[Value], rid: u64) -> Result<()> {
        self.check_arity(values.len())?;
        let k = self.key(token, values, rid)?;
        self.tree.insert(txn, &k, &rid_payload(rid))
    }

    /// Removes `(token, values) -> rid` under `txn`, returning whether it was present.
    ///
    /// # Errors
    /// See [`Self::insert`].
    pub fn remove(&mut self, txn: TxnId, token: u32, values: &[Value], rid: u64) -> Result<bool> {
        self.check_arity(values.len())?;
        let k = self.key(token, values, rid)?;
        self.tree.delete(txn, &k)
    }

    /// Full-key equality seek (`values.len()` must equal [`Self::arity`]).
    ///
    /// # Errors
    /// See [`Self::insert`].
    pub fn seek_eq(&mut self, token: u32, values: &[Value]) -> Result<Vec<u64>> {
        self.check_arity(values.len())?;
        let tail = composite_tail(values)?;
        let lo = token_value_lo(token, &tail);
        let hi = token_value_hi(token, &tail);
        Ok(self
            .tree
            .range(&lo, &hi)?
            .into_iter()
            .filter_map(|(_, v)| rid_decode(&v))
            .collect())
    }

    /// Leading-prefix seek: all record ids whose first `prefix.len()` properties equal `prefix`
    /// (`prefix.len()` must be `>= 1` and `<= arity`). The composite index's headline capability.
    ///
    /// # Errors
    /// Returns a storage error if the prefix length is out of range; propagates encoding/B+-tree
    /// failures.
    pub fn seek_prefix(&mut self, token: u32, prefix: &[Value]) -> Result<Vec<u64>> {
        if prefix.is_empty() || prefix.len() > self.arity {
            return Err(graphus_core::GraphusError::Storage(format!(
                "composite prefix length {} out of range 1..={}",
                prefix.len(),
                self.arity
            )));
        }
        let tail = composite_tail(prefix)?;
        // All keys sharing this leading-field prefix lie in [prefix-lo, prefix-hi): the prefix is
        // self-delimiting per field (keycodec framing), so appending the all-zero id is the lower
        // bound and the prefix + 0xFF…  is just above every continuation.
        let lo = token_value_lo(token, &tail);
        let mut hi = keycodec::with_token_prefix(token, &tail);
        hi.push(0xFF); // strictly greater than any key extending this prefix
        Ok(self
            .tree
            .range(&lo, &hi)?
            .into_iter()
            .filter_map(|(_, v)| rid_decode(&v))
            .collect())
    }

    fn check_arity(&self, got: usize) -> Result<()> {
        if got != self.arity {
            return Err(graphus_core::GraphusError::Storage(format!(
                "composite index arity is {}, got {got} values",
                self.arity
            )));
        }
        Ok(())
    }
}

/// A relationship-property index keyed `(reltype, property_value)` → relationship id (`04 §6.2`,
/// required by `D-v1-index-types`). Structurally identical to [`PropertyIndex`] but named for the
/// relationship-record domain so call sites are unambiguous.
pub struct RelPropertyIndex<D: BlockDevice, S: LogSink> {
    inner: PropertyIndex<D, S>,
}

impl<D: BlockDevice, S: LogSink> RelPropertyIndex<D, S> {
    /// Wraps a [`BTree`] as a relationship-property index.
    #[must_use]
    pub fn new(tree: BTree<D, S>) -> Self {
        Self {
            inner: PropertyIndex::new(tree),
        }
    }

    /// Borrows the underlying tree.
    pub fn tree_mut(&mut self) -> &mut BTree<D, S> {
        self.inner.tree_mut()
    }

    /// Inserts `(reltype, value) -> rel_id` under `txn`.
    ///
    /// # Errors
    /// See [`PropertyIndex::insert`].
    pub fn insert(&mut self, txn: TxnId, reltype: u32, value: &Value, rel_id: u64) -> Result<()> {
        self.inner.insert(txn, reltype, value, rel_id)
    }

    /// Removes `(reltype, value) -> rel_id` under `txn`.
    ///
    /// # Errors
    /// See [`PropertyIndex::insert`].
    pub fn remove(&mut self, txn: TxnId, reltype: u32, value: &Value, rel_id: u64) -> Result<bool> {
        self.inner.remove(txn, reltype, value, rel_id)
    }

    /// Equality seek over relationships of `reltype` with property `value`.
    ///
    /// # Errors
    /// See [`PropertyIndex::insert`].
    pub fn seek_eq(&mut self, reltype: u32, value: &Value) -> Result<Vec<u64>> {
        self.inner.seek_eq(reltype, value)
    }

    /// Range seek over relationships of `reltype`.
    ///
    /// # Errors
    /// See [`PropertyIndex::insert`].
    pub fn seek_range(
        &mut self,
        reltype: u32,
        lo_value: &Value,
        hi_value: Option<&Value>,
    ) -> Result<Vec<u64>> {
        self.inner.seek_range(reltype, lo_value, hi_value)
    }
}

/// Encodes a single value tail, mapping a [`KeyEncodeError`] to a storage error so callers work in
/// the crate-wide [`Result`].
fn encode_or_storage_err(value: &Value) -> Result<Vec<u8>> {
    keycodec::encode_single(value).map_err(key_err)
}

/// Encodes a composite tail (concatenated fields), mapping errors to storage errors.
fn composite_tail(values: &[Value]) -> Result<Vec<u8>> {
    keycodec::encode_composite(values).map_err(key_err)
}

fn key_err(e: KeyEncodeError) -> graphus_core::GraphusError {
    graphus_core::GraphusError::Storage(e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::recovery::SharedWal;
    use graphus_bufpool::BufferPool;
    use graphus_io::MemBlockDevice;
    use graphus_wal::{MemLogSink, WalManager};

    type Dev = MemBlockDevice;
    type Sink = MemLogSink;

    fn fresh_tree() -> BTree<Dev, Sink> {
        let wal = WalManager::create(MemLogSink::new()).unwrap();
        let shared = SharedWal::new(wal);
        let pool = BufferPool::with_wal(MemBlockDevice::new(0), shared.clone(), 64);
        BTree::create(pool, shared).unwrap()
    }

    #[test]
    fn token_index_scans_per_token() {
        let mut idx = TokenIndex::new(fresh_tree());
        let txn = TxnId(1);
        idx.tree_mut().with_wal(|w| w.begin(txn));
        idx.insert(txn, 7, 100).unwrap();
        idx.insert(txn, 7, 50).unwrap();
        idx.insert(txn, 9, 200).unwrap(); // different token
        idx.tree_mut().with_wal(|w| w.commit(txn).unwrap());
        assert_eq!(idx.scan_token(7).unwrap(), vec![50, 100]);
        assert_eq!(idx.scan_token(9).unwrap(), vec![200]);
        assert_eq!(idx.scan_token(1).unwrap(), Vec::<u64>::new());
    }

    #[test]
    fn property_index_equality_and_range() {
        let mut idx = PropertyIndex::new(fresh_tree());
        let txn = TxnId(1);
        idx.tree_mut().with_wal(|w| w.begin(txn));
        idx.insert(txn, 1, &Value::Integer(10), 1000).unwrap();
        idx.insert(txn, 1, &Value::Integer(10), 1001).unwrap(); // same value, two ids
        idx.insert(txn, 1, &Value::Integer(20), 1002).unwrap();
        idx.insert(txn, 1, &Value::Integer(30), 1003).unwrap();
        idx.tree_mut().with_wal(|w| w.commit(txn).unwrap());

        let mut eq = idx.seek_eq(1, &Value::Integer(10)).unwrap();
        eq.sort_unstable();
        assert_eq!(eq, vec![1000, 1001]);

        // [10, 30) -> values 10 and 20
        let mut r = idx
            .seek_range(1, &Value::Integer(10), Some(&Value::Integer(30)))
            .unwrap();
        r.sort_unstable();
        assert_eq!(r, vec![1000, 1001, 1002]);

        // >= 20
        let mut r2 = idx.seek_range(1, &Value::Integer(20), None).unwrap();
        r2.sort_unstable();
        assert_eq!(r2, vec![1002, 1003]);
    }

    #[test]
    fn composite_index_full_and_leading_prefix() {
        let mut idx = CompositeIndex::new(fresh_tree(), 2);
        let txn = TxnId(1);
        idx.tree_mut().with_wal(|w| w.begin(txn));
        let v = |a: i64, b: &str| vec![Value::Integer(a), Value::String(b.to_owned())];
        idx.insert(txn, 1, &v(1, "a"), 10).unwrap();
        idx.insert(txn, 1, &v(1, "b"), 11).unwrap();
        idx.insert(txn, 1, &v(2, "a"), 12).unwrap();
        idx.tree_mut().with_wal(|w| w.commit(txn).unwrap());

        assert_eq!(idx.seek_eq(1, &v(1, "a")).unwrap(), vec![10]);
        // Leading-prefix: first property == 1 -> ids 10, 11 (not 12)
        let mut p = idx.seek_prefix(1, &[Value::Integer(1)]).unwrap();
        p.sort_unstable();
        assert_eq!(p, vec![10, 11]);
    }

    #[test]
    fn rel_property_index_equality() {
        let mut idx = RelPropertyIndex::new(fresh_tree());
        let txn = TxnId(1);
        idx.tree_mut().with_wal(|w| w.begin(txn));
        idx.insert(txn, 5, &Value::String("2020".to_owned()), 900)
            .unwrap();
        idx.insert(txn, 5, &Value::String("2021".to_owned()), 901)
            .unwrap();
        idx.tree_mut().with_wal(|w| w.commit(txn).unwrap());
        assert_eq!(
            idx.seek_eq(5, &Value::String("2020".to_owned())).unwrap(),
            vec![900]
        );
    }

    #[test]
    fn build_histogram_matches_brute_force_oracle() {
        use crate::keycodec::encode_single;

        let mut idx = PropertyIndex::new(fresh_tree());
        let txn = TxnId(1);
        idx.tree_mut().with_wal(|w| w.begin(txn));

        // A known multiset: 0..200 once each, plus value 50 inserted 9 extra times (10 total), under
        // token 1; plus a couple of rows under a *different* token 2 that must NOT leak in.
        let mut rid = 0u64;
        let mut multiset: Vec<i64> = Vec::new();
        for v in 0..200i64 {
            idx.insert(txn, 1, &Value::Integer(v), rid).unwrap();
            multiset.push(v);
            rid += 1;
        }
        for _ in 0..9 {
            idx.insert(txn, 1, &Value::Integer(50), rid).unwrap();
            rid += 1;
        }
        multiset.extend(std::iter::repeat_n(50, 9));
        idx.insert(txn, 2, &Value::Integer(999), rid).unwrap();
        rid += 1;
        idx.insert(txn, 2, &Value::Integer(1000), rid).unwrap();
        idx.tree_mut().with_wal(|w| w.commit(txn).unwrap());

        let hist = idx.build_histogram(1, 32).unwrap();

        // Totals/distinct match the oracle exactly (token 2 excluded).
        assert_eq!(
            hist.total(),
            multiset.len() as u64,
            "209 rows under token 1"
        );
        let distinct: std::collections::BTreeSet<i64> = multiset.iter().copied().collect();
        assert_eq!(
            hist.distinct(),
            distinct.len() as u64,
            "200 distinct values"
        );

        // Equality on the frequent value tracks its true frequency within a small bound.
        let enc50 = encode_single(&Value::Integer(50)).unwrap();
        let true50 = multiset.iter().filter(|&&v| v == 50).count() as f64;
        let est50 = hist.estimate_eq(&enc50);
        assert!(
            (est50 - true50).abs() <= true50, // within one frequency unit-scale; equi-depth keeps it tight
            "frequent-value estimate {est50} vs true {true50}"
        );

        // Default-bucket path (target 0) is accepted and produces the same totals.
        let hist_default = idx.build_histogram(1, 0).unwrap();
        assert_eq!(hist_default.total(), multiset.len() as u64);
        assert_eq!(hist_default.distinct(), distinct.len() as u64);

        // A token with no entries yields the empty histogram.
        let empty = idx.build_histogram(7, 16).unwrap();
        assert!(empty.is_empty());
        assert_eq!(empty.total(), 0);
    }

    #[test]
    fn null_value_is_unindexable() {
        let mut idx = PropertyIndex::new(fresh_tree());
        let txn = TxnId(1);
        idx.tree_mut().with_wal(|w| w.begin(txn));
        assert!(idx.insert(txn, 1, &Value::Null, 1).is_err());
    }

    #[test]
    fn composite_arity_is_enforced() {
        let mut idx = CompositeIndex::new(fresh_tree(), 2);
        let txn = TxnId(1);
        idx.tree_mut().with_wal(|w| w.begin(txn));
        assert!(idx.insert(txn, 1, &[Value::Integer(1)], 1).is_err());
    }
}
