//! `ColumnCache` — a **derived, in-memory, rebuilt-on-open** columnar value cache for declared
//! `(label, property)` pairs, the foundation of the *complementary* columnar analytical read path
//! (`rmp` tasks #329 / #330).
//!
//! # What it is (and, deliberately, what it is **not**)
//!
//! This is the same **lifecycle class** as the in-memory full-text ([`crate::index_set`] inverted
//! index) and spatial grid: a derived structure that
//!
//! - is **rebuilt by scanning the authoritative [`RecordStore`]** (it captures a point-in-time
//!   snapshot of each declared column), and
//! - is **never persisted, never WAL-logged, never recovered** — a fresh coordinator over a recovered
//!   store rebuilds it by construction.
//!
//! It therefore adds **zero durability / ACID / recovery surface**: the on-disk authoritative format,
//! the WAL, the storage write path, MVCC and crash recovery are all untouched. The columnar scan is a
//! **pure accelerator**: every cached `(node, value)` it yields is re-validated against the node's
//! *current* MVCC state at read time, and on any mismatch the caller falls back to the authoritative
//! row read. The cache can be arbitrarily stale and the result is still exactly correct.
//!
//! # The contiguous columns
//!
//! For each declared `(label_token, prop_key)` the cache holds, in **node-id order**, parallel
//! arrays captured at the rebuild snapshot:
//!
//! - `ids` — the dense node ids whose **current, committed** value of `prop_key` was index-encodable
//!   at rebuild (a node with no such value contributes no row);
//! - `values` — the column of [`Value`]s, stored **graphus-columnar-encoded** (dictionary for
//!   strings, integer FOR/Delta for integers; raw otherwise) and decoded back exactly on demand;
//! - `prop_pids` — the physical id of the [`PropRecord`](graphus_storage::record::PropRecord) each
//!   value came from, and
//! - `node_first_props` — the node record's `first_prop` chain-head pointer at rebuild.
//!
//! The last two are the **staleness witnesses** that make the read-time re-check both cheap (O(1) per
//! node, no property-chain walk) and provably correct — see [`ColumnSnapshot`].
//!
//! ## The win
//!
//! An analytical property scan / aggregation (`MATCH (n:Label) RETURN sum(n.p)`) over the row path
//! decodes the node's **whole property chain** (overflow-heap walks for strings/lists included),
//! allocates a `Vec<(String, Value)>`, maps every key id back to a name and sorts it — *per matched
//! node*, just to keep one value (`rmp` #326 cut this to one chain probe; this cuts it to a
//! contiguous column read). The columnar scan reads the value straight from `values` and confirms
//! freshness with two O(1) record reads, so on a clean (un-mutated-since-rebuild) column it never
//! touches the property chain at all.

use std::collections::HashMap;

use graphus_columnar::{dictionary, integer};
use graphus_core::Value;

/// One declared column's captured snapshot: parallel, node-id-ordered arrays plus the two staleness
/// witnesses. Values are stored **encoded** (`encoding` selects the codec); [`Self::value_at`]
/// decodes a single row, [`Self::decode_values`] the whole column.
struct Column {
    /// The dense node ids, ascending (the order [`RecordStore::scan_node_ids`] yields).
    ids: Vec<u64>,
    /// The graphus-columnar-encoded value column (see [`ColumnEncoding`]).
    encoded: ColumnEncoding,
    /// `prop_pids[i]` is the physical id of the [`PropRecord`](graphus_storage::record::PropRecord)
    /// that supplied `ids[i]`'s value at rebuild. Re-read O(1) at query time to detect a tombstone
    /// (`REMOVE n.p`, which stamps `xmax` in place without moving the chain head).
    prop_pids: Vec<u64>,
    /// `node_first_props[i]` is `ids[i]`'s node record `first_prop` chain-head pointer at rebuild.
    /// Any property write to the node (`SET`/overwrite/add, or a concurrent uncommitted prepend)
    /// changes `first_prop`, so an unchanged value proves no prepend happened since rebuild — the
    /// cached `PropRecord` is therefore still the newest version of its key (no overwrite went
    /// unseen). The one mutation `first_prop` does **not** catch (an in-place tombstone) is caught by
    /// the `prop_pids` visibility re-check, so the two witnesses together are exact.
    node_first_props: Vec<u64>,
}

/// The encoded form of a captured value column: a graphus-columnar codec for the homogeneous integer
/// / string cases (the analytical hot columns), or a verbatim `Vec<Value>` fallback for everything
/// else (floats/temporal/mixed — still correct, just uncompressed). Decoding is **exact** in every
/// arm (the round-trip-exact codec contract), so the columnar scan and the row scan agree byte for
/// byte.
enum ColumnEncoding {
    /// All values were `Value::Integer`: stored via [`integer::encode_i64`] (FOR / Delta auto-select).
    Integers(Vec<u8>),
    /// All values were `Value::String`: stored via [`dictionary::encode`] (sorted dict + bit-packed
    /// codes — the low-cardinality win for repeated names/enums).
    Strings(Vec<u8>),
    /// Anything else (floats, booleans, temporal, points, or a mixed column): the values verbatim.
    /// Correct and still a contiguous column (no per-node chain decode); simply not compressed.
    Raw(Vec<Value>),
}

impl Column {
    /// Builds an encoded column from the captured `(id, value, prop_pid, node_first_prop)` rows,
    /// choosing the codec that fits the column's value shape. The four arrays stay index-aligned.
    fn build(rows: Vec<(u64, Value, u64, u64)>) -> Self {
        let mut ids = Vec::with_capacity(rows.len());
        let mut values = Vec::with_capacity(rows.len());
        let mut prop_pids = Vec::with_capacity(rows.len());
        let mut node_first_props = Vec::with_capacity(rows.len());
        for (id, value, pid, first_prop) in rows {
            ids.push(id);
            values.push(value);
            prop_pids.push(pid);
            node_first_props.push(first_prop);
        }
        let encoded = encode_column(&values);
        Self {
            ids,
            encoded,
            prop_pids,
            node_first_props,
        }
    }

    /// The number of captured rows.
    fn len(&self) -> usize {
        self.ids.len()
    }

    /// Decodes the whole value column (one allocation), index-aligned with `ids` / `prop_pids` /
    /// `node_first_props`. Used by the batched (vectorized) scan, which decodes once and folds the
    /// contiguous slice rather than decoding row-by-row.
    fn decode_values(&self) -> Vec<Value> {
        match &self.encoded {
            ColumnEncoding::Integers(bytes) => integer::decode_i64(bytes, self.ids.len())
                .into_iter()
                .map(Value::Integer)
                .collect(),
            ColumnEncoding::Strings(bytes) => dictionary::decode(bytes, self.ids.len())
                .into_iter()
                // The bytes were captured from a valid Rust `String`, so they are valid UTF-8; a
                // defensive lossy decode keeps this panic-free even if that ever ceased to hold.
                .map(|b| Value::String(String::from_utf8_lossy(&b).into_owned()))
                .collect(),
            ColumnEncoding::Raw(values) => values.clone(),
        }
    }
}

/// Encodes a captured value column with the codec that fits its shape (see [`ColumnEncoding`]).
fn encode_column(values: &[Value]) -> ColumnEncoding {
    if !values.is_empty() && values.iter().all(|v| matches!(v, Value::Integer(_))) {
        let ints: Vec<i64> = values
            .iter()
            .map(|v| match v {
                Value::Integer(i) => *i,
                // Unreachable: the `all` guard above proved every value is an integer.
                _ => unreachable!("integer column guard"),
            })
            .collect();
        return ColumnEncoding::Integers(integer::encode_i64(&ints));
    }
    if !values.is_empty() && values.iter().all(|v| matches!(v, Value::String(_))) {
        let strings: Vec<Vec<u8>> = values
            .iter()
            .map(|v| match v {
                Value::String(s) => s.clone().into_bytes(),
                _ => unreachable!("string column guard"),
            })
            .collect();
        return ColumnEncoding::Strings(dictionary::encode(&strings));
    }
    ColumnEncoding::Raw(values.to_vec())
}

/// An immutable, point-in-time **snapshot of one declared column**, handed to the read path so the
/// columnar scan needs no borrow of the live cache while it re-validates against the store.
///
/// Each entry is `(node_id, value, witness)` where `witness = ColumnWitness { prop_pid,
/// node_first_prop }`. The read path ([`crate::record_graph`]) walks these, and for each one performs
/// the O(1) re-check that decides whether the cached value is still the node's exact snapshot-visible
/// value — see [`ColumnWitness`] for the soundness argument.
pub struct ColumnSnapshot {
    /// The dense node ids, ascending.
    pub ids: Vec<u64>,
    /// The decoded values, index-aligned with [`Self::ids`].
    pub values: Vec<Value>,
    /// The per-row staleness witnesses, index-aligned with [`Self::ids`].
    pub witnesses: Vec<ColumnWitness>,
}

/// The two staleness witnesses captured for one cached `(node, value)` row (`rmp` #329).
///
/// # Why these two words are exactly sufficient
///
/// The read path holds these from the rebuild snapshot and re-reads the node's *current* records:
///
/// * **`node_first_prop`** is the node record's property-chain head. Every property mutation that
///   *adds a version* — a fresh property, an overwrite (`SET n.p = x` prepends a new
///   [`PropRecord`](graphus_storage::record::PropRecord)), or a concurrent uncommitted prepend —
///   changes `first_prop`. So `current.first_prop == node_first_prop` proves **no prepend** has
///   happened since rebuild ⇒ the cached `PropRecord` is still the **newest** version of its key (no
///   overwrite slipped past, newest-visible-wins is preserved).
/// * **`prop_pid`** is the physical id of the cached value's `PropRecord`. Re-reading it and checking
///   it is still **visible** to the query snapshot catches the one mutation `first_prop` does *not*:
///   an in-place **tombstone** (`REMOVE n.p` / `SET n.p = null` stamps `xmax` on the record without
///   moving the chain head). A tombstoned record fails the visibility test ⇒ fallback.
///
/// Together they are exact: the cached value is the node's snapshot-visible newest value **iff** the
/// node is visible, `first_prop` is unchanged, and the cached `PropRecord` is the same key and still
/// visible. Any divergence (a mutation, a concurrent writer, a reused slot) makes the re-check fail
/// and the caller falls back to the authoritative [`read_node_prop_one`](crate::record_graph) — which
/// is always correct, so the cache is a pure accelerator that can never return a wrong row.
#[derive(Debug, Clone, Copy)]
pub struct ColumnWitness {
    /// Physical id of the cached value's `PropRecord` (re-read O(1) to detect a tombstone).
    pub prop_pid: u64,
    /// The node record `first_prop` chain head at rebuild (compared O(1) to detect any prepend).
    pub node_first_prop: u64,
}

/// A derived, in-memory columnar value cache over declared `(label_token, prop_key)` columns
/// (`rmp` tasks #329 / #330).
///
/// Owned by the [`TxnCoordinator`](crate::coordinator::TxnCoordinator) alongside the
/// [`IndexSet`](crate::index_set::IndexSet) and rebuilt from the store on open and on every schema
/// change, exactly like the other derived structures. See the [module docs](self) for the lifecycle
/// and the soundness contract.
#[derive(Default)]
#[must_use]
pub struct ColumnCache {
    /// The declared columns, keyed `(label_token, prop_key)`. A column is present iff the pair was
    /// declared (via [`declare`](Self::declare)); an undeclared pair is simply not accelerated (the
    /// read path uses the row scan, as it always did).
    columns: HashMap<(u32, u32), Column>,
    /// The set of declared `(label_token, prop_key)` pairs, kept across a [`clear`](Self::clear) so a
    /// rebuild re-captures exactly the declared columns. Separate from `columns` because `clear`
    /// drops the captured data but must remember *what* to re-capture.
    declared: Vec<(u32, u32)>,
    /// The number of [`snapshot`](Self::snapshot) calls that served a cached column — i.e. the number
    /// of times the columnar analytical read path was actually taken (`rmp` #330). A cheap
    /// observability counter: a monitor can confirm the accelerator is engaged, and a test asserts the
    /// vectorized path ran (rather than silently declining to the row path, which would make an
    /// equivalence check vacuous). `Cell` because [`snapshot`](Self::snapshot) takes `&self`.
    scan_hits: std::cell::Cell<u64>,
    /// The number of candidate nodes whose value was served **from the contiguous column** (a fresh
    /// witness match), i.e. with **zero** property-chain decode (`rmp` #329/#330). The accelerator's
    /// payoff signal.
    value_hits: std::cell::Cell<u64>,
    /// The number of candidate nodes the columnar path had to read from the **authoritative property
    /// chain** ([`read_node_prop_one`](crate::record_graph)) because the cache was stale / missing for
    /// that node — i.e. the property-record decodes the columnar path still paid. On a fresh column
    /// this is `0`; it rises with the staleness of the cache. The row path, by contrast, pays one such
    /// decode for **every** matched node, so `value_hits` vs `fallback_reads` is the measured decode
    /// reduction.
    fallback_reads: std::cell::Cell<u64>,
    /// The number of times the **parallel** label-property aggregation tier (`rmp` task #352) projected
    /// a snapshot off this cache and folded it across cores. A cheap observability counter, distinct
    /// from [`scan_hits`](Self::scan_hits) (which the serial columnar scan also bumps): a test asserts
    /// the *parallel* path was actually engaged (not silently declined to the serial tier, which would
    /// make a parallel-vs-serial equivalence check vacuous). `Cell` because the projection path takes
    /// `&self`.
    parallel_scan_hits: std::cell::Cell<u64>,
}

impl ColumnCache {
    /// An empty cache with no declared columns.
    pub fn new() -> Self {
        Self::default()
    }

    /// Declares that `(label_token, prop_key)` should be cached (idempotent). Declaration only
    /// registers intent; the column is populated by the next [`set_column`](Self::set_column) during a
    /// rebuild. Mirrors how a node-property index is *registered* then *rebuilt*.
    pub fn declare(&mut self, label_token: u32, prop_key: u32) {
        if !self.declared.contains(&(label_token, prop_key)) {
            self.declared.push((label_token, prop_key));
        }
    }

    /// Whether `(label_token, prop_key)` is a declared (cacheable) column.
    #[must_use]
    pub fn is_declared(&self, label_token: u32, prop_key: u32) -> bool {
        self.declared.contains(&(label_token, prop_key))
    }

    /// The declared `(label_token, prop_key)` pairs (the rebuild re-captures exactly these).
    #[must_use]
    pub fn declared(&self) -> &[(u32, u32)] {
        &self.declared
    }

    /// Drops every captured column's data but **keeps** the declared set, so a following rebuild
    /// re-captures exactly the declared columns. The cache-side analogue of [`IndexSet::clear`].
    pub fn clear(&mut self) {
        self.columns.clear();
    }

    /// Installs the captured rows for `(label_token, prop_key)` (called by the coordinator's rebuild
    /// with the freshly-scanned column). Rows are `(node_id, value, prop_pid, node_first_prop)` in
    /// node-id order. A no-op-but-stored empty column is fine (it simply yields no rows).
    pub fn set_column(
        &mut self,
        label_token: u32,
        prop_key: u32,
        rows: Vec<(u64, Value, u64, u64)>,
    ) {
        self.columns
            .insert((label_token, prop_key), Column::build(rows));
    }

    /// The number of cached rows for `(label_token, prop_key)`, or `None` if the column is not cached.
    /// (Used by tests / diagnostics to prove the column was actually captured.)
    #[must_use]
    pub fn column_len(&self, label_token: u32, prop_key: u32) -> Option<usize> {
        self.columns.get(&(label_token, prop_key)).map(Column::len)
    }

    /// Produces an immutable [`ColumnSnapshot`] of the cached column for `(label_token, prop_key)`,
    /// or `None` when the pair is not cached (the caller then uses the authoritative row scan).
    ///
    /// The snapshot decodes the value column once (a contiguous read, no per-node property-chain
    /// walk) and clones the witness arrays, so the read path can re-validate each row against the
    /// store without holding any borrow of the cache.
    #[must_use]
    pub fn snapshot(&self, label_token: u32, prop_key: u32) -> Option<ColumnSnapshot> {
        let col = self.columns.get(&(label_token, prop_key))?;
        // Count a cache hit: this is reached only when the columnar analytical read path is taken for
        // a cached column (`rmp` #330 observability / test-engagement proof).
        self.scan_hits.set(self.scan_hits.get() + 1);
        let values = col.decode_values();
        let witnesses = col
            .prop_pids
            .iter()
            .zip(&col.node_first_props)
            .map(|(&prop_pid, &node_first_prop)| ColumnWitness {
                prop_pid,
                node_first_prop,
            })
            .collect();
        Some(ColumnSnapshot {
            ids: col.ids.clone(),
            values,
            witnesses,
        })
    }

    /// The number of times the columnar analytical read path served a cached column (`rmp` #330) —
    /// the count of [`snapshot`](Self::snapshot) hits since this cache was built. Used by monitors and
    /// by tests to confirm the accelerator was actually engaged.
    #[must_use]
    pub fn scan_hits(&self) -> u64 {
        self.scan_hits.get()
    }

    /// Records that `n` candidate values were served from the contiguous column (zero property-chain
    /// decode) — called by the read path with its per-scan tally (`rmp` #329/#330).
    pub fn record_value_hits(&self, n: u64) {
        self.value_hits.set(self.value_hits.get() + n);
    }

    /// Records one engagement of the parallel label-property aggregation tier (`rmp` task #352): a
    /// snapshot was projected off this cache and folded across cores. Bumped by
    /// [`RecordStoreGraph::project_snapshot`](crate::record_graph::RecordStoreGraph) on a successful
    /// projection.
    pub fn record_parallel_scan_hit(&self) {
        self.parallel_scan_hits
            .set(self.parallel_scan_hits.get() + 1);
    }

    /// The number of times the parallel aggregation tier projected a snapshot off this cache
    /// (`rmp` task #352) — the parallel-path engagement count. Used by tests to prove the parallel path
    /// actually ran (so an equivalence assertion is not vacuous).
    #[must_use]
    pub fn parallel_scan_hits(&self) -> u64 {
        self.parallel_scan_hits.get()
    }

    /// Records that `n` candidate values had to be read from the authoritative property chain (a stale
    /// / missing cache entry) — the property-record decodes the columnar path still paid.
    pub fn record_fallback_reads(&self, n: u64) {
        self.fallback_reads.set(self.fallback_reads.get() + n);
    }

    /// The cumulative count of values served from the contiguous column (zero decode) — the
    /// accelerator's payoff signal (`rmp` #329/#330).
    #[must_use]
    pub fn value_hits(&self) -> u64 {
        self.value_hits.get()
    }

    /// The cumulative count of values the columnar path read from the property chain (a stale/missing
    /// cache entry). On a fresh column this stays `0`; the row path would pay one per matched node.
    #[must_use]
    pub fn fallback_reads(&self) -> u64 {
        self.fallback_reads.get()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rows(items: &[(u64, Value)]) -> Vec<(u64, Value, u64, u64)> {
        // Synthetic witnesses (pid = id*10, first_prop = id*100) — the cache treats them opaquely;
        // the real witnesses come from the store at rebuild. Here we only test capture + exact decode.
        items
            .iter()
            .map(|(id, v)| (*id, v.clone(), id * 10, id * 100))
            .collect()
    }

    #[test]
    fn integer_column_round_trips_through_codec() {
        let mut cache = ColumnCache::new();
        cache.declare(1, 2);
        let data = rows(&[
            (1, Value::Integer(10)),
            (2, Value::Integer(20)),
            (3, Value::Integer(10)),
        ]);
        cache.set_column(1, 2, data);
        let snap = cache.snapshot(1, 2).expect("column cached");
        assert_eq!(snap.ids, vec![1, 2, 3]);
        assert_eq!(
            snap.values,
            vec![Value::Integer(10), Value::Integer(20), Value::Integer(10)]
        );
        // Witnesses index-aligned and preserved.
        assert_eq!(snap.witnesses[1].prop_pid, 20);
        assert_eq!(snap.witnesses[1].node_first_prop, 200);
    }

    #[test]
    fn string_column_round_trips_through_dictionary() {
        let mut cache = ColumnCache::new();
        cache.declare(5, 6);
        let data = rows(&[
            (1, Value::String("red".into())),
            (2, Value::String("green".into())),
            (3, Value::String("red".into())),
        ]);
        cache.set_column(5, 6, data);
        let snap = cache.snapshot(5, 6).expect("column cached");
        assert_eq!(
            snap.values,
            vec![
                Value::String("red".into()),
                Value::String("green".into()),
                Value::String("red".into()),
            ]
        );
    }

    #[test]
    fn mixed_column_falls_back_to_raw_but_decodes_exactly() {
        let mut cache = ColumnCache::new();
        cache.declare(7, 8);
        let data = rows(&[
            (1, Value::Integer(1)),
            (2, Value::Float(2.5)),
            (3, Value::String("x".into())),
        ]);
        cache.set_column(7, 8, data);
        let snap = cache.snapshot(7, 8).expect("column cached");
        assert_eq!(
            snap.values,
            vec![
                Value::Integer(1),
                Value::Float(2.5),
                Value::String("x".into())
            ]
        );
    }

    #[test]
    fn float_column_round_trips_via_raw() {
        let mut cache = ColumnCache::new();
        cache.declare(9, 10);
        let data = rows(&[(1, Value::Float(1.5)), (2, Value::Float(-2.0))]);
        cache.set_column(9, 10, data);
        let snap = cache.snapshot(9, 10).expect("column cached");
        assert_eq!(snap.values, vec![Value::Float(1.5), Value::Float(-2.0)]);
    }

    #[test]
    fn declare_is_idempotent_and_clear_keeps_declarations() {
        let mut cache = ColumnCache::new();
        cache.declare(1, 1);
        cache.declare(1, 1);
        assert_eq!(cache.declared(), &[(1, 1)]);
        cache.set_column(1, 1, rows(&[(1, Value::Integer(1))]));
        assert_eq!(cache.column_len(1, 1), Some(1));
        cache.clear();
        // Data dropped, declaration retained (a rebuild re-captures it).
        assert_eq!(cache.column_len(1, 1), None);
        assert_eq!(cache.declared(), &[(1, 1)]);
        assert!(cache.is_declared(1, 1));
    }

    #[test]
    fn empty_column_is_cached_and_yields_no_rows() {
        let mut cache = ColumnCache::new();
        cache.declare(2, 2);
        cache.set_column(2, 2, Vec::new());
        let snap = cache.snapshot(2, 2).expect("empty column still cached");
        assert!(snap.ids.is_empty());
        assert!(snap.values.is_empty());
        assert_eq!(cache.column_len(2, 2), Some(0));
    }

    #[test]
    fn undeclared_column_has_no_snapshot() {
        let cache = ColumnCache::new();
        assert!(cache.snapshot(99, 99).is_none());
    }
}
