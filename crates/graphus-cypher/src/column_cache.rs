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
use std::rc::Rc;

use graphus_columnar::{dictionary, integer};
use graphus_core::Value;

/// One declared column's captured snapshot: parallel, node-id-ordered arrays plus the two staleness
/// witnesses. Values are stored **encoded** (`encoding` selects the codec); [`Self::decode`]
/// materializes the column (and memoizes the result for repeated scans of an un-mutated column).
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
    /// This column's **build generation** (`rmp` task #375), assigned by the cache from a monotonic
    /// counter the instant the column is installed by [`set_column`](ColumnCache::set_column). A
    /// column is **immutable after build** — the only mutations the cache exposes are *replacing* a
    /// column (a fresh `set_column`, which mints a new generation) or *dropping* every column
    /// ([`clear`](ColumnCache::clear)). So this number changing is **exactly** "this column was
    /// re-captured", which the read path uses to invalidate its per-query lookup map (see
    /// [`generation`](Self::generation)).
    generation: u64,
    /// Memoized decode of the value column (`rmp` task #375), shared (`Rc`) so a snapshot can hand it
    /// to the read path without re-cloning. Filled on the first [`decode`](Self::decode) and reused on
    /// every subsequent scan of this (immutable) column — repeated analytical scans of an un-mutated
    /// column therefore pay the dictionary/integer decode **once**, not per query. Replaced wholesale
    /// when the column is re-captured (the new `Column` starts with an empty cell), so a stale decode
    /// can never be served after a write. `RefCell` because [`decode`](Self::decode) runs under the
    /// cache's `&self` snapshot path.
    decoded: std::cell::RefCell<Option<Rc<DecodedColumn>>>,
    /// Memoized `node_id -> row index` lookup map (`rmp` task #375 (c)), shared (`Rc`) with the read
    /// path so a repeated scan of this immutable column re-uses it instead of rebuilding an O(n)
    /// `HashMap` per query (the [`record_graph`](crate::record_graph) hot path previously did exactly
    /// that on every scan). Built once, on the first [`index_map`](Self::index_map); a re-capture
    /// builds a fresh `Column` with an empty cell, so a stale map is never served.
    index_map: std::cell::RefCell<Option<Rc<HashMap<u64, usize>>>>,
}

/// The materialized value column plus, for a dictionary-string column, its **codes and dictionary**
/// (`rmp` task #375). A consumer that folds equality / `GROUP BY` reads `codes`/`dict` directly (no
/// per-row `String` rebuild, no string compares); a consumer that needs the [`Value`] reads `values`.
/// Both views are byte-identical (the canonical-dictionary guarantee, see
/// [`graphus_columnar::dictionary::decode_codes`]).
pub struct DecodedColumn {
    /// The decoded [`Value`]s, index-aligned with the column's `ids`.
    pub values: Vec<Value>,
    /// For a **dictionary-string** column: `Some((codes, dict))` where `codes[i]` is the canonical
    /// dictionary index of row `i` and `dict[c]` the `c`-th distinct UTF-8 string. `None` for integer
    /// / raw columns (no dictionary to fold on). When present, `values[i] == Value::String(dict[codes[i]])`
    /// exactly, so a code-keyed fold yields the identical groups a value-keyed fold would.
    pub string_codes: Option<(Vec<u32>, Vec<String>)>,
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
    /// `generation` is the cache-assigned build stamp (`rmp` task #375).
    fn build(rows: Vec<(u64, Value, u64, u64)>, generation: u64) -> Self {
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
            generation,
            decoded: std::cell::RefCell::new(None),
            index_map: std::cell::RefCell::new(None),
        }
    }

    /// The memoized `node_id -> row index` map, built once and re-used on every subsequent scan of
    /// this immutable column (`rmp` task #375 (c)). Later duplicate ids (which the rebuild scan never
    /// produces — node ids are scanned once, ascending) would resolve to the first occurrence; the
    /// arrays are dense and ascending, so the map is a faithful O(1) `id -> index`.
    fn index_map(&self) -> Rc<HashMap<u64, usize>> {
        if let Some(m) = self.index_map.borrow().as_ref() {
            return Rc::clone(m);
        }
        let mut map = HashMap::with_capacity(self.ids.len());
        for (i, &id) in self.ids.iter().enumerate() {
            map.entry(id).or_insert(i);
        }
        let rc = Rc::new(map);
        *self.index_map.borrow_mut() = Some(Rc::clone(&rc));
        rc
    }

    /// The number of captured rows.
    fn len(&self) -> usize {
        self.ids.len()
    }

    /// This column's build generation (changes only when the column is re-captured).
    fn generation(&self) -> u64 {
        self.generation
    }

    /// Decodes the column to its [`DecodedColumn`] — values, plus the canonical `(codes, dict)` for a
    /// dictionary-string column — **memoizing** the result (`rmp` task #375). The decode (FOR/Delta
    /// integer or dictionary bit-unpack) runs at most **once** per column build: a repeated scan of
    /// this immutable column reuses the cached `Rc`, and a re-capture builds a fresh `Column` with an
    /// empty cell, so a stale decode is never served. The integer/raw arms carry no codes (`None`);
    /// only the dictionary arm exposes the fold-on-codes view.
    fn decode(&self) -> Rc<DecodedColumn> {
        if let Some(d) = self.decoded.borrow().as_ref() {
            return Rc::clone(d);
        }
        let count = self.ids.len();
        let decoded = match &self.encoded {
            ColumnEncoding::Integers(bytes) => DecodedColumn {
                values: integer::decode_i64(bytes, count)
                    .into_iter()
                    .map(Value::Integer)
                    .collect(),
                string_codes: None,
            },
            ColumnEncoding::Strings(bytes) => {
                // Decode the dictionary ONCE (not one owned `String` per row): the canonical codes
                // index a deduped, sorted dict, so a consumer can fold equality / `GROUP BY` on the
                // integer codes and materialize a `Value::String` only for the rows it actually keeps.
                let (codes, raw_dict) = dictionary::decode_codes(bytes, count);
                // The dict bytes were captured from valid Rust `String`s, so they are valid UTF-8; a
                // defensive lossy decode keeps this panic-free even if that ever ceased to hold.
                let dict: Vec<String> = raw_dict
                    .into_iter()
                    .map(|b| String::from_utf8_lossy(&b).into_owned())
                    .collect();
                // `values` stays byte-identical to the old `decode` (dict[code] per row); kept so the
                // value-consuming read path is unchanged, while the codes/dict enable code folding.
                let values: Vec<Value> = codes
                    .iter()
                    .map(|&c| Value::String(dict[c as usize].clone()))
                    .collect();
                DecodedColumn {
                    values,
                    string_codes: Some((codes, dict)),
                }
            }
            ColumnEncoding::Raw(values) => DecodedColumn {
                values: values.clone(),
                string_codes: None,
            },
        };
        let rc = Rc::new(decoded);
        *self.decoded.borrow_mut() = Some(Rc::clone(&rc));
        rc
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
    /// The decoded value column plus, for a dictionary-string column, its canonical `(codes, dict)`
    /// (`rmp` task #375). Shared (`Rc`) with the cache's memoized decode, so a repeated scan of an
    /// un-mutated column re-uses it without re-decoding. Read [`DecodedColumn::values`] for the
    /// [`Value`] view (byte-identical to the old `values` field) or
    /// [`DecodedColumn::string_codes`] to fold on codes.
    pub decoded: Rc<DecodedColumn>,
    /// The per-row staleness witnesses, index-aligned with [`Self::ids`].
    pub witnesses: Vec<ColumnWitness>,
    /// The memoized `node_id -> row index` map (`rmp` task #375 (c)), shared with the cache: the read
    /// path looks up a candidate's row in O(1) without rebuilding a per-query `HashMap`. Index into
    /// [`Self::ids`] / [`DecodedColumn::values`] / [`Self::witnesses`].
    pub index_map: Rc<HashMap<u64, usize>>,
    /// The column's build generation at the time this snapshot was taken (`rmp` task #375). The read
    /// path keys its per-query lookup map on `(label, prop, generation)`, so an un-mutated column is
    /// served from the prebuilt map and a re-captured column (new generation) forces a rebuild.
    pub generation: u64,
}

impl ColumnSnapshot {
    /// The decoded values, index-aligned with [`Self::ids`] (the [`Value`] view — byte-identical to
    /// the pre-`rmp`-#375 `values` field).
    #[must_use]
    pub fn values(&self) -> &[Value] {
        &self.decoded.values
    }
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
    /// A monotonic counter that stamps each installed column's **build generation** (`rmp` task #375).
    /// Bumped on every mutation that changes a column's contents — a [`set_column`](Self::set_column)
    /// (which replaces a column with freshly-captured rows) and a [`clear`](Self::clear) (which drops
    /// every column ahead of a rebuild). A column's generation therefore changes **iff** it was
    /// re-captured, so the read path can trust a `(label, prop, generation)` key: equal generation ⇒
    /// the column is byte-for-byte the one it last decoded ⇒ its memoized lookup map is still exact.
    generation: std::cell::Cell<u64>,
    /// The number of [`snapshot`](Self::snapshot) calls that **re-used the column's memoized decode**
    /// rather than decoding afresh (`rmp` task #375). A test asserts a second scan of an un-mutated
    /// column hits this (proving the decode is paid once), and a monitor reads it to confirm the
    /// late-materialization cache is engaged. `Cell` because [`snapshot`](Self::snapshot) takes `&self`.
    decode_cache_hits: std::cell::Cell<u64>,
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
    ///
    /// Bumps the generation (`rmp` task #375): every column it drops will be re-built with a fresh
    /// generation, so any read path holding an older `(label, prop, generation)` key is invalidated.
    pub fn clear(&mut self) {
        self.columns.clear();
        self.bump_generation();
    }

    /// Advances the build-generation counter (`rmp` task #375). Saturating so a pathologically long-
    /// lived cache can never wrap to a previously-served generation and serve a stale decode.
    fn bump_generation(&self) {
        self.generation.set(self.generation.get().saturating_add(1));
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
        // A fresh generation per installed column (`rmp` task #375): replacing the column with
        // freshly-captured rows changes its contents, so any reader's cached decode keyed on the old
        // generation is now stale and must rebuild. The new `Column` starts with an empty decode cell.
        self.bump_generation();
        let generation = self.generation.get();
        self.columns
            .insert((label_token, prop_key), Column::build(rows, generation));
    }

    /// The current build generation of the cached column for `(label_token, prop_key)`, or `None` when
    /// the pair is not cached (`rmp` task #375). The read path captures this alongside a snapshot and
    /// re-uses its memoized lookup map only while the generation is unchanged.
    #[must_use]
    pub fn column_generation(&self, label_token: u32, prop_key: u32) -> Option<u64> {
        self.columns
            .get(&(label_token, prop_key))
            .map(Column::generation)
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
        // If this column was already decoded by an earlier scan (and not re-captured since), the
        // memoized `Rc` is reused — the dictionary/integer decode is paid once, not per query
        // (`rmp` task #375). `was_cached` is read *before* `decode()` populates the cell.
        let was_cached = col.decoded.borrow().is_some();
        let decoded = col.decode();
        if was_cached {
            self.decode_cache_hits.set(self.decode_cache_hits.get() + 1);
        }
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
            decoded,
            witnesses,
            index_map: col.index_map(),
            generation: col.generation(),
        })
    }

    /// The number of [`snapshot`](Self::snapshot) calls that re-used a column's memoized decode rather
    /// than decoding afresh (`rmp` task #375) — the late-materialization cache's engagement signal.
    /// Used by tests to prove a second scan of an un-mutated column avoids re-decoding.
    #[must_use]
    pub fn decode_cache_hits(&self) -> u64 {
        self.decode_cache_hits.get()
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
            snap.values(),
            &[Value::Integer(10), Value::Integer(20), Value::Integer(10)]
        );
        // An integer column carries no fold-on-codes view.
        assert!(snap.decoded.string_codes.is_none());
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
            snap.values(),
            &[
                Value::String("red".into()),
                Value::String("green".into()),
                Value::String("red".into()),
            ]
        );
        // The fold-on-codes view is present and consistent with the values: codes index a canonical
        // (sorted, deduped) dict, so `dict[codes[i]]` reproduces the value exactly and code-equality
        // mirrors value-equality (rows 0 and 2 are both "red" ⇒ identical code).
        let (codes, dict) = snap
            .decoded
            .string_codes
            .as_ref()
            .expect("string column exposes codes");
        assert!(dict.windows(2).all(|w| w[0] < w[1]), "dict canonical");
        assert_eq!(codes[0], codes[2]);
        assert_ne!(codes[0], codes[1]);
        for (i, v) in snap.values().iter().enumerate() {
            assert_eq!(*v, Value::String(dict[codes[i] as usize].clone()));
        }
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
            snap.values(),
            &[
                Value::Integer(1),
                Value::Float(2.5),
                Value::String("x".into())
            ]
        );
        assert!(snap.decoded.string_codes.is_none());
    }

    #[test]
    fn float_column_round_trips_via_raw() {
        let mut cache = ColumnCache::new();
        cache.declare(9, 10);
        let data = rows(&[(1, Value::Float(1.5)), (2, Value::Float(-2.0))]);
        cache.set_column(9, 10, data);
        let snap = cache.snapshot(9, 10).expect("column cached");
        assert_eq!(snap.values(), &[Value::Float(1.5), Value::Float(-2.0)]);
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
        assert!(snap.values().is_empty());
        assert_eq!(cache.column_len(2, 2), Some(0));
    }

    #[test]
    fn undeclared_column_has_no_snapshot() {
        let cache = ColumnCache::new();
        assert!(cache.snapshot(99, 99).is_none());
    }

    #[test]
    fn repeated_scan_of_unmutated_column_reuses_decode() {
        // `rmp` #375 (c): a second scan of an un-mutated column must NOT re-decode — it reuses the
        // memoized `Rc<DecodedColumn>` (proven by the decode-cache-hit counter and by `Rc` identity).
        let mut cache = ColumnCache::new();
        cache.declare(5, 6);
        cache.set_column(
            5,
            6,
            rows(&[
                (1, Value::String("red".into())),
                (2, Value::String("green".into())),
            ]),
        );
        assert_eq!(cache.decode_cache_hits(), 0);
        let s1 = cache.snapshot(5, 6).expect("cached");
        assert_eq!(cache.decode_cache_hits(), 0, "first scan decodes");
        let s2 = cache.snapshot(5, 6).expect("cached");
        assert_eq!(cache.decode_cache_hits(), 1, "second scan reuses decode");
        // Same underlying decode (no re-decode): the snapshots share one `Rc`.
        assert!(Rc::ptr_eq(&s1.decoded, &s2.decoded));
        // Generation unchanged across reads.
        assert_eq!(s1.generation, s2.generation);
    }

    #[test]
    fn mutation_bumps_generation_and_invalidates_decode() {
        // `rmp` #375 (c): re-capturing the column (a `set_column`, the only content mutation the cache
        // exposes besides `clear`) mints a new generation and a fresh decode cell — a stale decode is
        // never served. `clear` likewise bumps the generation.
        let mut cache = ColumnCache::new();
        cache.declare(5, 6);
        cache.set_column(5, 6, rows(&[(1, Value::String("red".into()))]));
        let g0 = cache.column_generation(5, 6).expect("cached");
        let s0 = cache.snapshot(5, 6).expect("cached");
        assert_eq!(s0.generation, g0);

        // Re-capture with different contents.
        cache.set_column(5, 6, rows(&[(1, Value::String("blue".into()))]));
        let g1 = cache.column_generation(5, 6).expect("cached");
        assert!(g1 > g0, "set_column must bump the generation: {g0} -> {g1}");
        let s1 = cache.snapshot(5, 6).expect("cached");
        // Fresh decode (new column), and it reflects the new contents.
        assert!(!Rc::ptr_eq(&s0.decoded, &s1.decoded));
        assert_eq!(s1.values(), &[Value::String("blue".into())]);
        // The fresh column starts cold (no decode-cache hit was charged for `s1`).
        assert_eq!(cache.decode_cache_hits(), 0);

        // `clear` also advances the generation (so any held key is invalidated before a rebuild).
        let before = g1;
        cache.clear();
        cache.set_column(5, 6, rows(&[(1, Value::String("blue".into()))]));
        let g2 = cache.column_generation(5, 6).expect("cached");
        assert!(g2 > before, "clear+rebuild must bump the generation");
    }
}
