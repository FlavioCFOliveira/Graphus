//! MVCC version history for the node **label bitmap** (`rmp` task #767).
//!
//! # Why this exists
//!
//! A node's label set lives in the `labels` `u64` **inside** the node record ([`crate::labels`],
//! `05 §9`) and is mutated **in place** — unlike a property, which is a separate `PropRecord` with
//! its own MVCC header, so a property overwrite MVCC-tombstones the old version and prepends the new
//! one (`rmp` #50, newest-**visible**-wins).
//!
//! That left the label word with the in-place half of `04 §5.1`'s ratified MVCC scheme ("store the
//! newest version in place and keep older versions as logical undo deltas") and **none** of the delta
//! half. There was no `v` for `graphus_txn::is_visible` to be applied to, so every label read
//! returned whatever the word held *at that instant*. Two anomalies followed, both reproduced on a
//! pure scan with no index involved (`graphus-cypher/tests/mvcc_label_snapshot_767.rs`):
//!
//! * a **non-repeatable read** — a committed `REMOVE n:Person` was immediately visible to a reader
//!   whose snapshot predated the commit, so one transaction's `MATCH (n:Person)` could return a node
//!   and then stop returning it;
//! * a **dirty read** — an *uncommitted* writer's label change was visible to a concurrent reader,
//!   which is below READ COMMITTED. `docs/transactions.md` documents Snapshot Isolation as the
//!   weakest tier Graphus offers, so this broke the guarantee even for a plain autocommit read.
//!
//! This module supplies the missing delta half.
//!
//! # Why the history is in memory only, and why that is sufficient
//!
//! An older version of the label word is needed by exactly one kind of caller: a **still-active**
//! transaction whose snapshot predates the change. A crash or a clean restart ends every such
//! transaction, and a recovered store's label words are the committed ones (the ARIES undo restores
//! any loser's word — `RecordStore::write_node_labels`'s CAS logical undo, `rmp` #772). So no reader
//! can ever ask for a pre-restart version, and the history needs **no durability**.
//!
//! That is what keeps the on-disk format frozen: `05 §9` is untouched, no migration, and the backup,
//! consistency-check and bulk-import paths are unaffected.
//!
//! # The steady-state cost is one atomic load
//!
//! The label bitmap is the hottest predicate in the engine (every `MATCH (n:L)` re-check goes through
//! it), so [`resolve`](LabelHistory::resolve) short-circuits on [`any`](LabelHistory::any) — a single
//! `Acquire` load (see that method for why it is not `Relaxed`) — whenever no node has a tracked
//! change. Entries are pruned at GC time (see [`prune`](LabelHistory::prune)), so a workload without
//! concurrent label churn keeps the map empty and pays only that load. The lock is taken only while
//! label history actually exists.
//!
//! # Multi-core read scaling while the history is ARMED — the lock-free pre-filter (`rmp` #808)
//!
//! While the map is empty the gate short-circuits on a load of a read-only cache line, which stays
//! Shared across cores and costs nothing to scale. Once the history is non-empty ("armed"), the
//! naive design took a shared [`RwLock`] read acquisition on **every** re-check — an atomic
//! read-modify-write on ONE cache line, contended by every reader. That collapsed aggregate
//! label-scan throughput to well below single-thread past a couple of cores (measured: 0.12× of
//! single-thread at 16 threads, 20_000 labelled nodes, AMD Ryzen 9 5900HX (8C/16T), `--release`,
//! idle host).
//!
//! The realisation that fixes it cheaply: while armed, the tracked set is TINY (typically one or two
//! nodes — a relabel of an already-committed node, retained only until the next GC prune) relative to
//! a scan, so for nearly every candidate the correct answer is "not tracked, use the live word". A
//! [`TrackedFilter`] — a lock-free Bloom membership pre-filter maintained by the single writer and
//! read with atomic **loads only** — answers exactly that question without the lock. The `RwLock` is
//! taken only for the handful of genuinely-tracked ids (plus a negligible false-positive rate), so
//! the armed path scales like the unarmed one, and the certified resolution logic behind the lock is
//! byte-identical to before. See [`TrackedFilter`] for the no-false-negative safety argument.
//!
//! This stays inside the workspace's **no-external-dependencies** rule (no `ArcSwap`): a naive
//! atomic-`Arc` snapshot would not even help, since `Arc::clone` on load is itself an RMW on the
//! control block — the same contention by another name — and a scaling variant needs
//! hazard-pointer/epoch reclamation. The pre-filter avoids all of that: no reclamation, no `unsafe`,
//! and the slow path reuses the existing lock unchanged.
//!
//! # Version resolution
//!
//! Each tracked change appends `(stamp, bitmap_after)`, where `stamp` is the writer's
//! [`VersionStamp`]: the in-flight `TxnId` while the writer is open, **settled to `Committed(ts)` by
//! [`settle`](LabelHistory::settle) the moment it commits**. `base` is the bitmap as it stood before
//! the oldest retained change.
//!
//! ## Settling is eager here, unlike the record headers — and that is REQUIRED
//!
//! A record header freezes lazily at GC time (`rmp` #49) because eager settling was
//! `O(records touched)` WAL-logged page writes. This history is small and in-memory, so settling costs
//! a walk of one transaction's own entries and logs nothing.
//!
//! It is not merely an optimisation. The first cut of this module kept the raw in-flight stamp and
//! resolved it through the [`CommitRegistry`], mirroring the headers — but the GC freeze sweep walks
//! only on-disk headers, never this history, while the same pass FORGETS committed writers from the
//! registry. After that prune `CommitRegistry::outcome` maps the unknown id to `Aborted`, so the
//! version read as never-committed, [`resolve`](LabelHistory::resolve) fell back to `base`, and a
//! COMMITTED label change silently reverted for every reader until the process restarted. Settling at
//! commit removes the registry from the committed path entirely: afterwards it is consulted only for
//! genuinely in-flight writers, where "unknown ⇒ not visible" is the correct answer anyway.
//!
//! ## Entries are keyed by PHYSICAL id, which is reused
//!
//! Physical ids are reused after reclamation (`04 §2.7`), so an entry outliving its node would be
//! inherited by the next node given that slot — and since `resolve` ignores the live word whenever an
//! entry exists, and a freshly created node retains no version of its own, the dead node's bitmap
//! would stick permanently. `RecordStore::reclaim_node` therefore calls
//! [`forget_node`](LabelHistory::forget_node) before the id reaches the free list. The GC-time
//! [`prune`](LabelHistory::prune) is not sufficient on its own: an in-flight writer's version is
//! (correctly) unprunable, so it would strand there.
//!
//! A reader takes the **newest** version visible to its snapshot, falling back to `base`. When a
//! history exists the live word is deliberately **not** consulted: the live word may hold an
//! uncommitted writer's value, which is precisely the dirty read being closed.

use std::collections::HashMap;
use std::sync::RwLock;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use graphus_core::{Timestamp, TxnId};
use graphus_txn::{CommitRegistry, Snapshot, VersionStamp, is_visible};

/// One tracked change to a node's label bitmap.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct LabelVersion {
    /// The writing transaction's [`VersionStamp`], raw — `InFlight(txn)` until it resolves, exactly
    /// as a record header's `xmin` is stamped (`rmp` #49 lazy freezing). Resolved through the
    /// [`CommitRegistry`], never interpreted directly.
    stamp: u64,
    /// The full label bitmap **after** this change (not a delta): resolution picks a version, it
    /// never replays a chain, so an interleaving of writers on one node cannot compose wrongly.
    bitmap: u64,
}

/// The retained versions of one node's label bitmap, oldest first.
#[derive(Debug, Clone, Default)]
struct NodeLabelHistory {
    /// The bitmap as it stood **before** [`versions`](Self::versions)`[0]`, i.e. the value a reader
    /// older than every retained change must see.
    base: u64,
    /// Tracked changes in write order.
    versions: Vec<LabelVersion>,
}

/// The store-wide label bitmap version history (`rmp` #767).
///
/// Shared by `Arc` between the engine thread (which records changes) and the off-thread reader pool
/// (which resolves them), so a reader thread reaches exactly the same history the writer maintains.
/// This must be shared **live** rather than captured per dispatch: the page cache the reader decodes
/// from is itself live (`rmp` #721), so a label change committed after dispatch is already visible in
/// the word the reader reads, and only a live history can undo it.
#[derive(Debug)]
pub struct LabelHistory {
    /// Fast gate: `true` iff [`map`](Self::map) is non-empty. Lets the overwhelmingly common
    /// no-label-churn path skip the lock entirely.
    any: AtomicBool,
    /// Lock-free membership pre-filter over the tracked node ids (`rmp` #808). Consulted after the
    /// [`any`](Self::any) gate and before the [`map`](Self::map) lock: a **miss** is authoritative
    /// ("this node has no tracked change"), so the overwhelming majority of re-checks — every
    /// untracked node in a scan while a handful of others are armed — skip the `RwLock` entirely and
    /// pay only a pair of atomic **loads** on read-mostly cache lines. See [`TrackedFilter`].
    filter: TrackedFilter,
    /// `node_id -> retained versions`.
    map: RwLock<HashMap<u64, NodeLabelHistory>>,
}

impl Default for LabelHistory {
    fn default() -> Self {
        Self {
            any: AtomicBool::new(false),
            filter: TrackedFilter::new(),
            map: RwLock::new(HashMap::new()),
        }
    }
}

/// Number of 64-bit words backing [`TrackedFilter`]. 64 words = 4096 bits = 512 bytes: enough that,
/// for the realistic armed set (one or two nodes, up to a few dozen under heavy churn), the
/// false-positive rate is negligible (≈`(k·n/m)^k`; for `n=32, k=2, m=4096` it is ≈`2·10⁻⁴`), while
/// staying small enough that the two words a lookup touches are almost always cache-resident.
const LABEL_FILTER_WORDS: usize = 64;
/// Total bit capacity of the filter.
const LABEL_FILTER_BITS: u64 = (LABEL_FILTER_WORDS as u64) * 64;

/// A lock-free Bloom membership pre-filter over the tracked node ids (`rmp` #808).
///
/// # Why this exists
///
/// The authoritative history is [`LabelHistory::map`], behind a `RwLock`. Even a *read* acquisition
/// of that lock is an atomic read-modify-write on one cache line, so once the history is armed every
/// reader thread contends on it and aggregate label-scan throughput collapses (measured: 0.12× of
/// single-thread at 16 threads on an idle Ryzen 9 5900HX). This filter lets a reader decide, with
/// **loads only**, that a given id is definitely *not* tracked and skip the lock — which is the case
/// for nearly every candidate, because the armed set is tiny relative to a scan.
///
/// # No false negatives (the safety property)
///
/// A lookup may return a false *positive* (harmless: the reader takes the lock, finds no entry, and
/// returns the live word) but **never** a false negative for a genuinely tracked id. Two facts
/// establish this:
///
/// * **Adds are monotonic.** [`insert`](Self::insert) only ever sets bits, so once an id's bits are
///   set they stay set for the whole armed window.
/// * **Rebuilds preserve every surviving key.** [`rebuild`](Self::rebuild) recomputes the image from
///   the *surviving* keys and publishes it one word at a time; a surviving key has both its bits set
///   in the new image, so any per-word interleaving of the old and new images a concurrent reader
///   might observe still has that key's bits set. Only bits belonging exclusively to *removed* ids
///   can clear, and a removed id is one whose live word is authoritative again — returning the live
///   word for it is correct.
///
/// The publication ordering that makes a newly-armed id visible mirrors [`LabelHistory::any`]: the
/// writer sets the bits (with `Release`) **before** it arms the gate and, on the store write path,
/// before it mutates the in-place live word the version guards; a reader that observes either the
/// armed gate or the mutated word (through the buffer-pool page latch) therefore also observes the
/// bits. Reads use `Acquire` so the property holds by construction rather than by a neighbour's
/// implementation detail.
#[derive(Debug)]
struct TrackedFilter {
    words: [AtomicU64; LABEL_FILTER_WORDS],
}

impl TrackedFilter {
    /// An empty filter (no id tracked).
    fn new() -> Self {
        Self {
            words: [const { AtomicU64::new(0) }; LABEL_FILTER_WORDS],
        }
    }

    /// The two bit indices `id` maps to (double hashing with two independent mixes of the id).
    #[inline]
    fn bits(id: u64) -> (usize, usize) {
        // splitmix64 finalizers: full-avalanche mixing so adjacent physical ids do not collide.
        let mix = |mut z: u64| -> u64 {
            z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
            z ^ (z >> 31)
        };
        let h1 = mix(id) % LABEL_FILTER_BITS;
        let h2 = mix(id ^ 0x9e37_79b9_7f4a_7c15) % LABEL_FILTER_BITS;
        (h1 as usize, h2 as usize)
    }

    /// Marks `id` as tracked (writer only). Monotonic: only sets bits.
    fn insert(&self, id: u64) {
        let (b1, b2) = Self::bits(id);
        self.words[b1 / 64].fetch_or(1u64 << (b1 % 64), Ordering::Release);
        self.words[b2 / 64].fetch_or(1u64 << (b2 % 64), Ordering::Release);
    }

    /// Whether `id` *may* be tracked — **loads only**, the hot path. A `false` is authoritative:
    /// `id` is definitely not tracked. Never a false negative for a tracked id (see type docs).
    #[inline]
    #[must_use]
    fn maybe_contains(&self, id: u64) -> bool {
        let (b1, b2) = Self::bits(id);
        self.words[b1 / 64].load(Ordering::Acquire) & (1u64 << (b1 % 64)) != 0
            && self.words[b2 / 64].load(Ordering::Acquire) & (1u64 << (b2 % 64)) != 0
    }

    /// Recomputes the image from exactly the surviving `keys` (writer only), publishing each word
    /// with a single store. Preserves every surviving key's bits under concurrent reads (see type
    /// docs); an empty `keys` clears the filter.
    fn rebuild<'a>(&self, keys: impl Iterator<Item = &'a u64>) {
        let mut image = [0u64; LABEL_FILTER_WORDS];
        for &id in keys {
            let (b1, b2) = Self::bits(id);
            image[b1 / 64] |= 1u64 << (b1 % 64);
            image[b2 / 64] |= 1u64 << (b2 % 64);
        }
        for (w, &v) in self.words.iter().zip(image.iter()) {
            w.store(v, Ordering::Release);
        }
    }
}

impl LabelHistory {
    /// A history with no tracked changes.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Whether any node currently has a tracked label change (the hot-path gate).
    ///
    /// # Ordering: `Acquire`/`Release`, deliberately, not `Relaxed`
    ///
    /// The gate is a **publication** flag: a writer fills the map under the lock and then arms it, and
    /// a reader that observes it armed must also observe the map contents that justify it. `Relaxed`
    /// alone does not order those two, so a reader could see `any() == true` and then take the lock
    /// and find the entry — fine — or, more dangerously, see `any() == false` and skip the lock while
    /// the entry it needed was already published.
    ///
    /// It was originally written `Relaxed`, and an audit found it was sound only by accident: the
    /// buffer pool's `RwLock` read latch (`graphus-bufpool`, taken to decode the node record one line
    /// before every gate check) supplied the missing happens-before. That is an undocumented
    /// dependency on an unrelated component, and Graphus targets aarch64 (Apple Silicon, Raspberry Pi
    /// 5) where the weaker model makes such accidents observable. Paying an `Acquire` load — free on
    /// x86-64, one cheap barrier on aarch64 — buys a property that is true by construction rather than
    /// by a neighbour's implementation detail. Measured: no detectable change on a label scan at either
    /// 1_000 or 100_000 nodes.
    #[must_use]
    #[inline]
    pub fn any(&self) -> bool {
        self.any.load(Ordering::Acquire)
    }

    /// Records that `txn` changed node `id`'s label bitmap from `prior` to `new`.
    ///
    /// Call **only** for a change to a node that already existed as a committed version. A node
    /// created by `txn` itself needs no history: the node record is invisible to every older
    /// snapshot, so no reader can ask what its labels were.
    ///
    /// A no-op change (`prior == new`) records nothing.
    pub fn record(&self, id: u64, txn: TxnId, prior: u64, new: u64) {
        if prior == new {
            return;
        }
        let mut map = self.map.write().unwrap_or_else(|e| e.into_inner());
        let entry = map.entry(id).or_insert_with(|| NodeLabelHistory {
            base: prior,
            versions: Vec::new(),
        });
        entry.versions.push(LabelVersion {
            stamp: VersionStamp::in_flight(txn),
            bitmap: new,
        });
        // Mark the id in the lock-free pre-filter BEFORE arming the gate, so a reader that observes
        // `any() == true` also observes the bits (the same publication ordering `any` documents), and
        // — on the store write path — before the in-place live word is mutated, so a reader that
        // reaches the mutated word through the page latch is guaranteed to take the slow path.
        self.filter.insert(id);
        self.any.store(true, Ordering::Release);
    }

    /// The label bitmap node `id` presents to `snapshot`.
    ///
    /// `live` is the bitmap currently in the node record, used only when the node has no tracked
    /// change — in which case no in-flight or recently-committed writer can have perturbed it.
    ///
    /// When a history exists the live word is **not** consulted: it may hold an uncommitted writer's
    /// value.
    #[must_use]
    pub fn resolve(
        &self,
        id: u64,
        live: u64,
        snapshot: Snapshot,
        registry: &CommitRegistry,
    ) -> u64 {
        // Hot path: no node anywhere has a tracked change.
        if !self.any() {
            return live;
        }
        // Second gate (`rmp` #808): a lock-free membership check with loads only. A miss is
        // authoritative — this node has no tracked change — so the untracked majority of a scan
        // skips the `RwLock` below entirely instead of contending on its reader-count cache line.
        // A false positive merely reaches the (byte-identical) slow path and returns `live`.
        if !self.filter.maybe_contains(id) {
            return live;
        }
        let map = self.map.read().unwrap_or_else(|e| e.into_inner());
        let Some(hist) = map.get(&id) else {
            return live;
        };
        // Newest visible wins, mirroring the property chain (`rmp` #50). `xmax = 0`: a label version
        // is never independently expired — it is superseded by the next entry — so `is_visible`
        // reduces to its creator clause, which is exactly the question being asked. Reusing the
        // audited predicate also keeps this off the `CommitRegistry::outcome(w) == InFlight` trap
        // (that arm is dead — a running writer has no registry entry at all).
        for v in hist.versions.iter().rev() {
            if is_visible(snapshot, v.stamp, 0, registry) {
                return v.bitmap;
            }
        }
        hist.base
    }

    /// **Settles** every version stamped by `txn` to `Committed(commit_ts)`, for use when `txn`
    /// COMMITS.
    ///
    /// # Why this is eager here, when record headers freeze lazily
    ///
    /// A record header's `xmin` is settled lazily at GC time (`rmp` #49) because settling eagerly was
    /// `O(records touched)` **WAL-logged page writes**. This history is small and purely in-memory, so
    /// settling costs a walk of one transaction's own entries and logs nothing.
    ///
    /// It is also MANDATORY, not an optimisation. A raw `InFlight(txn)` stamp is only resolvable while
    /// the [`CommitRegistry`] still holds `txn` — and a GC pass **forgets** committed writers from that
    /// registry once their record headers are frozen (`RecordStore::commit`'s `pending_gc_prune`).
    /// After that, `CommitRegistry::outcome` maps the now-unknown id to `Aborted`, so
    /// `is_visible(.., InFlight(txn), ..)` is false FOREVER, [`resolve`](Self::resolve) falls back to
    /// `base`, and a COMMITTED label change becomes permanently invisible to every reader — silently,
    /// and healed only by a restart (the on-disk word was right all along). Settling at commit removes
    /// the registry from the committed path entirely: afterwards the registry is consulted only for
    /// genuinely in-flight writers, where "unknown ⇒ not visible" is the correct answer anyway.
    /// `nodes` are the physical ids `txn` relabelled (its `ActiveTxn::labelled_nodes`). Settling is
    /// keyed on them so the commit path is `O(this transaction's own writes)`, never
    /// `O(tracked_nodes)` — the map is keyed by node id, so a blind scan would put an unbounded walk
    /// on the commit hot path.
    pub fn settle(&self, txn: TxnId, commit_ts: Timestamp, nodes: &[u64]) {
        if nodes.is_empty() {
            return;
        }
        let stamp = VersionStamp::in_flight(txn);
        let settled = VersionStamp::committed(commit_ts);
        let mut map = self.map.write().unwrap_or_else(|e| e.into_inner());
        for id in nodes {
            if let Some(hist) = map.get_mut(id) {
                for v in &mut hist.versions {
                    if v.stamp == stamp {
                        v.stamp = settled;
                    }
                }
            }
        }
    }

    /// Whether any retained version anywhere is still stamped `InFlight(txn)` (test/assertion seam).
    ///
    /// The invariant `settle` establishes is *no `LabelHistory` stamp outlives its registry entry*;
    /// this is how a test checks it directly rather than inferring it from a symptom.
    #[must_use]
    pub fn has_inflight_versions_of(&self, txn: TxnId) -> bool {
        let stamp = VersionStamp::in_flight(txn);
        self.map
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .values()
            .any(|h| h.versions.iter().any(|v| v.stamp == stamp))
    }

    /// Whether node `id` currently has any retained version (the `alloc_id` reuse assertion).
    #[must_use]
    pub fn tracks_node(&self, id: u64) -> bool {
        self.map
            .read()
            .unwrap_or_else(|e| e.into_inner())
            .contains_key(&id)
    }

    /// Drops every retained version for node `id`, for use when its physical slot is **reclaimed**.
    ///
    /// Physical ids are reused after reclamation (`04 §2.7`) and this history is keyed by physical id,
    /// so an entry outliving its node would be inherited by whatever NEW node is given that slot —
    /// and [`resolve`](Self::resolve) deliberately ignores the live word whenever an entry exists, so
    /// the new node would report the DEAD node's label bitmap. Worse, the new node records no version
    /// of its own (its creator is its own in-flight writer, which
    /// `RecordStore::track_label_history` deliberately skips), so nothing ever overrides the stale
    /// value.
    pub fn forget_node(&self, id: u64) {
        if !self.any() {
            return;
        }
        let mut map = self.map.write().unwrap_or_else(|e| e.into_inner());
        map.remove(&id);
        // Rebuild the pre-filter from the survivors so a churn of reclaimed slots does not let stale
        // bits accumulate. Surviving keys keep their bits, so no concurrent reader can be misled.
        self.filter.rebuild(map.keys());
        self.any.store(!map.is_empty(), Ordering::Release);
    }

    /// Drops every version stamped by `txn`, for use when `txn` **rolls back**.
    ///
    /// Not required for correctness — an aborted stamp is invisible to every snapshot, so resolution
    /// would already fall through it — but it bounds the memory a churning aborted writer can pin.
    pub fn forget(&self, txn: TxnId) {
        if !self.any() {
            return;
        }
        let stamp = VersionStamp::in_flight(txn);
        let mut map = self.map.write().unwrap_or_else(|e| e.into_inner());
        map.retain(|_, hist| {
            hist.versions.retain(|v| v.stamp != stamp);
            !hist.versions.is_empty()
        });
        self.filter.rebuild(map.keys());
        self.any.store(!map.is_empty(), Ordering::Release);
    }

    /// Collapses history no live or future reader can still need.
    ///
    /// `watermark` MUST be at or below the oldest active reader's snapshot timestamp — the same
    /// contract [`RecordStore::gc`](crate::RecordStore::gc) imposes, which is where this is called
    /// from. A version committed at or before it is visible to **every** current and future snapshot,
    /// so it and everything older collapse into `base`; a node left with no retained version is
    /// dropped entirely (its live word is then authoritative again).
    pub fn prune(&self, watermark: Timestamp, registry: &CommitRegistry) {
        if !self.any() {
            return;
        }
        let mut map = self.map.write().unwrap_or_else(|e| e.into_inner());
        map.retain(|_, hist| {
            // The newest version that every snapshot can already see.
            let cutoff = hist.versions.iter().rposition(|v| {
                registry
                    .resolve_commit_ts(v.stamp)
                    .is_some_and(|ts| ts <= watermark)
            });
            if let Some(i) = cutoff {
                hist.base = hist.versions[i].bitmap;
                hist.versions.drain(..=i);
            }
            !hist.versions.is_empty()
        });
        self.filter.rebuild(map.keys());
        self.any.store(!map.is_empty(), Ordering::Release);
    }

    /// The number of nodes with retained label history (observability / tests).
    #[must_use]
    pub fn tracked_nodes(&self) -> usize {
        self.map.read().unwrap_or_else(|e| e.into_inner()).len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn snap(owner: u64, ts: u64) -> Snapshot {
        Snapshot {
            owner: TxnId(owner),
            ts: Timestamp(ts),
        }
    }

    #[test]
    fn no_history_returns_the_live_bitmap() {
        let h = LabelHistory::new();
        let reg = CommitRegistry::default();
        assert!(!h.any(), "a fresh history must not arm the hot-path gate");
        assert_eq!(h.resolve(1, 0b101, snap(9, 100), &reg), 0b101);
    }

    #[test]
    fn an_uncommitted_change_is_invisible_to_others_but_visible_to_its_author() {
        let h = LabelHistory::new();
        let reg = CommitRegistry::default();
        // Node 1 had bit 0; txn 7 clears it, uncommitted.
        h.record(1, TxnId(7), 0b1, 0b0);
        // Another reader must still see the committed value: THE DIRTY READ.
        assert_eq!(h.resolve(1, 0b0, snap(9, 100), &reg), 0b1);
        // The author sees its own write.
        assert_eq!(h.resolve(1, 0b0, snap(7, 100), &reg), 0b0);
    }

    #[test]
    fn a_commit_is_invisible_to_a_snapshot_that_predates_it() {
        let h = LabelHistory::new();
        let mut reg = CommitRegistry::default();
        h.record(1, TxnId(7), 0b1, 0b0);
        reg.record_commit(TxnId(7), Timestamp(50));
        // Older snapshot: THE NON-REPEATABLE READ.
        assert_eq!(h.resolve(1, 0b0, snap(9, 49), &reg), 0b1);
        // At the commit timestamp, and after it.
        assert_eq!(h.resolve(1, 0b0, snap(9, 50), &reg), 0b0);
        assert_eq!(h.resolve(1, 0b0, snap(9, 51), &reg), 0b0);
    }

    #[test]
    fn an_aborted_change_is_invisible_to_everyone_else() {
        let h = LabelHistory::new();
        let mut reg = CommitRegistry::default();
        h.record(1, TxnId(7), 0b1, 0b0);
        reg.record_abort(TxnId(7));
        assert_eq!(h.resolve(1, 0b0, snap(9, 100), &reg), 0b1);
    }

    #[test]
    fn stacked_writers_resolve_newest_visible_wins() {
        let h = LabelHistory::new();
        let mut reg = CommitRegistry::default();
        // base 0b1 -> A sets 0b11 (commits at 10) -> B sets 0b111 (commits at 20).
        h.record(1, TxnId(1), 0b1, 0b11);
        h.record(1, TxnId(2), 0b11, 0b111);
        reg.record_commit(TxnId(1), Timestamp(10));
        reg.record_commit(TxnId(2), Timestamp(20));
        assert_eq!(h.resolve(1, 0b111, snap(9, 5), &reg), 0b1, "before both");
        assert_eq!(h.resolve(1, 0b111, snap(9, 10), &reg), 0b11, "between");
        assert_eq!(h.resolve(1, 0b111, snap(9, 15), &reg), 0b11, "between");
        assert_eq!(h.resolve(1, 0b111, snap(9, 20), &reg), 0b111, "after both");
    }

    #[test]
    fn a_no_op_change_records_nothing() {
        let h = LabelHistory::new();
        h.record(1, TxnId(7), 0b1, 0b1);
        assert!(!h.any());
        assert_eq!(h.tracked_nodes(), 0);
    }

    /// `rmp` #767, Finding 3 (adversarial audit): WHY `RecordStore::rollback` must call `forget`
    /// **after** the WAL undo, not before.
    ///
    /// This demonstrates the composition that makes the ordering load-bearing, in the one place it can
    /// be shown deterministically. `forget` drops the node's entry outright when the aborting writer
    /// was its only versioner; `resolve` then falls back to the LIVE word. Call the two in the wrong
    /// order — `forget` first, undo second — and every concurrent reader (the off-thread pool reads
    /// through the same `Arc`) sees the ABORTED value unmasked in that window: the dirty read #767
    /// exists to close, reintroduced by its own cleanup.
    #[test]
    fn forgetting_before_the_word_is_restored_would_expose_the_aborted_value() {
        let h = LabelHistory::new();
        let reg = CommitRegistry::new();
        // Committed state: bit 0 set. An in-flight writer clears it; the live word now holds 0b0.
        h.record(1, TxnId(7), 0b1, 0b0);

        // WHILE the history still holds the version, a concurrent reader is correctly masked.
        assert_eq!(
            h.resolve(1, 0b0, snap(9, 100), &reg),
            0b1,
            "precondition: the retained version masks the uncommitted word"
        );

        // The WRONG order: forget first, while the word is still the aborted 0b0.
        h.forget(TxnId(7));
        assert_eq!(
            h.resolve(1, 0b0, snap(9, 100), &reg),
            0b0,
            "THE HAZARD: with the entry dropped and the word not yet restored, the reader sees the \
             ABORTED value — this is why `rollback` calls `forget` AFTER the WAL undo"
        );

        // The RIGHT order: the undo has already restored the word, so the fallback is correct.
        assert_eq!(
            h.resolve(1, 0b1, snap(9, 100), &reg),
            0b1,
            "after the undo restores the word, dropping the entry is safe"
        );
    }

    #[test]
    fn forget_drops_an_aborted_writers_versions_and_disarms_the_gate() {
        let h = LabelHistory::new();
        h.record(1, TxnId(7), 0b1, 0b0);
        assert!(h.any());
        h.forget(TxnId(7));
        assert!(!h.any(), "the gate must disarm once the last version goes");
        assert_eq!(h.tracked_nodes(), 0);
    }

    /// `rmp` #767, Finding 4 (adversarial audit): a SETTLED version is prunable, so a full-watermark
    /// pass drains the history completely and disarms the hot-path gate.
    ///
    /// Before `settle` existed, a version whose writer the registry had forgotten resolved to no
    /// commit timestamp FOREVER, so `prune` could never collapse it: the entry leaked for the life of
    /// the process AND kept `any()` armed, putting a lock + map lookup on every label re-check in the
    /// store — the same ~2.9x class of regression the creator gate exists to avoid, arriving by
    /// another route.
    #[test]
    fn a_settled_version_is_prunable_even_after_the_registry_forgets_its_writer() {
        let h = LabelHistory::new();
        let mut reg = CommitRegistry::new();
        h.record(1, TxnId(7), 0b1, 0b0);
        // The store settles at commit; the registry entry is recorded at the same moment.
        h.settle(TxnId(7), Timestamp(100), &[1]);
        reg.record_commit(TxnId(7), Timestamp(100));
        assert!(
            !h.has_inflight_versions_of(TxnId(7)),
            "settle must leave no in-flight stamp behind"
        );

        // The GC pass forgets the writer (NOT watermark-gated: `committed_writers()` returns every
        // writer currently recorded as committed, however recently).
        for w in reg.committed_writers() {
            reg.forget(w);
        }

        // The committed change is STILL visible — resolution no longer consults the registry for it.
        assert_eq!(
            h.resolve(1, 0b0, snap(99, 1000), &reg),
            0b0,
            "a settled version must resolve without its registry entry"
        );
        // And it is prunable, so nothing leaks and the gate disarms.
        h.prune(Timestamp(u64::MAX), &reg);
        assert_eq!(h.tracked_nodes(), 0, "a settled version must be prunable");
        assert!(!h.any(), "the hot-path gate must disarm");
    }

    #[test]
    fn prune_collapses_versions_below_the_watermark_and_disarms_the_gate() {
        let h = LabelHistory::new();
        let mut reg = CommitRegistry::default();
        h.record(1, TxnId(1), 0b1, 0b11);
        reg.record_commit(TxnId(1), Timestamp(10));
        h.settle(TxnId(1), Timestamp(10), &[1]);
        h.prune(Timestamp(10), &reg);
        assert!(!h.any(), "fully-collapsed history must disarm the gate");
        // With the entry gone the live word is authoritative again.
        assert_eq!(h.resolve(1, 0b11, snap(9, 10), &reg), 0b11);
    }

    #[test]
    fn prune_retains_a_version_an_older_reader_still_needs() {
        let h = LabelHistory::new();
        let mut reg = CommitRegistry::default();
        h.record(1, TxnId(1), 0b1, 0b11);
        reg.record_commit(TxnId(1), Timestamp(10));
        // Watermark below the commit: an older reader may still exist.
        h.prune(Timestamp(9), &reg);
        assert!(h.any(), "history needed by an older snapshot must survive");
        assert_eq!(h.resolve(1, 0b11, snap(9, 9), &reg), 0b1);
    }

    #[test]
    fn prune_keeps_an_in_flight_version_above_the_collapsed_base() {
        let h = LabelHistory::new();
        let mut reg = CommitRegistry::default();
        h.record(1, TxnId(1), 0b1, 0b11);
        reg.record_commit(TxnId(1), Timestamp(10));
        h.record(1, TxnId(2), 0b11, 0b111); // still in flight
        h.prune(Timestamp(10), &reg);
        assert!(h.any(), "an in-flight version must not be pruned away");
        // A reader still sees the committed value, not the in-flight one.
        assert_eq!(h.resolve(1, 0b111, snap(9, 10), &reg), 0b11);
        // The author sees its own.
        assert_eq!(h.resolve(1, 0b111, snap(2, 10), &reg), 0b111);
    }

    // ------------------------- pre-filter (`rmp` #808) -------------------------

    /// The pre-filter never yields a false negative for a tracked id: a resolve for any of a set of
    /// tracked ids must reach the history, across an id range wide enough to exercise many
    /// bit-position collisions and the whole hash space.
    #[test]
    fn filter_has_no_false_negative_across_a_wide_id_range() {
        let h = LabelHistory::new();
        let mut reg = CommitRegistry::new();
        // Track a spread of ids (uncommitted writer 7): each resolve MUST return the masked value,
        // never the live word — i.e. the pre-filter must route every one to the slow path.
        let tracked: Vec<u64> = (0..256).map(|k| k * 7919 + 3).collect();
        for &id in &tracked {
            h.record(id, TxnId(7), 0b1, 0b0);
        }
        let _ = &mut reg;
        for &id in &tracked {
            assert_eq!(
                h.resolve(id, 0b0, snap(9, 100), &reg),
                0b1,
                "tracked id {id} was skipped by the pre-filter (false negative = dirty read)"
            );
        }
    }

    /// After a shrink (`forget`), the filter is rebuilt from the survivors, so a still-tracked id is
    /// still routed to the slow path (no false negative), while the disarmed node returns its live
    /// word.
    #[test]
    fn filter_rebuild_preserves_survivors_after_forget() {
        let h = LabelHistory::new();
        let reg = CommitRegistry::new();
        // Two nodes tracked by two different in-flight writers.
        h.record(10, TxnId(7), 0b1, 0b0);
        h.record(20, TxnId(8), 0b1, 0b0);
        // Writer 7 rolls back: node 10's version is dropped; node 20 survives.
        h.forget(TxnId(7));
        assert!(h.any(), "node 20 still tracked");
        // Node 20 (survivor) must still be masked — the rebuilt filter keeps its bits.
        assert_eq!(
            h.resolve(20, 0b0, snap(9, 100), &reg),
            0b1,
            "survivor was skipped after rebuild (false negative)"
        );
        // Node 10 is no longer tracked: its live word is authoritative again.
        assert_eq!(h.resolve(10, 0b1, snap(9, 100), &reg), 0b1);
    }

    /// When the last tracked node is forgotten, the gate disarms and the filter is cleared: a
    /// resolve for the id that WAS tracked now returns the live word via the ultra-fast gate.
    #[test]
    fn filter_clears_when_history_empties() {
        let h = LabelHistory::new();
        let reg = CommitRegistry::new();
        h.record(42, TxnId(7), 0b1, 0b0);
        assert!(
            h.filter.maybe_contains(42),
            "an armed id must be in the filter"
        );
        h.forget(TxnId(7));
        assert!(!h.any(), "gate disarms when the last version goes");
        assert!(
            !h.filter.maybe_contains(42),
            "the filter must be cleared once the history empties"
        );
        assert_eq!(h.resolve(42, 0b111, snap(9, 100), &reg), 0b111);
    }

    /// The filter membership question is exact for a single tracked id and (with overwhelming
    /// probability, given the 4096-bit width) a miss for an untracked one — the property that makes
    /// the untracked majority of a scan skip the lock.
    #[test]
    fn filter_membership_matches_tracked_set() {
        let h = LabelHistory::new();
        h.record(1000, TxnId(7), 0b1, 0b0);
        assert!(h.filter.maybe_contains(1000));
        // A large sample of untracked ids: essentially all should miss (false positives are rare and
        // harmless, so we assert the rate is low rather than zero).
        let fp = (0u64..10_000)
            .filter(|&id| id != 1000 && h.filter.maybe_contains(id))
            .count();
        assert!(
            fp <= 5,
            "false-positive rate unexpectedly high ({fp}/10000) for a single tracked id"
        );
    }
}
