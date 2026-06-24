//! The **opt-in** type-bucketed CSR adjacency accelerator (`rmp` task #324, "Win 2").
//!
//! # What this is and why it exists
//!
//! "Win 1" (commit `b7a9ea9`) made a typed `expand` walk the node's `first_rel` incidence chain
//! **once**, reading each incident edge a single time and SSI-marking only the matching-type ones
//! ([`graphus_storage::RecordStore::incident_rels_typed`]). That removed the *second* read of every
//! non-matching edge, but a type-selective expand still **reads every non-matching chain link once**
//! to follow the chain's `next` pointers.
//!
//! "Win 2" removes that remaining read for type-selective expands: a flat
//! [Compressed-Sparse-Row][csr]-style adjacency, keyed by `(node_id, type_id)`, that yields **only
//! the matching-type candidate relationship ids** directly — so the engine never touches a
//! non-matching chain link. It is built from the store's committed state, exactly like the derived
//! [`IndexSet`](crate::index_set::IndexSet), and is **strictly opt-in**: when the
//! [`csr_adjacency_enabled`] knob is off (the default) **no CSR is built**, so there is zero extra RAM
//! and `expand` behaves byte-for-byte identically to Win-1-only.
//!
//! [csr]: https://en.wikipedia.org/wiki/Sparse_matrix#Compressed_sparse_row_(CSR,_CRS_or_Yale_format)
//!
//! # Candidate accelerator only — never a source of truth (`rmp` #324 constraint 2)
//!
//! [`candidates`](CsrAdjacency::candidates) returns relationship **physical ids** of the requested
//! type(s) incident to a node. They are exactly that — **candidates**. The caller
//! ([`read_source::expand`](crate::read_source::expand)) still issues a per-candidate `rel()` read and
//! the full MVCC visibility re-check, exactly as an index seek re-checks its candidates. The CSR never
//! decides which edges are *visible*; it only restricts *which physical ids the engine bothers to
//! read*. A stale CSR that returned a **superset** would therefore still be correct (the extra ids are
//! filtered out by visibility + the type re-check on the decoded record); the only thing that would be
//! a correctness bug is **under-coverage** — a matching, committed edge the CSR omits — which the
//! freshness gate below makes impossible.
//!
//! # Result-equality with the chain walk (`rmp` #324 constraint 3)
//!
//! When the CSR is consulted, the relationship-id **set** it yields for `(node, wanted_types)` is
//! exactly the set [`incident_rels_typed`](graphus_storage::RecordStore::incident_rels_typed) yields,
//! so `expand` produces the identical visible-edge set and the identical SSI markers. The CSR is built
//! from the **same committed-edge enumeration** the chain walk traverses (a full live-relationship
//! scan, deduping a self-loop's two physical occurrences to one id, threading through dead-link
//! corpses by simply ignoring not-`in_use` slots), so its per-`(node, type)` id set is the chain
//! walk's matching subset by construction. The `expand` body still registers the **rel-type predicate
//! marker** (the phantom cover for a concurrent matching-type insert) and SIREAD-marks each candidate,
//! so the SSI footprint is byte-identical whether the ids came from the CSR or the chain.
//!
//! # Maintenance model (`rmp` #324 constraint 5) — rebuild-on-open + freshness gate
//!
//! The CSR is **rebuilt from the store on coordinator open**
//! ([`TxnCoordinator::new`](crate::coordinator::TxnCoordinator::new)), the same lifecycle as
//! [`IndexSet`](crate::index_set::IndexSet) — so a freshly-recovered store yields a store-consistent
//! CSR by construction, with nothing to commit or replay.
//!
//! Rather than patch the flat arrays on every edge insert/delete — which would force a per-node
//! growable structure (the `rmp` #379 anti-pattern: per-node `Vec<RelId>` reallocation under churn)
//! and lose the compact 8-bytes/edge layout — the CSR is **marked stale** the moment any statement
//! attempts a relationship mutation ([`mark_dirty`](CsrAdjacency::mark_dirty), driven from
//! `create_rel` / `delete_rel`). While stale it is **never consulted**: `expand` falls back to the
//! Win-1 chain walk, which reflects the live store exactly. This is the design the task explicitly
//! sanctions ("marked stale and consulted only when fresh, falling back to the Win-1 chain walk when
//! stale/disabled") and it keeps the result-equality guarantee unconditional — the CSR is consulted
//! **only** while it provably still mirrors the committed incidence (built-on-open, no rel write
//! since), and the chain walk covers every other case.
//!
//! This makes the accelerator most effective for the workload `rmp` #324 targets: a bulk load (or any
//! write-then-read phase) followed by type-selective analytical traversal (e.g. `top_liked@large`),
//! where the CSR is built once and then consulted across many read-only queries.

use std::collections::BTreeMap;

use graphus_io::BlockDevice;
use graphus_storage::RecordStore;
use graphus_wal::LogSink;

/// A flat, type-bucketed CSR adjacency over committed relationship incidence (`rmp` task #324, Win 2).
///
/// # Layout (`rmp` #324 constraint 4 — compact, no per-node `Vec`)
///
/// Three flat arrays, mirroring the [`IndexSet`](crate::index_set::IndexSet) rebuild-on-open model:
///
/// * `directory: Vec<(u64, u32)>` — the **group key** `(node_id, type_id)` for each non-empty bucket,
///   sorted ascending, so a `(node, type)` lookup is a [`slice::binary_search`].
/// * `offsets: Vec<u32>` — `offsets[g]..offsets[g + 1]` is group `g`'s slice into `rels`. Length is
///   `directory.len() + 1` (the standard CSR offset sentinel).
/// * `rels: Vec<u64>` — the relationship physical ids, grouped by `(node_id, type_id)` in `directory`
///   order, ascending within a group.
///
/// The dominant cost is `rels` at **8 bytes per (deduped) incident edge endpoint**; `directory` and
/// `offsets` add a small per-`(node, type)`-bucket overhead (12 + 4 bytes), amortised across the
/// bucket's edges. There is **no** per-node owned `Vec` (the `rmp` #379 anti-pattern); the whole
/// structure is three contiguous allocations.
///
/// # Freshness
///
/// `dirty` starts `false` after a build and is latched `true` by [`mark_dirty`](Self::mark_dirty) on
/// the first relationship mutation. [`candidates`](Self::candidates) returns `None` while `dirty`, so
/// the caller falls back to the chain walk (see the module docs' maintenance model).
#[derive(Debug, Default)]
pub struct CsrAdjacency {
    /// The sorted `(node_id, type_id)` group keys; index `g` here selects `offsets[g]..offsets[g+1]`.
    directory: Vec<(u64, u32)>,
    /// CSR offsets: `offsets[g]..offsets[g + 1]` bounds group `g`'s ids in `rels`. `directory.len() + 1`.
    offsets: Vec<u32>,
    /// The relationship physical ids, grouped by `directory` order, ascending within a group.
    rels: Vec<u64>,
    /// Whether the CSR has been invalidated by a relationship mutation since it was last built. While
    /// `true`, [`candidates`](Self::candidates) declines so the caller uses the live chain walk.
    dirty: bool,
}

impl CsrAdjacency {
    /// An empty, **fresh** CSR (no buckets). Built into a populated one by
    /// [`build`](Self::build_from_store); used as the initial coordinator state before a build.
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// Whether this CSR is currently stale (a relationship mutation invalidated it since the last
    /// build). A stale CSR is never consulted.
    #[must_use]
    pub fn is_dirty(&self) -> bool {
        self.dirty
    }

    /// Latches the CSR stale (`rmp` #324, the freshness gate). Called from `create_rel` / `delete_rel`
    /// on the statement seam: any attempt to mutate relationship incidence invalidates the snapshot,
    /// so subsequent [`candidates`](Self::candidates) calls decline and `expand` walks the live chain
    /// until the next rebuild-on-open. Idempotent.
    pub fn mark_dirty(&mut self) {
        self.dirty = true;
    }

    /// The total number of relationship-id entries stored (the `rels` length): the measured footprint
    /// is `8 * entries()` bytes for `rels`, plus `16 * groups()` for the directory/offsets. `0` for an
    /// empty or never-built CSR.
    #[must_use]
    pub fn entries(&self) -> usize {
        self.rels.len()
    }

    /// The number of non-empty `(node_id, type_id)` groups (the `directory` length).
    #[must_use]
    pub fn groups(&self) -> usize {
        self.directory.len()
    }

    /// The approximate heap footprint of this CSR in bytes: `size_of::<u64>() * entries()` for `rels`,
    /// `size_of::<(u64, u32)>() * groups()` for `directory`, and `size_of::<u32>() * offsets.len()` for
    /// `offsets`. Used by the footprint test/bench to report bytes-per-edge. An empty CSR (knob off, so
    /// never built) reports `0`.
    #[must_use]
    pub fn approx_heap_bytes(&self) -> usize {
        self.rels.len() * std::mem::size_of::<u64>()
            + self.directory.len() * std::mem::size_of::<(u64, u32)>()
            + self.offsets.len() * std::mem::size_of::<u32>()
    }

    /// The matching-type candidate relationship ids incident to `node_id` for the requested
    /// `wanted_types`, **or `None` if the CSR is stale** (the caller must then walk the live chain).
    ///
    /// `wanted_types` must be **non-empty** (a typed expand): an untyped expand has no type bucket to
    /// seek and always uses the chain walk, so this returns `None` for an empty `wanted_types`. The
    /// returned ids are **candidates** (constraint 2): the caller re-reads each with `rel()` and
    /// applies the full MVCC visibility + type re-check.
    ///
    /// The returned set equals
    /// [`incident_rels_typed`](graphus_storage::RecordStore::incident_rels_typed)`(node_id,
    /// wanted_types)`'s id set whenever the CSR is fresh (constraint 3): the same committed edges, the
    /// same self-loop dedupe (one id per self-loop, recorded once at build), the same corpse threading
    /// (a not-`in_use` slot is simply absent from the build). Order within the result is ascending by
    /// id, then grouped by the order of `wanted_types`; `expand` does not depend on order (it
    /// SIREAD-marks and visibility-filters each, then reports the matching side), but ascending-per-type
    /// keeps the candidate stream deterministic.
    #[must_use]
    pub fn candidates(&self, node_id: u64, wanted_types: &[u32]) -> Option<Vec<u64>> {
        if self.dirty || wanted_types.is_empty() {
            return None;
        }
        let mut out = Vec::new();
        for &ty in wanted_types {
            if let Ok(g) = self.directory.binary_search(&(node_id, ty)) {
                let start = self.offsets[g] as usize;
                let end = self.offsets[g + 1] as usize;
                out.extend_from_slice(&self.rels[start..end]);
            }
        }
        Some(out)
    }

    /// Rebuilds the CSR from `store`'s committed relationship state (`rmp` task #324, Win 2), clearing
    /// any stale flag. This is the rebuild-on-open path the coordinator calls; it mirrors
    /// [`TxnCoordinator::rebuild_index`](crate::coordinator::TxnCoordinator::rebuild_index)'s
    /// full-store scan.
    ///
    /// It enumerates every live relationship (`scan_rel_ids` yields only `in_use` slots, so dead-link
    /// corpses are excluded — exactly as the chain walk threads through them), and for each, buckets
    /// its id under **each distinct incident node** `(node, type_id)`: under `start_node` and, unless
    /// it is a self-loop, under `end_node`. A self-loop (`start_node == end_node`) is bucketed **once**
    /// under that single node, matching the chain walk's one-id-per-self-loop dedupe. The resulting
    /// per-bucket id lists are then flattened into the three CSR arrays in sorted `(node, type)` order.
    ///
    /// On a transient storage read error for a relationship the relationship is skipped (it cannot be
    /// bucketed). This can only under-cover, which a stale flag would normally forbid — but a build
    /// that hit a read fault is conservatively marked **dirty** so the (possibly incomplete) CSR is
    /// never consulted; `expand` then uses the always-correct chain walk. (In practice the rel store
    /// never unmaps a slot `scan_rel_ids` returned, so this is defence-in-depth.)
    pub fn build_from_store<D: BlockDevice, S: LogSink>(&mut self, store: &RecordStore<D, S>) {
        // A BTreeMap keyed by (node_id, type_id) gives the sorted group order the flat directory needs
        // and dedups a self-loop naturally (it is inserted under one key). Build cost is one full live
        // relationship scan — the same scan `rebuild_index` runs over nodes.
        let mut buckets: BTreeMap<(u64, u32), Vec<u64>> = BTreeMap::new();
        let mut faulted = false;

        let rel_ids = match store.scan_rel_ids() {
            Ok(ids) => ids,
            Err(_) => {
                // Could not enumerate live relationships: leave the CSR empty and mark it dirty so it
                // is never consulted. `expand` uses the chain walk.
                self.directory.clear();
                self.offsets.clear();
                self.rels.clear();
                self.dirty = true;
                return;
            }
        };

        for rid in rel_ids {
            let rec = match store.rel(rid) {
                Ok(rec) => rec,
                Err(_) => {
                    faulted = true;
                    continue;
                }
            };
            // `scan_rel_ids` already filtered to `in_use`, but guard anyway: a corpse must not be
            // bucketed (the chain walk ignores not-`in_use` links).
            if !rec.mvcc.in_use() {
                continue;
            }
            buckets
                .entry((rec.start_node, rec.type_id))
                .or_default()
                .push(rid);
            if rec.end_node != rec.start_node {
                // Not a self-loop: also incident to the end node. A self-loop is bucketed once (above),
                // matching the chain walk's single-id-per-self-loop dedupe.
                buckets
                    .entry((rec.end_node, rec.type_id))
                    .or_default()
                    .push(rid);
            }
        }

        // Flatten the sorted buckets into the three CSR arrays. `BTreeMap` iteration is ascending by
        // key, so `directory` is sorted (binary-searchable) by construction; each bucket's ids are
        // sorted ascending because `scan_rel_ids` yields ascending ids and we push in scan order.
        let group_count = buckets.len();
        self.directory.clear();
        self.directory.reserve(group_count);
        self.offsets.clear();
        self.offsets.reserve(group_count + 1);
        self.rels.clear();
        self.offsets.push(0);
        for (key, ids) in buckets {
            self.directory.push(key);
            self.rels.extend_from_slice(&ids);
            // CSR offsets fit in u32 (the rel store's id space is u64, but the count of incident
            // endpoints is bounded by 2 * live-rel-count; a graph with > 4 billion incident endpoints
            // is far past this single-process engine's footprint). Saturate defensively.
            let off = u32::try_from(self.rels.len()).unwrap_or(u32::MAX);
            self.offsets.push(off);
        }

        // A clean, complete build is fresh; a build that hit a read fault is conservatively stale.
        self.dirty = faulted;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A small hand-built CSR to unit-test the lookup/offset arithmetic without a store: two nodes,
    /// two types, including a node with two same-type parallel edges and a node with edges of two
    /// types. Asserts `candidates` slices the right ids and respects the freshness gate.
    fn fixture() -> CsrAdjacency {
        // directory (sorted): (1,10), (1,20), (2,10)
        // node 1 / type 10 -> [100, 101]   (parallel multigraph edges)
        // node 1 / type 20 -> [102]
        // node 2 / type 10 -> [100]         (the other endpoint of rel 100)
        CsrAdjacency {
            directory: vec![(1, 10), (1, 20), (2, 10)],
            offsets: vec![0, 2, 3, 4],
            rels: vec![100, 101, 102, 100],
            dirty: false,
        }
    }

    #[test]
    fn candidates_slices_the_requested_type_bucket() {
        let csr = fixture();
        assert_eq!(csr.candidates(1, &[10]), Some(vec![100, 101]));
        assert_eq!(csr.candidates(1, &[20]), Some(vec![102]));
        assert_eq!(csr.candidates(2, &[10]), Some(vec![100]));
    }

    #[test]
    fn candidates_unions_multiple_requested_types() {
        let csr = fixture();
        // Both types of node 1, in `wanted_types` order.
        assert_eq!(csr.candidates(1, &[10, 20]), Some(vec![100, 101, 102]));
        assert_eq!(csr.candidates(1, &[20, 10]), Some(vec![102, 100, 101]));
    }

    #[test]
    fn candidates_empty_for_absent_node_or_type() {
        let csr = fixture();
        assert_eq!(csr.candidates(1, &[99]), Some(vec![]));
        assert_eq!(csr.candidates(7, &[10]), Some(vec![]));
    }

    #[test]
    fn untyped_request_declines() {
        let csr = fixture();
        // An empty `wanted_types` (untyped expand) has no bucket; the chain walk handles it.
        assert_eq!(csr.candidates(1, &[]), None);
    }

    #[test]
    fn stale_csr_declines_every_lookup() {
        let mut csr = fixture();
        csr.mark_dirty();
        assert!(csr.is_dirty());
        assert_eq!(csr.candidates(1, &[10]), None);
        assert_eq!(csr.candidates(1, &[10, 20]), None);
    }

    #[test]
    fn footprint_accounting() {
        let csr = fixture();
        assert_eq!(csr.entries(), 4);
        assert_eq!(csr.groups(), 3);
        // 4 ids * 8 + 3 dir * 16 + 4 offs * 4 = 32 + 48 + 16 = 96
        assert_eq!(csr.approx_heap_bytes(), 96);
        let empty = CsrAdjacency::empty();
        assert_eq!(empty.approx_heap_bytes(), 0);
        assert!(!empty.is_dirty());
    }
}
