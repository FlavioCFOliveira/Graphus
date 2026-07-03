//! Weakly Connected Components (WCC) via union-find.
//!
//! Two nodes are in the same weak component if they are connected ignoring edge direction.
//!
//! # Two union-find engines (`rmp` #342 / #559)
//!
//! - **Sequential** uses a classic disjoint-set forest with **path-halving** and **union by size** —
//!   near-linear total time, cache-friendly, and hard to beat on a single core.
//! - **Parallel** uses a **lock-free** disjoint-set forest whose links always point toward the
//!   **smaller** id ([`AtomicU32`] parent array, `compare_exchange`-linked). Edges are unioned across
//!   all cores; path-halving keeps the trees shallow. Link-by-min guarantees `parent[x] <= x` for
//!   every node, so the parent chain strictly descends — there can never be a cycle, and `find`
//!   always terminates even while other threads mutate the array. It uses **no `unsafe`** (only safe
//!   atomics), honouring the crate's `#![forbid(unsafe_code)]`.
//!
//! Both engines yield the **same partition**, and both canonicalise every node to the **minimum
//! internal id** in its component — a property of the final partition, not of the union order — so the
//! `component` vector and `count` are **bit-identical** regardless of the [`Execution`] mode or the
//! `rayon` pool width. The disjoint-set forest uses path compression / halving and union by size /
//! by-min, giving near-linear total time (inverse-Ackermann amortized per operation).

use crate::cancel::Cancel;
use crate::csr::{CsrGraph, InternalId};
use crate::error::Result;
use crate::execution::Execution;
use std::sync::atomic::{AtomicU32, Ordering};

/// A disjoint-set (union-find) forest with path compression and union by size.
#[derive(Debug)]
struct UnionFind {
    parent: Vec<u32>,
    size: Vec<u32>,
}

impl UnionFind {
    fn new(n: usize) -> Self {
        let mut parent = Vec::with_capacity(n);
        for i in 0..n {
            parent.push(i as u32);
        }
        Self {
            parent,
            size: vec![1u32; n],
        }
    }

    /// Finds the representative of `x` with iterative path-halving (no recursion, no stack growth).
    fn find(&mut self, mut x: u32) -> u32 {
        while self.parent[x as usize] != x {
            let grandparent = self.parent[self.parent[x as usize] as usize];
            self.parent[x as usize] = grandparent;
            x = grandparent;
        }
        x
    }

    /// Unions the sets containing `a` and `b` (union by size). Returns whether a merge happened.
    fn union(&mut self, a: u32, b: u32) -> bool {
        let ra = self.find(a);
        let rb = self.find(b);
        if ra == rb {
            return false;
        }
        let (big, small) = if self.size[ra as usize] >= self.size[rb as usize] {
            (ra, rb)
        } else {
            (rb, ra)
        };
        self.parent[small as usize] = big;
        self.size[big as usize] = self.size[big as usize].saturating_add(self.size[small as usize]);
        true
    }
}

/// A lock-free disjoint-set forest keyed on an [`AtomicU32`] parent array, linking always toward the
/// **smaller** id. Safe under concurrent `union` from many threads with no locks and no `unsafe`.
struct AtomicUnionFind {
    parent: Vec<AtomicU32>,
}

impl AtomicUnionFind {
    fn new(n: usize) -> Self {
        Self {
            parent: (0..n as u32).map(AtomicU32::new).collect(),
        }
    }

    /// Finds the current root of `x`, applying best-effort path-halving. Terminates under concurrent
    /// mutation because `parent[y] <= y` always holds (link-by-min), so following parents strictly
    /// descends until a self-parent (root) is reached. `Relaxed` suffices: correctness needs only
    /// per-location atomicity, never cross-location ordering (the final read phase is fenced by the
    /// `rayon` join that follows the union phase).
    fn find(&self, mut x: u32) -> u32 {
        loop {
            let p = self.parent[x as usize].load(Ordering::Relaxed);
            if p == x {
                return x;
            }
            let gp = self.parent[p as usize].load(Ordering::Relaxed);
            // Path-halving shortcut: point `x` at its grandparent. A stale CAS simply no-ops; the
            // target `gp` is always an ancestor (id <= p <= x), so the descend invariant is preserved.
            let _ = self.parent[x as usize].compare_exchange(
                p,
                gp,
                Ordering::Relaxed,
                Ordering::Relaxed,
            );
            x = gp;
        }
    }

    /// Unions the sets of `a` and `b`, always linking the larger root under the smaller. Retries on a
    /// lost race until the two roots coincide. Because the surviving root of any merge is the smaller
    /// id, a component's root is its minimum id — the canonical label — with no separate relabel pass.
    fn union(&self, a: u32, b: u32) {
        let mut ra = self.find(a);
        let mut rb = self.find(b);
        while ra != rb {
            let (hi, lo) = if ra > rb { (ra, rb) } else { (rb, ra) };
            // Link `hi -> lo`, but only while `hi` is still a root. If another thread re-parented
            // `hi` first, re-find both roots and retry; roots only ever decrease, so this converges.
            match self.parent[hi as usize].compare_exchange(
                hi,
                lo,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(_) => {
                    ra = self.find(hi);
                    rb = self.find(lo);
                }
            }
        }
    }
}

/// The result of a WCC computation.
#[derive(Debug, Clone)]
pub struct WccResult {
    /// `component[i]` is the canonical component id (the smallest internal id in the component) of
    /// node `i`.
    pub component: Vec<InternalId>,
    /// The number of distinct components (equals `node_count` for an edgeless graph).
    pub count: usize,
}

/// Computes weakly connected components with the default [`Execution`].
///
/// A thin wrapper over [`weakly_connected_components_with`].
///
/// # Errors
/// See [`weakly_connected_components_with`].
pub fn weakly_connected_components(graph: &CsrGraph, cancel: &Cancel<'_>) -> Result<WccResult> {
    weakly_connected_components_with(graph, Execution::default(), cancel)
}

/// Computes weakly connected components with an explicit [`Execution`] knob.
///
/// # Determinism
/// The `component` labels (minimum internal id per component) and `count` are **bit-identical** across
/// [`Execution`] modes and `rayon` pool widths — connectivity and the per-component minimum id are
/// invariants of the graph, independent of union order.
///
/// # Complexity
/// Time `O(n + m · α(n))` (effectively linear), space `O(n)`. Self-loops, parallel edges and
/// direction are irrelevant to the result and handled without special-casing.
///
/// # Errors
/// [`crate::error::GdsError::Cancelled`] if `cancel` fires (checked periodically).
pub fn weakly_connected_components_with(
    graph: &CsrGraph,
    exec: Execution,
    cancel: &Cancel<'_>,
) -> Result<WccResult> {
    let n = graph.node_count();
    // `rmp` #580: gate on **edge** count (WCC's cost is `O(m·α)`, dominated by the `m` union
    // operations) against a floor, because the lock-free atomic union-find + `rayon` fan-out has a
    // fixed overhead that a small/sparse graph cannot amortise — below the floor the parallel engine
    // *regresses* vs the trivial sequential union-find (measured in `tests/perf_probe.rs`).
    if exec.is_parallel_floor(graph.edge_count(), WCC_MIN_PARALLEL_EDGES) {
        weakly_connected_components_parallel(graph, n, exec, cancel)
    } else {
        weakly_connected_components_sequential(graph, n, cancel)
    }
}

/// Minimum edge count for the lock-free parallel WCC engine to beat the sequential union-find
/// (`rmp` #580). Below this the atomic-CAS + `rayon` overhead dominates the near-linear serial cost.
/// Measured on the 8-core reference box (`tests/perf_probe.rs`): `~40k` edges is still marginal
/// (`≈0.9–1.2x`, noisy), while `~400k` edges is a clean `≈2x`; this conservative floor sits above the
/// marginal zone so the parallel engine is only chosen where it reliably wins.
const WCC_MIN_PARALLEL_EDGES: usize = 1 << 17;

/// Sequential union-find (the classic path-halving + union-by-size engine).
fn weakly_connected_components_sequential(
    graph: &CsrGraph,
    n: usize,
    cancel: &Cancel<'_>,
) -> Result<WccResult> {
    const CANCEL_STRIDE: usize = 1 << 16;
    let mut uf = UnionFind::new(n);

    let mut processed = 0usize;
    for (src, neis) in graph.iter_adjacency() {
        for &dst in neis {
            uf.union(src, dst);
            processed += 1;
            if processed % CANCEL_STRIDE == 0 {
                cancel.check()?;
            }
        }
    }

    // Relabel each node to the minimum internal id in its set, giving a stable canonical id.
    let mut canonical = vec![InternalId::MAX; n];
    for i in 0..n {
        let root = uf.find(i as u32);
        let slot = &mut canonical[root as usize];
        if (i as InternalId) < *slot {
            *slot = i as InternalId;
        }
    }
    let mut component = vec![0 as InternalId; n];
    let mut seen_roots = std::collections::HashSet::new();
    for (i, slot) in component.iter_mut().enumerate() {
        let root = uf.find(i as u32);
        *slot = canonical[root as usize];
        seen_roots.insert(root);
    }

    Ok(WccResult {
        component,
        count: seen_roots.len(),
    })
}

/// Lock-free union-find: unions every edge across cores, then reads each node's (min-id) root.
fn weakly_connected_components_parallel(
    graph: &CsrGraph,
    n: usize,
    exec: Execution,
    cancel: &Cancel<'_>,
) -> Result<WccResult> {
    let uf = AtomicUnionFind::new(n);

    // Union phase: fan the per-source edge lists across cores. Each `union` is a lock-free atomic
    // operation on the shared parent array. Cancellation is checked per source.
    exec.try_for_each(n, |src| {
        cancel.check()?;
        if let Some(neis) = graph.neighbors(src as InternalId) {
            for &dst in neis {
                uf.union(src as u32, dst);
            }
        }
        Ok(())
    })?;

    // Read phase (after the `try_for_each` join = a happens-before barrier): each node's root is the
    // minimum id of its component, so `component[i] = find(i)` is already the canonical label. Written
    // once per slot => deterministic and safely parallel.
    let mut component = vec![0 as InternalId; n];
    exec.map_into(&mut component, |i| uf.find(i as u32));

    // Distinct component labels = component count. Counted serially in a fixed order.
    let distinct: std::collections::HashSet<InternalId> = component.iter().copied().collect();
    Ok(WccResult {
        component,
        count: distinct.len(),
    })
}
