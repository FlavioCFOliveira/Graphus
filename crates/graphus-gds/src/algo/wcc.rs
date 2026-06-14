//! Weakly Connected Components (WCC) via union-find.
//!
//! Two nodes are in the same weak component if they are connected ignoring edge direction. The
//! disjoint-set forest uses **path compression** and **union by size**, giving near-linear total
//! time (inverse-Ackermann amortized per operation).

use crate::cancel::Cancel;
use crate::csr::{CsrGraph, InternalId};
use crate::error::Result;

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

/// The result of a WCC computation.
#[derive(Debug, Clone)]
pub struct WccResult {
    /// `component[i]` is the canonical component id (the smallest internal id in the component) of
    /// node `i`.
    pub component: Vec<InternalId>,
    /// The number of distinct components (equals `node_count` for an edgeless graph).
    pub count: usize,
}

/// Computes weakly connected components.
///
/// # Complexity
/// Time `O(n + m · α(n))` (effectively linear), space `O(n)`. Self-loops, parallel edges and
/// direction are irrelevant to the result and handled without special-casing.
///
/// # Errors
/// [`crate::error::GdsError::Cancelled`] if `cancel` fires (checked every `CANCEL_STRIDE` edges).
pub fn weakly_connected_components(graph: &CsrGraph, cancel: &Cancel<'_>) -> Result<WccResult> {
    const CANCEL_STRIDE: usize = 1 << 16;
    let n = graph.node_count();
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
