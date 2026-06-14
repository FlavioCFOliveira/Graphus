//! Strongly Connected Components (SCC) via **iterative** Tarjan.
//!
//! Tarjan's algorithm is naturally recursive; on large graphs a recursive DFS overflows the call
//! stack. This implementation drives the DFS with an **explicit heap-allocated work stack**, so its
//! memory use is bounded by the heap, not the OS thread stack — the project mandate forbids any
//! recursion whose depth scales with graph size.

use crate::cancel::Cancel;
use crate::csr::{CsrGraph, InternalId};
use crate::error::Result;

const UNVISITED: u32 = u32::MAX;

/// A single frame of the explicit DFS stack.
struct Frame {
    node: u32,
    /// Index into `node`'s neighbour slice of the next edge to explore.
    next_edge: usize,
}

/// The result of an SCC computation.
#[derive(Debug, Clone)]
pub struct SccResult {
    /// `component[i]` is the SCC id of node `i`. Ids are assigned in the order SCCs are finalized.
    pub component: Vec<u32>,
    /// The number of strongly connected components.
    pub count: usize,
}

/// Computes strongly connected components with iterative Tarjan.
///
/// # Complexity
/// Time `O(n + m)`, space `O(n)` (index/lowlink/on-stack arrays plus the explicit DFS and Tarjan
/// stacks). Self-loops and parallel edges do not change the SCC partition and need no special
/// handling.
///
/// # Errors
/// [`crate::error::GdsError::Cancelled`] if `cancel` fires (checked per DFS root and periodically
/// while popping the Tarjan stack).
pub fn strongly_connected_components(graph: &CsrGraph, cancel: &Cancel<'_>) -> Result<SccResult> {
    let n = graph.node_count();
    let mut index = vec![UNVISITED; n]; // discovery index, UNVISITED = not yet visited
    let mut lowlink = vec![0u32; n];
    let mut on_stack = vec![false; n];
    let mut component = vec![UNVISITED; n];

    let mut tarjan_stack: Vec<u32> = Vec::new();
    let mut dfs_stack: Vec<Frame> = Vec::new();
    let mut next_index: u32 = 0;
    let mut next_component: u32 = 0;

    for root in 0..n {
        if index[root] != UNVISITED {
            continue;
        }
        cancel.check()?;

        dfs_stack.push(Frame {
            node: root as u32,
            next_edge: 0,
        });
        // Initialize the root frame on first push.
        index[root] = next_index;
        lowlink[root] = next_index;
        next_index += 1;
        on_stack[root] = true;
        tarjan_stack.push(root as u32);

        while let Some(frame) = dfs_stack.last_mut() {
            let v = frame.node;
            let neighbors = graph.neighbors(v).unwrap_or(&[]);

            if frame.next_edge < neighbors.len() {
                let w = neighbors[frame.next_edge];
                frame.next_edge += 1;
                let wi = w as usize;
                if index[wi] == UNVISITED {
                    // Tree edge: descend. Initialize w, then push its frame.
                    index[wi] = next_index;
                    lowlink[wi] = next_index;
                    next_index += 1;
                    on_stack[wi] = true;
                    tarjan_stack.push(w);
                    dfs_stack.push(Frame {
                        node: w,
                        next_edge: 0,
                    });
                } else if on_stack[wi] {
                    // Back/cross edge to a node still on the Tarjan stack.
                    let vi = v as usize;
                    lowlink[vi] = lowlink[vi].min(index[wi]);
                }
                // else: edge to an already-finalized SCC; ignore.
            } else {
                // All edges of v explored: v is done. Pop and propagate lowlink to parent.
                let vi = v as usize;
                if lowlink[vi] == index[vi] {
                    // v is an SCC root: pop the Tarjan stack down to v.
                    let comp_id = next_component;
                    next_component += 1;
                    while let Some(w) = tarjan_stack.pop() {
                        on_stack[w as usize] = false;
                        component[w as usize] = comp_id;
                        if w == v {
                            break;
                        }
                    }
                    cancel.check()?;
                }
                dfs_stack.pop();
                if let Some(parent) = dfs_stack.last() {
                    let pi = parent.node as usize;
                    lowlink[pi] = lowlink[pi].min(lowlink[vi]);
                }
            }
        }
    }

    Ok(SccResult {
        component,
        count: next_component as usize,
    })
}

/// Convenience: maps internal SCC ids to the canonical (minimum internal id) representative, useful
/// for cross-checking against WCC-style canonical labelling in tests.
#[must_use]
pub fn canonicalize(result: &SccResult, node_count: usize) -> Vec<InternalId> {
    let mut rep = vec![InternalId::MAX; result.count];
    for (node, &comp) in result.component.iter().enumerate().take(node_count) {
        let c = comp as usize;
        if c < rep.len() {
            rep[c] = rep[c].min(node as InternalId);
        }
    }
    result.component.iter().map(|&c| rep[c as usize]).collect()
}
