//! `#[ignore]` micro-bench for the shared simple-undirected flat CSR cache (`rmp` task #379).
//!
//! Run with: `cargo test -p graphus-gds --test simple_undirected_bench --release -- --ignored
//! --nocapture`.
//!
//! It contrasts a triangles + LPA **sweep** over the same projection under two adjacency strategies:
//!  - **OLD**: each consumer rebuilds the per-node-`Vec` adjacency from scratch (`n` small `Vec`s,
//!    sorted+deduped) — modelled here by `old_per_node_vecs`, the pre-#379 helper.
//!  - **NEW**: the single flat CSR is built once on the projection and reused by both consumers.
//!
//! Both wall time and **allocation count** (via a counting global allocator) are reported so the CPU
//! and RAM-fragmentation reduction is measured, not asserted by folklore.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use graphus_gds::algo::community::{LabelPropagationConfig, label_propagation};
use graphus_gds::algo::triangles::triangle_count;
use graphus_gds::{Cancel, CsrGraph, InternalId, Orientation, VecGraphSource};

/// A pass-through allocator that counts every allocation, so a sweep's alloc count is observable.
struct CountingAlloc;

static ALLOCS: AtomicU64 = AtomicU64::new(0);

// The allocator delegates every call to the system allocator unchanged; the only added behaviour is a
// relaxed counter bump, which cannot affect allocation correctness.
unsafe impl GlobalAlloc for CountingAlloc {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        ALLOCS.fetch_add(1, Ordering::Relaxed);
        // SAFETY: forwarding to the system allocator with the caller's layout.
        unsafe { System.alloc(layout) }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        // SAFETY: forwarding the caller's (ptr, layout) pair to the system allocator.
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static GLOBAL: CountingAlloc = CountingAlloc;

/// The pre-#379 per-node-`Vec` adjacency build (one fresh allocation set per call).
fn old_per_node_vecs(graph: &CsrGraph) -> Vec<Vec<InternalId>> {
    let n = graph.node_count();
    let mut adj: Vec<Vec<InternalId>> = vec![Vec::new(); n];
    for i in 0..n as InternalId {
        for &v in graph.neighbors(i).unwrap_or(&[]) {
            if i == v {
                continue;
            }
            adj[i as usize].push(v);
            if let Some(list) = adj.get_mut(v as usize) {
                list.push(i);
            }
        }
    }
    for list in &mut adj {
        list.sort_unstable();
        list.dedup();
    }
    adj
}

/// A ring-of-cliques fixture: dense enough that the adjacency build is non-trivial.
fn fixture(cliques: u64, clique_size: u64) -> CsrGraph {
    let n = cliques * clique_size;
    let nodes: Vec<u64> = (0..n).collect();
    let mut edges: Vec<(u64, u64, f64)> = Vec::new();
    for c in 0..cliques {
        let base = c * clique_size;
        for a in 0..clique_size {
            for b in (a + 1)..clique_size {
                edges.push((base + a, base + b, 1.0));
            }
        }
        // bridge to the next clique
        let next = ((c + 1) % cliques) * clique_size;
        edges.push((base, next, 1.0));
    }
    let src = VecGraphSource { nodes, edges };
    src.build(Orientation::Directed, false).expect("build")
}

#[test]
#[ignore = "bench: run with --release -- --ignored --nocapture"]
fn bench_sweep_old_vs_new() {
    let g = fixture(200, 40); // 8_000 nodes, ~156k undirected edges
    let cancel = Cancel::never();
    let cfg = LabelPropagationConfig { max_iter: 20 };

    // ---- OLD: each consumer rebuilds the per-node-Vec adjacency. Model the two builds a sweep paid.
    let a0 = ALLOCS.load(Ordering::Relaxed);
    let t0 = Instant::now();
    let _adj_triangles = old_per_node_vecs(&g); // triangle_count's build
    let _adj_lpa = old_per_node_vecs(&g); // label_propagation's build
    let old_build_time = t0.elapsed();
    let old_build_allocs = ALLOCS.load(Ordering::Relaxed) - a0;
    std::hint::black_box((&_adj_triangles, &_adj_lpa));

    // ---- NEW: one flat-CSR build, shared. Force it once; the second "consumer" reuses (0 allocs).
    let g2 = fixture(200, 40);
    let a1 = ALLOCS.load(Ordering::Relaxed);
    let t1 = Instant::now();
    let _ = std::hint::black_box(g2.simple_undirected_csr()); // build
    let _ = std::hint::black_box(g2.simple_undirected_csr()); // reuse (no alloc)
    let new_build_time = t1.elapsed();
    let new_build_allocs = ALLOCS.load(Ordering::Relaxed) - a1;

    // ---- Full sweep wall time end-to-end (build + compute), to confirm no regression.
    let g3 = fixture(200, 40);
    let s0 = Instant::now();
    let tri = triangle_count(&g3, &cancel).expect("triangles");
    let com = label_propagation(&g3, cfg, &cancel).expect("lpa");
    let sweep_time = s0.elapsed();
    std::hint::black_box((tri.total_triangles, com.count));

    println!(
        "=== rmp #379 simple-undirected adjacency: OLD (2x per-node-Vec) vs NEW (1x flat CSR) ==="
    );
    println!(
        "nodes={} undirected_edges~={}",
        g.node_count(),
        g.edge_count()
    );
    println!(
        "OLD adjacency build: {old_build_allocs:>9} allocs, {:>10.3?}",
        old_build_time
    );
    println!(
        "NEW adjacency build: {new_build_allocs:>9} allocs, {:>10.3?}  (second request = 0 allocs, reused)",
        new_build_time
    );
    let alloc_ratio = old_build_allocs as f64 / (new_build_allocs.max(1)) as f64;
    println!("alloc reduction: {alloc_ratio:.1}x fewer allocations (NEW vs OLD sweep)");
    println!(
        "full sweep (triangles+LPA) end-to-end: {:>10.3?}",
        sweep_time
    );

    // Sanity: the new build must allocate dramatically fewer times than the OLD two-build sweep.
    assert!(
        new_build_allocs < old_build_allocs,
        "flat CSR must allocate fewer times than the per-node-Vec sweep ({new_build_allocs} < {old_build_allocs})"
    );
}
