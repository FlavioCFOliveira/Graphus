//! Integration tests for `graphus-gds` algorithms against graphs with known reference values, plus
//! robustness tests over every degenerate graph shape.

use graphus_gds::algo::centrality::{
    betweenness_centrality, closeness_centrality, undirected_scale,
};
use graphus_gds::algo::community::{LabelPropagationConfig, label_propagation};
use graphus_gds::algo::degree::{Direction, degree_centrality};
use graphus_gds::algo::pagerank::{PageRankConfig, pagerank};
use graphus_gds::algo::scc::strongly_connected_components;
use graphus_gds::algo::shortest_path::{bellman_ford, dijkstra};
use graphus_gds::algo::triangles::triangle_count;
use graphus_gds::algo::wcc::weakly_connected_components;
use graphus_gds::{Cancel, CsrGraph, GdsError, Orientation, VecGraphSource};

fn directed(nodes: &[u64], edges: &[(u64, u64)]) -> CsrGraph {
    let src = VecGraphSource {
        nodes: nodes.to_vec(),
        edges: edges.iter().map(|&(a, b)| (a, b, 1.0)).collect(),
    };
    src.build(Orientation::Directed, false)
        .expect("build directed")
}

fn undirected(nodes: &[u64], edges: &[(u64, u64)]) -> CsrGraph {
    let src = VecGraphSource {
        nodes: nodes.to_vec(),
        edges: edges.iter().map(|&(a, b)| (a, b, 1.0)).collect(),
    };
    src.build(Orientation::Undirected, false)
        .expect("build undirected")
}

fn weighted(nodes: &[u64], edges: &[(u64, u64, f64)], orientation: Orientation) -> CsrGraph {
    let src = VecGraphSource {
        nodes: nodes.to_vec(),
        edges: edges.to_vec(),
    };
    src.build(orientation, true).expect("build weighted")
}

const EPS: f64 = 1e-9;

// --------------------------------------------------------------------------------------------
// PageRank
// --------------------------------------------------------------------------------------------

#[test]
fn pagerank_symmetric_ring_is_uniform() {
    // A directed cycle 0->1->2->3->0: by symmetry every node has equal rank == 1/n.
    let g = directed(&[0, 1, 2, 3], &[(0, 1), (1, 2), (2, 3), (3, 0)]);
    let r = pagerank(&g, PageRankConfig::default(), &Cancel::never()).unwrap();
    let sum: f64 = r.rank.iter().sum();
    assert!((sum - 1.0).abs() < 1e-6, "ranks must sum to 1, got {sum}");
    for &x in &r.rank {
        assert!((x - 0.25).abs() < 1e-6, "uniform expected, got {x}");
    }
    assert!(r.converged);
}

#[test]
fn pagerank_dangling_node_conserves_mass() {
    // Node 2 is dangling (no out-edges). Mass must not leak: ranks still sum to 1.
    let g = directed(&[0, 1, 2], &[(0, 1), (1, 2)]);
    let r = pagerank(&g, PageRankConfig::default(), &Cancel::never()).unwrap();
    let sum: f64 = r.rank.iter().sum();
    assert!((sum - 1.0).abs() < 1e-6, "dangling leak: sum {sum}");
}

#[test]
fn pagerank_star_centre_dominates() {
    // Undirected star: leaves all point to centre 0, so the centre has the highest rank.
    let g = undirected(&[0, 1, 2, 3], &[(0, 1), (0, 2), (0, 3)]);
    let r = pagerank(&g, PageRankConfig::default(), &Cancel::never()).unwrap();
    let centre = r.rank[0];
    for leaf in 1..4 {
        assert!(
            centre > r.rank[leaf],
            "centre {centre} must exceed leaf {}",
            r.rank[leaf]
        );
    }
    let sum: f64 = r.rank.iter().sum();
    assert!((sum - 1.0).abs() < 1e-6);
}

// `rmp` #422: PageRank on a WEIGHTED projection must honour edge weights — a node distributes rank to
// each out-neighbour in proportion to the edge weight. Before the fix `neighbor_weights` was ignored,
// so a weighted star silently produced the unweighted (equal-rank) result. After the fix the heavier
// edge carries more rank.
#[test]
fn pagerank_weighted_directed_star_respects_weights() {
    // 0 -> 1 (w=1), 0 -> 2 (w=100). 1 and 2 are dangling sinks; the heavy edge must give 2 >> 1.
    let g = weighted(
        &[0, 1, 2],
        &[(0, 1, 1.0), (0, 2, 100.0)],
        Orientation::Directed,
    );
    let r = pagerank(&g, PageRankConfig::default(), &Cancel::never()).unwrap();
    assert!(
        r.rank[2] > r.rank[1] + 1e-6,
        "weighted PageRank must rank the heavy-edge target higher: rank[2]={} rank[1]={}",
        r.rank[2],
        r.rank[1]
    );
    // Sanity: with EQUAL weights the same shape must yield equal ranks (degenerates to unweighted).
    let g_eq = weighted(
        &[0, 1, 2],
        &[(0, 1, 5.0), (0, 2, 5.0)],
        Orientation::Directed,
    );
    let r_eq = pagerank(&g_eq, PageRankConfig::default(), &Cancel::never()).unwrap();
    assert!(
        (r_eq.rank[1] - r_eq.rank[2]).abs() < 1e-9,
        "equal weights must give equal ranks: {} vs {}",
        r_eq.rank[1],
        r_eq.rank[2]
    );
    // Mass must still be conserved (dangling + teleport handling intact).
    let sum: f64 = r.rank.iter().sum();
    assert!(
        (sum - 1.0).abs() < 1e-6,
        "weighted PageRank mass leak: {sum}"
    );
}

// `rmp` #422: a weighted projection with a negative edge weight cannot form a valid transition.
#[test]
fn pagerank_weighted_rejects_negative_weight() {
    let g = weighted(&[0, 1], &[(0, 1, -1.0)], Orientation::Directed);
    assert!(matches!(
        pagerank(&g, PageRankConfig::default(), &Cancel::never()),
        Err(GdsError::InvalidArgument(_))
    ));
}

#[test]
fn pagerank_rejects_bad_damping() {
    let g = directed(&[0, 1], &[(0, 1)]);
    let cfg = PageRankConfig {
        damping: 1.0,
        ..Default::default()
    };
    assert!(matches!(
        pagerank(&g, cfg, &Cancel::never()),
        Err(GdsError::InvalidArgument(_))
    ));
}

// --------------------------------------------------------------------------------------------
// WCC
// --------------------------------------------------------------------------------------------

#[test]
fn wcc_two_components() {
    // {0,1,2} connected; {3,4} connected; direction ignored.
    let g = directed(&[0, 1, 2, 3, 4], &[(0, 1), (2, 1), (3, 4)]);
    let r = weakly_connected_components(&g, &Cancel::never()).unwrap();
    assert_eq!(r.count, 2);
    // 0,1,2 share a label; 3,4 share a different one.
    assert_eq!(r.component[0], r.component[1]);
    assert_eq!(r.component[1], r.component[2]);
    assert_eq!(r.component[3], r.component[4]);
    assert_ne!(r.component[0], r.component[3]);
}

#[test]
fn wcc_isolated_nodes_each_own_component() {
    let g = directed(&[0, 1, 2], &[]);
    let r = weakly_connected_components(&g, &Cancel::never()).unwrap();
    assert_eq!(r.count, 3);
}

// --------------------------------------------------------------------------------------------
// SCC — classic CLRS example (Introduction to Algorithms, fig. 22.9)
// --------------------------------------------------------------------------------------------

#[test]
fn scc_clrs_example() {
    // Vertices a..h = 0..7. Edges from CLRS 22.9. Expected SCCs: {a,b,e}, {c,d}, {f,g}, {h}.
    // a=0 b=1 c=2 d=3 e=4 f=5 g=6 h=7
    let edges = [
        (0, 1), // a->b
        (1, 2), // b->c
        (1, 4), // b->e
        (1, 5), // b->f
        (2, 3), // c->d
        (2, 6), // c->g
        (3, 2), // d->c
        (3, 7), // d->h
        (4, 0), // e->a
        (4, 5), // e->f
        (5, 6), // f->g
        (6, 5), // g->f
        (6, 7), // g->h
        (7, 7), // h->h (self-loop)
    ];
    let g = directed(&[0, 1, 2, 3, 4, 5, 6, 7], &edges);
    let r = strongly_connected_components(&g, &Cancel::never()).unwrap();
    assert_eq!(r.count, 4, "CLRS graph has 4 SCCs");

    let same = |a: usize, b: usize| r.component[a] == r.component[b];
    // {a=0, b=1, e=4}
    assert!(same(0, 1) && same(1, 4));
    // {c=2, d=3}
    assert!(same(2, 3));
    // {f=5, g=6}
    assert!(same(5, 6));
    // h=7 alone
    assert!(!same(7, 0) && !same(7, 2) && !same(7, 5));
    // distinct groups
    assert!(!same(0, 2) && !same(0, 5) && !same(2, 5));
}

#[test]
fn scc_self_loop_only() {
    let g = directed(&[0], &[(0, 0)]);
    let r = strongly_connected_components(&g, &Cancel::never()).unwrap();
    assert_eq!(r.count, 1);
}

// --------------------------------------------------------------------------------------------
// Degree centrality
// --------------------------------------------------------------------------------------------

#[test]
fn degree_directed_in_out_total() {
    // 0->1, 0->2, 1->2
    let g = directed(&[0, 1, 2], &[(0, 1), (0, 2), (1, 2)]);
    assert_eq!(degree_centrality(&g, Direction::Out), vec![2, 1, 0]);
    assert_eq!(degree_centrality(&g, Direction::In), vec![0, 1, 2]);
    assert_eq!(degree_centrality(&g, Direction::Total), vec![2, 2, 2]);
}

#[test]
fn degree_counts_parallel_edges_and_self_loops() {
    // Multigraph: two 0->1 edges and a self-loop on 0.
    let g = directed(&[0, 1], &[(0, 1), (0, 1), (0, 0)]);
    assert_eq!(degree_centrality(&g, Direction::Out), vec![3, 0]);
    assert_eq!(degree_centrality(&g, Direction::In), vec![1, 2]);
}

// --------------------------------------------------------------------------------------------
// Betweenness — closed-form on path and star (undirected convention: raw/2)
// --------------------------------------------------------------------------------------------

#[test]
fn betweenness_path_graph() {
    // Undirected path 0-1-2-3-4 (P5). For the undirected convention, internal node i has
    // betweenness = (i)*(n-1-i) over the line. For P5 (n=5): nodes 0..4 -> 0,3,4,3,0.
    let g = undirected(&[0, 1, 2, 3, 4], &[(0, 1), (1, 2), (2, 3), (3, 4)]);
    let raw = betweenness_centrality(&g, &Cancel::never()).unwrap();
    let bc = undirected_scale(&g, raw);
    let expected = [0.0, 3.0, 4.0, 3.0, 0.0];
    for (i, &e) in expected.iter().enumerate() {
        assert!((bc[i] - e).abs() < EPS, "node {i}: got {}, want {e}", bc[i]);
    }
}

#[test]
fn betweenness_star_graph() {
    // Undirected star with centre 0 and 4 leaves. Centre lies on every shortest path between two
    // leaves: C(4,2) = 6 pairs. Undirected convention => centre betweenness = 6, leaves = 0.
    let g = undirected(&[0, 1, 2, 3, 4], &[(0, 1), (0, 2), (0, 3), (0, 4)]);
    let raw = betweenness_centrality(&g, &Cancel::never()).unwrap();
    let bc = undirected_scale(&g, raw);
    let n: f64 = 4.0; // leaves
    let expected_centre = n * (n - 1.0) / 2.0; // (n-1)(n-2)/2 with n=5 => 6
    assert!((bc[0] - expected_centre).abs() < EPS, "centre {}", bc[0]);
    for (leaf, &score) in bc.iter().enumerate().skip(1) {
        assert!(score.abs() < EPS, "leaf {leaf} = {score}");
    }
}

// `rmp` #416: Brandes' shortest-path count σ is defined over a SIMPLE graph. A multigraph projection
// may carry parallel edges, but duplicating an edge must NOT inflate the shortest-path count — `k`
// parallel edges between adjacent nodes are still one shortest hop. Before the fix the BFS walked the
// raw multigraph adjacency, so a doubled S–A edge counted as two distinct shortest paths and skewed
// betweenness; after the fix betweenness traverses the deduplicated simple adjacency, so the doubled
// graph equals the simple one.
#[test]
fn betweenness_multigraph_equals_simple_graph() {
    // Diamond S(0)-A(1)-T(3), S(0)-B(2)-T(3): A and B are symmetric, each on one of two equal-length
    // shortest S→T paths, so their betweenness must be equal.
    let simple = undirected(&[0, 1, 2, 3], &[(0, 1), (1, 3), (0, 2), (2, 3)]);
    let simple_bc = undirected_scale(
        &simple,
        betweenness_centrality(&simple, &Cancel::never()).unwrap(),
    );

    // Same diamond, but the S–A edge is DOUBLED (a genuine multigraph). On a simple graph this is the
    // identical graph; the parallel edge must be collapsed, so betweenness must be unchanged.
    let doubled = undirected(&[0, 1, 2, 3], &[(0, 1), (0, 1), (1, 3), (0, 2), (2, 3)]);
    let doubled_bc = undirected_scale(
        &doubled,
        betweenness_centrality(&doubled, &Cancel::never()).unwrap(),
    );

    for i in 0..4 {
        assert!(
            (simple_bc[i] - doubled_bc[i]).abs() < EPS,
            "node {i}: doubled-edge betweenness {} != simple-graph {}",
            doubled_bc[i],
            simple_bc[i]
        );
    }
    // The diamond's A and B are symmetric: their betweenness must be equal (the bug made A != B).
    assert!(
        (doubled_bc[1] - doubled_bc[2]).abs() < EPS,
        "A ({}) and B ({}) must have equal betweenness on the doubled diamond",
        doubled_bc[1],
        doubled_bc[2]
    );
}

// `rmp` #416: a directed multigraph must likewise collapse parallel out-edges for σ, while keeping
// direction. Doubling a directed edge must not change directed betweenness.
#[test]
fn directed_betweenness_multigraph_equals_simple_graph() {
    // Directed diamond 0->1->3, 0->2->3.
    let simple = directed(&[0, 1, 2, 3], &[(0, 1), (1, 3), (0, 2), (2, 3)]);
    let simple_bc = betweenness_centrality(&simple, &Cancel::never()).unwrap();
    let doubled = directed(&[0, 1, 2, 3], &[(0, 1), (0, 1), (1, 3), (0, 2), (2, 3)]);
    let doubled_bc = betweenness_centrality(&doubled, &Cancel::never()).unwrap();
    for i in 0..4 {
        assert!(
            (simple_bc[i] - doubled_bc[i]).abs() < EPS,
            "directed node {i}: doubled {} != simple {}",
            doubled_bc[i],
            simple_bc[i]
        );
    }
}

// --------------------------------------------------------------------------------------------
// Closeness
// --------------------------------------------------------------------------------------------

#[test]
fn closeness_path_graph_centre_highest() {
    let g = undirected(&[0, 1, 2, 3, 4], &[(0, 1), (1, 2), (2, 3), (3, 4)]);
    let c = closeness_centrality(&g, &Cancel::never()).unwrap();
    // Centre (2) is closest to everyone; endpoints (0,4) are farthest.
    assert!(c[2] > c[1] && c[1] > c[0]);
    assert!((c[0] - c[4]).abs() < EPS);
    assert!((c[1] - c[3]).abs() < EPS);
}

// --------------------------------------------------------------------------------------------
// Triangles & clustering coefficient
// --------------------------------------------------------------------------------------------

#[test]
fn triangle_count_single_triangle() {
    // Triangle 0-1-2.
    let g = undirected(&[0, 1, 2], &[(0, 1), (1, 2), (2, 0)]);
    let r = triangle_count(&g, &Cancel::never()).unwrap();
    assert_eq!(r.total_triangles, 1);
    assert_eq!(r.triangles, vec![1, 1, 1]);
    for c in r.coefficient {
        assert!((c - 1.0).abs() < EPS);
    }
}

#[test]
fn triangle_count_square_no_triangle() {
    // 4-cycle has no triangles; clustering coefficient zero everywhere.
    let g = undirected(&[0, 1, 2, 3], &[(0, 1), (1, 2), (2, 3), (3, 0)]);
    let r = triangle_count(&g, &Cancel::never()).unwrap();
    assert_eq!(r.total_triangles, 0);
    for c in r.coefficient {
        assert!(c.abs() < EPS);
    }
}

#[test]
fn clustering_coefficient_hand_computed() {
    // Node 0 connected to 1,2,3; edge 1-2 exists but not 1-3 or 2-3.
    // deg(0)=3 => 3 possible pairs; 1 closed (1-2) => coefficient 1/3.
    let g = undirected(&[0, 1, 2, 3], &[(0, 1), (0, 2), (0, 3), (1, 2)]);
    let r = triangle_count(&g, &Cancel::never()).unwrap();
    assert!(
        (r.coefficient[0] - 1.0 / 3.0).abs() < EPS,
        "got {}",
        r.coefficient[0]
    );
    assert_eq!(r.total_triangles, 1);
}

// --------------------------------------------------------------------------------------------
// Dijkstra & Bellman-Ford
// --------------------------------------------------------------------------------------------

#[test]
fn dijkstra_known_distances() {
    // Classic small weighted DAG.
    //   0 --1--> 1 --2--> 3
    //   0 --4--> 2 --1--> 3
    // Shortest 0->3 = 0->1->3 = 3.
    let g = weighted(
        &[0, 1, 2, 3],
        &[(0, 1, 1.0), (1, 3, 2.0), (0, 2, 4.0), (2, 3, 1.0)],
        Orientation::Directed,
    );
    let sp = dijkstra(&g, 0, &Cancel::never()).unwrap();
    assert_eq!(sp.dist[0], Some(0.0));
    assert_eq!(sp.dist[1], Some(1.0));
    assert_eq!(sp.dist[2], Some(4.0));
    assert_eq!(sp.dist[3], Some(3.0));
}

#[test]
fn dijkstra_rejects_negative_weight() {
    let g = weighted(&[0, 1], &[(0, 1, -1.0)], Orientation::Directed);
    assert!(matches!(
        dijkstra(&g, 0, &Cancel::never()),
        Err(GdsError::InvalidArgument(_))
    ));
}

#[test]
fn dijkstra_unreachable_is_none() {
    let g = weighted(&[0, 1, 2], &[(0, 1, 1.0)], Orientation::Directed);
    let sp = dijkstra(&g, 0, &Cancel::never()).unwrap();
    assert_eq!(sp.dist[2], None);
}

#[test]
fn bellman_ford_handles_negative_edges() {
    // 0->1 (4), 0->2 (5), 2->1 (-3). Shortest 0->1 = 5 + (-3) = 2.
    let g = weighted(
        &[0, 1, 2],
        &[(0, 1, 4.0), (0, 2, 5.0), (2, 1, -3.0)],
        Orientation::Directed,
    );
    let sp = bellman_ford(&g, 0, &Cancel::never()).unwrap();
    assert_eq!(sp.dist[1], Some(2.0));
    assert_eq!(sp.dist[2], Some(5.0));
}

#[test]
fn bellman_ford_detects_negative_cycle() {
    // 0->1 (1), 1->2 (-1), 2->0 (-1): reachable negative cycle.
    let g = weighted(
        &[0, 1, 2],
        &[(0, 1, 1.0), (1, 2, -1.0), (2, 0, -1.0)],
        Orientation::Directed,
    );
    assert!(matches!(
        bellman_ford(&g, 0, &Cancel::never()),
        Err(GdsError::NegativeCycle)
    ));
}

// --------------------------------------------------------------------------------------------
// Community detection
// --------------------------------------------------------------------------------------------

#[test]
fn label_propagation_two_cliques() {
    // Two triangles connected by a single bridge edge -> should find ~2 communities.
    let g = undirected(
        &[0, 1, 2, 3, 4, 5],
        &[
            (0, 1),
            (1, 2),
            (2, 0), // clique A
            (3, 4),
            (4, 5),
            (5, 3), // clique B
            (2, 3), // bridge
        ],
    );
    let r = label_propagation(&g, LabelPropagationConfig::default(), &Cancel::never()).unwrap();
    // Each clique should collapse to a single internal label.
    assert_eq!(r.label[0], r.label[1]);
    assert_eq!(r.label[1], r.label[2]);
    assert_eq!(r.label[3], r.label[4]);
    assert_eq!(r.label[4], r.label[5]);
    assert!(r.converged);
}

// --------------------------------------------------------------------------------------------
// Robustness: degenerate graphs must never panic and must return sane output
// --------------------------------------------------------------------------------------------

#[test]
fn empty_graph_every_algorithm_is_panic_free() {
    let g = directed(&[], &[]);
    let c = Cancel::never();
    assert!(
        pagerank(&g, PageRankConfig::default(), &c)
            .unwrap()
            .rank
            .is_empty()
    );
    assert_eq!(weakly_connected_components(&g, &c).unwrap().count, 0);
    assert_eq!(strongly_connected_components(&g, &c).unwrap().count, 0);
    assert!(degree_centrality(&g, Direction::Total).is_empty());
    assert!(closeness_centrality(&g, &c).unwrap().is_empty());
    assert!(betweenness_centrality(&g, &c).unwrap().is_empty());
    assert_eq!(triangle_count(&g, &c).unwrap().total_triangles, 0);
    assert_eq!(
        label_propagation(&g, LabelPropagationConfig::default(), &c)
            .unwrap()
            .count,
        0
    );
}

#[test]
fn single_isolated_node_is_sane() {
    let g = directed(&[42], &[]);
    let c = Cancel::never();
    let pr = pagerank(&g, PageRankConfig::default(), &c).unwrap();
    assert!((pr.rank[0] - 1.0).abs() < 1e-9);
    assert_eq!(weakly_connected_components(&g, &c).unwrap().count, 1);
    assert_eq!(strongly_connected_components(&g, &c).unwrap().count, 1);
    let sp = dijkstra(&g, 0, &c).unwrap();
    assert_eq!(sp.dist[0], Some(0.0));
    assert_eq!(triangle_count(&g, &c).unwrap().total_triangles, 0);
}

#[test]
fn self_loop_and_parallel_edges_are_panic_free() {
    let g = undirected(&[0, 1], &[(0, 0), (0, 1), (0, 1)]);
    let c = Cancel::never();
    // No panic; triangle count remains 0 (simple-graph folding drops the multi-edges/self-loop).
    assert_eq!(triangle_count(&g, &c).unwrap().total_triangles, 0);
    assert!(pagerank(&g, PageRankConfig::default(), &c).is_ok());
    assert!(betweenness_centrality(&g, &c).is_ok());
    assert_eq!(weakly_connected_components(&g, &c).unwrap().count, 1);
}

#[test]
fn disconnected_graph_distances_are_none() {
    let g = weighted(
        &[0, 1, 2, 3],
        &[(0, 1, 2.0), (2, 3, 5.0)],
        Orientation::Directed,
    );
    let c = Cancel::never();
    let sp = dijkstra(&g, 0, &c).unwrap();
    assert_eq!(sp.dist[1], Some(2.0));
    assert_eq!(sp.dist[2], None);
    assert_eq!(sp.dist[3], None);
    let bf = bellman_ford(&g, 0, &c).unwrap();
    assert_eq!(bf.dist[2], None);
}

#[test]
fn cancellation_is_honoured() {
    use std::sync::atomic::{AtomicBool, Ordering};
    let g = directed(&(0..1000).collect::<Vec<_>>(), &[]);
    let flag = AtomicBool::new(true);
    flag.store(true, Ordering::Relaxed);
    let c = Cancel::flag(&flag);
    // With the flag pre-set, an iterative algorithm must bail out with Cancelled.
    assert!(matches!(
        pagerank(&g, PageRankConfig::default(), &c),
        Err(GdsError::Cancelled)
    ));
}
