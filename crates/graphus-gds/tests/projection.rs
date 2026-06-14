//! Tests for the CSR projection, the catalog, and property-based invariants.

use graphus_gds::algo::pagerank::{PageRankConfig, pagerank};
use graphus_gds::algo::wcc::weakly_connected_components;
use graphus_gds::{Cancel, CsrBuilder, GdsError, GraphCatalog, Orientation, VecGraphSource};

#[test]
fn csr_directed_adjacency_is_correct() {
    let g = VecGraphSource {
        nodes: vec![10, 20, 30],
        edges: vec![(10, 20, 1.0), (10, 30, 1.0), (20, 30, 1.0)],
    }
    .build(Orientation::Directed, false)
    .unwrap();

    assert_eq!(g.node_count(), 3);
    assert_eq!(g.edge_count(), 3);
    let i10 = g.internal_id(10).unwrap();
    let i20 = g.internal_id(20).unwrap();
    let i30 = g.internal_id(30).unwrap();
    let mut n10: Vec<_> = g.neighbors(i10).unwrap().to_vec();
    n10.sort_unstable();
    let mut expect = vec![i20, i30];
    expect.sort_unstable();
    assert_eq!(n10, expect);
    assert_eq!(g.out_degree(i30), Some(0));
    assert_eq!(g.external_id(i10), Some(10));
}

#[test]
fn csr_undirected_symmetrizes() {
    let g = VecGraphSource {
        nodes: vec![0, 1],
        edges: vec![(0, 1, 1.0)],
    }
    .build(Orientation::Undirected, false)
    .unwrap();
    // One input edge -> two stored directed edges.
    assert_eq!(g.edge_count(), 2);
    assert_eq!(g.out_degree(0), Some(1));
    assert_eq!(g.out_degree(1), Some(1));
}

#[test]
fn csr_undirected_self_loop_not_duplicated() {
    let g = VecGraphSource {
        nodes: vec![0],
        edges: vec![(0, 0, 1.0)],
    }
    .build(Orientation::Undirected, false)
    .unwrap();
    assert_eq!(g.edge_count(), 1, "self-loop materialized once");
}

#[test]
fn csr_weights_are_parallel_to_targets() {
    let g = VecGraphSource {
        nodes: vec![0, 1, 2],
        edges: vec![(0, 1, 2.5), (0, 2, 7.5)],
    }
    .build(Orientation::Directed, true)
    .unwrap();
    assert!(g.is_weighted());
    let neis = g.neighbors(0).unwrap();
    let ws = g.neighbor_weights(0).unwrap();
    assert_eq!(neis.len(), ws.len());
    // Pair them up and check the weight matches the target.
    for (i, &t) in neis.iter().enumerate() {
        let ext = g.external_id(t).unwrap();
        let expected = if ext == 1 { 2.5 } else { 7.5 };
        assert!((ws[i] - expected).abs() < 1e-12);
    }
}

#[test]
fn csr_accessors_are_bounds_checked() {
    let g = VecGraphSource {
        nodes: vec![0],
        edges: vec![],
    }
    .build(Orientation::Directed, false)
    .unwrap();
    assert!(g.neighbors(99).is_none());
    assert!(g.out_degree(99).is_none());
    assert!(g.external_id(99).is_none());
    assert!(g.internal_id(12345).is_none());
}

#[test]
fn csr_memory_bytes_is_nonzero_and_grows() {
    let small = VecGraphSource {
        nodes: vec![0, 1],
        edges: vec![(0, 1, 1.0)],
    }
    .build(Orientation::Directed, false)
    .unwrap();
    let big = VecGraphSource {
        nodes: (0..1000).collect(),
        edges: (0..999).map(|i| (i, i + 1, 1.0)).collect(),
    }
    .build(Orientation::Directed, false)
    .unwrap();
    assert!(small.memory_bytes() > 0);
    assert!(big.memory_bytes() > small.memory_bytes());
}

#[test]
fn builder_rejects_unknown_node_without_implicit() {
    let mut b = CsrBuilder::new(Orientation::Directed);
    b.add_node(0);
    assert!(matches!(
        b.add_edge(0, 99, 1.0),
        Err(GdsError::UnknownNode(99))
    ));
}

#[test]
fn catalog_lifecycle() {
    let mut cat = GraphCatalog::new();
    let g = VecGraphSource {
        nodes: vec![0, 1],
        edges: vec![(0, 1, 1.0)],
    }
    .build(Orientation::Directed, false)
    .unwrap();
    assert!(cat.is_empty());
    cat.project("g1", g).unwrap();
    assert!(cat.contains("g1"));
    assert_eq!(cat.len(), 1);
    assert_eq!(cat.list(), vec!["g1".to_string()]);

    // Duplicate project rejected.
    let g2 = VecGraphSource {
        nodes: vec![0],
        edges: vec![],
    }
    .build(Orientation::Directed, false)
    .unwrap();
    assert!(matches!(
        cat.project("g1", g2),
        Err(GdsError::GraphAlreadyExists(_))
    ));

    // get returns a live Arc; drop removes but the Arc stays alive.
    let handle = cat.get("g1").unwrap();
    let dropped = cat.drop("g1").unwrap();
    assert_eq!(handle.node_count(), 2);
    assert_eq!(dropped.node_count(), 2);
    assert!(matches!(cat.get("g1"), Err(GdsError::GraphNotFound(_))));
    assert!(matches!(cat.drop("g1"), Err(GdsError::GraphNotFound(_))));
}

// --------------------------------------------------------------------------------------------
// Property-based invariants (proptest is in the workspace lockfile at 1.11.0)
// --------------------------------------------------------------------------------------------

use proptest::prelude::*;

fn arb_graph() -> impl Strategy<Value = (Vec<u64>, Vec<(u64, u64)>)> {
    (1usize..30).prop_flat_map(|n| {
        let nodes: Vec<u64> = (0..n as u64).collect();
        let edge = (0..n as u64, 0..n as u64);
        let edges = proptest::collection::vec(edge, 0..(n * 3));
        (Just(nodes), edges)
    })
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(200))]

    #[test]
    fn prop_wcc_component_count_le_n((nodes, edges) in arb_graph()) {
        let src = VecGraphSource {
            nodes: nodes.clone(),
            edges: edges.iter().map(|&(a, b)| (a, b, 1.0)).collect(),
        };
        let g = src.build(Orientation::Directed, false).unwrap();
        let r = weakly_connected_components(&g, &Cancel::never()).unwrap();
        prop_assert!(r.count <= g.node_count());
        prop_assert!(r.count >= 1);
    }

    #[test]
    fn prop_pagerank_sums_to_one((nodes, edges) in arb_graph()) {
        let src = VecGraphSource {
            nodes: nodes.clone(),
            edges: edges.iter().map(|&(a, b)| (a, b, 1.0)).collect(),
        };
        let g = src.build(Orientation::Directed, false).unwrap();
        let r = pagerank(&g, PageRankConfig::default(), &Cancel::never()).unwrap();
        let sum: f64 = r.rank.iter().sum();
        prop_assert!((sum - 1.0).abs() < 1e-6, "sum was {sum}");
        // All ranks non-negative.
        for x in r.rank {
            prop_assert!(x >= -1e-12, "negative rank {x}");
        }
    }

    #[test]
    fn prop_betweenness_non_negative((nodes, edges) in arb_graph()) {
        use graphus_gds::algo::centrality::betweenness_centrality;
        let src = VecGraphSource {
            nodes,
            edges: edges.iter().map(|&(a, b)| (a, b, 1.0)).collect(),
        };
        let g = src.build(Orientation::Undirected, false).unwrap();
        let bc = betweenness_centrality(&g, &Cancel::never()).unwrap();
        for x in bc {
            prop_assert!(x >= -1e-9, "negative betweenness {x}");
        }
    }
}
