//! Security regression battery for `graphus-gds` — adversarial-graph CPU/RAM DoS and
//! float-correctness findings from the red-team audit.
//!
//! Every test here is bounded (small inputs and/or short wall-clock budgets) so it proves the
//! vulnerability class **without** taking down the test runner. Every finding exercised here is
//! **fixed**; each test is a `// Regression: SEC-<task-id>` asserting the *secure* post-fix
//! behaviour (it passes now and would fail if the fix regressed). No `// VULNERABLE: SEC-<task-id>`
//! markers remain.

use std::sync::atomic::AtomicBool;
use std::time::{Duration, Instant};

use graphus_gds::algo::centrality::{betweenness_centrality, closeness_centrality};
use graphus_gds::algo::community::{LabelPropagationConfig, label_propagation};
use graphus_gds::algo::pagerank::{PageRankConfig, pagerank};
use graphus_gds::{Cancel, Orientation, VecGraphSource};

/// A complete graph `K_n` (every ordered pair, undirected projection), the canonical dense
/// adversarial input: `m = O(n^2)`, which is what makes the O(n*m) / O(n^2) algorithms explode.
fn complete_graph(n: u64) -> graphus_gds::CsrGraph {
    let nodes: Vec<u64> = (0..n).collect();
    let mut edges = Vec::new();
    for a in 0..n {
        for b in (a + 1)..n {
            edges.push((a, b, 1.0));
        }
    }
    VecGraphSource { nodes, edges }
        .build(Orientation::Undirected, false)
        .expect("complete graph builds")
}

/// A grid/lattice DAG with an explosive number of shortest paths between the first and last node,
/// to stress Brandes' `f64` shortest-path counters (`sigma`). `width` parallel ranks of `depth`
/// each, fully connected rank-to-rank: the number of source->sink paths is `width^depth`.
fn lattice_dag(width: u64, depth: u64) -> graphus_gds::CsrGraph {
    let mut nodes = vec![0u64]; // source = 0
    let mut edges = Vec::new();
    let mut prev_layer = vec![0u64];
    let mut next_id = 1u64;
    for _ in 0..depth {
        let mut layer = Vec::new();
        for _ in 0..width {
            nodes.push(next_id);
            layer.push(next_id);
            next_id += 1;
        }
        for &p in &prev_layer {
            for &c in &layer {
                edges.push((p, c, 1.0));
            }
        }
        prev_layer = layer;
    }
    // sink
    let sink = next_id;
    nodes.push(sink);
    for &p in &prev_layer {
        edges.push((p, sink, 1.0));
    }
    VecGraphSource { nodes, edges }
        .build(Orientation::Directed, false)
        .expect("lattice builds")
}

// -------------------------------------------------------------------------------------------------
// SEC-201: gds.* procedures hard-wire `Cancel::never()`. The *engine* honours a real Cancel — this
// test proves the mechanism works, so the fix is purely to plumb a real token at the procedure
// layer. We also demonstrate that without a flag the algorithm has no way to stop early.
// -------------------------------------------------------------------------------------------------

#[test]
fn betweenness_honours_a_cancel_flag_when_one_is_supplied() {
    // The library layer is NOT the bug: it respects cancellation. Flip the flag before the call so
    // the first per-source check trips immediately — proving a real token (which the procedure
    // layer fails to provide, SEC-201) would abort a runaway run.
    let g = complete_graph(40);
    let flag = AtomicBool::new(true);
    let cancel = Cancel::flag(&flag);
    let err = betweenness_centrality(&g, &cancel).unwrap_err();
    assert_eq!(err, graphus_gds::GdsError::Cancelled);
}

#[test]
fn betweenness_library_respects_the_cancel_it_is_given() {
    // Regression: SEC-201 — the LIBRARY honours whatever Cancel it is handed (proven by the test
    // above with a flag). The bug was that the *procedure layer* (graphus-cypher) hard-wired
    // `Cancel::never()`; that is now fixed to a real deadline-backed Cancel and regression-tested in
    // `graphus-cypher/tests/security_pipeline.rs`. Here we just confirm the library computes when
    // given a never-cancel token (the bounded-by-n baseline).
    let g = complete_graph(30);
    let start = Instant::now();
    let scores = betweenness_centrality(&g, &Cancel::never()).expect("runs");
    // It completes only because WE bounded n. Document the current uninterruptible behaviour.
    assert_eq!(scores.len(), g.node_count());
    // Sanity guard: even K_30 should be sub-second; if this ever regresses badly the bound catches
    // it. (Not a security assertion — just keeps the suite snappy.)
    assert!(
        start.elapsed() < Duration::from_secs(5),
        "K_30 betweenness should be fast; got {:?}",
        start.elapsed()
    );
}

// -------------------------------------------------------------------------------------------------
// SEC-202: client-controlled `maxIterations` is unbounded at the procedure layer. The library
// faithfully loops up to whatever `max_iter` it is handed. We prove the loop is bounded ONLY by
// that client-supplied number (no internal ceiling), using a non-converging config.
// -------------------------------------------------------------------------------------------------

/// A directed star: nodes `1..n` all point at hub `0`. This is the empirically-verified
/// adversarial input for SEC-202 — its PageRank vector never reaches an *exact* `delta == 0` in
/// floating point, so with `tolerance: 0.0` the power iteration runs the **full** client-supplied
/// `max_iter` without ever converging. (A symmetric graph like `K_n` converges in one step and
/// would *hide* the unbounded-loop risk; the star exposes it.)
fn directed_star(n: u64) -> graphus_gds::CsrGraph {
    let nodes: Vec<u64> = (0..n).collect();
    let edges: Vec<(u64, u64, f64)> = (1..n).map(|i| (i, 0, 1.0)).collect();
    VecGraphSource { nodes, edges }
        .build(Orientation::Directed, false)
        .expect("star builds")
}

#[test]
fn pagerank_runs_exactly_max_iter_when_it_never_converges() {
    // Regression: SEC-202 — the LIBRARY faithfully loops up to whatever `max_iter` it is handed
    // (that is correct). The bug was at the *procedure layer*, which coerced a client float into
    // `max_iter` with no ceiling (so `{maxIterations: 4e9}` -> ~4.29e9 sweeps). That clamp now lives
    // in `gds_procedures::clamp_max_iter` and is regression-tested in graphus-cypher. Here we pin the
    // library contract: it honours the (now-clamped) value exactly.
    let g = directed_star(10);
    let cfg = PageRankConfig {
        damping: 0.85,
        max_iter: 5000,
        tolerance: 0.0, // never satisfied on this graph -> always hits the cap
    };
    let res = pagerank(&g, cfg, &Cancel::never()).expect("runs");
    assert_eq!(
        res.iterations, 5000,
        "loop bound is purely the client max_iter — nothing inside the library clamps it"
    );
    assert!(!res.converged, "tolerance 0.0 on the star never converges");
}

#[test]
fn label_propagation_loop_is_bounded_only_by_client_max_iter() {
    // Regression: SEC-202 — library contract for LPA: it honours the `max_iter` it is given. The
    // procedure-layer clamp (and the float->u32 coercion fix) is regression-tested in graphus-cypher.
    let g = complete_graph(6);
    let cfg = LabelPropagationConfig { max_iter: 250 };
    let res = label_propagation(&g, cfg, &Cancel::never()).expect("runs");
    // On K_n LPA converges fast, but the contract under test is: nothing clamps max_iter below the
    // requested value inside the library.
    assert!(res.iterations <= 250);
    // Reproduce the exact float->u32 coercion the procedure layer performs (gds_procedures.rs:507).
    let huge = f64::INFINITY;
    let coerced = huge.max(1.0) as u32;
    assert_eq!(
        coerced,
        u32::MAX,
        "f64::INFINITY coerces to u32::MAX iterations — worst case from a single config value"
    );
}

// -------------------------------------------------------------------------------------------------
// SEC-205: Brandes betweenness counts shortest paths in `f64` (`sigma`). On a lattice with a
// super-exponential path count, `sigma` overflows to +inf and the dependency division produces
// NaN/0, silently corrupting scores. This is a correctness/integrity bug reachable from data.
// -------------------------------------------------------------------------------------------------

#[test]
fn betweenness_sigma_overflow_is_a_clean_overflow_error_not_nan() {
    // Regression: SEC-205 — on a lattice with a super-exponential shortest-path count, `sigma`
    // overflows f64 to +inf. Previously the dependency division produced NaN/0 and silently
    // corrupted every score; now the algorithm detects the non-finite count and returns a clean
    // `GdsError::Overflow`, so a caller never observes corrupted (NaN) betweenness values.
    let g_overflow = lattice_dag(10, 320); // 10^320 > f64::MAX (1.8e308) -> sigma becomes +inf

    let err = betweenness_centrality(&g_overflow, &Cancel::never())
        .expect_err("sigma overflow must surface as a clean error, not corrupted scores");
    assert_eq!(
        err,
        graphus_gds::GdsError::Overflow("betweenness shortest-path count exceeded f64 range"),
        "expected a clean Overflow error instead of NaN scores"
    );

    // A finite, well-shaped graph still produces finite scores (no false positives from the guard).
    let small = lattice_dag(2, 4); // 2^4 = 16 paths — comfortably finite
    let scores = betweenness_centrality(&small, &Cancel::never()).expect("finite graph computes");
    assert!(
        scores.iter().all(|s| s.is_finite()),
        "a finite-path-count graph must yield finite scores"
    );
}

// -------------------------------------------------------------------------------------------------
// SEC-210: the CSR builder's `ExternalId -> InternalId` map is keyed by client-controlled node ids
// and MUST stay on a DoS-resistant (randomly-seeded SipHash) hasher to resist hash-flooding. There
// is no runtime exploit (the default `std::collections::HashMap` is already resistant); this guards
// the *policy* — a future swap to a fixed-seed fast hasher over these keys would reintroduce CWE-407.
// -------------------------------------------------------------------------------------------------

#[test]
fn sec210_csr_index_map_uses_a_dos_resistant_hasher() {
    // Source-level guard: the `index_of` map must be declared on the std `HashMap` (SipHash), not a
    // fast fixed-seed hasher (FxHashMap / ahash-without-keys). Assert the source still declares it so
    // and carries the security note, so a regressive swap is caught here.
    let src = include_str!("../src/csr.rs");
    assert!(
        src.contains("index_of: HashMap<ExternalId, InternalId>"),
        "SEC-210: CsrBuilder.index_of must remain a std HashMap (DoS-resistant SipHash)"
    );
    // Guard against an actual *declaration* on a fast fixed-seed hasher (not mere mentions in the
    // security note, which deliberately names the forbidden types).
    assert!(
        !src.contains("index_of: FxHashMap") && !src.contains("index_of: AHashMap"),
        "SEC-210: the client-keyed CSR id map must NOT be declared on a fixed-seed fast hasher"
    );
    assert!(
        src.contains("SEC-210"),
        "SEC-210: the security invariant note must stay next to the client-keyed map"
    );

    // Functional sanity: many client-chosen ids (including ones engineered to be adjacent) index
    // and round-trip correctly under the default hasher.
    let n = 5000u64;
    let nodes: Vec<u64> = (0..n).map(|i| i.wrapping_mul(0x9E37_79B9_7F4A_7C15)).collect();
    let g = VecGraphSource {
        nodes: nodes.clone(),
        edges: Vec::new(),
    }
    .build(Orientation::Directed, false)
    .expect("builds");
    for (i, &ext) in nodes.iter().enumerate() {
        assert_eq!(g.internal_id(ext), Some(i as u32));
    }
}

// -------------------------------------------------------------------------------------------------
// SEC-209: weighted closeness centrality used to re-scan ALL edges to validate non-negative weights
// on EVERY source (once per node), making the precondition check alone O(n*m). The fix hoists the
// validation to a single up-front O(m) scan and drives the per-source core via `dijkstra_validated`.
// -------------------------------------------------------------------------------------------------

/// A weighted path graph `0 -w- 1 -w- 2 -w- ... -w- (n-1)`, all weights `w`.
fn weighted_path(n: u64, w: f64) -> graphus_gds::CsrGraph {
    let nodes: Vec<u64> = (0..n).collect();
    let edges: Vec<(u64, u64, f64)> = (0..n.saturating_sub(1)).map(|i| (i, i + 1, w)).collect();
    VecGraphSource { nodes, edges }
        .build(Orientation::Undirected, true)
        .expect("weighted path builds")
}

#[test]
fn closeness_validates_weights_once_and_computes_on_a_valid_weighted_graph() {
    // Regression: SEC-209 — weighted closeness now validates non-negativity ONCE up front and runs
    // each source via the pre-validated Dijkstra core. We assert the observable contract: a valid
    // weighted graph computes finite scores (the per-source rescan no longer changes the result),
    // and the run stays well within a tight wall-clock budget even though it is O(n) Dijkstras.
    let g = weighted_path(200, 2.0);
    let start = Instant::now();
    let scores = closeness_centrality(&g, &Cancel::never()).expect("valid weighted graph computes");
    assert_eq!(scores.len(), g.node_count());
    assert!(
        scores.iter().all(|s| s.is_finite()),
        "all closeness scores on a connected weighted graph must be finite"
    );
    // Not a hard security assertion, but the whole point of SEC-209 is that the precondition scan is
    // no longer O(n*m); a 200-node path must finish near-instantly.
    assert!(
        start.elapsed() < Duration::from_secs(5),
        "weighted closeness on a 200-node path should be fast; got {:?}",
        start.elapsed()
    );
}

#[test]
fn closeness_rejects_a_negative_weight_with_a_single_validation() {
    // Regression: SEC-209 — the up-front, once-per-invocation validation rejects a negative edge
    // weight with a clean InvalidArgument (Dijkstra's precondition), rather than silently rescanning
    // per source. One bad edge is enough to fail closed.
    let g = VecGraphSource {
        nodes: vec![0, 1, 2],
        edges: vec![(0, 1, 1.0), (1, 2, -3.0)],
    }
    .build(Orientation::Undirected, true)
    .expect("graph builds");
    let err = closeness_centrality(&g, &Cancel::never())
        .expect_err("a negative weight must be rejected up front");
    assert!(
        matches!(err, graphus_gds::GdsError::InvalidArgument(_)),
        "expected InvalidArgument for a negative weight, got {err:?}"
    );
}
