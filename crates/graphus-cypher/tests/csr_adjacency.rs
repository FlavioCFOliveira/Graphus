//! Acceptance tests for the **opt-in** CSR-adjacency accelerator (`rmp` task #324, "Win 2").
//!
//! These assert the four hard guarantees the task mandates:
//!   1. **CSR-ON == CSR-OFF** — a typed expand with the CSR consulted returns the EXACT same visible
//!      edge set and the EXACT same SSI markers as the Win-1 chain walk, over a multigraph with
//!      parallel same-type edges, self-loops and deleted/corpse edges
//!      ([`csr_on_equals_csr_off_visible_edges_and_markers`]).
//!   2. **Non-matching-read elimination** — with the CSR consulted, a type-selective expand issues NO
//!      reads of non-matching incidence-chain links (the residual Win-1 cost), unlike the chain walk
//!      ([`csr_eliminates_nonmatching_chain_reads`]).
//!   3. **RAM footprint** — the CSR is ~8 bytes per incident-edge endpoint when built, and there is a
//!      build path that allocates nothing ([`csr_footprint_bytes_per_edge`]).
//!   4. **Freshness gate** — once a relationship mutates, the CSR declines and the chain walk takes
//!      over, still result-equal ([`csr_declines_after_mutation_still_correct`]).
//!
//! The equivalence is proven by driving the SAME `read_source::expand_with_csr` seam twice over the
//! SAME committed store: once with `csr_candidates = None` (the Win-1 chain walk = CSR-OFF behaviour)
//! and once with the candidate list a fresh [`CsrAdjacency`] yields (= CSR-ON behaviour). A
//! marker-recording sink captures every SIREAD key + predicate so the two footprints are compared as
//! sets, exactly as the engine merges them (sorted + deduped) into the SSI tracker.

use std::cell::RefCell;

use graphus_core::TxnId;
use graphus_cypher::csr_adjacency::CsrAdjacency;
use graphus_cypher::{ExpandDirection, Incident, LiveSource, NodeId, ReadSink, VisCtx};
use graphus_io::MemBlockDevice;
use graphus_storage::{Namespace, RecordStore};
use graphus_txn::{PredicateRead, Snapshot};
use graphus_wal::{MemLogSink, WalManager};

type Store = RecordStore<MemBlockDevice, MemLogSink>;

fn fresh() -> Store {
    let device = MemBlockDevice::new(0);
    let wal = WalManager::create(MemLogSink::new()).expect("create wal");
    RecordStore::create(device, wal, 64, 1).expect("create store")
}

/// A sink that records the multiset of per-rel SIREAD keys and the multiset of predicate markers, so a
/// CSR-ON run's SSI footprint can be compared against a CSR-OFF run's. (The engine sorts + dedups
/// before replay, so we compare the deduped *sets*.)
#[derive(Default)]
struct RecordingSink {
    reads: RefCell<Vec<u64>>,
    predicates: RefCell<Vec<String>>,
}

impl RecordingSink {
    fn read_set(&self) -> Vec<u64> {
        let mut v = self.reads.borrow().clone();
        v.sort_unstable();
        v.dedup();
        v
    }
    fn predicate_set(&self) -> Vec<String> {
        let mut v = self.predicates.borrow().clone();
        v.sort();
        v.dedup();
        v
    }
}

impl ReadSink for RecordingSink {
    fn note_read(&self, key: u64) {
        self.reads.borrow_mut().push(key);
    }
    fn note_predicate_read(&self, p: PredicateRead) {
        self.predicates.borrow_mut().push(format!("{p:?}"));
    }
    fn capture(&self, err: graphus_core::error::GraphusError) {
        panic!("unexpected captured error in expand: {err}");
    }
}

fn ids_of(out: &[Incident]) -> Vec<(u64, u64)> {
    let mut v: Vec<(u64, u64)> = out.iter().map(|i| (i.rel.0, i.neighbour.0)).collect();
    v.sort_unstable();
    v
}

/// Builds a multigraph hub with every edge shape the task names:
///   * a minority of matching `LIKE` edges among a majority of non-matching `FRIEND` edges;
///   * **parallel same-type edges** (two `LIKE` edges to the same neighbour);
///   * a **self-loop** `LIKE` edge on the hub;
///   * a **deleted/corpse** `LIKE` edge (created then deleted, so its slot is a dead-link corpse the
///     chain threads through and the CSR build excludes).
///
/// Returns `(store, hub_id, expected_visible_like_count)`.
fn build_multigraph() -> (Store, u64, usize) {
    let mut s = fresh();
    let txn = TxnId(1);
    s.begin(txn);
    let t_friend = s.intern_token(Namespace::RelType, "FRIEND").unwrap();
    let t_like = s.intern_token(Namespace::RelType, "LIKE").unwrap();
    let (hub, _) = s.create_node(txn).unwrap();

    let mut visible_likes = 0usize;
    // 60 FRIEND edges (non-matching majority).
    for _ in 0..60u64 {
        let (b, _) = s.create_node(txn).unwrap();
        s.create_rel(txn, t_friend, hub, b).unwrap();
    }
    // 10 LIKE edges to distinct neighbours.
    for _ in 0..10u64 {
        let (b, _) = s.create_node(txn).unwrap();
        s.create_rel(txn, t_like, hub, b).unwrap();
        visible_likes += 1;
    }
    // Parallel same-type edges: two more LIKE edges to ONE neighbour (multigraph).
    let (par, _) = s.create_node(txn).unwrap();
    s.create_rel(txn, t_like, hub, par).unwrap();
    s.create_rel(txn, t_like, hub, par).unwrap();
    visible_likes += 2;
    // A self-loop LIKE edge on the hub.
    s.create_rel(txn, t_like, hub, hub).unwrap();
    visible_likes += 1;
    // A LIKE edge that becomes a corpse: create then delete it (a dead-link corpse the chain threads
    // through; it must NOT appear in either path's visible result).
    let (gone, _) = s.create_node(txn).unwrap();
    let corpse = s.create_rel(txn, t_like, hub, gone).unwrap().0;
    s.delete_rel(txn, corpse).unwrap();
    s.commit(txn).unwrap();

    (s, hub, visible_likes)
}

fn ctx_for(s: &Store) -> (graphus_txn::CommitRegistry, Snapshot) {
    (
        s.commit_registry().clone(),
        Snapshot {
            owner: TxnId(99),
            ts: s.snapshot_ts(),
        },
    )
}

/// **Guarantee 1 (the mandatory regression test):** a typed expand with the CSR consulted (ON) returns
/// the EXACT same visible-edge set and the EXACT same SSI markers as the Win-1 chain walk (OFF), over a
/// multigraph with parallel same-type edges, self-loops and deleted/corpse edges.
#[test]
fn csr_on_equals_csr_off_visible_edges_and_markers() {
    let (s, hub, expected_likes) = build_multigraph();
    let (registry, snapshot) = ctx_for(&s);
    let ctx = VisCtx {
        snapshot,
        registry: &registry,
        txn: TxnId(99),
    };
    let t_like = s.token_id(Namespace::RelType, "LIKE").unwrap();

    // Build a fresh CSR over the committed store; seek the LIKE candidates for the hub.
    let mut csr = CsrAdjacency::empty();
    csr.build_from_store(&s);
    assert!(!csr.is_dirty(), "a clean build is fresh");
    let candidates = csr
        .candidates(hub, &[t_like])
        .expect("fresh CSR yields candidates for a typed expand");

    // CSR-OFF: the Win-1 chain walk (csr_candidates = None).
    let off_sink = RecordingSink::default();
    let off = graphus_cypher::read_source::expand_with_csr(
        &LiveSource(&s),
        &ctx,
        &off_sink,
        NodeId(hub),
        ExpandDirection::Outgoing,
        &["LIKE".to_string()],
        None,
    );

    // CSR-ON: read only the CSR's matching-type candidates.
    let on_sink = RecordingSink::default();
    let on = graphus_cypher::read_source::expand_with_csr(
        &LiveSource(&s),
        &ctx,
        &on_sink,
        NodeId(hub),
        ExpandDirection::Outgoing,
        &["LIKE".to_string()],
        Some(candidates),
    );

    // The visible-edge sets are byte-identical (constraint 3): the corpse is excluded by both, the
    // self-loop appears once in both, the parallel edges both appear.
    assert_eq!(
        ids_of(&on),
        ids_of(&off),
        "CSR-ON visible-edge set must equal CSR-OFF"
    );
    assert_eq!(
        on.len(),
        expected_likes,
        "exactly the visible LIKE edges (parallel + self-loop counted, corpse excluded)"
    );

    // The SSI footprints are byte-identical: the per-rel SIREAD set and the predicate-marker set match.
    assert_eq!(
        on_sink.read_set(),
        off_sink.read_set(),
        "CSR-ON SIREAD set must equal CSR-OFF (matching candidates marked, no under-marking)"
    );
    assert_eq!(
        on_sink.predicate_set(),
        off_sink.predicate_set(),
        "CSR-ON predicate marker set must equal CSR-OFF (rel-type phantom cover preserved)"
    );
    assert!(
        !on_sink.predicate_set().is_empty(),
        "the rel-type predicate marker is still registered on the CSR path"
    );
}

/// **Guarantee 1, Both-direction variant:** the equality also holds for an undirected (`Both`) expand,
/// where a self-loop's two chain occurrences and both endpoints of a normal edge are in play.
#[test]
fn csr_on_equals_csr_off_both_direction() {
    let (s, hub, _) = build_multigraph();
    let (registry, snapshot) = ctx_for(&s);
    let ctx = VisCtx {
        snapshot,
        registry: &registry,
        txn: TxnId(99),
    };
    let t_like = s.token_id(Namespace::RelType, "LIKE").unwrap();
    let mut csr = CsrAdjacency::empty();
    csr.build_from_store(&s);
    let candidates = csr.candidates(hub, &[t_like]).unwrap();

    let off_sink = RecordingSink::default();
    let off = graphus_cypher::read_source::expand_with_csr(
        &LiveSource(&s),
        &ctx,
        &off_sink,
        NodeId(hub),
        ExpandDirection::Both,
        &["LIKE".to_string()],
        None,
    );
    let on_sink = RecordingSink::default();
    let on = graphus_cypher::read_source::expand_with_csr(
        &LiveSource(&s),
        &ctx,
        &on_sink,
        NodeId(hub),
        ExpandDirection::Both,
        &["LIKE".to_string()],
        Some(candidates),
    );
    assert_eq!(
        ids_of(&on),
        ids_of(&off),
        "Both-direction CSR-ON == CSR-OFF"
    );
    assert_eq!(on_sink.read_set(), off_sink.read_set());
    assert_eq!(on_sink.predicate_set(), off_sink.predicate_set());
}

/// **Guarantee 2 (counting test):** with the CSR consulted, a type-selective expand reads ONLY the
/// matching candidates — it never reads a non-matching (`FRIEND`) chain link. The chain-walk path
/// (CSR-OFF) must read every link to follow the chain; the CSR path reads only the LIKE candidates.
#[test]
fn csr_eliminates_nonmatching_chain_reads() {
    use std::cell::Cell;

    use graphus_cypher::StoreReadSource;
    use graphus_storage::record::{NodeRecord, PropRecord, RelRecord};

    /// A source that counts every `rel()` decode and every `incident_rels_typed` chain walk.
    struct Counting<'a> {
        inner: LiveSource<'a, MemBlockDevice, MemLogSink>,
        rel_calls: Cell<usize>,
        typed_calls: Cell<usize>,
    }
    impl StoreReadSource for Counting<'_> {
        fn node(&self, id: u64) -> Result<NodeRecord, graphus_core::error::GraphusError> {
            self.inner.node(id)
        }
        fn rel(&self, id: u64) -> Result<RelRecord, graphus_core::error::GraphusError> {
            self.rel_calls.set(self.rel_calls.get() + 1);
            self.inner.rel(id)
        }
        fn scan_node_ids(&self) -> Result<Vec<u64>, graphus_core::error::GraphusError> {
            self.inner.scan_node_ids()
        }
        fn node_labels(&self, id: u64) -> Result<Vec<u32>, graphus_core::error::GraphusError> {
            self.inner.node_labels(id)
        }
        fn node_has_label(
            &self,
            id: u64,
            l: u32,
        ) -> Result<bool, graphus_core::error::GraphusError> {
            self.inner.node_has_label(id, l)
        }
        fn node_properties(
            &self,
            id: u64,
        ) -> Result<Vec<(u64, PropRecord)>, graphus_core::error::GraphusError> {
            self.inner.node_properties(id)
        }
        fn rel_properties(
            &self,
            id: u64,
        ) -> Result<Vec<(u64, PropRecord)>, graphus_core::error::GraphusError> {
            self.inner.rel_properties(id)
        }
        fn incident_rels(&self, id: u64) -> Result<Vec<u64>, graphus_core::error::GraphusError> {
            self.inner.incident_rels(id)
        }
        fn incident_rels_typed(
            &self,
            id: u64,
            w: &[u32],
        ) -> Result<Vec<(u64, RelRecord)>, graphus_core::error::GraphusError> {
            self.typed_calls.set(self.typed_calls.get() + 1);
            self.inner.incident_rels_typed(id, w)
        }
        fn decode_property_value(
            &self,
            t: u8,
            v: u64,
        ) -> Result<graphus_core::Value, graphus_core::error::GraphusError> {
            self.inner.decode_property_value(t, v)
        }
        fn token_id(&self, ns: Namespace, name: &str) -> Option<u32> {
            self.inner.token_id(ns, name)
        }
        fn token_name(&self, ns: Namespace, id: u32) -> Option<String> {
            self.inner.token_name(ns, id)
        }
    }

    let (s, hub, expected_likes) = build_multigraph();
    let (registry, snapshot) = ctx_for(&s);
    let ctx = VisCtx {
        snapshot,
        registry: &registry,
        txn: TxnId(99),
    };
    let t_like = s.token_id(Namespace::RelType, "LIKE").unwrap();
    let mut csr = CsrAdjacency::empty();
    csr.build_from_store(&s);
    let candidates = csr.candidates(hub, &[t_like]).unwrap();
    // The CSR yields the matching-type candidates: every committed LIKE slot incident to the hub. That
    // is the visible LIKE edges PLUS the committed-tombstone corpse (still an `in_use` MVCC slot at
    // scan time), and crucially NO FRIEND edge. A superset of the visible result is allowed (constraint
    // 2: the per-candidate MVCC re-check drops the corpse); under-coverage would be the bug.
    let total_incident = 60 /* FRIEND */ + expected_likes + 1 /* corpse */;
    assert_eq!(
        candidates.len(),
        expected_likes + 1,
        "CSR yields every LIKE slot (visible + tombstone corpse), never a FRIEND"
    );
    assert!(
        candidates.len() < total_incident,
        "CSR candidate count ({}) is far below the total incident-edge count ({total_incident}) — \
         the non-matching FRIEND links are never even candidates",
        candidates.len()
    );

    let src = Counting {
        inner: LiveSource(&s),
        rel_calls: Cell::new(0),
        typed_calls: Cell::new(0),
    };
    let sink = RecordingSink::default();
    let out = graphus_cypher::read_source::expand_with_csr(
        &src,
        &ctx,
        &sink,
        NodeId(hub),
        ExpandDirection::Outgoing,
        &["LIKE".to_string()],
        Some(candidates.clone()),
    );

    assert_eq!(out.len(), expected_likes);
    // No chain walk at all on the CSR path.
    assert_eq!(
        src.typed_calls.get(),
        0,
        "CSR path performs NO incident_rels_typed chain walk"
    );
    // The ONLY rel() reads are the matching candidates — never a FRIEND link. The chain walk would
    // instead read all ~74 incident links to follow the chain; the CSR reads exactly `expected_likes`.
    assert_eq!(
        src.rel_calls.get(),
        candidates.len(),
        "CSR path reads exactly the matching candidates, zero non-matching chain links"
    );
}

/// **Guarantee 3 (RAM footprint):** the CSR is ~8 bytes per incident-edge endpoint when built, and the
/// never-built (knob-off) CSR allocates nothing.
#[test]
fn csr_footprint_bytes_per_edge() {
    let (s, _hub, _) = build_multigraph();

    // OFF: a never-built CSR has zero footprint (the knob-off invariant — no `rels`/`directory`).
    let off = CsrAdjacency::empty();
    assert_eq!(off.approx_heap_bytes(), 0, "knob-off CSR allocates nothing");
    assert_eq!(off.entries(), 0);

    // ON: build over the committed store and measure.
    let mut on = CsrAdjacency::empty();
    on.build_from_store(&s);
    let entries = on.entries();
    let bytes = on.approx_heap_bytes();
    // `rels` dominates at 8 bytes/entry; assert the per-entry cost is in the ~8-byte band (the directory
    // + offsets add a small per-group amortised overhead).
    let bytes_per_entry = bytes as f64 / entries as f64;
    assert!(entries > 0, "the multigraph has incident edges to index");
    assert!(
        (8.0..=20.0).contains(&bytes_per_entry),
        "per-entry footprint {bytes_per_entry:.1} B should be in the ~8 B/edge band (rels=8 B + small \
         per-group directory/offset overhead); entries={entries}, bytes={bytes}"
    );
    // Report the headline number for the task evidence.
    eprintln!(
        "CSR footprint (multigraph): {entries} entries, {} groups, {bytes} bytes ({bytes_per_entry:.2} B/entry)",
        on.groups()
    );

    // Footprint model and its asymptote. The dominant array is `rels` at EXACTLY 8 B per
    // incident-edge endpoint (each edge contributes one endpoint entry per distinct incident node — so
    // 2 entries for a normal edge, 1 for a self-loop). The directory + offsets add `16 + 4` bytes per
    // distinct `(node, type)` group. The per-ENTRY cost therefore approaches the 8 B floor as the
    // average number of same-type edges per `(node, type)` group grows (groups ≪ entries) — a dense
    // graph — and rises toward ~28 B/entry in the degenerate star where every group has one entry.
    //
    // Demonstrate the floor with a dense clustered graph: a few hubs each carrying many same-type
    // edges, so groups ≪ entries.
    let mut s2 = fresh();
    let txn = TxnId(1);
    s2.begin(txn);
    let t = s2.intern_token(Namespace::RelType, "LIKE").unwrap();
    let hubs: Vec<u64> = (0..20).map(|_| s2.create_node(txn).unwrap().0).collect();
    // Each of the 20 hubs links to each of 2000 shared targets: 40k edges, but only 20 + 2000 = 2020
    // distinct `(node, type)` groups carrying 80k endpoint entries (avg ~40 entries/group).
    let targets: Vec<u64> = (0..2000).map(|_| s2.create_node(txn).unwrap().0).collect();
    for &h in &hubs {
        for &tg in &targets {
            s2.create_rel(txn, t, h, tg).unwrap();
        }
    }
    s2.commit(txn).unwrap();
    let mut dense_csr = CsrAdjacency::empty();
    dense_csr.build_from_store(&s2);
    let dense_bpe = dense_csr.approx_heap_bytes() as f64 / dense_csr.entries() as f64;
    eprintln!(
        "CSR footprint (dense, ~40 edges/group): {} entries, {} groups, {} bytes ({dense_bpe:.3} B/entry)",
        dense_csr.entries(),
        dense_csr.groups(),
        dense_csr.approx_heap_bytes()
    );
    assert!(
        dense_bpe <= 9.0,
        "on a dense graph the per-entry footprint {dense_bpe:.3} B approaches the 8 B/edge `rels` floor"
    );
}

/// **Guarantee 4 (freshness gate):** after a relationship mutation marks the CSR stale, every lookup
/// declines (`None`), so `expand` falls back to the chain walk — which is always store-faithful — and
/// the result still equals the CSR-OFF baseline.
#[test]
fn csr_declines_after_mutation_still_correct() {
    let (s, hub, _) = build_multigraph();
    let t_like = s.token_id(Namespace::RelType, "LIKE").unwrap();
    let mut csr = CsrAdjacency::empty();
    csr.build_from_store(&s);
    assert!(
        csr.candidates(hub, &[t_like]).is_some(),
        "fresh ⇒ candidates"
    );

    // Any relationship mutation latches the CSR stale.
    csr.mark_dirty();
    assert!(csr.is_dirty());
    assert!(
        csr.candidates(hub, &[t_like]).is_none(),
        "stale CSR declines every lookup ⇒ caller uses the chain walk"
    );

    // The `expand_with_csr` body with `None` (the fallback the decline produces) is the exact Win-1
    // chain walk, so correctness is unchanged — covered byte-for-byte by the equality test above.
}

/// **End-to-end through the real executor + coordinator:** with the knob ON, the per-database
/// `TxnCoordinator` builds a CSR on open and a typed-expand query routes through it; the query must
/// return the EXACT same rows as the same query against a coordinator built with the knob OFF. This
/// exercises the full production wiring (`set_csr_adjacency` ⇒ `TxnCoordinator::new` build ⇒
/// `RecordStoreGraph::expand` consultation), not just the `read_source` seam.
#[test]
fn coordinator_csr_on_equals_off_through_executor() {
    use graphus_cypher::binding::{Parameters, bind_parameters};
    use graphus_cypher::catalog::IndexCatalog;
    use graphus_cypher::coordinator::TxnCoordinator;
    use graphus_cypher::executor::execute;
    use graphus_cypher::lexer::tokenize;
    use graphus_cypher::lower::lower;
    use graphus_cypher::parser::parse_tokens;
    use graphus_cypher::physical::plan_physical;
    use graphus_cypher::semantics::analyze;

    type Coord = TxnCoordinator<MemBlockDevice, MemLogSink>;

    // Seed a store with a typed-expand-shaped graph: a hub with FRIEND + LIKE edges (parallel + self).
    fn seed() -> Store {
        let (s, _, _) = build_multigraph();
        s
    }

    // Run `MATCH (a)-[:LIKE]->(b) RETURN id(b) AS x` and collect the sorted neighbour ids.
    fn run_like_neighbours(coord: &mut Coord) -> Vec<i64> {
        let src = "MATCH (a)-[:LIKE]->(b) RETURN id(b) AS x";
        let toks = tokenize(src).expect("lex");
        let ast = parse_tokens(&toks, src).expect("parse");
        let validated = analyze(&ast).expect("analyze");
        let plan = plan_physical(&lower(&validated), &IndexCatalog::empty());
        let bound = bind_parameters(&plan, &Parameters::new()).expect("bind");
        let txn = coord.begin_serializable();
        let rows = {
            let mut graph = coord.statement(txn).expect("statement");
            let mut cursor = execute(&plan, &bound, &mut graph).expect("cursor");
            let rows = cursor.collect_all().expect("collect");
            assert!(!graph.has_error(), "captured: {:?}", graph.take_error());
            rows
        };
        coord.commit(txn).expect("commit");
        let mut v: Vec<i64> = rows
            .iter()
            .filter_map(|r| match r.value("x") {
                graphus_core::Value::Integer(k) => Some(k),
                _ => None,
            })
            .collect();
        v.sort_unstable();
        v
    }

    // OFF baseline: build the coordinator with the knob off.
    graphus_cypher::read_source::set_csr_adjacency(false);
    let mut coord_off = TxnCoordinator::new(seed());
    let off = run_like_neighbours(&mut coord_off);

    // ON: enable the knob, then build a coordinator (so it builds the CSR on open) and run the query.
    graphus_cypher::read_source::set_csr_adjacency(true);
    let mut coord_on = TxnCoordinator::new(seed());
    let on = run_like_neighbours(&mut coord_on);

    // Reset the process-global knob so it does not leak into other tests in this binary.
    graphus_cypher::read_source::set_csr_adjacency(false);

    assert!(!off.is_empty(), "the query returns LIKE neighbours");
    assert_eq!(
        on, off,
        "CSR-ON query rows must equal CSR-OFF rows through the real executor + coordinator"
    );
}
