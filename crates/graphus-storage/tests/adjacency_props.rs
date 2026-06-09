//! Property-based fuzzing of index-free adjacency (`rmp` task #13 acceptance criterion 3:
//! *adjacency well-formed under property-based tests*).
//!
//! A deterministic, seedable [`SimRng`] (the project's DST RNG, `04 §11`) drives long random CRUD
//! sequences — create node, create edge (including parallel edges and self-loops), delete edge —
//! against the store. After every operation the test checks the store's adjacency against an
//! independent reference model and verifies the doubly-linked incidence-chain invariants directly
//! from the relationship records:
//!
//! * the store's [`incident_rels`](graphus_storage::RecordStore::incident_rels) for each node
//!   equals the reference set (degree counts agree; self-loops counted once);
//! * every relationship the chain enumerates is live and actually incident to the node (no
//!   dangling ids);
//! * both endpoints' chains are internally consistent (a `prev`/`next` neighbour link is mutual).
//!
//! Many seeds yield many independent histories, so a single failing seed is reproducible.

use std::collections::{BTreeSet, HashMap, HashSet};

use graphus_core::TxnId;
use graphus_core::capability::Rng;
use graphus_io::MemBlockDevice;
use graphus_sim::SimRng;
use graphus_storage::record::ChainSide;
use graphus_storage::{Namespace, RecordStore};
use graphus_wal::{MemLogSink, WalManager};

type Store = RecordStore<MemBlockDevice, MemLogSink>;

/// An independent reference model of the multigraph: for each live node, the set of live incident
/// relationship ids (self-loops appear once, as a distinct-incident traversal requires).
#[derive(Default)]
struct Model {
    nodes: BTreeSet<u64>,
    /// node -> set of incident rel ids
    incidence: HashMap<u64, BTreeSet<u64>>,
    /// rel id -> (start, end)
    rels: HashMap<u64, (u64, u64)>,
}

impl Model {
    fn add_node(&mut self, id: u64) {
        self.nodes.insert(id);
        self.incidence.entry(id).or_default();
    }

    fn add_rel(&mut self, id: u64, start: u64, end: u64) {
        self.rels.insert(id, (start, end));
        self.incidence.entry(start).or_default().insert(id);
        self.incidence.entry(end).or_default().insert(id); // self-loop: set dedupes
    }

    fn remove_rel(&mut self, id: u64) {
        if let Some((start, end)) = self.rels.remove(&id) {
            if let Some(s) = self.incidence.get_mut(&start) {
                s.remove(&id);
            }
            if let Some(s) = self.incidence.get_mut(&end) {
                s.remove(&id);
            }
        }
    }

    fn incident(&self, node: u64) -> BTreeSet<u64> {
        self.incidence.get(&node).cloned().unwrap_or_default()
    }
}

/// Asserts the store's adjacency matches the model and the chain invariants hold, for every node.
fn check(store: &mut Store, model: &Model, seed: u64, step: usize) {
    for &node in &model.nodes {
        let walked: BTreeSet<u64> = store
            .incident_rels(node)
            .unwrap_or_else(|e| panic!("seed={seed} step={step} node={node}: walk failed: {e}"))
            .into_iter()
            .collect();
        let expected = model.incident(node);
        assert_eq!(
            walked, expected,
            "seed={seed} step={step} node={node}: chain walk != model"
        );
        assert_eq!(
            store.degree(node).unwrap(),
            expected.len(),
            "seed={seed} step={step} node={node}: degree mismatch"
        );

        // Every enumerated rel is live and genuinely incident to `node` (no dangling ids).
        for &rid in &walked {
            let r = store.rel(rid).unwrap();
            assert!(
                r.mvcc.in_use(),
                "seed={seed} step={step}: rel {rid} on node {node}'s chain is not live"
            );
            assert!(
                r.start_node == node || r.end_node == node,
                "seed={seed} step={step}: rel {rid} on node {node}'s chain is not incident"
            );
        }

        // Doubly-linked consistency, treating each `(rel_id, side)` as a distinct chain *link*
        // (a self-loop contributes two links in the same record). Walk the chain forward via each
        // link's `next` and assert the successor's matching link points its `prev` back here.
        check_chain_links(store, node, seed, step);
    }
}

/// Verifies node `node`'s incidence chain is a well-formed doubly-linked list of `(rel_id, side)`
/// links: starting from `first_rel`, each link's `next` has a successor link (on the side facing
/// `node`) whose `prev` points back, and the head link has `prev == 0`.
fn check_chain_links(store: &mut Store, node: u64, seed: u64, step: usize) {
    /// The chain link (`prev`, `next`) of relationship `rid` on the side facing `node`, when
    /// arriving from `from` (the previous link's id, `0` at the head). For a self-loop both sides
    /// face `node`; pick the side whose `prev` equals `from` (the side we actually arrived through).
    fn link_of(store: &mut Store, rid: u64, node: u64, from: u64) -> (u64, u64) {
        let r = store.rel(rid).unwrap();
        let is_loop = r.start_node == node && r.end_node == node;
        if is_loop {
            let end = r.chain_pointers(ChainSide::End);
            // The END side is the head link (prev == 0); the START side follows it (prev == rid).
            if from == 0 || end.0 == from {
                end
            } else {
                r.chain_pointers(ChainSide::Start)
            }
        } else if r.start_node == node {
            r.chain_pointers(ChainSide::Start)
        } else {
            r.chain_pointers(ChainSide::End)
        }
    }

    let first = store.node(node).unwrap().first_rel;
    let mut from = 0u64;
    let mut cur = first;
    let mut steps = 0u64;
    let guard = 4 * (store.degree(node).unwrap() as u64) + 8;
    while cur != 0 {
        steps += 1;
        assert!(
            steps <= guard,
            "seed={seed} step={step} node={node}: chain link walk did not terminate"
        );
        let (prev, next) = link_of(store, cur, node, from);
        assert_eq!(
            prev, from,
            "seed={seed} step={step} node={node}: link {cur} prev={prev} expected {from}"
        );
        from = cur;
        cur = next;
    }
}

/// Runs one randomized CRUD history for `seed` over `steps` operations.
fn run_history(seed: u64, steps: usize) {
    let device = MemBlockDevice::new(0);
    let wal = WalManager::create(MemLogSink::new()).expect("create wal");
    let mut store: Store = RecordStore::create(device, wal, 32, 1).expect("create store");

    // Deletes are MVCC tombstones (`rmp` task #45): a deleted relationship stays threaded into the
    // incidence chain until a committed GC pass reclaims it, whereas the reference model drops a
    // deleted edge immediately. So each checkpoint commits the current batch, runs a GC pass
    // (watermark = the latest commit — safe because this single-threaded history has no older live
    // reader), and only then checks: the physical chains then reflect the logical model exactly.
    let mut txn_ctr = 1u64;
    let mut txn = TxnId(txn_ctr);
    store.begin(txn);
    let rt = store.intern_token(Namespace::RelType, "E").unwrap();

    let mut rng = SimRng::new(seed);
    let mut model = Model::default();
    let mut node_ids: Vec<u64> = Vec::new();
    let mut rel_ids: Vec<u64> = Vec::new();
    let mut alive_rels: HashSet<u64> = HashSet::new();

    for step in 0..steps {
        let choice = rng.next_u64() % 100;
        if node_ids.len() < 2 || choice < 25 {
            // create node
            let (id, _) = store.create_node(txn).unwrap();
            model.add_node(id);
            node_ids.push(id);
        } else if choice < 80 {
            // create edge (possibly parallel; possibly a self-loop when start == end picked)
            let a = node_ids[(rng.next_u64() as usize) % node_ids.len()];
            let b = node_ids[(rng.next_u64() as usize) % node_ids.len()];
            let (rid, _) = store.create_rel(txn, rt, a, b).unwrap();
            model.add_rel(rid, a, b);
            rel_ids.push(rid);
            alive_rels.insert(rid);
        } else if !alive_rels.is_empty() {
            // delete a live edge (MVCC tombstone; reclaimed at the next checkpoint's GC pass)
            let live: Vec<u64> = alive_rels.iter().copied().collect();
            let rid = live[(rng.next_u64() as usize) % live.len()];
            store.delete_rel(txn, rid).unwrap();
            model.remove_rel(rid);
            alive_rels.remove(&rid);
        }

        // Check invariants periodically (every op is correct but checking every op is O(n^2);
        // check every few steps and always at the end). Commit the batch and GC its tombstones
        // first so the store's physical chains match the model before we compare.
        if step % 7 == 0 || step + 1 == steps {
            store.commit(txn).unwrap();
            txn_ctr += 1;
            let gc_txn = TxnId(txn_ctr);
            let watermark = store.snapshot_ts();
            store.begin(gc_txn);
            store.gc(gc_txn, watermark).unwrap();
            store.commit(gc_txn).unwrap();
            check(&mut store, &model, seed, step);
            txn_ctr += 1;
            txn = TxnId(txn_ctr);
            store.begin(txn);
        }
    }

    // The final loop iteration already committed, GC'd and checked; `txn` is a fresh empty txn.
    store.commit(txn).unwrap();
    // A final full check after commit, and after a flush (pages written home).
    check(&mut store, &model, seed, steps);
    store.flush().unwrap();
    check(&mut store, &model, seed, steps + 1);
}

#[test]
fn random_crud_keeps_adjacency_well_formed() {
    for seed in 1..=40u64 {
        run_history(seed, 120);
    }
}

#[test]
fn larger_histories_a_few_seeds() {
    for seed in [101u64, 202, 303] {
        run_history(seed, 400);
    }
}

#[test]
fn self_loops_and_parallel_edges_are_exercised_by_the_generator() {
    // A focused seed-search proves the random generator actually produces self-loops and parallel
    // edges, so the property tests above genuinely cover criterion 2 as well.
    let mut saw_loop = false;
    let mut saw_parallel = false;
    'outer: for seed in 1..=40u64 {
        let mut rng = SimRng::new(seed);
        let mut nodes = 0u64;
        let mut pairs: HashMap<(u64, u64), u32> = HashMap::new();
        for _ in 0..120 {
            let choice = rng.next_u64() % 100;
            if nodes < 2 || choice < 25 {
                nodes += 1;
            } else if choice < 80 {
                let a = (rng.next_u64()) % nodes;
                let b = (rng.next_u64()) % nodes;
                if a == b {
                    saw_loop = true;
                }
                let c = pairs.entry((a, b)).or_default();
                *c += 1;
                if *c >= 2 {
                    saw_parallel = true;
                }
            } else {
                // deletion path consumes RNG identically to run_history's branch shape
                let _ = rng.next_u64();
            }
            if saw_loop && saw_parallel {
                break 'outer;
            }
        }
    }
    assert!(saw_loop, "generator should produce self-loops");
    assert!(saw_parallel, "generator should produce parallel edges");
}
