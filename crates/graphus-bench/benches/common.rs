//! Shared benchmark fixtures, included by each benchmark target via `#[path = "common.rs"] mod
//! common;`. Lives under `benches/` (not `src/`) because it depends on the engine crates that are
//! `[dev-dependencies]` of `graphus-bench`, which a crate's own `src/` cannot see.
//!
//! Every fixture drives the **real** persistent store ([`graphus_storage::RecordStore`]) over the
//! in-memory Deterministic-Simulation-Testing device + log sink, so the commit path exercises the
//! actual group-commit serialization point (`04 §4.2`/§9.1) deterministically, with no disk noise.
//!
//! `#![allow(dead_code)]`: each bench target compiles this module independently and uses only the
//! helpers it needs, so the unused ones would otherwise warn in that target.
#![allow(dead_code)]

use graphus_core::TxnId;
use graphus_io::MemBlockDevice;
use graphus_storage::{Namespace, RecordStore};
use graphus_wal::{MemLogSink, WalManager};

/// The buffer-pool capacity (frames) used by every benchmark store. Large enough that the small
/// benchmark working sets stay resident, so we measure the commit/read logic and not eviction
/// (eviction policy is a *separate* spike, §12 item 6).
pub const POOL_CAPACITY: usize = 4096;

/// The reltype every benchmark edge uses (interned once per store).
pub const REL_TYPE: &str = "KNOWS";

/// The property key every benchmark `SET` writes to (interned once per store).
pub const PROP_KEY: &str = "weight";

/// The concrete store type the benchmarks operate on (real store over the DST substrate).
pub type BenchStore = RecordStore<MemBlockDevice, MemLogSink>;

/// A record store on a fresh in-memory DST device + log sink — the substrate every benchmark runs
/// on. Returns the store with its catalog already created and hardened.
///
/// # Panics
/// Panics if store creation fails (a benchmark fixture, so a failure is a programming error, not a
/// condition to handle gracefully — mirrors the `unwrap` policy for fatal init).
#[must_use]
pub fn fresh_store() -> BenchStore {
    let device = MemBlockDevice::new(0);
    let wal = WalManager::create(MemLogSink::new()).expect("create WAL");
    RecordStore::create(device, wal, POOL_CAPACITY, 1).expect("create store")
}

/// Interns the standard reltype + propkey on a store and returns their token ids.
#[must_use]
pub fn intern_tokens(store: &mut BenchStore) -> (u32, u32) {
    let rel_type = store
        .intern_token(Namespace::RelType, REL_TYPE)
        .expect("intern reltype");
    let prop_key = store
        .intern_token(Namespace::PropKey, PROP_KEY)
        .expect("intern propkey");
    (rel_type, prop_key)
}

/// Builds a connected benchmark graph of `nodes` vertices and `edges_per_node` outgoing edges per
/// vertex (a ring-plus-chords topology, so every node has non-trivial degree and traversals are
/// representative of a property graph rather than a star or a line). All work is committed in
/// `batch`-sized transactions so the builder itself goes through the real commit path.
///
/// Returns the populated store and the vector of node physical ids (dense, `1..=nodes`).
///
/// # Panics
/// Panics on any store error — see [`fresh_store`] for the fixture `unwrap` rationale.
#[must_use]
pub fn build_graph(nodes: u64, edges_per_node: u64, batch: u64) -> (BenchStore, Vec<u64>) {
    assert!(nodes > 0, "need at least one node");
    assert!(batch > 0, "batch size must be positive");
    let mut store = fresh_store();
    let rel_type = store
        .intern_token(Namespace::RelType, REL_TYPE)
        .expect("intern reltype");

    let mut ids = Vec::with_capacity(nodes as usize);
    let mut txn_counter: u64 = 1;

    // Phase 1: create the nodes, `batch` per transaction.
    let mut created: u64 = 0;
    while created < nodes {
        let txn = TxnId(txn_counter);
        txn_counter += 1;
        store.begin(txn);
        let upto = (created + batch).min(nodes);
        for _ in created..upto {
            let (id, _) = store.create_node(txn).expect("create node");
            ids.push(id);
        }
        store.commit(txn).expect("commit node batch");
        created = upto;
    }

    // Phase 2: wire `edges_per_node` chords from each node to deterministically-chosen targets,
    // `batch` edges per transaction. The stride pattern keeps the graph connected and gives every
    // node both out- and in-edges, so incidence-chain walks have real length.
    let mut pending: u64 = 0;
    let mut txn = TxnId(txn_counter);
    txn_counter += 1;
    store.begin(txn);
    for (i, &src) in ids.iter().enumerate() {
        for k in 0..edges_per_node {
            let stride = 1 + k * 7;
            let dst = ids[(i as u64 + stride) as usize % nodes as usize];
            store
                .create_rel(txn, rel_type, src, dst)
                .expect("create rel");
            pending += 1;
            if pending == batch {
                store.commit(txn).expect("commit edge batch");
                pending = 0;
                txn = TxnId(txn_counter);
                txn_counter += 1;
                store.begin(txn);
            }
        }
    }
    if pending > 0 {
        store.commit(txn).expect("commit final edge batch");
    } else {
        // The last `begin` opened an empty transaction; commit it so no txn is left dangling.
        store.commit(txn).expect("commit empty trailing txn");
    }

    (store, ids)
}
