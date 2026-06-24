//! `#[ignore]` micro-benchmarks for the typed incidence walk (`rmp` #324) and a footprint probe for
//! the prospective in-memory type-bucketed adjacency (Win 2).
//!
//! Run with: `cargo test -p graphus-storage --test typed_expand_bench -- --ignored --nocapture`
//!
//! These are deterministic, single-threaded timing/space measurements (not criterion harnesses) —
//! enough to quantify the before/after of a type-selective traversal and the bytes/edge of a CSR
//! adjacency on a representative `top_liked`-shaped graph (a high-degree hub with a minority of the
//! selective type, the rest a noise type), without pulling a bench dependency into the crate.

use std::time::Instant;

use graphus_core::TxnId;
use graphus_io::MemBlockDevice;
use graphus_storage::{Namespace, RecordStore};
use graphus_wal::{MemLogSink, WalManager};

type Store = RecordStore<MemBlockDevice, MemLogSink>;

/// Builds `hubs` hubs, each with `degree` incident edges of which `~1/keep_ratio` are the selective
/// type `LIKE` and the rest the noise type `FRIEND`. Returns the store, the LIKE token id, and the
/// hub ids.
fn build(hubs: u64, degree: u64, keep_every: u64) -> (Store, u32, Vec<u64>) {
    let device = MemBlockDevice::new(0);
    let wal = WalManager::create(MemLogSink::new()).expect("wal");
    let mut s = RecordStore::create(device, wal, 4096, 1).expect("store");
    let txn = TxnId(1);
    s.begin(txn);
    let t_friend = s.intern_token(Namespace::RelType, "FRIEND").unwrap();
    let t_like = s.intern_token(Namespace::RelType, "LIKE").unwrap();
    let mut hub_ids = Vec::new();
    for _ in 0..hubs {
        let (hub, _) = s.create_node(txn).unwrap();
        hub_ids.push(hub);
        for j in 0..degree {
            let (other, _) = s.create_node(txn).unwrap();
            let t = if j % keep_every == 0 {
                t_like
            } else {
                t_friend
            };
            s.create_rel(txn, t, hub, other).unwrap();
        }
    }
    s.commit(txn).unwrap();
    (s, t_like, hub_ids)
}

#[test]
#[ignore = "timing bench; run explicitly with --ignored --nocapture"]
fn bench_typed_vs_untyped_then_filter() {
    // top_liked shape: 200 hubs * 2000 incident edges, keep every 3rd as LIKE (~33% match,
    // ~67% wasted under the old path) — proportional to the production 996k/2.75M.
    let (s, t_like, hubs) = build(200, 2_000, 3);

    // OLD path simulation: walk incident_rels (degree reads) THEN re-read each id (degree reads)
    // and filter by type. This is exactly the pre-#324 `expand` cost.
    let start = Instant::now();
    let mut old_matched = 0usize;
    for &h in &hubs {
        let ids = s.incident_rels(h).unwrap();
        for id in ids {
            let rec = s.rel(id).unwrap(); // the wasteful second read
            if rec.type_id == t_like {
                old_matched += 1;
            }
        }
    }
    let old = start.elapsed();

    // NEW path (#324 Win 1): single typed walk, materialises only matching records.
    let start = Instant::now();
    let mut new_matched = 0usize;
    for &h in &hubs {
        let typed = s.incident_rels_typed(h, &[t_like]).unwrap();
        new_matched += typed.len();
    }
    let new = start.elapsed();

    assert_eq!(old_matched, new_matched, "same matched count both paths");
    println!(
        "typed-expand bench: hubs=200 degree=2000 match={}/{} | OLD(incident+per-id rel+filter)={:?} NEW(incident_rels_typed)={:?} speedup={:.2}x",
        new_matched,
        200 * 2000,
        old,
        new,
        old.as_secs_f64() / new.as_secs_f64().max(1e-9),
    );
}

#[test]
#[ignore = "RAM footprint probe; run explicitly with --ignored --nocapture"]
fn probe_csr_adjacency_footprint() {
    // Measure the bytes/edge of a flat CSR-like (node,type)->rel-id adjacency built from the base
    // store — the Win 2 acceleration structure. Layout (the compact design, no per-node Vec):
    //   * `rels: Vec<u64>`        — every incident (node-side) rel id, grouped by (node, type)
    //   * `offsets: Vec<u32>`     — one per (node, type) group: start index into `rels`
    //   * `groups: Vec<(u64,u32)>`— the (node_id, type_id) key of each group, parallel to offsets
    // i.e. CSR with a sorted group directory. We BUILD it here and report the measured footprint;
    // we do NOT wire it into the store in this probe.
    let (s, _t_like, hubs) = build(50, 4_000, 3);
    let degree = 4_000u64;
    let edges = hubs.len() as u64 * degree;

    // Build the CSR from the base store (rebuild-on-open model, like IndexSet).
    let mut groups: Vec<(u64, u32)> = Vec::new();
    let mut offsets: Vec<u32> = Vec::new();
    let mut rels: Vec<u64> = Vec::new();
    for &h in &hubs {
        // Collect (type, rel_id) for the node, then group by type.
        let typed = s.incident_rels_typed(h, &[]).unwrap();
        let mut by_type: std::collections::BTreeMap<u32, Vec<u64>> =
            std::collections::BTreeMap::new();
        for (rid, rec) in typed {
            by_type.entry(rec.type_id).or_default().push(rid);
        }
        for (ty, ids) in by_type {
            groups.push((h, ty));
            offsets.push(rels.len() as u32);
            rels.extend(ids);
        }
    }
    offsets.push(rels.len() as u32); // sentinel end

    let bytes = rels.len() * std::mem::size_of::<u64>()
        + offsets.len() * std::mem::size_of::<u32>()
        + groups.len() * std::mem::size_of::<(u64, u32)>();
    println!(
        "CSR adjacency footprint: hubs={} degree={} edges={} | rels={} offsets={} groups={} | total={} bytes = {:.2} bytes/edge",
        hubs.len(),
        degree,
        edges,
        rels.len(),
        offsets.len(),
        groups.len(),
        bytes,
        bytes as f64 / edges as f64,
    );
    // Sanity: every edge appears once on its hub side here (no self-loops in this fixture).
    assert_eq!(rels.len() as u64, edges);
}
