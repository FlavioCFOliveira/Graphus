//! Hermetic, in-process bulk round-trip — the dev-only cargo mirror of the `examples/bulk-etl` core
//! (`rmp #269`).
//!
//! This runs in the DEFAULT `cargo test` (no subprocess, no server, no disk, no network): it
//! generates a small deterministic dataset with the example's own generator, drives it through the
//! real `graphus-bulk` **library** [`BulkImporter`] into a fresh in-memory store, asserts the imported
//! counts equal the manifest, then dumps the whole graph back to CSV, re-imports it into a SECOND
//! fresh store, and proves losslessness the same way the core proves it — by asserting:
//!
//! 1. the re-imported node / relationship **counts** equal the originals, and
//! 2. the id-independent **content hash** of store B equals store A's.
//!
//! It is the fast-profile (and a tiny custom-profile) scenario the bigger `bulk_roundtrip` driver
//! exercises over the real binary, distilled to a pure-Rust unit so CI catches a losslessness
//! regression with zero external dependencies.

use graphus_bulk::{BulkImporter, DEFAULT_BATCH_SIZE, dump_nodes, dump_relationships};
use graphus_bulk_gen::content_hash::content_hash;
use graphus_bulk_gen::{Dataset, GenConfig, Profile, generate};
use graphus_io::MemBlockDevice;
use graphus_storage::RecordStore;
use graphus_wal::{MemLogSink, WalManager};

/// A fully in-memory store: hermetic (no disk), the right substrate for a default-run test.
type MemStore = RecordStore<MemBlockDevice, MemLogSink>;

/// A fresh, empty in-memory store.
fn fresh_store() -> MemStore {
    let device = MemBlockDevice::new(0);
    let wal = WalManager::create(MemLogSink::new()).expect("create wal");
    RecordStore::create(device, wal, 256, 1).expect("create store")
}

/// Imports a whole generated [`Dataset`] (every node file then every relationship file, in load
/// order) into a fresh store through the real [`BulkImporter`] library API, returning the store and
/// the importer's reported `(nodes, relationships)` counts.
fn import_dataset(dataset: &Dataset) -> (MemStore, u64, u64) {
    let mut importer = BulkImporter::new(fresh_store(), DEFAULT_BATCH_SIZE, b',');
    for nf in &dataset.node_files {
        importer
            .import_nodes(nf.csv.as_bytes())
            .unwrap_or_else(|e| panic!("import nodes {}: {e}", nf.name));
    }
    for rf in &dataset.rel_files {
        importer
            .import_relationships(rf.csv.as_bytes())
            .unwrap_or_else(|e| panic!("import rels {}: {e}", rf.name));
    }
    let (store, stats) = importer.finish();
    (store, stats.nodes, stats.relationships)
}

/// Drives one config through `generate -> import -> dump -> re-import` entirely in-process and asserts
/// counts + content-hash losslessness.
fn assert_lossless_roundtrip(cfg: GenConfig, profile: &str) {
    let dataset = generate(cfg, profile);
    let manifest = &dataset.manifest;

    // ----- Import A: the generated dataset into a fresh store. -----
    let (mut store_a, nodes_a, rels_a) = import_dataset(&dataset);
    assert_eq!(
        nodes_a, manifest.total_nodes,
        "{profile}: imported node count must equal the manifest"
    );
    assert_eq!(
        rels_a, manifest.total_relationships,
        "{profile}: imported relationship count must equal the manifest"
    );

    let hash_a = content_hash(&mut store_a);
    assert_eq!(hash_a.nodes, manifest.total_nodes);
    assert_eq!(hash_a.relationships, manifest.total_relationships);

    // ----- Dump store A to CSV. -----
    let mut node_csv = Vec::new();
    let mut rel_csv = Vec::new();
    dump_nodes(&mut store_a, &mut node_csv).expect("dump nodes");
    dump_relationships(&mut store_a, &mut rel_csv).expect("dump rels");
    assert!(!node_csv.is_empty(), "{profile}: dumped node CSV is empty");
    assert!(!rel_csv.is_empty(), "{profile}: dumped rel CSV is empty");

    // ----- Re-import the dump into a SECOND fresh store. -----
    let mut importer_b = BulkImporter::new(fresh_store(), DEFAULT_BATCH_SIZE, b',');
    importer_b
        .import_nodes(node_csv.as_slice())
        .expect("re-import nodes");
    importer_b
        .import_relationships(rel_csv.as_slice())
        .expect("re-import rels");
    let (mut store_b, stats_b) = importer_b.finish();

    assert_eq!(
        stats_b.nodes, manifest.total_nodes,
        "{profile}: re-imported node count must equal the original"
    );
    assert_eq!(
        stats_b.relationships, manifest.total_relationships,
        "{profile}: re-imported relationship count must equal the original"
    );

    // ----- The losslessness proof: id-independent content hash A == B. -----
    let hash_b = content_hash(&mut store_b);
    assert_eq!(
        hash_a.hex, hash_b.hex,
        "{profile}: import -> dump -> re-import must be LOSSLESS (content hash diverged: \
         A={} B={})",
        hash_a.hex, hash_b.hex
    );
}

/// The fast profile — the same dataset the committed baseline + `run.sh` use — round-trips losslessly
/// through the library, asserting counts + content hash.
#[test]
fn fast_profile_roundtrips_losslessly_in_process() {
    assert_lossless_roundtrip(Profile::Fast.config(), "fast");
}

/// A tiny custom config exercises every node label, every relationship type, arrays, and the
/// present-but-empty dump column-unification — and still round-trips losslessly. Kept small so the
/// default `cargo test` stays fast.
#[test]
fn tiny_custom_config_roundtrips_losslessly_in_process() {
    let cfg = GenConfig {
        seed: 0x0BAD_F00D_1234_5678,
        persons: 16,
        forums: 4,
        posts_per_forum: 3,
        comments_per_post: 2,
        knows_per_person: 3,
        members_per_forum: 5,
        likes_per_person: 2,
    };
    assert_lossless_roundtrip(cfg, "tiny");
}
