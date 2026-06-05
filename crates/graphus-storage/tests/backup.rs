//! Integration tests for offline **backup / restore / verification** (`rmp` task #23:
//! "Backups restore to a consistent state; verification detects a tampered backup"; serves
//! `CLAUDE.md`'s inviolable *never corrupt* mandate, `04-technical-design.md` §2.1, §3.2, §4.7).
//!
//! The suite has three halves:
//!
//! * **Round-trip equality.** A store is built with nodes, relationships (including parallel edges
//!   and self-loops) and properties, across several deterministic [`SimRng`] seeds; it is backed up,
//!   restored onto a fresh device, opened, and the restored graph is asserted to **equal** the
//!   original — same nodes (element ids + labels), same relationships (element ids, types,
//!   endpoints), same adjacency, same properties — by comparing both to an independent reference
//!   model. The restored store also passes [`verify_on_open`].
//! * **Verification has teeth.** One focused test per tamper kind — a flipped payload byte, a
//!   truncated artifact, a corrupt header, a per-page checksum corruption, a misplaced page — first
//!   confirms the *untampered* artifact verifies and restores cleanly, then asserts the tampered
//!   artifact is rejected by [`verify_backup`] **and** that a restore from it fails.
//! * **Consistency of restore.** A backup that frames an internally-inconsistent image (a record
//!   corrupted in a way that survives both the per-page checksum and the whole-payload digest, by
//!   re-faking both) is caught by the post-restore consistency check inside [`restore`].
//!
//! All tests are deterministic and use only the in-memory DST devices.

use std::collections::{BTreeMap, BTreeSet};

use graphus_bufpool::page;
use graphus_core::capability::Rng;
use graphus_core::{ElementId, TxnId};
use graphus_io::{MemBlockDevice, PAGE_SIZE, Page};
use graphus_sim::SimRng;
use graphus_storage::record::NODE_RECORD_SIZE;
use graphus_storage::{
    Namespace, RecordStore, backup_creation_marker, backup_store, restore, restore_onto,
    verify_backup, verify_on_open,
};
use graphus_wal::{MemLogSink, WalManager};

type Store = RecordStore<MemBlockDevice, MemLogSink>;

/// Builds a fresh store over an in-memory device + log.
fn fresh(cap: usize) -> Store {
    let device = MemBlockDevice::new(0);
    let wal = WalManager::create(MemLogSink::new()).expect("create wal");
    RecordStore::create(device, wal, cap, 1).expect("create store")
}

/// A fresh, empty WAL for a restored store (the backup carries the data image at a clean
/// checkpoint, so the restored store needs no WAL replay).
fn fresh_wal() -> WalManager<MemLogSink> {
    WalManager::create(MemLogSink::new()).expect("create wal")
}

// ============================================================================================
// An independent reference model of the durable graph, derived from a store by reading records.
// ============================================================================================

/// The query-visible identity of a node: its stable element id and its (opaque, but exactly
/// preserved) label set word.
#[derive(Debug, Clone, PartialEq, Eq)]
struct NodeView {
    element_id: ElementId,
    labels: u64,
}

/// A property `(key, type_tag, value_inline)` exactly as stored.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct PropView {
    key: u32,
    type_tag: u8,
    value_inline: u64,
}

/// A full, order-independent snapshot of a store's durable graph, keyed by **stable element id** so
/// it is comparable across a backup/restore even though physical ids are an implementation detail
/// (`04 §2.2`: element ids are the stable identity, physical ids may be reused).
#[derive(Debug, Clone, PartialEq, Eq)]
struct GraphSnapshot {
    /// element_id -> node view.
    nodes: BTreeMap<u128, NodeView>,
    /// element_id -> rel view (endpoints are remapped to the start/end nodes' element ids).
    rels: BTreeMap<u128, (u32, u128, u128)>,
    /// node element_id -> set of incident rel element ids (self-loop counted once).
    adjacency: BTreeMap<u128, BTreeSet<u128>>,
    /// node element_id -> sorted multiset of its properties.
    node_props: BTreeMap<u128, Vec<PropView>>,
}

/// Derives a [`GraphSnapshot`] from a store by scanning live records and walking adjacency +
/// property chains. Uses `high_water` bounds via the public CRUD reads; a record is "live" iff its
/// MVCC header reads `in_use`. (We scan ids `1..=max` by probing; a missing page ends the scan.)
///
/// Generic over the block device so it works for both the in-memory and the file-backed restore.
fn snapshot<D: graphus_io::BlockDevice>(store: &mut RecordStore<D, MemLogSink>) -> GraphSnapshot {
    // Map physical id -> element id for live nodes, so rel endpoints can be remapped.
    let mut phys_to_eid: BTreeMap<u64, u128> = BTreeMap::new();
    let mut nodes: BTreeMap<u128, NodeView> = BTreeMap::new();
    let mut node_phys: Vec<u64> = Vec::new();

    let mut id = 1u64;
    // The scan ends when a record's page is not allocated (`store.node` returns `Err`).
    while let Ok(rec) = store.node(id) {
        if rec.mvcc.in_use() {
            phys_to_eid.insert(id, rec.element_id.0);
            nodes.insert(
                rec.element_id.0,
                NodeView {
                    element_id: rec.element_id,
                    labels: rec.labels,
                },
            );
            node_phys.push(id);
        }
        id += 1;
    }

    // Relationships: scan and remap endpoints to element ids.
    let mut rels: BTreeMap<u128, (u32, u128, u128)> = BTreeMap::new();
    let mut rel_phys_to_eid: BTreeMap<u64, u128> = BTreeMap::new();
    let mut id = 1u64;
    while let Ok(rec) = store.rel(id) {
        if rec.mvcc.in_use() {
            let s = phys_to_eid.get(&rec.start_node).copied().unwrap_or(0);
            let e = phys_to_eid.get(&rec.end_node).copied().unwrap_or(0);
            rels.insert(rec.element_id.0, (rec.type_id, s, e));
            rel_phys_to_eid.insert(id, rec.element_id.0);
        }
        id += 1;
    }

    // Adjacency + node properties, walked via the store's public traversals.
    let mut adjacency: BTreeMap<u128, BTreeSet<u128>> = BTreeMap::new();
    let mut node_props: BTreeMap<u128, Vec<PropView>> = BTreeMap::new();
    for &nphys in &node_phys {
        let neid = phys_to_eid[&nphys];
        let mut inc: BTreeSet<u128> = BTreeSet::new();
        for rid in store.incident_rels(nphys).expect("incident rels") {
            inc.insert(rel_phys_to_eid[&rid]);
        }
        adjacency.insert(neid, inc);

        let mut props: Vec<PropView> = store
            .node_properties(nphys)
            .expect("node properties")
            .into_iter()
            .map(|(_, p)| PropView {
                key: p.key,
                type_tag: p.type_tag,
                value_inline: p.value_inline,
            })
            .collect();
        props.sort();
        node_props.insert(neid, props);
    }

    GraphSnapshot {
        nodes,
        rels,
        adjacency,
        node_props,
    }
}

// ============================================================================================
// Builders.
// ============================================================================================

/// Builds a randomized but deterministic graph for `seed`: nodes (with a label + a couple of
/// properties), edges (incl. parallel edges and self-loops). Returns the store and the reltype
/// token id used for edges. All work is committed.
fn build_graph(seed: u64, ops: usize) -> Store {
    let mut store = fresh(64);
    let txn = TxnId(1);
    store.begin(txn);
    // Intern tokens across all three namespaces so the durable token dictionary is non-trivial and
    // its round-trip through the metadata page is exercised.
    let _person = store.intern_token(Namespace::Label, "Person").unwrap();
    let key_a = store.intern_token(Namespace::PropKey, "age").unwrap();
    let key_b = store.intern_token(Namespace::PropKey, "score").unwrap();
    let rt = store.intern_token(Namespace::RelType, "KNOWS").unwrap();

    let mut rng = SimRng::new(seed);
    let mut node_ids: Vec<u64> = Vec::new();
    let mut rel_ids: Vec<u64> = Vec::new();

    for _ in 0..ops {
        let choice = rng.next_u64() % 100;
        if node_ids.len() < 2 || choice < 30 {
            let (id, _) = store.create_node(txn).unwrap();
            // Give the node a couple of inline properties so the snapshot has record-level data to
            // compare byte-for-byte across the round trip (the labels word has no CRUD setter yet).
            store
                .add_node_property(txn, id, key_a, 2, rng.next_u64() % 200)
                .unwrap();
            store
                .add_node_property(txn, id, key_b, 3, rng.next_u64())
                .unwrap();
            node_ids.push(id);
        } else if choice < 85 {
            let a = node_ids[(rng.next_u64() as usize) % node_ids.len()];
            let b = node_ids[(rng.next_u64() as usize) % node_ids.len()]; // a==b => self-loop
            let (rid, _) = store.create_rel(txn, rt, a, b).unwrap();
            rel_ids.push(rid);
        } else if !rel_ids.is_empty() {
            // Delete a previously-created edge to exercise the free list in the durable image.
            let idx = (rng.next_u64() as usize) % rel_ids.len();
            let rid = rel_ids.swap_remove(idx);
            // The edge may already be gone if a self-loop's id collided; guard with a liveness read.
            if store.rel(rid).map(|r| r.mvcc.in_use()).unwrap_or(false) {
                store.delete_rel(txn, rid).unwrap();
            }
        }
    }
    store.commit(txn).unwrap();
    store
}

// ============================================================================================
// Round-trip equality.
// ============================================================================================

#[test]
fn round_trip_preserves_the_graph_across_seeds() {
    for seed in 1..=12u64 {
        let mut original = build_graph(seed, 120);
        let before = snapshot(&mut original);
        let marker = original.element_id_next();

        let artifact = backup_store(&mut original).expect("backup");
        verify_backup(&artifact).expect("untampered artifact verifies");
        assert_eq!(
            backup_creation_marker(&artifact).unwrap(),
            marker,
            "seed={seed}: creation marker is the source's element-id-next"
        );

        let mut restored = restore(&artifact, fresh_wal(), 64).expect("restore");
        let after = snapshot(&mut restored);

        assert_eq!(before, after, "seed={seed}: restored graph != original");
        verify_on_open(&mut restored, &[]).expect("restored store is consistent");
    }
}

#[test]
fn empty_store_round_trips() {
    let mut original = fresh(16);
    let before = snapshot(&mut original);
    assert!(before.nodes.is_empty());

    let artifact = backup_store(&mut original).expect("backup empty");
    verify_backup(&artifact).expect("empty artifact verifies");

    let mut restored = restore(&artifact, fresh_wal(), 16).expect("restore empty");
    let after = snapshot(&mut restored);
    assert_eq!(before, after);
    verify_on_open(&mut restored, &[]).expect("restored empty store is consistent");

    // A new node after restore continues element ids past the recovered high-water (never reused).
    let txn = TxnId(1);
    restored.begin(txn);
    let (_id, eid) = restored.create_node(txn).unwrap();
    restored.commit(txn).unwrap();
    assert_eq!(
        eid.0,
        backup_creation_marker(&artifact).unwrap(),
        "first post-restore element id equals the captured next-id marker"
    );
}

#[test]
fn backup_does_not_mutate_the_source_graph() {
    let mut original = build_graph(7, 80);
    let before = snapshot(&mut original);
    let _ = backup_store(&mut original).expect("backup");
    let after = snapshot(&mut original);
    assert_eq!(before, after, "backup must be read-only w.r.t. the graph");
}

#[test]
fn self_loops_and_parallel_edges_survive_round_trip() {
    // A focused, hand-built graph that definitely contains a self-loop and parallel edges.
    let mut original = fresh(32);
    let txn = TxnId(1);
    original.begin(txn);
    let rt = original.intern_token(Namespace::RelType, "E").unwrap();
    let (a, eid_a) = original.create_node(txn).unwrap();
    let (b, _) = original.create_node(txn).unwrap();
    let _p1 = original.create_rel(txn, rt, a, b).unwrap(); // a->b
    let _p2 = original.create_rel(txn, rt, a, b).unwrap(); // parallel a->b
    let _loop_a = original.create_rel(txn, rt, a, a).unwrap(); // self-loop on a
    original.commit(txn).unwrap();

    let before = snapshot(&mut original);
    // a is incident to: two parallel edges + one self-loop (deduped to a single incident rel) = 3.
    assert_eq!(
        before.adjacency[&eid_a.0].len(),
        3,
        "a has two parallel edges and one self-loop incident"
    );

    let artifact = backup_store(&mut original).expect("backup");
    let mut restored = restore(&artifact, fresh_wal(), 32).expect("restore");
    let after = snapshot(&mut restored);
    assert_eq!(before, after);
}

// ============================================================================================
// Verification has teeth: each tamper kind is rejected, and a restore from it fails.
// ============================================================================================

/// Builds a representative artifact and confirms the *untampered* form verifies + restores cleanly,
/// returning the artifact for a test to then tamper with.
fn good_artifact() -> Vec<u8> {
    let mut original = build_graph(3, 100);
    let artifact = backup_store(&mut original).expect("backup");
    verify_backup(&artifact).expect("baseline: untampered artifact verifies");
    let mut restored = restore(&artifact, fresh_wal(), 64).expect("baseline: untampered restores");
    verify_on_open(&mut restored, &[]).expect("baseline: restored store is consistent");
    artifact
}

#[test]
fn tamper_flip_payload_byte_is_rejected() {
    let mut artifact = good_artifact();
    // Flip a byte inside the page section (well past the header, before the digest trailer).
    let target = artifact.len() / 2;
    artifact[target] ^= 0xFF;

    let err = verify_backup(&artifact).unwrap_err().to_string();
    assert!(
        err.contains("digest") || err.contains("CRC32C"),
        "flipped payload byte must be caught; got: {err}"
    );
    assert!(
        restore(&artifact, fresh_wal(), 64).is_err(),
        "restore from a flipped-byte artifact must fail"
    );
}

#[test]
fn tamper_truncation_is_rejected() {
    let mut artifact = good_artifact();
    artifact.truncate(artifact.len() - 10); // drop part of the trailing page + digest

    assert!(
        verify_backup(&artifact).is_err(),
        "a truncated artifact must be rejected"
    );
    assert!(
        restore(&artifact, fresh_wal(), 64).is_err(),
        "restore from a truncated artifact must fail"
    );
}

#[test]
fn tamper_header_page_count_is_rejected() {
    let mut artifact = good_artifact();
    // Corrupt the declared page_count (bytes 32..40) without touching the section length.
    let bumped = u64::from_le_bytes(artifact[32..40].try_into().unwrap()) + 1;
    artifact[32..40].copy_from_slice(&bumped.to_le_bytes());

    let err = verify_backup(&artifact).unwrap_err().to_string();
    assert!(
        err.contains("page section") || err.contains("digest"),
        "a corrupt header page_count must be caught; got: {err}"
    );
    assert!(
        restore(&artifact, fresh_wal(), 64).is_err(),
        "restore from a corrupt-header artifact must fail"
    );
}

#[test]
fn tamper_per_page_checksum_then_refake_digest_is_caught_by_page_crc() {
    // Corrupt a page *body* and re-fake only the whole-payload digest. The per-page CRC32C in the
    // page header now fails, which `verify_backup`'s second layer catches even though the artifact
    // digest matches.
    let mut artifact = good_artifact();
    // The first framed page is the metadata page: its body starts at HEADER_LEN + 8 (after page_id).
    const HEADER_LEN: usize = 8 + 4 + 4 + 16 + 8;
    let body_byte = HEADER_LEN + 8 + 200; // 200 bytes into the first page's body
    artifact[body_byte] ^= 0xFF;
    // Re-fake the whole-payload digest so the first integrity layer passes.
    let digest_at = artifact.len() - 4;
    let digest = crc32c::crc32c(&artifact[..digest_at]);
    artifact[digest_at..].copy_from_slice(&digest.to_le_bytes());

    let err = verify_backup(&artifact).unwrap_err().to_string();
    assert!(
        err.contains("CRC32C"),
        "a body corruption with a re-faked digest must be caught by the per-page CRC; got: {err}"
    );
    assert!(restore(&artifact, fresh_wal(), 64).is_err());
}

#[test]
fn tamper_misplaced_page_id_is_rejected() {
    // Rewrite the *framing* page_id of the first page (the metadata page, device id 0) to a wrong
    // value, while keeping the page body (with its self-referential page_id header = 0) and re-fake
    // the digest. The header/framing disagreement is what fires.
    let mut artifact = good_artifact();
    const HEADER_LEN: usize = 8 + 4 + 4 + 16 + 8;
    // First framed page_id is at HEADER_LEN..HEADER_LEN+8; it should be 0 (the metadata page).
    let original_framed =
        u64::from_le_bytes(artifact[HEADER_LEN..HEADER_LEN + 8].try_into().unwrap());
    assert_eq!(
        original_framed, 0,
        "first framed page is the metadata page (device 0)"
    );
    artifact[HEADER_LEN..HEADER_LEN + 8].copy_from_slice(&999u64.to_le_bytes());
    let digest_at = artifact.len() - 4;
    let digest = crc32c::crc32c(&artifact[..digest_at]);
    artifact[digest_at..].copy_from_slice(&digest.to_le_bytes());

    let err = verify_backup(&artifact).unwrap_err().to_string();
    assert!(
        err.contains("misplaced") || err.contains("page_id"),
        "a misplaced page must be caught; got: {err}"
    );
    assert!(restore(&artifact, fresh_wal(), 64).is_err());
}

// ============================================================================================
// Consistency of restore: an internally-inconsistent image that survives both digests is caught
// by the post-restore consistency check.
// ============================================================================================

#[test]
fn restore_rejects_an_inconsistent_image_that_passes_both_digests() {
    // Build a graph with at least one relationship, capture its backup, then corrupt a *node*
    // record so its incidence chain no longer matches the relationships (a structural inconsistency
    // the per-page CRC and the whole-payload digest both pass once re-faked). The post-restore
    // consistency check inside `restore` must reject it.
    let mut original = fresh(64);
    let txn = TxnId(1);
    original.begin(txn);
    let rt = original.intern_token(Namespace::RelType, "E").unwrap();
    let (a, eid_a) = original.create_node(txn).unwrap();
    let (b, _) = original.create_node(txn).unwrap();
    let _r = original.create_rel(txn, rt, a, b).unwrap();
    original.commit(txn).unwrap();

    let mut artifact = backup_store(&mut original).expect("backup");
    verify_backup(&artifact).expect("baseline verifies");
    restore(&artifact, fresh_wal(), 64).expect("baseline restores consistently");

    // Locate node `a`'s record in the artifact by matching its (unique) element id, then zero its
    // `first_rel` so its incidence chain no longer contains the relationship the rel records still
    // claim — an incidence mismatch the consistency checker detects (`AdjacencyFault::*`).
    let (page_body_start, in_page) = locate_record(&artifact, eid_a.0, NODE_RECORD_SIZE);
    // `first_rel` follows the 25-byte MVCC header + the 16-byte element id (frozen layout, `04 §2.3`).
    let first_rel_off = page_body_start + in_page + mvcc_plus_eid();
    artifact[first_rel_off..first_rel_off + 8].copy_from_slice(&0u64.to_le_bytes());

    // Re-checksum that page and re-fake the whole-payload digest so both integrity layers pass.
    refresh_page_checksum(&mut artifact, page_body_start);
    refresh_artifact_digest(&mut artifact);

    // Both integrity layers now pass...
    verify_backup(&artifact).expect("re-faked artifact passes structural + integrity verification");
    // ...but the restore's post-restore consistency check rejects the inconsistent graph.
    let err = match restore(&artifact, fresh_wal(), 64) {
        Ok(_) => panic!("restore must reject an internally-inconsistent image"),
        Err(e) => e.to_string(),
    };
    assert!(
        err.contains("integrity check failed"),
        "restore must reject via the consistency checker (not a structural error); got: {err}"
    );
}

// ---- helpers for the inconsistency test (locate a record's bytes inside the artifact) ----

const ARTIFACT_HEADER_LEN: usize = 8 + 4 + 4 + 16 + 8;
const PAGE_ENTRY_LEN: usize = 8 + PAGE_SIZE;

/// Scans every framed page of `artifact` for the `record_size`-byte record whose 16-byte element id
/// (which immediately follows the 25-byte MVCC header) equals `element_id`, returning
/// `(page_body_start, in_page_offset)`. Element ids are unique across all stores, so the match is
/// unambiguous (mirrors the locator in `tests/consistency.rs`).
fn locate_record(artifact: &[u8], element_id: u128, record_size: usize) -> (usize, usize) {
    use graphus_storage::MVCC_HEADER_SIZE;
    let page_count = u64::from_le_bytes(artifact[32..40].try_into().unwrap()) as usize;
    let rpp = (PAGE_SIZE - page::HEADER_SIZE) / record_size;
    for i in 0..page_count {
        let entry = ARTIFACT_HEADER_LEN + i * PAGE_ENTRY_LEN;
        let page_body_start = entry + 8;
        for slot in 0..rpp {
            let off = page::HEADER_SIZE + slot * record_size;
            let eid_off = page_body_start + off + MVCC_HEADER_SIZE;
            let eid = u128::from_le_bytes(artifact[eid_off..eid_off + 16].try_into().unwrap());
            if eid == element_id {
                return (page_body_start, off);
            }
        }
    }
    panic!("record with element id {element_id} not found in artifact");
}

/// Recomputes the CRC32C of the page whose body starts at `page_body_start` in `artifact`.
fn refresh_page_checksum(artifact: &mut [u8], page_body_start: usize) {
    let page: &mut Page = (&mut artifact[page_body_start..page_body_start + PAGE_SIZE])
        .try_into()
        .unwrap();
    page::write_checksum(page);
}

/// Recomputes the whole-payload CRC32C trailer of `artifact`.
fn refresh_artifact_digest(artifact: &mut [u8]) {
    let digest_at = artifact.len() - 4;
    let digest = crc32c::crc32c(&artifact[..digest_at]);
    artifact[digest_at..].copy_from_slice(&digest.to_le_bytes());
}

/// Byte span of the MVCC header + element id that precede `first_rel` in a node record (`04 §2.3`).
fn mvcc_plus_eid() -> usize {
    use graphus_storage::MVCC_HEADER_SIZE;
    MVCC_HEADER_SIZE + 16
}

// Keep `restore_onto` exercised directly (the device-agnostic primitive) so its path is covered.
#[test]
fn restore_onto_a_caller_device_matches_restore() {
    let mut original = build_graph(5, 90);
    let artifact = backup_store(&mut original).expect("backup");

    // Restore via the high-level path.
    let mut via_restore = restore(&artifact, fresh_wal(), 64).expect("restore");
    let expected = snapshot(&mut via_restore);

    // Restore onto a caller-provided device, then open + check manually.
    let mut device = MemBlockDevice::new(0);
    restore_onto(&artifact, &mut device).expect("restore_onto");
    let mut manual = RecordStore::open(device, fresh_wal(), 64).expect("open");
    verify_on_open(&mut manual, &[]).expect("manual restore is consistent");
    let got = snapshot(&mut manual);

    assert_eq!(expected, got, "restore_onto + open must match restore");
}

/// Proves the **file-backed** restore path empirically (not just the in-memory DST device): the
/// device-agnostic [`restore_onto`] primitive restores onto a real [`FileBlockDevice`], which is
/// then reopened from disk, opened as a store, and asserted equal to the in-memory restore.
#[test]
fn restore_onto_a_file_device_round_trips() {
    use graphus_io::FileBlockDevice;
    use std::sync::atomic::{AtomicU64, Ordering};

    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let path = std::env::temp_dir().join(format!("graphus-backup-{}-{n}.blk", std::process::id()));

    let mut original = build_graph(9, 90);
    let artifact = backup_store(&mut original).expect("backup");
    let mut via_restore = restore(&artifact, fresh_wal(), 64).expect("restore");
    let expected = snapshot(&mut via_restore);

    // Restore onto a file device, drop it (closing the file), then reopen from disk.
    {
        let mut file_dev = FileBlockDevice::open(&path).expect("open file device");
        restore_onto(&artifact, &mut file_dev).expect("restore_onto file");
    }
    let file_dev = FileBlockDevice::open(&path).expect("reopen file device");
    let mut from_file = RecordStore::open(file_dev, fresh_wal(), 64).expect("open store from file");
    verify_on_open(&mut from_file, &[]).expect("file-restored store is consistent");
    let got = snapshot(&mut from_file);

    assert_eq!(
        expected, got,
        "file-backed restore must match in-memory restore"
    );
    std::fs::remove_file(&path).ok();
}
