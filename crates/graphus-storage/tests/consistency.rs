//! Integration tests for the consistency checker + startup integrity hook (`rmp` task #24:
//! "Checker passes on healthy stores and flags injected corruption; runs at startup before
//! serving"; serves `CLAUDE.md`'s inviolable *never corrupt* mandate, `04-technical-design.md`
//! §4.6).
//!
//! The suite has two halves:
//!
//! * **Healthy stores pass (no false positives).** Stores built with nodes, relationships
//!   (including parallel edges and self-loops), properties, and deletes — across many deterministic
//!   `graphus_sim::SimRng` seeds — are reported with **zero** violations. A store reopened after a
//!   crash+recovery also passes.
//! * **Injected corruption is flagged (the checker has teeth).** One focused test per violation
//!   class deliberately corrupts the on-disk image, then asserts that the checker reports exactly
//!   the matching [`Violation`] — and, crucially, that the *uncorrupted* image first passes, so each
//!   test proves both specificity and the absence of false positives.
//!
//! ## How corruption is injected
//!
//! A store is built and flushed, then its on-disk image is snapshotted into a fresh
//! [`MemBlockDevice`] (in `mapped_pages` order) alongside its durable WAL. A [`DiskImage`] helper
//! then mutates the raw bytes of a chosen record or page, recomputing the page checksum **unless the
//! test is specifically corrupting the checksum**. Reopening a [`RecordStore`] over the mutated
//! device and running [`check_store`]/[`verify_on_open`] exercises the exact startup path.

use std::collections::BTreeSet;

use graphus_bufpool::page;
use graphus_core::capability::Rng;
use graphus_core::{PageId, Timestamp, TxnId, Value, VersionStamp};
use graphus_io::{BlockDevice, MemBlockDevice, PAGE_SIZE, Page};
use graphus_sim::SimRng;
use graphus_storage::record::{
    ChainSide, NODE_RECORD_SIZE, NodeRecord, PropRecord, REL_RECORD_SIZE, RelRecord,
};
use graphus_storage::store::StoreKind;
use graphus_storage::{
    AgreementFault, ConsistencyReport, IndexAgreement, IndexEntry, Namespace, RecordStore,
    Violation, check::AdjacencyFault, check::FreeListFault, check::HeapChainFault,
    check::LabelBitmapFault, check::MvccHeaderFault, check::PropertyFault, recovery,
    verify_on_open,
};
use graphus_wal::{LogSink, MemLogSink, WalManager};

type Store = RecordStore<MemBlockDevice, MemLogSink>;

/// Builds a fresh store over an in-memory device + log.
fn fresh(cap: usize) -> Store {
    let device = MemBlockDevice::new(0);
    let wal = WalManager::create(MemLogSink::new()).expect("create wal");
    RecordStore::create(device, wal, cap, 1).expect("create store")
}

/// The full consistency report for `store` with no indexes (store-only checks).
fn report(store: &mut Store) -> ConsistencyReport {
    graphus_storage::check::check_store(store, &[]).expect("checker runs")
}

/// Runs an MVCC GC pass under `txn`, physically reclaiming every tombstone visible to no live
/// snapshot (`rmp` task #45). Deletes are MVCC tombstones now — a deleted record stays in use until
/// GC frees its id and clears it — so a test that needs the *freed / dead* end state runs this after
/// the deleting transaction has committed (watermark = latest commit; no older live reader here).
fn gc_pass(store: &mut Store, txn: TxnId) {
    let watermark = store.snapshot_ts();
    store.begin(txn);
    store.gc(txn, watermark).expect("gc runs");
    store.commit(txn).expect("gc commits");
}

// ============================================================================================
// A captured, mutable on-disk image + WAL — the corruption harness.
// ============================================================================================

/// A snapshot of a flushed store's on-disk pages (in `mapped_pages` order) and its durable WAL,
/// so a test can mutate the raw bytes and then reopen + check.
struct DiskImage {
    pages: Vec<(u64, Box<Page>)>,
    log: Vec<u8>,
}

impl DiskImage {
    /// Captures `store` after flushing it (pages written home).
    fn capture(store: &mut Store) -> Self {
        store.flush().expect("flush");
        let mut pages = Vec::new();
        for p in store.mapped_pages() {
            pages.push((p.0, store.read_device_page(p).expect("read page")));
        }
        let log = store.with_wal(|w| w.sink().durable_bytes().to_vec());
        Self { pages, log }
    }

    /// Materialises the image into a device + WAL and recovers it (matching the real startup path),
    /// then opens a [`RecordStore`] over it.
    fn open(&self) -> Store {
        let max = self.pages.iter().map(|(i, _)| *i).max().unwrap_or(0);
        let mut device = MemBlockDevice::new(max + 1);
        for (idx, bytes) in &self.pages {
            device.write_page(PageId(*idx), bytes).expect("stage page");
        }
        device.sync_all().expect("persist");

        let mut sink = MemLogSink::new();
        sink.append(&self.log);
        sink.sync().expect("sync log");
        let mut wal = WalManager::open(sink.clone()).expect("open wal");
        recovery::recover_device(&mut wal, &mut device).expect("recover");
        let wal = WalManager::open(sink).expect("reopen wal");
        RecordStore::open(device, wal, 64).expect("open store")
    }

    /// The mutable bytes of the page stored at device id `page_id`.
    fn page_mut(&mut self, page_id: u64) -> &mut Page {
        let entry = self
            .pages
            .iter_mut()
            .find(|(i, _)| *i == page_id)
            .expect("page in image");
        &mut entry.1
    }

    /// Recomputes and stores the CRC32C of the page at `page_id` (call after a mutation that should
    /// keep the page valid, so a *non*-checksum violation is what surfaces).
    fn refresh_checksum(&mut self, page_id: u64) {
        page::write_checksum(self.page_mut(page_id));
    }

    /// Locates the `(device_page_id, byte_offset)` of record `id` of `kind`, identified by matching
    /// the `element_id` captured at creation (element ids are unique across all three stores, so the
    /// match is unambiguous). Returns the page id and the in-page offset of the record.
    fn locate(&self, kind: StoreKind, element_id: u128) -> (u64, usize) {
        let size = kind.record_size();
        let rpp = (PAGE_SIZE - page::HEADER_SIZE) / size;
        for (pid, bytes) in &self.pages {
            // Only record pages (type 1) hold records; the meta page (type 5) is skipped.
            if page::page_type(bytes) != 1 {
                continue;
            }
            for slot in 0..rpp {
                let off = page::HEADER_SIZE + slot * size;
                if off + size > PAGE_SIZE {
                    break;
                }
                let eid = decode_element_id(kind, &bytes[off..off + size]);
                if eid == element_id {
                    return (*pid, off);
                }
            }
        }
        panic!("record with element_id {element_id} not found in the image");
    }

    /// Reads record `id`'s bytes for `kind` at the located slot.
    fn read_rel_at(&self, page_id: u64, off: usize) -> RelRecord {
        let bytes = &self.pages.iter().find(|(i, _)| *i == page_id).unwrap().1;
        RelRecord::decode(&bytes[off..off + StoreKind::Rel.record_size()])
    }

    fn read_node_at(&self, page_id: u64, off: usize) -> NodeRecord {
        let bytes = &self.pages.iter().find(|(i, _)| *i == page_id).unwrap().1;
        NodeRecord::decode(&bytes[off..off + StoreKind::Node.record_size()])
    }

    /// Overwrites a relationship record at `(page_id, off)` and refreshes the checksum.
    fn write_rel_at(&mut self, page_id: u64, off: usize, rel: &RelRecord) {
        let mut buf = [0u8; REL_RECORD_SIZE];
        rel.encode(&mut buf);
        self.page_mut(page_id)[off..off + buf.len()].copy_from_slice(&buf);
        self.refresh_checksum(page_id);
    }

    /// Overwrites a node record at `(page_id, off)` and refreshes the checksum.
    fn write_node_at(&mut self, page_id: u64, off: usize, node: &NodeRecord) {
        let mut buf = [0u8; NODE_RECORD_SIZE];
        node.encode(&mut buf);
        self.page_mut(page_id)[off..off + buf.len()].copy_from_slice(&buf);
        self.refresh_checksum(page_id);
    }

    /// Reads a property record at `(page_id, off)`.
    fn read_prop_at(&self, page_id: u64, off: usize) -> PropRecord {
        let bytes = &self.pages.iter().find(|(i, _)| *i == page_id).unwrap().1;
        PropRecord::decode(&bytes[off..off + StoreKind::Prop.record_size()])
    }

    /// Overwrites a property record at `(page_id, off)` and refreshes the checksum.
    fn write_prop_at(&mut self, page_id: u64, off: usize, prop: &PropRecord) {
        let size = StoreKind::Prop.record_size();
        let mut buf = vec![0u8; size];
        prop.encode(&mut buf);
        self.page_mut(page_id)[off..off + size].copy_from_slice(&buf);
        self.refresh_checksum(page_id);
    }

    /// Locates the **single** in-use property record in the image (the corruption tests build exactly
    /// one), returning its `(device_page_id, byte_offset)`. Property records have no element id, so
    /// they are found by scanning record pages for an in-use property slot.
    fn locate_only_prop(&self) -> (u64, usize) {
        let size = StoreKind::Prop.record_size();
        let rpp = (PAGE_SIZE - page::HEADER_SIZE) / size;
        for (pid, bytes) in &self.pages {
            if page::page_type(bytes) != 1 {
                continue;
            }
            for slot in 0..rpp {
                let off = page::HEADER_SIZE + slot * size;
                if off + size > PAGE_SIZE {
                    break;
                }
                let prop = PropRecord::decode(&bytes[off..off + size]);
                // A property record is distinguished from node/rel pages only by being on the prop
                // store's pages; the corruption tests place exactly one in-use prop, and node/rel
                // records on other pages will not coincidentally decode as an in-use prop *with* the
                // overflow tag we look for, so match the overflow flag to disambiguate.
                if prop.mvcc.in_use() && prop.type_tag & graphus_storage::PROP_OVERFLOW_BIT != 0 {
                    return (*pid, off);
                }
            }
        }
        panic!("no in-use overflow property record found in the image");
    }

    /// Locates **every** in-use overflow property record `(device_page_id, byte_offset)` in the image,
    /// in page/slot order. Used by the heap-aliasing test, which needs two distinct overflow chains.
    fn locate_overflow_props(&self) -> Vec<(u64, usize)> {
        let size = StoreKind::Prop.record_size();
        let rpp = (PAGE_SIZE - page::HEADER_SIZE) / size;
        let mut out = Vec::new();
        for (pid, bytes) in &self.pages {
            if page::page_type(bytes) != 1 {
                continue;
            }
            for slot in 0..rpp {
                let off = page::HEADER_SIZE + slot * size;
                if off + size > PAGE_SIZE {
                    break;
                }
                let prop = PropRecord::decode(&bytes[off..off + size]);
                if prop.mvcc.in_use() && prop.type_tag & graphus_storage::PROP_OVERFLOW_BIT != 0 {
                    out.push((*pid, off));
                }
            }
        }
        out
    }

    /// Locates an in-use `strings.store` heap block whose payload is filled with `fill`, returning
    /// `(device_page_id, byte_offset)`. A multi-block `String` value of a single repeated byte fills
    /// its blocks' 48-byte payloads with that byte, which disambiguates a real heap block from any
    /// node/rel record that happens to live on another page (those never carry 48 bytes of `fill`).
    fn locate_value_block(&self, fill: u8) -> (u64, usize) {
        let size = StoreKind::Strings.record_size();
        let rpp = (PAGE_SIZE - page::HEADER_SIZE) / size;
        for (pid, bytes) in &self.pages {
            if page::page_type(bytes) != 1 {
                continue;
            }
            for slot in 0..rpp {
                let off = page::HEADER_SIZE + slot * size;
                if off + size > PAGE_SIZE {
                    break;
                }
                let block = graphus_storage::HeapBlock::decode(&bytes[off..off + size]);
                if block.mvcc.in_use()
                    && block.bytes().iter().all(|&b| b == fill)
                    && !block.bytes().is_empty()
                {
                    return (*pid, off);
                }
            }
        }
        panic!("no in-use heap block filled with {fill:#x} found in the image");
    }
}

/// Decodes just the `element_id` field of a record slice for the given kind (used to locate a record
/// in a raw page image).
fn decode_element_id(kind: StoreKind, bytes: &[u8]) -> u128 {
    match kind {
        StoreKind::Node => NodeRecord::decode(bytes).element_id.0,
        StoreKind::Rel => RelRecord::decode(bytes).element_id.0,
        // Property and heap-block records have no element id; never located by element id.
        StoreKind::Prop => PropRecord::decode(bytes).mvcc.created_ts as u128,
        StoreKind::Strings => u128::from(graphus_storage::HeapBlock::decode(bytes).mvcc.created_ts),
    }
}

// ============================================================================================
// Healthy stores pass (no false positives).
// ============================================================================================

#[test]
fn empty_store_passes() {
    let mut s = fresh(64);
    assert!(report(&mut s).is_consistent());
    verify_on_open(&mut s, &[]).expect("empty store serves");
}

#[test]
fn simple_graph_passes() {
    let mut s = fresh(64);
    let txn = TxnId(1);
    s.begin(txn);
    let (a, _) = s.create_node(txn).unwrap();
    let (b, _) = s.create_node(txn).unwrap();
    let (c, _) = s.create_node(txn).unwrap();
    let t = s.intern_token(Namespace::RelType, "KNOWS").unwrap();
    s.create_rel(txn, t, a, b).unwrap();
    s.create_rel(txn, t, a, b).unwrap(); // parallel
    s.create_rel(txn, t, c, c).unwrap(); // self-loop
    let key = s.intern_token(Namespace::PropKey, "name").unwrap();
    s.add_node_property(txn, a, key, 4, 0xABCD).unwrap();
    s.add_node_property(txn, a, key, 4, 0x1234).unwrap();
    s.commit(txn).unwrap();

    let r = report(&mut s);
    assert!(r.is_consistent(), "healthy graph: {:?}", r.violations);
    assert_eq!(r.live_nodes, 3);
    assert_eq!(r.live_rels, 3);
    assert_eq!(r.live_props, 2);
}

/// A long random CRUD history (nodes, parallel edges, self-loops, deletions) must leave the store
/// consistent at the end, across many seeds — the no-false-positives backbone, reusing the
/// `adjacency_props.rs` generator shape.
#[test]
fn random_histories_stay_consistent() {
    for seed in 1..=40u64 {
        let mut s = fresh(32);
        let txn = TxnId(1);
        s.begin(txn);
        let rt = s.intern_token(Namespace::RelType, "E").unwrap();
        let pk = s.intern_token(Namespace::PropKey, "p").unwrap();

        let mut rng = SimRng::new(seed);
        let mut nodes: Vec<u64> = Vec::new();
        let mut alive_rels: Vec<u64> = Vec::new();

        for _ in 0..150 {
            let choice = rng.next_u64() % 100;
            if nodes.len() < 2 || choice < 25 {
                let (id, _) = s.create_node(txn).unwrap();
                nodes.push(id);
            } else if choice < 70 {
                let a = nodes[(rng.next_u64() as usize) % nodes.len()];
                let b = nodes[(rng.next_u64() as usize) % nodes.len()];
                let (rid, _) = s.create_rel(txn, rt, a, b).unwrap();
                alive_rels.push(rid);
            } else if choice < 85 {
                let a = nodes[(rng.next_u64() as usize) % nodes.len()];
                s.add_node_property(txn, a, pk, 2, rng.next_u64()).unwrap();
            } else if !alive_rels.is_empty() {
                let i = (rng.next_u64() as usize) % alive_rels.len();
                let rid = alive_rels.swap_remove(i);
                s.delete_rel(txn, rid).unwrap();
            }
        }
        s.commit(txn).unwrap();

        let r = report(&mut s);
        assert!(
            r.is_consistent(),
            "seed={seed}: healthy store flagged: {:?}",
            r.violations
        );
        // Reopen after crash+recovery and re-check: a recovered store must also be consistent.
        let img = DiskImage::capture(&mut s);
        let mut reopened = img.open();
        let r2 = report(&mut reopened);
        assert!(
            r2.is_consistent(),
            "seed={seed}: recovered store flagged: {:?}",
            r2.violations
        );
        verify_on_open(&mut reopened, &[]).expect("recovered store serves");
    }
}

#[test]
fn store_with_deleted_records_passes() {
    let mut s = fresh(64);
    let txn = TxnId(1);
    s.begin(txn);
    let (a, _) = s.create_node(txn).unwrap();
    let (b, _) = s.create_node(txn).unwrap();
    let (c, _) = s.create_node(txn).unwrap();
    let t = s.intern_token(Namespace::RelType, "E").unwrap();
    let r1 = s.create_rel(txn, t, a, b).unwrap().0;
    s.create_rel(txn, t, a, c).unwrap();
    s.delete_rel(txn, r1).unwrap(); // free a rel id
    s.delete_node(txn, b).unwrap(); // free a node id
    s.commit(txn).unwrap();

    let r = report(&mut s);
    assert!(r.is_consistent(), "with deletes: {:?}", r.violations);
}

// ============================================================================================
// Injected corruption is flagged — one focused test per class (with no-false-positive structure).
// ============================================================================================

/// (a) Checksum: flip a byte in a record page → exactly a checksum violation, and `verify_on_open`
/// refuses to serve.
#[test]
fn corrupt_checksum_is_flagged() {
    let mut s = fresh(64);
    let txn = TxnId(1);
    s.begin(txn);
    let (a, eid_a) = s.create_node(txn).unwrap();
    let (b, _) = s.create_node(txn).unwrap();
    let t = s.intern_token(Namespace::RelType, "E").unwrap();
    s.create_rel(txn, t, a, b).unwrap();
    s.commit(txn).unwrap();

    let mut img = DiskImage::capture(&mut s);
    // First: the uncorrupted image passes (proves we are not flagging a healthy store).
    {
        let mut clean = img.open();
        assert!(report(&mut clean).is_consistent());
    }

    // Corrupt: flip a body byte in node a's page, WITHOUT refreshing the checksum.
    let (page_id, off) = img.locate(StoreKind::Node, eid_a.0);
    img.page_mut(page_id)[off + 30] ^= 0xFF; // a body byte inside the record region

    let mut store = img.open();
    let r = report(&mut store);
    assert!(
        r.violations
            .iter()
            .any(|v| matches!(v, Violation::Checksum { page } if *page == page_id)),
        "expected a Checksum violation on page {page_id}: {:?}",
        r.violations
    );
    assert!(
        verify_on_open(&mut store, &[]).is_err(),
        "must refuse to serve"
    );
}

/// (b) Adjacency: break an incidence-chain pointer (dangling next) → an adjacency violation.
#[test]
fn corrupt_adjacency_dangling_link_is_flagged() {
    let mut s = fresh(64);
    let txn = TxnId(1);
    s.begin(txn);
    let (a, _) = s.create_node(txn).unwrap();
    let (b, _) = s.create_node(txn).unwrap();
    let t = s.intern_token(Namespace::RelType, "E").unwrap();
    let (_r1, eid_r1) = s.create_rel(txn, t, a, b).unwrap();
    let (_r2, _) = s.create_rel(txn, t, a, b).unwrap();
    s.commit(txn).unwrap();

    let mut img = DiskImage::capture(&mut s);
    {
        let mut clean = img.open();
        assert!(report(&mut clean).is_consistent());
    }

    // Point r1's start-side next at a non-existent relationship id (dangling).
    let (page_id, off) = img.locate(StoreKind::Rel, eid_r1.0);
    let mut rel = img.read_rel_at(page_id, off);
    rel.start_next_rel = 9_999; // out of range -> dangling
    img.write_rel_at(page_id, off, &rel);

    let mut store = img.open();
    let r = report(&mut store);
    assert!(
        r.violations
            .iter()
            .any(|v| matches!(v, Violation::Adjacency { .. })),
        "expected an Adjacency violation: {:?}",
        r.violations
    );
    assert!(verify_on_open(&mut store, &[]).is_err());
}

/// (b') Adjacency: make a link asymmetric (a `next` whose successor's `prev` no longer points back)
/// → an `AsymmetricLink` adjacency violation.
#[test]
fn corrupt_adjacency_asymmetric_link_is_flagged() {
    let mut s = fresh(64);
    let txn = TxnId(1);
    s.begin(txn);
    let (a, _) = s.create_node(txn).unwrap();
    let (b, _) = s.create_node(txn).unwrap();
    let t = s.intern_token(Namespace::RelType, "E").unwrap();
    // Two parallel edges: a's chain is r2(head) -> r1(tail). Break r1's back-link.
    let (_r1, eid_r1) = s.create_rel(txn, t, a, b).unwrap();
    s.create_rel(txn, t, a, b).unwrap();
    s.commit(txn).unwrap();

    let mut img = DiskImage::capture(&mut s);
    let (page_id, off) = img.locate(StoreKind::Rel, eid_r1.0);
    let mut rel = img.read_rel_at(page_id, off);
    // r1 is the tail; its start_prev_rel points at r2. Corrupt it to a bogus id so r2.next (=r1)
    // still points at r1 but r1.prev no longer points back at r2 -> asymmetric.
    rel.start_prev_rel = 7_777;
    img.write_rel_at(page_id, off, &rel);

    let mut store = img.open();
    let r = report(&mut store);
    assert!(
        r.violations.iter().any(|v| matches!(
            v,
            Violation::Adjacency {
                detail: AdjacencyFault::AsymmetricLink | AdjacencyFault::RelOutOfRange,
                ..
            }
        )),
        "expected an asymmetric/out-of-range adjacency violation: {:?}",
        r.violations
    );
}

/// (c) Referential: point a relationship endpoint at a freed/non-existent node → a referential
/// violation.
#[test]
fn corrupt_referential_endpoint_is_flagged() {
    let mut s = fresh(64);
    let txn = TxnId(1);
    s.begin(txn);
    let (a, _) = s.create_node(txn).unwrap();
    let (b, _) = s.create_node(txn).unwrap();
    let t = s.intern_token(Namespace::RelType, "E").unwrap();
    let (_r, eid_r) = s.create_rel(txn, t, a, b).unwrap();
    s.commit(txn).unwrap();

    let mut img = DiskImage::capture(&mut s);
    {
        let mut clean = img.open();
        assert!(report(&mut clean).is_consistent());
    }

    // Repoint the relationship's end_node at a non-existent node id, leaving the chain otherwise as
    // the checker re-derives it from endpoints -> referential fault on the end side.
    let (page_id, off) = img.locate(StoreKind::Rel, eid_r.0);
    let mut rel = img.read_rel_at(page_id, off);
    rel.end_node = 4_242; // no such node
    img.write_rel_at(page_id, off, &rel);

    let mut store = img.open();
    let r = report(&mut store);
    assert!(
        r.violations.iter().any(|v| matches!(
            v,
            Violation::Referential { node, side: ChainSide::End, .. } if *node == 4_242
        )),
        "expected a Referential violation for node 4242: {:?}",
        r.violations
    );
    assert!(verify_on_open(&mut store, &[]).is_err());
}

/// (d) Property chain: make a node's property chain reference a dead/missing record → a
/// property-chain violation.
#[test]
fn corrupt_property_chain_is_flagged() {
    let mut s = fresh(64);
    let txn = TxnId(1);
    s.begin(txn);
    let (a, eid_a) = s.create_node(txn).unwrap();
    let key = s.intern_token(Namespace::PropKey, "name").unwrap();
    s.add_node_property(txn, a, key, 4, 1).unwrap();
    s.commit(txn).unwrap();

    let mut img = DiskImage::capture(&mut s);
    {
        let mut clean = img.open();
        assert!(report(&mut clean).is_consistent());
    }

    // Point node a's first_prop at a non-existent property id.
    let (page_id, off) = img.locate(StoreKind::Node, eid_a.0);
    let mut node = img.read_node_at(page_id, off);
    node.first_prop = 5_000; // out of range
    img.write_node_at(page_id, off, &node);

    let mut store = img.open();
    let r = report(&mut store);
    assert!(
        r.violations.iter().any(|v| matches!(
            v,
            Violation::PropertyChain {
                detail: PropertyFault::PropOutOfRange | PropertyFault::DeadProp,
                ..
            }
        )),
        "expected a PropertyChain violation: {:?}",
        r.violations
    );
    assert!(verify_on_open(&mut store, &[]).is_err());
}

/// (d2) Overflow heap chain: make an overflow property's `value_inline` (chain head) point at a
/// non-existent heap block → a [`Violation::HeapChain`] (`rmp` task #43). Proves the checker has
/// teeth on dangling overflow chains, and that the uncorrupted image first passes.
#[test]
fn dangling_overflow_chain_is_flagged() {
    let mut s = fresh(64);
    let txn = TxnId(1);
    s.begin(txn);
    let (n, _) = s.create_node(txn).unwrap();
    let key = s.intern_token(Namespace::PropKey, "bio").unwrap();
    // A multi-block String value, so the property record holds an overflow chain head.
    s.set_node_property_value(txn, n, key, &Value::String("z".repeat(200)))
        .unwrap();
    s.commit(txn).unwrap();

    let mut img = DiskImage::capture(&mut s);
    {
        // The uncorrupted image is healthy.
        let mut clean = img.open();
        assert!(
            report(&mut clean).is_consistent(),
            "clean overflow store passes"
        );
    }

    // Point the overflow property's chain head at a non-existent (out-of-range) block id.
    let (page_id, off) = img.locate_only_prop();
    let mut prop = img.read_prop_at(page_id, off);
    prop.value_inline = 9_999; // far past the heap high-water
    img.write_prop_at(page_id, off, &prop);

    let mut store = img.open();
    let r = report(&mut store);
    assert!(
        r.violations.iter().any(|v| matches!(
            v,
            Violation::HeapChain {
                detail: HeapChainFault::BlockOutOfRange | HeapChainFault::DeadBlock,
                ..
            }
        )),
        "expected a HeapChain violation for the dangling chain: {:?}",
        r.violations
    );
    assert!(verify_on_open(&mut store, &[]).is_err());
}

// ============================================================================================
// MVCC-header integrity (storage audit F8) — the version-visibility metadata graphus-txn reads.
// ============================================================================================

/// A live record whose MVCC stamps invert (created at a *later* committed timestamp than it expired)
/// is flagged — a tombstone that "expired before it was created" would feed visibility nonsense.
#[test]
fn mvcc_timestamp_inversion_is_flagged() {
    let mut s = fresh(64);
    let txn = TxnId(1);
    s.begin(txn);
    let (_n, eid) = s.create_node(txn).unwrap();
    s.commit(txn).unwrap();

    let mut img = DiskImage::capture(&mut s);
    {
        let mut clean = img.open();
        assert!(report(&mut clean).is_consistent(), "clean store passes");
    }
    let (page_id, off) = img.locate(StoreKind::Node, eid.0);
    let mut node = img.read_node_at(page_id, off);
    // created (xmin) > expired (xmax), both committed timestamps.
    node.mvcc.created_ts = VersionStamp::committed(Timestamp(100));
    node.mvcc.expired_ts = VersionStamp::committed(Timestamp(50));
    img.write_node_at(page_id, off, &node);

    let mut store = img.open();
    let r = report(&mut store);
    assert!(
        r.violations.iter().any(|v| matches!(
            v,
            Violation::MvccHeader {
                detail: MvccHeaderFault::TimestampInversion { .. },
                ..
            }
        )),
        "expected a timestamp-inversion violation: {:?}",
        r.violations
    );
    assert!(verify_on_open(&mut store, &[]).is_err());
}

/// A live record whose `undo_ptr` (older-version back-pointer) dangles past its store's high-water
/// is flagged — a corrupt version-chain pointer (and the future unbounded-loop hazard).
#[test]
fn mvcc_dangling_undo_ptr_is_flagged() {
    let mut s = fresh(64);
    let txn = TxnId(1);
    s.begin(txn);
    let (_n, eid) = s.create_node(txn).unwrap();
    s.commit(txn).unwrap();

    let mut img = DiskImage::capture(&mut s);
    let (page_id, off) = img.locate(StoreKind::Node, eid.0);
    let mut node = img.read_node_at(page_id, off);
    node.mvcc.undo_ptr = 9_999; // far past the node store's high-water
    img.write_node_at(page_id, off, &node);

    let mut store = img.open();
    let r = report(&mut store);
    assert!(
        r.violations.iter().any(|v| matches!(
            v,
            Violation::MvccHeader {
                detail: MvccHeaderFault::UndoPtrOutOfRange { undo_ptr: 9_999 },
                ..
            }
        )),
        "expected a dangling-undo_ptr violation: {:?}",
        r.violations
    );
    assert!(verify_on_open(&mut store, &[]).is_err());
}

/// A live record with no creator stamp (`created_ts`/`xmin` zeroed) is flagged — every version must
/// record who created it.
#[test]
fn mvcc_missing_creator_is_flagged() {
    let mut s = fresh(64);
    let txn = TxnId(1);
    s.begin(txn);
    let (_n, eid) = s.create_node(txn).unwrap();
    s.commit(txn).unwrap();

    let mut img = DiskImage::capture(&mut s);
    let (page_id, off) = img.locate(StoreKind::Node, eid.0);
    let mut node = img.read_node_at(page_id, off);
    node.mvcc.created_ts = 0; // the "none" sentinel — invalid on a live record
    img.write_node_at(page_id, off, &node);

    let mut store = img.open();
    let r = report(&mut store);
    assert!(
        r.violations.iter().any(|v| matches!(
            v,
            Violation::MvccHeader {
                detail: MvccHeaderFault::NoCreator,
                ..
            }
        )),
        "expected a missing-creator violation: {:?}",
        r.violations
    );
    assert!(verify_on_open(&mut store, &[]).is_err());
}

// ============================================================================================
// Overflow-heap aliasing + block-length (storage audit F13).
// ============================================================================================

/// A heap block reachable from TWO distinct overflow chains is flagged — its payload would be shared
/// between two property values (silent data corruption the per-chain walk alone could not see).
#[test]
fn heap_block_aliased_by_two_chains_is_flagged() {
    let mut s = fresh(64);
    let txn = TxnId(1);
    s.begin(txn);
    let (n1, _) = s.create_node(txn).unwrap();
    let (n2, _) = s.create_node(txn).unwrap();
    let key = s.intern_token(Namespace::PropKey, "bio").unwrap();
    s.set_node_property_value(txn, n1, key, &Value::String("a".repeat(200)))
        .unwrap();
    s.set_node_property_value(txn, n2, key, &Value::String("b".repeat(200)))
        .unwrap();
    s.commit(txn).unwrap();

    let mut img = DiskImage::capture(&mut s);
    {
        let mut clean = img.open();
        assert!(
            report(&mut clean).is_consistent(),
            "clean two-chain store passes"
        );
    }
    // Point the second overflow chain's head at the first chain's head block (alias).
    let props = img.locate_overflow_props();
    assert_eq!(props.len(), 2, "two overflow properties were created");
    let head1 = img.read_prop_at(props[0].0, props[0].1).value_inline;
    let mut p2 = img.read_prop_at(props[1].0, props[1].1);
    p2.value_inline = head1; // both chains now reference the same block
    img.write_prop_at(props[1].0, props[1].1, &p2);

    let mut store = img.open();
    let r = report(&mut store);
    assert!(
        r.violations.iter().any(|v| matches!(
            v,
            Violation::HeapChain {
                detail: HeapChainFault::SharedBlock { .. },
                ..
            }
        )),
        "expected a shared-block violation: {:?}",
        r.violations
    );
    assert!(verify_on_open(&mut store, &[]).is_err());
}

/// A heap block whose `len` exceeds [`BLOCK_PAYLOAD`] is flagged — a corrupt length `HeapBlock::bytes`
/// would otherwise clamp silently.
#[test]
fn heap_block_len_too_long_is_flagged() {
    let mut s = fresh(64);
    let txn = TxnId(1);
    s.begin(txn);
    let (n, _) = s.create_node(txn).unwrap();
    let key = s.intern_token(Namespace::PropKey, "bio").unwrap();
    s.set_node_property_value(txn, n, key, &Value::String("c".repeat(200)))
        .unwrap();
    s.commit(txn).unwrap();

    let mut img = DiskImage::capture(&mut s);
    let (page_id, off) = img.locate_value_block(b'c');
    // The `len` field sits at byte 33 within a block: MVCC header (25) + next_block (8). Corrupt it
    // to one past the 48-byte payload, then re-checksum so the *length* (not the CRC) is what fires.
    let len_off = off + 33;
    let bad = (graphus_storage::BLOCK_PAYLOAD as u16) + 1;
    img.page_mut(page_id)[len_off..len_off + 2].copy_from_slice(&bad.to_le_bytes());
    img.refresh_checksum(page_id);

    let mut store = img.open();
    let r = report(&mut store);
    assert!(
        r.violations.iter().any(|v| matches!(
            v,
            Violation::HeapChain {
                detail: HeapChainFault::BlockLenTooLong { .. },
                ..
            }
        )),
        "expected a block-len-too-long violation: {:?}",
        r.violations
    );
    assert!(verify_on_open(&mut store, &[]).is_err());
}

/// (d3) A healthy store whose **relationships carry properties** (inline scalar + a multi-block
/// `String` overflow value) passes with zero violations (`rmp` task #44). This is the no-false-
/// positive guard for the relationship-property path — the checker walks a relationship's chain over
/// [`RelRecord::first_prop`](graphus_storage::record::RelRecord) the same way it walks a node's.
#[test]
fn healthy_relationship_with_properties_passes() {
    let mut s = fresh(64);
    let txn = TxnId(1);
    s.begin(txn);
    let (a, _) = s.create_node(txn).unwrap();
    let (b, _) = s.create_node(txn).unwrap();
    let t = s.intern_token(Namespace::RelType, "KNOWS").unwrap();
    let r = s.create_rel(txn, t, a, b).unwrap().0;
    let k_i = s.intern_token(Namespace::PropKey, "since").unwrap();
    let k_s = s.intern_token(Namespace::PropKey, "note").unwrap();
    s.set_rel_property_value(txn, r, k_i, &Value::Integer(1999))
        .unwrap();
    s.set_rel_property_value(txn, r, k_s, &Value::String("z".repeat(200)))
        .unwrap();
    s.commit(txn).unwrap();

    assert!(
        report(&mut s).is_consistent(),
        "a relationship with inline + overflow properties is healthy: {:?}",
        report(&mut s).violations
    );
}

/// (d4) Relationship property chain: make a **relationship's** `first_prop` reference a dead/missing
/// property record → a [`Violation::PropertyChain`] whose owner is the relationship (`rmp` task #44).
/// The relationship analogue of [`corrupt_property_chain_is_flagged`]; proves the checker has teeth
/// on a relationship's property chain (rooted at
/// [`RelRecord::first_prop`](graphus_storage::record::RelRecord)), and that the uncorrupted image
/// first passes.
#[test]
fn corrupt_relationship_property_chain_is_flagged() {
    let mut s = fresh(64);
    let txn = TxnId(1);
    s.begin(txn);
    let (a, _) = s.create_node(txn).unwrap();
    let (b, _) = s.create_node(txn).unwrap();
    let t = s.intern_token(Namespace::RelType, "KNOWS").unwrap();
    let (r, eid_r) = s.create_rel(txn, t, a, b).unwrap();
    let k = s.intern_token(Namespace::PropKey, "since").unwrap();
    s.set_rel_property_value(txn, r, k, &Value::Integer(2002))
        .unwrap();
    s.commit(txn).unwrap();

    let mut img = DiskImage::capture(&mut s);
    {
        let mut clean = img.open();
        assert!(
            report(&mut clean).is_consistent(),
            "clean rel-prop store passes"
        );
    }

    // Point the relationship's first_prop at a non-existent property id (dangling chain head).
    let (page_id, off) = img.locate(StoreKind::Rel, eid_r.0);
    let mut rel = img.read_rel_at(page_id, off);
    rel.first_prop = 5_000; // far past the prop high-water -> out of range
    img.write_rel_at(page_id, off, &rel);

    let mut store = img.open();
    let r = report(&mut store);
    assert!(
        r.violations.iter().any(|v| matches!(
            v,
            Violation::PropertyChain {
                owner_kind: StoreKind::Rel,
                detail: PropertyFault::PropOutOfRange | PropertyFault::DeadProp,
                ..
            }
        )),
        "expected a relationship PropertyChain violation: {:?}",
        r.violations
    );
    assert!(verify_on_open(&mut store, &[]).is_err());
}

/// (d5) Dangling **overflow** chain on a *relationship* property: corrupt the relationship's overflow
/// property record's `value_inline` (its chain head) to point past the heap high-water → a
/// [`Violation::HeapChain`] (`rmp` task #44 + #43). Proves a relationship's overflow property is
/// validated identically to a node's (both live in the one `props.store` / `strings.store`).
#[test]
fn dangling_overflow_chain_on_a_rel_property_is_flagged() {
    let mut s = fresh(64);
    let txn = TxnId(1);
    s.begin(txn);
    let (a, _) = s.create_node(txn).unwrap();
    let (b, _) = s.create_node(txn).unwrap();
    let t = s.intern_token(Namespace::RelType, "KNOWS").unwrap();
    let r = s.create_rel(txn, t, a, b).unwrap().0;
    let key = s.intern_token(Namespace::PropKey, "bio").unwrap();
    // A multi-block String value, so the relationship's property record holds an overflow chain head.
    s.set_rel_property_value(txn, r, key, &Value::String("z".repeat(200)))
        .unwrap();
    s.commit(txn).unwrap();

    let mut img = DiskImage::capture(&mut s);
    {
        let mut clean = img.open();
        assert!(
            report(&mut clean).is_consistent(),
            "clean rel-overflow store passes"
        );
    }

    // The single in-use overflow property record is the relationship's; point its chain head past
    // the heap high-water (`locate_only_prop` matches the one in-use overflow property).
    let (page_id, off) = img.locate_only_prop();
    let mut prop = img.read_prop_at(page_id, off);
    prop.value_inline = 9_999;
    img.write_prop_at(page_id, off, &prop);

    let mut store = img.open();
    let r = report(&mut store);
    assert!(
        r.violations.iter().any(|v| matches!(
            v,
            Violation::HeapChain {
                detail: HeapChainFault::BlockOutOfRange | HeapChainFault::DeadBlock,
                ..
            }
        )),
        "expected a HeapChain violation for the dangling rel overflow chain: {:?}",
        r.violations
    );
    assert!(verify_on_open(&mut store, &[]).is_err());
}

/// (e) Store/index agreement: an index entry pointing at a record whose value no longer matches
/// (modelled as an entry absent from the expected set) and a missing expected entry.
#[test]
fn index_agreement_unexpected_and_missing_are_flagged() {
    let mut s = fresh(64);
    let txn = TxnId(1);
    s.begin(txn);
    let (a, _) = s.create_node(txn).unwrap();
    let (b, _) = s.create_node(txn).unwrap();
    let (c, _) = s.create_node(txn).unwrap();
    s.commit(txn).unwrap();

    // Healthy agreement: index contains {a, b}, expected {a, b} -> consistent.
    let ok = IndexAgreement {
        name: "label:Person".to_owned(),
        indexed_store: StoreKind::Node,
        entries: vec![IndexEntry::rid(a), IndexEntry::rid(b)],
        expected: Some([a, b].into_iter().collect::<BTreeSet<_>>()),
    };
    let r_ok = graphus_storage::check::check_store(&mut s, std::slice::from_ref(&ok)).unwrap();
    assert!(r_ok.is_consistent(), "healthy index: {:?}", r_ok.violations);

    // Stale entry (value no longer matches): index has {a, b} but expected {a, c}.
    // -> b is UnexpectedEntry (stale), c is MissingEntry.
    let bad = IndexAgreement {
        name: "label:Person".to_owned(),
        indexed_store: StoreKind::Node,
        entries: vec![IndexEntry::rid(a), IndexEntry::rid(b)],
        expected: Some([a, c].into_iter().collect::<BTreeSet<_>>()),
    };
    let r = graphus_storage::check::check_store(&mut s, std::slice::from_ref(&bad)).unwrap();
    assert!(
        r.violations.iter().any(|v| matches!(
            v,
            Violation::IndexAgreement { detail: AgreementFault::UnexpectedEntry { rid }, .. } if *rid == b
        )),
        "expected an UnexpectedEntry for b={b}: {:?}",
        r.violations
    );
    assert!(
        r.violations.iter().any(|v| matches!(
            v,
            Violation::IndexAgreement { detail: AgreementFault::MissingEntry { rid }, .. } if *rid == c
        )),
        "expected a MissingEntry for c={c}: {:?}",
        r.violations
    );
}

/// (e') Store/index agreement: an index entry pointing at a dead record → a DeadRecord agreement
/// violation, derived purely from the store (no expected set needed).
#[test]
fn index_agreement_dead_record_is_flagged() {
    let mut s = fresh(64);
    let txn = TxnId(1);
    s.begin(txn);
    let (a, _) = s.create_node(txn).unwrap();
    let (b, _) = s.create_node(txn).unwrap();
    s.commit(txn).unwrap();
    let txn2 = TxnId(2);
    s.begin(txn2);
    s.delete_node(txn2, b).unwrap(); // b is MVCC-tombstoned
    s.commit(txn2).unwrap();
    gc_pass(&mut s, TxnId(3)); // GC reclaims b -> dead/freed, so a stale index entry is now dangling

    let ix = IndexAgreement {
        name: "label:Stale".to_owned(),
        indexed_store: StoreKind::Node,
        entries: vec![IndexEntry::rid(a), IndexEntry::rid(b)], // b is dead
        expected: None,
    };
    let r = graphus_storage::check::check_store(&mut s, &[ix]).unwrap();
    assert!(
        r.violations.iter().any(|v| matches!(
            v,
            Violation::IndexAgreement { detail: AgreementFault::DeadRecord { rid }, .. } if *rid == b
        )),
        "expected a DeadRecord agreement violation for b={b}: {:?}",
        r.violations
    );
}

/// (f) Self-loop / parallel-edge corruption: break the internal link of a self-loop so its two
/// chain links are no longer consistent → an adjacency violation. Confirms the loop-specific path
/// has teeth.
#[test]
fn corrupt_self_loop_internal_link_is_flagged() {
    let mut s = fresh(64);
    let txn = TxnId(1);
    s.begin(txn);
    let (a, _) = s.create_node(txn).unwrap();
    let t = s.intern_token(Namespace::RelType, "SELF").unwrap();
    let (_r, eid_r) = s.create_rel(txn, t, a, a).unwrap(); // self-loop
    s.commit(txn).unwrap();

    let mut img = DiskImage::capture(&mut s);
    {
        let mut clean = img.open();
        assert!(
            report(&mut clean).is_consistent(),
            "healthy self-loop must pass"
        );
    }

    // A self-loop threads END (head) -> START. Corrupt the END side's next so it no longer points at
    // the loop's START link -> the loop's two links are inconsistent.
    let (page_id, off) = img.locate(StoreKind::Rel, eid_r.0);
    let mut rel = img.read_rel_at(page_id, off);
    rel.end_next_rel = 0; // breaks END -> START internal threading
    img.write_rel_at(page_id, off, &rel);

    let mut store = img.open();
    let r = report(&mut store);
    assert!(
        r.violations
            .iter()
            .any(|v| matches!(v, Violation::Adjacency { .. })),
        "expected an Adjacency violation on the corrupted self-loop: {:?}",
        r.violations
    );
}

/// (g) Free-list sanity: a freed id that is still in use (a live record sitting on the free list)
/// → a `StillInUse` free-list violation. We model this by re-marking a deleted record live on disk
/// while it remains on the recovered free list.
#[test]
fn corrupt_free_list_still_in_use_is_flagged() {
    let mut s = fresh(64);
    let txn = TxnId(1);
    s.begin(txn);
    let (a, _) = s.create_node(txn).unwrap();
    let (b, eid_b) = s.create_node(txn).unwrap();
    s.commit(txn).unwrap();
    let txn2 = TxnId(2);
    s.begin(txn2);
    s.delete_node(txn2, b).unwrap(); // b is MVCC-tombstoned
    s.commit(txn2).unwrap();
    gc_pass(&mut s, TxnId(3)); // GC reclaims b -> free list, record cleared (not in use)

    let mut img = DiskImage::capture(&mut s);
    {
        // Uncorrupted: b is freed and its record is not in use -> consistent.
        let mut clean = img.open();
        assert!(report(&mut clean).is_consistent());
    }

    // Corrupt: resurrect b's record to "in use" on disk while it stays on the free list.
    let (page_id, off) = img.locate(StoreKind::Node, eid_b.0);
    let mut node = img.read_node_at(page_id, off);
    node.mvcc = graphus_storage::MvccHeader::live(99);
    img.write_node_at(page_id, off, &node);

    let mut store = img.open();
    let r = report(&mut store);
    assert!(
        r.violations.iter().any(|v| matches!(
            v,
            Violation::FreeList { id, detail: FreeListFault::StillInUse, .. } if *id == b
        )),
        "expected a StillInUse free-list violation for b={b}: {:?}",
        r.violations
    );
    let _ = a;
}

/// (h) Termination on corruption: a deliberately cyclic incidence-chain pointer must be reported as
/// malformed and the checker must terminate (no infinite loop). A test timeout would otherwise hang;
/// reaching the assertion proves termination.
#[test]
fn cyclic_chain_terminates_and_is_reported() {
    let mut s = fresh(64);
    let txn = TxnId(1);
    s.begin(txn);
    let (a, _) = s.create_node(txn).unwrap();
    let (b, _) = s.create_node(txn).unwrap();
    let t = s.intern_token(Namespace::RelType, "E").unwrap();
    let (_r1, eid_r1) = s.create_rel(txn, t, a, b).unwrap();
    s.commit(txn).unwrap();

    let mut img = DiskImage::capture(&mut s);
    // Make r1's start-side next point back at itself -> a self-cycle in a's chain. r1's physical id
    // is the value some node stores in `first_rel` (the head of a non-empty chain); scan for it.
    let r1_phys = self_first_rel(&img);
    let (page_id, off) = img.locate(StoreKind::Rel, eid_r1.0);
    let mut rel = img.read_rel_at(page_id, off);
    rel.start_next_rel = r1_phys; // cycle: r1 -> r1
    img.write_rel_at(page_id, off, &rel);

    let mut store = img.open();
    let r = report(&mut store); // must return (terminate), not hang
    assert!(
        r.violations.iter().any(|v| matches!(
            v,
            Violation::Adjacency {
                detail: AdjacencyFault::NonTerminating
                    | AdjacencyFault::AsymmetricLink
                    | AdjacencyFault::IncidenceMismatch,
                ..
            }
        )),
        "cyclic chain must be reported as malformed: {:?}",
        r.violations
    );
}

/// Finds the physical id stored in some node's `first_rel` (the head of a non-empty incidence
/// chain) by scanning the image's node pages.
fn self_first_rel(img: &DiskImage) -> u64 {
    let size = StoreKind::Node.record_size();
    let rpp = (PAGE_SIZE - page::HEADER_SIZE) / size;
    for (_, bytes) in &img.pages {
        if page::page_type(bytes) != 1 {
            continue;
        }
        for slot in 0..rpp {
            let off = page::HEADER_SIZE + slot * size;
            if off + size > PAGE_SIZE {
                break;
            }
            let n = NodeRecord::decode(&bytes[off..off + size]);
            if n.mvcc.in_use() && n.first_rel != 0 {
                return n.first_rel;
            }
        }
    }
    panic!("no node with a non-empty incidence chain in the image");
}

// ============================================================================================
// Label-bitmap well-formedness (`05 §9`, `rmp` task #42 — node labels).
// ============================================================================================

/// A healthy labelled store passes (no false positive on a valid label bitmap).
#[test]
fn labelled_graph_passes() {
    let mut s = fresh(64);
    let txn = TxnId(1);
    s.begin(txn);
    let (a, _) = s.create_node(txn).unwrap();
    let (_b, _) = s.create_node(txn).unwrap();
    let person = s.intern_token(Namespace::Label, "Person").unwrap();
    let admin = s.intern_token(Namespace::Label, "Admin").unwrap();
    s.set_node_labels(txn, a, &[person, admin]).unwrap();
    s.commit(txn).unwrap();

    let r = report(&mut s);
    assert!(
        r.is_consistent(),
        "healthy labelled graph: {:?}",
        r.violations
    );
    // It also passes after crash + recovery.
    let img = DiskImage::capture(&mut s);
    let mut reopened = img.open();
    assert!(report(&mut reopened).is_consistent());
}

/// (i) A node whose `labels` bitmap has the overflow flag set (a state this build never writes, so
/// necessarily stale/corrupt) is flagged — and the *uncorrupted* image first passes.
#[test]
fn label_bitmap_overflow_flag_is_flagged() {
    let mut s = fresh(64);
    let txn = TxnId(1);
    s.begin(txn);
    let (_a, eid_a) = s.create_node(txn).unwrap();
    let l = s.intern_token(Namespace::Label, "L").unwrap();
    s.set_node_labels(txn, _a, &[l]).unwrap();
    s.commit(txn).unwrap();

    // Uncorrupted image passes.
    let mut img = DiskImage::capture(&mut s);
    assert!(report(&mut img.open()).is_consistent());

    // Corrupt: set the overflow flag (bit 63) on the node's labels bitmap.
    let (page_id, off) = img.locate(StoreKind::Node, eid_a.0);
    let mut node = img.read_node_at(page_id, off);
    node.labels |= 1u64 << graphus_storage::OVERFLOW_BIT;
    img.write_node_at(page_id, off, &node);

    let mut store = img.open();
    let r = report(&mut store);
    assert!(
        r.violations.iter().any(|v| matches!(
            v,
            Violation::LabelBitmap {
                detail: LabelBitmapFault::OverflowFlagSet,
                ..
            }
        )),
        "an overflow-flagged label bitmap must be flagged: {:?}",
        r.violations
    );
}

/// (j) A node whose `labels` bitmap references a `Label` token id that does not exist in the token
/// store (a dangling label reference) is flagged.
#[test]
fn label_bitmap_unknown_token_is_flagged() {
    let mut s = fresh(64);
    let txn = TxnId(1);
    s.begin(txn);
    let (_a, eid_a) = s.create_node(txn).unwrap();
    let l = s.intern_token(Namespace::Label, "L").unwrap(); // token id 0
    s.set_node_labels(txn, _a, &[l]).unwrap();
    s.commit(txn).unwrap();

    let mut img = DiskImage::capture(&mut s);
    assert!(report(&mut img.open()).is_consistent());

    // Corrupt: set bit 5 too — no `Label` token with id 5 exists (only id 0 was interned).
    let (page_id, off) = img.locate(StoreKind::Node, eid_a.0);
    let mut node = img.read_node_at(page_id, off);
    node.labels |= 1u64 << 5;
    img.write_node_at(page_id, off, &node);

    let mut store = img.open();
    let r = report(&mut store);
    assert!(
        r.violations.iter().any(|v| matches!(
            v,
            Violation::LabelBitmap {
                detail: LabelBitmapFault::UnknownLabelToken { token_id: 5 },
                ..
            }
        )),
        "a label bitmap referencing an unknown token id must be flagged: {:?}",
        r.violations
    );
}
