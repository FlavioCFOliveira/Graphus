//! Security regression battery for `graphus-index` (red-team audit, 2026-06-14; fixes landed).
//!
//! The B+-tree slotted-page accessors (`NodeView::key/value/child`) read a cell offset and length
//! straight out of the page bytes. Before the fix, three code paths read slots **without** first
//! running `NodeView::validate()` (`discover_max_page`, `delete`, `insert_descend`), so a page that
//! is corrupt-yet-CRC-valid (an adversarially tampered index/backup file) drove an out-of-bounds
//! panic — a DoS on open / query.
//!
//! These tests now pin the **hardened** behaviour:
//! - the unvalidated read paths (`BTree::open` → `discover_max_page`, `delete`, `insert`) surface a
//!   forged page as a graceful `Storage` **error**, never a panic (SEC-203/206);
//! - the bounds-checked `try_*` accessors never slice out of bounds on a forged page (SEC-207);
//! - `validate()` rejects the forged pages it is the gate against.
//!
//! Findings covered:
//! - Regression: SEC-203  `discover_max_page` now validates each node before slot access (CWE-125)
//! - Regression: SEC-206  `delete` / `insert_descend` now validate the node before slot access (CWE-125)
//! - Regression: SEC-207  accessors are bounds-checked (`try_*`) and never read OOB (CWE-125)

use graphus_bufpool::BufferPool;
use graphus_bufpool::page::{self, HEADER_SIZE};
use graphus_core::{PageId, TxnId};
use graphus_index::BTree;
use graphus_index::node::{
    NodeView, PAGE_TYPE_BTREE_INTERNAL, PAGE_TYPE_BTREE_LEAF, SLOT_DIR_START,
};
use graphus_index::recovery::SharedWal;
use graphus_io::{BlockDevice, MemBlockDevice, PAGE_SIZE};
use graphus_wal::{MemLogSink, WalManager};

/// Node-header field offsets (mirrors `node.rs`, which keeps them private).
const OFF_LEVEL: usize = HEADER_SIZE; // u16: 0 = leaf, >0 = internal
const OFF_SLOT_COUNT: usize = HEADER_SIZE + 2; // u16

fn put_u16(page: &mut [u8], off: usize, v: u16) {
    page[off..off + 2].copy_from_slice(&v.to_le_bytes());
}

/// Builds a page buffer whose single slot points at a cell offset near the very end of the page,
/// with a key length that makes any `key()`/`child()` read run past `PAGE_SIZE`.
fn forge_oob_page(level: u16) -> Vec<u8> {
    let mut page = vec![0u8; PAGE_SIZE];
    put_u16(&mut page, OFF_LEVEL, level);
    put_u16(&mut page, OFF_SLOT_COUNT, 1); // one live slot
    page[0] = if level == 0 {
        PAGE_TYPE_BTREE_LEAF
    } else {
        PAGE_TYPE_BTREE_INTERNAL
    };

    // Slot 0: cell_off points 4 bytes before the page end, key_len = 64. Reading the key (off..off+64)
    // or the internal child (rd_u64 at off+64) runs well past PAGE_SIZE.
    let slot = SLOT_DIR_START;
    let bad_off = (PAGE_SIZE - 4) as u16;
    put_u16(&mut page, slot, bad_off); // cell_off
    put_u16(&mut page, slot + 2, 64); // key_len
    put_u16(&mut page, slot + 4, 0); // val_len
    put_u16(&mut page, slot + 6, 0); // reserved
    page
}

// ---------------------------------------------------------------------------------------------
// SEC-207 — the bounds-checked accessors never read OOB on a forged page.
// ---------------------------------------------------------------------------------------------

/// Regression: SEC-207. `try_child()` returns `None` on a forged internal page instead of slicing
/// out of bounds — the defense-in-depth primitive the read paths now rely on.
#[test]
fn sec207_try_child_returns_none_on_forged_page() {
    // Regression: SEC-207
    let page = forge_oob_page(/* internal */ 1);
    let view = NodeView::new(&page);
    assert_eq!(
        view.try_child(0),
        None,
        "try_child must reject the out-of-range cell, not panic"
    );
}

/// Regression: SEC-207. `try_key()` / `try_value()` likewise return `None` on a forged leaf page.
#[test]
fn sec207_try_key_value_return_none_on_forged_page() {
    // Regression: SEC-207
    let page = forge_oob_page(/* leaf */ 0);
    let view = NodeView::new(&page);
    assert_eq!(view.try_key(0), None, "try_key must reject the forged slot");
    assert_eq!(
        view.try_value(0),
        None,
        "try_value must reject the forged slot"
    );
}

// ---------------------------------------------------------------------------------------------
// validate() rejects the forged pages it is the gate against (unchanged contract).
// ---------------------------------------------------------------------------------------------

#[test]
fn validate_rejects_forged_internal_page() {
    let page = forge_oob_page(1);
    assert!(
        NodeView::new(&page).validate().is_err(),
        "validate() must reject the forged internal page"
    );
}

#[test]
fn validate_rejects_forged_leaf_page() {
    let page = forge_oob_page(0);
    assert!(
        NodeView::new(&page).validate().is_err(),
        "validate() must reject the forged leaf page"
    );
}

#[test]
fn validate_rejects_absurd_slot_count() {
    let mut page = vec![0u8; PAGE_SIZE];
    put_u16(&mut page, OFF_LEVEL, 0);
    put_u16(&mut page, OFF_SLOT_COUNT, u16::MAX);
    assert!(
        NodeView::new(&page).validate().is_err(),
        "validate() must reject a slot_count that overflows the directory"
    );
}

#[test]
fn empty_leaf_page_is_valid() {
    let mut page = vec![0u8; PAGE_SIZE];
    put_u16(&mut page, OFF_LEVEL, 0);
    put_u16(&mut page, OFF_SLOT_COUNT, 0);
    let view = NodeView::new(&page);
    assert!(view.validate().is_ok(), "an empty leaf must validate");
    assert_eq!(view.slot_count(), 0);
}

// ---------------------------------------------------------------------------------------------
// End-to-end: the production read/write paths must surface a forged page as a graceful error,
// never a panic. This is the change SEC-203/206 makes: route the unvalidated paths through
// validate().
// ---------------------------------------------------------------------------------------------

/// Builds a real single-leaf tree, then overwrites its root leaf on the device with a forged slot
/// directory (key length running past the page) and a **recomputed, valid** checksum — the exact
/// shape of an adversarially tampered index file. Returns the WAL bytes and the device so a fresh
/// `BTree::open` can be driven over them.
fn tree_with_forged_root_leaf() -> (MemBlockDevice, WalManager<MemLogSink>, PageId) {
    let wal = WalManager::create(MemLogSink::new()).expect("wal create");
    let shared = SharedWal::new(wal);
    let pool = BufferPool::with_wal(MemBlockDevice::new(0), shared.clone(), 32);
    let mut tree = BTree::create(pool, shared.clone()).expect("create tree");
    let base = tree.base();

    // One insert creates a leaf root; flush it home so it is on the device.
    let txn = TxnId(1);
    tree.with_wal(|w| {
        w.begin(txn);
    });
    tree.insert(txn, b"k", b"v").expect("insert");
    tree.with_wal(|w| w.commit(txn).expect("commit"));
    tree.flush().expect("flush home");

    // The root leaf is the page right after the meta/base page.
    let root = PageId(base.0 + 1);

    // Snapshot every mapped device page out of the tree, then drop the tree (releasing its pool +
    // WAL clones) so the WAL handle can be unwrapped.
    let mut device = {
        let mapped = tree.mapped_pages();
        let mut dev = MemBlockDevice::new(0);
        dev.extend(mapped.len() as u64).expect("extend");
        for p in mapped {
            let bytes = tree.read_device_page(p).expect("read page");
            dev.write_page(p, &bytes).expect("write page");
        }
        dev
    };
    drop(tree); // releases the pool's and the tree's SharedWal clones
    let wal = shared
        .into_inner()
        .unwrap_or_else(|_| panic!("WAL still shared"));

    // Forge the root leaf: a single slot whose cell runs past the page. Keep the page id/type and
    // recompute the checksum so the page passes verification — only the slot directory is poisoned.
    let mut buf = [0u8; PAGE_SIZE];
    device.read_page(root, &mut buf).expect("read root");
    page::set_page_type(&mut buf, PAGE_TYPE_BTREE_LEAF);
    put_u16(&mut buf, OFF_LEVEL, 0);
    put_u16(&mut buf, OFF_SLOT_COUNT, 1);
    let slot = SLOT_DIR_START;
    put_u16(&mut buf, slot, (PAGE_SIZE - 4) as u16); // cell_off near the end
    put_u16(&mut buf, slot + 2, 64); // key_len runs past the page
    put_u16(&mut buf, slot + 4, 0);
    put_u16(&mut buf, slot + 6, 0);
    page::set_page_id(&mut buf, root.0);
    page::write_checksum(&mut buf);
    device.write_page(root, &buf).expect("write forged root");

    (device, wal, base)
}

/// Regression: SEC-206. `delete` / `insert` over a forged-but-CRC-valid leaf return a `Storage`
/// error instead of panicking out of bounds.
#[test]
fn sec206_delete_and_insert_on_forged_leaf_error_not_panic() {
    // Regression: SEC-206
    let (device, wal, base) = tree_with_forged_root_leaf();
    let shared = SharedWal::new(wal);
    let pool = BufferPool::with_wal(device, shared.clone(), 32);
    let mut tree = BTree::open(pool, shared, base).expect("open over forged-but-valid meta");

    let txn = TxnId(2);
    tree.with_wal(|w| {
        w.begin(txn);
    });

    // A lookup over the forged leaf is a graceful error (the read path already validated; this is
    // the control that the leaf is genuinely poisoned).
    assert!(
        tree.lookup(b"k").is_err(),
        "lookup over the forged leaf must error, not panic"
    );
    // The fixed write paths must do the same instead of an OOB panic.
    assert!(
        tree.delete(txn, b"k").is_err(),
        "delete over the forged leaf must error, not panic"
    );
    assert!(
        tree.insert(txn, b"z", b"w").is_err(),
        "insert over the forged leaf must error, not panic"
    );
}

/// Regression: SEC-203. `BTree::open` walks the tree (`discover_max_page`) over a forged **internal**
/// root and surfaces a `Storage` error instead of panicking at startup.
#[test]
fn sec203_open_over_forged_internal_root_errors_not_panic() {
    // Regression: SEC-203
    let (mut device, wal, base) = tree_with_forged_root_leaf();

    // Promote the forged root leaf to a forged *internal* node so `discover_max_page` actually
    // descends into it (it only reads child slots of internal nodes). Same OOB slot directory.
    let root = PageId(base.0 + 1);
    let mut buf = [0u8; PAGE_SIZE];
    device.read_page(root, &mut buf).expect("read root");
    page::set_page_type(&mut buf, PAGE_TYPE_BTREE_INTERNAL);
    put_u16(&mut buf, OFF_LEVEL, 1); // internal
    put_u16(&mut buf, OFF_SLOT_COUNT, 1);
    let slot = SLOT_DIR_START;
    put_u16(&mut buf, slot, (PAGE_SIZE - 4) as u16);
    put_u16(&mut buf, slot + 2, 64);
    put_u16(&mut buf, slot + 4, 0);
    put_u16(&mut buf, slot + 6, 0);
    page::set_page_id(&mut buf, root.0);
    page::write_checksum(&mut buf);
    device
        .write_page(root, &buf)
        .expect("write forged internal root");

    let shared = SharedWal::new(wal);
    let pool = BufferPool::with_wal(device, shared.clone(), 32);
    // `open` calls `discover_max_page`, which walks the (forged) internal root: it must return Err,
    // not panic the process at startup/recovery.
    let opened = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        BTree::open(pool, shared, base)
    }));
    match opened {
        Ok(Err(_)) => { /* graceful error: the fix */ }
        Ok(Ok(_)) => panic!("open must reject the forged internal root, not succeed"),
        Err(_) => panic!("open must NOT panic on the forged internal root (SEC-203 regression)"),
    }
}
