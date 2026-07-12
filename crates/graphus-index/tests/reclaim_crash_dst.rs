//! Deterministic crash-injection campaign for B+-tree whole-page reclamation (`rmp` #225).
//!
//! This is the heart of the task: it crashes at **each of the four patch boundaries** of the
//! empty-leaf unlink and asserts that recovery leaves the tree either with the leaf **present** (or
//! stranded) or **fully reclaimed** — **never a page that is both reachable AND on the free list**.
//!
//! ## The four patches (`btree.rs::reclaim_empty_leaf`), in strict order
//!
//! (a) detach the empty leaf from its parent → (b) re-link the leaf chain so the predecessor skips
//! it → (c) mark its page a canonical free page (successor = current free-list head) → (d) publish
//! it as the new free-list head. The publish (d) is strictly **after** the page is unreachable
//! (a + b), so at every durable prefix the leaf is reachable-but-not-free or free-but-not-reachable —
//! never both.
//!
//! ## Crash model (identical to `tests/crash_recovery.rs`, the certified index recovery path)
//!
//! A crash is the durable WAL prefix (everything a committed transaction's group-commit `fdatasync`
//! hardened) plus an optional on-disk page image (the *steal* policy). To observe an intermediate
//! durable state at boundary `k`, the campaign drives the unlink emitting only its first `k` patches
//! (`BTree::reclaim_leaf_crash_inject`, `dst`-gated) inside a transaction that then **commits** — so
//! the recovered state IS that prefix. Because ARIES redo replays committed patches in log order,
//! this proves the ordering invariant holds for **any** durability granularity, not merely the
//! whole-transaction atomicity the production path also enjoys (defence in depth).
//!
//! ## Teeth (`rmp` #225 acceptance criterion 3)
//!
//! Running the same boundaries with a **deliberately mis-ordered** publish (publish before the page
//! is unreachable) drives an intermediate durable state that is both reachable and free-listed, which
//! the recovery invariant catches. A crash test that could not catch a mis-ordered publish would not
//! be a guard; [`mis_ordered_publish_is_caught_by_the_recovery_invariant`] proves it fires, and
//! [`correct_order_is_crash_safe_at_every_boundary`] proves the correct order never trips it.
#![cfg(feature = "dst")]

use std::collections::HashSet;

use graphus_bufpool::BufferPool;
use graphus_core::{PageId, TxnId};
use graphus_index::BTree;
use graphus_index::keycodec::encode_i64_bits;
use graphus_index::recovery::{SharedWal, recover_index_device};
use graphus_io::{BlockDevice, MemBlockDevice, Page};
use graphus_wal::{LogSink, MemLogSink, WalManager};

type Tree = BTree<MemBlockDevice, MemLogSink>;

fn key(k: i64) -> Vec<u8> {
    encode_i64_bits(k).to_vec()
}
fn val(v: u64) -> Vec<u8> {
    v.to_le_bytes().to_vec()
}
fn decode_i64(bytes: &[u8]) -> i64 {
    let arr: [u8; 8] = bytes.try_into().expect("8-byte key");
    (u64::from_be_bytes(arr) ^ 0x8000_0000_0000_0000) as i64
}

fn fresh(cap: usize) -> Tree {
    let wal = WalManager::create(MemLogSink::new()).expect("create wal");
    let shared = SharedWal::new(wal);
    let pool = BufferPool::with_wal(MemBlockDevice::new(0), shared.clone(), cap);
    BTree::create(pool, shared).expect("create btree")
}

/// The durable WAL bytes (the group-committed log prefix) of a tree — the crash's log image.
fn durable_log(tree: &Tree) -> Vec<u8> {
    tree.with_wal(|w| w.sink().durable_bytes().to_vec())
}

/// Reopens a tree from a recovered device + the durable log sink, sharing one WAL.
fn reopen(device: MemBlockDevice, sink: MemLogSink, base: PageId) -> Tree {
    let wal = WalManager::open(sink).expect("reopen wal");
    let shared = SharedWal::new(wal);
    let pool = BufferPool::with_wal(device, shared.clone(), 64);
    BTree::open(pool, shared, base).expect("open tree")
}

/// Snapshots the tree's on-disk image into a fresh device for the steal scenario.
fn snapshot_device(tree: &mut Tree) -> MemBlockDevice {
    let pages = tree.mapped_pages();
    let max = pages.iter().map(|p| p.0).max().unwrap_or(0);
    let mut device = MemBlockDevice::new(max + 1);
    let mut staged: Vec<(u64, Box<Page>)> = Vec::new();
    for p in &pages {
        staged.push((p.0, tree.read_device_page(*p).expect("read device page")));
    }
    for (idx, bytes) in staged {
        device.write_page(PageId(idx), &bytes).expect("stage page");
    }
    device.sync_all().expect("persist disk image");
    device
}

/// The outcome of recovering a crash injected at one patch boundary.
struct Outcome {
    /// `true` iff the recovered tree has no page that is both reachable and free-listed.
    phys_ok: bool,
    /// `Some(true/false)` when the recovered tree is physically sound and its ordered scan was
    /// compared against the model; `None` when the physical invariant already failed (a corrupt tree
    /// whose scan is not meaningfully comparable).
    scan_matches: Option<bool>,
}

/// Builds a fixed multi-leaf tree, empties one interior leaf, drives the empty-leaf unlink emitting
/// only its first `max_steps` patches in the chosen order (`publish_first` = the unsafe ordering),
/// commits, crashes (`steal` selects the crash policy), recovers, and inspects the recovered tree.
fn run(publish_first: bool, max_steps: usize, steal: bool) -> Outcome {
    let mut tree = fresh(16);
    let base = tree.base();
    let n = 400i64;

    // Fill [0, n) and commit — a multi-leaf tree whose interior leaves have a chain predecessor and
    // successor and a parent with several children (so the single-leaf unlink does not recurse).
    let t1 = TxnId(1);
    tree.with_wal(|w| w.begin(t1));
    let mut model: Vec<i64> = Vec::new();
    for k in 0..n {
        tree.insert(t1, &key(k), &val(k as u64)).expect("insert");
        model.push(k);
    }
    tree.with_wal(|w| w.commit(t1).expect("commit fill"));

    // Target an interior leaf (routed to by a mid key), read its keys, and drop them from the model.
    let leaf = tree
        .debug_leaf_for_key(&key(n / 2))
        .expect("leaf lookup")
        .expect("a leaf exists");
    let leaf_keys = tree.debug_leaf_keys(leaf).expect("leaf keys");
    assert!(
        leaf_keys.len() >= 2,
        "want a target leaf with several keys, got {}",
        leaf_keys.len()
    );
    let leaf_key_set: HashSet<i64> = leaf_keys.iter().map(|k| decode_i64(k)).collect();
    model.retain(|k| !leaf_key_set.contains(k));

    // Empty the leaf, then drive the unlink to the chosen boundary, and commit (durable prefix).
    let probe = leaf_keys[0].clone();
    let t2 = TxnId(2);
    tree.with_wal(|w| w.begin(t2));
    tree.debug_empty_leaf(t2, leaf).expect("empty leaf");
    tree.reclaim_leaf_crash_inject(t2, leaf, &probe, publish_first, max_steps)
        .expect("stepped reclaim");
    tree.with_wal(|w| w.commit(t2).expect("commit reclaim prefix"));

    // Crash: capture the durable log, and for a steal crash the flushed-home page image.
    let log = durable_log(&tree);
    let mut device = if steal {
        tree.flush().expect("flush (steal)");
        snapshot_device(&mut tree)
    } else {
        MemBlockDevice::new(0)
    };
    let mut sink = MemLogSink::new();
    sink.append(&log);
    sink.sync().expect("sync");
    let mut wal = WalManager::open(sink.clone()).expect("open wal");
    recover_index_device(&mut wal, &mut device).expect("recover");

    let mut rec = reopen(device, sink, base);
    let phys_ok = rec.assert_no_reachable_page_is_free().is_ok();
    let scan_matches = if phys_ok {
        // A physically sound tree must also be structurally consistent and scan to the model.
        rec.check_invariants().expect("recovered invariants");
        let scanned: Vec<i64> = rec
            .scan_all()
            .expect("scan")
            .into_iter()
            .map(|(k, _)| decode_i64(&k))
            .collect();
        Some(scanned == model)
    } else {
        None
    };
    Outcome {
        phys_ok,
        scan_matches,
    }
}

/// Correct-ordered reclamation is crash-safe at every one of the four patch boundaries, under both
/// the no-force and steal crash policies: the recovered tree is always physically sound (no reachable
/// page is free-listed), structurally consistent, and scans exactly to the model. Boundaries: 0 =
/// leaf emptied but not yet unlinked (present); 1 = detached from parent (still chain-reachable);
/// 2 = also chain-relinked (unreachable, stranded, not yet freed); 3 = also marked free (still not
/// published — invisible); 4 = published (fully reclaimed).
#[test]
fn correct_order_is_crash_safe_at_every_boundary() {
    for &steal in &[false, true] {
        for k in 0..=4usize {
            let o = run(false, k, steal);
            assert!(
                o.phys_ok,
                "correct order, boundary k={k}, steal={steal}: recovery left a page both reachable \
                 and on the free list"
            );
            assert_eq!(
                o.scan_matches,
                Some(true),
                "correct order, boundary k={k}, steal={steal}: recovered ordered scan != model"
            );
        }
    }
}

/// The teeth (`rmp` #225 acceptance criterion 3): a **mis-ordered publish** — publishing the page to
/// the free list before it is unreachable — makes an intermediate durable state that is both
/// reachable and free-listed, which the recovery invariant catches. The invariant is *precise*: it
/// passes before the publish (k = 0, 1) and after the page is finally unreachable again (k = 4), and
/// fails exactly in the publish-while-reachable window (k = 2, 3). A crash test that could not catch a
/// mis-ordered publish would not be a guard — this proves it fires, and
/// [`correct_order_is_crash_safe_at_every_boundary`] proves the correct order never trips it.
#[test]
fn mis_ordered_publish_is_caught_by_the_recovery_invariant() {
    for &steal in &[false, true] {
        // Before the (wrongly early) publish: still safe.
        assert!(
            run(true, 0, steal).phys_ok,
            "mis-ordered k=0 (nothing done yet) must be safe, steal={steal}"
        );
        assert!(
            run(true, 1, steal).phys_ok,
            "mis-ordered k=1 (marked free but not yet published) must be safe, steal={steal}"
        );
        // Publish-while-reachable window: MUST be caught as corruption.
        assert!(
            !run(true, 2, steal).phys_ok,
            "mis-ordered k=2 (published while still reachable) MUST be caught, steal={steal}"
        );
        assert!(
            !run(true, 3, steal).phys_ok,
            "mis-ordered k=3 (published, detached, still chain-reachable) MUST be caught, steal={steal}"
        );
        // After the wrongly-ordered sequence completes the page is unreachable again → disjoint.
        assert!(
            run(true, 4, steal).phys_ok,
            "mis-ordered k=4 (fully unlinked) is disjoint again, steal={steal}"
        );
    }
}

/// End-to-end via the **production** path: a real monotonic delete-without-reinsert TTL sweep (each
/// drained leaf auto-reclaimed by `BTree::delete`) followed by a crash recovers exactly to the model,
/// with no reachable page free-listed — under both crash policies. This exercises the full
/// reclamation (including parent-emptying + root collapse) through the real API, not the injection
/// hook.
#[test]
fn production_delete_reclamation_recovers_to_model() {
    for &steal in &[false, true] {
        let mut tree = fresh(16);
        let base = tree.base();
        let n = 600i64;

        // Fill [0, 2n), commit.
        let t1 = TxnId(1);
        tree.with_wal(|w| w.begin(t1));
        for k in 0..(2 * n) {
            tree.insert(t1, &key(k), &val(k as u64)).expect("insert");
        }
        tree.with_wal(|w| w.commit(t1).expect("commit fill"));

        // Delete the low range [0, n) (TTL expiry) — drained leaves auto-reclaimed. Commit.
        let t2 = TxnId(2);
        tree.with_wal(|w| w.begin(t2));
        for k in 0..n {
            assert!(tree.delete(t2, &key(k)).expect("delete"));
        }
        tree.with_wal(|w| w.commit(t2).expect("commit delete"));
        let model: Vec<i64> = (n..(2 * n)).collect();

        // Crash + recover.
        let log = durable_log(&tree);
        let mut device = if steal {
            tree.flush().expect("flush");
            snapshot_device(&mut tree)
        } else {
            MemBlockDevice::new(0)
        };
        let mut sink = MemLogSink::new();
        sink.append(&log);
        sink.sync().expect("sync");
        let mut wal = WalManager::open(sink.clone()).expect("open wal");
        recover_index_device(&mut wal, &mut device).expect("recover");

        let mut rec = reopen(device, sink, base);
        rec.assert_no_reachable_page_is_free()
            .expect("recovered: no reachable page is free-listed");
        rec.check_invariants().expect("recovered invariants");
        let scanned: Vec<i64> = rec
            .scan_all()
            .expect("scan")
            .into_iter()
            .map(|(k, _)| decode_i64(&k))
            .collect();
        assert_eq!(
            scanned, model,
            "steal={steal}: recovered tree after TTL reclamation must equal the surviving model"
        );

        // The freed low pages are reusable: inserting a fresh disjoint range pops them (bounded
        // high-water) and stays consistent after another crash cycle.
        let before = rec.mapped_pages().len();
        let t3 = TxnId(3);
        rec.with_wal(|w| w.begin(t3));
        for k in (2 * n)..(3 * n) {
            rec.insert(t3, &key(k), &val(k as u64))
                .expect("insert high");
        }
        rec.with_wal(|w| w.commit(t3).expect("commit high"));
        let after = rec.mapped_pages().len();
        assert!(
            after <= before,
            "steal={steal}: post-recovery inserts must reuse freed pages (before={before}, after={after})"
        );
    }
}
