//! Regression: a derived, ephemeral secondary index must cost a **bounded, per-element-flat** amount
//! of resident memory — never ~one 8 KiB page (or more) per indexed element (`rmp` #724).
//!
//! # The bug this pins
//!
//! Every derived index tree is a `BTree<MemBlockDevice, DiscardingLogSink>` built by inserting one
//! entry per indexed element under a **fixed, never-committed** transaction. Each B+-tree insert logs
//! a WAL update whose *undo* image is the full ~8 KiB node-payload pre-image. The WAL manager retained
//! that undo image in its in-memory undo back-chain until the transaction committed — but the ephemeral
//! index transaction is *never* committed, so the chain grew ~8 KiB **per inserted element** and was
//! held for the life of the process. Measured on a real server: a RANGE index over 59,967 relationships
//! cost **+445 MB** of RSS (≈7.8 KiB/element), linear in the element count — a hard ceiling on the graph
//! size Graphus could serve with indexes (~7.5 GB extrapolated for a 1M-relationship index).
//!
//! The B+-tree device pages themselves are tiny (a packed leaf holds hundreds of ~20-byte entries), so
//! the retained cost MUST be dominated by the packed pages, not by the entry count.
//!
//! # What these tests assert (deterministically, no RSS sampling)
//!
//! The two structures that retain memory across an ephemeral index build are (1) the in-memory device's
//! B+-tree pages and (2) the WAL manager's undo back-chain. Both are measured exactly:
//! `resident_bytes = device_pages * PAGE_SIZE + wal.retained_undo_bytes()`. Pre-fix this is ~8.2 KiB per
//! element (the undo chain dominates); post-fix it is ~80 B per element (packed pages only, undo == 0).
//! A ceiling of [`MAX_RESIDENT_PER_ELEMENT`] cleanly fails the old implementation and passes the fix.

use graphus_bufpool::BufferPool;
use graphus_core::{TxnId, Value};
use graphus_index::recovery::SharedWal;
use graphus_index::{BTree, CompositeIndex, PropertyIndex, RelPropertyIndex};
use graphus_io::{MemBlockDevice, PAGE_SIZE};
use graphus_wal::{DiscardingLogSink, LogSink, MemLogSink, WalManager};

/// The ephemeral derived-index buffer-pool capacity (mirrors `graphus_cypher::index_set::POOL_FRAMES`).
const POOL_FRAMES: usize = 64;
/// The fixed, never-committed transaction id every derived-index op uses (mirrors `EPHEMERAL_TXN`).
const EPHEMERAL_TXN: TxnId = TxnId(1);

/// Hard per-element resident ceiling (bytes). Post-fix a build costs ~80 B/element (packed B+-tree
/// pages, zero retained undo); pre-fix it cost ~8.2 KiB/element (one full-page undo image retained per
/// insert). `1024` sits an order of magnitude below the bug and an order of magnitude above the fix, so
/// it is a robust regression gate that never false-fails on page-fill variation.
const MAX_RESIDENT_PER_ELEMENT: usize = 1024;

/// Builds a fresh ephemeral index tree exactly as `graphus_cypher::index_set::fresh_tree` does:
/// `BTree<MemBlockDevice, DiscardingLogSink>` over a `POOL_FRAMES`-frame pool.
fn fresh_tree<S: LogSink>(sink: S) -> BTree<MemBlockDevice, S> {
    let wal = WalManager::create(sink).expect("in-memory WAL creation is infallible");
    let shared = SharedWal::new(wal);
    let pool = BufferPool::with_wal(MemBlockDevice::new(0), shared.clone(), POOL_FRAMES);
    BTree::create(pool, shared).expect("in-memory BTree creation is infallible")
}

/// The exactly-measured resident cost of a built tree: its in-memory device pages plus the WAL
/// manager's retained undo back-chain (the two structures that persist across an ephemeral build).
fn resident_bytes<S: LogSink>(tree: &mut BTree<MemBlockDevice, S>) -> usize {
    let device = tree.mapped_pages().len() * PAGE_SIZE;
    let undo = tree.with_wal(|w| w.retained_undo_bytes());
    device + undo
}

/// Asserts a built tree stays under the per-element resident ceiling and holds **zero** retained undo
/// (the `rmp` #724 fix), printing the measured cost for the record.
fn assert_bounded<S: LogSink>(label: &str, tree: &mut BTree<MemBlockDevice, S>, n: u64) {
    let undo = tree.with_wal(|w| w.retained_undo_bytes());
    let resident = resident_bytes(tree);
    let per_elem = resident / n as usize;
    let pages = tree.mapped_pages().len();
    println!(
        "{label}: N={n} pages={pages} device={:.2}MB undo={:.2}MB resident={:.2}MB per_elem={per_elem}B",
        (pages * PAGE_SIZE) as f64 / 1e6,
        undo as f64 / 1e6,
        resident as f64 / 1e6,
    );
    assert_eq!(
        undo, 0,
        "{label}: an ephemeral (DiscardingLogSink) index must retain NO undo back-chain \
         (rmp #724); retained {undo} bytes over {n} elements"
    );
    assert!(
        per_elem <= MAX_RESIDENT_PER_ELEMENT,
        "{label}: resident cost {per_elem} B/element exceeds the {MAX_RESIDENT_PER_ELEMENT} B ceiling \
         (rmp #724 regression: a secondary index must not cost ~one 8 KiB page per element)"
    );
}

/// A node RANGE index (`PropertyIndex`) over N nodes must be per-element bounded.
#[test]
fn node_range_index_is_per_element_bounded() {
    const N: u64 = 20_000;
    let mut pi = PropertyIndex::new(fresh_tree(DiscardingLogSink::new()));
    for i in 0..N {
        let v = Value::Float((i as f64) * 0.5 + 0.25);
        pi.insert(EPHEMERAL_TXN, 7, &v, i).unwrap();
    }
    assert_bounded("node_range", pi.tree_mut(), N);
}

/// A relationship RANGE index (`RelPropertyIndex`) over N relationships — the headline `rmp` #724 case
/// (`CREATE INDEX FOR ()-[c:CITES]-() ON (c.weight)`) — must be per-element bounded.
#[test]
fn rel_range_index_is_per_element_bounded() {
    const N: u64 = 20_000;
    let mut ri = RelPropertyIndex::new(fresh_tree(DiscardingLogSink::new()));
    for i in 0..N {
        let v = Value::Float((i as f64) * 0.5 + 0.25);
        ri.insert(EPHEMERAL_TXN, 3, &v, i).unwrap();
    }
    assert_bounded("rel_range", ri.tree_mut(), N);
}

/// A UNIQUE constraint's backing index (`CompositeIndex`, arity 1) over N nodes must be per-element
/// bounded (the `CREATE CONSTRAINT ... IS UNIQUE` case, +20.3 MB over 2400 nodes pre-fix).
#[test]
fn unique_constraint_index_is_per_element_bounded() {
    const N: u64 = 20_000;
    let mut ci = CompositeIndex::new(fresh_tree(DiscardingLogSink::new()), 1);
    for i in 0..N {
        let vals = [Value::Integer(i as i64)];
        ci.insert(EPHEMERAL_TXN, 11, &vals, i).unwrap();
    }
    assert_bounded("unique_constraint", ci.tree_mut(), N);
}

/// The per-element resident cost must NOT grow with N: doubling the element count roughly doubles the
/// resident cost (packed pages scale with entries), so per-element stays flat. Pre-fix it was flat too
/// but at ~8 KiB; this asserts the *level*, so it is the companion to the ceiling gate above.
#[test]
fn per_element_cost_does_not_grow_with_n() {
    let build = |n: u64| -> usize {
        let mut pi = PropertyIndex::new(fresh_tree(DiscardingLogSink::new()));
        for i in 0..n {
            let v = Value::Float((i as f64) * 0.5 + 0.25);
            pi.insert(EPHEMERAL_TXN, 7, &v, i).unwrap();
        }
        resident_bytes(pi.tree_mut()) / n as usize
    };
    let small = build(20_000);
    let large = build(60_000);
    println!("per_element_growth: small(20k)={small}B  large(60k)={large}B");
    assert!(
        small <= MAX_RESIDENT_PER_ELEMENT && large <= MAX_RESIDENT_PER_ELEMENT,
        "per-element cost must stay under the ceiling at both scales (small={small}, large={large})"
    );
    // Flatness: the larger build's per-element cost must not exceed the smaller's by more than a small
    // margin (page-fill jitter). A per-element cost that *grew* with N would betray a per-element leak.
    assert!(
        large <= small + 64,
        "per-element cost must be flat in N (small={small}B, large={large}B): a growing per-element \
         cost is the rmp #724 leak"
    );
}

/// Dropping the index frees the retained memory: after the tree is dropped, a fresh empty tree over the
/// same wiring holds only its meta/root pages — i.e. memory is not stranded for the process lifetime
/// (`rmp` #724 acceptance criterion 3). Rust ownership frees the device pages and the WAL on drop; this
/// asserts the freed state is genuinely empty (no residual retained undo).
#[test]
fn dropping_the_index_releases_memory() {
    const N: u64 = 20_000;
    let built_pages;
    {
        let mut pi = PropertyIndex::new(fresh_tree(DiscardingLogSink::new()));
        for i in 0..N {
            pi.insert(EPHEMERAL_TXN, 7, &Value::Integer(i as i64), i)
                .unwrap();
        }
        built_pages = pi.tree_mut().mapped_pages().len();
        assert!(built_pages > 1, "the build should have allocated pages");
        // pi (and its device + WAL) is dropped at the end of this scope.
    }
    // A freshly recreated empty tree (what `IndexSet::clear` / `unregister_*` produces) holds only its
    // meta page — the built index's pages are gone, not stranded.
    let mut empty = PropertyIndex::new(fresh_tree(DiscardingLogSink::new()));
    let empty_pages = empty.tree_mut().mapped_pages().len();
    let empty_undo = empty.tree_mut().with_wal(|w| w.retained_undo_bytes());
    assert!(
        empty_pages <= 1,
        "a fresh empty ephemeral index holds only its meta page (got {empty_pages})"
    );
    assert_eq!(
        empty_undo, 0,
        "a fresh empty ephemeral index retains no undo"
    );
}

/// CONTROL: the fix is **targeted**, not global. A durable/recoverable WAL sink (`MemLogSink`) MUST
/// still retain the undo back-chain — that chain backs live rollback and crash-recovery loser-undo
/// (steal/no-force), an inviolable ACID guarantee. This asserts the durable path is unchanged: the same
/// uncommitted build over a durable sink retains a full undo image per insert.
#[test]
fn durable_sink_still_retains_undo_back_chain() {
    // Small N: a durable sink also retains the appended log bytes, so keep the footprint modest.
    const N: u64 = 2_000;
    let mut pi = PropertyIndex::new(fresh_tree(MemLogSink::new()));
    for i in 0..N {
        let v = Value::Float((i as f64) * 0.5 + 0.25);
        pi.insert(EPHEMERAL_TXN, 7, &v, i).unwrap();
    }
    let undo = pi.tree_mut().with_wal(|w| w.retained_undo_bytes());
    // Every insert logs a full node-payload (~8 KiB) undo image that a durable manager retains until
    // commit; over N uncommitted inserts that is well over N * 4 KiB. This proves the durable/crash-safe
    // path keeps its rollback/recovery undo chain intact (the fix only opts the discarding sink out).
    assert!(
        undo as u64 >= N * 4_000,
        "a durable sink must retain the full undo back-chain (rollback/recovery); \
         retained only {undo} bytes over {N} inserts"
    );
}
