//! Regression: the **streaming** (allocation-free) candidate forms added in `rmp` #369 must visit
//! **exactly** the same ids/keys, in the **same order**, as the prior eager `Vec`-collecting forms.
//!
//! The streaming form (`BTree::range_for_each` and friends, `BitmapIndex::seek_eq_iter`,
//! `intersect_treemap`) is a pure allocation optimization on the label/reltype/bitmap scan access
//! paths: it must never change the candidate set (CLAUDE.md: candidate sets must be IDENTICAL). These
//! tests pin that invariant by computing the candidate set both ways and asserting byte-identity of
//! the resulting ordered `Vec`s.

use graphus_bufpool::BufferPool;
use graphus_core::{TxnId, Value};
use graphus_index::BTree;
use graphus_index::bitmap::{self, BitmapIndex};
use graphus_index::recovery::SharedWal;
use graphus_io::MemBlockDevice;
use graphus_wal::{MemLogSink, WalManager};

type Dev = MemBlockDevice;
type Sink = MemLogSink;

fn fresh_tree() -> BTree<Dev, Sink> {
    let wal = WalManager::create(MemLogSink::new()).unwrap();
    let shared = SharedWal::new(wal);
    // A small pool so a multi-thousand-entry range spans many leaves and forces the right-sibling
    // walk to fetch/unpin across page boundaries (the latch-lifetime path the visitor must respect).
    let pool = BufferPool::with_wal(MemBlockDevice::new(0), shared.clone(), 16);
    BTree::create(pool, shared).unwrap()
}

/// Build a multi-leaf tree of `n` keys with be-encoded `(key=i, value=i)` so both the eager `range`
/// and the streaming `range_for_each` traverse the full right-sibling chain.
fn build_tree(n: u32) -> BTree<Dev, Sink> {
    let mut t = fresh_tree();
    let txn = TxnId(1);
    t.with_wal(|w| {
        w.begin(txn);
    });
    for i in 0..n {
        t.insert(txn, &i.to_be_bytes(), &(u64::from(i)).to_le_bytes())
            .unwrap();
    }
    t.with_wal(|w| w.commit(txn).unwrap());
    assert!(
        t.height().unwrap() >= 2,
        "want a multi-level tree for the leaf-chain walk"
    );
    t
}

#[test]
fn btree_range_for_each_matches_eager_range() {
    let mut t = build_tree(5_000);

    // Several bounded sub-ranges + an unbounded-above range + a full scan, each compared eager vs
    // streaming over identical (lo, hi).
    let cases: &[(u32, Option<u32>)] = &[
        (0, Some(5_000)), // full half-open span
        (1_000, Some(4_000)),
        (4_999, Some(5_000)), // single-entry
        (4_999, None),        // unbounded above, tail
        (123, Some(123)),     // empty (lo == hi)
        (0, None),            // everything, unbounded above
    ];

    for &(lo, hi) in cases {
        let lo_b = lo.to_be_bytes();
        // Eager form.
        let eager: Vec<(Vec<u8>, Vec<u8>)> = match hi {
            Some(h) => t.range(&lo_b, &h.to_be_bytes()).unwrap(),
            None => t.range_from(&lo_b).unwrap(),
        };
        // Streaming form: copy the slices out in visit order.
        let mut streamed: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
        match hi {
            Some(h) => t
                .range_for_each(&lo_b, &h.to_be_bytes(), |k, v| {
                    streamed.push((k.to_vec(), v.to_vec()))
                })
                .unwrap(),
            None => t
                .range_from_for_each(&lo_b, |k, v| streamed.push((k.to_vec(), v.to_vec())))
                .unwrap(),
        }
        assert_eq!(
            eager, streamed,
            "streaming range_for_each must yield identical (key,value) sequence for ({lo}, {hi:?})"
        );
    }

    // Full scan parity (scan_all vs scan_all_for_each).
    let eager_all = t.scan_all().unwrap();
    let mut streamed_all: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
    t.scan_all_for_each(|k, v| streamed_all.push((k.to_vec(), v.to_vec())))
        .unwrap();
    assert_eq!(
        eager_all, streamed_all,
        "scan_all vs scan_all_for_each must match"
    );
}

#[test]
fn bitmap_seek_eq_iter_matches_eager_seek_eq() {
    // A low-cardinality column with a large, sparse 64-bit id space (forces multiple Roaring
    // containers, the case where the eager flat `Vec` is most wasteful).
    let mut bm = BitmapIndex::new();
    let values = [
        Value::Boolean(true),
        Value::Boolean(false),
        Value::String("x".into()),
    ];
    for i in 0..50_000u64 {
        // spread ids across the high 32 bits so the treemap holds several containers
        let id = i * 97 + (i % 7) * (1u64 << 33);
        let v = &values[(i % 3) as usize];
        bm.insert(v, id);
    }

    for v in &values {
        let eager: Vec<u64> = bm.seek_eq(v);
        let streamed: Vec<u64> = bm
            .seek_eq_iter(v)
            .map(Iterator::collect)
            .unwrap_or_default();
        assert_eq!(
            eager, streamed,
            "seek_eq vs seek_eq_iter must be identical for {v:?}"
        );
        // ascending invariant the caller relies on
        assert!(
            streamed.windows(2).all(|w| w[0] < w[1]),
            "ids must be ascending"
        );
    }

    // Absent value: both yield empty.
    let absent = Value::Integer(999);
    assert!(bm.seek_eq(&absent).is_empty());
    assert!(bm.seek_eq_iter(&absent).is_none());
}

#[test]
fn bitmap_intersect_treemap_matches_eager_intersect() {
    let mut a = BitmapIndex::new();
    let mut b = BitmapIndex::new();
    let mut c = BitmapIndex::new();
    for id in 0..30_000u64 {
        a.insert(&Value::Integer(1), id);
        if id % 2 == 0 {
            b.insert(&Value::Integer(2), id);
        }
        if id % 3 == 0 {
            c.insert(&Value::Integer(3), id);
        }
    }

    let bitmaps = [
        a.bitmap_for(&Value::Integer(1)),
        b.bitmap_for(&Value::Integer(2)),
        c.bitmap_for(&Value::Integer(3)),
    ];
    let eager: Vec<u64> = bitmap::intersect(&bitmaps);
    let streamed: Vec<u64> = bitmap::intersect_treemap(&bitmaps).iter().collect();
    assert_eq!(
        eager, streamed,
        "intersect vs intersect_treemap must be identical"
    );

    // Absent predicate ⇒ empty conjunction, both forms.
    let with_absent = [a.bitmap_for(&Value::Integer(1)), None];
    assert!(bitmap::intersect(&with_absent).is_empty());
    assert!(bitmap::intersect_treemap(&with_absent).is_empty());
}
