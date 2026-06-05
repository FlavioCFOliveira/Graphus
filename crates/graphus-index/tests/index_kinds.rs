//! Focused integration tests for the four v1 index kinds through the public API
//! (`04-technical-design.md` §6.2, `D-v1-index-types`).
//!
//! Each kind gets a dedicated test exercising the seek a future planner (#16) will call:
//! token-lookup (per-token range), property (equality + range), composite (full key + leading
//! prefix), and relationship-property (equality + range over relationship records). These demonstrate
//! the index-seek APIs the planner integrates against (the planner integration seam — there is no
//! planner yet).

use graphus_bufpool::BufferPool;
use graphus_core::{TxnId, Value};
use graphus_index::recovery::SharedWal;
use graphus_index::{BTree, CompositeIndex, PropertyIndex, RelPropertyIndex, TokenIndex};
use graphus_io::MemBlockDevice;
use graphus_wal::{MemLogSink, WalManager};

type Dev = MemBlockDevice;
type Sink = MemLogSink;

fn fresh_tree() -> BTree<Dev, Sink> {
    let wal = WalManager::create(MemLogSink::new()).unwrap();
    let shared = SharedWal::new(wal);
    let pool = BufferPool::with_wal(MemBlockDevice::new(0), shared.clone(), 32);
    BTree::create(pool, shared).unwrap()
}

/// Runs `f` inside one committed transaction over the tree.
fn committed(tree: &mut BTree<Dev, Sink>, id: u64, f: impl FnOnce(&mut BTree<Dev, Sink>, TxnId)) {
    let txn = TxnId(id);
    tree.with_wal(|w| {
        w.begin(txn);
    });
    f(tree, txn);
    tree.with_wal(|w| w.commit(txn).unwrap());
}

#[test]
fn token_lookup_index_ranges_per_token() {
    let mut idx = TokenIndex::new(fresh_tree());
    let txn = TxnId(1);
    idx.tree_mut().with_wal(|w| {
        w.begin(txn);
    });
    // Label token 7 on nodes 3, 1, 8; label token 9 on node 2.
    idx.insert(txn, 7, 3).unwrap();
    idx.insert(txn, 7, 1).unwrap();
    idx.insert(txn, 7, 8).unwrap();
    idx.insert(txn, 9, 2).unwrap();
    idx.tree_mut().with_wal(|w| w.commit(txn).unwrap());

    // A per-token scan is the `MATCH (n:Label)` seek, returned in ascending element-id order.
    assert_eq!(idx.scan_token(7).unwrap(), vec![1, 3, 8]);
    assert_eq!(idx.scan_token(9).unwrap(), vec![2]);
    assert_eq!(idx.scan_token(42).unwrap(), Vec::<u64>::new());

    // Removing one element narrows the per-token result.
    let txn2 = TxnId(2);
    idx.tree_mut().with_wal(|w| {
        w.begin(txn2);
    });
    assert!(idx.remove(txn2, 7, 3).unwrap());
    idx.tree_mut().with_wal(|w| w.commit(txn2).unwrap());
    assert_eq!(idx.scan_token(7).unwrap(), vec![1, 8]);
}

#[test]
fn property_index_equality_and_range_with_type_aware_order() {
    let mut idx = PropertyIndex::new(fresh_tree());
    committed(idx.tree_mut(), 1, |_, _| {});
    let txn = TxnId(2);
    idx.tree_mut().with_wal(|w| {
        w.begin(txn);
    });
    // Property key/token 1; values across negative/zero/positive and a float between ints.
    idx.insert(txn, 1, &Value::Integer(-5), 100).unwrap();
    idx.insert(txn, 1, &Value::Integer(0), 101).unwrap();
    idx.insert(txn, 1, &Value::Float(0.5), 102).unwrap();
    idx.insert(txn, 1, &Value::Integer(10), 103).unwrap();
    idx.insert(txn, 1, &Value::Integer(10), 104).unwrap(); // two ids share value 10
    idx.tree_mut().with_wal(|w| w.commit(txn).unwrap());

    // Equality.
    let mut eq = idx.seek_eq(1, &Value::Integer(10)).unwrap();
    eq.sort_unstable();
    assert_eq!(eq, vec![103, 104]);

    // Range [-5, 10): everything except the value-10 ids; note the float 0.5 sorts between 0 and 10.
    let mut r = idx
        .seek_range(1, &Value::Integer(-5), Some(&Value::Integer(10)))
        .unwrap();
    r.sort_unstable();
    assert_eq!(r, vec![100, 101, 102]);

    // Unbounded above (>= 0): drops the negative.
    let mut r2 = idx.seek_range(1, &Value::Integer(0), None).unwrap();
    r2.sort_unstable();
    assert_eq!(r2, vec![101, 102, 103, 104]);
}

#[test]
fn composite_index_full_key_and_leading_prefix() {
    let mut idx = CompositeIndex::new(fresh_tree(), 2);
    let txn = TxnId(1);
    idx.tree_mut().with_wal(|w| {
        w.begin(txn);
    });
    let v = |a: i64, b: &str| vec![Value::Integer(a), Value::String(b.to_owned())];
    idx.insert(txn, 1, &v(1, "alice"), 10).unwrap();
    idx.insert(txn, 1, &v(1, "bob"), 11).unwrap();
    idx.insert(txn, 1, &v(2, "alice"), 12).unwrap();
    idx.tree_mut().with_wal(|w| w.commit(txn).unwrap());

    // Full-key equality.
    assert_eq!(idx.seek_eq(1, &v(1, "alice")).unwrap(), vec![10]);

    // Leading-prefix on the first property only: ids 10 and 11 (first field == 1), not 12.
    let mut p = idx.seek_prefix(1, &[Value::Integer(1)]).unwrap();
    p.sort_unstable();
    assert_eq!(p, vec![10, 11]);

    // Prefix on the second field is rejected as a non-leading prefix is impossible; full arity ok.
    let mut full = idx.seek_prefix(1, &v(1, "bob")).unwrap();
    full.sort_unstable();
    assert_eq!(full, vec![11]);
}

#[test]
fn relationship_property_index_equality_and_range() {
    let mut idx = RelPropertyIndex::new(fresh_tree());
    let txn = TxnId(1);
    idx.tree_mut().with_wal(|w| {
        w.begin(txn);
    });
    // reltype 5 (e.g. :RATED) with a `year` property over relationship ids.
    idx.insert(txn, 5, &Value::Integer(2019), 900).unwrap();
    idx.insert(txn, 5, &Value::Integer(2020), 901).unwrap();
    idx.insert(txn, 5, &Value::Integer(2021), 902).unwrap();
    idx.tree_mut().with_wal(|w| w.commit(txn).unwrap());

    assert_eq!(idx.seek_eq(5, &Value::Integer(2020)).unwrap(), vec![901]);

    let mut r = idx
        .seek_range(5, &Value::Integer(2019), Some(&Value::Integer(2021)))
        .unwrap();
    r.sort_unstable();
    assert_eq!(r, vec![900, 901]); // [2019, 2021)
}
