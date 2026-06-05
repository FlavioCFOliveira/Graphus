//! Constraint acceptance tests (`04-technical-design.md` §6.5; task #15 acceptance criterion:
//! *uniqueness/existence constraints reject violations atomically*).
//!
//! * **Uniqueness** — a duplicate-key insert under a unique constraint fails and leaves the index
//!   byte-for-byte unchanged (atomic rejection: zero writes on the rejected path).
//! * **Existence** — a write missing a required property fails (pure predicate, no I/O, no mutation).

use graphus_bufpool::BufferPool;
use graphus_core::{GraphusError, TxnId, Value};
use graphus_index::recovery::SharedWal;
use graphus_index::{BTree, ConstraintError, ExistenceConstraint, UniqueConstraint};
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

#[test]
fn uniqueness_rejects_duplicate_atomically_leaving_index_unchanged() {
    let mut uc = UniqueConstraint::new(fresh_tree(), 1);

    // Commit a unique email.
    let txn = TxnId(1);
    uc.tree_mut().with_wal(|w| {
        w.begin(txn);
    });
    uc.insert(txn, &Value::String("alice@x.com".to_owned()), 100)
        .unwrap();
    uc.tree_mut().with_wal(|w| w.commit(txn).unwrap());

    // Open the second transaction first (its BEGIN is legitimate WAL traffic), THEN snapshot, so
    // the comparison isolates exactly the writes the rejected insert would make.
    let txn2 = TxnId(2);
    uc.tree_mut().with_wal(|w| {
        w.begin(txn2);
    });
    let before_scan = uc.tree_mut().scan_all().unwrap();
    let before_wal = uc.tree_mut().with_wal(|w| w.next_lsn());

    // A *different* record id trying to claim the same value must be rejected.
    let err = uc
        .insert(txn2, &Value::String("alice@x.com".to_owned()), 200)
        .unwrap_err();
    assert!(
        matches!(err, GraphusError::Runtime(_)),
        "must be a runtime Cypher error"
    );

    // Atomic rejection: the index is unchanged AND no WAL update record was appended for the insert.
    let after_scan = uc.tree_mut().scan_all().unwrap();
    let after_wal = uc.tree_mut().with_wal(|w| w.next_lsn());
    assert_eq!(
        before_scan, after_scan,
        "rejected insert must not mutate the index"
    );
    assert_eq!(
        before_wal, after_wal,
        "rejected insert must append nothing to the WAL"
    );
    // The original owner is intact.
    assert_eq!(
        uc.owner(&Value::String("alice@x.com".to_owned())).unwrap(),
        Some(100)
    );
}

#[test]
fn uniqueness_allows_reinsert_of_same_owner_and_distinct_values() {
    let mut uc = UniqueConstraint::new(fresh_tree(), 1);
    let txn = TxnId(1);
    uc.tree_mut().with_wal(|w| {
        w.begin(txn);
    });
    uc.insert(txn, &Value::Integer(1), 10).unwrap();
    uc.insert(txn, &Value::Integer(1), 10).unwrap(); // same owner -> idempotent
    uc.insert(txn, &Value::Integer(2), 20).unwrap(); // distinct value -> ok
    uc.tree_mut().with_wal(|w| w.commit(txn).unwrap());
    assert_eq!(uc.owner(&Value::Integer(1)).unwrap(), Some(10));
    assert_eq!(uc.owner(&Value::Integer(2)).unwrap(), Some(20));
}

#[test]
fn uniqueness_freed_value_can_be_reclaimed() {
    let mut uc = UniqueConstraint::new(fresh_tree(), 1);
    let txn = TxnId(1);
    uc.tree_mut().with_wal(|w| {
        w.begin(txn);
    });
    uc.insert(txn, &Value::String("k".to_owned()), 1).unwrap();
    uc.tree_mut().with_wal(|w| w.commit(txn).unwrap());

    // Remove it, then a different record may now claim the value.
    let txn2 = TxnId(2);
    uc.tree_mut().with_wal(|w| {
        w.begin(txn2);
    });
    assert!(uc.remove(txn2, &Value::String("k".to_owned())).unwrap());
    uc.insert(txn2, &Value::String("k".to_owned()), 2).unwrap();
    uc.tree_mut().with_wal(|w| w.commit(txn2).unwrap());
    assert_eq!(uc.owner(&Value::String("k".to_owned())).unwrap(), Some(2));
}

#[test]
fn existence_constraint_rejects_missing_property() {
    let c = ExistenceConstraint::new(1, 42); // label token 1 requires property key 42

    // A record carrying the required key passes.
    assert!(c.check(&[1, 42, 7]).is_ok());

    // A record missing it fails — and the failure carries the offending token + key.
    assert_eq!(
        c.check(&[1, 7]),
        Err(ConstraintError::MissingProperty {
            token: 1,
            required: 42
        })
    );

    // The error converts to a runtime Cypher error class (`04 §7.3`).
    let cypher_err: GraphusError = c.check(&[1, 7]).unwrap_err().into();
    assert!(matches!(cypher_err, GraphusError::Runtime(_)));
}

#[test]
fn unindexable_constraint_key_is_a_runtime_error_not_a_panic() {
    let mut uc = UniqueConstraint::new(fresh_tree(), 1);
    let txn = TxnId(1);
    uc.tree_mut().with_wal(|w| {
        w.begin(txn);
    });
    // Null is treated as absent for indexing; a unique insert of Null is a runtime error, not UB.
    assert!(matches!(
        uc.insert(txn, &Value::Null, 1),
        Err(GraphusError::Runtime(_))
    ));
}
