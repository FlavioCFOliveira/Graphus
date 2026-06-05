//! Uniqueness and existence constraints (`04-technical-design.md` §6.5).
//!
//! Constraints reject violations **atomically**: the violating operation fails and nothing partial
//! persists (the B+-tree is left exactly as before). Constraint violations surface as
//! [`ConstraintError`], which the Cypher layer maps to the TCK-conformant error class — never a
//! panic (`04 §6.5`, §7.3).
//!
//! ## Existence constraints — checked on write (`04 §6.5`)
//!
//! An existence constraint ("property *p* must be present on every node with label *L*") is a pure
//! predicate over the record being written: [`ExistenceConstraint::check`] is called with the set
//! of property keys the record carries and fails if the required key is absent. It performs no I/O
//! and never mutates the index, so a failure leaves nothing partial by construction.
//!
//! ## Uniqueness constraints — via a unique index, commit-time validated (`04 §6.5`)
//!
//! A uniqueness constraint is enforced by a **unique B+-tree index**: the key is the property
//! value alone (no record-id suffix), so a duplicate value collides on the same key. The crucial
//! semantics (`04 §6.5`): the final check is done against **committed state** so two concurrent
//! transactions inserting the same value cannot both succeed — the second committer fails. In this
//! single-threaded core "committed state" is the current tree (the txn layer adds SSI conflict
//! detection at commit, the documented seam in the crate root). [`UniqueConstraint::insert`]:
//!
//! 1. looks the value up; if a *different* record id already owns it → [`ConstraintError::Duplicate`]
//!    is returned and the tree is untouched (atomic rejection);
//! 2. otherwise inserts `value -> rid`.
//!
//! Because the lookup precedes any WAL-logged mutation, a rejected insert performs **zero** writes,
//! so the index is provably unchanged — the acceptance-criterion guarantee, asserted in
//! `tests/constraints.rs`.

use graphus_core::error::Result;
use graphus_core::{TxnId, Value};
use graphus_io::BlockDevice;
use graphus_wal::LogSink;

use crate::btree::BTree;
use crate::keycodec;

/// A constraint violation. Mapped by the Cypher layer to the TCK error class (`04 §7.3`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConstraintError {
    /// A uniqueness constraint was violated: `value` is already owned by record `existing`.
    Duplicate {
        /// The token (label/reltype) the unique index is scoped to.
        token: u32,
        /// The id of the record that already holds the value.
        existing: u64,
    },
    /// An existence constraint was violated: required property key `required` is absent.
    MissingProperty {
        /// The token (label/reltype) the constraint is scoped to.
        token: u32,
        /// The required property key that was absent.
        required: u32,
    },
    /// The value cannot participate in a constraint key (e.g. `Null`, `List`).
    Unindexable(String),
}

impl std::fmt::Display for ConstraintError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Duplicate { token, existing } => write!(
                f,
                "uniqueness constraint violated for token {token}: value already owned by record {existing}"
            ),
            Self::MissingProperty { token, required } => write!(
                f,
                "existence constraint violated for token {token}: required property key {required} is absent"
            ),
            Self::Unindexable(t) => write!(f, "value cannot be a constraint key: {t}"),
        }
    }
}

impl std::error::Error for ConstraintError {}

impl From<ConstraintError> for graphus_core::GraphusError {
    fn from(e: ConstraintError) -> Self {
        // Constraint violations are *runtime* Cypher errors (`04 §7.3`).
        graphus_core::GraphusError::Runtime(e.to_string())
    }
}

/// An existence constraint: every record scoped to `token` must carry property key `required`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExistenceConstraint {
    /// The label/reltype the constraint applies to.
    pub token: u32,
    /// The property key that must be present.
    pub required: u32,
}

impl ExistenceConstraint {
    /// Creates an existence constraint.
    #[must_use]
    pub fn new(token: u32, required: u32) -> Self {
        Self { token, required }
    }

    /// Checks a record carrying `present_keys`; fails if [`Self::required`] is absent. Pure, no I/O,
    /// no mutation — so rejection is atomic by construction (`04 §6.5`).
    ///
    /// # Errors
    /// Returns [`ConstraintError::MissingProperty`] if the required key is not in `present_keys`.
    pub fn check(&self, present_keys: &[u32]) -> std::result::Result<(), ConstraintError> {
        if present_keys.contains(&self.required) {
            Ok(())
        } else {
            Err(ConstraintError::MissingProperty {
                token: self.token,
                required: self.required,
            })
        }
    }
}

/// A uniqueness constraint enforced by a unique B+-tree index (one record id per value).
///
/// The index key is `(token, value)` with **no record-id suffix**, so distinct records carrying
/// the same value collide on the same B+-tree key — which is exactly how the constraint detects a
/// duplicate.
pub struct UniqueConstraint<D: BlockDevice, S: LogSink> {
    tree: BTree<D, S>,
    token: u32,
}

impl<D: BlockDevice, S: LogSink> UniqueConstraint<D, S> {
    /// Wraps a [`BTree`] as a unique index scoped to `token`.
    #[must_use]
    pub fn new(tree: BTree<D, S>, token: u32) -> Self {
        Self { tree, token }
    }

    /// Borrows the underlying tree (flush / recovery wiring).
    pub fn tree_mut(&mut self) -> &mut BTree<D, S> {
        &mut self.tree
    }

    /// The unique-index key for `value`: `(token, value)` with no id suffix.
    fn key(&self, value: &Value) -> std::result::Result<Vec<u8>, ConstraintError> {
        let tail = keycodec::encode_single(value)
            .map_err(|e| ConstraintError::Unindexable(e.to_string()))?;
        Ok(keycodec::with_token_prefix(self.token, &tail))
    }

    /// The record id currently owning `value`, or `None`.
    ///
    /// # Errors
    /// Propagates a B+-tree fetch failure; returns [`graphus_core::GraphusError::Runtime`] for an
    /// unindexable value.
    pub fn owner(&mut self, value: &Value) -> Result<Option<u64>> {
        let k = self.key(value).map_err(graphus_core::GraphusError::from)?;
        Ok(self
            .tree
            .lookup(&k)?
            .and_then(|v| v.try_into().ok().map(u64::from_le_bytes)))
    }

    /// Inserts `value -> rid` under `txn`, **atomically rejecting** a duplicate.
    ///
    /// The committed-state lookup precedes any mutation, so on rejection the index performs zero
    /// writes and is provably unchanged (`04 §6.5`). Re-inserting the *same* `rid` for a value it
    /// already owns is idempotent (no error).
    ///
    /// # Errors
    /// Returns [`graphus_core::GraphusError::Runtime`] wrapping [`ConstraintError::Duplicate`] if a
    /// *different* record already owns `value`; propagates B+-tree/WAL failures otherwise.
    pub fn insert(&mut self, txn: TxnId, value: &Value, rid: u64) -> Result<()> {
        let k = self.key(value).map_err(graphus_core::GraphusError::from)?;
        if let Some(existing) = self.tree.lookup(&k)? {
            let existing = u64::from_le_bytes(existing.try_into().map_err(|_| {
                graphus_core::GraphusError::Storage("corrupt unique-index payload".to_owned())
            })?);
            if existing != rid {
                return Err(ConstraintError::Duplicate {
                    token: self.token,
                    existing,
                }
                .into());
            }
            return Ok(()); // idempotent: same rid already owns the value
        }
        self.tree.insert(txn, &k, &rid.to_le_bytes())
    }

    /// Removes the entry for `value` under `txn`, returning whether it was present.
    ///
    /// # Errors
    /// Propagates a B+-tree/WAL failure; runtime error for an unindexable value.
    pub fn remove(&mut self, txn: TxnId, value: &Value) -> Result<bool> {
        let k = self.key(value).map_err(graphus_core::GraphusError::from)?;
        self.tree.delete(txn, &k)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::recovery::SharedWal;
    use graphus_bufpool::BufferPool;
    use graphus_io::MemBlockDevice;
    use graphus_wal::{MemLogSink, WalManager};

    fn fresh_tree() -> BTree<MemBlockDevice, MemLogSink> {
        let wal = WalManager::create(MemLogSink::new()).unwrap();
        let shared = SharedWal::new(wal);
        let pool = BufferPool::with_wal(MemBlockDevice::new(0), shared.clone(), 64);
        BTree::create(pool, shared).unwrap()
    }

    #[test]
    fn existence_check_passes_when_present_fails_when_absent() {
        let c = ExistenceConstraint::new(1, 42);
        assert!(c.check(&[1, 42, 7]).is_ok());
        assert_eq!(
            c.check(&[1, 7]),
            Err(ConstraintError::MissingProperty {
                token: 1,
                required: 42
            })
        );
    }

    #[test]
    fn unique_rejects_duplicate_and_leaves_index_unchanged() {
        let mut c = UniqueConstraint::new(fresh_tree(), 1);
        let txn = TxnId(1);
        c.tree_mut().with_wal(|w| w.begin(txn));
        c.insert(txn, &Value::String("a@x.com".to_owned()), 100)
            .unwrap();
        c.tree_mut().with_wal(|w| w.commit(txn).unwrap());

        // Capture state before the rejected insert.
        let before = c.tree_mut().scan_all().unwrap();
        let txn2 = TxnId(2);
        c.tree_mut().with_wal(|w| w.begin(txn2));
        let err = c
            .insert(txn2, &Value::String("a@x.com".to_owned()), 200)
            .unwrap_err();
        assert!(matches!(err, graphus_core::GraphusError::Runtime(_)));
        // The index must be byte-for-byte unchanged: the duplicate insert wrote nothing.
        let after = c.tree_mut().scan_all().unwrap();
        assert_eq!(
            before, after,
            "rejected duplicate must not mutate the index"
        );
        // The original owner is intact.
        assert_eq!(
            c.owner(&Value::String("a@x.com".to_owned())).unwrap(),
            Some(100)
        );
    }

    #[test]
    fn unique_same_rid_is_idempotent() {
        let mut c = UniqueConstraint::new(fresh_tree(), 1);
        let txn = TxnId(1);
        c.tree_mut().with_wal(|w| w.begin(txn));
        c.insert(txn, &Value::Integer(7), 100).unwrap();
        c.insert(txn, &Value::Integer(7), 100).unwrap(); // same rid -> ok
        c.tree_mut().with_wal(|w| w.commit(txn).unwrap());
        assert_eq!(c.owner(&Value::Integer(7)).unwrap(), Some(100));
    }

    #[test]
    fn unique_allows_distinct_values() {
        let mut c = UniqueConstraint::new(fresh_tree(), 1);
        let txn = TxnId(1);
        c.tree_mut().with_wal(|w| w.begin(txn));
        c.insert(txn, &Value::Integer(1), 10).unwrap();
        c.insert(txn, &Value::Integer(2), 20).unwrap();
        c.tree_mut().with_wal(|w| w.commit(txn).unwrap());
        assert_eq!(c.owner(&Value::Integer(1)).unwrap(), Some(10));
        assert_eq!(c.owner(&Value::Integer(2)).unwrap(), Some(20));
    }
}
