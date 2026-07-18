//! Focused deterministic reproducer for **a rolled-back LABEL change clobbering a concurrently
//! committed PROPERTY write on the same node** (`rmp` #772) — the direct sibling of the free-list
//! double-allocation reproducer ([`crate::freelist_reuse`], `rmp` #578). Both are committed-data-loss
//! defects caused by a **live rollback** perturbing a field a concurrently-committed transaction owns,
//! reachable only through the statement-interleaving the generic [`crate::harness`] never performs.
//!
//! ## The defect
//!
//! `add_label` / `remove_label` change only the node record's 8-byte `labels` word, but persisted the
//! change with a **whole-record** pre-image undo ([`RecordStore::write_node`] -> `write_region`). The
//! node record's OTHER words are concurrently shared: a different transaction's `SET n.prop`
//! (`add_node_property`) pushes onto the same record's `first_prop` head via the compare-and-set
//! `write_chain_head` (`rmp` #220/#172) and MVCC-tombstones the old property. When the label writer
//! **live-rolls-back** AFTER that transaction committed, replaying the whole-record pre-image reverts
//! `first_prop` to its pre-commit value — orphaning the committed property version (whose predecessor
//! the committer tombstoned on a byte region the whole-record undo does not restore). The committed
//! value is destroyed.
//!
//! ## Why it needs the DST, not the generic harness
//!
//! The corruption requires three statement-interleaved transactions over one node — a **seed**
//! committing a labelled node with a property; **W1** removing the label and staying *open*; **W2**
//! setting the property and *committing* on top of W1's uncommitted record; then **W1 rolling back**.
//! Driven at the [`RecordStore`] layer (below the coordinator's lock table — exactly the unguarded
//! `IsolationLevel::Snapshot` write path the bug is reachable through), it is fully deterministic.
//!
//! ## The invariant asserted
//!
//! After W1 rolls back, node `n`'s `first_prop` head still points at W2's committed property record
//! `p1` (NOT reverted to the pre-commit `p0`), and `p1` still decodes to W2's committed value.
//! Pre-fix the head is reverted to `p0` (which W2 tombstoned) and the committed value is lost; the
//! crash-recovery variant proves the fix's compare-and-set undo CLRs replay identically on `open`.
//!
//! The fix ([`RecordStore::write_node_labels`], `rmp` #772) scopes the write and its undo to the
//! `labels` word alone with the same CAS logical-undo discipline the three chain-participating writes
//! already use.

use graphus_core::{PageId, Value};
use graphus_io::{BlockDevice, MemBlockDevice};
use graphus_storage::RecordStore;
use graphus_wal::{LogSink, MemLogSink, WalManager};

use graphus_core::TxnId;

/// The store type the reproducer drives: the record store over the in-memory DST device + log.
type Store = RecordStore<MemBlockDevice, MemLogSink>;

/// A small buffer-pool capacity, so eviction + the WAL rule are exercised during the run.
const POOL_CAPACITY: usize = 16;
/// The single label bit W1 removes and its rollback must restore.
const LABEL_BIT: u32 = 0;
/// The single property key W2 overwrites.
const PROP_KEY: u32 = 0;

fn next_txn(next: &mut u64) -> TxnId {
    let id = TxnId(*next);
    *next += 1;
    id
}

/// The outcome of one reproduction: the observed physical state after W1's rollback.
#[derive(Debug, Clone, PartialEq)]
pub struct LabelRollbackReport {
    /// W2's committed property record id (the head that must survive).
    pub committed_prop_id: u64,
    /// The node's `first_prop` head AFTER W1's rollback. Post-fix `== committed_prop_id`; pre-fix it
    /// is reverted to the tombstoned pre-commit record (the defect).
    pub first_prop_after_rollback: u64,
    /// The value read back from the node's `first_prop` head after W1's rollback. Post-fix this is
    /// W2's committed value; pre-fix the head points at a tombstoned record (committed value lost).
    pub head_value_after_rollback: Value,
    /// Whether node `n` still carries `LABEL_BIT` after W1's rollback (W1's own change undone).
    pub label_restored: bool,
}

impl LabelRollbackReport {
    /// The `rmp` #772 invariant: W2's committed property survived W1's rollback and W1's own label
    /// change was cleanly undone.
    #[must_use]
    pub fn committed_property_survived(&self) -> bool {
        self.first_prop_after_rollback == self.committed_prop_id
            && self.head_value_after_rollback == Value::String("committed@x.io".to_owned())
            && self.label_restored
    }
}

/// Drives the three-transaction interleaving to completion (through W1's rollback) and returns the
/// `(store, node_id, committed_prop_id)`. The store is left with W2 committed and W1 rolled back.
fn drive_scenario() -> (Store, u64, u64) {
    let device = MemBlockDevice::new(0);
    let wal = WalManager::create(MemLogSink::new()).expect("create wal");
    let mut store: Store =
        RecordStore::create(device, wal, POOL_CAPACITY, 1).expect("create store");
    let mut next = 1u64;

    // Seed: a committed labelled node carrying `original@x.io`.
    let t0 = next_txn(&mut next);
    store.begin(t0);
    let (n, _eid) = store.create_node(t0).expect("create node");
    store.add_label(t0, n, LABEL_BIT).expect("seed label");
    store
        .set_node_property_value(t0, n, PROP_KEY, &Value::String("original@x.io".to_owned()))
        .expect("seed property");
    store.commit(t0).expect("seed commits");

    // W1: remove the label, left OPEN (captures the whole-record undo image pre-fix).
    let w1 = next_txn(&mut next);
    store.begin(w1);
    store
        .remove_label(w1, n, LABEL_BIT)
        .expect("W1 remove_label");

    // W2: a DIFFERENT transaction overwrites the property and COMMITS on top of W1's open record.
    let w2 = next_txn(&mut next);
    store.begin(w2);
    let p1 = store
        .set_node_property_value(w2, n, PROP_KEY, &Value::String("committed@x.io".to_owned()))
        .expect("W2 set property");
    store.commit(w2).expect("W2 commits");

    // W1 rolls back. Its undo must touch ONLY the labels word, never W2's committed `first_prop`.
    store.rollback(w1).expect("W1 rollback");

    (store, n, p1)
}

/// Reads the physical `(first_prop, head_value, label_present)` for node `n` from a settled store.
fn observe(store: &Store, n: u64) -> (u64, Value, bool) {
    let node = store.node(n).expect("read node n");
    let head_value = if node.first_prop == 0 {
        Value::Null
    } else {
        let head = store.property(node.first_prop).expect("read head prop");
        store
            .decode_property_value(head.type_tag, head.value_inline)
            .expect("decode head value")
    };
    let label_present = node.labels & (1u64 << LABEL_BIT) != 0;
    (node.first_prop, head_value, label_present)
}

/// Runs the live reproduction (no crash) and reports the post-rollback physical state.
#[must_use]
pub fn run_label_rollback_clobber() -> LabelRollbackReport {
    let (store, n, committed_prop_id) = drive_scenario();
    let (first_prop_after_rollback, head_value_after_rollback, label_restored) = observe(&store, n);
    LabelRollbackReport {
        committed_prop_id,
        first_prop_after_rollback,
        head_value_after_rollback,
        label_restored,
    }
}

/// Runs the reproduction, then **crashes** (no-force or steal) and recovers, proving the label CAS
/// undo CLRs replay identically on `open`: W2's committed property still survives and W1's aborted
/// label change stays undone after recovery.
#[must_use]
pub fn run_label_rollback_clobber_crash(steal: bool) -> LabelRollbackReport {
    let (store, n, committed_prop_id) = drive_scenario();
    // Harden the committed + CLR tail so the crash WAL carries the whole history.
    store.with_wal(WalManager::flush);
    let mut store = if steal {
        crash_steal(store)
    } else {
        crash_no_force(store)
    };
    let (first_prop_after_rollback, head_value_after_rollback, label_restored) = observe(&store, n);
    // Touch `store` mutably to mirror the freelist_reuse contract (a recovered store is usable).
    store.flush().expect("flush after recovery");
    LabelRollbackReport {
        committed_prop_id,
        first_prop_after_rollback,
        head_value_after_rollback,
        label_restored,
    }
}

/// No-force crash: rebuild onto a fresh empty device from the durable WAL prefix, then reopen.
fn crash_no_force(store: Store) -> Store {
    let log = store.with_wal(|w| w.sink().durable_bytes().to_vec());
    let mut sink = MemLogSink::new();
    sink.append(&log);
    sink.sync().expect("sync log prefix");
    let mut device = MemBlockDevice::new(0);
    let mut wal = WalManager::open(sink.clone()).expect("open wal");
    graphus_storage::recovery::recover_device(&mut wal, &mut device).expect("recover");
    let wal = WalManager::open(sink).expect("reopen wal");
    RecordStore::open(device, wal, POOL_CAPACITY).expect("open store")
}

/// Steal crash: flush dirty pages home, snapshot that on-disk image, then recover so undo rolls back
/// any stolen uncommitted pages.
fn crash_steal(mut store: Store) -> Store {
    store.flush().expect("flush (steal)");
    let pages = store.mapped_pages();
    let max = pages.iter().map(|p| p.0).max().unwrap_or(0);
    let mut device = MemBlockDevice::new(max + 1);
    for p in &pages {
        let bytes = store.read_device_page(*p).expect("read device page");
        device.write_page(PageId(p.0), &bytes).expect("stage page");
    }
    device.sync_all().expect("persist disk image");

    let log = store.with_wal(|w| w.sink().durable_bytes().to_vec());
    let mut sink = MemLogSink::new();
    sink.append(&log);
    sink.sync().expect("sync log prefix");
    let mut wal = WalManager::open(sink.clone()).expect("open wal");
    graphus_storage::recovery::recover_device(&mut wal, &mut device).expect("recover");
    let wal = WalManager::open(sink).expect("reopen wal");
    RecordStore::open(device, wal, POOL_CAPACITY).expect("open store")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn live_rollback_preserves_committed_property() {
        let report = run_label_rollback_clobber();
        // Non-vacuity: the reproduction actually reached the interleaving — W2 committed a distinct
        // new property record on top of the seed's (`committed_prop_id != 0`).
        assert_ne!(
            report.committed_prop_id, 0,
            "reproduction did not reach W2's committed property write"
        );
        assert!(
            report.committed_property_survived(),
            "W1's rollback destroyed W2's committed property (rmp #772): {report:?}"
        );
    }

    #[test]
    fn crash_recovery_preserves_committed_property() {
        for steal in [false, true] {
            let report = run_label_rollback_clobber_crash(steal);
            assert_ne!(
                report.committed_prop_id, 0,
                "steal={steal}: reproduction did not reach W2's committed property write"
            );
            assert!(
                report.committed_property_survived(),
                "steal={steal}: crash recovery lost W2's committed property (rmp #772): {report:?}"
            );
        }
    }

    #[test]
    fn reproduction_is_deterministic() {
        assert_eq!(run_label_rollback_clobber(), run_label_rollback_clobber());
    }
}
