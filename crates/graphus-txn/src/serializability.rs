//! A deterministic **serialization-graph checker** for transaction histories (Elle/Jepsen-style).
//!
//! This is the empirical correctness oracle the manager is validated against (acceptance criterion:
//! *"Elle/Jepsen-style anomaly checks find no anomalies at the default level"*). It is independent
//! of the manager: it consumes a *recorded history* and decides serializability by the textbook
//! theorem (Adya; Berenson et al. — `04 §13`):
//!
//! > An execution is serializable **iff** its **Direct Serialization Graph (DSG)** is acyclic.
//!
//! The DSG has one node per committed transaction and three edge kinds, all derived purely from the
//! recorded read/write operations and the per-key **version order**:
//!
//! - **ww (`T1 → T2`)** — `T2` installs the version of a key that directly follows `T1`'s version.
//! - **wr (`T1 → T2`)** — `T2` reads a version that `T1` installed (read-depends).
//! - **rw (`T1 → T2`)** — `T1` reads version `vi` of a key and `T2` installs the *next* version
//!   `vi+1` of that key (the rw-antidependency SSI is built to catch, `04 §5.4`).
//!
//! [`HistoryChecker::find_anomaly`] returns a cycle (as the transaction ids on it) if one exists,
//! and `None` otherwise. Used in tests two ways: it must report **no** cycle for any history the
//! SERIALIZABLE manager produced, and it must **catch** a cycle in a hand-built anomalous history
//! (so the checker is proven to have teeth, not vacuously pass).

use std::collections::{BTreeMap, BTreeSet};

use graphus_core::TxnId;

use crate::store::Key;

/// A single recorded operation within a transaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Op {
    /// Read key `key`, observing version `version` (the version's monotonic write sequence number
    /// on that key; `0` means "the initial / pre-history version").
    Read {
        /// The key read.
        key: Key,
        /// The version number observed.
        version: u64,
    },
    /// Wrote key `key`, installing version `version` (strictly increasing per key, starting at `1`).
    Write {
        /// The key written.
        key: Key,
        /// The version number installed.
        version: u64,
    },
}

/// One committed transaction's recorded operations, in program order.
#[derive(Debug, Clone)]
pub struct TxnHistory {
    /// The transaction id.
    pub txn: TxnId,
    /// Its operations in order.
    pub ops: Vec<Op>,
}

impl TxnHistory {
    /// A new, empty history for `txn`.
    #[must_use]
    pub fn new(txn: TxnId) -> Self {
        Self {
            txn,
            ops: Vec::new(),
        }
    }

    /// Records a read of `key` observing `version`.
    pub fn read(&mut self, key: Key, version: u64) {
        self.ops.push(Op::Read { key, version });
    }

    /// Records a write of `key` installing `version`.
    pub fn write(&mut self, key: Key, version: u64) {
        self.ops.push(Op::Write { key, version });
    }
}

/// Builds and checks the Direct Serialization Graph of a set of committed transactions.
#[derive(Debug, Default)]
pub struct HistoryChecker {
    histories: Vec<TxnHistory>,
}

impl HistoryChecker {
    /// An empty checker.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds one committed transaction's history.
    pub fn add(&mut self, history: TxnHistory) {
        self.histories.push(history);
    }

    /// Returns the transaction ids on a serialization cycle if the history is non-serializable, or
    /// `None` if its DSG is acyclic (serializable).
    ///
    /// The returned vector lists the transactions of one cycle in traversal order; its mere
    /// presence is the anomaly. Edge construction is documented at the module level.
    #[must_use]
    pub fn find_anomaly(&self) -> Option<Vec<TxnId>> {
        let edges = self.build_edges();
        find_cycle(&edges)
    }

    /// Builds the DSG edge set (deduplicated, ignoring self-edges). Public for white-box tests that
    /// assert the exact edges derived from a history.
    #[must_use]
    pub fn build_edges(&self) -> BTreeSet<(TxnId, TxnId)> {
        // Index 1: writer of (key, version).
        let mut writer_of: BTreeMap<(Key, u64), TxnId> = BTreeMap::new();
        for h in &self.histories {
            for op in &h.ops {
                if let Op::Write { key, version } = op {
                    writer_of.insert((*key, *version), h.txn);
                }
            }
        }

        let mut edges: BTreeSet<(TxnId, TxnId)> = BTreeSet::new();
        let push = |a: TxnId, b: TxnId, edges: &mut BTreeSet<(TxnId, TxnId)>| {
            if a != b {
                edges.insert((a, b));
            }
        };

        for h in &self.histories {
            for op in &h.ops {
                match *op {
                    Op::Write { key, version } => {
                        // ww: predecessor version's writer -> this writer.
                        if version > 1
                            && let Some(&prev) = writer_of.get(&(key, version - 1))
                        {
                            push(prev, h.txn, &mut edges);
                        }
                    }
                    Op::Read { key, version } => {
                        // wr: writer of the observed version -> this reader.
                        if let Some(&w) = writer_of.get(&(key, version)) {
                            push(w, h.txn, &mut edges);
                        }
                        // rw: this reader -> writer of the *next* version (anti-dependency).
                        if let Some(next_version) = version.checked_add(1)
                            && let Some(&w_next) = writer_of.get(&(key, next_version))
                        {
                            push(h.txn, w_next, &mut edges);
                        }
                    }
                }
            }
        }
        edges
    }
}

/// Finds a directed cycle in an edge set, returning its nodes in traversal order, or `None`.
fn find_cycle(edges: &BTreeSet<(TxnId, TxnId)>) -> Option<Vec<TxnId>> {
    // Adjacency list.
    let mut adj: BTreeMap<TxnId, Vec<TxnId>> = BTreeMap::new();
    let mut nodes: BTreeSet<TxnId> = BTreeSet::new();
    for &(a, b) in edges {
        adj.entry(a).or_default().push(b);
        nodes.insert(a);
        nodes.insert(b);
    }

    let mut visiting: BTreeSet<TxnId> = BTreeSet::new();
    let mut visited: BTreeSet<TxnId> = BTreeSet::new();

    for &start in &nodes {
        if !visited.contains(&start) {
            let mut stack: Vec<TxnId> = Vec::new();
            if let Some(cycle) = dfs_cycle(start, &adj, &mut visiting, &mut visited, &mut stack) {
                return Some(cycle);
            }
        }
    }
    None
}

fn dfs_cycle(
    node: TxnId,
    adj: &BTreeMap<TxnId, Vec<TxnId>>,
    visiting: &mut BTreeSet<TxnId>,
    visited: &mut BTreeSet<TxnId>,
    stack: &mut Vec<TxnId>,
) -> Option<Vec<TxnId>> {
    visiting.insert(node);
    stack.push(node);
    if let Some(targets) = adj.get(&node) {
        for &next in targets {
            if visiting.contains(&next) {
                // Back-edge: the cycle is `next .. top-of-stack`.
                if let Some(pos) = stack.iter().position(|t| *t == next) {
                    return Some(stack[pos..].to_vec());
                }
            } else if !visited.contains(&next)
                && let Some(cycle) = dfs_cycle(next, adj, visiting, visited, stack)
            {
                return Some(cycle);
            }
        }
    }
    stack.pop();
    visiting.remove(&node);
    visited.insert(node);
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_history_is_serializable() {
        let c = HistoryChecker::new();
        assert_eq!(c.find_anomaly(), None);
    }

    #[test]
    fn sequential_history_has_no_cycle() {
        // T1 writes x=1; T2 reads x=1 and writes x=2. A clean wr + ww chain, no cycle.
        let mut c = HistoryChecker::new();
        let mut t1 = TxnHistory::new(TxnId(1));
        t1.write(100, 1);
        let mut t2 = TxnHistory::new(TxnId(2));
        t2.read(100, 1);
        t2.write(100, 2);
        c.add(t1);
        c.add(t2);
        assert_eq!(c.find_anomaly(), None);
        // Edges: wr(1->2) from the read, ww(1->2) from the successor write.
        let edges = c.build_edges();
        assert!(edges.contains(&(TxnId(1), TxnId(2))));
        assert!(!edges.contains(&(TxnId(2), TxnId(1))));
    }

    #[test]
    fn write_skew_history_is_caught() {
        // The teeth test. Write-skew G2: two concurrent txns each read the other's pre-write
        // version (initial version 0) and write a new version, producing rw edges both ways.
        // T1: read y@0, write x=1.  T2: read x@0, write y=1.
        // rw edges: T1 read x@0 ... actually model directly:
        //   T1 reads y (version 0), writes x (version 1)
        //   T2 reads x (version 0), writes y (version 1)
        // rw(T1 -> writer of y@1 = T2); rw(T2 -> writer of x@1 = T1) -> cycle T1<->T2.
        let mut c = HistoryChecker::new();
        let mut t1 = TxnHistory::new(TxnId(1));
        t1.read(200, 0); // read y, initial
        t1.write(100, 1); // write x
        let mut t2 = TxnHistory::new(TxnId(2));
        t2.read(100, 0); // read x, initial
        t2.write(200, 1); // write y
        c.add(t1);
        c.add(t2);

        let edges = c.build_edges();
        assert!(edges.contains(&(TxnId(1), TxnId(2))), "rw T1->T2 expected");
        assert!(edges.contains(&(TxnId(2), TxnId(1))), "rw T2->T1 expected");

        let cycle = c.find_anomaly().expect("write-skew must be flagged");
        assert!(cycle.contains(&TxnId(1)) && cycle.contains(&TxnId(2)));
    }

    #[test]
    fn g2_item_three_txn_cycle_is_caught() {
        // A longer anti-dependency cycle T1 -> T2 -> T3 -> T1 to show the checker is not limited to
        // 2-cycles. Each reads the initial version and writes the key the next one read.
        let mut c = HistoryChecker::new();
        let mut t1 = TxnHistory::new(TxnId(1));
        t1.read(10, 0);
        t1.write(20, 1); // T1 -> writer of 20@1 (T2)
        let mut t2 = TxnHistory::new(TxnId(2));
        t2.read(20, 0);
        t2.write(30, 1); // T2 -> writer of 30@1 (T3)
        let mut t3 = TxnHistory::new(TxnId(3));
        t3.read(30, 0);
        t3.write(10, 1); // T3 -> writer of 10@1 (T1)
        c.add(t1);
        c.add(t2);
        c.add(t3);
        let cycle = c.find_anomaly().expect("3-cycle must be flagged");
        assert_eq!(cycle.len(), 3);
    }

    #[test]
    fn read_only_no_cycle() {
        let mut c = HistoryChecker::new();
        let mut t1 = TxnHistory::new(TxnId(1));
        t1.write(100, 1);
        let mut t2 = TxnHistory::new(TxnId(2));
        t2.read(100, 1); // read-only after T1
        c.add(t1);
        c.add(t2);
        assert_eq!(c.find_anomaly(), None);
    }
}
