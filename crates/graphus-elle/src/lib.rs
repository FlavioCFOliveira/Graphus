//! `graphus-elle` — an Elle/Adya-style **isolation-anomaly checker** for Graphus
//! (`04-technical-design.md` §11; one of the four DST oracles). It certifies that a recorded
//! transaction history is **serializable** (the ACID "I"): if the SSI engine ever produced a history
//! that is not, this finds it.
//!
//! ## The list-append model (why it is self-recoverable)
//!
//! Each object (a [`Key`]) holds a **list**. A transaction either **appends** a value (unique per
//! key) or **reads** the whole list. Because appended values are unique and a read returns the list
//! *in order*, the observed lists reveal the true **version order** of each key — no external schedule
//! is needed. This is Elle's key idea (Kingsbury & Alvaro): recover the dependency graph from the
//! observed values alone.
//!
//! ## The check (Adya's formalism)
//!
//! From the committed transactions we build a directed graph over transactions with three edge kinds:
//!
//! - **ww** (write-depends): the writer of version `v_i` precedes the writer of `v_{i+1}` (consecutive
//!   in a key's recovered order).
//! - **wr** (read-depends): a reader that observed `v` depends on the transaction that wrote `v`.
//! - **rw** (anti-depends): a reader that observed up to `v_i` (but not the next version `v_{i+1}`)
//!   precedes the writer of `v_{i+1}` — it must serialize *before* that later write.
//!
//! A **cycle** in this graph is a serializability violation (Adya's G0/G1c/G2 phenomena: dirty
//! writes, lost updates, write skew, …). A serializable execution is acyclic.
#![forbid(unsafe_code)]

use std::collections::{HashMap, HashSet};

/// A transaction identifier (unique within a history).
pub type TxId = u64;
/// An object key (each holds an append-only list).
pub type Key = String;
/// A value appended to a key's list (unique per key in the list-append model).
pub type Val = i64;

/// One operation inside a transaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Op {
    /// Append `val` to `key`'s list.
    Append {
        /// The target key.
        key: Key,
        /// The unique value appended.
        val: Val,
    },
    /// Read `key`'s whole list, observing `observed` (in order).
    Read {
        /// The key read.
        key: Key,
        /// The list the read observed, in order.
        observed: Vec<Val>,
    },
}

/// One transaction: its ops, in order, and whether it **committed** (only committed transactions
/// constrain serializability; aborted ones leave no trace).
#[derive(Debug, Clone)]
pub struct Transaction {
    /// The transaction id.
    pub id: TxId,
    /// The ops, in execution order.
    pub ops: Vec<Op>,
    /// Whether the transaction committed.
    pub committed: bool,
}

impl Transaction {
    /// A committed transaction from `ops`.
    #[must_use]
    pub fn committed(id: TxId, ops: Vec<Op>) -> Self {
        Self {
            id,
            ops,
            committed: true,
        }
    }

    /// An aborted transaction from `ops`.
    #[must_use]
    pub fn aborted(id: TxId, ops: Vec<Op>) -> Self {
        Self {
            id,
            ops,
            committed: false,
        }
    }
}

/// A recorded history: the transactions in some observation order.
pub type History = Vec<Transaction>;

/// The checker's verdict.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Verdict {
    /// `true` if the committed sub-history is serializable (no dependency cycle, consistent orders).
    pub serializable: bool,
    /// A human-readable description of the first anomaly found, if any.
    pub anomaly: Option<String>,
}

impl Verdict {
    /// A clean (serializable) verdict.
    #[must_use]
    pub fn ok() -> Self {
        Self {
            serializable: true,
            anomaly: None,
        }
    }

    /// A violation verdict carrying `reason`.
    #[must_use]
    pub fn violation(reason: impl Into<String>) -> Self {
        Self {
            serializable: false,
            anomaly: Some(reason.into()),
        }
    }
}

/// Checks `history` for isolation anomalies, returning a [`Verdict`].
///
/// Considers only committed transactions. Recovers each key's version order from the observed reads,
/// rejects mutually-inconsistent read orders, builds the ww/wr/rw dependency graph, and reports the
/// first dependency cycle it finds (a serializability violation).
#[must_use]
pub fn check(history: &History) -> Verdict {
    let committed: Vec<&Transaction> = history.iter().filter(|t| t.committed).collect();

    // writer_of[(key, val)] = the tx that appended `val` to `key`.
    let mut writer_of: HashMap<(Key, Val), TxId> = HashMap::new();
    for t in &committed {
        for op in &t.ops {
            if let Op::Append { key, val } = op {
                if let Some(prev) = writer_of.insert((key.clone(), *val), t.id) {
                    if prev != t.id {
                        return Verdict::violation(format!(
                            "value {val} appended to key {key:?} by two transactions ({prev}, {})",
                            t.id
                        ));
                    }
                }
            }
        }
    }

    // Recover each key's version order = the longest observed read for that key; every other observed
    // read for the key must be a prefix of it (consistent-order property under serializability).
    let mut order: HashMap<Key, Vec<Val>> = HashMap::new();
    for t in &committed {
        for op in &t.ops {
            if let Op::Read { key, observed } = op {
                let cur = order.entry(key.clone()).or_default();
                if observed.len() > cur.len() {
                    if !cur.iter().zip(observed).all(|(a, b)| a == b) {
                        return Verdict::violation(format!(
                            "incompatible read orders for key {key:?}: {cur:?} vs {observed:?}"
                        ));
                    }
                    *cur = observed.clone();
                } else if !observed.iter().zip(cur.iter()).all(|(a, b)| a == b) {
                    return Verdict::violation(format!(
                        "incompatible read orders for key {key:?}: {observed:?} not a prefix of {cur:?}"
                    ));
                }
            }
        }
    }

    // index_in_order[(key, val)] = position of `val` in the key's recovered order.
    let mut index_in_order: HashMap<(Key, Val), usize> = HashMap::new();
    for (key, vals) in &order {
        for (i, v) in vals.iter().enumerate() {
            index_in_order.insert((key.clone(), *v), i);
        }
    }

    let mut graph: HashMap<TxId, HashSet<TxId>> = HashMap::new();
    let add_edge = |from: TxId, to: TxId, graph: &mut HashMap<TxId, HashSet<TxId>>| {
        if from != to {
            graph.entry(from).or_default().insert(to);
        }
    };

    // ww edges: consecutive versions in each key's order.
    for (key, vals) in &order {
        for pair in vals.windows(2) {
            let (a, b) = (pair[0], pair[1]);
            if let (Some(&wa), Some(&wb)) = (
                writer_of.get(&(key.clone(), a)),
                writer_of.get(&(key.clone(), b)),
            ) {
                add_edge(wa, wb, &mut graph);
            }
        }
    }

    // All committed (value, writer) pairs per key — so the anti-dependency also covers values that
    // were written but never read back (e.g. classic write skew, where neither side reads the other's
    // write). Without this, an unread write leaves no trace and the cycle is missed.
    let mut values_of_key: HashMap<Key, Vec<(Val, TxId)>> = HashMap::new();
    for ((key, val), &w) in &writer_of {
        values_of_key
            .entry(key.clone())
            .or_default()
            .push((*val, w));
    }

    // wr + rw edges from each committed read.
    for t in &committed {
        for op in &t.ops {
            let Op::Read { key, observed } = op else {
                continue;
            };
            // wr: this reader depends on the writer of every value it observed.
            for v in observed {
                if let Some(&w) = writer_of.get(&(key.clone(), *v)) {
                    add_edge(w, t.id, &mut graph);
                }
            }
            // rw (anti-dependency): for every committed value of this key the reader did NOT observe,
            // the reader serializes *before* that value's writer (it read a state without that write).
            if let Some(vals) = values_of_key.get(key) {
                for (v, w) in vals {
                    if !observed.contains(v) {
                        add_edge(t.id, *w, &mut graph);
                    }
                }
            }
        }
    }

    // Cycle detection (iterative DFS with colours), reporting the first cycle.
    if let Some(cycle) = find_cycle(&committed, &graph) {
        return Verdict::violation(format!("dependency cycle (non-serializable): {cycle:?}"));
    }
    Verdict::ok()
}

/// Returns a transaction-id cycle if the dependency graph has one, else `None`. DFS with a recursion
/// stack; tries each committed transaction as a root.
fn find_cycle(
    committed: &[&Transaction],
    graph: &HashMap<TxId, HashSet<TxId>>,
) -> Option<Vec<TxId>> {
    #[derive(Clone, Copy, PartialEq)]
    enum Colour {
        White,
        Grey,
        Black,
    }
    let mut colour: HashMap<TxId, Colour> =
        committed.iter().map(|t| (t.id, Colour::White)).collect();

    // Iterative DFS preserving the path so a back-edge yields the actual cycle.
    for t in committed {
        if colour.get(&t.id) != Some(&Colour::White) {
            continue;
        }
        // Stack of (node, iterator-position over its sorted successors); `path` mirrors the grey stack.
        let mut path: Vec<TxId> = Vec::new();
        let mut stack: Vec<(TxId, Vec<TxId>, usize)> = Vec::new();
        let succ = |n: TxId| -> Vec<TxId> {
            let mut s: Vec<TxId> = graph
                .get(&n)
                .map(|e| e.iter().copied().collect())
                .unwrap_or_default();
            s.sort_unstable(); // deterministic traversal
            s
        };
        colour.insert(t.id, Colour::Grey);
        path.push(t.id);
        stack.push((t.id, succ(t.id), 0));

        while let Some((node, succs, idx)) = stack.last_mut() {
            if *idx < succs.len() {
                let next = succs[*idx];
                *idx += 1;
                match colour.get(&next).copied().unwrap_or(Colour::Black) {
                    Colour::White => {
                        colour.insert(next, Colour::Grey);
                        path.push(next);
                        let s = succ(next);
                        stack.push((next, s, 0));
                    }
                    Colour::Grey => {
                        // Back-edge: extract the cycle from `path` starting at `next`.
                        let start = path.iter().position(|&x| x == next).unwrap_or(0);
                        let mut cycle = path[start..].to_vec();
                        cycle.push(next);
                        return Some(cycle);
                    }
                    Colour::Black => {}
                }
            } else {
                let done = *node;
                colour.insert(done, Colour::Black);
                path.pop();
                stack.pop();
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn append(key: &str, val: Val) -> Op {
        Op::Append {
            key: key.to_owned(),
            val,
        }
    }
    fn read(key: &str, observed: &[Val]) -> Op {
        Op::Read {
            key: key.to_owned(),
            observed: observed.to_vec(),
        }
    }

    #[test]
    fn serial_history_is_clean() {
        // T1 appends a=1; T2 reads [1] then appends a=2; T3 reads [1,2].
        let h = vec![
            Transaction::committed(1, vec![append("a", 1)]),
            Transaction::committed(2, vec![read("a", &[1]), append("a", 2)]),
            Transaction::committed(3, vec![read("a", &[1, 2])]),
        ];
        assert_eq!(check(&h), Verdict::ok());
    }

    #[test]
    fn write_skew_cycle_is_detected() {
        // Classic write-skew: T1 reads y (empty), writes x; T2 reads x (empty), writes y. Each missed
        // the other's write ⇒ rw edges both ways ⇒ cycle ⇒ non-serializable.
        let h = vec![
            Transaction::committed(1, vec![read("y", &[]), append("x", 1)]),
            Transaction::committed(2, vec![read("x", &[]), append("y", 1)]),
        ];
        let v = check(&h);
        assert!(!v.serializable, "write skew must be flagged: {v:?}");
        assert!(v.anomaly.unwrap().contains("cycle"));
    }

    #[test]
    fn lost_update_cycle_is_detected() {
        // Both T1 and T2 read the same empty list and each appends "first" (value 1 / 2) believing it
        // is the head — an inconsistent order or a cycle. Here both read [] then write the SAME key,
        // so the recovered order is [1,2] or [2,1]; each read missed the other's write ⇒ rw both ways.
        let h = vec![
            Transaction::committed(1, vec![read("a", &[]), append("a", 1)]),
            Transaction::committed(2, vec![read("a", &[]), append("a", 2)]),
        ];
        let v = check(&h);
        assert!(
            !v.serializable,
            "concurrent blind appends to one key are non-serializable: {v:?}"
        );
    }

    #[test]
    fn aborted_transactions_do_not_constrain() {
        // An aborted T2 leaves no trace; the rest is serial.
        let h = vec![
            Transaction::committed(1, vec![append("a", 1)]),
            Transaction::aborted(2, vec![read("a", &[1]), append("a", 99)]),
            Transaction::committed(3, vec![read("a", &[1])]),
        ];
        assert_eq!(check(&h), Verdict::ok());
    }

    #[test]
    fn incompatible_read_orders_are_flagged() {
        // Two committed reads disagree on the order of the same key (not prefix-consistent).
        let h = vec![
            Transaction::committed(1, vec![append("a", 1), append("a", 2)]),
            Transaction::committed(2, vec![read("a", &[1, 2])]),
            Transaction::committed(3, vec![read("a", &[2, 1])]),
        ];
        let v = check(&h);
        assert!(
            !v.serializable,
            "contradictory read orders are an anomaly: {v:?}"
        );
    }

    #[test]
    fn check_is_deterministic() {
        let h = vec![
            Transaction::committed(1, vec![read("y", &[]), append("x", 1)]),
            Transaction::committed(2, vec![read("x", &[]), append("y", 1)]),
        ];
        assert_eq!(check(&h), check(&h));
    }
}
