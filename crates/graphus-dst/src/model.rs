//! The independent reference model of the committed graph, and the acknowledged-commit ledger.
//!
//! The harness never trusts the engine to tell it what *should* be true. It maintains a separate,
//! deliberately simple model of the multigraph built only from the logical effects of transactions
//! whose `commit()` returned `Ok` — the **durability obligations** the engine took on
//! (`specification/04-technical-design.md` §4.2: a commit only returns success after the WAL is
//! group-committed and `fdatasync`'d, so an `Ok` from `commit()` is an acknowledgement). After a
//! crash and recovery, the recovered engine state is checked against this model
//! ([`crate::checker`]).
//!
//! Two facts make the model both an *atomicity* and a *durability* oracle:
//!
//! * effects are applied to the model **only at commit** (a staged set is discarded on rollback or
//!   when a crash leaves the transaction in flight), so anything in the model is an acknowledged
//!   commit — its presence after recovery proves durability, and its *exclusive* presence proves
//!   committed-or-nothing atomicity;
//! * the model is an independent re-derivation, not a copy of engine state, so a corruption that
//!   fooled the engine cannot fool the model.

use std::collections::{BTreeMap, BTreeSet};

/// A property in the reference model: an entity-local `(key, type_tag, value_inline)` triple, the
/// same shape the store persists for an inline property (`04 §2.3`). The set of a node's properties
/// is compared as a multiset (a node may legitimately hold two properties with the same key under
/// the append-only property-chain model).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct PropTriple {
    /// The property-key token id.
    pub key: u32,
    /// The value type tag (`04 §2.3`).
    pub type_tag: u8,
    /// The inline-encoded value.
    pub value_inline: u64,
}

/// The expected committed state of the multigraph, derived independently from acknowledged
/// commits.
///
/// Nodes and relationships are keyed by their **physical id** (the store's internal record number,
/// `04 §2.2`), because that is the handle the harness uses to interrogate the recovered store.
/// Physical ids may be reused after a free + GC; the model mirrors that by removing a deleted
/// entity, so a later reuse of the id simply re-inserts it.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Model {
    /// Live node physical ids.
    nodes: BTreeSet<u64>,
    /// Live relationship physical id -> `(start_node, end_node)`.
    rels: BTreeMap<u64, (u64, u64)>,
    /// Node physical id -> set of incident relationship ids (a self-loop appears once, matching the
    /// distinct-incident-relationships traversal the store performs, `04 §2.4`).
    incidence: BTreeMap<u64, BTreeSet<u64>>,
    /// Node physical id -> its property multiset (sorted; duplicates kept).
    node_props: BTreeMap<u64, Vec<PropTriple>>,
}

impl Model {
    /// An empty model.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Inserts a live node.
    pub fn add_node(&mut self, id: u64) {
        self.nodes.insert(id);
        self.incidence.entry(id).or_default();
        self.node_props.entry(id).or_default();
    }

    /// Inserts a live relationship and threads it into both endpoints' incidence sets (a self-loop
    /// lands once because the set dedupes).
    pub fn add_rel(&mut self, id: u64, start: u64, end: u64) {
        self.rels.insert(id, (start, end));
        self.incidence.entry(start).or_default().insert(id);
        self.incidence.entry(end).or_default().insert(id);
    }

    /// Removes a relationship from the graph and from both endpoints' incidence sets.
    pub fn remove_rel(&mut self, id: u64) {
        if let Some((start, end)) = self.rels.remove(&id) {
            if let Some(s) = self.incidence.get_mut(&start) {
                s.remove(&id);
            }
            if let Some(s) = self.incidence.get_mut(&end) {
                s.remove(&id);
            }
        }
    }

    /// Removes a node and all its modelled property state. The harness only deletes a node after
    /// detaching its relationships (the store requires it, `04 §2`), so its incidence set is empty
    /// here.
    pub fn remove_node(&mut self, id: u64) {
        self.nodes.remove(&id);
        self.incidence.remove(&id);
        self.node_props.remove(&id);
    }

    /// Appends a property to a node's modelled property multiset.
    pub fn add_node_prop(&mut self, node: u64, prop: PropTriple) {
        self.node_props.entry(node).or_default().push(prop);
    }

    /// Whether `id` is a live node.
    #[must_use]
    pub fn has_node(&self, id: u64) -> bool {
        self.nodes.contains(&id)
    }

    /// Whether `id` is a live relationship.
    #[must_use]
    pub fn has_rel(&self, id: u64) -> bool {
        self.rels.contains_key(&id)
    }

    /// The live node ids, ascending.
    #[must_use]
    pub fn nodes(&self) -> &BTreeSet<u64> {
        &self.nodes
    }

    /// The live relationships as `id -> (start, end)`.
    #[must_use]
    pub fn rels(&self) -> &BTreeMap<u64, (u64, u64)> {
        &self.rels
    }

    /// The incident relationship-id set of `node` (empty if the node is absent).
    #[must_use]
    pub fn incident(&self, node: u64) -> BTreeSet<u64> {
        self.incidence.get(&node).cloned().unwrap_or_default()
    }

    /// The degree of `node` (distinct incident relationships).
    #[must_use]
    pub fn degree(&self, node: u64) -> usize {
        self.incidence.get(&node).map_or(0, BTreeSet::len)
    }

    /// A node's property multiset, sorted (a stable order for comparison against the store).
    #[must_use]
    pub fn node_props_sorted(&self, node: u64) -> Vec<PropTriple> {
        let mut v = self.node_props.get(&node).cloned().unwrap_or_default();
        v.sort_unstable();
        v
    }
}

/// The acknowledged-commit ledger: the exact logical effect of every transaction whose `commit()`
/// returned `Ok`, plus the count of acknowledged commits.
///
/// In this harness the ledger and the [`Model`] are updated together at commit, so the model *is*
/// the cumulative effect of the ledger. The ledger keeps the auxiliary bookkeeping the checker and
/// the run report need: how many commits were acknowledged (a non-vacuity signal) and the ids that
/// belong to committed entities (so the checker can assert each is present and correct).
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct AckLedger {
    acknowledged_commits: u64,
    rolled_back: u64,
    in_flight_at_crash: u64,
}

impl AckLedger {
    /// An empty ledger.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Records that a transaction's `commit()` returned `Ok` (a new durability obligation).
    pub fn record_commit(&mut self) {
        self.acknowledged_commits += 1;
    }

    /// Records that a transaction was explicitly rolled back.
    pub fn record_rollback(&mut self) {
        self.rolled_back += 1;
    }

    /// Records that a transaction was still in flight (never committed, never rolled back) when a
    /// crash hit — its effects must not survive.
    pub fn record_in_flight_at_crash(&mut self) {
        self.in_flight_at_crash += 1;
    }

    /// How many commits were acknowledged.
    #[must_use]
    pub fn acknowledged_commits(&self) -> u64 {
        self.acknowledged_commits
    }

    /// How many transactions were rolled back.
    #[must_use]
    pub fn rolled_back(&self) -> u64 {
        self.rolled_back
    }

    /// How many transactions were in flight when a crash hit.
    #[must_use]
    pub fn in_flight_at_crash(&self) -> u64 {
        self.in_flight_at_crash
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rel_threads_into_both_endpoints_and_self_loop_once() {
        let mut m = Model::new();
        m.add_node(1);
        m.add_node(2);
        m.add_rel(10, 1, 2);
        m.add_rel(11, 1, 1); // self-loop

        assert_eq!(m.incident(1), BTreeSet::from([10, 11]));
        assert_eq!(m.incident(2), BTreeSet::from([10]));
        assert_eq!(m.degree(1), 2); // self-loop counted once
    }

    #[test]
    fn removing_a_rel_clears_both_endpoints() {
        let mut m = Model::new();
        m.add_node(1);
        m.add_node(2);
        m.add_rel(10, 1, 2);
        m.remove_rel(10);
        assert_eq!(m.degree(1), 0);
        assert_eq!(m.degree(2), 0);
        assert!(!m.has_rel(10));
    }

    #[test]
    fn node_props_are_a_sorted_multiset() {
        let mut m = Model::new();
        m.add_node(1);
        m.add_node_prop(
            1,
            PropTriple {
                key: 2,
                type_tag: 1,
                value_inline: 9,
            },
        );
        m.add_node_prop(
            1,
            PropTriple {
                key: 2,
                type_tag: 1,
                value_inline: 9,
            },
        ); // duplicate kept
        m.add_node_prop(
            1,
            PropTriple {
                key: 1,
                type_tag: 1,
                value_inline: 5,
            },
        );
        let props = m.node_props_sorted(1);
        assert_eq!(props.len(), 3);
        assert_eq!(props[0].key, 1); // sorted: key 1 first
        assert_eq!(props[1], props[2]); // the duplicate survives
    }

    #[test]
    fn ledger_counts_outcomes() {
        let mut l = AckLedger::new();
        l.record_commit();
        l.record_commit();
        l.record_rollback();
        l.record_in_flight_at_crash();
        assert_eq!(l.acknowledged_commits(), 2);
        assert_eq!(l.rolled_back(), 1);
        assert_eq!(l.in_flight_at_crash(), 1);
    }
}
