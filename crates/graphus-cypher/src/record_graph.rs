//! A [`GraphAccess`] backed by the **real** persistent record store
//! (`04-technical-design.md` §2, §7.4; `rmp` task #38).
//!
//! [`RecordStoreGraph`] is the seam where the two halves of the database meet: the Cypher
//! compile/execute pipeline ([`crate::executor`]) runs **unchanged** over a real, WAL-logged,
//! crash-recoverable [`graphus_storage::RecordStore`] instead of the in-memory reference
//! [`MemGraph`](crate::graph_access::MemGraph). The executor depends only on the [`GraphAccess`]
//! trait, so swapping the backend needs no operator change (`04 §7.4`).
//!
//! # The achievable subset (#38 + #42) and what is deferred (#39)
//!
//! This is the **achievable subset** of the storage integration: nodes/relationships/properties
//! (#38) and **node labels** (#42, this task — the bit-packed small-label-set case of `05 §9`). The
//! remaining wiring (index-accelerated label scans, the string/list property overflow heap, the
//! label token-list overflow block, and MVCC concurrency / SSI visibility) is the follow-up **#39**.
//! Every deferral is signalled by a **clear error**, never a silently wrong answer:
//!
//! | Capability | here (#38 + #42) | How a deferral is signalled |
//! |------------|------------------|-----------------------------|
//! | Nodes / relationships CRUD + traverse | supported (over real records, real WAL) | — |
//! | Inline scalar node properties (`Integer`/`Float`/`Boolean`) | supported via [`graphus_storage::encode_inline`] | — |
//! | Node **labels** (`CREATE (:L)`, `SET`/`REMOVE` label, `n:L` predicates, `labels(n)`, label scan) | **supported** (#42) via the inline label bitmap, `05 §9` | a label needing token id `≥ 63` (a 64th+ distinct label) captures the documented overflow error (the token-list block is #39) |
//! | `String`/`Bytes`/`List`/`Map`/temporal property values | **deferred (#39)** | a write captures a runtime error (the strings/overflow heap is not built) |
//! | Property **removal** (`SET n.p = null`, `REMOVE n.p`) | **deferred (#39)** | a write captures a runtime error (the store has no in-place delete/tombstone API yet) |
//! | **Relationship** properties | **deferred (#39)** | a write captures a runtime error (the store exposes no relationship-property chain API) |
//! | **Index-accelerated** label / property scans | **deferred (#39)** | a label scan is correct but does a full scan + `node_has_label` filter (no label index); the [`GraphAccess`] default `index_seek_*` returns `None`, so the executor falls back to scan+filter |
//! | MVCC concurrency / SSI | **deferred (#39)** | one query runs in a single transaction against the latest committed state |
//!
//! # Identity
//!
//! A [`NodeId`] / [`RelId`] **is** the store's physical record id (`u64`). The executor treats them
//! as opaque handles (`04 §7.4`), so using the physical id directly is sound and avoids a side
//! table. Physical ids are reused after deletion (`04 §2.7`); within one transaction that is
//! invisible to the executor (a deleted id is not handed back out mid-query).
//!
//! # Transaction scope
//!
//! The seam is transaction-scoped (`04 §7.4`): [`RecordStoreGraph::begin`] opens one store
//! transaction, the executor reads and writes through it, and the caller ends it with
//! [`commit`](RecordStoreGraph::commit) or [`rollback`](RecordStoreGraph::rollback). A committed
//! query's effects are durable and survive a crash; an uncommitted (or rolled-back) query's writes
//! are undone by the store's ARIES WAL (`04 §4.4`), so a query that hits a deferred-feature error
//! can be rolled back cleanly with no partial state.
//!
//! # Interior mutability and error capture (two impedance mismatches)
//!
//! The [`GraphAccess`] trait's read methods take `&self` and return plain values (no `Result`),
//! while [`RecordStore`]'s reads take `&mut self` (they fetch pages through the buffer pool) and
//! return `Result`. [`RecordStoreGraph`] bridges both:
//!
//! * a [`RefCell`] gives the `&self` trait methods the `&mut` access the store needs (the type is
//!   single-threaded — `!Sync` — which matches the #38 single-transaction scope; concurrency is
//!   #39);
//! * a captured-error cell records the **first** storage / deferred-feature error a read or write
//!   hits. The trait method then degrades safely (a read returns `None`/empty, a write is a no-op),
//!   and the caller **must** inspect [`take_error`](RecordStoreGraph::take_error) after running the
//!   cursor. A captured error means the result is **not** trustworthy and the transaction should be
//!   rolled back. This keeps a deferral a hard, surfaced error — never a wrong row.

use std::cell::RefCell;

use graphus_core::error::GraphusError;
use graphus_core::{TxnId, Value};
use graphus_io::BlockDevice;
use graphus_storage::{Namespace, RecordStore, decode_inline, encode_inline};
use graphus_wal::LogSink;

use crate::graph_access::{ExpandDirection, GraphAccess, Incident, NodeId, RelData, RelId};

/// A [`GraphAccess`] implementation over a real [`RecordStore`], scoped to one transaction
/// (`rmp` task #38; see the module docs for the supported-vs-deferred matrix).
///
/// Generic over the block device `D` and WAL log sink `S` exactly like the underlying
/// [`RecordStore`], so it runs over the production file device + file log and over the in-memory
/// DST device + log used by the executor/crash-recovery tests.
#[must_use]
pub struct RecordStoreGraph<D: BlockDevice, S: LogSink> {
    /// The store, behind a `RefCell` so the `&self` [`GraphAccess`] reads can drive the store's
    /// `&mut self` methods (see module docs).
    store: RefCell<RecordStore<D, S>>,
    /// The single transaction this query runs in.
    txn: TxnId,
    /// The first storage / deferred-feature error encountered by a read or write, if any. While set,
    /// results are untrustworthy and the transaction should be rolled back (see module docs).
    error: RefCell<Option<GraphusError>>,
}

impl<D: BlockDevice, S: LogSink> RecordStoreGraph<D, S> {
    /// Wraps `store` and **begins** transaction `txn`, returning a graph seam the executor can run
    /// one query against.
    ///
    /// The caller owns the transaction lifecycle: after running the query it calls
    /// [`commit`](Self::commit) (to make the writes durable) or [`rollback`](Self::rollback) (to
    /// undo them), and should first check [`take_error`](Self::take_error).
    pub fn begin(mut store: RecordStore<D, S>, txn: TxnId) -> Self {
        store.begin(txn);
        Self {
            store: RefCell::new(store),
            txn,
            error: RefCell::new(None),
        }
    }

    /// The transaction id this query runs in.
    #[must_use]
    pub fn txn(&self) -> TxnId {
        self.txn
    }

    /// Takes the first captured storage / deferred-feature error, leaving the cell empty.
    ///
    /// Returns `Some(err)` if any read or write hit an error during execution — in which case the
    /// query's results are **not** trustworthy and the caller should [`rollback`](Self::rollback)
    /// rather than [`commit`](Self::commit). `None` means every seam operation succeeded.
    #[must_use]
    pub fn take_error(&self) -> Option<GraphusError> {
        self.error.borrow_mut().take()
    }

    /// Whether a storage / deferred-feature error has been captured (non-consuming peek).
    #[must_use]
    pub fn has_error(&self) -> bool {
        self.error.borrow().is_some()
    }

    /// Commits the query's transaction, making its writes durable, and returns the wrapped store.
    ///
    /// # Errors
    /// Returns a storage error if the commit (catalog persist + WAL group-commit) fails.
    pub fn commit(self) -> Result<RecordStore<D, S>, GraphusError> {
        let mut store = self.store.into_inner();
        store.commit(self.txn)?;
        Ok(store)
    }

    /// Rolls the query's transaction back (undoing every write via the WAL) and returns the wrapped
    /// store. Use this when [`take_error`](Self::take_error) reported an error, or to discard a
    /// read-only or speculative query.
    ///
    /// # Errors
    /// Returns a storage error if the undo apply or catalog reload fails.
    pub fn rollback(self) -> Result<RecordStore<D, S>, GraphusError> {
        let mut store = self.store.into_inner();
        store.rollback(self.txn)?;
        Ok(store)
    }

    /// Reclaims the wrapped store **without** ending the transaction (no commit, no rollback).
    ///
    /// The transaction's effects remain uncommitted: not durable, and a crash before a later commit
    /// rolls them back via the WAL (`04 §4.4`). This is the seam the orchestration layer uses to
    /// retrieve the store for inspection or shutdown, and the crash-recovery tests use it to crash
    /// with an in-flight (loser) transaction.
    pub fn into_store(self) -> RecordStore<D, S> {
        self.store.into_inner()
    }

    /// Records `err` as the first captured error (a later error does not overwrite the first, which
    /// is usually the root cause).
    fn capture(&self, err: GraphusError) {
        let mut slot = self.error.borrow_mut();
        if slot.is_none() {
            *slot = Some(err);
        }
    }

    /// Captures a "deferred to #39" runtime error for `feature` and returns it as the `Err` arm so a
    /// write helper can early-return after recording it.
    fn defer(&self, feature: &str) {
        self.capture(GraphusError::Runtime(format!(
            "{feature} is not supported in this build (deferred to graphus #39)"
        )));
    }

    /// Resolves the property key id for `key`, interning it if new (a new key becomes durable when
    /// the transaction commits, `04 §2.6`). Captures and returns `None` on a storage error.
    fn prop_key_id(&self, key: &str) -> Option<u32> {
        match self
            .store
            .borrow_mut()
            .intern_token(Namespace::PropKey, key)
        {
            Ok(id) => Some(id),
            Err(e) => {
                self.capture(e);
                None
            }
        }
    }

    /// Resolves the [`Namespace::Label`] token id for `name`, **interning it if new** (a new label
    /// token becomes durable when the transaction commits, exactly like a relationship type,
    /// `04 §2.6`). Used by label writes (`CREATE (:L)`, `SET n:L`). Captures and returns `None` on a
    /// storage error.
    fn label_id_intern(&self, name: &str) -> Option<u32> {
        match self.store.borrow_mut().intern_token(Namespace::Label, name) {
            Ok(id) => Some(id),
            Err(e) => {
                self.capture(e);
                None
            }
        }
    }

    /// The existing [`Namespace::Label`] token id for `name`, **without** interning it.
    ///
    /// Returns `None` when `name` was never interned — by which point no live node can carry it (a
    /// label only exists once some node was labelled with it), so a label *read* (scan / predicate)
    /// on an unknown label is correctly empty/false. This is the read-side counterpart to
    /// [`label_id_intern`](Self::label_id_intern), which must not create a token just by *asking*
    /// whether a node has a label.
    fn label_id_existing(&self, name: &str) -> Option<u32> {
        self.store.borrow().token_id(Namespace::Label, name)
    }

    /// Interns and sets each of `labels` on `node`'s inline label bitmap (`05 §9`, `rmp` task #42),
    /// idempotently. Shared by `create_node` (with labels) and `add_labels`.
    ///
    /// On the first error — a storage fault, or the documented overflow deferral (a label whose
    /// token id is `≥ 63`, i.e. the 64th+ distinct label, whose token-list block is #39) — the error
    /// is captured and the rest are skipped; the captured error makes the whole query untrustworthy
    /// (the caller rolls back). This is never a silently-dropped label.
    fn apply_add_labels(&self, node: NodeId, labels: &[String]) {
        for name in labels {
            let Some(token_id) = self.label_id_intern(name) else {
                return; // storage error already captured (token-namespace exhaustion)
            };
            if let Err(e) = self
                .store
                .borrow_mut()
                .add_label(self.txn, node.0, token_id)
            {
                self.capture(e);
                return;
            }
        }
    }

    /// Reads `node`'s live properties as newest-wins `(key_name, value)` pairs.
    ///
    /// The store's property chain is prepend-ordered (newest record first), so a `SET` of an
    /// existing key adds a newer record that shadows the older one; this keeps the **first**
    /// occurrence per key id while walking head-to-tail. Non-inline / unknown-tag values would mean
    /// the store holds something this build cannot decode — that is captured as an error (it cannot
    /// happen for data this build wrote, since writing such values is itself deferred).
    fn read_node_props(&self, node: NodeId) -> Vec<(String, Value)> {
        let mut store = self.store.borrow_mut();
        let chain = match store.node_properties(node.0) {
            Ok(chain) => chain,
            Err(e) => {
                drop(store);
                self.capture(e);
                return Vec::new();
            }
        };
        let mut out: Vec<(u32, Value)> = Vec::new();
        for (_pid, prop) in chain {
            // Newest-wins: skip a key id already seen (a more recent record shadows it).
            if out.iter().any(|(k, _)| *k == prop.key) {
                continue;
            }
            match decode_inline(prop.type_tag, prop.value_inline) {
                Ok(v) => out.push((prop.key, v)),
                Err(e) => {
                    drop(store);
                    self.capture(e.into());
                    return Vec::new();
                }
            }
        }
        // Map key ids back to names and sort by name for the deterministic order the seam promises.
        let mut named: Vec<(String, Value)> = out
            .into_iter()
            .filter_map(|(kid, v)| {
                store
                    .token_name(Namespace::PropKey, kid)
                    .map(|name| (name.to_owned(), v))
            })
            .collect();
        named.sort_by(|a, b| a.0.cmp(&b.0));
        named
    }
}

impl<D: BlockDevice, S: LogSink> GraphAccess for RecordStoreGraph<D, S> {
    // ---- reads --------------------------------------------------------------------------------

    fn scan_nodes(&self) -> Vec<NodeId> {
        match self.store.borrow_mut().scan_node_ids() {
            Ok(ids) => ids.into_iter().map(NodeId).collect(),
            Err(e) => {
                self.capture(e);
                Vec::new()
            }
        }
    }

    fn scan_nodes_by_label(&self, label: &str) -> Vec<NodeId> {
        // Resolve the label name -> token id without interning: if the label was never created, no
        // live node can carry it, so the scan is correctly empty (`05 §9`, `rmp` task #42).
        let Some(token_id) = self.label_id_existing(label) else {
            return Vec::new();
        };
        // Index-accelerated label scans are #39; here we scan every live node and filter by the
        // inline label bitmap (`node_has_label`). This is correct, just O(live nodes).
        let mut store = self.store.borrow_mut();
        let ids = match store.scan_node_ids() {
            Ok(ids) => ids,
            Err(e) => {
                drop(store);
                self.capture(e);
                return Vec::new();
            }
        };
        let mut out = Vec::new();
        for id in ids {
            match store.node_has_label(id, token_id) {
                Ok(true) => out.push(NodeId(id)),
                Ok(false) => {}
                Err(e) => {
                    // An overflow-form bitmap (a #39-written node) surfaces as a captured error
                    // rather than a wrong (missing/extra) row.
                    drop(store);
                    self.capture(e);
                    return Vec::new();
                }
            }
        }
        out
    }

    fn expand(&self, node: NodeId, direction: ExpandDirection, types: &[String]) -> Vec<Incident> {
        let mut store = self.store.borrow_mut();
        let rels = match store.incident_rels(node.0) {
            Ok(rels) => rels,
            Err(e) => {
                drop(store);
                self.capture(e);
                return Vec::new();
            }
        };
        let mut out = Vec::new();
        for rid in rels {
            let rec = match store.rel(rid) {
                Ok(rec) => rec,
                Err(e) => {
                    drop(store);
                    self.capture(e);
                    return Vec::new();
                }
            };
            // Filter by relationship type name (empty = any type).
            if !types.is_empty() {
                let type_ok = store
                    .token_name(Namespace::RelType, rec.type_id)
                    .is_some_and(|name| types.iter().any(|t| t == name));
                if !type_ok {
                    continue;
                }
            }
            // Report the matching side(s) relative to the anchor, exactly like `MemGraph`: a
            // self-loop participates as both start and end and is reported once per matching
            // direction (the executor deduplicates by rel id, `04 §2.4`). `incident_rels` already
            // deduplicates a self-loop's two chain links to one id, so a self-loop is reported once
            // per matching direction here.
            let touches_as_start = rec.start_node == node.0;
            let touches_as_end = rec.end_node == node.0;
            let want_out = matches!(direction, ExpandDirection::Outgoing | ExpandDirection::Both);
            let want_in = matches!(direction, ExpandDirection::Incoming | ExpandDirection::Both);
            if touches_as_start && want_out {
                out.push(Incident {
                    rel: RelId(rid),
                    neighbour: NodeId(rec.end_node),
                });
            }
            if touches_as_end && want_in {
                out.push(Incident {
                    rel: RelId(rid),
                    neighbour: NodeId(rec.start_node),
                });
            }
        }
        out
    }

    fn node_exists(&self, node: NodeId) -> bool {
        match self.store.borrow_mut().node(node.0) {
            Ok(rec) => rec.mvcc.in_use(),
            // A missing page means the id was never allocated — i.e. the node does not exist. That
            // is a normal answer, not a captured storage fault.
            Err(_) => false,
        }
    }

    fn rel_exists(&self, rel: RelId) -> bool {
        match self.store.borrow_mut().rel(rel.0) {
            Ok(rec) => rec.mvcc.in_use(),
            Err(_) => false,
        }
    }

    fn node_labels(&self, node: NodeId) -> Option<Vec<String>> {
        if !self.node_exists(node) {
            return None;
        }
        // Read the node's label token ids from its inline bitmap (`05 §9`, `rmp` task #42), then map
        // each id back to its name. An overflow-form bitmap (a #39-written node) is captured as an
        // error and reported as `Some(vec![])` so the result is not silently wrong; the caller must
        // inspect `take_error`.
        let mut store = self.store.borrow_mut();
        let ids = match store.node_labels(node.0) {
            Ok(ids) => ids,
            Err(e) => {
                drop(store);
                self.capture(e);
                return Some(Vec::new());
            }
        };
        let mut names: Vec<String> = ids
            .into_iter()
            .filter_map(|id| {
                store
                    .token_name(Namespace::Label, id)
                    .map(ToOwned::to_owned)
            })
            .collect();
        // Deterministic, name-sorted order (mirrors `MemGraph`, which keeps labels sorted).
        names.sort();
        Some(names)
    }

    fn rel_data(&self, rel: RelId) -> Option<RelData> {
        let mut store = self.store.borrow_mut();
        let rec = match store.rel(rel.0) {
            Ok(rec) if rec.mvcc.in_use() => rec,
            Ok(_) => return None,
            Err(_) => return None,
        };
        let rel_type = store
            .token_name(Namespace::RelType, rec.type_id)
            .unwrap_or("")
            .to_owned();
        Some(RelData {
            rel_type,
            start: NodeId(rec.start_node),
            end: NodeId(rec.end_node),
        })
    }

    fn node_property(&self, node: NodeId, key: &str) -> Option<Value> {
        if !self.node_exists(node) {
            return None;
        }
        self.read_node_props(node)
            .into_iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v)
    }

    fn rel_property(&self, _rel: RelId, _key: &str) -> Option<Value> {
        // Relationship properties have no storage API yet (#39). Reading one is moot until it can be
        // written; a write already captures the deferral, so a read just reports "absent".
        None
    }

    fn node_properties(&self, node: NodeId) -> Option<Vec<(String, Value)>> {
        if !self.node_exists(node) {
            return None;
        }
        Some(self.read_node_props(node))
    }

    fn rel_properties(&self, rel: RelId) -> Option<Vec<(String, Value)>> {
        // No relationship-property storage yet (#39); report an empty set for a live relationship so
        // the caller distinguishes it from a missing relationship (`None`).
        if self.rel_exists(rel) {
            Some(Vec::new())
        } else {
            None
        }
    }

    // ---- writes -------------------------------------------------------------------------------

    fn create_node(&mut self, labels: &[String], properties: &[(String, Value)]) -> NodeId {
        let id = match self.store.borrow_mut().create_node(self.txn) {
            Ok((id, _eid)) => id,
            Err(e) => {
                self.capture(e);
                // Return a sentinel id; the captured error makes the whole query untrustworthy.
                return NodeId(0);
            }
        };
        let node = NodeId(id);
        // Apply labels via the inline label bitmap (`05 §9`, `rmp` task #42). An overflowing label
        // (token id `≥ 63`) captures the documented deferred error rather than dropping it silently.
        self.apply_add_labels(node, labels);
        for (k, v) in properties {
            self.set_node_property(node, k, v.clone());
        }
        node
    }

    fn create_rel(
        &mut self,
        rel_type: &str,
        start: NodeId,
        end: NodeId,
        properties: &[(String, Value)],
    ) -> RelId {
        let type_id = match self
            .store
            .borrow_mut()
            .intern_token(Namespace::RelType, rel_type)
        {
            Ok(id) => id,
            Err(e) => {
                self.capture(e);
                return RelId(0);
            }
        };
        let id = match self
            .store
            .borrow_mut()
            .create_rel(self.txn, type_id, start.0, end.0)
        {
            Ok((id, _eid)) => id,
            Err(e) => {
                self.capture(e);
                return RelId(0);
            }
        };
        if !properties.is_empty() {
            // Relationship properties have no storage API yet (#39); do not silently drop them.
            self.defer("relationship properties");
        }
        RelId(id)
    }

    fn set_node_property(&mut self, node: NodeId, key: &str, value: Value) {
        if value.is_null() {
            // Removal (`SET n.p = null`) needs an in-place delete / tombstone the store lacks (#39);
            // signal rather than no-op (a no-op would leave a stale value = a wrong answer).
            self.defer("removing a node property (SET n.p = null)");
            return;
        }
        let (type_tag, value_inline) = match encode_inline(&value) {
            Ok(pair) => pair,
            Err(e) => {
                // Non-inline value class (String/List/Map/temporal): deferred to #39's overflow heap.
                self.capture(e.into());
                return;
            }
        };
        let Some(key_id) = self.prop_key_id(key) else {
            return; // error already captured
        };
        if let Err(e) = self.store.borrow_mut().add_node_property(
            self.txn,
            node.0,
            key_id,
            type_tag,
            value_inline,
        ) {
            self.capture(e);
        }
    }

    fn set_rel_property(&mut self, _rel: RelId, _key: &str, _value: Value) {
        self.defer("setting a relationship property");
    }

    fn add_labels(&mut self, node: NodeId, labels: &[String]) {
        if labels.is_empty() || !self.node_exists(node) {
            return;
        }
        self.apply_add_labels(node, labels);
    }

    fn remove_labels(&mut self, node: NodeId, labels: &[String]) {
        if labels.is_empty() || !self.node_exists(node) {
            return;
        }
        // Remove each label that has ever been interned; a label name that was never created cannot
        // be set on any node, so removing it is a no-op (no token is created just to remove it).
        for name in labels {
            let Some(token_id) = self.label_id_existing(name) else {
                continue;
            };
            if let Err(e) = self
                .store
                .borrow_mut()
                .remove_label(self.txn, node.0, token_id)
            {
                self.capture(e);
                return;
            }
        }
    }

    fn remove_node_property(&mut self, node: NodeId, _key: &str) {
        if !self.node_exists(node) {
            return;
        }
        self.defer("removing a node property (REMOVE n.p)");
    }

    fn remove_rel_property(&mut self, _rel: RelId, _key: &str) {
        self.defer("removing a relationship property");
    }

    fn replace_node_properties(&mut self, node: NodeId, _properties: &[(String, Value)]) {
        if !self.node_exists(node) {
            return;
        }
        // `SET n = map` must first clear the existing properties, which needs the in-place
        // delete/tombstone the store lacks (#39); signal rather than partially apply.
        self.defer("replacing node properties (SET n = map)");
    }

    fn merge_node_properties(&mut self, node: NodeId, properties: &[(String, Value)]) {
        // `SET n += map` keeps unmentioned keys and overlays the map; for a non-null value this is
        // an append (newest-wins read), which the store supports. A null value would be a removal
        // (deferred); `set_node_property` signals that.
        if !self.node_exists(node) {
            return;
        }
        for (k, v) in properties {
            self.set_node_property(node, k, v.clone());
        }
    }

    fn incident_rels(&self, node: NodeId) -> Vec<RelId> {
        match self.store.borrow_mut().incident_rels(node.0) {
            Ok(rels) => rels.into_iter().map(RelId).collect(),
            Err(e) => {
                self.capture(e);
                Vec::new()
            }
        }
    }

    fn delete_rel(&mut self, rel: RelId) {
        // Idempotent: a relationship that is already gone (or was never created) is a no-op, not an
        // error — matching the `MemGraph` contract.
        let in_use = matches!(self.store.borrow_mut().rel(rel.0), Ok(r) if r.mvcc.in_use());
        if !in_use {
            return;
        }
        if let Err(e) = self.store.borrow_mut().delete_rel(self.txn, rel.0) {
            self.capture(e);
        }
    }

    fn delete_node(&mut self, node: NodeId) {
        let in_use = matches!(self.store.borrow_mut().node(node.0), Ok(n) if n.mvcc.in_use());
        if !in_use {
            return;
        }
        if let Err(e) = self.store.borrow_mut().delete_node(self.txn, node.0) {
            self.capture(e);
        }
    }
}
