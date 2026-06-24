//! Empirical proof of the typed-expand wasted-read + wasted-SSI-mark elimination (`rmp` #324,
//! "Win 1"), measured at the `read_source::expand` seam.
//!
//! The old `expand` body walked the incidence chain (`incident_rels`) and then re-read EVERY incident
//! id with a second `rel()` call before filtering by type, SSI-marking each. For a type-selective
//! traversal that keeps a minority of edges, this re-read and SSI-marked the majority of edges
//! pointlessly (the measured ~64% on `top_liked`). The rewritten body calls `incident_rels_typed`,
//! which materialises ONLY the matching records in a single pass, so the per-edge `rel()` re-reads
//! and the per-edge SSI marks on non-matching edges both vanish.
//!
//! This test wraps a `StoreReadSource` so it counts `rel()` calls, and a `ReadSink` so it counts
//! per-rel SIREAD markers, then runs `expand` with a type filter and asserts:
//!  * ZERO per-edge `rel()` calls (the single-pass walk returns the records itself), and
//!  * exactly `matching` SIREAD markers (was: every incident edge) — the ~64% reduction.

use std::cell::Cell;

use graphus_core::TxnId;
use graphus_cypher::{ExpandDirection, LiveSource, NodeId, ReadSink, StoreReadSource, VisCtx};
use graphus_io::MemBlockDevice;
use graphus_storage::record::{NodeRecord, PropRecord, RelRecord};
use graphus_storage::{Namespace, RecordStore};
use graphus_txn::{PredicateRead, Snapshot};
use graphus_wal::{MemLogSink, WalManager};

type Store = RecordStore<MemBlockDevice, MemLogSink>;

/// A `StoreReadSource` that forwards to a `LiveSource` while counting the per-edge `rel()` calls and
/// the `incident_rels_typed` walk calls.
struct Counting<'a> {
    inner: LiveSource<'a, MemBlockDevice, MemLogSink>,
    rel_calls: Cell<usize>,
    typed_calls: Cell<usize>,
}

impl<'a> Counting<'a> {
    fn new(store: &'a Store) -> Self {
        Self {
            inner: LiveSource(store),
            rel_calls: Cell::new(0),
            typed_calls: Cell::new(0),
        }
    }
}

impl StoreReadSource for Counting<'_> {
    fn node(&self, id: u64) -> Result<NodeRecord, graphus_core::error::GraphusError> {
        self.inner.node(id)
    }
    fn rel(&self, id: u64) -> Result<RelRecord, graphus_core::error::GraphusError> {
        self.rel_calls.set(self.rel_calls.get() + 1);
        self.inner.rel(id)
    }
    fn scan_node_ids(&self) -> Result<Vec<u64>, graphus_core::error::GraphusError> {
        self.inner.scan_node_ids()
    }
    fn node_labels(&self, id: u64) -> Result<Vec<u32>, graphus_core::error::GraphusError> {
        self.inner.node_labels(id)
    }
    fn node_has_label(&self, id: u64, l: u32) -> Result<bool, graphus_core::error::GraphusError> {
        self.inner.node_has_label(id, l)
    }
    fn node_properties(
        &self,
        id: u64,
    ) -> Result<Vec<(u64, PropRecord)>, graphus_core::error::GraphusError> {
        self.inner.node_properties(id)
    }
    fn rel_properties(
        &self,
        id: u64,
    ) -> Result<Vec<(u64, PropRecord)>, graphus_core::error::GraphusError> {
        self.inner.rel_properties(id)
    }
    fn incident_rels(&self, id: u64) -> Result<Vec<u64>, graphus_core::error::GraphusError> {
        self.inner.incident_rels(id)
    }
    fn incident_rels_typed(
        &self,
        id: u64,
        types: &[u32],
    ) -> Result<Vec<(u64, RelRecord)>, graphus_core::error::GraphusError> {
        self.typed_calls.set(self.typed_calls.get() + 1);
        self.inner.incident_rels_typed(id, types)
    }
    fn decode_property_value(
        &self,
        t: u8,
        v: u64,
    ) -> Result<graphus_core::Value, graphus_core::error::GraphusError> {
        self.inner.decode_property_value(t, v)
    }
    fn token_id(&self, ns: Namespace, name: &str) -> Option<u32> {
        self.inner.token_id(ns, name)
    }
    fn token_name(&self, ns: Namespace, id: u32) -> Option<String> {
        self.inner.token_name(ns, id)
    }
}

/// A `ReadSink` that counts per-rel SIREAD markers and the predicate markers.
#[derive(Default)]
struct CountSink {
    reads: Cell<usize>,
    predicates: Cell<usize>,
}

impl ReadSink for CountSink {
    fn note_read(&self, _key: u64) {
        self.reads.set(self.reads.get() + 1);
    }
    fn note_predicate_read(&self, _p: PredicateRead) {
        self.predicates.set(self.predicates.get() + 1);
    }
    fn capture(&self, err: graphus_core::error::GraphusError) {
        panic!("unexpected captured error in expand: {err}");
    }
}

fn fresh() -> Store {
    let device = MemBlockDevice::new(0);
    let wal = WalManager::create(MemLogSink::new()).expect("create wal");
    RecordStore::create(device, wal, 64, 1).expect("create store")
}

#[test]
fn typed_expand_skips_nonmatching_reads_and_marks() {
    // A `top_liked`-shaped hub: many FRIEND edges, a minority of LIKE edges.
    let mut s = fresh();
    let txn = TxnId(1);
    s.begin(txn);
    let t_friend = s.intern_token(Namespace::RelType, "FRIEND").unwrap();
    let t_like = s.intern_token(Namespace::RelType, "LIKE").unwrap();
    let (a, _) = s.create_node(txn).unwrap();

    let total = 100usize;
    let mut likes = 0usize;
    for i in 0..total as u64 {
        let (b, _) = s.create_node(txn).unwrap();
        if i % 3 == 0 {
            s.create_rel(txn, t_like, a, b).unwrap();
            likes += 1;
        } else {
            s.create_rel(txn, t_friend, a, b).unwrap();
        }
    }
    s.commit(txn).unwrap();

    let registry = s.commit_registry().clone();
    let ctx = VisCtx {
        snapshot: Snapshot {
            owner: TxnId(99),
            ts: s.snapshot_ts(),
        },
        registry: &registry,
        txn: TxnId(99),
    };

    let src = Counting::new(&s);
    let sink = CountSink::default();
    let out = graphus_cypher::read_source::expand(
        &src,
        &ctx,
        &sink,
        NodeId(a),
        ExpandDirection::Outgoing,
        &["LIKE".to_string()],
    );

    // Correctness: exactly the LIKE edges are returned.
    assert_eq!(
        out.len(),
        likes,
        "typed expand returns exactly the LIKE edges"
    );

    // Win 1, claim 1: ZERO per-edge `rel()` re-reads (was: one per incident edge = `total`). The
    // single-pass `incident_rels_typed` returns the records directly.
    assert_eq!(
        src.rel_calls.get(),
        0,
        "no per-edge rel() re-read on the typed path"
    );
    assert_eq!(src.typed_calls.get(), 1, "one typed chain walk");

    // Win 1, claim 2: per-rel SIREAD markers drop to the matching count (was: `total`). The
    // wasted-mark elimination is `total - likes` markers skipped.
    assert_eq!(
        sink.reads.get(),
        likes,
        "only matching-type edges are SIREAD-marked"
    );
    let skipped = total - sink.reads.get();
    assert!(
        skipped * 100 / total >= 60,
        "skipped >=60% of per-edge SSI marks (skipped {skipped}/{total})"
    );

    // The rel-type predicate marker is still registered (phantom cover preserved, MUST #4).
    assert!(
        sink.predicates.get() >= 1,
        "rel-type predicate read still registered for phantom cover"
    );
}

#[test]
fn untyped_expand_marks_and_returns_all() {
    // Untyped expand must still examine + mark + return every incident edge (MUST #5).
    let mut s = fresh();
    let txn = TxnId(1);
    s.begin(txn);
    let t_a = s.intern_token(Namespace::RelType, "A").unwrap();
    let t_b = s.intern_token(Namespace::RelType, "B").unwrap();
    let (a, _) = s.create_node(txn).unwrap();
    let total = 30usize;
    for i in 0..total as u64 {
        let (b, _) = s.create_node(txn).unwrap();
        let t = if i % 2 == 0 { t_a } else { t_b };
        s.create_rel(txn, t, a, b).unwrap();
    }
    s.commit(txn).unwrap();

    let registry = s.commit_registry().clone();
    let ctx = VisCtx {
        snapshot: Snapshot {
            owner: TxnId(99),
            ts: s.snapshot_ts(),
        },
        registry: &registry,
        txn: TxnId(99),
    };
    let src = Counting::new(&s);
    let sink = CountSink::default();
    let out = graphus_cypher::read_source::expand(
        &src,
        &ctx,
        &sink,
        NodeId(a),
        ExpandDirection::Outgoing,
        &[], // untyped
    );
    assert_eq!(out.len(), total, "untyped expand returns ALL edges");
    assert_eq!(sink.reads.get(), total, "untyped marks every edge");
    assert_eq!(src.rel_calls.get(), 0, "still no per-edge rel() re-read");
}
