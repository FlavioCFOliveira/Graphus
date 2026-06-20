//! Serializable Snapshot Isolation conflict tracking (`04 §5.4`).
//!
//! Pure Snapshot Isolation permits **write-skew** and other serialization anomalies. SSI
//! (Cahill/Fekete; PostgreSQL SSI — `04 §13` sources) upgrades SI to full serializability without
//! adding read locks, by detecting the **rw-antidependency** (read-write) edge:
//!
//! > `T1 --rw--> T2` when `T1` reads a version that `T2` then overwrites.
//!
//! **Cahill's theorem.** Every non-serializable execution contains a transaction with **both** an
//! inbound and an outbound rw-antidependency — a *dangerous structure* whose middle transaction is
//! the **pivot**. Aborting one transaction on every such structure makes all executions
//! serializable.
//!
//! ## What this module tracks
//!
//! - **SIREAD markers** (`record_read`): the non-blocking read set. A read records `(reader, key)`;
//!   it never blocks a writer (`04 §5.7`, NFR-4).
//! - **rw-antidependency edges** (`record_write`): when a transaction writes a `key` that another
//!   *concurrent* transaction has SIREAD-marked, an edge `reader --rw--> writer` is registered.
//! - **per-transaction conflict flags**: following PostgreSQL, each transaction carries
//!   `in_conflict` (has an inbound rw-edge) and `out_conflict` (has an outbound rw-edge); it is a
//!   pivot iff both are set.
//!
//! ## Pivot abort + safe retry (`04 §5.4`)
//!
//! At a transaction's commit, [`SsiTracker::detect_pivot_abort`] checks for a dangerous structure
//! `Tin --rw--> Tpivot --rw--> Tout` where the committing transaction participates, and where the
//! outbound edge's target `Tout` *committed first or is still concurrent* (Cahill's precise
//! condition that the edges can close a cycle). When found it returns the [`TxnId`] to abort.
//!
//! **Safe-retry policy (no mutual-abort livelock).** We abort the **pivot** (the middle of the
//! structure) rather than an arbitrary participant, and only when its outbound partner has already
//! committed *or* will be checked itself. Because an already-committed transaction can never be
//! chosen, every dangerous structure has at least one member that survives — at least one
//! transaction in any unsafe set commits. This is the PostgreSQL rule that prevents two
//! transactions from aborting each other forever.
//!
//! ## Read-only optimization (`04 §5.4`)
//!
//! A read-only transaction has no outbound rw-edge it can *create* by writing, so it can never be
//! the pivot of a structure that its own commit closes; [`detect_pivot_abort`](SsiTracker::detect_pivot_abort)
//! exempts a committing transaction that performed no writes, which matters under read-heavy graph
//! workloads.

// Deterministic hashing (no per-process `RandomState` seed), matching every sibling module in this
// crate (`store`, `manager`, `snapshot`, `lock`). This is load-bearing for determinism: the SSI
// validator iterates `txns` to choose a pivot-abort victim, and `std::HashMap`'s randomized iteration
// order would make that choice — and hence which concurrent transaction reports a serialization error
// — vary run-to-run for the *same* seed, breaking the DST's "same seed ⇒ identical trace" invariant
// (surfaced by the rmp #235 cooperative interleaver, which is the first path to hold ≥2 conflicting
// transactions open at once).
use rustc_hash::{FxHashMap as HashMap, FxHashSet as HashSet};

use graphus_core::{Timestamp, TxnId};

use crate::store::Key;

/// A **predicate SIREAD marker** — the read footprint of a query that reads *the set of nodes
/// matching a predicate*, rather than a single physical record (`04 §5.4`; PostgreSQL SSI
/// "predicate locks" / SIREAD-on-index-range).
///
/// Pure per-record SIREAD markers ([`SsiTracker::record_read`]) only close an rw-antidependency when
/// a writer **overwrites a record the reader already saw**. They cannot catch a **phantom**: a reader
/// that evaluates `MATCH (n:Label {p: v})` and sees *nothing* has read the **absence** of any such
/// node, and a concurrent transaction that then **inserts** a node matching that predicate has
/// invalidated the reader's result — but there is no shared physical key between them, so no edge
/// forms and both commit (a non-serializable history; `rmp` #171).
///
/// A `PredicateRead` is the reader's declaration "I depend on which nodes match *this* predicate".
/// A concurrent writer enumerates the predicate footprint of every node it creates/relabels/sets
/// ([`SsiTracker::record_predicate_write`]); when that footprint contains a marker a concurrent
/// reader holds, the rw-antidependency `reader --rw--> writer` is closed exactly as a physical-key
/// edge is, feeding the unchanged Cahill dangerous-structure detection.
///
/// ## Granularity (a sound over-approximation is acceptable)
///
/// - [`PredicateRead::Equality`] — the precise `MATCH (n:Label {prop: value})` access path. The value
///   is an **order-preserving encoded** key (the same encoding the secondary index uses), so two
///   values that are Cypher-equal compare equal here and a writer's inserted value matches byte-for-byte.
/// - [`PredicateRead::Label`] — a bare label scan `MATCH (n:Label)`, *and* the conservative
///   over-approximation used for a **range / property-existence** scan over a label: any insert of
///   that label matches. Coarser than equality (it may abort a few extra genuinely-concurrent
///   transactions) but never unsound.
/// - [`PredicateRead::AllNodes`] — an all-nodes scan `MATCH (n)`: any node insert matches.
///
/// Coarser granularity only ever causes *more* aborts among **concurrently-overlapping** transactions;
/// it never produces a false abort for non-overlapping (serial) transactions, because every edge is
/// gated on [`SsiTracker::are_concurrent`] just like a physical-key edge.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum PredicateRead {
    /// An all-nodes scan (`MATCH (n)`): the read depends on *every* node, so any node insert matches.
    AllNodes,
    /// A bare label scan (`MATCH (n:Label)`) by label token; also the conservative marker a range or
    /// property-existence scan over the label registers. Any insert carrying this label matches.
    Label(u32),
    /// An exact label + property-equality predicate (`MATCH (n:Label {prop: value})`), keyed by the
    /// label token, the property-key token, and the order-preserving encoded `value`.
    Equality {
        /// The covered label token.
        label: u32,
        /// The covered property-key token.
        property: u32,
        /// The order-preserving encoded predicate value (the secondary-index key encoding), so a
        /// writer's inserted value matches a reader's marker iff they are Cypher-equal.
        value: Vec<u8>,
    },
    /// A relationship-pattern read over **any** relationship type — a `MATCH ()-[r]-()` /
    /// untyped traversal (`rmp` #171 blocker A1). Any relationship create/delete matches, the
    /// relationship analogue of [`AllNodes`](Self::AllNodes).
    AnyRel,
    /// A relationship-pattern read scoped to a **relationship type** — a `MATCH ()-[r:T]-()`
    /// traversal (`rmp` #171 blocker A1), keyed by the relationship-type token. A concurrent
    /// `create_rel`/`delete_rel` of that type matches (a relationship phantom: read "no `:T` edges",
    /// then a concurrent `CREATE` of a `:T` edge). The relationship analogue of [`Label`](Self::Label).
    RelType(u32),
}

/// Per-transaction SSI bookkeeping (its node in the conflict graph).
#[derive(Debug, Default)]
struct TxnConflict {
    /// Keys this transaction SIREAD-marked (its read set).
    reads: HashSet<Key>,
    /// Predicate SIREAD markers this transaction holds (its **predicate** read set): the set of
    /// node-predicates whose matching-node set it depends on (`rmp` #171). A concurrent writer whose
    /// inserted node satisfies any of these closes an rw-edge into this transaction.
    predicate_reads: HashSet<PredicateRead>,
    /// Keys this transaction wrote (its write set).
    writes: HashSet<Key>,
    /// Predicate markers this transaction's inserts/modifications satisfy (its **predicate** write
    /// footprint, `rmp` #171): the union over every node it created/relabelled/set of the markers that
    /// node now matches. A concurrent predicate-reader whose marker is in this set gains an inbound
    /// rw-edge. Retained (like [`writes`](Self::writes)) until GC so a *later* concurrent predicate
    /// read can still discover the conflict.
    predicate_writes: HashSet<PredicateRead>,
    /// Has an **inbound** rw-edge `X --rw--> self` (someone read what self wrote).
    in_conflict: bool,
    /// Has an **outbound** rw-edge `self --rw--> X` (self read what someone else wrote).
    out_conflict: bool,
    /// Transactions this one has an outbound rw-edge to (`self --rw--> target`).
    out_edges: HashSet<TxnId>,
    /// Transactions that have an inbound rw-edge into this one (`source --rw--> self`). Tracked so a
    /// dangerous structure whose pivot has already committed can be broken at edge-formation time.
    in_edges: HashSet<TxnId>,
    /// Commit timestamp once committed (`None` while in flight).
    commit_ts: Option<Timestamp>,
    /// Begin timestamp (snapshot), to decide concurrency.
    begin_ts: Timestamp,
}

/// The SSI dangerous-structure tracker over all in-flight and recently-committed transactions.
#[derive(Debug, Default)]
pub struct SsiTracker {
    txns: HashMap<TxnId, TxnConflict>,
    /// For each key, the set of transactions that currently hold a SIREAD marker on it. A reverse
    /// index so a write can find concurrent readers in O(readers-of-key).
    readers_of: HashMap<Key, HashSet<TxnId>>,
    /// For each [`PredicateRead`] marker, the set of transactions that currently hold it. The
    /// predicate analogue of [`readers_of`](Self::readers_of): a node insert enumerates the predicate
    /// markers it satisfies and finds the concurrent predicate-readers in O(matched-markers) (`rmp`
    /// #171). Maintained in lock-step with each `TxnConflict::predicate_reads` and cleared on
    /// [`forget`](Self::forget).
    predicate_readers_of: HashMap<PredicateRead, HashSet<TxnId>>,
    /// Transactions condemned to abort at their commit. Populated when a dangerous structure
    /// completes around a pivot that has **already committed** (so the pivot itself cannot be the
    /// victim): the still-active endpoint that just closed the structure is doomed instead. This is
    /// the eager counterpart of the commit-time [`detect_pivot_abort`](Self::detect_pivot_abort),
    /// which alone cannot catch a pivot whose two rw-edges form only after it commits (`rmp` audit F9).
    doomed: HashSet<TxnId>,
}

impl SsiTracker {
    /// An empty tracker.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Registers transaction `txn` (begun at `begin_ts`) so its conflicts can be tracked.
    pub fn register(&mut self, txn: TxnId, begin_ts: Timestamp) {
        self.txns.entry(txn).or_insert_with(|| TxnConflict {
            begin_ts,
            ..TxnConflict::default()
        });
    }

    /// Records a non-blocking SIREAD marker: `reader` read `key` (`04 §5.4`).
    ///
    /// If a *concurrent* transaction has already written `key`, this read closes an
    /// rw-antidependency `reader --rw--> writer` immediately (the read saw a stale version the
    /// writer superseded).
    pub fn record_read(&mut self, reader: TxnId, key: Key) {
        if let Some(t) = self.txns.get_mut(&reader) {
            t.reads.insert(key);
        }
        self.readers_of.entry(key).or_default().insert(reader);

        // If a concurrent writer already wrote this key, the reader has an outbound rw-edge to it.
        let concurrent_writers: Vec<TxnId> = self
            .txns
            .iter()
            .filter(|(id, t)| {
                **id != reader && t.writes.contains(&key) && self.are_concurrent(reader, **id)
            })
            .map(|(id, _)| *id)
            .collect();
        for w in concurrent_writers {
            self.add_edge(reader, w);
        }
    }

    /// Records that `writer` wrote `key`. Any *concurrent* transaction that SIREAD-marked `key`
    /// gains an outbound rw-edge `reader --rw--> writer` (`04 §5.4`).
    pub fn record_write(&mut self, writer: TxnId, key: Key) {
        if let Some(t) = self.txns.get_mut(&writer) {
            t.writes.insert(key);
        }
        let readers: Vec<TxnId> = self
            .readers_of
            .get(&key)
            .into_iter()
            .flatten()
            .copied()
            .filter(|r| *r != writer && self.are_concurrent(*r, writer))
            .collect();
        for r in readers {
            self.add_edge(r, writer);
        }
    }

    /// Records a **predicate** SIREAD marker: `reader` read the set of nodes matching `predicate`
    /// (`04 §5.4`, `rmp` #171). This is the phantom-safe counterpart of [`record_read`](Self::record_read):
    /// it tracks the *absence* (or presence) of matching nodes, so a concurrent **insert** that makes a
    /// node match `predicate` closes an rw-antidependency even though no physical record is shared.
    ///
    /// If a *concurrent* transaction has already inserted a node satisfying `predicate` (announced via
    /// [`record_predicate_write`](Self::record_predicate_write)), this read closes the rw-edge
    /// `reader --rw--> writer` immediately — symmetric to how `record_read` closes an edge against a
    /// concurrent writer that already wrote the read key.
    pub fn record_predicate_read(&mut self, reader: TxnId, predicate: PredicateRead) {
        if let Some(t) = self.txns.get_mut(&reader) {
            t.predicate_reads.insert(predicate.clone());
        }
        self.predicate_readers_of
            .entry(predicate.clone())
            .or_default()
            .insert(reader);

        // A concurrent writer that already announced an insert satisfying this exact predicate is an
        // outbound rw-edge target for the reader (the reader saw an absence the writer superseded).
        let concurrent_writers: Vec<TxnId> = self
            .txns
            .iter()
            .filter(|(id, t)| {
                **id != reader
                    && t.predicate_writes.contains(&predicate)
                    && self.are_concurrent(reader, **id)
            })
            .map(|(id, _)| *id)
            .collect();
        for w in concurrent_writers {
            self.add_edge(reader, w);
        }
    }

    /// Records that `writer` inserted/modified a node whose **predicate footprint** is `footprint`:
    /// the full set of [`PredicateRead`] markers that node now satisfies (its `AllNodes` marker, one
    /// `Label` marker per label it carries, and one `Equality` marker per `(label, property, value)`
    /// it holds). Any *concurrent* transaction holding a predicate marker the footprint contains gains
    /// an rw-edge `reader --rw--> writer` (`rmp` #171) — exactly as [`record_write`](Self::record_write)
    /// closes physical-key edges.
    ///
    /// Idempotent and additive across a transaction's statements: re-announcing a node (e.g. after a
    /// `SET` that adds a property) simply unions in any newly-satisfied markers and re-checks readers.
    pub fn record_predicate_write(&mut self, writer: TxnId, footprint: &[PredicateRead]) {
        for predicate in footprint {
            if let Some(t) = self.txns.get_mut(&writer) {
                t.predicate_writes.insert(predicate.clone());
            }
            let readers: Vec<TxnId> = self
                .predicate_readers_of
                .get(predicate)
                .into_iter()
                .flatten()
                .copied()
                .filter(|r| *r != writer && self.are_concurrent(*r, writer))
                .collect();
            for r in readers {
                self.add_edge(r, writer);
            }
        }
    }

    /// Whether `a` and `b` ran concurrently: neither had committed before the other began. Two
    /// in-flight transactions are always concurrent; a committed transaction is concurrent with `x`
    /// iff it committed after `x` began.
    fn are_concurrent(&self, a: TxnId, b: TxnId) -> bool {
        let (Some(ta), Some(tb)) = (self.txns.get(&a), self.txns.get(&b)) else {
            return false;
        };
        let a_before_b = ta.commit_ts.is_some_and(|c| c <= tb.begin_ts);
        let b_before_a = tb.commit_ts.is_some_and(|c| c <= ta.begin_ts);
        !a_before_b && !b_before_a
    }

    /// Adds the rw-antidependency edge `from --rw--> to` and updates the conflict flags.
    ///
    /// If this edge completes a dangerous structure whose **pivot has already committed** (so it can
    /// no longer be aborted), the still-active endpoint that just closed the structure is added to the
    /// [`doomed`](Self::doomed) set, breaking the would-be cycle before it can fully commit. (When the
    /// pivot is still active, the structure is left to the commit-time [`detect_pivot_abort`].)
    fn add_edge(&mut self, from: TxnId, to: TxnId) {
        if from == to {
            return;
        }
        if let Some(t) = self.txns.get_mut(&from) {
            t.out_conflict = true;
            t.out_edges.insert(to);
        }
        if let Some(t) = self.txns.get_mut(&to) {
            t.in_conflict = true;
            t.in_edges.insert(from);
        }

        // Eager committed-pivot break. The just-added edge can make either endpoint a pivot (in +
        // out). If that pivot has already committed, neither commit-time case can abort it, so doom
        // the *other* endpoint of this edge — the active transaction that just closed the structure.
        let pivot_committed = |s: &Self, p: TxnId| {
            s.txns
                .get(&p)
                .is_some_and(|t| t.in_conflict && t.out_conflict && t.commit_ts.is_some())
        };
        let active = |s: &Self, p: TxnId| s.txns.get(&p).is_some_and(|t| t.commit_ts.is_none());
        // `to` became a committed pivot ⇒ its in-partner `from` (the active reader) is the victim.
        if pivot_committed(self, to) && active(self, from) {
            self.doomed.insert(from);
        }
        // `from` became a committed pivot ⇒ its out-partner `to` (the active writer) is the victim.
        if pivot_committed(self, from) && active(self, to) {
            self.doomed.insert(to);
        }
    }

    /// Decides whether committing `txn` must abort to break a dangerous structure (`04 §5.4`).
    ///
    /// Returns `Some(victim)` — the [`TxnId`] to abort with a serialization failure — when a
    /// dangerous structure in which `txn` participates can close a cycle, and `None` when it is safe
    /// to commit.
    ///
    /// Implements the pivot rule and the read-only optimization; see the module docs for the
    /// safe-retry guarantee.
    #[must_use]
    pub fn detect_pivot_abort(&self, txn: TxnId) -> Option<TxnId> {
        // Eagerly-condemned victim: a dangerous structure completed around an already-committed pivot
        // and this transaction was chosen to break it (`add_edge`). Abort it (self) — a retriable
        // serialization failure, like any other SSI abort.
        if self.doomed.contains(&txn) {
            return Some(txn);
        }

        let t = self.txns.get(&txn)?;

        // Read-only optimization: a transaction that wrote nothing cannot be the pivot of a
        // structure its own commit closes (it has no outbound edge it created by writing).
        if t.writes.is_empty() && !t.out_conflict {
            return None;
        }

        // Case A: the committing transaction is itself the pivot (in + out conflict). Cahill's
        // condition: its outbound partner committed first or is concurrent (so the cycle can close).
        if t.in_conflict && t.out_conflict {
            let closes = t.out_edges.iter().any(|out| {
                self.txns.get(out).is_some_and(|o| {
                    // Outbound partner committed before us, or is still concurrent (in flight).
                    o.commit_ts.is_some() || self.are_concurrent(txn, *out)
                })
            });
            if closes {
                // Abort the pivot (self). An already-committed outbound partner can never be the
                // victim, so at least one member of every structure survives (safe retry).
                return Some(txn);
            }
        }

        // Case B: the committing transaction `Tout` is the *outbound* target of a pivot
        // `Tin --rw--> Tpivot --rw--> Tout(=txn)`. We commit `Tout`; the pivot is the still-running
        // (or to-be-checked) middle transaction, which is the safe victim because aborting the
        // pivot — not the now-committing endpoint — guarantees forward progress.
        //
        // Pick the **lowest-id** qualifying pivot rather than the first one iteration yields: when more
        // than one pivot qualifies, a deterministic tie-break keeps the abort choice a pure function of
        // the transaction set (independent of map iteration order), which the DST relies on for
        // reproducibility.
        self.txns
            .iter()
            .filter(|&(&pid, p)| {
                pid != txn
                    && p.in_conflict
                    && p.out_conflict
                    && p.out_edges.contains(&txn)
                    && p.commit_ts.is_none()
            })
            .map(|(&pid, _)| pid)
            .min()
    }

    /// Marks `txn` committed at `commit_ts` (kept for conflict resolution until GC).
    pub fn record_commit(&mut self, txn: TxnId, commit_ts: Timestamp) {
        if let Some(t) = self.txns.get_mut(&txn) {
            t.commit_ts = Some(commit_ts);
        }
    }

    /// Forgets `txn` entirely (aborted, or GC'd after no live snapshot can observe it).
    pub fn forget(&mut self, txn: TxnId) {
        self.doomed.remove(&txn);
        if let Some(t) = self.txns.remove(&txn) {
            for key in t.reads {
                if let Some(set) = self.readers_of.get_mut(&key) {
                    set.remove(&txn);
                    if set.is_empty() {
                        self.readers_of.remove(&key);
                    }
                }
            }
            // Drop this transaction's predicate markers from the reverse index too, so a later writer
            // never closes an edge against a forgotten reader (`rmp` #171).
            for predicate in t.predicate_reads {
                if let Some(set) = self.predicate_readers_of.get_mut(&predicate) {
                    set.remove(&txn);
                    if set.is_empty() {
                        self.predicate_readers_of.remove(&predicate);
                    }
                }
            }
        }
    }

    /// Prunes committed transactions no live transaction can conflict with, returning how many were
    /// forgotten (`04 §5.5`, `rmp` task #59).
    ///
    /// `low_water` is the oldest active begin timestamp (`None` = no active transactions). A
    /// transaction that committed at or before `low_water` committed before every active transaction
    /// began, so it is concurrent with none of them: no rw-antidependency edge can connect it to any
    /// live transaction (edges are only ever recorded between concurrent transactions, and any
    /// transaction that *was* concurrent with it has since finished). Forgetting it can therefore
    /// never hide a dangerous structure from [`detect_pivot_abort`](Self::detect_pivot_abort) —
    /// the same retention rule PostgreSQL applies to its SSI summary of committed transactions.
    pub fn prune_committed(&mut self, low_water: Option<Timestamp>) -> usize {
        let settled: Vec<TxnId> = self
            .txns
            .iter()
            .filter(|(_, t)| {
                t.commit_ts
                    .is_some_and(|c| low_water.is_none_or(|mark| c <= mark))
            })
            .map(|(id, _)| *id)
            .collect();
        for txn in &settled {
            self.forget(*txn);
        }
        settled.len()
    }

    /// Whether `txn` currently has both an inbound and an outbound rw-edge (is a pivot). Test aid.
    #[must_use]
    pub fn is_pivot(&self, txn: TxnId) -> bool {
        self.txns
            .get(&txn)
            .is_some_and(|t| t.in_conflict && t.out_conflict)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ts(n: u64) -> Timestamp {
        Timestamp(n)
    }

    #[test]
    fn no_conflict_no_abort() {
        let mut s = SsiTracker::new();
        s.register(TxnId(1), ts(1));
        s.register(TxnId(2), ts(1));
        s.record_read(TxnId(1), 10);
        s.record_write(TxnId(2), 20); // disjoint key
        assert_eq!(s.detect_pivot_abort(TxnId(1)), None);
        assert_eq!(s.detect_pivot_abort(TxnId(2)), None);
    }

    #[test]
    fn write_skew_forms_a_pivot_and_aborts() {
        // Classic write-skew: T1 reads x writes y; T2 reads y writes x; concurrent.
        let mut s = SsiTracker::new();
        s.register(TxnId(1), ts(1));
        s.register(TxnId(2), ts(1));
        s.record_read(TxnId(1), 100); // x
        s.record_read(TxnId(2), 200); // y
        s.record_write(TxnId(1), 200); // T1 writes y -> T2 --rw--> T1
        s.record_write(TxnId(2), 100); // T2 writes x -> T1 --rw--> T2
        // Both are now pivots (in + out conflict).
        assert!(s.is_pivot(TxnId(1)));
        assert!(s.is_pivot(TxnId(2)));
        // First committer aborts itself (its outbound partner is concurrent -> cycle can close).
        let victim = s.detect_pivot_abort(TxnId(1));
        assert_eq!(victim, Some(TxnId(1)));
    }

    #[test]
    fn after_first_commits_second_commits_safely() {
        // Safe-retry: once one of the pair has committed, the structure that the *second* commit
        // would close must abort the (still-running) pivot, never the already-committed one.
        let mut s = SsiTracker::new();
        s.register(TxnId(1), ts(1));
        s.register(TxnId(2), ts(1));
        s.record_read(TxnId(1), 100);
        s.record_read(TxnId(2), 200);
        s.record_write(TxnId(1), 200);
        s.record_write(TxnId(2), 100);
        // T1 commits (it was the pivot and would normally abort, but say the manager committed it
        // because it was alone first — we model: T1 commits, then T2 tries).
        s.record_commit(TxnId(1), ts(10));
        let victim = s.detect_pivot_abort(TxnId(2));
        // T2 is itself a pivot; its outbound partner T1 already committed -> T2 aborts itself.
        assert_eq!(victim, Some(TxnId(2)));
        // The committed T1 is never selected.
        assert_ne!(victim, Some(TxnId(1)));
    }

    #[test]
    fn read_only_transaction_never_aborts_itself() {
        let mut s = SsiTracker::new();
        s.register(TxnId(1), ts(1)); // read-only
        s.register(TxnId(2), ts(1)); // writer
        s.record_read(TxnId(1), 100);
        s.record_write(TxnId(2), 100); // T1 --rw--> T2
        // T1 wrote nothing -> exempt.
        assert_eq!(s.detect_pivot_abort(TxnId(1)), None);
    }

    #[test]
    fn forget_clears_read_markers() {
        let mut s = SsiTracker::new();
        s.register(TxnId(1), ts(1));
        s.record_read(TxnId(1), 100);
        s.forget(TxnId(1));
        // A later writer of key 100 finds no concurrent reader.
        s.register(TxnId(2), ts(2));
        s.record_write(TxnId(2), 100);
        assert_eq!(s.detect_pivot_abort(TxnId(2)), None);
    }

    #[test]
    fn prune_committed_forgets_only_settled_transactions() {
        let mut s = SsiTracker::new();
        // T1 committed at 5; T2 committed at 30; T3 is in flight (begun at 20).
        s.register(TxnId(1), ts(1));
        s.record_write(TxnId(1), 100);
        s.record_commit(TxnId(1), ts(5));
        s.register(TxnId(2), ts(10));
        s.record_write(TxnId(2), 200);
        s.record_commit(TxnId(2), ts(30));
        s.register(TxnId(3), ts(20));
        s.record_read(TxnId(3), 200);

        // low_water = 20 (T3's begin): T1 (committed at 5 ≤ 20) is settled; T2 (committed at 30,
        // concurrent with T3) and T3 (in flight) must be retained.
        assert_eq!(s.prune_committed(Some(ts(20))), 1);
        assert!(!s.is_pivot(TxnId(1))); // forgotten
        // T3's edge to the retained T2 still works: T3 read 200 which T2 (concurrent) wrote.
        assert!(s.txns.contains_key(&TxnId(2)));
        assert!(s.txns.contains_key(&TxnId(3)));

        // With no active transactions, every committed entry is settled; in-flight ones stay.
        assert_eq!(s.prune_committed(None), 1);
        assert!(!s.txns.contains_key(&TxnId(2)));
        assert!(s.txns.contains_key(&TxnId(3)));
    }

    fn label_pred(label: u32) -> PredicateRead {
        PredicateRead::Label(label)
    }

    #[test]
    fn predicate_read_then_concurrent_matching_insert_closes_rw_edge() {
        // `rmp` #171: T1 predicate-reads label L (sees nothing); T2 (concurrent) inserts a node of L.
        // T2's insert must close `T1 --rw--> T2`, even though no physical record is shared.
        let mut s = SsiTracker::new();
        s.register(TxnId(1), ts(1));
        s.register(TxnId(2), ts(1));
        s.record_predicate_read(TxnId(1), label_pred(7));
        // T2 inserts a node carrying label 7 (its predicate footprint includes Label(7)).
        s.record_predicate_write(TxnId(2), &[PredicateRead::AllNodes, label_pred(7)]);
        // The rw-edge T1 --rw--> T2 is now present: T1 has an outbound conflict.
        assert!(s.txns.get(&TxnId(1)).unwrap().out_conflict);
        assert!(s.txns.get(&TxnId(2)).unwrap().in_conflict);
    }

    #[test]
    fn predicate_write_before_concurrent_read_closes_rw_edge() {
        // Symmetric order: the insert is announced first, then a concurrent reader registers the
        // matching predicate marker. `record_predicate_read` must discover the prior concurrent write.
        let mut s = SsiTracker::new();
        s.register(TxnId(1), ts(1));
        s.register(TxnId(2), ts(1));
        s.record_predicate_write(TxnId(2), &[PredicateRead::AllNodes, label_pred(7)]);
        s.record_predicate_read(TxnId(1), label_pred(7));
        assert!(s.txns.get(&TxnId(1)).unwrap().out_conflict);
        assert!(s.txns.get(&TxnId(2)).unwrap().in_conflict);
    }

    #[test]
    fn equality_predicate_matches_only_exact_value() {
        // An equality predicate read on (label 7, prop 3, value-A) is closed by an insert of the same
        // (7, 3, A), but NOT by an insert of (7, 3, B).
        let a = PredicateRead::Equality {
            label: 7,
            property: 3,
            value: vec![0xAA],
        };
        let b_footprint = [
            PredicateRead::AllNodes,
            label_pred(7),
            PredicateRead::Equality {
                label: 7,
                property: 3,
                value: vec![0xBB],
            },
        ];
        let mut s = SsiTracker::new();
        s.register(TxnId(1), ts(1));
        s.register(TxnId(2), ts(1));
        s.record_predicate_read(TxnId(1), a);
        // T2 inserts a node whose equality footprint is value B, not A: no equality edge forms.
        s.record_predicate_write(TxnId(2), &b_footprint);
        assert!(
            !s.txns.get(&TxnId(1)).unwrap().out_conflict,
            "an equality predicate on value A must not conflict with an insert of value B"
        );
    }

    #[test]
    fn non_overlapping_predicate_read_and_insert_no_edge() {
        // A serial (non-overlapping) predicate read + insert must NOT conflict: T1 commits before T2
        // begins, so T2's matching insert is not concurrent with T1's predicate read. This is the
        // no-false-abort-on-serial guarantee — the same `are_concurrent` gate physical-key edges use.
        let mut s = SsiTracker::new();
        s.register(TxnId(1), ts(1));
        s.record_predicate_read(TxnId(1), label_pred(7));
        s.record_commit(TxnId(1), ts(5));
        s.register(TxnId(2), ts(10)); // begins after T1 committed
        s.record_predicate_write(TxnId(2), &[PredicateRead::AllNodes, label_pred(7)]);
        assert!(
            !s.txns.get(&TxnId(1)).unwrap().out_conflict,
            "a serial (non-concurrent) predicate read + insert must not form an rw-edge"
        );
        assert_eq!(s.detect_pivot_abort(TxnId(2)), None);
    }

    #[test]
    fn forget_clears_predicate_markers() {
        // After a reader is forgotten, a later writer must not close an edge against it (no dangling
        // entry in `predicate_readers_of`).
        let mut s = SsiTracker::new();
        s.register(TxnId(1), ts(1));
        s.record_predicate_read(TxnId(1), label_pred(7));
        s.forget(TxnId(1));
        assert!(!s.predicate_readers_of.contains_key(&label_pred(7)));
        s.register(TxnId(2), ts(2));
        s.record_predicate_write(TxnId(2), &[label_pred(7)]);
        assert_eq!(s.detect_pivot_abort(TxnId(2)), None);
    }

    #[test]
    fn phantom_write_skew_across_two_predicates_forms_a_pivot() {
        // The end-to-end `rmp` #171 shape at the tracker level: T1 reads predicate Px (empty) + inserts
        // a node matching Py; T2 reads Py (empty) + inserts a node matching Px; concurrent. Two rw-edges
        // form (T1->T2 and T2->T1) → both are pivots → one is aborted, restoring serializability.
        let px = label_pred(100);
        let py = label_pred(200);
        let mut s = SsiTracker::new();
        s.register(TxnId(1), ts(1));
        s.register(TxnId(2), ts(1));
        // Reads of the empty predicates.
        s.record_predicate_read(TxnId(1), px.clone());
        s.record_predicate_read(TxnId(2), py.clone());
        // Each inserts a node matching the OTHER's predicate.
        s.record_predicate_write(TxnId(1), &[PredicateRead::AllNodes, py]); // T2 --rw--> T1
        s.record_predicate_write(TxnId(2), &[PredicateRead::AllNodes, px]); // T1 --rw--> T2
        // Each also wrote a node (non-read-only), so the pivot rule applies.
        s.record_write(TxnId(1), 1);
        s.record_write(TxnId(2), 2);
        assert!(s.is_pivot(TxnId(1)));
        assert!(s.is_pivot(TxnId(2)));
        // The first committer aborts itself (its outbound partner is concurrent → cycle can close).
        assert_eq!(s.detect_pivot_abort(TxnId(1)), Some(TxnId(1)));
    }

    fn equality_pred(label: u32, property: u32, value: Vec<u8>) -> PredicateRead {
        PredicateRead::Equality {
            label,
            property,
            value,
        }
    }

    #[test]
    fn equal_value_bytes_close_equality_rw_edge_c1() {
        // `rmp` #171 blocker C1 (tracker contract): an equality marker matches on **value-byte
        // equality**. The fix lives in the *encoder* (`graphus-index::keycodec::encode_equality_canonical`,
        // proven there) which makes Cypher-equal `1` and `1.0` produce the SAME bytes; this test pins
        // the complementary tracker invariant — equal bytes ⇒ the rw-edge closes — so the reader of
        // `{p: 1}` and the concurrent insert of `{p: 1.0}` (which the encoder maps to identical bytes)
        // conflict. The canonical bytes are modelled here as one shared `value` vector.
        let canonical = vec![0x40, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]; // tag::NUMBER + magnitude
        let mut s = SsiTracker::new();
        s.register(TxnId(1), ts(1));
        s.register(TxnId(2), ts(1));
        s.record_predicate_read(TxnId(1), equality_pred(7, 3, canonical.clone()));
        s.record_predicate_write(
            TxnId(2),
            &[
                PredicateRead::AllNodes,
                label_pred(7),
                equality_pred(7, 3, canonical),
            ],
        );
        assert!(
            s.txns.get(&TxnId(1)).unwrap().out_conflict,
            "equal canonical equality-marker bytes must close the rw-edge (blocker C1)"
        );
    }

    #[test]
    fn read_then_delete_write_skew_forms_a_pivot_b1() {
        // `rmp` #171 blocker B1: read-then-delete write-skew at the tracker level. T1 predicate-reads
        // label 7 (sees a matching node) + writes elsewhere; T2 DELETEs a node satisfying label 7 (its
        // pre-image footprint announces Label(7)) + writes elsewhere; concurrent. The delete's
        // pre-image predicate write closes `T1 --rw--> T2`, and the symmetric structure makes a pivot.
        let mut s = SsiTracker::new();
        s.register(TxnId(1), ts(1));
        s.register(TxnId(2), ts(1));
        // T1 reads label 7 (a non-empty predicate); T2 reads label 8.
        s.record_predicate_read(TxnId(1), label_pred(7));
        s.record_predicate_read(TxnId(2), label_pred(8));
        // Each "unmatches" a node satisfying the OTHER's predicate (a delete/relabel pre-image write).
        s.record_predicate_write(TxnId(1), &[PredicateRead::AllNodes, label_pred(8)]); // T2 --rw--> T1
        s.record_predicate_write(TxnId(2), &[PredicateRead::AllNodes, label_pred(7)]); // T1 --rw--> T2
        s.record_write(TxnId(1), 1);
        s.record_write(TxnId(2), 2);
        assert!(s.is_pivot(TxnId(1)));
        assert!(s.is_pivot(TxnId(2)));
        assert_eq!(s.detect_pivot_abort(TxnId(1)), Some(TxnId(1)));
    }

    fn reltype_pred(token: u32) -> PredicateRead {
        PredicateRead::RelType(token)
    }

    #[test]
    fn relationship_phantom_closes_rw_edge_a1() {
        // `rmp` #171 blocker A1: a reader of `MATCH ()-[r:T]-()` (rel-type token 5, sees nothing) and a
        // concurrent `CREATE` of a `:T` edge (its footprint announces RelType(5)). The create must close
        // `reader --rw--> writer`, even though the new edge's physical id was never SIREAD-marked.
        let mut s = SsiTracker::new();
        s.register(TxnId(1), ts(1));
        s.register(TxnId(2), ts(1));
        s.record_predicate_read(TxnId(1), reltype_pred(5));
        s.record_predicate_write(TxnId(2), &[PredicateRead::AnyRel, reltype_pred(5)]);
        assert!(s.txns.get(&TxnId(1)).unwrap().out_conflict);
        assert!(s.txns.get(&TxnId(2)).unwrap().in_conflict);
    }

    #[test]
    fn relationship_phantom_write_skew_forms_a_pivot_a1() {
        // End-to-end A1 shape: T1 reads rel-type 5 (empty) + creates a rel of type 6; T2 reads type 6
        // (empty) + creates a rel of type 5; concurrent. Two rw-edges form ⇒ both pivots ⇒ one aborts.
        let mut s = SsiTracker::new();
        s.register(TxnId(1), ts(1));
        s.register(TxnId(2), ts(1));
        s.record_predicate_read(TxnId(1), reltype_pred(5));
        s.record_predicate_read(TxnId(2), reltype_pred(6));
        s.record_predicate_write(TxnId(1), &[PredicateRead::AnyRel, reltype_pred(6)]); // T2 --rw--> T1
        s.record_predicate_write(TxnId(2), &[PredicateRead::AnyRel, reltype_pred(5)]); // T1 --rw--> T2
        s.record_write(TxnId(1), 1);
        s.record_write(TxnId(2), 2);
        assert!(s.is_pivot(TxnId(1)));
        assert!(s.is_pivot(TxnId(2)));
        assert_eq!(s.detect_pivot_abort(TxnId(1)), Some(TxnId(1)));
    }

    #[test]
    fn any_rel_reader_closes_against_typed_create_a1() {
        // An untyped `MATCH ()-[r]-()` reader registers `AnyRel`; a concurrent typed create announces
        // `AnyRel` in its footprint too, so the edge closes regardless of type.
        let mut s = SsiTracker::new();
        s.register(TxnId(1), ts(1));
        s.register(TxnId(2), ts(1));
        s.record_predicate_read(TxnId(1), PredicateRead::AnyRel);
        s.record_predicate_write(TxnId(2), &[PredicateRead::AnyRel, reltype_pred(9)]);
        assert!(s.txns.get(&TxnId(1)).unwrap().out_conflict);
    }

    #[test]
    fn serial_relationship_read_and_create_no_edge_a1() {
        // No-false-abort on serial rel phantom: T1 reads rel-type 5 and commits before T2 begins, so
        // T2's matching create is not concurrent — no rw-edge.
        let mut s = SsiTracker::new();
        s.register(TxnId(1), ts(1));
        s.record_predicate_read(TxnId(1), reltype_pred(5));
        s.record_commit(TxnId(1), ts(5));
        s.register(TxnId(2), ts(10));
        s.record_predicate_write(TxnId(2), &[PredicateRead::AnyRel, reltype_pred(5)]);
        assert!(
            !s.txns.get(&TxnId(1)).unwrap().out_conflict,
            "a serial (non-concurrent) rel read + create must not form an rw-edge"
        );
        assert_eq!(s.detect_pivot_abort(TxnId(2)), None);
    }

    #[test]
    fn non_concurrent_reader_creates_no_edge() {
        // A reader whose snapshot is after the writer committed is not concurrent -> no rw-edge.
        let mut s = SsiTracker::new();
        s.register(TxnId(1), ts(1));
        s.record_write(TxnId(1), 100);
        s.record_commit(TxnId(1), ts(5));
        s.register(TxnId(2), ts(10)); // begins after T1 committed
        s.record_read(TxnId(2), 100);
        assert!(!s.is_pivot(TxnId(2)));
        assert_eq!(s.detect_pivot_abort(TxnId(2)), None);
    }
}
