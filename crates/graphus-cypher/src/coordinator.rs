//! The transaction coordinator: drives **concurrent** Cypher transactions over one shared record
//! store with Serializable Snapshot Isolation (`04-technical-design.md` §5.4/§5.7; `rmp` task #46).
//!
//! [`crate::record_graph::RecordStoreGraph`] already runs one transaction at a time over the
//! MVCC-native store (`rmp` task #45). [`TxnCoordinator`] is the layer above that lets several
//! transactions be open at once and makes their concurrent execution **serializable**:
//!
//! - it owns the one shared [`RecordStore`] (so several transactions read/write the same graph) and
//!   uses the store itself as the timestamp source (the store became the commit-timestamp oracle in
//!   `rmp` task #45: [`RecordStore::snapshot_ts`] is the begin snapshot, and a `commit` advances it);
//! - it owns the shared [`SsiTracker`] and [`LockTable`] from `graphus-txn` — the **complete,
//!   tested** SSI machine — so each transaction's statements contribute non-blocking SIREAD markers
//!   and rw-antidependency edges, and writes take a first-updater-wins lock;
//! - at [`commit`](TxnCoordinator::commit) it runs SSI validation (SERIALIZABLE only) and aborts a
//!   **pivot** on a dangerous structure with a retriable serialization error (PostgreSQL safe-retry:
//!   at least one transaction in any unsafe set commits, no livelock). [`IsolationLevel::Snapshot`]
//!   is the documented weaker opt-in that skips validation and therefore permits write-skew.
//!
//! ## Driving a transaction
//!
//! ```ignore
//! let mut coord = TxnCoordinator::new(store);
//! let t1 = coord.begin_serializable();
//! {
//!     // One statement: borrow a per-statement graph seam, run the executor over it, drop it.
//!     let mut g = coord.statement(t1)?;
//!     let mut cursor = execute(&plan, &bound, &mut g)?;
//!     let _rows = cursor.collect_all()?;
//!     // (check `g.has_error()` before relying on the rows)
//! }
//! coord.commit(t1)?; // may return a retriable serialization failure under SSI
//! ```
//!
//! A transaction spans many statements: [`begin`](TxnCoordinator::begin) once, any number of
//! [`statement`](TxnCoordinator::statement) executions (the store is borrowed only for each
//! statement's duration, never for the whole transaction), then [`commit`](TxnCoordinator::commit)
//! or [`rollback`](TxnCoordinator::rollback). Markers and locks accumulate across statements in the
//! coordinator's shared trackers.

use std::cell::RefCell;
use std::collections::{HashMap, VecDeque};
use std::rc::Rc;

use graphus_core::Value;
use graphus_core::error::{GraphusError, Result};
use graphus_core::{Timestamp, TxnId};
use graphus_index::histogram::PropertyHistogram;
use graphus_io::BlockDevice;
use graphus_storage::{IndexState, Namespace, RecordStore};
use graphus_txn::{IsolationLevel, LockTable, Snapshot, SsiTracker};
use graphus_wal::LogSink;

use crate::catalog::IndexCatalog;
use crate::index_set::IndexSet;
use crate::record_graph::RecordStoreGraph;
use crate::statistics::Statistics;
use crate::store_statistics;

/// Live state of an open transaction the coordinator drives.
#[derive(Debug, Clone, Copy)]
struct ActiveTxn {
    snapshot: Snapshot,
    isolation: IsolationLevel,
}

/// One in-progress **non-blocking** node-property index build (`rmp` task #91).
///
/// A build indexes the nodes captured in `snapshot` (the store's live node-id list at build
/// start), a bounded chunk at a time, advancing `cursor` until it reaches the end; the index is
/// then promoted to [`IndexState::Online`]. Nodes created *after* the snapshot, value changes,
/// and deletes are all handled outside this snapshot by [`RecordStoreGraph::reindex_node`] /
/// the candidate-set re-check (see [`TxnCoordinator::advance_index_builds`] for the full
/// consistency argument), so the snapshot only needs to cover the rows that already existed.
struct PendingIndexBuild {
    /// The label token the index is declared on.
    label_token: u32,
    /// The property-key token the index is declared on.
    prop_key: u32,
    /// The node-id list captured at build start (`store.scan_node_ids()`). Indexing walks this in
    /// order; a since-deleted id simply inserts a stale candidate (harmless — the re-check drops it).
    snapshot: Vec<u64>,
    /// The next index into `snapshot` to process; the build is complete once `cursor >= snapshot.len()`.
    cursor: usize,
}

/// Drives concurrent, serializable Cypher transactions over one shared [`RecordStore`] (`04 §5`).
pub struct TxnCoordinator<D: BlockDevice, S: LogSink> {
    /// The one shared store, behind `Rc<RefCell<…>>` so each statement seam borrows it for the
    /// statement's duration while the transaction stays open across statements.
    store: Rc<RefCell<RecordStore<D, S>>>,
    /// The shared SSI dangerous-structure tracker (`04 §5.4`).
    ssi: Rc<RefCell<SsiTracker>>,
    /// The shared first-updater-wins write-lock table (`04 §5.7`).
    locks: Rc<RefCell<LockTable>>,
    /// The shared derived secondary [`IndexSet`] (`rmp` task #48): the always-present label index
    /// plus any declared node-property indexes. Rebuilt from the store on [`new`](Self::new) and on
    /// [`create_node_property_index`](Self::create_node_property_index), and maintained per write by
    /// each statement seam ([`RecordStoreGraph::reindex_node`]). It holds **candidate** ids only
    /// (never visibility-filtered), so it is in-memory and never committed or recovered — a fresh
    /// coordinator over a recovered store rebuilds a store-consistent index by construction.
    index: Rc<RefCell<IndexSet>>,
    /// Open transactions (begun, not yet committed/rolled back).
    active: HashMap<TxnId, ActiveTxn>,
    /// Monotonic transaction-id source (distinct from the commit timestamp, which the store issues).
    next_txn_id: u64,
    /// Queue of in-progress **non-blocking** index builds (`rmp` task #91), advanced in bounded
    /// chunks by [`advance_index_builds`](Self::advance_index_builds) between engine commands. The
    /// front build is the one currently being populated; each completes (durably promoted to
    /// [`IndexState::Online`]) before the next starts, so the queue is processed in declaration order.
    pending_builds: VecDeque<PendingIndexBuild>,
}

impl<D: BlockDevice, S: LogSink> TxnCoordinator<D, S> {
    /// A coordinator over `store` with no open transactions.
    ///
    /// The derived [`IndexSet`] is built empty and then **rebuilt** from `store` so it is consistent
    /// with the persisted graph by construction (`rmp` task #48). Over a freshly-recovered store this
    /// is precisely the crash-recovery requirement: a new coordinator's index reflects exactly the
    /// recovered, committed graph — nothing to commit or replay for the index itself.
    ///
    /// # Resuming an interrupted non-blocking build (the `rmp` task #91 crash path)
    ///
    /// A non-blocking index build ([`begin_online_node_property_index`](Self::begin_online_node_property_index))
    /// records its catalog entry durably as [`IndexState::Populating`] and only flips it to
    /// [`IndexState::Online`] once every snapshot node is indexed. If a crash interrupts a build, its
    /// catalog entry recovers `Populating`. But `rebuild_index` above has just **synchronously and
    /// fully** repopulated *every registered index* — `Populating` ones included — from the recovered
    /// store, so an interrupted build is now actually complete. We therefore **promote every
    /// durable-`Populating` index to `Online`** here, in one committed transaction, and mirror the
    /// promotion in the in-memory set. Startup is allowed to block: the server is not yet serving when
    /// the coordinator is constructed (see `graphus_server::engine::spawn_engine`). After this, no
    /// build is left pending — they either completed online before the crash or are completed by the
    /// rebuild here.
    #[must_use]
    pub fn new(store: RecordStore<D, S>) -> Self {
        let store = Rc::new(RefCell::new(store));
        let index = Rc::new(RefCell::new(IndexSet::new()));
        Self::rebuild_index(&store, &index);
        // Promote any index left `Populating` by an interrupted `rmp` task #91 build: the rebuild
        // above already fully populated it from the recovered store, so it is complete. Done with a
        // local txn-id of 0 (no transaction is open yet, and `begin` only ever issues ids `>= 1`).
        let next_txn_id = Self::promote_recovered_populating_indexes(&store, &index, 0);
        Self {
            store,
            ssi: Rc::new(RefCell::new(SsiTracker::new())),
            locks: Rc::new(RefCell::new(LockTable::new())),
            index,
            active: HashMap::new(),
            next_txn_id,
            pending_builds: VecDeque::new(),
        }
    }

    /// Promotes every durable-[`IndexState::Populating`] node-property index to
    /// [`IndexState::Online`] (catalog + in-memory set), in one committed transaction minted from
    /// `next_txn_id`. Returns the advanced `next_txn_id` (so [`new`](Self::new) keeps its monotonic
    /// id source consistent). A no-op (no commit) when no index is `Populating`.
    ///
    /// This is the crash-recovery completion of an interrupted non-blocking build (`rmp` task #91):
    /// by the time this runs the rebuild has already fully populated the in-memory index, so the
    /// durable state simply needs to catch up. The candidate-set contract makes this sound regardless:
    /// even if some node were missed, a seek re-checks the store, so promoting can only ever expose a
    /// fully-populated index. Errors interning/committing are swallowed best-effort: a failed promotion
    /// leaves the index `Populating` (withheld from the planner, scan-and-filter fallback stays
    /// correct), to be retried on the next open.
    fn promote_recovered_populating_indexes(
        store: &Rc<RefCell<RecordStore<D, S>>>,
        index: &Rc<RefCell<IndexSet>>,
        next_txn_id: u64,
    ) -> u64 {
        let populating: Vec<(u32, u32)> = store
            .borrow()
            .node_property_indexes()
            .into_iter()
            .filter(|(_, _, state)| *state == IndexState::Populating)
            .map(|(label_token, prop_key, _)| (label_token, prop_key))
            .collect();
        if populating.is_empty() {
            return next_txn_id;
        }

        let txn = TxnId(next_txn_id + 1);
        store.borrow_mut().begin(txn);
        {
            let mut store = store.borrow_mut();
            for &(label_token, prop_key) in &populating {
                store.set_node_property_index(label_token, prop_key, IndexState::Online);
            }
        }
        if store.borrow_mut().commit(txn).is_err() {
            // Could not make the promotion durable; leave the indexes `Populating` (still correct via
            // the scan fallback) and reconcile on the next open.
            return next_txn_id + 1;
        }
        let mut idx = index.borrow_mut();
        for (label_token, prop_key) in populating {
            idx.set_node_property_state(label_token, prop_key, IndexState::Online);
        }
        next_txn_id + 1
    }

    /// Reloads the durable node-property index catalog into `index` (`rmp` task #90), then clears and
    /// repopulates `index` from every in-use node in `store` (`rmp` task #48): each node's label
    /// tokens go into the label index, and for each **registered** node-property index the node
    /// matches, its current property value is inserted.
    ///
    /// # Durable registration reload (the crash-recovery fix, `rmp` task #90)
    ///
    /// The set of declared node-property indexes is recovered from the store's durable index catalog
    /// **before** the rebuild scan, so a fresh coordinator over a recovered store re-registers exactly
    /// the indexes that were committed — no manual re-registration after recovery. A catalog entry
    /// recorded `Online` is registered `Online`; a `Populating` one is registered, populated by the
    /// scan below, and — since population is synchronous in this task — left registered (its promotion
    /// to `Online` is the coordinator's caller path; `rmp` task #91 owns the non-blocking flip). Any
    /// indexes already registered in `index` (e.g. one just declared via
    /// [`create_node_property_index`](Self::create_node_property_index)) are preserved: the reload only
    /// *adds* the durable set, and [`IndexSet::register_node_property_with_state`] is idempotent.
    ///
    /// This is the store-side analogue of [`RecordStoreGraph::reindex_node`], but it reads directly
    /// off the store (no MVCC snapshot) because the index is a **candidate** set: an entry for a
    /// version that is invisible to some future reader is harmless — every seek re-checks visibility,
    /// the current label, and the current value. Inserting every in-use node's current state
    /// therefore guarantees **no false negatives**.
    ///
    /// Errors reading any single node/label/property are skipped (best-effort): a missing candidate
    /// only degrades that node to the full-scan fallback for that reader, never to a wrong row. The
    /// store and the index are borrowed in separate, non-overlapping scopes.
    fn rebuild_index(store: &Rc<RefCell<RecordStore<D, S>>>, index: &Rc<RefCell<IndexSet>>) {
        // Recover the durable index catalog (`rmp` task #90) into the in-memory set first: this is
        // what makes registration survive a crash. Done before `clear` (which keeps the registered set
        // but wipes entries) so the rebuild scan below indexes the recovered indexes too.
        let durable: Vec<(u32, u32, IndexState)> = store.borrow().node_property_indexes();
        {
            let mut idx = index.borrow_mut();
            for (label_token, prop_key, state) in durable {
                idx.register_node_property_with_state(label_token, prop_key, state);
            }
        }

        index.borrow_mut().clear();

        // The set of registered node-property indexes (any state), captured before walking the store so
        // the index is not borrowed across a store borrow. A `Populating` index is maintained too (so
        // its entries are ready the instant it is promoted), so the rebuild reads the full set here;
        // the planner only ever sees the `Online` subset via `catalog()`.
        let registered: Vec<(u32, u32)> = index.borrow().registered_node_properties();

        let node_ids = match store.borrow_mut().scan_node_ids() {
            Ok(ids) => ids,
            // A store-read fault on the whole scan leaves the index empty; every reader then falls
            // back to a full scan (correct, just unaccelerated).
            Err(_) => return,
        };

        for id in node_ids {
            Self::index_one_node(store, index, id, &registered);
        }
    }

    /// Inserts node `id`'s current label tokens and indexed property values into `index`, for the
    /// set of `registered` `(label_token, prop_key)` indexes. The store and the index are borrowed in
    /// **separate, non-overlapping** scopes (the load-bearing borrow discipline of this file).
    ///
    /// Extracted so the full-store rebuild ([`rebuild_index`](Self::rebuild_index)) and the
    /// incremental non-blocking build ([`advance_index_builds`](Self::advance_index_builds)) index a
    /// node through **exactly one** code path — the per-node logic cannot drift between them. A
    /// store-read fault on this node (an overflow-form bitmap, a non-storable value, a reclaimed slot)
    /// skips that node's entries best-effort: a missing candidate degrades that node to the full-scan
    /// fallback for a reader, never to a wrong row (the candidate-set contract).
    fn index_one_node(
        store: &Rc<RefCell<RecordStore<D, S>>>,
        index: &Rc<RefCell<IndexSet>>,
        id: u64,
        registered: &[(u32, u32)],
    ) {
        // Read this node's current label tokens (store borrow, released before the index borrow).
        let label_tokens = match store.borrow_mut().node_labels(id) {
            Ok(tokens) => tokens,
            Err(_) => return, // overflow-form bitmap or read fault: skip this node's entries.
        };

        // Resolve the node's current property values, keyed by prop-key, so the index borrow
        // below never overlaps a store borrow. `node_property_values` decodes the whole chain
        // newest-first (`rmp` task #50); the first occurrence per key is the newest value. No MVCC
        // snapshot is needed — the index is a candidate set and every seek re-checks visibility.
        let mut values: Vec<(u32, graphus_core::Value)> = Vec::new();
        {
            let chain = match store.borrow_mut().node_property_values(id) {
                Ok(chain) => chain,
                Err(_) => return, // a non-storable / read fault: skip this node's properties.
            };
            for (_pid, key, value) in chain {
                // Newest-wins: keep only the first occurrence of each key.
                if values.iter().any(|(k, _)| *k == key) {
                    continue;
                }
                // Only keep keys that a registered index over one of this node's labels uses.
                let used = registered.iter().any(|&(reg_label, prop_key)| {
                    prop_key == key && label_tokens.contains(&reg_label)
                });
                if used {
                    values.push((key, value));
                }
            }
        }

        let mut index = index.borrow_mut();
        for &lt in &label_tokens {
            index.insert_label(lt, id);
        }
        for (prop_key, value) in &values {
            for &lt in &label_tokens {
                if index.has_node_property(lt, *prop_key) {
                    index.insert_node_property(lt, *prop_key, value, id);
                }
            }
        }
    }

    /// Begins a transaction at `isolation`, returning its [`TxnId`].
    ///
    /// Its read snapshot is the store's latest commit ([`RecordStore::snapshot_ts`], `04 §5.2`), so
    /// it sees exactly what has committed so far; it is registered with the SSI tracker so its
    /// conflicts are tracked from this begin timestamp.
    pub fn begin(&mut self, isolation: IsolationLevel) -> TxnId {
        self.next_txn_id += 1;
        let txn = TxnId(self.next_txn_id);
        let begin_ts = self.store.borrow().snapshot_ts();
        self.store.borrow_mut().begin(txn);
        self.ssi.borrow_mut().register(txn, begin_ts);
        self.active.insert(
            txn,
            ActiveTxn {
                snapshot: Snapshot {
                    owner: txn,
                    ts: begin_ts,
                },
                isolation,
            },
        );
        txn
    }

    /// Begins a SERIALIZABLE transaction (the default level).
    pub fn begin_serializable(&mut self) -> TxnId {
        self.begin(IsolationLevel::Serializable)
    }

    /// Declares a node-property index on `(label, property)`, **durably records it** in the store's
    /// index catalog, and populates it from the current graph (`rmp` tasks #48 / #90).
    ///
    /// The label and property-key tokens are interned **durably** and the `(label_token, prop_key)`
    /// index is recorded in the durable index catalog (`rmp` task #90) — both in one committed
    /// transaction, so the *registration* survives a crash. Before `rmp` task #90 only the tokens were
    /// durable and the registered-index set lived only in the in-memory [`IndexSet`], so after a crash
    /// and reopen the index was silently lost; persisting the catalog entry fixes that. The index is
    /// then registered in the shared [`IndexSet`] and rebuilt so every existing node is indexed, and
    /// subsequent writes maintain it incrementally via the statement seam.
    ///
    /// Population is **synchronous** in this task (the non-blocking incremental build is `rmp`
    /// task #91), so the durable end-state of a successful create is [`IndexState::Online`]: the
    /// catalog entry is written `Online` in the same committed transaction as the tokens, and the
    /// in-memory index is registered `Online`. The index *data* itself is in-memory and candidate-only
    /// (never committed); only the token interning and the catalog entry need durability.
    ///
    /// # Errors
    /// Returns a storage error if interning either token, recording the catalog entry, or the
    /// committing transaction fails.
    pub fn create_node_property_index(&mut self, label: &str, property: &str) -> Result<()> {
        // Intern the label + prop-key tokens and record the durable catalog entry in one dedicated
        // transaction so the schema change (tokens + registration) survives a crash atomically, even
        // if no node yet uses them.
        self.next_txn_id += 1;
        let txn = TxnId(self.next_txn_id);
        self.store.borrow_mut().begin(txn);
        let (label_token, prop_key) = {
            let mut store = self.store.borrow_mut();
            let label_token = match store.intern_token(Namespace::Label, label) {
                Ok(t) => t,
                Err(e) => {
                    drop(store);
                    let _ = self.store.borrow_mut().rollback(txn);
                    return Err(e);
                }
            };
            let prop_key = match store.intern_token(Namespace::PropKey, property) {
                Ok(t) => t,
                Err(e) => {
                    drop(store);
                    let _ = self.store.borrow_mut().rollback(txn);
                    return Err(e);
                }
            };
            // Record the index in the durable catalog at `Online` (population is synchronous here, so a
            // successful create ends `Online`). This becomes durable at the commit below, alongside the
            // tokens; a crash mid-create recovers to the last committed catalog (no entry), and the
            // failed create leaves no orphan registration.
            store.set_node_property_index(label_token, prop_key, IndexState::Online);
            (label_token, prop_key)
        };
        self.store.borrow_mut().commit(txn)?;

        // Register the index `Online` in the in-memory set and (re)build it so existing rows are
        // indexed. The durable catalog and the in-memory set now agree.
        self.index.borrow_mut().register_node_property_with_state(
            label_token,
            prop_key,
            IndexState::Online,
        );
        Self::rebuild_index(&self.store, &self.index);
        Ok(())
    }

    /// Declares a node-property index on `(label, property)` and starts a **non-blocking** background
    /// build of it (`rmp` task #91): the catalog entry is recorded durably as [`IndexState::Populating`]
    /// and a pending build is enqueued, but **no node is scanned here** — the call returns promptly so
    /// the single-threaded engine stays responsive to other commands. The build is advanced in bounded
    /// chunks by [`advance_index_builds`](Self::advance_index_builds) and promoted to
    /// [`IndexState::Online`] only when every snapshot node has been indexed.
    ///
    /// In contrast, [`create_node_property_index`](Self::create_node_property_index) populates the
    /// index **synchronously** before returning (`Online` on success) — keep it for the
    /// startup/recovery path and any caller that can tolerate a blocking full-store scan; use *this*
    /// for a live `CREATE INDEX` over a populated store, where blocking the engine thread for the scan
    /// would stall every concurrent query.
    ///
    /// # Build snapshot and the no-missed-results guarantee
    ///
    /// At build start the current live node-id list is snapshotted ([`RecordStore::scan_node_ids`]).
    /// The build later indexes each snapshot node's *current* state. Concurrent writes between chunks
    /// are covered without any extra bookkeeping because the index is a **candidate set** and writes
    /// already maintain it (`RecordStoreGraph::reindex_node` inserts into *every* registered index in
    /// *any* state):
    ///
    /// - A node **deleted** before the scan reaches it → indexed as a stale candidate → harmless (the
    ///   seek's re-check drops the now-invisible version).
    /// - A node **created** after build start → not in the snapshot, but `reindex_node` inserts its
    ///   current label/value on the creating write → covered.
    /// - A value **changed** mid-build → `reindex_node` inserts the new value as a candidate; the
    ///   snapshot scan may also insert the old value; both are candidates and the re-check keeps only
    ///   the current one → covered.
    ///
    /// So at completion every node that should match is a candidate (zero missed results), and only
    /// harmless stale candidates may exist — exactly the contract the executor's re-check already
    /// assumes.
    ///
    /// While `Populating`, the planner withholds the index (it is absent from
    /// [`catalog`](Self::catalog)), so reads fall back to a label-scan + filter and observe correct
    /// results throughout the build.
    ///
    /// # Errors
    /// Returns a storage error if interning either token, recording the catalog entry, the committing
    /// transaction, or the initial snapshot scan fails. On any error the index is left undeclared.
    pub fn begin_online_node_property_index(&mut self, label: &str, property: &str) -> Result<()> {
        // Intern the tokens and record the durable catalog entry as `Populating`, in one committed
        // transaction — exactly like `create_node_property_index` but for the in-progress state, so an
        // interrupted build recovers `Populating` and is completed by the open-time rebuild.
        self.next_txn_id += 1;
        let txn = TxnId(self.next_txn_id);
        self.store.borrow_mut().begin(txn);
        let (label_token, prop_key) = {
            let mut store = self.store.borrow_mut();
            let label_token = match store.intern_token(Namespace::Label, label) {
                Ok(t) => t,
                Err(e) => {
                    drop(store);
                    let _ = self.store.borrow_mut().rollback(txn);
                    return Err(e);
                }
            };
            let prop_key = match store.intern_token(Namespace::PropKey, property) {
                Ok(t) => t,
                Err(e) => {
                    drop(store);
                    let _ = self.store.borrow_mut().rollback(txn);
                    return Err(e);
                }
            };
            store.set_node_property_index(label_token, prop_key, IndexState::Populating);
            (label_token, prop_key)
        };
        self.store.borrow_mut().commit(txn)?;

        // Register the index `Populating` in the in-memory set so concurrent writes maintain it from
        // now on (the planner still withholds it until it is promoted `Online`).
        self.index.borrow_mut().register_node_property_with_state(
            label_token,
            prop_key,
            IndexState::Populating,
        );

        // Snapshot the current live node-id list and enqueue the pending build. The scan is the only
        // store walk here; the per-node indexing is deferred to `advance_index_builds`.
        let snapshot = self.store.borrow_mut().scan_node_ids()?;
        self.pending_builds.push_back(PendingIndexBuild {
            label_token,
            prop_key,
            snapshot,
            cursor: 0,
        });
        Ok(())
    }

    /// Whether any non-blocking index build is still in progress (`rmp` task #91). The engine loop
    /// uses this to decide between a plain blocking receive (no builds) and a timed receive that also
    /// drives the build between commands.
    #[must_use]
    pub fn has_pending_index_builds(&self) -> bool {
        !self.pending_builds.is_empty()
    }

    /// Advances the front non-blocking index build by up to `budget` nodes (`rmp` task #91), returning
    /// whether **any** build remains pending afterwards.
    ///
    /// For the front build it indexes the next `budget` snapshot nodes (each via the shared
    /// `index_one_node` helper, so the per-node logic matches the full
    /// rebuild). When the front build's cursor reaches the end of its snapshot it is **complete**: the
    /// catalog entry is durably flipped to [`IndexState::Online`] in a committed transaction, the
    /// in-memory state is promoted, and the build is dequeued — after which the planner begins routing
    /// seeks to it. Per-call work is bounded by `budget` so a build never monopolises the engine
    /// thread (the responsiveness guarantee).
    ///
    /// A `budget` of `0` performs no indexing but still returns the pending state (callers should pass
    /// a positive chunk size). If the durable promotion commit fails, the build is left in place
    /// `Populating` (still correct via the scan fallback) to be retried on the next call/open.
    pub fn advance_index_builds(&mut self, budget: usize) -> bool {
        let Some(build) = self.pending_builds.front_mut() else {
            return false;
        };

        // Index up to `budget` nodes from the snapshot, starting at the cursor.
        let registered = [(build.label_token, build.prop_key)];
        let end = build.snapshot.len().min(build.cursor + budget);
        for &id in &build.snapshot[build.cursor..end] {
            Self::index_one_node(&self.store, &self.index, id, &registered);
        }
        build.cursor = end;

        if build.cursor < build.snapshot.len() {
            // More of this build remains; nothing else is processed this call.
            return true;
        }

        // The front build's snapshot is fully indexed: promote it durably to `Online`, then dequeue.
        let (label_token, prop_key) = (build.label_token, build.prop_key);
        self.next_txn_id += 1;
        let txn = TxnId(self.next_txn_id);
        self.store.borrow_mut().begin(txn);
        self.store
            .borrow_mut()
            .set_node_property_index(label_token, prop_key, IndexState::Online);
        if self.store.borrow_mut().commit(txn).is_err() {
            // The durable flip failed; leave the build pending `Populating` and retry next call. The
            // index stays withheld from the planner (correct, just unaccelerated) until then.
            return true;
        }
        self.index
            .borrow_mut()
            .set_node_property_state(label_token, prop_key, IndexState::Online);
        self.pending_builds.pop_front();
        !self.pending_builds.is_empty()
    }

    /// Drops the node-property index on `(label, property)` (`rmp` task #91): removes its durable
    /// catalog entry in a committed transaction and unregisters it from the in-memory [`IndexSet`],
    /// cancelling any in-progress non-blocking build of the same index.
    ///
    /// Idempotent on a never-declared index: the durable removal is a no-op and the in-memory
    /// unregister is a no-op, so dropping an absent index succeeds. The tokens are looked up (not
    /// interned): an unknown label/property means no such index can exist, so the call is a clean
    /// no-op success.
    ///
    /// # Errors
    /// Returns a storage error if the committing transaction fails.
    pub fn drop_node_property_index(&mut self, label: &str, property: &str) -> Result<()> {
        // Resolve the tokens by lookup only; a missing token means the index cannot exist.
        let tokens = {
            let store = self.store.borrow();
            match (
                store.token_id(Namespace::Label, label),
                store.token_id(Namespace::PropKey, property),
            ) {
                (Some(label_token), Some(prop_key)) => Some((label_token, prop_key)),
                _ => None,
            }
        };
        let Some((label_token, prop_key)) = tokens else {
            return Ok(()); // no such tokens → no such index → clean no-op.
        };

        // Remove the durable catalog entry in its own committed transaction (mirrors the create path).
        self.next_txn_id += 1;
        let txn = TxnId(self.next_txn_id);
        self.store.borrow_mut().begin(txn);
        self.store
            .borrow_mut()
            .remove_node_property_index(label_token, prop_key);
        self.store.borrow_mut().commit(txn)?;

        // Cancel any in-progress build for this index and unregister it from the in-memory set.
        self.pending_builds
            .retain(|b| !(b.label_token == label_token && b.prop_key == prop_key));
        self.index
            .borrow_mut()
            .unregister_node_property(label_token, prop_key);
        Ok(())
    }

    /// Lists every declared node-property index as `(label, property, state)` (`rmp` task #91), for a
    /// `SHOW INDEXES` surface. Reads the durable catalog and resolves the tokens back to names; an
    /// index whose tokens have no resolvable name (a defensively-skipped impossibility for a live
    /// token) is omitted. Ordered by the catalog's ascending `(label_token, prop_key)` key.
    #[must_use]
    pub fn list_node_property_indexes(&self) -> Vec<(String, String, IndexState)> {
        let store = self.store.borrow();
        store
            .node_property_indexes()
            .into_iter()
            .filter_map(|(label_token, prop_key, state)| {
                let label = store.token_name(Namespace::Label, label_token)?;
                let property = store.token_name(Namespace::PropKey, prop_key)?;
                Some((label.to_owned(), property.to_owned(), state))
            })
            .collect()
    }

    /// The physical planner's [`IndexCatalog`] reflecting the indexes this coordinator currently
    /// holds (`rmp` task #48, `04 §6.6`): a token-lookup entry for every label that has at least one
    /// indexed node, and a single-property entry for every **`Online`** node-property index. Tokens
    /// with no resolvable name (a defensively-skipped impossibility for a live token) are omitted.
    ///
    /// # State gating (`rmp` task #90)
    ///
    /// Only an [`IndexState::Online`] node-property index is surfaced to the planner: a `Populating`
    /// one is **withheld** so the planner never routes a seek to a half-built index — it falls back to
    /// a label-scan + filter for that `(label, property)` until the index is promoted. The filtering
    /// happens here ([`IndexSet::online_node_properties`]), so the `IndexCatalog` only ever contains
    /// usable indexes and the physical planner needs no state awareness — the lowest-friction path.
    /// The token-lookup (label) entries are unaffected: they come from the always-present label index,
    /// not from any declared node-property index.
    pub fn catalog(&self) -> IndexCatalog {
        let mut builder = IndexCatalog::builder();
        let store = self.store.borrow();

        for token in self.index.borrow_mut().indexed_label_tokens() {
            if let Some(name) = store.token_name(Namespace::Label, token) {
                builder = builder.with_token_lookup(name);
            }
        }
        for (label_token, prop_key) in self.index.borrow().online_node_properties() {
            let (Some(label), Some(property)) = (
                store.token_name(Namespace::Label, label_token),
                store.token_name(Namespace::PropKey, prop_key),
            ) else {
                continue;
            };
            builder = builder.with_label_property(label, property);
        }
        builder.build()
    }

    /// A compile-time [`Statistics`] source over this coordinator's shared store (`rmp` task #82),
    /// for [`plan_physical_with_stats`](crate::physical::plan_physical_with_stats).
    ///
    /// This is how the production compile paths (the server's per-`Run` compile, the TCK runner,
    /// the LDBC bench driver) activate the cost-based optimiser: they hold no statement seam while
    /// compiling, so the per-statement [`RecordStoreGraph::statistics`](crate::graph_access::GraphAccess::statistics)
    /// seam is unavailable — this one answers from the same durable catalogue without needing an
    /// open transaction. See [`CoordinatorStatistics`] for the snapshot and borrow contracts.
    #[must_use]
    pub fn statistics(&self) -> CoordinatorStatistics<D, S> {
        CoordinatorStatistics {
            store: Rc::clone(&self.store),
        }
    }

    /// Borrows a per-statement [`RecordStoreGraph`] seam for the open transaction `txn`: the executor
    /// runs over it, its reads/writes contribute SIREAD markers / rw-edges / write locks to the
    /// shared trackers, and it is dropped when the statement ends (the transaction stays open).
    ///
    /// # Errors
    /// Returns [`GraphusError::Transaction`] if `txn` is not an open transaction.
    pub fn statement(&self, txn: TxnId) -> Result<RecordStoreGraph<D, S>> {
        let snapshot = self.active.get(&txn).map(|a| a.snapshot).ok_or_else(|| {
            GraphusError::Transaction(format!("statement in inactive txn {}", txn.0))
        })?;
        Ok(RecordStoreGraph::attach(
            Rc::clone(&self.store),
            txn,
            snapshot,
            Rc::clone(&self.ssi),
            Rc::clone(&self.locks),
            Rc::clone(&self.index),
        ))
    }

    /// Commits `txn`: runs SSI validation (SERIALIZABLE only, aborting a pivot on a dangerous
    /// structure), then commits it on the store (assign commit timestamp, settle MVCC headers, WAL
    /// group-commit) and publishes the SSI outcome. Returns the commit timestamp.
    ///
    /// # Errors
    /// - [`GraphusError::Transaction`] if `txn` is not open.
    /// - [`GraphusError::Transaction`] (retriable serialization failure) if `txn` is chosen as the
    ///   SSI abort victim — it is rolled back and the caller should retry.
    /// - A storage error if the store commit fails.
    pub fn commit(&mut self, txn: TxnId) -> Result<Timestamp> {
        let isolation = self.active.get(&txn).map(|a| a.isolation).ok_or_else(|| {
            GraphusError::Transaction(format!("commit of inactive txn {}", txn.0))
        })?;

        // 1) SSI validation (SERIALIZABLE only): abort a pivot on a dangerous structure (`04 §5.4`).
        if isolation.runs_ssi() {
            let victim = self.ssi.borrow().detect_pivot_abort(txn);
            if let Some(victim) = victim {
                if victim == txn {
                    self.abort(txn)?;
                    return Err(GraphusError::Transaction(format!(
                        "serialization failure: transaction {} aborted to preserve serializability \
                         (SSI dangerous structure); retry",
                        txn.0
                    )));
                }
                // The pivot is another open transaction: abort it so this safe member commits. Its
                // own later commit/statement will fail as inactive (the poisoned-victim model).
                self.abort(victim)?;
            }
        }

        // 2) Commit on the store: it assigns the commit timestamp, settles MVCC headers and group-
        //    commits the WAL (`rmp` task #45). The store is the timestamp oracle, so the commit
        //    timestamp is its post-commit snapshot high-water.
        self.store.borrow_mut().commit(txn)?;
        let commit_ts = self.store.borrow().snapshot_ts();

        // 3) Publish the outcome: record the commit in the SSI tracker (kept for later conflict
        //    resolution until GC), release write locks, and close the transaction.
        self.ssi.borrow_mut().record_commit(txn, commit_ts);
        self.locks.borrow_mut().release_all(txn);
        self.active.remove(&txn);
        Ok(commit_ts)
    }

    /// Rolls `txn` back: undoes its writes on the store, forgets its SSI markers, and releases its
    /// locks.
    ///
    /// # Errors
    /// Returns [`GraphusError::Transaction`] if `txn` is not open, or a storage error if the undo
    /// fails.
    pub fn rollback(&mut self, txn: TxnId) -> Result<()> {
        if !self.active.contains_key(&txn) {
            return Err(GraphusError::Transaction(format!(
                "rollback of inactive txn {}",
                txn.0
            )));
        }
        self.abort(txn)
    }

    /// The number of currently open transactions (observability / tests).
    #[must_use]
    pub fn active_count(&self) -> usize {
        self.active.len()
    }

    /// Reclaims the underlying store once no transaction is open and no statement seam is live
    /// (tests / shutdown).
    ///
    /// # Panics
    /// Panics if a statement seam still shares the store (a live [`RecordStoreGraph`] from
    /// [`statement`](Self::statement) has not been dropped).
    #[must_use]
    pub fn into_store(self) -> RecordStore<D, S> {
        match Rc::try_unwrap(self.store) {
            Ok(cell) => cell.into_inner(),
            Err(_) => panic!("into_store requires that no statement seam still shares the store"),
        }
    }

    /// Aborts `txn`: store undo, SSI forget, lock release, and removal from the open set.
    fn abort(&mut self, txn: TxnId) -> Result<()> {
        self.store.borrow_mut().rollback(txn)?;
        self.ssi.borrow_mut().forget(txn);
        self.locks.borrow_mut().release_all(txn);
        self.active.remove(&txn);
        Ok(())
    }
}

/// The coordinator-level [`Statistics`] seam (`rmp` task #82): exact catalogue counts and
/// per-indexed-property histograms over the coordinator's shared store, consumed by
/// [`plan_physical_with_stats`](crate::physical::plan_physical_with_stats) at compile time.
///
/// # What is reported (snapshot semantics)
///
/// Each call reads the store's **current committed catalogue**: the durable grand-total and
/// per-label / per-relationship-type counts (`rmp` task #79) and the durable equi-depth property
/// histograms (`rmp` task #81). The planner treats the values as a consistent-enough snapshot for
/// one compilation; the counts are advisory cost inputs, so a materially-stale histogram (or a count
/// racing a concurrent commit) only **mis-costs** a plan — it never affects correctness, because
/// every cost-based rewrite is bag-preserving (`rmp` task #65). This deliberately mirrors the
/// catalogue-count semantics of [`RecordStoreGraph`]'s own [`Statistics`] impl: cost estimation
/// wants the aggregate shape of the data, not one transaction's MVCC view.
///
/// # Borrow discipline (why this is safe on the single engine thread)
///
/// The seam holds an `Rc` clone of the coordinator's shared store and borrows it **briefly, per
/// method call** — never across calls, and any decoded histogram is owned before the borrow is
/// released. The other holders of this `Rc` ([`TxnCoordinator`] itself and every
/// [`RecordStoreGraph`] statement seam) likewise borrow only for the duration of one call, so a
/// `CoordinatorStatistics` may be held across an entire compilation — including while a transaction
/// is open and while a statement seam exists — without ever overlapping a live borrow: the planner
/// is pure and never re-enters the store while one of these calls is borrowing it.
///
/// # Error policy
///
/// This seam has **no error-capture channel** (compilation must not fail over an advisory
/// statistic), so a corrupt stored histogram degrades to the `None` "fall back" sentinel — the
/// estimator then uses its documented constants — instead of being surfaced. The per-statement
/// [`RecordStoreGraph`] seam, which *does* have a channel, captures the same error; both read
/// through the shared (crate-private) `store_statistics` helpers so the lookup semantics cannot
/// drift.
pub struct CoordinatorStatistics<D: BlockDevice, S: LogSink> {
    /// A clone of the coordinator's shared store handle (see the borrow-discipline doc above).
    store: Rc<RefCell<RecordStore<D, S>>>,
}

impl<D: BlockDevice, S: LogSink> CoordinatorStatistics<D, S> {
    /// Decodes the durable histogram for `(label, property)` via the shared reader, applying this
    /// seam's error policy: a corrupt histogram is reported as `None` (the estimator's constant
    /// fallback) because compile-time statistics are advisory and have no error channel — never a
    /// panic, never a failed compilation.
    fn decode_histogram(&self, label: &str, property: &str) -> Option<PropertyHistogram> {
        store_statistics::decode_histogram(&self.store.borrow(), label, property)
            .ok()
            .flatten()
    }
}

impl<D: BlockDevice, S: LogSink> Statistics for CoordinatorStatistics<D, S> {
    fn total_nodes(&self) -> u64 {
        self.store.borrow().total_node_count()
    }

    fn nodes_with_label(&self, label: &str) -> Option<u64> {
        // Exact per-label catalogue counts (`rmp` task #79): a never-interned label is an exact
        // `Some(0)`, never the `None` "unknown" sentinel.
        Some(store_statistics::nodes_with_label(
            &self.store.borrow(),
            label,
        ))
    }

    fn total_relationships(&self) -> u64 {
        self.store.borrow().total_relationship_count()
    }

    fn relationships_with_type(&self, rel_type: &str) -> Option<u64> {
        // Exact per-relationship-type catalogue counts; a never-interned type is an exact 0.
        Some(store_statistics::relationships_with_type(
            &self.store.borrow(),
            rel_type,
        ))
    }

    fn estimate_nodes_label_property_eq(
        &self,
        label: &str,
        property: &str,
        value: &Value,
    ) -> Option<f64> {
        // No histogram (or a corrupt one, per this seam's error policy) -> None (fall back); an
        // unindexable query value (Null/List/Map) likewise -> None (`store_statistics` docs).
        let hist = self.decode_histogram(label, property)?;
        store_statistics::histogram_estimate_eq(&hist, value)
    }

    fn estimate_nodes_label_property_range(
        &self,
        label: &str,
        property: &str,
        lo: Option<&Value>,
        lo_inclusive: bool,
        hi: Option<&Value>,
        hi_inclusive: bool,
    ) -> Option<f64> {
        // A *present* but unindexable bound -> None (fall back) rather than silently dropping the
        // bound; an absent bound is open on that side (`store_statistics::histogram_estimate_range`).
        let hist = self.decode_histogram(label, property)?;
        store_statistics::histogram_estimate_range(&hist, lo, lo_inclusive, hi, hi_inclusive)
    }

    fn distinct_label_property_values(&self, label: &str, property: &str) -> Option<u64> {
        Some(self.decode_histogram(label, property)?.distinct())
    }
}
