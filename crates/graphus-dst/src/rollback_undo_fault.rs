//! Focused deterministic reproducer for **a transaction that disappears from the store's active set
//! without its effects having been undone** (`rmp` #955) — the ordering twin of the count-delta undo
//! ([`crate::count_txn_undo`], `rmp` #866), the catalog-DDL undo ([`crate::catalog_rollback_undo`],
//! `rmp` #734) and the free-list double-allocation ([`crate::freelist_reuse`], `rmp` #578). Like all
//! four, it is reachable only through a fault the generic [`crate::harness`] never performs.
//!
//! ## The defect
//!
//! `RecordStore::rollback` used to take the transaction's active-set entry out of the map on its very
//! first line, and only *then* perform the WAL undo, the compensation replay into the buffer pool and
//! the catalog reload — three fallible steps, one of which additionally PANICS on an `fdatasync`
//! failure (`04 §4.9`, the fsyncgate policy). A failure or unwind anywhere in that window left the
//! store in the one state it must never be in: the transaction's writes physically present, and the
//! transaction itself invisible.
//!
//! Invisible matters because the active set is not bookkeeping — it is a **safety input**:
//!
//! * `RecordStore::uncommitted_data_writer` (`rmp` #902) reads it to answer "is the committed image
//!   decidable right now?", and `CREATE CONSTRAINT` refuses while the answer is no. On this fault path
//!   the answer flipped from *no* to *yes* while uncommitted rows were still on the page — the guard
//!   turning fail-open at exactly the moment it exists for.
//! * `RecordStore::is_txn_active` reads it to decide whether a writer might still commit, so a
//!   transaction that vanished has its half-written versions treated as resolved.
//! * `RecordStore::committed_statistics` reads it to strip open transactions' pending count deltas
//!   before a checkpoint persists the catalog, so a vanished transaction's uncommitted counts are
//!   durably published as committed.
//!
//! `commit_prepare` carried the same shape in miniature. Since `rmp` #866 it keeps the active-set
//! entry across its fallible steps — but it still took `labelled_nodes` out of that entry, and settled
//! the label history to `Committed(commit_ts)`, *before* `checkpoint_meta` and `commit_at_no_sync`.
//! A failure between the two therefore left a transaction that (a) no longer looked like a label
//! writer to the #902 guard, and (b) had its uncommitted label versions already stamped committed —
//! which the subsequent rollback's `LabelHistory::forget`, keyed on the *in-flight* stamp, could not
//! find. It published, and then could not retract, a label change that never committed. The commit
//! registry entry was published early for the same reason and with the same consequence for every
//! record header, not only for labels.
//!
//! ## What is asserted, and why "still active" is the right answer rather than "cleaned up"
//!
//! A rollback is one indivisible repair — WAL undo, compensation replay, catalog reload — and the
//! store cannot restart it from an arbitrary mid-point: once `WalManager::rollback` has consumed its
//! own active-transaction entry, a second call finds no undo chain and returns `Ok` over pages it
//! never repaired. So this module deliberately **never retries a failed rollback**, and the fix does
//! not try to make it retryable. It makes the failure *honest*: the transaction stays active, every
//! gate keeps answering "uncommitted state is present", and the server layer turns that into a
//! per-database degraded engine (`rmp` #409/#414) so the operator gets a controlled restart instead of
//! a database quietly serving over rows it cannot account for.
//!
//! ## Scope of what a single-threaded DST can and cannot reach
//!
//! Everything here is deterministic and single-threaded, which is the mandate. The store-level
//! scenarios drive a bare `RecordStore` so the fault can be injected between two exactly-known steps;
//! the engine-level consequence — that `CREATE CONSTRAINT` is refused across the fault, and that the
//! engine is flagged degraded — is asserted in `crate::isolation`, which drives the same code through
//! a real `LocalEngine`. Nothing here needs threads, so nothing here is deferred to one.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use graphus_core::TxnId;
use graphus_core::error::{GraphusError, Result};
use graphus_io::MemBlockDevice;
use graphus_storage::{Namespace, RecordStore};
use graphus_txn::Snapshot;
use graphus_wal::{LogSink, MemLogSink, WalManager};

/// Buffer-pool frames for the scenarios below. Large enough that no scenario's working set forces an
/// eviction, so the only device/WAL traffic is the one each scenario deliberately triggers — the
/// determinism the fault windows depend on.
const POOL_CAPACITY: usize = 64;

/// Property-key tokens the committing transaction interns so its catalog no longer fits one metadata
/// page, forcing `checkpoint_meta` to GROW the metadata chain — a `new_page` + `flush_unlogged`, i.e.
/// the first *device write* of the commit. That is what makes
/// [`MemBlockDevice::arm_io_error`] land inside `checkpoint_meta` rather than somewhere later.
/// (Same lever, same reason, as [`crate::count_txn_undo`].)
const CHAIN_GROWTH_TOKENS: usize = 1024;

const SEED_LABEL: &str = "Person";
const NEW_LABEL: &str = "Archived";

/// A [`LogSink`] whose `fdatasync` can be armed to FAIL, which `WalManager::harden` turns into the
/// controlled fsyncgate PANIC (`04 §4.9`). That is how a WAL write failure actually manifests in this
/// engine — `LogSink::append` is infallible by design, so the sync is the only WAL failure point — and
/// it is therefore the faithful way to inject "the WAL undo failed" during a rollback.
///
/// The flag is shared through an `Arc<AtomicBool>` so a scenario can arm it *after* its transaction
/// has written, while the sink itself lives inside the store. Mirrors the `FaultSink` the `rmp` #415
/// coordinator regression uses.
struct FaultSink {
    inner: MemLogSink,
    fail_sync: Arc<AtomicBool>,
}

impl LogSink for FaultSink {
    fn append(&mut self, bytes: &[u8]) {
        self.inner.append(bytes);
    }
    fn sync(&mut self) -> Result<()> {
        if self.fail_sync.load(Ordering::SeqCst) {
            return Err(GraphusError::Storage(
                "injected WAL fdatasync failure during undo (rmp #955)".to_owned(),
            ));
        }
        self.inner.sync()
    }
    fn begin_harden(&mut self) -> Result<graphus_wal::FsyncJob> {
        self.inner.begin_harden()
    }
    fn complete_harden(&mut self, target_len: u64) {
        self.inner.complete_harden(target_len);
    }
    fn durable_len(&self) -> u64 {
        self.inner.durable_len()
    }
    fn buffered_len(&self) -> u64 {
        self.inner.buffered_len()
    }
    fn read_durable(&self, from: u64, into: &mut Vec<u8>) -> Result<()> {
        self.inner.read_durable(from, into)
    }
    fn read_bounded(&self, from: u64, to: u64, into: &mut Vec<u8>) -> Result<()> {
        self.inner.read_bounded(from, to, into)
    }
    fn reclaim(&mut self, from: u64, up_to: u64) -> Result<()> {
        self.inner.reclaim(from, up_to)
    }
    fn reclaimed_floor(&self) -> u64 {
        self.inner.reclaimed_floor()
    }
}

type FaultStore = RecordStore<MemBlockDevice, FaultSink>;
type PlainStore = RecordStore<MemBlockDevice, MemLogSink>;

/// What the store says about a transaction, gathered through the exact predicates the safety gates
/// consult. Every field is a *public* store predicate, so the oracle shares no private state with the
/// code under test.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WriterVisibility {
    /// `RecordStore::is_txn_active` — "this writer might still commit".
    pub is_active: bool,
    /// `RecordStore::uncommitted_data_writer() == Some(txn)` — the `rmp` #902 constraint-DDL guard's
    /// input, and the field that answers "would `CREATE CONSTRAINT` be refused right now?".
    pub is_uncommitted_data_writer: bool,
    /// The raw id the guard reports (the LOWEST open data writer). Kept alongside the boolean above
    /// because the pre-fix failure is not "the guard reported nothing" but "the guard reported a
    /// DIFFERENT, unrelated transaction" — a distinction `Option<bool>` cannot express and a test that
    /// only checked for `None` would miss entirely.
    pub reported_uncommitted_writer: Option<TxnId>,
    /// Whether the label history still carries a version stamped `InFlight(txn)` — i.e. the label
    /// change has NOT been settled as committed.
    pub holds_inflight_label_versions: bool,
    /// Whether a fresh snapshot resolves the node's labels to the value this transaction wrote. This
    /// is the reader-visible face of the defect: `true` means uncommitted work is being served.
    pub label_change_is_visible: bool,
}

/// The outcome of [`run_wal_sync_failure_during_rollback`].
#[derive(Debug, Clone, Copy)]
pub struct RollbackFaultReport {
    /// Whether the armed WAL `fdatasync` actually made the rollback unwind. `false` means the fault
    /// never fired and every assertion below would hold vacuously.
    pub fault_surfaced: bool,
    /// The store's view of the writer BEFORE the rollback was attempted (the non-vacuity baseline).
    pub before: WriterVisibility,
    /// The store's view of the writer AFTER the rollback failed. This is the assertion that matters.
    pub after: WriterVisibility,
    /// The store's view of an unrelated, still-open bystander after the fault, proving the fault did
    /// not simply freeze the whole active set.
    pub bystander_after: WriterVisibility,
}

/// The outcome of [`run_io_error_at_commit_of_a_label_writer`].
#[derive(Debug, Clone, Copy)]
pub struct CommitFaultReport {
    /// Whether the injected I/O error actually failed the commit.
    pub fault_surfaced: bool,
    /// No `COMMIT` record was appended, i.e. the failure landed inside `checkpoint_meta` — the exact
    /// window between the old `labelled_nodes` capture and the fallible steps.
    pub failed_before_commit_record: bool,
    /// The store's view of the writer BEFORE the commit was attempted.
    pub before: WriterVisibility,
    /// The store's view of the writer AFTER its commit failed. The whole point: a failed commit must
    /// leave a fully-formed open writer, not a half-published one.
    pub after: WriterVisibility,
    /// The store's view after the subsequent rollback, which must succeed and must leave nothing of
    /// the transaction behind.
    pub after_rollback: WriterVisibility,
    /// The node's labels as a fresh snapshot resolves them after the rollback — the committed value.
    pub labels_after_rollback: u64,
    /// The committed label bitmap the seed established, for comparison with the field above.
    pub committed_labels: u64,
}

/// Builds a fresh store over a WAL sink whose `fdatasync` can be armed to fail.
fn create_fault_store(fail_sync: &Arc<AtomicBool>) -> FaultStore {
    let device = MemBlockDevice::new(0);
    let sink = FaultSink {
        inner: MemLogSink::new(),
        fail_sync: Arc::clone(fail_sync),
    };
    let wal = WalManager::create(sink).expect("create wal");
    RecordStore::create(device, wal, POOL_CAPACITY, 1).expect("create store")
}

/// Builds a fresh store over an ordinary in-memory WAL (the device is the fault seam here).
fn create_plain_store() -> PlainStore {
    let device = MemBlockDevice::new(0);
    let wal = WalManager::create(MemLogSink::new()).expect("create wal");
    RecordStore::create(device, wal, POOL_CAPACITY, 1).expect("create store")
}

/// Reads the four gate predicates for `txn` over node `node`, whose in-flight label bitmap (the value
/// the faulting transaction wrote) is `written_labels`.
fn observe<D: graphus_io::BlockDevice, S: LogSink>(
    store: &RecordStore<D, S>,
    txn: TxnId,
    node: u64,
    written_labels: u64,
) -> WriterVisibility {
    let reported = store.uncommitted_data_writer();
    WriterVisibility {
        is_active: store.is_txn_active(txn),
        is_uncommitted_data_writer: reported == Some(txn),
        reported_uncommitted_writer: reported,
        holds_inflight_label_versions: store.label_history().has_inflight_versions_of(txn),
        label_change_is_visible: resolve_labels(store, node) == written_labels,
    }
}

/// Node `node`'s LIVE label bitmap — the word physically on the page, with no MVCC arbitration. This
/// is what an uncommitted in-place label write mutates.
fn live_bitmap<D: graphus_io::BlockDevice, S: LogSink>(
    store: &RecordStore<D, S>,
    node: u64,
) -> u64 {
    store
        .node_labels(node)
        .expect("read node labels")
        .iter()
        .fold(0u64, |acc, t| acc | (1u64 << u64::from(*t)))
}

/// Resolves node `node`'s label bitmap exactly as a reader beginning NOW would: the live word,
/// arbitrated through the retained label history against a fresh snapshot and the commit registry.
/// This calls the production predicate ([`RecordStore::label_bitmap_at`]), not a re-implementation of
/// it, so the oracle cannot drift from the read path it is judging.
fn resolve_labels<D: graphus_io::BlockDevice, S: LogSink>(
    store: &RecordStore<D, S>,
    node: u64,
) -> u64 {
    let live = live_bitmap(store, node);
    let snapshot = Snapshot {
        owner: TxnId(u64::MAX),
        ts: store.snapshot_ts(),
    };
    store.label_bitmap_at(node, live, snapshot, store.commit_registry())
}

/// Seeds a committed `(:Person)` node and returns `(node id, its committed label bitmap, the bitmap a
/// later `Archived` label change produces)`.
fn seed<D: graphus_io::BlockDevice, S: LogSink>(store: &mut RecordStore<D, S>) -> (u64, u64, u64) {
    let t0 = TxnId(1);
    store.begin(t0);
    let person = store
        .intern_token(Namespace::Label, SEED_LABEL)
        .expect("intern seed label");
    let archived = store
        .intern_token(Namespace::Label, NEW_LABEL)
        .expect("intern new label");
    let (node, _) = store.create_node(t0).expect("seed node");
    store.add_label(t0, node, person).expect("label seed node");
    store.commit(t0).expect("seed commits");
    store.flush().expect("flush seed");

    let committed = live_bitmap(store, node);
    // The bitmap the pending change produces, computed the same way `add_label` does.
    let written = committed | (1u64 << u64::from(archived));
    assert_ne!(
        committed, written,
        "the pending change must actually alter the bitmap, else `label_change_is_visible` cannot \
         distinguish the committed value from the uncommitted one"
    );
    (node, committed, written)
}

/// Adds the `Archived` label to `node` under `txn`, the *label-only* mutation this module is built
/// around: it writes the label word in place and creates no record, so the transaction shows up in
/// `uncommitted_data_writer` through `labelled_nodes` ALONE. That is what makes the two defects
/// separable — a scenario that also created a node would keep the guard closed through `created` and
/// hide the `labelled_nodes` half entirely.
fn relabel<D: graphus_io::BlockDevice, S: LogSink>(
    store: &mut RecordStore<D, S>,
    txn: TxnId,
    node: u64,
) {
    let archived = store
        .token_id(Namespace::Label, NEW_LABEL)
        .expect("the new label token was interned by the seed");
    store.add_label(txn, node, archived).expect("relabel");
}

/// **Scenario 1 — the WAL undo fails during `rollback`.**
///
/// A label-only writer `W` is open over a committed node; an unrelated bystander `B` is open too. The
/// WAL `fdatasync` is armed to fail, so `WalManager::rollback` writes its compensation log records and
/// then PANICS in `harden` — the fsyncgate policy — unwinding out of `RecordStore::rollback` with the
/// compensating images never replayed into the buffer pool and the catalog never reloaded. `W`'s
/// change is, at that instant, still physically on the page.
///
/// The assertion is that `W` is still, in every respect the store can be asked about, an open writer
/// holding uncommitted state — because it is one.
///
/// # Panics
/// Panics if the store fixture cannot be built, or if the deliberately-armed fault fails to fire in a
/// way that leaves the store unusable for the observations that follow.
#[must_use]
pub fn run_wal_sync_failure_during_rollback() -> RollbackFaultReport {
    let fail_sync = Arc::new(AtomicBool::new(false));
    let mut store = create_fault_store(&fail_sync);
    let (node, _committed, written) = seed(&mut store);

    // The writer takes the LOWER id, so `uncommitted_data_writer` — which reports the lowest open
    // data writer, deterministically — names it while it is open.
    let writer = TxnId(2);
    store.begin(writer);
    relabel(&mut store, writer, node);

    // A bystander that stays open across the whole fault. It is a data writer too, and its id is
    // HIGHER, so it is exactly what the guard falls back to naming the moment the writer vanishes.
    // That makes the post-fault assertion a claim about WHICH transaction is reported, not merely
    // about something being reported — the pre-fix code answered `Some(bystander)` here, which a test
    // written against `is_some()` would have accepted.
    let bystander = TxnId(3);
    store.begin(bystander);
    let (_bystander_node, _) = store.create_node(bystander).expect("bystander node");
    let before = observe(&store, writer, node, written);

    // ARM: the next WAL `fdatasync` fails. The rollback below writes its CLRs, appends the ABORT
    // record, and panics hardening them.
    fail_sync.store(true, Ordering::SeqCst);
    let unwound = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _ = store.rollback(writer);
    }));
    fail_sync.store(false, Ordering::SeqCst);
    let fault_surfaced = unwound.is_err();

    let after = observe(&store, writer, node, written);
    let bystander_after = observe(&store, bystander, node, written);

    RollbackFaultReport {
        fault_surfaced,
        before,
        after,
        bystander_after,
    }
}

/// **Scenario 2 — the commit of a label-only writer fails inside `checkpoint_meta`.**
///
/// `W` relabels a committed node and interns enough property-key tokens that its catalog no longer
/// fits one metadata page. A one-shot device I/O error is armed, so the metadata-chain growth inside
/// `checkpoint_meta` — the commit's first device write — fails and takes the commit with it, landing
/// the fault in the exact window `commit_prepare` used to have between taking `labelled_nodes` (plus
/// settling the label history and publishing the commit-registry entry) and its fallible steps.
///
/// The assertions are that the failed commit leaves a fully-formed open writer whose label change is
/// still invisible and still un-settled, that the guard still names it, and that the subsequent
/// rollback then removes every trace of it.
///
/// # Panics
/// Panics if the store fixture cannot be built or the seed transaction cannot commit.
#[must_use]
pub fn run_io_error_at_commit_of_a_label_writer() -> CommitFaultReport {
    let mut store = create_plain_store();
    let (node, committed_labels, written) = seed(&mut store);

    let writer = TxnId(2);
    store.begin(writer);
    relabel(&mut store, writer, node);
    // Force the catalog past one metadata page so `checkpoint_meta` must grow the chain (and therefore
    // must write to the device) before it can persist anything.
    for i in 0..CHAIN_GROWTH_TOKENS {
        store
            .intern_token(Namespace::PropKey, &format!("prop_key_number_{i:08}"))
            .expect("intern chain-growth token");
    }
    let before = observe(&store, writer, node, written);

    // ARM: the next home write fails. The first device write from here is inside `checkpoint_meta`.
    store.with_device_mut(MemBlockDevice::arm_io_error);
    let commit = store.commit(writer);
    let fault_surfaced = commit
        .as_ref()
        .err()
        .is_some_and(|e| e.to_string().contains("injected I/O error"));
    // No `COMMIT` record ⇒ the failure landed before `commit_at_no_sync`, i.e. inside `checkpoint_meta`.
    let failed_before_commit_record = store.with_wal(|w| w.is_active(writer));
    let after = observe(&store, writer, node, written);

    store
        .rollback(writer)
        .expect("a failed commit must leave the transaction rollback-able");
    let after_rollback = observe(&store, writer, node, written);
    let labels_after_rollback = resolve_labels(&store, node);

    CommitFaultReport {
        fault_surfaced,
        failed_before_commit_record,
        before,
        after,
        after_rollback,
        labels_after_rollback,
        committed_labels,
    }
}

/// **Scenario 3 — a bystander's counts and DDL survive a neighbour's failed rollback.**
///
/// Holding the faulting transaction's active-set entry across the fallible steps changes what
/// `pre_statistics` and `committed_statistics` see, so this pins the property that motivated the
/// original ordering: an unrelated open transaction's pending state must be unaffected by a
/// neighbour's rollback, whether that rollback succeeds or fails. Returns
/// `(counts_match_committed_image_after_fault, bystander_still_active)`.
///
/// # Panics
/// Panics if the store fixture cannot be built or the seed transaction cannot commit.
#[must_use]
pub fn run_bystander_survives_failed_rollback() -> (bool, bool) {
    let fail_sync = Arc::new(AtomicBool::new(false));
    let mut store = create_fault_store(&fail_sync);
    let (node, _committed, _written) = seed(&mut store);

    // The bystander moves a counter (a fresh node) and interns a token, so it holds BOTH a pending
    // count delta and a pending catalog change.
    let bystander = TxnId(2);
    store.begin(bystander);
    let (_n, _) = store.create_node(bystander).expect("bystander node");
    store
        .intern_token(Namespace::PropKey, "bystander_key")
        .expect("bystander token");

    let writer = TxnId(3);
    store.begin(writer);
    relabel(&mut store, writer, node);

    fail_sync.store(true, Ordering::SeqCst);
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _ = store.rollback(writer);
    }));
    fail_sync.store(false, Ordering::SeqCst);

    // The bystander's own pending count delta must still be attributed to it (so a checkpoint would
    // still strip it), and it must still be an open transaction.
    (
        !store.counts_match_committed_image(),
        store.is_txn_active(bystander),
    )
}

/// Whether `store`'s commit registry reports `txn` as committed — the predicate an in-flight version
/// stamp is resolved through. A transaction whose commit FAILED must never report as committed.
fn registry_says_committed<D: graphus_io::BlockDevice, S: LogSink>(
    store: &RecordStore<D, S>,
    txn: TxnId,
) -> bool {
    matches!(
        store.commit_registry().outcome(txn),
        graphus_txn::TxnOutcome::Committed(_)
    )
}

/// **Scenario 4 — a failed commit must not publish a commit-registry entry.**
///
/// The registry is what resolves an `InFlight(txn)` stamp, and every record a transaction wrote still
/// carries one until GC freezes it. Publishing the entry before `checkpoint_meta` therefore made a
/// failed commit's whole uncommitted write set resolve as `Committed(commit_ts)`. Returns
/// `(fault_surfaced, registry_says_committed_after_the_failed_commit)`.
///
/// # Panics
/// Panics if the store fixture cannot be built or the seed transaction cannot commit.
#[must_use]
pub fn run_failed_commit_publishes_no_registry_entry() -> (bool, bool) {
    let mut store = create_plain_store();
    let (node, _committed, _written) = seed(&mut store);

    // Non-vacuity control: the SEED transaction committed, so the predicate below really does report
    // `true` for a transaction that committed. Without this, "the writer is not reported as committed"
    // could hold simply because the predicate never reports anything.
    assert!(
        registry_says_committed(&store, TxnId(1)),
        "the seed transaction committed, so the registry predicate must report it as committed — \
         otherwise the assertion below is vacuous"
    );

    let writer = TxnId(2);
    store.begin(writer);
    relabel(&mut store, writer, node);
    let (_created, _) = store.create_node(writer).expect("writer node");
    for i in 0..CHAIN_GROWTH_TOKENS {
        store
            .intern_token(Namespace::PropKey, &format!("prop_key_number_{i:08}"))
            .expect("intern chain-growth token");
    }

    store.with_device_mut(MemBlockDevice::arm_io_error);
    let commit = store.commit(writer);
    let fault_surfaced = commit
        .as_ref()
        .err()
        .is_some_and(|e| e.to_string().contains("injected I/O error"));
    let says_committed = registry_says_committed(&store, writer);
    (fault_surfaced, says_committed)
}

// =================================================================================================
// Coordinator-level scenarios: the `rmp` #902 guard and the `rmp` #903 registration, directly
// =================================================================================================
//
// The two scenarios below drive a real `TxnCoordinator` so the assertion is the *guard function
// itself* — `refuse_constraint_ddl_while_writers_open`, reached through `create_constraint` — rather
// than the predicate it reads. They write through `with_store_mut` instead of Cypher: the fault
// windows are storage-level, the coordinator's transaction bookkeeping is identical either way, and a
// compiled statement would add a parser/planner dependency to a test about undo ordering.

/// The state of BOTH transaction registries after a fault, plus what the constraint DDL actually does.
#[derive(Debug, Clone)]
pub struct GuardReport {
    /// Whether the injected fault actually fired.
    pub fault_surfaced: bool,
    /// `CREATE CONSTRAINT` was refused, and the refusal is the `rmp` #902 "holds uncommitted writes"
    /// one (not some other error that would make the assertion accidental).
    pub ddl_refused_for_uncommitted_writes: bool,
    /// The refusal message verbatim.
    pub refusal: String,
    /// The faulting writer's id, so a test can prove the refusal names THAT transaction and not some
    /// other open one — the guard reports the lowest open data writer, so "a refusal happened" and
    /// "this writer caused it" are different claims.
    pub writer: TxnId,
    /// The COORDINATOR's active-transaction count after the fault (the `rmp` #903 registration).
    pub coordinator_active_count: usize,
    /// The SSI tracker's retained-conflict-record count BEFORE the writer opened. The tracker retains
    /// a COMMITTED transaction's record until `prune_committed` runs, so the seed's entry is still
    /// there and only the DELTA against this baseline says anything about the writer.
    pub ssi_tracked_len_before: usize,
    /// The SSI tracker's retained-conflict-record count after the fault.
    pub ssi_tracked_len: usize,
    /// Whether the DDL is accepted once the transaction is genuinely resolved — the control that
    /// proves the refusal above was caused by this writer and is not permanent.
    pub ddl_accepted_after_resolution: bool,
}

/// Interns the tokens and creates the committed `(:Person)` node through a coordinator-managed
/// transaction, returning `(node id, the Archived label token)`.
fn seed_via_coordinator<S: LogSink>(
    coord: &mut graphus_cypher::TxnCoordinator<MemBlockDevice, S>,
) -> (u64, u32) {
    let t = coord.begin_serializable();
    let (node, archived) = coord.with_store_mut(|s| {
        let person = s
            .intern_token(Namespace::Label, SEED_LABEL)
            .expect("intern seed label");
        let archived = s
            .intern_token(Namespace::Label, NEW_LABEL)
            .expect("intern new label");
        let (node, _) = s.create_node(t).expect("seed node");
        s.add_label(t, node, person).expect("label seed node");
        (node, archived)
    });
    coord.commit(t).expect("seed commits");
    (node, archived)
}

/// Attempts the constraint DDL and classifies the answer.
fn try_constraint<S: LogSink>(
    coord: &mut graphus_cypher::TxnCoordinator<MemBlockDevice, S>,
    name: &str,
) -> std::result::Result<(), String> {
    coord
        .create_constraint(
            name,
            SEED_LABEL,
            "email",
            graphus_cypher::ConstraintKind::Unique,
        )
        .map(|_| ())
        .map_err(|e| e.to_string())
}

/// **Scenario 5 — the `rmp` #902 guard across a FAILED ROLLBACK, through the guard itself.**
///
/// The writer's rollback unwinds on the injected WAL `fdatasync` failure, so its label change is still
/// on the page. `CREATE CONSTRAINT` must still be REFUSED, because the committed image is still not
/// decidable.
///
/// Note what this scenario also pins about the *coordinator* registries: `rmp` #415 releases the SSI
/// markers, the locks and the coordinator's own active-set entry in a drop guard that fires even on a
/// panicking undo — deliberately, because a dangling rw-edge would false-abort innocent successors.
/// The STORE's active-set entry is the opposite obligation and is deliberately retained. The two are
/// not in conflict and neither is accidental, so both are reported here rather than only the one that
/// makes the fix look tidy.
///
/// # Panics
/// Panics if the fixture cannot be built or the seed transaction cannot commit.
#[must_use]
pub fn run_guard_across_failed_rollback() -> GuardReport {
    let fail_sync = Arc::new(AtomicBool::new(false));
    let store = create_fault_store(&fail_sync);
    let mut coord = graphus_cypher::TxnCoordinator::new(store);
    let (node, archived) = seed_via_coordinator(&mut coord);
    let ssi_tracked_len_before = coord.ssi_tracked_len();

    let writer = coord.begin_serializable();
    coord.with_store_mut(|s| s.add_label(writer, node, archived).expect("relabel"));
    assert!(
        coord.ssi_tracked_len() > ssi_tracked_len_before,
        "precondition: the writer must be SSI-registered, else \"its footprint was forgotten\" is a \
         statement about a footprint that never existed"
    );

    fail_sync.store(true, Ordering::SeqCst);
    let unwound = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _ = coord.rollback(writer);
    }));
    fail_sync.store(false, Ordering::SeqCst);

    let refusal = try_constraint(&mut coord, "u_email")
        .err()
        .unwrap_or_default();
    GuardReport {
        fault_surfaced: unwound.is_err(),
        ddl_refused_for_uncommitted_writes: refusal.contains("holds uncommitted writes"),
        refusal,
        writer,
        coordinator_active_count: coord.active_count(),
        ssi_tracked_len_before,
        ssi_tracked_len: coord.ssi_tracked_len(),
        // The transaction can never be resolved once its undo has failed (see the module docs), so the
        // control below is run on a SECOND, fault-free coordinator instead of by "finishing" this one.
        ddl_accepted_after_resolution: guard_reopens_after_a_clean_rollback(),
    }
}

/// The control for [`run_guard_across_failed_rollback`]: the identical workload with NO fault must
/// leave the DDL accepted, so the refusal above is attributable to the fault and not to the fixture.
fn guard_reopens_after_a_clean_rollback() -> bool {
    let fail_sync = Arc::new(AtomicBool::new(false));
    let store = create_fault_store(&fail_sync);
    let mut coord = graphus_cypher::TxnCoordinator::new(store);
    let (node, archived) = seed_via_coordinator(&mut coord);

    let writer = coord.begin_serializable();
    coord.with_store_mut(|s| s.add_label(writer, node, archived).expect("relabel"));
    assert!(
        try_constraint(&mut coord, "u_email").is_err(),
        "control precondition: an OPEN writer must already refuse the DDL (that is rmp #902, and \
         without it the fault scenario would prove nothing)"
    );
    coord.rollback(writer).expect("clean rollback succeeds");
    try_constraint(&mut coord, "u_email").is_ok()
}

/// **Scenario 6 — the `rmp` #902 guard AND the `rmp` #903 registration across a FAILED COMMIT.**
///
/// This is the window where both registries must still hold the transaction:
/// `TxnCoordinator::commit` propagates the store's failure before it reaches
/// `self.active.remove(&txn)` and `ssi.record_commit`, so the coordinator still has it; and the store
/// keeps its own entry (`rmp` #866) with `labelled_nodes` intact (`rmp` #955), so the guard still
/// names it. Both are asserted, and the DDL is then accepted once the transaction is rolled back.
///
/// # Panics
/// Panics if the fixture cannot be built or the seed transaction cannot commit.
#[must_use]
pub fn run_guard_across_failed_commit() -> GuardReport {
    let store = create_plain_store();
    let mut coord = graphus_cypher::TxnCoordinator::new(store);
    let (node, archived) = seed_via_coordinator(&mut coord);
    let ssi_before = coord.ssi_tracked_len();

    let writer = coord.begin_serializable();
    coord.with_store_mut(|s| {
        s.add_label(writer, node, archived).expect("relabel");
        for i in 0..CHAIN_GROWTH_TOKENS {
            s.intern_token(Namespace::PropKey, &format!("prop_key_number_{i:08}"))
                .expect("intern chain-growth token");
        }
        s.with_device_mut(MemBlockDevice::arm_io_error);
    });
    let commit = coord.commit(writer);
    let fault_surfaced = commit
        .as_ref()
        .err()
        .is_some_and(|e| e.to_string().contains("injected I/O error"));

    let refusal = try_constraint(&mut coord, "u_email")
        .err()
        .unwrap_or_default();
    let ddl_refused_for_uncommitted_writes = refusal.contains("holds uncommitted writes");
    let coordinator_active_count = coord.active_count();
    let ssi_tracked_len = coord.ssi_tracked_len();
    assert!(
        ssi_tracked_len > ssi_before,
        "the writer must be SSI-registered for the tracked-length comparison to mean anything"
    );

    coord
        .rollback(writer)
        .expect("a failed commit must leave the transaction rollback-able");
    let ddl_accepted_after_resolution = try_constraint(&mut coord, "u_email").is_ok();

    GuardReport {
        fault_surfaced,
        ddl_refused_for_uncommitted_writes,
        refusal,
        writer,
        coordinator_active_count,
        ssi_tracked_len_before: ssi_before,
        ssi_tracked_len,
        ddl_accepted_after_resolution,
    }
}

#[cfg(test)]
mod tests {
    use graphus_core::Timestamp;

    use super::*;

    /// Acceptance criterion 1: a WAL undo failure during rollback must leave the transaction VISIBLE
    /// as active — never silently gone with its effects intact.
    ///
    /// Fails against the pre-#955 code, where `rollback` removed the entry on its first line and the
    /// fsyncgate panic unwound straight past the restore.
    #[test]
    fn a_wal_undo_failure_leaves_the_writer_visibly_active_955() {
        let r = run_wal_sync_failure_during_rollback();

        assert!(
            r.fault_surfaced,
            "non-vacuity: the armed WAL fdatasync must actually make the rollback unwind, otherwise \
             every assertion below is a statement about an ordinary successful rollback"
        );
        // Non-vacuity of the baseline: the guard predicates must have been TRUE before the fault, so
        // "still true after" is a preservation claim rather than a tautology over an empty set.
        assert!(
            r.before.is_active && r.before.is_uncommitted_data_writer,
            "precondition: the label-only writer must be an active uncommitted data writer before the \
             rollback is attempted (got {:?})",
            r.before
        );
        assert!(
            !r.before.label_change_is_visible,
            "precondition: the uncommitted label change must be invisible to a fresh snapshot (got \
             {:?})",
            r.before
        );

        assert!(
            r.after.is_active,
            "a rollback whose WAL undo failed must leave the transaction ACTIVE — its writes were not \
             undone, so `is_txn_active` must keep reporting it (rmp #955)"
        );
        assert!(
            r.after.is_uncommitted_data_writer,
            "the rmp #902 constraint-DDL guard must stay FAIL-CLOSED across the fault: \
             `uncommitted_data_writer` must still name the writer whose effects are still on the page \
             (rmp #955)"
        );
        assert!(
            r.after.holds_inflight_label_versions,
            "the failed undo must not have settled or dropped the writer's retained label versions"
        );
        assert!(
            !r.after.label_change_is_visible,
            "the un-undone label change must remain INVISIBLE: it never committed, so no snapshot may \
             resolve to it"
        );
        assert!(
            r.bystander_after.is_active,
            "the unrelated bystander must still be open — the fault must not have frozen the whole \
             active set, which is what would make the assertion above hold for the wrong reason"
        );
        assert!(
            !r.bystander_after.is_uncommitted_data_writer,
            "the guard must still name the FAULTING writer, not the higher-id bystander it falls back \
             to the instant the writer vanishes — this is the assertion the pre-fix code fails, and it \
             fails it by reporting `Some(bystander)` rather than `None` (got {:?})",
            r.bystander_after.reported_uncommitted_writer
        );
    }

    /// Acceptance criterion 2: a failure between `commit_prepare`'s `labelled_nodes` capture and its
    /// later fallible steps must leave the same fully-formed open writer.
    ///
    /// Fails against the pre-#955 code on two separate assertions: the guard no longer named the
    /// writer (its `labelled_nodes` had been taken), and its label versions had already been settled
    /// to `Committed(commit_ts)` — which the rollback's `forget`, keyed on the in-flight stamp, could
    /// then not find, leaving the rolled-back change permanently visible.
    #[test]
    fn a_failed_commit_leaves_a_label_writer_fully_open_955() {
        let r = run_io_error_at_commit_of_a_label_writer();

        assert!(
            r.fault_surfaced,
            "non-vacuity: the armed I/O error must actually fail the commit"
        );
        assert!(
            r.failed_before_commit_record,
            "non-vacuity: the failure must land INSIDE `checkpoint_meta` (no COMMIT record appended), \
             which is the window between the old `labelled_nodes` capture and the fallible steps"
        );
        assert!(
            r.before.is_active && r.before.is_uncommitted_data_writer,
            "precondition: the label-only writer must be an active uncommitted data writer before it \
             attempts to commit (got {:?})",
            r.before
        );

        assert!(
            r.after.is_active,
            "a failed commit must leave the transaction active (rmp #866, re-asserted here)"
        );
        assert!(
            r.after.is_uncommitted_data_writer,
            "the rmp #902 guard must stay FAIL-CLOSED across a failed commit: taking `labelled_nodes` \
             before the fallible steps made a label-only writer vanish from it (rmp #955)"
        );
        assert!(
            r.after.holds_inflight_label_versions,
            "a failed commit must NOT have settled the label history: settling it stamps the versions \
             `Committed(commit_ts)`, which the rollback's `LabelHistory::forget` — keyed on the \
             in-flight stamp — can no longer find (rmp #955)"
        );
        assert!(
            !r.after.label_change_is_visible,
            "the label change of a FAILED commit must not be visible to any snapshot"
        );

        assert!(
            !r.after_rollback.is_active,
            "the subsequent rollback must resolve the transaction"
        );
        assert!(
            !r.after_rollback.is_uncommitted_data_writer,
            "the guard must re-open once the transaction is genuinely resolved"
        );
        assert!(
            !r.after_rollback.holds_inflight_label_versions,
            "the rollback must drop the writer's retained label versions"
        );
        assert_eq!(
            r.labels_after_rollback, r.committed_labels,
            "after the rollback the node must resolve to its COMMITTED label set — a settled-then-\
             rolled-back label change that stays visible is the silent, restart-healed defect"
        );
    }

    /// The ordering fix must not change what a *bystander* observes: its pending count delta and its
    /// open status survive a neighbour's failed rollback untouched.
    #[test]
    fn a_bystanders_pending_state_survives_a_neighbours_failed_rollback_955() {
        let (counts_differ_from_committed, bystander_active) =
            run_bystander_survives_failed_rollback();
        assert!(
            bystander_active,
            "the bystander must still be open after an unrelated transaction's rollback failed"
        );
        assert!(
            counts_differ_from_committed,
            "the bystander's pending count delta must still be attributed to it, so a checkpoint \
             would still strip it from the durable image (rmp #866)"
        );
    }

    /// A commit that failed must not have published a commit-registry entry, because that entry is
    /// what resolves the in-flight stamps its uncommitted records still carry.
    ///
    /// Fails against the pre-#955 code, which recorded the commit before `checkpoint_meta`.
    #[test]
    fn a_failed_commit_publishes_no_commit_registry_entry_955() {
        let (fault_surfaced, says_committed) = run_failed_commit_publishes_no_registry_entry();
        assert!(
            fault_surfaced,
            "non-vacuity: the armed I/O error must actually fail the commit"
        );
        assert!(
            !says_committed,
            "a commit that FAILED must not report as committed: every record it wrote still bears its \
             in-flight stamp, and the registry is what resolves that stamp — so a premature entry makes \
             the whole uncommitted write set readable as committed data (rmp #955)"
        );
    }

    /// The ordinary, fault-free rollback must be unchanged by the reordering: it still resolves the
    /// transaction, still reverts the label word, and still leaves the guard open.
    #[test]
    fn a_successful_rollback_is_unchanged_by_the_reordering_955() {
        let mut store = create_plain_store();
        let (node, committed, written) = seed(&mut store);

        let writer = TxnId(2);
        store.begin(writer);
        relabel(&mut store, writer, node);
        let before = observe(&store, writer, node, written);
        assert!(
            before.is_active && before.is_uncommitted_data_writer,
            "precondition: the writer holds uncommitted state"
        );

        store.rollback(writer).expect("rollback succeeds");

        let after = observe(&store, writer, node, written);
        assert!(!after.is_active, "a successful rollback resolves the txn");
        assert!(
            !after.is_uncommitted_data_writer,
            "a successful rollback re-opens the rmp #902 guard"
        );
        assert!(
            !after.holds_inflight_label_versions,
            "a successful rollback forgets the writer's label versions"
        );
        assert_eq!(
            live_bitmap(&store, node),
            committed,
            "the WAL undo restored the committed label word"
        );
        assert_eq!(
            store.uncommitted_data_writer(),
            None,
            "no writer remains once the only open transaction has rolled back"
        );
    }

    /// Acceptance criterion 4, through the guard function itself: after a rollback whose WAL undo
    /// failed, `CREATE CONSTRAINT` must still be REFUSED, naming the transaction whose writes are
    /// still on the page.
    ///
    /// Fails against the pre-#955 code, where the DDL was ACCEPTED — the guard fail-open the whole
    /// task exists to close.
    #[test]
    fn the_902_guard_stays_closed_across_a_failed_rollback_955() {
        let r = run_guard_across_failed_rollback();

        assert!(
            r.fault_surfaced,
            "non-vacuity: the armed WAL fdatasync must actually make the rollback unwind"
        );
        assert!(
            r.ddl_accepted_after_resolution,
            "control: with no fault, the identical workload must leave the DDL ACCEPTED once the \
             writer rolls back — without this, a refusal below could come from the fixture rather \
             than from the fault"
        );
        assert!(
            r.ddl_refused_for_uncommitted_writes,
            "CREATE CONSTRAINT must still be refused while a transaction's un-undone writes sit on \
             the page (rmp #902 fail-closed, preserved across the fault by rmp #955); got {:?}",
            r.refusal
        );
        assert!(
            r.refusal.contains(&format!("transaction {}", r.writer.0)),
            "the refusal must name the FAULTING writer — the guard reports the lowest open data \
             writer, so a refusal naming someone else would mean the fix is not what closed it; got \
             {:?} for writer {:?}",
            r.refusal,
            r.writer
        );
        // The two registries answer DIFFERENTLY here, and both answers are deliberate. Pinning them
        // together stops a future change from "harmonising" them and silently reverting one fix or the
        // other.
        assert_eq!(
            r.coordinator_active_count, 0,
            "rmp #415: the COORDINATOR-level footprint (active entry, SSI markers, locks) is released \
             by a drop guard even when the durable undo panics — a dangling rw-edge would false-abort \
             innocent successors. That is why the store-level entry, not this one, is what keeps the \
             rmp #902 guard closed"
        );
        assert_eq!(
            r.ssi_tracked_len, r.ssi_tracked_len_before,
            "rmp #415, same reason: the SSI footprint is forgotten on a failed abort, so the tracker \
             returns to its pre-writer size (the seed's retained committed record stays — the tracker \
             keeps those until `prune_committed`, which is why this compares against a baseline rather \
             than against zero)"
        );
    }

    /// Acceptance criterion 4 across the OTHER fault: after a commit that failed at the store level,
    /// BOTH the `rmp` #902 guard and the `rmp` #903 coordinator/SSI registration must still see the
    /// transaction — and the DDL must be accepted again once it is genuinely rolled back.
    ///
    /// Fails against the pre-#955 code on the guard assertion: the commit had already taken
    /// `labelled_nodes`, so a label-only writer was invisible to `uncommitted_data_writer`.
    #[test]
    fn both_registries_still_see_a_failed_commit_955() {
        let r = run_guard_across_failed_commit();

        assert!(
            r.fault_surfaced,
            "non-vacuity: the armed I/O error must actually fail the commit"
        );
        assert!(
            r.ddl_refused_for_uncommitted_writes,
            "the rmp #902 guard must still refuse: the writer's label change is uncommitted and still \
             on the page; got {:?}",
            r.refusal
        );
        assert!(
            r.refusal.contains(&format!("transaction {}", r.writer.0)),
            "the refusal must name the writer whose commit failed; got {:?} for writer {:?}",
            r.refusal,
            r.writer
        );
        assert_eq!(
            r.coordinator_active_count, 1,
            "the rmp #903 registration must survive a failed commit: `TxnCoordinator::commit` \
             propagates the store failure BEFORE it removes the active-set entry, so the transaction \
             is still a live member and still SSI-tracked"
        );
        assert!(
            r.ddl_accepted_after_resolution,
            "once the transaction is genuinely rolled back the guard must re-open — otherwise the \
             refusal above would be a permanent poison rather than a fail-closed gate (the rmp \
             #467/#803 latch shape)"
        );
    }

    /// The `Timestamp` import is load-bearing only through `resolve_labels`; this pins that a fresh
    /// snapshot really is taken at the store's current high-water, so "invisible" above means
    /// "invisible to the newest possible reader" rather than to an accidentally-stale one.
    #[test]
    fn the_oracle_snapshot_is_the_newest_possible_one_955() {
        let mut store = create_plain_store();
        let (_node, _committed, _written) = seed(&mut store);
        assert!(
            store.snapshot_ts() > Timestamp(0),
            "the seed commit must have advanced the commit-timestamp oracle, else the oracle snapshot \
             would see nothing and every visibility assertion would pass vacuously"
        );
    }
}
