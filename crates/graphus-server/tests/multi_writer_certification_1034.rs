//! **`rmp` #1034 — the multi-writer engine, certified against the project's own oracles, on real
//! OS threads.**
//!
//! ## The gap this owns
//!
//! Seven files already drive the engine at `engine_workers > 1`: `engine_multi_worker_shutdown_1036`
//! (drain convergence), `engine_reclaim_barrier_1037` (the slot-reuse barrier across workers),
//! `engine_latch_scaling_1038` / `engine_latch_order_1038` (latch discipline and concurrent
//! execution), `engine_shared_reader_pool_1039` (one reader pool and one retirement channel per
//! engine), `wal_group_sync_multiworker_1040` (one fsync leader, every ack durable),
//! `engine_shared_sessions_1041` (engine-scoped session state) and `multi_stream_transaction_907`
//! (session ordering). Each pins one *mechanism* of the multi-worker engine.
//!
//! None of them answers the question the certification exists for: **does a run with several real
//! writer threads lose a committed write, or admit an isolation anomaly?** Every isolation and
//! durability oracle in the project consumes a history produced by ONE writer thread or by
//! cooperative interleaving — `graphus-dst`'s `isolation.rs` drives the inline single-threaded
//! `LocalEngine`, and the deterministic writer scheduler orders one OS thread's worth of work by
//! construction. That single-writer premise is exactly what `D-multi-writer` retires, and the
//! project's own history says why it matters: the `rmp` #811 corpse-zeroing defect and the #1014
//! class before it were both invisible to the deterministic oracle and appeared only under real
//! threads.
//!
//! So: real `std::thread`s, no cooperative scheduling, no injected interleaving. What the host's
//! scheduler does is what the engine is certified against.
//!
//! # The three gates
//!
//! 1. [`no_acknowledged_commit_is_lost_or_invented_across_a_restart`] — the cardinal ACID gate. Many
//!    concurrent writers, every acknowledged commit recorded by the test, and the set of ids present
//!    in the database required to equal the acknowledged set **exactly** — before a restart and
//!    again after one. Set equality is deliberate: `acked ⊄ present` is a lost commit, and
//!    `present ⊄ acked` is a transaction that was refused and left a trace anyway.
//! 2. [`the_concurrent_history_has_no_isolation_anomaly`] — a history recorded from the concurrent
//!    run, checked by [`graphus_elle::check`].
//! 3. [`the_store_is_physically_consistent_after_a_concurrent_write_storm`] — a churn workload
//!    (relationships created and deleted, nodes created and deleted, properties overwritten) then a
//!    reopen and [`graphus_storage::check::check_store`], which walks the free lists, the incidence
//!    chains and the property chains.
//!
//! # Which oracle, and why
//!
//! [`graphus_elle::check`] (list-append / Adya), **not**
//! [`graphus_txn::serializability::HistoryChecker`]. The two differ in what the test must supply.
//! `HistoryChecker` consumes `Op::Read { key, version }` and `Op::Write { key, version }` — it needs
//! a **per-key version number** for every operation, i.e. it needs the test to already know each
//! key's true write order. With real OS threads the test does not know that and cannot: the order in
//! which `commit_blocking` returns on N client threads is the host scheduler's answer, not the
//! engine's serialization order, and inventing version numbers from the client side would smuggle
//! back the single-writer premise this file exists to retire — the checker would then certify the
//! test's assumption rather than the engine's behaviour.
//!
//! Elle's list-append model has no such requirement, which is its whole point: appended values are
//! unique and a read returns the list **in order**, so the true version order of each key is
//! *recovered from the observed data*. The test supplies only what it genuinely observed. The
//! mapping onto Cypher is direct and needs no encoding tricks — a key is a `(:Reg {k})` node holding
//! a list property, an append is `SET n.vals = n.vals + $v`, and a read is `RETURN n.vals`.
//!
//! That mapping is also what makes the workload *contend*, which is the second half of choosing it.
//! An append is a genuine read-modify-write of one record, so two writers on one key collide on the
//! entity's MVCC header and, under `D-write-conflict-detection`, the second aborts immediately with
//! a retriable serialization failure — no waiting, no lock. And because every transaction reads two
//! keys and writes one of them, the run continuously produces write-skew shapes (read `a`, read `b`,
//! write `b`, against a concurrent read `b`, read `a`, write `a`) that no write-write check can
//! catch and only the SSI rw-antidependency machinery can.
//!
//! **No client-side retry.** An aborted transaction is recorded as aborted and the client moves on.
//! A retry loop would be the realistic client, but it dissolves the very signal these gates are
//! measured by (measured elsewhere in this project: a retrying client took an engine abort rate of
//! 0.907 down to 0.049), and Elle needs the aborts as aborts — an abort that leaves a trace is a
//! dirty write, and the checker can only look for one if it is told the transaction aborted.
//!
//! # Non-vacuity: the controls are permanent, not a one-off experiment
//!
//! Three ways these gates could certify nothing, each answered by a control that runs on every
//! invocation rather than by an experiment somebody once did:
//!
//! - **The workload might not contend.** If writers touched disjoint keys no conflict would ever
//!   form, no abort would happen, and the oracle would bless a history that never had a chance to be
//!   wrong. Every gate therefore counts its own aborts and **asserts they are non-zero**, prints the
//!   measured abort rate, and — for the isolation gate — additionally requires that some key
//!   received committed appends from more than one client thread.
//! - **The oracle might have no teeth.** After certifying the real history,
//!   [`the_concurrent_history_has_no_isolation_anomaly`] injects a **real write-skew cycle** into a
//!   clone of that same history — two committed transactions that wrote different keys are each
//!   given a read of the other's key observing nothing — and requires the checker to REJECT it, with
//!   a cycle. The clone is discarded; the recorded history is untouched.
//! - **The lost-write comparison might not compare.** [`reconcile`] is the single function both the
//!   real assertion and its control go through. The gate asserts it reports nothing for
//!   (acknowledged, present), then asserts it reports something when one acknowledged id is dropped
//!   from the expected set, and again when a phantom id is added — so both of its branches are
//!   proven live on every run.
//!
//! # The restart is a real restart
//!
//! [`reopen_engine`] follows `wal_group_sync_multiworker_1040`: the engine is shut down gracefully
//! and joined, then a **new** engine is built over the same directory through
//! `FileBlockDevice::open` → `WalManager::open` → `recover_device` → `RecordStore::open`. Nothing is
//! carried over in memory; the data comes back from the durable WAL and the device image, through
//! the same recovery the server runs at startup. A teardown that merely dropped handles would prove
//! nothing about durability — the lesson recorded from `rmp` #907.
//!
//! # Why these engines are built directly
//!
//! `admission.engine_workers` above one is still refused by configuration until this certification
//! closes, so these gates call `spawn_engine_with_timeout` — the same door the other multi-worker
//! files use. The refusal bounds who can reach the multi-worker engine, not whether it is tested.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use graphus_core::Value;
use graphus_core::capability::Clock;
use graphus_core::error::GraphusError;
use graphus_cypher::MaterializedValue;
use graphus_elle::{History, Key, Op, Transaction, Val, check};
use graphus_io::FileBlockDevice;
use graphus_server::engine::command::AccessMode;
use graphus_server::engine::{Engine, EngineHandle, TxTicket, spawn_engine_with_timeout};
use graphus_storage::RecordStore;
use graphus_storage::check::{ConsistencyReport, check_store};
use graphus_storage::recovery::recover_device;
use graphus_wal::{FileLogSink, WalManager};

// ---------------------------------------------------------------------------------------------
// Fixture
// ---------------------------------------------------------------------------------------------

/// A monotonic real clock — the engine reads `now_nanos` only for latency and age bookkeeping.
struct RealClock;
impl Clock for RealClock {
    fn now_nanos(&self) -> u64 {
        use std::time::{SystemTime, UNIX_EPOCH};
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u64
    }
}

/// A unique scratch directory, removed on drop.
///
/// `CARGO_TARGET_TMPDIR`, not `std::env::temp_dir()`: the latter honours `$TMPDIR`, which CI images
/// and containers routinely point at tmpfs, and every gate here is about what survives a restart of
/// a store on a **real filesystem**. The Cargo-provided directory lives under the build's `target/`,
/// on the same real filesystem as the repository.
struct TempDir {
    path: PathBuf,
}
impl TempDir {
    fn new(tag: &str) -> Self {
        let path = Path::new(env!("CARGO_TARGET_TMPDIR")).join(format!(
            "graphus_mw1034_{tag}_{}_{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_nanos()
        ));
        std::fs::create_dir_all(&path).expect("create scratch dir");
        Self { path }
    }
}
impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

/// How many engine workers to certify on this host.
///
/// **Four is the floor and it is not negotiable**: it is the shape every other multi-worker gate
/// (`rmp` #1036–#1041) is written against, so a host that cannot run four workers has not run this
/// certification. Above the floor it follows the host, because more writer threads than the machine
/// can actually run in parallel stops adding interleavings and only adds scheduler noise — and it is
/// capped at eight so a 64-core build machine does not spend the whole gate context-switching. Every
/// assertion below is a property of the engine and holds at any `W`; only the reported numbers move.
fn engine_workers() -> usize {
    std::thread::available_parallelism()
        .map(std::num::NonZeroUsize::get)
        .unwrap_or(4)
        .clamp(4, 8)
}

/// Spawns a multi-worker engine over a **fresh** file-backed store.
fn create_engine(dir: &Path, workers: usize) -> Engine {
    let device_path = dir.join("graph.db");
    let wal_dir = dir.join("wal");
    let clock: Arc<dyn Clock + Send + Sync> = Arc::new(RealClock);
    spawn_engine_with_timeout::<FileBlockDevice, FileLogSink, _>(
        Arc::from("mw1034"),
        move || {
            let device = FileBlockDevice::open(&device_path)?;
            let sink = FileLogSink::open(&wal_dir)?;
            let wal = WalManager::create(sink)?;
            let store = RecordStore::create(device, wal, 65_536, 1)?;
            Ok(graphus_cypher::TxnCoordinator::new(store))
        },
        8192,
        256,
        4,
        workers,
        Arc::new(graphus_server::metrics::Metrics::new()),
        clock,
        None,
        None,
        None,
        Arc::new(graphus_server::txn_registry::TransactionRegistry::new()),
    )
    .expect("spawn multi-worker engine")
}

/// Reopens the store from disk — recover from the durable WAL, then open — and spawns a new engine
/// over it. This is the restart: nothing is carried over from the process's previous engine.
fn reopen_engine(dir: &Path, workers: usize) -> Engine {
    let device_path = dir.join("graph.db");
    let wal_dir = dir.join("wal");
    let clock: Arc<dyn Clock + Send + Sync> = Arc::new(RealClock);
    spawn_engine_with_timeout::<FileBlockDevice, FileLogSink, _>(
        Arc::from("mw1034"),
        move || {
            let mut device = FileBlockDevice::open(&device_path)?;
            let sink = FileLogSink::open(&wal_dir)?;
            let mut wal = WalManager::open(sink)?;
            recover_device(&mut wal, &mut device)?;
            let store = RecordStore::open(device, wal, 65_536)?;
            Ok(graphus_cypher::TxnCoordinator::new(store))
        },
        8192,
        256,
        4,
        workers,
        Arc::new(graphus_server::metrics::Metrics::new()),
        clock,
        None,
        None,
        None,
        Arc::new(graphus_server::txn_registry::TransactionRegistry::new()),
    )
    .expect("reopen multi-worker engine")
}

/// Gracefully stops the engine (final harden and drain) and joins every worker, so a subsequent
/// reopen sees a store nobody holds and a WAL nothing is still writing to.
fn graceful_shutdown(engine: Engine) {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("build shutdown runtime");
    rt.block_on(engine.handle.shutdown())
        .expect("graceful shutdown");
    for j in engine.joins {
        j.join().expect("engine worker joins cleanly");
    }
}

/// Reopens the store **outside** any engine and runs the full physical consistency pass over it.
/// Requires that no engine holds the store: call it after [`graceful_shutdown`].
fn reopen_and_check(dir: &Path) -> ConsistencyReport {
    let device_path = dir.join("graph.db");
    let wal_dir = dir.join("wal");
    let mut device = FileBlockDevice::open(&device_path).expect("reopen device");
    let sink = FileLogSink::open(&wal_dir).expect("reopen wal");
    let mut wal = WalManager::open(sink).expect("open wal manager");
    recover_device(&mut wal, &mut device).expect("recover device");
    let sink = FileLogSink::open(&wal_dir).expect("reopen wal for the store");
    let wal = WalManager::open(sink).expect("reopen wal manager");
    let store = RecordStore::open(device, wal, 65_536).expect("reopen store");
    check_store(&store, &[]).expect("consistency check runs")
}

/// Runs one statement inside the already-open transaction `ticket` and drains it fully, returning
/// its rows or the terminal error.
fn run_in(
    handle: &EngineHandle,
    ticket: TxTicket,
    query: &str,
    params: Vec<(String, Value)>,
) -> Result<Vec<Vec<MaterializedValue>>, GraphusError> {
    let mut reply = handle.run_blocking(ticket, query.to_owned(), params, false, None, None)?;
    let mut rows = Vec::new();
    loop {
        match reply.rows.next() {
            Ok(Some(row)) => rows.push(row),
            Ok(None) => return Ok(rows),
            Err(e) => return Err(e),
        }
    }
}

/// One auto-commit statement, drained, returning its rows. Used for seeding and for the final
/// read-back, both of which run with no concurrency.
fn run_auto(
    handle: &EngineHandle,
    mode: AccessMode,
    query: &str,
    params: Vec<(String, Value)>,
) -> Vec<Vec<MaterializedValue>> {
    let ticket = handle
        .begin_auto_commit_blocking(mode)
        .expect("begin auto-commit");
    let mut reply = handle
        .run_blocking(ticket, query.to_owned(), params, true, None, None)
        .unwrap_or_else(|e| panic!("auto-commit statement {query:?} must run: {e}"));
    let mut rows = Vec::new();
    loop {
        match reply.rows.next() {
            Ok(Some(row)) => rows.push(row),
            Ok(None) => return rows,
            Err(e) => panic!("auto-commit statement {query:?} must drain cleanly: {e}"),
        }
    }
}

/// The single `Integer` in a one-row, one-column result.
fn single_int(rows: &[Vec<MaterializedValue>], what: &str) -> i64 {
    match rows.first().and_then(|r| r.first()) {
        Some(MaterializedValue::Value(Value::Integer(n))) => *n,
        other => panic!("{what} must be a single Integer, got {other:?} from {rows:?}"),
    }
}

/// Every `Integer` in a one-column result, as a set (the ids are unique by construction, so a
/// duplicate would collapse here — which the caller checks by comparing lengths).
fn int_column(rows: &[Vec<MaterializedValue>], what: &str) -> Vec<i64> {
    rows.iter()
        .map(|r| match r.first() {
            Some(MaterializedValue::Value(Value::Integer(n))) => *n,
            other => panic!("{what} must be an Integer column, got {other:?}"),
        })
        .collect()
}

/// A list property, as the `i64`s it holds. A pure-property list is always a
/// `MaterializedValue::Value(Value::List)` — the canonical representation documented on
/// [`MaterializedValue::List`], which is reserved for lists containing entities.
fn int_list(rows: &[Vec<MaterializedValue>], what: &str) -> Vec<i64> {
    match rows.first().and_then(|r| r.first()) {
        Some(MaterializedValue::Value(Value::List(items))) => items
            .iter()
            .map(|v| match v {
                Value::Integer(n) => *n,
                other => panic!("{what} must hold Integers, got {other:?}"),
            })
            .collect(),
        other => panic!("{what} must be a list property, got {other:?}"),
    }
}

/// A deterministic xorshift64, so the *shape* of the workload (which key each transaction touches)
/// is reproducible from the seed even though the thread interleaving never is.
struct Rng(u64);
impl Rng {
    fn new(seed: u64) -> Self {
        Self(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1)
    }
    fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next_u64() % n
    }
}

/// Whether a failure is the **retriable serialization failure** a contended run is supposed to
/// produce, as opposed to an error the workload never asked for.
///
/// Classified by the error VARIANT, not by its text, and that is the project's own contract rather
/// than this file's convention: `rmp` #988 moved every *permanent* misuse off
/// [`GraphusError::Transaction`] precisely so that the variant alone decides retryability — it is
/// what the Bolt seam renders as `Neo.TransientError.Transaction.Outdated` and what the official
/// drivers replay. Three engine paths reach it here and all three are legitimate outcomes of
/// contention:
///
/// - the `D-write-conflict-detection` header check, which aborts a writer that finds another open
///   transaction's delta at the head of the entity's chain;
/// - the SSI pivot abort at commit time; and
/// - the **condemned-victim** form of the same thing — a committing transaction dooms *another* open
///   transaction as the pivot (`rmp` #1051), and that transaction then aborts itself, on its own
///   worker, at its own commit, with the same retriable serialization failure. It is never undone by
///   the committer's thread: doing that put two workers inside one transaction's rollback, which is
///   the defect this gate found.
///
/// Anything else is counted separately, kept verbatim, and fails the gate. A gate that folded an
/// unexpected error into "contention" would be measuring its own bugs.
fn is_serialization_failure(e: &GraphusError) -> bool {
    matches!(e, GraphusError::Transaction(_))
}

/// Collapses the variable parts of an error message — ids, timestamps — so failures of the same
/// kind aggregate into one histogram row instead of one row each.
fn message_shape(e: &GraphusError) -> String {
    let mut out = String::with_capacity(64);
    let mut in_number = false;
    for ch in e.to_string().chars() {
        if ch.is_ascii_digit() {
            if !in_number {
                out.push('#');
                in_number = true;
            }
        } else {
            in_number = false;
            out.push(ch);
        }
    }
    out
}

/// What a concurrent phase measured about its own contention, shared across the client threads.
///
/// Reported by every gate, and asserted on, because a run with no aborts is a run in which nothing
/// ever collided. It keeps a **histogram of every distinct failure shape**, on both sides of the
/// classification: a gate that only counted failures would report "320 transactions failed" and
/// leave the reader to guess, and printing only the unexpected ones would hide the case where the
/// "contention" a gate congratulates itself on is really one engine fault repeating.
#[derive(Default)]
struct Tally {
    committed: AtomicU64,
    /// Failure shapes that ARE retriable serialization failures, with their counts.
    conflicts: std::sync::Mutex<BTreeMap<String, u64>>,
    /// Failure shapes that are not, with their counts. Must be empty for a gate to proceed.
    unexpected: std::sync::Mutex<BTreeMap<String, u64>>,
}

impl Tally {
    fn commit(&self) {
        self.committed.fetch_add(1, Ordering::Relaxed);
    }

    /// Classifies and records one failed transaction.
    fn refuse(&self, e: &GraphusError) {
        let bucket = if is_serialization_failure(e) {
            &self.conflicts
        } else {
            &self.unexpected
        };
        *bucket
            .lock()
            .expect("tally is not poisoned")
            .entry(message_shape(e))
            .or_default() += 1;
    }

    fn committed(&self) -> u64 {
        self.committed.load(Ordering::Relaxed)
    }
    fn total(bucket: &std::sync::Mutex<BTreeMap<String, u64>>) -> u64 {
        bucket.lock().expect("tally is not poisoned").values().sum()
    }
    fn conflicts(&self) -> u64 {
        Self::total(&self.conflicts)
    }
    fn unexpected(&self) -> u64 {
        Self::total(&self.unexpected)
    }
    fn attempted(&self) -> u64 {
        self.committed() + self.conflicts() + self.unexpected()
    }
    fn abort_rate(&self) -> f64 {
        let n = self.attempted();
        if n == 0 {
            0.0
        } else {
            (self.conflicts() + self.unexpected()) as f64 / n as f64
        }
    }
    fn histogram(bucket: &std::sync::Mutex<BTreeMap<String, u64>>) -> String {
        bucket
            .lock()
            .expect("tally is not poisoned")
            .iter()
            .map(|(shape, n)| format!("\n    {n:>5} x {shape}"))
            .collect()
    }

    /// Fails the calling gate unless the phase genuinely contended, and only contended.
    ///
    /// A zero abort count does not mean "the engine handled it": with several writer threads all
    /// doing a read-modify-write of a handful of shared records, it means the writers never
    /// overlapped, so nothing the gate goes on to assert was ever put at risk. The workload is what
    /// has to change in that case, never this assertion.
    fn assert_contended(&self, gate: &str) {
        assert!(
            self.attempted() > 0,
            "{gate}: no transaction was even attempted"
        );
        assert_eq!(
            self.unexpected(),
            0,
            "{gate}: {} of {} transactions failed with something OTHER than a retriable \
             serialization failure. A contended multi-writer run is expected to abort; it is not \
             expected to fault. Shapes:{}",
            self.unexpected(),
            self.attempted(),
            Self::histogram(&self.unexpected)
        );
        assert!(
            self.conflicts() > 0,
            "{gate}: {} concurrent transactions over a deliberately tiny set of shared records \
             produced ZERO write-write conflicts and ZERO serialization aborts. The writers never \
             overlapped, so every property this gate goes on to certify was certified over a \
             history that had no chance to be wrong. Fix the workload — more writers, fewer keys, \
             longer transactions — never this assertion.",
            self.attempted()
        );
        assert!(
            self.committed() > 0,
            "{gate}: every transaction aborted; there is no committed history to check"
        );
    }
}

// ---------------------------------------------------------------------------------------------
// GATE 1 — no acknowledged commit is lost, and no refused one leaves a trace
// ---------------------------------------------------------------------------------------------

/// Compares what the server acknowledged against what the database holds, returning the first
/// discrepancy or `None` when the two agree exactly.
///
/// This is the ONE function the gate and its own controls both go through, which is what makes the
/// controls worth anything: a comparison that had quietly stopped comparing would take the controls
/// down with the assertion.
fn reconcile(acked: &BTreeSet<i64>, present: &BTreeSet<i64>) -> Option<String> {
    if let Some(lost) = acked.difference(present).next() {
        return Some(format!(
            "id {lost} was ACKNOWLEDGED as committed and is ABSENT from the database — a lost \
             committed write ({} acknowledged, {} present)",
            acked.len(),
            present.len()
        ));
    }
    if let Some(invented) = present.difference(acked).next() {
        return Some(format!(
            "id {invented} is PRESENT in the database but was never acknowledged — a refused \
             transaction left a trace ({} acknowledged, {} present)",
            acked.len(),
            present.len()
        ));
    }
    None
}

/// **GATE 1 — every acknowledged commit is there, before and after a restart; nothing else is.**
///
/// `CLIENTS` threads each run `PER_CLIENT` explicit read-write transactions against a
/// multi-worker engine. Every transaction does two things:
///
/// - increments one of `SHARDS` shared counters (`SET c.n = c.n + 1`) — a read-modify-write of a
///   record several other threads are also reading and modifying, which is what makes the run
///   contend; and
/// - creates a `(:Rec {id})` node with an id unique across the whole run.
///
/// A commit that returns `Ok` is recorded as acknowledged; anything else is recorded as refused and
/// rolled back. The oracle is then exact set equality between the acknowledged ids and the ids
/// present, checked twice: on the live engine, and again after a full restart through the durable
/// WAL. Both directions matter and [`reconcile`] reports each with its own message.
///
/// A third, independent oracle rides along: the counters. Every acknowledged commit incremented
/// exactly one counter, so the sum across shards must equal the number of acknowledged commits. A
/// lost update — two writers reading the same counter value and both committing — would leave the
/// ids intact and the sum short, so this catches a class the id comparison structurally cannot.
///
/// The gate assumes that a `commit_blocking` error means the transaction did not commit. That is not
/// a convenience: if the engine ever refused a client and committed anyway, the refused id would
/// show up as present and `reconcile` would report it as "a refused transaction left a trace" —
/// which is the correct diagnosis of exactly that bug.
#[test]
// `rmp` #1053 is FIXED, and this gate's `#[ignore]` was removed with it. It used to report a
// reopened store carrying `UndoSlot { kind: Commit, DeltaCountMismatch { recorded: 3, actual: 4 } }`
// on several COMMITTED slots — durable corruption of the undo area that survived WAL recovery, on
// EVERY run at `engine_workers = 8` and on none at `engine_workers = 1`.
//
// The cause was in `RecordStore::link_delta`: a delta is written live BEFORE its chain-head
// publication (the order `04 §5.1.2` fixes) and registered in `undo_links` AFTER it, so a refused
// publication — the write-write conflict two writers on one chain produce — left the delta live, on
// no chain, uncounted by `publish_commit_slot` and unfreed by `detach_own_deltas`. It outlived its
// transaction and went on naming a commit slot the allocator had already re-issued to somebody else.
// `link_delta` now retires that delta before propagating the refusal. Measured: 36 of 36 runs that
// reached this check were corrupt with the retirement withdrawn, 0 of 40 with it in place. Its
// by-seed guard is `graphus-dst`'s `det_scheduler_unpublished_delta_1053`.
//
// `rmp` #1052 is FIXED and no longer contributes: the two engine workers that used to panic
// simultaneously on `statistics count decrement underflow at absent key` no longer do — 14 runs of
// this gate in a row came back with neither that panic nor any other engine-thread panic. Its
// regression guards are `graphus-storage`'s `catalog_counts_multi_writer_1052` (which asserts the
// counter VALUE, so it fails in a release build too) and `graphus-dst`'s
// `det_scheduler_catalog_counts_1052`.
//
// STILL IGNORED, for a defect neither of those was: `rmp` #1056. With both fixes in place this gate
// still fails about 15 % of runs on a different oracle — "the shared counters total 105 after 107
// acknowledged concurrent increments", a LOST UPDATE, which is the cardinal ACID violation. It was
// measured to be independent and pre-existing (4 failures in 40 runs with #1053's fix withdrawn
// against 6 in 40 with it — statistically indistinguishable), and it composes two defects in another
// subsystem: `ensure_chain_head_unheld` never implemented the "nor committed before its own start
// timestamp" arm that `D-write-conflict-detection` ratified, and `SsiTracker::are_concurrent` treats
// `commit_ts == begin_ts` as non-concurrent, which contradicts visibility and stops the rw-edge from
// forming — so the SSI backstop never fires either. Every losing pair measured had exactly that
// equality.
//
// Ignored under the same bounded exception the project owner approved on 2026-08-11: #1056 removes
// this attribute and may not close while it is still here.
#[ignore = "rmp #1056: lost update at engine_workers > 1; un-ignored by the task that fixes it"]
fn no_acknowledged_commit_is_lost_or_invented_across_a_restart() {
    const SHARDS: i64 = 4;
    const PER_CLIENT: i64 = 40;
    let workers = engine_workers();
    let clients = workers * 2;
    let started = Instant::now();

    let dir = TempDir::new("lostwrite");
    let engine = create_engine(&dir.path, workers);
    let handle = engine.handle.clone();

    // Seed the contended counters, and warm the catalog so the measured phase is steady state.
    for s in 0..SHARDS {
        run_auto(
            &handle,
            AccessMode::Write,
            "CREATE (:Ctr {s: $s, n: 0})",
            vec![("s".to_owned(), Value::Integer(s))],
        );
    }
    run_auto(&handle, AccessMode::Write, "CREATE (:Rec {id: -1})", vec![]);

    let tally = Arc::new(Tally::default());
    let mut threads = Vec::with_capacity(clients);
    for c in 0..clients {
        let handle = handle.clone();
        let tally = Arc::clone(&tally);
        threads.push(std::thread::spawn(move || {
            let mut acked: Vec<i64> = Vec::new();
            let mut refused: Vec<i64> = Vec::new();
            for j in 0..PER_CLIENT {
                let id = (c as i64 + 1) * 1_000_000 + j;
                // Rotating the shard by the iteration keeps every client's share of every shard
                // roughly equal, so the contention is spread rather than concentrated on one record.
                let shard = (c as i64 + j) % SHARDS;
                let outcome = (|| -> Result<(), GraphusError> {
                    let ticket = handle.begin_blocking(AccessMode::Write)?;
                    let out = (|| {
                        run_in(
                            &handle,
                            ticket,
                            "MATCH (c:Ctr {s: $s}) SET c.n = c.n + 1",
                            vec![("s".to_owned(), Value::Integer(shard))],
                        )?;
                        run_in(
                            &handle,
                            ticket,
                            "CREATE (:Rec {id: $id})",
                            vec![("id".to_owned(), Value::Integer(id))],
                        )?;
                        handle.commit_blocking(ticket).map(|_| ())
                    })();
                    if out.is_err() {
                        // The transaction is finished either way; the engine may already have
                        // rolled it back, in which case this rollback is a no-op that errors.
                        let _ = handle.rollback_blocking(ticket);
                    }
                    out
                })();
                match outcome {
                    Ok(()) => {
                        tally.commit();
                        acked.push(id);
                    }
                    Err(e) => {
                        tally.refuse(&e);
                        refused.push(id);
                    }
                }
            }
            (acked, refused)
        }));
    }

    let mut acked: BTreeSet<i64> = BTreeSet::new();
    let mut refused: BTreeSet<i64> = BTreeSet::new();
    for t in threads {
        let (a, r) = t.join().expect("client thread joins");
        acked.extend(a);
        refused.extend(r);
    }
    acked.insert(-1); // the warm-up write, which also has to still be there
    let elapsed_storm = started.elapsed();
    tally.assert_contended("gate 1 (no lost committed write)");

    // --- before the restart -------------------------------------------------------------------
    let present_live = read_back(&handle, "live engine");
    assert_eq!(
        reconcile(&acked, &present_live),
        None,
        "on the LIVE engine, the ids present do not match the ids the server acknowledged"
    );
    let counter_live = counter_sum(&handle);
    assert_eq!(
        counter_live,
        tally.committed() as i64,
        "the shared counters total {counter_live} after {} acknowledged concurrent increments: an \
         increment was lost, which means two writers read the same value and both committed",
        tally.committed()
    );

    // --- the restart --------------------------------------------------------------------------
    drop(handle);
    graceful_shutdown(engine);
    let engine = reopen_engine(&dir.path, workers);
    let handle = engine.handle.clone();

    let present_restart = read_back(&handle, "restarted engine");
    assert_eq!(
        reconcile(&acked, &present_restart),
        None,
        "after a restart through the durable WAL, the ids present do not match the ids the server \
         acknowledged"
    );
    let counter_restart = counter_sum(&handle);
    assert_eq!(
        counter_restart, counter_live,
        "the shared counters read {counter_live} before the restart and {counter_restart} after it"
    );
    // Stated separately from the set comparison so the failure names the class directly.
    let leaked: Vec<i64> = refused.intersection(&present_restart).copied().collect();
    assert!(
        leaked.is_empty(),
        "transactions the server REFUSED left data behind after a restart: {leaked:?}"
    );

    // --- the controls, on the very sets the assertions above passed on --------------------------
    // Both branches of `reconcile` are proven live here, against the real data, on every run.
    let mut minus_one = acked.clone();
    let dropped = *minus_one.iter().next().expect("the acked set is non-empty");
    minus_one.remove(&dropped);
    assert!(
        reconcile(&minus_one, &present_restart).is_some(),
        "CONTROL FAILED: dropping acknowledged id {dropped} from the expected set was not reported \
         as a discrepancy, so the comparison this gate rests on cannot detect an invented row"
    );
    let mut plus_phantom = acked.clone();
    plus_phantom.insert(i64::MAX);
    assert!(
        reconcile(&plus_phantom, &present_restart).is_some(),
        "CONTROL FAILED: adding a phantom acknowledged id was not reported as a discrepancy, so \
         the comparison this gate rests on cannot detect a LOST committed write"
    );

    // --- physical integrity of the reopened store ----------------------------------------------
    drop(handle);
    graceful_shutdown(engine);
    let report = reopen_and_check(&dir.path);
    assert!(
        report.is_consistent(),
        "the reopened store is structurally inconsistent: {:?}",
        report.violations
    );

    println!(
        "rmp #1034 gate 1: workers={workers} clients={clients} attempted={} committed={} \
         conflicts={} abort_rate={:.3} storm={:.2}s live_nodes={} live_props={}\n  abort shapes:{}",
        tally.attempted(),
        tally.committed(),
        tally.conflicts(),
        tally.abort_rate(),
        elapsed_storm.as_secs_f64(),
        report.live_nodes,
        report.live_props,
        Tally::histogram(&tally.conflicts),
    );
}

/// Reads back every `:Rec` id as a set, asserting on the way that no id appears twice.
fn read_back(handle: &EngineHandle, where_: &str) -> BTreeSet<i64> {
    let rows = run_auto(
        handle,
        AccessMode::Read,
        "MATCH (n:Rec) RETURN n.id AS id",
        vec![],
    );
    let ids = int_column(&rows, "the :Rec id column");
    let set: BTreeSet<i64> = ids.iter().copied().collect();
    assert_eq!(
        set.len(),
        ids.len(),
        "the {where_} returned duplicate :Rec ids ({} rows, {} distinct)",
        ids.len(),
        set.len()
    );
    set
}

/// The sum of the shared counters. Summed in the test rather than by an aggregate so the oracle is
/// the stored values themselves.
fn counter_sum(handle: &EngineHandle) -> i64 {
    let rows = run_auto(
        handle,
        AccessMode::Read,
        "MATCH (c:Ctr) RETURN c.n AS n",
        vec![],
    );
    int_column(&rows, "the counter column").iter().sum()
}

// ---------------------------------------------------------------------------------------------
// GATE 2 — the concurrent history is serializable
// ---------------------------------------------------------------------------------------------

/// The Elle key for register `k`.
fn reg_key(k: i64) -> Key {
    format!("k{k}")
}

/// Injects a **real write-skew cycle** into a clone of `history`, or returns `None` if the recorded
/// run contained no two committed transactions that appended to different keys.
///
/// The injection is minimal and uses the recorded transactions themselves rather than synthetic
/// ones: two committed transactions `T1` and `T2` that appended to different keys `k1` and `k2` are
/// each given one extra read — `T1` reads `k2` observing nothing, `T2` reads `k1` observing nothing.
/// Each therefore missed the other's committed write, which is an rw-antidependency in both
/// directions and a cycle of length two: the textbook write skew, and precisely the anomaly SSI
/// exists to prevent. An empty observation is a prefix of every other observation of the same key,
/// so the mutation cannot be rejected for the unrelated "incompatible read orders" reason — the
/// caller checks that the verdict names a cycle.
fn inject_write_skew(history: &History) -> Option<History> {
    let appended_key = |t: &Transaction| -> Option<Key> {
        t.ops.iter().find_map(|o| match o {
            Op::Append { key, .. } => Some(key.clone()),
            Op::Read { .. } => None,
        })
    };
    let mut first: Option<(usize, Key)> = None;
    for (i, t) in history.iter().enumerate() {
        if !t.committed {
            continue;
        }
        let Some(k) = appended_key(t) else { continue };
        match &first {
            None => first = Some((i, k)),
            Some((j, k0)) if *k0 != k => {
                let (j, k0) = (*j, k0.clone());
                let mut mutated = history.clone();
                mutated[j].ops.insert(
                    0,
                    Op::Read {
                        key: k.clone(),
                        observed: Vec::new(),
                    },
                );
                mutated[i].ops.insert(
                    0,
                    Op::Read {
                        key: k0,
                        observed: Vec::new(),
                    },
                );
                return Some(mutated);
            }
            Some(_) => {}
        }
    }
    None
}

/// **GATE 2 — a history recorded from real concurrent writers has no isolation anomaly.**
///
/// `CLIENTS` threads run explicit read-write transactions over `KEYS` list-valued registers. Each
/// transaction reads two distinct registers and then appends a globally unique value to one of them
/// — the list-append model [`graphus_elle`] checks, and a shape that produces both classes of
/// conflict on purpose: the append is a read-modify-write of a record other threads are also
/// writing (write-write), and reading two registers while writing one of them is the write-skew
/// shape that only rw-antidependency tracking can catch.
///
/// Every transaction is recorded, committed or aborted, with exactly the values it observed. The
/// committed sub-history goes to [`graphus_elle::check`], which recovers each register's true
/// version order from the observed lists and reports any ww/wr/rw cycle.
///
/// Two further oracles run beside the checker, because a clean Elle verdict is a statement about the
/// history the test recorded and not, on its own, about the database:
///
/// - **No committed append is missing and no aborted one survived.** Each register's final list must
///   be exactly the set of values committed transactions appended to it — appends never remove, so
///   an absent value is a lost committed write and an extra one is a dirty write.
/// - **No register's list contains a duplicate**, which is what a lost update looks like from the
///   other side.
#[test]
// GREEN SINCE `rmp` #1051, and what it found is worth keeping next to the gate that found it. At
// `engine_workers = 8` this failed 3 runs out of 3 with the store's own fail-closed tripwire —
// "delta D on Node X is not on the head prefix of its chain, so detaching it would splice a live
// chain" — after which the transaction stayed OPEN with its uncommitted writes physically present
// and `degrade_on_incomplete_undo` took the whole database out: 476 of 480 requests answered "engine
// degraded … pending a controlled restart". The IDENTICAL workload passed at `engine_workers = 1`,
// which is what said the defect was multi-writer and not the workload.
//
// The cause was NOT the chain-head protocol the message points at. `TxnCoordinator::commit_prepare`
// answered an SSI Case-B dangerous structure by running the VICTIM's undo from the committing
// worker's thread, and the victim was a transaction another worker was running — so two workers
// entered one `rollback_logical`. The victim is now condemned instead
// (`TxnCoordinator::break_dangerous_structure`, `SsiTracker::doom`) and aborts itself, on its own
// worker. Reproduced from a seed by `graphus-dst`'s `det_scheduler_double_rollback_1051`.
fn the_concurrent_history_has_no_isolation_anomaly() {
    const KEYS: i64 = 4;
    const PER_CLIENT: i64 = 30;
    let workers = engine_workers();
    let clients = workers * 2;
    let started = Instant::now();

    let dir = TempDir::new("isolation");
    let engine = create_engine(&dir.path, workers);
    let handle = engine.handle.clone();

    for k in 0..KEYS {
        run_auto(
            &handle,
            AccessMode::Write,
            "CREATE (:Reg {k: $k, vals: []})",
            vec![("k".to_owned(), Value::Integer(k))],
        );
    }
    // FIXTURE CHECK. The whole model rests on an append being `list + value`; if an empty list
    // property did not round-trip as an empty list, every append would evaluate `null + v = null`,
    // every read would observe nothing, and the checker would bless a history in which nothing ever
    // happened. Verified here, loudly, before a single concurrent transaction runs.
    let seeded = run_auto(
        &handle,
        AccessMode::Read,
        "MATCH (n:Reg {k: 0}) RETURN n.vals AS vals",
        vec![],
    );
    assert!(
        int_list(&seeded, "the seeded register").is_empty(),
        "a register must start as an empty list, not {seeded:?}"
    );

    let tally = Arc::new(Tally::default());
    let mut threads = Vec::with_capacity(clients);
    for c in 0..clients {
        let handle = handle.clone();
        let tally = Arc::clone(&tally);
        threads.push(std::thread::spawn(move || {
            let mut rng = Rng::new(c as u64 + 1);
            let mut local: History = Vec::with_capacity(PER_CLIENT as usize);
            for j in 0..PER_CLIENT {
                let a = rng.below(KEYS as u64) as i64;
                // A distinct second register, chosen without rejection sampling.
                let b = (a + 1 + rng.below(KEYS as u64 - 1) as i64) % KEYS;
                // Alternating the written register between the two read ones is what makes the
                // write-skew shape appear: half the transactions write the register they read
                // first, half write the other one, so two concurrent transactions routinely each
                // write the register the other read.
                let target = if j % 2 == 0 { a } else { b };
                let val: Val = (c as i64 + 1) * 1_000_000 + j;
                let txid = ((c as u64 + 1) * 1_000_000) + j as u64;

                let mut ops: Vec<Op> = Vec::with_capacity(3);
                let outcome = (|| -> Result<(), GraphusError> {
                    let ticket = handle.begin_blocking(AccessMode::Write)?;
                    let out = (|| {
                        for k in [a, b] {
                            let rows = run_in(
                                &handle,
                                ticket,
                                "MATCH (n:Reg {k: $k}) RETURN n.vals AS vals",
                                vec![("k".to_owned(), Value::Integer(k))],
                            )?;
                            ops.push(Op::Read {
                                key: reg_key(k),
                                observed: int_list(&rows, "a register's list"),
                            });
                        }
                        run_in(
                            &handle,
                            ticket,
                            "MATCH (n:Reg {k: $k}) SET n.vals = n.vals + $v",
                            vec![
                                ("k".to_owned(), Value::Integer(target)),
                                ("v".to_owned(), Value::Integer(val)),
                            ],
                        )?;
                        ops.push(Op::Append {
                            key: reg_key(target),
                            val,
                        });
                        handle.commit_blocking(ticket).map(|_| ())
                    })();
                    if out.is_err() {
                        let _ = handle.rollback_blocking(ticket);
                    }
                    out
                })();

                match outcome {
                    Ok(()) => {
                        tally.commit();
                        local.push(Transaction::committed(txid, ops));
                    }
                    Err(e) => {
                        tally.refuse(&e);
                        // Recorded WITH its ops: an aborted transaction that left a trace is a
                        // dirty write, and the checker can only look for one if it is told the
                        // transaction aborted rather than simply not told about it.
                        local.push(Transaction::aborted(txid, ops));
                    }
                }
            }
            local
        }));
    }

    let mut history: History = Vec::new();
    for t in threads {
        history.extend(t.join().expect("client thread joins"));
    }
    let elapsed_storm = started.elapsed();
    tally.assert_contended("gate 2 (no isolation anomaly)");

    // NON-VACUITY, second measure: aborts prove writers overlapped in TIME; this proves they
    // overlapped on the same RECORD. A run in which each client only ever appended to its own
    // register could contend on the shared counters of gate 1 and still leave the isolation oracle
    // nothing to reason about.
    let mut writers_per_key: BTreeMap<Key, BTreeSet<u64>> = BTreeMap::new();
    for t in history.iter().filter(|t| t.committed) {
        for op in &t.ops {
            if let Op::Append { key, .. } = op {
                writers_per_key
                    .entry(key.clone())
                    .or_default()
                    .insert(t.id / 1_000_000);
            }
        }
    }
    let shared_keys = writers_per_key.values().filter(|w| w.len() > 1).count();
    assert!(
        shared_keys > 0,
        "no register received committed appends from more than one client thread, so no two \
         transactions ever contended for the same record and the checker had nothing to reason \
         about: {writers_per_key:?}"
    );

    // --- the oracle ---------------------------------------------------------------------------
    let verdict = check(&history);
    assert!(
        verdict.serializable,
        "the history recorded from {clients} concurrent writer threads on a {workers}-worker \
         engine is NOT serializable: {}",
        verdict.anomaly.unwrap_or_default()
    );

    // --- the control: the same oracle, on the same history, made genuinely anomalous -------------
    let mutated = inject_write_skew(&history).expect(
        "CONTROL IMPOSSIBLE: the recorded run has no two committed transactions that appended to \
         different registers, so the oracle could not be shown to have teeth on this data",
    );
    let mutated_verdict = check(&mutated);
    assert!(
        !mutated_verdict.serializable,
        "CONTROL FAILED: a write-skew cycle injected into the recorded history was ACCEPTED by \
         graphus_elle::check, so the clean verdict above certifies nothing"
    );
    let reason = mutated_verdict.anomaly.unwrap_or_default();
    assert!(
        reason.contains("cycle"),
        "CONTROL FAILED: the injected write skew was rejected for the wrong reason ({reason:?}); \
         the control must exercise the dependency-cycle path, not the read-order check"
    );
    // The recorded history is what the assertion above passed on, and the mutation must not have
    // touched it — `inject_write_skew` clones. Cheap to state, and it is the difference between a
    // control and a corruption.
    assert_eq!(
        check(&history),
        verdict,
        "the recorded history changed while the control ran"
    );

    // --- the database itself agrees with the committed history ----------------------------------
    let mut expected: BTreeMap<Key, BTreeSet<Val>> = BTreeMap::new();
    for t in history.iter().filter(|t| t.committed) {
        for op in &t.ops {
            if let Op::Append { key, val } = op {
                assert!(
                    expected.entry(key.clone()).or_default().insert(*val),
                    "value {val} was appended to {key} by two committed transactions"
                );
            }
        }
    }
    for k in 0..KEYS {
        let rows = run_auto(
            &handle,
            AccessMode::Read,
            "MATCH (n:Reg {k: $k}) RETURN n.vals AS vals",
            vec![("k".to_owned(), Value::Integer(k))],
        );
        let list = int_list(&rows, "a register's final list");
        let as_set: BTreeSet<Val> = list.iter().copied().collect();
        assert_eq!(
            as_set.len(),
            list.len(),
            "register {k}'s final list holds a duplicate: {list:?}"
        );
        let want = expected.remove(&reg_key(k)).unwrap_or_default();
        assert_eq!(
            as_set,
            want,
            "register {k}'s final list disagrees with the committed history: missing {:?}, \
             unexpected {:?}",
            want.difference(&as_set).collect::<Vec<_>>(),
            as_set.difference(&want).collect::<Vec<_>>()
        );
    }

    drop(handle);
    graceful_shutdown(engine);

    println!(
        "rmp #1034 gate 2: workers={workers} clients={clients} attempted={} committed={} \
         conflicts={} abort_rate={:.3} shared_registers={shared_keys}/{KEYS} storm={:.2}s\n  \
         abort shapes:{}",
        tally.attempted(),
        tally.committed(),
        tally.conflicts(),
        tally.abort_rate(),
        elapsed_storm.as_secs_f64(),
        Tally::histogram(&tally.conflicts),
    );
}

// ---------------------------------------------------------------------------------------------
// GATE 3 — the store is physically intact after the storm
// ---------------------------------------------------------------------------------------------

/// **GATE 3 — a concurrent create/delete storm leaves a physically consistent store.**
///
/// Gates 1 and 2 grow the store and never shrink it, which leaves the structures that a multi-writer
/// engine is most likely to corrupt barely exercised: the free lists (nothing is freed), the
/// incidence chains (there are no relationships), and the chain-head publication protocol under
/// concurrent prepends. This gate's workload exists to reach them. Each transaction:
///
/// - creates a `LINK` relationship between two hub nodes drawn from a small pool, so several writers
///   prepend to the same incidence chain head at the same time;
/// - overwrites a hub's property, so the undo/property chain of a shared record churns;
/// - every third iteration deletes one of the hub's relationships, returning a record to the free
///   list while other writers are allocating from it;
/// - every fifth iteration creates and deletes a throw-away node inside the same transaction,
///   returning a node slot and its property in the same commit.
///
/// The oracle is [`graphus_storage::check::check_store`] over the reopened store — the full
/// read-only pass: checksums and page ids, the record scan, the free lists, and the chain walks. A
/// clean [`ConsistencyReport`] is required, and the live counts are printed so the run records what
/// was actually there rather than only that nothing was broken.
#[test]
// USED TO HANG, AND THAT WAS THE FINDING (`rmp` #1054, now FIXED — the `#[ignore]` is gone with it).
// At `engine_workers = 8` one engine worker spun at 105 % CPU for more than ten minutes while its 7
// siblings, the reader threads, the walsync thread and all 16 client threads sat in `futex_wait` — no
// progress, no timeout, no error — against 2.0 s at `engine_workers = 1` for the IDENTICAL workload.
//
// The spin was `RecordStore::unlink_side_with`'s publication retry. It decided headship from the
// relationship's own back-pointer (`prev == NULL_ID` ⇒ "I am the head") rather than from the node's
// `first_rel`, so when three separate writers of a `prev` word — a relink writing the side it did not
// own, a relink declining to write the side it did, and a neighbour repoint writing the record whole
// from a stale image — left that word naming nobody while the head word named somebody else, the
// compare-and-publish was refused for ever and the re-read could not change it. Headship now comes
// from the node, every writer of a chain word goes through one latched primitive, and the predecessor
// is derived from the forward chain when the back-pointer cannot supply it; the retry is bounded by
// `graphus_chainhead::MAX_ATTEMPTS` and fails loudly rather than spinning.
fn the_store_is_physically_consistent_after_a_concurrent_write_storm() {
    const HUBS: i64 = 6;
    const PER_CLIENT: i64 = 30;
    let workers = engine_workers();
    let clients = workers * 2;
    let started = Instant::now();

    let dir = TempDir::new("churn");
    let engine = create_engine(&dir.path, workers);
    let handle = engine.handle.clone();

    for k in 0..HUBS {
        run_auto(
            &handle,
            AccessMode::Write,
            "CREATE (:Hub {k: $k, hits: 0})",
            vec![("k".to_owned(), Value::Integer(k))],
        );
    }

    let tally = Arc::new(Tally::default());
    let mut threads = Vec::with_capacity(clients);
    for c in 0..clients {
        let handle = handle.clone();
        let tally = Arc::clone(&tally);
        threads.push(std::thread::spawn(move || {
            let mut rng = Rng::new(0xC0FF_EE00 + c as u64);
            for j in 0..PER_CLIENT {
                let i = rng.below(HUBS as u64) as i64;
                let o = (i + 1 + rng.below(HUBS as u64 - 1) as i64) % HUBS;
                let v = (c as i64 + 1) * 1_000_000 + j;
                let outcome = (|| -> Result<(), GraphusError> {
                    let ticket = handle.begin_blocking(AccessMode::Write)?;
                    let out = (|| {
                        run_in(
                            &handle,
                            ticket,
                            "MATCH (a:Hub {k: $i}) MATCH (b:Hub {k: $o}) \
                             CREATE (a)-[:LINK {w: $v}]->(b)",
                            vec![
                                ("i".to_owned(), Value::Integer(i)),
                                ("o".to_owned(), Value::Integer(o)),
                                ("v".to_owned(), Value::Integer(v)),
                            ],
                        )?;
                        run_in(
                            &handle,
                            ticket,
                            "MATCH (h:Hub {k: $i}) SET h.hits = h.hits + 1",
                            vec![("i".to_owned(), Value::Integer(i))],
                        )?;
                        if j % 3 == 0 {
                            run_in(
                                &handle,
                                ticket,
                                "MATCH (:Hub {k: $i})-[r:LINK]->() WITH r LIMIT 1 DELETE r",
                                vec![("i".to_owned(), Value::Integer(i))],
                            )?;
                        }
                        if j % 5 == 0 {
                            run_in(
                                &handle,
                                ticket,
                                "CREATE (:Tmp {v: $v})",
                                vec![("v".to_owned(), Value::Integer(v))],
                            )?;
                            run_in(
                                &handle,
                                ticket,
                                "MATCH (t:Tmp {v: $v}) DELETE t",
                                vec![("v".to_owned(), Value::Integer(v))],
                            )?;
                        }
                        handle.commit_blocking(ticket).map(|_| ())
                    })();
                    if out.is_err() {
                        let _ = handle.rollback_blocking(ticket);
                    }
                    out
                })();
                match outcome {
                    Ok(()) => tally.commit(),
                    Err(e) => tally.refuse(&e),
                }
            }
        }));
    }
    for t in threads {
        t.join().expect("client thread joins");
    }
    let elapsed_storm = started.elapsed();
    tally.assert_contended("gate 3 (physical integrity after the storm)");

    // No `:Tmp` node may survive: every one was created and deleted inside a single transaction,
    // so an aborted one leaves nothing and a committed one leaves nothing either.
    let tmp = single_int(
        &run_auto(
            &handle,
            AccessMode::Read,
            "MATCH (t:Tmp) RETURN count(t) AS c",
            vec![],
        ),
        "the surviving :Tmp count",
    );
    assert_eq!(
        tmp, 0,
        "{tmp} throw-away nodes survived a create-then-delete in the same transaction"
    );

    drop(handle);
    graceful_shutdown(engine);
    let report = reopen_and_check(&dir.path);
    assert!(
        report.is_consistent(),
        "after {} committed concurrent create/delete transactions on {workers} workers, the \
         reopened store is structurally inconsistent: {:?}",
        tally.committed(),
        report.violations
    );
    // The check is only worth running over a store that actually holds the structures it walks.
    assert!(
        report.live_rels > 0,
        "the churn left no live relationships, so the incidence-chain and free-list checks walked \
         nothing"
    );
    // The hubs must all still be there. Deliberately a LOWER BOUND and not an equality: the logical
    // question ("did a deleted node survive?") is answered above by the `MATCH (t:Tmp)` count, which
    // is zero, whereas `live_nodes` counts *records not yet returned to the free list*. A node
    // deleted by a committed transaction, and a slot orphaned by a logical rollback
    // (`D-orphan-slot-parking`), both stay in use until a GC pass reclaims them, so the physical
    // count legitimately exceeds the logical one by however much GC has not yet run. Asserting
    // equality here measures the GC's schedule, not the engine's correctness — measured at `W = 1`,
    // 6 hubs against 14 live node records.
    assert!(
        report.live_nodes >= HUBS as u64,
        "the {HUBS} hub nodes must all survive the storm; the store reports only {} live node \
         records",
        report.live_nodes
    );

    println!(
        "rmp #1034 gate 3: workers={workers} clients={clients} attempted={} committed={} \
         conflicts={} abort_rate={:.3} storm={:.2}s live_nodes={} live_rels={} live_props={} \
         live_blocks={}\n  abort shapes:{}",
        tally.attempted(),
        tally.committed(),
        tally.conflicts(),
        tally.abort_rate(),
        elapsed_storm.as_secs_f64(),
        report.live_nodes,
        report.live_rels,
        report.live_props,
        report.live_blocks,
        Tally::histogram(&tally.conflicts),
    );
}
