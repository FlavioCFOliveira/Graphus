//! **Two real writer threads over one shared `TxnCoordinator`** (`rmp` #1010, layer 2 of #975).
//!
//! # Why this scenario exists
//!
//! Every multi-threaded shape the project could express before this was **one writer plus N readers**.
//! That was not a design preference, it was a *type* constraint: the coordinator's six shared fields
//! were `Rc<RefCell<…>>`, so `TxnCoordinator` was `!Send`, so it could not cross a thread boundary at
//! all — and "two threads that both write through one coordinator" was not a scenario anyone could
//! write down, correct or otherwise.
//!
//! `rmp` #1009 made the six *contents* `Send + Sync`; `rmp` #1010 replaced the packaging with
//! [`graphus_cypher::shared_cell::SharedCell`] (`Arc<Mutex<…>>`). Together they make the coordinator
//! `Send`, and this scenario is the proof that the frontier actually moved: it **compiles**, which was
//! previously impossible, and it **runs**, which is the part a type assertion alone cannot show.
//!
//! # What it does and does NOT prove
//!
//! It does **not** prove parallel write throughput, and it is not meant to. The writers still
//! serialise — first on the outer lock this scenario has to take, and underneath that on every
//! `SharedCell` acquisition. Layer 2 deliberately keeps one thread of *execution*; removing the
//! serialisation is layers 3 to 7.
//!
//! What it proves is the three things that must hold before those layers can be attempted:
//!
//! 1. **Expressibility** — `TxnCoordinator` is `Send`, and `Arc<…>` over it is `Send + Sync`, so two
//!    OS threads can share one. Stated as a compile-time assertion as well as exercised.
//! 2. **Liveness under genuine cross-thread contention** — two writer threads that really do collide
//!    on the shared cells make progress and terminate. This is not free: the `SharedCell` tripwire
//!    panics on a *re-entrant* acquisition, so a scenario like this is exactly what would expose a
//!    tripwire that could not tell re-entrancy from ordinary contention (it would abort here instead
//!    of blocking).
//! 3. **Safety** — every transaction that commits is durable and readable afterwards, and the two
//!    threads' writes do not corrupt or lose one another.
//!
//! # Why an outer lock is still needed
//!
//! The coordinator's transaction lifecycle (`begin_serializable`, `commit`) takes `&mut self`, so a
//! bare `Arc<TxnCoordinator>` cannot drive a transaction no matter how `Send` it is. That `&mut self`
//! is the *next* frontier, not this one — the task that owns it is explicitly downstream. So the
//! shared handle here is `Arc<Mutex<TxnCoordinator<…>>>`, and the load-bearing fact is that this type
//! is `Send + Sync` **at all**: `Mutex<T>: Sync` requires `T: Send`, which is precisely what layer 2
//! delivered and what no amount of wrapping could have produced before it.
//!
//! # Thread lane, not seed lane
//!
//! Like [`crate`]'s other real-OS-thread scenarios, the interleaving here is chosen by the OS
//! scheduler, so this is **not** part of the deterministic seed-replay gate. It needs no
//! `det-sched` feature. Its assertions are all scheduler-independent: totals, liveness, and a
//! contention hand-off that is sequenced by explicit signalling rather than by timing.

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Barrier, Mutex, mpsc};
use std::time::{Duration, Instant};

use graphus_core::Value;
use graphus_cypher::TxnCoordinator;
use graphus_io::MemBlockDevice;
use graphus_storage::{Namespace, RecordStore};
use graphus_wal::{MemLogSink, WalManager};

/// The coordinator this scenario shares between writer threads.
type Coord = TxnCoordinator<MemBlockDevice, MemLogSink>;

/// The shared handle. See the module docs for why the [`Mutex`] is still here.
type SharedCoord = Arc<Mutex<Coord>>;

/// The label every writer thread stamps on the nodes it creates.
const LABEL: &str = "Written";

/// The property holding the id of the thread that created the node, so the read-back can attribute
/// every surviving row to a writer.
const AUTHOR: &str = "author";

/// **The type frontier layer 2 moved**, stated so it is a build error rather than a claim.
///
/// This is the whole of acceptance criterion 1, plus the `Arc` form criterion 2 names. It has no
/// runtime body: `Send`/`Sync` are auto-derived, so the only way to assert them is to make the
/// compilation fail when they stop holding.
const _: () = {
    fn assert_send<T: Send>() {}
    fn assert_send_sync<T: Send + Sync>() {}
    fn assertions() {
        // Criterion 1: the coordinator itself crosses a thread boundary.
        assert_send::<Coord>();
        // Criterion 2: `Arc<TxnCoordinator<…>>` is shareable between threads. `Arc<T>: Send + Sync`
        // requires `T: Send + Sync`, so this is strictly stronger than the line above.
        assert_send_sync::<Arc<Coord>>();
        // And the form this scenario actually drives, which additionally needs `Mutex<T>: Sync`
        // (i.e. `T: Send`) — the property that did not hold before `rmp` #1010.
        assert_send_sync::<SharedCoord>();
    }
    let _ = assertions;
};

/// What [`run_two_writer_threads`] observed.
#[derive(Debug, Clone)]
pub struct MultiWriterReport {
    /// Commits reported by each writer thread, in thread order.
    pub committed_per_thread: Vec<usize>,
    /// Transactions each writer thread had refused (an SSI abort, say), in thread order. Reported
    /// rather than asserted away: a refusal is a legitimate serializable outcome, and hiding it would
    /// let a run that refused *everything* look identical to one that succeeded.
    pub refused_per_thread: Vec<usize>,
    /// Nodes carrying [`LABEL`] visible to a fresh transaction after both writers joined.
    pub visible_after: usize,
    /// Of those, how many each thread is recorded as the author of, in thread order.
    pub visible_per_author: Vec<usize>,
    /// Distinct OS threads that actually ran a writer body. Two threads that both did work is the
    /// non-vacuity control: without it, a run where one thread did everything would pass every total.
    pub distinct_writer_threads: usize,
    /// Wall-clock duration of the concurrent phase, purely informational.
    pub elapsed: Duration,
}

impl MultiWriterReport {
    /// Total commits across every writer thread.
    #[must_use]
    pub fn committed_total(&self) -> usize {
        self.committed_per_thread.iter().sum()
    }
}

/// What [`run_contended_handoff`] observed — the deterministic half of the scenario.
#[derive(Debug, Clone)]
pub struct HandoffReport {
    /// Whether the second thread's acquisition completed **after** the first thread released, which
    /// is what "it blocked rather than panicking or barging" means.
    pub second_acquired_after_release: bool,
    /// Whether the second thread panicked. A `SharedCell` tripwire that could not distinguish
    /// contention from re-entrancy would set this.
    pub second_panicked: bool,
    /// Whether the second thread's write is visible afterwards — it must not merely survive the
    /// contention, it must take effect.
    pub second_write_visible: bool,
}

/// Builds a fresh in-memory coordinator with the scenario's tokens already interned.
///
/// # Panics
/// Panics if the store or its WAL cannot be created, or the seed transaction cannot commit.
#[must_use]
pub fn fresh_shared_coordinator() -> SharedCoord {
    let device = MemBlockDevice::new(0);
    let wal = WalManager::create(MemLogSink::new()).expect("create wal");
    let store: RecordStore<MemBlockDevice, MemLogSink> =
        RecordStore::create(device, wal, 512, 1).expect("create store");
    let coord = TxnCoordinator::new(store);

    // Intern the tokens up front, in their own committed transaction, so a writer thread's failure
    // can never be "the label did not exist yet" — which would make a lost write look like a refusal.
    let seed = coord.begin_serializable();
    coord.with_store_mut(|s| {
        s.intern_token(Namespace::Label, LABEL)
            .expect("intern label");
        s.intern_token(Namespace::PropKey, AUTHOR)
            .expect("intern author key");
    });
    coord.commit(seed).expect("seed commits");

    Arc::new(Mutex::new(coord))
}

/// Runs one write transaction: create a node, label it, and stamp the author.
///
/// Returns the committed node id, or the error text if the coordinator refused the transaction.
fn write_one(coord: &SharedCoord, author: i64) -> Result<u64, String> {
    use graphus_cypher::graph_access::GraphAccess;

    let guard = coord
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let txn = guard.begin_serializable();
    // Through the STATEMENT SEAM, not `with_store_mut`. The raw store escape hatch writes the record
    // and skips `reindex_node`, so the derived label index never learns about the row — but the point
    // is not the read-back: it is that the seam is the **coordinated write path**, the one that runs
    // index maintenance and constraint enforcement. That is where `rmp` #1010 found its real
    // production re-entrancy (`filter_label_candidates` → `entity_visible`), so driving anything less
    // than the full seam here would be exercising the easy half.
    let created = {
        let mut seam = match guard.statement(txn) {
            Ok(seam) => seam,
            Err(e) => {
                let _ = guard.rollback(txn);
                return Err(e.to_string());
            }
        };
        let node = seam.create_node(
            &[LABEL.to_owned()],
            &[(AUTHOR.to_owned(), Value::Integer(author))],
        );
        // The seam CAPTURES a storage / deferred-feature error rather than returning it, so it must be
        // inspected before the transaction is allowed to commit: a captured error means the result is
        // untrustworthy (see `RecordStoreGraph`'s module docs).
        seam.take_error().map_or(Ok(node.0), |e| Err(e.to_string()))
    };
    match created {
        Ok(node) => match guard.commit(txn) {
            Ok(_) => Ok(node),
            Err(e) => Err(e.to_string()),
        },
        Err(e) => {
            let _ = guard.rollback(txn);
            Err(e)
        }
    }
}

/// Counts the labelled nodes visible to a fresh transaction, grouped by the author each carries.
///
/// # Panics
/// Panics if the read transaction cannot be opened or its statement seam cannot be taken.
fn read_back(coord: &SharedCoord, authors: usize) -> (usize, Vec<usize>) {
    use graphus_cypher::graph_access::GraphAccess;

    let guard = coord
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let txn = guard.begin_serializable();
    let mut per_author = vec![0usize; authors];
    let total = {
        let seam = guard.statement(txn).expect("statement seam");
        let nodes = seam.scan_nodes_by_label(LABEL);
        for node in &nodes {
            if let Some(Value::Integer(a)) = seam.node_property(*node, AUTHOR) {
                if let Ok(idx) = usize::try_from(a) {
                    if let Some(slot) = per_author.get_mut(idx) {
                        *slot += 1;
                    }
                }
            }
        }
        nodes.len()
    };
    guard.rollback(txn).expect("read-only rollback");
    (total, per_author)
}

/// **The stress half.** `threads` real OS writer threads, each committing `per_thread` transactions
/// through one shared coordinator, started together at a [`Barrier`] so they genuinely overlap.
///
/// # Panics
/// Panics if a writer thread panics — which is the point: a `SharedCell` re-entrancy under contention
/// would surface exactly here.
#[must_use]
pub fn run_two_writer_threads(threads: usize, per_thread: usize) -> MultiWriterReport {
    assert!(threads >= 2, "the scenario is about MORE than one writer");
    assert!(
        per_thread > 0,
        "a writer that writes nothing proves nothing"
    );

    let coord = fresh_shared_coordinator();
    let gate = Arc::new(Barrier::new(threads));
    let thread_ids = Arc::new(Mutex::new(Vec::<std::thread::ThreadId>::new()));

    let started = Instant::now();
    let mut handles = Vec::with_capacity(threads);
    for author in 0..threads {
        let coord = Arc::clone(&coord);
        let gate = Arc::clone(&gate);
        let thread_ids = Arc::clone(&thread_ids);
        handles.push(std::thread::spawn(move || {
            thread_ids
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .push(std::thread::current().id());
            // Release both writers at once, so their transactions really are in flight together
            // rather than one after the other.
            gate.wait();
            let (mut committed, mut refused) = (0usize, 0usize);
            for _ in 0..per_thread {
                match write_one(&coord, i64::try_from(author).expect("a small author index")) {
                    Ok(_) => committed += 1,
                    Err(_) => refused += 1,
                }
            }
            (committed, refused)
        }));
    }

    let mut committed_per_thread = Vec::with_capacity(threads);
    let mut refused_per_thread = Vec::with_capacity(threads);
    for handle in handles {
        let (committed, refused) = handle.join().expect(
            "a writer thread must not panic: under `SharedCell` a panic here means the tripwire \
             mistook ordinary cross-thread contention for a re-entrancy, or a genuine re-entrancy \
             is reachable only when two writers overlap",
        );
        committed_per_thread.push(committed);
        refused_per_thread.push(refused);
    }
    let elapsed = started.elapsed();

    let (visible_after, visible_per_author) = read_back(&coord, threads);
    // A `HashSet`, not sort+dedup: `ThreadId` is `Hash + Eq` but deliberately not `Ord`.
    let distinct_writer_threads = thread_ids
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .iter()
        .copied()
        .collect::<std::collections::HashSet<_>>()
        .len();

    MultiWriterReport {
        committed_per_thread,
        refused_per_thread,
        visible_after,
        visible_per_author,
        distinct_writer_threads,
        elapsed,
    }
}

/// **The deterministic half.** Thread B must *block* on a coordinator thread A is holding, then get it
/// and complete — never panic, never barge in.
///
/// Sequenced by explicit signalling rather than by timing: A signals that it holds the coordinator, B
/// signals that it is about to ask for it, and A only releases after seeing that signal. So the
/// contention is a fact of the run, not a hope about the scheduler.
///
/// This is what distinguishes a tripwire with teeth from one that is merely loud. `SharedCell` panics
/// on a re-entrant acquisition; if it could not tell "this thread already holds it" from "some thread
/// holds it", this hand-off would abort instead of blocking, and every future multi-writer scenario
/// with it.
///
/// # Panics
/// Panics if the fixture cannot be built.
#[must_use]
pub fn run_contended_handoff() -> HandoffReport {
    let coord = fresh_shared_coordinator();
    let released = Arc::new(AtomicBool::new(false));
    // Observed by B at the moment its acquisition succeeds; compared against `released` afterwards.
    let saw_release_before_acquiring = Arc::new(AtomicBool::new(false));
    let acquisitions = Arc::new(AtomicUsize::new(0));

    let (a_holds_tx, a_holds_rx) = mpsc::channel::<()>();
    let (b_asking_tx, b_asking_rx) = mpsc::channel::<()>();

    let b = {
        let coord = Arc::clone(&coord);
        let released = Arc::clone(&released);
        let saw = Arc::clone(&saw_release_before_acquiring);
        let acquisitions = Arc::clone(&acquisitions);
        std::thread::spawn(move || {
            // Wait until A definitely holds the coordinator, then announce the attempt and make it.
            a_holds_rx
                .recv_timeout(Duration::from_secs(60))
                .expect("A signalled that it holds the coordinator");
            b_asking_tx.send(()).expect("A is still listening");
            // Blocks here for as long as A holds the lock.
            let acquired = write_one(&coord, 1);
            saw.store(released.load(Ordering::SeqCst), Ordering::SeqCst);
            acquisitions.fetch_add(1, Ordering::SeqCst);
            acquired.is_ok()
        })
    };

    {
        let guard = coord
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        a_holds_tx.send(()).expect("B is still listening");
        b_asking_rx
            .recv_timeout(Duration::from_secs(60))
            .expect("B announced its attempt");
        // B is now either blocked on the lock or about to be. Do real work under the lock so the
        // overlap is not instantaneous, then mark the release BEFORE dropping the guard.
        let txn = guard.begin_serializable();
        guard.with_store_mut(|s| {
            let _ = s.create_node(txn);
        });
        guard.commit(txn).expect("A's transaction commits");
        std::thread::sleep(Duration::from_millis(50));
        released.store(true, Ordering::SeqCst);
        drop(guard);
    }

    let second_write_ok = b.join();
    let second_panicked = second_write_ok.is_err();
    let second_write_visible = second_write_ok.unwrap_or(false);

    HandoffReport {
        second_acquired_after_release: saw_release_before_acquiring.load(Ordering::SeqCst)
            && acquisitions.load(Ordering::SeqCst) == 1,
        second_panicked,
        second_write_visible,
    }
}
