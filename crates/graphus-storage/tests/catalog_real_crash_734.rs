//! A **genuine** crash + ARIES-replay cycle over the per-transaction catalog undo (`rmp` #734).
//!
//! Every other crash test in this repository — including the `graphus-dst` scenarios — *models* the
//! crash: it reconstructs the durable WAL prefix and reopens over a staged device image, in-process.
//! That models steal / no-force faithfully, but it is still the same process, and the durable state it
//! asserts is one the test itself assembled.
//!
//! This test does not model anything. It re-executes its own binary as a **child process** that opens
//! a real file-backed store (`FileBlockDevice` + `FileLogSink`, real `fsync`), performs the catalog
//! interleaving, and then calls [`std::process::abort`] — SIGABRT, no unwinding, no destructors, no
//! `Drop`, no flush, nothing written home that was not already forced. The parent then opens whatever
//! is actually on disk and runs real ARIES recovery over it.
//!
//! What it pins is the riskiest part of the #734 change: the catalog checkpoint now persists a
//! COMPUTED image (the committed one) rather than the live `Statistics`. If that computation were
//! wrong, ordinary committed DDL would stop surviving a real crash — so the committed half is asserted
//! just as hard as the rolled-back half.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

use graphus_core::TxnId;
use graphus_io::{FileBlockDevice, MemBlockDevice};
use graphus_storage::recovery::recover_device;
use graphus_storage::{IndexState, Namespace, RecordStore};
use graphus_wal::{FileLogSink, LogSink, MemLogSink, WalManager};

/// Env var carrying the scratch directory to the crashing child.
const CHILD_DIR: &str = "GRAPHUS_734_CRASH_DIR";

const POOL_PAGES: usize = 64;
/// Committed before the crash — must always survive.
const COMMITTED_INDEX: &str = "committed_ix";
/// Declared by a transaction that ROLLS BACK before the crash — must never survive.
const ROLLED_BACK_INDEX: &str = "rolled_back_ix";
/// Declared by a transaction still OPEN at the crash — must never survive.
const IN_FLIGHT_INDEX: &str = "in_flight_ix";

type FileStore = RecordStore<FileBlockDevice, FileLogSink>;

/// A unique scratch directory for one run (no collisions across tests / processes / hosts).
/// Follows the existing `tests/backup.rs` convention rather than pulling in a `tempfile`
/// dev-dependency, which this crate deliberately does without.
fn unique_dir(tag: &str) -> PathBuf {
    static N: AtomicU64 = AtomicU64::new(0);
    let n = N.fetch_add(1, Ordering::Relaxed);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    std::env::temp_dir().join(format!(
        "graphus-734-crash-{tag}-{}-{nanos}-{n}",
        std::process::id()
    ))
}

/// `SIGABRT`. Spelled out rather than pulled from a `libc` dev-dependency this crate does without;
/// the value is fixed by POSIX for every platform Graphus targets.
#[cfg(unix)]
const fn libc_sigabrt() -> i32 {
    6
}

fn device_path(dir: &Path) -> PathBuf {
    dir.join("graph.store")
}
fn wal_path(dir: &Path) -> PathBuf {
    dir.join("graph.wal")
}

/// Creates a fresh file-backed store in `dir`.
fn create_file_store(dir: &Path) -> FileStore {
    let device = FileBlockDevice::open(device_path(dir)).expect("open device");
    let wal = WalManager::create(FileLogSink::open(wal_path(dir)).expect("open wal sink"))
        .expect("create wal");
    RecordStore::create(device, wal, POOL_PAGES, 1).expect("create store")
}

/// Opens the store in `dir`, running real ARIES recovery over whatever survived the crash.
fn recover_file_store(dir: &Path) -> FileStore {
    let mut device = FileBlockDevice::open(device_path(dir)).expect("open device");
    let mut wal = WalManager::open(FileLogSink::open(wal_path(dir)).expect("open wal sink"))
        .expect("open wal");
    recover_device(&mut wal, &mut device).expect("ARIES recovery");
    let wal = WalManager::open(FileLogSink::open(wal_path(dir)).expect("reopen wal sink"))
        .expect("reopen wal");
    RecordStore::open(device, wal, POOL_PAGES).expect("open recovered store")
}

/// The child half: build the catalog state, then die hard.
///
/// Runs only when [`CHILD_DIR`] is set, so under a normal `cargo test` this is inert.
fn run_child_and_abort(dir: &Path) -> ! {
    let mut s = create_file_store(dir);

    // --- committed baseline DDL ------------------------------------------------------------------
    let t0 = TxnId(1);
    s.begin(t0);
    let person = s.intern_token(Namespace::Label, "Person").expect("label");
    let age = s.intern_token(Namespace::PropKey, "age").expect("age");
    let name = s.intern_token(Namespace::PropKey, "name").expect("name");
    let city = s.intern_token(Namespace::PropKey, "city").expect("city");
    s.set_node_property_index(t0, person, age, IndexState::Online);
    s.set_node_property_index_name(t0, COMMITTED_INDEX.to_owned(), person, age);
    s.commit(t0).expect("commit baseline");

    // --- an IN-FLIGHT DDL transaction that is never resolved --------------------------------------
    let in_flight = TxnId(2);
    s.begin(in_flight);
    s.set_node_property_index(in_flight, person, name, IndexState::Online);
    s.set_node_property_index_name(in_flight, IN_FLIGHT_INDEX.to_owned(), person, name);

    // --- a DDL transaction that ROLLS BACK while the in-flight one is open ------------------------
    let doomed = TxnId(3);
    s.begin(doomed);
    s.set_node_property_index(doomed, person, city, IndexState::Online);
    s.set_node_property_index_name(doomed, ROLLED_BACK_INDEX.to_owned(), person, city);
    s.rollback(doomed).expect("rollback doomed");

    // --- an unrelated commit, which runs the catalog checkpoint while `in_flight` is still open ----
    // This is what forces the checkpoint to decide what "committed" means, with pending DDL live.
    let filler = TxnId(4);
    s.begin(filler);
    let _ = s.create_node(filler).expect("filler node");
    s.commit(filler).expect("commit filler");

    // Die. No unwinding, no destructors, no flush — whatever is on disk is all there is.
    std::process::abort();
}

/// A genuine SIGABRT + ARIES replay: committed DDL survives; rolled-back and in-flight DDL do not.
#[test]
fn catalog_ddl_survives_a_real_process_crash_exactly_when_committed() {
    if let Ok(dir) = std::env::var(CHILD_DIR) {
        run_child_and_abort(Path::new(&dir));
    }

    let dir = unique_dir("real");
    std::fs::create_dir_all(&dir).expect("create scratch dir");
    let exe = std::env::current_exe().expect("current exe");
    let status = Command::new(exe)
        .arg("catalog_ddl_survives_a_real_process_crash_exactly_when_committed")
        .arg("--exact")
        .arg("--nocapture")
        .env(CHILD_DIR, &dir)
        .status()
        .expect("spawn crashing child");

    // Non-vacuity: the child must have died from the ABORT specifically. `!success()` alone is too
    // weak — a child that panicked in setup also exits non-zero, and would leave a store that was
    // never crashed at the point this test means to crash it.
    assert!(
        !status.success(),
        "child exited cleanly ({status:?}) — it never reached the abort, so no crash was exercised"
    );
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        assert_eq!(
            status.signal(),
            Some(libc_sigabrt()),
            "child did not die from SIGABRT ({status:?}) — it failed before reaching the abort, so \
             the crash under test never happened"
        );
    }
    assert!(
        device_path(&dir).exists() && wal_path(&dir).exists(),
        "child produced no store on disk — nothing was crashed"
    );

    // --- recover from what genuinely survived ------------------------------------------------------
    let r = recover_file_store(&dir);

    let person = r
        .token_id(Namespace::Label, "Person")
        .expect("the committed label token must have survived");
    let age = r
        .token_id(Namespace::PropKey, "age")
        .expect("the committed property token must have survived");

    assert_eq!(
        r.node_property_index_state(person, age),
        Some(IndexState::Online),
        "committed DDL was LOST across a real crash"
    );
    assert_eq!(
        r.node_property_index_name(COMMITTED_INDEX),
        Some((person, age)),
        "the committed index NAME was lost across a real crash"
    );
    assert_eq!(
        r.node_property_index_name(ROLLED_BACK_INDEX),
        None,
        "a rolled-back index was RESURRECTED by real crash recovery (rmp #734)"
    );
    assert_eq!(
        r.node_property_index_name(IN_FLIGHT_INDEX),
        None,
        "an in-flight (never-committed) index became durable across a real crash (rmp #734)"
    );

    // The recovered catalog must also be internally consistent: every recorded name resolves to a
    // declared index. A half-published catalog is the failure mode that stops a store reopening at all.
    for (nm, l, p) in r.node_property_index_names() {
        assert!(
            r.node_property_index_state(l, p).is_some(),
            "recovered index name {nm:?} points at no declared index"
        );
    }

    drop(r);
    let _ = std::fs::remove_dir_all(&dir);
}

/// Guards the guard: proves the in-process `MemBlockDevice` reopen used by the other #734 tests agrees
/// with the real on-disk crash above, so those cheaper tests can be trusted to mean what they claim.
#[test]
fn the_modelled_reopen_agrees_with_the_real_crash_on_the_same_interleaving() {
    let device = MemBlockDevice::new(0);
    let wal = WalManager::create(MemLogSink::new()).expect("create wal");
    let mut s = RecordStore::create(device, wal, POOL_PAGES, 1).expect("create store");

    let t0 = TxnId(1);
    s.begin(t0);
    let person = s.intern_token(Namespace::Label, "Person").unwrap();
    let age = s.intern_token(Namespace::PropKey, "age").unwrap();
    let name = s.intern_token(Namespace::PropKey, "name").unwrap();
    let city = s.intern_token(Namespace::PropKey, "city").unwrap();
    s.set_node_property_index(t0, person, age, IndexState::Online);
    s.set_node_property_index_name(t0, COMMITTED_INDEX.to_owned(), person, age);
    s.commit(t0).unwrap();

    let in_flight = TxnId(2);
    s.begin(in_flight);
    s.set_node_property_index(in_flight, person, name, IndexState::Online);
    s.set_node_property_index_name(in_flight, IN_FLIGHT_INDEX.to_owned(), person, name);

    let doomed = TxnId(3);
    s.begin(doomed);
    s.set_node_property_index(doomed, person, city, IndexState::Online);
    s.set_node_property_index_name(doomed, ROLLED_BACK_INDEX.to_owned(), person, city);
    s.rollback(doomed).unwrap();

    let filler = TxnId(4);
    s.begin(filler);
    let _ = s.create_node(filler).unwrap();
    s.commit(filler).unwrap();

    // Rebuild from the durable WAL prefix — the modelled no-force crash the other tests use.
    let log = s.with_wal(|w| w.sink().durable_bytes().to_vec());
    let mut sink = MemLogSink::new();
    sink.append(&log);
    sink.sync().expect("sync prefix");
    let mut device = MemBlockDevice::new(0);
    let mut wal = WalManager::open(sink.clone()).expect("open wal");
    recover_device(&mut wal, &mut device).expect("recover");
    let wal = WalManager::open(sink).expect("reopen wal");
    let r = RecordStore::open(device, wal, POOL_PAGES).expect("open recovered");

    assert_eq!(
        r.node_property_index_state(person, age),
        Some(IndexState::Online),
        "committed DDL lost in the modelled crash"
    );
    assert_eq!(r.node_property_index_name(ROLLED_BACK_INDEX), None);
    assert_eq!(r.node_property_index_name(IN_FLIGHT_INDEX), None);
}
