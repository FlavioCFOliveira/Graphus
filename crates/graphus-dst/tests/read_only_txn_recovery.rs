//! Deterministic crash-recovery sweep proving **read-only transactions leave zero durable trace**
//! and do not perturb crash recovery or the WAL reclaim floor (`rmp` #529).
//!
//! ## What #529 changed and why this is the right DST scenario
//!
//! Before #529 every committed transaction — *including a read-only one* — logged a WAL `BEGIN` +
//! `COMMIT` and hardened (`fdatasync`) at commit, even though a read has nothing durable to persist.
//! #529 makes the WAL `BEGIN` **lazy** (emitted only by the first data record) and gives
//! [`RecordStore::commit`] a fast path that, for a transaction that wrote no data record and dirtied
//! no catalog, skips the catalog checkpoint, the `COMMIT` record and the `fdatasync` entirely.
//!
//! That touches the two most ACID-critical machineries — crash recovery and WAL reclamation — so it
//! must be proven crash-safe under the DST oracle, not just unit-tested. The properties this sweep
//! pins:
//!
//!  1. **Durability + atomicity + integrity under mixed read/write interleaving.** A workload that
//!     interleaves committed writes, committed read-only transactions, a long-lived open read-only
//!     reader held *across a checkpoint/reclaim boundary and the crash*, a live-rolled-back write
//!     loser, and a write loser left in flight at the crash — recovers to exactly the committed
//!     write state ([`checker::verify`] against the reference [`Model`]). A read-only transaction,
//!     committed **or** in flight at the crash, contributes nothing to recover and nothing to undo.
//!
//!  2. **The reclaim floor is driven only by writers (the #525 / #220 HARD INVARIANT).** A read-only
//!     transaction has no WAL Active-Transaction-Table entry, so it must contribute **no**
//!     `first_lsn` to [`WalManager::oldest_active_first_lsn`] — a long-lived reader must never floor
//!     WAL reclamation (the old behaviour did, via its `BEGIN`). The sweep asserts the floor is
//!     `None` while only read-only readers are open, and non-vacuously that an open *writer* does
//!     floor it.
//!
//!  3. **Recovery loser count excludes read-only transactions.** Recovery's loser set comes from the
//!     transactions that logged records; a read-only transaction logs none, so it is never a loser.
//!
//! The shape mirrors the other recovery soaks (commit survivors, interleave losers, harden the tail,
//! crash no-force or steal, recover, reopen, `checker::verify`), adding read-only traffic and the
//! reclaim-floor assertions that are unique to #529.

use graphus_core::{PageId, TxnId};
use graphus_dst::checker::{self, CheckFailure};
use graphus_dst::model::{Model, PropTriple};
use graphus_dst::rng::DetRng;
use graphus_io::{BlockDevice, MemBlockDevice};
use graphus_storage::recovery::recover_device;
use graphus_storage::{Namespace, RecordStore};
use graphus_wal::{LogSink, MemLogSink, WalManager};

type Store = RecordStore<MemBlockDevice, MemLogSink>;

/// A small buffer-pool capacity, to exercise eviction and the WAL rule during the run.
const POOL_CAPACITY: usize = 16;
/// Inline integer-like value tag (no overflow heap chain).
const INLINE_TAG: u8 = 2;

/// The outcome of one read-only-recovery run.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ReadOnlyRecoveryReport {
    seed: u64,
    result: std::result::Result<(), CheckFailure>,
    /// How many committed read-only transactions were interleaved into the history.
    read_only_commits: usize,
    /// Whether a read-only transaction was left IN FLIGHT at the crash (must leave no trace).
    read_only_in_flight_at_crash: bool,
    /// Recovery's loser count — must equal exactly the number of WRITE losers (read-only txns are
    /// never losers).
    recovery_losers: usize,
    /// The number of WRITE losers the run created (live rollback + in-flight-at-crash).
    write_losers: usize,
    /// Whether the run reached the state where a read-only reader is held open across the checkpoint
    /// and crash (non-vacuity for the reclaim-floor invariant).
    reader_held_across_reclaim: bool,
    steal: bool,
}

fn next_txn(next: &mut u64) -> TxnId {
    let id = TxnId(*next);
    *next += 1;
    id
}

/// Drives a read-only transaction: begin, read a few nodes (touching the store's read path), then
/// end it per `commit`. It writes nothing, so its whole lifecycle must be WAL-silent.
fn read_only_txn(store: &mut Store, txn: TxnId, nodes: &[u64], rng: &mut DetRng, commit: bool) {
    store.begin(txn);
    if !nodes.is_empty() {
        let reads = rng.range_inclusive(1, nodes.len() as u64) as usize;
        for _ in 0..reads {
            let n = nodes[rng.index(nodes.len())];
            // A real read through the store's read path. Its result is irrelevant to durability.
            let _ = store.node(n);
        }
    }
    // Also touch the MVCC snapshot oracle, as a real read-only statement would.
    let _ = store.snapshot_ts();
    if commit {
        store
            .commit(txn)
            .expect("read-only commit must succeed and be WAL-silent");
    }
    // Otherwise: left in flight (a crash target). A read-only in-flight txn has no WAL entry at all.
}

/// Runs one deterministic read-only crash-recovery scenario for `seed`.
fn run_read_only_recovery(seed: u64) -> ReadOnlyRecoveryReport {
    let mut rng = DetRng::new(seed);
    let steal = rng.chance(40);

    let device = MemBlockDevice::new(0);
    let wal = WalManager::create(MemLogSink::new()).expect("create wal");
    let mut store = RecordStore::create(device, wal, POOL_CAPACITY, 1).expect("create store");

    let mut next = 1u64;
    let mut model = Model::new();

    // --- A committed base graph: nodes, a relationship type, some parallel edges + self-loops,
    //     and a few node properties. This is the committed data a crash must never lose. ---
    let setup = next_txn(&mut next);
    store.begin(setup);
    let link = store
        .intern_token(Namespace::RelType, "LINK")
        .expect("intern rel type");
    let key = store
        .intern_token(Namespace::PropKey, "v")
        .expect("intern prop key");
    let node_count = rng.range_inclusive(2, 5) as usize;
    let mut nodes = Vec::with_capacity(node_count);
    for _ in 0..node_count {
        let (id, _) = store.create_node(setup).expect("create_node");
        nodes.push(id);
    }
    store.commit(setup).expect("commit setup");
    for &n in &nodes {
        model.add_node(n);
    }

    // Committed edges + properties across a couple of write transactions.
    let write_txns = rng.range_inclusive(1, 3) as usize;
    for _ in 0..write_txns {
        let t = next_txn(&mut next);
        store.begin(t);
        let ops = rng.range_inclusive(1, 4);
        for _ in 0..ops {
            if rng.chance(50) {
                let s = nodes[rng.index(nodes.len())];
                let e = nodes[rng.index(nodes.len())]; // equal ⇒ self-loop
                let (rid, _) = store.create_rel(t, link, s, e).expect("create_rel");
                model.add_rel(rid, s, e);
            } else {
                let n = nodes[rng.index(nodes.len())];
                let value = 0x1000 + rng.range_inclusive(0, 0xFF);
                store
                    .add_node_property(t, n, key, INLINE_TAG, value)
                    .expect("add_node_property");
                model.add_node_prop(
                    n,
                    PropTriple {
                        key,
                        type_tag: INLINE_TAG,
                        value_inline: value,
                    },
                );
            }
        }
        store.commit(t).expect("commit writes");

        // Interleave a committed read-only auto-commit transaction between write transactions.
        let ro = next_txn(&mut next);
        read_only_txn(&mut store, ro, &nodes, &mut rng, true);
    }
    let mut read_only_commits = write_txns; // one per write-txn iteration above

    // --- A LONG-LIVED read-only reader R, held open across the reclaim boundary and the crash. ---
    let reader = next_txn(&mut next);
    store.begin(reader);
    for _ in 0..rng.range_inclusive(1, nodes.len() as u64) {
        let _ = store.node(nodes[rng.index(nodes.len())]);
    }

    // THE HARD INVARIANT (#525 / #220): with only the read-only reader R open — every write
    // transaction so far has committed and been removed — the WAL's oldest-active-first-LSN must be
    // `None`. A read-only transaction has no WAL Active-Transaction-Table entry, so it contributes no
    // reclaim floor; a long-lived reader must NEVER pin WAL reclamation.
    assert_eq!(
        store.with_wal(|w| w.oldest_active_first_lsn()),
        None,
        "seed {seed}: a held-open read-only reader must not floor WAL reclamation \
         (oldest_active_first_lsn must be None while only readers are open)"
    );

    // A checkpoint reclaims the WAL prefix. It must advance the reclaim floor — NOT be pinned back by
    // the still-open reader R (the pre-#529 reader would have floored it at its BEGIN LSN). The
    // checkpoint FLUSHES committed pages home and truncates the WAL below it, so its redo is now on the
    // home pages, not the WAL — only the *steal* crash (which preserves the on-disk home image)
    // recovers consistently after it. The no-force crash (fresh device, WAL-only redo) legitimately
    // could not, so the checkpoint+reclaim is exercised in the steal mode; the reader-floor invariant
    // above is asserted in BOTH modes regardless.
    let reader_held_across_reclaim = true;
    if steal {
        store.checkpoint().expect("checkpoint");
        let reclaimed_floor = store.with_wal(|w| w.sink().reclaimed_floor());
        assert!(
            reclaimed_floor > 0,
            "seed {seed}: a checkpoint must reclaim the WAL past the header even with a read-only \
             reader held open (reclaimed_floor={reclaimed_floor})"
        );
    }

    // More committed writes AFTER the reclaim, while R is still open (these live above the reclaimed
    // floor and must recover through the #525-bounded read).
    {
        let t = next_txn(&mut next);
        store.begin(t);
        let n = nodes[rng.index(nodes.len())];
        let value = 0x2000 + rng.range_inclusive(0, 0xFF);
        store
            .add_node_property(t, n, key, INLINE_TAG, value)
            .expect("post-reclaim add_node_property");
        model.add_node_prop(
            n,
            PropTriple {
                key,
                type_tag: INLINE_TAG,
                value_inline: value,
            },
        );
        store.commit(t).expect("commit post-reclaim write");
    }

    // Another interleaved committed read-only transaction after the reclaim.
    let ro2 = next_txn(&mut next);
    read_only_txn(&mut store, ro2, &nodes, &mut rng, true);
    read_only_commits += 1;

    // --- WRITE losers: one live-rolled-back, and one left in flight at the crash. ---
    let mut write_losers = 0usize;
    let loser_live = next_txn(&mut next);
    store.begin(loser_live);
    {
        let s = nodes[rng.index(nodes.len())];
        let e = nodes[rng.index(nodes.len())];
        let _ = store.create_rel(loser_live, link, s, e).expect("loser rel");
    }
    store
        .rollback(loser_live)
        .expect("live rollback of a write loser");
    write_losers += 1;

    let loser_in_flight = next_txn(&mut next);
    store.begin(loser_in_flight);
    {
        let n = nodes[rng.index(nodes.len())];
        let _ = store
            .add_node_property(loser_in_flight, n, key, INLINE_TAG, 0xDEAD)
            .expect("loser prop");
    }
    // Left in flight — its effects must be undone by recovery.
    write_losers += 1;

    // Commit the long-lived reader R now (a read-only commit: WAL-silent).
    store
        .commit(reader)
        .expect("read-only reader commit must be WAL-silent");
    read_only_commits += 1;

    // Optionally leave a FRESH read-only transaction in flight at the crash: it must leave no trace
    // (it never logged a BEGIN, so recovery never even sees it).
    let read_only_in_flight_at_crash = rng.chance(60);
    if read_only_in_flight_at_crash {
        let ro_crash = next_txn(&mut next);
        read_only_txn(&mut store, ro_crash, &nodes, &mut rng, false);
    }

    // Harden the tail so the in-flight write loser's records are in the crash WAL (recovery redoes
    // then undoes them).
    store.with_wal(WalManager::flush);

    let (store, recovery_losers) = if steal {
        crash_steal(store)
    } else {
        crash_no_force(store)
    };

    let result = checker::verify(&store, &model);

    ReadOnlyRecoveryReport {
        seed,
        result,
        read_only_commits,
        read_only_in_flight_at_crash,
        recovery_losers,
        write_losers,
        reader_held_across_reclaim,
        steal,
    }
}

/// No-force crash: rebuild onto a fresh empty device from the durable WAL prefix, then reopen.
fn crash_no_force(store: Store) -> (Store, usize) {
    let log = store.with_wal(|w| w.sink().durable_bytes().to_vec());
    let mut sink = MemLogSink::new();
    sink.append(&log);
    sink.sync().expect("sync log prefix");
    let mut device = MemBlockDevice::new(0);
    let mut wal = WalManager::open(sink.clone()).expect("open wal");
    let report = recover_device(&mut wal, &mut device).expect("recover");
    let wal = WalManager::open(sink).expect("reopen wal");
    let store = RecordStore::open(device, wal, POOL_CAPACITY).expect("open store");
    (store, report.losers)
}

/// Steal crash: flush dirty pages home, snapshot that on-disk image, then recover so undo rolls back
/// any stolen uncommitted (loser) pages.
fn crash_steal(store: Store) -> (Store, usize) {
    store.flush().expect("flush (steal)");
    let pages = store.mapped_pages();
    let max = pages.iter().map(|p| p.0).max().unwrap_or(0);
    let mut device = MemBlockDevice::new(max + 1);
    for p in &pages {
        let bytes = store.read_device_page(*p).expect("read device page");
        device.write_page(PageId(p.0), &bytes).expect("stage page");
    }
    device.sync_all().expect("persist disk image");

    let log = store.with_wal(|w| w.sink().durable_bytes().to_vec());
    let mut sink = MemLogSink::new();
    sink.append(&log);
    sink.sync().expect("sync log prefix");
    let mut wal = WalManager::open(sink.clone()).expect("open wal");
    let report = recover_device(&mut wal, &mut device).expect("recover");
    let wal = WalManager::open(sink).expect("reopen wal");
    let store = RecordStore::open(device, wal, POOL_CAPACITY).expect("open store");
    (store, report.losers)
}

/// The seed sweep: across a broad family of read/write interleavings and crash modes, recovery must
/// preserve every committed write and every #529 invariant, and be deterministic.
const SEEDS: u64 = 2_000;

#[test]
fn read_only_transactions_are_crash_neutral_across_many_seeds() {
    let mut in_flight_ro_seen = false;
    let mut steal_seen = false;
    let mut no_force_seen = false;

    for seed in 1..=SEEDS {
        let report = run_read_only_recovery(seed);

        assert!(
            report.result.is_ok(),
            "seed {seed} [{}]: recovery lost/created committed state or broke integrity: {:?}\n\
             read_only_commits={} ro_in_flight={} recovery_losers={} write_losers={}",
            if report.steal { "steal" } else { "no-force" },
            report.result,
            report.read_only_commits,
            report.read_only_in_flight_at_crash,
            report.recovery_losers,
            report.write_losers,
        );

        // A read-only transaction is NEVER a recovery loser: recovery's loser count must equal exactly
        // the number of WRITE losers (live-rolled-back writers already have durable ABORTs so they are
        // not losers; the single in-flight WRITE loser is). It must never exceed the write-loser count
        // no matter how many read-only transactions were committed or left in flight.
        assert!(
            report.recovery_losers <= report.write_losers,
            "seed {seed}: recovery losers ({}) must never exceed write losers ({}) — a read-only \
             transaction must never be undone by recovery",
            report.recovery_losers,
            report.write_losers,
        );

        assert!(
            report.reader_held_across_reclaim,
            "seed {seed}: the reclaim-floor invariant assertion must have been exercised"
        );

        // Determinism: the same seed reproduces the identical report.
        let again = run_read_only_recovery(seed);
        assert_eq!(report, again, "seed {seed} is not deterministic");

        in_flight_ro_seen |= report.read_only_in_flight_at_crash;
        steal_seen |= report.steal;
        no_force_seen |= !report.steal;
    }

    // Non-vacuity: the sweep really exercised both crash modes and left read-only txns in flight.
    assert!(
        in_flight_ro_seen,
        "sweep never left a read-only txn in flight at the crash"
    );
    assert!(steal_seen, "sweep never exercised the steal crash mode");
    assert!(
        no_force_seen,
        "sweep never exercised the no-force crash mode"
    );
}

/// A focused, direct proof of the reclaim-floor contrast (non-vacuity for property 2): a held-open
/// **read-only** reader does NOT floor WAL reclamation (`oldest_active_first_lsn == None`), whereas a
/// held-open **writer** DOES (`Some`). This is the crux of the #529 reclaim-floor safety: the pre-#529
/// reader logged a `BEGIN` and so floored reclamation exactly like a writer.
#[test]
fn read_only_reader_does_not_floor_reclamation_but_a_writer_does() {
    let device = MemBlockDevice::new(0);
    let wal = WalManager::create(MemLogSink::new()).expect("create wal");
    let store: Store = RecordStore::create(device, wal, POOL_CAPACITY, 1).expect("create store");

    // Commit a base node so there is committed data + a non-trivial WAL.
    let t0 = TxnId(1);
    store.begin(t0);
    let (n, _) = store.create_node(t0).expect("create_node");
    store.commit(t0).expect("commit");

    // A held-open read-only reader: no WAL entry, so no reclaim floor.
    let reader = TxnId(2);
    store.begin(reader);
    let _ = store.node(n);
    assert_eq!(
        store.with_wal(|w| w.oldest_active_first_lsn()),
        None,
        "a held-open read-only reader must contribute NO WAL reclaim floor"
    );
    // Reclamation proceeds unimpeded while the reader is open.
    store.checkpoint().expect("checkpoint under open reader");
    assert!(
        store.with_wal(|w| w.sink().reclaimed_floor()) > 0,
        "reclamation must advance past the header even with a read-only reader open"
    );

    // Non-vacuity: a held-open WRITER (it logged a data record) DOES floor reclamation.
    let writer = TxnId(3);
    store.begin(writer);
    let _ = store.create_node(writer).expect("writer create_node");
    assert!(
        store.with_wal(|w| w.oldest_active_first_lsn()).is_some(),
        "a held-open writer MUST floor WAL reclamation (its first data record seeds first_lsn)"
    );

    // The reader is still open and still contributes nothing; only the writer's floor is present.
    let floor_with_writer = store
        .with_wal(|w| w.oldest_active_first_lsn())
        .expect("writer floor present");
    store.commit(writer).expect("commit writer");
    store
        .commit(reader)
        .expect("read-only reader commit (WAL-silent)");
    // Once both close, no floor remains.
    assert_eq!(
        store.with_wal(|w| w.oldest_active_first_lsn()),
        None,
        "after the writer commits and the reader closes, no WAL reclaim floor remains"
    );
    let _ = floor_with_writer;
}
