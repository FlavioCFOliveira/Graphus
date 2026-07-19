//! Focused deterministic reproducer for **a rolled-back schema-catalog (DDL) change surviving its
//! own rollback** (`rmp` #734) — the catalog twin of the label-word clobber
//! ([`crate::label_rollback_clobber`], `rmp` #772) and the free-list double-allocation
//! ([`crate::freelist_reuse`], `rmp` #578). All three are live-rollback defects reachable only through
//! statement-interleaving the generic [`crate::harness`] never performs.
//!
//! ## The defect
//!
//! Schema-catalog DDL — declared indexes of every kind, their names, constraints, property histograms
//! — is the one class of mutation the WAL does **not** log. It mutates a single shared in-memory
//! `Statistics` and becomes durable only via the commit-time catalog checkpoint. `RecordStore::rollback`
//! therefore cannot undo it by replaying the log; it reloads `Statistics` wholesale from the durable
//! image instead. But that reload would also wipe a *concurrent* open transaction's pending DDL, so
//! `rmp` #534 made the rollback restore the entire pre-rollback in-memory schema whenever any other
//! transaction was open — it had no way to tell whose pending DDL was whose.
//!
//! The consequence was an ACID breach with a **non-deterministic** face: `BEGIN; <catalog DDL>;
//! ROLLBACK` discarded the DDL when the transaction ran alone, and **persisted** it when any unrelated
//! transaction happened to be open at the time. Same statement, same data, two durable outcomes.
//!
//! ## Why it needs the DST, not the generic harness
//!
//! The breach requires two statement-interleaved transactions each holding *different* pending catalog
//! DDL, one of which rolls back while the other stays open — driven at the [`RecordStore`] layer,
//! below the coordinator (whose DDL paths run as yield-free auto-commit transactions). It is fully
//! deterministic: no randomness, no timing.
//!
//! ## The invariants asserted
//!
//! After B rolls back and the store **crashes and recovers**:
//!
//! 1. B's own rolled-back DDL is **not** durable — a rollback whose undo is interrupted by a crash
//!    must not resurrect the DDL it discarded.
//! 2. A's DDL is durable **iff A committed** before the crash — the ordinary atomicity contract, held
//!    across the same rollback that must not disturb it.
//! 3. The seed's committed DDL is untouched throughout.
//!
//! Both crash flavours (no-force and steal) are exercised, and the run is asserted deterministic.

use graphus_core::{PageId, TxnId};
use graphus_io::{BlockDevice, MemBlockDevice};
use graphus_storage::{IndexState, Namespace, RecordStore};
use graphus_wal::{LogSink, MemLogSink, WalManager};

/// The store type the reproducer drives: the record store over the in-memory DST device + log.
type Store = RecordStore<MemBlockDevice, MemLogSink>;

/// A small buffer-pool capacity, so eviction + the WAL rule are exercised during the run.
const POOL_CAPACITY: usize = 16;

/// The index name the seed transaction declares and commits (must always survive).
const SEED_INDEX: &str = "seed_ix";
/// The index name transaction **A** declares and leaves pending (durable iff A commits).
const A_INDEX: &str = "a_ix";
/// The index name transaction **B** declares and then **rolls back** (must never be durable).
const B_INDEX: &str = "b_ix";
/// The one committed histogram value the multi-holder scenario must always recover.
const COMMITTED_HISTOGRAM: &[u8] = &[0xCC];

/// How the run ends before the crash, for transaction **A** — the transaction that holds pending
/// catalog DDL *concurrently* with B's rollback.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AOutcome {
    /// A commits after B's rollback: A's DDL must be durable after recovery.
    Commits,
    /// A is still open when the crash happens: A's DDL must **not** be durable after recovery.
    LeftOpen,
}

/// How the store is crashed before recovery.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Crash {
    /// No-force: rebuild from the durable WAL prefix onto a fresh device.
    NoForce,
    /// Steal: dirty pages (committed and not) are written home first, then recovery undoes them.
    Steal,
}

/// What one reproduction observed in the **recovered** store.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CatalogRollbackReport {
    /// The seed's committed index, after recovery. Must always be `true`.
    pub seed_ddl_durable: bool,
    /// A's index after recovery. Must be `true` exactly when A committed.
    pub a_ddl_durable: bool,
    /// B's **rolled-back** index after recovery. Must always be `false` — this is the #734 defect.
    pub b_ddl_durable: bool,
    /// B's rolled-back index *name* entry after recovery. Must always be `false`; tracked separately
    /// because the name lives in its own catalog map with its own undo entries.
    pub b_name_durable: bool,
    /// Whether A's DDL was still pending in memory immediately after B's rollback — the non-vacuity
    /// witness that the interleaving actually happened and the rollback did not simply wipe
    /// everything (which would make `b_ddl_durable == false` true for the wrong reason).
    pub a_ddl_survived_rollback_in_memory: bool,
}

impl CatalogRollbackReport {
    /// The `rmp` #734 invariant for the given ending: B's rolled-back DDL is gone, A's DDL is durable
    /// exactly when A committed, and the seed is untouched.
    #[must_use]
    pub fn holds(&self, a: AOutcome) -> bool {
        self.seed_ddl_durable
            && !self.b_ddl_durable
            && !self.b_name_durable
            && self.a_ddl_durable == (a == AOutcome::Commits)
    }
}

/// Drives the interleaving to completion and crashes, returning the observation from the recovered
/// store.
///
/// # Panics
///
/// Panics if any store operation fails — every one of them is expected to succeed in this scenario.
#[must_use]
pub fn run_catalog_rollback_undo(a: AOutcome, crash: Crash) -> CatalogRollbackReport {
    let device = MemBlockDevice::new(0);
    let wal = WalManager::create(MemLogSink::new()).expect("create wal");
    let mut store: Store =
        RecordStore::create(device, wal, POOL_CAPACITY, 1).expect("create store");

    // --- seed: tokens + one committed, named index. Committed and flushed, so what follows is
    //     isolated to the catalog ENTRIES (token durability rides its own #220/#172 restore).
    let t0 = TxnId(1);
    store.begin(t0);
    let person = store
        .intern_token(Namespace::Label, "Person")
        .expect("intern label");
    let age = store
        .intern_token(Namespace::PropKey, "age")
        .expect("intern age");
    let name = store
        .intern_token(Namespace::PropKey, "name")
        .expect("intern name");
    let city = store
        .intern_token(Namespace::PropKey, "city")
        .expect("intern city");
    store.set_node_property_index(t0, person, age, IndexState::Online);
    store.set_node_property_index_name(t0, SEED_INDEX.to_owned(), person, age);
    store.commit(t0).expect("seed commits");
    store.flush().expect("flush seed");

    // --- A: declares an index + name and stays OPEN across B's rollback.
    let ta = TxnId(2);
    store.begin(ta);
    store.set_node_property_index(ta, person, name, IndexState::Online);
    store.set_node_property_index_name(ta, A_INDEX.to_owned(), person, name);

    // --- B: declares DIFFERENT DDL, then rolls back while A is still open.
    let tb = TxnId(3);
    store.begin(tb);
    store.set_node_property_index(tb, person, city, IndexState::Online);
    store.set_node_property_index_name(tb, B_INDEX.to_owned(), person, city);
    store.rollback(tb).expect("B rolls back");

    // Non-vacuity: A's pending DDL must still be in memory here. If it is not, the rollback wiped
    // everything and B's absence below would prove nothing.
    let a_ddl_survived_rollback_in_memory = store.node_property_index_state(person, name)
        == Some(IndexState::Online)
        && store.node_property_index_name(A_INDEX) == Some((person, name));

    if a == AOutcome::Commits {
        store.commit(ta).expect("A commits");
    }

    // --- crash + recover.
    store.with_wal(WalManager::flush);
    let recovered = match crash {
        Crash::NoForce => crash_no_force(store),
        Crash::Steal => crash_steal(store),
    };

    CatalogRollbackReport {
        seed_ddl_durable: recovered.node_property_index_state(person, age)
            == Some(IndexState::Online)
            && recovered.node_property_index_name(SEED_INDEX) == Some((person, age)),
        a_ddl_durable: recovered.node_property_index_state(person, name)
            == Some(IndexState::Online),
        b_ddl_durable: recovered.node_property_index_state(person, city).is_some(),
        b_name_durable: recovered.node_property_index_name(B_INDEX).is_some(),
        a_ddl_survived_rollback_in_memory,
    }
}

/// No-force crash: rebuild onto a fresh empty device from the durable WAL prefix, then reopen.
fn crash_no_force(store: Store) -> Store {
    let log = store.with_wal(|w| w.sink().durable_bytes().to_vec());
    let mut sink = MemLogSink::new();
    sink.append(&log);
    sink.sync().expect("sync log prefix");
    let mut device = MemBlockDevice::new(0);
    let mut wal = WalManager::open(sink.clone()).expect("open wal");
    graphus_storage::recovery::recover_device(&mut wal, &mut device).expect("recover");
    let wal = WalManager::open(sink).expect("reopen wal");
    RecordStore::open(device, wal, POOL_CAPACITY).expect("open store")
}

/// Steal crash: flush dirty pages home, snapshot that on-disk image, then recover so undo rolls back
/// any stolen uncommitted pages.
fn crash_steal(mut store: Store) -> Store {
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
    graphus_storage::recovery::recover_device(&mut wal, &mut device).expect("recover");
    let wal = WalManager::open(sink).expect("reopen wal");
    RecordStore::open(device, wal, POOL_CAPACITY).expect("open store")
}

/// How the DDL-holding transaction B ends, in [`run_checkpoint_excludes_pending_ddl`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BEnding {
    /// B is still open when the crash happens — its DDL is in-flight and must not be durable.
    LeftOpen,
    /// B rolls back before the crash — its DDL is discarded and must not be resurrected.
    RollsBack,
}

/// Drives the **checkpoint** half of `rmp` #734: an unrelated transaction commits (running the
/// catalog checkpoint) *while* B holds pending DDL, and only then does B resolve.
///
/// The checkpoint persists the whole catalog, so before #734 it published B's **uncommitted** DDL into
/// the durable image. Two crashes fall out of that, and this scenario covers both:
///
/// * [`BEnding::LeftOpen`] — crash with B still in flight: recovery finds a schema object no
///   transaction ever committed.
/// * [`BEnding::RollsBack`] — B rolls back (its in-memory undo is correct) and the crash lands before
///   anything re-checkpoints: recovery **resurrects the rolled-back DDL** from the stale durable
///   image. This is the ordering in which a rollback's undo is genuinely "interrupted by a crash".
///
/// Returns whether B's DDL was durable after recovery — which must be `false` for both endings.
///
/// # Panics
///
/// Panics if any store operation fails — every one of them is expected to succeed in this scenario.
#[must_use]
pub fn run_checkpoint_excludes_pending_ddl(ending: BEnding, crash: Crash) -> bool {
    let device = MemBlockDevice::new(0);
    let wal = WalManager::create(MemLogSink::new()).expect("create wal");
    let mut store: Store =
        RecordStore::create(device, wal, POOL_CAPACITY, 1).expect("create store");

    let t0 = TxnId(1);
    store.begin(t0);
    let person = store
        .intern_token(Namespace::Label, "Person")
        .expect("intern label");
    let city = store
        .intern_token(Namespace::PropKey, "city")
        .expect("intern city");
    store.commit(t0).expect("seed commits");
    store.flush().expect("flush seed");

    // B declares DDL and stays open.
    let tb = TxnId(2);
    store.begin(tb);
    store.set_node_property_index(tb, person, city, IndexState::Online);
    store.set_node_property_index_name(tb, B_INDEX.to_owned(), person, city);

    // A does unrelated DATA work and commits — this runs the catalog checkpoint while B is open.
    let ta = TxnId(3);
    store.begin(ta);
    let _ = store.create_node(ta).expect("A creates a node");
    store.commit(ta).expect("A commits");

    if ending == BEnding::RollsBack {
        store.rollback(tb).expect("B rolls back");
        assert_eq!(
            store.node_property_index_state(person, city),
            None,
            "non-vacuity: B's rollback must have removed its DDL from memory before the crash"
        );
    }

    store.with_wal(WalManager::flush);
    let recovered = match crash {
        Crash::NoForce => crash_no_force(store),
        Crash::Steal => crash_steal(store),
    };
    recovered.node_property_index_state(person, city).is_some()
        || recovered.node_property_index_name(B_INDEX).is_some()
}

/// Drives **several** concurrent DDL holders over the SAME catalog entry, aborting them in `order`,
/// then crashes and recovers (`rmp` #734).
///
/// The two scenarios above have a single DDL holder each, so their undo chains are one link long and
/// always unwind newest-first. This one builds a real chain and aborts it out of order, which is where
/// the predecessor links matter: an older writer aborting first must be spliced out of the chain, or
/// the writers that abort after it restore ITS value — leaving, after recovery, a catalog entry whose
/// value no transaction ever committed.
///
/// Returns the histogram bytes durable after recovery; must always be the committed seed value.
///
/// # Panics
///
/// Panics if any store operation fails, or if `order` is not a permutation of `0..3`.
#[must_use]
pub fn run_multi_holder_out_of_order_abort(order: [usize; 3], crash: Crash) -> Option<Vec<u8>> {
    let device = MemBlockDevice::new(0);
    let wal = WalManager::create(MemLogSink::new()).expect("create wal");
    let mut store: Store =
        RecordStore::create(device, wal, POOL_CAPACITY, 1).expect("create store");

    let t0 = TxnId(1);
    store.begin(t0);
    let person = store
        .intern_token(Namespace::Label, "Person")
        .expect("intern label");
    let age = store
        .intern_token(Namespace::PropKey, "age")
        .expect("intern age");
    store.set_property_histogram(t0, person, age, COMMITTED_HISTOGRAM.to_vec());
    store.commit(t0).expect("seed commits");
    store.flush().expect("flush seed");

    // Three concurrent writers stack uncommitted values on the one entry.
    let writers = [TxnId(2), TxnId(3), TxnId(4)];
    for (i, &t) in writers.iter().enumerate() {
        store.begin(t);
        store.set_property_histogram(t, person, age, vec![0xA0 + u8::try_from(i).unwrap()]);
    }
    // Abort them in the given order, and commit an unrelated transaction in between so the catalog
    // checkpoint runs against a partially-unwound chain.
    for (step, &i) in order.iter().enumerate() {
        store.rollback(writers[i]).expect("writer rolls back");
        if step == 0 {
            let filler = TxnId(10 + u64::try_from(step).unwrap());
            store.begin(filler);
            let _ = store.create_node(filler).expect("filler creates a node");
            store.commit(filler).expect("filler commits");
        }
    }

    store.with_wal(WalManager::flush);
    let recovered = match crash {
        Crash::NoForce => crash_no_force(store),
        Crash::Steal => crash_steal(store),
    };
    recovered
        .property_histogram(person, age)
        .map(<[u8]>::to_vec)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every abort order of three concurrent DDL holders on one entry must recover the committed
    /// value — never a value only an aborted transaction wrote.
    #[test]
    fn multi_holder_out_of_order_aborts_recover_the_committed_value() {
        for order in [
            [0usize, 1, 2],
            [0, 2, 1],
            [1, 0, 2],
            [1, 2, 0],
            [2, 0, 1],
            [2, 1, 0],
        ] {
            for crash in [Crash::NoForce, Crash::Steal] {
                assert_eq!(
                    run_multi_holder_out_of_order_abort(order, crash),
                    Some(COMMITTED_HISTOGRAM.to_vec()),
                    "{order:?}/{crash:?}: recovery surfaced a value no transaction committed \
                     (rmp #734 chain splice)"
                );
            }
        }
    }

    /// A catalog checkpoint driven by an unrelated commit must not publish an open transaction's
    /// uncommitted DDL — neither while it is still in flight, nor (worse) as a resurrection of DDL it
    /// has since rolled back.
    #[test]
    fn a_checkpoint_never_publishes_another_transactions_pending_ddl() {
        for ending in [BEnding::LeftOpen, BEnding::RollsBack] {
            for crash in [Crash::NoForce, Crash::Steal] {
                assert!(
                    !run_checkpoint_excludes_pending_ddl(ending, crash),
                    "{ending:?}/{crash:?}: an unrelated commit's checkpoint made transaction B's \
                     uncommitted DDL durable (rmp #734)"
                );
            }
        }
    }

    /// The `rmp` #734 crash-recovery invariant, over both endings and both crash flavours.
    #[test]
    fn rolled_back_catalog_ddl_is_not_resurrected_by_recovery() {
        for a in [AOutcome::Commits, AOutcome::LeftOpen] {
            for crash in [Crash::NoForce, Crash::Steal] {
                let report = run_catalog_rollback_undo(a, crash);
                // Non-vacuity first: if A's pending DDL did not survive B's rollback in memory, the
                // interleaving never happened and B's absence proves nothing.
                assert!(
                    report.a_ddl_survived_rollback_in_memory,
                    "{a:?}/{crash:?}: A's pending DDL did not survive B's rollback — the \
                     reproduction never reached the interleaving: {report:?}"
                );
                assert!(
                    report.holds(a),
                    "{a:?}/{crash:?}: catalog rollback/recovery invariant violated (rmp #734): \
                     {report:?}"
                );
            }
        }
    }

    #[test]
    fn reproduction_is_deterministic() {
        for a in [AOutcome::Commits, AOutcome::LeftOpen] {
            for crash in [Crash::NoForce, Crash::Steal] {
                assert_eq!(
                    run_catalog_rollback_undo(a, crash),
                    run_catalog_rollback_undo(a, crash),
                    "{a:?}/{crash:?}: reproduction is not deterministic"
                );
            }
        }
    }
}
