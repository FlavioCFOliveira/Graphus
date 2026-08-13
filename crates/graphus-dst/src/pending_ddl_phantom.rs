//! Focused deterministic reproducer for **a committing transaction's uncommitted schema DDL riding
//! its own catalogue image and surviving when it never commits** (`rmp` #1083) — the schema twin of
//! the counter defect [`crate::count_txn_undo`] closed for the cardinalities (`rmp` #1067), and the
//! residual `rmp` #1063 named when it made that image redo-only.
//!
//! ## The defect
//!
//! A schema DDL change — an index or constraint declaration, a histogram — logs no data record. Its
//! only route to disk is the catalogue image `RecordStore::checkpoint_meta` writes at commit, and
//! that checkpoint runs **before** the `COMMIT` record. So `committed_statistics` had to keep the
//! *committing* transaction's DDL in the image it built (it strips every other open transaction's),
//! and an image written by a transaction that then never committed left that transaction's DDL
//! durable.
//!
//! ```text
//!   L: checkpoint_meta -> Update(META, redo = committed catalogue + L's DDL)   ... and no COMMIT
//!   crash
//!   recovery: redo the image; L is a loser, and since `rmp` #1063 the image is REDO-ONLY,
//!             so nothing takes it back  =>  the page holds L's DDL
//! ```
//!
//! Half of the exposure was pre-existing and half was #1063's own regression, and the split matters:
//! a transaction that owns a commit slot already took `rollback_logical`, which reverts no bytes, so
//! its image already stayed on the page. A **DDL-only** transaction creates no delta and owns no
//! slot, so before #1063 it took `rollback_physical`, whose `compensate_one` did revert this page.
//! For that class the live-rollback exposure was new.
//!
//! A phantom index is a wrong plan. A phantom `UNIQUE` constraint is worse than that: it **rejects
//! writes that must be admitted**, which is a correctness violation and not a cosmetic one. That is
//! why the oracle here is a constraint.
//!
//! ## The fix this pins
//!
//! `rmp` #1067's treatment, applied to the schema half. The durable catalogue carries only COMMITTED
//! schema, and the committing transaction's own contribution reaches disk **attributed to it**, in
//! the catalogue's pending-DDL block (`graphus_storage::PendingSchema`, format version 5). `open`
//! applies that block iff recovery found that transaction's `COMMIT` record, and drops it otherwise.
//!
//! ## Why it needs the DST, not the generic harness
//!
//! Both endings are states no ordinary API call reaches:
//!
//! * **[`Ending::CrashedMidCommit`]** is a crash between `checkpoint_meta` and the `COMMIT` record.
//!   It cannot be staged by tearing the log tail — the loser's `COMMIT` record would then sit
//!   *before* a later committer's and no durable prefix could hold the one without the other — so the
//!   transaction is stopped where a crash would stop it, through
//!   `RecordStore::checkpoint_meta_for_test`, which runs the production `checkpoint_meta` at the
//!   exact point `commit_prepare_at` calls it.
//! * **[`Ending::RolledBack`]** is that same image followed by a live rollback, then a crash before
//!   any further catalogue write. The rollback corrects memory and sets `catalog_dirty`, so the
//!   window is bounded — what remains is a crash inside it.
//!
//! Both crash flavours (no-force and steal) are exercised. The run is deterministic by construction:
//! no randomness, no timing, no scheduler.
//!
//! ## The oracle, and why the committed case is asserted from the same code path
//!
//! [`Ending::Committed`] runs the identical workload and lets the transaction commit. Its DDL MUST be
//! there after recovery. Without that half, "the phantom is gone" would be satisfied by a build that
//! simply never persists DDL at all — which is the same class of vacuity that made
//! `rmp` #1063's own report insist the winner and the loser come out of one code path.

use graphus_bufpool::page;
use graphus_core::{PageId, TxnId};
use graphus_io::{BlockDevice, MemBlockDevice};
use graphus_storage::{ConstraintEntry, ConstraintKind, Meta, Namespace, RecordStore};
use graphus_wal::{LogSink, MemLogSink, WalManager};

/// The store type the reproducer drives: the record store over the in-memory DST device + log.
type Store = RecordStore<MemBlockDevice, MemLogSink>;

/// A small buffer-pool capacity, so eviction + the WAL rule are exercised during the run.
const POOL_CAPACITY: usize = 16;

/// The label the seed interns and every constraint covers.
const SEED_LABEL: &str = "Person";
/// The property key every constraint covers.
const SEED_KEY: &str = "email";
/// The constraint the seed transaction declares and commits. It must survive every ending: it is the
/// witness that the fix did not buy "no phantom" by dropping the catalogue wholesale.
const SEED_CONSTRAINT: &str = "seed_unique";
/// The constraint the transaction under test declares. Durable **iff** that transaction commits.
const SUBJECT_CONSTRAINT: &str = "subject_unique";
/// The constraint an open BYSTANDER declares and never commits. It must never be durable, and it must
/// never appear in the pending-DDL block either — only ONE transaction can be pending in an image.
const BYSTANDER_CONSTRAINT: &str = "bystander_unique";

/// How the transaction that wrote the catalogue image ends before the crash.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ending {
    /// Its commit-time catalogue checkpoint ran and then the store died: no `COMMIT` record, no
    /// rollback. The state a power loss between `checkpoint_meta` and `commit_at_no_sync` leaves.
    CrashedMidCommit,
    /// Its catalogue checkpoint ran, then it rolled back, then the store died before any further
    /// catalogue write. The image is still on the page and the transaction is decided: it lost.
    RolledBack,
    /// It committed and hardened. Its DDL MUST survive — the control that keeps the two endings above
    /// from being satisfied by a build that never persists DDL.
    Committed,
}

impl Ending {
    /// All three, for exhaustive test loops.
    #[must_use]
    pub fn all() -> [Ending; 3] {
        [
            Ending::CrashedMidCommit,
            Ending::RolledBack,
            Ending::Committed,
        ]
    }

    /// Whether this ending's DDL must be in the recovered catalogue.
    #[must_use]
    pub fn survives(self) -> bool {
        self == Ending::Committed
    }
}

/// Which crash flavour to take.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Crash {
    /// Rebuild onto a fresh empty device from the durable WAL prefix.
    NoForce,
    /// Flush dirty pages home first (stealing uncommitted pages onto the durable image), then
    /// recover, so undo runs against a real page image.
    Steal,
}

impl Crash {
    /// Both flavours, for exhaustive test loops.
    #[must_use]
    pub fn all() -> [Crash; 2] {
        [Crash::NoForce, Crash::Steal]
    }
}

/// What [`run`] observed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PhantomReport {
    /// The ending this run took.
    pub ending: Ending,
    /// The crash flavour this run took.
    pub crash: Crash,
    /// Whether the LIVE store held the subject's constraint immediately after the catalogue
    /// checkpoint and before the ending. `false` means the workload never declared it and every
    /// assertion below is vacuous.
    pub subject_declared_live: bool,
    /// Metadata-page chunks the subject's `checkpoint_meta` WROTE. Zero means it logged no catalogue
    /// update at all, so there is no image to be wrong about and the run is vacuous.
    pub subject_meta_chunk_writes: u64,
    /// The transaction the metadata page's pending-DDL block names after the ending, read back by
    /// decoding the image the store actually holds.
    ///
    /// This is the run's strongest non-vacuity witness and the direct assertion of "**only one**
    /// transaction can be pending in an image": it must be `Some(subject)` for the two endings whose
    /// image is the subject's, and it must NEVER name the open bystander. Without it, "the phantom is
    /// absent after recovery" could be satisfied by an image that never carried the DDL in the first
    /// place, which would move the defect rather than fix it.
    pub image_pending_txn: Option<u64>,
    /// Whether the SUBJECT's constraint is in the pending-DDL block of that image (as opposed to its
    /// committed half). It must be, for the two endings whose image the subject wrote.
    pub image_block_holds_subject: bool,
    /// Whether the SEED's committed constraint is in the COMMITTED half of that image — i.e. not in
    /// the block. Committed DDL must ride the image itself; if it rode the block, the block would be
    /// carrying committed state and the split would be a fiction.
    pub image_committed_holds_seed: bool,
    /// Whether the recovered store reports the subject's constraint. Must equal
    /// [`Ending::survives`].
    pub subject_constraint_recovered: bool,
    /// Whether the recovered store reports the OPEN bystander's constraint. Must always be `false`:
    /// `committed_statistics` strips every other open transaction's DDL, and the pending-DDL block
    /// carries the committing transaction's alone.
    pub bystander_constraint_recovered: bool,
    /// Whether the recovered store still reports the SEED's committed constraint. Must always be
    /// `true` — the witness that the fix did not simply stop persisting DDL.
    pub seed_constraint_recovered: bool,
    /// Whether the bystander held its own pending DDL in the LIVE store at the moment the image was
    /// written. `false` makes [`bystander_constraint_recovered`](Self::bystander_constraint_recovered)
    /// vacuous.
    pub bystander_declared_live: bool,
    /// Live nodes the recovered store counts, and what it must be. The witness that the rest of
    /// recovery still did its job on this run rather than the store coming back empty.
    pub recovered_total_nodes: u64,
    /// What [`recovered_total_nodes`](Self::recovered_total_nodes) must be.
    pub expected_total_nodes: u64,
    /// Whether recovery stopped at a torn tail. Must be `false`: nothing is truncated here.
    pub recovery_tail_truncated: bool,
}

impl PhantomReport {
    /// **The property.** The subject's DDL is in the recovered catalogue exactly when the subject
    /// committed, the open bystander's never is, and the seed's committed DDL always is.
    #[must_use]
    pub fn holds(&self) -> bool {
        self.subject_constraint_recovered == self.ending.survives()
            && !self.bystander_constraint_recovered
            && self.seed_constraint_recovered
            && self.recovered_total_nodes == self.expected_total_nodes
    }
}

/// A `UNIQUE` constraint over `(label, key)`.
fn unique(label: u32, key: u32) -> ConstraintEntry {
    ConstraintEntry {
        label_token: label,
        property_tokens: vec![key],
        kind: ConstraintKind::Unique,
        type_descriptor: None,
    }
}

/// Drives `rmp` #1083: a transaction declares a `UNIQUE` constraint, runs its commit-time catalogue
/// checkpoint, and then ends per `ending` before the store crashes.
///
/// A second transaction stays OPEN throughout, holding its own pending DDL, so the run also pins that
/// only ONE transaction's DDL can be pending in an image.
///
/// # Panics
///
/// Panics if any store operation that is expected to succeed fails, or if the recovered store cannot
/// be opened at all — which is itself a failure of this property, in its loudest form.
#[must_use]
pub fn run(ending: Ending, crash: Crash) -> PhantomReport {
    let store = create_store(POOL_CAPACITY);

    // ---- The seed: a committed baseline catalogue, hardened. ----
    let seed = TxnId(1);
    store.begin(seed);
    let label = store
        .intern_token(Namespace::Label, SEED_LABEL)
        .expect("intern the label");
    let key = store
        .intern_token(Namespace::PropKey, SEED_KEY)
        .expect("intern the property key");
    let (seed_node, _) = store.create_node(seed).expect("seed node");
    store.set_constraint(seed, SEED_CONSTRAINT.to_owned(), unique(label, key));
    store.commit(seed).expect("the seed commits");
    store.flush().expect("flush the seed");
    store.with_wal(WalManager::flush);
    let _ = seed_node;

    // ---- The BYSTANDER: open, holding its own pending DDL, and never resolved. ----
    let bystander = TxnId(2);
    store.begin(bystander);
    store.set_constraint(
        bystander,
        BYSTANDER_CONSTRAINT.to_owned(),
        unique(label, key),
    );
    let bystander_declared_live = store.constraint(BYSTANDER_CONSTRAINT).is_some();

    // ---- The SUBJECT: a DDL-ONLY transaction, so it creates no delta and owns no commit slot. ----
    //
    // That class is the one `rmp` #1063 regressed: with no slot it takes `rollback_physical`, whose
    // `compensate_one` used to revert this very page.
    let subject = TxnId(3);
    store.begin(subject);
    store.set_constraint(subject, SUBJECT_CONSTRAINT.to_owned(), unique(label, key));
    let subject_declared_live = store.constraint(SUBJECT_CONSTRAINT).is_some();

    let before = store.meta_chunk_writes().0;
    match ending {
        // The production `checkpoint_meta`, at the exact point `commit_prepare_at` calls it, and then
        // STOP: the image is on the page and no `COMMIT` record exists.
        Ending::CrashedMidCommit => store
            .checkpoint_meta_for_test(subject)
            .expect("the subject's catalogue checkpoint"),
        // The same image, followed by a live rollback. The rollback corrects memory and marks the
        // catalogue dirty; the image it already wrote stays on the page, and redo-only leaves it
        // there (`rmp` #1063).
        Ending::RolledBack => {
            store
                .checkpoint_meta_for_test(subject)
                .expect("the subject's catalogue checkpoint");
            store.rollback(subject).expect("the subject rolls back");
        }
        Ending::Committed => {
            store.commit(subject).expect("the subject commits");
        }
    }
    let subject_meta_chunk_writes = store.meta_chunk_writes().0 - before;
    // THE LOG IS HARDENED FOR EVERY ENDING, and it has to be for two of them to mean anything.
    //
    // The subject's catalogue page writes are WAL records like any other, so a crash that loses the
    // un-hardened tail loses the image with it — and then there is no phantom to find, because
    // nothing of the checkpoint is durable. Measured, not assumed: without this the `NoForce` runs
    // recovered the SEED's image and the scenario was vacuous in exactly the direction that would
    // have made a broken build look fixed.
    //
    // Hardening here is not a contrivance. A log is a prefix, so ANY later committer's
    // `fdatasync` — one arriving a microsecond after the subject's checkpoint — makes the subject's
    // records durable without the subject having committed anything. This models that committer and
    // nothing more exotic. For `Committed` it is the ordinary ack-after-fsync.
    store.with_wal(WalManager::flush);

    // What the image the store is holding actually says, decoded from the metadata page itself.
    let image = durable_catalogue(&store);
    let image_pending_txn = image.pending_ddl.as_ref().map(|p| p.txn);
    let image_block_holds_subject = image
        .pending_ddl
        .as_ref()
        .is_some_and(|p| p.schema.constraint(SUBJECT_CONSTRAINT).is_some());
    let image_committed_holds_seed = image.statistics.constraint(SEED_CONSTRAINT).is_some();

    // ---- The crash. Nothing is truncated: the subject either has a COMMIT record or never wrote
    // one, so there is no tail to tear. ----
    let (recovered, report) = match crash {
        Crash::NoForce => crash_no_force(&store, POOL_CAPACITY),
        Crash::Steal => crash_steal(store, POOL_CAPACITY),
    };

    PhantomReport {
        ending,
        crash,
        subject_declared_live,
        subject_meta_chunk_writes,
        image_pending_txn,
        image_block_holds_subject,
        image_committed_holds_seed,
        subject_constraint_recovered: recovered.constraint(SUBJECT_CONSTRAINT).is_some(),
        bystander_constraint_recovered: recovered.constraint(BYSTANDER_CONSTRAINT).is_some(),
        seed_constraint_recovered: recovered.constraint(SEED_CONSTRAINT).is_some(),
        bystander_declared_live,
        recovered_total_nodes: recovered.statistics().total_nodes(),
        // The seed's node, and nothing else: neither the bystander nor the subject writes a record.
        expected_total_nodes: 1,
        recovery_tail_truncated: report.tail_truncated,
    }
}

/// Decodes the catalogue image the metadata page is holding, so a test can read the pending-DDL
/// block instead of inferring it from what a reopen happens to report.
///
/// The metadata page's payload is framed as `len: u32 | next: u64 | chunk`, where bit 31 of `len` is
/// the format tripwire that makes a pre-`rmp`-#966 build refuse the page rather than misread it —
/// masked off here, exactly as `RecordStore::read_meta` does. This fixture's catalogue fits in the
/// head page, which the `next == 0` assertion pins rather than assumes.
///
/// # Panics
///
/// Panics if the page cannot be read, the chain continues past the head, or the catalogue does not
/// decode — each of which would make every assertion built on the result meaningless.
fn durable_catalogue(store: &Store) -> Meta {
    let bytes = store
        .read_device_page(PageId(0))
        .expect("read the metadata page");
    let at = page::HEADER_SIZE;
    let framed = u32::from_le_bytes(bytes[at..at + 4].try_into().expect("4 bytes"));
    let len = (framed & 0x7fff_ffff) as usize;
    let next = u64::from_le_bytes(bytes[at + 4..at + 12].try_into().expect("8 bytes"));
    assert_eq!(
        next, 0,
        "this fixture's catalogue must fit in the head page, or this helper reads only a prefix"
    );
    Meta::decode(&bytes[at + 12..at + 12 + len]).expect("decode the catalogue")
}

/// A fresh store over an empty in-memory device + log.
fn create_store(capacity: usize) -> Store {
    let device = MemBlockDevice::new(0);
    let wal = WalManager::create(MemLogSink::new()).expect("create wal");
    RecordStore::create(device, wal, capacity, 1).expect("create store")
}

/// No-force crash: rebuild onto a fresh empty device from the durable WAL prefix, then reopen.
fn crash_no_force(store: &Store, capacity: usize) -> (Store, graphus_wal::RecoveryReport) {
    let log = store.with_wal(|w| w.sink().durable_bytes().to_vec());
    let mut sink = MemLogSink::new();
    sink.append(&log);
    sink.sync().expect("sync log prefix");

    let mut device = MemBlockDevice::new(0);
    let mut wal = WalManager::open(sink.clone()).expect("open wal");
    let report = graphus_storage::recovery::recover_device(&mut wal, &mut device).expect("recover");
    let wal = WalManager::open(sink).expect("reopen wal");
    (
        RecordStore::open(device, wal, capacity).expect("open store"),
        report,
    )
}

/// Steal crash: flush dirty pages home (stealing the open transaction's uncommitted pages onto the
/// durable image), snapshot that image, then recover so undo rolls those pages back.
fn crash_steal(store: Store, capacity: usize) -> (Store, graphus_wal::RecoveryReport) {
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
    let report = graphus_storage::recovery::recover_device(&mut wal, &mut device).expect("recover");
    let wal = WalManager::open(sink).expect("reopen wal");
    (
        RecordStore::open(device, wal, capacity).expect("open store"),
        report,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// **The defect.** A transaction whose catalogue image reached the metadata page and whose commit
    /// never happened must not leave its DDL durable — for BOTH endings, and both crash flavours.
    ///
    /// Before the fix this fails on `CrashedMidCommit` and `RolledBack` alike: the image carried the
    /// subject's constraint, and since `rmp` #1063 nothing takes a loser's image back.
    #[test]
    fn a_transaction_that_never_commits_leaves_no_phantom_constraint() {
        for ending in [Ending::CrashedMidCommit, Ending::RolledBack] {
            for crash in Crash::all() {
                let report = run(ending, crash);
                // Non-vacuity, in the order a failure would need to be read.
                assert!(
                    report.subject_declared_live,
                    "{ending:?}/{crash:?}: the subject never declared its constraint, so there is \
                     no phantom to be absent: {report:?}"
                );
                assert!(
                    report.subject_meta_chunk_writes > 0,
                    "{ending:?}/{crash:?}: the subject's checkpoint wrote no metadata chunk, so its \
                     image never reached the page and this run proves nothing: {report:?}"
                );
                // THE PHANTOM IS REALLY STAGED. The durable image carries the subject's constraint,
                // attributed to the subject — so its absence after recovery is a DECISION and not an
                // image that never held it. Without this the fix could pass by never persisting DDL.
                assert_eq!(
                    report.image_pending_txn,
                    Some(3),
                    "{ending:?}/{crash:?}: the durable image does not attribute pending DDL to the \
                     subject, so there is nothing for recovery to decide about: {report:?}"
                );
                assert!(
                    report.image_block_holds_subject,
                    "{ending:?}/{crash:?}: the durable image's pending block does not carry the \
                     subject's constraint: {report:?}"
                );
                assert!(
                    !report.recovery_tail_truncated,
                    "{ending:?}/{crash:?}: recovery stopped at a torn tail, so the durable prefix \
                     is not the one this scenario staged: {report:?}"
                );
                assert!(
                    !report.subject_constraint_recovered,
                    "{ending:?}/{crash:?}: the recovered catalogue carries a UNIQUE constraint \
                     declared by a transaction that never committed. It will REJECT writes that \
                     must be admitted (`rmp` #1083): {report:?}"
                );
                assert!(
                    report.holds(),
                    "{ending:?}/{crash:?}: the pending-DDL property does not hold: {report:?}"
                );
            }
        }
    }

    /// **The control, from the same code path.** A transaction that DOES commit its DDL still finds
    /// it after recovery — so the property above cannot be bought by never persisting DDL at all.
    #[test]
    fn a_committed_constraint_still_survives_recovery() {
        for crash in Crash::all() {
            let report = run(Ending::Committed, crash);
            assert!(
                report.subject_declared_live && report.subject_meta_chunk_writes > 0,
                "{crash:?}: the committed run declared nothing or wrote no image, so it controls \
                 nothing: {report:?}"
            );
            assert!(
                report.subject_constraint_recovered,
                "{crash:?}: a COMMITTED constraint is missing from the recovered catalogue — its \
                 only durable record is the catalogue image, so this is silent loss of committed \
                 DDL (`rmp` #1083): {report:?}"
            );
            assert!(
                report.holds(),
                "{crash:?}: the pending-DDL property does not hold: {report:?}"
            );
        }
    }

    /// **Only one transaction's DDL can be pending in an image**, asserted rather than assumed: an
    /// open bystander's constraint is absent from the recovered catalogue in every ending, including
    /// the one where the image was written by a transaction that committed.
    #[test]
    fn an_open_bystanders_ddl_is_never_in_the_image() {
        for ending in Ending::all() {
            for crash in Crash::all() {
                let report = run(ending, crash);
                assert!(
                    report.bystander_declared_live,
                    "{ending:?}/{crash:?}: the bystander declared nothing, so its absence below is \
                     vacuous: {report:?}"
                );
                // The singleton, asserted on the IMAGE and not only on what a reopen reports: the
                // block names AT MOST one transaction, and it is never the bystander (id 2).
                assert_ne!(
                    report.image_pending_txn,
                    Some(2),
                    "{ending:?}/{crash:?}: the pending-DDL block is attributed to the OPEN \
                     bystander: {report:?}"
                );
                assert!(
                    !report.bystander_constraint_recovered,
                    "{ending:?}/{crash:?}: the durable catalogue carries an OPEN transaction's \
                     pending constraint: {report:?}"
                );
                // Committed DDL rides the image itself, never the block — otherwise the split
                // between "committed" and "pending" would be a fiction and the block would be
                // deciding the fate of state that is already decided.
                assert!(
                    report.image_committed_holds_seed,
                    "{ending:?}/{crash:?}: the seed's COMMITTED constraint is not in the image's \
                     committed half: {report:?}"
                );
            }
        }
    }

    /// The run is deterministic: the same ending and crash flavour produce the same report.
    #[test]
    fn the_run_is_deterministic() {
        for ending in Ending::all() {
            for crash in Crash::all() {
                assert_eq!(
                    run(ending, crash),
                    run(ending, crash),
                    "{ending:?}/{crash:?}: two identical runs disagreed"
                );
            }
        }
    }
}
