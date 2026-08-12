//! **Deterministic writer scheduling seam** (`rmp` #973): the hooks through which a Deterministic
//! Simulation Testing run takes control of the interleaving of real OS threads.
//!
//! # The problem this closes
//!
//! The DST simulator's reproducibility rests today on a *single total order* of operations, which
//! exists only because there is exactly one writer thread per database. Sprint 96 introduces N
//! concurrent writers, and with them that guarantee disappears — precisely when concurrency defects
//! become most likely. Without a replacement, the DST can no longer reproduce a concurrency defect
//! from a seed, and `CLAUDE.md` makes the DST mandatory for exactly that class of scenario.
//!
//! # The mechanism: one execution token, cooperative hand-off
//!
//! A scheduler installed with [`install`] owns a **single execution token**. Only the thread holding
//! it runs; every other registered thread is parked. At each *yield point* the running thread hands
//! the token back, and the scheduler picks the next runnable thread with a **seeded RNG**. The global
//! order of operations therefore becomes a pure function of the seed.
//!
//! Two properties make that claim hold, and both are enforced here rather than left to convention:
//!
//! * **Logical thread ids are assigned by the parent while it holds the token**, before the child
//!   runs ([`spawn`]). If threads registered themselves on arrival, the registration order would
//!   itself be a race and the determinism would be lost at birth.
//! * **Nothing in a scheduling decision may depend on an address, an OS thread id, or a clock.**
//!   [`ResourceId`] is a frame index or a page id, never a pointer (ASLR would break replay);
//!   [`LogicalThreadId`] is assigned by the scheduler, never [`std::thread::ThreadId`]; the runnable
//!   set is ordered ([`std::collections::BTreeSet`] in the implementation, never a `HashSet`).
//!
//! # Why this granularity, and not `loom`
//!
//! The defect class this exists for (`rmp` #811) is an interleaving race at the granularity of the
//! **buffer-pool page latch**, not of the memory model. The off-thread reader in
//! `graphus_storage::read_view::collect_prop_chain` walks a property chain with
//! `let p = read_prop(...)?; let next = p.next_prop; …; cur = next;` — the severance window lies
//! entirely *between two record reads*, each one a `with_page_fetched`, while GC mutates the record
//! in place through `write_prop`. `loom` explores the memory model exhaustively and would deliver far
//! more than that at prohibitive cost; the existing VOPR delivers less (its operations are atomic).
//! A cooperative token at latch granularity is exactly the missing rung.
//!
//! # Cost
//!
//! **Feature off (the default, and every production build): zero.** [`yield_at`] is an empty
//! `#[inline(always)] const fn`, [`release`]/[`release_all`]/[`exempt`] likewise, [`acquire`] reduces
//! to calling its blocking closure, [`ReleaseOnDrop`] is a zero-sized type with an empty `Drop`, and
//! [`spawn`] is `std::thread::spawn`. There is no branch to predict and no code to eliminate.
//!
//! The gate is a **cargo feature** (`det-sched`), deliberately *not* `debug_assertions` — the choice
//! `latch.rs` made. That module wants its tripwire armed across the whole test suite because it is a
//! *correctness* tripwire. A scheduler hook is *hot-path instrumentation*: under `debug_assertions`
//! it would be live in every `cargo test --workspace`, which is the very unification this workspace
//! argues against in `graphus-storage/Cargo.toml` for `read-probe`. It is equally not the `dst`
//! feature pattern, which is unified workspace-wide and is only harmless because production builds
//! with `-p graphus-server`.
//!
//! # The API vanishes when the feature is off
//!
//! [`Scheduler`], [`install`] and [`Installed`] do **not exist** without `det-sched`, exactly as
//! `graphus_storage::read_probe`'s observation API does not. A test that installs a scheduler must
//! **fail to compile** in the default build rather than silently run unscheduled and assert a
//! determinism property it never exercised.
//!
//! # Running it
//!
//! An installed scheduler is **process-global** (one static), and `cargo test` runs a
//! binary's tests on parallel threads. So a scheduled test and an ordinary one running side by side
//! in the same binary is not a supported configuration: the ordinary one's thread is neither
//! registered nor [`exempt`], and the first yield point it reaches panics with the message above.
//! That is the tripwire working — the ordinary test really would have run free of the scheduler that
//! was installed — but it means a run must be FILTERED to the scheduled targets rather than sprayed
//! across a whole crate. `cargo test -p graphus-dst --features det-sched` on its own fails ~172
//! unrelated tests for exactly this reason, and `scripts/verify.sh` gate 5 is narrowed accordingly:
//!
//! ```text
//! cargo test -p graphus-dst --features det-sched --lib detsched::
//! cargo test -p graphus-dst --features det-sched --test det_scheduler_<scenario>
//! ```
//!
//! Each `--test` target is its own binary, so scenarios in different files never see each other's
//! scheduler; within one binary, [`install`] serialises them.

// The scheduler creates a happens-before edge between every pair of consecutive steps, so ThreadSanitizer
// running under it would observe a totally ordered program and report **zero** races — hiding exactly what
// `scripts/tsan-soak.sh` exists to find. Refuse the combination rather than produce a vacuously clean run.
#[cfg(all(feature = "det-sched", tsan))]
compile_error!(
    "`det-sched` and ThreadSanitizer are mutually exclusive: the deterministic scheduler serialises \
     every step, so TSan under it observes a totally ordered program and reports zero races — a \
     vacuously clean soak. Run scripts/tsan-soak.sh WITHOUT --features det-sched."
);

// `loom` replaces the synchronisation primitives with its own model-checking versions and drives the
// interleaving itself. Two schedulers cannot both own the interleaving.
#[cfg(all(feature = "det-sched", loom))]
compile_error!(
    "`det-sched` and `--cfg loom` are mutually exclusive: both take ownership of the thread \
     interleaving. Run the loom model-check WITHOUT --features det-sched."
);

/// A place in the engine where a scheduled thread offers the execution token back.
///
/// `#[repr(u16)]` because the discriminant is serialised into the scheduling history as a fixed-width
/// little-endian field: the history is compared **byte for byte** across runs, so the encoding must be
/// stable and explicit rather than compiler-chosen.
///
/// Values are assigned in blocks by subsystem and are **append-only** — renumbering an existing site
/// would invalidate every recorded history.
#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum YieldSite {
    // ---- Buffer-pool frame latches (10..=29) ------------------------------------------------
    /// `ConcurrentBufferPool::with_page` — frame read latch.
    FrameReadWithPage = 10,
    /// `ConcurrentBufferPool::try_with_page` — frame read latch (fallible handle).
    FrameReadTryWithPage = 11,
    /// `ConcurrentBufferPool::with_page_fetched` — the record-read choke point of the whole engine.
    FrameReadFetched = 12,
    /// `ConcurrentBufferPool::fetch` — the identity re-validation read latch on the hit path.
    FrameReadFetch = 13,
    /// `ConcurrentBufferPool::with_page_mut` — frame write latch.
    FrameWriteWithPageMut = 14,
    /// `ConcurrentBufferPool::with_page_mut_lsn` — frame write latch, LSN-stamping.
    FrameWriteWithPageMutLsn = 15,
    /// `ConcurrentBufferPool::flush` — frame write latch for a single write-back.
    FrameWriteFlush = 16,
    /// `ConcurrentBufferPool::flush_unlogged` — frame write latch for the seed-checksum write-back.
    FrameWriteFlushUnlogged = 17,
    /// `ConcurrentBufferPool::select_victim` — the CLOCK sweep's `try_write` on a candidate frame.
    FrameWriteSelectVictim = 18,
    /// `FlushBatch::collect` — the batch flush, which latches every selected dirty frame.
    FrameWriteFlushBatch = 19,
    /// A frame latch was released (the other half of the protocol: without it the blocked set never
    /// reopens).
    FrameLatchRelease = 20,
    // 21 and 22 are deliberately unused. They were reserved for the page-table shard lock, which
    // turned out NOT to be a legal yield point: `fetch` publishes its `Ready` entry under the shard
    // lock while still holding the freshly loaded victim's frame latch, so handing the token over
    // there would park a thread holding both. The shard lock is a [`NoSwitchScope`] instead. The
    // codes stay retired rather than being recycled, because the discriminants are serialised into
    // comparable histories.

    // ---- Thread lifecycle (30..=39) ---------------------------------------------------------
    /// A parent registered a child and spawned it (recorded by the parent, holding the token).
    ThreadSpawn = 30,
    /// A child thread took the token for the first time and is about to run its body.
    ThreadStart = 31,
    /// A thread's body finished (normally or by unwinding) and it gave the token up for good.
    ThreadExit = 32,
    /// A thread waited for a child to exit.
    ThreadJoin = 33,

    // ---- Commit publication (40..=49) -------------------------------------------------------
    /// `RecordStore::commit` — just before the **durable** commit slot is published.
    CommitPublishSlot = 40,
    /// `RecordStore::commit` — just before the **in-memory** registry records the commit. This is the
    /// instant a commit becomes visible; the interesting window is *between* this and
    /// [`CommitPublishSlot`](Self::CommitPublishSlot).
    CommitRegistryRecord = 41,
    /// `RecordStore::commit` — just before the transaction's active-set entry is settled.
    CommitSettle = 42,
    /// `RecordStore::committed_statistics` — just before a checkpoint samples the catalog image it is
    /// about to make durable.
    ///
    /// The image is the live counters MINUS every still-open transaction's pending delta, and `rmp`
    /// #1052 was that difference being sampled at two instants. This site sits immediately BEFORE the
    /// single hold that now samples both, so a scheduled writer released here runs to completion
    /// against a checkpoint that has not started — which is the interleaving the defect needed, and
    /// which the fix has to survive.
    CatalogCommittedImage = 43,

    // ---- Snapshot acquisition (50..=59) -----------------------------------------------------
    /// `TxnCoordinator::oldest_active_snapshot` — the reclamation floor every GC watermark derives
    /// from.
    SnapshotOldestActive = 50,
    /// `TxnCoordinator::read_task_inputs` — the snapshot an off-thread read task carries away.
    SnapshotReadTaskInputs = 51,
    /// `RecordStore::begin` — immediately before a transaction reads the commit-visibility horizon
    /// and becomes its begin timestamp.
    ///
    /// The instant `rmp` #1056 is about. A snapshot taken here while another worker is *inside*
    /// `commit_prepare` — past the issue of its commit timestamp, short of publishing its commit — is
    /// what produced a begin timestamp naming a commit nobody could see, and with it a lost update.
    /// Without a yield point at the snapshot itself the deterministic scheduler cannot place a
    /// transaction in that window: `begin` runs straight through from wherever its thread was last
    /// parked, so reaching the window is left to how many steps happen to separate the two, which is
    /// how the by-seed reproduction of #1056 initially came back empty. Its guard is `graphus-dst`'s
    /// `det_scheduler_lost_update_1056`.
    SnapshotBegin = 52,

    // ---- Storage coverage points (60..=79) --------------------------------------------------
    /// `RecordStore::free_push` — a slot returned to a store's free list.
    FreeListPush = 60,
    /// `RecordStore::link_delta` — between reading the undo-chain head and republishing it.
    UndoChainHeadPublish = 61,
    /// GC phase A — relationship-tombstone reclamation.
    GcPhaseA = 62,
    /// GC phase B — dead-link relationship corpse splice.
    GcPhaseB = 63,
    /// GC phase C — node-tombstone reclamation.
    GcPhaseC = 64,
    /// GC phase B2 — orphan-slot reclamation.
    GcPhaseB2 = 65,
    /// GC phase F — undo-chain reclamation.
    GcPhaseF = 66,
    /// GC phase D — the property-chain sweep. This is the phase that reclaims a tombstone sitting on
    /// a live owner's chain, i.e. the `rmp` #811 severance window.
    GcPhaseD = 67,
    /// GC phase E — MVCC stamp freeze.
    GcPhaseE = 68,

    // ---- Write-path header reads (80..=89) --------------------------------------------------
    // Exercised by several concurrent writers since `rmp` #1034: `graphus-dst`'s
    // `det_scheduler_multi_writer_1034` drives four scheduled writers against one store and asserts
    // that each of these sites is reached by MORE THAN ONE of them — so the writer-vs-writer value
    // `rmp` #975 wired them for is now proven rather than anticipated.
    /// `RecordStore::read_mvcc` — the header read every write-path conflict decision starts from.
    WriteReadMvcc = 80,
    /// `RecordStore::ensure_no_conflicting_writer` — the write-write conflict check.
    WriteConflictCheck = 81,
    /// `RecordStore::ensure_chain_head_unheld` — the undo-chain-head ownership check.
    WriteChainHeadUnheld = 82,
    /// `RecordStore::link_delta` — the chain-head read that the republication below must not race.
    WriteLinkDelta = 83,
}

impl YieldSite {
    /// The stable numeric code written into the history record.
    #[must_use]
    pub const fn code(self) -> u16 {
        self as u16
    }

    /// Whether reaching this site with a buffer-pool frame latch held is a bug.
    ///
    /// The scheduler's whole safety argument is that the token is only ever handed over at points
    /// where the yielding thread holds no page latch — a thread parked holding one would make every
    /// other thread's blocking acquisition freeze the simulation. Every latch-class site is therefore
    /// checked against the `rmp` #974/#993 tripwire (`crate::latch::frame_latch_depth`) rather than
    /// against a new mechanism of its own.
    #[must_use]
    pub const fn requires_no_frame_latch(self) -> bool {
        matches!(
            self,
            Self::FrameReadWithPage
                | Self::FrameReadTryWithPage
                | Self::FrameReadFetched
                | Self::FrameReadFetch
                | Self::FrameWriteWithPageMut
                | Self::FrameWriteWithPageMutLsn
                | Self::FrameWriteFlush
                | Self::FrameWriteFlushUnlogged
                | Self::FrameWriteSelectVictim
                | Self::FrameWriteFlushBatch
        )
    }
}

/// The thing a yield point is about: a buffer-pool frame, a page-table shard, a store slot, a
/// transaction, a logical thread.
///
/// **Never an address.** A pointer would differ between two runs of the same seed under ASLR and the
/// replay would diverge for a reason that has nothing to do with the schedule. The top byte tags the
/// class so two different kinds of resource can never collide in the blocked map.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ResourceId(u64);

impl ResourceId {
    /// A yield point with no associated resource.
    pub const NONE: Self = Self(0);

    const CLASS_SHIFT: u32 = 56;
    const VALUE_MASK: u64 = (1u64 << Self::CLASS_SHIFT) - 1;

    const CLASS_FRAME: u64 = 1;
    const CLASS_SHARD: u64 = 2;
    const CLASS_PAGE: u64 = 3;
    const CLASS_THREAD: u64 = 4;
    const CLASS_TXN: u64 = 5;
    const CLASS_SLOT: u64 = 6;

    const fn tagged(class: u64, value: u64) -> Self {
        Self((class << Self::CLASS_SHIFT) | (value & Self::VALUE_MASK))
    }

    /// A buffer-pool frame, identified by its **index** in the pool.
    #[must_use]
    pub const fn frame(index: usize) -> Self {
        Self::tagged(Self::CLASS_FRAME, index as u64)
    }

    /// A buffer-pool page-table shard, identified by its index.
    #[must_use]
    pub const fn shard(index: usize) -> Self {
        Self::tagged(Self::CLASS_SHARD, index as u64)
    }

    /// A logical page id.
    #[must_use]
    pub const fn page(page_id: u64) -> Self {
        Self::tagged(Self::CLASS_PAGE, page_id)
    }

    /// A logical thread (used by `join`).
    #[must_use]
    pub const fn thread(t: LogicalThreadId) -> Self {
        Self::tagged(Self::CLASS_THREAD, t.0 as u64)
    }

    /// A transaction id.
    #[must_use]
    pub const fn txn(id: u64) -> Self {
        Self::tagged(Self::CLASS_TXN, id)
    }

    /// A record slot, tagged by its store kind so two stores' slot `7`s are distinct resources.
    #[must_use]
    pub const fn slot(store_kind: u8, id: u64) -> Self {
        Self::tagged(
            Self::CLASS_SLOT,
            ((store_kind as u64) << 48) | (id & 0xFFFF_FFFF_FFFF),
        )
    }

    /// The raw encoding, as written into the history record.
    #[must_use]
    pub const fn raw(self) -> u64 {
        self.0
    }
}

/// A thread id **assigned by the scheduler**, in registration order.
///
/// Deliberately not [`std::thread::ThreadId`]: that is opaque, its numbering depends on the process's
/// allocation history, and it is therefore not reproducible across runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct LogicalThreadId(pub u32);

/// The width, in bytes, of one serialised history record. Fixed width so two histories compare as
/// `Vec<u8> == Vec<u8>`, byte for byte, with no parsing.
pub const HISTORY_RECORD_LEN: usize = 24;

/// One scheduling decision, as recorded in the history.
///
/// Serialised by [`Step::encode`] into exactly [`HISTORY_RECORD_LEN`] little-endian bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Step {
    /// Global sequence number of this step (0-based, dense).
    pub seq: u64,
    /// The thread that reached the yield point.
    pub thread: LogicalThreadId,
    /// Which yield point.
    pub site: YieldSite,
    /// The resource the yield point concerns.
    pub resource: ResourceId,
    /// `1` if the token actually moved to a different thread here, `0` otherwise.
    pub switched: u8,
}

impl Step {
    /// Appends this step's fixed-width little-endian encoding to `out`.
    ///
    /// Layout (24 bytes): `seq` u64, `thread` u32, `site` u16, `switched` u8, one zero pad byte,
    /// `resource` u64.
    pub fn encode(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.seq.to_le_bytes());
        out.extend_from_slice(&self.thread.0.to_le_bytes());
        out.extend_from_slice(&self.site.code().to_le_bytes());
        out.push(self.switched);
        out.push(0); // explicit pad, so the record width is a round 24 and never compiler-chosen
        out.extend_from_slice(&self.resource.raw().to_le_bytes());
    }
}

#[cfg(feature = "det-sched")]
pub use imp::{Installed, Scheduler, install, installed};

pub use imp::{acquire, exempt, history_hash, release, release_all, yield_at};

/// A region in which the execution token must **not** change hands.
///
/// # Why this exists
///
/// The scheduler's safety argument is that no thread is ever parked while holding a lock another
/// scheduled thread might block on — a parked lock holder freezes the whole simulation, because only
/// one thread runs at a time and the blocked one cannot yield. Page latches are covered by
/// [`YieldSite::requires_no_frame_latch`], which turns a violation into a loud assertion.
///
/// The buffer pool's **page-table shard lock** cannot be covered the same way, because it is
/// genuinely taken *around* work that reaches yield points: `fetch` publishes its `Ready` entry under
/// the shard lock while still holding the victim's frame latch, and `select_victim` runs its whole
/// CLOCK sweep under it. Rather than forbid those, this scope suppresses the *hand-off* for their
/// duration: a yield point reached inside the region is still **recorded** in the history (so the
/// site is provably reached and the history stays a complete account of the run) but the token stays
/// put, and [`acquire`] takes the lock directly instead of parking.
///
/// Zero-sized in every build; the depth is a thread-local, and with `det-sched` off both the counter
/// and the `Drop` body vanish.
#[derive(Debug)]
pub struct NoSwitchScope {
    /// Makes the scope non-constructible except through [`NoSwitchScope::new`], and `!Send`/`!Sync`
    /// — the depth is a `thread_local`, so a scope created on one thread and dropped on another
    /// would corrupt both counters. Exactly the reasoning [`crate::latch::FrameLatchScope`] uses.
    _private: std::marker::PhantomData<*const ()>,
}

impl NoSwitchScope {
    /// Enters a no-hand-off region on the current thread. Re-entrant (the depth is a counter).
    #[must_use]
    #[inline(always)]
    pub fn new() -> Self {
        #[cfg(feature = "det-sched")]
        imp::push_no_switch();
        Self {
            _private: std::marker::PhantomData,
        }
    }
}

impl Default for NoSwitchScope {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for NoSwitchScope {
    #[inline(always)]
    fn drop(&mut self) {
        #[cfg(feature = "det-sched")]
        imp::pop_no_switch();
    }
}

/// An RAII announcement that a resource has been released.
///
/// Declare it **before** the lock guard it accompanies: Rust drops locals in reverse declaration
/// order, so the guard (declared later) releases the lock first and this announcement (declared
/// earlier) fires second — the blocked set therefore only reopens once the lock is genuinely free.
/// This is the same reverse-drop discipline `ConcurrentBufferPool::with_page_fetched` already uses
/// for its pin guard.
///
/// Zero-sized with an empty `Drop` when `det-sched` is off.
#[derive(Debug)]
pub struct ReleaseOnDrop {
    #[cfg(feature = "det-sched")]
    site: YieldSite,
    #[cfg(feature = "det-sched")]
    resource: ResourceId,
}

impl ReleaseOnDrop {
    /// Announces `resource` as released when the returned value drops.
    #[must_use]
    #[inline(always)]
    pub const fn new(site: YieldSite, resource: ResourceId) -> Self {
        #[cfg(feature = "det-sched")]
        {
            Self { site, resource }
        }
        #[cfg(not(feature = "det-sched"))]
        {
            let _ = (site, resource);
            Self {}
        }
    }
}

impl Drop for ReleaseOnDrop {
    #[inline(always)]
    fn drop(&mut self) {
        #[cfg(feature = "det-sched")]
        release(self.site, self.resource);
    }
}

/// An RAII announcement that a *batch* of resources has been released, without naming them.
///
/// Used by the buffer pool's batch flush, which latches and releases many frames at once. Waking
/// every blocked thread is a deliberate **superset**: a thread woken for a resource that is still
/// held simply retries and parks again, whereas a *missed* wake-up is a lost wakeup and would be
/// reported as a deadlock. Supersets over subsets, for the same reason an index that cannot answer a
/// predicate must decline rather than return an empty set.
///
/// Zero-sized with an empty `Drop` when `det-sched` is off.
#[derive(Debug)]
pub struct ReleaseAllOnDrop {
    #[cfg(feature = "det-sched")]
    site: YieldSite,
}

impl ReleaseAllOnDrop {
    /// Wakes every blocked thread when the returned value drops.
    #[must_use]
    #[inline(always)]
    pub const fn new(site: YieldSite) -> Self {
        #[cfg(feature = "det-sched")]
        {
            Self { site }
        }
        #[cfg(not(feature = "det-sched"))]
        {
            let _ = site;
            Self {}
        }
    }
}

impl Drop for ReleaseAllOnDrop {
    #[inline(always)]
    fn drop(&mut self) {
        #[cfg(feature = "det-sched")]
        release_all(self.site);
    }
}

/// A handle to a thread created by [`spawn`].
///
/// `#[repr(transparent)]`-equivalent when `det-sched` is off: the scheduler bookkeeping field does not
/// exist, and [`join`](JoinHandle::join) is `std::thread::JoinHandle::join`.
#[derive(Debug)]
pub struct JoinHandle<T> {
    inner: std::thread::JoinHandle<T>,
    #[cfg(feature = "det-sched")]
    logical: Option<LogicalThreadId>,
}

impl<T> JoinHandle<T> {
    /// Waits for the thread to finish.
    ///
    /// Under a scheduler this first hands the execution token away and parks on the child's exit, so
    /// the child can actually reach it — a plain `join()` with the token held would freeze the
    /// simulation.
    ///
    /// # Errors
    /// Returns the panic payload if the thread panicked, exactly as
    /// [`std::thread::JoinHandle::join`].
    pub fn join(self) -> std::thread::Result<T> {
        #[cfg(feature = "det-sched")]
        imp::join_child(self.logical);
        self.inner.join()
    }

    /// Whether the thread has finished (a non-blocking probe, delegated to `std`).
    #[must_use]
    pub fn is_finished(&self) -> bool {
        self.inner.is_finished()
    }
}

/// Spawns a thread that participates in deterministic scheduling.
///
/// The logical id is assigned **by this (parent) thread while it holds the token**, before the child
/// runs. That ordering is the whole determinism argument for thread creation: were children to
/// register themselves on arrival, the registration order would be a race and every recorded history
/// would depend on OS scheduling.
///
/// With `det-sched` off — or with no scheduler installed — this is `std::thread::spawn(f)`.
///
/// # Panics
/// Propagates a failure to spawn the underlying OS thread.
pub fn spawn<F, T>(name: &str, f: F) -> JoinHandle<T>
where
    F: FnOnce() -> T + Send + 'static,
    T: Send + 'static,
{
    imp::spawn(name, f)
}

// ---------------------------------------------------------------------------------------------
// Instrumented implementation
// ---------------------------------------------------------------------------------------------

#[cfg(feature = "det-sched")]
mod imp {
    use super::{JoinHandle, LogicalThreadId, ResourceId, YieldSite};
    use std::cell::Cell;
    use std::sync::{Arc, Mutex, MutexGuard, RwLock};

    /// The policy a [`super::install`]ed scheduler implements.
    ///
    /// The policy deliberately does **not** live in this crate: it needs a seeded RNG (`graphus-sim`),
    /// which depends on `graphus-core`. This mirrors [`crate::capability`] — traits here, the
    /// deterministic implementation outside. The concrete scheduler is
    /// `graphus_dst::detsched::DetScheduler`.
    ///
    /// Every method is called with the caller already known to be a registered thread, except
    /// [`release`](Scheduler::release) and [`release_all`](Scheduler::release_all), which may be
    /// called by an exempt thread (they are liveness-only and record nothing in that case).
    pub trait Scheduler: Send + Sync + std::fmt::Debug {
        /// Registers a new logical thread and makes it runnable. Called by a thread that holds the
        /// token (or by `install` for the root). The very first registration also takes the token.
        fn register(&self, name: &str) -> LogicalThreadId;

        /// Called by a freshly spawned child: blocks until it holds the token.
        fn thread_entry(&self, id: LogicalThreadId);

        /// Called on a child's exit — normal or unwinding. Gives the token up for good.
        fn thread_exit(&self, id: LogicalThreadId);

        /// A cooperative yield point: record it and, per the seeded draw, possibly hand the token to
        /// another runnable thread.
        fn yield_at(&self, id: LogicalThreadId, site: YieldSite, resource: ResourceId);

        /// Record a yield point **without** handing the token over, because the caller is inside a
        /// [`super::NoSwitchScope`]. The step still enters the history: a site that was reached must
        /// be visible in the record even when the schedule could not act on it.
        fn observe(&self, id: LogicalThreadId, site: YieldSite, resource: ResourceId);

        /// Park `id` until some thread releases `resource`, handing the token away meanwhile.
        fn park_on(&self, id: LogicalThreadId, site: YieldSite, resource: ResourceId);

        /// Make every thread blocked on `resource` runnable again. Never switches: a release can
        /// happen while the caller still holds *other* latches (the batch flush does), and switching
        /// there would park a thread holding a latch — the one thing that must never happen.
        fn release(&self, id: Option<LogicalThreadId>, site: YieldSite, resource: ResourceId);

        /// Make every blocked thread runnable again (a superset wake-up; see
        /// [`super::ReleaseAllOnDrop`]).
        fn release_all(&self, id: Option<LogicalThreadId>, site: YieldSite);

        /// Block `id` until `child` has exited.
        fn join_child(&self, id: LogicalThreadId, child: LogicalThreadId);

        /// The running FNV-1a digest of the history recorded so far.
        fn history_hash(&self) -> u64;
    }

    /// Serialises scheduler-using tests. A cooperative token is process-global by nature, so two
    /// scheduled runs cannot overlap; `install` blocks until the previous [`Installed`] is dropped.
    static INSTALL_LOCK: Mutex<()> = Mutex::new(());

    /// The installed scheduler, or `None`. Read on every yield point, so the guard is dropped (and
    /// the `Arc` cloned) before any call that can park — holding it across a park would block
    /// `install`/`Installed::drop` forever.
    static ACTIVE: RwLock<Option<Arc<dyn Scheduler>>> = RwLock::new(None);

    thread_local! {
        /// This thread's logical id, or `None` if it was never registered.
        static CURRENT: Cell<Option<LogicalThreadId>> = const { Cell::new(None) };
        /// Whether this thread is deliberately outside the scheduler's control.
        static EXEMPT: Cell<bool> = const { Cell::new(false) };
        /// Nesting depth of [`super::NoSwitchScope`] regions on this thread.
        static NO_SWITCH: Cell<u32> = const { Cell::new(0) };
    }

    pub(super) fn push_no_switch() {
        NO_SWITCH.with(|d| d.set(d.get().saturating_add(1)));
    }

    pub(super) fn pop_no_switch() {
        NO_SWITCH.with(|d| d.set(d.get().saturating_sub(1)));
    }

    fn in_no_switch_region() -> bool {
        NO_SWITCH.with(Cell::get) > 0
    }

    /// A poisoned scheduler lock must not wedge the process: the protected state is scheduling
    /// bookkeeping and a panicking test is already failing.
    fn unpoison<G>(r: std::result::Result<G, std::sync::PoisonError<G>>) -> G {
        r.unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// The installed scheduler, if any, without touching thread-local state.
    fn active() -> Option<Arc<dyn Scheduler>> {
        let guard = unpoison(ACTIVE.read());
        guard.as_ref().map(Arc::clone)
    }

    /// The scheduler and this thread's logical id, for a call that **must** be deterministic.
    ///
    /// Returns `None` when no scheduler is installed or the thread is [`exempt`]. Panics when a
    /// scheduler *is* installed and the thread is neither registered nor exempt: such a thread runs
    /// free and would destroy determinism silently, so it fails loudly instead (`rmp` #973 risk 3).
    ///
    /// # Panics
    /// If an unregistered, non-exempt thread reaches a yield point under an installed scheduler.
    fn scheduled() -> Option<(Arc<dyn Scheduler>, LogicalThreadId)> {
        let sched = active()?;
        if EXEMPT.with(Cell::get) {
            return None;
        }
        match CURRENT.with(Cell::get) {
            Some(id) => Some((sched, id)),
            None => panic!(
                "graphus_core::sched: thread {:?} reached a deterministic-scheduler yield point \
                 without being registered. A thread the scheduler does not control runs freely and \
                 destroys the determinism of the whole run in silence, so this fails loudly. Create \
                 it with `graphus_core::sched::spawn`, or — if it is deliberately outside the \
                 simulation (a reader-pool worker, the WAL fsync offload, a rayon worker) — mark it \
                 with `graphus_core::sched::exempt()` as its first statement.",
                std::thread::current().name().unwrap_or("<unnamed>")
            ),
        }
    }

    /// Marks the calling thread as deliberately outside the scheduler's control.
    pub fn exempt() {
        EXEMPT.with(|e| e.set(true));
    }

    /// Whether a scheduler is currently installed.
    #[must_use]
    pub fn installed() -> bool {
        unpoison(ACTIVE.read()).is_some()
    }

    /// The running history digest of the installed scheduler, or `None` if there is none.
    #[must_use]
    pub fn history_hash() -> Option<u64> {
        active().map(|s| s.history_hash())
    }

    /// Installs `sched` for the calling thread and every thread it later
    /// [`spawn`](super::spawn)s, registering the caller as the root logical thread.
    ///
    /// Blocks until any previously installed scheduler has been uninstalled: the execution token is
    /// process-global, so two scheduled runs cannot overlap (a `cargo test` harness runs test
    /// functions on several threads by default).
    ///
    /// The scheduler is uninstalled when the returned [`Installed`] drops.
    pub fn install(sched: Arc<dyn Scheduler>, root_name: &str) -> Installed {
        let lock = unpoison(INSTALL_LOCK.lock());
        let root = sched.register(root_name);
        CURRENT.with(|c| c.set(Some(root)));
        EXEMPT.with(|e| e.set(false));
        *unpoison(ACTIVE.write()) = Some(sched);
        Installed { _lock: lock, root }
    }

    /// The lifetime of an installed scheduler. Dropping it uninstalls the scheduler and releases the
    /// process-wide install lock.
    #[derive(Debug)]
    #[must_use = "the scheduler is uninstalled the moment this guard drops"]
    pub struct Installed {
        _lock: MutexGuard<'static, ()>,
        root: LogicalThreadId,
    }

    impl Installed {
        /// The root thread's logical id (the thread that called [`install`]).
        #[must_use]
        pub fn root(&self) -> LogicalThreadId {
            self.root
        }
    }

    impl Drop for Installed {
        fn drop(&mut self) {
            *unpoison(ACTIVE.write()) = None;
            CURRENT.with(|c| c.set(None));
        }
    }

    /// A cooperative yield point.
    ///
    /// # Panics
    /// If the calling thread is neither registered nor exempt while a scheduler is installed, or if a
    /// latch-class site is reached with a buffer-pool frame latch held.
    #[inline]
    pub fn yield_at(site: YieldSite, resource: ResourceId) {
        let Some((sched, id)) = scheduled() else {
            return;
        };
        assert_no_latch(site);
        if in_no_switch_region() {
            sched.observe(id, site, resource);
        } else {
            sched.yield_at(id, site, resource);
        }
    }

    /// Announces that `resource` has been released, reopening the blocked set.
    ///
    /// Deliberately tolerant of an unregistered or exempt caller: it runs inside `Drop`, where a panic
    /// during unwinding aborts the process, and its effect (waking a parked thread) is liveness-only.
    /// An exempt caller records **nothing** in the history — an uncontrolled thread must never inject
    /// a step at a nondeterministic position.
    #[inline]
    pub fn release(site: YieldSite, resource: ResourceId) {
        let Some(sched) = active() else {
            return;
        };
        let id = if EXEMPT.with(Cell::get) {
            None
        } else {
            CURRENT.with(Cell::get)
        };
        sched.release(id, site, resource);
    }

    /// Announces that a batch of resources has been released. See [`super::ReleaseAllOnDrop`].
    #[inline]
    pub fn release_all(site: YieldSite) {
        let Some(sched) = active() else {
            return;
        };
        let id = if EXEMPT.with(Cell::get) {
            None
        } else {
            CURRENT.with(Cell::get)
        };
        sched.release_all(id, site);
    }

    /// Yields, then acquires a resource, parking on the scheduler while it is held by someone else.
    ///
    /// Under the scheduler's own invariant (no thread is ever parked holding a page latch) the first
    /// `try_acquire` succeeds; the park path is the safety net that turns a *broken* invariant — or
    /// contention with an [`exempt`] thread — into a reported deadlock or a correct wait, instead of a
    /// frozen simulation.
    ///
    /// # Panics
    /// As [`yield_at`], plus a bounded-retry panic if the resource cannot be taken within
    /// [`MAX_ACQUIRE_PARKS`] parks (a livelock backstop).
    #[inline]
    pub fn acquire<G>(
        site: YieldSite,
        resource: ResourceId,
        mut try_acquire: impl FnMut() -> Option<G>,
        blocking: impl FnOnce() -> G,
    ) -> G {
        let Some((sched, id)) = scheduled() else {
            return blocking();
        };
        assert_no_latch(site);
        // Inside a no-hand-off region the acquisition must NOT park: parking is a hand-off, and the
        // region exists precisely because handing the token over there would strand a lock holder.
        // Record the site and take the lock the ordinary way.
        if in_no_switch_region() {
            sched.observe(id, site, resource);
            return blocking();
        }
        sched.yield_at(id, site, resource);
        for _ in 0..MAX_ACQUIRE_PARKS {
            if let Some(guard) = try_acquire() {
                return guard;
            }
            sched.park_on(id, site, resource);
        }
        panic!(
            "graphus_core::sched: thread {id:?} could not take {resource:?} at {site:?} within \
             {MAX_ACQUIRE_PARKS} parks. Under the scheduler's invariant no thread is ever parked \
             holding a page latch, so a contended acquisition should resolve on the first retry; a \
             run this long means a yield point was placed inside a latched region, or an exempt \
             thread holds the resource indefinitely."
        );
    }

    /// How many times [`acquire`] will park before declaring a livelock. Generous, because a
    /// superset wake-up (`release_all`) legitimately produces a retry that re-parks.
    const MAX_ACQUIRE_PARKS: u32 = 10_000;

    /// Enforces "yield before acquiring, never with the latch in hand" for the latch-class sites,
    /// reusing the `rmp` #974/#993 tripwire rather than inventing a second mechanism.
    ///
    /// The tripwire is itself `debug_assertions`-gated, so this is exact in the debug profile every
    /// DST scenario runs under, and vacuous in release — which is the tripwire's documented scope.
    #[inline]
    fn assert_no_latch(site: YieldSite) {
        if site.requires_no_frame_latch() {
            let depth = crate::latch::frame_latch_depth();
            assert!(
                depth == 0,
                "graphus_core::sched: {site:?} handed the execution token over while holding \
                 {depth} buffer-pool frame latch(es). A thread parked holding a page latch makes \
                 every other thread's blocking acquisition freeze the whole simulation — yield \
                 BEFORE acquiring, never with the latch in hand."
            );
        }
    }

    pub(super) fn spawn<F, T>(name: &str, f: F) -> JoinHandle<T>
    where
        F: FnOnce() -> T + Send + 'static,
        T: Send + 'static,
    {
        let Some((sched, parent)) = scheduled() else {
            return JoinHandle {
                inner: std::thread::spawn(f),
                logical: None,
            };
        };
        // The id is minted HERE, by the parent, while it holds the token — before the child exists.
        // `register` also makes the child runnable, so the scheduler may legitimately choose it
        // before its OS thread has started; that costs a real wait and changes no state.
        let child = sched.register(name);
        let child_sched = Arc::clone(&sched);
        let inner = std::thread::Builder::new()
            .name(name.to_owned())
            .spawn(move || {
                CURRENT.with(|c| c.set(Some(child)));
                child_sched.thread_entry(child);
                // The token must be surrendered on EVERY exit path, including an unwind out of `f`
                // — `catch_unwind` boundaries exist on the reader-pool and coordinator paths, and a
                // thread that dies holding the token freezes the run (`rmp` #973 risk 2).
                let _exit = ExitGuard {
                    sched: Arc::clone(&child_sched),
                    id: child,
                };
                f()
            })
            .expect("graphus_core::sched: failed to spawn a scheduled thread");
        // The parent's yield point comes AFTER the OS thread exists, never before. Yielding first
        // would let the scheduler hand the token to a thread that has not been created yet: the
        // parent then waits for a hand-off back from a thread that will never run, and the run
        // deadlocks at step 1. (Found by the scheduler's own stall detector on the first run.)
        sched.yield_at(parent, YieldSite::ThreadSpawn, ResourceId::thread(child));
        JoinHandle {
            inner,
            logical: Some(child),
        }
    }

    /// Surrenders the execution token when a scheduled thread's body ends, normally or by unwinding.
    struct ExitGuard {
        sched: Arc<dyn Scheduler>,
        id: LogicalThreadId,
    }

    impl Drop for ExitGuard {
        fn drop(&mut self) {
            self.sched.thread_exit(self.id);
        }
    }

    pub(super) fn join_child(child: Option<LogicalThreadId>) {
        let Some(child) = child else {
            return;
        };
        let Some((sched, me)) = scheduled() else {
            return;
        };
        sched.join_child(me, child);
    }
}

// ---------------------------------------------------------------------------------------------
// No-op implementation (the default, and every production build)
// ---------------------------------------------------------------------------------------------

#[cfg(not(feature = "det-sched"))]
mod imp {
    use super::{JoinHandle, ResourceId, YieldSite};

    /// No-op: the `det-sched` feature is off, so no scheduling hook reaches the engine.
    #[inline(always)]
    pub const fn yield_at(_site: YieldSite, _resource: ResourceId) {}

    /// No-op: the `det-sched` feature is off.
    #[inline(always)]
    pub const fn release(_site: YieldSite, _resource: ResourceId) {}

    /// No-op: the `det-sched` feature is off.
    #[inline(always)]
    pub const fn release_all(_site: YieldSite) {}

    /// No-op: the `det-sched` feature is off.
    #[inline(always)]
    pub const fn exempt() {}

    /// Always `None`: without the feature there is no scheduler and therefore no history. Returning
    /// `None` rather than `Some(0)` keeps a caller from mistaking "not instrumented" for "an empty
    /// history was recorded".
    #[must_use]
    #[inline(always)]
    pub const fn history_hash() -> Option<u64> {
        None
    }

    /// Acquires the resource directly: without the feature there is nothing to schedule, so this is
    /// exactly the blocking acquisition the call site would otherwise have written inline.
    #[inline(always)]
    pub fn acquire<G>(
        _site: YieldSite,
        _resource: ResourceId,
        _try_acquire: impl FnMut() -> Option<G>,
        blocking: impl FnOnce() -> G,
    ) -> G {
        blocking()
    }

    #[inline(always)]
    pub(super) fn spawn<F, T>(_name: &str, f: F) -> JoinHandle<T>
    where
        F: FnOnce() -> T + Send + 'static,
        T: Send + 'static,
    {
        JoinHandle {
            inner: std::thread::spawn(f),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resource_classes_never_collide() {
        assert_ne!(ResourceId::frame(7), ResourceId::shard(7));
        assert_ne!(ResourceId::frame(7), ResourceId::page(7));
        assert_ne!(ResourceId::page(7), ResourceId::txn(7));
        assert_ne!(ResourceId::slot(1, 7), ResourceId::slot(2, 7));
        assert_ne!(ResourceId::frame(0), ResourceId::NONE);
    }

    #[test]
    fn step_encoding_is_fixed_width_and_little_endian() {
        let step = Step {
            seq: 0x0102_0304_0506_0708,
            thread: LogicalThreadId(0x0A0B_0C0D),
            site: YieldSite::FrameReadFetched,
            resource: ResourceId::frame(1),
            switched: 1,
        };
        let mut out = Vec::new();
        step.encode(&mut out);
        assert_eq!(out.len(), HISTORY_RECORD_LEN);
        assert_eq!(&out[0..8], &0x0102_0304_0506_0708u64.to_le_bytes());
        assert_eq!(&out[8..12], &0x0A0B_0C0Du32.to_le_bytes());
        assert_eq!(
            &out[12..14],
            &YieldSite::FrameReadFetched.code().to_le_bytes()
        );
        assert_eq!(out[14], 1);
        assert_eq!(out[15], 0);
        assert_eq!(&out[16..24], &ResourceId::frame(1).raw().to_le_bytes());
    }

    #[test]
    fn latch_class_is_exactly_the_page_latch_sites() {
        assert!(YieldSite::FrameReadFetched.requires_no_frame_latch());
        assert!(YieldSite::FrameWriteFlushBatch.requires_no_frame_latch());
        assert!(!YieldSite::CommitPublishSlot.requires_no_frame_latch());
        assert!(!YieldSite::FrameLatchRelease.requires_no_frame_latch());
        assert!(!YieldSite::GcPhaseD.requires_no_frame_latch());
    }

    /// The site codes are serialised into a byte-comparable history, so a duplicate would make two
    /// different sites indistinguishable in a replay diff.
    #[test]
    fn site_codes_are_unique() {
        let sites = [
            YieldSite::FrameReadWithPage,
            YieldSite::FrameReadTryWithPage,
            YieldSite::FrameReadFetched,
            YieldSite::FrameReadFetch,
            YieldSite::FrameWriteWithPageMut,
            YieldSite::FrameWriteWithPageMutLsn,
            YieldSite::FrameWriteFlush,
            YieldSite::FrameWriteFlushUnlogged,
            YieldSite::FrameWriteSelectVictim,
            YieldSite::FrameWriteFlushBatch,
            YieldSite::FrameLatchRelease,
            YieldSite::ThreadSpawn,
            YieldSite::ThreadStart,
            YieldSite::ThreadExit,
            YieldSite::ThreadJoin,
            YieldSite::CommitPublishSlot,
            YieldSite::CommitRegistryRecord,
            YieldSite::CommitSettle,
            YieldSite::CatalogCommittedImage,
            YieldSite::SnapshotOldestActive,
            YieldSite::SnapshotReadTaskInputs,
            YieldSite::FreeListPush,
            YieldSite::UndoChainHeadPublish,
            YieldSite::GcPhaseA,
            YieldSite::GcPhaseB,
            YieldSite::GcPhaseC,
            YieldSite::GcPhaseB2,
            YieldSite::GcPhaseF,
            YieldSite::GcPhaseD,
            YieldSite::GcPhaseE,
            YieldSite::WriteReadMvcc,
            YieldSite::WriteConflictCheck,
            YieldSite::WriteChainHeadUnheld,
            YieldSite::WriteLinkDelta,
        ];
        let mut codes: Vec<u16> = sites.iter().map(|s| s.code()).collect();
        codes.sort_unstable();
        let before = codes.len();
        codes.dedup();
        assert_eq!(codes.len(), before, "duplicate YieldSite discriminant");
    }

    /// With the feature off the hooks must be no-ops that any thread may call, registered or not.
    #[cfg(not(feature = "det-sched"))]
    #[test]
    fn hooks_are_inert_without_the_feature() {
        yield_at(YieldSite::FrameReadFetched, ResourceId::frame(0));
        release(YieldSite::FrameLatchRelease, ResourceId::frame(0));
        release_all(YieldSite::FrameLatchRelease);
        exempt();
        assert_eq!(history_hash(), None);
        let taken = acquire(
            YieldSite::FrameReadFetched,
            ResourceId::frame(0),
            || Some(1u8),
            || 2u8,
        );
        assert_eq!(
            taken, 2,
            "without the feature `acquire` must take the blocking path"
        );
        let h = spawn("inert", || 7u8);
        assert_eq!(h.join().expect("joined"), 7);
    }
}
