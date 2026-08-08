//! Physical-id allocation, the per-store free list, and the never-reused [`ElementId`]
//! allocator (`04-technical-design.md` §2.2, §2.7).
//!
//! Two id spaces coexist (`04 §2.2`):
//!
//! - **Physical ids** ([`PhysicalAllocator`]) are dense `u64` record numbers, *private* and
//!   *reusable*. Freed ids are pushed onto a [`FreeList`] (a WAL-logged stack, `04 §2.7`) and
//!   popped before the store is extended.
//! - **`ElementId`s** ([`ElementIdAllocator`]) are stable 128-bit public identities, allocated
//!   monotonically and **never reused** (`04 §2.2`, `D-element-id`). The allocator is *seedable*
//!   so tests are reproducible; the exact ULID/UUIDv7 text encoding is deferred (`05 §8`), so the
//!   raw `u128` is what is stored.
//!
//! Physical id `0` is reserved as the null pointer (`04 §2.2`), so both the first real physical
//! id and the first `ElementId` are `1`.
//!
//! # One latch per store (`rmp` #1012, layer 4 of #975)
//!
//! A store's physical-id state is not one number but four, and they are only correct **together**:
//! the high-water mark ([`PhysicalAllocator`]), the [`FreeList`], the `rmp` #588 shadow-hold overlay,
//! and the reuse barrier that stamps it. [`StoreAllocator`] owns all four behind **one**
//! [`Mutex`] — one per [`StoreKind`](crate::StoreKind), never one global latch — and
//! [`StoreAllocator::lock`] is the only door to mutating any of them.
//!
//! That the latch covers all four is the load-bearing part, not an implementation detail. Deciding
//! "this freed id is shadow-held, so do not hand it out" means **reading** the overlay and
//! **acting** on the free list; splitting those across two holds would not prepare the code for
//! concurrency, it would *create* a time-of-check/time-of-use window that no single-writer test can
//! observe. Every composite decision here is therefore expressed as one method on
//! [`AllocGuard`], and the borrow checker enforces it: the free list, the overlay and the barrier
//! are unreachable except through a guard, and a guard is one hold.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

use graphus_core::{ElementId, GraphusError, Result};

/// The reserved null physical id: `first_rel`/`first_prop`/`next_prop` etc. use it for "none"
/// (`04 §2.2`). Real records start at id `1`.
pub const NULL_ID: u64 = 0;

/// Allocates dense, reusable physical record ids for one store (`04 §2.2`).
///
/// `next` is the high-water mark — one past the largest id ever allocated; ids `[1, next)` have
/// existed at some point. Freed ids are reclaimed from a [`FreeList`] before `next` is bumped.
///
/// # Read without a latch, mutated only under one (`rmp` #1012)
///
/// The mark is an [`AtomicU64`], and that is what lets [`high_water`](Self::high_water) take `&self`
/// and answer **lock-free** — which it must, because it is the read path's scan bound
/// ([`StorePages::high_water`](crate::StorePages::high_water)) and is consulted once per record scan
/// and once per undo-chain hop. Putting it inside the store's mutex would have put a lock acquisition
/// on the hottest read in the engine to protect a value the reader only uses as a *ceiling*.
///
/// Every **mutation**, on the other hand, happens while the owning [`StoreAllocator`]'s latch is
/// held: the mutators below are private to this module and reachable only through [`AllocGuard`]. So
/// the atomic is not a second, competing synchronisation scheme — it is the mechanism that permits a
/// lock-free *observer*, while the latch remains the single total order over every change to the
/// store's allocation state. The atomicity is still load-bearing on its own for
/// [`try_lower`](Self::try_lower): see [`AllocGuard::unbump_fresh`].
#[derive(Debug)]
pub struct PhysicalAllocator {
    next: AtomicU64,
}

impl Default for PhysicalAllocator {
    fn default() -> Self {
        Self::new()
    }
}

impl PhysicalAllocator {
    /// A fresh allocator whose first fresh id is `1` (id `0` is the reserved null).
    #[must_use]
    pub fn new() -> Self {
        Self {
            next: AtomicU64::new(1),
        }
    }

    /// Restores an allocator whose high-water mark is `next` (one past the largest live id),
    /// used when rebuilding state on recovery.
    ///
    /// # Panics
    /// Panics if `next` is `0` (id `0` is reserved).
    #[must_use]
    pub fn restore(next: u64) -> Self {
        assert!(next >= 1, "physical id 0 is reserved as the null pointer");
        Self {
            next: AtomicU64::new(next),
        }
    }

    /// The high-water mark (one past the largest id allocated so far).
    ///
    /// Lock-free, and `Relaxed` on purpose: this value is a **bound**, never a gate. Nothing is
    /// published by advancing it — a record's bytes are published by the buffer pool's frame latch
    /// and its page by [`PageMap`](graphus_pagemap::PageMap)'s `Release`/`Acquire` `len` — so a
    /// stronger ordering here would order nothing that is not already ordered, and would cost a real
    /// barrier on `aarch64` (Apple Silicon, Raspberry Pi 5 are first-class targets).
    #[must_use]
    pub fn high_water(&self) -> u64 {
        self.next.load(Ordering::Relaxed)
    }

    /// Allocates the next fresh physical id by bumping the high-water mark.
    ///
    /// # Errors
    /// Returns a storage error if the physical-id space is exhausted (`next == u64::MAX`). This is a
    /// fail-closed bound (`rmp` #452): the release profile leaves `overflow-checks` off, so an
    /// unchecked `self.next += 1` at the ceiling would WRAP to `0` and hand out the reserved NULL id
    /// (id `0` is the "none" pointer for `first_rel`/`first_prop`/`next_prop`) as a live record id —
    /// an ACID/identity violation. `checked_add` turns that overflow into a clean error instead, and
    /// `fetch_update` applies it atomically so a check-then-add cannot let two callers at the ceiling
    /// both pass the check.
    fn alloc_fresh(&self) -> Result<u64> {
        self.next
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_add(1))
            .map_err(|_| {
                GraphusError::Storage(
                    "physical-id space exhausted: high-water mark at u64::MAX".to_owned(),
                )
            })
    }

    /// Lowers the mark from `from` to `to`, **only if it is still exactly `from`**; reports whether
    /// it moved.
    ///
    /// This is the conditional un-bump, and the condition is the whole point (`rmp` #1012). See
    /// [`AllocGuard::unbump_fresh`] for the defect an unconditional lowering reintroduces.
    fn try_lower(&self, from: u64, to: u64) -> bool {
        debug_assert!(to >= 1, "physical id 0 is reserved as the null pointer");
        self.next
            .compare_exchange(from, to, Ordering::Relaxed, Ordering::Relaxed)
            .is_ok()
    }

    /// Records that `id` has been observed (e.g. when rebuilding from a scan), keeping the
    /// high-water mark one past the largest seen id.
    ///
    /// A compare-exchange max, so it can only ever move the mark **forwards** — the same discipline
    /// as [`ElementIdAllocator::observe`], and for the same reason: this is how a rollback restores
    /// the pre-rollback floor (`rmp` #220 / #172), and a read-then-replace there would discard a
    /// concurrent writer's advance and re-hand-out an id that already names a committed record.
    fn observe(&self, id: u64) {
        let want = id.saturating_add(1);
        let _ = self
            .next
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| {
                (want > n).then_some(want)
            });
    }

    /// Replaces the mark outright (the catalog-reload path, which restores a durable image).
    fn restore_to(&self, next: u64) {
        assert!(next >= 1, "physical id 0 is reserved as the null pointer");
        self.next.store(next, Ordering::Relaxed);
    }
}

/// A WAL-logged stack of freed physical ids for one store (`04 §2.7`).
///
/// Deletion pushes the freed id; allocation pops a freed id before extending the store. The whole
/// stack is small and held in memory; [`encode`](Self::encode) / [`decode`](Self::decode) give it
/// a byte image so the store can log and recover it.
/// # Membership is O(1) (`rmp` #1024)
///
/// The stack carries a `HashSet` mirror of its own contents, so `contains` is a hash lookup rather
/// than a scan. The mirror lives **inside** this type deliberately: every mutation already goes
/// through `push` / `pop` / `remove_id` / `decode`, so there is no way for a caller to move the stack
/// and forget the index, which is exactly how a hand-maintained side index rots.
///
/// It is not a micro-optimisation. `rmp` #1024 folds an "is it already listed?" test into every free,
/// and with a linear scan that turns a rollback freeing *n* ids into O(n²) work — measured at **12×**
/// on the large-store leg of the `rmp` #970 rollback-cost test, which is precisely the regression that
/// test exists to catch. The mirror is derived state and is never encoded:
/// [`encode`](Self::encode) writes the stack alone, and [`decode`](Self::decode) rebuilds it.
///
/// A **multiset**, not a set, so that every operation is O(1) *including* `pop`. A set would force
/// `pop` to scan the stack before dropping the entry — reintroducing the linear cost on the hottest
/// path of all, allocation — and a multiset also stays honest if a malformed list ever does arrive
/// through [`decode`](Self::decode) or [`replace_free`](AllocGuard::replace_free): the count tracks
/// how many copies are really there, so `contains` cannot start lying in the direction that would
/// permit yet another push.
#[derive(Debug, Default, Clone)]
pub struct FreeList {
    stack: Vec<u64>,
    /// How many times each id appears in `stack`. Derived, never serialised — see the type docs.
    index: HashMap<u64, u32>,
}

/// Equality is decided by the **stack** alone: the index is derived from it, so two lists with equal
/// stacks are equal lists. Comparing the mirror as well would be comparing the same fact twice.
impl PartialEq for FreeList {
    fn eq(&self, other: &Self) -> bool {
        self.stack == other.stack
    }
}

impl Eq for FreeList {}

impl FreeList {
    /// An empty free list.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Pushes a freed id onto the stack.
    ///
    /// # Panics
    /// Panics if `id` is the reserved null id `0`.
    pub fn push(&mut self, id: u64) {
        assert!(id != NULL_ID, "cannot free the reserved null id 0");
        self.stack.push(id);
        *self.index.entry(id).or_insert(0u32) += 1;
    }

    /// Pops the most recently freed id, if any (LIFO reuse).
    pub fn pop(&mut self) -> Option<u64> {
        let id = self.stack.pop()?;
        if let std::collections::hash_map::Entry::Occupied(mut e) = self.index.entry(id) {
            *e.get_mut() -= 1;
            if *e.get() == 0 {
                e.remove();
            }
        }
        Some(id)
    }

    /// Removes every occurrence of `id` from the stack, preserving the relative (LIFO) order of the
    /// remaining ids.
    ///
    /// Used by [`RecordStore::rollback`](crate::store::RecordStore::rollback) to undo a rolled-back
    /// GC pass's own free-list pushes (`rmp` #578): after a live rollback restores the pre-rollback
    /// in-memory free list, the aborting transaction's pushes must be withdrawn because the WAL undo
    /// has just restored the corresponding records' `in_use` bit. A well-formed free list holds each
    /// id at most once (an id can only be freed again after being re-allocated, which pops it), so
    /// this removes exactly the transaction's push.
    pub fn remove_id(&mut self, id: u64) {
        self.stack.retain(|&x| x != id);
        self.index.remove(&id);
    }

    /// Whether `id` is currently listed, in O(1) (`rmp` #1024). See the type docs for why the mirror
    /// that makes this constant-time is not optional.
    #[must_use]
    pub fn contains(&self, id: u64) -> bool {
        self.index.contains_key(&id)
    }

    /// The number of free ids currently held.
    #[must_use]
    pub fn len(&self) -> usize {
        self.stack.len()
    }

    /// The freed ids currently held, in stack (LIFO) order. Used by the consistency checker
    /// ([`crate::check`]) to verify free-list sanity (`04 §2.7`): a freed id must not be in use and
    /// must not be referenced by any live chain.
    #[must_use]
    pub fn ids(&self) -> &[u64] {
        &self.stack
    }

    /// Whether the free list is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.stack.is_empty()
    }

    /// Serialises the free list to a byte image: `count(u32) | [id(u64)]*` (stack order).
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(4 + self.stack.len() * 8);
        out.extend_from_slice(&(self.stack.len() as u32).to_le_bytes());
        for &id in &self.stack {
            out.extend_from_slice(&id.to_le_bytes());
        }
        out
    }

    /// Rebuilds a free list from an image produced by [`encode`](Self::encode).
    ///
    /// # Errors
    /// Returns a storage error if the image is truncated.
    pub fn decode(bytes: &[u8]) -> graphus_core::Result<Self> {
        use graphus_core::GraphusError;
        if bytes.len() < 4 {
            return Err(GraphusError::Storage(
                "free-list image too short".to_owned(),
            ));
        }
        let count = u32::from_le_bytes(bytes[0..4].try_into().expect("4-byte slice")) as usize;
        let need = 4 + count * 8;
        if bytes.len() < need {
            return Err(GraphusError::Storage(
                "free-list image truncated".to_owned(),
            ));
        }
        let mut stack = Vec::with_capacity(count);
        for i in 0..count {
            let off = 4 + i * 8;
            stack.push(u64::from_le_bytes(
                bytes[off..off + 8].try_into().expect("8-byte slice"),
            ));
        }
        let mut index: HashMap<u64, u32> = HashMap::with_capacity(stack.len());
        for &id in &stack {
            *index.entry(id).or_insert(0u32) += 1;
        }
        Ok(Self { stack, index })
    }
}

/// What [`AllocGuard::allocate`] handed out, and where it came from.
///
/// The distinction is not cosmetic: a reused id's page already exists, while a fresh id's page may
/// still have to be mapped — and only the fresh one can ever need un-bumping.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Allocation {
    /// A freed id popped off the free list. Its store page is already mapped.
    Reused(u64),
    /// A fresh id taken by advancing the high-water mark. Its page must be mapped before the id is
    /// used, and the caller must [`unbump_fresh`](AllocGuard::unbump_fresh) if that mapping fails.
    Fresh(u64),
}

impl Allocation {
    /// The allocated physical id, whichever way it was obtained.
    #[must_use]
    pub fn id(self) -> u64 {
        match self {
            Allocation::Reused(id) | Allocation::Fresh(id) => id,
        }
    }
}

/// The latch-guarded half of one store's allocation state.
#[derive(Debug, Default)]
struct AllocState {
    /// Freed ids available for reuse (`04 §2.7`).
    free: FreeList,
    /// `rmp` #588 shadow-hold overlay: `id -> reuse barrier`. A freed id listed here is on the
    /// durable free list but must NOT be handed out until every off-thread reader that predates the
    /// free has retired.
    held: HashMap<u64, u64>,
}

/// The reuse barrier stamped onto every free while a bracketed GC pass runs (`rmp` #588), shared by
/// all six stores as **one** atomic (`rmp` #1025).
///
/// # Why one value and not six
///
/// Layer 4 gave each store its own copy, to buy the read-and-act atomicity that matters: `free_push`
/// reads the barrier and stamps the overlay in the same hold. That part was right. What it also
/// created was an *arming* race, because six copies are armed one latch at a time
/// (`RecordStore::set_reuse_barrier` loops over the stores). A free landing on store 5 after store 0
/// is armed and before store 5 is armed is **not stamped** — so the slot is immediately reusable, a
/// writer takes it, and an off-thread reader that predates the free and is mid-walk through that slot
/// reads a stranger's record. That is the ACID Isolation violation `rmp` #588 exists to close,
/// re-opened by the replication that was meant to make it safe.
///
/// One atomic gives what six copies structurally cannot: a **single linearisation point**. Every free
/// either precedes the arming — and legitimately goes unstamped, because the GC pass had not begun —
/// or follows it and is stamped. There is no third case. The read-and-act atomicity is untouched: the
/// load happens *inside* the store's hold, immediately before the stamp and the listing.
///
/// # The encoding, and why it is not the barrier itself
///
/// Stored as `barrier + 1`, with `0` meaning *not armed*. The barrier is an engine ticket and `0` is
/// a legal ticket value, so using it as the sentinel would silently read a genuine barrier of `0` as
/// "no GC pass running" and skip the hold. Arming at `u64::MAX` saturates rather than wrapping: that
/// errs towards holding slots longer, which costs space, where the other direction costs correctness.
#[derive(Debug, Default)]
pub struct SharedReuseBarrier(AtomicU64);

impl SharedReuseBarrier {
    /// Arms (or, with `None`, disarms) the barrier for every store at once.
    fn set(&self, barrier: Option<u64>) {
        let encoded = match barrier {
            None => 0,
            // Fail-closed on the ceiling: saturating keeps a barrier armed (slots held longer),
            // whereas wrapping would encode `u64::MAX` as `0` and disarm the hold entirely.
            Some(b) => b.saturating_add(1),
        };
        self.0.store(encoded, Ordering::Release);
    }

    /// The barrier to stamp onto a free happening now, or `None` outside a bracketed GC pass.
    fn get(&self) -> Option<u64> {
        match self.0.load(Ordering::Acquire) {
            0 => None,
            encoded => Some(encoded - 1),
        }
    }
}

/// One store's complete physical-id allocation state, and the latch that covers it (`rmp` #1012).
///
/// Six of these exist, one per [`StoreKind`](crate::StoreKind) — deliberately **not** one global
/// latch. The stores allocate independently: a writer creating a node and a writer creating a
/// relationship contend for nothing, and a GC pass reclaiming undo slots blocks neither.
///
/// # What is behind the latch, and what is not
///
/// Behind it: the free list, the `rmp` #588 shadow-hold overlay and its barrier — the three that no
/// decision can read separately from acting on. The high-water mark is an atomic
/// ([`PhysicalAllocator`]) so the read path's scan bound stays lock-free, but **every mutation of it
/// also happens under this latch**, so the latch remains a total order over every change to the
/// four together. That is what makes a composite read taken under the latch (the durable catalog
/// image, the live-record cardinality) internally consistent.
///
/// # The latch is never held across I/O — rank 25
///
/// Graphus orders its latches by rank (innermost last): **10** catalog/DDL, **20** commit sequencer
/// and active-transaction table, **25** *this latch*, **30** WAL, **40** buffer-pool frame latch,
/// **50** page-table shard, **60** device and doublewrite stager. An out-of-order acquisition is
/// permitted only as a `try_lock`, which creates no wait edge.
///
/// Rank 25 is the tightest position that is truthful. It must be **below** the active-transaction
/// table (20), because the paths that allocate and free ids are already inside a transaction and
/// record their pops and pushes in that table. It must be **above** the WAL (30) and everything
/// under it, because the hard rule of this latch is that it is **released before any I/O**: mapping a
/// fresh id's page ([`ensure_store_page`](crate::RecordStore)) grows the device, fetches pages, may
/// evict, and may harden the log — a chain that would otherwise convoy every allocator in the
/// database behind one `fdatasync`. The rule is mechanically checked in debug builds by
/// [`graphus_core::latch::assert_no_alloc_latch_held`], armed here in [`lock`](Self::lock).
#[derive(Debug)]
pub struct StoreAllocator {
    alloc: PhysicalAllocator,
    state: Mutex<AllocState>,
    /// The `rmp` #588 reuse barrier, shared with the other five stores (`rmp` #1025). Read inside
    /// this store's hold, armed globally in one atomic store. See [`SharedReuseBarrier`].
    barrier: Arc<SharedReuseBarrier>,
}

impl Default for StoreAllocator {
    fn default() -> Self {
        Self::new()
    }
}

impl StoreAllocator {
    /// A fresh, empty allocator: high-water `1`, no freed ids, no shadow holds, no barrier.
    #[must_use]
    pub fn new() -> Self {
        Self {
            alloc: PhysicalAllocator::new(),
            state: Mutex::new(AllocState::default()),
            barrier: Arc::default(),
        }
    }

    /// The same, sharing `barrier` with the other stores of one `RecordStore` (`rmp` #1025). This is
    /// the constructor the engine uses; [`new`](Self::new) leaves an allocator with a private barrier,
    /// which is right for a standalone one (a test fixture) and wrong for a store in a set of six.
    #[must_use]
    pub fn with_shared_barrier(barrier: Arc<SharedReuseBarrier>) -> Self {
        Self {
            alloc: PhysicalAllocator::new(),
            state: Mutex::new(AllocState::default()),
            barrier,
        }
    }

    /// An allocator rebuilt from a durable catalog entry: `high_water` and its freed ids. No slot is
    /// shadow-held — a store that has just been opened has no in-flight reader to protect.
    ///
    /// # Panics
    /// Panics if `high_water` is `0` (id `0` is reserved).
    #[must_use]
    pub fn restore(high_water: u64, free: FreeList) -> Self {
        Self::restore_with_shared_barrier(high_water, free, Arc::default())
    }

    /// [`restore`](Self::restore), sharing `barrier` with the other stores (`rmp` #1025).
    #[must_use]
    pub fn restore_with_shared_barrier(
        high_water: u64,
        free: FreeList,
        barrier: Arc<SharedReuseBarrier>,
    ) -> Self {
        Self {
            alloc: PhysicalAllocator::restore(high_water),
            state: Mutex::new(AllocState {
                free,
                held: HashMap::new(),
            }),
            barrier,
        }
    }

    /// The high-water mark — one past the largest id ever allocated. **Lock-free**: this is the read
    /// path's scan bound (`1..high_water`), so it must not take the latch. See
    /// [`PhysicalAllocator::high_water`].
    #[must_use]
    pub fn high_water(&self) -> u64 {
        self.alloc.high_water()
    }

    /// Takes the store's allocation latch. Everything that mutates the free list, the shadow-hold
    /// overlay, the reuse barrier or the high-water mark goes through the returned guard.
    ///
    /// # Panics
    /// Never for poisoning: a poisoned latch is recovered rather than re-panicked, matching the
    /// crate's convention ([`crate::wal_rule::SharedWal`], [`crate::dwb`]). It is sound here because
    /// each guarded operation is ordered to fail **closed** if a panic tears it — a half-done free
    /// leaves a slot shadow-held but unlisted (never handed out again; a bounded leak), and a
    /// half-done pop loses a reusable id (likewise). No partial update can produce a *live* record
    /// sharing a slot, which is the only outcome that would justify bricking the store.
    #[must_use]
    pub fn lock(&self) -> AllocGuard<'_> {
        AllocGuard {
            alloc: &self.alloc,
            barrier: &self.barrier,
            state: self
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
            _scope: graphus_core::latch::AllocLatchScope::new(),
        }
    }

    /// Allocates one physical id — a reusable freed one if the free list offers it, otherwise a fresh
    /// one — under **one** hold. See [`AllocGuard::allocate`] for why pop-or-grow cannot be two.
    ///
    /// # Errors
    /// Returns a storage error if the physical-id space is exhausted (`rmp` #452).
    pub fn allocate(&self) -> Result<Allocation> {
        self.lock().allocate()
    }

    /// Arms (or, with `None`, disarms) the `rmp` #588 reuse barrier for **every** store sharing it,
    /// as one atomic store (`rmp` #1025).
    ///
    /// Takes no hold, and must not: arming is a single global act, and taking six latches in sequence
    /// to publish one value is exactly the staggered window this replaced. The read-and-act atomicity
    /// that matters is on the other side — [`AllocGuard::push_free_shadow_held`] loads this inside the
    /// store's hold.
    pub fn arm_reuse_barrier(&self, barrier: Option<u64>) {
        self.barrier.set(barrier);
    }

    /// The barrier currently armed, as this store sees it (`rmp` #1025). Observability, and the hook
    /// the arming-atomicity test needs: with one shared atom, "store 0 sees it armed" and "store 5
    /// sees it armed" are the same fact, which is the whole property.
    #[must_use]
    pub fn armed_barrier(&self) -> Option<u64> {
        self.barrier.get()
    }

    /// A handle to this allocator's shared barrier, for building its five siblings (`rmp` #1025).
    #[must_use]
    pub fn shared_barrier(&self) -> Arc<SharedReuseBarrier> {
        Arc::clone(&self.barrier)
    }

    /// Lists `id` as free and, if a GC pass has armed a reuse barrier, shadow-holds it from reuse —
    /// under **one** hold. See [`AllocGuard::push_free_shadow_held`] for why stamping and listing
    /// cannot be two.
    pub fn free_shadow_held(&self, id: u64) {
        self.lock().push_free_shadow_held(id);
    }

    /// Lists `id` **only if it is not already listed**, shadow-holding it, under one hold; reports
    /// whether it listed it. See [`AllocGuard::push_free_shadow_held_if_absent`] for why the test and
    /// the push cannot be two holds (`rmp` #1024).
    pub fn free_shadow_held_if_absent(&self, id: u64) -> bool {
        self.lock().push_free_shadow_held_if_absent(id)
    }

    /// The same, **without** the `rmp` #588 shadow hold — the pairing of
    /// [`AllocGuard::push_free`], for the one caller (`reclaim_aborted_pops`) whose pushes were never
    /// shadow-held and must stay that way.
    pub fn free_if_absent(&self, id: u64) -> bool {
        self.lock().push_free_if_absent(id)
    }

    /// A copy of the free list — the durable catalog image, and the `rmp` #578 pre-rollback snapshot.
    #[must_use]
    pub fn free_snapshot(&self) -> FreeList {
        self.lock().free().clone()
    }

    /// Whether `id` is currently listed as free.
    #[must_use]
    pub fn free_contains(&self, id: u64) -> bool {
        self.lock().free().contains(id)
    }

    /// The freed ids currently held, in stack (LIFO) order.
    #[must_use]
    pub fn free_ids(&self) -> Vec<u64> {
        self.lock().free().ids().to_vec()
    }

    /// How many ids are currently listed as free.
    #[must_use]
    pub fn free_len(&self) -> usize {
        self.lock().free().len()
    }

    /// Whether no id is currently listed as free.
    #[must_use]
    pub fn free_is_empty(&self) -> bool {
        self.lock().free().is_empty()
    }

    /// How many slots of this store are currently shadow-held from reuse (`rmp` #588).
    #[must_use]
    pub fn held_len(&self) -> usize {
        self.lock().held_len()
    }
}

/// Exclusive access to one store's allocation state (`rmp` #1012). See [`StoreAllocator`].
///
/// Every composite decision — "pop a reusable id", "free this id and shadow-hold it" — is a single
/// method here, so that reading the state and acting on it can never be split across two holds.
#[derive(Debug)]
pub struct AllocGuard<'a> {
    alloc: &'a PhysicalAllocator,
    /// The globally-shared reuse barrier (`rmp` #1025). Loaded inside this hold, so reading it and
    /// stamping the overlay stay one indivisible decision.
    barrier: &'a SharedReuseBarrier,
    state: MutexGuard<'a, AllocState>,
    /// Debug-only marker proving no I/O happens while this guard is alive. Declared last so it is
    /// dropped **after** the latch is released: over-reporting the held region is the safe direction
    /// for a tripwire, under-reporting is not.
    _scope: graphus_core::latch::AllocLatchScope,
}

impl AllocGuard<'_> {
    /// The high-water mark. Exact while the guard is alive — no mutation can be in flight.
    #[must_use]
    pub fn high_water(&self) -> u64 {
        self.alloc.high_water()
    }

    /// Allocates one physical id: a reusable freed id if the free list offers one, otherwise a fresh
    /// id from the high-water mark.
    ///
    /// Pop-or-grow is **one** operation, under **one** hold, because the two halves are a single
    /// decision: splitting them would let another allocator slip between "the free list gave me
    /// nothing" and "so I will grow".
    ///
    /// # Errors
    /// Returns a storage error if the physical-id space is exhausted (`rmp` #452).
    pub fn allocate(&mut self) -> Result<Allocation> {
        if let Some(id) = self.pop_reusable() {
            return Ok(Allocation::Reused(id));
        }
        Ok(Allocation::Fresh(self.alloc.alloc_fresh()?))
    }

    /// Pops the next **reusable** freed id, or `None` when the free list is empty or holds only ids
    /// still shadow-held for an in-flight off-thread reader (`rmp` #588).
    ///
    /// Held ids are stashed and re-listed so they stay free for later reuse once released; if only
    /// held ids remain this returns `None` and the caller grows a fresh id rather than reusing one.
    /// On the common path (nothing shadow-held) this is the pre-#588 single pop.
    ///
    /// Consulting the overlay and popping the list happen under the one hold this guard *is*. That
    /// is the correctness requirement, not an optimisation: with two holds, a slot released between
    /// the check and the pop would be handed to a writer while a reader still threads through it —
    /// the ACID Isolation violation #588 exists to close.
    pub fn pop_reusable(&mut self) -> Option<u64> {
        if self.state.held.is_empty() {
            return self.state.free.pop();
        }
        let mut stash: Vec<u64> = Vec::new();
        let picked = loop {
            match self.state.free.pop() {
                Some(id) if self.state.held.contains_key(&id) => stash.push(id),
                other => break other,
            }
        };
        for id in stash {
            self.state.free.push(id);
        }
        picked
    }

    /// Claims a **run** of fresh ids: reads the mark, asks `end_of_run` where the run stops, and
    /// advances the mark to that point. Returns the claimed `[first, end)`.
    ///
    /// One hold, for the reason [`allocate`](Self::allocate) is one hold: the run's extent is
    /// computed *from* the mark it is about to move, so reading and advancing must be indivisible.
    /// Undo-delta slabs (`rmp` #1011) are the caller.
    ///
    /// # Monotonicity is checked in RELEASE, not asserted (`rmp` #1012)
    ///
    /// `end_of_run` is caller-supplied and this method is public, so its result is untrusted input:
    /// the guard against `end <= first` belongs in the primitive, not in every caller. It used to be a
    /// `debug_assert!` followed by an unconditional store — which means that in a release build, where
    /// `overflow-checks` and `debug_assert!` are both off, a closure returning a smaller value would
    /// have **silently lowered the mark and re-issued live ids**: exactly the defect class this whole
    /// layer exists to close, arriving through the one door left open. Refusing costs a comparison.
    ///
    /// # Errors
    /// Returns a storage error if `end_of_run` fails, or if it proposes a run that does not advance
    /// the mark. The mark is unmoved in both cases.
    pub fn claim_run<F>(&mut self, end_of_run: F) -> Result<(u64, u64)>
    where
        F: FnOnce(u64) -> Result<u64>,
    {
        let first = self.high_water().max(1);
        let end = end_of_run(first)?;
        if end <= first {
            return Err(GraphusError::Storage(format!(
                "refusing to claim the physical-id run [{first}, {end}): a run must advance the \
                 high-water mark, and applying this one would lower it — re-issuing ids that are \
                 already live (`rmp` #1012)"
            )));
        }
        self.alloc.restore_to(end);
        Ok((first, end))
    }

    /// Withdraws a fresh id that was never used — but **only if the mark has not moved on**; reports
    /// whether it was withdrawn.
    ///
    /// # Why the condition is the fix (`rmp` #1012)
    ///
    /// This was an unconditional `alloc = PhysicalAllocator::restore(id)`: a read-then-replace, the
    /// same shape as the page map's old index claim, and wrong for the same reason the moment a
    /// second writer exists. Writer A takes `id`, writer B takes `id + 1`; A's page mapping then
    /// fails and its unconditional restore drops the mark to `id` — **below** the id B is still
    /// holding. The next allocation re-issues `id + 1`, so two live records share one physical slot
    /// and their property / incidence chains self-cycle; and, until then, the catalog carries a
    /// `high_water` that no longer covers every allocated id.
    ///
    /// The compare-exchange makes "the mark is still exactly where I left it, and it is now back" a
    /// single indivisible decision. When it is not — because someone allocated after us — the
    /// withdrawal is simply declined and `id` is left accounted for: conservative in the one
    /// direction that cannot lose data (a burnt id, never a shared slot).
    ///
    /// # This is a mitigation, not the cure
    ///
    /// The real defect is that the mark is advanced **before** the id's page is mapped, so the
    /// catalog invariant `high_water <= addressable capacity` is momentarily false and needs undoing
    /// at all. Mapping the page before publishing the bump is `rmp` #1014 (layer 5b), acceptance
    /// criterion 6 — it needs the buffer pool and the WAL to be reachable under `&self`, which is
    /// that layer's subject. Until then this refuses to make the window worse, and
    /// [`StoreAllocator`]'s catalog floor refuses to *persist* a catalog written inside it.
    pub fn unbump_fresh(&mut self, id: u64) -> bool {
        self.alloc.try_lower(id.saturating_add(1), id.max(1))
    }

    /// Withdraws a whole claimed run `[first, end)` that was never used, on the same conditional
    /// terms as [`unbump_fresh`](Self::unbump_fresh); reports whether it was withdrawn.
    pub fn unbump_run(&mut self, first: u64, end: u64) -> bool {
        self.alloc.try_lower(end, first.max(1))
    }

    /// Raises the mark so that `id` is accounted for, never lowering it (`rmp` #220 / #172 floor).
    pub fn observe(&mut self, id: u64) {
        self.alloc.observe(id);
    }

    /// Restores the mark and the free list together from a durable catalog image (the rollback
    /// catalog reload). One hold, so no writer can observe the two disagreeing.
    ///
    /// The shadow-hold overlay and the barrier are deliberately **left alone**: they describe
    /// in-flight *readers*, not durable state, and a catalog reload knows nothing about them.
    ///
    /// # This LOWERS the mark unconditionally — only `reload_catalog` may call it
    ///
    /// Every other mutator here either advances the mark or withdraws conditionally
    /// ([`unbump_fresh`](Self::unbump_fresh), [`claim_run`](Self::claim_run)), because lowering it
    /// underneath a live id re-issues that id. This one lowers it flat, so it is sound **only** in the
    /// one situation where lowering is the point: replacing the whole in-memory image with the last
    /// durably-committed one during
    /// [`RecordStore::reload_catalog`](crate::RecordStore). Even there it is only *half* the answer —
    /// the durable image predates every concurrent open transaction's allocations, so the caller MUST
    /// re-floor the mark afterwards with [`observe`](Self::observe) over the pre-rollback high-water
    /// (`rmp` #220 / #172). Calling this from anywhere else silently lowers the mark under a live
    /// writer, and nothing downstream will notice until two records share a slot.
    ///
    /// # Panics
    /// Panics if `high_water` is `0` (id `0` is reserved).
    pub fn restore(&mut self, high_water: u64, free: FreeList) {
        self.alloc.restore_to(high_water);
        self.state.free = free;
    }

    /// Replaces just the free list (the `rmp` #578 pre-rollback restore).
    pub fn replace_free(&mut self, free: FreeList) {
        self.state.free = free;
    }

    /// Lists `id` as free.
    pub fn push_free(&mut self, id: u64) {
        self.state.free.push(id);
    }

    /// Lists `id` as free **and**, if a GC pass has armed a reuse barrier, shadow-holds it from reuse
    /// until every reader that predates the free has retired (`rmp` #588).
    ///
    /// Reading the barrier, stamping the overlay and listing the id are one hold — the free list must
    /// never be able to offer an id whose stamp has not landed yet.
    ///
    /// The stamp is written **before** the id is listed, so a panic between them fails closed: an
    /// unlisted-but-held id can never be handed out, whereas a listed-but-unstamped one could.
    pub fn push_free_shadow_held(&mut self, id: u64) {
        // The load is INSIDE this hold (`rmp` #1025): reading the barrier and stamping the overlay
        // remain one decision, exactly as when the barrier was a per-store field. What changed is that
        // the value read is global, so a free cannot land between one store being armed and another.
        if let Some(barrier) = self.barrier.get() {
            self.state.held.insert(id, barrier);
        }
        self.state.free.push(id);
    }

    /// Lists `id` **only if it is not already listed**, shadow-holding it as
    /// [`push_free_shadow_held`](Self::push_free_shadow_held) does; reports whether it listed it.
    ///
    /// # This exists so the caller cannot get it wrong (`rmp` #1024)
    ///
    /// "Is it already listed?" and "list it" are **one** decision. Split across two holds — even two
    /// holds a microsecond apart — two reclaimers can both observe the id absent and both push it, and
    /// a free list holding the same id twice hands one physical slot to two writers. That is the
    /// `rmp` #578 duplicate-free-list-entry shape: two live records in one slot, whose property /
    /// incidence chains then self-cycle. [`FreeList::remove_id`](FreeList::remove_id)'s contract
    /// ("a well-formed free list holds each id at most once") depends on it never happening.
    ///
    /// Before the per-store latch of `rmp` #1012 the pairing was free: every caller held `&mut
    /// RecordStore`, so the test and the push were atomic whether the author thought about it or not.
    /// Turning that borrow into a latch acquisition removed the guarantee without changing a line of
    /// the logic — the classic hazard of this refactor — and left three call sites deciding under one
    /// hold and acting under another, one of them with a **WAL write** in the gap.
    ///
    /// So the primitive takes the whole decision. A caller that must do I/O first (reading a record to
    /// prove the slot unreferenced) does it **outside** any hold, as latch rank 25 requires, and then
    /// calls this — which re-tests inside the hold that acts, rather than trusting what it read
    /// earlier. Impossible-by-construction, instead of correct-by-caller-discipline.
    pub fn push_free_shadow_held_if_absent(&mut self, id: u64) -> bool {
        if self.state.free.contains(id) {
            return false;
        }
        self.push_free_shadow_held(id);
        true
    }

    /// [`push_free_if_absent`](Self::push_free_shadow_held_if_absent) without the `rmp` #588 hold —
    /// the pairing of [`push_free`](Self::push_free), for the one caller that must not shadow-hold.
    pub fn push_free_if_absent(&mut self, id: u64) -> bool {
        if self.state.free.contains(id) {
            return false;
        }
        self.push_free(id);
        true
    }

    /// Removes every occurrence of `id` from the free list (`rmp` #578 rollback withdrawal).
    pub fn remove_free_id(&mut self, id: u64) {
        self.state.free.remove_id(id);
    }

    /// The free list, for inspection (the consistency checker and the durable catalog image).
    #[must_use]
    pub fn free(&self) -> &FreeList {
        &self.state.free
    }

    /// Sets (or clears) the reuse barrier stamped onto subsequent frees (`rmp` #588).
    ///
    /// Arms it for **every** store sharing this barrier, in one atomic store (`rmp` #1025) — it is no
    /// longer this store's own field. Kept on the guard because callers already hold one and because
    /// arming is meaningless outside a store's context, but note that it does not need the hold: see
    /// [`StoreAllocator::arm_reuse_barrier`], which is what the engine calls.
    pub fn set_reuse_barrier(&mut self, barrier: Option<u64>) {
        self.barrier.set(barrier);
    }

    /// Releases every shadow-held slot whose barrier `b` satisfies `b <= oldest_open_ticket` — i.e.
    /// every reader that predated the free has retired (`rmp` #588). `u64::MAX` releases everything.
    pub fn release_held(&mut self, oldest_open_ticket: u64) {
        if !self.state.held.is_empty() {
            self.state
                .held
                .retain(|_id, &mut barrier| barrier > oldest_open_ticket);
        }
    }

    /// How many slots are currently shadow-held from reuse.
    #[must_use]
    pub fn held_len(&self) -> usize {
        self.state.held.len()
    }

    /// Whether `id` is currently shadow-held from reuse.
    #[must_use]
    pub fn is_shadow_held(&self, id: u64) -> bool {
        self.state.held.contains_key(&id)
    }
}

/// Allocates stable, never-reused 128-bit [`ElementId`]s (`04 §2.2`, `D-element-id`).
///
/// Deterministic and seedable: starting from `seed`, each allocation returns the seed and bumps
/// it by one, so a test that seeds the same value gets the same id stream. The raw `u128` is the
/// stored identity (text encoding deferred per `05 §8`).
///
/// # Lock-free, and why it is allowed to be (`rmp` #1012)
///
/// Every allocation is a `fetch_add`, so `N` writer threads may mint identities at once without a
/// latch. That is sound because this counter owes **monotonicity, not total order**: an `ElementId`
/// is an identity, never a position — nothing reads it to order two events, and no invariant relates
/// one id to another. Two concurrent allocations may therefore be handed out in either order, as long
/// as they are handed out *once each*, which is exactly what `fetch_add` guarantees and what a
/// read-then-write does not.
///
/// The alternative was a `Mutex`, and it was rejected on the objective this sprint exists for: an
/// identity is minted for **every node and every relationship created**, so a lock here would
/// serialise the write path at its hottest point — reintroducing, one layer down, precisely the
/// single-writer bottleneck the multi-writer work removes.
///
/// # The counter is 64-bit, and the identity stays 128-bit
///
/// Rust has no `AtomicU128`, so the live counter is an [`AtomicU64`] widened to `u128` on the way
/// out. That narrows the *allocable* range, not the *type*: ids are handed out from `1..=u64::MAX`,
/// which at a sustained billion identities per second is over five centuries of allocation, while
/// `ElementId` remains the 128-bit value `04 §2.2` specifies and every stored, encoded and
/// wire-visible identity is unchanged.
///
/// Both doors into the counter fail closed rather than truncating: a seed from the durable catalog
/// above `u64::MAX` is refused ([`try_new`](Self::try_new)) instead of being wrapped into a value
/// that would re-issue live identities, and exhaustion is refused instead of wrapping to the
/// reserved `ElementId(0)`.
#[derive(Debug)]
pub struct ElementIdAllocator {
    /// One past the largest identity handed out. Monotone by construction: it is only ever advanced,
    /// by `fetch_add` here and by a compare-exchange max in [`observe`](Self::observe).
    next: AtomicU64,
}

impl Default for ElementIdAllocator {
    fn default() -> Self {
        Self::new(1)
    }
}

impl Clone for ElementIdAllocator {
    /// A snapshot of the counter's current value, not a shared handle. The only callers are the
    /// catalog paths that copy a store's allocator state around; an allocator is never *shared* by
    /// cloning it (the live one is shared by reference).
    fn clone(&self) -> Self {
        Self {
            next: AtomicU64::new(self.next.load(Ordering::Relaxed)),
        }
    }
}

impl PartialEq for ElementIdAllocator {
    fn eq(&self, other: &Self) -> bool {
        self.next.load(Ordering::Relaxed) == other.next.load(Ordering::Relaxed)
    }
}

impl Eq for ElementIdAllocator {}

impl ElementIdAllocator {
    /// A new allocator whose first id is `seed`.
    ///
    /// # Panics
    /// Panics if `seed` is `0` (an `ElementId` of `0` would collide with "absent") or if it exceeds
    /// the allocable range (see [`try_new`](Self::try_new) for the fallible form every path that
    /// reads a seed from durable state must use instead).
    #[must_use]
    pub fn new(seed: u128) -> Self {
        Self::try_new(seed).expect("element-id seed within the allocable range")
    }

    /// A new allocator whose first id is `seed`, refusing a seed outside the allocable range.
    ///
    /// # Errors
    /// Returns a storage error if `seed` is `0`, or above `u64::MAX`. The second is the case that
    /// matters: a seed comes from the durable catalog, so a corrupt or adversarial one must not be
    /// truncated into the live range — that would re-issue identities that already name committed
    /// entities.
    pub fn try_new(seed: u128) -> Result<Self> {
        if seed == 0 {
            return Err(GraphusError::Storage(
                "element-id seed 0 is reserved as the absent id".to_owned(),
            ));
        }
        let seed = u64::try_from(seed).map_err(|_| {
            GraphusError::Storage(format!(
                "element-id seed {seed} exceeds the allocable range (ceiling {})",
                u64::MAX
            ))
        })?;
        Ok(Self {
            next: AtomicU64::new(seed),
        })
    }

    /// The next id this allocator will hand out (one past the largest allocated so far).
    #[must_use]
    pub fn peek(&self) -> u128 {
        u128::from(self.next.load(Ordering::Relaxed))
    }

    /// Allocates the next [`ElementId`], advancing the counter. Never reused (`04 §2.2`).
    ///
    /// Takes `&self`: `N` writers may allocate concurrently, each receiving a distinct identity. See
    /// the type docs for why monotonicity alone is the right contract here.
    ///
    /// # Errors
    /// Returns a storage error if the allocable range is exhausted. The release profile leaves
    /// `overflow-checks` off, so an unchecked bump at the ceiling would WRAP to `0` and hand out the
    /// reserved "absent" `ElementId(0)` as a live identity (`rmp` #452). `fetch_update` fails closed
    /// instead, and it does so atomically — a check-then-add would let two threads at the ceiling
    /// both pass the check.
    pub fn alloc(&self) -> Result<ElementId> {
        let id = self
            .next
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_add(1))
            .map_err(|_| {
                GraphusError::Storage(format!(
                    "element-id space exhausted: next id at the ceiling {}",
                    u64::MAX
                ))
            })?;
        Ok(ElementId(u128::from(id)))
    }

    /// Records that `id` has already been issued, so future allocations never collide with it
    /// (used when rebuilding from a scan of existing records).
    ///
    /// A saturating compare-exchange max, so it is safe against a concurrent [`alloc`](Self::alloc)
    /// and against another `observe`: the counter only ever moves forwards, and a racing pair leaves
    /// it at the larger of the two. An id outside the allocable range raises the counter to the
    /// ceiling rather than wrapping, which makes the next `alloc` fail closed.
    pub fn observe(&self, id: ElementId) {
        let want = u64::try_from(id.0).unwrap_or(u64::MAX).saturating_add(1);
        let _ = self
            .next
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| {
                (want > n).then_some(want)
            });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn physical_ids_start_at_one_and_are_monotonic() {
        let a = PhysicalAllocator::new();
        assert_eq!(a.alloc_fresh().unwrap(), 1);
        assert_eq!(a.alloc_fresh().unwrap(), 2);
        assert_eq!(a.high_water(), 3);
    }

    #[test]
    fn observe_keeps_high_water_ahead() {
        let a = PhysicalAllocator::new();
        a.observe(10);
        assert_eq!(a.alloc_fresh().unwrap(), 11);
    }

    /// Regression (`rmp` #452): a `PhysicalAllocator` restored at the `u64::MAX` ceiling (e.g. from a
    /// corrupt-but-CRC-valid catalog) must FAIL the next `alloc_fresh` rather than wrap to `0` and
    /// hand out the reserved NULL id. Because `[profile.release]` leaves `overflow-checks` off, an
    /// unchecked `+= 1` here would silently return `0` in a release build; `checked_add` errors.
    #[test]
    fn alloc_fresh_at_u64_max_ceiling_errors_instead_of_wrapping_to_null() {
        let a = PhysicalAllocator::restore(u64::MAX);
        // The id at the ceiling is itself `u64::MAX` — but advancing past it overflows, so the call
        // must report the exhausted space and must NOT have produced (or be about to produce) `0`.
        let err = a.alloc_fresh();
        assert!(
            err.is_err(),
            "alloc_fresh at u64::MAX must fail closed, not wrap to the reserved NULL id"
        );
        // The high-water mark is unchanged by the failed allocation (no silent advance to `0`).
        assert_eq!(a.high_water(), u64::MAX);
        // And it keeps failing — it never resurrects as id `0`.
        assert!(a.alloc_fresh().is_err());
        assert_ne!(a.high_water(), NULL_ID);
    }

    // ----------------------- StoreAllocator (`rmp` #1012) ------------------------

    /// **A withdrawal that would drop the mark below a live id is REFUSED** (`rmp` #1012).
    ///
    /// This is restriction (a) of layer 4, and it is deterministic: it needs no threads, only the
    /// *order* two writers can produce. `A` takes an id, `B` takes the next one, then `A`'s page
    /// mapping fails. An unconditional `restore(id)` — what this replaced — would drop the mark to
    /// `A`'s id, below the id `B` is still holding, and the very next allocation would issue `B`'s id
    /// a **second** time: two live records in one physical slot, whose property / incidence chains
    /// then self-cycle (the `rmp` #578 shape), plus a catalog whose `high_water` no longer covers
    /// every allocated id (the `rmp` #479 / VOPR seed 5043221 shape).
    #[test]
    fn a_withdrawal_is_refused_once_another_allocation_has_moved_the_mark() {
        let alloc = StoreAllocator::new();
        let a = alloc.allocate().expect("space");
        let b = alloc.allocate().expect("space");
        assert_eq!((a, b), (Allocation::Fresh(1), Allocation::Fresh(2)));
        assert_eq!(alloc.high_water(), 3);

        // `A`'s mapping fails *after* `B` has already taken id 2.
        assert!(
            !alloc.lock().unbump_fresh(a.id()),
            "the withdrawal must be DECLINED: the mark has moved on, and lowering it would drop it \
             below id 2, which another allocation is still holding"
        );
        assert_eq!(
            alloc.high_water(),
            3,
            "a declined withdrawal must leave the mark exactly where it was"
        );

        // And the proof that matters: no id is ever issued twice.
        let c = alloc.allocate().expect("space");
        assert_eq!(
            c,
            Allocation::Fresh(3),
            "the next allocation must continue past the ids still outstanding, never re-issue one"
        );

        // The conditional withdrawal still WORKS when it is the sound thing to do — nothing has
        // allocated since, so `c` really is the last id out and can be handed back.
        assert!(alloc.lock().unbump_fresh(c.id()));
        assert_eq!(alloc.high_water(), 3);
    }

    /// A claimed run is withdrawn on the same terms: only while the mark is still at its end.
    #[test]
    fn a_run_withdrawal_is_refused_once_another_claim_has_moved_the_mark() {
        let alloc = StoreAllocator::new();
        let (first_a, end_a) = alloc
            .lock()
            .claim_run(|first| Ok(first + 8))
            .expect("first run");
        let (first_b, end_b) = alloc
            .lock()
            .claim_run(|first| Ok(first + 8))
            .expect("second run");
        assert_eq!((first_a, end_a), (1, 9));
        assert_eq!(
            (first_b, end_b),
            (9, 17),
            "runs are claimed from the mark under one hold, so they never overlap"
        );

        assert!(
            !alloc.lock().unbump_run(first_a, end_a),
            "withdrawing the FIRST run would strand the second one above the mark"
        );
        assert_eq!(alloc.high_water(), 17);
        assert!(
            alloc.lock().unbump_run(first_b, end_b),
            "the last run out is still withdrawable"
        );
        assert_eq!(alloc.high_water(), 9);
    }

    /// **A run that would lower the mark is REFUSED, in release as in debug** (`rmp` #1012).
    ///
    /// `claim_run` is public and its extent comes from a caller-supplied closure, so the closure's
    /// result is untrusted input. It used to be guarded by a `debug_assert!` in front of an
    /// unconditional store — meaning that in a release build (no `debug_assert!`, no
    /// `overflow-checks`) a closure returning a smaller value would have silently lowered the mark and
    /// re-issued live ids: the exact defect this layer exists to close, coming through the one door
    /// left open. This test runs in both profiles because the guard is now a real branch.
    #[test]
    fn a_run_that_would_lower_the_mark_is_refused() {
        let alloc = StoreAllocator::new();
        let (_, end) = alloc.lock().claim_run(|first| Ok(first + 16)).expect("run");
        assert_eq!(alloc.high_water(), end);

        for proposed in [1u64, 5, end - 1, end] {
            let err = alloc.lock().claim_run(|_| Ok(proposed));
            assert!(
                err.is_err(),
                "a run ending at {proposed} does not advance the mark ({end}) and must be refused"
            );
            assert_eq!(
                alloc.high_water(),
                end,
                "a refused run must leave the mark exactly where it was"
            );
        }

        // And the ids the first run claimed are still accounted for: nothing was re-issued.
        assert_eq!(
            alloc.lock().allocate().expect("space"),
            Allocation::Fresh(end)
        );

        // A propagated closure error also moves nothing.
        let err = alloc
            .lock()
            .claim_run(|_| Err(graphus_core::GraphusError::Storage("no slab".to_owned())));
        assert!(err.is_err());
        assert_eq!(alloc.high_water(), end + 1);
    }

    /// **A shadow-held slot is never handed out, and reading the overlay is part of the pop**
    /// (`rmp` #588 through the `rmp` #1012 API).
    ///
    /// The check and the pop are one hold because they are one decision. Split, a slot released
    /// between them goes to a writer while an off-thread reader is still threading through it.
    #[test]
    fn a_shadow_held_slot_is_skipped_until_it_is_released() {
        let alloc = StoreAllocator::restore(100, FreeList::new());
        // A GC pass frees three slots with a barrier armed.
        {
            let mut g = alloc.lock();
            g.set_reuse_barrier(Some(7));
            for id in [10, 20, 30] {
                g.push_free_shadow_held(id);
            }
            g.set_reuse_barrier(None);
        }
        assert_eq!(alloc.held_len(), 3);
        assert_eq!(alloc.free_len(), 3, "the ids ARE listed as free, just held");

        // Every allocation grows instead of reusing a held slot...
        for expected in 100..105 {
            assert_eq!(
                alloc.allocate().expect("space"),
                Allocation::Fresh(expected),
                "a shadow-held slot must never be reused while a predating reader may hold it"
            );
        }
        // ...and the held ids are still on the free list afterwards (stashed and re-listed, never
        // dropped), so no space is lost.
        let mut still_free = alloc.free_ids();
        still_free.sort_unstable();
        assert_eq!(still_free, vec![10, 20, 30]);

        // Once every predating reader has retired, they become reusable — LIFO, as before #588.
        alloc.lock().release_held(7);
        assert_eq!(alloc.held_len(), 0);
        let mut reused = Vec::new();
        for _ in 0..3 {
            match alloc.allocate().expect("space") {
                Allocation::Reused(id) => reused.push(id),
                Allocation::Fresh(id) => panic!("expected reuse, grew to {id}"),
            }
        }
        reused.sort_unstable();
        assert_eq!(reused, vec![10, 20, 30]);
    }

    /// The barrier is read and the hold stamped inside the same operation that lists the id, so the
    /// free list can never offer an id whose stamp has not landed.
    #[test]
    fn freeing_under_an_armed_barrier_stamps_before_it_lists() {
        let alloc = StoreAllocator::restore(50, FreeList::new());
        alloc.lock().set_reuse_barrier(Some(42));
        alloc.free_shadow_held(5);
        let g = alloc.lock();
        assert!(g.is_shadow_held(5));
        assert!(g.free().ids().contains(&5));
        drop(g);

        // No barrier armed => listed, not held: the pre-#588 immediate-reuse path.
        alloc.lock().set_reuse_barrier(None);
        alloc.free_shadow_held(6);
        let g = alloc.lock();
        assert!(!g.is_shadow_held(6));
        assert!(g.free().ids().contains(&6));
    }

    /// `allocate` prefers reuse over growth, and reports which it did — the distinction the caller
    /// needs, since only a fresh id can require a page to be mapped.
    #[test]
    fn allocate_prefers_reuse_and_reports_its_provenance() {
        let mut free = FreeList::new();
        free.push(3);
        let alloc = StoreAllocator::restore(10, free);
        assert_eq!(alloc.allocate().unwrap(), Allocation::Reused(3));
        assert_eq!(alloc.allocate().unwrap(), Allocation::Fresh(10));
        assert_eq!(alloc.high_water(), 11);
    }

    /// Exhaustion still fails closed through the latched API — a wrapped mark would hand out the
    /// reserved NULL id (`rmp` #452).
    #[test]
    fn allocate_at_the_ceiling_fails_closed_through_the_latch() {
        let alloc = StoreAllocator::restore(u64::MAX, FreeList::new());
        assert!(alloc.allocate().is_err());
        assert_eq!(alloc.high_water(), u64::MAX);
        assert_ne!(alloc.high_water(), NULL_ID);
    }

    /// **The allocator is shareable across threads — the point of layer 4** (`rmp` #1012).
    ///
    /// Asserted by the compiler rather than described in prose: if a later change puts a `Cell`, an
    /// `Rc` or a raw pointer inside the guarded state, this stops compiling instead of quietly
    /// un-sharing the store one layer above.
    #[test]
    fn the_store_allocator_is_send_and_sync() {
        const fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<StoreAllocator>();
        assert_send_sync::<PhysicalAllocator>();
        assert_send_sync::<Allocation>();
    }

    /// **Two allocation latches at once are refused** (`rmp` #1012) — the real shape, at the
    /// `StoreAllocator` level rather than at the raw scope.
    ///
    /// Two rank-25 latches cannot be sequenced *by* rank, so two threads that take a different pair in
    /// a different order deadlock. Nothing in the store needs to hold two: every composite decision
    /// lives inside one store's guard. The reachable way to violate it is
    /// [`AllocGuard::claim_run`], whose closure runs with the latch held — a closure that reached for
    /// a second store's allocator would deadlock and pass every test that only checks results.
    #[cfg(debug_assertions)]
    #[test]
    #[should_panic(expected = "Rank 25 is not re-entrant")]
    fn holding_two_store_latches_at_once_is_refused() {
        let node = StoreAllocator::new();
        let rel = StoreAllocator::new();
        let _a = node.lock();
        let _b = rel.lock();
    }

    /// ...and the same latch taken twice **in sequence** is fine, which is what every six-store loop
    /// (`set_reuse_barrier`, `release_held`, the catalog image) relies on.
    #[test]
    fn taking_the_six_latches_one_after_another_is_fine() {
        let stores: Vec<StoreAllocator> = (0..6).map(|_| StoreAllocator::new()).collect();
        for s in &stores {
            s.lock().set_reuse_barrier(Some(7));
        }
        for s in &stores {
            s.free_shadow_held(1);
        }
        assert!(stores.iter().all(|s| s.held_len() == 1));
    }

    /// **The rank-25 tripwire is actually armed by `lock()`** (`rmp` #1012).
    ///
    /// [`graphus_core::latch`] proves the assertion *fires* when the depth is non-zero; this proves
    /// the depth is non-zero exactly while an [`AllocGuard`] is alive. Without this link the tripwire
    /// at `ensure_store_page` and at the WAL barrier would be permanently satisfied and would prove
    /// nothing — a dead guard that reads as a live one.
    #[test]
    fn holding_the_latch_arms_the_no_io_tripwire() {
        use graphus_core::latch::alloc_latch_depth;
        let alloc = StoreAllocator::new();
        assert_eq!(alloc_latch_depth(), 0);
        {
            let _g = alloc.lock();
            #[cfg(debug_assertions)]
            assert_eq!(
                alloc_latch_depth(),
                1,
                "StoreAllocator::lock must arm the rank-25 scope, or the I/O tripwires are dead"
            );
        }
        assert_eq!(
            alloc_latch_depth(),
            0,
            "the scope must unwind with the guard, or every later barrier would false-alarm"
        );
        // The convenience wrappers take and release the latch too — the depth must not leak.
        let _ = alloc.allocate();
        alloc.free_shadow_held(1);
        let _ = alloc.free_len();
        assert_eq!(alloc_latch_depth(), 0);
    }

    #[test]
    fn free_list_reuses_lifo() {
        let mut f = FreeList::new();
        f.push(5);
        f.push(9);
        assert_eq!(f.pop(), Some(9));
        assert_eq!(f.pop(), Some(5));
        assert_eq!(f.pop(), None);
    }

    #[test]
    #[should_panic(expected = "reserved null id 0")]
    fn free_list_rejects_freeing_the_null_id() {
        FreeList::new().push(NULL_ID);
    }

    #[test]
    fn free_list_round_trips() {
        let mut f = FreeList::new();
        f.push(3);
        f.push(7);
        f.push(1);
        let back = FreeList::decode(&f.encode()).unwrap();
        assert_eq!(back, f);
    }

    #[test]
    fn element_ids_are_seedable_and_never_repeat() {
        let a = ElementIdAllocator::new(100);
        assert_eq!(a.alloc().unwrap(), ElementId(100));
        assert_eq!(a.alloc().unwrap(), ElementId(101));
        // Same seed -> same stream (reproducible).
        let b = ElementIdAllocator::new(100);
        assert_eq!(b.alloc().unwrap(), ElementId(100));
    }

    #[test]
    fn element_id_observe_prevents_collision() {
        let a = ElementIdAllocator::new(1);
        a.observe(ElementId(50));
        assert_eq!(a.alloc().unwrap(), ElementId(51));
    }

    /// Regression (`rmp` #452): an `ElementIdAllocator` seeded at the `u128::MAX` ceiling must FAIL
    /// the next `alloc` rather than wrap to `0` and hand out the reserved "absent" `ElementId(0)`.
    /// Same release-profile wrap hazard as the physical allocator above.
    #[test]
    fn element_id_alloc_at_the_ceiling_errors_instead_of_wrapping_to_absent() {
        // One below the ceiling still allocates, and lands the counter ON it.
        let a = ElementIdAllocator::new(u128::from(u64::MAX) - 1);
        assert_eq!(a.alloc().unwrap(), ElementId(u128::from(u64::MAX) - 1));
        assert_eq!(a.peek(), u128::from(u64::MAX));
        // At the ceiling the counter can no longer advance, so the identity is refused rather than
        // handed out with a wrapped counter behind it. The ceiling value itself is therefore never
        // issued — conservative by one id, which is the direction that cannot collide.
        assert!(
            a.alloc().is_err(),
            "alloc at the ceiling must fail closed, not wrap to the reserved absent id 0"
        );
        assert_eq!(
            a.peek(),
            u128::from(u64::MAX),
            "a refused alloc must leave the counter exactly where it was, never wrapped to 0"
        );
    }

    /// **A seed above the allocable range is refused, not truncated** (`rmp` #1012).
    ///
    /// The counter is a 64-bit atomic widened to `u128` on the way out, and the seed it is built from
    /// comes off the durable catalog. Truncating an out-of-range seed would silently restart the
    /// identity stream inside the live range and re-issue identities that already name committed
    /// entities — a corruption, where refusing is merely an unopenable store that says why.
    #[test]
    fn an_element_id_seed_above_the_allocable_range_is_refused() {
        let err = ElementIdAllocator::try_new(u128::from(u64::MAX) + 1);
        assert!(err.is_err(), "an out-of-range seed must be refused");
        assert!(
            ElementIdAllocator::try_new(u128::from(u64::MAX)).is_ok(),
            "the ceiling itself is in range"
        );
        assert!(ElementIdAllocator::try_new(0).is_err(), "0 is reserved");
    }

    /// **`N` threads never receive the same identity** (`rmp` #1012) — the property that lets the
    /// allocator take `&self` at all. An `ElementId` names an entity, so a repeat is two entities
    /// sharing one public identity: a duplicate the whole `04 §2.2` contract exists to forbid.
    #[test]
    fn concurrent_allocation_never_repeats_an_identity() {
        use std::sync::Arc;
        const THREADS: usize = 8;
        const PER_THREAD: usize = 5_000;
        let a = Arc::new(ElementIdAllocator::new(1));

        let handles: Vec<_> = (0..THREADS)
            .map(|_| {
                let a = Arc::clone(&a);
                std::thread::spawn(move || {
                    (0..PER_THREAD)
                        .map(|_| a.alloc().expect("space is not exhausted").0)
                        .collect::<Vec<u128>>()
                })
            })
            .collect();

        let mut all: Vec<u128> = handles
            .into_iter()
            .flat_map(|h| h.join().expect("allocator thread panicked"))
            .collect();
        all.sort_unstable();
        let total = THREADS * PER_THREAD;
        assert_eq!(all.len(), total);
        all.dedup();
        assert_eq!(
            all.len(),
            total,
            "two threads received the same ElementId: a public identity was issued twice"
        );
        assert_eq!(
            a.peek(),
            (total + 1) as u128,
            "the counter must account for every identity handed out"
        );
    }

    #[test]
    #[should_panic(expected = "element-id seed 0 is reserved")]
    fn element_id_seed_zero_is_rejected() {
        let _ = ElementIdAllocator::new(0);
    }
}
