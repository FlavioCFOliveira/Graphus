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

use std::sync::atomic::{AtomicU64, Ordering};

use graphus_core::{ElementId, GraphusError, Result};

/// The reserved null physical id: `first_rel`/`first_prop`/`next_prop` etc. use it for "none"
/// (`04 §2.2`). Real records start at id `1`.
pub const NULL_ID: u64 = 0;

/// Allocates dense, reusable physical record ids for one store (`04 §2.2`).
///
/// `next` is the high-water mark — one past the largest id ever allocated; ids `[1, next)` have
/// existed at some point. Freed ids are reclaimed from a [`FreeList`] before `next` is bumped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PhysicalAllocator {
    next: u64,
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
        Self { next: 1 }
    }

    /// Restores an allocator whose high-water mark is `next` (one past the largest live id),
    /// used when rebuilding state on recovery.
    ///
    /// # Panics
    /// Panics if `next` is `0` (id `0` is reserved).
    #[must_use]
    pub fn restore(next: u64) -> Self {
        assert!(next >= 1, "physical id 0 is reserved as the null pointer");
        Self { next }
    }

    /// The high-water mark (one past the largest id allocated so far).
    #[must_use]
    pub fn high_water(self) -> u64 {
        self.next
    }

    /// Allocates the next fresh physical id by bumping the high-water mark.
    ///
    /// # Errors
    /// Returns a storage error if the physical-id space is exhausted (`next == u64::MAX`). This is a
    /// fail-closed bound (`rmp` #452): the release profile leaves `overflow-checks` off, so an
    /// unchecked `self.next += 1` at the ceiling would WRAP to `0` and hand out the reserved NULL id
    /// (id `0` is the "none" pointer for `first_rel`/`first_prop`/`next_prop`) as a live record id —
    /// an ACID/identity violation. `checked_add` turns that overflow into a clean error instead.
    pub fn alloc_fresh(&mut self) -> Result<u64> {
        let id = self.next;
        self.next = self.next.checked_add(1).ok_or_else(|| {
            GraphusError::Storage(
                "physical-id space exhausted: high-water mark at u64::MAX".to_owned(),
            )
        })?;
        Ok(id)
    }

    /// Records that `id` has been observed (e.g. when rebuilding from a scan), keeping the
    /// high-water mark one past the largest seen id.
    pub fn observe(&mut self, id: u64) {
        if id >= self.next {
            self.next = id + 1;
        }
    }
}

/// A WAL-logged stack of freed physical ids for one store (`04 §2.7`).
///
/// Deletion pushes the freed id; allocation pops a freed id before extending the store. The whole
/// stack is small and held in memory; [`encode`](Self::encode) / [`decode`](Self::decode) give it
/// a byte image so the store can log and recover it.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct FreeList {
    stack: Vec<u64>,
}

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
    }

    /// Pops the most recently freed id, if any (LIFO reuse).
    pub fn pop(&mut self) -> Option<u64> {
        self.stack.pop()
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
        Ok(Self { stack })
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
        let mut a = PhysicalAllocator::new();
        assert_eq!(a.alloc_fresh().unwrap(), 1);
        assert_eq!(a.alloc_fresh().unwrap(), 2);
        assert_eq!(a.high_water(), 3);
    }

    #[test]
    fn observe_keeps_high_water_ahead() {
        let mut a = PhysicalAllocator::new();
        a.observe(10);
        assert_eq!(a.alloc_fresh().unwrap(), 11);
    }

    /// Regression (`rmp` #452): a `PhysicalAllocator` restored at the `u64::MAX` ceiling (e.g. from a
    /// corrupt-but-CRC-valid catalog) must FAIL the next `alloc_fresh` rather than wrap to `0` and
    /// hand out the reserved NULL id. Because `[profile.release]` leaves `overflow-checks` off, an
    /// unchecked `+= 1` here would silently return `0` in a release build; `checked_add` errors.
    #[test]
    fn alloc_fresh_at_u64_max_ceiling_errors_instead_of_wrapping_to_null() {
        let mut a = PhysicalAllocator::restore(u64::MAX);
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
