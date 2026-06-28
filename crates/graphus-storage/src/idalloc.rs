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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ElementIdAllocator {
    next: u128,
}

impl Default for ElementIdAllocator {
    fn default() -> Self {
        Self::new(1)
    }
}

impl ElementIdAllocator {
    /// A new allocator whose first id is `seed`.
    ///
    /// # Panics
    /// Panics if `seed` is `0` (an `ElementId` of `0` would collide with "absent").
    #[must_use]
    pub fn new(seed: u128) -> Self {
        assert!(seed != 0, "ElementId 0 is reserved as the absent id");
        Self { next: seed }
    }

    /// The next id this allocator will hand out (one past the largest allocated so far).
    #[must_use]
    pub fn peek(self) -> u128 {
        self.next
    }

    /// Allocates the next [`ElementId`], advancing the counter. Never reused (`04 §2.2`).
    ///
    /// # Errors
    /// Returns a storage error if the 128-bit identity space is exhausted (`next == u128::MAX`). As
    /// with [`PhysicalAllocator::alloc_fresh`], the release profile leaves `overflow-checks` off, so
    /// an unchecked `self.next += 1` at the ceiling would WRAP to `0` and hand out the reserved
    /// "absent" `ElementId(0)` as a live identity (`rmp` #452); `checked_add` fails closed instead.
    pub fn alloc(&mut self) -> Result<ElementId> {
        let id = ElementId(self.next);
        self.next = self.next.checked_add(1).ok_or_else(|| {
            GraphusError::Storage("element-id space exhausted: next id at u128::MAX".to_owned())
        })?;
        Ok(id)
    }

    /// Records that `id` has already been issued, so future allocations never collide with it
    /// (used when rebuilding from a scan of existing records).
    pub fn observe(&mut self, id: ElementId) {
        if id.0 >= self.next {
            self.next = id.0 + 1;
        }
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
        let mut a = ElementIdAllocator::new(100);
        assert_eq!(a.alloc().unwrap(), ElementId(100));
        assert_eq!(a.alloc().unwrap(), ElementId(101));
        // Same seed -> same stream (reproducible).
        let mut b = ElementIdAllocator::new(100);
        assert_eq!(b.alloc().unwrap(), ElementId(100));
    }

    #[test]
    fn element_id_observe_prevents_collision() {
        let mut a = ElementIdAllocator::new(1);
        a.observe(ElementId(50));
        assert_eq!(a.alloc().unwrap(), ElementId(51));
    }

    /// Regression (`rmp` #452): an `ElementIdAllocator` seeded at the `u128::MAX` ceiling must FAIL
    /// the next `alloc` rather than wrap to `0` and hand out the reserved "absent" `ElementId(0)`.
    /// Same release-profile wrap hazard as the physical allocator above.
    #[test]
    fn element_id_alloc_at_u128_max_ceiling_errors_instead_of_wrapping_to_absent() {
        let mut a = ElementIdAllocator::new(u128::MAX);
        let err = a.alloc();
        assert!(
            err.is_err(),
            "ElementId alloc at u128::MAX must fail closed, not wrap to the reserved absent id 0"
        );
        assert_eq!(a.peek(), u128::MAX);
        assert!(a.alloc().is_err());
        assert_ne!(a.peek(), 0);
    }

    #[test]
    #[should_panic(expected = "ElementId 0 is reserved")]
    fn element_id_seed_zero_is_rejected() {
        let _ = ElementIdAllocator::new(0);
    }
}
