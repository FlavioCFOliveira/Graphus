//! `PageMap` — the **live**, append-only, lock-free store-relative-page → device-`PageId` map
//! (`rmp` #721).
//!
//! # Why this type exists
//!
//! Every fixed-record store owns one of these: the map from a store-relative page index to the
//! device page that backs it. It is a store's **location oracle** — the thing that turns a physical
//! record id into "which device page do I fetch".
//!
//! Before `rmp` #721 this was a plain `Vec<PageId>` owned by the writer, and an off-thread reader
//! (`graphus_storage::StoreReadView` (`rmp` #336/#543)) took a **frozen copy** of it at dispatch.
//! That was unsound, and it broke the read path in production: the reader's *location oracle* was a
//! snapshot while the record *content* it navigates is **live** (the page cache is shared
//! `Arc`-wise), and the two were not consistent with each other.
//!
//! The old safety argument — "the writer only appends to `device_pages` and advances `high_water`,
//! so a reader scanning `1..high_water` only ever indexes already-existing entries; any id allocated
//! later commits after the reader's snapshot and is invisible anyway" — is true for **scans** and
//! false for **chain walks**. A chain walk FOLLOWS POINTERS (`node.first_rel`, `node.first_prop`,
//! `prop.next_prop`, `HeapBlock::next_block`) read out of LIVE, in-place-updated record content. A
//! concurrently committed writer prepends its new record to a chain head, so a reader can legitimately
//! read a pointer to a record that lives on a page allocated **after** its snapshot. The "invisible
//! anyway" clause cannot save it, because **visibility is decided ABOVE the location oracle**: a
//! record the reader cannot LOCATE is never filtered — the walk dies first, with
//! `Storage("Rel store page 5 not allocated")` surfacing to the client as an internal server error.
//!
//! # The invariant that makes a live map correct
//!
//! **A store's page map is monotone: entries are only ever APPENDED, and an existing entry is never
//! remapped, moved or removed.** Page growth is never undone — not by a rollback (the record-page
//! type stamp is WAL-logged with `undo == redo` precisely so an aborted allocator's page survives,
//! `rmp` #239), and not by GC (slots are reused; pages are not returned to the device).
//!
//! So resolving a record id against the **live** map is not merely safe, it is the only self-consistent
//! choice: the reader already reads live record *content* and undoes it to its snapshot with MVCC, so
//! the *location* of that content must be live too. Locating a record and making it visible are
//! different questions, decided at different layers. This type answers only the first, and always
//! truthfully.
//!
//! `high_water` — the *other* half of the old `graphus_storage::MetaSnapshot` — stays **snapshotted**:
//! it bounds scans (`1..high_water`) and must not drift while a scan runs.
//!
//! # The structure
//!
//! A geometric chunked vector (the classic lock-free append-only vector: a fixed spine of
//! [`OnceLock`] chunk slots, chunk `k` holding `CHUNK0 << k` entries, so the spine itself never has to
//! grow and therefore never has to be republished):
//!
//! - **Reader** — `len.load(Acquire)` bounds-checks, then one `OnceLock::get` (an acquire load of a
//!   state word — no lock, no refcount, no shared-cache-line RMW) and one `AtomicU64::load`. There is
//!   **no lock anywhere on the read path**, which is what keeps the reader pool's core scaling
//!   (`rmp` #336/#575) intact.
//! - **Writer** — the single engine thread appends with [`PageMap::push`]. `O(1)` amortised.
//! - **Capture** — a reader's `graphus_storage::MetaSnapshot` now holds an `Arc<PageMap>`: one
//!   refcount bump. The old code deep-**copied** every store's whole `Vec<PageId>` into an
//!   `Arc<[PageId]>` on *every read dispatch* (`O(store pages)` per read); that copy is gone.
//!
//! ## Publication ordering (the memory model)
//!
//! [`PageMapWriter::push`] writes the entry (and, if it starts a new chunk, installs the chunk) and
//! only **then** `Release`-stores the new `len`. [`PageMap::get`] `Acquire`-loads `len` first and
//! refuses any index at or beyond it. So a reader that observes `len > i` has synchronised-with the
//! push of entry `i` and is guaranteed to see both the chunk and the entry. That single edge is the
//! whole synchronisation story; the entries themselves are `Relaxed`.
//!
//! The property the read path actually needs is stronger, and it is worth stating exactly, because it
//! is **not** established by this module alone:
//!
//! > **The `push` that maps record X's page precedes, in the writer's program order, every write of
//! > every pointer that names X.**
//!
//! The reader learns of X by reading a pointer to it (`node.first_rel`, `prop.next_prop`, …) out of
//! another record's live content, and that content is published to readers by the buffer pool's
//! per-frame latch — a `Release` on unlock paired with the reader's `Acquire` on lock
//! (`graphus-bufpool`'s `concurrent.rs` frame `RwLock<FrameMeta>`; the evicted-page route is likewise
//! transitive through the device `RwLock`). So a reader that can see the *pointer* has synchronised
//! past everything the writer sequenced before writing it — including, **given the invariant above**,
//! the `push`. Hence `get` can never report "not allocated" for a page a visible pointer names.
//!
//! **What guarantees the invariant is `RecordStore::alloc_id` (`rmp` #479): a fresh
//! id's page is mapped EAGERLY, before the id is handed out.** It is *not* enough that
//! `ensure_store_page` pushes before writing X's own body — the dangerous writes are the *pointers to*
//! X in other records (`relink_old_head`, the `first_rel`/`first_prop` chain-head stamps,
//! `HeapBlock::next_block`), and those are written by callers that obtained X from `alloc_id`. Because
//! `alloc_id` maps X's page before returning X, every such caller is already past the `push`.
//!
//! If page mapping were ever made lazy again (mapped at write time rather than at allocation time),
//! **this fix would silently break.** #479 introduced eager mapping for a different reason (keeping
//! `high_water <= addressable capacity` true at all times); #721 now depends on it too.
//!
//! Entries are `AtomicU64` (a [`PageId`] is a `u64` newtype), so a writer mutates a chunk it shares
//! with readers with no `unsafe` — the crate is `#![forbid(unsafe_code)]`. Appending is gated behind
//! the non-`Clone` [`PageMapWriter`] token, which says *who* may append; since `rmp` #1012 it no
//! longer says *how many at once*, because the index is claimed by `compare_exchange` rather than by
//! a read-then-write. `N` producers may append concurrently while every reader stays wait-free.

#![forbid(unsafe_code)]

mod sync;

use std::fmt;
use std::sync::{Arc, OnceLock};

use graphus_core::PageId;
use graphus_core::error::{GraphusError, Result};

// The atomics come from the `loom` seam so this structure can be MODEL-CHECKED, not merely tested on
// an x86-TSO box where a missing `Acquire` is invisible. See `crate::sync`.
use crate::sync::{AtomicU64, AtomicUsize, Ordering, spin_once};

/// `log2` of the first chunk's entry count. Chunk `k` holds `1 << (CHUNK0_LOG2 + k)` entries, so the
/// allocated capacity is at most ~2x the used length — exactly a `Vec`'s doubling behaviour — while a
/// small store pays only `64 * 8 = 512` bytes for its first chunk.
#[cfg(not(loom))]
const CHUNK0_LOG2: u32 = 6;

/// Under `loom`, the first chunk holds a SINGLE entry, so index 1 already crosses a chunk boundary and
/// installs a fresh chunk. The chunk geometry is a memory/locality tuning parameter — it is NOT part of
/// the synchronisation — so shrinking it lets the model check the chunk-install path with a model small
/// enough to terminate. (loom explores an exponential interleaving space; with the production geometry a
/// model would need 64+ concurrent pushes just to reach a boundary, and would never finish.)
#[cfg(loom)]
const CHUNK0_LOG2: u32 = 0;

/// The number of chunk slots in the (fixed, never-republished) spine. Total addressable entries are
/// `(1 << CHUNK0_LOG2) * ((1 << MAX_CHUNKS) - 1)` ≈ 2.75e11 device pages ≈ 2 EiB per store at the
/// 8 KiB logical page size — unreachable in practice (a store would exhaust RAM building the map long
/// before), and [`PageMap::push`] fails **closed** with a clear error past it rather than wrapping.
const MAX_CHUNKS: usize = 32;

/// Splits a flat entry index into `(chunk, offset_within_chunk)`.
///
/// Chunk `k` covers the half-open range `[base(k), base(k+1))` where
/// `base(k) = ((1 << k) - 1) << CHUNK0_LOG2` and its capacity is `1 << (CHUNK0_LOG2 + k)` — so
/// `base(k) + capacity(k) == base(k + 1)` and the chunks tile the index space exactly.
#[inline]
fn split(i: usize) -> (usize, usize) {
    // `q + 1` is in `[2^k, 2^(k+1))` exactly when `i` lies in chunk `k`.
    let q = (i >> CHUNK0_LOG2) as u64;
    let k = (u64::BITS - 1 - (q + 1).leading_zeros()) as usize;
    let base = ((1usize << k) - 1) << CHUNK0_LOG2;
    (k, i - base)
}

/// The entry capacity of chunk `k`.
#[inline]
const fn chunk_capacity(k: usize) -> usize {
    1usize << (CHUNK0_LOG2 as usize + k)
}

/// The ceiling on the number of device pages one store's map can address.
const MAX_ENTRIES: usize = ((1usize << MAX_CHUNKS) - 1) << CHUNK0_LOG2;

/// A store's live, append-only, lock-free store-relative-page → device-`PageId` map (`rmp` #721).
///
/// **Readers only.** This type exposes *no* way to mutate the map: appending requires the
/// [`PageMapWriter`] token, which is not `Clone` and is owned solely by the store's `FixedStore`. That
/// is a *capability* boundary — who may append at all — and it is all it has ever been meant to be.
///
/// It is **not** a single-writer contract, and there is no longer one to enforce (`rmp` #1012). This
/// comment used to claim the borrow checker enforced one, on the strength of `push` taking `&mut self`
/// and the token being reachable only through `&RecordStore`. Both halves are now false: `push`
/// takes `&self` since 37ecb26, and layer 4 of `rmp` #975 retired `RecordStore::store_mut` entirely,
/// so a store handle is reached through `&self`. The safety of concurrent appends does not rest on
/// exclusion at all — it rests on the index being claimed by `compare_exchange` and published in index
/// order. See [`PageMapWriter`] for that protocol and for why it is a stronger guarantee than the one
/// it replaced.
///
/// Shared as an `Arc<PageMap>` between the writer and every off-thread reader. See the module
/// documentation for the monotonicity invariant that makes a live map the correct location oracle, and
/// for the publication ordering.
pub struct PageMap {
    /// The chunk spine. Fixed-size, so it is never reallocated and never republished; a chunk is
    /// installed exactly once, by the writer, via [`OnceLock::get_or_init`].
    ///
    /// Declared FIRST, and sized so that `len` below lands on its own cache line — see `len`'s note.
    chunks: [OnceLock<Box<[AtomicU64]>>; MAX_CHUNKS],
    /// Padding that isolates `len` from `chunks` and (more importantly) from the `Arc`'s strong count,
    /// which sits immediately *before* a heap `Arc`'s payload and is RMW-bumped on **every** read
    /// dispatch and every morsel-worker clone (`rmp` #575).
    ///
    /// Without this, a `repr(Rust)` field reordering could co-locate the read path's hottest word
    /// (`len`, read by every reader core on every record lookup) with a globally contended
    /// reference-count line — turning a read-mostly Shared line into a ping-ponging Modified one and
    /// silently regressing the reader pool's core scaling. `repr(Rust)` field order is unspecified, so
    /// this is guaranteed by construction rather than observed: [`assert_len_is_cache_line_isolated`]
    /// fails the build if it ever stops holding.
    _pad: CacheLinePad,
    /// The published entry count: the number of entries a reader may index.
    ///
    /// **This is the single publication point of the whole structure.** The writer `Release`-stores it
    /// *after* the entry (and, if new, its chunk) is fully written; a reader `Acquire`-loads it *before*
    /// touching anything else and refuses any index at or beyond it. Every other field is therefore
    /// read only through a happens-before edge established here, which is why the entries themselves
    /// need no ordering of their own (see [`PageMapWriter::push`] / [`PageMap::get`]).
    len: AtomicUsize,
    /// Padding that isolates the producers' contended word from the readers' hot one (`rmp` #1012).
    ///
    /// `reserved` below is RMW'd by **every** producer on every append, including on a failed
    /// `compare_exchange`. `len` above is loaded by every reader core on every record lookup. Sharing
    /// a line would make each reservation attempt invalidate the line the whole reader pool is reading
    /// — the same Shared-to-Modified regression `_pad` exists to prevent for the `Arc` refcount, with
    /// a contention source that grows with the writer count rather than the reader count.
    _pad2: CacheLinePad,
    /// The **reservation** counter: the next index to hand out (`rmp` #1012).
    ///
    /// Distinct from `len`, and the distinction is the whole design. A producer claims an index here
    /// (atomically, so no two producers can ever hold the same one) and only then writes its entry;
    /// `len` — the readers' gate — is advanced afterwards, in index order, so it never admits an index
    /// whose entry has not been written. Collapsing the two into one counter would publish a slot the
    /// instant it was claimed, i.e. hand readers an index whose entry is still a zero.
    ///
    /// `reserved >= len` always, and they meet whenever no append is in flight.
    reserved: AtomicUsize,
}

/// A cache line's worth of padding (64 bytes covers x86-64 and aarch64; Apple Silicon's 128-byte
/// lines are conservatively covered by the ~768-byte `chunks` array that precedes `len`).
///
/// Its bytes are never read — that is precisely the point: it exists to occupy space, keeping the read
/// path's hottest word off any cache line an `Arc` refcount RMW could touch.
#[repr(align(64))]
struct CacheLinePad(#[allow(dead_code)] [u8; 64]);

/// Fails the build if `len` ever shares a cache line with the start of the struct — i.e. with the
/// `Arc` strong count that immediately precedes an `Arc<PageMap>`'s payload on the heap. See
/// [`PageMap::_pad`].
const _: () = {
    // `chunks` is `MAX_CHUNKS` OnceLocks; even at a hypothetical 8 bytes each that is 256 bytes, and
    // the pad adds 64 more. The assertion is on the *guaranteed* property, not the observed layout.
    assert!(
        std::mem::size_of::<PageMap>() >= 128,
        "PageMap must be large enough that `len` cannot share a cache line with the Arc refcount"
    );
};

/// The **sole** means of appending to a [`PageMap`] (`rmp` #721): a non-`Clone`, non-`Copy` token
/// owned by the store's `FixedStore`, whose [`push`](Self::push) takes `&self` and is safe to call
/// from any number of threads at once (`rmp` #1012).
///
/// # Why the token exists, and what changed
///
/// The token separates *who may append* from *how many may append at once*. It still answers the
/// first: readers hold `Arc<PageMap>` and have no mutating API at all, so an append is reachable only
/// from a component the store handed the token to.
///
/// What it no longer answers is the second, and the reason is worth stating precisely because the
/// previous version of this comment argued the exact opposite. Under `rmp` #721 `push` took
/// `&mut self`, and the justification was that "two racing `push`es both claim the same index, so one
/// device page silently vanishes from the map" — a durability breach, since `FixedStore::to_meta`
/// serialises the live map into the durable catalog. That reasoning was correct about the **defect**
/// and wrong about the **remedy**: `&mut self` did not make concurrent appends safe, it made them
/// impossible, and with them any second writer thread. The defect was never concurrency; it was that
/// the index was claimed by a non-atomic read-then-write.
///
/// `rmp` #1012 fixes the claim instead of forbidding the caller: an index is reserved by
/// `compare_exchange`, so no two producers can hold the same one, and publication advances in index
/// order so `len` never admits a slot that has not been written. See [`push`](Self::push) for the
/// three phases. The guarantee is now stronger than the borrow checker's was — it holds for `N`
/// producers rather than assuming there is only ever one.
pub struct PageMapWriter {
    map: Arc<PageMap>,
}

impl PageMapWriter {
    /// A writer over a fresh, empty map.
    #[must_use]
    pub fn new() -> Self {
        Self {
            map: Arc::new(PageMap {
                chunks: [const { OnceLock::new() }; MAX_CHUNKS],
                _pad: CacheLinePad([0; 64]),
                len: AtomicUsize::new(0),
                _pad2: CacheLinePad([0; 64]),
                reserved: AtomicUsize::new(0),
            }),
        }
    }

    /// A writer over a map pre-loaded from the durable catalog's page list (the `open` path).
    ///
    /// # Errors
    /// Returns a storage error if the list is longer than the map can address ([`MAX_ENTRIES`]).
    pub fn from_pages(pages: impl IntoIterator<Item = PageId>) -> Result<Self> {
        let w = Self::new();
        for p in pages {
            w.push(p)?;
        }
        Ok(w)
    }

    /// A shared, **read-only** handle on the live map — what a reader's `MetaSnapshot` carries. Cheap:
    /// one refcount bump, never a copy.
    #[must_use]
    pub fn reader(&self) -> Arc<PageMap> {
        Arc::clone(&self.map)
    }

    /// Appends `page` as the next store-relative page, publishing it to every reader.
    ///
    /// **Safe to call from any number of threads at once** (`rmp` #1012), which is the change this
    /// method exists to carry: see [`PageMapWriter`] for what replaced the old `&mut self` guarantee
    /// and why the replacement is stronger rather than merely looser.
    ///
    /// # The three phases, and why they cannot be two
    ///
    /// 1. **Reserve** an index by `compare_exchange` on `reserved`. Atomic, so no two producers can
    ///    ever hold the same index — which is the defect this replaces, where two `push`es both read
    ///    the same `len` and one device page silently vanished from the map.
    /// 2. **Write** the entry into the reserved slot. Nobody else can hold that slot, so this needs no
    ///    ordering of its own beyond being sequenced before phase 3.
    /// 3. **Publish** by advancing `len` from exactly `i` to `i + 1`, waiting for any producer that
    ///    reserved an earlier index to publish first.
    ///
    /// Phases 1 and 3 cannot be the same step. A single counter that both reserved and published would
    /// admit the reader the instant the index was claimed — before phase 2 wrote anything — so a reader
    /// would resolve a store-relative page to device page **zero**. Nor can phase 3 skip the ordering:
    /// `len` is a single count, not a bitmap, so publishing `i + 1` while `i - 1` is still unwritten
    /// would admit that hole too. Waiting is bounded by the producers already ahead in the queue, and
    /// each of them is a handful of instructions from publishing.
    ///
    /// # Why the ceiling check is INSIDE the reservation loop
    ///
    /// A `fetch_add` would be cheaper but cannot check and claim in one step: `N` producers arriving at
    /// the ceiling together would each push the counter past [`MAX_ENTRIES`] before any of them looked,
    /// and `split`'s shifts would then be handed an out-of-range index. The `compare_exchange` makes
    /// "the index is in range and it is now mine" a single indivisible decision.
    ///
    /// # Errors
    /// Returns a storage error if the map is already at its addressable ceiling ([`MAX_ENTRIES`]).
    pub fn push(&self, page: PageId) -> Result<()> {
        // PHASE 1 — reserve. `Relaxed` on both sides: this counter orders nothing by itself; the
        // structure's one synchronisation edge is the `Release` in phase 3, and the entry write in
        // phase 2 is sequenced between them.
        let mut i = self.map.reserved.load(Ordering::Relaxed);
        loop {
            // Fail closed BEFORE the index is claimed, so `split`'s shifts can never overflow and a
            // failed append leaves the counter exactly where a successful one would not have moved it.
            if i >= MAX_ENTRIES {
                return Err(GraphusError::Storage(format!(
                    "store page map is full: cannot map page index {i} (ceiling {MAX_ENTRIES} pages)"
                )));
            }
            match self.map.reserved.compare_exchange_weak(
                i,
                i + 1,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                // Somebody else claimed it; `compare_exchange_weak` hands back what is actually there,
                // so the retry costs no extra load. A spurious failure retries the same index.
                Err(actual) => i = actual,
            }
        }
        // PHASE 2 — write the entry into the slot that is now exclusively ours.
        let (k, off) = split(i);
        // Install the chunk on first use. `OnceLock::get_or_init` publishes the (zero-filled) chunk
        // with `Release` and reads it back with `Acquire`, so a reader that reaches it below sees a
        // fully-initialised chunk. Readers cannot reach it yet in any case: `len` still excludes `i`.
        let chunk = self.map.chunks[k].get_or_init(|| {
            (0..chunk_capacity(k))
                .map(|_| AtomicU64::new(0))
                .collect::<Vec<_>>()
                .into_boxed_slice()
        });
        // `Relaxed` is sufficient and intentional. This store is *sequenced-before* the `Release` store
        // of `len` below, so it is ordered ahead of it, and every reader reaches this entry only after
        // an `Acquire` load of `len` that observed the new value — which establishes happens-before with
        // everything sequenced before that `Release`, this store included. Making it `Release` would buy
        // nothing and would cost a real barrier (`stlr`) on aarch64, a first-class target (Apple
        // Silicon, Raspberry Pi 5).
        //
        // This is sound ONLY because `len` is the sole gate: every read of an entry goes through
        // `PageMap::get`, which loads `len` with `Acquire` first. Any future reader path that touches an
        // entry without passing that gate MUST restore an ordering here.
        chunk[off].store(page.0, Ordering::Relaxed);
        // PHASE 3 — THE PUBLICATION, the one and only synchronisation edge in this structure, and now
        // also the point that keeps `len` a contiguous prefix. `Release` on success carries phase 2's
        // entry write (and the chunk install) to every reader that `Acquire`-loads this `len`; the
        // failure ordering is `Relaxed` because a failed attempt publishes nothing and its retry
        // re-reads through the next attempt anyway.
        while self
            .map
            .len
            .compare_exchange_weak(i, i + 1, Ordering::Release, Ordering::Relaxed)
            .is_err()
        {
            // A producer holding an earlier index has not published yet. Bounded: every one of them is
            // a few instructions from its own phase 3, and none can block on us — the wait is strictly
            // backwards in index order, so it is a queue and never a cycle.
            spin_once();
        }
        Ok(())
    }
}

impl Default for PageMapWriter {
    fn default() -> Self {
        Self::new()
    }
}

impl std::ops::Deref for PageMapWriter {
    type Target = PageMap;

    /// The writer can read its own map with the same API readers use.
    fn deref(&self) -> &PageMap {
        &self.map
    }
}

impl fmt::Debug for PageMapWriter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PageMapWriter")
            .field("len", &self.map.len())
            .finish_non_exhaustive()
    }
}

impl PageMap {
    /// The number of device pages currently mapped. LIVE and monotone: it only ever grows.
    #[must_use]
    pub fn len(&self) -> usize {
        self.len.load(Ordering::Acquire)
    }

    /// Whether the store maps no device pages yet.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// The device page backing store-relative page `i`, or `None` if `i` is not mapped.
    ///
    /// Lock-free and wait-free: one `Acquire` load of `len`, one `OnceLock::get` (itself an acquire
    /// load of a state word — no lock, no refcount, no shared-cache-line RMW), and one `Relaxed` load
    /// of the entry. Safe to call concurrently from any number of reader threads while the writer
    /// appends.
    ///
    /// # Panics
    /// Panics if the map's own internal invariant is broken (a published index whose chunk is missing).
    /// That is unreachable — [`PageMapWriter::push`] installs the chunk and writes the entry *before*
    /// publishing the `len` that admits the index — and it is deliberately loud rather than a silent
    /// `None`: returning `None` here would make an internal inconsistency masquerade as the ordinary
    /// "page not allocated" miss, i.e. it would surface as a phantom `rmp` #721 regression and send the
    /// next investigator down the wrong path entirely.
    #[must_use]
    pub fn get(&self, i: usize) -> Option<PageId> {
        // THE PUBLICATION GATE. Everything the writer did before `Release`-storing this `len` — the
        // chunk install and the entry write — happens-before this `Acquire` load, so both are visible
        // below and the entry needs no ordering of its own.
        if i >= self.len.load(Ordering::Acquire) {
            // The ordinary, expected miss: `i` names a page this store has not allocated. The caller
            // turns this into `"{kind} store page {i} not allocated"`.
            return None;
        }
        let (k, off) = split(i);
        // Below the published `len`, all three of these hold by construction. A violation is an
        // internal inconsistency, not a miss — fail loudly, and say so.
        let chunk = self.chunks[k]
            .get()
            .expect("PageMap invariant: a chunk holding a published index is always installed");
        Some(PageId(chunk[off].load(Ordering::Relaxed)))
    }

    /// Iterates the mapped device pages in store-relative page order — the durable catalog's view of
    /// the map (`FixedStore::to_meta`), and the DST device-image snapshot.
    pub fn iter(&self) -> impl Iterator<Item = PageId> + '_ {
        let len = self.len();
        (0..len).map(move |i| {
            self.get(i)
                .expect("index below the published len is always mapped")
        })
    }
}

impl fmt::Debug for PageMap {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PageMap")
            .field("len", &self.len())
            .finish_non_exhaustive()
    }
}

// The map is shared between the engine thread (which appends) and every reader thread (which reads);
// a compile-time assertion, so removing a field's `Sync`-ness fails the build rather than silently
// de-optimising the read path into a copy. The auto derivation holds with no `unsafe impl`:
// `AtomicUsize`, `AtomicU64` and `OnceLock<T: Send + Sync>` are all `Send + Sync`.
const _: () = {
    fn assert_send_sync<T: Send + Sync>() {}
    fn assert_page_map() {
        assert_send_sync::<PageMap>();
        assert_send_sync::<PageMapWriter>();
    }
    let _ = assert_page_map;
};

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

    use super::*;

    /// The chunks must tile the index space exactly: every index maps into its chunk's bounds, and
    /// consecutive indices are contiguous within/across chunks.
    #[test]
    fn split_tiles_the_index_space_exactly() {
        for i in 0..200_000usize {
            let (k, off) = split(i);
            assert!(k < MAX_CHUNKS, "index {i} escaped the spine");
            assert!(
                off < chunk_capacity(k),
                "index {i} -> chunk {k} offset {off} is past the chunk's {} entries",
                chunk_capacity(k)
            );
            let base = ((1usize << k) - 1) << CHUNK0_LOG2;
            assert_eq!(base + off, i, "index {i} did not round-trip");
        }
        // The first chunk boundary and the one after it, explicitly.
        assert_eq!(split(0), (0, 0));
        assert_eq!(split(63), (0, 63));
        assert_eq!(split(64), (1, 0));
        assert_eq!(split(191), (1, 127));
        assert_eq!(split(192), (2, 0));
    }

    #[test]
    fn push_get_len_round_trip_across_many_chunks() {
        let m = PageMapWriter::new();
        assert!(m.is_empty());
        assert_eq!(m.get(0), None);
        const N: usize = 100_000;
        for i in 0..N {
            m.push(PageId(i as u64 * 7 + 3)).unwrap();
            assert_eq!(m.len(), i + 1);
        }
        for i in 0..N {
            assert_eq!(m.get(i), Some(PageId(i as u64 * 7 + 3)), "entry {i}");
        }
        assert_eq!(m.get(N), None, "one past the end is not mapped");
        assert_eq!(m.get(usize::MAX), None, "a wild index is not mapped");
        assert_eq!(m.iter().count(), N);
        assert_eq!(m.iter().next(), Some(PageId(3)));
    }

    #[test]
    fn from_pages_round_trips() {
        let src: Vec<PageId> = (0..1000).map(|i| PageId(i * 3)).collect();
        let m = PageMapWriter::from_pages(src.iter().copied()).unwrap();
        assert_eq!(m.len(), src.len());
        assert_eq!(m.iter().collect::<Vec<_>>(), src);
    }

    /// The whole point of the type: a reader thread indexing the map **concurrently** with the writer
    /// appending to it must never see a torn, missing or stale-but-published entry. A reader that
    /// observes `len > i` must see entry `i` — including across a chunk boundary, which is where a
    /// naive implementation would republish a spine and lose a racing reader.
    ///
    /// This is the real-thread form of the `rmp` #721 race: reader and writer in genuine parallel.
    #[test]
    fn concurrent_readers_never_miss_a_published_entry() {
        const N: usize = 50_000;
        const READERS: usize = 4;
        let w = PageMapWriter::new();
        let m = w.reader();
        let stop = Arc::new(AtomicBool::new(false));
        // The readers must be RUNNING before the writer starts, or this test measures the scheduler.
        // Without the barrier the writer can finish all 50 000 pushes and set `stop` before a reader
        // is ever scheduled: every reader then observes nothing, `any_saw_growth` is false, and the
        // gate reports "the readers never observed the map at all" — which is what it did once the
        // suite began running binaries concurrently (`rmp` #1044), and what it would do on any loaded
        // machine. The barrier makes the overlap a fact rather than a hope, and costs one rendezvous.
        let ready = Arc::new(std::sync::Barrier::new(READERS + 1));
        let observed = Arc::new(AtomicBool::new(false));

        let readers: Vec<_> = (0..READERS)
            .map(|_| {
                let m = Arc::clone(&m);
                let stop = Arc::clone(&stop);
                let ready = Arc::clone(&ready);
                let observed = Arc::clone(&observed);
                std::thread::spawn(move || {
                    let mut max_seen = 0usize;
                    ready.wait();
                    while !stop.load(Ordering::Relaxed) {
                        let len = m.len();
                        // Every index below the published length MUST resolve, and to the right value.
                        for i in (0..len).rev().take(64) {
                            let got = m.get(i).unwrap_or_else(|| {
                                panic!("entry {i} was published (len {len}) but is not mapped")
                            });
                            assert_eq!(got, PageId(i as u64 + 1), "entry {i} is wrong");
                        }
                        if len > 0 {
                            observed.store(true, Ordering::Release);
                        }
                        max_seen = max_seen.max(len);
                    }
                    max_seen
                })
            })
            .collect();

        ready.wait();
        for i in 0..N {
            w.push(PageId(i as u64 + 1)).unwrap();
        }
        // Hold the window open until a reader has actually READ the map. That is the condition the
        // assertion below states, so waiting for it is what turns the assertion from lucky into true:
        // closing the window on a timer instead leaves "did anyone look?" to the scheduler.
        //
        // The deadline is not a margin on the property — it is what keeps a BROKEN map reportable. If
        // `len()` were mutated to never grow, the readers would observe nothing, this wait would never
        // be satisfied, and an unbounded spin would turn a defect into a hung test that reports
        // nothing at all. With the deadline the wait simply gives up and the assertion below fails
        // with the message it always had. The bound is enormous compared with what a working map needs
        // (the readers are already inside the loop and the map is fully published, so the next `len()`
        // any of them performs returns `N`), so a healthy run never approaches it.
        let give_up = std::time::Instant::now() + std::time::Duration::from_secs(30);
        while !observed.load(Ordering::Acquire) && std::time::Instant::now() < give_up {
            std::hint::spin_loop();
        }
        stop.store(true, Ordering::Relaxed);

        let mut any_saw_growth = false;
        for r in readers {
            let max_seen = r.join().expect("reader thread panicked");
            any_saw_growth |= max_seen > 0;
        }
        assert!(any_saw_growth, "the readers never observed the map at all");
        assert_eq!(w.len(), N);
    }

    /// **N real threads append at once and not one page is lost** (`rmp` #1012).
    ///
    /// The `loom` model proves the property over every interleaving the memory model permits; this
    /// proves it over the ones this machine actually produces, at a volume no model checker could
    /// explore. Both are needed and neither substitutes for the other: loom would pass a version that
    /// is correct but livelocks under real contention, and a real-thread test on x86-TSO would pass a
    /// version whose ordering is wrong on aarch64.
    ///
    /// The assertion is on the multiset of mapped pages, because that is what durability rests on:
    /// `FixedStore::to_meta` serialises this map into the catalog, so a page appearing twice — or not
    /// at all — puts committed records on an unaddressable page. Each producer writes a disjoint,
    /// self-identifying range, so a duplicate or a gap names the producer that lost it.
    #[test]
    fn many_producers_append_concurrently_without_losing_a_page() {
        const PRODUCERS: u64 = 8;
        const PER_PRODUCER: u64 = 2_000;
        let w = Arc::new(PageMapWriter::new());

        let producers: Vec<_> = (0..PRODUCERS)
            .map(|p| {
                let w = Arc::clone(&w);
                std::thread::spawn(move || {
                    for k in 0..PER_PRODUCER {
                        // Disjoint per producer and never zero, so a gap or a repeat is attributable.
                        w.push(PageId(p * PER_PRODUCER + k + 1)).unwrap();
                    }
                })
            })
            .collect();
        for t in producers {
            t.join().expect("producer thread panicked");
        }

        let total = (PRODUCERS * PER_PRODUCER) as usize;
        assert_eq!(
            w.len(),
            total,
            "the published length must account for every append: a short length means an index was \
             claimed twice and a device page vanished from the map"
        );
        let mut seen: Vec<u64> = w.iter().map(|p| p.0).collect();
        seen.sort_unstable();
        let expected: Vec<u64> = (1..=(PRODUCERS * PER_PRODUCER)).collect();
        assert_eq!(
            seen, expected,
            "every page must be mapped exactly once — no duplicate (two producers on one index) and \
             no gap (an entry published but never written)"
        );
    }
}
