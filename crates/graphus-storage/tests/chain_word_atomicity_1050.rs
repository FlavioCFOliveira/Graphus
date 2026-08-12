//! **A chain-word update is ONE atom: the back-pointer and its first-in-chain marker are never
//! observed disagreeing** (`rmp` #1050).
//!
//! # The defect, and why both halves have to be asserted at once
//!
//! `rmp` #1050 is not "the write is too wide" and it is not "the write is not atomic". It is that
//! those two were, with the primitives of the time, **mutually exclusive**:
//!
//! * A whole-record `write_rel` is ONE `with_page_mut_lsn` — one acquisition of the frame write
//!   latch — so a reader taking the frame read latch sees the record either wholly before or wholly
//!   after. Atomic, and **clobbering**: the image is built from an unlatched `read_rel`, so it carries
//!   the neighbour's `first_prop`, its MVCC header (`undo_ptr` included) and the three chain words the
//!   caller never meant to touch, all from a snapshot another writer may have moved on from. That is
//!   the `rmp` #772 lost-update class.
//! * Writing only the changed words, one `write_field` per word, does not clobber — and is not atomic.
//!   `rmp` #1030 measured exactly that: with the per-word conversion in place,
//!   `concurrent_reader_serializability::concurrent_readers_see_consistent_snapshot` reported a
//!   conserved-total violation under eight concurrent readers (left 1, right 0) while passing 5/5 in
//!   isolation. The chain-pointer words are contiguous (`61..93`) but `chain_flags` sits at `101`, so
//!   no single `write_region` covers both; a reader landing between them sees a `prev` that has been
//!   re-pointed and a first-in-chain marker that has not been set.
//!
//! `rmp` #1054 resolved it with option (b) of #1050's technical requirements — a multi-region write
//! primitive, `RecordStore::patch_chain_words`, that takes the frame write latch **once** and applies
//! every pointer word AND the marker byte inside that one hold. So the two tests below assert the two
//! halves, separately and deliberately, because neither implies the other:
//!
//! 1. [`the_repoint_writes_the_back_pointer_word_and_its_marker_and_nothing_else`] — the **extent**.
//!    A WAL oracle, deterministic and thread-free: every image the engine logs against the neighbour's
//!    record during the unlink must lie inside the `start_prev` word or the `chain_flags` byte. It
//!    fails the moment the whole-record write comes back, in redo *or* in undo.
//! 2. [`a_concurrent_reader_never_sees_a_back_pointer_and_its_marker_disagree`] — the **atomicity**.
//!    Real reader threads against a real writer, asserting the record-level invariant that
//!    `patch_chain_words` publishes as one atom. It fails when that single critical section is split
//!    into two.
//!
//! # The invariant the reader checks, and why it is exactly the right one
//!
//! For a live relationship and a chain side `S`:
//!
//! ```text
//!     (prev(S) == NULL_ID)  ==  (chain_flags & FIRST(S) != 0)
//! ```
//!
//! "I name no predecessor" and "I am the head of this chain" are the same fact written in two places,
//! and every transactional writer of either one writes **both**, together:
//!
//! * `create_rel` threads a new record in with `prev = NULL` and the marker set — one `write_rel_create`.
//!   (A self-loop's START side is threaded with `prev = id`, its own record, and the START marker
//!   clear; the invariant covers that case as stated, without an exception.)
//! * `relink_old_head` displaces a head: `prev = new_id`, marker cleared — one `patch_chain_words`.
//! * `repoint_neighbour` promotes the successor of an unlinked head: `prev = NULL`, marker set — one
//!   `patch_chain_words`.
//!
//! Note what the invariant deliberately does **not** say. It is a statement about ONE record, never
//! about the chain: between a publication and its repair the *chain* legitimately has a head whose
//! `prev` is not `NULL` (the unlink publishes `first_rel := next` and only then repoints `next`), and
//! a non-head record whose marker is still set (the prepend publishes `first_rel := new` and only then
//! relinks the displaced record). Those windows belong to the protocol and both keep the record-level
//! invariant true. What cannot happen — what the split write makes happen — is the two fields of ONE
//! record contradicting each other.
//!
//! # Why this half is real threads and not the deterministic simulator
//!
//! `patch_chain_words_latched` opens with a [`graphus_core::sched::NoSwitchScope`], and inside such a
//! region `graphus_core::sched::yield_at` degrades to `observe`: the step is recorded in the history
//! but the token is **not** handed over. Under the DST deterministic scheduler no other logical thread
//! can therefore be scheduled anywhere inside that function — with the mechanism or without it — so a
//! scheduled reader would report the split write as sound. The window is real all the same: the frame
//! latch is an ordinary `RwLock` and a reader thread is not scheduler-mediated, which is precisely why
//! `rmp` #1030 measured the violation with eight OS-level readers. This is the same limit `rmp` #811
//! ran into (GC corpse-zeroing versus an off-thread reader) and it is stated here rather than left for
//! the next author to rediscover.
//!
//! # Non-vacuity
//!
//! Both tests carry their own controls, because a green run of either is worthless without them:
//! the extent test asserts that the window it measures is non-empty and that the unlink took the head
//! branch at all; the race test asserts that the readers observed the neighbour in **both** states
//! (head and displaced), so a run in which the churn never overlapped a read cannot pass by default.
//! The recorded mutation is in `rmp` #1050's closing summary.
//!
//! # Running it
//!
//! ```text
//! cargo test -p graphus-storage --test chain_word_atomicity_1050
//! ```

use std::ops::Range;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use graphus_core::{PageId, TxnId};
use graphus_io::MemBlockDevice;
use graphus_storage::paging::{CAS_SENTINEL, record_location};
use graphus_storage::record::{CHAIN_FLAG_END_FIRST, CHAIN_FLAG_START_FIRST};
use graphus_storage::{
    MVCC_HEADER_SIZE, NULL_ID, Namespace, REL_RECORD_SIZE, RecordStore, RelRecord,
};
use graphus_wal::{LogRecord, MemLogSink, WalManager};

type Store = RecordStore<MemBlockDevice, MemLogSink>;

/// Small enough that eviction and the WAL-before-data rule stay live rather than everything simply
/// staying resident, and large enough that this tiny working set never thrashes.
const POOL_CAPACITY: usize = 64;

// ---------------------------------------------------------------------------------------------
// The relationship record's layout, derived rather than copied
// ---------------------------------------------------------------------------------------------

/// Byte offset of `start_prev_rel` inside a relationship record, derived from the layout of
/// `05-storage-format.md` §2.3 rather than copied as a magic number: the record is
/// `MVCC header | element_id: u128 | type: u32 | start_node: u64 | end_node: u64 | start_prev …`.
///
/// The real constant is `pub(crate)` in `graphus-storage`, so this derivation is **checked** at
/// runtime against the live record instead of trusted — see [`assert_layout_offsets`].
const OFF_START_PREV: usize =
    MVCC_HEADER_SIZE + size_of::<u128>() + size_of::<u32>() + 2 * size_of::<u64>();
/// Byte offset of `start_next_rel`, immediately after `start_prev_rel`.
const OFF_START_NEXT: usize = OFF_START_PREV + size_of::<u64>();
/// Byte offset of `end_prev_rel`, immediately after `start_next_rel`.
const OFF_END_PREV: usize = OFF_START_NEXT + size_of::<u64>();
/// Byte offset of `end_next_rel`, immediately after `end_prev_rel`.
const OFF_END_NEXT: usize = OFF_END_PREV + size_of::<u64>();
/// Byte offset of `first_prop`, immediately after `end_next_rel`.
const OFF_FIRST_PROP: usize = OFF_END_NEXT + size_of::<u64>();
/// The `chain_flags` byte is the record's last, so its offset falls out of the record size.
const OFF_CHAIN_FLAGS: usize = REL_RECORD_SIZE - 1;

/// The derived offsets must describe the record they claim to. A compile-time check, because it is a
/// statement about constants and nothing about a run could change the answer.
const _: () = assert!(
    OFF_FIRST_PROP + size_of::<u64>() == OFF_CHAIN_FLAGS,
    "the derived relationship layout must account for every byte between `start_prev` and \
     `chain_flags`"
);

/// The extent a correct `repoint_neighbour` is allowed to write inside the neighbour's record: the
/// `start_prev` word, and the `chain_flags` byte. Nothing between them, and nothing outside them.
fn allowed_extent(at: usize) -> bool {
    (OFF_START_PREV..OFF_START_PREV + size_of::<u64>()).contains(&at) || at == OFF_CHAIN_FLAGS
}

// ---------------------------------------------------------------------------------------------
// Fixture
// ---------------------------------------------------------------------------------------------

/// A hub node `v` whose incidence chain is headed by the **anchor** relationship `anchor`, plus the
/// spoke `w` that every displacing relationship is created towards.
///
/// The anchor carries a property (so `first_prop` is non-zero) and an undo-chain head, because a
/// clobber of a field that is already zero says nothing.
struct Fixture {
    store: Arc<Store>,
    /// The hub. Its chain head is what the prepend displaces and the unlink restores.
    v: u64,
    /// The relationship this suite watches: `v -> u`, permanently live, patched twice per round.
    anchor: u64,
    /// The far endpoint of every displacing relationship.
    w: u64,
    rel_type: u32,
}

fn fixture() -> Fixture {
    let device = MemBlockDevice::new(0);
    let wal = WalManager::create(MemLogSink::new()).expect("create wal");
    let store = RecordStore::create(device, wal, POOL_CAPACITY, 1).expect("create store");

    let t0 = TxnId(1);
    store.begin(t0);
    let rel_type = store
        .intern_token(Namespace::RelType, "KNOWS")
        .expect("intern relationship type");
    let key = store
        .intern_token(Namespace::PropKey, "seed")
        .expect("intern property key");
    let (v, _) = store.create_node(t0).expect("create the hub V");
    let (u, _) = store
        .create_node(t0)
        .expect("create the anchor's far endpoint U");
    let (w, _) = store.create_node(t0).expect("create the spoke W");
    let (anchor, _) = store
        .create_rel(t0, rel_type, v, u)
        .expect("create the anchor relationship");
    store
        .add_rel_property(t0, anchor, key, 1, 0x5EED)
        .expect("give the anchor a property");
    store.commit(t0).expect("commit the seed state");

    let seeded = store
        .rel(anchor)
        .expect("read the anchor after the seed commit");
    assert_eq!(
        store.node(v).expect("read V").first_rel,
        anchor,
        "the fixture must leave V's incidence chain headed by the anchor"
    );
    assert_eq!(
        seeded.start_prev_rel, NULL_ID,
        "the anchor must start as the head of V's chain"
    );
    assert_ne!(
        seeded.chain_flags & CHAIN_FLAG_START_FIRST,
        0,
        "the anchor must start with its START first-in-chain marker set"
    );
    assert_ne!(
        seeded.first_prop, NULL_ID,
        "the anchor must carry a property, or a clobber of `first_prop` says nothing"
    );
    assert_ne!(
        seeded.mvcc.undo_ptr, NULL_ID,
        "the anchor must carry an undo-chain head, or a clobber of the MVCC header says nothing"
    );

    Fixture {
        store: Arc::new(store),
        v,
        anchor,
        w,
        rel_type,
    }
}

// ---------------------------------------------------------------------------------------------
// Test 1 — the extent (deterministic, thread-free)
// ---------------------------------------------------------------------------------------------

/// One patch image found in the log, reduced to what this suite reasons about.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Touch {
    /// Byte range **relative to the start of the relationship record**.
    extent: Range<usize>,
    /// A compare-and-set image (`encode_cas_patch`) rather than a plain region overwrite.
    conditional: bool,
    /// `true` for the record's redo image, `false` for its undo image. Both are writes the engine may
    /// perform: an undo image is replayed onto the page by live rollback and by crash recovery, so a
    /// whole-record pre-image undo clobbers a neighbouring field exactly as a whole-record redo does.
    redo: bool,
}

/// Decodes the patch at the head of a WAL image into the byte range it writes, plus how it writes it.
///
/// Mirrors `graphus_storage::paging::apply_patch`'s own reading of the two image shapes — a plain
/// `[offset: u16][bytes]` region overwrite, and a `[CAS_SENTINEL][offset: u16][expect: u64][new: u64]`
/// compare-and-set — because stating exactly which bytes each shape touches is the whole point here.
fn decode_patch(image: &[u8]) -> Option<(Range<usize>, bool)> {
    if image.len() < 2 {
        return None;
    }
    let lead = u16::from_le_bytes(image[0..2].try_into().expect("2 bytes"));
    if lead == CAS_SENTINEL {
        assert_eq!(
            image.len(),
            2 + 2 + 8 + 8,
            "a compare-and-set image is a fixed 20 bytes"
        );
        let at = usize::from(u16::from_le_bytes(image[2..4].try_into().expect("2 bytes")));
        return Some((at..at + 8, true));
    }
    let at = usize::from(lead);
    Some((at..at + image.len() - 2, false))
}

/// Every write the log records **inside** relationship record `[off, off + REL_RECORD_SIZE)` of
/// `page`, from byte `from` of the log onwards, as offsets relative to the start of that record.
fn writes_inside_record(log: &[u8], from: usize, page: PageId, off: usize) -> Vec<Touch> {
    let mut touches = Vec::new();
    let mut at = from;
    while at < log.len() {
        let (record, used) = match LogRecord::decode(&log[at..]) {
            Ok(decoded) => decoded,
            // A torn tail is the clean end of the durable log; anything else is corruption and must
            // not be passed over in silence.
            Err(graphus_wal::DecodeError::Incomplete) => break,
            Err(e) => panic!("the WAL tail failed to decode at byte {at}: {e:?}"),
        };
        at += used;
        if record.page_id != page {
            continue;
        }
        for (image, redo) in [(&record.redo, true), (&record.undo, false)] {
            let Some((extent, conditional)) = decode_patch(image) else {
                continue;
            };
            // Only the part that lands inside THIS record. The relationship page holds other records
            // too — the aborted relationship's own is very likely on it — and a write to a
            // neighbouring record is not this record's business.
            let lo = extent.start.max(off);
            let hi = extent.end.min(off + REL_RECORD_SIZE);
            if lo < hi {
                touches.push(Touch {
                    extent: lo - off..hi - off,
                    conditional,
                    redo,
                });
            }
        }
    }
    touches
}

/// Finds the device page holding relationship `id`'s record, and the record's offset within it.
///
/// The store does not expose its per-store page mapping, so the page is **identified by its
/// contents** and the identification is required to be unique: the offset comes from
/// [`record_location`], and the page is the one whose `element_id`, `start_node` and `end_node` at
/// that offset are exactly the record's.
fn locate_rel_record(store: &Store, id: u64, rec: &RelRecord) -> (PageId, usize) {
    let (_, off) = record_location(id, REL_RECORD_SIZE);
    let mut found: Vec<PageId> = Vec::new();
    for page in store.mapped_pages() {
        let bytes = store.read_device_page(page).expect("read a device page");
        if bytes.len() < off + REL_RECORD_SIZE {
            continue;
        }
        let word = |at: usize| {
            u64::from_le_bytes(bytes[off + at..off + at + 8].try_into().expect("8 bytes"))
        };
        let eid = u128::from_le_bytes(
            bytes[off + MVCC_HEADER_SIZE..off + MVCC_HEADER_SIZE + 16]
                .try_into()
                .expect("16 bytes"),
        );
        if eid == rec.element_id.0
            && word(MVCC_HEADER_SIZE + 16 + 4) == rec.start_node
            && word(MVCC_HEADER_SIZE + 16 + 4 + 8) == rec.end_node
        {
            found.push(page);
        }
    }
    assert_eq!(
        found.len(),
        1,
        "relationship {id}'s record must be identifiable on exactly one device page, found \
         {found:?}. Without a unique page the extent oracle would be reading somebody else's bytes."
    );
    (found[0], off)
}

/// Checks the offsets this suite derives against the live record, so the constants above are a
/// verified claim rather than magic numbers that quietly stop meaning anything if the layout moves.
fn assert_layout_offsets(store: &Store, page: PageId, off: usize, rec: &RelRecord) {
    let bytes = store.read_device_page(page).expect("read the rel page");
    let word =
        |at: usize| u64::from_le_bytes(bytes[off + at..off + at + 8].try_into().expect("8 bytes"));
    assert_eq!(
        word(OFF_START_PREV),
        rec.start_prev_rel,
        "the derived `start_prev` offset ({OFF_START_PREV}) does not name `start_prev` on the page"
    );
    assert_eq!(
        word(OFF_START_NEXT),
        rec.start_next_rel,
        "the derived `start_next` offset ({OFF_START_NEXT}) does not name `start_next` on the page"
    );
    assert_eq!(
        word(OFF_END_PREV),
        rec.end_prev_rel,
        "the derived `end_prev` offset ({OFF_END_PREV}) does not name `end_prev` on the page"
    );
    assert_eq!(
        word(OFF_FIRST_PROP),
        rec.first_prop,
        "the derived `first_prop` offset ({OFF_FIRST_PROP}) does not name `first_prop` on the page"
    );
    assert_eq!(
        bytes[off + OFF_CHAIN_FLAGS],
        rec.chain_flags,
        "the derived `chain_flags` offset ({OFF_CHAIN_FLAGS}) does not name `chain_flags` on the page"
    );
}

/// The hardened log as bytes. Every append this suite measures is hardened first, so the mark and the
/// tail are taken from the same durable image.
fn hardened_log(store: &Store) -> Vec<u8> {
    store.harden_wal();
    store.with_wal(|w| w.sink().durable_bytes())
}

/// **The extent half of the property.** During the unlink that promotes the anchor back to head, the
/// engine may write the anchor's `start_prev` word and its `chain_flags` byte — and no other byte of
/// its 102-byte record.
///
/// This is what fails the instant `repoint_neighbour` goes back to a whole-record `write_rel`: that
/// write's redo AND undo images both span `0..102`, carrying the anchor's `first_prop`, its MVCC
/// header (`undo_ptr` included) and its three untouched chain words from a stale read.
#[test]
fn the_repoint_writes_the_back_pointer_word_and_its_marker_and_nothing_else() {
    let f = fixture();
    let seeded = f.store.rel(f.anchor).expect("read the anchor");
    let (page, off) = locate_rel_record(&f.store, f.anchor, &seeded);
    assert_layout_offsets(&f.store, page, off, &seeded);

    // The displacing transaction. Its prepend relinks the anchor (`prev := doomed`, marker cleared);
    // its rollback unlinks the doomed head and repoints the anchor (`prev := NULL`, marker set).
    let txn = TxnId(100);
    f.store.begin(txn);
    let (doomed, _) = f
        .store
        .create_rel(txn, f.rel_type, f.v, f.w)
        .expect("create the relationship this transaction aborts");
    assert_eq!(
        f.store.node(f.v).expect("read V").first_rel,
        doomed,
        "the new relationship must be V's chain head before the abort, or the rollback takes the \
         neighbour branch of `unlink_side_with` and never repoints the anchor at all"
    );
    assert_eq!(
        f.store
            .rel(f.anchor)
            .expect("read the anchor")
            .start_prev_rel,
        doomed,
        "the prepend must have relinked the anchor's back-pointer onto the new head"
    );

    // The mark: everything the prepend logged is behind us, so what follows is the rollback's.
    let mark = hardened_log(&f.store).len();
    f.store
        .rollback(txn)
        .expect("the logical rollback that unlinks the relationship failed");
    let after = hardened_log(&f.store);
    assert!(
        after.len() > mark,
        "the rollback logged nothing: `rollback_logical` never ran, so this test proves nothing"
    );

    let touches = writes_inside_record(&after, mark, page, off);
    assert!(
        !touches.is_empty(),
        "the rollback logged no write at all inside the anchor's record, so the extent measured \
         below is vacuous. The unlink must repoint the anchor's back-pointer."
    );
    for t in &touches {
        for at in t.extent.clone() {
            assert!(
                allowed_extent(at),
                "the unlink wrote byte {at} of the anchor's record ({} image, extent {:?}, \
                 conditional {}). A repoint owns the back-pointer word \
                 ({OFF_START_PREV}..{}) and the `chain_flags` byte ({OFF_CHAIN_FLAGS}) and nothing \
                 else: every other byte belongs to a field this writer read from an unlatched image \
                 and would be writing back stale — the `rmp` #772 clobber class, and the reason \
                 `rmp` #1050 refused the whole-record write (all touches: {touches:?})",
                if t.redo { "redo" } else { "undo" },
                t.extent,
                t.conditional,
                OFF_START_PREV + size_of::<u64>(),
            );
        }
    }

    // And the pointer word must be repaired CONDITIONALLY. `repoint_neighbour` mends a word that names
    // the record it is removing, and only while it still does; an unconditional store would overwrite
    // a writer that legitimately moved the word on in between.
    let pointer_touches: Vec<&Touch> = touches
        .iter()
        .filter(|t| {
            t.extent.start < OFF_START_PREV + size_of::<u64>() && t.extent.end > OFF_START_PREV
        })
        .collect();
    assert!(
        !pointer_touches.is_empty(),
        "the unlink logged no write of the anchor's back-pointer word, so the conditionality \
         assertion below is vacuous"
    );
    for t in &pointer_touches {
        assert!(
            t.conditional,
            "the anchor's back-pointer was repaired with a plain region patch ({t:?}). It must be \
             a compare-and-set image: the comparison has to travel into the redo record so replay \
             re-takes the decision this writer took (`rmp` #1028 / #1054)"
        );
    }

    // The end state, as a statement of the property. Not its proof — a whole-record write-back from a
    // fresh single-threaded read would leave exactly this too, which is why the extent test above is
    // where the teeth are.
    let restored = f
        .store
        .rel(f.anchor)
        .expect("read the anchor after the rollback");
    assert_eq!(
        restored.start_prev_rel, NULL_ID,
        "the anchor is V's head again, so its back-pointer must name nobody"
    );
    assert_ne!(
        restored.chain_flags & CHAIN_FLAG_START_FIRST,
        0,
        "the anchor is V's head again, so its START first-in-chain marker must be set"
    );
    assert_eq!(
        (
            restored.first_prop,
            restored.mvcc.undo_ptr,
            restored.end_prev_rel
        ),
        (seeded.first_prop, seeded.mvcc.undo_ptr, seeded.end_prev_rel),
        "the unlink must not have disturbed the anchor's property chain, undo chain or the chain \
         side facing its other endpoint"
    );
}

// ---------------------------------------------------------------------------------------------
// Test 2 — the atomicity (real threads)
// ---------------------------------------------------------------------------------------------

/// Reader threads. Eight is the project's floor for a contention test, and it is the number of
/// concurrent readers under which `rmp` #1030 measured the torn update in the first place.
const READERS: usize = 8;

/// Rounds of prepend + rollback. Each round patches the anchor's `start_prev`/`chain_flags` pair
/// twice — once cleared by the prepend, once set by the unlink — so this is 2 × `ROUNDS` chances for a
/// reader to land between the pointer and the marker.
const ROUNDS: u64 = 6_000;

/// The record-level atom `patch_chain_words` publishes: naming no predecessor and being the head of
/// the chain are the same fact, so the two fields must never disagree.
fn side_is_consistent(prev: u64, chain_flags: u8, first_flag: u8) -> bool {
    (prev == NULL_ID) == (chain_flags & first_flag != 0)
}

/// **The atomicity half of the property.** While a writer churns the head of V's incidence chain,
/// eight readers hammer the neighbour's record. Not one of them may see its back-pointer and its
/// first-in-chain marker disagree.
///
/// Split `patch_chain_words_latched`'s single `with_page_mut_lsn_if` into two — the pointer words in
/// one, the `chain_flags` byte in another — and this fails: the readers catch the record with
/// `start_prev == 0` and the START marker still clear (or the pointer moved and the marker still set,
/// depending on which half went first), which is a state no snapshot of the chain ever contained.
#[test]
fn a_concurrent_reader_never_sees_a_back_pointer_and_its_marker_disagree() {
    let f = fixture();
    let anchor = f.anchor;

    let stop = Arc::new(AtomicBool::new(false));
    let reads = Arc::new(AtomicU64::new(0));
    // The two states the anchor legitimately alternates between. Seeing only one of them means the
    // reads never overlapped the churn and the run proves nothing — see the controls at the end.
    let saw_head = Arc::new(AtomicU64::new(0));
    let saw_displaced = Arc::new(AtomicU64::new(0));
    let torn: Arc<Mutex<Vec<String>>> = Arc::new(Mutex::new(Vec::new()));

    let readers: Vec<_> = (0..READERS)
        .map(|_| {
            let store = Arc::clone(&f.store);
            let stop = Arc::clone(&stop);
            let reads = Arc::clone(&reads);
            let saw_head = Arc::clone(&saw_head);
            let saw_displaced = Arc::clone(&saw_displaced);
            let torn = Arc::clone(&torn);
            std::thread::spawn(move || {
                let mut local = 0u64;
                let mut local_head = 0u64;
                let mut local_displaced = 0u64;
                while !stop.load(Ordering::Relaxed) {
                    // One `read_rel` decodes the whole 102-byte record inside ONE `with_page_fetched`,
                    // i.e. one acquisition of the frame READ latch — so what it returns is exactly
                    // what a single frame-latch hold on the writer's side is supposed to make atomic.
                    let r = store.rel(anchor).expect("read the anchor");
                    local += 1;
                    if r.start_prev_rel == NULL_ID {
                        local_head += 1;
                    } else {
                        local_displaced += 1;
                    }
                    let bad_start = !side_is_consistent(
                        r.start_prev_rel,
                        r.chain_flags,
                        CHAIN_FLAG_START_FIRST,
                    );
                    let bad_end =
                        !side_is_consistent(r.end_prev_rel, r.chain_flags, CHAIN_FLAG_END_FIRST);
                    if bad_start || bad_end {
                        let side = if bad_start { "START" } else { "END" };
                        torn.lock()
                            .expect("the violation log is poisoned")
                            .push(format!(
                                "{side} side torn: start_prev={} end_prev={} chain_flags={:#06b} \
                             (in_use={})",
                                r.start_prev_rel,
                                r.end_prev_rel,
                                r.chain_flags,
                                r.mvcc.in_use()
                            ));
                        // One is proof; keep going only to bound the log.
                        if torn.lock().expect("the violation log is poisoned").len() > 8 {
                            break;
                        }
                    }
                }
                reads.fetch_add(local, Ordering::Relaxed);
                saw_head.fetch_add(local_head, Ordering::Relaxed);
                saw_displaced.fetch_add(local_displaced, Ordering::Relaxed);
            })
        })
        .collect();

    // The writer. Each round prepends a relationship onto V (which relinks the anchor: `prev :=
    // doomed`, START marker cleared) and rolls it back (which unlinks the doomed head and repoints the
    // anchor: `prev := NULL`, START marker set). Both writes go through `patch_chain_words`.
    for i in 0..ROUNDS {
        let txn = TxnId(1_000 + i);
        f.store.begin(txn);
        f.store
            .create_rel(txn, f.rel_type, f.v, f.w)
            .expect("create the displacing relationship");
        f.store
            .rollback(txn)
            .expect("roll the displacing relationship back");
    }
    stop.store(true, Ordering::Relaxed);
    for h in readers {
        h.join().expect("a reader thread panicked");
    }

    let torn = torn.lock().expect("the violation log is poisoned").clone();
    assert!(
        torn.is_empty(),
        "a reader observed the anchor's back-pointer and its first-in-chain marker disagreeing, \
         which is a state no consistent snapshot of the chain ever contained. `patch_chain_words` \
         must apply the pointer word and the marker byte in ONE `with_page_mut_lsn_if`, because that \
         single frame write-latch hold is what excludes a reader taking the frame read latch \
         (`rmp` #1050 / #1054). Observations: {torn:?}"
    );

    // ---- non-vacuity controls -----------------------------------------------------------------
    let reads = reads.load(Ordering::Relaxed);
    assert!(
        reads >= ROUNDS,
        "the readers made only {reads} observations against {ROUNDS} rounds of churn; a run this \
         thin cannot have sampled the window and proves nothing"
    );
    // THE control that matters. The invariant is trivially true while nothing moves, so a run in
    // which the readers only ever caught the anchor in one of its two states would pass without ever
    // having raced. Requiring both proves the reads and the writes genuinely overlapped.
    let head = saw_head.load(Ordering::Relaxed);
    let displaced = saw_displaced.load(Ordering::Relaxed);
    assert!(
        head > 0 && displaced > 0,
        "the readers observed the anchor as head {head} times and as displaced {displaced} times. \
         Both must be non-zero: if the readers never caught it mid-churn, the invariant they \
         checked was never at risk and this test is vacuous"
    );

    // The end state, for completeness: the chain is exactly as the fixture left it.
    let restored = f.store.rel(anchor).expect("read the anchor at the end");
    assert_eq!(
        f.store.node(f.v).expect("read V").first_rel,
        anchor,
        "every round was rolled back, so V's chain must be headed by the anchor again"
    );
    assert_eq!(
        restored.start_prev_rel, NULL_ID,
        "the anchor is V's head, so its back-pointer must name nobody"
    );
    assert_ne!(
        restored.chain_flags & CHAIN_FLAG_START_FIRST,
        0,
        "the anchor is V's head, so its START first-in-chain marker must be set"
    );
}
