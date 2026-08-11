//! **The rollback unlink writes the chain-head word and nothing else** (`rmp` #1030, acceptance
//! criterion 3).
//!
//! # The defect this exists for
//!
//! `RecordStore::unlink_side_with` repoints a node's `first_rel` when the relationship it is
//! unlinking is the head of that node's incidence chain. It used to do so like this:
//!
//! ```text
//! let is_head = prev == NULL_ID || (prev != id && self.read_node(node)?.first_rel == id);
//! if is_head {
//!     let mut n = self.read_node(node)?;   // <-- a WHOLE-RECORD read
//!     n.first_rel = next;
//!     self.write_node(node, &n, txn)?;     // <-- a WHOLE-RECORD write-back
//! }
//! ```
//!
//! One 8-byte word had to change and all 65 bytes of the `NodeRecord` were written back:
//! `first_prop`, `labels` and the MVCC header rode along from an image read moments earlier. That is
//! the `rmp` #772 clobber class. A writer that committed a change to one of those *other* fields in
//! the gap between the read and the write-back had its committed work silently reverted — a lost
//! update with no error, no log entry, and no reader able to tell afterwards.
//!
//! It now publishes **only** the `first_rel` word, through `compare_and_publish_chain_head`,
//! conditionally on the head still naming the record being unlinked. A neighbouring field is never in
//! the write's footprint at all.
//!
//! # The oracle: the WAL is the ground truth of which bytes a write touched
//!
//! The property is about the **extent** of a write, not about the values it happens to leave behind,
//! and those are two different things. A single-threaded whole-record write-back re-reads the record
//! immediately before writing it, so every neighbouring field is written back with the value it
//! already had: **the page bytes do not change, and no value check anywhere can see it.** The defect
//! is invisible to values and perfectly visible to extents.
//!
//! So this suite reads the write log. Every page change the engine makes is a WAL `Update` record
//! carrying a patch image, and a patch states its own offset and length
//! ([`graphus_storage::paging::encode_patch`] / [`encode_cas_patch`](graphus_storage::paging)). The
//! test marks the log, drives the unlink, decodes every record appended afterwards, and computes the
//! union of the byte offsets written **inside V's node record**. That union must be exactly the eight
//! bytes of `first_rel`.
//!
//! Two things follow from using the log rather than the page, and both matter:
//!
//! * it is **deterministic** — no threads, no scheduler, no interleaving to get lucky with. The
//!   assertion holds or fails identically on every run, on every machine;
//! * it is **exact** — a write that changes no value is still a write, and the log says so.
//!
//! # What failure looks like under the whole-record write-back
//!
//! Restore the read-modify-write above and
//! [`the_rollback_unlink_writes_only_the_chain_head_word`] fails on every run, reporting a written
//! extent of **`0..65`** where it requires **`41..49`**. Measured, not predicted: `write_node` logs
//! the 65-byte post-image as its redo *and* a 65-byte pre-image as its undo, so both halves of the
//! record cover `first_prop` at 49, `labels` at 57 and the MVCC header at 0 — precisely the set of
//! fields a concurrently-committed writer owns.
//!
//! The same run also fails [`the_rollback_unlink_publishes_conditionally`], because a whole-record
//! image is a plain region patch and not a compare-and-set image — so the write is unconditional, and
//! a compare-and-set is sound only while EVERY writer of the word goes through it.
//!
//! [`the_unlinked_node_keeps_its_other_fields`] keeps passing under that mutation, which is exactly
//! why it is documented below as the statement of the property rather than as its proof.
//!
//! # Scope, stated honestly
//!
//! [`the_unlinked_node_keeps_its_other_fields`] states the end-state half of the criterion — after
//! the rollback V's `first_prop`, `labels` and MVCC header still hold their committed values, and
//! `first_rel` reflects the unlink. It is a statement of the property, **not** the teeth: as argued
//! above, a single-threaded whole-record write-back preserves those values and that test would pass
//! with the defect present. The extent and conditionality tests are the ones that fail. They are kept
//! apart deliberately rather than blended into one test that looks stronger than it is.
//!
//! # Running it
//!
//! ```text
//! cargo test -p graphus-dst --test unlink_head_write_extent_1030
//! ```

use std::ops::Range;

use graphus_core::{PageId, TxnId};
use graphus_io::MemBlockDevice;
use graphus_storage::paging::{CAS_SENTINEL, record_location};
use graphus_storage::{MVCC_HEADER_SIZE, NODE_RECORD_SIZE, Namespace, NodeRecord, RecordStore};
use graphus_wal::{LogRecord, MemLogSink, WalManager};

type Store = RecordStore<MemBlockDevice, MemLogSink>;

/// Small enough that eviction and the WAL-before-data rule are live rather than everything staying
/// resident, and large enough that the tiny working set never thrashes.
const POOL_CAPACITY: usize = 16;

/// Byte offset of `first_rel` inside a node record, derived from the layout rather than copied as a
/// magic number: the record is `MVCC header | element_id: u128 | first_rel | first_prop | labels`
/// (`04 §2.3`).
///
/// `NODE_OFF_FIRST_REL` itself is `pub(crate)` in `graphus-storage`, so the derivation is checked at
/// runtime instead of trusted — see [`assert_layout_offsets`], which reads each word out of the raw
/// device page and requires it to equal the decoded record's field.
const OFF_FIRST_REL: usize = MVCC_HEADER_SIZE + size_of::<u128>();
/// Byte offset of `first_prop`, immediately after `first_rel`.
const OFF_FIRST_PROP: usize = OFF_FIRST_REL + size_of::<u64>();
/// Byte offset of the `labels` word, immediately after `first_prop`.
const OFF_LABELS: usize = OFF_FIRST_PROP + size_of::<u64>();

/// The extent a correct unlink is allowed to write inside the node record: the `first_rel` word, and
/// not one byte more.
const ALLOWED: Range<usize> = OFF_FIRST_REL..OFF_FIRST_REL + size_of::<u64>();

/// One patch found in the log, reduced to what this suite reasons about.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Touch {
    /// Byte range **relative to the start of the node record**.
    extent: Range<usize>,
    /// Whether the image was a compare-and-set (`encode_cas_patch`) rather than a plain region
    /// overwrite (`encode_patch`).
    conditional: bool,
    /// `(expect, new)` of a compare-and-set image.
    cas: Option<(u64, u64)>,
    /// Whether this came from the record's redo image (`false` = its undo image). Both are writes the
    /// engine may perform: an undo image is replayed onto the page by rollback and by recovery.
    redo: bool,
}

/// The fixture: a node V that carries all three words at once, so a clobber of any of them is
/// observable, plus the second endpoint the aborted relationship needs.
struct Fixture {
    store: Store,
    /// The node whose chain head the unlink repoints.
    v: u64,
    /// The relationship committed before the aborted one; V's head again once the unlink is done.
    anchor_rel: u64,
    /// The other endpoint of the relationship that gets created and aborted.
    w: u64,
    rel_type: u32,
    /// V's record image after the seed commit.
    seeded: NodeRecord,
    /// V's node record on the device: which page, and at which offset within it.
    page: PageId,
    off: usize,
}

/// Builds the fixture and commits it, so everything the unlink must not disturb is durable and
/// non-zero before the aborting transaction starts.
fn fixture() -> Fixture {
    let device = MemBlockDevice::new(0);
    let wal = WalManager::create(MemLogSink::new()).expect("create wal");
    let store = RecordStore::create(device, wal, POOL_CAPACITY, 1).expect("create store");

    let t0 = TxnId(1);
    store.begin(t0);
    let rel_type = store
        .intern_token(Namespace::RelType, "KNOWS")
        .expect("intern relationship type");
    let label = store
        .intern_token(Namespace::Label, "Anchor")
        .expect("intern label");
    let key = store
        .intern_token(Namespace::PropKey, "seed")
        .expect("intern property key");

    let (v, _) = store.create_node(t0).expect("create V");
    let (u, _) = store.create_node(t0).expect("create U");
    let (w, _) = store.create_node(t0).expect("create W");
    store
        .add_node_property(t0, v, key, 1, 0x5EED)
        .expect("give V a property");
    store.add_label(t0, v, label).expect("give V a label");
    let (anchor_rel, _) = store
        .create_rel(t0, rel_type, v, u)
        .expect("create the anchor relationship");
    store.commit(t0).expect("commit the seed state");

    let seeded = store.node(v).expect("read V after the seed commit");
    assert_eq!(
        seeded.first_rel, anchor_rel,
        "the fixture must leave V's incidence chain headed by the anchor relationship"
    );
    assert_ne!(
        seeded.first_prop, 0,
        "the fixture must leave V's `first_prop` non-zero, or a clobber of it says nothing"
    );
    assert_ne!(
        seeded.labels, 0,
        "the fixture must leave V's `labels` non-zero, or a clobber of it says nothing"
    );
    assert_ne!(
        seeded.mvcc.undo_ptr, 0,
        "the fixture must leave V's MVCC header carrying an undo-chain head"
    );

    let (page, off) = locate_node_record(&store, v, &seeded);
    assert_layout_offsets(&store, page, off, &seeded);
    Fixture {
        store,
        v,
        anchor_rel,
        w,
        rel_type,
        seeded,
        page,
        off,
    }
}

/// Finds the device page holding node `id`'s record, and the record's offset within it.
///
/// The store does not expose its per-store page mapping, so the page is **identified by its
/// contents** and the identification is required to be unique: the offset comes from
/// [`record_location`], and the page is the one whose three words at that offset are exactly the
/// record's `first_rel` / `first_prop` / `labels`. All three are non-zero in this fixture, so a
/// coincidental match is not a practical concern — and the uniqueness assertion below turns "not a
/// practical concern" into a checked claim.
fn locate_node_record(store: &Store, id: u64, rec: &NodeRecord) -> (PageId, usize) {
    let (_, off) = record_location(id, NODE_RECORD_SIZE);
    let mut found: Vec<PageId> = Vec::new();
    for page in store.mapped_pages() {
        let bytes = store.read_device_page(page).expect("read a device page");
        if bytes.len() < off + NODE_RECORD_SIZE {
            continue;
        }
        let word = |at: usize| {
            u64::from_le_bytes(bytes[off + at..off + at + 8].try_into().expect("8 bytes"))
        };
        if word(OFF_FIRST_REL) == rec.first_rel
            && word(OFF_FIRST_PROP) == rec.first_prop
            && word(OFF_LABELS) == rec.labels
        {
            found.push(page);
        }
    }
    assert_eq!(
        found.len(),
        1,
        "node {id}'s record must be identifiable on exactly one device page, found {found:?}. \
         Without a unique page the extent oracle below would be reading somebody else's bytes."
    );
    (found[0], off)
}

/// Checks the layout offsets this suite derives against the live record, so the constants above are a
/// verified claim rather than three magic numbers that quietly stop meaning anything if the record
/// layout changes.
fn assert_layout_offsets(store: &Store, page: PageId, off: usize, rec: &NodeRecord) {
    let bytes = store.read_device_page(page).expect("read the node page");
    let word =
        |at: usize| u64::from_le_bytes(bytes[off + at..off + at + 8].try_into().expect("8 bytes"));
    assert_eq!(
        word(OFF_FIRST_REL),
        rec.first_rel,
        "the derived `first_rel` offset ({OFF_FIRST_REL}) does not name `first_rel` on the page"
    );
    assert_eq!(
        word(OFF_FIRST_PROP),
        rec.first_prop,
        "the derived `first_prop` offset ({OFF_FIRST_PROP}) does not name `first_prop` on the page"
    );
    assert_eq!(
        word(OFF_LABELS),
        rec.labels,
        "the derived `labels` offset ({OFF_LABELS}) does not name `labels` on the page"
    );
}

/// The derived offsets must lie inside the record they describe. A compile-time check, because it is
/// a statement about two constants and nothing about a run could change the answer.
const _: () = assert!(
    ALLOWED.end <= NODE_RECORD_SIZE,
    "the allowed extent must lie inside the node record"
);

/// The hardened log as bytes. Every append this suite cares about is hardened first, so the mark and
/// the tail are taken from the same durable image.
fn hardened_log(store: &Store) -> Vec<u8> {
    store.harden_wal();
    store.with_wal(|w| w.sink().durable_bytes())
}

/// One decoded patch image: the page bytes it writes, and how it writes them.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Patched {
    /// Byte range **within the page**.
    extent: Range<usize>,
    /// A compare-and-set image rather than a plain region overwrite.
    conditional: bool,
    /// `(expect, new)` of a compare-and-set image.
    cas: Option<(u64, u64)>,
}

/// Decodes the patch at the head of a WAL image into the byte range it writes, plus how it writes it.
///
/// Mirrors [`graphus_storage::paging::apply_patch`]'s own reading of the two image shapes — a plain
/// `[offset: u16][bytes]` region overwrite, and a `[CAS_SENTINEL][offset: u16][expect: u64][new: u64]`
/// compare-and-set — because the point of this suite is to state exactly which bytes each shape
/// touches.
fn decode_patch(image: &[u8]) -> Option<Patched> {
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
        let expect = u64::from_le_bytes(image[4..12].try_into().expect("8 bytes"));
        let new = u64::from_le_bytes(image[12..20].try_into().expect("8 bytes"));
        return Some(Patched {
            extent: at..at + 8,
            conditional: true,
            cas: Some((expect, new)),
        });
    }
    let at = usize::from(lead);
    Some(Patched {
        extent: at..at + image.len() - 2,
        conditional: false,
        cas: None,
    })
}

/// Every write the log records **inside** node record `[off, off + NODE_RECORD_SIZE)` of `page`, from
/// byte `from` of the log onwards, as offsets relative to the start of that record.
///
/// Both the redo and the undo image of each record are examined. An undo image is not commentary: it
/// is replayed onto the page by live rollback and by recovery, so a whole-record pre-image undo
/// clobbers a neighbouring field exactly as a whole-record post-image redo does — that is the shape
/// `rmp` #772 was.
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
            let Some(patched) = decode_patch(image) else {
                continue;
            };
            // Only the part that lands inside THIS record. The node page holds other nodes' records
            // too — W's side of the same relationship is unlinked on this very page — and a write to
            // a neighbouring record is not this record's business.
            let lo = patched.extent.start.max(off);
            let hi = patched.extent.end.min(off + NODE_RECORD_SIZE);
            if lo < hi {
                touches.push(Touch {
                    extent: lo - off..hi - off,
                    conditional: patched.conditional,
                    cas: patched.cas,
                    redo,
                });
            }
        }
    }
    touches
}

/// The union of a set of touches, as a sorted list of maximal ranges — what the assertions read.
fn union(touches: &[Touch]) -> Vec<Range<usize>> {
    let mut ranges: Vec<Range<usize>> = touches.iter().map(|t| t.extent.clone()).collect();
    ranges.sort_by_key(|r| (r.start, r.end));
    let mut merged: Vec<Range<usize>> = Vec::new();
    for r in ranges {
        match merged.last_mut() {
            Some(last) if r.start <= last.end => last.end = last.end.max(r.end),
            _ => merged.push(r),
        }
    }
    merged
}

/// Runs the aborting transaction and returns every write it logged inside V's record.
///
/// The log is marked **after** the relationship has been created and prepended, so the only writes in
/// the window are the rollback's own: the prepend's publication (which `rmp` #1028 already scoped to
/// the word) is not what this criterion is about.
fn unlink_writes(f: &Fixture) -> (Vec<Touch>, u64) {
    let before = hardened_log(&f.store);
    let mark = before.len();

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
         neighbour branch of `unlink_side_with` and never repoints a head at all"
    );

    // The mark: everything the prepend logged is already behind us, so what follows is the rollback.
    let marked = hardened_log(&f.store);
    let mark_after_prepend = marked.len();
    assert!(
        mark_after_prepend > mark,
        "the prepend logged nothing at all, so the window below cannot be attributed to anything"
    );

    f.store
        .rollback(txn)
        .expect("the logical rollback that unlinks the relationship failed");

    let after = hardened_log(&f.store);
    assert!(
        after.len() > mark_after_prepend,
        "the rollback logged nothing: `rollback_logical` never ran, so this test proves nothing"
    );
    (
        writes_inside_record(&after, mark_after_prepend, f.page, f.off),
        doomed,
    )
}

/// **Acceptance criterion 3, the teeth.** The unlink performed by a logical rollback writes exactly
/// the eight bytes of `first_rel` inside the node record, and nothing else.
#[test]
fn the_rollback_unlink_writes_only_the_chain_head_word() {
    let f = fixture();
    let (touches, doomed) = unlink_writes(&f);

    // Non-vacuity first: an empty set of touches would satisfy "wrote nothing outside the word"
    // trivially, and would mean the unlink never touched V's record at all.
    assert!(
        !touches.is_empty(),
        "the rollback logged no write inside node {}'s record on page {:?}. The unlink of \
         relationship {doomed} must repoint V's `first_rel`, so a window with no write in it means \
         the oracle is looking at the wrong page or the wrong offset — not that the engine behaved.",
        f.v,
        f.page
    );

    let extents = union(&touches);
    assert_eq!(
        extents,
        vec![ALLOWED],
        "`rmp` #1030/#772 — the rollback unlink wrote {:?} inside node {}'s {NODE_RECORD_SIZE}-byte \
         record, but it may write ONLY {ALLOWED:?}, the `first_rel` word. Anything wider is a \
         read-modify-write of a record whose other fields — `first_prop` at {OFF_FIRST_PROP}, \
         `labels` at {OFF_LABELS}, the MVCC header at 0 — belong to whichever transaction last \
         committed a change to them, and rewriting them from a stale image reverts that committed \
         work with no error and no trace. Images logged: {:#?}",
        extents,
        f.v,
        touches
    );
}

/// **Acceptance criterion 3, the other half of "publishes the word".** The write is a
/// **compare-and-set** on the head, not an unconditional store.
///
/// A compare-and-set is sound only while EVERY writer of the word goes through it: one writer that
/// stores unconditionally makes every other writer's comparison meaningless. So "wrote only eight
/// bytes" is not enough on its own — the eight bytes must be published conditionally, naming the
/// record being unlinked as the head it expects.
#[test]
fn the_rollback_unlink_publishes_conditionally() {
    let f = fixture();
    let (touches, doomed) = unlink_writes(&f);

    assert!(
        !touches.is_empty(),
        "the rollback logged no write inside node {}'s record — see the extent test",
        f.v
    );
    for touch in &touches {
        assert!(
            touch.conditional,
            "`rmp` #1030 — the rollback unlink published node {}'s chain head with an \
             UNCONDITIONAL image ({}) covering {:?}. The head must be published by \
             compare-and-set: the read that decides headship happens outside the publication latch, \
             so between it and the write another writer can prepend, and an unconditional store then \
             publishes over the entry that writer just linked in. Images logged: {:#?}",
            f.v,
            if touch.redo { "redo" } else { "undo" },
            touch.extent,
            touches
        );
    }
    let publications: Vec<(u64, u64)> = touches.iter().filter_map(|t| t.cas).collect();
    assert!(
        publications.contains(&(doomed, f.anchor_rel)),
        "`rmp` #1030 — no publication expected the unlinked relationship {doomed} and installed the \
         anchor relationship {} in its place; the compare-and-set images found were {publications:?}. \
         The condition has to name the record being unlinked, or the compare cannot detect that the \
         head moved.",
        f.anchor_rel
    );
}

/// **Acceptance criterion 3, stated as the end state.** After the rollback, the fields the unlink
/// does not own still hold their committed values, and the field it does own reflects the unlink.
///
/// This is the property in the words the task uses. It is deliberately **not** claimed as the teeth:
/// a single-threaded whole-record write-back re-reads the record immediately before writing it, so
/// these values survive it and this test passes with the defect present. The extent and
/// conditionality tests above are the ones that fail.
#[test]
fn the_unlinked_node_keeps_its_other_fields() {
    let f = fixture();
    let (_, doomed) = unlink_writes(&f);
    let after = f.store.node(f.v).expect("read V after the rollback");

    assert_eq!(
        after.first_prop, f.seeded.first_prop,
        "`rmp` #1030 — unlinking relationship {doomed} moved node {}'s `first_prop` from {} to {}. \
         The unlink owns `first_rel` and nothing else.",
        f.v, f.seeded.first_prop, after.first_prop
    );
    assert_eq!(
        after.labels, f.seeded.labels,
        "`rmp` #1030 — unlinking relationship {doomed} changed node {}'s `labels` word from {:#x} to \
         {:#x}",
        f.v, f.seeded.labels, after.labels
    );
    assert_eq!(
        after.mvcc, f.seeded.mvcc,
        "`rmp` #1030 — unlinking relationship {doomed} rewrote node {}'s MVCC header",
        f.v
    );
    assert_eq!(
        after.element_id, f.seeded.element_id,
        "`rmp` #1030 — unlinking relationship {doomed} rewrote node {}'s element id",
        f.v
    );
    assert_eq!(
        after.first_rel, f.anchor_rel,
        "`rmp` #1030 — relationship {doomed} was ABORTED, so node {}'s chain head must be the anchor \
         relationship {} again; it is {}",
        f.v, f.anchor_rel, after.first_rel
    );

    // And the chain the head names must still be walkable, so the unlink left a well-formed chain
    // rather than a head pointing at a record it also detached.
    let incident = f
        .store
        .incident_rels(f.v)
        .expect("walk V's incidence chain");
    assert_eq!(
        incident,
        vec![f.anchor_rel],
        "after the rollback V's incidence chain must hold exactly the anchor relationship"
    );
}
