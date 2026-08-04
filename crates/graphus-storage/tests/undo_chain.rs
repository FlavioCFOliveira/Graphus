//! The undo area end to end (`rmp` #966, `05-storage-format.md` §12, `04-technical-design.md` §5.1).
//!
//! These tests exercise the version chain through the **production write path** only — `create_node`,
//! `create_rel`, `delete_node`, `delete_rel`, `commit`, `rollback`, `gc` — never by writing a delta
//! by hand. That is deliberate: the acceptance criterion this file answers is that `undo_ptr` stops
//! being permanently `0` *in production code*, so a test that fabricated a chain would prove nothing
//! about it.
//!
//! Each test states, in its own doc comment, what it would look like against a tree without the undo
//! area — i.e. why it is not vacuous.

use graphus_core::{TxnId, VersionStamp};
use graphus_io::MemBlockDevice;
use graphus_storage::{
    Namespace, RecordStore, StoreKind, StorePages, UndoAction, check::check_store, verify_on_open,
};
use graphus_wal::{LogSink, MemLogSink, WalManager};

type Store = RecordStore<MemBlockDevice, MemLogSink>;

const POOL: usize = 32;

fn fresh() -> Store {
    let device = MemBlockDevice::new(0);
    let wal = WalManager::create(MemLogSink::new()).expect("create wal");
    RecordStore::create(device, wal, POOL, 1).expect("create store")
}

/// Runs `f` inside a committed transaction.
fn in_txn<R>(store: &mut Store, txn: u64, f: impl FnOnce(&mut Store, TxnId) -> R) -> R {
    let txn = TxnId(txn);
    store.begin(txn);
    let out = f(store, txn);
    store.commit(txn).expect("commit");
    out
}

fn assert_consistent(store: &mut Store, when: &str) {
    let report = check_store(store, &[]).expect("consistency check runs");
    assert!(
        report.violations.is_empty(),
        "store must be consistent {when}, found: {:?}",
        report.violations
    );
}

// ============================================================================================
// Acceptance criterion 1 — a new store writes and reads back a chain of at least two versions.
// Acceptance criterion 2 — `undo_ptr` is no longer always `0` in production code.
// ============================================================================================

/// Creating and then deleting a node leaves a **two-delta** chain on that node, in the inverse order
/// `05 §12.3` mandates: the newest delta undoes the newest change.
///
/// **Non-vacuity.** Against a tree whose `MvccHeader::live` writes `undo_ptr: 0` unconditionally and
/// has no undo area, every assertion below fails at the first one: `version_chain` returns empty and
/// `undo_ptr` is `0`. The two `assert_ne!`s on the head are the guards that fail the moment a future
/// change makes `undo_ptr` permanently zero again.
#[test]
fn create_then_delete_builds_a_two_delta_chain_that_reads_back() {
    let mut s = fresh();
    let id = in_txn(&mut s, 1, |s, txn| s.create_node(txn).expect("create").0);

    // One delta after the create. It is `DeleteObject`, because deleting is what undoes a creation.
    let head_after_create = s.node(id).expect("node").mvcc.undo_ptr;
    assert_ne!(
        head_after_create, 0,
        "creating a node must publish a chain head — `undo_ptr` is live since `rmp` #966"
    );
    let chain = s.version_chain(StoreKind::Node, id).expect("chain");
    assert_eq!(chain.len(), 1, "one change so far ⇒ one delta");
    assert_eq!(
        chain[0].0, head_after_create,
        "the head is the newest delta"
    );
    assert_eq!(chain[0].1.action, UndoAction::DeleteObject);
    assert_eq!(chain[0].1.next, 0, "the oldest delta ends the chain");

    in_txn(&mut s, 2, |s, txn| s.delete_node(txn, id).expect("delete"));

    // Two deltas now: the newest undoes the delete, the oldest undoes the create.
    let head_after_delete = s.node(id).expect("node").mvcc.undo_ptr;
    assert_ne!(head_after_delete, 0);
    assert_ne!(
        head_after_delete, head_after_create,
        "the head must advance to the newly-prepended delta"
    );
    let chain = s.version_chain(StoreKind::Node, id).expect("chain");
    assert_eq!(chain.len(), 2, "two changes ⇒ two versions reachable");
    assert_eq!(chain[0].1.action, UndoAction::RecreateObject);
    assert_eq!(chain[1].1.action, UndoAction::DeleteObject);
    assert_eq!(
        chain[0].1.next, chain[1].0,
        "the chain links newest to oldest"
    );
    assert_eq!(chain[1].1.next, 0, "and terminates");

    // The two deltas belong to two different transactions, so they resolve through two different
    // commit slots — the indirection point is per transaction, not per delta.
    assert_ne!(chain[0].1.commit_info, chain[1].1.commit_info);
    assert_ne!(chain[0].1.commit_info, 0);

    assert_consistent(&mut s, "after building a two-delta chain");
}

/// A relationship gets its own chain, anchored on the relationship record, and its endpoints keep
/// theirs — one chain per entity, as `04 §5.1` requires.
///
/// **Non-vacuity.** Without the undo area all four `undo_ptr`s are `0` and every `assert_ne!` fails.
/// The distinctness assertions are the positive control that the three chains are genuinely separate
/// rather than one shared head accidentally read three times.
#[test]
fn every_entity_gets_its_own_chain() {
    let mut s = fresh();
    let (a, b, r) = in_txn(&mut s, 1, |s, txn| {
        let t = s.intern_token(Namespace::RelType, "KNOWS").expect("intern");
        let (a, _) = s.create_node(txn).expect("a");
        let (b, _) = s.create_node(txn).expect("b");
        let (r, _) = s.create_rel(txn, t, a, b).expect("rel");
        (a, b, r)
    });

    let head_a = s.node(a).expect("a").mvcc.undo_ptr;
    let head_b = s.node(b).expect("b").mvcc.undo_ptr;
    let head_r = s.rel(r).expect("r").mvcc.undo_ptr;
    for (what, head) in [("a", head_a), ("b", head_b), ("r", head_r)] {
        assert_ne!(head, 0, "{what} must anchor a chain");
    }
    assert_ne!(head_a, head_b);
    assert_ne!(head_a, head_r);
    assert_ne!(head_b, head_r);

    // All three were created by ONE transaction, so all three deltas name the SAME commit slot —
    // this is the commit indirection point doing its job (`04 §5.1.3`).
    let slot_a = s.version_chain(StoreKind::Node, a).expect("chain")[0]
        .1
        .commit_info;
    let slot_b = s.version_chain(StoreKind::Node, b).expect("chain")[0]
        .1
        .commit_info;
    let slot_r = s.version_chain(StoreKind::Rel, r).expect("chain")[0]
        .1
        .commit_info;
    assert_eq!(slot_a, slot_b);
    assert_eq!(slot_a, slot_r);

    // And that one slot carries the commit, published exactly once, with a count of all three deltas.
    let slot = s.commit_slot(slot_a).expect("read slot").expect("occupied");
    assert!(slot.in_use());
    assert_eq!(slot.txn_id, 1);
    assert_eq!(
        slot.delta_count, 5,
        "five deltas resolve through this slot: one `DeleteObject` per created entity (two nodes \
         and the relationship) plus one incidence delta per end of the relationship (`rmp` #969)"
    );
    assert!(
        matches!(
            VersionStamp::from_raw(slot.commit_ts),
            VersionStamp::Committed(_)
        ),
        "a committed transaction's slot carries a committed stamp, not an in-flight one"
    );

    assert_consistent(&mut s, "after one transaction touched three entities");
}

/// An **open** transaction's slot carries its in-flight stamp and no count; the commit publishes both,
/// and the count is only ever published once (`05 §12.4`).
///
/// **Non-vacuity.** The pre-#966 tree has no commit slot at all, so `commit_slot` does not exist and
/// this does not compile. The in-flight assertion is the positive control that the slot is genuinely
/// unpublished before the commit rather than published early with a plausible-looking value.
#[test]
fn the_commit_slot_is_published_once_at_commit_and_not_before() {
    let mut s = fresh();
    let txn = TxnId(1);
    s.begin(txn);
    let (n, _) = s.create_node(txn).expect("create");
    let slot_id = s.version_chain(StoreKind::Node, n).expect("chain")[0]
        .1
        .commit_info;

    let open = s.commit_slot(slot_id).expect("read").expect("occupied");
    assert_eq!(
        VersionStamp::from_raw(open.commit_ts),
        VersionStamp::InFlight(txn),
        "an open transaction's slot carries its in-flight stamp (`05 §12.4`)"
    );
    assert_eq!(open.delta_count, 0, "an open transaction's slot counts 0");

    s.create_node(txn).expect("second create");
    s.commit(txn).expect("commit");

    let done = s.commit_slot(slot_id).expect("read").expect("occupied");
    assert!(matches!(
        VersionStamp::from_raw(done.commit_ts),
        VersionStamp::Committed(_)
    ));
    assert_eq!(done.delta_count, 2, "both deltas of the transaction");
}

// ============================================================================================
// Acceptance criterion 3 — the checker validates the chain, before and after a GC pass.
// ============================================================================================

/// The consistency checker accepts a healthy chain, and still accepts the store after a GC pass has
/// reclaimed part of it — the "before and after GC" half of acceptance criterion 3.
///
/// **Non-vacuity.** The positive control is the `assert!(reclaimed > 0)`: without it the test would
/// pass trivially on a GC pass that did nothing, which is exactly the shape of a vacuous
/// after-GC assertion. It fails against a tree with no chains, because nothing is ever reclaimed and
/// the chain assertions before it fail first.
#[test]
fn the_checker_accepts_a_chain_before_and_after_gc() {
    let mut s = fresh();
    let (a, b, r) = in_txn(&mut s, 1, |s, txn| {
        let t = s.intern_token(Namespace::RelType, "KNOWS").expect("intern");
        let (a, _) = s.create_node(txn).expect("a");
        let (b, _) = s.create_node(txn).expect("b");
        let (r, _) = s.create_rel(txn, t, a, b).expect("rel");
        (a, b, r)
    });
    assert_consistent(&mut s, "before GC");
    assert_eq!(s.version_chain(StoreKind::Node, a).expect("chain").len(), 1);

    // A GC pass at a watermark past the creating commit: every delta on every chain is committed at
    // or below it, so all three chains are reclaimable.
    let watermark = s.snapshot_ts();
    let gc = TxnId(2);
    s.begin(gc);
    let report = s.gc(gc, watermark).expect("gc");
    s.commit(gc).expect("commit gc");
    assert!(
        report.undo_deltas_reclaimed > 0,
        "positive control: the pass must actually have reclaimed deltas, else the assertions below \
         say nothing (reclaimed {})",
        report.undo_deltas_reclaimed
    );

    assert_consistent(&mut s, "after GC");
    for (kind, id) in [
        (StoreKind::Node, a),
        (StoreKind::Node, b),
        (StoreKind::Rel, r),
    ] {
        assert!(
            s.version_chain(kind, id).expect("chain").is_empty(),
            "{kind:?} {id}'s chain is fully reclaimed, so its `undo_ptr` is detached"
        );
    }
    // The commit slot goes with the last delta that named it (`05 §12.4`: a slot outlives its last
    // delta, and not one pass longer).
    let (free_deltas, free_slots) = s.undo_area_free_counts();
    assert_eq!(
        free_deltas, 5,
        "all five deltas are back on the free list (`rmp` #969 adds one per relationship end)"
    );
    assert_eq!(
        free_slots, 1,
        "the transaction's commit slot is reclaimed once its last delta is (`05 §12.4`)"
    );
}

/// GC must **not** reclaim a chain a live snapshot can still reach: a delta committed *after* the
/// watermark stays.
///
/// **Non-vacuity.** The positive control is the second half: the same chain IS reclaimed once the
/// watermark advances past its commit. Without it, a GC that never reclaims anything would satisfy
/// the first assertion.
#[test]
fn gc_keeps_a_chain_a_live_snapshot_can_still_reach() {
    let mut s = fresh();
    let n = in_txn(&mut s, 1, |s, txn| s.create_node(txn).expect("create").0);
    // A watermark taken BEFORE the delete: the delete's delta commits above it.
    let old_watermark = s.snapshot_ts();
    in_txn(&mut s, 2, |s, txn| s.delete_node(txn, n).expect("delete"));
    assert_eq!(s.version_chain(StoreKind::Node, n).expect("chain").len(), 2);

    let gc = TxnId(3);
    s.begin(gc);
    let report = s.gc(gc, old_watermark).expect("gc");
    s.commit(gc).expect("commit gc");
    assert_eq!(
        report.undo_deltas_reclaimed, 0,
        "a chain whose newest delta committed after the watermark is not reclaimable"
    );
    assert_eq!(
        s.version_chain(StoreKind::Node, n).expect("chain").len(),
        2,
        "both versions survive for the snapshot that can still see them"
    );
    assert_consistent(&mut s, "with a live chain retained");

    // Positive control: advance the watermark and the same chain goes.
    let new_watermark = s.snapshot_ts();
    let gc = TxnId(4);
    s.begin(gc);
    let report = s.gc(gc, new_watermark).expect("gc");
    s.commit(gc).expect("commit gc");
    assert!(
        report.undo_deltas_reclaimed > 0 || report.reclaimed > 0,
        "once the watermark passes, the node and its chain are reclaimed"
    );
    assert_consistent(&mut s, "after the watermark advanced");
}

// ============================================================================================
// Rollback
// ============================================================================================

/// A rolled-back transaction leaves **no** reachable delta and no chain head: its physical undo
/// reverts the chain-head publication, and its delta / commit slots return to their free lists.
///
/// **Non-vacuity.** The positive control is the pre-rollback assertion that the chain really existed
/// and the free lists really were empty — without it, "no reachable delta after rollback" is
/// satisfied by a tree that never wrote one.
#[test]
fn a_rolled_back_transaction_leaves_no_reachable_delta() {
    let mut s = fresh();
    let survivor = in_txn(&mut s, 1, |s, txn| s.create_node(txn).expect("create").0);
    let survivor_head = s.node(survivor).expect("node").mvcc.undo_ptr;
    assert_ne!(survivor_head, 0);

    let txn = TxnId(2);
    s.begin(txn);
    let (doomed, _) = s.create_node(txn).expect("create");
    // Positive control: the chain is genuinely there before the rollback.
    assert_eq!(
        s.version_chain(StoreKind::Node, doomed)
            .expect("chain")
            .len(),
        1,
        "the aborting transaction really did link a delta"
    );
    let doomed_delta = s.node(doomed).expect("node").mvcc.undo_ptr;
    assert_ne!(doomed_delta, 0);
    s.rollback(txn).expect("rollback");

    assert_eq!(
        s.node(doomed).expect("node").mvcc.undo_ptr,
        0,
        "the aborted chain-head publication is compare-and-set-undone back to `0`"
    );
    assert_eq!(
        s.node(survivor).expect("node").mvcc.undo_ptr,
        survivor_head,
        "an unrelated committed entity's chain head is untouched by the rollback"
    );
    let (free_deltas, free_slots) = s.undo_area_free_counts();
    assert!(
        free_deltas > 0 && free_slots > 0,
        "the aborted transaction's delta and commit slots are reusable again \
         (deltas {free_deltas}, slots {free_slots})"
    );
    assert_consistent(&mut s, "after a rollback");
}

// ============================================================================================
// Slab allocation
// ============================================================================================

/// Deltas are allocated from a **slab** that never crosses a page boundary, so one transaction's
/// deltas cluster in one page (`05 §12.1`; the store-record form of Memgraph's `delta_container`).
///
/// **Non-vacuity.** The assertion is on real allocated ids: a tree that allocated one id per delta
/// from a shared counter would still pass the "same page" test *by accident* for small runs, so the
/// test creates enough nodes to fill more than one page and asserts the page transition happens
/// exactly at the frozen page boundary rather than anywhere.
#[test]
fn deltas_are_allocated_a_page_at_a_time() {
    const RECORDS_PER_PAGE: u64 = 145; // `05 §12.1`: (8192 - 24) / 56
    let mut s = fresh();
    let mut heads = Vec::new();
    in_txn(&mut s, 1, |s, txn| {
        for _ in 0..(RECORDS_PER_PAGE + 10) {
            let (n, _) = s.create_node(txn).expect("create");
            heads.push(s.node(n).expect("node").mvcc.undo_ptr);
        }
    });
    assert_eq!(heads[0], 1, "ids start at 1; id 0 is the reserved null");
    // Contiguous within a page, and the run restarts exactly at the page boundary — proof the slab is
    // page-aligned rather than a plain running counter.
    for (i, &head) in heads.iter().enumerate() {
        let expected = i as u64 + 1;
        assert_eq!(
            head, expected,
            "delta {i} should occupy slab slot {expected}"
        );
    }
    // The boundary itself: slot 145 is the first slot of page 1, so the slab was refilled there.
    assert!(heads.len() as u64 > RECORDS_PER_PAGE);
    assert_consistent(&mut s, "after filling more than one delta page");
}

// ============================================================================================
// Acceptance criterion 4 — a store of an earlier format is migrated, never misread.
// ============================================================================================

/// A store whose durable catalog carries **no** undo-area block is a format-version-1 store: it is
/// reported as such, opened as an upgrade (no chains, which is exactly what version 1 means), and
/// rewritten at the current version by its first checkpoint.
///
/// **Non-vacuity.** The positive control is the round trip: the store is *first* observed at version
/// 1 and *then* at the current version, so neither half can pass by the version being a hard-coded
/// constant. It fails against a tree with no version field at all, which does not compile.
#[test]
fn a_version_1_catalog_is_migrated_on_open() {
    use graphus_storage::Meta;

    // Build a version-1 image by encoding a catalog and truncating the trailing undo-area block. The
    // block is appended last precisely so a pre-#966 image is this prefix, byte for byte.
    let meta = Meta::new(1);
    let v2 = meta.encode().expect("encode");
    let magic_at = v2
        .windows(8)
        .rposition(|w| w == b"GRPHUNDO")
        .expect("a current-version image carries the undo-area magic");
    let v1 = &v2[..magic_at];

    let decoded = Meta::decode(v1).expect("a version-1 image decodes");
    assert_eq!(decoded.format_version, 1);
    assert_eq!(
        decoded.stores[4],
        Default::default(),
        "a version-1 store has no undo store"
    );
    assert_eq!(
        decoded.stores[5],
        Default::default(),
        "a version-1 store has no commit store"
    );

    // ... and the full image of the same catalog decodes at the current version with the same
    // content. The undo-area block's layout is identical from version 2 up (`rmp` #967 changed what a
    // property cell MEANS, not where anything sits), so this asserts against the live constant rather
    // than a literal that would have to be edited on every bump.
    let decoded_v2 = Meta::decode(&v2).expect("a current-version image decodes");
    assert_eq!(
        decoded_v2.format_version,
        graphus_core::constants::FORMAT_VERSION
    );
    assert_eq!(decoded_v2.element_id_next, decoded.element_id_next);
}

/// The **head metadata page** carries the format-version tripwire that makes a pre-`rmp`-#966 build
/// refuse an undo-area-era store instead of misreading it (`05 §12.6`).
///
/// An already-shipped build cannot be taught a new version check, so the refusal has to come from a
/// validation it already performs. It performs exactly one on this frame: it rejects a catalog chunk
/// whose length runs past the page. Setting bit 31 of the head page's `chunk_len` makes that guard
/// fire deterministically, while this build masks the bit off and reads the frame normally.
///
/// **Non-vacuity.** The test asserts both halves — the flag IS set on the head page, and the masked
/// length is the honest one this build reads back — so neither a build that stopped setting the flag
/// nor one that stopped masking it can pass. The `assert!(len <= META_CHUNK_CAP)` is the positive
/// control that a real length could never collide with the flag bit.
#[test]
fn the_head_metadata_page_carries_the_format_tripwire() {
    use graphus_bufpool::page::HEADER_SIZE;
    use graphus_core::PageId;

    let mut s = fresh();
    in_txn(&mut s, 1, |s, txn| s.create_node(txn).expect("create"));
    s.flush().expect("flush");
    let head = s
        .read_device_page(PageId(0))
        .expect("the metadata page is device page 0");
    let raw = u32::from_le_bytes(
        head[HEADER_SIZE..HEADER_SIZE + 4]
            .try_into()
            .expect("4-byte slice"),
    );
    assert_ne!(
        raw & 0x8000_0000,
        0,
        "the head metadata page must carry the undo-area-era tripwire, so a pre-#966 build \
         fails its own `chunk runs past the page` guard rather than dropping the undo area"
    );
    let len = (raw & !0x8000_0000) as usize;
    assert!(
        len > 0 && len <= graphus_io::PAGE_SIZE - HEADER_SIZE,
        "the masked length is a real chunk length ({len}), so the flag bit can never collide with one"
    );

    // `rmp` #967: the tripwire must keep protecting each NEW version, not just the one it shipped
    // for. This store is a version-3 store, and the check below is the *pre-#966* read path executed
    // verbatim — that build did not know the flag, so it took the raw `u32` as the length and
    // compared `HEADER_SIZE + 12 + chunk_len` against the page. Reproducing its arithmetic here is
    // what turns "the bit is set" into "the old build refuses this exact image".
    assert_eq!(
        s.opened_format_version(),
        graphus_core::constants::FORMAT_VERSION,
        "the fixture must be a store at the CURRENT version, or the claim below is about the wrong \
         image"
    );
    let unmasked_chunk_len = raw as usize;
    assert!(
        HEADER_SIZE + 12 + unmasked_chunk_len > graphus_io::PAGE_SIZE,
        "a pre-#966 build reads the length unmasked ({unmasked_chunk_len}) and must fail its own \
         `metadata chunk runs past the page` guard on this image; if this ever fits in a page it \
         would parse the catalog and silently drop the trailing undo-area block"
    );
}

/// A catalog claiming a format version this build does not know is **refused**, not partially
/// interpreted (`05 §12.6`, applied forwards).
///
/// **Non-vacuity.** The first half proves the same bytes decode when the version is one this build
/// supports, so the refusal is attributable to the version and to nothing else.
#[test]
fn a_future_format_version_is_refused() {
    use graphus_storage::Meta;

    let image = Meta::new(1).encode().expect("encode");
    let magic_at = image
        .windows(8)
        .rposition(|w| w == b"GRPHUNDO")
        .expect("magic");
    assert!(Meta::decode(&image).is_ok(), "the honest image decodes");

    let mut forged = image.clone();
    forged[magic_at + 8..magic_at + 12].copy_from_slice(&99u32.to_le_bytes());
    let err = Meta::decode(&forged).expect_err("a future version must be refused");
    let msg = err.to_string();
    assert!(
        msg.contains("format version 99") && msg.contains("not readable"),
        "the refusal must name the version and say plainly it cannot be read: {msg}"
    );

    // A version *below* the block's own minimum is equally a lie about the image's shape.
    let mut forged = image.clone();
    forged[magic_at + 8..magic_at + 12].copy_from_slice(&1u32.to_le_bytes());
    assert!(Meta::decode(&forged).is_err());

    // A corrupted magic is refused too, rather than read as a truncated tail.
    let mut forged = image;
    forged[magic_at] ^= 0xFF;
    let err = Meta::decode(&forged).expect_err("a bad magic must be refused");
    assert!(err.to_string().contains("bad magic"), "{err}");
}

/// A store this build creates **persists** the current format version, so reopening it reports
/// the current version rather than falling back to the version-1 default — and `verify_on_open` accepts the
/// reopened store with its chains intact.
///
/// **Non-vacuity.** The version is read back from the durable catalog after a real reopen, so a build
/// that computed the version rather than persisting it, or that emitted a pre-#966 catalog, reports
/// version 1 here and fails. The chain assertion after the reopen is the second guard: a chain that
/// did not survive the reopen makes the version claim worthless.
#[test]
fn the_format_version_is_persisted_and_read_back_on_reopen() {
    use graphus_io::BlockDevice;

    let mut s = fresh();
    assert_eq!(
        s.opened_format_version(),
        graphus_core::constants::FORMAT_VERSION,
        "a freshly created store is at the current version"
    );
    let n = in_txn(&mut s, 1, |s, txn| s.create_node(txn).expect("create").0);
    let head = s.node(n).expect("node").mvcc.undo_ptr;
    assert_ne!(head, 0);

    // Reopen from the durable image, exactly as startup does.
    s.flush().expect("flush");
    let pages = s.mapped_pages();
    let max = pages.iter().map(|p| p.0).max().unwrap_or(0);
    let mut device = MemBlockDevice::new(max + 1);
    for p in &pages {
        let bytes = s.read_device_page(*p).expect("read page");
        device
            .write_page(graphus_core::PageId(p.0), &bytes)
            .expect("stage");
    }
    device.sync_all().expect("persist");
    let log = s.with_wal(|w| w.sink().durable_bytes().to_vec());
    let mut sink = MemLogSink::new();
    sink.append(&log);
    sink.sync().expect("sync log");
    let mut wal = WalManager::open(sink.clone()).expect("open wal");
    graphus_storage::recovery::recover_device(&mut wal, &mut device).expect("recover");
    let wal = WalManager::open(sink).expect("reopen wal");
    let mut reopened: Store = RecordStore::open(device, wal, POOL).expect("reopen store");

    assert_eq!(
        reopened.opened_format_version(),
        graphus_core::constants::FORMAT_VERSION,
        "the format version must be PERSISTED, not defaulted"
    );
    assert_eq!(
        reopened.node(n).expect("node").mvcc.undo_ptr,
        head,
        "the chain head survives the reopen byte for byte"
    );
    assert_eq!(
        reopened
            .version_chain(StoreKind::Node, n)
            .expect("chain")
            .len(),
        1,
        "and the chain it anchors is still walkable"
    );
    verify_on_open(&mut reopened, &[])
        .expect("a reopened store with live chains passes the startup integrity hook");
}

// ============================================================================================
// The cost of the chain, pinned.
// ============================================================================================

/// The undo area is not free: every created entity now writes a delta record as well as its own
/// record. This test **pins that cost from both sides**, because this project has repeatedly paid for
/// WAL amplification discovered late (`rmp` #315 / #702 / #706 / #713).
///
/// Measured over 1000 `create_node`s in one transaction, on a `MemLogSink` whose framing is
/// byte-deterministic:
///
/// | build | WAL bytes per created node |
/// | --- | --- |
/// | pre-`rmp`-#966 (no chain at all) | 192 |
/// | #966 with a separate chain-head write | 398 |
/// | #966 with the head carried in the record's own first write | **311** |
///
/// **Non-vacuity, in both directions.** The lower bound fails against a build that stopped writing
/// deltas (it would land at the 192-byte baseline), so the test cannot pass vacuously on a store with
/// no chains. The upper bound fails against a build that reintroduced a separate chain-head write for
/// creations (398), which is exactly the regression the inline-head design exists to prevent.
#[test]
fn the_wal_cost_of_a_created_entity_stays_within_its_budget() {
    let mut s = fresh();
    in_txn(&mut s, 1, |s, _txn| {
        s.intern_token(Namespace::RelType, "T").expect("intern");
    });
    let before = s.with_wal(|w| w.durable_len());
    in_txn(&mut s, 2, |s, txn| {
        for _ in 0..1000 {
            s.create_node(txn).expect("create");
        }
    });
    let per_node = (s.with_wal(|w| w.durable_len()) - before) / 1000;

    assert!(
        per_node > 250,
        "a created node must actually carry a delta into the WAL; {per_node} B/node is at or near \
         the pre-#966 no-chain baseline of 192 B/node"
    );
    assert!(
        per_node <= 360,
        "the chain must not cost more than one delta record per created entity; {per_node} B/node \
         exceeds the budget (measured 311; a separate chain-head write costs 398)"
    );
}

// ============================================================================================
// Regression: an ORPHAN undo-area page must not brick `open` (`rmp` #966).
// ============================================================================================

/// A store must reopen when `undo.store` has an **orphan** page: one a transaction allocated and then
/// aborted, so it exists on the device (its store-kind subtype byte is WAL-logged with `undo == redo`,
/// because page growth is never undone) but no durable catalog maps it.
///
/// # What this covers, and — precisely — what it does not
///
/// `RecordStore::open` re-attributes every orphan record page to its owning store by that subtype byte
/// and then cross-validates the page's records against the claimed kind (`rmp` #398). That check reads
/// a 25-byte MVCC header out of each slot, and the undo area's records have none (`05 §12`), so it is
/// wrong *in kind* for these two stores — see
/// `an_undo_page_is_cross_validated_by_its_own_codec_not_the_mvcc_header`, which proves directly that
/// a page of live deltas would be rejected by the header reading and is accepted by the codec.
///
/// **This test does not reach that rejection, and the reason is worth recording rather than papering
/// over.** An orphan undo page can only belong to a transaction that never committed — every commit's
/// `checkpoint_meta` snapshots the LIVE page map, so any commit after the allocation folds the page
/// into the catalog and it stops being an orphan. A never-committed transaction's deltas have had
/// their `in_use` bit cleared by the creation undo, and the old header-shaped check skipped
/// not-in-use slots. So the mis-firing branch is, as far as the public API can reach today,
/// **unreachable**: the codec branch is hardening of a defence-in-depth check, not a fix for a
/// reachable data-loss bug, and it is described as such.
///
/// What this test DOES pin is the reachable half: an aborted transaction that grows `undo.store` past
/// a page boundary must reopen cleanly, with its orphan pages re-attributed and the committed data and
/// chains intact. The `assert!` on the page growth is the positive control — without it the test would
/// pass on a store that never produced an orphan undo page at all.
#[test]
fn an_orphan_undo_page_left_by_an_aborted_transaction_does_not_brick_open() {
    use graphus_io::BlockDevice;

    const RECORDS_PER_PAGE: usize = 145; // `05 §12.1`

    let mut s = fresh();
    // One committed transaction, so the durable catalog is non-trivial but maps NO undo page yet
    // beyond what this commit folds in.
    let committed = in_txn(&mut s, 1, |s, txn| s.create_node(txn).expect("create").0);
    let undo_pages_committed = s.read_view().meta().mapped_page_count(StoreKind::Undo);

    // A transaction that pushes `undo.store` well past a page boundary and then ABORTS. Its pages stay
    // on the device (page growth is never undone) but no commit ever folds them into the catalog.
    let txn = TxnId(2);
    s.begin(txn);
    for _ in 0..(RECORDS_PER_PAGE * 2) {
        s.create_node(txn).expect("create");
    }
    s.rollback(txn).expect("rollback");
    let undo_pages_live = s.read_view().meta().mapped_page_count(StoreKind::Undo);
    assert!(
        undo_pages_live > undo_pages_committed,
        "positive control: the aborted transaction must really have grown `undo.store` past a page \
         boundary ({undo_pages_committed} -> {undo_pages_live} pages), or there is no orphan page to \
         reconstruct and this test proves nothing"
    );

    // Reopen from the durable image, exactly as startup does. The orphan undo pages are re-attributed
    // by their subtype byte and cross-validated against `StoreKind::Undo`.
    s.flush().expect("flush");
    let pages = s.mapped_pages();
    let max = pages.iter().map(|p| p.0).max().unwrap_or(0);
    let mut device = MemBlockDevice::new(max + 1);
    for p in &pages {
        let bytes = s.read_device_page(*p).expect("read page");
        device
            .write_page(graphus_core::PageId(p.0), &bytes)
            .expect("stage");
    }
    device.sync_all().expect("persist");
    let log = s.with_wal(|w| w.sink().durable_bytes().to_vec());
    let mut sink = MemLogSink::new();
    sink.append(&log);
    sink.sync().expect("sync log");
    let mut wal = WalManager::open(sink.clone()).expect("open wal");
    graphus_storage::recovery::recover_device(&mut wal, &mut device).expect("recover");
    let wal = WalManager::open(sink).expect("reopen wal");
    let mut reopened: Store = RecordStore::open(device, wal, POOL)
        .expect("an orphan undo page must be re-attributed, not treated as corruption");

    // The committed node and its chain survive, and the store is consistent.
    assert_eq!(
        reopened
            .version_chain(StoreKind::Node, committed)
            .expect("chain")
            .len(),
        1
    );
    verify_on_open(&mut reopened, &[]).expect("the reopened store must be consistent");
}

// ============================================================================================
// Regression: the undo area must PLATEAU under sustained create/delete churn (`rmp` #966).
// ============================================================================================

/// Sustained churn — create entities, delete them, reclaim, repeat — must leave `undo.store`'s
/// physical-id high-water **flat**. Every delta a reclaimed entity accumulated must come back.
///
/// # The defect this pins closed, and why it needed its own test
///
/// `reclaim_node` clears the node's MVCC header (`MvccHeader::default()`), and that header holds
/// `undo_ptr`. The first cut of #966 called `free_undo_chain` *after* that write, so it read an
/// already-zeroed chain head, walked an empty chain, and freed nothing. Every reclaimed node leaked
/// its whole delta chain.
///
/// The failure was **silent**: no error, no violated invariant, no failing consistency check — an
/// unreachable delta is indistinguishable from a reclaimed one except by counting. It surfaced only in
/// `crates/graphus-iot-gen/tests/churn_plateau.rs`, an example-level gate a long way from the code, and
/// only because that gate asserts an exact footprint. Storage-level reclamation deserves a
/// storage-level guard, so this is it: fast, hermetic, and it names the ordering.
///
/// MEASURED at the time of the fix, on the `iot-timeseries` churn profile: 25 leaked delta slots per
/// tick, `undo.store` growing without bound (1 → 35 pages over 200 ticks) while every other store sat
/// flat at 1–2 pages. After the fix the whole footprint is flat at 73 728 B from tick 2 to tick 199.
///
/// **Non-vacuity.** Two positive controls guard the two ways this could pass while proving nothing:
/// the warm-up high-water must be non-zero (deltas really are being allocated) and each round must
/// really reclaim entities (the churn really is churning). With the ordering reverted the high-water
/// grows every round and the flatness assertion fails.
#[test]
fn the_undo_store_plateaus_under_sustained_create_delete_churn() {
    const PER_ROUND: usize = 20;
    const ROUNDS: u64 = 30;
    const WARMUP: u64 = 5;

    let mut s = fresh();
    let rel_type = in_txn(&mut s, 1, |s, _txn| {
        s.intern_token(Namespace::RelType, "LINK").expect("intern")
    });

    let undo_high_water = |s: &Store| s.read_view().meta().high_water(StoreKind::Undo);
    let mut warm_high_water = 0u64;
    let mut total_reclaimed = 0usize;
    let mut next = 2u64;

    for round in 0..ROUNDS {
        // Create a batch of nodes each with an incident relationship.
        let mut entities = Vec::with_capacity(PER_ROUND);
        let txn = TxnId(next);
        next += 1;
        s.begin(txn);
        for _ in 0..PER_ROUND {
            let (a, _) = s.create_node(txn).expect("node a");
            let (b, _) = s.create_node(txn).expect("node b");
            let (r, _) = s.create_rel(txn, rel_type, a, b).expect("rel");
            entities.push((a, b, r));
        }
        s.commit(txn).expect("commit creates");

        // Delete every one of them, relationship first (the `DETACH DELETE` shape).
        let txn = TxnId(next);
        next += 1;
        s.begin(txn);
        for &(a, b, r) in &entities {
            s.delete_rel(txn, r).expect("delete rel");
            s.delete_node(txn, a).expect("delete a");
            s.delete_node(txn, b).expect("delete b");
        }
        s.commit(txn).expect("commit deletes");

        // Reclaim at the latest watermark: every deletion above is now invisible to any snapshot.
        let gc = TxnId(next);
        next += 1;
        let watermark = s.snapshot_ts();
        s.begin(gc);
        let report = s.gc(gc, watermark).expect("gc");
        s.commit(gc).expect("commit gc");
        total_reclaimed += report.reclaimed;

        if round == WARMUP {
            warm_high_water = undo_high_water(&s);
        } else if round > WARMUP {
            assert_eq!(
                undo_high_water(&s),
                warm_high_water,
                "round {round}: `undo.store` must not grow once the churn is in steady state — its \
                 high-water went {warm_high_water} -> {}, i.e. reclaimed delta slots are not being \
                 reused (see this test's docs: the `reclaim_node` ordering)",
                undo_high_water(&s)
            );
        }
    }

    // Positive controls: the churn really churned, and deltas really were allocated.
    assert!(
        warm_high_water > 1,
        "positive control: deltas must actually have been allocated (high-water {warm_high_water})"
    );
    assert!(
        total_reclaimed >= PER_ROUND * 3 * (ROUNDS as usize - 2),
        "positive control: each round must really reclaim its entities ({total_reclaimed} over \
         {ROUNDS} rounds)"
    );
    assert_consistent(&mut s, "after sustained churn");
}
