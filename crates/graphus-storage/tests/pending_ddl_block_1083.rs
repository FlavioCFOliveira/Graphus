//! **The pending-DDL catalogue block** (`rmp` #1083): its wire format, its version gate, and the
//! reclaim floor that keeps the transaction it names decidable.
//!
//! The behavioural half of #1083 — the phantom index/constraint itself, both crash endings and the
//! committed control — lives in `graphus-dst`'s `pending_ddl_phantom`, which drives it deterministically
//! through crash and recovery. This suite pins the parts that sit below that: what the block IS on
//! disk, what happens to a store written before it existed, and the one obligation attributing state
//! to a transaction creates — that the log must still be able to say what that transaction did.

use graphus_core::{PageId, TxnId};
use graphus_io::{BlockDevice, MemBlockDevice};
use graphus_storage::{
    ConstraintEntry, ConstraintKind, Meta, Namespace, PendingSchema, RecordStore, Statistics,
};
use graphus_wal::{MemLogSink, WalManager};

type Store = RecordStore<MemBlockDevice, MemLogSink>;

/// The magic word introducing the trailing pending-DDL block.
const PENDING_DDL_MAGIC: &[u8] = b"GRPHPDDL";
/// The magic word introducing the trailing applied-transaction-set block, which precedes it.
const APPLIED_COUNTS_MAGIC: &[u8] = b"GRPHCNTD";
/// The magic word introducing the trailing undo-area block, which precedes both.
const UNDO_AREA_MAGIC: &[u8] = b"GRPHUNDO";

/// A fresh store over an empty in-memory device + log.
fn fresh(capacity: usize) -> Store {
    let device = MemBlockDevice::new(0);
    let wal = WalManager::create(MemLogSink::new()).expect("create wal");
    RecordStore::create(device, wal, capacity, 1).expect("create store")
}

/// The offset of `magic` inside `bytes`.
fn magic_at(bytes: &[u8], magic: &[u8]) -> usize {
    bytes
        .windows(magic.len())
        .position(|w| w == magic)
        .unwrap_or_else(|| {
            panic!(
                "a current-version catalog must carry the {} magic",
                String::from_utf8_lossy(magic)
            )
        })
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

// -------------------------------------------------------------------------------------------------
// The wire format
// -------------------------------------------------------------------------------------------------

/// The block round-trips, both present and absent, and the presence byte is what distinguishes them.
#[test]
fn the_pending_ddl_block_round_trips() {
    let mut schema = Statistics::new();
    schema.constraints.insert("u".to_owned(), unique(7, 9));

    let mut with = Meta::new(1);
    with.pending_ddl = Some(PendingSchema {
        txn: 4242,
        schema: schema.clone(),
    });
    let decoded = Meta::decode(&with.encode().expect("encode")).expect("decode");
    assert_eq!(decoded, with, "the block did not survive a round trip");

    let without = Meta::new(1);
    let decoded = Meta::decode(&without.encode().expect("encode")).expect("decode");
    assert_eq!(decoded.pending_ddl, None);

    // NON-VACUITY: the two images really differ, so the round trip above is not comparing an image
    // with itself.
    assert_ne!(
        with.encode().expect("encode"),
        without.encode().expect("encode"),
        "a pending block changed no bytes, so nothing was persisted"
    );
}

/// The block is the LAST trailing block, after the applied-transaction set. The order matters to
/// every fixture that forges an older image by truncating at a magic word: cutting at `GRPHCNTD`
/// removes this block with it, which is what keeps `property_undo_chain_967`'s version-2 arm a
/// faithful forgery without needing to know this block exists.
#[test]
fn the_block_is_appended_after_every_earlier_one() {
    let bytes = Meta::new(1).encode().expect("encode");
    let undo = magic_at(&bytes, UNDO_AREA_MAGIC);
    let counts = magic_at(&bytes, APPLIED_COUNTS_MAGIC);
    let pending = magic_at(&bytes, PENDING_DDL_MAGIC);
    assert!(
        undo < counts && counts < pending,
        "block order on the wire is undo({undo}) < applied({counts}) < pending({pending})"
    );
}

/// **A version-4 image that still carries the pending-DDL block is refused.** It came from no
/// writer: no build below version 5 ever emitted one. Reading it would take a catalogue whose
/// committed half was written under a *different rule* — version 5 keeps only committed schema
/// there — while discarding the DDL that rule moved into the block.
///
/// This is the obligation every downgrade fixture inherits: forging an older image by rewriting the
/// version word must also CUT the blocks that version does not define.
#[test]
fn a_downgraded_image_still_carrying_the_pending_block_is_refused() {
    let mut current = Meta::new(1);
    current.statistics.total_nodes = 42;
    let bytes = current.encode().expect("encode");
    let version_at = magic_at(&bytes, UNDO_AREA_MAGIC) + 8;
    let pending_at = magic_at(&bytes, PENDING_DDL_MAGIC);

    // The incomplete forgery: version word rewritten, block left in place.
    let mut half_forged = bytes.clone();
    half_forged[version_at..version_at + 4].copy_from_slice(&4u32.to_le_bytes());
    let err = Meta::decode(&half_forged)
        .expect_err("a version-4 image still carrying the pending-DDL block must be refused");
    assert!(
        format!("{err}").contains("self-contradictory"),
        "the refusal must say WHY it is not simply an old image: {err}"
    );

    // The complete forgery — version word rewritten AND the block cut — opens, with no pending DDL.
    // Without this the assertion above would be satisfied by a decoder that refused every downgrade.
    let mut forged = bytes[..pending_at].to_vec();
    forged[version_at..version_at + 4].copy_from_slice(&4u32.to_le_bytes());
    let decoded = Meta::decode(&forged).expect("a faithful version-4 forgery must open");
    assert_eq!(decoded.format_version, 4);
    assert_eq!(decoded.statistics.total_nodes, 42, "the counters survive");
    assert_eq!(decoded.pending_ddl, None);
}

/// **A version-5 image missing its pending-DDL block is corruption, not an older image.** Its
/// committed half was written by a build that moved the committing transaction's DDL out, so
/// accepting it silently would discard whatever that transaction declared.
#[test]
fn a_version_5_image_without_its_block_is_refused() {
    let bytes = Meta::new(1).encode().expect("encode");
    assert_eq!(
        Meta::new(1).format_version,
        graphus_core::constants::FORMAT_VERSION,
        "the fixture must be an image at this build's version"
    );
    assert!(
        Meta::decode(&bytes).is_ok(),
        "NON-VACUITY: the intact image must decode, or the truncation below proves nothing"
    );
    let pending_at = magic_at(&bytes, PENDING_DDL_MAGIC);
    for drop in 1..=(bytes.len() - pending_at) {
        assert!(
            Meta::decode(&bytes[..bytes.len() - drop]).is_err(),
            "a version-{} image truncated by {drop} byte(s) decoded as if whole",
            graphus_core::constants::FORMAT_VERSION
        );
    }
}

/// A presence byte that is neither 0 nor 1 is named rather than guessed at.
#[test]
fn an_unknown_presence_byte_is_refused() {
    let mut bytes = Meta::new(1).encode().expect("encode");
    let at = magic_at(&bytes, PENDING_DDL_MAGIC) + 8;
    bytes[at] = 7;
    let err = Meta::decode(&bytes).expect_err("an unknown presence byte must be refused");
    assert!(
        format!("{err}").contains("presence byte 7"),
        "the refusal must name the byte: {err}"
    );
}

// -------------------------------------------------------------------------------------------------
// The reclaim floor
// -------------------------------------------------------------------------------------------------

/// **No WAL prefix is reclaimed while a pending-DDL block is still the durable image.**
///
/// The block names a transaction and `open` applies it only if it finds that transaction's `COMMIT`
/// record in the RETAINED log — so reclaiming that record while the block is still the durable image
/// would invert the decision, and a **committed** `CREATE CONSTRAINT` would be read as a phantom and
/// dropped. `RecordStore::checkpoint` therefore settles the pending image before it reclaims anything
/// (inside `fold_counts_for_reclaim`): the `SYSTEM_TXN` image it writes carries no block and carries every
/// committed DDL as ordinary committed state, so the old block can no longer decide anything.
///
/// # What this pins, and what it does NOT — stated rather than glossed
///
/// It pins the settle: after `checkpoint()` the durable image is block-free and still holds the
/// declaration. It does **not** demonstrate that the loss is reachable without the settle, and the
/// difference was measured rather than assumed. Three independent properties currently keep the
/// deciding `COMMIT` record alive on their own: `unfrozen_commit_lsn` floors the reclaim at that
/// record and is cleared only by a GC prune (which a DDL-only transaction never gets, since it has no
/// versions to freeze); every later write commit rewrites the catalogue, so the block stops being
/// durable; and a GC pass itself commits, which rewrites it too. So the settle is defence in depth —
/// but each of those three is an accident of other machinery rather than a stated invariant, and
/// `rmp` #1083's whole subject is durable state whose fate rides on a decision made elsewhere.
///
/// The workload is deliberately DDL-ONLY: with no cardinality change there is nothing owed, so
/// `fold_counts_for_reclaim` writes no image of its own and the block below can be cleared by
/// the pending-DDL settle and by nothing else. An earlier draft of this test created a node,
/// which made the counter fold write the block-free image — and the assertions passed with the
/// settle REMOVED. That is the shape of a vacuous control, and it is recorded here because the fix
/// for it was to change the workload, not the assertion.
#[test]
fn no_prefix_is_reclaimed_while_a_pending_block_is_durable() {
    let store = fresh(64);
    let t0 = TxnId(1);
    store.begin(t0);
    let label = store
        .intern_token(Namespace::Label, "Person")
        .expect("intern");
    let key = store
        .intern_token(Namespace::PropKey, "email")
        .expect("intern");
    store.commit(t0).expect("seed commits");

    // A DDL-bearing commit: its declaration reaches disk in the pending-DDL block, attributed to it.
    let ddl = TxnId(2);
    store.begin(ddl);
    store.set_constraint(ddl, "u".to_owned(), unique(label, key));
    store.commit(ddl).expect("the declaration commits");
    store.with_wal(WalManager::flush);

    // NON-VACUITY: the durable image really is the one carrying the block, so the reclaim below is
    // running against the state this test is about.
    assert_eq!(
        durable_catalogue(&store).pending_ddl.map(|p| p.txn),
        Some(ddl.0),
        "the image does not attribute pending DDL to the declaring transaction, so the floor has \
         nothing to protect and this test proves nothing"
    );

    // The real reclaim path.
    store.checkpoint().expect("checkpoint + reclaim");

    // After the settle the image carries no block, and the declaration is committed state in it.
    let image = durable_catalogue(&store);
    assert_eq!(
        image.pending_ddl.map(|p| p.txn),
        None,
        "the reclaim ran with a pending block still on the durable image"
    );
    assert!(
        image.statistics.constraint("u").is_some(),
        "the settled image lost the committed declaration"
    );

    // And a reopen over the reclaimed log still reports it.
    let reopened = reopen(store);
    assert!(
        reopened.constraint("u").is_some(),
        "a COMMITTED constraint vanished across a reopen after a WAL reclaim (`rmp` #1083)"
    );
}

/// Clean reopen: flush, stage every mapped page onto a fresh device, reopen over the same WAL sink.
/// What is asserted after this is what is **durable**, not what is merely in memory.
fn reopen(s: Store) -> Store {
    s.flush().expect("flush");
    let pages = s.mapped_pages();
    let max = pages.iter().map(|p| p.0).max().unwrap_or(0);
    let mut device = MemBlockDevice::new(max + 1);
    let staged: Vec<(u64, Box<graphus_io::Page>)> = pages
        .iter()
        .map(|p| (p.0, s.read_device_page(*p).expect("read device page")))
        .collect();
    for (idx, bytes) in staged {
        device.write_page(PageId(idx), &bytes).expect("stage page");
    }
    device.sync_all().expect("persist disk image");
    let wal = WalManager::open(s.with_wal(|w| w.sink().clone())).expect("reopen wal");
    RecordStore::open(device, wal, 64).expect("reopen store")
}

/// Decodes the catalogue image the metadata page is holding. See the twin in `graphus-dst`'s
/// `pending_ddl_phantom` for why the framing is masked and why `next == 0` is asserted.
fn durable_catalogue(store: &Store) -> Meta {
    let bytes = store
        .read_device_page(PageId(0))
        .expect("read the metadata page");
    let at = graphus_bufpool::page::HEADER_SIZE;
    let framed = u32::from_le_bytes(bytes[at..at + 4].try_into().expect("4 bytes"));
    let len = (framed & 0x7fff_ffff) as usize;
    let next = u64::from_le_bytes(bytes[at + 4..at + 12].try_into().expect("8 bytes"));
    assert_eq!(
        next, 0,
        "this fixture's catalogue must fit in the head page"
    );
    Meta::decode(&bytes[at + 12..at + 12 + len]).expect("decode the catalogue")
}
