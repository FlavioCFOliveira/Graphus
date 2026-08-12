//! **`rmp` #1066 — a WAL record for cardinality deltas, and an idempotent replay.**
//!
//! # What this file certifies
//!
//! The counters in [`Statistics`](graphus_storage::Statistics) answer `count()` since `rmp` #866,
//! and nothing recomputes them from a scan at `open`. They reach disk today only inside the whole
//! catalogue image a commit rewrites, which cannot be made exact under concurrent committers
//! (`rmp` #1055). The route out — measured against Neo4j, the only surveyed engine that keeps this
//! number exact — is to log the change as a **delta** and fold it in at recovery.
//!
//! This is the first layer: the record format and the recovery. **Nothing in the write path emits a
//! delta yet** — `checkpoint_meta` still persists the counters in the image, and making a commit log
//! its delta (and taking the counters out of the image) is `rmp` #1067. So the records this suite
//! replays are appended to the log **by the test**, through the same public seam `rmp` #1067 will
//! use ([`WalManager::log_count_delta`]). That is deliberate: a recovery path first exercised by the
//! change that starts depending on it is a recovery path nobody has tested.
//!
//! # The oracle
//!
//! Every assertion is about the counters a **reopened** store reads out of its durable catalogue,
//! against a ground truth the test computes independently. Not the live ones: the whole class of
//! defect here lives in what survives a restart.
//!
//! # Non-vacuity
//!
//! Asserted, never assumed, on every test that could be hollow:
//!
//! * the counters really move (a replay that folded nothing would satisfy "no double count"
//!   trivially) — [`a_committed_count_delta_is_folded_in_at_open`];
//! * the delta record is still in the **retained** log at the second open — `RecordStore::checkpoint`
//!   reclaims the WAL prefix, so a record that had been reclaimed away would make the idempotence
//!   assertion prove nothing, and it is checked rather than hoped for
//!   ([`replaying_the_same_log_twice_folds_the_delta_once`]);
//! * the two log orders really differ ([`the_order_of_the_records_in_the_log_does_not_matter`]).

use graphus_core::{PageId, Timestamp, TxnId};
use graphus_io::{BlockDevice, MemBlockDevice, Page};
use graphus_storage::recovery::recover_device;
use graphus_storage::{CountDelta, CountKey, Meta, Namespace, RecordStore};
use graphus_wal::{LogSink, MemLogSink, WalManager};

type Store = RecordStore<MemBlockDevice, MemLogSink>;

const POOL_PAGES: usize = 256;

/// Committed nodes the fixture starts from, all carrying [`LABEL`]. Large enough that a counter that
/// came back clamped at the saturating rail is plainly a different number.
const BASE_NODES: u64 = 12;

const LABEL: &str = "Widget";

/// Transaction ids for the synthetic delta records. Far above anything the fixture's own writes use,
/// so no synthetic id can collide with a real transaction and the two are never confused.
const SYNTH: [u64; 3] = [900_001, 900_002, 900_003];

fn fresh() -> Store {
    let device = MemBlockDevice::new(0);
    let wal = WalManager::create(MemLogSink::new()).expect("create wal");
    RecordStore::create(device, wal, POOL_PAGES, 1).expect("create store")
}

/// Reopens `store` through its own durable device image and WAL — the same steal-crash recovery
/// shape the rest of this crate's suites use (`catalog_counts_multi_writer_1052`).
fn reopen(store: &mut Store) -> Store {
    store.flush().expect("flush the dirty pages home");
    let pages = store.mapped_pages();
    let max = pages.iter().map(|p| p.0).max().unwrap_or(0);
    let mut device = MemBlockDevice::new(max + 1);
    let staged: Vec<(u64, Box<Page>)> = pages
        .iter()
        .map(|p| (p.0, store.read_device_page(*p).expect("read device page")))
        .collect();
    for (idx, bytes) in staged {
        device
            .write_page(PageId(idx), &bytes)
            .expect("stage the page");
    }
    device.sync_all().expect("persist the disk image");

    let mut sink = MemLogSink::new();
    sink.append(&store.with_wal(|w| w.sink().durable_bytes().to_vec()));
    sink.sync().expect("sync the durable log prefix");
    let mut wal = WalManager::open(sink.clone()).expect("open wal");
    recover_device(&mut wal, &mut device).expect("ARIES recovery");
    let wal = WalManager::open(sink).expect("reopen wal");
    RecordStore::open(device, wal, POOL_PAGES).expect("open the recovered store")
}

/// How many count-delta records the store's **retained** log still holds. The non-vacuity witness
/// for any assertion of the form "replaying this log again changes nothing".
fn retained_count_delta_records(store: &Store, txn: TxnId) -> usize {
    store
        .with_wal(|w| w.recovered_transactions())
        .expect("scan the retained log")
        .count_deltas
        .iter()
        .filter(|rec| rec.txn_id == txn)
        .count()
}

/// A store with [`BASE_NODES`] committed nodes carrying [`LABEL`], its catalogue already durable
/// (the commit runs `checkpoint_meta`). Returns the store and the label's token id.
fn fixture() -> (Store, u32) {
    let store = fresh();
    let label = store
        .intern_token(Namespace::Label, LABEL)
        .expect("intern the label");
    let seed = TxnId(1);
    store.begin(seed);
    for _ in 0..BASE_NODES {
        let (node, _) = store.create_node(seed).expect("create a base node");
        store.add_label(seed, node, label).expect("label it");
    }
    store.commit(seed).expect("commit the base");
    (store, label)
}

/// A delta claiming `nodes` new nodes, all carrying `label`.
fn node_delta(label: u32, nodes: i64) -> CountDelta {
    let mut d = CountDelta::default();
    d.record(CountKey::TotalNodes, nodes);
    d.record(CountKey::Label(label), nodes);
    d
}

/// Appends `delta` for transaction `txn`, followed by a `COMMIT` record — the exact shape and order
/// `rmp` #1067's commit path will produce (the delta before the commit, so a transaction never
/// becomes durably committed with its counter change absent from the log).
fn log_committed_delta(store: &Store, txn: u64, delta: &CountDelta) {
    let txn = TxnId(txn);
    let payload = delta.encode();
    store.with_wal(|w| {
        w.begin(txn);
        w.log_count_delta(txn, &payload);
        w.commit_at(txn, Timestamp(1)).expect("commit the delta");
    });
}

/// Appends `delta` for `txn` and then **nothing** — the shape a crash leaves behind when a
/// transaction logged its delta and never reached its commit.
fn log_uncommitted_delta(store: &Store, txn: u64, delta: &CountDelta) {
    let txn = TxnId(txn);
    let payload = delta.encode();
    store.with_wal(|w| {
        w.begin(txn);
        w.log_count_delta(txn, &payload);
        w.flush();
    });
}

/// `(total_nodes, nodes carrying `label`)` as the store's catalogue holds them.
fn counters(store: &Store, label: u32) -> (u64, u64) {
    let s = store.statistics();
    (s.total_nodes(), s.node_count_for_label(label))
}

// =================================================================================================
// The replay itself.
// =================================================================================================

/// **A committed count-delta record in the log is folded into the catalogue at `open`.**
///
/// The base counters are durable before the record is appended, and nothing else in the run touches
/// them, so the difference a reopen reads back is exactly this record's delta and nothing else.
#[test]
fn a_committed_count_delta_is_folded_in_at_open() {
    let (mut store, label) = fixture();
    assert_eq!(counters(&store, label), (BASE_NODES, BASE_NODES));

    log_committed_delta(&store, SYNTH[0], &node_delta(label, 5));
    assert_eq!(
        counters(&store, label),
        (BASE_NODES, BASE_NODES),
        "logging a delta must not move the LIVE counters — the record is a durability instrument, \
         and the live value already accounts for whatever the writer did"
    );

    let reopened = reopen(&mut store);
    assert_eq!(
        counters(&reopened, label),
        (BASE_NODES + 5, BASE_NODES + 5),
        "NON-VACUITY and the property in one: the reopened catalogue must be the durable image PLUS \
         the logged delta. Equal to the base would mean the replay folded nothing, and every \
         idempotence assertion in this file would then be about a mechanism that never runs"
    );
}

/// **A delta whose transaction never committed is never folded in.**
///
/// Its rows are not in the store — recovery's undo pass rolled them back — so folding its counter
/// change in would report a cardinality for records that do not exist. Nothing else removes it
/// either: undo writes CLRs for *page* changes, and a count delta is not one, so the committed-set
/// filter is the only thing standing between a loser's delta and the durable catalogue.
#[test]
fn an_uncommitted_count_delta_is_never_folded_in() {
    let (mut store, label) = fixture();
    log_uncommitted_delta(&store, SYNTH[0], &node_delta(label, 7));

    let mut reopened = reopen(&mut store);
    assert_eq!(
        counters(&reopened, label),
        (BASE_NODES, BASE_NODES),
        "a loser's delta reached the durable catalogue: its transaction never committed, so its \
         rows were undone and the counters must not know about them"
    );

    // And it stays out on every later recovery, not just the first: the transaction is not in the
    // applied set (nothing was applied for it), so nothing has been silently decided about it.
    let again = reopen(&mut reopened);
    assert_eq!(counters(&again, label), (BASE_NODES, BASE_NODES));
}

/// **Replaying the same log twice folds the delta once** (`rmp` #1066, acceptance criterion 3),
/// end to end through two real recoveries.
///
/// The chain is the one a restart-after-a-restart actually takes:
///
/// 1. the base image, with a committed delta record in the log — a reopen folds it in;
/// 2. that store commits, which runs `checkpoint_meta` and persists the counters **and** the applied
///    set together;
/// 3. a reopen of *that* image, whose log **still holds the same delta record**, must read back the
///    same number.
///
/// Step 3 is only a test of anything if the record survived into the second image's log, and
/// `RecordStore::checkpoint` reclaims the WAL prefix — so that is asserted rather than assumed. If
/// the applied set were not persisted in step 2, this run would come back with the delta counted
/// twice.
#[test]
fn replaying_the_same_log_twice_folds_the_delta_once() {
    let (mut store, label) = fixture();
    log_committed_delta(&store, SYNTH[0], &node_delta(label, 5));

    let mut once = reopen(&mut store);
    assert_eq!(counters(&once, label), (BASE_NODES + 5, BASE_NODES + 5));

    // A commit, which is the only thing that writes the catalogue. It also adds exactly one node,
    // which the ground truth below accounts for — using a plain commit rather than a
    // `RecordStore::checkpoint` is deliberate: a checkpoint would RECLAIM the delta record out of
    // the log and leave nothing for step 3 to double-count.
    let t = TxnId(2);
    once.begin(t);
    let (node, _) = once.create_node(t).expect("create a node");
    once.add_label(t, node, label).expect("label it");
    once.commit(t).expect("commit");

    assert_eq!(
        retained_count_delta_records(&once, TxnId(SYNTH[0])),
        1,
        "NON-VACUITY: the delta record is no longer in the retained log, so the reopen below has \
         nothing it could double-count and the assertion that follows would pass on an empty log. \
         Counted for THIS transaction rather than over the whole log (`rmp` #1067): since a commit \
         logs its own delta, the log also holds the fixture's and this step's, and a total would go \
         green on those alone"
    );

    let twice = reopen(&mut once);
    assert_eq!(
        counters(&twice, label),
        (BASE_NODES + 6, BASE_NODES + 6),
        "the delta was folded in a second time. The applied-transaction set the checkpoint persists \
         is what makes a replay idempotent; without it every restart adds the same rows again, and \
         `rmp` #866 answers count() from the result with nothing to recompute it"
    );
}

/// **The order the records sit in the log does not change the recovered catalogue**
/// (`rmp` #1066, acceptance criterion 2), end to end.
///
/// Log order is not apply order — that is the premise the whole record rests on — so a recovery that
/// depended on it would give different durable answers for logs that describe the same work.
///
/// # Why the deltas name a label the durable image has NO rows for
///
/// Because otherwise this test proves nothing, which was **measured** rather than reasoned about: a
/// first draft aimed the same batch at [`LABEL`], whose durable count is [`BASE_NODES`], and it
/// passed with the fold deliberately replaced by a one-delta-at-a-time loop. A base of twelve
/// absorbs a `−4` without ever reaching zero, so no order of that batch can hit the saturating rail
/// and every order agrees for the wrong reason.
///
/// Against a label at **zero**, applying the removal first drives the counter below zero, which
/// `Statistics` cannot represent — `add_keyed` catches it in a debug build and clamps in silence in
/// a release one — and the two orders then disagree. That is the state this asserts is unreachable.
#[test]
fn the_order_of_the_records_in_the_log_does_not_matter() {
    /// `(transaction slot, node delta)`; the third undoes the first, so applying the third before
    /// the first drives a counter that starts at zero below zero.
    const BATCH: [(usize, i64); 3] = [(0, 4), (1, 3), (2, -4)];

    let run = |order: [usize; 3]| -> (u64, u64) {
        let (mut store, _) = fixture();
        // A label the durable image holds NO rows for: interned (so the token exists) and never put
        // on a node, so its counter is absent — which is the same thing as zero.
        let empty = store
            .intern_token(Namespace::Label, "Gadget")
            .expect("intern the empty label");
        let t = TxnId(3);
        store.begin(t);
        store.commit(t).expect("make the token durable");
        assert_eq!(
            counters(&store, empty).1,
            0,
            "the label the batch aims at must start at zero, or the removal cannot reach the rail"
        );

        for i in order {
            let (slot, nodes) = BATCH[i];
            log_committed_delta(&store, SYNTH[slot], &node_delta(empty, nodes));
        }
        let reopened = reopen(&mut store);
        counters(&reopened, empty)
    };

    let forward = run([0, 1, 2]);
    let reversed = run([2, 1, 0]);
    let interleaved = run([2, 0, 1]);

    // +4 +3 −4 = +3 on both counters, independently of anything.
    let want = (BASE_NODES + 3, 3);
    assert_eq!(
        (forward, reversed, interleaved),
        (want, want, want),
        "two logs describing the same committed work recovered to different catalogues, so the \
         durable answer depends on the order the records happen to sit in — which is exactly what \
         `rmp` #1062 measured is NOT the order they are applied in once several workers are running"
    );

    // NON-VACUITY: the three orders really are different, and the batch really does contain a
    // removal that, applied before the addition that pays for it, takes a zero-based counter
    // negative. Walked on an exact shadow so this holds in every build profile.
    assert_ne!([0, 1, 2], [2, 1, 0]);
    let mut shadow = 0i64;
    let mut went_negative = false;
    for i in [2usize, 0, 1] {
        shadow += BATCH[i].1;
        went_negative |= shadow < 0;
    }
    assert!(
        went_negative && shadow == 3,
        "the batch never drives the counter negative in the reversed order, so no order of it can \
         reach the saturating rail and the equality above is satisfied for the wrong reason"
    );
}

// =================================================================================================
// The on-disk format version.
// =================================================================================================

/// **A catalogue written before version 4 upgrades, with an empty applied set**
/// (`rmp` #1066, acceptance criterion 5 — the "migrated" branch, and the decision it rests on).
///
/// The decision is recorded on `graphus_storage::meta::COUNT_DELTA_FORMAT_VERSION` and on
/// `graphus_core::constants::FORMAT_VERSION`: the upgrade is lossless because no build below version
/// 4 ever wrote a count-delta record, so an empty set is not an approximation of that store's
/// history — it *is* that store's history, and there is nothing an empty set could cause to be
/// applied twice.
#[test]
fn a_catalogue_written_before_version_4_upgrades_with_an_empty_applied_set() {
    let mut older = Meta::new(1);
    older.format_version = 3;
    older.statistics.total_nodes = 17;
    let bytes = older.encode().expect("encode a version-3 image");

    let decoded = Meta::decode(&bytes).expect("a version-3 image must open");
    assert_eq!(decoded.format_version, 3);
    assert_eq!(decoded.statistics.total_nodes, 17, "the counters survive");
    assert!(
        decoded.applied_counts.is_empty(),
        "a pre-version-4 image must decode to an EMPTY applied set: it names the transactions \
         already folded into the counters beside it, and such a store has folded none"
    );

    // The upgrade is what a checkpoint completes: re-stamped at this build's version, the image
    // carries the block, and round-trips through it.
    let mut upgraded = decoded;
    upgraded.format_version = graphus_core::constants::FORMAT_VERSION;
    let bytes = upgraded.encode().expect("encode the upgraded image");
    assert_eq!(
        Meta::decode(&bytes).expect("the upgraded image must open"),
        upgraded
    );
    assert_ne!(
        graphus_core::constants::FORMAT_VERSION,
        3,
        "NON-VACUITY: this build still writes version 3, so the whole test compares an image with \
         itself and proves nothing about an upgrade"
    );
}

/// **An image whose version this build cannot read is refused, with a diagnostic**
/// (`rmp` #1066, acceptance criterion 5 — the "refused" branch).
///
/// This is the direction the version bump exists for. An older build handed a version-4 image would
/// not merely miss the applied-set block: it would rewrite the catalogue **without** it, discarding
/// the record of what had already been applied, and the next version-4 build to open that store
/// would fold every retained delta in again. The refusal is `Meta::decode`'s
/// `version > FORMAT_VERSION` arm, and it is exercised here in the only way one build can — by
/// forging the version one past what this build writes, which is the same comparison an older build
/// makes against a version-4 image.
#[test]
fn an_image_from_a_newer_build_is_refused_with_a_diagnostic() {
    let mut newer = Meta::new(1);
    newer.format_version = graphus_core::constants::FORMAT_VERSION + 1;
    let bytes = newer.encode().expect("encode");
    let err = Meta::decode(&bytes).expect_err("a newer image must be refused");
    let msg = format!("{err}");
    assert!(
        msg.contains("not readable by this build"),
        "the refusal must name the cause: {msg}"
    );
    assert!(
        msg.contains(&format!("{}", graphus_core::constants::FORMAT_VERSION)),
        "the refusal must name the version this build supports, which is the operator's route \
         out: {msg}"
    );
}

/// **An image that declares a version below 4 while still carrying the block is refused.**
///
/// The mirror of [`a_version_4_image_without_its_block_is_refused`], and the second half of one rule:
/// the counters and the applied set are one fact, so neither may appear without the other. A version
/// below 4 that still carries a `GRPHCNTD` block came from no writer — no such build ever emitted
/// one — so it is self-contradictory rather than merely old, and opening it would take the counters
/// of a version-4 store while discarding the record of what has already been folded into them.
///
/// # What this rule obliges, and where that obligation is already met
///
/// Fail-closed here means anything that *forges* an older image by rewriting the version word must
/// also cut the blocks that version does not define. `rmp` #967's legacy fixture
/// (`property_undo_chain_967`'s `downgrade_catalog_to`) is the one place in the tree that does this,
/// and its version-2 arm truncates at this block's magic for exactly this reason; its version-1 arm
/// truncates at the undo-area magic, which removes both blocks at once. Without that cut, a store
/// engineered to be refused by `refuse_legacy_property_tombstones` — with a message naming the
/// offending record and the migration route — is instead refused here, by a message about a layout
/// it cannot act on. That is the failure mode this test exists to keep visible.
#[test]
fn a_downgraded_image_still_carrying_a_newer_block_is_refused() {
    let mut current = Meta::new(1);
    current.statistics.total_nodes = 42;
    let bytes = current.encode().expect("encode a current-version image");

    // Write an older version into the undo-area block's version word WITHOUT cutting the trailing
    // applied-set block — the incomplete forgery the rule above is about.
    let undo_magic = u64::from_le_bytes(*b"GRPHUNDO");
    let counts_magic = u64::from_le_bytes(*b"GRPHCNTD");
    let undo_at = bytes
        .windows(8)
        .position(|w| w == undo_magic.to_le_bytes())
        .expect("a current image carries the undo-area magic");
    let counts_at = bytes
        .windows(8)
        .position(|w| w == counts_magic.to_le_bytes())
        .expect("a current image carries the applied-counts magic");
    let version_at = undo_at + 8;

    for older in [2u32, 3] {
        let mut half_forged = bytes.clone();
        half_forged[version_at..version_at + 4].copy_from_slice(&older.to_le_bytes());
        let err = match Meta::decode(&half_forged) {
            Ok(_) => panic!(
                "a version-{older} image still carrying the applied-set block must be refused: it \
                 is not an older image, it is one no build could have written"
            ),
            Err(e) => e,
        };
        let msg = format!("{err}");
        assert!(
            msg.contains("self-contradictory"),
            "the refusal must say WHY it is not simply an old image: {msg}"
        );

        // And the complete forgery — version word rewritten AND the block cut, which is what the
        // #967 fixture does — opens, with an empty applied set. Without this the assertion above
        // would be satisfied by a decoder that refused every downgraded image.
        let mut forged = bytes[..counts_at].to_vec();
        forged[version_at..version_at + 4].copy_from_slice(&older.to_le_bytes());
        let decoded = Meta::decode(&forged)
            .unwrap_or_else(|e| panic!("a faithful version-{older} forgery must open: {e}"));
        assert_eq!(decoded.format_version, older);
        assert_eq!(decoded.statistics.total_nodes, 42, "the counters survive");
        assert!(decoded.applied_counts.is_empty());
    }

    // NON-VACUITY: the block really sits after the undo-area one, so cutting at its magic really is
    // the difference between the two forgeries above.
    assert!(
        counts_at > undo_at,
        "the applied-set block must follow the undo-area block for this fixture to mean anything"
    );
}

/// **A version-4 image missing its applied-set block is corruption, not an older image.**
///
/// The counters and the set are one fact. An image that declares version 4 — so its counters were
/// written by a build that folds logged deltas into them — and then has no set is not an older
/// writer that stopped early; it is an image whose two halves disagree, and reading it would replay
/// deltas that are already accounted for. Presence is therefore decided by the version, in both
/// directions, and not by whether bytes happen to remain.
#[test]
fn a_version_4_image_without_its_block_is_refused() {
    let meta = Meta::new(1);
    assert_eq!(
        meta.format_version,
        graphus_core::constants::FORMAT_VERSION,
        "the fixture must be an image at this build's version"
    );
    let bytes = meta.encode().expect("encode");
    assert!(
        Meta::decode(&bytes).is_ok(),
        "NON-VACUITY: the intact image must decode, or the truncation below proves nothing"
    );

    // The block is `magic(8) + frontier(8) + count(4)` for an empty set: dropping any of it must be
    // refused, and dropping all of it must be refused too (that is the case a "trailing bytes are
    // optional" decoder would wave through as an older image).
    for drop in 1..=20usize {
        let cut = bytes.len() - drop;
        assert!(
            Meta::decode(&bytes[..cut]).is_err(),
            "a version-{} image truncated by {drop} byte(s) decoded as if whole",
            graphus_core::constants::FORMAT_VERSION
        );
    }

    // And a block whose magic is wrong is named as such rather than parsed.
    let mut corrupt = bytes.clone();
    let magic_at = bytes.len() - 20;
    corrupt[magic_at] ^= 0xFF;
    let err = Meta::decode(&corrupt).expect_err("a bad magic must be refused");
    assert!(
        format!("{err}").contains("applied-transaction-set block has a bad magic"),
        "the refusal must name the block: {err}"
    );
}
