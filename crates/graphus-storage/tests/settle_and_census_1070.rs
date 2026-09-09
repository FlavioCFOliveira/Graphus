//! **The settle is a side effect of the reference census** (`rmp` #1070).
//!
//! `rmp` #1070 retired three things that existed only to make a *separate* freeze sweep affordable
//! and watchable: the sweep itself, the per-kind **freeze frontier** every writer had to lower when
//! it stamped a header, and the `rmp` #809 rotating-window audit that watched that frontier. What
//! replaced them is one walk of the three MVCC record stores per GC pass which reports the
//! `commit.store` slots the headers name *and* settles what it can settle while it is there.
//!
//! Settling could not simply disappear. Since `rmp` #1069 it is no longer needed for correctness — an
//! unsettled word names a durable commit slot and resolves for ever — but it is still the ONLY thing
//! that takes a slot's last name away, and since #1069 a named slot is never freed. So a build that
//! stopped settling would not lose data; it would leak one `commit.store` slot per writing
//! transaction, for ever, and no test that reads rows could tell.
//!
//! Each test below states which inverse edit makes it fail, because a test that passes against the
//! code it was written to guard proves nothing.

use graphus_core::{HeaderStamp, PageId, TxnId, Value};
use graphus_io::{BlockDevice, MemBlockDevice, Page};
use graphus_storage::{Namespace, RecordStore, StoreKind, StorePages, recovery::recover_device};
use graphus_txn::{Snapshot, is_visible_via};
use graphus_wal::{LogSink, MemLogSink, WalManager};

type Store = RecordStore<MemBlockDevice, MemLogSink>;

const POOL: usize = 64;

fn fresh() -> Store {
    let device = MemBlockDevice::new(0);
    let wal = WalManager::create(MemLogSink::new()).expect("create wal");
    RecordStore::create(device, wal, POOL, 1).expect("create store")
}

/// Runs one GC pass at the latest watermark and returns its report.
fn gc_pass(store: &Store, txn: u64) -> graphus_storage::GcPassReport {
    let txn = TxnId(txn);
    let watermark = store.snapshot_ts();
    store.begin(txn);
    let report = store.gc(txn, watermark).expect("gc");
    store.commit(txn).expect("commit gc");
    report
}

/// Whether `kind`'s record `id` still carries a word that NAMES a commit slot, in either header
/// field — i.e. whether it is still unsettled. This is the exact predicate `slot_named_by_header_word`
/// applies inside the census, restated here from the public header accessor so the test cannot drift
/// into asserting something the collector does not ask.
fn names_a_slot(store: &Store, kind: StoreKind, id: u64) -> bool {
    let mvcc = store.read_mvcc_for_test(kind, id).expect("read header");
    HeaderStamp::from_raw(mvcc.created_ts).slot_id().is_some()
        || HeaderStamp::from_raw(mvcc.expired_ts).slot_id().is_some()
}

/// How many IN-USE records of `kind` still name a commit slot — the store-wide form of
/// [`names_a_slot`], and the quantity the retired `rmp` #809 audit sampled a window of at a time.
fn unsettled_records(store: &Store, kind: StoreKind) -> usize {
    let high_water = store.read_view().meta().high_water(kind);
    (1..high_water)
        .filter(|&id| {
            let mvcc = store.read_mvcc_for_test(kind, id).expect("read header");
            mvcc.in_use() && names_a_slot(store, kind, id)
        })
        .count()
}

/// Whether node `id` is visible to `reader`, decided through the production MVCC rule over the raw
/// header words — which is what makes this a test of the naming words rather than of a helper.
fn node_visible(store: &Store, id: u64, reader: Snapshot) -> bool {
    let mvcc = store.read_mvcc_for_test(StoreKind::Node, id).expect("read");
    mvcc.in_use()
        && is_visible_via(store, reader, mvcc.created_ts, mvcc.expired_ts)
            .expect("every header word must resolve")
}

/// Reopens `store` through its own durable device image and WAL — the steal-crash recovery shape the
/// rest of this crate's suites use (`count_delta_wal_replay_1066`).
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
    RecordStore::open(device, wal, POOL).expect("open the recovered store")
}

// =================================================================================================
// 1. The write path keeps no bookkeeping, and the collector still finds the work.
// =================================================================================================

/// **An in-place property restamp at a LOW physical id is settled by the very next GC pass, although
/// nothing on the write path told the collector where to look** (`rmp` #1070, acceptance criterion 3's
/// subject).
///
/// # The mechanism this replaces, and why the shape of the test is what it is
///
/// `RecordStore::write_prop_cell` is the one place a property cell is rewritten in place, and every
/// such rewrite restamps `created_ts` with the writer's own commit slot. Until #1070 that write had to
/// call `lower_freeze_low` — an atomic read-modify-write on ONE cache line shared by every writer of
/// the database — for a reason that was not cosmetic: the freeze sweep only visited
/// `[freeze_low, high_water)`, and a `SET` of an existing key restamps an id that is very often far
/// below the frontier, so without the descent the sweep never revisited the record and the stamp was
/// never settled (`rmp` #967 reopened the `rmp` #522 shape from a new direction).
///
/// The test therefore builds exactly that geometry: a store whose recent activity is all at HIGH ids
/// (so a frontier, had one survived, would sit high), then a `SET` on the property of the FIRST node
/// created — the lowest ids in the store — and then a single GC pass. If the collector's walk is
/// bounded by anything the write path is no longer maintaining, that record is missed.
///
/// # Non-vacuity
///
/// * **The inverse edit that makes it fail**: re-bound the scan in
///   `RecordStore::settle_and_census_headers` to start at anything above id 1 (which is what restoring
///   the frontier does, since no write path lowers it any more). The low record is then never visited
///   and `names_a_slot` still holds after the pass.
/// * **The positive control inside the test**: the record must be unsettled *before* the pass. Without
///   it, "settled afterwards" would be satisfied by a store where the write never restamped anything.
/// * **The negative control inside the test**: a record that a still-OPEN writer stamped must NOT be
///   settled by the same pass. A scan that settled everything it saw would pass the main assertion
///   while destroying the ability of any later census to see an open writer's claim.
#[test]
fn an_in_place_property_restamp_at_a_low_id_is_settled_with_no_write_path_bookkeeping_1070() {
    let store = fresh();
    let key = store.intern_token(Namespace::PropKey, "v").unwrap();

    // The FIRST node, and its property cell: the lowest physical ids this store will ever hand out.
    let t1 = TxnId(1);
    store.begin(t1);
    let (low_node, _) = store.create_node(t1).expect("create low node");
    store
        .set_node_property_value(t1, low_node, key, &Value::Integer(1))
        .expect("set");
    store.commit(t1).expect("commit t1");

    // Grow the store well above it, and settle everything, so a frontier — had one survived this
    // task — would be sitting at the top of the id space when the restamp below lands.
    let t2 = TxnId(2);
    store.begin(t2);
    for _ in 0..400 {
        let (n, _) = store.create_node(t2).expect("create filler node");
        store
            .set_node_property_value(t2, n, key, &Value::Integer(7))
            .expect("set filler");
    }
    store.commit(t2).expect("commit t2");
    gc_pass(&store, 3);
    assert_eq!(
        unsettled_records(&store, StoreKind::Prop),
        0,
        "setup: every property cell must start SETTLED, or the assertion below cannot distinguish \
         'the restamp was settled' from 'it was already settled'"
    );

    // THE SUBJECT: an in-place restamp of the low cell. `set_node_property_value` on an existing key
    // rewrites the cell in place and restamps `created_ts` — the write that used to have to lower the
    // frontier and now tells the collector nothing at all.
    let t4 = TxnId(4);
    store.begin(t4);
    store
        .set_node_property_value(t4, low_node, key, &Value::Integer(2))
        .expect("in-place overwrite");
    store.commit(t4).expect("commit t4");
    assert_eq!(
        unsettled_records(&store, StoreKind::Prop),
        1,
        "positive control: the in-place overwrite must leave exactly the low cell naming its writer's \
         commit slot, or there is nothing for the pass below to settle"
    );

    // A NEGATIVE CONTROL, armed before the pass: a still-open writer's stamp on a different record.
    // The same pass must leave it alone — a scan that settles an open transaction's claim would
    // destroy the census's only means of seeing it.
    let open_writer = TxnId(5);
    store.begin(open_writer);
    let (open_node, _) = store.create_node(open_writer).expect("create open node");

    // ONE pass. No hint, no frontier, no bookkeeping from the write path.
    let report = gc_pass(&store, 6);
    assert!(
        report.frozen >= 1,
        "the pass must have settled at least the restamped cell (settled {} words)",
        report.frozen
    );
    assert_eq!(
        unsettled_records(&store, StoreKind::Prop),
        0,
        "the in-place restamp at a LOW id must be settled by the next GC pass. It is not, which means \
         the collector's walk is bounded by state the write path no longer maintains — the `rmp` #967 \
         reopening of the `rmp` #522 shape, arriving through the removal instead of through the write"
    );
    assert!(
        names_a_slot(&store, StoreKind::Node, open_node),
        "negative control: a still-OPEN writer's stamp must NOT be settled — its transaction has not \
         resolved, so there is no commit timestamp to settle it to, and the census must go on seeing \
         the slot it names"
    );
    store
        .rollback(open_writer)
        .expect("release the open writer");

    // And the value the row actually holds, read through the production path, is the new one.
    let reader = Snapshot::new(TxnId(9999), store.snapshot_ts());
    let decided = store
        .decision_scan_node_properties(low_node, reader)
        .expect("decision-polarity property read");
    let seen = decided.visible_version(key).expect("the key is present");
    assert_eq!(
        store
            .decode_property_value(seen.type_tag, seen.value_inline)
            .expect("decode"),
        Value::Integer(2),
        "settling a header must not change what the row says"
    );
}

// =================================================================================================
// 2. Nothing grows without bound now that the settle has moved.
// =================================================================================================

/// **The `CommitRegistry` — the Active/Recent Transaction Table — plateaus under sustained
/// create/delete churn** (`rmp` #1070, acceptance criterion 4).
///
/// # Why this needs its own test, beside the `commit.store` one
///
/// They are two different leaks with two different causes, and one can be fixed while the other is
/// live. `commit.store` grows when the CENSUS stops proving slots unreachable; the registry grows when
/// the PRUNE stops being scheduled. The prune's precondition is that the pass settled every naming
/// stamp of every resolved writer — so if the settle stops happening, or stops being complete, this
/// table grows by one entry per writing transaction, for ever, and nothing else fails.
///
/// `undo_chain.rs::the_undo_store_plateaus_under_sustained_create_delete_churn` is the `commit.store`
/// half. This is the registry half, on the same churn profile.
///
/// # Non-vacuity
///
/// * **The inverse edit that makes it fail**: delete the `pending_gc_prune` scheduling at the end of
///   `RecordStore::gc_inner`, or drop the settle from `settle_and_census_headers` (which is the same
///   thing one step earlier — a pass that settles nothing still schedules a prune, but
///   `debug_assert_freeze_complete` fires first in a debug build, and in a release build the registry
///   is pruned while headers still name the forgotten writers). Either way the table climbs with the
///   round number instead of sitting flat.
/// * **The positive control**: the warm-up length must be non-zero and the churn must really reclaim,
///   or "flat" is what an idle store looks like.
#[test]
fn the_commit_registry_plateaus_under_sustained_create_delete_churn_1070() {
    const PER_ROUND: usize = 20;
    const ROUNDS: u64 = 30;
    const WARMUP: u64 = 5;

    let store = fresh();
    let rel_type = {
        let t = TxnId(1);
        store.begin(t);
        let rt = store.intern_token(Namespace::RelType, "LINK").unwrap();
        store.commit(t).expect("commit intern");
        rt
    };

    let registry_len = |s: &Store| s.commit_registry().len();
    let mut warm_len = 0usize;
    let mut total_reclaimed = 0usize;
    let mut next = 2u64;

    for round in 0..ROUNDS {
        let mut entities = Vec::with_capacity(PER_ROUND);
        let txn = TxnId(next);
        next += 1;
        store.begin(txn);
        for _ in 0..PER_ROUND {
            let (a, _) = store.create_node(txn).expect("node a");
            let (b, _) = store.create_node(txn).expect("node b");
            let (r, _) = store.create_rel(txn, rel_type, a, b).expect("rel");
            entities.push((a, b, r));
        }
        store.commit(txn).expect("commit creates");

        let txn = TxnId(next);
        next += 1;
        store.begin(txn);
        for &(a, b, r) in &entities {
            store.delete_rel(txn, r).expect("delete rel");
            store.delete_node(txn, a).expect("delete a");
            store.delete_node(txn, b).expect("delete b");
        }
        store.commit(txn).expect("commit deletes");

        let report = gc_pass(&store, next);
        next += 1;
        total_reclaimed += report.reclaimed;

        if round == WARMUP {
            warm_len = registry_len(&store);
        } else if round > WARMUP {
            assert_eq!(
                registry_len(&store),
                warm_len,
                "round {round}: the Active/Recent Transaction Table must not grow once the churn is \
                 in steady state — it went {warm_len} -> {}. A table that grows by one entry per \
                 writing transaction is what a settle that stopped covering the store looks like: \
                 nothing errs, no row is wrong, and the process's memory climbs until it is killed",
                registry_len(&store)
            );
        }
    }

    assert!(
        warm_len > 0,
        "positive control: the registry must actually hold entries between passes ({warm_len}), or \
         'it does not grow' is a statement about an empty table"
    );
    assert!(
        total_reclaimed >= PER_ROUND * 3 * (ROUNDS as usize - 2),
        "positive control: each round must really reclaim its entities ({total_reclaimed} over \
         {ROUNDS} rounds)"
    );
}

// =================================================================================================
// 3. A store this task's predecessor could leave behind still reads.
// =================================================================================================

/// **A store left with UNSETTLED headers — the state a build from before this task routinely left
/// between GC passes — reopens and reads every committed value correctly** (`rmp` #1070, acceptance
/// criterion 2).
///
/// # What "a store written before this task" means here, and why no format forgery is involved
///
/// `rmp` #1070 moves no byte on disk, defines no new block and changes no header encoding: the freeze
/// frontier it removed was pure in-memory state, rebuilt from `1` on every `open` and never persisted
/// in the catalogue. So the format version does not move, and the version-downgrade forger
/// (`property_undo_chain_967.rs::downgrade_catalog_to`) has nothing to forge — an image written by the
/// `rmp` #1069 build IS an image this build writes.
///
/// What DOES distinguish such an image is its *state*: records whose `created_ts` / `expired_ts` still
/// name a `commit.store` slot because no GC pass has settled them yet. Every build since #1069 leaves
/// that state between passes, and it is precisely the state the retired sweep existed to clear. This
/// test constructs it deliberately — commit, never run GC, close — and requires the reopened store to
/// resolve every one of those headers.
///
/// It is an INVARIANCE test, and honesty about that matters: it passes against `d105f96` too, because
/// #1069 is what made an unsettled header resolvable and #1070 does not touch that path. It is here
/// because `retired-mechanism-leaves-data-behind` says a retired mechanism's leftovers are exactly
/// what green tests structurally miss — the leftovers must be constructed, not reasoned about.
///
/// # Non-vacuity
///
/// * **The positive control**: the image must really carry unsettled stamps at the moment it is
///   closed, counted with [`read_view::scan_unsettled_stamps`]. Without it the test would be reading
///   an ordinary settled store and proving nothing about the leftover state.
/// * **The inverse edit that makes it fail**: make `CommitOracle::resolve_stamp` refuse a word that
///   names a slot (the pre-#1069 rule, where only the in-memory registry could translate a stamp).
///   Every row below then reads as invisible — which is what this state cost before #1069, and the
///   reason the retired sweep had a deadline to meet.
#[test]
fn a_store_left_with_unsettled_headers_reopens_and_reads_them_1070() {
    let store = fresh();
    let key = store.intern_token(Namespace::PropKey, "v").unwrap();

    let t1 = TxnId(1);
    store.begin(t1);
    let nodes: Vec<u64> = (0..25)
        .map(|i| {
            let (n, _) = store.create_node(t1).expect("create node");
            store
                .set_node_property_value(t1, n, key, &Value::Integer(i))
                .expect("set");
            n
        })
        .collect();
    store.commit(t1).expect("commit t1");

    // Tombstones too, so `expired_ts` carries naming words as well as `created_ts`.
    let t2 = TxnId(2);
    store.begin(t2);
    let deleted: Vec<u64> = nodes.iter().copied().step_by(5).collect();
    for &n in &deleted {
        store.delete_node(t2, n).expect("delete");
    }
    store.commit(t2).expect("commit t2");

    // NO GC PASS. This is the whole point: the image goes to disk with every one of those stamps
    // still naming its writer's commit slot.
    let before_nodes = unsettled_records(&store, StoreKind::Node);
    let before_props = unsettled_records(&store, StoreKind::Prop);
    assert!(
        before_nodes >= nodes.len() && before_props >= nodes.len(),
        "positive control: the image must really be left with unsettled stamps (nodes \
         {before_nodes}, props {before_props}) — otherwise this test reopens an ordinary store"
    );

    let mut store = store;
    let store = reopen(&mut store);

    // The state survived the reopen — the reader below is genuinely resolving naming words, not words
    // some step in between quietly settled.
    let after_nodes = unsettled_records(&store, StoreKind::Node);
    assert!(
        after_nodes >= nodes.len(),
        "the reopened image must still carry its unsettled stamps ({after_nodes}), or the read below \
         is not exercising the leftover state this test exists for"
    );

    let reader = Snapshot::new(TxnId(9999), store.snapshot_ts());
    for (i, &n) in nodes.iter().enumerate() {
        if deleted.contains(&n) {
            // A committed deletion whose `expired_ts` is still a naming word must still read as
            // deleted. An `expired_ts` that failed to resolve reads as NOT expired — a committed
            // deletion coming back.
            assert!(
                !node_visible(&store, n, reader),
                "node {n} was deleted before the close and must not be visible after the reopen"
            );
            continue;
        }
        assert!(
            node_visible(&store, n, reader),
            "node {n} was committed before the close and must be visible after the reopen — an \
             unsettled `created_ts` that failed to resolve reads as INVISIBLE, which is silent lost \
             committed data"
        );
        let decided = store
            .decision_scan_node_properties(n, reader)
            .expect("decision-polarity property read");
        let seen = decided.visible_version(key).unwrap_or_else(|| {
            panic!("node {n}'s committed property must be visible after reopen")
        });
        assert_eq!(
            store
                .decode_property_value(seen.type_tag, seen.value_inline)
                .expect("decode"),
            Value::Integer(i64::try_from(i).expect("small")),
            "node {n} must read back the value its unsettled header names"
        );
    }

    // And the settle still works on such an image: one pass clears every leftover.
    gc_pass(&store, 100);
    assert_eq!(
        unsettled_records(&store, StoreKind::Node),
        0,
        "one GC pass over a reopened image must settle every leftover node stamp"
    );
    assert_eq!(
        unsettled_records(&store, StoreKind::Prop),
        0,
        "one GC pass over a reopened image must settle every leftover property stamp"
    );
}
