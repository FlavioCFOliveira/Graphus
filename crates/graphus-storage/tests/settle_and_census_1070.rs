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
use graphus_txn::{CommitOracle, Snapshot, is_visible_via};
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
/// lower the retired freeze frontier — an atomic read-modify-write on ONE cache line shared by every
/// writer of the database — for a reason that was not cosmetic: the freeze sweep only visited the ids
/// from the frontier up to the high-water mark, and a `SET` of an existing key restamps an id that is
/// very often far below the frontier, so without the descent the sweep never revisited the record and
/// the stamp was never settled (`rmp` #967 reopened the `rmp` #522 shape from a new direction).
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
///   `RecordStore::gc_inner`. The table then climbs with the round number instead of sitting flat.
///   (Dropping the settle instead is caught one step earlier, by
///   `RecordStore::debug_assert_prune_precondition` in a debug build.) The concurrent-writer form of
///   this property, with the Active Transaction Table, the WAL floor map and heap bytes as well, is
///   `transaction_tables_plateau_1070.rs`.
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

// =================================================================================================
// 4. The settle is the only un-namer: what it bounds, and what it deliberately does not.
// =================================================================================================

/// The `commit.store` high-water mark and how many slots in it are in use.
fn commit_store_shape(store: &Store) -> (u64, usize) {
    let high_water = store.read_view().meta().high_water(StoreKind::Commit);
    let live = (1..high_water)
        .filter(|&id| matches!(store.commit_slot(id), Ok(Some(slot)) if slot.in_use()))
        .count();
    (high_water, live)
}

/// **`commit.store` plateaus on a workload where the settle is the ONLY thing that un-names a slot**
/// (`rmp` #1070, acceptance criterion 5, audit finding E).
///
/// # Why this workload, and not create/delete churn
///
/// Under create/delete churn a slot loses its last header name when the record is RECLAIMED, so the
/// census frees slots whether or not anything settles — which is why
/// `undo_chain.rs::the_undo_store_plateaus_under_sustained_create_delete_churn` passes with the
/// settle removed and proves nothing about it. Here every node SURVIVES: each round commits five new
/// nodes (a creation header that names the round's slot for as long as nothing settles it) and
/// overwrites the property of the SAME five old nodes in place (cells that are restamped every
/// round). Nothing is ever reclaimed, so the only way a slot stops being named is that a GC pass
/// rewrites the words naming it to their `Committed(ts)` form.
///
/// # Non-vacuity
///
/// * **The inverse edit that makes it fail**: in `RecordStore::settle_and_census_headers`, make the
///   settle never write (e.g. `if false && let Some(settled_word) = …`). Every creation header keeps
///   its name, every round pins one more slot, and the high-water climbs with the round number.
/// * **The positive control**: the churn must allocate a slot per writing transaction and the store
///   must really keep what it creates, or "flat" is what an idle store looks like.
#[test]
fn commit_store_plateaus_when_only_the_settle_can_un_name_a_slot_1070() {
    const ROUNDS: u64 = 30;
    const WARMUP: u64 = 5;
    let store = fresh();
    let key = store.intern_token(Namespace::PropKey, "v").unwrap();
    let mut next = 10u64;
    let mut nodes: Vec<u64> = Vec::new();
    let mut warm = (0u64, 0usize);
    for round in 0..ROUNDS {
        let value = Value::Integer(i64::try_from(round).expect("small"));
        let t = TxnId(next);
        next += 1;
        store.begin(t);
        for _ in 0..5 {
            let (n, _) = store.create_node(t).unwrap();
            store.set_node_property_value(t, n, key, &value).unwrap();
            nodes.push(n);
        }
        store.commit(t).unwrap();
        let t = TxnId(next);
        next += 1;
        store.begin(t);
        for &n in nodes.iter().take(5) {
            store.set_node_property_value(t, n, key, &value).unwrap();
        }
        store.commit(t).unwrap();
        gc_pass(&store, next);
        next += 1;
        let shape = commit_store_shape(&store);
        if round == WARMUP {
            warm = shape;
        } else if round > WARMUP {
            assert!(
                shape.0 <= warm.0 && shape.1 <= warm.1,
                "round {round}: commit.store must not grow once the churn is in steady state — \
                 (high-water, live slots) went {warm:?} -> {shape:?}. A slot named by a surviving \
                 record is freed only after a GC pass settles that name away, so a store whose \
                 settle stopped leaks one slot per writing transaction, for ever."
            );
        }
    }
    let reader = Snapshot::new(TxnId(9_999_999), store.snapshot_ts());
    assert!(
        nodes.len() == 5 * ROUNDS as usize
            && nodes.iter().all(|&n| node_visible(&store, n, reader)),
        "positive control: every node the churn created must survive and stay visible"
    );
    assert!(
        next > 2 * ROUNDS && warm.0 > 1,
        "positive control: the churn must have allocated commit slots ({warm:?})"
    );
}

/// The `created_ts` word of `n`'s cell for `key`.
fn cell_word(store: &Store, n: u64, key: u32) -> u64 {
    store
        .superset_scan_node_properties(n)
        .expect("read the cells")
        .cells_ignoring_history()
        .iter()
        .find(|(_, cell)| cell.key == key)
        .map(|(_, cell)| cell.mvcc.created_ts)
        .expect("the node's cell")
}

/// **An aborted in-place `SET` leaves the cell stamped with its value's TRUE installer — and a crash
/// with a later writer open cannot bring the aborted transaction's slot name back** (`rmp` #1070,
/// audit findings G and F1).
///
/// # The defect this pins
///
/// The rollback used to restore the cell's value but leave its `created_ts` naming the aborted
/// transaction A's slot, relying on the census to pin that slot. The pin did not survive a later
/// writer: W overwrote the cell (so the census stopped seeing A's name), A's slot — which no delta
/// names — was zeroed and recycled, and a crash with W still open had ARIES restore W's whole-cell
/// pre-image, i.e. A's name. The recovered cell then named a slot that "was never written" (every
/// later `gc()` failed) or a stranger's slot (the next settle stamped the stranger as installer).
///
/// Now the rollback re-stamps the cell with the settled commit timestamp of whoever installed the
/// value it restores (`RecordStore::installer_stamp_after_rollback`), so no live cell ever names an
/// aborted slot and W's pre-image is a value, not an id.
///
/// # Non-vacuity
///
/// * **The inverse edit that makes it fail**: in `RecordStore::undo_own_property`, drop the
///   `cell.mvcc.created_ts = …installer_stamp_after_rollback(…)?` assignment. The first assertion
///   fails (the cell names A's slot), and with it removed too, the post-recovery GC pass fails with
///   the "never written" read fault.
/// * **The positive controls**: W's write really restamps the cell (so the census cannot see A's
///   name any more), and the churn really recycles slots, so a recycled name would be observable.
#[test]
fn an_aborted_in_place_set_leaves_no_slot_name_a_crash_can_resurrect_1070() {
    let mut store = fresh();
    let key = store.intern_token(Namespace::PropKey, "v").unwrap();
    let t1 = TxnId(1);
    store.begin(t1);
    let (n, _) = store.create_node(t1).unwrap();
    store
        .set_node_property_value(t1, n, key, &Value::Integer(1))
        .unwrap();
    let ts1 = store.commit(t1).unwrap();
    gc_pass(&store, 2);

    // A overwrites in place and aborts.
    let a = TxnId(100);
    store.begin(a);
    store
        .set_node_property_value(a, n, key, &Value::Integer(2))
        .unwrap();
    store.rollback(a).unwrap();
    assert_eq!(
        cell_word(&store, n, key),
        HeaderStamp::committed(ts1),
        "the rolled-back cell must carry its value's installer (t1, committed at {ts1:?}), never the \
         aborted transaction's slot"
    );

    // W overwrites in place and stays OPEN across passes and slot churn.
    let w = TxnId(200);
    store.begin(w);
    store
        .set_node_property_value(w, n, key, &Value::Integer(3))
        .unwrap();
    assert!(
        HeaderStamp::from_raw(cell_word(&store, n, key))
            .slot_id()
            .is_some(),
        "positive control: W's write restamps the cell with W's slot"
    );
    let mut next = 1_000u64;
    let mut churn = std::collections::BTreeSet::new();
    for _ in 0..4 {
        for _ in 0..5 {
            let u = TxnId(next);
            next += 1;
            store.begin(u);
            let (m, _) = store.create_node(u).unwrap();
            churn.extend(
                HeaderStamp::from_raw(
                    store
                        .read_mvcc_for_test(StoreKind::Node, m)
                        .unwrap()
                        .created_ts,
                )
                .slot_id(),
            );
            store.commit(u).unwrap();
        }
        gc_pass(&store, next);
        next += 1;
    }
    assert!(
        churn.len() < 20,
        "positive control: the churn must recycle slots ({} distinct for 20 writers)",
        churn.len()
    );

    // Crash with W in flight: ARIES undoes W's cell write, restoring its pre-image.
    let recovered = reopen(&mut store);
    let word = cell_word(&recovered, n, key);
    assert_eq!(
        word,
        HeaderStamp::committed(ts1),
        "after recovery the cell must carry t1's settled stamp again, not a slot name"
    );
    let reader = Snapshot::new(TxnId(9_999_999), recovered.snapshot_ts());
    let seen = recovered
        .decision_scan_node_properties(n, reader)
        .unwrap()
        .visible_version(key)
        .map(|pv| {
            recovered
                .decode_property_value(pv.type_tag, pv.value_inline)
                .unwrap()
        });
    assert_eq!(
        seen,
        Some(Value::Integer(1)),
        "the committed value reads back"
    );
    gc_pass(&recovered, 900_000);
    assert_eq!(
        cell_word(&recovered, n, key),
        HeaderStamp::committed(ts1),
        "a GC pass after recovery succeeds and leaves the installer unchanged"
    );
    let report = graphus_storage::check::check_store(&recovered, &[]).expect("consistency pass");
    assert!(report.is_consistent(), "{:?}", report.violations);
}

/// **When the installer's own delta has already been reclaimed, the rollback stamps a lower bound
/// that every reader answers identically** (`rmp` #1070, audit finding G).
///
/// Here t1's chain is reclaimed (the watermark has passed it) before A writes, so no delta on the
/// chain names the installer; the stamp falls back to the entity's creation timestamp. The oracle
/// is behavioural: every snapshot that can still exist reads t1's value, and the cell's stamp is a
/// committed timestamp at or below t1's.
///
/// # Non-vacuity
///
/// The positive control asserts the chain really is empty before A writes. The inverse edit that
/// makes it fail is the same as the sibling test's (drop the re-stamp): the cell then names A's slot.
#[test]
fn an_aborted_set_over_a_reclaimed_history_stamps_a_sound_lower_bound_1070() {
    let store = fresh();
    let key = store.intern_token(Namespace::PropKey, "v").unwrap();
    let t1 = TxnId(1);
    store.begin(t1);
    let (n, _) = store.create_node(t1).unwrap();
    store
        .set_node_property_value(t1, n, key, &Value::Integer(1))
        .unwrap();
    let ts1 = store.commit(t1).unwrap();
    gc_pass(&store, 2);
    gc_pass(&store, 3);
    assert_eq!(
        store
            .read_mvcc_for_test(StoreKind::Node, n)
            .unwrap()
            .undo_ptr,
        0,
        "positive control: t1's chain is reclaimed before A writes"
    );
    let a = TxnId(100);
    store.begin(a);
    store
        .set_node_property_value(a, n, key, &Value::Integer(2))
        .unwrap();
    store.rollback(a).unwrap();
    let word = cell_word(&store, n, key);
    assert!(
        HeaderStamp::from_raw(word).slot_id().is_none() && word != 0,
        "the cell must carry a settled stamp, not a slot name ({word:#x})"
    );
    let stamped = store.resolve_commit_ts(word).unwrap().expect("committed");
    assert!(
        stamped <= ts1,
        "{stamped:?} must not be later than the installer's {ts1:?}"
    );
    let reader = Snapshot::new(TxnId(9_999_999), store.snapshot_ts());
    let seen = store
        .decision_scan_node_properties(n, reader)
        .unwrap()
        .visible_version(key)
        .map(|pv| {
            store
                .decode_property_value(pv.type_tag, pv.value_inline)
                .unwrap()
        });
    assert_eq!(seen, Some(Value::Integer(1)));
}

/// **The installer found on the chain is the NEWEST committed writer of the key, not a lower bound**
/// (`rmp` #1070, audit finding G, re-certification gap).
///
/// T1 installs `v = 1`, T2 overwrites it with `v = 2`, T3 overwrites again and aborts. T2's delta is
/// still on the chain, so the rollback must stamp the cell `Committed(ts2)`. A lower bound here would
/// be UNSOUND: the cell's stamp is what the column cache's freshness witness tests against a reader's
/// snapshot, and a stamp at or below `ts1` tells a reader at `ts1` that the cell's `v = 2` is visible
/// to it — while the authoritative chain read correctly gives that reader `v = 1`.
///
/// # Non-vacuity
///
/// The inverse edit that makes it fail: in `RecordStore::installer_stamp_after_rollback`, skip the
/// chain walk (start it at `NULL_ID`), so every rollback takes the reclaimed-history fallback. The
/// cell is then stamped with the entity's creation timestamp (`ts1`), and both assertions below fail.
#[test]
fn an_aborted_set_stamps_the_newest_committed_installer_on_the_chain_1070() {
    let store = fresh();
    let key = store.intern_token(Namespace::PropKey, "v").unwrap();
    let t1 = TxnId(1);
    store.begin(t1);
    let (n, _) = store.create_node(t1).unwrap();
    store
        .set_node_property_value(t1, n, key, &Value::Integer(1))
        .unwrap();
    let ts1 = store.commit(t1).unwrap();
    let t2 = TxnId(2);
    store.begin(t2);
    store
        .set_node_property_value(t2, n, key, &Value::Integer(2))
        .unwrap();
    let ts2 = store.commit(t2).unwrap();
    assert!(ts1 < ts2, "positive control: two distinct commits");

    let t3 = TxnId(3);
    store.begin(t3);
    store
        .set_node_property_value(t3, n, key, &Value::Integer(3))
        .unwrap();
    store.rollback(t3).unwrap();

    assert_eq!(
        cell_word(&store, n, key),
        HeaderStamp::committed(ts2),
        "the restored v = 2 was installed by T2 (committed at {ts2:?}); the cell must say so"
    );
    // The consequence the stamp exists for: a reader at ts1 must not be told, by the cell's own
    // header, that the cell's current value is visible to it.
    let old_reader = Snapshot::new(TxnId(9_999_999), ts1);
    let word = cell_word(&store, n, key);
    assert!(
        !is_visible_via(&store, old_reader, word, 0).unwrap(),
        "a reader at {ts1:?} must not see the cell's v = 2 through its header"
    );
    let seen = store
        .decision_scan_node_properties(n, old_reader)
        .unwrap()
        .visible_version(key)
        .map(|pv| {
            store
                .decode_property_value(pv.type_tag, pv.value_inline)
                .unwrap()
        });
    assert_eq!(
        seen,
        Some(Value::Integer(1)),
        "the chain read gives that reader v = 1"
    );
}
