//! Acceptance tests for the **directional** relationship-count projections (`rmp` task #856):
//! `(startLabel, type)` and `(type, endLabel)`.
//!
//! The planner needs these to tell a selective anchor from a fan-out one. `rels_per_type` alone gives
//! one graph-wide degree per type, which makes both ends of a relationship look identical — measured on
//! the evaluation store, `LIKES` estimates a degree of 9.7 from *any* anchor while the true out-degree
//! is about 10 from a `USER` and about 333 from an `ARTICLE`.
//!
//! An estimate is only as trustworthy as the counter behind it, so every test here compares the
//! incrementally-maintained counters against an **independent re-scan oracle** built in this file from
//! nothing but public record reads. The oracle shares no code with the maintenance path under test:
//! that is the whole point, and it is why `recount_directional_rel_counts` (which the store exposes for
//! the backfill) is deliberately *not* used as the oracle here — only as the subject of the backfill
//! test.
//!
//! "Live" means the same thing it means to the counters: the slot is in use **and** the record carries
//! no MVCC tombstone (`xmax == 0`).

use std::collections::BTreeMap;

use graphus_core::TxnId;
use graphus_io::MemBlockDevice;
use graphus_storage::recovery::recover_device;
use graphus_storage::{Namespace, RecordStore};
use graphus_wal::{LogSink, MemLogSink, WalManager};

type Store = RecordStore<MemBlockDevice, MemLogSink>;

/// Both directional maps: `(by_start_label_type, by_type_end_label)`.
type Directional = (BTreeMap<(u32, u32), u64>, BTreeMap<(u32, u32), u64>);

fn fresh(cap: usize) -> Store {
    let device = MemBlockDevice::new(0);
    let wal = WalManager::create(MemLogSink::new()).expect("create wal");
    RecordStore::create(device, wal, cap, 1).expect("create store")
}

/// Independent re-scan oracle, from public reads only.
///
/// For every live relationship: one increment per label its **start** node carries, keyed
/// `(label, type)`; and one per label its **end** node carries, keyed `(type, label)`. A self-loop's
/// single node is both endpoints, so it contributes to both maps — the oracle gets that for free by
/// asking the same node twice rather than by special-casing it, which is exactly why it can catch a
/// maintenance path that special-cased it wrongly.
fn rescan_directional(s: &mut Store) -> Directional {
    let mut by_start: BTreeMap<(u32, u32), u64> = BTreeMap::new();
    let mut by_end: BTreeMap<(u32, u32), u64> = BTreeMap::new();
    for id in s.scan_rel_ids().expect("scan rels") {
        let rel = s.rel(id).expect("read rel");
        if rel.mvcc.expired_ts != 0 {
            continue;
        }
        for label in s.node_labels(rel.start_node).expect("start labels") {
            *by_start.entry((label, rel.type_id)).or_insert(0) += 1;
        }
        for label in s.node_labels(rel.end_node).expect("end labels") {
            *by_end.entry((rel.type_id, label)).or_insert(0) += 1;
        }
    }
    (by_start, by_end)
}

/// Asserts the maintained counters exactly equal the oracle — the invariant the whole task rests on.
fn assert_matches_rescan(s: &mut Store) {
    let (want_start, want_end) = rescan_directional(s);
    let stats = s.statistics();
    assert_eq!(
        stats.rels_per_start_label_type, want_start,
        "(startLabel, type) counters must equal an independent re-scan"
    );
    assert_eq!(
        stats.rels_per_type_end_label, want_end,
        "(type, endLabel) counters must equal an independent re-scan"
    );
}

/// Asserts the counters are non-empty, so a passing equality above cannot be the trivial empty==empty.
fn assert_non_vacuous(s: &Store) {
    assert!(
        s.has_directional_rel_counts(),
        "the corpus must produce counters, else every comparison here holds vacuously"
    );
}

/// Splits a flushed store into its device + a freshly-opened WAL over the same durable log, so the
/// store can be reopened. The pages were flushed home, so this is a clean reopen (no recovery work).
fn into_parts(mut s: Store) -> (MemBlockDevice, WalManager<MemLogSink>) {
    s.flush().unwrap();
    let pages = s.mapped_pages();
    let max = pages.iter().map(|p| p.0).max().unwrap_or(0);
    let mut device = MemBlockDevice::new(max + 1);
    {
        let mut staged: Vec<(u64, Box<graphus_io::Page>)> = Vec::new();
        for p in &pages {
            staged.push((p.0, s.read_device_page(*p).expect("read device page")));
        }
        use graphus_io::BlockDevice;
        for (idx, bytes) in staged {
            device
                .write_page(graphus_core::PageId(idx), &bytes)
                .expect("stage page");
        }
        device.sync_all().expect("persist disk image");
    }
    let sink = s.with_wal(|w| w.sink().clone());
    let wal = WalManager::open(sink).expect("reopen wal");
    (device, wal)
}

fn durable_log(store: &Store) -> Vec<u8> {
    store.with_wal(|w| w.sink().durable_bytes().to_vec())
}

/// Recovers a no-force crash: committed work lives only in the durable WAL.
fn recover_no_force(store: &Store) -> Store {
    let log = durable_log(store);
    let mut sink = MemLogSink::new();
    sink.append(&log);
    sink.sync().expect("sync log prefix");
    let mut device = MemBlockDevice::new(0);
    let mut wal = WalManager::open(sink.clone()).expect("open wal");
    recover_device(&mut wal, &mut device).expect("recover");
    let wal = WalManager::open(sink).expect("reopen wal");
    RecordStore::open(device, wal, 64).expect("open recovered store")
}

/// A corpus with deliberately ASYMMETRIC degrees, which is the shape the whole task exists for:
/// `USER -[:LIKES]-> ARTICLE`, where each user likes 2 articles and one article is liked by everyone.
/// Returns `(user_label, article_label, likes_type, users, articles)`.
fn asymmetric_corpus(s: &mut Store) -> (u32, u32, u32, Vec<u64>, Vec<u64>) {
    let txn = TxnId(1);
    s.begin(txn);
    let user = s.intern_token(Namespace::Label, "USER").unwrap();
    let article = s.intern_token(Namespace::Label, "ARTICLE").unwrap();
    let likes = s.intern_token(Namespace::RelType, "LIKES").unwrap();
    let users: Vec<u64> = (0..6)
        .map(|_| {
            let (id, _) = s.create_node(txn).unwrap();
            s.add_label(txn, id, user).unwrap();
            id
        })
        .collect();
    let articles: Vec<u64> = (0..3)
        .map(|_| {
            let (id, _) = s.create_node(txn).unwrap();
            s.add_label(txn, id, article).unwrap();
            id
        })
        .collect();
    for (i, &u) in users.iter().enumerate() {
        // Everyone likes article 0; each user also likes one other, so out-degree is 2 per user while
        // article 0's in-degree is 6 — the asymmetry a graph-wide degree cannot see.
        s.create_rel(txn, likes, u, articles[0]).unwrap();
        s.create_rel(txn, likes, u, articles[1 + i % 2]).unwrap();
    }
    s.commit(txn).unwrap();
    (user, article, likes, users, articles)
}

// =================================================================================================
// Exactness under every mutation shape
// =================================================================================================

#[test]
fn fresh_store_has_no_directional_counters() {
    let mut s = fresh(64);
    assert!(!s.has_directional_rel_counts());
    assert_eq!(s.rel_count_for_start_label_type(0, 0), 0);
    assert_eq!(s.rel_count_for_type_end_label(0, 0), 0);
    assert_matches_rescan(&mut s);
}

#[test]
fn counters_capture_the_asymmetry_a_graph_wide_degree_cannot() {
    // The measurement that motivates the task, in miniature: the same relationship type has a
    // different degree from each end, and only a directional counter can say so.
    let mut s = fresh(256);
    let (user, article, likes, users, _articles) = asymmetric_corpus(&mut s);
    assert_non_vacuous(&s);
    assert_matches_rescan(&mut s);

    let from_users = s.rel_count_for_start_label_type(user, likes);
    let into_articles = s.rel_count_for_type_end_label(likes, article);
    assert_eq!(from_users, 12, "6 users x 2 likes each");
    assert_eq!(into_articles, 12, "the same 12 edges land on articles");
    // Per-anchor degree: 12/6 = 2 out of a USER, 12/3 = 4 into an ARTICLE. The graph-wide degree
    // (12 edges over 9 nodes = 1.33) matches neither, which is exactly the defect being fixed.
    let out_degree = from_users as f64 / users.len() as f64;
    let in_degree = into_articles as f64 / 3.0;
    assert!(
        (out_degree - 2.0).abs() < 1e-9 && (in_degree - 4.0).abs() < 1e-9,
        "out={out_degree} in={in_degree}"
    );
    assert!(
        (out_degree - in_degree).abs() > 1e-9,
        "the two directions must differ, or the projection adds nothing"
    );
}

#[test]
fn counters_stay_exact_across_relationship_deletes() {
    let mut s = fresh(256);
    let (user, _article, likes, users, articles) = asymmetric_corpus(&mut s);
    let before = s.rel_count_for_start_label_type(user, likes);

    let txn = TxnId(2);
    s.begin(txn);
    // Delete two of the edges out of user 0.
    let victims: Vec<u64> = s
        .incident_rels(users[0])
        .unwrap()
        .into_iter()
        .take(2)
        .collect();
    assert_eq!(victims.len(), 2, "premise: user 0 must have two edges");
    for v in victims {
        s.delete_rel(txn, v).unwrap();
    }
    s.commit(txn).unwrap();

    assert_matches_rescan(&mut s);
    assert_eq!(
        s.rel_count_for_start_label_type(user, likes),
        before - 2,
        "deleting two edges must drop the start-side counter by exactly two"
    );
    let _ = articles;
}

#[test]
fn a_self_loop_counts_on_both_sides() {
    // Its one node genuinely IS both the start and the end, so it must appear in both projections. A
    // maintenance path that read the endpoints once and counted once would silently halve one side.
    let mut s = fresh(64);
    let txn = TxnId(1);
    s.begin(txn);
    let l = s.intern_token(Namespace::Label, "L").unwrap();
    let ty = s.intern_token(Namespace::RelType, "T").unwrap();
    let (n, _) = s.create_node(txn).unwrap();
    s.add_label(txn, n, l).unwrap();
    s.create_rel(txn, ty, n, n).unwrap();
    s.commit(txn).unwrap();

    assert_non_vacuous(&s);
    assert_matches_rescan(&mut s);
    assert_eq!(s.rel_count_for_start_label_type(l, ty), 1);
    assert_eq!(s.rel_count_for_type_end_label(ty, l), 1);

    // And deleting it must clear both sides, not just one.
    let rel = s.incident_rels(n).unwrap()[0];
    let t2 = TxnId(2);
    s.begin(t2);
    s.delete_rel(t2, rel).unwrap();
    s.commit(t2).unwrap();
    assert_matches_rescan(&mut s);
    assert_eq!(s.rel_count_for_start_label_type(l, ty), 0);
    assert_eq!(s.rel_count_for_type_end_label(ty, l), 0);
}

#[test]
fn a_multi_label_endpoint_counts_once_per_label() {
    // One relationship, whose start node carries three labels, contributes to three separate keys —
    // exactly as a multi-labelled node contributes to three per-label node counts. Summing the map
    // therefore overcounts the edge, which is why the accessor reads one pair at a time.
    let mut s = fresh(64);
    let txn = TxnId(1);
    s.begin(txn);
    let a = s.intern_token(Namespace::Label, "A").unwrap();
    let b = s.intern_token(Namespace::Label, "B").unwrap();
    let c = s.intern_token(Namespace::Label, "C").unwrap();
    let ty = s.intern_token(Namespace::RelType, "T").unwrap();
    let (start, _) = s.create_node(txn).unwrap();
    let (end, _) = s.create_node(txn).unwrap();
    s.set_node_labels(txn, start, &[a, b, c]).unwrap();
    s.add_label(txn, end, a).unwrap();
    s.create_rel(txn, ty, start, end).unwrap();
    s.commit(txn).unwrap();

    assert_matches_rescan(&mut s);
    for label in [a, b, c] {
        assert_eq!(
            s.rel_count_for_start_label_type(label, ty),
            1,
            "each of the start node's labels gets its own entry"
        );
    }
    assert_eq!(s.rel_count_for_type_end_label(ty, a), 1);
    assert_eq!(
        s.rel_count_for_type_end_label(ty, b),
        0,
        "end carries only A"
    );
    let start_side_sum: u64 = s.statistics().rels_per_start_label_type.values().sum();
    assert_eq!(
        start_side_sum, 3,
        "the sum over labels overcounts the single edge threefold — read one pair at a time"
    );
}

#[test]
fn adding_a_label_rekeys_every_incident_relationship() {
    // The expensive case, and the one an incremental counter is easiest to get wrong: labelling a node
    // moves the contribution of ALL its edges. Both directions are covered — the node under test is the
    // start of some edges and the end of others.
    let mut s = fresh(256);
    let txn = TxnId(1);
    s.begin(txn);
    let old = s.intern_token(Namespace::Label, "OLD").unwrap();
    let new = s.intern_token(Namespace::Label, "NEW").unwrap();
    let ty = s.intern_token(Namespace::RelType, "T").unwrap();
    let (hub, _) = s.create_node(txn).unwrap();
    s.add_label(txn, hub, old).unwrap();
    let others: Vec<u64> = (0..4).map(|_| s.create_node(txn).unwrap().0).collect();
    // Two edges out of the hub, two into it.
    s.create_rel(txn, ty, hub, others[0]).unwrap();
    s.create_rel(txn, ty, hub, others[1]).unwrap();
    s.create_rel(txn, ty, others[2], hub).unwrap();
    s.create_rel(txn, ty, others[3], hub).unwrap();
    s.commit(txn).unwrap();

    assert_eq!(s.rel_count_for_start_label_type(old, ty), 2);
    assert_eq!(s.rel_count_for_type_end_label(ty, old), 2);
    assert_eq!(s.rel_count_for_start_label_type(new, ty), 0);

    let t2 = TxnId(2);
    s.begin(t2);
    s.add_label(t2, hub, new).unwrap();
    s.commit(t2).unwrap();

    assert_matches_rescan(&mut s);
    assert_eq!(
        s.rel_count_for_start_label_type(new, ty),
        2,
        "the new label must inherit the hub's out-edges"
    );
    assert_eq!(
        s.rel_count_for_type_end_label(ty, new),
        2,
        "and its in-edges"
    );
    assert_eq!(
        s.rel_count_for_start_label_type(old, ty),
        2,
        "the old label keeps its entries — the node still carries it"
    );
}

#[test]
fn removing_a_label_rekeys_every_incident_relationship() {
    let mut s = fresh(256);
    let txn = TxnId(1);
    s.begin(txn);
    let keep = s.intern_token(Namespace::Label, "KEEP").unwrap();
    let drop = s.intern_token(Namespace::Label, "DROP").unwrap();
    let ty = s.intern_token(Namespace::RelType, "T").unwrap();
    let (hub, _) = s.create_node(txn).unwrap();
    s.set_node_labels(txn, hub, &[keep, drop]).unwrap();
    let (a, _) = s.create_node(txn).unwrap();
    let (b, _) = s.create_node(txn).unwrap();
    s.create_rel(txn, ty, hub, a).unwrap();
    s.create_rel(txn, ty, b, hub).unwrap();
    s.commit(txn).unwrap();
    assert_eq!(s.rel_count_for_start_label_type(drop, ty), 1);
    assert_eq!(s.rel_count_for_type_end_label(ty, drop), 1);

    let t2 = TxnId(2);
    s.begin(t2);
    s.remove_label(t2, hub, drop).unwrap();
    s.commit(t2).unwrap();

    assert_matches_rescan(&mut s);
    assert_eq!(
        s.rel_count_for_start_label_type(drop, ty),
        0,
        "the removed label must shed its edges"
    );
    assert_eq!(s.rel_count_for_type_end_label(ty, drop), 0);
    assert_eq!(
        s.rel_count_for_start_label_type(keep, ty),
        1,
        "the retained label is untouched"
    );
    assert_eq!(s.rel_count_for_type_end_label(ty, keep), 1);
}

#[test]
fn a_label_change_ignores_tombstoned_relationships() {
    // A deleted relationship already shed its contribution at `delete_rel`. Re-keying it on a later
    // label change would credit the new label with an edge that no longer exists — a drift the re-scan
    // oracle catches because it skips tombstones too.
    let mut s = fresh(256);
    let txn = TxnId(1);
    s.begin(txn);
    let old = s.intern_token(Namespace::Label, "OLD").unwrap();
    let new = s.intern_token(Namespace::Label, "NEW").unwrap();
    let ty = s.intern_token(Namespace::RelType, "T").unwrap();
    let (hub, _) = s.create_node(txn).unwrap();
    s.add_label(txn, hub, old).unwrap();
    let (a, _) = s.create_node(txn).unwrap();
    let (b, _) = s.create_node(txn).unwrap();
    let (live_rel, _) = s.create_rel(txn, ty, hub, a).unwrap();
    let (doomed, _) = s.create_rel(txn, ty, hub, b).unwrap();
    s.commit(txn).unwrap();

    let t2 = TxnId(2);
    s.begin(t2);
    s.delete_rel(t2, doomed).unwrap();
    s.commit(t2).unwrap();
    assert_matches_rescan(&mut s);

    let t3 = TxnId(3);
    s.begin(t3);
    s.add_label(t3, hub, new).unwrap();
    s.commit(t3).unwrap();

    assert_matches_rescan(&mut s);
    assert_eq!(
        s.rel_count_for_start_label_type(new, ty),
        1,
        "only the surviving edge may be re-keyed onto the new label"
    );
    let _ = live_rel;
}

#[test]
fn a_rolled_back_create_leaves_the_counters_untouched() {
    let mut s = fresh(256);
    let (user, _article, likes, _users, _articles) = asymmetric_corpus(&mut s);
    let before_start = s.rel_count_for_start_label_type(user, likes);
    let before_maps = s.statistics().rels_per_start_label_type.clone();

    let txn = TxnId(9);
    s.begin(txn);
    let (extra, _) = s.create_node(txn).unwrap();
    s.add_label(txn, extra, user).unwrap();
    s.create_rel(txn, likes, extra, extra).unwrap();
    s.rollback(txn).unwrap();

    assert_matches_rescan(&mut s);
    assert_eq!(
        s.rel_count_for_start_label_type(user, likes),
        before_start,
        "an aborted create must not leave the counters incremented"
    );
    assert_eq!(s.statistics().rels_per_start_label_type, before_maps);
}

#[test]
fn a_rolled_back_label_change_leaves_the_counters_untouched() {
    let mut s = fresh(256);
    let (_user, _article, likes, users, _articles) = asymmetric_corpus(&mut s);
    let other = {
        let txn = TxnId(2);
        s.begin(txn);
        let t = s.intern_token(Namespace::Label, "OTHER").unwrap();
        s.commit(txn).unwrap();
        t
    };
    let before = s.statistics().rels_per_start_label_type.clone();

    let txn = TxnId(3);
    s.begin(txn);
    s.add_label(txn, users[0], other).unwrap();
    s.rollback(txn).unwrap();

    assert_matches_rescan(&mut s);
    assert_eq!(
        s.rel_count_for_start_label_type(other, likes),
        0,
        "an aborted label change must not leave its re-keying behind"
    );
    assert_eq!(s.statistics().rels_per_start_label_type, before);
}

// =================================================================================================
// Durability
// =================================================================================================

#[test]
fn counters_persist_across_a_clean_reopen() {
    let mut s = fresh(256);
    let (user, article, likes, _u, _a) = asymmetric_corpus(&mut s);
    assert_non_vacuous(&s);
    let want = s.statistics().rels_per_start_label_type.clone();
    let want_end = s.statistics().rels_per_type_end_label.clone();

    let (device, wal) = into_parts(s);
    let mut reopened = RecordStore::open(device, wal, 256).expect("reopen");

    assert_eq!(reopened.statistics().rels_per_start_label_type, want);
    assert_eq!(reopened.statistics().rels_per_type_end_label, want_end);
    assert_eq!(reopened.rel_count_for_start_label_type(user, likes), 12);
    assert_eq!(reopened.rel_count_for_type_end_label(likes, article), 12);
    assert_matches_rescan(&mut reopened);
}

#[test]
fn counters_are_exact_after_a_no_force_crash() {
    let mut s = fresh(256);
    let (user, article, likes, _u, _a) = asymmetric_corpus(&mut s);
    assert_non_vacuous(&s);

    let mut recovered = recover_no_force(&s);
    assert_matches_rescan(&mut recovered);
    assert_eq!(recovered.rel_count_for_start_label_type(user, likes), 12);
    assert_eq!(recovered.rel_count_for_type_end_label(likes, article), 12);
}

// =================================================================================================
// Backfill and backward compatibility
// =================================================================================================

#[test]
fn a_catalogue_image_without_the_projections_decodes_them_empty() {
    // The append-only image rule: a pre-#856 image ends where these two blocks would start, so both
    // must decode empty rather than failing to load. Truncating a real image at that boundary is a
    // faithful stand-in for an older database's bytes.
    use graphus_storage::meta::Statistics;
    let mut s = fresh(256);
    let (user, _article, likes, _u, _a) = asymmetric_corpus(&mut s);
    let full = s.statistics().encode();
    let decoded = Statistics::decode(&full).expect("a full image round-trips");
    assert!(decoded.has_directional_rel_counts());

    // Re-encode the same catalogue with both projections emptied: that image is byte-identical to what
    // a pre-#856 build would have written, since the two blocks are last and encode as a zero count.
    let mut without = s.statistics().clone();
    without.rels_per_start_label_type.clear();
    without.rels_per_type_end_label.clear();
    let legacy = without.encode();
    let decoded = Statistics::decode(&legacy).expect("an image without the projections must load");
    assert!(
        !decoded.has_directional_rel_counts(),
        "the projections must decode empty, not be invented"
    );
    // Everything else survives, so the truncation cost nothing but the new blocks.
    assert_eq!(decoded.rel_count_for_type(likes), 12);
    assert_eq!(decoded.node_count_for_label(user), 6);
}

#[test]
fn the_backfill_converges_an_empty_projection_onto_exact_counters() {
    let mut s = fresh(256);
    let (user, article, likes, _u, _a) = asymmetric_corpus(&mut s);
    let want_start = s.statistics().rels_per_start_label_type.clone();
    let want_end = s.statistics().rels_per_type_end_label.clone();
    assert!(!want_start.is_empty(), "non-vacuity");

    // Simulate a database that predates the projections: clear them, then backfill.
    s.clear_directional_rel_counts_for_test();
    assert!(!s.has_directional_rel_counts());

    s.backfill_directional_rel_counts().expect("backfill");

    assert_eq!(
        s.statistics().rels_per_start_label_type,
        want_start,
        "the backfill must reproduce the incrementally-maintained counters exactly"
    );
    assert_eq!(s.statistics().rels_per_type_end_label, want_end);
    assert_matches_rescan(&mut s);
    assert_eq!(s.rel_count_for_start_label_type(user, likes), 12);
    assert_eq!(s.rel_count_for_type_end_label(likes, article), 12);
}

#[test]
fn the_backfill_skips_tombstoned_relationships() {
    // The backfill must count the same population the incremental path maintains — live versions only.
    // If it counted tombstones the two would disagree and the equality above would be meaningless.
    let mut s = fresh(256);
    let (user, _article, likes, users, _a) = asymmetric_corpus(&mut s);
    let txn = TxnId(2);
    s.begin(txn);
    let victim = s.incident_rels(users[0]).unwrap()[0];
    s.delete_rel(txn, victim).unwrap();
    s.commit(txn).unwrap();

    let incremental = s.statistics().rels_per_start_label_type.clone();
    let (recount, _) = s.recount_directional_rel_counts().expect("recount");
    assert_eq!(
        incremental, recount,
        "a tombstoned relationship must be absent from both"
    );
    assert_eq!(s.rel_count_for_start_label_type(user, likes), 11);
}

#[test]
fn has_directional_counts_distinguishes_absent_from_a_genuine_zero() {
    // A bare zero cannot tell "never backfilled" from "no such relationship", and a consumer that
    // confused the two would estimate a fan-out of nothing. A graph with nodes but no relationships is
    // a genuine zero, and must still report no counters — there is nothing to distinguish it from an
    // un-backfilled catalogue at the map level, which is precisely why the CONSUMER must fall back in
    // both cases (task #886).
    let mut s = fresh(64);
    let txn = TxnId(1);
    s.begin(txn);
    let l = s.intern_token(Namespace::Label, "L").unwrap();
    let ty = s.intern_token(Namespace::RelType, "T").unwrap();
    let (n, _) = s.create_node(txn).unwrap();
    s.add_label(txn, n, l).unwrap();
    s.commit(txn).unwrap();
    assert!(
        !s.has_directional_rel_counts(),
        "no relationships, no counters"
    );
    assert_eq!(s.rel_count_for_start_label_type(l, ty), 0);

    // Add one relationship and the flag flips — so the flag really tracks content, not a constant.
    let t2 = TxnId(2);
    s.begin(t2);
    s.create_rel(t2, ty, n, n).unwrap();
    s.commit(t2).unwrap();
    assert!(s.has_directional_rel_counts());
}
