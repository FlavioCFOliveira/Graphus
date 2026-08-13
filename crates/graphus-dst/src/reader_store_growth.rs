//! Focused deterministic reproducer for **an off-thread reader failing a legitimate read while a
//! concurrent writer grows the store** (`rmp` #721).
//!
//! # The defect
//!
//! A read served by the off-thread reader pool (`rmp` #336/#543) intermittently failed with an
//! internal server error — `Neo.DatabaseError.General.UnknownError: Prop store page 321 not
//! allocated` (and the `Rel` variant) — whenever a writer was committing underneath it. On an idle
//! 16-core host, `examples/product-recommendations` measured 2–5 of every 1500 reads per rung
//! (~0.2–0.3%) failing this way in the MIXED arm, while the writers-off CONTROL arm of the very same
//! ladder was 100% clean at every rung.
//!
//! The root cause is an **inconsistent pair**: the reader's *location oracle* was a SNAPSHOT while the
//! data it navigates is LIVE.
//!
//! - `RecordStore::capture_read_meta` froze each store's record-id → device-page **map**
//!   (`device_pages`) into the reader's `MetaSnapshot`.
//! - But `RecordStore::read_view` shares the page cache **live** (`Arc::clone(&self.pool)`), so record
//!   *contents* are read at their latest in-place-updated state and MVCC-filtered afterwards.
//!
//! A chain walk FOLLOWS POINTERS (`node.first_rel`, `node.first_prop`, `prop.next_prop`,
//! `HeapBlock::next_block`) read out of that live content. A concurrently committed writer PREPENDS its
//! new record to the chain head — so the reader legitimately reads a pointer to a record living on a
//! page allocated AFTER its snapshot, indexes past the end of its frozen page list, and the walk dies
//! with `"{kind} store page N not allocated"`.
//!
//! The old safety argument (`capture_read_meta`'s own doc comment) was: *"the writer only APPENDS to
//! `device_pages` and ADVANCES `high_water`, so a reader scanning `1..high_water` only ever indexes
//! already-existing entries; any id allocated later … is invisible anyway"*. That is true for **scans**
//! and false for **chain walks** — and the "invisible anyway" clause cannot save it, because
//! **visibility is decided ABOVE the location oracle**: a record the reader cannot LOCATE is never
//! filtered. The walk dies first.
//!
//! # Why this needs its own deterministic reproducer
//!
//! The race window is a *single read statement*: the reader captures its `MetaSnapshot` at dispatch
//! (`TxnCoordinator::read_task_inputs`) and then executes off-thread while the engine thread keeps
//! committing. The generic [`crate::harness`] runs each statement atomically to completion on one
//! cooperative thread, so it can never place a commit *inside* a read — it is structurally blind to
//! this defect (the same reason [`crate::freelist_reuse`] and [`crate::selfloop_churn`] exist).
//!
//! So this module drives [`graphus_storage::RecordStore`] directly and reproduces the exact ORDERING —
//! no threads needed, because the bug is about ordering, not parallelism:
//!
//! 1. commit a hub, a leaf and a property — the **survivors**, committed strictly BEFORE the reader's
//!    snapshot, which the reader must still see afterwards;
//! 2. **capture the reader's view** (`read_view()`) — this is the off-thread reader's dispatch instant;
//! 3. the writer commits a paced mixed workload that **grows every store**: `CREATE (u)-[:PURCHASED]->(p)`
//!    (rel + node growth) and `SET p.hot = …` (prop + strings growth), each `SET` prepending a fresh
//!    property version to the hub's chain — the same shape `examples/product-recommendations` runs;
//! 4. drive a **traversal battery** through the pre-growth view and assert the two oracles below.
//!
//! # The oracles (both have teeth)
//!
//! 1. **Location** (`rmp` #721 itself) — NO read may fail. A `Storage("… store page N not allocated")`
//!    is the defect. Pre-fix this fires; post-fix it does not.
//! 2. **Isolation** (the ACID obligation the fix must not trade away) — making the location oracle LIVE
//!    must NOT make post-snapshot data VISIBLE. The reader filters everything it locates through
//!    `graphus_txn::is_visible_via` against its own snapshot timestamp and its own cloned `CommitRegistry`,
//!    exactly as `graphus-cypher`'s `VisCtx` does, and must see **exactly** the pre-snapshot committed
//!    state — not one record more. A fix that made the reader see the writer's fresh commits would
//!    trade an internal error for a snapshot-isolation breach, which is strictly worse.
//!
//! The fix (`rmp` #721) makes the page map a live, append-only, lock-free [`graphus_storage::PageMap`]
//! shared `Arc`-wise with every reader, while `high_water` stays SNAPSHOTTED (it bounds scans). That is
//! sound precisely because the map is **monotone**: pages are only ever appended, never remapped,
//! removed, or undone by a rollback (`rmp` #239). Locating a post-snapshot record is harmless;
//! *showing* it would not be — and oracle 2 proves the fix does not.

use graphus_core::{TxnId, Value};
use graphus_io::MemBlockDevice;
use graphus_storage::{NULL_ID, Namespace, RecordStore};
use graphus_txn::{Snapshot, is_visible_via};
use graphus_wal::{MemLogSink, WalManager};

use crate::rng::DetRng;

/// The store type the reproducer drives: the record store over the in-memory DST device + log.
type Store = RecordStore<MemBlockDevice, MemLogSink>;

/// What one run of [`run_reader_vs_store_growth`] observed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReaderGrowthReport {
    /// The seed this run replays from.
    pub seed: u64,
    /// How many transactions the writer committed underneath the in-flight reader.
    pub writer_commits: u64,
    /// How many device pages the writer added across all four stores *after* the reader's snapshot —
    /// the run is **vacuous** if this is 0 (the reader would never index past its frozen map), so the
    /// oracle asserts it is positive. This is the non-vacuity teeth.
    pub pages_grown_after_snapshot: u64,
    /// Reads through the pre-growth view that failed with a storage error. **Must be empty**: each one
    /// is an internal server error on a legitimate read (`rmp` #721).
    pub read_failures: Vec<String>,
    /// Records the reader could LOCATE and that its snapshot filter judged VISIBLE, but which were
    /// committed AFTER its snapshot. **Must be empty**: a live location oracle must not leak
    /// post-snapshot data into a visible result (snapshot isolation).
    pub visibility_leaks: Vec<String>,
    /// Survivors (committed strictly before the reader's snapshot) the reader could no longer see.
    /// **Must be empty**: committed data must never become unreachable.
    pub lost_survivors: Vec<String>,
}

impl ReaderGrowthReport {
    /// Whether every oracle held.
    #[must_use]
    pub fn ok(&self) -> bool {
        self.read_failures.is_empty()
            && self.visibility_leaks.is_empty()
            && self.lost_survivors.is_empty()
            && self.pages_grown_after_snapshot > 0
    }

    /// A short, reproducible detail line.
    #[must_use]
    pub fn detail(&self) -> String {
        format!(
            "seed {} · {} writer commits · +{} store pages after the snapshot · {} read failures · \
             {} visibility leaks · {} lost survivors",
            self.seed,
            self.writer_commits,
            self.pages_grown_after_snapshot,
            self.read_failures.len(),
            self.visibility_leaks.len(),
            self.lost_survivors.len()
        )
    }
}

fn fresh() -> Store {
    let device = MemBlockDevice::new(0);
    let wal = WalManager::create(MemLogSink::new()).expect("create wal");
    // A pool big enough that the working set stays resident: the defect is about the page MAP, not
    // about eviction, and a cold pool would only add noise.
    RecordStore::create(device, wal, 1024, 1).expect("create store")
}

/// Runs the deterministic `rmp` #721 reproducer at `seed`.
///
/// Everything is a pure function of the seed: the same seed replays the same commits, the same store
/// growth and the same verdict.
#[must_use]
#[allow(clippy::too_many_lines)]
pub fn run_reader_vs_store_growth(seed: u64) -> ReaderGrowthReport {
    let mut rng = DetRng::new(seed);
    let s = fresh();

    // ---------------------------------------------------------------------------------------------
    // Setup: the SURVIVORS — committed strictly before the reader's snapshot.
    // ---------------------------------------------------------------------------------------------
    let txn = TxnId(1);
    s.begin(txn);
    let rel_type = s.intern_token(Namespace::RelType, "PURCHASED").unwrap();
    let hot = s.intern_token(Namespace::PropKey, "hot").unwrap();
    let tag = s.intern_token(Namespace::PropKey, "tag").unwrap();
    let (hub, _) = s.create_node(txn).unwrap();
    let (leaf, _) = s.create_node(txn).unwrap();
    let (survivor_rel, _) = s.create_rel(txn, rel_type, hub, leaf).unwrap();
    s.set_node_property_value(txn, hub, hot, &Value::Integer(0))
        .unwrap();
    // An overflow (heap-backed) value, so the reader's battery also exercises the `strings` store's
    // page map via `HeapBlock::next_block`.
    s.set_node_property_value(txn, hub, tag, &Value::String("s".repeat(500)))
        .unwrap();
    s.commit(txn).unwrap();

    // ---------------------------------------------------------------------------------------------
    // (2) THE READER DISPATCHES. This is the instant `TxnCoordinator::read_task_inputs` captures a
    //     `StoreReadView` + the MVCC snapshot + a clone of the `CommitRegistry`, and hands them to a
    //     reader-pool worker. Everything the writer does below happens WHILE this read is in flight.
    // ---------------------------------------------------------------------------------------------
    let view = s.read_view();
    // A reader ticket distinct from every writer below.
    let reader_snapshot = Snapshot::new(TxnId(u64::MAX), s.snapshot_ts());
    let registry = s.commit_registry_snapshot();
    let pages_before = s.store_page_count();

    // The survivors as the reader must still see them, and the id watermark that separates
    // "committed before the snapshot" from "committed after it".
    let rel_hw_at_snapshot = view
        .meta()
        .store(graphus_storage::StoreKind::Rel)
        .high_water;

    // ---------------------------------------------------------------------------------------------
    // (3) THE WRITER COMMITS UNDERNEATH THE IN-FLIGHT READER — the paced mixed OLTP workload of
    //     `examples/product-recommendations`: `CREATE (u)-[:PURCHASED]->(p)` and
    //     `SET p.hot = coalesce(p.hot,0)+1`. Every commit grows a store; the rel/prop chain heads on
    //     the hub are re-pointed at records the reader's frozen map never saw.
    // ---------------------------------------------------------------------------------------------
    let mut writer_commits = 0u64;
    for i in 0..600u64 {
        let txn = TxnId(1000 + i);
        s.begin(txn);
        // A purchase edge on the hub: prepends to the hub's incidence chain (rel + node growth).
        let (buyer, _) = s.create_node(txn).unwrap();
        s.create_rel(txn, rel_type, hub, buyer).unwrap();
        // A hot-counter bump on the hub. `rmp` #967 RE-ARM: this used to be the prop-store growth
        // driver, because per-value MVCC allocated a fresh record per `SET` and re-pointed
        // `hub.first_prop` at it. It no longer does — the same key is now rewritten IN PLACE and
        // allocates nothing — so on its own this loop would leave the prop store one page wide and
        // the `Prop store page N not allocated` hazard would never be exercised. The counter bump
        // stays (it is what the isolation oracle below reads), and a DISTINCT key per iteration is
        // added beside it to restore the growth. `pages_grown_after_snapshot` below is the
        // non-vacuity control that the store really did grow.
        s.set_node_property_value(txn, hub, hot, &Value::Integer(i as i64 + 1))
            .unwrap();
        let fresh_key = s
            .intern_token(Namespace::PropKey, &format!("k{i}"))
            .unwrap();
        s.set_node_property_value(txn, hub, fresh_key, &Value::Integer(i as i64))
            .unwrap();
        // Occasionally churn the overflow value too, so the `strings` store grows as well.
        if rng.below(4) == 0 {
            s.set_node_property_value(
                txn,
                hub,
                tag,
                &Value::String("s".repeat(500 + (i % 97) as usize)),
            )
            .unwrap();
        }
        s.commit(txn).unwrap();
        writer_commits += 1;
    }
    let pages_grown_after_snapshot = s.store_page_count().saturating_sub(pages_before);

    // ---------------------------------------------------------------------------------------------
    // (4) THE READER'S TRAVERSAL BATTERY, driven through the view it captured BEFORE all of that.
    // ---------------------------------------------------------------------------------------------
    let mut read_failures: Vec<String> = Vec::new();
    let mut visibility_leaks: Vec<String> = Vec::new();
    let mut lost_survivors: Vec<String> = Vec::new();

    // -- the incidence chain (the `Rel store page N not allocated` face) --------------------------
    match view.incident_rels(hub) {
        Err(e) => read_failures.push(format!("incident_rels(hub): {e}")),
        Ok(rels) => {
            // ORACLE 1 (location): every id the walk reports must also be READABLE.
            for id in &rels {
                if let Err(e) = view.rel(*id) {
                    read_failures.push(format!("rel({id}): {e}"));
                }
            }
            // ORACLE 2 (isolation): filtering by the reader's own snapshot must yield EXACTLY the
            // survivor — the 600 edges the writer committed after the snapshot are LOCATABLE (that is
            // the fix) but must be INVISIBLE (that is snapshot isolation).
            let visible: Vec<u64> = rels
                .iter()
                .copied()
                .filter(|id| {
                    // Through the `rmp` #1069 door. The reader's cloned in-memory registry never
                    // faults; a fault would be a defect in the door, so this oracle panics rather
                    // than quietly dropping the edge from the visible set it is asserting over.
                    view.rel(*id).is_ok_and(|r| {
                        is_visible_via(
                            &registry,
                            reader_snapshot,
                            r.mvcc.created_ts,
                            r.mvcc.expired_ts,
                        )
                        .expect("resolve rel stamp")
                    })
                })
                .collect();
            for id in &visible {
                if *id >= rel_hw_at_snapshot {
                    visibility_leaks.push(format!(
                        "rel {id} was committed after the reader's snapshot (rel high-water \
                         {rel_hw_at_snapshot}) yet is visible to it"
                    ));
                }
            }
            if !visible.contains(&survivor_rel) {
                lost_survivors.push(format!(
                    "the pre-snapshot committed edge {survivor_rel} is no longer visible to the reader"
                ));
            }
            if visible.len() != 1 {
                visibility_leaks.push(format!(
                    "the reader's snapshot must see exactly 1 incident edge, saw {}",
                    visible.len()
                ));
            }
        }
    }

    // -- the property chain + the overflow heap (the `Prop`/`Strings` faces) ----------------------
    // ORACLE 1 (location): EVERY candidate the superset read reports must decode — including its
    // overflow chain, which walks the `strings` store's page map. After `rmp` #967 the candidates are
    // the live cells PLUS the entity's undo history, and it is the history that names the overflow
    // chains allocated after the reader's snapshot — so decoding only the cells would walk one chain
    // and miss the hazard this scenario exists to catch.
    match view.superset_scan_node_properties(hub) {
        Err(e) => read_failures.push(format!("superset_scan_node_properties(hub): {e}")),
        Ok(props) => {
            for c in props.candidates() {
                if let Err(e) = view.decode_property_value(c.type_tag, c.value_inline) {
                    read_failures.push(format!("decode_property_value({:?}): {e}", c.source));
                }
            }
        }
    }
    // ORACLE 2 (isolation), through the DECISION-polarity read — the production rule, rather than a
    // hand-rolled `is_visible_via` fold over cell stamps, which `D-property-visibility` retired.
    match view.decision_scan_node_properties(hub, reader_snapshot) {
        Err(e) => read_failures.push(format!("decision_scan_node_properties(hub): {e}")),
        Ok(decided) => {
            let mut visible_hot: Option<Value> = None;
            let mut visible_tag = 0u32;
            for c in decided.visible_versions() {
                let value = match view.decode_property_value(c.type_tag, c.value_inline) {
                    Ok(v) => v,
                    Err(e) => {
                        read_failures.push(format!("decode_property_value({:?}): {e}", c.source));
                        continue;
                    }
                };
                // The only `hot` the reader may see is the pre-snapshot 0.
                if c.key == hot {
                    visible_hot = Some(value);
                } else if c.key == tag {
                    visible_tag += 1;
                }
            }
            match visible_hot {
                None => lost_survivors
                    .push("the pre-snapshot committed property `hot` is no longer visible".into()),
                Some(Value::Integer(0)) => {}
                Some(other) => visibility_leaks.push(format!(
                    "the reader's snapshot must see `hot = 0` (its pre-snapshot value), saw {other:?} \
                     — a post-snapshot version leaked into a visible result"
                )),
            }
            if visible_tag != 1 {
                visibility_leaks.push(format!(
                    "the reader's snapshot must see exactly 1 visible `tag`, saw {visible_tag}"
                ));
            }
        }
    }

    // -- the raw chain walk the reader pool performs hop-by-hop -----------------------------------
    // `incident_rels` above is the batched form; walk the chain by hand too, so a failure to LOCATE an
    // intermediate link (which the batched walk might mask) is caught.
    let mut cur = match view.node(hub) {
        Ok(n) => n.first_rel,
        Err(e) => {
            read_failures.push(format!("node(hub): {e}"));
            NULL_ID
        }
    };
    let mut hops = 0u64;
    while cur != NULL_ID && hops < 10_000 {
        hops += 1;
        match view.rel(cur) {
            Ok(r) => {
                cur = if r.start_node == hub {
                    r.start_next_rel
                } else {
                    r.end_next_rel
                }
            }
            Err(e) => {
                read_failures.push(format!("hand-walk hop {hops} at rel {cur}: {e}"));
                break;
            }
        }
    }

    // -- the scan path: `high_water` is SNAPSHOTTED, so a scan must NOT be chased by the writer -----
    match view.scan_rel_ids() {
        Err(e) => read_failures.push(format!("scan_rel_ids: {e}")),
        Ok(ids) => {
            for id in ids {
                if id >= rel_hw_at_snapshot {
                    visibility_leaks.push(format!(
                        "scan_rel_ids returned id {id} at or above the snapshot's rel high-water \
                         {rel_hw_at_snapshot} — the scan bound must stay snapshotted"
                    ));
                }
            }
        }
    }

    ReaderGrowthReport {
        seed,
        writer_commits,
        pages_grown_after_snapshot,
        read_failures,
        visibility_leaks,
        lost_survivors,
    }
}
