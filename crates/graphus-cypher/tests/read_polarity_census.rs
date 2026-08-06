//! **Read-polarity census** (`rmp` task #905) — the enforced half of the rule
//! [`graphus_storage::scan_polarity`] states, plus the reviewer-facing record of every raw read this
//! crate performs **on purpose**.
//!
//! # Why this file exists
//!
//! Three CRITICAL defects (`rmp` tasks #902, #904 and, before them, #771) were one mistake: a read of
//! raw physical state used where a different polarity's answer was owed. The property-chain axis is now
//! separated in the type system — `RecordStore::decision_scan_*` cannot be called without a
//! `Snapshot`, and the `DecidedProperties` it returns has no other constructor, so a validation helper
//! cannot be handed a raw chain. The **label** axis cannot be separated the same way: the live-word
//! read (`RecordStore::node_labels`), the candidate superset (`node_label_superset`) and the
//! snapshot-exact resolver (`label_bitmap_at`) all deal in the same `u64` bitmap and the same
//! `Vec<u32>` token list, and only the last is enforced by its signature (it demands a
//! `(Snapshot, &CommitRegistry)` pair). That axis is held here instead.
//!
//! # What a failure of this file means
//!
//! It does **not** mean the new code is wrong. It means a polarity-sensitive read appeared, or moved,
//! and nobody classified it. Classify it against
//! [`graphus_storage::scan_polarity`]'s three obligations, then either fix the read or add it to the
//! table below **with its justification**. An entry with no justification is not an entry.
//!
//! # The reviewer-facing census: raw reads that are deliberately correct
//!
//! ## Where a property's old values live since `rmp` #967
//!
//! The property path moved onto the unified undo chain. An overwrite is now written **in place** and
//! the superseded value descends onto the owning entity's undo chain, so:
//!
//! * `SupersetProperties::cells_ignoring_history()` is the **current image** — no longer a superset;
//! * `SupersetProperties::candidates()` is the **superset** — cells plus every retained historical
//!   value;
//! * `RecordStore::decision_scan_*` / `StoreReadView::decision_scan_*` is the **decision** read, and
//!   it is the only way to obtain a `DecidedProperties`.
//!
//! That renamed every call site's polarity question, which is why this census names the *current
//! image* reads explicitly below and counts them (`the_census_of_current_image_property_reads_is_complete`).
//!
//! ## Superset — index population (a hole is unrecoverable, an extra entry is dropped by the re-check)
//!
//! * `TxnCoordinator::index_one_node`, `index_one_node_spatial`, `index_one_node_text`,
//!   `index_one_node_bitmap` (and their `index_one_rel*` twins) — each indexes **every** property
//!   candidate with no visibility filter (`rmp` #766, #773, #779), through the decoded superset
//!   `superset_scan_*_property_values`, which since #967 yields cells **and** undo-chain history.
//! * `TxnCoordinator::index_one_node_composite` / `index_one_rel_composite` — the same superset, but
//!   read through `stamped_candidates`, which rebuilds each candidate's validity interval from the
//!   undo chain. A composite index indexes *tuples*, and a tuple is observable only if its members
//!   were current at one common instant, so the intervals cannot be dropped: without them the build
//!   must either collapse to one value per key (losing the candidate that catches a committed
//!   duplicate on a NODE KEY / REL KEY — `rmp` #683 / #765) or emit the `O(V^k)` Cartesian product.
//!   Pinned by `a_composite_refill_reads_the_superset_with_intervals`.
//! * Every one of them gates label membership on the live-OR-retained union
//!   `RecordStore::node_label_superset` (`rmp` #904). Both axes are required: a seek's re-check can
//!   remove a candidate but never resurrect one. Pinned by
//!   `every_index_refill_gates_on_the_label_superset` below.
//! * `TxnCoordinator::index_one_rel*` gate on `RelRecord::type_id`, read live and **not** widened,
//!   because a relationship's type is fixed at creation and no statement changes it; there is no older
//!   version for a superset to recover.
//!
//! ## Current image — structures that hold ONE value per entity and cannot union versions
//!
//! * `TxnCoordinator::index_one_node_fulltext` / `index_one_rel_fulltext` — a full-text **document** is
//!   indexed whole and `fulltext_query` re-checks a hit's visibility and current label but never its
//!   terms, so a term unioned in from an older version is a wrong row the consumer cannot drop. This
//!   build has therefore never been a superset; what makes it safe is the `rmp` #778 option-(b) gate,
//!   which refuses to bake at all while an in-flight writer holds the newest version of a covered key.
//!   It reads `cells_ignoring_history` for both halves — the bake, and the gate, which needs the EMPTY
//!   cells a `REMOVE` leaves behind and `candidates()` drops.
//! * `TxnCoordinator::index_one_node_vector` / `index_one_rel_vector` — an HNSW graph holds one
//!   embedding per entity, and `rmp` #780 already settled that a conflicted entity is left out
//!   entirely rather than indexed at an older version. Same read, same gate.
//! * `TxnCoordinator::rebuild_columns` — see "Live word" below; its witness names a `props.store`
//!   **cell**, and an undo-store id read as a cell id is not a stale row, it is a wrong one.
//!
//! ## Decision — the query read path
//!
//! * `graphus_cypher::read_source::{read_node_props, read_rel_props, read_node_prop_one,
//!   read_rel_prop_one}` and their `RecordStoreGraph` twins — these resolve at the reader's snapshot
//!   through `decision_scan_*`. Before `rmp` #967 they read the superset and folded `is_visible` over
//!   each record themselves, which was sound only while every version of a key was a cell with its own
//!   MVCC stamps; `D-property-visibility` made the undo chain the sole oracle, so the fold moved into
//!   the storage-side walk. Both the inline `RecordStore` path and the off-thread `StoreReadView` path
//!   go through the same seam method for exactly that reason (`rmp` #755/#768/#769/#770). Pinned by
//!   `the_query_read_path_resolves_at_its_snapshot` and
//!   `both_read_sources_resolve_properties_through_the_same_seam`.
//!
//! ## Conservative — pruning structures (an excluded range disappears before any re-check runs)
//!
//! * `TxnCoordinator::rebuild_zone_column` — a zone map prunes whole id ranges, and nothing rebuilds
//!   one afterwards, so it may never narrow on unproven state. It is a superset on **both** axes: the
//!   same `node_label_superset` label gate an index refill takes (`rmp` #904), and **every version** of
//!   the property rather than the chain head (`rmp` #958) — the head may belong to an open writer, and
//!   even when it is committed, a reader whose snapshot predates the overwrite still resolves the older
//!   version. Pinned by `a_pruning_rebuild_gates_on_the_label_superset` and
//!   `a_pruning_rebuild_summarizes_every_property_version`.
//! * The zone map's *consumer* is `RecordStoreGraph::zone_scan_eq`, and it is deliberately **not**
//!   listed under "live word" below: it performs no raw read at all. The pruning layer yields
//!   candidates and the statement seam decides them through `read_source::index_seek_eq_recheck`, i.e.
//!   `label_bitmap_at` + `is_visible`, exactly as every node equality seek does (`rmp` #958). Pinned by
//!   `the_zone_map_consumer_decides_through_the_shared_recheck`.
//!
//! ## Live word — write-path enforcement and total-fallback memoization
//!
//! * `RecordStoreGraph::note_predicate_write_preimage` / `reindex_node` /
//!   `enforce_constraints_for_node` (`record_graph.rs`) — the write path reads the node's **current**
//!   labels because the state it is announcing, indexing or enforcing against is the state it has just
//!   written. There is no snapshot to resolve against and no superset to widen to: the question is
//!   "what does this record say now". Pinned by
//!   `the_census_of_live_word_reads_in_record_graph_is_complete`.
//!   (These three names were wrong in this census until `rmp` #967's audit: it listed
//!   `note_node_predicate_write`, `reindex_node_bitmap` and `note_node_label_predicate_write`, two of
//!   which have never existed. Prose naming a function nothing checks is exactly how a census rots,
//!   which is why they are now asserted rather than listed.)
//!
//! ## Superset — SSI predicate announcement (`record_graph.rs`)
//!
//! * `RecordStoreGraph::rel_type_and_resolved_props` — the read behind `note_rel_property_preimage`
//!   and `note_rel_predicate_write_full`, whose output is an **rw-edge**, not a row. A *missing*
//!   marker is a lost edge and therefore a serializability hole; an *extra* marker is a spurious,
//!   retryable abort. That is superset polarity exactly, so the candidate superset is the right read
//!   — and after `rmp` #967 it is strictly **more** conservative than before (a key whose cell a
//!   `REMOVE` emptied now also announces its pre-removal value), never less. Pinned by
//!   `the_census_of_superset_property_reads_in_record_graph_is_complete`.
//! * `TxnCoordinator::rebuild_columns` (the columnar accelerator) reads the live word on purpose. The
//!   column is a **memoization with a total fallback**, not a candidate source: `columnar_scan`
//!   re-checks every candidate's visibility and label through `label_bitmap_at`, and a row the column
//!   does not hold — or holds staler than its witness allows — falls through to
//!   `read_node_prop_one`, the authoritative path. A hole therefore costs one property decode, never a
//!   row. That is what distinguishes it from an index refill, where a hole is a row no seek can
//!   resurrect.
//!
//! ## Decision — nothing re-checks the answer
//!
//! * `TxnCoordinator::validate_existing_against_constraint` /
//!   `validate_existing_rels_against_constraint` and the helpers they drive — every entity is filtered
//!   by `is_visible` and every value resolved through `decision_scan_*`. The one raw read that remains
//!   is the node's label word, decoded off the record the visibility filter has just read, and it is
//!   sound **only** while the `rmp` #902 guard refuses the DDL whenever another transaction holds
//!   uncommitted state. That coupling is pinned by
//!   `the_constraint_walks_raw_label_read_stays_coupled_to_the_902_guard`; if the guard is ever lifted,
//!   this read must become `label_bitmap_at`.
//!
//! ## Scope of this census
//!
//! It covers `graphus-cypher`, and — since `rmp` #967's audit — it covers `record_graph.rs` **as a
//! whole**, not only the handful of functions named above. It did not before, and the consequence was
//! immediate: `reindex_rel` resolved its values by folding first-occurrence-wins over
//! `superset_scan_rel_property_values`, which after #967 yields the candidate superset, so a
//! `REMOVE r.p` re-baked the pre-removal value into the relationship full-text index (a wrong row) and
//! back into the ANN graph (a phantom candidate that costs a genuine neighbour its row). That read sat
//! in no section of this file and was covered by no assertion, which is why it could happen at all.
//! `the_census_of_superset_property_reads_in_record_graph_is_complete` and
//! `per_write_index_maintenance_resolves_at_the_statement_snapshot` now hold that file.
//!
//! The `superset_scan_*` reads outside this crate are all
//! **offline or diagnostic** surfaces that hold no snapshot and answer no query: the consistency
//! checker (`graphus_storage::check`), the whole-graph dumper and bulk importer, the backup/restore
//! paths, and the DST oracles. They read the physical image on purpose, because the physical image is
//! precisely what they are there to inspect or copy. If a *query* path is ever added outside this
//! crate, extend the census to it rather than assuming the rule stops at the crate boundary.

const COORDINATOR: &str = include_str!("../src/coordinator.rs");
const RECORD_GRAPH: &str = include_str!("../src/record_graph.rs");
const READ_SOURCE: &str = include_str!("../src/read_source.rs");

/// Every raw read on the **property** axis, of whatever polarity, by the name it is called at a call
/// site: the decoded and undecoded superset scans, both `SupersetProperties` accessors, and the
/// stamped-superset helper.
///
/// A function that performs none of these resolves its property values through `decision_scan_*` or
/// through a helper that does — which, for anything that is not an index population, is the only
/// correct answer.
///
/// `.cells_ignoring_history()` belongs here as much as `.candidates()` does: since `rmp` #967 the
/// current image is not a superset either, and it is just as wrong in a decision path, because it
/// answers "what does the cell say now" rather than "what does this snapshot see".
const PROPERTY_AXIS_RAW_READS: &[&str] = &[
    "superset_scan_node_properties",
    "superset_scan_rel_properties",
    "superset_scan_node_property_values",
    "superset_scan_rel_property_values",
    ".candidates()",
    ".cells_ignoring_history()",
    "stamped_candidates(",
];

/// The raw reads on the **label** axis. Held here rather than in the type system because the live
/// word, the candidate superset and the snapshot-exact resolver all deal in the same `u64` bitmap.
const LABEL_AXIS_RAW_READS: &[&str] = &["node_label_superset"];

/// Every read that returns raw physical state, on either axis. A decision path must contain none of
/// them.
fn raw_reads() -> impl Iterator<Item = &'static &'static str> {
    PROPERTY_AXIS_RAW_READS
        .iter()
        .chain(LABEL_AXIS_RAW_READS.iter())
}

/// The reads that return the **current image** of the property axis (`rmp` #967): the live cells and
/// nothing else. Correct only where the structure being populated holds one value per entity and
/// nothing downstream can repair an extra one — never in a decision path, and never in a candidate
/// structure a later reader re-checks.
const CURRENT_IMAGE_PROPERTY_READS: &[&str] = &[".cells_ignoring_history()"];

/// The functions in `record_graph.rs` that may perform a raw **property**-axis read, each with the
/// reason it is correct there. Anything else performing one in that file fails the census.
const RECORD_GRAPH_RAW_PROPERTY_READERS: &[(&str, &str)] = &[(
    "rel_type_and_resolved_props",
    "SSI predicate ANNOUNCEMENT, not a population and not a decision: it feeds \
     `note_rel_property_preimage` / `note_rel_predicate_write_full`, whose output is an rw-EDGE, not \
     a row. A missing marker is a lost edge and therefore a serializability hole; an extra marker is \
     a spurious, retryable abort — superset polarity exactly. After `rmp` #967 the read is strictly \
     MORE conservative than before (a key whose cell a `REMOVE` emptied now also announces its \
     pre-removal value), never less",
)];

/// The functions in `record_graph.rs` that may read the **live** label word, each with its reason.
const RECORD_GRAPH_LIVE_WORD_READERS: &[(&str, &str)] = &[
    (
        "note_predicate_write_preimage",
        "announces the labels the node currently carries, BEFORE the mutation that changes them — the \
         pre-image IS the live word, and there is no snapshot to resolve it against",
    ),
    (
        "reindex_node",
        "per-write maintenance: the state being indexed is the state this statement has just written, \
         so the question is 'what does this record say now'",
    ),
    (
        "enforce_constraints_for_node",
        "write-path enforcement: the constraints that apply are the ones on the labels the node \
         carries after this statement's write. Fails CLOSED on a read fault (`rmp` #733/#967) rather \
         than skipping enforcement",
    ),
];

/// The per-entity index-maintenance seams in `record_graph.rs`, and the **decision** read each one
/// must reach — directly, or through the named helper that does.
const INDEX_MAINTENANCE_SEAMS: &[(&str, &str)] = &[
    ("reindex_node", "read_node_props"),
    ("reindex_rel", "decision_scan_rel_properties"),
];

/// The functions that may perform a **current-image** property read in `coordinator.rs`, each with the
/// reason it is correct there. Anything else calling `cells_ignoring_history` in that file fails the
/// census — which is the check that catches a population path quietly switched off the superset.
const CURRENT_IMAGE_READERS: &[(&str, &str)] = &[
    (
        "index_one_node_fulltext",
        "a full-text document is indexed WHOLE and `fulltext_query` never re-checks terms, so a term \
         from an older version is a wrong row the consumer cannot drop; the `rmp` #778 gate refuses \
         to bake while an in-flight writer holds a covered key, and that gate needs the EMPTY cells \
         `candidates()` drops",
    ),
    (
        "index_one_rel_fulltext",
        "the relationship twin of `index_one_node_fulltext`, same argument",
    ),
    (
        "index_one_node_vector",
        "an HNSW graph holds ONE embedding per entity and `rmp` #780 leaves a conflicted entity out \
         entirely rather than indexing an older version; the gate reads the cells' own MVCC headers",
    ),
    (
        "index_one_rel_vector",
        "the relationship twin of `index_one_node_vector`, same argument",
    ),
    (
        "rebuild_columns",
        "memoization with a total fallback whose witness names a `props.store` CELL: a candidate from \
         the undo store would be read back at an undo-store id, and a row the column omits falls \
         through to `read_node_prop_one`, so a hole costs a decode and never a row",
    ),
    (
        "stamped_candidates",
        "not a current-image read at all: it reads the cells as the FIRST half of the superset and \
         then walks `history()` for the second, which is why it is also required to call `.history()` \
         (`a_composite_refill_reads_the_superset_with_intervals`)",
    ),
];

/// The constraint-validation surface: the functions whose answer is written into the catalogue and is
/// never re-checked (`rmp` tasks #902, #903).
const DECISION_POLARITY_FNS: &[&str] = &[
    "validate_existing_against_constraint",
    "validate_existing_rels_against_constraint",
    "constraint_node_value",
    "constraint_rel_value",
    "node_value_for_key",
    "rel_value_for_key",
    "decided_value_for_key",
];

/// The per-node index refills. Every one of them must gate label membership on the superset.
const SUPERSET_POLARITY_FNS: &[&str] = &[
    "index_one_node",
    "index_one_node_composite",
    "index_one_node_fulltext",
    "index_one_node_spatial",
    "index_one_node_text",
    "index_one_node_vector",
    "index_one_node_bitmap",
];

/// The functions that may read the **live** label word in `coordinator.rs`, each with the reason it is
/// correct there. Anything else calling `node_labels` in that file fails the census.
const LIVE_WORD_READERS: &[(&str, &str)] = &[(
    "rebuild_columns",
    "memoization with a total fallback: a row the column omits falls through to \
         read_node_prop_one, so a hole costs a decode and never a row",
)];

/// The body of the method named `name`, as `coordinator.rs` / `record_graph.rs` style it: a method
/// declared at one `impl` level, so its closing brace is the first line that is exactly four spaces
/// and `}`.
///
/// # Panics
/// Panics when the method is not found or its body does not terminate, because either means the census
/// is inspecting something that no longer exists and would otherwise pass vacuously.
fn method_body(src: &str, name: &str) -> String {
    let lines: Vec<&str> = src.lines().collect();
    let start = lines
        .iter()
        .position(|l| {
            let t = l.trim_start();
            t.starts_with(&format!("fn {name}("))
                || t.starts_with(&format!("pub fn {name}("))
                || t.starts_with(&format!("fn {name}<"))
                || t.starts_with(&format!("pub fn {name}<"))
        })
        .unwrap_or_else(|| panic!("`{name}` not found: the census is inspecting a stale name"));
    let end = lines[start..]
        .iter()
        .position(|l| *l == "    }")
        .unwrap_or_else(|| {
            panic!("the body of `{name}` does not terminate at an `impl`-level brace")
        });
    let body = lines[start..=start + end].join("\n");
    assert!(
        body.lines().count() > 2,
        "the extracted body of `{name}` is implausibly short: {body}"
    );
    body
}

/// The number of non-comment lines in `body` that contain `needle`. Doc comments are excluded so a
/// docstring that *names* a read is not mistaken for a call to it — which matters, because these
/// bodies document their polarity at length.
fn code_hits(body: &str, needle: &str) -> usize {
    body.lines()
        .filter(|l| !l.trim_start().starts_with("//"))
        .filter(|l| l.contains(needle))
        .count()
}

/// **THE `rmp` #902 SHAPE, as a check.** No constraint-validation function may perform a
/// superset-polarity read. The property axis also fails to compile if it is tried (a
/// `SupersetProperties` cannot be handed to `decided_value_for_key`); this catches the shapes the type
/// system cannot, notably an inline chain walk and the label superset.
#[test]
fn a_decision_path_never_performs_a_superset_polarity_read() {
    for f in DECISION_POLARITY_FNS {
        let body = method_body(COORDINATOR, f);
        for read in raw_reads() {
            assert_eq!(
                code_hits(&body, read),
                0,
                "`{f}` is a constraint-validation path: its answer is written into the catalogue and \
                 nothing re-checks it, so it must not call the superset-polarity read `{read}`. That \
                 is `rmp` task #902 exactly. Resolve the value through `decision_scan_*` (which \
                 demands the walk's `Snapshot`) instead — see `graphus_storage::scan_polarity`.",
            );
        }
    }
}

/// Both value resolvers must go through the decision-polarity store read, which cannot be called
/// without the snapshot the decision is made under.
#[test]
fn the_constraint_value_resolvers_read_through_a_snapshot() {
    for (f, expected) in [
        ("node_value_for_key", "decision_scan_node_properties"),
        ("rel_value_for_key", "decision_scan_rel_properties"),
    ] {
        let body = method_body(COORDINATOR, f);
        assert!(
            code_hits(&body, expected) == 1,
            "`{f}` must resolve its value through `{expected}`, the read that cannot be performed \
             without a `Snapshot` (`rmp` tasks #902, #905)",
        );
        assert!(
            body.contains("snapshot: Snapshot"),
            "`{f}` must take the deciding snapshot as a parameter, not infer one",
        );
    }
}

/// **The reclamation witness reads the superset on BOTH axes** (`rmp` #992).
///
/// `read_dead_key_evidence` is the read that authorises the GC-driven removal of a derived-index
/// entry, and it is the mirror image of a refill: a refill that reads a subset **omits** an entry, a
/// witness that reads a subset **removes** one. Both lose a row no seek can resurrect, so the polarity
/// requirement is identical and belongs in this census.
///
/// Both axes are asserted because the two failure modes are independent: a decision-polarity property
/// read would destroy the entry of a value only an older snapshot sees, and the live label word would
/// destroy the label entries of a node whose `REMOVE n:L` an open writer may still roll back.
#[test]
fn the_reclamation_witness_reads_the_superset_on_both_axes() {
    let body = method_body(COORDINATOR, "read_dead_key_evidence");
    // The UNDECODED scans, which is what the witness reads since the covered-keys filter moved ahead
    // of the decode (decoding walks the overflow heap, so the decoded twin charges a full heap walk
    // per unindexed property of every entity a dead key names). Both members of the family are
    // superset-polarity; what this census fixes is that the read is a `superset_scan_*` at all.
    assert!(
        code_hits(&body, "superset_scan_node_properties") >= 1
            && code_hits(&body, "superset_scan_rel_properties") >= 1,
        "`read_dead_key_evidence` decides whether an index entry may be DESTROYED, so its property          read must be the superset — the live cells PLUS everything the undo chain can still          reconstruct. A decision-polarity read here removes the entry of a value an older snapshot          still sees (`rmp` #992)",
    );
    assert!(
        code_hits(&body, "node_label_superset") >= 1,
        "`read_dead_key_evidence`'s label gate must be `node_label_superset`, for the same reason          every refill's is (`rmp` #904): the live word is a SUBSET while an uncommitted `REMOVE n:L`          is open, and here that subset would DELETE the label entries instead of merely omitting them",
    );
    assert_eq!(
        code_hits(&body, ".node_labels("),
        0,
        "`read_dead_key_evidence` must not read the live label word",
    );
    for decision in DECISION_POLARITY_FNS
        .iter()
        .chain(CURRENT_IMAGE_PROPERTY_READS.iter())
    {
        assert_eq!(
            code_hits(&body, decision),
            0,
            "`read_dead_key_evidence` must not narrow its witness through `{decision}`",
        );
    }
}

/// **THE `rmp` #904 SHAPE, as a check.** Every per-node index refill gates membership on the
/// live-OR-retained label superset, never on the live word. Gating on the live word writes a SUBSET
/// while an uncommitted `REMOVE n:L` is open, and a seek's re-check can never resurrect the candidate
/// it drops.
#[test]
fn every_index_refill_gates_on_the_label_superset() {
    for f in SUPERSET_POLARITY_FNS {
        let body = method_body(COORDINATOR, f);
        assert!(
            code_hits(&body, "node_label_superset") >= 1,
            "`{f}` populates a candidate structure, so its label gate must be \
             `RecordStore::node_label_superset` — the live word unioned with every retained bitmap \
             (`rmp` task #904)",
        );
        assert_eq!(
            code_hits(&body, ".node_labels("),
            0,
            "`{f}` must not read the live label word: it is a SUBSET while an uncommitted \
             `REMOVE n:L` is open, and the entry this refill then fails to write is one no seek can \
             resurrect (`rmp` task #904)",
        );
    }
}

/// A zone map PRUNES: `candidate_ranges_eq` removes a whole id range before the per-row re-check ever
/// runs, and nothing rebuilds a zone map afterwards. Its rebuild therefore takes the same superset gate
/// as an index refill — the conservative obligation of `graphus_storage::scan_polarity`.
#[test]
fn a_pruning_rebuild_gates_on_the_label_superset() {
    let body = method_body(COORDINATOR, "rebuild_zone_column");
    assert!(
        code_hits(&body, "node_label_superset") >= 1,
        "`rebuild_zone_column` narrows a pruning structure, so it must gate on \
         `node_label_superset`; nothing repairs a zone map, so a narrowed zone is permanent \
         (`rmp` task #904)",
    );
    assert_eq!(
        code_hits(&body, ".node_labels("),
        0,
        "`rebuild_zone_column` must not narrow a zone on the strength of a live word an open writer \
         may roll back (`rmp` task #904)",
    );
}

/// **THE `rmp` #958 REBUILD SHAPE, as a check.** The same rebuild is a superset on the VALUE axis too:
/// it widens each zone with **every** version of the property, never with the chain head alone.
///
/// The head may belong to a transaction that has not committed, and even a committed head leaves an
/// older reader resolving the version underneath it (`rmp` #50, newest-**visible**-wins). Either way a
/// head-only summary narrows the zone below a value some live snapshot can still see, and the id range
/// vanishes before any re-check can restore it.
#[test]
fn a_pruning_rebuild_summarizes_every_property_version() {
    let body = method_body(COORDINATOR, "rebuild_zone_column");
    assert!(
        code_hits(&body, "superset_scan_node_property_values") >= 1,
        "`rebuild_zone_column` must read the raw property chain — the superset — and say so at the \
         call site (`rmp` tasks #905, #958)",
    );
    assert_eq!(
        code_hits(&body, ".find(|(_, k, _)| *k == prop_key)"),
        0,
        "`rebuild_zone_column` must not summarise the chain HEAD: `find` stops at the newest version, \
         which may be an uncommitted overwrite (a rollback restores the record but never the summary) \
         or a committed one an existing reader still reads past. Widen the zone with every version \
         (`filter`, not `find`) — `rmp` task #958",
    );
    assert!(
        code_hits(&body, "abandon_column") >= 1,
        "a rebuild whose scan faults must ABANDON the column (it then declines to a full scan), never \
         install a summary over the ids it happened to read — `rmp` task #958",
    );
}

/// **THE `rmp` #958 RE-CHECK SHAPE, as a check.** The zone map's consumer decides its candidates
/// through the one lifted re-check body every node equality seek shares, so the label is resolved with
/// `label_bitmap_at` and the version with `is_visible`, at the reader's snapshot.
///
/// The defect this replaces re-checked candidates against the raw live label word and `mvcc.in_use()`
/// **and returned rows**, so a dirty read in either direction reached the caller unrepaired. Any future
/// consumer that re-implements the re-check instead of calling the shared body fails here.
#[test]
fn the_zone_map_consumer_decides_through_the_shared_recheck() {
    let body = method_body(RECORD_GRAPH, "zone_scan_eq");
    assert!(
        code_hits(&body, "candidate_ids_eq") == 1,
        "`RecordStoreGraph::zone_scan_eq` must obtain CANDIDATES from the zone map \
         (`ZoneMap::candidate_ids_eq`), never rows (`rmp` task #958)",
    );
    assert!(
        code_hits(&body, "index_seek_eq_recheck") == 1,
        "`RecordStoreGraph::zone_scan_eq` must decide those candidates through the shared \
         `read_source::index_seek_eq_recheck` — `label_bitmap_at` + `is_visible` + the value residual \
         + the SIREAD markers + the fail-closed read-fault handling — so the zone-routed answer and \
         the scan it accelerates are the same set by construction (`rmp` task #958)",
    );
    for raw in [".node_labels(", "mvcc.in_use()"] {
        assert_eq!(
            code_hits(&body, raw),
            0,
            "`RecordStoreGraph::zone_scan_eq` must not re-check a candidate with `{raw}`: the label \
             word is mutated in place and `in_use` is not a visibility predicate, so that read is a \
             dirty read in both directions (`rmp` task #958)",
        );
    }
    assert_eq!(
        code_hits(COORDINATOR, "fn zone_scan_eq"),
        0,
        "the zone-map skip query must live on a seam that owns a snapshot. `TxnCoordinator` has \
         none — `label_bitmap_at` demands a `(Snapshot, CommitRegistry)` pair — so a coordinator-level \
         `zone_scan_eq` cannot be anything but a dirty read (`rmp` task #958)",
    );
}

/// The constraint walk reads the node's label word **in place**, off the record its visibility filter
/// has just decoded. That is sound only because the `rmp` #902 guard refuses the DDL whenever another
/// transaction holds uncommitted state, so no uncommitted label change can be in flight while the walk
/// runs. This pins the two together: removing the guard and leaving the raw read is the defect.
#[test]
fn the_constraint_walks_raw_label_read_stays_coupled_to_the_902_guard() {
    let walk = method_body(COORDINATOR, "validate_existing_against_constraint");
    let reads_live_word = code_hits(&walk, "labels::token_ids(rec.labels)") == 1;
    let guard_exists = COORDINATOR.contains("fn refuse_constraint_ddl_while_writers_open");
    // The guard must stand on the path that *runs the walk*, not merely somewhere in the file: the
    // walk is driven by `create_constraint_general_cancellable`, and that is where the DDL is refused
    // while another transaction holds uncommitted state.
    let guard_is_called = code_hits(
        &method_body(COORDINATOR, "create_constraint_general_cancellable"),
        "self.refuse_constraint_ddl_while_writers_open(",
    ) >= 1;
    if reads_live_word {
        assert!(
            guard_exists && guard_is_called,
            "`validate_existing_against_constraint` decodes the node's LIVE label word. That is only \
             sound while `refuse_constraint_ddl_while_writers_open` (`rmp` task #902) refuses the DDL \
             on the path that drives the walk, whenever another transaction holds uncommitted state. \
             The guard is gone from that path, so this read must become \
             `RecordStore::label_bitmap_at`, the as-of-snapshot resolver (`rmp` #767).",
        );
    } else {
        assert_eq!(
            code_hits(&walk, ".node_labels("),
            0,
            "the constraint walk no longer decodes labels off the record it read; if it now calls a \
             label reader, it must be the snapshot-exact `label_bitmap_at`",
        );
    }
}

/// The census of live-word reads in `coordinator.rs` is complete: every one of them sits in a function
/// this file has classified, with a reason. A new one fails here until it is classified.
#[test]
fn the_census_of_live_word_reads_in_the_coordinator_is_complete() {
    let total = code_hits(COORDINATOR, ".node_labels(");
    let classified: usize = LIVE_WORD_READERS
        .iter()
        .map(|(f, _)| code_hits(&method_body(COORDINATOR, f), ".node_labels("))
        .sum();
    assert_eq!(
        total, classified,
        "`coordinator.rs` performs {total} live-label-word read(s) but only {classified} of them sit \
         in a function this census has classified. A live-word read is correct only where nothing \
         downstream needs a superset and nothing decides on it; classify the new one against \
         `graphus_storage::scan_polarity` and add it to `LIVE_WORD_READERS` with its reason, or \
         change it to `node_label_superset` / `label_bitmap_at`.",
    );
    assert!(
        classified > 0,
        "the census found no classified live-word read at all, so it is passing vacuously",
    );
}

/// The body of `name` in `src`, whether it is declared at `impl` level (four-space indent) or as a
/// free function at column 0. Used by the censuses that classify a name without knowing which it is.
///
/// # Panics
/// Panics when `name` is found in neither form, because that means the census is inspecting a stale
/// name and would otherwise pass vacuously.
fn any_fn_body(src: &str, name: &str) -> String {
    if src.contains(&format!("\n    fn {name}(")) || src.contains(&format!("\n    pub fn {name}("))
    {
        return method_body(src, name);
    }
    let start = src
        .find(&format!("\nfn {name}("))
        .unwrap_or_else(|| panic!("`{name}` not found at impl level or at column 0"));
    let rest = &src[start + 1..];
    let end = rest.find("\n}\n").unwrap_or(rest.len());
    rest[..end].to_owned()
}

/// The body of the free function `name` in `read_source.rs` (declared at column 0).
///
/// # Panics
/// Panics when the function is not found, because that means the census is inspecting a stale name and
/// would otherwise pass vacuously.
fn free_fn_body(src: &str, name: &str) -> String {
    let start = src
        .find(&format!("\nfn {name}<"))
        .unwrap_or_else(|| panic!("`{name}` not found in read_source.rs"));
    let rest = &src[start + 1..];
    let end = rest.find("\n}\n").unwrap_or(rest.len());
    rest[..end].to_owned()
}

/// **THE `rmp` #967 QUERY-PATH SHAPE, as a check.** A query materialising a property resolves it at
/// the reader's snapshot, through the storage-side decision walk — it does **not** read a raw chain
/// and fold visibility itself.
///
/// That fold used to live here and was correct while every version of a key was a cell carrying its
/// own `xmin`/`xmax`. After `rmp` #967 an overwrite is written in place and the superseded value
/// descends onto the entity's undo chain, which `D-property-visibility` makes the sole oracle: a fold
/// over the cells' own stamps now resolves the CURRENT value for every reader, including one whose
/// snapshot predates the overwrite.
#[test]
fn the_query_read_path_resolves_at_its_snapshot() {
    for (src, name, fns) in [
        (
            READ_SOURCE,
            "read_source.rs",
            &[
                "read_node_prop_one",
                "read_rel_prop_one",
                "read_node_props",
                "read_rel_props",
            ][..],
        ),
        (
            RECORD_GRAPH,
            "record_graph.rs",
            &["read_node_prop_one", "read_node_props"][..],
        ),
    ] {
        for f in fns {
            let body = if src == READ_SOURCE {
                free_fn_body(src, f)
            } else {
                method_body(src, f)
            };
            assert!(
                code_hits(&body, "decision_scan_") >= 1,
                "`{f}` ({name}) materialises a property for a query, so it must resolve the version \
                 through `decision_scan_*` — the read that cannot be performed without a `Snapshot` \
                 (`rmp` tasks #905, #967)",
            );
            for raw in raw_reads() {
                assert_eq!(
                    code_hits(&body, raw),
                    0,
                    "`{f}` ({name}) must not perform the raw read `{raw}`: after `rmp` #967 the \
                     entity's undo chain is the sole visibility oracle for a property, so a fold over \
                     the cells' own MVCC stamps serves the CURRENT value to a reader whose snapshot \
                     predates the overwrite",
                );
            }
            assert_eq!(
                code_hits(&body, "visible(prop.mvcc)"),
                0,
                "`{f}` ({name}) must not re-decide visibility from a property cell's own MVCC header: \
                 `D-property-visibility` made that stamp informative (`rmp` #967)",
            );
        }
    }
}

/// **THE `rmp` #755/#768/#769/#770 SHAPE, as a check.** The inline path and the off-thread reader pool
/// resolve a property version through the **same** mechanism.
///
/// That family of defects is one shape repeated: the reader pool quietly answered from a different
/// mechanism than the inline path — full-scanning where the inline path sought, declining an index the
/// inline path used. A property version is now reconstructed by an undo-chain walk, which is exactly
/// the kind of mechanism that can be reimplemented slightly differently on one side and diverge
/// silently. So it lives on the `StoreReadSource` seam, and both implementations forward to the one
/// storage body.
#[test]
fn both_read_sources_resolve_properties_through_the_same_seam() {
    for m in [
        "decision_scan_node_properties",
        "decision_scan_rel_properties",
    ] {
        assert_eq!(
            code_hits(READ_SOURCE, &format!("fn {m}(")),
            3,
            "`{m}` must appear exactly three times in read_source.rs: the `StoreReadSource` \
             declaration, the `LiveSource` (inline) implementation and the `ReadViewSource` \
             (off-thread reader pool) implementation. A missing implementation means one of the two \
             paths resolves versions some other way (`rmp` #755/#768/#769/#770)",
        );
    }
    // Each implementation is a pure forward to the one storage body — the inline path to
    // `RecordStore`, the off-thread path to `StoreReadView`, both of which delegate to
    // `graphus_storage::read_view`. A body that did anything else would be a second mechanism.
    for (recv, m) in [
        ("self.0.decision_scan_node_properties(", "LiveSource node"),
        ("self.0.decision_scan_rel_properties(", "LiveSource rel"),
        (
            "self.view.decision_scan_node_properties(",
            "ReadViewSource node",
        ),
        (
            "self.view.decision_scan_rel_properties(",
            "ReadViewSource rel",
        ),
    ] {
        assert_eq!(
            code_hits(READ_SOURCE, recv),
            1,
            "the {m} implementation must be a single forward to the shared storage body (`{recv}…`)",
        );
    }
}

/// **THE `rmp` #967 COMPOSITE SHAPE, as a check.** A composite refill reads the superset **with**
/// per-candidate validity intervals, and never the current image.
///
/// A composite index indexes tuples, and a tuple is observable only if its members were current at one
/// common instant, so this build cannot use the stampless `candidates()` — it would have to collapse
/// to one value per key (dropping the candidate that catches a committed duplicate on a NODE KEY /
/// REL KEY: `rmp` #683 / #765) or emit the Cartesian product. And it cannot use the current image at
/// all, for the same reason plus one more: after #967 the cells hold only the newest value.
#[test]
fn a_composite_refill_reads_the_superset_with_intervals() {
    for f in ["index_one_node_composite", "index_one_rel_composite"] {
        let body = method_body(COORDINATOR, f);
        assert!(
            code_hits(&body, "stamped_candidates(") >= 1,
            "`{f}` must build its candidate tuples from `stamped_candidates`, the superset read that \
             rebuilds each value's validity interval from the undo chain (`rmp` #967)",
        );
        for raw in CURRENT_IMAGE_PROPERTY_READS {
            assert_eq!(
                code_hits(&body, raw),
                0,
                "`{f}` must not read the current image (`{raw}`): after `rmp` #967 the live cells hold \
                 only the NEWEST value of each key, so a refill that reads them drops every tuple an \
                 older snapshot still needs — and for a NODE KEY / REL KEY the write path's duplicate \
                 check then finds nothing and ADMITS a committed duplicate (`rmp` #683 / #765)",
            );
        }
    }
    // And the helper itself must read BOTH halves of the superset: the cells give the current value of
    // each key, the history gives every value an older snapshot can still ask for.
    let helper = {
        let start = COORDINATOR
            .find("\nfn stamped_candidates(")
            .expect("`stamped_candidates` not found: the census is inspecting a stale name");
        let rest = &COORDINATOR[start + 1..];
        let end = rest.find("\n}\n").unwrap_or(rest.len());
        rest[..end].to_owned()
    };
    for half in [".cells_ignoring_history()", ".history()"] {
        assert!(
            code_hits(&helper, half) >= 1,
            "`stamped_candidates` must read `{half}`: the superset is cells PLUS undo history, and \
             either half alone loses candidates (`rmp` #967)",
        );
    }
}

/// The census of **current-image** property reads in `coordinator.rs` is complete: every one of them
/// sits in a function this file has classified, with a reason. A population path switched off the
/// superset onto the current image fails here until somebody writes down why that is sound — which,
/// for a structure whose consumer re-checks candidates, it is not.
#[test]
fn the_census_of_current_image_property_reads_is_complete() {
    for read in CURRENT_IMAGE_PROPERTY_READS {
        let total = code_hits(COORDINATOR, read);
        let classified: usize = CURRENT_IMAGE_READERS
            .iter()
            .map(|(f, _)| code_hits(&any_fn_body(COORDINATOR, f), read))
            .sum();
        assert_eq!(
            total, classified,
            "`coordinator.rs` performs {total} current-image property read(s) (`{read}`) but only \
             {classified} of them sit in a function this census has classified. After `rmp` #967 the \
             live cells are the CURRENT image and not a superset, so this read is correct only where \
             the structure holds one value per entity and nothing downstream needs an older one. \
             Classify the new one against `graphus_storage::scan_polarity` and add it to \
             `CURRENT_IMAGE_READERS` with its reason, or change it to the candidate superset.",
        );
        assert!(
            classified > 0,
            "the census found no classified current-image read at all, so it is passing vacuously",
        );
    }
}

/// **THE `rmp` #967 `reindex_rel` SHAPE, as a check.** The census of raw **property**-axis reads in
/// `record_graph.rs` is complete: every one of them sits in a function this file has classified, with
/// a reason.
///
/// This assertion did not exist, and that is why the defect it now catches could happen. The census's
/// three earlier assertions each scanned `coordinator.rs` only, or a hard-coded list of names — so
/// `reindex_rel`, the per-write maintenance of every derived RELATIONSHIP index, could fold
/// first-occurrence-wins over `superset_scan_rel_property_values` and appear in no section and no
/// check. After #967 that read is the candidate superset (cells, with the empty cell a `REMOVE` leaves
/// behind skipped, then the undo history), so a removed key's first surviving candidate is its
/// pre-removal value, and the wholesale re-index put it back into the full-text terms and the ANN
/// graph.
///
/// `record_graph.rs` is where the query seam lives, so a raw property read here is nearly always
/// wrong. Classifying one is meant to be an unusual, deliberate act.
#[test]
fn the_census_of_superset_property_reads_in_record_graph_is_complete() {
    let mut total = 0usize;
    let mut classified = 0usize;
    for read in PROPERTY_AXIS_RAW_READS {
        total += code_hits(RECORD_GRAPH, read);
        classified += RECORD_GRAPH_RAW_PROPERTY_READERS
            .iter()
            .map(|(f, _)| code_hits(&any_fn_body(RECORD_GRAPH, f), read))
            .sum::<usize>();
    }
    assert_eq!(
        total, classified,
        "`record_graph.rs` performs {total} raw property-axis read(s) but only {classified} of them \
         sit in a function this census has classified. `record_graph.rs` is the QUERY seam: its \
         property reads resolve at the reader's snapshot through `decision_scan_*`, and a raw read \
         here answers 'what does the cell say now' (or, worse since `rmp` #967, 'what did it once \
         say') to a question that was about a snapshot. Either resolve through `decision_scan_*`, or \
         classify the new read in `RECORD_GRAPH_RAW_PROPERTY_READERS` with the reason it is correct — \
         and an entry with no justification is not an entry.",
    );
    assert!(
        classified > 0,
        "the census found no classified raw property read in `record_graph.rs` at all, so it is \
         passing vacuously — the classified read must still exist for this check to have teeth"
    );
}

/// The census of **live label word** reads in `record_graph.rs` is complete, the same way the
/// coordinator's is. A new one fails here until it is classified.
///
/// This also keeps the prose honest: until `rmp` #967's audit the module docs above named
/// `note_node_predicate_write`, `reindex_node_bitmap` and `note_node_label_predicate_write` as the
/// classified readers, and two of those three have never existed in this crate. `any_fn_body` panics
/// on a name it cannot find, so a stale entry now fails the gate instead of reassuring a reviewer.
#[test]
fn the_census_of_live_word_reads_in_record_graph_is_complete() {
    let total = code_hits(RECORD_GRAPH, ".node_labels(");
    let classified: usize = RECORD_GRAPH_LIVE_WORD_READERS
        .iter()
        .map(|(f, _)| code_hits(&any_fn_body(RECORD_GRAPH, f), ".node_labels("))
        .sum();
    assert_eq!(
        total, classified,
        "`record_graph.rs` performs {total} live-label-word read(s) but only {classified} of them sit \
         in a function this census has classified. The live word is a SUBSET while an uncommitted \
         `REMOVE n:L` is open and a SUPERSET-of-nothing for an older reader, so it is correct only on \
         the write path (where it is the state just written) — anywhere else it must be \
         `node_label_superset` (population) or `label_bitmap_at` (decision). Classify the new one in \
         `RECORD_GRAPH_LIVE_WORD_READERS` with its reason, or change the read.",
    );
    assert!(
        classified > 0,
        "the census found no classified live-word read in `record_graph.rs` at all, so it is passing \
         vacuously"
    );
}

/// **THE POPULATION-PATH SHAPE, as a check.** Per-write index maintenance resolves its property
/// values at the **statement's snapshot**, and performs no raw property read of any polarity.
///
/// This is the assertion that would have caught `reindex_rel` directly, and it catches the two ways
/// the same mistake is spelled: reading the candidate superset (which after `rmp` #967 resurrects a
/// removed key's pre-removal value) and reading the current image `cells_ignoring_history` (which is
/// not a superset either, and answers without a snapshot).
///
/// Both seams maintain structures that hold ONE value per entity and whose consumers do not re-check
/// that value — the full-text inverted index re-checks a hit's visibility and label/type but never its
/// terms, and the ANN graph is not re-checked at candidate-selection time at all — so what they owe is
/// the decision read, exactly like the query path.
#[test]
fn per_write_index_maintenance_resolves_at_the_statement_snapshot() {
    for (f, resolver) in INDEX_MAINTENANCE_SEAMS {
        let body = method_body(RECORD_GRAPH, f);
        assert!(
            code_hits(&body, resolver) >= 1,
            "`{f}` maintains structures that hold one value per entity, so it must resolve that value \
             at this statement's snapshot through `{resolver}` (`rmp` tasks #905, #967)",
        );
        for raw in PROPERTY_AXIS_RAW_READS {
            assert_eq!(
                code_hits(&body, raw),
                0,
                "`{f}` must not perform the raw property read `{raw}`. After `rmp` #967 the candidate \
                 superset yields the live cells — with the EMPTY cell a `REMOVE` leaves behind \
                 skipped — followed by the undo history, so folding first-occurrence-wins over it \
                 resolves a REMOVED key to its pre-removal value; and the current image \
                 (`cells_ignoring_history`) answers without a snapshot at all. Either one re-bakes a \
                 committed-removed value into the full-text terms (a wrong ROW: the query re-checks \
                 visibility and label/type, never terms) and back into the ANN graph (a phantom that \
                 consumes the `2k` over-fetch budget, costing a genuine neighbour its row). Resolve \
                 through `{resolver}`.",
            );
        }
    }
}
