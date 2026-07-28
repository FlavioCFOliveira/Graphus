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
//! ## Superset — index population (a hole is unrecoverable, an extra entry is dropped by the re-check)
//!
//! * `TxnCoordinator::index_one_node`, `index_one_node_composite`, `index_one_node_fulltext`,
//!   `index_one_node_spatial`, `index_one_node_text`, `index_one_node_vector`,
//!   `index_one_node_bitmap` — each indexes **every** property version with no visibility filter
//!   (`rmp` #766) and gates label membership on the live-OR-retained union
//!   `RecordStore::node_label_superset` (`rmp` #904). Both are required: a seek's re-check can remove a
//!   candidate but never resurrect one, so the tree must be a superset in both directions. Pinned by
//!   `every_index_refill_gates_on_the_label_superset` below.
//! * `TxnCoordinator::index_one_rel*` — the relationship twins. They gate on `RelRecord::type_id`, read
//!   live and **not** widened, because a relationship's type is fixed at creation and no statement
//!   changes it; there is no older version for a superset to recover. Their property reads are the same
//!   every-version superset as the node twins.
//! * `graphus_cypher::read_source::{read_node_props, read_rel_props, read_node_prop_one,
//!   read_rel_prop_one}` and their `RecordStoreGraph` twins — these read the superset and apply the
//!   visibility fold themselves, one record at a time, so that a hot single-property probe stops at the
//!   first visible version instead of materialising the whole narrowed set. The polarity is decision;
//!   the *read* is superset by construction, which is why the call is spelled
//!   `superset_scan_*` at those sites. Pinned by `the_query_read_path_folds_visibility_over_the_superset`.
//!
//! ## Conservative — pruning structures (an excluded range disappears before any re-check runs)
//!
//! * `TxnCoordinator::rebuild_zone_column` — a zone map prunes whole id ranges, and nothing rebuilds
//!   one afterwards, so it may never narrow on unproven state. It takes the same
//!   `node_label_superset` gate as an index refill (`rmp` #904). Pinned by
//!   `a_pruning_rebuild_gates_on_the_label_superset`.
//!
//! ## Live word — write-path enforcement and total-fallback memoization
//!
//! * `RecordStoreGraph::note_node_predicate_write` / `reindex_node` / `reindex_node_bitmap` /
//!   `note_node_label_predicate_write` (`record_graph.rs`) — the write path reads the node's **current**
//!   labels because the state it is announcing or indexing is the state it has just written. There is no
//!   snapshot to resolve against and no superset to widen to: the question is "what does this record say
//!   now".
//! * `TxnCoordinator::rebuild_columns` (the columnar accelerator) reads the live word on purpose. The
//!   column is a **memoization with a total fallback**, not a candidate source: `columnar_scan`
//!   re-checks every candidate's visibility and label through `label_bitmap_at`, and a row the column
//!   does not hold — or holds staler than its witness allows — falls through to
//!   `read_node_prop_one`, the authoritative path. A hole therefore costs one property decode, never a
//!   row. That is what distinguishes it from an index refill, where a hole is a row no seek can
//!   resurrect.
//! * `TxnCoordinator::zone_scan_eq` reads the live word in its per-row re-check. It is a documented
//!   current-state diagnostic surface with no planner or executor caller (`tests/zone_map_skipping.rs`
//!   only); wiring it into a query path requires moving it to a seam that carries a snapshot first.
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
//! It covers `graphus-cypher`, which is where the two opposite polarities meet — the same file holds
//! the index refills and the constraint walks. The `superset_scan_*` reads outside this crate are all
//! **offline or diagnostic** surfaces that hold no snapshot and answer no query: the consistency
//! checker (`graphus_storage::check`), the whole-graph dumper and bulk importer, the backup/restore
//! paths, and the DST oracles. They read the physical image on purpose, because the physical image is
//! precisely what they are there to inspect or copy. If a *query* path is ever added outside this
//! crate, extend the census to it rather than assuming the rule stops at the crate boundary.

const COORDINATOR: &str = include_str!("../src/coordinator.rs");
const RECORD_GRAPH: &str = include_str!("../src/record_graph.rs");
const READ_SOURCE: &str = include_str!("../src/read_source.rs");

/// Every read that returns raw physical state on the property axis, by the name it is called at a call
/// site. A decision path must contain none of these.
const SUPERSET_POLARITY_READS: &[&str] = &[
    "superset_scan_node_properties",
    "superset_scan_rel_properties",
    "superset_scan_node_property_values",
    "superset_scan_rel_property_values",
    "every_version(",
    "node_label_superset",
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
const LIVE_WORD_READERS: &[(&str, &str)] = &[
    (
        "zone_scan_eq",
        "current-state diagnostic surface with no planner or executor caller; it holds no snapshot to \
         resolve against and is documented as such",
    ),
    (
        "rebuild_columns",
        "memoization with a total fallback: a row the column omits falls through to \
         read_node_prop_one, so a hole costs a decode and never a row",
    ),
];

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
        for read in SUPERSET_POLARITY_READS {
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

/// A zone map PRUNES: `candidate_ranges_eq` removes a whole id range before `zone_scan_eq`'s per-row
/// re-check ever runs, and nothing rebuilds a zone map afterwards. Its rebuild therefore takes the same
/// superset gate as an index refill — the conservative obligation of
/// `graphus_storage::scan_polarity`.
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

/// The query read path reads the superset and folds visibility over it itself. Both halves matter: the
/// read must be spelled as a superset read (so the polarity is stated at the call site), and the fold
/// must be there (so the answer is a decision).
#[test]
fn the_query_read_path_folds_visibility_over_the_superset() {
    for (src, name, fns) in [
        (
            READ_SOURCE,
            "read_source.rs",
            &["read_node_prop_one", "read_rel_prop_one"][..],
        ),
        (
            RECORD_GRAPH,
            "record_graph.rs",
            &["read_node_prop_one", "read_node_props"][..],
        ),
    ] {
        for f in fns {
            let body = if src == READ_SOURCE {
                // Free functions in `read_source.rs` are declared at column 0.
                let start = src
                    .find(&format!("\nfn {f}<"))
                    .unwrap_or_else(|| panic!("`{f}` not found in {name}"));
                let rest = &src[start + 1..];
                let end = rest.find("\n}\n").unwrap_or(rest.len());
                rest[..end].to_owned()
            } else {
                method_body(src, f)
            };
            assert!(
                code_hits(&body, "superset_scan_") >= 1,
                "`{f}` ({name}) reads a raw property chain, so the call must say so: \
                 `superset_scan_*`",
            );
            assert!(
                code_hits(&body, "visible(prop.mvcc)") >= 1,
                "`{f}` ({name}) must fold `is_visible` over every version it walks — the read is a \
                 superset, the answer owed to a query is a decision",
            );
        }
    }
}
