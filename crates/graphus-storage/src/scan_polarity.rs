//! **Read polarity** — which of three answers a storage read is required to give, and the types that
//! keep them apart (`rmp` task #905), plus the **undo-chain reconstruction** that turns a stored
//! entity into the property set one snapshot sees (`rmp` #967).
//!
//! Every read of the record store returns *physical* state: whatever occupies the slot at that
//! instant, including versions written by transactions that have not committed, and (for labels,
//! which are mutated in place) a word that a rollback will change back. Nothing about that raw image
//! is wrong. What is wrong — three times over, in `rmp` tasks #902, #904 and #771 — is using one
//! polarity's read where another polarity's answer was required.
//!
//! The three polarities are not two ends of a scale. They are three different obligations:
//!
//! | Polarity | Obligation | Who re-checks | What a wrong answer costs |
//! |---|---|---|---|
//! | **Superset** | the result must CONTAIN every row any snapshot could need | the consumer, against its own snapshot | a missing row is unrecoverable; an extra row is dropped by the re-check |
//! | **Decision** | the result must be EXACTLY what the deciding snapshot sees | nobody | a wrong row is committed into the schema or into a uniqueness verdict |
//! | **Conservative** | the result must never EXCLUDE on state that is not proven | nobody, for the excluded range | an excluded range disappears before any re-check runs |
//!
//! # Where a property's old values live now (`rmp` #967)
//!
//! This module changed shape when the property path moved onto the unified undo chain. Before #967 a
//! `SET` **prepended** a new `props.store` record and tombstoned the old one, so *every* version of
//! every key was a cell in the owner's `first_prop` chain and "read the superset" meant "walk that
//! chain". After #967 the newest version is written **in place** and the old value descends onto the
//! entity's undo-delta chain (ratified decisions `D-property-removal` and `D-property-visibility`).
//!
//! Two consequences are load-bearing, and both are enforced by the types below rather than by
//! comments:
//!
//! * **The live cells are no longer a superset.** They are the *current* image and nothing else. A
//!   population path (an index refill, a zone-map rebuild) that reads only the cells silently loses
//!   every value an older snapshot still needs — the `rmp` #766/#958 defect shape, reintroduced from
//!   a new direction. So the superset is `cells + SetProperty delta history`, exposed as
//!   [`PropertyCandidate`]s through [`SupersetProperties::candidates`], and the old
//!   `every_version() -> &[(u64, PropRecord)]` accessor was **removed rather than widened**: a delta
//!   is not a `PropRecord` (no physical property id, no MVCC header), so widening would have meant
//!   fabricating one.
//! * **The cell's own MVCC stamp is no longer the visibility oracle.** `D-property-visibility` makes
//!   the undo chain the sole oracle for a property's value; the cell's `created_ts` is informative
//!   and `in_use` keeps only its structural meaning (slot occupancy, corpse threading). So
//!   [`SupersetProperties::decide`] folds the chain rather than testing `is_visible` per cell.
//!
//! # Superset — index population
//!
//! An index built by a refill has **no reader and therefore no snapshot**. It populates a *candidate*
//! structure, and every consumer re-checks each candidate against its own snapshot. The asymmetry that
//! makes that safe is one-directional: **a re-check can REMOVE a candidate, but it can never RESURRECT
//! one.** So the only image a candidate structure may hold is a superset of every row any snapshot can
//! ask for. Reading raw is not a concession here, it is the requirement:
//! `TxnCoordinator::index_one_node` indexes **every** property version with no visibility filter on
//! purpose (`rmp` task #766), and the label gate is the live-OR-retained union
//! [`RecordStore::node_label_superset`](crate::RecordStore::node_label_superset), not the live word
//! (`rmp` task #904), because the live word is a *subset* while an uncommitted `REMOVE n:L` is open.
//!
//! # Decision — constraint validation
//!
//! A `CREATE CONSTRAINT` walk is the opposite. It does not produce candidates, it produces a verdict
//! that is then written durably into the catalogue, and **nothing downstream re-checks it**. It must
//! therefore see exactly the graph a `MATCH` in the same transaction would see. Reading raw there
//! counted a committed `REMOVE n.email` as a present value, so `IS UNIQUE` was refused over a duplicate
//! no query could find and `IS NOT NULL` was accepted over a property that was gone (`rmp` task #902).
//!
//! # Conservative — data-skipping structures
//!
//! A zone map is neither. It **prunes**: the per-row re-check only ever runs on the ids
//! `candidate_ranges_eq` did *not* prune, so a narrowed zone removes a whole id range before any
//! re-check can see it, and nothing rebuilds a zone map afterwards. A pruning structure may therefore
//! only ever narrow on state it can prove, which in practice means its rebuild takes the same superset
//! gates an index refill takes and never the current image: the live-OR-retained label union rather
//! than the live word (`rmp` task #904), and **every** property candidate rather than the live cell
//! (`rmp` tasks #958, #967) — both in `TxnCoordinator::rebuild_zone_column`. A rebuild whose scan
//! faults abandons the column rather than summarising the part of the store it could read.
//!
//! The obligation has a second half that is easy to miss, because it is not about the summary at all:
//! the structure must produce **candidates**, and the per-candidate re-check that turns them into rows
//! must run at the reader's snapshot. `rmp` #958 was exactly that miss — the skip query re-checked its
//! candidates against the raw live label word and `mvcc.in_use()` and then returned *rows*, so an
//! uncommitted creation was served to every reader and an uncommitted `REMOVE n:L` hid a committed one,
//! with nothing downstream able to repair either.
//!
//! # What this module enforces
//!
//! The property axis — the one the `rmp` #902 defect lived on — is separated in the type system:
//!
//! * [`SupersetProperties`] is what a raw entity read returns. It is not a `Vec` and does not
//!   dereference to one; reaching the values means naming the polarity out loud
//!   ([`candidates`](SupersetProperties::candidates), which says in its own name that these are
//!   candidates to be re-checked, not rows).
//! * [`DecidedProperties`] is what a decision path must hold. It has **no public constructor**: the
//!   only way to obtain one is [`SupersetProperties::decide`], which takes a [`Snapshot`]. A decision
//!   helper that takes `&DecidedProperties` therefore cannot be handed a raw read — that is a type
//!   error, not a review finding.
//!
//! The label axis is separated by *signature* rather than by type, and was already so before this
//! module existed: the decision-grade read
//! [`RecordStore::label_bitmap_at`](crate::RecordStore::label_bitmap_at) cannot be called without a
//! `(Snapshot, &CommitRegistry)` pair, and the superset-grade read
//! [`RecordStore::node_label_superset`](crate::RecordStore::node_label_superset) says its polarity in
//! its name.

use std::collections::HashSet;

use graphus_core::{CommandId, GraphusError, Result, TxnId, VersionStamp};
use graphus_txn::Snapshot;

use crate::record::PropRecord;
use crate::undo::{CommitSlot, TYPE_TAG_ABSENT, UndoAction, UndoDelta};

/// Where one [`PropertyCandidate`]'s `(type_tag, value_inline)` pair was read from.
///
/// The distinction is not cosmetic: a `Cell` names a `props.store` record that a caller may read
/// again, freeze, or reclaim, whereas a `Delta` names an immutable `undo.store` record that carries
/// no MVCC header of its own and whose lifetime is governed by its transaction's commit slot.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum CandidateSource {
    /// The live `props.store` cell at this physical id — the entity's *current* value for the key.
    Cell(u64),
    /// The `undo.store` [`UndoAction::SetProperty`] delta at this physical id — a *historical* value
    /// the key held before some write.
    Delta(u64),
}

impl CandidateSource {
    /// The physical id, whichever store it belongs to. Use only for diagnostics and de-duplication;
    /// a cell id and a delta id live in **different** id spaces and are never comparable.
    #[must_use]
    pub fn id(self) -> u64 {
        match self {
            Self::Cell(id) | Self::Delta(id) => id,
        }
    }

    /// Whether this candidate came from a live cell rather than from the undo history.
    #[must_use]
    pub fn is_cell(self) -> bool {
        matches!(self, Self::Cell(_))
    }
}

/// One `(key, value)` pair an entity holds, or once held — the unit both polarities deal in
/// (`rmp` #967).
///
/// It carries the *stored* encoding (`type_tag` + `value_inline`) rather than a decoded
/// [`Value`](graphus_core::Value) on purpose: decoding an overflow value reads its `strings.store`
/// chain, and a caller that needs one key must not be made to fail on an unreadable chain belonging
/// to an unrelated property (`rmp` task #733). Decode one candidate at a time, through
/// [`RecordStore::decode_property_value`](crate::RecordStore::decode_property_value).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PropertyCandidate {
    /// Property-key token id (`tokens.store`, `04 §2.6`).
    pub key: u32,
    /// Value-class + inline/overflow discriminant, encoded exactly as `props.store`'s `type_tag`
    /// (`05 §9`). Never [`TYPE_TAG_ABSENT`]: an empty cell and an "was absent" delta carry no value
    /// and are therefore not candidates at all.
    pub type_tag: u8,
    /// The inline value, or the head block id of the `strings.store` overflow chain.
    pub value_inline: u64,
    /// Which record this pair was read from.
    pub source: CandidateSource,
}

/// One entry of an entity's undo chain as the property reader needs it: the delta and — for a
/// non-corpse delta — the [`CommitSlot`] its `commit_info` resolves to (`05 §12.4`).
///
/// The slot is resolved **at walk time**, by the code that owns the page cache, so that
/// [`SupersetProperties::decide`] can be a pure fold with no store access. `slot` is [`None`]
/// exactly for a **corpse** delta (`in_use` clear — an aborted transaction's), whose slot is never
/// consulted: the corpse is skipped before its commit information is needed, which also saves the
/// read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PropertyDelta {
    /// Physical id in `undo.store`.
    pub id: u64,
    /// The delta itself.
    pub delta: UndoDelta,
    /// The writing transaction's commit slot, or [`None`] for a corpse delta.
    pub slot: Option<CommitSlot>,
}

/// What a snapshot must do with one delta while reconstructing an older version (`rmp` #967,
/// `04 §5.6`). The three-way answer mirrors Memgraph's `ApplyDeltasForRead`
/// (`/data/refsrc/memgraph/src/storage/v2/mvcc.hpp`) and this store's own
/// `RecordStore::delta_is_dead`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeltaVerdict {
    /// Not this snapshot's business, but the chain continues **through** it: an aborted
    /// transaction's corpse. Its action is never applied; its `next` is still the way down.
    Skip,
    /// Undo it: it happened after this snapshot, or it belongs to a transaction this snapshot cannot
    /// see.
    Apply,
    /// Everything from here down is already reflected in the image being reconstructed — the walk is
    /// finished.
    ///
    /// This is sound **only** because commit timestamps are non-increasing along a chain, which is
    /// what the entity-granularity write-conflict check (`D-property-write-conflict`,
    /// `RecordStore::ensure_no_conflicting_writer`) buys: no two transactions can interleave deltas
    /// on one entity, so a chain cannot hold an older-committed delta above a newer-committed one.
    /// The consistency checker re-verifies the ordering independently
    /// ([`UndoChainFault::CommitTimestampsNotDescending`](crate::check::UndoChainFault)).
    ///
    /// The claim survives `rmp` #969 intact, and that is a property of where the incidence deltas
    /// live: they anchor on the **relationship**, a fresh slot private to its creator
    /// (`D-incidence-anchor`), so they never interleave with another transaction's deltas and never
    /// put a chain out of commit order.
    Stop,
}

/// Decides what `snapshot` must do with one delta, given the commit slot the walk resolved for it.
///
/// # Errors
/// Returns a storage error when the delta is live but its commit slot could not be resolved. That is
/// the one thing `05 §12.4` promises can never happen ("a slot outlives its last delta"), so it is
/// **failed closed** rather than guessed: a delta whose commit status is unknowable could be either
/// visible or invisible, and picking one would silently corrupt the reconstructed version.
pub(crate) fn delta_verdict(
    delta: &UndoDelta,
    slot: Option<CommitSlot>,
    snapshot: Snapshot,
    delta_id: u64,
) -> Result<DeltaVerdict> {
    if !delta.in_use() {
        // A corpse: its transaction aborted and its creation undo cleared the flag while preserving
        // the body, so the walk threads through it exactly as the incidence walk threads through a
        // dead-link relationship corpse (`rmp` #220).
        return Ok(DeltaVerdict::Skip);
    }
    let Some(slot) = slot else {
        return Err(GraphusError::Storage(format!(
            "undo delta {delta_id} names commit slot {} which holds no record; a slot must outlive \
             its last delta (`05 §12.4`), so this version cannot be resolved",
            delta.commit_info
        )));
    };
    if !slot.in_use() {
        // The slot is a corpse: the transaction aborted. Its deltas never happened.
        return Ok(DeltaVerdict::Skip);
    }
    Ok(match VersionStamp::from_raw(slot.commit_ts) {
        // Committed at or before this snapshot: the image already reflects it, and everything below
        // it committed earlier still.
        VersionStamp::Committed(ts) if ts <= snapshot.ts => DeltaVerdict::Stop,
        // Committed after this snapshot: undo it.
        VersionStamp::Committed(_) => DeltaVerdict::Apply,
        // This snapshot's own writer. Whether its uncommitted change is already reflected in the
        // image is a **statement**-granularity question (`04 §5.1.4`): under `View::New` every one of
        // our own writes is, so the walk is done; under `View::Old` the current statement's own
        // writes are not, so they are undone and the walk continues down to the previous statement's.
        //
        // Continuing is sound for the same reason stopping is: our own deltas sit at the head of the
        // chain in the order we linked them, so their command ids descend as the walk descends, and
        // below them sit only commit-ordered deltas. The walk therefore still meets `Stop` exactly
        // once, and never revisits a version it has already accounted for.
        VersionStamp::InFlight(w) if w == snapshot.owner => {
            if snapshot.hides_own_command(CommandId(delta.command_id)) {
                DeltaVerdict::Apply
            } else {
                DeltaVerdict::Stop
            }
        }
        // Another open writer: invisible to this snapshot, so undo it.
        VersionStamp::InFlight(_) => DeltaVerdict::Apply,
        // `commit_ts` is `0`, which `CommitSlot::decode` already rejects — so reaching here means the
        // slot was mutated behind the decoder. Fail closed.
        VersionStamp::None => {
            return Err(GraphusError::Storage(format!(
                "undo delta {delta_id} resolves to commit slot {} whose `commit_ts` is not a version \
                 stamp",
                delta.commit_info
            )));
        }
    })
}

/// The order-preserving accumulator both reconstruction paths share: the eager
/// [`SupersetProperties::decide`] fold and the early-stopping walk in
/// [`read_view`](crate::read_view). Sharing it is what makes the two provably agree.
///
/// The image is a `Vec`, because the output order is part of what
/// [`DecidedProperties::visible_versions`] promises and no hashed container preserves it. To be
/// precise about *why* that promise is kept — an earlier version of this comment attributed it to
/// `graphus-dst`'s checker, which does not hold up: the checker reads
/// [`SupersetProperties`] and sorts, and every other consumer
/// (`graphus-cypher`'s `read_node_props`/`read_rel_props`, `graphus-dst`'s reader-growth oracle)
/// either sorts by key name or selects by key. Nothing today depends on this exact order. It is kept
/// because a *deterministic* read result is a precondition for deterministic replay, and because it
/// is the documented contract of the type — not because a named consumer would break.
///
/// How a key is *looked up* in that `Vec` while it is being built is a separate question, and it is
/// decided by measurement (`rmp` #967 technical requirement 3): **a linear scan up to
/// [`LINEAR_DEDUP_MAX`] cells, a `HashSet` above it**.
///
/// # Why the dispatch, with the numbers
///
/// A pure linear scan is `O(K²)` in the number of cells, and that was not academic: it was
/// **essentially the entire cost of reading one entity's properties** once an entity held more than
/// a few hundred keys. From `cargo bench -p graphus-bench --bench prop_overwrite` (`distinct keys`
/// arms, mean latency of one visible-property read at the final chain length, same host, same
/// build, back-to-back):
///
/// | K | read before | read after | speed-up |
/// |---|---|---|---|
/// | 1000 | 232.1 µs | 45.5 µs | 5.1× |
/// | 2000 | 854.7 µs | 88.4 µs | 9.7× |
/// | 4000 | 3252.8 µs | 177.0 µs | 18.4× |
/// | 8000 | 12 523.5 µs | 373.7 µs | 33.5× |
///
/// The `after` column doubles when `K` doubles, which is the point: what remains is the `K` record
/// reads (`prop/undo/commit` is `K/1/1` in both columns — the substrate was always linear, and this
/// change does not touch it), so the read is now `O(K)` end to end. The removed term was ~97% of the
/// `K = 8000` read.
///
/// A pure `HashSet` fixes that but is ~3× *slower* than the scan at single-digit `K`. That half of
/// the comment this replaces was therefore correct — it had simply never been measured. (Its other
/// premise, that entities in real workloads hold single-digit key counts, is **still unmeasured**:
/// nothing here establishes the distribution of `K`, only what each implementation costs at a given
/// `K`. The dispatch is what makes that gap harmless — it no longer matters which side of it the
/// real distribution sits on.) Both readings are true, so the code takes both paths. ns per `seed()`
/// call over this store's own types, K distinct keys, median of 9 in one run:
///
/// | K | linear scan | `HashSet` | ratio |
/// |---|---|---|---|
/// | 16 | 69.0 | 215.3 | 3.12 |
/// | 32 | 189.0 | 404.9 | 2.14 |
/// | 48 | 472.2 | 649.6 | 1.38 |
/// | **64** | **764.3** | **820.6** | **1.07** |
/// | **80** | **1369.9** | **1026.7** | **0.75** |
/// | 128 | 2620.0 | 1606.5 | 0.61 |
/// | 256 | 12 622.8 | 3141.0 | 0.25 |
/// | 512 | 51 584.9 | 6001.0 | 0.12 |
///
/// The crossover is between 64 and 80, so [`LINEAR_DEDUP_MAX`] is 64: at or below it the scan is
/// still ahead and the code executed is exactly what it was before this change (measured
/// side by side at `K = 1, 2, 4, 8, 16, 64`, agreeing within run-to-run noise); above it the cost
/// stops being quadratic. The dispatch is **one length test at the top**, not a per-element branch,
/// so the small-`K` path carries no share of the large-`K` path's machinery — an incremental
/// "promote the scan to a set mid-loop" hybrid was also measured and is *worse* than either pure
/// path in a band just above its threshold (1.4–1.9 µs at `K = 64`, against 0.76 µs for the scan),
/// because it pays the whole set construction for the few elements that remain.
///
/// Two faster large-`K` alternatives were measured and **not** taken. At `K = 8000` a
/// `rustc-hash`-class integer hasher costs 42.4 µs and a sort-based dedup 25.2 µs, against this
/// `HashSet`'s 104.7 µs — but the read they sit inside is 373.7 µs, so the whole spread is ~20% of
/// one read and both cost something real: the hasher adds a dependency to `graphus-storage`, which
/// is the user's decision and not this code's (`rustc-hash = "2"` is already in the workspace via
/// `graphus-bufpool`, `graphus-txn` and `graphus-cypher`, so it would cost no new transitive edge);
/// and the sort needs two sorts plus an index remap to keep first-occurrence-wins, or it silently
/// falls back to the quadratic scan on exactly the duplicated-key input the de-duplication exists
/// for.
///
/// # What is NOT fixed here
///
/// [`apply`](Self::apply)'s lookup is the same scan and stays linear, so undoing `D` deltas over an
/// image of `K` keys is `O(D × K)`: measured at 3.4 ns per applied delta at `K = 8`, 2.08 µs at
/// `K = 8000`. It is left alone deliberately — `prop_overwrite`'s read arm stops the walk at the
/// first delta and therefore applies **none**, so there is no measurement that would justify
/// changing it, and indexing it would mean keeping a key→position map valid across the `retain` in
/// the removal branch. Recorded rather than silently carried.
///
/// Note that this whole fold **subsumes** the pre-#967 `O(V×K)` de-duplication over every version of
/// every key: the fold no longer sees `V` versions at all, only `K` live cells plus however many
/// deltas the walk applies before it stops — normally zero.
pub(crate) struct DecisionFold {
    visible: Vec<PropertyCandidate>,
}

/// Cell counts at or below which [`DecisionFold::seed`] de-duplicates with a linear scan instead of
/// a [`HashSet`]. The measured crossover is between 64 and 80 — see [`DecisionFold`].
const LINEAR_DEDUP_MAX: usize = 64;

/// The candidate a live cell at physical id `pid` contributes to a decided image.
fn cell_candidate(pid: u64, cell: PropRecord) -> PropertyCandidate {
    PropertyCandidate {
        key: cell.key,
        type_tag: cell.type_tag,
        value_inline: cell.value_inline,
        source: CandidateSource::Cell(pid),
    }
}

/// Position of the first candidate holding `key`, or [`None`].
///
/// The **single** linear key scan in this module: [`DecisionFold::seed`]'s small-image path and
/// [`DecisionFold::apply`] both go through it, so the probe counter below cannot drift away from the
/// scan it claims to measure.
fn find_key(visible: &[PropertyCandidate], key: u32) -> Option<usize> {
    let hit = visible.iter().position(|c| c.key == key);
    // Test-only, and derived from `hit` rather than counted inside the loop, so the scan compiled
    // into every other build — the benchmark's included — is untouched by the instrument.
    #[cfg(test)]
    note_linear_probes(hit.map_or(visible.len(), |i| i + 1));
    hit
}

#[cfg(test)]
thread_local! {
    /// Elements examined by [`find_key`] since [`take_linear_probes`] was last called.
    static LINEAR_PROBES: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}

#[cfg(test)]
fn note_linear_probes(n: usize) {
    LINEAR_PROBES.with(|c| c.set(c.get() + n as u64));
}

/// Elements examined by [`find_key`] since the last call, resetting the counter.
#[cfg(test)]
fn take_linear_probes() -> u64 {
    LINEAR_PROBES.with(|c| c.replace(0))
}

impl DecisionFold {
    /// Seeds the image from the entity's live cells: the *current* value of every key.
    ///
    /// Empty cells ([`TYPE_TAG_ABSENT`]) are dropped — the key is currently absent, and the drop
    /// happens **before** the de-duplication, so an empty cell does not claim its key against a
    /// later live cell for the same key. A duplicate key keeps the **first** cell in chain order
    /// (the chain is prepend-ordered, so that is the newest); a healthy post-#967 store never holds
    /// two live cells for one key, and the consistency checker reports it as a fault, but resolving
    /// deterministically here means a store written by an older build still reads sanely instead of
    /// doubling a key.
    ///
    /// Both paths below push in chain order and keep the first cell of each key, so which one runs
    /// is invisible in the result — it changes only how long the answer takes. See [`DecisionFold`]
    /// for the measurement that put the boundary where it is.
    pub(crate) fn seed(cells: &[(u64, PropRecord)]) -> Self {
        let mut visible: Vec<PropertyCandidate> = Vec::with_capacity(cells.len());
        if cells.len() <= LINEAR_DEDUP_MAX {
            for &(pid, cell) in cells {
                if cell.type_tag == TYPE_TAG_ABSENT {
                    continue;
                }
                if find_key(&visible, cell.key).is_some() {
                    continue;
                }
                visible.push(cell_candidate(pid, cell));
            }
        } else {
            // `seen` is only ever *probed*, never iterated, and that is load-bearing rather than
            // incidental: `std`'s `RandomState` is seeded per process, so iterating it would make
            // the output order differ between two runs of the same input and break deterministic
            // replay. The order comes from `cells` in both branches. Do not iterate `seen`.
            let mut seen: HashSet<u32> = HashSet::with_capacity(cells.len());
            for &(pid, cell) in cells {
                if cell.type_tag == TYPE_TAG_ABSENT {
                    continue;
                }
                // `insert` returns false for a key already present — the same "first occurrence
                // wins" rule the scan applies, decided in `O(1)` instead of `O(len)`.
                if !seen.insert(cell.key) {
                    continue;
                }
                visible.push(cell_candidate(pid, cell));
            }
        }
        Self { visible }
    }

    /// Undoes one delta: a [`UndoAction::SetProperty`] restores the value it carries, or — when that
    /// value is [`TYPE_TAG_ABSENT`] — restores the key's **absence**. Every other action changes no
    /// property and is ignored (it still participates in the walk's ordering, which is why the caller
    /// passes it here rather than filtering it out).
    pub(crate) fn apply(&mut self, delta: &UndoDelta, delta_id: u64) {
        if delta.action != UndoAction::SetProperty {
            return;
        }
        if delta.type_tag == TYPE_TAG_ABSENT {
            self.visible.retain(|c| c.key != delta.token);
            return;
        }
        let restored = PropertyCandidate {
            key: delta.token,
            type_tag: delta.type_tag,
            value_inline: delta.value_inline,
            source: CandidateSource::Delta(delta_id),
        };
        // Restoring in place preserves the key's position, which is what keeps the output order
        // independent of how many deltas the walk had to undo.
        match find_key(&self.visible, delta.token) {
            Some(i) => self.visible[i] = restored,
            None => self.visible.push(restored),
        }
    }

    /// Freezes the reconstruction into the decision-polarity type.
    pub(crate) fn finish(self, snapshot: Snapshot) -> DecidedProperties {
        DecidedProperties {
            snapshot,
            visible: self.visible,
        }
    }
}

/// One entity's properties as the store physically holds them: **every live cell** plus **every
/// `SetProperty` delta on its undo chain** (`rmp` tasks #905, #967).
///
/// This is the **superset** polarity of the module docs, and after #967 both halves are needed for it
/// to *be* a superset — the cells are the current image and the deltas are every value an older
/// snapshot can still ask for. It is the right read for an index refill or a zone-map rebuild, and
/// the wrong read for a decision; to make a decision, call [`decide`](Self::decide), which requires
/// the snapshot the decision is being made under.
#[derive(Debug, Clone)]
pub struct SupersetProperties {
    /// The entity's live `props.store` cells, head to tail of its `first_prop` chain.
    cells: Vec<(u64, PropRecord)>,
    /// The entity's undo chain, newest first, with each live delta's commit slot already resolved.
    history: Vec<PropertyDelta>,
}

impl SupersetProperties {
    /// Wraps an entity's cells and undo history a store read just walked. Crate-private on purpose: a
    /// value of this type is a claim that these records came off the store, so nothing outside the
    /// storage crate may mint one.
    #[must_use]
    pub(crate) fn from_chain(cells: Vec<(u64, PropRecord)>, history: Vec<PropertyDelta>) -> Self {
        Self { cells, history }
    }

    /// **Every candidate value** the entity holds or has held: each live cell first (in `first_prop`
    /// chain order), then each historical value from the undo chain (newest first).
    ///
    /// This is the read a population path must use. It yields only pairs that carry an actual value:
    /// an empty cell and a "was absent" delta are skipped ([`TYPE_TAG_ABSENT`]), a corpse delta is
    /// skipped (its transaction aborted, so the value it names was never real), and a delta whose
    /// transaction aborted after committing nothing is skipped through its corpse commit slot.
    ///
    /// It is *not* filtered by any snapshot — that is the point of the polarity. The consumer
    /// re-checks each candidate against its own snapshot, and a re-check can remove a candidate but
    /// can never resurrect one.
    pub fn candidates(&self) -> impl Iterator<Item = PropertyCandidate> + '_ {
        let cells = self.cells.iter().filter_map(|&(pid, cell)| {
            (cell.type_tag != TYPE_TAG_ABSENT).then_some(PropertyCandidate {
                key: cell.key,
                type_tag: cell.type_tag,
                value_inline: cell.value_inline,
                source: CandidateSource::Cell(pid),
            })
        });
        let deltas = self.history.iter().filter_map(|entry| {
            let live_slot = entry.slot.is_some_and(CommitSlot::in_use);
            (entry.delta.in_use()
                && live_slot
                && entry.delta.action == UndoAction::SetProperty
                && entry.delta.type_tag != TYPE_TAG_ABSENT)
                .then_some(PropertyCandidate {
                    key: entry.delta.token,
                    type_tag: entry.delta.type_tag,
                    value_inline: entry.delta.value_inline,
                    source: CandidateSource::Delta(entry.id),
                })
        });
        cells.chain(deltas)
    }

    /// The entity's live cells, **ignoring its undo history**.
    ///
    /// The name is a warning, and it is deliberate. This is the *current* image, not a superset: a
    /// caller that populates an index, a zone map, or any other structure a later reader re-checks
    /// must use [`candidates`](Self::candidates) instead, or it silently drops every value an older
    /// snapshot still needs. Legitimate uses are structural — walking the physical chain, counting
    /// slots, checking a cell's own MVCC header.
    #[must_use]
    pub fn cells_ignoring_history(&self) -> &[(u64, PropRecord)] {
        &self.cells
    }

    /// The entity's undo history as the walk resolved it (newest first), every action included.
    #[must_use]
    pub fn history(&self) -> &[PropertyDelta] {
        &self.history
    }

    /// How many live cells the entity holds. **Not** the number of candidates — see
    /// [`candidates`](Self::candidates) — and after `rmp` #967 not the number of values either, since
    /// a cell may be empty.
    #[must_use]
    pub fn len(&self) -> usize {
        self.cells.len()
    }

    /// How many deltas the entity's undo chain holds (every action, corpses included).
    #[must_use]
    pub fn history_len(&self) -> usize {
        self.history.len()
    }

    /// Whether the entity has no property cell at all.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.cells.is_empty()
    }

    /// Narrows to what `snapshot` sees: **the value of each key as of that snapshot**, and nothing
    /// else (`rmp` tasks #905, #967).
    ///
    /// This is the superset → decision conversion, and the only way a [`DecidedProperties`] comes into
    /// existence — which is what makes "a decision path must hold a snapshot" a property of the type
    /// system rather than of a comment.
    ///
    /// The rule is the one the read path applies (`04 §5.6`): seed the image from the live cells, then
    /// walk the undo chain newest-first, undoing every delta this snapshot must not see and stopping
    /// at the first delta it already reflects — the three-way [`DeltaVerdict`], decided by the same
    /// crate-private predicate the early-stopping walk in
    /// [`read_view`](crate::read_view) applies, so the two paths cannot disagree.
    ///
    /// # Errors
    /// Returns a storage error if a live delta's commit slot could not be resolved. That is the one
    /// thing `05 §12.4` promises can never happen ("a slot outlives its last delta"), so the
    /// reconstruction is failed **closed** rather than completed from a partial chain: a
    /// partially-undone image is a value no transaction ever wrote.
    pub fn decide(self, snapshot: Snapshot) -> Result<DecidedProperties> {
        let mut fold = DecisionFold::seed(&self.cells);
        for entry in &self.history {
            match delta_verdict(&entry.delta, entry.slot, snapshot, entry.id)? {
                DeltaVerdict::Skip => {}
                DeltaVerdict::Apply => fold.apply(&entry.delta, entry.id),
                DeltaVerdict::Stop => break,
            }
        }
        Ok(fold.finish(snapshot))
    }
}

/// One entity's properties **as of a snapshot**: at most one value per key, and exactly the values a
/// `MATCH` under that snapshot would resolve (`rmp` tasks #905, #967).
///
/// This is the **decision** polarity of the module docs — the only image a constraint validation, or
/// any other read whose answer is final and never re-checked, may be built on.
///
/// # It cannot be constructed without a snapshot
///
/// The fields are private and there is no public constructor; the sole ways to obtain a value are
/// [`SupersetProperties::decide`] and the store's `decision_scan_*` methods, all of which take the
/// [`Snapshot`] the narrowing is performed against. A helper that accepts `&DecidedProperties`
/// therefore cannot be handed a raw read, and the `rmp` #902 defect — a raw chain resolved
/// first-occurrence-wins into a constraint verdict — does not compile against this API.
#[derive(Debug, Clone)]
pub struct DecidedProperties {
    /// The snapshot the narrowing was performed against, retained so a caller can assert the decision
    /// and the walk agree on it.
    snapshot: Snapshot,
    /// The value of each key the entity holds in this snapshot, in deterministic order: live cells in
    /// `first_prop` chain order first, then keys restored from the undo chain in the order they were
    /// restored.
    visible: Vec<PropertyCandidate>,
}

impl DecidedProperties {
    /// Builds a decided image directly from a walk that already applied the fold. Crate-private: the
    /// public way in is [`SupersetProperties::decide`] or a `decision_scan_*` method.
    #[must_use]
    pub(crate) fn from_fold(fold: DecisionFold, snapshot: Snapshot) -> Self {
        fold.finish(snapshot)
    }

    /// The value of `prop_key` this snapshot sees, or [`None`] when the entity does not hold that
    /// key in this snapshot — because it never had it, because a visible removal emptied it, or
    /// because the only writes of it belong to transactions this snapshot cannot see.
    #[must_use]
    pub fn visible_version(&self, prop_key: u32) -> Option<PropertyCandidate> {
        self.visible.iter().copied().find(|c| c.key == prop_key)
    }

    /// Every key the entity holds in this snapshot — one candidate per key.
    #[must_use]
    pub fn visible_versions(&self) -> &[PropertyCandidate] {
        &self.visible
    }

    /// The snapshot this view was narrowed against.
    #[must_use]
    pub fn snapshot(&self) -> Snapshot {
        self.snapshot
    }

    /// How many distinct keys the entity holds in this snapshot.
    #[must_use]
    pub fn len(&self) -> usize {
        self.visible.len()
    }

    /// Whether the entity holds no property at all in this snapshot.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.visible.is_empty()
    }
}

/// The transaction id of the writer a live commit slot belongs to while it is still open, or [`None`]
/// once it has published a commit timestamp. Used by the write-conflict check
/// (`D-property-write-conflict`).
#[must_use]
pub(crate) fn open_writer_of(slot: CommitSlot) -> Option<TxnId> {
    if !slot.in_use() {
        return None;
    }
    match VersionStamp::from_raw(slot.commit_ts) {
        VersionStamp::InFlight(w) => Some(w),
        VersionStamp::Committed(_) | VersionStamp::None => None,
    }
}

#[cfg(test)]
mod tests {
    use graphus_core::{Timestamp, TxnId};
    use graphus_txn::View;

    use super::*;
    use crate::record::MvccHeader;
    use crate::undo::FLAG_IN_USE;

    /// A live cell holding `key` = `value`, at physical id `pid`. Its MVCC stamps are deliberately
    /// arbitrary: after `rmp` #967 they are informative only (`D-property-visibility`), and a test
    /// that passes only because they happen to be right would be testing the retired oracle.
    fn cell(pid: u64, key: u32, type_tag: u8, value: u64) -> (u64, PropRecord) {
        (
            pid,
            PropRecord {
                mvcc: MvccHeader {
                    flags: crate::record::FLAG_IN_USE,
                    created_ts: 0xDEAD_BEEF,
                    expired_ts: 0,
                    undo_ptr: 0,
                },
                key,
                type_tag,
                value_inline: value,
                next_prop: 0,
            },
        )
    }

    /// A `SetProperty` delta carrying `(key, type_tag, value)` as the OLD value, written by a
    /// transaction whose slot is `slot`.
    fn set_delta(id: u64, key: u32, type_tag: u8, value: u64, slot: CommitSlot) -> PropertyDelta {
        let mut delta = UndoDelta::new(UndoAction::SetProperty, 1, 0, 0);
        delta.token = key;
        delta.type_tag = type_tag;
        delta.value_inline = value;
        PropertyDelta {
            id,
            delta,
            slot: Some(slot),
        }
    }

    fn committed(ts: u64) -> CommitSlot {
        CommitSlot {
            flags: FLAG_IN_USE,
            commit_ts: VersionStamp::committed(Timestamp(ts)),
            txn_id: 1,
            delta_count: 1,
        }
    }

    fn in_flight(txn: u64) -> CommitSlot {
        CommitSlot::open(txn, VersionStamp::in_flight(TxnId(txn)))
    }

    fn aborted(txn: u64) -> CommitSlot {
        CommitSlot {
            flags: 0,
            ..CommitSlot::open(txn, VersionStamp::in_flight(TxnId(txn)))
        }
    }

    fn snapshot_at(owner: u64, ts: u64) -> Snapshot {
        Snapshot::new(TxnId(owner), Timestamp(ts))
    }

    /// [`delta_verdict`]'s statement arm, asserted directly on the three-way answer (`rmp` #972).
    ///
    /// The chain walks above this go through the fold, so an inverted comparison could in principle
    /// be compensated for somewhere else; this pins the verdict itself. Everything **except** the own
    /// in-flight writer must be untouched by the view, which is the other half of the claim.
    #[test]
    fn the_verdict_of_an_own_delta_is_decided_by_the_statement_and_the_view() {
        let mine = TxnId(9);
        let slot = in_flight(mine.0);
        let mut delta = UndoDelta::new(UndoAction::SetProperty, 1, 0, 0);

        for (writer_cmd, new_view, old_view) in [
            // an earlier statement's write: already reflected under both views
            (1u32, DeltaVerdict::Stop, DeltaVerdict::Stop),
            // the current statement's own write: the one case the views disagree about
            (5, DeltaVerdict::Stop, DeltaVerdict::Apply),
            // a later statement's write: never reflected
            (6, DeltaVerdict::Apply, DeltaVerdict::Apply),
            // written outside any statement — the transaction's baseline, never undone
            (0, DeltaVerdict::Stop, DeltaVerdict::Stop),
        ] {
            delta.command_id = writer_cmd;
            for (view, expected) in [(View::New, new_view), (View::Old, old_view)] {
                let snap = Snapshot::at_command(mine, Timestamp(30), CommandId(5), view);
                assert_eq!(
                    delta_verdict(&delta, Some(slot), snap, 1).expect("verdict"),
                    expected,
                    "delta written by command {writer_cmd}, read at command 5 on {view:?}"
                );
            }
        }

        // The view decides nothing outside our own in-flight writer.
        for (slot, expected) in [
            (committed(20), DeltaVerdict::Stop), // committed at or before the snapshot
            (committed(40), DeltaVerdict::Apply), // committed after it
            (in_flight(7), DeltaVerdict::Apply), // another open writer
            (aborted(7), DeltaVerdict::Skip),    // an aborted one
        ] {
            for view in [View::New, View::Old] {
                let snap = Snapshot::at_command(mine, Timestamp(30), CommandId(5), view);
                assert_eq!(
                    delta_verdict(&delta, Some(slot), snap, 1).expect("verdict"),
                    expected,
                    "{view:?} must not change a verdict about another transaction"
                );
            }
        }
    }

    /// THE `rmp` #902 SHAPE, restated for the undo chain: the cell alone says "key 7 is absent"; only
    /// the chain says "and it held 1 until ts 20, so a snapshot at 15 still reads 1".
    ///
    /// Semantic equivalent of the retired
    /// `a_committed_removal_leaves_the_key_absent_in_the_decision`, and strictly stronger: it asserts
    /// the exact old value the older snapshot must read, not merely that the newer one is absent.
    #[test]
    fn a_committed_removal_leaves_the_key_absent_and_the_old_value_readable_below_it() {
        // Cell emptied by the removal; the old value 0xAA descends onto the chain, committed at 20.
        let chain = SupersetProperties::from_chain(
            vec![cell(1, 7, TYPE_TAG_ABSENT, 0)],
            vec![set_delta(9, 7, 2, 0xAA, committed(20))],
        );

        let after = chain.clone().decide(snapshot_at(9, 30)).expect("decides");
        assert!(
            after.visible_version(7).is_none(),
            "a committed removal must not be resolvable as a present value",
        );
        assert!(after.is_empty());

        let before = chain.decide(snapshot_at(9, 15)).expect("decides");
        assert_eq!(
            before.visible_version(7).map(|c| c.value_inline),
            Some(0xAA),
            "an older snapshot must read the EXACT old value, not merely 'not the new one'",
        );
        assert_eq!(before.visible_version(7).map(|c| c.type_tag), Some(2));
        assert_eq!(before.len(), 1);
        assert_eq!(before.snapshot().ts, Timestamp(15));
    }

    /// Semantic equivalent of the retired `an_older_snapshot_still_sees_the_version_the_removal_expired`,
    /// for an overwrite rather than a removal — and again asserting the exact old value.
    #[test]
    fn an_older_snapshot_reads_the_exact_previous_value_of_an_overwritten_key() {
        let chain = SupersetProperties::from_chain(
            vec![cell(1, 7, 2, 0xBB)],
            vec![set_delta(9, 7, 2, 0xAA, committed(20))],
        );
        let old = chain.clone().decide(snapshot_at(9, 15)).expect("decides");
        assert_eq!(old.visible_version(7).map(|c| c.value_inline), Some(0xAA));
        assert!(
            matches!(
                old.visible_version(7).map(|c| c.source),
                Some(CandidateSource::Delta(9))
            ),
            "the old value must be attributed to the delta it was reconstructed from",
        );
        let new = chain.decide(snapshot_at(9, 30)).expect("decides");
        assert_eq!(new.visible_version(7).map(|c| c.value_inline), Some(0xBB));
        assert!(matches!(
            new.visible_version(7).map(|c| c.source),
            Some(CandidateSource::Cell(1))
        ));
    }

    /// Semantic equivalent of the retired `an_uncommitted_version_does_not_win_the_decision`: an open
    /// writer's in-place value is invisible to everyone else, so the fold undoes it back to the
    /// committed one — and IS visible to the writer itself.
    #[test]
    fn an_uncommitted_write_is_undone_for_others_and_kept_for_its_own_writer() {
        let chain = SupersetProperties::from_chain(
            vec![cell(1, 7, 2, 0xBB)],
            vec![set_delta(9, 7, 2, 0xAA, in_flight(5))],
        );
        let other = chain.clone().decide(snapshot_at(9, 30)).expect("decides");
        assert_eq!(
            other.visible_version(7).map(|c| c.value_inline),
            Some(0xAA),
            "the committed value is the one another snapshot holds",
        );
        assert_eq!(other.visible_versions().len(), 1, "one value per key");

        let own = chain.decide(snapshot_at(5, 30)).expect("decides");
        assert_eq!(
            own.visible_version(7).map(|c| c.value_inline),
            Some(0xBB),
            "a writer sees its own uncommitted write",
        );
    }

    /// Semantic equivalent of the retired `each_key_resolves_to_its_own_newest_visible_version`, plus
    /// the property the old test could not express: a `Stop` on ONE key's delta must not leak an
    /// older, already-reflected delta of ANOTHER key into the image.
    #[test]
    fn each_key_resolves_independently_and_stop_ends_the_whole_walk() {
        let chain = SupersetProperties::from_chain(
            vec![cell(3, 7, 2, 0xBB), cell(2, 8, 2, 0xCC)],
            vec![
                set_delta(11, 7, 2, 0xAA, committed(20)),
                set_delta(10, 8, 2, 0x11, committed(10)),
            ],
        );
        // At ts 30 the newest delta already committed, so nothing is undone.
        let now = chain.clone().decide(snapshot_at(9, 30)).expect("decides");
        assert_eq!(now.len(), 2);
        assert_eq!(now.visible_version(7).map(|c| c.value_inline), Some(0xBB));
        assert_eq!(now.visible_version(8).map(|c| c.value_inline), Some(0xCC));
        assert!(now.visible_version(9).is_none());

        // At ts 15 only key 7's write is in the future: key 8's delta committed at 10 and is STOPped
        // on, so key 8 keeps its cell value.
        let mid = chain.decide(snapshot_at(9, 15)).expect("decides");
        assert_eq!(mid.visible_version(7).map(|c| c.value_inline), Some(0xAA));
        assert_eq!(
            mid.visible_version(8).map(|c| c.value_inline),
            Some(0xCC),
            "key 8's delta committed at 10 <= 15, so the walk stops there and its cell stands",
        );
    }

    /// An aborted transaction's delta must be threaded through, never applied — by either route (a
    /// corpse delta, or a live delta whose slot is a corpse).
    #[test]
    fn an_aborted_transactions_delta_is_skipped_not_applied() {
        let mut corpse = set_delta(11, 7, 2, 0xAA, committed(20));
        corpse.delta.flags = 0; // creation-undo cleared the flag; body (and `next`) intact
        corpse.slot = None; // a corpse's slot is never read
        let chain = SupersetProperties::from_chain(vec![cell(1, 7, 2, 0xBB)], vec![corpse]);
        let d = chain.decide(snapshot_at(9, 1)).expect("decides");
        assert_eq!(
            d.visible_version(7).map(|c| c.value_inline),
            Some(0xBB),
            "a corpse delta must not restore a value its transaction never committed",
        );

        let chain = SupersetProperties::from_chain(
            vec![cell(1, 7, 2, 0xBB)],
            vec![set_delta(11, 7, 2, 0xAA, aborted(5))],
        );
        let d = chain.decide(snapshot_at(9, 1)).expect("decides");
        assert_eq!(d.visible_version(7).map(|c| c.value_inline), Some(0xBB));
    }

    /// A live delta whose commit slot cannot be resolved is failed closed, never guessed
    /// (`05 §12.4`).
    #[test]
    fn an_unresolvable_commit_slot_fails_the_reconstruction_closed() {
        let mut orphan = set_delta(11, 7, 2, 0xAA, committed(20));
        orphan.slot = None; // live delta, missing slot
        let chain = SupersetProperties::from_chain(vec![cell(1, 7, 2, 0xBB)], vec![orphan]);
        let err = chain.decide(snapshot_at(9, 1)).expect_err("fails closed");
        assert!(
            format!("{err}").contains("slot must outlive its last delta"),
            "the error must name the invariant that failed: {err}",
        );
    }

    /// The superset is cells **plus** history — the property that makes an index refill safe after
    /// `rmp` #967. Reading only the cells would yield one candidate where two are needed.
    #[test]
    fn the_superset_carries_both_the_live_cell_and_the_historical_value() {
        let chain = SupersetProperties::from_chain(
            vec![cell(1, 7, 2, 0xBB)],
            vec![set_delta(9, 7, 2, 0xAA, committed(20))],
        );
        let got: Vec<_> = chain.candidates().collect();
        assert_eq!(got.len(), 2, "both the current and the historical value");
        assert_eq!(got[0].value_inline, 0xBB);
        assert_eq!(got[0].source, CandidateSource::Cell(1));
        assert_eq!(got[1].value_inline, 0xAA);
        assert_eq!(got[1].source, CandidateSource::Delta(9));
        assert_eq!(chain.len(), 1, "one cell");
        assert_eq!(chain.history_len(), 1, "one delta");
        assert_eq!(
            chain.cells_ignoring_history().len(),
            1,
            "the cell-only view is exactly the current image",
        );
    }

    /// An empty cell and a "was absent" delta carry no value, so neither is a candidate — otherwise
    /// an index would be populated with a zero-tagged entry that decodes as nothing.
    #[test]
    fn empty_cells_and_absent_deltas_are_not_candidates() {
        let chain = SupersetProperties::from_chain(
            vec![cell(1, 7, TYPE_TAG_ABSENT, 0), cell(2, 8, 2, 0xCC)],
            vec![
                set_delta(9, 8, TYPE_TAG_ABSENT, 0, committed(20)),
                set_delta(10, 7, 2, 0xAA, committed(10)),
            ],
        );
        let got: Vec<_> = chain.candidates().collect();
        assert_eq!(got.len(), 2);
        assert_eq!(got[0].source, CandidateSource::Cell(2));
        assert_eq!(got[1].source, CandidateSource::Delta(10));
    }

    /// A corpse delta is not a candidate either: its transaction aborted, so the value it names was
    /// never committed and indexing it would resurrect a write that never happened.
    #[test]
    fn a_corpse_delta_is_not_a_candidate() {
        let mut corpse = set_delta(9, 7, 2, 0xAA, committed(20));
        corpse.delta.flags = 0;
        corpse.slot = None;
        let aborted_slot = set_delta(10, 8, 2, 0xBB, aborted(5));
        let chain =
            SupersetProperties::from_chain(vec![cell(1, 7, 2, 0xBB)], vec![corpse, aborted_slot]);
        let got: Vec<_> = chain.candidates().collect();
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].source, CandidateSource::Cell(1));
    }

    /// A key that was **absent** before an in-flight writer added it must read as absent to every
    /// other snapshot — the case that has no cell-stamp to fall back on after
    /// `D-property-visibility`, and therefore the one that proves the "was absent" delta is not
    /// optional.
    #[test]
    fn a_newly_added_key_is_invisible_to_other_snapshots() {
        let chain = SupersetProperties::from_chain(
            vec![cell(1, 7, 2, 0xBB)],
            vec![set_delta(9, 7, TYPE_TAG_ABSENT, 0, in_flight(5))],
        );
        let other = chain.clone().decide(snapshot_at(9, 30)).expect("decides");
        assert!(
            other.visible_version(7).is_none(),
            "without the `was absent` delta an older snapshot would see an uncommitted key",
        );
        let own = chain.decide(snapshot_at(5, 30)).expect("decides");
        assert_eq!(own.visible_version(7).map(|c| c.value_inline), Some(0xBB));
    }

    /// `rmp` #967 technical requirement 3, asserted **structurally**: the de-duplication in
    /// [`DecisionFold::seed`] must not do work quadratic in the entity's key count.
    ///
    /// This counts key comparisons rather than timing the fold, on purpose. A timing threshold on a
    /// shared CI host is a flaky test that has to be given enough slack to be useless; the number of
    /// elements the linear scan examines is exact, deterministic, machine-independent, and is the
    /// thing that was actually wrong. Before the fix this count was `K(K-1)/2` — 31 996 000 at
    /// `K = 8000`; it is now bounded by a constant no matter how large `K` is.
    ///
    /// The first assertion is the **non-vacuity control** and it is not optional: it pins the counter
    /// to the exact closed form `K(K-1)/2` on an input small enough to take the scan path, so a probe
    /// that silently stopped counting — or a `find_key` that stopped being the scan the bound is
    /// claimed over — fails here rather than making every later assertion pass against zero.
    #[test]
    fn the_dedup_never_does_work_quadratic_in_the_key_count() {
        let cells = |k: u32| -> Vec<(u64, PropRecord)> {
            (0..k)
                .map(|i| cell(u64::from(i) + 1, i, 2, u64::from(i)))
                .collect()
        };

        // CONTROL: on the scan path the counter reports exactly the closed form, so it is
        // demonstrably counting the comparisons the bound below is about.
        for k in [1u32, 2, 8, 16, 64] {
            take_linear_probes();
            let fold = DecisionFold::seed(&cells(k));
            let probes = take_linear_probes();
            let n = u64::from(k);
            assert_eq!(
                probes,
                n * (n - 1) / 2,
                "the linear scan path must examine exactly K(K-1)/2 elements at K={k}; if this \
                 fails the probe is not measuring the scan and the bound below proves nothing",
            );
            assert_eq!(
                fold.visible.len(),
                k as usize,
                "every distinct key survives"
            );
        }

        // THE SUBJECT: past the dispatch the count stops growing with K entirely. Under the old
        // implementation these three numbers were 499 500, 7 998 000 and 31 996 000.
        const BOUND: u64 = (LINEAR_DEDUP_MAX as u64) * (LINEAR_DEDUP_MAX as u64 - 1) / 2;
        let mut counts = Vec::new();
        for k in [1000u32, 4000, 8000] {
            take_linear_probes();
            let fold = DecisionFold::seed(&cells(k));
            counts.push(take_linear_probes());
            assert_eq!(
                fold.visible.len(),
                k as usize,
                "every distinct key survives"
            );
        }
        assert!(
            counts.iter().all(|&c| c <= BOUND),
            "seed must never examine more than {BOUND} elements linearly, found {counts:?} — the \
             quadratic de-duplication is back",
        );
        assert_eq!(
            counts[0], counts[2],
            "the linear-probe count must be IDENTICAL at K=1000 and K=8000, not merely small; \
             found {counts:?}",
        );
    }

    /// The dispatch is an optimisation, so it must be undetectable in the answer: both paths must
    /// agree, element for element, on the same input — including the order, which
    /// [`DecidedProperties::visible_versions`] promises, and the first-occurrence-wins rule that
    /// resolves a duplicated key.
    #[test]
    fn both_dedup_paths_agree_on_order_and_on_which_duplicate_wins() {
        // The k values straddle LINEAR_DEDUP_MAX *in cells*, which is not the same as in keys: this
        // construction injects three extra cells per eight keys, so k=46 yields exactly 64 cells
        // (the last linear case) and k=47 yields 65 (the first hashed one). Getting that wrong is
        // easy and silent — an earlier draft used k=63/64/65 and put ALL of them on the hashed path
        // — so the loop below does not take it on trust: it reads the probe counter and asserts
        // which path actually ran.
        let mut paths_seen: Vec<bool> = Vec::new();
        for k in [4u32, 46, 47, 200] {
            let mut cells: Vec<(u64, PropRecord)> = Vec::new();
            let mut pid = 1u64;
            for i in 0..k {
                cells.push(cell(pid, i, 2, u64::from(i)));
                pid += 1;
                if i % 8 == 3 {
                    // A stale second cell for a key already present: the FIRST must win.
                    cells.push(cell(pid, i, 2, 0xDEAD));
                    pid += 1;
                    // An empty cell for a key that is NOT yet present: it must claim nothing.
                    cells.push(cell(pid, k + i, TYPE_TAG_ABSENT, 0));
                    pid += 1;
                    cells.push(cell(pid, k + i, 2, 0xBEEF));
                    pid += 1;
                }
            }

            take_linear_probes();
            let got = DecisionFold::seed(&cells).visible;
            let probed = take_linear_probes() > 0;

            // Which path ran, asserted rather than assumed. `> 0` means the linear scan was used;
            // exactly `0` means the hashed path was, because it never calls `find_key` at all.
            let expected_linear = cells.len() <= LINEAR_DEDUP_MAX;
            paths_seen.push(expected_linear);
            assert_eq!(
                probed,
                expected_linear,
                "K={k} produced {} cells and should have taken the {} path; if this fails the \
                 constants drifted and this test is no longer covering both",
                cells.len(),
                if expected_linear { "linear" } else { "hashed" },
            );

            // The reference: the pre-#967-fix rule, written out plainly.
            let mut want: Vec<PropertyCandidate> = Vec::new();
            for &(p, c) in &cells {
                if c.type_tag != TYPE_TAG_ABSENT && !want.iter().any(|w| w.key == c.key) {
                    want.push(cell_candidate(p, c));
                }
            }
            assert_eq!(got, want, "the two paths disagree at K={k}");
            assert!(
                got.iter().any(|c| c.value_inline == 0xBEEF),
                "a live cell whose key was first seen on an EMPTY cell must still be kept (K={k})",
            );
            assert!(
                got.iter().all(|c| c.value_inline != 0xDEAD),
                "the FIRST cell of a duplicated key must win, not the later one (K={k})",
            );
        }

        // The whole point of the test is that it compares TWO implementations, so covering only one
        // of them would make every assertion above true and meaningless.
        assert!(
            paths_seen.contains(&true) && paths_seen.contains(&false),
            "both the linear and the hashed path must be exercised, took {paths_seen:?}",
        );
    }

    /// A non-property delta on the chain changes no property but still ends the walk when this
    /// snapshot already reflects it.
    #[test]
    fn a_non_property_delta_changes_nothing_but_still_orders_the_walk() {
        let mut label = UndoDelta::new(UndoAction::RemoveLabel, 1, 0, 0);
        label.token = 3;
        let chain = SupersetProperties::from_chain(
            vec![cell(1, 7, 2, 0xBB)],
            vec![
                PropertyDelta {
                    id: 12,
                    delta: label,
                    slot: Some(committed(10)),
                },
                set_delta(11, 7, 2, 0xAA, committed(5)),
            ],
        );
        let d = chain.decide(snapshot_at(9, 20)).expect("decides");
        assert_eq!(
            d.visible_version(7).map(|c| c.value_inline),
            Some(0xBB),
            "the label delta stops the walk without touching the property image",
        );
    }
}
